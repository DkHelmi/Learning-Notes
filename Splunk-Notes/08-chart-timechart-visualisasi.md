---
day: 08
title: 'chart, timechart, dan memilih visualisasi: over, by, span, dan batas sepuluh seri'
researched_on: 2026-10-14
versions_checked: 'Splunk Enterprise 10.6 (Search Reference: chart, timechart, bin, timewrap; Create dashboards and reports: Visualization reference, Generate a single value); ES 8.7.0; CIM 6.4; BOTS v1 (dataset statis, README tidak menyebut rentang tanggal datanya)'
---

# Day 08: chart, timechart, dan memilih visualisasi (over, by, span, dan batas sepuluh seri)

Cakupan: cara mengubah hasil search menjadi tabel dua dimensi dan grafik waktu yang bisa dipercaya, mulai dari `chart ... over ... by`, `timechart` dengan `span`, `bin`, batas sepuluh seri beserta `limit`, `useother`, dan `usenull`, sampai memilih antara line, column, single value, dan tabel.

## Ide inti

`stats` menjawab "berapa". `chart` dan `timechart` menjawab "berapa, dipecah menurut dua sumbu", dan itulah yang membuat mata bisa melihat bentuk: lonjakan, pergeseran, atau satu host yang berperilaku lain dari semua host sejenisnya. Yang perlu dikuasai bukan nama commandnya, melainkan empat keputusan yang kamu ambil setiap kali memakainya: apa yang menjadi sumbu baris, apa yang menjadi seri (kolom), seberapa lebar satu bin waktu, dan seri mana yang dibuang Splunk tanpa memberi tahu. Keputusan terakhir yang paling sering menjatuhkan analyst, karena `chart` dan `timechart` hanya menampilkan sepuluh seri secara default dan menyapu sisanya ke satu kolom bernama OTHER.

Kamu sudah punya kebiasaan ini dari NOC. Grafik trafik per interface di NMS adalah `timechart`: sumbu X waktu, satu garis per interface, dan interval polling lima menit yang menentukan apakah microburst terlihat atau rata. Rekap gangguan per POP per vendor perangkat adalah `chart`: baris POP, kolom vendor, angka di persimpangan. Bedanya, NMS menyimpan counter yang sudah diagregasi pada interval tetap, sedangkan di Splunk lebar bin ditentukan saat search dijalankan, jadi grafik yang sama bisa memperlihatkan lonjakan atau menyembunyikannya hanya karena kamu mengubah satu angka. Dan grafik NMS menggambar semua interface yang kamu pilih, sementara Splunk diam-diam memotong di seri kesepuluh.

```
Event mentah
  -> transforming command (stats / chart / timechart)
       stats     : satu baris per kombinasi BY, tidak ada sumbu
       chart      : OVER <field> = sumbu baris, BY <field> = satu kolom per nilai (maks 10)
       timechart : sumbu baris selalu _time dengan lebar span, BY <field> = seri (maks 10)
  -> tabel hasil (statistics table)
  -> visualisasi dipilih di atas tabel hasil, bukan di atas event
       line / area   : tren terhadap waktu
       column / bar  : perbandingan antar kategori
       single value  : satu angka utama
       table         : angka yang mau dibaca, disalin, atau ditempel ke tiket
```

Situasi yang dipakai sepanjang Day ini: pukul 07:40 di PT Jaringan Anak Bangsa (PT JAB, ISP menengah fiktif, SOC internal satu lantai dengan NOC). Tiket SOC-2026-0217 dari shift malam, brute force VPN dari `203.0.113.45` dengan 180 login gagal dan satu login sukses, sudah dipegang L2. SOC lead minta bahan untuk rapat harian pukul 09:00 dan menulis di grup shift:

> "Untuk rapat jam 09:00 aku butuh tiga hal. Pertama, bentuk login gagal VPN per jam selama tujuh hari terakhir, supaya kelihatan apakah tadi malam memang tidak wajar atau tiap malam seperti itu. Kedua, tujuan koneksi teratas per host dari segmen data center, satu tampilan saja. Ketiga, trafik DNS resolver pelanggan per jam, karena NOC menanyakan lonjakan kemarin siang. Tolong jangan kirim screenshot tabel 200 baris."

Permintaan itu memuat lima pertanyaan:

1. Kapan sebuah pertanyaan dijawab dengan `chart` dan kapan dengan `timechart`, dan apa beda `over` dan `by`?
2. Bagaimana menentukan lebar bin waktu supaya lonjakan satu jam tidak hilang dan tidak juga melebar?
3. Kenapa host atau tujuan tertentu tidak muncul di grafik, dan apa sebenarnya OTHER dan NULL?
4. Visualisasi mana yang dipakai untuk masing-masing pertanyaan?
5. Kapan jawaban yang benar justru bukan grafik?

Pertanyaan 1 dijawab di bagian 1.1 dan 1.2, pertanyaan 2 di bagian 1.3 dan 1.4, pertanyaan 3 di bagian 1.5, pertanyaan 4 di bagian 1.6, dan pertanyaan 5 di bagian 1.7. Bagian 2 mengerjakan ketiga permintaan itu sampai jadi panel dan angka yang bisa ditempel ke tiket.

**Kapan relevan:** setiap kali pertanyaan triage berbentuk "apakah ini tidak wajar dibanding biasanya", "siapa yang paling banyak", atau "kapan mulainya", dan setiap kali kamu membuat panel dashboard atau lampiran laporan dari data Splunk.
**Kapan bukan jawaban:** grafik bukan bukti. Angka yang masuk ke note tiket harus berasal dari `stats` pada rentang waktu absolut yang disebut (Day 07 bagian 1.8), bukan dari membaca puncak grafik. Untuk mengubah panel menjadi report terjadwal, alert, dan dashboard lengkap dengan token, lanjut ke Day 09.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dasar dari Day 01 sampai Day 07 (index, sourcetype, `_time`, time picker, snap-to, pipeline, `stats`, `eval`) tidak diulang di sini. Tabel ini hanya memuat istilah yang dipakai Day ini; cari kolom padanan bila sebuah istilah terasa asing.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Transforming command | Command yang mengubah event menjadi tabel hasil, misalnya `stats`, `chart`, `timechart`, `top` | Script rekap yang mengubah file log menjadi tabel laporan |
| Tabel hasil (statistics table) | Tabel yang keluar dari transforming command dan menjadi dasar visualisasi | Tabel rekap yang jadi sumber grafik di laporan bulanan |
| Row-split (`over`) | Field yang menjadi kolom pertama dan label sumbu X di `chart` | Kolom "POP" di rekap gangguan per POP |
| Column-split (`by`) | Field yang setiap nilainya menjadi satu kolom atau satu seri grafik | Kolom "vendor" di rekap yang sama, atau satu garis per interface di NMS |
| Bin (bucket) | Satu kelompok nilai yang dianggap sama, misalnya semua event dalam satu jam | Satu interval polling di grafik NMS |
| `span` | Lebar satu bin, misalnya `span=1h` atau `span=5m` | Interval polling lima menit di RRD |
| Seri OTHER | Satu kolom gabungan untuk semua nilai di luar batas seri | Baris "lain-lain" di rekap manual |
| Seri NULL | Satu kolom untuk event yang tidak punya field pemecah sama sekali | Perangkat yang mengirim log tanpa nama interface |
| Klausa `where` di `chart`/`timechart` | Cara memilih seri berdasarkan nilai, misalnya puncak tertinggi, bukan total | Memilih interface yang mau digambar berdasarkan puncak trafik, bukan rata-rata |
| Partial bin | Bin pertama atau terakhir yang hanya terisi sebagian karena rentang search | Interval polling pertama setelah perangkat baru dipasang |
| Sparkline | Grafik mini di dalam satu sel tabel atau di bawah single value | Grafik kecil di kolom status layar NOC |
| Single value dan trend indicator | Satu angka utama, dengan penunjuk arah perubahan dibanding bin sebelumnya | Angka besar "pelanggan terdampak" di layar NOC |
| Stacked column | Column chart yang menumpuk seri dalam satu batang | Grafik batang gangguan per POP yang dipecah per penyebab |
| `timewrap` | Membandingkan periode dengan periode sebelumnya di satu grafik | Membandingkan grafik trafik hari ini dengan hari yang sama minggu lalu |

### 1.1 Tabel hasil dulu, visualisasi kemudian

Permintaan SOC lead berbunyi "satu tampilan saja", tetapi yang sebenarnya kamu susun bukan gambar. Yang kamu susun adalah tabel hasil, dan gambar hanya cara menampilkannya.

Urutannya selalu sama. Search mengambil event, transforming command mengubahnya menjadi tabel, lalu tab Visualization menggambar tabel itu. Konsekuensinya: bila bentuk tabel hasilnya salah, tidak ada pengaturan visualisasi yang bisa menyelamatkannya. `table` dan `fields` tidak mengubah event menjadi tabel hasil agregat, jadi keduanya tidak menghasilkan grafik yang bermakna walau tampilannya sudah berbentuk tabel.

Tiga transforming command yang dipakai paling sering, dan perbedaan bentuk keluarannya:

- `stats count BY host action` menghasilkan satu baris per kombinasi `host` dan `action`, dengan `count` sebagai kolom nilai. Bentuk ini bagus untuk dibaca dan disalin, tetapi tidak punya sumbu: `host` dan `action` sama-sama menjadi kolom teks.
- `chart count OVER host BY action` menghasilkan satu baris per `host`, dan setiap nilai `action` menjadi kolom tersendiri. Bentuk ini yang digambar sebagai column chart: satu batang per host, dipecah per `action`.
- `timechart span=1h count BY action` menghasilkan satu baris per jam, dengan `_time` sebagai kolom pertama dan setiap nilai `action` sebagai kolom. Bentuk ini yang digambar sebagai line chart.

Istilah resminya: field yang menjadi kolom pertama dan label sumbu X disebut row-split, dan field yang setiap nilainya menjadi satu kolom disebut column-split atau data series [S1]. `chart` wajib diberi minimal satu fungsi statistik, dan bisa juga diberi sparkline atau ekspresi `eval` dalam tanda kurung [S1].

### 1.2 `chart`: memilih sumbu baris dan sumbu kolom

Permintaan kedua SOC lead, tujuan koneksi teratas per host, punya dua dimensi yang bukan waktu: tujuan dan host. Di sini `chart` yang dipakai.

Ada dua cara menulis dimensi itu, dan keduanya menghasilkan hal yang sama [S1]:

```
chart count OVER dest BY src
chart count BY dest src
```

Pada bentuk kedua, field pertama setelah `BY` menjadi row-split dan field kedua menjadi column-split. Bentuk `OVER` lebih jelas dibaca enam bulan kemudian, jadi pakai itu kecuali kamu sedang menyingkat di search bar.

Tiga batasan yang perlu diingat sejak awal:

1. Hanya ada satu klausa `BY` [S1]. `chart` tidak bisa diberi tiga dimensi. Bila kamu butuh tiga, gabungkan dua di antaranya menjadi satu field dengan `eval` lebih dulu, atau terima bentuk tabel dari `stats`.
2. Satu field tidak boleh dipakai di dalam fungsi sekaligus sebagai row-split pada command yang sama [S1]. `chart dc(dest) OVER dest` tidak jalan; salin dulu field itu dengan `eval tujuan=dest`, lalu pakai salinannya di salah satu posisi.
3. Jumlah kolom dibatasi sepuluh secara default [S1]. Ini dibahas di bagian 1.5 karena dampaknya besar.

Opsi `chart` yang paling sering dipakai saat triage:

| Opsi | Nilai default | Kapan kamu mengubahnya |
|---|---|---|
| `limit=(top\|bottom) <int>` | `top 10` [S1] | Saat seri yang kamu cari ternyata disapu ke OTHER |
| `useother` | `true` [S1] | Saat kamu ingin tahu, atau tidak ingin tahu, berapa besar sisa yang dipotong |
| `usenull` | `true` [S1] | Saat ada event tanpa field pemecah dan kamu sudah tahu kenapa |
| `agg=<fungsi>` | tidak disebut di dokumentasi | Saat fungsi agregasi ditulis sekali untuk banyak field |
| `sep` dan `format` | tidak ada | Saat nama kolom hasil perlu dirapikan; `format` memakai `$AGG$` dan `$VAL$` dan menang atas `sep` [S1] |
| `cont` | `true` [S1] | Saat bin numerik yang tidak bersambung ingin ditempelkan berdampingan, pakai `cont=false` |
| `dedup_splitvals` | `false` [S1] | Saat field pemecah multivalue, misalnya `Account_Name` di log Windows format klasik (Day 03 bagian 1.5), menghitung satu event dua kali |

Row-split juga menerima opsi bin, jadi `chart` bisa memecah field numerik menjadi kelompok: `chart count OVER bytes span=1000` atau `chart max(delay) BY size bins=10` [S1]. Untuk `chart`, jumlah bin maksimum default-nya 300 [S1]. Angka itu berbeda dari `timechart` dan dari command `bin`, dan bagian 1.3 serta 1.4 menyebut angka masing-masing.

### 1.3 `timechart`: sumbu X selalu waktu

Permintaan pertama dan ketiga SOC lead berbentuk "per jam", jadi keduanya milik `timechart`. Yang membedakan `timechart` dari `chart` hanya satu hal, tetapi hal itu mengubah segalanya: row-split-nya tidak bisa dipilih, selalu `_time` [S2].

Akibatnya `timechart` hanya menerima satu field pemecah, karena satu dimensi sudah dipakai waktu [S2]. Bila kamu butuh dua dimensi di atas waktu, pakai `bin` dan `stats` (bagian 1.4) atau gabungkan dua field menjadi satu dengan `eval`.

Lebar bin ditentukan dengan `span`, dan kalau tidak ditentukan Splunk memilih sendiri. Yang dicari Splunk adalah bin terkecil yang menghasilkan tidak lebih dari `bins` bin, dan `bins` default-nya 100 untuk `timechart` [S2]. Bila `bins` dan `span` diberikan bersamaan, `span` yang dipakai dan `bins` diabaikan [S2]. Untuk preset time picker, dokumentasi menyebut span default yang dipakai [S2]:

| Rentang di time picker | Span default [S2] |
|---|---|
| Last 15 minutes | 10 detik |
| Last 60 minutes | 1 menit |
| Last 4 hours | 5 menit |
| Last 24 hours | 30 menit |
| Last 7 days dan Last 30 days | 1 hari |
| Previous year | 1 bulan |

Baris "Last 7 days" adalah alasan permintaan SOC lead tidak bisa dijawab tanpa `span` eksplisit. Dengan span default satu hari, 180 login gagal dalam 14 menit melebur ke dalam total satu hari penuh dan bentuknya hilang. Karena itu `span=1h` ditulis sendiri.

Empat opsi `timechart` yang mengubah cara grafik dibaca:

- `span`. Selain satuan waktu biasa, `span` menerima bentuk snap seperti `span=1w@w` dan bentuk log untuk sumbu logaritmik [S2]. Satu jebakan penting: bin disnap turun dari waktu paling awal, sehingga bin bisa tidak sejajar dengan zona waktu lokalmu. Dokumentasi menyarankan memakai `span=1d` untuk batas hari, bukan `span=86400s` [S2]. Untuk menggeser titik awal bin, pakai `aligntime`, yang diabaikan bila span-nya hari, bulan, atau tahun [S2].
- `partial`, default `true` [S2]. Bin pertama dan bin terakhir boleh terisi sebagian. Hal ini yang membuat batang pertama dan terakhir sering tampak pendek tanpa alasan. Mencegahnya bisa dengan snap di time picker (`-7d@h` sampai `@h`) atau dengan `partial=false`.
- `cont`, default `true` [S2]. Celah waktu tetap digambar sebagai bin kosong, sehingga sumbu waktunya jujur. Kalau diubah ke `false`, bin yang tidak bersambung ditempelkan berdampingan dan grafik jadi menipu.
- `fixedrange`, default `true` [S2]. Rentang earliest dan latest dari search dipertahankan. Dengan `fixedrange=false`, grafik menyesuaikan diri ke rentang data yang benar-benar ada.

Fungsi `per_day()`, `per_hour()`, `per_minute()`, dan `per_second()` tidak menentukan span; keduanya mengubah nilai menjadi laju untuk span yang sedang dipakai [S2]. Jadi `timechart span=5m per_minute(count)` membaca "kueri per menit", dan angkanya tetap bisa dibandingkan walau nanti span-nya diubah.

### 1.4 `bin`: membuat bucket sendiri

Pertanyaan NOC tentang DNS bisa berkembang menjadi "per jam, per resolver, per tipe kueri". Tiga dimensi, dan satu di antaranya waktu. `timechart` menolak karena hanya menerima satu field pemecah, dan di sinilah `bin` masuk.

`bin` mengubah nilai numerik atau waktu menjadi kelompok, dengan menyetel nilai field supaya semua anggota satu kelompok punya nilai yang sama [S3]. Setelah `bin _time span=1h`, semua event dalam satu jam memiliki `_time` yang identik, sehingga `stats ... BY _time <field lain>` bisa memecah per jam sekaligus per dua dimensi lain.

Yang perlu diingat tentang `bin` [S3]:

- `bucket` adalah alias dari `bin`. Dua nama itu command yang sama.
- `bins` default-nya 100, diatur di stanza `[discretize]` pada `limits.conf`.
- Saat span bernilai satu hari atau lebih, bin disejajarkan ke tengah malam di zona waktu user. Ini berbeda dari perilaku snap-turun `timechart`, jadi jangan berasumsi dua command menghasilkan batas bin yang identik tanpa diuji.
- `aligntime` hanya berlaku untuk pembagian berbasis waktu dan diabaikan bila span-nya hari, bulan, atau tahun.
- `start` dan `end` untuk bin numerik hanya bisa memperlebar rentang, tidak memperpendeknya.
- `chart` dan `timechart` memanggil `bin` secara otomatis, dan dokumentasi menyarankan memakai `bin` sendiri hanya untuk operasi statistik yang tidak bisa dikerjakan dua command itu.

Nasihat terakhir itu adalah aturan praktisnya: jangan menulis `bin _time span=1h | stats count` bila `timechart span=1h count` sudah cukup. Pakai `bin` saat kamu butuh lebih dari satu dimensi selain waktu, atau saat hasilnya memang mau dibaca sebagai tabel dan bukan sebagai grafik.

### 1.5 Batas sepuluh seri: `limit`, `useother`, `usenull`, dan klausa `where`

Ini bagian yang paling sering menyebabkan kesimpulan salah. Grafik login gagal per host di PT JAB terlihat lengkap, padahal PT JAB punya jauh lebih dari sepuluh host, dan host yang kamu cari bisa jadi tidak ada di sana.

Perilaku default-nya begini. `chart` dan `timechart` menampilkan sepuluh seri teratas [S1][S2]. Bila ada klausa `where` eksplisit, opsi `limit` dan `agg` diabaikan [S1]. Tanpa klausa `where`, default-nya setara dengan "sepuluh seri dengan jumlah terbesar", yang dokumentasi `chart` sebut sebagai sepuluh seri teratas menurut area di bawah kurva [S1]. Cara peringkat dihitung bergantung jumlah agregasi [S2]:

- Satu agregasi: skor tiap nilai pemecah adalah jumlah agregasi itu.
- Lebih dari satu agregasi: skornya frekuensi kemunculan tiap nilai pemecah.
- Nilai yang seri diputuskan secara leksikografis.

Empat pengatur yang perlu kamu kuasai:

| Pengatur | Arti | Catatan penting |
|---|---|---|
| `limit=top10` (default) | Ambil sepuluh seri berskor tertinggi | `limit=0` menampilkan semua seri; `bottomN` mengambil yang terendah; tanpa `top` atau `bottom`, dianggap `top` [S1][S2] |
| `useother=true` (default) | Semua seri di luar batas digabung menjadi satu seri | Namanya diatur `otherstr` dan default-nya `OTHER` [S1][S2] |
| `usenull=true` (default) | Event yang tidak punya field pemecah dijadikan satu seri | Namanya diatur `nullstr` dan default-nya `NULL` [S1][S2] |
| Klausa `where` | Memilih seri dengan kriteria sendiri | Bentuknya `<satu-agregasi> <pembanding>`, misalnya `WHERE max in top5` atau `WHERE count > 10` [S1][S2] |

Tiga hal yang mengubah cara kerja di lapangan:

**OTHER bukan nilai field.** OTHER adalah nama seri yang dibuat oleh command [S1][S2], bukan nilai yang ada di data. Jadi drilldown atau search lanjutan yang menyaring `dest="OTHER"` tidak akan menemukan apa pun. Untuk menelusuri isinya, jalankan ulang search dengan `limit=0` atau dengan filter yang membuang sepuluh nilai teratas.

**`useother=false` tidak menaikkan batas.** Mematikan OTHER hanya menghilangkan kolom gabungannya; sepuluh seri teratas tetap sepuluh. Grafiknya jadi lebih rapi dan sekaligus lebih menipu, karena satu-satunya tanda bahwa ada data yang dipotong ikut hilang. Bila yang kamu mau adalah semua seri, yang diubah `limit`, bukan `useother`.

**Memilih seri menurut puncak, bukan total.** Default "sepuluh teratas menurut jumlah" cocok untuk pertanyaan kapasitas, tetapi buruk untuk keamanan. Penyerang yang menyala 14 menit sekali dalam tujuh hari punya total kecil, jadi ia kalah dari host berisik yang mengirim log setiap menit. Ganti kriterianya: `WHERE max in top5` memilih lima seri dengan puncak tertinggi, dan dokumentasi `chart` menyebut penggantian jumlah dengan maksimum sebagai cara memilih seri dengan lonjakan tertinggi [S1]. Contoh di dokumentasi `timechart` memakai pola yang sama untuk mengambil lima source dengan nilai puncak tertinggi dan menggabungkan sisanya [S2].

Soal `usenull`: kolom NULL bukan sampah yang perlu disembunyikan. Kolom itu berarti ada event yang sama sekali tidak punya field pemecah, dan pada data keamanan itu biasanya gejala, bukan hiasan. Proxy yang tidak mengisi `user`, firewall yang tidak mengisi `dest` pada paket yang di-drop, atau sourcetype yang salah sehingga field tidak terekstrak. Matikan `usenull` hanya setelah kamu tahu penyebabnya, dan tulis penyebabnya di catatan panel.

### 1.6 Memilih visualisasi: line, column, single value, dan tabel

Permintaan "jangan kirim screenshot tabel 200 baris" sebenarnya permintaan agar bentuknya cocok dengan pertanyaannya. Dokumentasi Splunk mengelompokkan jenis visualisasi beserta kalimat singkat kegunaannya: events list untuk memperlihatkan event yang dihasilkan search, table untuk membandingkan dan mengagregasi nilai field, charts (pie, area, line, column, bar, bubble, scatter) untuk memvisualkan satu dimensi atau lebih, single value untuk memperlihatkan satu metrik agregat dalam konteks, gauges untuk metrik agregat terhadap sebuah rentang, dan maps untuk data berkoordinat geografis [S5].

Tabel berikut menerjemahkan itu menjadi aturan kerja untuk pertanyaan triage. Cari bentuk pertanyaanmu di kolom pertama, lalu pastikan bentuk tabel hasilnya sesuai kolom ketiga.

| Bentuk pertanyaan | Visualisasi | Bentuk tabel hasil yang dibutuhkan |
|---|---|---|
| "Apakah tadi malam tidak wajar dibanding tujuh hari terakhir?" | Line chart | `timechart span=1h` dengan satu atau sedikit seri |
| "Siapa yang paling banyak, dan siapa nomor duanya?" | Column chart (bar bila label panjang) | `chart count OVER <kategori>`, kategori berkardinalitas rendah |
| "Berapa besar porsi tiap kategori dalam satu host?" | Stacked column | `chart count OVER host BY kategori` |
| "Berapa angkanya sekarang, dan naik atau turun?" | Single value | `timechart` untuk satu angka terakhir berikut tren, `stats` untuk total [S6] |
| "Angka mana yang mau kusalin ke tiket?" | Table | `stats` atau `chart`, diurutkan, dengan rentang waktu tertulis |
| "Apakah ada pola yang hanya terlihat kalau dibandingkan minggu lalu?" | Line chart | `timechart` lalu `timewrap` [S4] |

Aturan single value perlu diperhatikan khusus karena paling sering menghasilkan panel yang salah dibaca [S6]:

- Single value bekerja paling baik untuk search yang membuat time series dengan `timechart` atau mengagregasi dengan `stats`.
- Search dengan `timechart` menghasilkan visualisasi yang memperlihatkan hasil paling baru di dalam rentang itu, sedangkan search dengan `stats` memperlihatkan total agregat sepanjang rentang.
- Sparkline muncul secara default di bawah single value yang dihasilkan `timechart`, dan trend indicator muncul di sebelah kanannya. Keduanya hanya tersedia bila search memakai `timechart`.
- Bila hasil search berisi banyak nilai, dashboard editor memakai nilai di sel pertama tabel hasil.

Gabungan dua poin pertama itulah jebakannya: panel berjudul "login gagal 24 jam" yang dibangun dari `timechart span=1h` tidak menampilkan total 24 jam, melainkan angka satu jam terakhir. Bagian 2.5 memperlihatkan dua versinya berdampingan.

### 1.7 Grafik untuk melihat bentuk, angka untuk ditulis

Satu kebiasaan yang membedakan analyst yang catatannya bisa dipercaya: grafik dipakai untuk menemukan tempat yang harus dilihat, lalu angkanya diambil ulang dengan `stats` pada rentang waktu absolut.

Alasannya ada tiga, dan ketiganya muncul di bagian 2. Batas bin memotong satu lonjakan menjadi dua angka yang keduanya bukan ukuran lonjakan itu. Batas sepuluh seri membuat angka di grafik hanya mewakili sebagian data. Dan rentang relatif seperti tujuh hari terakhir berarti grafik yang sama menghasilkan angka berbeda bila dibuka besok. Untuk note tiket, ketiga hal itu fatal, karena orang lain harus bisa mengulang search dan mendapat angka yang sama (Day 07 bagian 1.8).

Jadi pakai urutan ini: `timechart` untuk menemukan jam yang tidak wajar, lalu `stats` dengan `earliest` dan `latest` absolut untuk mendapatkan angka yang masuk ke tiket.

## 2. Contoh SPL dan panel untuk rapat pukul 09:00

Semua keluaran di bagian ini adalah keluaran ilustrasi untuk organisasi fiktif PT JAB, bukan hasil eksekusi. Asumsi data: `index=vpn` dengan field gaya CIM (`user`, `src`, `action` bernilai `success` atau `failure`), `index=firewall` dengan `action`, `src`, `dest`, `dest_port`, `bytes`, `index=dns` dengan `query` dan `host` resolver, dan `index=wineventlog` format XML dengan field dari Splunk Add-on for Microsoft Windows seperti di Day 03. Nama field persis bergantung add-on vendor, jadi cek di instance-mu; log jaringan dibahas di Day 05. Semua search jalan di app Search & Reporting tanpa ES. Waktu ditulis dalam WIB sesuai preferensi zona waktu user.

### 2.1 Bentuk login gagal VPN per jam selama tujuh hari

Ini permintaan pertama SOC lead. Pertanyaannya bukan "berapa", melainkan "apakah bentuk tadi malam berbeda dari malam-malam lain".

**Tujuan:** melihat deret waktu login gagal VPN per jam selama tujuh hari, cukup untuk menilai apakah malam tadi menyimpang.

```
index=vpn action=failure earliest=-7d@h latest=@h
| timechart span=1h count AS gagal
```

| Bagian | Penjelasan |
|---|---|
| `index=vpn action=failure` | Filter paling murah ditaruh paling awal, sebelum command apa pun |
| `earliest=-7d@h latest=@h` | Tujuh hari ke belakang, disnap ke awal jam, supaya bin pertama dan terakhir tidak terisi sebagian [S2] |
| `timechart span=1h` | Lebar bin ditulis eksplisit; tanpa ini, preset Last 7 days memakai span satu hari dan bentuknya hilang [S2] |
| `count AS gagal` | Satu agregasi, tanpa field pemecah, sehingga hasilnya satu seri dan satu garis |

Keluaran ilustrasi (enam baris di sekitar lonjakan, dari 168 baris):

```
_time                 gagal
2026-10-13 23:00      4
2026-10-14 00:00      7
2026-10-14 01:00      104
2026-10-14 02:00      84
2026-10-14 03:00      5
2026-10-14 04:00      3
```

**Cara membaca hasil:** garis dasar malam hari di PT JAB ada di kisaran 3 sampai 10 login gagal per jam, jadi dua bin berurutan bernilai 104 dan 84 memang menyimpang jauh. Yang penting diperhatikan: tidak ada satu bin pun yang bernilai 180. Serangan berlangsung 01:52 sampai 02:06, menyeberangi batas jam, sehingga satu burst terbelah menjadi dua bin. Angka 104 bukan ukuran serangan, dan bila kamu menuliskannya di tiket sebagai "104 percobaan", angkamu salah. Ukuran sebenarnya diambil dengan `stats` pada rentang absolut seperti di Day 07 bagian 2.1.

**Variasi 1, melihat bentuk burst:** perkecil span dan persempit rentang ke sekitar kejadian.

```
index=vpn action=failure earliest="10/14/2026:01:30:00" latest="10/14/2026:02:30:00"
| timechart span=5m count AS gagal
```

Dengan `span=5m`, 12 bin memperlihatkan burst naik dari nol, memuncak, lalu berhenti. Bentuk ini yang membedakan serangan otomatis dari kegagalan konfigurasi yang muncul teratur sepanjang hari.

**Variasi 2, membandingkan dengan hari sebelumnya:** `timewrap` menumpuk periode supaya bisa dibandingkan dalam satu grafik, dan command ini wajib didahului `timechart` [S4].

```
index=vpn action=failure earliest=-3d@d latest=@d
| timechart span=1h count AS gagal
| timewrap d series=short
```

Hasilnya satu kolom per hari (`s0`, `s1`, `s2` dengan `series=short`) dan 24 baris jam, sehingga pola "setiap malam memang ada 5 sampai 10 kegagalan" langsung terlihat sebagai garis yang hampir menumpuk, dengan satu garis yang melonjak. Perhatian: di `timewrap`, `m` berarti bulan, sedangkan di `timechart` dan `bin` `m` berarti menit [S4].

**Variasi 3, sukses dan gagal dalam satu grafik:** `timechart span=1h count BY action` memberi dua seri sehingga login sukses yang menyusul kegagalan terlihat di grafik yang sama. Untuk itu jangan filter `action=failure` di awal.

**Kapan gagal:** bila add-on VPN tidak menormalkan `action`, nilainya bisa `REJECT`, `Login failed`, atau kode angka, sehingga filternya tidak cocok dan grafiknya kosong. Jalankan `index=vpn earliest=-24h | stats count BY action` dulu. Bila rentang tidak disnap, bin pertama dan terakhir terisi sebagian dan tampak seperti penurunan trafik [S2]. Dan pada index yang sangat besar, `span=5m` untuk tujuh hari menghasilkan lebih dari 2.000 bin yang berat digambar dan tidak terbaca.

### 2.2 Memisahkan sinyal: per sumber, dipilih menurut puncak

Grafik 2.1 memperlihatkan ada lonjakan, tetapi tidak memperlihatkan siapa penyebabnya. Pemecahan per sumber menjawab itu, dan sekaligus menjadi contoh terbaik kenapa cara memilih seri penting.

**Tujuan:** melihat lima sumber dengan puncak login gagal tertinggi per jam, bukan lima sumber dengan total terbanyak.

```
index=vpn action=failure earliest=-7d@h latest=@h
| timechart span=1h count BY src WHERE max in top5 usenull=f
```

| Bagian | Penjelasan |
|---|---|
| `BY src` | Setiap nilai `src` menjadi satu seri; batas default sepuluh seri berlaku di sini [S2] |
| `WHERE max in top5` | Kriteria pemilihan seri diganti: lima seri dengan nilai puncak tertinggi, bukan total tertinggi. Dengan klausa `where` eksplisit, `limit` dan `agg` diabaikan [S1] |
| `usenull=f` | Event tanpa field `src` tidak dibuatkan seri NULL [S2]. Dipakai di sini karena PT JAB sudah mengetahui penyebabnya, bukan untuk merapikan grafik |
| Seri OTHER | Tetap muncul karena `useother` default `true`, dan itu memang diinginkan: kolom itu tanda bahwa ada sisa yang tidak digambar [S2] |

Keluaran ilustrasi (empat baris dari 168):

```
_time             10.10.5.21  198.51.100.23  203.0.113.45  203.0.113.51  192.0.2.77  OTHER
2026-10-14 00:00  4           1              0             0             1           1
2026-10-14 01:00  3           0              98            2             0           1
2026-10-14 02:00  0           1              82            0             0           1
2026-10-14 03:00  3           0              0             1             0           1
```

**Cara membaca hasil:** jumlah tiap baris cocok dengan 2.1 (baris 01:00 berjumlah 104, baris 02:00 berjumlah 84), jadi tidak ada data yang hilang, hanya dipecah. `203.0.113.45` menyumbang 98 dan 82, yaitu 180 kegagalan yang disebut di tiket SOC-2026-0217. `10.10.5.21` adalah klien internal salah konfigurasi yang menyumbang beberapa kegagalan setiap jam sepanjang tujuh hari dan puncaknya di jam kerja mencapai puluhan, jadi ia lolos baik dengan kriteria puncak maupun dengan kriteria total. Kolom OTHER bernilai 1 per jam pada baris-baris ini, yang berarti sisanya memang remah dan tidak ada sumber besar yang tersembunyi.

**Variasi 1, melihat efek kriteria:** jalankan ulang tanpa klausa `where`.

```
index=vpn action=failure earliest=-7d@h latest=@h
| timechart span=1h count BY src limit=5
```

Dengan default "lima teratas menurut jumlah", `203.0.113.45` berisiko hilang ke OTHER karena totalnya selama tujuh hari hanya 180, sementara beberapa klien internal yang salah konfigurasi mengumpulkan ribuan kegagalan pelan-pelan. Jalankan keduanya sekali di lingkunganmu sendiri dan simpan dua tangkapan hasilnya; perbedaan itu lebih meyakinkan daripada penjelasan apa pun.

**Variasi 2, memastikan tidak ada yang dipotong:** `limit=0` menampilkan semua seri [S2]. Hasilnya tidak terbaca sebagai grafik bila ada ratusan sumber, tetapi berguna sebagai pemeriksaan sekali jalan, atau sebagai tabel yang diurutkan.

**Variasi 3, memilih dengan ambang:** `WHERE count > 50` hanya menyimpan seri yang pernah melewati 50 dalam satu bin [S2]. Cocok untuk panel pemantauan yang hanya boleh menampilkan hal yang patut dilihat.

**Kapan gagal:** `src` bisa berkardinalitas sangat tinggi pada log perimeter (satu nilai per IP di internet), sehingga pemecahan per `src` membuat search mahal walau yang digambar hanya lima seri; peringkat seri tetap dihitung untuk semua nilai. Pada kasus itu, saring dulu (hanya `action=failure`, hanya gateway tertentu) atau kelompokkan dulu dengan `eval` menjadi subnet. `usenull=f` juga bisa menyembunyikan masalah ekstraksi: bila separuh event tidak punya `src`, yang perlu diperbaiki add-on-nya, bukan grafiknya.

### 2.3 Tujuan koneksi teratas per host di segmen data center

Ini permintaan kedua, dan bentuknya dua dimensi tanpa waktu, jadi `chart` yang dipakai.

**Tujuan:** satu tabel dua dimensi berisi tujuan koneksi teratas (baris) dari lima host tersibuk di segmen data center (kolom), untuk 24 jam terakhir.

```
index=firewall action=allowed src="10.20.0.0/16" earliest=-24h@h latest=@h
| chart count OVER dest BY src limit=5
| addtotals fieldname=total
| sort - total
| head 8
```

| Bagian | Penjelasan |
|---|---|
| `src="10.20.0.0/16"` | Pencocokan CIDR di command `search`, membatasi ke segmen data center PT JAB |
| `chart count OVER dest BY src` | `dest` menjadi kolom pertama dan sumbu X, setiap `src` menjadi satu kolom [S1] |
| `limit=5` | Lima kolom host berskor tertinggi; sisanya digabung ke OTHER karena `useother` default `true` [S1] |
| `addtotals fieldname=total` | Menjumlahkan tiap baris, karena `chart` tidak mengurutkan baris menurut besarnya |
| `sort - total \| head 8` | Mengambil delapan baris terbesar; row-split tidak terpengaruh `limit`, jadi pembatasan baris harus dilakukan sendiri |

Keluaran ilustrasi (delapan baris pertama; lima baris ditampilkan di sini):

```
dest             10.20.10.11  10.20.10.12  10.20.20.5  10.20.30.7  10.20.30.9  OTHER  total
203.0.113.10     4120         3980         0           0           0           640    8740
198.51.100.44    0            0            2610        0           0           120    2730
192.0.2.19       310          290          0           1850        0           0      2450
203.0.113.77     0            0            0           0           1420        0      1420
192.0.2.55       120          140          95          60          80          210    705
```

**Cara membaca hasil:** pola angka nol sama pentingnya dengan angka besar. `203.0.113.10` dihubungi dua host dengan volume mirip, yang wajar untuk dua node layanan yang sama. `203.0.113.77` hanya dihubungi `10.20.30.9` sebanyak 1.420 kali dan tidak oleh host lain; tujuan yang dipakai satu host saja adalah kandidat pemeriksaan, apalagi bila host itu seharusnya kembar dengan `10.20.30.7`. Kolom OTHER memberi tahu bahwa host di luar lima teratas juga menghubungi tujuan-tujuan ini, jadi angka di kolom `total` bukan total segmen.

**Variasi 1, membalik sumbu:** `chart count OVER src BY dest` menjawab pertanyaan yang berbeda, yaitu komposisi tujuan untuk setiap host, dan bentuknya cocok untuk stacked column. Memilih mana yang menjadi row-split berarti memilih pertanyaan, bukan selera tampilan.

**Variasi 2, mengganti metrik:** `chart dc(dest) OVER src` memberi satu angka per host, yaitu jumlah tujuan unik, dan itu sering lebih berguna untuk menemukan scanning daripada jumlah koneksi. Perhatikan bahwa `chart dc(dest) OVER dest` tidak bisa dijalankan karena satu field tidak boleh berada di dalam fungsi sekaligus menjadi row-split [S1]; salin dulu dengan `eval tujuan=dest`.

**Variasi 3, kardinalitas lebih rendah:** untuk panel rapat, `chart count OVER dest_port BY src limit=5` jauh lebih terbaca daripada per `dest`, karena port yang dipakai di satu data center biasanya hanya puluhan.

**Kapan gagal:** `dest` pada log perimeter bisa berisi puluhan ribu nilai, dan `chart` akan mencoba membuat satu baris untuk setiap nilai sebelum `head` jalan, sehingga search berat dan hasilnya tidak terbaca. Saring dulu atau pindah ke field berkardinalitas lebih rendah. Pencocokan CIDR juga gagal bila `src` tidak diekstrak sebagai alamat bersih (misalnya berisi `10.20.10.11:443`); periksa satu event dengan `| table _raw src` lebih dulu. Dan bila sebagian event tidak punya `src`, akan muncul kolom NULL; itu temuan onboarding data, bukan gangguan tampilan (Day 28).

### 2.4 Trafik DNS resolver pelanggan per jam

Permintaan ketiga datang dari NOC lewat SOC lead. Di PT JAB, `index=dns` memuat resolver karyawan dan resolver pelanggan, dan volumenya besar sehingga disampling.

**Tujuan:** melihat volume kueri dan jumlah domain unik per jam selama 24 jam, lalu menentukan apakah lonjakan kemarin siang menyeluruh atau hanya pada satu resolver.

```
index=dns earliest=-24h@h latest=@h
| timechart span=1h count AS kueri dc(query) AS domain_unik
```

| Bagian | Penjelasan |
|---|---|
| Dua agregasi dalam satu `timechart` | Menghasilkan dua seri: volume dan keragaman. Keduanya naik bersama pada lonjakan wajar; volume naik tanpa keragaman naik mengarah ke pengulangan satu nama |
| `dc(query)` | Jumlah nama domain berbeda per jam |
| Tanpa `BY` | Tidak ada field pemecah, jadi batas sepuluh seri tidak berlaku di sini |

Keluaran ilustrasi (lima baris dari 24):

```
_time                kueri      domain_unik
2026-10-13 12:00     2731000    214000
2026-10-13 13:00     2794000    218000
2026-10-13 14:00     4998000    221000
2026-10-13 15:00     2870000    223000
2026-10-13 16:00     2905000    225000
```

**Cara membaca hasil:** volume naik sekitar 79 persen pada bin 14:00 sementara domain unik hampir tidak bergerak (naik dari 218 ribu ke 221 ribu). Lonjakan dengan pola seperti ini bukan lonjakan "semua pelanggan tiba-tiba browsing", melainkan pengulangan sejumlah kecil nama: bisa resolver yang gagal lalu klien mengulang kueri, bisa satu perangkat pelanggan yang membanjiri resolver. Perhatian: karena index ini disampling, angka `kueri` adalah sinyal relatif, bukan volume sebenarnya. Jangan menulis "4,99 juta kueri per jam" di laporan tanpa menyebut faktor samplingnya.

**Variasi 1, menemukan resolver mana:** pecah per resolver, dan pilih seri menurut puncak.

```
index=dns earliest=-24h@h latest=@h
| timechart span=1h count BY host WHERE max in top5
```

Keluaran ilustrasi (tiga baris):

```
_time                bdg-res01  jkt-res01  jkt-res02  sby-res01
2026-10-13 13:00     441000     1020000    975000     378000
2026-10-13 14:00     438000     3180000    981000     399000
2026-10-13 15:00     445000     1035000    988000     402000
```

Hanya `jkt-res01` yang naik lebih dari tiga kali, dan resolver pasangannya `jkt-res02` tidak ikut naik. Dengan itu pertanyaan NOC berubah dari "kenapa trafik DNS naik" menjadi "apa yang terjadi di `jkt-res01` pukul 14:00", yang dijawab dengan `top` per klien pada rentang satu jam itu (Day 02).

**Variasi 2, laju yang bisa dibandingkan:** `timechart span=5m per_minute(count)` membaca kueri per menit, dan nilainya tetap bisa dibandingkan bila nanti span-nya diubah, karena fungsi `per_*` menskalakan nilai menjadi laju untuk span yang dipakai [S2].

**Variasi 3, pengganti yang lebih murah:** untuk keragaman nama, `estdc(query)` jauh lebih ringan daripada `dc(query)`; dokumentasi menyebut `distinct_count`, `values`, dan `list` sebagai fungsi yang memakai memori besar dan menyarankan `estdc` pada kardinalitas yang lebih rendah [S2].

**Kapan gagal:** `dc(query)` pada index DNS tingkat ISP adalah salah satu cara tercepat membuat search head kehabisan memori; batasi rentang dan pertimbangkan `estdc`. Grafik juga menyesatkan bila faktor sampling berubah di tengah rentang, misalnya karena konfigurasi ingest diubah; naik turunnya grafik lalu mencerminkan perubahan sampling, bukan trafik pelanggan. Dan kolom NULL akan muncul bila ada event DNS tanpa `host` resolver, yang berarti ada pengirim log yang belum diberi identitas.

### 2.5 Satu angka untuk layar: single value dengan `timechart` dan dengan `stats`

PT JAB memasang satu panel angka besar di layar SOC. Dua search di bawah tampak serupa dan membaca dua hal yang sama sekali berbeda.

**Tujuan:** memperlihatkan selisih arti antara single value dari `timechart` dan dari `stats`, supaya judul panel tidak berbohong.

```
index=vpn action=failure earliest=-24h@h latest=@h
| timechart span=1h count AS gagal
```

Keluaran ilustrasi (tiga baris terakhir dari 24):

```
_time                gagal
2026-10-14 05:00     6
2026-10-14 06:00     4
2026-10-14 07:00     9
```

Sebagai single value, search ini menampilkan 9, yaitu hasil paling baru di dalam rentang, lengkap dengan sparkline di bawahnya dan trend indicator di sebelah kanan yang membandingkan 9 dengan 4 [S6].

```
index=vpn action=failure earliest=-24h@h latest=@h
| stats count AS gagal
```

Keluaran ilustrasi:

```
gagal
391
```

Sebagai single value, search ini menampilkan 391, yaitu total agregat sepanjang rentang, tanpa sparkline dan tanpa trend indicator [S6].

**Cara membaca hasil:** dua angka itu benar-benar berbeda artinya. Panel berjudul "login gagal 24 jam" yang dibangun dari versi `timechart` menampilkan 9, dan siapa pun yang melihat layar akan menyimpulkan malam itu tenang. Judul harus mengikuti search: "login gagal jam terakhir" untuk versi `timechart`, "login gagal 24 jam" untuk versi `stats`.

**Variasi:** bila kamu ingin total 24 jam sekaligus sparkline, pakai `timechart` lalu `addtotals`, atau buat dua panel berdampingan. Yang tidak bisa adalah menyelipkan `stats` ke dalam query `timechart` dan tetap mengharapkan sparkline, karena sparkline dan trend indicator menuntut search yang memakai `timechart` [S6].

**Kapan gagal:** bila search mengembalikan banyak nilai, dashboard editor memakai nilai di sel pertama tabel hasil [S6], sehingga panel menampilkan angka yang kebetulan berada di baris teratas. Kunci bentuk hasilnya ke satu nilai (`stats count`, atau `timechart` dengan satu agregasi tanpa `BY`) sebelum menjadikannya single value.

### 2.6 Ketika tabel adalah jawaban yang benar

Untuk tiket SOC-2026-0217, yang dibutuhkan L2 bukan grafik, melainkan angka per akun yang bisa disalin ke note. Bentuk pivot dari `chart` cocok untuk itu.

**Tujuan:** satu tabel berisi jumlah gagal dan sukses per akun selama jendela serangan, pada rentang waktu absolut sehingga bisa diulang.

```
index=vpn src="203.0.113.45" earliest="10/14/2026:01:30:00" latest="10/14/2026:02:30:00"
| chart count OVER user BY action usenull=f
| addtotals fieldname=total
| sort - total - success
```

| Bagian | Penjelasan |
|---|---|
| `earliest` dan `latest` absolut | Rentang dikunci di sekitar kejadian, sehingga search bisa diulang besok dengan hasil yang sama. Format default-nya `%m/%d/%Y:%H:%M:%S` |
| `chart count OVER user BY action` | Satu baris per akun, satu kolom per nilai `action`; nilai `failure` dan `success` menjadi nama kolom [S1] |
| `usenull=f` | Event tanpa `action` tidak dibuatkan kolom NULL; di sini sudah dipastikan semua event punya `action` |
| `addtotals` lalu `sort` | Akun dengan percobaan terbanyak di atas, dan di antara yang sama banyak, yang punya `success` lebih dulu |

Keluaran ilustrasi (enam baris pertama dari 25):

```
user              failure  success  total
andi.pratama      8        0        8
budi.santoso      8        0        8
dewi.lestari      8        0        8
eko.saputra       8        0        8
fitri.handayani   8        0        8
rina.wulandari    7        1        8
```

Sembilan belas baris berikutnya bernilai `failure=7`, `success=0`, `total=7`. Totalnya 25 akun, 180 kegagalan (lima akun dengan 8 dan dua puluh akun dengan 7), dan satu keberhasilan, cocok dengan angka di tiket.

**Cara membaca hasil:** kolom `success` yang hanya berisi satu angka satu adalah inti kasusnya, dan justru itu yang paling mudah hilang di grafik. Pada line chart, satu peristiwa di antara 180 tidak terlihat; pada tabel, ia satu kolom tersendiri. Tabel ini yang ditempel ke note tiket, bukan screenshot grafik.

**Variasi:** `chart count OVER user BY action` bisa diganti `stats count(eval(action="failure")) AS gagal count(eval(action="success")) AS sukses BY user` dan hasilnya setara. Bedanya, bentuk `chart` otomatis membuat kolom untuk setiap nilai `action` yang ada, termasuk nilai yang tidak kamu duga, sedangkan bentuk `stats` hanya menghitung yang kamu sebut. Untuk eksplorasi, bentuk `chart` lebih aman; untuk panel tetap dengan nama kolom yang stabil, bentuk `stats` lebih aman.

**Kapan gagal:** bila `action` berisi banyak nilai vendor (`REJECT`, `TIMEOUT`, `AUTH_FAIL`, kode angka), jumlah kolom ikut melonjak dan tabelnya tidak terbaca. Normalkan dulu dengan `eval` (`eval hasil=case(in(action,"failure","REJECT","AUTH_FAIL"),"failure", action=="success","success", true(),"lain")`), lalu pecah menurut field hasil itu. Bila `user` berisi prefix domain pada sebagian event (`JAB\rina.wulandari`), satu akun akan muncul sebagai dua baris; normalkan dulu seperti di Day 07 bagian 2.3.

### 2.7 Tiga dimensi: `bin` ditambah `stats`

Pertanyaan lanjutan dari pemeriksaan Windows: per jam, per host, dan per kode kegagalan. Tiga dimensi, salah satunya waktu, sehingga `timechart` tidak cukup.

**Tujuan:** merangkum 4625 per jam, per host, dan per `SubStatus`, dalam bentuk tabel.

```
index=wineventlog source="XmlWinEventLog:Security" EventCode=4625 earliest=-24h@h latest=@h
| bin _time span=1h
| stats count BY _time host SubStatus
| sort - count
| head 6
```

| Bagian | Penjelasan |
|---|---|
| `bin _time span=1h` | Semua event dalam satu jam diberi nilai `_time` yang sama, sehingga `_time` bisa dipakai sebagai field pemecah biasa [S3] |
| `stats count BY _time host SubStatus` | Tiga dimensi sekaligus, yang tidak bisa dilakukan `timechart` karena hanya menerima satu field pemecah [S2] |
| `sort - count \| head 6` | Kombinasi paling sering di atas |

Keluaran ilustrasi:

```
_time                host         SubStatus   count
2026-10-14 01:00     JKT-JUMP01   0xc000006a  119
2026-10-13 23:00     JKT-JUMP01   0xc000006a  118
2026-10-14 02:00     JKT-JUMP01   0xc000006a  116
2026-10-14 00:00     JKT-JUMP01   0xc000006a  114
2026-10-14 02:00     JKT-FS01     0xc0000064  22
2026-10-14 02:00     JKT-FS01     0xc000006a  4
```

**Cara membaca hasil:** empat baris pertama memperlihatkan pola yang rata, sekitar 114 sampai 119 kegagalan password salah per jam di `JKT-JUMP01` sepanjang malam, yaitu kira-kira satu percobaan setiap 31 detik. Rata dan terus-menerus seperti itu adalah tanda konfigurasi, yaitu kasus `svc_backup` di Day 03, bukan serangan. Baris kelima lain sifatnya: 22 kegagalan dengan `0xc0000064`, yaitu username tidak ada, terkumpul di satu jam di `JKT-FS01`, yang merupakan pola enumerasi akun.

**Variasi:** bila kamu memang butuh grafik dari tiga dimensi, gabungkan dua di antaranya menjadi satu field seri lebih dulu.

```
index=wineventlog source="XmlWinEventLog:Security" EventCode=4625 earliest=-24h@h latest=@h
| eval seri=host.":".SubStatus
| timechart span=1h count BY seri WHERE max in top5
```

Dengan cara ini batas sepuluh seri kembali berlaku, dan jumlah kombinasi `host` dikali `SubStatus` tumbuh cepat, jadi klausa `where` wajib dipikirkan, bukan opsional.

**Kapan gagal:** `bin _time` mengubah `_time` secara permanen di pipeline, jadi setelah itu kamu tidak bisa lagi melihat waktu asli event di baris yang sama; simpan dulu dengan `eval waktu_asli=_time` bila masih dibutuhkan. Pada host yang mengirim format klasik, field `SubStatus` tidak ada dan namanya berbeda (Day 03 bagian 1.1), sehingga baris host itu hilang dari tabel tanpa pesan error. Dan `bin` dengan span satu hari atau lebih disejajarkan ke tengah malam zona waktu user [S3], yang bisa berbeda dari batas bin `timechart` pada data yang sama.

## 3. Lab praktik

Lab memakai tiga sumber: data sintetis dari `makeresults` (untuk memverifikasi perilaku command dengan angka yang bisa dihitung tangan), BOTS v1 (dataset statis, jadi semua search memakai rentang absolut), dan log dari VM lab-mu sendiri. Semua dijalankan di lab terisolasi.

1. **Verifikasi `span` dengan data yang bisa dihitung.** Jalankan search ini, tetapi hitung dulu hasil yang kamu harapkan sebelum menekan enter:

   ```
   | makeresults count=48
   | streamstats count AS n
   | eval _time=strptime("2026-10-07 00:00:00","%Y-%m-%d %H:%M:%S") + (n-1)*1800
   | eval host=if(n<=24,"JKT-WS-0101","JKT-WS-0102")
   | timechart span=1h count BY host
   ```

   Hitungan yang benar: 48 event berjarak 30 menit mulai 00:00 menutupi 23,5 jam, jadi ada 24 bin satu jam dengan dua event per bin. Dua puluh empat event pertama (00:00 sampai 11:30) milik `JKT-WS-0101` dan sisanya milik `JKT-WS-0102`, sehingga 12 baris pertama bernilai 2 pada kolom pertama dan 0 pada kolom kedua, lalu terbalik. Cocokkan dengan keluaran Splunk-mu sebelum lanjut.
2. **Lihat apa yang dilakukan span yang terlalu lebar.** Ulangi langkah 1 dengan `span=4h`, lalu `span=1d`. Catat berapa baris yang keluar dan di mana pergantian host menjadi tidak terlihat. Tulis satu kalimat: span terlebar yang masih memperlihatkan pergantian host.
3. **Buktikan batas sepuluh seri.** Jalankan:

   ```
   | makeresults count=120
   | streamstats count AS n
   | eval _time=strptime("2026-10-07 00:00:00","%Y-%m-%d %H:%M:%S") + (n-1)*600
   | eval host="host-".(n%12)
   | timechart span=1h count BY host
   ```

   Ada 12 nilai `host` dengan 10 event masing-masing, jadi grafik default akan menampilkan 10 seri ditambah OTHER bernilai 20 event total. Catat dua host mana yang masuk OTHER: karena semua seri berskor sama, pemenangnya ditentukan secara leksikografis, dan hasil pengamatan ini lebih dapat dipercaya daripada menebaknya. Ulangi dengan `limit=0`, lalu dengan `useother=f`, dan tulis beda ketiga hasilnya.
4. **Uji seri NULL.** Ubah langkah 3 sehingga sebagian event tidak punya field `host` (misalnya `| eval host=if(n%5==0,null(),"host-".(n%12))`), lalu jalankan dengan `usenull=t` dan `usenull=f`. Hitung sendiri berapa event yang seharusnya masuk kolom NULL dan cocokkan.
5. **Rentang waktu BOTS v1.** README dataset ini tidak menyebut rentang tanggal datanya [S7], jadi tentukan sendiri lebih dulu: `| tstats min(_time) AS awal max(_time) AS akhir where index=botsv1 | eval awal=strftime(awal,"%F %T"), akhir=strftime(akhir,"%F %T")`. Catat hasilnya dan pakai sebagai `earliest` dan `latest` absolut di langkah berikutnya. Jangan memakai rentang relatif pada dataset statis.
6. **Timechart di data nyata yang statis.** Dengan rentang dari langkah 5, jalankan `index=botsv1 | timechart span=1h count BY sourcetype WHERE max in top5`, lalu ulangi dengan default (tanpa klausa `where`). Tulis satu kalimat tentang sourcetype mana yang muncul di satu versi tetapi tidak di versi lain, dan kenapa.
7. **Dua pertanyaan, dua sumbu.** Pada data BOTS v1 atau log lab-mu, buat dua `chart` yang memakai field yang sama tetapi bertukar posisi (`OVER a BY b` dan `OVER b BY a`). Tulis pertanyaan yang dijawab masing-masing dalam satu kalimat.
8. **Panel single value yang jujur.** Buat dua panel single value dari data lab-mu, satu dengan `timechart` dan satu dengan `stats`, lalu beri judul yang tepat untuk masing-masing. Minta orang lain membaca judulnya dan menebak angkanya; bila tebakannya salah, judulnya yang perlu diperbaiki.
9. **Dari grafik ke angka tiket.** Ambil satu lonjakan dari langkah 6, lalu tulis dua baris note gaya Day 07: satu baris menyebut jam yang tidak wajar (dari grafik) dan satu baris menyebut angka pasti beserta rentang absolutnya (dari `stats`).

**Hasil yang sebaiknya tersimpan:**
- Keluaran langkah 1 dan 3 yang cocok dengan hitungan manual, beserta dua host yang masuk OTHER.
- Satu kalimat per langkah 2, 6, dan 7.
- Dua tangkapan hasil dari langkah 3 (default dan `limit=0`) sebagai pengingat visual batas sepuluh seri.
- Rentang waktu BOTS v1 yang terverifikasi di lab-mu.
- Dua baris note dari langkah 9.

**Variasi tantangan:** ulangi langkah 6 dengan `span` yang berbeda (`5m`, `1h`, `1d`) dan catat pada span berapa lonjakan yang kamu temukan di `5m` menjadi tidak terlihat. Angka itu adalah batas resolusi praktis untuk jenis data itu, dan berguna saat menentukan span panel pemantauan nanti.

## 4. Troubleshooting

Tabel ini memuat gejala yang paling sering muncul saat membuat chart dan panel. Cari gejalanya di kolom pertama.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Tab Visualization kosong padahal ada hasil | Search tidak memakai transforming command (`table`, `fields`, atau hanya filter) | Tambahkan `stats`, `chart`, atau `timechart` [S5] |
| Host atau tujuan yang dicari tidak ada di grafik | Batas sepuluh seri; nilainya tersapu ke OTHER [S1][S2] | Naikkan `limit`, atau pilih seri dengan `WHERE max in topN` |
| Drilldown pada OTHER tidak menghasilkan event | OTHER adalah nama seri buatan command, bukan nilai field [S1][S2] | Jalankan ulang dengan `limit=0` atau saring di luar sepuluh nilai teratas |
| Muncul kolom NULL | Ada event tanpa field pemecah [S1][S2] | Cari penyebabnya di ekstraksi atau add-on dulu, baru pertimbangkan `usenull=f` |
| Bin pertama dan terakhir selalu lebih pendek | Partial bin, karena rentang search tidak sejajar batas bin [S2] | Snap rentangnya (`-7d@h` sampai `@h`) atau pakai `partial=false` |
| Bin harian tidak mulai tengah malam | `span=86400s` memakai snap turun dari waktu paling awal [S2] | Pakai `span=1d`, atau geser dengan `aligntime` |
| `span` yang ditulis diabaikan | `bins` dan `span` diberikan bersamaan, `span` menang [S2] | Hapus salah satu; untuk kontrol penuh pakai `span` |
| Nama kolom menjadi `VALUE_<nama>` | Field pemecah namanya dimulai garis bawah [S2] | Tambahkan `\| rename VALUE_* AS *` |
| Error karena field dipakai dua kali | Satu field berada di dalam fungsi sekaligus menjadi row-split [S1] | Salin dulu: `eval tujuan=dest`, lalu pakai salinannya |
| `timechart` menolak dua field pemecah | Hanya satu klausa `BY` yang diizinkan [S1][S2] | Pakai `bin` ditambah `stats`, atau gabungkan dua field dengan `eval` |
| Garis grafik berlubang | Bin kosong dan pengaturan null value di panel | Biarkan `cont=true` supaya waktu jujur, lalu atur perlakuan null di format panel |
| Grafik terlalu padat dan tidak terbaca | Span terlalu kecil untuk rentang yang lebar | Lebarkan span, atau persempit rentang dan pertahankan span kecil |
| `timechart` setelah `tstats` kosong atau aneh | `prestats=true` belum dipakai, atau span `tstats` lebih besar dari span `timechart` | Lihat Day 25 bagian 2.3 |
| Single value menampilkan angka yang tidak diduga | Search mengembalikan banyak nilai; dashboard editor memakai sel pertama [S6] | Pastikan hasilnya satu nilai, atau pilih antara `timechart` dan `stats` sesuai arti yang kamu mau |
| Sparkline dan trend indicator tidak muncul | Search tidak memakai `timechart` [S6] | Ubah ke `timechart`, atau terima bahwa panel itu menampilkan total |
| Satu event dihitung dua kali | Field pemecah multivalue, misalnya `Account_Name` format klasik | Coba `dedup_splitvals=true` [S1], atau pecah field-nya dulu seperti di Day 03 bagian 2.3 |

## 5. Kesalahan umum dan jebakan

- Membaca nilai satu bin sebagai ukuran satu burst. Lonjakan yang menyeberangi batas jam terbelah menjadi dua angka yang keduanya bukan ukuran lonjakan itu (bagian 2.1). Angka untuk tiket diambil dengan `stats` pada rentang absolut.
- Menganggap grafik menampilkan semua host atau semua tujuan. Default-nya sepuluh seri [S1][S2], dan tidak ada peringatan di layar selain kolom OTHER.
- Memakai `useother=false` untuk merapikan grafik. Itu menghapus satu-satunya tanda bahwa data dipotong, tanpa menaikkan batasnya.
- Mencari `dest="OTHER"` atau `host="OTHER"` di search lanjutan. OTHER nama seri, bukan nilai field [S1][S2].
- Memilih seri dengan kriteria default pada pertanyaan keamanan. "Sepuluh teratas menurut jumlah" memihak host berisik, dan penyerang yang menyala 14 menit biasanya kalah (bagian 2.2).
- Mematikan `usenull` sebelum tahu kenapa ada kolom NULL. Kolom itu sering gejala parsing atau onboarding yang perlu tiket sendiri.
- Memakai span default pada rentang lebar lalu menyimpulkan tidak ada lonjakan. Pada preset Last 7 days, span default-nya satu hari [S2].
- Memberi judul panel single value tidak sesuai searchnya. Versi `timechart` memperlihatkan hasil terbaru, versi `stats` memperlihatkan total [S6].
- Memakai `span=86400s` untuk batas harian. Bin disnap turun dari waktu paling awal, jadi batasnya bisa tidak jatuh di tengah malam lokal; pakai `span=1d` [S2].
- Mengira `m` punya arti yang sama di semua command. Di `timechart` dan `bin`, `m` berarti menit; di `timewrap`, `m` berarti bulan [S4].
- Memakai `dc()` pada field berkardinalitas sangat tinggi tanpa membatasi rentang. Dokumentasi menyebut fungsi ini berat dan menyarankan `estdc` pada kasus yang cocok [S2].
- Memakai `cont=false` supaya grafik terlihat penuh. Bin yang tidak bersambung ditempelkan berdampingan [S1][S2], sehingga sumbu waktunya tidak lagi mewakili waktu.
- Memakai rentang relatif pada dataset statis seperti BOTS. Tentukan rentang absolutnya lebih dulu dan pakai itu.
- Menyimpan screenshot grafik sebagai bukti di tiket. Lampirkan tabel angka beserta search dan rentang waktu absolutnya, supaya orang lain bisa mengulang dan mendapat hasil yang sama.
- Memecah per field berkardinalitas tinggi (`dest` publik, `query` DNS) hanya untuk menampilkan lima seri. Peringkat seri tetap dihitung untuk semua nilai, jadi biayanya tidak ikut mengecil.

## 6. Catatan terkini

Bagian ini menampung detail versi dan angka default yang berbeda antar command. Isinya tidak mengubah cara kerja, tetapi menjelaskan kenapa angka yang mirip tidak selalu sama.

- Tiga nilai default `bins` yang berbeda: 300 untuk opsi bin di `chart` [S1], 100 untuk `timechart` [S2], dan 100 untuk command `bin` yang diatur di stanza `[discretize]` pada `limits.conf` [S3]. Jangan menyalin asumsi dari satu command ke command lain.
- Batas sepuluh seri disebut sebagai nilai default di dokumentasi `chart` dan `timechart` [S1][S2], dan diubah dengan `limit` atau klausa `where`, bukan dengan `useother`.
- Dokumentasi `chart` 10.6 menulis opsi `dedup_splitvals` di bagian sintaks, tetapi contohnya memakai `dedup_splitval` tanpa huruf s [S1]. Cek ejaan yang diterima di versi instance-mu sebelum memakainya di objek yang disimpan.
- Halaman Visualization reference 10.6 memberi satu kalimat kegunaan per jenis visualisasi dan tidak membedakan kapan line lebih tepat daripada column [S5], jadi tabel pemilihan di bagian 1.6 adalah praktik kerja, bukan aturan produk.
- Aturan sparkline dan trend indicator pada single value hanya berlaku bila search memakai `timechart` [S6]. Di Dashboard Studio, nama dan letak pengaturannya berbeda dari Classic; pembuatan dashboard beserta perbedaan keduanya dibahas di Day 09.
- `timewrap` menyediakan `series=relative` (default, menghasilkan nama seperti `latest_week` dan `1week_before`), `series=exact` yang memakai `time_format`, dan `series=short` yang menghasilkan `s0` dan `s1` [S4]. Nama seri ini sering dipakai di panel pembanding, jadi pilih satu gaya dan pertahankan.
- Dokumentasi resmi kini di help.splunk.com, dan tautan docs.splunk.com lama masih beredar untuk halaman yang sama.

## 7. Cheat sheet

```
BENTUK DASAR
  stats     count BY a b                  -> tabel, tanpa sumbu
  chart     count OVER a BY b             -> baris = a, kolom = b (maks 10 kolom)
  chart     count BY a b                  -> sama dengan OVER a BY b
  timechart span=1h count BY b            -> baris = _time, seri = b (maks 10 seri)
  bin _time span=1h | stats count BY _time a b   -> tiga dimensi, bentuk tabel

BATAS SERI (penyebab kesimpulan salah paling sering)
  default               : top 10 menurut jumlah; sisanya OTHER; event tanpa field -> NULL
  limit=0               : semua seri        limit=bottom5 : lima terendah
  useother=f            : hilangkan OTHER (batas tetap 10)   otherstr=<nama>
  usenull=f             : hilangkan NULL (cek dulu penyebabnya)  nullstr=<nama>
  WHERE max in top5     : pilih menurut puncak, bukan total (untuk keamanan)
  WHERE count > 50      : pilih menurut ambang
  klausa WHERE eksplisit membuat limit dan agg diabaikan

WAKTU
  span=1h 5m 1d 1w@w    ; span=1d untuk batas hari (BUKAN 86400s)
  bins default          : chart 300 | timechart 100 | bin 100
  span + bins bersama   : span menang
  partial=f             : buang bin pertama/terakhir yang terisi sebagian
  cont=true (default)   : celah waktu tetap digambar
  aligntime=@d+5h       : geser titik awal bin (diabaikan untuk d/mon/y)
  per_minute(count)     : ubah nilai menjadi laju; tidak menentukan span
  timechart ... | timewrap d series=short   : tumpuk periode (m = BULAN di timewrap)

MEMILIH VISUALISASI
  tren terhadap waktu          -> line / area      (timechart)
  perbandingan antar kategori  -> column / bar     (chart OVER kategori)
  komposisi per kategori       -> stacked column   (chart OVER a BY b)
  satu angka + arah            -> single value     (timechart = nilai terbaru + sparkline)
  satu angka total             -> single value     (stats = total, tanpa sparkline)
  angka untuk disalin ke tiket -> table            (stats/chart + rentang absolut)

JEBAKAN
  satu burst bisa terbelah dua bin        ambil angka final dengan stats + rentang absolut
  field tidak boleh di fungsi + row-split chart dc(dest) OVER dest -> eval tujuan=dest dulu
  timechart hanya satu BY                 pakai bin+stats atau eval gabungan
  nama kolom VALUE_*                      rename VALUE_* AS *
  dataset statis (BOTS)                   rentang absolut, bukan -7d
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Grafik `timechart span=1h count` memperlihatkan puncak 104 pada bin 01:00. Rekanmu menulis di tiket: "terjadi 104 percobaan login gagal". Tepat?

<details><summary>Jawaban</summary>

Tidak. Nilai satu bin adalah jumlah event di dalam jendela waktu bin itu, bukan ukuran satu rangkaian aktivitas. Serangan yang berlangsung 01:52 sampai 02:06 menyeberangi batas jam, sehingga terbelah menjadi 104 dan 84, dan tidak ada satu bin pun yang menunjukkan 180. Angka yang masuk tiket harus diambil dengan `stats` pada rentang absolut yang menutupi seluruh rangkaian. Lihat bagian 1.7 dan 2.1.

</details>

**2. Skenario keputusan.** Panel "login gagal per host" memperlihatkan sepuluh seri ditambah OTHER, dan host yang sedang kamu investigasi tidak ada di antaranya. Rekanmu menambahkan `useother=f` supaya grafiknya bersih. Apa yang kamu lakukan?

- A. Setuju, karena OTHER memang membuat grafik sulit dibaca dan host yang hilang berarti tidak penting.
- B. Naikkan batas serinya (`limit=0` untuk memeriksa, atau `WHERE max in top5` untuk panel tetap), dan pertahankan `useother` supaya tetap terlihat bila masih ada sisa yang dipotong.
- C. Tambahkan `host="<host yang dicari>"` ke panel supaya pasti muncul.

<details><summary>Jawaban</summary>

B. Masalahnya batas sepuluh seri, dan `useother` tidak mengubah batas itu; mematikannya hanya menghapus tanda bahwa ada data yang dipotong. `limit=0` dipakai sekali untuk memastikan apa yang hilang, lalu untuk panel tetap pilih seri dengan kriteria yang sesuai pertanyaan keamanan, misalnya puncak tertinggi. A keliru karena host bisa tersapu ke OTHER justru karena totalnya kecil, dan aktivitas penyerang memang berdurasi pendek. C bukan jawaban untuk panel pemantauan: menyaring satu host membuat panel tidak bisa lagi menemukan host lain yang bermasalah, walau untuk pemeriksaan satu kasus cara itu sah. Lihat bagian 1.5 dan 2.2.

</details>

**3. Pertanyaan jebakan.** "Kolom NULL di grafik itu sampah hasil event rusak, jadi selalu pakai `usenull=f`." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Kolom NULL berarti ada event yang sama sekali tidak punya field pemecah, dan pada data keamanan itu biasanya gejala: add-on tidak mengekstrak field, sourcetype salah, atau perangkat tidak mengirim atribut itu. Menyembunyikannya membuat masalah data tidak pernah diperbaiki, dan grafik tampak lengkap padahal sebagian event tidak terwakili. Matikan `usenull` hanya setelah penyebabnya diketahui dan dicatat. Lihat bagian 1.5.

</details>

**4. Jelaskan ulang.** Jelaskan kepada network engineer NOC PT JAB dalam tiga kalimat kapan ia memakai `chart` dan kapan `timechart`, dan kenapa `span` harus ditulis sendiri.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Pakai `timechart` kalau pertanyaanmu tentang bentuk sesuatu terhadap waktu, karena sumbu X-nya otomatis `_time`, dan pakai `chart` kalau dua dimensimu bukan waktu, misalnya tujuan koneksi per host. Di `chart` kamu memilih sendiri mana yang jadi baris lewat `over` dan mana yang jadi kolom lewat `by`, sedangkan `timechart` hanya menerima satu field pemecah karena satu dimensi sudah dipakai waktu. Tulis `span` sendiri karena kalau tidak, Splunk memilih lebar bin dari rentang waktunya, dan pada rentang tujuh hari span default satu hari akan melumat lonjakan 14 menit sampai tidak terlihat."

Kesalahan yang sering muncul:
- Menjelaskan `chart` dan `timechart` sebagai dua jenis grafik, padahal keduanya command yang membentuk tabel hasil.
- Lupa menyebut bahwa `timechart` hanya menerima satu field pemecah.
- Menyebut span hanya soal tampilan, padahal span menentukan apakah sebuah lonjakan ada atau tidak di hasil.

</details>

**5. Skenario keputusan.** Layar SOC menampilkan panel single value berjudul "Login gagal VPN 24 jam" yang dibangun dari `index=vpn action=failure earliest=-24h@h latest=@h | timechart span=1h count`. Panel menunjukkan 9, dan SOC lead menyimpulkan malam itu tenang. Apa yang kamu perbaiki?

- A. Tidak ada yang salah; 9 adalah angka 24 jam terakhir dan memang tenang.
- B. Judulnya atau searchnya. Versi `timechart` memperlihatkan nilai bin terbaru, jadi pilih: ubah judul menjadi "login gagal jam terakhir", atau ganti search menjadi `stats count` bila yang dimaksud total 24 jam.
- C. Ganti visualisasinya menjadi line chart supaya tidak ada yang salah paham.

<details><summary>Jawaban</summary>

B. Single value dari search `timechart` memperlihatkan hasil paling baru di dalam rentang, sedangkan single value dari `stats` memperlihatkan total agregat sepanjang rentang. Panel itu menampilkan satu jam terakhir, bukan 24 jam, jadi judul dan search harus disepakati. A keliru karena 9 adalah hitungan satu bin, dan total 24 jamnya jauh lebih besar. C menghindari masalah, bukan memperbaikinya, dan menghilangkan fungsi panel angka besar yang memang dibutuhkan di layar. Lihat bagian 1.6 dan 2.5.

</details>

**6. Pertanyaan jebakan.** "`chart count OVER dest BY src limit=5` berarti hasilnya paling banyak lima baris." Benarkah?

<details><summary>Jawaban</summary>

Tidak. `limit` berlaku untuk column-split, yaitu jumlah kolom atau seri, bukan untuk row-split. Dengan `limit=5` kamu mendapat lima kolom `src` ditambah OTHER, sementara jumlah barisnya tetap sebanyak nilai `dest` yang ada, yang di log perimeter bisa ribuan. Pembatasan baris dilakukan sendiri, misalnya dengan `addtotals` lalu `sort - total` lalu `head`, atau dengan memilih field row-split yang kardinalitasnya lebih rendah. Lihat bagian 1.2, 1.5, dan 2.3.

</details>

**7. Interview question (English).** "How do you decide between stats, chart and timechart, and how do you pick the right visualization?"

<details><summary>Sample answer</summary>

"I start from the question, not the chart. If I just need numbers to put in a ticket, `stats` is enough, because it gives me one row per combination and I can quote it with an absolute time range. If the question has two dimensions that aren't time, like top destinations per host, I use `chart` with `over` for the row axis and `by` for the series, and that becomes a column chart. If the question is about shape over time, like whether last night's failed logins were abnormal, I use `timechart` and I always set the span explicitly, because on a seven day range the default span is one day and a fourteen minute burst simply disappears. The thing I check every single time is the series limit: `chart` and `timechart` only show ten series by default and quietly roll everything else into OTHER, and for security questions the default ranking by total favours noisy hosts, so I usually select series by peak instead, with a where clause. And whatever the chart shows, the number I write in the note comes from a `stats` search over an absolute time range, because a bucket boundary can split one burst into two values and neither of them is the real figure."

What makes this answer strong: it ties command choice to the question rather than to taste, names the span and series-limit traps with concrete consequences, shows awareness that default ranking is wrong for security use cases, and separates exploration from the evidence that goes into a ticket.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Splunk Enterprise 10.6 Search Reference: chart | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/chart | primer | diakses 2026-10-14 | Tinggi. Sintaks `OVER`/`BY`, row-split dan column-split, `limit` default top 10, batas sepuluh kolom, `useother`, `usenull`, `otherstr`, `nullstr`, klausa `where`, opsi bin dengan `bins` default 300, `cont`, `sep`, `format`, `dedup_splitvals` |
| S2 | Splunk Enterprise 10.6 Search Reference: timechart | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/timechart | primer | diakses 2026-10-14 | Tinggi. `bins` default 100, span default per preset time picker, satu klausa `BY`, `limit`, `useother`, `usenull`, klausa `where`, `partial`, `cont`, `fixedrange`, fungsi `per_*`, snap span dan `aligntime`, prefix `VALUE_`, catatan `dc` dan `estdc` |
| S3 | Splunk Enterprise 10.6 Search Reference: bin | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/bin | primer | diakses 2026-10-14 | Tinggi. Alias `bucket`, `bins` default 100 di stanza `[discretize]`, penyejajaran ke tengah malam untuk span harian, `aligntime`, `start`/`end`, saran memakai `bin` hanya untuk yang tidak bisa dikerjakan `chart` dan `timechart` |
| S4 | Splunk Enterprise 10.6 Search Reference: timewrap | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/timewrap | primer | diakses 2026-10-14 | Tinggi. Keharusan memakai `timechart` lebih dulu, opsi `align`, `series`, `time_format`, dan catatan `m` berarti bulan |
| S5 | Splunk Enterprise 10.6: Visualization reference | https://help.splunk.com/en/splunk-enterprise/create-dashboards-and-reports/simple-xml-dashboards/10.6/get-started-with-visualizations | primer | diakses 2026-10-14 | Tinggi untuk daftar jenis visualisasi dan satu kalimat kegunaan masing-masing. Tidak membedakan kapan line lebih tepat daripada column |
| S6 | Splunk Enterprise 10.6: Generate a single value | https://help.splunk.com/en/splunk-enterprise/create-dashboards-and-reports/simple-xml-dashboards/10.6/single-value/generate-a-single-value | primer | diakses 2026-10-14 | Tinggi. Beda arti single value dari `timechart` dan dari `stats`, syarat sparkline dan trend indicator, perilaku sel pertama di dashboard editor |
| S7 | GitHub splunk/botsv1 | https://github.com/splunk/botsv1 | primer | 2016 (dataset); diakses 2026-10-14 | Tinggi. Lisensi CC0, daftar add-on pembuat dataset, dan contoh `index=botsv1 earliest=0`. README tidak menyebut rentang tanggal data |

**Catatan sumber:** tabel pemilihan visualisasi di bagian 1.6 adalah praktik kerja yang disusun untuk catatan ini; dokumentasi hanya memberi satu kalimat kegunaan per jenis visualisasi [S5]. Pernyataan bahwa drilldown pada OTHER tidak menghasilkan event adalah konsekuensi langsung dari dokumentasi yang menyebut OTHER sebagai nama seri yang dibuat command [S1][S2], bukan kutipan dari halaman tersendiri; buktikan sendiri dengan langkah 3 di bagian 3. Semua angka di keluaran ilustrasi disusun agar konsisten dengan tiket SOC-2026-0217 di Day 07 dan bisa dijumlahkan ulang, tetapi bukan hasil eksekusi. Rentang tanggal BOTS v1 tidak disebut di README-nya [S7], jadi rentang absolut untuk dataset itu ditentukan di lab.
