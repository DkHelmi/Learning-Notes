---
day: 22
title: 'Membuat data model dan memakai Pivot: dataset, constraint, dan jenis attribute'
researched_on: 2026-10-14
versions_checked: 'Splunk Enterprise 10.6 (Knowledge Manager Manual: About data models, Design data models, Define dataset fields, Manage datasets, Dataset types and usage, Accelerate data models; Pivot Manual: Design pivot tables with the Pivot Editor; Search Reference: datamodel, pivot)'
---

# Day 22: Membuat data model dan memakai Pivot

Cakupan: membangun data model sendiri untuk sumber log yang tidak punya model siap pakai, mulai dari jenis dataset (root event, root search, root transaction, child), constraint dan pewarisan field, lima jenis attribute (auto-extracted, eval expression, lookup, regular expression, dan geo IP), sampai memakainya lewat Pivot editor dan halaman Datasets.

## Ide inti

Semua yang kamu pelajari sampai Day 21 adalah cara menjawab pertanyaanmu sendiri. Data model adalah cara menjawab pertanyaan orang lain tanpa kamu harus hadir. Dokumentasi menyebutnya pemetaan pengetahuan semantik berjenjang atas satu atau lebih kumpulan data, yang dipakai Splunk untuk menghasilkan laporan bagi pengguna Pivot, dan padanan paling dekat adalah skema basis data untuk Pivot [S1]. Praktisnya: kamu yang paham index, sourcetype, regex, dan lookup menuangkan pemahaman itu satu kali ke dalam sebuah struktur, lalu orang yang tidak menulis SPL bisa mengajukan pertanyaan di atasnya lewat antarmuka menyerupai pivot table.

Strukturnya punya tiga lapis yang perlu dibedakan sejak awal. Dataset menentukan event mana yang masuk, lewat constraint. Attribute (di antarmuka disebut field) menentukan kolom apa yang tersedia, dan ada lima jenis attribute dengan cara kerja berbeda. Pivot menentukan bagaimana pengguna menyusun pertanyaan di atas keduanya. Kesalahan paling mahal di Day ini bukan salah menulis regex, melainkan salah memilih jenis dataset: root transaction dataset dan turunannya tidak bisa di-accelerate [S2][S9], jadi keputusan di menit pertama menentukan apakah model itu akan cepat atau selamanya lambat.

Kamu sudah mengenal pola ini dari dua arah. Data model adalah template laporan baku yang diisi dari banyak vendor: siapa pun boleh memakainya, tetapi isinya hanya sebaik field dan tag yang benar di setiap sumber. Pivot adalah pivot table di spreadsheet, dengan satu batas penting: ia hanya bisa membaca field yang sudah didefinisikan di data model, sehingga field yang kamu lupa definisikan tidak ada untuk pengguna Pivot, walau ada di `_raw`.

```
Data model  (satu objek, punya permission sendiri)
  |
  +-- Root event dataset        constraint = bagian filter sebuah search      BISA di-accelerate
  |     |                       contoh: index=linux sourcetype=jab:portal:access
  |     +-- Child dataset       constraint tambahan, mewarisi semua field parent
  |     +-- Child dataset
  |
  +-- Root search dataset       search string bebas (harus search index event) accelerate HANYA bila streaming
  |
  +-- Root transaction dataset  menggabungkan dataset lain dalam model yang sama   TIDAK bisa di-accelerate
  |
  +-- Attribute per dataset:
        Inherited  : turun dari parent, plus field default
        Extracted  : auto-extracted (hanya boleh ditambahkan di root dataset)
        Calculated : eval expression, regular expression, lookup, geo IP

Pemakaian:
  Datasets (bilah Apps)  -> Explore > Visualize with Pivot      (tanpa SPL)
                         -> Explore > Investigate in Search     (pakai command from)
  SPL                    -> | datamodel <model> <dataset> search
                         -> | pivot <model> <dataset> ...
```

Situasi yang dipakai sepanjang Day ini: di PT Jaringan Anak Bangsa (PT JAB, ISP menengah fiktif), dua aplikasi internal tidak punya add-on dan tidak masuk model standar mana pun, yaitu portal pelanggan di `jkt-portal01` dan aplikasi billing di `jkt-billing01`, keduanya mengirim log ke index `linux`. Tiket SOC-2026-0251 dibuka setelah ada laporan percobaan pengambilalihan akun portal. SOC lead menulis:

> "Dua hal. Pertama, tim fraud dan analyst L1 terus menanyakan hal yang sama ke kita: login gagal portal per segmen pelanggan, pembayaran yang gagal berulang, akses dari negara yang tidak wajar. Mereka tidak akan belajar SPL, jadi mereka butuh bisa bertanya sendiri. Kedua, log portal dan billing ini tidak tercakup model standar yang kita pakai untuk firewall dan Windows, jadi jangan dipaksakan ke sana. Buat satu struktur sendiri, tapi jangan sampai nanti tidak bisa di-accelerate seperti percobaan tahun lalu yang akhirnya kita matikan."

Permintaan itu memuat enam pertanyaan:

1. Apa sebenarnya yang dibuat, dan kenapa bukan sekadar beberapa saved search?
2. Jenis dataset mana yang dipakai untuk portal dan untuk billing?
3. Constraint seperti apa yang benar, dan apa yang diwarisi child dataset?
4. Field apa yang perlu didefinisikan, dan dari jenis attribute mana masing-masing?
5. Bagaimana tim fraud memakainya tanpa menulis SPL?
6. Apa yang menentukan apakah model ini bisa di-accelerate nanti?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4 dan 1.5, pertanyaan 5 di bagian 1.6 dan 1.7, dan pertanyaan 6 di bagian 1.8. Bagian 2 membangun modelnya sampai bisa dipakai, baik dari Pivot maupun dari SPL.

**Kapan relevan:** ketika sebuah sumber data dipakai berulang oleh orang yang tidak menulis SPL, ketika kamu ingin satu definisi field dipakai sama oleh semua laporan, dan ketika sumber log tidak punya model standar sehingga normalisasi ke model bersama bukan pilihan.

**Kapan bukan jawaban:** untuk sumber log yang umum (Windows, firewall, proxy, DNS, autentikasi), menormalkan ke CIM jauh lebih berharga daripada membuat model sendiri, karena detection dan dashboard yang sudah ada langsung ikut bekerja; itu dibahas di Day 23 dan Day 24. Data model juga bukan alat untuk mempercepat search dengan sendirinya: kecepatan datang dari acceleration beserta syaratnya (Day 26) dan dari `tstats` yang membaca summary-nya (Day 25). Untuk pertanyaan sekali pakai, search biasa tetap lebih murah daripada membangun dataset baru.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (index, sourcetype, field extraction, lookup, event type, tag, knowledge object, permission) tidak diulang di sini. Tabel ini hanya memuat istilah yang dipakai Day ini; cari kolom padanan bila sebuah istilah terasa asing.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Data model | Pemetaan pengetahuan berjenjang atas satu atau lebih kumpulan data, dipakai untuk menghasilkan laporan bagi pengguna Pivot [S1] | Template laporan baku yang diisi dari banyak sumber |
| Dataset | Satu bagian data di dalam model, dulu disebut data model object [S1][S6] | Satu lembar kerja di dalam template laporan |
| Root event dataset | Dataset puncak yang didefinisikan satu atau lebih constraint [S1][S2] | Filter dasar laporan: perangkat dan jenis log mana yang dihitung |
| Root search dataset | Dataset puncak yang didefinisikan sebuah search string bebas [S1][S2] | Kueri khusus yang hasilnya dipakai sebagai dasar laporan |
| Root transaction dataset | Dataset puncak yang mengelompokkan event berurutan menjadi satu kesatuan [S1][S2] | Rekonstruksi satu sesi dari banyak baris log |
| Child dataset | Himpunan yang lebih sempit dari parent, menambah constraint [S1][S2] | Sheet turunan yang memfilter lagi dari sheet induk |
| Constraint | Bagian filter sebuah search yang menentukan event mana yang masuk dataset [S2] | Kriteria baris yang ikut dihitung di laporan |
| Attribute (field) | Kolom yang tersedia bagi pengguna Pivot di sebuah dataset [S3] | Kolom di template laporan |
| Inherited, Extracted, Calculated | Tiga kategori field di editor: warisan parent, auto-extracted, dan hasil perhitungan [S3] | Kolom warisan, kolom asli, dan kolom formula |
| Auto-extracted | Field yang sudah terekstrak saat index time atau search time, hanya bisa ditambahkan di root dataset [S3] | Kolom yang sudah ada di file sumber |
| Eval Expression | Field hasil ekspresi `eval` di definisi field [S3] | Kolom formula di spreadsheet |
| Regular Expression | Field hasil regex atas data event; satu regex bisa menghasilkan beberapa field [S3] | Kolom hasil parsing teks |
| Lookup | Field yang masuk lewat lookup, dikaitkan ke field yang sudah ada di dataset [S3] | Kolom hasil VLOOKUP ke tabel referensi |
| Geo IP | Jenis lookup yang menambahkan latitude, longitude, country, dan city untuk event dengan field IP yang valid [S3] | Kolom lokasi dari alamat IP |
| Flag Required dan Hidden | Penanda per dataset: Required membuang event yang tidak punya field itu, Hidden menyembunyikan field dari pengguna Pivot [S3] | Kolom wajib ada vs kolom kerja yang tidak dicetak |
| Pivot editor | Antarmuka penyusun tabel dari dataset tanpa menulis SPL [S4] | Pivot table di spreadsheet |
| Elemen Pivot | Empat kategori penyusun: Filters, Split Rows, Split Columns, Column Values [S4] | Filter, baris, kolom, dan nilai di pivot table |
| Halaman Datasets | Daftar dataset yang bisa kamu akses, beserta jenis, pemilik, dan status sharing [S5] | Daftar laporan tersedia beserta pemiliknya |
| Acceleration | Ringkasan berperforma tinggi atas rentang waktu tertentu untuk mempercepat pivot dan chart [S1][S9] | Counter yang sudah diagregasi di belakang |

### 1.1 Data model adalah skema untuk orang lain

Permintaan "mereka butuh bisa bertanya sendiri" adalah inti perbedaan antara saved search dan data model.

Saved search menjawab satu pertanyaan. Setiap pertanyaan baru butuh orang yang bisa menulis SPL. Data model tidak menjawab pertanyaan apa pun; ia mendefinisikan ruang pertanyaan yang bisa diajukan, lalu Splunk yang menghasilkan laporannya untuk pengguna Pivot [S1]. Dokumentasi menyebut yang membangun dan merawatnya adalah knowledge manager, yaitu orang yang memahami datanya dan akrab dengan bahasa search Splunk [S1]. Di PT JAB, itu kamu, bukan tim fraud.

Tiga konsekuensi yang perlu diterima bersama keuntungannya:

- Model itu satu objek yang bisa diberi permission, dan permission model berlaku untuk semua dataset di dalamnya [S1]. Jadi keputusan siapa yang boleh melihat log portal diambil sekali di tingkat model, bukan per laporan.
- Pengguna Pivot hanya bisa memakai field yang didefinisikan di dataset [S3]. Field yang ada di `_raw` tetapi tidak didefinisikan tidak ada untuk mereka. Ini membatasi, dan pembatasan itulah yang membuat hasilnya bisa dipercaya.
- Desainnya dimulai dari kebutuhan pengguna, bukan dari bentuk log. Dokumentasi menyebut praktik merancang model dengan memulai dari apa yang ingin dikerjakan pengguna Pivot [S2].

Yang perlu dicek sebelum mulai: apakah sumber datanya benar-benar tidak punya model standar. Untuk firewall, Windows, proxy, dan DNS di PT JAB, jawabannya ada dan dibahas di Day 23. Untuk portal pelanggan dan billing, tidak ada, dan di situlah membangun sendiri menjadi pekerjaan yang benar.

### 1.2 Empat jenis dataset, dan konsekuensinya pada kecepatan

Pertanyaan kedua SOC lead (jenis mana untuk portal dan untuk billing) dijawab dengan tabel ini. Dokumentasi menyebut empat jenis dataset [S1], dan yang perlu kamu cari di tabel adalah kolom terakhir.

| Jenis | Cara mendefinisikan | Dibutuhkan | Bisa di-accelerate |
|---|---|---|---|
| Root event | Satu atau lebih constraint, yaitu bagian filter sebuah search, misalnya `sourcetype=access_*` [S1][S2] | Nama dan ID dataset | Ya, dan ini jenis yang disyaratkan acceleration [S9] |
| Root search | Search string bebas, biasanya search atas index event [S1][S2] | Search yang dimulai command `search` dan berupa search index event [S1] | Hanya bila seluruhnya memakai streaming command; transforming command atau data non-event tidak bisa [S2][S9] |
| Root transaction | Nama, ID, dan minimal satu Group Dataset (dataset event, transaction, atau search di model yang sama), ditambah minimal satu dari Group by, Max Pause, atau Max Span [S2] | Dataset lain yang sudah ada di model yang sama [S1] | Tidak, termasuk turunannya [S2][S9] |
| Child | Constraint tambahan di atas parent [S1][S2] | Sebuah parent | Mengikuti parent-nya |

Tiga aturan yang jarang disebut tetapi sering menghukum:

1. Sebuah model tidak boleh hanya terdiri dari transaction dataset dan turunannya [S1]. Harus ada dasar berupa event atau search dataset.
2. Search dengan `transaction` yang sederhana sebaiknya dibuat sebagai root transaction dataset, bukan dijejalkan ke root search dataset [S2]. Tetapi keduanya sama-sama menutup pintu acceleration, jadi pikirkan apakah pengelompokan itu benar-benar harus terjadi di dalam model.
3. Model yang dibangun dari sumber datar berbentuk tabel, misalnya berkas CSV, hanya punya satu root dataset, dan child-nya tidak menambah field apa pun di luar yang diwarisi [S1].

Untuk PT JAB: log akses portal cocok sebagai root event dataset, karena pertanyaan tim fraud berbentuk hitungan per segmen, per status, per waktu, dan semuanya bisa dijawab dari event individual. Log billing yang butuh penyaringan lebih rumit tetap dibuat sebagai root search dataset dengan hanya streaming command, supaya pintu acceleration tidak tertutup. Pengelompokan beberapa event pembayaran menjadi satu sesi memang paling alami sebagai transaction dataset, dan justru karena itu dibiarkan di luar model: biayanya hilangnya acceleration untuk seluruh cabang (Day 13 membahas `transaction` sebagai command, dan Day 26 membahas sisi operasi acceleration).

Penamaan juga punya aturan yang tidak bisa diperbaiki belakangan: Dataset Name menerima karakter apa pun kecuali tanda bintang, termasuk spasi, sedangkan Dataset ID hanya menerima alfanumerik, garis bawah, dan tanda hubung tanpa spasi, dan tidak bisa diubah setelah disimpan [S2]. ID inilah yang muncul di SPL, jadi pilih yang masih enak dibaca setahun kemudian.

### 1.3 Constraint dan apa yang diwarisi child dataset

Constraint adalah bagian filter sebuah search [S2]. Di root event dataset PT JAB, bentuknya sesederhana `index=linux sourcetype=jab:portal:access`.

Dokumentasi menyarankan constraint root yang luas, supaya child dataset masih punya ruang untuk mempersempit data, dan menyediakan Preview untuk menguji hasilnya sebelum disimpan [S2]. Child dataset mewarisi semua constraint dan field dari parent lalu menambahkan constraint sendiri, sehingga setiap child selalu himpunan bagian parent-nya [S1][S2]. Satu parent boleh punya beberapa child [S2]. Contoh di dokumentasi: child "HTTP Success" yang menambahkan `status = 2*` [S2].

Empat batasan yang menentukan bentuk hirarkimu:

- Constraint child tidak boleh memakai search macro [S2]. Jadi macro yang kamu buat di Day 18 tidak bisa dipakai di sini; tulis constraint-nya eksplisit.
- Child dataset tidak boleh menambahkan auto-extracted field baru [S1][S3]. Semua auto-extracted field harus didaftarkan di root dataset, lalu diwarisi ke bawah.
- Field warisan tidak bisa dihapus atau disunting langsung di child; perubahan dilakukan di parent tempat field itu berasal [S1].
- Hirarki sebaiknya dangkal, karena penyaringan constraint makin tidak efisien di cabang yang makin dalam [S2].

Praktik terbaik lain dari dokumentasi yang langsung berlaku untuk PT JAB [S2]: sebut index di constraint atau search (meningkatkan efisiensi dan akurasi acceleration), pakai hanya streaming command di root event dan root search yang akan di-accelerate, dan hindari ketergantungan sirkular, yaitu constraint yang memakai field yang bukan auto-extracted dan bukan warisan. Jebakan terakhir itu halus: constraint child yang memakai field hasil eval expression tidak akan bekerja seperti yang kamu harapkan, karena field itu baru dihitung setelah dataset terbentuk.

### 1.4 Lima jenis attribute

Pertanyaan keempat SOC lead adalah inti pekerjaan teknis Day ini. Dokumentasi menyebut lima jenis field, dan masing-masing punya syarat sendiri [S1][S3].

| Jenis | Asal nilainya | Batasan penting |
|---|---|---|
| Auto-extracted | Field yang sudah terekstrak saat index time atau search time [S3] | Hanya bisa ditambahkan di root dataset, dan diwarisi child [S3] |
| Eval Expression | Ekspresi `eval` yang ditulis di definisi field [S3] | Dihitung setelah field extracted; urutannya menentukan apa yang bisa dipakainya [S3] |
| Regular Expression | Regex atas data event [S3] | Satu regex bisa menghasilkan beberapa field, dan setiap field muncul terpisah di daftar [S3] |
| Lookup | Lookup yang dikonfigurasi di definisi field [S3] | Lookup apa pun boleh dipakai, dan dikaitkan ke field yang sudah ada di dataset [S3] |
| Geo IP | Jenis lookup yang menambahkan latitude, longitude, country, dan city [S3] | Hanya untuk event yang punya field alamat IP yang valid [S3] |

Auto-extracted field sendiri punya tiga asal [S3]:

1. Ekstraksi key-value otomatis, misalnya field seperti `uri` atau `version`, termasuk dari input data terstruktur seperti header CSV.
2. Knowledge object, yaitu field extraction, lookup, dan calculated field yang sudah terdefinisi di `props.conf`. Ini bagian yang sering mengejutkan: field yang kamu buat dengan Field Extractor di Day 15 dan calculated field di Day 16 masuk ke data model sebagai auto-extracted, bukan sebagai calculated field data model.
3. Field yang ditambahkan manual, misalnya field yang jarang muncul atau field dari generating command seperti `inputcsv` dan `dbinspect`.

Di editor, kelima jenis itu dikelompokkan menjadi tiga kategori [S3]:

- Inherited: field warisan dari parent, ditambah field default pada root event, search, dan transaction dataset.
- Extracted: auto-extracted field yang ditambahkan ke dataset.
- Calculated: eval expression, regular expression, lookup, dan geo IP.

Nama dan tipe juga bagian dari definisi [S3]. Field Extracted dan Calculated bisa diberi nama tampilan dan tipe, walau tipenya sudah ditetapkan otomatis. Tipe yang disebut halaman itu adalah Boolean, IPv4, Number, dan String [S3]. Nama field tidak boleh memuat tanda bintang, dan mengganti nama hanya mengubah namanya di data model, bukan di index [S3]. Tipe field warisan tidak bisa diubah [S3]. Soal tipe ini bukan kosmetik: di Pivot, jenis filter dan fungsi agregasi yang tersedia ditentukan tipe field (bagian 1.6), jadi field angka yang bertipe String membuat pengguna Pivot tidak bisa menjumlahkannya.

### 1.5 Flag dan urutan: dua hal yang mengubah isi, bukan tampilan

Dua setelan kecil di daftar field punya efek besar, dan keduanya gampang disalahpahami sebagai urusan tampilan.

**Urutan field.** Field diproses menurun dari atas ke bawah, dan field Extracted diproses sebelum field Calculated [S3]. Bila sebuah lookup bergantung pada field hasil eval, field eval itu harus berada di atas lookup-nya [S3]. Dokumentasi memberi contoh rantai: dua auto-extracted field, lalu eval expression yang memakai keduanya, lalu lookup yang memakai hasil eval itu [S3]. Editor menyediakan cara menyusun ulang urutannya [S3]. Akibat praktisnya: bila sebuah field tiba-tiba kosong setelah kamu menambah field baru, periksa urutannya sebelum memeriksa logikanya.

**Flag Shown dan Hidden, Optional dan Required.** Default-nya semua field shown dan optional [S3]. Artinya [S3]:

- Shown berarti field terlihat oleh pengguna Pivot dalam konteks dataset itu; Hidden berarti tidak tersedia bagi pengguna Pivot, dan ini berguna untuk field perantara dalam sebuah rantai.
- Optional berarti field tidak harus ada di setiap event; Required berarti harus ada, dan event yang tidak punya field itu disaring keluar, sehingga efeknya seperti constraint tambahan.
- Flag berlaku per dataset, jadi satu field bisa Required di parent dan Optional di child.
- Pengecualian: flag pada field Calculated yang diwarisi tidak bisa diubah di child dataset; ubah di parent tempat field itu pertama muncul.

Flag Required adalah sumber kebingungan klasik: seseorang menandainya Required supaya "pasti terlihat", lalu jumlah event di Pivot turun tanpa penjelasan. Yang terjadi bukan masalah tampilan, melainkan penyaringan data [S3]. Di PT JAB, menandai `customer_id` sebagai Required pada dataset akses portal akan membuang seluruh akses anonim ke halaman login, yang justru paling menarik untuk kasus pengambilalihan akun.

Perubahan flag dilakukan lewat Override untuk field warisan atau Edit untuk field extracted dan calculated, dan beberapa field sekaligus lewat Bulk Edit dengan pilihan Optional, Required, Hidden, atau Shown [S3]. Bulk Edit juga dipakai untuk menetapkan satu tipe ke beberapa field [S3].

### 1.6 Pivot editor: empat kategori elemen

Pertanyaan kelima SOC lead (bagaimana tim fraud memakainya) dijawab di sini.

Setelah memilih data model dan dataset, editor terbuka dalam mode tabel pivot dengan satu baris berisi jumlah hasil dataset itu atas seluruh waktu [S4]. Arti angka itu bergantung jenis dataset [S4]: pada event dataset dan turunannya, total event yang cocok; pada transaction dataset, total transaksi; pada search dataset, total baris tabel dari base search-nya, atau total event bila search-nya bukan transforming dan bukan streaming. Dua elemen sudah ada sejak awal, yaitu Filter waktu yang disetel All time dan satu Column Values berisi field `Count_of_<nama dataset>` [S4].

Empat kategori elemen dan fungsinya [S4]:

| Kategori | Fungsi | Catatan |
|---|---|---|
| Filters | Mempersempit hasil di luar constraint dataset | Filter waktu selalu ada dan tidak bisa dihapus; elemen tidak bisa dipindahkan ke atau dari kategori ini |
| Split Rows | Membuat satu baris per nilai atau rentang | Punya Label dan Sort |
| Split Columns | Membuat satu kolom per nilai atau rentang | Punya Group Others |
| Column Values | Menghitung agregasi, misalnya count, sum, atau average | Elemen `Count_of` bawaan hanya bisa diganti Label-nya |

Jenis filter yang tersedia ditentukan tipe field [S4]. Filter match untuk String menyediakan is, contains, is not, does not contain, starts with, ends with, is null, dan is not null; IPv4 sama kecuali tidak ada ends with; Number memakai pembanding `=`, `!=`, `<`, `<=`, `>=`, `>`, is null, dan is not null; Boolean memakai true, false, null, dan not null; Timestamp memakai earliest dan latest dari menu rentang waktu. Satu hal yang penting untuk pekerjaan keamanan: filter match hanya mendukung logika AND, tidak OR [S4]. Pertanyaan berbentuk "A atau B" tidak bisa disusun di Pivot, dan itu salah satu alasan Pivot bukan pengganti SPL.

Selain filter match, ada limit filter untuk field String dan Number [S4]: pilih Highest atau Lowest dan jumlah hasil maksimum, dengan dasar count atau distinct count untuk String, dan count, distinct count, sum, atau average untuk Number, sedangkan field `Count_of` hanya menerima count. Dokumentasi mengingatkan distinct count pada field berkardinalitas tinggi bisa memperlambat [S4].

Opsi split yang paling sering menyebabkan kesimpulan salah [S4]:

- Max Rows dan Max Columns, dengan nilai 0 berarti tanpa batas. Opsi ini tidak tersedia bila hanya ada satu split pada field timestamp atau Boolean, atau pada field numerik yang memakai rentang.
- Totals menambahkan baris atau kolom ALL, default No, dan tidak dihitung terhadap batas.
- Group Others, hanya untuk Split Columns, mengelompokkan kolom berlebih menjadi kolom OTHER atau menyembunyikannya; default-nya Group Others, dan OTHER tidak dihitung terhadap batas.
- Field numerik punya Create ranges yang default Yes, dan bila kolom rentangnya dibiarkan kosong perilakunya menjadi No. Jumlah rentang maksimum, ukuran rentang maksimum, serta nilai awal dan akhir bisa diatur.
- Field timestamp punya Period dengan pilihan Year, Month, Day, Hour, Minute, dan Second, default Auto.
- Split Rows punya Sort dengan pilihan Default, Ascending, dan Descending; Default mengurutkan menurut tipe field, sedangkan Ascending dan Descending mengurutkan menurut kolom metrik pertama.

Fungsi Column Values juga ditentukan tipe [S4]: String menyediakan List Distinct Values, First Value, Last Value, Count, dan Distinct Count; Number menyediakan Sum, Count, Average, Max, Min, Standard Deviation, dan List Distinct Values; Timestamp menyediakan Duration, Earliest, dan Latest.

Dua hal operasional yang membantu saat mendampingi pengguna baru [S4]: paginasi hasil bisa 10, 20, atau 50 dengan default 20, dan drilldown punya dua mode, yaitu Row yang menambahkan batasan field-value untuk setiap elemen split row (atau memakai earliest dan latest baris itu bila split row pertamanya `_time`), dan Cell yang menambahkan batasan untuk split row dan split column yang relevan.

### 1.7 Halaman Datasets: tempat semuanya bertemu

Halaman Datasets adalah pintu masuk yang dipakai pengguna non-SPL, dan di app Search & Reporting ia diklik di bilah Apps berwarna hijau [S5].

Yang ditampilkan halaman itu [S5]: semua dataset yang bisa kamu akses beserta jenis, pemilik, dan status sharing-nya. Dataset private milik orang lain tidak muncul. Membuka tanda `>` di kolom pertama memperlihatkan detail, termasuk field di dalam dataset dan tanggal terakhir diubah.

Aksi yang tersedia [S5]:

- Explore membuka Explorer view untuk memeriksa hasil, meringkas field, memakai time range picker, mengelola search job, mengekspor isi, dan menyimpannya sebagai report terjadwal.
- Explore > Visualize with Pivot membuka Pivot editor atas dataset itu, dan hasilnya bisa disimpan sebagai report atau panel dashboard.
- Explore > Investigate in Search menjalankan search yang memakai command `from`, dan hasilnya bisa disimpan sebagai report, panel dashboard, atau alert, atau dijadikan table dataset baru lewat New Table.
- Manage > Edit Data Model membuka Data Model Editor; untuk lookup, tersedia Edit Lookup Table Files dan Edit Lookup Definition.
- Permission dataset data model diatur di Data Model Editor atau di Settings > Data models, dan secara default hanya role Power dan Admin yang boleh mengatur permission dataset.

Satu kalimat di dokumentasi yang mengubah cara kamu menjelaskan ke tim fraud: semua jenis dataset bisa dibuka di Pivot [S5]. Jenis dataset yang dimaksud di halaman itu ada tiga, yaitu lookup, data model, dan table dataset [S6]. Lookup yang muncul sebagai dataset adalah berkas lookup `.csv` dan definisi lookup (`.csv` dan KV store), sedangkan jenis lain seperti external lookup dan geospatial lookup tidak terdaftar sebagai dataset [S6]. Table dataset adalah kumpulan event terkurasi yang dibuat dan dirawat lewat Table Views [S6]. Istilah yang perlu dikenali karena dokumentasi lama masih beredar: dataset data model dulu disebut data model object [S6].

Data Model Editor sendiri bisa dibuka dari tiga tempat [S2]: Settings > Data Models lalu Edit > Edit Datasets, dari halaman Datasets lewat Manage > Edit data model, dan dari Pivot Editor. Mengeditnya butuh permission yang sesuai [S2].

### 1.8 Akselerasi: satu paragraf yang menentukan desainmu

Syarat dari SOC lead ("jangan sampai nanti tidak bisa di-accelerate") sebenarnya dijawab di bagian 1.2, tetapi angka dan prosedurnya milik Day 26. Yang perlu kamu pegang saat merancang: acceleration mempercepat pivot dan chart dengan membangun ringkasan atas sebuah summary range, yaitu rentang waktu yang kamu pilih saat mengaktifkannya, dan rentang kosong berarti All Time [S9]. Model yang bisa di-accelerate secara persisten harus dibagikan ke semua pengguna app atau secara global, karena model private tidak bisa di-accelerate, dan harus punya minimal satu hirarki root event, atau satu hirarki root search yang hanya memakai streaming command [S9]. Root search dataset dengan command non-streaming dan root transaction dataset tidak bisa di-accelerate secara persisten; pivot atas keduanya kembali membaca data mentah dan hanya mendapat ad hoc acceleration yang hilang begitu kamu meninggalkan Pivot Editor [S9]. Pengaktifannya lewat Settings > Data Models lalu Edit > Edit Acceleration [S9]. Sisi operasinya, mulai dari ukuran summary, pemantauan, sampai `summariesonly`, dibahas di Day 25 dan Day 26.

## 2. Contoh membangun model untuk PT JAB

Semua keluaran di bagian ini adalah keluaran ilustrasi, bukan hasil eksekusi. Nama model, dataset, dan field dipakai konsisten di seluruh bagian, dan angkanya disusun agar bisa dijumlahkan ulang.

### 2.1 Root event dataset untuk akses portal pelanggan

**Tujuan:** menyiapkan dasar yang luas tetapi jelas, supaya child dataset masih punya ruang mempersempit.

Isi form di Data Model Editor:

| Setelan | Nilai |
|---|---|
| Nama data model | `JAB Billing dan Portal` |
| ID data model | `jab_billing_portal` |
| Jenis dataset | Root Event |
| Dataset Name | `Portal Access` |
| Dataset ID | `Portal_Access` |
| Constraint | `index=linux sourcetype=jab:portal:access` |

**Penjelasan tiap bagian.** Constraint menyebut index secara eksplisit, yang disarankan dokumentasi untuk efisiensi dan akurasi acceleration [S2]. Constraint-nya sengaja tidak menyebut status atau path, karena itu pekerjaan child dataset [S2]. Dataset ID memakai garis bawah karena ID hanya menerima alfanumerik, garis bawah, dan tanda hubung, dan tidak bisa diubah setelah disimpan [S2]. Nama dataset boleh berspasi [S2].

**Keluaran ilustrasi** dari Preview di editor, pada rentang 2026-10-07 00:00 sampai 2026-10-14 00:00:

```
_time                host          uri_path       status  customer_id
2026-10-13 21:14:02  jkt-portal01  /login         401     -
2026-10-13 21:14:48  jkt-portal01  /login         401     -
2026-10-13 21:15:20  jkt-portal01  /login         200     C-004127
2026-10-13 21:16:03  jkt-portal01  /tagihan       200     C-004127
2026-10-13 21:18:55  jkt-portal01  /bayar         500     C-004127
```

**Cara membaca hasil.** Preview dipakai untuk satu hal: memastikan constraint-nya memanggil event yang kamu maksud, dan memastikan field yang kamu butuhkan memang terlihat. Perhatikan `customer_id` yang kosong pada event `/login` yang gagal; itu normal, dan nanti menjadi alasan untuk tidak menandai field itu Required (bagian 1.5).

**Variasi.** Bila log portal juga dikirim ke index lain saat migrasi, constraint boleh memakai `index IN (linux, linux_app)`. Tetap sebut index-nya, jangan mengandalkan default.

**Kapan gagal.** Bila sourcetype masih salah saat onboarding (Day 28), field tidak terekstrak dan daftar auto-extracted field akan kosong walau event masuk. Perbaiki di sisi onboarding dulu; data model tidak bisa menambal parsing yang salah.

### 2.2 Child dataset: mempersempit tanpa menduplikasi

**Tujuan:** memberi tim fraud dua pintu masuk yang sudah terfilter, tanpa membuat model kedua.

| Dataset | Parent | Constraint tambahan | Dipakai untuk |
|---|---|---|---|
| `Portal Login` (`Portal_Login`) | `Portal_Access` | `uri_path="/login"` | Pertanyaan tentang percobaan login |
| `Portal Login Gagal` (`Portal_Login_Gagal`) | `Portal_Login` | `status>=400` | Brute force dan pengambilalihan akun |
| `Portal Pembayaran` (`Portal_Pembayaran`) | `Portal_Access` | `uri_path="/bayar"` | Pembayaran gagal berulang |

**Penjelasan tiap bagian.** Setiap child mewarisi constraint dan field parent lalu menambahkan satu constraint, sehingga `Portal_Login_Gagal` otomatis juga `uri_path="/login"` dan `index=linux sourcetype=jab:portal:access` [S1][S2]. Hirarkinya dibuat hanya dua tingkat di bawah root, mengikuti saran menjaga hirarki tetap dangkal [S2].

**Keluaran ilustrasi** jumlah event per dataset pada rentang tujuh hari yang sama:

```
Portal Access         5286
  Portal Login        3127
    Portal Login Gagal 1030
  Portal Pembayaran    842
```

**Cara membaca hasil.** Angka child selalu lebih kecil atau sama dengan parent, karena child adalah himpunan bagian [S1]. Bila kamu melihat child lebih besar dari parent, yang salah pasti pemahamanmu tentang constraint mana yang berlaku, bukan datanya.

**Variasi.** Untuk kasus pengambilalihan akun, child ketiga `Portal Login Sukses` dengan `status=200` berguna untuk membandingkan gagal dan sukses per akun.

**Kapan gagal.** Constraint child tidak boleh memakai search macro [S2], jadi macro `jab_portal_gagal` yang kamu buat di Day 18 tidak bisa dipakai di sini. Dan constraint yang memakai field hasil eval expression termasuk ketergantungan sirkular yang disarankan dihindari [S2]; bila kamu butuh memfilter berdasarkan hasil perhitungan, filter itu dikerjakan di Pivot, bukan di constraint.

### 2.3 Lima jenis attribute dalam satu dataset

**Tujuan:** menyiapkan kolom yang dibutuhkan tim fraud, dengan setiap jenis attribute dipakai di tempat yang tepat.

Daftar field pada `Portal_Access`, ditulis dalam urutan pemrosesan dari atas ke bawah [S3]:

| Urutan | Nama field | Jenis | Definisi | Tipe | Flag |
|---|---|---|---|---|---|
| 1 | `clientip` | Auto-extracted | sudah terekstrak dari log | IPv4 | Optional, Shown |
| 2 | `uri_path` | Auto-extracted | sudah terekstrak dari log | String | Optional, Shown |
| 3 | `status` | Auto-extracted | sudah terekstrak dari log | Number | Optional, Shown |
| 4 | `bytes` | Auto-extracted | sudah terekstrak dari log | Number | Optional, Shown |
| 5 | `customer_id` | Auto-extracted | sudah terekstrak dari log | String | Optional, Shown |
| 6 | `invoice_id` | Regular Expression | `invoice_id=(?<invoice_id>INV-\d{4}-\d{6})` atas `_raw` | String | Optional, Shown |
| 7 | `status_kategori` | Eval Expression | `case(status<300,"sukses",status<400,"redirect",status<500,"error_klien",true(),"error_server")` | String | Optional, Shown |
| 8 | `kunci_pelanggan` | Eval Expression | `coalesce(customer_id,"anonim")` | String | Optional, Hidden |
| 9 | `customer_segment` | Lookup | lookup `jab_pelanggan` dengan input `kunci_pelanggan`, output `segment` | String | Optional, Shown |
| 10 | `customer_pop` | Lookup | lookup `jab_pelanggan` dengan input `kunci_pelanggan`, output `pop` | String | Optional, Shown |
| 11 | `clientip_country`, `clientip_city`, `clientip_lat`, `clientip_lon` | Geo IP | dari field `clientip` | String dan Number | Optional, Shown |

**Penjelasan tiap bagian.**

Field 1 sampai 5 adalah auto-extracted, dan semuanya didaftarkan di root dataset karena child tidak boleh menambah auto-extracted field [S3]. Perlu diingat bahwa field extraction dan calculated field yang sudah kamu buat lewat `props.conf` juga masuk sebagai auto-extracted di sini [S3], jadi periksa dulu apa yang sudah ada sebelum menulis regex baru.

Field 6 memakai Regular Expression. Satu regex bisa menghasilkan beberapa field sekaligus, dan tiap field muncul terpisah di daftar [S3]. Pola `INV-\d{4}-\d{6}` cocok untuk nomor seperti `INV-2026-004812`, yaitu empat digit tahun dan enam digit urut.

Field 7 adalah Eval Expression yang menerjemahkan kode status menjadi kategori yang bisa dibaca orang non-teknis. Ini contoh paling jelas bahwa data model adalah pekerjaan terjemahan, bukan hanya pemetaan.

Field 8 ada demi field 9 dan 10. Lookup dikaitkan ke field yang sudah ada di dataset [S3], dan karena `customer_id` kosong pada akses anonim, `coalesce` memberi kunci yang selalu ada. Field ini diberi flag Hidden karena ia field perantara, dan Hidden memang disarankan untuk field perantara dalam sebuah rantai [S3]. Urutannya wajib di atas lookup yang memakainya [S3].

Field 9 dan 10 adalah Lookup, memakai lookup `jab_pelanggan` yang dirawat tim billing (pembuatan dan perawatan lookup dibahas di Day 12). Dua field keluaran dibuat sebagai dua definisi karena keduanya dipakai terpisah di Pivot.

Field 11 adalah Geo IP, yang menambahkan latitude, longitude, country, dan city untuk event dengan field IP yang valid [S3].

**Keluaran ilustrasi** satu baris setelah semua field terisi:

```
_time            = 2026-10-13 21:15:20
clientip         = 203.0.113.45
uri_path         = /login
status           = 200
customer_id      = C-004127
status_kategori  = sukses
kunci_pelanggan  = C-004127     (Hidden, tidak terlihat di Pivot)
customer_segment = korporat
customer_pop     = JKT
clientip_country = (kosong pada contoh ini)
```

**Cara membaca hasil.** Kolom `clientip_country` yang kosong bukan kerusakan: Geo IP hanya mengisi untuk event dengan field IP yang valid [S3], dan nilai di luar basis datanya tidak menghasilkan apa-apa. Untuk ISP, ada jebakan tambahan yang lebih penting: sebagian besar pelanggan portal mengakses dari ruang alamat PT JAB sendiri, jadi lokasi geo untuk mereka tidak memberi informasi apa pun. Geo IP di sini hanya berguna untuk akses dari luar jaringan sendiri, terutama login akun admin portal.

**Variasi.** Bila yang dibutuhkan hanya negara, buat satu field Geo IP saja dan sembunyikan sisanya, supaya daftar field tetap bisa dibaca pengguna Pivot.

**Kapan gagal.** Bila `kunci_pelanggan` dipindahkan ke bawah field lookup, kedua field lookup menjadi kosong, karena pemrosesan berjalan dari atas ke bawah [S3]. Bila lookup `jab_pelanggan` basi, segmen yang muncul salah tanpa tanda apa pun; lookup butuh pemilik dan jadwal pembaruan. Dan bila kamu mengubah flag field Calculated yang diwarisi dari child, perubahannya tidak bisa dilakukan di sana; ubah di parent [S3].

### 2.4 Root search dataset untuk billing, tanpa menutup pintu acceleration

**Tujuan:** memasukkan log billing yang butuh penyaringan lebih rumit, tetapi tetap bisa di-accelerate.

| Setelan | Nilai |
|---|---|
| Jenis dataset | Root Search |
| Dataset Name | `Billing Transaksi` |
| Dataset ID | `Billing_Transaksi` |
| Search | `search index=linux sourcetype=jab:billing:app ("invoice" OR "refund") \| eval jenis=if(like(_raw,"%refund%"),"refund","invoice")` |

**Penjelasan tiap bagian.** Search-nya dimulai dengan command `search` dan berupa search atas index event, sesuai syarat root search dataset [S1]. Hanya `search` dan `eval` yang dipakai, dan keduanya streaming, sehingga dataset ini masih memenuhi syarat acceleration [S2][S9]. Fungsi `like()` dipakai di dalam `eval` agar tidak bergantung versi.

**Keluaran ilustrasi** jumlah per `jenis` pada rentang tujuh hari yang sama:

```
jenis     count
invoice   1904
refund      61
```

**Cara membaca hasil.** Total 1965 event. Angka `refund` yang kecil justru yang menarik untuk fraud: 61 refund dalam tujuh hari bisa diperiksa satu per satu, dan itu alasan dataset ini ada.

**Variasi.** Bila nanti billing butuh pengelompokan beberapa event menjadi satu transaksi, jangan menambah `transaction` ke search ini. Buat root transaction dataset terpisah dan terima bahwa cabang itu tidak bisa di-accelerate [S2][S9], atau kerjakan pengelompokan di luar model dengan `stats` (Day 13).

**Kapan gagal.** Menambahkan satu `stats` atau `dedup` ke search ini membuatnya tidak bisa di-accelerate [S2][S9], dan gejalanya bukan error, hanya pivot yang lambat selamanya. Itu kemungkinan penyebab percobaan tahun lalu yang disebut SOC lead gagal, dan layak dicek di definisi model lama sebelum dihapus.

### 2.5 Memeriksa model dari SPL sebelum menyerahkannya

**Tujuan:** memastikan apa yang akan dilihat pengguna Pivot, dan menemukan field yang hilang sebelum mereka menemukannya.

**Sintaks dan tujuan tiap baris:**

```
| datamodel jab_billing_portal Portal_Access search
| stats count BY Portal_Access.status_kategori
```

Command `datamodel` adalah generating command, jadi ia harus berada di awal search dengan pipe di depannya [S7]. Mode `search` menjalankan search dataset itu [S7]. Perhatikan nama field: dalam mode `search`, field memakai hirarki `<Dataset>.<field>` [S7].

**Keluaran ilustrasi:**

```
Portal_Access.status_kategori  count
sukses                         4256
error_klien                    1030
```

Total 5286, sama dengan jumlah event `Portal Access` di bagian 2.2. Bila totalnya berbeda, berarti ada event yang `status`-nya tidak terisi sehingga `status_kategori` kosong, dan itu temuan onboarding yang perlu tiket sendiri.

**Jebakan utama command ini.** Secara default `datamodel` hanya mengembalikan field default dan field yang disebut di constraint, dan untuk mendapatkan semua field model termasuk warisan, extracted, calculated, dan hasil lookup, `strict_fields` harus disetel `false` [S2][S7]:

```
| datamodel jab_billing_portal Portal_Access search strict_fields=false
| stats dc(clientip) AS ip_unik BY Portal_Access.customer_segment
```

Tanpa `strict_fields=false`, field `customer_segment` yang baru saja kamu definisikan tampak hilang, dan kesimpulan yang gampang diambil adalah "lookup-nya tidak jalan". Yang tidak jalan adalah asumsinya.

**Variasi.** Mode `flat` membuang hirarki dari nama field, sehingga `dmdataset.server` menjadi `server` [S7]. Mode bentuk string (`search_string`, `flat_string`, `acceleration_search_string`) mengembalikan search yang sebenarnya dijalankan Splunk [S7], dan ini cara tercepat memahami apa yang terjadi di belakang sebuah dataset. Tanpa argumen, `| datamodel` mengembalikan JSON semua model di konteks app saat ini [S7].

**Kapan gagal.** Mode `acceleration_search` hanya berlaku untuk root event dataset atau root search dataset yang memakai streaming command [S7]. Argumen `summariesonly` dan `allow_old_summaries` hanya berlaku untuk model yang di-accelerate [S7], jadi memakainya pada model baru yang belum di-accelerate menghasilkan hasil kosong, bukan error yang jelas.

### 2.6 Pertanyaan tim fraud, disusun di Pivot editor

**Tujuan:** menjawab "login gagal portal per segmen pelanggan" tanpa SPL, lalu menyimpannya supaya tim fraud bisa mengulanginya sendiri.

Elemen yang disusun di Pivot editor atas dataset `Portal Login`:

| Kategori | Elemen | Setelan |
|---|---|---|
| Filters | waktu | absolut 2026-10-07 00:00:00 sampai 2026-10-14 00:00:00 |
| Filters | `customer_segment` | match: is not null |
| Split Rows | `customer_segment` | Label `Segmen`, Sort Descending |
| Split Columns | `status_kategori` | Max Columns 5, Group Others |
| Column Values | `Count_of_Portal_Login` | Label `Jumlah percobaan` |
| Column Values | `clientip` | Distinct Count, Label `IP unik` |

**Penjelasan tiap bagian.** Filter waktu diisi rentang absolut, bukan relatif, karena pertanyaan fraud selalu merujuk periode tertentu dan angkanya akan masuk laporan. Filter is not null memakai salah satu operator match untuk String [S4]. Split Columns dibatasi lima dengan Group Others, sehingga kategori di luar lima teratas masuk kolom OTHER yang tidak dihitung terhadap batas [S4]. Distinct Count pada `clientip` dipilih karena pertanyaan fraud sebenarnya "berapa banyak sumber", bukan "berapa banyak percobaan"; dokumentasi mengingatkan distinct count pada field berkardinalitas tinggi bisa memperlambat [S4].

**Keluaran ilustrasi:**

```
Segmen      error_klien  sukses  IP unik
broadband   902          1744    611
korporat    128          353      47
ALL         1030         2097    658
```

**Cara membaca hasil.** Jumlahnya konsisten: 902 + 128 = 1030 login gagal, sama dengan jumlah dataset `Portal Login Gagal` di bagian 2.2, dan 1744 + 353 = 2097 login sukses, sehingga total 3127 sama dengan jumlah dataset `Portal Login`. Yang menarik bukan angka terbesar, melainkan perbandingannya: segmen korporat punya 128 kegagalan dari hanya 47 IP unik, yaitu rata-rata hampir tiga kegagalan per IP, sedangkan broadband 902 kegagalan dari 611 IP, yaitu sekitar satu setengah per IP. Pemusatan di segmen korporat itu yang layak dibawa ke tiket SOC-2026-0251.

**Catatan tentang baris ALL.** Baris itu muncul karena Totals disetel Yes, dan ia tidak dihitung terhadap batas baris [S4].

**Variasi.** Pindahkan `status_kategori` dari Split Columns ke Split Rows untuk bentuk tabel yang lebih enak disalin ke tiket, atau tambahkan `clientip_country` sebagai Split Columns untuk pertanyaan akses dari luar negeri. Ingat bahwa untuk pelanggan di jaringan sendiri kolom itu akan kosong (bagian 2.3).

**Kapan gagal.** Pertanyaan berbentuk "login gagal ATAU pembayaran gagal" tidak bisa disusun di Pivot, karena filter match hanya mendukung AND [S4]. Pertanyaan seperti itu dikerjakan dengan SPL, atau dengan membuat dataset tersendiri yang constraint-nya sudah memuat kondisi OR.

### 2.7 Bentuk SPL dari pivot yang sama

**Tujuan:** menyimpan pertanyaan yang sama dalam bentuk yang bisa dijadwalkan dan di-review, dan memahami apa yang sebenarnya dijalankan Pivot.

```
| pivot jab_billing_portal Portal_Login
    count(Portal_Login) AS "Jumlah percobaan"
    dc(clientip) AS "IP unik"
    SPLITROW customer_segment AS Segmen
    SPLITCOL status_kategori
    FILTER customer_segment isNull false
```

**Penjelasan tiap bagian.** Sintaksnya `| pivot <datamodel> <object> <pivot-element>`, dan `pivot` adalah report-generating command yang harus berada di awal search [S8]. Urutan elemennya punya aturan: cell value selalu lebih dulu, lalu split row dan split column boleh berselang-seling [S8]. Fungsi yang boleh dipakai bergantung tipe field, dan untuk String tersedia list, values, first, last, count, dan distinct_count (`dc`) [S8]. Operator filter untuk String mencakup is, contains, in, dan isNull [S8].

**Cara membacanya.** Dokumentasi menyebut `pivot` sebagai pembungkus `stats` dan `xyseries` yang tidak menambah perilaku baru [S8]. Itu kalimat yang melegakan: tidak ada keajaiban di Pivot, dan apa pun yang bisa dilakukan Pivot bisa kamu tulis sendiri. Yang diberikan Pivot adalah antarmuka bagi orang yang tidak akan menulis `stats`, dan jaminan bahwa definisi field-nya sama untuk semua orang.

**Variasi.** Elemen `LIMIT <field> BY <top|bottom> <number> <fungsi>(<field>)` dipakai untuk membatasi nilai yang ditampilkan [S8], padanan limit filter di Pivot editor.

**Kapan gagal.** Nama yang dipakai di SPL adalah ID, bukan nama tampilan, jadi `JAB Billing dan Portal` tidak bisa dipakai di sini. Dokumentasi juga memberi contoh yang memakai `SORT 100 host`, bentuk yang tidak cocok dengan elemen `rowsort` yang didokumentasikan [S8], jadi untuk pengurutan sebaiknya uji di lab dulu atau urutkan di luar `pivot` dengan `sort`.

### 2.8 Menyerahkannya ke tim fraud lewat halaman Datasets

**Tujuan:** memastikan tim fraud bisa mengulang pertanyaan itu sendiri tanpa bertanya kepada SOC.

Langkahnya, memakai aksi yang ada di halaman Datasets [S5]:

1. Buka Datasets dari bilah Apps di app Search & Reporting.
2. Cari `Portal Login`, buka tanda `>` di kolom pertama, lalu periksa daftar field yang muncul. Ini tampilan yang akan dilihat tim fraud, dan tempat terbaik memverifikasi bahwa field Hidden memang tidak terlihat.
3. Pilih Explore > Visualize with Pivot, susun pertanyaan seperti bagian 2.6, lalu simpan sebagai report atau panel dashboard.
4. Untuk pertanyaan yang perlu dilanjutkan dengan SPL, pilih Explore > Investigate in Search, yang menjalankan search memakai command `from`.
5. Atur permission model di Data Model Editor atau di Settings > Data models. Secara default hanya role Power dan Admin yang boleh mengatur permission dataset, jadi mintakan yang sesuai bila tim fraud perlu menyimpan report sendiri.

**Keluaran ilustrasi** baris halaman Datasets:

```
Nama                  Jenis               Pemilik   Sharing
Portal Access         Data Model Dataset  admin     Global
Portal Login          Data Model Dataset  admin     Global
Portal Login Gagal    Data Model Dataset  admin     Global
Portal Pembayaran     Data Model Dataset  admin     Global
Billing Transaksi     Data Model Dataset  admin     Global
jab_pelanggan         Lookup Definition   admin     App
```

**Cara membaca hasil.** Kolom Sharing adalah hal pertama yang diperiksa ketika tim fraud melapor tidak melihat dataset. Dataset private milik orang lain tidak muncul di halaman ini [S5], dan model private juga tidak bisa di-accelerate [S9], jadi sharing bukan sekadar soal visibilitas.

**Kapan gagal.** Bila lookup `jab_pelanggan` hanya dibagikan sebatas app tertentu sementara model dipakai global, field `customer_segment` bisa kosong untuk sebagian pengguna. Periksa permission lookup, bukan hanya permission model.

## 3. Lab praktik (di VM lab terisolasi)

Lab ini memakai `index=_internal` supaya tidak butuh onboarding data, lalu satu langkah memakai BOTS v1 untuk Geo IP. Jangan menyalakan acceleration pada model lab dengan summary range panjang; prosedurnya milik Day 26.

1. **Buat data model baru** bernama `Lab Splunkd` dengan ID `lab_splunkd`, lalu buat root event dataset `Splunkd Log` (ID `Splunkd_Log`) dengan constraint `index=_internal sourcetype=splunkd`. Jalankan Preview dan catat jumlah event pada rentang satu jam terakhir.
2. **Tambahkan dua auto-extracted field** (`component` dan `log_level`), lalu coba tambahkan auto-extracted field pada child dataset di langkah 3 dan catat apa yang terjadi. Aturannya ada di bagian 1.4.
3. **Buat child dataset** `Metrics` dengan constraint `component=Metrics`. Catat jumlah event child dan bandingkan dengan parent; child harus lebih kecil atau sama.
4. **Buat rantai tiga field** untuk membuktikan urutan pemrosesan: satu Eval Expression `grup_komponen` = `lower(component)`, satu lookup CSV kecil yang kamu buat sendiri (`lab_pemilik.csv` dengan kolom `grup_komponen` dan `tim`) yang memakai `grup_komponen` sebagai input, dan satu Eval Expression lagi yang memakai hasil lookup. Jalankan Pivot, catat hasilnya, lalu pindahkan field eval pertama ke bawah lookup dan jalankan ulang. Catat apa yang menjadi kosong.
5. **Uji flag Hidden.** Set `grup_komponen` menjadi Hidden, lalu buka Pivot dan pastikan field itu tidak ada di daftar pilihan, sementara field lookup yang bergantung padanya tetap terisi.
6. **Uji flag Required.** Catat jumlah event di Pivot, lalu set `log_level` menjadi Required dan catat jumlahnya lagi. Hitung selisihnya dan jelaskan selisih itu dalam satu kalimat. Kembalikan ke Optional setelah selesai.
7. **Uji Regular Expression field.** Buat satu field regex yang mengambil nama grup dari `_raw` (misalnya pola `group=(?<grup_metrics>\w+)`), lalu periksa berapa persen event yang terisi. Catat satu kasus positif dan satu kasus negatif yang kamu uji.
8. **Susun pivot** dengan Split Rows `component`, Split Columns `log_level`, dan Column Values count. Set Max Columns menjadi 2 dengan Group Others aktif, catat isi kolom OTHER, lalu matikan Group Others dan catat perbedaannya. Kaitkan ke aturan di bagian 1.6.
9. **Bandingkan Pivot dan SPL.** Jalankan `| datamodel lab_splunkd Splunkd_Log search | stats count BY Splunkd_Log.component`, lalu ulangi dengan `strict_fields=false`, lalu dengan mode `flat`. Catat perbedaan nama field dan field mana yang hanya muncul di salah satunya.
10. **Lihat search yang sebenarnya dijalankan.** Jalankan `| datamodel lab_splunkd Splunkd_Log search_string` dan simpan keluarannya. Bandingkan dengan constraint yang kamu tulis.
11. **Geo IP di data nyata yang statis.** Tentukan dulu rentang absolut BOTS v1 dengan `| tstats min(_time) AS awal max(_time) AS akhir where index=botsv1 | eval awal=strftime(awal,"%F %T"), akhir=strftime(akhir,"%F %T")`, catat hasilnya, lalu buat model kedua dengan root event dataset atas satu sourcetype web di BOTS v1, tambahkan Geo IP field dari field IP klien, dan catat berapa persen event yang mendapat `country`. Jangan memakai rentang relatif pada dataset statis.
12. **Halaman Datasets.** Buka Datasets, kembangkan baris `Metrics`, catat daftar field yang terlihat, lalu bandingkan dengan daftar di editor untuk memastikan field Hidden tidak muncul. Terakhir pilih Explore > Investigate in Search dan catat bentuk search yang dihasilkan, termasuk command `from`.

**Hasil yang sebaiknya tersimpan:**
- Jumlah event parent dan child dari langkah 1 dan 3, sebagai bukti hubungan himpunan bagian.
- Catatan langkah 2 tentang apa yang terjadi saat menambah auto-extracted field di child.
- Dua hasil langkah 4 (sebelum dan sesudah urutan diubah) berdampingan.
- Dua angka dari langkah 6 beserta satu kalimat penjelasan selisihnya.
- Satu kasus positif dan satu kasus negatif regex dari langkah 7.
- Isi kolom OTHER dari langkah 8.
- Tiga keluaran langkah 9 dan satu keluaran langkah 10, sebagai pengingat perilaku `strict_fields`.
- Rentang waktu BOTS v1 yang terverifikasi di lab-mu, beserta persentase event yang mendapat `country` dari langkah 11.
- Bentuk search dari langkah 12.

**Variasi tantangan:** buat satu root search dataset yang memakai `stats`, lalu coba aktifkan acceleration untuk model itu dan catat apa yang terjadi atau apa pesan yang muncul. Setelah itu tulis ulang dataset yang sama hanya dengan streaming command dan bandingkan. Catatan ini yang nanti menghemat waktumu ketika merancang model untuk data produksi.

## 4. Troubleshooting

Tabel ini memuat gejala yang paling sering muncul saat membangun atau memakai data model. Cari gejalanya di kolom pertama.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Field lookup atau eval tidak muncul di `\| datamodel ... search` | `strict_fields` default `true`, hanya field default dan field di constraint yang kembali [S2][S7] | Tambahkan `strict_fields=false`, atau periksa lewat Pivot |
| Jumlah event di Pivot turun tanpa sebab | Ada field yang ditandai Required, sehingga event tanpa field itu disaring keluar [S3] | Periksa flag semua field dataset itu; kembalikan ke Optional |
| Field lookup kosong untuk semua event | Field input lookup berada di bawah lookup dalam urutan pemrosesan [S3] | Pindahkan field input ke atas lookup |
| Field warisan tidak bisa disunting di child | Field warisan diubah di parent tempat ia berasal [S1] | Buka parent dataset dan ubah di sana; untuk flag, pakai Override |
| Flag field Calculated warisan tidak bisa diubah | Perubahan flag pada Calculated warisan tidak diizinkan di child [S3] | Ubah di dataset parent tempat field itu pertama muncul |
| Tidak bisa menambah auto-extracted field | Child dataset tidak boleh menambah auto-extracted field [S1][S3] | Tambahkan di root dataset, lalu warisi |
| Daftar auto-extracted field kosong | Parsing atau sourcetype salah sehingga field tidak terekstrak | Perbaiki di sisi onboarding dulu (Day 28) |
| Acceleration tidak bisa diaktifkan | Model private, atau tidak punya hirarki root event maupun root search yang hanya streaming [S9] | Bagikan model ke app atau global, dan periksa jenis dataset serta command di search-nya |
| Pivot lambat walau acceleration aktif | Rentang pivot di luar summary range, atau dataset-nya jenis yang tidak bisa di-accelerate [S9] | Persempit rentang, atau ubah desain dataset (bagian 1.2) |
| Constraint child memakai macro ditolak | Constraint child tidak boleh memuat search macro [S2] | Tulis constraint eksplisit |
| Kolom yang dicari tidak ada di hasil Pivot | Max Columns dan Group Others membatasi kolom [S4] | Naikkan Max Columns (0 berarti tanpa batas) dan periksa isi kolom OTHER |
| Tidak bisa menyusun pertanyaan "A atau B" di Pivot | Filter match hanya mendukung AND [S4] | Pakai SPL, atau buat dataset dengan constraint yang sudah memuat OR |
| Field angka tidak bisa dijumlahkan di Pivot | Tipe field-nya String | Ubah tipe field di editor; tipe field warisan tidak bisa diubah [S3] |
| Tim lain tidak melihat dataset di halaman Datasets | Dataset private milik orang lain tidak ditampilkan [S5] | Periksa sharing model dan lookup pendukungnya |
| Tidak bisa mengatur permission dataset | Secara default hanya role Power dan Admin yang boleh [S5] | Minta role yang sesuai, atau mintakan lewat admin |
| Dataset ID salah dan ingin diperbaiki | ID tidak bisa diubah setelah disimpan [S2] | Buat dataset baru dengan ID yang benar dan pindahkan definisi field-nya |
| Nilai Geo IP kosong | Hanya event dengan field IP yang valid yang terisi [S3] | Periksa field IP-nya; untuk IP internal hasilnya memang kosong |

## 5. Kesalahan umum dan jebakan

- Membuat data model sendiri untuk sumber log yang sudah punya model standar. Hasilnya dua kebenaran yang berbeda untuk data yang sama, dan konten yang sudah ada tidak ikut bekerja. Day 23 dan Day 24 membahas jalur yang benar untuk sumber umum.
- Memilih root transaction dataset karena datanya "berbentuk sesi". Jenis itu dan turunannya tidak bisa di-accelerate [S2][S9], dan keputusan ini sulit dibatalkan setelah pengguna bergantung padanya.
- Menambahkan satu transforming command ke root search dataset. Dataset itu langsung kehilangan kelayakan acceleration [S2][S9], tanpa pesan error saat disimpan.
- Menganggap data model membuat search lebih cepat. Model hanya definisi; kecepatan datang dari acceleration beserta syaratnya [S9] dan dari `tstats` (Day 25).
- Membuat constraint root yang terlalu sempit. Dokumentasi menyarankan constraint luas supaya child punya ruang mempersempit [S2], dan constraint sempit memaksa dataset kembar untuk setiap variasi pertanyaan.
- Memakai field hasil eval di constraint child. Itu termasuk ketergantungan sirkular yang disarankan dihindari [S2], dan hasilnya tidak seperti yang kamu harapkan.
- Menandai field Required supaya "pasti terlihat". Required menyaring event yang tidak punya field itu [S3], sehingga angka di laporan berubah tanpa ada yang sadar.
- Lupa bahwa urutan field menentukan hasil. Pemrosesan menurun dari atas ke bawah dan Extracted sebelum Calculated [S3], jadi lookup yang bergantung pada eval harus berada di bawahnya.
- Mendefinisikan field perantara sebagai Shown. Daftar field pengguna Pivot menjadi penuh hal yang tidak mereka butuhkan; Hidden memang disediakan untuk itu [S3].
- Membiarkan field angka bertipe String. Pengguna Pivot kehilangan Sum, Average, dan Max, dan mereka tidak akan tahu kenapa [S3][S4].
- Memakai `| datamodel` tanpa `strict_fields=false` lalu menyimpulkan lookup-nya rusak. Default-nya hanya mengembalikan field default dan field di constraint [S2][S7].
- Memakai nama tampilan di SPL. `pivot` dan `datamodel` memakai ID, dan ID tidak bisa diubah setelah disimpan [S2].
- Mengandalkan Geo IP untuk IP pelanggan di jaringan sendiri. Hasilnya kosong atau tidak bermakna; Geo IP hanya mengisi untuk event dengan field IP yang valid [S3].
- Menyerahkan model yang masih private. Pengguna lain tidak melihatnya di halaman Datasets [S5], dan model private tidak bisa di-accelerate [S9].
- Menjanjikan pertanyaan "A atau B" di Pivot. Filter match hanya AND [S4].
- Melupakan pemilik lookup. Lookup basi membuat segmen dan POP salah tanpa gejala apa pun; lookup butuh pemilik dan jadwal pembaruan (Day 12).

## 6. Catatan terkini

Bagian ini menampung detail versi dan istilah yang berbeda antar halaman dokumentasi, supaya catatan ini tetap terbaca ketika antarmuka berubah.

- Istilah lama dan baru: dataset data model dulu disebut data model object, dan dokumentasi serta tulisan lama masih memakai istilah itu [S6]. Di editor, yang disebut "attribute" di materi lama kini muncul sebagai "field" [S3].
- Jenis dataset di halaman Datasets berbeda cakupannya dari jenis dataset di dalam data model. Halaman Datasets mengenal tiga jenis, yaitu lookup, data model, dan table dataset [S6], sedangkan di dalam sebuah data model ada empat jenis dataset, yaitu event, search, transaction, dan child [S1]. Dua daftar ini sering tertukar saat membaca dokumentasi.
- Tidak semua lookup muncul sebagai dataset: berkas lookup `.csv` dan definisi lookup (`.csv` dan KV store) terdaftar, sedangkan external lookup dan geospatial lookup tidak [S6].
- Tipe field yang disebut halaman definisi field 10.6 adalah Boolean, IPv4, Number, dan String [S3]. Halaman itu tidak menyebut tipe timestamp, padahal Pivot menyediakan filter dan fungsi khusus untuk field timestamp [S4]; perbedaan ini layak dicek di instance-mu bila kamu perlu mendefinisikan field waktu sendiri.
- Dua setelan di `datamodels.conf` yang memengaruhi perilaku model tanpa terlihat di editor: `strict_fields` yang bisa disetel di file selain di command [S2], dan `tags_whitelist` yang membatasi tag mana yang dimuat untuk meningkatkan performa, dengan catatan setelan itu tidak memvalidasi bahwa tag-nya benar-benar ada di model [S2].
- Halaman command `pivot` 10.6 memuat contoh dengan `SORT 100 host`, bentuk yang tidak cocok dengan elemen `rowsort` di sintaksnya [S8]. Untuk pengurutan, uji di lab atau urutkan di luar `pivot`.
- Angka operasional acceleration (periode summarization setiap lima menit, batas waktu search summarization satu jam, tiga search summarization bersamaan, dan pembersihan berkas `.tsidx` lama setiap tiga puluh menit) ada di halaman acceleration 10.6 [S9], tetapi pembahasannya bersama pemantauan dan `summariesonly` ada di Day 25 dan Day 26.
- Dokumentasi resmi kini di help.splunk.com, dan tautan docs.splunk.com lama masih beredar untuk halaman yang sama.

## 7. Cheat sheet

```
EMPAT JENIS DATASET (di dalam satu data model)
  root event        constraint = bagian filter search        -> BISA accelerate (syarat utama)
  root search       search string bebas, mulai command search -> accelerate HANYA bila streaming
  root transaction  butuh Group Dataset + (Group by | Max Pause | Max Span) -> TIDAK bisa accelerate
  child             constraint tambahan, warisi semua field parent
  model tidak boleh hanya transaction + turunannya
  Dataset Name: bebas kecuali *      Dataset ID: alfanumerik _ - , TIDAK bisa diubah

LIMA JENIS ATTRIBUTE
  Auto-extracted     hanya di ROOT dataset; termasuk field dari props.conf (extraction, lookup, calc)
  Eval Expression    ekspresi eval di definisi field
  Regular Expression satu regex boleh menghasilkan beberapa field
  Lookup             lookup apa pun; input harus field yang sudah ada di dataset
  Geo IP             latitude, longitude, country, city dari field IP yang valid
  kategori di editor : Inherited | Extracted | Calculated
  tipe               : Boolean | IPv4 | Number | String

FLAG DAN URUTAN (mengubah ISI, bukan tampilan)
  default            shown + optional
  Required           event tanpa field itu DIBUANG (seperti constraint tambahan)
  Hidden             tidak terlihat pengguna Pivot; untuk field perantara
  urutan             menurun atas ke bawah; Extracted sebelum Calculated
  eval yang dipakai lookup HARUS di atas lookup-nya
  flag Calculated warisan tidak bisa diubah di child -> ubah di parent

PIVOT: EMPAT KATEGORI ELEMEN
  Filters        waktu (selalu ada) + match + limit ; match hanya AND, TIDAK ada OR
  Split Rows     Label, Sort (Default | Ascending | Descending), Max Rows (0 = tanpa batas), Totals
  Split Columns  Max Columns, Group Others (default aktif; OTHER tidak dihitung ke batas)
  Column Values  String: list/values/first/last/count/dc | Number: sum/count/avg/max/min/stdev
                 Timestamp: duration/earliest/latest
  timestamp Period: Year|Month|Day|Hour|Minute|Second (default Auto)

SPL
  | datamodel <model_id> <dataset_id> search                nama field: <Dataset>.<field>
  | datamodel ... search strict_fields=false                WAJIB untuk melihat field calculated/lookup
  | datamodel ... flat                                      buang hirarki nama field
  | datamodel ... search_string                             lihat search yang sebenarnya jalan
  | pivot <model_id> <dataset_id> <cellvalue> SPLITROW <f> SPLITCOL <f> FILTER <f> <op> <v>
      cell value selalu lebih dulu; pivot = pembungkus stats + xyseries

HALAMAN DATASETS (bilah Apps di Search & Reporting)
  Explore > Visualize with Pivot     -> simpan sebagai report / panel dashboard
  Explore > Investigate in Search    -> search memakai command from, bisa jadi New Table
  Manage  > Edit Data Model          -> Data Model Editor
  permission dataset data model: Data Model Editor atau Settings > Data models (default Power/Admin)
  dataset private milik orang lain TIDAK muncul

AKSELERASI (detail di Day 26)
  syarat: model dibagikan (app/global) + root event, atau root search streaming saja
  summary range kosong = All Time ; Settings > Data Models > Edit > Edit Acceleration
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Kita buat data model supaya search-nya jadi cepat." Tepat?

<details><summary>Jawaban</summary>

Tidak. Data model adalah definisi, yaitu pemetaan pengetahuan atas data yang dipakai untuk menghasilkan laporan bagi pengguna Pivot. Kecepatan datang dari acceleration, dan acceleration punya syarat: modelnya harus dibagikan ke app atau global, dan harus punya minimal satu hirarki root event atau root search yang hanya memakai streaming command. Root transaction dataset dan root search dengan command non-streaming tidak bisa di-accelerate secara persisten, jadi sebuah data model bisa saja sama lambatnya dengan search biasa. Lihat bagian 1.1, 1.2, dan 1.8.

</details>

**2. Skenario keputusan.** Log billing PT JAB punya beberapa event per transaksi (permintaan, otorisasi, hasil), dan tim fraud ingin melihat satu transaksi sebagai satu baris. Kamu merancang dataset-nya. Pilihan mana?

- A. Root transaction dataset, karena itu memang bentuk datanya dan paling mudah dipahami pengguna.
- B. Root event dataset (ditambah child bila perlu), lalu pengelompokan per transaksi dikerjakan di luar model atau di Pivot dengan agregasi per ID transaksi.
- C. Root search dataset dengan command `transaction` di dalam search-nya.

<details><summary>Jawaban</summary>

B. Root transaction dataset dan turunannya tidak bisa di-accelerate, dan root search dataset yang memakai command non-streaming juga kehilangan kelayakan acceleration, jadi A dan C sama-sama menutup pintu kecepatan untuk seluruh cabang itu. Dokumentasi memang menyarankan search `transaction` sederhana dibuat sebagai root transaction dataset dan bukan root search dataset, tetapi itu soal memilih yang kurang buruk di antara dua jenis yang tidak bisa di-accelerate. Dengan root event dataset, agregasi per ID transaksi tetap bisa dilakukan sebagai Column Values di Pivot atau dengan `stats` di SPL, dan modelnya tetap cepat. Lihat bagian 1.2 dan 1.8.

</details>

**3. Pertanyaan jebakan.** "Field lookup yang sudah kamu definisikan di dataset otomatis ikut keluar ketika kamu menjalankan `| datamodel <model> <dataset> search`." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Secara default command itu hanya mengembalikan field default dan field yang disebut di constraint, karena `strict_fields` default-nya `true`. Untuk mendapatkan semua field model, termasuk warisan, extracted, calculated, dan hasil lookup, setel `strict_fields=false`, atau periksa lewat Pivot yang memang bekerja di atas definisi field. Kesalahan yang sering terjadi: menyimpulkan lookup-nya rusak padahal yang salah asumsi tentang default command. Lihat bagian 2.5.

</details>

**4. Jelaskan ulang.** Jelaskan kepada engineer billing PT JAB dalam tiga kalimat apa yang ia dapat dari data model dan Pivot, dibanding kalau SOC sekadar mengirimkan beberapa saved search.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Saved search menjawab satu pertanyaan yang sudah kami tebak sebelumnya, jadi setiap pertanyaan baru harus lewat kami lagi. Data model itu kami menuangkan sekali pemahaman soal log kalian ke dalam struktur: event mana yang masuk, dan kolom apa yang tersedia beserta artinya, termasuk kolom turunan seperti kategori status dan segmen pelanggan dari tabel referensi. Setelah itu kalian bisa menyusun pertanyaan sendiri di Pivot seperti pivot table di spreadsheet, dan kalau kalian memakai kolom yang sama, angkanya akan sama dengan angka kami, karena definisinya cuma satu."

Kesalahan yang sering muncul:
- Menjanjikan bahwa semua pertanyaan bisa dijawab di Pivot. Filter di Pivot hanya mendukung AND, dan pertanyaan "A atau B" tetap butuh SPL atau dataset tersendiri.
- Menjelaskannya sebagai salinan data. Data model tidak menyalin apa pun; ia definisi di atas data yang sudah ada.
- Lupa menyebut bahwa kolom yang tidak didefinisikan tidak akan terlihat di Pivot, walau ada di log mentah.

</details>

**5. Skenario keputusan.** Tim fraud melapor bahwa di tabel Pivot mereka hanya melihat dua kategori status, padahal kamu tahu ada empat. Apa yang kamu periksa lebih dulu?

- A. Definisi field `status_kategori`, karena kemungkinan ekspresi evalnya salah.
- B. Setelan Max Columns dan Group Others pada elemen Split Columns, lalu isi kolom OTHER.
- C. Acceleration, karena summary-nya mungkin tertinggal dari data mentah.

<details><summary>Jawaban</summary>

B. Split Columns punya batas jumlah kolom, dan secara default kolom berlebih dikelompokkan menjadi OTHER, yang tidak dihitung terhadap batas itu. Jadi tabel bisa tampak hanya punya dua kategori padahal dua lainnya sudah disapu ke OTHER, atau disembunyikan bila Group Others dimatikan. A layak diperiksa setelahnya, terutama bila ada kategori yang hilang sama sekali termasuk dari OTHER. C tidak menjelaskan hilangnya kategori, karena summary yang tertinggal memengaruhi kelengkapan data terbaru, bukan jumlah kolom. Lihat bagian 1.6.

</details>

**6. Pertanyaan jebakan.** "Menandai sebuah field Required hanya memengaruhi tampilan: field itu jadi pasti muncul di daftar Pivot." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Required berarti field itu harus ada di setiap event, dan event yang tidak memilikinya disaring keluar, sehingga efeknya seperti menambah satu constraint pada dataset. Yang mengatur terlihat atau tidak adalah flag Shown dan Hidden, bukan Required dan Optional. Di PT JAB, menandai `customer_id` sebagai Required pada dataset akses portal akan membuang semua akses anonim ke halaman login, yaitu justru event yang paling dibutuhkan untuk kasus pengambilalihan akun. Lihat bagian 1.5.

</details>

**7. Interview question (English).** "When would you build your own data model instead of normalizing the data to a shared model, and how do you make sure it stays fast?"

<details><summary>Sample answer</summary>

"My default is not to build one. If the source is something common, like Windows, firewall, proxy or DNS, I normalize it to the shared model instead, because then every detection, dashboard and accelerated search we already own starts working on it for free. I build a model of my own when there is genuinely no shared model for the data, which for us was the customer portal and the billing application, and when non-SPL users need to ask their own questions about it rather than queue up behind me. The design decision that matters most is the dataset type, because it is the one you cannot cheaply undo: a root event dataset, or a root search dataset that uses only streaming commands, can be accelerated, while a root transaction dataset and anything under it cannot, and a single `stats` in a root search quietly disqualifies it too. So I keep the root constraints broad and index-scoped, push the narrowing into child datasets, define the derived columns as eval, lookup, regex or geo IP fields in the right processing order, hide the intermediate ones, and never mark a field required unless I actually want events without it dropped, because required silently filters data rather than just hiding a column."

What makes this answer strong: it starts from the decision not to build, which is the senior answer, names the acceleration constraint as the irreversible design choice with the specific disqualifiers, and shows awareness that two small settings, field order and the required flag, change results rather than appearance.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Splunk Enterprise 10.6 Knowledge Manager Manual: About data models | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/build-a-data-model | primer | diakses 2026-10-14 | Tinggi. Definisi data model dan padanannya dengan skema basis data untuk Pivot, peran knowledge manager, empat jenis dataset, constraint dan pewarisan, lima jenis field, tiga kategori field, aturan field warisan, permission model mencakup semua dataset, batasan model yang hanya berisi transaction dataset, syarat root search berupa search index event, larangan auto-extracted field di child, dan perilaku sumber datar berbentuk tabel |
| S2 | Splunk Enterprise 10.6 Knowledge Manager Manual: Design data models | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/build-a-data-model/design-data-models | primer | diakses 2026-10-14 | Tinggi. Tempat membuka Data Model Editor, definisi tiap jenis dataset termasuk syarat root transaction (Group Dataset dan Group by, Max Pause, atau Max Span), saran constraint luas dan Preview, aturan Dataset Name dan Dataset ID, larangan macro di constraint child, `strict_fields` dan `tags_whitelist` di `datamodels.conf`, serta praktik terbaik (streaming command, sebut index, hindari ketergantungan sirkular, hirarki dangkal, mulai dari kebutuhan pengguna Pivot) |
| S3 | Splunk Enterprise 10.6 Knowledge Manager Manual: Define dataset fields | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/define-data-model-dataset-fields | primer | diakses 2026-10-14 | Tinggi. Lima jenis field beserta batasannya, tiga asal auto-extracted field termasuk knowledge object di `props.conf`, kategori Inherited, Extracted, dan Calculated, urutan pemrosesan menurun dan Extracted sebelum Calculated, contoh rantai eval lalu lookup, flag Shown dan Hidden serta Optional dan Required beserta efek penyaringan Required, pengecualian flag pada Calculated warisan, Override, Edit, dan Bulk Edit, tipe Boolean, IPv4, Number, dan String, larangan tanda bintang pada nama, dan catatan bahwa penggantian nama tidak mengubah index |
| S4 | Splunk Enterprise 10.6 Pivot Manual: Design pivot tables with the Pivot Editor | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/pivot-manual/10.6/building-pivots | primer | diakses 2026-10-14 | Tinggi. Keadaan awal editor dan arti jumlah hasil per jenis dataset, dua elemen default (Filter All time dan `Count_of_<dataset>`), empat kategori elemen dan aturan memindahkannya, jenis filter match per tipe field dan catatan hanya AND, limit filter beserta dasar perhitungannya, opsi Max Rows dan Max Columns, Totals, Group Others, Create ranges, Period, Label dan Sort, fungsi Column Values per tipe, paginasi, serta mode drilldown Row dan Cell |
| S5 | Splunk Enterprise 10.6 Knowledge Manager Manual: Manage datasets | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/manage-and-explore-datasets/manage-datasets | primer | diakses 2026-10-14 | Tinggi. Isi halaman Datasets (jenis, pemilik, status sharing), dataset private milik orang lain tidak ditampilkan, detail baris yang bisa dikembangkan, letak Datasets di bilah Apps, Explore dan Explorer view, Visualize with Pivot, Investigate in Search dengan command `from` dan New Table, Manage > Edit Data Model, tempat mengatur permission dataset data model, default hanya role Power dan Admin, dan pernyataan bahwa semua jenis dataset bisa dibuka di Pivot |
| S6 | Splunk Enterprise 10.6 Knowledge Manager Manual: Dataset types and usage | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/manage-and-explore-datasets | primer | diakses 2026-10-14 | Tinggi. Tiga jenis dataset di halaman Datasets (lookup, data model, table dataset), berkas dan definisi lookup yang terdaftar serta jenis lookup yang tidak terdaftar, table dataset lewat Table Views, dan istilah lama data model object |
| S7 | Splunk Enterprise 10.6 Search Reference: datamodel | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/datamodel | primer | diakses 2026-10-14 | Tinggi. Sintaks, mode hasil `search`, `flat`, dan `acceleration_search` beserta bentuk stringnya, penghapusan hirarki nama field pada mode `flat`, `strict_fields` default `true` dan arti `false`, `allow_old_summaries` dan `summariesonly` yang hanya berlaku untuk model ter-accelerate, sifat generating command, dan contoh pemakaian |
| S8 | Splunk Enterprise 10.6 Search Reference: pivot | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/pivot | primer | diakses 2026-10-14 | Tinggi. Sintaks dan daftar elemen, aturan cell value lebih dulu dan split yang boleh berselang-seling, fungsi per tipe field, operator FILTER, bentuk LIMIT, sifat report-generating command, dan pernyataan bahwa `pivot` adalah pembungkus `stats` dan `xyseries`. Contoh di halaman ini memakai `SORT 100 host` yang tidak cocok dengan elemen `rowsort` yang didokumentasikan |
| S9 | Splunk Enterprise 10.6 Knowledge Manager Manual: Accelerate data models | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/use-data-summaries-to-accelerate-searches/accelerate-data-models | primer | diakses 2026-10-14 | Tinggi. Syarat sharing (model private tidak bisa di-accelerate), syarat hirarki root event atau root search streaming, summary range dan arti nilai kosong, perilaku search yang melampaui summary range dan `summariesonly`, dataset yang tidak bisa di-accelerate secara persisten beserta ad hoc acceleration di Pivot Editor, jalur Settings > Data Models > Edit > Edit Acceleration, dan angka operasional (periode lima menit, batas satu jam, tiga search bersamaan, pembersihan tiap tiga puluh menit) |

**Catatan sumber:** keputusan desain untuk PT JAB (portal sebagai root event dataset, billing sebagai root search dataset yang hanya memakai streaming command, dan pengelompokan transaksi dibiarkan di luar model) adalah penerapan praktik terbaik di dokumentasi [S2][S9], bukan rekomendasi yang tertulis untuk kasus ini. Catatan bahwa Geo IP tidak bermakna untuk IP pelanggan di ruang alamat ISP sendiri adalah penalaran operasional; yang berasal dari dokumentasi hanya bahwa Geo IP mengisi latitude, longitude, country, dan city untuk event dengan field IP yang valid [S3]. Halaman definisi field 10.6 tidak menyebut tipe timestamp sementara Pivot menyediakan filter dan fungsi untuk field timestamp [S3][S4]; perbedaan ini belum terkonfirmasi dan perlu dicek di instance-mu. Semua keluaran di bagian 2 adalah keluaran ilustrasi yang disusun agar jumlahnya konsisten (5286 event `Portal Access`, 3127 di antaranya `Portal Login`, 1030 di antaranya gagal, dan 842 `Portal Pembayaran`), bukan hasil eksekusi.
