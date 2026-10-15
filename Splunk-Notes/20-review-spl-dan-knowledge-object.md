---
day: 20
title: 'Review SPL lanjutan dan knowledge object: peta konsep, jejak satu detection, glosarium, dan lab gabungan'
researched_on: 2026-10-15
versions_checked: 'Merangkum Day 11-19; Splunk Enterprise 10.6 (SPL Search Reference dan Knowledge Manager Manual); CIM 6.4; ES 8.7.0; dataset BOTS v1 (repo splunk/botsv1, lisensi CC0)'
---

# Day 20: Review SPL lanjutan dan knowledge object

Cakupan: ringkasan Day 11-19 (SPL lanjutan dan knowledge object), peta konsep, jejak satu detection PT JAB dari menu pivot sampai field paling dasar, daftar kegagalan yang tidak memberi error, glosarium, lab gabungan di lab sendiri dan di BOTS v1, serta latihan skenario beserta pembahasannya.

## Ide inti

Day 11-14 menajamkan SPL di dalam satu search: `rex` dan `eval` membentuk field yang belum ada, `foreach`, `lookup`, dan `makeresults` membuat logika bisa dirawat, diperkaya, dan diuji, `transaction` dan `first`/`last` mengajarkan kapan urutan benar-benar penting, dan search efisien mengajarkan cara membuktikan sebuah search lebih murah tanpa mengubah pertanyaannya. Day 15-19 memindahkan logika yang sudah terbukti berguna keluar dari search bar menjadi knowledge object yang dirawat tim: field extraction, field alias dan calculated field, event type dan tag, macro, dan workflow action. Kesembilan Day itu berporos pada satu keputusan yang sama: logika ini tinggal di search yang kutulis, atau menjadi objek yang dipakai semua orang? Dan satu kegagalan yang sama muncul berulang di hampir setiap Day: hasil yang kosong atau lebih kecil, tanpa satu pun pesan error.

Fondasi bagian ini sudah kokoh bila kamu bisa mengambil satu detection lalu menunjukkan dari tahap mana setiap field-nya lahir, objek apa saja yang dipakainya, siapa pemiliknya, siapa yang bisa melihatnya, dan bagaimana membuktikan bahwa ia bekerja untuk akun lain, bukan hanya untukmu. Menghafal sintaks tidak cukup; detection yang diam di akun pemilik yang salah tidak pernah mengeluh.

Analoginya tetap yang sudah dipakai sepanjang Day 11-19. SPL pipeline adalah pipe di shell Linux (`grep | sort | uniq -c`), dengan batas bahwa command transforming mengubah event menjadi tabel sehingga field event asli hilang setelahnya. Field extraction search-time adalah parser yang dijalankan saat log dibaca, bukan saat disimpan, sehingga bisa diperbaiki kapan saja tanpa re-ingest. Permission knowledge object adalah tiga tingkat yang ada di tempat kerja mana pun: draft pribadi, dokumen yang dibagikan ke tim, dan dokumen yang dipakai seluruh organisasi; batasnya, objek milik user yang keluar menjadi yatim dan search terjadwalnya berhenti. Review ini memeriksa apakah one-liner pribadimu sudah benar-benar naik menjadi konfigurasi bersama, dan apakah masih ada mata rantai yang hanya hidup di draft pribadi seseorang.

```
SPL DI SATU SEARCH (Day 11-14)                 KNOWLEDGE OBJECT (Day 15-19)
  rex / eval      bentuk field                   field extraction      rex yang disimpan (15)
  foreach         satu template, banyak field    alias + calculated    satu nama, satu kosakata (16)
  lookup          konteks setelah stats          event type + tag      kategori dan isi data model (17)
  makeresults     uji logika dulu                macro                 logika dipakai ulang (18)
  transaction     hanya bila sesi harus utuh     workflow action       pivot satu klik (19)
  stats           default untuk agregasi
  efisien         saring dini, ukur di Job Inspector
           |                                              |
           +---------- logika dipakai berulang? ----------+
                       ya: jadikan objek, bagikan, serahkan ke akun tim
                       tidak: biarkan di search bar

Detection gagal? Telusuri dari menu pivot ke field paling dasar,
lalu periksa pemilik dan cakupan setiap objek di sepanjang jalan.
```

Situasi yang dipakai di Day ini: detection brute force lintas sumber yang dibangun di Day 17-18 di PT Jaringan Anak Bangsa (PT JAB, ISP menengah fiktif, SOC internal satu lantai dengan NOC) akan dipindah bulan depan ke search head Enterprise Security, yang di PT JAB berdiri terpisah dari search head biasa. SOC lead menulis di kanal tim:

> "Sebelum dipindah, buktikan detection itu bekerja untuk akun lain, bukan cuma untuk yang membuatnya. Telusuri dari klik pivot analyst sampai field paling dasar. Kalau ada mata rantai yang masih hidup di search bar seseorang atau di akun pribadi, tulis sebagai temuan sekarang, jangan setelah migrasi."

Pesan itu bisa dipecah menjadi enam pertanyaan:

1. Bagian mana dari logika detection yang masih ditulis di search, dan apakah pilihannya tepat (`rex`, `eval`, `lookup`, `stats` atau `transaction`)? (Day 11-13)
2. Apakah search-nya murah untuk dijalankan terjadwal, dan apakah setiap perubahan dibandingkan secara sah? (Day 14)
3. Dari tahap mana `user`, `src`, dan `action` lahir, dan apakah urutan operasi search-time dipatuhi? (Day 15-16)
4. Bagaimana event masuk kategori `authentication` dan masuk data model? (Day 17)
5. Di mana logika dipakai ulang, dan bagaimana melihat apa yang sebenarnya dijalankan? (Day 18)
6. Bagaimana analyst pivot dari hasil detection, dan apa yang ikut keluar dari organisasi? (Day 19)

Ringkasan per Day ada di bagian 1.1 sampai 1.9. Bagian 1.10 menelusuri keenam pertanyaan itu pada detection PT JAB dengan artefak dari Day 15-19, bagian 1.11 mengumpulkan kegagalan tanpa error dari kesembilan Day, dan lab di bagian 2-4 memintamu membangun lalu menguji rantai yang sama di lab sendiri.

Day 21-28 berikutnya masuk ke data model dan normalisasi: membuat data model dan Pivot, CIM, field CIM untuk pivot investigasi, `tstats`, dan akselerasi. Semua itu mengandaikan alias, calculated field, event type, dan tag di sini sudah lancar.

**Kapan relevan:** sebelum masuk data model dan CIM, sebelum interview, dan sebelum menyerahkan detection atau knowledge object buatanmu ke tim atau ke search head lain.
**Kapan bukan jawaban:** review ini tidak menambah fakta baru. Bila ada yang terasa baru atau kabur, kembali ke Day asalnya.

## 1. Ringkasan, peta konsep, dan glosarium

### 1.1 Day 11: rex dan eval

- `rex` punya dua mode: ekstraksi dengan named capture group `(?<nama>...)` dan substitusi `mode=sed`. Field sumber default-nya `_raw`, dan mengarahkannya ke field yang lebih kecil lewat `field=` lebih cepat dan lebih tepat [S1].
- `max_match` default-nya 1; `max_match=0` berarti tanpa batas dan menghasilkan field multivalue [S1]. Command `regex` hanya menyaring event, tidak membuat field [S1].
- Mode sed hanya mengubah hasil search yang sedang dilihat, bukan data di index. Masking saat ingest adalah konfigurasi admin.
- `eval` dievaluasi dari kiri ke kanan, sehingga field yang dibuat di assignment pertama bisa dipakai di assignment berikutnya dalam `eval` yang sama. Kutip ganda berarti string literal, kutip tunggal berarti nama field, dan pembagian dengan nol menghasilkan null [S2].
- Fungsi yang paling sering dipakai: `case`, `if`, `coalesce`, `cidrmatch`, `match`, `like`, `in`, `len`, `lower`, `urldecode`, fungsi multivalue, dan fungsi waktu. Pencocokan payload dilakukan setelah `urldecode()` dan `lower()`, karena penyerang memanfaatkan encoding dan huruf besar kecil.
- Skor dari `eval` adalah alat triage, bukan detection final. Regex yang dipakai banyak dashboard dan alert sebaiknya diusulkan menjadi extraction permanen, karena logika yang hidup di lima salinan akan menyimpang.

`rex` dan `eval` adalah alat membentuk data, dan keduanya streaming, jadi murah bila dijalankan setelah data disaring. Kesalahan yang paling mahal di sini bukan soal performa, melainkan soal hasil: kutip tunggal dan ganda yang tertukar, atau pencocokan tanpa `lower()` dan `urldecode()`, membuat detection diam-diam tidak menangkap apa pun.

### 1.2 Day 12: foreach, lookup, dan makeresults

- `foreach` menjalankan satu template untuk setiap field yang cocok dengan pola (mode `multifield`, default) atau setiap elemen multivalue dan array JSON. Nama field bertitik dibungkus kutip tunggal di dalam template, `'<<FIELD>>'` [S3]. Akumulator diinisialisasi lebih dulu (`eval score=0`), karena operasi dengan null menghasilkan null.
- `lookup` dengan `OUTPUT` menimpa field event yang sudah ada, `OUTPUTNEW` hanya mengisi bila field itu belum ada, dan lookup ditempatkan setelah command transforming bila memungkinkan [S4]. Baris yang tidak cocok tidak mendapat nilai; aset yang tidak dikenal juga temuan.
- Match type `CIDR(<field>)` melekat pada lookup definition, jadi yang dipanggil adalah nama definition, bukan nama file `.csv`.
- `inputlookup append=true` lalu `stats min(firstSeen)` lalu `outputlookup` membentuk baseline "first seen" yang diperbarui terjadwal; baseline itu butuh pembersihan supaya tidak tumbuh tanpa batas.
- `makeresults` membuat hasil di memori; `format=csv` dengan `data=` membuat event dari data inline dengan batas 29.999 karakter, dan di lingkungan terdistribusi hasilnya bisa berlipat bila `splunk_server` tidak dibatasi [S5].
- Lulus uji di `makeresults` membuktikan logikanya sesuai maksudmu, bukan membuktikan detection-nya bekerja di data nyata yang punya field kosong, zona waktu aneh, dan nilai multivalue.

Ketiganya alat produktivitas. `foreach` menghindari puluhan baris `eval` yang mirip, `lookup` memberi konteks yang tidak ada di log, dan `makeresults` membuat data uji yang hasilnya bisa dihitung lebih dulu, sehingga logika diuji sebelum menyentuh data produksi.

### 1.3 Day 13: transaction dan first/last

- `transaction` mengelompokkan event yang punya nilai sama pada field-list, dengan batas `maxspan` dan `maxpause` (default tidak terbatas), `maxevents` (default 1000), serta penanda `startswith` dan `endswith`. Field yang ditambahkan: `duration`, `eventcount`, dan `closed_txn` [S6].
- Transaksi terbuka ditahan di memori; bila batas tercapai, transaksi tertua di-evict, dan karena `keepevicted` default-nya false, transaksi itu hilang dari hasil tanpa peringatan [S6]. Event harus dalam urutan waktu menurun sebelum `maxspan` diterapkan [S6].
- `stats` bisa melakukan pra-agregasi di indexer dan dokumentasi menempatkannya sebagai pilihan utama; `stats range(_time) BY trade_id` setara dengan `transaction trade_id` bila ID-nya unik [S7].
- `transaction` layak dipakai bila ID dipakai ulang sehingga butuh `maxspan` atau `maxpause`, bila awal dan akhir sesi ditandai teks, atau bila raw event yang tergabung perlu dibaca [S7]. Untuk search terjadwal yang sering berjalan, pakai `stats`.
- `first()` dan `last()` mengikuti urutan pemrosesan, jadi pada urutan default `first()` biasanya nilai terbaru; `earliest()` dan `latest()` mengikuti waktu event [S8].
- Versi `bin` plus `stats` untuk pola "gagal lalu berhasil" tidak menjamin urutan dan bisa memecah rangkaian di batas bucket; biasanya diterima untuk detection karena murah, sedangkan investigasi urutan tetap memakai `transaction`.

Benang merah Day ini adalah pertanyaan "di mana data dikerjakan dan seberapa banyak yang harus ditahan". `stats` membaca event dan bisa dikerjakan paralel di indexer, sedangkan `transaction` harus mengumpulkan event di search head dan menyimpannya di memori. Urutan pilihan yang sehat untuk pertanyaan agregat adalah `stats` dulu, dan baru `transaction` bila logika sesi memang tidak bisa diganti.

### 1.4 Day 14: search efisien

- Search berjalan dalam dua tahap: paralel di indexer, lalu terpusat di search head. Splunk mengelompokkan command ke enam tipe, dan begitu pemrosesan berpindah ke search head ia tidak kembali ke indexer [S9][S10]. Command seperti `sort` dan `eventstats` butuh seluruh data di search head, jadi ditaruh selambat mungkin.
- Saring sedini mungkin: `index=` (bukan `index=*`), `sourcetype`, `host`, `source`, rentang waktu sesempit mungkin, istilah spesifik, `TERM()`, dan `field::value` untuk indexed field [S9].
- Leading wildcard mahal. `NOT` dan `!=` juga mahal, dan semantiknya berbeda: `status!=200` hanya mengembalikan event yang punya field `status`, sedangkan `NOT status=200` juga mengembalikan event tanpa field itu [S11].
- `fields` di awal karena distributable streaming; `table` dan `sort` di akhir. Ganti `transaction` dengan `stats` bila ID unik, `join` dengan `stats` atas gabungan sumber atau `lookup`, dan `dedup` dengan `stats latest()`.
- Ukur di Job Inspector: durasi, scanCount terhadap resultCount, dan komponen yang menghabiskan waktu. Monitoring Console memperlihatkan search yang paling mahal dan yang terlewat.
- Optimasi tidak boleh mengubah pertanyaan. Versi sebelum dan sesudah harus menghasilkan resultCount yang sama di rentang waktu yang sama.

Rasio scanCount terhadap resultCount adalah angka paling berguna di Job Inspector. Bila search memindai 5 juta event untuk menghasilkan 200 baris, hampir semua kerja dibuang, dan filter seharusnya dipindah ke bagian awal. Jebakan paling halus ada pada `NOT` dan `!=`: menukar satu dengan yang lain demi kecepatan bisa mengubah hasil investigasi, bukan hanya biayanya.

### 1.5 Day 15: Field Extractor dan sharing

- `rex` dan field extraction memakai mesin regex yang sama; yang berbeda jangkauannya. Extraction yang disimpan berlaku untuk semua search pada `<spec>` itu, dan field-nya sudah bisa disaring di baris pertama search.
- Field Extractor punya alur Select sample, Select method (`Regular expression` atau `Delimiters`), Select fields atau Rename fields, Validate fields (hanya regex), dan Save [S12]. Pintu dari fields sidebar hanya memakai event yang dikembalikan search itu, dan sourcetype `Automatic` tidak ditawarkan [S12].
- Regex dari satu sample hampir selalu terjangkar pada teks varian itu. Tambah sample setiap varian, tetapkan required text, dan tandai nilai yang salah sebagai counterexample. Metode delimiter tidak punya langkah Validate, jadi cakupannya diukur sendiri dengan search; nilai yang memuat pemisah menggeser semua kolom setelahnya tanpa error.
- Hasilnya tersimpan di `props.conf` pada tier search head: `EXTRACT-<class>` untuk inline, `REPORT-<class>` untuk yang memakai transform, dan keduanya terlihat di Settings > Fields > Field extractions dengan kolom Type `inline` atau `uses transform` [S13]. `MV_ADD` default false menyimpan nilai pertama dan membuang sisanya.
- Objek baru hanya tersedia untuk pembuatnya. `Display for` bernilai App atau All apps, Read dan Write diatur per role, dan mempromosikan objek ke All apps tidak otomatis memperluas hak mengubahnya [S14]. Extraction berbasis transform punya dua objek, jadi permission transform-nya juga diperiksa.
- Objek yang pemiliknya dihapus menjadi yatim; scheduled report yang yatim berhenti karena scheduler butuh role pemilik untuk kuota dan konkurensi [S15]. Halaman Reassign Knowledge Objects bagian `Orphaned` hanya menemukan objek yang dibagikan di tingkat app atau global, dan memindahkan kepemilikan hanya bisa dilakukan role Admin [S15].
- Detection terjadwal berjalan dalam konteks pemiliknya, jadi field dari extraction yang private milik akun lain tidak ada untuknya, dan detection itu berjalan tepat waktu tanpa pernah fire.

Separuh Day 15 soal wizard, separuh lainnya soal siapa yang bisa melihat hasilnya, dan bagian kedua itu yang lebih sering menjatuhkan orang. Field yang private tidak memunculkan error bagi orang lain; search mereka hanya mengembalikan nol baris, persis seperti kalau memang tidak ada aktivitas.

### 1.6 Day 16: field alias, calculated field, dan urutan operasi search-time

- Field alias memberi nama kedua tanpa menghapus nama asli. Satu field boleh punya banyak alias, tetapi satu alias hanya boleh menunjuk satu field, dan alias tidak bisa dibuat untuk calculated field, event type, tag, atau field dari lookup [S16]; alias seperti itu tetap bisa disimpan, dan gejalanya field kosong, bukan penolakan saat menyimpan.
- `Overwrite field values` menentukan apakah nilai yang sudah ada ditimpa. Di file, `AS` menimpa dan menghapus field alias bila field asalnya tidak ada, sedangkan `ASNEW` (sejak 7.2.4) melewati field yang sudah terisi. Beberapa class yang menyasar nama alias yang sama diterapkan dalam urutan leksikografis nama class, dan yang terakhir menang [S17].
- Calculated field (`EVAL-<fieldname>`) dijalankan setelah alias dan sebelum lookup. Semua `EVAL` di satu stanza dijalankan berbarengan, sehingga tidak bisa dirantai: dengan `EVAL-x = x * 2` dan `EVAL-y = x * 2` pada `x=4`, hasilnya 8 dan 8, bukan 8 dan 16. Calculated field bernama sama dengan field hasil extraction menimpanya bahkan bila hasilnya null; `coalesce(src, ...)` mencegahnya [S18].
- Urutan operasi search-time di 10.6: field filter, inline extraction, extraction lewat transform, key-value otomatis, field alias, calculated field, lookup, event type, lalu tag. Setiap tahap hanya boleh memakai hasil tahap sebelumnya [S19].
- Satu nama dari beberapa field memakai calculated field dengan `coalesce()`, bukan dua alias. Semua nilai dipertahankan dengan `mvdedup(mvappend(...))`, dengan konsekuensi field menjadi multivalue.
- Satu nama field boleh lintas domain, satu kosakata nilai tidak. Authentication memakai `success`, `failure`, `pending`, `error` [S20]; All_Traffic memakai `allowed`, `blocked`, `teardown` [S21].
- Untuk menghitung baris yang memenuhi kondisi, `sum(eval(if(<kondisi>,1,0)))` benar, sedangkan `count(eval(<kondisi>))` ikut menghitung baris yang bernilai false.

Pertanyaan yang dibawa dari Day 16 ke setiap ekspresi yang kamu tulis: field yang aku baca ini lahir dari tahap berapa? Yang menentukan boleh atau tidak bukan nama field, tetapi tahap yang melahirkannya.

### 1.7 Day 17: event type dan tag

- Event type adalah kriteria search tersimpan; setiap event yang cocok mendapat nilai di field `eventtype`, yang berpotensi multivalue [S22].
- Search event type tidak boleh memuat pipe atau subsearch, sebaiknya tidak merujuk report lewat `savedsearch`, dan tidak boleh merujuk tag karena tag dievaluasi setelah event type [S22]. Event type menambah ongkos ke setiap search di app itu, dan dokumentasinya sendiri menunjuk macro untuk menyingkat search [S22].
- Priority (1 tertinggi, 10 terendah) dan warna hanya mengatur tampilan: urutan daftar dan warna dari priority terbaik. Keduanya tidak memengaruhi event yang cocok, hasil `stats`, atau keanggotaan data model.
- Tag menempel pada pasangan field dan value atau pada event type; dicari dengan `tag=<nama>` atau `tag::<field>=<nama>`. Splunk tidak memvalidasi pasangan yang kamu tulis, dan untuk puluhan ribu nilai yang dipakai adalah lookup.
- Data model CIM memilih anggotanya dengan tag sebagai constraint. Dataset Authentication memakai `authentication`, lalu `default`, `cleartext` atau `insecure`, dan `privileged` untuk dataset anak; `success` dan `failure` adalah nilai field `action`, bukan tag [S20].
- Rantai keanggotaan data model punya empat mata: event type cocok, tag constraint ada, nama field sesuai CIM, nilai field sesuai harapan. Satu putus, event hilang dari model tanpa error.

Di PT JAB, empat event type otentikasi (`jab_win_auth`, `jab_vpn_auth`, `jab_o365_auth`, `jab_linux_auth`) yang diberi tag `authentication` membuat satu detection berjalan di empat sumber, dan tag yang lupa dipasang pada `jab_o365_auth` membuat dataset Authentication kekurangan 2.787 dari 12.180 event pada rentang shift malam di Day 17 bagian 2.6.

### 1.8 Day 18: macro

- Macro adalah teks bernama yang disubstitusi ke dalam search sebelum search di-parse, sehingga definisinya harus sah di posisi tempat ia dipanggil dan biayanya nol saat search berjalan [S23][S24].
- Dibuat di Settings > Advanced Search > Search macros. Macro berargumen memuat jumlah argumen di namanya (`jab_window(1)`), dan argumen disubstitusi lewat `$nama$` [S23]. Nama macro tidak boleh memuat tanda hubung [S25]. Dua macro boleh bernama sama dengan jumlah argumen berbeda (overloading) [S24].
- Validation expression boolean gagal bila hasilnya false atau null dan menampilkan `errormsg`; ekspresi bukan boolean seperti `validate()` lolos bila hasilnya null dan gagal dengan string yang dikembalikannya [S23][S24]. Validasi memeriksa teks argumen, bukan keberadaan index atau field.
- `iseval = true` membuat Definition dibaca sebagai ekspresi eval yang hasilnya menjadi teks ekspansi [S24].
- Macro boleh bersarang, siklus dideteksi dan menghasilkan error, macro di dalam nilai yang dikutip tidak diekspansi, dan macro yang isinya dimulai dengan generating command dipanggil dengan pipe di luar macro [S25][S24].
- Hasil ekspansi dilihat dengan Control-Shift-E (Windows atau Linux) atau Command-Shift-E (Mac), termasuk macro bersarang, dengan tombol Open in Search [S25].
- Konten detection resmi memakai macro sumber data di baris pertama (`wineventlog_security` merujuk sebuah event type), macro utilitas seperti `security_content_ctime`, macro konfigurasi bersarang, dan macro filter `search *` di akhir untuk pengecualian lokal tanpa menyunting SPL detection [S26].

Satu konsekuensi yang paling mahal: search yang memanggil macro tidak menyimpan salinan isinya, sehingga mengubah satu definisi mengubah semua report, alert, dan detection yang memanggilnya pada jadwal berikutnya, tanpa satu pun tercatat berubah.

### 1.9 Day 19: workflow action

- Workflow action dibuat di Settings > Fields > Workflow actions, dan tiga jenisnya adalah GET (link ke sumber daya web), POST (HTTP request ke sebuah URI), dan Search (search kedua dengan nilai field event itu) [S27]. Menunya muncul di Event Actions pada Events tab atau di menu Actions pada field [S27].
- Apply only to the following fields default-nya `*`, yaitu semua field. Dengan beberapa field, menu field muncul untuk setiap field yang disebut, tetapi menu event hanya muncul bila semua field itu ada [S27]. Pembatas kedua adalah event type.
- Nilai `$field$` pada GET di-URL-encode dan pada POST di-HTTP-form-encode; prefix `$!` mencegah escaping [S28]. Encoding bukan perlindungan kerahasiaan, dan `$_raw$` mengirim seluruh event; di ISP seperti PT JAB, satu event log portal pelanggan bisa memuat ID pelanggan. Label yang memuat `$field$` membuat analyst melihat nilai yang akan dikirim sebelum mengklik.
- Search workflow action dengan Earliest dan Latest kosong berjalan atas all time [S29]. `search.preserve_timerange` default false dan diabaikan bila earliest atau latest diisi, dan nilai yang disisipkan ke search string tidak diperiksa soal quoting atau escaping [S30].
- Yang mengirim GET dan POST adalah browser analyst, sehingga nilai field tercatat di log pihak ketiga, di log proxy sendiri, dan di riwayat browser.
- Di ES 8.7, halaman triage finding mendokumentasikan drill-down search untuk mengumpulkan konteks dan tidak menyebut workflow action [S31].

Perbedaan yang paling penting untuk keputusan sehari-hari bukan teknisnya, melainkan ke mana datanya pergi. Search workflow action tetap di dalam Splunk; GET dan POST ke URI pihak ketiga membawa nilai field keluar dari organisasi. Daftar field yang eksplisit adalah kontrol keamanan, bukan kerapian.

### 1.10 Peta konsep dan jejak satu detection di PT JAB

Peta berikut menggabungkan diagram Day 11-19 dalam satu gambar. Pakai sebagai satu-satunya bantuan saat mengerjakan lab di bagian 2-4.

```
                 PERTANYAAN INVESTIGASI / DETECTION
                                |
    SEARCH YANG KAMU TULIS      |       OBJEK YANG DIRAWAT TIM
    ----------------------      |       ----------------------
    saring dini (Day 14)        |       URUTAN SEARCH-TIME (Day 16)
      index, sourcetype,        |         1 field filter
      waktu, istilah spesifik   |         2 EXTRACT-   3 REPORT-   (Day 15)
    bentuk field (Day 11)       |         4 KV_MODE
      rex field=, eval          |         5 FIELDALIAS-             (Day 16)
    iterasi (Day 12)            |         6 EVAL-  (berbarengan)    (Day 16)
      foreach '<<FIELD>>'       |         7 LOOKUP-
    agregasi (Day 13)           |         8 event type              (Day 17)
      stats BY id  <- default   |         9 tag  -> constraint data model CIM
      transaction  <- sesi      |
    konteks (Day 12)            |       DIPAKAI ULANG (Day 18)
      lookup OUTPUTNEW          |         macro: sumber, rentang, agregasi, filter
      setelah stats             |         ekspansi: Control-Shift-E
    uji (Day 12, 14)            |       PIVOT (Day 19)
      makeresults: logika       |         GET / POST keluar, Search tetap di dalam
      Job Inspector: biaya      |
                                |
         SIAPA YANG MELIHAT? permission private / App / All apps (Day 15)
         SIAPA PEMILIKNYA?   akun tim, bukan akun pribadi (Day 15)
```

Cara membaca peta: setiap kotak di sisi kanan punya objek yang bisa diperiksa di Settings, dan setiap kotak di sisi kiri punya angka yang bisa diperiksa di Job Inspector. Bila sebuah detection gagal, telusuri dari pivot ke field paling dasar sampai menemukan kotak yang objeknya hilang, private, atau lahir di tahap yang salah.

Tabel berikut menjawab permintaan SOC lead di bagian Ide inti dengan artefak fiktif PT JAB dari Day 15-19. Baca per baris dari atas; kolom terakhir adalah pertanyaan yang kamu ajukan untuk memastikan mata rantainya tidak putus ketika detection pindah ke search head ES.

| Mata rantai | Artefak PT JAB | Day asal | Pertanyaan pemeriksa |
|---|---|---|---|
| Pivot analyst | Search workflow action `jab_riwayat_ip_24jam`: field `src`, Earliest `-24h`, penanda ditulis `src="$src$"` | Day 19 bagian 2.3 | Apakah menunya muncul untuk role L1 di Events tab, dan apa padanannya bila L1 bekerja di analyst queue ES? |
| Detection | `` `jab_auth_failure` `jab_window(8)` \| `jab_top_gagal(bidang=src, ambang=50)` \| `jab_brute_force_filter` `` | Day 18 bagian 2.7 | Apakah ekspansi dari akun pemilik detection tidak menyisakan tanda petik miring, dan siapa pemilik macro filternya? |
| Logika agregasi | `stats ... BY src` di dalam `jab_top_gagal(2)`, bukan `transaction`; ambang divalidasi `isnum()` | Day 18 bagian 2.5, Day 13 bagian 1.3 | Apakah search yang berjalan terjadwal tetap murah, dan apakah resultCount sama sebelum dan sesudah setiap perubahan? |
| Kategori | Empat event type `jab_*_auth` bertag `authentication` | Day 17 bagian 2.3 | Apakah `stats count BY eventtype tag::eventtype` tidak menyisakan kolom tag kosong? |
| Nama dan nilai field | Alias `jab_vpn_cim` (`jab_user AS user`, `jab_src AS src`), `EVAL-action` per domain | Day 16 bagian 2.2 dan 2.4 | Apakah setiap selisih di search inventaris punya penjelasan yang sudah dikenal? |
| Field dasar | Extraction inline `jab_vpnlegacy_auth` untuk `jab:vpnlegacy` | Day 15 bagian 2.3 | Apakah rekan dari akun lain mendapat `ada_user` 2.244 dari 12.480 event, bukan 0? |
| Cakupan dan pemilik | `Display for` All apps, Read untuk L1, Write untuk detection engineer dan SOC lead, pemilik `svc_soc` | Day 15 bagian 2.6 | Apakah semua objek di atas, termasuk transform dan macro, ada di search head ES dengan cakupan yang sama? |

**Penilaian (bukan fakta):** mata rantai yang paling mungkin putus saat pindah ke ES bukan SPL-nya, melainkan baris pertama dan terakhir tabel. Konfigurasi search-time dibuat di tier search head [S19], jadi objek yang hanya dibagikan ke app SOC di search head biasa tidak ada di search head ES, dan workflow action yang dibuat di Splunk Enterprise belum tentu muncul di analyst queue, yang dokumentasinya menyebut drill-down search sebagai cara mengumpulkan konteks [S31]. Keduanya ditulis sebagai temuan sebelum migrasi.

### 1.11 Kegagalan yang tidak memberi error

Kesembilan Day punya satu pola yang sama: yang salah tidak berteriak, ia hanya menghasilkan angka yang lebih kecil, kolom yang kosong, atau nilai yang terlihat masuk akal. Tabel ini mengumpulkannya supaya bisa dipakai sebagai daftar periksa; cari gejalanya di kolom pertama, lalu buka Day di kolom ketiga.

| Gejala | Penyebab | Day asal | Cara membuktikan |
|---|---|---|---|
| Search orang lain nol baris, detection milik akun lain tidak pernah fire | Extraction, alias, event type, atau macro masih private, atau cakupannya App | Day 15 bagian 1.6 | Jalankan dari akun pemilik detection; hitung event dengan dan tanpa filter field |
| Field terisi di sebagian event saja | Regex wizard terjangkar pada satu varian | Day 15 bagian 1.3 | `count(<field>)` per varian baris |
| Kolom berpemisah terlihat wajar tetapi isinya milik kolom lain | Nilai memuat pemisah | Day 15 bagian 1.4 | `mvcount(split(_raw,","))` per event |
| Calculated field kosong untuk semua event | Membaca `EVAL` lain di stanza yang sama, atau field dari tahap sesudahnya | Day 16 bagian 1.6 | `stats count(<field>)` sebelum dan sesudah ekspresi digabung |
| Nilai alias berubah setelah orang lain menambah objek | Beberapa class alias ke satu nama, menang menurut urutan leksikografis | Day 16 bagian 1.3 | Daftar objek alias pada sourcetype itu di Settings > Fields > Field aliases |
| Event type tidak pernah cocok | Definisinya merujuk tag | Day 17 bagian 1.3 | Jalankan kriterianya sebagai search biasa |
| Pivot atau data model lebih kecil dari search langsung | Satu event type belum punya tag constraint | Day 17 bagian 1.7 | `stats count BY eventtype tag::eventtype` |
| Kolom kosong di hasil macro | Argumen terbaca sebagai string | Day 18 bagian 1.5 | Validasi `isnum()` dan baca hasil ekspansi |
| Alert berubah perilaku tanpa ada yang menyuntingnya | Definisi macro yang dipanggilnya berubah | Day 18 bagian 1.1 | Cocokkan waktu perubahan macro dengan waktu alert |
| Jumlah sesi lebih kecil dari dugaan | Transaksi di-evict, `keepevicted` default false | Day 13 bagian 1.2 | `keepevicted=true` lalu baca `closed_txn` |
| "Waktu pertama" ternyata waktu terbaru | `first()` mengikuti urutan pemrosesan | Day 13 bagian 1.4 | Bandingkan `first()` dengan `earliest()` di satu `stats` |
| Hasil berubah setelah "optimasi" | `NOT f=x` ditukar dengan `f!=x` | Day 14 bagian 1.3 | Bandingkan resultCount di rentang yang sama |
| Skor `foreach` kosong | Akumulator tidak diinisialisasi | Day 12 bagian 1.1 | `eval score=0` sebelum `foreach` |
| Field CIM berisi nilai dari tabel referensi | `lookup ... OUTPUT` menimpa field event | Day 12 bagian 1.2 | Bandingkan dengan `OUTPUTNEW` |
| Detection melewatkan variasi serangan | Regex hanya diuji satu kasus positif | Day 12 bagian 2.5 | `makeresults` dengan kasus positif, negatif, dan variasi |
| Scheduled report berhenti | Pemiliknya bukan lagi akun valid | Day 15 bagian 1.7 | Reassign Knowledge Objects bagian `Orphaned` |
| Klik pivot membebani search head | Search workflow action tanpa Earliest berjalan atas all time | Day 19 bagian 1.5 | Job Inspector dari job yang dibuka menu itu |

Satu kalimat yang perlu dibawa ke setiap shift: nol baris adalah hasil yang harus dibuktikan, bukan kabar baik yang diterima begitu saja.

### 1.12 Glosarium

Definisi di bawah ditulis dengan kata sendiri untuk keperluan belajar. Kolom "Sering tertukar dengan" memuat pasangan yang paling sering membuat jawaban interview keliru, dan kolom Day menunjuk tempat kembali bila istilahnya terasa kabur.

| Istilah | Arti singkat | Sering tertukar dengan | Day |
|---|---|---|---|
| `rex` | Ekstraksi field dengan named group, atau substitusi `mode=sed` | `regex` (hanya menyaring) | 11 |
| `max_match` | Jumlah kecocokan `rex`; default 1, 0 berarti tanpa batas | | 11 |
| Kutip tunggal di `eval` | Nama field | Kutip ganda (string literal) | 11 |
| `foreach` | Satu template untuk banyak field atau elemen | Loop yang menghitung berurutan seperti bahasa pemrograman | 12 |
| `OUTPUTNEW` | Lookup hanya mengisi field yang belum ada | `OUTPUT` (menimpa) | 12 |
| Match type CIDR | Opsi lookup definition untuk mencocokkan IP dengan subnet | Nama file `.csv` | 12 |
| `makeresults` | Hasil sintetis di memori untuk menguji logika | Bukti detection bekerja di produksi | 12 |
| `closed_txn` | 1 transaksi tertutup normal, 0 tidak tertutup atau di-evict | Jumlah sesi sebenarnya | 13 |
| `first()` | Nilai pertama menurut urutan pemrosesan | `earliest()` (menurut waktu) | 13 |
| Distributable streaming | Command yang berjalan paralel di indexer | Dataset processing (`sort`, `eventstats`) | 14 |
| scanCount | Jumlah event yang dipindai | resultCount | 14 |
| `f!=x` | Event yang punya field `f` dengan nilai selain `x` | `NOT f=x` (termasuk event tanpa `f`) | 14 |
| Knowledge object | Objek yang menambah arti ke data tanpa mengubah data | Data itu sendiri | 15 |
| Field Extractor | Wizard pembuat extraction dari event contoh | `rex` di search bar | 15 |
| Counterexample | Nilai hasil ekstraksi yang ditandai salah di langkah Validate | Required text | 15 |
| `EXTRACT-` dan `REPORT-` | Extraction inline dan extraction yang memakai transform | | 15 |
| `Display for` | Cakupan objek: App atau All apps | Read dan Write (hak per role) | 15 |
| Objek yatim | Objek yang pemiliknya bukan lagi akun valid | Objek private | 15 |
| Field alias | Nama kedua untuk field yang sudah ada | Mengganti nama field | 16 |
| `ASNEW` | Alias yang melewati field tujuan yang sudah terisi | `AS` (menimpa) | 16 |
| Calculated field | Field dari ekspresi `eval` yang dihitung setiap search | Field hasil extraction | 16 |
| Urutan operasi search-time | Urutan tetap tahap saat event dibaca | Urutan command di pipeline | 16 |
| Event type | Kriteria tersimpan yang memberi label ke event yang cocok | Saved search atau report | 17 |
| Tag | Label pada pasangan field-value atau event type | Nilai field `action` | 17 |
| Tag constraint | Tag yang menentukan event masuk dataset CIM | Filter index | 17 |
| Macro | Teks SPL bernama yang disubstitusi sebelum search jalan | Event type | 18 |
| Validation expression | Ekspresi eval yang memeriksa argumen macro | Pemeriksaan keberadaan field | 18 |
| Macro filter | Macro `search *` di akhir detection untuk pengecualian | `NOT` di awal search | 18 |
| Workflow action | Menu pivot di event atau field | Adaptive response | 19 |
| `$!field$` | Nilai field tanpa escaping pada GET dan POST | `$field$` | 19 |
| `search.preserve_timerange` | Memakai rentang search asal; diabaikan bila earliest atau latest diisi | Kolom waktu kosong (all time) | 19 |

## 2-4. Lab gabungan dan troubleshooting

Lab ini terdiri dari dua bagian yang saling melengkapi. Bagian A membangun dan mengaudit rantai knowledge object Day 15-19 di lab sendiri, karena hanya di lab kamu bisa menjadi dua user dan membuktikan apa yang dilihat orang lain. Bagian B melatih SPL lanjutan Day 11-14 pada dataset BOTS v1. Bagian C berisi latihan skenario singkat. Semua langkah dijalankan di VM lab terisolasi, tanpa data dari pekerjaan.

### Bagian A: rantai knowledge object dari akun lain (Day 15-19)

**Prasyarat:** satu instance Splunk Enterprise lab tanpa ES, satu index lab, dan berkas fiktif dari lab Day 15 dan Day 16 (`vpnlegacy.log` 40 baris dengan 25 `AUTH FAIL`, 8 `AUTH OK`, 4 `AUTH FAIL (unknown user)`, 3 `SESSION CLOSE`; `fwpop.csv`; `proxypop.log` dengan dua generasi nama alamat klien). Buat ulang bila belum ada, dan catat komposisinya sebelum mulai. Siapkan dua akun: akun pembuat, dan akun kedua dengan role `user`.

1. **Extraction (Day 15 bagian 2.2 dan 2.3).** Prototipe dengan `rex` dulu, lalu simpan lewat Field Extractor dengan sample setiap varian dan required text `AUTH`. Dari 33 baris `AUTH`, 29 baris seharusnya menghasilkan nama akun dan 4 tidak. Catat juga apakah keempat baris `(unknown user)` tetap mendapat `jab_result` dan `jab_src`. Dengan regex Day 15 bagian 2.2 seharusnya ya, karena grup nama akun punya alternatif `\(unknown user\)`; tanpa alternatif itu regex gagal di tengah dan tidak mengisi grup apa pun.
2. **Normalisasi (Day 16 bagian 2.2 sampai 2.4).** Buat alias untuk VPN dan firewall, calculated field `coalesce(src, c_ip, x_client_ip)` untuk proxy, dan `EVAL-action` per domain. Jalankan search inventaris Day 16 bagian 2.6 dan tulis penjelasan untuk setiap selisih antara `total` dan kolom lainnya.
3. **Kategori (Day 17 bagian 2.1 sampai 2.3).** Buat satu event type untuk autentikasi VPN lab tanpa pipe, beri tag `authentication`, lalu jalankan `| stats count BY eventtype tag::eventtype`. Bila add-on CIM terpasang di lab, bandingkan dengan `| datamodel Authentication Authentication search | stats count`.
4. **Macro (Day 18 bagian 2.1 sampai 2.7).** Buat `lab_auth`, `lab_fail` yang memanggilnya, `lab_top_gagal(2)` dengan validasi `isnum()`, dan `lab_brute_force_filter` berisi `search *`. Susun detection dari keempatnya, lalu tekan Control-Shift-E dan simpan hasil ekspansinya.
5. **Pivot (Day 19 bagian 2.1 dan 2.3).** Buat Search workflow action untuk field `src` dengan Earliest `-24h` dan penanda dikutip, dan satu GET ke `https://example.com/lookup?ip=$src$` yang dibatasi ke field `src` saja.
6. **Uji dari akun kedua, sebelum dibagikan.** Login sebagai akun kedua, jalankan detection dari langkah 4 dan buka satu event untuk mencari kedua menu dari langkah 5. Isi tabel berikut untuk setiap objek: terlihat atau tidak, dan gejala apa yang muncul (nol baris, pesan macro tidak ditemukan, menu tidak ada).
7. **Bagikan dan serahkan.** Ubah setiap objek ke All apps dengan Read untuk role `user`, periksa juga transform bila ada extraction bertipe `uses transform`, lalu pindahkan kepemilikan ke akun lain lewat Reassign Knowledge Objects. Ulangi langkah 6 dan isi kolom kedua tabel.
8. **Yatimkan dengan sengaja.** Buat satu scheduled report sederhana milik akun ketiga yang memakai field dari langkah 1, nonaktifkan akun itu, lalu periksa dashboard orphaned dan halaman Reassign Knowledge Objects. Catat objek mana yang terdeteksi dan mana yang tidak (Day 15 bagian 2.7).

Tabel kerja untuk langkah 6 dan 7:

```
Objek                     Jenis              Sebelum dibagikan (akun kedua)   Sesudah dibagikan
jab_vpnlegacy_auth        extraction         ...                              ...
alias + EVAL-action       alias / calc       ...                              ...
event type + tag          event type / tag   ...                              ...
lab_auth ... filter       macro              ...                              ...
riwayat src / GET         workflow action    ...                              ...
```

**Cara membaca hasil Bagian A:** kolom "sebelum dibagikan" seharusnya memperlihatkan tiga gejala berbeda untuk masalah yang sama. Field dari extraction, alias, dan event type yang private menghasilkan nol baris atau kolom kosong tanpa error. Macro yang private menghasilkan pesan bahwa macro tidak ditemukan, satu-satunya gejala yang bersuara. Workflow action yang private hanya tidak muncul di menu. Bila kolom "sesudah dibagikan" masih memuat satu gejala, cari objek kedua yang terlewat: transform di belakang extraction, atau macro terdalam di rantai bersarang.

### Bagian B: SPL lanjutan di BOTS v1 (Day 11-14)

**Prasyarat:** BOTS v1 dari Splunk, dirilis 2016 dengan lisensi CC0. Datanya ada di `index=botsv1` dan berisi 21 sourcetype (Windows event log, Sysmon, Fortigate, IIS, Nessus, Stream (DNS/HTTP/SMB, dll.), Suricata, registry Windows), dan membutuhkan add-on terkait, termasuk TA Windows, Sysmon, Stream, Suricata, dan URL Toolbox [S32]. Tersedia versi penuh (sekitar 6,1 GB terkompresi) dan versi "attack only" (sekitar 135 MB) [S32]. BOTS v1 memuat dua skenario: defacement website fiktif `imreallynotbatman.com` dan ransomware pada workstation `we8105desk` [S33]. Cek nama field di instalasimu, karena versi add-on memengaruhi nama field.

Dataset ini juga dipakai sebagai CTF. Lab di bawah memakai metode tanpa menyebut jawaban spesifik; tujuan latihannya adalah prosesnya.

1. **Tentukan rentang.** Ikuti cara Day 01 bagian 2.5: `index=botsv1 earliest=0 | stats min(_time) AS awal max(_time) AS akhir count BY sourcetype`, lalu ubah `awal` dan `akhir` dengan `strftime`. Catat rentang tanggal kejadian; semua langkah berikutnya memakai rentang absolut itu, misalnya `earliest="08/01/2016:00:00:00" latest="09/01/2016:00:00:00"` seperti di Day 14 bagian 2.1 setelah tanggalnya kamu pastikan. Versi `tstats` yang jauh lebih murah dibahas di Day 25.
2. **Sumber teratas ke situs target.** Dengan rentang absolut dari langkah 1:

   ```
   index=botsv1 sourcetype=stream:http site="imreallynotbatman.com"
   | stats count dc(uri) AS uris values(http_user_agent) AS ua BY src_ip
   | sort - count
   ```

3. **Skor request.** Terapkan pola `eval` Day 11 bagian 2.3 dengan flag bernama `f_*`, lalu jumlahkan dengan `eval score=0 | foreach f_* [eval score = score + '<<FIELD>>']` seperti Day 12 bagian 2.2.
4. **Konteks aset.** Buat `lab_assets.csv` untuk IP internal web server dan workstation berdasarkan observasimu sendiri, lalu `lookup ... OUTPUTNEW` setelah `stats` (Day 12 bagian 2.3). Ukur durasi bila `lookup` ditaruh sebelum `stats`.
5. **Upload atau brute force ke CMS.** Cari `http_method=POST`, pola `uri` login, dan form data bila terekstrak. Pakai `rex field=<field form data>` bila parameter tidak ter-parse, dengan `max_match=0` bila satu event memuat banyak nilai, dan cek nama field form data di `stream:http`.
6. **Timeline per penyerang.** `stats earliest(_time) AS awal latest(_time) AS akhir count BY src_ip uri`. Jangan memakai `first`/`last` untuk waktu (Day 13 bagian 2.4).
7. **Sesi web: transaction lawan stats.** Buat sesi per `src_ip` dengan `transaction src_ip maxpause=5m keepevicted=true`, lalu versi `streamstats` yang menandai jeda lebih dari 5 menit sebagai sesi baru (variasi tantangan di Day 13 bagian 3). Bandingkan jumlah sesi, jumlah `closed_txn=0`, dan durasi job.
8. **Validasi logika.** Ambil satu regex atau ambang dari langkah 3 atau 5, lalu uji dengan `makeresults format=csv data=...` berisi 3 kasus positif dan 2 kasus negatif yang kamu tulis sendiri (Day 12 bagian 2.5). Hitung hasil yang diharapkan sebelum menjalankan.
9. **Sebelum dan sesudah.** Pilih search paling lambat dari langkah 2 sampai 7, optimalkan dengan prinsip Day 14, lalu catat durasi, scanCount, dan resultCount kedua versi di rentang yang sama. ResultCount harus identik.

**Cara membaca hasil Bagian B:** sumber dengan jumlah request sangat tinggi, `dc(uri)` besar, dan user agent yang menyebut nama tool pemindai biasanya adalah tahap reconnaissance. Sumber lain dengan request lebih sedikit tetapi banyak `POST` ke halaman login adalah kandidat brute force. Bedakan keduanya di catatanmu, karena di insiden nyata dua aktivitas itu bisa berasal dari IP berbeda milik aktor yang sama. Skor dari `eval` hanya alat urut; setiap `src_ip` dengan skor tinggi tetap perlu dibaca event-nya.

Pada langkah 7, jumlah sesi dari `transaction` dan dari `streamstats` bisa berbeda tipis. Penyebab umumnya transaksi yang ter-evict (`closed_txn=0`) atau batas `maxevents` (default 1000) yang memotong sesi panjang. Catat selisihnya dan penyebabnya. Untuk scheduled search, pilihan yang wajar adalah versi `streamstats` dan `stats` karena lebih murah dan tidak bergantung memori search head.

**Variasi lab:** ulangi metode Bagian B untuk skenario ransomware pada `we8105desk` dengan sumber Sysmon dan registry Windows. Fokus pada metode: proses apa yang muncul pertama kali di host itu, koneksi keluar apa yang menyertainya, dan perubahan file apa yang terjadi dalam jumlah besar. Pakai `stats count BY sourcetype` untuk inventaris sumber host itu, `stats earliest/latest` untuk timeline, dan `rex`/`eval` untuk mengambil nama file dan ekstensi.

### Bagian C: latihan skenario singkat

Jawab dulu tiap skenario sebelum membaca pembahasannya.

**Skenario A.** Kamu perlu durasi setiap sesi VPN. Log VPN memiliki `session_id` yang unik per sesi, dan setiap sesi punya event connect dan disconnect.
Pembahasan: karena ada ID unik, `stats earliest(_time) AS start latest(_time) AS end range(_time) AS duration BY session_id user` sudah cukup dan jauh lebih murah daripada `transaction`. `transaction` baru diperlukan bila ID dipakai ulang (misalnya Logon ID Windows yang bisa muncul lagi setelah reboot) sehingga butuh `maxspan`/`maxpause`, atau bila awal dan akhir sesi hanya bisa dikenali dari teks (Day 13).

**Skenario B.** Rekanmu menulis timeline dengan `stats first(_time) AS waktu_awal BY src_ip` dan heran waktu awalnya selalu paling baru.
Pembahasan: `first()` mengambil nilai pertama menurut urutan pemrosesan. Search biasa mengembalikan event dari yang terbaru, jadi `first(_time)` adalah waktu terakhir. Untuk timeline, pakai `earliest(_time)` dan `latest(_time)` yang berbasis waktu (Day 13).

**Skenario C.** Detection PowerShell terenkode di lab menangkap `-enc` tetapi melewatkan `-EncodedCommand` dan `-ec`.
Pembahasan: regex terlalu sempit. PowerShell menerima singkatan parameter apa pun yang tidak ambigu dan alias `-ec`, serta awalan `-` atau `/`. Perluas pola, lalu uji dengan `makeresults format=csv` berisi minimal tiga kasus positif (`-e`, `-EncodedCommand`, `/ec`) dan dua kasus negatif (parameter lain yang diawali huruf e, perintah tanpa parameter terenkode) sebelum detection dipakai (Day 11-12).

**Skenario D.** Search investigasi kamu memakai `| lookup asset_list.csv ip AS src_ip OUTPUT owner` tepat setelah `index=proxy` dan berjalan 6 menit.
Pembahasan: lookup dijalankan untuk setiap event. Pindahkan ke setelah `stats ... BY src_ip`, sehingga lookup hanya berjalan sekali per IP unik. Hasilnya sama, durasinya turun drastis. Bila `asset_list.csv` berisi subnet, definisikan lookup definition dengan match type `CIDR(ip)` (Day 12 dan 14).

**Skenario E.** Detection engineer ingin event type `brute_force_vpn` berisi `index=vpn action=failure | stats count BY src | where count > 50`, supaya alert cukup menulis `eventtype=brute_force_vpn`.
Pembahasan: event type tidak boleh memuat pipe atau subsearch, karena ia harus bisa dijawab untuk satu event dengan ya atau tidak. Kriterianya (`index=vpn action=failure`) boleh menjadi event type; agregasi dan ambangnya menjadi macro berargumen dengan validasi, seperti `jab_top_gagal(2)` (Day 17 dan 18).

**Skenario F.** Proxy punya `c_ip` di event lama dan `x_client_ip` di event baru. Rekanmu membuat dua alias ke `src` dan menyebut pekerjaannya selesai.
Pembahasan: satu alias hanya boleh menunjuk satu field, dan dua class yang menyasar nama yang sama diselesaikan secara leksikografis menurut nama class, bukan menurut niatnya. Pakai satu calculated field `coalesce(src, c_ip, x_client_ip)` setelah membuktikan kedua field tidak pernah muncul bersamaan (Day 16).

**Skenario G.** Scanner kerentanan internal `10.20.30.9` memicu detection brute force setiap minggu. Rekanmu menambahkan `NOT src="10.20.30.9"` ke baris pertama detection.
Pembahasan: pengecualian itu sebaiknya masuk ke macro filter di akhir detection, misalnya `jab_brute_force_filter` menjadi `search NOT src="10.20.30.9"`, sehingga detection-nya tidak disunting dan pengecualian berjalan atas hasil agregasi. Isi macro filter diperlakukan sebagai daftar yang punya pemilik dan ditinjau, karena pengecualian yang terlalu luas mematikan detection tanpa jejak (Day 18).

**Skenario H.** Search workflow action riwayat IP dibuat dengan kedua kolom waktu kosong dan search string `index=dns src=$src$`.
Pembahasan: kolom waktu yang kosong berarti all time, dan `index=dns` di PT JAB berisi resolver pelanggan bervolume besar. Nilai yang disisipkan juga tidak di-quote atau di-escape oleh Splunk. Isi minimal Earliest, tulis penanda sebagai `src="$src$"`, dan batasi action ke field `src` (Day 19).

### Troubleshooting lintas Day

Tabel ini memetakan gejala yang sering muncul di lab ke Day yang perlu diulang. Mulai dari gejala yang paling mirip dengan kesulitanmu.

| Gejala | Day yang perlu diulang | Pemeriksaan |
|---|---|---|
| Tidak ada hasil sama sekali di BOTS v1 | 01, 14 | Rentang waktu default 24 jam; pakai `earliest=0` untuk mencari rentang, lalu rentang absolut 2016 |
| Field kosong di `stream:http` | 11 | TA Stream tidak terpasang atau versinya berbeda; pasang add-on yang disebut repo [S32] dan cek nama field |
| Search lambat | 13, 14 | `index=*`, Verbose mode, `transaction` atas semua data, `lookup` sebelum `stats` |
| Hasil berbeda setelah dipercepat | 14 | Apakah kedua versi menjawab pertanyaan yang sama dan resultCount-nya identik? |
| Field ada di layarmu, kosong di layar rekan | 15 | Permission, `Display for`, transform yang dirujuk, dan app context |
| Calculated field atau alias kosong | 16 | Field yang dibaca lahir di tahap berapa? |
| Data model lebih kecil dari search langsung | 17 | Tag constraint per event type, lalu nama dan nilai field |
| Pesan macro tidak ditemukan | 18 | Jumlah argumen di nama, permission, Destination app |
| Menu workflow action tidak muncul | 19 | Events tab atau Statistics tab, daftar field, event type, permission |
| Scheduled report berhenti tanpa error | 15 | Pemilik objek dan halaman Reassign Knowledge Objects |

**Hasil yang sebaiknya tersimpan:**

- Tabel lima objek dari Bagian A langkah 6 dan 7, dengan gejala per objek sebelum dan sesudah dibagikan.
- Hasil ekspansi detection dari Bagian A langkah 4, dan daftar objek yatim yang terdeteksi serta yang tidak dari langkah 8.
- Rentang waktu kejadian BOTS v1 dari Bagian B langkah 1.
- Daftar `src_ip` mencurigakan beserta skor dan alasannya, dan timeline penyerang berbasis `earliest`/`latest`.
- Perbandingan `transaction` dan `streamstats` dengan angka, dan satu uji `makeresults` dengan hitungan yang diharapkan.
- Tabel sebelum dan sesudah dari Bagian B langkah 9 dengan resultCount yang identik.
- Jawaban tertulis untuk skenario A sampai H, lalu catatan Day mana yang jawabanmu paling banyak meleset dari pembahasan.

## 5. Kesalahan umum dan jebakan

- Menganggap nol baris sebagai bukti aman. Objek private, tag yang hilang, dan `EVAL` yang dirantai semuanya menghasilkan nol atau angka lebih kecil tanpa error (bagian 1.11).
- Membiarkan logika yang dipakai banyak dashboard dan detection hidup sebagai salinan `rex` di setiap search (Day 11).
- Kutip tunggal dan ganda tertukar di `eval` dan `foreach` (Day 11-12).
- `lookup` sebelum `stats`, atau `OUTPUT` yang menimpa field CIM (Day 12).
- `first()` untuk "waktu pertama", dan `transaction` di search terjadwal yang sering berjalan (Day 13).
- `NOT` dan `!=` dianggap sama, dan optimasi tanpa membandingkan resultCount (Day 14).
- Menyimpan hasil Field Extractor dari satu sample, dan menganggap extraction yang bekerja di layarmu sudah bekerja untuk tim (Day 15).
- Membiarkan objek operasional dimiliki akun pribadi (Day 15).
- Dua alias ke satu nama, rantai `EVAL`, dan satu kosakata nilai untuk semua domain (Day 16).
- Event type yang memuat pipe atau merujuk tag, dan `tag=failure` sebagai pengganti `action=failure` (Day 17).
- Mengubah macro bersama tanpa catatan, dan memasang detection dari luar tanpa membaca ekspansinya (Day 18).
- Workflow action eksternal dengan daftar field `*` atau `$_raw$`, dan Search workflow action tanpa Earliest (Day 19).
- Rentang waktu relatif (`earliest=-30d`) pada dataset statis 2016 (Bagian B di bagian 2-4).

## 6. Catatan terkini

Bagian ini menampung detail versi dan perubahan dokumentasi yang dipakai di Day 11-19. Isinya tidak mengubah review, tetapi menjelaskan kenapa materi lama dan layar di versi-mu bisa berbeda.

- BOTS v1 dibuat dengan Splunk 6.5.2 dan versi add-on lama [S32]. Pada Splunk 10.x dan add-on terbaru, nama field atau sourcetype bisa berbeda dari write-up lama di internet. Selalu verifikasi dengan data di instance Splunk-mu.
- Banyak write-up publik dan lab CTF (mis. CyberDefenders "Boss Of The SOC v1", proyek kelas samsclass) memakai dataset ini [S33][S34]. Lab di Day ini sudah memuat metode yang dibutuhkan, jadi write-up itu tidak perlu dibuka; bila tetap dibaca, pakai hanya untuk membandingkan metode, bukan jawaban.
- Urutan operasi search-time di 10.6 memuat field filter sebagai langkah pertama [S19]. Materi lama yang menyebut extraction sebagai langkah pertama tidak salah untuk versinya, hanya tidak lengkap untuk 10.6.
- Kata kunci `ASNEW` dan perilaku alias yang menghapus field ketika field asalnya tidak ada berlaku sejak 7.2.4, dan dijelaskan di catatan perubahan perilaku field alias dokumentasi Splunk Cloud Platform 10.6 [S17]; halaman field alias Knowledge Manager Manual 10.6 tidak menyebutnya.
- Spesifikasi `eventtypes.conf` 10.6 menandai atribut `tags` sebagai DEPRECATED, sementara UI masih menyediakan kolom Tag(s) (Day 17 bagian 6). Jalur yang aman adalah `tags.conf` atau halaman Tags di UI.
- Mode `foreach` selain `multifield` dan `makeresults format=` relatif baru; versi yang pertama kali memperkenalkannya belum dikonfirmasi, jadi uji dulu di lab versi 9.x lama (Day 12 bagian 9).
- Dokumentasi resmi kini di help.splunk.com, dan tautan docs.splunk.com lama masih beredar untuk halaman yang sama.

## 7. Cheat sheet

```
SPL DI SATU SEARCH
rex     | rex field=F "(?<x>re)" max_match=0 | rex field=F mode=sed "s/a/b/g"   (default _raw, max_match 1)
eval    | eval a=case(..,true(),..), b=if(), c=coalesce(), d=cidrmatch("cidr",ip), e=match(f,"re"), u=lower(urldecode(uri))
        "..." = string   '...' = nama field   /0 -> null   in() di eval/where, IN (...) di search
foreach | eval s=0 | foreach f_* [eval s=s+'<<FIELD>>']
lookup  | stats ... | lookup def key AS field OUTPUTNEW cols   (CIDR(f)/WILDCARD(f) di definition)
mkres   | makeresults format=csv data="a,b\n1,2" | makeresults count=N | streamstats count AS n | eval _time=now()-n*60
trans   | transaction <ids> maxspan= maxpause= startswith= endswith= keepevicted=t -> duration eventcount closed_txn
stats   | stats earliest(_time) latest(_time) range(_time) count values() dc() BY <id>
order   first/last = urutan proses | earliest/latest = waktu
EFISIEN index/sourcetype/waktu/istilah -> fields -> eval/rex/where -> stats -> lookup -> sort -> table
        f!=x hanya event yang PUNYA f | NOT f=x termasuk event TANPA f | ukur: durasi, scanCount, resultCount

KNOWLEDGE OBJECT
FX      Select sample > method (regex|delimiter) > fields/rename > Validate (regex saja) > Save
URUTAN  filter > EXTRACT > REPORT > KV_MODE > FIELDALIAS > EVAL (berbarengan) > LOOKUP > eventtype > tag
ALIAS   satu alias = satu field ; dua class ke satu nama: leksikografis ; AS timpa, ASNEW lewati
EVAL    EVAL-src = coalesce(src, c_ip, x_client_ip)   tidak bisa baca EVAL lain atau lookup
NILAI   Authentication: success failure pending error | All_Traffic: allowed blocked teardown
ETYPE   tanpa pipe, subsearch, savedsearch, tag ; eventtype multivalue ; priority = tampilan saja
TAG     tag=x  tag::field=x  tag::eventtype ; CIM Authentication: tag authentication (+ default,
        cleartext/insecure, privileged) ; verifikasi: stats count BY eventtype tag::eventtype
MACRO   [nama(2)] args= definition=$a$ validation= errormsg= iseval= ; Control/Command-Shift-E
        generating cmd: | `macro` ; tidak diekspansi di dalam "..." ; filter: search *
WFA     GET (URL-encode) | POST (form-encode) | Search (TIDAK di-escape: src="$src$")
        fields default * ; Earliest+Latest kosong = all time ; preserve_timerange diabaikan bila diisi
SHARE   private -> App -> All apps ; Read pakai, Write ubah ; owner akun tim ; yatim -> terjadwal berhenti
DEBUG   nol baris? jalankan dari akun pemilik, telusuri pivot -> macro -> tag -> eventtype -> EVAL -> alias -> extraction
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci. Soal di bawah mencampur materi Day 11-19; kunci juga menunjuk Day asal bila perlu diulang.

**1. Pertanyaan jebakan.** Detection brute force PT JAB berjalan benar di search head biasa dari akun pembuatnya. Setelah dipindah ke search head ES dan dijalankan oleh akun fungsional, hasilnya nol baris tanpa error. Rekanmu menyimpulkan data otentikasi belum masuk ke ES. Tepat?

<details><summary>Jawaban</summary>

Belum tentu, dan itu bukan hipotesis pertama. Knowledge object baru hanya tersedia untuk pembuatnya, dan field yang private tidak memunculkan error bagi orang lain, hanya nol baris. Konfigurasi search-time dibuat di tier search head, jadi extraction, alias, calculated field, event type, tag, dan macro harus ada di search head ES dengan cakupan yang mencakup app yang dipakai di sana, dan detection terjadwal berjalan dalam konteks pemiliknya. Buktikan dengan menjalankan search dari akun pemilik detection, menghitung event dengan dan tanpa filter field, lalu memeriksa permission setiap objek di rantai, termasuk transform dan macro terdalam. Lihat bagian 1.5, 1.10, dan 1.11, atau Day 15 bagian 1.6.

</details>

**2. Skenario keputusan.** Logika "kegagalan otentikasi, dikelompokkan per `src`, ambang 50" kini dipakai di sembilan search. Detection engineer ingin satu tempat untuk merawatnya. Mana yang dipilih?

- A. Event type berisi `tag=authentication action=failure | stats count BY src | where count >= 50`.
- B. Event type untuk kriterianya, ditambah macro berargumen untuk agregasi dan ambang, dengan validation expression `isnum()` pada ambang.
- C. Calculated field yang menghitung jumlah kegagalan per `src`.

<details><summary>Jawaban</summary>

B. Kriteria yang bisa dinilai per event menjadi event type, karena labelnya ikut menentukan tag dan keanggotaan data model; agregasi dan ambang menjadi macro, karena macro adalah substitusi teks yang boleh memuat pipe dan `stats`, dan validasi mencegah argumen yang salah menghasilkan kolom kosong tanpa error. A keliru karena search event type tidak boleh memuat pipe, dan juga tidak boleh merujuk tag karena tag dievaluasi setelah event type. C keliru karena calculated field dihitung per event dari field yang sudah ada, tidak bisa mengagregasi banyak event. Lihat bagian 1.7 dan 1.8, atau Day 18 bagian 2.5.

</details>

**3. Pertanyaan jebakan.** Supaya dashboard lama tetap jalan, rekanmu membuat `EVAL-src = coalesce(src, c_ip, x_client_ip)` untuk sourcetype proxy, lalu field alias `src AS client_addr`. Field `client_addr` kosong untuk semua event. Kenapa, dan apa perbaikannya?

<details><summary>Jawaban</summary>

Field alias berada di tahap lima dan calculated field di tahap enam urutan operasi search-time, sehingga alias tidak bisa menunjuk field yang lahir dari calculated field; dokumentasi alias juga menyebut alias tidak bisa dibuat untuk calculated field, dan gejalanya field kosong, bukan penolakan saat menyimpan. Perbaikannya membuat field tujuan langsung dengan calculated field sendiri, `EVAL-client_addr = coalesce(src, c_ip, x_client_ip)`. Ekspresinya ditulis ulang, bukan merujuk `src`, karena semua `EVAL` di satu stanza dijalankan berbarengan dan tidak bisa dirantai. Lihat bagian 1.6 dan 1.11, atau Day 16 bagian 1.6.

</details>

**4. Skenario keputusan.** Sebuah search terjadwal tiap 15 menit harus memberi durasi setiap sesi VPN (log punya `session_id` unik per sesi) beserta nama pemilik aset dari lookup. Susunan mana yang dipilih?

- A. `transaction session_id` lalu `lookup ... OUTPUT owner`, karena `transaction` memberi `duration` langsung.
- B. `stats earliest(_time) AS start latest(_time) AS end range(_time) AS duration BY session_id src`, lalu `lookup ... OUTPUTNEW owner` setelahnya.
- C. `lookup ... OUTPUT owner` pada semua event lebih dulu, lalu `stats ... BY session_id owner`.

<details><summary>Jawaban</summary>

B. Dengan ID unik, `stats range(_time)` setara dengan `transaction` dan bisa dipra-agregasi di indexer, sedangkan `transaction` menahan transaksi terbuka di memori dan tidak cocok untuk search yang sering berjalan. `lookup` ditempatkan setelah `stats` supaya dijalankan sekali per baris hasil, dan `OUTPUTNEW` tidak menimpa field yang sudah ada. A mahal untuk jadwal 15 menit dan berisiko kehilangan transaksi yang ter-evict tanpa peringatan. C menjalankan lookup pada setiap event, dan `OUTPUT` bisa menimpa field event. Lihat bagian 1.2 dan 1.3, atau Day 13 bagian 1.3 dan Day 12 bagian 1.2.

</details>

**5. Jelaskan ulang.** Jelaskan kepada network engineer NOC PT JAB dalam tiga kalimat bedanya urutan command di pipeline SPL dan urutan operasi search-time, dan kenapa keduanya penting.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Urutan command adalah urutan yang kamu tulis setelah pipe, dan ia menentukan di mesin mana kerja dilakukan: command ringan seperti `eval` dan `fields` berjalan paralel di indexer, tetapi begitu ada `sort` atau `eventstats`, semua data pindah ke search head dan tidak kembali, jadi filter ditaruh di awal dan command berat di akhir. Urutan operasi search-time adalah urutan tetap yang dijalankan Splunk sendiri saat membaca event, sebelum command pertama kamu: extraction, lalu alias, lalu calculated field, lalu lookup, lalu event type dan tag. Urutan pertama menentukan seberapa mahal search-mu, sedangkan urutan kedua menentukan field mana yang boleh dipakai objek mana, dan pelanggarannya tidak memunculkan error, hanya field yang kosong."

Kesalahan yang sering muncul:
- Menyamakan keduanya, seolah urutan search-time bisa diubah dengan menukar baris di search.
- Menyebut urutan command hanya soal kerapian, padahal ia menentukan paralelisme.
- Lupa bahwa pelanggaran urutan search-time gagal tanpa error, bagian yang paling penting untuk diingat.

</details>

**6. Skenario keputusan.** SOC lead ingin satu klik dari field `src` di hasil detection ke layanan reputasi publik, dan satu klik untuk riwayat 24 jam IP itu di Splunk. Rancangan mana yang kamu pakai?

- A. Satu GET workflow action dengan daftar field `*` dan Label statis "Cek reputasi", supaya fleksibel untuk semua field.
- B. GET dibatasi ke field `src`, dengan event type perimeter sebagai pembatas kedua dan Label yang memuat `$src$`; Search workflow action terpisah dengan Earliest `-24h` dan penanda ditulis `src="$src$"`.
- C. POST ke layanan reputasi dengan Post arguments `description` berisi `$_raw$`, supaya layanan mendapat konteks lengkap.

<details><summary>Jawaban</summary>

B. Daftar field yang eksplisit dan event type adalah kontrol yang mencegah nilai internal, misalnya akun atau ID pelanggan, terkirim ke pihak ketiga, dan Label yang memuat nilai membuat analyst melihat apa yang akan keluar sebelum mengklik. Search workflow action butuh Earliest karena kolom waktu kosong berarti all time, dan penanda perlu dikutip karena nilai yang disisipkan ke search string tidak di-escape. A membuat menu muncul di semua field, sehingga satu klik keliru menjadi pengiriman data ke luar. C mengirim seluruh event ke layanan publik; di ISP, satu baris log bisa mengidentifikasi pelanggan, dan URL atau form encoding bukan perlindungan kerahasiaan. Lihat bagian 1.9, atau Day 19 bagian 1.6 dan 2.3.

</details>

**7. Interview question (English).** "Walk me through how you turn a useful ad hoc Splunk search into something the whole SOC can rely on."

<details><summary>Sample answer</summary>

"I start by checking the search itself before I share anything: explicit index and sourcetype, the narrowest time range, fields early, stats instead of transaction or join where the question allows it, lookups after the aggregation, and I compare duration, scan count and result count in Job Inspector to make sure any speed-up didn't change the answer. I also test the logic with makeresults, including negative cases, because a regex that only ever saw one clean example is how detections quietly miss things. Then I move each repeated piece into the right knowledge object. A regex that keeps getting copied becomes a field extraction; different vendor names become field aliases or a calculated field with coalesce, keeping value vocabularies per domain; the 'what kind of event is this' criteria become an event type with the CIM tag so data models pick it up; and the reusable logic with thresholds becomes a macro with validation, plus an empty filter macro at the end for exceptions. The part people skip is verification from someone else's seat. New objects are private, and a private field doesn't error for anyone else, it just returns zero results, so I share every object at the right scope, hand ownership to a team service account so nothing goes orphaned when people leave, and then run the detection as its owner, expand it with Control-Shift-E, and compare tag coverage against a raw count. Only then do I add workflow actions for the pivots, scoped to specific fields, with a time range, and nothing raw going to third parties."

What makes this answer strong: it separates search quality from object design, names the right object for each kind of reuse with a reason, and treats silent failure as the main risk, closing with concrete checks run from another account rather than an assumption that what works for the author works for the team.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | SPL Search Reference: rex (10.2) | https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.2/search-commands/rex | primer | diakses 2026-10-07 | Tinggi. Dari Day 11 |
| S2 | SPL Search Reference: eval (10.2) | https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.2/search-commands/eval | primer | diakses 2026-10-07 | Tinggi. Aturan kutip, urutan kiri ke kanan, null. Dari Day 11 |
| S3 | SPL Search Reference: foreach (10.2) | https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.2/search-commands/foreach | primer | diakses 2026-10-07 | Tinggi. Mode, token, kutip tunggal. Dari Day 12 |
| S4 | SPL Search Reference: lookup (10.2) | https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.2/search-commands/lookup | primer | diakses 2026-10-07 | Tinggi. OUTPUT/OUTPUTNEW, penempatan. Dari Day 12 |
| S5 | SPL Search Reference: makeresults (10.2) | https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.2/search-commands/makeresults | primer | diakses 2026-10-07 | Tinggi. format/data, batas 29.999, splunk_server. Dari Day 12 |
| S6 | SPL Search Reference: transaction (Splunk Enterprise 10.2) | https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.2/search-commands/transaction | primer | diakses 2026-10-07 | Tinggi. Opsi, default, field, urutan waktu. Dari Day 13 |
| S7 | Search Manual: About transactions (10.6) | https://help.splunk.com/en/splunk-enterprise/search/search-manual/10.6/group-and-correlate-events/about-transactions | primer | diakses 2026-10-07 | Tinggi. Panduan transaction vs stats. Dari Day 13 |
| S8 | SPL Search Reference: Event order functions (10.0) | https://help-preview.splunk.com/en/splunk-enterprise/spl-search-reference/10.0/statistical-and-charting-functions/event-order-functions | primer | diakses 2026-10-07 | Tinggi. first/last vs earliest/latest (domain help-preview). Dari Day 13 |
| S9 | Search Manual: Write better searches (9.4) | https://help.splunk.com/en/splunk-enterprise/search/search-manual/9.4/optimizing-searches/write-better-searches | primer | diakses 2026-10-07 | Tinggi. Dari Day 14 |
| S10 | Search Manual: Types of commands (10.2) | https://help.splunk.com/en/splunk-enterprise/search/search-manual/10.2/search-overview/types-of-commands | primer | diakses 2026-10-07 | Tinggi. Dari Day 14 |
| S11 | Search Manual: Difference between != and NOT (10.2 / Cloud 10.5.2605) | https://help.splunk.com/en/splunk-enterprise/search/search-manual/10.2/expressions-and-predicates/difference-between-and-not | primer | tanggal tidak tercatat | Tinggi untuk semantik. Dari Day 14 |
| S12 | Splunk Enterprise 10.6 Knowledge Manager Manual: Build field extractions with the field extractor | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/use-the-field-extractor-in-splunk-web | primer | diakses 2026-10-14 | Tinggi. Langkah wizard, dua metode, pintu masuk. Dari Day 15 |
| S13 | Splunk Enterprise 10.6 Knowledge Manager Manual: Use the Field extractions page | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/use-the-settings-pages-for-field-extractions-in-splunk-web | primer | diakses 2026-10-14 | Tinggi. Kolom Name, Type, Extraction/Transform. Dari Day 15 |
| S14 | Splunk Enterprise 10.6 Knowledge Manager Manual: Manage knowledge object permissions | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/get-started-with-knowledge-objects/manage-knowledge-object-permissions | primer | diakses 2026-10-14 | Tinggi. Objek baru private, Display for, Read dan Write. Dari Day 15 dan 16 |
| S15 | Splunk Enterprise 10.6 Knowledge Manager Manual: Manage orphaned knowledge objects | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/get-started-with-knowledge-objects/manage-orphaned-knowledge-objects | primer | diakses 2026-10-14 | Tinggi. Sebab dan akibat objek yatim, Reassign Knowledge Objects. Dari Day 15 |
| S16 | Splunk Enterprise 10.6 Knowledge Manager Manual: Create field aliases in Splunk Web | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/field-aliases | primer | diakses 2026-10-14 | Tinggi. Aturan dan batas alias. Dari Day 16 |
| S17 | Splunk Cloud Platform 10.6: Field alias behavior change | https://help.splunk.com/en/splunk-cloud-platform/release-notes/10.6/splunk-cloud-platform-release-notes/splunk-cloud-platform-field-alias-behavior-change | primer | diakses 2026-10-14 | Tinggi untuk perilaku timpa, `ASNEW`, urutan leksikografis. Dokumentasi Splunk Cloud Platform. Dari Day 16 |
| S18 | Splunk Enterprise 10.6 Knowledge Manager Manual: About calculated fields | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/calculated-fields | primer | diakses 2026-10-14 | Tinggi. `EVAL-`, tidak bisa dirantai, contoh `x * 2`, menimpa extraction. Dari Day 16 |
| S19 | Splunk Enterprise 10.6 Knowledge Manager Manual: The sequence of search-time operations | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/get-started-with-knowledge-objects/the-sequence-of-search-time-operations | primer | diakses 2026-10-14 | Tinggi. Urutan sembilan operasi, konfigurasi di tier search head. Dari Day 15 dan 16 |
| S20 | Splunk CIM 6.4: Authentication data model | https://help.splunk.com/en/data-management/common-information-model/6.4/data-models/authentication | primer | diakses 2026-10-14 | Tinggi. Nilai `action`, tag constraint per dataset. Dari Day 16 dan 17 |
| S21 | Splunk CIM 6.4: Network Traffic data model | https://help.splunk.com/en/data-management/common-information-model/6.4/data-models/network-traffic | primer | diakses 2026-10-14 | Tinggi. Nilai `action` All_Traffic. Dari Day 16 |
| S22 | Splunk Enterprise 10.6 Knowledge Manager Manual: About event types | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/event-types/about-event-types | primer | diakses 2026-10-14 | Tinggi. Larangan pipe, subsearch, tag; `eventtype` multivalue; ongkos search. Dari Day 17 |
| S23 | Splunk Enterprise 10.6 Knowledge Manager Manual: Define search macros in Settings | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/search-macros/define-search-macros-in-settings | primer | diakses 2026-10-14 | Tinggi. Form, nama berargumen, dua jalur validasi. Dari Day 18 |
| S24 | Splunk Enterprise 10.6 Admin Manual: macros.conf | https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.6/configuration-file-reference/10.6.0-configuration-file-reference/macros.conf | primer | diakses 2026-10-14 | Tinggi. Overloading, `validate()`, `iseval`, deteksi siklus. Dari Day 18 |
| S25 | Splunk Enterprise 10.6 Knowledge Manager Manual: Use search macros in searches | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/search-macros/use-search-macros-in-searches | primer | diakses 2026-10-14 | Tinggi. Bersarang, kutip, tanda hubung, generating command, ekspansi. Dari Day 18 |
| S26 | Splunk Threat Research: WinEvent Scheduled Task Created to Spawn Shell | https://research.splunk.com/endpoint/203ef0ea-9bd8-11eb-8201-acde48001122/ | primer | diakses 2026-10-14 | Tinggi. Macro `wineventlog_security` dan macro filter `search *`. Dari Day 18 |
| S27 | Splunk Enterprise 10.6 Knowledge Manager Manual: About workflow actions in Splunk Web | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/workflow-actions | primer | diakses 2026-10-14 | Tinggi. Tiga jenis, letak menu, pembatas field dan event type. Dari Day 19 |
| S28 | Splunk Enterprise 10.6 Knowledge Manager Manual: Set up a GET workflow action | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/workflow-actions/set-up-a-get-workflow-action | primer | diakses 2026-10-14 | Tinggi. URL encoding, prefix `$!`. Dari Day 19 |
| S29 | Splunk Enterprise 10.6 Knowledge Manager Manual: Set up a search workflow action | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/workflow-actions/set-up-a-search-workflow-action | primer | diakses 2026-10-14 | Tinggi. All time bila kedua kolom waktu kosong. Dari Day 19 |
| S30 | Splunk Enterprise 10.6 Admin Manual: workflow_actions.conf (spesifikasi 10.6.0.5) | https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.6/configuration-file-reference/10.6.0-configuration-file-reference/workflow_actions.conf | primer | diakses 2026-10-14 | Tinggi. `search.preserve_timerange`, nilai search string tidak di-escape. Dari Day 19 |
| S31 | Splunk Enterprise Security 8.7 User Guide: Triage findings and finding groups | https://help.splunk.com/en/splunk-enterprise-security-8/user-guide/8.7/mission-control/triage-findings-and-finding-groups-in-splunk-enterprise-security | primer | diakses 2026-10-14 | Tinggi untuk drill-down search; tidak menyebut workflow action. Dari Day 19 |
| S32 | GitHub splunk/botsv1: BOTS v1 dataset | https://github.com/splunk/botsv1 | primer | 2016 (dataset); diakses 2026-10-07 | Tinggi. Index, sourcetype, add-on, lisensi CC0 |
| S33 | CyberDefenders: Boss Of The SOC v1 (lab) | https://cyberdefenders.org/labs/15 | sekunder/komunitas | tanggal tidak tercatat | Sedang. Hanya untuk deskripsi skenario; isi lab tidak dipakai agar tidak membocorkan jawaban |
| S34 | samsclass.info: Boss of the SOC v1: Threat Hunting with Splunk | https://samsclass.info/50/proj/botsv1 | komunitas (materi kelas) | tanggal tidak tercatat | Rendah-sedang. Hanya untuk deskripsi skenario |

**Catatan sumber:** Day ini merangkum Day 11-19; klaim rinci, sumber komunitas, dan catatan kelemahannya ada di bagian Sumber Day asal, dan sumber di tabel ini hanya yang dipakai untuk klaim di ringkasan. Deskripsi dua skenario BOTS v1 berasal dari sumber komunitas [S33][S34], dan nama field per sourcetype BOTS v1 pada Splunk 10.x dan add-on terbaru belum terkonfirmasi, jadi cek dengan data di instance-mu. Tabel jejak di bagian 1.10 memakai artefak fiktif PT JAB dari Day 15-19, dan angkanya mengikuti keluaran ilustrasi Day asal. Latihan skenario di bagian 2-4 fiktif dan merangkum isi Day 11-19.
