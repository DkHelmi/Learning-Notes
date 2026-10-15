---
day: 16
title: 'Field alias, calculated field, dan urutan operasi search-time: satu nama field untuk banyak vendor'
researched_on: 2026-10-14
versions_checked: 'Splunk Enterprise 10.6 (Knowledge Manager Manual: Create field aliases in Splunk Web, Configure field aliases with props.conf, About calculated fields, The sequence of search-time operations, Manage knowledge object permissions; Search Reference: Evaluation functions); Splunk Cloud Platform 10.6 (catatan perubahan perilaku field alias, berlaku sejak 7.2.4); CIM 6.4; ES 8.7.0'
---

# Day 16: Field alias, calculated field, dan urutan operasi search-time

Cakupan: menyatukan nama dan nilai field dari beberapa vendor menjadi satu nama lewat field alias dan calculated field di Settings > Fields, beserta urutan operasi search-time yang menentukan apa yang boleh merujuk apa.

## Ide inti

Satu detection yang ditulis sekali dan bekerja untuk firewall, proxy, dan VPN dari vendor berbeda bukan hasil dari search yang pintar, melainkan hasil dari pekerjaan yang sudah dilakukan sebelum search itu ditulis: nama field dari semua sumber sudah disamakan, dan nilai field dari semua sumber sudah memakai kosakata yang sama. Dua knowledge object yang mengerjakannya adalah field alias, yang memberi nama kedua pada field yang sudah ada, dan calculated field, yang membuat field baru dari ekspresi `eval` yang dihitung setiap kali search jalan. Keduanya dibuat di Settings > Fields, keduanya tidak mengubah data mentah, dan keduanya berlaku untuk semua orang yang punya izin, bukan hanya untuk search yang menuliskannya.

Yang membuat topik ini sering gagal bukan sintaksnya, tetapi urutannya. Splunk menjalankan operasi search-time dalam urutan tetap, dan setiap tahap hanya bisa memakai field yang dihasilkan tahap sebelumnya, tidak field yang dihasilkan tahap sesudahnya [S4]. Dari aturan satu baris itu lahir semua jebakan di Day ini: field alias tidak bisa menunjuk hasil calculated field, calculated field tidak bisa menunjuk hasil lookup, dan calculated field tidak bisa menunjuk hasil calculated field lain karena semua `EVAL` di satu stanza dijalankan berbarengan, bukan berurutan [S3][S4]. Gagalnya selalu sama: field-nya kosong, searchnya tidak error, dan orang menyangka datanya yang salah.

Dua analogi yang dipakai di Day ini sudah kamu kenal. Field alias adalah mapping nama field antar vendor ke satu nama, seperti memetakan `srcip`, `src_ip`, dan `SourceAddress` menjadi satu kolom `src` di laporan gabungan. Batasnya: alias tidak menghapus nama aslinya, dan dua alias yang menuju satu nama bisa saling menimpa dengan pemenang yang ditentukan urutan nama kelasnya, bukan niatmu [S1][S5]. Calculated field adalah kolom turunan di spreadsheet yang dihitung ulang setiap kali tabelnya dibuka. Batasnya: ia benar-benar dihitung setiap kali search jalan, jadi ekspresi berat memperlambat semua search pada sourcetype itu, dan kolom formula tidak bisa mengambil nilai dari kolom formula lain di tabel yang sama.

```
URUTAN OPERASI SEARCH-TIME (setiap tahap hanya bisa memakai hasil tahap di atasnya)

  0  operasi index-time (default field, indexed field)      di luar daftar ini
  1  field filter            field_filters.conf
  2  inline extraction       EXTRACT-<class>      (props.conf)
  3  extraction + transform  REPORT-<class>       (props.conf + transforms.conf)
  4  key-value otomatis      KV_MODE              (default auto)
  5  FIELD ALIAS             FIELDALIAS-<class>   <- bisa pakai hasil 1-4
  6  CALCULATED FIELD        EVAL-<fieldname>     <- bisa pakai hasil 1-5, semua EVAL berbarengan
  7  lookup otomatis         LOOKUP-<class>       <- bisa pakai hasil 1-6
  8  event type              eventtypes.conf
  9  tag                     tags.conf

  AKIBATNYA
    alias  tidak bisa menunjuk calculated field, lookup, event type, tag
    EVAL   tidak bisa menunjuk lookup, event type, tag, atau EVAL lain
    lookup BISA menunjuk alias dan calculated field
```

Situasi yang dipakai sepanjang Day ini adalah lanjutan pekerjaan Day 15 di PT Jaringan Anak Bangsa (PT JAB, ISP menengah fiktif, SOC internal satu lantai dengan NOC). Field extraction untuk VPN vendor `jab:vpnlegacy` dan firewall POP Bandung `jab:fw:pop` sudah jadi, dibagikan ke semua app, dan dimiliki akun fungsional `svc_soc`. Sumber ketiga, proxy POP `jab:proxy:pop`, sudah lebih lama masuk tetapi punya masalahnya sendiri: firmware perangkat naik versi pertengahan tahun dan nama field alamat klien berganti, sehingga event lama memakai `c_ip` dan event baru memakai `x_client_ip`. Tiket SOC-2026-0235 ditutup dengan kesimpulan akun vendor `vendor.bnet01` dipakai dari `203.0.113.45`, mendapat alamat tunnel `10.10.250.37`, lalu alamat itu mencoba menjangkau file server dan ditolak di perimeter POP. Detection engineer menulis di grup:

> "Searchku untuk tiket tadi panjangnya enam baris cuma karena tiga sumber memakai tiga nama untuk alamat yang sama, dan satu sumber memakai dua nama untuk dirinya sendiri. Aku mau satu detection yang bunyinya `action=blocked` dan `src=...`, bukan tiga blok OR per vendor. Buat lewat Settings > Fields supaya berlaku untuk semua orang. Satu lagi: percobaanku semalam gagal, aku bikin calculated field `src` dari dua nama field proxy itu, lalu calculated field kedua yang membaca `src` untuk menentukan zona, dan yang kedua selalu kosong. Aku tidak mengerti kenapa."

Permintaan itu memuat enam pertanyaan:

1. Kapan cukup memakai field alias dan kapan harus calculated field?
2. Apa yang terjadi bila dua field dialias ke nama yang sama, dan apa arti pilihan `Overwrite field values`?
3. Bagaimana menyamakan nilai field, bukan hanya namanya, dan kosakata nilai mana yang dipakai?
4. Apa urutan operasi search-time yang persis, dan apa yang boleh merujuk apa?
5. Kenapa calculated field yang membaca calculated field lain selalu kosong?
6. Bagaimana membuktikan bahwa satu detection benar-benar menangkap ketiga sumber?

Pertanyaan 1 dijawab di bagian 1.2 dan 1.7, pertanyaan 2 di bagian 1.3, pertanyaan 3 di bagian 1.4, pertanyaan 4 di bagian 1.5, pertanyaan 5 di bagian 1.6, dan pertanyaan 6 di bagian 2.6 dan 2.7.

**Kapan relevan:** setiap kali dua sumber atau lebih harus dijawab oleh satu search, setiap kali kamu melihat blok `OR` per vendor di dalam detection, dan setiap kali nilai field yang artinya sama ditulis berbeda oleh vendor (`deny`, `TCP_DENIED`, `FAIL`).
**Kapan bukan jawaban:** untuk normalisasi sekali pakai di satu search, `eval` di search bar lebih cepat dan tidak mengubah apa pun untuk orang lain (Day 11). Untuk sumber yang add-on resminya ada dan sudah memetakan field ke nama standar, verifikasi add-on itu dan jangan menumpuk alias sendiri di atasnya (Day 05 bagian 1.1). Untuk memberi label kategori pada event, yang kamu butuhkan event type dan tag, bukan alias (Day 17). Dan untuk memetakan kode menjadi teks dari tabel referensi, yang dipakai lookup, bukan calculated field dengan `case` sepanjang lima puluh baris (Day 12).

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dasar dari Day 01 sampai Day 15 (index, sourcetype, `_raw`, field extraction search-time, `EXTRACT-`, `REPORT-`, knowledge object, permission private, app, dan global) tidak diulang di sini. Tabel ini hanya memuat istilah yang dipakai Day ini; kolom padanan memakai hal yang sudah kamu kerjakan di NOC dan SOC.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Field alias | Nama kedua untuk field yang sudah ada, tanpa menghapus nama aslinya | Mapping nama field antar vendor ke satu nama di laporan gabungan |
| `FIELDALIAS-<class>` | Setting `props.conf` yang mendefinisikan alias | Baris mapping di berkas konfigurasi parser |
| `AS` dan `ASNEW` | Dua cara menulis alias: `AS` menimpa field tujuan bila sumbernya ada, `ASNEW` melewatinya bila field tujuan sudah terisi | Mode penulisan: timpa atau jangan timpa |
| `Overwrite field values` | Pilihan di form alias Splunk Web yang menentukan perilaku timpa | Centang "ganti nilai yang sudah ada" di alat impor |
| Calculated field | Field yang dihitung dari ekspresi `eval` setiap kali search jalan | Kolom formula di spreadsheet |
| `EVAL-<fieldname>` | Setting `props.conf` yang mendefinisikan calculated field | Rumus kolom yang disimpan di template laporan |
| Urutan operasi search-time | Urutan tetap tahap-tahap yang dijalankan Splunk saat membaca event | Urutan tahap di pipeline parsing kolektor |
| Field filter | Penyaring atau penyamar nilai field berbasis role yang berjalan paling awal | Masking kolom sebelum laporan dibagikan |
| `KV_MODE` | Pengaturan ekstraksi `key=value` otomatis, defaultnya `auto` | Parser bawaan untuk log berformat `key=value` |
| Automatic lookup (`LOOKUP-<class>`) | Lookup yang dijalankan otomatis tanpa command `lookup` di search | Join otomatis ke tabel referensi |
| Event type | Kriteria search tersimpan yang memberi label kategori pada event | Saved filter di konsol |
| Tag | Label pada pasangan field-value atau pada event type | Tag di sistem tiket |
| `class` sebuah setting | Label unik di belakang `FIELDALIAS-` atau `REPORT-`, dipakai juga untuk menentukan urutan antar alias | Nama aturan di konfigurasi perangkat |
| Nilai baku (prescribed values) CIM | Daftar nilai yang diharapkan sebuah data model untuk satu field | Daftar kode status baku di laporan NOC |
| `coalesce()` | Fungsi eval yang mengembalikan nilai pertama yang tidak NULL [S7] | Ambil kolom pertama yang terisi |
| Field multivalue | Field yang memuat lebih dari satu nilai dalam satu event | Satu baris log dengan dua alamat tujuan |

### 1.1 Satu nama field, satu detection

Keluhan detection engineer soal search enam baris adalah gejala, dan penyebabnya bisa dihitung. Tiga sumber di PT JAB memakai empat nama berbeda untuk satu hal yang sama, yaitu alamat yang memulai koneksi: `fw_srcaddr` di firewall POP, `c_ip` dan `x_client_ip` di proxy POP, dan `jab_src` di VPN vendor. Untuk nilai keputusan, tiga sumber memakai lima kata berbeda: `deny` dan `accept` di firewall, `TCP_DENIED` dan `TCP_HIT` di proxy, `FAIL` dan `OK` di VPN.

Nama tujuannya bukan karangan sendiri. CIM menetapkan nama field standar per domain, dan dokumentasi CIM 6.4 secara eksplisit menyebut bahwa `src` boleh dialias dari field yang lebih spesifik seperti `src_host`, `src_ip`, atau `src_name`, dan `dest` dari `dest_host`, `dest_ip`, atau `dest_name` [S9]. Jadi alias bukan akal-akalan; ia memang mekanisme yang dirancang untuk pekerjaan ini.

Yang perlu kamu putuskan lebih dulu adalah domain tiap sumber, karena kosakata nilainya berbeda per domain:

| Sumber PT JAB | Domain CIM yang cocok | Nilai baku `action` |
|---|---|---|
| `jab:fw:pop` (traffic log firewall) | Network Traffic (`All_Traffic`) | `allowed`, `blocked`, `teardown` [S9] |
| `jab:proxy:pop` (access log proxy) | Web, dan trafiknya juga relevan ke Network Traffic | `blocked` dan `allowed` mengikuti kosakata trafik [S9] |
| `jab:vpnlegacy` (autentikasi VPN) | Authentication | `success`, `failure`, `pending`, `error` [S8] |

Perbedaan baris ketiga itu penting dan sering dilanggar. Menormalkan login VPN gagal menjadi `action="blocked"` terasa rapi karena semua sumber lalu memakai satu kata, tetapi itu memasukkan event autentikasi ke kosakata trafik, sehingga detection yang menghitung koneksi ditolak ikut menghitung login gagal, dan data model Authentication yang menyaring `action="failure"` tidak menemukan apa pun [S8]. Satu nama field boleh lintas domain; satu kosakata nilai tidak.

Tag dataset yang membuat event benar-benar masuk data model (`authentication` untuk Authentication, `network` dan `communicate` untuk All_Traffic) adalah pekerjaan event type dan tag, dan itu Day 17. Day ini berhenti di nama dan nilai field, yang merupakan prasyaratnya.

**Tanpa ES:** field alias dan calculated field adalah fitur Splunk Enterprise, bukan ES, dan dipakai sepenuhnya tanpa ES maupun tanpa CIM add-on terpasang. Yang kamu dapat dari memakai nama CIM sejak sekarang adalah pekerjaan yang tidak perlu diulang nanti: ketika ES atau CIM add-on dipasang, sumber yang namanya sudah benar cukup diberi tag untuk masuk data model, sedangkan sumber yang memakai nama sendiri harus dinormalisasi dari awal. Di PT JAB, ES ada di search head terpisah, jadi alias dan calculated field ini juga harus punya cakupan yang mencakup app yang dipakai di sana (Day 15 bagian 1.6).

### 1.2 Field alias: aturan dan batasnya

Alias adalah alat yang paling murah di Day ini: ia tidak menghitung apa pun, hanya memberi nama kedua. Karena murah, ia pilihan pertama, dan calculated field dipakai hanya bila alias tidak bisa.

Aturan dan batas yang perlu dipegang [S1][S2]:

- Satu field boleh punya beberapa alias, tetapi satu alias hanya boleh menunjuk satu field. Contoh di dokumentasi: `vendor_action` boleh dialias menjadi `action` atau menjadi `message_type`, tidak keduanya sekaligus.
- Alias tidak menghapus atau mengganti nama field aslinya. `fw_srcaddr` tetap ada setelah dialias menjadi `src`, dan dua-duanya bisa dipakai di search.
- Jangan memberi alias nama yang sama dengan internal field seperti `_time`; dokumentasi menyebut hasilnya tidak bisa diduga.
- Alias boleh dibuat untuk field yang diekstrak di index-time maupun search-time. Alias tidak bisa dibuat untuk calculated field, event type, tag, atau field yang ditambahkan lookup.
- Alias dijalankan setelah ekstraksi `key=value` dan sebelum calculated field, lookup, event type, dan tag, sehingga konfigurasi lookup boleh menunjuk alias.
- Splunk Enterprise hanya mendukung alias untuk field single value [S2]. Untuk field yang berpotensi multivalue, periksa dulu dengan `mvcount()` sebelum mengandalkan alias.
- Perubahan `props.conf` membutuhkan restart Splunk Enterprise [S2]. Yang dibuat lewat Splunk Web tidak, tetapi pembuatan lewat UI dan lewat file menghasilkan stanza yang sama.

Langkah membuatnya di Splunk Web [S1]:

1. Temukan field di searchmu yang ingin diberi alias.
2. Buka Settings > Fields > Field aliases.
3. Pilih app yang akan memakai alias itu.
4. Beri nama objek aliasnya. Karakter yang diizinkan a sampai z, A sampai Z, 0 sampai 9, dan garis bawah.
5. Pilih sasarannya: host, source, atau sourcetype.
6. Isi field yang sudah ada di kolom kiri dan nama aliasnya di kolom kanan.
7. Pilih `Overwrite field values` bila perlu; secara default tidak dipilih.
8. Simpan. Alias baru muncul di halaman Field Aliases.

Satu hal yang tidak tertulis di langkah mana pun tetapi menentukan apakah pekerjaanmu berguna: objek alias yang baru dibuat private, sama seperti knowledge object lainnya [S6]. Alias yang private berarti hanya kamu yang melihat field `src` pada sourcetype itu, dan detection milik akun lain tetap melihat dunia dengan nama lama. Gejalanya nol baris tanpa error, persis seperti pada field extraction di Day 15 bagian 1.6.

### 1.3 Dua sumber ke satu nama: `Overwrite field values`, `AS`, dan `ASNEW`

Pertanyaan kedua detection engineer muncul karena proxy POP punya dua nama untuk alamat klien. Naluri pertama orang adalah membuat dua alias ke `src`, dan itu justru kasus yang dokumentasinya melarang.

Mulai dari pilihan `Overwrite field values` di form, karena itu yang paling sering salah dipahami. Perilakunya [S1]:

| Keadaan event | `Overwrite field values` tidak dipilih | `Overwrite field values` dipilih |
|---|---|---|
| Field asal dan field alias dua-duanya ada | Nilai field alias dibiarkan apa adanya | Nilai field alias diganti dengan nilai field asal |
| Hanya field alias yang ada | Nilai field alias tetap | Field alias dihapus dari event |
| Hanya field asal yang ada | Alias terisi dari field asal | Alias terisi dari field asal |

Di tingkat konfigurasi, dua perilaku itu adalah dua kata kunci. `AS` menimpa dan menghapus sesuai baris tabel di atas, sedangkan `ASNEW` melewati field yang sudah terisi tanpa menimpa maupun menghapusnya; kata kunci `ASNEW` diperkenalkan di versi 7.2.4 bersama perubahan perilaku alias yang menghapus field alias dari event ketika field asalnya tidak ada [S5]. Artinya, bila di lingkunganmu ada event yang sudah memiliki field bernama `src` dari jalur lain, alias bergaya `AS` akan menghapus nilai itu pada event yang tidak punya field asal. Itu bukan bug, itu perilaku yang dipilih.

Lalu bagian yang paling perlu diingat. Bila beberapa stanza atau beberapa `FIELDALIAS` class menyasar nama alias yang sama, search head menerapkannya dalam urutan leksikografis nama class dan yang terakhir diterapkan yang menang [S5]. Contoh dokumentasi: `class1` berisi `uid AS user` diterapkan sebelum `class2` berisi `id AS user`, sehingga `user` akhirnya bernilai `id` [S5]. Konsekuensi praktisnya keras: pemenang ditentukan nama objek yang kamu karang, bukan oleh prioritas yang kamu maksudkan, dan nama objek itu sering dibuat tergesa-gesa. Dua alias ke satu nama bukan cara menangani dua kemungkinan sumber; ia cara menghasilkan nilai yang berubah bila ada orang lain menambah alias dengan nama class yang lebih besar.

Jalan yang benar untuk satu nama dari beberapa sumber disebut langsung di dokumentasi alias: pakai calculated field [S1][S5]. Ada dua bentuknya, dan pilihan di antara keduanya adalah keputusan analitik, bukan selera:

- `coalesce(c_ip, x_client_ip)` menghasilkan satu nilai, yaitu nilai pertama yang tidak NULL [S7]. Urutan argumen menentukan siapa yang menang bila dua-duanya terisi.
- `mvdedup(mvappend(c_ip, x_client_ip))` menyimpan semua nilai tanpa duplikat sebagai field multivalue [S5]. Ini dipakai bila kehilangan salah satu nilai berarti kehilangan bukti, misalnya alamat sebelum dan sesudah NAT. Harganya: field itu menjadi multivalue, sehingga `stats count BY src` bisa menghitung satu event di dua baris.

Untuk proxy POP PT JAB, dua nama itu adalah generasi firmware yang berbeda dan tidak pernah muncul bersamaan dalam satu event, jadi `coalesce` yang dipakai. Pastikan dulu asumsi "tidak pernah bersamaan" itu benar dengan satu search, dan caranya ada di bagian 2.1.

### 1.4 Calculated field: ekspresi yang dihitung setiap search

Calculated field adalah field search-time yang menghitung nilainya dari field yang sudah ada di event, dan gunanya sebagai jalan pintas untuk ekspresi `eval` yang berulang atau rumit [S3]. Di `props.conf` bentuknya `EVAL-<fieldname> = <ekspresi eval>`, dan nama di belakang `EVAL-` itulah nama field yang dihasilkan.

Enam aturan yang menentukan apakah calculated field-mu bekerja seperti yang kamu harapkan [S3]:

1. Calculated field dijalankan setelah field alias dan sebelum lookup. Jadi ekspresinya boleh memakai field hasil extraction dan hasil alias, tetapi tidak boleh memakai field yang ditambahkan lookup, event type, atau tag. Ekspresi yang memakai field dari lookup menghasilkan error.
2. Tidak ada rantai. Semua setting `EVAL` di satu stanza dijalankan berbarengan, bukan berurutan, sehingga satu calculated field tidak bisa memakai hasil calculated field lain.
3. Contoh dari dokumentasi yang paling jelas menerangkan aturan kedua: dengan `EVAL-x = x * 2` dan `EVAL-y = x * 2` di satu stanza, kedua ekspresi memakai nilai `x` yang asli, sehingga untuk `x=4` hasilnya `x` menjadi 8 dan `y` juga 8 [S3]. Nilai `y` bukan 16.
4. Calculated field yang namanya sama dengan field hasil extraction akan menimpanya, bahkan ketika ekspresinya menghasilkan null. Membungkus ekspresi dengan `coalesce()` mencegah itu, dan urutan argumennya menentukan nilai mana yang menang.
5. Calculated field tidak bisa disasarkan ke host, source, atau sourcetype yang berupa alias. Bila perlu pembedaan seperti itu, pakai kondisi `if()` di dalam ekspresinya.
6. Calculated field bisa dibuat lewat Splunk Web maupun lewat `props.conf`, dan halaman dokumentasinya menguraikan cara `props.conf` sementara cara Splunk Web ada di halaman tersendiri [S3]. Di Splunk Web, pembuatannya ada di Settings > Fields > Calculated fields dengan bentuk form yang sama polanya seperti alias: app tujuan, nama, sasaran sourcetype, source, atau host, nama field hasil, dan ekspresi eval. Cocokkan label formnya dengan layar versi-mu.

Aturan keempat pantas diulang dengan contoh PT JAB, karena ia kemungkinan besar akan mengenai kamu suatu hari. Bila nanti add-on resmi untuk proxy dipasang dan add-on itu mengekstrak `src` sendiri, calculated field `EVAL-src = coalesce(c_ip, x_client_ip)` akan menimpa `src` dari add-on, termasuk pada event yang `c_ip` dan `x_client_ip`-nya kosong, sehingga `src` menjadi kosong padahal add-on sudah mengisinya. Bentuk yang aman: `EVAL-src = coalesce(src, c_ip, x_client_ip)`, yang membiarkan nilai dari extraction menang dan hanya mengisi bila field itu kosong [S3].

Biaya calculated field juga perlu disadari. Ia dihitung setiap kali search pada sourcetype itu dijalankan, oleh siapa pun, termasuk search terjadwal yang jalan tiap lima menit. Satu `case()` dengan lima cabang tidak terasa; `coalesce` atas sepuluh field ditambah `match()` regex di sourcetype bervolume tinggi seperti DNS resolver pelanggan terasa di semua search, bukan hanya di searchmu.

### 1.5 Urutan operasi search-time yang persis

Pertanyaan keempat detection engineer adalah inti Day ini, dan jawabannya satu tabel. Aturan tunggalnya: setiap operasi bisa memakai field yang dihasilkan operasi sebelumnya, dan konfigurasi yang sama tidak boleh memuat field yang dihasilkan operasi sesudahnya [S4]. Operasi index-time, yaitu ekstraksi default field dan indexed field, berjalan sebelum semua operasi di tabel ini dan bukan bagian dari daftar [S4].

| Urutan | Operasi | Letak konfigurasi | Boleh memakai hasil |
|---|---|---|---|
| 1 | Field filter | stanza `fieldFilterName` di `field_filters.conf` | Hanya field index-time [S4] |
| 2 | Inline field extraction | `EXTRACT-<class>` di `props.conf` | Hanya field index-time [S4] |
| 3 | Field extraction lewat transform | `REPORT-<class>` di `props.conf`, dengan stanza di `transforms.conf` | Hasil inline extraction [S4] |
| 4 | Ekstraksi key-value otomatis | `KV_MODE` di `props.conf` (default `auto`), `AUTO_KV_JSON` untuk JSON | Setelah extraction eksplisit [S4] |
| 5 | Field aliasing | `FIELDALIAS-<class>` di `props.conf` | Field index-time dan field hasil extraction search-time; bukan lookup dan bukan calculated field [S4] |
| 6 | Calculated field | `EVAL-<fieldname>` di `props.conf` | Semua jenis field extraction dan alias; bukan lookup, event type, atau tag [S3][S4] |
| 7 | Lookup | `LOOKUP-<class>` di `props.conf`, menunjuk stanza `transforms.conf` | Extraction, alias, dan calculated field; bukan event type dan tag [S4] |
| 8 | Event type | stanza di `eventtypes.conf` | Semua di atasnya; tidak bisa menunjuk tag [S4] |
| 9 | Tag | stanza di `tags.conf` | Pasangan field-value apa pun, tidak peduli bagaimana field itu ditambahkan [S4] |

Dua catatan dari halaman yang sama yang perlu dibawa ke pekerjaan nyata [S4]. Pertama, field filter berada di urutan pertama dan bisa mengubah nilai field, misalnya menggantinya dengan nilai yang disamarkan, sehingga ia bisa merusak operasi sesudahnya yang bergantung pada nilai asli, termasuk lookup dan event type; dokumentasi menyebut bahwa melakukan hashing pada nilai mempertahankan keunikannya sehingga statistik masih bisa dihitung. Secara default hanya role admin atau sc_admin yang bisa membuat, menyunting, dan menghapus field filter, dan pengecualian role diberikan lewat Splunk Web atau REST API, bukan lewat file konfigurasi [S4]. Sisi kebijakannya ada di Day 44. Kedua, konfigurasi berbasis file untuk semua operasi di tabel ini dibuat di tier search head [S4], yang berarti di PT JAB objek ini harus ada di search head yang menjalankan searchnya, termasuk search head ES.

Urutan ini juga menjelaskan satu hal yang terasa aneh pada awalnya: event type berada di urutan delapan, sehingga event type boleh memakai field hasil alias dan calculated field, tetapi tidak boleh memakai tag; sedangkan tag di urutan sembilan boleh menempel pada pasangan field-value apa pun, termasuk field hasil calculated field [S4]. Itu sebabnya alur normalisasi CIM yang dipakai di Day 23 berbentuk seperti itu: nama dan nilai field dibenahi lebih dulu, baru event type dan tag dipasang di atasnya.

### 1.6 Rantai yang tidak boleh, dan apa yang harus dilakukan

Kegagalan semalam yang ditanyakan detection engineer sekarang bisa dijelaskan tanpa menebak. Ia membuat dua calculated field di satu stanza:

```
[jab:proxy:pop]
EVAL-src = coalesce(c_ip, x_client_ip)
EVAL-src_zona = if(cidrmatch("10.30.0.0/16", src), "bandung", "luar")
```

Baris kedua selalu kosong karena semua `EVAL` di satu stanza dijalankan berbarengan, bukan berurutan, sehingga `src` yang dibaca baris kedua adalah `src` sebelum tahap calculated field, yang di sourcetype ini tidak ada [S3][S4]. Tidak ada error, tidak ada peringatan; hanya kolom kosong.

Perbaikannya menggabungkan logikanya menjadi satu ekspresi:

```
[jab:proxy:pop]
EVAL-src = coalesce(c_ip, x_client_ip)
EVAL-src_zona = if(cidrmatch("10.30.0.0/16", coalesce(c_ip, x_client_ip)), "bandung", "luar")
```

Yang menarik, stanza untuk firewall POP bisa melakukan hal yang tampaknya sama dan berhasil:

```
[jab:fw:pop]
FIELDALIAS-jab_fw_src = fw_srcaddr AS src
EVAL-src_zona = if(cidrmatch("10.20.0.0/16", src), "datacenter", "luar")
```

Di sini `src` lahir dari alias, yaitu tahap lima, sedangkan calculated field tahap enam, jadi membacanya sah [S4]. Perbedaan antara dua stanza di atas bukan soal gaya menulis; ia soal tahap mana yang menghasilkan field yang kamu baca. Pertanyaan yang harus kamu ajukan setiap kali menulis ekspresi di calculated field: field yang aku baca ini lahir dari tahap berapa?

Empat rantai yang paling sering dicoba dan hasilnya:

| Yang dicoba | Hasil | Sebabnya | Yang dilakukan |
|---|---|---|---|
| Alias menunjuk field hasil `EVAL-` | Alias kosong | Alias tahap 5, calculated field tahap 6 [S1][S4] | Buat field tujuannya langsung dengan `EVAL-<nama tujuan>` |
| Alias menunjuk field dari lookup | Alias kosong | Lookup tahap 7 [S1][S4] | Pakai `OUTPUTNEW` dengan nama yang kamu mau di lookup itu |
| `EVAL-` menunjuk field dari lookup | Error pada ekspresi [S4] | Lookup tahap 7 | Pindahkan logikanya ke search, atau hitung di lookup-nya |
| `EVAL-` menunjuk hasil `EVAL-` lain | Field kosong | Semua `EVAL` satu stanza berbarengan [S3] | Gabungkan menjadi satu ekspresi |

### 1.7 Memilih alat: alias, calculated field, atau lookup

Pertanyaan pertama detection engineer dijawab dengan satu urutan keputusan. Pilih alat yang paling murah yang masih menjawab kebutuhan, karena setiap alat menambah satu hal yang harus dirawat orang lain.

| Kebutuhan | Alat | Alasan |
|---|---|---|
| Satu field vendor punya satu nama lain | Field alias | Paling murah, tidak menghitung apa pun, dan nama aslinya tetap ada [S1] |
| Satu nama diisi dari dua atau lebih field yang mungkin kosong | Calculated field dengan `coalesce()` | Alias hanya boleh satu sumber per nama, dan dua alias ke satu nama diselesaikan secara leksikografis [S1][S5] |
| Semua nilai dari beberapa field perlu dipertahankan | Calculated field dengan `mvdedup(mvappend(...))` | Menghasilkan multivalue, bukan memilih satu [S5] |
| Nilai vendor perlu diterjemahkan ke kosakata baku | Calculated field dengan `case()` atau `if()` | Yang diubah nilainya, bukan namanya [S3][S7] |
| Field baru dari perhitungan, misalnya total byte atau penanda jam kerja | Calculated field | Dihitung setiap search, tanpa mengubah data [S3] |
| Pemetaan dari tabel referensi yang panjang atau sering berubah | Lookup otomatis | Tabel bisa diperbarui tanpa menyentuh `props.conf`, dan boleh memakai alias serta calculated field sebagai kuncinya [S4] |
| Label kategori pada sekelompok event | Event type dan tag | Yang ditandai eventnya, bukan satu field (Day 17) |
| Normalisasi sekali pakai untuk satu investigasi | `eval` atau `rex` di search bar | Tidak perlu mengubah apa pun untuk orang lain (Day 11) |

Satu patokan tambahan dari pengalaman merawat objek seperti ini: bila jawaban atas "kenapa field ini ada" tidak bisa ditulis dalam satu kalimat, objek itu akan menjadi beban untuk orang berikutnya. Tulis alasan itu di deskripsi objeknya saat membuat.

## 2. Contoh dan langkah praktis di PT JAB

Semua keluaran di bagian ini adalah keluaran ilustrasi: angkanya disusun agar konsisten dengan tiket SOC-2026-0235 dan bisa dijumlahkan ulang, bukan hasil eksekusi. Rentang waktunya memakai snap-to jam supaya hasilnya bisa diulang.

### 2.1 Inventaris nama field tiga sumber sebelum mengubah apa pun

Pekerjaan normalisasi yang dimulai tanpa inventaris akan menghasilkan alias untuk field yang ternyata sudah ada namanya, atau `coalesce` atas asumsi yang salah.

**Tujuan:** mengetahui field apa yang ada di tiap sourcetype, seberapa sering terisi, dan nilai apa yang muncul.

```
index=proxy sourcetype=jab:proxy:pop earliest=-24h@h latest=@h
| fieldsummary maxvals=5
| search field IN ("c_ip","x_client_ip","cs_username","px_action","sc_status")
| table field count distinct_count values
```

Keluaran ilustrasi:

```
field          count    distinct_count   values
c_ip           41260              1204   [{"value":"10.30.4.19","count":812}, ...]
cs_username    58940               486   [{"value":"andi.pratama","count":1420}, ...]
px_action      58940                 3   [{"value":"TCP_HIT","count":31204}, {"value":"TCP_MISS","count":22610}, {"value":"TCP_DENIED","count":5126}]
sc_status      58940                12   [{"value":"200","count":48310}, ...]
x_client_ip    17680               604   [{"value":"10.30.4.19","count":""}, ...]
```

**Cara membaca hasil:** total event proxy dalam jendela itu 58.940. Field `c_ip` terisi di 41.260 event dan `x_client_ip` di 17.680; jumlahnya 58.940, persis sama dengan totalnya. Itu bukti kuat bahwa keduanya tidak pernah muncul bersamaan dalam satu event, sehingga `coalesce` atas keduanya aman dan tidak akan kehilangan nilai. Kalau jumlahnya melebihi total, berarti ada event yang punya dua-duanya, dan kamu harus memutuskan mana yang menang, atau mempertahankan keduanya sebagai multivalue.

**Variasi, menguji asumsi "tidak pernah bersamaan" secara langsung:** jangan mengandalkan penjumlahan saja.

```
index=proxy sourcetype=jab:proxy:pop earliest=-24h@h latest=@h
| eval punya=case(isnotnull(c_ip) AND isnotnull(x_client_ip),"dua-duanya", isnotnull(c_ip),"c_ip saja", isnotnull(x_client_ip),"x_client_ip saja", true(),"tidak ada")
| stats count BY punya
```

Keluaran ilustrasi:

```
punya               count
c_ip saja           41260
x_client_ip saja    17680
```

Tidak ada baris `dua-duanya` dan tidak ada baris `tidak ada`, jadi asumsinya terbukti untuk jendela waktu ini. `case()` mengembalikan nilai cabang pertama yang bernilai benar, dan cabang `true()` di akhir berfungsi sebagai penampung sisanya [S7].

**Kapan gagal:** `fieldsummary` tidak melihat field yang belum pernah terekstrak sama sekali, jadi field yang hilang karena add-on tidak terpasang tidak akan muncul sebagai baris kosong; ia tidak muncul sama sekali. Untuk sumber yang baru, lihat juga `_raw`-nya seperti di Day 15 bagian 2.1.

### 2.2 Membuat field alias lewat Settings > Fields > Field aliases

Tiga sumber, tiga objek alias. Langkahnya sama untuk ketiganya, mengikuti form di bagian 1.2 [S1].

Untuk firewall POP:

1. Settings > Fields > Field aliases, lalu `New Field Alias`.
2. Destination app: app SOC.
3. Name: `jab_fw_pop_cim`.
4. Apply to: `sourcetype`, named `jab:fw:pop`.
5. Baris mapping: `fw_srcaddr` menjadi `src`, `fw_dstaddr` menjadi `dest`, `fw_srcport` menjadi `src_port`, `fw_dstport` menjadi `dest_port`, `fw_policy` menjadi `rule`.
6. `Overwrite field values`: biarkan tidak dipilih, karena di sourcetype ini tidak ada field bernama `src` atau `dest` dari jalur lain. Pilihan ini yang kamu ubah hanya bila kamu memang ingin nilai field asal selalu menang [S1].
7. Simpan, lalu atur permission dan pemilik seperti Day 15 bagian 2.6.

Alasan `fw_dstport` dialias ke `dest_port` dan bukan dibuat ulang dengan `EVAL`: CIM mendeskripsikan `dest_port` sebagai angka dan mengingatkan agar tidak diubah menjadi teks seperti `http` [S9]. Alias menyalin nilai apa adanya, jadi tipe datanya tidak berubah; `EVAL` yang menyusun teks justru merusaknya.

Stanza yang dihasilkan, yang bisa kamu cocokkan di `props.conf` app itu:

```
[jab:fw:pop]
FIELDALIAS-jab_fw_pop_cim = fw_srcaddr AS src fw_dstaddr AS dest fw_srcport AS src_port fw_dstport AS dest_port fw_policy AS rule
```

Satu stanza boleh memuat beberapa rename seperti di atas [S2]; bentuk persis yang ditulis UI untuk beberapa baris dalam satu objek alias perlu dicocokkan dengan `props.conf` app-mu, karena yang dijamin dokumentasi adalah sintaksnya, bukan tata letak hasil generatornya.

Untuk VPN vendor dan proxy, objek aliasnya:

```
[jab:vpnlegacy]
FIELDALIAS-jab_vpn_cim = jab_user AS user jab_src AS src jab_group AS user_group

[jab:proxy:pop]
FIELDALIAS-jab_proxy_cim = cs_username AS user sc_status AS status
```

Perhatikan apa yang tidak ada di stanza proxy: tidak ada alias untuk `src`. Alamat klien proxy datang dari dua field, dan satu alias hanya boleh menunjuk satu field [S1], jadi pekerjaan itu pindah ke bagian 2.3.

Verifikasi setelah menyimpan:

```
index=firewall sourcetype=jab:fw:pop earliest=-24h@h latest=@h
| stats count AS total, count(src) AS ada_src, count(dest) AS ada_dest, dc(rule) AS aturan
```

Keluaran ilustrasi:

```
total   ada_src   ada_dest   aturan
90948     90630      90630        14
```

**Cara membaca hasil:** dari 90.948 event, 90.630 punya `src` dan `dest`. Selisih 318 adalah event log `system` yang di Day 15 bagian 2.4 sudah diketahui tidak mengikuti pemetaan kolom yang sama, jadi angkanya konsisten dengan temuan sebelumnya dan bukan masalah baru. Konsistensi seperti ini yang membuat normalisasi bisa dipercaya: setiap selisih harus punya penjelasan yang sudah kamu kenal.

**Kapan gagal:** bila `ada_src` bernilai 0 sementara `total` normal, kemungkinan terbesar objek alias masih private atau cakupan app-nya belum mencakup app yang kamu pakai [S6]. Bila `ada_src` terisi tetapi isinya nomor port, berarti baris mapping tergeser saat diisi di form; periksa stanzanya langsung.

### 2.3 Satu nama dari dua field: calculated field dengan `coalesce`

Inilah kasus yang membedakan alias dan calculated field, dan sekaligus jawaban atas dua nama alamat klien di proxy POP.

**Tujuan:** mengisi `src` di `jab:proxy:pop` dari `c_ip` atau `x_client_ip`, mana pun yang ada, dengan cara yang tetap benar bila nanti add-on resmi dipasang.

Buat di Settings > Fields > Calculated fields dengan sasaran sourcetype `jab:proxy:pop`, nama field `src`, dan ekspresi di bawah. Stanza yang dihasilkan:

```
[jab:proxy:pop]
EVAL-src = coalesce(src, c_ip, x_client_ip)
```

**Penjelasan tiap bagian:** `coalesce` mengembalikan nilai pertama yang tidak NULL [S7]. Argumen pertama `src` sengaja ditulis walaupun sourcetype ini belum punya field `src`, dan inilah bentuk defensifnya: calculated field yang namanya sama dengan field hasil extraction akan menimpanya bahkan ketika ekspresinya menghasilkan null, dan membungkusnya dengan `coalesce` dengan urutan argumen yang tepat mencegah itu [S3]. Hari ini argumen pertama itu tidak melakukan apa pun. Hari ketika add-on proxy resmi dipasang dan mulai mengekstrak `src`, argumen itu yang menyelamatkan datamu.

Uji ekspresinya dengan data sintetis sebelum menyimpan objek, supaya kamu tahu persis apa yang akan terjadi pada ketiga keadaan:

```
| makeresults count=3
| streamstats count AS n
| eval c_ip=case(n==1,"10.30.4.19", true(),null())
| eval x_client_ip=case(n==2,"10.30.4.77", true(),null())
| eval src=case(n==3,"10.30.4.99", true(),null())
| eval hasil=coalesce(src, c_ip, x_client_ip)
| table n src c_ip x_client_ip hasil
```

Keluaran ilustrasi:

```
n   src           c_ip          x_client_ip    hasil
1                 10.30.4.19                   10.30.4.19
2                               10.30.4.77     10.30.4.77
3   10.30.4.99                                 10.30.4.99
```

Hitung sendiri dulu sebelum menjalankan: tiga baris masuk, masing-masing hanya punya satu field terisi, jadi ketiganya menghasilkan nilai yang terisi itu. Bila kamu menukar urutan argumen menjadi `coalesce(c_ip, x_client_ip, src)`, baris ketiga tetap sama karena hanya `src` yang terisi; perbedaan urutan baru terasa pada event yang punya dua field terisi sekaligus, dan itu sebabnya asumsi "tidak pernah bersamaan" di bagian 2.1 harus diuji lebih dulu.

**Variasi, bila kedua nilai harus dipertahankan:** ganti ekspresinya menjadi `mvdedup(mvappend(c_ip, x_client_ip))`, yang menyimpan semua nilai tanpa duplikat [S5]. Konsekuensinya `src` menjadi field multivalue, sehingga `stats count BY src` bisa menghitung satu event di dua baris, dan `cidrmatch()` atas field multivalue perlu diuji perilakunya di lab-mu lebih dulu. Untuk PT JAB bentuk ini tidak dipakai di proxy, tetapi akan dipakai nanti bila log firewall mulai memuat alamat sebelum dan sesudah NAT dalam satu baris.

**Kapan gagal:** ekspresi ini akan selalu kosong bila `c_ip` dan `x_client_ip` sendiri belum terekstrak, misalnya karena extraction untuk sourcetype itu masih private milik orang lain (Day 15 bagian 1.6). Calculated field hanya bisa memakai field yang sudah ada di tahap sebelumnya [S4]; ia tidak bisa menyelamatkan extraction yang tidak berlaku.

### 2.4 Menormalkan nilai, bukan hanya nama

Nama field yang sama tidak membuat satu detection mungkin bila nilainya masih tiga kosakata. Di sini `case()` dipakai, dan di sini keputusan domain dari bagian 1.1 diterapkan.

Tiga stanza, dengan kosakata nilai yang berbeda sesuai domainnya:

```
[jab:fw:pop]
EVAL-action = case(fw_act=="deny","blocked", fw_act=="accept","allowed", fw_act=="close","teardown", true(),null())

[jab:proxy:pop]
EVAL-action = case(px_action=="TCP_DENIED","blocked", in(px_action,"TCP_HIT","TCP_MISS"),"allowed", true(),null())

[jab:vpnlegacy]
EVAL-action = case(jab_result=="OK","success", jab_result=="FAIL","failure", true(),null())
EVAL-app = "vpn-vendor-portal"
```

**Penjelasan tiap bagian:** `case()` mengembalikan nilai untuk kondisi pertama yang benar [S7]. Cabang terakhir `true(), null()` sengaja menghasilkan NULL, bukan teks `unknown`: nilai di luar daftar yang dikenal sebaiknya terlihat sebagai kosong, supaya search inventaris di bagian 2.6 bisa menemukannya, sedangkan teks `unknown` akan tampak seperti nilai yang sah dan diam-diam ikut terhitung. Fungsi `in()` dipakai di dalam ekspresi eval seperti ini, sedangkan bentuk operator `IN (...)` dipakai di command `search`. `EVAL-app = "vpn-vendor-portal"` adalah calculated field bernilai konstan, cara yang sama seperti contoh konfigurasi di Day 23 bagian 2.4, dan gunanya memberi penanda sumber yang bisa dipakai membedakan jalur login di satu data model.

Nilai yang dipakai bukan karangan: `allowed`, `blocked`, dan `teardown` adalah nilai baku `action` untuk All_Traffic, sedangkan `success`, `failure`, `pending`, dan `error` untuk Authentication [S8][S9]. Itu alasan stanza VPN tidak memakai `blocked` walaupun terasa lebih seragam; login gagal bukan koneksi yang diblokir, dan memaksanya menjadi satu kata akan merusak dua data model sekaligus.

Verifikasi, dan ini search yang paling berguna untuk seluruh pekerjaan hari ini:

```
(index=firewall sourcetype=jab:fw:pop) OR (index=proxy sourcetype=jab:proxy:pop) OR (index=vpn sourcetype=jab:vpnlegacy)
earliest=-24h@h latest=@h
| stats count AS total, count(action) AS ada_action, values(action) AS nilai BY sourcetype
```

Keluaran ilustrasi:

```
sourcetype        total   ada_action   nilai
jab:fw:pop        90948        90630   allowed, blocked, teardown
jab:proxy:pop     58940        58940   allowed, blocked
jab:vpnlegacy     12480         2330   failure, success
```

**Cara membaca hasil:** tiga hal dibaca di sini sekaligus. Kolom `nilai` tidak boleh memuat kata asing vendor; kalau ada `deny` di situ, berarti ada jalur lain yang mengisi `action` atau ada stanza yang belum tersimpan. Selisih `total` dan `ada_action` harus punya penjelasan: 318 di firewall adalah log `system`, dan 10.150 di VPN adalah baris `SESSION` yang memang bukan event autentikasi (Day 15 bagian 2.1). Angka 2.330 di VPN cocok dengan 1.918 gagal ditambah 412 sukses dari Day 15, jadi tidak ada event autentikasi yang hilang.

**Kapan gagal:** bila `nilai` di satu sourcetype memuat kata vendor dan kata baku sekaligus, kemungkinan ada dua objek calculated field untuk nama yang sama di app berbeda. Periksa halaman Calculated fields dengan kolom app, dan ingat bahwa objek global dari app lain juga ikut berlaku.

### 2.5 Rantai `EVAL` yang gagal dan cara memperbaikinya

Pekerjaan detection engineer semalam diulang di sini sebagai contoh yang bisa kamu kenali lagi nanti, karena bentuk kegagalannya tidak memberi petunjuk apa pun.

Yang ditulis semula:

```
[jab:proxy:pop]
EVAL-src = coalesce(src, c_ip, x_client_ip)
EVAL-src_zona = if(cidrmatch("10.30.0.0/16", src), "bandung", "luar")
```

Hasilnya, keluaran ilustrasi:

```
sourcetype       total   ada_src   ada_src_zona
jab:proxy:pop    58940     58940              0
```

`src` terisi penuh, `src_zona` kosong seluruhnya. Sebabnya bukan ekspresi `cidrmatch` dan bukan format CIDR-nya: semua setting `EVAL` di satu stanza dijalankan berbarengan, sehingga `src` yang dibaca baris kedua adalah keadaan sebelum tahap calculated field, dan di sourcetype ini `src` belum ada pada tahap itu [S3][S4].

Yang benar, dengan logikanya digabung:

```
[jab:proxy:pop]
EVAL-src = coalesce(src, c_ip, x_client_ip)
EVAL-src_zona = if(cidrmatch("10.30.0.0/16", coalesce(src, c_ip, x_client_ip)), "bandung", "luar")
```

Hasil setelah perbaikan, keluaran ilustrasi:

```
sourcetype       total   ada_src   ada_src_zona
jab:proxy:pop    58940     58940          58940
```

Pengulangan ekspresi `coalesce` di dua baris terasa jelek, dan memang jelek, tetapi itu konsekuensi dari aturan yang tidak bisa dinegosiasi. Dua jalan keluar bila ekspresinya mulai panjang: pindahkan logikanya ke lookup otomatis, yang boleh memakai hasil calculated field karena berada di tahap setelahnya [S4], atau jadikan `src` hasil extraction sungguhan dengan menambah extraction untuk kedua nama field itu sehingga `src` lahir di tahap extraction dan bisa dibaca semua `EVAL` (Day 15).

Bandingkan dengan stanza firewall yang bentuknya mirip tetapi berhasil:

```
[jab:fw:pop]
FIELDALIAS-jab_fw_pop_cim = fw_srcaddr AS src fw_dstaddr AS dest fw_srcport AS src_port fw_dstport AS dest_port fw_policy AS rule
EVAL-src_zona = if(cidrmatch("10.20.0.0/16", src), "datacenter", "luar")
```

Di stanza ini `src` lahir dari alias di tahap lima, dan calculated field di tahap enam boleh membacanya [S4]. Satu kalimat yang pantas ditempel di dinding: yang menentukan boleh atau tidak bukan nama field, tetapi tahap yang melahirkannya.

Satu pengujian yang bisa kamu lakukan untuk melihat aturan ini dari sisi lain adalah mencoba membuat alias dari field hasil calculated field, misalnya `src_zona AS zona`. Dokumentasi menyebut alias tidak bisa dibuat untuk calculated field [S1], dan di lab yang akan kamu lihat adalah field `zona` yang kosong, bukan pesan kesalahan saat menyimpan.

### 2.6 Membuktikan normalisasi lengkap sebelum menulis detection

Sebelum satu detection dijanjikan bekerja untuk tiga sumber, buktikan dulu bahwa keempat nama yang dipakai detection itu memang ada di ketiga sumber. Ini search yang sebaiknya kamu simpan sebagai report dan jalankan ulang setiap kali ada sumber baru.

**Tujuan:** memeriksa kelengkapan `src`, `dest`, `user`, dan `action` per sourcetype dalam satu tabel.

```
(index=firewall sourcetype=jab:fw:pop) OR (index=proxy sourcetype=jab:proxy:pop) OR (index=vpn sourcetype=jab:vpnlegacy)
earliest=-24h@h latest=@h
| stats count AS total, count(src) AS src, count(dest) AS dest, count(user) AS user, count(action) AS action BY sourcetype
| eval persen_src=round(src/total*100, 1)
```

Keluaran ilustrasi:

```
sourcetype        total     src     dest    user   action   persen_src
jab:fw:pop        90948   90630    90630       0    90630         99.7
jab:proxy:pop     58940   58940        0   58940    58940        100.0
jab:vpnlegacy     12480    2330        0    2244     2330         18.7
```

**Cara membaca hasil:** tabel ini jujur tentang apa yang tidak ada, dan itu gunanya. Firewall tidak punya `user` karena perangkat itu memang hanya melihat alamat, bukan identitas; detection yang mengandalkan `user` tidak akan pernah menangkap event firewall, dan itu harus diketahui sebelum detection ditulis, bukan setelah. Proxy tidak punya `dest` karena access log yang dipakai PT JAB mencatat situs tujuan sebagai nama, bukan alamat; bila `dest` dibutuhkan, itu pekerjaan extraction tambahan, bukan alias. Angka 18,7 persen di VPN bukan kerusakan: pembaginya seluruh 12.480 event termasuk 10.150 baris `SESSION`, sedangkan 2.330 baris autentikasi semuanya terisi. Angka 2.244 pada `user` adalah 2.330 dikurangi 86 event varian tanpa nama akun dari Day 15 bagian 2.2.

**Variasi, mencari nilai yang luput dari normalisasi:** cari event yang `action`-nya kosong padahal seharusnya ada.

```
(index=firewall sourcetype=jab:fw:pop) OR (index=proxy sourcetype=jab:proxy:pop)
earliest=-24h@h latest=@h
| where isnull(action)
| stats count BY sourcetype, source
```

Keluaran ilustrasi:

```
sourcetype     source                      count
jab:fw:pop     udp:514/BDG-FW-01-system      318
```

Semua event tanpa `action` berasal dari satu jalur yang sudah dikenal, dan tidak ada kejutan dari sumber lain. Hasil seperti ini yang membuat kamu bisa menulis di tiket bahwa normalisasi sudah lengkap untuk jendela waktu itu.

**Kapan gagal:** search ini membaca tiga index sekaligus tanpa filter lain, jadi pada jendela yang lebar biayanya besar. Pakai jendela pendek untuk pemeriksaan rutin, dan jalankan versi jendela panjangnya sebagai report terjadwal di luar jam sibuk (Day 09).

### 2.7 Satu detection untuk tiga sumber

Sekarang bentuk search yang diminta detection engineer bisa ditulis, dan perbandingan sebelum dengan sesudah yang paling meyakinkan untuk ditunjukkan ke orang lain.

Sebelum normalisasi, pertanyaan "apa saja yang ditolak untuk alamat tunnel `10.10.250.37`" harus ditulis seperti ini:

```
(index=firewall sourcetype=jab:fw:pop fw_srcaddr="10.10.250.37" fw_act=deny)
OR (index=proxy sourcetype=jab:proxy:pop (c_ip="10.10.250.37" OR x_client_ip="10.10.250.37") px_action=TCP_DENIED)
OR (index=vpn sourcetype=jab:vpnlegacy jab_src="10.10.250.37" jab_result=FAIL)
earliest=-24h@h latest=@h
| stats count BY sourcetype
```

Setiap sumber baru menambah satu blok, dan setiap blok harus diperbarui ketika firmware mengganti nama field. Setelah normalisasi, pertanyaan yang sama ditulis seperti ini:

```
(index=firewall OR index=proxy OR index=vpn) src="10.10.250.37" action IN ("blocked","failure")
earliest=-24h@h latest=@h
| stats count AS ditolak, values(action) AS action, values(rule) AS aturan BY sourcetype
```

Keluaran ilustrasi:

```
sourcetype       ditolak   action    aturan
jab:fw:pop          1190   blocked   POP-EDGE-IN
jab:proxy:pop         41   blocked
```

**Penjelasan tiap bagian:** `src` dan `action` adalah nama hasil pekerjaan bagian 2.2 sampai 2.4, bukan nama vendor. Operator `IN (...)` dipakai di command `search` seperti di sini, sedangkan fungsi `in()` dipakai di dalam ekspresi eval dan `where`. `values(rule)` menampilkan nama aturan firewall yang menolak, dan kosong untuk proxy karena sourcetype itu tidak punya field `rule`.

**Cara membaca hasil:** 1.190 koneksi dari alamat tunnel ditolak di perimeter POP oleh aturan `POP-EDGE-IN`, ditambah 41 request yang ditolak proxy. Alamat tunnel tidak muncul di sumber VPN karena di sana ia bukan `src`, melainkan alamat yang diberikan ke sesi; pemetaan dari alamat tunnel ke akun tetap butuh langkah tersendiri dan batasnya ada di Day 05 bagian 1.6.

Sisi identitas dijawab dengan search yang sama tetapi dikelompokkan per `user`:

```
(index=proxy OR index=vpn) user="vendor.bnet01"
earliest=-24h@h latest=@h
| stats count AS total, sum(eval(if(in(action,"blocked","failure"),1,0))) AS ditolak, values(action) AS action BY sourcetype
```

Keluaran ilustrasi:

```
sourcetype       total   ditolak   action
jab:proxy:pop       46        41   allowed, blocked
jab:vpnlegacy      148       147   failure, success
```

**Cara membaca hasil:** 148 event autentikasi untuk akun itu, 147 di antaranya gagal, cocok dengan tiket SOC-2026-0235 dari Day 15. Di proxy, 46 request dengan 41 ditolak. Perhatikan bentuk `sum(eval(if(in(action,...),1,0)))` dan bukan `count(eval(in(action,...)))`: bentuk kedua menghitung semua baris yang ekspresinya tidak NULL, termasuk yang bernilai false, sehingga angkanya akan sama dengan `total` dan terlihat benar padahal salah. Ini kesalahan yang sangat mudah lolos review.

**Kapan gagal:** search `(index=firewall OR index=proxy OR index=vpn) src="..."` mengandalkan `src` ada di ketiga index. Bila besok ada sourcetype baru masuk ke salah satu index tanpa dinormalisasi, event itu diam-diam tidak ikut terhitung, dan detection tetap kelihatan bekerja. Itu alasan search inventaris di bagian 2.6 perlu dijalankan terjadwal, bukan sekali saat onboarding.

## 3. Lab praktik (di VM lab terisolasi)

Lab memakai satu instance Splunk Enterprise lab tanpa ES, index lab sendiri, dan tiga berkas log fiktif yang kamu buat. Beberapa langkah memerlukan penyuntingan `props.conf` di app lab-mu; kerjakan di app buatan sendiri, bukan di app bawaan, dan ingat bahwa perubahan file memerlukan restart [S2].

1. **Siapkan tiga sumber.** Buat `fwpop.csv` (berpemisah koma, dua belas kolom seperti Day 15), `proxypop.log` dengan dua generasi nama field (20 baris memakai `c_ip=`, 10 baris memakai `x_client_ip=`), dan `vpnlegacy.log` seperti Day 15. Unggah dengan sourcetype tetap. Catat jumlah baris per jenis sebelum mulai.
2. **Inventaris dulu.** Jalankan kedua search bagian 2.1 pada data lab-mu dan buktikan sendiri apakah `c_ip` dan `x_client_ip` pernah muncul bersamaan. Catat angkanya dan cocokkan dengan jumlah baris yang kamu buat di langkah 1.
3. **Buat alias lewat UI.** Buat objek alias untuk ketiga sourcetype seperti bagian 2.2, lalu buka `props.conf` app itu dan catat bentuk stanza yang dihasilkan UI, termasuk apakah beberapa rename digabung dalam satu baris.
4. **Uji `Overwrite field values`.** Buat satu event lab yang sudah punya field bernama `src` dari extraction, lalu buat alias ke `src` dengan opsi itu tidak dipilih, catat hasilnya, lalu pilih opsi itu dan catat lagi. Cocokkan dengan tabel di bagian 1.3, terutama baris ketika field asal tidak ada [S1].
5. **Buat tabrakan alias dengan sengaja.** Buat dua objek alias pada sourcetype yang sama, satu bernama `aaa_src` berisi `c_ip AS src` dan satu bernama `zzz_src` berisi `x_client_ip AS src`. Jalankan search dan catat nilai mana yang menang. Bandingkan dengan aturan urutan leksikografis nama class [S5], lalu hapus keduanya dan ganti dengan satu calculated field `coalesce`.
6. **Uji `coalesce` dengan data sintetis.** Jalankan search `makeresults` di bagian 2.3, hitung dulu hasil yang kamu harapkan untuk ketiga baris, lalu cocokkan. Ulangi dengan urutan argumen dibalik dan catat baris mana yang berubah.
7. **Buktikan `EVAL` tidak bisa dirantai.** Tulis dua `EVAL-` di satu stanza seperti versi gagal di bagian 2.5, jalankan `stats count(src) count(src_zona)`, lalu perbaiki dengan menggabungkan ekspresinya dan jalankan lagi. Catat dua pasang angka itu; ini bukti yang paling cepat meyakinkan rekan kerja.
8. **Buktikan `EVAL` boleh membaca alias.** Pada sourcetype firewall, buat `src` lewat alias lalu `src_zona` lewat `EVAL-` yang membacanya. Jalankan dan catat hasilnya. Tulis satu kalimat tentang kenapa yang ini berhasil sementara langkah 7 tidak.
9. **Coba yang dilarang.** Buat alias dari field hasil calculated field (`src_zona AS zona`) dan catat apakah Splunk menolak saat menyimpan atau membiarkanmu menyimpan objek yang tidak menghasilkan apa pun [S1]. Catat juga apa yang terjadi bila sebuah `EVAL-` memakai field dari automatic lookup [S4].
10. **Normalisasi nilai dan ukur.** Terapkan tiga stanza `EVAL-action` bagian 2.4, lalu jalankan search inventaris bagian 2.6. Perbaiki sampai kolom nilai tidak memuat satu pun kata vendor dan setiap selisih angka punya penjelasan tertulis.
11. **Tulis satu detection.** Tulis satu search yang menjawab satu pertanyaan untuk ketiga sumber memakai hanya nama hasil normalisasi, lalu tulis versi "sebelum" yang memakai nama vendor. Catat jumlah baris kedua versi dan pastikan keduanya menghasilkan angka yang sama.
12. **Bagikan dan serahkan.** Atur permission ketiga kelompok objek ke app lab-mu dan pindahkan kepemilikannya ke akun lain, lalu jalankan search dari akun itu (Day 15 bagian 2.6).

**Hasil yang sebaiknya tersimpan:**
- Dua angka dari langkah 2 yang membuktikan apakah dua nama field pernah muncul bersamaan.
- Stanza `props.conf` hasil UI dari langkah 3, apa adanya.
- Empat hasil pengujian `Overwrite field values` dari langkah 4.
- Nama objek yang menang pada tabrakan alias di langkah 5.
- Dua pasang angka dari langkah 7 dan satu kalimat dari langkah 8.
- Tabel inventaris akhir dari langkah 10, dengan penjelasan setiap selisih.
- Dua versi search dari langkah 11 beserta jumlah barisnya.

**Variasi tantangan:** buat `EVAL-action` kedua untuk sourcetype yang sama di app berbeda dengan pemetaan nilai yang berbeda, bagikan keduanya secara global, lalu jalankan search dan temukan mana yang berlaku. Catat bagaimana kamu menemukannya. Ini mensimulasikan keadaan yang terjadi ketika add-on vendor dipasang di atas normalisasi buatan sendiri, dan jawabannya menentukan apakah kamu bisa mempercayai nilai `action` di lingkunganmu.

## 4. Troubleshooting

Tabel ini memuat gejala yang paling sering muncul saat membuat alias dan calculated field. Cari gejalanya di kolom pertama.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Alias kosong untuk semua event | Objek masih private, atau cakupan app belum mencakup app yang dipakai [S6] | Atur `Display for` dan Read per role; jalankan ulang dari akun lain (Day 15 bagian 2.6) |
| Alias kosong padahal field asal ada | Field asal sebenarnya hasil calculated field atau lookup, yang tidak bisa dialias [S1] | Buat field tujuan langsung dengan `EVAL-<nama tujuan>`, atau beri nama yang kamu mau di `OUTPUTNEW` lookup |
| Nilai alias hilang pada sebagian event | Perilaku `AS`: field alias dihapus bila field asalnya tidak ada [S5] | Pakai `ASNEW`, atau jangan pilih `Overwrite field values` sesuai tabel di bagian 1.3 |
| Nilai alias berubah setelah orang lain menambah objek | Beberapa class menyasar nama alias yang sama; yang menang ditentukan urutan leksikografis nama class [S5] | Hapus salah satunya dan ganti dengan satu calculated field `coalesce` |
| Satu event dihitung dua kali setelah normalisasi | Field tujuannya multivalue, misalnya hasil `mvappend` [S5] | Periksa dengan `mvcount()`; pilih `coalesce` bila satu nilai cukup |
| Alias ke `_time` atau internal field membuat hasil aneh | Nama alias sama dengan internal field; dokumentasi menyebut hasilnya tidak bisa diduga [S1] | Ganti namanya |
| Calculated field kosong seluruhnya | Ekspresinya membaca field dari tahap setelahnya, termasuk `EVAL` lain di stanza yang sama [S3][S4] | Gabungkan ekspresinya, atau pindahkan logikanya ke lookup yang berada di tahap setelah calculated field |
| Calculated field memunculkan error ekspresi | Ekspresinya memakai field hasil lookup [S4] | Pindahkan perhitungannya ke search, atau sediakan nilainya di tabel lookup |
| Field hasil extraction tiba-tiba kosong setelah membuat calculated field | Calculated field dengan nama sama menimpa field extraction, bahkan ketika ekspresinya null [S3] | Bungkus dengan `coalesce(<nama field>, ...)` dan atur urutan argumennya |
| Calculated field tidak berlaku untuk sourcetype tertentu | Sasarannya host, source, atau sourcetype yang berupa alias, yang tidak didukung [S3] | Sasarkan ke nama aslinya dan pakai `if()` di dalam ekspresi untuk membedakan |
| Nilai `action` memuat kata vendor dan kata baku sekaligus | Ada dua objek calculated field untuk nama yang sama di app berbeda | Periksa halaman Calculated fields beserta kolom app; objek global dari app lain juga berlaku |
| `dest_port` berisi teks, bukan angka | Nilainya dibentuk ulang dengan ekspresi, bukan dialias | Pakai alias supaya nilai disalin apa adanya; CIM mendeskripsikan port sebagai angka [S9] |
| Detection menangkap event autentikasi sebagai trafik yang diblokir | Login gagal dinormalisasi menjadi `blocked` | Pakai kosakata per domain: `failure` untuk Authentication, `blocked` untuk All_Traffic [S8][S9] |
| Perubahan `props.conf` tidak terlihat | Belum restart, atau file ada di search head yang salah [S2][S4] | Restart sesuai prosedur, dan pastikan konfigurasinya di tier search head yang menjalankan search |
| Angka hasil normalisasi lebih kecil dari yang diharapkan | Ada sourcetype baru di index yang sama yang belum dinormalisasi | Jalankan search inventaris bagian 2.6 secara terjadwal, bukan sekali saat onboarding |

## 5. Kesalahan umum dan jebakan

- Membuat dua alias ke satu nama field untuk menangani dua kemungkinan sumber. Satu alias hanya boleh menunjuk satu field, dan tabrakannya diselesaikan secara leksikografis menurut nama class, bukan menurut niatmu [S1][S5]. Pakai calculated field dengan `coalesce`.
- Mengira `Overwrite field values` hanya soal rapi-rapi. Pilihan itu menentukan apakah nilai yang sudah ada ditimpa, dan dalam satu keadaan apakah field aliasnya dihapus dari event [S1][S5].
- Merantai calculated field. Semua `EVAL` di satu stanza dijalankan berbarengan, jadi yang kedua membaca keadaan sebelum tahap calculated field dan hasilnya kosong tanpa error [S3].
- Membaca contoh `EVAL-x = x * 2` sebagai perhitungan berurutan. Untuk `x=4`, `EVAL-x` dan `EVAL-y = x * 2` dua-duanya memakai nilai asli, sehingga hasilnya 8 dan 8, bukan 8 dan 16 [S3].
- Membuat calculated field bernama sama dengan field hasil extraction tanpa `coalesce`. Ia menimpa field itu bahkan ketika ekspresinya menghasilkan null [S3].
- Memaksa semua sumber memakai satu kosakata nilai. Autentikasi memakai `success` dan `failure`, trafik memakai `allowed` dan `blocked` [S8][S9]; menyatukannya merusak dua data model sekaligus.
- Memakai teks seperti `unknown` sebagai cabang terakhir `case()`. Nilai itu tampak sah dan ikut terhitung; NULL justru bisa dicari dengan search inventaris.
- Mengubah nilai yang seharusnya disalin apa adanya. Nomor port dan alamat lebih baik dialias, bukan dibentuk ulang dengan ekspresi, supaya tipe dan isinya tidak berubah [S9].
- Membuat alias untuk field hasil calculated field atau hasil lookup. Dokumentasi menyebutnya tidak bisa, dan gejalanya field kosong, bukan penolakan saat menyimpan [S1].
- Memakai field hasil lookup di dalam `EVAL-`. Lookup berada setelah calculated field, dan ekspresinya menghasilkan error [S4].
- Melupakan field filter di urutan pertama. Nilai yang disamarkan atau dibuang di tahap itu bisa merusak lookup dan event type di tahap berikutnya [S4].
- Membiarkan objek alias dan calculated field berstatus private. Sama seperti field extraction, orang lain mendapat nol baris tanpa error [S6].
- Memakai ekspresi berat di calculated field pada sourcetype bervolume tinggi. Ia dihitung setiap search oleh siapa pun, termasuk search terjadwal [S3].
- Memakai `count(eval(<kondisi>))` untuk menghitung baris yang memenuhi kondisi. Bentuk itu menghitung semua baris yang hasilnya tidak NULL, termasuk yang false; pakai `sum(eval(if(<kondisi>,1,0)))`.
- Menganggap pekerjaan selesai setelah tiga sumber dinormalisasi. Sourcetype baru yang masuk ke index yang sama tidak ikut, dan detection tetap kelihatan bekerja (bagian 2.6).
- Menganggap nama field yang benar sudah cukup untuk masuk data model. Masih dibutuhkan event type dan tag (Day 17), dan nilai yang sesuai harapan model (Day 23).

## 6. Catatan terkini

Bagian ini menampung detail versi dan hal yang bergantung lingkungan. Isinya tidak mengubah cara kerja, tetapi menjelaskan kenapa layar dan perilaku di instance-mu bisa berbeda dari uraian di atas.

- Kata kunci `ASNEW` dan perilaku yang menghapus field alias dari event ketika field asalnya tidak ada diperkenalkan di versi 7.2.4, dan dijelaskan di halaman catatan perubahan perilaku field alias pada dokumentasi Splunk Cloud Platform 10.6 [S5]. Halaman field alias di Knowledge Manager Manual 10.6 sendiri tidak menyebut `ASNEW` [S1][S2], jadi untuk perilaku timpa yang persis di versi-mu, halaman catatan perubahan itu yang lebih rinci.
- Halaman field alias 10.6 menyebut bahwa Splunk Enterprise hanya mendukung field single value untuk alias [S2]. Untuk field yang berpotensi multivalue, pemeriksaannya dilakukan sendiri dengan `mvcount()`.
- Halaman calculated field 10.6 menguraikan cara `props.conf` dan menautkan cara Splunk Web ke halaman tersendiri, sehingga nama dan letak field di form Settings > Fields > Calculated fields tidak dijelaskan di halaman itu [S3]. Cocokkan label formnya dengan layar versi-mu.
- Urutan operasi search-time di 10.6 memuat field filter sebagai langkah pertama [S4]. Versi dokumentasi lama tidak memuat langkah itu, jadi tulisan dan materi lama yang menyebut extraction sebagai langkah pertama bukan salah untuk versinya, hanya tidak lengkap untuk 10.6.
- Secara default hanya role admin atau sc_admin yang bisa membuat, menyunting, dan menghapus field filter, dan admin, sc_admin, atau power yang bisa melihatnya; pengecualian role diatur lewat Splunk Web atau REST API, bukan lewat file konfigurasi [S4].
- CIM 6.4 mencantumkan nilai baku `action` sebagai `success`, `failure`, `pending`, `error` untuk Authentication [S8] dan `allowed`, `blocked`, `teardown` untuk All_Traffic [S9]. Halaman CIM juga muncul dengan label versi 8.x di sebagian jalur dokumentasi; yang menentukan adalah versi add-on CIM yang terpasang di instance-mu (Day 23).
- Perubahan pada `props.conf` membutuhkan restart Splunk Enterprise [S2], sedangkan perubahan lewat Splunk Web berlaku tanpa restart. Di deployment dengan search head cluster, mekanisme distribusinya berbeda; cek dengan admin platform.
- Dokumentasi resmi kini di help.splunk.com, dan tautan docs.splunk.com lama masih beredar untuk halaman yang sama.

## 7. Cheat sheet

```
MEMILIH ALAT
  satu field, satu nama lain                 -> FIELD ALIAS
  satu nama dari beberapa field              -> EVAL-<nama> = coalesce(a, b, c)
  semua nilai perlu disimpan                 -> EVAL-<nama> = mvdedup(mvappend(a, b))   (jadi multivalue)
  nilai vendor -> kosakata baku              -> EVAL-action = case(...)
  tabel referensi panjang / sering berubah   -> automatic lookup (LOOKUP-)
  label kategori pada event                  -> event type + tag (Day 17)
  sekali pakai di satu search                -> eval / rex di search bar (Day 11)

URUTAN OPERASI SEARCH-TIME (tiap tahap hanya boleh memakai hasil tahap di atasnya)
  1 field filter (field_filters.conf)      5 FIELDALIAS-<class>
  2 EXTRACT-<class>                        6 EVAL-<fieldname>   (semua EVAL satu stanza BERBARENGAN)
  3 REPORT-<class> + transforms.conf       7 LOOKUP-<class>
  4 KV_MODE (default auto)                 8 eventtypes.conf    9 tags.conf
  index-time (default + indexed field) berjalan sebelum semuanya

  alias  TIDAK boleh: calculated field, lookup, event type, tag
  EVAL   TIDAK boleh: lookup (error), event type, tag, EVAL lain (kosong)
  lookup BOLEH: extraction, alias, calculated field
  event type BOLEH semua di atasnya, TIDAK boleh tag ; tag boleh pasangan field-value apa pun

FIELD ALIAS (Settings > Fields > Field aliases)
  FIELDALIAS-<class> = <orig> AS <alias>        AS     = timpa; hapus alias bila orig tidak ada
                                                ASNEW  = lewati bila field tujuan sudah terisi (sejak 7.2.4)
  Overwrite field values  : tidak dipilih = nilai alias dibiarkan ; dipilih = diganti nilai orig
  satu field boleh banyak alias ; satu alias HANYA satu field
  beberapa class ke alias sama -> urutan leksikografis nama class, yang terakhir menang
  alias tidak menghapus nama asli ; jangan pakai nama internal field (_time)
  Splunk Enterprise: single value saja

CALCULATED FIELD (Settings > Fields > Calculated fields)
  EVAL-<fieldname> = <ekspresi eval>
  nama sama dengan field extraction -> MENIMPA, bahkan bila hasilnya null
     aman: EVAL-src = coalesce(src, c_ip, x_client_ip)    (urutan argumen = urutan prioritas)
  tidak bisa disasarkan ke host/source/sourcetype yang berupa alias -> pakai if() di ekspresi
  contoh dokumentasi: EVAL-x = x*2 dan EVAL-y = x*2 pada x=4  ->  x=8, y=8  (bukan 16)

NILAI BAKU CIM YANG SERING DIPAKAI
  Authentication : action = success | failure | pending | error      tag authentication
  All_Traffic    : action = allowed | blocked | teardown             tag network, communicate
  port adalah ANGKA ; src/dest boleh dialias dari src_ip, src_host, src_name, dst

MENGHITUNG DENGAN BENAR
  salah : count(eval(in(action,"blocked","failure")))     (ikut menghitung yang false)
  benar : sum(eval(if(in(action,"blocked","failure"),1,0)))
  fungsi in() di eval/where ; operator IN (...) di command search
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Proxy punya dua nama field untuk alamat klien, `c_ip` di event lama dan `x_client_ip` di event baru. Rekanmu membuat dua objek field alias, keduanya menuju `src`, lalu bilang sudah selesai. Tepat?

<details><summary>Jawaban</summary>

Tidak. Satu alias hanya boleh menunjuk satu field, dan bila beberapa class alias menyasar nama alias yang sama, search head menerapkannya dalam urutan leksikografis nama class dan yang terakhir diterapkan yang menang. Artinya nilai `src` ditentukan oleh nama objek yang dikarang, bukan oleh prioritas yang dimaksudkan, dan hasilnya bisa berubah ketika orang lain menambah alias dengan nama class yang lebih besar. Jalan yang benar untuk satu nama dari beberapa sumber adalah calculated field, misalnya `coalesce(c_ip, x_client_ip)` bila cukup satu nilai, atau `mvdedup(mvappend(c_ip, x_client_ip))` bila semua nilai harus disimpan. Lihat bagian 1.3 dan 2.3.

</details>

**2. Skenario keputusan.** Kamu menulis dua calculated field di satu stanza: `EVAL-src = coalesce(c_ip, x_client_ip)` lalu `EVAL-src_zona = if(cidrmatch("10.30.0.0/16", src), "bandung", "luar")`. Kolom `src` terisi penuh, `src_zona` kosong seluruhnya. Apa yang kamu lakukan?

- A. Perbaiki format CIDR-nya, karena `cidrmatch` kemungkinan menolak notasi itu.
- B. Gabungkan logikanya menjadi satu ekspresi, karena semua `EVAL` di satu stanza dijalankan berbarengan sehingga yang kedua tidak melihat hasil yang pertama.
- C. Pindahkan `EVAL-src_zona` ke stanza terpisah untuk sourcetype yang sama supaya dijalankan setelahnya.

<details><summary>Jawaban</summary>

B. Semua setting `EVAL` di satu stanza diproses berbarengan, bukan berurutan, jadi `src` yang dibaca ekspresi kedua adalah keadaan sebelum tahap calculated field. Perbaikannya menulis ulang ekspresi sumbernya di dalam ekspresi kedua, atau memindahkan logikanya ke lookup otomatis yang berada di tahap setelah calculated field, atau membuat `src` lahir di tahap extraction. A keliru karena gejalanya kosong untuk semua event, bukan untuk sebagian, dan `cidrmatch` yang salah format akan salah untuk semua baris dengan cara yang sama tetapi tetap mengembalikan nilai false, bukan kosong. C tidak membantu karena urutan yang berlaku adalah urutan tahap operasi search-time, bukan urutan stanza. Lihat bagian 1.6 dan 2.5.

</details>

**3. Pertanyaan jebakan.** "Supaya satu detection bisa menangkap semuanya, normalisasikan semua kegagalan menjadi `action=blocked`: koneksi firewall yang ditolak, request proxy yang ditolak, dan login VPN yang gagal." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Satu nama field boleh lintas domain, tetapi satu kosakata nilai tidak. CIM menetapkan nilai `allowed`, `blocked`, dan `teardown` untuk trafik jaringan, dan `success`, `failure`, `pending`, serta `error` untuk autentikasi. Memberi `blocked` pada login gagal membuat detection yang menghitung koneksi ditolak ikut menghitung login gagal, dan membuat pencarian berbasis Authentication yang menyaring `failure` tidak menemukan apa pun. Yang disamakan nama fieldnya (`src`, `user`, `action`), sedangkan nilainya mengikuti domain tiap sumber. Lihat bagian 1.1 dan 2.4.

</details>

**4. Jelaskan ulang.** Jelaskan kepada analyst L1 baru di PT JAB dalam tiga kalimat apa bedanya field alias dan calculated field, dan kenapa urutan operasi search-time perlu diketahui.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Field alias cuma memberi nama kedua ke field yang sudah ada, jadi `fw_srcaddr` juga bisa dipanggil `src` tanpa menghitung apa pun dan tanpa menghapus nama aslinya. Calculated field membuat field baru dari ekspresi `eval` yang dihitung setiap kali search jalan, jadi dia yang dipakai kalau satu nama harus diisi dari dua field, atau kalau nilai vendor harus diterjemahkan ke kosakata baku. Urutannya perlu diketahui karena Splunk menjalankan tahap-tahap ini dalam urutan tetap, alias sebelum calculated field dan keduanya sebelum lookup, sehingga alias tidak bisa membaca hasil calculated field dan calculated field tidak bisa membaca hasil lookup, dan kalau dilanggar field-nya cuma kosong tanpa ada pesan error apa pun."

Kesalahan yang sering muncul:
- Menyebut alias mengganti nama field. Alias menambah nama; nama aslinya tetap ada.
- Mengira keduanya cuma dua cara menulis hal yang sama.
- Lupa menyebut bahwa pelanggaran urutan gagal tanpa error, yang justru bagian paling penting untuk diingat.

</details>

**5. Skenario keputusan.** Enam bulan setelah normalisasi selesai, add-on resmi untuk proxy dipasang dan add-on itu mengekstrak `src` sendiri. Calculated field kalian masih berbunyi `EVAL-src = coalesce(c_ip, x_client_ip)`. Apa yang terjadi dan apa yang kamu kerjakan?

- A. Tidak ada masalah; add-on menang karena extraction berjalan lebih dulu daripada calculated field.
- B. Calculated field menimpa `src` dari add-on, termasuk pada event yang `c_ip` dan `x_client_ip`-nya kosong, sehingga `src` menjadi kosong di event itu. Ubah menjadi `coalesce(src, c_ip, x_client_ip)` atau hapus calculated field itu setelah memastikan add-on mencakup semua generasi event.
- C. Hapus semua alias dan calculated field, lalu percaya sepenuhnya pada add-on.

<details><summary>Jawaban</summary>

B. Calculated field yang namanya sama dengan field hasil extraction akan menimpanya, bahkan ketika ekspresinya menghasilkan null, dan pencegahannya membungkus ekspresi dengan `coalesce()` dengan urutan argumen yang menentukan nilai mana yang menang. A keliru justru karena urutan tahap: extraction memang lebih dulu, tetapi itulah yang membuat calculated field bisa menimpa hasilnya. C terlalu cepat: add-on perlu diverifikasi dulu, termasuk apakah ia mengenali format event generasi lama, dan bentuk `coalesce(src, ...)` adalah cara aman untuk hidup berdampingan sampai verifikasi itu selesai. Lihat bagian 1.4 dan 2.3.

</details>

**6. Pertanyaan jebakan.** "Karena tag dijalankan paling akhir, tag tidak bisa dipasang pada field yang dibuat calculated field." Benarkah?

<details><summary>Jawaban</summary>

Tidak, terbalik. Justru karena tag berada di urutan terakhir, ia boleh menempel pada pasangan field-value apa pun, tidak peduli bagaimana field itu ditambahkan, termasuk field hasil alias dan calculated field. Yang berlaku sebaliknya: event type tidak bisa menunjuk tag karena event type berada sebelum tag, dan calculated field tidak bisa menunjuk apa pun yang lahir di tahap setelahnya. Aturan tunggalnya satu baris: setiap operasi boleh memakai hasil operasi sebelumnya, dan tidak boleh memuat field yang dihasilkan operasi sesudahnya. Lihat bagian 1.5.

</details>

**7. Interview question (English).** "You have firewall, proxy and VPN logs from three different vendors. How do you get to one detection instead of three?"

<details><summary>Sample answer</summary>

"The detection is the last step, not the first. I start by listing what each source actually calls the same thing, so for us that was four different names for the client address and five different words for the decision, and I check with fieldsummary how often each field is populated before I touch anything. Then I use the cheapest tool that works: a field alias where one vendor field maps to one standard name, like `src_ip` to `src`, because an alias costs nothing and keeps the original name. Where one standard name has to come from several possible fields, I use a calculated field with coalesce instead of two aliases, because two aliases pointing at the same name are resolved in lexicographic order of the class name, so the winner depends on what someone typed as the object name. Then I normalise the values, not just the names, and I keep them inside the right vocabulary: failed logins become `failure` for authentication, blocked connections become `blocked` for traffic, because collapsing them into one word breaks both data models. The thing I always keep in mind while doing this is the search-time operations order: extractions, then aliases, then calculated fields, then lookups, then event types and tags, and each step can only use what earlier steps produced. That's why a calculated field can't read another calculated field in the same stanza, they're evaluated in parallel, and that failure mode is silent, the field is just empty. Last, I share the objects and hand ownership to a team service account, because a private alias means everyone else's search quietly returns nothing, and I keep a scheduled inventory search that counts how many events in each sourcetype have the normalised fields, so a new source type doesn't silently fall out of the detection."

What makes this answer strong: it treats inventory and measurement as part of the work, picks the cheapest tool per case with a documented reason, keeps value vocabularies per domain instead of flattening them, names the operations order and the silent parallel-evaluation trap, and closes the loop with sharing, ownership and ongoing verification.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Splunk Enterprise 10.6 Knowledge Manager Manual: Create field aliases in Splunk Web | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/field-aliases | primer | diakses 2026-10-14 | Tinggi. Langkah form, karakter nama yang diizinkan, perilaku `Overwrite field values`, satu alias satu field, nama asli tetap ada, larangan nama internal field, larangan alias atas calculated field, event type, tag, dan field lookup, saran memakai calculated field dengan `coalesce` untuk beberapa sumber |
| S2 | Splunk Enterprise 10.6 Knowledge Manager Manual: Configure field aliases with props.conf | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/field-aliases/configure-field-aliases-with-props.conf | primer | diakses 2026-10-14 | Tinggi. Sintaks `FIELDALIAS-<class> = <orig> AS <new>`, beberapa rename dalam satu stanza, dukungan single value saja, keharusan restart, contoh alias atas hasil `EXTRACT` dan pemakaiannya di lookup. Tidak menyebut `ASNEW` |
| S3 | Splunk Enterprise 10.6 Knowledge Manager Manual: About calculated fields | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/calculated-fields | primer | diakses 2026-10-14 | Tinggi. `EVAL-<fieldname>`, posisi setelah alias dan sebelum lookup, tidak bisa merujuk lookup, event type, tag, tidak bisa dirantai karena `EVAL` satu stanza berjalan berbarengan, contoh `EVAL-x = x * 2`, perilaku menimpa field extraction dan penangkalnya dengan `coalesce`, larangan menyasar host, source, atau sourcetype yang berupa alias |
| S4 | Splunk Enterprise 10.6 Knowledge Manager Manual: The sequence of search-time operations | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/get-started-with-knowledge-objects/the-sequence-of-search-time-operations | primer | diakses 2026-10-14 | Tinggi. Urutan sembilan operasi beserta letak konfigurasi dan apa yang boleh dirujuk, aturan tidak boleh merujuk hasil tahap setelahnya, posisi operasi index-time, catatan field filter dan role yang bisa mengelolanya, keterangan konfigurasi berbasis file dibuat di tier search head |
| S5 | Splunk Cloud Platform 10.6: Field alias behavior change | https://help.splunk.com/en/splunk-cloud-platform/release-notes/10.6/splunk-cloud-platform-release-notes/splunk-cloud-platform-field-alias-behavior-change | primer | diakses 2026-10-14 | Tinggi untuk perilaku timpa. Perubahan sejak 7.2.4, penghapusan field alias ketika field asal tidak ada, kata kunci `ASNEW`, urutan leksikografis nama class dengan contoh `class1` dan `class2`, saran audit dan pemakaian calculated field `coalesce` atau `mvdedup(mvappend(...))`. Halaman ini dokumentasi Splunk Cloud Platform; perilaku yang sama perlu dicocokkan dengan versi Splunk Enterprise-mu |
| S6 | Splunk Enterprise 10.6 Knowledge Manager Manual: Manage knowledge object permissions | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/get-started-with-knowledge-objects/manage-knowledge-object-permissions | primer | diakses 2026-10-14 | Tinggi. Objek baru private, `Display for` App dan All apps, Read dan Write per role, role yang bisa membagikan dan mempromosikan |
| S7 | Splunk Enterprise 10.6 Search Reference: Evaluation functions | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/evaluation-functions | primer | diakses 2026-10-14 | Tinggi. `coalesce` mengembalikan nilai pertama yang tidak NULL, `case` mengembalikan nilai kondisi pertama yang benar, `if`, `in`, `match`, `cidrmatch`, `mvappend`, `mvdedup`, `null`, `isnotnull` |
| S8 | Splunk CIM 6.4: Authentication data model | https://help.splunk.com/en/data-management/common-information-model/6.4/data-models/authentication | primer | diakses 2026-10-14 | Tinggi. Nilai baku `action` berupa `success`, `failure`, `pending`, `error`, tag `authentication`, deskripsi `user`, `src`, `dest`, `app` |
| S9 | Splunk CIM 6.4: Network Traffic data model | https://help.splunk.com/en/data-management/common-information-model/6.4/data-models/network-traffic | primer | diakses 2026-10-14 | Tinggi. Nilai baku `action` berupa `allowed`, `blocked`, `teardown`, tag `network` dan `communicate`, keterangan bahwa `src` dan `dest` boleh dialias dari `src_ip`, `src_host`, `src_name` dan seterusnya, serta port sebagai angka |

**Catatan sumber:** kata kunci `ASNEW` dan perilaku timpa yang persis berasal dari halaman catatan perubahan perilaku field alias di dokumentasi Splunk Cloud Platform 10.6 [S5]; halaman field alias Knowledge Manager Manual 10.6 tidak menyebutnya [S1][S2], jadi untuk Splunk Enterprise cocokkan perilakunya dengan pengujian di bagian 3 langkah 4 dan 5. Bentuk persis stanza yang dituliskan Splunk Web ketika satu objek alias memuat beberapa baris rename tidak dinyatakan dokumentasi; yang dijamin adalah sintaksnya dan bahwa satu stanza boleh memuat beberapa rename [S2]. Pernyataan bahwa pelanggaran urutan operasi menghasilkan field kosong tanpa error, bukan penolakan saat menyimpan, adalah konsekuensi dari aturan urutan [S3][S4] dan diuji di bagian 3 langkah 7 sampai 9. Contoh konfigurasi `.conf` di bagian 2 mengikuti pola yang sama dengan contoh di Day 23 bagian 2.4 (`EXTRACT-`, `FIELDALIAS-`, `EVAL-action`, `EVAL-app`), diterapkan ke sumber PT JAB. Semua angka di keluaran ilustrasi disusun agar konsisten dengan Day 15 dan tiket SOC-2026-0235 dan bisa dijumlahkan ulang, tetapi bukan hasil eksekusi.
