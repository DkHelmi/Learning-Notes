---
day: 18
title: 'Macro: memakai ulang logika search dengan argumen, validasi, dan ekspansi'
researched_on: 2026-10-14
versions_checked: 'Splunk Enterprise 10.6 (Knowledge Manager Manual: Define search macros in Settings, Use search macros in searches, Search macro examples; Admin Manual: macros.conf); ES 8.7.0; CIM 6.4; repo security_content (macro security_content_ctime dan security_content_summariesonly, modifikasi tercatat 2026-05-13)'
---

# Day 18: Macro

Cakupan: membuat dan memakai search macro, dari macro tanpa argumen sampai macro dengan argumen beserta validation expression, definisi berbasis eval, macro bersarang, cara melihat hasil ekspansinya di search bar, dan pola memakai ulang logika detection termasuk macro `security_content_*` dari konten resmi Splunk.

## Ide inti

Macro adalah teks yang disimpan dengan nama, lalu ditempelkan kembali ke dalam search sebelum search itu dijalankan. Tidak ada keajaiban di dalamnya: Splunk mengganti `` `jab_auth` `` dengan isi definisinya, lalu mem-parsing hasil penggantian itu sebagai search biasa. Karena ia substitusi teks, macro bisa memuat apa saja yang sah di posisi tempat ia dipanggil, termasuk pipe, `stats`, subsearch, bahkan sebagian dari sebuah command. Itu membuatnya jauh lebih bebas daripada event type (Day 17), dan sekaligus jauh lebih berbahaya: satu salah ketik di satu definisi langsung menyebar ke setiap search, report, alert, dan detection yang memakainya, tanpa satu pun di antaranya ikut berubah di layar.

Kebiasaan ini sudah kamu punya dari skrip kerja: fungsi atau alias shell yang dipakai ulang di banyak skrip. Nilainya sama, yaitu satu tempat untuk diperbaiki, dan risikonya juga sama, yaitu satu tempat untuk dirusak. Bedanya dengan fungsi di bahasa pemrograman ada dua dan keduanya penting. Pertama, macro tidak punya scope: ia tidak mengembalikan nilai, ia mengganti teks, sehingga hasilnya hanya bisa dinilai setelah diekspansi. Kedua, macro tidak punya tipe data; satu-satunya pengaman yang tersedia adalah validation expression yang kamu tulis sendiri.

```
Yang kamu tulis di search bar
  `jab_auth_failure` `jab_window(8)`
  | `jab_top_gagal(src, 50)`

Tahap ekspansi (sebelum search di-parse)
  `jab_auth_failure`  -> `jab_auth` action=failure        macro bersarang, diekspansi lagi
  `jab_auth`          -> (index=vpn OR index=wineventlog OR index=linux OR index=o365) tag=authentication
  `jab_window(8)`     -> earliest=-8h@h latest=@h         argumen disubstitusi ke $jam$
  `jab_top_gagal(..)` -> stats ... | where ... | sort ...

Yang benar-benar dijalankan Splunk
  (index=vpn OR index=wineventlog OR index=linux OR index=o365) tag=authentication action=failure
  earliest=-8h@h latest=@h
  | stats count AS gagal dc(user) AS user_unik BY src | where gagal >= 50 | sort - gagal

Yang tidak ikut diekspansi
  teks di dalam tanda kutip ganda
```

Situasi yang dipakai sepanjang Day ini melanjutkan Day 17. Empat event type otentikasi di PT Jaringan Anak Bangsa (PT JAB, ISP menengah fiktif) sudah diberi tag `authentication`, dan perangkat POP sudah diberi tag `pop`. Dua hari setelah itu detection engineer menulis lagi di kanal tim:

> "Dua hal. Pertama, filter aset POP sekarang dipakai di sembilan search dan tiga di antaranya ketinggalan waktu perangkat Medan ditambahkan, jadi saya mau logika itu hidup di satu tempat saja, termasuk ambang dan rentang waktunya. Kedua, saya memasang satu detection resmi dari Splunk dan hasilnya kosong. Baris pertamanya memanggil sesuatu di antara tanda petik miring yang sepertinya tidak ada di lingkungan kita, dan saya belum tahu cara melihat isinya."

Permintaan itu memuat lima pertanyaan:

1. Apa yang sebenarnya dilakukan macro saat search dijalankan, dan kapan ia bukan alat yang tepat?
2. Di mana macro dibuat, dan bagian mana dari formnya yang menentukan cara memanggilnya?
3. Bagaimana memberi argumen, dan bagaimana mencegah argumen yang salah merusak hasil tanpa memberi tanda?
4. Bisakah satu macro memakai macro lain, dan apa yang tidak ikut diekspansi?
5. Bagaimana melihat isi macro di detection yang ditulis orang lain, dan kenapa detection resmi bisa kosong?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2 dan 1.3, pertanyaan 3 di bagian 1.4 sampai 1.6, pertanyaan 4 di bagian 1.7, dan pertanyaan 5 di bagian 1.8 dan 1.9. Bagian 2 membangun enam macro PT JAB sampai menjadi satu detection, lalu membaca detection resmi yang hasilnya kosong.

**Kapan relevan:** setiap kali logika yang sama muncul di lebih dari dua search, setiap kali ambang atau daftar pengecualian perlu bisa diubah di satu tempat, dan setiap kali kamu membaca atau memasang konten detection dari luar yang memanggil macro.
**Kapan bukan jawaban:** bila yang dipakai ulang adalah kriteria yang bisa dinilai per event, misalnya "event ini adalah event otentikasi", event type lebih tepat karena hasilnya ikut menentukan keanggotaan data model (Day 17). Bila yang dibutuhkan adalah memetakan banyak nilai ke atribut, pakai lookup. Bila logikanya perlu berjalan sendiri menurut jadwal dan mengirim notifikasi, yang kamu butuhkan report atau alert (Day 09); macro hanya bagian dari isinya.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dasar dari Day 01 sampai Day 17 (pipeline, `stats`, `eval`, `where`, event type, tag, data model, permission knowledge object) tidak diulang di sini. Tabel ini hanya memuat istilah yang dipakai Day ini; cari kolom padanan bila sebuah istilah terasa asing.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Search macro | Teks SPL bernama yang disubstitusi ke dalam search sebelum dijalankan | Fungsi atau alias di skrip yang dipakai ulang di banyak skrip |
| Ekspansi | Proses penggantian nama macro dengan isi definisinya | Hasil akhir perintah setelah alias shell diurai |
| Tanda petik miring | Karakter backtick yang mengapit nama macro saat dipanggil | Tanda pemanggilan fungsi di skrip |
| Argumen macro | Nilai yang dikirim saat memanggil macro dan disubstitusi ke `$nama$` | Parameter yang dikirim ke skrip di baris perintah |
| `nama(2)` | Nama macro berargumen; angka di dalam kurung adalah jumlah argumennya | Versi skrip yang menerima dua parameter |
| Overloading | Dua macro bernama sama dengan jumlah argumen berbeda | Dua mode pemakaian skrip yang sama, dibedakan jumlah parameter |
| Validation expression | Ekspresi eval yang memeriksa nilai argumen sebelum search jalan | Pemeriksaan parameter di awal skrip sebelum eksekusi |
| Definisi berbasis eval | Definisi yang berupa ekspresi eval dan hasilnya yang menjadi teks ekspansi | Skrip yang menyusun sendiri baris perintah lalu menjalankannya |
| Macro bersarang | Macro yang definisinya memanggil macro lain | Fungsi yang memanggil fungsi lain |
| Generating command | Command yang berada di awal pipeline dan menghasilkan event sendiri, misalnya `tstats` | Perintah yang menghasilkan datanya sendiri, bukan membaca dari pipe |
| Macro filter | Macro kosong di akhir detection, tempat menambahkan pengecualian | Daftar pengecualian terpisah dari isi alarm di NMS |
| ESCU | Kumpulan konten detection resmi Splunk yang isinya bergantung pada macro | Paket template alarm vendor yang masih perlu disesuaikan ke lingkungan |

### 1.1 Macro: substitusi teks sebelum search jalan

Yang membuat macro mudah dipahami sekaligus mudah disalahpahami adalah sifatnya sebagai substitusi teks. Definisi sebuah macro adalah teks yang akan dipakai untuk mengganti pemanggilannya setelah argumen disubstitusi [S4]. Setelah penggantian itu, yang di-parse Splunk adalah hasil penggantian, bukan nama macro-nya.

Tiga akibat praktis yang perlu kamu pegang:

- **Definisi harus mengikuti sintaks tempat ia dipanggil.** Dokumentasi menyatakan definisi harus memenuhi sintaks command yang akan memakainya, dan memberi contoh bahwa string literal di dalam `eval` harus memakai tanda kutip ganda [S1]. Macro yang benar di satu posisi bisa menjadi error di posisi lain.
- **Macro tidak tahu apa yang ada di sebelahnya.** Karena ia hanya teks, macro yang isinya dimulai dengan `stats` tidak otomatis mendapat pipe. Kamu yang harus menuliskannya, dan di satu kasus justru harus tidak menuliskannya di dalam definisi (bagian 1.7).
- **Biayanya nol saat search jalan.** Berbeda dari event type yang diuji terhadap setiap event (Day 17 bagian 1.8), macro selesai sebelum search dimulai. Itu sebabnya dokumentasi event type sendiri menunjuk macro sebagai alat yang tepat untuk menyingkat search [S1 di Day 17].

Satu konsekuensi yang jarang disadari sampai terjadi: karena macro selesai sebelum search jalan, search yang memakainya tidak menyimpan salinan isinya. Mengubah satu definisi mengubah perilaku semua report, alert, dan detection yang memanggilnya pada jadwal berikutnya, tanpa satu pun di antaranya tercatat sebagai berubah. Karena itu macro yang dipakai banyak objek diperlakukan seperti perubahan konfigurasi: ada pemilik, ada catatan, dan ada pemeriksaan setelah diubah.

### 1.2 Tempatnya di UI dan isi formnya

Macro dibuat dari Settings > Advanced Search > Search macros, lalu klik New [S1]. Form itu punya delapan bagian, dan tabel berikut memuat arti masing-masing beserta bagian Day ini yang membahasnya; cari kolom terakhir bila kamu hanya ingin tahu tempat penjelasan lengkapnya.

| Kolom di form | Arti [S1] | Dibahas di |
|---|---|---|
| Destination app | App tempat macro itu berlaku | bagian 1.3 |
| Name | Nama unik; bila macro menerima argumen, jumlah argumennya ditambahkan di belakang nama, misalnya `mymacro(2)` | bagian 1.4 |
| Definition | SPL yang akan menggantikan pemanggilan macro | bagian 1.3 |
| Use eval-based definition? | Menandai bahwa Definition adalah ekspresi eval yang hasilnya berupa string ekspansi | bagian 1.6 |
| Arguments | Daftar nama argumen dipisah koma; hanya huruf, angka, garis bawah, dan tanda hubung, tanpa pengulangan nama | bagian 1.4 |
| Validation expression | Ekspresi eval yang memeriksa nilai argumen | bagian 1.5 |
| Validation error message | Pesan yang muncul bila pemeriksaan gagal | bagian 1.5 |
| Save | Menyimpan definisi ke `macros.conf` | bagian 1.3 |

Karena macro adalah knowledge object seperti event type dan lookup, permission dan kepemilikannya mengikuti aturan yang sama: macro yang masih private tidak terlihat oleh rekan tim, dan detection yang memanggilnya akan gagal di konteks app lain. Permission dibahas di Day 15, dan objek yatim di Day 09 bagian 1.6.

### 1.3 Macro tanpa argumen

Bentuk paling sederhana: satu nama, satu definisi. Pemanggilannya memakai tanda petik miring sebelum dan sesudah nama macro [S2]:

```
sourcetype=access_* | `mymacro`
```

Di `macros.conf`, stanza tanpa argumen hanya berisi namanya [S4]:

```
[nama_macro]
definition = <teks SPL>
description = <penjelasan singkat>
iseval = false
```

Atribut `description` bersifat opsional dan isinya penjelasan singkat tentang apa yang dilakukan macro itu [S4]. Di lingkungan dengan banyak macro, kolom itu yang membedakan macro yang masih dipakai dari macro yang tinggal sejarah, jadi isi selalu.

Dua aturan nama yang perlu diingat sejak awal:

- Nama macro tidak boleh memuat tanda hubung. Dokumentasi menyatakan app Search tidak mendukung tanda hubung di nama macro, jadi pakai garis bawah [S2].
- Nama harus unik di dalam app-nya [S1]. Macro dengan nama sama tetapi jumlah argumen berbeda adalah kasus tersendiri yang memang diizinkan (bagian 1.4).

### 1.4 Macro dengan argumen: `nama(2)` dan `$arg$`

Begitu macro perlu menerima nilai, dua hal berubah: namanya dan isinya.

Namanya diberi jumlah argumen di belakangnya. Macro dengan dua argumen diberi nama `mymacro(2)`, dan di `macros.conf` stanza-nya ditulis `[foobar(2)]` [S1][S4]. Angka itu bagian dari identitas macro, bukan dokumentasi: memanggil `` `mymacro(a)` `` ketika yang terdaftar adalah `mymacro(2)` berarti memanggil macro yang tidak ada.

Isinya memakai nama argumen yang diapit tanda dolar. Dokumentasi menyatakan argumen yang akan disubstitusi harus dimulai dan diakhiri tanda dolar, dan bahwa pola `$<arg>$` diganti secara global di dalam string, termasuk di dalam tanda kutip [S4]. Nama argumen hanya boleh memuat huruf, angka, garis bawah, dan tanda hubung, dan tidak boleh berulang [S1][S4]. Daftar `args` diabaikan untuk macro yang nama stanza-nya tidak menyebut jumlah argumen [S4].

Pemanggilannya menerima dua gaya [S2][S3]:

```
`argmacro(120,300)`
`iis_search(fragment=TM)`
```

Gaya pertama posisional, gaya kedua menyebut nama argumen. Gaya kedua lebih tahan terhadap kesalahan urutan dan jauh lebih mudah dibaca enam bulan kemudian, jadi pakai itu untuk macro yang argumennya lebih dari satu.

Bila nilai argumen memuat tanda kutip, tanda kutipnya di-escape [S2]:

```
`mymacro("He said \"hello!\"")`
```

Satu nama macro boleh dipakai beberapa kali dengan jumlah argumen berbeda. Dokumentasi menyebutnya overloading: macro bisa bernama sama tetapi jumlah argumennya berbeda [S4]. Itu dipakai di bagian 2.4 untuk memberi dua cara menyebut rentang waktu.

Contoh resmi yang paling ringkas untuk memahami kegunaannya: sebuah macro `iis_search(1)` dengan definisi `sourcetype="iis" cs_username!="-" /$fragment$/ .pdf` menggantikan tiga search yang hanya berbeda pada bagian di antara dua garis miring [S3]. Tiga search menjadi satu definisi dan tiga pemanggilan.

### 1.5 Validation expression dan pesan error

Macro berargumen punya satu lubang yang khas: argumen yang bentuknya salah tidak selalu menghasilkan error. Kadang ia menghasilkan search yang sah dengan arti yang berbeda, dan itu jauh lebih berbahaya karena hasilnya terlihat normal.

Contoh resminya tajam. Macro `newrate(2)` dengan argumen `val` dan `rate`, definisi `eval new_rate=$val$*$rate$`, dan validation expression `isnum($rate$)` [S3]. Memanggilnya dengan `` `newrate(revenue, .79)` `` gagal validasi, karena `.79` tanpa nol di depan dibaca sebagai string, bukan angka; perbaikannya `` `newrate(revenue, tonumber(.79))` `` [S3]. Tanpa validasi, perkalian dengan string menghasilkan nilai kosong, dan kolom yang kosong di tengah laporan jauh lebih sulit disadari daripada pesan error.

Cara kerja validasi ada dua jalur, dan membingungkan bila tidak dipisahkan [S1][S4]:

| Bentuk validation expression | Dinyatakan lolos bila | Dinyatakan gagal bila | Pesan yang ditampilkan |
|---|---|---|---|
| Boolean, misalnya `isnum($rate$)` | hasilnya `true` | hasilnya `false` atau null | isi `errormsg` (Validation error message) |
| Bukan boolean, misalnya `validate(...)` | hasilnya null | hasilnya sebuah string | string yang dikembalikan itu sendiri |

Jalur kedua dipakai bersama fungsi `validate()`, yang menerima argumen dalam jumlah genap minimal dua, berupa pasangan kondisi dan pesan yang dikembalikan bila kondisi itu gagal [S4]. Contoh di berkas contoh resminya memeriksa dua batas sekaligus dengan pesan berbeda untuk masing-masing [S4]. Keuntungannya jelas: satu macro bisa memberi pesan yang tepat untuk setiap jenis kesalahan, bukan satu pesan umum untuk semuanya.

Satu hal yang perlu disadari: validasi berjalan terhadap teks argumen, bukan terhadap data. Ia bisa memastikan sebuah argumen berupa angka dan berada di rentang yang wajar, tetapi tidak bisa memastikan nama index yang kamu kirim memang ada.

### 1.6 Definisi berbasis eval

Kadang teks ekspansi yang kamu inginkan bergantung pada nilai argumen, bukan hanya memuatnya. Untuk itu ada `iseval`, yang di UI muncul sebagai Use eval-based definition? dan default-nya `false` [S1][S4]. Bila disetel `true`, Definition dibaca sebagai ekspresi eval, dan hasil ekspresi itulah yang menjadi teks pengganti pemanggilan macro [S1][S4].

Contoh di berkas contoh resmi: sebuah macro dua argumen dengan `iseval = true`, sehingga `fooeval(10,20)` diganti menjadi `10 + 20` [S4]. Perhatikan apa yang terjadi: yang masuk ke search bukan angka hasil hitungan, melainkan teks `10 + 20` yang kemudian dihitung oleh command yang memakainya.

Pola yang paling berguna di pekerjaan SOC adalah memilih satu di antara beberapa bentuk SPL berdasarkan argumen, misalnya memilih lebar bin waktu menurut panjang rentang (bagian 2.6). Yang perlu diingat: hasil ekspresi harus berupa string yang sah di posisi pemanggilan, jadi bagian SPL-nya ditulis sebagai string literal di dalam tanda kutip ganda, dan logikanya yang berada di luar tanda kutip.

### 1.7 Macro bersarang, dan apa yang tidak diekspansi

Macro boleh memanggil macro lain dengan sintaks yang sama [S2]. Kemampuan ini yang membuat konten detection resmi bisa dikonfigurasi di satu titik kecil tanpa menyunting puluhan search (bagian 1.9).

Empat perilaku yang perlu diketahui sebelum memakai pola ini:

- **Cycle terdeteksi dan menghasilkan error.** Berkas contoh resmi mencatat bahwa siklus pemanggilan dideteksi dan menyebabkan error [S4]. Jadi macro A yang memanggil B yang memanggil A tidak akan menggantung, tetapi juga tidak akan jalan.
- **Teks di dalam tanda kutip tidak diekspansi.** Dokumentasi menyatakan macro tidak diekspansi ketika berada di dalam nilai yang dikutip, dengan contoh `"audit`users`local"` yang membiarkan nama macro di tengahnya apa adanya [S2][S4]. Ini sering menjadi penyebab search yang tampak benar tetapi mencari string harfiah.
- **Macro yang isinya dimulai dengan generating command tidak membawa pipe-nya.** Pipe ditulis di luar macro, di dalam search [S1][S2]. Dokumentasi menyebut `from`, `search`, `metadata`, `inputlookup`, `pivot`, dan `tstats` sebagai command yang berperilaku demikian, dengan pemanggilan berbentuk `` | `mygeneratingmacro` `` [S2].
- **Ekspansi bersifat tekstual sampai akhir.** Macro bersarang diekspansi juga, dan hasil akhirnya yang di-parse. Karena itu kesalahan sintaks di macro terdalam muncul sebagai error di search terluar, tanpa menyebut macro mana yang bersalah. Bagian 1.8 adalah obatnya.

### 1.8 Melihat hasil ekspansi

Ini keahlian yang membedakan orang yang bisa memakai macro dari orang yang bisa memperbaikinya. Dari search bar di halaman Search, hasil ekspansi dibuka dengan Command-Shift-E di Mac dan Control-Shift-E di Windows atau Linux [S2][S3].

Yang ditampilkan jendela itu [S2]:

- search yang sudah diekspansi, termasuk macro bersarang dan saved search yang dirujuk;
- kemampuan menyalin bagian dari hasil ekspansi, yang berguna untuk mengisolasi bagian yang error;
- tombol Open in Search untuk menjalankan hasil ekspansi itu di jendela baru.

Contoh resminya sederhana: tulis `` `audit_searchlocal(error)` `` di search bar lalu tekan kombinasi tombol itu untuk melihat isinya tanpa menjalankan search [S3]. Kebiasaan yang layak dibangun: sebelum memasang detection dari luar, ekspansi dulu, baca hasilnya, dan baru jalankan.

Jalur kedua untuk melihat apa yang sebenarnya dijalankan adalah Job Inspector, yang memperlihatkan search setelah ekspansi macro dan optimasi otomatis (Day 14). Bedanya dengan jendela ekspansi: jendela ekspansi bisa dipakai sebelum search dijalankan, sedangkan Job Inspector memperlihatkan hasil akhir setelah search jalan, termasuk perubahan yang dilakukan optimizer.

### 1.9 Pola pemakaian ulang logika detection

Konten detection resmi Splunk, yang ditulis di repo publik `security_content` dan dikirim sebagai app ESCU, memakai macro secara sistematis. Empat polanya layak ditiru apa adanya karena masing-masing memecahkan satu masalah nyata.

**Pertama, macro sumber data.** Baris pertama detection tidak menyebut index, melainkan memanggil macro sumber data. Detection untuk pembuatan scheduled task misalnya dimulai dengan `` `wineventlog_security` ``, yang nilainya `eventtype="wineventlog_security" OR Channel="security" OR source="XmlWinEventLog:Security" OR source="WinEventLog:Security"` [S7]. Perhatikan isinya: macro itu sendiri merujuk sebuah event type (Day 17). Itu sebabnya detection resmi bisa kosong di lingkungan yang index dan event type-nya berbeda, dan itu juga jawaban untuk keluhan detection engineer PT JAB: yang perlu disesuaikan bukan search detection-nya, melainkan satu macro.

**Kedua, macro utilitas.** Hal kecil yang diulang di hampir semua detection dijadikan macro satu argumen. Contohnya `security_content_ctime`, dengan definisi `convert timeformat="%Y-%m-%dT%H:%M:%S" ctime($field$)` dan satu argumen bernama `field` [S5]. Di detection ia dipanggil dua kali untuk mengubah `firstTime` dan `lastTime` dari epoch menjadi teks yang bisa dibaca [S8].

**Ketiga, macro konfigurasi yang bersarang.** Macro `security_content_summariesonly` punya definisi yang memanggil tiga macro lain sekaligus: `summariesonly=`summariesonly_config` allow_old_summaries=`oldsummaries_config` fillnull_value=`fillnull_config`` [S6]. Masing-masing macro di dalamnya berisi satu nilai saja, misalnya `summariesonly_config` berisi `false` dan `fillnull_config` berisi `null`, dan deskripsinya menyatakan keduanya ada untuk menyetel perilaku dari dalam `security_content_summariesonly` [S6]. Hasilnya: satu keputusan lingkungan, apakah detection membaca ringkasan akselerasi saja atau tidak, diubah di satu macro berisi satu kata, dan ratusan detection mengikutinya. Arti `summariesonly` dan akselerasi data model dibahas di Day 25 dan Day 26.

**Keempat, macro filter di akhir.** Setiap detection diakhiri pemanggilan macro filter khusus untuknya, misalnya `` `winevent_scheduled_task_created_to_spawn_shell_filter` ``, yang nilainya `search *` [S7]. Halaman detection-nya menyatakan macro itu kosong secara default dan memungkinkan pengguna menyaring hasil yang merupakan false positive tanpa menyunting SPL detection-nya [S7][S8]. Keuntungannya nyata saat konten diperbarui vendor: pengecualian lokalmu hidup di objek lain, jadi tidak tertimpa. Catatan praktisnya, filter di akhir pipeline berjalan atas hasil agregasi sehingga biasanya lebih murah daripada `NOT` di awal (Day 14).

**Tanpa ES:** macro `security_content_*` ikut terpasang bersama app ESCU, yang dipasang di search head Enterprise Security; cek ketersediaan dan prasyarat versinya di Splunkbase sebelum merencanakan pemakaiannya. Di Splunk Enterprise tanpa ES, definisi macro itu tetap bisa dibaca di repo publik `security_content` dan ditulis ulang sebagai macro milikmu sendiri, seperti yang dikerjakan di bagian 2. Yang hilang tanpa ES bukan kemampuan macro-nya, melainkan paket konten yang sudah memakainya secara konsisten.

## 2. Contoh dan langkah praktis di PT JAB

Semua keluaran di bagian ini adalah keluaran ilustrasi untuk organisasi fiktif PT JAB, bukan hasil eksekusi. Asumsi data melanjutkan Day 17: empat event type otentikasi (`jab_vpn_auth`, `jab_win_auth`, `jab_linux_auth`, `jab_o365_auth`) sudah diberi tag `authentication`, perangkat POP sudah diberi tag `pop` pada field `host`, dan field `user`, `src`, serta `action` sudah bernama dan bernilai sesuai CIM. Rentang acuan sama, yaitu `earliest="10/14/2026:00:00:00"` sampai `latest="10/14/2026:08:00:00"` dalam WIB, dengan 693 kegagalan otentikasi dari 12.180 event otentikasi. Tabel berikut adalah daftar macro yang dibangun di bagian ini; cari kolom terakhir untuk melihat masalah yang diselesaikan masing-masing.

| Macro | Argumen | Masalah yang diselesaikan |
|---|---|---|
| `jab_auth` | tidak ada | Daftar index otentikasi dan tag-nya ditulis sekali |
| `jab_auth_failure` | tidak ada | Varian yang paling sering dipakai, dibangun di atas `jab_auth` |
| `jab_aset_pop` | tidak ada | Filter aset POP yang tadinya tersebar di sembilan search |
| `jab_window(1)` | `jam` | Rentang waktu yang disnap, dengan pemeriksaan nilai |
| `jab_window(2)` | `mulai`, `akhir` | Rentang absolut untuk investigasi, nama sama dengan jumlah argumen berbeda |
| `jab_top_gagal(2)` | `bidang`, `ambang` | Agregasi dan ambang brute force yang dipakai ulang |
| `jab_span(1)` | `hari` | Lebar bin yang dipilih otomatis dari panjang rentang |
| `jab_brute_force_filter` | tidak ada | Tempat menaruh pengecualian tanpa menyunting detection |

### 2.1 Macro pertama tanpa argumen

**Tujuan:** menuliskan sekali saja daftar sumber otentikasi PT JAB beserta tag-nya, supaya semua search otentikasi berangkat dari titik yang sama.

Langkahnya di UI [S1]: Settings > Advanced Search > Search macros > New, isi Destination app dengan app tim SOC, Name dengan `jab_auth`, Definition dengan isi di bawah, lalu Save.

```
(index=vpn OR index=wineventlog OR index=linux OR index=o365) tag=authentication
```

Bentuk `.conf`-nya:

```
# macros.conf
[jab_auth]
definition = (index=vpn OR index=wineventlog OR index=linux OR index=o365) tag=authentication
description = Semua event otentikasi PT JAB: empat index, dibatasi tag authentication
iseval = false
```

Pemakaiannya:

```
`jab_auth` earliest="10/14/2026:00:00:00" latest="10/14/2026:08:00:00"
| stats count BY eventtype
```

Keluaran ilustrasi:

```
eventtype          count
jab_linux_auth      599
jab_o365_auth      2787
jab_vpn_auth       1296
jab_win_auth       7498
```

**Cara membaca hasil:** total 12.180, sama dengan hasil Day 17 bagian 2.6, jadi macro ini tidak mengubah pertanyaan, hanya cara menuliskannya. Daftar index tetap dipertahankan di dalam macro walaupun `tag=authentication` saja sudah cukup secara logika, karena filter index adalah pembatas termurah dan membuat search tidak menyentuh seluruh index yang boleh dibaca role-mu (Day 14).

**Variasi:** bila suatu saat ada index otentikasi kelima, satu definisi ini yang diubah dan semua yang memanggilnya ikut berubah pada jadwal berikutnya. Itu kekuatannya, dan sekaligus alasan perubahan definisi macro perlu dicatat.

**Kapan gagal:** macro yang masih private tidak terlihat oleh rekan tim, sehingga search yang sama gagal di akun lain dengan pesan bahwa macro tidak ditemukan. Ubah permission-nya ke app atau global lebih dulu (Day 15). Bila ada macro bernama sama di app lain, yang dipakai adalah yang berlaku di konteks app tempat search dijalankan, jadi periksa Destination app sebelum menyimpulkan definisinya salah.

### 2.2 Macro bersarang

**Tujuan:** menyediakan bentuk yang paling sering dipakai, yaitu kegagalan otentikasi, tanpa menduplikasi daftar index.

```
# macros.conf
[jab_auth_failure]
definition = `jab_auth` action=failure
description = Kegagalan otentikasi di semua sumber; memanggil jab_auth
iseval = false
```

Pemakaiannya:

```
`jab_auth_failure` earliest="10/14/2026:00:00:00" latest="10/14/2026:08:00:00"
| stats count BY eventtype
```

Keluaran ilustrasi:

```
eventtype          count
jab_linux_auth      341
jab_o365_auth        54
jab_vpn_auth        212
jab_win_auth         86
```

**Cara membaca hasil:** total 693, dan keempat angkanya sama dengan rekap Day 17 bagian 2.5, sehingga dua jalur penulisan yang berbeda menghasilkan angka yang sama. Bila suatu hari dua jalur itu berbeda, yang berubah adalah definisi macro atau tag pada event type, dan keduanya bisa diperiksa.

**Variasi:** dengan pola yang sama, `jab_auth_privileged` dapat didefinisikan sebagai `` `jab_auth` tag=privileged `` untuk otentikasi akun istimewa sesuai dataset CIM (Day 17 bagian 1.7).

**Kapan gagal:** bila `jab_auth` dan `jab_auth_failure` berada di app berbeda dan salah satu tidak dibagikan, ekspansi gagal di tengah dan pesannya menyebut macro terdalam yang tidak ditemukan. Jangan membuat `jab_auth` memanggil `jab_auth_failure`: siklus seperti itu dideteksi dan menghasilkan error [S4].

### 2.3 Macro dengan satu argumen dan validasi

**Tujuan:** menyeragamkan cara menyebut rentang waktu relatif yang disnap ke awal jam, dan menolak argumen yang tidak masuk akal sebelum search jalan.

```
# macros.conf
[jab_window(1)]
args = jam
definition = earliest=-$jam$h@h latest=@h
validation = validate(isnum($jam$), "Argumen jam harus berupa angka, contoh jab_window(8)", $jam$ <= 168, "Maksimal 168 jam; untuk rentang lebih panjang pakai rentang absolut")
description = Rentang relatif sepanjang $jam$ jam, disnap ke awal jam
iseval = false
```

| Bagian | Penjelasan |
|---|---|
| `[jab_window(1)]` | Angka 1 adalah bagian dari nama; memanggil `jab_window` tanpa argumen berarti memanggil macro lain yang mungkin tidak ada [S1][S4] |
| `args = jam` | Satu nama argumen; hanya huruf, angka, garis bawah, dan tanda hubung yang diizinkan [S1][S4] |
| `$jam$` di definisi | Pola yang disubstitusi; pola ini diganti di semua tempat di dalam definisi [S4] |
| `@h` | Snap ke awal jam, supaya bin pertama dan terakhir tidak terisi sebagian (Day 01 bagian 1.5 dan Day 08) |
| `validation = validate(...)` | Ekspresi bukan boolean, jadi lolos bila hasilnya null dan gagal dengan pesan berupa string yang dikembalikan [S1][S4] |

Pemakaiannya:

```
`jab_auth_failure` `jab_window(8)`
| stats count BY eventtype
```

Keluaran ilustrasi untuk delapan jam terakhir yang disnap, dengan angka yang sama seperti bagian 2.2 bila dijalankan pada pukul 08:00 WIB:

```
eventtype          count
jab_linux_auth      341
jab_o365_auth        54
jab_vpn_auth        212
jab_win_auth         86
```

**Cara membaca hasil:** 693 kegagalan, sama dengan rentang absolut di bagian 2.2 karena jendelanya memang jendela yang sama. Ini cara memeriksa macro rentang waktu: jalankan sekali dengan rentang absolut dan sekali dengan macro, pada waktu yang membuat keduanya setara, lalu pastikan angkanya identik.

**Variasi:** memanggil dengan nama argumen, `` `jab_window(jam=8)` ``, lebih jelas dibaca dan tetap sah [S3].

**Kapan gagal:** `` `jab_window(delapan)` `` ditolak oleh pemeriksaan pertama, dan `` `jab_window(720)` `` ditolak oleh pemeriksaan kedua dengan pesan yang berbeda. Perhatian pada hal yang tidak bisa diperiksa validasi: bila search yang memanggilnya juga punya rentang di time picker, nilai di dalam search yang menang (Day 01 bagian 1.5), sehingga panel dashboard yang memakai macro ini mengabaikan input waktu pengguna. Untuk panel dashboard, jangan tanam rentang waktu di dalam macro.

### 2.4 Nama yang sama dengan jumlah argumen berbeda

**Tujuan:** menyediakan satu nama untuk dua cara menyebut rentang, karena investigasi butuh rentang absolut sementara pemantauan butuh rentang relatif.

```
# macros.conf
[jab_window(2)]
args = mulai, akhir
definition = earliest="$mulai$" latest="$akhir$"
description = Rentang absolut; format waktu mengikuti preferensi zona waktu user
iseval = false
```

Pemakaiannya:

```
`jab_auth_failure` `jab_window("10/14/2026:00:00:00", "10/14/2026:08:00:00")`
| stats count BY eventtype
```

**Cara membaca hasil:** keluarannya sama dengan bagian 2.2 karena rentangnya memang rentang itu. Yang dibuktikan di sini bukan angkanya, melainkan bahwa dua macro bisa bernama sama selama jumlah argumennya berbeda, yang di dokumentasi disebut overloading [S4].

**Kapan gagal:** memanggil dengan jumlah argumen yang tidak terdaftar, misalnya tiga argumen, berarti memanggil macro yang tidak ada, dan pesannya menyebut macro tidak ditemukan alih-alih menyebut jumlah argumen salah. Itu sumber kebingungan yang khas, jadi hitung dulu argumen di pemanggilanmu sebelum mencurigai definisinya hilang.

### 2.5 Macro dua argumen untuk agregasi dan ambang

**Tujuan:** memindahkan logika brute force yang sama, yaitu agregasi per satu field dan ambang jumlah kegagalan, ke satu tempat.

```
# macros.conf
[jab_top_gagal(2)]
args = bidang, ambang
definition = stats count AS gagal dc(user) AS user_unik values(eventtype) AS kategori BY $bidang$ | where gagal >= $ambang$ | sort - gagal
validation = isnum($ambang$)
errormsg = Ambang harus berupa angka, contoh jab_top_gagal(src, 50)
description = Agregasi kegagalan per satu field, disaring dengan ambang
iseval = false
```

Perhatikan dua hal pada definisi itu. Definisinya memuat pipe, yang sah di macro dan justru tidak mungkin di event type (Day 17 bagian 1.2). Dan definisinya tidak dimulai dengan pipe, karena pipe pertama ditulis di search yang memanggilnya.

Pemakaiannya:

```
`jab_auth_failure` `jab_window(8)`
| `jab_top_gagal(bidang=src, ambang=50)`
```

Keluaran ilustrasi:

```
src              gagal   user_unik   kategori
198.51.100.77      266           9   jab_linux_auth
203.0.113.45       180          12   jab_vpn_auth
```

**Cara membaca hasil:** dua sumber melewati ambang, sama dengan hasil Day 17 bagian 2.5, dan 266 ditambah 180 adalah 446 dari 693 kegagalan di rentang itu, sehingga 247 kegagalan sisanya tersebar di bawah ambang. Baris `198.51.100.77` dengan sembilan akun berbeda adalah pola penyemprotan akun ke bastion, bukan satu orang yang lupa password.

**Variasi 1, bidang lain:** `` `jab_top_gagal(bidang=user, ambang=20)`  `` menjawab pertanyaan yang berbeda dengan logika yang sama, yaitu akun mana yang paling banyak gagal, dan tidak perlu macro baru.

**Variasi 2, menggabungkan dengan filter aset POP:** definisikan juga

```
# macros.conf
[jab_aset_pop]
definition = tag::host=pop
description = Perangkat POP regional; keanggotaannya dirawat lewat tag, bukan daftar host
iseval = false
```

lalu pakai keduanya: `` `jab_auth_failure` `jab_aset_pop` `jab_window(8)` | `jab_top_gagal(bidang=src, ambang=10)` ``. Inilah permintaan pertama detection engineer yang terjawab. Keanggotaan POP hidup di tag (Day 17 bagian 2.4), cara memakainya hidup di macro, dan sembilan search yang tadinya menyalin daftar host kini tidak memuat satu nama host pun.

**Kapan gagal:** `` `jab_top_gagal(src, "50")`  `` lolos `isnum()` atau tidak bergantung pada bagaimana nilai itu dibaca, jadi uji sendiri bentuk argumen yang ingin kamu izinkan. Bila `bidang` diisi nama field yang tidak ada, hasilnya satu baris tanpa pengelompokan atau hasil kosong, tanpa error; validasi tidak bisa memeriksa keberadaan field. Dan ingat bahwa `user` di log Windows format klasik bisa multivalue, sehingga `dc(user)` meleset ke atas (Day 03 bagian 1.5).

### 2.6 Definisi berbasis eval

**Tujuan:** memilih lebar bin waktu secara otomatis dari panjang rentang, supaya panel rekap tidak perlu dua versi search.

```
# macros.conf
[jab_span(1)]
args = hari
definition = if($hari$ > 7, "span=1d", "span=1h")
validation = isnum($hari$)
errormsg = Argumen hari harus berupa angka
iseval = true
description = Memilih span=1d untuk rentang di atas tujuh hari, selain itu span=1h
```

| Bagian | Penjelasan |
|---|---|
| `iseval = true` | Definition dibaca sebagai ekspresi eval, dan hasilnya yang menjadi teks pengganti [S1][S4] |
| `"span=1d"` dan `"span=1h"` | Bagian SPL ditulis sebagai string literal; yang berada di luar tanda kutip hanyalah logikanya |
| `if($hari$ > 7, ...)` | Substitusi argumen terjadi sebelum ekspresi dievaluasi, jadi yang dibandingkan adalah teks yang kamu kirim |

Pemakaiannya:

```
`jab_auth_failure` `jab_window(8)`
| timechart `jab_span(1)` count AS gagal
```

Hasil ekspansinya `| timechart span=1h count AS gagal`, dan dengan `` `jab_span(30)` `` menjadi `| timechart span=1d count AS gagal`.

Keluaran ilustrasi untuk pemanggilan pertama (empat baris dari delapan):

```
_time                 gagal
2026-10-14 00:00         31
2026-10-14 01:00        104
2026-10-14 02:00         84
2026-10-14 03:00         26
```

**Cara membaca hasil:** dua bin berurutan bernilai 104 dan 84 adalah lonjakan yang sama dengan tiket SOC-2026-0217, yaitu satu rangkaian yang terbelah di batas jam, sehingga tidak ada satu bin pun yang bernilai 180 (Day 08 bagian 2.1). Delapan bin itu berjumlah 693 bila semuanya dijumlahkan, sama dengan total di bagian 2.2.

**Variasi:** pola yang sama dipakai untuk memilih bentuk lain, misalnya memilih antara `tstats` dan `stats` berdasarkan argumen. Tahan diri sebelum melakukannya: macro yang mengubah command utama membuat dua jalur eksekusi yang harus diuji dua-duanya, dan jalur yang jarang dipakai akan membusuk tanpa ada yang tahu.

**Kapan gagal:** bila ekspresi eval mengembalikan angka alih-alih string, hasil ekspansinya bukan SPL yang sah di posisi itu. Bila tanda kutip pada `"span=1d"` lupa ditulis, ekspresi eval mencari field bernama `span=1d`. Dan bila `iseval` tidak dicentang, teks `if($hari$ > 7, "span=1d", "span=1h")` masuk ke search apa adanya dan menghasilkan error sintaks yang menyesatkan.

### 2.7 Macro filter di akhir detection

**Tujuan:** menyediakan satu tempat untuk pengecualian, supaya detection-nya sendiri tidak pernah disunting karena false positive.

```
# macros.conf
[jab_brute_force_filter]
definition = search *
description = Pengecualian untuk detection brute force otentikasi; kosong secara default
iseval = false
```

Detection PT JAB lengkap menjadi:

```
`jab_auth_failure` `jab_window(8)`
| `jab_top_gagal(bidang=src, ambang=50)`
| `jab_brute_force_filter`
```

Saat scanner kerentanan internal `10.20.30.9` mulai memicu alert setiap minggu, yang diubah hanya definisi macro filternya menjadi `search NOT src="10.20.30.9"`, dan detection-nya tidak disentuh. Pola ini meniru konten resmi Splunk, yang mengakhiri setiap detection dengan macro filter bernilai `search *` dan menyatakan macro itu memungkinkan pengguna menyaring false positive tanpa menyunting SPL [S7][S8].

**Cara membaca hasil:** setelah pengecualian itu aktif, baris `10.20.30.9` hilang dari keluaran dan dua baris di bagian 2.5 tetap ada. Jumlah baris yang hilang adalah ukuran berapa banyak kebisingan yang disumbang satu host, dan angka itu layak dicatat di tiket perubahan.

**Kapan gagal:** macro filter yang diisi terlalu luas, misalnya mengecualikan seluruh blok alamat internal, mematikan detection tanpa jejak di detection-nya. Karena itu isi macro filter diperlakukan sebagai daftar pengecualian yang punya pemilik dan ditinjau berkala, dan untuk pengecualian yang panjang lookup lebih tepat daripada daftar di dalam definisi (Day 12). Perhatikan juga bahwa `search` di dalam definisi itu wajib karena macro dipanggil di tengah pipeline.

### 2.8 Membaca ekspansi dan menelusuri perubahan

**Tujuan:** melihat search yang sebenarnya dijalankan, dan mengisolasi macro mana yang bersalah ketika search gagal.

Langkahnya: tulis search di search bar tanpa menjalankannya, lalu tekan Control-Shift-E di Windows atau Linux, atau Command-Shift-E di Mac [S2][S3].

Untuk search bagian 2.7, hasil ekspansi ilustrasinya:

```
(index=vpn OR index=wineventlog OR index=linux OR index=o365) tag=authentication action=failure
earliest=-8h@h latest=@h
| stats count AS gagal dc(user) AS user_unik values(eventtype) AS kategori BY src
| where gagal >= 50
| sort - gagal
| search *
```

| Yang kamu periksa di hasil ekspansi | Kenapa |
|---|---|
| Apakah semua tanda petik miring sudah hilang | Nama macro yang tersisa berarti macro itu tidak ditemukan di konteks app ini |
| Apakah daftar index sesuai harapan | Memastikan `jab_auth` yang terpakai adalah yang kamu pikir, bukan macro bernama sama di app lain |
| Apakah argumen tersubstitusi dengan benar | `earliest=-8h@h` membuktikan `$jam$` terisi 8, bukan kosong |
| Apakah ada macro yang tidak diekspansi di dalam tanda kutip | Macro di dalam nilai yang dikutip memang tidak diekspansi [S2] |
| Apakah pipe berada di tempat yang kamu maksud | Macro tidak membawa pipe-nya sendiri untuk generating command [S1][S2] |

**Variasi:** tombol Open in Search menjalankan hasil ekspansi di jendela baru [S2], dan itu cara tercepat memisahkan masalah macro dari masalah SPL. Bila versi ekspansi jalan dan versi bermacro tidak, masalahnya ada di pemanggilan atau permission macro. Bila keduanya gagal dengan pesan sama, masalahnya ada di SPL hasil ekspansi.

**Kapan gagal:** jendela ekspansi memperlihatkan definisi yang berlaku saat itu, bukan definisi yang dipakai sebuah alert ketika ia berjalan tengah malam. Untuk menelusuri hasil alert yang sudah lewat, cocokkan waktu perubahan definisi macro dengan waktu alert itu, dan periksa Job Inspector dari job yang bersangkutan bila masih tersimpan (Day 14 dan Day 01 bagian 1.7).

### 2.9 Membaca macro di detection resmi yang hasilnya kosong

Keluhan kedua detection engineer PT JAB bisa diselesaikan dalam empat langkah, dan ini alur yang akan kamu pakai berulang kali setiap memasang konten dari luar.

Detection yang dimaksud adalah pendeteksi pembuatan scheduled task yang menjalankan shell, dengan SPL seperti ini [S7]:

```
`wineventlog_security` EventCode=4698 TaskContent IN ("*powershell.exe*", "*cmd.exe*", "*wscript.exe*", "*cscript.exe*")
| stats count min(_time) AS firstTime max(_time) AS lastTime BY Computer, TaskName, TaskContent
| rename Computer AS dest
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| `winevent_scheduled_task_created_to_spawn_shell_filter`
```

Langkah 1, ekspansi dulu. Tekan Control-Shift-E dan lihat mana yang tidak terekspansi. Bila `wineventlog_security` tetap muncul sebagai nama macro, ia belum ada di lingkunganmu.

Langkah 2, cari nilainya di sumber resmi. Halaman detection mencantumkan nilai macro yang dipakainya: `wineventlog_security` bernilai `eventtype="wineventlog_security" OR Channel="security" OR source="XmlWinEventLog:Security" OR source="WinEventLog:Security"` [S7], dan `security_content_ctime` bernilai `convert timeformat="%Y-%m-%dT%H:%M:%S" ctime($field$)` dengan satu argumen [S5][S8].

Langkah 3, sesuaikan macro sumber datanya ke lingkunganmu, bukan detection-nya. Di PT JAB, log Windows Security masuk ke `index=wineventlog` dengan sourcetype dari add-on Windows (Day 03), jadi definisinya menjadi:

```
# macros.conf
[wineventlog_security]
definition = index=wineventlog (source="XmlWinEventLog:Security" OR source="WinEventLog:Security")
description = Sumber log Windows Security di PT JAB; disesuaikan dari definisi ESCU
iseval = false
```

Langkah 4, sediakan macro utilitas dan macro filternya. `security_content_ctime(1)` ditulis ulang persis seperti definisi aslinya, dan macro filter detection itu dibuat dengan definisi `search *` supaya detection-nya jalan tanpa pengecualian lebih dulu [S7].

Keluaran ilustrasi setelah keempat langkah itu, pada rentang sebulan di PT JAB:

```
dest          TaskName              TaskContent                        count   firstTime             lastTime
JKT-FS01      \Microsoft\Sync       ...powershell.exe -enc...              2    2026-10-02T03:14:07   2026-10-09T03:14:11
JKT-WS-0417   \UpdateHelper         ...cmd.exe /c ...                      1    2026-10-11T22:05:44   2026-10-11T22:05:44
```

**Cara membaca hasil:** dua baris, tiga event. Kolom `firstTime` dan `lastTime` sudah berbentuk teks, bukan epoch, dan itu hasil kerja `security_content_ctime`. Baris `JKT-FS01` yang muncul dua kali dengan jarak tujuh hari pada jam yang hampir sama adalah pola terjadwal, yang bisa berarti otomasi sah maupun persistence; 4698 dan cara memeriksanya dibahas di Day 03.

**Kapan gagal:** bila add-on Windows tidak terpasang, `TaskContent` dan `TaskName` tidak terekstraksi dan detection ini mengembalikan nol baris walaupun event 4698 ada. Bila macro sumber data didefinisikan terlalu luas, misalnya tanpa pembatas index, detection ini membaca seluruh index yang boleh dibaca role-nya dan menjadi mahal. Dan bila nama macro filter ditulis berbeda satu karakter dari yang dipanggil detection, ekspansinya gagal di baris terakhir setelah seluruh agregasi selesai dihitung.

## 3. Lab praktik (di VM lab terisolasi)

Lab memakai data sintetis dari `makeresults` untuk memeriksa perilaku dengan angka yang bisa dihitung sendiri, ditambah log dari VM lab-mu atau BOTS v1. BOTS v1 adalah dataset statis, jadi tentukan dulu rentang absolutnya seperti di Day 01 bagian 2.5.

1. **Macro pertama dan ekspansinya.** Buat macro tanpa argumen bernama `lab_src` berisi filter index dan sourcetype yang ada di lab-mu. Jalankan `` `lab_src` | stats count ``, lalu tekan kombinasi tombol ekspansi dan salin hasilnya ke catatan. Bandingkan hasil ekspansi dengan definisi yang kamu tulis, karakter per karakter.
2. **Macro dengan satu argumen.** Buat `lab_window(1)` seperti bagian 2.3, lengkap dengan validasi. Jalankan dengan argumen angka, lalu dengan argumen kata, lalu dengan angka di luar batas. Catat tiga pesan yang muncul dan dari jalur validasi mana masing-masing datang.
3. **Dua jalur validasi.** Ubah `lab_window(1)` supaya memakai validasi boolean `isnum($jam$)` dengan `errormsg`, lalu kembalikan ke `validate()` dengan dua pasangan kondisi. Catat beda pesan yang muncul untuk argumen yang sama, dan tulis satu kalimat kapan masing-masing lebih berguna.
4. **Hitung dulu, baru jalankan.** Jalankan rangkaian berikut dan hitung hasil yang kamu harapkan sebelum menekan enter:

   ```
   | makeresults count=120
   | streamstats count AS n
   | eval _time=strptime("2026-10-07 00:00:00","%Y-%m-%d %H:%M:%S") + (n-1)*600
   | eval src="10.20.30.".(n%4), user="akun".(n%7), action="failure", eventtype="lab_auth"
   | `lab_top_gagal(bidang=src, ambang=25)`
   ```

   Dengan 120 event berjarak sepuluh menit dan `n%4`, keempat nilai `src` masing-masing mendapat 30 event, jadi keempat baris lolos ambang 25. Buktikan dulu dengan tangan, lalu cocokkan, lalu naikkan ambang ke 31 dan pastikan hasilnya kosong.
5. **Macro bersarang dan siklus.** Buat `lab_fail` yang memanggil `lab_src`, buktikan jalan, lalu sengaja ubah `lab_src` supaya memanggil `lab_fail`. Catat pesan error yang muncul dan kembalikan definisinya.
6. **Apa yang tidak diekspansi.** Jalankan search yang memuat nama macro di dalam tanda kutip ganda, misalnya `| eval catatan="nilai `lab_src` di sini"`. Catat apa yang terjadi pada nilai field itu, dan tulis satu kalimat kenapa.
7. **Generating command.** Buat macro yang definisinya dimulai dengan `tstats` atau `inputlookup` tanpa pipe di depan, lalu panggil dengan pipe di luar. Catat pesan yang muncul bila pipe ditulis di dua tempat sekaligus, dan bila tidak ditulis sama sekali.
8. **Definisi berbasis eval.** Buat `lab_span(1)` seperti bagian 2.6 dan jalankan dengan argumen 3 lalu 30. Baca hasil ekspansi untuk keduanya dan catat perbedaannya. Lalu hilangkan centang eval-based dan catat error yang muncul.
9. **Overloading.** Buat `lab_window(2)` dengan dua argumen, lalu panggil dengan satu, dua, dan tiga argumen. Catat ketiga hasilnya, termasuk bentuk pesan ketika jumlah argumennya tidak terdaftar.
10. **Membaca konten resmi.** Ambil satu detection dari repo publik Splunk yang dimulai dengan macro sumber data, tulis ulang macro-nya supaya menunjuk index dan source di lab-mu, sediakan macro filternya dengan definisi `search *`, lalu jalankan. Catat berapa macro yang harus kamu definisikan sebelum detection itu berjalan.
11. **Dampak perubahan.** Catat berapa objek yang memanggil `lab_src` (search tersimpan, report, alert, panel), lalu ubah definisinya dan jalankan ulang semuanya. Tulis satu kalimat tentang apa yang akan terjadi bila perubahan itu dilakukan tanpa catatan dan tanpa pemberitahuan ke tim.

**Hasil yang sebaiknya tersimpan:**
- Isi `macros.conf` lab-mu, sebagai cikal bakal add-on kecil milik sendiri bersama `eventtypes.conf` dan `tags.conf` dari Day 17.
- Tiga pesan validasi dari langkah 2 dan beda pesan dari langkah 3.
- Hasil hitungan tangan dari langkah 4 beserta keluaran yang cocok dengannya.
- Pesan error siklus dari langkah 5 dan pesan generating command dari langkah 7.
- Dua hasil ekspansi dari langkah 8.
- Daftar macro yang harus didefinisikan di langkah 10.

**Variasi tantangan:** susun satu detection PT JAB lengkap dari empat macro (sumber, rentang, agregasi, filter) dan satu dari search mentah tanpa macro, lalu jalankan keduanya dan buktikan hasilnya identik. Setelah itu ubah satu ambang: di versi bermacro di satu tempat, di versi mentah di search itu sendiri. Ukur mana yang lebih cepat dan tulis apa yang akan terjadi bila ada sembilan versi mentah, seperti keadaan PT JAB sebelum Day ini.

## 4. Troubleshooting

Tabel ini memuat gejala yang paling sering muncul saat memakai macro. Cari gejalanya di kolom pertama.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Pesan bahwa macro tidak ditemukan | Macro belum dibagikan, atau berada di app lain, atau jumlah argumen di pemanggilan tidak terdaftar [S1][S4] | Periksa permission (Day 15), Destination app, dan hitung argumen di pemanggilan |
| Macro yang dipanggil tiga argumen gagal padahal definisinya ada | Nama macro berargumen memuat jumlah argumennya [S1][S4] | Buat stanza untuk jumlah argumen itu, atau perbaiki pemanggilannya |
| Nama macro muncul apa adanya di hasil | Pemanggilan berada di dalam nilai yang dikutip, yang tidak diekspansi [S2][S4] | Keluarkan pemanggilan dari tanda kutip, atau susun nilainya dengan penggabungan string |
| Error sintaks di search yang tidak menyebut macro apa pun | Kesalahan ada di definisi macro, dan yang di-parse adalah hasil ekspansi | Tekan Control-Shift-E atau Command-Shift-E, lalu Open in Search untuk mengisolasi [S2] |
| Macro bernama `nama-macro` tidak jalan | App Search tidak mendukung tanda hubung di nama macro [S2] | Ganti ke garis bawah |
| Definisi dengan `tstats` menghasilkan error | Generating command butuh pipe di luar macro, bukan di dalam definisi [S1][S2] | Hapus pipe dari definisi dan tulis `\| ` + pemanggilan di search |
| Validasi tidak pernah menolak apa pun | Ekspresi bukan boolean dan hasilnya null, yang berarti lolos [S1][S4] | Pastikan `validate()` mengembalikan string saat kondisi gagal |
| Validasi selalu menolak | Ekspresi boolean mengembalikan null, yang dihitung gagal [S1][S4] | Periksa fungsi di dalamnya terhadap argumen yang kosong |
| Hasil kolom kosong tanpa error | Argumen dibaca sebagai string padahal dimaksudkan angka [S3] | Tambahkan validasi `isnum()`, dan bungkus nilai dengan `tonumber()` saat memanggil |
| Error siklus saat menyimpan atau menjalankan | Macro memanggil macro yang memanggilnya kembali [S4] | Putus salah satu rantainya |
| Ekspansi memperlihatkan definisi yang berbeda dari yang kamu sunting | Ada macro bernama sama di app lain, atau yang kamu sunting berada di app lain | Periksa Destination app pada kedua definisi |
| Panel dashboard mengabaikan input waktu pengguna | Rentang waktu ditanam di dalam macro, dan rentang di dalam search menang | Keluarkan rentang dari macro untuk panel dashboard (Day 01 bagian 1.5) |
| Alert tiba-tiba berubah perilaku tanpa ada yang menyuntingnya | Definisi macro yang dipanggilnya diubah | Cocokkan waktu perubahan definisi dengan waktu alert, dan perlakukan macro bersama sebagai perubahan konfigurasi |
| Detection dari luar mengembalikan nol baris | Macro sumber datanya belum disesuaikan ke index, source, dan event type lingkunganmu [S7] | Ekspansi dulu, lalu definisikan macro sumber data dan macro filternya (bagian 2.9) |

## 5. Kesalahan umum dan jebakan

- Mengubah definisi macro yang dipakai banyak objek tanpa catatan dan tanpa pemberitahuan. Semua report, alert, dan detection yang memanggilnya ikut berubah pada jadwal berikutnya, dan tidak ada satu pun di antaranya yang tercatat sebagai berubah.
- Memasang detection dari luar tanpa membaca hasil ekspansinya lebih dulu. Baris pertama detection resmi biasanya memanggil macro sumber data yang harus disesuaikan [S7].
- Lupa menambahkan jumlah argumen ke nama macro. `mymacro` dan `mymacro(2)` adalah dua macro yang berbeda [S1][S4].
- Menaruh pemanggilan macro di dalam tanda kutip ganda dan mengharapkannya diekspansi [S2][S4].
- Menulis pipe di dalam definisi macro yang isinya generating command. Pipe-nya ditulis di search yang memanggilnya [S1][S2].
- Mengandalkan validasi untuk hal yang tidak bisa diperiksanya. Validasi memeriksa teks argumen, bukan keberadaan index, field, atau lookup.
- Mencampur dua jalur validasi. Ekspresi boolean gagal bila hasilnya `false` atau null, sedangkan ekspresi bukan boolean lolos bila hasilnya null [S1][S4].
- Memakai tanda hubung di nama macro. App Search tidak mendukungnya [S2].
- Menanam rentang waktu di dalam macro lalu memakainya di panel dashboard, sehingga input waktu pengguna diabaikan.
- Memakai macro untuk hal yang seharusnya event type. Kriteria yang menentukan arti sebuah event sebaiknya menjadi event type supaya ikut menentukan keanggotaan data model (Day 17); macro tidak terlihat oleh data model sama sekali.
- Membuat macro berlapis terlalu dalam hanya karena bisa. Setiap lapisan menambah satu tempat yang harus dibuka saat menelusuri masalah, dan pesan error tidak menyebut lapisan mana yang bersalah.
- Mengisi macro filter dengan pengecualian yang terlalu luas. Detection menjadi diam tanpa jejak di detection-nya sendiri.
- Menyimpan daftar pengecualian yang panjang di dalam definisi macro. Daftar yang tumbuh sebaiknya menjadi lookup dengan pemilik dan jadwal pembaruan (Day 12).
- Menganggap `.79` sama dengan `0.79` saat mengirim argumen angka. Contoh resmi memperlihatkan nilai tanpa nol di depan dibaca sebagai string [S3].
- Membuat macro private lalu memasang alert terjadwal yang memanggilnya. Bila pemiliknya keluar, objeknya menjadi yatim dan alert-nya berhenti (Day 09 bagian 1.6).

## 6. Catatan terkini

Bagian ini menampung detail versi dan ketidakcocokan antar halaman dokumentasi. Isinya tidak mengubah cara kerja, tetapi menjelaskan kenapa dua halaman resmi bisa terasa bertentangan.

- Dua pernyataan soal tanda kutip perlu dibaca sebagai dua hal berbeda. Spesifikasi `macros.conf` menyatakan pola `$<arg>$` diganti secara global di dalam string definisi, termasuk di dalam tanda kutip [S4], sementara halaman pemakaian menyatakan macro tidak diekspansi ketika pemanggilannya berada di dalam nilai yang dikutip [S2]. Yang pertama tentang substitusi argumen di dalam definisi; yang kedua tentang pemanggilan macro di dalam search.
- Penulisan nama menu berbeda antar halaman: ada yang menulis Settings > Advanced Search > Search macros dan ada yang menulis Advanced search [S1]. Letaknya sama.
- Fungsi `validate()` dijelaskan di berkas contoh `macros.conf` dan menerima argumen dalam jumlah genap minimal dua [S4]. Karena penjelasannya ada di berkas contoh, bukan di halaman UI, periksa perilakunya di versi-mu sebelum memakainya pada macro yang dipakai banyak detection.
- Nama argumen boleh memuat tanda hubung menurut aturan nama argumen [S1][S4], sementara nama macro tidak boleh [S2]. Untuk mengurangi kebingungan, pakai garis bawah di keduanya.
- Macro `security_content_ctime` dan `security_content_summariesonly` di repo `security_content` keduanya tercatat versi 1 dengan tanggal modifikasi 2026-05-13 [S5][S6]. Nilai `summariesonly_config` saat diperiksa adalah `false` dan `fillnull_config` adalah `null` [S6]; nilai itu memang dimaksudkan untuk diubah per lingkungan, jadi jangan menganggapnya tetap.
- Halaman detection di research.splunk.com mencantumkan nilai macro yang dipakainya, tetapi tidak selalu lengkap: satu halaman mencantumkan `wineventlog_security` dan macro filternya tanpa mencantumkan `security_content_ctime` [S7], sementara halaman lain mencantumkan nilai `security_content_ctime` [S8]. Bila sebuah macro tidak tercantum, cari definisinya di repo publik.
- Dokumentasi resmi kini di help.splunk.com, dan tautan docs.splunk.com lama masih beredar untuk halaman yang sama.

## 7. Cheat sheet

```
MEMBUAT
  Settings > Advanced Search > Search macros > New
  Kolom: Destination app, Name, Definition, Use eval-based definition?,
         Arguments, Validation expression, Validation error message

NAMA DAN PEMANGGILAN
  tanpa argumen   : [jab_auth]            dipanggil `jab_auth`
  dua argumen     : [jab_window(2)]       dipanggil `jab_window("...","...")`
  nama argumen    : `jab_top_gagal(bidang=src, ambang=50)`
  escape kutip    : `mymacro("He said \"hello!\"")`
  generating cmd  : pipe di luar macro -> | `jab_tstats_auth`
  tanda hubung di nama macro: TIDAK didukung app Search
  di dalam tanda kutip ganda: TIDAK diekspansi

macros.conf
  [jab_window(1)]
  args = jam
  definition = earliest=-$jam$h@h latest=@h
  validation = isnum($jam$)            boolean: lolos true, gagal false atau null
  errormsg = Argumen jam harus angka   dipakai untuk validasi boolean
  iseval = false                       true berarti definition adalah ekspresi eval
  description = ...

VALIDASI
  boolean       isnum($jam$)                         gagal -> errormsg
  bukan boolean validate(kondisi1,"pesan1",kondisi2,"pesan2")
                lolos bila null, gagal bila mengembalikan string (pesan itu sendiri)

EVAL-BASED (iseval = true)
  definition = if($hari$ > 7, "span=1d", "span=1h")
  `jab_span(30)` -> span=1d          hasil ekspresi menjadi teks ekspansi

MELIHAT EKSPANSI
  Control-Shift-E (Windows, Linux)   Command-Shift-E (Mac)
  memperlihatkan macro bersarang dan saved search; tombol Open in Search
  Job Inspector memperlihatkan search yang benar-benar dijalankan

POLA KONTEN RESMI
  `wineventlog_security`            macro sumber data, sesuaikan ke lingkungan
  `security_content_ctime(field)`   convert timeformat="%Y-%m-%dT%H:%M:%S" ctime($field$)
  `security_content_summariesonly`  bersarang ke summariesonly_config,
                                    oldsummaries_config, fillnull_config
  `<nama_detection>_filter`         search *   tempat pengecualian lokal
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Rekanmu membuat macro bernama `jab_window` dengan satu argumen bernama `jam`, lalu memanggilnya dengan `` `jab_window(8)` `` dan mendapat pesan bahwa macro tidak ditemukan. Definisinya jelas ada di Settings. Apa yang terjadi?

<details><summary>Jawaban</summary>

Nama macro berargumen harus memuat jumlah argumennya, jadi yang terdaftar seharusnya `jab_window(1)`, bukan `jab_window`. Angka itu bagian dari identitas macro: `jab_window` dan `jab_window(1)` adalah dua objek berbeda, dan memanggil dengan satu argumen berarti mencari yang kedua. Pesan yang muncul menyebut macro tidak ditemukan, bukan menyebut jumlah argumen salah, dan itulah yang membuat gejala ini membingungkan. Lihat bagian 1.4 dan 2.3.

</details>

**2. Skenario keputusan.** Sebuah alert terjadwal yang sudah berjalan tenang selama tiga bulan tiba-tiba mengirim 40 notifikasi dalam satu malam. Tidak ada yang menyunting alert itu. Apa langkah pertamamu?

- A. Naikkan throttle alert itu supaya notifikasinya berkurang, lalu selidiki besok.
- B. Ekspansi search alert itu, bandingkan hasil ekspansi dengan yang kamu harapkan, dan periksa apakah definisi macro yang dipanggilnya berubah.
- C. Nonaktifkan alert itu karena jelas rusak, dan tulis ulang search-nya tanpa macro supaya tidak terjadi lagi.

<details><summary>Jawaban</summary>

B. Alert yang isinya memanggil macro tidak menyimpan salinan definisi macro itu, sehingga perubahan satu definisi mengubah perilaku semua objek yang memanggilnya tanpa salah satu pun tercatat berubah. Ekspansi memperlihatkan search yang sebenarnya berjalan, termasuk macro bersarang, dan itu cara tercepat memisahkan perubahan definisi dari perubahan data. A menyembunyikan gejala dan menunda jawabannya, dan bila penyebabnya memang perubahan definisi, throttle hanya mengurangi notifikasi dari search yang salah. C membuang keuntungan utama macro dan mengembalikan masalah awal, yaitu logika yang sama tersebar di banyak tempat. Lihat bagian 1.1, 1.8, dan 2.8.

</details>

**3. Pertanyaan jebakan.** Untuk menulis catatan otomatis di hasil search, rekanmu memakai `| eval catatan="sumber: `jab_auth`"`. Apa yang masuk ke field `catatan`?

<details><summary>Jawaban</summary>

Teks harfiah berisi nama macro beserta tanda petik miringnya, bukan isi definisinya, karena macro tidak diekspansi ketika pemanggilannya berada di dalam nilai yang dikutip. Dokumentasi menyatakannya dengan contoh serupa. Bila yang kamu inginkan memang isi definisi di dalam string, susun nilainya di luar tanda kutip lalu gabungkan, dan ingat bahwa isi `jab_auth` adalah kriteria search, bukan kalimat yang pantas dibaca manusia di dalam tiket. Lihat bagian 1.7.

</details>

**4. Jelaskan ulang.** Jelaskan kepada analyst L1 PT JAB dalam tiga kalimat apa bedanya macro dan event type, dan kenapa keduanya tidak saling menggantikan.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Event type itu kriteria yang bisa dinilai untuk satu event, dan hasilnya menempel ke event itu sebagai label, jadi isinya tidak boleh ada pipe dan tidak boleh ada subsearch. Macro itu teks SPL yang kita simpan dan ditempel kembali ke search sebelum search jalan, jadi isinya bisa apa saja, termasuk pipe, `stats`, dan ambang. Keduanya tidak saling menggantikan karena label dari event type itu yang dipakai tag dan data model untuk memilih event mana yang masuk, sedangkan macro tidak terlihat oleh data model sama sekali dan hanya menolong kita berhenti menyalin logika yang sama ke banyak search."

Kesalahan yang sering muncul:
- Menyebut macro sebagai "event type yang lebih fleksibel", sehingga peran event type di data model hilang.
- Lupa menyebut bahwa macro selesai sebelum search jalan, sehingga kesan yang muncul adalah macro ikut dievaluasi per event.
- Menyebut event type bisa memuat pipe karena bentuknya mirip search.

</details>

**5. Skenario keputusan.** Kamu butuh satu macro yang dipakai di dua rentang pemantauan, mingguan dengan bin satu jam dan bulanan dengan bin satu hari. Mana yang kamu pilih?

- A. Satu macro dengan definisi berbasis eval yang memilih span dari argumen panjang rentang.
- B. Dua macro terpisah, `jab_span_jam` dan `jab_span_hari`, dan panel memilih yang sesuai.
- C. Satu macro berargumen biasa yang menerima teks span apa adanya, misalnya `jab_span(1d)`.

<details><summary>Jawaban</summary>

Ketiganya bisa jalan, dan jawaban yang bisa dipertahankan adalah A atau C dengan alasan yang jelas; yang penting adalah tahu konsekuensinya. A memusatkan keputusan di satu tempat sehingga aturan "di atas tujuh hari pakai bin harian" berlaku seragam, tetapi menambah satu jalur yang hanya aktif pada argumen tertentu dan karena itu harus diuji untuk kedua cabang. C paling sederhana dan paling mudah dibaca, tetapi memindahkan keputusan ke pemanggil, sehingga panel bisa saja memakai bin yang tidak sesuai rentangnya dan tidak ada yang mencegahnya. B adalah pilihan yang paling lemah di antara ketiganya: dua objek untuk satu keputusan berarti dua tempat yang bisa menyimpang, dan itu persis masalah yang membuat PT JAB mulai memakai macro. Lihat bagian 1.6 dan 2.6.

</details>

**6. Pertanyaan jebakan.** Sebuah macro berisi `tstats count from datamodel=Authentication by Authentication.src`. Rekanmu memanggilnya dengan `` `jab_tstats_auth` | sort - count `` dan mendapat error. Apa yang kurang?

<details><summary>Jawaban</summary>

Pipe di depan pemanggilan. Macro yang isinya dimulai dengan generating command seperti `tstats`, `inputlookup`, `metadata`, `pivot`, atau `from` tidak membawa pipe-nya sendiri: pipe ditulis di search, di luar macro, sehingga pemanggilannya menjadi `` | `jab_tstats_auth` | sort - count ``. Dokumentasi menyarankan justru tidak menulis pipe di dalam definisi, supaya macro itu tetap jelas sebagai awal pipeline. Lihat bagian 1.7 dan tabel Troubleshooting.

</details>

**7. Interview question (English).** "Your team has twelve detections that share the same filtering logic. How would you stop maintaining twelve copies, and what are the risks of the approach you choose?"

<details><summary>Sample answer</summary>

"I would pull the shared parts into search macros: one for the data sources, one for the time window, one for the aggregation and threshold, and an empty filter macro at the end of each detection for local exceptions. That is the pattern Splunk's own detection content uses, where the first line is a data source macro and the last line is a `<detection>_filter` macro that is just `search *`, so analysts tune out false positives without touching the detection SPL, and the tuning survives a content update. The risks are real and worth saying out loud. A macro is text substitution, so one typo propagates to every object that calls it, and none of those objects shows up as modified, which means a scheduled alert can change behaviour overnight with nobody having edited it. So I treat shared macros as configuration: an owner, a description on every macro, a change note, and a check run after every edit. I also use validation expressions on any macro that takes an argument, because a bad argument often does not error, it just quietly produces an empty column. And before I ship anything that calls macros, I expand it in the search bar with Control-Shift-E and read what actually runs, nested macros included."

What makes this answer strong: it names a concrete decomposition rather than "use macros", borrows a pattern from vendor content and explains why that pattern survives updates, states the blast radius of text substitution honestly, and closes with two habits that catch the specific failure modes: validation for silent bad arguments, and expansion review for silent wrong SPL.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Splunk Enterprise 10.6 Knowledge Manager Manual: Define search macros in Settings | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/search-macros/define-search-macros-in-settings | primer | diakses 2026-10-14 | Tinggi. Jalur Settings > Advanced Search > Search macros, seluruh kolom form, aturan penambahan jumlah argumen ke nama, aturan nama argumen, `$arg$`, dua jalur validasi, catatan generating command tanpa pipe di definisi, penyimpanan ke `macros.conf` |
| S2 | Splunk Enterprise 10.6 Knowledge Manager Manual: Use search macros in searches | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/search-macros/use-search-macros-in-searches | primer | diakses 2026-10-14 | Tinggi. Tanda petik miring, macro bersarang, macro tidak diekspansi di dalam nilai yang dikutip, larangan tanda hubung di nama macro, daftar generating command dan pemanggilannya dengan pipe di luar, escape tanda kutip pada argumen, kombinasi tombol ekspansi dan tombol Open in Search |
| S3 | Splunk Enterprise 10.6 Knowledge Manager Manual: Search macro examples | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/search-macros/search-macro-examples | primer | diakses 2026-10-14 | Tinggi. Contoh `iis_search(1)` dengan `$fragment$`, pemanggilan dengan nama argumen, contoh macro `transaction`, contoh `newrate(2)` dengan validasi `isnum($rate$)` beserta kasus `.79` yang dibaca sebagai string dan perbaikannya dengan `tonumber()`, contoh melihat ekspansi `audit_searchlocal(error)` |
| S4 | Splunk Enterprise 10.6 Admin Manual: macros.conf | https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.6/configuration-file-reference/10.6.0-configuration-file-reference/macros.conf | primer | diakses 2026-10-14 | Tinggi. Format stanza dengan dan tanpa jumlah argumen, overloading, `args`, `definition` dan substitusi global `$<arg>$`, `validation`, `errormsg`, `iseval` default `false`, `description`, fungsi `validate()` dengan argumen berjumlah genap minimal dua, contoh `iseval` yang menghasilkan `10 + 20`, catatan deteksi siklus |
| S5 | Repo security_content: macros/security_content_ctime.yml | https://raw.githubusercontent.com/splunk/security_content/develop/macros/security_content_ctime.yml | primer | modifikasi tercatat 2026-05-13; diakses 2026-10-14 | Tinggi. Definisi `convert timeformat="%Y-%m-%dT%H:%M:%S" ctime($field$)` dengan satu argumen bernama `field` |
| S6 | Repo security_content: macros/security_content_summariesonly.yml beserta summariesonly_config.yml dan fillnull_config.yml | https://raw.githubusercontent.com/splunk/security_content/develop/macros/security_content_summariesonly.yml | primer | modifikasi tercatat 2026-05-13; diakses 2026-10-14 | Tinggi. Definisi bersarang ke tiga macro konfigurasi; nilai `summariesonly_config` adalah `false` dan `fillnull_config` adalah `null` saat diperiksa |
| S7 | Splunk Threat Research: WinEvent Scheduled Task Created to Spawn Shell | https://research.splunk.com/endpoint/203ef0ea-9bd8-11eb-8201-acde48001122/ | primer | diakses 2026-10-14 | Tinggi. SPL detection lengkap, nilai macro `wineventlog_security`, macro filter bernilai `search *` beserta keterangan bahwa ia kosong secara default dan dipakai menyaring false positive tanpa menyunting SPL |
| S8 | Splunk Threat Research: Detect New Local Admin account | https://research.splunk.com/endpoint/b25f6f62-0712-43c1-b203-083231ffd97d/ | primer | diakses 2026-10-14 | Tinggi. Contoh pemakaian `security_content_ctime` dua kali pada `firstTime` dan `lastTime`, nilai macro itu, dan macro filter di akhir detection |

**Catatan sumber:** semua keluaran di bagian 2 adalah keluaran ilustrasi yang angkanya disusun agar konsisten dengan Day 17 dan bisa dijumlahkan ulang (693 kegagalan dari 12.180 event otentikasi), bukan hasil eksekusi. Perbedaan antara substitusi argumen yang berlaku di dalam tanda kutip pada definisi [S4] dan pemanggilan macro yang tidak diekspansi di dalam nilai yang dikutip [S2] adalah dua pernyataan dari dua halaman berbeda yang keduanya benar untuk konteksnya masing-masing; perilaku persisnya layak dibuktikan di lab seperti langkah 6 di bagian 3. Nilai macro konfigurasi di repo `security_content` memang dimaksudkan berubah per lingkungan [S6], jadi nilai yang tercatat di sini adalah keadaan saat pemeriksaan. Definisi `wineventlog_security` versi PT JAB di bagian 2.9 adalah penyesuaian lingkungan, bukan nilai resmi; nilai resminya ada di [S7].
