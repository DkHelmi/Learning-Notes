---
day: 17
title: 'Event type dan tag: label kategori supaya satu detection jalan di semua sumber log'
researched_on: 2026-10-14
versions_checked: 'Splunk Enterprise 10.6 (Knowledge Manager Manual: About event types, Define event types in Splunk Web, About event type priorities, Automatically find and build event types, About tags and aliases, Define and manage tags in Settings, Tag event types; Admin Manual: eventtypes.conf, tags.conf; Search Reference: tags, findtypes); CIM 6.4 (Authentication data model); ES 8.7.0'
---

# Day 17: Event type dan tag

Cakupan: membuat event type dari sebuah search beserta priority dan warnanya, batasan isi search sebuah event type, memberi tag pada pasangan field dan value maupun pada event type, dan peran tag sebagai penentu event mana yang masuk data model CIM.

## Ide inti

Event type adalah kriteria search yang disimpan dan menempel sebagai label pada setiap event yang cocok dengannya. Tag adalah nama kategori yang ditempelkan ke sebuah pasangan field dan value, atau ke sebuah event type. Keduanya tidak mengubah satu byte pun data yang sudah tersimpan: keduanya dihitung saat search dijalankan, dan keduanya bisa dihapus atau diperbaiki besok pagi tanpa re-ingest. Yang membuat keduanya penting bukan kenyamanan menyingkat search, melainkan satu hal yang sangat praktis: setelah empat sumber log otentikasi dari empat vendor diberi label kategori yang sama, satu detection yang ditulis sekali akan berjalan di keempatnya, termasuk di sumber kelima yang baru masuk bulan depan. Dan tag itu juga yang menentukan event mana yang masuk ke data model CIM, sehingga tag yang kurang satu membuat sebagian data tidak terlihat oleh semua detection yang dibangun di atas model itu.

Kebiasaan ini sudah kamu punya dari sistem tiket. Event type adalah filter tersimpan yang memberi label kategori ke tiket yang cocok, dan tag adalah label kategori yang bisa ditempel ke banyak hal sekaligus sehingga satu kueri menjangkau semuanya. Bedanya ada dua. Pertama, event type bukan saved search: isinya hanya kriteria pencarian, tanpa pipe dan tanpa subsearch, karena ia dievaluasi terhadap setiap event yang dikembalikan search-mu. Kedua, di sistem tiket tag hanya alat pencarian, sedangkan di Splunk tag punya pekerjaan struktural: data model CIM memakai tag sebagai constraint, jadi tag yang hilang membuat bagian data model kosong tanpa satu pesan error pun.

```
Satu event masuk pipeline search
  -> field extraction           (regex, delimiter, KV)
  -> field alias                (SourceAddress menjadi src)
  -> calculated field           (EVAL-)
  -> lookup                     (enrichment dari tabel referensi)
  -> EVENT TYPE                 setiap event type yang cocok menambah nilai ke field eventtype
  -> TAG                        tag dari pasangan field dan value, termasuk dari eventtype
  -> hasil search

Akibat urutan itu:
  search event type BOLEH memakai field hasil alias, calculated field, dan lookup
  search event type TIDAK BOLEH memakai tag (tag belum ada saat event type dievaluasi)

Jalur sebuah event masuk data model CIM:
  event -> event type cocok -> event type punya tag constraint -> field CIM bernama benar
        -> nilai field sesuai yang diharapkan -> baru terhitung di data model
```

Situasi yang dipakai sepanjang Day ini: pukul 09:30 di PT Jaringan Anak Bangsa (PT JAB, ISP menengah fiktif dengan SOC internal satu lantai dengan NOC). Tiket SOC-2026-0217, brute force VPN dari `203.0.113.45`, sudah ditutup minggu lalu. Dua hari kemudian kejadian serupa muncul di bastion Linux `jkt-bastion01` dan tidak ada alert sama sekali, karena alert brute force yang ada hanya menyaring `index=vpn`. Detection engineer menulis di kanal tim:

> "Kita punya empat sumber log otentikasi: VPN, Windows, Linux, dan sign-in Entra ID. Alert brute force kita ada tiga, isinya logika yang sama dengan index berbeda, dan satu lagi belum dibuat. Saya mau satu alert saja yang jalan di empat sumber itu dan otomatis ikut mencakup sumber kelima nanti. Sekalian: Pivot Authentication di search head ES kelihatan kurang data dibanding hasil search langsung, dan saya curiga ini soal label, bukan soal index."

Permintaan itu memuat lima pertanyaan:

1. Apa sebenarnya event type, dan apa bedanya dengan saved search atau report yang sudah kita punya?
2. Apa yang boleh dan tidak boleh ditulis di dalam search sebuah event type, dan kenapa ada batasan itu?
3. Priority dan warna di form event type itu mengatur apa, dan apakah ia memengaruhi hasil search?
4. Tag ditempel ke apa: ke nilai field, ke event type, atau keduanya, dan bagaimana mencarinya?
5. Kenapa data model bisa kurang data padahal event-nya jelas ada di index?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2 dan 1.3, pertanyaan 3 di bagian 1.4, pertanyaan 4 di bagian 1.5 dan 1.6, dan pertanyaan 5 di bagian 1.7. Bagian 2 mengerjakan seluruh permintaan itu sampai menjadi satu search detection yang berjalan di empat sumber dan satu bukti bahwa data model sudah utuh.

**Kapan relevan:** setiap kali logika yang sama ditulis ulang untuk sumber log berbeda, setiap kali kamu menyiapkan sumber data baru supaya terpakai oleh detection dan data model yang sudah ada, dan setiap kali data model atau Pivot memberi angka yang lebih kecil daripada search langsung.
**Kapan bukan jawaban:** bila yang ingin kamu pakai ulang adalah logika yang memuat pipe, `stats`, atau subsearch, event type tidak bisa menampungnya dan macro yang kamu butuhkan (Day 18). Bila yang kamu butuhkan adalah memetakan ribuan nilai ke kategori, misalnya daftar pelanggan korporat, lookup lebih tepat daripada tag. Bila masalahnya nama field berbeda antar vendor, yang kamu perlukan adalah field alias dan calculated field (Day 16), bukan tag.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dasar dari Day 01 sampai Day 14 (index, sourcetype, pipeline, `stats`, `eval`, field extraction, lookup, permission knowledge object) tidak diulang di sini. Tabel ini hanya memuat istilah yang dipakai Day ini; cari kolom padanan bila sebuah istilah terasa asing.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Event type | Kriteria search tersimpan yang memberi label kategori ke setiap event yang cocok | Filter tersimpan di sistem tiket yang menandai tiket sejenis |
| Field `eventtype` | Field hasil pencocokan event type; berisi nama event type yang cocok dan bisa multivalue | Kolom kategori di tiket yang bisa berisi lebih dari satu nilai |
| Priority event type | Angka 1 sampai 10 yang mengatur urutan tampil dan warna mana yang dipakai | Urutan prioritas kategori saat satu tiket masuk dua kategori |
| Color atau Style event type | Pita warna di sisi event saat hasil search dibuka | Warna baris di layar NOC untuk membedakan jenis alarm |
| Tag | Nama kategori yang ditempel ke pasangan field dan value atau ke event type | Label di sistem tiket yang bisa dipakai di banyak tiket |
| `tag::<field>` | Bentuk pencarian tag yang dibatasi ke satu field, misalnya `tag::host=pop` | Mencari label hanya pada kolom tertentu, bukan di semua kolom |
| `tag::eventtype` | Tag yang menempel lewat event type, bukan lewat nilai field biasa | Label yang diwarisi tiket karena kategorinya, bukan karena diberi manual |
| Constraint data model | Syarat keanggotaan sebuah dataset, di CIM umumnya berupa tag | Syarat sebuah perangkat masuk laporan bulanan tertentu |
| Dataset CIM | Satu bagian data model, misalnya Authentication dan anak-anaknya | Satu tabel di template laporan baku |
| `findtypes` | Command yang menyarankan kandidat event type dari hasil search | Script yang mengusulkan pengelompokan alarm dari log mentah |
| Build Event Type | Utilitas di menu event untuk menyusun event type dari satu event contoh | Membuat filter baru dengan mengklik nilai di satu tiket contoh |
| Command `tags` | Command SPL yang menampilkan tag yang menempel pada field di hasil search | Perintah untuk melihat label apa saja yang menempel pada satu objek |

### 1.1 Event type: kriteria yang menempel sebagai label

Masalah PT JAB bukan kekurangan search. Masalahnya tiga alert dengan logika identik dan index berbeda, yang berarti tiga tempat untuk diperbaiki setiap kali ambangnya berubah dan satu sumber yang terlewat.

Event type membalik arahnya. Alih-alih setiap search menyebutkan sumbernya, setiap sumber menyebutkan dirinya sebagai anggota sebuah kategori, lalu search menanyakan kategori itu. Dokumentasi menyebut event type sebagai cara menyortir data dalam jumlah besar, menemukan pola yang serupa, dan membangun alert serta report di atasnya [S1]. Mekanismenya sederhana: setiap event yang bisa dikembalikan oleh search sebuah event type akan mendapat asosiasi dengan event type itu [S1]. Asosiasi itu muncul sebagai field `eventtype`, dan karena satu event bisa cocok dengan beberapa event type sekaligus, `eventtype` adalah field yang berpotensi multivalue [S1][S2].

Tiga hal yang membedakannya dari objek lain yang mirip:

- **Bukan saved search atau report.** Report dijalankan dan menghasilkan tabel; event type tidak dijalankan sendiri, ia dievaluasi terhadap event. Dokumentasi bahkan menyarankan tidak mendefinisikan event type dengan merujuk sebuah report lewat `savedsearch`, karena report yang dirujuk bisa diubah orang lain sampai tidak lagi sah sebagai definisi event type [S1][S4].
- **Bukan pengganti macro.** Halaman resminya menyatakan dengan jelas bahwa memakai event type sebagai jalan pintas untuk menyingkat search tidak disarankan, dan menunjuk search macro sebagai alat yang tepat untuk itu [S1]. Alasannya ada di bagian 1.8.
- **Bukan nama lain dari sourcetype.** Sourcetype menentukan cara parsing dan ditetapkan saat ingest. Event type adalah penilaian yang kamu buat sendiri tentang arti event itu, dan satu event type bisa mencakup banyak sourcetype sekaligus. Itulah yang dimanfaatkan di bagian 2.

### 1.2 Yang tidak boleh ada di dalam search sebuah event type

Batasan ini yang paling sering mengejutkan orang yang baru memakai event type, dan di dokumentasi dicantumkan sebagai pembatasan definisi yang penting [S1]. Sebuah event type tidak boleh didasarkan pada search yang:

1. memuat pipe, yaitu karakter `|` setelah search sederhana [S1][S4];
2. memuat subsearch, yaitu pipeline search di dalam tanda kurung siku [S1][S4];
3. memakai command `savedsearch` untuk merujuk sebuah report. Yang ketiga disebut sebagai praktik terbaik, bukan larangan teknis, dengan alasan report yang dirujuk bisa berubah [S1][S4].

Ada satu batasan lagi yang berasal dari urutan operasi, bukan dari sintaks: search yang mendefinisikan event type tidak boleh merujuk tag [S1]. Penjelasannya di bagian 1.3.

Kenapa pipe dilarang masuk akal begitu kamu melihat cara kerjanya. Event type harus bisa dijawab untuk satu event, sendiri-sendiri, dengan jawaban ya atau tidak. `stats count BY src` tidak punya jawaban untuk satu event; ia hanya punya jawaban untuk sekumpulan event. Karena itu semua logika yang butuh agregasi, pengurutan, atau hasil search lain tidak bisa hidup di dalam event type. Tempatnya di macro (Day 18) atau di detection itu sendiri.

Yang masih boleh dan sering cukup: operator boolean, tanda kutip, wildcard, perbandingan nilai field, dan operator `IN (...)` di command `search`. Jadi `index=wineventlog (EventCode=4624 OR EventCode=4625 OR EventCode=4648)` adalah definisi event type yang sah, dan begitu juga `index=linux sourcetype=linux_secure (sshd OR sudo)`.

### 1.3 Letak event type di urutan operasi search-time

Urutan lengkap operasi search-time dibahas di Day 16. Yang perlu dipegang di Day ini hanya posisi dua hal: event type dijalankan setelah lookup, dan tag dijalankan setelah event type [S1]. Tag sendiri adalah operasi search-time yang paling akhir, dan diterapkan ke pasangan field dan value dalam urutan ASCII [S5].

Dua konsekuensi langsung yang menjelaskan banyak kebingungan di lapangan:

- Search event type boleh memakai field hasil field alias, calculated field, dan lookup, karena ketiganya sudah selesai lebih dulu [S1]. Jadi event type boleh ditulis dengan nama field CIM seperti `user` dan `src` walaupun field aslinya bernama lain, selama alias-nya memang ada untuk sourcetype itu.
- Search event type tidak boleh merujuk tag [S1]. Bila kamu menulis `tag=authentication` di dalam definisi sebuah event type, tag itu belum ada ketika event type dievaluasi, sehingga hasilnya bukan error yang jelas melainkan event type yang tidak pernah cocok dengan apa pun.

Di antara event type sendiri, dokumentasi menyebut urutan pemrosesan ditentukan oleh skor priority lebih dulu, lalu urutan leksikografis [S1]. Yang tidak disebut di halaman itu adalah apakah satu event type boleh merujuk event type lain dengan `eventtype=`; karena urutannya hanya dijamin oleh priority dan abjad, pola seperti itu sebaiknya dihindari, dan bila terpaksa dipakai, buktikan dulu di lab bahwa hasilnya stabil.

### 1.4 Priority dan color: yang berubah hanya tampilan

Di form event type ada dua kolom yang mudah disalahpahami sebagai pengatur perilaku, padahal keduanya mengatur tampilan.

Priority adalah angka 1 sampai 10, dengan 1 sebagai yang tertinggi dan 10 yang terendah [S3][S4]. Pengaruhnya dua [S3]:

1. Urutan daftar event type pada event yang dibuka. Event type yang punya priority ditampilkan di atas event type yang tidak punya, dan yang tidak punya diurutkan menurut abjad.
2. Pemilihan warna. Satu event hanya menampilkan satu warna, yaitu warna dari event type dengan priority terbaik di antara yang cocok [S3]. Untuk event type yang dikelompokkan dengan command `transaction`, tidak ada warna yang ditampilkan [S3].

Warna yang tersedia adalah daftar tertutup: `none`, `et_blue`, `et_green`, `et_magenta`, `et_orange`, `et_purple`, `et_red`, `et_sky`, `et_teal`, dan `et_yellow` [S4]. Di utilitas Build Event Type, kolom yang sama disebut Style [S10], jadi jangan mencari kolom bernama Color di sana.

Yang perlu jelas di kepala: priority tidak memengaruhi event mana yang cocok, tidak memengaruhi hasil `stats`, dan tidak memengaruhi keanggotaan data model. Dua event type yang sama-sama cocok tetap keduanya masuk ke field `eventtype` dan tag keduanya tetap berlaku. Priority hanya memutuskan mana yang tampil lebih dulu dan warna siapa yang dipakai.

### 1.5 Tag pada pasangan field dan value

Tag memberi nama pada kombinasi field dan value [S5]. Satu tag bisa dipakai di banyak pasangan, dan satu pasangan bisa punya banyak tag [S5][S6]. Dokumentasi menyebut dua pola pemakaian yang paling sering [S5]:

- satu tag untuk banyak nilai, misalnya dua nama host untuk satu mesin diberi tag yang sama sehingga satu search menjangkau keduanya;
- banyak tag untuk satu nilai, misalnya satu alamat IP diberi tag fungsi dan tag lokasi sehingga search bisa dipersempit dari dua arah.

Pencariannya memakai dua bentuk [S7]:

```
tag=<nama tag>
tag::<field>=<nama tag>
```

Bentuk pertama mencari tag di semua field, bentuk kedua membatasi ke satu field. Wildcard boleh dipakai pada nilainya; contoh resmi yang diberikan adalah `tag::host=*local*` [S7]. Tag juga bisa digabung dengan boolean seperti pencarian biasa; contoh di dokumentasi adalah `tag=router tag=SF NOT (tag=Building1)` untuk mencari router di satu kota yang tidak berada di gedung tertentu [S5].

Tiga hal yang perlu diingat sebelum membuat banyak tag:

- **Splunk tidak memvalidasi pasangan field dan value yang kamu tulis.** Halaman pengelolaan tag menyatakan tidak ada validasi, dan menyarankan memastikan sendiri pasangan itu benar-benar ada di data sebelum membuat recordnya [S6]. Salah ketik satu karakter menghasilkan tag yang sah tetapi tidak pernah cocok.
- **Tag tidak mengubah nilai field.** Memberi tag pada `host=bdg-rtr01` tidak mengubah nilai `host`. Satu event tetap punya satu nama host, tetapi bisa punya banyak tag host [S11].
- **Untuk puluhan ribu nilai, pakai lookup.** Dokumentasi menyarankan field lookup, bukan tag, ketika jumlah hal yang perlu diberi label mencapai puluhan ribu, dan menambahkan bahwa banyaknya tag tidak memengaruhi indexing [S5].

Di UI ada dua jalan masuk. Dari hasil search, buka event, pakai menu Actions pada field yang ingin diberi tag lalu pilih Edit Tags, dan isi tag pada dialog yang muncul; nilai di kolom Tag(s) dipisahkan koma atau spasi [S11]. Dari Settings, buka Settings > Tags yang punya tiga halaman: List by field value pair, List by tag name, dan All unique tag objects [S6]. Dua halaman pertama masing-masing punya tombol New untuk membuat tag baru dari sisi pasangan field dan value atau dari sisi nama tag [S6].

Mematikan tag dan menghapus tag adalah dua hal berbeda yang penting dibedakan saat merapikan lingkungan yang sudah berumur. Asosiasi tag yang dimatikan tetap ada di sistem tetapi tidak aktif sampai dinyalakan lagi, dan menyalakannya kembali dilakukan dari halaman List by field value pair dengan menambahkan nama tag itu lagi ke pasangannya [S6]. Perubahan juga berlaku per app: mematikan tag untuk sebuah pasangan di app Search & Reporting tidak mematikannya untuk pasangan yang sama di app lain [S6].

### 1.6 Tag pada event type dan sintaks `tag::eventtype`

Tag menjadi jauh lebih berguna begitu ditempelkan ke event type, bukan ke nilai field satu per satu. Alasannya: event type adalah satu-satunya tempat di mana "arti" sebuah event dirumuskan sebagai kriteria, sehingga tag yang menempel di sana otomatis berlaku untuk semua event yang cocok, termasuk event yang besok datang dari host baru yang belum pernah kamu lihat. Dokumentasi menyatakan satu event type bisa punya banyak tag, dan setelah sebuah event type diberi tag, setiap event type yang cocok dengan pola yang ditandai itu juga ikut tertandai [S7].

Contoh resmi yang paling ringkas: dua event type dibuat untuk dua jenis error HTTP, keduanya diberi tag yang sama, lalu semua event dari kedua event type itu diambil dengan satu pencarian `tag::eventtype=HTTP client error` [S1]. Pola inilah yang dipakai PT JAB di bagian 2, dengan kategori otentikasi sebagai ganti error HTTP.

Memberi tag ke event type bisa dilakukan saat menyimpannya dari search lewat kolom Tag(s), atau nanti dari Settings > Event types dengan membuka event type itu dan mengisi kolom Tag(s) [S2][S7]. Perhatian soal akses: event type biasanya terikat ke app tertentu dan punya permission berbasis role, sehingga bisa saja kamu tidak melihat atau tidak bisa menyunting event type yang sebenarnya ada [S7]. Permission knowledge object dibahas di Day 15.

Untuk memverifikasi bahwa tag benar-benar menempel, ada dua cara yang tidak bergantung pada ingatan:

- Pakai field `tag::eventtype` langsung di search, misalnya `| stats count BY eventtype tag::eventtype`. Panduan normalisasi CIM juga menyebut langkah verifikasi tag dengan melihat `tag::eventtype` [S12].
- Pakai command `tags`, yang menuliskan tag dari field di hasil search ke field baru [S9]. Tanpa opsi, command ini membuat satu field per field yang punya tag, dan juga sebuah field `tags` yang memuat semua nama tag [S9]. Dengan `outputfield`, semua tag dikumpulkan ke satu field, dan `inclname=t` serta `inclvalue=t` menambahkan nama dan nilai field asalnya sehingga formatnya menjadi `<field>::<value>::<tag_name>` [S9]. Karena command ini streaming, dokumentasi menyarankan menaruh command seperti `stats` lebih dulu bila ingin melihat hasilnya sebagai tabel; tanpa itu hasilnya hanya muncul di daftar interesting fields [S9].

### 1.7 Peran tag di CIM: penentu event mana yang masuk data model

Kecurigaan detection engineer PT JAB bahwa Pivot kurang data terjawab di sini. Data model CIM tidak memilih anggotanya berdasarkan index atau sourcetype. Ia memilih berdasarkan tag. Halaman data model Authentication di CIM 6.4 menyatakan bahwa tag yang dicantumkannya berfungsi sebagai constraint untuk menandai event sebagai relevan bagi data model itu [S8].

Tag constraint untuk Authentication di CIM 6.4, yang perlu dicocokkan satu per satu dengan data-mu sebelum berharap Pivot dan `tstats` memberi angka yang benar:

| Dataset | Tag constraint [S8] |
|---|---|
| Authentication | `authentication` |
| Default_Authentication | `default` |
| Insecure_Authentication | `cleartext` atau `insecure` |
| Privileged_Authentication | `privileged` |

Yang sering salah dipahami: sukses dan gagal bukan tag. Di CIM 6.4, status otentikasi adalah nilai field `action`, dengan nilai yang diharapkan `success`, `failure`, `pending`, dan `error` [S8]. Jadi detection yang mencari login gagal menyaring `action=failure`, bukan `tag=failure`. Memberi tag bernama `failure` ke event type-mu tidak membuatnya lebih patuh CIM; yang dibutuhkan adalah nilai `action` yang benar, biasanya lewat calculated field atau lookup (Day 16 dan Day 23).

Rantai keanggotaan lengkapnya ada empat mata, dan rantai itu putus bila satu saja hilang: event type cocok, event type punya tag constraint, field bernama sesuai CIM, dan nilai field sesuai yang diharapkan. Day 23 membahas rantai ini dari sisi CIM dan add-on vendor; Day ini membahas dua mata rantai pertama, yang justru paling sering dikerjakan sendiri karena sumber internal seperti portal pelanggan dan RADIUS tidak punya add-on resmi.

Satu kalimat yang perlu diingat soal biaya: data model yang kekurangan tag tidak memberi error. Ia memberi angka yang lebih kecil, dan angka yang lebih kecil terlihat seperti lingkungan yang tenang.

**Tanpa ES:** event type dan tag adalah fitur Splunk Enterprise biasa dan seluruh isi Day ini jalan di app Search & Reporting tanpa ES. Yang ditambahkan ES dan add-on CIM adalah banyaknya event type dan tag yang sudah terpasang sejak awal, plus data model CIM yang siap diakselerasi. Konten detection resmi pun memakainya: macro `wineventlog_security` di detection Splunk Threat Research berisi `eventtype="wineventlog_security" OR Channel="security" OR source="XmlWinEventLog:Security" OR source="WinEventLog:Security"`, jadi baris pertama sebuah detection ESCU benar-benar bergantung pada sebuah event type yang ada di lingkunganmu [S13]. Di Splunk Enterprise tanpa ES, kamu membuat event type dan tag yang sama dengan tangan seperti di bagian 2, lalu memakai `tag=` di report dan alert biasa (Day 09).

### 1.8 Biaya: kapan event type bukan pilihan yang tepat

Event type bukan gratis. Dokumentasi menyatakan bahwa pemakaian event type bisa menghabiskan banyak data, dan biaya search naik seiring bertambahnya event type yang didefinisikan [S1]. Masuk akal secara mekanis: setiap event yang dikembalikan search harus diuji terhadap setiap event type yang berlaku di app itu.

Dari situ muncul tiga aturan praktis:

- Buat event type untuk kategori yang akan dipakai ulang oleh banyak search, data model, atau alert. Empat sumber otentikasi di PT JAB memenuhi syarat ini.
- Jangan membuat event type hanya untuk menyingkat search yang panjang. Untuk itu dokumentasi sendiri menunjuk macro [S1], dan macro tidak menambah beban pada setiap event karena ia hanya substitusi teks sebelum search jalan (Day 18).
- Rapikan event type yang tidak terpakai, terutama yang dibuat untuk satu investigasi lalu dibagikan ke app global. Objek yang pemiliknya keluar bisa menjadi yatim dan tetap ikut dievaluasi (Day 09 bagian 1.6 dan Day 15).

## 2. Contoh dan langkah praktis di PT JAB

Semua keluaran di bagian ini adalah keluaran ilustrasi untuk organisasi fiktif PT JAB, bukan hasil eksekusi. Asumsi data: empat index otentikasi di PT JAB (`vpn`, `wineventlog`, `linux`, `o365`) sudah masuk dengan add-on vendor masing-masing, field `user` dan `src` sudah bernama CIM lewat add-on atau lewat alias yang dibuat sendiri (Day 16), dan field `action` sudah bernilai `success` atau `failure`. Rentang waktu yang dipakai seluruh bagian ini adalah shift malam sampai pagi, `earliest="10/14/2026:00:00:00"` sampai `latest="10/14/2026:08:00:00"` dalam WIB, dan angka dasarnya seperti di tabel berikut. Tabel ini dipakai untuk mencocokkan setiap keluaran ilustrasi di bawah, jadi cari barisnya sebelum menerima sebuah angka.

| Event type | Index | Event di rentang itu | `action=failure` | `action=success` |
|---|---|---|---|---|
| `jab_win_auth` | `wineventlog` | 7498 | 86 | 7412 |
| `jab_vpn_auth` | `vpn` | 1296 | 212 | 1084 |
| `jab_o365_auth` | `o365` | 2787 | 54 | 2733 |
| `jab_linux_auth` | `linux` | 599 | 341 | 258 |
| Total | | 12180 | 693 | 11487 |

### 2.1 Membuat event type pertama dari sebuah search

Mulai dari search yang sudah kamu percayai, bukan dari form kosong. Ini juga cara memeriksa definisinya: bila search-nya mengembalikan event yang salah, event type-nya akan salah dengan cara yang sama.

**Tujuan:** menjadikan kriteria event otentikasi VPN sebagai satu kategori bernama `jab_vpn_auth`.

```
index=vpn (action=success OR action=failure)
```

Langkah menyimpannya [S2]:

1. Jalankan search itu di app Search & Reporting.
2. Klik Save As lalu pilih Event Type.
3. Isi Name dengan `jab_vpn_auth`.
4. Isi Tag(s) dengan `authentication` (opsional di form, wajib untuk keperluan PT JAB; lihat bagian 2.3).
5. Pilih Color bila mau, misalnya `et_sky`.
6. Isi Priority bila mau; pada form ini dinyatakan 1 adalah priority terbaik dan 10 yang terburuk.
7. Klik Save.

Satu hal yang perlu diperhatikan soal lokasi penyimpanan: definisi itu disimpan ke `eventtypes.conf` di direktori user, yaitu `$SPLUNK_HOME/etc/users/<nama user>/<app>/local/`, dan baru dipindahkan ke `$SPLUNK_HOME/etc/apps/<App>/local/` ketika kamu membagikannya secara global [S2]. Artinya event type yang baru dibuat belum terlihat oleh rekan satu tim dan belum berpengaruh pada data model sampai permission-nya diubah. Ini sumber kebingungan yang klasik: detection berjalan benar di layar pembuatnya dan kosong di layar orang lain.

**Cara membaca hasil:** setelah event type aktif, jalankan `index=vpn earliest="10/14/2026:00:00:00" latest="10/14/2026:08:00:00" | stats count BY eventtype`. Keluaran ilustrasi:

```
eventtype        count
jab_vpn_auth     1296
```

**Variasi:** bila kamu ingin memastikan definisinya tidak terlalu lebar, bandingkan jumlah event yang cocok event type dengan jumlah event di index itu: `index=vpn earliest=... latest=... | stats count AS semua count(eval(isnotnull(eventtype))) AS bertipe`. Selisih yang besar berarti ada event VPN yang bukan otentikasi (misalnya log tunnel atau heartbeat) dan itu wajar; selisih nol pada index yang kamu tahu berisi campuran berarti definisinya terlalu lebar.

**Kapan gagal:** bila add-on VPN tidak menormalkan `action`, nilainya bisa `REJECT` atau kode angka, sehingga definisi di atas tidak cocok dengan apa pun. Periksa dulu dengan `index=vpn earliest=-24h | stats count BY action`, lalu normalkan nilainya (Day 16) atau ubah definisi event type memakai field asli vendor.

### 2.2 Tiga sumber lain, dan versi `.conf` dari keempatnya

Dari Settings, formnya sama tetapi search-nya ditulis manual [S2]: Settings > Event types, klik New, pilih Destination App bila bukan app yang sedang dibuka, isi Name, isi Search String, lalu Tag(s), Color, dan Priority bila perlu, dan Save.

Tiga definisi berikutnya untuk PT JAB, dengan alasan masing-masing dibatasi seperti itu:

| Nama | Search String | Catatan |
|---|---|---|
| `jab_win_auth` | `index=wineventlog (EventCode=4624 OR EventCode=4625 OR EventCode=4648)` | Tiga event logon dari Day 03; 4672 tidak dimasukkan karena ia penanda hak istimewa, bukan peristiwa otentikasi tersendiri |
| `jab_linux_auth` | `index=linux sourcetype=linux_secure (sshd OR sudo)` | Dua kata kunci saja supaya tetap tanpa pipe; penyaringan Accepted dan Failed dilakukan lewat `action` |
| `jab_o365_auth` | `index=o365 sourcetype=o365:management:activity Workload=AzureActiveDirectory` | Nama sourcetype dan field add-on Microsoft berbeda antar versi, jadi cek nama persisnya di instance-mu sebelum menyimpan |

Bentuk `.conf` dari keempat event type, untuk dipasang di app atau add-on milikmu sendiri. Perhatikan bahwa tag tidak ditulis di sini:

```
# eventtypes.conf
[jab_vpn_auth]
search = index=vpn (action=success OR action=failure)
priority = 5
color = et_sky
description = Event otentikasi VPN karyawan dan vendor

[jab_win_auth]
search = index=wineventlog (EventCode=4624 OR EventCode=4625 OR EventCode=4648)
priority = 5
color = et_blue
description = Event logon Windows: 4624, 4625, 4648

[jab_linux_auth]
search = index=linux sourcetype=linux_secure (sshd OR sudo)
priority = 5
color = et_green
description = Event otentikasi dan eskalasi hak di server Linux

[jab_o365_auth]
search = index=o365 sourcetype=o365:management:activity Workload=AzureActiveDirectory
priority = 5
color = et_teal
description = Sign-in Entra ID lewat Management Activity
```

Atribut yang dipakai di atas dan artinya menurut spesifikasi 10.6 [S4]: `search` adalah kriteria pencarian event type itu, `priority` adalah angka 1 sampai 10 dengan 1 tertinggi, `color` adalah salah satu dari daftar tertutup di bagian 1.4, dan `description` adalah penjelasan untuk manusia. Ada juga `disabled` yang disetel 1 untuk mematikan sebuah event type tanpa menghapusnya [S4]. Atribut `tags` di `eventtypes.conf` ditandai DEPRECATED di spesifikasi 10.6 dan diarahkan ke `tags.conf` [S4], padahal UI masih menyediakan kolom Tag(s) dan halaman Tag event types masih menyebut tag bisa disetel di `eventtypes.conf` [S2][S7]. Lihat bagian 6; jalur yang aman adalah `tags.conf` atau halaman Tags di UI.

**Kapan gagal:** bila `Workload` tidak ada karena nama field add-on berbeda, event type `jab_o365_auth` tidak cocok dengan satu event pun dan bagian 2.3 akan memperlihatkannya sebagai baris yang hilang, bukan sebagai error.

### 2.3 Memberi tag `authentication` ke empat event type, lalu membuktikannya

Sampai titik ini PT JAB punya empat kategori tetapi belum punya satu nama bersama. Tag yang memberikannya.

Lewat UI, untuk setiap event type [S7]: Settings > Event types, klik nama event type itu, isi atau tambahkan `authentication` di kolom Tag(s), lalu Save. Lewat file, satu stanza per pasangan field dan value, dan satu tag per baris [S14]:

```
# tags.conf
[eventtype=jab_vpn_auth]
authentication = enabled

[eventtype=jab_win_auth]
authentication = enabled

[eventtype=jab_linux_auth]
authentication = enabled

[eventtype=jab_o365_auth]
authentication = enabled
```

Nama stanza adalah pasangan field dan value yang menjadi sasaran tag, dan setiap baris di dalamnya adalah satu nama tag yang disetel `enabled` atau `disabled`; nama tag tidak diberi tanda kutip, dan hanya satu tag per baris [S14]. Spesifikasinya juga menyarankan nilai di nama stanza di-URL-encode untuk menghindari kesalahan parsing bila nilainya memuat karakter seperti tanda sama dengan atau kurung siku [S14]. Tidak ada `tags.conf` default yang dikirim bersama Splunk, dan perubahan lewat file memerlukan restart, berbeda dengan perubahan lewat UI [S14].

**Tujuan verifikasi:** membuktikan keempat event type benar-benar membawa tag, dan menemukan yang tidak.

```
(index=vpn OR index=wineventlog OR index=linux OR index=o365)
earliest="10/14/2026:00:00:00" latest="10/14/2026:08:00:00"
| stats count BY eventtype tag::eventtype
```

| Bagian | Penjelasan |
|---|---|
| Empat index di depan | Filter paling murah ditaruh paling awal; tanpa ini search menyentuh seluruh index yang boleh dibaca role-mu |
| `BY eventtype tag::eventtype` | Dua kolom sekaligus memperlihatkan pasangan kategori dan tag; event tanpa tag muncul dengan kolom tag kosong |

Keluaran ilustrasi ketika tag di `jab_o365_auth` belum dibuat:

```
eventtype          tag::eventtype    count
jab_linux_auth     authentication     599
jab_o365_auth                        2787
jab_vpn_auth       authentication    1296
jab_win_auth       authentication    7498
```

**Cara membaca hasil:** baris dengan kolom tag kosong adalah penyakitnya. Total event otentikasi di rentang itu 12.180, dan yang bertag hanya 9.393. Artinya 2.787 event, sekitar 23 persen, tidak akan ikut terhitung oleh apa pun yang berangkat dari tag, termasuk data model Authentication dan setiap detection yang dibangun di atasnya.

**Variasi:** command `tags` memberi tampilan yang berbeda dan berguna saat kamu belum tahu field mana yang punya tag [S9].

```
(index=vpn OR index=linux) earliest="10/14/2026:00:00:00" latest="10/14/2026:08:00:00"
| stats count BY eventtype host
| tags outputfield=label inclname=t
```

Keluaran ilustrasi (dua baris dari sebelas):

```
eventtype          host             count   label
jab_linux_auth     jkt-bastion01     266    eventtype::authentication
jab_vpn_auth       jkt-vpn01         212    eventtype::authentication
```

Format `<field>::<tag_name>` muncul karena `inclname=t`; dengan `inclvalue=t` juga disetel, formatnya menjadi `<field>::<value>::<tag_name>` [S9].

**Kapan gagal:** bila tag dibuat lewat file tetapi Splunk belum di-restart, hasilnya tetap kosong [S14]. Bila tag dibuat di app lain dan event type-nya tidak dibagikan secara global, tag itu hanya terlihat dari app tempat ia dibuat [S6]. Dan bila kamu salah mengetik nama event type di nama stanza, tidak ada peringatan sama sekali, karena Splunk tidak memvalidasi pasangan field dan value [S6].

### 2.4 Tag pada pasangan field dan value: aset POP

Permintaan kedua yang sering datang ke SOC PT JAB bukan soal otentikasi, melainkan soal cakupan: NOC ingin memisahkan kejadian di perangkat POP regional dari kejadian di data center Jakarta. Nama host perangkat POP tidak seragam karena beberapa generasi perangkat, jadi menyaring dengan wildcard selalu meninggalkan sisa.

Di sini tag pada pasangan field dan value lebih tepat daripada event type, karena yang diberi label adalah nilai field `host`, bukan arti event-nya.

Lewat hasil search [S11]: jalankan `index=netops host=bdg-rtr01`, buka satu event, pakai menu Actions pada field `host`, pilih Edit Tags, lalu isi `pop, pop_bandung` di kolom Tag(s) dan simpan. Nilai di kolom itu dipisahkan koma atau spasi [S11].

Lewat Settings [S6]: Settings > Tags > List by field value pair > New, isi pasangan field dan value lalu satu atau lebih nama tag.

Bentuk `.conf`-nya, dengan tiga perangkat POP dan dua perangkat data center sebagai pembanding:

```
# tags.conf
[host=bdg-rtr01]
pop = enabled
pop_bandung = enabled

[host=sby-rtr01]
pop = enabled
pop_surabaya = enabled

[host=mdn-rtr01]
pop = enabled
pop_medan = enabled

[host=jkt-dc-rtr01]
datacenter = enabled
```

**Tujuan:** menghitung kejadian per POP tanpa menuliskan daftar host di setiap search.

```
index=netops tag::host=pop earliest="10/14/2026:00:00:00" latest="10/14/2026:08:00:00"
| stats count BY host
```

Keluaran ilustrasi:

```
host          count
bdg-rtr01      418
mdn-rtr01      207
sby-rtr01      362
```

**Cara membaca hasil:** tiga baris, total 987 event. Bila besok ada perangkat POP keempat, search ini tetap benar setelah satu tag ditambahkan, dan setiap report serta alert yang memakai `tag::host=pop` ikut mencakupnya tanpa disunting. Itu nilai sebenarnya dari tag: satu tempat untuk diperbarui.

**Variasi:** `tag=pop` tanpa `tag::host` juga jalan, tetapi mencari tag itu di semua field, bukan hanya `host` [S7]. Pada data yang punya `src` dan `dest` berisi nama perangkat, bedanya bisa besar. Pakai bentuk yang dibatasi field bila yang kamu maksud memang hanya satu field.

**Kapan gagal:** bila nama host di log ditulis sebagai FQDN (`bdg-rtr01.corp.jab.example`) sementara tag dibuat untuk nama pendek, pasangannya tidak cocok dan hasilnya kosong. Tag berlaku untuk nilai yang persis, bukan untuk pola, kecuali kamu memakai wildcard di sisi pencarian [S7]. Untuk daftar yang terus bertambah seperti perangkat pelanggan, lookup lebih cocok daripada tag [S5].

### 2.5 Satu detection untuk empat sumber

Sekarang permintaan utama detection engineer bisa dikerjakan. Logikanya sama dengan alert brute force VPN di Day 09 bagian 2.2, tetapi baris pertamanya tidak lagi menyebut index.

**Tujuan:** menemukan sumber yang menghasilkan banyak kegagalan otentikasi di semua sumber log otentikasi yang sudah diberi tag, tanpa menyebut index satu per satu.

```
tag=authentication action=failure
earliest="10/14/2026:00:00:00" latest="10/14/2026:08:00:00"
| stats count AS gagal dc(user) AS user_unik values(eventtype) AS kategori BY src
| where gagal >= 50
| sort - gagal
```

| Bagian | Penjelasan |
|---|---|
| `tag=authentication` | Satu kriteria menggantikan daftar index; sumber kelima nanti ikut tercakup setelah event type-nya diberi tag yang sama |
| `action=failure` | Status otentikasi di CIM adalah nilai field, bukan tag [S8] |
| `dc(user) AS user_unik` | Membedakan satu akun yang salah password dari penyemprotan banyak akun |
| `values(eventtype) AS kategori` | Memperlihatkan sumber mana yang menyumbang; `eventtype` berpotensi multivalue [S1] |
| `where gagal >= 50` | Ambang kerja PT JAB; `where` dipakai karena membandingkan hasil `stats`, bukan field event (Day 02 bagian 1.2) |

Keluaran ilustrasi:

```
src              gagal   user_unik   kategori
198.51.100.77      266           9   jab_linux_auth
203.0.113.45       180          12   jab_vpn_auth
```

**Cara membaca hasil:** dua sumber melewati ambang, dari dua kategori berbeda, dan satu di antaranya tidak akan pernah muncul di alert versi lama karena alert itu hanya menyaring `index=vpn`. Angka 266 adalah bagian dari 341 kegagalan Linux di rentang itu, dan 180 adalah bagian dari 212 kegagalan VPN, sehingga sisanya tersebar di bawah ambang. Baris `198.51.100.77` dengan sembilan akun berbeda ke `jkt-bastion01` adalah pola penyemprotan akun, bukan satu orang yang lupa password.

**Variasi 1, per kategori:** `| stats count BY eventtype` di tempat `BY src` memberi rekap 341, 212, 86, dan 54 dengan total 693, dan itu angka yang pas untuk laporan harian.

**Variasi 2, mempersempit ke sumber eksternal:** tambahkan `| where NOT cidrmatch("10.0.0.0/8", src)` untuk memisahkan sumber luar dari sumber internal. Perhatikan bahwa `cidrmatch` di sini dipakai di dalam `where`, jadi tulis `in()` dan fungsi eval lain dengan gaya eval, bukan gaya command `search`.

**Variasi 3, menaikkan presisi dengan tag anak:** bila sebagian event type sudah diberi tag `privileged` sesuai CIM, `tag=authentication tag=privileged action=failure` mempersempit ke kegagalan otentikasi akun istimewa, yang ambang wajarnya jauh lebih rendah [S8].

**Kapan gagal:** bila satu event type kehilangan tag, sumbernya hilang dari hasil tanpa jejak, dan inilah mode kegagalan paling berbahaya dari pendekatan ini. Karena itu verifikasi di bagian 2.3 dijalankan sebagai report terjadwal, bukan sekali saat memasang. Bila `user` di log Windows format klasik berisi dua akun dalam satu event, `dc(user)` ikut menghitung akun Subject dan nilainya meleset ke atas (Day 03 bagian 1.5). Dan bila ada event type kedua yang juga cocok dengan event yang sama, `values(eventtype)` akan memperlihatkan dua nilai, yang justru berguna untuk mengetahuinya.

### 2.6 Membuktikan data model sudah utuh sebelum detection dipindahkan ke atasnya

Pertanyaan terakhir detection engineer soal Pivot yang kurang data bisa dijawab dengan angka, bukan dengan dugaan.

**Tujuan:** membandingkan jumlah event yang masuk dataset Authentication dengan jumlah event otentikasi yang benar-benar ada di index.

```
| datamodel Authentication Authentication search
| stats count BY eventtype
```

| Bagian | Penjelasan |
|---|---|
| `\| datamodel <model> <dataset> search` | Mengembalikan event anggota dataset itu sebagai event biasa, sehingga bisa diperiksa dengan command biasa |
| Rentang waktu | Diambil dari time picker, karena `datamodel` adalah generating command dan `earliest` di dalam search tidak berlaku untuknya seperti pada search biasa |
| `stats count BY eventtype` | Memperlihatkan kategori mana yang sudah ikut dan mana yang belum |

Keluaran ilustrasi sebelum tag `jab_o365_auth` dibuat:

```
eventtype          count
jab_linux_auth      599
jab_vpn_auth       1296
jab_win_auth       7498
```

Keluaran ilustrasi setelah tag itu dibuat:

```
eventtype          count
jab_linux_auth      599
jab_o365_auth      2787
jab_vpn_auth       1296
jab_win_auth       7498
```

**Cara membaca hasil:** 9.393 menjadi 12.180. Selisih 2.787 event itu sebelumnya tidak terlihat oleh Pivot, oleh `tstats` atas data model (Day 25), dan oleh setiap detection ES yang berangkat dari data model Authentication. Tidak ada pesan error yang pernah muncul untuk memberi tahu.

**Variasi:** untuk memeriksa mata rantai ketiga dan keempat, yaitu nama dan nilai field, pakai `| datamodel Authentication Authentication search | stats count BY action` dan pastikan nilainya hanya `success`, `failure`, `pending`, atau `error` [S8]. Nilai seperti `Failed` atau `4625` berarti normalisasi nilai belum selesai (Day 16 dan Day 23).

**Kapan gagal:** pada data model yang terakselerasi, `tstats` dengan `summariesonly=true` hanya membaca ringkasan, sehingga event yang baru diberi tag belum muncul sampai ringkasannya dibangun ulang (Day 25 dan Day 26). Karena itu pemeriksaan di atas dilakukan dengan command `datamodel` atau dengan `summariesonly=false` lebih dulu.

### 2.7 Ketika dua event type cocok dengan satu event

Di PT JAB ada satu event type tambahan untuk kegagalan logon akun admin, supaya analyst melihatnya menonjol di layar:

```
# eventtypes.conf
[jab_admin_auth_failure]
search = index=wineventlog EventCode=4625 user=adm.*
priority = 2
color = et_red
description = Kegagalan logon akun administratif
```

Sebuah event 4625 untuk `adm.rina` di `JKT-JUMP01` cocok dengan dua event type: `jab_win_auth` (priority 5, `et_blue`) dan `jab_admin_auth_failure` (priority 2, `et_red`).

Yang terjadi [S1][S3]:

- Field `eventtype` berisi dua nilai, `jab_admin_auth_failure` dan `jab_win_auth`, sehingga `stats count BY eventtype` menghitung event itu di dua baris. Ini perilaku field multivalue yang normal dan perlu disadari saat menjumlahkan.
- Pada tampilan event yang dibuka, `jab_admin_auth_failure` tampil lebih dulu karena priority-nya lebih baik, dan event itu berwarna merah, bukan biru, karena hanya satu warna yang ditampilkan dan yang dipakai adalah warna dari priority terbaik [S3].
- Tag dari kedua event type tetap berlaku. Priority tidak memilih tag mana yang menang; ia hanya mengatur tampilan.

Keluaran ilustrasi `index=wineventlog EventCode=4625 earliest="10/14/2026:00:00:00" latest="10/14/2026:08:00:00" | stats count BY eventtype`:

```
eventtype                  count
jab_admin_auth_failure         7
jab_win_auth                  86
```

**Cara membaca hasil:** 86 adalah seluruh kegagalan logon Windows, dan 7 di antaranya adalah akun admin. Dua baris itu tidak boleh dijumlahkan menjadi 93, karena tujuh event dihitung dua kali. Bila kamu butuh angka tanpa tumpang tindih, hitung dengan `stats count` biasa lalu pecah dengan `eval` berdasarkan kriteria yang eksplisit.

### 2.8 Mencari kandidat event type untuk sumber log yang belum dikenal

PT JAB akan memasukkan log portal pelanggan bulan depan dan tidak ada yang tahu bentuk event-nya. Dua alat resmi membantu di tahap itu, dan keduanya hanya menyarankan: keputusan tetap di tangan kamu.

Command `findtypes` menghasilkan daftar kandidat event type dari hasil search [S15]. Sintaksnya `findtypes max=<int> [notcovered] [useraw]`, default `max` adalah 10, `notcovered` membatasi hasil ke kandidat yang belum tercakup event type yang ada, dan `useraw` memakai frasa di `_raw` untuk menyusun kandidat [S15]. Command ini menganalisis maksimal 5.000 event [S15].

```
index=linux sourcetype=linux_secure
earliest="10/14/2026:00:00:00" latest="10/14/2026:08:00:00"
| head 1000
| findtypes max=5 notcovered
```

`head 1000` di depan membuat pemeriksaan lebih cepat dengan ongkos ketelitian, dan itu memang cara yang disarankan dokumentasi untuk mempercepat [S10]. Kandidat yang keluar berbentuk search siap pakai, misalnya kriteria yang menggabungkan `sshd` dengan kata `Failed`, yang kemudian kamu rapikan sendiri. Nama kolom keluaran `findtypes` tidak dicantumkan di halaman commandnya [S15], jadi catat bentuk tabelnya saat pertama kali kamu menjalankannya di lab dan pakai catatan itu.

Utilitas Build Event Type bekerja dari arah sebaliknya, mulai dari satu event yang kamu anggap mewakili [S10]:

1. Jalankan search yang mengembalikan event yang ingin kamu jadikan dasar.
2. Buka event itu, klik Event Actions, pilih Build Event Type.
3. Di sidebar Event type features, pilih pasangan field dan value yang relevan; kolom Generated event type search ikut berubah dan boleh disunting langsung.
4. Klik Test untuk menjalankan search itu di jendela terpisah.
5. Klik Save, isi Name, lalu Style dan Priority bila perlu, dan Save sekali lagi.

**Kapan gagal:** kandidat dari `findtypes` cenderung memilih kata yang sering muncul, termasuk kata yang kebetulan sering muncul di rentang waktu yang kamu pilih. Jalankan di dua rentang waktu berbeda sebelum memutuskan, dan uji definisi akhirnya terhadap event yang seharusnya tidak cocok, bukan hanya terhadap event yang seharusnya cocok.

## 3. Lab praktik (di VM lab terisolasi)

Lab memakai dua sumber: data sintetis dari `makeresults` untuk memverifikasi perilaku dengan angka yang bisa dihitung sendiri, dan log dari VM lab-mu atau BOTS v1. BOTS v1 adalah dataset statis, jadi tentukan dulu rentang absolutnya seperti di Day 01 bagian 2.5 dan pakai rentang itu, bukan rentang relatif.

1. **Buat event type pertama dari search.** Di lab-mu, cari satu sourcetype otentikasi yang ada (`linux_secure` atau Windows Security). Simpan kriterianya sebagai event type lewat Save As, beri priority 5 dan satu warna. Catat path file tempat definisinya tersimpan, lalu buka file itu dan cocokkan isinya dengan yang kamu isi di form.
2. **Buktikan larangan pipe dan subsearch.** Coba simpan sebuah event type dengan definisi `index=main | stats count BY host`, lalu dengan definisi yang memuat subsearch `index=main [search index=main | head 1]`. Catat persis pesan yang muncul di layar untuk masing-masing, karena pesan itu yang nanti kamu kenali saat orang lain melaporkan masalah.
3. **Buktikan event type tidak boleh merujuk tag.** Buat tag apa pun pada satu pasangan field dan value, lalu buat event type yang definisinya memakai tag itu. Jalankan search `eventtype=<nama>` dan catat bahwa hasilnya kosong walaupun tidak ada error. Tulis satu kalimat kenapa, dengan menyebut urutan operasi search-time.
4. **Uji priority dan warna.** Buat dua event type yang sengaja saling tumpang tindih, satu priority 2 warna `et_red` dan satu priority 8 warna `et_green`. Buka satu event yang cocok dengan keduanya dan catat urutan daftarnya serta warna yang muncul. Lalu tukar priority-nya dan ulangi pengamatan.
5. **Hitung sendiri efek multivalue.** Jalankan `<search yang cocok dua event type> | stats count BY eventtype` lalu `| stats count`. Hitung lebih dulu berapa selisih yang kamu harapkan, lalu cocokkan. Tulis satu kalimat tentang kapan menjumlahkan baris `BY eventtype` menghasilkan angka yang salah.
6. **Tag pada pasangan field dan value.** Beri tag `pop` pada dua nilai `host` di lab-mu lewat Edit Tags dari hasil search, dan satu lagi lewat Settings > Tags. Lalu jalankan `tag=pop` dan `tag::host=pop` dan catat bila hasilnya berbeda, beserta alasannya.
7. **Tag pada event type dan verifikasinya.** Beri tag `authentication` pada event type dari langkah 1, lalu jalankan `| stats count BY eventtype tag::eventtype` dan `| tags outputfield=label inclname=t`. Bandingkan bentuk keluarannya dan catat mana yang lebih cepat kamu baca saat sedang memeriksa lingkungan orang lain.
8. **Rantai CIM yang putus.** Dengan event type dari langkah 7, jalankan `| datamodel Authentication Authentication search | stats count` dan catat angkanya. Matikan tag-nya dari halaman List by tag name, jalankan ulang, dan catat angka barunya. Nyalakan kembali dari halaman List by field value pair. Tulis satu kalimat tentang apa yang dilihat analyst lain selama tag itu mati.
9. **Normalkan satu sumber internal.** Ambil log aplikasi apa pun dari lab-mu yang punya baris login, buat event type untuknya, beri tag `authentication`, lalu periksa apakah ia muncul di dataset Authentication. Bila belum, periksa mata rantai ketiga dan keempat: nama field dan nilai `action`.
10. **Kandidat otomatis.** Jalankan `| head 1000 | findtypes max=5` pada satu sourcetype yang belum punya event type, catat nama kolom keluarannya, lalu jalankan ulang dengan `notcovered`. Pilih satu kandidat, perbaiki definisinya dengan tangan, dan uji dengan satu kasus yang seharusnya tidak cocok.

**Hasil yang sebaiknya tersimpan:**
- Isi `eventtypes.conf` dan `tags.conf` lab-mu, sebagai cikal bakal add-on kecil milik sendiri.
- Pesan error persis dari langkah 2, untuk dua kasus yang berbeda.
- Dua angka dari langkah 8 beserta selisihnya.
- Satu kalimat per langkah 3, 5, 6, dan 8.
- Nama kolom keluaran `findtypes` di versi lab-mu.

**Variasi tantangan:** tambahkan event type kelima untuk satu sumber otentikasi lain, tetapi sengaja beri tag yang salah ketik (`autentication`). Jalankan verifikasi bagian 2.3 dan ukur berapa lama kamu butuh untuk menemukan kesalahannya hanya dari keluaran search itu. Lalu tulis bentuk report terjadwal yang akan menemukannya otomatis, dengan `stats count BY eventtype tag::eventtype` sebagai dasarnya.

## 4. Troubleshooting

Tabel ini memuat gejala yang paling sering muncul saat memakai event type dan tag. Cari gejalanya di kolom pertama.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Event type tidak bisa disimpan | Definisinya memuat pipe atau subsearch [S1][S4] | Pindahkan logika setelah pipe ke macro (Day 18) atau ke detection-nya |
| `eventtype=<nama>` tidak mengembalikan apa pun | Definisi memakai tag, yang dievaluasi setelah event type [S1] | Ganti rujukan tag dengan kriteria field asli |
| Event type jalan di layarmu, kosong di layar rekan | Masih tersimpan di direktori user dan belum dibagikan [S2] | Ubah permission ke app atau global (Day 15) |
| Data model Authentication kurang event | Satu event type belum punya tag constraint [S8] | `\| stats count BY eventtype tag::eventtype` lalu cari kolom tag yang kosong |
| Tag dibuat tetapi tidak pernah cocok | Pasangan field dan value tidak ada di data; tidak ada validasi [S6] | Jalankan `<field>=<value>` langsung lebih dulu, baru buat tag |
| Tag dibuat lewat file tetapi tidak muncul | `tags.conf` butuh restart [S14] | Restart, atau buat lewat UI |
| Tag muncul di satu app dan tidak di app lain | Tag dan event type terikat app dan permission [S6][S7] | Periksa kepemilikan dan sharing objeknya |
| `tag::host=pop` kosong padahal tag ada | Nilai host di log berbentuk FQDN, tag dibuat untuk nama pendek | Buat tag untuk nilai yang persis, atau normalkan `host` lebih dulu |
| Jumlah baris `BY eventtype` lebih besar dari jumlah event | `eventtype` multivalue karena beberapa event type cocok [S1] | Hitung total dengan `stats count` biasa, jangan menjumlahkan baris |
| Warna event bukan yang kamu atur | Event type lain dengan priority lebih baik ikut cocok [S3] | Periksa semua nilai `eventtype` pada event itu, lalu atur priority |
| Warna tidak muncul sama sekali | Event type dikelompokkan lewat `transaction` [S3] | Perilaku yang didokumentasikan; jangan andalkan warna di hasil `transaction` |
| Search menjadi lambat setelah banyak event type dibuat | Setiap event diuji terhadap setiap event type yang berlaku [S1] | Hapus event type yang tidak dipakai; ganti yang sekadar penyingkat dengan macro |
| Tag yang dimatikan tidak bisa dinyalakan dari halaman yang sama | Penyalaan dilakukan dari halaman List by field value pair [S6] | Buka pasangan field dan value itu dan tambahkan kembali nama tagnya |
| `\| tags` tidak menampilkan apa-apa di tabel | Command ini streaming dan hasilnya masuk daftar interesting fields [S9] | Taruh `stats` sebelum `tags` |
| `tstats` atas data model belum memperlihatkan event yang baru diberi tag | Ringkasan akselerasi belum dibangun ulang | Periksa dengan command `datamodel` atau `summariesonly=false` (Day 25, Day 26) |

## 5. Kesalahan umum dan jebakan

- Membuat event type untuk menyingkat search panjang. Dokumentasi sendiri menyarankan macro untuk itu [S1], dan event type menambah ongkos pada setiap search yang berjalan di app itu.
- Menulis `tag=...` di dalam definisi event type. Hasilnya bukan error, melainkan event type yang tidak pernah cocok [S1].
- Menganggap priority memengaruhi hasil. Priority hanya mengatur urutan tampil dan warna [S3].
- Menjumlahkan hasil `stats count BY eventtype`. Satu event bisa punya beberapa nilai `eventtype`, sehingga sebagian event terhitung lebih dari sekali [S1].
- Menganggap `success` dan `failure` sebagai tag CIM. Di CIM 6.4 Authentication keduanya nilai field `action`; tag yang berlaku adalah `authentication`, `default`, `cleartext` atau `insecure`, dan `privileged` [S8].
- Mengandalkan Pivot atau `tstats` sebagai bukti cakupan tanpa membandingkannya dengan search langsung. Data model yang kekurangan tag memberi angka yang lebih kecil, bukan error.
- Membuat tag untuk ribuan nilai yang terus bertambah, misalnya IP pelanggan. Dokumentasi menyarankan lookup untuk skala puluhan ribu [S5].
- Membuat event type dan tag di app pribadi lalu memasang detection yang bergantung padanya di app lain. Objek yang tidak dibagikan tidak terlihat dari app lain [S2][S6].
- Mengandalkan atribut `tags` di `eventtypes.conf`. Atribut itu ditandai DEPRECATED di spesifikasi 10.6 [S4]; pakai `tags.conf` atau UI.
- Mendefinisikan event type dengan merujuk sebuah report. Report itu bisa diubah orang lain sampai definisinya tidak lagi sah [S1][S4].
- Memberi tag ke nilai field satu per satu padahal yang dimaksud adalah arti event. Tag pada event type otomatis mencakup host dan sumber baru; tag pada nilai field harus ditambah setiap kali ada nilai baru.
- Membuat event type yang definisinya persis sama dengan sourcetype. Itu tidak menambah apa pun, dan hanya menambah satu objek lagi untuk diuji di setiap search.
- Menerima kandidat `findtypes` apa adanya. Kandidat itu disusun dari pola yang sering muncul di maksimal 5.000 event [S15], jadi uji dengan kasus yang seharusnya tidak cocok.
- Lupa bahwa penghapusan dan pematian tag berlaku per app, sehingga membersihkan satu app meninggalkan tag yang sama tetap aktif di app lain [S6].

## 6. Catatan terkini

Bagian ini menampung detail versi dan ketidakcocokan antar halaman dokumentasi. Isinya tidak mengubah cara kerja, tetapi menjelaskan kenapa dua halaman resmi bisa terasa bertentangan.

- Spesifikasi `eventtypes.conf` 10.6 menandai atribut `tags` sebagai DEPRECATED dan mengarahkan ke `tags.conf` [S4], sementara UI masih menyediakan kolom Tag(s) saat membuat event type dan halaman Tag event types masih menyebut tag bisa disetel di `eventtypes.conf` [S2][S7]. Cara yang paling aman untuk jangka panjang adalah `tags.conf` atau halaman Tags di UI, dengan satu catatan di dokumentasi internal supaya rekan tim tidak bingung melihat dua jalur.
- Nama kolom warna berbeda antar jalur UI: form event type menyebutnya Color, utilitas Build Event Type menyebutnya Style [S2][S10]. Keduanya atribut `color` yang sama di file [S4].
- Halaman command `tags` 10.6 menulis konvensi nama field keluaran sebagai `tag_name::<field>`, sementara contoh di halaman yang sama memperlihatkan `tag` dan `tag::host` [S9]. Bentuk yang dipakai di Day ini adalah `tag::<field>` karena itu yang muncul di contoh dan di panduan CIM [S9][S12]; cek bentuk persisnya di instance-mu bila kamu menulis report yang bergantung pada nama field itu.
- Halaman command `findtypes` 10.6 tidak mencantumkan nama kolom keluarannya, dan menyebut batas analisis 5.000 event [S15]. Catat sendiri bentuk tabelnya saat pertama kali dijalankan.
- Halaman data model Authentication CIM 6.4 hanya mencantumkan tiga dataset anak, yaitu Default_Authentication, Insecure_Authentication, dan Privileged_Authentication [S8]. Nama seperti Successful_Authentication dan Failed_Authentication tidak muncul di halaman itu, jadi bila kamu menemukannya di contoh search yang beredar, cocokkan dulu dengan versi CIM yang terpasang.
- Tidak ada `tags.conf` default yang dikirim bersama Splunk, dan perubahan lewat file memerlukan restart [S14]. Perubahan lewat UI berlaku tanpa restart, yang membuat dua jalur itu terasa berbeda saat dipakai bergantian.
- Penulisan menu berbeda antar halaman dokumentasi, ada yang menulis Settings > Event Types dan ada yang menulis Settings > Event types [S2][S7]. Letaknya sama.
- Dokumentasi resmi kini di help.splunk.com, dan tautan docs.splunk.com lama masih beredar untuk halaman yang sama.

## 7. Cheat sheet

```
EVENT TYPE
  Save As > Event Type                     dari hasil search
  Settings > Event types > New             Name, Search String, Tag(s), Color, Priority
  eventtypes.conf:
    [jab_vpn_auth]
    search = index=vpn (action=success OR action=failure)
    priority = 5          1 tertinggi, 10 terendah
    color = et_sky        none et_blue et_green et_magenta et_orange
                          et_purple et_red et_sky et_teal et_yellow
    disabled = 1          matikan tanpa menghapus
  DILARANG di search event type: pipe ( | ), subsearch ( [ ... ] ), savedsearch
  TIDAK JALAN: rujukan tag di dalam definisi event type
  Pakai: eventtype=jab_vpn_auth            field eventtype bisa multivalue

TAG
  Settings > Tags > List by field value pair > New
  Settings > Tags > List by tag name > New
  Event actions pada field > Edit Tags     dari hasil search, dipisah koma atau spasi
  tags.conf:
    [eventtype=jab_vpn_auth]
    authentication = enabled
    [host=bdg-rtr01]
    pop = enabled
  Pakai: tag=pop   |   tag::host=pop   |   tag::eventtype=authentication
  Boolean: tag=router tag=SF NOT (tag=Building1)
  Wildcard: tag::host=*local*

VERIFIKASI
  ... | stats count BY eventtype tag::eventtype
  ... | stats count BY host | tags outputfield=label inclname=t
  | datamodel Authentication Authentication search | stats count BY eventtype
  | head 1000 | findtypes max=5 notcovered

URUTAN SEARCH-TIME (bagian yang penting di Day ini)
  extraction -> alias -> calculated field -> lookup -> EVENT TYPE -> TAG
  boleh dipakai di event type : alias, calculated field, hasil lookup
  tidak boleh                 : tag

CIM AUTHENTICATION (6.4)
  Authentication              tag=authentication
  Default_Authentication      tag=default
  Insecure_Authentication     tag=cleartext atau tag=insecure
  Privileged_Authentication   tag=privileged
  action = success | failure | pending | error      ini nilai field, BUKAN tag

RANTAI MASUK DATA MODEL (putus satu, hilang semua)
  event type cocok -> tag constraint ada -> nama field CIM benar -> nilai field benar
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Rekanmu ingin membuat event type bernama `brute_force_vpn` dengan definisi `index=vpn action=failure | stats count BY src | where count > 50`, supaya alert cukup memakai `eventtype=brute_force_vpn`. Bisa?

<details><summary>Jawaban</summary>

Tidak. Search yang mendefinisikan event type tidak boleh memuat pipe maupun subsearch. Alasannya bukan selera: event type harus bisa dijawab untuk satu event sendiri-sendiri dengan jawaban ya atau tidak, sedangkan `stats count BY src` hanya punya jawaban untuk sekumpulan event. Yang bisa dijadikan event type adalah bagian kriterianya (`index=vpn action=failure`), sementara agregasi dan ambangnya tinggal di detection, atau dijadikan macro bila mau dipakai ulang. Lihat bagian 1.2 dan 2.5.

</details>

**2. Skenario keputusan.** Pivot Authentication memberi 9.393 event, sementara search langsung ke empat index otentikasi memberi 12.180 event di rentang yang sama. Selisihnya tepat sebesar jumlah event sign-in Entra ID. Apa yang kamu lakukan?

- A. Ubah constraint dataset Authentication di data model CIM supaya mencakup `index=o365`.
- B. Periksa `| stats count BY eventtype tag::eventtype`, lalu tambahkan tag `authentication` ke event type sumber yang tagnya kosong.
- C. Tambahkan `OR index=o365` ke setiap detection yang memakai data model, supaya datanya ikut terbaca.

<details><summary>Jawaban</summary>

B. Keanggotaan dataset CIM ditentukan oleh tag, bukan oleh index, jadi sumber yang hilang hampir selalu berarti tag constraint yang belum menempel. A keliru karena mengubah data model bawaan CIM membuat lingkunganmu menyimpang dari standar yang dipakai semua konten resmi, dan masalahnya tetap ada untuk model lain. C keliru karena memperbaiki satu detection satu per satu justru mengembalikan masalah awal PT JAB, yaitu logika yang sama tersebar di banyak tempat, dan detection berbasis `tstats` atas data model tidak bisa diperbaiki dengan menambah index. Lihat bagian 1.7 dan 2.6.

</details>

**3. Pertanyaan jebakan.** "Event type-ku punya priority 8 dan event type lain punya priority 2, jadi event itu masuk data model lewat event type yang priority-nya 2 saja." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Priority hanya mengatur dua hal tampilan: urutan daftar event type pada event yang dibuka, dan warna mana yang dipakai bila beberapa event type cocok. Keanggotaan data model tidak dipengaruhi priority. Semua event type yang cocok tetap masuk ke field `eventtype`, dan semua tag dari semua event type itu tetap berlaku, sehingga event itu masuk setiap dataset yang constraint-nya terpenuhi. Lihat bagian 1.4 dan 2.7.

</details>

**4. Jelaskan ulang.** Jelaskan kepada network engineer NOC PT JAB dalam tiga kalimat apa bedanya event type dan tag, dan kenapa tag yang menentukan isi data model.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Event type itu kriteria search yang kita simpan, dan setiap event yang cocok dengannya otomatis dapat label nama event type itu, jadi anggap saja seperti filter tersimpan yang menandai log sejenis. Tag itu nama kategori yang kita tempelkan, bisa ke satu nilai field seperti nama host, bisa juga ke event type, dan satu tag bisa dipakai banyak event type sekaligus. Data model memilih anggotanya berdasarkan tag, bukan berdasarkan index, jadi kalau satu sumber log lupa diberi tag, laporan dan alert yang dibangun di atas data model akan tetap jalan tetapi angkanya kurang, dan tidak ada error yang muncul."

Kesalahan yang sering muncul:
- Menyebut event type sebagai saved search, padahal event type tidak dijalankan sendiri dan tidak boleh memuat pipe.
- Menyebut tag sebagai sekadar alat pencarian, sehingga peran strukturalnya di data model hilang.
- Lupa menyebut bahwa kekurangan tag tidak memberi error, yang justru bagian paling penting bagi orang yang membaca dashboard.

</details>

**5. Skenario keputusan.** PT JAB ingin menandai sekitar 4.000 alamat IP pelanggan korporat supaya bisa dipisahkan dari pelanggan broadband di semua search. Mana yang kamu pakai?

- A. Tag pada pasangan field dan value, satu tag `korporat` untuk 4.000 nilai `src`.
- B. Lookup CSV berisi daftar IP dan atributnya, dengan pemilik dan jadwal pembaruan.
- C. Satu event type per blok alamat, lalu semuanya diberi tag `korporat`.

<details><summary>Jawaban</summary>

B. Untuk jumlah nilai sebesar itu dan daftar yang terus berubah, dokumentasi sendiri menyarankan field lookup, bukan tag. Lookup juga memberi tempat untuk atribut tambahan seperti nama pelanggan dan tingkat layanan, yang tidak bisa dibawa oleh tag. A keliru karena setiap nilai baru harus ditambahkan sebagai pasangan baru dan tidak ada validasi, sehingga daftar sebesar itu cepat menjadi tidak dapat dipercaya. C lebih buruk lagi: event type dievaluasi terhadap setiap event di app itu, jadi puluhan event type berbasis blok alamat menambah ongkos ke semua search sekaligus. Lihat bagian 1.5 dan 1.8.

</details>

**6. Pertanyaan jebakan.** Untuk mencari kegagalan otentikasi di seluruh sumber yang sudah CIM-compliant, rekanmu menulis `tag=authentication tag=failure`. Apa yang akan terjadi?

<details><summary>Jawaban</summary>

Hasilnya kosong, atau setidaknya jauh lebih kecil dari yang diharapkan, karena di CIM 6.4 `failure` bukan tag. Tag yang berlaku untuk data model Authentication adalah `authentication` untuk dataset induknya, lalu `default`, `cleartext` atau `insecure`, dan `privileged` untuk dataset anaknya. Status otentikasi adalah nilai field `action`, dengan nilai yang diharapkan `success`, `failure`, `pending`, dan `error`. Bentuk yang benar adalah `tag=authentication action=failure`. Lihat bagian 1.7 dan 2.5.

</details>

**7. Interview question (English).** "You have authentication logs from four different vendors. How would you make one detection cover all of them, and how would you verify your coverage?"

<details><summary>Sample answer</summary>

"I would stop writing the vendor into the detection and write it into the data instead. For each source I create an event type whose search is just the matching criteria, no pipes and no subsearch, because an event type has to be answerable for a single event. Then I tag all four event types with the CIM tag, `authentication` in this case, so the detection can start from `tag=authentication action=failure` rather than from a list of indexes, and the fifth source we onboard next month is covered as soon as its event type carries the same tag. Verification is the part people skip, so I run a coverage search, something like `stats count by eventtype tag::eventtype`, and compare it against a straight count over the indexes; if the data model is involved I also compare `datamodel Authentication` against the raw count, because a missing tag never produces an error, it just produces a smaller number, and a smaller number looks like a quiet night. In one environment that gap was about twenty three percent of authentication events, all from the cloud identity source, invisible to every detection built on the data model. I keep that coverage search as a scheduled report rather than a one-off check, because tags and event types are edited by people and drift quietly."

What makes this answer strong: it moves the vendor-specific part out of the detection and into reusable knowledge objects, names the real constraint on event type definitions, knows that CIM membership comes from tags rather than indexes, distinguishes the tag from the `action` field value, and treats coverage as something measured and monitored rather than assumed.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Splunk Enterprise 10.6 Knowledge Manager Manual: About event types | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/event-types/about-event-types | primer | diakses 2026-10-14 | Tinggi. Definisi event type, letaknya di urutan operasi search-time (setelah lookup, sebelum tag), larangan pipe dan subsearch serta rujukan report, larangan merujuk tag, pemrosesan menurut priority lalu leksikografis, `eventtype` multivalue, ongkos search, saran memakai macro untuk penyingkat, contoh tag event type dengan `tag::eventtype` |
| S2 | Splunk Enterprise 10.6 Knowledge Manager Manual: Define event types in Splunk Web | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/event-types/define-event-types-in-splunk-web | primer | diakses 2026-10-14 | Tinggi. Alur Save As > Event Type dan Settings > Event Types > New, kolom Name, Search String, Tag(s), Color, Priority, Destination App, path penyimpanan di direktori user dan perpindahannya saat dibagikan, pemakaian `eventtype=` di search |
| S3 | Splunk Enterprise 10.6 Knowledge Manager Manual: About event type priorities | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/event-types/about-event-type-priorities | primer | diakses 2026-10-14 | Tinggi. Urutan daftar event type pada event yang dibuka, pemilihan warna menurut priority terbaik, tidak ada warna untuk event type yang dikelompokkan dengan `transaction` |
| S4 | Splunk Enterprise 10.6 Admin Manual: eventtypes.conf | https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.6/configuration-file-reference/10.6.0-configuration-file-reference/eventtypes.conf | primer | diakses 2026-10-14 | Tinggi. Atribut `search`, `disabled`, `priority` 1 sampai 10, daftar nilai `color`, `description`, atribut `tags` ditandai DEPRECATED, daftar isi search yang tidak diizinkan |
| S5 | Splunk Enterprise 10.6 Knowledge Manager Manual: About tags and aliases | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/tags/about-tags-and-aliases | primer | diakses 2026-10-14 | Tinggi. Tag pada kombinasi field dan value termasuk `eventtype`, pola satu tag banyak nilai dan banyak tag satu nilai, contoh boolean dengan tag, saran memakai lookup untuk puluhan ribu nilai, tag sebagai operasi search-time terakhir dalam urutan ASCII |
| S6 | Splunk Enterprise 10.6 Knowledge Manager Manual: Define and manage tags in Settings | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/tags/define-and-manage-tags-in-settings | primer | diakses 2026-10-14 | Tinggi. Tiga halaman List by field value pair, List by tag name, dan All unique tag objects; tombol New di dua halaman pertama; tidak ada validasi pasangan field dan value; beda mematikan dan menghapus tag; perilaku per app |
| S7 | Splunk Enterprise 10.6 Knowledge Manager Manual: Tag event types | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/tags/tag-event-types | primer | diakses 2026-10-14 | Tinggi. Satu event type bisa punya banyak tag, langkah menambah tag dari Settings > Event types, sintaks `tag=<nama>` dan `tag::<field>=<nama>`, contoh wildcard `tag::host=*local*`, catatan permission dan keterikatan app |
| S8 | CIM 6.4: Authentication data model | https://help.splunk.com/en/data-management/common-information-model/6.4/data-models/authentication | primer | diakses 2026-10-14 | Tinggi. Tag sebagai constraint, tag per dataset (`authentication`, `default`, `cleartext` atau `insecure`, `privileged`), nilai yang diharapkan untuk field `action` |
| S9 | Splunk Enterprise 10.6 Search Reference: tags | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/tags | primer | diakses 2026-10-14 | Tinggi. Sintaks dan opsi `outputfield`, `inclname`, `inclvalue`, `allowed_tags`; format keluaran; sifat streaming dan saran menaruh `stats` lebih dulu. Konvensi nama field keluaran di teks dan di contoh tidak konsisten |
| S10 | Splunk Enterprise 10.6 Knowledge Manager Manual: Automatically find and build event types | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/event-types/automatically-find-and-build-event-types | primer | diakses 2026-10-14 | Tinggi. Langkah utilitas Build Event Type lewat Event Actions, sidebar Event type features, tombol Test, kolom Style dan Priority, saran memakai `head` untuk mempercepat `findtypes` |
| S11 | Splunk Enterprise 10.4 Knowledge Manager Manual: Tag the host field | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.4/tags/tag-the-host-field | primer | diakses 2026-10-14 | Tinggi untuk alur Edit Tags dari hasil search dan pemisah nilai di kolom Tag(s). Halaman versi 10.6 tidak ditemukan saat pemeriksaan, jadi langkahnya dicocokkan ke UI versi-mu |
| S12 | Use the CIM to normalize data at search time (dokumentasi CIM 6.1) | https://help.splunk.com/en/data-management/common-information-model/6.1/using-the-common-information-model/use-the-cim-to-normalize-data-at-search-time | primer | diakses 2026-10-07 | Tinggi. Alur normalisasi: konfigurasi tag lewat event type lalu verifikasi `tag::eventtype`. Halaman versi 6.1; dipakai juga di Day 23 |
| S13 | Splunk Threat Research: WinEvent Scheduled Task Created to Spawn Shell | https://research.splunk.com/endpoint/203ef0ea-9bd8-11eb-8201-acde48001122/ | primer | diakses 2026-10-14 | Tinggi. Nilai macro `wineventlog_security` yang merujuk `eventtype="wineventlog_security"`, dipakai di Day ini sebagai bukti bahwa detection resmi bergantung pada event type |
| S14 | Splunk Enterprise 10.6 Admin Manual: tags.conf | https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.6/configuration-file-reference/10.6.0-configuration-file-reference/tags.conf | primer | diakses 2026-10-14 | Tinggi. Format stanza `[<fieldname>=<value>]`, satu tag per baris dengan `enabled` atau `disabled`, larangan tanda kutip, saran URL encoding, tidak ada file default, perlu restart |
| S15 | Splunk Enterprise 10.6 Search Reference: findtypes | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/findtypes | primer | diakses 2026-10-14 | Tinggi. Sintaks, `max` default 10, `notcovered`, `useraw`, batas analisis 5.000 event. Nama kolom keluaran tidak didokumentasikan |

**Catatan sumber:** semua angka di keluaran ilustrasi disusun agar konsisten dengan tabel dasar di awal bagian 2 dan bisa dijumlahkan ulang, tetapi bukan hasil eksekusi. Pernyataan bahwa event type tidak boleh merujuk event type lain tidak ada di dokumentasi; yang ada hanya keterangan bahwa urutan pemrosesan ditentukan priority lalu leksikografis [S1], jadi saran menghindarinya di bagian 1.3 adalah kesimpulan dari fakta itu dan perlu diuji sendiri bila kamu memang membutuhkannya. Nama sourcetype dan field untuk sign-in Entra ID di bagian 2.2 mengikuti pola add-on Microsoft dan harus dicocokkan dengan add-on yang terpasang. Alur Edit Tags dari hasil search dirujuk ke halaman versi 10.4 karena halaman 10.6 untuk topik itu tidak ditemukan saat pemeriksaan [S11]. Perbedaan antara atribut `tags` yang DEPRECATED di `eventtypes.conf` [S4] dan kolom Tag(s) yang masih ada di UI [S2][S7] adalah ketidakcocokan antar halaman dokumentasi resmi, bukan kesimpulan; perilaku persisnya di versi-mu perlu dicek di lab sebelum memilih satu jalur untuk seluruh tim.
