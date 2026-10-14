---
day: 15
title: 'Field Extractor dan sharing knowledge object: dari regex sekali pakai menjadi field milik tim'
researched_on: 2026-10-14
versions_checked: 'Splunk Enterprise 10.6 (Knowledge Manager Manual: Build field extractions with the field extractor, Use the Field extractions page, Configure advanced extractions with field transforms, The sequence of search-time operations, Manage knowledge object permissions, Manage orphaned knowledge objects, When Splunk software extracts fields; Search Reference: rex); ES 8.7.0; CIM 6.4'
---

# Day 15: Field Extractor dan sharing knowledge object

Cakupan: membuat field extraction search-time lewat wizard Field Extractor dengan metode regex dan delimiter, memeriksa di mana hasilnya tersimpan, lalu mengatur permission dan kepemilikan supaya extraction itu dipakai seluruh tim dan tidak mati bersama akun pembuatnya.

## Ide inti

Regex yang kamu tulis di search bar hanya hidup selama search itu berjalan. Begitu kamu menutup tab, field yang kamu buat hilang, dan orang berikutnya yang menangani sumber log yang sama mulai dari nol lagi. Field extraction adalah jawabannya: aturan parsing yang disimpan sebagai knowledge object, dijalankan otomatis setiap kali seseorang men-search sourcetype itu, tanpa ada yang perlu menyalin regex apa pun. Field Extractor adalah wizard yang membuat aturan itu dari satu contoh event, sehingga analyst yang tidak punya akses ke file konfigurasi tetap bisa membuatnya.

Separuh Day ini soal wizard, separuh lainnya soal siapa yang bisa melihat hasilnya, dan bagian kedua itu yang lebih sering menjatuhkan orang. Knowledge object baru hanya terlihat oleh pembuatnya [S5]. Untuk saved search, akibatnya kelihatan: orang lain tidak menemukan report-mu di daftar. Untuk field extraction, akibatnya tidak kelihatan sama sekali. Field yang private tidak memunculkan error bagi orang lain, tidak memunculkan peringatan, dan tidak memunculkan tanda apa pun; search mereka hanya mengembalikan nol baris, persis seperti kalau memang tidak ada aktivitas yang cocok. Detection terjadwal yang menyaring field itu akan berjalan tenang setiap jam, tidak pernah menemukan apa pun, dan tidak pernah mengeluh.

Dua analogi yang dipakai di Day ini sudah kamu kenal. Field Extractor adalah wizard pembuat parser dari contoh log, dengan batas yang sama seperti semua wizard seperti itu: regex yang dihasilkan dari satu baris contoh hampir selalu terlalu sempit atau terlalu longgar untuk baris lain, jadi hasilnya harus diuji dengan sample lain sebelum disimpan. Permission knowledge object adalah tiga tingkat yang juga ada di tempat kerja mana pun: draft pribadi, dokumen yang dibagikan ke tim, dan dokumen yang dipakai seluruh organisasi. Batas analoginya ada di kepemilikan. Dokumen tim yang penulisnya resign tetap bisa dibaca; objek Splunk yang pemiliknya dihapus menjadi yatim, dan yang terjadwal berhenti berjalan karena scheduler tidak punya pemilik yang rolenya bisa dipakai untuk menghitung kuota [S6].

```
RAW EVENT (sourcetype jab:vpnlegacy)
  |
  +- rex di search bar      : field ada di satu search ini saja
  |
  +- FIELD EXTRACTOR (5 langkah)
       1 Select sample      pilih sourcetype atau source, lalu satu event contoh
       2 Select method      Regular expression  |  Delimiters
       3a Select fields     (regex) sorot nilai, beri nama, tambah sample
       3b Rename fields     (delimiter) tentukan pemisah, ganti nama field
       4 Validate fields    (regex) tandai hasil yang salah sebagai counterexample
       5 Save               beri nama extraction, atur permission
  |
  +- tersimpan di props.conf pada search head
       inline          : EXTRACT-<class>
       uses transform  : REPORT-<class> + stanza di transforms.conf
  |
  +- PERMISSION menentukan siapa mendapat field itu
       private  : hanya pembuatnya            (orang lain: field tidak ada)
       app      : semua yang memakai app itu
       global   : semua app  (Display for = All apps)
  |
  +- OWNER menentukan apakah objek tetap hidup
       akun pemilik dihapus -> objek yatim -> yang terjadwal berhenti
```

Situasi yang dipakai sepanjang Day ini: Senin pagi di PT Jaringan Anak Bangsa (PT JAB, ISP menengah fiktif, SOC internal satu lantai dengan NOC). Dua sumber log baru masuk pekan lalu dan keduanya tidak punya add-on yang dirawat: concentrator VPN lama untuk akses vendor di `jkt-vpnl01` (sourcetype `jab:vpnlegacy`, index `vpn`) dan firewall POP Bandung dari vendor kedua (sourcetype `jab:fw:pop`, index `firewall`). Tiket SOC-2026-0231 dibuka akhir pekan karena akun vendor `vendor.bnet01` login dari `203.0.113.45` setelah 147 percobaan gagal, dan triage-nya terhambat karena tidak ada satu pun field yang bisa dipakai menyaring. Detection engineer menulis di grup:

> "Dua sumber baru itu masih mentah, semua orang menyalin regex dari chat. Tolong buat field extraction yang benar untuk keduanya, pakai Field Extractor saja supaya tercatat di Splunk dan bukan di catatan pribadi. Syaratnya tiga: field-nya harus muncul untuk semua orang di app SOC, detection terjadwal yang dimiliki akun `svc_soc` harus bisa memakainya, dan jangan sampai extraction ini mati waktu kontrak anak magang yang bantu onboarding selesai bulan depan."

Permintaan itu memuat enam pertanyaan:

1. Kapan sebuah regex sebaiknya berhenti menjadi `rex` dan menjadi field extraction yang disimpan?
2. Apa saja langkah Field Extractor, dan apa yang sebenarnya diputuskan di setiap langkah?
3. Kapan metode regex dipakai dan kapan metode delimiter, dan apa yang berbeda dari hasilnya?
4. Di mana hasil extraction itu tersimpan, dan bagaimana memeriksanya kembali nanti?
5. Apa arti private, app, dan global untuk sebuah field extraction, dan kenapa salah pilih di sini tidak memunculkan error?
6. Apa yang terjadi pada extraction dan detection ketika akun pemiliknya dihapus, dan bagaimana mencegahnya?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3 dan 1.4, pertanyaan 4 di bagian 1.5, pertanyaan 5 di bagian 1.6, dan pertanyaan 6 di bagian 1.7. Bagian 2 mengerjakan keduanya sampai field-nya terpakai di search milik orang lain.

**Kapan relevan:** setiap kali sebuah sumber log masuk tanpa add-on yang menormalisasi field-nya, setiap kali kamu melihat regex yang sama disalin ulang di beberapa dashboard atau detection, dan setiap kali kamu menyerahkan hasil kerjamu ke tim supaya tidak bergantung pada satu orang.
**Kapan bukan jawaban:** untuk pertanyaan sekali pakai saat investigasi, `rex` lebih cepat dan tidak perlu izin siapa pun (Day 11). Untuk mengubah nama field yang sudah ada menjadi nama yang sama antar vendor, yang kamu butuhkan field alias atau calculated field, bukan extraction baru (Day 16). Untuk sumber yang add-on resminya ada, pasang add-on itu dan verifikasi, karena menulis extraction sendiri di atas add-on yang juga mengekstrak field yang sama hanya menambah dua sumber kebenaran (Day 05 bagian 1.1). Dan untuk field yang harus bisa dipakai di `tstats` sebagai indexed field, extraction search-time bukan jalannya; itu keputusan index-time (Day 28).

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dasar dari Day 01 sampai Day 14 (index, sourcetype, source, host, `_raw`, search mode, fields sidebar, pipeline, `rex`, `eval`) tidak diulang di sini. Tabel ini hanya memuat istilah yang dipakai Day ini; kolom padanan memakai hal yang sudah kamu kerjakan di NOC dan SOC.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Knowledge object | Objek yang menambah arti ke data tanpa mengubah data: field extraction, field alias, calculated field, lookup, event type, tag, macro, report, dashboard | Konfigurasi di konsol yang bukan data, misalnya template laporan dan daftar perangkat |
| Field extraction search-time | Aturan parsing yang dijalankan setiap kali log dibaca, bukan saat disimpan | Parser di konsol yang dipasang sekali lalu berlaku untuk semua orang |
| Field Extractor | Wizard di Splunk Web yang membuat regex atau aturan delimiter dari satu event contoh | Wizard pembuat parser dari contoh log |
| Sample event | Event contoh yang dipakai wizard sebagai dasar regex | Satu baris log yang dipakai menguji parser |
| Required text | Teks yang kamu wajibkan ada di event supaya extraction hanya berlaku untuk event sejenis | Filter baris sebelum di-parse |
| Counterexample | Nilai hasil ekstraksi yang kamu tandai salah supaya wizard memperbaiki regexnya | Kasus negatif saat menguji parser |
| Inline extraction (`EXTRACT-<class>`) | Extraction yang regexnya ditulis langsung di `props.conf` | Aturan parsing yang ditulis di satu tempat dan dipakai satu sumber |
| Transform-based extraction (`REPORT-<class>`) | Extraction yang menunjuk satu atau beberapa stanza di `transforms.conf` | Fungsi parsing bersama yang dipanggil beberapa sumber |
| Field transform | Stanza `transforms.conf` berisi regex atau definisi delimiter yang bisa dipakai ulang | Library parser milik tim |
| `DELIMS` dan `FIELDS` | Setting transform untuk data berpemisah: pemisahnya dan daftar nama kolomnya | Membaca CSV dengan daftar nama kolom di sebelahnya |
| `class` sebuah extraction | Label unik di belakang `EXTRACT-` atau `REPORT-` | Nama aturan di konfigurasi perangkat |
| `<spec>` sebuah stanza | Sasaran extraction: sourcetype, `host::<host>`, atau `source::<source>` | Cakupan aturan: per jenis perangkat, per perangkat, atau per file |
| Permission private, app, global | Tiga tingkat cakupan knowledge object | Draft pribadi, dibagikan ke tim, dipakai seluruh organisasi |
| `Display for` | Pengaturan cakupan di dialog Permissions, bernilai App atau All apps | Scope publikasi sebuah dokumen |
| Read dan Write | Hak melihat dan menjalankan objek, dan hak mengubah definisinya | Hak baca dan hak ubah pada dokumen tim |
| App context | App tempat objek disimpan dan dari mana ia berlaku | Folder tim tempat konfigurasi disimpan |
| Owner | Akun yang tercatat sebagai pemilik objek | Pemilik tiket |
| Objek yatim (orphaned knowledge object) | Objek yang pemiliknya bukan lagi akun yang valid | Tiket yang pemiliknya sudah resign dan tidak diserahkan |
| Capability | Izin granular yang menempel pada role, misalnya `edit_monitor` | Privilege level di konsol perangkat |

### 1.1 Dari `rex` ke field extraction yang disimpan

Permintaan detection engineer dimulai dari gejala yang khas: regex disalin ulang di chat. Itu tanda bahwa aturan parsing sudah dipakai berulang, dan sesuatu yang dipakai berulang sebaiknya tinggal di Splunk, bukan di kepala orang.

`rex` dan field extraction memakai mesin regex yang sama dan menghasilkan field dengan cara yang sama lewat named capture group. Yang berbeda bukan regexnya, melainkan jangkauannya. Tabel ini memuat perbedaan yang menentukan pilihan; cari baris yang paling cocok dengan situasimu.

| Hal | `rex` di search bar | Field extraction yang disimpan |
|---|---|---|
| Jangkauan | Hanya search yang menuliskannya | Semua search pada `<spec>` itu, untuk semua pemakai yang punya izin [S2] |
| Siapa yang mendapat field | Hanya yang menjalankan search itu | Semua yang izinnya mencakup objek itu [S5] |
| Letak di pipeline | Di posisi `rex` ditulis, jadi field belum ada sebelum baris itu | Sebelum command pertama, jadi field sudah ada untuk disaring di awal [S4] |
| Bisa menyaring di awal search | Tidak, filter harus ditulis setelah `rex` | Ya, bisa langsung `jab_user=vendor.bnet01` di baris pertama |
| Sumber datanya | Field apa pun lewat `field=`, default `_raw` [S7] | `_raw` secara default; field lain lewat `SOURCE_KEY` di transform [S3] |
| Perawatan | Tidak ada; setiap pemakai bertanggung jawab atas salinannya | Satu tempat, satu pemilik, satu riwayat perubahan |
| Izin yang dibutuhkan | Tidak ada selain bisa men-search | Butuh izin membuat objek, dan admin atau power untuk membagikannya [S5] |
| Risiko khasnya | Regex bercabang menjadi beberapa versi yang hasilnya berbeda | Satu kesalahan regex berlaku untuk semua orang sekaligus |

Baris ketiga dan keempat sering diremehkan padahal dampaknya ke performa paling besar. Dengan `rex`, Splunk harus membaca semua event yang lolos filter sebelumnya, baru menyaring hasil ekstraksi. Dengan extraction yang disimpan, nama field itu sudah bisa dipakai di baris pertama search, dan Splunk memakainya untuk mempersempit pembacaan sejak awal (Day 14).

Satu hal yang perlu kamu tahu tentang perilaku bawaan sebelum menulis extraction apa pun: Splunk sudah mencoba mengekstrak field sendiri. Dengan field discovery aktif, Splunk mengekstrak sampai 100 pasangan `key=value` pertama yang ditemukannya, ditambah field yang disebut di dalam search, ditambah extraction yang sudah dikonfigurasi [S9]. Artinya untuk log yang memang berbentuk `key=value`, sebagian field muncul tanpa kamu membuat apa pun, dan pekerjaanmu tinggal menormalkan namanya (Day 16). Field Extractor diperlukan justru untuk log yang bentuknya posisional atau berpemisah, seperti dua sumber baru di PT JAB.

### 1.2 Lima langkah Field Extractor dan apa yang diputuskan di tiap langkah

Field Extractor punya lima langkah, dan alurnya bercabang di langkah kedua sesuai metode yang dipilih [S1]:

1. **Select sample.** Pilih sourcetype atau source yang memuat field itu, lalu pilih satu event contoh. Langkah ini berlaku untuk kedua metode.
2. **Select method.** Pilih `Regular expression` atau `Delimiters`. Dokumentasi menempatkan regex untuk data tidak terstruktur dan delimiter untuk data terstruktur yang punya header [S1].
3. **Select fields**, hanya untuk metode regex. Kamu menyorot nilai di event contoh, memberinya nama, dan wizard membuat regex yang cocok. Di langkah ini kamu juga bisa menambah sample event, menetapkan required text, meninjau hasil, dan menyunting regexnya sendiri [S1].
4. **Rename fields**, hanya untuk metode delimiter. Kamu menetapkan pemisah yang memisahkan setiap field, lalu mengganti nama field yang ditemukannya [S1].
5. **Validate fields**, hanya untuk metode regex. Kamu meninjau hasil ekstraksi dan menandai nilai yang salah sebagai counterexample supaya akurasinya naik [S1].
6. **Save**, untuk kedua metode. Kamu memberi nama field extraction itu, mengatur permission-nya, lalu menyimpan [S1].

Pintu masuk wizard ada beberapa, dan pilihan pintu menentukan apa yang bisa kamu kerjakan [S1]:

| Pintu masuk | Jalannya | Batasnya |
|---|---|---|
| Setelah menjalankan search | Gulir ke bawah fields sidebar lalu `Extract New Fields` | Hanya memakai event yang dikembalikan search itu |
| Dialog All Fields | Buka All Fields dari fields sidebar | Sama, hanya data hasil search itu |
| Menu Event Actions satu event | `Extract Fields` pada event yang dipilih | Sama |
| Halaman Field extractions | Settings > Fields > Field extractions lalu `Open field extractor` | Bisa memilih sourcetype apa pun di deployment |
| Halaman Home | Tautan extract fields di bawah ikon Add Data | Butuh capability `edit_monitor`, misalnya role Admin |
| Setelah menambah data | Lanjutan dari Add Data | Butuh `edit_monitor`; input harus punya sourcetype tetap, dan dokumentasi menyarankan menunggu sekitar 30 detik setelah input disimpan |

Dua batas yang perlu diingat sejak awal. Pertama, wizard tidak menawarkan apa pun bila sourcetype input diset `Automatic`, karena event dari satu input bisa berakhir dengan sourcetype yang berbeda-beda [S1]. Kedua, kalau kamu masuk dari fields sidebar, wizard hanya melihat event yang dikembalikan search tadi, jadi varian event yang tidak ikut terambil tidak akan pernah menjadi bahan uji. Untuk bekerja di seluruh sourcetype, masuk dari halaman Field extractions di Settings [S1].

### 1.3 Metode regex: memilih sample, menambah sample, dan counterexample

Log VPN vendor PT JAB berbentuk posisional, bukan `key=value`, jadi metode regex yang dipakai.

Yang penting dipahami soal langkah Select fields: wizard tidak mengerti format log, ia hanya melihat teks di sekitar nilai yang kamu sorot. Kalau kamu menyorot nama akun di event yang berbunyi `AUTH FAIL vendor.bnet01 from ...`, regex yang dihasilkan biasanya memakai kata `FAIL` sebagai jangkar, sehingga event yang berbunyi `AUTH OK` tidak akan ikut terekstrak. Gejalanya halus: field muncul, isinya benar untuk sebagian event, dan sebagian lain diam-diam kosong.

Karena itu tiga fasilitas di langkah ini bukan tambahan, tetapi bagian dari pekerjaan [S1]:

- **Menambah sample event.** Berikan contoh dari setiap varian yang kamu tahu ada, bukan hanya varian yang sedang kamu selidiki. Untuk log autentikasi, minimal satu sukses dan satu gagal.
- **Required text.** Teks yang kamu wajibkan ada supaya extraction hanya berlaku untuk event sejenis. Ini yang menjaga regex tidak dipaksakan ke baris lain yang bentuknya berbeda di sourcetype yang sama, misalnya baris `session closed` yang tidak punya nama akun.
- **Menyunting regex sendiri.** Regex buatan wizard hampir selalu bisa dipersempit atau diperlonggar dengan satu suntingan kecil. Di sini pengetahuan regex dari Day 11 langsung terpakai.

Langkah Validate fields adalah tempat kasus negatif diuji. Kamu meninjau hasil ekstraksi lalu menandai nilai yang salah sebagai counterexample, dan wizard memperbaiki regexnya supaya nilai itu tidak lagi ikut [S1]. Pola kesalahan yang paling sering tertangkap di sini adalah nilai yang terlalu longgar: pemisah `[^\s]+` yang ikut menelan tanda baca, atau kata pengganti seperti `(unknown` yang masuk ke field nama akun karena perangkat menulis `AUTH FAIL (unknown user)` ketika akunnya tidak ada.

Satu hal yang tidak dilakukan wizard: ia tidak menguji regex terhadap data lama. Validasi di wizard memakai sample yang ada di layar. Format log berubah ketika firmware perangkat naik versi, dan extraction yang lolos validasi hari ini bisa berhenti cocok setelah upgrade POP. Itu alasan bagian 2.5 menutup pekerjaan dengan satu search penghitung cakupan, bukan dengan melihat hasil wizard.

### 1.4 Metode delimiter: data berpemisah dan batasnya

Log firewall POP Bandung masuk sebagai satu baris berpemisah koma dengan urutan kolom yang didokumentasikan vendor. Untuk bentuk seperti ini, menulis regex adalah pekerjaan sia-sia: metode `Delimiters` cukup diberi tahu pemisahnya, lalu kamu mengganti nama field yang ditemukannya [S1].

Yang perlu diketahui tentang hasilnya:

- Nama bawaan yang diberikan wizard bersifat berurutan dan tidak bermakna, jadi langkah Rename fields bukan kosmetik. Nama yang tidak diganti akan muncul di fields sidebar semua orang sebagai nama tanpa arti, dan nama seperti itu akan dipakai orang lain di dashboard, lalu sulit dibersihkan.
- Di tingkat konfigurasi, data berpemisah dikerjakan oleh field transform dengan `DELIMS` dan `FIELDS`: `DELIMS` menggantikan `REGEX` untuk pemisah ASCII dan ditulis dalam tanda kutip ganda, sedangkan `FIELDS` memberi daftar nama kolom dalam urutan ekstraksi untuk event yang hanya berisi nilai tanpa nama field [S3].
- Pemisah non-ASCII tidak bisa dipakai di `DELIMS` dan harus memakai `REGEX` [S3]. Begitu pula bila nilainya bisa memuat tanda kutip ganda yang tidak di-escape; dokumentasi transform menyebut kasus itu sebagai alasan memakai `REGEX` [S3].
- Jebakan yang paling sering muncul pada data berpemisah tidak disebut dokumentasi tetapi selalu terjadi di lapangan: satu nilai yang memuat pemisah di dalamnya akan menggeser semua kolom setelahnya. Nama aturan firewall yang mengandung koma cukup untuk membuat `dest_port` berisi nama protokol. Uji ini sendiri di lab dengan satu event yang sengaja dibuat seperti itu, lalu putuskan apakah sumbernya perlu dikonfigurasi ulang atau extraction-nya perlu memakai regex.

Metode delimiter juga tidak punya langkah Validate [S1]. Tidak ada counterexample, tidak ada peninjauan hasil terhadap varian lain. Karena itu untuk data berpemisah, verifikasinya harus kamu kerjakan dengan search sendiri setelah extraction disimpan, dan yang paling berguna adalah menghitung berapa persen event yang kolomnya terisi lengkap.

### 1.5 Di mana hasilnya tersimpan dan bagaimana memeriksanya kembali

Pertanyaan keempat detection engineer penting karena pekerjaan ini akan diwarisi orang lain. Hasil wizard bukan file di laptopmu; ia stanza di `props.conf` pada tier search head [S4], dan Splunk Web punya halaman untuk melihatnya.

Halaman Settings > Fields > Field extractions memuat seluruh extraction search-time yang kamu buat atau yang izinmu memperbolehkan kamu lihat, untuk semua app di deployment [S2]. Tiga kolomnya yang perlu dibaca:

| Kolom | Isinya | Yang kamu cari di situ |
|---|---|---|
| Name | `<spec> : EXTRACT-<class>` atau `<spec> : REPORT-<class>`, dengan `<spec>` berupa sourcetype, `host::<host>`, atau `source::<source>` [S2] | Apakah extraction menyasar sourcetype, host, atau source, dan apa nama kelasnya |
| Type | `inline` bila seluruhnya didefinisikan di `props.conf`, atau `uses transform` bila menunjuk stanza `transforms.conf` [S2] | Apakah masih ada objek kedua (transform) yang izinnya perlu diatur juga |
| Extraction/Transform | Regexnya untuk inline, atau nama stanza transform yang dirujuk [S2] | Isi aturannya, tanpa membuka file |

Dari halaman itu kamu bisa membuat extraction baru lewat tombol `New`, mengubah permission, dan menghapus extraction kecuali izin app-mu tidak memperbolehkan atau objeknya objek default; knowledge object default tidak bisa dihapus [S2]. Form extraction baru menanyakan empat hal: destination app (default app yang sedang kamu buka), nama (spasi menjadi garis bawah), sasaran berupa sourcetype, source, atau host, dan tipe `Inline` dengan regexnya atau `Uses transform` dengan nama transform yang dipisah koma [S2]. Dengan izin write tambahan, kamu bisa menyunting regex sebuah inline extraction, atau menambah dan menghapus transform yang dirujuk sebuah extraction berbasis transform [S2].

Dua batas halaman ini perlu diketahui sebelum kamu berjanji apa pun ke tim. Index-time field extraction tidak bisa dikelola di Splunk Web dan harus disunting langsung di `props.conf` dan `transforms.conf` [S2], dan itu memang pekerjaan yang berbeda dengan konsekuensi berbeda (Day 28). Lalu, menghapus sebuah extraction bisa merusak knowledge object yang bergantung padanya, termasuk event type, saved search, dan dashboard [S2]. Daftar dependensi itu tidak ditampilkan di layar, jadi sebelum menghapus, cari nama field itu di saved search dan dashboard lebih dulu.

Kapan sebuah extraction sebaiknya berbasis transform, bukan inline? Dokumentasi transform menyebut setting dan batasnya, dan dari situ kasus yang jelas membutuhkan transform [S3]: regex yang sama harus berlaku untuk beberapa sourcetype, host, atau source; data berpemisah yang perlu `DELIMS` dan `FIELDS`; pemisah non-ASCII; nilai yang perlu diambil dari field selain `_raw` lewat `SOURCE_KEY`, yang defaultnya memang `_raw`; dan field yang perlu menjadi multivalue lewat `MV_ADD = true`, karena nilai default `false` menyimpan nilai pertama dan membuang sisanya. Satu transform bisa dipakai beberapa extraction, dan satu extraction bisa menunjuk beberapa transform yang ditulis dipisah koma setelah `REPORT-<class>` [S3].

Setting `MV_ADD` itu pantas digarisbawahi untuk pekerjaan keamanan. Log yang memuat beberapa nilai untuk hal yang sama, misalnya beberapa alamat tujuan di satu baris, akan kehilangan semua nilai kecuali yang pertama bila `MV_ADD` dibiarkan default [S3]. Kehilangan itu tidak terlihat di hasil search, karena field-nya tetap terisi.

### 1.6 Permission: private, app, dan global

Syarat pertama detection engineer berbunyi "field-nya harus muncul untuk semua orang di app SOC". Itu pekerjaan dialog Permissions, dan ini bagian yang paling sering dilewatkan karena wizard sudah terasa selesai sebelum sampai ke sana.

Aturan yang perlu dipegang [S5]:

- Objek baru hanya tersedia untuk pembuatnya. Extraction yang dibuat lewat Field Extractor atau lewat halaman Field extractions tetap private sampai dibagikan [S2].
- Dialog Permissions dibuka dari halaman daftar objek, lewat tautan `Permissions`, atau lewat `Edit > Edit Permissions`, atau `Manage > Edit Permissions`, tergantung halamannya.
- `Display for` menentukan cakupan: `App` berarti hanya app pemilik objek, `All apps` berarti global.
- Bagian Permissions memuat daftar role ditambah baris `Everyone`, masing-masing dengan kotak `Read` dan `Write`. Read berarti bisa melihat dan menjalankan objek tanpa mengubah definisinya. Write berarti bisa melihat, memakai, dan mengubah definisinya. Tanpa keduanya, role itu tidak bisa melihat atau memakai objek tersebut.
- Secara default hanya role admin dan power yang bisa membagikan dan mempromosikan objek. Admin bisa mengubah permission objek apa pun; power hanya objek miliknya. Untuk memberi role lain kemampuan itu, izin app yang disunting lewat Manage Apps, bukan capability role.
- Mempromosikan objek ke `All apps` tidak otomatis memperluas hak mengubahnya. Cakupan dan hak edit adalah dua pengaturan terpisah.

Untuk field extraction, tiga tingkat itu punya arti yang sangat konkret, dan inilah yang membuat salah pilih di sini berbahaya:

| Tingkat | Siapa yang mendapat field itu | Gejala bila salah pilih |
|---|---|---|
| Private | Hanya pembuatnya | Search orang lain mengembalikan nol baris tanpa error; detection terjadwal milik akun lain tidak pernah menemukan apa pun |
| App | Semua pemakai app itu yang punya Read | Search dari app lain, termasuk app ES di search head terpisah, tidak melihat field itu |
| Global (`All apps`) | Semua app | Nama field bertabrakan dengan field bernama sama dari sumber lain bila namanya terlalu umum |

Perbedaan antara objek yang hilang dan field yang hilang pantas diucapkan sekali lagi. Saved search yang private membuat orang lain tidak menemukan report-nya, dan itu segera terasa. Field extraction yang private membuat orang lain mendapat hasil kosong, dan hasil kosong di SOC terlihat sama seperti kabar baik. Kalau sebuah detection terjadwal menyaring `jab_user="vendor.bnet01"` sementara extraction `jab_user` masih private milik orang lain, detection itu berjalan tepat waktu, tidak error, dan tidak pernah fire. Itu kegagalan yang paling mahal di seluruh Day ini.

Karena extraction berbasis transform punya dua objek, izinnya juga dua. [komunitas, belum terkonfirmasi] Di forum Splunk ada laporan bahwa membagikan extraction yang dibuat lewat UI tidak ikut membagikan transform yang dirujuknya, sehingga transform tetap private walaupun extraction-nya sudah global, dan laporan itu menyebut nomor known issue SPL-118752; ada juga kasus di mana stanza props-nya ternyata tersimpan di konteks user, bukan di app, dan baru berfungsi untuk semua orang setelah stanza itu dipindahkan ke app [S8]. Yang belum pasti adalah apakah kedua perilaku itu masih ada di 10.6, karena thread-nya lama. Yang bisa kamu lakukan tanpa menunggu kepastian: setelah membagikan extraction bertipe `uses transform`, buka juga halaman Field transformations dan periksa permission transform-nya [S2].

**Tanpa ES:** aturan permission di atas milik Splunk Enterprise, bukan fitur ES, jadi semuanya berlaku di instance tanpa ES. Yang berubah hanya jumlah tempat yang bisa pecah. Di PT JAB, ES berada di search head terpisah, sehingga extraction yang hanya dibagikan ke app SOC di search head biasa tidak akan terlihat oleh detection yang berjalan di search head ES. Field extraction search-time dikonfigurasi di tier search head [S4], jadi objeknya harus ada di search head yang menjalankan searchnya, dengan cakupan yang mencakup app yang dipakai di sana.

### 1.7 Kepemilikan dan objek yatim

Syarat ketiga detection engineer, "jangan sampai mati waktu kontrak anak magang selesai", adalah soal owner, bukan permission. Keduanya diatur di tempat berbeda dan gagal dengan cara berbeda.

Ketika sebuah akun dihapus atau dinonaktifkan, knowledge object yang dimilikinya tetap ada di sistem sebagai objek yatim, dan objek yatim bisa merusak search yang bergantung padanya, misalnya search yang merujuk lookup definition yang sudah yatim [S6]. Dampak yang paling tajam ada di objek terjadwal: scheduler tidak bisa menjalankan scheduled report tanpa pemilik yang valid, karena ia butuh role pemilik untuk menerapkan kuota search dan batas konkurensi [S6]. Report itu lalu berhenti berjalan tanpa suara, dan efek berantainya mengenai dashboard serta embedded search yang membacanya, termasuk celah di summary index [S6].

Empat cara menemukannya, dengan batas masing-masing [S6]:

| Cara | Jalannya | Batasnya |
|---|---|---|
| Pesan | Splunk menjalankan search harian untuk scheduled report yang yatim dan memasang pesan bila menemukan; klik `Messages` lalu tautan pesannya | Hanya scheduled report |
| Dashboard bawaan | Orphaned Scheduled Searches, Reports, and Alerts di app Search & Reporting, atau report Orphaned Searches, Reports And Alerts dari halaman Reports | Hanya objek terjadwal |
| Monitoring Console | Settings > Monitoring Console, tab Health Check, lalu `Start`, lalu baris Orphaned Scheduled Searches untuk melihat namanya | Butuh Monitoring Console yang sudah dikonfigurasi |
| Reassign Knowledge Objects | Settings > All configurations > Reassign Knowledge Objects lalu `Orphaned` | Satu-satunya cara yang menemukan semua jenis knowledge object, tetapi hanya objek yang dibagikan di tingkat app atau global |

Baris terakhir itu punya konsekuensi langsung untuk pekerjaan ini: field extraction yang yatim hanya akan muncul di halaman Reassign bila sebelumnya sudah dibagikan. Extraction yatim yang dulu private tidak akan muncul di mana pun, dan tidak ada pesan yang memberitahu. Selain itu, tidak satu pun dari keempat cara di atas bisa mendeteksi user yang dihapus lewat sistem autentikasi pihak ketiga [S6], yang justru lazim di organisasi yang memakai direktori terpusat.

Memindahkan kepemilikan hanya bisa dilakukan role Admin [S6]. Untuk satu objek, klik `Reassign` di kolom `Action`, lalu `Select an owner`, lalu `Save`. Untuk beberapa objek sekaligus sampai 100 buah, centang kotaknya, klik `Edit Selected Knowledge Objects`, pilih `Reassign`, lalu pilih pemilik dan simpan [S6]. Perlu diperiksa dulu sebelum menekan simpan, karena memindahkan kepemilikan saved search bisa mengubah data yang bisa diaksesnya [S6].

Objek yang sudah yatim dalam keadaan private tidak bisa dipindahkan dari UI. Dua jalan keluar yang disebut dokumentasi [S6]: membuat ulang akun pemilik lama sementara, memindahkan objeknya di halaman Reassign Knowledge Objects, lalu menonaktifkan kembali akun itu; atau memindahkan stanza objeknya secara manual dari `etc/users/<invalid_user>/search/local/<conf_file>` ke `etc/users/<valid_user>/search/local/<conf_file>`, yang mensyaratkan Splunk Enterprise, akses filesystem, tidak ada search head clustering, dan restart. Keduanya pekerjaan admin platform, bukan analyst, dan keduanya bisa dihindari dengan satu kebiasaan: memindahkan kepemilikan sebelum akunnya dihapus [S5].

Untuk scheduled search yang sudah yatim, pilihan tindakannya ditentukan tujuannya [S6]: supaya tetap berjalan sesuai jadwal, pindahkan ke pemilik baru; supaya hanya bisa dijalankan manual, hapus jadwalnya di Settings > Searches, reports, and alerts dan batasi hak edit supaya tidak dijadwalkan ulang orang lain; supaya berhenti selamanya, matikan atau hapus. Notifikasi orphaned search sendiri bisa dimatikan dengan menyetel `orphan_searches` menjadi `disabled` di stanza `[system_checks]` pada `limits.conf` [S6], dan itu sebaiknya tidak dilakukan di lingkungan SOC, karena pesan itu salah satu dari sedikit alarm bawaan tentang kesehatan objek.

## 2. Contoh dan langkah praktis di PT JAB

Semua keluaran di bagian ini adalah keluaran ilustrasi: angkanya disusun agar konsisten dengan tiket SOC-2026-0231 dan bisa dijumlahkan ulang, bukan hasil eksekusi. Semua rentang waktu memakai bentuk absolut atau snap-to jam supaya hasilnya bisa diulang, dan semua index memakai index PT JAB.

### 2.1 Memastikan field memang belum ada, dan seberapa banyak event yang terdampak

Langkah pertama bukan membuka wizard, tetapi memastikan apa yang benar-benar hilang. Kalau add-on sebenarnya terpasang dan hanya salah sourcetype, membuat extraction baru akan menambah masalah, bukan mengurangi.

**Tujuan:** melihat satu event mentah dan mengetahui field apa saja yang sudah ada untuk sourcetype baru itu.

```
index=vpn sourcetype=jab:vpnlegacy earliest=-24h@h latest=@h
| head 3
| table _time host _raw
```

Keluaran ilustrasi:

```
_time                 host         _raw
2026-10-14 01:12:44   jkt-vpnl01   sslvpn[5542]: AUTH FAIL vendor.bnet01 from 203.0.113.45 group VENDOR-NOC via portal (bad credentials) session 118342
2026-10-14 01:12:51   jkt-vpnl01   sslvpn[5542]: AUTH FAIL vendor.bnet01 from 203.0.113.45 group VENDOR-NOC via portal (bad credentials) session 118343
2026-10-14 01:19:02   jkt-vpnl01   sslvpn[5542]: AUTH OK vendor.bnet01 from 203.0.113.45 group VENDOR-NOC via portal assigned 10.10.250.37 session 118391
```

**Penjelasan tiap bagian:** `index` dan `sourcetype` membatasi pembacaan ke sumber yang ditanyakan. `head 3` membatasi biaya saat kamu hanya ingin melihat bentuk data. `table _raw` menampilkan teks aslinya, yang di tahap ini satu-satunya hal yang bisa diandalkan.

**Cara membaca hasil:** tidak ada satu pun pasangan `key=value` di baris itu, jadi ekstraksi otomatis Splunk tidak punya apa pun untuk dipungut [S9]. Yang bisa disaring hanya `host`, `_time`, dan kata-kata di `_raw`. Perhatikan juga bahwa event sukses memuat bagian `assigned 10.10.250.37` yang tidak ada di event gagal; perbedaan itu yang nanti menjadi sumber kesalahan regex.

**Variasi, memetakan ragam bentuk baris sebelum menulis regex:** hitung dulu ada berapa jenis baris di sourcetype itu, karena setiap jenis adalah kandidat varian yang harus diuji.

```
index=vpn sourcetype=jab:vpnlegacy earliest=-24h@h latest=@h
| rex field=_raw "sslvpn\[\d+\]:\s+(?<jenis>(?:AUTH (?:OK|FAIL))|[A-Z]+)"
| stats count BY jenis
```

Keluaran ilustrasi:

```
jenis        count
AUTH FAIL     1918
AUTH OK        412
SESSION      10150
```

Totalnya 12.480 event dalam 24 jam, dan hanya 2.330 di antaranya baris autentikasi. Angka 2.330 ini yang menjadi pembanding saat memeriksa cakupan extraction nanti; kalau extraction hanya mengisi field pada 1.918 event, berarti varian `AUTH OK` tidak ikut.

**Kapan gagal:** kalau `jenis` keluar kosong untuk semua event, format baris di instance-mu berbeda dari contoh di sini, dan yang harus kamu pakai adalah bentuk `_raw`-mu sendiri. Jangan menyalin regex contoh ke produksi tanpa mencocokkannya dengan satu event asli.

### 2.2 Prototipe dengan `rex` sebelum masuk wizard

Kebiasaan yang menghemat banyak waktu: bangun dulu regexnya di search bar, karena di situ siklus coba-ulangnya paling cepat dan kesalahannya tidak mengenai siapa pun.

**Tujuan:** mendapatkan regex yang mengekstrak akun, hasil autentikasi, alamat sumber, dan grup, lalu mengukur cakupannya sebelum disimpan sebagai objek.

```
index=vpn sourcetype=jab:vpnlegacy earliest=-24h@h latest=@h
| rex field=_raw "AUTH\s+(?<jab_result>OK|FAIL)\s+(?<jab_user>[\w.\-]+)\s+from\s+(?<jab_src>\d{1,3}(?:\.\d{1,3}){3})\s+group\s+(?<jab_group>\S+)"
| stats count AS total, count(jab_user) AS ada_user, count(jab_src) AS ada_src BY jab_result
```

**Penjelasan tiap bagian:** `(?<jab_result>OK|FAIL)` menangkap dua varian sekaligus, sehingga regexnya tidak terjangkar pada satu di antaranya. `[\w.\-]+` untuk nama akun sengaja tidak memakai `\S+`, supaya teks seperti `(unknown` yang dipakai perangkat saat akun tidak dikenal tidak ikut tertangkap. `\d{1,3}(?:\.\d{1,3}){3}` membatasi tangkapan alamat ke bentuk alamat IPv4, bukan sembarang teks. Awalan `jab_` dipakai supaya jelas bahwa field ini buatan sendiri dan bukan field dari add-on; penyamaan nama ke nama standar lintas vendor dikerjakan di Day 16, bukan di sini.

Keluaran ilustrasi:

```
jab_result   total   ada_user   ada_src
FAIL          1918       1832       1918
OK             412        412        412
```

**Cara membaca hasil:** `jab_src` terisi di seluruh 2.330 baris autentikasi, sedangkan `jab_user` kosong di 86 baris gagal (1.918 dikurangi 1.832). Delapan puluh enam baris itu adalah varian `AUTH FAIL (unknown user)`, dan kosong di situ justru benar: tidak ada nama akun yang bisa dilaporkan, dan mengisinya dengan teks `(unknown` akan membuat `stats count BY jab_user` memunculkan akun yang tidak pernah ada. Inilah bentuk hasil yang kamu bawa ke wizard.

**Variasi, menguji regex dengan data sintetis sebelum menyentuh data nyata:** untuk memastikan ketiga varian berperilaku seperti yang kamu harapkan, buat ketiganya sendiri.

```
| makeresults format=csv data="_raw
sslvpn[5542]: AUTH FAIL vendor.bnet01 from 203.0.113.45 group VENDOR-NOC via portal (bad credentials) session 118342
sslvpn[5542]: AUTH OK vendor.bnet01 from 203.0.113.45 group VENDOR-NOC via portal assigned 10.10.250.37 session 118391
sslvpn[5542]: AUTH FAIL (unknown user) from 198.51.100.23 group - via portal (no such user) session 118400
sslvpn[5542]: SESSION CLOSE session 118391 duration 742"
| rex field=_raw "AUTH\s+(?<jab_result>OK|FAIL)\s+(?<jab_user>[\w.\-]+)\s+from\s+(?<jab_src>\d{1,3}(?:\.\d{1,3}){3})\s+group\s+(?<jab_group>\S+)"
| table _raw jab_result jab_user jab_src jab_group
```

Hasil yang benar: baris pertama dan kedua terisi lengkap, baris ketiga hanya `jab_result` yang terisi karena nama akunnya tidak cocok dengan `[\w.\-]+` sehingga seluruh sisa regex gagal, dan baris keempat seluruhnya kosong karena tidak memuat kata `AUTH`. Hitung sendiri dulu sebelum menjalankan: empat baris masuk, dua baris terisi penuh, satu baris terisi satu field, satu baris kosong.

**Kapan gagal:** `makeresults format=csv` dengan `_raw` berisi tanda kutip atau koma butuh penulisan yang lebih hati-hati, dan di sebagian versi perilakunya berbeda; kalau bentuk ini tidak jalan di instance-mu, pakai berkas log kecil yang kamu unggah sendiri ke index lab.

### 2.3 Field Extractor metode regex untuk `jab:vpnlegacy`

Sekarang regexnya dipindahkan menjadi objek. Langkah-langkah di bawah mengikuti alur lima langkah di bagian 1.2 [S1].

1. Jalankan search dasar `index=vpn sourcetype=jab:vpnlegacy earliest=-24h@h latest=@h` supaya ada hasil, lalu gulir ke bawah fields sidebar dan pilih `Extract New Fields`. Pintu ini praktis, tetapi ingat bahwa wizard hanya memakai event yang dikembalikan search ini [S1], jadi pastikan rentang waktunya cukup lebar untuk memuat event sukses, bukan hanya event gagal.
2. Di langkah Select sample, pilih satu event `AUTH FAIL` sebagai contoh pertama.
3. Di langkah Select method, pilih `Regular expression`, karena baris ini posisional dan tidak punya header [S1].
4. Di langkah Select fields, sorot `vendor.bnet01` dan beri nama `jab_user`, lalu sorot `203.0.113.45` dan beri nama `jab_src`. Nama field harus dimulai dengan huruf.
5. Masih di langkah yang sama, tambahkan satu sample event `AUTH OK` dan satu sample `AUTH FAIL (unknown user)`. Di sini biasanya terlihat bahwa regex buatan wizard terjangkar pada kata `FAIL` sehingga event `AUTH OK` tidak terekstrak. Perbaiki dengan menyunting regexnya menjadi bentuk yang sudah kamu uji di bagian 2.2, dan tambahkan `jab_result` serta `jab_group` sekaligus.
6. Tetapkan required text `AUTH` supaya extraction ini tidak dipaksakan ke baris `SESSION CLOSE` yang memang tidak punya nama akun.
7. Di langkah Validate fields, tandai nilai `(unknown` yang muncul di field `jab_user` sebagai counterexample bila wizard masih menangkapnya [S1]. Setelah itu baris varian ketiga seharusnya tidak lagi menghasilkan `jab_user`.
8. Di langkah Save, beri nama extraction yang menyebut sumber dan isinya, misalnya `jab_vpnlegacy_auth`, lalu atur permission-nya. Nama ini yang akan muncul sebagai `class` di halaman Field extractions [S2], jadi hindari nama seperti `extract1`.

Setelah disimpan, periksa hasilnya dengan search yang tidak menyebut `rex` sama sekali. Ini pembuktian bahwa field-nya benar-benar datang dari objek, bukan dari baris search-mu:

```
index=vpn sourcetype=jab:vpnlegacy jab_result=FAIL earliest=-24h@h latest=@h
| stats count AS gagal, dc(jab_user) AS akun_unik, values(jab_group) AS grup BY jab_src
| sort - gagal
| head 5
```

Keluaran ilustrasi:

```
jab_src          gagal   akun_unik   grup
203.0.113.45       147           1   VENDOR-NOC
198.51.100.23       86           0   -
192.0.2.91          31           2   VENDOR-NOC
203.0.113.77         9           1   STAFF-REMOTE
198.51.100.14        4           1   STAFF-REMOTE
```

**Cara membaca hasil:** `203.0.113.45` dengan 147 kegagalan pada satu akun adalah pola tiket SOC-2026-0231, dan sekarang bisa disaring di baris pertama search, bukan setelah `rex`. Baris kedua, `198.51.100.23` dengan `akun_unik` bernilai 0, adalah 86 event varian `(unknown user)`: `dc()` menghitung nol karena field-nya memang tidak terisi, dan itu informasi yang berguna, bukan kerusakan. Kelima baris pertama berjumlah 277 kegagalan dari total 1.918, jadi sisanya tersebar di banyak sumber kecil.

**Kapan gagal:** kalau `jab_result=FAIL` tidak mengembalikan apa pun padahal wizard menampilkan hasil, kemungkinan terbesar extraction masih private dan kamu sedang men-search dari app lain, atau permission app-nya belum diatur. Itu dikerjakan di bagian 2.6. Kemungkinan kedua, nama field tidak sama persis: nama field bersifat sensitif huruf, jadi `jab_Result` dan `jab_result` adalah dua hal berbeda.

### 2.4 Field Extractor metode delimiter untuk `jab:fw:pop`

Sumber kedua berbentuk berpemisah koma dengan urutan kolom yang didokumentasikan vendor, jadi metode `Delimiters` yang dipakai.

Satu event mentah dari firewall POP Bandung:

```
2026-10-14 01:12:44,BDG-FW-01,traffic,deny,203.0.113.45,41532,10.30.4.11,445,tcp,POP-EDGE-IN,0,64
```

Urutan kolom menurut dokumen vendor ada dua belas: waktu perangkat, nama perangkat, jenis log, keputusan, alamat sumber, port sumber, alamat tujuan, port tujuan, protokol, nama aturan, byte terkirim, byte diterima. Hitung sendiri jumlah koma di baris contoh sebelum lanjut; sebelas koma berarti dua belas nilai, dan kalau hitunganmu berbeda dari dokumen vendor, dokumen itulah yang perlu dicek, bukan wizardnya.

Langkahnya:

1. Jalankan `index=firewall sourcetype=jab:fw:pop earliest=-24h@h latest=@h`, lalu buka Field Extractor dan pilih satu event `traffic` sebagai sample.
2. Di langkah Select method, pilih `Delimiters`, lalu tentukan koma sebagai pemisah [S1].
3. Di langkah Rename fields, ganti nama bawaan menjadi nama yang bermakna sesuai dokumen vendor: `fw_time`, `fw_device`, `fw_logtype`, `fw_act`, `fw_srcaddr`, `fw_srcport`, `fw_dstaddr`, `fw_dstport`, `fw_proto`, `fw_policy`, `fw_sent`, `fw_rcvd`. Kolom yang tidak kamu pakai boleh dibiarkan bernama bawaan, tetapi di PT JAB kebiasaannya semua diberi nama, karena nama bawaan yang nyangkut di dashboard orang lain sulit dibersihkan nanti.
4. Simpan dengan nama `jab_fw_pop_csv` dan atur permission-nya seperti di bagian 2.6.

Metode delimiter tidak punya langkah Validate [S1], jadi verifikasinya kamu kerjakan sendiri. Dua search berikut yang paling berguna.

**Tujuan pertama:** mengukur berapa banyak event yang kolomnya benar-benar terisi lengkap.

```
index=firewall sourcetype=jab:fw:pop earliest=-24h@h latest=@h
| eval lengkap=if(isnotnull(fw_act) AND isnotnull(fw_srcaddr) AND isnotnull(fw_dstport), 1, 0)
| stats count AS total, sum(lengkap) AS terisi BY fw_logtype
| eval persen=round(terisi/total*100, 1)
```

Keluaran ilustrasi:

```
fw_logtype   total    terisi   persen
traffic      86420     86420     100.0
utm           4210      4210     100.0
system         318         0       0.0
```

**Cara membaca hasil:** baris `system` nol persen bukan kebetulan. Log system perangkat ini memakai jumlah kolom yang berbeda, sehingga pemetaan posisi tidak berlaku untuknya. Ada dua jalan: menerima bahwa extraction ini hanya untuk baris `traffic` dan `utm`, atau memisahkan log system ke sourcetype sendiri saat onboarding (Day 28). Yang tidak boleh dilakukan adalah membiarkan 318 event itu terisi dengan nilai yang bergeser kolom, karena nilai yang salah lebih berbahaya daripada nilai yang kosong.

**Tujuan kedua:** menguji nilai yang memuat pemisah di dalamnya, yaitu jebakan utama metode delimiter.

```
| makeresults format=csv data="_raw
2026-10-14 01:12:44,BDG-FW-01,traffic,deny,203.0.113.45,41532,10.30.4.11,445,tcp,POP-EDGE-IN,0,64
2026-10-14 01:13:02,BDG-FW-01,traffic,deny,203.0.113.45,41533,10.30.4.11,445,tcp,POP-EDGE-IN,TEMP,0,64"
| eval kolom=mvcount(split(_raw, ","))
| table kolom _raw
```

Hasilnya: baris pertama 12 kolom, baris kedua 13 kolom karena nama aturan `POP-EDGE-IN,TEMP` memuat koma. Pada baris kedua, nilai `0` akan jatuh ke posisi byte terkirim, `64` ke posisi byte diterima, dan satu nilai tergeser keluar. Di hasil search, `fw_rcvd` akan terlihat terisi dan masuk akal, padahal isinya nilai milik kolom lain. Kesalahan jenis ini tidak pernah muncul sebagai error.

**Kapan gagal:** metode delimiter tidak cocok sejak awal bila pemisahnya non-ASCII atau nilainya bisa memuat tanda kutip ganda yang tidak di-escape; dokumentasi transform menyebut keduanya sebagai alasan memakai `REGEX` [S3]. Untuk kasus nama aturan yang memuat koma seperti di atas, pilihan yang lebih sehat adalah memperbaiki format di sisi pengirim bersama NOC, karena format yang ambigu akan menyusahkan setiap alat yang membacanya, bukan hanya Splunk.

### 2.5 Memeriksa kembali hasilnya di Settings

Setelah dua extraction tersimpan, buka Settings > Fields > Field extractions dan cari dua baris baru itu [S2]. Yang kamu cocokkan di layar:

| Yang dicari | Nilai yang diharapkan untuk pekerjaan ini | Artinya |
|---|---|---|
| Name | `jab:vpnlegacy : EXTRACT-jab_vpnlegacy_auth` | Menyasar sourcetype, bukan host atau source, dan kelasnya bernama jelas |
| Type extraction VPN | `inline` | Regexnya ada di `props.conf`; hanya satu objek yang izinnya perlu diatur |
| Type extraction firewall | `uses transform` | Ada stanza `transforms.conf` terpisah yang izinnya juga perlu diperiksa |
| Extraction/Transform | Regex untuk yang inline, nama stanza untuk yang berbasis transform | Isi aturannya bisa dibaca tanpa membuka file |

Kolom Type pada extraction delimiter itu perlu kamu lihat sendiri dan bukan diasumsikan. Secara konseptual, data berpemisah dikerjakan dengan `DELIMS` dan `FIELDS` yang keduanya setting transform [S3], sehingga wajar bila hasil wizard muncul sebagai `uses transform`. Tetapi dokumentasi Field Extractor tidak menyatakan bentuk penyimpanan hasil wizard untuk metode delimiter [S1], jadi perlakukan ini sebagai hal yang dicek di lab-mu: lihat kolom Type pada barisnya, dan kalau berbunyi `uses transform`, buka halaman Field transformations dan periksa permission stanza itu juga.

Untuk extraction berbasis transform, aturan tambahan dari dokumentasi yang perlu dicatat di dokumentasi internalmu: satu transform bisa dipakai beberapa extraction, dan satu extraction bisa menunjuk beberapa transform yang ditulis dipisah koma [S3]. Itu yang membuat pola "satu transform untuk beberapa POP" mungkin bila nanti POP Surabaya memakai firewall vendor yang sama.

### 2.6 Membagikan ke app SOC dan memindahkan kepemilikan

Dua langkah ini yang menjawab syarat pertama dan ketiga detection engineer. Kerjakan berurutan, dan kerjakan sekarang, bukan nanti.

1. Pada baris extraction di Settings > Fields > Field extractions, buka dialog Permissions [S5].
2. Setel `Display for` ke `App` bila yang memakainya hanya app SOC, atau ke `All apps` bila dashboard dan detection di app lain juga membacanya [S5]. Di PT JAB, extraction untuk dua sumber ini diset `All apps`, karena searchnya dipakai dari app Search & Reporting, app SOC, dan nanti dari search head ES.
3. Beri `Read` pada role analyst L1, dan `Write` hanya pada role detection engineer serta SOC lead. Read berarti bisa memakai tanpa mengubah definisinya [S5]. Jangan memberi Write ke `Everyone`, karena satu suntingan regex yang keliru di objek global langsung mengubah hasil search semua orang.
4. Bila tipenya `uses transform`, ulangi langkah 1 sampai 3 untuk stanza transform-nya di halaman Field transformations [S2].
5. Pindahkan kepemilikan ke akun fungsional tim SOC, `svc_soc`, lewat Settings > All configurations > Reassign Knowledge Objects [S6]. Ini yang mencegah extraction menjadi yatim ketika kontrak anak magang yang membuatnya selesai. Hanya role Admin yang bisa melakukannya [S6], jadi mintakan ke admin platform bila rolemu bukan admin.
6. Catat di dokumentasi internal: nama extraction, sourcetype sasarannya, siapa pemiliknya sekarang, dan nomor tiket yang menjadi alasannya, misalnya SOC-2026-0231. Halaman Field extractions tidak menyimpan alasan sebuah objek dibuat.

Verifikasi yang jujur bukan dengan membuka ulang halaman Permissions, tetapi dengan menjalankan search dari akun lain. Minta rekan satu shift menjalankan ini dari app yang biasa ia pakai:

```
index=vpn sourcetype=jab:vpnlegacy earliest=-24h@h latest=@h
| stats count AS total, count(jab_user) AS ada_user
```

Keluaran ilustrasi yang benar untuk akun lain:

```
total   ada_user
12480       2244
```

**Cara membaca hasil:** angka 2.244 adalah 2.330 baris autentikasi dikurangi 86 baris varian `(unknown user)`, dan cocok dengan hitungan di bagian 2.2. Kalau rekanmu mendapat `ada_user` bernilai 0 sementara `total` tetap 12.480, datanya terbaca tetapi extraction-nya tidak berlaku untuknya, dan itu persis gejala objek private atau cakupan app yang belum tepat. Kalau `total` juga 0, masalahnya izin index, bukan extraction (Day 44).

### 2.7 Memeriksa objek yatim sebelum sebuah akun dihapus

Pekerjaan terakhir yang pantas menjadi kebiasaan bulanan di PT JAB, dan yang harus dikerjakan sebelum akun apa pun dihapus.

1. Buka Settings > All configurations > Reassign Knowledge Objects, lalu klik `Orphaned` [S6]. Ini satu-satunya tempat yang menampilkan semua jenis knowledge object yatim, termasuk field extraction, tetapi hanya yang dibagikan di tingkat app atau global [S6].
2. Pindahkan yang masih dibutuhkan ke pemilik yang aktif. Untuk beberapa objek sekaligus, centang kotaknya lalu pakai `Edit Selected Knowledge Objects` dengan batas 100 objek per sekali jalan [S6].
3. Periksa daftar scheduled search yatim lewat dashboard Orphaned Scheduled Searches, Reports, and Alerts di app Search & Reporting, atau lewat baris Orphaned Scheduled Searches di tab Health Check Monitoring Console [S6]. Untuk tiap objek, putuskan satu dari tiga: pindahkan pemiliknya supaya tetap berjalan, hapus jadwalnya supaya hanya manual, atau matikan [S6].
4. Catat satu hal yang tidak akan muncul di mana pun: objek yatim yang dulunya private tidak terdeteksi oleh cara mana pun di atas [S6]. Karena itu kebiasaan membagikan objek yang dipakai operasional bukan soal kolaborasi saja, tetapi soal supaya objek itu bisa ditemukan ketika pemiliknya hilang.
5. Untuk akun yang dihapus lewat direktori terpusat, tidak ada deteksi otomatis sama sekali [S6]. Masukkan langkah "pindahkan knowledge object" ke proses offboarding bersama HR dan tim IT, bukan ke daftar pekerjaan SOC saja.

Bila sebuah objek penting ternyata sudah yatim dalam keadaan private, dua jalan keluarnya ada di bagian 1.7 dan keduanya pekerjaan admin platform. Yang perlu kamu sampaikan ke admin adalah nama objeknya, app-nya, dan nama akun pemilik lamanya, karena ketiganya yang dibutuhkan untuk kedua cara itu.

## 3. Lab praktik (di VM lab terisolasi)

Lab memakai satu instance Splunk Enterprise lab tanpa ES, satu index lab, dan dua berkas log fiktif yang kamu buat sendiri. Semua langkah dijalankan di lab terisolasi, dan tidak ada data dari pekerjaan yang dipakai.

1. **Siapkan dua sumber.** Buat berkas `vpnlegacy.log` berisi 40 baris dengan komposisi yang kamu catat lebih dulu: 25 baris `AUTH FAIL`, 8 baris `AUTH OK`, 4 baris `AUTH FAIL (unknown user)`, dan 3 baris `SESSION CLOSE`. Buat juga `fwpop.csv` berisi 30 baris berpemisah koma dua belas kolom, dengan satu baris yang sengaja memuat koma di dalam nama aturan. Unggah keduanya lewat Add Data dengan sourcetype tetap, bukan `Automatic`, karena wizard tidak menawarkan apa pun untuk sourcetype automatic [S1].
2. **Prototipe dengan `rex`.** Jalankan search bagian 2.2 pada data lab-mu dan cocokkan hitungannya dengan komposisi yang kamu catat di langkah 1. Dari 33 baris `AUTH`, seharusnya 29 baris menghasilkan nama akun dan 4 baris tidak.
3. **Buat extraction regex lewat wizard.** Kerjakan lima langkah bagian 2.3, tetapi dengan sengaja memakai hanya satu sample event `AUTH FAIL` lebih dulu dan menyimpannya. Jalankan `stats count(jab_user)` dan catat angkanya. Lalu buka kembali extraction itu, tambahkan sample `AUTH OK`, simpan lagi, dan catat angkanya. Selisih kedua angka itu adalah ukuran bahaya menyimpan hasil wizard dari satu sample.
4. **Pakai counterexample.** Pastikan regexmu menangkap `(unknown` sebagai nama akun lebih dulu, lalu tandai nilai itu sebagai counterexample di langkah Validate dan simpan. Catat regex sebelum dan sesudahnya, lalu jalankan `stats dc(jab_user)` untuk melihat akun fiktif yang hilang dari daftar.
5. **Buat extraction delimiter.** Kerjakan bagian 2.4 pada `fwpop.csv`. Setelah disimpan, cari baris yang nama aturannya memuat koma dan buktikan kolom mana yang bergeser. Tulis satu kalimat tentang kolom apa yang akan salah dibaca oleh dashboard yang memakai field byte.
6. **Periksa tempat penyimpanannya.** Buka Settings > Fields > Field extractions dan catat kolom Name, Type, dan Extraction/Transform untuk kedua extraction [S2]. Catat apakah yang delimiter muncul sebagai `inline` atau `uses transform` di versi lab-mu, karena hal ini tidak dinyatakan di dokumentasi wizard.
7. **Buktikan efek private.** Buat user kedua di lab dengan role `user`, lalu jalankan search bagian 2.6 dari akun itu sementara extraction masih private. Catat dua angka: total event dan jumlah event yang field-nya terisi. Lalu bagikan extraction ke app, ulangi, dan catat angkanya lagi.
8. **Uji cakupan app.** Jalankan search yang sama dari app lain (misalnya app baru yang kamu buat bernama `lab_soc`) sementara `Display for` masih `App`. Catat hasilnya, lalu ubah ke `All apps` dan ulangi.
9. **Buat objek yatim dengan sengaja.** Buat satu scheduled report sederhana yang memakai field hasil extraction, miliki dengan user kedua, lalu nonaktifkan user itu. Tunggu jadwal berikutnya, lalu periksa dashboard Orphaned Scheduled Searches, Reports, and Alerts dan halaman Reassign Knowledge Objects [S6]. Catat objek mana yang terdeteksi dan mana yang tidak, terutama bedanya objek yang private dengan objek yang sudah dibagikan.
10. **Pulihkan.** Pindahkan kepemilikan objek yatim itu ke akun lain lewat Reassign Knowledge Objects, lalu pastikan jadwalnya berjalan lagi [S6]. Tulis prosedur enam baris untuk offboarding dari pengalaman ini.

**Hasil yang sebaiknya tersimpan:**
- Dua regex untuk `jab:vpnlegacy`, versi dari satu sample dan versi akhir, beserta angka cakupan masing-masing.
- Catatan kolom Name, Type, dan Extraction/Transform untuk kedua extraction dari halaman Field extractions.
- Empat angka dari langkah 7 dan 8 yang menunjukkan perbedaan private, app, dan global dari sudut pandang akun lain.
- Satu kalimat tentang kolom yang bergeser pada baris yang nama aturannya memuat koma.
- Daftar objek yatim yang terdeteksi dan yang tidak terdeteksi dari langkah 9.
- Prosedur offboarding enam baris dari langkah 10.

**Variasi tantangan:** buat extraction kedua pada sourcetype yang sama dengan nama field yang sama tetapi regex berbeda, lalu jalankan search dan amati nilai mana yang muncul. Catat apa yang terjadi dan bagaimana kamu menemukan extraction mana yang menang. Ini mensimulasikan keadaan nyata ketika add-on vendor dipasang di atas extraction buatan sendiri.

## 4. Troubleshooting

Tabel ini memuat gejala yang paling sering muncul saat membuat dan membagikan field extraction. Cari gejalanya di kolom pertama.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Wizard tidak menawarkan apa pun setelah menambah data | Sourcetype input diset `Automatic` [S1] | Set sourcetype tetap pada input, lalu ulangi; dokumentasi juga menyarankan menunggu sekitar 30 detik setelah input disimpan [S1] |
| Field terisi untuk sebagian event saja | Regex terjangkar pada teks yang hanya ada di satu varian | Tambahkan sample event varian lain di langkah Select fields [S1], lalu ukur cakupan dengan `count(<field>)` per varian |
| Field berisi teks pengganti seperti `(unknown` | Pola nilai terlalu longgar | Tandai sebagai counterexample di langkah Validate [S1], atau persempit kelas karakter, misalnya `[\w.\-]+` bukan `\S+` |
| Extraction jalan untukmu, orang lain mendapat nol baris | Objek masih private; extraction dari wizard private sampai dibagikan [S2] | Buka dialog Permissions, setel `Display for` dan beri Read ke role yang perlu [S5] |
| Sudah global tetapi masih tidak terlihat untuk orang lain | [komunitas, belum terkonfirmasi] transform yang dirujuk tetap private, atau stanza tersimpan di konteks user, bukan app [S8] | Periksa permission stanza di halaman Field transformations [S2]; cek apakah di versi-mu perilaku ini masih ada |
| Detection terjadwal tidak pernah fire padahal searchnya benar | Field tidak ada dalam konteks pemilik detection, atau app contextnya berbeda | Jalankan searchnya sebagai akun pemilik; pastikan cakupan objek mencakup app yang dipakai detection |
| Field muncul di app Search & Reporting tetapi tidak di ES | Cakupan masih `App`, dan ES ada di search head lain | Promosikan ke `All apps`, dan pastikan objeknya ada di search head yang menjalankan searchnya [S4] |
| Kolom bergeser pada data berpemisah | Satu nilai memuat pemisah di dalamnya | Buktikan dengan `mvcount(split(_raw,","))`; perbaiki format di sisi pengirim atau ganti ke extraction berbasis regex [S3] |
| Hanya satu dari beberapa nilai yang muncul di satu field | `MV_ADD` masih default `false`, nilai pertama disimpan dan sisanya dibuang [S3] | Setel `MV_ADD = true` pada transform bila field itu memang multivalue |
| Field hasil extraction tidak bisa dipakai di `tstats` | Extraction search-time bukan indexed field | Pakai `stats` biasa, atau bahas kebutuhan indexed field dengan admin (Day 25, Day 28) |
| Nama extraction berubah menjadi bergaris bawah | Spasi pada nama diubah menjadi garis bawah [S2] | Beri nama tanpa spasi sejak awal supaya nama di layar sama dengan nama di konfigurasi |
| Extraction tidak bisa dihapus | Izin app tidak mencukupi, atau objeknya objek default yang tidak bisa dihapus [S2] | Minta izin app yang sesuai; untuk objek default, timpa dengan objek sendiri daripada menghapusnya |
| Dashboard dan event type rusak setelah extraction dihapus | Objek lain bergantung pada field itu [S2] | Cari nama field di saved search dan dashboard sebelum menghapus; pulihkan dengan membuat ulang extraction |
| Scheduled report berhenti sendiri tanpa error | Pemiliknya tidak lagi akun valid; scheduler butuh role pemilik untuk kuota dan konkurensi [S6] | Periksa halaman Reassign Knowledge Objects bagian `Orphaned`, lalu pindahkan kepemilikannya [S6] |
| Objek yatim tidak muncul di halaman Reassign | Objeknya private saat menjadi yatim, atau user dihapus lewat autentikasi pihak ketiga [S6] | Buat ulang akun pemilik sementara lalu pindahkan, atau pindahkan stanzanya secara manual [S6] |

## 5. Kesalahan umum dan jebakan

- Menyimpan hasil wizard dari satu sample event. Regexnya akan terjangkar pada teks varian itu, dan varian lain diam-diam kosong. Tambahkan sample dan ukur cakupannya dengan angka, bukan dengan melihat layar [S1].
- Menganggap langkah Validate sudah membuktikan kebenaran. Validasi memakai sample yang ada di layar [S1]; perubahan format setelah upgrade perangkat tidak terdeteksi olehnya.
- Lupa bahwa metode delimiter tidak punya langkah Validate [S1]. Verifikasi untuk data berpemisah harus kamu kerjakan sendiri dengan search penghitung cakupan.
- Membiarkan nama field bawaan hasil metode delimiter. Nama tanpa arti akan dipakai orang lain di dashboard, lalu sulit dibersihkan.
- Mengisi field dengan nilai pengganti supaya "tidak kosong". Field kosong jujur; field berisi `(unknown` memunculkan akun yang tidak pernah ada di hasil `stats count BY user`.
- Mengira field extraction yang bekerja di layarmu sudah bekerja untuk tim. Objek baru private sampai dibagikan [S2][S5], dan gejalanya nol baris, bukan error.
- Membagikan extraction berbasis transform tanpa memeriksa permission transform-nya [S2][S8].
- Memberi `Write` ke `Everyone` supaya tidak perlu mengatur role. Satu suntingan regex pada objek global mengubah hasil search semua orang sekaligus [S5].
- Mempromosikan objek ke `All apps` lalu menganggap hak edit juga sudah beres. Cakupan dan hak edit diatur terpisah [S5].
- Memakai nama field yang terlalu umum untuk objek global. `user` atau `src` yang kamu buat sendiri akan bertabrakan dengan field bernama sama dari sumber lain; untuk nama lintas vendor, pakai alias dan calculated field (Day 16).
- Membiarkan extraction operasional dimiliki akun pribadi. Akun yang dihapus membuat objeknya yatim, dan yang terjadwal berhenti berjalan tanpa suara [S5][S6].
- Mengandalkan pesan orphaned search sebagai jaring pengaman. Pesan itu hanya mencakup scheduled report, dan tidak ada cara apa pun yang mendeteksi user yang dihapus lewat autentikasi pihak ketiga [S6].
- Mematikan `orphan_searches` di `limits.conf` supaya pesannya berhenti [S6]. Itu menghapus satu-satunya alarm bawaan untuk masalah ini.
- Menghapus extraction lama tanpa mencari dependensinya. Event type, saved search, dan dashboard bisa ikut rusak [S2].
- Membuat extraction baru di atas add-on vendor yang sudah mengekstrak field yang sama. Dua sumber kebenaran untuk satu nama field menghasilkan nilai yang berbeda tergantung urutan dan cakupan objek; pasang add-on lalu verifikasi, jangan ditimpa (Day 05 bagian 1.1).
- Menganggap field hasil extraction search-time bisa dipakai di `tstats` seperti indexed field. Keduanya keputusan yang berbeda dengan konsekuensi berbeda (Day 25, Day 28).

## 6. Catatan terkini

Bagian ini menampung detail versi dan hal yang bergantung lingkungan. Isinya tidak mengubah cara kerja, tetapi menjelaskan kenapa layar di instance-mu bisa berbeda dari uraian di atas.

- Dokumentasi Field Extractor 10.6 menyebut lima langkah dan dua metode, tetapi tidak menguraikan bentuk penyimpanan hasilnya, penanganan multivalue, atau penamaan bawaan field hasil metode delimiter [S1]. Detail itu dicek di halaman Field extractions dan di dokumentasi transform [S2][S3], dan untuk metode delimiter sebaiknya diperiksa langsung di lab-mu.
- Label langkah di wizard pernah berubah antar versi, dan halaman per langkah di dokumentasi versi lama (7.x) tidak lagi dapat diakses saat riset ini disusun. Yang dipakai di Day ini adalah uraian langkah di halaman 10.6 [S1], jadi cocokkan nama tombol dan label dengan layar versi-mu.
- Halaman Field extractions hanya mengelola extraction search-time. Index-time field extraction tidak bisa dikelola di Splunk Web dan harus disunting di `props.conf` dan `transforms.conf` [S2].
- Membuat field dari subtoken lewat Splunk Web membuat extraction-nya tampil di halaman Field extractions, tetapi extraction itu tidak bisa dipakai di search; untuk itu dibutuhkan penyuntingan file konfigurasi [S2].
- Konfigurasi berbasis file untuk extraction search-time diletakkan di tier search head [S4], dan perubahan pada transform memerlukan restart menurut halaman transform [S3]. Di deployment dengan search head cluster, mekanisme distribusinya berbeda; cek dengan admin platform.
- Role dan capability yang dibutuhkan berbeda per pintu masuk. Pintu dari halaman Home dan dari Add Data membutuhkan `edit_monitor` [S1], sedangkan membagikan dan mempromosikan objek secara default hanya bisa dilakukan role admin dan power [S5].
- Capability saved search yang relevan untuk kepemilikan ada tiga: `edit_saved_search`, `edit_saved_search_owner` yang perlu dipasangkan dengan `list_all_users` untuk dipakai di Splunk Web, dan `list_saved_search` [S5]. Dokumentasi mengingatkan bahwa pemilik capability ini bisa mengambil alih sebuah saved search dan mengendalikannya [S5].
- Dokumentasi resmi kini di help.splunk.com, dan tautan docs.splunk.com lama masih beredar untuk halaman yang sama. Sebagian halaman versi lama sudah tidak dapat diakses.

## 7. Cheat sheet

```
KAPAN MEMAKAI APA
  pertanyaan sekali pakai          -> rex di search bar (Day 11)
  aturan dipakai berulang          -> field extraction yang disimpan
  nama beda antar vendor           -> field alias / calculated field (Day 16)
  butuh indexed field untuk tstats -> keputusan index-time (Day 28)

FIELD EXTRACTOR (5 LANGKAH)
  1 Select sample     pilih sourcetype/source + satu event contoh
  2 Select method     Regular expression | Delimiters
  3a Select fields    (regex) sorot nilai, beri nama, TAMBAH SAMPLE, required text, sunting regex
  3b Rename fields    (delimiter) tentukan pemisah, ganti SEMUA nama bawaan
  4 Validate fields   (regex saja) tandai nilai salah sebagai counterexample
  5 Save              nama extraction + PERMISSION
  pintu masuk: fields sidebar "Extract New Fields" | All Fields | Event Actions
               Settings > Fields > Field extractions > Open field extractor
               Home / Add Data (butuh edit_monitor; sourcetype harus tetap)
  batas: pintu dari search hanya memakai event yang dikembalikan search itu
         sourcetype Automatic tidak ditawarkan; delimiter TIDAK punya langkah Validate

TEMPAT PENYIMPANAN (Settings > Fields > Field extractions)
  Name  : <spec> : EXTRACT-<class>   (inline, regex di props.conf)
          <spec> : REPORT-<class>    (uses transform, regex di transforms.conf)
  <spec>: sourcetype | host::<host> | source::<source>
  transform perlu dipakai bila: beberapa sourcetype, DELIMS+FIELDS, pemisah non-ASCII,
          SOURCE_KEY selain _raw, MV_ADD=true (default false membuang nilai ke-2 dst)
  index-time extraction TIDAK bisa dikelola di Splunk Web

PERMISSION
  private              hanya pembuatnya            (orang lain: field TIDAK ADA, nol baris, tanpa error)
  App                  app itu saja
  All apps (global)    semua app
  Read  = pakai & jalankan      Write = ubah definisi      tanpa keduanya = tidak terlihat
  default: hanya admin & power bisa share/promote; power hanya objek miliknya
  promote != memberi hak edit   ; izin role lain diatur lewat Manage Apps
  tipe uses transform -> atur juga permission transform-nya

OWNER DAN OBJEK YATIM
  akun dihapus -> objek yatim -> scheduled report BERHENTI tanpa suara (butuh role owner untuk kuota)
  temukan: Messages | dashboard Orphaned Scheduled Searches, Reports, and Alerts
           Monitoring Console > Health Check > Orphaned Scheduled Searches
           Settings > All configurations > Reassign Knowledge Objects > Orphaned  (semua jenis objek,
                                                                   tetapi hanya yang app/global)
  TIDAK terdeteksi: objek yang private saat yatim; user dihapus lewat auth pihak ketiga
  pindahkan: Reassign (admin saja), maks 100 objek sekaligus
  private yang sudah yatim: buat ulang akun lama sementara, atau pindahkan stanzanya manual
  pencegahan: objek operasional dimiliki akun fungsional tim, bukan akun pribadi
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Kamu membuat field extraction lewat Field Extractor, mengujinya, dan hasilnya benar. Seminggu kemudian detection terjadwal yang memakai field itu belum pernah fire sekali pun. Rekanmu menyimpulkan tidak ada aktivitas yang cocok. Tepat?

<details><summary>Jawaban</summary>

Belum tentu, dan ini kemungkinan pertama yang harus diperiksa, bukan terakhir. Knowledge object baru hanya tersedia untuk pembuatnya, dan extraction dari wizard tetap private sampai dibagikan. Untuk field extraction, akibatnya tidak memunculkan error: search yang menyaring field yang tidak ada hanya mengembalikan nol baris, sama seperti kalau memang tidak ada aktivitas. Detection terjadwal berjalan dalam konteks pemiliknya, jadi bila pemiliknya akun lain, field itu tidak ada untuknya. Buktikan dengan menjalankan searchnya dari akun pemilik detection, lalu periksa dialog Permissions dan cakupan app-nya. Lihat bagian 1.6 dan 2.6.

</details>

**2. Skenario keputusan.** Log firewall POP baru masuk sebagai satu baris berpemisah koma dengan dua belas kolom yang didokumentasikan vendor, dan sebagian baris memuat nama aturan yang mengandung koma. Apa yang kamu lakukan?

- A. Pakai metode `Delimiters` dengan pemisah koma, karena datanya memang berpemisah koma.
- B. Pakai metode `Delimiters` untuk mayoritas baris, lalu ukur cakupannya dan selesaikan baris bermasalah dengan memperbaiki format di sisi pengirim atau memakai extraction berbasis regex.
- C. Pakai metode `Regular expression` sejak awal untuk semua kolom, karena regex selalu lebih aman.

<details><summary>Jawaban</summary>

B. Metode delimiter adalah pilihan yang tepat untuk bentuk datanya, tetapi nilai yang memuat pemisah akan menggeser semua kolom setelahnya tanpa memunculkan error, sehingga kolom byte bisa berisi nilai milik kolom lain. Karena metode delimiter tidak punya langkah Validate, pengukuran cakupan harus kamu kerjakan sendiri dengan search, lalu baris bermasalah diselesaikan di akarnya. A keliru karena berhenti sebelum memeriksa, dan nilai yang bergeser lebih berbahaya daripada nilai yang kosong. C berlebihan: menulis regex dua belas kolom untuk data yang rapi adalah pekerjaan yang lebih sulit dirawat, walaupun regex memang diperlukan untuk pemisah non-ASCII atau nilai yang memuat tanda kutip ganda yang tidak di-escape. Lihat bagian 1.4 dan 2.4.

</details>

**3. Pertanyaan jebakan.** "Kalau extraction sudah diset `All apps`, berarti semua orang bisa memakainya dan semua orang bisa mengubahnya." Benarkah?

<details><summary>Jawaban</summary>

Tidak, keduanya salah. Cakupan dan hak akses adalah dua pengaturan terpisah di dialog Permissions. `Display for` menentukan di app mana objek berlaku, sedangkan Read dan Write per role menentukan siapa yang bisa memakai dan siapa yang bisa mengubah definisinya. Objek yang global tetapi tanpa Read untuk sebuah role tidak terlihat oleh role itu, dan mempromosikan objek ke global tidak otomatis memperluas hak mengubahnya. Praktik yang dipakai untuk extraction operasional: Read untuk role yang memakainya, Write hanya untuk detection engineer dan SOC lead. Lihat bagian 1.6.

</details>

**4. Jelaskan ulang.** Jelaskan kepada network engineer NOC PT JAB dalam tiga kalimat apa bedanya `rex` di search bar dengan field extraction yang disimpan, dan kenapa yang kedua perlu diatur izinnya.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Regex yang kamu tulis pakai `rex` hanya berlaku di search itu, jadi kalau orang lain mau menyaring field yang sama, dia harus menyalin regexmu dulu. Field extraction yang disimpan adalah aturan yang sama tetapi dipasang di Splunk, jadi field-nya langsung ada untuk semua search pada sourcetype itu, dan bisa dipakai menyaring di baris pertama search sehingga lebih murah. Bedanya, objek seperti ini milik pembuatnya dan tidak terlihat oleh orang lain sampai dibagikan, dan kalau belum dibagikan, search orang lain tidak error tetapi hanya mengembalikan nol baris."

Kesalahan yang sering muncul:
- Menjelaskannya sebagai perbedaan kemampuan regex, padahal mesin regexnya sama dan yang berbeda jangkauan serta posisinya di pipeline.
- Lupa menyebut bahwa field yang private gagal tanpa error.
- Menyebut extraction search-time mengubah data yang tersimpan. Tidak; data mentah tidak berubah, dan extraction bisa diperbaiki kapan saja tanpa re-ingest.

</details>

**5. Skenario keputusan.** Anak magang yang mengerjakan onboarding dua sumber baru selesai kontrak bulan depan. Ia pemilik dua field extraction yang sudah global dan satu scheduled report yang memakai keduanya. Apa yang kamu kerjakan sekarang?

- A. Tidak ada; extraction sudah global, jadi tetap berlaku untuk semua orang walaupun akunnya dihapus.
- B. Pindahkan kepemilikan ketiga objek itu ke akun fungsional tim lewat Reassign Knowledge Objects sebelum akunnya dihapus, lalu catat namanya di dokumentasi internal.
- C. Minta anak magang membuat ulang ketiganya dari akun SOC lead di hari terakhir.

<details><summary>Jawaban</summary>

B. Akun yang dihapus membuat objek miliknya menjadi yatim, dan objek terjadwal yang yatim berhenti berjalan karena scheduler butuh role pemilik untuk menerapkan kuota dan batas konkurensi. Memindahkan kepemilikan sebelum akun dihapus jauh lebih murah daripada memulihkannya nanti, terutama bila ada objek yang masih private, karena objek private yang sudah yatim tidak bisa dipindahkan dari UI dan butuh akun pemilik lama dibuat ulang atau stanzanya dipindahkan manual. A keliru karena mencampur dua hal: cakupan global menentukan siapa yang bisa memakai, bukan apakah objeknya punya pemilik yang valid. C menambah pekerjaan dan risiko salah ketik tanpa alasan, dan tetap meninggalkan objek lama yang yatim. Lihat bagian 1.7 dan 2.7.

</details>

**6. Pertanyaan jebakan.** "Halaman Reassign Knowledge Objects bagian `Orphaned` menampilkan semua objek yatim, jadi kalau di sana bersih berarti tidak ada masalah." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Halaman itu memang satu-satunya cara yang mencakup semua jenis knowledge object, tetapi hanya menemukan objek yang dibagikan di tingkat app atau global. Objek yang berstatus private saat pemiliknya dihapus tidak muncul di sana, dan tidak muncul di pesan harian, dashboard orphaned, maupun health check Monitoring Console. Selain itu tidak ada satu pun cara yang mendeteksi user yang dihapus lewat sistem autentikasi pihak ketiga, yang justru umum di organisasi dengan direktori terpusat. Karena itu pemindahan kepemilikan harus menjadi langkah di proses offboarding, bukan hanya hasil pemeriksaan berkala. Lihat bagian 1.7 dan 2.7.

</details>

**7. Interview question (English).** "You built a field extraction that works for you, but a scheduled detection that uses it never fires. How do you troubleshoot that?"

<details><summary>Sample answer</summary>

"My first assumption is not that the data is missing, it's that the field is missing for whoever runs that search. A field extraction is a knowledge object, and a new one is private to its creator until you share it, so for everyone else the field simply doesn't exist. The dangerous part is that this fails silently: filtering on a field that isn't there returns zero results, not an error, and a scheduled search runs in the owner's context, so if the detection is owned by a service account, my private extraction is invisible to it. So I check three things in order: I run the raw search as the detection's owner and count events with and without the field filter, I open the Permissions dialog and confirm both the sharing scope and read access for the relevant roles, and if the extraction is the transform-based type I check the permissions on the transform too, because sharing the extraction doesn't necessarily cover the transform it references. After that I look at app context, since in our setup Enterprise Security sits on a separate search head, and a field shared only to one app won't be there. And while I'm in that dialog I also fix the thing that causes the next outage: operational objects get owned by a team service account, not by a person, because when an account is removed the object becomes orphaned and anything scheduled stops running without telling anyone."

What makes this answer strong: it names silent failure as the default hypothesis, separates sharing scope from read access from app context, mentions the transform as a second object with its own permissions, ties the scheduled-search owner context to the symptom, and ends with the ownership practice that prevents the recurrence.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Splunk Enterprise 10.6 Knowledge Manager Manual: Build field extractions with the field extractor | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/use-the-field-extractor-in-splunk-web | primer | diakses 2026-10-14 | Tinggi. Lima langkah wizard, dua metode (Regular expression dan Delimiters), pintu masuk dan batasnya, `edit_monitor`, sourcetype `Automatic` tidak ditawarkan, counterexample di langkah Validate |
| S2 | Splunk Enterprise 10.6 Knowledge Manager Manual: Use the Field extractions page | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/use-the-settings-pages-for-field-extractions-in-splunk-web | primer | diakses 2026-10-14 | Tinggi. Kolom Name, Type (`inline` dan `uses transform`), Extraction/Transform, form extraction baru, extraction dari wizard private sampai dibagikan, batas index-time, risiko menghapus |
| S3 | Splunk Enterprise 10.6 Knowledge Manager Manual: Configure advanced extractions with field transforms | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/use-the-configuration-files-to-configure-field-extractions/configure-advanced-extractions-with-field-transforms | primer | diakses 2026-10-14 | Tinggi. `REGEX`, `FORMAT`, `DELIMS`, `FIELDS`, `MV_ADD`, `SOURCE_KEY`, named capture group, pemakaian ulang transform, `REPORT-<class>` dan `<spec>` |
| S4 | Splunk Enterprise 10.6 Knowledge Manager Manual: The sequence of search-time operations | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/get-started-with-knowledge-objects/the-sequence-of-search-time-operations | primer | diakses 2026-10-14 | Tinggi. Urutan operasi search-time dan keterangan bahwa konfigurasi berbasis file dibuat di tier search head |
| S5 | Splunk Enterprise 10.6 Knowledge Manager Manual: Manage knowledge object permissions | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/get-started-with-knowledge-objects/manage-knowledge-object-permissions | primer | diakses 2026-10-14 | Tinggi. Objek baru private, `Display for` App dan All apps, Read dan Write per role plus baris Everyone, admin dan power, izin app lewat Manage Apps, capability saved search, clone dan move, objek yatim |
| S6 | Splunk Enterprise 10.6 Knowledge Manager Manual: Manage orphaned knowledge objects | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/get-started-with-knowledge-objects/manage-orphaned-knowledge-objects | primer | diakses 2026-10-14 | Tinggi. Sebab dan akibat objek yatim, empat cara deteksi dan batasnya, Reassign Knowledge Objects, batas 100 objek, penanganan objek private yang yatim, tiga pilihan untuk scheduled search, `orphan_searches` di `limits.conf` |
| S7 | Splunk Enterprise 10.6 Search Reference: rex | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/rex | primer | diakses 2026-10-14 | Tinggi. `field` default `_raw` dan catatan performanya, `max_match`, `mode=sed`, `offset_field`, named capture group |
| S8 | Splunk Community: "Field extraction invisible to other users despite global" dan "sharing field extraction saved search or dashboard between users" | https://community.splunk.com/t5/Splunk-Search/Field-extraction-invisible-to-other-users-despite-global/td-p/104063 | komunitas | tanggal tidak tercatat (thread lama) | Rendah-sedang. Laporan bahwa transform yang dirujuk tetap private saat extraction dibagikan lewat UI (disebut known issue SPL-118752) dan kasus stanza props tersimpan di konteks user; keduanya perlu diuji di versi 10.6 |
| S9 | Splunk Enterprise 10.6 Knowledge Manager Manual: When Splunk software extracts fields | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/fields-and-field-extractions/when-splunk-software-extracts-fields | primer | diakses 2026-10-14 | Tinggi. Beda index-time dan search-time, default field, batas 100 pasangan `key=value` pertama saat field discovery aktif, saran tidak menambah field ke daftar default index-time |

**Catatan sumber:** bentuk penyimpanan hasil wizard untuk metode delimiter tidak dinyatakan di halaman Field Extractor [S1]; yang pasti dari dokumentasi adalah bahwa `DELIMS` dan `FIELDS` merupakan setting field transform [S3] dan bahwa halaman Field extractions membedakan tipe `inline` dan `uses transform` [S2], jadi periksa kolom Type di instance-mu seperti pada langkah 6 di bagian 3. Pernyataan bahwa field yang tidak ada menghasilkan nol baris tanpa error adalah konsekuensi langsung dari model permission [S2][S5] dan bukan kutipan satu halaman tersendiri; buktikan dengan langkah 7 di bagian 3. Jebakan nilai yang memuat pemisah pada metode delimiter tidak dibahas dokumentasi dan diuji di lab seperti pada bagian 2.4. Klaim komunitas tentang transform yang tetap private dan stanza di konteks user [S8] berasal dari thread lama dan belum dikonfirmasi untuk 10.6. Semua angka di keluaran ilustrasi disusun agar konsisten dengan tiket SOC-2026-0231 dan bisa dijumlahkan ulang, tetapi bukan hasil eksekusi.
