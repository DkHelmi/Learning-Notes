---
day: 23
title: 'CIM, CIM Add-on, dan praktik terbaik SIEM: normalisasi saat search yang membuat data model terisi'
researched_on: 2026-10-07
versions_checked: 'Splunk CIM Add-on 6.4.0 (4 Feb 2026; referensi data model CIM 6.4); panduan setup CIM (dok 6.2) dan normalisasi (dok 6.1); SA-cim_vladiator 2.1.0 (Jun 2026); Splunk Enterprise 10.6; ES 8.7'
---

# Day 23: CIM, CIM Add-on, dan praktik terbaik SIEM

Cakupan: CIM sebagai skema saat search, daftar data model CIM 6.4 dan cara memilih model yang tepat, rantai yang menentukan event mana masuk data model, alur normalisasi resmi, pengaturan CIM Add-on (index allowlist dan akselerasi), cara memvalidasi kepatuhan sebuah sourcetype, dan praktik terbaik operasi SIEM yang paling menentukan di pekerjaan.

## Ide inti

Satu detection yang ditulis sekali dan menangkap percobaan brute force di VPN, Windows, Linux, Entra ID, dan sumber berikutnya yang masuk bulan depan tidak lahir dari search yang pintar. Ia lahir karena semua sumber itu memakai kosakata yang sama: nama field yang sama untuk hal yang sama, dan nilai field yang sama untuk keadaan yang sama. Tanpa kosakata itu, setiap vendor berbicara dengan bahasanya sendiri. Windows memakai `Account_Name`, Linux memakai `user`, Okta memakai `actor.alternateId`, dan firewall memakai `srcip`, `src_ip`, atau `source_address` tergantung vendornya. Konsekuensinya satu detection harus ditulis ulang untuk setiap sumber. CIM adalah kosakata bersama itu: model semantik yang diimplementasikan sebagai add-on, bekerja sebagai skema saat search, dan tidak mengubah satu byte data mentah. Yang ditambahkan hanyalah aturan baca [S1].

Yang membuat topik ini sering gagal di lapangan adalah salah paham tentang siapa yang mengerjakan apa. CIM tidak menormalisasi data. CIM hanya menetapkan nama field, nilai yang diharapkan, dan tag yang menjadi syarat keanggotaan. Yang menormalisasi adalah add-on vendor atau kamu sendiri, lewat extraction, field alias, calculated field, lookup, event type, dan tag. Karena itu sebuah sumber bisa masuk index dengan volume besar, terlihat sehat di semua grafik, dan tetap tidak ada sama sekali di data model yang dipakai setiap detection dan setiap dashboard ES. Kegagalannya tidak pernah berupa error. Ia berupa angka yang lebih kecil, dan angka yang lebih kecil terbaca seperti lingkungan yang tenang.

Dua analogi yang sudah kamu pakai sejak Day 22 tetap berlaku di sini. CIM adalah kamus field standar lintas vendor, sama seperti normalisasi format log yang harus dikerjakan di SIEM mana pun sebelum korelasi masuk akal; batasnya, kamus tidak memaksa data menjadi benar, ia hanya menetapkan namanya. Data model adalah template laporan baku yang diisi dari banyak vendor; batasnya, isinya hanya sebaik field dan tag yang benar di setiap sumber, sehingga satu template yang sama bisa penuh di satu lingkungan dan setengah kosong di lingkungan lain tanpa ada yang terlihat rusak.

```
CIM = skema SAAT SEARCH (add-on Splunk_SA_CIM), data mentah tidak diubah

RANTAI KEANGGOTAAN SATU EVENT (putus satu mata, event tidak terhitung)
  event  ->  event type cocok              (kriteria search tersimpan, Day 17)
         ->  event type punya tag constraint (mis. authentication)
         ->  field bernama sesuai CIM        (extraction, alias, calculated field, Day 16)
         ->  nilai field sesuai yang diharapkan (mis. action=failure, bukan "Failed")
         ->  baru terhitung di data model, Pivot, tstats, detection, dashboard ES

PENGATURAN CIM ADD-ON per data model (menentukan cepat atau lambat)
  Indexes allowlist | Tags allowlist | Accelerate | Summary range | Backfill range
  akselerasi default OFF  ;  bila ES terpasang, pengaturannya di-enforce oleh ES
```

Situasi yang dipakai sepanjang Day ini: di PT Jaringan Anak Bangsa (PT JAB, ISP menengah fiktif dengan SOC internal satu lantai dengan NOC), Enterprise Security baru dipasang di search head terpisah. Pekerjaan Day 17 sudah selesai, yaitu empat sumber otentikasi karyawan (`vpn`, `wineventlog`, `linux`, `o365`) sudah punya event type dan sudah diberi tag `authentication`. Tiket SOC-2026-0258 dibuka setelah ada percobaan credential stuffing ke akun pelanggan broadband lewat RADIUS, dan tiket itu memperlihatkan dua hal yang belum selesai: log RADIUS pelanggan di `jkt-radius01` tidak punya add-on resmi sehingga tidak masuk model mana pun, dan dashboard Access di ES menampilkan angka yang lebih kecil daripada hasil search langsung. SOC lead menulis:

> "Dua hal yang perlu beres minggu ini. Pertama, alert brute force kita jalan untuk akun karyawan, tetapi percobaan ke akun pelanggan lewat RADIUS lolos semuanya karena log itu tidak masuk model yang dipakai alert. Saya tidak mau menulis alert kedua dengan logika yang sama; saya mau sumber itu dibuat terbaca oleh alert yang sudah ada. Kedua, dashboard ES dan Pivot memberi angka yang lebih kecil dari search biasa, dan beberapa panel lambat sekali. Tim platform sempat menyalakan akselerasi semua data model dan kemarin setelan itu kembali sendiri ke keadaan lama, jadi tolong jelaskan juga apa yang sebenarnya mengatur itu."

Permintaan itu memuat enam pertanyaan:

1. Apa sebenarnya CIM, dan apa yang dipasang ketika orang berkata "CIM sudah ada"?
2. Model mana yang dipakai untuk sebuah sumber, dan bagaimana memilihnya tanpa menebak?
3. Apa yang menentukan sebuah event terhitung di data model atau tidak?
4. Langkah apa saja yang dikerjakan untuk membuat satu sumber tanpa add-on menjadi terbaca?
5. Apa yang mengatur index yang dicari dan akselerasi, dan kenapa setelan itu bisa kembali sendiri?
6. Praktik mana yang paling menentukan supaya kejadian seperti ini tidak terulang di sumber berikutnya?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.1 dan 1.3, pertanyaan 3 di bagian 1.2, pertanyaan 4 di bagian 1.3 dan bagian 2.4, pertanyaan 5 di bagian 1.4, dan pertanyaan 6 di bagian 1.5. Bagian 2 mengerjakan validasi dan normalisasinya sampai sumber RADIUS terbaca oleh detection yang sudah ada.

**Kapan relevan:** ketika satu pertanyaan harus dijawab untuk banyak vendor sekaligus, ketika sebuah sumber baru harus langsung terpakai oleh detection dan dashboard yang sudah ada, ketika Pivot atau `tstats` memberi angka yang lebih kecil daripada search langsung, dan ketika kamu menilai apakah sebuah add-on vendor benar-benar mengerjakan tugasnya.
**Kapan bukan jawaban:** untuk sumber log yang memang tidak punya padanan di model mana pun, membangun data model sendiri lebih tepat daripada memaksakan field ke model yang artinya berbeda (Day 22). Untuk normalisasi sekali pakai di satu search, `eval` di search bar sudah cukup dan tidak perlu menyentuh knowledge object apa pun (Day 11). CIM juga bukan alat mempercepat search: kecepatan datang dari akselerasi beserta syaratnya (Day 26) dan dari `tstats` yang membaca summary-nya (Day 25).

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (index, sourcetype, field extraction, field alias, calculated field, lookup, event type, tag, data model, dataset, constraint, Pivot, akselerasi) tidak diulang di sini. Tabel ini hanya memuat istilah yang dipakai Day ini; cari kolom padanan bila sebuah istilah terasa asing.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| CIM (Common Information Model) | Model semantik bersama berisi data model, dokumentasi, alat validasi, dan model aksi umum; bekerja sebagai skema saat search [S1] | Kamus field standar lintas vendor di SIEM mana pun |
| `Splunk_SA_CIM` | Nama add-on tempat CIM diimplementasikan; disertakan bersama ES [S1] | Paket kamus yang dipasang di konsol |
| Technology Add-on (TA) | Add-on vendor yang mengerjakan parsing dan normalisasi sebuah sumber ke nama dan nilai CIM | Parser per vendor di kolektor log |
| Nilai yang diharapkan ("ES expects") | Daftar nilai yang dipakai sebuah field di referensi CIM, termasuk yang dibutuhkan ES [S2] | Daftar kode status baku di laporan NOC |
| Indexes allowlist | Daftar index yang dicari sebuah data model, diatur di CIM Setup [S5] | Membatasi laporan hanya ke perangkat yang relevan |
| Tags allowlist | Daftar tag yang dipakai sebagai syarat sebuah data model di CIM Setup [S5] | Daftar label yang diakui laporan |
| Summary range dan Backfill range | Rentang waktu ringkasan akselerasi yang dipelihara dan yang diisi ke belakang [S5] | Jangka simpan data agregat di NMS |
| Capability `accelerate_datamodel` | Hak yang dibutuhkan untuk membuka pengaturan akselerasi CIM, sejak CIM 4.12.0 [S5] | Hak khusus untuk mengubah pengaturan pengumpulan data |
| Data Model Acceleration Enforcement | Modular input ES yang memaksa pengaturan akselerasi data model CIM [S5] | Konfigurasi terpusat yang menimpa perubahan manual di perangkat |
| Data Model Audit | Halaman pemantauan status dan ukuran akselerasi data model [S5] | Dashboard kesehatan pengumpulan data |
| Command `datamodel` | Command SPL yang menjalankan constraint sebuah dataset sebagai search [S4] | Menjalankan filter baku laporan untuk melihat isinya |
| `fieldsummary` | Command SPL yang memberi statistik per field: jumlah terisi, nilai unik, dan contoh nilai | Rekap kelengkapan kolom sebelum laporan dikirim |
| Kepatuhan CIM (CIM compliance) | Tingkat kesesuaian sebuah sourcetype terhadap field, tag, dan nilai yang diharapkan data model | Tingkat kesesuaian format log vendor terhadap standar internal |
| Mini TA | Add-on buatan sendiri berisi `eventtypes.conf`, `tags.conf`, dan `props.conf` untuk satu sumber | Berkas konfigurasi parser sendiri untuk perangkat tanpa template vendor |

### 1.1 Apa itu CIM, dan apa yang dipasang

Pertanyaan pertama SOC lead muncul karena kalimat "CIM sudah ada" bisa berarti tiga hal berbeda. CIM adalah model semantik bersama yang diimplementasikan sebagai add-on bernama `Splunk_SA_CIM`. Isinya [S1]:

- kumpulan data model;
- dokumentasi;
- alat validasi;
- model aksi umum untuk alert action.

CIM adalah skema saat search: data dinormalisasi ketika dibaca, tanpa mengubah raw data. CIM disertakan bersama ES [S1]. Setiap data model berisi nama field dan tag yang mewakili penyebut terkecil yang sama untuk satu domain, misalnya autentikasi atau trafik jaringan [S1].

Jadi memasang add-on CIM memberi kamu kamusnya, bukan datanya. Yang mengisi data model adalah add-on vendor per sumber, atau konfigurasi yang kamu tulis sendiri seperti di bagian 2.4.

Data model di CIM 6.4. Navigasi referensi resmi menampilkan 26 entri, dua di antaranya deprecated [S2]. Tabel ini dipakai untuk memilih model mana yang relevan bagi sebuah sumber, jadi cari domain sumbernya dulu, bukan nama field-nya.

| Domain | Data model |
|---|---|
| Identitas dan akses | Authentication, Data Access, Change |
| Endpoint | Endpoint, Malware, Updates, Inventory, Performance |
| Jaringan | Network Traffic, Network Resolution (DNS), Network Sessions, Intrusion Detection, Web, Email, Certificates |
| Data dan aplikasi | Data Loss Prevention, Databases, Interprocess Messaging, Java Virtual Machines (JVM) |
| Operasi keamanan | Alerts, Event Signatures, Vulnerabilities, Ticket Management, Splunk Audit Logs |
| Deprecated | Application State, Change Analysis |

Untuk PT JAB, log RADIUS pelanggan adalah peristiwa otentikasi, jadi modelnya Authentication, walaupun log itu juga memuat alamat IP dan bisa terasa seperti data jaringan. Aturan memilihnya ada di bagian 1.3 langkah dua.

CIM 6.4.0 (4 Feb 2026) menambahkan field unit bisnis di Data Access (untuk aset dan identitas), serta beberapa field di Network Sessions, Network Traffic, dan Endpoint [S3].

**Catatan dokumentasi:** halaman CIM di help.splunk.com juga muncul dengan label versi 8.x di beberapa jalur (misalnya jalur Splunk Cloud/Enterprise 8.5/8.6), padahal versi add-on terbaru adalah 6.4.0. Ini kemungkinan karena dokumentasi mengikuti versi produk induk, perlu dicek. Yang penting adalah versi add-on CIM yang terpasang di instance Splunk-mu.

### 1.2 Rantai yang menentukan sebuah event masuk data model

Keluhan kedua SOC lead, yaitu Pivot dan dashboard ES yang memberi angka lebih kecil, hampir selalu berujung ke rantai ini. Data model mendefinisikan constraint, yang di CIM umumnya berupa tag. Contoh: dataset Authentication menyaring event dengan `tag=authentication` (Day 25). Sebuah event terhitung di model bila keempat hal berikut terpenuhi:

1. Event type cocok dengan event itu.
2. Event type itu diberi tag yang sesuai constraint, misalnya `authentication`.
3. Field event bernama sesuai CIM (`user`, `src`, `dest`, `action`, dan seterusnya), lewat extraction, field alias, atau calculated field (`EVAL-`).
4. Nilai field sesuai harapan. Contoh: `action` di Authentication harus `success`, `failure`, `pending`, atau `error`, bukan `Failed` atau `4625`. Untuk itu dipakai lookup atau `EVAL-`.

Dua mata rantai pertama adalah pekerjaan event type dan tag, yang dibahas penuh di Day 17 bagian 1.5 sampai 1.7 beserta cara membuat dan membuktikannya; mata rantai ketiga dan keempat adalah pekerjaan field alias dan calculated field, yang dibahas penuh di Day 16 bagian 1.2 sampai 1.6 beserta urutan operasi search-time yang menentukan apa boleh merujuk apa. Day ini memakai keempatnya dari sisi CIM: mana yang diharapkan sebuah data model, dan bagaimana membuktikan bahwa harapan itu terpenuhi.

Referensi CIM mencantumkan nilai yang diharapkan, termasuk nilai yang diharapkan ES ("ES expects") dan nilai yang dipakai sebagai constraint ("Other") [S2]. Jika nilainya salah, event mungkin tetap masuk ke model, tetapi detection yang memfilter `action="failure"` tidak akan menemukannya. Perbedaan dua kegagalan ini penting saat troubleshooting: tag yang hilang membuat event tidak ada sama sekali di model, sedangkan nilai yang salah membuat event ada di model tetapi tidak terjawab oleh filter detection.

Biasanya semua ini sudah dikerjakan oleh Technology Add-on (TA) vendor, misalnya Splunk Add-on for Microsoft Windows, for Sysmon, atau for Palo Alto. Tugasmu sebagai analyst atau engineer adalah memverifikasi, dan menormalkan sendiri hanya bila TA tidak ada. Di PT JAB, empat sumber otentikasi karyawan masuk kategori pertama dan RADIUS pelanggan masuk kategori kedua.

### 1.3 Alur normalisasi saat search menurut dokumentasi

Dokumentasi CIM menjabarkan langkahnya, dan urutan ini yang dipakai di bagian 2 [S4]:

1. Ingest data apa adanya. Normalisasi terjadi saat search.
2. **Periksa data dalam konteks CIM:** tentukan data model berdasarkan tujuan event. Event login masuk Authentication walaupun field `app` juga ada di model lain. Jangan memaksa berdasarkan nama field [S4].
3. Konfigurasi tag lewat event type di Settings > Event types [S4], dengan cara dan batasan di Day 17.
4. Verifikasi tag, yaitu memastikan `tag::eventtype` benar-benar menempel pada event yang dimaksud [S4].
5. **Normalisasi field:** prioritaskan field yang direkomendasikan model itu, pakai field alias (`FIELDALIAS-`), extraction dengan nama persis sesuai CIM, dan lookup untuk menambah atau menormalkan nilai (vendor, product, kode menjadi teks), lalu verifikasi [S4]. Alat dan urutannya ada di Day 16.
6. Validasi terhadap data model lewat Datasets atau Pivot, atau lewat command `datamodel` [S4].
7. (Opsional) Perluas CIM dengan field kustom.
8. (Opsional) Paketkan sebagai add-on [S4].

Langkah dua adalah yang paling sering dilewati dan paling mahal bila salah. Memilih model berdasarkan nama field menghasilkan sumber yang masuk ke model yang kosakata nilainya berbeda, sehingga detection yang menghitung koneksi ditolak ikut menghitung login gagal. Untuk RADIUS PT JAB, pertanyaan yang dijawab log itu adalah "apakah akun ini berhasil masuk", jadi modelnya Authentication dan kosakata `action`-nya `success`, `failure`, `pending`, `error`.

### 1.4 Setup CIM Add-on: index allowlist, akselerasi, dan enforcement ES

Pertanyaan kelima SOC lead, yaitu kenapa setelan akselerasi kembali sendiri, dijawab di halaman ini. Halaman CIM Setup (Apps > Manage Apps > Set up untuk CIM, atau `/app/search/cim_setup`) mengatur per data model [S5]:

- **Indexes allowlist**: index yang dicari data model itu. Ini kunci performa, karena tanpa allowlist sebuah model menyapu seluruh index yang bisa dibaca (Day 25) [S6].
- Tags allowlist.
- Accelerate, Summary range, Backfill range, dan Max summarization search time.

Fakta penting yang menentukan keputusan [S5]:

- Semua data model CIM non-aktif akselerasinya secara default.
- Akses setup membutuhkan capability `accelerate_datamodel` (CIM 4.12.0 ke atas).
- Jika ES terpasang, akselerasi dipaksakan (enforced) oleh ES. Perubahan hanya bertahan bila dilakukan lewat modular input Data Model Acceleration Enforcement; cek nama dan lokasi pengaturan ini di ES 8.x.
- Pantau hasilnya dengan Data Model Audit [S5].

Butir ketiga itulah yang terjadi di PT JAB: tim platform mengubah akselerasi dari CIM Setup di search head yang ada ES-nya, lalu enforcement ES mengembalikannya ke keadaan yang didefinisikan ES. Jalan keluarnya bukan mengubahnya berulang kali, melainkan mengubahnya di tempat yang benar.

**Tanpa ES:** add-on CIM gratis dan bisa dipakai di Splunk Enterprise tanpa ES, lengkap dengan data model dan akselerasinya, sehingga kamu bisa membangun detection berbasis data model sendiri lewat report dan alert biasa (Day 09). Yang ditambahkan ES adalah ketergantungan: dashboard, detection, risk, dan korelasi aset dan identitas ES semuanya membaca field CIM, dan ES juga memaksakan pengaturan akselerasi [S1][S5]. Di PT JAB, ES ada di search head terpisah, jadi normalisasi yang dikerjakan di bagian 2 harus punya permission yang mencakup app yang dipakai di sana, kalau tidak, hasilnya benar di satu search head dan kosong di search head sebelahnya (Day 15).

### 1.5 Praktik terbaik operasi SIEM

Delapan hal berikut adalah yang paling sering menentukan apakah sebuah SIEM dipercaya atau tidak. Urutannya mengikuti alur kerja, dari keputusan mengumpulkan data sampai menjaga antrean analyst tetap bisa dikerjakan.

1. Use case dan risiko menggerakkan koleksi data, bukan sebaliknya (Day 21).
2. Normalisasi ke CIM sebelum menulis detection lintas vendor, lalu validasi; jangan berasumsi add-on sudah benar.
3. Batasi index per data model dan aktifkan akselerasi hanya untuk model yang dipakai [S5].
4. **Waktu yang benar:** UTC, sinkron NTP, dan parsing timestamp yang benar (Day 21).
5. Konteks aset dan identitas untuk prioritas dan korelasi (Day 26).
6. Detection teruji dan terdokumentasi, dengan tuning lewat filter (Day 36, Day 45).
7. **Pantau kesehatan pipeline:** kesegaran data, skipped searches, dan status akselerasi (Day 14, Day 21).
8. Kurangi alert fatigue dengan pendekatan berbasis risiko (Day 35).

Butir dua adalah pelajaran tiket SOC-2026-0258: sumber yang tidak ternormalisasi bukan masalah kualitas data yang bisa ditunda, melainkan lubang deteksi yang tidak terlihat di dashboard mana pun.

## 2. Contoh dan langkah praktis di PT JAB

Semua keluaran di bagian ini adalah keluaran ilustrasi untuk organisasi fiktif PT JAB, bukan hasil eksekusi. Asumsi: empat sumber otentikasi karyawan sudah punya event type dan tag `authentication` dari Day 17, add-on Windows 11.0.3 memakai format XML (`sourcetype=XmlWinEventLog`, `source=XmlWinEventLog:Security`), dan sumber kelima (`jab:radius:auth` di index `linux`) belum dinormalisasi. Rentang waktu yang dipakai seluruh bagian ini adalah satu hari penuh, `earliest="10/15/2026:00:00:00"` sampai `latest="10/16/2026:00:00:00"` dalam WIB. Angka dasarnya ada di tabel berikut, dan setiap keluaran di bawah bisa dicocokkan ke baris tabel ini, jadi cari barisnya sebelum menerima sebuah angka.

| Sumber | Index dan sourcetype | Event type | Event di rentang itu | Terhitung di Authentication |
|---|---|---|---|---|
| Windows Security (4624, 4625, 4648) | `wineventlog`, `XmlWinEventLog` | `jab_win_auth` | 25060 | 25060 |
| Entra ID sign-in | `o365`, `o365:management:activity` | `jab_o365_auth` | 9140 | 9140 |
| VPN karyawan dan vendor | `vpn`, `jab:vpnlegacy` | `jab_vpn_auth` | 4260 | 4260 |
| Server Linux | `linux`, `linux_secure` | `jab_linux_auth` | 1905 | 1905 |
| RADIUS pelanggan | `linux`, `jab:radius:auth` | belum ada | 38602 | 0 |
| Total | | | 78967 | 40365 |

### 2.1 Apakah sourcetype ini sudah diberi tag dan masuk model?

**Tujuan:** memastikan event logon Windows benar-benar membawa event type dan tag yang dibutuhkan data model Authentication, sebelum menyalahkan data model.

```
index=wineventlog source="XmlWinEventLog:Security" (EventCode=4624 OR EventCode=4625)
    earliest="10/15/2026:00:00:00" latest="10/16/2026:00:00:00"
| stats count BY EventCode tag eventtype
```

- `source="XmlWinEventLog:Security"` memilih channel Security pada add-on Windows modern yang memakai sourcetype generik (Day 03).
- `stats count BY EventCode tag eventtype` memperlihatkan tag dan event type yang melekat pada event logon. Field `tag` dan `eventtype` keduanya berpotensi multivalue, karena satu event bisa cocok dengan beberapa event type sekaligus.

Keluaran ilustrasi:

```
EventCode  tag             eventtype      count
4624       authentication  jab_win_auth   21965
4625       authentication  jab_win_auth    2153
```

**Cara membaca hasil:** dua baris itu berjumlah 24.118, dan sisa 942 event dari baris pertama tabel dasar adalah 4648 yang tidak disaring search ini. Yang dicari di sini bukan angkanya, melainkan kolom `tag`: ada `authentication` dari TA Windows, jadi mata rantai pertama dan kedua sudah terpenuhi untuk sumber ini.

**Variasi untuk sumber yang belum dinormalisasi:** jalankan hal yang sama pada RADIUS. Karena `eventtype` tidak terisi, `stats ... BY eventtype` akan membuang barisnya dan hasilnya nol baris, bukan nol count, sehingga mudah disalahartikan sebagai search yang keliru. Isi dulu field kosongnya:

```
index=linux sourcetype=jab:radius:auth
    earliest="10/15/2026:00:00:00" latest="10/16/2026:00:00:00"
| fillnull value="(tidak ada)" eventtype
| stats count BY sourcetype eventtype
```

Keluaran ilustrasi:

```
sourcetype       eventtype      count
jab:radius:auth  (tidak ada)    38602
```

**Kapan gagal:** bila tidak ada tag sama sekali, kemungkinannya TA tidak terpasang di search head tempat kamu mencari, atau event type-nya tidak cocok dengan event yang ada, sehingga event itu tidak akan pernah masuk Authentication.

### 2.2 Validasi nilai field CIM dengan tstats

**Tujuan:** memeriksa mata rantai keempat, yaitu apakah nilai field yang dipakai detection benar-benar sesuai yang diharapkan model.

```
| tstats count from datamodel=Authentication
    where source="XmlWinEventLog:Security"
        earliest="10/15/2026:00:00:00" latest="10/16/2026:00:00:00"
    by Authentication.action Authentication.app Authentication.signature_id
| rename Authentication.* AS *
```

- `from datamodel=Authentication` membaca lewat data model, bukan lewat index, sehingga hasilnya memperlihatkan dunia seperti yang dilihat detection.
- `where source=...` menyaring dengan field indexed, yang boleh ditulis tanpa prefiks nama dataset.
- `by Authentication.action ...` memakai nama berprefiks dataset, dan `rename` di akhir membuat kolomnya mudah dibaca.

Keluaran ilustrasi:

```
action   app         signature_id  count
success  win:local   4624          14207
success  win:remote  4624           7758
success  win:remote  4648            942
failure  win:local   4625           1486
failure  win:remote  4625            667
```

**Cara membaca hasil:** lima baris itu berjumlah 25.060, sama dengan baris Windows di tabel dasar, jadi tidak ada event yang hilang di jalan. `action` hanya bernilai `success` dan `failure`, keduanya ada di daftar nilai yang diharapkan CIM, jadi detection yang menyaring `action="failure"` menemukan 2.153 event. `signature_id` berisi kode event Windows, yang perlu dicocokkan dengan pemetaan TA Windows versi-mu. Nilai `app` mengikuti pola add-on Windows dan juga perlu dicocokkan, karena ia dipakai untuk membedakan jalur login di satu model. Bila muncul `action=unknown`, nilai kosong, atau nilai vendor seperti `Failed`, detection berbasis `action` akan bolong tepat sebesar baris itu.

**Variasi:** ganti `source` menjadi `sourcetype="jab:radius:auth"` setelah bagian 2.4 dikerjakan, lalu bandingkan dengan tabel dasar untuk memastikan seluruh 38.602 event masuk.

**Kapan gagal:** pada model yang belum diakselerasi, `tstats` tetap jalan tetapi lebih lambat karena harus menjalankan pencarian data model-nya (Day 26). Bila hasilnya nol baris, jangan langsung menyimpulkan tidak ada aktivitas: periksa dulu bagian 2.1 dan 2.3.

### 2.3 Melihat isi model langsung dengan datamodel dan fieldsummary

**Tujuan:** mengukur kelengkapan field, yaitu berapa banyak event di model yang benar-benar punya field yang dipakai investigasi.

```
| datamodel Authentication Authentication search
| search source="XmlWinEventLog:Security"
    earliest="10/15/2026:00:00:00" latest="10/16/2026:00:00:00"
| fieldsummary maxvals=5
| search field IN ("Authentication.user","Authentication.src","Authentication.dest","Authentication.action","Authentication.app")
| table field count distinct_count values
```

- `datamodel <model> <dataset> search` menjalankan constraint dataset sebagai search. Ini pola validasi resmi; dokumentasi mencontohkan `| datamodel Authentication Successful_Authentication search | search sourcetype=linux_secure | table * | fieldsummary` [S4].
- `fieldsummary` memberi statistik per field: berapa event yang terisi, berapa nilai unik, dan contoh nilainya.
- `search field IN (...)` membatasi tabel ke field yang memang kamu pakai, karena `fieldsummary` mengembalikan semua field.

Keluaran ilustrasi, dengan kolom `values` dipendekkan:

```
field                  count  distinct_count  values
Authentication.action   25060               2  success, failure
Authentication.app      25060               2  win:local, win:remote
Authentication.dest     25060              93  JKT-DC01, JKT-FS01, ...
Authentication.src      19183             514  10.10.14.22, 10.20.10.11, ...
Authentication.user     25060            1127  andi.pratama, svc_backup, ...
```

**Cara membaca hasil:** `count` kecil dibanding total event berarti banyak event tanpa field itu, alias ada celah normalisasi. Di sini `src` terisi 19.183 dari 25.060, jadi 5.877 event tidak punya alamat sumber. Untuk logon lokal dan logon service di Windows itu wajar, tetapi konsekuensinya nyata: setiap detection yang mengelompokkan `BY src` tidak melihat 5.877 event tersebut, dan korelasi aset untuk `src` juga tidak bisa jalan di sana (Day 24, Day 26).

**Variasi:** jalankan tanpa `| search field IN (...)` sekali saja untuk melihat semua field yang terisi di model itu, lalu bandingkan dengan daftar field yang direkomendasikan model tersebut di referensi CIM.

**Kapan gagal:** cek nama field hasil `datamodel` (dengan atau tanpa prefiks dataset) di versi-mu, dan apakah dataset `Successful_Authentication` ada di CIM yang kamu pakai (Day 25 mencatat perbedaan versi).

### 2.4 Menormalkan log RADIUS pelanggan ke Authentication

Sumber inilah yang membuat percobaan credential stuffing di tiket SOC-2026-0258 lolos. Contoh raw event dari `jkt-radius01`, satu baris per percobaan otentikasi pelanggan broadband:

```
2026-10-15T02:14:07+07:00 jkt-radius01 jabaaa[2184]: auth result=FAILED username=pelanggan.0192 nas=10.20.30.7 client=192.0.2.88 service=pppoe
```

Konfigurasi di app atau add-on buatan sendiri, dibagikan dengan permission yang mencakup search head ES:

`eventtypes.conf`
```
[jab_radius_auth]
search = index=linux sourcetype=jab:radius:auth "auth"
```

`tags.conf`
```
[eventtype=jab_radius_auth]
authentication = enabled
```

`props.conf`
```
[jab:radius:auth]
EXTRACT-radius_fields = result=(?<rad_result>\w+)\s+username=(?<rad_user>\S+)\s+nas=(?<rad_nas>\S+)\s+client=(?<rad_client>\S+)\s+service=(?<rad_service>\S+)
FIELDALIAS-rad_user = rad_user AS user
FIELDALIAS-rad_src = rad_client AS src
FIELDALIAS-rad_dest = rad_nas AS dest
EVAL-action = case(rad_result=="SUCCESS","success", rad_result=="FAILED","failure", true(),"unknown")
EVAL-app = "radius-pppoe"
```

Setiap baris mengerjakan satu mata rantai dari bagian 1.2. Cari di kolom kanan alasan kenapa baris itu tidak bisa dilewati.

| Baris | Fungsi | Kenapa |
|---|---|---|
| Event type `jab_radius_auth` | Mengelompokkan event otentikasi RADIUS | Tag melekat ke event type, bukan langsung ke sourcetype (Day 17) |
| Tag `authentication` | Memenuhi constraint data model Authentication | Tanpa tag, event tidak masuk model walau field-nya sempurna |
| `EXTRACT-` | Ekstraksi dengan nama sementara `rad_*` | Bisa juga langsung bernama CIM [S4]; nama sementara memudahkan membaca mana yang asli dan mana hasil pemetaan |
| `FIELDALIAS-` | Memetakan `rad_user` menjadi `user`, `rad_client` menjadi `src`, `rad_nas` menjadi `dest` | Pola alias resmi untuk menyamakan nama field [S4] |
| `EVAL-action` | Menormalkan nilai `FAILED` menjadi `failure` | CIM mengharapkan nilai tertentu; nilai vendor membuat detection buta [S2] |
| `EVAL-app` | Mengisi field `app` dengan nilai konstan | Membedakan jalur login pelanggan dari login karyawan di satu model yang sama |

Cabang terakhir `EVAL-action` menghasilkan teks `unknown` untuk nilai di luar daftar yang dikenal, sehingga bagian 2.2 bisa menemukannya sebagai baris tersendiri. Day 16 bagian 2.4 membahas pilihan lain, yaitu menghasilkan NULL, supaya nilai yang tidak dikenal tidak terlihat seperti nilai yang sah.

Validasi: jalankan bagian 2.2 dan 2.3 untuk `sourcetype="jab:radius:auth"`. Keluaran ilustrasi dari bagian 2.2 setelah konfigurasi di atas aktif:

```
action   app            signature_id  count
success  radius-pppoe                 37058
failure  radius-pppoe                  1544
```

**Cara membaca hasil:** jumlahnya 38.602, sama dengan baris RADIUS di tabel dasar, jadi seluruh event sudah terbaca model. Kolom `signature_id` kosong karena log RADIUS tidak punya kode event; itu bukan kesalahan normalisasi, dan field yang tidak ada di sumbernya memang sebaiknya dibiarkan kosong daripada diisi nilai karangan. Setelah ini, total Authentication di rentang tersebut menjadi 78.967, dan alert brute force yang sudah ada mulai menghitung percobaan ke akun pelanggan tanpa satu baris pun diubah.

**Kapan gagal:**
- Konfigurasi diletakkan di app yang izinnya tidak global, sehingga tidak berlaku saat search dijalankan dari app lain atau dari search head ES (Day 15).
- Rantai rujukan antar baris salah urutan. Field alias tidak bisa menunjuk hasil `EVAL-`, dan satu `EVAL-` tidak bisa menunjuk hasil `EVAL-` lain di stanza yang sama karena semuanya dievaluasi berbarengan. Urutan operasi search-time yang persis, beserta cara memperbaiki rantai yang gagal, ada di Day 16 bagian 1.5 dan 1.6.
- `username` di log memuat realm (`pelanggan.0192@jab.example`) di sebagian perangkat, sehingga `user` punya dua format di satu model. Periksa formatnya sebelum menulis detection yang mencocokkan nilai persis (Day 24).

### 2.5 Alat bantu kepatuhan CIM

Setelah normalisasi manual seperti bagian 2.4 dikerjakan untuk beberapa sumber, memeriksanya satu per satu menjadi tidak praktis. Tiga alat yang biasa dipakai:

- SA-cim_vladiator (komunitas, Splunkbase): mengidentifikasi field yang hilang dan nilai yang tidak sesuai harapan CIM. Versi 2.1.0 tercatat Juni 2026 [S7]; cocokkan dengan Splunkbase sebelum memasang.
- CIM Assessment Toolkit (Splunkbase) dan dashboard CIM Compliance Check di SSE [S7]. Keduanya membandingkan field dan tag data-mu dengan yang diharapkan data model; cek nama dan ketersediaannya di Splunkbase dan SSE versi-mu.
- Pemeriksaan sendiri dengan bagian 2.1 sampai 2.3, yang tidak butuh instalasi apa pun dan cukup untuk satu atau dua sumber baru per bulan.

### 2.6 Di ES (generik)

- Halaman Data Model Audit menunjukkan status akselerasi dan ukuran ringkasan per data model [S5]. Ini tempat pertama yang dibuka ketika dashboard ES lambat atau kosong.
- Pengaturan akselerasi data model di ES di-enforce, jadi ubah lewat mekanisme ES, bukan hanya lewat CIM Setup [S5]. Cek nama menunya di ES 8.x.

## 3. Lab praktik (di VM lab terisolasi)

1. Pasang Splunk CIM add-on di Splunk lab (gratis). Buka CIM Setup [S5]. Untuk Authentication dan Endpoint, isi Indexes allowlist dengan index lab-mu dan aktifkan akselerasi.
2. Jalankan bagian 2.1 sampai 2.3 untuk data Windows dan Sysmon lab. Catat celahnya: field yang kosong dan nilai di luar harapan.
3. Buat sourcetype `jab:radius:auth` dengan mengunggah file log fiktif berisi 20 baris lewat Add Data, campuran `SUCCESS` dan `FAILED` dengan beberapa username dan beberapa `client`.
4. Terapkan konfigurasi bagian 2.4 di app lab-mu, lewat UI (Settings > Event types, Tags, Fields > Field aliases dan Calculated fields) atau dengan mengedit file `.conf` bila punya akses.
5. Validasi dengan bagian 2.2 dan 2.3. Lalu jalankan detection brute force dari Day 25 dan pastikan sumber baru itu ikut terdeteksi tanpa mengubah detection-nya. Ini inti nilai CIM.
6. Dokumentasikan konfigurasimu sebagai mini TA, dengan struktur folder `default/eventtypes.conf`, `tags.conf`, dan `props.conf`.
7. Rusak satu mata rantai dengan sengaja: matikan tag `authentication` pada event type baru itu, jalankan ulang bagian 2.2, dan catat bentuk kegagalannya. Lalu kembalikan tag dan ganti satu nilai `action` menjadi `Failed`, jalankan ulang, dan bandingkan dua bentuk kegagalan itu.

**Hasil yang sebaiknya tersimpan:**
- CIM Setup dengan allowlist index dan akselerasi aktif untuk model yang dipakai.
- Laporan celah normalisasi untuk Windows dan Sysmon lab.
- Sourcetype baru muncul di Authentication dengan `action` bernilai `success` dan `failure`.
- Detection Day 25 menangkap sumber baru itu tanpa modifikasi.
- Catatan dua bentuk kegagalan dari langkah tujuh, yaitu tag hilang dan nilai salah.

**Variasi tantangan:** tambahkan lookup `radius_reason.csv` yang memetakan kode error perangkat ke field CIM `reason`, pasang sebagai automatic lookup, lalu validasi dengan `fieldsummary`.

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Event tidak masuk data model | Tidak ada tag yang sesuai constraint | Bagian 2.1; perbaiki event type dan tag [S4] |
| Masuk model, tetapi detection tidak fire | Nilai field tidak sesuai harapan, misalnya `Failed` | Bagian 2.2; normalisasi nilai dengan `EVAL-` atau lookup [S2][S4] |
| Field alias tidak muncul | Izin knowledge object masih private atau app, atau sourcetype salah | Bagikan ke app atau global; cek stanza (Day 15, Day 16) |
| Akselerasi kembali ke setelan lama | ES meng-enforce pengaturan | Ubah lewat mekanisme enforcement ES [S5] |
| Data model lambat | Tanpa index allowlist | CIM Setup > Indexes allowlist [S5] |
| `stats count BY eventtype` nol baris, bukan nol count | Field `eventtype` tidak terisi sama sekali | Isi dulu dengan `fillnull` seperti variasi di bagian 2.1 |
| Validator menunjukkan 0% compliance padahal field ada | Konfigurasi validator, nama dataset, atau versi CIM | `[komunitas]` kasus serupa dilaporkan di Splunk Community [S7], perlu dicek |

## 5. Kesalahan umum dan jebakan

- Mengira memasang add-on CIM berarti data sudah ternormalisasi. Add-on CIM membawa kamusnya; yang menormalisasi adalah TA vendor atau konfigurasimu sendiri [S1].
- Memilih data model berdasarkan nama field, bukan tujuan event [S4].
- Mengira field CIM saja cukup. Tag dan nilai yang benar sama pentingnya [S2].
- Menimpa field CIM dengan `eval` di search dan menganggap itu normalisasi. Itu hanya berlaku di satu search (Day 11).
- Akselerasi semua data model tanpa allowlist index. Mahal, dan model yang menyapu index yang tidak relevan juga lebih lambat (Day 25, Day 26) [S5].
- Lupa bahwa ES meng-enforce akselerasi, lalu mengubah setelan yang sama berulang kali di tempat yang salah [S5].
- Menyimpulkan "tidak ada aktivitas" dari `tstats` yang nol baris, padahal yang kosong adalah data model-nya.
- `[komunitas]` Banyak pertanyaan di Splunk Community berbentuk "cara membuat data CIM-compliant di ES" [S7]. Jawabannya hampir selalu sama: pakai TA vendor, lalu validasi tag dan field. Konsisten dengan dokumentasi [S4].

## 6. Catatan terkini

Bagian ini menampung detail versi dan perubahan istilah yang berguna saat membaca dokumentasi lama, bukan keputusan sehari-hari.

- **CIM 6.4.0 (Feb 2026):** field unit bisnis baru di Data Access untuk aset dan identitas, plus tambahan field di Network Sessions, Network Traffic, dan Endpoint [S3].
- Dokumentasi CIM kini memakai istilah allowlist, dulu whitelist [S5].
- Alat validasi komunitas aktif diperbarui (SA-cim_vladiator 2.1.0 dan CIM Assessment Toolkit 2.10.0, keduanya tercatat Juni 2026) [S7]; versi ini perlu dicocokkan dengan Splunkbase.
- ES 8 menyelaraskan istilahnya dengan OCSF (Day 45). CIM tetap menjadi skema data model yang dipakai ES 8; cek hubungan CIM dan OCSF di dokumentasi ES 8.

## 7. Cheat sheet

```
CIM = skema saat search (add-on Splunk_SA_CIM): data model = field + tag (+ nilai yang diharapkan)
      add-on CIM memberi KAMUS, bukan data; yang menormalisasi = TA vendor atau konfigurasimu

MASUK MODEL: event type -> tag (constraint) -> field CIM (EXTRACT/FIELDALIAS/EVAL) -> nilai benar (EVAL/lookup)
             tag hilang  = event tidak ada di model
             nilai salah = event ada di model, tapi filter detection tidak menemukannya

PILIH MODEL berdasarkan TUJUAN event (login -> Authentication), bukan nama field

ALUR: ingest -> tentukan DM -> event type + tag -> verifikasi tag -> alias/extract/lookup
      -> validasi (datamodel/Pivot) -> (extend) -> (package TA)

SETUP: Apps > Manage Apps > CIM Set up : Indexes allowlist | Tags allowlist | Accelerate
       Summary range | Backfill range | Max summarization time
       akselerasi CIM default OFF ; ES meng-enforce ; capability accelerate_datamodel

VALIDASI: index=.. source=.. | stats count BY tag eventtype        (mata rantai 1-2)
          | tstats count from datamodel=DM where .. by DM.action   (mata rantai 4)
          | datamodel DM Dataset search | search .. | fieldsummary (kelengkapan field)
          eventtype kosong -> fillnull dulu, kalau tidak hasilnya nol BARIS

DM 6.4: Authentication, Endpoint, Network_Traffic, Network_Resolution, Web, Email, Intrusion_Detection,
        Malware, Change, Data_Access, Vulnerabilities, Alerts, Certificates, DLP, Databases,
        Network_Sessions, Updates, Inventory, Performance, ...
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Tim platform melapor: "Add-on CIM sudah terpasang di search head, jadi data kita sudah CIM-compliant." Apa yang salah dari kalimat itu?

<details><summary>Jawaban</summary>

Add-on CIM hanya membawa kamusnya: data model, dokumentasi, alat validasi, dan model aksi umum. Ia tidak menyentuh data sama sekali, karena CIM bekerja sebagai skema saat search dan raw data tidak diubah. Yang membuat data patuh adalah TA vendor atau konfigurasi yang kamu tulis sendiri, yang memberi event type dan tag, menyamakan nama field, dan menormalkan nilainya. Kepatuhan juga bukan sifat satu instalasi, melainkan sifat per sourcetype, dan harus diukur satu per satu. Lihat bagian 1.1 dan 1.2.

</details>

**2. Skenario keputusan.** Log RADIUS pelanggan memuat `username`, alamat IP klien, alamat NAS, dan nama layanan. Karena isinya banyak alamat IP, rekanmu mengusulkan memasukkannya ke Network Traffic. Mana yang kamu pilih?

- A. Network Traffic, karena field-nya paling cocok dipetakan ke `src` dan `dest`.
- B. Authentication, karena peristiwa yang dicatat log itu adalah percobaan masuk yang berhasil atau gagal.
- C. Keduanya, dengan dua set tag, supaya dashboard jaringan dan dashboard akses sama-sama terisi.

<details><summary>Jawaban</summary>

B. Dokumentasi menyuruh menentukan data model berdasarkan tujuan event, bukan berdasarkan nama field yang tersedia, dan tujuan log RADIUS adalah menjawab apakah sebuah akun berhasil masuk. A keliru karena kosakata nilai `action` di model trafik berbeda dari kosakata otentikasi, sehingga login gagal akan ikut terhitung oleh detection yang menghitung koneksi ditolak, sementara data model Authentication yang menyaring `action="failure"` tetap kosong. C bukan jalan tengah yang aman: ia menggandakan event di dua model dengan dua kosakata nilai yang bertentangan, dan setiap angka yang dihasilkan keduanya menjadi tidak bisa dipercaya. Lihat bagian 1.3 dan 2.4.

</details>

**3. Pertanyaan jebakan.** Sebuah sourcetype firewall sudah punya event type dan tag yang benar, dan `| tstats count from datamodel=Network_Traffic` memperlihatkan event-nya. Tetapi detection yang menyaring `action="blocked"` tidak pernah fire. Apa yang terjadi?

<details><summary>Jawaban</summary>

Mata rantai keempat yang putus, yaitu nilai field. Event sudah masuk model karena tag-nya benar, tetapi nilai `action`-nya masih kosakata vendor, misalnya `deny` atau `drop`, sedangkan filter detection mencari nilai yang diharapkan CIM. Bedakan dua gejala ini saat troubleshooting: tag yang hilang membuat event tidak ada sama sekali di model, sedangkan nilai yang salah membuat event ada di model tetapi tidak terjawab oleh filter. Perbaikannya di sisi normalisasi nilai, lewat calculated field atau lookup, bukan dengan menambahkan `OR action="deny"` ke detection-nya. Lihat bagian 1.2 dan 2.2.

</details>

**4. Skenario keputusan.** Dashboard ES lambat, dan tim platform menyalakan akselerasi untuk semua data model CIM dari halaman CIM Setup. Dua hari kemudian setelan itu kembali ke keadaan lama dan dashboard tetap lambat. Langkah mana yang benar?

- A. Ulangi perubahan dari CIM Setup dan buat jadwal untuk memeriksanya setiap pagi.
- B. Isi Indexes allowlist per data model, nyalakan akselerasi hanya untuk model yang benar-benar dipakai, dan lakukan perubahannya lewat mekanisme enforcement ES, lalu pantau di Data Model Audit.
- C. Matikan akselerasi seluruhnya dan andalkan `summariesonly=false` di semua panel.

<details><summary>Jawaban</summary>

B. Dua fakta bergabung di sini: akselerasi data model CIM non-aktif secara default dan pengaturannya dipaksakan oleh ES bila ES terpasang, sehingga perubahan hanya bertahan bila dilakukan lewat modular input enforcement ES. Selain itu akselerasi tanpa Indexes allowlist membuat model menyapu index yang tidak relevan, dan itu sendiri sudah menjadi penyebab lambat. A memperbaiki gejala dan mengulang pekerjaan setiap hari tanpa pernah menyentuh penyebabnya. C menukar lambat dengan jauh lebih lambat, karena setiap panel lalu harus menelusuri data mentah setiap kali dibuka. Lihat bagian 1.4 dan 1.5.

</details>

**5. Jelaskan ulang.** Jelaskan kepada SOC lead PT JAB dalam tiga kalimat kenapa sebuah sumber log bisa sudah masuk Splunk dengan volume besar dan tetap tidak terlihat oleh satu pun detection.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh jawaban: "Detection dan dashboard kita tidak membaca index, mereka membaca data model, dan data model memilih anggotanya berdasarkan label dan nama field, bukan berdasarkan besarnya volume. Sumber yang masuk tanpa add-on yang menormalisasi tidak punya event type, tidak punya tag, dan nama field-nya masih bahasa vendor, jadi dia ada di index tetapi nol di model. Yang membuat ini berbahaya adalah tidak ada error sama sekali: alert tetap hijau, dashboard tetap terisi dari sumber lain, dan satu-satunya gejalanya adalah angka yang lebih kecil daripada kenyataan."

Kesalahan yang sering muncul:
- Menjawab dengan masalah lisensi atau retensi, padahal datanya memang ada dan bisa dicari langsung.
- Menyebut tag saja dan melupakan nama serta nilai field, sehingga separuh rantainya hilang.
- Menjanjikan bahwa memasang add-on CIM akan menyelesaikan masalahnya.
- Lupa menyebut bahwa kegagalan ini tidak memunculkan error, yang justru bagian paling penting bagi orang yang mengambil keputusan dari dashboard.

</details>

**6. Pertanyaan jebakan.** Setelah menormalkan sumber baru, kamu menjalankan `| tstats count from datamodel=Authentication where sourcetype="jab:radius:auth" by Authentication.action` dan hasilnya nol baris. Apakah ini berarti tidak ada percobaan login di rentang itu?

<details><summary>Jawaban</summary>

Tidak. Nol baris dari `tstats` atas data model berarti model itu tidak punya event yang cocok di rentang tersebut, dan penyebab yang paling sering adalah tag yang belum menempel, event type yang tidak cocok dengan event, atau konfigurasi yang masih private sehingga tidak berlaku di search head tempat kamu mencari. Bila kamu memakai `summariesonly=true`, rentang yang belum masuk ringkasan akselerasi juga memberi nol baris walau datanya ada. Urutan pemeriksaannya: hitung dulu dari index dengan `stats count BY tag eventtype` dan isi field kosongnya dengan `fillnull` supaya barisnya tidak terbuang, lalu jalankan `| datamodel Authentication Authentication search` untuk melihat isi model tanpa bergantung pada ringkasan akselerasi. Lihat bagian 2.1, 2.2, dan 2.3.

</details>

**7. Interview question (English).** "You onboard a new log source and the SOC wants your existing detections to cover it. Walk me through what you do and how you prove it works."

<details><summary>Sample answer</summary>

"First I check whether a vendor add-on exists, because the add-on does the normalisation and I would rather verify someone else's mapping than write my own. If there is none, I decide which CIM data model the source belongs to based on what the events are about, not on which fields happen to be present, so customer RADIUS authentication goes to Authentication even though it is full of IP addresses. Then I work the chain: an event type that matches the events, a tag on that event type that satisfies the model's constraint, field names aliased or calculated to the CIM names, and values normalised to the ones the model expects, because `FAILED` is not `failure` and a detection filtering on `action=failure` will quietly miss everything. Proving it is the part people skip, so I do three checks: count by tag and event type from the index to confirm the labels landed, `tstats` from the data model grouped by `action` to confirm the values, and `datamodel ... search` with `fieldsummary` to see how complete the key fields really are, since a field that is only populated in sixty percent of events will silently shrink any detection that groups by it. The final proof is behavioural: I run the existing brute force detection unchanged and confirm it now fires on the new source. I also set the model's index allowlist and only accelerate the models we actually use, and in an ES environment I make acceleration changes through the enforcement mechanism, otherwise they revert and everyone blames the dashboard."

What makes this answer strong: it prefers verifying a vendor add-on over hand-rolling, picks the model from event purpose rather than field names, names all four links of the membership chain including the value vocabulary, proves coverage with three different measurements plus an unchanged detection, and treats index allowlist and ES acceleration enforcement as part of onboarding rather than platform trivia.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Overview of the Splunk Common Information Model | https://help.splunk.com/en/data-management/common-information-model | primer | diakses 2026-10-07 | Tinggi. Halaman menampilkan label versi 8.7 (lihat catatan bagian 1.1) |
| S2 | CIM 6.4: How to use the CIM data model reference tables (daftar data model) | https://help.splunk.com/en/data-management/common-information-model/6.4/data-models | primer | diakses 2026-10-07 | Tinggi. Daftar model, nilai yang diharapkan ES |
| S3 | CIM 6.4: Release notes | https://help.splunk.com/en/data-management/common-information-model/6.4/introduction/release-notes-for-the-splunk-common-information-model-add-on | primer | 2026-02-04 | Tinggi |
| S4 | Use the CIM to normalize data at search time (dok 6.1) | https://help.splunk.com/en/data-management/common-information-model/6.1/using-the-common-information-model/use-the-cim-to-normalize-data-at-search-time | primer | diakses 2026-10-07 | Tinggi. Alur normalisasi, contoh konfigurasi, pola validasi dengan `datamodel` dan `fieldsummary` |
| S5 | Set up the Splunk Common Information Model Add-on (dok 6.2) | https://help.splunk.com/en/data-management/common-information-model/6.2/introduction/set-up-the-splunk-common-information-model-add-on | primer | diakses 2026-10-07 | Tinggi. Allowlist, akselerasi, enforcement ES, capability, Data Model Audit |
| S6 | Lantern: Managing data models in ES (lihat Day 25) | https://lantern.splunk.com/Security/Product_Tips/Enterprise_Security/Managing_data_models_in_Enterprise_Security | primer | diakses 2026-10-07 | Tinggi |
| S7 | SA-cim_vladiator (GitHub dan Splunkbase), CIM Assessment Toolkit, Splunk Community "SA-cim validator showing 0% compliance", "How to make CIM compliant data in ES" | https://github.com/hire-vladimir/SA-cim_vladiator | komunitas | tanggal tidak tercatat | Rendah sampai sedang. Versi dan tanggal perlu dicocokkan dengan Splunkbase |

**Catatan sumber:** panduan normalisasi dan setup yang dirujuk adalah dokumentasi CIM 6.1 dan 6.2 [S4][S5]; isinya diasumsikan masih berlaku untuk 6.4, jadi cek bila ada perbedaan menu. Versi alat validasi komunitas [S7] perlu dicocokkan dengan Splunkbase. Semua angka di keluaran ilustrasi disusun agar konsisten dengan tabel dasar di awal bagian 2 dan bisa dijumlahkan ulang, tetapi bukan hasil eksekusi; nilai `app` untuk Windows dan nama sourcetype `jab:radius:auth` adalah contoh, bukan nilai yang dijamin ada di add-on versi-mu. Pemetaan log RADIUS fiktif di bagian 2.4 mengikuti pola konfigurasi di dokumentasi CIM [S4], bukan contoh resmi untuk RADIUS.
