---
day: 26
title: 'Acceleration dan Asset & Identity framework: dari summary data model sampai konteks src_priority dan user_category'
researched_on: 2026-10-14
versions_checked: Splunk Enterprise Security 8.7 (Add asset and identity data; Configure asset and identity correlation; Asset and identity fields after processing); Splunk CIM 6.4; Splunk Enterprise 10.6 (Knowledge Manager Manual 10.6 dan 10.4 untuk acceleration)
---

# Day 26: Acceleration dan Asset & Identity framework

Cakupan: akselerasi data model (summary, ukuran, pemantauan) dan Asset and Identity framework di ES untuk memperkaya finding dengan konteks aset dan identitas.

## Ide inti

Dua hal yang membuat SIEM bisa dipakai di skala PT JAB tidak pernah muncul di search yang kamu tulis. Yang pertama adalah ringkasan yang dibangun di belakang: akselerasi data model menjalankan search terjadwal yang menulis summary tsidx di indexer, dan itulah yang dibaca `tstats summariesonly=true` di hampir semua detection. Yang kedua adalah daftar aset dan identitas: ES mencocokkan setiap event dengan daftar itu saat search, lalu menempelkan konteks seperti prioritas, unit bisnis, kategori, dan status karyawan. Yang pertama menentukan apakah detection selesai pada waktunya, yang kedua menentukan apakah hasilnya bisa diurutkan. Keduanya sama-sama pekerjaan pemeliharaan, dan keduanya gagal tanpa pesan error: summary yang tertinggal mengembalikan hasil kosong, dan aset yang tidak terdaftar menghasilkan alert tanpa prioritas.

Alert yang sama, "login gagal 50 kali", punya arti berbeda bila targetnya domain controller berprioritas critical atau VM uji berprioritas low. Tanpa konteks itu, analyst menebak, dan antrean dikerjakan menurut urutan kedatangan. Dengan konteks itu, urutan kerja ditentukan oleh nilai aset dan identitas yang terlibat, dan konteks yang sama dipakai lagi saat skor risiko dihitung per entity.

Keduanya punya padanan di pekerjaan NOC. Akselerasi adalah counter SNMP yang sudah diagregasi: rekap panjang selesai cepat karena angkanya dihitung di belakang, dengan batas bahwa ringkasan selalu tertinggal dari data mentah dan hanya memuat field yang memang didefinisikan. Asset & Identity adalah CMDB dan direktori karyawan yang ditempelkan ke setiap alert, dengan batas yang lebih keras: kualitasnya sebatas daftar yang kamu isi, jadi perangkat yang tidak terdaftar tidak akan pernah mendapat prioritas, dan tidak ada mekanisme yang memberitahu bahwa prioritasnya hilang.

```
Log mentah di index
  |
  |-- akselerasi data model: search summarization berjalan terjadwal, per bucket
  |     -> summary tsidx di indexer (hanya field yang didefinisikan model,
  |        hanya di dalam summary range)
  |     -> dibaca tstats summariesonly=true oleh detection dan dashboard
  |
  +-- korelasi aset dan identitas: automatic lookup saat search
        sumber (Exposure Analytics, CSV, LDAP/AD, cloud)
          -> merge oleh identity manager
          -> asset_lookup_by_str, asset_lookup_by_cidr, identity_lookup_expanded
          -> src, dest, dvc dicocokkan ke aset ; user, src_user ke identitas
          -> event membawa src_priority, dest_category, user_bunit, dan seterusnya
```

Situasi yang dipakai sepanjang Day ini: minggu ini SOC lead PT JAB menulis dua keluhan di satu pesan.

> "Pertama, beberapa dashboard ES dan detection lambat, dan satu laporan malah kosong padahal lognya ada. Tim platform bilang akselerasi data model kita 'kadang tertinggal' dan disk di indexer mulai terasa. Saya mau tahu apa yang sebenarnya dibangun di belakang, apa yang menentukan biayanya, dan dari mana saya melihat statusnya tanpa menanyakan mereka. Kedua, antrean L1 tidak bisa diprioritaskan. Alert login gagal ke `JKT-DC01` dan ke satu workstation uji di lab jaringan muncul sama pentingnya. Daftar aset kita baru berisi server data center Jakarta: perangkat POP Bandung, Surabaya, dan Medan belum masuk sama sekali, begitu juga perangkat yang kita pasang di sisi pelanggan korporat, dan kontraktor yang kontraknya sudah habis masih terdaftar sebagai karyawan aktif. Saya butuh angka berapa persen yang tidak dikenal dan akibatnya kalau dibiarkan."

Pesan itu memuat enam pertanyaan:

1. Apa yang dibangun akselerasi, seberapa sering, dan apa yang menentukan biaya serta cakupannya?
2. Dari mana ES mendapat daftar aset dan identitas, dan apa yang terjadi pada data itu sebelum dipakai?
3. Field apa yang tersedia setelah pemrosesan, dan mana yang berguna untuk triage?
4. Bagaimana sebuah event mendapat konteks itu, dan kenapa sebagian event tidak mendapatnya?
5. Apa akibat aset dan identitas yang tidak dikenal terhadap urgensi, detection, dan risk?
6. Berapa persen entitas yang tidak dikenal, dan bagaimana mengukurnya?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, dan pertanyaan 5 di bagian 1.5. Pertanyaan 6 dijawab sebagai search di bagian 2.4, dan bagian 2.1 sampai 2.3 menyiapkan jalannya.

**Kapan relevan:** saat detection atau dashboard yang memakai data model lambat atau hasilnya kosong, saat memutuskan model mana yang di-accelerate dan dengan summary range berapa, saat antrean alert tidak bisa diurutkan karena semua alert tampak sama penting, dan saat menyiapkan risk based alerting atau laporan kualitas data aset.
**Kapan bukan jawaban:** akselerasi tidak memperbaiki data yang belum ternormalisasi, karena model dengan tag dan field yang salah hanya menghasilkan summary kosong lebih cepat (Day 23). Asset & Identity juga bukan pengganti inventaris: ES hanya menempelkan apa yang ada di daftar, jadi perangkat POP yang tidak pernah masuk CMDB tetap tidak dikenal, dan memperbaikinya adalah pekerjaan pemilik aset. Untuk sintaks `tstats` dan `summariesonly`, lihat Day 25; untuk syarat desain model agar bisa di-accelerate, Day 22 bagian 1.8.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (data model, dataset, constraint, attribute, CIM, tag, lookup, `tstats`, `summariesonly`, tsidx) tidak diulang di sini. Tabel ini hanya memuat istilah yang dipakai Day ini; cari kolom padanan bila sebuah istilah terasa asing.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Summary data model | Berkas ringkasan per bucket yang memuat field data model, dibangun oleh search terjadwal dan disimpan di indexer [S1][S7] | Rekap yang dihitung di belakang, bukan log aslinya |
| Summarization period | Jadwal search pembangun summary, default setiap lima menit dan diatur dengan cron [S7] | Interval polling di NMS |
| Max summarization search time | Batas kasar durasi satu jalannya search summarization, default satu jam; jalannya berikutnya melanjutkan dari titik terakhir [S7] | Batas durasi satu job pengumpul data |
| Maximum concurrent summarization searches | Jumlah search summarization yang boleh berjalan bersamaan, default tiga [S7] | Jumlah job polling paralel yang diizinkan |
| Summary range | Rentang waktu ke belakang yang dicakup summary; nilai kosong berarti All Time, dan cakupannya perkiraan karena summary dibangun per bucket [S7] | Berapa lama data detail disimpan sebelum diringkas |
| Backfill range | Rentang awal yang lebih pendek supaya summary tumbuh bertahap menuju rentang penuh [S7] | Mengisi data historis sedikit-sedikit agar tidak membebani |
| Ad hoc acceleration | Ringkasan sementara di search head untuk pivot atas model yang tidak di-accelerate [S7] | Hitungan sekali pakai yang dibuang setelah laporan selesai |
| Automatic rebuild | Pembangunan ulang summary ketika knowledge object yang dipakai model berubah, menyala secara default [S7] | Kalibrasi ulang setelah template laporan diubah |
| Asset & Identity framework (A&I) | Mekanisme ES yang mengorelasikan daftar aset dan identitas dengan event sehingga event diperkaya saat search [S3] | CMDB dan direktori karyawan yang ditempelkan ke setiap alert |
| Aset | Perangkat atau sistem yang dikenali lewat IP, MAC, nama DNS, atau nama NetBIOS [S4][S5] | Satu baris inventaris perangkat |
| Identitas | Orang atau akun beserta atributnya, dikenali lewat beberapa bentuk nama sekaligus [S4] | Satu baris direktori karyawan |
| Identity manager | Modular input ES yang memproses semua konfigurasi sumber lalu menggabungkannya menjadi lookup gabungan [S3] | Rekonsiliasi beberapa daftar inventaris menjadi satu daftar induk |
| `asset_lookup_by_str`, `asset_lookup_by_cidr`, `identity_lookup_expanded` | Lookup hasil merge: pencocokan string, pencocokan rentang jaringan, dan daftar identitas yang sudah diperluas [S3] | Tabel master yang dipakai semua laporan |
| `priority`, `bunit`, `category`, `watchlist` | Konteks bisnis dan risiko yang dibawa aset dan identitas [S4] | Kolom kekritisan, unit, kategori, dan daftar pantau di inventaris |
| Korelasi aset dan identitas | Automatic lookup saat search yang mencocokkan `src`, `dest`, `dvc` ke daftar aset dan `user`, `src_user` ke daftar identitas [S5] | Menempelkan kolom inventaris ke setiap baris laporan |
| Field berprefiks | Hasil korelasi, dinamai menurut field asal yang cocok, misalnya `src_priority`, `dest_category`, `user_bunit` [S5] | Kolom hasil VLOOKUP yang dinamai menurut kolom kuncinya |
| Exposure Analytics entity discovery | Sumber aset dan identitas otomatis yang diutamakan di ES 8.x bila tersedia [S3] | Penemuan perangkat otomatis di NMS |

### 1.1 Akselerasi sebagai sistem yang berjalan terus

Keluhan pertama SOC lead ("kadang tertinggal" dan disk indexer mulai terasa) tidak bisa dijawab dari search mana pun, karena yang dipersoalkan adalah proses yang berjalan di belakang. Dasarnya:

- Akselerasi membangun summary tsidx di indexer untuk field data model. Search terjadwal sekitar setiap 5 menit, summary range menentukan cakupan waktu, dan max summarization search time default sekitar 1 jam [S1].
- Akselerasi data model CIM nonaktif secara default. Saat ES terpasang, akselerasi dipaksakan oleh ES lewat mekanisme enforcement [S2].
- Summary hanya mencerminkan definisi model saat dibangun. Mengubah constraint atau field berarti summary harus dibangun ulang (lihat `allow_old_summaries`, Day 25).
- Biaya: disk di indexer, CPU dari search akselerasi, dan beban scheduler. Lantern menyarankan perencanaan kapasitas dan audit rutin. Angka perkiraan penyimpanan di Lantern ("sekitar 3,4x volume input harian" per tahun), cek konteks dan satuannya sebelum dikutip.

Angka operasional yang menentukan kapan summary tertinggal dan berapa biayanya, semuanya dari halaman acceleration [S7]:

| Pengaturan | Default | Yang terjadi bila diubah |
|---|---|---|
| Summarization period | setiap lima menit, berbentuk cron | Memperpanjang jarak berarti summary lebih sering tertinggal dari data mentah |
| Max summarization search time | satu jam, sebagai batas kasar | Search dihentikan lalu dilanjutkan jalannya berikutnya, jadi model yang terlalu luas bisa tidak pernah mengejar |
| Maximum concurrent summarization searches | tiga | Menaikkannya menambah pemakaian memori, CPU, dan disk I/O, dan bisa menyentuh batas kuota search otomatis |
| Pembersihan summary tsidx kedaluwarsa | setiap 30 menit | Interval ini dan interval di baris-baris sebelumnya diatur lewat `datamodels.conf` dan `limits.conf` |
| Automatic rebuilds | menyala | Dimatikan untuk model dengan summary besar, karena rebuild membebani dan menaikkan pemakaian memori; rebuild manual lewat Data Model Manager |

Tempat summary disimpan menentukan siapa yang harus dilibatkan ketika disk indexer mulai menipis [S7]. Untuk index biasa, summary berada berdampingan dengan bucket asalnya, secara default di bawah volume `_splunk_summaries` dan tanpa batas ukuran, kecuali kamu mengarahkan `tstatsHomePath` atau membatasi volume khusus dengan `maxVolumeDataSizeMB`. Untuk index SmartStore, indexer membangun summary lalu mengunggahnya ke remote storage, `tstatsHomePath` tidak boleh diatur, dan `maxVolumeDataSizeMB` tidak berlaku. Ringkasan ad hoc yang dibuat untuk pivot atas model yang tidak di-accelerate hidup di direktori dispatch search head, jadi ia tidak pernah menolong detection terjadwal.

Soal cakupan, summary range menentukan sejauh mana ke belakang hasil `summariesonly=true` masih bisa dipercaya [S7]. Nilai kosong berarti All Time, cakupannya perkiraan karena summary dibangun per bucket, dan ia tidak bisa melampaui retensi index sumber. Search yang rentangnya sebagian di luar summary range memakai summary untuk bagian yang tercakup dan data mentah untuk sisanya. Bila sebuah model perlu rentang panjang tetapi tidak boleh membebani indexer sekaligus, Backfill Range membangun summary sebagian lebih dulu lalu menumbuhkannya.

Statusnya dibaca di Settings > Data Models: buka baris modelnya, lalu lihat bagian ACCELERATION, yang menampilkan Complete atau Building beserta persentasenya [S7]. Persentase itu dihitung terhadap Schedule Window, atau terhadap backfill range bila kamu menyetelnya, jadi "100 persen" berarti summary lengkap untuk rentang yang kamu minta, bukan untuk seluruh isi index. Metrik Size on Disk di halaman yang sama bisa lebih kecil dari kenyataan untuk model dengan beberapa root object, karena ia hanya mencerminkan satu root object; angka yang bisa dipakai untuk kapasitas diambil dari data `disk_objects.log` di index `_introspection`, yang melaporkan total per indexer [S7]. Untuk memastikan search summarization benar-benar terjadwal, dokumentasi menyebut penyetelan `category.SavedSplunker=DEBUG` di `log.cfg` lalu memeriksa `scheduler.log` [S7].

**Prinsip:** akselerasikan data model yang dipakai detection/dashboard, batasi index lewat allowlist, dan pilih summary range sesuai kebutuhan detection (bukan "All time").

Untuk PT JAB, urutan kerjanya menjadi jelas: data model yang dipakai detection dan dashboard (Authentication, Network_Traffic, Endpoint) di-accelerate dengan allowlist index yang hanya memuat index yang benar-benar menyuplainya, summary range dipilih dari rentang terpanjang yang dibutuhkan detection, dan status serta ukurannya dicatat sebagai angka rutin, bukan dicari saat ada keluhan.

### 1.2 Apa itu Asset & Identity framework

Keluhan kedua SOC lead berakar di sini. Konteks yang membuat antrean bisa diurutkan tidak datang dari log, melainkan dari daftar terpisah yang harus diisi, digabungkan, dan dirawat sebelum ES bisa menempelkannya ke event.

ES memakai sistem aset dan identitas untuk mengorelasikan informasi aset/identitas dengan event, sehingga event diperkaya konteks saat search [S3].

Sumber data di ES 8.7 [S3]:
1. Exposure Analytics entity discovery, sumber yang diutamakan dan otomatis bila tersedia, cek lisensi/ketersediaan Exposure Analytics di deployment-mu.
2. Lookup CSV manual lewat Asset and Identity Manager.
3. LDAP/Active Directory.
4. Penyedia cloud.

Alur penambahan data [S3]:

```
kumpulkan data -> format sebagai lookup -> lookup definition -> daftarkan di Asset and Identity Manager -> verifikasi
```

Setelah itu, identity manager (modular input) memproses semua konfigurasi dan menggabungkan (merge) data berdasarkan field kunci dan kebijakan yang kamu tentukan. Hasilnya ditulis ke lookup gabungan, antara lain [S3]:
- `asset_lookup_by_str`: pencocokan string (IP tunggal, nama, MAC);
- `asset_lookup_by_cidr`: pencocokan rentang jaringan;
- `identity_lookup_expanded`.

Akses pengelolaan membutuhkan capability `edit_modinput_identity_manager` [S3].

Di PT JAB keempat sumber itu tidak setara. Direktori karyawan sudah ada di Active Directory dan bisa disambungkan, sedangkan inventaris perangkat POP dan perangkat yang dipasang di sisi pelanggan korporat masih berupa spreadsheet milik NOC. Jalur paling realistis untuk gelombang pertama adalah ekspor CSV terjadwal dari spreadsheet itu yang didaftarkan lewat Asset and Identity Manager, dengan satu pemilik yang bertanggung jawab memperbaruinya, lalu AD untuk identitas. Yang penting dicatat sejak awal: menambahkan sumber tidak sama dengan menyelesaikan masalah, karena hasil merge-lah yang dipakai, dan merge bisa gagal tanpa pesan yang jelas (bagian 4).

### 1.3 Field aset dan identitas

Setelah merge, setiap baris aset dan identitas punya bentuk baku. Tabel di bawah ada supaya kamu bisa memilih kolom mana yang benar-benar harus diisi lebih dulu ketika daftar masih kosong, dan mengenali field yang dibangkitkan ES sendiri sehingga tidak perlu kamu sediakan.

Aset (setelah pemrosesan) [S4]:

| Field | Arti / pemrosesan |
|---|---|
| `ip` | Divalidasi dan dipecah ke subnet CIDR bila perlu; multivalue |
| `mac`, `nt_host`, `dns` | Pengenal lain; menjadi kunci pencocokan |
| `asset_id`, `asset` | Diturunkan dari ip/mac/nt_host/dns |
| `owner`, `priority`, `bunit`, `category` | Konteks bisnis. `category` diperkaya "pci" bila mengandung "cardholder" |
| `pci_domain` | wireless/trust/untrust/cardholder/dmz |
| `is_expected`, `should_timesync`, `should_update`, `requires_av` | Dinormalkan ke boolean |
| `lat`, `long`, `city`, `country` | Lokasi |
| `asset_tag` | Dibangkitkan dari category, pci_domain, flag boolean, dan bunit |
| `cim_entity_zone` | Hanya bila entity zones aktif |

Identitas [S4]:

| Field | Arti / pemrosesan |
|---|---|
| `identity` | Dibangkitkan dari baris input dan konvensi di Identity Lookup Configuration; multivalue (mis. `rina.wulandari`, `JAB\rina.wulandari`, `rina.wulandari@corp.jab.example`) |
| `identity_id` | Dari identity, first, last, email |
| `first`, `last`, `email`, `prefix`, `suffix`, `nick`, `phone`, `managedBy` | Atribut orang |
| `priority`, `bunit`, `category` | Konteks bisnis/risiko |
| `watchlist` | Boolean, untuk user yang perlu diawasi |
| `startDate`, `endDate` | Masa kerja. Aktivitas setelah `endDate` adalah sinyal kuat |
| `work_city`, `work_country`, `work_lat`, `work_long` | Lokasi kerja |
| `identity_tag` | Dari bunit, category, watchlist |

Nilai `priority` yang umum dipakai ES adalah `unknown`, `low`, `medium`, `high`, `critical`. Halaman pemrosesan field tidak menyebut daftar nilai yang diizinkan [S4], cek di dokumentasi format lookup aset/identitas.

Untuk PT JAB, dua kolom menentukan hasil paling cepat. `priority` membuat `JKT-DC01` tidak lagi sejajar dengan workstation lab di antrean, dan `endDate` mengubah akun kontraktor yang kontraknya sudah habis dari baris lama yang tidak diperhatikan menjadi sinyal yang bisa dicari. Keduanya murah diisi dan tidak menunggu proyek CMDB selesai.

### 1.4 Korelasi: bagaimana event diperkaya

Daftar yang lengkap belum berarti setiap event ikut diperkaya. Yang menentukan adalah field apa yang ada di event itu dan apakah korelasi dinyalakan untuk sourcetype-nya.

Saat korelasi aktif, ES membandingkan event dengan daftar aset/identitas memakai automatic lookup saat search [S5]:
- **Aset:** field event `src`, `dest`, atau `dvc` dicocokkan dengan IP, MAC, nama DNS, atau nama NetBIOS di daftar aset.
- **Identitas:** field `user` atau `src_user` dicocokkan dengan daftar identitas.
- Field hasil diberi prefiks sesuai field asalnya. Contoh: `src` menghasilkan `src_is_expected`, `src_should_timesync`, dan seterusnya. Pola yang sama memberi `src_priority`, `dest_category`, `user_bunit`, cek nama persis di event lab-mu.
- **Penting:** korelasi tidak lagi otomatis dilakukan terhadap field `host` atau `orig_host` [S5]. Jadi event yang hanya punya `host` tidak akan diperkaya kecuali dinormalkan ke `dest`/`src`/`dvc` lewat CIM (Day 23).

Pengaturan di Configure > All configurations > Assets and identities > Correlation setup [S5]:
- aktif untuk semua sourcetype (default bila tidak memakai search head deployer);
- nonaktif;
- selektif per sourcetype.

Dokumentasi memperingatkan bahwa menonaktifkan korelasi bisa membuat detection dan dashboard tidak bekerja sebagaimana mestinya [S5].

Aturan tentang `host` itu langsung mengenai PT JAB. Syslog router dan switch POP di index `netops` sering hanya membawa `host`, jadi melengkapi daftar aset POP saja tidak akan mengubah apa pun di antrean; field-nya harus dinormalkan ke `dest` atau `dvc` lebih dulu. Urutan kerja yang benar untuk sumber seperti itu adalah normalisasi dulu, isi daftar aset kemudian, lalu ukur lagi.

### 1.5 Kenapa A&I penting untuk detection dan risk

Pertanyaan terakhir SOC lead, apa akibatnya kalau dibiarkan, punya empat jawaban yang semuanya bisa ditunjukkan dengan angka.

- **Prioritas finding/notable:** urgensi biasanya dihitung dari severity detection dan prioritas aset/identitas yang terlibat, cek matriks urgensi di ES 8 (Day 31).
- **Risk-Based Alerting:** risk score diberikan ke entity (dulu *risk object*). Konteks seperti `priority`, `category`, dan `watchlist` dipakai untuk memodulasi skor (Day 35).
- **Konteks investigasi:** pemilik aset, unit bisnis, dan kontak manajer mempercepat eskalasi.
- **Sinyal sendiri:** login oleh identitas dengan `endDate` di masa lalu, atau trafik dari aset yang `is_expected=false`.

**Tanpa ES:** akselerasi data model adalah fitur platform, jadi seluruh bagian 1.1 berlaku di Splunk Enterprise biasa; yang ditambahkan ES hanyalah enforcement akselerasi data model CIM [S2] dan dashboard untuk memantaunya. Asset & Identity framework sebaliknya milik ES sepenuhnya: tanpa ES tidak ada merge, tidak ada pencocokan CIDR, tidak ada konvensi identitas, dan tidak ada field otomatis seperti `src_priority` atau `user_category` [S5], sedangkan Exposure Analytics entity discovery hanya ada di ES 8.x bila tersedia [S3]. Yang bisa kamu bangun sendiri di Splunk Enterprise adalah lookup aset dan identitas berbentuk CSV atau KV store ditambah automatic lookup, dan itu dikerjakan di bagian 2.5. Di PT JAB keduanya memang hidup berdampingan: L1 masih bekerja di app Search & Reporting di search head biasa, sementara ES berjalan di search head terpisah, jadi pola field gaya ES dipakai di kedua tempat supaya kebiasaannya sama.

## 2. Contoh SPL dan langkah di ES

> Semua keluaran di bagian ini adalah keluaran ilustrasi, bukan hasil eksekusi. Asumsi: Splunk Enterprise 10.6 dengan add-on CIM, ES 8.7 di search head terpisah, data model `Authentication` sudah di-accelerate, dan index PT JAB seperti `wineventlog` dan `linux` sebagai sumbernya. Query yang memakai lookup ES (`asset_lookup_by_str`, `identity_lookup_expanded`) hanya berjalan di ES. Untuk lab tanpa ES, lihat bagian 2.5.

Empat search pertama menjawab pertanyaan SOC lead dalam urutan yang bisa kamu kerjakan dalam satu duduk: apa yang sudah dibangun akselerasi, apa isi daftar aset dan identitas sekarang, bagaimana konteks itu mengubah urutan antrean, dan berapa persen yang masih tidak dikenal.

### 2.1 Status akselerasi data model

**Tujuan:** menjawab "apa yang sebenarnya dibangun di belakang dan seberapa besar" tanpa menunggu jawaban tim platform.

```
| rest /services/admin/summarization by_tstats=t splunk_server=local count=0
| eval datamodel=replace('summary.id', "DM_" . 'eai:acl.app' . "_", "")
| table datamodel summary.complete summary.size summary.earliest_time summary.latest_time summary.is_inprogress
```

- Endpoint `admin/summarization` mengembalikan status summary akselerasi. Pola ini umum dipakai komunitas, cek nama endpoint dan field di versi-mu.
- `summary.complete` mendekati 1 berarti selesai dibangun. `summary.size` menunjukkan disk.
- `eval` di baris kedua hanya merapikan nama: `summary.id` berbentuk `DM_<app>_<model>`, dan prefiks itu dibuang memakai nama app dari `eai:acl.app`.
- Alternatif UI: Settings > Data models (kolom status) atau Data Model Audit di ES [S2].

Keluaran ilustrasi (`summary.size` dalam byte, dua kolom waktu dalam epoch):

```
datamodel        summary.complete  summary.size   summary.earliest_time  summary.latest_time  summary.is_inprogress
Authentication   1.00              48318382080    1784160000             1791935700           0
Endpoint         1.00              23622320128    1784160000             1791935700           0
Network_Traffic  0.87              128849018880   1784160000             1791933000           1
```

**Cara membaca hasil:** `Authentication` dan `Endpoint` lengkap untuk rentang yang diminta, masing-masing 45 GiB dan 22 GiB. `Network_Traffic` masih 0,87 dan sedang dibangun, ukurannya 120 GiB, dan waktu terakhirnya tertinggal sekitar 45 menit dari dua model lain. Model itulah kandidat pertama untuk allowlist index yang lebih sempit atau summary range yang lebih pendek, dan sekaligus penjelasan kenapa satu dashboard tampak kosong di jam tertentu.
**Variasi:** tambahkan `| eval mb=round('summary.size'/1024/1024, 0)` dan `| eval last=strftime('summary.latest_time', "%F %T")` supaya angkanya bisa langsung dibaca di rapat. Untuk melihat tren, catat hasilnya harian ke summary index (Day 40).
**Kapan gagal:** hasil kosong bila role-mu tidak punya hak ke endpoint REST itu, dan nama field bisa berbeda antar versi. Angka ukuran di sini tetap angka per search head yang kamu tanya; untuk kapasitas indexer pakai `disk_objects.log` di `_introspection` seperti di bagian 1.1.

### 2.2 Melihat isi lookup aset dan identitas (ES)

**Tujuan:** mengetahui isi daftar aset dan identitas apa adanya, sebelum menyalahkan detection. Ini juga cara memverifikasi bahwa CSV yang baru didaftarkan benar-benar masuk hasil merge.

```
| inputlookup asset_lookup_by_str
| stats count BY priority category bunit
| sort - count
```

```
| inputlookup identity_lookup_expanded
| eval ended=if(isnotnull(endDate) AND strptime(endDate, "%Y-%m-%d") < now(), "yes", "no")
| stats count BY priority watchlist ended
```

- Query pertama: distribusi aset menurut prioritas/kategori. Banyak `unknown` berarti data aset kurang lengkap.
- Query kedua: berapa identitas yang sudah berakhir masa kerjanya. Format tanggal `endDate` adalah asumsi, perlu dicek.

Keluaran ilustrasi untuk query pertama:

```
priority  category     bunit          count
unknown   unknown      unknown        1184
medium    workstation  korporat        318
high      datacenter   infrastruktur    65
critical  datacenter   infrastruktur    42
```

Keluaran ilustrasi untuk query kedua:

```
priority  watchlist  ended  count
medium    0          no     1102
high      0          no       58
medium    0          yes      37
critical  1          no        6
```

**Cara membaca hasil:** daftar aset PT JAB berisi 1.609 baris, dan 1.184 di antaranya (sekitar 74 persen) masuk dari ekspor NOC tanpa kolom prioritas, kategori, dan unit bisnis, jadi secara praktis tidak membawa konteks apa pun. Hanya 107 baris yang punya prioritas `high` atau `critical`, dan semuanya server data center Jakarta: perangkat POP dan perangkat pelanggan korporat memang belum ada di daftar, sehingga ia tidak muncul sebagai `unknown` di sini, melainkan tidak muncul sama sekali. Di sisi identitas, 1.203 baris mendekati jumlah karyawan, dan 37 di antaranya sudah melewati `endDate` tetapi masih terdaftar. Tiga puluh tujuh baris itu adalah pekerjaan paling murah di seluruh Day ini: satu daftar yang bisa diserahkan ke HR dan sekaligus dipakai sebagai detection di bagian 3.
**Variasi:** ganti `BY priority category bunit` dengan `BY bunit` untuk melihat unit bisnis mana yang sama sekali belum menyetor data, dan pakai `| inputlookup asset_lookup_by_cidr | stats count` untuk memastikan ada entri rentang jaringan, bukan hanya IP tunggal.
**Kapan gagal:** lookup ini hasil merge, bukan file yang kamu unggah. Kosong atau tidak berubah setelah unggah berarti merge belum jalan atau gagal, dan itu ditangani di bagian 4. Query kedua bergantung pada format `endDate`: bila formatnya bukan `%Y-%m-%d`, `strptime()` menghasilkan null dan semua baris terbaca `no`, yang justru terlihat seperti kabar baik.

### 2.3 Event yang diperkaya: triage berbasis prioritas

**Tujuan:** menunjukkan ke SOC lead bentuk antrean yang sudah bisa diurutkan, memakai konteks yang ditempelkan korelasi.

```
| tstats summariesonly=true count from datamodel=Authentication
    where Authentication.action="failure"
    by Authentication.src Authentication.dest Authentication.user Authentication.dest_priority Authentication.user_category
| rename Authentication.* AS *
| eval dest_priority=coalesce(dest_priority, "unknown")
| eval rank=case(dest_priority=="critical",4, dest_priority=="high",3, dest_priority=="medium",2, dest_priority=="low",1, true(),0)
| sort - rank - count
```

- Bila A&I aktif, field seperti `dest_priority` dan `user_category` diisi oleh korelasi aset/identitas. Referensi CIM mencantumkan field ini di data model Authentication dengan catatan "disediakan otomatis" oleh korelasi A&I (Day 24). Cek field ini benar-benar terisi di summary data model lab-mu, karena nilainya bergantung pada korelasi saat summary dibangun.
- `case()` mengubah prioritas menjadi angka urut untuk sorting.
- `coalesce()` dipakai supaya baris tanpa prioritas tetap ikut terhitung dan terlihat, bukan hilang dari laporan.

Keluaran ilustrasi:

```
src            dest            user             dest_priority  user_category  count  rank
10.30.12.44    JKT-DC01        adm.rina         critical       admin          214    4
198.51.100.23  jkt-bastion01   budi.santoso     high           contractor      61    3
10.10.7.19     JKT-WS-0412     fitri.handayani  unknown        employee         9    0
```

- **Cara membaca hasil:** baris teratas adalah kegagalan login terhadap aset kritis. Mulai triage dari sana. Baris kedua menarik karena dua konteks bertemu: sumber dari luar dan identitas berkategori contractor ke bastion host. Baris ketiga adalah peringatan tentang metode ini sendiri: nilai `unknown` menempatkan sebuah workstation di urutan paling bawah tanpa ada yang pernah memutuskan bahwa host itu tidak penting.
**Variasi:** ganti `dest_priority` dengan `user_priority` untuk mengurutkan menurut siapa yang diserang, atau tambahkan `Authentication.app` di `by` supaya terlihat jalur mana (VPN, SSH, Windows) yang dipakai.
**Kapan gagal:** dengan `summariesonly=true`, field enrichment hanya ada bila korelasi sudah aktif ketika summary dibangun, jadi menyalakan korelasi hari ini tidak mengisi summary kemarin. Bila seluruh kolom prioritas berisi `unknown` padahal daftar aset terisi, periksa dulu apakah event itu punya `dest` dan bukan hanya `host` (bagian 1.4).

### 2.4 Mengukur cakupan A&I: berapa entitas yang tidak dikenal?

**Tujuan:** menghasilkan angka yang diminta SOC lead, yaitu berapa persen entitas yang tidak dikenal, dalam bentuk yang bisa diulang setiap bulan.

```
| tstats count from datamodel=Authentication by Authentication.dest Authentication.dest_priority
| rename Authentication.* AS *
| eval known=if(isnull(dest_priority) OR dest_priority="unknown", "unknown", "known")
| stats dc(dest) AS hosts sum(count) AS events BY known
```

- Persentase host "unknown" adalah metrik kualitas data yang bagus untuk dilaporkan.
- Perhatikan `summariesonly` tidak dipakai di sini, jadi angkanya mencakup data mentah untuk bagian rentang yang belum ter-summarize.

Keluaran ilustrasi:

```
known    hosts  events
known      147  2841902
unknown    612   948317
```

**Cara membaca hasil:** dari 759 host yang muncul di data autentikasi, 612 atau sekitar 81 persen tidak dikenal daftar aset, dan host itu menyumbang sekitar 25 persen event autentikasi. Dua angka itu dilaporkan berpasangan: yang pertama menunjukkan luasnya titik buta, yang kedua menunjukkan berapa banyak aktivitas yang saat ini tidak bisa diprioritaskan. Jalankan ulang setiap bulan dan angka inilah bukti bahwa pengisian daftar aset memang berjalan.
**Variasi:** ganti `dest` dengan `src` untuk sudut pandang sumber, pecah `by Authentication.dest Authentication.dest_priority sourcetype` untuk mengetahui sumber log mana yang paling banyak menyumbang host tidak dikenal, dan pakai `user` dengan `user_bunit` untuk versi identitasnya.
**Kapan gagal:** host diidentifikasi dengan nama berbeda (FQDN vs NetBIOS) dari daftar aset, sehingga tidak cocok. Lengkapi field `dns` dan `nt_host` di sumber aset. Angka ini juga menghitung host yang sudah dinonaktifkan tetapi masih mengirim log, jadi bandingkan dengan daftar aset yang `is_expected=false` sebelum menyimpulkan bahwa semuanya perlu didaftarkan.

### 2.5 Lab tanpa ES: meniru enrichment dengan lookup biasa

**Tujuan:** mendapatkan kolom konteks yang sama di search head tanpa ES, tempat L1 PT JAB masih bekerja sehari-hari.

```
index=wineventlog sourcetype="XmlWinEventLog:Security" EventCode=4625
| stats count BY dest user
| lookup lab_assets.csv nt_host AS dest OUTPUTNEW priority AS dest_priority owner AS dest_owner
| lookup lab_identities.csv identity AS user OUTPUTNEW priority AS user_priority endDate AS user_endDate
| fillnull value="unknown" dest_priority user_priority
```

- Sama dengan pola Day 12, tetapi dengan nama field gaya ES (`dest_priority`, `user_priority`) agar kebiasaanmu cocok dengan ES.
- Untuk otomatis, jadikan automatic lookup di Settings > Lookups. Ini analog sederhana dari korelasi ES.
- Cek nama index dan field di lab-mu.

Keluaran ilustrasi:

```
dest          user             count  dest_priority  dest_owner  user_priority  user_endDate
JKT-DC01      adm.rina           214  critical       tim-infra   high
JKT-FS01      svc_backup          75  high           tim-infra   unknown
BDG-WS-0118   rina.wulandari      12  unknown                    medium         2026-08-31
```

**Cara membaca hasil:** dua baris pertama mendapat konteks, baris ketiga tidak, dan itu wajar karena workstation Bandung belum ada di daftar. Perhatikan `dest_owner` di baris ketiga tetap kosong, bukan `unknown`, karena `fillnull` hanya menyebut `dest_priority` dan `user_priority`. Kolom kosong seperti ini yang membuat laporan terlihat "hampir benar" dan luput diperiksa, jadi sebut semua field konteks di `fillnull` atau pakai `fillnull value="unknown"` tanpa daftar field. Baris ketiga juga memuat `user_endDate` yang sudah lewat, dan itu sinyal yang berdiri sendiri terlepas dari jumlah kegagalannya.
**Variasi:** tambahkan `| where user_endDate < strftime(now(), "%Y-%m-%d")` untuk mengubah tabel ini menjadi kandidat alert, dan `| lookup lab_assets.csv ip AS src ...` untuk sumber log yang hanya punya IP.
**Kapan gagal:** `lookup` mencocokkan nilai secara literal, jadi `JKT-DC01` tidak akan cocok dengan `jkt-dc01.corp.jab.example` di file aset. Normalkan salah satu sisi dengan `eval dest=lower(replace(dest, "\..*$", ""))` sebelum lookup, atau sediakan kolom terpisah untuk FQDN dan NetBIOS.

### 2.6 Langkah di ES (generik)

1. Assets and identities > Correlation setup (jalur: Configure > All configurations > Assets and identities) untuk memastikan korelasi aktif [S5].
2. Asset and Identity Manager untuk menambah sumber (CSV, LDAP, cloud) dan mengecek status merge [S3]. Komunitas melaporkan kegagalan parsing CSV bisa terjadi diam-diam [S6], jadi selalu verifikasi dengan bagian 2.2.
3. Data Model Audit untuk akselerasi [S2].

## 3. Lab praktik

1. Jalankan bagian 2.1 (atau buka Settings > Data models). Catat status dan ukuran akselerasi Authentication dan Endpoint.
2. Buat `lab_assets.csv` (fiktif) dengan kolom `ip,mac,nt_host,dns,owner,priority,category,bunit,is_expected`. Isi untuk VM-VM lab-mu (mis. DC lab `priority=critical`, workstation `medium`).
3. Buat `lab_identities.csv` (fiktif) dengan kolom `identity,first,last,email,priority,bunit,category,watchlist,startDate,endDate`. Sertakan satu akun "mantan karyawan" dengan `endDate` di masa lalu.
4. **Dengan ES:** daftarkan kedua file di Asset and Identity Manager, tunggu merge, lalu verifikasi dengan bagian 2.2.
   **Tanpa ES:** buat automatic lookup (bagian 2.5).
5. Di VM Windows lab, login dengan akun "mantan karyawan" (gagal dan berhasil). Cari event 4624/4625 dan pastikan field enrichment muncul.
6. Jalankan bagian 2.3 dan 2.4. Hitung persentase host unknown.
7. Tulis deteksi sederhana: "login sukses oleh identitas dengan endDate < hari ini". Uji dulu dengan `makeresults` (Day 12).
8. Buka Settings > Data Models, pilih satu model lab-mu, lalu Edit > Edit Acceleration. Catat empat nilai apa adanya: summary range, summarization period, max summarization search time, dan status beserta persentasenya. Lalu bandingkan angka Size on Disk di halaman itu dengan data `disk_objects.log` di index `_introspection` untuk model yang sama, dan catat selisihnya beserta jumlah root object model itu.
9. Tambahkan satu field baru ke model lab-mu (eval expression sederhana), simpan, lalu amati apa yang terjadi pada status akselerasi dan berapa lama summary kembali lengkap. Catat juga apakah hasil `tstats summariesonly=true` atas field lama berubah selama proses itu.
10. Tulis laporan satu halaman untuk SOC lead fiktif: dua angka dari bagian 2.4 (host tidak dikenal dan porsi event-nya), daftar sumber aset yang belum ada, dan satu langkah berikutnya yang paling murah.

**Hasil yang sebaiknya tersimpan:**
- Status akselerasi tercatat, beserta empat nilai pengaturan dari langkah 8 dan selisih Size on Disk.
- Lookup aset/identitas fiktif aktif (ES atau automatic lookup).
- Event login lab diperkaya dengan prioritas dan konteks identitas.
- Persentase aset unknown dihitung, dalam dua angka: jumlah host dan porsi event.
- Deteksi "akun berakhir masih login" teruji.
- Catatan apa yang terjadi pada summary setelah definisi model diubah.
- Laporan satu halaman dari langkah 10.

**Variasi tantangan:** tambahkan subnet ke daftar aset dengan notasi CIDR (mis. `10.66.0.0/16`, `category=lab`), lalu pastikan IP tunggal di subnet itu ikut diperkaya. Di ES ini lewat `asset_lookup_by_cidr` [S3]; tanpa ES, lewat lookup definition dengan match type CIDR (Day 12).

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Field `src_*`/`dest_*` tidak muncul | Korelasi nonaktif/selektif untuk sourcetype itu; event hanya punya `host` | Correlation setup [S5]; normalisasi `src`/`dest`/`dvc` (Day 23) |
| Banyak aset "unknown" | Daftar aset tidak lengkap; format nama berbeda (FQDN vs NetBIOS) | Lengkapi `dns`, `nt_host`; tambahkan CIDR |
| Lookup gabungan kosong setelah unggah CSV | Kegagalan parsing diam-diam; format kolom salah | Cek isi `asset_lookup_by_*`; log identity manager [S3]; `[komunitas]` laporan kegagalan diam-diam [S6] |
| `asset_lookup_by_cidr` kosong | Tidak ada entri CIDR/rentang di sumber | Tambahkan entri CIDR. `[komunitas]` thread lama (ES 6) [S6], cek di ES 8 |
| Akselerasi tidak selesai | Model terlalu luas; batas waktu summarization satu jam per jalannya | Allowlist index (Day 23); perpendek summary range atau pakai backfill range; pantau Data Model Audit. Menaikkan jumlah search summarization bersamaan bukan langkah pertama karena menambah pemakaian memori, CPU, dan disk I/O serta bisa menyentuh kuota search [S7] |
| Size on Disk kecil padahal disk indexer naik | Metrik itu hanya mencerminkan satu root object pada model dengan beberapa root object | Ambil angka dari `disk_objects.log` di index `_introspection`, yang melaporkan total per indexer [S7] |
| Hasil `summariesonly=true` berubah setelah model disunting | Summary lama tidak dipakai setelah definisi berubah, dan rebuild sedang berjalan | Tunggu status kembali Complete; untuk model bersummary besar matikan automatic rebuild dan jadwalkan rebuild manual lewat Data Model Manager [S7] |
| Prioritas notable/finding tidak sesuai | Prioritas aset/identitas salah atau kosong | Perbaiki data sumber A&I; cek matriks urgensi (Day 31) |

## 5. Kesalahan umum dan jebakan

- Menganggap A&I "sekali isi selesai". Data aset dan identitas basi dengan cepat (karyawan keluar, IP DHCP berpindah). Butuh sumber otomatis (AD/LDAP, CMDB, Exposure Analytics) [S3].
- Mengandalkan field `host` untuk enrichment. ES 8 tidak lagi mengorelasikan `host`/`orig_host` secara otomatis [S5].
- Mematikan korelasi demi performa tanpa memahami dampaknya pada detection [S5].
- Akselerasi summary range "All time" tanpa kebutuhan. Boros disk dan waktu, dan itu arti dari nilai summary range yang dibiarkan kosong [S7].
- Membaca status "100 persen" sebagai "seluruh isi index sudah ter-summarize". Persentase itu dihitung terhadap schedule window atau backfill range yang kamu setel, dan cakupan summary sendiri bersifat perkiraan karena dibangun per bucket [S7].
- Menaikkan jumlah search summarization bersamaan sebagai jalan keluar pertama saat akselerasi tertinggal, padahal penyebabnya biasanya model yang terlalu luas [S7].
- Tidak memantau merge A&I. Kegagalan bisa diam-diam [S6].
- `[komunitas]` Thread Splunk Community tentang `assets_by_cidr` kosong dan error merge kebanyakan dari era ES 6.x [S6]. Polanya (format IP/CIDR, entri dummy) mungkin tidak berlaku lagi, cek di ES 8.

## 6. Catatan terkini

Bagian ini menampung detail versi dan perubahan istilah yang perlu kamu kenali saat membaca dokumentasi atau tulisan lama, tanpa mengubah keputusan di bagian sebelumnya.

- **ES 8.x:** Exposure Analytics entity discovery menjadi sumber A&I yang direkomendasikan [S3]. Ini perubahan dibanding era ES 7 yang mengandalkan lookup manual dan LDAP.
- **ES 8.x:** korelasi tidak lagi otomatis terhadap `host`/`orig_host` [S5].
- **CIM 6.4.0 (Feb 2026):** menambah field unit bisnis di Data Access untuk mendukung aset/identitas (Day 23).
- Istilah ES 8: risk object menjadi entity (Day 31). Dokumentasi A&I tetap memakai "asset" dan "identity" untuk daftar sumbernya.

## 7. Cheat sheet

```
ACCEL   summary tsidx di indexer | period 5 menit (cron) | max search time 1 jam | max 3 search paralel
        cleanup tsidx basi tiap 30 menit | automatic rebuild ON | default OFF (CIM) | ES enforce
        summary range kosong = All Time ; backfill range untuk tumbuh bertahap
        status: Settings > Data Models > baris model > ACCELERATION (Complete / Building %)
        ukuran nyata: disk_objects.log di index _introspection (Size on Disk bisa kurang hitung)
        | rest /services/admin/summarization by_tstats=t  (status, size), perlu dicek
A&I     sumber: Exposure Analytics (utama) | CSV | LDAP/AD | cloud
        alur: collect -> lookup -> definition -> Asset and Identity Manager -> merge (identity manager) -> verify
        hasil: asset_lookup_by_str | asset_lookup_by_cidr | identity_lookup_expanded
ASET    ip mac nt_host dns | owner priority bunit category pci_domain | is_expected should_timesync should_update requires_av | asset_tag
IDENT   identity (konvensi) first last email managedBy | priority bunit category watchlist startDate endDate | identity_tag
KORELASI src/dest/dvc -> aset ; user/src_user -> identitas ; output berprefiks: src_priority, dest_category, user_bunit...
        BUKAN host/orig_host ; Configure > All configurations > Assets and identities > Correlation setup (all/selective/off)
PAKAI   prioritas triage | risk scoring entity | konteks investigasi | sinyal (endDate lewat, is_expected=false)
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Tim platform melapor bahwa akselerasi `Authentication` sudah 100 persen, jadi rekanmu menyimpulkan bahwa detection dengan `summariesonly=true` di rentang 90 hari pasti melihat semuanya. Kenapa kesimpulan itu belum aman?

<details><summary>Jawaban</summary>

Persentase itu dihitung terhadap schedule window, atau terhadap backfill range bila disetel, bukan terhadap seluruh isi index. Jadi "100 persen" berarti summary lengkap untuk rentang yang diminta, dan bila summary range-nya 30 hari, search 90 hari hanya mendapat 30 hari terakhir dari summary. Dua hal lain ikut membatasi: cakupan summary bersifat perkiraan karena dibangun per bucket, dan ia tidak bisa melampaui retensi index sumber. Yang perlu kamu tanyakan bukan "berapa persen", melainkan "berapa summary range-nya dan berapa retensi index-nya". Lihat bagian 1.1.

</details>

**2. Skenario keputusan.** Alert dari firewall POP Bandung tidak pernah membawa `dest_priority`, padahal perangkat POP sudah kamu masukkan ke daftar aset dan merge-nya sudah terverifikasi. Event itu hanya punya field `host`. Langkah mana yang menyelesaikannya?

- A. Nyalakan korelasi untuk semua sourcetype di Correlation setup, karena kemungkinan sourcetype itu belum dipilih.
- B. Normalkan field perangkat ke `dest` atau `dvc` lewat add-on atau knowledge object CIM, lalu ukur lagi cakupannya.
- C. Tambahkan nama host POP itu ke `asset_lookup_by_str` dalam bentuk NetBIOS supaya cocok dengan nilai `host`.

<details><summary>Jawaban</summary>

B. ES tidak lagi mengorelasikan field `host` dan `orig_host` secara otomatis, jadi event yang hanya punya `host` tidak akan diperkaya seberapa pun lengkap daftar asetmu. Yang dicocokkan ke daftar aset adalah `src`, `dest`, dan `dvc`, serta `user` dan `src_user` untuk identitas. A tidak mengubah apa pun untuk kasus ini, karena masalahnya bukan sourcetype mana yang dipilih, melainkan field mana yang dipakai korelasi, dan menyalakan korelasi untuk semua sourcetype justru menambah beban tanpa hasil. C salah sasaran untuk alasan yang sama: nilainya mungkin sudah ada di daftar, tetapi tidak ada yang mencocokkannya karena field asalnya tidak ikut dikorelasikan. Lihat bagian 1.4 dan 2.3.

</details>

**3. Pertanyaan jebakan.** Daftar aset sudah diisi sekali dari ekspor spreadsheet NOC dan lookup gabungan di ES tidak kosong, sehingga pekerjaan A&I dianggap selesai. Tiga bulan kemudian prioritas di antrean masih terasa salah. Apa yang paling mungkin terjadi?

<details><summary>Jawaban</summary>

Tiga hal yang semuanya diam. Pertama, isinya basi: karyawan keluar, kontraktor habis kontrak, dan IP DHCP berpindah, sehingga daftar yang benar pada hari diimpor tidak lagi benar sekarang, dan itu alasan dokumentasi mengarahkan ke sumber otomatis seperti LDAP/AD, penyedia cloud, atau Exposure Analytics. Kedua, lookup yang tidak kosong tidak berarti lengkap: baris yang masuk tanpa kolom `priority`, `category`, dan `bunit` terbaca sebagai `unknown` dan tidak membawa konteks apa pun, sedangkan perangkat yang belum pernah didaftarkan tidak muncul sebagai `unknown`, melainkan tidak muncul sama sekali. Ketiga, merge bisa gagal sebagian tanpa pesan yang jelas, jadi satu-satunya bukti adalah memeriksa isi lookup hasil merge dan mengulang pengukuran cakupan secara rutin. Lihat bagian 1.2 dan 2.2.

</details>

**4. Skenario keputusan.** Akselerasi `Network_Traffic` tidak pernah mencapai Complete dan selalu menunjukkan Building di bawah 90 persen. Tim platform mengusulkan menaikkan jumlah search summarization bersamaan dari tiga menjadi sepuluh. Apa yang kamu sarankan?

- A. Setuju, karena summary dibangun lebih banyak sekaligus sehingga cepat mengejar.
- B. Persempit dulu cakupannya: allowlist index yang hanya memuat index penyuplai model, summary range sesuai kebutuhan detection terpanjang, dan backfill range bila rentang panjang memang dibutuhkan.
- C. Matikan akselerasi untuk model itu dan ubah semua detection yang memakainya menjadi `summariesonly=false`.

<details><summary>Jawaban</summary>

B. Penyebab yang paling sering adalah model yang terlalu luas, sehingga satu jalannya search summarization menyentuh batas waktu satu jam dan selalu ada bagian yang belum tersentuh ketika jadwal berikutnya tiba. Menyempitkan cakupan memperbaiki penyebabnya dan sekaligus memurahkan disk serta CPU. A menambah pemakaian memori, CPU, dan disk I/O dan bisa menyentuh batas kuota search otomatis, jadi ia memindahkan masalah ke scheduler. C menghilangkan masalah akselerasi dengan membuat setiap detection membaca data mentah, yang justru beban terbesar yang ingin dihindari, dan itu pilihan terakhir untuk model yang memang tidak layak di-accelerate. Lihat bagian 1.1 dan 5.

</details>

**5. Jelaskan ulang.** Jelaskan ke NOC lead PT JAB, dalam tiga kalimat, kenapa daftar aset POP yang tidak lengkap adalah masalah keamanan dan bukan urusan administrasi.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh jawaban: "Setiap alert yang kami terima dinilai sebagian dari nilai aset yang terlibat, jadi perangkat yang tidak ada di daftar masuk antrean tanpa prioritas dan otomatis dikerjakan paling akhir. Dari data autentikasi bulan ini, 612 dari 759 host tidak dikenal daftar aset, dan host itu menyumbang sekitar seperempat event, artinya seperempat aktivitas tidak bisa kami urutkan menurut kepentingannya. Yang kami minta bukan proyek CMDB, melainkan dua kolom per perangkat, yaitu pemilik dan tingkat kepentingan, ditambah satu ekspor terjadwal supaya daftarnya tidak basi."

Kesalahan yang sering muncul: menyampaikannya sebagai keluhan proses tanpa angka, sehingga mudah ditunda; menjanjikan bahwa melengkapi daftar aset akan menaikkan deteksi, padahal yang berubah adalah prioritas dan konteks; dan melupakan sisi identitas, padahal akun yang sudah melewati `endDate` tetapi masih aktif adalah temuan yang berdiri sendiri. Lihat bagian 1.5 dan 2.4.

</details>

**6. Pertanyaan jebakan.** Korelasi aset dan identitas baru kamu nyalakan hari ini. Kamu menjalankan `tstats summariesonly=true` atas data minggu lalu dan mengharapkan `dest_priority` ikut terisi, tetapi kolomnya kosong. Apa penjelasannya?

<details><summary>Jawaban</summary>

Nilai yang dibaca `summariesonly=true` adalah nilai yang tertulis di summary ketika summary itu dibangun, jadi baris minggu lalu dibangun saat korelasi belum menempelkan apa pun. Menyalakan korelasi hari ini hanya memengaruhi summary yang dibangun sesudahnya. Untuk memastikan ini yang terjadi, jalankan ulang dengan `summariesonly=false` dan bandingkan: bila kolomnya terisi di sana, penyebabnya memang summary lama, bukan daftar aset. Lihat bagian 2.3 dan 1.1.

</details>

**7. Interview question (English).** "Your alert queue cannot be prioritised because the asset and identity data is incomplete. How do you approach it?"

<details><summary>Sample answer</summary>

"I start by measuring it, because 'incomplete' is not actionable. I run a count over the authentication data model grouped by destination and its priority field, and report two numbers: how many distinct hosts have no priority, and what share of the events those hosts represent. In the environment I have in mind that was about eighty per cent of hosts and a quarter of the events, which turns a vague complaint into a target. Then I check why they are unknown, because there are three different causes with three different owners: devices that were never in the inventory, which is an asset owner problem; devices that are in the list but matched under a different name, FQDN against NetBIOS, which I fix by filling the dns and nt_host fields; and events that only carry a host field, which modern Enterprise Security does not correlate at all, so those need normalising to dest or dvc first. While that is in progress I ask for the two cheapest columns, owner and priority, instead of waiting for a full CMDB project, and I pull identities from Active Directory so that start and end dates come in automatically. The identity side usually pays off immediately: accounts still active past their end date are a finding in themselves, not just stale data. And I re-run the same measurement every month, because the only evidence that this work is happening is the number going down."

What makes this answer strong: it converts a complaint into two reportable numbers, separates the causes by owner instead of blaming the data, names the one platform behaviour most people miss (host is not correlated), and ends with a repeatable measurement rather than a one-off cleanup.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Accelerate data models (Knowledge Manager Manual 10.4) | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.4/use-data-summaries-to-accelerate-searches/accelerate-data-models | primer | diakses 2026-10-07 | Tinggi |
| S2 | Set up the Splunk CIM Add-on (akselerasi CIM nonaktif secara default, enforcement oleh ES, Data Model Audit) | https://help.splunk.com/en/data-management/common-information-model/6.2/introduction/set-up-the-splunk-common-information-model-add-on | primer | diakses 2026-10-07 | Tinggi |
| S3 | ES 8.7: Add asset and identity data to Splunk Enterprise Security | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/asset-and-identity-management | primer | diakses 2026-10-07 | Tinggi. Sumber, alur, merge, lookup hasil |
| S4 | ES 8.7: Asset and identity fields after processing | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/asset-and-identity-validation/asset-and-identity-fields-after-processing-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi. Field dan pemrosesan |
| S5 | ES 8.7: Configure asset and identity correlation | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/asset-and-identity-validation/configure-asset-and-identity-correlation-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi. Field korelasi, menu, host tidak dikorelasikan |
| S6 | Splunk Community: assets_by_cidr not populating; A&I merge issues; merge errors | https://community.splunk.com/t5/Splunk-Enterprise-Security/Why-is-the-assets-by-cidr-csv-lookup-file-not-populating-during/m-p/513370 | komunitas | sebagian era ES 6 (>3 tahun) | Rendah-sedang |
| S7 | Accelerate data models (Knowledge Manager Manual 10.6) | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/use-data-summaries-to-accelerate-searches/accelerate-data-models | primer | diakses 2026-10-14 | Tinggi. Summarization period lima menit berbentuk cron, max summarization search time satu jam, maksimum tiga search summarization bersamaan, pembersihan summary tsidx kedaluwarsa tiap 30 menit beserta `datamodels.conf` dan `limits.conf`, lokasi summary dan volume `_splunk_summaries`, perilaku SmartStore, arti summary range kosong dan sifat perkiraannya, backfill range, syarat sharing dan jenis dataset, status di Settings > Data Models, keterbatasan Size on Disk dan `disk_objects.log` di `_introspection`, automatic rebuilds |

**Catatan sumber:** rincian format lookup aset/identitas (daftar nilai priority, format tanggal), matriks urgensi, dan Exposure Analytics belum dirujuk ke halaman dokumentasi khusus; cek di dokumentasi ES 8.7 bagian asset and identity. Endpoint REST summarization perlu diuji di instance-mu. Thread komunitas [S6] sebagian besar dari era ES 6, jadi polanya mungkin tidak berlaku di ES 8.
