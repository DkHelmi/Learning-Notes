---
day: 25
title: 'tstats: pencarian cepat atas tsidx dan data model'
researched_on: 2026-10-07
versions_checked: Splunk Enterprise 10.6 (rilis 30 Sep 2026; referensi tstats dari dokumentasi 10.2, acceleration dari 10.4); Splunk Enterprise Security 8.7.0 (2 Sep 2026); Splunk CIM 6.4 (halaman diperbarui 2026-02-03); security_content (detection dimodifikasi 22 Sep 2026)
---

# Day 25: tstats untuk pencarian cepat atas tsidx dan data model

Cakupan: cara kerja `tstats` atas tsidx dan data model CIM yang di-accelerate, termasuk `summariesonly`, `prestats`, validasi summary, dan pola detection Splunk Threat Research.

## Ide inti

Day 23 menyatukan kosakata lintas vendor lewat CIM dan Day 24 memetakan field mana yang dipakai untuk pivot investigasi. Yang belum terjawab adalah biayanya. Pola kerja yang sudah kamu pakai, `index=... sourcetype=... | stats ...`, wajar untuk investigasi satu kasus. Biayanya baru terasa pada pertanyaan yang lebar dan berulang: "berapa kegagalan login per sumber selama 30 hari di seluruh PT JAB?", atau detection yang berjalan setiap 5 menit di atas ratusan juta event, misalnya log resolver pelanggan. Pada skala itu, membaca raw event menjadi mahal. `tstats` adalah jalan pintasnya. Ia tidak membaca raw event, melainkan file tsidx (time-series index), yaitu file indeks yang memetakan pasangan `field::value` ke lokasi event [S1][S2]. Begitu sebuah data model CIM di-accelerate, field CIM yang kamu pelajari di Day 24 ikut ditulis ke tsidx milik model itu, sehingga `Authentication.action` dan `Processes.process_name` bisa diagregasi tanpa membuka satu pun event. Itu sebabnya hampir semua correlation search bawaan ES dan detection di Splunk Security Content dibangun di atas `tstats` dan data model CIM yang di-accelerate [S4][S6]. SPL di balik sebuah detection hampir selalu dimulai dengan `| tstats`, jadi command ini perlu dikuasai untuk membaca konten orang lain, bukan hanya untuk menulis search sendiri.

Kecepatan itu dibayar dengan dua batasan, dan keduanya menjadi isi Day ini. Pertama, `tstats` hanya melihat apa yang ada di tsidx: field indexed bawaan (`index`, `sourcetype`, `source`, `host`, `_time`) atau field data model yang sudah ter-summarize. Field search-time biasa, termasuk hasil `rex` dan calculated field, tidak ada di sana. Kedua, ringkasan selalu tertinggal dari data mentah dan hanya mencakup rentang waktu yang dipilih saat akselerasi dinyalakan. Argumen `summariesonly` adalah tempat kedua sifat itu bertemu, dan di situ juga kesalahan paling mahal terjadi: hasil kosong dibaca sebagai "tidak ada aktivitas".

Padanannya di pekerjaan NOC adalah membaca counter yang sudah diagregasi di NMS, bukan menarik ulang log perangkat: angka per interval sudah dihitung di belakang, jadi rekap panjang selesai dalam hitungan detik. Batasnya juga mirip. Counter hanya memuat metrik yang memang dicatat, sehingga pertanyaan di luar daftar itu tetap harus dijawab dari log mentah, dan nilai terakhir bisa tertinggal satu periode polling. Di Splunk batas itu lebih keras: `tstats` tidak bisa membaca `_raw` sama sekali, dan field yang tidak masuk definisi data model tidak ada untuk `tstats` walaupun jelas terlihat ketika kamu membuka event satu per satu.

**Kapan relevan:** pertanyaan agregat (count, dc, values, min/max time) atas field yang ter-indeks atau field data model yang di-accelerate; detection terjadwal; panel dashboard; hunting lebar seperti long tail; dan membaca SPL detection bawaan ES.
**Kapan bukan jawaban:** saat kamu perlu isi raw event, field search-time yang tidak ada di data model, regex atas `_raw`, atau logika yang butuh event demi event (mis. `transaction`). Untuk itu, pakai search biasa, atau pakai `tstats` sebagai penyaring awal lalu lanjutkan ke search raw yang sempit. Day ini juga memperlakukan akselerasi sebagai sesuatu yang sudah menyala; prosedur mengaktifkannya, ukuran summary, dan cara memantaunya ada di Day 26.

## 1. Konsep inti

### 1.1 Apa yang sebenarnya dibaca tstats

Saat Splunk mengindeks data, setiap bucket berisi raw data terkompresi dan file `.tsidx`. File tsidx menyimpan *lexicon* (daftar term) beserta posting list ke event. Field yang selalu ada di tsidx adalah field indexed bawaan: `index`, `sourcetype`, `source`, `host`, dan `_time`. Field lain (mis. `user`, `src_ip`) umumnya diekstrak saat search (search-time extraction), jadi tidak ada di tsidx kecuali kamu membuat indexed field [S1].

`tstats` melakukan statistik langsung dari tsidx. Karena tidak perlu mendekompresi dan mem-parsing raw event, ia jauh lebih cepat daripada `stats` [S1]. Konsekuensinya: tanpa data model, `tstats` hanya "melihat" field indexed. Query `| tstats count where index=botsv1 by user` tidak akan bekerja seperti yang kamu harapkan, karena `user` bukan indexed field.

### 1.2 Data model acceleration: tsidx kedua yang berisi field CIM

Di sinilah data model berperan. Saat sebuah data model (mis. `Authentication` dari CIM) di-accelerate secara persisten, Splunk menjalankan search terjadwal (default sekitar setiap 5 menit) yang mengambil event sesuai constraint data model, mengekstrak field-nya, lalu menulis summary tsidx di indexer, berdampingan dengan bucket asal (default di `$SPLUNK_DB/<index>/datamodel_summary/`) [S2]. Isinya pasangan `Authentication.user::alice`, `Authentication.action::failure`, dan seterusnya. Jadi field search-time "dipindahkan" ke tsidx.

Fakta penting dari dokumentasi acceleration [S2]:
- Summary range menentukan seberapa jauh ke belakang summary dijaga (mis. 7 hari, 90 hari; kosong berarti All Time). Cakupannya perkiraan, karena summary dibangun per bucket.
- Max summarization search time default sekitar 1 jam per jalannya pembuatan summary.
- Hanya data model yang di-share (ke app atau global) yang bisa di-accelerate; model private tidak bisa.
- Hanya root event dataset dan root search dataset yang memakai streaming command yang bisa di-accelerate persisten.
- Ada juga *ad hoc acceleration* di Pivot. Itu dibuat di search head, sementara, dan tidak dipakai report/dashboard.

### 1.3 summariesonly: kecepatan vs kelengkapan

Default `summariesonly=false` [S1]. Artinya, jika rentang waktu search melebihi summary range, atau ada bagian yang belum di-summarize, `tstats` tetap mengembalikan hasil lengkap: bagian yang ada di summary cepat, sisanya diambil dari data mentah (lebih lambat) [S1].

Dengan `summariesonly=true`, `tstats` hanya membaca summary. Hasilnya cepat dan bebannya bisa diprediksi, tetapi data yang belum ter-summarize hilang dari hasil tanpa peringatan. Contoh: summary range 7 hari, kamu mencari 30 hari, maka yang keluar hanya sekitar 7 hari terakhir. Contoh lain: event yang baru masuk beberapa menit dan belum diproses search acceleration berikutnya.

Kenapa ES dan Security Content tetap memakai `summariesonly=true`? Karena correlation search berjalan terus-menerus dan harus murah. Splunk Security Content membungkus pilihan ini dalam macro `` `security_content_summariesonly` ``, yang berkembang menjadi `summariesonly=<config> allow_old_summaries=<config> fillnull_value=<config>` [S5]. Hasilnya, satu konfigurasi bisa mengatur ratusan detection sekaligus.

`allow_old_summaries` (default `false`) mengatur apakah summary yang dibangun sebelum definisi data model berubah boleh dipakai [S1]. Biarkan `false` kecuali kamu paham konsekuensinya.

### 1.4 Sintaks inti

Sintaks lengkap menurut SPL reference [S1]:

```
| tstats [prestats=<bool>] [local=<bool>] [append=<bool>] [summariesonly=<bool>]
         [include_reduced_buckets=<bool>] [allow_old_summaries=<bool>]
         [chunk_size=<unsigned int>] [fillnull_value=<string>]
         <stats-func>...
         [FROM datamodel=<data_model_name>.<root_dataset_name>
              [where nodename=<root_dataset_name>.<...>.<target_dataset_name>]]
         [WHERE <search-query> | <field> IN (<value-list>)]
         [BY (<field-list> | PREFIX(<field>)) [span=<timespan>]]
```

Hal-hal yang sering salah:
- `tstats` adalah generating command, jadi harus diawali pipe: `| tstats ...`.
- Di WHERE, field harus indexed atau field data model. Nilai tidak boleh mengandung major/minor breaker kecuali kamu memakai `TERM()`/`PREFIX()` [S1].
- Wildcard tidak boleh di nama field BY, dan fungsi kompleks seperti `count(eval(...))` tidak didukung [S1].
- Jika BY `_time`, berikan `span=` (default `auto`) [S1].
- Field data model dipanggil dengan nama objek: `Authentication.user`, `Processes.process_name` (untuk Endpoint.Processes), `All_Traffic.dest_port`. Untuk dataset turunan dipakai `where nodename=...` [S1][S3].
- `fillnull_value` tidak punya default. Tanpa itu, baris dengan nilai null di field BY dibuang [S1]. Ini sumber umum hasil yang "hilang".

### 1.5 Enterprise biasa vs Enterprise Security

| Komponen | Splunk Enterprise biasa | Hanya/umumnya di ES |
|---|---|---|
| `tstats`, data model, acceleration | Ya, fitur inti platform [S1][S2] | - |
| Data model CIM (Authentication, Endpoint, Network_Traffic, ...) | Ya, lewat add-on Splunk Common Information Model (gratis) [S3] | ES memasang dan memakainya secara default |
| Macro `drop_dm_object_name`, `summariesonly` | Tidak ada secara default | Ada di ES, cek di Settings > Advanced search > Search macros pada instance ES-mu |
| Macro `security_content_*` | Jika ES Content Update / security_content terpasang [S4][S5] | - |
| Audit > Data Model Audit | - | Dashboard ES [S6] |

Jadi kamu bisa berlatih `tstats` + CIM sepenuhnya di Splunk Enterprise (lisensi trial/dev) tanpa ES. Cukup pasang add-on CIM dan accelerate data model yang dibutuhkan.

### 1.6 Kenapa tstats kadang lebih lambat

Dokumentasi menyebut WHERE dengan kardinalitas tinggi bisa membuat `tstats` lebih lambat daripada `stats` biasa [S1]. Penyebab lain: BY terlalu banyak field berkardinalitas tinggi, sehingga hasilnya hampir "satu baris per event" seperti pada contoh security_content di bagian 2.5. Itu tetap jauh lebih murah daripada raw search, tetapi bukan gratis. Prinsipnya: agregasi kasar dulu dengan `tstats`, lalu persempit.

## 2. Contoh SPL dan langkah di ES

> Semua keluaran di bawah adalah keluaran ilustrasi, bukan hasil eksekusi nyata.

**Asumsi umum lab:** Splunk Enterprise 10.x, dataset BOTS v1 di-index ke `botsv1` (nama index bergantung pada cara kamu memasang app BOTS, jadi cek di instance-mu), add-on Splunk CIM terpasang, data Windows/Sysmon dari VM lab dengan TA Windows/Sysmon yang memetakan ke CIM.

### 2.1 tstats atas indexed field (tanpa data model)

**Tujuan:** inventaris cepat sourcetype yang ada di index, langkah pertama di dataset yang belum kamu kenal.

```
| tstats count where index=botsv1 by sourcetype
| sort - count
```

| Bagian | Penjelasan |
|---|---|
| `\| tstats` | Generating command, harus di awal search setelah pipe. |
| `count` | Fungsi statistik: jumlah event. |
| `where index=botsv1` | Filter memakai indexed field `index`. |
| `by sourcetype` | Kelompokkan per `sourcetype` (indexed field). |
| `\| sort - count` | Command biasa setelah tstats: urutkan menurun. |

Keluaran ilustrasi:

```
sourcetype              count
stream:http             (angka besar)
WinEventLog:Security    (angka)
fgt_traffic             (angka)
...
```

**Cara membaca hasil:** daftar ini adalah peta sumber data. Bandingkan durasinya dengan `index=botsv1 | stats count by sourcetype` di rentang yang sama. Hasil hitungannya harus sama, tetapi `tstats` jauh lebih cepat.
**Variasi:** `by sourcetype, host` atau `by _time span=1d sourcetype` untuk melihat kapan tiap sumber aktif.
**Kapan gagal:** jika kamu menulis `by user`, kolom `user` kosong atau baris hilang, karena `user` bukan indexed field.

### 2.2 Brute force / password spraying dari data model Authentication

**Tujuan:** menemukan sumber yang gagal login ke banyak akun berbeda.
**Asumsi:** data model `Authentication` di-accelerate (summary range minimal sepanjang rentang search); data auth (mis. Windows Security 4625 lewat TA Windows, atau `linux_secure`) sudah ter-tag `authentication` dan `action` ter-normalisasi ke `success`/`failure` [S3].

```
| tstats summariesonly=true allow_old_summaries=false
    count AS failures
    dc(Authentication.user) AS distinct_users
    min(_time) AS firstTime max(_time) AS lastTime
  from datamodel=Authentication.Authentication
  where Authentication.action="failure"
  by Authentication.src Authentication.app
| rename Authentication.* AS *
| where distinct_users >= 5
| convert ctime(firstTime) ctime(lastTime)
| sort - distinct_users
```

Baris demi baris:
1. `summariesonly=true`: hanya baca summary (cepat). Pastikan rentang waktu tidak melebihi summary range [S1][S2].
2. `allow_old_summaries=false`: tolak summary lama setelah definisi data model berubah (ini juga default) [S1].
3. `count AS failures`: jumlah event gagal.
4. `dc(Authentication.user) AS distinct_users`: jumlah akun unik yang dicoba. Ini inti deteksi spraying: satu sumber, banyak akun.
5. `min(_time)/max(_time)`: rentang aktivitas, untuk timeline.
6. `from datamodel=Authentication.Authentication`: format `<data_model>.<root_dataset>`. Root dataset di CIM bernama sama dengan modelnya [S3].
7. `where Authentication.action="failure"`: nilai `action` di CIM adalah `success`, `failure`, `pending`, `error` [S3].
8. `by Authentication.src Authentication.app`: kelompokkan per sumber dan aplikasi (mis. `win:remote`, `ssh`).
9. `rename Authentication.* AS *`: buang prefiks objek supaya nama field rapi. Di ES, macro `` `drop_dm_object_name(Authentication)` `` melakukan hal serupa.
10. `where distinct_users >= 5`: ambang. Ini asumsi, jadi sesuaikan dengan baseline lingkunganmu.
11. `convert ctime(...)`: ubah epoch ke waktu yang terbaca.

Keluaran ilustrasi:

```
src            app         failures  distinct_users  firstTime            lastTime
10.10.5.23     win:remote  412       37              10/07/2026 01:12:03  10/07/2026 01:19:44
192.0.2.10     ssh         58        9               10/07/2026 03:00:11  10/07/2026 03:02:55
```

**Cara membaca hasil:** baris pertama (banyak akun dalam 7 menit dari satu host internal) mengarah ke password spraying atau host yang terinfeksi. Baris kedua bisa juga scanner SSH. Langkah lanjut: pivot ke `Authentication.action="success"` dari `src` yang sama setelah `lastTime`. Pertanyaannya: apakah ada login yang berhasil?
**Variasi:** ganti `by` dengan `Authentication.user` untuk sudut pandang terbalik: satu akun diserang dari banyak sumber, memakai `dc(Authentication.src)`.
**Kapan gagal/lambat:**
- Hasil kosong: data model belum di-accelerate, summary belum selesai dibangun, rentang waktu di luar summary range, atau `action` tidak ter-normalisasi (mis. masih `Failed`). Coba ulang dengan `summariesonly=false` untuk membandingkan.
- `src` kosong: TA tidak memetakan `src`, dan baris dengan null di field BY dibuang. Tambahkan `fillnull_value="unknown"` untuk melihatnya [S1].

### 2.3 prestats untuk timechart: aktivitas PowerShell per host

**Tujuan:** tren eksekusi `powershell.exe` per jam per host dari Sysmon EventCode 1 / Security 4688 yang dipetakan ke `Endpoint.Processes` [S4].

```
| tstats prestats=true summariesonly=true count
  from datamodel=Endpoint.Processes
  where Processes.process_name="powershell.exe"
  by _time span=1h Processes.dest
| timechart span=1h count by Processes.dest
```

- `prestats=true` mengeluarkan format internal yang hanya bermakna bagi `chart`/`stats`/`timechart` [S1]. Tanpa itu, `timechart` setelah `tstats` tidak berfungsi sebagaimana mestinya.
- `span` di `tstats` sebaiknya sama dengan atau lebih kecil dari `span` di `timechart` berikutnya [S1].
- `Processes.dest` adalah host tempat proses berjalan (CIM Endpoint).

Keluaran ilustrasi: grafik garis per host. Lonjakan di satu host pada jam yang tidak biasa layak dipivot ke `values(Processes.process)` (command line) untuk jam itu.
**Kapan gagal:** data Sysmon tidak dipetakan ke Endpoint (TA tidak terpasang atau tag tidak sesuai) sehingga hasil kosong. Cek dengan bagian 2.4.

### 2.4 Validasi: sumber apa yang mengisi data model, dan sejauh mana summary

```
| tstats count from datamodel=Endpoint.Processes by sourcetype
```

Pola ini juga direkomendasikan Lantern untuk melihat sourcetype yang masuk ke sebuah data model [S6]. Field `sourcetype`, `host`, `source`, `index` tersedia sebagai field bawaan di data model.

```
| tstats summariesonly=true min(_time) AS min max(_time) AS max from datamodel=Endpoint
| eval prettymin=strftime(min, "%c"), prettymax=strftime(max, "%c")
```

Contoh kedua diadaptasi dari pola di SPL reference untuk melihat rentang waktu yang benar-benar tercakup summary [S1]. Jika `prettymin` hanya dua hari lalu padahal summary range 30 hari, berarti summary masih dibangun atau ada gap.

### 2.5 Membaca pola detection Splunk Threat Research

Detection "Attacker Tools On Endpoint" di repo security_content (versi 20, dimodifikasi 22 Sep 2026) memakai pola berikut (dipotong) [S4]:

```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    values(Processes.process) as process ...
  FROM datamodel=Endpoint.Processes
  WHERE [ | inputlookup attacker_tools | rename attacker_tool_names AS Processes.process_name | fields Processes.process_name ]
    AND Processes.dest!=unknown Processes.user!=unknown
  by Processes.dest Processes.process_name Processes.user ...
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| ...
```

Pelajaran:
- Subsearch di WHERE menghasilkan daftar `Processes.process_name=...` dari lookup. Ini cara memakai daftar IOC di `tstats`.
- `Processes.dest!=unknown` membuang baris yang di-fillnull. Pola ini konsisten dengan macro yang mengatur `fillnull_value` [S5].
- Macro membuat konten portabel. Di lab tanpa ES, ganti macro dengan argumen eksplisit dan `rename`.

### 2.6 Langkah di ES (generik)

1. Settings > Data models (platform): pilih `Authentication` > Edit > Edit Acceleration, lalu aktifkan dan pilih summary range. Di ES, accelerate CIM data model juga bisa diatur lewat menu konfigurasi data model ES, cek nama menu di ES 8.x (Configure > CIM Setup / Data model acceleration) berbeda antar versi.
2. Batasi index yang dicari data model (indexes allow list / constraint macro). Lantern dan praktisi menekankan ini untuk performa [S6][S7]. Cek nama macro constraint di add-on CIM, mis. `cim_Authentication_indexes`.
3. Audit > Data Model Audit di ES untuk melihat status dan ukuran summary [S6].
4. Buka correlation search ES mana pun, lalu lihat SPL-nya. Hampir semua dimulai dengan `| tstats`. Latih membaca pola di bagian 2.5.

## 3. Lab praktik

**Prasyarat:** Splunk Enterprise dengan BOTS v1 (atau data Sysmon dari VM Windows lab), add-on Splunk CIM, TA yang relevan.

1. **Inventaris:** jalankan bagian 2.1 di rentang All time. Catat 5 sourcetype terbesar dan durasi search (Job > Inspect Job).
2. **Bandingkan:** jalankan `index=botsv1 | stats count by sourcetype` di rentang yang sama. Catat durasinya. Hasil yang diharapkan: hitungan sama, tetapi `tstats` jauh lebih cepat.
3. **Accelerate:** aktifkan acceleration untuk `Authentication` dan `Endpoint` dengan summary range yang mencakup dataset. BOTS v1 bertanggal 2016, jadi pilih range yang mencakup tahun itu, atau All Time untuk lab kecil. Tunggu status 100%.
4. **Validasi data model:** jalankan bagian 2.4 untuk `Authentication` dan `Endpoint.Processes`. Hasil yang diharapkan: muncul sourcetype Windows/Sysmon. Jika kosong, cek TA dan tag.
5. **Deteksi:** jalankan bagian 2.2 dengan ambang `>= 3`. Catat `src` teratas.
6. **Eksperimen summariesonly:** jalankan ulang langkah 5 dengan rentang dua kali summary range, dengan `summariesonly=true` lalu `false`. Hasil yang diharapkan: `true` lebih cepat tetapi jumlahnya sama atau lebih kecil dari `false`.
7. **prestats:** jalankan bagian 2.3, lalu ulangi tanpa `prestats=true` dan amati perbedaannya.
8. (Opsional, lab Atomic Red Team) Di VM Windows lab yang terisolasi, jalankan sendiri satu test eksekusi PowerShell yang jinak. Tunggu sekitar 5-10 menit, lalu cek apakah bagian 2.3 menangkapnya dengan `summariesonly=true`. Amati jeda acceleration.

**Hasil yang sebaiknya tersimpan:**
- Paham dan bisa menunjukkan beda durasi `tstats` vs `stats`.
- Data model Authentication dan Endpoint 100% ter-accelerate.
- Bagian 2.2 menghasilkan baris dengan `src` dan `distinct_users`.
- Bisa menjelaskan perbedaan hasil `summariesonly=true/false` dari langkah 6.

**Variasi tantangan:** tulis `tstats` atas `Network_Traffic.All_Traffic` yang mencari `src` dengan `dc(All_Traffic.dest_port) > 50` dalam 10 menit (indikasi port scan). Gunakan `by _time span=10m All_Traffic.src`. Jelaskan kemungkinan penjelasan jinak, mis. vulnerability scanner internal.

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| `tstats` tanpa data model mengembalikan kolom kosong | Field di BY/WHERE bukan indexed field | Pakai hanya `index/sourcetype/source/host/_time`, atau beralih ke data model [S1] |
| Hasil kosong dengan `summariesonly=true` | Acceleration mati/belum selesai, rentang di luar summary range, gap summary | Settings > Data models (status %), bagian 2.4, coba `summariesonly=false` [S2] |
| Jumlah lebih kecil daripada search raw | Baris null di field BY dibuang; atau sebagian rentang belum ter-summarize | Tambahkan `fillnull_value="unknown"`; bandingkan dengan `summariesonly=false` [S1] |
| `timechart` setelah `tstats` aneh/kosong | Lupa `prestats=true`, atau `span` tstats > span timechart | Tambahkan `prestats=true`; samakan atau perkecil span [S1] |
| Error/hasil salah saat memakai `count(eval(...))` | Tidak didukung tstats | Hitung terpisah dengan WHERE berbeda, atau agregasi lalu `eval` setelahnya [S1] |
| Data model tidak bisa di-accelerate | Model private | Share ke app/global [S2] |
| Acceleration tidak pernah 100% | Search summarization melebihi max time, model tanpa batas index | Batasi index (constraint), sesuaikan sumber daya [S2][S7]; `[komunitas]` banyak laporan serupa di Splunk Community, perlu dicek |
| Hasil berubah setelah edit data model | Summary lama vs baru | `allow_old_summaries=false` (default) dan rebuild bila perlu [S1] |

## 5. Kesalahan umum dan jebakan

- Mengira `summariesonly=true` itu default. Defaultnya `false` [S1]. Di ES/security_content nilainya dibuat `true` lewat macro [S5]. Kalau kamu menyalin SPL dari ES ke instance lain, perilakunya bisa berbeda.
- "Tidak ada hasil" diartikan "tidak ada serangan". Dengan `summariesonly=true`, gap summary membuat event hilang diam-diam. Dalam investigasi, konfirmasi dengan `summariesonly=false` atau search raw.
- Menaruh field search-time di WHERE tanpa data model. `tstats` hanya melihat yang ada di tsidx [S1].
- Memakai wildcard di BY (`by Authentication.*`). Tidak didukung [S1].
- Data model tanpa batas index. Acceleration memindai semua index, sehingga mahal dan lambat. Praktisi menyarankan setiap data model yang di-accelerate punya daftar index spesifik [S6][S7].
- `[komunitas, belum terkonfirmasi]` Hasil berbeda saat memakai nama dataset turunan (path objek) dibanding nama model saja. Penyebab yang paling sering disebut adalah salah path `nodename` atau constraint dataset. Buktikan di lab dengan menjalankan kedua bentuk pada rentang yang sama dan membandingkan jumlahnya.

## 6. Catatan terkini

- Dokumentasi Splunk pindah ke help.splunk.com (SPL reference 9.x-10.x) [S1][S2]. Tautan lama docs.splunk.com di tulisan lama sering tidak lagi bisa dibuka.
- **Versi:** Splunk Enterprise 10.6 rilis 30 Sep 2026 dan ES 8.7.0 rilis 2 Sep 2026; cocokkan tanggalnya dengan release notes resmi. Referensi `tstats` 10.2 tidak menunjukkan perubahan sintaks besar dibanding 9.x.
- **Federated Search:** klausa `FROM` di `tstats` untuk federated search membutuhkan minimal Splunk Enterprise 9.1.0 atau Cloud 9.0.2303 [S1].
- Security Content masih memakai `tstats` + data model untuk detection endpoint, dengan detection yang dimodifikasi September 2026 [S4]. Polanya stabil, jadi investasi belajar di sini tahan lama.
- CIM 6.4 (halaman diperbarui 3 Feb 2026) mencantumkan dataset Authentication: `Authentication`, `Default_Authentication`, `Insecure_Authentication`, `Privileged_Authentication` [S3]. Materi lama sering menyebut `Failed_Authentication`/`Successful_Authentication` sebagai dataset turunan. Cek di versi CIM yang terpasang di lab sebelum memakai `nodename`. Filter `Authentication.action="failure"` aman di semua versi.
- Sumber praktisi (Hurricane Labs, halaman bertanggal Okt 2026) masih menekankan audit acceleration dan constraint index sebagai penyebab utama masalah performa [S7].

## 7. Cheat sheet

```
# Indexed fields only (cepat, tanpa data model)
| tstats count where index=<idx> by sourcetype, host
| tstats count where index=<idx> by _time span=1h

# Data model CIM
| tstats summariesonly=true count from datamodel=<DM>.<Root> where <Root>.<field>=<val> by <Root>.<field>
| rename <Root>.* AS *                 (atau `drop_dm_object_name(<Root>)` di ES)

# Timechart dari tstats
| tstats prestats=true count from datamodel=... by _time span=1h <field> | timechart span=1h count by <field>

# Validasi
| tstats count from datamodel=<DM> by sourcetype
| tstats summariesonly=true min(_time) max(_time) from datamodel=<DM>
```

| Argumen | Default | Ingat |
|---|---|---|
| `summariesonly` | false | true = hanya summary (cepat, bisa tidak lengkap) |
| `allow_old_summaries` | false | true = pakai summary dari definisi lama |
| `prestats` | false | true untuk diteruskan ke chart/stats/timechart |
| `fillnull_value` | (tidak ada) | tanpa ini, null di BY dibuang |
| `chunk_size` | 10000000 | jarang diubah |

Root dataset umum: `Authentication.Authentication`, `Endpoint.Processes`, `Network_Traffic.All_Traffic`, `Network_Resolution.DNS`, `Web.Web`.

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Rekanmu menyalin satu detection dari search head ES ke search head biasa, menghapus macro-nya, dan menulis ulang jadi `| tstats count from datamodel=Authentication ...` tanpa argumen tambahan. Hasilnya jauh lebih banyak daripada di ES, dan ia menyimpulkan ada lonjakan serangan. Apa yang sebenarnya terjadi?

<details><summary>Jawaban</summary>

Yang berubah bukan datanya, melainkan `summariesonly`. Defaultnya `false`, jadi versi barunya mengembalikan hasil lengkap: bagian yang ada di summary dibaca dari summary, sisanya diambil dari data mentah. Di ES, macro `security_content_summariesonly` mengisi `summariesonly=true` beserta `allow_old_summaries` dan `fillnull_value`, sehingga search aslinya hanya melihat yang sudah ter-summarize dan karena itu bisa melaporkan lebih sedikit. Selisih dua angka itu bukan temuan keamanan, melainkan selisih cakupan summary, jadi jangan pakai salah satunya sebagai bukti tanpa menyebutkan argumen yang dipakai. Lihat bagian 1.3 dan 5.

</details>

**2. Skenario keputusan.** Kamu menulis `| tstats count where index=wineventlog by user` untuk menghitung event per akun, dan hasilnya kosong. Langkah mana yang paling tepat?

- A. Tambahkan `summariesonly=false` supaya `tstats` ikut membaca data mentah untuk bagian yang belum ter-summarize.
- B. Pindahkan pertanyaannya ke data model yang memuat field itu, misalnya `from datamodel=Authentication.Authentication ... by Authentication.user`, atau terima bahwa ini pekerjaan `stats` atas search biasa.
- C. Tambahkan `fillnull_value="unknown"` supaya baris dengan `user` kosong tidak dibuang.

<details><summary>Jawaban</summary>

B. Tanpa klausa `FROM datamodel=...`, `tstats` hanya melihat isi tsidx, yaitu field indexed seperti `index`, `sourcetype`, `source`, `host`, dan `_time`. Field `user` umumnya hasil ekstraksi saat search, jadi ia tidak ada di tsidx dan tidak bisa dipakai di `by` maupun di `where`. A tidak menolong karena `summariesonly` hanya mengatur pemakaian summary data model, dan pertanyaannya di sini tidak menyentuh data model sama sekali. C menjawab gejala yang berbeda: `fillnull_value` menyelamatkan baris yang nilainya null pada field BY, bukan field yang sejak awal tidak dikenal. Lihat bagian 1.1 dan 2.1.

</details>

**3. Pertanyaan jebakan.** Sebuah `tstats` atas data model mengembalikan jumlah yang lebih kecil daripada search raw untuk rentang waktu yang sama, padahal akselerasi sudah 100 persen dan rentangnya masih di dalam summary range. Apa dugaan pertamamu?

<details><summary>Jawaban</summary>

Baris yang nilainya null pada salah satu field di `by` dibuang, karena `fillnull_value` tidak punya default. Satu field yang tidak dipetakan add-on, misalnya `src` yang kosong pada sebagian sourcetype, cukup untuk menghilangkan sekelompok hasil tanpa pesan error. Tambahkan `fillnull_value="unknown"` untuk melihat baris itu, lalu bandingkan dengan `summariesonly=false` untuk memastikan penyebabnya memang null dan bukan gap summary. Lihat bagian 1.4 dan 4.

</details>

**4. Jelaskan ulang.** Jelaskan ke rekan NOC yang sudah biasa membaca counter di NMS, dalam tiga kalimat, kenapa `tstats` cepat dan apa yang tidak bisa dilihatnya.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh jawaban: "Splunk menyimpan dua hal untuk setiap bucket: teks event yang dikompresi, dan file tsidx yang memetakan pasangan field dan nilai ke lokasi event. `tstats` hanya membaca file tsidx itu, jadi ia tidak perlu mendekompresi dan mem-parsing event sama sekali, mirip membaca counter yang sudah diagregasi daripada menarik ulang log perangkat. Konsekuensinya ia hanya melihat field yang ada di tsidx, yaitu field indexed bawaan dan field data model yang sudah ter-summarize, sehingga field hasil ekstraksi saat search dan isi `_raw` berada di luar jangkauannya."

Kesalahan yang sering muncul: menyebut `tstats` sebagai `stats` versi cepat tanpa menyebut batas fieldnya; mengira akselerasi data model menyalin seluruh event, padahal yang ditulis hanya field yang didefinisikan di model; dan lupa bahwa summary selalu tertinggal dari data mentah, sehingga aktivitas beberapa menit terakhir bisa belum terhitung. Lihat bagian 1.1 dan 1.2.

</details>

**5. Interview question (English).** "Most of the detections you read in Splunk start with tstats. Why, and what do you check before trusting the result?"

<details><summary>Sample answer</summary>

"Because detections run on a schedule against very large volumes, and tstats answers aggregate questions straight from the tsidx files instead of decompressing and parsing raw events, so the cost stays predictable. When a data model is accelerated, the CIM fields are written into the model's own summary, which is why content from Splunk Security Content is built on tstats over accelerated CIM data models rather than on raw searches. Before I trust a result, I check three things. First, summariesonly: it defaults to false, but ES content sets it to true through a macro, so the same SPL can mean different coverage on different instances. Second, the summary itself: whether the model is accelerated, whether the search range sits inside the summary range, and how fresh the summary is, because an empty result can simply mean the events are not summarised yet. Third, the by clause: fillnull_value has no default, so rows with a null in a group-by field are silently dropped, and that alone can make the count look smaller than the raw search. In an investigation I confirm anything negative with summariesonly=false or a narrow raw search, because 'no results' is not the same as 'no activity'."

What makes this answer strong: it explains the mechanism rather than repeating that tstats is fast, names the three specific failure modes with the behaviour that causes each one, and ends with the habit that matters in an investigation, which is refusing to treat an empty result as evidence.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | SPL Search Reference: tstats (Splunk Enterprise 10.2) | https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.2/search-commands/tstats | primer | diakses 2026-10-07 | Tinggi. Sintaks, default, batasan, contoh |
| S2 | Accelerate data models (Knowledge Manager Manual 10.4) | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.4/use-data-summaries-to-accelerate-searches/accelerate-data-models | primer | diperbarui 2026-07-24; diakses 2026-10-07 | Tinggi. Summary range, lokasi, interval, batasan |
| S3 | CIM 6.4: Authentication data model | https://help.splunk.com/en/data-management/common-information-model/6.4/data-models/authentication | primer | diperbarui 2026-02-03; diakses 2026-10-07 | Tinggi. Dataset, field, nilai `action` |
| S4 | security_content: attacker_tools_on_endpoint.yml | https://github.com/splunk/security_content/blob/develop/detections/endpoint/attacker_tools_on_endpoint.yml | sekunder (repo resmi Splunk Threat Research) | dimodifikasi 2026-09-22; diakses 2026-10-07 | Tinggi untuk pola SPL. Isi detection bisa berubah |
| S5 | security_content: macro security_content_summariesonly | https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml | sekunder | diakses 2026-10-07 | Tinggi. Definisi macro |
| S6 | Splunk Lantern: Managing data models in Enterprise Security | https://lantern.splunk.com/Security/Product_Tips/Enterprise_Security/Managing_data_models_in_Enterprise_Security | primer (Lantern resmi) | tanggal tidak terlihat; diakses 2026-10-07 | Sedang-tinggi. Contoh tstats by sourcetype, Data Model Audit, allow list |
| S7 | Hurricane Labs: How to improve your data model acceleration in Splunk | https://www.hurricanelabs.com/blog/how-to-improve-your-data-model-acceleration-in-splunk | sekunder (praktisi) | tanggal di halaman Okt 2026; diakses 2026-10-07 | Sedang. Praktik lapangan constraint index |
| S8 | Splunk Community: thread "tstats summariesonly=t gets no results" dan "Datamodel Acceleration Consistently Reaching Max Summarization" | https://community.splunk.com/t5/Splunk-Search/tstats-summariesonly-t-gets-no-results-on-accelerated-data/m-p/355202 ; https://community.splunk.com/t5/Knowledge-Management/Datamodel-Acceleration-Consistently-Reaching-Max-Summarization/m-p/747890 | komunitas | tanggal tidak tercatat | Rendah. Dipakai sebagai petunjuk jebakan, tanpa klaim faktual tambahan |

**Catatan sumber:** klaim bertanda `[komunitas]` di bagian 4 dan 5 hanya bersandar pada thread Splunk Community [S8]; anggap sebagai petunjuk dan buktikan di lab. Pola detection dirujuk dari file YAML di repo security_content [S4][S5] karena isi dan alamat halaman research.splunk.com bisa berubah antar rilis ESCU.
