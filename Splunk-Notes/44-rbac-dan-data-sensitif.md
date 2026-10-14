---
day: 44
title: 'RBAC, srchFilter, dan penanganan data sensitif: membatasi akses tanpa mematikan investigasi'
researched_on: 2026-10-10
versions_checked: 'Splunk Enterprise 10.6 (Securing Splunk Enterprise: roles dan capabilities, authorize.conf spec, audit events; field filter, diakses 2026-10-15); Splunk Enterprise Security 8.7 (role ES); rujukan Day 28, 33, 40, 43'
---

# Day 44: RBAC dan penanganan data sensitif di Splunk

Cakupan: cara role, capability, dan izin index bekerja; apa yang bisa dan tidak bisa dilakukan `srchFilter`; pilihan untuk membatasi data sensitif beserta harganya; serta cara mengaudit siapa melihat apa tanpa mengganggu pekerjaan investigasi.

## Ide inti

Di Splunk, apa yang bisa dilihat dan dilakukan seseorang ditentukan empat lapis: authentication, role, capability, dan izin atas index serta knowledge object. Dari semua mekanisme itu, batas yang benar-benar kuat hanya satu, yaitu index terpisah yang dibuka per role lewat `srchIndexesAllowed`. Mekanisme lain punya tempatnya masing-masing, tetapi juga celahnya: `srchFilter` menyaring event, bukan field, dan bisa terlewati lewat jalur seperti `tstats`, summary index, dan lookup; field filter bisa menyamarkan satu kolom saat search, tetapi tidak melindungi lookup dan hanya sebagian dipatuhi `tstats`; masking saat index tidak bisa dibuka lagi dan hanya berlaku untuk data baru; dan setiap hasil search yang disimpan ke lookup atau summary index menjadi salinan data dengan model izin baru. Ditambah satu sifat yang sering terlupa, yaitu izin bersifat akumulatif, kesimpulannya sederhana: membatasi akses berarti mencabut role yang luas dan memisahkan data, bukan menambah role sempit atau memasang filter. Karena itu kontrol akses yang rapi di Splunk hampir selalu dimulai dari desain index yang rapi, dan Day ini memakai masking saat index (Day 28) serta pemisahan index untuk retensi (Day 43) sebagai bahan.

Dua kegagalan sering terjadi bersamaan di SOC. Yang pertama, semua analyst diberi role `admin` karena "biar tidak ribet", sehingga tidak ada pemisahan tugas dan setiap kesalahan bisa berakibat luas. Yang kedua, reaksi berlebihan setelah audit: akses dipersempit sampai analyst tidak bisa melihat log yang dibutuhkan untuk menilai insiden, lalu investigasi berjalan dengan tebakan. Keduanya masalah desain, bukan masalah teknis. Day ini membahas mekanismenya supaya kamu bisa ikut merancang, dan supaya kamu bisa menjelaskan dengan tenang ketika auditor bertanya "siapa yang bisa melihat data ini". Auditor biasanya menanyakan tiga hal: akses diberikan berdasarkan kebutuhan tugas (least privilege), hak akses ditinjau berkala, dan akses ke log itu sendiri tercatat sehingga bisa dibuktikan.

Padanannya sudah kamu kenal dari konsol NOC: hak akses per tim, misalnya L1 hanya melihat perangkat tertentu. Batasnya ada di cara pembatasan itu bekerja. `srchFilter` ditambahkan ke setiap search milik role itu, tetapi bukan pengganti pemisahan index. Index sendiri mirip folder per kelompok perangkat di server syslog, dengan satu perbedaan penting: index juga batas hak akses dan retensi, bukan hanya tempat menyimpan, sehingga keputusan "data ini masuk index mana" sebenarnya sudah keputusan akses.

Di PT Jaringan Anak Bangsa (PT JAB, ISP menengah fiktif), SOC terdiri dari enam analyst L1 dalam tiga shift, dua analyst L2, satu detection engineer, dan satu SOC lead, sehingga tiga peran kerja di bagian 1.5 (triage, investigator, engineer) punya pemegang yang nyata. Beberapa index di sana lebih sensitif daripada kesan namanya: command line di `wineventlog` dan isi script di `powershell` bisa memuat password (Day 03 dan Day 04), dan query di `dns` adalah catatan perilaku pelanggan (Day 05). Permintaan yang rutin datang adalah auditor internal yang meminta bukti review akun admin, dan jawabannya ada di bagian 2.4.

**Kapan relevan:** saat menyiapkan akses untuk anggota tim baru; saat ada data berklasifikasi tinggi masuk ke SIEM; saat audit internal menanyakan pemisahan tugas atau meminta bukti siapa bisa melihat index tertentu; saat investigasi terhambat izin; dan saat menulis search yang menyalin hasil ke lookup atau summary index.
**Kapan bukan jawaban:** `srchIndexesAllowed` dan `srchFilter` bekerja pada tingkat event, jadi kebutuhan menyamarkan sebagian isi event diselesaikan dengan field filter, saat index (Day 28), atau dengan memisahkan datanya. Role juga tidak menjangkau data yang sudah keluar dari Splunk, seperti email alert (Day 09), ekspor CSV, atau tangkapan layar yang dikirim lewat chat. Dan mempersempit akses bukan jawaban selama belum ada jalur akses sementara untuk insiden, karena kontrol yang membuat pekerjaan tidak mungkin akan diakali.

## 1. Konsep inti

### 1.1 Empat lapis yang menentukan apa yang bisa dilakukan seseorang

| Lapis | Mengatur | Contoh |
|---|---|---|
| Authentication | Siapa yang masuk | Lokal, LDAP, SAML, multifactor |
| Role | Kumpulan izin yang diberikan ke user | `soc_triage`, `soc_investigator`, `power`, `admin` |
| Capability | Aksi apa yang boleh dilakukan | `search`, `schedule_search`, `rtsearch`, `edit_tokens_settings`, `admin_all_objects` |
| Izin objek dan index | Data dan knowledge object apa yang terlihat | `srchIndexesAllowed`, izin app, sharing dashboard dan lookup |

Satu user bisa memegang beberapa role, dan role bisa mewarisi role lain. Yang perlu diingat: izin bersifat akumulatif. Menambahkan role sempit ke user yang sudah punya role luas tidak mempersempit apa pun. Pembatasan hanya nyata bila role luasnya dicabut.

Konfigurasinya tersimpan di `authorize.conf`, dan bisa diatur dari UI pada Settings lalu Roles [S1]:

```
# authorize.conf
[role_soc_triage]
importRoles = user
srchIndexesAllowed = idx_security;idx_endpoint;idx_proxy;idx_auth
srchIndexesDefault = idx_security
srchJobsQuota = 3
rtSrchJobsQuota = 0
srchDiskQuota = 200
srchTimeWin = 2592000
cumulativeSrchJobsQuota = 10

[role_soc_investigator]
importRoles = soc_triage
srchIndexesAllowed = idx_security;idx_endpoint;idx_proxy;idx_auth;idx_dns;idx_email_meta
srchJobsQuota = 6
srchTimeWin = 0
schedule_search = enabled
```

Setting yang paling sering menentukan pengalaman kerja sehari-hari:

- `srchIndexesAllowed`: index yang boleh dicari. Ini kontrol akses data yang paling kuat dan paling jelas di Splunk.
- `srchIndexesDefault`: index yang dicari bila user menulis search tanpa `index=`. Isi ini dengan hati-hati; terlalu luas membuat search mahal, terlalu sempit membuat orang bingung kenapa hasilnya kosong.
- `srchTimeWin`: batas rentang waktu maksimum per search. Nilai 0 berarti tanpa batas. Berguna untuk role triage, tetapi jangan dipasang ke role investigator, karena investigasi sering perlu menengok jauh ke belakang.
- `srchJobsQuota` dan `rtSrchJobsQuota`: batas search bersamaan, termasuk real-time. Mematikan kuota real-time untuk role biasa adalah salah satu cara termudah menjaga kesehatan search head (Day 43).
- `srchDiskQuota`: batas ruang hasil search tersimpan per user.

### 1.2 Capability yang perlu diperhatikan

Beberapa capability memberi kekuatan yang jauh lebih besar daripada kesannya:

| Capability | Risikonya bila diberikan sembarangan |
|---|---|
| `admin_all_objects` | Melewati izin objek. Pemegangnya bisa melihat dan mengubah knowledge object siapa pun |
| `edit_user` | Bisa mengubah user lain, termasuk menaikkan hak |
| `edit_roles` atau `edit_roles_grantable` | Bisa memperluas izinnya sendiri secara tidak langsung |
| `edit_indexes` dan `edit_monitor` | Bisa mengubah apa yang masuk dan ke mana, termasuk menghentikan ingest |
| `edit_tokens_settings` dan pembuatan token | Bisa membuat akses yang bertahan lama di luar sesi login |
| `run_script` atau izin custom command tertentu | Jalur eksekusi kode di server Splunk |
| `rtsearch` | Real-time search mengunci slot dan bisa membebani search head |
| `delete_by_keyword` | Menandai data sebagai terhapus dari pencarian |
| `run_commands_ignoring_field_filter` | Melewati semua field filter di semua index (bagian 1.4) [S6] |

Aturan praktisnya: role analyst tidak perlu capability yang mengubah platform. Kebutuhan analyst hampir semuanya tentang membaca data, membuat knowledge object di app timnya, dan menjalankan search terjadwal.

Di ES, ada role tambahan (misalnya pemakai ES dan pengelola ES) yang mengatur siapa boleh mengubah detection, menjalankan adaptive response, dan mengelola threat intelligence. Nama role ES berbeda antar versi, jadi cek daftar role di instance-mu dan petakan ke tiga peran kerja di bagian 1.5 [S2].

### 1.3 `srchFilter` dan batasnya

`srchFilter` menambahkan filter yang dipaksakan ke setiap search milik role itu:

```
[role_soc_app_team]
importRoles = user
srchIndexesAllowed = idx_app
srchFilter = business_unit=retail
```

Setiap search dari role itu akan diperlakukan seolah memuat `business_unit=retail`. Ini berguna untuk multi-tenant ringan, misalnya satu index berisi data beberapa unit bisnis.

Tiga batasan yang wajib kamu ketahui sebelum mengandalkannya:

1. **Ia menyaring event, bukan field.** Bila satu event memuat kolom sensitif, pemegang akses melihat seluruh event itu. Kebutuhan menyembunyikan sebagian isi event diselesaikan dengan field filter (bagian 1.4), masking saat index (Day 28), atau dengan memisahkan datanya.
2. **Ia bekerja paling andal untuk field yang nilainya ada di raw data atau indexed field.** Filter yang bergantung field hasil ekstraksi search-time, lookup, atau calculated field bisa berperilaku tidak seperti yang diharapkan. Setiap `srchFilter` harus diuji dengan akun uji, bukan diasumsikan.
3. **Ia tidak berlaku pada beberapa jalur akses data.** `tstats` atas data model terakselerasi, summary index, hasil lookup, dan laporan terjadwal yang dijalankan atas nama user lain adalah tempat kebocoran paling sering terjadi. Bila datanya benar-benar sensitif, pisahkan index-nya, jangan hanya memfilter.

Kesimpulannya: `srchFilter` adalah alat kenyamanan dan pemisahan ringan, bukan batas keamanan yang kuat. Batas yang kuat adalah index terpisah dengan `srchIndexesAllowed`.

### 1.4 Field filter: menyamarkan field saat search

Kembali ke `wineventlog` di PT JAB: command line di sana sesekali memuat password, tetapi analyst L1 tetap butuh event-nya untuk triage. `srchFilter` tidak bisa menolong karena ia hanya meloloskan atau menahan event utuh. Untuk kebutuhan ini Splunk Enterprise 10.6 punya field filter, yang menghapus atau menyamarkan field tertentu di hasil search tanpa mengubah event yang tersimpan di index [S5].

Cara kerjanya yang perlu kamu pegang:

- Satu field filter berlaku untuk index tertentu dan bisa dipersempit ke host, source, atau sourcetype tertentu [S8]. Ia bisa menyasar `_raw`, indexed field, maupun field hasil ekstraksi search-time [S5].
- Ada tiga cara menyamarkan nilai: menghapus field dari hasil, mengganti nilainya dengan string tetap seperti `XXXX`, atau menggantinya dengan hash SHA-256 atau SHA-512 [S5]. Untuk `_raw`, spesifikasi `field_filters.conf` juga mengenal ekspresi `sed` [S8]. Hash berguna di SOC karena nilai yang sama tetap menghasilkan hash yang sama, sehingga `stats count` dan `dc` masih bisa dihitung tanpa membuka nilai aslinya.
- Filter berlaku untuk semua role, lalu role tertentu dikecualikan. Pengecualian diatur lewat Splunk Web atau REST API, bukan dengan menyunting file konfigurasi [S5] [S8]. Di PT JAB, misalnya, `soc_investigator` dikecualikan sementara `soc_triage` hanya melihat hash.

Batasannya justru yang paling menentukan desain:

1. **Beberapa command dimatikan di index yang punya field filter.** Di 10.6, `mpreview` dan `mstats` tidak bisa dijalankan siapa pun di index itu secara default. Role bisa diizinkan lewat pengecualian dari filter tertentu, atau lewat capability `run_commands_ignoring_field_filter` yang melewati semua field filter di semua index [S6].
2. **`tstats` hanya mematuhi filter pada indexed field.** Filter atas `_raw` tidak berlaku karena `tstats` membaca file tsidx, dan pembatasan host, source, atau sourcetype tidak selalu ditegakkan, misalnya di fungsi agregat [S7]. Ini jalur bocor yang sama seperti pada `srchFilter` di bagian 1.3.
3. **Data di luar index tidak terlindungi.** Lookup table tidak bisa dilindungi dengan field filter [S5], jadi hasil `outputlookup` tetap menjadi salinan dengan izin sendiri (bagian 1.6).
4. **Dampak ke ES.** Dokumentasi menyarankan tidak memakai field filter di produksi pada deployment ES sebelum dampaknya direncanakan, termasuk ke data model terakselerasi dan detection yang memakainya [S5].

Posisi field filter sebagai operasi pertama di urutan search-time, beserta siapa yang secara default boleh mengelolanya, dibahas di Day 16 bagian 1.5. Kesimpulan untuk Day ini: field filter mengisi celah "event boleh dilihat, satu kolomnya tidak", tetapi bukan pengganti index terpisah untuk data yang benar-benar sensitif.

### 1.5 Tiga role SOC yang masuk akal

Rancangan awal yang bisa kamu pakai di lab dan di tempat kerja kecil:

| Role | Tugas | Akses data | Capability penting | Batasan |
|---|---|---|---|---|
| `soc_triage` | Triage antrean, penilaian awal, eskalasi | Index deteksi inti (security, endpoint, auth, proxy) | `search` | Tanpa real-time, `srchTimeWin` 30 hari, kuota kecil |
| `soc_investigator` | Investigasi mendalam, hunting, pembuatan case | Semua index operasional ditambah DNS dan metadata email | `search`, `schedule_search` | Tanpa capability administratif |
| `soc_engineer` | Detection engineering, onboarding, tuning | Index operasional ditambah `_internal` dan `_audit` | `schedule_search`, izin mengubah detection di app tim | Perubahan index dan input lewat proses terpisah |

Tiga catatan yang membuat rancangan ini bertahan:

- Akses ke `_internal` dan `_audit` bukan hal sepele. Keduanya berisi query orang lain dan informasi sistem, tetapi tanpa itu detection engineer tidak bisa mendiagnosis skipped search (Day 43).
- Data berklasifikasi tinggi (HR, hukum, rekaman transaksi berisi data pribadi) dipisah ke index sendiri dan diberikan per kebutuhan, dengan pencatatan siapa diberi akses dan sampai kapan.
- Akses sementara untuk insiden perlu jalur resmi yang cepat. Bila jalur itu tidak ada, orang akan memakai akun bersama, dan itu jauh lebih buruk.

### 1.6 Data sensitif: lima pilihan dan harganya

| Pilihan | Cara | Yang didapat | Harganya |
|---|---|---|---|
| Jangan kirim | Matikan field di sumber atau di HF | Risiko paling kecil | Data hilang untuk investigasi, selamanya |
| Masking saat index | `SEDCMD` atau transform (Day 28) | Nilai asli tidak pernah tersimpan | Tidak bisa dibuka lagi; hanya untuk data baru |
| Samarkan saat search | Field filter (bagian 1.4) | Nilai asli tetap tersimpan dan terlihat oleh role yang dikecualikan; berlaku juga untuk data lama | `mpreview` dan `mstats` dibatasi, `tstats` hanya mematuhi filter indexed field, lookup tidak terlindungi, perlu rencana bila ada ES |
| Pisahkan index | Routing berdasarkan isi (Day 28 bagian 1.5) | Batas akses jelas dan kuat | Perlu desain index dan pemeliharaan izin |
| Batasi role | `srchIndexesAllowed`, `srchFilter` | Fleksibel, bisa diubah cepat | Lemah bila hanya mengandalkan `srchFilter` |

Urutan keputusan yang biasanya benar: tanyakan dulu apakah datanya benar-benar perlu masuk. Kalau perlu, tanyakan apakah nilainya perlu utuh untuk investigasi. Nomor kartu dan password tidak perlu utuh, jadi mask. Nama pasien atau nomor rekening mungkin perlu utuh untuk investigasi penipuan, jadi pisahkan index-nya dan batasi aksesnya, bukan dimask. Field filter ada di tengah: cocok bila event-nya perlu dilihat banyak orang tetapi satu atau dua kolomnya hanya untuk segelintir role, dengan syarat batasan di bagian 1.4 sudah diuji di lab-mu.

Satu hal yang sering terlewat: hasil search juga data. Dashboard tersimpan, lookup hasil ekspor, summary index (Day 40), dan file ekspor CSV bisa memuat data sensitif yang izinnya tidak seketat index asalnya. Setiap kali kamu menulis `outputlookup` atau `collect`, kamu membuat salinan data dengan model izin baru. Periksa itu secara sadar.

### 1.7 Audit: siapa melihat apa

`index=_audit` mencatat login, search yang dijalankan, dan perubahan konfigurasi [S3]. Ini sekaligus bukti kontrol untuk audit dan alat diagnosis untuk platform.

Yang penting dipahami sebagai analyst: query yang kamu jalankan tercatat, termasuk teksnya. Itu wajar dan benar. Konsekuensi etisnya: jangan menjalankan search terhadap data pribadi rekan kerja atau data di luar lingkup tugas. Di beberapa organisasi, pelanggaran seperti itu diperlakukan sebagai pelanggaran disipliner, tidak lagi dianggap kebiasaan buruk.

### 1.8 Risiko dari akses yang terlalu sempit

Jarang dibahas, tetapi nyata:

- Analyst tidak bisa menilai dampak, sehingga eskalasi dilakukan berdasarkan dugaan dan insiden kecil membesar.
- Orang meminta tangkapan layar atau ekspor data dari tim lain lewat chat, sehingga data sensitif berpindah ke tempat yang tidak terkontrol.
- Muncul akun bersama dan kredensial yang dipakai bergantian supaya pekerjaan tetap jalan.
- Deteksi tidak di-tuning karena orang yang melihat false positive tidak punya akses untuk memeriksa penyebabnya.

Karena itu pembatasan akses perlu dirancang bersama kebutuhan kerja, dan perlu ada jalur eskalasi akses yang cepat saat insiden. Kontrol yang membuat pekerjaan tidak mungkin akan diakali, dan hasilnya lebih berisiko daripada sebelum kontrol itu ada.

## 2. Contoh konfigurasi dan search audit

> Keluaran berlabel ilustrasi. Semua dijalankan di instance lab sendiri dengan akun uji.

### 2.1 Membuat dan menguji role triage

```
# authorize.conf (di search head)
[role_soc_triage]
importRoles = user
srchIndexesAllowed = idx_security;idx_endpoint;idx_auth
srchIndexesDefault = idx_security
srchTimeWin = 2592000
srchJobsQuota = 3
rtSrchJobsQuota = 0
```

Uji dengan akun uji, bukan dengan akun admin:

```
# login sebagai user uji, lalu jalankan:
index=idx_hr error
```

Hasil yang diharapkan: kosong atau pesan bahwa index tidak ditemukan, bukan data HR. Lanjutkan dengan uji batas waktu:

```
index=idx_security earliest=-90d | stats count
```

Hasil yang diharapkan: search dipotong atau ditolak sesuai `srchTimeWin` 30 hari. Bila ternyata jalan penuh 90 hari, berarti user itu masih memegang role lain yang lebih longgar. Periksa dengan:

```
| rest /services/authentication/users | search title="uji_triage" | table title roles
```

### 2.2 Membuktikan `srchFilter` benar-benar membatasi

```
[role_app_retail]
importRoles = user
srchIndexesAllowed = idx_app
srchFilter = business_unit=retail
```

Tiga uji yang harus dilakukan, bukan satu:

```
# 1. jalur normal
index=idx_app | stats count BY business_unit

# 2. jalur data model terakselerasi
| tstats count from datamodel=Lab_App.Events by Lab_App.Events.business_unit

# 3. jalur summary index dan lookup
index=summary_lab source="si_app_harian" | stats count BY business_unit
| inputlookup lab_app_inventory | stats count BY business_unit
```

Keluaran ilustrasi untuk uji pertama:

```
business_unit  count
retail         18422
```

Bila uji kedua atau ketiga memperlihatkan unit lain, kamu baru saja menemukan kebocoran yang khas. Perbaikannya: pindahkan data ke index terpisah, atau batasi juga akses ke data model dan summary index-nya.

### 2.3 Melihat siapa menjalankan search apa

```
index=_audit action=search info=completed earliest=-7d
| rex field=search "index\s*=\s*\"?(?<index_dicari>[\w*_-]+)"
| stats count AS jumlah values(index_dicari) AS index_disentuh BY user
| sort - jumlah
| head 20
```

Keluaran ilustrasi:

```
user          jumlah  index_disentuh
dhika         412     idx_auth idx_endpoint idx_security
uji_triage    38      idx_security
svc_dashboard 1180    idx_proxy
```

Cara membacanya: akun layanan dengan jumlah search sangat tinggi biasanya dashboard yang menyegarkan diri terlalu sering, dan itu beban nyata di search head (Day 43). Untuk tujuan audit akses, yang dicari berbeda: user yang menyentuh index di luar kebiasaan perannya.

**Variasi yang berguna** untuk memeriksa pencarian terhadap entitas tertentu, misalnya saat ada dugaan penyalahgunaan akses:

```
index=_audit action=search info=completed earliest=-30d search="*nomor_rekening*" OR search="*nik*"
| table _time user search
| sort - _time
```

**Kapan gagal:** teks search di `_audit` bisa terpotong untuk search yang sangat panjang, dan search yang dijalankan lewat dashboard muncul dengan bentuk yang sudah diekspansi. Jangan memakai hasil ini sebagai bukti tunggal.

### 2.4 Memeriksa perubahan konfigurasi dan role

```
index=_audit action IN ("edit_user","edit_roles","edit") earliest=-30d
| table _time user action object info
| sort - _time
```

```
| rest /services/authorization/roles
| table title, srchIndexesAllowed, srchIndexesDefault, srchTimeWin, srchJobsQuota, rtSrchJobsQuota, imported_roles
| sort title
```

Search kedua menghasilkan gambaran izin saat ini dalam satu tabel. Simpan hasilnya setiap kali ada perubahan; inilah bukti yang diminta auditor, dan sekaligus cara tercepat menjawab "siapa yang bisa melihat index ini".

### 2.5 Memeriksa apakah objek turunan membocorkan data

```
| rest /services/saved/searches
| search action.outputlookup.* = * OR search="*outputlookup*" OR search="*collect*"
| table title, author, eai:acl.sharing, eai:acl.perms.read, search
```

Yang dicari: saved search yang menulis hasil ke lookup atau summary index yang izin bacanya lebih luas daripada index sumbernya. Ini kebocoran paling umum dan paling tidak disengaja di Splunk.

### 2.6 Pola pemberian akses sementara saat insiden

Dicatat sebagai prosedur, bukan sebagai perintah:

```
1. Permintaan: siapa, index apa, untuk insiden apa, sampai kapan (maksimal 72 jam).
2. Pemberian: tambahkan role sementara (mis. ir_temp_idx_hr) ke user, bukan menambah index ke role permanen.
3. Catat: nomor insiden, pemberi, waktu, dan waktu kedaluwarsa di tabel (bisa lookup KV store, Day 40).
4. Pencabutan: scheduled search harian memeriksa tabel dan memberi alert bila ada akses melewati batas.
5. Setelah insiden: tulis di laporan bahwa akses sementara dipakai, oleh siapa, dan untuk apa.
```

Langkah 4 adalah bagian yang paling sering dilupakan, dan justru itu yang membuat kontrol ini bisa dipercaya.

## 3. Lab praktik

**Prasyarat:** Splunk lab dengan beberapa index, akses admin untuk membuat role, dan satu akun uji (bukan akun utamamu).

1. Buat tiga index lab: `idx_security`, `idx_app`, dan `idx_sensitif` (isi terakhir dengan data fiktif yang menyerupai data pribadi, misalnya nomor identitas palsu berpola jelas).
2. Buat tiga role sesuai bagian 1.5, lalu buat satu akun uji per role.
3. Login sebagai masing-masing akun uji dan coba: cari di index yang tidak diizinkan, jalankan search 90 hari, jalankan real-time search. Catat perilaku persisnya, termasuk teks pesan errornya.
4. Pasang `srchFilter` pada satu role untuk `idx_app`, lalu jalankan tiga uji jalur di bagian 2.2. Dokumentasikan jalur mana yang bocor di lab-mu.
5. Masking: tambahkan `SEDCMD` untuk data sensitif di satu sourcetype (Day 28), onboard ulang, lalu buktikan role investigator pun tidak bisa melihat nilai aslinya.
6. Buat satu saved search yang menulis hasil `idx_sensitif` ke lookup yang dibagikan global. Jalankan deteksi kebocoran di bagian 2.5 dan buktikan masalahnya terlihat. Perbaiki dengan mempersempit sharing lookup.
7. Jalankan audit bagian 2.3 dan 2.4 untuk melihat aktivitasmu sendiri selama lab ini. Simpan satu tangkapan tabel izin dari bagian 2.4 sebagai lampiran.
8. Tulis satu halaman rancangan akses untuk SOC fiktif: daftar index, klasifikasi, role yang berhak, alasannya, dan prosedur akses sementara.

**Hasil yang sebaiknya tersimpan:**
- Isi `authorize.conf` tiga role milikmu dengan komentar alasan tiap setting.
- Tabel hasil uji akses per akun uji (apa yang diizinkan dan ditolak).
- Daftar jalur yang membocorkan `srchFilter` di lab-mu.
- Satu halaman rancangan akses, termasuk prosedur akses sementara.

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Pembatasan role tidak berefek | User masih memegang role lain yang lebih longgar (izin akumulatif) | `\| rest /services/authentication/users \| table title roles` |
| Search user kosong padahal datanya ada | `srchIndexesDefault` tidak memuat index itu dan user tidak menulis `index=` | Minta user menulis `index=` eksplisit; periksa default role |
| `srchFilter` bocor di `tstats` | Jalur data model terakselerasi tidak terfilter | Uji jalur bagian 2.2; pisahkan index bila data benar-benar sensitif |
| Dashboard bekerja untuk pembuatnya saja | Knowledge object masih private | Cek sharing objek; untuk SHC pastikan replikasi (Day 43) |
| Analyst tidak bisa menjalankan scheduled search | Capability `schedule_search` tidak ada di role | Periksa daftar capability role di UI atau `authorize.conf` |
| Data sensitif muncul di summary index | `collect` dari index terbatas ke index yang lebih longgar | Deteksi dengan bagian 2.5; perketat izin index summary |
| Akun layanan punya akses sangat luas | Dibuat sekali lalu tidak ditinjau | Tinjau semua akun layanan; batasi per kebutuhan, aktifkan audit |
| Token lama masih berfungsi setelah orang keluar | Token tidak dicabut saat offboarding | Tinjau daftar token; masukkan pencabutan ke prosedur offboarding |
| `mstats` atau `mpreview` tidak jalan di index tertentu | Index itu punya field filter, dan kedua command dimatikan secara default di sana | Cek daftar field filter di Splunk Web; bila perlu, beri pengecualian filter atau capability `run_commands_ignoring_field_filter` setelah dinilai risikonya (bagian 1.4) |

## 5. Kesalahan umum dan jebakan

- Memberi role `admin` ke analyst supaya cepat, lalu kehilangan pemisahan tugas sepenuhnya.
- Mengandalkan `srchFilter` sebagai batas keamanan untuk data yang benar-benar sensitif.
- Mengira masking melindungi data lama, padahal hanya berlaku untuk data yang masuk setelahnya (Day 28).
- Lupa bahwa lookup, summary index, dan dashboard tersimpan adalah salinan data dengan izin baru.
- Mengira field filter melindungi semua jalur, padahal lookup tidak terlindungi dan `tstats` mengabaikan filter atas `_raw`.
- Mempersempit akses tanpa menyiapkan jalur akses sementara untuk insiden, sehingga lahir akun bersama.
- Memberi akses `_audit` dan `_internal` tanpa menjelaskan bahwa isinya memuat query orang lain.
- Tidak pernah meninjau akun layanan dan token, yang biasanya paling lama hidup dan paling luas izinnya.
- Mencatat keputusan akses hanya di chat, sehingga tidak ada jejak saat ditanya enam bulan kemudian.

## 6. Catatan terkini

- Mekanisme role, capability, dan `srchIndexesAllowed` sudah lama stabil di Splunk Enterprise. Yang berubah bertahap adalah jumlah capability bawaan (bertambah setiap kali ada fitur baru) dan nama role di app seperti ES.
- Di ES 8, izin untuk mengubah detection, menjalankan adaptive response, dan mengelola threat intelligence diatur lewat role ES tersendiri. Petakan role ES ke peran kerja timmu dan catat hasilnya, karena nama role ES berubah antar versi [S2].
- Untuk Splunk Cloud, pengelolaan role ada di Admin Config Service atau UI, dan sebagian setting tidak bisa disentuh pelanggan. Prinsip pemisahan index tetap sama.
- Splunk Enterprise 10.6 memuat field filter untuk menyamarkan field per role saat search [S5]. Materi lama yang menyebut Splunk tidak punya kontrol tingkat field sudah tidak berlaku untuk versi ini. Daftar command yang dibatasi dan perilaku `tstats` di halaman dokumentasi berbeda antar versi, jadi cek halaman "Plan for field filters in your organization" untuk versi instance-mu sebelum merancang di atasnya [S6] [S7].
- Autentikasi modern (SAML dengan grup, SCIM untuk provisioning) membuat pemetaan grup direktori ke role Splunk menjadi titik kontrol yang penting. Salah petakan grup di sini membatalkan seluruh rancangan role.

## 7. Cheat sheet

```
LAPIS     authentication -> role -> capability -> izin index dan objek
AKUMULATIF banyak role = gabungan izin ; mempersempit berarti mencabut role, bukan menambah role sempit
INDEX     srchIndexesAllowed (batas kuat) | srchIndexesDefault (tanpa index= di search)
BATAS     srchTimeWin (rentang maks) | srchJobsQuota | rtSrchJobsQuota=0 untuk role biasa | srchDiskQuota
FILTER    srchFilter = field=value  -> menyaring EVENT, bukan field ; uji juga tstats, summary, lookup
FIELD     field filter: hapus | ganti string | hash SHA-256/512 saat search ; pengecualian per role lewat UI/REST
          mpreview dan mstats mati di index berfilter ; tstats hanya patuh filter indexed field ; lookup tidak terlindungi
CAPABILITY awas: admin_all_objects, edit_user, edit_roles, edit_indexes, run_script, rtsearch, delete_by_keyword
SENSITIF  jangan kirim > mask saat index (Day 28) > pisah index > batasi role ; hasil search = salinan data baru
AUDIT     index=_audit action=search info=completed | stats BY user ; action IN (edit_user,edit_roles)
INVENTARIS | rest /services/authorization/roles  dan  /services/authentication/users
SEMENTARA role temporer + tabel pencatat + alert kedaluwarsa + dicatat di laporan insiden
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Seorang analyst baru sebelumnya memegang role `soc_investigator`. Supaya aksesnya sempit selama masa percobaan, kamu menambahkan role `soc_triage` (`srchTimeWin` 30 hari, tanpa `idx_dns`) ke akunnya. Keesokan harinya ia masih bisa menjalankan search 90 hari dan mencari di `idx_dns`. Apa yang salah, dan bagaimana membuktikannya?

<details><summary>Jawaban</summary>

Izin di Splunk bersifat akumulatif: user dengan beberapa role mendapat gabungan izin semua role-nya, jadi menambahkan role sempit ke user yang sudah memegang role luas tidak mempersempit apa pun. Pembatasan baru nyata bila `soc_investigator` dicabut dari akun itu, sehingga yang tersisa hanya `soc_triage`. Buktinya dibaca dari `| rest /services/authentication/users | search title="<nama_user>" | table title roles`, yang memperlihatkan semua role yang masih dipegang. Uji ulangnya dilakukan dengan akun itu sendiri, bukan dengan akun admin: search ke index yang tidak diizinkan harus kosong, dan search 90 hari harus dipotong atau ditolak sesuai `srchTimeWin`. Lihat bagian 1.1 dan 2.1.

</details>

**2. Skenario keputusan.** Index `idx_app` berisi data beberapa unit bisnis. Satu unit menyimpan rekaman transaksi berisi nomor rekening, dan nilai itu perlu utuh untuk investigasi penipuan. Tim aplikasi tiap unit hanya boleh melihat data unitnya sendiri. Rancangan mana yang kamu pilih?

- A. Pasang `srchFilter = business_unit=<unit>` per role tim, lalu buktikan dengan `index=idx_app | stats count BY business_unit` dari akun uji.
- B. Pindahkan data unit yang memuat nomor rekening ke index terpisah lewat routing berdasarkan isi, buka index itu hanya ke role yang berhak lewat `srchIndexesAllowed`, dan pakai `srchFilter` hanya untuk pemisahan ringan sisanya setelah diuji di tiga jalur.
- C. Mask nomor rekening dengan `SEDCMD` saat index, lalu buka `idx_app` ke semua tim.

<details><summary>Jawaban</summary>

B. Data yang benar-benar sensitif dan perlu tetap utuh dipisahkan ke index sendiri, karena index terpisah dengan `srchIndexesAllowed` adalah batas akses yang paling kuat di Splunk; `srchFilter` di atasnya cukup untuk pemisahan ringan, dengan syarat lolos uji jalur normal, data model terakselerasi, serta summary index dan lookup. A keliru karena `srchFilter` menyaring event, bukan field, bisa berperilaku tidak terduga bila bergantung pada field hasil ekstraksi search-time, dan jalur seperti `tstats`, summary index, dan lookup adalah tempat kebocoran paling sering; satu uji `stats count BY business_unit` hanya membuktikan jalur normal. C keliru karena masking tidak bisa dibuka lagi dan hanya berlaku untuk data yang masuk setelahnya, sehingga data lama tetap terbuka dan investigasi penipuan kehilangan nilai yang dibutuhkannya. Lihat bagian 1.3, 1.6, dan 2.2.

</details>

**3. Pertanyaan jebakan.** `idx_sensitif` hanya bisa dibaca role `soc_investigator`. Seorang engineer membuat saved search harian yang meringkas index itu lalu menulis hasilnya ke lookup dengan `outputlookup`, dan lookup itu dibagikan global supaya dashboard tim lain bisa memakainya. Izin index-nya tidak berubah sama sekali. Apakah datanya tetap terlindungi?

<details><summary>Jawaban</summary>

Tidak. Hasil search juga data: setiap `outputlookup` atau `collect` membuat salinan dengan model izin baru, dan lookup yang dibagikan global bisa dibaca orang yang tidak pernah punya akses ke `idx_sensitif`. Ini kebocoran paling umum dan paling tidak disengaja di Splunk, dan izin index yang tidak berubah justru membuatnya tidak terlihat. Cara menemukannya adalah `| rest /services/saved/searches` yang menyaring search berisi `outputlookup` atau `collect`, lalu membandingkan `eai:acl.sharing` dan `eai:acl.perms.read` dengan izin index sumbernya. Perbaikannya mempersempit sharing lookup, dan hal yang sama berlaku untuk summary index, dashboard tersimpan, dan ekspor CSV. Lihat bagian 1.6 dan 2.5.

</details>

**4. Jelaskan ulang.** Auditor internal PT JAB meminta bukti review akun admin dan bertanya siapa saja yang bisa melihat index `wineventlog`. Jelaskan, dalam tiga kalimat, apa yang kamu tunjukkan sebagai bukti.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh jawaban: "Akses Splunk kami diberikan per role sesuai tugas (triage, investigator, engineer), dan siapa yang bisa melihat sebuah index ditentukan oleh `srchIndexesAllowed` di role itu, jadi tabel dari `| rest /services/authorization/roles` ditambah daftar role per user dari `| rest /services/authentication/users` menjawab pertanyaan Bapak/Ibu secara langsung. Tabel itu kami simpan setiap kali ada perubahan, sehingga review berkala bisa dibandingkan dari waktu ke waktu, termasuk untuk akun layanan dan token yang biasanya paling lama hidup. Perubahan user dan role, serta setiap search yang dijalankan beserta teksnya, tercatat di `index=_audit`, jadi kami bisa menunjukkan siapa mengubah izin dan siapa mencari data apa."

Kesalahan yang sering muncul: menunjuk `srchFilter` sebagai batas keamanan, padahal ia hanya pemisahan ringan; menunjukkan dokumen kebijakan tanpa tabel konfigurasi yang benar-benar berlaku; melupakan bahwa izin akumulatif, sehingga daftar role saja tidak cukup tanpa daftar role per user; dan menyajikan teks search dari `_audit` sebagai bukti tunggal, padahal teks itu bisa terpotong untuk search yang sangat panjang dan search dari dashboard muncul dalam bentuk yang sudah diekspansi. Lihat bagian 1.1, 1.7, 2.3, dan 2.4.

</details>

**5. Interview question (English).** "How would you set up Splunk access for a SOC team so that sensitive data is protected but investigations are not blocked?"

<details><summary>Sample answer</summary>

"I start from the index design rather than from roles, because in Splunk the only strong boundary is a separate index granted per role through srchIndexesAllowed. Data that is genuinely sensitive but needs to stay intact for investigations goes into its own index; values that never need to be read in clear, like card numbers or passwords, are masked at index time, knowing that masking only applies to new data. Where only one or two fields in otherwise useful events are sensitive, field filters can hash or redact them at search time with an exemption for investigators, but I test them against tstats and remember that lookups are not covered. On top of that I would define three roles that match the work: triage with core detection indexes, a thirty-day search window and no real-time searches; investigator with all operational indexes and no time limit, because investigations often need to look far back; and engineer with access to _internal and _audit to diagnose skipped searches, but without capabilities that change indexes or inputs. I keep powerful capabilities like admin_all_objects, edit_roles and run_script away from analyst roles. I treat srchFilter as a convenience for light separation, not a security control, and I test it against accelerated data models, summary indexes and lookups, because that is where it usually leaks. I also watch for derived copies, since every outputlookup or collect creates data with a new permission model. Finally, I make sure there is a fast, documented path for temporary access during an incident, with an expiry date and a scheduled search that alerts when access outlives it, because if that path does not exist, people end up sharing accounts, which is far worse."

What makes this answer strong: it names the strongest control first and explains why the weaker ones are still useful, it ties each role to the work it supports instead of to seniority, and it closes the loop on the most common real-world failure, which is restrictions so tight that people work around them.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Securing Splunk Enterprise: "About configuring role-based user access", "Add and edit roles with authorize.conf", spesifikasi `authorize.conf` | https://help.splunk.com/en/splunk-enterprise | primer | judul halaman dirujuk 2026-10-09 | Tinggi untuk nama setting. URL menunjuk ke situs dokumentasi; cari halaman dari judulnya. Daftar capability bergantung versi |
| S2 | Splunk Enterprise Security 8.7: administer guide bagian role dan izin ES | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7 | primer | dirujuk 2026-10-09 | Tinggi. Nama role ES berbeda antar versi, cek daftar di instance |
| S3 | Securing Splunk Enterprise: "Audit Splunk activity" dan daftar event di `index=_audit` | https://help.splunk.com/en/splunk-enterprise | primer | judul halaman dirujuk 2026-10-09 | Tinggi untuk konsep; nama field audit bisa berbeda antar versi |
| S4 | Splunk-Notes Day 28 (masking dan routing index-time), Day 43 (kuota search dan knowledge object), Day 40 (summary dan lookup sebagai salinan data), Day 33 (alur investigasi) | (lokal) | rujukan internal | 2026-10-09 | Keterkaitan antar Day |
| S5 | Splunk Enterprise 10.6 Securing Splunk: "Protect PII, PHI, and other sensitive data with field filters" | https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.6/use-field-filters-to-protect-sensitive-data | primer | diperbarui 2026-09-09, diakses 2026-10-15 | Tinggi. Fungsi field filter, tiga cara menyamarkan, pengecualian role, data index tidak berubah, lookup tidak terlindungi, peringatan untuk ES dan data model terakselerasi |
| S6 | Splunk Enterprise 10.6: "READ THIS: Restricted commands do not work in searches on indexes that have field filters" | https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.6/use-field-filters-to-protect-sensitive-data/plan-for-field-filters-in-your-organization/read-this-restricted-commands-do-not-work-in-searches-on-indexes-that-have-field-filters | primer | diperbarui 2026-09-09, diakses 2026-10-15 | Tinggi. Daftar command terbatas di 10.6 dan capability `run_commands_ignoring_field_filter` |
| S7 | Splunk Enterprise 10.6: "Support for tstats in searches on indexes with field filters" | https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.6/use-field-filters-to-protect-sensitive-data/use-field-filters-in-searches/support-for-tstats-in-searches-on-indexes-with-field-filters | primer | diperbarui 2026-09-09, diakses 2026-10-15 | Tinggi. `tstats` hanya mematuhi filter indexed field; pembatasan host, source, sourcetype tidak selalu ditegakkan |
| S8 | Splunk Enterprise Admin Manual 10.4.3: spesifikasi `field_filters.conf` | https://help.splunk.com/en/data-management/splunk-enterprise-admin-manual/10.4/configuration-file-reference/10.4.3-configuration-file-reference/field_filters.conf | primer | diakses 2026-10-15 | Tinggi untuk nama setting; versi spesifikasi 10.4.3, cek ulang di 10.6. Cakupan per index dan host/source/sourcetype, operator `null()`, hash, string, `sed`, `roleExemptions` yang dibuat otomatis oleh UI atau REST |

**Catatan sumber:** daftar capability dan nama role bawaan bertambah atau berubah antar versi, jadi dua hal itu selalu dicek di instance sendiri lewat UI atau `| rest /services/authorization/roles`. Perilaku `srchFilter` terhadap data model terakselerasi, summary index, dan lookup perlu diuji sendiri di lab karena inilah sumber kesalahan asumsi yang paling mahal di Day ini.
