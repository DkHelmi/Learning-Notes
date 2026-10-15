---
day: 17
title: 'Investigasi dengan EDR: advanced hunting KQL, process tree, live response, dan konsep lintas vendor'
researched_on: 2026-10-15
versions_checked: 'Microsoft Defender XDR, halaman Advanced hunting overview (ms.date 2026-08-07), Data tables in the advanced hunting schema (ms.date 2026-07-27), DeviceProcessEvents (ms.date 2026-08-07), DeviceImageLoadEvents, DeviceNetworkEvents, dan DeviceFileEvents (ms.date 2025-03-28); Microsoft Defender for Endpoint, halaman Investigate devices (ms.date 2026-07-23), Live response (ms.date 2026-07-28), Take response actions on a device (ms.date 2026-07-23); MITRE ATT&CK v20 (T1574.001 versi 3.0, T1189 versi 1.7); CrowdStrike Tech Center, Real Time Response (2 Mei 2024); CrowdStrike API reference, Real Time Response Admin; SentinelOne blog Rapid Threat Hunting with Storylines (diperbarui 27 Maret 2024) dan Remote Script Orchestration (diperbarui 28 April 2025)'
---

# Day 17: Investigasi dengan EDR (advanced hunting KQL, process tree, live response, dan konsep lintas vendor)

Cakupan: memakai EDR untuk memastikan sebuah alert, membaca process tree dan timeline perangkat, memperluas pencarian dari satu perangkat ke seluruh fleet dengan advanced hunting, memahami kualitas dan retensi telemetry, memakai live response untuk konfirmasi tanpa mengambil perangkat, menempatkan EDR sebagai alat investigasi dan bukan pengganti bukti, dan menerjemahkan konsep yang sama ke CrowdStrike Falcon dan SentinelOne.

## Ide inti

EDR mencatat jauh lebih banyak daripada yang ia alertkan. Alert hanya sebagian kecil telemetry yang kebetulan cocok dengan aturan deteksi; di belakangnya ada telemetry setiap proses, file, koneksi, DLL yang dimuat, dan logon di setiap perangkat yang terpasang sensor. Investigasi dengan EDR berarti memakai telemetry itu untuk tiga hal secara berurutan: memastikan apa yang sebenarnya terjadi di perangkat yang alert, mencari tanda yang sama di semua perangkat lain, lalu mengonfirmasi temuan langsung di perangkat lewat live response. Hasil terpentingnya sering bukan perangkat yang alert, tetapi perangkat lain yang tidak alert sama sekali.

Kamu sudah mengenal pola ini dari NOC. Alarm NMS hanya berbunyi bila ambang terlewati, tetapi NetFlow dan syslog dari semua perangkat tetap tercatat di collector walau tidak ada alarm. Saat satu router alarm karena trafik aneh, engineer yang berpengalaman tidak berhenti di router itu: ia mencari pola trafik yang sama di collector untuk semua perangkat, lalu masuk ke perangkat yang dicurigai lewat console untuk memastikan. Bedanya di EDR: collector-nya hanya menyimpan data mentah dalam jendela waktu terbatas, dan perangkat tanpa sensor sama sekali tidak terlihat.

```
alert di satu perangkat
  |
  v
pastikan: process tree + timeline perangkat   -> true positive? apa yang terjadi?
  |
  v
ambil sinyal yang khas: hash, path, domain, nama task, perilaku
  |
  v
advanced hunting ke seluruh fleet (maks 30 hari data mentah)
  |
  +-- perangkat lain dengan sinyal sama, termasuk yang TIDAK alert
  +-- aktivitas lanjutan (discovery, logon ke host lain)
  |
  v
live response di perangkat terpilih: konfirmasi, ambil file
  |
  v
scope statement -> containment (Day 05) -> query jadi custom detection
```

Situasi yang dipakai sepanjang Day ini adalah `INC-2026-026` di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif yang memakai Microsoft Defender for Endpoint Plan 2 di server Windows dan workstation Jakarta serta Bandung. Senin 7 Desember 2026 pukul 10:31 WIB, Defender mengeluarkan alert `SOC-2026-0270` di laptop `JKT-WS-0452` milik `dian.permata` (staf Marketing Jakarta): proses bertanda tangan `pdfupdater.exe` memuat DLL tidak bertanda tangan dari folder profil pengguna, lalu terhubung ke internet. Analyst L1 Gilang Ramadhan mengeskalasi ke L2 Rudi Hartanto pukul 10:45. Rudi memastikan alert itu benar pukul 10:58, dan SOC lead Dimas Prasetyo menyatakan insiden SEV-3 pukul 11:05 dengan Rudi sebagai technical lead. Pukul 11:10, Dimas menulis di kanal `#inc-2026-026`:

> "Rud, sebelum saya putuskan containment, saya perlu tahu beberapa hal. Kamu yakin ini bukan false positive, cuma aplikasi PDF yang aneh? Apa sebenarnya yang terjadi di laptop Dian, urut dari awal? Ada laptop lain yang kena, padahal alert-nya cuma satu? Seberapa jauh ke belakang data Defender bisa kita lihat, dan kalau ada laptop yang kena tapi tidak alert, kenapa bisa begitu? Bisa dipastikan langsung di laptopnya tanpa harus ambil laptop? Kalau nanti dipakai untuk laporan ke manajemen atau auditor, data EDR cukup jadi bukti? Satu lagi, Pak Hendra tanya: kalau tahun depan kita pindah ke CrowdStrike atau SentinelOne, cara kerja seperti ini masih bisa?"

Pesan itu memuat tujuh pertanyaan:

1. Alert ini true positive atau false positive?
2. Apa yang terjadi di laptop Dian, berurutan?
3. Ada perangkat lain yang terdampak walau tidak alert?
4. Seberapa jauh data bisa dilihat, dan kenapa ada perangkat yang kena tanpa alert?
5. Bisakah dipastikan langsung di perangkat tanpa mengambilnya?
6. Apakah data EDR cukup sebagai bukti?
7. Apakah cara kerja ini berlaku di EDR lain?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, pertanyaan 6 di bagian 1.6, dan pertanyaan 7 di bagian 1.7. Bagian 2 berisi query, sesi live response, dan update scope yang dibuat Rudi hari itu.

**Kapan relevan:** setiap kali alert EDR perlu dipastikan dan di-scope, saat mencari perangkat lain dengan indikator atau perilaku yang sama, dan saat menyiapkan query hunting, custom detection, dan library skrip live response sebelum insiden.
**Kapan bukan jawaban:** EDR tidak melihat perangkat tanpa sensor, server Linux yang belum di-onboard, perangkat jaringan, atau layanan cloud; sumber lain (log Splunk, firewall, proxy) tetap dibutuhkan. Day ini juga tidak mengulang pengambilan bukti dengan paket investigasi (Day 04 bagian 1.3) dan isolasi perangkat (Day 05 bagian 1.4).

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (alert, triage, severity, scoping, pivot, IOC, live response, paket investigasi, isolasi host, scope statement) tidak diulang. Tabel berikut memuat istilah baru Day ini. Kolom padanan memakai analogi NOC dan SOC yang sama di semua Day IR.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Telemetry EDR | Catatan mentah aktivitas perangkat (proses, file, jaringan, registry, logon, DLL) yang dikirim sensor, terlepas dari ada alert atau tidak | NetFlow dan syslog yang tetap tercatat walau alarm NMS tidak berbunyi |
| Advanced hunting | Fitur query Defender XDR berbahasa KQL atas data mentah, maksimal 30 hari ke belakang | Query terpusat di collector NetFlow untuk semua perangkat |
| KQL | Kusto Query Language, bahasa query yang dipakai advanced hunting | Bahasa query di collector atau SIEM, mirip SPL di Splunk |
| Process tree | Hubungan induk dan anak antar proses yang menunjukkan siapa menjalankan apa | Urutan perintah dalam satu sesi di log TACACS accounting |
| Device timeline | Daftar kronologis event dan alert di satu perangkat di portal Defender | Log kronologis satu perangkat di NMS |
| Prevalence | Berapa banyak perangkat yang memiliki file, hash, atau perilaku yang sama | Berapa banyak perangkat yang menjalankan versi firmware yang sama |
| DLL side-loading | Aplikasi sah dibuat memuat DLL buatan penyerang yang ditaruh di folder yang sama | Perangkat sah yang memuat modul konfigurasi palsu dari slot yang salah |
| Custom detection | Query hunting yang dijadwalkan berjalan otomatis dan membuat alert | Ambang alarm NMS baru yang dibuat dari temuan gangguan |
| Retensi telemetry | Berapa lama data mentah bisa di-query sebelum hilang | Buffer log perangkat yang berputar dan menimpa data lama |

### 1.1 Alert bukan insiden: memastikan dulu, lalu memutuskan

Pertanyaan pertama Dimas adalah pekerjaan triage, dan jawabannya tidak boleh berhenti di judul alert. Judul alert hanya menyebut aturan yang terpicu; yang dinilai adalah rangkaian event di sekitarnya.

Halaman investigasi perangkat Defender mengurutkan pekerjaan analis: buka detail perangkat, lihat alert aktif dan pengguna yang login, analisis timeline termasuk process tree, periksa alert dan insiden terkait, nilai postur keamanan, cek paparan jaringan, lalu ambil tindakan respons [S6]. Dari urutan itu, Rudi memakai empat pertanyaan untuk memutuskan true positive atau false positive:

1. **Dari mana file datang?** File yang diunduh browser dari domain yang tidak dikenal berbeda dengan file yang dipasang tim IT lewat software distribution. `DeviceFileEvents` mencatat URL asal unduhan, referrer, dan IP asal [S2].
2. **Siapa menjalankan apa?** Process tree menunjukkan apakah aplikasi dijalankan pengguna dari folder unduhan atau oleh sistem manajemen perangkat.
3. **Apa yang dimuat dan dihubungi?** DLL yang dimuat dari folder yang bisa ditulis pengguna, dan koneksi berkala ke domain baru, adalah dua tanda yang jarang muncul bersamaan pada aplikasi sah.
4. **Seberapa umum?** File atau perilaku yang ada di ratusan perangkat yang dikelola biasanya sah; yang hanya ada di satu atau dua perangkat perlu dijelaskan.

Di `JKT-WS-0452`, keempat jawaban mengarah ke satu kesimpulan: file diunduh dari situs tiruan aplikasi PDF lewat iklan pencarian, dijalankan Dian dari folder unduhan, memuat `version.dll` tidak bertanda tangan dari folder `AppData\Local\PDFSuite`, dan terhubung ke domain yang belum pernah dihubungi perangkat lain di PT JAB. Tim IT tidak pernah mendistribusikan aplikasi itu. True positive.

Satu hal yang membedakan alert dari insiden: alert adalah keputusan mesin, insiden adalah keputusan orang. Rudi memastikan alert pukul 10:58, tetapi insiden baru dinyatakan Dimas pukul 11:05 dengan severity dan pemiliknya. Rentang tujuh menit itu bukan birokrasi; di situlah severity awal dipilih dan peran dibagi.

### 1.2 Process tree dan timeline: membaca urutan, bukan satu baris

Pertanyaan kedua Dimas ("apa yang terjadi, urut dari awal?") dijawab dengan process tree dan timeline perangkat, bukan dengan satu event yang memicu alert.

Device timeline menampilkan event dan alert secara kronologis, bisa dipersempit ke rentang waktu tertentu, menandai teknik ATT&CK pada event, menampilkan process tree saat event dipilih, dan menyediakan tombol untuk membuka advanced hunting berisi event di sekitar waktu yang sama di perangkat itu. Event penting bisa diberi flag untuk menyusun timeline kejadian yang bersih, dan timeline bisa diekspor untuk rentang maksimal tujuh hari [S6]. Di advanced hunting, hubungan induk dan anak dibaca dari kolom `InitiatingProcess*` di setiap tabel: `DeviceProcessEvents` mencatat proses yang dibuat beserta proses yang membuatnya dan induk dari proses itu [S3].

Membaca process tree berarti menjawab tiga hal untuk setiap simpul:

- **Siapa induknya, dan apakah wajar?** `explorer.exe` menjalankan installer dari folder `Downloads` artinya pengguna mengklik file itu. `pdfupdater.exe` menjalankan `cmd.exe` bukan perilaku updater biasa.
- **Dari mana image-nya?** Program yang berjalan dari `AppData\Local` milik pengguna, bukan dari `Program Files`, berarti dipasang tanpa hak admin, sering di luar distribusi resmi.
- **Akun dan waktu apa?** Akun yang menjalankan dan waktu pembuatan proses menghubungkan pohon ke sesi pengguna tertentu.

Pola yang dilihat Rudi di `JKT-WS-0452` cocok dengan DLL side-loading. ATT&CK v20 memasukkan side-loading ke dalam T1574.001 (DLL): penyerang menaruh DLL berbahaya lalu menjalankan aplikasi sah yang akan memuatnya, dan deteksinya mencari pemuatan DLL dari direktori yang tidak standar serta perilaku DLL yang tidak wajar di proses tepercaya [S9]. Pintu masuknya adalah unduhan dari iklan, yang di ATT&CK masuk ke T1189 Drive-by Compromise, termasuk malvertising lewat penyedia iklan sah dan pembaruan software palsu [S10].

Perhatian soal waktu: advanced hunting menyimpan dan menerima query dalam UTC, sedangkan hasil di portal dikonversi ke zona waktu yang diatur pengguna [S1]. WIB adalah UTC + 7 jam. Di catatan insiden PT JAB semua waktu ditulis WIB, sehingga setiap rentang di query harus dikonversi dulu.

### 1.3 Dari satu perangkat ke seluruh fleet

Pertanyaan ketiga Dimas ("ada laptop lain?") adalah alasan utama memakai advanced hunting. Alert hanya muncul di perangkat yang cocok dengan aturan deteksi pada saat itu; telemetry tercatat di semua perangkat bersensor.

Prinsip pivot sama dengan Day 03 bagian 1.3: ambil sinyal yang khas dari perangkat pertama, lalu cari di semua sumber. Bedanya, di EDR satu query bisa mencari banyak jenis sinyal sekaligus di semua perangkat. Rudi memakai sinyal dari tiga lapis, dari yang paling mudah diganti penyerang sampai yang paling sulit:

| Lapis | Sinyal di `INC-2026-026` | Tabel advanced hunting | Kelemahan |
|---|---|---|---|
| Infrastruktur | Domain unduhan `pdf-suite-download.example.net`, domain C2 `cdn.pdfsuite-update.example.net`, IP `198.51.100.37` | `DeviceFileEvents` (asal unduhan), `DeviceNetworkEvents` | Diganti murah dan cepat |
| File | SHA1 `version.dll`, nama folder `AppData\Local\PDFSuite` | `DeviceImageLoadEvents`, `DeviceFileEvents` | Hash berubah setiap build |
| Perilaku | Proses bertanda tangan memuat DLL tak bertanda tangan dari profil pengguna, lalu menjalankan `cmd.exe` | `DeviceImageLoadEvents`, `DeviceProcessEvents` | Butuh baseline supaya tidak banjir hasil |

Tabel ini dibaca dari kolom kanan: sinyal infrastruktur dan file menemukan kampanye yang sama dengan cepat, sedangkan sinyal perilaku menemukan varian berikutnya yang sudah berganti domain dan hash. Rudi menjalankan ketiganya, dan hasil (bagian 2.3) menunjukkan tiga perangkat: `JKT-WS-0452` milik Dian, `BDG-WS-0163` milik `bima.ardiansyah` (staf Sales Bandung) yang menjalankan file yang sama sejak Jumat 4 Desember tanpa satu pun alert, dan `JKT-WS-0455` milik `nadia.safitri` yang mengunduh file itu Senin pagi tetapi belum membukanya.

Penemuan `BDG-WS-0163` langsung diikuti pertanyaan berikutnya: apa yang terjadi di sana selama tiga hari? Query process tree di perangkat itu (bagian 2.4) menunjukkan `pdfupdater.exe` menjalankan `cmd.exe` Senin pukul 08:10 WIB, diikuti perintah discovery domain. Itu bukan perilaku malware otomatis biasa, melainkan tanda ada orang yang mengetik di ujung lain. Dimas menaikkan severity ke SEV-2 pukul 11:40.

### 1.4 Telemetry punya batas: retensi, cakupan sensor, dan alert yang tidak muncul

Pertanyaan keempat Dimas punya dua bagian, dan keduanya menyangkut batas data.

**Seberapa jauh ke belakang.** Advanced hunting bisa meng-query data mentah Defender XDR sampai 30 hari ke belakang; setiap query juga dibatasi 100.000 baris hasil, 64 MB ukuran hasil, dan 10 menit waktu jalan [S1]. Untuk menyimpan lebih lama, tabel hunting harus dialirkan ke workspace Microsoft Sentinel atau diekspor lewat streaming API, dan retensi itu baru berlaku sejak streaming diaktifkan, tidak mundur ke belakang [S1]. Halaman investigasi perangkat menyebut timeline perangkat menampilkan 30 hari terakhir secara default, dan retensi data perangkat mengikuti pengaturan retensi tenant [S6]; cek nilai yang berlaku di tenant-mu di pengaturan Defender. Konsekuensinya untuk PT JAB: kampanye yang dimulai lebih dari 30 hari lalu hanya bisa dilacak lewat log Splunk (proxy, DNS, firewall) yang retensinya lebih panjang.

**Kenapa ada perangkat yang kena tanpa alert.** Alert lahir dari aturan deteksi yang cocok pada saat event diproses; telemetry tetap dikirim walau tidak ada aturan yang cocok. Di `INC-2026-026`, file yang sama berjalan di `BDG-WS-0163` hari Jumat tanpa alert, dan baru Senin aturan deteksi mengenali polanya di `JKT-WS-0452`. Ada juga alasan lain yang harus diperiksa setiap kali hasil hunting kosong:

- **Perangkat tanpa sensor atau sensor tidak sehat.** Perangkat yang belum di-onboard tidak punya telemetry sama sekali. Sensor juga bisa masuk mode kritis saat kekurangan sumber daya dan tidak memproses event baru sampai kembali normal; kejadian itu tercatat sebagai event di timeline perangkat [S6].
- **Data yang tidak dikumpulkan.** Event firewall Windows di timeline butuh kebijakan audit yang diaktifkan lebih dulu [S6]. Kolom tertentu juga sering kosong; misalnya `SHA256` di `DeviceProcessEvents` biasanya tidak terisi, sehingga pivot hash memakai `SHA1` [S3].
- **Tabel yang bergantung pada produk lain.** Tabel seperti `IdentityLogonEvents` dan `IdentityDirectoryEvents` berisi event autentikasi dan event domain controller [S8], dan advanced hunting mengambil data identitas itu dari Defender for Identity [S1]. PT JAB tidak memakai Defender for Identity, sehingga logon di DC dicari di log `wineventlog` di Splunk; cek sumber setiap tabel di schema reference portal sebelum menyimpulkan.

Jadi "tidak ditemukan di advanced hunting" baru berarti "tidak ada" setelah cakupan sensor, kesehatan sensor, dan rentang waktunya diperiksa. Rudi menulis batas ini di scope statement (bagian 2.6).

### 1.5 Live response: konfirmasi di perangkat, tanpa mengambil perangkat

Pertanyaan kelima Dimas ("bisa dipastikan langsung di laptopnya?") dijawab dengan live response. Day 04 bagian 1.3 sudah membahas perintah dan batasnya untuk pengambilan bukti; di sini fungsinya berbeda, yaitu mengonfirmasi hal yang tidak bisa dijawab telemetry.

Telemetry menunjukkan apa yang pernah terjadi; live response menunjukkan keadaan sekarang dan memberi akses ke file. Dokumentasi Defender menyebut live response sebagai shell jarak jauh untuk investigasi mendalam dan tindakan respons, dengan perintah dasar seperti `processes`, `connections`, `scheduledtasks`, `persistence`, `fileinfo`, `findfile`, dan `getfile`, serta perintah lanjutan seperti `analyze`, `run`, `library`, `putfile`, dan `remediate` yang hanya tersedia untuk peran tertentu [S7]. Skrip yang dijalankan dengan `run` harus diunggah dulu ke library di tingkat tenant, dan skrip PowerShell tidak bertanda tangan hanya bisa dijalankan bila pengaturannya diaktifkan, yang menurut dokumentasi menambah paparan risiko [S7].

Untuk `INC-2026-026`, live response menjawab tiga hal yang tidak ada di telemetry:

1. **Apakah proses dan scheduled task masih ada sekarang**, setelah hunting menunjukkan keduanya pernah dibuat.
2. **Isi file itu sendiri**, yang diambil dengan `getfile` untuk dianalisis retainer atau tim internal, dengan batas 3 GB per file [S7].
3. **Apakah ada yang tidak tercatat**, misalnya file lain di folder yang sama yang belum pernah dijalankan.

Setiap perintah tercatat di Command log sesi beserta ID, baris perintah, durasi, dan status [S7]. Catatan itu menjadi bukti tindakan responder, sama seperti case notes di Day 03 bagian 1.7. Batas lain yang memengaruhi rencana: satu perangkat hanya bisa berada di satu sesi, satu pengguna maksimal lima sesi bersamaan, dan sesi berakhir setelah 30 menit tidak aktif [S7]. Untuk tiga perangkat, Rudi dan Yoga membagi perangkat supaya tidak saling menunggu.

Perhatian: membatalkan perintah dengan Ctrl + C di portal hanya membatalkan di sisi portal; perintah yang mengubah perangkat, seperti `remediate`, bisa tetap berjalan di agen [S7]. Perintah yang mengubah perangkat tidak dijalankan sebelum keputusan containment.

### 1.6 EDR adalah alat investigasi, bukan bukti dengan sendirinya

Pertanyaan keenam Dimas ("cukup jadi bukti?") punya jawaban "cukup untuk keputusan, belum tentu cukup untuk pembuktian".

Telemetry EDR sangat baik untuk keputusan cepat: memastikan alert, menentukan scope, dan memilih containment. Tetapi ada tiga alasan kenapa data itu tidak menggantikan bukti yang diamankan dengan prosedur di Day 04:

- **Data berada di layanan pihak ketiga dan punya umur.** Advanced hunting hanya 30 hari [S1]; setelah itu data mentah hilang kecuali sudah diekspor. Hasil query yang tidak disimpan saat itu tidak bisa diulang bulan depan.
- **Data adalah ringkasan sensor, bukan salinan perangkat.** Telemetry mencatat event yang dipilih sensor; isi file, memori, dan artefak yang tidak dicatat sensor hanya bisa diperoleh dari perangkat. Kolom hash juga bisa kosong bila file terkunci, berada di penyimpanan jarak jauh, atau terkompresi [S2].
- **Query bisa salah.** Filter waktu yang keliru atau nama kolom yang salah menghasilkan "tidak ditemukan" yang tampak meyakinkan.

Karena itu PT JAB memperlakukan hasil EDR seperti artefak lain: hasil query yang dipakai untuk keputusan diekspor dan diberi nomor bukti, query-nya disimpan bersama rentang waktunya, file yang diambil dengan `getfile` di-hash dan dicatat di evidence log, dan perangkat yang mungkin dibutuhkan untuk analisis lanjutan diamankan dengan paket investigasi atau image sebelum di-reimage (Day 04 bagian 1.6).

### 1.7 Konsep yang sama di EDR lain

Pertanyaan terakhir Dimas datang dari Hendra, dan jawabannya: alurnya sama, nama dan sintaksnya berbeda. Analis yang paham konsep pindah vendor dalam hitungan minggu; yang hanya hafal menu Defender perlu mulai dari awal.

Tabel berikut memetakan konsep Day ini ke dua EDR lain yang sering muncul di lowongan L2 dan IR. Isinya hanya dari materi publik vendor; nama menu, lisensi, dan ketersediaan fitur harus dicek di dokumentasi resmi masing-masing sebelum dipakai.

| Konsep | Microsoft Defender for Endpoint | CrowdStrike Falcon | SentinelOne Singularity |
|---|---|---|---|
| Query telemetry seluruh fleet | Advanced hunting dengan KQL [S1] | Event Search; kurikulum resmi menyebut pencarian real-time dan retrospektif serta query kustom dengan Events Data Dictionary [S13] | Deep Visibility dengan query mirip subset SQL [S14] |
| Menghubungkan event satu rangkaian | Process tree dan `InitiatingProcess*` [S3][S6] | Process tree dari detection; kurikulum menyebut korelasi lewat hubungan proses [S13] | Storyline ID yang mengikat proses, file, dan event terkait dalam satu query [S14] |
| Shell jarak jauh ke perangkat | Live response [S7] | Real Time Response (RTR): melihat proses, aktivitas jaringan, menjalankan skrip [S11] | Remote Script Orchestration untuk skrip di banyak endpoint sekaligus [S15] |
| Skrip dan file yang disiapkan | Library, `run`, `putfile` [S7] | Custom script untuk `runscript` dan put-file untuk `put` [S12] | Script Library di RSO [S15] |
| Mencari per teknik ATT&CK | Teknik ATT&CK di device timeline [S6] | Bergantung pada detection dan query | Query dengan ID teknik ATT&CK [S14] |

Materi publik SentinelOne tahun 2019 juga menyebut fitur shell jarak jauh penuh (Remote Shell); ketersediaan dan lisensinya saat ini perlu dicek di dokumentasi SentinelOne. Yang tidak berubah antar vendor adalah urutan kerja di Ide inti: pastikan alert, baca rangkaian, cari di fleet, konfirmasi di perangkat, simpan hasilnya, dan ubah temuan menjadi deteksi.

## 2. Contoh artefak dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Query ditulis untuk advanced hunting Defender XDR; semua waktu di query dan keluaran memakai UTC (WIB = UTC + 7 jam), sesuai aturan advanced hunting [S1]. `DeviceName` di data nyata berisi FQDN, misalnya `jkt-ws-0452.corp.jab.example` [S3], sehingga query memakai `startswith`. Kolom `FolderPath` di contoh ditampilkan bersama nama file; cek bentuknya di tenant-mu.

### 2.1 Process tree `JKT-WS-0452`: dari unduhan sampai koneksi keluar

Query ini menjawab pertanyaan kedua Dimas untuk perangkat yang alert.

**Tujuan:** menyusun urutan proses yang dibuat di sesi Dian sekitar waktu alert, lalu melihat DLL non-sistem yang dimuat dan koneksi keluar dari proses yang dicurigai.

```kusto
let dev = "jkt-ws-0452";
let mulai = datetime(2026-12-07 03:15:00);
let selesai = datetime(2026-12-07 03:45:00);
DeviceProcessEvents
| where Timestamp between (mulai .. selesai)
| where DeviceName startswith dev
| where AccountName == "dian.permata"
| project Timestamp, InitiatingProcessFileName, FileName, FolderPath, ProcessCommandLine, SHA1
| order by Timestamp asc
```

Penjelasan tiap bagian:

- `let` menyimpan nama perangkat dan rentang waktu supaya query mudah diulang untuk perangkat lain. Rentang 03:15 sampai 03:45 UTC sama dengan 10:15 sampai 10:45 WIB.
- `InitiatingProcessFileName` dan `FileName` dibaca sebagai pasangan induk dan anak [S3].
- `AccountName` membatasi ke proses yang dijalankan atas nama Dian, sehingga proses sistem latar belakang tidak memenuhi hasil.

Keluaran ilustrasi (path dipersingkat):

```
Timestamp            InitiatingProcessFileName  FileName                FolderPath                                       ProcessCommandLine
2026-12-07 03:21:05  explorer.exe               PDFSuite_Setup_4.2.exe  ...\dian.permata\Downloads\PDFSuite_Setup_4.2\   "PDFSuite_Setup_4.2.exe"
2026-12-07 03:21:15  PDFSuite_Setup_4.2.exe     pdfupdater.exe          ...\dian.permata\AppData\Local\PDFSuite\         "pdfupdater.exe" /silent
2026-12-07 03:21:30  pdfupdater.exe             schtasks.exe            C:\Windows\System32\                             schtasks.exe /create /tn "PDFSuite Updater" /sc onlogon /tr [path pdfupdater.exe] /f
```

Lanjutan untuk proses yang dicurigai, dengan dua tabel lain:

```kusto
let dev = "jkt-ws-0452";
union
  (DeviceImageLoadEvents
   | where DeviceName startswith dev and InitiatingProcessFileName =~ "pdfupdater.exe"
   | where not(FolderPath startswith @"C:\Windows\")
   | project Timestamp, Jenis = "load_dll", Objek = FolderPath),
  (DeviceNetworkEvents
   | where DeviceName startswith dev and InitiatingProcessFileName =~ "pdfupdater.exe"
   | project Timestamp, Jenis = "koneksi", Objek = strcat(RemoteUrl, " ", RemoteIP, ":", tostring(RemotePort)))
| where Timestamp between (datetime(2026-12-07 03:20:00) .. datetime(2026-12-07 04:35:00))
| summarize Pertama = min(Timestamp), Terakhir = max(Timestamp), Jumlah = count() by Jenis, Objek
| order by Pertama asc
```

Keluaran ilustrasi:

```
Jenis     Objek                                                     Pertama              Terakhir             Jumlah
load_dll  C:\Users\dian.permata\AppData\Local\PDFSuite\version.dll  2026-12-07 03:21:15  2026-12-07 03:21:15       1
koneksi   cdn.pdfsuite-update.example.net 198.51.100.37:443         2026-12-07 03:22:00  2026-12-07 04:32:00      15
```

Cara membaca hasil:

- `explorer.exe` menjalankan installer dari folder `Downloads`: Dian mengklik file itu sendiri pukul 10:21 WIB. Installer lalu menjalankan `pdfupdater.exe` dari `AppData\Local`, yang langsung membuat scheduled task saat logon. Persistence terpasang 25 detik setelah klik.
- `pdfupdater.exe` memuat `version.dll` dari foldernya sendiri. Versi asli DLL itu ada di `C:\Windows\System32`; salinan di folder aplikasi yang dimuat lebih dulu adalah pola side-loading di T1574.001 [S9].
- Dua baris di query kedua berasal dari `DeviceImageLoadEvents`, yang mencatat DLL yang dimuat proses [S4], dan `DeviceNetworkEvents`, yang mencatat koneksi beserta `RemoteUrl`, `RemoteIP`, dan `RemotePort` [S5].
- Lima belas koneksi dari 03:22 sampai 04:32 UTC adalah satu koneksi setiap 5 menit selama 70 menit. Pola berkala seperti ini adalah beacon, bukan pengecekan pembaruan yang biasanya sekali saat aplikasi mulai.

**Variasi:** dari device timeline, pilih event `pdfupdater.exe` lalu "Hunt for related events" untuk membuka advanced hunting berisi event di sekitar waktu yang sama di perangkat itu [S6].

**Kapan gagal:** proses dijalankan dengan akun lain (misalnya `SYSTEM` lewat service), sehingga filter `AccountName` membuangnya. Bila hasil terlalu sedikit, hapus filter akun dan persempit waktunya.

### 2.2 Seberapa umum: prevalence dan tanda tangan

Query ini melengkapi pertanyaan pertama Dimas ("bukan cuma aplikasi PDF yang aneh?") dengan melihat seberapa umum DLL itu di seluruh fleet.

**Tujuan:** menghitung berapa perangkat memuat `version.dll` dari luar folder Windows, per hash dan per proses pemuat, beserta informasi tanda tangannya.

```kusto
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where FileName =~ "version.dll" and not(FolderPath startswith @"C:\Windows\")
| summarize Perangkat = dcount(DeviceId), Contoh = any(FolderPath), Pertama = min(Timestamp)
    by SHA1, InitiatingProcessFileName
| join kind=leftouter (
    DeviceFileCertificateInfo
    | summarize arg_max(Timestamp, IsSigned, Signer) by SHA1
  ) on SHA1
| project SHA1, InitiatingProcessFileName, Perangkat, IsSigned, Signer, Contoh, Pertama
| order by Perangkat asc
```

Penjelasan tiap bagian:

- `dcount(DeviceId)` menghitung perangkat unik; angka kecil berarti jarang.
- `DeviceFileCertificateInfo` berisi informasi sertifikat file yang ditandatangani [S8]. Dokumentasi `DeviceProcessEvents` memakai pola join yang sama lewat `SHA1` untuk mendapatkan informasi tanda tangan file [S3].
- `leftouter` mempertahankan baris yang tidak punya informasi sertifikat. Kolom kosong berarti tidak ada catatan sertifikat untuk hash itu, yang perlu dikonfirmasi dengan `fileinfo` di live response (bagian 2.5).

Keluaran ilustrasi:

```
SHA1         InitiatingProcessFileName  Perangkat  IsSigned  Signer                          Contoh                                                  Pertama
3f9c2b7e...  pdfupdater.exe                     2                                            C:\Users\bima.ardiansyah\AppData\Local\PDFSuite\...    2026-12-04 08:05:10
8a41d0c3...  jabdocsync.exe                   214  true      PT Jaringan Anak Bangsa         C:\Program Files\JAB DocSync\version.dll               2026-11-08 01:12:44
```

Cara membaca hasil:

- Baris kedua adalah aplikasi internal PT JAB yang membawa `version.dll` sendiri, bertanda tangan, di 214 perangkat, terpasang dari `Program Files`. Pola folder aplikasi yang memuat DLL bernama sama dengan DLL sistem tidak otomatis berbahaya.
- Baris pertama hanya di dua perangkat, tanpa catatan sertifikat, dari profil pengguna, dan pertama kali muncul Jumat 4 Desember, tiga hari sebelum alert. Itu jawaban untuk Dimas: bukan aplikasi aneh, tetapi file yang sama di perangkat kedua yang belum diketahui.

**Kapan gagal:** penyerang memakai nama DLL lain untuk side-loading. Ganti filter `FileName` dengan pola perilaku: proses yang berjalan dari folder profil pengguna dan memuat DLL dari folder yang sama, lalu lihat prevalence-nya.

### 2.3 Pivot ke seluruh fleet dengan tiga lapis sinyal

Query ini menjawab pertanyaan ketiga Dimas: perangkat mana saja yang menyentuh kampanye ini, termasuk yang tidak alert.

**Tujuan:** dalam satu query, mencari unduhan dari domain kampanye, pemuatan DLL dengan hash yang sama, dan koneksi ke infrastruktur C2 di semua perangkat.

```kusto
let domain_unduh = "pdf-suite-download.example.net";
let domain_c2 = "pdfsuite-update.example.net";
let ip_c2 = "198.51.100.37";
let sha1_dll = "3f9c2b7e...";   // SHA1 lengkap dari bagian 2.2
union
  (DeviceFileEvents
   | where Timestamp > ago(30d) and FileOriginUrl has domain_unduh
   | extend Sinyal = "unduh_zip"),
  (DeviceImageLoadEvents
   | where Timestamp > ago(30d) and SHA1 == sha1_dll
   | extend Sinyal = "load_dll"),
  (DeviceNetworkEvents
   | where Timestamp > ago(30d) and (RemoteUrl has domain_c2 or RemoteIP == ip_c2)
   | extend Sinyal = "koneksi_c2")
| summarize Pertama = min(Timestamp), Terakhir = max(Timestamp), Jumlah = count() by DeviceName, Sinyal
| order by DeviceName asc, Pertama asc
```

Penjelasan tiap bagian:

- `FileOriginUrl` di `DeviceFileEvents` adalah URL asal file yang diunduh [S2]; perangkat yang mengunduh tetapi belum menjalankan file tetap terlihat di sini.
- `has` mencocokkan domain sebagai kata utuh di dalam URL, sehingga subdomain seperti `cdn.` ikut tertangkap.
- `union` menggabungkan tiga tabel dengan kolom berbeda; `summarize` merapikannya menjadi satu baris per perangkat per sinyal.

Keluaran ilustrasi (dijalankan pukul 04:35 UTC, nama perangkat dipersingkat):

```
DeviceName    Sinyal      Pertama              Terakhir             Jumlah
bdg-ws-0163   unduh_zip   2026-12-04 08:02:31  2026-12-04 08:02:31       1
bdg-ws-0163   load_dll    2026-12-04 08:05:10  2026-12-07 00:58:02       2
bdg-ws-0163   koneksi_c2  2026-12-04 08:06:02  2026-12-07 04:34:40      73
jkt-ws-0452   unduh_zip   2026-12-07 03:19:40  2026-12-07 03:19:40       1
jkt-ws-0452   load_dll    2026-12-07 03:21:15  2026-12-07 03:21:15       1
jkt-ws-0452   koneksi_c2  2026-12-07 03:22:00  2026-12-07 04:32:00      15
jkt-ws-0455   unduh_zip   2026-12-07 02:58:12  2026-12-07 02:58:12       1
```

Cara membaca hasil:

- `BDG-WS-0163` (Bima, Bandung) mengunduh dan menjalankan file yang sama Jumat 15:02 WIB. DLL dimuat dua kali: saat instalasi Jumat dan saat logon Senin 07:58 WIB, sesuai scheduled task saat logon. 73 koneksi C2 berasal dari dua periode laptop menyala: Jumat 08:06 sampai 10:26 UTC (140 menit, 29 koneksi) dan Senin 00:59:40 sampai 04:34:40 UTC (215 menit, 44 koneksi). Tidak ada alert di perangkat ini.
- `JKT-WS-0455` (Nadia) hanya mengunduh, tanpa `load_dll` dan tanpa koneksi. File ada di disk tetapi belum dijalankan; perangkat ini masuk scope untuk dibersihkan, bukan untuk diisolasi.
- Tidak ada perangkat lain. Kesimpulan ini dibatasi oleh cakupan sensor dan rentang 30 hari (bagian 1.4), sehingga Rudi juga menjalankan pencarian domain yang sama di index `proxy` dan `dns` Splunk untuk perangkat tanpa sensor. Hasilnya sama: tiga alamat IP yang cocok dengan tiga perangkat di atas.

**Variasi:** ganti lapis infrastruktur dan file dengan lapis perilaku dari bagian 1.3, yaitu proses di folder profil pengguna yang memuat DLL dari folder yang sama lalu terhubung ke domain yang belum pernah dilihat. Query itu lebih lambat dan lebih berisik, tetapi tetap bekerja saat penyerang mengganti domain dan hash.

**Kapan gagal:** perangkat dimatikan atau di luar jaringan dan belum mengirim telemetry, sehingga hasilnya terlambat. Jalankan ulang query yang sama beberapa kali selama insiden, bukan sekali.

### 2.4 Apa yang terjadi selama tiga hari di `BDG-WS-0163`

Query ini menindaklanjuti temuan bagian 2.3: perangkat yang sudah terinfeksi sejak Jumat perlu dicek apakah ada aktivitas di luar beacon.

**Tujuan:** melihat semua proses yang dijalankan `pdfupdater.exe` atau anaknya di `BDG-WS-0163` sejak infeksi.

```kusto
DeviceProcessEvents
| where DeviceName startswith "bdg-ws-0163"
| where Timestamp between (datetime(2026-12-04 08:00:00) .. datetime(2026-12-07 04:40:00))
| where InitiatingProcessFileName =~ "pdfupdater.exe"
     or InitiatingProcessParentFileName =~ "pdfupdater.exe"
| project Timestamp, InitiatingProcessFileName, FileName, ProcessCommandLine
| order by Timestamp asc
```

Penjelasan tiap bagian:

- Dua kondisi `or` menangkap anak langsung `pdfupdater.exe` dan cucu-nya, misalnya program yang dijalankan dari `cmd.exe` yang dibuka `pdfupdater.exe` [S3].
- Rentang dimulai Jumat sebelum infeksi pertama, sehingga semua aktivitas tercakup.

Keluaran ilustrasi:

```
Timestamp            InitiatingProcessFileName  FileName      ProcessCommandLine
2026-12-04 08:05:20  pdfupdater.exe             schtasks.exe  schtasks.exe /create /tn "PDFSuite Updater" /sc onlogon /tr [path] /f
2026-12-07 01:10:05  pdfupdater.exe             cmd.exe       cmd.exe
2026-12-07 01:10:07  cmd.exe                    whoami.exe    whoami /groups
2026-12-07 01:10:31  cmd.exe                    nltest.exe    nltest /domain_trusts
2026-12-07 01:11:02  cmd.exe                    net.exe       net group "domain admins" /domain
2026-12-07 01:11:40  cmd.exe                    net.exe       net view
2026-12-07 01:12:15  cmd.exe                    ipconfig.exe  ipconfig /all
```

Cara membaca hasil:

- Jumat hanya ada pembuatan scheduled task, sama dengan di laptop Dian.
- Senin 08:10 sampai 08:12 WIB, `pdfupdater.exe` membuka `cmd.exe` lalu menjalankan lima perintah pengenalan: grup akun, trust domain, anggota Domain Admins, daftar host di jaringan, dan konfigurasi IP. Updater aplikasi PDF tidak punya alasan menanyakan Domain Admins; ini tanda ada operator yang mengetik.
- Setelah 08:12 WIB tidak ada proses baru dari rantai ini sampai query dijalankan.

Pemeriksaan lanjutan untuk lateral movement memakai dua tabel lain dalam rentang yang sama:

```kusto
DeviceLogonEvents
| where Timestamp between (datetime(2026-11-07 00:00:00) .. datetime(2026-12-07 04:40:00))
| where AccountName == "bima.ardiansyah"
| summarize Jumlah = count(), Pertama = min(Timestamp), Terakhir = max(Timestamp)
    by DeviceName, LogonType, RemoteIP
```

Keluaran ilustrasi:

```
DeviceName    LogonType    RemoteIP     Jumlah  Pertama              Terakhir
bdg-ws-0163   Interactive                   22  2026-11-09 00:41:10  2026-12-07 00:57:51
bdg-ws-0163   Unlock                        61  2026-11-09 03:12:05  2026-12-07 03:55:20
jkt-fs01      Network      10.30.16.63      44  2026-11-09 00:43:02  2026-12-07 01:02:18
```

Cara membaca hasil: rentang 30 hari dipakai sebagai baseline. Akun Bima hanya login interaktif di laptopnya sendiri dan logon jaringan ke `JKT-FS01` dari IP laptopnya, pola yang sama setiap hari kerja sejak awal bulan (drive bersama tim Sales). Tidak ada logon ke perangkat lain setelah perintah discovery. Itu bukan bukti bahwa penyerang tidak mencoba; itu bukti bahwa tidak ada logon berhasil dengan akun Bima ke perangkat bersensor. Log DC di Splunk dicek terpisah untuk perangkat tanpa sensor.

**Kapan gagal:** penyerang memakai akun lain yang kredensialnya diambil dari laptop. Ulangi query dengan filter `RemoteIP == "10.30.16.63"` tanpa filter akun.

### 2.5 Live response di `JKT-WS-0452` dan `BDG-WS-0163`

Langkah ini menjawab pertanyaan kelima Dimas. Rudi memegang sesi `JKT-WS-0452`, Yoga memegang `BDG-WS-0163`, karena satu perangkat hanya bisa berada di satu sesi [S7]. Untuk `BDG-WS-0163`, Yoga lebih dulu mengambil paket investigasi dengan prosedur Day 04 bagian 2.2, karena ada aktivitas operator.

**Tujuan:** memastikan proses dan scheduled task masih ada, mengambil file untuk analisis, dan melihat isi folder yang tidak tercatat di telemetry.

```
processes -output json > inc026_jkt-ws-0452_processes.json
connections -output json > inc026_jkt-ws-0452_connections.json
scheduledtasks -output json > inc026_jkt-ws-0452_tasks.json
dir "C:\Users\dian.permata\AppData\Local\PDFSuite"
fileinfo "C:\Users\dian.permata\AppData\Local\PDFSuite\version.dll"
fileinfo "C:\Users\dian.permata\AppData\Local\PDFSuite\pdfupdater.exe"
getfile "C:\Users\dian.permata\AppData\Local\PDFSuite\version.dll"
getfile "C:\Users\dian.permata\AppData\Local\PDFSuite\update.dat"
getfile "C:\Windows\System32\Tasks\PDFSuite Updater"
```

Penjelasan tiap bagian:

- `-output json` dan redirection `>` menyimpan keluaran lengkap ke file, karena tampilan tabel menampilkan lebih sedikit kolom [S7].
- `dir` dan `fileinfo` hanya membaca; `getfile` mengunduh file ke analis, maksimal 3 GB per file [S7].
- Tidak ada `remediate`, `analyze`, atau `run` di tahap ini. `remediate` mengubah perangkat dan diputuskan di jam H; `analyze` dan `run` tidak dibutuhkan untuk konfirmasi.

Keluaran ilustrasi (diringkas):

```
> dir "C:\Users\dian.permata\AppData\Local\PDFSuite"
12/07/2026  10:21 AM      1,284,096  pdfupdater.exe
12/07/2026  10:21 AM        148,480  version.dll
12/07/2026  10:21 AM        512,016  update.dat

> fileinfo "...\pdfupdater.exe"     Signer: Northwind Media Tools Inc.   Is signed: true
> fileinfo "...\version.dll"        Signer: -                            Is signed: false

> connections (diringkas)
pdfupdater.exe  7724  10.10.45.52:51544  198.51.100.37:443  ESTABLISHED
```

Cara membaca hasil:

- `pdfupdater.exe` bertanda tangan vendor software sah (nama fiktif di contoh ini), sedangkan `version.dll` tidak bertanda tangan. Itu inti teknik side-loading: kepercayaan pada program yang sah dipinjam untuk menjalankan kode yang tidak sah [S9].
- `update.dat` tidak pernah muncul di telemetry karena tidak pernah dijalankan atau dimuat; isinya kemungkinan muatan yang dibaca DLL. File ini hanya ditemukan karena isi folder dilihat langsung.
- Koneksi ke `198.51.100.37:443` masih aktif saat sesi berjalan. Ketiga file diunduh, di-hash, dan dicatat sebagai `INC-2026-026-E01` sampai `-E03` di evidence log. Command log sesi diekspor sebagai catatan tindakan responder.

**Kapan gagal:** live response belum diaktifkan di pengaturan lanjutan, peran analis tidak punya izin perintah lanjutan, atau perangkat dalam sesi lain [S7]. Cek ketiganya saat menyiapkan on-call, bukan saat insiden.

### 2.6 Update scope ke IC dan menjadikan query sebagai deteksi

Update ini menutup pertanyaan keempat dan keenam Dimas: apa yang diketahui, sampai mana visibilitasnya, dan apa yang dilakukan dengan hasil hunting.

```
INC-2026-026 | Scope v2 | Senin 2026-12-07 11:50 WIB | Rudi Hartanto (TL) untuk Dimas Prasetyo (IC)
Severity: SEV-2 sejak 11:40 (aktivitas operator, discovery domain dari BDG-WS-0163)

TERKONFIRMASI
- BDG-WS-0163 (bima.ardiansyah): terinfeksi sejak Jumat 2026-12-04 15:05; beacon ke
  cdn.pdfsuite-update.example.net / 198.51.100.37; discovery domain Senin 08:10-08:12.
- JKT-WS-0452 (dian.permata): terinfeksi Senin 10:21; beacon; tanpa aktivitas operator.
- JKT-WS-0455 (nadia.safitri): file diunduh 09:58, belum dijalankan.
- Jalan masuk: iklan pencarian ke pdf-suite-download.example.net (installer palsu).
- Persistence: scheduled task "PDFSuite Updater" saat logon. File: E01-E03 dari JKT-WS-0452.

SUDAH DIPERIKSA, TIDAK DITEMUKAN
- Perangkat lain dengan unduhan, DLL, atau koneksi yang sama (advanced hunting 30 hari,
  proxy dan dns Splunk 30 hari).
- Logon akun Bima ke perangkat lain; koneksi SMB/RDP baru dari BDG-WS-0163.

BATAS VISIBILITAS
- Advanced hunting hanya 30 hari; perangkat tanpa sensor hanya terlihat dari proxy/dns.
- Isi update.dat dan apa yang dibaca operator di BDG-WS-0163 belum diketahui.

RENCANA JAM H 12:30 (menunggu persetujuan IC)
- Isolasi BDG-WS-0163 dan JKT-WS-0452 (Day 05); indikator blok domain, IP, dan SHA1.
- Hapus file unduhan di JKT-WS-0455 lewat live response remediate.
- Akun Bima dan Dian: reset dua kali dan revoke sessions (Day 05 bagian 2.3).
- Dua custom detection: lapis perilaku (bagian 1.3) dan unduhan installer PDFSuite_Setup*
  dari domain mana pun.
```

Cara membaca elemennya:

- **Batas visibilitas ditulis eksplisit**, termasuk retensi 30 hari, supaya "tidak ditemukan" dibaca dengan benar oleh IC dan oleh siapa pun yang membaca laporan nanti.
- **Query hunting dijadikan deteksi.** Advanced hunting memungkinkan query yang sama dipakai untuk custom detection rule yang berjalan otomatis [S1]. Rudi membuat dua rule: lapis perilaku, karena tetap bekerja saat domain dan hash berganti, dan unduhan file bernama `PDFSuite_Setup*` dari domain mana pun, karena nama umpan biasanya bertahan lebih lama daripada domainnya. Selasa 8 Desember 09:12 WIB, rule kedua menghasilkan alert `SOC-2026-0272` di `JKT-WS-0458`: pengguna Marketing lain mengunduh installer yang sama dari domain baru kampanye itu, dan eksekusinya diblok indikator SHA1 sehingga rule perilaku tidak perlu terpicu. Alert manual untuk temuan hunting di `BDG-WS-0163` tercatat sebagai `SOC-2026-0271`.

Dimas menyetujui jam H pukul 12:05. Langkah berikutnya mengikuti Day 05 untuk containment dan Day 06 untuk reimage kedua laptop.

## 3. Lab praktik (di VM lab terisolasi)

Lab ini memakai VM Windows dengan Sysmon, Splunk lab, dan bila ada, tenant trial Microsoft Defender for Endpoint dengan VM yang di-onboard. Tidak ada malware: "beacon" adalah scheduled task jinak yang memanggil web server lab, dan "side-loading" diamati dari aplikasi portable sah yang memuat DLL dari foldernya sendiri. Semua langkah di VM dengan snapshot, dan jangan memakai data atau nama dari pekerjaan nyata.

1. **Siapkan jejak jinak.** Taruh aplikasi portable sah (misalnya editor teks versi portable) di `C:\Users\<user>\AppData\Local\LabApp\`, jalankan sekali, lalu buat scheduled task saat logon yang menjalankan PowerShell untuk memanggil `http://beacon.lab.test/ping` setiap 5 menit. Biarkan berjalan minimal satu jam.
2. **Process tree.** Dengan Defender: jalankan query bagian 2.1 dengan nama perangkat dan akun lab. Tanpa Defender: cari padanannya di Splunk dari Sysmon Event ID 1 (process create, dengan `ParentImage`), 7 (image load), dan 3 (network connection). Gambar pohon prosesnya di kertas.
3. **Hitung beacon.** Hitung jumlah koneksi yang seharusnya muncul dari durasi dan interval, lalu bandingkan dengan hasil query. Bila berbeda, cari tahu kenapa (VM sleep, jam tidak sinkron, retry).
4. **Prevalence.** Buat VM kedua tanpa aplikasi portable, lalu jalankan query bagian 2.2 (atau padanannya di Splunk). Pastikan DLL aplikasi portable hanya terlihat di satu perangkat, dan DLL sistem terlihat di keduanya.
5. **Pivot.** Di VM kedua, unduh file apa pun dari web server lab dengan nama `LabSetup.zip` tetapi jangan dibuka. Jalankan query bagian 2.3 dengan domain lab dan pastikan VM kedua muncul hanya di sinyal unduhan.
6. **Live response atau padanannya.** Dengan Defender: buka sesi live response, jalankan perintah bagian 2.5 dan ekspor Command log. Tanpa Defender: kumpulkan informasi yang sama dengan PowerShell di VM (`Get-Process`, `Get-NetTCPConnection`, `Get-ScheduledTask`, `Get-FileHash`) dan catat setiap perintah beserta waktunya.
7. **Dokumen.** Tulis scope v2 dengan format bagian 2.6, termasuk bagian batas visibilitas.

**Hasil yang sebaiknya tersimpan:**

- Query yang dipakai (KQL atau SPL) beserta rentang waktunya, dan hasil yang diekspor.
- Gambar process tree dari langkah 2 dan perhitungan beacon dari langkah 3.
- Command log live response atau catatan perintah PowerShell beserta waktunya.
- `latihan/day17-scope.md` berisi scope v2.

**Variasi tantangan:** matikan sensor (atau Sysmon) di VM kedua selama 30 menit, jalankan aktivitas yang sama, lalu nyalakan lagi. Query mana yang masih menemukan aktivitas itu, dan sumber apa (log web server lab, DNS lab) yang menutup celahnya?

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat investigasi dengan EDR. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Query tidak menemukan event yang terlihat di timeline | Rentang waktu ditulis dalam WIB, bukan UTC | Tulis rentang dalam UTC; hasil portal dikonversi ke zona pengguna [S1] |
| Query lama berhenti dengan error atau hasil terpotong | Batas 10 menit, 100.000 baris, atau 64 MB | Persempit waktu dan perangkat, `summarize` lebih awal [S1] |
| Data untuk insiden lama tidak ada | Lewat dari 30 hari | Pakai log Splunk atau data yang dialirkan ke workspace lain sejak sebelum insiden [S1] |
| Pivot hash tidak menemukan apa pun | Memakai `SHA256` yang sering kosong | Pakai `SHA1` [S3] |
| Perangkat yang dicurigai tidak punya event sama sekali | Belum di-onboard, offline, atau sensor dalam mode kritis | Cek inventaris perangkat dan event mode kritis di timeline [S6] |
| Event firewall Windows tidak muncul di timeline | Kebijakan audit Filtering Platform belum diaktifkan | Aktifkan audit sebelum insiden [S6] |
| Tombol live response tidak tersedia | Fitur belum diaktifkan, peran tidak cukup, atau perangkat dalam sesi lain | Cek advanced features, peran RBAC, dan sesi aktif [S7] |
| Perintah `remediate` tetap berjalan setelah dibatalkan | Ctrl + C hanya membatalkan di portal | Jangan jalankan perintah yang mengubah perangkat sebelum diputuskan [S7] |

## 5. Kesalahan umum dan jebakan

- Menutup alert setelah membaca judulnya, tanpa membaca rangkaian event di sekitarnya.
- Berhenti di perangkat yang alert. Di `INC-2026-026`, perangkat terpenting justru yang tidak alert.
- Menyimpulkan "tidak ada" dari hasil hunting kosong tanpa memeriksa cakupan sensor, kesehatan sensor, dan rentang 30 hari.
- Menulis rentang waktu query dalam WIB, sehingga jendela yang dicari bergeser tujuh jam [S1].
- Hanya memakai IOC atomik (domain, IP, hash) untuk pivot. Varian berikutnya lolos; tambahkan lapis perilaku.
- Menjalankan `remediate` atau perintah yang mengubah perangkat saat masih investigasi, sehingga penyerang diberi tanda dan bukti berubah.
- Tidak menyimpan hasil query dan Command log. Setelah 30 hari, hasil yang sama tidak bisa dibuat ulang.
- Menganggap pengetahuan EDR terikat satu vendor. Yang dipelajari adalah alur dan model datanya; menu dan sintaks bisa dipelajari ulang.

## 6. Catatan terkini

Bagian ini menampung detail versi dan perilaku produk yang bisa berubah. Berguna saat memakai fitur yang disebut, tetapi tidak mengubah alur investigasi di atas.

- **Defender XDR advanced hunting** (halaman overview ms.date 2026-08-07): batas 30 hari untuk data native Defender XDR, 100.000 baris, 10 menit, dan 64 MB per query. Tabel Microsoft Sentinel yang di-onboard ke portal Defender mengikuti retensi analytics tier workspace, dan data yang hanya ada di Sentinel data lake tidak tersedia di advanced hunting [S1].
- **Skema advanced hunting** terus bertambah; halaman daftar tabel (ms.date 2026-07-27) memuat tabel baru dan tabel berstatus preview, termasuk `EntraIdSignInEvents` di samping `AADSignInEventsBeta` [S8]. Cek nama tabel dan `ActionType` di schema reference portal sebelum menyalin query lama.
- **Halaman investigasi perangkat** (ms.date 2026-07-23) menyebut timeline menampilkan 30 hari terakhir secara default dan bisa diekspor untuk rentang maksimal tujuh hari [S6]. Halaman itu juga menyebut retensi default 90 hari untuk data event; pengaturan retensi data Defender di tenant perlu dicek karena bisa diubah.
- **MITRE ATT&CK v20**: side-loading dibahas di dalam T1574.001 (DLL), versi 3.0 dimodifikasi September 2026 [S9]. Materi lama masih memakai nomor T1574.002 untuk DLL Side-Loading; bila kamu menemukannya, cek versi ATT&CK yang dirujuk.
- **CrowdStrike dan SentinelOne**: dokumentasi produk lengkap kedua vendor berada di portal pelanggan. Pemetaan di bagian 1.7 memakai blog, referensi API, dan silabus publik [S11][S12][S13][S14][S15], sehingga nama menu dan lisensi bisa berbeda dari tenant yang kamu pakai.

## 7. Cheat sheet

```
ALUR: pastikan alert -> process tree + timeline -> sinyal khas -> hunting fleet
      -> live response konfirmasi -> scope v2 + batas visibilitas -> containment -> custom detection

TRUE POSITIVE? asal file (FileOriginUrl) | siapa menjalankan (induk-anak) |
               DLL/koneksi tidak wajar | prevalence (1-2 perangkat vs ratusan)

KQL: waktu dalam UTC (WIB = UTC+7) | DeviceName = FQDN -> startswith | pivot hash pakai SHA1
  DeviceProcessEvents   proses + InitiatingProcess* (induk) + InitiatingProcessParent* (kakek)
  DeviceImageLoadEvents DLL dimuat           DeviceNetworkEvents  RemoteUrl/RemoteIP/RemotePort
  DeviceFileEvents      FileOriginUrl        DeviceLogonEvents    LogonType, RemoteIP
  DeviceFileCertificateInfo  join SHA1 untuk tanda tangan
  batas: 30 hari | 100.000 baris | 10 menit | 64 MB

PIVOT 3 LAPIS: infrastruktur (domain/IP) | file (hash/path) | perilaku (tahan ganti IOC)

KOSONG != TIDAK ADA: cek sensor terpasang + sehat (mode kritis) + rentang 30 hari + audit policy

LIVE RESPONSE: processes | connections | scheduledtasks | dir | fileinfo | getfile (3 GB)
  -output json > file | 1 perangkat = 1 sesi | 5 sesi/pengguna | idle 30 menit
  JANGAN remediate sebelum keputusan; Ctrl+C tidak menghentikan perintah di agen
  simpan: hasil query + Command log + hash file (evidence log)

LINTAS VENDOR: Defender advanced hunting / process tree / live response
  CrowdStrike Event Search / process tree / RTR (put, runscript)
  SentinelOne Deep Visibility / Storyline / Remote Script Orchestration
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Alert hanya muncul di `JKT-WS-0452`, jadi hanya laptop Dian yang terinfeksi." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Alert hanya muncul bila aturan deteksi cocok pada saat event diproses, sedangkan telemetry tercatat di semua perangkat bersensor. Di `INC-2026-026`, `BDG-WS-0163` menjalankan file yang sama sejak Jumat tanpa alert dan bahkan dipakai operator untuk discovery domain; perangkat itu hanya ditemukan lewat advanced hunting. Lihat bagian 1.3, 1.4, dan 2.3.

</details>

**2. Skenario keputusan.** Query hunting untuk domain C2 tidak mengembalikan apa pun di perangkat lain. Rudi harus melapor ke Dimas. Kalimat mana yang paling tepat?

- A. "Tidak ada perangkat lain yang terdampak."
- B. "Tidak ada perangkat bersensor lain yang menghubungi domain itu dalam 30 hari terakhir; perangkat tanpa sensor dicek lewat proxy dan DNS Splunk, dan hasilnya juga kosong."
- C. "Hasil hunting kosong, jadi containment cukup di laptop Dian."

<details><summary>Jawaban</summary>

B. Hasil hunting kosong hanya bermakna setelah cakupan sensor, kesehatan sensor, dan rentang 30 hari disebut, dan sumber lain dipakai untuk menutup celahnya. A keliru karena mengubah "tidak ditemukan di data yang ada" menjadi "tidak ada". C keliru karena juga melompat ke keputusan containment tanpa menyebut batas data, padahal perangkat yang sudah terinfeksi bisa memakai domain lain. Lihat bagian 1.4 dan 2.6.

</details>

**3. Pertanyaan jebakan.** "`pdfupdater.exe` bertanda tangan vendor yang sah, jadi proses itu aman dan alert ini false positive." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Side-loading justru memakai program sah yang bertanda tangan untuk memuat DLL buatan penyerang dari folder yang sama. Yang dinilai bukan hanya tanda tangan program, tetapi DLL yang dimuatnya (tidak bertanda tangan, dari profil pengguna), asal unduhan, prevalence, dan perilaku sesudahnya (koneksi berkala, menjalankan `cmd.exe`). Lihat bagian 1.1, 1.2, 2.2, dan 2.5.

</details>

**4. Skenario keputusan.** Saat sesi live response di `JKT-WS-0452`, Yoga mengusulkan langsung menjalankan `remediate` untuk menghapus `version.dll` dan scheduled task "supaya cepat beres". Respons mana yang tepat?

- A. Setuju, karena file dan task sudah dipastikan berbahaya.
- B. Ambil file dengan `getfile`, simpan keluaran dan Command log, lalu jalankan `remediate` di jam H bersama tindakan containment lain setelah IC memutuskan.
- C. Setuju, tetapi batalkan dengan Ctrl + C bila ternyata salah.

<details><summary>Jawaban</summary>

B. Menghapus sebelum jam H memberi tanda ke operator yang masih aktif di `BDG-WS-0163` dan menghilangkan file yang belum diambil sebagai bukti. A keliru karena mengubah perangkat sebelum keputusan containment yang serentak. C keliru karena Ctrl + C hanya membatalkan di portal; perintah yang mengubah perangkat bisa tetap berjalan di agen. Lihat bagian 1.5 dan 2.5.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Gilang Ramadhan (analyst L1), dalam tiga kalimat, kenapa memastikan alert EDR tidak cukup dengan membaca judul alert dan satu event pemicunya.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Judul alert hanya menyebut aturan mana yang terpicu, sedangkan yang perlu kita nilai adalah rangkaian kejadiannya: dari mana file datang, siapa yang menjalankannya, apa yang dimuat dan dihubunginya, dan seberapa umum file itu di perangkat lain. Untuk itu buka process tree dan timeline perangkat di sekitar waktu alert, lalu cek prevalence dengan advanced hunting. Kalau rangkaiannya tidak wajar, eskalasi dengan menyebut temuan itu, bukan hanya judul alert-nya."

Kesalahan yang sering muncul:
- Hanya mengatakan "lihat konteksnya" tanpa menyebut apa yang dicek.
- Tidak menyebut prevalence, padahal itu cara tercepat membedakan aplikasi internal dari file asing.
- Membuat Gilang merasa harus menyelesaikan semua investigasi sebelum eskalasi.

</details>

**6. Pertanyaan jebakan.** "Semua yang kita butuhkan ada di Defender, jadi kita tidak perlu menyimpan apa pun; kalau auditor bertanya bulan depan, query saja ulang." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Advanced hunting hanya menyimpan data mentah 30 hari, sehingga query yang sama bulan depan tidak lagi menemukan event insiden ini. Telemetry juga hanya ringkasan sensor; isi file seperti `update.dat` hanya ada di perangkat. Hasil query, rentang waktunya, Command log, dan file yang diambil harus diekspor, di-hash, dan dicatat sebagai bukti. Lihat bagian 1.4, 1.6, dan 2.5.

</details>

**7. Interview question (English).** "Walk me through how you investigate an EDR alert, and how would that change if you moved to a different EDR vendor?"

<details><summary>Sample answer</summary>

"I start by validating the alert, not just reading its title. I open the device timeline and the process tree around the alert time and answer four questions: where the file came from, who launched what, what it loaded and connected to, and how common it is across the fleet. If it's malicious, I take the distinctive signals at three layers, infrastructure like domains and IPs, file hashes and paths, and behavior, and hunt across all devices, because the most important finding is often a device that never alerted. Then I use live response to confirm current state and pull files, without remediating until the containment decision is made. I write the scope with explicit visibility limits, like the 30-day hunting window and devices without sensors, and I check proxy and DNS logs to cover those gaps. I export query results and the live response command log as evidence, and I turn the hunting query into a custom detection. With another vendor the workflow stays the same: CrowdStrike has Event Search and Real Time Response, SentinelOne has Deep Visibility, Storyline, and remote scripting. I'd relearn the query syntax and data model, not the method."

What makes this answer strong: it separates alert validation from incident scoping, names concrete pivots and their weaknesses, states data limits instead of overclaiming, treats EDR output as evidence to preserve, and shows the skill transfers across vendors.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Microsoft Learn: Advanced hunting overview in Microsoft Defender XDR | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview | primer (dokumentasi vendor) | ms.date 2026-08-07; diakses 2026-10-15 | Tinggi. Batas 30 hari, kuota query, UTC, perpanjangan retensi, custom detection |
| S2 | Microsoft Learn: DeviceFileEvents table in the advanced hunting schema | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table | primer (dokumentasi vendor) | ms.date 2025-03-28; diakses 2026-10-15 | Tinggi. `FileOriginUrl`, `FileOriginReferrerUrl`, `FileOriginIP`; hash bisa kosong |
| S3 | Microsoft Learn: DeviceProcessEvents table in the advanced hunting schema | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table | primer (dokumentasi vendor) | ms.date 2026-08-07; diakses 2026-10-15 | Tinggi. Kolom proses dan induk, `SHA256` biasanya kosong, join tanda tangan lewat `SHA1` |
| S4 | Microsoft Learn: DeviceImageLoadEvents table in the advanced hunting schema | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceimageloadevents-table | primer (dokumentasi vendor) | ms.date 2025-03-28; diakses 2026-10-15 | Tinggi. Event pemuatan DLL dan kolomnya |
| S5 | Microsoft Learn: DeviceNetworkEvents table in the advanced hunting schema | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table | primer (dokumentasi vendor) | ms.date 2025-03-28; diakses 2026-10-15 | Tinggi. `RemoteUrl`, `RemoteIP`, `RemotePort`, kolom proses pemrakarsa |
| S6 | Microsoft Learn: Investigate devices in Microsoft Defender for Endpoint | https://learn.microsoft.com/en-us/defender-endpoint/investigate-machines | primer (dokumentasi vendor) | ms.date 2026-07-23; diakses 2026-10-15 | Tinggi. Tahap investigasi perangkat, timeline, process tree, flag, ekspor tujuh hari, mode kritis, audit firewall, retensi |
| S7 | Microsoft Learn: Investigate entities on devices using live response in Microsoft Defender for Endpoint | https://learn.microsoft.com/en-us/defender-endpoint/live-response | primer (dokumentasi vendor) | ms.date 2026-07-28; diakses 2026-10-15 | Tinggi. Perintah dasar dan lanjutan, library, batas sesi dan file, Command log, Ctrl + C |
| S8 | Microsoft Learn: Data tables in the Microsoft Defender XDR advanced hunting schema | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables | primer (dokumentasi vendor) | ms.date 2026-07-27; diakses 2026-10-15 | Tinggi. Daftar tabel dan isinya, termasuk `DeviceFileCertificateInfo` dan tabel `Identity*` |
| S9 | MITRE ATT&CK: Hijack Execution Flow: DLL (T1574.001) | https://attack.mitre.org/techniques/T1574/001/ | primer | ATT&CK v20, versi 3.0, dimodifikasi 2026-09-11; diakses 2026-10-15 | Tinggi. DLL side-loading dan arah deteksinya |
| S10 | MITRE ATT&CK: Drive-by Compromise (T1189) | https://attack.mitre.org/techniques/T1189/ | primer | ATT&CK v20, versi 1.7; diakses 2026-10-15 | Tinggi. Malvertising dan pembaruan software palsu |
| S11 | CrowdStrike Tech Center: How to Remotely Remediate an Incident (Real Time Response) | https://www.crowdstrike.com/blog/tech-center/remote-remediation-real-time-response/ | sekunder (blog vendor) | 2024-05-02; diakses 2026-10-15 | Sedang. Kemampuan RTR secara umum; tidak memuat daftar perintah |
| S12 | CrowdStrike API reference: Real Time Response Admin | https://developer.crowdstrike.com/api-reference/collections/real-time-response-admin/ | primer (dokumentasi API vendor) | diakses 2026-10-15 | Sedang sampai tinggi. Custom script untuk `runscript`, put-file untuk `put` |
| S13 | CrowdStrike University: FALCON 202 course syllabus | https://www.crowdstrike.com/en-gb/resources/data-sheets/crowdstrike-university-falcon-202-course-syllabus/ | sekunder (materi pelatihan vendor) | tanpa tanggal; diakses 2026-10-15 | Sedang. Pencarian real-time dan retrospektif, query kustom, korelasi hubungan proses |
| S14 | SentinelOne: Rapid Threat Hunting with Storylines (Feature Spotlight) | https://www.sentinelone.com/blog/rapid-threat-hunting-with-deep-visibility-feature-spotlight/ | sekunder (blog vendor) | diperbarui 2024-03-27; diakses 2026-10-15 | Sedang. Deep Visibility, Storyline ID, query subset SQL, pencarian per teknik ATT&CK |
| S15 | SentinelOne: Revolutionize Incident Response and Endpoint Management with Remote Script Orchestration | https://www.sentinelone.com/blog/revolutionize-incident-response-and-endpoint-management-with-remote-script-orchestration/ | sekunder (blog vendor) | diperbarui 2025-04-28; diakses 2026-10-15 | Sedang. Skrip ke banyak endpoint, koleksi forensik, tindakan respons, Script Library |
| S16 | GitHub Bert-JanP: Hunting-Queries-Detection-Rules | https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules | komunitas | lisensi BSD-3-Clause; diakses 2026-10-15 | Sedang. Kumpulan query KQL publik untuk Defender XDR dan Sentinel, termasuk folder DFIR; bahan latihan menulis query |

**Catatan sumber:** empat pertanyaan untuk memutuskan true positive di bagian 1.1, tiga lapis sinyal pivot di bagian 1.3, dan tiga alasan EDR bukan pengganti bukti di bagian 1.6 adalah susunan catatan ini dari sumber yang disebut, bukan daftar resmi. Bentuk `FolderPath` yang memuat nama file, nilai `LogonType` seperti `Unlock`, dan nama kolom `DeviceFileCertificateInfo` (`IsSigned`, `Signer`) perlu dicek di schema reference tenant-mu. Pemetaan CrowdStrike dan SentinelOne di bagian 1.7 memakai materi publik vendor [S11][S12][S13][S14][S15]; dokumentasi produk lengkap keduanya berada di portal pelanggan, dan fitur shell jarak jauh SentinelOne (Remote Shell) disebut tanpa rujukan karena materi publik yang menyebutnya berasal dari 2019 dan ketersediaannya sekarang perlu dicek. Query komunitas [S16] dipakai sebagai bahan latihan, bukan dasar klaim. Semua isi PT JAB, termasuk nama perangkat, hash, alamat IP, waktu, dan angka di keluaran ilustrasi, adalah contoh fiktif; retensi 90 hari untuk log proxy dan DNS di Splunk yang disebut di scope v2 juga contoh.
