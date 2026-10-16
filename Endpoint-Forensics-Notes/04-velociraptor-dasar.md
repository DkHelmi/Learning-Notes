---
day: 04
title: 'Velociraptor dasar untuk forensik: server dan client, koleksi triage dan adaptive, hunt, offline collector, dan ekspor'
researched_on: 2026-10-16
versions_checked: 'Velociraptor 0.77.3 (rilis 5 Okt 2026, masih rilis terbaru per 2026-10-16; dokumentasi meminta update ke 0.77.3 karena beberapa CVE); Windows.Triage.Targets dari proyek Velociraptor Triage (tidak bawaan sejak 0.75, diimpor lewat Server.Import.Extras); Microsoft Defender for Endpoint live response (ms.date 2026-07-28); msiexec (Microsoft Learn); Eric Zimmerman tools (.NET 9)'
---

# Day 04: Velociraptor dasar untuk forensik

Cakupan: memakai Velociraptor sebagai mesin akuisisi forensik untuk satu atau banyak host, dari membangun server sementara, mengantar client, menjalankan koleksi triage, adaptive, dan hunt, membuat offline collector untuk host yang tidak terjangkau, sampai mengekspor hasil sebagai bukti dan menulis hasil negatif dengan batas yang jujur.

## Ide inti

Velociraptor adalah cara menanyakan hal yang sama ke banyak endpoint sekaligus dan menerima jawabannya sebagai satu koleksi yang tercatat. Pertanyaannya ditulis sebagai artifact (query VQL yang dibungkus dengan parameter), dijalankan oleh client di endpoint, dan jawabannya kembali ke server berupa baris hasil plus file yang disalin. Nilai forensiknya ada di dua hal: jangkauan (banyak host, host jauh, bahkan host tanpa agent lewat offline collector) dan konsistensi (artifact dan parameter yang sama untuk semua host, dengan waktu, client, dan versi yang tercatat). Kelemahannya juga perlu diingat sejak awal: jawaban hanya sekuat pertanyaannya. "Tidak ditemukan" dari sebuah hunt berarti "tidak ditemukan oleh artifact ini, dengan parameter ini, pada waktu ini", bukan "host ini bersih".

Dari NOC kamu sudah mengenal polanya. Saat gangguan merambat, engineer tidak login satu per satu ke ratusan router; ia menjalankan satu set perintah `show` yang sama lewat alat otomasi ke semua perangkat di daftar, lalu membaca output yang terkumpul di satu folder. Untuk perangkat di lokasi yang tidak terjangkau dari NMS, ia menitipkan flashdisk berisi skrip capture ke teknisi lapangan, dan isi skrip itu harus benar sebelum teknisi berangkat karena tidak bisa diulang dari jauh. Hunt Velociraptor adalah versi endpoint dari skrip massal itu, dan offline collector adalah flashdisk titipannya. Bedanya, menjalankan client di endpoint mengubah host sedikit (proses, service, file baru), dan hasil negatif hanya berlaku untuk perintah yang memang dijalankan.

```
pertanyaan investigasi (IOC, perilaku, artefak yang perlu dipreservasi)
  |
  v
SERVER (jkt-velo01)  -- artifact + parameter --+
  |                                            |
  v                                            v
CLIENT terpasang di host                  OFFLINE COLLECTOR (host tak terjangkau)
  collection (1 host) | hunt (banyak host)  dijalankan operator lokal sebagai admin
  |                                            |
  v                                            v
hasil: baris JSON + file (uploads)        container ZIP terenkripsi + log (Container hash)
  |                                            |
  +---------------> EKSPOR / IMPORT <----------+
                       |
                       v
          hash -> master di server bukti -> salinan kerja -> EZ Tools / notebook
                       |
                       v
          temuan: "ditemukan" atau "tidak ditemukan oleh X pada waktu Y, dengan batas Z"
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan, kantor pusat di Jakarta, dan POP regional di Bandung. Kasusnya `INC-2026-019`: email dari `billing@vendor-tagihan.example` dengan lampiran `Tagihan-Okt-2026.zip` (berisi `Tagihan-Okt-2026.js`) masuk ke 9 mailbox pada Senin 2026-10-12 pukul 15:58. Tiga penerima menjalankannya: `andi.pratama` (`JKT-WS-0388`), `dewi.anggraini` (`BDG-WS-0142`, tanpa EDR), dan `rizky.saputra` (`JKT-WS-0412`, tanpa EDR). Di ketiga laptop itu penyerang memasang scheduled task `\SysCacheUpdate` yang menjalankan `C:\Users\<user>\AppData\Roaming\SysCache\upd.ps1`, dengan C2 `cdn-sync.example.net` (`203.0.113.77:443`). Ketiga laptop sudah diambil memorinya, dan image disknya sudah berjalan atau dijadwalkan. Enam penerima lain tidak di-image dan tidak diambil memorinya, karena pivot di SIEM dan EDR tidak menemukan eksekusi lampiran atau koneksi ke C2; risiko yang dicatat, laptop tanpa EDR di antara mereka hanya terlihat dari log jaringan.

Kamis 2026-10-15 siang kamu, analyst L2 yang memegang forensik endpoint, mengusulkan untuk mengurangi risiko itu dengan koleksi ringan di keenam laptop, bukan image. Pukul 16:00 Dimas Prasetyo, SOC lead dan incident commander, membalas di kanal `#inc-2026-019`:

> "Usulanmu saya setujui: koleksi ringan di enam penerima lain, bukan image. Sebelum jalan saya perlu paham beberapa hal. Velociraptor ini apa, dan kenapa tidak cukup Defender yang sudah kita punya? Servernya ditaruh di mana, dan setelah kasus selesai bagaimana? Agent-nya sampai ke laptop bagaimana, terutama laptop Wawan yang tanpa EDR dan laptop Ratih yang hampir selalu di lapangan? Apa saja yang diambil, dan kenapa itu cukup tanpa image? Hasilnya dicatat sebagai bukti seperti apa? Terakhir, kalau hasilnya bersih, kalimat apa yang boleh saya tulis di scope statement dan ke Pak Agus (DPO)?"

Pesan itu memuat enam pertanyaan:

1. Apa itu Velociraptor, dan kenapa tidak cukup memakai EDR yang sudah ada?
2. Di mana servernya, dan apa yang terjadi padanya setelah kasus selesai?
3. Bagaimana client sampai ke laptop, termasuk yang tanpa EDR dan yang di lapangan?
4. Apa yang dikumpulkan, dan kenapa itu cukup tanpa image?
5. Bagaimana hasilnya dicatat sebagai bukti?
6. Bila hasilnya bersih, kalimat apa yang boleh ditulis?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 dan 3 di bagian 1.2 (laptop Ratih di bagian 1.5), pertanyaan 4 di bagian 1.3 dan 1.4, pertanyaan 5 di bagian 1.6, dan pertanyaan 6 di bagian 1.7. Bagian 2 berisi langkah yang kamu jalankan Kamis sore sampai Jumat, beserta hasilnya.

**Kapan relevan:** koleksi dari banyak host atau host jarak jauh, scoping setelah IOC diketahui, adaptive collection, host yang tidak bisa diakses langsung, dan host tanpa agent yang hanya bisa dijangkau lewat operator lokal (offline collector).
**Kapan bukan jawaban:** satu host yang bisa diakses langsung dengan media cukup memakai KAPE (Day 03); kebutuhan file terhapus atau unallocated space tetap butuh image penuh (Day 01); analisis memori mendalam memakai alat akuisisi dan Volatility 3 (Day 14). Day ini juga bukan Day threat hunting: hunt di sini dipakai untuk mengumpulkan dan mempreservasi, bukan untuk mencari pola baru di seluruh fleet.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day 01 sampai 03 (triage collection, adaptive collection, salinan kerja, chain of custody, dan sejenisnya) tidak diulang. Tabel ini hanya memuat istilah yang baru muncul di Day ini; kolom padanan memakai analogi NOC dan SOC yang sama dengan Day sebelumnya.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Client (agent) | Proses Velociraptor di endpoint yang menerima tugas dari server, menjalankan query, dan mengirim hasil | Agent SNMP atau telemetry di router yang menjawab polling NMS |
| Server (frontend dan GUI) | Tempat investigator memberi tugas, menyimpan hasil, dan membaca notebook | NMS atau server otomasi yang memegang daftar perangkat |
| VQL | Velociraptor Query Language, bahasa query mirip SQL yang dijalankan di endpoint | Perintah `show` dengan filter `include` |
| Artifact | File YAML yang membungkus query VQL beserta parameter, sehingga investigator tinggal memilih dan mengisi parameter | Template skrip capture yang sudah disetujui |
| Collection | Menjalankan satu atau beberapa artifact di satu client | Capture `show tech` dari satu router |
| Hunt | Menjalankan artifact yang sama ke semua client yang cocok dengan kondisi (label, OS), termasuk yang baru online selama hunt aktif | Skrip `show` massal ke semua perangkat di satu grup |
| Label | Tanda pada client untuk menentukan target hunt | Grup perangkat di NMS |
| Offline collector | Biner Velociraptor dengan konfigurasi dan artifact tertanam, dijalankan tanpa client terpasang | Flashdisk skrip capture yang dititipkan ke teknisi lapangan |
| Collection container | ZIP terstruktur berisi hasil JSON, file yang disalin, log, dan metadata; bisa diekspor dan diimpor antar server | Arsip `show tech` beserta checksum dan tiket |
| Live response (EDR) | Shell jarak jauh dari konsol EDR ke perangkat yang menyala | Masuk ke console perangkat untuk menjalankan perintah `show` sebelum reboot |

### 1.1 Velociraptor sebagai mesin koleksi, dan bedanya dengan EDR

Pertanyaan pertama Dimas masuk akal: PT JAB sudah punya Microsoft Defender for Endpoint Plan 2 di workstation, jadi kenapa perlu alat lain?

Velociraptor adalah platform endpoint dengan empat bagian: client (agent), server, VQL, dan artifact [S2]. VQL adalah bahasa query mirip SQL yang dijalankan di endpoint; query bisa membaca file, registry, event log, atau memanggil parser bawaan. Artifact adalah file YAML yang membungkus satu atau beberapa query VQL beserta parameternya, sehingga investigator cukup memilih artifact dan mengisi parameter tanpa menulis VQL sendiri. Untuk forensik, tabel berikut menunjukkan peran tiap komponen; cari baris yang menjawab "siapa yang menyimpan bukti".

| Komponen | Peran forensik |
|---|---|
| Client (agent) | Dipasang di endpoint; menjalankan koleksi dan mengirim hasil ke server |
| Server | Tempat investigator memberi tugas koleksi dan menyimpan hasil |
| Artifact koleksi | Mendefinisikan apa yang dikumpulkan (triage targets, file spesifik) |
| Offline collector | Paket mandiri untuk host tanpa agent |

Velociraptor memetakan ke pola akuisisi Day 01: triage collection (artifact triage), adaptive collection (artifact yang memparse lalu mengambil file tambahan), dan bukan full image (untuk itu tetap perlu alat imaging).

Velociraptor juga banyak dipakai untuk threat hunting, yaitu menjalankan query ke seluruh fleet untuk menemukan host yang mencurigakan. Day ini memakainya untuk forensik: mengumpulkan dan mempreservasi bukti dari host yang sudah ditentukan. Alat sama, tujuan berbeda: hunting mencari, forensik mengumpulkan dan menganalisis.

Jawaban untuk Dimas ada di tiga perbedaan dengan EDR. Pertama, telemetry EDR hanya mencatat apa yang dicatat sensornya, dari host yang bersensor, dalam jendela retensi tertentu; pivot hari Selasa memakai sumber itu. Koleksi Velociraptor membaca keadaan host sekarang (file task di `C:\Windows\System32\Tasks`, file di profil pengguna, Prefetch, event log) sebagai sumber kedua yang independen. Kedua, dua dari enam laptop tidak punya EDR, sehingga untuk mereka koleksi di host adalah satu-satunya sumber di luar log jaringan. Ketiga, live response Defender memang punya perintah seperti `scheduledtasks`, `persistence`, dan `getfile` [S23], tetapi dijalankan satu sesi per perangkat dan setiap perangkat hanya bisa berada di satu sesi pada satu waktu [S23]. Hunt menjalankan artifact yang sama ke enam host dan menghasilkan satu koleksi yang bisa diekspor utuh. Karena itu Defender tetap dipakai, tetapi sebagai jalan untuk mengantar client ke host ber-EDR (bagian 1.2), bukan sebagai alat koleksinya.

### 1.2 Server sementara dan cara client sampai ke host

Pertanyaan kedua dan ketiga Dimas menyangkut infrastruktur: server di mana, dan bagaimana agent masuk ke enam laptop yang kondisinya berbeda.

Velociraptor berjalan sebagai biner tunggal; peran server atau client ditentukan oleh konfigurasi dan subcommand [S2]. Dokumentasi menyebut deployment cepat dengan sertifikat self-signed dan autentikasi Basic cocok untuk pemakaian jangka pendek seperti IR sementara dan deployment kecil yang tidak terbuka ke internet [S13]. Port bawaannya dua: TCP 8000 untuk koneksi client (frontend) dan TCP 8889 untuk GUI admin [S13]. Konfigurasi dibuat dengan wizard `config generate -i`, dan konfigurasi frontend harus diubah dari `bind_address: 127.0.0.1` ke `0.0.0.0` supaya client dari host lain bisa terhubung; GUI sebaiknya tetap terbatas ke jaringan tepercaya [S13].

Untuk PT JAB, keputusannya ditulis Kamis 16:10: server sementara `jkt-velo01` (`10.20.1.30`) di jaringan manajemen, dibangun khusus untuk `INC-2026-019`, dengan aturan firewall yang hanya membuka TCP 8000 dari jaringan kantor Jakarta (`10.10.0.0/16`) dan Bandung (`10.30.0.0/16`) ke `jkt-velo01`, dan TCP 8889 hanya dari jaringan manajemen. Server dimatikan setelah kasus ditutup, sesudah semua hasil diekspor ke `jkt-evid01` dan client di laptop dicopot.

Client di Windows dipasang dari MSI yang di-repack dengan konfigurasi client. Server artifact `Server.Utils.CreateMSI` mengunduh MSI rilis dan me-repack-nya dengan konfigurasi client; hasilnya diunduh dari tab Uploaded Files [S12][S13]. Instalasi dengan `msiexec /i` membutuhkan hak administrator, memasang file di `C:\Program Files\Velociraptor\`, dan menjalankan service sebagai Local System [S12]. Dokumentasi menyebut cara massal lewat SCCM atau Group Policy, client sementara yang dijalankan sebagai scheduled task dari share read-only, dan pilihan menjalankan client tanpa instalasi dengan `velociraptor.exe --config client.config.yaml client -v` untuk uji coba [S12]. Untuk offline collector, dokumentasi juga menyebut Group Policy, PsExec, WinRM, dan EDR dengan kemampuan eksekusi jarak jauh sebagai jalan menjalankan biner di host lain, dengan syarat tetap berjalan sebagai administrator [S8]. Alat yang sama bisa dipakai untuk mengantar MSI client.

Tabel berikut adalah keputusan per host untuk enam penerima. Perhatikan kolom "Jalan masuk", karena itu yang membedakan host ber-EDR dari yang tidak.

| Pengguna | Host | IP | EDR | Jalan masuk client |
|---|---|---|---|---|
| `sinta.maharani` | `JKT-WS-0395` | `10.10.23.95` | Ya | Live response Defender: `putfile` MSI, lalu `run` skrip PowerShell pemasang |
| `eko.prasetyo` | `JKT-WS-0397` | `10.10.23.97` | Ya | Live response Defender |
| `lia.kurniasih` | `JKT-WS-0405` | `10.10.40.5` | Ya | Live response Defender (laptop baru online Jumat pagi) |
| `wawan.gunawan` | `JKT-WS-0418` | `10.10.41.18` | Tidak | Manual: Yoga menyalin MSI lewat admin share dari `JKT-JUMP01` dengan `adm.yoga`, lalu menjalankan `msiexec` dari jarak jauh |
| `yanti.oktaviani` | `BDG-WS-0151` | `10.30.15.51` | Ya | Live response Defender |
| `ratih.puspita` | `BDG-WS-0147` | `10.30.14.47` | Tidak | Tidak dipasang client; offline collector dijalankan Fajar Nugraha dari `USB-E-12` (bagian 1.5) |

Live response Defender cocok untuk empat host ber-EDR karena perintah `putfile` menaruh file dari library ke perangkat dan `run` menjalankan skrip PowerShell dari library [S23]. Batasnya perlu dicek sebelum dipakai: `putfile` di Windows dibatasi 300 MB dan library 250 MB, perintah `run` punya batas waktu 30 menit, skrip tanpa tanda tangan hanya bisa dijalankan bila pengaturan "live response unsigned script execution" diaktifkan, dan file hasil `putfile` disimpan di folder kerja yang secara bawaan terhapus saat perangkat restart [S23]. Semua perintah sesi tercatat di tab Command log [S23], sehingga jejak pemasangan ikut terdokumentasi di konsol EDR.

Untuk `JKT-WS-0418` tidak ada live response, jadi jalannya manual dengan akun admin per analyst dari jump host, sesuai pola akses admin PT JAB. Apa pun jalannya, pemasangan client meninggalkan jejak di host: service baru, file di `Program Files`, dan event pemasangan. Waktunya dicatat di case notes per host, supaya analisis berikutnya tidak membaca jejak itu sebagai aktivitas penyerang.

Satu hal lagi perlu diberitahukan ke SOC sebelum pemasangan. Cisco Talos (Oktober 2025) melaporkan penyerang memasang Velociraptor versi lama (0.73.4.0) secara diam-diam dengan `msiexec` sebagai alat akses jarak jauh dalam serangan ransomware, dan menyarankan pemantauan instalasi Velociraptor yang tidak disetujui [S26]. Karena itu L1 diberi tahu hash MSI resmi, host tujuan, dan jendela waktunya, supaya alert yang mungkin muncul bisa dicocokkan, bukan diabaikan begitu saja.

### 1.3 Artifact koleksi triage dan adaptive

Pertanyaan keempat Dimas ("apa saja yang diambil?") dimulai dari artifact triage.

Velociraptor punya artifact yang mengumpulkan artefak forensik, penerus pendekatan KapeFiles (Day 01) [S1]. Artifact itu adalah `Windows.Triage.Targets`, yang menurut artikel Adaptive Collections adalah nama baru dari `Windows.KapeFiles.Targets` [S5]. Sejak 0.75 target KapeFiles dikelola di proyek terpisah, sehingga `Windows.Triage.Targets` tidak bawaan dan harus diimpor [S5][S11]. Dokumentasi menyarankan server artifact bawaan `Server.Import.Extras` untuk mengimpor dan memperbaruinya [S11]. Artifact itu mengunduh bundle dari beberapa repositori eksternal, salah satunya The Triage Artifacts [S22], sehingga server butuh akses keluar ke alamat bundle itu atau bundle harus dibawa masuk dengan cara lain. Untuk `jkt-velo01`, akses itu diberikan sementara lewat proxy terbatas.

Halaman artifact `Windows.Triage.Targets` mencantumkan parameter yang menentukan isi koleksi [S10]. Tabel berikut memuat parameter yang dipakai di PT JAB; baca kolom "Akibat bila salah paham", karena di situlah koleksi diam-diam menjadi tidak lengkap.

| Parameter | Bawaan | Arti | Akibat bila salah paham |
|---|---|---|---|
| `CollectionPolicy` | `ExcludeSigned` | `ExcludeSigned`: executable bertanda tangan tidak dikumpulkan; `HashOnly`: file tidak dikumpulkan, hanya hash; `AllFiles`: semua file dikumpulkan | File yang hanya di-hash tidak bisa diparse isinya |
| `HighLevelTargets` | kosong | Meta-target `_BasicCollection`, `_KapeTriage`, `_Live`, `_SANS_Triage` | Kosong berarti hanya `Targets` yang dipilih yang diambil |
| `Targets` | kosong | Target individual, misalnya `EventLogs`, `Prefetch`, `RegistryHivesSystem` | Artefak yang tidak ada di target tidak dikumpulkan |
| `Devices` | `["C:"]` | Drive yang dicari | Data di drive lain terlewat |
| `VSS_MAX_AGE_DAYS` | `0` | Di atas 0, ikut membaca Volume Shadow Copy sekian hari ke belakang dengan accessor `ntfs` yang lebih lambat | Bernilai 0 berarti salinan lama di VSS tidak dibaca |
| `TrustedPathRegex` | `^C:\\Windows\\` | File yang cocok tidak di-hash dan tidak di-upload | Lihat catatan di bawah tabel |
| `MaxFileSize` | lihat catatan | Ukuran maksimum file yang dikumpulkan | Halaman artifact tidak konsisten soal nilai bawaannya |

Kebijakan `ExcludeSigned` (bawaan) tidak mengambil biner bertanda tangan tepercaya untuk mengurangi ukuran, dan `HashOnly` hanya mencatat hash dan keberadaan file, bukan isinya [S1][S10]. Kebijakan ketiga, `AllFiles`, tidak disarankan untuk adaptive collection karena ikut mengambil file sistem dan biner tepercaya [S5]. Dua catatan dari halaman artifact perlu dicek di lab sebelum dipercaya. Pertama, deskripsi `MaxFileSize` menyebut bawaan 100 MB, tetapi badan halaman menyebut batas ini nonaktif secara bawaan [S10]. Kedua, `TrustedPathRegex` disebut membuat file di bawah `C:\Windows\` tidak di-hash dan tidak di-upload [S10]; cek di koleksi lab apakah aturan itu hanya berlaku untuk file hasil aturan adaptive atau juga untuk target seperti `EventLogs` yang berada di bawah `C:\Windows`. Ejaan meta-target juga berbeda antar sumber: halaman artifact menulis `_SANS_Triage` [S10], artikel Adaptive Collections menulis `_SansTriage` [S5]. Pilih dari daftar yang muncul di GUI versi-mu.

Adaptive collection (Day 01) memparse artefak saat koleksi untuk memutuskan file tambahan yang diambil, misalnya biner yang dirujuk Prefetch atau scheduled task [S1]. Ini jalan tengah antara triage (cepat, bisa melewatkan) dan full image (lengkap, berat). Di `Windows.Triage.Targets`, meta-target `_Live` memicu semua aturan adaptive [S5]. Tabel berikut memuat aturan itu dan file yang diambilnya.

| Aturan adaptive | Yang diparse di endpoint | File yang diambil |
|---|---|---|
| `PrefetchBinaries` | File Prefetch | Executable yang dirujuk Prefetch dan masih ada |
| `AdaptiveScheduledTasks` | Definisi scheduled task | Biner yang dijalankan task |
| `Services` | Daftar service terpasang | Biner service |
| `PsList` | Proses yang berjalan | Biner proses |
| `LnkTargets` | File `.lnk` | Target shortcut |

File yang sama hanya dikumpulkan dan di-hash sekali karena ada deduplikasi [S5]. Untuk `INC-2026-019`, kombinasi `_Live` dan target `EventLogs` dengan `ExcludeSigned` cocok: `upd.ps1` atau biner tidak bertanda tangan yang dijalankan task akan ikut terambil bila ada, sedangkan biner Windows bertanda tangan tidak membebani koleksi. Artifact triage hanya menyalin file dan tidak memparse [S10]; pertanyaan spesifik (task bernama `\SysCacheUpdate`, file `upd.ps1`, string C2 di event log) dijawab oleh artifact lain di bagian 1.4.

### 1.4 Collection dan hunt

Bagian kedua dari jawaban "apa saja yang diambil, dan kenapa cukup tanpa image" ada pada cara menjalankan artifact: satu host atau banyak host.

Tabel berikut membandingkan dua cara menjalankan artifact; pilih berdasarkan kolom "Kapan".

| Aksi | Tujuan | Kapan |
|---|---|---|
| Collection (satu client) | Kumpulkan artefak dari satu host yang sudah ditentukan | Forensik mendalam satu host; uji artifact sebelum hunt |
| Hunt (banyak client) | Jalankan artifact ke banyak host sekaligus | Triage luas, scoping, hunting |

Untuk forensik, alur umum: hunt luas untuk menemukan host relevan, lalu collection mendalam dari host itu untuk preservasi (pola lapangan di Day 01). Hasil collection diperlakukan sebagai bukti: di-hash, disimpan read-only.

Perilaku hunt yang perlu diingat [S14]:

- Hunt dibuat dari Hunt Manager lewat tombol New Hunt, dan dibuat dalam keadaan `Paused`; hunt baru berjalan setelah Start ditekan. Dokumentasi menyarankan menguji artifact di satu atau dua endpoint dulu.
- Hunt tidak "selesai", tetapi kedaluwarsa. Bawaannya satu minggu. Selama aktif, hunt dijadwalkan ke setiap client baru yang memenuhi kondisi, dan setiap client hanya menerima satu hunt satu kali.
- Target bisa dibatasi dengan label. Memberi label pada client yang baru terpasang membuat hunt berlabel itu terjadwal di client tersebut.
- Hunt bisa menghasilkan data besar; artifact yang mengembalikan sedikit baris per endpoint lebih disukai daripada koleksi file mentah.

Soal volume, dokumentasi memberi contoh hitungan: 100 MB dari 10.000 endpoint sama dengan 1 TB, dan file tidak dideduplikasi antar koleksi yang berbeda [S11]. Enam laptop bukan masalah volume, tetapi kebiasaan menghitung sebelum menekan Start tetap berguna.

Untuk enam penerima, hunt diisi dua jenis artifact. Jenis pertama menjawab pertanyaan spesifik dan mengembalikan baris: `Windows.System.TaskScheduler` (memparse XML di `C:/Windows/System32/Tasks/**` dan menampilkan nama task, command, argumen, dan akun) [S17], `Windows.Search.FileFinder` (mencari file berdasarkan glob, dengan opsi hash dan upload) [S18], `Windows.Forensics.Prefetch` (riwayat eksekusi dari Prefetch, termasuk delapan waktu jalan terakhir di Windows 10) [S19], `Windows.EventLogs.EvtxHunter` (mencari regex IOC di semua file EVTX) [S20], dan `Windows.System.DNSCache` (isi cache DNS saat ini) [S21]. Jenis kedua mempreservasi: `Windows.Triage.Targets` dengan `_Live` dan `EventLogs` (bagian 1.3). Jenis pertama menjawab "ada atau tidak"; jenis kedua menyimpan bahan supaya pertanyaan baru minggu depan masih bisa dijawab dari file yang sama.

Kenapa cukup tanpa image: pertanyaannya sempit dan sudah diketahui. Penyerang di tiga host terdampak memakai nama task, path file, dan C2 yang sama, dan IOC itu meninggalkan jejak di artefak yang dibaca artifact di atas. Image baru dibutuhkan bila salah satu host menunjukkan tanda eksekusi; saat itu host tersebut pindah ke pola yang sama dengan tiga host terdampak.

### 1.5 Offline collector untuk host yang tidak terjangkau

Laptop Ratih (`BDG-WS-0147`) hampir selalu di lapangan, tidak terhubung ke jaringan kantor, dan tanpa EDR. Client yang dipasang tidak akan pernah bisa menjangkau `jkt-velo01`, jadi jawabannya offline collector.

Offline collector adalah paket mandiri yang dijalankan di host tanpa memasang agent permanen [S2]. Ia adalah biner Velociraptor standar dengan konfigurasi dan artifact pilihan yang tertanam; biner tidak perlu dikompilasi ulang [S6]. Perilaku offline hanya berjalan bila biner dijalankan tanpa argumen; dengan argumen apa pun, ia berperilaku sebagai biner Velociraptor biasa [S6][S8]. Saat dijalankan, collector mengumpulkan artifact terpilih, menyimpan hasil, log, dan metadata ke ZIP terstruktur yang biasanya terenkripsi, lalu bila dikonfigurasi mengunggahnya ke tujuan jaringan atau cloud dan bisa menghapus salinan lokal [S6]. Untuk forensik, offline collector berguna saat:

- Host tidak boleh dipasangi agent permanen.
- Akuisisi satu kali di host yang diakses lewat media (mirip KAPE, tetapi dengan logika VQL Velociraptor).
- Host terisolasi dari server.

Collector dibuat dengan Offline Collector builder dari layar Server Artifacts, yang merupakan pembungkus GUI untuk server artifact `Server.Utils.CreateCollector` [S7]. Langkah wizard-nya: pilih artifact, atur parameter, atur collector, atur batas sumber daya, review, lalu launch; binernya diunduh dari tab Uploaded Files, dan sejak 0.75.5 file spec ikut tersedia untuk membangun ulang collector yang sama lewat command line [S7]. Pilihan yang paling menentukan bagi forensik ada di tabel berikut; baca kolom "Pilihan untuk `BDG-WS-0147`" sebagai keputusan kasus ini.

| Opsi builder | Arti [S7] | Pilihan untuk `BDG-WS-0147` |
|---|---|---|
| Target Operating System | Platform dan arsitektur biner; ada opsi Generic collector | Windows 64-bit |
| Encryption | Mengamankan ZIP hasil dengan sertifikat atau password | X.509 dengan sertifikat `jkt-velo01` |
| Collection Type | Tujuan container: Zip Archive (bawaan, di folder tempat collector dijalankan), Google Cloud Bucket, AWS Bucket, Azure SAS URL, SMB Share, SFTP Upload | Zip Archive, karena laptop tidak terhubung ke jaringan kantor |
| Concurrency | Jumlah query yang berjalan bersamaan; bawaan 2 | Bawaan |
| Pause For Prompt | Menahan terminal Windows dengan prompt di akhir | Aktif, supaya Fajar melihat bahwa koleksi selesai |
| Filename Format | Mendukung variabel lingkungan serta `%Hostname%`, `%FQDN%`, `%TIMESTAMP%` | `INC-2026-019-E20_%Hostname%_%TIMESTAMP%` |
| Output format | JSON bawaan; CSV bisa ditambahkan | JSON, karena itu yang dipakai server saat impor |

Enkripsi X.509 adalah pilihan yang direkomendasikan: password acak mengenkripsi container dan password itu dienkripsi dengan sertifikat server, sehingga server bisa mendekripsi otomatis saat impor. Password tetap tertanam di konfigurasi tidak disarankan karena siapa pun yang memegang biner bisa mengambilnya, PGP setara keamanannya tetapi tanpa dekripsi otomatis, dan tanpa enkripsi hanya untuk lab atau latihan [S6]. Container terenkripsi berbentuk ZIP luar yang berisi `data.zip` terproteksi dan `metadata.json`, sehingga nama file di dalamnya juga tersembunyi [S6].

Collector buatan GUI membutuhkan hak administrator. Di Windows bisa lewat klik kanan Run as administrator; tanpa hak admin, collector yang dibuka dari Explorer bisa menutup terlalu cepat sehingga pesan galatnya tidak terbaca [S8]. Collector menulis log dengan nama dasar yang sama dengan container [S8], dan SHA-256 container ditulis di log itu dengan pesan `Container hash` [S9]. Itu penting untuk Fajar: hash tersedia di titik koleksi tanpa alat tambahan.

Dokumentasi juga menyebut batas desain yang harus diterima: cakupan koleksi direncanakan di depan karena mengulang berarti membangun collector baru, client online lebih disukai bila endpoint bisa menjangkau server, dan offline collector berjalan tanpa batas sumber daya secara bawaan [S6]. Artikel Adaptive Collections menyarankan memakai Registry Hunter dan Triage Targets bersama untuk koleksi offline [S5]. Di kasus ini collector diisi artifact yang sama dengan hunt (bagian 1.4), supaya hasil `BDG-WS-0147` bisa dibandingkan langsung dengan lima host lain.

### 1.6 Ekspor, impor, dan kebersihan bukti

Pertanyaan kelima Dimas adalah soal bentuk bukti: hasil hunt ada di server sementara yang akan dimatikan, jadi apa yang disimpan dan bagaimana membuktikan bahwa ia tidak berubah?

Hasil hunt diekspor dengan Prepare Download. Server mengemas file upload dan data JSON dari semua collection yang terhubung ke hunt menjadi satu collection container yang bisa diimpor ke server Velociraptor lain; data CSV bisa ditambahkan di samping JSON [S15]. Waktu persiapan bawaan 10 menit; untuk ekspor sangat besar ada server artifact `Server.Utils.ExportHunt` dengan timeout lebih panjang [S15]. Fungsi VQL `create_hunt_download` melakukan hal yang sama dari notebook dan membutuhkan izin `PREPARE_RESULTS` [S15][S16].

Container offline masuk ke server dengan arah sebaliknya. Karena biasanya terlalu besar untuk diunggah lewat browser, container disalin ke server dengan SFTP atau SCP lalu diimpor dengan server artifact `Server.Utils.ImportCollection`, pembungkus fungsi VQL `import_collection` [S9]. Impor membaca `metadata.json`, mendekripsi password bila bisa, membuka `data.zip`, membuat virtual client bila belum ada client dengan hostname yang sama, lalu mengaitkan hasilnya ke client itu; container X.509 dengan sertifikat server didekripsi otomatis [S9].

Isi container perlu dikenali supaya kamu tahu apa yang di-hash dan di mana mencarinya. Tabel berikut merangkum struktur container yang tidak terenkripsi menurut dokumentasi [S9]; perhatikan baris `uploads.json`, karena di situ hash per file berada.

| Isi | Fungsi |
|---|---|
| `uploads/ntfs/`, `uploads/auto/` | File yang disalin, dipisah per accessor; backslash dan titik dua di path di-escape (misalnya `%5C%5C.%5CC%3A`) |
| `results/` | Hasil query JSON dengan pola nama `<Artifact>%2F<Source>.json` dan file `.index` |
| `log.json` | Log koleksi |
| `collection_context.json`, `requests.json`, `client_info.json` | Metadata koleksi |
| `uploads.json` | Metadata file yang disalin: path asli, ukuran, SHA-256, timestamp |
| `metadata.json` | Hanya pada skema terenkripsi: detail enkripsi |

Timestamp file disimpan di metadata JSON, bukan di timestamp ZIP [S9]. Saat diekstrak biasa, file hasil ekstraksi tidak membawa timestamp aslinya. Artifact `Windows.KapeFiles.Extract` mereplikasi timestamp yang tersimpan saat mengekstrak [S9].

Velociraptor bisa mengumpulkan dan sebagian memparse di VQL, tetapi untuk analisis mendalam artefak Windows, alur umum adalah mengekspor file mentah yang dikumpulkan (hive, `$MFT`, event log) lalu memparse dengan EZ Tools (Day 02-03) [S4]. Velociraptor menjadi mesin akuisisi, EZ Tools mesin parsing, Timeline Explorer pembacanya. Apa pun mesin koleksinya (KAPE atau Velociraptor), hasilnya masuk ke pipeline EZ Tools yang sama.

Kebersihan bukti di Velociraptor mengikuti prinsip Day 01:

- Hasil collection di server adalah bukti; catat waktu, client, dan artifact yang dipakai.
- Ekspor hasil, hash, lalu analisis atas salinan.
- Koleksi lewat agent mengubah sebagian state host (proses dan service Velociraptor berjalan); catat ini, seperti koleksi live KAPE (Day 03).
- `ExcludeSigned` dan `HashOnly` mengurangi ukuran tetapi berarti sebagian file tidak dikumpulkan utuh; sadari saat analisis, karena file yang hanya di-hash tidak bisa diparse isinya.
- Hash container dihitung sedini mungkin. Untuk offline collector, nilai `Container hash` di log adalah hash di titik koleksi [S9]; untuk ekspor hunt, hash dihitung saat ekspor selesai, sedangkan hash per file di `uploads.json` mencatat keadaan saat file disalin dari host. Cek di ekspor versi-mu apakah `uploads.json` ekspor hunt memuat SHA-256 yang sama dengan container offline.

Untuk `INC-2026-019`, ekspor hunt lima host dicatat sebagai `INC-2026-019-E19` dan container offline `BDG-WS-0147` sebagai `INC-2026-019-E20`. Keduanya disimpan master di `jkt-evid01` sebelum `jkt-velo01` dimatikan, sehingga bukti tidak bergantung pada server sementara.

### 1.7 Membaca hasil negatif: batas klaim "tidak ditemukan"

Pertanyaan terakhir Dimas adalah yang paling mudah dijawab terlalu kuat. Bila hunt tidak menemukan apa pun, godaannya menulis "enam penerima bersih". Kalimat itu tidak bisa dipertanggungjawabkan, karena hunt hanya melihat apa yang ditanyakannya.

Hasil negatif yang jujur selalu menyebut empat hal: apa yang dicari, dengan artifact dan parameter apa, kapan, dan apa yang tidak tercakup. Tabel berikut memetakan setiap pemeriksaan di hunt `INC-2026-019` ke batasnya; kolom kanan adalah kalimat yang harus ikut tertulis di temuan.

| Pemeriksaan | Yang tercakup | Yang tidak tercakup |
|---|---|---|
| Scheduled task (`Windows.System.TaskScheduler`) | Definisi task yang ada di `C:\Windows\System32\Tasks` saat koleksi [S17] | Task yang sudah dihapus; nama task yang berbeda dari IOC (dikompensasi dengan filter perilaku pada command dan argumen, bagian 2.5) |
| File (`Windows.Search.FileFinder`) | File yang ada saat koleksi di glob yang dicari [S18] | File terhapus, file di luar glob, salinan di VSS (`VSS_MAX_AGE_DAYS` tidak dipakai) |
| Prefetch (`Windows.Forensics.Prefetch`) | Riwayat eksekusi yang masih tersimpan di file `.pf`; Windows 10 menyimpan delapan waktu jalan terakhir [S19] | Eksekusi yang tidak tercatat Prefetch atau yang file `.pf`-nya sudah tertimpa atau dihapus |
| Event log (`Windows.EventLogs.EvtxHunter`) | Event di file EVTX yang ada saat koleksi, yang cocok dengan regex IOC [S20] | Event yang sudah dirotasi atau dihapus; channel yang tidak aktif (Sysmon tidak ada di laptop tanpa EDR; audit yang tidak dinyalakan, Day 05) |
| Cache DNS (`Windows.System.DNSCache`) | Entri yang masih ada di cache saat koleksi; Windows menyimpan lookup hanya sebentar [S21] | Lookup hari Senin sampai Rabu hampir pasti sudah hilang dari cache; ketiadaan entri bukan bukti apa pun |
| Triage (`Windows.Triage.Targets`) | Event log dan file yang dirujuk aturan adaptive saat koleksi [S5][S10] | Memori, unallocated space, file bertanda tangan (`ExcludeSigned`) |

Dua faktor lain menentukan seberapa kuat kesimpulan. Pertama, sumber independen: untuk empat host ber-EDR, hasil negatif di host menguatkan hasil negatif dari telemetry EDR hari Selasa, jadi ada dua sumber yang berbeda cara kerjanya. Untuk `JKT-WS-0418` dan `BDG-WS-0147`, hanya ada artefak di host dan log jaringan; bila penyerang sempat menjalankan lampiran lalu menghapus task dan file, sisa yang masih mungkin ada adalah Prefetch dan event log, dan keduanya punya batas di tabel di atas. Kedua, kontrol positif: hunt yang sama harus terbukti menemukan IOC ketika IOC memang ada. Itu sebabnya artifact dan parameter diuji dulu di lab dengan IOC tiruan (bagian 3) sebelum hasil negatif di produksi dipercaya.

Kalimat yang boleh ditulis Dimas berbentuk: "Pada koleksi Jumat 2026-10-16 (lima host lewat client Velociraptor, satu host lewat offline collector), tidak ditemukan scheduled task `\SysCacheUpdate`, file `upd.ps1` di profil pengguna, eksekusi `Tagihan-Okt-2026.js` di Prefetch, atau string C2 di event log. Ini menurunkan kemungkinan bahwa keenam penerima menjalankan lampiran. Koleksi tidak mencakup memori, file terhapus, dan log yang sudah dirotasi. Keyakinan sedang-tinggi untuk empat host ber-EDR (dua sumber independen) dan sedang untuk dua host tanpa EDR." Contoh lengkapnya, termasuk satu temuan yang bukan eksekusi, ada di bagian 2.8.

## 2. Contoh artefak dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Perintah ditulis untuk lingkungan PT JAB; untuk latihan, jalankan hanya di VM lab terisolasi (bagian 3). Waktu di catatan memakai WIB (UTC+7); Velociraptor menampilkan timestamp dalam UTC, jadi setiap waktu dari hasil query dikonversi saat ditulis ke case notes.

### 2.1 Membangun server sementara `jkt-velo01`

Langkah ini menjawab pertanyaan kedua Dimas. `jkt-velo01` adalah VM Ubuntu LTS baru di jaringan manajemen; biner Velociraptor 0.77.3 diunduh lewat proxy terbatas dan SHA-256-nya dicatat di case notes.

**Tujuan:** server dengan sertifikat self-signed yang bisa dihubungi client dari jaringan kantor Jakarta dan Bandung.

```bash
./velociraptor config generate -i
# wizard: pilih "Self Signed SSL", isi 10.20.1.30, buat user admin, terima bawaan lainnya
# hasil: server.config.yaml; ubah bagian Frontend: bind_address 127.0.0.1 -> 0.0.0.0
./velociraptor debian server --config ./server.config.yaml
sudo dpkg -i <paket-velociraptor-server>.deb
systemctl status velociraptor_server.service
nc -vz 127.0.0.1 8889
nc -vz 127.0.0.1 8000
```

- `config generate -i` menjalankan wizard interaktif dan menghasilkan `server.config.yaml` [S13].
- `bind_address` frontend diubah ke `0.0.0.0` supaya client dari host lain bisa terhubung; GUI dibiarkan sesuai kebijakan jaringan tepercaya [S13].
- `debian server` membuat paket Debian berisi konfigurasi server; setelah `dpkg -i`, service bernama `velociraptor_server.service` [S13].
- `nc -vz` memastikan port 8889 (GUI) dan 8000 (frontend) mendengarkan [S13].

Untuk lab yang hanya perlu proses di foreground, server dan client juga bisa dijalankan langsung dengan subcommand (cek perintah persis di `velociraptor -h` versi lab):

```
velociraptor config generate -i
velociraptor --config server.config.yaml frontend
velociraptor --config client.config.yaml client
```

Setelah login ke GUI, dua langkah lagi dijalankan dari layar Welcome dan Server Artifacts:

1. **Import Extra Artifacts** menjalankan `Server.Import.Extras` untuk mengimpor artifact dari sub-proyek Velociraptor, termasuk `Windows.Triage.Targets` [S13][S22]. Di PT JAB, proxy dibuka sementara untuk alamat bundle selama langkah ini.
2. `Server.Utils.CreateMSI` menghasilkan MSI client yang sudah di-repack dengan konfigurasi `jkt-velo01`; MSI diunduh dari tab Uploaded Files [S12][S13]. Dokumentasi menyarankan menandatangani ulang MSI hasil repack dengan sertifikat code signing yang sah [S12]; PT JAB tidak sempat melakukannya untuk server sementara ini, dan keputusan itu dicatat.

Keluaran ilustrasi di case notes:

```
2026-10-15 16:20  jkt-velo01 (10.20.1.30) dibuat; velociraptor 0.77.3 linux-amd64 SHA-256 dicatat.
2026-10-15 16:55  velociraptor_server.service active; 8000 dan 8889 listening.
2026-10-15 17:02  Server.Import.Extras selesai lewat proxy sementara (ditutup 17:05).
2026-10-15 17:10  Server.Utils.CreateMSI: velociraptor-inc019-amd64.msi, SHA-256 c41e... dikirim ke L1
                  (Gilang) beserta daftar 5 host dan jendela waktu pemasangan.
```

**Cara membaca hasil:** server siap bila kedua port mendengarkan, artifact `Windows.Triage.Targets` muncul di daftar artifact, dan MSI beserta hash-nya sudah dicatat.

**Kapan gagal:** frontend masih `127.0.0.1` sehingga client dari jaringan kantor tidak pernah muncul; atau `Server.Import.Extras` gagal karena server tidak punya akses keluar ke alamat bundle.

### 2.2 Mengantar client ke host ber-EDR lewat live response

Langkah ini menjawab pertanyaan ketiga Dimas untuk empat host ber-EDR. MSI dan skrip pemasang diunggah ke library live response lewat halaman Library management, karena opsi unggah dari dalam sesi butuh izin Manage Security Settings [S23].

Skrip pemasang `pasang-velo-inc019.ps1` (disimpan di repo IR, ditinjau Sari sebelum diunggah):

```powershell
param([Parameter(Mandatory)][string]$MsiPath)
$log = "C:\Windows\Temp\velo-inc019-install.log"
Start-Process msiexec.exe -ArgumentList "/i `"$MsiPath`" /qn /L*V `"$log`"" -Wait
Get-Service velociraptor | Format-List Name, Status, StartType
```

- `/i` instalasi normal, `/qn` tanpa UI, `/L*V <file>` log lengkap dengan output verbose [S25].
- `Get-Service velociraptor` memastikan service terpasang; nama service `velociraptor` mengikuti contoh `sc query velociraptor` di dokumentasi [S12].

Perintah di konsol live response `JKT-WS-0395`:

```console
library
putfile velociraptor-inc019-amd64.msi
dir -full_path
run pasang-velo-inc019.ps1 -parameters "-MsiPath <path folder kerja>\velociraptor-inc019-amd64.msi"
```

- `library` menampilkan file di library; `putfile` menaruh file dari library ke folder kerja di perangkat [S23][S24].
- Path folder kerja tidak disebut di dokumentasi yang diperiksa; ambil dari keluaran `putfile` atau `dir -full_path` lalu isi ke parameter [S24].
- `run ... -parameters "..."` menjalankan skrip library dengan argumen. Parameter tidak boleh memuat karakter `;`, `&`, `|`, `!`, dan `$` [S24].

Keluaran ilustrasi (bagian akhir skrip):

```
Name      : velociraptor
Status    : Running
StartType : Automatic
```

**Cara membaca hasil:** service berjalan, lalu client `JKT-WS-0395` muncul di kolom pencarian client `jkt-velo01`. Beri label `inc-2026-019` pada client itu di GUI. Waktu pemasangan dicatat dari tab Command log.

**Variasi:** bila skrip tanpa tanda tangan ditolak, opsi yang aman adalah menandatangani skrip dengan sertifikat internal; mengaktifkan "unsigned script execution" berlaku untuk seluruh tenant dan menambah risiko [S23].

**Kapan gagal:** perangkat offline (live response butuh perangkat terhubung), file lebih besar dari batas library atau `putfile`, perintah `run` melewati batas 30 menit, atau perangkat sedang dalam sesi live response orang lain [S23]. `JKT-WS-0405` gagal Kamis sore karena laptop Lia offline; pemasangan diulang Jumat 10:20.

### 2.3 Mengantar client ke `JKT-WS-0418` tanpa EDR

Langkah ini adalah jalan manual untuk host tanpa EDR di jaringan kantor. Wawan diminta membiarkan laptopnya menyala Kamis sore; Yoga menjalankan langkah dari `JKT-JUMP01` dengan `adm.yoga`.

```
copy velociraptor-inc019-amd64.msi \\JKT-WS-0418\C$\Windows\Temp\
<alat eksekusi jarak jauh yang disetujui> \\JKT-WS-0418 msiexec.exe /i C:\Windows\Temp\velociraptor-inc019-amd64.msi /qn /L*V C:\Windows\Temp\velo-inc019-install.log
```

- Penyalinan lewat admin share `C$` dan eksekusi jarak jauh mengikuti pola yang disebut dokumentasi Velociraptor (contohnya memakai `net use`, salin ke `C$`, lalu menjalankan dari jarak jauh; alat yang disebut termasuk PsExec dan WinRM) [S8].
- Alat eksekusinya dipilih dari yang sudah disetujui Infrastruktur PT JAB; sintaks persisnya mengikuti alat itu.

**Cara membaca hasil:** client `JKT-WS-0418` muncul di `jkt-velo01`, diberi label `inc-2026-019`. Di case notes ditulis: waktu penyalinan, waktu eksekusi, akun yang dipakai, dan bahwa pemasangan membuat service dan file baru di host.

**Kapan gagal:** admin share atau eksekusi jarak jauh diblokir kebijakan; firewall host menolak; laptop dibawa pulang sebelum langkah selesai. Rencana cadangannya adalah offline collector yang sama dengan `BDG-WS-0147`, dijalankan Yoga di meja Wawan.

### 2.4 Menyusun hunt `INC-2026-019`

Langkah ini menjawab pertanyaan keempat Dimas dengan isi yang konkret. Sebelum hunt dibuat, artifact yang sama dijalankan sebagai collection tunggal ke `JKT-WS-0395` Kamis 18:40 untuk mengukur durasi dan memastikan parameter benar, sesuai saran dokumentasi untuk menguji di satu atau dua endpoint dulu [S14].

Tabel berikut adalah isi hunt. Kolom "Parameter" adalah nilai yang ditulis di wizard; kolom "Pertanyaan" menunjukkan kenapa artifact itu ada.

| Artifact | Parameter | Pertanyaan |
|---|---|---|
| `Windows.System.TaskScheduler` | `AlsoUpload=N`, `UploadCommands=N` | Ada task `\SysCacheUpdate`, atau task lain yang menjalankan PowerShell dari `AppData\Roaming`? |
| `Windows.Search.FileFinder` | `SearchFilesGlobTable`: `C:\Users\*\AppData\Roaming\SysCache\**` dan `C:\Users\*\**\Tagihan-Okt-2026*`; `Calculate_Hash=Y`; `Upload_File=N` | Ada `upd.ps1` atau lampiran di profil pengguna? |
| `Windows.Forensics.Prefetch` | `binaryRegex`: `WSCRIPT\|CSCRIPT\|POWERSHELL`; `dateAfter`: `2026-10-12T08:00:00Z`; `IncludeFilesAccessed=Y` | Ada eksekusi script host atau PowerShell sejak Senin 15:00 WIB, dan file apa yang disentuhnya? |
| `Windows.EventLogs.EvtxHunter` | `IocRegex`: lihat blok di bawah; `DateAfter`: `2026-10-12T08:00:00Z` | Ada string IOC di event log mana pun? |
| `Windows.System.DNSCache` | tanpa parameter | Ada entri C2 di cache DNS saat ini? |
| `Windows.Triage.Targets` | `HighLevelTargets=_Live`, `Targets=EventLogs`, `CollectionPolicy=ExcludeSigned` | Preservasi event log dan biner tidak bertanda tangan yang dirujuk task, service, proses, Prefetch, dan shortcut |

Regex IOC untuk `EvtxHunter`:

```
(?i)cdn-sync\.example\.net|203\.0\.113\.77|SysCacheUpdate|upd\.ps1|Tagihan-Okt-2026
```

- `(?i)` membuat pencarian tidak peka huruf besar dan kecil.
- Titik di nama domain dan IP di-escape supaya hanya cocok dengan titik.
- `dateAfter` 08:00 UTC sama dengan Senin 15:00 WIB, hampir satu jam sebelum email masuk pukul 15:58. Batas ini sengaja dilebarkan supaya selisih jam host tidak memotong event yang relevan.
- `EvtxHunter` membaca semua EVTX dan disebut bisa berat di endpoint [S20]; untuk enam laptop beban itu diterima, tetapi uji durasinya di collection tunggal.

Pengaturan hunt: deskripsi `INC-2026-019 enam penerima lain`, target label `inc-2026-019`, kedaluwarsa Jumat 2026-10-16 17:00 (lebih pendek dari bawaan satu minggu, supaya hunt tidak terjadwal ke client lain yang kebetulan diberi label belakangan) [S14]. Hunt dibuat Kamis 19:10 dalam keadaan `Paused` dan di-Start Jumat 09:00.

**Kapan gagal:** label tidak dipasang pada client, sehingga hunt berjalan tanpa target; atau hunt dibuat tetapi tidak pernah di-Start.

### 2.5 Membaca hasil hunt di notebook

Langkah ini mengubah baris hasil menjadi jawaban per host. Setiap hunt punya notebook, dan hasilnya bisa dibaca dengan plugin `hunt_results` dengan parameter `hunt_id`, `artifact`, dan `source` opsional [S14][S27].

**Tujuan:** menemukan task yang cocok dengan IOC atau dengan perilaku yang sama, bukan hanya nama yang sama.

```
SELECT ClientId, TaskName, Command, Arguments, UserId
FROM hunt_results(hunt_id="H.D1K7Q3", artifact="Windows.System.TaskScheduler", source="Analysis")
WHERE TaskName =~ "(?i)SysCache"
   OR (Command =~ "(?i)powershell" AND Arguments =~ "(?i)AppData.Roaming")
```

- `hunt_id` adalah ID hunt di Hunt Manager; `H.D1K7Q3` adalah contoh.
- `source="Analysis"` adalah nama source artifact `Windows.System.TaskScheduler` [S17].
- `=~` adalah pencocokan regex VQL. Titik di `AppData.Roaming` sengaja dipakai sebagai wildcard untuk backslash, supaya tidak perlu memikirkan escaping di string VQL.
- Kolom `TaskName`, `Command`, `Arguments`, `UserId` berasal dari artifact [S17]. Cek apakah kolom `ClientId` ikut di baris hasil versi-mu; bila tidak, gabungkan dengan daftar client hunt.

Keluaran ilustrasi: nol baris.

Kueri status per host memakai artifact yang sama tanpa filter, dihitung per client. Tabel berikut adalah ringkasan status Jumat 11:00 yang ditulis ke case notes (waktu sudah dikonversi ke WIB).

| Host | Client terpasang | Hunt selesai | Baris task | Upload triage |
|---|---|---|---|---|
| `JKT-WS-0395` | Kamis 17:48 | Jumat 09:24 | 142 | 312 MB |
| `JKT-WS-0397` | Kamis 17:55 | Jumat 09:21 | 139 | 296 MB |
| `JKT-WS-0405` | Jumat 10:24 | Jumat 10:48 | 145 | 341 MB |
| `JKT-WS-0418` | Kamis 17:35 | Jumat 09:41 | 137 | 288 MB |
| `BDG-WS-0151` | Kamis 18:12 | Jumat 09:33 | 141 | 305 MB |
| Total lima host | | | 704 | 1.542 MB |

Hasil pemeriksaan IOC dirangkum di tabel kedua. Baca kolom "Catatan", karena dua baris berisi hasil yang bukan nol dan perlu dijelaskan.

| Pemeriksaan | Hasil lima host | Catatan |
|---|---|---|
| Task `SysCache` atau PowerShell dari `AppData\Roaming` | 0 | Task dengan command di `AppData` hanya OneDrive Standalone Update Task di `AppData\Local`, di kelima host |
| File `AppData\Roaming\SysCache\**` | 0 | |
| File `Tagihan-Okt-2026*` | 1 | `C:\Users\eko.prasetyo\Downloads\Tagihan-Okt-2026.zip`, BTime `2026-10-12T09:21:37Z` (16:21 WIB), hash dicatat |
| Prefetch `WSCRIPT`/`CSCRIPT`/`POWERSHELL` sejak Senin | 5 host punya `WSCRIPT.EXE`; 3 host punya `POWERSHELL.EXE` | `WSCRIPT.EXE` semua dari logon script `map-drive.vbs`; `FilesAccessed` kedua executable tidak memuat `Tagihan-Okt-2026.js` atau path `SysCache` |
| `EvtxHunter` regex IOC | 0 | |
| Cache DNS `cdn-sync.example.net` | 0 | Tidak bermakna sebagai bukti (bagian 1.7) |

**Cara membaca hasil:** satu-satunya kecocokan IOC adalah ZIP lampiran yang tersimpan di folder Downloads Eko, tanpa `.js` hasil ekstraksi di profilnya dan tanpa eksekusi `Tagihan-Okt-2026.js` di Prefetch. Artinya lampiran disimpan, tetapi tidak ada tanda dijalankan di artefak yang dikumpulkan. Temuan itu dilaporkan ke Dimas pukul 11:05, file dihapus oleh tim IT setelah hash dan path dicatat, dan EDR `JKT-WS-0397` dicek ulang untuk event pembukaan ZIP.

**Variasi:** kueri yang sama untuk `Windows.Forensics.Prefetch` dengan filter `FilesAccessed =~ "(?i)Tagihan"` langsung menjawab "apakah ada script host yang menyentuh file lampiran".

**Kapan gagal:** filter terlalu sempit (hanya nama task), sehingga varian nama dari penyerang terlewat; atau timestamp UTC ditulis sebagai WIB.

### 2.6 Offline collector untuk `BDG-WS-0147`

Langkah ini menyelesaikan pertanyaan ketiga Dimas untuk laptop Ratih. Collector dibangun Kamis 19:30 dengan opsi di bagian 1.5 dan artifact yang sama dengan hunt.

Pengiriman collector ke Fajar memakai dua kanal. Biner `Collector_velociraptor-v0.77.3-windows-amd64.exe` ditaruh di share internal sementara yang hanya bisa dibaca akun Fajar, dan SHA-256 biner dikirim terpisah lewat grup Signal "JAB-CSIRT-OOB". Fajar mencocokkan hash sebelum menyalin collector ke `USB-E-12`, media bukti yang sudah disiapkan di POP Bandung. Karena container dienkripsi dengan sertifikat `jkt-velo01` dan tipe koleksinya Zip Archive, collector tidak membawa kredensial unggah apa pun.

Ratih mampir ke POP Bandung Jumat siang. Langkah Fajar, yang dibacakan Yoga lewat telepon:

1. Catat waktu laptop (`Get-Date -Format o`) dan nomor seri di formulir.
2. Colok `USB-E-12`, klik kanan collector, pilih Run as administrator dengan akun admin teknisi POP.
3. Tunggu sampai prompt di akhir muncul (Pause For Prompt); jangan menutup jendela lebih awal.
4. Buka file log dengan nama dasar yang sama dengan container di `USB-E-12`, cari baris `Container hash`, kirim nilainya lewat Signal.
5. Lepas `USB-E-12`, masukkan ke kantong bukti, isi formulir chain of custody.

Keluaran ilustrasi (cuplikan baris di log collector, disederhanakan):

```
... Container hash 5be1...  INC-2026-019-E20_BDG-WS-0147_<timestamp>.zip
```

Fajar juga menyalin container terenkripsi itu ke share sementara untuk analisis cepat, sementara `USB-E-12` dikirim sebagai master. Formulir chain of custody untuk E20 berikut menunjukkan kapan hash mulai ada; bandingkan dengan formulir laptop di Day 01, di mana hash baru ada setelah image dibuat.

| Item | Deskripsi | SHA-256 | Dari | Ke | Waktu (WIB) | Tujuan |
|---|---|---|---|---|---|---|
| E20 | Container offline `BDG-WS-0147` di `USB-E-12` | `5be1...` (`Container hash` di log) | `BDG-WS-0147`, collector dijalankan Fajar | `USB-E-12` | 2026-10-16 14:06 | Koleksi selesai (mulai 13:40) |
| E20-C | Salinan elektronik container | `5be1...` (dicek di `jkt-evid01`: cocok) | Fajar (POP Bandung) | `jkt-evid01` lewat share sementara | 2026-10-16 14:40 | Analisis cepat |
| E20 | `USB-E-12`, kantong bukti No. 0093 | `5be1...` | Fajar Nugraha | Kurir internal, resi `INT-1016-027` | 2026-10-16 15:30 | Pengiriman master ke Jakarta |
| E20 | idem | `5be1...` (verifikasi ulang: cocok) | Kurir internal | Yoga Pratama | 2026-10-19 08:45 | Diterima, segel utuh; master ke `jkt-evid01` |

**Cara membaca hasil:** hash di titik koleksi berasal dari collector sendiri, jadi salinan elektronik dan media fisik bisa diverifikasi terhadap nilai yang sama.

**Kapan gagal:** collector dijalankan tanpa hak admin dan menutup tanpa pesan [S8]; jendela ditutup sebelum selesai; atau nilai `Container hash` tidak dikirim, sehingga hash pertama baru dihitung di Jakarta.

### 2.7 Ekspor E19, impor E20, dan parsing dengan EZ Tools

Langkah ini menjawab pertanyaan kelima Dimas: hasil keluar dari server sementara dan menjadi bukti di `jkt-evid01`.

**Ekspor hunt (E19).** Di Hunt Manager, Prepare Download untuk hunt `H.D1K7Q3`, dengan CSV ditambahkan. Persiapan berjalan 11:30 sampai 11:44; container diunduh ke `JKT-DFIR01`, lalu disalin ke `jkt-evid01`:

```bash
sha256sum INC-2026-019-E19_hunt-H.D1K7Q3.zip | tee INC-2026-019-E19_hunt-H.D1K7Q3.zip.sha256
sha256sum -c INC-2026-019-E19_hunt-H.D1K7Q3.zip.sha256
```

Keluaran ilustrasi: `a7c3...  INC-2026-019-E19_hunt-H.D1K7Q3.zip`, lalu `INC-2026-019-E19_hunt-H.D1K7Q3.zip: OK`. Ukuran container sekitar 1,09 GB, lebih kecil dari total upload 1.542 MB karena event log terkompresi baik.

**Impor container offline (E20).** Salinan `E20-C` disalin ke `jkt-velo01` dengan SCP, lalu diimpor:

```
Server Artifacts > Server.Utils.ImportCollection   (isi path container di server)
```

atau dari notebook:

```
SELECT import_collection(filename="/srv/import/INC-2026-019-E20_BDG-WS-0147_<timestamp>.zip")
FROM scope()
```

- Container X.509 dengan sertifikat server didekripsi otomatis [S9].
- Hasilnya muncul sebagai virtual client `BDG-WS-0147` di Collected Artifacts [S9].
- Kueri notebook yang sama dengan bagian 2.5 dijalankan ke collection ini. Keluaran ilustrasi: nol task, nol file IOC, `WSCRIPT.EXE` hanya dari `map-drive.vbs`, nol hit `EvtxHunter`, tanpa entri C2 di cache DNS.

**Ekstraksi untuk EZ Tools.** Ekstrak salinan kerja dengan mempertahankan timestamp:

```
velociraptor artifacts collect Windows.KapeFiles.Extract --args ContainerPath=<salinan-kerja>.zip --args OutputDirectory=D:\Cases\INC-2026-019\E19-W1\
```

- `Windows.KapeFiles.Extract` mereplikasi timestamp yang tersimpan di metadata [S9].
- Container terenkripsi perlu didekripsi dulu, misalnya dengan `velociraptor --config server.config.yaml unzip <zip> --dump_dir ./output/` untuk X.509 dengan sertifikat server [S9].

Lalu parse artefak dengan EZ Tools, misalnya `$MFT` bila target itu ikut dikumpulkan di koleksi lain:

```
MFTECmd.exe -f ".\triage\C\$MFT" --csv ".\analysis" --csvf mft.csv
```

- Struktur folder di dalam container Velociraptor berbeda dari KAPE: file asli berada di bawah `uploads/ntfs/` atau `uploads/auto/` dengan path yang di-escape [S9]. Sesuaikan path `-f` dengan hasil ekstraksi; cek struktur persisnya di lab.
- Hasil CSV dibaca di Timeline Explorer, sama seperti alur KAPE (Day 03).

Lewat CLI, artifact juga bisa dijalankan lokal tanpa server, mirip offline collector:

```
velociraptor artifacts collect Windows.Triage.Targets --args Devices=C: --output triage.zip
```

- `artifacts collect` menjalankan artifact secara lokal dan menulis hasil ke arsip. Nama parameter drive di halaman artifact adalah `Devices` dengan bawaan `["C:"]` [S10], jadi argumen ini biasanya bisa dihilangkan; cek format nilainya dan flag `--output` di `velociraptor artifacts collect -h`.
- Karena `Windows.Triage.Targets` tidak bawaan, definisinya harus tersedia untuk biner lokal; README proyek triage memakai opsi `--definitions` (`-D`) untuk memuat definisi dari direktori, dengan sintaks berbeda untuk 0.76 ke atas dan versi lebih lama [S28].

**Kapan gagal:** ekspor besar berhenti di batas 10 menit (pakai `Server.Utils.ExportHunt`) [S15]; container PGP atau X.509 dengan sertifikat lain tidak terdekripsi otomatis saat impor [S9]; path `-f` EZ Tools masih memakai struktur KAPE.

### 2.8 Temuan untuk scope statement, DPO, dan pembersihan

Langkah ini menjawab pertanyaan keenam Dimas. Draf berikut dikirim ke Dimas Senin 2026-10-19 09:30, setelah master E20 diterima dan diverifikasi.

```
INC-2026-019 | Temuan koleksi enam penerima lain | Analyst: <kamu> | TZ: WIB
Dasar: E19 (ekspor hunt H.D1K7Q3, 5 host, Jumat 2026-10-16 09:00-11:30), E20 (offline collector
       BDG-WS-0147, Jumat 13:40-14:06). Artifact dan parameter: lampiran case notes 2026-10-15 19:10.
Hasil: tidak ditemukan task \SysCacheUpdate atau task PowerShell dari AppData\Roaming, file upd.ps1
       di profil pengguna, eksekusi Tagihan-Okt-2026.js di Prefetch, atau string IOC di event log,
       di keenam host.
       Ditemukan Tagihan-Okt-2026.zip tersimpan di Downloads JKT-WS-0397 (eko.prasetyo), tanpa tanda
       eksekusi di artefak yang dikumpulkan; file dihapus IT 2026-10-16 11:40 setelah hash dicatat.
Batas: tidak mencakup memori, file terhapus, VSS, log yang sudah dirotasi; cache DNS tidak bermakna.
       JKT-WS-0418 dan BDG-WS-0147 tanpa EDR: hanya artefak host + log jaringan.
       Kontrol positif: artifact dan parameter yang sama menemukan IOC tiruan di lab CASE-2026-LAB-004.
Keyakinan: sedang-tinggi (4 host ber-EDR), sedang (2 host tanpa EDR).
Tindak lanjut bila ada informasi baru: host yang terindikasi pindah ke pola memori + image.
```

Rencana pembersihan ditulis di case notes yang sama, supaya server sementara tidak tertinggal:

1. Client dicopot dengan `msiexec /x` dan MSI yang sama [S25], lewat live response untuk host ber-EDR dan lewat jalan manual untuk `JKT-WS-0418`. File writeback (`velociraptor.writeback.yaml`) secara bawaan dibiarkan oleh installer [S12]; cek dan hapus manual bila tidak dibutuhkan lagi.
2. E19 dan E20 sudah menjadi master di `/evidence/INC-2026-019/` di `jkt-evid01`; notebook diekspor sebagai lampiran.
3. `jkt-velo01` dimatikan setelah kasus ditutup, dan aturan firewall TCP 8000 dihapus.

**Kapan gagal:** temuan ditulis tanpa baris "Batas", sehingga pembaca memahami "tidak ditemukan" sebagai "tidak ada"; atau server sementara dibiarkan menyala dengan client yang masih terpasang.

### 2.9 Memilih KAPE atau Velociraptor

Tabel ini membantu memilih alat koleksi di kasus berikutnya. Cari baris yang paling mirip situasimu.

| Situasi | Pilihan |
|---|---|
| Satu host, akses langsung dengan media | KAPE (Day 03) |
| Banyak host, dari jarak jauh | Velociraptor hunt koleksi |
| Butuh adaptive collection (file berdasarkan artefak) | Velociraptor |
| Host tanpa agent, satu kali | Velociraptor offline collector atau KAPE |
| Lingkungan sudah ada agent Velociraptor | Velociraptor |

Keduanya menghasilkan artefak yang diparse pipeline EZ Tools yang sama; pilihannya soal jangkauan dan akses, bukan hasil akhir.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** VM korban `LAB-WS01` (Windows 11, Sysmon, snapshot `bersih-2026-10-15`), VM analisis `LAB-DFIR01`, dan VM server `LAB-VELO01` (Ubuntu LTS, `172.16.50.30`) di jaringan host-only `172.16.50.0/24` (Day 02). Folder kasus `CASE-2026-LAB-004`. Biner Velociraptor sesuai versi di case notes. Jangan memakai data, nama, atau kejadian dari pekerjaan nyata.

1. **Server.** Bangun `LAB-VELO01` dengan langkah bagian 2.1 (Self Signed SSL, `bind_address` frontend `0.0.0.0`). Catat versi dan SHA-256 biner di case notes.
2. **Artifact tambahan.** Jalankan Import Extra Artifacts. Bila lab tidak punya akses internet, unduh bundle di luar lab lalu bawa masuk; cek cara impor bundle dari file lokal di dokumentasi versi-mu. Pastikan `Windows.Triage.Targets` muncul.
3. **Client.** Buat MSI dengan `Server.Utils.CreateMSI` dan pasang di `LAB-WS01` (bagian 2.2, tanpa live response), atau jalankan client interaktif dengan `velociraptor.exe --config client.config.yaml client -v` [S12]. Beri label `lab-004`.
4. **Kontrol positif.** Di `LAB-WS01`, buat IOC tiruan yang tidak berbahaya: folder `C:\Users\<user-lab>\AppData\Roaming\SysCache\`, file `upd.ps1` berisi satu baris `Write-Output "lab"`, dan scheduled task `\LabSysCacheUpdate` yang menjalankan `powershell.exe -NoProfile -File` ke file itu setiap hari. Jalankan task sekali secara manual supaya ada jejak di Prefetch dan event log.
5. **Hunt.** Buat hunt dengan isi bagian 2.4 (ganti regex menjadi `(?i)SysCache|upd\.ps1` untuk lab), target label `lab-004`, lalu Start. Hasil yang diharapkan: task, file, dan event ditemukan.
6. **Kontrol negatif.** Kembalikan `LAB-WS01` ke snapshot `bersih-2026-10-15`, pasang client lagi, jalankan hunt baru dengan artifact yang sama. Hasil yang diharapkan: nol. Tulis tabel batas seperti bagian 1.7 untuk hasil ini.
7. **Hash dan ekspor.** Prepare Download untuk hunt langkah 5, hash container, simpan ke `hashes.txt`, ekstrak ke folder analysis dengan `Windows.KapeFiles.Extract` (bagian 2.7).
8. **Parse.** Parse satu event log dan, bila dikumpulkan, `$MFT` dari koleksi dengan EZ Tools; baca di Timeline Explorer. Bandingkan dengan koleksi KAPE Day 03: artefak yang sama atau tidak, dan di mana bedanya struktur folder.
9. **Offline collector.** Buat offline collector Windows dengan enkripsi X.509, Zip Archive, dan Pause For Prompt. Jalankan sebagai administrator di `LAB-WS01` (setelah snapshot), salin container ke `LAB-DFIR01`, cocokkan SHA-256 dengan `Container hash` di log, lalu impor ke `LAB-VELO01` dengan `Server.Utils.ImportCollection`. Bandingkan hasilnya dengan koleksi lewat agent.
10. **Adaptive.** Bandingkan koleksi `Windows.Triage.Targets` dengan `Targets=Prefetch` saja dan dengan `HighLevelTargets=_Live`; amati file tambahan yang dikumpulkan aturan adaptive.
11. **Catat.** Tulis case notes: artifact, parameter (`CollectionPolicy`, target), waktu dalam UTC dan WIB, hash, versi Velociraptor, dan waktu pemasangan client.

**Hasil yang sebaiknya tersimpan:**

- Server dan client berjalan; client terlihat di GUI dengan label.
- Hunt kontrol positif menemukan IOC tiruan; hunt kontrol negatif tidak, dengan tabel batasnya.
- Container ekspor dan container offline di-hash dan cocok dengan nilai di log.
- Artefak diparse dengan EZ Tools dan dibaca di Timeline Explorer.
- Catatan kasus dengan artifact, parameter, hash, versi, dan zona waktu.

**Variasi tantangan:** jalankan koleksi dengan `ExcludeSigned` dan dengan `AllFiles`, lalu bandingkan ukuran arsip dan jumlah file. Tulis trade-off: `ExcludeSigned` memperkecil koleksi tetapi melewatkan biner bertanda tangan yang kadang disalahgunakan. Biner seperti ini disebut LOLBin (living-off-the-land binary): program bawaan Windows bertanda tangan Microsoft, misalnya `certutil.exe`, `rundll32.exe`, atau `mshta.exe`, yang dipakai penyerang untuk mengunduh atau menjalankan sesuatu tanpa membawa alat sendiri. Bila penyerang menyalin LOLBin ke lokasi lain atau mengganti namanya, salinan itu tetap bertanda tangan dan bisa terlewat oleh `ExcludeSigned`. Putuskan kapan kamu akan menonaktifkannya, dan cek juga efek `TrustedPathRegex` terhadap file di bawah `C:\Windows\`.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat membangun server sementara, mengantar client, dan memindahkan hasil. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Client tidak muncul di server | Frontend masih `bind_address: 127.0.0.1`; TCP 8000 diblokir; konfigurasi client salah | Cek konfigurasi frontend [S13]; `nc -vz` dari jaringan client; jaringan host-only menjangkau server |
| Artifact koleksi tidak ditemukan | `Windows.Triage.Targets` tidak bawaan sejak 0.75 | Jalankan `Server.Import.Extras`; pastikan server bisa menjangkau alamat bundle [S11][S22] |
| Hunt tidak punya client | Hunt masih `Paused`; label belum dipasang; hunt sudah kedaluwarsa | Start hunt; pasang label; buat hunt baru bila perlu [S14] |
| Client baru tidak menerima hunt | Client sudah pernah menerima hunt itu, atau tidak cocok kondisi | Setiap client hanya menerima satu hunt sekali; cek label [S14] |
| Koleksi sangat besar | `AllFiles`; target luas; `VSS_MAX_AGE_DAYS` aktif pada event log | Kembali ke `ExcludeSigned`; persempit target [S1][S10] |
| File hanya hash, tidak bisa diparse | `HashOnly` aktif | Pakai `ExcludeSigned` untuk artefak yang perlu diparse [S1][S10] |
| Struktur arsip tak cocok path EZ Tool | Layout container Velociraptor beda dari KAPE (`uploads/ntfs/`, path di-escape) | Ekstrak dengan `Windows.KapeFiles.Extract`; sesuaikan path [S9] |
| Offline collector menutup seketika | Dijalankan tanpa hak admin dari Explorer | Run as administrator; jalankan dari terminal untuk melihat pesannya [S8] |
| Offline collector gagal atau perilakunya seperti biner biasa | Collector dijalankan dengan argumen; konfigurasi collector salah | Jalankan tanpa argumen; buat ulang lewat builder atau file spec [S7][S8] |
| Impor container gagal | Skema PGP atau X.509 dengan sertifikat lain | Dekripsi manual (`pk_decrypt`, atau `decrypt`/`unzip` CLI) [S9] |
| Ekspor hunt seperti macet | Kompresi file tunggal besar; batas 10 menit | Tunggu dan cek progres; pakai `Server.Utils.ExportHunt` [S15] |
| `putfile` atau unggah library gagal | File melebihi 300 MB (`putfile` Windows) atau 250 MB (library) | Pecah atau perkecil paket; cek ukuran MSI [S23] |
| `run` ditolak di live response | Skrip tanpa tanda tangan dan pengaturan unsigned tidak aktif | Tandatangani skrip; atau aktifkan pengaturan dengan persetujuan [S23] |
| Alert EDR saat client dipasang | Instalasi Velociraptor dipantau karena pernah disalahgunakan | Cocokkan hash MSI dan jendela waktu yang sudah diberikan ke L1 [S26] |

## 5. Kesalahan umum dan jebakan

- **Menulis "tidak ditemukan" sebagai "bersih".** Hasil negatif hanya berlaku untuk artifact, parameter, waktu, dan sumber yang dipakai. Tulis batasnya (bagian 1.7).
- **Percaya hasil negatif tanpa kontrol positif.** Regex yang salah escape atau glob yang salah path menghasilkan nol baris yang terlihat sama dengan "tidak ada". Uji dulu dengan IOC tiruan di lab.
- **Mencari nama IOC saja.** Penyerang bisa mengganti nama task di host lain. Tambahkan filter perilaku (PowerShell dari `AppData\Roaming`).
- **Menganggap koleksi lewat agent tidak mengubah host.** Proses dan service Velociraptor berjalan, file dipasang; catat seperti koleksi live (Day 03).
- **Lupa `ExcludeSigned`/`HashOnly` berarti sebagian file tidak utuh.** File yang hanya di-hash tidak bisa diparse isinya; `TrustedPathRegex` juga bisa melewatkan file di bawah `C:\Windows\`.
- **Tidak hash hasil koleksi.** Perlakukan hasil sebagai bukti; hash dan analisis atas salinan (Day 01).
- **Menulis timestamp UTC dari Velociraptor sebagai WIB.** Selisih tujuh jam membuat temuan bertentangan dengan timeline SIEM.
- **Membiarkan server sementara dan client tetap terpasang.** Server IR yang terlupakan adalah permukaan serangan; Talos melaporkan Velociraptor versi lama dipakai penyerang [S26], dan dokumentasi meminta update ke 0.77.3 karena beberapa CVE [S6].
- **Memakai Velociraptor untuk satu host yang mudah diakses langsung** padahal KAPE lebih sederhana.
- **Mengira Velociraptor menggantikan full image.** Untuk unallocated space dan file terhapus tetap perlu imaging (Day 01).
- `[komunitas, belum terkonfirmasi]` Velociraptor banyak dipakai sebagai mesin akuisisi lintas fleet lalu artefaknya diparse EZ Tools; nama artifact dan parameter berubah antar versi, jadi konfirmasi di versi lab [S1][S2].

## 6. Catatan terkini

Bagian ini menampung detail versi dan perubahan dokumentasi yang bisa berubah lagi. Berguna saat membuka sumbernya, tetapi tidak mengubah alur keputusan di atas.

- Velociraptor 0.77.3 (5 Oktober 2026) masih rilis terbaru per 2026-10-16; halaman rilis juga memuat 0.77.2 dan 0.76.7 (10 Agustus) [S3]. Banner dokumentasi meminta update ke 0.77.3 untuk menutup beberapa CVE dari advisori 0.77.2 [S6]. Perbarui untuk CVE.
- Sejak 0.75, target KapeFiles dikelola di proyek terpisah; `Windows.Triage.Targets` (nama baru `Windows.KapeFiles.Targets`) harus diimpor, misalnya lewat `Server.Import.Extras` atau tombol Import Extra Artifacts di layar Welcome [S5][S11][S13]. Artifact koleksi triage dengan `ExcludeSigned` dan `HashOnly` adalah pendekatan adaptive collection yang direkomendasikan (Day 01) [S1].
- Ejaan meta-target berbeda antar sumber: `_SANS_Triage` di halaman artifact [S10], `_SansTriage` di artikel Adaptive Collections (28 September 2025) [S5].
- Offline Collector builder bisa dibuka dari layar Welcome sejak 0.75, dan file spec untuk membangun ulang collector tersedia sejak 0.75.5 [S7]. Generic collector (konfigurasi terpisah dari biner) wajib di macOS karena konfigurasi tertanam membatalkan tanda tangan kode, dengan batas 100 MB setelah ekstraksi [S6].
- Cisco Talos (9 Oktober 2025, diperbarui 17 Oktober 2025) melaporkan penyerang memakai Velociraptor 0.73.4.0 yang rentan CVE-2025-6264 dalam serangan ransomware [S26].
- Halaman live response Microsoft Defender for Endpoint yang diperiksa bertanggal 2026-07-28: batas 50 sesi bersamaan, timeout tidak aktif 30 menit, batas perintah 10 menit kecuali `getfile`, `findfile`, dan `run` yang 30 menit, lima sesi per pengguna, satu sesi per perangkat [S23].
- Apa pun mesin koleksinya (KAPE atau Velociraptor), pipeline parsing EZ Tools dan pembacaan Timeline Explorer sama (Day 02-03).

## 7. Cheat sheet

```
PERAN      client (agent) | server (frontend :8000, GUI :8889) | artifact (VQL+param) | offline collector
SERVER     config generate -i (Self Signed SSL) ; Frontend bind_address 0.0.0.0 ; debian server
           Import Extra Artifacts = Server.Import.Extras (Windows.Triage.Targets TIDAK bawaan sejak 0.75)
CLIENT     Server.Utils.CreateMSI -> msiexec /i <msi> /qn /L*V <log> ; copot: msiexec /x <msi>
           EDR: library -> putfile <msi> -> run <skrip.ps1> -parameters "..." (Command log tercatat)
           tanpa EDR: admin share + eksekusi jarak jauh yang disetujui ; catat jejak pemasangan
TRIAGE     Windows.Triage.Targets: CollectionPolicy ExcludeSigned (default) | HashOnly | AllFiles
           HighLevelTargets _Live (adaptive) | _BasicCollection | _KapeTriage | _SANS_Triage
           cek: TrustedPathRegex ^C:\\Windows\\ ; MaxFileSize ; VSS_MAX_AGE_DAYS
PERTANYAAN TaskScheduler | Search.FileFinder | Forensics.Prefetch | EventLogs.EvtxHunter | System.DNSCache
HUNT       New Hunt -> Paused -> Start ; label ; kedaluwarsa (default 1 minggu) ; 1 client = 1 kali
           uji di 1-2 host dulu ; notebook: hunt_results(hunt_id=, artifact=, source=)
OFFLINE    builder = Server.Utils.CreateCollector ; X.509 ; Zip Archive ; Pause For Prompt
           jalankan TANPA argumen, sebagai admin ; log: "Container hash" = SHA-256 di titik koleksi
EKSPOR     Prepare Download (hunt -> 1 container) ; besar: Server.Utils.ExportHunt
IMPOR      salin (SCP/SFTP) -> Server.Utils.ImportCollection / import_collection()
EKSTRAK    Windows.KapeFiles.Extract (timestamp dipertahankan) -> hash -> EZ Tools -> Timeline Explorer
NEGATIF    "tidak ditemukan oleh <artifact+param> pada <waktu>; tidak mencakup <...>; keyakinan <...>"
           + kontrol positif di lab ; host tanpa EDR = satu sumber di host + log jaringan
PILIH      1 host akses langsung -> KAPE | banyak/jauh/adaptive -> Velociraptor ; hasil ke pipeline EZ yang sama
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Hunt di enam penerima tidak menemukan `\SysCacheUpdate`, `upd.ps1`, atau string C2, jadi keenam penerima terbukti tidak terdampak." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Hasil negatif hanya berlaku untuk artifact, parameter, waktu, dan sumber yang dipakai. Koleksi tidak mencakup memori, file terhapus, VSS, dan log yang sudah dirotasi; cache DNS hampir pasti sudah tidak memuat lookup hari Senin; dan dua host tanpa EDR hanya punya artefak host dan log jaringan sebagai sumber. Kalimat yang tepat menyebut apa yang dicari, kapan, batasnya, dan tingkat keyakinan per kelompok host. Lihat bagian 1.7 dan 2.8.

</details>

**2. Skenario keputusan.** Kamis sore, client harus dipasang di `JKT-WS-0418` milik Wawan yang tidak punya EDR. Pilihan mana yang tepat?

- A. Pasang lewat live response Defender seperti empat host lain.
- B. Yoga menyalin MSI lewat admin share dari `JKT-JUMP01` dengan `adm.yoga`, menjalankan `msiexec` dengan alat eksekusi jarak jauh yang disetujui, lalu mencatat waktu dan jejak pemasangan di case notes.
- C. Kirim offline collector lewat email ke Wawan dan minta ia menjalankannya sendiri.

<details><summary>Jawaban</summary>

B. Host tanpa EDR tidak bisa dijangkau live response, jadi A tidak mungkin. Dokumentasi Velociraptor menyebut admin share dan alat seperti PsExec atau WinRM sebagai jalan menjalankan biner di host lain dengan hak admin, dan jejak pemasangan harus dicatat supaya tidak dibaca sebagai aktivitas penyerang. C keliru karena email adalah kanal yang sedang dipakai penyerang di kasus ini, pengguna biasa tidak punya hak admin yang dibutuhkan collector, dan tidak ada operator yang mengawasi koleksi serta hash. Lihat bagian 1.2 dan 2.3.

</details>

**3. Pertanyaan jebakan.** "`Windows.Triage.Targets` adalah artifact bawaan Velociraptor 0.77.3, jadi tinggal dipilih di daftar artifact." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Sejak 0.75 target KapeFiles dikelola di proyek terpisah, dan `Windows.Triage.Targets` harus diimpor, misalnya dengan `Server.Import.Extras` lewat tombol Import Extra Artifacts. Artifact itu mengunduh bundle dari repositori eksternal, jadi server sementara di jaringan tertutup butuh akses keluar sementara atau bundle dibawa masuk dengan cara lain. Lihat bagian 1.3 dan 2.1.

</details>

**4. Skenario keputusan.** Hunt `INC-2026-019` sudah di-Start Jumat 09:00. Laptop Lia baru online pukul 10:20 dan client-nya baru terpasang pukul 10:24. Apa yang kamu lakukan?

- A. Buat hunt baru khusus untuk laptop Lia.
- B. Beri label `inc-2026-019` pada client Lia; hunt yang masih aktif akan terjadwal otomatis ke client itu.
- C. Tunggu hunt kedaluwarsa, lalu jalankan collection manual ke laptop Lia.

<details><summary>Jawaban</summary>

B. Hunt tidak "selesai" selama belum kedaluwarsa, dan selama aktif ia dijadwalkan ke setiap client baru yang cocok kondisi; memberi label pada client membuat hunt berlabel itu terjadwal di sana. A menambah satu hunt lagi sehingga hasil terpecah dan ekspor E19 tidak lagi satu koleksi. C membuang waktu dan memisahkan hasil Lia dari hunt yang sama tanpa alasan. Lihat bagian 1.4 dan 2.5.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Fajar Nugraha, dalam tiga kalimat, cara menjalankan offline collector di laptop Ratih dan apa yang harus ia laporkan.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Colok `USB-E-12`, klik kanan collector lalu pilih Run as administrator, dan biarkan jendela terbuka sampai muncul prompt di akhir, tanpa mengetik argumen apa pun. Setelah selesai, buka file log yang namanya sama dengan file ZIP di USB, cari baris `Container hash`, dan kirim nilainya ke kami lewat Signal. Lalu masukkan USB ke kantong bukti dan isi formulir serah terima dengan waktu dan nomor kantong."

Kesalahan yang sering muncul:
- Lupa menyebut hak administrator, padahal tanpa itu collector bisa menutup tanpa pesan.
- Menyuruh menjalankan collector dengan argumen, yang membuatnya berperilaku sebagai biner biasa.
- Tidak meminta nilai `Container hash`, sehingga hash pertama baru dihitung di Jakarta.

</details>

**6. Pertanyaan jebakan.** "Cache DNS di `JKT-WS-0418` tidak memuat `cdn-sync.example.net`, jadi laptop itu tidak pernah menghubungi C2." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Windows hanya menyimpan lookup DNS di cache untuk waktu singkat, sehingga lookup hari Senin sampai Rabu hampir pasti sudah hilang saat koleksi Jumat. Ketiadaan entri di cache tidak membuktikan apa pun; jejak koneksi lebih kuat dicari di event log (bila channelnya aktif), Prefetch untuk eksekusi, dan log jaringan di luar host. Lihat bagian 1.7.

</details>

**7. Interview question (English).** "How would you use Velociraptor to scope an incident across many endpoints, and how do you report a negative result?"

<details><summary>Sample answer</summary>

"I start from what we already know, the IOCs and the behaviour, and turn them into a small set of artifacts: scheduled tasks, a file finder on the attacker's paths, Prefetch for execution, an event log search for the IOC strings, plus a light triage collection with adaptive rules so I preserve event logs and unsigned binaries that tasks or services point to. I test the exact artifacts and parameters on one host, and in the lab against a planted fake IOC, so I know the hunt can actually find what I'm looking for. Then I target the hosts with a label, start the hunt, and handle the ones that can't reach the server with an offline collector run by someone on site, with X.509 encryption and the container hash taken at the point of collection. Results are exported, hashed and stored on the evidence server before the temporary server goes away. For a negative result, I never write 'clean'. I write what was searched, with which artifacts and when, what was not covered, like memory, deleted files and rotated logs, and a confidence level that's lower for hosts where the only source is the host itself."

What makes this answer strong: it ties the hunt to specific investigative questions, includes a positive control, handles unreachable hosts with a defensible evidence path, and treats the limits of a negative result as part of the finding rather than a footnote.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Velociraptor: Adaptive Collections / Triage artifacts (Day 01) | https://docs.velociraptor.app/ | primer | diakses 2026-10-09 | Tinggi untuk konsep; nama artifact dicek ulang di S5 dan S10 |
| S2 | Velociraptor documentation: Overview (client, server, offline collector) | https://docs.velociraptor.app/docs/overview/ | primer | diakses 2026-10-09 | Tinggi |
| S3 | Velociraptor releases | https://github.com/Velocidex/velociraptor/releases | primer | 0.77.3 (5 Okt 2026); diakses 2026-10-09, dicek ulang 2026-10-16 | Tinggi. 0.77.3 masih Latest per 2026-10-16 |
| S4 | Eric Zimmerman tools (parsing hasil koleksi) | https://ericzimmerman.github.io/ | primer | diakses 2026-10-09 (Day 02) | Tinggi |
| S5 | Velociraptor: Adaptive Collections with Velociraptor | https://docs.velociraptor.app/blog/2025/2025-09-28-adaptive-collections/ | primer (blog proyek resmi) | 2025-09-28; diakses 2026-10-16 | Tinggi; ada sudut pandang proyek. Penggantian nama, aturan adaptive, meta-target, kebijakan koleksi |
| S6 | Velociraptor docs: Offline Collections | https://docs.velociraptor.app/docs/deployment/offline_collections/ | primer | diakses 2026-10-16 | Tinggi. Cara kerja, enkripsi, generic collector, pertimbangan desain |
| S7 | Velociraptor docs: Building offline collectors | https://docs.velociraptor.app/docs/deployment/offline_collections/building/ | primer | diakses 2026-10-16 | Tinggi. Builder, `Server.Utils.CreateCollector`, opsi collector |
| S8 | Velociraptor docs: Running offline collectors | https://docs.velociraptor.app/docs/deployment/offline_collections/running/ | primer | diakses 2026-10-16 | Tinggi. Hak admin, log, deployment lewat GPO, PsExec, WinRM, EDR |
| S9 | Velociraptor docs: Working with offline collection data | https://docs.velociraptor.app/docs/deployment/offline_collections/collection_data/ | primer | diakses 2026-10-16 | Tinggi. `Server.Utils.ImportCollection`, struktur container, `Container hash`, `Windows.KapeFiles.Extract` |
| S10 | Velociraptor Triage Artifacts: Windows.Triage.Targets | https://triage.velocidex.com/docs/windows.triage.targets/ | primer (proyek resmi) | diakses 2026-10-16 | Tinggi untuk nama parameter; deskripsi `MaxFileSize` tidak konsisten di halaman itu sendiri |
| S11 | Velociraptor docs: Bulk File Acquisition | https://docs.velociraptor.app/docs/file_collection/bulk/ | primer | diakses 2026-10-16 | Tinggi. `Windows.Triage.Targets` tidak bawaan, contoh hitungan volume |
| S12 | Velociraptor docs: Client deployment | https://docs.velociraptor.app/docs/deployment/clients/ | primer | diakses 2026-10-16 | Tinggi. `Server.Utils.CreateMSI`, instalasi MSI, client interaktif, writeback |
| S13 | Velociraptor docs: Quickstart | https://docs.velociraptor.app/docs/deployment/quickstart/ | primer | diakses 2026-10-16 | Tinggi. `config generate -i`, port 8000 dan 8889, paket Debian, Import Extra Artifacts |
| S14 | Velociraptor docs: Hunting | https://docs.velociraptor.app/docs/hunting/ | primer | diakses 2026-10-16 | Tinggi. Hunt `Paused`, kedaluwarsa, label, client baru |
| S15 | Velociraptor docs: Exporting Bulk File Collections | https://docs.velociraptor.app/docs/file_collection/exporting/ | primer | diakses 2026-10-16 | Tinggi. Prepare Download, `Server.Utils.ExportHunt`, batas waktu |
| S16 | Velociraptor VQL reference: create_hunt_download | https://docs.velociraptor.app/vql_reference/server/create_hunt_download | primer | diakses 2026-10-16 | Tinggi |
| S17 | Velociraptor artifact reference: Windows.System.TaskScheduler | https://docs.velociraptor.app/artifact_references/pages/windows.system.taskscheduler/ | primer | diakses 2026-10-16 | Tinggi. Parameter, source `Analysis`, kolom |
| S18 | Velociraptor artifact reference: Windows.Search.FileFinder | https://docs.velociraptor.app/artifact_references/pages/windows.search.filefinder/ | primer | diakses 2026-10-16 | Tinggi |
| S19 | Velociraptor artifact reference: Windows.Forensics.Prefetch | https://docs.velociraptor.app/artifact_references/pages/windows.forensics.prefetch/ | primer | diakses 2026-10-16 | Tinggi |
| S20 | Velociraptor artifact reference: Windows.EventLogs.EvtxHunter | https://docs.velociraptor.app/artifact_references/pages/windows.eventlogs.evtxhunter/ | primer | diakses 2026-10-16 | Tinggi |
| S21 | Velociraptor artifact reference: Windows.System.DNSCache | https://docs.velociraptor.app/artifact_references/pages/windows.system.dnscache/ | primer | diakses 2026-10-16 | Tinggi. Tidak menyebut durasi cache |
| S22 | Velociraptor artifact reference: Server.Import.Extras | https://docs.velociraptor.app/artifact_references/pages/server.import.extras/ | primer | diakses 2026-10-16 | Tinggi. Daftar bundle eksternal |
| S23 | Microsoft Learn: Investigate entities on devices using live response in Microsoft Defender for Endpoint | https://learn.microsoft.com/en-us/defender-endpoint/live-response | primer (dokumentasi vendor) | ms.date 2026-07-28; diakses 2026-10-16 | Tinggi. Perintah, batas ukuran dan waktu, pengaturan unsigned script |
| S24 | Microsoft Learn: Live response command examples | https://learn.microsoft.com/en-us/defender-endpoint/live-response-command-examples | primer (dokumentasi vendor) | ms.date 2025-01-24; diakses 2026-10-16 | Tinggi. Sintaks `putfile`, `run -parameters`, karakter terlarang |
| S25 | Microsoft Learn: msiexec | https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/msiexec | primer (dokumentasi vendor) | diakses 2026-10-16 | Tinggi. `/i`, `/x`, `/qn`, `/L*V` |
| S26 | Cisco Talos: Velociraptor leveraged in ransomware attacks | https://blog.talosintelligence.com/velociraptor-leveraged-in-ransomware-attacks/ | sekunder (peneliti) | 2025-10-09, diperbarui 2025-10-17; diakses 2026-10-16 | Tinggi untuk temuan kasusnya; satu insiden, bukan statistik |
| S27 | Velociraptor VQL reference: hunt_results | https://docs.velociraptor.app/vql_reference/server/hunt_results/ | primer | diakses 2026-10-16 | Tinggi. Parameter; kolom tambahan per baris tidak disebut |
| S28 | Velocidex: velociraptor-triage-collector (GitHub) | https://github.com/Velocidex/velociraptor-triage-collector | primer (repo resmi) | diakses 2026-10-16 | Sedang-tinggi. Opsi `--definitions` untuk biner lokal |

**Catatan sumber:** beberapa detail masih perlu dicek di lab versi 0.77.x: format nilai `Devices` dan flag `--output` untuk `artifacts collect`, perilaku `TrustedPathRegex` terhadap target di bawah `C:\Windows\`, nilai bawaan `MaxFileSize`, ejaan meta-target (`_SANS_Triage` atau `_SansTriage`), kolom `ClientId` di hasil `hunt_results`, apakah `uploads.json` di ekspor hunt memuat SHA-256 per file, dan cara mengimpor bundle artifact dari file lokal di server tanpa akses keluar. Path folder kerja `putfile` live response tidak disebut di dokumentasi Microsoft yang diperiksa. Dokumentasi Velociraptor menyebut PsExec, WinRM, dan EDR sebagai jalan eksekusi jarak jauh tanpa rincian per produk; langkah live response di bagian 2.2 adalah penerapan dua dokumentasi itu pada kasus fiktif, bukan prosedur resmi salah satu vendor. Nama host, waktu, hash, ID hunt, ukuran, dan semua isi PT JAB adalah contoh fiktif.
