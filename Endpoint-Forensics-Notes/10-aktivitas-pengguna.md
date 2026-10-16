---
day: 10
title: 'Aktivitas pengguna: ShellBags, LNK, Jump List, RecentDocs, OpenSavePidlMRU, TypedPaths, dan membedakan kerja interaktif dari skrip'
researched_on: 2026-10-16
versions_checked: 'EZ Tools 2026.5.0 (SBECmd, LECmd, JLECmd, RECmd untuk .NET 4.7.2 dan .NET 9; ShellBags Explorer, JumpList Explorer, Registry Explorer, Timeline Explorer hanya .NET 9); README LECmd dan JLECmd (banner JLECmd 1.4.0.0), README RECmd (banner 1.6.0.0); RECmd BatchExamples UserActivity.reb (versi 1) dan DFIRBatch.md (v2.22, 2026-03-17; nama Kroll_Batch diganti DFIRBatch di v2.00, 2024-05-18); KapeFiles target LNKFilesAndJumpLists (versi 1.3) dan RegistryHivesUser (versi 1.0); Microsoft Open Specifications [MS-SHLLINK] revisi 10.0 (2025-11-21); Microsoft Learn SHAddToRecentDocs (ms.date 2018-12-05, diperbarui 2025-07-01); kebijakan arsip Do not keep history of recently opened documents (ms.date 2017-05-04); Windows 10 dan 11'
---

# Day 10: Aktivitas pengguna (ShellBags, LNK, Jump List, RecentDocs, OpenSavePidlMRU, TypedPaths)

Cakupan: membaca artefak per pengguna yang ditulis antarmuka Windows (ShellBags, file LNK, Jump List, RecentDocs, OpenSavePidlMRU, LastVisitedPidlMRU, TypedPaths, WordWheelQuery) untuk menjawab folder apa yang dilihat, file apa yang dibuka, dan apa yang diketik pengguna, lalu memakainya untuk membedakan kerja interaktif di desktop dari aktivitas skrip, memisahkan pemilik akun dari responder dan penyerang, dan menulis batas kesimpulannya.

## Ide inti

Artefak aktivitas pengguna adalah efek samping fitur kenyamanan Windows, bukan log audit. Explorer mengingat tampilan folder supaya folder yang sama terbuka dengan ukuran dan urutan yang sama (ShellBags). Shell mencatat dokumen yang baru dibuka supaya muncul di Recent, Quick Access, dan Jump List (file LNK, Jump List, RecentDocs). Dialog Open/Save mengingat lokasi terakhir (OpenSavePidlMRU), dan address bar serta kotak pencarian Explorer mengingat apa yang diketik (TypedPaths, WordWheelQuery). Semua jejak itu ditulis oleh antarmuka: Explorer, dialog umum, dan aplikasi yang memberi tahu shell. Program yang membaca file langsung lewat API, misalnya skrip PowerShell yang mendaftar isi folder dan membaca isi file, tidak lewat antarmuka itu, sehingga biasanya tidak meninggalkan apa pun di artefak ini. Karena itu artefak aktivitas pengguna menjawab satu pertanyaan dengan sangat baik, yaitu "apakah seseorang bekerja di desktop sesi ini, dan apa yang ia buka", dan hampir tidak bisa menjawab pertanyaan sebaliknya, yaitu "file apa saja yang disentuh proses di belakang layar".

Kamu sudah mengenal polanya dari NOC. Router menyimpan history perintah per sesi VTY, dan accounting TACACS mencatat setiap perintah yang diketik engineer. Perubahan yang dibuat EEM applet atau skrip otomasi lewat API tidak muncul di history sesi siapa pun. Kalau manajer bertanya "apakah ada orang yang login dan mengetik di router ini malam itu?", kamu memeriksa sesi VTY dan history-nya; tidak adanya sesi tidak berarti tidak ada perubahan, tetapi berarti perubahan tidak datang dari orang yang mengetik di CLI. Bedanya, history CLI dirancang sebagai catatan, sedangkan artefak shell Windows hanya fitur kenyamanan: isinya dibatasi jumlah entri, timestamp-nya tidak dirancang untuk forensik, dan bisa dikosongkan pengguna.

```
pertanyaan: "ada kerja interaktif di sesi ini, atau hanya skrip?"
  |
  v
1. SIAPA YANG MUNGKIN ADA DI DESKTOP
   event log: logon type 2/7 (konsol, unlock), type 10 (RDP), switch user  -> Day 05
  |
  v
2. APA YANG DITULIS ANTARMUKA (per profil: NTUSER.DAT, UsrClass.dat, folder Recent)
   ShellBags ............ folder DILIHAT di Explorer / dialog
   LNK, Jump List ....... file DIBUKA lewat shell (Explorer, dialog, aplikasi)
   RecentDocs ........... file dibuka, per ekstensi
   OpenSave/LastVisited . file dipilih di dialog Open/Save, oleh aplikasi apa
   TypedPaths, WordWheel  path DIKETIK, kata DICARI di Explorer
  |
  v
3. COCOKKAN DENGAN POLA PEMILIK, RESPONDER, PENYERANG (waktu, profil, path)
  |
  v
4. SISI YANG TIDAK TERLIHAT: proses yang membaca file langsung (skrip, C2)
   -> 4104, Sysmon, EDR, memori, log jaringan
  |
  v
jawaban: "jejak interaktif ada/tidak ada" + jendela + keyakinan + yang tidak bisa dijawab
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan dan data pribadi sekitar 400 ribu pelanggan broadband. Kasusnya `INC-2026-019`: email dari `billing@vendor-tagihan.example` dengan lampiran `Tagihan-Okt-2026.zip` (berisi `Tagihan-Okt-2026.js`) diterima sembilan mailbox Senin 2026-10-12 pukul 15:58. Di laptop `JKT-WS-0388` milik staf penagihan `andi.pratama` (Windows 11, Microsoft Defender for Endpoint, Sysmon), event log sudah menunjukkan rantainya (Day 05): Andi login interaktif Senin 07:58:14 dengan Logon ID `0x3A1F2C`, ZIP disimpan `OUTLOOK.EXE` ke Downloads pukul 16:04:48, `.js` diekstrak Explorer ke folder `Temp1_Tagihan-Okt-2026.zip` di `AppData\Local\Temp` pukul 16:05:09, lalu `wscript.exe` menjalankannya pukul 16:05:11. Penyerang memasang scheduled task `\SysCacheUpdate` yang menjalankan `C:\Users\andi.pratama\AppData\Roaming\SysCache\upd.ps1` tiap 15 menit. Senin 23:40:17 PowerShell script block logging mencatat `upd.ps1` mencari kata password, svc, dan ssh di Documents dan Desktop lalu membaca `export-tagihan.ps1`; password akun service `svc_billing` di skrip itu dipakai untuk SSH ke server billing Selasa 02:14. Andi sendiri menjalankan `export-tagihan.ps1` Senin 14:02 seperti biasa, membuka layar lagi Selasa 08:12:05, menyimpan `Rekap-Penagihan-Okt-2026.xlsx` di Desktop Selasa 08:24 sampai 08:52, dan memindahkan ZIP ke Recycle Bin pukul 11:12:40 setelah ditelepon analyst L1 Gilang Ramadhan pukul 11:08 (Day 08). Yoga Pratama, analyst L2 yang memegang bukti, login dengan akun admin lokal khusus IR `ir-admin` Selasa 12:38 untuk mengambil memori, dan mematikan laptop Kamis 08:47 sebelum image E15 pukul 09:00. Salinan kerja `E15-W1` ada di `\\jkt-evid01\cases\INC-2026-019\work\`.

Jumat 2026-10-23 pukul 09:00, Sari Kusuma (technical lead) sedang menyusun draf after-action report untuk post-incident review hari Selasa. Ia menulis kepadamu di kanal `#inc-2026-019`:

> "Pagi. Draf laporan untuk PIR Selasa harus kukirim Senin siang, dan Pak Dimas minta satu jawaban yang bisa dipegang: apakah ada tanda penyerang bekerja interaktif di sesi Andi, misalnya membuka folder lewat Explorer, mengetik path, mencari file, atau membuka dokumen, atau semuanya lewat skrip? Laporan retainer menulis 'pencarian file di Documents dan Desktop', dan ada yang membacanya seolah penyerang melihat-lihat folder Andi seperti orang biasa. Tolong pakai E15-W1. Pisahkan jejak Andi sendiri (ZIP Senin sore, skrip ekspor Senin siang, Excel Selasa pagi) dan jejak Yoga. Kalau jawabannya 'tidak ada', aku perlu tahu seberapa kuat, dan apa yang bisa membuatnya salah, termasuk soal file dari ZIP dan folder Temp. Jawaban sebelum jam 16:00 ya."

Pesan itu memuat enam pertanyaan:

1. Artefak apa yang mencatat interaksi pengguna dengan antarmuka, kenapa skrip biasanya tidak meninggalkannya, dan di mana artefak itu diambil dari E15-W1?
2. Folder apa yang dibuka lewat Explorer di sesi Andi, dan adakah yang dibuka di luar jam kerja Andi?
3. File apa yang dibuka lewat antarmuka, dari lokasi mana, dan kapan?
4. Apa yang diketik, dicari, atau dipilih lewat dialog Open/Save?
5. Mana jejak Andi, mana jejak responder, dan adakah jejak yang tidak bisa dijelaskan keduanya?
6. Seberapa kuat kesimpulan "tidak ada jejak interaktif penyerang", dan apa batasnya?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3 dan 1.4, pertanyaan 4 di bagian 1.5, pertanyaan 5 di bagian 1.6, dan pertanyaan 6 di bagian 1.7. Bagian 2 berisi perintah, hasil parse, dan jawaban tertulis yang kamu kirim ke Sari.

**Kapan relevan:** saat pertanyaannya tentang manusia di depan layar: folder apa yang dijelajahi, dokumen apa yang dibuka, path apa yang diketik, perangkat USB atau share mana yang dibuka lewat Explorer; saat membedakan kerja interaktif (pengguna, orang dalam, penyerang lewat RDP atau konsol) dari aktivitas skrip; dan saat file, folder, atau perangkatnya sudah tidak ada, karena artefak ini bertahan setelah targetnya hilang.
**Kapan bukan jawaban:** untuk membuktikan file dibaca atau dicari oleh proses di belakang layar (pakai 4104, Sysmon, EDR, memori; Day 05), untuk membuktikan file diubah, disalin, atau dihapus (file system; Day 08), untuk membuktikan program berjalan (artefak eksekusi; Day 07), dan untuk menyatakan "tidak ada akses" hanya karena artefak shell kosong.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (salinan kerja, Logon ID, logon type, hive, transaction log, `$J`, jejak responder) tidak diulang. Tabel ini memuat istilah artefak aktivitas pengguna yang dipakai Day ini; kolom padanan memakai analogi NOC dan SOC.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Artefak aktivitas pengguna (artefak shell) | Jejak per profil yang ditulis Explorer, dialog umum, dan shell saat pengguna bekerja lewat antarmuka | History perintah per sesi VTY di router |
| Hands-on-keyboard | Aktivitas yang dikerjakan orang secara langsung, di desktop atau lewat shell jarak jauh, bukan oleh skrip yang berjalan sendiri | Engineer yang mengetik di CLI vs EEM applet yang berjalan terjadwal |
| ShellBags (`BagMRU`, `Bags`) | Key registry yang mengingat folder yang dibuka di Explorer atau dialog beserta pengaturan tampilannya | Daftar node di peta NMS yang pernah dibuka operator, lengkap dengan zoom dan layout yang diingat |
| Shell item | Struktur biner yang mewakili satu folder, file, drive, atau lokasi jaringan di ShellBags dan LNK | Satu baris path di inventaris, dengan atribut tersimpan |
| File LNK (shell link) | File shortcut berformat [MS-SHLLINK]; dibuat otomatis di folder Recent saat dokumen dibuka lewat shell | Entri "recent sessions" di aplikasi terminal yang menyimpan detail koneksi terakhir |
| Source time vs target time | Waktu file `.lnk` itu sendiri (dibuat, diubah) vs waktu file target yang disalin ke dalam LNK | Waktu entri recent session dibuat vs waktu yang dibaca dari perangkat saat itu |
| VolumeID dan DriveSerialNumber | Bagian LNK yang mencatat jenis drive, nomor seri volume, dan label tempat target berada | Nomor seri modul flash dari `show version`, bukan nomor seri chassis |
| TrackerDataBlock (MachineID, Droid) | Blok tambahan LNK berisi nama NetBIOS mesin tempat target terakhir diketahui dan ID pelacakan | Hostname dan ID objek yang dicatat bersama entri inventaris |
| Jump List (`AutomaticDestinations`, `CustomDestinations`, `DestList`) | Daftar item terbaru dan sering dipakai per aplikasi; file automatic memuat stream `DestList` dan LNK per item | Riwayat sesi per aplikasi terminal: host terakhir dan berapa kali dibuka |
| AppID | Identitas aplikasi pemilik Jump List, menjadi awalan nama file | ID aplikasi di NMS yang menandai siapa pemilik riwayat itu |
| `SHAddToRecentDocs` | Fungsi Windows yang memberi tahu shell bahwa sebuah item dipakai; memperbarui folder Recent dan Jump List | Hook di aplikasi yang menulis ke history hanya bila aksi lewat menu GUI |
| RecentDocs | Key NTUSER berisi nama file dan folder yang baru dibuka, dikelompokkan per ekstensi | Daftar file konfigurasi terakhir yang dibuka di editor, per jenis file |
| OpenSavePidlMRU dan LastVisitedPidlMRU | Key NTUSER berisi file yang dipilih di dialog Open/Save (per ekstensi) dan folder terakhir per aplikasi | Riwayat dialog copy TFTP/SCP: file apa diambil atau disimpan ke mana, oleh tool apa |
| TypedPaths dan WordWheelQuery | Path yang diketik di address bar Explorer dan kata yang diketik di kotak pencarian Explorer | Host yang diketik manual di kolom alamat dan kata yang dicari di kolom pencarian NMS |
| `MRUListEx` | Nilai biner yang menyimpan urutan entri dari yang paling baru | Urutan baris di `show history` |
| LastWriteTime key | Waktu terakhir sebuah key registry berubah; berlaku untuk key, bukan untuk tiap value | Waktu terakhir file history disimpan, bukan waktu tiap baris diketik |

### 1.1 Peta artefak: apa yang ditulis antarmuka, dan kenapa skrip tidak menulisnya

Pertanyaan pertama Sari adalah dasar seluruh jawaban: kalau kamu akan menyimpulkan "tidak ada kerja interaktif" dari artefak yang kosong, kamu harus tahu artefak itu ditulis oleh siapa dan dalam keadaan apa.

Microsoft menjelaskan mekanismenya lewat fungsi `SHAddToRecentDocs`. Fungsi ini memberi tahu sistem bahwa sebuah item dipakai, lalu sistem memperbarui daftar Recent dan Frequent di Jump List aplikasi terkait dan menambahkan shortcut ke folder Recent pengguna [S7]. Shell memanggil fungsi itu atas nama aplikasi dalam dua keadaan utama: saat pengguna membuka item lewat Windows Explorer, dan saat dialog umum dipakai untuk membuka, menyimpan, atau membuat file. Aplikasi yang punya antarmuka pemilihan file sendiri diminta memanggilnya secara eksplisit [S7]. Dokumentasi yang sama menulis tiga detail yang sering menentukan cara membaca hasil [S7]:

- File `.exe` disaring dari daftar dokumen terbaru, walaupun fungsi menerima path-nya.
- Folder diterima, tetapi hanya muncul di Jump List milik Explorer.
- Verb seperti `delete` tidak dilacak: entri `NoRecentDocs` dipasang secara default pada class `*`, `AllFileSystemObjects`, `Folder`, `Directory`, dan `DesktopBackground`, sehingga menghapus file lewat menu konteks tidak menambah entri Recent.

Dari situ lahir prinsip yang dipakai di seluruh Day ini. Skrip PowerShell yang menjalankan `Get-ChildItem` dan `Get-Content` memanggil API file system, bukan Explorer dan bukan dialog umum, sehingga tidak ada pihak yang memanggil `SHAddToRecentDocs` dan tidak ada ShellBags yang ditulis. Praktisi mencatat hal yang sama dari sisi anti-forensik: navigasi lewat PowerShell atau Command Prompt disebut sebagai cara menghindari jejak ShellBags [S15], dan ShellBags hanya mencatat akses lewat Explorer, bukan lewat command line atau proses otomatis [S15][S19].

Tabel berikut adalah peta kerja Day ini. Baca dua kolom terakhir bersamaan, karena kesalahan paling umum adalah membaca kolom "membuktikan" tanpa kolom "tidak membuktikan".

| Artefak | Lokasi (per profil) | Ditulis oleh | Membuktikan | Tidak membuktikan | Parser |
|---|---|---|---|---|---|
| ShellBags | `UsrClass.dat` (lokal dan removable), `NTUSER.DAT` (share jaringan) | Explorer dan dialog Open/Save | Folder pernah dibuka atau dilihat, termasuk yang sudah dihapus, di USB, atau di share | File di dalamnya dibuka; waktu persis setiap kunjungan | SBECmd, ShellBags Explorer |
| LNK di Recent | `AppData\Roaming\Microsoft\Windows\Recent\` | Shell lewat `SHAddToRecentDocs` | File (dan folder induknya) pernah dibuka lewat shell; path, volume, waktu target saat LNK diperbarui | Apa yang dilakukan pada file; pembacaan oleh proses | LECmd |
| Jump List | `Recent\AutomaticDestinations\`, `Recent\CustomDestinations\` | Shell untuk aplikasi terkait; aplikasi itu sendiri | Aplikasi tertentu membuka file tertentu, berapa kali, kapan terakhir | Isi atau perubahan file | JLECmd, JumpList Explorer |
| RecentDocs | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` | Explorer | Nama file atau folder yang baru dibuka, per ekstensi, berurutan | Path lengkap; waktu tiap entri selain yang terbaru | RECmd, Registry Explorer |
| OpenSavePidlMRU, LastVisitedPidlMRU | `NTUSER.DAT\...\Explorer\ComDlg32\` | Dialog Open/Save | File dipilih atau disimpan lewat dialog, path lengkap; aplikasi pemakai dialog | File dibuka dengan cara lain | RECmd |
| TypedPaths | `NTUSER.DAT\...\Explorer\TypedPaths` | Address bar Explorer | Path diketik manual (navigasi sengaja) | Folder yang dibuka dengan klik | RECmd |
| WordWheelQuery | `NTUSER.DAT\...\Explorer\WordWheelQuery` | Kotak pencarian Explorer | Kata yang dicari di Explorer, berurutan | Pencarian oleh skrip atau aplikasi lain | RECmd |

Isi tabel ini dirangkum dari peta artefak aktivitas pengguna di poster SANS [S1], lokasi ShellBags dan pembagian hive dari Cyber Triage [S15], ringkasan key registry pengguna dari Cyber Triage [S16], dan daftar key di batch `UserActivity.reb` milik RECmd [S11].

Tiga hal yang perlu diingat sebelum masuk ke artefak satu per satu:

1. **Semuanya per profil.** Aktivitas Andi ada di hive dan folder Recent milik `andi.pratama`; aktivitas Yoga dengan `ir-admin` ada di profil `ir-admin`. Penyerang yang menumpang sesi Andi menulis ke profil Andi, bukan ke profil sendiri. Satu profil yang tidak dikoleksi berarti satu orang yang tidak terlihat.
2. **Hive pengguna punya transaction log.** Perubahan terbaru bisa masih berada di `NTUSER.DAT.LOG1`/`LOG2` dan `UsrClass.dat.LOG1`/`LOG2`. Target KAPE `RegistryHivesUser` mengambil `NTUSER.DAT`, `UsrClass.dat`, dan transaction log keduanya [S14], dan RECmd memakai transaction log untuk hive dirty kecuali opsi `--nl` dipasang [S10].
3. **Aplikasi Windows App (MSIX) punya hive sendiri.** Bila aplikasi yang membuka dialog Open/Save adalah Windows App, ShellBags-nya ditulis ke `User.dat` dan `UserClasses.dat` di `AppData\Local\Packages\<nama paket>\SystemAppData\Helium\`, bukan ke hive pengguna biasa [S15]. Target `RegistryHivesUser` tidak mencantumkan lokasi itu [S14], jadi untuk aplikasi seperti itu koleksinya perlu ditambah. Aplikasi bawaan mana saja yang berbentuk Windows App di build Windows 11-mu perlu dicek di lab.

### 1.2 ShellBags: folder yang dilihat, bukan file yang dibuka

Pertanyaan kedua Sari ("folder apa yang dibuka lewat Explorer, dan adakah yang dibuka di luar jam kerja Andi?") adalah pekerjaan ShellBags, karena artefak inilah yang mencatat navigasi folder.

ShellBags menyimpan preferensi tampilan folder di Explorer dan dialog Open/Save: posisi dan ukuran jendela, kolom, urutan, ukuran ikon. Sebagai efek samping, ia mencatat folder mana yang pernah dibuka [S15][S19]. Strukturnya dua key [S15][S19]:

- **`BagMRU`** menyimpan path folder sebagai shell item biner, tersusun mengikuti hierarki navigasi, dengan nilai `MRUListEx` untuk urutan dan referensi `NodeSlot`.
- **`Bags`** menyimpan preferensi tampilan per `NodeSlot`, di subkey `Shell` untuk Explorer atau `ComDlg` untuk dialog Open/Save.

Lokasinya di Windows Vista sampai 11 terbagi dua [S15]. Tabel ini perlu diingat karena satu hive yang terlewat berarti satu jenis lokasi yang tidak terlihat.

| Hive | Path di dalam hive | Isi |
|---|---|---|
| `UsrClass.dat` | `Local Settings\Software\Microsoft\Windows\Shell\BagMRU` dan `Bags` | Folder lokal dan removable |
| `NTUSER.DAT` | `Software\Microsoft\Windows\Shell\BagMRU` dan `Bags` | Folder di share jaringan (UNC) |

Di host hidup, key `UsrClass.dat` terlihat di bawah `HKCU\Software\Classes\Local Settings\...` [S19].

Apa yang dibuktikan dan tidak dibuktikan ShellBags dirangkum Cyber Triage (Maret 2025, ditinjau untuk 2026) dengan hati-hati [S15]:

- **Membuktikan:** path folder pernah ada dan dijelajahi, termasuk folder yang sudah dihapus, di USB yang sudah dicabut, atau di share yang sudah terputus; hive pengguna mana yang mencatatnya. Bila subkey `Bags` untuk folder itu berisi preferensi tampilan, folder itu berhasil ditampilkan.
- **Tidak membuktikan dengan andal:** isi folder dibuka (entri bisa ada untuk folder induk yang hanya dilewati, dan folder yang tidak dikunjungi langsung tidak punya `NodeSlot`), akses berhasil (percobaan yang ditolak tetap membuat entri tanpa preferensi tampilan), aktivitas tingkat file, dan waktu akses pertama atau terakhir yang pasti.
- **Arsip:** Explorer memperlakukan arsip seperti ZIP sebagai folder, sehingga menjelajah ke dalam arsip bisa menghasilkan entri ShellBags [S15][S19]. File biasa seperti TXT, EXE, PDF, atau DOCX umumnya tidak tercatat sendiri [S19].

Timestamp adalah bagian yang paling sering dilebih-lebihkan. Ada tiga jenis, dan maknanya berbeda:

| Timestamp | Asal | Cara membaca |
|---|---|---|
| Created, Modified, Accessed folder di shell item | Disalin dari file system saat folder pertama kali masuk ShellBags | Keadaan folder saat pertama tercatat; tidak diperbarui pada kunjungan berikutnya [S15] |
| LastWriteTime key `BagMRU` | Waktu key terakhir berubah | Hanya untuk key itu; perubahan anak atau urutan bisa memperbaruinya |
| FirstInteracted dan LastInteracted di SBECmd dan ShellBags Explorer | Disimpulkan parser dari LastWriteTime key `BagMRU` dan urutannya | Inferensi, bukan fakta yang dijamin [S15]; nama kolom cek di versi-mu |

Praktisi menegaskan bahwa logika penulisan ShellBags tidak didokumentasikan publik oleh Microsoft dan berubah antar versi Windows [S15]. Karena itu waktu ShellBags dipakai untuk mempersempit jendela dan dikorelasikan dengan sumber lain, bukan dikutip sebagai "pukul sekian pengguna membuka folder".

Untuk Andi, pertanyaan yang diajukan ke ShellBags dibuat sempit: adakah folder yang dibuka lewat Explorer setelah Andi pulang Senin sore sampai ia membuka layar Selasa 08:12:05, dan adakah folder penyerang (`AppData\Roaming\SysCache`, folder Temp) yang pernah dibuka lewat Explorer. Pencarian `upd.ps1` pukul 23:40 di Documents dan Desktop tidak diharapkan muncul, karena ia berjalan sebagai skrip (bagian 2.2).

### 1.3 File LNK: file yang dibuka, dari mana, dan apa yang tersimpan tentang targetnya

Pertanyaan ketiga Sari ("file apa yang dibuka lewat antarmuka, dari mana, dan kapan?") dimulai dari file LNK di folder Recent.

File LNK adalah format biner yang didokumentasikan Microsoft sebagai [MS-SHLLINK] [S3]. Windows membuatnya otomatis di `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\` saat dokumen dibuka lewat shell (bagian 1.1) [S7], dan aplikasi Office punya folder sendiri di `AppData\Roaming\Microsoft\Office\Recent\` [S13][S17]. Tabel berikut berisi bagian LNK yang dipakai dalam investigasi; kolom kanan adalah hal yang paling sering salah dibaca.

| Bagian | Isi menurut spesifikasi | Catatan baca |
|---|---|---|
| `ShellLinkHeader`: `CreationTime`, `AccessTime`, `WriteTime`, `FileSize` | Waktu dibuat, diakses, ditulis, dan ukuran file target, dalam UTC; nol berarti tidak diisi [S4] | Ini waktu target pada saat LNK ditulis, bukan waktu LNK |
| `LinkTargetIDList` | Shell item yang menunjuk target | Bisa memuat nomor entry dan sequence `$MFT` target |
| `LinkInfo` dan `VolumeID` | Path lokal atau jaringan; `DriveType` (misalnya `DRIVE_FIXED`, `DRIVE_REMOVABLE`, `DRIVE_REMOTE`), `DriveSerialNumber`, label volume tempat target berada saat link dibuat [S5] | Nomor seri volume (file system), bukan nomor seri perangkat USB |
| `TrackerDataBlock` | `MachineID` (nama NetBIOS mesin tempat target terakhir diketahui), `Droid` dan `DroidBirth` untuk layanan Link Tracking [S6] | Parser menurunkan MAC address dari `Droid`; itu MAC mesin pembuat, bukan bukti komunikasi |

LECmd memparse header, target ID list, dan extra block, dengan opsi `-f` untuk satu file, `-d` untuk folder secara rekursif, `-r` untuk hanya LNK yang menunjuk drive removable, `--csv` dan `--csvf` untuk output, dan `--mp` untuk timestamp presisi tinggi [S8]. CSV-nya memisahkan dua kelompok waktu: `SourceCreated`, `SourceModified`, `SourceAccessed` untuk file `.lnk` itu sendiri, dan `TargetCreated`, `TargetModified`, `TargetAccessed` dari header, ditambah kolom seperti `LocalPath`, `DriveType`, `VolumeSerialNumber`, `TargetMFTEntryNumber`, `MachineID`, dan `MachineMACAddress` [S17].

Cara membaca dua kelompok waktu itu:

- **Source time (file `.lnk`).** Praktisi membaca `SourceCreated` sebagai waktu target pertama kali dibuka, karena LNK dibuat saat itu, dan `SourceModified` sebagai waktu target terakhir dibuka, karena LNK diperbarui setiap kali target dibuka lagi [S17]. Ini konsensus praktisi, bukan perilaku yang ditulis Microsoft; uji di build lab.
- **Target time (dari header).** Waktu file target pada saat LNK terakhir ditulis [S4]. Bila target diubah setelah dibuka, misalnya disimpan ulang, `TargetModified` di LNK tetap menunjukkan nilai sebelum perubahan itu. LNK adalah potret target saat dibuka, bukan keadaan terakhirnya.

Panduan CSIRT.SK menambahkan perilaku yang berguna sekaligus perlu diuji [S17]: saat file dibuka, Windows membuat dua dan kadang tiga LNK (untuk file, untuk folder induknya, dan sejak Windows 10 untuk folder di atasnya), nama LNK memuat ekstensi file asli (`Laporan.xlsx.lnk`), dan kapasitas folder Recent disebut 149 LNK. Angka kapasitas dan jumlah LNK per pembukaan berasal dari satu panduan praktisi tahun 2019; cek di build lab sebelum dipakai untuk menyimpulkan bahwa LNK lama "seharusnya masih ada".

Satu varian LNK patut dikenal untuk pertanyaan Sari. Mandiant (Februari 2020) menemukan "search LNK": saat pengguna membuka file dari hasil pencarian Explorer, Windows membuat LNK di folder Recent yang namanya sama dengan kata kunci pencarian (misalnya `passw.lnk`), dengan target ID berisi `Search Folder\<kata kunci>` dan konteks seperti "Search Results in Local Disk (C:)", sementara timestamp header dan ukuran target kosong [S20]. Search LNK hanya dibuat bila hasil pencarian benar-benar dibuka [S20]. Kalau penyerang yang duduk di desktop Andi mencari "password" lewat Explorer lalu membuka hasilnya, artefak ini yang akan muncul.

Apa yang tidak dibuktikan LNK: apa yang dilakukan pada file setelah dibuka, apakah file disalin, dan apakah file dibaca oleh proses yang tidak lewat shell. LNK juga bisa dihapus pengguna atau otomatis, dan jumlah yang disimpan terbatas [S17]. Ketiadaan LNK untuk sebuah file tidak membuktikan file itu tidak dibuka.

### 1.4 Jump List: file per aplikasi, dengan hitungan dan waktu terakhir

Jump List melengkapi LNK dengan dua hal yang tidak ada di LNK biasa: aplikasi mana yang membuka file, dan berapa kali.

Menurut dokumentasi `SHAddToRecentDocs`, daftar Recent dan Frequent di Jump List diperbarui bersamaan dengan folder Recent [S7]. Jump List disimpan per profil di `AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` dan `CustomDestinations\`, dengan nama file berupa AppID heksadesimal diikuti ekstensi `.automaticDestinations-ms` atau `.customDestinations-ms` [S18]. Tabel berikut membandingkan keduanya; perhatikan kolom kanan, karena di situlah perbedaan nilai forensiknya.

| Jenis | Format | Isi | Nilai forensik |
|---|---|---|---|
| Automatic Destinations | Compound File Binary (OLE), stream `DestList` plus satu stream LNK per item | Dibuat OS untuk aplikasi yang memakai API shell | `DestList` memberi posisi MRU, hitungan akses, waktu terakhir dipakai, dan nama NetBIOS mesin [S18] |
| Custom Destinations | Rangkaian struktur LNK tanpa `DestList` | Ditentukan aplikasi (task, kategori kustom) | Lebih sedikit metadata; interpretasi lebih sulit [S17][S18] |

AppID mengikat Jump List ke aplikasinya. Contoh yang dikenal luas: `f01b4d95cf55d32a` adalah Jump List File Explorer [S18]. Microsoft menulis bahwa folder hanya muncul di Jump List Explorer [S7], jadi Jump List Explorer adalah tempat mencari folder yang dibuka, sedangkan Jump List Excel, Word, atau Notepad adalah tempat mencari dokumen.

JLECmd memparse kedua jenis, dengan opsi `-d` untuk folder rekursif, `--csv` dan `--csvf`, `--ld` dan `--fd` untuk detail LNK di dalamnya, `--dumpTo` untuk mengekspor LNK yang tertanam supaya bisa diproses LECmd, `--appIds` untuk memuat daftar AppID tambahan berformat `appid|deskripsi`, dan `--withDir` untuk menampilkan isi direktori yang tidak tercatat di `DestList` [S9]. Kolom CSV yang paling sering dipakai: `AppId`, `AppIdDescription`, `Path`, `MRU`, `InteractionCount`, `LastModified` (waktu terakhir dipakai, dari `DestList`), `TargetCreated`/`TargetModified`/`TargetAccessed` (dari LNK tertanam), `VolumeSerialNumber`, dan `Hostname`/`MacAddress` [S18]. AppID yang tidak dikenal tampil sebagai heksadesimal saja; cari padanannya dan tambahkan lewat `--appIds`.

Batasnya sama dengan LNK: keberadaan item di Jump List adalah indikator kuat bahwa file dibuka lewat aplikasi itu, tetapi tidak menunjukkan apa yang dilakukan pada file atau apakah isinya berubah [S18]. Jump List bisa menyimpan jejak file yang sudah dipindah atau dihapus [S18].

Untuk Andi, Jump List Excel diharapkan menguatkan pekerjaan Selasa pagi (`Rekap-Penagihan-Okt-2026.xlsx`), yang di `$J` hanya terlihat sebagai pola simpan tanpa pelaku (Day 08). Jump List juga menjadi pemeriksaan silang untuk LNK: entri yang ada di satu tetapi tidak di yang lain perlu dijelaskan (bagian 2.4).

### 1.5 RecentDocs, OpenSavePidlMRU, LastVisitedPidlMRU, TypedPaths, dan WordWheelQuery: apa yang diketik dan dipilih

Pertanyaan keempat Sari ("apa yang diketik, dicari, atau dipilih lewat dialog?") dijawab dari key registry di `NTUSER.DAT`. Semuanya ada di bawah `Software\Microsoft\Windows\CurrentVersion\Explorer\` dan semuanya tercantum di batch `UserActivity.reb` milik RECmd [S11].

| Key | Path di bawah `...\Explorer\` | Isi | Catatan baca |
|---|---|---|---|
| RecentDocs | `RecentDocs` (rekursif) | Nama file dan folder yang baru dibuka; subkey per ekstensi, masing-masing dengan `MRUListEx` [S16] | Hanya nama, bukan path lengkap [S16] |
| OpenSavePidlMRU | `ComDlg32\OpenSavePidlMRU` (rekursif) | File yang dibuka atau disimpan lewat dialog umum, path lengkap, subkey per ekstensi [S16][S21] | Hanya pemakaian dialog; Ctrl+S pada file yang sudah ada tidak membuka dialog |
| LastVisitedPidlMRU | `ComDlg32\LastVisitedPidlMRU` | Aplikasi yang memakai dialog dan lokasi terakhir yang dibukanya [S16] | Mengikat file di OpenSavePidlMRU ke executable |
| TypedPaths | `TypedPaths` | Path yang diketik langsung di address bar Explorer [S16] | Navigasi sengaja; klik tidak tercatat di sini |
| WordWheelQuery | `WordWheelQuery` | Kata yang diketik di kotak pencarian Explorer, berurutan lewat `MRUListEx` [S16][S20] | Pasangannya adalah search LNK bila hasil dibuka (bagian 1.3) |
| RunMRU | `RunMRU` | Perintah yang diketik di dialog Run [S16] | Bukan program yang diluncurkan dari menu |

Dua aturan membaca waktu berlaku untuk semua key di tabel itu:

1. **LastWriteTime milik key, bukan milik value.** Value registry tidak punya timestamp sendiri. Waktu terakhir key berubah biasanya cocok dengan entri `MRUListEx` posisi 0 (yang paling baru); entri lain hanya punya urutan, bukan waktu. Mandiant memakai pola ini untuk WordWheelQuery: sebelum ada search LNK, waktu pencarian hanya bisa disimpulkan untuk kata terbaru dari LastWriteTime key [S20].
2. **Satu perubahan menimpa waktu sebelumnya.** Bila Andi menyimpan file lewat dialog Save As Selasa, LastWriteTime key `OpenSavePidlMRU` ikut bergeser ke Selasa, dan waktu entri Senin tidak lagi terlihat dari key itu. Ketiadaan LastWriteTime di sebuah jendela waktu hanya berarti tidak ada perubahan terakhir di jendela itu, bukan tidak ada perubahan sama sekali; perubahan di jendela itu yang tertimpa perubahan berikutnya tidak lagi terlihat.

Rangkaian tiga tingkat bukti dari Day lama tetap berguna sebagai pegangan: TypedPaths membuktikan path diketik (navigasi sengaja), ShellBags membuktikan folder dilihat, dan LNK, Jump List, RecentDocs, serta OpenSavePidlMRU membuktikan file dibuka atau dipilih [S1]. WordWheelQuery menambah tingkat keempat yang penting untuk kasus ini: kata yang dicari. Penyerang yang bekerja di desktop dan mencari kredensial akan meninggalkan kata seperti "password" di WordWheelQuery; skrip yang mencari kata yang sama dengan `Select-String` tidak menyentuh key itu.

### 1.6 Memisahkan pelaku: pemilik akun, responder, penyerang, dan tanda kerja interaktif

Pertanyaan kelima Sari menuntut pemisahan tiga kelompok jejak di satu laptop: Andi, Yoga, dan penyerang yang menumpang sesi Andi.

**Andi** menulis ke profilnya sendiri, dan polanya bisa dicocokkan dengan hal yang sudah diketahui: jam kerja, folder kerja (Documents, Desktop, Downloads, share tim penagihan), file kerja yang ia akui, dan sumber lain yang mencatat kejadian yang sama (Sysmon EID 11 untuk ZIP, `$J` untuk penyimpanan Excel, `$I` Recycle Bin untuk penghapusan).

**Responder** memakai profil terpisah. Yoga login dengan `ir-admin` lewat Switch user, sehingga semua jejak shell Yoga ada di `C:\Users\ir-admin\`, bukan di profil Andi. Profil yang baru terbentuk saat responder login pertama kali juga jejak responder yang dicatat, bukan temuan.

**Penyerang** di kasus ini tidak punya profil sendiri. Kode penyerang berjalan dalam sesi dan akun Andi (Logon ID `0x3A1F2C`, token terbatas; Day 05 bagian 2.4), jadi kalau penyerang membuka Explorer di desktop Andi, jejaknya akan bercampur dengan jejak Andi di profil Andi. Pemisahannya lewat waktu dan isi, bukan lewat profil.

Kerja interaktif di desktop sesi Andi hanya mungkin lewat tiga jalan, dan masing-masing meninggalkan jejak di sumber yang berbeda. Tabel ini dipakai untuk menyusun argumen, bukan hanya untuk mencari artefak: baca kolom "Jejak yang diharapkan" dan tanyakan apakah jejak itu ada.

| Jalan masuk ke desktop | Jejak yang diharapkan | Sumber |
|---|---|---|
| Konsol fisik: membuka layar yang terkunci | 4624 logon type 7 (unlock) untuk akun yang membuka | Security log (Day 05 bagian 1.2) |
| Remote Desktop | 4624 logon type 10 atau reconnect, event RemoteConnectionManager | Security dan RCM log (Day 05) |
| Desktop yang dibiarkan tidak terkunci | Tidak ada logon baru; hanya artefak shell dan aktivitas aplikasi di jam yang tidak cocok dengan pemilik | Artefak Day ini, UserAssist (Day 07) |

Tanda kerja interaktif penyerang di artefak shell biasanya berupa salah satu dari ini: folder yang tidak pernah dipakai pemilik akun (folder penyerang di `AppData`, folder sistem, share yang bukan milik timnya), path yang diketik ke lokasi seperti itu di TypedPaths, kata kunci kredensial di WordWheelQuery atau search LNK, dokumen sensitif yang dibuka di jam ketika pemilik tidak bekerja, dan LNK yang menunjuk file di folder sementara atau drive yang tidak dikenal.

Ada satu batas yang harus ditulis di jawaban untuk Sari: hands-on-keyboard tidak selalu berarti desktop. Operator yang mengetik perintah secara langsung lewat kanal C2 bekerja interaktif dari sisi manusia, tetapi dari sisi Windows ia hanya proses PowerShell yang menjalankan perintah. Artefak shell tidak membedakan skrip yang berjalan sendiri dari perintah yang diketik operator lewat C2. Pembedaan itu butuh sumber lain: isi dan pola 4104 (perintah satu per satu vs blok skrip utuh), jeda waktu antar perintah, telemetry EDR, memori, dan pola trafik ke C2.

**Menautkan file ke perangkat USB.** Bagian ini dipertahankan dari Day lama karena muncul setiap kali LNK atau ShellBags menunjuk drive removable, termasuk saat memisahkan drive USB responder. LNK menyimpan `DriveSerialNumber`, yaitu nomor seri volume yang dibuat saat volume diformat [S5]; USBSTOR menyimpan nomor seri perangkat yang dilaporkan hardware. Keduanya berbeda dan tidak bisa dicocokkan langsung. Yang dibutuhkan adalah artefak yang memuat keduanya, atau rantai yang menghubungkannya [S3]:

| Jembatan | Isi | Catatan |
|---|---|---|
| Event log `Microsoft-Windows-Partition/Diagnostic` EID 1006 | Nomor seri perangkat, vendor, model, dan salinan sektor awal volume (VBR) yang memuat nomor seri volume | Ada di build Windows 10/11 yang lebih baru; nomor seri volume perlu diekstrak dari data VBR |
| `SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt` | Nama subkey memuat nomor seri perangkat, label, dan nomor seri volume (desimal) | Terkait ReadyBoost; sering tidak ada bila disk sistem SSD |
| `SYSTEM\MountedDevices` dan MountPoints2 | Volume GUID dan huruf drive dipetakan ke device instance path yang memuat nomor seri USBSTOR; MountPoints2 menautkan volume GUID ke pengguna | Menghubungkan perangkat, huruf drive, dan pengguna, tetapi bukan nomor seri volume |

Contoh generik dari Day lama (bukan PT JAB) memperlihatkan rantainya untuk kasus pencurian data: TypedPaths berisi `\\fileserver\finance` (path share diketik); ShellBags berisi `\\fileserver\finance\reports` dan `E:\exfil` (share dan folder di removable dijelajahi); LNK menunjuk `E:\exfil\report_final.xlsx` di volume `A4F21B3C` (file di removable dibuka); RecentDocs memuat `report_final.xlsx`; EID 1006 atau EMDMgmt menautkan volume `A4F21B3C` ke perangkat SanDisk dengan nomor seri berawalan `4C530001`; MountedDevices menunjukkan perangkat itu memakai huruf `E:`; dan MountPoints2 di NTUSER pengguna memuat volume GUID-nya. Kesimpulan yang boleh ditulis: pengguna menavigasi ke share finance, membuka laporan, dan menyentuh file di USB tertentu. Artefak ini membuktikan akses dan pembukaan, bukan penyalinan; untuk penyalinan dibutuhkan korelasi dengan `$J` dan `$MFT` di volume tujuan atau artefak lain. Bila jembatan tidak tersedia, tulis bahwa file dibuka dari volume removable `E:` dengan nomor seri volume tertentu, tanpa mengklaim perangkat fisiknya. Detail USBSTOR dan MountedDevices dari sisi registry dibahas di Day 09.

### 1.7 Batas kesimpulan: ZIP, folder Temp, Windows 10 dan 11, pembersihan, dan cara menulis "tidak ada"

Pertanyaan keenam Sari ("seberapa kuat, dan apa yang bisa membuatnya salah?") adalah bagian yang menentukan apakah jawabanmu bisa masuk laporan.

**ZIP dan folder Temp.** Explorer memperlakukan ZIP sebagai folder (bagian 1.2), jadi membuka ZIP lewat Explorer bisa meninggalkan ShellBags untuk arsip itu dan LNK untuk file `.zip`-nya; contoh di panduan CSIRT.SK memperlihatkan LNK `pestudio.zip.lnk` yang dibuat saat arsip di Downloads dibuka [S17]. Yang belum pasti adalah file yang dijalankan dari dalam ZIP. Saat pengguna membuka file dari dalam arsip, Explorer mengekstraknya ke folder sementara (di laptop Andi `Temp1_Tagihan-Okt-2026.zip`; nama persisnya cek di build lab) lalu menjalankan aplikasi pemiliknya. Sumber yang diperiksa tidak menjelaskan apakah shell membuat LNK, entri RecentDocs, atau item Jump List untuk file hasil ekstraksi itu, dan apakah jenis skrip seperti `.js` disaring seperti `.exe` [S7]. Uji di lab sebelum menulis apa pun tentang ketiadaan LNK untuk `.js` (bagian 3).

**Windows 10 dan 11.** Format LNK yang dipakai Day ini adalah [MS-SHLLINK] revisi terbaru [S3], dan sumber yang diperiksa tidak menyebut perubahan format ShellBags, LNK, atau Jump List antara Windows 10 dan 11; praktisi menegaskan path registry ShellBags tidak berubah dan perilaku penulisannya bisa berbeda antar versi Windows tanpa dokumentasi publik [S15]. Perbedaan praktis yang terdokumentasi adalah hive aplikasi Windows App (bagian 1.1) [S15]. JLECmd disebut mendukung Jump List Windows 7 sampai 11 [S18]. Untuk build tertentu, uji perilaku di lab dengan build yang sama.

**Pembersihan dan kebijakan.** `SHAddToRecentDocs` yang dipanggil dengan nilai NULL menghapus semua data pemakaian [S7], dan kebijakan "Do not keep history of recently opened documents" di User Configuration, Administrative Templates, Start Menu and Taskbar membuat sistem berhenti menyimpan shortcut dokumen terbaru [S22]. Dokumentasi kebijakan itu berasal dari arsip Microsoft untuk Windows lama; nama dan efek pengaturan setara di Windows 11 (termasuk pengaturan privasi untuk item yang baru dibuka) perlu dicek di GPO PT JAB dan di hive `NTUSER.DAT`. Tidak ada saklar bawaan untuk mematikan ShellBags, tetapi praktisi menunjukkan ACL yang menolak penulisan ke `BagMRU` bisa menghentikan entri baru [S15]. Folder Recent yang kosong di laptop yang sudah lama dipakai adalah alasan untuk mencari pembersihan, bukan alasan untuk menyimpulkan "tidak ada aktivitas".

**Keberadaan bukan niat.** File bisa muncul di RecentDocs atau Recent karena dibuka oleh aplikasi atas nama pengguna, bukan selalu karena pengguna sadar membukanya. Sebutkan ini bila kesimpulanmu menyentuh niat.

Setiap jawaban dari artefak shell ditulis dengan empat unsur, sama seperti jawaban file system (Day 08 bagian 1.7):

1. **Klaim:** jejak interaktif ada atau tidak ada, untuk profil dan rentang waktu tertentu.
2. **Jendela:** rentang waktu yang benar-benar tercakup (misalnya sejak entri tertua di Recent, sampai laptop dimatikan).
3. **Dasar dan korelasi:** artefak mana, ditambah sumber yang mengunci siapa yang bisa berada di desktop (unlock, RDP).
4. **Keyakinan dan batas:** termasuk kalimat bahwa artefak shell tidak mencatat akses oleh proses, sehingga "tidak ada jejak interaktif" tidak berarti "file tidak diakses".

Untuk `INC-2026-019`, kalimat intinya: tidak ada jejak interaktif penyerang di desktop sesi Andi, karena tidak ada yang membuka layar di malam hari, tidak ada RDP, dan semua artefak shell di sesi Andi cocok dengan pekerjaan Andi sendiri; aktivitas penyerang yang diketahui (pencarian dan pembacaan file 23:40, SSH 02:14) berjalan lewat PowerShell dan terlihat di event log dan memori, bukan di artefak shell (bagian 2.7).

## 2. Contoh dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Nama kolom CSV dan format nilai bisa berbeda antar versi SBECmd, LECmd, JLECmd, dan RECmd; cocokkan dengan versi di lab-mu. Semua timestamp dari EZ Tools dalam UTC; laporan PT JAB memakai WIB (UTC+7), jadi setiap waktu penting ditulis keduanya sekali. Perintah ditulis untuk lingkungan PT JAB; untuk latihan, jalankan hanya di VM lab terisolasi (bagian 3).

### 2.1 Menyiapkan E15-W1 dan mengambil hive pengguna serta folder Recent

Langkah ini menyiapkan bahan untuk semua jawaban ke Sari. Pukul 09:10 kamu menghitung ulang hash `E15-W1` di `JKT-DFIR01` dan mencocokkannya dengan catatan Yoga, lalu me-mount volume sistemnya read-only sebagai `G:` dengan alat mount image yang sama seperti Day 08 (prinsipnya di Day 02 bagian 1.5). Hive pengguna dan folder Recent diambil dengan KAPE supaya ada copylog dengan SHA-1 tiap file (Day 03 bagian 2.3).

```
C:\DFIR\tools\KAPE\kape.exe --tsource G: --target RegistryHivesUser,LNKFilesAndJumpLists --tdest C:\DFIR\work\INC-2026-019\E15-W1\user --tflush
```

- `--tsource G:`: volume sistem E15-W1 yang di-mount read-only.
- `RegistryHivesUser`: `NTUSER.DAT` dan `UsrClass.dat` setiap profil beserta transaction log `.LOG*`, ditambah hive `DEFAULT` [S14].
- `LNKFilesAndJumpLists`: folder `Recent` setiap profil secara rekursif (termasuk `AutomaticDestinations` dan `CustomDestinations`), `Office\Recent`, LNK di Desktop, dan LNK Start Menu [S13].
- Hive aplikasi Windows App di `AppData\Local\Packages\...\SystemAppData\Helium\` tidak termasuk kedua target itu (bagian 1.1). Di E15, profil Andi diperiksa terpisah untuk folder `Helium`, dan aplikasi yang dipakai Andi di insiden ini (Outlook, Excel, Explorer) bukan Windows App, sehingga tidak ada hive tambahan yang relevan; daftar paket yang terpasang tetap dicatat di case notes.

Keluaran ilustrasi (ringkas):

```
2026-10-23 09:18:40  Using Targets: RegistryHivesUser,LNKFilesAndJumpLists
2026-10-23 09:19:52  Copied 241 files (deferred: 0). Skipped (deduped): 0
```

Variabel PowerShell yang dipakai ulang di bagian 2.2 sampai 2.6:

```powershell
$ez  = 'C:\DFIR\tools\EZTools-2026-10-15\net9'                   # EZ Tools 2026.5.0, dibekukan selama kasus
$t   = 'C:\DFIR\work\INC-2026-019\E15-W1\user\G'                  # hasil Targets; nama subfolder volume cek di hasil KAPE
$out = '\\jkt-evid01\cases\INC-2026-019\analysis\E15-W1\EZ-2026.5.0\UserActivity'
```

Case notes untuk langkah ini:

```
INC-2026-019 | Case notes forensik | <kamu> | TZ catatan: UTC+7 (WIB)
2026-10-23 09:00  Permintaan Sari: ada/tidak jejak interaktif penyerang di sesi andi.pratama (JKT-WS-0388);
                  untuk draf after-action report PIR Selasa 2026-10-27; tenggat 16:00.
2026-10-23 09:10  E15-W1: hash cocok dengan catatan Yoga. Mount read-only sebagai G: di JKT-DFIR01.
2026-10-23 09:18  KAPE Targets RegistryHivesUser,LNKFilesAndJumpLists -> C:\DFIR\work\INC-2026-019\E15-W1\user.
                  Profil di E15: andi.pratama, ir-admin, Default, Public.
                  Konteks: laptop dimatikan normal oleh Yoga (ir-admin) Kamis 2026-10-15 08:47 sebelum image;
                  sesi Andi ikut di-logoff saat shutdown, sehingga hive Andi sudah ditulis ke disk.
                  Tindakan responder di laptop ini (Day 05): Selasa 12:31 E02, 12:36 getfile, 12:38-12:55
                  ir-admin + WinPmem dari USB-E-07; Kamis 08:46-08:47 ir-admin + shutdown.
2026-10-23 09:20  Mulai parsing (2.2-2.6).
```

**Cara membaca hasil:** dua fakta di case notes menentukan apa yang bisa dipercaya. Shutdown normal berarti perubahan registry sesi Andi sudah masuk ke hive; RECmd tetap diberi transaction log, dan di bagian 2.5 ia melaporkan hive Andi tidak dirty. Daftar tindakan responder menjadi dasar pelabelan di bagian 2.6.

**Kapan gagal:** hanya `NTUSER.DAT` yang diambil, sehingga ShellBags lokal di `UsrClass.dat` tidak ada dan hasil kosong dibaca sebagai "tidak ada folder yang dibuka"; atau profil `ir-admin` tidak ikut diproses sehingga jejak Yoga tidak bisa ditunjukkan secara positif.

### 2.2 ShellBags dengan SBECmd

Langkah ini menjawab pertanyaan kedua Sari: folder apa yang dibuka lewat Explorer di sesi Andi, dan kapan.

```powershell
& "$ez\SBECmd.exe" -d "$t\Users\andi.pratama" --csv "$out" --csvf E15-W1_SBE_andi.csv
& "$ez\SBECmd.exe" -d "$t\Users\ir-admin" --csv "$out" --csvf E15-W1_SBE_ir-admin.csv
```

- `-d`: folder profil; SBECmd mencari `NTUSER.DAT` dan `UsrClass.dat` di dalamnya. Opsi live (`-l`) hanya untuk host hidup dengan hak admin [S15][S19]. Opsi SBECmd di sini mengikuti panduan praktisi dan Day lama; cek persisnya dengan `SBECmd.exe -h` di versi-mu.
- Dua profil diproses terpisah supaya setiap baris CSV jelas milik siapa.

Keluaran ilustrasi untuk Andi, kolom diringkas dan dipilih baris yang relevan dari 214 baris (198 dari `UsrClass.dat`, 16 dari `NTUSER.DAT`); waktu UTC:

```
AbsolutePath                                              ShellType      Hive      FirstInteracted       LastInteracted
\\JKT-FS01\Penagihan\tools                                Network        NTUSER    2026-09-11 07:19:48   2026-09-11 07:19:48
My Computer\C:\Users\andi.pratama\Documents               Directory      UsrClass  2026-03-16 02:40:11   2026-10-12 07:01:50
My Computer\C:\Users\andi.pratama\Documents\Arsip-2026    Directory      UsrClass  2026-04-02 03:12:09   2026-10-09 08:05:27
My Computer\C:\Users\andi.pratama\Downloads               Directory      UsrClass  2026-03-16 02:41:30   2026-10-13 04:12:31
My Computer\C:\Users\andi.pratama\Downloads\Tagihan-Okt-2026.zip   Zip file   UsrClass  2026-10-12 09:05:04   2026-10-12 09:05:04
```

**Cara membaca hasil:**

- **`\\JKT-FS01\Penagihan\tools`** tercatat di `NTUSER.DAT`, sesuai pembagian hive untuk share jaringan (bagian 1.2), Jumat 2026-09-11 14:19:48 WIB. Empat puluh lima detik kemudian `export-tagihan.ps1` lahir di Documents (Created 14:20:33 WIB, Day 08 bagian 2.2). Ini cerita asal skrip itu: Andi membuka folder skrip tim di share dan menyalinnya ke Documents.
- **Documents** terakhir berinteraksi Senin 14:01:50 WIB, 21 detik sebelum 4104 pertama dari `export-tagihan.ps1` (14:02:11, Day 05 bagian 2.5). Andi membuka Documents lalu menjalankan skripnya.
- **Downloads** terakhir berinteraksi Selasa 11:12:31 WIB, sembilan detik sebelum ZIP dipindah ke Recycle Bin (11:12:40, Day 08 bagian 2.5). Andi membuka Downloads untuk menghapus ZIP setelah ditelepon Gilang.
- **`Downloads\Tagihan-Okt-2026.zip`** sebagai entri berjenis arsip, Senin 16:05:04 WIB: Andi membuka ZIP di Explorer, lima detik sebelum `.js` diekstrak (16:05:09). Explorer memperlakukan ZIP sebagai folder (bagian 1.2); nama jenis yang ditampilkan SBECmd untuk arsip cek di versi-mu.

**Kueri: entri yang tidak cocok dengan pola Andi.** Dua filter dijalankan atas CSV Andi:

```powershell
$sb = Import-Csv "$out\E15-W1_SBE_andi.csv"
# 1. Folder penyerang dan folder sementara
$sb | Where-Object { $_.AbsolutePath -match 'SysCache|\\AppData\\|\\Temp\\|Temp1_' } | Measure-Object
# 2. Key BagMRU yang berubah antara Senin 17:10 WIB dan Selasa 08:12:05 WIB
$sb | Where-Object { $_.LastWriteTime -ge '2026-10-12 10:10:00' -and $_.LastWriteTime -lt '2026-10-13 01:12:05' } |
  Select-Object AbsolutePath, LastWriteTime
```

- Regex filter 1 mencakup folder `SysCache`, semua path di bawah `AppData`, folder `Temp`, dan nama folder ekstraksi ZIP.
- Rentang filter 2 dalam UTC: `2026-10-12 10:10` sama dengan Senin 17:10 WIB, saat Andi mengunci layar dan pulang menurut pengakuannya; `2026-10-13 01:12:05` sama dengan unlock Selasa 08:12:05 WIB. Nama kolom `LastWriteTime` cek di versi-mu.

Keluaran ilustrasi: filter 1 `Count : 0`; filter 2 nol baris.

**Cara membaca hasil:** tidak ada folder penyerang, folder `AppData`, atau folder ekstraksi yang pernah dibuka lewat Explorer di profil Andi, dan tidak ada key `BagMRU` yang berubah selama Andi tidak di tempat. Pencarian `upd.ps1` di Documents dan Desktop pukul 23:40:17 tidak muncul, sesuai mekanisme di bagian 1.1: skrip memanggil API file system, bukan Explorer. Batasnya ditulis di bagian 1.5 aturan 2: perubahan malam itu yang tertimpa perubahan Andi berikutnya tidak akan terlihat dari LastWriteTime. Karena itu filter 2 hanya dipakai bersama bukti bahwa tidak ada yang membuka layar malam itu (bagian 2.7), bukan sendirian.

**Variasi:** buka `UsrClass.dat` Andi di ShellBags Explorer untuk melihat hierarki dan subkey `Bags` per `NodeSlot`. Folder yang punya preferensi tampilan di `Bags` berarti berhasil ditampilkan, sedangkan folder induk tanpa `NodeSlot` hanya dilewati (bagian 1.2).

**Kapan gagal:** `FirstInteracted` dan `LastInteracted` dikutip di laporan sebagai "jam Andi membuka folder". Kolom itu inferensi parser [S15]; tulis "sekitar" dan sebut korelasinya (4104, Recycle Bin, Sysmon).

### 2.3 LNK dengan LECmd

Langkah ini menjawab pertanyaan ketiga: file apa yang dibuka lewat shell, dari mana, dan kapan.

```powershell
& "$ez\LECmd.exe" -d "$t\Users\andi.pratama\AppData\Roaming\Microsoft\Windows\Recent" --csv "$out" --csvf E15-W1_LNK_andi.csv -q
& "$ez\LECmd.exe" -d "$t\Users\ir-admin\AppData\Roaming\Microsoft\Windows\Recent" --csv "$out" --csvf E15-W1_LNK_ir-admin.csv -q
```

- `-d`: folder Recent diproses rekursif; LECmd hanya mengambil file `*.lnk` kecuali `--all` dipakai [S8]. Folder `AutomaticDestinations` di dalamnya diproses JLECmd di bagian 2.4.
- `-q`: hanya menampilkan nama file yang diproses, mempercepat ekspor [S8].
- `--csv` dan `--csvf`: folder dan nama CSV [S8].

Keluaran ilustrasi di konsol: profil Andi 87 file `.lnk` diproses, `SourceModified` tertua 2026-06-22 dan terbaru 2026-10-13 01:24:05 UTC; profil `ir-admin` nol file `.lnk`.

Filter LNK yang diperbarui sejak email diterima sampai laptop dimatikan:

```powershell
$lnk = Import-Csv "$out\E15-W1_LNK_andi.csv"
$lnk | Where-Object { $_.SourceModified -ge '2026-10-12 08:58:00' } | Sort-Object SourceModified |
  Select-Object SourceFile, SourceCreated, SourceModified, LocalPath, TargetCreated, TargetModified, FileSize,
                DriveType, VolumeSerialNumber, TargetMFTEntryNumber, MachineID
```

- `2026-10-12 08:58` UTC adalah Senin 15:58 WIB, saat email diterima.
- Kolom yang dipilih memisahkan waktu LNK (`Source*`) dari waktu target (`Target*`), ditambah volume dan mesin [S17].

Keluaran ilustrasi (UTC; `SourceFile` disingkat ke nama file):

```
SourceFile           : Tagihan-Okt-2026.zip.lnk
SourceCreated        : 2026-10-12 09:05:04
SourceModified       : 2026-10-12 09:05:04
LocalPath            : C:\Users\andi.pratama\Downloads\Tagihan-Okt-2026.zip
TargetCreated        : 2026-10-12 09:04:48
TargetModified       : 2026-10-12 09:04:48
FileSize             : 3371
DriveType            : Fixed storage media (Hard drive)
VolumeSerialNumber   : B41C7E59
TargetMFTEntryNumber : 287889
MachineID            : jkt-ws-0388

SourceFile           : Downloads.lnk
SourceCreated        : 2026-03-16 02:41:30
SourceModified       : 2026-10-12 09:05:04
LocalPath            : C:\Users\andi.pratama\Downloads

SourceFile           : Rekap-Penagihan-Okt-2026.xlsx.lnk
SourceCreated        : 2026-10-01 01:15:02
SourceModified       : 2026-10-13 01:24:05
LocalPath            : C:\Users\andi.pratama\Desktop\Rekap-Penagihan-Okt-2026.xlsx
TargetCreated        : 2026-10-01 01:14:40
TargetModified       : 2026-10-12 08:41:10
FileSize             : 84112
DriveType            : Fixed storage media (Hard drive)
VolumeSerialNumber   : B41C7E59
MachineID            : jkt-ws-0388

SourceFile           : Desktop.lnk
SourceCreated        : 2026-03-16 02:40:02
SourceModified       : 2026-10-13 01:24:05
LocalPath            : C:\Users\andi.pratama\Desktop
```

**Cara membaca hasil:**

- **`Tagihan-Okt-2026.zip.lnk`** dibuat Senin 16:05:04 WIB, enam belas detik setelah ZIP disimpan (Target Created 16:04:48, cocok dengan Sysmon EID 11 dan `$J` `FileCreate`). Ukuran target 3.371 byte sama dengan ukuran ZIP di `$MFT` (Day 08). `SourceCreated` sama dengan `SourceModified`, sehingga ZIP hanya dibuka sekali lewat shell. Nomor seri volume `B41C7E59` adalah volume sistem laptop dan `MachineID` adalah laptop itu sendiri: ZIP dibuka dari disk lokal, bukan dari share atau USB. Entry `$MFT` 287889 tetap dipakai `$R7K2QXD.zip` setelah ZIP dipindah ke Recycle Bin, karena pemindahan itu rename (Day 08 bagian 1.6); cocokkan di `$MFT` sebelum menuliskannya.
- **`Downloads.lnk`** diperbarui pada detik yang sama: LNK folder induk yang dibuat bersama LNK file (bagian 1.3).
- **`Rekap-Penagihan-Okt-2026.xlsx.lnk`** pertama dibuat 2026-10-01 08:15:02 WIB dan terakhir diperbarui Selasa 08:24:05 WIB, dua detik sebelum Excel membuat file pemilik `~$Rekap-Penagihan-Okt-2026.xlsx` (08:24:07 di `$J`, Day 08 bagian 2.4). `TargetModified` di LNK adalah Senin 15:41:10 WIB, yaitu keadaan file saat dibuka Selasa pagi, sebelum Andi menyimpannya 08:31:44. Ini contoh langsung aturan di bagian 1.3: waktu target adalah potret saat LNK ditulis, bukan keadaan terakhir file.
- **Tidak ada LNK lain** yang diperbarui setelah email diterima. Tidak ada LNK yang menunjuk `Temp1_Tagihan-Okt-2026.zip`, `Tagihan-Okt-2026.js`, folder `SysCache`, `export-tagihan.ps1`, atau file lain di Documents; tidak ada search LNK (target ID `Search Folder`).
- **`ir-admin` tanpa LNK:** Yoga tidak membuka dokumen lewat shell. Ia membuka folder di drive USB (bagian 2.6), dan navigasi folder tidak menambah Recent karena class `Folder` dan `Directory` memakai `NoRecentDocs` secara default [S7].

Satu ketiadaan perlu kalimat sendiri. Andi membuka `.js` dari dalam ZIP, dan tidak ada LNK atau entri RecentDocs untuk file itu. Ketiadaan ini bukan bukti bahwa `.js` tidak dibuka lewat Explorer, karena Sysmon EID 1 sudah menunjukkan `wscript.exe` berinduk `explorer.exe` dengan path di folder `Temp1_...` (Day 05 bagian 2.4). Penjelasannya kemungkinan perilaku shell untuk file yang dijalankan dari dalam arsip atau untuk jenis skrip, yang belum dikonfirmasi sumber yang diperiksa (bagian 1.7). Jawaban ke Sari menyebut ini sebagai hal yang diuji di lab, bukan sebagai temuan.

**Variasi:** jalankan LECmd dengan `-r` untuk menampilkan hanya LNK yang menunjuk drive removable [S8]. Di profil Andi hasilnya nol; di kasus pencurian data, inilah filter pertama.

**Kapan gagal:** `TargetModified` dibaca sebagai waktu file dibuka, atau `SourceAccessed` dipakai sebagai waktu akses padahal pembaruan last access di laptop ini mati (`NtfsDisableLastAccessUpdate` `0x80000003`, Day 08 bagian 2.3).

### 2.4 Jump List dengan JLECmd

Langkah ini menguatkan pertanyaan ketiga dengan dimensi aplikasi dan hitungan.

```powershell
& "$ez\JLECmd.exe" -d "$t\Users\andi.pratama\AppData\Roaming\Microsoft\Windows\Recent" --csv "$out" --csvf E15-W1_JL_andi.csv -q
```

- `-d` ke folder Recent: JLECmd hanya mengambil file `.automaticDestinations-ms` dan `.customDestinations-ms` kecuali `--all` dipakai, sehingga kedua jenis Jump List diproses dalam satu jalan [S9][S18].
- Di profil Andi ada 14 file Automatic Destinations dan 3 file Custom Destinations.

Filter item Jump List yang dipakai sejak email diterima:

```powershell
$jl = Import-Csv "$out\E15-W1_JL_andi_AutomaticDestinations.csv"
$jl | Where-Object { $_.LastModified -ge '2026-10-12 08:58:00' } | Sort-Object LastModified |
  Select-Object AppId, AppIdDescription, Path, MRU, InteractionCount, LastModified, Hostname
```

- JLECmd menulis CSV terpisah untuk Automatic dan Custom Destinations; nama file hasilnya cek di versi-mu.
- `LastModified` di sini adalah waktu terakhir item dipakai menurut `DestList` [S18].

Keluaran ilustrasi (UTC):

```
AppId             AppIdDescription        Path                                                       MRU  InteractionCount  LastModified         Hostname
f01b4d95cf55d32a  Quick Access            C:\Users\andi.pratama\Downloads\Tagihan-Okt-2026.zip       0    1                 2026-10-12 09:05:04  jkt-ws-0388
<AppID Excel>     Microsoft Excel         C:\Users\andi.pratama\Desktop\Rekap-Penagihan-Okt-2026.xlsx 0   23                2026-10-13 01:24:05  jkt-ws-0388
```

**Cara membaca hasil:**

- **Explorer (`f01b4d95cf55d32a`)** mencatat ZIP dibuka satu kali, Senin 16:05:04 WIB, detik yang sama dengan LNK dan ShellBags. Deskripsi yang ditampilkan JLECmd untuk AppID itu dan apakah ZIP masuk Jump List Explorer saat dibuka sebagai folder arsip perlu dicek di lab; yang penting di sini adalah tiga artefak independen menunjuk detik yang sama.
- **Excel** mencatat `Rekap-Penagihan-Okt-2026.xlsx` sebagai item terbaru dengan 23 kali pemakaian, terakhir Selasa 08:24:05 WIB. Hitungan 23 sejak awal Oktober cocok dengan buku kerja yang dipakai harian. Ini jawaban yang dijanjikan Day 08 untuk penyimpanan Excel Selasa pagi: pelakunya Excel di profil Andi, pada jam kerja Andi. Ganti `<AppID Excel>` dengan nilai yang tertulis di CSV-mu; AppID bergantung pada versi dan jalur instalasi Office.
- **Tidak ada item lain** sejak email diterima: tidak ada Notepad, editor skrip, atau aplikasi lain yang membuka file di Documents, Desktop, atau `AppData` selama insiden.

**Variasi:** jalankan dengan `--dumpTo "$out\jl-lnk"` untuk mengekspor LNK yang tertanam di Jump List, lalu proses folder itu dengan LECmd [S9]. Cara ini berguna bila LNK di Recent sudah dihapus tetapi Jump List masih menyimpan salinannya.

**Kapan gagal:** AppID yang tidak dikenal tampil hanya sebagai heksadesimal lalu dilewati. Cari padanannya, catat sumbernya, dan muat lewat `--appIds` [S9].

### 2.5 RecentDocs, OpenSavePidlMRU, LastVisitedPidlMRU, TypedPaths, dan WordWheelQuery dengan RECmd

Langkah ini menjawab pertanyaan keempat: apa yang diketik, dicari, dan dipilih lewat dialog.

```powershell
& "$ez\RECmd\RECmd.exe" -f "$t\Users\andi.pratama\NTUSER.DAT" --bn "$ez\RECmd\BatchExamples\UserActivity.reb" --csv "$out" --csvf E15-W1_RECmd_UserActivity_andi.csv
```

- `-f`: satu hive, supaya semua baris milik Andi [S10].
- `--bn`: batch file; wajib bersama `--csv` [S10]. `UserActivity.reb` (versi 1, "User Configuration and Activity") memuat antara lain `RecentDocs` dan `ComDlg32\OpenSavePidlMRU` (rekursif), `ComDlg32\LastVisitedPidlMRU`, `TypedPaths`, `WordWheelQuery`, `RunMRU`, dan `UserAssist` [S11]. Batch yang lebih lengkap, `DFIRBatch.reb` (dulu Kroll Batch), juga punya kategori User Activity [S12]. Lokasi folder `BatchExamples` di instalasi-mu cek di hasil Get-ZimmermanTools.
- Transaction log hive dirty dipakai secara default; `--nl` mematikannya [S10]. Konsol melaporkan hive Andi tidak dirty, sesuai shutdown normal (bagian 2.1).

Keluaran ilustrasi, disederhanakan ke kolom key, isi yang sudah didekode, dan LastWriteTime key (UTC). Nilai MRU berbentuk biner; isi terdekode dibaca lewat file detail plugin atau Registry Explorer, dan nama kolomnya cek di versi-mu:

```
Key                                         Isi (MRU 0 lebih dulu)                                              LastWriteTime
RecentDocs                                  Rekap-Penagihan-Okt-2026.xlsx, Tagihan-Okt-2026.zip, Downloads, ...  2026-10-13 01:24:05
RecentDocs\.xlsx                            Rekap-Penagihan-Okt-2026.xlsx, Rekap-Penagihan-Sep-2026.xlsx, ...    2026-10-13 01:24:05
RecentDocs\.zip                             Tagihan-Okt-2026.zip, Bukti-Transfer-Sep-2026.zip                    2026-10-12 09:05:04
ComDlg32\OpenSavePidlMRU\zip                C:\Users\andi.pratama\Downloads\Tagihan-Okt-2026.zip                 2026-10-12 09:04:48
ComDlg32\OpenSavePidlMRU\*                  C:\Users\andi.pratama\Downloads\Tagihan-Okt-2026.zip, ...            2026-10-12 09:04:48
ComDlg32\LastVisitedPidlMRU                 OUTLOOK.EXE -> C:\Users\andi.pratama\Downloads                       2026-10-12 09:04:48
TypedPaths                                  url1 \\JKT-FS01\Penagihan                                            2026-09-11 07:19:41
WordWheelQuery                              rekap, kontrak, tagihan sep                                          2026-10-09 08:12:30
```

**Cara membaca hasil:**

- **OpenSavePidlMRU dan LastVisitedPidlMRU** pada detik 16:04:48 WIB menunjukkan Andi memilih lokasi simpan ZIP di dialog Save As milik Outlook. Sysmon EID 11 pada detik yang sama mencatat `OUTLOOK.EXE` menulis ZIP ke Downloads (Day 05 bagian 2.4). Penyimpanan lampiran itu adalah aksi interaktif Andi, bukan unduhan otomatis.
- **RecentDocs `.zip`** berubah Senin 16:05:04 WIB, sama dengan LNK dan ShellBags. `.xlsx` dan key induk `RecentDocs` berubah Selasa 08:24:05 WIB, sama dengan LNK dan Jump List Excel. Tidak ada subkey `.js`, dan tidak ada subkey untuk `.ps1` atau `.txt` yang berubah selama insiden. Apakah menjalankan `.ps1` lewat menu "Run with PowerShell" menambah entri RecentDocs perlu dicek di lab; di E15 tidak ada entri untuk `export-tagihan.ps1`.
- **TypedPaths** hanya berisi path share tim `\\JKT-FS01\Penagihan`, dengan LastWriteTime Jumat 2026-09-11 14:19:41 WIB, tujuh detik sebelum ShellBags mencatat folder `Skrip` di share itu. Andi mengetik alamat share lalu masuk ke subfolder. Tidak ada path ke `AppData`, folder Temp, atau lokasi lain yang diketik selama insiden. Apakah `url1` selalu entri terbaru perlu dicek di lab; di sini hanya ada satu entri.
- **WordWheelQuery** berisi tiga kata pencarian Andi, terakhir Jumat 2026-10-09 15:12:30 WIB, tiga hari sebelum email datang. Tidak ada kata seperti password, svc, atau ssh. Pencarian dengan kata-kata itu pukul 23:40 dilakukan `upd.ps1` (4104), dan skrip tidak memakai kotak pencarian Explorer.
- **RunMRU** tidak berubah selama insiden.

**Kueri: key apa pun yang berubah saat Andi tidak di tempat.**

```powershell
$re = Import-Csv "$out\E15-W1_RECmd_UserActivity_andi.csv"
$re | Where-Object { $_.LastWriteTimestamp -ge '2026-10-12 10:10:00' -and $_.LastWriteTimestamp -lt '2026-10-13 01:12:05' } |
  Select-Object Description, KeyPath, LastWriteTimestamp
```

Keluaran ilustrasi: nol baris. Nama kolom waktu di CSV RECmd cek di versi-mu.

**Cara membaca hasil:** tidak ada key aktivitas pengguna di `NTUSER.DAT` Andi yang berubah antara Senin 17:10 dan Selasa 08:12:05 WIB, termasuk UserAssist. Seperti di bagian 2.2, ini dibaca bersama bukti layar terkunci, bukan sendirian.

**Variasi:** jalankan RECmd dengan batch yang sama atas `NTUSER.DAT` `ir-admin`. Hasilnya hanya entri dari Selasa 12:38 sampai 12:55 dan Kamis 08:46, semua jejak Yoga (bagian 2.6).

**Kapan gagal:** LastWriteTime `RecentDocs` dibaca sebagai waktu setiap file di dalamnya dibuka; atau batch yang dipakai tidak memuat `WordWheelQuery`, lalu hasil kosong dibaca sebagai "tidak ada pencarian". Selalu cek `KeyPath` di batch sebelum membaca hasil kosong.

### 2.6 Jejak responder: profil `ir-admin` dan drive USB `USB-E-07`

Langkah ini menjawab bagian kedua pertanyaan kelima: jejak Yoga harus bisa ditunjukkan secara positif, bukan hanya "bukan Andi".

Keluaran ilustrasi SBECmd untuk `ir-admin` (9 baris, dipilih yang relevan; UTC):

```
AbsolutePath                       ShellType    Hive      FirstInteracted       LastInteracted
My Computer\E:                     Drive        UsrClass  2026-10-13 05:41:22   2026-10-13 05:54:12
My Computer\E:\INC-2026-019        Directory    UsrClass  2026-10-13 05:54:12   2026-10-13 05:54:12
```

Hive `ir-admin` dibuat saat akun itu login pertama kali di laptop ini, Selasa 12:38:41 WIB (profil `C:\Users\ir-admin` lahir di detik yang sama di `$MFT`). Yoga membuka drive `E:` pukul 12:41:22 WIB, sebelum menjalankan `cmd.exe` sebagai administrator (12:41:50) dan WinPmem dari `E:\tools\` (12:42:07), lalu membuka folder `E:\INC-2026-019` pukul 12:54:12 WIB untuk memeriksa file output, setelah `certutil` menghitung hash (12:53:40) dan sebelum sign out (12:55:10). Semua waktu itu cocok dengan case notes Yoga dan event log (Day 05 bagian 2.6).

ShellBags tidak menyimpan nomor seri volume untuk drive, jadi identitas `E:` dibuktikan lewat jembatan di bagian 1.6. Event log `Microsoft-Windows-Partition/Diagnostic` di E15 diparse dengan EvtxECmd seperti Day 05:

```powershell
$e = Import-Csv '\\jkt-evid01\cases\INC-2026-019\analysis\E15-W1\EZ-2026.5.0\EventLogs\E15-W1_evtx.csv'
$e | Where-Object { $_.Channel -like '*Partition/Diagnostic*' -and $_.EventId -eq '1006' -and
                    $_.TimeCreated -ge '2026-10-13 05:30' -and $_.TimeCreated -lt '2026-10-13 06:00' } |
  Select-Object TimeCreated, PayloadData1, PayloadData2, PayloadData3
```

Keluaran ilustrasi (kolom diringkas; isi VBR sudah diekstrak ke nomor seri volume):

```
TimeCreated (UTC)       Ringkasan
2026-10-13 05:40:58.31  Perangkat USB (vendor dan model sesuai inventaris toolkit), serial 0123E07A9F31, VBR: NTFS, volume serial 2F6B8D10
2026-10-13 05:55:31.07  Perangkat yang sama dilepas
```

**Cara membaca hasil:** drive USB dicolok Selasa 12:40:58 WIB dan dilepas 12:55:31 WIB. Nomor seri perangkat dan nomor seri volume `2F6B8D10` cocok dengan catatan inventaris toolkit untuk `USB-E-07`. Rantainya lengkap: ShellBags `ir-admin` menunjuk `E:`, EID 1006 menautkan perangkat `USB-E-07` ke volume `2F6B8D10` pada jendela waktu yang sama, dan Sysmon EID 1 mencatat WinPmem dijalankan dari `E:\tools\`. Bila yang ditemukan di profil Andi adalah LNK dengan `DriveSerialNumber` `2F6B8D10`, kamu tahu itu drive responder. Di E15 tidak ada LNK seperti itu, dan profil Andi tidak punya ShellBags untuk drive removable mana pun. Field persis tempat EvtxECmd menaruh nomor seri perangkat dan data VBR, serta cara mengekstrak nomor seri volume dari VBR, cek di map EvtxECmd dan di lab.

**Variasi:** cocokkan juga `MountPoints2` di `NTUSER.DAT` `ir-admin` dan `MountedDevices` di hive SYSTEM untuk huruf `E:` (Day 09).

**Kapan gagal:** jejak responder disimpulkan "pasti Yoga" hanya karena profilnya `ir-admin`, tanpa mencocokkan waktu dengan case notes. Akun admin lokal IR dipakai banyak orang di banyak host; yang membuatnya bisa diatribusikan adalah catatan siapa memakainya kapan.

### 2.7 Timeline gabungan dan jawaban tertulis untuk Sari

Timeline ini menyatukan artefak shell dengan sumber yang sudah ada dari Day 05 dan Day 08. Baca kolom "Pelaku" bersama kolom "Penguat": setiap baris shell punya pasangan di sumber lain.

| Waktu (WIB) | Artefak shell | Pelaku | Penguat |
|---|---|---|---|
| Jumat 2026-09-11 14:19:41-14:19:48 | TypedPaths `\\JKT-FS01\Penagihan`; ShellBags `\\JKT-FS01\Penagihan\tools` (NTUSER) | Andi | `export-tagihan.ps1` lahir di Documents 14:20:33 (`$MFT`) |
| Senin 14:01:50 | ShellBags Documents | Andi | 4104 `export-tagihan.ps1` 14:02:11 |
| Senin 16:04:48 | OpenSavePidlMRU `zip`, LastVisitedPidlMRU `OUTLOOK.EXE` | Andi | Sysmon EID 11 `OUTLOOK.EXE` menulis ZIP 16:04:48 |
| Senin 16:05:04 | ShellBags ZIP; LNK `Tagihan-Okt-2026.zip.lnk` dan `Downloads.lnk`; RecentDocs `.zip`; Jump List Explorer | Andi | `.js` diekstrak `explorer.exe` 16:05:09; `wscript.exe` 16:05:11 |
| Senin 17:10 sampai Selasa 08:12:05 | Tidak ada perubahan ShellBags, LNK, Jump List, atau key aktivitas pengguna | - | Tidak ada unlock (type 7) sejak Senin 13:02:40 sampai Selasa 08:12:05 dan tidak ada RDP (type 10); 4104 `upd.ps1` 23:40:17; `ssh.exe` 02:14:31 |
| Selasa 08:24:05 | LNK `Rekap-Penagihan-Okt-2026.xlsx.lnk` dan `Desktop.lnk`; RecentDocs `.xlsx`; Jump List Excel (23 kali) | Andi | Unlock 08:12:05; `$J` `~$` 08:24:07, simpan 08:31:44 |
| Selasa 11:12:31 | ShellBags Downloads | Andi | ZIP ke Recycle Bin 11:12:40 (`$I`, SID Andi); telepon Gilang 11:08 |
| Selasa 12:41:22 dan 12:54:12 | ShellBags `E:` dan `E:\INC-2026-019` (profil `ir-admin`) | Yoga (responder) | 4624 `ir-admin` 12:38:41; EID 1006 `USB-E-07` 12:40:58; WinPmem 12:42:07; case notes |

Jawaban ini dikirim ke Sari pukul 14:50. Baca kolom "Keyakinan dan batas" lebih dulu, karena kolom itulah yang akan dikutip di after-action report.

| Pertanyaan | Jawaban | Dasar | Keyakinan dan batas |
|---|---|---|---|
| Ada jejak penyerang bekerja interaktif di desktop sesi Andi? | Tidak. Semua artefak shell di profil Andi cocok dengan pekerjaan Andi sendiri, dan tidak ada yang berubah Senin 17:10 sampai Selasa 08:12:05 | ShellBags, LNK, Jump List, RecentDocs, OpenSave, TypedPaths, WordWheelQuery (2.2-2.5); tidak ada unlock malam dan tidak ada RDP (Day 05) | Tinggi untuk desktop. Jam Andi mengunci layar Senin hanya dari pengakuannya; event kunci layar tidak diaudit GPO `JAB-WS-Audit`, tetapi unlock Selasa 08:12:05 membuktikan layar terkunci dan tidak dibuka sebelumnya |
| "Pencarian file di Documents dan Desktop" itu penyerang melihat-lihat folder lewat Explorer? | Tidak. Pencarian dilakukan `upd.ps1` pukul 23:40:17 sebagai skrip | 4104 dan memori (retainer); nol ShellBags, LNK, WordWheelQuery, search LNK untuk folder dan kata kunci itu | Tinggi. Artefak shell tidak mencatat akses oleh proses, jadi ketiadaannya hanya menunjukkan tidak lewat antarmuka, bukan tidak ada akses |
| Apakah operator penyerang mengetik perintah secara langsung lewat C2 (misalnya SSH 02:14)? | Tidak bisa dijawab dari artefak shell | Perlu pola 4104, telemetry EDR, memori, log proxy | Di luar cakupan artefak ini; dicatat sebagai pertanyaan terbuka untuk retainer |
| Jejak siapa yang terlihat? | Andi: share tim (September), Documents dan skrip ekspor (Senin 14:01), simpan dan buka ZIP (16:04-16:05), Excel (Selasa 08:24), hapus ZIP (11:12). Yoga: drive `E:` `USB-E-07` (Selasa 12:41-12:54) di profil `ir-admin` | Bagian 2.2-2.6, dicocokkan dengan Sysmon, `$J`, `$I`, case notes | Tinggi. Tidak ada jejak yang tidak bisa dijelaskan keduanya |
| File dari ZIP dan folder Temp? | ZIP dibuka Andi lewat Explorer (tiga artefak pada 16:05:04). Tidak ada LNK atau RecentDocs untuk `.js` hasil ekstraksi di folder `Temp1_...` | LECmd, RECmd; Sysmon EID 1 membuktikan `.js` dijalankan dari Explorer | Ketiadaan LNK `.js` belum dijelaskan sumber; diuji di `CASE-2026-LAB-010` sebelum laporan final. Tidak mengubah kesimpulan, karena eksekusi sudah terbukti dari sumber lain |

Kalimat pengantar ke Sari: "Dari artefak aktivitas pengguna di laptop Andi tidak ada tanda penyerang bekerja di desktop: tidak ada yang membuka layar atau masuk lewat RDP malam itu, dan semua folder dan file yang dibuka lewat antarmuka di sesi Andi cocok dengan pekerjaan Andi sendiri dan dengan sumber lain. Pencarian file pukul 23:40 dilakukan skrip penyerang, bukan orang yang membuka folder. Artefak ini tidak bisa menunjukkan apakah operator penyerang mengetik perintah langsung lewat C2; itu pertanyaan untuk event log PowerShell, memori, dan log jaringan."

**Kapan gagal:** jawaban ditulis "penyerang tidak mengakses Documents" karena ShellBags kosong. Kalimat itu salah dan bertentangan dengan 4104; yang benar adalah "penyerang tidak membuka Documents lewat Explorer".

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** lab dari Day 02: VM korban `LAB-WS01` (`172.16.50.10`, Windows 11, Sysmon, snapshot `bersih-2026-10-15`), VM analisis `LAB-DFIR01` (`172.16.50.20`) dengan KAPE, SBECmd, LECmd, JLECmd, RECmd, EvtxECmd, ShellBags Explorer, dan Timeline Explorer, jaringan host-only `172.16.50.0/24`. Folder kasus lab `CASE-2026-LAB-010`. Akun uji `lab.user` (pengguna biasa) dan `lab.ir` (admin lokal "responder"), disk USB virtual `LAB-USB`. Semua file uji adalah teks jinak buatanmu sendiri; `uji-lab.js` hanya berisi `WScript.Echo("lab")`. Jangan memakai data, nama, atau kejadian dari pekerjaan nyata.

1. **Catat kondisi awal.** Kembalikan `LAB-WS01` ke snapshot, login sebagai `lab.user`, catat waktu dan build Windows. Siapkan folder `C:\LabShare\Data` dan file `C:\Users\lab.user\Documents\rahasia-lab.txt`.
2. **Navigasi dan ketik.** Buka Explorer, masuk ke Documents dengan klik, lalu ketik `C:\LabShare\Data` di address bar. Catat waktu setiap langkah.
3. **Cari dan buka.** Di kotak pencarian Explorer pada Documents, cari `rahasia`, lalu buka `rahasia-lab.txt` dari hasil pencarian. Cari juga kata `password` tanpa membuka hasil apa pun.
4. **Dialog Save As.** Buka Notepad, tulis satu baris, simpan dengan Save As ke Desktop sebagai `catatan-lab.txt`. Catat apakah Notepad di build-mu adalah Windows App, karena itu menentukan hive tempat jejak dialognya ditulis (bagian 1.1).
5. **ZIP dan folder Temp.** Di `LAB-DFIR01`, buat ZIP berisi `catatan-zip.txt` dan `uji-lab.js`, salin ke Downloads `lab.user`. Buka ZIP di Explorer, buka `catatan-zip.txt` dari dalam ZIP, lalu jalankan `uji-lab.js` dari dalam ZIP. Catat nama folder sementara yang dibuat.
6. **Akses lewat skrip.** Di PowerShell sebagai `lab.user`, jalankan `Get-ChildItem C:\Users\lab.user\Documents -Recurse -File | Select-String -Pattern rahasia` lalu `Get-Content C:\Users\lab.user\Desktop\catatan-lab.txt`. Catat waktunya.
7. **Run with PowerShell dan hapus.** Buat `uji-lab.ps1` berisi `Get-Date` di Documents, jalankan lewat klik kanan "Run with PowerShell". Lalu hapus `catatan-lab.txt` lewat Explorer ke Recycle Bin.
8. **USB.** Colok `LAB-USB`, catat nomor seri volumenya dengan `vol E:`, buka satu folder dan satu file teks di USB lewat Explorer, lalu cabut.
9. **Kunci dan responder.** Kunci layar, tunggu 10 menit, buka lagi. Lalu Switch user ke `lab.ir`, buka drive `C:\` dan satu folder di Explorer, sign out.
10. **Koleksi dan parse.** Ambil `RegistryHivesUser`, `LNKFilesAndJumpLists`, dan `EventLogs` dengan KAPE ke disk bukti lab, lalu di `LAB-DFIR01` jalankan SBECmd, LECmd, JLECmd, RECmd (`UserActivity.reb`) untuk kedua profil, dan EvtxECmd untuk Security dan Partition/Diagnostic.
11. **Isi tabel.** Untuk setiap langkah 2 sampai 9: artefak yang muncul (ShellBags, LNK, Jump List, RecentDocs, OpenSave, TypedPaths, WordWheelQuery, event), timestamp yang terkait, profil, dan selisihnya dengan waktu yang kamu catat.
12. **Uji klaim dari datamu sendiri.** Apakah langkah 6 meninggalkan artefak shell apa pun? Apakah langkah 3 membuat WordWheelQuery dan search LNK, dan apakah kata `password` tanpa hasil yang dibuka hanya muncul di WordWheelQuery? Apakah `uji-lab.js` dan `catatan-zip.txt` di langkah 5 menghasilkan LNK, RecentDocs, atau item Jump List, dan apakah path folder sementara muncul di mana pun? Apakah ZIP masuk Jump List Explorer? Apakah langkah 7 menambah LNK atau RecentDocs untuk `.ps1`, dan apakah penghapusan memperbarui LNK? Apakah jejak `lab.ir` hanya ada di profilnya?
13. **USB.** Cocokkan nomor seri volume dari `vol E:` dengan `DriveSerialNumber` di LNK dan dengan EID 1006 (bagian 1.6).
14. **Laporan.** Tulis tabel jawaban seperti bagian 2.7 untuk pertanyaan "apakah ada kerja interaktif di sesi `lab.user` saat langkah 6?", lengkap dengan jendela dan batasnya.

**Hasil yang sebaiknya tersimpan:**

- Tabel langkah ke artefak, dengan timestamp dan profil, dari data lab.
- Bukti bahwa akses lewat skrip (langkah 6) tidak meninggalkan artefak shell, atau catatan bila hasil lab-mu berbeda.
- Perilaku shell untuk file yang dibuka dan dijalankan dari dalam ZIP di build lab, termasuk nama folder sementara.
- WordWheelQuery dan search LNK dari langkah 3, dan perbandingan dengan kata yang dicari tanpa membuka hasil.
- Hive tempat jejak dialog Notepad ditulis di build lab.
- Rantai USB: `vol E:`, LNK, EID 1006, MountPoints2.
- Tabel jawaban dengan jendela dan batas.

**Variasi tantangan:** setelah langkah 10, kosongkan riwayat item terbaru lewat pengaturan Windows di `LAB-WS01`, koleksi ulang, dan catat apa yang hilang (LNK, Jump List, RecentDocs) dan apa yang tetap (ShellBags, TypedPaths, WordWheelQuery). Lalu ulangi langkah 8 dengan USB yang dicabut sebelum koleksi, dan buktikan dari ShellBags dan LNK bahwa folder dan file di USB tetap tercatat walau drive sudah tidak ada. Tulis kenapa itu penting untuk kasus pencurian data (bukti bertahan setelah perangkat dibawa pergi). Kembalikan snapshot setelah selesai.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat membaca artefak aktivitas pengguna. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| ShellBags kosong atau sangat sedikit | Hanya `NTUSER.DAT` yang diparse; `UsrClass.dat` tidak dikoleksi | Ambil `RegistryHivesUser` (memuat `UsrClass.dat` dan log-nya) [S14] |
| Folder share tidak muncul di ShellBags | Hanya `UsrClass.dat` yang diparse | Share jaringan ada di `NTUSER.DAT` [S15] |
| Jejak dialog aplikasi tertentu tidak ada di hive pengguna | Aplikasi Windows App menulis ke hive di folder `Packages\...\Helium` | Koleksi hive aplikasi itu secara manual [S15] |
| Perubahan terbaru tidak terlihat di hive | Hive dirty dan transaction log tidak dipakai | Sertakan `.LOG1`/`.LOG2`; jangan pakai `--nl` kecuali sengaja [S10] |
| LNK tidak ada untuk file yang jelas dibuka | File dibuka oleh proses, bukan lewat shell; Recent dibersihkan; kebijakan riwayat dokumen; perilaku untuk file dari arsip | Cek mekanisme (bagian 1.1), kebijakan [S22], uji perilaku di lab |
| `TargetModified` LNK lebih lama dari Modified di `$MFT` | Target diubah setelah LNK terakhir ditulis | Normal; waktu target adalah potret saat dibuka [S4] |
| AppID Jump List tidak dikenal | Aplikasi tidak ada di daftar bawaan JLECmd | Cari padanannya dan muat lewat `--appIds` [S9] |
| Waktu ShellBags membingungkan | `FirstInteracted`/`LastInteracted` adalah inferensi parser; waktu shell item hanya dari saat pertama tercatat | Pakai sebagai jendela, korelasikan [S15] |
| `VolumeSerialNumber` LNK tidak cocok dengan serial USBSTOR | Dua jenis serial berbeda (volume vs perangkat) | Pakai jembatan EID 1006, EMDMgmt, atau MountedDevices (bagian 1.6) |
| Aktivitas pengguna tidak muncul | Profil yang diparse salah | Pastikan profil yang benar; semua artefak ini per profil |
| Hasil RECmd kosong untuk key yang dicari | Batch yang dipakai tidak memuat key itu | Cek `KeyPath` di file `.reb` [S11] |

## 5. Kesalahan umum dan jebakan

- Menganggap ShellBags berarti file dibuka. ShellBags berarti folder dilihat; file dibuka ada di LNK, Jump List, RecentDocs, dan OpenSavePidlMRU (bagian 1.5).
- Menyimpulkan "tidak ada akses" dari artefak shell yang kosong. Artefak ini ditulis antarmuka; skrip dan proses yang membaca file langsung tidak menulisnya [S7][S15].
- Menyamakan hands-on-keyboard dengan desktop. Operator lewat C2 bekerja interaktif tanpa artefak shell (bagian 1.6).
- Mengira keberadaan di RecentDocs berarti dibuka secara sadar. File bisa dibuka aplikasi atas nama pengguna; sebutkan bila kesimpulan menyentuh niat.
- Membaca waktu target di LNK sebagai waktu file dibuka. Itu waktu target saat LNK ditulis [S4]; waktu pembukaan dibaca dari `SourceCreated` dan `SourceModified` [S17].
- Memakai LastWriteTime key untuk semua entri di dalamnya. Waktu itu milik key dan biasanya hanya cocok dengan entri MRU posisi 0 [S20].
- Mengutip waktu ShellBags seolah presisi. Logikanya tidak didokumentasikan publik dan berbeda antar versi Windows [S15].
- Lupa bahwa artefak ini per profil. Penyerang yang menumpang sesi menulis ke profil korban; responder dengan akun lain menulis ke profilnya sendiri.
- Menyimpulkan penyalinan dari pembukaan. Membuka file bukan menyalin; untuk penyalinan dibutuhkan `$J`, `$MFT` di volume tujuan, atau artefak lain (Day 08).
- Mencocokkan nomor seri volume LNK langsung dengan nomor seri USBSTOR. Itu dua serial berbeda; dibutuhkan jembatan (bagian 1.6).
- ShellBags dan LNK bertahan setelah folder, file, atau perangkatnya hilang [S15][S17][S18], sehingga menjadi kunci di kasus pencurian data. Menautkan file ke perangkat tetap butuh jembatan antara nomor seri volume dan nomor seri perangkat, dan makna timestamp ShellBags tetap diperlakukan hati-hati.

## 6. Catatan terkini

Bagian ini menampung detail versi dan tanggal sumber yang bisa berubah. Berguna saat membuka dokumen sumbernya, tetapi tidak mengubah alur analisis di atas.

- EZ Tools 2026.5.0: SBECmd, LECmd, JLECmd, dan RECmd tersedia untuk .NET 4.7.2 dan .NET 9; ShellBags Explorer, JumpList Explorer, Registry Explorer, dan Timeline Explorer hanya .NET 9, dan versi net4 GUI tidak lagi tersedia [S2]. README JLECmd menampilkan banner 1.4.0.0 dan README RECmd 1.6.0.0; angka itu versi internal di README, bukan nomor rilis paket [S9][S10].
- RECmd: batch Kroll diganti nama menjadi `DFIRBatch.reb` di v2.00 (2024-05-18) supaya bisa dipakai tanpa kekhawatiran lisensi atau afiliasi; entri terbaru yang diperiksa v2.22 (2026-03-17) [S12]. `UserActivity.reb` berversi 1 dan disusun Troy Larson [S11].
- KapeFiles: `LNKFilesAndJumpLists` versi 1.3 dan `RegistryHivesUser` versi 1.0 [S13][S14].
- [MS-SHLLINK] revisi 10.0 terbit 2025-11-21 (revisi besar sebelumnya 9.0 pada 2025-06-10) [S3]. Halaman `SHAddToRecentDocs` ber-ms.date 2018-12-05 dan diperbarui 2025-07-01 [S7].
- Cyber Triage: panduan ShellBags terbit 2025-03-21 dan cheat sheet registry 2025-06-02, keduanya dinyatakan ditinjau untuk 2026 [S15][S16]. IT-Connect: seri forensik Windows bagian Jump List bertanggal 2026-09-25 dan bagian ShellBags menampilkan alat versi 2026.5.0 [S18][S19].
- Panduan LNK CSIRT.SK berasal dari 2019 (diunggah ulang 2021) dan artikel search LNK Mandiant dari Februari 2020 dengan contoh dari Windows Server 2012 R2 [S17][S20]. Keduanya lebih dari 3 tahun; perilaku dasarnya tetap dipakai praktisi, tetapi detail versi (jumlah LNK per pembukaan, kapasitas Recent) diuji di build yang sedang diperiksa.
- Kebijakan "Do not keep history of recently opened documents" yang dirujuk berasal dari dokumentasi arsip Microsoft (ms.date 2017-05-04) [S22]; pengaturan setara di Windows 11 dicek di GPO dan lab.

## 7. Cheat sheet

```
PRINSIP     artefak shell = ditulis ANTARMUKA (Explorer, dialog Open/Save, SHAddToRecentDocs)
            skrip/proses yang baca file langsung -> TIDAK menulis artefak ini -> pakai 4104/Sysmon/EDR/memori
SHELLBAGS   UsrClass.dat (lokal, removable) + NTUSER.DAT (UNC) ; BagMRU + Bags ; SBECmd -d <profil>
            FOLDER dilihat (termasuk ZIP, dihapus, USB, share) ; First/LastInteracted = inferensi
LNK         ...\Recent\*.lnk (+ Office\Recent, Desktop) ; LECmd -d <Recent> --csv <dir> -q ; -r = removable saja
            SourceCreated = pertama dibuka ; SourceModified = terakhir dibuka (konsensus praktisi)
            Target* = potret target saat LNK ditulis ; VolumeID: DriveType, DriveSerialNumber ; MachineID
            search LNK: nama = kata kunci, target "Search Folder\..." -> pasangan WordWheelQuery
JUMP LIST   Recent\AutomaticDestinations (DestList: MRU, InteractionCount, LastModified) / CustomDestinations
            JLECmd -d <Recent> --csv <dir> ; Explorer = f01b4d95cf55d32a ; folder hanya di JL Explorer
NTUSER      ...\Explorer\RecentDocs (nama, per ekstensi) | ComDlg32\OpenSavePidlMRU (path, dialog)
            ComDlg32\LastVisitedPidlMRU (aplikasi -> folder) | TypedPaths (diketik) | WordWheelQuery (dicari)
            RECmd -f NTUSER.DAT --bn UserActivity.reb --csv <dir> ; LastWriteTime = milik KEY (MRU 0)
BEDA        TypedPaths = DIKETIK | ShellBags = DILIHAT | LNK/JL/RecentDocs/OpenSave = DIBUKA | WordWheel = DICARI
INTERAKTIF  siapa bisa di desktop? 4624 type 7 (unlock), type 10 (RDP) ; lalu artefak shell di luar pola pemilik
            operator lewat C2 = interaktif TANPA artefak shell
RESPONDER   profil sendiri (ir-admin) ; drive USB: ShellBags -> EID 1006 (serial perangkat + VBR) -> inventaris
LINK KE USB LNK DriveSerialNumber (volume) -> EID 1006 / EMDMgmt -> USBSTOR serial (perangkat) ; MountedDevices = huruf drive
KOLEKSI     KAPE RegistryHivesUser,LNKFilesAndJumpLists (+ hive Windows App di Packages\...\Helium bila perlu)
BATAS       per profil ; keberadaan != niat ; dibuka != disalin ; tidak ada jejak != tidak ada akses ; waktu ShellBags halus
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "ShellBags Andi tidak punya entri untuk Documents setelah Senin 14:01:50, jadi loader tidak mencari apa pun di Documents pukul 23:40." Benarkah?

<details><summary>Jawaban</summary>

Tidak. ShellBags ditulis Explorer dan dialog Open/Save. `upd.ps1` mencari dan membaca file lewat PowerShell, yang memanggil API file system tanpa lewat antarmuka, sehingga tidak ada ShellBags, LNK, atau WordWheelQuery yang ditulis. Pencarian dan pembacaan pukul 23:40:17 terbukti dari 4104 dan memori. Ketiadaan ShellBags hanya menunjukkan Documents tidak dibuka lewat Explorer. Lihat bagian 1.1 dan 2.2.

</details>

**2. Skenario keputusan.** Retainer membaca `Tagihan-Okt-2026.zip.lnk` (dibuat Senin 16:05:04 WIB) dan menulis "penyerang membuka arsip secara interaktif". Respons mana yang paling tepat?

- A. Setuju, karena LNK membuktikan kerja interaktif dan penyerang sudah aktif di laptop sejak sore.
- B. Koreksi: LNK, ShellBags arsip, RecentDocs `.zip`, dan Jump List Explorer pada detik yang sama, ditambah OpenSavePidlMRU dan Sysmon EID 11 `OUTLOOK.EXE` 16:04:48, menunjukkan Andi sendiri menyimpan lampiran lewat dialog lalu membukanya di Explorer, enam detik sebelum `wscript.exe` berjalan; kode penyerang baru ada setelah itu.
- C. Abaikan LNK itu, karena LNK bisa dibuat oleh `wscript.exe` saat skrip dijalankan.

<details><summary>Jawaban</summary>

B. LNK dibuat shell saat dokumen dibuka lewat Explorer atau dialog, di profil yang sedang bekerja, dan rangkaian artefak pada 16:04:48 sampai 16:05:04 terjadi sebelum `.js` diekstrak (16:05:09) dan dijalankan (16:05:11). A keliru karena sebelum 16:05:11 belum ada kode penyerang yang berjalan; yang ada hanya Andi membuka lampiran. C keliru karena tidak ada dasar bahwa `wscript.exe` membuat LNK untuk ZIP, dan mengabaikan artefak yang dikuatkan empat sumber lain bukan analisis. Lihat bagian 2.3, 2.5, dan 2.7.

</details>

**3. Pertanyaan jebakan.** "`TargetModified` di `Rekap-Penagihan-Okt-2026.xlsx.lnk` adalah Senin 15:41:10 WIB, jadi file itu tidak diubah Selasa pagi." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Waktu target di header LNK adalah keadaan file pada saat LNK terakhir ditulis, yaitu saat Andi membuka file Selasa 08:24:05. Andi menyimpannya setelah itu (08:31:44 di `$J`), dan perubahan itu tidak memperbarui LNK. Waktu pembukaan dibaca dari `SourceModified`, bukan dari `TargetModified`. Lihat bagian 1.3 dan 2.3.

</details>

**4. Skenario keputusan.** Sari bertanya, "Bagaimana kita tahu tidak ada orang yang duduk di laptop Andi malam itu?" Dasar mana yang paling kuat?

- A. LastWriteTime key `BagMRU` dan `RecentDocs` tidak ada yang jatuh di malam hari.
- B. Tidak ada unlock (4624 type 7) antara Senin 13:02:40 dan Selasa 08:12:05, tidak ada logon RDP, dan unlock Selasa membuktikan layar terkunci; lalu artefak shell yang tidak berubah di jendela itu dipakai sebagai penguat.
- C. WordWheelQuery tidak berisi kata password.

<details><summary>Jawaban</summary>

B. Jalan masuk ke desktop (konsol, RDP) dikunci dulu dari event log, baru artefak shell dipakai sebagai penguat. A lemah sendirian karena LastWriteTime hanya menyimpan perubahan terakhir; perubahan malam yang tertimpa perubahan Andi berikutnya tidak terlihat. C hanya menunjukkan tidak ada pencarian kata itu lewat Explorer, tidak menjawab apakah ada orang di desktop. Lihat bagian 1.5, 1.6, dan 2.7.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Dimas Prasetyo (SOC lead), dalam tiga kalimat, kenapa "tidak ada jejak interaktif di desktop Andi" tidak sama dengan "penyerang tidak bekerja secara manual".

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Artefak yang kita periksa hanya ditulis saat seseorang memakai antarmuka Windows di desktop, misalnya membuka folder di Explorer, mengetik path, atau membuka dokumen, dan semua jejak seperti itu di laptop Andi milik Andi sendiri. Operator penyerang yang mengetik perintah lewat kanal C2 tetap bekerja manual, tetapi di mata Windows ia hanya proses PowerShell, jadi tidak meninggalkan jejak di artefak ini. Untuk menjawab apakah SSH pukul 02:14 diketik operator atau dijalankan skrip otomatis, kita perlu pola log PowerShell, memori, dan trafik ke C2, bukan artefak desktop."

Kesalahan yang sering muncul:
- Menyatakan penyerang "tidak interaktif sama sekali", padahal yang dibuktikan hanya tidak ada kerja di desktop.
- Menjelaskan format ShellBags atau LNK, padahal yang dibutuhkan Dimas adalah batas kesimpulannya.
- Tidak menyebut sumber lain yang bisa menjawab sisa pertanyaannya.

</details>

**6. Pertanyaan jebakan.** "LNK menunjuk `E:\exfil\report_final.xlsx` dengan nomor seri volume `A4F21B3C`, jadi kita tinggal mencari `A4F21B3C` di USBSTOR untuk menemukan USB-nya." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Nomor seri di LNK adalah nomor seri volume yang dibuat saat volume diformat, sedangkan USBSTOR menyimpan nomor seri perangkat dari hardware. Keduanya dihubungkan lewat jembatan seperti EID 1006 di log Partition/Diagnostic (nomor seri perangkat dan VBR berisi nomor seri volume), EMDMgmt, lalu MountedDevices dan MountPoints2 untuk huruf drive dan pengguna. Tanpa jembatan, tulis hanya bahwa file dibuka dari volume removable dengan nomor seri volume tertentu. Lihat bagian 1.6 dan 2.6.

</details>

**7. Interview question (English).** "How would you determine whether an attacker had hands-on-keyboard access to a user's desktop session, as opposed to only running scripts in it?"

<details><summary>Sample answer</summary>

"I start by asking how anyone could have reached the desktop: console unlocks, RDP logons and reconnects, or a session left unlocked, so I check logon types 7 and 10 and the RDP-related logs first. Then I look at the per-user shell artifacts, ShellBags, LNK files, jump lists, RecentDocs, OpenSave and LastVisited MRUs, TypedPaths and WordWheelQuery, because those are written by Explorer and the common dialogs, not by scripts that read files through the API. I line every entry up against the account owner's known work and against independent sources like Sysmon, the USN journal and the Recycle Bin, and I keep responder activity in its own profile with case notes. If nothing in that window falls outside the owner's pattern, I can say there's no evidence of interactive desktop use, but I'm explicit that shell artifacts don't record file access by processes, and they can't tell me whether an operator typed commands through a C2 channel; for that I go to script block logs, EDR telemetry, memory and network data."

What makes this answer strong: it starts from access paths instead of artifacts, explains why shell artifacts separate GUI work from scripts, insists on corroboration and responder separation, and states the two limits that most often get overstated.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | SANS: Windows Forensic Analysis poster (aktivitas pengguna: ShellBags, LNK, Jump List, RecentDocs) | https://www.sans.org/posters/windows-forensic-analysis/ | sekunder (SANS) | diakses 2026-10-09 | Sedang-tinggi. Peta makna artefak dan tiga tingkat bukti (diketik, dilihat, dibuka) |
| S2 | Eric Zimmerman tools: SBECmd, LECmd, JLECmd, RECmd, ShellBags Explorer, JumpList Explorer | https://ericzimmerman.github.io/ | primer | diakses 2026-10-16 | Tinggi. Versi 2026.5.0, .NET 4.7.2 dan .NET 9 untuk CLI, GUI hanya .NET 9 |
| S3 | Microsoft Open Specifications: [MS-SHLLINK] Shell Link (.LNK) Binary File Format | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/16cb4ca1-9339-4d0c-a68d-bf1d6cc0f943 | primer | revisi 10.0, 2025-11-21; diakses 2026-10-10, dicek ulang 2026-10-16 | Tinggi. Format LNK; dasar perbedaan nomor seri volume dan perangkat |
| S4 | [MS-SHLLINK] ShellLinkHeader | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c3376b21-0931-45e4-b2fc-a48ac0e60d15 | primer | 2025-11-21; diakses 2026-10-16 | Tinggi. `CreationTime`, `AccessTime`, `WriteTime`, `FileSize` adalah milik target, UTC |
| S5 | [MS-SHLLINK] VolumeID | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/b7b3eea7-dbff-4275-bd58-83ba3f12d87a | primer | 2025-06-10; diakses 2026-10-16 | Tinggi. `DriveType`, `DriveSerialNumber`, label volume tempat target berada saat link dibuat |
| S6 | [MS-SHLLINK] TrackerDataBlock | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/df8e3748-fba5-4524-968a-f72be06d71fc | primer | 2025-11-21; diakses 2026-10-16 | Tinggi. `MachineID` (NetBIOS), `Droid`, `DroidBirth` |
| S7 | Microsoft Learn: SHAddToRecentDocs function (shlobj_core.h) | https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shaddtorecentdocs | primer | ms.date 2018-12-05, diperbarui 2025-07-01; diakses 2026-10-16 | Tinggi. Recent dan Jump List; dipanggil shell untuk Explorer dan dialog umum; `.exe` disaring; folder hanya di Jump List Explorer; `NoRecentDocs` default; NULL menghapus data |
| S8 | LECmd README (GitHub) | https://github.com/EricZimmerman/LECmd | primer (repo resmi) | diakses 2026-10-16 | Tinggi untuk opsi CLI (`-f`, `-d`, `-r`, `--all`, `--csv`, `--csvf`, `--mp`); tidak menjelaskan makna field |
| S9 | JLECmd README (GitHub) | https://github.com/EricZimmerman/JLECmd | primer (repo resmi) | diakses 2026-10-16 | Tinggi untuk opsi CLI (`-d`, `--csv`, `--ld`, `--fd`, `--dumpTo`, `--appIds`, `--withDir`); banner 1.4.0.0 |
| S10 | RECmd README (GitHub) | https://github.com/EricZimmerman/RECmd | primer (repo resmi) | diakses 2026-10-16 | Tinggi. `-f`/`-d`, `--bn` wajib bersama `--csv`, `--nl`, `--recover`, `--vss`; banner 1.6.0.0 |
| S11 | RECmd BatchExamples: UserActivity.reb | https://raw.githubusercontent.com/EricZimmerman/RECmd/master/BatchExamples/UserActivity.reb | primer (repo resmi) | versi 1; diakses 2026-10-16 | Tinggi. Daftar key aktivitas pengguna: RecentDocs, ComDlg32, TypedPaths, WordWheelQuery, RunMRU, UserAssist; tidak memuat BagMRU |
| S12 | RECmd BatchExamples: DFIRBatch.md | https://github.com/EricZimmerman/RECmd/blob/master/BatchExamples/DFIRBatch.md | primer (repo resmi) | v2.22, 2026-03-17; diakses 2026-10-16 | Tinggi. Rename dari Kroll_Batch di v2.00 (2024-05-18); kategori termasuk User Activity |
| S13 | KapeFiles: LNKFilesAndJumpLists.tkape | https://raw.githubusercontent.com/EricZimmerman/KapeFiles/master/Targets/Windows/LNKFilesAndJumpLists.tkape | primer (repo resmi) | versi 1.3; diakses 2026-10-16 | Tinggi. Recent (termasuk Jump List), Office\Recent, LNK Desktop dan Start Menu |
| S14 | KapeFiles: RegistryHivesUser.tkape | https://raw.githubusercontent.com/EricZimmerman/KapeFiles/master/Targets/Windows/RegistryHivesUser.tkape | primer (repo resmi) | versi 1.0; diakses 2026-10-16 | Tinggi. NTUSER.DAT, UsrClass.dat, transaction log, DEFAULT; tidak memuat hive Windows App |
| S15 | Cyber Triage: ShellBags Forensic Analysis 2026 | https://www.cybertriage.com/blog/shellbags-forensic-analysis-2026/ | sekunder (vendor DFIR) | 2025-03-21, ditinjau 2026; diakses 2026-10-16 | Sedang-tinggi. Lokasi per hive, hive Windows App, apa yang dibuktikan dan tidak, timestamp sebagai inferensi, anti-forensik; vendor punya kepentingan produk |
| S16 | Cyber Triage: Windows Registry Forensics Cheat Sheet 2026 | https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/ | sekunder (vendor DFIR) | 2025-06-02, ditinjau 2026; diakses 2026-10-16 | Sedang. Ringkasan RecentDocs, OpenSavePidlMRU, LastVisitedMRU, TypedPaths, WordWheelQuery, RunMRU |
| S17 | CSIRT.SK: LNK File Forensics | http://www.csirt.gov.sk/wp-content/uploads/2021/08/LNK_File_Forensics-RC.pdf | sekunder (CSIRT pemerintah) | 2019, diunggah 2021-08 (lebih dari 3 tahun); diakses 2026-10-16 | Sedang. LNK otomatis per pembukaan, makna source time, kolom CSV LECmd, contoh LNK ZIP; jumlah LNK per pembukaan dan kapasitas 149 perlu diuji |
| S18 | IT-Connect: Forensic Windows, Partie 13: analyser les Jump Lists | https://www.it-connect.fr/forensic-windows-jump-lists/ | sekunder (blog praktisi) | 2026-09-25; diakses 2026-10-16 | Sedang. Format, isi `DestList`, AppID Explorer, kolom CSV JLECmd, batas |
| S19 | IT-Connect: Windows Forensic, Partie 8: explorer les Shellbags | https://www.it-connect.fr/windows-forensic-partie-8-explorer-les-shellbags/ | sekunder (blog praktisi) | 2026; diakses 2026-10-16 | Sedang. Lokasi key, BagMRU vs Bags, ZIP sebagai folder, SBECmd 2026.5.0 |
| S20 | Mandiant: The Missing LNK: Correlating User Search LNK Files | https://cloud.google.com/blog/topics/threat-intelligence/the-missing-lnk-correlating-user-search-lnk-files | sekunder (vendor IR) | 2020-02-19 (lebih dari 3 tahun); diakses 2026-10-16 | Sedang-tinggi. Search LNK, korelasi dengan WordWheelQuery dan `MRUListEx`; contoh dari Windows Server 2012 R2 |
| S21 | Binalyze AIR Knowledge Base: OpenSavePidlMRU | https://kb.binalyze.com/air/features/acquisition/supported-evidence/windows-collections-detail/opensavepidlmru | sekunder (vendor DFIR) | diperbarui 2026-10-15; diakses 2026-10-16 | Sedang. Path key, subkey per ekstensi, `MRUListEx` |
| S22 | Microsoft Learn (arsip): Do not keep history of recently opened documents | https://learn.microsoft.com/en-us/previous-versions/ms811590(v=msdn.10) | primer (arsip) | ms.date 2017-05-04 (isi untuk Windows lama); diakses 2026-10-16 | Sedang untuk Windows modern. Lokasi dan efek kebijakan; padanan Windows 11 perlu dicek |

**Catatan sumber:** makna `SourceCreated` dan `SourceModified` sebagai waktu pertama dan terakhir dibuka [S17], waktu ShellBags sebagai inferensi [S15], dan isi `DestList` [S18] berasal dari sumber praktisi, bukan dokumentasi Microsoft; perlakukan sebagai konsensus praktisi dan uji di build lab. Opsi SBECmd ditulis dari panduan praktisi dan perlu dicocokkan dengan `SBECmd.exe -h`. Perilaku shell untuk file yang dibuka dari dalam ZIP, untuk jenis skrip, untuk verb "Run with PowerShell", dan masuknya ZIP ke Jump List Explorer tidak dijelaskan sumber yang diperiksa dan menjadi bahan lab (bagian 3). Jumlah LNK per pembukaan dan kapasitas folder Recent berasal dari satu panduan praktisi tahun 2019. Sumber yang diperiksa tidak menyebut perbedaan format artefak ini antara Windows 10 dan 11 selain hive Windows App. Semua isi PT JAB, termasuk nama, waktu, nomor seri volume dan perangkat, entry `$MFT`, hitungan, dan isi registry, adalah contoh fiktif.
