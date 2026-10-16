---
day: 03
title: 'Triage dengan KAPE: Targets dan Modules, compound target, VSS, container output, dan membaca hasil'
researched_on: 2026-10-16
versions_checked: 'KAPE (changelog dokumentasi resmi mencatat 1.3.0.2, 2022-12-22; EULA KAPE Solo terakhir diubah 2020-06-04; FAQ lisensi di dokumentasi diperbarui 2026-02-11, KAPE tidak lagi tersedia untuk penggunaan komersial sejak 2026-01-01); KapeFiles master per 2026-10-16 (!SANS_Triage v1.5, KapeTriage v4.2, !BasicCollection v1.1, EvidenceOfExecution v1.1, !EZParser v1.5); EZ Tools 2026.5.0 (CLI .NET 4.7.2 dan .NET 9, GUI hanya .NET 9); Mount-DiskImage (modul Storage, dokumentasi Windows Server 2025); about_PSReadLine dan about_Logging_Windows (PowerShell 7.6, ms.date 2026)'
---

# Day 03: Triage dengan KAPE (Targets, Modules, VSS, container, dan membaca hasil)

Cakupan: koleksi triage satu host Windows dengan KAPE, dari memilih Targets dan compound target, file terkunci dan Volume Shadow Copy, container VHDX dan hashing, sampai memproses salinan kerja dengan Modules (`!EZParser`) dan menulis apa yang ada dan yang tidak ada di koleksi.

## Ide inti

Koleksi KAPE hanya berisi apa yang tertulis di daftar target. KAPE cepat, bisa menyalin file yang sedang dikunci Windows, dan mencatat setiap file yang disalin beserta hash-nya. Tetapi ia tidak menebak: folder yang tidak disebut di target mana pun tidak ikut, shadow copy tidak dibaca kecuali diminta, dan isi file yang tidak terkumpul tidak bisa dimunculkan oleh parser apa pun. Karena itu pekerjaan triage dengan KAPE selalu punya dua sisi. Sisi pertama adalah koleksi (Targets) di host, dijaga sebagai bukti dan di-hash. Sisi kedua adalah pemrosesan (Modules) di workstation analisis atas salinan kerja, yang hasilnya dibaca untuk menjawab pertanyaan. Di antara keduanya ada satu dokumen yang sering dilupakan: daftar apa yang ada di koleksi, apa yang tidak, dan apa yang harus menunggu bukti lain.

Kamu sudah mengenal pola ini dari NOC. Saat membuka kasus ke TAC vendor, kamu mengirim paket `show tech-support`. Paket itu cepat dibuat dan berisi banyak perintah `show` sekaligus, tetapi hanya perintah yang ada di daftarnya. Bila TAC bertanya isi file konfigurasi tambahan di flash yang tidak termasuk paket, jawabannya bukan "tidak ada", melainkan "tidak diambil", dan kamu mengirim susulan. Parser di sisi TAC juga hanya mengolah apa yang ada di paket. Koleksi KAPE bekerja dengan cara yang sama, dengan satu perbedaan: host yang kamu koleksi mungkin akan di-reimage, sehingga "kirim susulan" tidak selalu bisa dilakukan.

```
HOST (menyala, terisolasi)            jkt-evid01 (master)        JKT-DFIR01 (analisis)
kape.exe  Targets                     E14 .zip + .sha256         salinan kerja E14-W1
  --tsource C:                          |                          | cek hash
  --target !SANS_Triage                 | verifikasi tiap pindah   | ekstrak .vhdx, hash
  (tanpa --vss)                         v                          | Mount-DiskImage -Access ReadOnly
  --tdest  -> --vhdx -> zip (--zv) ---> master  ----salin------->  v
  copylog / skiplog / ConsoleLog                                 kape.exe  Modules
                                                                   --msource F:\ --module !EZParser
                                                                   --mdest  -> CSV per kategori
                                                                   v
                                                                 Timeline Explorer
                                                                 + daftar: ada | tidak ada | menunggu E16
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan dan data pribadi 400 ribu pelanggan broadband. Kasusnya `INC-2026-019`: lampiran `Tagihan-Okt-2026.zip` (berisi `Tagihan-Okt-2026.js`) dari `billing@vendor-tagihan.example` dijalankan di tiga laptop staf penagihan. Laptop ketiga, `JKT-WS-0412` milik `rizky.saputra` (`10.10.41.23`, tanpa EDR), dibawa rapat di luar kantor sejak Senin dan baru terlihat Selasa 2026-10-13 pukul 17:12 lewat DNS sinkhole, lalu port switch-nya dimatikan pukul 17:20. Persistence yang sudah dikenal dari laptop pertama adalah scheduled task `\SysCacheUpdate` yang menjalankan `C:\Users\<user>\AppData\Roaming\SysCache\upd.ps1`. Malam itu Yoga Pratama, analyst L2 yang memegang bukti, mengambil memori laptop itu pukul 17:45 (E13), lalu triage KAPE dari SSD eksternal `USB-E-11` sekitar 18:00 sampai 18:35 (E14). Kamis 2026-10-15 pukul 08:52, E14 diverifikasi ulang (`sha256sum -c` OK) sebelum diserahkan ke retainer PT Forensik Digital Contoh, dan Yoga membuat salinan kerja `E14-W1` di workstation analisis forensik `JKT-DFIR01`. Pukul 10:30, sambil image disk E15 dan E16 berjalan, Sari Kusuma (technical lead) menulis kepadamu di kanal `#inc-2026-019`:

> "Image E15 dan E16 masih jalan, perkiraan selesai siang. Sambil menunggu, tolong olah E14 di JKT-DFIR01 pakai salinan kerja E14-W1, jangan sentuh master. Jalankan !EZParser. Retainer sudah terima E14 tadi pagi dan langsung tanya: bagian mana yang bukti dan mana yang hasil olahan? Kenapa task `\SysCacheUpdate` ada tapi `upd.ps1`-nya tidak ada di koleksi? Hive dan event log yang sedang dipakai Windows kok bisa ikut tersalin, dan ada versi lama dari shadow copy atau tidak? Mereka juga minta command line persis yang dipakai Yoga, dan tanya apakah mereka boleh menjalankan KAPE sendiri di laptop Dewi hari Senin. Sebelum jam 13:00 aku perlu daftar: apa yang ada di E14, apa yang tidak, dan apa yang harus menunggu E16."

Pesan itu memuat enam pertanyaan:

1. Bagian mana dari E14 yang merupakan bukti, dan bagian mana yang hasil olahan?
2. Kenapa task `\SysCacheUpdate` ada di koleksi tetapi `upd.ps1` tidak?
3. Bagaimana file yang dikunci Windows bisa tersalin, dan apakah ada versi lama dari shadow copy?
4. Bagaimana mengolah E14 tanpa mengubah master maupun salinan kerjanya?
5. Command line apa yang dipakai Yoga, dan bolehkah retainer menjalankan KAPE sendiri?
6. Apa yang bisa dijawab hasil `!EZParser`, apa yang tidak ada di E14, dan apa yang harus menunggu E16?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, dan pertanyaan 6 di bagian 1.6 dan 1.7. Bagian 2 berisi perintah, log, hasil parse, dan daftar yang kamu kirim ke Sari.

**Kapan relevan:** koleksi triage dari host Windows yang bisa kamu sentuh langsung (konsol, media USB, atau sesi admin), preservasi cepat sebelum host di-reimage atau di-image penuh, dan pemrosesan koleksi atau image yang sudah di-mount menjadi CSV yang bisa dibaca.
**Kapan bukan jawaban:** saat butuh unallocated space atau file terhapus yang tidak tercatat di artefak (perlu image penuh, Day 01), saat host tidak bisa disentuh langsung atau jumlahnya banyak (koleksi lewat agent, Day 04), dan saat yang menjalankan adalah pihak ketiga dalam engagement berbayar (lisensi, bagian 1.5).

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day 01 (triage collection, adaptive collection, hash bukti, salinan kerja, case notes, chain of custody) tidak diulang. Tabel ini memuat istilah KAPE yang dipakai di Day ini; kolom padanan memakai analogi NOC dan SOC.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Target (`.tkape`) | File konfigurasi YAML yang menyebut path dan mask file yang dikumpulkan | Satu baris di daftar perintah `show` yang diambil skrip capture |
| Module (`.mkape`) | File konfigurasi yang menyebut program dan argumen untuk memproses file | Skrip parser yang mengubah output `show` menjadi tabel |
| Compound target | Target yang isinya merujuk target lain, mis. `!SANS_Triage` | Paket `show tech-support`: gabungan banyak `show` dalam satu perintah |
| KapeFiles | Repo publik berisi definisi Targets dan Modules, diperbarui dengan `--sync` | Repo template capture dari vendor yang diperbarui berkala |
| Deferred copy | File yang dikunci OS dibaca lewat raw disk read, bukan API file biasa | Membaca file dari flash langsung saat file itu sedang dipakai proses |
| Volume Shadow Copy (VSS/VSC) | Snapshot volume yang dibuat Windows; bisa berisi versi lama file | Arsip konfigurasi lama di router (`show archive`) |
| Container | Hasil Targets dibungkus dalam satu VHD, VHDX, atau ZIP | Satu bundle tar berisi seluruh output `show tech` |
| copylog dan skiplog | CSV catatan setiap file yang disalin (dengan SHA-1) dan yang dilewati | Manifest berkas yang diunggah ke TAC, lengkap dengan checksum |
| Deduplication (`--tdd`) | File dengan SHA-1 sama hanya disalin sekali; yang pertama ditemukan menang | Tidak mengirim dua kali file log yang identik |
| `!EZParser` | Compound module yang menjalankan rangkaian EZ Tools atas koleksi | Parser bundle TAC yang membuat tabel dari seluruh output sekaligus |

### 1.1 Targets dan Modules: dua mesin, dua tempat, dua status

Pertanyaan pertama retainer ("bagian mana yang bukti?") dijawab oleh pemisahan paling dasar di KAPE.

KAPE punya dua mesin [S8]. Targets mencari file di sebuah sumber (huruf drive atau path UNC) lalu menyalinnya ke tujuan. Modules menjalankan program, biasanya atas file yang sudah dikumpulkan Targets, dan menghasilkan CSV atau teks yang bisa dibaca [S8][S10]. Tabel berikut merangkum masukan dan keluaran keduanya; perhatikan kolom terakhir, karena di situlah status bukti berbeda.

| Mesin | Fungsi | Masukan | Keluaran | Status di kasus |
|---|---|---|---|---|
| Targets | Mengumpulkan file dari sumber (disk hidup, image yang di-mount) | `--tsource` (sumber), `--target` (apa) | File tersalin ke `--tdest`, opsional dibungkus container | Bukti: di-hash, disimpan sebagai master |
| Modules | Menjalankan program (EZ Tools dan lainnya) atas file | `--msource` (biasanya hasil Targets), `--module` | Hasil parse ke `--mdest`, dikelompokkan per kategori | Hasil olahan: bisa dibuat ulang kapan saja dari salinan |

Keduanya bisa dijalankan sekaligus dalam satu perintah atau terpisah [S6]. Alur paling umum: Targets mengumpulkan ke folder atau container, lalu Modules memproses hasil itu. Pemisahan ini penting karena koleksi Targets adalah bukti yang dipreservasi dan di-hash (Day 01), sedangkan Modules bekerja atas salinannya. Hasil Module bisa salah karena versi parser, dan itu tidak masalah selama koleksinya utuh: parser bisa diganti dan dijalankan ulang.

Definisi Target (`.tkape`) dan Module (`.mkape`) adalah file teks dari repo KapeFiles, diperbarui dengan `kape.exe --sync` [S3][S5][S6]. Target menentukan path dan mask file yang dikumpulkan; Module menentukan executable dan argumennya. Executable yang dipanggil Module tidak diunduh otomatis: ia harus ditaruh di `Modules\bin` di folder KAPE, atau di folder bernama sama dengan Module [S8][S10].

Untuk E14, jawabannya ke retainer: arsip `INC-2026-019-E14_JKT-WS-0412_triage.zip` (berisi container VHDX hasil Targets) adalah bukti. CSV yang kamu hasilkan hari ini di `JKT-DFIR01` adalah hasil olahan yang bisa mereka buat ulang sendiri dari salinan E14 yang mereka terima.

### 1.2 Compound target: apa yang masuk daftar, dan apa yang tidak

Pertanyaan kedua ("kenapa task-nya ada tapi `upd.ps1`-nya tidak?") adalah pertanyaan tentang cakupan compound target.

Compound target adalah Target yang field `Path`-nya merujuk file Target lain; KAPE mengembangkannya menjadi spesifikasi file dari target-target itu, dan susunannya boleh berlapis [S9]. Nama compound yang umum diawali `!` sehingga muncul di atas daftar. Tiga compound yang paling sering dipakai di KapeFiles per 2026-10-16 dibandingkan di tabel berikut [S13][S14]; cari baris yang menyebut profil pengguna, karena itulah yang menentukan nasib `upd.ps1`.

| Compound target | Versi, penyusun | Isi (target yang dirujuk) |
|---|---|---|
| `!SANS_Triage` | 1.5, Mark Hallman | Antivirus, CloudStorage_Metadata, CombinedLogs (event log, trace log, PowerShell console, transcript, firewall, USB log, .NET CLR), GroupPolicy, EvidenceOfExecution (Amcache, PCA, Prefetch, RecentFileCache, Syscache), FileSystem (`$MFT`, `$LogFile`, `$J`, `$SDS`, `$Boot`, `$T`), FTPClients, LNKFilesAndJumpLists, MessagingClients, NetworkScanner, RecycleBin_InfoFiles, RegistryHives, RemoteAdmin, ScheduledTasks, SRUM, SUM, WER, Thumbcache, WBEM, BITS, WebBrowsers, WindowsIndexSearch, WindowsTimeline |
| `KapeTriage` | 4.2, Scott Downie | Mirip, lebih ringkas: EventLogs, EvidenceOfExecution, FileSystem, LNK dan Jump Lists, Notepad, PowerShellConsole, RegistryHives, ScheduledTasks, SRUM, WebBrowsers, dan beberapa lainnya |
| `!BasicCollection` | 1.1, Phill Moore | Set dasar: EventLogs, EvidenceOfExecution, FileSystem, LNK dan Jump Lists, PowerShellConsole, RecycleBin_InfoFiles, RegistryHives, ScheduledTasks, SRUM, Thumbcache, USBDevicesLogs, WindowsIndexSearch |

`!SANS_Triage` adalah titik awal yang umum karena mengumpulkan registry hive, event log, Prefetch, `$MFT`, `$J`, dan banyak artefak lain dalam satu perintah [S4][S13]. Tiga target besar sengaja dikomentari di dalamnya (isi Recycle Bin, PST/OST Outlook, dan seluruh file cloud storage) karena volumenya bisa sangat besar; komentar di file itu menyarankan menjalankan target tersebut dengan mode simulasi lebih dulu untuk melihat jumlah dan ukuran file [S13]. Untuk belajar, mulai dari compound, lalu pelajari target individual yang membentuknya.

Tidak satu pun target di `!SANS_Triage` mengumpulkan isi folder sembarang di `AppData\Roaming`. Yang dikumpulkan adalah artefak dengan lokasi yang dikenal. Untuk persistence `INC-2026-019`, akibatnya begini:

- Target `ScheduledTasks` menyalin seluruh XML di `C:\Windows\System32\Tasks\` secara rekursif [S14]. File task `SysCacheUpdate`, termasuk command line yang menunjuk ke `upd.ps1`, ikut terkumpul.
- Folder `C:\Users\rizky.saputra\AppData\Roaming\SysCache\` tidak disebut di target mana pun, sehingga `upd.ps1` tidak disalin.
- Keberadaan file itu tetap tercatat di `$MFT` dan `$J` yang dikumpulkan target `FileSystem`: nama, path induk, ukuran, dan timestamp ada, isinya tidak.

Perhatikan jebakan nama: target `Syscache` di dalam EvidenceOfExecution mengumpulkan `C:\System Volume Information\Syscache.hve` beserta transaction log-nya [S14]. Itu artefak Windows, tidak ada hubungannya dengan folder `SysCache` milik penyerang. Pencarian teks "syscache" di copylog bisa memunculkan file task dan, bila host punya file itu, `Syscache.hve`, lalu memberi kesan palsu bahwa folder penyerang ikut terkumpul.

Kenapa Yoga tidak menambahkan target untuk folder itu Selasa malam? Ia sudah tahu path IOC dari laptop pertama, tetapi toolkit di `USB-E-11` belum punya target custom untuk IOC kasus ini. Menulis `.tkape` baru di laptop terkompromi tanpa pernah diuji berisiko salah path dan baru ketahuan setelah laptop dihapus; menyalin folder secara manual dengan program bawaan host melanggar prinsip "jangan percaya program di host" dan tidak tercatat di copylog. Keputusannya: jalankan target standar yang sudah teruji, catat folder IOC sebagai "tidak diambil", dan andalkan memori E13 serta image E16 untuk isi file. Itu keputusan yang tertulis di case notes (bagian 2.1), bukan kelalaian yang ditutupi. Pelajaran untuk kasus berikutnya: target custom untuk IOC disiapkan dan diuji di lab sebelum dipakai (bagian 2.7).

### 1.3 File terkunci, log koleksi, dan Volume Shadow Copy

Pertanyaan ketiga retainer menyangkut dua hal yang sering tertukar: bagaimana file aktif bisa disalin, dan apakah versi lamanya ikut.

Banyak artefak kunci (registry hive aktif, `$MFT`, event log yang sedang ditulis) dikunci OS saat sistem hidup, sehingga tidak bisa disalin lewat API file biasa. KAPE membaca file seperti itu dengan raw disk read: copylog punya kolom `DeferredCopy` yang bernilai true bila file terkunci dan dibaca lewat raw read [S7]. KAPE memerlukan hak Administrator [S8]. Halaman tips di dokumentasi KAPE juga mengutip pengalaman praktisi bahwa menjalankan KAPE sebagai SYSTEM menghilangkan galat akses file yang masih muncul saat dijalankan sebagai Administrator [S15]; perlakukan itu sebagai pengalaman praktisi dan uji di lab-mu.

Log koleksi adalah jawaban untuk "bagaimana membuktikan file apa yang diambil". Tabel berikut merangkum dua CSV yang dibuat KAPE setiap koleksi [S7]; kolom yang paling sering dipakai dalam diskusi dengan retainer adalah `SourceFile`, `SourceFileSha1`, dan `DeferredCopy`.

| Log | Nama | Kolom penting | Kegunaan |
|---|---|---|---|
| copylog | `<cap waktu>_<target>_copylog.csv` (target diganti `(Multiple)` bila lebih dari satu) | `CopiedTimestamp`, `SourceFile`, `DestinationFile`, `FileSize`, `SourceFileSha1`, `DeferredCopy`, `CreatedOnUtc`, `ModifiedOnUtc`, `LastAccessedOnUtc`, `CopyDuration` | Bukti per file: apa yang disalin, dari mana, hash SHA-1 sumber, dan timestamp file saat disalin |
| skiplog | `<cap waktu>_<target>_skiplog.csv` | `SourceFile`, `SourceFileSha1`, `Reason` (`Excluded` atau `Deduped`) | File yang sengaja tidak disalin karena deduplication atau daftar hash `--hex` |

KAPE juga menulis console log berisi semua yang tampil di jendela perintah, dengan timestamp resolusi tinggi dan level pesan, ke `--tdest` dan/atau `--mdest`; bila terjadi galat, log ditulis ke folder `kape.exe` [S7]. Lokasi persis copylog dan skiplog tidak disebut di halaman log; di koleksimu, cek apakah ketiganya ada di root container atau di samping container.

Volume Shadow Copy adalah urusan lain. Opsi `--vss` bernilai false secara default; bila diaktifkan, KAPE mencari, me-mount, dan menelusuri semua shadow copy yang tersedia di `--tsource` [S6]. File dari shadow copy tercatat di copylog dengan awalan `VSS` dan nomor VSC di `SourceFile`, dan folder tujuannya memakai nama VSC [S7]. Bersama `--vss`, opsi `--tdd` (deduplication berdasarkan SHA-1) mencegah file yang identik disalin berkali-kali; yang pertama ditemukan menang, biasanya file aktif, dan duplikatnya tercatat di skiplog dengan alasan `Deduped` [S6][S7]. Set `--tdd` ke false bila kamu ingin semua salinan.

E14 diambil tanpa `--vss`. Jadi E14 tidak berisi versi lama hive, event log, atau file lain dari shadow copy, walaupun shadow copy itu mungkin ada di laptop. Apakah `JKT-WS-0412` punya shadow copy sama sekali tidak bisa dijawab dari E14; image E16 akan menjawabnya, karena image penuh membawa seluruh volume termasuk area penyimpanan shadow copy. Alasan Yoga: waktu. Koleksi dengan `--vss` menelusuri setiap snapshot sehingga jauh lebih lama, sementara malam itu prioritasnya artefak saat ini dari host yang baru ditemukan.

Implikasi forensik koleksi live tetap berlaku: koleksi dari sistem hidup mengubah sebagian timestamp dan metadata host dan tidak menangkap unallocated space. Itu trade-off triage yang disadari (Day 01); catat di case notes bahwa koleksi dilakukan pada sistem hidup.

### 1.4 Container, zip, dan salinan kerja yang tidak berubah saat dibuka

Pertanyaan keempat Sari ("jangan sentuh master") dijawab oleh cara KAPE membungkus hasil dan cara kamu membukanya.

KAPE bisa menulis hasil Targets ke container, bukan file lepas [S4][S6]. Ketiga opsi container membutuhkan base name; tanpa nama, opsi diabaikan dan container tidak dibuat [S6]. Tabel berikut merangkum pilihannya; baris terakhir menjelaskan kenapa E14 berbentuk `.zip` walaupun Yoga meminta VHDX.

| Opsi | Hasil | Catatan |
|---|---|---|
| tanpa opsi container | File lepas di `--tdest` | Paling mudah dibaca, paling mudah berubah tanpa disadari |
| `--vhd <nama>` | Satu file VHD dari isi `--tdest` | Nama berisi cap waktu, nama target, dan base name, mis. pola `2018-09-03T144144_EvidenceOfExecution_EricWorkstation.vhd` di dokumentasi [S6] |
| `--vhdx <nama>` | Satu file VHDX dari isi `--tdest` | Pilihan umum untuk koleksi: satu file, mudah di-hash, dipindah, lalu di-mount |
| `--zip <nama>` | Arsip ZIP dari isi `--tdest` | Tanpa disk virtual; dibaca dengan ekstraksi biasa |
| `--zv` | Mengompres file VHD/VHDX | Default true, jadi `--vhdx` tanpa `--zv false` menghasilkan VHDX yang dikompres [S6] |

Saat container dipakai, path yang lebih dari 255 karakter dipendekkan: file aslinya disimpan di folder `LongFileNames` di tujuan, dan satu file teks mencatat path lengkapnya [S8]. Bila ada file dengan path sangat panjang di profil pengguna, cari folder itu sebelum menyimpulkan file tidak terkumpul.

Container VHDX disarankan karena satu file bisa di-hash sebagai bukti, dipindah ke workstation analisis, lalu di-mount read-only untuk diproses. Yang sering terlewat adalah kata read-only itu sendiri. `Mount-DiskImage` me-mount VHD/VHDX dalam mode read-write bila parameter `-Access` tidak dipakai atau bernilai `Unknown`; nilai yang diterima adalah `Unknown`, `ReadWrite`, dan `ReadOnly`, dan me-mount VHD membutuhkan hak administrator [S16]. Me-mount secara read-write membuka kemungkinan Windows menulis ke volume di dalam VHDX, dan hash VHDX bisa berubah.

Untuk E14 ada tiga lapis yang harus dibedakan saat mencatat hash:

1. Arsip `.zip` (yang di-hash Yoga Selasa malam dan diverifikasi ulang Kamis 08:52).
2. File `.vhdx` di dalam arsip, yang hash-nya berbeda dari hash arsip dan baru bisa dihitung setelah diekstrak.
3. Hash SHA-1 per file di copylog, yang dihitung KAPE dari file sumber saat koleksi [S7].

Lapis ketiga berguna untuk celah waktu yang selalu ada: KAPE selesai pukul 18:29, sedangkan hash arsip baru dihitung pukul 18:48. Selama 19 menit itu, `USB-E-11` dipegang Yoga dan tercatat di case notes; hash per file di copylog memberi pemeriksaan tambahan atas isi, karena file di dalam VHDX bisa dicocokkan dengan SHA-1 yang dicatat saat disalin.

### 1.5 CLI, gkape, dan siapa yang boleh menjalankan KAPE

Pertanyaan kelima menggabungkan hal teknis (command line persis) dan hal non-teknis (lisensi).

KAPE adalah program mandiri tanpa instalasi; cukup diekstrak ke folder pilihanmu [S8]. Ia punya CLI (`kape.exe`) dan GUI (`gkape.exe`) [S1]. gkape membantu menyusun command line yang valid lalu menjalankan `kape.exe` [S8], dan kotak di bagian bawah GUI menunjukkan perintah persis yang akan dijalankan [S1]. Cara belajar yang disarankan: susun koleksi di gkape, salin command line yang terbentuk ke case notes, lalu biasakan menjalankan CLI.

Tabel flag berikut adalah yang dipakai di Day ini, sesuai dokumentasi KAPE [S6]. Baca kolom "Perhatian" untuk flag yang punya efek samping.

| Flag | Fungsi | Perhatian |
|---|---|---|
| `--tsource` | Huruf drive sumber Targets (mis. `C`, `D:`, `F:\`); UNC didukung | Bisa juga huruf drive image yang di-mount |
| `--target` | Nama Target tanpa ekstensi; beberapa dipisah koma tanpa spasi; nama folder menjalankan semua target di dalamnya | Cek nama dengan `--tlist` atau `--tdetail` |
| `--tdest` | Folder tujuan koleksi; dibuat bila belum ada; mendukung `%d` (cap waktu) dan `%m` (nama mesin) | Jangan di drive sistem host |
| `--tflush` | Bila true, menghapus folder `--tdest` sebelum koleksi | Salah path berarti menghapus isi folder lain; pakai folder khusus per item bukti |
| `--tdd` | Deduplication berdasarkan SHA-1 | Duplikat tercatat di skiplog |
| `--vss` | Menelusuri semua shadow copy di `--tsource`; default false | Koleksi jauh lebih lama |
| `--vhd`, `--vhdx`, `--zip` | Container dari isi `--tdest`; wajib diberi base name | Tanpa nama, container tidak dibuat |
| `--zv` | Kompres VHD/VHDX; default true | Hasil akhir berupa arsip |
| `--msource` | Folder yang diproses Modules; bisa kosong bila Targets dijalankan bersamaan (memakai `--tdest`) | Untuk koleksi yang di-mount, isi dengan huruf drive mount |
| `--module` | Nama Module tanpa ekstensi | Cek dengan `--mlist` atau `--mdetail` |
| `--mdest` | Folder tujuan hasil Modules; subfolder dibuat per kategori; mendukung `%d`, `%m`, `%s` | Simpan di luar container |
| `--mflush` | Bila true, menghapus `--mdest` sebelum memproses | Sama berbahayanya dengan `--tflush` |
| `--mef` | Mengganti format ekspor default Module (CSV, txt, JSON, dan lainnya) | Bila format tidak ada, processor default dipakai |
| `--tlist`, `--mlist`, `--tdetail`, `--mdetail` | Daftar Target dan Module; versi detail menambah path, kategori, command line, dan Module yang executable-nya belum ada | `--mlist . --mdetail` membantu menemukan biner yang kurang [S11] |
| `--sync` | Memperbarui Targets dan Modules dari repo KapeFiles | Butuh akses internet; di `JKT-DFIR01` lewat proxy terjadwal (Day 02) |
| `--debug`, `--trace` | Pesan lebih rinci; `--trace` memperlambat KAPE secara nyata | Pakai saat troubleshooting, bukan saat koleksi darurat |

Mode simulasi (`--sim`) ditambahkan di versi 0.9.0.2: proses hashing dan logging tetap berjalan tetapi data tidak disalin, sehingga berguna untuk memperkirakan ukuran koleksi [S12][S13]. Flag ini tidak muncul di halaman daftar switch yang diperiksa, jadi cek di `kape.exe --help` versi lab-mu sebelum dipakai.

Untuk command line Yoga, sumbernya ada dua: case notes Selasa malam yang mencatat perintah persis, dan console log KAPE yang merekam apa yang tampil di jendela perintah [S7]. Keduanya dikirim ke retainer bersama copylog dan skiplog.

Soal lisensi, ada dua dokumen resmi yang harus dibaca bersama, dan keduanya tidak sepenuhnya sejalan:

- EULA KAPE Solo (terakhir diubah 4 Juni 2020) menyebut edisi gratis untuk tujuan non-komersial, yaitu lembaga penegak hukum dan pemerintah, perorangan untuk pemakaian pribadi, serta pelajar dan institusi pendidikan; penggunaan untuk tujuan bisnis membutuhkan KAPE Enterprise License [S20].
- FAQ di dokumentasi KAPE (diperbarui Februari 2026) menyebut KAPE gratis untuk pemerintah, pendidikan, riset, dan penggunaan internal perusahaan, dan sejak 1 Januari 2026 tidak lagi tersedia untuk penggunaan komersial, yaitu bila dipakai di jaringan pihak ketiga dan/atau sebagai bagian dari engagement berbayar [S11].

Keduanya berbeda soal penggunaan internal perusahaan, tetapi sejalan soal pihak ketiga yang dibayar. Untuk PT JAB artinya:

- PT JAB mengikuti tafsir yang lebih ketat: KAPE dipakai di bawah Enterprise License yang nomor order dan pengguna terdaftarnya dicatat di inventaris alat (Day 02).
- Bila retainer menjalankan KAPE di laptop Dewi dalam engagement berbayar, pemakaian itu tidak tercakup lisensi PT JAB, yang terbatas pada pengguna terdaftar di jaringan PT JAB (Day 02), dan masuk kategori yang menurut FAQ tidak lagi tersedia. Pilihannya, koleksi dijalankan tim internal lalu hasilnya diserahkan, atau retainer memakai alat mereka sendiri yang lisensinya jelas.
- Keputusan akhir ada di Legal bersama perjanjian retainer; bila ragu, tanyakan langsung ke Kroll. Ini bukan nasihat hukum.

### 1.6 Module `!EZParser`: apa yang diproses, dan apa yang tidak

Bagian pertama pertanyaan keenam ("apa yang bisa dijawab hasil `!EZParser`?") bergantung pada daftar module di dalamnya, bukan pada isi koleksi.

`!EZParser` adalah compound module (versi 1.5, Phill Moore) yang menjalankan module untuk AmcacheParser, AppCompatCacheParser, EvtxECmd, JLECmd, LECmd, MFTECmd, PECmd, RBCmd, RecentFileCacheParser, RECmd (batch DFIR), SBECmd, SQLECmd, SrumECmd, SumECmd, dan WxTCmd [S17]. Module MFTECmd sendiri adalah compound yang memproses `$Boot`, `$MFT`, `$J`, dan `$SDS` [S17]. Hasilnya CSV per artefak, ditaruh di subfolder sesuai `Category` di file Module [S6][S10]. Ini jembatan dari koleksi mentah ke data yang bisa dibaca: Targets mengumpulkan `$MFT`, `!EZParser` menjalankan MFTECmd atasnya, hasilnya CSV untuk Timeline Explorer. Output CSV ini yang kamu baca di Day 07-10.

Dua hal tidak ada di daftar itu, dan keduanya relevan untuk E14:

- Tidak ada parser untuk XML scheduled task. File `SysCacheUpdate` dari target `ScheduledTasks` tidak menjadi CSV; kamu membacanya langsung sebagai XML (bagian 2.5).
- Tidak ada parser untuk file yang memang tidak dikumpulkan. `!EZParser` tidak bisa memunculkan isi `upd.ps1`; yang muncul hanya metadata dari `$MFT` dan `$J`.

Isi skrip penyerang kadang tetap bisa didekati dari event log. Bila Script Block Logging aktif, PowerShell mencatat isi semua scriptblock yang diproses, baik yang dijalankan interaktif maupun lewat otomasi, sebagai event 4104 [S19]. Dokumentasi yang sama membaca event 4104 dari channel `Microsoft-Windows-PowerShell/Operational` milik Windows PowerShell, sedangkan PowerShell 7 menulis ke log `PowerShellCore/Operational` [S19]. Script block bisa terpecah ke beberapa event, dan yang tercatat adalah blok yang diproses, bukan salinan file, jadi 4104 bukan pengganti `upd.ps1`. Riwayat PSReadLine (`ConsoleHost_history.txt` di `$Env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine`) yang dikumpulkan target PowerShellConsole hanya berisi perintah yang diketik di console, dan baris yang mengandung kata seperti `password`, `token`, atau `secret` tidak ditulis [S18]. Skrip yang dijalankan scheduled task tidak diketik siapa pun, jadi jangan berharap menemukannya di sana.

### 1.7 Keterbatasan triage KAPE: menulis "tidak ada" dengan benar

Bagian kedua pertanyaan keenam ("apa yang tidak ada di E14, dan apa yang menunggu E16?") adalah pekerjaan menulis, bukan menjalankan alat.

Keterbatasan yang selalu berlaku:

- Tidak menangkap unallocated space atau file terhapus yang tidak tercatat di `$MFT` atau artefak lain (butuh image penuh, Day 01).
- Bergantung pada daftar target: artefak yang tidak ada di target tidak dikumpulkan (adaptive collection di Velociraptor menambal sebagian, Day 04).
- Koleksi dari sistem hidup mengubah sebagian timestamp dan metadata host.
- Shadow copy hanya dibaca bila `--vss` diaktifkan.
- Pemrosesan dengan Module bergantung versi EZ Tools; catat versinya (Day 02).

Sebaliknya, `$MFT` dan `$J` yang ikut terkumpul tetap mencatat metadata file, termasuk entri file yang sudah dihapus selama catatannya belum tertimpa. Triage bisa menunjukkan bahwa sebuah file pernah ada beserta nama dan waktunya, walaupun isinya tidak bisa dipulihkan (Day 08).

Dari keterbatasan itu lahir tiga kategori jawaban yang harus dibedakan di setiap laporan triage:

| Kategori | Arti | Contoh di E14 |
|---|---|---|
| Ada | Artefak terkumpul dan sudah diproses atau dibaca | XML task `SysCacheUpdate`, Prefetch, event log, `$MFT` |
| Tidak ada karena tidak diambil | Lokasinya di luar target atau opsi tidak diaktifkan; tidak berarti tidak ada di host | Isi `upd.ps1`, lampiran di profil pengguna, versi lama dari shadow copy |
| Tidak ditemukan di yang diambil | Lokasinya termasuk target, tetapi isinya tidak memuat jejak yang dicari | Diisi setelah analisis, dengan menyebut artefak yang diperiksa |

Kategori kedua tidak boleh tercampur dengan kategori ketiga. Kalimat "`upd.ps1` tidak ditemukan di E14" akan dibaca retainer atau DPO sebagai "file itu tidak ada", padahal yang benar "tidak diambil". Copylog adalah alat ukurnya: file yang tidak ada di copylog tidak pernah disalin, sedangkan file yang ada di copylog tetapi tidak memuat jejak termasuk kategori ketiga.

Setelah E16 selesai, Targets yang sama bisa dijalankan atas image yang di-mount (`--tsource` diisi huruf drive mount), ditambah target custom untuk folder IOC. Hasilnya bisa dibandingkan langsung dengan copylog E14.

## 2. Contoh dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Nama kolom CSV, nama folder kategori, dan teks console bisa berbeda antar versi KAPE dan EZ Tools; cocokkan dengan versi di lab-mu. Perintah ditulis untuk lingkungan PT JAB; untuk latihan, jalankan hanya di VM lab terisolasi (bagian 3).

### 2.1 Perintah dan case notes koleksi E14 (Selasa malam)

Ini perintah yang diminta retainer, direkonstruksi dari case notes Yoga dan console log KAPE. Tujuannya: koleksi triage standar dari laptop yang baru ditemukan, ke SSD eksternal, dalam satu container yang bisa di-hash.

```
E:\kape\kape.exe --tsource C: --target !SANS_Triage --tdest E:\INC-2026-019\E14\tdest --tflush --vhdx INC-2026-019-E14_JKT-WS-0412
```

- `E:\kape\kape.exe`: KAPE dijalankan dari `USB-E-11` (huruf drive `E:` di laptop), bukan dari disk laptop, supaya program yang dipakai bukan milik host.
- `--tsource C:`: volume sistem laptop.
- `--target !SANS_Triage`: compound target standar toolkit (bagian 1.2) [S13].
- `--tdest E:\INC-2026-019\E14\tdest`: tujuan di SSD eksternal, di folder khusus item E14, bukan di drive sistem host.
- `--tflush`: mengosongkan folder tujuan dulu. Aman karena folder itu khusus untuk E14 dan kosong sebelumnya.
- `--vhdx INC-2026-019-E14_JKT-WS-0412`: base name container. Karena `--zv` default true, VHDX dikompres [S6].
- Tidak ada `--vss`, jadi shadow copy tidak ditelusuri (default false) [S6].

Keluaran ilustrasi (ringkas, dari console log):

```
2026-10-13 18:02:11  Using Targets: !SANS_Triage
2026-10-13 18:02:11  tsource: C:\  tdest: E:\INC-2026-019\E14\tdest  VSS: False
2026-10-13 18:24:40  Copied 3,118 files (deferred: 46). Skipped (deduped): 14
2026-10-13 18:26:02  Creating VHDX container...
2026-10-13 18:29:37  Zipping container... done
```

**Cara membaca hasil:** 3.118 file disalin, 46 di antaranya lewat deferred copy (file terkunci), dan 14 dilewati karena deduplication. Ketiga angka itu harus sama dengan jumlah baris di copylog, jumlah baris `DeferredCopy` true, dan jumlah baris skiplog (bagian 2.3). `VSS: False` adalah bukti tertulis bahwa shadow copy tidak diambil.

Case notes Yoga untuk koleksi ini mencatat keputusan, bukan hanya perintah:

```
INC-2026-019 | Case notes forensik | Yoga Pratama | TZ catatan: UTC+7 (WIB)
2026-10-13 17:58  JKT-WS-0412: memori E13 selesai (mulai 17:45). Lanjut triage KAPE dari USB-E-11.
2026-10-13 18:00  Login konsol adm.yoga. Laptop menyala, port switch mati sejak 17:20.
2026-10-13 18:02  kape.exe --tsource C: --target !SANS_Triage --tdest E:\INC-2026-019\E14\tdest
                  --tflush --vhdx INC-2026-019-E14_JKT-WS-0412   (KapeFiles di USB-E-11: !SANS_Triage v1.5)
                  Keputusan: target standar toolkit, tanpa --vss, tanpa target tambahan.
                  Alasan: host baru ditemukan; prioritas artefak saat ini secepatnya; target custom IOC
                  belum ada di toolkit dan tidak bisa diuji malam ini.
                  Tidak diambil: isi C:\Users\rizky.saputra\AppData\Roaming\SysCache\ (di luar target),
                  file di profil pengguna di luar target (termasuk lampiran), salinan dari shadow copy.
                  Risiko: isi upd.ps1 versi host ini dan versi lama artefak tidak tersedia dari E14.
                  Mitigasi: memori E13; usulkan image disk bila analisis butuh isi file.
2026-10-13 18:29  KAPE selesai: 3.118 disalin, 46 deferred, 14 deduped. VHDX dikompres (--zv default).
2026-10-13 18:35  USB-E-11 dilepas, masuk tas bukti. Laptop dibiarkan menyala, tetap terisolasi.
2026-10-13 18:48  SHA-256 arsip dihitung di workstation SOC (Get-FileHash): 4c7e...; nama asli dicatat.
2026-10-13 19:05  Diunggah ke jkt-evid01 sebagai INC-2026-019-E14_JKT-WS-0412_triage.zip; sha256sum cocok.
```

**Variasi:** dengan target custom IOC yang sudah diuji, perintahnya menjadi `--target !SANS_Triage,INC2026019_IOC` (koma tanpa spasi) [S6]. Bila waktu cukup dan shadow copy diperlukan, tambahkan `--vss`; perkirakan dulu ukurannya dengan mode simulasi di lab.

**Kapan gagal:** KAPE dijalankan tanpa hak Administrator, sehingga file terkunci gagal disalin dan jumlah deferred copy nol; atau `--tdest` menunjuk ke drive sistem host sehingga koleksi menimpa ruang kosong yang mungkin berisi bukti.

### 2.2 Dari master ke salinan kerja yang di-mount read-only (JKT-DFIR01)

Langkah ini menjawab pertanyaan keempat Sari. Setelah verifikasi 08:52, Yoga membuat salinan kerja E14-W1 di area kerja kasus `\\jkt-evid01\cases\INC-2026-019\work\` (Day 02). Karena me-mount VHDX langsung dari share SMB belum teruji di lingkungan PT JAB, kamu menyalin E14-W1 ke disk lokal `JKT-DFIR01` di `C:\DFIR\work\INC-2026-019\E14-W1\`, lalu memastikan salinan itu identik, mengekstrak VHDX-nya, dan me-mount-nya tanpa kemungkinan menulis.

```powershell
$w = 'C:\DFIR\work\INC-2026-019\E14-W1'
# 1. salinan kerja identik dengan master?
Get-FileHash -Path "$w\INC-2026-019-E14_JKT-WS-0412_triage.zip" -Algorithm SHA256 |
  Format-List Algorithm, Hash
# 2. ekstrak, lalu hash VHDX sebagai turunan yang dicatat
Expand-Archive -Path "$w\INC-2026-019-E14_JKT-WS-0412_triage.zip" -DestinationPath "$w\vhdx"
$v = Get-ChildItem "$w\vhdx" -Filter *.vhdx
Get-FileHash -Path $v.FullName -Algorithm SHA256 | Format-List Hash, Path
# 3. mount read-only
Mount-DiskImage -ImagePath $v.FullName -Access ReadOnly -PassThru | Get-Volume
```

- `Get-FileHash -Algorithm SHA256`: hash arsip dibandingkan dengan file `.sha256` master. Harus sama persis.
- `Expand-Archive`: mengeluarkan VHDX dari arsip ke subfolder `vhdx`. Nama VHDX berisi cap waktu, nama target, dan base name dari KAPE; perintah memakai `-Filter *.vhdx` supaya tidak perlu menebak nama persisnya.
- Hash VHDX dicatat sebagai item turunan. Lapis ini berbeda dari hash arsip (bagian 1.4).
- `Mount-DiskImage -Access ReadOnly`: tanpa `-Access`, VHDX di-mount read-write [S16]. `-PassThru | Get-Volume` menampilkan huruf drive yang diberikan.

Keluaran ilustrasi:

```
Algorithm : SHA256
Hash      : 4C7E...                         (cocok dengan .sha256 master)

Hash      : A91D...
Path      : C:\DFIR\work\INC-2026-019\E14-W1\vhdx\<cap waktu>_..._INC-2026-019-E14_JKT-WS-0412.vhdx

DriveLetter FileSystemLabel FileSystem DriveType HealthStatus SizeRemaining     Size
----------- --------------- ---------- --------- ------------ -------------     ----
F                           NTFS       Fixed     Healthy           ...          ...
```

**Cara membaca hasil:** hash arsip cocok berarti E14-W1 identik dengan master. Volume `F:` berisi struktur folder hasil KAPE: folder `C` untuk file dari volume sumber, dan log koleksi. Karena tidak ada `--vss`, tidak ada folder `VSS1`, `VSS2`, dan seterusnya.

**Variasi:** di `JKT-DFIR01` yang dipakai bergantian, matikan auto-mount volume baru sebelum menyambungkan media bukti, dan setelah selesai lepas dengan `Dismount-DiskImage -ImagePath $v.FullName`. Untuk latihan, hash VHDX sesudah dismount dan bandingkan dengan hash sebelum mount (bagian 3).

**Kapan gagal:** `Mount-DiskImage` menolak dengan pesan bahwa file sedang dipakai proses lain, karena VHDX sudah di-mount sebelumnya [S16]; atau seseorang membuka VHDX dengan klik ganda di Explorer, sehingga mode mount-nya tidak tercatat. Bila ragu, buat salinan kerja baru dari master.

### 2.3 Membaca copylog dan skiplog: apa yang benar-benar diambil

Langkah ini menjawab pertanyaan kedua dan ketiga retainer dengan data, bukan ingatan. Copylog dan skiplog di root volume `F:` dibaca dengan PowerShell.

```powershell
$c = Import-Csv (Get-ChildItem F:\ -Filter *_copylog.csv).FullName
$s = Import-Csv (Get-ChildItem F:\ -Filter *_skiplog.csv).FullName
$c.Count
($c | Where-Object DeferredCopy -eq 'True').Count
$s | Group-Object Reason | Select-Object Name, Count
$c | Where-Object SourceFile -match 'syscache|upd\.ps1' | Select-Object SourceFile, FileSize, SourceFileSha1
$c | Where-Object SourceFile -like 'VSS*' | Measure-Object
```

- `Import-Csv`: membaca CSV menjadi objek per baris. Nama file diawali cap waktu koleksi, jadi dicari dengan filter.
- `DeferredCopy -eq 'True'`: file terkunci yang dibaca lewat raw read [S7]. Nilai di CSV berupa teks, dan `-eq` di PowerShell tidak peka huruf besar-kecil untuk string.
- `Group-Object Reason`: memisahkan `Deduped` dan `Excluded` [S7].
- `-match 'syscache|upd\.ps1'`: regex tidak peka huruf besar-kecil; menangkap file task, `Syscache.hve` bila ada, dan `upd.ps1` bila ikut tersalin.
- `-like 'VSS*'`: baris dari shadow copy berawalan `VSS` [S7]; harus nol untuk E14.

Keluaran ilustrasi:

```
3118
46

Name    Count
----    -----
Deduped    14

SourceFile                                   FileSize SourceFileSha1
----------                                   -------- --------------
C:\Windows\System32\Tasks\SysCacheUpdate         3612 5e0b...

Count    : 0
```

**Cara membaca hasil:**

- 3.118 baris, 46 deferred, 14 deduped: cocok dengan console log (bagian 2.1).
- File task `SysCacheUpdate` ada. Tidak ada baris untuk `AppData\Roaming\SysCache\upd.ps1`: file itu tidak disalin, sesuai catatan "tidak diambil" Yoga. Di host contoh ini tidak ada baris `Syscache.hve`, jadi file itu tidak ada di laptop atau tidak terbaca; cek dulu sebelum menulis yang mana.
- Nol baris `VSS*`: tidak ada salinan dari shadow copy.

**Variasi:** ekspor daftar path saja (`$c.SourceFile | Set-Content ...`) dan lampirkan ke laporan untuk retainer. Untuk koleksi dengan `--vss`, kelompokkan `SourceFile` berdasarkan awalan (`C:` versus `VSS1`, `VSS2`) untuk melihat berapa file datang dari tiap snapshot.

**Kapan gagal:** copylog dibuka di Excel lalu disimpan ulang di folder yang sama, sehingga isi dan encoding berubah. Baca dari volume read-only atau dari salinan.

### 2.4 Memproses E14-W1 dengan `!EZParser`

Langkah ini adalah permintaan utama Sari. `JKT-DFIR01` memakai KAPE dari `C:\DFIR\tools\KAPE`, dengan definisi KapeFiles dan EZ Tools yang diperbarui pagi ini lewat proxy terjadwal lalu dibekukan sampai kasus selesai (Day 02). Yang dijalankan `!EZParser` adalah salinan EZ Tools di `Modules\bin` milik KAPE, jadi versi di folder itu yang dicatat sebelum dijalankan.

```
C:\DFIR\tools\KAPE\kape.exe --msource F:\ --module !EZParser --mdest \\jkt-evid01\cases\INC-2026-019\analysis\E14-W1\EZ-2026.5.0 --mflush
```

- `--msource F:\`: volume VHDX yang di-mount read-only.
- `--module !EZParser`: compound module EZ Tools (bagian 1.6) [S17].
- `--mdest`: hasil ke area kerja kasus di `jkt-evid01`, di luar container, di folder yang namanya memuat nomor bukti dan versi EZ Tools (Day 02). Subfolder dibuat per kategori Module [S6].
- `--mflush`: aman karena folder itu khusus untuk hasil E14-W1 dengan versi ini; bila dijalankan ulang, hasil lama dihapus dulu.

Keluaran ilustrasi (ringkas):

```
2026-10-15 10:56:20  Using Modules: !EZParser   msource: F:\   mdest: \\jkt-evid01\cases\INC-2026-019\analysis\E14-W1\EZ-2026.5.0
2026-10-15 10:56:21  Running EvtxECmd ...      (C\Windows\System32\winevt\Logs)
2026-10-15 11:02:47  Running MFTECmd ...       ($MFT, $J, $Boot, $SDS)
2026-10-15 11:19:05  Running PECmd ... RECmd ... SrumECmd ... AmcacheParser ...
2026-10-15 11:31:12  Modules complete. 27 output files.
```

Struktur hasil, keluaran ilustrasi:

```
EZ-2026.5.0\
  EventLogs\          ..._EvtxECmd_Output.csv
  FileFolderAccess\   ..._LECmd_Output.csv, ..._AutomaticDestinations.csv
  FileSystem\         ..._MFTECmd_$MFT_Output.csv, ..._MFTECmd_$J_Output.csv
  ProgramExecution\   ..._PECmd_Output.csv, ..._Amcache_*.csv, ..._AppCompatCache.csv
  Registry\           ..._RECmd_Batch_..._Output.csv
  SRUMDatabase\       ..._SrumECmd_*.csv
```

**Cara membaca hasil:** nama folder mengikuti field `Category` di setiap file `.mkape` [S10]; cek nama persisnya di versi KapeFiles-mu. Tidak ada folder untuk scheduled task karena tidak ada module task di `!EZParser`. Waktu proses 35 menit dicatat di case notes.

**Variasi:** jalankan satu module saja untuk iterasi cepat, misalnya `--module EvtxECmd`, atau ganti format dengan `--mef` bila module menyediakan processor lain [S6].

**Kapan gagal:** executable EZ Tools tidak ada di `Modules\bin`, sehingga KAPE berhenti memproses module itu dengan peringatan di console [S10]. Cek dengan `kape.exe --mlist . --mdetail` sebelum memproses bukti [S11].

### 2.5 Membaca hasil: metadata `upd.ps1`, XML task, dan event log

Langkah ini mengisi kolom "ada" untuk Sari. Semua timestamp dari EZ Tools dalam UTC; laporan PT JAB memakai WIB (UTC+7), jadi setiap waktu di bawah ditulis keduanya sekali, lalu WIB.

Pertama, metadata `upd.ps1` dari output MFTECmd `$MFT`, dibuka di Timeline Explorer atau difilter dengan PowerShell:

```powershell
Import-Csv (Get-ChildItem \\jkt-evid01\cases\INC-2026-019\analysis\E14-W1\EZ-2026.5.0\FileSystem -Filter '*$MFT_Output.csv').FullName |
  Where-Object { $_.ParentPath -like '*\AppData\Roaming\SysCache' } |
  Select-Object ParentPath, FileName, FileSize, InUse, Created0x10, Created0x30, LastModified0x10
```

Keluaran ilustrasi:

```
ParentPath       : .\Users\rizky.saputra\AppData\Roaming\SysCache
FileName         : upd.ps1
FileSize         : 4812
InUse            : True
Created0x10      : 2026-10-12 13:14:37.5520114
Created0x30      : 2026-10-12 13:14:37.5520114
LastModified0x10 : 2026-10-12 13:14:37.6018822
```

**Cara membaca hasil:** file ada di disk saat koleksi (`InUse` true), dibuat Senin 2026-10-12 13:14:37 UTC (20:14:37 WIB), saat laptop berada di luar kantor. Ukuran 4.812 byte bisa dibandingkan dengan salinan `upd.ps1` dari laptop pertama, tetapi ukuran sama tidak membuktikan isi sama. Arti kolom `0x10` dan `0x30` (dua set timestamp di MFT) dan cara membaca timestomping dibahas di Day 08; nama kolom cek di versi MFTECmd-mu.

Kedua, XML task dibaca langsung dari volume read-only, karena tidak ada module yang memprosesnya:

```powershell
[xml]$t = Get-Content 'F:\C\Windows\System32\Tasks\SysCacheUpdate'
$t.Task.RegistrationInfo.Date
$t.Task.Triggers.InnerXml
$t.Task.Actions.Exec | Format-List Command, Arguments
```

Keluaran ilustrasi:

```
2026-10-12T20:14:39
<TimeTrigger><Repetition><Interval>PT15M</Interval></Repetition>...</TimeTrigger><LogonTrigger>...</LogonTrigger>
Command   : powershell.exe
Arguments : -NoProfile -WindowStyle Hidden -File "C:\Users\rizky.saputra\AppData\Roaming\SysCache\upd.ps1"
```

**Cara membaca hasil:** task terdaftar dua detik setelah `upd.ps1` dibuat dan menjalankannya lewat `powershell.exe` setiap 15 menit dan saat logon. Waktu di `RegistrationInfo` bisa tertulis tanpa zona; di contoh ini nilainya cocok dengan waktu lokal WIB, tetapi selalu bandingkan dengan `$MFT` sebelum menyimpulkan zona. Field ini ditulis oleh pembuat task, jadi bisa dipalsukan; jejak task di registry dan event log dibahas di Day 09 dan Day 11.

Ketiga, event log dari output EvtxECmd, difilter untuk event yang relevan:

```powershell
Import-Csv (Get-ChildItem \\jkt-evid01\cases\INC-2026-019\analysis\E14-W1\EZ-2026.5.0\EventLogs -Filter '*EvtxECmd_Output.csv').FullName |
  Where-Object { $_.EventId -in 4104, 4698 -and $_.Payload -match 'SysCache' } |
  Sort-Object TimeCreated | Select-Object -First 3 TimeCreated, EventId, Channel
```

Keluaran ilustrasi:

```
TimeCreated                 EventId Channel
-----------                 ------- -------
2026-10-12 13:14:52.0331870 4104    Microsoft-Windows-PowerShell/Operational
2026-10-12 13:14:52.0418226 4104    Microsoft-Windows-PowerShell/Operational
2026-10-12 13:29:53.1170539 4104    Microsoft-Windows-PowerShell/Operational
```

**Cara membaca hasil:** event 4104 pertama Senin 20:14:52 WIB, lalu berulang sekitar 15 menit kemudian, cocok dengan trigger task. Isi blok skrip di kolom payload menunjukkan loader yang sama dengan laptop pertama, sehingga sebagian isi `upd.ps1` bisa dibaca dari sini [S19]. Tidak ada 4698 (task dibuat) di hasil ini; itu bisa berarti audit yang diperlukan tidak aktif di laptop itu, bukan berarti task tidak dibuat. Cek kebijakan audit host sebelum menulis kesimpulan (Day 05).

**Variasi:** buka output PECmd dan cari Prefetch `WSCRIPT.EXE` yang mereferensikan `Tagihan-Okt-2026.js`; di contoh ini waktu jalannya Senin 20:14:21 WIB, 16 detik sebelum `upd.ps1` dibuat. Output SrumECmd memberi pemakaian jaringan per aplikasi selama laptop di luar kantor, tanpa alamat tujuan (Day 10).

**Kapan gagal:** zona waktu tidak dinormalisasi, sehingga 13:14 UTC dibaca sebagai 13:14 WIB dan kejadian tampak terjadi sebelum email diterima pukul 15:58.

### 2.6 Daftar untuk Sari: ada, tidak ada, menunggu E16

Daftar ini adalah keluaran akhir yang dikirim ke Sari pukul 12:40. Baca kolom kedua dengan teliti: "tidak diambil" dan "tidak ditemukan" sengaja dibedakan (bagian 1.7).

| Pertanyaan | Status di E14 | Dasar | Menunggu E16? |
|---|---|---|---|
| Kapan lampiran dijalankan? | Ada | Prefetch `WSCRIPT.EXE` (Senin 20:14:21 WIB), `$J` | Tidak, hanya untuk konfirmasi |
| Apakah persistence `\SysCacheUpdate` terpasang, dan apa yang dijalankannya? | Ada | XML task, `$MFT` | Tidak |
| Metadata `upd.ps1` (path, ukuran, waktu)? | Ada | `$MFT` dan `$J` | Tidak |
| Isi lengkap `upd.ps1` versi laptop ini? | Tidak diambil (di luar target) | Copylog tanpa baris `upd.ps1`; sebagian isi dari 4104 | Ya |
| File lampiran `Tagihan-Okt-2026.zip` dan `.js` di profil pengguna? | Tidak diambil (di luar target) | Copylog; hanya referensi di Prefetch dan LNK | Ya |
| Versi lama hive dan event log dari shadow copy? | Tidak diambil (`--vss` tidak dipakai) | Console log `VSS: False`, nol baris `VSS*` | Ya, termasuk apakah shadow copy ada |
| File yang dihapus penyerang di laptop ini? | Tidak bisa dijawab dari triage | Triage tidak membawa unallocated space | Ya |
| Koneksi selama di luar kantor? | Sebagian | SRUM (volume per aplikasi, tanpa tujuan) | Tidak menambah; memori E13 sudah diperiksa retainer |

Kalimat pengantar ke Sari: "E14 menjawab kapan lampiran dijalankan dan bagaimana persistence dipasang di `JKT-WS-0412`; isi `upd.ps1`, lampiran, versi dari shadow copy, dan file terhapus tidak pernah diambil di E14, dan dijawab dari E16."

### 2.7 Target custom untuk IOC kasus (disiapkan dan diuji sebelum dipakai)

Target ini menutup celah E14 untuk koleksi berikutnya, misalnya atas image E16 yang di-mount atau host lain. File ditaruh di `Targets\!Local\` supaya tidak tertimpa saat `--sync`; target yang hanya ada di lokal dipindahkan ke folder itu saat sync [S9].

```yaml
Description: INC-2026-019 IOC folder SysCache dan task
Author: Tim SOC PT JAB
Version: 1.0
Id: <GUID dari kape.exe --guids>
RecreateDirectories: true
Targets:
    -
        Name: SysCache folder per user
        Category: INC2026019
        Path: C:\Users\%user%\AppData\Roaming\SysCache\
        Recursive: true
        Comment: Folder loader INC-2026-019
    -
        Name: SysCacheUpdate task XML
        Category: INC2026019
        Path: C:\Windows\System32\Tasks\
        FileMask: SysCacheUpdate
```

- Field wajib `Description`, `Author`, `Version`, `Id`, dan `RecreateDirectories`; setiap entri butuh `Name`, `Category`, dan `Path`; `Recursive` default false dan `FileMask` default `*` [S9].
- `Id` harus GUID unik; `kape.exe --guids` mencetak sepuluh GUID acak [S6].
- `%user%` dipakai target resmi untuk mengulang path di setiap profil, misalnya di target `ScheduledTasks` [S14].
- Simpan sebagai `INC2026019_IOC.tkape`, lalu cek dengan `kape.exe --tlist` dan `--tdetail` bahwa KAPE mengenalinya dan path-nya benar [S6].

**Cara membaca hasil:** uji di VM lab dengan folder dan task tiruan (bagian 3). Target dianggap siap bila copylog lab memuat file di folder tiruan dengan `SourceFileSha1` yang cocok dengan hash yang kamu hitung sendiri.

**Kapan gagal:** indentasi YAML salah sehingga KAPE menolak memuat target, atau path ditulis dengan huruf drive selain `C:`. Path di target ditulis seolah-olah di drive C; KAPE menyesuaikannya dengan `--tsource` [S9].

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** lab dari Day 02: VM korban `LAB-WS01` (Windows 11, Sysmon, snapshot `bersih-2026-10-15`), VM analisis `LAB-DFIR01` dengan KAPE dan EZ Tools, jaringan host-only `172.16.50.0/24`. Tambahkan disk virtual kedua di `LAB-WS01` sebagai media bukti (`E:`). Folder kasus lab `CASE-2026-LAB-003`. Jangan memakai data, nama, atau kejadian dari pekerjaan nyata. Semua "IOC" di lab adalah tiruan jinak.

1. **Catat versi.** Di `LAB-DFIR01`, catat versi KAPE dan EZ Tools. Bila lab punya akses update terjadwal, jalankan `kape.exe --sync` dan catat waktunya; buka `Targets\Compound\!SANS_Triage.tkape` dan catat field `Version`.
2. **Siapkan jejak tiruan.** Di `LAB-WS01`, buat folder `C:\Users\<user lab>\AppData\Roaming\SysCache\` berisi `upd.ps1` dengan satu baris jinak (`Write-Output "lab"`), dan satu scheduled task `SysCacheUpdate` yang menjalankannya. Jalankan task sekali. Catat waktu dan SHA-256 `upd.ps1`.
3. **Koleksi standar.** Salin folder KAPE ke `E:\kape\`, lalu jalankan `!SANS_Triage` ke VHDX seperti bagian 2.1 dengan `--tdest E:\CASE-2026-LAB-003\T1\tdest`. Catat jumlah file dari console. Keluaran ilustrasi untuk lab: `Copied 3,412 files`.
4. **Hash.** Hitung SHA-256 arsip hasil (bagian 1.4) dan simpan di `hashes.txt` bersama bukti.
5. **Baca copylog.** Mount container di `LAB-DFIR01` secara read-only (bagian 2.2) dan jalankan query bagian 2.3. Pastikan file task ada dan `upd.ps1` tidak ada. Catat jumlah baris `DeferredCopy` true.
6. **Uji read-only.** Hitung hash VHDX, mount read-only, buka beberapa file, dismount, lalu hash ulang. Ulangi pada salinan VHDX yang lain dengan mount read-write. Catat apakah hash berubah di masing-masing percobaan; jangan menebak, ukur.
7. **Proses.** Jalankan `!EZParser` atas volume read-only (bagian 2.4). Catat jumlah CSV, waktu proses, dan nama folder kategori yang muncul.
8. **Baca.** Temukan `upd.ps1` di output MFTECmd `$MFT`, baca XML task langsung (bagian 2.5), dan cari Prefetch `POWERSHELL.EXE` di output PECmd. Ubah semua waktu ke WIB.
9. **Target custom.** Buat `INC2026019_IOC.tkape` di `Targets\!Local\` (bagian 2.7), cek dengan `--tlist`, lalu koleksi ulang dengan `--target !SANS_Triage,INC2026019_IOC` ke `E:\CASE-2026-LAB-003\T2\tdest`. Bandingkan SHA-1 `upd.ps1` di copylog dengan hash yang kamu hitung di langkah 2 (hitung SHA-1-nya juga).
10. **Target tunggal.** Jalankan `kape.exe --tsource C: --target RegistryHives --tdest E:\CASE-2026-LAB-003\T3\reg --tflush` dan bandingkan isinya dengan bagian registry dari koleksi `!SANS_Triage`. Cek nama target di `--tlist`.
11. **Daftar ada dan tidak ada.** Tulis tabel seperti bagian 2.6 untuk koleksi T1, lalu perbarui untuk T2.
12. **Case notes.** Tulis case notes: waktu koleksi, sistem hidup (ya), akun yang dipakai, perintah persis, hash, versi KAPE, KapeFiles, dan EZ Tools, serta apa yang tidak diambil di T1 beserta alasannya.

**Hasil yang sebaiknya tersimpan:**

- Versi KAPE, `!SANS_Triage`, dan EZ Tools tercatat.
- Koleksi T1 ke VHDX berhasil; jumlah file, deferred copy, dan deduped dicatat dan cocok dengan copylog dan skiplog.
- Arsip di-hash; hash cocok setelah dipindah.
- Hasil uji read-only versus read-write (berubah atau tidak) tercatat dari pengukuran.
- `!EZParser` menghasilkan CSV; `upd.ps1` ditemukan di `$MFT` dan task terbaca dari XML.
- Target custom terbukti mengumpulkan `upd.ps1` dengan SHA-1 yang cocok.
- Tabel ada, tidak diambil, dan tidak ditemukan untuk T1 dan T2.

**Variasi tantangan:** aktifkan System Protection di `LAB-WS01` dan buat restore point dengan cara yang didukung build Windows lab-mu, ubah `upd.ps1`, lalu jalankan koleksi dengan dan tanpa `--vss`. Hitung baris copylog berawalan `VSS` dan baris skiplog `Deduped`, lalu bandingkan apakah versi lama `upd.ps1` (yang ada di target custom) dan versi lama `NTUSER.DAT` muncul dari shadow copy. Tulis apa yang VSS tambahkan, berapa tambahan waktunya, dan kapan itu berguna (misalnya melihat registry sebelum penyerang membersihkan jejak).

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat koleksi dan pemrosesan dengan KAPE. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Target tidak dikenal | Definisi lama atau nama salah | `kape.exe --sync`; cek `--tlist` dan `--tdetail` [S4][S6] |
| File terkunci tidak tersalin, `DeferredCopy` nol | Bukan Administrator, atau akses raw gagal | Jalankan sebagai administrator; uji juga sebagai SYSTEM di lab [S8][S15]; pastikan tujuan koleksi bukan volume yang sama |
| Hasil `--vhdx` berupa `.zip` | `--zv` default true | Normal; set `--zv false` bila ingin VHDX mentah [S6] |
| Container tidak dibuat | Opsi `--vhdx`/`--vhd`/`--zip` tanpa base name | Beri nama setelah opsi [S6] |
| VHDX tidak bisa di-mount | Belum didukung OS, korup, atau sudah di-mount | Verifikasi hash; cek `Get-DiskImage`; mount di Windows yang mendukung VHDX [S16] |
| File dengan path panjang tidak ada di tempatnya | Path lebih dari 255 karakter dipendekkan saat container dipakai | Cari folder `LongFileNames` dan file teks path aslinya [S8] |
| `!EZParser` tidak menghasilkan CSV untuk satu artefak | Executable tidak ditemukan Module | Taruh di `Modules\bin` atau folder bernama Module; cek `--mlist . --mdetail` [S2][S10][S11] |
| Flag ditolak | Nama flag beda versi | Pakai gkape dan baca command line yang terbentuk [S1]; cek `kape.exe --help` |
| Timestamp koleksi berubah | Koleksi dari sistem hidup | Normal untuk triage; catat di case notes (Day 01) |
| KAPE sangat lambat saat koleksi darurat | `--trace` aktif, atau `--vss` di host dengan banyak snapshot | Matikan `--trace` [S6]; putuskan `--vss` secara sadar dan catat |
| Folder hasil hilang setelah dijalankan ulang | `--tflush` atau `--mflush` menunjuk folder yang salah | Pakai folder khusus per item bukti; cek path sebelum Enter |

## 5. Kesalahan umum dan jebakan

- **Menulis koleksi ke drive sistem korban.** Bisa menimpa bukti di ruang kosong; tulis ke drive atau share terpisah.
- **Memproses (Modules) di korban atas bukti asli.** Proses di workstation analisis atas salinan (VHDX).
- **Lupa hash koleksi.** Hash segera setelah koleksi dan verifikasi setelah pindah (Day 01). Bedakan hash arsip, hash VHDX, dan SHA-1 per file di copylog.
- **Menganggap triage menangkap segalanya.** Tidak ada unallocated space atau file terhapus; itu butuh image (Day 01). Folder di luar target juga tidak ikut, termasuk folder penyerang.
- **Menulis "tidak ditemukan" untuk sesuatu yang tidak diambil.** Cek copylog dulu; tulis "tidak diambil" bila path-nya tidak pernah disalin.
- **Tertipu nama target.** Target `Syscache` mengumpulkan `Syscache.hve` di `System Volume Information`, bukan folder `SysCache` di profil pengguna [S14].
- **Mengira `--vss` aktif.** Default-nya false [S6]. Lihat console log atau hitung baris `VSS*` di copylog.
- **Me-mount VHDX dengan klik ganda atau tanpa `-Access ReadOnly`.** Default `Mount-DiskImage` untuk VHD adalah read-write [S16].
- **Mencari skrip scheduled task di riwayat PSReadLine.** Riwayat hanya berisi perintah yang diketik di console, dan baris dengan kata sensitif tidak ditulis [S18].
- **Mengandalkan nama flag dari tutorial lama.** Nama bisa berubah; konfirmasi lewat gkape atau `--help`.
- **Menganggap KAPE gratis untuk semua orang.** EULA Solo membatasi edisi gratis untuk tujuan non-komersial [S20], dan FAQ menyebut penggunaan di jaringan pihak ketiga atau engagement berbayar tidak lagi tersedia sejak 1 Januari 2026 [S11].
- `[komunitas, belum terkonfirmasi]` Banyak praktisi memulai dari `!SANS_Triage` ke VHDX lalu `!EZParser`, memisahkan koleksi (di korban) dan pemrosesan (di workstation analisis). Pola ini umum dan sejalan dengan pemisahan Targets dan Modules di dokumentasi [S1][S4][S8]; konfirmasi nama target dan module di versimu.

## 6. Catatan terkini

Bagian ini menampung detail versi dan perubahan yang bisa berubah lagi. Berguna saat memperbarui toolkit, tetapi tidak mengubah alur kerja di atas.

- **Lisensi KAPE:** FAQ dokumentasi (diperbarui 11 Februari 2026) menyebut gratis untuk pemerintah, pendidikan, riset, dan penggunaan internal perusahaan, dan sejak 1 Januari 2026 tidak lagi tersedia untuk penggunaan komersial [S11]. EULA Solo (4 Juni 2020) lebih ketat soal tujuan bisnis dan mengarahkan ke Enterprise License [S20]. Perbedaan soal penggunaan internal perusahaan ini perlu dipantau; PT JAB memakai tafsir yang lebih ketat.
- **Changelog KAPE:** halaman changelog di dokumentasi resmi terakhir mencatat versi 1.3.0.2 (22 Desember 2022), yang mengganti logging console ke Serilog dan menambah variabel module `%d%`, `%guid%`, dan `%sourceDirectoryBase%` [S12]. Paket KAPE diunduh lewat Kroll; versi yang terpasang dicatat dari banner `kape.exe` atau gkape, bukan dari changelog.
- **KapeFiles tetap aktif** dan terus menambah target, misalnya target untuk Windows Copilot Recall dan AI coding agent di folder target per 2026-10-16 [S3][S14]. Selalu catat versi compound yang dipakai (`!SANS_Triage` v1.5, `KapeTriage` v4.2, `!BasicCollection` v1.1, `!EZParser` v1.5 per 2026-10-16) [S13][S14][S17].
- **EZ Tools 2026.5.0:** CLI tersedia untuk .NET 4.7.2 dan .NET 9, semua GUI (termasuk Timeline Explorer) hanya .NET 9 [S2]. Dokumentasi KAPE sendiri masih menyebut .NET 4.5.2 atau lebih baru sebagai syarat `kape.exe` [S8]. Catat versi EZ Tools karena memengaruhi hasil parse.
- **gkape** menampilkan command line yang terbentuk, cara andal memastikan flag di versimu [S1].
- Compound target `!SANS_Triage` dan `!BasicCollection` tetap titik awal umum; output container VHD/VHDX didukung [S4][S6].

## 7. Cheat sheet

```
DUA MESIN  Targets: --tsource --target --tdest [--vhdx nama] [--vss]   = BUKTI (hash, master)
           Modules: --msource --module --mdest                          = HASIL OLAHAN (bisa diulang)
COMPOUND   !SANS_Triage (v1.5) | KapeTriage (v4.2) | !BasicCollection (v1.1) ; cek --tlist / --tdetail
           folder sembarang di profil pengguna TIDAK ikut ; target Syscache = Syscache.hve, bukan folder SysCache
KOLEKSI    E:\kape\kape.exe --tsource C: --target !SANS_Triage --tdest E:\<kasus>\<item>\tdest --tflush --vhdx <nama>
           --zv default true -> hasil .zip ; --vss default false ; --tdd dedup SHA-1
LOG        copylog: SourceFile, SourceFileSha1, DeferredCopy, Created/Modified/LastAccessedOnUtc
           skiplog: Reason Deduped/Excluded ; VSS -> SourceFile berawalan VSS<n>
HASH       arsip .zip != .vhdx != SHA-1 per file (copylog) ; catat ketiganya
MOUNT      Mount-DiskImage -ImagePath <vhdx> -Access ReadOnly -PassThru | Get-Volume   (tanpa -Access = read-write)
PROSES     kape.exe --msource F:\ --module !EZParser --mdest <area kerja>\analysis\<item>\EZ-<versi> --mflush
           !EZParser: Amcache, AppCompatCache, Evtx, JLE, LE, MFT($MFT,$J,$Boot,$SDS), PE, RB, RECmd, SBE, SQLE, Srum, Sum, WxT
           tidak ada parser task XML -> baca XML langsung
WAKTU      EZ Tools = UTC ; laporan PT JAB = WIB (UTC+7)
LAPORAN    ada | tidak diambil (cek copylog) | tidak ditemukan di yang diambil
CUSTOM     Targets\!Local\<nama>.tkape ; Id dari --guids ; %user% ; uji di lab dulu
LISENSI    EULA Solo: gratis hanya non-komersial, bisnis = Enterprise License ; FAQ 2026: pihak ketiga/engagement berbayar tidak lagi tersedia
           PT JAB: Enterprise License, pengguna terdaftar ; retainer tidak memakai lisensi PT JAB
BATAS      tanpa unallocated/file terhapus ; bergantung daftar target ; live ubah timestamp
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Pencarian `syscache` di copylog E14 mengembalikan baris, jadi folder `SysCache` milik penyerang ikut terkumpul." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Baris yang muncul adalah file task `C:\Windows\System32\Tasks\SysCacheUpdate` dari target `ScheduledTasks`, dan di host lain bisa juga `Syscache.hve` dari target `Syscache`, yang merupakan artefak Windows di `System Volume Information`. Tidak ada baris untuk `AppData\Roaming\SysCache\upd.ps1`, karena tidak ada target di `!SANS_Triage` yang mengumpulkan folder sembarang di profil pengguna. Yang ada hanya metadata file itu di `$MFT` dan `$J`. Lihat bagian 1.2 dan 2.3.

</details>

**2. Skenario keputusan.** Sari ingin hasil cepat dan menyarankan membuka VHDX E14-W1 dengan klik ganda di Explorer. Langkah mana yang tepat?

- A. Klik ganda saja; VHDX hasil KAPE otomatis read-only.
- B. Verifikasi hash salinan kerja, ekstrak VHDX dan catat hash-nya, lalu `Mount-DiskImage -Access ReadOnly`.
- C. Mount langsung master E14 dari share `\\jkt-evid01\evidence` karena share itu read-only.

<details><summary>Jawaban</summary>

B. Hash memastikan salinan kerja identik dengan master, hash VHDX dicatat sebagai item turunan, dan `-Access ReadOnly` mencegah mount read-write, yang menjadi default `Mount-DiskImage` untuk VHD bila parameter itu tidak dipakai. A keliru karena tidak ada jaminan read-only dan mode mount tidak tercatat. C keliru karena master tidak dipakai untuk pemrosesan: yang diolah selalu salinan kerja, supaya master tetap bisa diverifikasi ulang kapan saja. Lihat bagian 1.4 dan 2.2.

</details>

**3. Pertanyaan jebakan.** "E14 diambil tanpa `--vss`, jadi E14 sama sekali tidak bisa memberi tahu apa pun tentang file yang sudah berubah atau dihapus." Benarkah?

<details><summary>Jawaban</summary>

Tidak sepenuhnya. Tanpa `--vss`, E14 memang tidak berisi salinan file dari shadow copy, dan triage tidak membawa unallocated space. Tetapi `$MFT` dan `$J` yang dikumpulkan target `FileSystem` tetap mencatat metadata file dan perubahannya, termasuk file yang dihapus selama catatannya belum tertimpa. Apakah laptop punya shadow copy pun tidak bisa dijawab dari E14; image E16 yang menjawabnya. Lihat bagian 1.3 dan 1.7.

</details>

**4. Skenario keputusan.** Retainer menawarkan menjalankan KAPE sendiri di laptop Dewi hari Senin sebagai bagian dari engagement. Respons mana yang paling tepat?

- A. Setujui, karena KAPE gratis dan dipakai di mana-mana.
- B. Sampaikan bahwa lisensi PT JAB hanya untuk pengguna terdaftarnya, dan menurut FAQ resmi sejak 1 Januari 2026 KAPE tidak lagi tersedia untuk penggunaan di jaringan pihak ketiga atau engagement berbayar; koleksi dijalankan tim internal PT JAB lalu hasilnya diserahkan, atau retainer memakai alat dengan lisensi yang jelas, dan minta Legal memastikan.
- C. Larang semua pemakaian KAPE di PT JAB, termasuk oleh tim internal.

<details><summary>Jawaban</summary>

B. Tim internal memakai KAPE di bawah Enterprise License PT JAB, sedangkan pemakaian oleh retainer di laptop PT JAB dalam engagement berbayar tidak tercakup lisensi itu dan masuk kategori yang menurut FAQ tidak lagi tersedia. A keliru karena KAPE tidak gratis untuk tujuan bisnis menurut EULA, dan mengabaikan perubahan 2026 untuk pihak ketiga. C keliru karena pemakaian internal di bawah lisensi yang dipegang PT JAB tetap sah. Lihat bagian 1.5.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Dimas Prasetyo (IC), dalam tiga kalimat, kenapa E14 tidak berisi `upd.ps1` dan kenapa itu bukan kegagalan.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Triage KAPE Selasa malam memakai daftar artefak standar yang sudah teruji, dan folder tempat penyerang menaruh `upd.ps1` tidak termasuk daftar itu, sehingga isinya tidak diambil; yang terkumpul adalah task yang menjalankannya serta catatan nama, ukuran, dan waktu file itu. Yoga mencatat keputusan ini malam itu juga, karena menambah daftar baru di laptop terkompromi tanpa diuji berisiko salah dan memori laptop sudah diambil lebih dulu. Isi file akan kita ambil dari image disk yang sedang dibuat hari ini, dan untuk kasus berikutnya kita siapkan daftar tambahan yang sudah diuji di lab."

Kesalahan yang sering muncul:
- Mengatakan "file itu tidak ditemukan", yang terdengar seperti file tidak ada.
- Menjelaskan cara kerja Targets dan compound target secara rinci, padahal IC butuh dampak dan rencana.
- Tidak menyebut kapan dan dari mana isi file akan didapat.

</details>

**6. Pertanyaan jebakan.** "`!EZParser` memproses semua yang dikumpulkan `!SANS_Triage`. Tidak ada CSV untuk scheduled task di hasilnya, jadi tidak ada task mencurigakan di E14." Benarkah?

<details><summary>Jawaban</summary>

Tidak. `!EZParser` hanya menjalankan module yang terdaftar di dalamnya (Amcache, AppCompatCache, EvtxECmd, MFTECmd, PECmd, RECmd, SrumECmd, dan lainnya), dan tidak satu pun memproses XML scheduled task. File `SysCacheUpdate` ada di koleksi dan harus dibaca langsung sebagai XML. Tidak adanya CSV menunjukkan batas parser, bukan isi koleksi. Lihat bagian 1.6 dan 2.5.

</details>

**7. Interview question (English).** "How do you use KAPE in an investigation, and what are its limits?"

<details><summary>Sample answer</summary>

"I treat KAPE as two separate jobs. On the host, I run Targets, usually a standard compound like SANS_Triage plus any case-specific target I've already tested, writing to external media in a VHDX container. That collection is evidence: I hash it, record the exact command line, and keep the copy log, which lists every file copied with its SHA-1 and whether it was read through raw access because it was locked. On a separate analysis workstation, I mount a working copy read-only and run Modules like EZParser to get CSVs. The limits are that KAPE only collects what the target list names, it doesn't read shadow copies unless I enable it, and it never captures unallocated space. So my write-up always separates three things: what was collected, what was not collected, and what was collected but showed nothing, and I use the copy log to prove which is which. I'd also check licensing: commercial use needs an enterprise license, and as of January 2026 the KAPE FAQ says it's no longer available for use on third-party networks or in paid engagements."

What makes this answer strong: it separates evidence from derived output, names the copy log as proof of scope, states concrete limits (target list, VSS off by default, no unallocated space), and shows awareness of the licensing constraints, including the 2026 change.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Kroll: Exploring KAPE's graphical user interface | https://www.kroll.com/en/publications/cyber/exploring-kapes-graphical-user-interface | primer (vendor) | diakses 2026-10-09; situs bisa menolak akses otomatis | Sedang-tinggi. gkape menampilkan command line |
| S2 | Eric Zimmerman tools (EZ Tools yang dijalankan Module) | https://ericzimmerman.github.io/ | primer | diakses 2026-10-09, dicek ulang 2026-10-16 | Tinggi. Versi 2026.5.0; CLI .NET 4.7.2 dan .NET 9; GUI hanya .NET 9 |
| S3 | KapeFiles (Targets/Modules komunitas) | https://github.com/EricZimmerman/KapeFiles | primer | diakses 2026-10-09, dicek ulang 2026-10-16 | Tinggi. Definisi `.tkape`/`.mkape`, `--sync` |
| S4 | Cyber Triage docs: Add KAPE output (!BasicCollection, !SANS_Triage, VHD/VHDX) | https://docs.cybertriage.com/en/latest/chapters/importing/kape.html | sekunder | diakses 2026-10-09 | Sedang. Compound target dan container; kini dikonfirmasi [S6][S13] |
| S5 | SANS ISC: KAPE (Kroll Artifact Parser and Extractor) | https://isc.sans.edu/diary/25258 | sekunder | diakses 2026-10-09 | Sedang. Konsep KAPE |
| S6 | KAPE documentation: Using KAPE (daftar switch) | https://raw.githubusercontent.com/EricZimmerman/KapeDocs/master/Pages/3.-Using-KAPE.md | primer (dokumentasi resmi) | diakses 2026-10-16 | Tinggi. `--tsource`, `--target`, `--tdest`, `--tflush`, `--tdd`, `--vss` (default false), `--vhd`/`--vhdx`/`--zip`, `--zv` (default true), `--msource`, `--module`, `--mdest`, `--mflush`, `--mef`, `--sync`, `--guids`, `--debug`/`--trace` |
| S7 | KAPE documentation: Log files | https://raw.githubusercontent.com/EricZimmerman/KapeDocs/master/Pages/4.-Log-files.md | primer (dokumentasi resmi) | diakses 2026-10-16 | Tinggi. Kolom copylog termasuk `SourceFileSha1` dan `DeferredCopy`; skiplog `Deduped`/`Excluded`; awalan `VSS` |
| S8 | KAPE documentation: Getting started | https://raw.githubusercontent.com/EricZimmerman/KapeDocs/master/Pages/2.-Getting-started.md | primer (dokumentasi resmi) | diakses 2026-10-16 | Tinggi. Hak Administrator, .NET 4.5.2+, dua fase, `Modules\bin`, `LongFileNames` |
| S9 | KAPE documentation: Targets | https://raw.githubusercontent.com/EricZimmerman/KapeDocs/master/Pages/2.1-Targets.md | primer (dokumentasi resmi) | diakses 2026-10-16 | Tinggi. Field `.tkape`, compound target, `!Local` dan `!Disabled` |
| S10 | KAPE documentation: Modules | https://raw.githubusercontent.com/EricZimmerman/KapeDocs/master/Pages/2.2-Modules.md | primer (dokumentasi resmi) | diakses 2026-10-16 | Tinggi. Field `.mkape`, variabel, lokasi executable, subfolder per `Category` |
| S11 | KAPE documentation: Frequently asked questions | https://raw.githubusercontent.com/EricZimmerman/KapeDocs/master/Pages/50-Frequently-asked-questions.md | primer (dokumentasi resmi) | diperbarui 2026-02-11; diakses 2026-10-16 | Tinggi. Lisensi: tidak lagi tersedia untuk penggunaan komersial sejak 2026-01-01; `--mlist . --mdetail` |
| S12 | KAPE documentation: Change log | https://raw.githubusercontent.com/EricZimmerman/KapeDocs/master/Pages/0.-Changelog.md | primer (dokumentasi resmi) | entri terakhir 2022-12-22; diakses 2026-10-16 | Sedang-tinggi. Versi 1.3.0.2; `--sim` sejak 0.9.0.2. Changelog mungkin tidak mengikuti rilis terbaru |
| S13 | KapeFiles: `!SANS_Triage.tkape` | https://raw.githubusercontent.com/EricZimmerman/KapeFiles/master/Targets/Compound/!SANS_Triage.tkape | primer | diakses 2026-10-16 | Tinggi. Versi 1.5, daftar target aktif dan tiga target yang dikomentari |
| S14 | KapeFiles: folder Targets (`KapeTriage`, `!BasicCollection`, `CombinedLogs`, `EvidenceOfExecution`, `FileSystem`, `ScheduledTasks`, `Syscache`) | https://github.com/EricZimmerman/KapeFiles/tree/master/Targets | primer | diakses 2026-10-16 | Tinggi. Isi compound dan path target individual yang dirujuk Day ini |
| S15 | KAPE documentation: Tips and tricks | https://raw.githubusercontent.com/EricZimmerman/KapeDocs/master/Pages/60-Tips-and-tricks.md | primer (dokumentasi resmi, mengutip praktisi) | diakses 2026-10-16 | Sedang. Pengalaman praktisi bahwa SYSTEM menghilangkan galat akses; mount banyak VHDX |
| S16 | Microsoft Learn: Mount-DiskImage (Storage) | https://learn.microsoft.com/en-us/powershell/module/storage/mount-diskimage | primer (dokumentasi vendor) | dokumentasi Windows Server 2025, ms.date 2016-12-20; diakses 2026-10-16 | Tinggi. `-Access` (Unknown, ReadWrite, ReadOnly), default read-write untuk VHD |
| S17 | KapeFiles: `!EZParser.mkape` dan `MFTECmd.mkape` | https://raw.githubusercontent.com/EricZimmerman/KapeFiles/master/Modules/Compound/!EZParser.mkape | primer | diakses 2026-10-16 | Tinggi. Versi 1.5, daftar module; MFTECmd memproses `$Boot`, `$MFT`, `$J`, `$SDS` |
| S18 | Microsoft Learn: about_PSReadLine | https://learn.microsoft.com/en-us/powershell/module/psreadline/about/about_psreadline | primer (dokumentasi vendor) | PowerShell 7.6, ms.date 2026-03-18; diakses 2026-10-16 | Tinggi. Lokasi riwayat, filter kata sensitif |
| S19 | Microsoft Learn: about_Logging_Windows | https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows | primer (dokumentasi vendor) | PowerShell 7.6, ms.date 2026-01-18; diakses 2026-10-16 | Tinggi. Script Block Logging mencatat isi scriptblock interaktif maupun otomasi, event 4104; contoh channel `Microsoft-Windows-PowerShell/Operational` |
| S20 | Kroll: End User License Agreement (KAPE Solo Edition) | https://www.kroll.com/en/end-user-license-agreement | primer (vendor) | terakhir diubah 2020-06-04; diakses 2026-10-16 | Tinggi untuk ketentuan Solo: gratis untuk non-komersial; tujuan bisnis butuh Enterprise License. Tidak sejalan dengan FAQ 2026 [S11] soal penggunaan internal perusahaan |

**Catatan sumber:** nama flag, nilai default `--vss` dan `--zv`, kolom copylog, dan isi compound target kini dikonfirmasi dari dokumentasi resmi KAPE dan repo KapeFiles [S6][S7][S13][S14]. Yang masih perlu dicek di lab: pola nama file VHDX untuk compound target, lokasi persis copylog dan console log (di dalam atau di samping container), apakah VHDX mentah ikut tersimpan saat `--zv` aktif, nama folder kategori hasil Modules, nama kolom output EZ Tools, dan flag `--sim` (disebut changelog dan komentar `!SANS_Triage`, tidak ada di halaman daftar switch). Dua dokumen lisensi resmi tidak sejalan soal penggunaan internal perusahaan: EULA Solo 2020 [S20] mengarahkan semua tujuan bisnis ke Enterprise License, sedangkan FAQ 2026 [S11] menyebut penggunaan internal perusahaan gratis. Catatan ini memilih tafsir EULA yang lebih ketat karena EULA adalah dokumen perjanjian; cocokkan dengan EULA di paket KAPE yang kamu unduh dan dengan Legal sebelum dipakai untuk keputusan kontrak. Saran menjalankan sebagai SYSTEM [S15] adalah pengalaman praktisi. Penjelasan bahwa kegunaan 4104 bergantung pada Script Block Logging yang aktif berasal dari dokumentasi PowerShell 7.6 [S19]; perilaku Windows PowerShell 5.1 di host PT JAB perlu dicek dari kebijakan GPO. Semua isi PT JAB, termasuk waktu, jumlah file, nilai hash, isi task, dan hasil parse, adalah contoh fiktif.
