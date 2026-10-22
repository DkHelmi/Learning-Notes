---
day: 14
title: 'Akuisisi memori dan Volatility 3 dasar: capture RAM, format dan smear, symbol table, windows.info, dan daftar proses'
researched_on: 2026-10-22
versions_checked: 'Volatility 3 2.28.2 (17 Sep 2026, rilis stabil terbaru per 2026-10-22; subpaket windows.malware.* sejak 2.26.2; source pslist 3.0.1, psscan, pstree, cmdline, sessions, info di cabang develop); symbol pack windows.zip v0.0.1; WinPmem 4.0 RC2 (rilis berlabel Latest; 4.1 dev pre-release dengan driver test-signed); Windows 11 Enterprise 23H2 build 22631 (KB5027397); Credential Guard (Microsoft Learn ms.date 2026-04-27); Velociraptor 0.77.3 (Windows.Memory.Acquisition)'
---

# Day 14: Akuisisi memori dan Volatility 3 dasar

Cakupan: menilai kualitas image memori Windows yang diambil dari host hidup, menyiapkan Volatility 3 agar image terbaca, membaca profil image, dan membaca daftar proses (aktif, hierarki, yang sudah berakhir, command line, dan pemiliknya) sebagai titik awal analisis memori, lengkap dengan batas yang tidak bisa dijawab memori.

## Ide inti

Image memori adalah potret satu jendela waktu, bukan rekaman. Ia hanya berisi apa yang ada di RAM selama alat akuisisi membacanya, dan jendela itu tidak berlangsung satu detik: WinPmem membaca halaman fisik satu per satu dari alamat rendah ke tinggi selama beberapa menit, sementara sistem terus berjalan. Akibatnya ada dua hal yang harus kamu nilai sebelum percaya pada satu baris pun dari Volatility. Pertama, kualitas akuisisinya: alat dan cara, kapan mulai dan selesai, di mana hash dihitung, dan apa yang terjadi di host selama jendela itu (smear). Kedua, batas waktunya: memori hanya bisa menjawab tentang proses yang hidup atau baru saja berakhir saat jendela itu, sehingga image yang diambil Selasa siang tidak bisa membuktikan apa pun tentang Senin malam, baik ada maupun tidak ada. Setelah dua hal itu jelas, analisis dasar dimulai dengan urutan yang tetap: pastikan image terbaca dan dikenali (symbol table dan `windows.info`), lalu daftar proses dari dua arah (daftar aktif kernel dan pemindaian memori), lalu command line dan pemilik tiap proses, lalu tautkan ke event log dan artefak disk.

Kamu sudah mengenal pola ini dari NOC. Sebelum router agregasi yang bermasalah di-reboot, engineer mengambil crashinfo atau core dump, karena isi memorinya hilang saat reboot. Tetapi `show tech` panjang dari router yang masih melayani trafik juga bukan satu potret: `show interface` di awal dan `show ip route` di akhir diambil beberapa menit berbeda, dan counter yang terlihat tidak pernah ada bersamaan dalam satu detik. Engineer yang berpengalaman mencatat jam mulai dan selesai capture, membandingkan isinya dengan syslog di jam yang sama, dan tidak memakai crashinfo hari Selasa untuk menjelaskan flapping hari Senin. Image memori dibaca dengan disiplin yang sama, dan file MIB-nya adalah symbol table: tanpa itu, isi memori hanya byte tanpa arti.

```
host hidup (RAM berubah terus)
  |
  v
AKUISISI  alat + media terpisah + hak admin   (WinPmem / VM / agen / hiberfil-pagefile)
  |        catat mulai dan selesai = jendela smear ; hash di titik koleksi
  v
NILAI KUALITAS  hash cocok? | jendela berapa lama? | apa yang terjadi selama jendela?
  |             | apa yang TIDAK mungkin ada (sebelum jendela, sudah tertimpa)?
  v
TERBACA?  symbol table (GUID/age PDB kernel) -> windows.info (build, SystemTime)
  |
  v
PROSES    pslist (daftar aktif) + pstree (hierarki) <-> psscan (pindai: berakhir / tersembunyi)
  |       cmdline (apa persisnya) + sessions (sesi dan nama pengguna)
  v
TAUTKAN   PID + waktu dibuat + command line  <->  Sysmon 1 / 4688 / Task 200-201 / artefak disk
  |
  v
kalimat temuan: "di jendela X, ada/tidak ada ..." + yang tidak bisa dijawab memori
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan dan data pribadi sekitar 400 ribu pelanggan broadband di sistem billing. Kasusnya `INC-2026-019`: lampiran `Tagihan-Okt-2026.zip` (berisi `Tagihan-Okt-2026.js`) dari `billing@vendor-tagihan.example` dijalankan di tiga laptop staf penagihan. Di laptop `JKT-WS-0388` milik `andi.pratama` (Windows 11, Microsoft Defender for Endpoint, Sysmon), lampiran dibuka Senin 2026-10-12 pukul 16:05; `wscript.exe` (PID 5820) memunculkan `powershell.exe -enc` (PID 6136), yang menulis `C:\Users\andi.pratama\AppData\Roaming\SysCache\upd.ps1` dan mendaftarkan scheduled task `\SysCacheUpdate` yang berjalan setiap 15 menit di sesi Andi. Senin 23:40 skrip dari task mencari kata password di Documents dan membaca `export-tagihan.ps1`, yang menyimpan password akun service `svc_billing`; Selasa 02:14 akun itu dipakai untuk SSH ke `jkt-billing01`. Selasa 2026-10-13 pukul 12:42 sampai 12:52, Yoga Pratama (analyst L2 pemegang bukti) mengambil memori laptop itu dengan WinPmem di konsol (bukti `INC-2026-019-E01`). Memori dua laptop lain juga diambil Selasa: `BDG-WS-0142` milik `dewi.anggraini` oleh teknisi POP Bandung Fajar Nugraha (E08) dan `JKT-WS-0412` milik `rizky.saputra` oleh Yoga (E13). Ketiga image diserahkan ke retainer PT Forensik Digital Contoh. Kesimpulan retainer atas E01 hanya satu kalimat di ringkasan dua halaman: "tidak menemukan akses ke LSASS". Ketiga laptop sudah di-reimage, dan post-incident review (PIR) berlangsung Selasa 2026-10-27. Salah satu action item PIR: PT JAB harus punya kemampuan analisis memori internal. Rabu 2026-10-28 pukul 16:30, Yoga membuat salinan kerja `E01-W1` dari master setelah memverifikasi hash. Kamis 2026-10-29 pukul 09:00, Dimas Prasetyo (SOC lead, incident commander) menulis kepadamu di kanal `#inc-2026-019`:

> "Pagi. Sesuai action item PIR, mulai kasus ini kita baca memori sendiri. Sebelum kasus saya tutup, saya mau kesimpulan retainer soal E01, 'tidak menemukan akses ke LSASS', kita cek sendiri, karena laporan mereka cuma ringkasan dua halaman tanpa cara kerja. Hari ini cukup dasarnya. Pertama, tiga image memori laptop itu (E01, E08, E13) kualitasnya bagaimana: diambil pakai apa, hash-nya beres, dan apa yang tidak mungkin ada di dalamnya karena diambil Selasa padahal infeksinya Senin? Kedua, E01 bisa dibaca alat kita, dan itu image dari Windows apa? Ketiga, waktu E01 diambil, proses apa saja yang jalan, dan mana punya Andi, mana penyerang, mana punya Yoga? Keempat, apa persisnya yang dijalankan penyerang saat itu? Kelima, proses yang sudah selesai sebelum diambil masih bisa kita lihat tidak? Terakhir, kalimat retainer itu boleh kita pakai sejauh mana, dan apa yang memang tidak bisa dijawab memori? Jawabannya saya tunggu sebelum jam 15:00."

Pesan itu memuat enam pertanyaan:

1. Bagaimana kualitas akuisisi E01, E08, dan E13: alat, cara, hash, dan apa yang tidak mungkin tertangkap?
2. Apakah E01 terbaca oleh alat PT JAB, dan image itu dari Windows apa?
3. Proses apa yang berjalan saat E01 diambil, dan milik siapa (pengguna, penyerang, responder)?
4. Apa persisnya yang dijalankan penyerang saat itu?
5. Apakah proses yang sudah berakhir masih bisa dilihat?
6. Sejauh mana kalimat retainer boleh dipakai, dan apa yang tidak bisa dijawab memori?

Pertanyaan 1 dijawab di bagian 1.1 dan 1.2, pertanyaan 2 di bagian 1.3 dan 1.4, pertanyaan 3 di bagian 1.5 dan 1.7, pertanyaan 4 di bagian 1.7, pertanyaan 5 di bagian 1.6, dan pertanyaan 6 di bagian 1.8. Bagian 2 berisi perintah, keluaran ilustrasi, tabel korelasi, dan jawaban tertulis yang kamu kirim ke Dimas.

**Kapan relevan:** setiap kali image memori Windows diambil atau diterima, terutama saat proses, command line, atau kode yang hanya hidup di RAM menentukan kesimpulan, saat kesimpulan pihak lain atas sebuah image perlu diverifikasi, dan saat kamu harus memutuskan alat dan cara akuisisi untuk host yang masih menyala.
**Kapan bukan jawaban:** saat pertanyaannya tentang kejadian sebelum jendela akuisisi (pakai event log, artefak eksekusi, dan file system), saat host sudah mati dan tidak ada image (memori tidak bisa diambil ulang), dan saat yang dibutuhkan adalah analisis lanjutan: handle ke LSASS, injeksi kode dengan `windows.malware.malfind`, DLL, dan dump proses dibahas di Day 15, sedangkan koneksi jaringan dan persistence di memori dibahas di Day 16.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (order of volatility, hash bukti, salinan kerja, chain of custody, symbol table, pembekuan versi, Logon ID, logon type, Sysmon, jejak responder, scheduled task) tidak diulang. Tabel berikut hanya memuat istilah baru Day ini. Kolom padanan memakai analogi NOC dan SOC yang sama di semua Day.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Image memori raw | Salinan isi memori fisik di mana offset di file sama dengan alamat fisik | Core dump atau crashinfo router sebelum reboot |
| Memory range dan padding | Rentang alamat fisik yang benar-benar RAM; celah di antaranya diisi nol di file raw supaya offset tetap sejajar | Peta memori perangkat: region I/O dilewati, tetapi penomoran alamat tetap berjalan |
| Smear | Ketidakkonsistenan di image karena halaman dibaca pada waktu berbeda selama sistem berjalan | `show tech` panjang dari router yang sedang melayani trafik: tiap bagian diambil pada menit berbeda |
| `EPROCESS` | Struktur kernel yang mewakili satu proses (PID, induk, waktu dibuat dan berakhir, sesi) | Satu baris entri di tabel sesi aktif |
| `pslist` | Daftar proses dengan mengikuti daftar berantai proses aktif di kernel | `show users`: tabel sesi yang sedang terdaftar |
| `psscan` (pool scanning) | Pemindaian memori untuk sisa struktur proses, termasuk yang sudah berakhir atau dilepas dari daftar | Mencari sisa record sesi di buffer accounting yang belum tertimpa |
| PEB dan command line | Blok proses di memori pengguna yang menyimpan command line dan environment variable | Baris perintah persis di accounting TACACS |
| Session ID | Nomor sesi Windows: 0 untuk service, 1 dan seterusnya untuk sesi logon interaktif | Nomor line console atau VTY tempat sesi berjalan |
| `SystemTime` (`windows.info`) | Jam sistem yang terbaca dari satu halaman memori (`KUSER_SHARED_DATA`) | Hasil `show clock` pada satu saat di tengah capture |
| Credential Guard dan `LsaIso.exe` | Fitur yang memindahkan rahasia kredensial domain ke lingkungan terisolasi berbasis virtualisasi; `LsaIso.exe` adalah proses terisolasinya | Kunci rahasia yang disimpan di modul keamanan terpisah, bukan di running-config |

### 1.1 Akuisisi memori dan memilih sumber memori

Pertanyaan pertama Dimas dimulai dari "diambil pakai apa". Jawabannya menentukan apa yang mungkin ada di image, apa yang ikut berubah karena pengambilan itu, dan jejak apa yang ditinggalkan responder di host.

Memori fisik diakuisisi dengan alat yang membaca RAM ke file image [S3]. Tabel berikut adalah alat yang umum di Windows; baca kolom "Catatan" untuk tahu kenapa PT JAB memakai WinPmem.

| Alat | Catatan |
|---|---|
| WinPmem | Open source; dipakai luas; bagian ekosistem Velociraptor. `winpmem_mini_x64.exe` adalah imager sederhana yang hanya menghasilkan raw [S3] |
| Magnet RAM Capture | Gratis |
| FTK Imager | Gratis; bisa capture memori dan disk |
| DumpIt (Comae) | Gratis; cepat |

WinPmem bekerja dengan memuat driver kernel. Executable `winpmem_mini` membawa driver 32-bit dan 64-bit sekaligus, memuat yang sesuai secara otomatis, dan membongkar driver setelah akuisisi selesai [S3]. Pemuatan driver itu yang menghasilkan event 7045 bertipe kernel driver (dan 4697 bila auditnya aktif) di host, jejak responder yang sudah dibahas di Day 05 bagian 1.4. Laporan pengguna di issue tracker WinPmem menunjukkan driver diekstrak ke file sementara berawalan `pme` dengan ekstensi `.tmp` dan service bernama `pmem` [S21]; ini sumber komunitas, jadi nama service dan lokasi file driver di versi toolkit PT JAB dicocokkan di lab sebelum dipakai sebagai pembeda.

Prinsip akuisisi yang berlaku untuk semua alat (Day 01 bagian 1.3):

- Memori diambil dari sistem hidup, karena sistem mati tidak punya memori. Akuisisi itu sendiri mengubah sedikit memori: alat berjalan, driver dimuat, buffer file ditulis. Ini trade-off yang disadari dan dicatat.
- Image disimpan ke media terpisah, bukan ke disk host yang sedang diinvestigasi. Menulis 18 GB ke disk korban bisa menimpa ruang yang belum dialokasikan, tempat sisa file terhapus berada [S20].
- Hash image dihitung segera, idealnya di titik koleksi (Day 01 bagian 1.4).
- Waktu mulai dan selesai, alat, versi, akun, dan host dicatat di case notes, karena rentang mulai sampai selesai adalah jendela tempat smear bisa terjadi (bagian 1.2).
- Order of volatility: bila memori dan disk sama-sama relevan, memori diambil lebih dulu karena reboot menghapusnya.

Tidak semua kasus memberi kesempatan akuisisi live. Tabel berikut adalah pilihan sumber memori yang realistis; baca kolom "Kekurangan" karena itulah yang harus tertulis di case notes saat memilih.

| Sumber | Kapan tersedia | Kelebihan | Kekurangan |
|---|---|---|---|
| Akuisisi live dengan alat dari USB | Host masih hidup dan bisa dijangkau fisik | Paling lengkap untuk keadaan saat ini | Smear; alat meninggalkan jejak; butuh hak admin |
| Berkas memori VM (`.vmem`, file state snapshot) | Host adalah VM | Bebas smear; tidak menjalankan apa pun di guest | Butuh akses ke hypervisor; format bergantung platform |
| Akuisisi lewat agen (misalnya Velociraptor menjalankan WinPmem) | Agen sudah terpasang | Jarak jauh, tercatat di server | Transfer image besar lewat jaringan |
| `hiberfil.sys` dan `pagefile.sys` | Dari image disk, juga dari host mati | Ada walaupun host sudah dimatikan | Hanya sebagian memori, waktunya lebih lama; dukungan parsing perlu dicek per versi |

Urutan pertimbangannya: bila host masih hidup dan memori relevan, akuisisi live atau file memori VM lebih dulu. Bila host sudah dimatikan, jangan langsung menyerah pada memori; berkas hibernasi dan pagefile di image disk bisa memuat fragmen proses dan string yang berguna, walaupun tidak bisa dianalisis selengkap image RAM. Untuk akuisisi lewat agen, artifact Velociraptor `Windows.Memory.Acquisition` memakai driver WinPmem bawaan, menulis driver ke `C:\Windows\Temp\winpmem.sys` secara bawaan, nama service-nya bisa diganti lewat parameter `ServiceName`, dan menawarkan kompresi S2, Snappy, atau Gzip; dokumentasinya sendiri mengingatkan bahwa image memori rentan smear sehingga akuisisi harus cepat [S19].

Hal praktis yang sering menentukan berhasil tidaknya akuisisi live: ukuran media tujuan minimal sebesar ukuran file raw (yang bisa lebih besar dari RAM, bagian 1.2) ditambah ruang untuk hash dan catatan; alat dijalankan dari media eksternal, bukan disalin ke disk korban; dan waktu mulai dan selesai akuisisi dicatat.

Di `INC-2026-019`, ketiga image laptop diambil dengan cara live dari USB, dan pilihan itu tepat untuk hari Selasa: Velociraptor baru dipasang Kamis 2026-10-15 (Day 04), dua dari tiga laptop tidak punya EDR, dan ketiganya laptop fisik, bukan VM. Yang berbeda adalah siapa dan dalam kondisi apa. E01 diambil Yoga di konsol `JKT-WS-0388` lewat Switch user dengan akun admin lokal khusus IR `ir-admin`, saat laptop belum diisolasi (isolasi Selasa 16:00). E08 diambil Fajar Nugraha, teknisi POP yang bukan analyst forensik, di `BDG-WS-0142` dengan panduan telepon Yoga, juga sebelum isolasi pukul 16:00. E13 diambil Yoga di `JKT-WS-0412` dengan elevasi UAC `ir-admin` di sesi Rizky yang masih terbuka, setelah port switch laptop itu dimatikan pukul 17:20. Perbedaan itu akan muncul lagi di bagian 2.1, karena misalnya E13 tidak mungkin memuat koneksi C2 yang aktif.

### 1.2 Format raw, ukuran file, hash, dan smear

Pertanyaan pertama Dimas juga menanyakan "hash-nya beres" dan "apa yang tidak mungkin ada". Ketiganya dijawab dengan memahami bagaimana file raw dibentuk dan berapa lama pembentukannya.

**Format dan ukuran.** Image raw adalah salinan byte demi byte memori fisik; alat seperti WinPmem menyimpannya dalam format yang langsung bisa dibaca Volatility [S20]. Memori fisik sebuah laptop tidak berupa satu blok utuh. Alat akuisisi lebih dulu menanyakan peta memori ke sistem operasi (di Windows lewat API `MmGetPhysicalMemoryRanges`), karena sebagian rentang alamat dicadangkan untuk perangkat seperti PCI dan BIOS, dan membaca rentang itu bisa membuat perangkat bereaksi atau sistem tidak stabil [S16]. Celah di antara rentang dipakai prosesor dan chipset dan tidak dikelola memory manager Windows [S20]. Supaya offset di file raw tetap sama dengan alamat fisik, celah itu diisi nol (padding). Akibatnya ukuran file raw mengikuti alamat fisik tertinggi, bukan jumlah RAM. Pada laptop 16 GB, sebagian RAM di bawah 4 GB dipindah ke atas 4 GB untuk memberi ruang alamat bagi perangkat, sehingga file raw bisa sekitar 2 GB lebih besar dari RAM. Ukuran file yang lebih besar dari RAM karena alasan ini normal; yang perlu dicocokkan adalah ukuran file dengan rentang yang dicetak alat saat akuisisi (bagian 2.1). Apakah versi WinPmem di toolkit mengisi celah dengan nol atau menulis format lain dicek di lab dengan membandingkan ukuran file dan daftar rentangnya.

**Hash.** Hash membuktikan file tidak berubah sejak hash dihitung, bukan bahwa isinya konsisten atau lengkap (Day 01 bagian 1.4). Untuk image memori, titik hitung hash penting: hash yang dihitung di host oleh responder satu menit setelah akuisisi menutup celah perjalanan USB; hash yang dihitung 40 menit kemudian di workstation SOC meninggalkan celah yang hanya ditutup oleh catatan custody USB itu.

**Smear.** Alat akuisisi software berjalan di dalam sistem yang terus bekerja. Selama file ditulis, proses baru muncul, koneksi masuk ditangani, dan file dibaca dan ditulis [S16]. Semua alat yang diketahui membaca halaman secara berurutan dari alamat fisik rendah ke tinggi [S16]. Jadi halaman di awal file adalah keadaan memori di menit pertama, dan halaman di akhir file adalah keadaan di menit terakhir. Pagani, Fedorov, dan Balzarotti (2019) menyebut hasilnya potret kabur dari target yang bergerak, dan menunjukkan bahwa ketidakkonsistenan seperti ini sering terjadi dan bisa menyesatkan analisis secara halus; mereka juga mengutip temuan sebelumnya bahwa sekitar satu dari lima akuisisi menghasilkan dump yang tidak bisa dipakai [S16]. Contoh bentuknya: sebuah proses dibuat setelah halaman berisi daftar proses tetangganya sudah dibaca, sehingga daftar berantai tidak menunjuk ke proses itu; atau sebuah struktur menunjuk ke halaman yang sudah dipakai ulang untuk hal lain.

Smear menyebabkan sebagian plugin gagal atau memberi hasil aneh. Ini keterbatasan inheren akuisisi live; image dari VM snapshot, yang membekukan state, lebih bersih untuk belajar. Untuk image kasus, smear tidak membuat image tidak berguna, tetapi mengubah cara membacanya: setiap struktur diperlakukan sebagai keadaan pada saat halamannya dibaca, di suatu titik di dalam jendela akuisisi. Konsep yang membantu adalah konsistensi waktu: sekumpulan halaman konsisten bila ada satu saat di dalam jendela ketika semua isinya hidup berdampingan [S16]. Seluruh image hampir tidak pernah konsisten, tetapi daftar proses yang konsisten sering sudah cukup untuk pertanyaan dasar.

Di E01, jendelanya Selasa 12:42:07 sampai 12:52:41 WIB, sepuluh menit 34 detik. Dalam jendela itu task `\SysCacheUpdate` menjalankan `powershell.exe` baru pukul 12:51:02. Proses itu ada di image karena halaman struktur prosesnya dibaca setelah 12:51:02, sementara jam sistem yang dibaca `windows.info` berasal dari halaman yang dibaca sekitar 12:47 (bagian 2.2). Image yang "lebih tua" dari salah satu prosesnya adalah tanda smear yang paling mudah dijelaskan ke orang lain.

**Apa yang tidak mungkin ada.** Image hanya menangkap jendela akuisisi. Proses yang berakhir lama sebelumnya hanya muncul bila sisa strukturnya belum tertimpa (bagian 1.6), dan isi memori proses yang sudah berakhir hampir selalu hilang. E01 diambil sekitar 20,5 jam setelah lampiran dibuka. Rantai Senin sore (`wscript.exe` 5820 dan `powershell.exe -enc` 6136) dan run task Senin 23:36 yang membaca `export-tagihan.ps1` berlangsung belasan jam sebelumnya di laptop yang terus bekerja, jadi ketiadaannya di E01 adalah hasil yang diharapkan, bukan bukti tidak terjadi.

### 1.3 Volatility 3 dan symbol table

Pertanyaan kedua Dimas ("bisa dibaca alat kita") dijawab dulu di tingkat alat. Volatility 3 tidak bisa membaca image Windows tanpa symbol table yang cocok dengan kernel di image, dan `jkt-dfir02` tidak punya internet.

Volatility 3 (2.28.2) berbeda mendasar dari Volatility 2 [S1]:

- **Tidak ada profil.** Volatility 2 butuh profil OS yang dipilih manual; Volatility 3 memakai symbol table (Intermediate Symbol Format, ISF) yang mencocokkan struktur kernel OS.
- Untuk Windows, Volatility 3 memakai symbol yang dibuat dari PDB Microsoft; biasanya ditemukan atau diunduh otomatis untuk versi Windows yang didukung.
- `windows.info` memverifikasi image terbaca dan menampilkan versi OS, yang menentukan apakah symbol cocok.

Bila symbol tidak cocok (OS sangat baru atau image rusak), plugin gagal. Menjalankan `windows.info` lebih dulu memastikan fondasi sebelum analisis.

Cara kerjanya untuk Windows perlu dipahami karena menentukan apakah workstation offline bisa jalan [S1]:

- Symbol table disimpan sebagai berkas JSON (boleh terkompresi `.json.gz`/`.json.xz`, atau dikemas dalam ZIP) di direktori `volatility3/symbols`, dengan subdirektori `windows`.
- Volatility membaca GUID dan age PDB kernel dari image, lalu mencari berkas symbol yang cocok. Bila tidak ada, ia mengunduh PDB dari Microsoft Symbol Server, mengonversinya ke JSON, dan menyimpannya.
- Pemetaan symbol di-cache di `~/.cache/volatility3` (atau `$XDG_CACHE_HOME/volatility3`). Cache ini yang membuat run kedua jauh lebih cepat daripada run pertama. Lokasi bawaan cache tidak bisa diubah lewat konfigurasi biasa, tetapi CLI menyediakan opsi `--cache-path` dan `--clear-cache` [S1][S13].

Implikasinya: workstation analisis yang terisolasi dari internet tidak bisa mengunduh PDB. Di `jkt-dfir02`, symbol pack Windows (`windows.zip` v0.0.1) sudah diverifikasi hash-nya dan ditaruh di direktori symbols sejak Kamis 2026-10-15 (Day 02 bagian 2.5). Bila build kernel di image tidak tercakup pack itu, jalan yang sah adalah jendela proxy khusus ke Microsoft Symbol Server, atau mengunduh PDB di mesin lain lalu mengonversinya dengan `pdbconv.py` bawaan Volatility. Saat symbol tidak ditemukan, kode Volatility mencatat pesan info yang menyebut nama PDB dan GUID yang dicari beserta saran perintah `pdbconv.py` [S14], jadi baca log dengan `-v` sebelum menebak. Catat sumber symbol di case notes, karena symbol yang salah menghasilkan offset struktur yang salah dan hasil plugin yang menyesatkan.

CLI Volatility punya opsi `--offline` untuk tidak mencari file JSON tambahan secara online [S13]. Kode pengunduhan PDB yang diperiksa tidak memeriksa opsi itu sebelum mencoba mengunduh [S14], jadi jangan menganggap `--offline` sebagai pengaman isolasi; pengamannya tetap tidak adanya rute internet dari `jkt-dfir02`. Perilaku `--offline` di versi-mu dicek di lab.

### 1.4 Sintaks Volatility 3 dan `windows.info`: profil image

Pertanyaan kedua Dimas yang kedua ("image dari Windows apa") dijawab oleh plugin pertama yang selalu dijalankan.

Sintaks dasarnya:

```
vol [opsi global] -f <image> <plugin> [opsi plugin]
python3 vol.py [opsi global] -f <image> <plugin> [opsi plugin]
```

- `vol` adalah perintah yang dipasang `pip install volatility3` (cara PT JAB, Day 02 bagian 2.5); `python3 vol.py` dipakai bila Volatility dijalankan dari source.
- Opsi global ditulis sebelum nama plugin: `-f` image, `-r` renderer (bawaan `quick`; `csv` dan lainnya untuk diolah ulang), `-o` direktori output untuk file yang dibuat plugin, `-q` tanpa progress, `-l` menulis log ke file, `-v` menambah detail log, `-s` direktori symbol tambahan [S13].
- Plugin dipanggil dengan nama modul, misalnya `windows.pslist`, atau bentuk penuh `windows.pslist.PsList` [S2].
- Opsi plugin ditulis setelah nama plugin, misalnya `--pid 12408` untuk memfilter proses tertentu [S7].

Catatan versi penting: sebagian plugin pindah ke subpaket `windows.malware.*` (misalnya `windows.malware.malfind`, `windows.malware.psxview`, `windows.malware.hollowprocesses`) [S2]. Halaman rilis mencatat pemindahan ini di 2.26.2, dengan nama lama masih berjalan sambil menampilkan pengingat deprecation dan dijadwalkan dihapus sekitar satu tahun kemudian [S6]. Nama plugin bisa berubah antar versi; selalu cek `vol -h` untuk daftar plugin di versi-mu. Plugin yang dipakai Day ini (`windows.info`, `windows.pslist`, `windows.pstree`, `windows.psscan`, `windows.cmdline`, `windows.sessions`) masih berada langsung di `windows.*` [S2].

`windows.info` adalah plugin pertama yang dijalankan [S2]:

- Menampilkan alamat kernel, DTB, file symbol yang dipakai, arsitektur, lapisan (layer) yang dibangun, versi dari `KdVersionBlock`, jumlah prosesor, `SystemTime`, `NtSystemRoot`, `NtProductType`, dan versi dari header PE kernel [S12].
- Memverifikasi symbol cocok; bila gagal, image atau symbol bermasalah.
- Waktu di image (`SystemTime`) berguna untuk menautkan snapshot ke timeline.

Tanpa `windows.info` yang sukses, plugin lain kemungkinan gagal; ini gerbang analisis memori. Tiga baris di keluarannya yang paling berguna untuk pertanyaan Dimas:

- **`Symbols`:** file symbol yang dipakai. Ini yang dicatat di case notes sebagai bukti bahwa image dibaca dengan symbol yang cocok, dan dari sumber mana symbol itu berasal.
- **`SystemTime`:** dibaca dari struktur `_KUSER_SHARED_DATA` pada alamat tetap [S12]. Karena struktur itu ada di satu halaman fisik, waktunya adalah jam sistem pada saat halaman itu dibaca, di suatu titik di dalam jendela akuisisi, bukan waktu "image diambil". Bandingkan dengan waktu mulai dan selesai di case notes: bila `SystemTime` jatuh di dalam jendela, jam host dan catatan responder konsisten; bila jauh di luar, curigai jam host atau catatan yang salah.
- **`Major/Minor` dan `NtMajorVersion`:** versi kernel. `Major/Minor` berasal dari `KdVersionBlock`, sedangkan `NtMajorVersion` dan `NtMinorVersion` dari `_KUSER_SHARED_DATA` [S12]. Untuk Windows 11 23H2, ingat bahwa 22H2 dan 23H2 berbagi inti sistem operasi dengan set file sistem yang identik, dan 23H2 diaktifkan lewat enablement package di atas update bulanan 22H2 [S18]. Karena itu nama build pada metadata kernel atau file symbol bisa menyebut 22621 walaupun `winver` di laptop menyebut 22631. Pencocokan symbol memakai GUID dan age PDB, bukan nomor build, jadi perbedaan ini tidak membuat symbol salah; cek di lab angka mana yang muncul di `Major/Minor` untuk image 23H2.

### 1.5 Daftar proses aktif: `pslist`, `pstree`, dan baseline Windows

Pertanyaan ketiga Dimas ("proses apa saja yang jalan") dijawab dari daftar proses aktif, lalu dibaca terhadap baseline proses Windows yang normal supaya yang janggal terlihat.

Tiga cara mendaftar proses, dengan perbedaan penting [S2]. Tabel berikut membandingkannya; baca kolom "Keterbatasan" karena kolom itulah yang menentukan kapan dua plugin harus dibandingkan.

| Plugin | Cara kerja | Kekuatan | Keterbatasan |
|---|---|---|---|
| `windows.pslist` | Mengikuti daftar proses aktif kernel (linked list) | Cepat, akurat untuk proses aktif | Proses yang di-unlink (disembunyikan) tidak muncul |
| `windows.pstree` | Seperti pslist tetapi menampilkan hierarki parent-child | Melihat relasi proses | Sama dengan pslist untuk cakupan |
| `windows.psscan` | Memindai memori untuk struktur proses (pool scanning) | Menemukan proses tersembunyi/terminated | Bisa menampilkan proses mati; lebih banyak noise |

Di Volatility 3 2.28.x, `windows.pslist` mengeluarkan kolom PID, PPID, ImageFileName, Offset(V), Threads, Handles, SessionId, Wow64, CreateTime, ExitTime, dan File output; opsi `--pid` membatasi ke PID tertentu, `--physical` menampilkan offset fisik alih-alih virtual, dan `--dump` mengekstrak proses yang terdaftar [S7]. `windows.pstree` membangun pohon berdasarkan PPID, dan opsi `--pid`-nya ikut menyertakan leluhur dan keturunan proses yang dipilih [S9]. Di versi ini `pstree` juga menambahkan kolom Audit, Cmd, dan Path, yang berisi nilai "tidak tersedia" bila datanya tidak terbaca [S9]. Proses yang induknya tidak ada di daftar ditampilkan sebagai akar pohon, dengan PPID tetap berisi nomor induk yang hilang [S9]. Ini penting: `explorer.exe` atau `csrss.exe` yang muncul sebagai akar bukan berarti tanpa induk, tetapi induknya sudah berakhir.

Membaca daftar proses butuh baseline proses Windows yang normal. Tabel berikut adalah pola yang stabil di Windows 10/11; baca kolom "Tanda janggal", karena itulah yang dicari di keluaran.

| Proses | Parent normal | Jumlah instance | Tanda janggal |
|---|---|---|---|
| `smss.exe` | `System` | Satu yang bertahan (instance sesi berakhir setelah tugasnya) | Path selain `System32` |
| `csrss.exe` | `smss.exe` instance sesi yang sudah keluar | Satu per sesi | Parent yang masih hidup; path selain `System32` |
| `wininit.exe` | `smss.exe` instance yang sudah keluar | Satu | Lebih dari satu |
| `winlogon.exe` | `smss.exe` instance sesi yang sudah keluar | Satu per sesi interaktif | Parent yang masih hidup |
| `services.exe` | `wininit.exe` | Satu | Parent lain |
| `lsass.exe` | `wininit.exe` | Satu | Lebih dari satu, atau punya proses anak |
| `LsaIso.exe` | `wininit.exe` | Satu, hanya bila Credential Guard aktif | Ada tanpa VBS aktif; path selain `System32` |
| `svchost.exe` | `services.exe` | Banyak | Parent selain `services.exe`; path selain `System32`/`SysWOW64` |
| `explorer.exe` | `userinit.exe` yang sudah keluar | Satu per sesi user | Path selain `C:\Windows` |

Karena `userinit.exe` keluar setelah menjalankan shell, `explorer.exe` biasanya tampil tanpa parent yang hidup. Itu normal. Sebaliknya, `svchost.exe` di bawah `explorer.exe` atau `lsass.exe` kedua adalah anomali yang harus dijelaskan. Nama yang mirip (`scvhost.exe`, `lsas.exe`) juga layak dicari karena penyamaran sederhana masih sering dipakai.

Satu baris di baseline itu menjawab sebagian kalimat retainer. Credential Guard memakai virtualization-based security (VBS) untuk mengisolasi hash password NTLM, Kerberos TGT, dan kredensial domain yang disimpan aplikasi, sehingga hanya perangkat lunak sistem yang istimewa yang bisa mengaksesnya; malware dengan hak admin di sistem operasi tidak bisa mengekstrak rahasia yang dilindungi VBS [S17]. Sejak Windows 11 22H2, Credential Guard aktif secara bawaan di perangkat yang memenuhi syarat lisensi (Enterprise atau Education) serta syarat hardware dan software, dan tidak dikonfigurasi untuk menonaktifkannya; aktivasi bawaan ini tanpa UEFI lock [S17]. Proses terisolasinya bernama `LSAIso.exe` di dokumentasi Microsoft [S17] dan tercatat sebagai `LsaIso.exe` di struktur proses. Jadi `lsass.exe` dan `LsaIso.exe` yang berjalan berdampingan di bawah `wininit.exe` bukan dua LSASS, melainkan tanda Credential Guard aktif. Dua batasnya ditulis sekalian: Credential Guard tidak melindungi database SAM untuk akun lokal [S17], dan proses dengan hak pengguna biasa memang tidak bisa membuka LSASS untuk dibaca. Keduanya relevan untuk kalimat retainer (bagian 1.8).

Di E01, `pslist` menunjukkan 184 proses aktif. Yang relevan untuk Dimas ada di tiga sesi: sesi 0 (service, termasuk `svchost.exe` PID 1948 yang menjalankan layanan Task Scheduler, sensor Sysmon, Defender, dan EDR), sesi 1 (Andi: `explorer.exe`, OneDrive, Outlook, Excel, dan satu `powershell.exe` dari task), dan sesi 2 (Yoga: `explorer.exe`, `cmd.exe`, dan WinPmem). Daftar lengkap ada di bagian 2.3 dan pohonnya di bagian 2.4.

### 1.6 `psscan`: proses yang sudah berakhir, yang disembunyikan, dan kenapa ia bukan mesin waktu

Pertanyaan kelima Dimas ("proses yang sudah selesai masih bisa kita lihat") dijawab oleh pemindaian memori, dengan satu peringatan yang paling sering dilupakan.

`windows.psscan` tidak mengikuti daftar proses; ia memakai pool scanner untuk mencari struktur proses berdasarkan tag pool (`Proc` dan varian yang ditandai) di seluruh image [S8]. Kolomnya sama dengan `pslist`, termasuk ExitTime, dan kodenya tidak menyaring proses yang sudah berakhir, sehingga proses yang selesai muncul dengan ExitTime terisi [S8]. Di versi ini offset bawaan `psscan` adalah offset virtual (kolom `Offset(V)`), dan opsi `--physical` menampilkan offset fisik [S8]. Objek yang alamatnya tidak valid dicatat ke log dan dilewati [S8].

Teknik forensik: bandingkan pslist dan psscan. Proses yang muncul di psscan tetapi tidak di pslist bisa berarti disembunyikan (unlinked) atau sudah berakhir. Ini dasar deteksi proses tersembunyi; konfirmasi dengan `windows.malware.psxview` dilakukan di Day 15 sebelum menyimpulkan penyembunyian. Untuk membedakan dua kemungkinan itu di tingkat dasar, lihat ExitTime: proses berakhir punya ExitTime terisi dan biasanya Threads nol; proses yang disembunyikan tetapi masih hidup tidak punya ExitTime.

Peringatannya: psscan bukan mesin waktu. Ketika proses berakhir, memorinya dikembalikan ke pool dan bisa dipakai ulang kapan saja. Struktur yang ditemukan psscan hanyalah sisa yang kebetulan belum tertimpa. Dua akibatnya:

- **Ditemukan tidak bergantung umur.** Di E01, psscan menemukan `svchost.exe` yang berakhir Senin pagi pukul 08:12, tetapi tidak menemukan `wscript.exe` dan `powershell.exe -enc` dari Senin sore, yang lebih muda. Sisa yang bertahan ditentukan oleh pola pemakaian ulang memori, bukan oleh waktu.
- **Tidak ditemukan tidak berarti tidak pernah ada.** Ketiadaan `wscript.exe` 5820 dan `powershell.exe` 6136 di pslist maupun psscan tidak membantah event log E15, yang mencatat keduanya dengan PID, induk, dan command line (Day 05 bagian 2.4). Laptop itu sudah bekerja lebih dari 20 jam sejak keduanya berakhir, termasuk sekitar 80 run task yang masing-masing membuat dan mengakhiri proses PowerShell.

Psscan di E01 menemukan empat proses berakhir yang tidak ada di pslist (bagian 2.5): run task pukul 12:36:02 yang selesai 12:36:44, instance `smss.exe` dan `userinit.exe` yang dibuat saat Yoga masuk lewat Switch user, dan `svchost.exe` Senin pagi. Tiga yang pertama berakhir kurang dari 20 menit sebelum akuisisi.

### 1.7 Command line dan pemilik proses: `cmdline` dan `sessions`

Pertanyaan ketiga (bagian "milik siapa") dan keempat Dimas ("apa persisnya") dijawab dari dua plugin yang membaca memori pengguna setiap proses.

`windows.cmdline` membaca command line dari struktur `_PEB` proses, tepatnya `ProcessParameters.CommandLine`, dan mengeluarkan kolom PID, Process, dan Args [S10]. Ia memakai pslist untuk mendaftar proses, jadi proses yang hanya ditemukan psscan tidak ikut diproses [S10]. Bila halaman PEB tidak terbaca (ter-swap, ter-page out, atau proses sudah berakhir), baris tetap muncul tetapi kolom Args berisi nilai tidak terbaca, dan alasan rincinya hanya muncul di log debug [S10]. Command line krusial karena mengungkap apa yang dijalankan, yang tidak terlihat dari nama proses saja: `powershell.exe` bisa berarti administrator yang bekerja, skrip login, atau loader penyerang.

Padukan dengan pstree: proses anak yang mencurigakan plus command line-nya menceritakan aktivitas.

`windows.sessions` mendaftar proses beserta Session ID, Session Type, PID, nama proses, User Name, dan waktu dibuat [S11]. Session ID diambil dari struktur proses, tetapi User Name dan Session Type diambil dari environment variable proses: `USERDOMAIN` dan `USERNAME` digabung menjadi `domain/user`, dan Session Type dari `SESSIONNAME`; bila tidak ada, nilainya "tidak tersedia" [S11]. Dua akibatnya untuk pertanyaan "milik siapa":

- Nama pengguna dari `sessions` adalah nama di environment saat proses dibuat, bukan identitas token. Untuk pertanyaan hak dan SID token, `windows.getsids` dipakai di Day 15. Untuk Day ini, `sessions` cukup sebagai petunjuk awal bila dicocokkan dengan Session ID, induk proses, dan event log.
- Session Type `Console` dicatat saat sesi logon dibuat dan tidak berubah saat layar dikunci atau pengguna lain masuk lewat Switch user.

Pemisahan pelaku di memori memakai kombinasi yang sama dengan event log (Day 05 bagian 1.4), dengan nama kolom yang berbeda. Tabel berikut adalah kartu pembedanya untuk E01; baca per baris dari kiri ke kanan.

| Pelaku | Session ID | Induk | User Name (`sessions`) | Command line | Pembanding di luar memori |
|---|---|---|---|---|---|
| Andi (pengguna) | 1 | `explorer.exe` 5476 | `JAB/andi.pratama` | Aplikasi kerja (Outlook, Excel, OneDrive) | 4624 Senin 07:58:14 Logon ID `0x3A1F2C` |
| Penyerang (lewat task di sesi Andi) | 1 | `svchost.exe` 1948 (Task Scheduler) | `JAB/andi.pratama` | `-File ...\SysCache\upd.ps1` | Task `\SysCacheUpdate`, Sysmon 1 dan TaskScheduler 200 di detik yang sama |
| Yoga (responder) | 2 | `explorer.exe` 10688 dan `cmd.exe` 11020 | `JKT-WS-0388/ir-admin` | `E:\tools\winpmem_mini_x64.exe E:\INC-2026-019\...` | 4624 `ir-admin` 12:38:41, case notes, evidence log E01 |

Baris kedua adalah inti jawaban untuk Dimas: proses penyerang berjalan di sesi Andi dengan nama pengguna Andi, karena task didaftarkan dengan token interaktif Andi. Yang membedakannya dari Andi adalah induk (`svchost.exe` layanan Task Scheduler, bukan `explorer.exe`) dan command line (`upd.ps1` di folder `SysCache`). Nama pengguna saja tidak memisahkan apa pun.

### 1.8 Batas memori, menautkan memori ke disk, dan kalimat yang boleh ditulis

Pertanyaan terakhir Dimas adalah soal kalimat retainer. Jawabannya bergantung pada apa yang memang bisa dijawab image yang diambil Selasa 12:42 sampai 12:52.

Keterbatasan analisis memori yang perlu ditulis bersama setiap temuan:

- **Snapshot sesaat:** image hanya menangkap state saat akuisisi; proses yang sudah keluar dari memori tidak ada.
- **Versi OS:** symbol harus cocok; OS sangat baru mungkin belum didukung.
- **Smear:** akuisisi live bisa menghasilkan image tidak konsisten (bagian 1.2).
- **Akuisisi mengubah memori:** alat berjalan di memori yang diakuisisi; jejak kecil tak terhindarkan.
- Memori melengkapi, bukan menggantikan, artefak disk: keduanya menjawab pertanyaan berbeda.

Proses di memori (dengan PID, waktu dibuat, command line) dikorelasikan dengan artefak disk:

- Waktu dibuat proses (pslist) dibandingkan dengan Sysmon 1, 4688, Prefetch, dan event Task Scheduler: konsistensi detik dan PID.
- Command line (cmdline) dibandingkan dengan 4688, Sysmon 1, dan 4104 (Day 05).
- `SystemTime` image (windows.info) menempatkan snapshot di timeline gabungan (Day 13).

Memori memberi state hidup; disk memberi riwayat. Bersama, mereka mengonfirmasi dan melengkapi. Di E01, korelasi itu juga bekerja ke arah sebaliknya: `explorer.exe` 5476 dan `OUTLOOK.EXE` 7112 masih hidup Selasa siang, dan keduanya adalah proses yang sama yang tercatat Sysmon Senin sore sebagai induk `wscript.exe` 5820 dan sebagai penyimpan ZIP (bagian 2.7). Memori tidak melihat Senin sore, tetapi membuktikan proses yang terlibat Senin sore adalah proses biasa milik Andi yang berjalan sejak pagi.

Untuk kalimat retainer, ada tiga lapis yang harus dipisah:

1. **Apa yang bisa diperiksa di E01.** Di jendela 12:42:07 sampai 12:52:41, apakah ada proses yang tidak dikenal, proses dengan command line alat dump, atau proses penyerang dengan akses ke LSASS. Bagian pertama (daftar proses dan command line) dijawab Day ini; handle ke LSASS dan injeksi kode dijawab besok di Day 15.
2. **Apa yang tidak bisa diperiksa di E01.** Apa pun sebelum jendela itu, termasuk Senin malam dan Selasa dini hari ketika kredensial dicari dan dipakai. Memori tidak bisa membuktikan ada atau tidak ada akses ke LSASS pada saat itu.
3. **Konteks yang membuat pertanyaan LSASS lebih kecil dari kelihatannya.** Penyerang di laptop ini bekerja dengan token pengguna biasa Andi, tanpa 4672 (Day 05 bagian 1.4), dan Credential Guard aktif. Kredensial yang benar-benar dicuri, password `svc_billing`, dibaca dari file skrip, bukan dari LSASS. Jadi "tidak ada akses ke LSASS" yang benar sekalipun tidak mengubah kesimpulan dampak.

Kalimat yang boleh ditulis: "Di image memori E01 (Selasa 12:42:07 sampai 12:52:41 WIB) tidak ada proses yang tidak dikenal atau proses dengan command line alat dump kredensial; proses penyerang yang hidup saat itu hanya satu run task `upd.ps1` di sesi Andi. Image ini tidak bisa menjawab apa pun tentang Senin malam." Kalimat yang tidak boleh ditulis: "Tidak ada akses ke LSASS selama insiden" dan "memori membuktikan penyerang tidak mencuri kredensial dari memori".

## 2. Contoh dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Perintah Volatility dijalankan di workstation analisis `jkt-dfir02` (Ubuntu LTS, Volatility 3 2.28.2 di virtualenv `~/venv/vol3`, symbol pack Windows offline, tanpa internet) atas salinan kerja `E01-W1`. Nama kolom, format waktu, dan bentuk keluaran bisa berbeda antar versi Volatility; cocokkan dengan versi di lab-mu. Volatility 3 menulis waktu dalam UTC; narasi dan laporan PT JAB memakai WIB (UTC+7), jadi setiap waktu kunci ditulis keduanya sekali, lalu WIB. Keluaran plugin diringkas: baris yang tidak relevan dipotong dan kolom yang seragam (Wow64 selalu False, File output selalu Disabled) dihilangkan.

### 2.1 Status tiga image memori: E01, E08, dan E13

Langkah pertama menjawab pertanyaan pertama Dimas tanpa menjalankan Volatility sama sekali. Bahannya case notes Yoga, formulir chain of custody, evidence log, dan file `.sha256` di `/evidence/INC-2026-019/`.

Tabel berikut merangkum ketiga image memori laptop. Baca kolom "Catatan kualitas", karena kolom itulah yang menjelaskan apa yang bisa dan tidak bisa diharapkan dari tiap image.

| Bukti | Host, RAM | Alat dan cara | Jendela akuisisi (WIB) | Hash dan titik hitung | Catatan kualitas |
|---|---|---|---|---|---|
| E01 | `JKT-WS-0388`, 16 GB | `winpmem_mini_x64.exe` (raw) dari `USB-E-07`, Yoga di konsol, Switch user `ir-admin`, `cmd.exe` elevated | Selasa 12:42:07 sampai 12:52:41 (10 menit 34 detik) | SHA-256 `ab61...` dengan `certutil` di laptop 12:53:40; master dan `E01-W1` cocok | Belum diisolasi; sekitar 20,5 jam setelah lampiran dibuka; run task mulai 12:51:02 di tengah jendela (smear) |
| E08 | `BDG-WS-0142`, 8 GB | `winpmem_mini_x64.exe` dari `USB-E-09`, Fajar dengan panduan telepon, akun admin lokal IR | Selasa 14:05:02 sampai 14:13:01 (7 menit 59 detik) | SHA-256 `2f81...` dengan `certutil` di laptop 14:19:30 | Belum diisolasi (isolasi 16:00); sekitar 5 jam 14 menit setelah lampiran dibuka (08:51:16); pengambil bukan analyst, sehingga case notes bersumber dari panduan telepon dan CoC |
| E13 | `JKT-WS-0412`, 16 GB | `winpmem_mini_x64.exe` dari `USB-E-10`, Yoga, elevasi UAC `ir-admin` di sesi Rizky yang masih terbuka | Selasa 17:45:04 sampai 17:58:12 (13 menit 8 detik) | SHA-256 `6d3c...` dengan `Get-FileHash` di workstation SOC 18:41, 43 menit setelah selesai | Port switch mati sejak 17:20, jadi tidak ada koneksi C2 yang hidup; sekitar 21,5 jam setelah lampiran dibuka (Senin 20:14:21); celah hash ditutup custody `USB-E-10` di tas bukti Yoga |

**Cara membaca tabel:**

- Ketiga image diambil dengan alat dan format yang sama, sehingga cara membacanya sama. Ketiganya juga diambil berjam-jam setelah infeksi di host masing-masing, jadi tidak satu pun bisa menunjukkan proses lampiran (`wscript.exe` dan `powershell.exe -enc` pertama) kecuali sebagai sisa kebetulan di psscan.
- E01 punya kualitas custody paling baik (hash di titik koleksi, 59 detik setelah akuisisi selesai). E13 punya celah 43 menit antara selesai dan hash; celah itu ditutup oleh catatan bahwa `USB-E-10` dicabut 17:59:20 (Day 09 bagian 2.5) dan berada di tas bukti Yoga sampai di-hash. Itu ditulis apa adanya, bukan disembunyikan.
- E13 diambil setelah isolasi, jadi analisis jaringan di memori (Day 16) hanya akan menunjukkan sisa koneksi yang sudah putus, bukan koneksi C2 aktif. E01 dan E08 diambil sebelum isolasi.
- E01 dan E13 diambil di sesi yang masih dipakai pengguna (layar Andi terkunci; sesi Rizky terbuka). Proses responder akan muncul di sesi berbeda di E01 (sesi 2), tetapi di sesi Rizky di E13, sama seperti `MountPoints2` di Day 09 bagian 2.5.

Konsol WinPmem yang disalin Yoga ke case notes E01 memperlihatkan rentang memori yang dipakai untuk mencocokkan ukuran file. Format persis baris konsol berbeda antar versi WinPmem; cocokkan dengan toolkit.

```
INC-2026-019 | Case notes forensik | Yoga Pratama | TZ catatan: UTC+7 (WIB)
2026-10-13 12:41:50  JKT-WS-0388: cmd.exe Run as administrator (ir-admin, sesi 2). USB-E-07 = E:
2026-10-13 12:42:07  E:\tools\winpmem_mini_x64.exe E:\INC-2026-019\E01_JKT-WS-0388_mem.raw
                     (konsol diringkas)
                     Extracting driver to C:\Users\ir-admin\AppData\Local\Temp\pme6A3F.tmp
                     The system time is: 12:42:07
                     Will generate a RAW image
                      3 memory ranges:
                     Start 0x00001000 - Length 0x0009E000
                     Start 0x00100000 - Length 0x75A47000
                     Start 0x100000000 - Length 0x37F800000
                     Acquisition mode PTE Remapping
                     ...
                     The system time is: 12:52:41
                     Driver Unloaded.
2026-10-13 12:52:41  Selesai. Ukuran E01_JKT-WS-0388_mem.raw: 19.318.964.224 byte.
2026-10-13 12:53:40  certutil -hashfile E:\INC-2026-019\E01_JKT-WS-0388_mem.raw SHA256
                     SHA256 hash of E:\INC-2026-019\E01_JKT-WS-0388_mem.raw:
                     ab615fb6d8bcb7094375050f0d335942664fda81870b4b3ba1b5be1a1fee9310
2026-10-13 12:55:10  Sign out ir-admin. Andi diminta tidak mematikan atau me-restart laptop.
```

**Cara membaca hasil:**

- Tiga rentang memori: dua di bawah 4 GB (berakhir di alamat `0x75B47000`, sekitar 1,84 GiB) dan satu mulai tepat di 4 GiB (`0x100000000`) dengan panjang `0x37F800000`. Jumlah RAM yang dipakai Windows adalah total ketiganya, 16.998.354.944 byte (sekitar 15,83 GiB; sisanya dari 16 GB dicadangkan firmware dan grafis). Alamat tertinggi adalah `0x100000000 + 0x37F800000 = 0x47F800000` = 19.318.964.224 byte, persis ukuran file. Selisih sekitar 2,16 GiB adalah celah antara 1,84 GiB dan 4 GiB yang diisi nol. File lebih besar dari RAM, dan itu cocok dengan rentangnya.
- Jam di awal dan akhir konsol (12:42:07 dan 12:52:41) adalah jendela smear. Kecepatannya sekitar 30 MB per detik (19,3 GB dalam 634 detik).
- Hash dihitung di laptop 59 detik setelah akuisisi selesai, dari media yang sama. Nilai ini yang ada di `E01_JKT-WS-0388_mem.raw.sha256` di master.
- Driver diekstrak ke folder sementara profil `ir-admin`, cocok dengan 7045 kernel driver pukul 12:42:08 (Day 05 bagian 2.6).

**Variasi:** untuk E08, cocokkan jam di konsol (bila Fajar menyalinnya) dengan run Prefetch WinPmem 14:05:02 dan waktu BAM 14:13:04 (Day 07 bagian 2.8). Untuk E13, cocokkan dengan 7045 pukul 17:45:06 di E16 (Day 09 bagian 2.6).

**Kapan gagal:** ukuran file lebih kecil dari alamat tertinggi di daftar rentang. Itu tanda akuisisi terputus (media penuh, USB tercabut, alat crash), dan image harus diperlakukan sebagai tidak lengkap walaupun hash-nya cocok, karena hash hanya membuktikan file tidak berubah sejak dihitung.

### 2.2 Menyiapkan `E01-W1` di `jkt-dfir02` dan menjalankan `windows.info`

Langkah ini menjawab pertanyaan kedua Dimas: apakah E01 terbaca oleh alat PT JAB, dan image dari Windows apa. Dilakukan Kamis 09:04 sampai 09:16.

**Tujuan:** menyalin salinan kerja ke disk lokal `jkt-dfir02`, membuktikan identik dengan master, lalu memastikan Volatility mengenali image dengan symbol yang cocok.

```bash
mkdir -p /data/INC-2026-019/E01-W1
cp /mnt/cases/INC-2026-019/work/E01-W1/E01_JKT-WS-0388_mem.raw /data/INC-2026-019/E01-W1/
chmod 444 /data/INC-2026-019/E01-W1/E01_JKT-WS-0388_mem.raw
cd /data/INC-2026-019/E01-W1
sha256sum E01_JKT-WS-0388_mem.raw
cat /mnt/evidence/INC-2026-019/E01/E01_JKT-WS-0388_mem.raw.sha256
```

- `/mnt/cases` adalah share `\\jkt-evid01\cases` yang di-mount read-write dengan akun analyst biasa; `/mnt/evidence` adalah share master yang di-mount read-only (Day 02 bagian 2.8).
- Image disalin ke disk lokal karena Volatility membaca image berkali-kali secara acak; membaca 19 GB lewat SMB untuk setiap plugin lambat dan membebani jaringan manajemen.
- `chmod 444`: salinan lokal dibuat read-only supaya tidak tertimpa output plugin. Ini bukan pengganti hash.
- `sha256sum` dibandingkan dengan file `.sha256` master yang ditulis Yoga di titik koleksi.

Keluaran ilustrasi:

```
ab615fb6d8bcb7094375050f0d335942664fda81870b4b3ba1b5be1a1fee9310  E01_JKT-WS-0388_mem.raw
ab615fb6d8bcb7094375050f0d335942664fda81870b4b3ba1b5be1a1fee9310  E01_JKT-WS-0388_mem.raw
```

Lalu Volatility, dengan log ke folder analisis supaya versi dan symbol yang dipakai tercatat:

```bash
. ~/venv/vol3/bin/activate
mkdir -p /mnt/cases/INC-2026-019/analysis/E01-W1/vol3-2.28.2
vol -q -v -l /mnt/cases/INC-2026-019/analysis/E01-W1/vol3-2.28.2/vol-info.log \
    -f /data/INC-2026-019/E01-W1/E01_JKT-WS-0388_mem.raw windows.info
```

- `. ~/venv/vol3/bin/activate`: memakai Volatility yang dibekukan untuk kasus ini (2.28.2), bukan salinan lain di sistem.
- Folder hasil memuat nomor bukti dan versi alat, mengikuti aturan folder kasus PT JAB (Day 02 bagian 1.6).
- `-q`: tanpa progress bar. `-v`: log lebih rinci, termasuk pencarian symbol. `-l`: log disimpan sebagai bagian dari case notes.
- `windows.info`: plugin pertama, gerbang analisis.

Keluaran ilustrasi (diringkas; waktu UTC):

```
Variable                        Value
Kernel Base                     0xf80357a00000
DTB                             0x1ad000
Symbols                         jar:file:///home/<analis>/venv/vol3/lib/python3/site-packages/volatility3/symbols/windows.zip!windows/ntkrnlmp.pdb/<GUID>-1.json.xz
Is64Bit                         True
IsPAE                           False
layer_name                      0 WindowsIntel32e
memory_layer                    1 FileLayer
KdVersionBlock                  0xf8035860f400
Major/Minor                     15.22621
MachineType                     34404
KeNumberProcessors              8
SystemTime                      2026-10-13 05:47:36 UTC
NtSystemRoot                    C:\Windows
NtProductType                   NtProductWinNt
NtMajorVersion                  10
NtMinorVersion                  0
PE MajorOperatingSystemVersion  10
PE MinorOperatingSystemVersion  0
PE Machine                      34404
```

**Cara membaca hasil:**

- Plugin selesai dan baris `Symbols` menunjuk file di dalam symbol pack `windows.zip` yang dipasang Kamis 2026-10-15. Image terbaca dengan symbol dari pack yang sudah diverifikasi hash-nya, tanpa unduhan. Bentuk URL file symbol berbeda antar versi; yang dicatat adalah sumbernya (pack, cache, atau hasil `pdbconv.py`).
- `Is64Bit True`, `MachineType 34404` (x64), `NtProductWinNt` (edisi workstation, bukan server), `NtMajorVersion 10` (Windows 10 dan 11 sama-sama melapor 10.0). `Major/Minor` menyebut 22621 walaupun inventaris IT mencatat Windows 11 23H2 build 22631: ini perbedaan nomor build inti 22H2 dan 23H2 yang dijelaskan di bagian 1.3, bukan tanda image dari host lain. Yang memastikan host adalah nama komputer dan akun di proses, bukan nomor build.
- `SystemTime` 2026-10-13 05:47:36 UTC adalah 12:47:36 WIB, di dalam jendela 12:42:07 sampai 12:52:41. Jam host konsisten dengan case notes. Waktu ini bukan "waktu image diambil": ia jam sistem saat halaman `_KUSER_SHARED_DATA` dibaca, lima menit 29 detik setelah akuisisi mulai.
- Uptime saat akuisisi mulai: laptop boot Senin 07:56:31 WIB, jadi sekitar 28 jam 46 menit. Semua yang terjadi selama itu bersaing memakai RAM yang sama.

**Variasi:** jalankan `windows.info` untuk E08 dan E13 dengan cara yang sama untuk memastikan ketiganya terbaca sebelum siapa pun meminta analisis lanjutan; catat `SystemTime` masing-masing dan bandingkan dengan jendela di bagian 2.1.

**Kapan gagal:** log berisi pesan bahwa library symbol yang dibutuhkan tidak ditemukan, disertai saran perintah `pdbconv.py` dengan nama PDB dan GUID [S14]. Itu berarti build kernel tidak tercakup pack. Jangan menyalin image ke mesin berinternet; minta jendela proxy khusus ke Microsoft Symbol Server atau konversi PDB yang diunduh di mesin lain (Day 02 bagian 2.5), lalu catat langkahnya.

### 2.3 Daftar proses aktif dengan `windows.pslist`

Langkah ini menjawab bagian pertama pertanyaan ketiga Dimas: proses apa saja yang hidup saat E01 diambil.

```bash
cd /mnt/cases/INC-2026-019/analysis/E01-W1/vol3-2.28.2
vol -q -r csv -f /data/INC-2026-019/E01-W1/E01_JKT-WS-0388_mem.raw windows.pslist > pslist.csv
vol -q -f /data/INC-2026-019/E01-W1/E01_JKT-WS-0388_mem.raw windows.pslist
```

- `-r csv`: hasil lengkap disimpan sebagai CSV untuk diolah dan diarsipkan bersama log; run kedua tanpa `-r` untuk dibaca di layar.
- Tanpa `--pid`: semua proses aktif. `--pid 12408` membatasi ke satu proses bila hanya itu yang dibutuhkan.
- Tanpa `--dump`: proses tidak diekstrak. Dump dibahas di Day 15.

Keluaran ilustrasi (184 baris; yang ditampilkan 30 baris yang relevan; CreateTime dan ExitTime dalam UTC):

```
PID    PPID   ImageFileName         Offset(V)        Threads Handles SessionId CreateTime (UTC)     ExitTime
4      0      System                0xc60b2c69a040   238     -       N/A       2026-10-12 00:56:31  N/A
120    4      Registry              0xc60b2c7a9080   4       -       N/A       2026-10-12 00:56:31  N/A
412    4      smss.exe              0xc60b2f1e3040   2       -       N/A       2026-10-12 00:56:31  N/A
596    500    csrss.exe             0xc60b2fa1c140   12      -       0         2026-10-12 00:56:33  N/A
688    500    wininit.exe           0xc60b2fb06080   1       -       0         2026-10-12 00:56:33  N/A
768    676    csrss.exe             0xc60b2fb0a140   14      -       1         2026-10-12 00:56:33  N/A
824    688    services.exe          0xc60b2fb6d080   8       -       0         2026-10-12 00:56:33  N/A
836    688    LsaIso.exe            0xc60b2fb70080   1       -       0         2026-10-12 00:56:33  N/A
844    688    lsass.exe             0xc60b2fb72080   9       -       0         2026-10-12 00:56:33  N/A
852    676    winlogon.exe          0xc60b2fb85080   5       -       1         2026-10-12 00:56:33  N/A
960    824    svchost.exe           0xc60b2fbd1080   17      -       0         2026-10-12 00:56:34  N/A
1236   852    dwm.exe               0xc60b30212080   19      -       1         2026-10-12 00:56:35  N/A
1948   824    svchost.exe           0xc60b30a4e080   11      -       0         2026-10-12 00:56:36  N/A
2380   4      MemCompression        0xc60b30c11040   62      -       N/A       2026-10-12 00:56:40  N/A
3312   824    Sysmon64.exe          0xc60b31266080   16      -       0         2026-10-12 00:56:41  N/A
3520   824    MsMpEng.exe           0xc60b3138c080   31      -       0         2026-10-12 00:56:42  N/A
3876   824    MsSense.exe           0xc60b314d3080   27      -       0         2026-10-12 00:56:44  N/A
5476   5404   explorer.exe          0xc60b33a52080   96      -       1         2026-10-12 00:58:21  N/A
6240   5476   OneDrive.exe          0xc60b33f0e080   34      -       1         2026-10-12 00:58:40  N/A
7112   5476   OUTLOOK.EXE           0xc60b34a87080   58      -       1         2026-10-12 01:03:12  N/A
9284   5476   EXCEL.EXE             0xc60b36d14080   29      -       1         2026-10-13 01:23:58  N/A
10112  10088  csrss.exe             0xc60b3812a140   12      -       2         2026-10-13 05:38:10  N/A
10164  10088  winlogon.exe          0xc60b38131080   4       -       2         2026-10-13 05:38:10  N/A
10196  10164  dwm.exe               0xc60b381c4080   15      -       2         2026-10-13 05:38:11  N/A
10688  10652  explorer.exe          0xc60b38e0b080   71      -       2         2026-10-13 05:38:52  N/A
11020  10688  cmd.exe               0xc60b39410080   1       -       2         2026-10-13 05:41:50  N/A
11028  11020  conhost.exe           0xc60b39417080   4       -       2         2026-10-13 05:41:50  N/A
11344  11020  winpmem_mini_x        0xc60b39a2f080   3       -       2         2026-10-13 05:42:07  N/A
12408  1948   powershell.exe        0xc60b3a6e8080   14      -       1         2026-10-13 05:51:02  N/A
12416  12408  conhost.exe           0xc60b3a6f1080   3       -       1         2026-10-13 05:51:02  N/A
```

**Cara membaca hasil:**

- **Sistem dan baseline.** `System` 4 dibuat Senin 07:56:31 WIB (00:56:31 UTC), waktu boot. `services.exe`, `lsass.exe`, dan `LsaIso.exe` semuanya berinduk `wininit.exe` 688 dan hanya satu instance; `LsaIso.exe` menandakan Credential Guard aktif (bagian 1.5). `csrss.exe` dan `wininit.exe` berinduk PID 500, dan `csrss.exe` serta `winlogon.exe` sesi 1 berinduk PID 676: itu instance `smss.exe` per sesi yang sudah berakhir setelah tugasnya, normal. Kolom Handles dikosongkan di ringkasan ini; handle per proses dibaca dengan plugin `windows.handles` di Day 15.
- **Sesi 1 (Andi).** `explorer.exe` 5476 dibuat Senin 07:58:21 WIB, tujuh detik setelah logon Andi 07:58:14 (Logon ID `0x3A1F2C`, Day 05 bagian 2.3), dengan induk `userinit.exe` 5404 yang sudah berakhir. OneDrive 07:58:40, Outlook 08:03:12, keduanya Senin pagi. `EXCEL.EXE` 9284 dibuat Selasa 08:23:58 WIB, tujuh detik sebelum `Rekap-Penagihan-Okt-2026.xlsx` tercatat dibuka di LNK dan Jump List (08:24:05, Day 10 bagian 2.3). Laptop tidak reboot sejak Senin pagi, jadi proses Senin pagi masih hidup.
- **Proses penyerang.** `powershell.exe` 12408 berinduk `svchost.exe` 1948 di sesi 1, dibuat Selasa 05:51:02 UTC (12:51:02 WIB), dengan `conhost.exe` 12416 sebagai anaknya. Waktu 12:51:02 jatuh tepat di jadwal task `\SysCacheUpdate` (mulai 16:21:02 Senin, setiap 15 menit, sehingga setiap menit 06, 21, 36, dan 51 lewat dua detik). Bahwa induknya `svchost.exe` 1948 adalah layanan Task Scheduler dikonfirmasi lewat command line di bagian 2.6.
- **Sesi 2 (Yoga).** `csrss.exe` 10112 dan `winlogon.exe` 10164 dibuat 12:38:10 WIB saat Switch user membuka sesi baru, sebelum password salah ketik 12:38:29 dan logon berhasil 12:38:41. `explorer.exe` 10688 12:38:52, `cmd.exe` 11020 12:41:50, `winpmem_mini_x64.exe` 11344 12:42:07: semuanya cocok detik demi detik dengan event log (Day 05 bagian 2.6). Di kolom nama, WinPmem tampil sebagai `winpmem_mini_x` karena nama di struktur proses kernel (`ImageFileName`) hanya menampung sekitar 15 byte dan nama yang lebih panjang terpotong; nama lengkap dan path dibaca dari kolom Path `pstree` atau dari `cmdline`. Jumlah karakter persis yang tampil dicek di lab.
- **Tanda smear.** `powershell.exe` 12408 dibuat 12:51:02 WIB, tiga menit 26 detik setelah `SystemTime` image (12:47:36). Image ini memuat proses yang "lebih muda" dari jam sistemnya, karena halaman struktur proses itu dibaca menjelang akhir jendela, sedangkan halaman jam dibaca di tengah.
- **PID tidak berurutan waktu.** PID 11344 dibuat 12:42:07, tetapi PID 11872 (bagian 2.5) dibuat lebih awal, 12:36:02. Windows memakai ulang nomor PID yang sudah bebas, jadi urutkan berdasarkan CreateTime, bukan PID.
- **Tidak ada nama yang janggal.** Di 184 baris tidak ada nama penyamaran (`scvhost.exe`, `lsas.exe`), tidak ada `lsass.exe` kedua, tidak ada `svchost.exe` berinduk selain `services.exe`, dan tidak ada executable dari folder pengguna selain OneDrive (yang memang terpasang per pengguna di `AppData\Local`). Path lengkap dicek dari kolom Path `pstree` dan dari `cmdline`.

**Variasi:** `vol ... windows.pslist --pid 12408 11344` untuk menampilkan dua proses yang dibandingkan saja; `--physical` bila offset fisik dibutuhkan untuk mencocokkan dengan alat lain.

**Kapan gagal:** image yang smear-nya mengenai halaman daftar proses bisa membuat pslist berhenti di tengah, menampilkan baris dengan nama kosong atau waktu mustahil, atau tidak menampilkan proses yang jelas hidup. Bila itu terjadi, bandingkan dengan psscan (bagian 2.5) sebelum menyimpulkan apa pun, dan catat bahwa daftar aktif tidak konsisten.

### 2.4 Hierarki proses dengan `windows.pstree`

Langkah ini mengubah daftar menjadi pohon, supaya pemisahan pengguna, penyerang, dan responder di pertanyaan ketiga Dimas terlihat sekali pandang.

```bash
vol -q -f /data/INC-2026-019/E01-W1/E01_JKT-WS-0388_mem.raw windows.pstree > pstree.txt
vol -q -f /data/INC-2026-019/E01-W1/E01_JKT-WS-0388_mem.raw windows.pstree --pid 12408
```

- Run pertama: seluruh pohon, disimpan sebagai teks.
- Run kedua: `--pid 12408` menampilkan proses itu beserta leluhur dan keturunannya saja [S9].

Keluaran ilustrasi (run pertama, diringkas; tanda `*` menunjukkan kedalaman; kolom Offset, Threads, Handles, Audit dipotong; Path ditampilkan untuk baris tertentu):

```
PID    PPID   ImageFileName          SessionId  CreateTime (UTC)     Path
4      0      System                 N/A        2026-10-12 00:56:31
* 120  4      Registry               N/A        2026-10-12 00:56:31
* 412  4      smss.exe               N/A        2026-10-12 00:56:31  \SystemRoot\System32\smss.exe
* 2380 4      MemCompression         N/A        2026-10-12 00:56:40
596    500    csrss.exe              0          2026-10-12 00:56:33  C:\Windows\system32\csrss.exe
688    500    wininit.exe            0          2026-10-12 00:56:33  C:\Windows\system32\wininit.exe
* 824  688    services.exe           0          2026-10-12 00:56:33  C:\Windows\system32\services.exe
** 960 824    svchost.exe            0          2026-10-12 00:56:34  C:\Windows\system32\svchost.exe
** 1948 824   svchost.exe            0          2026-10-12 00:56:36  C:\Windows\system32\svchost.exe
*** 12408 1948 powershell.exe        1          2026-10-13 05:51:02  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
**** 12416 12408 conhost.exe         1          2026-10-13 05:51:02  C:\Windows\system32\conhost.exe
** 3312 824   Sysmon64.exe           0          2026-10-12 00:56:41  C:\Windows\Sysmon64.exe
** 3520 824   MsMpEng.exe            0          2026-10-12 00:56:42
** 3876 824   MsSense.exe            0          2026-10-12 00:56:44
* 836  688    LsaIso.exe             0          2026-10-12 00:56:33  C:\Windows\system32\lsaiso.exe
* 844  688    lsass.exe              0          2026-10-12 00:56:33  C:\Windows\system32\lsass.exe
768    676    csrss.exe              1          2026-10-12 00:56:33
852    676    winlogon.exe           1          2026-10-12 00:56:33
* 1236 852    dwm.exe                1          2026-10-12 00:56:35
5476   5404   explorer.exe           1          2026-10-12 00:58:21  C:\Windows\Explorer.EXE
* 6240 5476   OneDrive.exe           1          2026-10-12 00:58:40  C:\Users\andi.pratama\AppData\Local\Microsoft\OneDrive\OneDrive.exe
* 7112 5476   OUTLOOK.EXE            1          2026-10-12 01:03:12
* 9284 5476   EXCEL.EXE              1          2026-10-13 01:23:58
10112  10088  csrss.exe              2          2026-10-13 05:38:10
10164  10088  winlogon.exe           2          2026-10-13 05:38:10
* 10196 10164 dwm.exe                2          2026-10-13 05:38:11
10688  10652  explorer.exe           2          2026-10-13 05:38:52  C:\Windows\Explorer.EXE
* 11020 10688 cmd.exe                2          2026-10-13 05:41:50  C:\Windows\system32\cmd.exe
** 11028 11020 conhost.exe           2          2026-10-13 05:41:50
** 11344 11020 winpmem_mini_x        2          2026-10-13 05:42:07  E:\tools\winpmem_mini_x64.exe
```

**Cara membaca hasil:**

- Akar pohon selain `System` adalah proses yang induknya sudah berakhir: `csrss.exe`/`wininit.exe` (induk 500), `csrss.exe`/`winlogon.exe` sesi 1 (induk 676), `explorer.exe` 5476 (induk `userinit.exe` 5404), `csrss.exe`/`winlogon.exe` sesi 2 (induk 10088), dan `explorer.exe` 10688 (induk 10652). Semua sesuai baseline (bagian 1.5); PPID tetap ditampilkan walaupun induknya hilang [S9].
- Tiga cabang menjawab "milik siapa": cabang `explorer.exe` 5476 di sesi 1 berisi aplikasi kerja Andi; cabang `svchost.exe` 1948 di bawah `services.exe` berisi satu `powershell.exe` sesi 1 dari task; cabang `explorer.exe` 10688 di sesi 2 berisi `cmd.exe` dan WinPmem dari `E:\tools\` milik Yoga.
- `powershell.exe` 12408 berjalan di sesi 1 walaupun induknya di sesi 0. Itu pola task yang didaftarkan dengan token interaktif pengguna: layanan Task Scheduler di sesi 0 meluncurkan proses ke sesi pengguna. Path `powershell.exe` adalah lokasi standar di `System32`; yang menyimpang adalah skrip yang dijalankannya (bagian 2.6), bukan executable-nya.
- `LsaIso.exe` dan `lsass.exe` sama-sama anak `wininit.exe`, tanpa proses anak. Tidak ada proses di pohon yang berinduk `lsass.exe`.
- WinPmem berjalan dari drive `E:`, bukan dari disk laptop, sesuai prinsip media terpisah.

**Variasi:** run kedua (`--pid 12408`) hanya menampilkan rantai `wininit.exe` 688, `services.exe` 824, `svchost.exe` 1948, `powershell.exe` 12408, dan `conhost.exe` 12416. Rantai pendek ini yang ditempel di laporan, bukan seluruh pohon.

**Kapan gagal:** membaca akar pohon sebagai "proses tanpa induk yang mencurigakan". `explorer.exe` tanpa induk hidup adalah normal; yang perlu diperiksa adalah PPID-nya menunjuk proses apa, dan psscan kadang masih menyimpan induk yang sudah berakhir (bagian 2.5).

### 2.5 Proses yang sudah berakhir: `windows.psscan` dibandingkan dengan `pslist`

Langkah ini menjawab pertanyaan kelima Dimas, dan sekaligus pertanyaan yang tidak ditanyakan tetapi akan muncul: kenapa rantai Senin sore tidak terlihat.

```bash
vol -q -r csv -f /data/INC-2026-019/E01-W1/E01_JKT-WS-0388_mem.raw windows.psscan > psscan.csv
python3 - <<'PY'
import csv
pl = {r['PID'] for r in csv.DictReader(open('pslist.csv'))}
for r in csv.DictReader(open('psscan.csv')):
    if r['PID'] not in pl:
        print(r['PID'], r['PPID'], r['ImageFileName'], r['SessionId'], r['CreateTime'], r['ExitTime'])
PY
```

- `windows.psscan` dengan renderer CSV: semua struktur proses yang ditemukan pemindaian.
- Skrip Python kecil membandingkan dua CSV berdasarkan PID dan mencetak yang hanya ada di psscan. Untuk image besar, membandingkan berdasarkan pasangan PID dan CreateTime lebih aman karena PID bisa dipakai ulang.

Keluaran ilustrasi (psscan 188 baris; 184 cocok dengan pslist; 4 hanya ada di psscan; waktu UTC):

```
PID    PPID   ImageFileName   SessionId  CreateTime (UTC)     ExitTime (UTC)
4412   824    svchost.exe     0          2026-10-12 01:12:09  2026-10-12 01:12:40
10088  412    smss.exe        N/A        2026-10-13 05:38:10  2026-10-13 05:38:10
10652  10164  userinit.exe    2          2026-10-13 05:38:51  2026-10-13 05:39:22
11872  1948   powershell.exe  1          2026-10-13 05:36:02  2026-10-13 05:36:44
```

Pencarian nama yang sengaja dilakukan untuk rantai Senin sore:

```bash
grep -iE 'wscript|5820|6136' psscan.csv pslist.csv
```

Keluaran ilustrasi: kosong.

**Cara membaca hasil:**

- Keempat baris punya ExitTime, jadi keempatnya proses yang sudah berakhir, bukan proses yang disembunyikan. Tidak ada kandidat proses tersembunyi di tingkat ini; konfirmasi dengan `windows.malware.psxview` tetap dijalankan di Day 15.
- `powershell.exe` 11872 adalah run task sebelumnya: dibuat 12:36:02 WIB dan berakhir 12:36:44 WIB, 42 detik, lima menit sebelum akuisisi mulai. Induknya `svchost.exe` 1948, sama dengan 12408. Sisa strukturnya masih ada; isi memorinya (command line, environment) tidak, karena `cmdline` dan `sessions` memakai pslist dan proses yang sudah berakhir tidak punya ruang alamat untuk dibaca.
- `smss.exe` 10088 dan `userinit.exe` 10652 adalah induk yang hilang di pohon sesi 2: `smss.exe` 10088 membuat `csrss.exe` 10112 dan `winlogon.exe` 10164 lalu berakhir di detik yang sama, dan `userinit.exe` 10652 membuat `explorer.exe` 10688 lalu berakhir 30 detik kemudian. Keduanya jejak Switch user Yoga.
- `svchost.exe` 4412 berakhir Senin 08:12:40 WIB, 31 detik setelah dibuat. Proses service singkat seperti ini normal. Ia satu-satunya sisa dari Senin, dan ia lebih tua dari rantai lampiran Senin sore yang tidak ditemukan.
- Pencarian `wscript`, 5820, dan 6136 kosong. Itu konsisten dengan bagian 1.6: sisa struktur bertahan atau hilang karena pemakaian ulang memori, bukan karena umur, dan sekitar 80 run task setelah Senin sore terus membuat dan membuang proses di laptop yang sama. Ketiadaan ini tidak membantah Sysmon 1 di E15 (Day 05 bagian 2.4).
- Induk sesi 0 dan sesi 1 (PID 500 dan 676) serta `userinit.exe` 5404 milik Andi tidak ditemukan. Ketiganya berakhir Senin pagi, sama seperti `svchost.exe` 4412, tetapi strukturnya sudah tertimpa.

**Variasi:** `vol ... windows.psscan --physical` untuk offset fisik bila ingin mencocokkan baris dengan posisi di file raw; posisi itu, dibagi kecepatan akuisisi, memberi perkiraan kasar kapan halaman itu dibaca. Perkiraan ini hanya berlaku bila kecepatan baca seragam, jadi jangan dipakai sebagai waktu.

**Kapan gagal:** psscan menampilkan baris dengan nama kosong, PID sangat besar, atau CreateTime di masa depan. Itu sisa struktur yang rusak atau tertimpa sebagian (dan smear bisa menambahnya). Baris seperti itu dicatat sebagai noise, bukan temuan, kecuali didukung artefak lain.

### 2.6 Command line dan pemilik: `windows.cmdline` dan `windows.sessions`

Langkah ini menjawab pertanyaan keempat Dimas (apa persisnya yang dijalankan) dan menutup pertanyaan ketiga (milik siapa).

```bash
vol -q -r csv -f /data/INC-2026-019/E01-W1/E01_JKT-WS-0388_mem.raw windows.cmdline > cmdline.csv
vol -q -f /data/INC-2026-019/E01-W1/E01_JKT-WS-0388_mem.raw windows.cmdline --pid 1948 5476 9284 11020 11344 12408 12416
vol -q -f /data/INC-2026-019/E01-W1/E01_JKT-WS-0388_mem.raw windows.sessions > sessions.txt
```

- Run pertama menyimpan semua command line untuk arsip dan pencarian.
- Run kedua hanya proses yang dibutuhkan jawaban; `--pid` menerima lebih dari satu PID [S10].
- `windows.sessions` membaca Session ID dan environment variable setiap proses di pslist [S11].

Keluaran ilustrasi `cmdline` (run kedua):

```
PID    Process               Args
1948   svchost.exe           C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
5476   explorer.exe          C:\Windows\Explorer.EXE
9284   EXCEL.EXE             "C:\Program Files\Microsoft Office\Root\Office16\EXCEL.EXE" "C:\Users\andi.pratama\Desktop\Rekap-Penagihan-Okt-2026.xlsx"
11020  cmd.exe               "C:\Windows\system32\cmd.exe"
11344  winpmem_mini_x        E:\tools\winpmem_mini_x64.exe E:\INC-2026-019\E01_JKT-WS-0388_mem.raw
12408  powershell.exe        powershell.exe -NoProfile -WindowStyle Hidden -File C:\Users\andi.pratama\AppData\Roaming\SysCache\upd.ps1
12416  conhost.exe           \??\C:\Windows\system32\conhost.exe 0x4
```

Keluaran ilustrasi `sessions` (diringkas ke sesi 1 dan 2; waktu UTC):

```
Session ID  Session Type  Process ID  Process               User Name              Create Time (UTC)
1           Console       5476        explorer.exe          JAB/andi.pratama       2026-10-12 00:58:21
1           Console       6240        OneDrive.exe          JAB/andi.pratama       2026-10-12 00:58:40
1           Console       7112        OUTLOOK.EXE           JAB/andi.pratama       2026-10-12 01:03:12
1           Console       9284        EXCEL.EXE             JAB/andi.pratama       2026-10-13 01:23:58
1           N/A           12408       powershell.exe        JAB/andi.pratama       2026-10-13 05:51:02
1           N/A           12416       conhost.exe           JAB/andi.pratama       2026-10-13 05:51:02
2           Console       10688       explorer.exe          JKT-WS-0388/ir-admin   2026-10-13 05:38:52
2           Console       11020       cmd.exe               JKT-WS-0388/ir-admin   2026-10-13 05:41:50
2           Console       11028       conhost.exe           JKT-WS-0388/ir-admin   2026-10-13 05:41:50
2           Console       11344       winpmem_mini_x        JKT-WS-0388/ir-admin   2026-10-13 05:42:07
```

**Cara membaca hasil:**

- `svchost.exe` 1948 menjalankan service `Schedule`: itulah layanan Task Scheduler. Dengan ini, induk `powershell.exe` 12408 terbukti layanan Task Scheduler, bukan `svchost.exe` lain.
- `powershell.exe` 12408 menjalankan `upd.ps1` dari `C:\Users\andi.pratama\AppData\Roaming\SysCache\` dengan `-NoProfile -WindowStyle Hidden`. Argumennya sama dengan action task `\SysCacheUpdate` di XML (Day 05 bagian 2.4); XML menulis path dalam tanda kutip, dan perbedaan itu tidak mengubah arti karena path tidak mengandung spasi. Ini jawaban untuk pertanyaan keempat: saat E01 diambil, penyerang menjalankan satu run loader yang sama seperti run lain sejak Senin, tidak ada alat lain. Isi `upd.ps1` tidak ada di command line; isi blok yang dijalankan terbaca di 4104 E15 dan file aslinya di E03.
- `conhost.exe` 12416 dengan argumen `0x4` adalah host console untuk `powershell.exe` yang jendelanya disembunyikan. Itu pasangan normal setiap proses console.
- `EXCEL.EXE` membuka `Rekap-Penagihan-Okt-2026.xlsx` di Desktop Andi, cocok dengan file yang disimpan Andi Selasa 08:24 sampai 08:52 (Day 08 bagian 2.4). Aktivitas kerja biasa.
- Command line WinPmem sama persis dengan Sysmon 1 pukul 12:42:07 dan case notes Yoga.
- `sessions` memberi nama pengguna dari environment: proses sesi 1, termasuk `powershell.exe` 12408, tercatat `JAB/andi.pratama`; proses sesi 2 tercatat `JKT-WS-0388/ir-admin`, yaitu akun lokal (domain-nya nama komputer). Nama pengguna yang sama untuk Outlook dan loader adalah inti kenapa nama saja tidak memisahkan Andi dari penyerang (bagian 1.7).
- Session Type `N/A` untuk `powershell.exe` 12408 dan `conhost.exe` 12416, berbeda dengan `Console` untuk proses yang diluncurkan dari `explorer.exe`, kemungkinan karena environment proses yang dibuat Task Scheduler tidak memuat `SESSIONNAME`. Ini petunjuk tambahan, bukan bukti; perilakunya diuji di lab (bagian 3) sebelum dipakai di laporan.

**Variasi:** `vol ... windows.envars --pid 12408` menampilkan seluruh environment variable proses itu bila perlu memeriksa `USERPROFILE`, `TEMP`, atau `SESSIONNAME` langsung. `windows.getsids --pid 12408` untuk SID token dibahas di Day 15.

**Kapan gagal:** kolom Args berisi nilai tidak terbaca untuk proses yang jelas hidup. Halaman PEB-nya ter-page out atau terkena smear. Jangan isi dengan tebakan dari event log; tulis "command line tidak terbaca di memori; command line dari Sysmon 1 adalah ..." dan sebut sumbernya.

### 2.7 Menautkan proses di memori ke event log dan disk

Langkah ini menguji setiap proses penting di E01 terhadap bukti yang diolah minggu lalu. Satu proses memori yang punya pasangan di event log dan disk dengan PID dan detik yang sama adalah temuan yang kuat; proses tanpa pasangan harus dijelaskan.

Tabel berikut adalah hasilnya. Baca kolom "Pasangan di luar memori" untuk melihat sumber yang mengonfirmasi; semua waktu WIB.

| Proses di E01 | Waktu dibuat (WIB) | Pasangan di luar memori | Arti |
|---|---|---|---|
| `explorer.exe` 5476, sesi 1 | Senin 07:58:21 | 4624 Andi 07:58:14 Logon ID `0x3A1F2C`; Sysmon 1 `wscript.exe` 5820 Senin 16:05:11 dengan `ParentProcessId` 5476 | Shell Andi sejak pagi; proses yang sama menjadi induk `wscript.exe` saat lampiran diklik |
| `OUTLOOK.EXE` 7112, sesi 1 | Senin 08:03:12 | Sysmon 11 Senin 16:04:48 `ProcessId` 7112 menyimpan ZIP ke Downloads | Outlook yang sama menyimpan lampiran, masih hidup Selasa |
| `EXCEL.EXE` 9284, sesi 1 | Selasa 08:23:58 | LNK dan Jump List 08:24:05 (Day 10); file disimpan 08:24-08:52 (Day 08) | Aktivitas kerja Andi |
| `powershell.exe` 11872 (psscan, berakhir) | Selasa 12:36:02, berakhir 12:36:44 | Sysmon 1 12:36:02 PID 11872; TaskScheduler 200 12:36:02 dan 201 12:36:44 | Run task sebelum akuisisi |
| `csrss.exe` 10112, `winlogon.exe` 10164, sesi 2 | Selasa 12:38:10 | 4625 `ir-admin` 12:38:29, 4624 12:38:41 | Switch user Yoga |
| `explorer.exe` 10688, sesi 2 | Selasa 12:38:52 | Profil `C:\Users\ir-admin` dibuat 12:38:41 (Day 10 bagian 2.6) | Shell responder |
| `cmd.exe` 11020 | Selasa 12:41:50 | 4688 `%%1937` 12:41:50 | Command Prompt elevated responder |
| `winpmem_mini_x64.exe` 11344 | Selasa 12:42:07 | Sysmon 1 12:42:07; 7045 dan 4697 12:42:08; case notes | Akuisisi E01 |
| `powershell.exe` 12408 | Selasa 12:51:02 | Sysmon 1 12:51:02 PID 12408 induk 1948; TaskScheduler 200 12:51:02, 201 12:53:19 | Run task di tengah akuisisi; selesai 38 detik setelah akuisisi berakhir |
| Image E01 (`SystemTime`) | 12:47:36 | Evidence log E01 12:42-12:53 | Jam host dan catatan responder konsisten |

**Cara membaca hasil:**

- Setiap proses penting di memori punya pasangan di E15 dengan PID dan detik yang sama. Tidak ada proses di E01 yang tidak bisa dijelaskan oleh Andi, task penyerang, sistem, atau Yoga.
- Event 201 untuk run 12:51:02 tercatat 12:53:19, setelah WinPmem selesai 12:52:41. Itu konfirmasi dari sisi event log bahwa proses 12408 memang masih hidup sampai akhir jendela, sehingga kemunculannya di image bukan kebetulan.
- `ParentProcessId` 5476 di Sysmon 1 `wscript.exe` dan `ProcessId` 7112 di Sysmon 11 menautkan kejadian Senin sore ke proses yang masih hidup di memori Selasa. Memori tidak melihat Senin sore, tetapi menunjukkan bahwa `explorer.exe` dan Outlook yang terlibat adalah proses biasa yang berjalan sejak pagi, tanpa tanda penggantian.

**Variasi:** untuk timeline gabungan (Day 13), keluaran pslist dan psscan bisa dijadikan baris timeline: CreateTime dan ExitTime setiap proses menjadi dua kejadian, dan `SystemTime` image menjadi satu kejadian "potret memori". Kode Volatility memang menyediakan fungsi timeline untuk pslist dan psscan [S7][S8].

**Kapan gagal:** membandingkan CreateTime UTC dari Volatility dengan waktu WIB di case notes tanpa konversi, lalu melaporkan "proses muncul tujuh jam sebelum akuisisi".

### 2.8 Jawaban tertulis untuk Dimas

Langkah terakhir menyatukan bagian 2.1 sampai 2.7 menjadi jawaban yang bisa dibaca Dimas tanpa membuka keluaran Volatility. Dikirim Kamis 14:30, disimpan di `\\jkt-evid01\cases\INC-2026-019\notes\memori-E01-dasar-2026-10-29.md`.

```
INC-2026-019 | Analisis memori dasar E01 + status E08/E13 | Kamis 2026-10-29
Dari: <kamu> (L2 forensik) | Untuk: Dimas Prasetyo (IC)
Alat: Volatility 3 2.28.2 (dibekukan untuk kasus), symbol pack windows.zip v0.0.1, di jkt-dfir02.
Bahan: E01-W1 (hash cocok master ab61...), case notes Yoga, CoC E08/E13, CSV event log E15-W1.
Semua waktu WIB (UTC+7). Hasil di analysis/E01-W1/vol3-2.28.2/.

1. KUALITAS IMAGE
- E01 (JKT-WS-0388): WinPmem raw dari USB-E-07, Selasa 12:42:07-12:52:41, hash di laptop 12:53:40. Baik.
  Ukuran 19,3 GB (> RAM 16 GB) cocok dengan rentang memori di konsol (celah di bawah 4 GB diisi nol).
- E08 (BDG-WS-0142): WinPmem dari USB-E-09 oleh Fajar, 14:05:02-14:13:01, hash di laptop 14:19:30.
- E13 (JKT-WS-0412): WinPmem dari USB-E-10 oleh Yoga, 17:45:04-17:58:12, hash di SOC 18:41
  (celah 43 menit ditutup custody USB). Diambil setelah port switch mati: tidak ada koneksi C2 hidup.
- Ketiganya diambil 5 sampai 21,5 jam setelah infeksi di host masing-masing. Proses lampiran dan
  apa pun yang sudah selesai sebelum Selasa siang tidak bisa diharapkan ada.

2. TERBACA DAN PROFIL
- E01 terbaca dengan symbol dari pack offline. Windows 11 x64 edisi workstation, build 23H2.
  Jam host konsisten dengan catatan Yoga.

3. PROSES SAAT E01 DIAMBIL (184 aktif)
- Andi (sesi 1): explorer, OneDrive, Outlook (sejak Senin pagi), Excel (Selasa 08:23).
- Penyerang: satu powershell.exe dari task \SysCacheUpdate (12:51:02), di sesi Andi dengan nama Andi,
  induk layanan Task Scheduler. Tidak ada proses penyerang lain.
- Yoga (sesi 2, ir-admin): explorer, cmd, WinPmem. Semua cocok dengan event log dan case notes.
- Credential Guard aktif (LsaIso.exe di samping lsass.exe). Tidak ada lsass kedua, tidak ada proses
  berinduk lsass, tidak ada nama samaran.

4. YANG DIJALANKAN PENYERANG
- powershell.exe -NoProfile -WindowStyle Hidden -File ...\SysCache\upd.ps1, sama dengan task sejak Senin.

5. PROSES YANG SUDAH BERAKHIR
- Terlihat sebagian: run task 12:36:02-12:36:44 dan jejak Switch user Yoga. Rantai Senin sore
  (wscript 5820, powershell -enc 6136) tidak ada; itu diharapkan setelah 20 jam, bukan bantahan
  atas event log.

6. KALIMAT RETAINER
- Boleh: "Di E01 (Selasa 12:42-12:52) tidak ada proses tak dikenal atau alat dump kredensial;
  satu-satunya proses penyerang adalah satu run upd.ps1 di sesi Andi."
- Tidak boleh: "tidak ada akses ke LSASS selama insiden". E01 tidak bisa menjawab Senin malam.
- Konteks: penyerang bekerja dengan hak pengguna biasa Andi; Credential Guard aktif;
  password svc_billing diambil dari file skrip, bukan dari LSASS.
- Pemeriksaan handle ke LSASS dan injeksi kode: besok (Jumat).
```

**Kapan gagal:** jawaban yang hanya berisi "kami setuju dengan retainer" tanpa jendela waktu. Kalimat itu akan dibaca sebagai "tidak ada pencurian kredensial dari memori selama insiden", yang tidak bisa didukung image Selasa siang.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** VM korban `LAB-WS01` (`172.16.50.10`, Windows 11 dengan Sysmon, snapshot `bersih-2026-10-15`) dengan akun pengguna biasa `lab.user` dan admin lokal `lab.ir`; disk virtual kedua `LAB-USB` berisi `winpmem_mini_x64.exe` di folder `tools\` (hash dicatat); VM analisis `LAB-DFIR01` (`172.16.50.20`) dengan Volatility 3 2.28.x di virtualenv dan symbol pack Windows offline yang hash-nya sudah diverifikasi; jaringan host-only `172.16.50.0/24`. Folder kasus lab `CASE-2026-LAB-014`. Semua aktivitas jinak.

1. **Siapkan aktivitas.** Di `LAB-WS01`, login sebagai `lab.user`, buka Notepad dan Edge. Daftarkan task `\LabTask14` di sesi `lab.user` dengan token interaktif yang setiap 5 menit menjalankan `powershell.exe -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 120"`. Catat jam setiap langkah.
2. **Akuisisi live (M1).** Kunci layar, masuk lewat Switch user sebagai `lab.ir`, buka Command Prompt sebagai administrator, lalu jalankan `E:\tools\winpmem_mini_x64.exe E:\CASE-2026-LAB-014\LAB014-M1_LAB-WS01.raw`. Atur waktunya supaya satu run `\LabTask14` dimulai di tengah akuisisi. Salin konsol (rentang memori, jam mulai dan selesai) ke catatan, lalu `certutil -hashfile ... SHA256`.
3. **Akuisisi dari hypervisor (M2).** Tanpa mengubah apa pun di guest, suspend VM dan salin file memori VM (`.vmem` atau setara di hypervisor-mu) sebagai `LAB014-M2_LAB-WS01.vmem`. Hash di host.
4. **Pindahkan ke analisis.** Pindahkan kedua image ke `LAB-DFIR01` lewat disk virtual, verifikasi hash, dan buat salinan kerja read-only.
5. **Ukuran dan rentang.** Hitung alamat tertinggi dari rentang di konsol M1 dan bandingkan dengan ukuran file (bagian 2.1). Bandingkan juga dengan ukuran M2.
6. **windows.info.** Jalankan di M1 dan M2 dengan log `-v -l` (bagian 2.2). Catat `Symbols`, `Major/Minor`, dan `SystemTime`, lalu letakkan `SystemTime` M1 di jendela mulai sampai selesai.
7. **Daftar proses.** Jalankan pslist, pstree, dan psscan di M1 (bagian 2.3 sampai 2.5). Temukan run task yang dimulai di tengah akuisisi dan bandingkan CreateTime-nya dengan `SystemTime`. Catat proses yang hanya ada di psscan dan ExitTime-nya.
8. **Command line dan pemilik.** Jalankan cmdline dan sessions (bagian 2.6). Catat Session Type untuk proses task dan untuk proses yang dibuka dari Explorer, lalu periksa `windows.envars` untuk proses task: apakah `SESSIONNAME` ada.
9. **Korelasi.** Ekspor Sysmon dan TaskScheduler/Operational dari `LAB-WS01`, lalu buat tabel seperti bagian 2.7: setiap proses penting dengan PID, detik, dan pasangan event.
10. **Jawaban tertulis.** Tulis satu paragraf gaya bagian 2.8 untuk M1: apa yang ada di jendela, apa yang tidak mungkin ada, dan kalimat yang dilarang.

**Hasil yang sebaiknya tersimpan:**

- Image M1 dan M2 beserta hash, konsol WinPmem, dan catatan jam setiap langkah.
- Hitungan ukuran file M1 terhadap rentang memori, dengan penjelasan selisih terhadap RAM.
- Log `windows.info` untuk kedua image, dengan `SystemTime` M1 diletakkan di jendela akuisisi.
- CSV pslist, psscan, cmdline, dan teks pstree serta sessions di folder yang memuat versi Volatility.
- Bukti smear: run task dengan CreateTime setelah `SystemTime` M1, atau alasan kenapa tidak terlihat.
- Hasil uji `SESSIONNAME` untuk proses task, sebagai dasar memakai Session Type di laporan.
- Tabel korelasi memori ke event log dan satu paragraf jawaban tertulis.

**Variasi tantangan:** setelah M1, biarkan VM bekerja satu jam dengan banyak proses singkat (misalnya skrip jinak yang membuka dan menutup Notepad 200 kali), lalu ambil M3 dan jalankan psscan. Bandingkan proses berakhir yang masih ditemukan di M1 dan M3, dan tulis kalimat yang menjelaskan kenapa psscan bukan mesin waktu. Variasi kedua: pindahkan sementara symbol pack dari direktori symbols di `LAB-DFIR01` (tanpa internet), jalankan `windows.info` dengan `-v`, dan simpan pesan error yang menyebut nama PDB dan GUID sebagai contoh untuk troubleshooting.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat menerima image memori dan menjalankan plugin dasar. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| windows.info gagal | Symbol tidak cocok; image rusak/smear | Cek versi OS; pastikan symbol; coba image dari snapshot |
| Log menyebut library symbol tidak ditemukan dan menyarankan `pdbconv.py` | Build kernel tidak tercakup symbol pack; mesin tanpa internet | Jendela proxy ke Microsoft Symbol Server atau konversi PDB di mesin lain dengan nama dan GUID dari log [S14] |
| Plugin tidak ditemukan | Nama pindah antar versi (mis. malfind) | Cek `vol -h`; gunakan `windows.malware.*` sejak 2.26.2 [S2][S6] |
| psscan jauh lebih banyak dari pslist | Proses terminated di pool | Normal; selisih = kandidat, bukan pasti tersembunyi; lihat ExitTime |
| Plugin lambat | Image besar; scanning; image dibaca lewat SMB | pslist cepat; psscan/filescan lambat (wajar); salin image ke disk lokal workstation analisis |
| cmdline kosong untuk proses | Proses sistem, PEB ter-page out, atau proses sudah dibersihkan | Tidak semua proses punya command line terbaca; ambil dari Sysmon 1 atau 4688 dan sebut sumbernya |
| Image tidak terbaca sama sekali | Format tidak didukung | Cek format (raw/AFF4/crash) vs dukungan versi, perlu dicek |
| Ukuran file raw lebih besar dari RAM | Celah alamat fisik diisi nol | Normal bila sama dengan alamat tertinggi di daftar rentang konsol |
| Ukuran file raw lebih kecil dari alamat tertinggi | Akuisisi terputus (media penuh, USB tercabut) | Perlakukan image sebagai tidak lengkap; catat; hash tidak menolong |
| Proses lebih muda dari `SystemTime` image | Smear: halaman dibaca pada waktu berbeda | Normal di akuisisi live; letakkan `SystemTime` dan CreateTime di jendela mulai sampai selesai |
| Waktu proses tampak tujuh jam meleset | Volatility menulis UTC, catatan memakai WIB | Konversi sekali di tabel korelasi; beri label zona waktu di setiap keluaran |

## 5. Kesalahan umum dan jebakan

- **Menganalisis image di disk yang sama dengan sumber.** Tulis ke media terpisah; hash segera.
- **Melewati windows.info.** Jalankan dulu untuk memverifikasi image dan symbol; simpan lognya sebagai bagian case notes.
- **Mengira nama plugin sama antar versi.** Volatility 3 sejak 2.26.2 memindahkan sebagian plugin ke `windows.malware.*`; cek daftar plugin [S2][S6].
- **Menyimpulkan penyembunyian hanya dari selisih psscan-pslist.** Bisa proses terminated; lihat ExitTime, lalu konfirmasi dengan `windows.malware.psxview` (Day 15).
- **Mengabaikan smear.** Image live bisa tidak konsisten; untuk belajar, image snapshot lebih bersih. Untuk kasus, setiap struktur dibaca sebagai keadaan di suatu titik dalam jendela akuisisi.
- **Memperlakukan `SystemTime` sebagai waktu potret.** Ia jam sistem saat satu halaman dibaca; jendela yang benar adalah mulai sampai selesai di case notes.
- **Memakai psscan sebagai mesin waktu.** "Tidak ditemukan di psscan" tidak berarti "tidak pernah berjalan", dan yang ditemukan tidak ditentukan umurnya.
- **Memakai nama pengguna untuk memisahkan pelaku.** Loader penyerang di task berjalan dengan nama pengguna korban; pisahkan dengan induk, command line, dan event log.
- **Mengurutkan proses berdasarkan PID.** PID dipakai ulang; urutkan berdasarkan CreateTime.
- **Membaca `LsaIso.exe` sebagai LSASS kedua.** Itu proses terisolasi Credential Guard; anomali adalah `lsass.exe` kedua atau `lsass.exe` dengan proses anak.
- **Memperluas kesimpulan satu image ke seluruh insiden.** "Tidak ditemukan di E01" berlaku untuk jendela E01, bukan untuk Senin malam.
- `[komunitas, belum terkonfirmasi]` Praktisi memakai image dari VM snapshot untuk belajar karena bebas smear, dan selalu menjalankan windows.info lebih dulu. Nama service driver WinPmem (`pmem`) dan file driver sementara berawalan `pme` berasal dari laporan pengguna di issue tracker [S21]; cocokkan dengan versi toolkit di lab sebelum dipakai di laporan.

## 6. Catatan terkini

Bagian ini menampung detail versi dan sumber yang bisa berubah; tidak mengubah alur analisis di atas.

- **Volatility 3 2.28.2 (17 September 2026)** masih rilis stabil terbaru per 2026-10-22, sama dengan versi yang dibekukan untuk `INC-2026-019`, jadi tidak ada keputusan update. Catatan rilisnya menyebut verifikasi layer Intel Windows lewat pemeriksaan translasi, renderer Mermaid untuk relasi pohon, dan peringatan deprecation untuk analisis macOS, tanpa perubahan nama plugin Windows [S6]. Pemindahan plugin ke subpaket `malware` terjadi di 2.26.2; nama lama masih berjalan dengan pengingat deprecation dan direncanakan dihapus sekitar satu tahun setelahnya [S6]. Bila nama lama dihapus di rilis berikutnya, skrip PT JAB yang masih memakai nama lama perlu diperbarui saat pembekuan versi dibuka.
- **Kolom plugin** di cabang pengembangan: `pslist` versi 3.0.1 dengan opsi `--pid`, `--physical`, `--dump` [S7]; `psscan` memakai offset virtual secara bawaan dengan opsi `--physical` [S8]; `pstree` menambah kolom Audit, Cmd, dan Path [S9]; `sessions` mengambil nama pengguna dari environment variable [S11]. Kolom bisa berbeda dari versi yang dibekukan; cocokkan dengan `vol <plugin> -h` di `jkt-dfir02`.
- **Opsi CLI `--offline`** didefinisikan untuk tidak mencari file JSON tambahan secara online [S13], tetapi kode unduhan PDB yang diperiksa tidak memeriksanya [S14]. Isolasi jaringan tetap pengaman utama.
- **WinPmem:** halaman rilis menandai 4.0 RC2 sebagai Latest; rilis itu memulihkan imager `mini` yang hanya menghasilkan raw, memperbaiki pemuatan driver di Windows terbaru, dan menyarankan `go-winpmem_amd64_1.0-rc2_signed.exe` (imager Go dengan kompresi Snappy, S2, atau Gzip) untuk produksi [S15]. Rilis 4.1 masih pre-release dengan driver test-signed yang mengharuskan test signing diaktifkan, sehingga tidak cocok untuk host produksi [S15]. Tahun rilis tidak tercantum di halaman yang diperiksa. Toolkit PT JAB memakai `winpmem_mini_x64.exe`; menguji `go-winpmem` di lab sebelum kasus berikutnya adalah usulan, bukan keputusan.
- **Credential Guard:** halaman Microsoft Learn (ms.date 2026-04-27) menyebut aktivasi bawaan sejak Windows 11 22H2 dan Windows Server 2025 untuk perangkat yang memenuhi syarat, tanpa UEFI lock, dan tidak menimpa konfigurasi yang sudah dinonaktifkan secara eksplisit sebelum update [S17].
- **Windows 11 23H2** dipasang lewat enablement package di atas 22H2; keduanya berbagi set file sistem yang identik [S18].
- **Velociraptor 0.77.3:** artifact `Windows.Memory.Acquisition` memakai driver WinPmem bawaan dengan parameter `ServiceName`, `DriverPath`, dan `Compression` [S19].

## 7. Cheat sheet

```
AKUISISI   WinPmem | Magnet RAM Capture | FTK Imager | DumpIt ; tulis ke media TERPISAH ; hash segera ; memori dulu (OOV)
           winpmem_mini_x64.exe <out.raw>  (raw saja) ; catat MULAI dan SELESAI = jendela smear
           VM lab: suspend + .vmem (bebas smear) ; agen: Velociraptor Windows.Memory.Acquisition
UKURAN     raw = alamat fisik tertinggi (celah diisi nol) ; > RAM itu normal ; < alamat tertinggi = terputus
SMEAR      halaman dibaca rendah->tinggi selama menit ; proses bisa lebih muda dari SystemTime
VOL3       vol [-q -v -l log -r csv -f img] <plugin> [--pid N] ; symbol table (ISF), BUKAN profil
           symbol: GUID/age PDB ; pack offline ; cache ~/.cache/volatility3 ; pdbconv.py ; --offline bukan pengaman
INFO       windows.info DULU: Symbols | Major/Minor | NtProductType | SystemTime (UTC, satu halaman)
PROSES     windows.pslist (aktif) | windows.pstree (hierarki, akar = induk sudah berakhir) | windows.psscan (pool scan)
           psscan - pslist = berakhir (ExitTime) atau tersembunyi (cek psxview Day 15)
           psscan BUKAN mesin waktu: tidak ditemukan != tidak pernah ada
CMDLINE    windows.cmdline (PEB; hanya proses pslist) -> apa persisnya
PEMILIK    windows.sessions (SessionId + USERNAME dari environment) ; SID token: getsids (Day 15)
           pisahkan pelaku: sesi + induk + command line + event log, BUKAN nama pengguna
BASELINE   smss>System | csrss/wininit/winlogon induk smss yg sudah keluar | services,lsass,LsaIso<wininit
           svchost<services | explorer<userinit yg sudah keluar | LsaIso = Credential Guard, bukan LSASS kedua
VERSI      2.26.2+: malfind/psxview/hollowprocesses -> windows.malware.* ; cek vol -h
KORELASI   PID + CreateTime + cmdline vs Sysmon 1/4688/Task 200-201 ; UTC vs WIB (+7) ; SystemTime -> timeline
BATAS      snapshot jendela | symbol harus cocok | smear | akuisisi ubah memori | tidak bisa jawab sebelum jendela
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Di E01, `wscript.exe` 5820 dan `powershell.exe` 6136 tidak ada di pslist maupun psscan. Jadi event log yang menyebut lampiran dijalankan Senin sore perlu diragukan." Benarkah?

<details><summary>Jawaban</summary>

Tidak. E01 diambil Selasa 12:42 sampai 12:52, sekitar 20,5 jam setelah kedua proses itu berakhir. Psscan hanya menemukan sisa struktur yang kebetulan belum tertimpa, dan yang bertahan ditentukan pemakaian ulang memori, bukan umur: di image yang sama psscan menemukan `svchost.exe` dari Senin 08:12 tetapi tidak menemukan rantai Senin sore. Laptop terus bekerja dan task membuat serta mengakhiri puluhan proses PowerShell setelahnya. Ketiadaan di memori adalah hasil yang diharapkan dan tidak membantah Sysmon 1 di E15. Lihat bagian 1.6 dan 2.5.

</details>

**2. Skenario keputusan.** `windows.info` E01 menunjukkan `SystemTime` 2026-10-13 05:47:36 UTC (12:47:36 WIB), tetapi `pslist` memuat `powershell.exe` 12408 yang dibuat 12:51:02 WIB. Retainer bertanya apakah image ini rusak atau jam laptop diubah penyerang. Jawaban mana yang tepat?

- A. Image rusak karena memuat proses dari masa depan; minta retainer berhenti memakai E01.
- B. Itu smear: akuisisi berlangsung 12:42:07 sampai 12:52:41 dan halaman dibaca berurutan, sehingga halaman jam dibaca di tengah jendela dan halaman struktur proses 12408 dibaca menjelang akhir. Jam host konsisten karena `SystemTime` jatuh di dalam jendela di case notes, dan event 201 run itu tercatat 12:53:19.
- C. Jam laptop terlambat sekitar tiga setengah menit; koreksi semua waktu di image dengan selisih itu.

<details><summary>Jawaban</summary>

B. `SystemTime` adalah jam sistem pada saat satu halaman dibaca, bukan waktu potret, dan akuisisi live membaca halaman pada waktu berbeda selama sepuluh menit. Proses yang "lebih muda" dari `SystemTime` adalah tanda smear yang normal. A keliru karena smear tidak membuat image tidak berguna, hanya mengubah cara membacanya. C keliru karena tidak ada bukti jam host salah: `SystemTime` cocok dengan jendela di case notes dan CreateTime proses responder cocok detik demi detik dengan event log. Lihat bagian 1.2, 1.4, dan 2.2.

</details>

**3. Pertanyaan jebakan.** "File `E01_JKT-WS-0388_mem.raw` berukuran 19.318.964.224 byte, padahal RAM laptop 16 GB. Berarti WinPmem ikut mengambil pagefile atau file-nya rusak." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Di file raw, offset sama dengan alamat fisik. Konsol WinPmem mencetak tiga rentang memori, dan rentang terakhir mulai di 4 GiB (`0x100000000`) dengan panjang `0x37F800000`, sehingga alamat tertinggi `0x47F800000` sama dengan 19.318.964.224 byte, persis ukuran file. Celah antara sekitar 1,84 GiB dan 4 GiB dicadangkan untuk perangkat dan diisi nol supaya offset tetap sejajar. Ukuran yang cocok dengan alamat tertinggi justru tanda akuisisi selesai; yang mencurigakan adalah file yang lebih kecil dari alamat tertinggi. Lihat bagian 1.2 dan 2.1.

</details>

**4. Skenario keputusan.** Kamu harus menulis siapa pemilik `powershell.exe` 12408 di E01. Pendekatan mana yang tepat?

- A. `powershell.exe` di laptop staf penagihan pasti penyerang; nama proses cukup.
- B. Gabungkan Session ID 1, induk `svchost.exe` 1948 yang command line-nya `-s Schedule`, command line `upd.ps1` di folder `SysCache`, nama pengguna `JAB/andi.pratama` dari `sessions`, dan pasangan Sysmon 1 serta TaskScheduler 200 pada 12:51:02, lalu tulis: run task penyerang yang berjalan di sesi dan dengan nama Andi.
- C. `windows.sessions` menyebut `JAB/andi.pratama`, jadi Andi sendiri yang menjalankannya.

<details><summary>Jawaban</summary>

B. Pemisahan pelaku di memori memakai kombinasi sesi, induk, command line, dan event log, sama seperti di event log. A keliru karena `powershell.exe` juga dipakai administrator dan skrip sah; nama saja tidak membuktikan apa pun. C keliru karena `sessions` mengambil nama pengguna dari environment variable, dan task yang didaftarkan dengan token interaktif Andi memang berjalan dengan nama Andi; yang membedakannya adalah induk layanan Task Scheduler dan skrip `upd.ps1`. Lihat bagian 1.7 dan 2.6.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Dimas, dalam tiga kalimat, kenapa kalimat retainer "tidak menemukan akses ke LSASS" di E01 tidak bisa dipakai untuk menyimpulkan bahwa Senin malam aman dari pencurian kredensial.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "E01 hanya memotret laptop Andi Selasa 12:42 sampai 12:52, jadi kalimat retainer berlaku untuk sepuluh menit itu, sedangkan pencarian password dan SSH terjadi Senin 23:40 dan Selasa 02:14 di proses yang sudah lama berakhir dan tidak ada lagi di memori. Di jendela itu kita memang tidak melihat proses tak dikenal atau alat dump, satu-satunya proses penyerang adalah satu run `upd.ps1`, dan pemeriksaan handle ke LSASS dilakukan besok. Lagi pula password `svc_billing` dicuri dari file skrip, bukan dari LSASS, penyerang hanya punya hak pengguna biasa Andi, dan Credential Guard aktif, jadi pertanyaan LSASS tidak mengubah penilaian dampak."

Kesalahan yang sering muncul:
- Menulis "memori membuktikan tidak ada pencurian kredensial dari memori" tanpa jendela waktu.
- Lupa bahwa kredensial yang dicuri berasal dari file, sehingga fokus pada LSASS mengalihkan dari jalur yang sebenarnya.
- Menganggap Credential Guard melindungi semua akun, padahal akun lokal di SAM tidak dilindunginya.

</details>

**6. Pertanyaan jebakan.** "`pslist` E01 menunjukkan `lsass.exe` 844 dan `LsaIso.exe` 836, keduanya anak `wininit.exe`. Dua proses LSA di satu host adalah anomali yang harus dilaporkan." Benarkah?

<details><summary>Jawaban</summary>

Tidak. `LsaIso.exe` adalah proses terisolasi Credential Guard, yang memakai virtualization-based security untuk mengisolasi hash NTLM, Kerberos TGT, dan kredensial domain yang disimpan aplikasi. Sejak Windows 11 22H2, Credential Guard aktif secara bawaan di perangkat Enterprise atau Education yang memenuhi syarat hardware dan tidak dinonaktifkan secara eksplisit. Anomali yang dicari adalah `lsass.exe` kedua, `lsass.exe` dengan induk lain, atau proses yang berinduk `lsass.exe`. Lihat bagian 1.5 dan 2.4.

</details>

**7. Interview question (English).** "You're handed a memory image someone else acquired from a Windows laptop during an incident. What do you check before trusting any plugin output, and what can that image never tell you?"

<details><summary>Sample answer</summary>

"First I check the acquisition itself, not the image: which tool and version, who ran it under which account, the start and end times, where the hash was computed, and whether the host was isolated. The start-to-end window is my smear window, so I treat every structure as the state at some point inside it. I verify the working copy's hash against the master, then compare the file size with the memory ranges the tool printed, because a raw file is padded to the highest physical address and a short file means a broken acquisition. Then I run windows.info with logging to confirm the symbol table matches and to place SystemTime inside the acquisition window. Only after that do I list processes with pslist and pstree, compare with psscan for exited or unlinked processes, and pull command lines and sessions, separating user, attacker, and responder by session, parent, and command line, then matching PIDs and seconds against Sysmon or 4688. What the image can never tell me is anything before that window: a process that ended hours earlier is usually gone, so absence in memory is not evidence it never ran, and I write every finding with its time window."

What makes this answer strong: it starts from acquisition quality and custody rather than tooling, explains smear and padding in practical terms, uses windows.info as a gate, separates actors by evidence instead of user names, and states the time-window limit that keeps a finding from being overstated.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Volatility 3 documentation (termasuk halaman Symbol Tables) dan releases (2.28.2, 17 September 2026) | https://volatility3.readthedocs.io/en/latest/symbol-tables.html | primer | 2.28.2; diakses 2026-10-10, dicek ulang 2026-10-22 | Tinggi. Symbol table, cache, unduh PDB, versi; format `.json`, `.json.gz`, `.json.xz`, ZIP; `pdbconv.py` |
| S2 | Volatility 3 Windows plugins (daftar modul) | https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html | primer | diakses 2026-10-09, dicek ulang 2026-10-22 | Tinggi. Nama plugin; subpaket `windows.malware.*` (malfind, psxview, hollowprocesses); `pslist`, `pstree`, `psscan`, `cmdline`, `sessions`, `getsids`, `info` di `windows.*` |
| S3 | Tool akuisisi memori (WinPMEM/Magnet/FTK/DumpIt); README WinPmem | https://github.com/Velocidex/WinPmem | primer | diakses 2026-10-09, dicek ulang 2026-10-22 | Sedang-tinggi. Akuisisi; `winpmem_mini` imager raw, driver 32/64-bit dimuat otomatis dan dibongkar setelah selesai; sintaks `winpmem_mini_x64.exe physmem.raw` |
| S4 | Endpoint-Forensics Day 01-02 (order of volatility, lab, hashing) | (lokal) | rujukan internal | 2026-10-09 | Akuisisi dan kebersihan bukti |
| S5 | Endpoint-Forensics Day 05, 07, 13 (korelasi disk dan timeline) | (lokal) | rujukan internal | 2026-10-09 | Korelasi memori-disk |
| S6 | GitHub: volatilityfoundation/volatility3 releases | https://github.com/volatilityfoundation/volatility3/releases | primer | 2.28.2 (17 Sep, Latest); diakses 2026-10-22 | Tinggi. 2.28.2 rilis terbaru tanpa pre-release lebih baru; isi catatan 2.28.2; pemindahan plugin ke subpaket `malware` di 2.26.2 dan rencana penghapusan nama lama |
| S7 | GitHub: volatility3 `plugins/windows/pslist.py` (cabang develop) | https://raw.githubusercontent.com/volatilityfoundation/volatility3/develop/volatility3/framework/plugins/windows/pslist.py | primer (source) | versi plugin 3.0.1; diakses 2026-10-22 | Tinggi untuk cabang develop. Opsi `--pid`, `--physical`, `--dump`; urutan kolom; fungsi timeline |
| S8 | GitHub: volatility3 `plugins/windows/psscan.py` (cabang develop) | https://raw.githubusercontent.com/volatilityfoundation/volatility3/develop/volatility3/framework/plugins/windows/psscan.py | primer (source) | diakses 2026-10-22 | Tinggi untuk cabang develop. Pool scanner dengan tag `Proc`; ExitTime tidak disaring; offset virtual bawaan; objek tidak valid dilewati |
| S9 | GitHub: volatility3 `plugins/windows/pstree.py` (cabang develop) | https://raw.githubusercontent.com/volatilityfoundation/volatility3/develop/volatility3/framework/plugins/windows/pstree.py | primer (source) | diakses 2026-10-22 | Tinggi untuk cabang develop. Pohon berdasarkan PPID; `--pid` dengan leluhur dan keturunan; kolom Audit, Cmd, Path; proses tanpa induk menjadi akar |
| S10 | GitHub: volatility3 `plugins/windows/cmdline.py` (cabang develop) | https://raw.githubusercontent.com/volatilityfoundation/volatility3/develop/volatility3/framework/plugins/windows/cmdline.py | primer (source) | diakses 2026-10-22 | Tinggi untuk cabang develop. Membaca `_PEB.ProcessParameters.CommandLine`; memakai pslist; nilai tidak terbaca dan pesan di log debug |
| S11 | GitHub: volatility3 `plugins/windows/sessions.py` (cabang develop) | https://raw.githubusercontent.com/volatilityfoundation/volatility3/develop/volatility3/framework/plugins/windows/sessions.py | primer (source) | diakses 2026-10-22 | Tinggi untuk cabang develop. User Name dari `USERDOMAIN`/`USERNAME`, Session Type dari `SESSIONNAME`, Session ID dari struktur proses |
| S12 | GitHub: volatility3 `plugins/windows/info.py` (cabang develop) | https://raw.githubusercontent.com/volatilityfoundation/volatility3/develop/volatility3/framework/plugins/windows/info.py | primer (source) | diakses 2026-10-22 | Tinggi untuk cabang develop. Urutan baris keluaran; `SystemTime` dari `_KUSER_SHARED_DATA`; `Major/Minor` dari `KdVersionBlock` |
| S13 | GitHub: volatility3 `cli/__init__.py` (cabang develop) | https://raw.githubusercontent.com/volatilityfoundation/volatility3/develop/volatility3/cli/__init__.py | primer (source) | diakses 2026-10-22 | Tinggi untuk cabang develop. Opsi global `-f`, `-r` (bawaan `quick`), `-o`, `-q`, `-l`, `-v`, `-s`, `--offline`, `--cache-path`, `--clear-cache` |
| S14 | GitHub: volatility3 `symbols/windows/pdbutil.py` (cabang develop) | https://raw.githubusercontent.com/volatilityfoundation/volatility3/develop/volatility3/framework/symbols/windows/pdbutil.py | primer (source) | diakses 2026-10-22 | Tinggi untuk cabang develop. Unduh PDB tanpa memeriksa opsi offline; pesan saran `pdbconv.py` dengan nama PDB dan GUID |
| S15 | GitHub: Velocidex/WinPmem releases | https://github.com/Velocidex/WinPmem/releases | primer | 4.0 RC2 (Latest), 4.1 dev (pre-release); tahun tidak tercantum; diakses 2026-10-22 | Tinggi untuk isi catatan rilis. Imager `mini` raw, Fast IO, `go-winpmem` dengan kompresi; 4.1 butuh test signing |
| S16 | Pagani, Fedorov, Balzarotti: Introducing the Temporal Dimension to Memory Forensics (ACM TOPS 22(2), 2019) | https://www.s3.eurecom.fr/docs/tops19_pagani.pdf | primer (riset, peer-reviewed) | Maret 2019 (lebih dari 24 bulan); diakses 2026-10-22 | Tinggi untuk konsep. Akuisisi berurutan dari alamat rendah ke tinggi, peta memori lewat `MmGetPhysicalMemoryRanges`, smear dan konsistensi waktu, kutipan sekitar satu dari lima dump tidak bisa dipakai |
| S17 | Microsoft Learn: Credential Guard overview | https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/ | primer | ms.date 2026-04-27; diakses 2026-10-22 | Tinggi. Aktivasi bawaan sejak Windows 11 22H2 untuk perangkat yang memenuhi syarat, tanpa UEFI lock; edisi Enterprise/Education; VBS; `LSAIso.exe`; tidak melindungi SAM |
| S18 | Microsoft Support: KB5027397 Feature update to Windows 11, version 23H2 by using an enablement package | https://support.microsoft.com/kb/5027397 | primer | tanggal artikel tidak tercantum; prasyarat KB5031455 (2023-10-31); diakses 2026-10-22 | Tinggi. 22H2 dan 23H2 berbagi inti OS dengan set file sistem identik; build 22621 dan 22631 |
| S19 | Velociraptor: Windows.Memory.Acquisition | https://docs.velociraptor.app/artifact_references/pages/windows.memory.acquisition/ | primer (dokumentasi proyek) | diakses 2026-10-22 | Sedang-tinggi. Driver WinPmem bawaan, `ServiceName`, `DriverPath` bawaan `C:\Windows\Temp\winpmem.sys`, kompresi, peringatan smear; saran update 0.77.3 |
| S20 | SANS ISC: Searching live memory on a running machine with winpmem (Mark Baggett) dan diary sebelumnya tentang winpmem | https://isc.sans.edu/diary/17063 | sekunder (praktisi) | 2013-11-19 dan 2013-11-20 (lebih dari 24 bulan); diakses 2026-10-22 | Sedang. Rentang memori yang dilaporkan driver dan celah yang dipakai prosesor dan chipset; image raw byte demi byte; peringatan menulis image ke disk korban. Versi WinPmem lama |
| S21 | GitHub issue Velocidex/WinPmem #19 | https://github.com/Velocidex/WinPmem/issues/19 | komunitas | diakses 2026-10-22 | Rendah-sedang. Contoh keluaran konsol: driver diekstrak ke file `pme*.tmp`, `service_name: pmem`, mode PTE Remapping, baris jam sistem |

**Catatan sumber:** subpaket `windows.malware.*` (malfind, psxview, hollowprocesses, dan lainnya) tercantum di daftar modul resmi, sedangkan nama pslist, pstree, psscan, dan cmdline adalah nama plugin inti Volatility 3 yang stabil; tetap cocokkan dengan `vol -h` di versimu. Mekanisme symbol (GUID dan age PDB, unduh dari Microsoft Symbol Server, lokasi cache) berasal dari halaman Symbol Tables di dokumentasi resmi. Dukungan format image (AFF4, crash dump, file VM, berkas hibernasi) perlu dicek di lab. Tabel baseline proses normal adalah pengetahuan DFIR yang mapan, tetapi detail jumlah instance bisa berbeda pada edisi Server dan sesi Remote Desktop. Kolom, opsi, dan perilaku plugin [S7]-[S14] dibaca dari source cabang develop, yang bisa sedikit berbeda dari rilis 2.28.2 yang dibekukan; versi plugin `pslist` 3.0.1 berasal dari source itu. Perilaku padding celah alamat di file raw WinPmem adalah penalaran dari daftar rentang dan dari sumber praktisi lama [S20], bukan pernyataan README WinPmem [S3], jadi dibuktikan di lab dengan membandingkan ukuran file dan rentang. Nama service `pmem` dan file driver `pme*.tmp` hanya dari laporan komunitas [S21]. Angka `Major/Minor` yang muncul untuk image Windows 11 23H2 (22621 atau 22631) tidak dikonfirmasi sumber dan dicek di lab. Ketiadaan `SESSIONNAME` di environment proses yang dibuat Task Scheduler adalah dugaan yang diuji di lab. Riset Pagani dkk. [S16] dan diary SANS [S20] berumur lebih dari 24 bulan; konsepnya tidak bergantung versi, tetapi angka "satu dari lima" berasal dari studi yang dikutip di dalamnya, bukan pengukuran pada alat terbaru. Semua isi PT JAB, termasuk PID, offset, jumlah thread, waktu, ukuran file, nilai hash, rentang memori, dan jawaban tertulis, adalah contoh fiktif yang disusun agar konsisten dengan fakta insiden, bukan kejadian nyata.
