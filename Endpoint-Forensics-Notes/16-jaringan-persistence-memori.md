---
day: 16
title: 'Jaringan dan persistence di memori: netscan, netstat, svcscan, registry in-memory, WMI, driver, dan callback'
researched_on: 2026-10-22
versions_checked: 'Volatility 3 2.28.2 (17 Sep 2026, masih rilis stabil terbaru per 2026-10-22; windows.netscan, windows.netstat, windows.svcscan, windows.svclist, windows.malware.svcdiff, windows.registry.hivelist, windows.registry.printkey, windows.registry.scheduled_tasks, windows.driverscan, windows.modules, windows.malware.drivermodule, windows.callbacks, windows.ssdt, windows.filescan, windows.dumpfiles; subpaket windows.malware.* sejak 2.26.2); Windows 11 Enterprise 23H2 (host kasus, build 22631, kernel 22621); Microsoft Defender for Endpoint investigation package (Microsoft Learn ms.date 2026-07-23); Sigcheck (Microsoft Learn, terbit 2026-10-15); MITRE ATT&CK T1543.003, T1547.001, T1546.003 v1.5, T1071.001'
---

# Day 16: Jaringan dan persistence di memori

Cakupan: menautkan koneksi jaringan ke proses pemiliknya dan membaca state service, registry, WMI, driver, dan callback dari image memori, lalu mengonfirmasinya dengan artefak disk dan log jaringan untuk menyusun temuan dan daftar IOC.

## Ide inti

Image memori menyimpan keadaan hidup satu host pada satu detik: struktur koneksi TCP dan UDP beserta proses pemiliknya, daftar service yang dipegang Service Control Manager, hive registry yang sedang termuat, proses penyedia WMI, driver kernel, dan callback yang didaftarkan driver. Itu yang tidak dimiliki disk dan log jaringan. Log firewall tahu `10.10.45.57` menghubungi `203.0.113.205:443`, tetapi tidak tahu proses mana; disk tahu ada service `WinHlpSvc`, tetapi tidak tahu apakah ia sedang berjalan dan menghubungi siapa. Memori menjawab "proses apa, menghubungi apa, dan bertahan lewat apa" dalam satu snapshot. Harga yang dibayar juga jelas: memori hanya memberi satu titik waktu, sebagian struktur yang ditemukan adalah sisa yang sudah dibebaskan tetapi belum ditimpa, dan pemilik sisa itu bisa tidak terbaca. Karena itu setiap temuan memori dibaca dengan tiga pertanyaan: apakah ini keadaan aktif atau sisa, apakah pemiliknya bisa dipastikan, dan sumber lain mana (disk, log jaringan, paket investigasi EDR) yang sepakat.

Kamu sudah mengenal pola ini dari NOC. Saat router bermasalah, engineer mengambil crashinfo atau core dump sebelum reboot karena di sana ada tabel NAT dan conntrack, running-config, dan proses yang sedang jalan, bukan hanya startup-config di flash. Membaca tabel conntrack dari core dump mirip netscan: entri yang aktif terlihat bersama entri yang sudah kedaluwarsa tetapi belum dibersihkan, dan untuk entri lama, informasi siapa pemilik sesinya bisa sudah tidak valid. Running-config yang belum di-`write memory` mirip registry in-memory: bisa berbeda dari file di flash. NetFlow di kolektor mirip log firewall: riwayatnya panjang tetapi tidak tahu proses mana di host yang mengirim. Batasnya: satu core dump tidak membuktikan apa yang terjadi kemarin, dan entri yang tidak ditemukan di dump bukan bukti sesi itu tidak pernah ada.

```
image memori (satu detik, UTC)
  |
  +-- JARINGAN     windows.netscan (scan pool: aktif + sisa) | windows.netstat (struktur aktif tcpip.sys)
  |                -> proses pemilik (PID, Owner), state, Created
  |
  +-- SERVICE      windows.svcscan | windows.svclist | windows.malware.svcdiff (tersembunyi?)
  |
  +-- REGISTRY     windows.registry.hivelist -> printkey (Services, Run) | registry.scheduled_tasks
  |
  +-- WMI          tidak ada plugin khusus: WmiPrvSE.exe + wbemcons.dll | psscan anak | filescan/dumpfiles OBJECTS.DATA
  |
  +-- KERNEL       windows.modules | windows.driverscan | windows.malware.drivermodule | windows.callbacks | windows.ssdt
  |
  v
korelasi: disk (7045, hive, OBJECTS.DATA, MFT) + log jaringan (firewall, proxy) + paket investigasi EDR
  |
  v
temuan + keyakinan + "aktif atau sisa" + "yang tidak terlihat dan kenapa" + daftar IOC
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan dan data pribadi sekitar 400 ribu pelanggan broadband. Kasusnya `INC-2026-017`, ransomware SEV-1 terhadap share `Keuangan` di file server `JKT-FS01` (`10.20.10.21`). Rantainya sudah dibedah dari disk: akses awal lewat server aplikasi lama yang menghadap internet `jkt-dmz-app01` (`10.20.9.20`), beacon ke `sync-win.example.net` (`203.0.113.205:443`), Kamis 2026-10-08 PsExec ke `JKT-WS-0441` (`siti.rahayu`, `10.10.44.41`) lalu RDP dengan akun `budi.santoso` ke `JKT-WS-0457` (`10.10.45.57`), host encryptor. Di `JKT-WS-0457` penyerang memasang dua jalur persistence untuk satu payload `C:\ProgramData\WinHlpSvc\hlpsvc.exe`: service `WinHlpSvc` (Auto, LocalSystem, 7045 Kamis 19:11:30 WIB) dan WMI subscription `HlpFilter`/`HlpConsumer` (`CommandLineEventConsumer`). Jumat 2026-10-09 terjadi exfil sekitar 6 GB dari `JKT-WS-0457` ke `198.51.100.205` pukul 18:40 sampai 20:10 (terlihat di log proxy dan firewall; proses pengirimnya belum teridentifikasi dari disk), tamper antivirus 20:52, lalu enkripsi 21:31:58 sampai 22:17:04. Pukul 23:18 Yoga Pratama mengisolasi `JKT-WS-0457` lewat EDR tanpa mematikannya, dan akun `budi.santoso` dinonaktifkan 23:24. Sabtu 2026-10-10 firewall memblok `203.0.113.205` dan `198.51.100.205`, dan `sync-win.example.net` di-sinkhole. Siang itu Yoga mengambil memori dan paket investigasi kedua workstation; Senin 2026-10-12 keduanya di-image (`E05` dan `E06`), dan post-incident review (PIR) berlangsung Senin 2026-10-26.

Senin 2026-11-02 pukul 09:00, Sari Kusuma (technical lead) menulis kepadamu di kanal `#inc-2026-017`:

> "Pagi. Ini action item PIR 017 yang masih terbuka: sebelum image dan memori dua laptop Keuangan dipindah ke arsip, kita harus pastikan dari memori `JKT-WS-0457` (E01) bahwa tidak ada kanal C2 kedua, tidak ada persistence di tingkat kernel, dan tidak ada service lain yang tidak kelihatan dari disk. Kalau masih ada jejaknya di memori, tolong tautkan proses mana yang bicara ke IP C2 dan ke IP exfil; aku tahu memorinya baru diambil sekitar 16 jam setelah exfil selesai, jadi bilang saja kalau sudah tidak bisa. Satu lagi: tim deteksi minta daftar IOC host dan jaringan dari kasus ini. Tenggat Selasa jam 12:00."

Pesan itu memuat enam pertanyaan:

1. Apakah ada kanal C2 kedua, yaitu proses lain atau tujuan lain yang berkomunikasi ke luar?
2. Proses mana yang berkomunikasi dengan IP C2 dan IP exfil, dan apakah jejaknya masih ada di memori setelah sekitar 16 jam?
3. Apakah ada service lain yang tidak terlihat dari disk?
4. Apakah persistence yang ditemukan di disk (service dan WMI) juga terlihat di memori, dan apakah registry di memori menyimpan sesuatu yang tidak ada di disk?
5. Apakah ada persistence tingkat kernel (driver atau callback yang tidak dikenal)?
6. IOC host dan jaringan apa yang layak diserahkan ke tim deteksi, dan seberapa yakin jawabannya?

Pertanyaan 1 dijawab di bagian 1.1 dan 1.2, pertanyaan 2 di bagian 1.2 dan 1.3, pertanyaan 3 di bagian 1.4, pertanyaan 4 di bagian 1.5 dan 1.6, pertanyaan 5 di bagian 1.7, dan pertanyaan 6 di bagian 1.8. Bagian 2 berisi perintah, keluaran ilustrasi, dan jawaban tertulis yang kamu kirim ke Sari.

**Kapan relevan:** saat image memori sudah ada dan pertanyaannya menyangkut proses pemilik koneksi (C2, exfil, lateral movement), service atau driver yang sedang berjalan, persistence yang mungkin hanya hidup di memori atau disembunyikan dari API biasa, dan saat log jaringan menunjukkan trafik tetapi tidak menunjukkan proses.
**Kapan bukan jawaban:** untuk riwayat koneksi dari waktu ke waktu (itu log firewall, proxy, dan NetFlow), untuk membuktikan sesuatu tidak pernah terjadi sebelum snapshot, untuk isi data yang dikirim, dan sebagai pengganti analisis proses dan injeksi (Day 15) atau akuisisi dan dasar Volatility (Day 14).

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (image memori, symbol table, `windows.info`, PID dan PPID, daftar proses, smear, service, Run key, scheduled task, 7045, WMI event subscription, `OBJECTS.DATA`, hive, last write time, hive kotor, jejak responder, salinan kerja) tidak diulang. Tabel berikut hanya memuat istilah baru Day ini. Kolom padanan memakai analogi NOC dan SOC yang sama di semua Day.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Pool scanning | Mencari struktur kernel di memori berdasarkan tag alokasi pool, termasuk struktur yang sudah dibebaskan tetapi belum ditimpa | Membaca tabel conntrack dari core dump, termasuk entri kedaluwarsa yang belum dibersihkan |
| List walking | Mengikuti daftar atau tabel yang sedang dipakai kernel, sehingga hanya objek aktif yang terlihat | `show ip nat translations` di perangkat hidup |
| TCP endpoint dan state | Objek koneksi TCP beserta keadaannya: `LISTENING`, `SYN_SENT`, `ESTABLISHED`, `CLOSED`, dan lainnya | State sesi di tabel firewall stateful |
| Owner (proses pemilik) | Proses yang membuat socket atau koneksi; di Volatility kolom `PID` dan `Owner` | Pemetaan sesi ke user di accounting RADIUS |
| Service Control Manager (SCM) | Komponen Windows di `services.exe` yang menyimpan daftar service dan state-nya di memori | Daemon supervisor yang memegang daftar proses terkelola |
| Hidden service | Service yang ada di memori SCM tetapi dilepas dari daftar yang dibaca API, sehingga tidak muncul di alat biasa | Proses yang berjalan tetapi disembunyikan dari `show processes` |
| Volatile key | Key registry yang hanya ada di memori dan tidak pernah ditulis ke file hive | Konfigurasi runtime yang tidak pernah masuk startup-config |
| Driver object | Struktur kernel yang mewakili driver termuat, dengan alamat awal, ukuran, dan nama service | Modul line card yang terdaftar di chassis |
| Kernel callback | Fungsi yang didaftarkan driver agar dipanggil kernel saat kejadian tertentu (proses dibuat, image dimuat, registry diubah) | Hook di control plane yang dipanggil setiap event, seperti EEM applet |
| Rootkit | Kode yang memodifikasi sistem (sering di kernel) untuk menyembunyikan proses, file, koneksi, atau service | Firmware termodifikasi yang menyembunyikan sesi dari perintah `show` |
| Beacon | Koneksi berulang dari implant ke server C2 dengan interval yang relatif teratur | Polling SNMP berkala dari perangkat ke NMS, dengan jitter |
| IOC (indicator of compromise) | Nilai atau pola yang menandai kompromi: hash, path, nama service, IP, domain, perilaku | Daftar MAC atau IP yang diblok setelah insiden |

### 1.1 Koneksi jaringan di memori: netscan dan netstat

Pertanyaan pertama Sari ("ada kanal C2 kedua?") diawali dengan mendaftar semua koneksi dan socket yang masih bisa ditemukan di image `JKT-WS-0457`, lalu menyaring tujuan di luar jaringan PT JAB. Volatility 3 punya dua plugin untuk ini, dan keduanya bekerja dengan cara yang berbeda.

Tabel berikut membandingkan keduanya; baca kolom "Cara kerja", karena dari situlah perbedaan hasil keduanya bisa dijelaskan.

| Plugin | Cara kerja | Memberi | Catatan |
|---|---|---|---|
| `windows.netscan` | Pool scanning untuk tag `TcpL` (listener), `TcpE` (endpoint TCP), dan `UdpA` (endpoint UDP) [S6] | Koneksi dan socket TCP/UDP dengan proses pemilik, termasuk yang sudah tutup bila strukturnya belum ditimpa [S1] | Bisa menampilkan sisa lama; perhatikan state dan konteks |
| `windows.netstat` | Menelusuri tabel partisi `tcpip.sys` dan port pool yang sedang dipakai [S7] | Koneksi dan listener dari struktur aktif | Lebih dekat ke state aktif; butuh symbol table `tcpip.sys` [S7] |

netscan menautkan koneksi ke proses (PID, nama), menjawab "proses apa menghubungi IP apa" tanpa log jaringan [S1]. Ini kuat untuk C2: koneksi keluar ke IP eksternal dari proses mencurigakan terlihat langsung di memori. Karena memindai memori, netscan bisa menemukan koneksi yang baru tutup (struktur belum ditimpa), tetapi juga bisa menampilkan sisa lama; perhatikan state dan konteks.

Kolom keluaran kedua plugin sama: `Offset`, `Proto`, `LocalAddr`, `LocalPort`, `ForeignAddr`, `ForeignPort`, `State`, `PID`, `Owner`, `Created` [S6][S7]. Listener selalu tampil sebagai `LISTENING` dengan foreign port 0, dan endpoint UDP tampil tanpa state dengan foreign address `*` [S6]. `Created` diambil dari waktu pembuatan objek dan ditulis dalam UTC; nilai di luar rentang wajar dianggap tidak valid dan ditampilkan sebagai `N/A` [S6][S25]. Untuk koneksi, praktisi lama mendeskripsikan waktu ini sebagai saat socket di-bind atau koneksi dibentuk, bukan saat koneksi ditutup [S23].

Dua detail cara kerja yang mengubah cara membaca hasil:

- **netscan memakai tabel struktur bawaan per build.** Plugin memilih tabel offset struktur `tcpip.sys` berdasarkan versi kernel. Tabel x64 bawaan berhenti di build 20348; untuk build yang lebih baru tanpa entri khusus, plugin memakai tabel terbaru dengan versi NT yang sama, dan komentar kodenya sendiri menyebut bahwa bila hasilnya tidak cocok, dukungan harus ditambahkan [S6]. Untuk host Windows 11 seperti `JKT-WS-0457`, artinya netscan berjalan dengan tabel terdekat, dan hasilnya perlu divalidasi dengan sumber kedua (netstat dan paket investigasi EDR).
- **netstat memakai symbol table `tcpip.sys` dari PDB.** netstat membaca simbol `tcpip!PartitionTable` dan `tcpip!PartitionCount` dan port pool, lewat symbol table yang dibuat dari PDB `tcpip.sys` [S7]. Di mesin analisis tanpa internet, symbol table itu bisa belum ada, sama seperti symbol table kernel yang dibahas di Day 02 bagian 2.5. Bila tabel partisi tidak ditemukan, plugin berhenti lebih awal dengan pesan debug saja, sehingga hasil kosong bisa berarti "tidak terbaca", bukan "tidak ada koneksi" [S7].

Opsi `--include-corrupt` di kedua plugin menampilkan objek yang sebagian sudah tertimpa; kode plugin sendiri memperingatkan bahwa hasilnya bisa berisi data rusak [S6][S7]. Opsi ini dipakai hanya untuk mencari tujuan tertentu yang dicurigai, dan setiap baris dari opsi ini ditandai di catatan.

### 1.2 Menautkan koneksi ke proses dan C2

Pertanyaan pertama dan kedua Sari bertemu di sini: daftar tujuan eksternal dari netscan dikelompokkan per proses pemilik, lalu setiap proses dinilai wajar atau tidak membuat koneksi itu. Kanal C2 kedua berarti proses lain, atau tujuan lain, yang tidak bisa dijelaskan.

Koneksi di memori dikaitkan ke proses pemilik. Untuk investigasi C2 (command and control, saluran tempat malware menerima perintah dan mengirim data), ini menjawab:

- Proses apa yang membuka koneksi keluar ke IP eksternal.
- Apakah proses itu wajar membuat koneksi (misalnya `mshta.exe` atau `rundll32.exe` yang berkoneksi ke luar adalah anomali; `MsSense.exe`, sensor Defender for Endpoint, yang menghubungi layanan Microsoft adalah wajar).
- Port dan arah: listener lokal yang tidak dikenal berarti host menunggu koneksi masuk; koneksi keluar ke port 443 berarti beacon atau unggahan.

Padukan dengan Day 15: proses yang terdeteksi injeksi dan juga punya koneksi keluar di netscan adalah gambaran C2 yang kuat. Memori menyatukan "kode disuntikkan" dan "menghubungi luar" dalam satu snapshot [S2].

Untuk kanal C2 kedua, cara kerjanya adalah eliminasi. Setiap tujuan eksternal yang muncul harus jatuh ke salah satu dari tiga kelompok: dikenal dan wajar (agen keamanan, layanan OS), dikenal sebagai C2 atau exfil kasus ini, atau belum dikenal. Kelompok ketiga yang kosong adalah syarat untuk menulis "tidak ada kanal C2 kedua yang terlihat di memori". Kata "terlihat di memori" wajib ikut, karena dua hal tidak bisa dijawab snapshot: kanal yang hanya aktif di hari sebelumnya dan strukturnya sudah ditimpa, dan kanal yang tidak memakai socket proses biasa (misalnya ditumpangkan ke proses sah yang memang berkomunikasi ke luar). Bagian pertama dijawab log firewall dan proxy; bagian kedua dijawab analisis proses dan injeksi (Day 15).

Pemilik koneksi juga punya batas. Volatility membaca PID dan nama proses dengan mengikuti pointer `Owner` di struktur endpoint; bila pointer itu kosong, tidak terbaca, atau menunjuk objek proses yang tidak lolos validasi, PID dan Owner tidak bisa ditentukan [S25]. Praktisi Volatility sudah lama mencatat bahwa struktur koneksi lama bisa tetap ada sementara pointer pemiliknya sudah tidak valid [S23]. Konsekuensinya untuk pertanyaan kedua Sari: koneksi exfil bisa saja masih ditemukan, tetapi tanpa pemilik yang bisa dipertanggungjawabkan. Pemilik yang terbaca untuk objek sisa juga harus dicek silang dengan waktu hidup proses (Day 14), karena PID bisa dipakai ulang oleh proses lain.

### 1.3 State koneksi, host terisolasi, dan arti "masih ada setelah 16 jam"

Pertanyaan kedua Sari menyebut 16 jam. Memori `JKT-WS-0457` diambil Sabtu 12:42 WIB, sekitar 16 jam 32 menit setelah exfil berakhir (Jumat 20:10) dan 13 jam 24 menit setelah isolasi (Jumat 23:18). Pertanyaannya bukan hanya "ada atau tidak", tetapi "apa arti state yang terlihat".

Tabel berikut memetakan state yang paling sering muncul di kasus seperti ini ke artinya; baca kolom "Yang boleh disimpulkan", karena di situ batasnya.

| State | Arti | Yang boleh disimpulkan |
|---|---|---|
| `LISTENING` | Socket menunggu koneksi masuk di port lokal | Proses pemilik membuka port; tidak berarti ada yang terhubung |
| `ESTABLISHED` | Koneksi aktif saat snapshot | Proses pemilik sedang berkomunikasi dengan tujuan itu |
| `SYN_SENT` | Upaya koneksi keluar sudah dikirim, belum ada jawaban | Proses mencoba menghubungi tujuan; belum tentu pernah tersambung |
| `CLOSED` | Struktur koneksi sudah tidak dipakai | Pernah ada koneksi atau upaya koneksi; waktu `Created` memberi kapan dibuat, bukan kapan ditutup |
| (tidak ditemukan) | Tidak ada struktur yang cocok | Tidak ada kesimpulan; struktur bisa sudah ditimpa |

Host yang diisolasi EDR memberi pola khusus. Isolasi Defender for Endpoint memutus host dari jaringan sambil mempertahankan koneksi ke layanan Defender, sehingga hanya proses dan tujuan tertentu yang diizinkan [S19]. Payload yang terus mencoba beacon setelah isolasi akan meninggalkan rangkaian upaya ke IP C2 dengan jarak yang mirip interval beacon, dan upaya terbaru bisa tertangkap sebagai `SYN_SENT`, sementara yang lebih tua sebagai `CLOSED`. State persis untuk upaya yang diblok di host bergantung pada cara blok diterapkan, jadi buktikan polanya di lab sebelum menulis kalimat yang bergantung pada `SYN_SENT` atau `CLOSED`. Pola ini justru berguna: ia membuktikan payload masih hidup dan masih mencoba, membuktikan isolasi bekerja (tidak ada `ESTABLISHED` ke IP C2), dan memberi interval beacon untuk deteksi.

Tiga aturan membaca sisa:

- **Jumlah sisa bukan jumlah kejadian.** Pool memory dipakai ulang tanpa urutan yang bisa ditebak; dari ratusan upaya beacon selama 13 jam, hanya beberapa yang bertahan, dan objek yang bertahan tidak selalu yang terbaru.
- **Waktu `Created` hanya untuk objek itu.** Ia tidak memberi awal atau akhir rangkaian koneksi; rentang dari log firewall tetap sumbernya.
- **Ketiadaan bukan bukti.** Koneksi exfil yang selesai 16 jam sebelumnya bisa sudah tidak tersisa sama sekali; bila tidak ditemukan, yang ditulis adalah "tidak tersisa di memori", bukan "tidak terjadi".

### 1.4 Service di memori: svcscan, svclist, dan svcdiff

Pertanyaan ketiga Sari ("service lain yang tidak kelihatan dari disk") butuh dua perbandingan: service di memori dibanding registry (disk dan in-memory), dan service yang dipegang SCM dibanding service yang dilihat API. Yang kedua adalah cara mencari service yang disembunyikan.

`windows.svcscan` mendaftar service dari memori, termasuk state dan binary path [S1]. Plugin ini memindai memori proses `services.exe` untuk tag record service (`serH` untuk Vista ke atas) lalu menelusuri record yang terhubung [S8]. Kolom keluarannya `Offset`, `Order`, `PID`, `Start`, `State`, `Type`, `Name`, `Display`, `Binary`, `Binary (Registry)`, dan `Dll`; dua kolom terakhir dan `Binary (Registry)` dibaca dari hive SYSTEM di memori (`CurrentControlSet\Services`, atau `ControlSet001\Services` bila yang pertama tidak terbaca), bukan dari record SCM [S8]. Nilainya dibanding registry disk (Day 09):

- State service saat snapshot (running atau stopped) dan PID proses service-nya.
- Service yang mungkin dimanipulasi in-memory.
- Korelasi dengan 7045 (disk, Day 11) dan registry Services.

Service dengan binary dari lokasi aneh atau yang menjalankan proses mencurigakan adalah persistence (ATT&CK T1543.003, Create or Modify System Process: Windows Service) [S4]. svcscan memberi state hidupnya.

Dua plugin tambahan menjawab pertanyaan "tersembunyi":

- **`windows.svclist`** mencari service lewat signature di image `services.exe` lalu membaca record dari sana; docstring-nya menyebut daftar berantai service di `services.exe`. Plugin ini hanya berjalan di Windows 10 build 15063 ke atas, 64-bit [S10].
- **`windows.malware.svcdiff`** menjalankan kedua cara pada image yang sama dan menampilkan service yang ditemukan lewat scan tetapi tidak lewat daftar, dengan tujuan menemukan service tersembunyi; docstring-nya menyebut tujuannya menemukan rootkit [S9]. Batas versinya sama: 64-bit, Windows 10 build 15063 ke atas; di luar itu plugin hanya memberi peringatan dan hasil kosong [S9]. Sejak Volatility 3 2.26.2 plugin ini berada di subpaket `windows.malware`; nama lama masih berjalan sebagai deprecated [S5].

Untuk pertanyaan Sari, "tidak ada service lain yang tidak terlihat di disk" ditulis bila tiga hal sepakat: `svcdiff` kosong, setiap nama service di svcscan punya key di `ControlSet001\Services` (hive SYSTEM di memori dan di image disk), dan setiap service yang tidak ada di baseline host sejenis bisa dijelaskan. Baseline paling dekat di kasus ini adalah memori workstation Keuangan lain dari build yang sama.

Satu batas: svcscan memakai tabel struktur per versi Windows, dan entri terbarunya untuk Windows 10 build 25398, dengan pemilihan dari versi terbaru ke terlama [S8]. Hasil yang tampak kurang lengkap dibanding svclist adalah tanda tabel tidak cocok, bukan tanda service disembunyikan; bandingkan jumlahnya sebelum menafsirkan selisih.

### 1.5 Registry in-memory: hivelist, printkey, dan scheduled_tasks

Pertanyaan keempat Sari ("persistence di disk juga terlihat di memori, dan apakah registry memori menyimpan sesuatu yang tidak ada di disk") dijawab dengan membaca hive yang termuat saat snapshot.

Registry sebagian ada di memori saat snapshot. Plugin [S1]:

- `windows.registry.hivelist`: daftar hive yang termuat di memori, dengan kolom `Offset` (offset virtual objek hive), `FileFullPath`, dan `File output`; opsi `--filter` menyaring nama hive tanpa membedakan huruf besar kecil, dan `--dump` mengekstrak hive [S12].
- `windows.registry.printkey`: menampilkan isi key tertentu dari hive in-memory, dengan opsi `--offset` (hive tertentu), `--key` (key awal), dan `--recurse` [S11]. Tanpa `--offset`, plugin menelusuri semua hive termuat; tanpa `--key`, ia mulai dari root setiap hive [S11].
- `windows.registry.scheduled_tasks`: mendekode task dari key `Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks` dan `Tree` di hive SOFTWARE in-memory, termasuk trigger, action, waktu pembuatan, dan waktu run terakhir [S13].

Nilainya: membaca autostart (Run), konfigurasi service, atau nilai lain saat snapshot, yang bisa berbeda dari hive disk bila baru diubah dan belum di-flush (bandingkan dengan transaction log, Day 09 bagian 1.2). Untuk persistence, printkey atas key Run di memori menunjukkan state autostart saat itu.

Path di `--key` ditulis relatif terhadap root hive, bukan path `HKLM`. Ini sumber kesalahan yang sering muncul. Run mesin berada di hive SOFTWARE, jadi key-nya `Microsoft\Windows\CurrentVersion\Run`; Run pengguna berada di `NTUSER.DAT`, jadi key-nya `Software\Microsoft\Windows\CurrentVersion\Run`; service berada di hive SYSTEM, jadi key-nya `ControlSet001\Services\<nama>`. Perintah `printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"` tanpa `--offset` hanya cocok di hive pengguna; untuk hive SOFTWARE key itu tidak ditemukan, dan plugin mencatat baris tidak terbaca alih-alih berhenti [S11].

printkey punya kolom yang tidak ada di parser disk: `Volatile` [S11]. Volatile key hanya hidup di memori dan tidak pernah ditulis ke file hive, sehingga tidak akan pernah terlihat di image disk atau hasil RECmd. Contoh bawaan adalah link `CurrentControlSet` yang dibuat saat boot. Untuk pertanyaan Sari, kolom ini dipakai untuk memastikan tidak ada key service atau autostart penyerang yang dibuat volatile. Subkey runtime yang memang dibuat Windows (misalnya subkey `Enum` di bawah key service yang sedang berjalan) lazim muncul volatile; pastikan pola ini di lab dengan host bersih sebelum menafsirkan baris volatile lain.

`printkey` atas `...\CurrentVersion\Run` di hive in-memory menampilkan nilai Run saat snapshot, melengkapi analisis registry disk (Day 09). Dengan kombinasi ini, satu snapshot memori bisa menjawab tiga hal untuk tiap persistence registry: nilainya ada di memori, nilainya sama dengan di disk, dan tidak ada key volatile yang menyembunyikan jalur lain.

### 1.6 WMI subscription dari memori: apa yang bisa dan tidak bisa

Pertanyaan keempat Sari juga menyangkut WMI subscription `HlpFilter`/`HlpConsumer`, yang di Day 11 bagian 2.5 dibuktikan dari Sysmon 19-21 dan `OBJECTS.DATA`. WMI subscription tidak muncul di svcscan, Run key, atau TaskCache, jadi pertanyaannya: bagaimana melihatnya dari memori?

Volatility 3 2.28.2 tidak punya plugin yang mem-parse WMI subscription; daftar plugin Windows dan subpaketnya (termasuk `windows.malware` dan `windows.registry`) tidak memuat plugin WMI [S1]. Jadi jangan mencari atau menulis nama plugin WMI yang tidak ada. Yang tersedia adalah tiga jejak tidak langsung yang masing-masing dibaca dengan plugin umum:

- **Proses penyedia dan DLL consumer.** `CommandLineEventConsumer` diimplementasikan oleh `wbemcons.dll`; rule Sigma "WMI Persistence - Command Line Event Consumer" mendeteksi `C:\Windows\System32\wbem\WmiPrvSE.exe` yang memuat `wbemcons.dll` [S22]. Di memori, `windows.dlllist` atas proses `WmiPrvSE.exe` yang memuat `wbemcons.dll` adalah padanan statis dari event image load itu. Ini tanda bahwa consumer baris perintah aktif di host, bukan bukti consumer mana.
- **Proses anak WMI.** ATT&CK T1546.003 menyarankan memantau proses anak `WmiPrvSE.exe` yang tidak lazim [S21]. Daftar proses aktif dan proses yang sudah berakhir (Day 14) bisa menunjukkan payload yang dijalankan dengan induk `WmiPrvSE.exe`. Hubungan induk ini juga dibuktikan di lab dengan consumer jinak sebelum dipakai di laporan.
- **Isi repository yang ter-cache.** `windows.filescan` menemukan objek file `OBJECTS.DATA`, dan `windows.dumpfiles` mengekstrak isi file yang ter-cache di memori (`DataSectionObject`, `ImageSectionObject`, `SharedCacheMap`) [S18]. Hasilnya bisa dicari dengan alat yang sama seperti di disk (Day 11 bagian 1.5). Isi cache hampir selalu tidak lengkap: hanya halaman yang ada di memori saat snapshot yang terbawa, jadi hasil negatif dari sini tidak berarti apa-apa.

Kesimpulannya: memori bisa menguatkan bahwa subscription aktif saat snapshot (consumer termuat, payload dijalankan dari `WmiPrvSE.exe`, sebagian isi repository ter-cache), tetapi sumber utama definisi filter, consumer, dan binding tetap disk dan Sysmon. Itu yang ditulis ke Sari.

### 1.7 Driver dan callback: persistence tingkat kernel

Pertanyaan kelima Sari ("persistence tingkat kernel") dijawab dengan memeriksa apa yang termuat di kernel dan siapa yang mendaftarkan callback. Persistence dan malware bisa berada di kernel, dan rootkit kernel bisa menyembunyikan proses, koneksi, atau service dari plugin yang mengandalkan daftar.

Tabel berikut memetakan plugin kernel ke pertanyaan yang dijawabnya; baca kolom "Tanda yang dicari", karena hasil normal di Windows 11 berisi ratusan baris sah.

| Plugin | Cara kerja | Tanda yang dicari |
|---|---|---|
| `windows.modules` | Daftar modul kernel termuat (list walking): `Base`, `Size`, `Name`, `Path`; opsi `--dump`, `--base`, `--name` [S17] | Path di luar `System32\drivers` atau `System32`, nama yang meniru driver sah, modul yang tidak punya file di image disk |
| `windows.modscan` | Pool scanning modul kernel | Modul yang ada di scan tetapi tidak di `modules` (dilepas dari daftar) |
| `windows.driverscan` | Pool scanning objek driver (tag `Dri\xf6` dan `Driv`): `Offset`, `Start`, `Size`, `Service Key`, `Driver Name`, `Name` [S14] | Driver tanpa nama service yang jelas, `Start` bernilai 0, atau service key yang tidak ada di registry |
| `windows.malware.drivermodule` | Mencocokkan alamat awal setiap driver ke modul yang dikenal [S15] | Driver yang alamatnya tidak jatuh di modul mana pun (kemungkinan dari modul tersembunyi) |
| `windows.callbacks` | Mendaftar callback kernel: notifikasi proses, thread, dan image load, callback registry, bugcheck, shutdown, dan lainnya, dengan kolom `Type`, `Callback`, `Module`, `Symbol`, `Detail` [S16] | Callback yang modulnya tidak dikenal atau tidak tersedia |
| `windows.ssdt` | Tabel panggilan sistem dan modul pemilik setiap entri | Entri yang menunjuk di luar `ntoskrnl.exe` dan modul `win32k` |

Beberapa detail yang menentukan cara membaca:

- driverscan tetap menyimpan driver dengan `Start` 0, karena rootkit sering mengosongkan nilai ini [S14].
- drivermodule mengabaikan driver dengan alamat awal di bawah ruang kernel (kemungkinan smear atau sisa), dan menandai beberapa komponen Windows yang sering memicu false positive (`ACPI_HAL`, `PnpManager`, `RAW`, `WMIxWDM`, `Win32k`, `Fs_Rec`) sebagai `Known Exception` [S15]. Sejak 2.26.2 plugin ini juga berada di `windows.malware` [S5].
- callbacks membaca daftar `PspCreateProcessNotifyRoutine`, `PspCreateThreadNotifyRoutine`, `PspLoadImageNotifyRoutine`, `CmRegisterCallback`/`CmRegisterCallbackEx` (registry), dan daftar bugcheck; daftar yang simbolnya tidak ada di build itu dilewati diam-diam [S16]. Modul yang tidak bisa ditentukan ditampilkan sebagai tidak tersedia [S16].

Driver dari lokasi tidak lazim atau tanpa tanda tangan, dan callback yang tidak dikenal, adalah sinyal persistence atau rootkit tingkat kernel. Banyak produk keamanan sah memakai callback yang sama: Defender (`WdFilter.sys`) dan Sysmon (`SysmonDrv.sys`) mendaftarkan callback proses, image, dan registry karena memang begitu cara mereka memantau. Callback yang "mencurigakan" adalah yang modulnya tidak bisa dipetakan ke driver yang dikenal, bukan yang jumlahnya banyak.

Volatility tidak memeriksa tanda tangan digital. Tanda tangan diperiksa pada file driver di image disk (path dari kolom `Path` modules), dengan Sigcheck: alat Sysinternals yang menampilkan versi file, timestamp, dan detail tanda tangan termasuk rantai sertifikat, dengan opsi `-e` (hanya executable image), `-c` (CSV), `-h` (hash), `-s` (rekursif), `-u` (hanya file tanpa tanda tangan bila VirusTotal tidak dipakai), dan `-f` (cari tanda tangan di file catalog tertentu) [S20]. Banyak driver Microsoft ditandatangani lewat catalog, bukan tanda tangan di file; saat memeriksa image offline, status catalog dibaca dari mesin analisis, sehingga driver sah bisa tampil tanpa tanda tangan bila catalog-nya tidak dikenal mesin analisis. Hasil "Unsigned" untuk driver Microsoft diperiksa ulang dengan `-f` dan file catalog dari image sebelum disebut temuan; perilaku ini dibuktikan di lab. Jangan memeriksa tanda tangan file hasil `--dump` dari memori: image yang dimuat sudah berubah dari file aslinya (section dipetakan, alamat direlokasi), jadi hash dan tanda tangannya tidak mewakili file di disk.

Untuk kasus PT JAB, satu driver yang pasti muncul di luar `System32\drivers` adalah driver akuisisi memori milik responder. WinPmem memuat driver lewat Service Control Manager (service `pmem`, 7045 Sabtu 12:42:08 WIB di Day 11 bagian 2.3), dan karena driver itu sedang bekerja saat image dibuat, ia ikut tertangkap di image yang ia buat sendiri. Ini jejak responder; dilabeli, bukan dilaporkan sebagai temuan (Day 07 bagian 1.5).

### 1.8 Korelasi memori, disk, dan log jaringan, lalu IOC

Pertanyaan keenam Sari meminta dua hal: daftar IOC dan tingkat keyakinan. Keduanya hanya bisa ditulis setelah temuan memori dipasangkan dengan sumber lain.

Temuan memori menguat dengan sumber lain:

- Koneksi netscan plus log jaringan (firewall, proxy, Zeek) bila ada: konfirmasi C2 dan rentang waktunya.
- Koneksi netscan plus paket investigasi EDR: daftar koneksi aktif (`ActiveNetConnections.txt`) dan cache DNS (`DnsCache.txt`) di paket investigasi Defender for Endpoint diambil beberapa menit setelah memori dan memberi pembanding independen [S19].
- Service svcscan plus 7045 dan registry disk (Day 11): persistence terkonfirmasi [S3].
- Run key printkey (memori) plus registry disk dan MFT payload (Day 08-09): autostart lengkap.
- Proses injeksi (Day 15) plus koneksi (netscan): C2 fileless.
- `WmiPrvSE.exe` dengan `wbemcons.dll` dan proses anak payload, plus Sysmon 19-21 dan `OBJECTS.DATA` (Day 11): WMI subscription aktif.

Memori memberi state hidup pada satu titik; disk dan log memberi riwayat dan konfirmasi. Satu snapshot memori bisa menangkap koneksi C2 yang tidak pernah masuk log (berumur pendek), yang unik dari memori.

Beacon adalah koneksi berulang dari implant ke server C2 dengan interval yang relatif teratur (misalnya tiap 60 detik dengan sedikit jitter), ukuran permintaan yang mirip, dan tujuan yang sama. Di log, polanya terlihat sebagai banyak koneksi kecil ke satu tujuan dengan selisih waktu yang hampir konstan, sesuatu yang jarang dihasilkan pengguna manusia. Rangkaian waktu `Created` di netscan untuk satu tujuan memberi perkiraan interval ini dari sisi host, yang lalu dicocokkan dengan log firewall.

IOC disusun dalam dua kelompok dengan sumber yang jelas untuk tiap nilai:

- **IOC host:** path dan hash payload dari file di image disk (bukan dari dump memori), nama service dan display name, nama WMI filter dan consumer, nilai Run dan path task, dan pola perilaku (`WmiPrvSE.exe` memuat `wbemcons.dll`, service yang binary-nya di `C:\ProgramData`). Hash dari dump memori tidak dipakai, karena alasan yang sama dengan tanda tangan di bagian 1.7.
- **IOC jaringan:** IP dan domain C2, IP tujuan exfil, port, dan pola beacon (interval dan jitter). IP dan domain murah diganti penyerang; pola perilaku lebih tahan lama, jadi keduanya diserahkan dengan catatan mana yang atomik dan mana yang perilaku.

Hal yang tetap harus ditafsir hati-hati:

- netscan bisa menampilkan koneksi lama (struktur sisa); perhatikan apakah masih aktif.
- Service dan driver sah banyak; bandingkan dengan baseline dan tanda tangan.
- Registry in-memory mencerminkan saat snapshot, bukan riwayat; untuk riwayat, pakai disk plus transaction log (Day 09).
- Snapshot sesaat: koneksi yang sudah tutup dan tidak tersisa di memori tidak terlihat.

## 2. Contoh dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi; angka di keluaran dihitung agar konsisten antar tabel. Perintah Volatility dijalankan di `jkt-dfir02` (Ubuntu LTS, Volatility 3 2.28.2 di virtualenv `~/venv/vol3`, dibekukan untuk kasus ini), atas salinan kerja image memori di disk lokal mesin itu; Sigcheck dijalankan di `JKT-DFIR01` atas salinan kerja image disk yang di-mount read-only. Narasi memakai WIB (UTC+7). Volatility menulis waktu dalam UTC, jadi setiap keluaran diberi label zona waktunya (WIB = UTC ditambah 7 jam). Kolom keluaran dipangkas agar terbaca; cocokkan nama kolom dengan versi di lab-mu.

Nomor bukti memori dan paket investigasi `INC-2026-017` yang dipakai di Day ini, semuanya diambil Yoga Pratama Sabtu 2026-10-10 saat host terisolasi tetapi menyala:

| Bukti | Isi | Waktu (WIB) |
|---|---|---|
| `INC-2026-017-E01` | Memori `JKT-WS-0457`, WinPmem dari media bukti `USB-E-05`, sesi konsol akun admin lokal khusus IR `ir-admin` | Mulai 12:42:05, driver `pmem` 12:42:08, selesai 12:57:30 |
| `INC-2026-017-E02` | Paket investigasi Defender for Endpoint `JKT-WS-0457` | 13:05 sampai 13:12 |
| `INC-2026-017-E03` | Memori `JKT-WS-0441` | 10:06:12 sampai 10:19:40 |
| `INC-2026-017-E04` | Paket investigasi Defender for Endpoint `JKT-WS-0441` | 10:25 sampai 10:31 |

Image disk `E05` (`JKT-WS-0457`) dan `E06` (`JKT-WS-0441`) diambil Senin 2026-10-12 09:00 dan sudah dibedah di Day 11. Day ini fokus pada E01; E03 hanya dipakai sebagai baseline service.

### 2.1 Menyiapkan E01-W1 dan memastikan image terbaca

Langkah ini menyiapkan salinan kerja memori sebelum menjawab pertanyaan Sari. Senin 09:05 Yoga membuat `E01-W1` di `/cases/INC-2026-017/work/` pada `jkt-evid01` setelah memverifikasi hash master; pukul 09:08 kamu menyalinnya ke disk lokal `jkt-dfir02`, karena membaca 16 GiB berulang kali lewat share jauh lebih lambat.

**Tujuan:** memastikan salinan kerja identik dengan master, image terbaca, dan versi kernel diketahui sebelum memilih plugin.

```bash
. ~/venv/vol3/bin/activate
IMG=/data/work/INC-2026-017/E01-W1/INC-2026-017-E01-W1_JKT-WS-0457_mem.raw
OUT=/mnt/cases/INC-2026-017/analysis/E01-W1/vol-2.28.2
sha256sum "$IMG"
cat /mnt/evidence/INC-2026-017/INC-2026-017-E01_JKT-WS-0457_mem.raw.sha256
vol -q -f "$IMG" windows.info | tee "$OUT/windows.info.txt"
```

- `. ~/venv/vol3/bin/activate`: mengaktifkan virtualenv Volatility yang dibekukan untuk kasus.
- `IMG` dan `OUT`: path salinan kerja lokal dan folder hasil di share kasus (`/mnt/cases` adalah `\\jkt-evid01\cases` yang di-mount read-write; `/mnt/evidence` read-only, Day 02 bagian 2.8).
- `sha256sum` dan `cat ...sha256`: hash salinan kerja dibandingkan dengan hash master yang dicatat Yoga Sabtu.
- `vol -q`: `-q` menekan baris progres, sehingga file keluaran bersih. `-f` menunjuk image.
- `windows.info`: membaca struktur kernel dasar dan membuktikan symbol table cocok (Day 14).

Keluaran ilustrasi (`windows.info`, dipangkas; waktu UTC):

```
Variable                 Value
Kernel Base              0xf80744800000
Is64Bit                  True
layer_name               0 WindowsIntel32e
memory_layer             1 FileLayer
KeNumberProcessors       8
SystemTime               2026-10-10 05:42:11+00:00
NtSystemRoot             C:\Windows
NtProductType            NtProductWinNt
NtMajorVersion           10
NtMinorVersion           0
Major/Minor              15.22621
```

**Cara membaca hasil:** hash cocok (09:12), dan `windows.info` berjalan, artinya symbol table kernel untuk build ini tersedia di `jkt-dfir02` (cara menyiapkannya ada di Day 14). `SystemTime` 05:42:11 UTC (12:42:11 WIB) jatuh enam detik setelah WinPmem mulai, cocok dengan catatan Yoga. Kernel melapor 22621 padahal host tercatat Windows 11 Enterprise 23H2 build 22631: 22H2 dan 23H2 berbagi inti OS dan file sistem yang sama, dan 23H2 diaktifkan lewat enablement package yang mengubah nomor build [S24]. Untuk Volatility, yang menentukan adalah build kernel 22621. Nomor ini juga yang dipakai netscan untuk memilih tabel struktur (bagian 1.1).

**Variasi:** `vol -r csv` mengubah renderer menjadi CSV untuk diolah di spreadsheet atau Timeline Explorer; `-r json` untuk diolah skrip.

**Kapan gagal:** pesan symbol table tidak ditemukan berarti build kernel ini belum punya symbol table di mesin offline (Day 02 bagian 2.5). Jangan menyalin image ke mesin yang punya internet.

### 2.2 Koneksi dengan netscan

Langkah ini menjawab pertanyaan pertama dan kedua Sari: semua tujuan eksternal dan proses pemiliknya. Dijalankan 09:24 sampai 09:31.

**Tujuan:** mendaftar semua objek koneksi dan socket yang masih bisa ditemukan, lalu menyaring tujuan di luar `10.0.0.0/8`, loopback, dan socket tanpa tujuan.

```bash
vol -q -r csv -f "$IMG" windows.netscan > "$OUT/netscan.csv"
head -1 "$OUT/netscan.csv"
awk -F, 'NR>1 && $6 !~ /^(10\.|127\.|0\.0\.0\.0|\*|::)/ && $7 != 0' "$OUT/netscan.csv" | sort -t, -k11
```

- `windows.netscan`: pool scanning untuk listener, endpoint TCP, dan endpoint UDP [S6].
- `-r csv` dan `>`: hasil penuh disimpan sebagai CSV di folder kasus, supaya penyaringan bisa diulang tanpa menjalankan plugin lagi.
- `head -1`: menampilkan header CSV. Renderer CSV Volatility 3 menambahkan kolom `TreeDepth` di depan, sehingga `ForeignAddr` menjadi kolom ke-6, `ForeignPort` ke-7, dan `Created` ke-11; pastikan urutan ini dengan header di versi-mu sebelum memakai `awk`.
- `awk -F, '...'`: membuang baris yang foreign address-nya internal (`10.`), loopback, kosong, `*`, atau IPv6 tanpa tujuan, dan baris berport tujuan 0 (listener). Ini penyaring kasar; hasil penuh tetap dibaca.
- `sort -t, -k11`: mengurutkan menurut kolom `Created`.

Keluaran ilustrasi (tujuan eksternal, dipangkas; waktu UTC). Total `netscan.csv` 187 baris: 24 listener TCP, 58 endpoint UDP, dan 105 endpoint TCP (1 `ESTABLISHED`, 1 `SYN_SENT`, 103 `CLOSED`). Dari 105 endpoint TCP, 16 menuju alamat eksternal:

```
Offset          Proto  LocalAddr    LPort  ForeignAddr     FPort  State        PID   Owner        Created (UTC)
0xd38b2c4e1a20  TCPv4  10.10.45.57  51544  198.51.100.205  443    CLOSED       N/A   N/A          2026-10-09 13:08:41
0xd38b2c71f6b0  TCPv4  10.10.45.57  49822  203.0.113.205   443    CLOSED       6412  hlpsvc.exe   2026-10-09 16:07:39
0xd38b2c5a0e40  TCPv4  10.10.45.57  49827  203.0.113.205   443    CLOSED       6412  hlpsvc.exe   2026-10-09 16:12:44
0xd38b2c8d33c0  TCPv4  10.10.45.57  50688  203.0.113.205   443    CLOSED       6412  hlpsvc.exe   2026-10-10 05:16:40
0xd38b2c6b9150  TCPv4  10.10.45.57  50694  203.0.113.205   443    CLOSED       6412  hlpsvc.exe   2026-10-10 05:21:46
0xd38b2c4f0d80  TCPv4  10.10.45.57  50699  203.0.113.205   443    CLOSED       6412  hlpsvc.exe   2026-10-10 05:26:42
0xd38b2c90a2e0  TCPv4  10.10.45.57  50705  203.0.113.205   443    CLOSED       6412  hlpsvc.exe   2026-10-10 05:31:44
0xd38b2c7c4570  TCPv4  10.10.45.57  50712  203.0.113.205   443    CLOSED       6412  hlpsvc.exe   2026-10-10 05:36:51
0xd38b2c3e88a0  TCPv4  10.10.45.57  50718  203.0.113.205   443    SYN_SENT     6412  hlpsvc.exe   2026-10-10 05:41:47
...             6 baris CLOSED ke 192.0.2.88:443, Owner MsSense.exe, PID 3120 (2026-10-09 15:02 s.d. 16:16 UTC)
0xd38b2c62d010  TCPv4  10.10.45.57  50716  192.0.2.88      443    ESTABLISHED  3120  MsSense.exe  2026-10-10 05:40:02
```

Satu baris internal ikut dicatat karena relevan dengan enkripsi:

```
0xd38b2c55b7f0  TCPv4  10.10.45.57  50217  10.20.10.21     445    CLOSED       4     System       2026-10-09 14:30:05
```

**Cara membaca hasil:**

- **Tiga tujuan eksternal saja.** `203.0.113.205` (C2 kasus), `198.51.100.205` (tujuan exfil), dan `192.0.2.88` (endpoint layanan Defender for Endpoint yang dipakai `MsSense.exe`, PID 3120; di lingkungan nyata ini alamat Microsoft, di sini ditulis dengan rentang dokumentasi). Tidak ada tujuan eksternal keempat, dan tidak ada proses selain `hlpsvc.exe` yang menghubungi IP C2.
- **`hlpsvc.exe` PID 6412 adalah pemilik semua koneksi ke C2.** Dua objek `CLOSED` dari Jumat 16:07:39 dan 16:12:44 UTC (23:07:39 dan 23:12:44 WIB) dibuat beberapa menit sebelum isolasi pukul 23:18 WIB. Enam objek Sabtu dibuat setelah isolasi: 05:16:40, 05:21:46, 05:26:42, 05:31:44, 05:36:51, dan 05:41:47 UTC (12:16:40 sampai 12:41:47 WIB). Selisih berurutannya 5:06, 4:56, 5:02, 5:07, dan 4:56, dan selisih dua objek Jumat 5:05: beacon sekitar lima menit dengan jitter beberapa detik. Upaya terakhir masih `SYN_SENT` 18 detik sebelum WinPmem mulai. Tidak ada `ESTABLISHED` ke `203.0.113.205`, jadi isolasi bekerja.
- **Hanya sebagian kecil upaya yang tersisa.** Selama 13 jam 24 menit isolasi, beacon lima menit berarti sekitar 160 upaya, tetapi hanya enam objek Sabtu yang bertahan, dan dua objek Jumat bertahan lebih lama daripada upaya Sabtu dini hari. Ini contoh langsung aturan "jumlah sisa bukan jumlah kejadian" (bagian 1.3).
- **Exfil: koneksinya tersisa, pemiliknya tidak.** Satu objek `CLOSED` ke `198.51.100.205:443` dibuat Jumat 13:08:41 UTC (20:08:41 WIB), di dalam jendela exfil 18:40 sampai 20:10 WIB dari log firewall. `PID` dan `Owner` tidak terbaca (`N/A`): pointer pemilik di struktur itu sudah tidak valid [S25]. Jadi memori membuktikan host ini masih menyimpan sisa koneksi ke tujuan exfil pada waktu yang cocok, tetapi tidak membuktikan proses pengirimnya.
- **SMB ke file server.** Objek `CLOSED` ke `10.20.10.21:445` (`JKT-FS01`) milik `System` PID 4 dibuat Jumat 14:30:05 UTC (21:30:05 WIB), cocok dengan ShellBags `\\JKT-FS01\Keuangan` pukul 21:30 di Day 11. Pemiliknya `System` karena klien SMB berjalan di kernel, jadi baris ini tidak menunjuk proses encryptor.

**Variasi:** `windows.netscan --include-corrupt` dijalankan sekali khusus untuk mencari objek tambahan ke `198.51.100.205`; hasilnya satu baris tambahan dengan local port 0 dan `Created` `N/A` (waktu di luar rentang wajar dianggap tidak valid [S25]), dicatat sebagai "tidak dapat dipakai" dan tidak masuk temuan [S6].

**Kapan gagal:** netscan memakai tabel struktur terdekat untuk build 22621 (bagian 1.1); bila kolom tampak acak (alamat tidak masuk akal, state `N/A` untuk banyak baris), tabel tidak cocok, dan hasil harus divalidasi dengan netstat dan paket investigasi EDR sebelum dipakai. Di image ini alamat, port, dan waktu konsisten dengan log firewall, jadi tabelnya cocok untuk struktur yang dibaca.

### 2.3 Koneksi aktif dengan netstat dan pembanding paket investigasi

Langkah ini memvalidasi netscan dengan cara kerja kedua (bagian 1.1), sekaligus menjawab apakah ada koneksi aktif yang luput dari netscan.

**Tujuan:** mendapatkan daftar koneksi dan listener dari struktur aktif `tcpip.sys`, lalu membandingkannya dengan netscan dan dengan `ActiveNetConnections.txt` di paket investigasi E02.

```bash
vol -q -r csv -f "$IMG" windows.netstat > "$OUT/netstat.csv"
```

- `windows.netstat`: menelusuri tabel partisi dan port pool `tcpip.sys` [S7].

Percobaan pertama pukul 09:35 berhenti dengan pesan bahwa symbol table untuk `tcpip.sys` tidak bisa dibuat: `jkt-dfir02` tidak punya internet, dan symbol pack offline hanya berisi tabel kernel. Kamu memilih jalan yang sah dari Day 02 bagian 2.5: Yoga meminta NOC membuka jendela proxy khusus ke Microsoft Symbol Server pukul 09:42 sampai 09:52, netstat dijalankan ulang pukul 09:47 dan Volatility mengunduh PDB `tcpip.sys`, mengonversinya, dan menyimpannya di cache simbol. Jendela, PDB yang diunduh, dan hash file symbol table hasilnya dicatat di `notes/case-notes.md`.

Keluaran ilustrasi (dipangkas; waktu UTC). Total 84 baris: 24 listener, 58 endpoint UDP, 1 `ESTABLISHED`, 1 `SYN_SENT`:

```
Proto  LocalAddr    LPort  ForeignAddr    FPort  State        PID   Owner        Created (UTC)
TCPv4  10.10.45.57  50718  203.0.113.205  443    SYN_SENT     6412  hlpsvc.exe   2026-10-10 05:41:47
TCPv4  10.10.45.57  50716  192.0.2.88     443    ESTABLISHED  3120  MsSense.exe  2026-10-10 05:40:02
TCPv4  0.0.0.0      135    0.0.0.0        0      LISTENING    1016  svchost.exe  2026-10-08 00:48:31
TCPv4  0.0.0.0      445    0.0.0.0        0      LISTENING    4     System       2026-10-08 00:48:36
TCPv4  0.0.0.0      3389   0.0.0.0        0      LISTENING    1288  svchost.exe  2026-10-08 00:48:40
...
```

Keluaran ilustrasi (`ActiveNetConnections.txt` di paket E02, keluaran `netstat -ano` Windows pada pukul 13:06 WIB; waktu tidak dicantumkan oleh perintah itu):

```
  Proto  Local Address          Foreign Address        State           PID
  TCP    10.10.45.57:50741      203.0.113.205:443      SYN_SENT        6412
  TCP    10.10.45.57:50739      192.0.2.88:443         ESTABLISHED     3120
```

**Cara membaca hasil:** netstat dan netscan sepakat untuk semua koneksi aktif: satu `SYN_SENT` milik `hlpsvc.exe` PID 6412 dan satu `ESTABLISHED` milik `MsSense.exe` PID 3120. Listener netstat (24) sama persis dengan listener netscan, semuanya milik proses Windows standar (`System`, `svchost.exe`, `lsass.exe`, `wininit.exe`, `services.exe`, `spoolsv.exe`); tidak ada listener yang dibuka `hlpsvc.exe` atau proses tak dikenal. netstat tidak menampilkan 103 objek `CLOSED`, sesuai cara kerjanya. Paket E02, diambil 24 menit setelah akuisisi memori dimulai, menunjukkan PID yang sama masih mencoba ke `203.0.113.205:443` dengan port lokal yang lebih baru: sumber ketiga yang independen dari Volatility. `DnsCache.txt` di E02 tidak memuat `sync-win.example.net`, padahal upaya ke IP terus berjalan; artinya payload menghubungi IP tanpa resolusi DNS saat itu, sehingga sinkhole domain saja tidak akan menghentikannya, dan blok IP di firewall sama pentingnya.

**Variasi:** di lab, putus internet `LAB-DFIR01` dan jalankan netstat untuk melihat pesan symbol table yang muncul di versi-mu, lalu bandingkan dengan hasil setelah simbol tersedia.

**Kapan gagal:** hasil kosong tanpa error jelas bisa berarti tabel partisi tidak ditemukan, karena plugin keluar lebih awal dengan pesan debug saja [S7]; jalankan dengan `-vvv` untuk melihat pesan itu sebelum menulis "tidak ada koneksi aktif". netstat historisnya lebih rapuh antar versi daripada netscan.

### 2.4 Service dengan svcscan, svclist, dan svcdiff

Langkah ini menjawab pertanyaan ketiga Sari. Dijalankan 10:05 sampai 10:32.

**Tujuan:** mendaftar service yang dipegang SCM, memastikan persistence `WinHlpSvc` hidup, mencari service tersembunyi, dan membandingkan dengan baseline.

```bash
vol -q -r csv -f "$IMG" windows.svcscan > "$OUT/svcscan.csv"
vol -q -r csv -f "$IMG" windows.svclist > "$OUT/svclist.csv"
vol -q -r csv -f "$IMG" windows.malware.svcdiff > "$OUT/svcdiff.csv"
grep -i -E 'WinHlpSvc|pmem' "$OUT/svcscan.csv"
```

- `windows.svcscan`: scan record service di memori `services.exe` [S8].
- `windows.svclist`: cara kedua lewat signature di image `services.exe` [S10].
- `windows.malware.svcdiff`: service yang ada di scan tetapi tidak di daftar [S9]. Nama lama `windows.svcdiff` masih berjalan sebagai deprecated sampai dihapus [S5].
- `grep`: menarik dua baris yang sudah dikenal dari Day 11.

Keluaran ilustrasi (dua baris dari svcscan, kolom dipangkas):

```
Offset          Order  PID   Start                 State            Type                       Name       Display               Binary                                 Binary (Registry)
0x1f4c3a2b8e0   612    6412  SERVICE_AUTO_START    SERVICE_RUNNING  SERVICE_WIN32_OWN_PROCESS  WinHlpSvc  Windows Help Service  C:\ProgramData\WinHlpSvc\hlpsvc.exe    C:\ProgramData\WinHlpSvc\hlpsvc.exe
0x1f4c3a9d150   731    N/A   SERVICE_DEMAND_START  SERVICE_RUNNING  SERVICE_KERNEL_DRIVER      pmem       pmem                  \Driver\pmem                           C:\Windows\winpmem.sys
```

Ringkasan hitungan:

| Plugin | Baris | Catatan |
|---|---|---|
| svcscan | 731 | Service dan driver |
| svclist | 731 | Nama sama persis dengan svcscan |
| svcdiff | 0 | Tidak ada service yang hanya ditemukan lewat scan |

**Cara membaca hasil:**

- **`WinHlpSvc` hidup dan sesuai disk.** Running, auto start, own process, PID 6412: PID yang sama dengan pemilik koneksi C2 di bagian 2.2. Binary dari record SCM sama dengan `ImagePath` registry, dan sama dengan 7045 Kamis 12:11:30 UTC di Day 11 bagian 2.3. Display name `Windows Help Service` meniru komponen Windows; nama ini ikut masuk IOC.
- **`pmem` adalah responder.** Driver kernel demand start yang running saat image dibuat, binary `C:\Windows\winpmem.sys`, cocok dengan 7045 Sabtu 05:42:08 UTC (12:42:08 WIB) di Day 11. Dilabeli jejak responder.
- **Tidak ada service tersembunyi yang terlihat.** svcscan dan svclist menemukan 731 nama yang sama, dan svcdiff kosong. Karena kedua jumlah sama, tidak ada tanda tabel svcscan tidak cocok dengan build ini (bagian 1.4).
- **Semua service punya key registry.** Seluruh 731 nama punya key di `ControlSet001\Services` pada hive SYSTEM di memori (bagian 2.5); untuk image disk E05-W1 perbandingan nama dilakukan di `JKT-DFIR01` dengan hasil RECmd Day 11, dan selain `pmem` yang dinilai terpisah sebagai jejak responder, tidak ada nama yang hanya ada di memori.

Baseline dengan E03 (`JKT-WS-0441`, build dan image standar yang sama) memakai daftar nama dari svcscan E03 yang diolah dengan perintah yang sama. Tabel berikut adalah selisihnya; baca kolom "Penjelasan", karena setiap baris harus punya penjelasan sebelum menulis "tidak ada service lain".

| Ada di | Nama | Penjelasan |
|---|---|---|
| E01 (`JKT-WS-0457`) | `WinHlpSvc` | Persistence penyerang (Day 11) |
| E01 dan E03 | `pmem` | Driver WinPmem responder di kedua host |
| E01 | 4 driver perangkat keras | `JKT-WS-0457` desktop, `JKT-WS-0441` laptop; keempatnya punya file bertanda tangan vendor di E05-W1 (bagian 2.7) |
| E03 | 3 driver perangkat keras | Driver Wi-Fi, baterai, dan touchpad laptop |

**Variasi:** `grep -v -i -E 'C:\\Windows\\|\\SystemRoot\\|\\Driver\\|\\FileSystem\\'` atas svcscan menampilkan service dengan binary di luar folder Windows; di image ini hasilnya `WinHlpSvc` plus service Program Files dari aplikasi standar PT JAB (agen backup, VPN, Office Click-to-Run), semua dikenal.

**Kapan gagal:** svclist dan svcdiff hanya berjalan di Windows 10 build 15063 ke atas, 64-bit; di luar itu plugin hanya mencetak peringatan dan hasil kosong [S9][S10], dan hasil kosong itu bukan "tidak ada service tersembunyi". Service yang dihapus sebelum snapshot tidak terlihat sama sekali; korelasikan dengan 7045 dan registry disk (Day 11).

### 2.5 Registry in-memory dengan hivelist, printkey, dan scheduled_tasks

Langkah ini menjawab pertanyaan keempat Sari untuk persistence di registry. Dijalankan 10:40 sampai 11:15.

**Tujuan:** menemukan offset hive SYSTEM dan SOFTWARE, membaca key service `WinHlpSvc` dan key Run dari memori, mencari key volatile di bawah `Services`, dan membaca task dari TaskCache in-memory.

```bash
vol -q -f "$IMG" windows.registry.hivelist
vol -q -f "$IMG" windows.registry.printkey --offset 0xa30c2e45f000 --key "ControlSet001\Services\WinHlpSvc"
vol -q -f "$IMG" windows.registry.printkey --offset 0xa30c2f1d8000 --key "Microsoft\Windows\CurrentVersion\Run"
vol -q -f "$IMG" windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
vol -q -r csv -f "$IMG" windows.registry.printkey --offset 0xa30c2e45f000 --key "ControlSet001\Services" --recurse > "$OUT/printkey_services.csv"
vol -q -r csv -f "$IMG" windows.registry.scheduled_tasks > "$OUT/scheduled_tasks.csv"
```

- `hivelist`: menampilkan hive yang termuat dengan offset virtual untuk dipakai printkey [S12].
- `printkey --offset ... --key ...`: membaca satu key dari satu hive; path relatif terhadap root hive (bagian 1.5) [S11].
- Baris keempat tanpa `--offset`: membaca Run pengguna dari semua `NTUSER.DAT` yang termuat.
- `--recurse` atas `ControlSet001\Services`: semua key service beserta kolom `Volatile`, disimpan sebagai CSV untuk disaring.
- `windows.registry.scheduled_tasks`: task dari TaskCache SOFTWARE in-memory [S13].

Keluaran ilustrasi (`hivelist`, dipangkas; total 37 hive):

```
Offset          FileFullPath
0xa30c2e45f000  \REGISTRY\MACHINE\SYSTEM
0xa30c2f1d8000  \SystemRoot\System32\Config\SOFTWARE
0xa30c2f2a1000  \SystemRoot\System32\Config\SAM
0xa30c2f2c6000  \SystemRoot\System32\Config\SECURITY
0xa30c2f2e9000  \SystemRoot\System32\Config\DEFAULT
0xa30c31b77000  \??\C:\Users\budi.santoso\ntuser.dat
0xa30c31b9a000  \??\C:\Users\budi.santoso\AppData\Local\Microsoft\Windows\UsrClass.dat
0xa30c33e40000  \??\C:\Users\ir-admin\ntuser.dat
0xa30c33e61000  \??\C:\Users\ir-admin\AppData\Local\Microsoft\Windows\UsrClass.dat
0xa30c2f9a4000  \??\C:\Windows\AppCompat\Programs\Amcache.hve
...
```

Keluaran ilustrasi (`printkey` atas `ControlSet001\Services\WinHlpSvc`, dipangkas; waktu UTC):

```
Last Write Time (UTC)  Type           Key                                                    Name         Data                                   Volatile
2026-10-08 12:11:30    REG_EXPAND_SZ  \REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\WinHlpSvc  ImagePath    C:\ProgramData\WinHlpSvc\hlpsvc.exe    False
2026-10-08 12:11:30    REG_DWORD      \REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\WinHlpSvc  Start        2                                      False
2026-10-08 12:11:30    REG_DWORD      \REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\WinHlpSvc  Type         16                                     False
2026-10-08 12:11:30    REG_SZ         \REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\WinHlpSvc  ObjectName   LocalSystem                            False
2026-10-08 12:11:30    REG_SZ         \REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\WinHlpSvc  DisplayName  Windows Help Service                   False
```

Keluaran ilustrasi (Run di SOFTWARE dan di `NTUSER.DAT` yang termuat):

```
SOFTWARE  Microsoft\Windows\CurrentVersion\Run  SecurityHealth  %windir%\system32\SecurityHealthSystray.exe
budi.santoso ntuser.dat  Software\Microsoft\Windows\CurrentVersion\Run  OneDrive  "C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background
ir-admin ntuser.dat      Software\Microsoft\Windows\CurrentVersion\Run  (tidak ada nilai)
```

**Cara membaca hasil:**

- **Key service di memori sama dengan disk.** `Start` 2 berarti auto start, `Type` 16 (0x10) berarti service dengan proses sendiri, `ObjectName` LocalSystem, last write Kamis 12:11:30 UTC (19:11:30 WIB), sama dengan 7045 dan registry E05-W1 di Day 11. Semua nilai `Volatile` False: key ini tersimpan normal di hive, tidak hanya di memori.
- **Run bersih.** Run mesin hanya berisi `SecurityHealth`, Run `budi.santoso` hanya OneDrive. Ini sesuai Day 11: di `JKT-WS-0457` penyerang memakai service dan WMI, bukan Run key (Run key `MsEdgeSync` ada di `JKT-WS-0441`).
- **Tidak ada key service volatile milik penyerang.** Dari `printkey_services.csv`, baris dengan `Volatile` True hanya subkey `Enum` di bawah service yang sedang berjalan, pola runtime Windows yang sama dengan memori baseline E03 (bagian 1.5). Tidak ada key service yang seluruhnya volatile.
- **Task tanpa temuan.** `scheduled_tasks.csv` berisi 198 task; setelah memisahkan task di bawah `\Microsoft\Windows\` yang action-nya menunjuk `System32`, sisanya task OneDrive, Office, Edge Update, dan agen backup PT JAB. Tidak ada task yang menjalankan `hlpsvc.exe` atau binary di `C:\ProgramData` selain milik vendor yang dikenal, sesuai dengan disk.

**Variasi:** `hivelist --filter ntuser` hanya menampilkan hive pengguna; `hivelist --dump` mengekstrak hive dari memori untuk dibuka dengan Registry Explorer, berguna bila hive disk kotor dan transaction log hilang. Hive yang diekstrak dari memori bisa berlubang di halaman yang tidak ada di memori, jadi hasil negatifnya lemah.

**Kapan gagal:** key yang tidak ditemukan di hive tertentu menghasilkan baris tidak terbaca, bukan error [S11]; baca baris itu sebelum menulis "key tidak ada". Bagian hive yang tidak ada di memori saat snapshot (paged out) juga tidak terbaca, sehingga printkey memori melengkapi disk, tidak menggantikannya.

### 2.6 WMI subscription dari memori

Langkah ini menjawab bagian WMI dari pertanyaan keempat Sari dengan tiga jejak tidak langsung (bagian 1.6). Dijalankan 11:20 sampai 12:10.

**Tujuan:** menunjukkan bahwa subscription `HlpFilter`/`HlpConsumer` aktif saat snapshot, tanpa mengandalkan plugin yang tidak ada.

```bash
vol -q -f "$IMG" windows.pstree | grep -i -E 'WmiPrvSE|hlpsvc|services.exe|DcomLaunch'
vol -q -f "$IMG" windows.psscan | grep -i hlpsvc
vol -q -f "$IMG" windows.dlllist --pid 3964 | grep -i wbemcons
vol -q -f "$IMG" windows.filescan | grep -i 'wbem\\Repository\\OBJECTS.DATA'
vol -q -f "$IMG" -o "$OUT/dumpfiles" windows.dumpfiles --virtaddr 0xd38b2e7a4b10
```

- `windows.pstree` dan `windows.psscan`: proses aktif dengan induknya dan proses yang sudah berakhir (dibahas di Day 14 dan Day 15).
- `windows.dlllist --pid 3964`: DLL yang dimuat proses `WmiPrvSE.exe` yang ditemukan di pstree.
- `windows.filescan`: objek file di memori, untuk mendapatkan offset objek `OBJECTS.DATA`.
- `-o ... windows.dumpfiles --virtaddr ...`: mengekstrak isi ter-cache untuk objek file itu ke folder keluaran; nama file hasil memakai pola `file.<offset objek file>.<offset objek cache>.<jenis cache>.<nama>.<ekstensi>` dengan ekstensi `dat`, `img`, atau `vacb` [S18].

Keluaran ilustrasi (dipangkas; waktu UTC):

```
pstree:
PID   PPID  ImageFileName  CreateTime (UTC)
812   680   services.exe   2026-10-08 00:48:19
. 6412 812  hlpsvc.exe     2026-10-08 12:11:31
. 936  812  svchost.exe    2026-10-08 00:48:21   (-k DcomLaunch)
.. 3964 936 WmiPrvSE.exe   2026-10-08 12:11:52

psscan (hlpsvc.exe):
PID   PPID  ImageFileName  CreateTime (UTC)     ExitTime (UTC)
6412  812   hlpsvc.exe     2026-10-08 12:11:31  N/A
8840  3964  hlpsvc.exe     2026-10-10 05:11:52  2026-10-10 05:11:53
9312  3964  hlpsvc.exe     2026-10-10 05:36:52  2026-10-10 05:36:53

dlllist PID 3964:
Base              Size     Name          Path                                  LoadTime (UTC)
0x7ffb4a6c0000    0x2e000  wbemcons.dll  C:\Windows\System32\wbem\wbemcons.dll  2026-10-08 12:11:52

filescan:
0xd38b2e7a4b10  \Windows\System32\wbem\Repository\OBJECTS.DATA

dumpfiles:
Cache              FileObject      FileName      Result
DataSectionObject  0xd38b2e7a4b10  OBJECTS.DATA  file.0xd38b2e7a4b10.0xd38b2b10c8a0.DataSectionObject.OBJECTS.DATA.dat
SharedCacheMap     0xd38b2e7a4b10  OBJECTS.DATA  file.0xd38b2e7a4b10.0xd38b2f4e2d50.SharedCacheMap.OBJECTS.DATA.vacb
```

Hasil `.dat` disalin ke `JKT-DFIR01` dan dicari dengan `wmi-parser` yang sama seperti di Day 11 bagian 2.5:

```
Consumer : CommandLineEventConsumer  Name=HlpConsumer  Arguments=C:\ProgramData\WinHlpSvc\hlpsvc.exe
Filter   : HlpFilter  Query=SELECT * FROM __InstanceModificationEvent WITHIN 300 WHERE ...
Binding  : HlpConsumer <-> HlpFilter
```

**Cara membaca hasil:**

- **Consumer baris perintah aktif.** `WmiPrvSE.exe` PID 3964, anak `svchost.exe -k DcomLaunch` PID 936, dibuat Kamis 12:11:52 UTC (19:11:52 WIB), sekitar 22 detik setelah service `WinHlpSvc` dipasang, dan memuat `wbemcons.dll` pada detik yang sama. Itu padanan memori dari rule Sigma untuk `CommandLineEventConsumer` [S22].
- **Payload dijalankan dari WMI.** psscan menemukan dua instance `hlpsvc.exe` yang sudah berakhir dengan induk `WmiPrvSE.exe` PID 3964, Sabtu 05:11:52 dan 05:36:52 UTC (12:11:52 dan 12:36:52 WIB), masing-masing berakhir satu detik kemudian; instance service PID 6412 tetap berjalan. Dua objek ini sisa, bukan jumlah eksekusi. Proses anak `WmiPrvSE.exe` yang tidak lazim adalah pola yang disarankan ATT&CK untuk dipantau [S21].
- **Isi repository ter-cache cocok dengan disk.** `wmi-parser` menemukan consumer, filter, dan binding yang sama dengan `OBJECTS.DATA` di E05-W1 dan Sysmon 19-21 di Day 11. Karena isi cache tidak lengkap, hasil ini menguatkan disk, bukan menggantikannya.

Kesimpulan untuk Sari: WMI subscription yang ditemukan di disk juga aktif di memori saat snapshot, menjalankan payload yang sama. Tidak ada consumer lain yang terlihat di cache repository, tetapi karena cache tidak lengkap, kalimat "tidak ada subscription lain" tetap bersandar pada `OBJECTS.DATA` dan Sysmon di disk.

**Variasi:** bila `wmi-parser` tidak menemukan apa pun di file `.dat`, coba file `.vacb` dari `SharedCacheMap`, yang memuat halaman cache lain dari file yang sama; atau jalankan `windows.dumpfiles --filter 'OBJECTS\.DATA' --ignore-case` tanpa offset untuk mengambil semua objek file yang cocok, karena repository bisa terbuka lewat lebih dari satu objek file [S18].

**Kapan gagal:** `WmiPrvSE.exe` bisa berakhir saat tidak dipakai, dan `OBJECTS.DATA` bisa tidak ter-cache sama sekali; dalam kedua kasus memori tidak memberi apa-apa tentang WMI, dan yang ditulis adalah "tidak dapat dinilai dari memori".

### 2.7 Driver, callback, dan tanda tangan

Langkah ini menjawab pertanyaan kelima Sari. Plugin dijalankan 13:10 sampai 13:55, pemeriksaan tanda tangan 14:30 sampai 15:05.

**Tujuan:** memastikan semua modul dan driver kernel dikenal dan bertanda tangan, tidak ada driver yang alamatnya jatuh di luar modul dikenal, dan semua callback dimiliki modul yang dikenal.

```bash
vol -q -r csv -f "$IMG" windows.modules > "$OUT/modules.csv"
vol -q -r csv -f "$IMG" windows.modscan > "$OUT/modscan.csv"
vol -q -r csv -f "$IMG" windows.driverscan > "$OUT/driverscan.csv"
vol -q -r csv -f "$IMG" windows.malware.drivermodule > "$OUT/drivermodule.csv"
vol -q -r csv -f "$IMG" windows.callbacks > "$OUT/callbacks.csv"
vol -q -r csv -f "$IMG" windows.ssdt > "$OUT/ssdt.csv"
grep -v -i -E '\\SystemRoot\\System32\\drivers\\|\\SystemRoot\\system32\\' "$OUT/modules.csv"
```

- `windows.modules`: modul kernel dari daftar aktif [S17]; `windows.modscan`: modul dari pool scanning.
- `windows.driverscan`: objek driver dari pool scanning [S14].
- `windows.malware.drivermodule`: driver yang alamat awalnya tidak jatuh di modul yang dikenal [S15].
- `windows.callbacks`: callback kernel terdaftar [S16]; `windows.ssdt`: tabel panggilan sistem.
- `grep -v`: menyaring modul di luar dua folder driver standar.

Keluaran ilustrasi (ringkasan dan baris yang menonjol; kolom dipangkas):

```
modules      214 baris | modscan 214 baris, nama dan base sama
driverscan   162 baris
drivermodule 3 baris  : \Driver\ACPI_HAL, \Driver\PnpManager, \FileSystem\RAW  (Known Exception True)
callbacks    47 baris : semua Module terpetakan; nol baris dengan Module tidak tersedia
ssdt         semua entri menunjuk ntoskrnl.exe atau modul win32k

modules di luar System32\drivers dan System32:
Base                Size     Name           Path
0xfffff80745a10000  0x16000  winpmem.sys    \??\C:\Windows\winpmem.sys
0xfffff80746c20000  0x7b000  SysmonDrv.sys  \SystemRoot\SysmonDrv.sys

driverscan (pmem):
Offset          Start               Size     Service Key  Driver Name   Name
0xd38b2a90c3e0  0xfffff80745a10000  0x16000  pmem         \Driver\pmem  \Driver\pmem

callbacks (contoh):
Type                           Module         Symbol  Detail
PspCreateProcessNotifyRoutine  WdFilter.sys   N/A     N/A
PspCreateProcessNotifyRoutine  SysmonDrv.sys  N/A     N/A
PspCreateProcessNotifyRoutine  cng.sys        N/A     N/A
PspLoadImageNotifyRoutine      WdFilter.sys   N/A     N/A
PspLoadImageNotifyRoutine      SysmonDrv.sys  N/A     N/A
CmRegisterCallbackEx           WdFilter.sys   N/A     N/A
CmRegisterCallbackEx           SysmonDrv.sys  N/A     N/A
```

Pemeriksaan tanda tangan di `JKT-DFIR01`, atas E05-W1 yang di-mount read-only sebagai `G:` (Sigcheck dari toolkit PT JAB, versinya dicatat di inventaris):

```
sigcheck.exe -accepteula -nobanner -c -e -h -s G:\Windows\System32\drivers > \\jkt-evid01\cases\INC-2026-017\analysis\E05-W1\sigcheck\drivers.csv
sigcheck.exe -accepteula -nobanner -c -e -h G:\Windows\SysmonDrv.sys G:\Windows\System32\ntoskrnl.exe > \\jkt-evid01\cases\INC-2026-017\analysis\E05-W1\sigcheck\lain.csv
```

- `-accepteula -nobanner`: tanpa prompt dan tanpa banner [S20].
- `-c`: keluaran CSV; `-e`: hanya executable image; `-h`: hash file; `-s`: rekursif [S20].
- Opsi VirusTotal (`-v`) sengaja tidak dipakai: mengirim hash bukti ke layanan luar butuh persetujuan IC.

**Cara membaca hasil:**

- **Tidak ada modul yang dilepas dari daftar.** modules dan modscan sama (214), jadi tidak ada modul yang hanya terlihat lewat scan.
- **Tidak ada driver tanpa modul.** drivermodule hanya menampilkan tiga komponen Windows yang ditandai `Known Exception` [S15].
- **Dua modul di luar folder standar, keduanya dikenal.** `winpmem.sys` adalah driver responder (`pmem`, bagian 2.4), dengan `Start` dan `Size` di driverscan sama dengan `Base` dan `Size` di modules. `SysmonDrv.sys` adalah driver Sysmon yang memang dipasang di `C:\Windows` oleh penginstalnya; versi dan tanda tangannya dicek di `lain.csv`.
- **Callback dimiliki agen keamanan dan komponen Windows.** Callback proses, image, dan registry dimiliki `WdFilter.sys` (Defender), `SysmonDrv.sys` (Sysmon), dan driver Windows seperti `cng.sys`; tidak ada callback dengan modul tidak tersedia.
- **Tanda tangan.** Dari 214 modul, 213 dipetakan ke file di E05-W1 dan semuanya bertanda tangan Microsoft atau vendor perangkat keras; 11 driver Microsoft yang awalnya tampil tanpa tanda tangan (ditandatangani lewat catalog) berhasil diverifikasi ulang dengan `-f` dan file catalog dari image (bagian 1.7). Modul ke-214 adalah `winpmem.sys` responder, yang dicocokkan dengan catatan Yoga dan 7045 Day 11, bukan dengan file di image.

Kesimpulan untuk Sari: tidak ada tanda persistence atau rootkit tingkat kernel di memori `JKT-WS-0457`. Satu-satunya driver tambahan adalah driver akuisisi milik responder.

**Variasi:** `windows.modules --name <substring>` menyaring modul tertentu, dan `--dump --base <alamat>` mengekstrak satu modul untuk analisis string atau YARA di lab analisis [S17]; hasil dump itu dipakai untuk melihat isi, bukan untuk hash atau tanda tangan (bagian 1.7). Untuk host tanpa image disk, path modul dicocokkan dengan koleksi triage yang memuat folder driver, atau dengan file yang sama di host bersih dari gold image.

**Kapan gagal:** callbacks melewati daftar yang simbolnya tidak ada di build itu tanpa error [S16]; hasil sedikit di build baru bisa berarti daftar tidak terbaca. Bila semua plugin kernel tampak "bersih" tetapi ada dugaan kuat rootkit (misalnya proses yang terlihat di psscan tetapi tidak di pslist, Day 15), analisis lanjut diserahkan ke retainer PT Forensik Digital Contoh.

### 2.8 Menyatukan C2 dan persistence

Langkah ini menyatukan temuan memori dan disk untuk satu host, sebagai dasar jawaban ke Sari. Baca kolom "Arti", karena setiap baris menyumbang satu bagian cerita.

| Sumber | Temuan | Arti |
|---|---|---|
| netscan (memori) | `hlpsvc.exe` PID 6412 ke `203.0.113.205:443`: 2 `CLOSED` Jumat sebelum isolasi, 5 `CLOSED` dan 1 `SYN_SENT` Sabtu | Payload adalah pemilik kanal C2, masih hidup dan mencoba setiap sekitar 5 menit |
| netstat (memori) | `SYN_SENT` yang sama, tanpa `ESTABLISHED` ke C2 | Koneksi aktif sepakat dengan netscan; isolasi bekerja |
| E02 `ActiveNetConnections.txt` | PID 6412 `SYN_SENT` ke `203.0.113.205:443` pukul 13:06 WIB | Sumber independen dari Volatility |
| E02 `DnsCache.txt` | Tidak ada `sync-win.example.net` | Payload menghubungi IP langsung; blok IP wajib selain sinkhole |
| netscan (memori) | 1 `CLOSED` ke `198.51.100.205:443` Jumat 20:08:41 WIB, pemilik tidak terbaca | Sisa koneksi exfil ada, proses pengirim tidak bisa dibuktikan |
| svcscan dan printkey (memori) | `WinHlpSvc` running, PID 6412, key service sama dengan disk, tidak volatile | Persistence service hidup dan tidak dimanipulasi di memori |
| pstree, psscan, dlllist, dumpfiles (memori) | `WmiPrvSE.exe` 3964 memuat `wbemcons.dll`; 2 instance `hlpsvc.exe` berinduk 3964; consumer dan filter di cache `OBJECTS.DATA` | WMI subscription aktif dan menjalankan payload yang sama |
| svclist, svcdiff, modules, modscan, drivermodule, callbacks, ssdt (memori) | Tidak ada selisih atau modul tak dikenal | Tidak ada service tersembunyi atau persistence kernel yang terlihat |
| disk E05 (Day 11) | 7045 `WinHlpSvc`, registry Services, Sysmon 19-21, `OBJECTS.DATA` | Korroborasi riwayat: kapan dan bagaimana dipasang |
| log firewall dan proxy | Exfil sekitar 6 GB ke `198.51.100.205` 18:40 sampai 20:10 WIB; beacon ke `203.0.113.205` | Rentang waktu dan volume yang tidak dimiliki memori |

Kesimpulan: `hlpsvc.exe` yang berjalan sebagai service `WinHlpSvc` (LocalSystem) adalah satu-satunya proses yang menghubungi C2, dengan dua jalur persistence yang sama-sama aktif di memori, dikonfirmasi oleh artefak disk. Memori menangkap upaya beacon yang tidak pernah sampai ke firewall (diblok di host oleh isolasi), dan sisa koneksi exfil tanpa pemilik; disk memberi riwayat pemasangan; log jaringan memberi rentang dan volume. Bersama, kasus lengkap untuk host ini, dengan satu lubang yang tetap terbuka: proses pengirim exfil.

**Kapan gagal:** menulis "proses exfil adalah `hlpsvc.exe`" karena ia satu-satunya proses mencurigakan yang terlihat adalah lompatan yang tidak didukung bukti. Objek exfil tidak punya pemilik terbaca, dan proses lain yang sudah berakhir 16 jam sebelumnya tidak harus meninggalkan jejak.

### 2.9 Korelasi dengan log jaringan, daftar IOC, dan jawaban untuk Sari

Langkah ini menjawab pertanyaan keenam Sari dan menutup action item. Koneksi netscan dicocokkan dengan log jaringan:

- IP remote dari netscan dicari di log jaringan (bila ada) untuk pola beacon. Interval sekitar lima menit dari waktu `Created` netscan dibandingkan dengan selisih waktu koneksi `10.10.45.57` ke `203.0.113.205` di log firewall Kamis sampai Jumat; pertanyaan ini diserahkan ke Sari sebagai query untuk tim SOC, karena memori hanya memberi enam titik waktu.
- Proses pemilik dikaitkan ke eksekusi (Prefetch dan 4688, Day 05 dan Day 07).
- Ini menautkan satu snapshot memori ke aktivitas jaringan dari waktu ke waktu.

Tabel IOC berikut disusun dari memori dan disk kedua workstation; baca kolom "Sumber", karena setiap nilai harus bisa ditelusuri ke bukti, dan kolom "Jenis" untuk membedakan nilai atomik dari pola perilaku.

| Jenis | Nilai | Host | Sumber |
|---|---|---|---|
| File (atomik) | `C:\ProgramData\WinHlpSvc\hlpsvc.exe`, SHA-256 `a4e9...` | `JKT-WS-0457` | File di E05-W1 (bukan dump memori) |
| File (atomik) | `C:\ProgramData\MsEdgeSync\sync.exe`, SHA-256 `3b7d...` | `JKT-WS-0441` | File di E06-W1 |
| Service | `WinHlpSvc`, display `Windows Help Service`, Auto, LocalSystem | `JKT-WS-0457` | 7045 dan registry (Day 11), svcscan dan printkey (E01) |
| WMI | `HlpFilter`, `HlpConsumer` (`CommandLineEventConsumer`) | `JKT-WS-0457` | Sysmon 19-21 dan `OBJECTS.DATA` (Day 11), cache `OBJECTS.DATA` (E01) |
| Run dan task | Run HKLM `MsEdgeSync`; task `\Microsoft\Windows\Servicing\SystemSync` | `JKT-WS-0441` | Day 11 |
| Perilaku | `WmiPrvSE.exe` memuat `wbemcons.dll`; proses anak `WmiPrvSE.exe` dari `C:\ProgramData` | Semua workstation | E01 (dlllist, psscan) dan rule Sigma [S22] |
| Perilaku | Service baru dengan binary di `C:\ProgramData` dan start Auto | Semua workstation | Day 11 dan E01 |
| Jaringan (atomik) | `203.0.113.205:443`, `sync-win.example.net` | Semua | Log firewall, E01 netscan, IR |
| Jaringan (atomik) | `198.51.100.205:443` | Semua | Log firewall dan proxy, E01 netscan |
| Jaringan (perilaku) | Koneksi keluar langsung ke IP (tanpa proxy, tanpa DNS) tiap sekitar 5 menit dengan jitter beberapa detik dari proses di `C:\ProgramData` | Semua workstation | E01 netscan dan E02 |

Jawaban tertulis yang dikirim ke Sari Senin 2026-11-02 pukul 16:50 WIB, disimpan di `\\jkt-evid01\cases\INC-2026-017\notes\memori-E01-jaringan-persistence.md`:

```
INC-2026-017 | Action item PIR: pemeriksaan memori JKT-WS-0457 sebelum arsip | Senin 2026-11-02
Dari: <kamu> (L2 forensik) | Untuk: Sari Kusuma (TL)
Bukti: E01 (memori, Sabtu 2026-10-10 12:42:05-12:57:30), E02 (paket investigasi 13:05-13:12),
       E05-W1 (disk). Volatility 3 2.28.2 di jkt-dfir02. Semua waktu WIB.

1. KANAL C2 KEDUA: tidak terlihat di memori. Tujuan eksternal hanya 203.0.113.205 (C2, hlpsvc.exe),
   198.51.100.205 (exfil, sisa tanpa pemilik), dan layanan Defender (MsSense.exe). Listener semua
   milik proses Windows. Kanal yang hanya aktif Kamis-Jumat tidak bisa dinilai dari snapshot:
   usul query log firewall untuk tujuan eksternal lain dari 10.10.45.57, 2026-10-08 s.d. 2026-10-09.
2. PROSES C2: hlpsvc.exe PID 6412 (service WinHlpSvc, LocalSystem, berjalan sejak Kamis 19:11:31).
   Upaya ke 203.0.113.205:443 tiap sekitar 5 menit, berlanjut setelah isolasi (terakhir SYN_SENT
   12:41:47), tanpa koneksi tersambung setelah isolasi. Dikuatkan netstat dan E02.
   PROSES EXFIL: TIDAK DAPAT DIPASTIKAN. Ada satu sisa koneksi ke 198.51.100.205:443 dibuat Jumat
   20:08:41 (dalam jendela exfil), tetapi pemiliknya tidak terbaca. Jangan ditulis hlpsvc.exe.
3. SERVICE TERSEMBUNYI: tidak ada. svcscan = svclist (731), svcdiff kosong, semua punya key registry.
4. PERSISTENCE DI MEMORI: WinHlpSvc running dan key-nya sama dengan disk (tidak volatile);
   WMI HlpFilter/HlpConsumer aktif (WmiPrvSE.exe memuat wbemcons.dll, menjalankan hlpsvc.exe).
   Run dan task tidak ada temuan. Satu payload, dua jalur, seperti di disk.
5. KERNEL: tidak ada tanda. Modul, driver, callback, SSDT semua dikenal dan bertanda tangan;
   satu-satunya driver tambahan adalah pmem/winpmem.sys milik responder (Yoga, 12:42:08).
6. IOC: tabel terlampir (file + hash dari disk, service, WMI, Run/task 0441, IP/domain, pola beacon).
   Catatan: payload menghubungi IP langsung; blok IP tetap perlu walau domain sudah di-sinkhole.

KEYAKINAN: tinggi untuk 2 (C2), 3, 4, 5 (tiga sumber atau lebih sepakat). Sedang untuk 1
(snapshot satu titik). Butir exfil: tidak terjawab dari memori; log jaringan tetap satu-satunya bukti.
Jejak responder di memori: sesi ir-admin, cmd.exe, winpmem, driver pmem; dilabeli, bukan temuan.
Setelah ini E01-E06 siap dipindah ke arsip dari sisi forensik host.
```

**Kapan gagal:** IOC tanpa kolom sumber akan dipakai tim deteksi tanpa tahu mana yang kuat; hash dari dump memori yang ikut masuk daftar akan menghasilkan rule yang tidak pernah cocok dengan file di disk host lain.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** `LAB-WS01` (`172.16.50.10`, Windows 11, Sysmon, audit diperluas, snapshot bersih), `LAB-DFIR01` (`172.16.50.20`, VM analisis dengan Volatility 3 2.28.x di virtualenv dan symbol table untuk build `LAB-WS01`), jaringan host-only `172.16.50.0/24`, folder kasus lab `CASE-2026-LAB-016`. Semua aktivitas uji jinak: fitur administrasi biasa, program buatan sendiri yang tidak berbahaya, atau test Atomic Red Team yang dirujuk lewat ID teknik ATT&CK dan GUID-nya setelah isinya dibaca (Day 15); tidak ada sampel liar. Opsional: log jaringan lab (misalnya log akses web server di `LAB-DFIR01`).

1. **Siapkan.** Di `LAB-DFIR01`, jalankan web server sederhana di port 8080 dan catat log aksesnya. Di `LAB-WS01` (snapshot), jalankan skrip jinak buatan sendiri yang mengirim permintaan HTTP ke `http://172.16.50.20:8080/` tiap 60 detik, sebagai pengganti beacon. Buat satu service jinak `LabSvc16` (boleh berstatus stopped, cukup terdaftar), satu Run key HKCU `LabRun16` yang menjalankan `notepad.exe`, dan satu WMI subscription jinak `LabFilter16`/`LabConsumer16` dengan `CommandLineEventConsumer` yang menulis waktu ke `C:\LabWmi16\log.txt`. Catat waktu tiap langkah dalam WIB dan UTC.
2. **Akuisisi.** Ambil memori `LAB-WS01` dengan WinPmem ke disk `LAB-USB`, atau suspend VM dan pakai file memori snapshot (Day 14). Catat waktu mulai dan selesai, lalu hash image.
3. **netscan.** Jalankan netscan (bagian 2.2). Temukan koneksi ke `172.16.50.20:8080` dan proses pemiliknya; hitung selisih waktu `Created` antar objek dan bandingkan dengan interval 60 detik yang kamu set.
4. **netstat.** Jalankan netstat (bagian 2.3); bandingkan dengan netscan. Putus akses simbol dulu untuk melihat pesan bila symbol table `tcpip.sys` tidak ada, lalu ulangi dengan simbol tersedia.
5. **svcscan.** Jalankan svcscan, svclist, dan svcdiff (bagian 2.4). Temukan `LabSvc16` dan service driver WinPmem-mu; catat apakah svcscan dan svclist memberi jumlah yang sama.
6. **Registry in-memory.** Jalankan hivelist dan printkey atas Run (bagian 2.5), dengan path yang benar untuk `NTUSER.DAT` dan untuk SOFTWARE. Temukan `LabRun16`; bandingkan dengan registry disk (Day 09). Jalankan printkey `--recurse` atas `ControlSet001\Services` dan catat key mana yang `Volatile` True di host bersih ini; itu baseline-mu.
7. **WMI.** Ikuti bagian 2.6: cari `WmiPrvSE.exe` yang memuat `wbemcons.dll`, proses `cmd.exe` anak `WmiPrvSE.exe` di psscan, dan isi cache `OBJECTS.DATA` dengan filescan dan dumpfiles. Catat induk proses yang dijalankan consumer; ini membuktikan hubungan induk yang dipakai di bagian 1.6.
8. **Driver (opsional).** Jalankan modules, modscan, driverscan, drivermodule, callbacks, dan ssdt (bagian 2.7); amati driver sah vs tidak lazim. Identifikasi driver WinPmem-mu dan callback Sysmon.
9. **Korelasi.** Isi tabel bagian 2.8 untuk proses beacon jinakmu: koneksi (netscan), proses dan induk (Day 14 dan 15), persistence (svcscan, printkey, WMI), dan korroborasi disk (Day 11). Tautkan ke log akses web server bila ada (bagian 2.9), lalu susun tabel IOC lab dengan kolom sumber.

**Hasil yang sebaiknya tersimpan:**

- netscan menampilkan koneksi keluar dengan proses pemilik, dan interval `Created` dibandingkan dengan interval yang kamu set.
- netstat dibandingkan dengan netscan, termasuk pesan saat symbol table `tcpip.sys` tidak ada.
- svcscan menemukan service persistence uji; jumlah svcscan dan svclist dicatat, svcdiff dijalankan.
- printkey menampilkan Run key saat snapshot dengan path yang benar; dibandingkan dengan disk; baseline key volatile host bersih tercatat.
- WMI subscription jinak terlihat dari tiga jejak tidak langsung, dengan induk proses consumer tercatat.
- (Opsional) driver dan callback diperiksa, driver WinPmem diidentifikasi.
- Satu insiden disatukan dari memori (koneksi, injeksi bila ada, persistence) dan disk, dengan tabel IOC berkolom sumber.

**Variasi tantangan:** jalankan beacon jinak, akuisisi memori, lalu hentikan beacon dan akuisisi lagi. Bandingkan netscan dua image: apakah koneksi yang sudah tutup masih muncul di netscan (struktur sisa) di image kedua? Tulis implikasinya untuk menafsir state koneksi di memori. Variasi kedua: blok trafik ke `172.16.50.20` dengan Windows Firewall di `LAB-WS01` sebelum akuisisi, lalu catat state yang muncul untuk upaya beacon yang diblok; hasilnya menjawab pertanyaan `SYN_SENT` atau `CLOSED` di bagian 1.3 untuk build-mu.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat membaca jaringan dan persistence dari memori. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| netscan tidak menampilkan koneksi | Koneksi sudah tutup dan ditimpa; smear | Snapshot lebih awal; perhatikan state; tulis "tidak tersisa", bukan "tidak terjadi" |
| netscan menampilkan alamat atau state acak | Tabel struktur bawaan tidak cocok dengan build (Windows 11 memakai tabel terdekat) | Validasi dengan netstat dan paket investigasi EDR (bagian 2.3) |
| netstat gagal atau kosong | Symbol table `tcpip.sys` tidak ada di mesin offline; plugin rapuh antar versi | Jendela proxy ke symbol server sesuai prosedur; jalankan `-vvv`; netscan sebagai utama |
| PID dan Owner `N/A` | Pointer pemilik sudah tidak valid untuk objek sisa | Catat sebagai pemilik tidak terbaca; jangan menebak dari proses lain |
| svcscan tidak menemukan service | Service dihapus sebelum snapshot | Korelasi 7045 dan registry disk (Day 11) |
| svclist atau svcdiff kosong dengan peringatan | Build di bawah 15063 atau 32-bit | Hasil kosong bukan "tidak ada service tersembunyi"; pakai perbandingan svcscan dengan registry |
| printkey key tidak ditemukan | Path ditulis dengan awalan `HKLM` atau `Software\` di hive SOFTWARE | Tulis path relatif terhadap root hive; pakai `--offset` dari hivelist (bagian 1.5) |
| printkey butuh offset | hivelist memberi offset | Jalankan hivelist dulu; pakai `--offset` untuk hive tertentu |
| Tidak ada plugin WMI | Volatility 3 tidak punya plugin WMI | Pakai dlllist, psscan, filescan, dumpfiles (bagian 2.6) dan disk |
| driverscan penuh driver sah | Banyak driver normal | Fokus drivermodule, path di luar folder standar, dan tanda tangan file di disk |
| Driver Microsoft tampil tanpa tanda tangan | Catalog dibaca dari mesin analisis, bukan dari image | Periksa ulang dengan `sigcheck -f` dan file catalog dari image |
| Hasil tidak konsisten | Smear image (Day 14) | Image dari snapshot VM di lab; di kasus nyata, validasi dengan sumber kedua |

## 5. Kesalahan umum dan jebakan

- **Mengira semua koneksi netscan aktif.** Struktur sisa bisa koneksi lama; perhatikan state.
- **Mengabaikan proses pemilik koneksi.** Nilai C2 ada di "proses apa menghubungi IP apa".
- **Menebak pemilik koneksi yang tidak terbaca.** Sisa koneksi exfil tanpa pemilik bukan bukti bahwa proses mencurigakan yang kebetulan masih berjalan adalah pengirimnya.
- **Menghitung sisa sebagai jumlah kejadian.** Enam objek beacon tidak berarti enam upaya; pool dipakai ulang tanpa urutan.
- **Membaca registry in-memory sebagai riwayat.** Itu state saat snapshot; riwayat ada di disk plus transaction log (Day 09).
- **Menulis path printkey seperti di Registry Editor.** `HKLM\SOFTWARE\...` atau `Software\...` di hive SOFTWARE tidak cocok; path relatif terhadap root hive.
- **Mengarang plugin.** Volatility 3 2.28.2 tidak punya plugin WMI; menulis nama plugin yang tidak ada di laporan merusak kredibilitas seluruh temuan.
- **Tidak mengorelasikan ke disk/log.** Memori menguat dengan 7045, registry disk, dan log jaringan.
- **Over-report driver sah sebagai rootkit.** Banyak driver normal; callback Defender dan Sysmon memang ada di daftar yang sama dengan callback rootkit; fokus anomali.
- **Memakai hash dari dump memori sebagai IOC.** Image di memori sudah berubah dari file aslinya; hash IOC diambil dari file di disk.
- **Melaporkan driver responder sebagai temuan.** WinPmem tertangkap di image yang ia buat sendiri; cocokkan dengan catatan responder dan 7045.
- `[komunitas, belum terkonfirmasi]` netscan adalah cara utama menautkan koneksi ke proses di memori, dan menangkap koneksi berumur pendek yang tak masuk log; netstat lebih rapuh antar versi. Reorganisasi dan keandalan plugin perlu dicek di versi [S1]. Untuk 2.28.2, sumber kode memastikan netstat bergantung pada symbol table `tcpip.sys` dan netscan memakai tabel struktur bawaan yang berhenti di build 20348 [S6][S7]; seberapa sering keduanya meleset di build Windows 11 tertentu belum terkonfirmasi.

## 6. Catatan terkini

Bagian ini menampung detail versi dan sumber yang bisa berubah; tidak mengubah alur analisis di atas.

- **Volatility 3 2.28.2** (17 September 2026) masih rilis stabil terbaru per 2026-10-22, sama dengan versi yang dibekukan di `jkt-dfir02`, jadi tidak ada keputusan update untuk kasus ini [S5]. 2.28.x menyediakan `windows.netscan`, `windows.netstat`, `windows.svcscan`, `windows.registry.*`, dan `windows.driverscan` [S1].
- **Subpaket `windows.malware`** dibuat di 2.26.2: plugin malware dipindah (contoh `windows.hollowprocesses` menjadi `windows.malware.hollowprocesses`), nama lama deprecated tetapi masih berjalan sampai dihapus [S5]. Untuk Day ini yang relevan adalah `windows.malware.svcdiff` dan `windows.malware.drivermodule` [S1]. `windows.callbacks`, `windows.driverscan`, `windows.modules`, `windows.modscan`, `windows.ssdt`, `windows.netscan`, `windows.netstat`, `windows.svcscan`, dan `windows.svclist` tetap di tingkat `windows.*` [S1].
- **`windows.svclist` dan `windows.svcdiff`** ditambahkan di 2.8.0, bersama dukungan `windows.callbacks` untuk lebih banyak jenis callback [S5]; **`windows.scheduled_tasks`** ditambahkan di 2.11.0 dan kini berada di `windows.registry.scheduled_tasks` [S5][S13]. Cek nama persis dengan `vol -h` di versi-mu.
- **Tabel struktur netscan** bawaan untuk x64 berhenti di build 20348; build Windows 11 memakai tabel terdekat [S6]. Bila rilis berikutnya menambah tabel untuk build 22621 ke atas, hasil netscan image yang sama bisa berubah; catat versi Volatility di setiap hasil.
- **netscan menangkap koneksi aktif dan sisa**; netstat lebih dekat ke state aktif dan bergantung pada symbol table `tcpip.sys` dari PDB [S7].
- **Paket investigasi Defender for Endpoint** (Microsoft Learn, ms.date 2026-07-23) memuat folder Network connections (`ActiveNetConnections.txt`, `Arp.txt`, `DnsCache.txt`, `IpConfig.txt`, log firewall) dan folder Autoruns, Processes, Scheduled tasks [S19]. Isi bisa berubah antar versi sensor.
- **Sigcheck** halaman Microsoft Learn terbit 2026-10-15, berjalan di Windows 11 dan Server 2019 ke atas [S20]. Versi di toolkit PT JAB dicatat di inventaris; update di tengah kasus mengikuti aturan pembekuan versi (Day 02).
- **ATT&CK T1546.003** versi 1.5 (dimodifikasi 2025-10-24) menyarankan memantau pembuatan filter, consumer, dan binding WMI, eksekusi `mofcomp.exe`, dan proses anak `WmiPrvSE.exe` yang tidak lazim [S21].
- Day 17-18 adalah simulasi kasus penuh yang memakai seluruh keterampilan disk dan memori (Day 05-16).

## 7. Cheat sheet

```
SIAP        sha256sum E01-W1 vs master | vol -q -f IMG windows.info (build kernel, SystemTime UTC)
JARINGAN    windows.netscan (scan pool TcpL/TcpE/UdpA; aktif + sisa; tabel struktur s.d. 20348)
            windows.netstat (tabel partisi tcpip.sys; butuh simbol tcpip.sys; hanya aktif)
            kolom: Proto LocalAddr LocalPort ForeignAddr ForeignPort State PID Owner Created(UTC)
            C2: proses tak lazim -> IP eksternal ; korelasi injeksi (Day 15) ; Owner N/A = jangan ditebak
STATE       LISTENING | ESTABLISHED (aktif) | SYN_SENT (mencoba) | CLOSED (sisa; Created != waktu tutup)
            host terisolasi: deret SYN_SENT/CLOSED ke C2 = payload hidup + isolasi bekerja + interval beacon
SERVICE     windows.svcscan (record SCM + Binary(Registry)) | windows.svclist | windows.malware.svcdiff (scan - list)
            svclist/svcdiff: x64, Win10 15063+ ; korelasi 7045 + registry disk (Day 11)
REGISTRY    windows.registry.hivelist [--filter] -> printkey --offset <hive> --key <relatif root hive> [--recurse]
            SOFTWARE: Microsoft\Windows\CurrentVersion\Run | NTUSER: Software\Microsoft\...\Run | SYSTEM: ControlSet001\Services\X
            kolom Volatile = hanya di memori ; windows.registry.scheduled_tasks (TaskCache in-memory)
WMI         TIDAK ADA plugin WMI: dlllist WmiPrvSE (wbemcons.dll) | psscan anak WmiPrvSE | filescan+dumpfiles OBJECTS.DATA
KERNEL      modules vs modscan | driverscan | windows.malware.drivermodule | callbacks | ssdt
            tanda: path di luar System32\drivers, modul tak terpetakan, callback Module tidak tersedia
            tanda tangan: sigcheck pada FILE DI DISK (bukan dump), catalog -> -f ; WinPmem = responder
KORELASI    netscan + log firewall/proxy (rentang, volume, interval) + paket EDR (ActiveNetConnections, DnsCache)
            svcscan + 7045 ; printkey Run + registry disk + MFT ; WmiPrvSE + Sysmon 19-21 + OBJECTS.DATA
IOC         hash dari disk ; service/WMI/Run/task ; IP+domain (atomik) ; pola beacon dan perilaku (tahan lama)
BATAS       snapshot sesaat ; sisa != jumlah ; tidak ditemukan != tidak terjadi ; registry = state ; smear
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "netscan atas E01 tidak bisa menentukan proses pemilik koneksi ke `198.51.100.205`, dan satu-satunya proses mencurigakan yang berjalan adalah `hlpsvc.exe`. Jadi `hlpsvc.exe` yang mengirim 6 GB itu." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Objek koneksi ke `198.51.100.205:443` adalah sisa berstate `CLOSED` dengan `PID` dan `Owner` tidak terbaca, karena pointer pemiliknya sudah tidak valid. Memori diambil sekitar 16 jam 32 menit setelah exfil berakhir; proses lain yang mengirim data dan sudah berakhir tidak harus meninggalkan jejak. Yang boleh ditulis: sisa koneksi ke tujuan exfil ada pada waktu yang cocok dengan log firewall, tetapi proses pengirimnya tidak dapat dipastikan dari memori. Lihat bagian 1.2, 1.3, dan 2.8.

</details>

**2. Skenario keputusan.** Di `jkt-dfir02` (tanpa internet), `windows.netstat` berhenti karena symbol table `tcpip.sys` tidak bisa dibuat. Apa yang kamu lakukan?

- A. Salin E01-W1 ke laptop kantor yang punya internet supaya Volatility bisa mengunduh simbol.
- B. Minta jendela proxy khusus ke Microsoft Symbol Server sesuai prosedur, jalankan ulang netstat, dan catat jendela, PDB, dan hash symbol table di case notes.
- C. Lewati netstat dan tulis "tidak ada koneksi aktif selain yang ditemukan netscan".

<details><summary>Jawaban</summary>

B. netstat membutuhkan symbol table `tcpip.sys` yang dibuat dari PDB, dan jendela proxy terbatas ke symbol server adalah jalan sah yang tercatat. A keliru karena memindahkan bukti ke mesin yang tidak terkendali. C keliru karena kegagalan plugin bukan hasil negatif; netstat ada justru untuk memvalidasi netscan yang di Windows 11 memakai tabel struktur terdekat. Lihat bagian 1.1 dan 2.3.

</details>

**3. Pertanyaan jebakan.** "svcscan dan Run key di memori tidak menampilkan `HlpConsumer`, jadi WMI subscription yang ditemukan di disk sudah tidak aktif saat memori diambil." Benarkah?

<details><summary>Jawaban</summary>

Tidak. WMI subscription memang tidak pernah muncul di svcscan, Run key, atau TaskCache, karena ia disimpan di repository WMI, bukan sebagai service atau autostart registry. Volatility 3 juga tidak punya plugin WMI. Yang menunjukkan subscription aktif adalah `WmiPrvSE.exe` yang memuat `wbemcons.dll`, instance `hlpsvc.exe` berinduk `WmiPrvSE.exe` di psscan, dan isi cache `OBJECTS.DATA` dari dumpfiles. Lihat bagian 1.6 dan 2.6.

</details>

**4. Skenario keputusan.** `windows.callbacks` menampilkan `WdFilter.sys` dan `SysmonDrv.sys` mendaftarkan callback pembuatan proses, image load, dan registry. Apa langkah yang tepat?

- A. Laporkan sebagai rootkit, karena callback proses dan registry adalah teknik rootkit.
- B. Pastikan setiap callback dimiliki modul yang terpetakan ke driver dikenal, periksa tanda tangan file driver itu di image disk, dan fokus pada callback yang modulnya tidak tersedia.
- C. Abaikan callbacks, karena hasilnya selalu penuh driver sah.

<details><summary>Jawaban</summary>

B. Defender dan Sysmon memakai callback yang sama dengan rootkit karena begitulah cara mereka memantau; yang mencurigakan adalah callback yang modulnya tidak bisa dipetakan, bukan jumlahnya. Tanda tangan diperiksa pada file di disk, bukan dump memori. A keliru karena menyamakan teknik sah dengan anomali. C keliru karena callback tak dikenal adalah salah satu sedikit tanda rootkit kernel yang bisa dilihat dari memori. Lihat bagian 1.7 dan 2.7.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Sari, dalam tiga kalimat, kenapa deret `SYN_SENT` dan `CLOSED` dari `hlpsvc.exe` ke `203.0.113.205` setelah isolasi adalah kabar baik sekaligus bahan IOC.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Setelah isolasi, `hlpsvc.exe` masih mencoba menghubungi `203.0.113.205:443` sekitar setiap lima menit, tetapi tidak ada satu pun yang tersambung, jadi isolasinya bekerja dan payload tidak menerima perintah selama 13 jam itu. Upaya itu juga membuktikan payload masih hidup sebagai service, dan karena cache DNS tidak memuat domain C2, payload menghubungi IP langsung, sehingga blok IP sama pentingnya dengan sinkhole. Interval lima menit dengan jitter beberapa detik dari proses di `C:\ProgramData` adalah pola yang bisa dipakai tim deteksi untuk mencari host lain, lebih tahan lama daripada IP-nya sendiri."

Kesalahan yang sering muncul:
- Menyebut jumlah objek (enam) sebagai jumlah upaya beacon.
- Menulis bahwa C2 masih tersambung setelah isolasi.
- Hanya menyerahkan IP sebagai IOC tanpa pola perilakunya.

</details>

**6. Pertanyaan jebakan.** "Untuk IOC, ambil hash SHA-256 `hlpsvc.exe` dari hasil `--dump` modul proses di memori E01, karena itu payload yang benar-benar berjalan." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Image yang dimuat ke memori sudah berubah dari file aslinya (section dipetakan, alamat direlokasi), sehingga hash dump memori tidak akan cocok dengan file yang sama di disk host lain, dan rule deteksi berbasis hash itu tidak pernah memicu. Hash IOC diambil dari file di image disk (`a4e9...` dari E05-W1), dan dicatat sumbernya. Alasan yang sama berlaku untuk pemeriksaan tanda tangan driver. Lihat bagian 1.7, 1.8, dan 2.9.

</details>

**7. Interview question (English).** "You have a memory image from a host that was isolated by EDR hours before acquisition. How do you tie network activity to processes, and what can't the memory image tell you?"

<details><summary>Sample answer</summary>

"I run netscan, which pool-scans for TCP and UDP endpoint structures, so it returns both active connections and freed remnants with the owning PID and a created timestamp in UTC. I validate it with netstat, which walks the live tcpip.sys tables, and with whatever the EDR collected, such as the active connections list in the investigation package. On an isolated host I expect a series of SYN_SENT or CLOSED attempts to the C2 address, which tells me the implant is alive, isolation is holding, and gives me a beacon interval. Then I tie the owning process to its persistence, for example a service in svcscan and the in-memory SYSTEM hive, and confirm against disk artifacts. What memory can't give me is history: remnants are a random survival sample, owner pointers on old objects are often invalid, and anything that closed hours earlier may simply be gone. So if a remnant has no readable owner, I report the connection and leave the process unattributed, and I go to firewall and proxy logs for the timeline and volume."

What makes this answer strong: it explains why two plugins disagree, uses an independent third source, turns the isolation pattern into evidence, and draws a clear line between what a snapshot proves and what only logs can answer, including refusing to guess an owner.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Volatility 3 Windows plugins dan dokumentasi (netscan, svcscan, registry, driverscan) | https://volatility3.readthedocs.io/ | primer | diakses 2026-10-09 (Day 14); halaman `volatility3.plugins.windows` diperiksa ulang 2026-10-22 | Tinggi. Nama plugin dan subpaket `windows.malware` (svcdiff, drivermodule, dan lainnya) serta `windows.registry` (hivelist, printkey, scheduled_tasks, dan lainnya); tidak ada plugin WMI. Keandalan netstat perlu dicek |
| S2 | Endpoint-Forensics Day 14-15 (akuisisi, proses, injeksi) | (lokal) | rujukan internal | 2026-10-09 | Fondasi memori |
| S3 | Endpoint-Forensics Day 09, 11 (registry disk, persistence) | (lokal) | rujukan internal | 2026-10-09 | Korelasi disk |
| S4 | MITRE ATT&CK: T1543.003 Windows Service, T1547.001 Registry Run Keys / Startup Folder, T1071.001 Application Layer Protocol: Web Protocols | https://attack.mitre.org/techniques/T1543/003/ | primer | dirujuk 2026-10-10 | Tinggi untuk ID dan nama teknik |
| S5 | GitHub: volatilityfoundation/volatility3 Releases | https://github.com/volatilityfoundation/volatility3/releases | primer (repo resmi) | 2.28.2 terbit 17 Sep 2026; diakses 2026-10-22 | Tinggi. 2.28.2 rilis terbaru; 2.26.2 memindah plugin malware ke `malware` (nama lama deprecated); 2.8.0 menambah svclist dan svcdiff serta callback lebih lengkap; 2.11.0 menambah scheduled_tasks |
| S6 | GitHub: volatility3 `plugins/windows/netscan.py` | https://raw.githubusercontent.com/volatilityfoundation/volatility3/develop/volatility3/framework/plugins/windows/netscan.py | primer (source) | cabang develop; diakses 2026-10-22 | Tinggi untuk perilaku kode: tag `TcpL`/`TcpE`/`UdpA`, kolom, `--include-corrupt`, tabel x64 berhenti di 20348 dengan fallback ke versi NT yang sama |
| S7 | GitHub: volatility3 `plugins/windows/netstat.py` | https://raw.githubusercontent.com/volatilityfoundation/volatility3/develop/volatility3/framework/plugins/windows/netstat.py | primer (source) | cabang develop; diakses 2026-10-22 | Tinggi untuk perilaku kode: `PartitionTable`/`PartitionCount`, port pool, symbol table `tcpip.sys` via PDB, keluar lebih awal dengan pesan debug |
| S8 | GitHub: volatility3 `plugins/windows/svcscan.py` | https://raw.githubusercontent.com/volatilityfoundation/volatility3/develop/volatility3/framework/plugins/windows/svcscan.py | primer (source) | cabang develop; diakses 2026-10-22 | Tinggi. Scan `services.exe` untuk tag `serH`; kolom; `Binary (Registry)` dan `Dll` dari hive SYSTEM; tabel versi s.d. 25398 |
| S9 | GitHub: volatility3 `plugins/windows/malware/svcdiff.py` | https://raw.githubusercontent.com/volatilityfoundation/volatility3/develop/volatility3/framework/plugins/windows/malware/svcdiff.py | primer (source) | cabang develop; diakses 2026-10-22 | Tinggi. Hasil = scan dikurangi list; x64 Win10 15063+; tujuan menemukan service tersembunyi |
| S10 | GitHub: volatility3 `plugins/windows/svclist.py` | https://raw.githubusercontent.com/volatilityfoundation/volatility3/develop/volatility3/framework/plugins/windows/svclist.py | primer (source) | cabang develop; diakses 2026-10-22 | Tinggi. Signature di image `services.exe`; x64 Win10 15063+ |
| S11 | GitHub: volatility3 `plugins/windows/registry/printkey.py` | https://raw.githubusercontent.com/volatilityfoundation/volatility3/develop/volatility3/framework/plugins/windows/registry/printkey.py | primer (source) | cabang develop; diakses 2026-10-22 | Tinggi. Opsi `--offset`, `--key`, `--recurse`; kolom termasuk `Volatile`; key tidak ditemukan menghasilkan baris tidak terbaca |
| S12 | GitHub: volatility3 `plugins/windows/registry/hivelist.py` | https://raw.githubusercontent.com/volatilityfoundation/volatility3/develop/volatility3/framework/plugins/windows/registry/hivelist.py | primer (source) | cabang develop; diakses 2026-10-22 | Tinggi. Opsi `--filter`, `--dump`; kolom `Offset`, `FileFullPath`, `File output` |
| S13 | GitHub: volatility3 `plugins/windows/registry/scheduled_tasks.py` | https://raw.githubusercontent.com/volatilityfoundation/volatility3/develop/volatility3/framework/plugins/windows/registry/scheduled_tasks.py | primer (source) | cabang develop; diakses 2026-10-22 | Tinggi. TaskCache `Tasks` dan `Tree` dari hive SOFTWARE in-memory; 15 kolom |
| S14 | GitHub: volatility3 `plugins/windows/driverscan.py` | https://raw.githubusercontent.com/volatilityfoundation/volatility3/develop/volatility3/framework/plugins/windows/driverscan.py | primer (source) | cabang develop; diakses 2026-10-22 | Tinggi. Pool tag `Dri\xf6` dan `Driv`; `DriverStart` 0 dipertahankan; kolom |
| S15 | GitHub: volatility3 `plugins/windows/malware/drivermodule.py` | https://raw.githubusercontent.com/volatilityfoundation/volatility3/develop/volatility3/framework/plugins/windows/malware/drivermodule.py | primer (source) | cabang develop; diakses 2026-10-22 | Tinggi. Driver yang alamat awalnya tidak di modul dikenal; daftar `Known Exception` |
| S16 | GitHub: volatility3 `plugins/windows/callbacks.py` | https://raw.githubusercontent.com/volatilityfoundation/volatility3/develop/volatility3/framework/plugins/windows/callbacks.py | primer (source) | cabang develop; diakses 2026-10-22 | Tinggi. Jenis callback yang dibaca; kolom; daftar tanpa simbol dilewati |
| S17 | GitHub: volatility3 `plugins/windows/modules.py` | https://raw.githubusercontent.com/volatilityfoundation/volatility3/develop/volatility3/framework/plugins/windows/modules.py | primer (source) | cabang develop; diakses 2026-10-22 | Tinggi. Opsi `--dump`, `--base`, `--name`; kolom |
| S18 | GitHub: volatility3 `plugins/windows/dumpfiles.py` | https://raw.githubusercontent.com/volatilityfoundation/volatility3/develop/volatility3/framework/plugins/windows/dumpfiles.py | primer (source) | cabang develop; diakses 2026-10-22 | Tinggi. Opsi `--pid`, `--virtaddr`, `--physaddr`, `--filter`; jenis cache dan pola nama file |
| S19 | Microsoft Learn: Take response actions on a device in Microsoft Defender for Endpoint | https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts | primer | ms.date 2026-07-23; diakses 2026-10-22 | Tinggi. Isi paket investigasi (Network connections: `ActiveNetConnections.txt`, `DnsCache.txt`, dan lainnya); isolasi mempertahankan koneksi ke layanan Defender |
| S20 | Microsoft Learn: Sigcheck (Sysinternals) | https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck | primer | terbit 2026-10-15; diakses 2026-10-22 | Tinggi. Opsi `-c`, `-e`, `-h`, `-s`, `-u`, `-f`, `-accepteula`, `-nobanner`, opsi VirusTotal; Windows 11 dan Server 2019 ke atas |
| S21 | MITRE ATT&CK: T1546.003 Windows Management Instrumentation Event Subscription | https://attack.mitre.org/techniques/T1546/003/ | primer | versi 1.5, dimodifikasi 2025-10-24; diakses 2026-10-22 | Tinggi. Saran deteksi: objek filter, consumer, binding; `mofcomp.exe`; proses anak `WmiPrvSE.exe` tidak lazim |
| S22 | Sigma rule: WMI Persistence - Command Line Event Consumer (via detection.fyi) | https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_wmi_persistence_commandline_event_consumer | komunitas (rule SigmaHQ) | dibuat 2018-03-07, dimodifikasi 2021-11-27; diakses 2026-10-22 | Sedang. `WmiPrvSE.exe` memuat `wbemcons.dll`; status test, tingkat false positive belum diketahui |
| S23 | Andrea Fortuna: Volatility, my own cheatsheet (Part 5: Networking) | https://andreafortuna.org/2017/07/24/volatility-my-own-cheatsheet-part-5-networking/ | komunitas (blog praktisi) | 2017-07-24; diakses 2026-10-22 | Sedang, era Volatility 2. Pool scanning bisa memulihkan koneksi yang sudah berakhir dengan risiko false positive; waktu netscan sebagai waktu bind atau koneksi dibentuk |
| S24 | Pureinfotech: KB5027397 required to change from 22H2 to 23H2 | https://pureinfotech.com/kb5027397-windows-11-change-22h2-23h2/ | sekunder (media teknologi) | 2023-11-03; diakses 2026-10-22 | Sedang. 22H2 dan 23H2 berbagi inti dan file sistem; enablement package mengubah build 22621 ke 22631. Halaman KB Microsoft asli tidak diperoleh |
| S25 | GitHub: volatility3 `symbols/windows/extensions/network.py` | https://raw.githubusercontent.com/volatilityfoundation/volatility3/develop/volatility3/framework/symbols/windows/extensions/network.py | primer (source) | cabang develop; diakses 2026-10-22 | Tinggi. Pemilik dari pointer `Owner` yang divalidasi; waktu pembuatan di luar 1950-2200 dianggap tidak valid |

**Catatan sumber:** nama plugin, opsi, kolom, dan cara kerja diambil dari source Volatility 3 cabang develop dan halaman dokumentasi plugin pada tanggal akses [S1][S5]-[S18][S25]; rilis 2.28.2 bisa berbeda kecil dari cabang develop, jadi nama kolom dan opsi dicek dengan `vol <plugin> -h` di versi lab. Detail bahwa netscan memakai tabel 20348 untuk build Windows 11 adalah tafsiran dari logika fallback di kode [S6], belum diuji di image Windows 11 nyata dalam catatan ini. Arti waktu `Created` netscan untuk koneksi dan sisa koneksi berasal dari praktisi era Volatility 2 [S23] dan belum dikonfirmasi dokumentasi Volatility 3. State persis upaya koneksi yang diblok isolasi EDR (`SYN_SENT` atau `CLOSED`) tidak ditemukan di sumber primer, jadi dibuktikan di lab (variasi tantangan bagian 3). Hubungan induk `WmiPrvSE.exe` untuk proses yang dijalankan `CommandLineEventConsumer` bersandar pada saran deteksi ATT&CK [S21] dan rule Sigma berstatus test [S22], bukan dokumentasi WMI Microsoft; buktikan di lab. Kernel 22621 pada host 23H2 bersandar pada artikel sekunder karena halaman KB Microsoft tidak diperoleh [S24]. Klaim bahwa image di memori berbeda dari file di disk (sehingga hash dan tanda tangan dump tidak mewakili file) adalah penalaran umum tentang pemuatan PE, tidak dari sumber tertentu di tabel ini; uji di lab dengan membandingkan hash. Semua isi PT JAB, termasuk nomor bukti `INC-2026-017-E01` sampai `-E04`, waktu akuisisi, PID, offset, port, hitungan baris, hash `a4e9...` dan `3b7d...`, display name `Windows Help Service`, dan IP `192.0.2.88` untuk layanan Defender, adalah contoh fiktif yang disusun agar konsisten dengan fakta insiden, bukan kejadian nyata.
