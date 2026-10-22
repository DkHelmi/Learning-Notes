---
day: 18
title: 'Simulasi kasus 2: infeksi installer palsu dengan DLL side-loading, dari eksekusi sampai C2 dan persistence'
researched_on: 2026-10-22
versions_checked: 'Windows 11 23H2 (host kasus, build 22631, kernel 22621); Volatility 3 2.28.2 (rilis 17 Sep 2026, masih rilis stabil terbaru per 2026-10-22; subpaket windows.malware.* sejak 2.26.2); EZ Tools 2026.5.0 (PECmd, AmcacheParser, AppCompatCacheParser, RECmd, SrumECmd); Plaso 20260720; Microsoft Defender for Endpoint (live response ms.date 2026-07-28; investigation package dan isolasi ms.date 2026-07-23); Microsoft Dynamic-link library search order (updated 2025-04-15); MITRE ATT&CK v20 (T1574.001 v3.0 modifikasi 2026-09-11, T1189 v1.7, T1053.005 v1.8, T1204.002, T1071.001, T1055); rujukan Day 07, 09, 11, 13, 14, 15, 16'
---

# Day 18: Simulasi kasus 2 (infeksi installer palsu dengan DLL side-loading, dari eksekusi sampai C2 dan persistence)

Cakupan: satu kasus fiktif infeksi lewat installer palsu dengan DLL side-loading, direkonstruksi dari titik masuk sampai C2 dan persistence memakai artefak disk dan memori satu host, lalu diubah menjadi IOC yang tahan lama, timeline, scope, dan paket serah terima untuk hunting di banyak host yang memuat DLL bernama sama secara sah.

## Ide inti

Kasus infeksi dari luar mengajukan dua pertanyaan sekaligus, dan keduanya harus dijawab dari satu host yang dibedah. Pertanyaan pertama adalah "apa yang terjadi di host ini", dijawab dengan menyatukan artefak eksekusi, persistence, memori, dan jaringan menjadi satu narasi yang bisa ditelusuri. Pertanyaan kedua lebih sulit dan sering menentukan nilai pekerjaan forensik: "apa yang bisa diserahkan supaya host lain yang terkena, tetapi belum ketahuan, bisa ditemukan". Yang membuat kasus ini menarik adalah DLL yang disalahgunakan, `version.dll`, adalah DLL sistem yang namanya juga dipakai sah oleh aplikasi internal di ratusan perangkat. Jadi indikator yang paling jelas, yaitu "ada `version.dll` yang dimuat dari folder aplikasi, bukan dari System32", justru cocok dengan ratusan perangkat yang bersih. Pekerjaan forensiknya belum selesai di temuan; ia selesai ketika temuan diubah menjadi indikator yang membedakan yang jahat dari yang sah tanpa membanjiri tim dengan false positive.

Kamu sudah mengenal pola ini dari NOC. Saat satu tool atau firmware diunduh dari hasil pencarian, bukan dari portal vendor resmi, kamu tidak berhenti di satu perangkat yang bermasalah: kamu mencari jejak versi yang sama di seluruh inventaris, dan kamu harus bisa membedakannya dari image resmi yang sah yang kebetulan bernama mirip. Memblokir berdasarkan nama file akan mematikan perangkat yang sehat; yang membedakan adalah tanda tangan, hash, asal, dan perilaku. Di forensik endpoint, bedanya satu: salah satu "firmware" di sini menjalankan beacon ke server luar dan membuka command prompt untuk mengetik perintah pengintaian, dan itu yang harus tertangkap tanpa ikut menangkap 214 perangkat yang hanya menjalankan aplikasi internal.

```
installer palsu (iklan pencarian)  ->  PDFSuite_Setup_4.2.exe (user klik)  [T1189, T1204.002]
  ->  pdfupdater.exe (bertanda tangan vendor) di C:\Users\<user>\AppData\Local\PDFSuite\
        ->  side-load version.dll (tak bertanda tangan) dari folder yang sama        [T1574.001]
              ->  baca update.dat  ->  tahap kedua di region RWX dalam pdfupdater.exe (memori)  [T1055-adjacent]
              ->  beacon ~5 menit ke cdn.pdfsuite-update.example.net / 198.51.100.37:443   [T1071.001]
              ->  persistence: scheduled task \PDFSuite Updater saat logon               [T1053.005]
              ->  Senin: cmd.exe anak pdfupdater.exe  ->  discovery domain (hands-on-keyboard)
disk: Prefetch/Amcache/task XML/MFT   memori: dlllist/malfind/netscan   EDR: process timeline + paket investigasi
  ->  IOC tahan lama (bukan sekadar "version.dll")  +  timeline  +  scope  +  serah terima hunting 214 host
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan dan data pribadi sekitar 400 ribu pelanggan broadband. Kasusnya `INC-2026-026`, infeksi dari kampanye installer palsu aplikasi PDF lewat iklan pencarian. Senin 2026-12-07, Defender for Endpoint mengeluarkan alert di `JKT-WS-0452` (`dian.permata`, Marketing Jakarta), dan hunting lintas perangkat menemukan `BDG-WS-0163` (`10.30.16.63`, `bima.ardiansyah`, staf Sales Bandung) yang sudah terinfeksi sejak Jumat 2026-12-04 tanpa satu pun alert. Insiden dinyatakan SEV-3 lalu naik SEV-2 karena ada aktivitas operator, dan dua laptop diisolasi pada jam H pukul 12:30. Selasa 2026-12-08 pukul 08:30 WIB, setelah jam H, Rudi Hartanto (analyst L2, technical lead `INC-2026-026`) menulis kepadamu (analyst L2 forensik) di kanal `#inc-2026-026`:

> "Pagi. Soal `INC-2026-026`: laptop Bima di Bandung, `BDG-WS-0163`, jalan tiga hari tanpa satu pun alert, dan itu yang bikin saya tidak tenang. Sebelum laptopnya di-reimage, saya mau bedah forensik lengkap dari host-nya sendiri, bukan cuma dari hunting EDR kemarin. Yang saya butuh: bagaimana kode ini masuk dan pertama kali dijalankan, urut dari awal? Apakah ada kode yang disuntikkan ke proses lain atau tahap kedua yang cuma hidup di memori? Bagaimana dia bertahan setelah restart? Ke mana dia bicara, dari proses apa, dan sejak kapan, lalu apa lagi yang dikerjakan operator di host ini, apakah ada tanda dia lompat ke host lain atau ambil kredensial? Lalu yang paling penting buat saya: `version.dll` itu ada sah di 214 perangkat kita yang pakai JAB DocSync, jadi IOC mana yang benar-benar bisa dipakai hunting tanpa membanjiri kita dengan false positive? Terakhir, timeline dan scope-nya, plus paket yang bisa langsung dipakai tim deteksi dan containment. Tolong sebelum 16:00."

Pesan itu memuat tujuh pertanyaan:

1. Bagaimana kode masuk dan pertama kali dijalankan, urut dari awal?
2. Apakah ada kode yang disuntikkan ke proses lain atau tahap kedua yang hanya hidup di memori?
3. Bagaimana kode bertahan setelah restart?
4. Ke mana kode berkomunikasi, dari proses apa, dan sejak kapan?
5. Apa lagi yang dikerjakan operator di host ini (pengintaian, lateral movement, kredensial)?
6. IOC mana yang tahan lama untuk hunting di 214 perangkat yang memuat `version.dll` secara sah?
7. Bagaimana timeline dan scope-nya, dan apa paket serah terima untuk deteksi dan containment?

Pertanyaan 1 dijawab di bagian 2.3, pertanyaan 2 di bagian 1.4 dan 2.5, pertanyaan 3 di bagian 2.4, pertanyaan 4 di bagian 2.6, pertanyaan 5 di bagian 2.7, pertanyaan 6 di bagian 1.3, 1.5, dan 2.8, dan pertanyaan 7 di bagian 2.9 dan 2.10. Bagian 1 membangun cara kerja kasus, templat temuan, dan konsep yang dibutuhkan; bagian 2 berisi perintah, keluaran ilustrasi, temuan per pertanyaan, IOC, timeline, dan paket serah terima yang kamu kirim ke Rudi.

**Kapan relevan:** saat alert atau hunting EDR menemukan host yang perlu dibedah dari sisi forensik, saat infeksi memakai teknik yang memakai komponen sah (side-loading, binary bertanda tangan), dan saat temuan satu host harus diubah menjadi indikator untuk dicari di seluruh fleet.
**Kapan bukan jawaban:** kasus orang dalam yang menekankan akses dan penyalinan data (Day 17) bukan eksekusi dan C2; Day ini juga bukan analisis sampel malware (isi `update.dat` dan payload diserahkan ke tim sampel, tidak dibedah di sini) dan bukan pengganti log jaringan untuk riwayat koneksi dari waktu ke waktu.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (Prefetch, Amcache, Shimcache, BAM, SRUM, PCA, `$MFT`, scheduled task, TaskCache, 4698, 4688, Sysmon, image memori, Volatility, netscan, malfind, ldrmodules, hollowprocesses, beacon, prevalence, known-good comparison, hands-on-keyboard, jejak responder, salinan kerja, paket investigasi, live response, isolasi host) tidak diulang. Tabel berikut hanya memuat istilah baru Day ini; kolom padanan memakai analogi NOC dan SOC yang sama di semua Day.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| DLL side-loading | Aplikasi sah dibuat memuat DLL buatan penyerang karena DLL itu ditaruh di folder yang dicari lebih dulu daripada DLL aslinya | Perangkat sah yang memuat modul konfigurasi palsu dari slot yang salah |
| Installer palsu (malvertising) | Program jahat yang disamarkan sebagai installer aplikasi populer dan disebar lewat iklan hasil pencarian atau situs tiruan | Tool atau firmware palsu yang diunduh dari hasil pencarian, bukan dari portal vendor resmi |
| Tahap kedua (second stage) | Kode yang dimuat atau didekode di memori setelah tahap pertama berjalan, sering tidak pernah ditulis sebagai file executable di disk | Konfigurasi runtime yang dibangun di memori perangkat dan tidak pernah masuk startup-config |
| IOC atomik | Nilai tunggal yang menandai kompromi: hash, IP, domain, nama file | MAC atau IP tunggal yang diblok setelah insiden |
| IOC perilaku | Pola yang menandai kompromi: kombinasi proses, folder, tanda tangan, dan tujuan koneksi | Pola trafik atau urutan event yang menandai gangguan, bukan satu alamat |
| Pyramid of Pain | Model yang mengurutkan jenis indikator menurut seberapa mahal penyerang menggantinya: hash paling murah, TTP paling mahal | Daftar blokir berdasarkan alamat (murah diganti) dibanding deteksi berdasarkan pola perilaku (mahal dihindari) |

### 1.1 Cara kerja kasus: pertanyaan, peta pertanyaan ke artefak, dan hipotesis

Permintaan Rudi adalah kasus, bukan satu query. Cara kerja yang bisa dipertanggungjawabkan selalu dimulai dari pertanyaan yang ditulis lebih dulu, bukan dari alat. Pertanyaan menjaga analisis tetap terarah dan membuat laporan bisa diperiksa: setiap jawaban menunjuk kembali ke pertanyaan yang memicunya.

Setiap pertanyaan dipetakan ke artefak yang bisa menjawabnya, dari tiga sumber yang berbeda sifatnya. Tabel berikut adalah peta itu; baca kolom "Yang khas dari sumbernya", karena tiap sumber menjawab hal yang tidak bisa dijawab sumber lain, dan `BDG-WS-0163` memperlihatkan bedanya dengan jelas.

| Pertanyaan | Disk (E06) | Memori (E05) | EDR (Defender) |
|---|---|---|---|
| Titik masuk dan eksekusi | Prefetch, Amcache, Shimcache, PCA, file di `AppData\Local\PDFSuite`, `$MFT` | `pslist`, `cmdline`, `dlllist` | Process timeline, `DeviceFileEvents` asal unduhan |
| Injeksi atau tahap kedua | (terbatas) | `malfind`, `ldrmodules`, `hollowprocesses` | (terbatas) |
| Persistence | File XML task, TaskCache registry, `$MFT` FN | `registry.scheduled_tasks`, `svcscan` | `scheduledtasks` live response, paket investigasi |
| C2 | (sedikit: SRUM volume) | `netscan` dengan proses pemilik | Paket investigasi `ActiveNetConnections.txt`, `DnsCache.txt` |
| Aktivitas lanjutan | Prefetch, BAM (tool discovery + akun) | `psscan` sisa `cmd.exe` | Process timeline (command line) |
| IOC dan scope | Hash dan path dari Amcache dan `$MFT` | Pemilik koneksi | Prevalence lintas fleet |

Yang khas dari tiap sumber penting di host ini. Disk membuktikan sebuah tool dijalankan dan kapan, tetapi tidak menyimpan argumen command line (Prefetch tidak punya argumen, Day 07). Memori membuktikan proses mana sedang bicara ke IP mana dan memegang tahap kedua, tetapi hanya satu titik waktu. EDR menyimpan process timeline dengan command line karena sensor Defender ada di host ini, tetapi `BDG-WS-0163` tidak menerima GPO audit Jakarta, sehingga di disk tidak ada 4688, tidak ada Sysmon, dan channel TaskScheduler/Operational mati (pola sama dengan laptop Bandung di Day 07). Konsekuensinya: perintah discovery yang persis (`whoami /groups` dan seterusnya) datang dari process timeline EDR, sedangkan disk hanya membuktikan tool-nya berjalan di jam itu di bawah akun Bima. Menyadari pembagian ini mencegah dua kesalahan: menyimpulkan "tidak ada discovery" karena tidak ada 4688, dan menyalin command line EDR seolah berasal dari disk.

Hipotesis ditulis sebelum analisis supaya setiap kemungkinan jinak disingkirkan dengan bukti, bukan dilewati:

- **H1:** infeksi dari installer palsu yang memuat `version.dll` berbahaya lewat side-loading, diikuti C2, persistence, dan pengintaian.
- **H2:** ini aplikasi sah. `version.dll` yang dimuat dari folder aplikasi adalah hal normal; aplikasi internal `jabdocsync.exe` melakukannya di 214 perangkat.
- **H3:** aktivitas berasal dari uji red team atau pengujian software yang dijadwalkan.

H2 disingkirkan dengan membandingkan tanda tangan, hash, dan executable pemuatnya (bagian 1.3 dan 2.8). H3 disingkirkan dengan menanyakan jadwal uji ke pemilik program keamanan dan dengan adanya C2 ke infrastruktur eksternal yang tidak dikenal. Tuliskan bagaimana tiap hipotesis disingkirkan, karena pembaca laporan akan menanyakannya.

### 1.2 Templat temuan: dari bukti ke keyakinan, dengan teknik ATT&CK dan IOC

Setiap pertanyaan dijawab dengan satu temuan yang strukturnya tetap, supaya keyakinan dan keterbatasannya terbaca, bukan tersembunyi di narasi. Templatnya:

```
Temuan <n>: <judul singkat>
Pertanyaan   : <pertanyaan Rudi yang dijawab>
Bukti        : <artefak dan nilai, dengan sumber E04/E05/E06 dan waktu berlabel zona>
Analisis     : <apa arti bukti itu bersama, bukan satu per satu>
Teknik ATT&CK: <ID dan nama teknik yang terlihat, dengan artefak pendukungnya>
IOC          : <nilai, jenis atomik atau perilaku, daya tahan>
Keyakinan    : <tinggi/sedang/rendah, dengan alasan>
Keterbatasan : <apa yang tidak bisa dibuktikan dari bukti ini>
```

Dua baris yang membedakan kasus malware dari kasus orang dalam adalah Teknik ATT&CK dan IOC. Teknik memberi bahasa bersama untuk deteksi (tim deteksi menulis rule per teknik), dan IOC memberi bahan hunting. Keyakinan dan keterbatasan wajib ada supaya IC dan pembaca laporan tahu seberapa jauh temuan boleh dipakai: keyakinan tinggi hanya ketika beberapa sumber yang sifatnya berbeda sepakat pada waktu, akun, proses, dan path yang sama.

### 1.3 Side-loading yang sah dan yang tidak: inti masalah 214 perangkat

Pertanyaan keenam Rudi berakar di cara Windows memuat DLL. Saat sebuah program memanggil DLL hanya dengan nama modul, tanpa path lengkap, Windows mencari di urutan tertentu. Untuk aplikasi desktop tak terpaket dengan safe DLL search mode aktif (bawaan), urutannya dimulai dari redirection dan manifest, lalu daftar modul yang sudah termuat, lalu daftar Known DLLs, baru setelah itu folder tempat aplikasi dimuat, lalu folder System32, dan seterusnya [S2]. Known DLLs adalah daftar di `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`; DLL di daftar itu selalu diambil dari System32, sehingga tidak bisa di-side-load [S2]. `version.dll` tidak ada di daftar Known DLLs standar, sehingga sebuah program yang memuatnya dengan nama saja akan memuat salinan di foldernya sendiri bila ada, karena folder aplikasi dicari sebelum System32 [S2]. Itulah mekanisme side-loading: taruh `version.dll` berbahaya di sebelah program sah, dan program itu memuatnya, bukan DLL asli di System32 [S1].

ATT&CK menempatkan ini di T1574.001 (Hijack Execution Flow: DLL), yang mencakup side-loading dan search-order hijacking; DLL berbahaya sering dikonfigurasi untuk ikut memuat DLL asli yang digantikannya agar program tampak berperilaku normal [S1]. HijackLibs, katalog komunitas untuk DLL hijacking, mencantumkan `version.dll` sebagai DLL Microsoft yang sah ada di `%SYSTEM32%` dan `%SYSWOW64%` dan rentan side-loading, dengan puluhan executable yang bisa menyalahgunakannya [S3]. Katalog itu juga menyarankan memantau aktivitas `version.dll` yang tidak biasa dan menyediakan pola berbasis image load dari folder tak terduga, tanda tangan yang tidak sesuai, dan penulisan ke lokasi yang tidak diharapkan [S3].

Di sinilah masalah 214 perangkat muncul. PT JAB memakai aplikasi internal `JAB DocSync` (`C:\Program Files\JAB\DocSync\jabdocsync.exe`) yang membawa `version.dll` sendiri di folder aplikasinya dan memuatnya dari sana. Secara mekanis, itu sama dengan side-loading: sebuah executable memuat `version.dll` dari folder aplikasi, bukan dari System32. Jadi indikator "proses memuat `version.dll` dari luar System32" cocok dengan 214 perangkat sehat sekaligus dengan `BDG-WS-0163`. Yang membedakan ada di hal lain, dan semuanya harus dibaca bersama:

- **Tanda tangan DLL.** `version.dll` milik JAB DocSync ditandatangani PT Jaringan Anak Bangsa; `version.dll` di `BDG-WS-0163` tidak bertanda tangan sama sekali.
- **Hash DLL.** SHA-1 `version.dll` sah sama di 214 perangkat; yang di `BDG-WS-0163` berbeda dan tidak dikenal.
- **Executable pemuat dan asalnya.** JAB DocSync dipasang tim IT di `C:\Program Files\` lewat distribusi resmi; `pdfupdater.exe` berada di `AppData\Local\PDFSuite`, folder yang bisa ditulis pengguna, dan diunduh dari situs tiruan lewat iklan pencarian.
- **Perilaku sesudahnya.** JAB DocSync menghubungi server internal; `pdfupdater.exe` membangun beacon berkala ke domain eksternal yang baru.

Pelajaran yang dibawa ke bagian IOC: tanda tangan program yang sah (`pdfupdater.exe` bertanda tangan vendor fiktif "Northwind Media Tools Inc.") tidak menjamin DLL yang dimuatnya sah, dan nama DLL saja bukan indikator. Indikator yang berguna menggabungkan beberapa dimensi dan mengecualikan known-good secara eksplisit (bagian 1.5 dan 2.8).

### 1.4 Tahap kedua di memori: region executable di proses native vs JIT .NET

Pertanyaan kedua Rudi membedakan dua hal yang sering dicampur: injeksi ke proses lain dan tahap kedua di dalam proses yang sama. Injeksi menaruh kode di ruang memori proses lain supaya berjalan dengan identitas proses itu (T1055). Tahap kedua di memori adalah kode yang dimuat atau didekode oleh tahap pertama ke dalam proses yang sama, sering tidak pernah ditulis sebagai file executable. Di kasus ini `version.dll` membaca `update.dat` dan menempatkan isinya di region memori yang bisa dieksekusi di dalam `pdfupdater.exe` sendiri, bukan menyuntikkannya ke proses lain.

`windows.malware.malfind` mencari region executable yang mencurigakan: region privat dengan proteksi yang memuat EXECUTE dan WRITE sekaligus (misalnya `PAGE_EXECUTE_READWRITE`), atau region executable yang halamannya pernah ditulis (Day 15 bagian 1.1). Hasil malfind adalah kandidat, bukan bukti, karena ada sumber sah yang membuat region seperti itu. Di Day 15, region RWX di `powershell.exe` dijelaskan oleh JIT .NET: Windows PowerShell 5.1 membawa runtime CLR yang mengompilasi kode ke memori privat yang executable, sehingga region RWX di proses itu normal.

Yang membuat region di `pdfupdater.exe` bermakna adalah konteksnya, dan konteks itu kebalikan dari PowerShell. `pdfupdater.exe` adalah binary native (C/C++) tanpa runtime .NET; `dlllist` tidak menunjukkan `clr.dll` atau `clrjit.dll` dimuat (bagian 2.5). Tanpa JIT, tidak ada alasan sah untuk region privat RWX berisi kode di proses itu. Jadi region RWX di `pdfupdater.exe` adalah kandidat kuat tahap kedua, sedangkan region RWX di `powershell.exe` adalah pola JIT yang wajar. Pembeda ini yang dijelaskan ke pembaca: bukan "ada region RWX, berarti jahat", melainkan "ada region RWX di proses yang tidak punya runtime JIT, dan file `update.dat` di disk adalah sumber terenkode yang cocok". Isi region tidak di-dump sebagai payload di catatan belajar; keberadaan dan proteksinya dicatat, hash dump region diserahkan ke tim sampel, dan analisis isi ditangani terpisah.

`hollowprocesses` membedakan hal ketiga: hollowing mengganti isi proses sah yang dibuat suspended (Day 15 bagian 1.2). Di sini `pdfupdater.exe` adalah binary asli yang benar-benar dijalankan, bukan proses yang di-hollow, sehingga hollowprocesses tidak menandainya. Jawaban untuk Rudi karena itu bertingkat: tidak ada injeksi ke proses lain dan tidak ada hollowing, tetapi ada tahap kedua yang hidup di memori di dalam `pdfupdater.exe` sendiri.

### 1.5 IOC atomik, IOC perilaku, dan Pyramid of Pain untuk hunting banyak host

Pyramid of Pain (David Bianco, 2013) mengurutkan jenis indikator menurut seberapa mahal penyerang menggantinya: hash paling mudah diganti, lalu IP, lalu domain, lalu artefak jaringan dan host (pola URL, nama task, path), lalu tool, dan paling sulit TTP [S10]. Semakin tinggi di piramida, semakin lama indikator berguna dan semakin mahal bagi penyerang untuk menghindarinya.

Untuk hunting di 214 perangkat, piramida ini menjadi praktis. IOC atomik (hash `version.dll` jahat, IP `198.51.100.37`, domain `cdn.pdfsuite-update.example.net`) presisi dan cepat: cari hash itu, cari koneksi ke IP itu, dan host yang cocok hampir pasti terkena. Kelemahannya, penyerang mengganti hash tiap build dan memindah IP dengan murah, dan kampanye yang sama sudah terlihat berganti domain (alert `SOC-2026-0272` Selasa di `JKT-WS-0458` memakai domain baru). IOC perilaku (binary bertanda tangan bukan penerbit korporat di folder yang bisa ditulis user, memuat DLL tak bertanda tangan dari folder yang sama, lalu beacon berkala) lebih lambat dan lebih berisik, tetapi tetap bekerja ketika hash dan domain berganti.

Kunci untuk 214 perangkat adalah menulis IOC perilaku yang mengecualikan known-good secara eksplisit. "Proses memuat `version.dll` dari luar System32" cocok dengan 214 perangkat JAB DocSync. "Proses memuat `version.dll` dari luar System32, dan DLL itu tidak bertanda tangan atau bukan ditandatangani PT Jaringan Anak Bangsa, dan executable pemuatnya bukan `jabdocsync.exe` di `C:\Program Files\JAB\DocSync\`" menyaring known-good dan menyisakan kandidat. Prinsipnya sama dengan known-good comparison di Day 07: daftar yang sah harus eksplisit, dan indikator yang baik membedakan yang jahat dari yang sah, bukan hanya mendaftar yang jahat yang sudah diketahui. Yang diserahkan ke tim deteksi karena itu adalah dua lapis sekaligus: nilai atomik untuk pencarian cepat hari ini, dan aturan perilaku berpengecualian untuk varian berikutnya.

### 1.6 Hands-on-keyboard, scope, dan apa yang host sendiri tidak bisa jawab

Pertanyaan kelima Rudi sering dilompati karena tekanan waktu, padahal jawabannya mengubah skala respons. Beacon otomatis adalah satu hal; operator yang mengetik perintah di command prompt adalah hal lain. Di `BDG-WS-0163`, Senin pagi `pdfupdater.exe` membuka `cmd.exe` lalu menjalankan rangkaian perintah pengintaian domain. Updater aplikasi PDF tidak punya alasan menanyakan anggota Domain Admins; pola ini adalah hands-on-keyboard, operator yang bekerja lewat C2 secara interaktif meski jejaknya tampak sebagai proses turunan `pdfupdater.exe`. Temuan ini yang menaikkan severity ke SEV-2.

Scope satu host selalu punya batas yang harus ditulis. Disk dan memori satu host bisa membuktikan apa yang terjadi di host itu, tetapi tidak bisa membuktikan bahwa kredensial Bima tidak dipakai dari tempat lain, atau bahwa tidak ada host lain yang menerima installer yang sama di luar jendela visibilitas. Pernyataan scope karena itu ditulis sebagai "minimal satu host terkonfirmasi" dengan daftar yang belum bisa dijawab dari host ini, dan menunjuk siapa yang menjawabnya (hunting lintas fleet, log proxy dan DNS untuk perangkat tanpa sensor). Scope insiden hampir selalu bertambah, jarang berkurang; menuliskan batasnya mencegah laporan membaca "tidak ditemukan dari host ini" sebagai "tidak ada".

## 2. Contoh dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi; angka di keluaran dihitung agar konsisten antar tabel dan antar bagian. Perintah disk dijalankan di `JKT-DFIR01` (Windows 11) atas salinan kerja image disk yang di-mount read-only; perintah Volatility dijalankan di `jkt-dfir02` (Ubuntu LTS, Volatility 3 2.28.2 di virtualenv `~/venv/vol3`, dibekukan untuk kasus) atas salinan kerja image memori di disk lokal mesin itu. Narasi memakai WIB (UTC+7). EZ Tools, Plaso, dan Volatility menulis waktu dalam UTC, jadi setiap keluaran diberi label zona waktunya (WIB = UTC ditambah 7 jam). Bukti dari EDR diambil Senin 2026-12-07; dissection forensik kamu kerjakan Selasa 2026-12-08 sesuai permintaan Rudi.

### 2.1 Menyiapkan bukti `BDG-WS-0163` dan menetapkan nomor

Insiden sudah menetapkan tiga bukti dari `JKT-WS-0452` (laptop Dian) saat live response: `INC-2026-026-E01` (`version.dll`), `-E02` (`update.dat`), dan `-E03` (file task `PDFSuite Updater`), semuanya diambil dengan `getfile`, di-hash, dan dicatat di evidence log. Bukti dari `BDG-WS-0163` ditetapkan di Day ini dengan melanjutkan nomor itu. Tabel berikut adalah tiga bukti baru; baca kolom "Catatan", karena cara pengambilan menentukan apa yang bisa dibuktikan darinya.

| Bukti | Isi | Diambil (WIB) | Catatan |
|---|---|---|---|
| `INC-2026-026-E04` | Paket investigasi Defender for Endpoint `BDG-WS-0163` | Yoga, Senin 2026-12-07 11:12 sampai 11:18, dari halaman perangkat | Potret koneksi aktif, cache DNS, Prefetch, scheduled tasks saat itu; bukan salinan penuh host [S7] |
| `INC-2026-026-E05` | Memori `BDG-WS-0163` (RAM 8 GB, raw sekitar 9,9 GiB) | Yoga, Senin 2026-12-07 11:22:10 sampai 11:31:48, lewat live response | Diambil sebelum isolasi 12:30, sehingga koneksi C2 aktif masih bisa tertangkap |
| `INC-2026-026-E06` | Image disk `BDG-WS-0163` | Fajar Nugraha, POP Bandung, Senin 2026-12-07 16:10 sampai 17:40, setelah isolasi | Sumber artefak eksekusi, persistence, dan file system |

Pengambilan memori lewat live response punya batas yang dicatat di case notes. Yoga mengunggah skrip akuisisi WinPmem bertanda tangan ke library live response, menjalankannya dengan `run` agar menulis image terkompresi ke `C:\Windows\Temp` di host, lalu menariknya dengan `getfile <file> &` di latar. `getfile` dibatasi 3 GB per file [S6], sedangkan raw 8 GB RAM sekitar 9,9 GiB jauh melewati batas itu, sehingga skrip mengompres image (hasilnya sekitar 2,6 GB, di bawah batas). Untuk host dengan RAM lebih besar, image terkompresi bisa ikut melewati 3 GB, sehingga akuisisi lokal ke media lepas lebih tepat, seperti yang dilakukan Fajar untuk host Bandung lain. Format terkompresi yang didukung skrip toolkit dan perilaku `getfile` untuk file besar dicek di lab sebelum diandalkan di insiden.

Salinan kerja dibuat setelah verifikasi hash master: `E05-W1` di `jkt-dfir02` (image didekompres ke raw sekitar 9,9 GiB di `/data/work/INC-2026-026/E05-W1/`), dan `E06-W1` di `JKT-DFIR01`, di-mount read-only sebagai `G:`. Semua output parser ke `\\jkt-evid01\cases\INC-2026-026\analysis\`, tidak menyentuh salinan kerja. Verifikasi `windows.info` atas `E05-W1` memberi `Major/Minor 15.22621`: `BDG-WS-0163` adalah Windows 11 Enterprise 23H2 (build 22631), yang kernelnya melapor 22621 karena 22H2 dan 23H2 berbagi inti OS (pola sama dengan Day 16 bagian 2.1).

### 2.2 Pertanyaan dan hipotesis

Sebelum menyentuh artefak, tulis pertanyaan (bagian Ide inti) dan hipotesis (bagian 1.1) di `case-notes.md`. Hipotesis H2 (aplikasi sah) dan H3 (uji red team) dicatat beserta cara menyingkirkannya, karena pembaca after-action report akan menanyakan kenapa ini bukan JAB DocSync yang salah konfigurasi dan bukan pengujian internal. Rencana bacanya: titik masuk dan eksekusi dari disk (2.3), persistence dari disk (2.4), tahap kedua dan injeksi dari memori (2.5), C2 dari memori dan paket investigasi (2.6), aktivitas lanjutan dari disk dan EDR (2.7), lalu IOC (2.8), timeline dan scope (2.9), dan serah terima (2.10).

### 2.3 Titik masuk dan eksekusi awal

Langkah ini menjawab pertanyaan pertama Rudi dari artefak eksekusi di `E06-W1`. Ambil artefak eksekusi dengan KAPE, lalu parse (pola sama dengan Day 07 bagian 2.1).

```
PECmd.exe -d G:\Windows\Prefetch --csv \\jkt-evid01\cases\INC-2026-026\analysis\E06-W1\EZ\Prefetch --csvf E06-W1_pf.csv
AmcacheParser.exe -f G:\Windows\appcompat\Programs\Amcache.hve --csv ...\E06-W1\EZ\Amcache --csvf E06-W1_amcache.csv
```

Keluaran ilustrasi (Prefetch, dipangkas; PECmd menulis waktu dalam UTC, tambah 7 jam untuk WIB):

```
Executable               RunCount  LastRun (UTC)         First/pf Created (UTC)  Files referenced (ringkas)
PDFSUITE_SETUP_4.2.EXE   1         2026-12-04 08:04:50   2026-12-04 08:04:50     ...\Downloads\PDFSuite_Setup_4.2\, ...\AppData\Local\PDFSuite\
PDFUPDATER.EXE           2         2026-12-07 00:58:04   2026-12-04 08:05:10     ...\AppData\Local\PDFSuite\version.dll, ...\AppData\Local\PDFSuite\update.dat
CMD.EXE                  14        2026-12-07 01:10:05   2026-09-18 02:11:30     \Windows\System32\
WHOAMI.EXE               1         2026-12-07 01:10:07   2026-12-07 01:10:07     \Windows\System32\
NLTEST.EXE               1         2026-12-07 01:10:31   2026-12-07 01:10:31     \Windows\System32\
```

Cara membaca hasil:

- `PDFSUITE_SETUP_4.2.EXE` dijalankan sekali Jumat 15:04:50 WIB, dan file yang dirujuknya memuat folder `Downloads\PDFSuite_Setup_4.2\` (hasil ekstraksi zip) dan `AppData\Local\PDFSuite\` (folder tujuan drop). Ini installer yang diklik Bima.
- `PDFUPDATER.EXE` punya run count 2: `.pf`-nya dibuat Jumat 15:05:10 WIB (run pertama, dipicu installer) dan last run Senin 07:58:04 WIB (run kedua, dipicu logon lewat scheduled task). Dua waktu run cocok dengan dua kali `version.dll` dimuat. File yang dirujuk memuat `version.dll` dan `update.dat` dari `AppData\Local\PDFSuite\`, jejak langsung side-loading.
- `WHOAMI.EXE` dan `NLTEST.EXE` dijalankan Senin 08:10 WIB, tool pengintaian yang jarang dipakai pengguna biasa (bagian 2.7).

Amcache menambahkan path dan hash file yang dibawa penyerang. Keluaran ilustrasi (`InventoryApplicationFile`, SHA-1 dihitung atas 30 MiB pertama file, Day 07 bagian 1.3):

```
Name            FullPath                                                  SHA1         Size      LinkDate (UTC)        IsPeSigned
pdfupdater.exe  C:\Users\bima.ardiansyah\AppData\Local\PDFSuite\pdfupdater.exe  d0a71e5c...  1284096   2026-11-19 05:02:11   true (Northwind Media Tools Inc.)
version.dll     C:\Users\bima.ardiansyah\AppData\Local\PDFSuite\version.dll    3f9c2b7e...  148480    2026-11-28 14:33:40   false
```

Cara membaca hasil: `version.dll` tidak bertanda tangan (`IsPeSigned` false) dengan SHA-1 `3f9c2b7e...`, berbeda dari `version.dll` JAB DocSync yang bertanda tangan PT Jaringan Anak Bangsa dengan SHA-1 `8a41d0c3...` (bagian 2.8). `pdfupdater.exe` bertanda tangan vendor fiktif "Northwind Media Tools Inc.", bukan PT JAB. Ukuran `version.dll` 148.480 byte di bawah 30 MiB, jadi SHA-1 Amcache sama dengan SHA-1 file utuh, bisa langsung dicocokkan ke intel.

Shimcache mencatat ketiga file sebagai ada dan dikenal sistem, tetapi kolom eksekusinya dibaca hati-hati: "Yes" indikator kuat, "No" tidak membuktikan apa pun (Day 07 bagian 1.3). PCA (`PcaAppLaunchDic.txt`, Windows 11) memberi satu sudut tambahan: ia mencatat `PDFSuite_Setup_4.2.exe` karena diluncurkan lewat Explorer dari halaman unduhan (peluncuran GUI), tetapi tidak mencatat `pdfupdater.exe`, karena run kedua dipicu scheduled task, dan PCA tidak menangkap eksekusi lewat scheduled task (Day 07 bagian 1.7). PCA yang kosong untuk `pdfupdater.exe` karena itu hasil yang diharapkan, bukan tanda bersih.

`$MFT` menetapkan waktu file. Folder `C:\Users\bima.ardiansyah\AppData\Local\PDFSuite\` dan ketiga file di dalamnya dibuat Jumat 2026-12-04 sekitar 08:05 UTC (15:05 WIB); `pdfupdater.exe` 1.284.096 byte, `version.dll` 148.480 byte, `update.dat` 512.016 byte. SI dan FN keduanya menunjuk Jumat 15:05, tidak ada tanda timestomp; installer menulisnya sebagai file baru, bukan menyalin sambil mempertahankan waktu lama.

**Temuan 1 (titik masuk dan eksekusi).** `PDFSuite_Setup_4.2.exe` diunduh dari situs tiruan lewat iklan pencarian (T1189 Drive-by Compromise) dan diklik Bima (T1204.002 User Execution: Malicious File) Jumat 15:04:50 WIB, lalu menjatuhkan `pdfupdater.exe` bertanda tangan vendor dan `version.dll` tidak bertanda tangan ke `AppData\Local\PDFSuite\`. `pdfupdater.exe` berjalan 15:05:10 WIB dan memuat `version.dll` dari foldernya sendiri (T1574.001 DLL side-loading). Keyakinan tinggi: Prefetch, Amcache, PCA, dan `$MFT` sepakat pada waktu dan path. Keterbatasan: argumen command line tidak ada di disk (Prefetch tanpa argumen); asal unduhan yang persis dibaca dari process timeline EDR dan log proxy. Mendukung H1, melemahkan H2 (DLL tak bertanda tangan, pemuat bukan JAB DocSync).

### 2.4 Persistence: scheduled task `\PDFSuite Updater`

Langkah ini menjawab pertanyaan ketiga Rudi. Di `BDG-WS-0163` tidak ada GPO audit Jakarta, sehingga tidak ada 4698, tidak ada 4688, dan channel TaskScheduler/Operational mati (pola sama dengan laptop Bandung di Day 07). Persistence task karena itu dibaca dari tiga sumber disk yang tidak bergantung audit: file XML, TaskCache registry, dan `$MFT`.

```
type G:\Windows\System32\Tasks\PDFSuite Updater
RECmd.exe --bn DFIRBatch.reb -d G:\Windows\System32\config --csv ...\E06-W1\EZ\Registry --csvf E06-W1_reg.csv
```

Keluaran ilustrasi (file XML task; tanggal `RegistrationInfo` ditulis waktu lokal host, WIB):

```
File XML \PDFSuite Updater (top-level, bukan di bawah \Microsoft\Windows):
  RegistrationInfo Date : 2026-12-04T15:05:12 (lokal, WIB)
  Author                : JAB\bima.ardiansyah
  Action Command        : C:\Users\bima.ardiansyah\AppData\Local\PDFSuite\pdfupdater.exe
  Trigger               : LogonTrigger (user JAB\bima.ardiansyah)
  Principal UserId      : JAB\bima.ardiansyah, LogonType InteractiveToken
```

Keluaran ilustrasi (TaskCache dari RECmd; last write dalam UTC):

```
KeyPath\Value                                              Data                               LastWrite (UTC)
...\Schedule\TaskCache\Tree\PDFSuite Updater (Id, Index, SD ada)  {b7e2c940-...}               2026-12-04 08:05:12
...\Schedule\TaskCache\Tasks\{b7e2c940-...}  Path          \PDFSuite Updater                  2026-12-07 00:58:06
```

Cara membaca hasil:

- Task `\PDFSuite Updater` dibuat di root `\`, bukan di bawah `\Microsoft\Windows\`, dan dijalankan saat logon oleh `pdfupdater.exe` yang sama. Principal-nya `bima.ardiansyah` dengan `InteractiveToken`, bukan SYSTEM: task berjalan di konteks pengguna, tanpa butuh hak admin. Ini cocok dengan `pdfupdater.exe` yang berada di `AppData\Local` (lokasi yang tidak butuh admin untuk ditulis).
- Last write `Tree\PDFSuite Updater` 08:05:12 UTC (15:05:12 WIB) sama dengan `RegistrationInfo` di XML dan dengan FN file task di `$MFT`: tiga sumber sepakat pada waktu pendaftaran. Key `Tree` punya nilai `SD`, jadi task tidak disembunyikan dengan menghapus `SD` (teknik yang didokumentasikan ATT&CK T1053.005 dan Microsoft, Day 09 bagian 1.6) [S5].
- Last write `Tasks\{GUID}` Senin 00:58:06 UTC (07:58:06 WIB) dekat run logon Senin; ini data runtime task yang diperbarui Windows, bukan waktu pembuatan. Pola ini sama dengan Day 09 bagian 2.6 dan tetap perlu dibuktikan di lab sebelum ditulis di laporan.

Paket investigasi E04 menambah pembanding independen: file CSV scheduled tasks di paket itu, diambil Senin 11:12 WIB sebelum isolasi, memuat `\PDFSuite Updater` dengan action yang sama, membuktikan task masih terpasang dan aktif saat itu [S7].

**Temuan 3 (persistence).** Satu mekanisme persistence: scheduled task `\PDFSuite Updater` yang menjalankan `pdfupdater.exe` saat logon (T1053.005 Scheduled Task), dibuat Jumat 15:05:12 WIB di konteks pengguna `bima.ardiansyah`. Keyakinan tinggi: file XML, TaskCache, `$MFT` FN, dan paket investigasi sepakat. Keterbatasan: tanpa 4698 dan tanpa 4688, proses pembuat task tidak bisa ditautkan dari disk; dari process timeline EDR, task dibuat oleh `schtasks.exe` yang dipanggil `pdfupdater.exe` Jumat 15:05:20. Tidak ada Run key, service, Startup folder, atau WMI subscription milik penyerang (diperiksa di registry dan `OBJECTS.DATA`, bagian 2.5); hanya satu jalur persistence di host ini.

### 2.5 Memori: proses, side-loading, dan tahap kedua

Langkah ini menjawab pertanyaan kedua Rudi dari `E05-W1`. Jalankan daftar proses lebih dulu (Day 14), lalu plugin analisis proses (Day 15).

```bash
. ~/venv/vol3/bin/activate
IMG=/data/work/INC-2026-026/E05-W1/INC-2026-026-E05-W1_BDG-WS-0163_mem.raw
OUT=/mnt/cases/INC-2026-026/analysis/E05-W1/vol-2.28.2
vol -q -f "$IMG" windows.pstree > "$OUT/pstree.txt"
vol -q -f "$IMG" windows.dlllist --pid 5216 > "$OUT/dlllist-5216.txt"
vol -q -f "$IMG" windows.malware.malfind --pid 5216 > "$OUT/malfind-5216.txt"
vol -q -f "$IMG" windows.malware.ldrmodules --pid 5216 > "$OUT/ldrmodules-5216.txt"
vol -q -f "$IMG" windows.malware.hollowprocesses > "$OUT/hollowprocesses.txt"
```

Keluaran ilustrasi (`pstree`, ringkas; waktu UTC):

```
PID    PPID   ImageFileName    CreateTime (UTC)       Cmd
...
1344   712    svchost.exe      2026-12-07 00:48:30    svchost.exe -k netsvcs -p -s Schedule
5216   1344   pdfupdater.exe   2026-12-07 00:58:04    "C:\Users\bima.ardiansyah\AppData\Local\PDFSuite\pdfupdater.exe"
3140   712    MsSense.exe      2026-12-07 00:48:40    "C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe"
```

Cara membaca hasil: `pdfupdater.exe` PID 5216 berinduk `svchost.exe` 1344 yang menjalankan layanan Schedule (Task Scheduler), bukan `services.exe` atau `explorer.exe`. Itu konsisten dengan proses yang dijalankan oleh scheduled task saat logon, bukan diklik pengguna. CreateTime Senin 00:58:04 UTC (07:58:04 WIB) cocok dengan run kedua di Prefetch dan dengan waktu logon. Proses ini masih hidup saat memori diambil, artinya persistence bekerja dan payload berjalan tiga hari.

Keluaran ilustrasi (`dlllist` PID 5216, ringkas; `LoadTime` UTC):

```
Base            Name          Path                                                              LoadTime (UTC)
0x7ff7a2c10000  pdfupdater.exe C:\Users\bima.ardiansyah\AppData\Local\PDFSuite\pdfupdater.exe   2026-12-07 00:58:04
0x7ffb1d3e0000  ntdll.dll     C:\Windows\SYSTEM32\ntdll.dll                                     2026-12-07 00:58:04
0x7ff7a0a50000  version.dll   C:\Users\bima.ardiansyah\AppData\Local\PDFSuite\version.dll       2026-12-07 00:58:04
0x7ffb18c20000  wininet.dll   C:\Windows\SYSTEM32\wininet.dll                                   2026-12-07 00:58:05
...    (DLL sistem lain dari C:\Windows\; tidak ada clr.dll, clrjit.dll, mscoree.dll)
```

Cara membaca hasil:

- `version.dll` dimuat dari `C:\Users\bima.ardiansyah\AppData\Local\PDFSuite\version.dll`, bukan dari `C:\Windows\System32\version.dll`. Ini jejak side-loading langsung di memori: salinan di folder aplikasi dimuat karena folder aplikasi dicari sebelum System32 (bagian 1.3) [S2].
- Tidak ada `clr.dll`, `clrjit.dll`, atau `mscoree.dll` di daftar modul. `pdfupdater.exe` adalah proses native tanpa runtime .NET, jadi tidak ada JIT yang membuat region RWX sah (bagian 1.4).
- `wininet.dll` dimuat satu detik setelah proses mulai, konsisten dengan proses yang membangun koneksi HTTP keluar.

Keluaran ilustrasi (`malfind` PID 5216, kolom hexdump dan disasm dipotong):

```
PID    Process         Start VPN       End VPN         Tag   Protection              PrivateMemory  Notes
5216   pdfupdater.exe  0x1d4a0000      0x1d4bffff      VadS  PAGE_EXECUTE_READWRITE  1              N/A
```

Cara membaca hasil: satu region privat RWX (`PrivateMemory` 1, tag `VadS`) di `pdfupdater.exe`. Berbeda dengan region RWX di `powershell.exe` di Day 15 yang dijelaskan JIT CLR, proses ini tidak punya runtime JIT, sehingga region executable privat berisi kode adalah kandidat kuat tahap kedua. `update.dat` (512.016 byte di disk) adalah sumber terenkode yang cocok dibaca `version.dll` ke region ini. Region tidak di-dump sebagai payload di catatan belajar; keberadaan dan proteksinya dicatat, hash dump region (`windows.malware.malfind --pid 5216 --dump`) diserahkan ke tim sampel bersama `update.dat`, dan isinya dianalisis terpisah.

Keluaran ilustrasi (`ldrmodules` PID 5216 untuk `version.dll`, dan `hollowprocesses`):

```
Pid    Process         Base            InLoad  InInit  InMem   MappedPath
5216   pdfupdater.exe  0x7ff7a0a50000  True    True    True    \Users\bima.ardiansyah\AppData\Local\PDFSuite\version.dll

hollowprocesses:
PID    Process  Notes
(tidak ada baris)
```

Cara membaca hasil: `version.dll` ada di ketiga daftar loader dengan `MappedPath` di folder aplikasi, jadi ia dimuat normal lewat loader (tidak dilepas untuk disembunyikan), dan `MappedPath` menegaskan asalnya dari `AppData\Local\PDFSuite`. `hollowprocesses` tidak menandai apa pun: `pdfupdater.exe` adalah binary asli yang benar-benar dijalankan, bukan proses yang di-hollow. Token proses (dari `windows.getsids --pid 5216`) adalah `bima.ardiansyah` dengan integrity Medium, tanpa `SeDebugPrivilege`, dan `windows.handles --pid 5216` tidak menunjukkan handle ke `lsass.exe`: proses ini tidak punya hak dan tidak terlihat mencoba membaca memori LSASS (relevan untuk pertanyaan kredensial, bagian 2.7).

**Temuan 2 (injeksi dan tahap kedua).** Tidak ada injeksi ke proses lain dan tidak ada process hollowing. Ada tahap kedua yang hidup di memori di dalam `pdfupdater.exe` sendiri: region RWX privat di proses native tanpa runtime JIT, dengan `update.dat` sebagai sumber terenkode di disk. `version.dll` tak bertanda tangan dimuat dari folder aplikasi (T1574.001). Keyakinan tinggi untuk side-loading (dlllist, ldrmodules, Amcache sepakat), sedang untuk sifat tahap kedua sampai tim sampel menganalisis region dan `update.dat`. Keterbatasan: isi region tidak dibedah di sini; memori hanya satu titik waktu.

### 2.6 C2 dari memori dan paket investigasi

Langkah ini menjawab pertanyaan keempat Rudi. Memori diambil sebelum isolasi (11:22 WIB, isolasi 12:30), sehingga koneksi C2 aktif masih bisa tertangkap.

```bash
vol -q -r csv -f "$IMG" windows.netscan > "$OUT/netscan.csv"
awk -F, 'NR>1 && $6 !~ /^(10\.|127\.|0\.0\.0\.0|\*|::)/ && $7 != 0' "$OUT/netscan.csv" | sort -t, -k11
```

Keluaran ilustrasi (tujuan eksternal, dipangkas; waktu UTC). Total `netscan.csv` memuat listener dan endpoint standar; yang menuju alamat eksternal non-Microsoft hanya `pdfupdater.exe`:

```
Proto  LocalAddr    LPort  ForeignAddr     FPort  State        PID   Owner           Created (UTC)
TCPv4  10.30.16.63  51802  198.51.100.37   443    ESTABLISHED  5216  pdfupdater.exe  2026-12-07 04:19:38
TCPv4  10.30.16.63  51788  198.51.100.37   443    CLOSED       5216  pdfupdater.exe  2026-12-07 04:14:33
TCPv4  10.30.16.63  51774  198.51.100.37   443    CLOSED       5216  pdfupdater.exe  2026-12-07 04:09:30
TCPv4  10.30.16.63  51760  198.51.100.37   443    CLOSED       5216  pdfupdater.exe  2026-12-07 04:04:28
TCPv4  10.30.16.63  51519  192.0.2.90      443    ESTABLISHED  3140  MsSense.exe     2026-12-07 04:21:02
```

Cara membaca hasil:

- `pdfupdater.exe` PID 5216 adalah pemilik semua koneksi ke `198.51.100.37:443`. Satu `ESTABLISHED` Senin 04:19:38 UTC (11:19:38 WIB) membuktikan koneksi C2 aktif saat snapshot, dan objek `CLOSED` sebelumnya di 04:14:33, 04:09:30, dan 04:04:28 UTC berjarak sekitar lima menit (selisih berurutan 5:05, 5:03, dan 5:02), sesuai beacon tiap lima menit. Karena memori diambil sebelum isolasi, koneksi masih `ESTABLISHED`, bukan `SYN_SENT` seperti pada host yang diambil setelah isolasi (bandingkan Day 16 bagian 2.2).
- `MsSense.exe` PID 3140 ke `192.0.2.90:443` adalah sensor Defender yang menghubungi layanan Microsoft (alamat ditulis dengan rentang dokumentasi), wajar.
- Tidak ada proses lain yang menghubungi IP eksternal, dan tidak ada tujuan eksternal keempat. Tidak ada kanal C2 kedua yang terlihat di memori.

Paket investigasi E04 memberi pembanding independen. `ActiveNetConnections.txt` yang diambil Senin 11:12 WIB (sebelum memori) menunjukkan PID 5216 terhubung ke `198.51.100.37:443`, dan `DnsCache.txt` memuat `cdn.pdfsuite-update.example.net` dengan jawaban `198.51.100.37` [S7]. Jadi domain C2 tertaut ke IP dari sumber yang berbeda dari Volatility.

**Temuan 4 (C2).** `pdfupdater.exe` PID 5216 berkomunikasi ke `cdn.pdfsuite-update.example.net` (`198.51.100.37:443`) lewat HTTPS dengan beacon sekitar lima menit, sejak Jumat 15:06 WIB (bagian 2.9). Pola interval teratur adalah ciri beacon (T1071.001 Application Layer Protocol: Web Protocols). Keyakinan tinggi: netscan, paket investigasi, dan SRUM (bagian 2.7) sepakat, dan satu koneksi `ESTABLISHED` membuktikan C2 aktif saat snapshot. Keterbatasan: isi komunikasi terenkripsi; domain bisa punya IP lain yang belum terlihat.

### 2.7 Aktivitas lanjutan: discovery, lateral movement, dan kredensial

Langkah ini menjawab pertanyaan kelima Rudi. Dari disk, Prefetch dan BAM membuktikan tool discovery berjalan; command line yang persis datang dari process timeline EDR.

```
RECmd.exe --bn DFIRBatch.reb -d G:\Windows\System32\config --csv ...\E06-W1\EZ\Registry --csvf E06-W1_bam.csv
```

Keluaran ilustrasi (BAM, device path dipangkas; waktu UTC, satu value per executable per SID):

```
SID (bima.ardiansyah)  Executable        LastExecution (UTC)
...-1142               pdfupdater.exe    2026-12-07 00:58:04
...-1142               cmd.exe           2026-12-07 01:10:05
...-1142               whoami.exe        2026-12-07 01:10:07
...-1142               nltest.exe        2026-12-07 01:10:31
...-1142               net.exe           2026-12-07 01:11:02
...-1142               ipconfig.exe      2026-12-07 01:12:15
```

Cara membaca hasil: semua tool discovery berjalan Senin 08:10 sampai 08:12 WIB (01:10 sampai 01:12 UTC) di bawah SID akun `bima.ardiansyah`, bukan akun lain, dalam rentang kurang dari tiga menit. BAM membuktikan tool-nya berjalan dan kapan, dan atas nama akun siapa; ia tidak menyimpan argumen (Day 07 bagian 1.4). Prefetch mengonfirmasi waktu yang sama. Argumen persis (`whoami /groups`, `nltest /domain_trusts`, `net group "domain admins" /domain`, `net view`, `ipconfig /all`) berasal dari process timeline EDR, yang mencatat bahwa `cmd.exe` adalah anak `pdfupdater.exe`, sehingga rangkaian ini bukan aktivitas sah Bima melainkan operator yang mengetik lewat C2.

Lateral movement dan kredensial diperiksa dari artefak klien dan logon (Day 11). ShellBags, `MountPoints2`, dan MRU `Terminal Server Client` hanya menunjukkan share tim Sales di `JKT-FS01` yang biasa dipetakan Bima; tidak ada MRU RDP keluar baru, tidak ada `PsExec` atau `wmic` di Prefetch, dan tidak ada 4648 ke host lain. Dari memori, token `pdfupdater.exe` Medium tanpa `SeDebugPrivilege` dan tanpa handle ke `lsass.exe` (bagian 2.5); tidak ada tanda dump kredensial. Credential Guard status di host ini dicek dari `windows.info` dan baseline proses (ada tidaknya `LsaIso.exe`, Day 14 bagian 1.5); apa pun hasilnya, token pengguna biasa memang tidak bisa membaca LSASS.

**Temuan 5 (aktivitas lanjutan).** Operator melakukan pengintaian domain dari host ini Senin 08:10 sampai 08:12 WIB lewat `cmd.exe` anak `pdfupdater.exe` (hands-on-keyboard). Tidak ditemukan jejak pencurian kredensial (token biasa, tanpa akses LSASS) atau lateral movement keluar sebelum isolasi. Keyakinan sedang: tidak adanya bukti di satu host tidak menyingkirkan kemungkinan kredensial Bima dipakai dari tempat lain; logon akun Bima di host lain dicek dari log DC dan EDR, bukan dari disk host ini.

### 2.8 IOC dan daya tahannya

Langkah ini menjawab pertanyaan keenam Rudi. Tabel berikut menyusun IOC dengan jenis dan daya tahannya; baca kolom "Daya tahan dan catatan known-good", karena di situ masalah 214 perangkat diselesaikan.

| IOC | Jenis | Sumber | Daya tahan dan catatan known-good |
|---|---|---|---|
| `3f9c2b7e...` (SHA-1 `version.dll` jahat) | Atomik (hash) | Amcache, E06 | Rendah: berubah tiap build. Berbeda dari `version.dll` sah JAB DocSync (`8a41d0c3...`) |
| `d0a71e5c...` (SHA-1 `pdfupdater.exe`) | Atomik (hash) | Amcache, E06 | Rendah |
| `198.51.100.37` | Atomik (IP) | netscan, E04 | Rendah: mudah dipindah |
| `cdn.pdfsuite-update.example.net` | Atomik (domain) | `DnsCache.txt` E04 | Sedang: kampanye sudah berganti domain (`SOC-2026-0272`) |
| `pdf-suite-download.example.net` | Atomik (domain unduhan) | log proxy | Sedang |
| Scheduled task `\PDFSuite Updater` saat logon | Artefak host | file XML, TaskCache | Sedang: nama bisa diganti |
| Path `AppData\Local\PDFSuite\` | Artefak host | `$MFT`, Amcache | Sedang |
| `version.dll` tak bertanda tangan dimuat proses di `AppData` user, lalu beacon | Perilaku | dlllist, netscan | Tinggi: tetap bekerja saat hash dan domain berganti |
| Binary bertanda tangan bukan PT JAB di folder user yang memuat `version.dll` tak bertanda tangan | Perilaku | Amcache, dlllist | Tinggi: mengecualikan JAB DocSync secara eksplisit |

Baris perilaku di bawah tabel adalah yang menjawab masalah 214 perangkat. Hunting "proses memuat `version.dll` dari luar System32" cocok dengan 214 perangkat JAB DocSync, jadi tidak dipakai sendirian. Yang dipakai adalah kombinasi berpengecualian: DLL tak bertanda tangan atau bukan bertanda tangan PT Jaringan Anak Bangsa, dimuat dari folder yang bisa ditulis user, oleh executable yang bukan `jabdocsync.exe` di `C:\Program Files\JAB\DocSync\`. Indikator atomik tetap diserahkan untuk pencarian cepat hari ini, tetapi yang membuat hunting bertahan saat penyerang mengganti infrastruktur adalah baris perilaku dengan pengecualian known-good (bagian 1.5) [S10].

### 2.9 Timeline dan scope

Garis waktu kurasi menyatukan artefak lintas sumber; tiap baris menunjuk buktinya. Semua WIB (UTC+7).

```
WIB (UTC)              Kejadian                                                          Sumber
Jum 15:02:31 (08:02:31) Unduh PDFSuite_Setup_4.2.zip dari pdf-suite-download.example.net  log proxy, DeviceFileEvents
Jum 15:04:50 (08:04:50) PDFSuite_Setup_4.2.exe dijalankan (user klik)                     Prefetch, PCA
Jum 15:05:10 (08:05:10) pdfupdater.exe berjalan, memuat version.dll dari AppData          Prefetch, Amcache, dlllist
Jum 15:05:12 (08:05:12) Scheduled task \PDFSuite Updater didaftarkan (saat logon)         XML, TaskCache, $MFT FN
Jum 15:06:02 (08:06:02) Beacon pertama ke 198.51.100.37:443                               netscan, SRUM, log firewall
Jum 15:06-17:26        29 koneksi C2 (laptop menyala)                                     netscan, log firewall
Sen 07:58:04 (00:58:04) Logon Bima; task menjalankan pdfupdater.exe lagi (version.dll)    Prefetch, pstree, dlllist
Sen 07:59:40 (00:59:40) Beacon Senin dimulai                                              netscan, log firewall
Sen 08:10:05 (01:10:05) pdfupdater.exe membuka cmd.exe                                    BAM, EDR timeline
Sen 08:10-08:12        Discovery domain (whoami, nltest, net group, net view, ipconfig)   Prefetch, BAM, EDR timeline
Sen 07:59-11:34        44 koneksi C2                                                      netscan, log firewall
Sen 11:12-11:18        Paket investigasi E04 diambil                                      case notes
Sen 11:22-11:32        Memori E05 diambil (ESTABLISHED ke C2 masih terlihat)              netscan
Sen 12:30              Host diisolasi lewat EDR                                           Action center
Sen 16:10-17:40        Image disk E06 diambil                                            CoC
```

Jumlah koneksi 29 (Jumat) ditambah 44 (Senin) adalah 73, sesuai hunting. Scope awal: satu host terkonfirmasi (`BDG-WS-0163`), satu host pembanding dari alert (`JKT-WS-0452`), dan satu host yang hanya mengunduh tanpa menjalankan (`JKT-WS-0455`). Yang belum bisa dijawab dari `BDG-WS-0163`: apakah kredensial Bima dipakai di host lain, apakah ada host lain yang menerima installer dari domain kampanye yang baru, dan isi tahap kedua serta `update.dat`. Ketiganya dijawab di luar host ini (hunting lintas fleet, log DC, tim sampel), sehingga scope ditulis "minimal tiga host tersentuh, satu dengan aktivitas operator" sampai pencarian lintas lingkungan selesai.

### 2.10 Paket serah terima dan rubrik penilaian diri

Serah terima yang baik bisa dikerjakan penerimanya tanpa membaca seluruh laporan. Jawaban tertulis dikirim ke Rudi Selasa 2026-12-08 pukul 15:30 WIB, disimpan `\\jkt-evid01\cases\INC-2026-026\notes\forensik-BDG-WS-0163-2026-12-08.md`.

Untuk tim hunting:

```
Hipotesis: host lain menjalankan version.dll jahat lewat installer palsu, atau
berkomunikasi dengan infrastruktur kampanye, sejak 2026-12-01.
Cari (kecualikan known-good JAB DocSync di C:\Program Files\JAB\DocSync\, signer PT JAB):
1. version.dll dimuat dari luar System32 yang tak bertanda tangan atau signer bukan PT JAB,
   oleh executable selain jabdocsync.exe.
2. Koneksi ke 198.51.100.37 atau DNS ke cdn.pdfsuite-update.example.net dan domain kampanye baru.
3. Hash version.dll 3f9c2b7e... atau pdfupdater.exe d0a71e5c...
4. Scheduled task \PDFSuite Updater; folder AppData\Local\PDFSuite\.
Rentang: 2026-12-01 00:00 WIB sampai sekarang; untuk host tanpa sensor, log proxy dan dns.
Hasil yang diharapkan: daftar host, waktu pertama, dan bukti per host.
```

Untuk tim deteksi:

```
Usulan 1 (perilaku, tahan ganti IOC): proses memuat DLL bernama version.dll (atau DLL
sistem lain) dari folder yang bisa ditulis user, DLL tak bertanda tangan atau signer
bukan PT Jaringan Anak Bangsa, lalu koneksi keluar berkala. Kecualikan jabdocsync.exe
di C:\Program Files\JAB\DocSync\. Sumber: DeviceImageLoadEvents + DeviceNetworkEvents.
False positive: aplikasi internal lain yang side-load DLL bernama sama; minta daftar ke tim aplikasi.

Usulan 2 (atomik): unduhan file bernama PDFSuite_Setup* dari domain mana pun; blok hash dan domain.

Usulan 3: scheduled task dengan action di AppData\Local\ saat logon di konteks user.
```

Untuk containment: blokir domain dan IP di proxy dan DNS, blok hash `version.dll` dan `pdfupdater.exe`, hapus installer dari host yang hanya mengunduh, reset kredensial Bima, dan reimage `BDG-WS-0163` setelah bukti diamankan.

Rubrik penilaian diri untuk kasus seperti ini; baca kolom "Kuat", karena di situ beda analyst yang matang:

| Aspek | Belum memadai | Memadai | Kuat |
|---|---|---|---|
| Titik masuk | Hanya "dari installer" | Prefetch dan Amcache | Plus PCA, `$MFT`, dan H2/H3 disingkirkan |
| Tahap kedua | "Ada region RWX, jahat" | Region di proses non-JIT | Plus alasan kenapa bukan JIT dan sumber `update.dat` |
| C2 | IP saja | IP, domain, proses pemilik | Plus interval beacon dan `ESTABLISHED` saat snapshot |
| Persistence | "Ada task" | Task dari XML dan TaskCache | Plus mengapa tanpa 4698, dan mekanisme yang diperiksa tidak ditemukan |
| IOC | Daftar nilai | Dengan jenis dan sumber | Dengan baris perilaku berpengecualian known-good 214 host |
| Scope | "Satu host" | "Minimal tiga host tersentuh" | Menyebut yang belum diketahui dan siapa yang mencarinya |

## 3. Lab praktik (di VM lab terisolasi)

Lab ini mereproduksi pola kasus dengan side-loading jinak, tanpa sampel liar dan tanpa menulis kode payload. Folder kasus `CASE-2026-LAB-018`, di `LAB-WS01` (`172.16.50.10`, Windows 11 23H2 dengan Sysmon dan snapshot bersih) dan `LAB-DFIR01` (`172.16.50.20`, EZ Tools, Volatility 3), jaringan host-only `172.16.50.0/24`. Server web lab di `LAB-DFIR01` menyajikan HTTP untuk "beacon". Semua langkah dari snapshot, dan jangan memakai data atau nama dari pekerjaan nyata.

1. **Siapkan side-loading jinak tanpa menulis kode.** Pakai contoh resmi yang aman: test Atomic Red Team T1574.001 yang mem-side-load DLL lewat binary sah, misalnya test GUP.exe Notepad++ (GUID `65526037-7079-44a9-bda1-2cb624838040`) yang menjalankan biner sah sehingga ia memuat DLL dari folder yang sama [S9]. Baca isi test sebelum menjalankan, dan jalankan dari snapshot. Alternatif tanpa kode: salin aplikasi portable sah yang diketahui memuat DLL dari foldernya ke `C:\Users\<user>\AppData\Local\LabApp\` dan amati pemuatan DLL-nya dengan Sysmon Event ID 7 (image load).
2. **Pasang persistence dan beacon jinak.** Buat scheduled task saat logon yang menjalankan aplikasi lab itu, dan satu task yang memanggil PowerShell untuk `http://beacon.lab.test/ping` setiap lima menit. Catat waktu tiap pembuatan. Biarkan berjalan minimal satu jam, lalu logoff dan login ulang untuk memicu task.
3. **Kumpulkan.** Akuisisi memori lebih dulu (dari snapshot VM, bebas smear), lalu image disk. Catat urutan dan waktunya, seperti E05 lalu E06 di kasus.
4. **Pertanyaan dan hipotesis.** Tulis tujuh pertanyaan (bagian Ide inti) dan tiga hipotesis (bagian 1.1) sebelum analisis, termasuk cara menyingkirkan "aplikasi sah".
5. **Analisis per pertanyaan.** Kerjakan bagian 2.3 sampai 2.7 dengan artefak lab: Prefetch, Amcache, PCA, task XML, TaskCache, lalu `pstree`, `dlllist`, `malfind`, `ldrmodules`, `netscan`.
6. **Bedakan JIT dari tahap kedua.** Jalankan juga satu `powershell.exe` di VM, ambil memori, dan bandingkan region malfind di `powershell.exe` (JIT CLR) dengan region di proses native. Tulis kalimat yang membedakan keduanya untuk laporan (bagian 1.4).
7. **IOC known-good.** Buat "aplikasi internal" kedua yang memuat DLL bernama sama dari `C:\Program Files\`, lalu tulis aturan hunting yang menangkap aplikasi lab jinak tetapi mengecualikan "aplikasi internal" itu. Uji aturannya menangkap satu dan melewatkan yang lain.
8. **Serah terima.** Tulis timeline, pernyataan scope, dua paket serah terima (bagian 2.10), dan tabel IOC dengan baris perilaku.

**Variasi tantangan:**

- Matikan Sysmon sebelum menjalankan skenario dan ulangi analisis hanya dengan Prefetch, Amcache, registry, dan memori. Tulis pertanyaan mana yang tidak lagi bisa dijawab dari disk, meniru `BDG-WS-0163` tanpa GPO audit.
- Buat satu proses yang di-hollow jinak (tool lab yang mengganti isi proses suspended) sebagai pembanding, lalu tunjukkan bahwa `hollowprocesses` menandainya sedangkan side-loading tidak. Ini melatih pembedaan hollowing (Day 15) dari side-loading.
- Reboot VM sebelum akuisisi memori dan amati apa yang hilang dari memori tetapi masih terlihat lewat persistence di disk.

**Hasil yang sebaiknya tersimpan:**

- Catatan skenario beserta GUID test Atomic dan waktunya, serta urutan akuisisi memori lalu disk.
- Pertanyaan dan hipotesis, beserta cara tiap hipotesis disingkirkan.
- Temuan per pertanyaan dengan teknik ATT&CK dan IOC.
- Perbandingan region malfind proses native dengan `powershell.exe` (JIT).
- Aturan hunting yang mengecualikan known-good, beserta bukti ia menangkap satu dan melewatkan yang lain.
- Timeline, pernyataan scope, dan dua paket serah terima.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat membedah kasus seperti ini. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Titik masuk tidak jelas | Installer sudah dihapus | Cari Prefetch, Amcache, PCA, dan folder drop di `$MFT`; nyatakan titik masuk disimpulkan |
| `malfind` penuh region RWX | Proses JIT (.NET, browser) | Fokus pada proses non-JIT; cek `dlllist` untuk `clr.dll`/`clrjit.dll` sebelum menyebut injeksi (Day 15) |
| C2 tidak ada di `netscan` | Memori diambil setelah isolasi atau koneksi sudah tutup | Cek paket investigasi `ActiveNetConnections.txt` dan `DnsCache.txt`; struktur `CLOSED` kadang masih tersisa |
| Tidak ada 4698/4688 untuk task | Host tanpa GPO audit Jakarta | Pakai file XML di `Tasks\`, TaskCache, dan `$MFT` FN; argumen dari process timeline EDR |
| Hunting `version.dll` membanjiri hasil | Cocok dengan 214 perangkat JAB DocSync | Tambahkan pengecualian known-good: signer PT JAB, path `Program Files\JAB\DocSync\`, hash sah |
| Hash biner Windows masuk daftar IOC | Hash `version.dll` System32 atau proses sah | Hapus; hanya hash file penyerang yang jadi IOC |
| `getfile` memori gagal | Image melebihi batas `getfile` 3 GB | Kompres image atau akuisisi lokal ke media lepas; cek format terkompusi di lab [S6] |

## 5. Kesalahan umum dan jebakan

- **Menghentikan analisis di host yang alert.** Di `INC-2026-026`, host terpenting justru yang tidak alert sama sekali.
- **Menyamakan "memuat `version.dll` dari luar System32" dengan "jahat".** Itu cocok dengan 214 perangkat sah; yang membedakan adalah tanda tangan, hash, pemuat, dan perilaku.
- **Membaca region RWX sebagai injeksi tanpa melihat runtime proses.** Region RWX di proses .NET adalah JIT; di proses native tanpa JIT, ia bermakna (bagian 1.4).
- **Menyimpulkan "tidak ada discovery" karena tidak ada 4688.** Host ini tanpa audit lengkap; Prefetch dan BAM tetap membuktikan tool berjalan dan kapan.
- **Menyalin command line EDR seolah berasal dari disk.** Sebut sumbernya; disk membuktikan eksekusi dan waktu, bukan argumen.
- **Menyerahkan hanya IOC atomik.** Hash dan IP berganti; sertakan baris perilaku berpengecualian known-good.
- **Menyimpulkan scope dari satu host.** Tulis "minimal ... host" dan sebut yang belum diketahui serta siapa yang mencarinya.
- **Membedakan side-loading dari hollowing secara keliru.** `pdfupdater.exe` adalah binary asli yang benar dijalankan; `hollowprocesses` tidak menandainya, dan itu bukan tanda bersih melainkan tanda bukan hollowing.

## 6. Catatan terkini

Bagian ini menampung detail versi dan perilaku produk yang bisa berubah; tidak mengubah alur analisis di atas.

- **Volatility 3 2.28.2** (rilis 17 September 2026) masih rilis stabil terbaru per 2026-10-22, dibekukan untuk kasus; plugin injeksi dan hollowing berada di subpaket `windows.malware.*` sejak 2.26.2, nama lama berjalan sebagai alias usang [S8].
- **MITRE ATT&CK v20**: DLL side-loading dibahas di dalam T1574.001 (versi 3.0, dimodifikasi 11 September 2026) [S1]; materi lama memakai nomor T1574.002 untuk DLL Side-Loading. Drive-by Compromise T1189 (versi 1.7) mencakup malvertising lewat penyedia iklan sah dan pembaruan software palsu [S4]. Scheduled Task T1053.005 (versi 1.8) menyebut penyembunyian task dengan menghapus nilai `SD` [S5].
- **Dynamic-link library search order** (Microsoft, updated 2025-04-15): untuk aplikasi tak terpaket dengan safe DLL search mode aktif, folder aplikasi dicari sebelum System32, dan Known DLLs selalu diambil dari System32 [S2].
- **Defender for Endpoint**: batas `getfile` 3 GB dan `putfile` 300 MB, timeout perintah 10 menit kecuali `getfile`, `findfile`, dan `run` yang 30 menit, satu perangkat satu sesi (live response, ms.date 2026-07-28) [S6]; isi paket investigasi dan isolasi yang mempertahankan koneksi ke layanan Defender (respond-machine-alerts, ms.date 2026-07-23) [S7].
- **HijackLibs** mencantumkan `version.dll` sebagai DLL yang rentan side-loading dengan puluhan executable; Sigma rule-nya ditandai eksperimental dan lebih cocok untuk hunting daripada deteksi otomatis [S3].

## 7. Cheat sheet

```
ALUR     installer palsu (T1189/T1204.002) -> pdfupdater.exe di AppData -> side-load version.dll (T1574.001)
         -> tahap kedua di region RWX (proses native, BUKAN JIT) -> beacon ~5 mnt (T1071.001)
         -> persistence scheduled task \PDFSuite Updater saat logon (T1053.005) -> discovery domain (hands-on-keyboard)
SUMBER   disk (Prefetch/Amcache/PCA/task XML/MFT): eksekusi + waktu, TANPA argumen
         memori (dlllist/malfind/ldrmodules/netscan): DLL asal + tahap kedua + proses pemilik koneksi
         EDR (process timeline + paket investigasi): command line + koneksi aktif + DNS
         host tanpa GPO audit -> tidak ada 4688/4698/Sysmon; task dibuktikan dari XML + TaskCache + MFT
RWX      proses JIT (.NET/powershell) = wajar ; proses native tanpa clr.dll = kandidat tahap kedua
IOC      atomik: hash version.dll/pdfupdater, IP 198.51.100.37, domain cdn.pdfsuite-update (rapuh)
         PERILAKU (tahan): version.dll tak bertanda tangan / signer bukan PT JAB, dimuat dari AppData,
                           pemuat bukan jabdocsync.exe di Program Files\JAB\DocSync, lalu beacon
         JANGAN jadikan "version.dll di luar System32" IOC: cocok 214 host sah
SCOPE    "minimal 3 host tersentuh, 1 dengan operator" ; sebut yang belum diketahui
SERAH    hunting: hipotesis + apa dicari + kecualikan known-good + rentang + hasil diharapkan
         deteksi: logika perilaku + sumber data + FP + pengecualian JAB DocSync
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "`version.dll` di `BDG-WS-0163` dimuat dari folder aplikasi, bukan dari System32, jadi itu pasti malware." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Aplikasi internal `jabdocsync.exe` di 214 perangkat juga memuat `version.dll` dari folder aplikasinya di `C:\Program Files\JAB\DocSync\`, bukan dari System32, karena folder aplikasi dicari sebelum System32. "Memuat `version.dll` dari luar System32" karena itu cocok dengan ratusan perangkat sah. Yang membedakan adalah tanda tangan (tak bertanda tangan vs bertanda tangan PT JAB), hash, executable pemuat, dan perilaku sesudahnya. Lihat bagian 1.3 dan 2.8.

</details>

**2. Skenario keputusan.** Tim deteksi minta satu indikator untuk hunting di 214 perangkat. Mana yang paling tepat?

- A. Blokir semua `version.dll` yang dimuat dari luar System32.
- B. Cari `version.dll` yang tak bertanda tangan atau signer bukan PT Jaringan Anak Bangsa, dimuat dari folder yang bisa ditulis user, oleh executable selain `jabdocsync.exe` di `C:\Program Files\JAB\DocSync\`.
- C. Blokir nama file `version.dll` di seluruh fleet.

<details><summary>Jawaban</summary>

B. Indikator yang berguna menggabungkan beberapa dimensi dan mengecualikan known-good secara eksplisit, sehingga 214 perangkat JAB DocSync tidak ikut terjaring. A keliru karena cocok dengan semua 214 perangkat sah dan akan membanjiri tim dengan false positive. C keliru karena `version.dll` adalah DLL sistem yang sah ada di mana-mana; memblokir namanya mematikan perangkat yang sehat. Lihat bagian 1.5 dan 2.8.

</details>

**3. Pertanyaan jebakan.** "`pdfupdater.exe` punya region `PAGE_EXECUTE_READWRITE`, sama seperti `powershell.exe` di Day 15 yang ternyata JIT, jadi region itu juga wajar." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Region RWX di `powershell.exe` dijelaskan oleh JIT .NET karena PowerShell membawa runtime CLR. `pdfupdater.exe` adalah binary native; `dlllist` tidak menunjukkan `clr.dll`, `clrjit.dll`, atau `mscoree.dll`, jadi tidak ada runtime JIT yang membuat region RWX sah. Di proses tanpa JIT, region executable privat berisi kode adalah kandidat kuat tahap kedua, apalagi dengan `update.dat` di disk sebagai sumber terenkode. Lihat bagian 1.4 dan 2.5.

</details>

**4. Jelaskan ulang.** Jelaskan kepada Gilang Ramadhan (analyst L1), dalam tiga kalimat, kenapa di `BDG-WS-0163` tidak ada event 4698 atau 4688 untuk scheduled task, tetapi kita tetap bisa membuktikan task itu dipasang.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "`BDG-WS-0163` tidak menerima GPO audit Jakarta, jadi Security log tidak mencatat 4698 atau 4688 dan channel TaskScheduler/Operational mati. Tetapi task tetap meninggalkan file XML di `C:\Windows\System32\Tasks\PDFSuite Updater`, dua key di TaskCache registry, dan entri di `$MFT`, dan ketiganya sepakat pada waktu pendaftaran Jumat 15:05. Paket investigasi Defender yang diambil sebelum isolasi juga memuat task itu, jadi kita punya empat sumber tanpa bergantung pada audit event."

Kesalahan yang sering muncul:
- Menyimpulkan "tidak ada task" karena tidak ada 4698.
- Lupa bahwa file XML dan TaskCache tidak bergantung pada audit policy.
- Tidak menyebut bahwa waktu pendaftaran dikuatkan oleh FN file di `$MFT`.

</details>

**5. Skenario keputusan.** `netscan` atas memori `BDG-WS-0163` menunjukkan satu koneksi `ESTABLISHED` dari `pdfupdater.exe` ke `198.51.100.37:443`. Apa yang paling tepat disimpulkan?

- A. Koneksi C2 aktif saat memori diambil, dan memori diambil sebelum isolasi.
- B. Host belum diisolasi dengan benar, karena seharusnya tidak ada koneksi apa pun.
- C. Koneksi itu sisa lama yang tidak bermakna.

<details><summary>Jawaban</summary>

A. Memori `BDG-WS-0163` diambil Senin 11:22 WIB, sebelum isolasi 12:30, sehingga koneksi C2 yang masih aktif wajar tertangkap sebagai `ESTABLISHED` dengan proses pemiliknya. B keliru karena isolasi belum terjadi saat akuisisi; justru itu alasan koneksi aktif masih terlihat. C keliru karena `ESTABLISHED` adalah koneksi aktif saat snapshot, bukan sisa, dan objek `CLOSED` sebelumnya memberi interval beacon lima menit. Lihat bagian 2.1 dan 2.6.

</details>

**6. Pertanyaan jebakan.** "Tidak ada 4688 di disk, jadi tidak ada perintah discovery yang dijalankan di host ini." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Host ini tanpa audit Process Creation, jadi memang tidak ada 4688, tetapi Prefetch dan BAM membuktikan `whoami.exe`, `nltest.exe`, dan `net.exe` berjalan Senin 08:10 sampai 08:12 di bawah akun Bima. Argumen persisnya (`net group "domain admins" /domain` dan lainnya) datang dari process timeline EDR, yang mencatat `cmd.exe` sebagai anak `pdfupdater.exe`. Ketiadaan 4688 hanya berarti satu sumber buta, bukan bahwa discovery tidak terjadi. Lihat bagian 1.1 dan 2.7.

</details>

**7. Interview question (English).** "You're handed a host that ran malware for three days without ever alerting, and the abused DLL is a legitimate Windows DLL that your own internal app ships on hundreds of machines. How do you investigate it and produce useful indicators?"

<details><summary>Sample answer</summary>

"I write the questions first, then map each to disk, memory, and EDR, because each proves something the others can't. From disk I get Prefetch, Amcache, PCA, the scheduled task XML, and MFT to establish how the fake installer dropped a signed updater and an unsigned version.dll into the user's AppData and when it ran. From memory I confirm the updater loaded version.dll from its own folder, that it holds an RWX region even though it's a native process with no .NET runtime, which points to an in-memory second stage rather than benign JIT, and that it owns the established C2 connection. This host had no audit GPO, so there's no 4688 or 4698; I prove the scheduled task and the discovery commands from the task XML, TaskCache, Prefetch, and BAM, and take the exact command lines from the EDR process timeline. The hard part is the indicators: because version.dll is legitimately everywhere, I don't hunt on 'version.dll outside System32', I hunt on a behavioral rule that excludes the known-good signer and path, and I hand over both atomic values for today and the behavioral rule for the next variant. I state scope as at least the confirmed hosts plus what only fleet-wide hunting and DC logs can answer."

What makes this answer strong: it separates what disk, memory, and EDR each prove, distinguishes an in-memory second stage from benign JIT, handles a host without full auditing, and solves the real problem of producing indicators that exclude a legitimately ubiquitous DLL.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | MITRE ATT&CK: Hijack Execution Flow: DLL (T1574.001) | https://attack.mitre.org/techniques/T1574/001/ | primer | ATT&CK v20, versi 3.0, dimodifikasi 2026-09-11; diakses 2026-10-22 | Tinggi. Side-loading dan search-order hijacking; DLL jahat bisa ikut memuat DLL asli agar tampak normal |
| S2 | Microsoft Learn: Dynamic-link library search order | https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order | primer | updated 2025-04-15 (ms.date 2023-02-08); diakses 2026-10-22 | Tinggi. Urutan pencarian aplikasi tak terpaket, folder aplikasi sebelum System32, Known DLLs selalu dari System32, safe DLL search mode |
| S3 | HijackLibs: version.dll (Microsoft) | https://hijacklibs.net/entries/microsoft/built-in/version.html | komunitas | diakses 2026-10-22 | Sedang. `version.dll` rentan side-loading, lokasi `%SYSTEM32%`/`%SYSWOW64%`, puluhan executable; Sigma rule eksperimental untuk hunting |
| S4 | MITRE ATT&CK: Drive-by Compromise (T1189) | https://attack.mitre.org/techniques/T1189/ | primer | ATT&CK v20, versi 1.7, dimodifikasi 2025-10-24; diakses 2026-10-22 | Tinggi. Malvertising lewat penyedia iklan sah, pembaruan software palsu |
| S5 | MITRE ATT&CK: Scheduled Task (T1053.005) | https://attack.mitre.org/techniques/T1053/005/ | primer | ATT&CK v20, versi 1.8, dimodifikasi 2026-05-12; diakses 2026-10-22 | Tinggi. Scheduled task sebagai persistence; penyembunyian task dengan menghapus nilai `SD` |
| S6 | Microsoft Learn: Investigate entities on devices using live response | https://learn.microsoft.com/en-us/defender-endpoint/live-response | primer | ms.date 2026-07-28; diakses 2026-10-22 | Tinggi. Perintah, batas `getfile` 3 GB dan `putfile` 300 MB, library 250 MB, timeout, satu perangkat satu sesi, skrip library |
| S7 | Microsoft Learn: Take response actions on a device | https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts | primer | ms.date 2026-07-23; diakses 2026-10-22 | Tinggi. Isi paket investigasi (Network connections `ActiveNetConnections.txt`, `DnsCache.txt`, Prefetch, Scheduled tasks), isolasi mempertahankan koneksi ke layanan Defender |
| S8 | GitHub: volatilityfoundation/volatility3 Releases | https://github.com/volatilityfoundation/volatility3/releases | primer | 2.28.2 rilis 17 Sep 2026; diakses 2026-10-22 | Tinggi. 2.28.2 terbaru; plugin malware di subpaket `windows.malware` sejak 2.26.2, nama lama usang |
| S9 | GitHub: redcanaryco/atomic-red-team T1574.001 | https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.001/T1574.001.md | primer (repo) | diakses 2026-10-22 | Tinggi. Test side-loading jinak dipetakan ke ATT&CK; test GUP.exe Notepad++ GUID `65526037-7079-44a9-bda1-2cb624838040` |
| S10 | David Bianco: The Pyramid of Pain | https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html | sekunder | 2013; diakses 2026-10-22 | Tinggi sebagai sumber asli konsep; daya tahan indikator dari hash sampai TTP |
| S11 | MITRE ATT&CK: Application Layer Protocol: Web Protocols (T1071.001) | https://attack.mitre.org/techniques/T1071/001/ | primer | ATT&CK v20; dirujuk 2026-10-22 | Tinggi untuk ID dan deskripsi teknik; C2 lewat HTTPS |
| S12 | MITRE ATT&CK: User Execution: Malicious File (T1204.002) | https://attack.mitre.org/techniques/T1204/002/ | primer | ATT&CK v20; dirujuk 2026-10-22 | Tinggi untuk ID; pengguna menjalankan file yang diunduh |

**Catatan sumber:** mekanisme urutan pencarian DLL dan safe DLL search mode berasal dari halaman Microsoft [S2], dan side-loading sebagai teknik dari ATT&CK [S1] dan katalog komunitas HijackLibs [S3]; Sigma rule HijackLibs ditandai eksperimental, jadi dipakai sebagai bahan hunting, bukan deteksi otomatis. Batas live response dan isi paket investigasi dari dokumentasi Defender [S6][S7]. Pemetaan pertanyaan ke artefak, templat temuan, dan pembagian IOC atomik dengan perilaku adalah susunan catatan ini dari sumber yang disebut, bukan daftar resmi. Semua isi PT JAB, termasuk nama perangkat, akun, hash (`3f9c2b7e...`, `d0a71e5c...`, `8a41d0c3...`), alamat IP dan domain (rentang dan domain dokumentasi), PID, offset, waktu, dan angka di keluaran ilustrasi, adalah contoh fiktif yang disusun agar konsisten dengan fakta insiden, bukan kejadian nyata. Nomor bukti `INC-2026-026-E04` sampai `-E06`, cara pengambilan memori lewat live response, dan path `C:\Program Files\JAB\DocSync\` untuk `jabdocsync.exe` ditetapkan di Day ini; behavior `getfile` untuk file besar, format terkompresi skrip akuisisi, last write `Tasks\{GUID}`, dan status Credential Guard host dicek di lab.
