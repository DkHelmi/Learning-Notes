---
day: 15
title: 'Analisis proses di memori: malfind, psxview, hollowprocesses, DLL, handle, akses LSASS, dump proses dan file, dan korelasi dengan disk'
researched_on: 2026-10-22
versions_checked: 'Volatility 3 2.28.2 (rilis 17 September 2026, masih terbaru per 2026-10-22; plugin malfind, hollowprocesses, psxview, ldrmodules, pebmasquerade di subpaket windows.malware sejak 2.26.2, nama lama windows.malfind dan sejenisnya masih ada sebagai alias usang dengan removal_date 2026-06-07); Windows 11 Enterprise 23H2 build 22631; Credential Guard (Microsoft Learn ms.date 2026-04-27 dan 2025-06-12); LSA protection (Microsoft Learn ms.date 2025-03-25); Sysmon (publikasi 2026-09-10); Windows PowerShell 5.1 di .NET Framework 4.x; WinPmem mini (README Velocidex); MITRE ATT&CK T1055.012 v2.0 dan T1003.001 v1.5'
---

# Day 15: Analisis proses di memori (injeksi, hollowing, proses tersembunyi, akses LSASS, dan dump)

Cakupan: menilai apakah proses di image memori Windows disusupi (injeksi kode, hollowing, penyamaran, penyembunyian), apakah ada proses yang membuka LSASS, cara memulihkan file dan region dari memori lalu membandingkannya dengan bukti disk, dan cara menulis kesimpulan beserta batas waktu dan batas tekniknya.

## Ide inti

Setiap plugin analisis proses menjawab satu pertanyaan sempit tentang satu struktur data, pada satu saat. `windows.malware.malfind` hanya melihat region memori yang proteksi VAD-nya bisa dieksekusi dan bukan image yang dipetakan dari file. `windows.malware.psxview` hanya membandingkan empat cara mendaftar proses. `windows.malware.hollowprocesses` hanya memeriksa tiga ketidakcocokan antara PEB, alamat image, dan proteksi VAD. `windows.handles` hanya melihat handle yang masih terbuka saat halaman tabel handle dibaca alat akuisisi. Karena itu hasil "nihil" dari satu plugin selalu berarti "tidak ada di struktur ini, pada detik image ini diambil, dengan kriteria plugin ini", bukan "tidak terjadi". Sebaliknya, hasil "ada" juga belum berarti jahat: runtime .NET dan antivirus menghasilkan region yang persis memenuhi kriteria malfind. Kesimpulan yang bisa dipertanggungjawabkan datang dari beberapa sinyal yang saling mengunci (region, command line, induk, token, DLL, handle) ditambah artefak disk dan event log yang mencakup jendela waktu lebih panjang daripada satu image memori.

Catatan ruang lingkup: Day ini membaca jejak teknik proses berbahaya (injeksi, hollowing) dari sisi forensik. Tidak ada cara membuat teknik itu, tidak ada kode payload, dan isi skrip penyerang tidak ditulis; yang ditulis hanya deskripsi perilakunya. Uji di lab memakai proses sah yang menghasilkan pola serupa (runtime .NET) dan, bila perlu, test Atomic Red Team yang dibaca dulu isinya sebelum dijalankan di VM snapshot.

Kamu sudah mengenal pola ini dari NOC. Image memori adalah core dump router yang diambil sebelum reboot: potret satu saat, besar, dan tidak bisa diulang. Menjalankan `show processes` dan `show memory` pada core dump menunjukkan proses dengan nama yang wajar, tetapi engineer yang curiga juga mencari blok memori yang menjalankan kode bukan dari image IOS di flash, membandingkan tabel ARP, MAC, dan DHCP untuk menemukan host yang hilang dari salah satunya, dan melihat sesi yang sedang terbuka ke perangkat. Engineer itu juga tahu batasnya: core dump tidak menunjukkan sesi yang sudah ditutup sebelum dump, dan blok memori aneh bisa saja milik fitur sah yang mengompilasi kode saat berjalan. Untuk riwayat, ia membuka accounting log yang mencakup berhari-hari. Di Windows, memori adalah core dump-nya, plugin Volatility adalah perintah `show`-nya, dan Sysmon serta event log adalah accounting log-nya.

```
image memori E01 (satu jendela: Selasa 12:42:07-12:52:41 WIB)
  |
  +-- injeksi kode?      windows.malware.malfind  -> region exec, bukan image file
  |                        lalu: vadinfo, dump region, YARA, pembanding lab
  +-- hollowing/menyamar? windows.malware.hollowprocesses | pebmasquerade | ldrmodules
  |                        + cmdline, PPID, path (Day 14)
  +-- tersembunyi?       windows.malware.psxview  -> pslist | psscan | thrdscan | csrss
  +-- konteks proses     windows.dlllist | windows.getsids | windows.privileges | windows.handles
  +-- akses LSASS?       windows.handles (Type Process -> lsass.exe Pid 844) + bit GrantedAccess
  +-- isi skrip?         windows.filescan -> windows.dumpfiles -> potong ke ukuran asli -> hash
  |                        windows.vadyarascan --pid (teks skrip di memori proses)
  v
korelasi dengan jendela lebih panjang (E15-W1): Sysmon 8/10/25, 4104, $J, Prefetch
  v
kesimpulan = sinyal yang saling mengunci + batas waktu + batas teknik per plugin
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan dan data pribadi sekitar 400 ribu pelanggan broadband. Kasusnya `INC-2026-019`: lampiran `Tagihan-Okt-2026.zip` (berisi `Tagihan-Okt-2026.js`) dibuka `andi.pratama`, staf penagihan Jakarta, di laptop `JKT-WS-0388` (Windows 11 Enterprise 23H2 build 22631 x64, RAM 16 GB, Microsoft Defender for Endpoint dan Sysmon) Senin 2026-10-12 pukul 16:05. Lampiran itu menulis `C:\Users\andi.pratama\AppData\Roaming\SysCache\upd.ps1` (4.812 byte) dan mendaftarkan scheduled task `\SysCacheUpdate` yang menjalankannya dengan `powershell.exe` setiap 15 menit (menit ke-06, 21, 36, dan 51, detik ke-02). Loader itu membaca skrip `export-tagihan.ps1` milik Andi yang berisi password akun service `svc_billing`, dan password itu dipakai untuk SSH ke server billing Selasa 02:14. Selasa 2026-10-13 pukul 12:42:07 sampai 12:52:41 WIB, Yoga Pratama (analyst L2 pemegang bukti) mengambil memori laptop itu dengan WinPmem dari drive bukti `USB-E-07` memakai akun admin lokal khusus IR `ir-admin`, saat laptop belum diisolasi (isolasi baru Selasa 16:00). Hasilnya bukti `E01` (`E01_JKT-WS-0388_mem.raw`). Retainer PT Forensik Digital Contoh sudah menganalisis E01 dan menulis satu kalimat: "tidak menemukan akses ke LSASS". Kamis kemarin (Day 14) kamu memprofil salinan kerja `E01-W1` (dibuat Yoga Rabu 2026-10-28 16:30, disalin ke disk lokal `jkt-dfir02`) dengan Volatility 3 2.28.2 yang dibekukan untuk kasus ini, menyusun daftar proses (184 baris di `pslist`, 188 di `psscan`), dan menjanjikan pemeriksaan handle LSASS hari Jumat. Hasil Kamis yang dipakai hari ini: `powershell.exe` PID 12408 (task, mulai 12:51:02 di tengah akuisisi dan baru selesai 12:53:19, setelah akuisisi berakhir) masih hidup, `powershell.exe` PID 11872 (task 12:36) sudah berakhir 12:36:44 dan hanya terlihat di `psscan`, dan Credential Guard aktif (`LsaIso.exe` PID 836).

Jumat 2026-10-30 pukul 09:00, Sari Kusuma (technical lead) menulis kepadamu di kanal `#inc-2026-019`:

> "Pagi. Untuk bahan penutupan kasus, Pak Agus (DPO) dan Pak Dimas minta jawaban dari memori laptop Andi, lanjutan profil kemarin. Mereka tanya: ada tidak tanda kode disuntikkan ke proses lain? Ada proses yang menyamar, di-hollow, atau disembunyikan? Retainer menulis 'tidak menemukan akses ke LSASS'; Pak Agus perlu tahu artinya apa dan batasnya apa, khususnya untuk kredensial Andi dan akun lain yang pernah login di laptop itu. Lalu, bisa tidak kita buktikan isi skrip yang sedang jalan di memori sama dengan `upd.ps1` yang kita ambil lewat `getfile` (E03)? Dan seberapa yakin kita. Aku perlu sebelum jam 14:00 ya."

Pesan itu memuat enam pertanyaan:

1. Adakah tanda kode disuntikkan ke proses lain, dan bagaimana membedakannya dari perilaku program sah?
2. Adakah proses yang di-hollow atau menyamar sebagai proses sah?
3. Adakah proses yang disembunyikan dari daftar proses?
4. Apa yang dimuat dan dipegang proses penyerang (DLL, token, handle), dan adakah yang janggal?
5. Adakah proses yang membuka LSASS, apa arti kalimat retainer, dan apa batasnya untuk kredensial Andi dan akun lain?
6. Bisakah isi skrip di memori dibuktikan sama dengan `upd.ps1` dari E03, dan seberapa yakin seluruh jawaban ini?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, dan pertanyaan 6 di bagian 1.6 sampai 1.8. Bagian 2 berisi perintah, keluaran ilustrasi, dan jawaban tertulis yang kamu kirim ke Sari pukul 13:30.

**Kapan relevan:** saat image memori sudah ada dan pertanyaannya tentang apa yang hidup di dalam proses: injeksi, hollowing, proses yang disembunyikan, akses ke LSASS, isi skrip atau payload yang hanya ada di memori, dan saat kesimpulan retainer tentang memori perlu dijelaskan batasnya ke DPO atau manajemen.
**Kapan bukan jawaban:** saat pertanyaannya tentang apa yang terjadi sebelum atau sesudah jendela akuisisi (jawabannya di event log, Sysmon, EDR, dan artefak disk), saat yang dibutuhkan adalah identifikasi keluarga malware atau analisis perilaku sampel (itu pekerjaan sandbox terpisah), dan saat image memori sendiri bermasalah (profil, smear, dan symbol table dibahas di Day 14).

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (image memori, smear, symbol table, `windows.pslist`, `windows.psscan`, `windows.pstree`, `windows.cmdline`, EPROCESS, PID, PPID, sesi, salinan kerja, Logon ID, 4104, Sysmon, `$J`, jejak responder) tidak diulang. Tabel berikut hanya memuat istilah baru Day ini; kolom padanan memakai analogi NOC dan SOC yang sama di semua Day.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| VAD (Virtual Address Descriptor) | Struktur kernel yang mencatat setiap rentang memori milik proses: alamat, proteksi awal, privat atau dipetakan dari file | Tabel alokasi blok memori di core dump router, lengkap dengan label pemiliknya |
| Region executable tanpa file | Rentang memori yang boleh dieksekusi tetapi tidak berasal dari file image di disk | Blok memori yang menjalankan kode bukan dari image IOS di flash |
| Injeksi kode (T1055) | Menaruh dan menjalankan kode di ruang memori proses lain | Menyisipkan skrip ke proses daemon sah supaya berjalan dengan identitas daemon itu |
| Process hollowing (T1055.012) | Membuat proses sah dalam keadaan suspended, mengganti isi image-nya, lalu melanjutkannya | Perangkat yang label dan nomor serinya asli tetapi firmware di dalamnya sudah diganti |
| JIT (just-in-time compilation) | Runtime (.NET, Java, browser) yang mengompilasi kode saat berjalan ke memori privat yang bisa dieksekusi | Fitur sah yang mengompilasi aturan ke memori saat berjalan, sehingga tampak seperti kode asing |
| PEB (Process Environment Block) | Struktur di memori pengguna milik proses: path image, command line, daftar modul yang dimuat | Konfigurasi yang dilaporkan proses tentang dirinya sendiri, yang bisa diedit oleh proses itu |
| Daftar modul loader (InLoad, InInit, InMem) | Tiga daftar berantai di PEB yang mencatat DLL yang dimuat loader Windows | Tiga tabel inventaris modul yang seharusnya sepakat satu sama lain |
| Handle dan GrantedAccess | Referensi yang dipegang proses ke objek kernel (proses lain, file, key), dengan bitmask hak yang diberikan saat dibuka | Sesi yang sedang terbuka ke perangkat lain beserta privilege level-nya |
| LSASS dan LsaIso | `lsass.exe` memvalidasi login dan menyimpan materi kredensial; dengan Credential Guard rahasia NTLM dan TGT disimpan di `LsaIso.exe` yang diisolasi VBS | Server AAA lokal; dengan Credential Guard, kunci rahasianya dipindah ke modul terpisah yang tidak bisa dibaca dari OS |
| LSA protection (RunAsPPL) | LSASS dijalankan sebagai protected process light sehingga proses biasa tidak bisa membaca memorinya atau menyuntikkan kode | ACL keras pada port manajemen AAA yang hanya mengizinkan proses bertanda tangan tertentu |
| File cache (DataSectionObject, SharedCacheMap) | Salinan halaman isi file yang disimpan Windows di memori setelah file dibaca atau dipetakan | Buffer `show running-config` yang memuat isi file dari flash, per blok, belum tentu utuh |
| Batas waktu dan batas teknik | Batas waktu: kesimpulan hanya berlaku untuk jendela akuisisi. Batas teknik: apa yang bisa lolos dari kriteria tiap plugin | Snapshot `show` hanya berlaku saat diketik, dan tiap perintah `show` hanya melihat tabelnya sendiri |

### 1.1 Injeksi kode dan malfind: apa yang dicari, dan kenapa hasilnya kandidat

Pertanyaan pertama Sari ("ada tanda kode disuntikkan ke proses lain?") adalah pertanyaan tentang memori yang menjalankan kode bukan dari file. Injeksi kode menempatkan kode di ruang memori proses lain sehingga kode itu berjalan dengan identitas proses sah [S2]. Proses normal memuat kode dari file EXE dan DLL yang dipetakan sebagai image; region privat yang boleh ditulis dan dieksekusi sekaligus, atau region privat executable yang berisi kode, adalah anomali yang perlu dijelaskan.

`windows.malware.malfind` mencari region seperti itu [S2]. Di source plugin versi 2.28.2 yang diperiksa (versi plugin 1.1.0), kriterianya bisa dibaca persis [S7]:

- Region dipilih bila string proteksi VAD-nya memuat "EXECUTE" dan "WRITE" sekaligus (misalnya `PAGE_EXECUTE_READWRITE`). Region yang hanya executable tanpa WRITE dipilih hanya bila salah satu halamannya dirty (pernah ditulis).
- Region itu harus privat dengan tag `VadS`, atau tidak privat tetapi proteksinya bukan `PAGE_EXECUTE_WRITECOPY` (proteksi normal untuk image yang dipetakan dari file).
- Region yang seluruh halamannya bernilai nol atau tidak tersedia (paged out) dilewati.
- Kolom `Notes` diisi hanya dari dua byte pertama region: `MZ` diberi label "MZ header", beberapa pola byte awal fungsi diberi label "Function prologue" atau "PE header". Label ini kasar; dua byte pertama tidak cukup untuk menilai isi region.
- Opsi `--pid` membatasi proses, dan `--dump` menulis region ke file bernama `pid.<PID>.vad.<awal>-<akhir>.dmp` [S7][S17].

Hasil malfind adalah kandidat, bukan bukti. Dua sumber kandidat sah yang paling sering muncul di workstation kantor:

- **Runtime JIT.** Runtime .NET, Java, dan browser mengompilasi kode ke memori privat yang executable, sehingga memenuhi kriteria malfind tanpa ada injeksi [S32]. `powershell.exe` di Windows 11 adalah Windows PowerShell 5.1, yang dibangun di atas .NET Framework 4.x [S27], jadi setiap proses PowerShell membawa runtime CLR dan JIT-nya. PowerShell 7 (`pwsh.exe`) berjalan di .NET modern; di .NET 7 ke atas JIT memakai W^X secara bawaan (satu alamat tidak pernah writable dan executable sekaligus) [komunitas, belum terkonfirmasi] [S31], sehingga pola region di `pwsh.exe` bisa berbeda dari `powershell.exe`. Bandingkan dengan proses pembanding di lab sebelum menyimpulkan.
- **Antivirus dan EDR.** Mesin antivirus yang memindai dan mengemulasi kode juga memegang region executable privat. Region malfind di `MsMpEng.exe` adalah pola yang dikenal praktisi [komunitas, belum terkonfirmasi]; dokumentasi artifact malfind Velociraptor juga menyebut false positive sebagai hal yang harus diharapkan dan di-triage [S32].

Yang membuat region menjadi sinyal kuat adalah kombinasinya: region di proses yang tidak punya alasan menjalankan JIT (misalnya `notepad.exe`, `svchost.exe`, `lsass.exe`), header PE lengkap di region privat, isi yang cocok dengan rule YARA keluarga yang dikenal, dan konteks proses yang janggal (induk, command line, token). Satu region RWX di proses .NET tanpa konteks lain bukan temuan.

Batas teknik malfind juga perlu diketahui sebelum menulis "tidak ada injeksi". Proteksi yang dibaca malfind adalah proteksi yang tercatat di VAD saat region dialokasikan; bila kode ditulis ke region non-executable lalu proteksi halamannya diubah kemudian, VAD bisa tetap mencatat non-executable dan malfind tidak melaporkannya [S30]. Kode yang ditulis ke dalam image DLL yang dipetakan dari file juga tidak memenuhi kriteria region privat. Untuk kasus seperti itu ada plugin pihak ketiga yang membaca page table (PTE) secara langsung [S30], dan pilihan itu dicatat sebagai langkah lanjutan, bukan bagian dari Volatility 3 bawaan.

### 1.2 Hollowing dan penyamaran: hollowprocesses, pebmasquerade, ldrmodules

Pertanyaan kedua Sari ("ada proses yang di-hollow atau menyamar?") membedakan dua hal. Hollowing mengganti isi proses sah: proses dibuat suspended, image aslinya dilepas, kode lain ditulis, konteks thread diarahkan ke kode itu, lalu proses dilanjutkan [S28]. Dari luar, nama, path, dan induknya terlihat sah. Penyamaran (masquerading) lebih sederhana: program penyerang diberi nama proses sistem, atau data di PEB-nya diedit supaya alat yang membaca PEB melihat path lain.

`windows.malware.hollowprocesses` (versi plugin 1.0.0) memeriksa tiga hal per proses, dan setiap temuan menjadi satu baris berkolom `PID`, `Process`, `Notes` [S9]:

1. `ImageBaseAddress` di PEB dibandingkan dengan `SectionBaseAddress` di EPROCESS. Pada hollowing klasik keduanya sering berbeda karena image baru ditulis di alamat lain.
2. Harus ada VAD yang dimulai di `SectionBaseAddress`, dan proteksinya harus `PAGE_EXECUTE_WRITECOPY` (proteksi normal image dari file). VAD yang hilang atau proteksi lain dilaporkan.
3. Untuk setiap DLL di daftar modul loader, VAD di alamat dasarnya harus berproteksi `PAGE_EXECUTE_WRITECOPY`.

Plugin ini juga melewati proses tanpa pesan bila daftar modul loader-nya berisi kurang dari tiga DLL atau proses itu punya kurang dari lima VAD; komentar source menyebut pengecualian itu untuk menghindari smear dan proses yang sudah berakhir [S9]. Akibatnya, hasil kosong tidak berarti semua proses diperiksa. Proses yang sudah berakhir (seperti PID 11872) dan proses yang PEB-nya tidak terbaca karena smear lolos dari pemeriksaan ini.

Untuk penyamaran, tiga pemeriksaan saling melengkapi:

- **Konteks dasar (Day 14):** nama, path, induk, sesi, dan jumlah instance. `lsass.exe` yang sah berinduk `wininit.exe` dan hanya ada satu; `svchost.exe` berinduk `services.exe`. Di E01 `lsass.exe` 844 dan `LsaIso.exe` 836 sama-sama berinduk `wininit.exe` 688, dan `svchost.exe` 1948 berinduk `services.exe` 824.
- **`windows.malware.pebmasquerade`:** menampilkan nama dari EPROCESS (`ImageFileName` dan `SeAuditProcessCreationInfo`) berdampingan dengan path image di PEB, dan menandai bila panjang string `ImagePathName` atau `CommandLine` di PEB tidak konsisten dengan field panjangnya [S10]. Plugin ini tidak membandingkan kolom-kolom itu untuk kamu; perbandingan nama dilakukan manual, dan penyamar yang menjaga panjang string tetap konsisten tidak ditandai [S10].
- **`windows.malware.ldrmodules`:** untuk setiap VAD yang diawali header MZ, plugin memeriksa apakah alamat dasarnya muncul di tiga daftar modul loader (`InLoad`, `InInit`, `InMem`), dan menampilkan path file yang dipetakan (`MappedPath`) [S11]. DLL yang dilepas dari daftar loader supaya tidak terlihat di `dlllist` muncul sebagai baris dengan `False` di kolom daftar tetapi tetap punya VAD. Satu pola `False` yang normal: executable utama proses tidak pernah ada di daftar `InInit`, jadi baris `powershell.exe` dengan `InInit` `False` bukan temuan.

### 1.3 Proses tersembunyi dan proses yang sudah berakhir: psxview

Pertanyaan ketiga Sari ("ada yang disembunyikan?") dijawab dengan membandingkan beberapa cara mendaftar proses. Rootkit yang melepas EPROCESS dari daftar proses aktif membuat proses hilang dari `pslist`, tetapi struktur EPROCESS-nya masih bisa ditemukan dengan memindai memori, thread-nya masih ada, dan `csrss.exe` masih memegang handle ke proses itu.

`windows.malware.psxview` di 2.28.2 (versi plugin 1.0.0) membandingkan empat sumber dan menampilkannya sebagai kolom boolean [S12]:

| Kolom | Sumber | Yang dibuktikan bila `True` |
|---|---|---|
| `pslist` | Daftar proses aktif kernel | Proses terdaftar di daftar berantai yang dipakai alat biasa |
| `psscan` | Pemindaian memori untuk struktur EPROCESS | Struktur proses ada di memori, termasuk yang sudah berakhir |
| `thrdscan` | Pemindaian thread, dipetakan ke proses pemiliknya | Proses masih punya struktur thread di memori |
| `csrss` | Handle bertipe Process milik setiap `csrss.exe` | `csrss.exe` sesi itu memegang handle ke proses |

Tabel di atas dipakai untuk membaca satu baris psxview: cari proses yang `False` di `pslist` tetapi `True` di sumber lain, lalu lihat kolom `Exit Time` di ujung kanan sebelum menyebutnya tersembunyi. Proses yang sudah berakhir tetapi strukturnya belum ditimpa muncul dengan pola yang sama, dan psxview tidak membuangnya; kolom `Exit Time` terisi untuk proses itu [S12]. Pola wajar lain: `System` dan proses yang dibuat sebelum `csrss.exe` biasanya `False` di kolom `csrss`.

Satu batas teknik psxview di 2.28.2 jarang disadari. Sebelum menampilkan hasil, plugin membuang proses yang namanya mengandung karakter selain huruf ASCII, titik, dan spasi [S12]. Nama dengan angka atau garis bawah, seperti `Sysmon64.exe` atau `winpmem_mini_x64.exe`, tidak muncul sama sekali di keluaran psxview, padahal ada di `pslist`. Ketiadaan sebuah proses di keluaran psxview karena itu tidak boleh dibaca sebagai "disembunyikan"; selalu bandingkan dengan `pslist` dan `psscan` dari Day 14. Plugin ini juga tidak memakai beberapa sumber yang dikenal dari Volatility 2 (desktop thread, sesi, PspCid), menurut komentar source-nya [S12].

### 1.4 DLL, token, dan handle: konteks yang membuat sinyal bermakna

Pertanyaan keempat Sari ("apa yang dimuat dan dipegang proses penyerang") mengubah satu PID menjadi cerita. Plugin konteks yang dipakai:

| Plugin | Memberi | Yang dicari |
|---|---|---|
| `windows.dlllist --pid` | DLL di daftar modul loader, dengan `Base`, `Size`, `Name`, `Path`, `LoadCount`, `LoadTime` [S13] | DLL dari folder yang bisa ditulis pengguna (`AppData`, `Temp`, `Downloads`, `ProgramData`, `Users\Public`), nama yang menyamar, DLL yang dimuat jauh setelah proses mulai |
| `windows.malware.ldrmodules --pid` | VAD ber-MZ dibandingkan dengan tiga daftar loader [S11] | DLL yang ada di memori tetapi dilepas dari daftar loader |
| `windows.getsids --pid` | SID akun, grup, dan integrity level token proses | Akun pemilik dan apakah token elevated (High) atau biasa (Medium) |
| `windows.privileges --pid` | Privilege token dengan atribut `Present`, `Enabled`, `Default` | Privilege seperti `SeDebugPrivilege` yang dibutuhkan untuk membuka proses lain dengan akses penuh |
| `windows.handles --pid` | Handle proses: `Type`, `GrantedAccess`, `Name` [S14] | File, key registry, mutex, dan proses lain yang sedang dibuka |

Tabel di atas dibaca sebagai daftar periksa per proses, bukan per plugin. `dlllist` membaca daftar loader di PEB, yang bisa diedit oleh kode di dalam proses itu sendiri; karena itu pasangannya adalah `ldrmodules`, yang mulai dari VAD [S11]. Untuk proses PowerShell, DLL yang wajar adalah DLL runtime CLR dan PowerShell dari folder Windows dan .NET Framework, ditambah `amsi.dll`. AMSI adalah antarmuka yang membuat PowerShell (skrip, penggunaan interaktif, dan evaluasi kode dinamis) mengirim isi yang dijalankan ke antimalware terpasang untuk dipindai [S26], jadi `amsi.dll` di proses PowerShell adalah komponen bawaan, bukan temuan.

Token menjawab pertanyaan hak. Untuk membuka proses lain dan mendapat hak akses penuh, proses harus mengaktifkan `SeDebugPrivilege` [S24]. Proses dengan token Medium milik pengguna biasa tidak punya privilege itu, sehingga tidak bisa membuka proses milik SYSTEM seperti `lsass.exe` dengan hak baca memori. Di event log Day 05, semua proses penyerang di laptop Andi bertoken terbatas; di memori, `getsids` dan `privileges` memeriksa hal yang sama dari sisi token yang hidup.

Handle adalah satu-satunya tempat di image memori yang menunjukkan "proses A sedang memegang akses ke proses B". `windows.handles` menulis nama objek proses dengan format `<nama image> Pid <PID>`, misalnya `lsass.exe Pid 844`, sehingga semua handle ke LSASS bisa disaring dari satu keluaran [S14]. Batasnya: yang terlihat hanya handle yang masih terbuka saat halaman tabel handle dibaca alat akuisisi. Handle yang dibuka, dipakai, lalu ditutup sebelum itu tidak meninggalkan apa pun di struktur ini.

### 1.5 LSASS: handle, hak akses, Credential Guard, dan arti "tidak menemukan akses"

Pertanyaan kelima Sari adalah yang paling sering salah dibaca di rapat. Kalimat retainer "tidak menemukan akses ke LSASS" adalah hasil pemeriksaan memori, dan maknanya bergantung pada apa yang diperiksa. Membaca kredensial dari LSASS membutuhkan proses yang membuka `lsass.exe` dengan hak membaca memori, oleh pengguna admin atau SYSTEM; dump memori LSASS lalu dianalisis untuk mengambil materi kredensial [S29].

Bit hak akses yang relevan untuk menilai sebuah handle ke LSASS berasal dari definisi resmi hak akses proses [S24]. Tabel berikut dipakai untuk menerjemahkan kolom `GrantedAccess`; perhatikan baris `PROCESS_VM_READ`, karena tanpa bit itu memori proses tidak bisa dibaca lewat handle tersebut.

| Hak akses | Nilai | Arti untuk LSASS |
|---|---|---|
| `PROCESS_QUERY_LIMITED_INFORMATION` | `0x1000` | Hanya informasi terbatas (nama image, exit code); dipakai banyak alat pemantau |
| `PROCESS_QUERY_INFORMATION` | `0x0400` | Informasi lebih luas termasuk token |
| `PROCESS_VM_READ` | `0x0010` | Membaca memori proses; syarat membaca materi kredensial |
| `PROCESS_VM_WRITE` dan `PROCESS_VM_OPERATION` | `0x0020`, `0x0008` | Menulis memori dan mengubah proteksi; dipakai injeksi |
| `PROCESS_CREATE_THREAD` | `0x0002` | Membuat thread di proses lain; dipakai injeksi |
| `PROCESS_DUP_HANDLE` | `0x0040` | Menduplikasi handle; bisa dipakai untuk mendapat akses maksimal |
| `SYNCHRONIZE` | `0x00100000` | Menunggu proses berakhir |
| `PROCESS_ALL_ACCESS` | `0x1FFFFF` | Semua hak; handle hasil `CreateProcess` milik induk punya nilai ini |

Dua perlindungan di laptop Andi mengubah makna handle dan isi memori LSASS:

- **LSA protection (RunAsPPL).** LSASS berjalan sebagai protected process sehingga proses yang tidak terlindungi tidak bisa membaca memorinya atau menyuntikkan kode [S23]. Untuk protected process, hak seperti `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`, `PROCESS_CREATE_THREAD`, `PROCESS_DUP_HANDLE`, `PROCESS_QUERY_INFORMATION`, dan `PROCESS_ALL_ACCESS` tidak diizinkan dari proses biasa; yang tersisa antara lain `PROCESS_QUERY_LIMITED_INFORMATION` [S24]. Fitur ini aktif bawaan pada instalasi baru Windows 11 22H2 ke atas yang tergabung ke domain atau Entra dan mampu HVCI, dan statusnya dibuktikan dari event WinInit 12 di log System ("LSASS.exe was started as a protected process with level: 4") [S23]. Di E15-W1 event itu tercatat pada setiap boot, termasuk Senin 2026-10-12 07:56 WIB.
- **Credential Guard.** Dengan Credential Guard, hash password NTLM, Kerberos TGT, dan kredensial domain yang disimpan aplikasi tidak lagi berada di memori `lsass.exe`, melainkan di proses LSA terisolasi `LsaIso.exe` yang dilindungi virtualization-based security; LSASS berkomunikasi dengannya lewat RPC, dan malware dengan hak admin di OS pun tidak bisa mengekstrak rahasia itu [S21][S22]. Credential Guard aktif bawaan di Windows 11 22H2 ke atas pada perangkat tergabung domain yang memenuhi syarat dan berlisensi Enterprise [S21].

Credential Guard punya batas yang menentukan jawaban untuk Agus. Microsoft menyebut hal yang tidak dilindunginya, antara lain [S22]:

- kredensial akun lokal dan Microsoft Account;
- kredensial yang dimasukkan pengguna saat diminta untuk autentikasi NTLM, yang tetap bisa dibaca dari memori LSASS;
- Kerberos service ticket (yang dilindungi hanya TGT);
- software yang mengelola kredensial di luar perlindungan fitur Windows, termasuk password yang ditulis di skrip atau file;
- keylogger dan serangan fisik;
- penyerang dengan malware di PC yang memakai hak yang melekat pada kredensial yang sedang login.

Dari sini jawaban untuk laptop Andi tersusun menjadi tiga lapis. Pertama, penyerang berjalan di sesi Andi dengan token Medium tanpa `SeDebugPrivilege`, dan LSASS dilindungi PPL, sehingga jalur membaca memori LSASS tertutup dua kali; temuan handle di memori (bagian 2.7) dan Sysmon EID 10 di disk (bagian 2.9) memeriksa apakah ada percobaan. Kedua, kalaupun memori LSASS terbaca, hash NTLM dan TGT Andi tidak ada di sana karena Credential Guard. Ketiga, dan ini yang paling penting untuk DPO: Credential Guard tidak relevan untuk dua kredensial yang paling berisiko di kasus ini. Password `svc_billing` dibaca dari file `export-tagihan.ps1` dalam teks biasa (rotasinya adalah tindak lanjut yang tidak bergantung pada hasil memori), dan penyerang yang berjalan di sesi Andi bisa memakai akses Andi (Kerberos dan SSO) selama sesi itu hidup tanpa perlu mencuri apa pun [S22].

Akun lain yang pernah login di laptop itu perlu disebut satu per satu. `ir-admin` adalah akun lokal, dan kredensial akun lokal tidak dilindungi Credential Guard [S22]; Yoga mengetik password-nya di konsol Selasa 12:38, sehingga materi kredensialnya mungkin ada di memori LSASS dan ikut ter-image di E01. Penyerang tidak punya hak untuk membacanya, dan password `ir-admin` diganti setelah setiap pemakaian (Day 05 bagian 1.4), tetapi E01 sendiri menjadi bukti sensitif yang aksesnya harus dibatasi seperti E03.

Satu jejak responder juga perlu dijelaskan sebelum ada yang bertanya. WinPmem membaca memori fisik lewat driver kernel yang menyediakan antarmuka baca ke memori fisik, lalu program pengguna menulis isinya ke file [S33]. Ia tidak membuka handle bertipe Process ke `lsass.exe`; yang terlihat di handle `winpmem_mini_x64.exe` adalah handle ke device driver dan file output di USB. Karena itu `winpmem` tidak muncul di daftar handle ke LSASS, dan itu memang yang diharapkan, bukan tanda alat itu disembunyikan.

### 1.6 Dump proses dan file: memulihkan isi, memotong padding, dan membandingkan hash

Pertanyaan keenam Sari ("isi skrip di memori sama dengan E03?") dijawab dengan dua jenis pemulihan dari memori, dan keduanya punya jebakan ukuran.

Jenis pertama adalah dump region atau proses. `malfind --dump` dan `vadinfo --dump` menulis isi VAD ke file `.dmp` [S7][S17]. Dump ini berisi apa yang ada di memori, termasuk kode yang mungkin tidak pernah ada di disk. Perlakukan sebagai data: hitung hash, periksa string dan header, jalankan YARA, tetapi jangan dijalankan dan jangan dibuka dengan aplikasi yang mungkin mengeksekusi isinya. YARA adalah mesin pencocokan pola: rule berisi kumpulan string (teks, hex, atau regex) dan kondisi yang menggabungkannya, misalnya "minimal dua dari lima string ini ada dan berkas diawali header MZ". Rule yang cocok memberi nama keluarga atau tooling yang dikenal, tetapi kualitasnya hanya sebaik rule-nya, jadi sumber dan versi rule set dicatat di case notes. Volatility menyediakan `windows.vadyarascan` untuk menjalankan rule YARA langsung ke memori proses (`--pid`, `--yara-file`, `--yara-string`, `--wide`, `--insensitive`) [S18][S19]. Analisis perilaku sampel adalah pekerjaan terpisah di sandbox terisolasi, bukan bagian dari forensik endpoint.

Jenis kedua adalah dump file dari file cache. Saat file dibaca atau dipetakan, Windows menyimpan halaman isinya di memori, dan `windows.dumpfiles` bisa menuliskannya kembali [S15]. Opsi yang tersedia: `--pid` (file yang terkait handle proses itu), `--virtaddr` dan `--physaddr` (objek `_FILE_OBJECT` di alamat tertentu, biasanya dari keluaran `windows.filescan`), dan `--filter` dengan `--ignore-case` untuk regex nama file; `--filter` tidak boleh digabung dengan opsi alamat [S15]. Untuk setiap objek file, plugin bisa menghasilkan tiga jenis keluaran [S15]:

| Cache | Ekstensi | Isi |
|---|---|---|
| `DataSectionObject` | `.dat` | Halaman file yang dipetakan sebagai data |
| `ImageSectionObject` | `.img` | File yang dipetakan sebagai image executable |
| `SharedCacheMap` | `.vacb` | View cache manager untuk file yang dibaca lewat cache |

Tabel di atas menjelaskan kenapa satu file bisa menghasilkan dua atau tiga keluaran dengan ukuran berbeda. Nama keluaran berpola `file.<alamat objek file>.<alamat objek memori>.<cache>.<nama file>.<ekstensi>` [S15].

Jebakan ukurannya ada di cara halaman ditulis. Untuk `DataSectionObject`, halaman ditulis per 4.096 byte; untuk `SharedCacheMap`, per view 256 KiB (262.144 byte), termasuk view terakhir yang hanya terisi sebagian; dan ukuran file asli (`FileSize`, `ValidDataLength`) tidak dipakai untuk memotong keluaran [S16]. Halaman yang tidak tersedia diisi byte nol karena pembacaan memakai padding [S15]. Konsekuensinya untuk `upd.ps1` (4.812 byte):

- Keluaran `.dat` berukuran kelipatan 4.096 byte (8.192 byte bila dua halaman tercatat), dan keluaran `.vacb` 262.144 byte. Hash file keluaran tidak akan pernah sama dengan hash file asli, walaupun isinya utuh.
- Isi harus dipotong ke ukuran asli dari sumber independen (`$MFT` entry 287903 dan E03 sama-sama 4.812 byte, Day 08 bagian 2.2), baru di-hash.
- Sebelum memotong, periksa apakah setiap halaman yang memuat data benar-benar terisi. File 4.812 byte menempati halaman pertama (byte 0 sampai 4.095) dan 716 byte di halaman kedua (byte 4.096 sampai 4.811). Bila halaman kedua tidak tersedia, 716 byte itu berisi nol; hash setelah dipotong tidak cocok, dan perbandingan harus turun ke tingkat halaman atau baris teks: hash halaman pertama dibandingkan dengan hash 4.096 byte pertama E03, dan bagian yang hilang dicatat sebagai "tidak tersedia di memori", bukan "berbeda".

Satu hal lagi tentang makna. File cache menunjukkan isi file seperti yang dibaca dari disk, bukan bukti bahwa proses tertentu menjalankannya. Isi yang dijalankan proses PowerShell 12408 dibuktikan dengan dua sumber lain: teks skrip di memori privat proses itu (`windows.vadyarascan --pid 12408` dengan string unik dari E03), dan event 4104 di E15-W1 yang mencatat blok skrip dengan `ProcessId` 12408. Ketiganya (cache, memori proses, 4104) dibandingkan dengan E03, dan USN `$J` membuktikan file tidak berubah sejak dibuat Senin 16:05:19 (Day 08 bagian 2.4).

### 1.7 Menafsir dengan hati-hati: sinyal, bukti, batas waktu, dan batas teknik

Analisis proses memori penuh sinyal yang juga muncul pada software sah:

- Region RWX muncul pada JIT sah (runtime .NET, Java, browser) dan antivirus, bukan hanya injeksi.
- Selisih psxview bisa berarti proses sudah berakhir, atau nama proses dibuang filter plugin, bukan disembunyikan.
- DLL dari path tidak biasa bisa software sah yang dipasang per pengguna.
- Label `Notes` malfind hanya membaca dua byte pertama.

Karena itu setiap sinyal adalah kandidat yang dikonfirmasi lewat command line, induk, token, DLL, handle, dan artefak disk (Day 05, 07, 08, 11). Satu plugin memberi petunjuk; kesimpulan datang dari gambaran yang konsisten.

Kalimat kesimpulan untuk orang non-teknis harus membawa dua batas.

**Batas waktu.** E01 hanya menggambarkan kondisi Selasa 12:42:07 sampai 12:52:41 WIB, dan karena akuisisi live membaca memori fisik secara berurutan, halaman yang berbeda menggambarkan detik yang berbeda di dalam jendela itu (smear, Day 14 bagian 1.2). Proses yang sudah berakhir sebelum jendela itu (seperti 82 eksekusi task sebelumnya, Senin 16:21 sampai Selasa 12:36) hanya meninggalkan sisa di `psscan`, tanpa tabel handle dan tanpa VAD yang bisa diperiksa. Proses yang mulai di tengah akuisisi (PID 12408, 12:51:02) hanya tertangkap pada halaman yang dibaca setelah 12:51:02. Untuk jendela Senin 16:05 sampai Selasa 16:00, sumbernya adalah Sysmon, event log, dan EDR.

**Batas teknik.** Tabel berikut adalah daftar apa yang bisa lolos dari tiap pemeriksaan; baca kolom kanan sebelum menulis kata "tidak ada".

| Pemeriksaan | Yang dilihat | Yang bisa lolos |
|---|---|---|
| `windows.malware.malfind` | VAD executable privat atau non-image, berisi data | Proteksi yang diubah setelah alokasi; kode di dalam image DLL dari file; region yang sudah dibebaskan atau paged out [S7][S30] |
| `windows.malware.hollowprocesses` | PEB vs alamat image, proteksi VAD image dan DLL | Varian yang menjaga PEB dan proteksi tetap konsisten; proses dengan kurang dari 3 DLL atau 5 VAD (dilewati); proses yang sudah berakhir [S9] |
| `windows.malware.pebmasquerade` | Nama EPROCESS vs path PEB, konsistensi panjang string | Penyamar yang menjaga panjang string; perbandingan nama tetap manual [S10] |
| `windows.malware.psxview` | Empat sumber daftar proses | Penyembunyian yang menghapus proses dari keempat sumber; nama dengan angka atau garis bawah tidak ditampilkan sama sekali [S12] |
| `windows.dlllist` dan `ldrmodules` | Daftar loader di PEB dan VAD ber-MZ | Kode tanpa header MZ (header dihapus); DLL yang sudah dilepas sebelum akuisisi [S11][S13] |
| `windows.handles` | Handle yang terbuka saat akuisisi | Handle yang sudah ditutup; akses dari kernel atau driver tanpa handle proses [S14] |
| `windows.dumpfiles` | Halaman file yang masih di cache | Halaman yang sudah dibuang dari cache; ukuran asli tidak diketahui plugin [S15][S16] |

### 1.8 Korelasi memori dan disk: jendela pendek, jendela panjang

Temuan memori menguat bila disk dan event log menunjukkan hal yang sama, dan disk mengisi waktu di luar jendela akuisisi. Pasangan yang dipakai di kasus ini:

- **Proses di memori dan eksekusi di event log (Day 05):** PID 12408 di memori dengan command line task dan induk `svchost.exe` 1948 (Schedule) cocok dengan Sysmon 1 dan TaskScheduler 200/201 untuk eksekusi 12:51:02.
- **Isi skrip di memori dan 4104 (Day 03 dan 05):** blok skrip yang dicatat 4104 untuk PID 12408 dibandingkan dengan teks di memori proses dan dengan E03.
- **Keadaan file di memori dan `$J` (Day 08):** `upd.ps1` tidak punya record perubahan setelah dibuat, sehingga isi di cache Selasa siang sama dengan isi yang ditulis Senin sore.
- **Handle ke LSASS di memori dan Sysmon (jendela panjang):** Sysmon mencatat proses yang membuka proses lain (EID 10, ProcessAccess, yang secara khusus disebut untuk mendeteksi alat pembaca memori LSASS), proses yang membuat thread di proses lain (EID 8, CreateRemoteThread, dengan proses sumber dan tujuan), dan perubahan image proses akibat teknik seperti hollowing (EID 25, ProcessTampering) [S25]. Ketiganya hanya ada bila konfigurasi Sysmon memasukkannya. Di PT JAB, konfigurasi Sysmon workstation di OU `Workstations-EDR` mencatat EID 8, EID 25, dan EID 10 dengan `TargetImage` `lsass.exe`, sehingga E15-W1 bisa menjawab untuk seluruh jendela Sysmon (sejak 2026-10-04 sampai Kamis 2026-10-15 08:47 WIB), bukan hanya sepuluh menit di E01.
- **Dump dan hash:** hash isi yang dipulihkan dicocokkan dengan bukti disk (E03, `$MFT`), bukan hanya dengan intel.

Memori menjawab "apa yang hidup, dan apakah ada yang disuntikkan, pada saat itu"; disk dan event log menjawab "dari mana, sejak kapan, dan apakah pernah terjadi di luar saat itu". Kesimpulan untuk Agus dibangun dari keduanya.

## 2. Contoh dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi yang disusun agar konsisten dengan fakta kasus; alamat memori, offset, dan jumlah baris dihitung agar cocok antar tabel, bukan hasil eksekusi nyata. Perintah Volatility dijalankan di `jkt-dfir02` (Ubuntu LTS, Volatility 3 2.28.2 di virtualenv `~/venv/vol3`, symbol pack Windows offline) atas salinan kerja `E01-W1`; perintah PowerShell untuk event log dijalankan di `JKT-DFIR01` atas CSV hasil parse E15-W1. Narasi memakai WIB (UTC+7). Volatility 3 dan EvtxECmd menulis waktu dalam UTC, jadi setiap keluaran diberi label zona waktunya; UTC sama dengan WIB dikurangi 7 jam. Nama kolom di bawah mengikuti source plugin 2.28.2; cocokkan dengan `vol <plugin> -h` di versi-mu.

### 2.1 Menyiapkan E01-W1 dan daftar proses acuan

Langkah ini memastikan salinan kerja yang dipakai Jumat pagi sama dengan yang diprofil Kamis, lalu menetapkan folder output supaya retainer bisa mengulang hasilnya.

```bash
. ~/venv/vol3/bin/activate
cd /data/INC-2026-019/E01-W1/
sha256sum E01_JKT-WS-0388_mem.raw
cat /mnt/evidence/INC-2026-019/E01/E01_JKT-WS-0388_mem.raw.sha256
IMG=/data/INC-2026-019/E01-W1/E01_JKT-WS-0388_mem.raw
OUT=/mnt/cases/INC-2026-019/analysis/E01-W1/vol3-2.28.2/day15
mkdir -p "$OUT"
vol -q -f "$IMG" -r csv windows.malware.malfind > "$OUT/malfind.csv"
```

- `sha256sum` dan `cat`: hash salinan lokal yang disalin Kamis ke disk `jkt-dfir02` (read-only, `chmod 444`) dibandingkan dengan berkas `.sha256` master yang ditulis Yoga di titik koleksi (Day 14 bagian 2.2). Bila berbeda, salinan lokal diambil ulang dari `E01-W1` di `/mnt/cases`, bukan diperbaiki.
- `IMG` dan `OUT`: variabel supaya setiap perintah di bawah memakai path yang sama. `OUT` adalah subfolder di folder hasil Volatility Kamis (`pslist.csv`, `psscan.csv`, `cmdline.csv`, dan lainnya), dan menyebut versi alat (`vol3-2.28.2`) sesuai aturan pembekuan versi kasus ini.
- `-q`: menyembunyikan progres; `-r csv`: renderer CSV yang bisa dibuka di spreadsheet atau disaring dengan alat teks.

Keluaran ilustrasi:

```
ab615fb6d8bcb7094375050f0d335942664fda81870b4b3ba1b5be1a1fee9310  E01_JKT-WS-0388_mem.raw
ab615fb6d8bcb7094375050f0d335942664fda81870b4b3ba1b5be1a1fee9310  E01_JKT-WS-0388_mem.raw
```

**Cara membaca hasil:** hash cocok, jadi semua angka di bawah berasal dari salinan yang identik dengan master E01. Tabel berikut adalah daftar proses acuan dari profil Kamis (Day 14 bagian 2.3 dan 2.5), dipakai untuk mencocokkan setiap PID yang muncul di plugin hari ini; perhatikan kolom "Catatan", karena tiga proses punya sifat khusus (berakhir, mulai di tengah akuisisi, milik responder).

| PID | Proses | PPID | Sesi | Dibuat (WIB) | Catatan |
|---|---|---|---|---|---|
| 4 | `System` | 0 | - | Senin 07:56:31 (boot) | |
| 120, 2380 | `Registry`, `MemCompression` | 4 | - | Senin, saat boot | Proses kernel tanpa PEB |
| 688 | `wininit.exe` | 500 | 0 | Senin 07:56:33 | Induk `services.exe`, `LsaIso.exe`, `lsass.exe` |
| 824 | `services.exe` | 688 | 0 | Senin 07:56:33 | |
| 836 | `LsaIso.exe` | 688 | 0 | Senin 07:56:33 | Credential Guard aktif |
| 844 | `lsass.exe` | 688 | 0 | Senin 07:56:33 | |
| 960, 1948 | `svchost.exe` | 824 | 0 | Senin 07:56:34 dan 07:56:36 | 1948 adalah layanan Schedule |
| 3312 | `Sysmon64.exe` | 824 | 0 | Senin 07:56:41 | |
| 3520 | `MsMpEng.exe` | 824 | 0 | Senin 07:56:42 | Defender Antivirus |
| 3876 | `MsSense.exe` | 824 | 0 | Senin 07:56:44 | Sensor Defender for Endpoint |
| 768, 852 | `csrss.exe`, `winlogon.exe` | 676 | 1 | Senin 07:56:33 | Sesi Andi |
| 5476 | `explorer.exe` | 5404 | 1 | Senin 07:58:21 | Shell Andi |
| 6240, 7112 | `OneDrive.exe`, `OUTLOOK.EXE` | 5476 | 1 | Senin 07:58:40 dan 08:03:12 | |
| 9284 | `EXCEL.EXE` | 5476 | 1 | Selasa 08:23:58 | Membuka `Rekap-Penagihan-Okt-2026.xlsx` |
| 11872 | `powershell.exe` | 1948 | 1 | Selasa 12:36:02 | Task; berakhir 12:36:44, hanya di `psscan` |
| 12408 | `powershell.exe` | 1948 | 1 | Selasa 12:51:02 | Task; mulai di tengah akuisisi, selesai 12:53:19 |
| 12416 | `conhost.exe` | 12408 | 1 | Selasa 12:51:02 | Konsol milik 12408 |
| 10688 | `explorer.exe` | 10652 | 2 | Selasa 12:38:52 | Responder (`ir-admin`) |
| 11020 | `cmd.exe` | 10688 | 2 | Selasa 12:41:50 | Responder, elevated |
| 11344 | `winpmem_mini_x64.exe` | 11020 | 2 | Selasa 12:42:07 | Responder, alat akuisisi |
| 4412, 10088, 10652 | `svchost.exe`, `smss.exe`, `userinit.exe` | - | - | Senin 08:12:09; Selasa 12:38:10 dan 12:38:51 | Sudah berakhir, hanya di `psscan` |

**Variasi:** simpan setiap keluaran sebagai CSV dan teks sekaligus (`-r csv` dan renderer bawaan) bila retainer memakai alat lain untuk membaca. Untuk plugin yang lama berjalan pada image 16 GB, jalankan di `tmux` supaya sesi SSH yang putus tidak menghentikan proses.

**Kapan gagal:** symbol table untuk build 22631 tidak ada di symbol pack offline, sehingga plugin berhenti dengan pesan symbol table tidak ditemukan. Itu sudah dicek Kamis saat profil (Day 14 bagian 2.2); bila muncul hari ini, berarti `vol` dijalankan dari virtualenv atau direktori simbol yang berbeda.

### 2.2 malfind pada seluruh image

Langkah ini menjawab pertanyaan pertama Sari dengan pemeriksaan pertama: region mana di proses mana yang memenuhi kriteria injeksi.

```bash
vol -q -f "$IMG" windows.malware.malfind
```

- `windows.malware.malfind`: nama plugin di 2.28.2. Nama lama `windows.malfind` masih ada sebagai alias usang (bagian 6), tetapi tidak dipakai di catatan kasus supaya perintah tetap jalan setelah alias dihapus [S8].
- Tanpa `--pid`: semua proses diperiksa, supaya pertanyaan "ke proses lain" terjawab, bukan hanya untuk PowerShell.

Keluaran ilustrasi (kolom `Hexdump` dan `Disasm` dipotong; ditampilkan utuh untuk satu baris di bagian 2.3):

```
PID    Process         Start VPN       End VPN         Tag   Protection              CommitCharge  PrivateMemory  File output  Notes
3520   MsMpEng.exe     0x1f6a3c40000   0x1f6a3c4ffff   VadS  PAGE_EXECUTE_READWRITE  16            1              Disabled     N/A
3520   MsMpEng.exe     0x1f6a4210000   0x1f6a422ffff   VadS  PAGE_EXECUTE_READWRITE  32            1              Disabled     N/A
12408  powershell.exe  0x7ff9b5a00000  0x7ff9b5a0ffff  VadS  PAGE_EXECUTE_READWRITE  3             1              Disabled     N/A
12408  powershell.exe  0x7ff9b5a10000  0x7ff9b5a1ffff  VadS  PAGE_EXECUTE_READWRITE  2             1              Disabled     Function prologue
12408  powershell.exe  0x7ff9b5aa0000  0x7ff9b5aaffff  VadS  PAGE_EXECUTE_READWRITE  1             1              Disabled     N/A
```

**Cara membaca hasil:**

- Lima region di dua proses. Tidak ada satu baris pun untuk `lsass.exe`, `LsaIso.exe`, `explorer.exe` (5476 maupun 10688), `svchost.exe`, `OUTLOOK.EXE`, `EXCEL.EXE`, `OneDrive.exe`, atau `winlogon.exe`.
- Semua region privat (`PrivateMemory` 1, tag `VadS`) dengan proteksi `PAGE_EXECUTE_READWRITE`. Region `MsMpEng.exe` berukuran 0x10000 (16 halaman) dan 0x20000 (32 halaman) dengan `CommitCharge` penuh; region `powershell.exe` masing-masing 0x10000 (16 halaman) dengan hanya 3, 2, dan 1 halaman ter-commit.
- Tidak ada `MZ header` di `Notes`. Satu region bertanda "Function prologue", artinya hanya dua byte pertamanya cocok dengan pola awal fungsi; label ini sendiri tidak membedakan kode JIT dari kode sisipan.
- `File output` bernilai `Disabled` karena `--dump` belum dipakai.

**Variasi:** `--pid 12408 3520` membatasi ke dua proses ini untuk pengulangan yang lebih cepat. Untuk image dengan banyak proses .NET (server aplikasi), simpan keluaran ke CSV lalu kelompokkan per proses sebelum membaca baris satu per satu.

**Kapan gagal:** halaman region sedang paged out saat akuisisi, sehingga malfind melewatinya karena dianggap kosong; hasil "tidak ada region" di proses itu tidak berarti region tidak pernah ada. Pada image dengan smear berat, region di proses yang baru mulai (seperti 12408) bisa hanya tertangkap sebagian.

### 2.3 Menilai region di PowerShell 12408 dan MsMpEng 3520

Langkah ini mengubah lima kandidat menjadi kesimpulan, dengan tiga pemeriksaan: tetangga region di peta VAD, isi region yang di-dump, dan pembanding dari VM lab.

```bash
vol -q -f "$IMG" windows.vadinfo --pid 12408 | grep -E '0x7ff9b5|clr\.dll|clrjit\.dll'
vol -q -f "$IMG" -o "$OUT/malfind-12408" windows.malware.malfind --pid 12408 --dump
sha256sum "$OUT"/malfind-12408/pid.12408.vad.*.dmp
strings -n 8 "$OUT"/malfind-12408/pid.12408.vad.*.dmp | grep -ci 'program cannot be run'
```

- `windows.vadinfo --pid 12408`: peta VAD proses; `grep` menyaring region kandidat dan modul CLR untuk melihat letaknya.
- `-o`: folder output global Volatility, tempat file `--dump` ditulis.
- `malfind --pid 12408 --dump`: menulis tiga region ke file `pid.12408.vad.<awal>-<akhir>.dmp` [S7][S17].
- `strings ... | grep -ci 'program cannot be run'`: menghitung string stub DOS yang ada di hampir semua file PE; nol berarti tidak ada header PE yang tertinggal di dalam region, bukan hanya di dua byte pertama.

Keluaran ilustrasi (`vadinfo`, kolom dipotong):

```
PID    Process         Start VPN       End VPN         Tag   Protection              PrivateMemory  File
12408  powershell.exe  0x7ff9b59f0000  0x7ff9b59fffff  VadS  PAGE_READWRITE          1              N/A
12408  powershell.exe  0x7ff9b5a00000  0x7ff9b5a0ffff  VadS  PAGE_EXECUTE_READWRITE  1              N/A
12408  powershell.exe  0x7ff9b5a10000  0x7ff9b5a1ffff  VadS  PAGE_EXECUTE_READWRITE  1              N/A
12408  powershell.exe  0x7ff9b5aa0000  0x7ff9b5aaffff  VadS  PAGE_EXECUTE_READWRITE  1              N/A
12408  powershell.exe  0x7ff9b6f20000  0x7ff9b710cfff  Vad   PAGE_EXECUTE_WRITECOPY  0              \Windows\Microsoft.NET\Framework64\v4.0.30319\clrjit.dll
12408  powershell.exe  0x7ff9c1e40000  0x7ff9c26f3fff  Vad   PAGE_EXECUTE_WRITECOPY  0              \Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll
```

Keluaran ilustrasi (`malfind` untuk region bertanda "Function prologue", 16 byte pertama dan tiga baris disassembly):

```
12408  powershell.exe  0x7ff9b5a10000  0x7ff9b5a1ffff  VadS  PAGE_EXECUTE_READWRITE  2  1  ...  Function prologue
55 48 8b ec 56 48 83 ec 30 48 8b f1 48 8b ce e8   UH..VH..0H..H...
0x7ff9b5a10000: push rbp
0x7ff9b5a10001: mov rbp, rsp
0x7ff9b5a10004: push rsi
```

Keluaran ilustrasi (`sha256sum` dan `strings`):

```
4a7d...  pid.12408.vad.0x7ff9b5a00000-0x7ff9b5a0ffff.dmp
c09e...  pid.12408.vad.0x7ff9b5a10000-0x7ff9b5a1ffff.dmp
e215...  pid.12408.vad.0x7ff9b5aa0000-0x7ff9b5aaffff.dmp
0
```

**Cara membaca hasil:**

- Ketiga region berada di blok alamat yang sama dengan heap loader CLR (`0x7ff9b59f0000` sampai `0x7ff9b5aaffff`), berdampingan dengan region data `PAGE_READWRITE` milik runtime, dan tidak jauh dari `clrjit.dll` serta `clr.dll`. Itu tata letak yang diharapkan dari heap kode JIT.
- Isi region diawali urutan instruksi pembuka fungsi biasa, tanpa header PE di mana pun di dalam region (hitungan string stub DOS nol). Tidak ada string URL, nama domain C2, atau nama fungsi API yang biasanya muncul di shellcode yang memuat dirinya sendiri; cek ini dicatat sebagai pemeriksaan negatif, bukan bukti kebersihan.
- Hash dump dicatat di case notes supaya retainer bisa memverifikasi file yang sama. Hash region memori tidak dicocokkan ke intel: region JIT berbeda di setiap proses dan tidak punya padanan file.

Pembanding datang dari VM lab PT JAB `LAB-WS01` (Windows 11 23H2 build 22631, snapshot bersih, Defender aktif). Jumat 09:20 sampai 09:50 Rudi Hartanto menjalankan `powershell.exe -NoProfile -WindowStyle Hidden -File` dengan skrip jinak yang menulis tanggal ke file, lalu mengambil memori dari snapshot VM (tanpa smear). Hasilnya dirangkum di tabel berikut; baca kolom "Sama dengan E01?" untuk melihat apakah pola di laptop Andi bisa dijelaskan oleh perilaku normal.

| Ciri | E01 (laptop Andi) | `LAB-WS01` (skrip jinak) | Sama dengan E01? |
|---|---|---|---|
| Region malfind di `powershell.exe` | 3, RWX, `VadS`, privat | 3, RWX, `VadS`, privat | Ya |
| Letak relatif terhadap `clr.dll` | Blok heap loader di bawah `clrjit.dll` | Pola sama, alamat berbeda | Ya |
| Header PE di region | Tidak ada | Tidak ada | Ya |
| Region malfind di `MsMpEng.exe` | 2, RWX, privat, tanpa MZ | 2, RWX, privat, tanpa MZ | Ya |
| Region malfind di proses lain | Tidak ada | Tidak ada | Ya |

**Kesimpulan langkah ini:** kelima region dijelaskan oleh JIT CLR di PowerShell dan oleh mesin pemindai Defender; tidak ada region yang menunjukkan kode disisipkan ke proses lain. Untuk `MsMpEng.exe`, region RWX tanpa header PE adalah pola yang dikenal praktisi pada antivirus [komunitas, belum terkonfirmasi] dan sama dengan VM lab; region itu tidak di-dump lebih jauh karena proses antivirus adalah protected process dan tidak terkait rantai penyerang.

**Variasi:** jalankan rule YARA tim atas file `.dmp` (atau `windows.vadyarascan --pid 12408` dengan rule yang sama) dan catat sumber serta versi rule set. Untuk proses .NET modern (`pwsh.exe`, aplikasi .NET 7 ke atas), siapkan pembanding terpisah karena pola memori JIT-nya bisa berbeda (bagian 1.1).

**Kapan gagal:** pembanding lab memakai build Windows atau versi .NET Framework berbeda dari laptop, sehingga jumlah dan letak region tidak bisa dibandingkan. Catat build dan versi runtime di VM pembanding sebelum memakai hasilnya.

### 2.4 Hollowing dan penyamaran: hollowprocesses, pebmasquerade, ldrmodules

Langkah ini menjawab pertanyaan kedua Sari dengan tiga plugin yang melihat sisi berbeda dari "proses ini benar-benar dirinya sendiri".

```bash
vol -q -f "$IMG" windows.malware.hollowprocesses
vol -q -f "$IMG" windows.malware.pebmasquerade --pid 844 1948 5476 12408
vol -q -f "$IMG" windows.malware.pebmasquerade --pid 836
vol -q -f "$IMG" windows.malware.ldrmodules --pid 12408 > "$OUT/ldrmodules-12408.txt"
```

- `hollowprocesses` tanpa `--pid`: semua proses yang lolos prasyarat (minimal 3 DLL di daftar loader dan 5 VAD) diperiksa [S9].
- `pebmasquerade --pid`: dibatasi ke proses yang relevan untuk penyamaran (LSASS, svchost Schedule, Explorer Andi, PowerShell task). `LsaIso.exe` dijalankan terpisah karena PEB-nya tidak diharapkan terbaca, supaya baris yang tidak terbaca tidak tercampur dengan proses lain.
- `ldrmodules --pid 12408`: semua VAD ber-MZ di proses task dibandingkan dengan tiga daftar loader [S11].

Keluaran ilustrasi (`hollowprocesses`):

```
PID     Process Notes
```

Keluaran ilustrasi (`pebmasquerade`):

```
PID    EPROCESS_ImageFileName  EPROCESS_SeAudit_ImageFileName                                         PEB_ImageFilePath                                                   PEB_ImageFilePath_Spoofed  PEB_CommandLine_Spoofed
844    lsass.exe               \Device\HarddiskVolume3\Windows\System32\lsass.exe                     C:\Windows\system32\lsass.exe                                       False                      False
1948   svchost.exe             \Device\HarddiskVolume3\Windows\System32\svchost.exe                   C:\Windows\system32\svchost.exe                                     False                      False
5476   explorer.exe            \Device\HarddiskVolume3\Windows\explorer.exe                           C:\Windows\Explorer.EXE                                             False                      False
12408  powershell.exe          \Device\HarddiskVolume3\Windows\System32\WindowsPowerShell\v1.0\powershell.exe  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe  False                      False

PID    EPROCESS_ImageFileName  EPROCESS_SeAudit_ImageFileName                                         PEB_ImageFilePath  PEB_ImageFilePath_Spoofed  PEB_CommandLine_Spoofed
836    LsaIso.exe              \Device\HarddiskVolume3\Windows\System32\LsaIso.exe                    N/A                N/A                        N/A
```

Keluaran ilustrasi (`ldrmodules`, ringkasan dari 84 baris):

```
Pid    Process         Base            InLoad  InInit  InMem   MappedPath
12408  powershell.exe  0x7ff7c2b10000  True    False   True    \Windows\System32\WindowsPowerShell\v1.0\powershell.exe
12408  powershell.exe  0x7ffa0c3e0000  True    True    True    \Windows\System32\ntdll.dll
12408  powershell.exe  0x7ff9c1e40000  True    True    True    \Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll
12408  powershell.exe  0x7ff9f8c90000  True    True    True    \Windows\System32\amsi.dll
...    (80 baris lain, semua True True True, MappedPath di \Windows\)
```

**Cara membaca hasil:**

- `hollowprocesses` hanya mencetak judul kolom: tidak ada proses yang memenuhi tiga kriterianya. Proses yang dilewati prasyarat tetap perlu disebut: proses tanpa PEB (`System` 4, `Registry` 120, `MemCompression` 2380), `LsaIso.exe` yang memorinya tidak bisa dibaca dari OS, dan empat proses yang sudah berakhir (11872, 4412, 10088, 10652). Untuk 11872, hollowing tidak bisa dinilai dari memori sama sekali.
- `pebmasquerade`: nama EPROCESS, path audit kernel, dan path PEB menunjuk file yang sama untuk keempat proses, dan tidak ada bendera panjang string yang tidak konsisten. Perbedaan huruf besar kecil (`system32` vs `System32`, `Explorer.EXE`) adalah cara Windows menulis path di PEB, bukan penyamaran.
- `LsaIso.exe` hanya punya nama dari EPROCESS; kolom PEB `N/A` karena proses LSA terisolasi dilindungi VBS dan tidak bisa dibaca seperti proses biasa [S22]. Itu bukan temuan, dan juga berarti E01 tidak bisa dipakai untuk menilai isi `LsaIso.exe`.
- `ldrmodules`: 84 VAD ber-MZ, semuanya ada di daftar loader. Satu-satunya `False` adalah `powershell.exe` di kolom `InInit`, pola normal untuk executable utama. Tidak ada DLL yang dipetakan tetapi dilepas dari daftar, dan tidak ada `MappedPath` di luar folder Windows.

**Variasi:** jalankan `ldrmodules` tanpa `--pid` lalu saring baris yang `False` di ketiga kolom daftar sekaligus; baris seperti itu dengan `MappedPath` berisi file data (misalnya file sumber daya bahasa) biasanya wajar, sedangkan baris tanpa `MappedPath` di proses sistem layak diperiksa.

**Kapan gagal:** `pebmasquerade` dijalankan untuk banyak proses sekaligus dan salah satu PEB tidak terbaca; penanganan error di source plugin perlu dicek, jadi baris setelah proses yang gagal dibaca sebaiknya diverifikasi ulang dengan `--pid` tunggal (bagian 9, Catatan sumber).

### 2.5 Proses tersembunyi: psxview

Langkah ini menjawab pertanyaan ketiga Sari, dengan satu perhatian khusus pada dua proses yang punya angka di namanya.

```bash
vol -q -f "$IMG" windows.malware.psxview > "$OUT/psxview.txt"
grep -E ' (4|688|824|836|844|1948|3520|3876|4412|5476|10088|10652|11020|11872|12408|12416) ' "$OUT/psxview.txt"
grep -cE 'Sysmon64|winpmem' "$OUT/psxview.txt"
```

- `psxview`: empat sumber daftar proses dalam satu tabel [S12].
- `grep` pertama: menampilkan proses yang ada di daftar acuan bagian 2.1.
- `grep -c` kedua: menghitung apakah dua proses bernama angka atau garis bawah muncul.

Keluaran ilustrasi (kolom `Offset(Virtual)` dipotong):

```
Name             PID    pslist  psscan  thrdscan  csrss  Exit Time
System           4      True    True    True      False
wininit.exe      688    True    True    True      True
services.exe     824    True    True    True      True
LsaIso.exe       836    True    True    True      True
lsass.exe        844    True    True    True      True
svchost.exe      1948   True    True    True      True
MsMpEng.exe      3520   True    True    True      True
MsSense.exe      3876   True    True    True      True
svchost.exe      4412   False   True    False     False  2026-10-12 01:12:40 UTC
explorer.exe     5476   True    True    True      True
smss.exe         10088  False   True    False     False  2026-10-13 05:38:10 UTC
userinit.exe     10652  False   True    False     False  2026-10-13 05:39:22 UTC
cmd.exe          11020  True    True    True      True
powershell.exe   11872  False   True    False     False  2026-10-13 05:36:44 UTC
powershell.exe   12408  True    True    True      True
conhost.exe      12416  True    True    True      True
0
```

**Cara membaca hasil:**

- Empat baris `False` di `pslist`, persis empat proses yang di Day 14 bagian 2.5 hanya ada di `psscan` (188 dikurangi 184). Semuanya punya `Exit Time`: `svchost.exe` 4412 (Senin 08:12:40 WIB), `smss.exe` 10088 dan `userinit.exe` 10652 (Switch user Yoga, Selasa 12:38:10 dan 12:39:22 WIB), dan `powershell.exe` 11872 (Selasa 12:36:44 WIB, sama dengan akhir task pukul 12:36 di event log). Ini proses yang sudah berakhir dan strukturnya belum ditimpa, bukan proses yang disembunyikan. Thread-nya sudah tidak ada dan `csrss.exe` sudah melepas handle-nya.
- `System` `False` di kolom `csrss` adalah pola normal.
- Hitungan nol pada baris terakhir: `Sysmon64.exe` (3312) dan `winpmem_mini_x64.exe` (11344) tidak ada di keluaran psxview, padahal keduanya ada di `pslist` Kamis. Itu efek filter nama di plugin 2.28.2, yang membuang nama berisi angka atau garis bawah [S12]. Status kedua proses dinilai dari `pslist`, `psscan`, dan `windows.threads` atau `windows.thrdscan` secara terpisah.

**Variasi:** `--physical-offsets` menampilkan offset fisik, berguna bila hasilnya dicocokkan dengan alat lain yang memakai offset fisik [S12].

**Kapan gagal:** keluaran psxview dibaca tanpa daftar `pslist` di sebelahnya, sehingga proses yang hilang karena filter nama dilaporkan sebagai proses yang disembunyikan rootkit.

### 2.6 Konteks PowerShell 12408: command line, token, privilege, DLL, dan handle

Langkah ini menjawab pertanyaan keempat Sari untuk satu-satunya proses penyerang yang hidup di E01.

```bash
vol -q -f "$IMG" windows.cmdline --pid 12408
vol -q -f "$IMG" windows.getsids --pid 12408
vol -q -f "$IMG" windows.privileges --pid 12408 | grep -E 'SeDebug|SeChangeNotify|SeImpersonate'
vol -q -f "$IMG" windows.dlllist --pid 12408 > "$OUT/dlllist-12408.txt"
vol -q -f "$IMG" windows.handles --pid 12408 > "$OUT/handles-12408.txt"
```

- `cmdline`: command line dari PEB proses.
- `getsids`: SID akun dan grup token, termasuk integrity level.
- `privileges`: privilege token dengan kolom `Attributes`; `grep` menyaring tiga privilege yang menentukan apakah proses bisa membuka proses lain atau meniru token lain.
- `dlllist` dan `handles`: disimpan ke file karena panjang; dibaca dengan filter di bawah.

Keluaran ilustrasi:

```
PID    Process         Args
12408  powershell.exe  powershell.exe -NoProfile -WindowStyle Hidden -File C:\Users\andi.pratama\AppData\Roaming\SysCache\upd.ps1

PID    Process         SID                                              Name
12408  powershell.exe  S-1-5-21-2847193650-1938475021-3765120984-4127   -
12408  powershell.exe  S-1-5-21-2847193650-1938475021-3765120984-513    Domain Users
12408  powershell.exe  S-1-1-0                                          Everyone
12408  powershell.exe  S-1-5-32-545                                     Users
12408  powershell.exe  S-1-5-4                                          Interactive
12408  powershell.exe  S-1-5-11                                         Authenticated Users
12408  powershell.exe  S-1-5-15                                         This Organization
12408  powershell.exe  S-1-16-8192                                      Medium Mandatory Level

PID    Process         Value  Privilege                Attributes                Description
12408  powershell.exe  20     SeDebugPrivilege                                   Debug programs
12408  powershell.exe  23     SeChangeNotifyPrivilege  Present,Enabled,Default   Bypass traverse checking
12408  powershell.exe  29     SeImpersonatePrivilege                             Impersonate a client after authentication
```

Ringkasan `dlllist-12408.txt` (84 modul; `LoadTime` dalam UTC):

```
Base            Name                                 Path                                                                          LoadTime (UTC)
0x7ff7c2b10000  powershell.exe                       C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe                     2026-10-13 05:51:02
0x7ffa0c3e0000  ntdll.dll                            C:\Windows\SYSTEM32\ntdll.dll                                                 2026-10-13 05:51:02
0x7ff9f9e10000  mscoree.dll                          C:\Windows\SYSTEM32\mscoree.dll                                               2026-10-13 05:51:02
0x7ff9c1e40000  clr.dll                              C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clr.dll                       2026-10-13 05:51:02
0x7ff9b6f20000  clrjit.dll                           C:\Windows\Microsoft.NET\Framework64\v4.0.30319\clrjit.dll                    2026-10-13 05:51:03
0x7ff9b8a70000  System.Management.Automation.ni.dll  C:\Windows\assembly\NativeImages_v4.0.30319_64\System.Manaa57fc8cc#\...\System.Management.Automation.ni.dll  2026-10-13 05:51:03
0x7ff9f8c90000  amsi.dll                             C:\Windows\SYSTEM32\amsi.dll                                                  2026-10-13 05:51:03
```

Saringan `handles-12408.txt` untuk tipe yang menunjuk objek di luar proses:

```
PID    Process         HandleValue  Type     GrantedAccess  Name
12408  powershell.exe  0x2c4        Process  0x1fffff       conhost.exe Pid 12416
12408  powershell.exe  0x2f0        File     0x100020       \Device\HarddiskVolume3\Windows\System32
```

**Cara membaca hasil:**

- Command line sama persis dengan action task `\SysCacheUpdate` di XML dan di 4698 (Day 05 bagian 2.4); induknya `svchost.exe` 1948 (Schedule) dari profil Kamis. Ini eksekusi task, bukan proses yang menyamar.
- SID pemilik RID 4127 (`andi.pratama`, SID domain dari Day 08), integrity Medium. Tidak ada SID grup Administrators yang aktif dan tidak ada High Mandatory Level.
- `SeDebugPrivilege` dan `SeImpersonatePrivilege` tidak ada di token (kolom `Attributes` kosong); token biasa pengguna non-admin. Dengan token ini proses tidak bisa membuka `lsass.exe` dengan hak membaca memori [S24].
- Semua 84 modul berasal dari `C:\Windows\` (System32, Microsoft.NET, assembly native image). Tidak ada DLL dari `AppData`, `Temp`, `Downloads`, `ProgramData`, atau `Users\Public`. `amsi.dll` dimuat satu detik setelah proses mulai, sesuai integrasi AMSI di PowerShell [S26]. Waktu muat semua modul jatuh di 05:51:02 sampai 05:51:03 UTC; tidak ada DLL yang dimuat belakangan.
- Satu-satunya handle bertipe `Process` menunjuk ke `conhost.exe` 12416, konsol milik proses itu sendiri. Tidak ada handle ke `lsass.exe` atau proses lain.

**Variasi:** di versi-mu, cek apakah `windows.privileges` menampilkan privilege yang tidak ada dengan `Attributes` kosong atau tidak menampilkannya sama sekali; keduanya berarti privilege itu tidak ada di token. Untuk proses tanpa Sysmon di host lain, `getsids` dan `privileges` adalah cara tercepat menilai elevasi dari memori.

**Kapan gagal:** proses dimulai di tengah akuisisi dan halaman PEB atau tabel handle-nya dibaca sebelum proses itu ada, sehingga `cmdline` atau `handles` kosong atau berisi sisa data. Untuk 12408 hasilnya lengkap dan konsisten dengan event log, tetapi kemungkinan itu disebut di batas waktu.

### 2.7 Handle ke LSASS di seluruh proses

Langkah ini menjawab inti pertanyaan kelima Sari: proses mana saja yang memegang handle ke `lsass.exe` saat E01 diambil, dan dengan hak apa.

```bash
vol -q -f "$IMG" -r csv windows.handles > "$OUT/handles-all.csv"
grep -i ',Process,' "$OUT/handles-all.csv" | grep -i 'lsass.exe Pid 844'
grep -i ',Thread,' "$OUT/handles-all.csv" | grep -i 'Pid 844' | grep -v '^[^,]*,844,'
grep -iE ',(11344|11020|10688),' "$OUT/handles-all.csv" | grep -iE ',(Process|File),'
```

- `windows.handles` tanpa `--pid`: semua handle dari semua proses yang tabel handle-nya terbaca [S14].
- `grep 'lsass.exe Pid 844'`: format nama objek proses di plugin ini adalah `<nama> Pid <PID>` [S14].
- Saringan kedua: handle bertipe `Thread` ke thread milik LSASS dari proses lain (jalur lain untuk menyisipkan kode).
- Saringan ketiga: handle milik proses responder, untuk menjawab pertanyaan "bagaimana WinPmem membaca memori tanpa membuka LSASS".

Keluaran ilustrasi (kolom `Offset` dipotong):

```
PID    Process       HandleValue  Type     GrantedAccess  Name
688    wininit.exe   0x1a8        Process  0x1fffff       lsass.exe Pid 844
824    services.exe  0x3d4        Process  0x1000         lsass.exe Pid 844
3520   MsMpEng.exe   0x1e9c       Process  0x101000       lsass.exe Pid 844
3876   MsSense.exe   0x2b40       Process  0x101000       lsass.exe Pid 844

(saringan Thread: tidak ada baris)

11344  winpmem_mini_x        0x0e8  File  0x12019f  \Device\<device driver WinPmem>
11344  winpmem_mini_x        0x0f4  File  0x120196  \Device\HarddiskVolume7\INC-2026-019\E01_JKT-WS-0388_mem.raw
11020  cmd.exe               0x05c  File  0x100020  \Device\HarddiskVolume7\tools
```

Tabel berikut menerjemahkan keempat nilai `GrantedAccess` dengan bit dari bagian 1.5; baca kolom `PROCESS_VM_READ`, karena itu syarat membaca memori LSASS.

| Pemegang | GrantedAccess | Bit yang terpasang | `PROCESS_VM_READ`? | Penilaian |
|---|---|---|---|---|
| `wininit.exe` 688 | `0x1FFFFF` | `PROCESS_ALL_ACCESS` | Ya | Induk yang membuat LSASS; handle hasil `CreateProcess` memang bernilai ini [S24] |
| `services.exe` 824 | `0x1000` | `PROCESS_QUERY_LIMITED_INFORMATION` | Tidak | Informasi terbatas |
| `MsMpEng.exe` 3520 | `0x101000` | `SYNCHRONIZE` + `PROCESS_QUERY_LIMITED_INFORMATION` | Tidak | Pemantauan oleh antivirus |
| `MsSense.exe` 3876 | `0x101000` | `SYNCHRONIZE` + `PROCESS_QUERY_LIMITED_INFORMATION` | Tidak | Pemantauan oleh sensor EDR |

**Cara membaca hasil:**

- Empat pemegang handle ke LSASS, semuanya proses sistem atau keamanan yang wajar. Hanya induknya yang memegang hak membaca memori.
- Tidak ada handle dari `powershell.exe` 12408, `explorer.exe` 5476, proses lain di sesi Andi, atau proses responder. Tidak ada handle ke thread LSASS dari proses lain.
- PID 11872 tidak bisa dinilai: proses itu sudah berakhir pukul 12:36:44 dan tabel handle-nya sudah dibebaskan. Hanya sisa EPROCESS-nya yang ada di `psscan`. Pertanyaan "apakah 11872 membuka LSASS" dijawab dari Sysmon EID 10 (bagian 2.9), bukan dari memori.
- WinPmem memegang handle ke device driver akuisisinya dan ke file output di drive USB (`HarddiskVolume7`, `USB-E-07`), bukan ke LSASS. Driver membaca memori fisik secara langsung [S33], sehingga memori LSASS ikut terbaca ke E01 tanpa handle proses. Driver itu diekstrak WinPmem ke file sementara `C:\Users\ir-admin\AppData\Local\Temp\pme6A3F.tmp` sebelum dimuat; nama device dan nama service driver bergantung versi WinPmem dan dicocokkan dengan toolkit yang sama, bukan ditebak.

**Variasi:** saring juga handle bertipe `Process` dengan bit `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`, atau `PROCESS_CREATE_THREAD` ke proses apa pun di sesi Andi (`explorer.exe`, `OUTLOOK.EXE`, `EXCEL.EXE`); kombinasi bit itu adalah prasyarat injeksi ke proses lain. Di E01 hasilnya nol selain handle induk ke anaknya.

**Kapan gagal:** handle dibuka, dipakai, lalu ditutup sebelum halaman tabel handle dibaca. Ini batas utama kalimat "tidak ada handle ke LSASS": ia hanya berlaku untuk detik akuisisi.

### 2.8 Memulihkan `upd.ps1` dari file cache dan membandingkannya dengan E03

Langkah ini menjawab bagian pertama pertanyaan keenam Sari. Bahannya tiga: file cache di E01, hash `upd.ps1` dari E03 yang dicatat di evidence log (`6f1c...`, 4.812 byte, teks ASCII), dan ukuran dari `$MFT` E15-W1 entry 287903 (4.812 byte, Day 08 bagian 2.2).

```bash
vol -q -f "$IMG" windows.filescan | grep -i 'SysCache'
vol -q -f "$IMG" -o "$OUT/dumpfiles" windows.dumpfiles --virtaddr 0xd38f0a4c2e10
cd "$OUT/dumpfiles" && ls -l
F=file.0xd38f0a4c2e10.0xd38f09e3b1c0.DataSectionObject.upd.ps1.dat
tail -c +4813 "$F" | tr -d '\000' | wc -c
dd if="$F" bs=1 skip=4096 count=716 2>/dev/null | tr -d '\000' | wc -c
head -c 4812 "$F" > upd_E01-cache_dat.ps1
head -c 4812 file.0xd38f0a4c2e10.0xd38f0a8d4010.SharedCacheMap.upd.ps1.vacb > upd_E01-cache_vacb.ps1
sha256sum upd_E01-cache_dat.ps1 upd_E01-cache_vacb.ps1
```

- `windows.filescan | grep`: mencari objek `_FILE_OBJECT` untuk file di folder `SysCache`; kolomnya `Offset` dan `Name` [S20].
- `windows.dumpfiles --virtaddr`: men-dump objek file di alamat itu. `--virtaddr` dipakai, bukan `--pid`, karena PowerShell biasanya sudah menutup handle ke file skrip setelah membacanya, sehingga file itu tidak terkait handle proses mana pun [S15].
- `tail -c +4813 ... | wc -c`: menghitung byte bukan nol setelah byte ke-4.812. Nol berarti sisa halaman hanya padding.
- `dd ... skip=4096 count=716`: menghitung byte bukan nol di 716 byte data pada halaman kedua. 716 berarti halaman kedua tersedia penuh; nol berarti halaman itu tidak tersedia dan diisi padding. Cek ini hanya sah untuk file teks tanpa byte nol (ASCII atau UTF-8); untuk file UTF-16 atau biner, bandingkan per halaman dengan E03.
- `head -c 4812`: memotong ke ukuran asli dari `$MFT` dan E03, lalu hash.

Keluaran ilustrasi:

```
0xd38f0a4c2e10  \Users\andi.pratama\AppData\Roaming\SysCache\upd.ps1
0xd38f0a51b6a0  \Users\andi.pratama\AppData\Roaming\SysCache

Cache              FileObject      FileName  Result
DataSectionObject  0xd38f0a4c2e10  upd.ps1   file.0xd38f0a4c2e10.0xd38f09e3b1c0.DataSectionObject.upd.ps1.dat
SharedCacheMap     0xd38f0a4c2e10  upd.ps1   file.0xd38f0a4c2e10.0xd38f0a8d4010.SharedCacheMap.upd.ps1.vacb

-rw-r--r-- 1 analyst analyst   8192 ... file.0xd38f0a4c2e10.0xd38f09e3b1c0.DataSectionObject.upd.ps1.dat
-rw-r--r-- 1 analyst analyst 262144 ... file.0xd38f0a4c2e10.0xd38f0a8d4010.SharedCacheMap.upd.ps1.vacb
0
716
6f1c...  upd_E01-cache_dat.ps1
6f1c...  upd_E01-cache_vacb.ps1
```

**Cara membaca hasil:**

- Dua keluaran untuk satu file: `.dat` 8.192 byte (dua halaman 4.096 byte) dan `.vacb` 262.144 byte (satu view 256 KiB). Keduanya lebih besar dari 4.812 byte karena plugin menulis per halaman dan per view, tanpa memotong ke ukuran file [S16].
- Setelah byte ke-4.812 hanya ada nol, dan 716 byte data di halaman kedua terisi semua. File utuh di cache.
- Setelah dipotong ke 4.812 byte, kedua salinan menghasilkan SHA-256 `6f1c...`, sama dengan `upd.ps1` di E03. Isi file di cache memori Selasa siang identik byte demi byte dengan file yang diambil lewat `getfile` pukul 12:36.
- Hash file `.dat` dan `.vacb` mentah dicatat juga di case notes sebagai hash turunan, dengan keterangan bahwa keduanya tidak bisa dibandingkan langsung dengan E03.

**Variasi:** bila halaman kedua tidak tersedia (hitungan `dd` nol), jangan menulis "hash tidak cocok, isi berbeda". Bandingkan hash 4.096 byte pertama dengan 4.096 byte pertama E03 (`head -c 4096` di kedua sisi), lalu bandingkan baris teks dengan `diff` dan tandai bagian halaman kedua sebagai "tidak tersedia di memori". Kalimat untuk laporan menjadi "4.096 byte pertama identik; 716 byte terakhir tidak tersedia di E01".

**Kapan gagal:** tidak ada objek file untuk `upd.ps1` di `filescan` karena halaman cache sudah dibuang; pemulihan dari file cache tidak mungkin, dan perbandingan isi bergantung pada memori proses dan 4104 saja.

Bagian kedua pertanyaan keenam ("isi skrip yang sedang berjalan") butuh bukti dari memori proses, bukan hanya cache. Rule YARA dibuat dari string unik di E03 yang tidak sensitif (nama fungsi dan nama variabel, tanpa URL C2 dan tanpa kredensial), dengan modifier `ascii wide` karena .NET menyimpan string dalam UTF-16:

```
rule upd_e03_strings
{
  strings:
    $f1 = "<nama fungsi unik dari E03>" ascii wide
    $f2 = "<nama variabel unik dari E03>" ascii wide
  condition:
    $f1 and $f2
}
```

```bash
vol -q -f "$IMG" windows.vadyarascan --yara-file "$OUT/upd-e03.yar"
```

- `windows.vadyarascan` tanpa `--pid`: memindai VAD semua proses, supaya terlihat apakah teks skrip ada di proses selain PowerShell [S18].
- `--yara-file`: rule dari file; Volatility memakai yara-x bila tersedia, atau yara-python minimal 3.8 [S19].

Keluaran ilustrasi (kolom dipotong):

```
Offset          PID    ImageFileName   Rule             Component
0x1b6e4a3c210   12408  powershell.exe  upd_e03_strings  $f1
0x1b6e4a3d0f8   12408  powershell.exe  upd_e03_strings  $f2
0x1b6e5c11480   12408  powershell.exe  upd_e03_strings  $f1
0x1b6e5c12370   12408  powershell.exe  upd_e03_strings  $f2
0x2a91f6e0c40   3520   MsMpEng.exe     upd_e03_strings  $f1
0x2a91f6e1a28   3520   MsMpEng.exe     upd_e03_strings  $f2
```

**Cara membaca hasil:** string skrip ada di memori privat PowerShell 12408 (dua lokasi, sesuai teks skrip dan hasil parse-nya) dan di `MsMpEng.exe`, yang menerima isi skrip lewat AMSI untuk dipindai [S26]. Tidak ada proses lain yang memuat teks itu, jadi tidak ada tanda skrip disisipkan ke `explorer.exe` atau proses lain. Ini membuktikan teks yang sama ada di proses yang berjalan; perbandingan teks lengkapnya datang dari 4104 di bagian 2.9.

### 2.9 Korelasi dengan E15-W1: Sysmon 8, 10, 25, eksekusi 12:51, dan 4104

Langkah ini memperpanjang jendela dari sepuluh menit di E01 ke seluruh jendela Sysmon di E15-W1, memakai CSV EvtxECmd yang sudah dibuat di Day 05.

```powershell
$e = Import-Csv '\\jkt-evid01\cases\INC-2026-019\analysis\E15-W1\EZ-2026.5.0\EventLogs\E15-W1_evtx.csv'
$s = $e | Where-Object { $_.Channel -like '*Sysmon*' }
$s | Where-Object { $_.EventId -in '8','10','25' } | Group-Object EventId | Select-Object Name, Count
$s | Where-Object { $_.EventId -eq '10' } | Group-Object ExecutableInfo | Select-Object Name, Count
$s | Where-Object { $_.EventId -eq '1' -and $_.TimeCreated -ge '2026-10-13 05:36:00' -and $_.TimeCreated -lt '2026-10-13 05:52:00' -and $_.ExecutableInfo -match 'powershell' } |
  Select-Object TimeCreated, PayloadData1, ExecutableInfo
$e | Where-Object { $_.EventId -eq '4104' -and $_.ProcessId -in '11872','12408' } |
  Select-Object TimeCreated, ProcessId, PayloadData1
```

- `$s`: semua event Sysmon E15-W1 (sejak 2026-10-04 21:37 WIB sampai Kamis 2026-10-15 08:47 WIB, Day 05 bagian 2.2).
- EID 8, 10, 25: CreateRemoteThread, ProcessAccess, ProcessTampering [S25]. Konfigurasi Sysmon di OU `Workstations-EDR` mencatat EID 10 hanya untuk target `lsass.exe`.
- Pengelompokan EID 10 per `ExecutableInfo`: proses sumber yang membuka LSASS. Kolom tempat proses sumber dan `GrantedAccess` dipetakan bergantung map EvtxECmd; cek di CSV versi-mu.
- Filter Sysmon 1 dan 4104: dua eksekusi task di sekitar jendela akuisisi.

Keluaran ilustrasi (waktu UTC):

```
Name Count
---- -----
10      37

Name                                   Count
----                                   -----
C:\Windows\System32\svchost.exe           37

TimeCreated                  PayloadData1                                                                                   ExecutableInfo
-----------                  ------------                                                                                   --------------
2026-10-13 05:36:02.4180000  ProcessID: 11872, ParentProcessID: 1948 (svchost.exe)                                          powershell.exe -NoProfile -WindowStyle Hidden -File C:\Users\andi.pratama\AppData\Roaming\SysCache\upd.ps1
2026-10-13 05:51:02.3570000  ProcessID: 12408, ParentProcessID: 1948 (svchost.exe)                                          powershell.exe -NoProfile -WindowStyle Hidden -File C:\Users\andi.pratama\AppData\Roaming\SysCache\upd.ps1

TimeCreated                  ProcessId  PayloadData1
-----------                  ---------  ------------
2026-10-13 05:36:04.1120000  11872      Path: C:\Users\andi.pratama\AppData\Roaming\SysCache\upd.ps1
2026-10-13 05:51:04.0590000  12408      Path: C:\Users\andi.pratama\AppData\Roaming\SysCache\upd.ps1
```

**Cara membaca hasil:**

- EID 8 dan EID 25 tidak muncul di pengelompokan, artinya nol event di seluruh jendela Sysmon: tidak ada thread yang dibuat di proses lain dan tidak ada perubahan image proses yang terdeteksi Sysmon, termasuk selama Senin 16:05 sampai Kamis 08:47.
- EID 10 ke `lsass.exe`: 37 event, semuanya dari `svchost.exe` layanan sistem dengan `GrantedAccess` `0x1000` (cek nilainya per baris di `Payload`). Nol dari `powershell.exe`, `wscript.exe`, atau proses lain di sesi Andi. Ini menutup celah PID 11872 dan 82 eksekusi task sebelum E01, sejauh konfigurasi Sysmon mencatatnya.
- Sysmon 1 untuk 11872 (12:36:02 WIB) dan 12408 (12:51:02 WIB) cocok dengan PID, induk 1948, dan command line di memori. TaskScheduler 201 mencatat run 12:36:02 selesai 12:36:44 dan run 12:51:02 selesai 12:53:19, jadi 12408 masih berjalan sepanjang sisa akuisisi sampai 12:52:41.
- 4104 dua detik setelah setiap proses mulai, dengan `ProcessId` yang sama dan `Path` `upd.ps1`. Teks `ScriptBlockText` dari 4104 PID 12408 diekspor dan dibandingkan per baris (`diff`) dengan E03 serta dengan salinan dari file cache: sama. Isi blok skrip yang sama juga cocok dengan loader yang tercatat di laptop Rizky (Day 03 bagian 2.5).
- `$J` E15-W1 tidak punya record perubahan `upd.ps1` setelah `FileCreate` Senin 16:05:19 (Day 08 bagian 2.4), sehingga isi yang dijalankan Selasa 12:51 adalah isi yang ditulis Senin sore.

**Variasi:** untuk host tanpa Sysmon (seperti `JKT-WS-0412` dan `BDG-WS-0142`), jendela panjang untuk akses LSASS tidak tersedia dari event log; satu-satunya sumber adalah telemetry EDR (bila ada) dan image memori, dan kalimat kesimpulannya harus lebih sempit.

**Kapan gagal:** konfigurasi Sysmon mengecualikan proses sumber tertentu dari EID 10 (misalnya alat keamanan), sehingga "nol EID 10 dari proses X" hanya berlaku untuk proses yang tidak dikecualikan. Baca konfigurasi Sysmon host itu sebelum menulis angka nol.

### 2.10 Jawaban tertulis untuk Sari dan Agus

Jawaban dikirim ke Sari pukul 13:30, disimpan sebagai `\\jkt-evid01\cases\INC-2026-019\notes\memori-E01-proses-2026-10-30.md`. Tabel berikut adalah isinya; kolom "Batas" wajib dibaca bersama kolom "Jawaban".

| Pertanyaan | Jawaban | Dasar | Keyakinan | Batas |
|---|---|---|---|---|
| Kode disuntikkan ke proses lain? | Tidak ditemukan | malfind: 5 region di `powershell.exe` 12408 dan `MsMpEng.exe`, dijelaskan JIT CLR dan Defender, sama dengan pembanding lab; nol region di LSASS, Explorer, svchost, Outlook, Excel; nol handle dengan hak tulis memori atau buat thread ke proses lain; Sysmon EID 8 nol | Tinggi untuk 12:42-12:52 Selasa; sedang-tinggi untuk Senin 16:05 sampai Kamis 08:47 (Sysmon) | Kode yang ditulis ke region non-executable lalu diubah proteksinya, atau ke dalam image DLL, tidak terlihat malfind |
| Proses di-hollow atau menyamar? | Tidak ditemukan | hollowprocesses nihil; pebmasquerade konsisten; ldrmodules tanpa DLL yang dilepas; PID, induk, path proses sistem wajar; Sysmon EID 25 nol | Tinggi untuk proses yang hidup saat akuisisi | Proses yang sudah berakhir (11872) tidak bisa dinilai dari memori; varian hollowing yang menjaga PEB konsisten |
| Proses disembunyikan? | Tidak ditemukan | psxview: satu selisih (11872, sudah berakhir, `Exit Time` 12:36:44); `Sysmon64.exe` dan WinPmem tidak tampil karena filter nama plugin, ada di `pslist` | Tinggi | Penyembunyian yang menghapus proses dari keempat sumber |
| Apa yang dimuat dan dipegang PowerShell? | Hanya modul Windows dan .NET Framework, `amsi.dll`; token Medium `andi.pratama` tanpa `SeDebugPrivilege`; handle proses hanya ke konsolnya | dlllist, ldrmodules, getsids, privileges, handles | Tinggi | Hanya 12408; 82 eksekusi task sebelumnya sudah berakhir |
| Akses ke LSASS? | Tidak ditemukan | Handle ke LSASS hanya dari `wininit`, `services`, Defender, dan sensor EDR; hanya induk yang punya hak baca memori; 37 EID 10 Sysmon semua dari `svchost.exe`; LSA protection aktif (WinInit 12) | Tinggi untuk saat akuisisi; sedang-tinggi untuk seluruh jendela Sysmon | Handle yang sudah ditutup sebelum akuisisi; proses yang dikecualikan konfigurasi Sysmon |
| Isi skrip di memori sama dengan E03? | Ya, identik | File cache (dua salinan) dipotong ke 4.812 byte, SHA-256 `6f1c...` sama dengan E03; teks 4104 PID 12408 sama dengan E03; string E03 ada di memori 12408; `$J` tanpa perubahan setelah dibuat | Tinggi | Bukti ini untuk `upd.ps1` di disk dan eksekusi 12:51; kode yang diunduh loader dari C2 saat berjalan tidak termasuk |

Kalimat untuk Agus, yang disepakati dengan Sari sebelum dikirim:

"Pemeriksaan memori laptop Andi yang diambil Selasa 13 Oktober pukul 12:42 sampai 12:52 tidak menemukan kode yang disisipkan ke proses lain, proses yang dipalsukan atau disembunyikan, atau proses yang membuka LSASS untuk membaca kredensial; log Sysmon laptop itu dari Senin sore sampai Kamis pagi juga tidak mencatat percobaan membuka LSASS dari proses penyerang. Artinya untuk kredensial Andi: penyerang tidak terlihat mencuri hash atau tiket login Andi, dan Credential Guard di laptop itu memang menyimpan keduanya di luar jangkauan proses biasa, tetapi selama laptop belum diisolasi penyerang bisa bertindak sebagai Andi karena berjalan di sesi Andi, sehingga reset password Andi dan pencabutan sesinya tetap diperlukan dan perlu dipastikan tercatat di catatan containment. Credential Guard tidak melindungi password `svc_billing` karena password itu tersimpan sebagai teks di skrip, dan tidak melindungi akun lokal; akun lokal tim IR yang dipakai Selasa siang sudah diganti password-nya setelah dipakai, dan image memori itu sendiri diperlakukan sebagai bukti sensitif karena memuat memori LSASS."

**Cara membaca hasil:** setiap baris jawaban punya pasangan di keluaran plugin atau event log yang bisa diulang retainer dengan versi alat yang sama. Kata "tidak ditemukan" selalu disertai jendela waktunya. Kalimat untuk Agus memisahkan tiga hal yang sering tercampur di rapat: pencurian kredensial dari LSASS (tidak terlihat), pemakaian akses Andi oleh penyerang di sesinya (mungkin, dan ditangani dengan reset), dan kredensial yang tidak pernah dilindungi Credential Guard (`svc_billing`, akun lokal).

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** `LAB-WS01` (`172.16.50.10`, Windows 11 23H2, Defender aktif, Sysmon dengan EID 8, EID 25, dan EID 10 untuk target `lsass.exe`, snapshot bersih), `LAB-DFIR01` (`172.16.50.20`, Volatility 3 2.28.2 di virtualenv, symbol pack offline), disk virtual `LAB-USB` berisi WinPmem mini dan Process Explorer dari Sysinternals, jaringan host-only `172.16.50.0/24`. Folder kasus lab `CASE-2026-LAB-015`. Semua aktivitas jinak; tidak ada sampel liar. Bila memakai test Atomic Red Team (pustaka test yang dipetakan ke teknik MITRE ATT&CK [S34]), rujuk test lewat ID teknik dan GUID-nya, baca isinya dan langkah cleanup-nya dulu, dan jalankan hanya di snapshot.

1. **Siapkan proses dan file yang diketahui.** Di `LAB-WS01`, buat `C:\LabCache\uji15.ps1` berisi skrip jinak yang menulis tanggal ke `C:\LabCache\log15.txt` setiap 10 detik selama 10 menit, dan beri skrip itu dua nama fungsi yang unik (misalnya `Tulis-LabWaktu15`). Buat `C:\LabCache\catatan-lab15.txt` berukuran tepat 5.000 byte (teks ASCII) lalu baca isinya sekali dengan `Get-Content`. Catat SHA-256 dan ukuran kedua file.
2. **Jalankan proses pembanding.** Jalankan `powershell.exe -NoProfile -WindowStyle Hidden -File C:\LabCache\uji15.ps1` sebagai pengguna lab biasa, dan `notepad.exe` sebagai proses tanpa JIT. Sebagai admin, buka Process Explorer (`procexp64.exe`) supaya ada proses yang memegang handle ke `lsass.exe`. Catat PID ketiganya dan waktunya.
3. **Ambil memori dua cara.** (a) Live dengan WinPmem dari `LAB-USB` sebagai admin, catat waktu mulai dan selesai; (b) dari file memori snapshot VM saat VM dijeda (tanpa smear). Hash keduanya.
4. **malfind.** Jalankan `windows.malware.malfind` di kedua image (bagian 2.2). Catat jumlah region per proses untuk `powershell.exe`, `MsMpEng.exe`, dan `notepad.exe`. Dump region `powershell.exe`, periksa header PE dan letaknya terhadap `clr.dll` dengan `vadinfo` (bagian 2.3).
5. **Hollowing dan penyamaran.** Jalankan `hollowprocesses`, `pebmasquerade --pid` untuk PowerShell dan `lsass.exe`, dan `ldrmodules --pid` untuk PowerShell (bagian 2.4). Catat proses yang dilewati `hollowprocesses` dengan memeriksa jumlah DLL dan VAD-nya.
6. **psxview.** Jalankan psxview (bagian 2.5). Buktikan bahwa `Sysmon64.exe`, `procexp64.exe`, dan WinPmem tidak tampil karena filter nama, dengan membandingkan ke `pslist`. Akhiri satu proses sebelum akuisisi berikutnya dan lihat polanya (`False` di `pslist`, `Exit Time` terisi).
7. **Konteks dan LSASS.** Untuk PowerShell, jalankan `cmdline`, `getsids`, `privileges`, `dlllist`, `handles` (bagian 2.6). Lalu saring semua handle ke `lsass.exe` (bagian 2.7): catat `GrantedAccess` milik Process Explorer, terjemahkan bitnya, dan cocokkan dengan Sysmon EID 10 di `LAB-WS01`. Periksa WinInit 12 di log System lab untuk status LSA protection, dan amati bedanya hak yang diberikan ke Process Explorer saat LSA protection aktif dan tidak.
8. **Pulihkan file dari cache.** `filescan` untuk `catatan-lab15.txt`, lalu `dumpfiles --virtaddr` (bagian 2.8). Catat ukuran `.dat` dan `.vacb`, periksa byte setelah 5.000 dan 904 byte data di halaman kedua (5.000 dikurangi 4.096), potong ke 5.000 byte, dan bandingkan hash dengan langkah 1.
9. **Teks skrip di memori proses.** Buat rule YARA dari dua nama fungsi di `uji15.ps1` dengan `ascii wide`, jalankan `windows.vadyarascan` tanpa `--pid` (bagian 2.8). Catat proses mana yang memuat string itu; apakah `MsMpEng.exe` ikut muncul?
10. **Kesimpulan.** Tulis tabel seperti bagian 2.10 untuk kasus lab, lengkap dengan kolom keyakinan, batas waktu (jendela akuisisi live) dan batas teknik per plugin.

**Hasil yang sebaiknya tersimpan:**

- Jumlah region malfind per proses di image live dan image snapshot, dengan penjelasan kenapa region PowerShell dan Defender bukan injeksi.
- Daftar proses yang dilewati `hollowprocesses` dan proses yang tidak tampil di psxview, dengan alasannya.
- Tabel handle ke `lsass.exe` dengan terjemahan bit `GrantedAccess`, dan pasangan Sysmon EID 10-nya.
- Hash `catatan-lab15.txt` asli, hash `.dat` dan `.vacb` mentah, dan hash setelah dipotong (yang harus sama dengan asli).
- Hasil `vadyarascan` untuk string skrip lab.
- Satu tabel kesimpulan dengan batas waktu dan batas teknik.

**Variasi tantangan:** ulangi langkah 2 dan 4 dengan PowerShell 7 (`pwsh.exe`) bila terpasang di VM, lalu bandingkan jumlah dan proteksi region malfind dengan `powershell.exe` 5.1. Tulis apakah pengamatanmu sejalan dengan klaim bahwa .NET 7 ke atas memakai W^X untuk JIT (bagian 1.1), dan simpan hasilnya sebagai pembanding untuk kasus berikutnya. Variasi kedua: buat file 300.000 byte, baca sekali, lalu pulihkan dari cache dan hitung berapa view `.vacb` 262.144 byte yang muncul dan halaman mana yang hilang.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat menganalisis proses di memori. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Plugin malware tidak ditemukan | Nama di subpaket `windows.malware.*`, atau versi lama sebelum pemindahan | `vol -h` untuk daftar plugin; pakai `windows.malware.malfind` dan sejenisnya [S1][S5] |
| Peringatan deprecation saat menjalankan `windows.malfind` | Nama lama adalah alias usang | Ganti ke nama di `windows.malware.*` di skrip dan case notes [S8] |
| malfind penuh region RWX | JIT sah (.NET, browser) atau antivirus | Bedakan dengan konteks, header PE, letak terhadap `clr.dll`, pembanding lab (bagian 2.3) |
| psxview tidak menampilkan proses yang ada di `pslist` | Filter nama plugin membuang nama berisi angka atau garis bawah | Bandingkan dengan `pslist` dan `psscan`; jangan disimpulkan disembunyikan (bagian 1.3) |
| psxview menandai banyak proses `False` di `pslist` | Proses sudah berakhir | Lihat kolom `Exit Time`; cocokkan dengan event log |
| hollowprocesses kosong untuk proses yang dicurigai | Proses dilewati prasyarat (kurang dari 3 DLL atau 5 VAD), sudah berakhir, atau PEB tidak terbaca | Cek `dlllist` dan `vadinfo` proses itu; catat sebagai "tidak bisa dinilai" (bagian 1.2) |
| Hash file hasil `dumpfiles` tidak sama dengan file asli | Keluaran dibulatkan ke halaman (4.096) atau view (262.144) dan diisi nol | Potong ke ukuran dari `$MFT` atau salinan disk, cek halaman yang hilang, baru hash (bagian 1.6) |
| `dumpfiles --filter` ditolak | Digabung dengan `--virtaddr` atau `--physaddr` | Pakai salah satu jenis opsi [S15] |
| `dumpfiles --pid` tidak menemukan file skrip | Proses sudah menutup handle ke file | Cari objek file dengan `filescan`, lalu `--virtaddr` |
| `vadyarascan` gagal dimuat | yara-x atau yara-python 3.8+ tidak terpasang di virtualenv | Pasang modul yang sesuai di virtualenv kasus dan catat versinya [S19] |
| `vadyarascan` tidak menemukan teks yang pasti ada | String disimpan UTF-16 oleh .NET | Tambahkan modifier `wide` di rule atau `--wide` untuk `--yara-string` |
| Handle ke LSASS dari proses yang tidak dikenal | Alat pemantau sah, atau temuan | Terjemahkan `GrantedAccess`; cari bit `PROCESS_VM_READ`; cocokkan dengan Sysmon EID 10 dan daftar software terpasang |
| Hasil aneh, kolom kosong, atau plugin crash | Smear image live | Ulangi pada image tanpa smear bila ada (snapshot VM); catat sebagai batas (Day 14 bagian 1.2) |

## 5. Kesalahan umum dan jebakan

- **Menganggap region RWX sama dengan injeksi.** JIT sah (.NET, browser) dan antivirus menghasilkan RWX; butuh konteks, isi, dan pembanding.
- **Membaca label `Notes` malfind sebagai penilaian.** Label hanya dari dua byte pertama; "Function prologue" bukan tanda jahat dan "N/A" bukan tanda bersih.
- **Menyimpulkan penyembunyian dari psxview saja.** Proses yang sudah berakhir dan proses yang namanya dibuang filter juga tidak konsisten antar sumber.
- **Menulis "hollowprocesses bersih" tanpa menyebut proses yang dilewati.** Prasyarat plugin melewati proses yang sudah berakhir dan proses dengan sedikit DLL atau VAD.
- **Menyamakan "tidak ada handle ke LSASS" dengan "LSASS tidak pernah diakses".** Handle yang sudah ditutup dan akses dari kernel tidak terlihat; pakai Sysmon EID 10 untuk jendela panjang.
- **Menyamakan "LSASS tidak diakses" dengan "kredensial aman".** Credential Guard tidak melindungi password di skrip, akun lokal, service ticket, kredensial NTLM yang diketik, dan tidak mencegah penyerang memakai sesi yang sudah login [S22].
- **Membandingkan hash dump file mentah dengan file asli.** Potong ke ukuran asli dulu; bila ada halaman hilang, bandingkan per halaman.
- **Mengabaikan korelasi disk.** Temuan memori menguat dengan Sysmon, 4104, Prefetch, dan `$J` (Day 05, 07, 08).
- **Menjalankan dump.** Dump region dan file adalah data; jangan dieksekusi. Analisis perilaku hanya di sandbox terisolasi.
- **Memakai nama plugin lama.** Volatility 3 2.26.2 ke atas memindahkan malfind, psxview, hollowprocesses, dan ldrmodules ke `windows.malware.*` [S1][S5].
- **Lupa bahwa image memori itu sendiri sensitif.** E01 memuat memori LSASS, termasuk kemungkinan materi kredensial akun lokal responder; aksesnya dibatasi seperti E03.
- `[komunitas, belum terkonfirmasi]` malfind adalah titik awal umum untuk injeksi tetapi false positive-nya tinggi (JIT, antivirus); praktisi selalu mengonfirmasi dengan konteks dan korelasi disk [S32].

## 6. Catatan terkini

Bagian ini menampung detail versi dan sumber yang bisa berubah; tidak mengubah alur analisis di atas.

- **Volatility 3 2.28.2** (17 September 2026) masih rilis terbaru per 2026-10-22, sama dengan versi yang dibekukan untuk `INC-2026-019` di `jkt-dfir02`, sehingga tidak ada keputusan upgrade yang perlu diambil [S5]. Catatan rilis 2.28.2 menyebut perubahan renderer dan kemampuan dump di `linux.malfind`, bukan perubahan plugin malware Windows.
- **Lokasi plugin.** Rilis 2.26.2 memindahkan plugin terkait malware ke kategori `windows.malware` dan menandai nama lama usang, dengan rencana penghapusan sekitar satu tahun [S5]. Di 2.28.2 subpaket itu berisi `malfind`, `hollowprocesses`, `psxview`, `ldrmodules`, `pebmasquerade`, `processghosting`, `suspicious_threads`, `svcdiff`, `drivermodule`, `skeleton_key_check`, dan beberapa plugin system call [S6]. Nama lama seperti `windows.malfind` dan `windows.psxview` masih ada sebagai alias usang dengan `removal_date` 2026-06-07 di source, tetapi tetap ikut di rilis 2.28.2 [S8]; jangan mengandalkannya di skrip baru.
- **`windows.malware.processghosting`** dan Sysmon EID 25 menyasar varian penggantian image yang tidak tertangkap kriteria hollowing klasik; keduanya disebut sebagai pemeriksaan tambahan, belum dipakai di kasus ini [S6][S25].
- **Plugin PTE pihak ketiga** (`PteMalfind` dan kawan-kawan, 2021) menutup sebagian batas malfind dengan membaca page table; plugin ini bukan bagian Volatility 3 bawaan dan perlu diuji di lab sebelum dipakai di kasus [S30].
- **Credential Guard** aktif bawaan di Windows 11 22H2 ke atas dan Windows Server 2025 pada perangkat tergabung domain yang memenuhi syarat dan lisensi, tanpa UEFI lock [S21]. Halaman MITRE T1003.001 masih menulis Credential Guard "tidak aktif bawaan"; untuk Windows modern, halaman Microsoft yang dipakai [S29][S21].
- **LSA protection** aktif bawaan pada instalasi baru Windows 11 22H2 ke atas yang tergabung ke domain atau Entra dan mampu HVCI; mode audit aktif bawaan di 22H2 ke atas, dan event CodeIntegrity 3065/3066 (audit) serta 3033/3063 (enforce) mencatat plugin yang gagal dimuat [S23].
- **Sysmon** (publikasi 2026-09-10) mencatat EID 8 CreateRemoteThread, EID 10 ProcessAccess, dan EID 25 ProcessTampering; EID 10 disarankan dengan filter karena volumenya besar [S25].
- **PowerShell dan .NET.** Windows PowerShell 5.1 dibangun di atas .NET Framework; PowerShell 7.4 di .NET 8, 7.5 di .NET 9, 7.6 di .NET 10 [S27]. Perbedaan runtime ini bisa mengubah pola memori JIT (bagian 1.1).

## 7. Cheat sheet

```
SIAPKAN    sha256sum salinan lokal vs .sha256 master ; IMG=/data/... ; OUT=.../vol3-2.28.2/day15 ; vol -q -r csv
INJEKSI    windows.malware.malfind [--pid] [--dump]
           kriteria: VAD EXECUTE+WRITE, atau EXECUTE + halaman dirty ; privat VadS atau non-image ; tidak kosong
           Notes = 2 byte pertama saja (MZ header / Function prologue) ; FP: JIT .NET, antivirus
           nilai: vadinfo (tetangga, clr.dll) + dump + strings/YARA + pembanding lab
           lolos: proteksi diubah setelah alokasi, kode di image DLL, region paged out
HOLLOWING  windows.malware.hollowprocesses -> PEB ImageBase vs SectionBase ; VAD exe = EXECUTE_WRITECOPY ; DLL VAD
           dilewati: <3 DLL, <5 VAD, proses berakhir -> sebut "tidak bisa dinilai"
MENYAMAR   PPID/path/instance (Day 14) | windows.malware.pebmasquerade --pid | windows.malware.ldrmodules --pid
           ldrmodules: exe utama InInit=False itu normal
TERSEMBUNYI windows.malware.psxview -> pslist | psscan | thrdscan | csrss | Exit Time
           False di pslist + Exit Time = sudah berakhir ; nama berisi angka/_ dibuang filter -> cek pslist
KONTEKS    windows.cmdline | windows.getsids (Medium/High) | windows.privileges (SeDebugPrivilege)
           windows.dlllist (path, LoadTime) | windows.handles --pid (Process/File/Key)
LSASS      windows.handles | grep 'lsass.exe Pid <pid>' ; cek bit 0x0010 VM_READ, 0x0020/0x0008/0x0002
           0x1000 QUERY_LIMITED ; 0x101000 +SYNCHRONIZE ; 0x1FFFFF ALL_ACCESS (induk pembuat)
           LSA PPL: WinInit 12 di System ; Credential Guard: LsaIso.exe (NTLM hash + TGT di luar lsass)
           CG TIDAK melindungi: akun lokal, password di skrip, service ticket, kredensial NTLM yang diketik, sesi aktif
           WinPmem baca memori fisik lewat driver -> tanpa handle ke lsass
FILE       windows.filescan | grep -> windows.dumpfiles --virtaddr <off> -> .dat (x4096) .vacb (x262144) .img
           cek nol setelah ukuran asli + halaman data terisi -> head -c <ukuran> -> sha256 vs bukti disk
           halaman hilang -> bandingkan per halaman / diff teks, tulis "tidak tersedia", bukan "berbeda"
SKRIP      windows.vadyarascan [--pid] --yara-file rule (ascii wide) ; 4104 ProcessId ; $J tanpa perubahan
JENDELA    E01 = detik akuisisi (smear) ; jendela panjang = Sysmon 8/10/25, 4104, TaskScheduler, EDR
PRINSIP    plugin = SINYAL/kandidat ; kesimpulan = sinyal saling mengunci + disk + batas waktu + batas teknik
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "malfind menemukan tiga region `PAGE_EXECUTE_READWRITE` di `powershell.exe` 12408, satu di antaranya bertanda 'Function prologue'. Jadi ada kode yang disuntikkan ke proses PowerShell." Benarkah?

<details><summary>Jawaban</summary>

Tidak. `powershell.exe` adalah Windows PowerShell 5.1 di atas .NET Framework, dan runtime CLR mengompilasi kode JIT ke memori privat yang executable, sehingga region seperti ini memenuhi kriteria malfind tanpa injeksi. Label "Function prologue" hanya berasal dari dua byte pertama region. Region di E01 berada di blok heap loader CLR dekat `clrjit.dll` dan `clr.dll`, tanpa header PE di dalamnya, dan pola yang sama muncul pada PowerShell dengan skrip jinak di VM lab. Kesimpulan injeksi butuh sinyal lain yang saling mengunci. Lihat bagian 1.1 dan 2.3.

</details>

**2. Skenario keputusan.** Keluaran psxview E01 tidak memuat `Sysmon64.exe` (PID 3312), padahal `pslist` Kamis menampilkannya. Langkah mana yang paling tepat?

- A. Laporkan bahwa Sysmon disembunyikan rootkit, karena psxview dirancang menemukan proses tersembunyi.
- B. Cek source dan keluaran pembanding: psxview 2.28.2 membuang proses yang namanya berisi angka atau garis bawah, jadi status Sysmon dinilai dari `pslist`, `psscan`, dan thread secara terpisah.
- C. Simpulkan Sysmon sudah berhenti sebelum akuisisi, sehingga event Sysmon setelah itu tidak bisa dipercaya.

<details><summary>Jawaban</summary>

B. Filter nama di psxview 2.28.2 hanya menerima huruf ASCII, titik, dan spasi, sehingga `Sysmon64.exe` dan `winpmem_mini_x64.exe` tidak tampil sama sekali. A keliru karena ketiadaan di keluaran psxview bukan pola penyembunyian; penyembunyian terlihat sebagai `False` di `pslist` tetapi `True` di sumber lain. C keliru karena `pslist` menunjukkan proses itu hidup, dan event Sysmon di E15 berlanjut sampai Kamis. Lihat bagian 1.3 dan 2.5.

</details>

**3. Pertanyaan jebakan.** "Retainer tidak menemukan akses ke LSASS di E01, dan laptop Andi memakai Credential Guard. Jadi tidak ada kredensial yang perlu dikhawatirkan dari laptop ini." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Kalimat retainer hanya berlaku untuk jendela 12:42 sampai 12:52 Selasa dan untuk handle yang masih terbuka saat itu; jendela lebih panjang datang dari Sysmon EID 10. Credential Guard melindungi hash NTLM dan TGT Andi, tetapi tidak melindungi password `svc_billing` yang tersimpan sebagai teks di `export-tagihan.ps1`, tidak melindungi akun lokal seperti `ir-admin`, tidak melindungi service ticket, dan tidak mencegah penyerang memakai akses Andi selama berjalan di sesinya. Karena itu reset password Andi, rotasi `svc_billing`, dan penggantian password `ir-admin` tetap diperlukan. Lihat bagian 1.5 dan 2.10.

</details>

**4. Skenario keputusan.** `windows.dumpfiles` menghasilkan `upd.ps1` versi `.dat` 8.192 byte, dan SHA-256-nya tidak sama dengan `upd.ps1` di E03 (4.812 byte). Rekan setim ingin menulis "isi skrip di memori berbeda dengan E03". Respons mana yang paling tepat?

- A. Setuju, karena hash berbeda berarti isi berbeda.
- B. Potong keluaran ke 4.812 byte (ukuran dari `$MFT` dan E03), periksa bahwa sisa setelahnya hanya nol dan 716 byte di halaman kedua terisi, lalu hash ulang; bila halaman kedua hilang, bandingkan 4.096 byte pertama dan tulis sisanya "tidak tersedia di memori".
- C. Abaikan `.dat` dan pakai `.vacb` saja karena lebih besar dan pasti lengkap.

<details><summary>Jawaban</summary>

B. `dumpfiles` menulis per halaman 4.096 byte untuk `DataSectionObject` dan per view 262.144 byte untuk `SharedCacheMap`, tanpa memotong ke ukuran file, dan halaman yang tidak tersedia diisi nol; hash mentahnya tidak pernah sama dengan file asli. A keliru karena memperlakukan padding sebagai perbedaan isi. C keliru karena `.vacb` juga dibulatkan (262.144 byte) dan sama-sama harus dipotong; "lebih besar" tidak berarti lebih lengkap. Lihat bagian 1.6 dan 2.8.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Agus Setiawan (DPO), dalam tiga kalimat, apa arti "tidak menemukan akses ke LSASS" dan apa batasnya.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Artinya, di memori laptop Andi yang diambil Selasa 12:42 sampai 12:52 tidak ada proses penyerang yang memegang akses untuk membaca memori LSASS, tempat Windows menyimpan materi login, dan log Sysmon dari Senin sore sampai Kamis pagi juga tidak mencatat percobaan itu. Batasnya: pemeriksaan memori hanya melihat detik saat diambil, dan perlindungan Credential Guard di laptop itu tidak berlaku untuk password `svc_billing` yang tersimpan di skrip, akun lokal, dan pemakaian akses Andi oleh penyerang yang berjalan di sesi Andi. Jadi kesimpulannya 'tidak terlihat ada pencurian dari LSASS', bukan 'semua kredensial aman', dan reset serta rotasi kredensial yang sudah direncanakan tetap jalan."

Kesalahan yang sering muncul:
- Menulis "LSASS tidak pernah diakses" tanpa jendela waktu.
- Menganggap Credential Guard melindungi semua password, termasuk yang ada di file.
- Tidak menyebut bahwa penyerang bisa memakai sesi Andi tanpa mencuri kredensial.

</details>

**6. Pertanyaan jebakan.** "`windows.malware.hollowprocesses` tidak mengeluarkan satu baris pun untuk E01, jadi semua proses sudah diperiksa dan tidak ada yang di-hollow, termasuk PowerShell 11872." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Plugin melewati proses yang daftar modul loader-nya berisi kurang dari tiga DLL atau yang punya kurang dari lima VAD, dan proses yang sudah berakhir seperti 11872 tidak punya ruang alamat yang bisa diperiksa. Plugin juga hanya memeriksa tiga ketidakcocokan (PEB vs alamat image, proteksi VAD image, proteksi VAD DLL), sehingga varian yang menjaga semuanya konsisten bisa lolos. Kalimat yang benar: tidak ada temuan untuk proses yang hidup dan memenuhi prasyarat; 11872 tidak bisa dinilai dari memori, dan jendela panjang dinilai dari Sysmon EID 25. Lihat bagian 1.2, 1.7, dan 2.4.

</details>

**7. Interview question (English).** "You have a memory image from a workstation where a malicious PowerShell scheduled task was running. How would you determine whether code was injected into other processes or whether LSASS was accessed, and how would you avoid false positives?"

<details><summary>Sample answer</summary>

"I start from the process list and the timing of the acquisition, because the image only shows what existed during those minutes. For injection, I run malfind across all processes, then triage every hit with context: where the region sits relative to clr.dll or other runtimes, whether there's a full PE header inside it, the parent, command line, and token of the owning process, and a baseline from the same Windows build running a benign PowerShell script, since the .NET JIT and antivirus engines routinely produce executable private memory. I check hollowing and masquerading with hollowprocesses, pebmasquerade, and ldrmodules, and hidden processes with psxview, while knowing their blind spots, for example processes that already exited or names the plugin filters out. For LSASS, I list every handle to lsass.exe and decode the granted access, looking for PROCESS_VM_READ from anything other than its parent, and I check the token of the suspicious process for SeDebugPrivilege. Because handles closed before acquisition are invisible, I extend the window with Sysmon event 10, 8, and 25 from disk. Finally, I state the conclusion with its time window and technique limits, and I separate LSASS access from credential exposure in general, since Credential Guard doesn't cover local accounts, passwords in scripts, or an attacker acting inside the user's session."

What makes this answer strong: it treats each plugin as a candidate generator, names concrete triage steps and a baseline instead of trusting a single flag, decodes access rights rather than just listing handles, extends the time window with disk telemetry, and ends with a scoped conclusion that distinguishes LSASS access from broader credential risk.

</details>

## 9. Sumber

| # | Judul | URL | Tipe | Tanggal / diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Volatility 3 Windows plugins (windows.malware.*) | https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.html | primer | diakses 2026-10-09 (Day 14), diperiksa ulang 2026-10-22 | Tinggi. Subpaket `malware` dan `registry`; malfind, psxview, hollowprocesses ada di `malware` |
| S2 | Volatility 3 documentation (malfind, psxview, hollowprocesses) | https://volatility3.readthedocs.io/ | primer | diakses 2026-10-09 | Tinggi; kriteria persis dibaca dari source plugin [S7][S9][S12] |
| S3 | Endpoint-Forensics Day 14 (akuisisi, pslist/psscan, cmdline) | (lokal) | rujukan internal | 2026-10-09 | Fondasi memori |
| S4 | Endpoint-Forensics Day 05, 07, 08, 11 (korelasi disk) | (lokal) | rujukan internal | 2026-10-09 | Korelasi memori-disk |
| S5 | GitHub: volatilityfoundation/volatility3 Releases | https://github.com/volatilityfoundation/volatility3/releases | primer | 2.28.2 rilis 17 Sep 2026; diakses 2026-10-22 | Tinggi. 2.28.2 terbaru; 2.26.2 memindahkan plugin malware ke kategori `windows.malware` dan menandai nama lama usang (dihapus sekitar setahun kemudian); hollowprocesses dan psxview baru di 2.8.0 |
| S6 | Volatility 3: volatility3.plugins.windows.malware package | https://volatility3.readthedocs.io/en/latest/volatility3.plugins.windows.malware.html | primer | diakses 2026-10-22 | Tinggi. Daftar 13 modul di subpaket malware (malfind, hollowprocesses, psxview, ldrmodules, pebmasquerade, processghosting, dan lainnya) |
| S7 | Source `windows/malware/malfind.py` (tag v2.28.2) | https://raw.githubusercontent.com/volatilityfoundation/volatility3/v2.28.2/volatility3/framework/plugins/windows/malware/malfind.py | primer (source) | diakses 2026-10-22 | Tinggi. Versi plugin 1.1.0; opsi `pid`, `dump`; kriteria EXECUTE+WRITE, halaman dirty, `VadS`, `PAGE_EXECUTE_WRITECOPY`, region kosong dilewati; kolom output; label `Notes` dari dua byte pertama |
| S8 | Source alias usang `windows/malfind.py` dan `windows/psxview.py` (tag v2.28.2) | https://raw.githubusercontent.com/volatilityfoundation/volatility3/v2.28.2/volatility3/framework/plugins/windows/malfind.py | primer (source) | diakses 2026-10-22 | Tinggi. `PluginRenameClass`, pengganti di `windows.malware`, `removal_date` 2026-06-07; alias psxview sama |
| S9 | Source `windows/malware/hollowprocesses.py` | https://raw.githubusercontent.com/volatilityfoundation/volatility3/develop/volatility3/framework/plugins/windows/malware/hollowprocesses.py | primer (source) | cabang develop; diakses 2026-10-22 | Tinggi untuk cabang develop. Tiga pemeriksaan; prasyarat minimal 3 DLL dan 5 VAD; kolom `PID`, `Process`, `Notes`; versi plugin 1.0.0 |
| S10 | Source `windows/malware/pebmasquerade.py` (tag v2.28.2) | https://raw.githubusercontent.com/volatilityfoundation/volatility3/v2.28.2/volatility3/framework/plugins/windows/malware/pebmasquerade.py | primer (source) | diakses 2026-10-22 | Tinggi. Kolom nama EPROCESS, SeAudit, path PEB, bendera panjang string; perbandingan nama tidak otomatis |
| S11 | Source `windows/malware/ldrmodules.py` (tag v2.28.2) | https://raw.githubusercontent.com/volatilityfoundation/volatility3/v2.28.2/volatility3/framework/plugins/windows/malware/ldrmodules.py | primer (source) | diakses 2026-10-22 | Tinggi. VAD ber-MZ vs `InLoad`, `InInit`, `InMem`; kolom `MappedPath` |
| S12 | Source `windows/malware/psxview.py` (tag v2.28.2) | https://raw.githubusercontent.com/volatilityfoundation/volatility3/v2.28.2/volatility3/framework/plugins/windows/malware/psxview.py | primer (source) | diakses 2026-10-22 | Tinggi. Sumber `pslist`, `psscan`, `thrdscan`, `csrss`; kolom `Exit Time`; filter nama hanya huruf ASCII, titik, spasi; opsi `physical-offsets`; versi plugin 1.0.0 |
| S13 | Source `windows/dlllist.py` (tag v2.28.2) | https://raw.githubusercontent.com/volatilityfoundation/volatility3/v2.28.2/volatility3/framework/plugins/windows/dlllist.py | primer (source) | diakses 2026-10-22 | Tinggi. Kolom `Base`, `Size`, `Name`, `Path`, `LoadCount`, `LoadTime`, `File output`; opsi `pid`, `dump` |
| S14 | Source `windows/handles.py` (tag v2.28.2) | https://raw.githubusercontent.com/volatilityfoundation/volatility3/v2.28.2/volatility3/framework/plugins/windows/handles.py | primer (source) | diakses 2026-10-22 | Tinggi. Kolom `HandleValue`, `Type`, `GrantedAccess`, `Name`; nama objek proses `<nama> Pid <PID>` |
| S15 | Source `windows/dumpfiles.py` (tag v2.28.2) | https://raw.githubusercontent.com/volatilityfoundation/volatility3/v2.28.2/volatility3/framework/plugins/windows/dumpfiles.py | primer (source) | diakses 2026-10-22 | Tinggi. Opsi `pid`, `virtaddr`, `physaddr`, `filter`, `ignore-case`; `.dat`, `.img`, `.vacb`; pola nama keluaran; pembacaan dengan padding |
| S16 | Source `symbols/windows/extensions/__init__.py` (CONTROL_AREA, SHARED_CACHE_MAP; tag v2.28.2) | https://raw.githubusercontent.com/volatilityfoundation/volatility3/v2.28.2/volatility3/framework/symbols/windows/extensions/__init__.py | primer (source) | diakses 2026-10-22 | Tinggi. Halaman 0x1000 untuk section, view 0x40000 untuk cache map; ukuran file tidak dipakai untuk memotong |
| S17 | Source `windows/vadinfo.py` (tag v2.28.2) | https://raw.githubusercontent.com/volatilityfoundation/volatility3/v2.28.2/volatility3/framework/plugins/windows/vadinfo.py | primer (source) | diakses 2026-10-22 | Tinggi. Pola nama dump `pid.<PID>.vad.<awal>-<akhir>.dmp`; `maxsize` bawaan 1 GB; kolom output |
| S18 | Source `windows/vadyarascan.py` (tag v2.28.2) | https://raw.githubusercontent.com/volatilityfoundation/volatility3/v2.28.2/volatility3/framework/plugins/windows/vadyarascan.py | primer (source) | diakses 2026-10-22 | Tinggi. Opsi `pid`; opsi YARA diwarisi dari yarascan; kolom output |
| S19 | Source `yarascan.py` (tag v2.28.2) | https://raw.githubusercontent.com/volatilityfoundation/volatility3/v2.28.2/volatility3/framework/plugins/yarascan.py | primer (source) | diakses 2026-10-22 | Tinggi. Opsi `yara_string`, `yara_file`, `yara_compiled_file`, `wide`, `insensitive`, `max_size`; yara-x atau yara-python 3.8+ |
| S20 | Source `windows/filescan.py` (tag v2.28.2) | https://raw.githubusercontent.com/volatilityfoundation/volatility3/v2.28.2/volatility3/framework/plugins/windows/filescan.py | primer (source) | diakses 2026-10-22 | Tinggi. Kolom `Offset` dan `Name` |
| S21 | Microsoft Learn: Credential Guard overview | https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/ | primer | ms.date 2026-04-27; diakses 2026-10-22 | Tinggi. Melindungi hash NTLM, TGT, kredensial domain aplikasi; aktif bawaan Windows 11 22H2+ dan Server 2025 pada perangkat tergabung domain yang memenuhi syarat; edisi Enterprise/Education |
| S22 | Microsoft Learn: How Credential Guard works | https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/how-it-works | primer | ms.date 2025-06-12; diakses 2026-10-22 | Tinggi. `LSAIso.exe`, RPC dari LSA; daftar yang tidak dilindungi: akun lokal, kredensial NTLM yang diketik, service ticket, software di luar fitur Windows, keylogger, pemakaian hak oleh malware |
| S23 | Microsoft Learn: Configure added LSA protection | https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection | primer | ms.date 2025-03-25; diakses 2026-10-22 | Tinggi. Mencegah proses tak terlindungi membaca memori LSA; `RunAsPPL`; aktif bawaan instalasi baru Windows 11 22H2+ tergabung domain/Entra dan mampu HVCI; WinInit 12; event CodeIntegrity |
| S24 | Microsoft Learn: Process Security and Access Rights | https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights | primer | ms.date 2025-07-14; diakses 2026-10-22 | Tinggi. Nilai hak akses proses; `SeDebugPrivilege` untuk akses penuh; handle `CreateProcess` = `PROCESS_ALL_ACCESS`; hak yang tidak diizinkan ke protected process |
| S25 | Microsoft Learn: Sysmon | https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon | primer | publikasi 2026-09-10; diakses 2026-10-22 | Tinggi. EID 8 CreateRemoteThread, EID 10 ProcessAccess (deteksi pembaca memori LSASS, perlu filter), EID 25 ProcessTampering |
| S26 | Microsoft Learn: Antimalware Scan Interface (AMSI) | https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal | primer | ms.date 2025-07-09; diakses 2026-10-22 | Tinggi. PowerShell (skrip, interaktif, evaluasi dinamis), Windows Script Host, JScript/VBScript terintegrasi AMSI |
| S27 | Microsoft Learn: Differences between Windows PowerShell 5.1 and PowerShell 7.x | https://learn.microsoft.com/en-us/powershell/scripting/whats-new/differences-from-windows-powershell | primer | ms.date 2026-02-04; diakses 2026-10-22 | Tinggi. 5.1 di atas .NET Framework; PowerShell 7.x per versi .NET |
| S28 | MITRE ATT&CK: T1055.012 Process Hollowing | https://attack.mitre.org/techniques/T1055/012/ | primer | versi 2.0, dimodifikasi 2026-09-11; diakses 2026-10-22 | Tinggi. Urutan suspended, unmap, tulis, ubah konteks thread, resume |
| S29 | MITRE ATT&CK: T1003.001 LSASS Memory | https://attack.mitre.org/techniques/T1003/001/ | primer | versi 1.5, dimodifikasi 2026-05-12; diakses 2026-10-22 | Tinggi untuk definisi teknik; pernyataan Credential Guard "tidak aktif bawaan" tertinggal dari Microsoft [S21] |
| S30 | insinuator.net (Frank Block): Release of PTE analysis plugins for Volatility 3 | https://insinuator.net/2021/12/release-of-pte-analysis-plugins-for-volatility-3/ | sekunder (praktisi) | 2021-12-31; diakses 2026-10-22 | Sedang-tinggi. Batas malfind: proteksi VAD saat alokasi, kode di VAD non-executable; PteMalfind |
| S31 | startdebugging.net (Marius Bughiu): What is the W^X flag in .NET | https://startdebugging.net/2026/09/what-is-the-w-xor-x-flag-in-dotnet-and-does-native-aot-need-it/ | komunitas (blog) | 2026-09-04; diakses 2026-10-22 | Sedang. W^X bawaan sejak .NET 7, double mapping; tidak membahas .NET Framework |
| S32 | Velociraptor Artifact Exchange: Windows.Detection.Malfind | https://docs.velociraptor.app/exchange/artifacts/pages/malfind | komunitas (exchange) | diakses 2026-10-22 | Sedang. Region executable tanpa file + YARA; catatan untuk mengharapkan false positive |
| S33 | GitHub: Velocidex/WinPmem | https://github.com/Velocidex/WinPmem | primer (repo) | diakses 2026-10-22 | Tinggi. Driver kernel dengan antarmuka baca memori fisik; mini binary memuat driver otomatis, output RAW, driver dilepas setelah akuisisi; versi rilis tidak tercantum di halaman repo |
| S34 | GitHub: redcanaryco/atomic-red-team | https://github.com/redcanaryco/atomic-red-team | primer (repo) | diakses 2026-10-22 | Tinggi. Pustaka test yang dipetakan ke MITRE ATT&CK |

**Catatan sumber:** nama plugin, opsi, kolom, dan kriteria plugin dibaca dari source tag v2.28.2 [S7][S8][S10]-[S20], kecuali `hollowprocesses` yang dibaca dari cabang develop [S9]; perilakunya perlu dicocokkan dengan `vol <plugin> -h` di instalasi kasus. Filter nama di psxview [S12] berasal dari pembacaan source, belum diuji pada image; buktikan di lab (bagian 3 langkah 6). Penanganan error `pebmasquerade` saat PEB tidak terbaca tampak tidak menghentikan iterasi di source [S10], sehingga baris setelah proses yang gagal dibaca perlu diverifikasi dengan `--pid` tunggal; ini pembacaan source, bukan perilaku yang diuji. Klaim bahwa W^X .NET 7 mengubah pola region JIT [S31] berasal dari satu blog dan tidak menyebut .NET Framework, jadi ditandai komunitas. Region malfind di proses antivirus sebagai pola yang dikenal adalah pengetahuan praktisi [S32], belum dikonfirmasi sumber primer. Halaman MITRE T1003.001 [S29] dan Microsoft [S21] berbeda soal status bawaan Credential Guard; sumber primer vendor yang dipakai. Semua isi PT JAB (alamat memori, offset objek file, nilai `GrantedAccess`, hash `6f1c...`, jumlah event Sysmon EID 10, isi konfigurasi Sysmon, pembanding lab, dan nama file catatan) adalah contoh fiktif yang disusun agar konsisten dengan fakta insiden, bukan kejadian nyata.
