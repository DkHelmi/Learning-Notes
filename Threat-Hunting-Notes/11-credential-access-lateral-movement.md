---
day: 11
title: 'Hunting credential access dan lateral movement: akses LSASS, spray lambat, tipe logon, dan eksekusi remote'
researched_on: 2026-10-18
versions_checked: 'MITRE ATT&CK v20 (T1003.001 LSASS Memory v1.5 12 Mei 2026; T1110.003 Password Spraying v1.8 24 Okt 2025; T1047 WMI v1.6 12 Mei 2026; T1021.002 SMB/Admin Shares v1.3; T1021.003 DCOM v1.3; T1021.006 WinRM v1.2; T1550 Use Alternate Auth Material v2.0; T1558.003 Kerberoasting v1.3); Microsoft Learn event 4624/4625/4648/4672/4768/4769/4771/4776 (arsip, diperbarui 2026); Sysmon v15.2 (26 Mar 2026), halaman Sysinternals diperbarui 10 Sep 2026; Microsoft Learn Process Security and Access Rights (14 Jul 2025); Configure added LSA protection (diperbarui 2026-10-12); Microsoft Entra error codes (diperbarui 2026-06-15); Atomic Red Team T1047, T1021.006, T1110.003; Splunk Enterprise 10.6 (SPL)'
---

# Day 11: Hunting credential access dan lateral movement (akses LSASS, spray lambat, tipe logon, dan eksekusi remote)

Cakupan: memburu jejak credential access (akses proses ke LSASS, password spray lambat, Kerberoasting) dan lateral movement (logon jaringan, RDP, SMB, WMI, WinRM, DCOM) di log Windows DC, Sysmon, dan EDR tanpa Defender for Identity, termasuk arti tipe logon, pola satu sumber ke banyak tujuan, logon tipe baru per akun, logon jaringan diikuti eksekusi remote, dan korelasi credential access lalu lateral movement.

## Ide inti

Credential access dan lateral movement adalah dua taktik yang membuat satu host yang dikuasai menjadi banyak host. Keduanya hampir tidak meninggalkan payload; jejaknya ada di event autentikasi dan di akses proses, bukan di file. Karena itu hunting di sini bertumpu pada dua hal: event logon Windows (siapa masuk, dari mana, dengan tipe apa) dan akses proses ke memori kredensial (siapa membuka handle ke LSASS, dengan hak akses apa). Masalahnya, administrasi yang sah terlihat sangat mirip: admin memang masuk ke banyak host, tool keamanan memang membaca LSASS, dan akun layanan memang logon jaringan ke banyak server. Yang membedakan serangan dari administrasi bukan satu event, melainkan gabungan sinyal dengan konteks: akun ini biasanya masuk tipe apa, dari host mana, dan apakah sumbernya memang host yang diizinkan. Tanpa baseline dan daftar aset serta identitas, setiap logon jaringan terlihat mencurigakan dan tidak ada yang bisa ditindaklanjuti.

Kamu sudah mengenal pola ini dari NOC. Satu workstation yang tiba-tiba membuka sesi ke puluhan router di banyak POP dalam waktu singkat adalah sinyal yang sama dengan "satu sumber ke banyak tujuan": normal hanya untuk jump host atau management station yang memang tugasnya begitu, mencurigakan dari mana pun yang lain. Kode tipe logon Windows mirip kode jenis sesi di log AAA (shell login, enable, vty, console): angkanya kecil tetapi menentukan arti. Batas analoginya ada dua. Pertama, admin dan akun layanan yang sah benar-benar meniru pola penyerang, sehingga kamu wajib punya daftar sumber dan akun yang diizinkan sebelum menyebut sesuatu aneh. Kedua, membaca memori LSASS tidak seperti membaca counter di router: banyak produk keamanan sah membacanya setiap menit, jadi yang dicari bukan "apakah ada akses" melainkan "dari proses mana dan dengan hak akses apa".

```
         CREDENTIAL ACCESS                         LATERAL MOVEMENT
   proses buka handle ke lsass.exe          logon jaringan 1 sumber -> banyak tujuan
   (Sysmon EID 10, GrantedAccess)           (4624 tipe 3/10) lalu eksekusi remote
   spray/roasting (4625/4771/4776/4769)     (WmiPrvSE/wsmprovhost/7045 service)
            |                                              |
            +--------------------- korelasi ---------------+
            akun X baca LSASS di host A, lalu akun X logon jaringan
            dari host A ke host B dan menjalankan proses di sana
                                 |
            label: insiden (IR) | pelanggaran kebijakan | jinak | data tidak cukup
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan dan data sekitar 400 ribu pelanggan broadband. SOC PT JAB memakai Splunk Enterprise dengan Enterprise Security (ES); log keamanan dua domain controller `JKT-DC01` dan `JKT-DC02` masuk `index=wineventlog`, Sysmon terpasang di server Windows dan di workstation OU `Workstations-EDR` (sekitar 40% workstation, 214 host ber-Sysmon) ke `index=sysmon`, dan Microsoft Defender for Endpoint (MDE) berjalan di server serta workstation Jakarta dan Bandung. PT JAB memakai lisensi Microsoft 365 E3, sehingga tidak punya Microsoft Defender for Identity: deteksi serangan Active Directory bertumpu pada event log DC di Splunk dan EDR di endpoint, bukan pada mesin analitik identitas. Akun admin setiap analyst dan engineer berpola `adm.<nama>`, dan kebijakan internal menyatakan akun admin hanya boleh dipakai masuk ke server dari jump host `JKT-JUMP01` (`10.10.1.10`). Sejak 1 Februari 2027 kamu, analyst L2, memegang "Program hunt PT JAB" setiap Selasa dan Kamis. Dua insiden 2026 masih dipakai sebagai pemicu: `INC-2026-017`, ketika penyerang mengambil kredensial dari satu host lalu memakai ulang password local administrator yang sama untuk bergerak ke dua workstation Keuangan; dan `INC-2026-023`, Kerberoasting yang dijalankan dari workstation `JKT-WS-0424`. Dari hunt pertama (`HUNT-2027-001`) tersisa satu backlog: eksekusi WMI dari host selain `JKT-JUMP01`, karena pola `WmiPrvSE.exe` yang memunculkan `cmd.exe` di `JKT-WS-0517` ternyata berasal dari `JKT-JUMP01` dan jinak. Kamis 2027-03-04 pukul 08:30, SOC lead Dimas Prasetyo menulis kepadamu:

> "Minggu ini aku mau kita sentuh yang paling bikin aku tidak tidur: pencurian kredensial dan pergerakan lateral. Kita kan tidak punya Defender for Identity, cuma log DC dan EDR, apa masih bisa diburu? Rule brute force kita sudah bunyi kalau ada banyak login gagal, tapi aku curiga spray yang pelan lolos, betul tidak? Soal akses ke LSASS, aku sering dengar itu tanda dumping, tapi antivirus kita kan juga buka LSASS terus, bedanya di mana? Terus tipe logon Windows itu angka-angkanya bikin pusing, yang mana yang penting buat lateral movement? Dan yang dari dulu nyangkut: backlog `HUNT-2027-001` soal WMI dari host selain `JKT-JUMP01`, ada yang jalankan remote execution yang tidak seharusnya tidak? Terakhir, kalau nanti ketemu admin lompat-lompat antar host, dari mana aku tahu itu insiden, pelanggaran kebijakan, atau wajar?"

Pesan itu memuat enam pertanyaan:

1. Tanpa Defender for Identity, dengan log DC, Sysmon, dan EDR saja, apakah credential access dan lateral movement bisa diburu, dan datanya apa?
2. Rule brute force menangkap login gagal yang banyak; apakah spray yang pelan lolos, dan bagaimana memburunya?
3. Akses ke LSASS katanya tanda dumping, tetapi antivirus juga membukanya; apa pembedanya?
4. Tipe logon Windows yang mana yang penting untuk lateral movement?
5. Backlog `HUNT-2027-001`: adakah eksekusi WMI atau remote dari host selain `JKT-JUMP01` yang tidak seharusnya?
6. Bila menemukan admin bergerak antar host, kapan itu insiden, kapan pelanggaran kebijakan, dan kapan wajar?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 3 di bagian 1.2, pertanyaan 4 di bagian 1.3, pertanyaan 2 di bagian 1.4, pertanyaan 5 di bagian 1.5, dan pertanyaan 6 di bagian 1.6. Bagian 2 menjalankan tiga hunt (`HUNT-2027-017` akses LSASS, `HUNT-2027-018` spray lambat, `HUNT-2027-019` eksekusi remote dari host selain jump host) dari abstract sampai laporan, plus satu halaman jawaban untuk Dimas.

**Kapan relevan:** saat menyisir jejak pencurian kredensial dan pergerakan lateral yang lolos rule ambang; saat scoping memerlukan pertanyaan "siapa lagi yang diakses dari sini"; dan saat menilai apakah akun admin dipakai dengan cara yang melanggar kebijakan.
**Kapan bukan jawaban:** saat sudah ada insiden aktif dengan indikasi kuat (itu incident response, walaupun tekniknya mirip); saat data autentikasi yang dibutuhkan tidak diaudit (itu celah visibilitas, perbaiki dulu); dan saat pertanyaannya sudah dijawab rule ambang per akun yang ada.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (threat hunting, hipotesis, stacking, baseline, first-seen, prevalence, handover) tidak diulang. Tabel ini hanya memuat istilah baru di Day ini; kolom kanan memetakannya ke pengalaman NOC dan SOC.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Credential access | Taktik mencuri kredensial (password, hash, tiket) untuk dipakai lebih lanjut | Membaca basis kredensial AAA/RADIUS langsung, bukan lewat portal resmi |
| Lateral movement | Taktik berpindah dari satu host yang dikuasai ke host lain memakai kredensial yang didapat | Satu workstation yang membuka sesi ke banyak router di banyak POP |
| LSASS | Proses `lsass.exe`, Local Security Authority Subsystem Service, yang menyimpan kredensial sesi di memori | Proses yang memegang state autentikasi, seperti daemon AAA di perangkat |
| ProcessAccess (Sysmon EID 10) | Event saat satu proses membuka handle ke proses lain | Log "proses A menyentuh proses B" |
| GrantedAccess | Bitmask hak akses yang diminta saat membuka handle ke proses | Hak yang diminta saat membuka sesi ke perangkat (baca saja vs tulis) |
| Tipe logon (LogonType) | Angka di 4624/4625 yang menandai sifat sesi logon | Kode jenis sesi di log AAA (console, vty, enable) |
| Password spray | Mencoba satu atau sedikit password ke banyak akun agar tidak memicu lockout per akun | Tebakan login tipis yang disebar ke banyak akun router |
| Kerberoasting | Meminta tiket layanan (4769) untuk akun service lalu memecah password-nya offline | Mengambil hash dari banyak akun service untuk dipecah di luar |
| Admin share | Share tersembunyi `C$`, `ADMIN$`, `IPC$` yang hanya bisa diakses administrator | Akses manajemen tersembunyi yang hanya untuk admin |
| WMI | Windows Management Instrumentation, antarmuka manajemen yang bisa dipakai remote lewat DCOM atau WinRM | Protokol manajemen jarak jauh seperti NETCONF/SNMP set |
| WinRM | Windows Remote Management, layanan dan protokol eksekusi jarak jauh | Sesi manajemen jarak jauh resmi |
| DCOM | Distributed COM, cara lain mengaktifkan objek aplikasi dari jarak jauh | Memanggil fungsi aplikasi di host lain |
| Pass the hash / pass the ticket | Memakai hash NTLM atau tiket Kerberos curian tanpa tahu password asli | Memakai token sesi curian tanpa tahu kredensial asli |
| Jump host | Host perantara yang diwajibkan untuk tugas administratif, di PT JAB `JKT-JUMP01` | Bastion / management station tempat semua akses admin dilakukan |
| LSA protection (RunAsPPL) | Fitur Windows yang menjadikan LSASS protected process agar sulit dibaca proses lain | Mengunci akses baca ke daemon kredensial |

### 1.1 Credential access dan lateral movement tanpa Defender for Identity

Pertanyaan pertama Dimas lahir dari keterbatasan nyata: lisensi M365 E3 tidak menyertakan Microsoft Defender for Identity, produk yang biasanya menganalisis trafik dan event domain controller untuk mendeteksi serangan identitas. Tanpa itu, PT JAB tidak kehilangan datanya, hanya kehilangan analitik siap pakainya. Datanya justru lengkap bila auditnya benar, dan hunting adalah cara memakai data mentah itu.

Tabel berikut memetakan taktik ke data yang dimiliki PT JAB. Baca kolom "Di mana tercatat", karena satu kesalahan paling umum adalah mencari event di host yang salah.

| Taktik / teknik | Sinyal yang diburu | Di mana tercatat |
|---|---|---|
| OS Credential Dumping: LSASS (T1003.001) | Proses membuka handle ke `lsass.exe` dengan hak baca memori | Sysmon EID 10 di 214 host ber-Sysmon; EDR di host ber-MDE [S1][S16] |
| Password Spraying (T1110.003) | Banyak akun gagal login dari satu sumber, sedikit percobaan per akun | 4625 dan 4776 (NTLM) di DC dan di host target; 4771 (Kerberos) di DC; sign-in Entra di `index=o365` [S2][S10][S14][S15] |
| Kerberoasting (T1558.003) | Permintaan tiket layanan (4769) dengan enkripsi lemah atau volume tak lazim | 4769 di DC [S8][S13] |
| Remote Services: SMB/Admin Shares (T1021.002) | Logon jaringan ke `C$`/`ADMIN$`, akses lintas host | 4624 tipe 3 di host target [S4][S9] |
| Remote Services: DCOM (T1021.003) | Objek COM diaktifkan remote oleh akun admin lalu memunculkan proses | 4624 tipe 3 + Sysmon EID 1 di target [S5] |
| Remote Services: WinRM (T1021.006) | Proses `wsmprovhost.exe` di target, logon jaringan | Sysmon EID 1 + 4624 tipe 3 di target [S6] |
| Windows Management Instrumentation (T1047) | `WmiPrvSE.exe` memunculkan proses anak, logon jaringan | Sysmon EID 1 + 4624 tipe 3 di target [S3] |
| Use Alternate Auth Material (T1550) | Logon tanpa event autentikasi yang sesuai; anomali NTLM atau tiket | 4624, 4768/4769, 4776 [S7] |

Kelemahan utamanya bukan ketiadaan Defender for Identity, melainkan cakupan Sysmon: sekitar 229 workstation tanpa Sysmon tidak menghasilkan EID 10, jadi akses LSASS di sana hanya terlihat bila host-nya punya MDE. Itu dicatat sebagai celah visibilitas di setiap laporan, bukan sebagai kegagalan hunt.

### 1.2 Akses LSASS sebagai sinyal credential access

Pertanyaan ketiga Dimas ("antivirus juga buka LSASS terus") adalah inti kesulitan teknik ini. Sysmon EID 10 (ProcessAccess) melaporkan saat satu proses membuka handle ke proses lain, operasi yang sering diikuti pembacaan memori proses target. Dokumentasi Sysmon menyebut event ini memungkinkan deteksi tool yang membaca memori LSASS untuk mencuri kredensial, dan memperingatkan bahwa mengaktifkannya tanpa filter menghasilkan volume sangat besar, jadi umumnya hanya dipakai dengan filter yang membuang akses yang diharapkan [S16]. Di PT JAB, profil Sysmon workstation lengkap (OU `Workstations-EDR`) dan profil server memuat rule `ProcessAccess` yang hanya meng-include `TargetImage` berakhiran `lsass.exe`; itu ditetapkan untuk Day ini dan dicatat sebagai asumsi data. Konsekuensinya, EID 10 di `index=sysmon` praktis hanya berisi akses ke LSASS, sehingga volumenya terkendali.

Yang membedakan dumping dari akses sah bukan "ada atau tidak", melainkan tiga hal: siapa (`SourceImage`), dengan hak apa (`GrantedAccess`), dan lewat jalur apa (`CallTrace`). `GrantedAccess` adalah bitmask hak akses proses Windows. Nilai yang relevan untuk membaca memori kredensial [S17]:

| Hak akses | Nilai | Arti |
|---|---|---|
| PROCESS_VM_READ | `0x0010` | Membaca memori proses (dibutuhkan untuk mengambil kredensial) |
| PROCESS_VM_WRITE | `0x0020` | Menulis memori proses |
| PROCESS_VM_OPERATION | `0x0008` | Operasi pada ruang alamat proses |
| PROCESS_QUERY_INFORMATION | `0x0400` | Query informasi proses (token, prioritas) |
| PROCESS_QUERY_LIMITED_INFORMATION | `0x1000` | Query terbatas; diberikan otomatis bila ada `0x0400` |
| PROCESS_ALL_ACCESS | `0x1fffff` (atau `0x1f0fff`) | Semua hak akses |

Kombinasi yang sering muncul pada upaya dumping memuat bit `0x0010` (baca memori), misalnya `0x1010` (`0x1000` + `0x0010`), `0x1410` (`0x1000` + `0x0400` + `0x0010`), atau `0x143a` yang menambah tulis dan create-thread. Nilai `0x1000` saja hanya query terbatas dan sangat sering sah. Perhatian: nilai bukan bukti. Banyak proses keamanan sah meminta `0x1410` atau bahkan hak penuh; analitik ATT&CK untuk T1003.001 menandai proses yang tidak lazim atau tidak berhak membuka handle akses penuh (`0x1F0FFF`) ke `lsass.exe` lalu diikuti dump memori, pembuatan file, atau perubahan registry [S1]. Jadi `GrantedAccess` menyaring, sementara `SourceImage` dan konteks memutuskan.

Dua hal tentang Windows modern perlu diketahui saat membaca hasil kosong. LSA protection (RunAsPPL) menjadikan LSASS protected process sehingga proses non-protected tidak bisa membaca memorinya atau menyuntikkan kode; fitur ini aktif secara default pada instalasi baru Windows 11 versi 22H2 dan setelahnya yang memenuhi syarat (domain-joined dan mendukung HVCI) [S18]. Credential Guard mengisolasi rahasia ke proses terisolasi `LSAIso.exe` dengan virtualization-based security, dan aktif default di Windows 11 22H2 pada perangkat yang memenuhi syarat [S18]. Keduanya mengurangi keberhasilan dumping, tetapi upaya membuka handle tetap tercatat di EID 10, jadi hunt tetap bernilai; yang berubah adalah peluang upaya itu berhasil.

### 1.3 Tipe logon Windows (kunci lateral movement)

Pertanyaan keempat Dimas butuh satu tabel yang dihafal. Event 4624 (logon berhasil) dan 4625 (logon gagal) memuat field `LogonType` yang menentukan sifat sesi; dua event ini tercatat di komputer tempat logon terjadi, yaitu host target, bukan di DC [S9][S10]. Tabel berikut memuat tipe logon yang didokumentasikan Microsoft; baca kolom "Relevansi hunting", karena tipe 3 dan 10 adalah jalur utama lateral movement, sementara tipe 9 menandai pemakaian kredensial alternatif.

| Tipe | Nama | Arti | Relevansi hunting |
|---|---|---|---|
| 2 | Interactive | Logon lokal di depan mesin | Baseline aktivitas normal workstation |
| 3 | Network | Logon dari jaringan (SMB, share, WMI, WinRM) | Jalur utama lateral movement; sangat umum, wajib baseline |
| 4 | Batch | Scheduled task | Eksekusi terjadwal; tipe 4 oleh akun admin domain patut dicek |
| 5 | Service | Service dimulai Service Control Manager | Akun service; tipe 5 oleh akun user biasa patut dicek |
| 7 | Unlock | Workstation dibuka dari lock | Jarang relevan sendiri |
| 8 | NetworkCleartext | Logon jaringan dengan password dikirim tanpa hash (mis. auth web dasar) | Jarang; kemunculan tak terduga patut dicek |
| 9 | NewCredentials | Proses mengkloning token lalu memakai kredensial lain untuk koneksi keluar (`runas /netonly`) | Bisa menandai pemakaian kredensial alternatif, termasuk overpass-the-hash |
| 10 | RemoteInteractive | RDP / Terminal Services | Jalur lateral movement RDP |
| 11 | CachedInteractive | Logon dengan kredensial yang di-cache lokal, DC tidak dihubungi | Logon saat terputus dari domain |

Event pendukung melengkapi gambar, dan masing-masing tercatat di tempat berbeda:

- **4648** (logon dengan kredensial eksplisit): muncul di host sumber saat proses menyebutkan kredensial akun lain, umum pada `runas` dan scheduled task; memuat akun pemanggil, akun yang kredensialnya dipakai, dan `Target Server Name` [S11]. Berguna untuk melihat sisi pengirim saat lateral movement memakai kredensial eksplisit.
- **4672** (hak istimewa saat logon): muncul saat sesi logon baru diberi hak sensitif seperti `SeDebugPrivilege` atau `SeTcbPrivilege`, menandai logon admin; dikaitkan ke 4624 lewat `Logon ID` yang sama [S12]. SYSTEM memicu ini terus-menerus, jadi fokus pada Security ID yang bukan SYSTEM/LOCAL SERVICE/NETWORK SERVICE.
- **4768/4769** (tiket Kerberos TGT/TGS) dan **4771** (pre-auth Kerberos gagal): hanya di DC [S13][S14].
- **4776** (validasi kredensial NTLM): di komputer yang otoritatif, yaitu DC untuk akun domain, memuat `Logon Account` dan `Source Workstation` tetapi tanpa IP sumber [S15].

Satu jebakan parsing: log Windows klasik sering memuat dua akun dalam satu event. Pada 4624, `Subject` (akun yang melaporkan) berbeda dari `New Logon` (akun yang masuk); untuk lateral movement yang dicari adalah akun di `New Logon` dan IP di `Source Network Address`. Microsoft mencatat bahwa field IP dan workstation terisi bergantung protokol: logon Kerberos jaringan sering tanpa informasi workstation, dan logon NTLM tanpa detail TCP/IP [S9].

### 1.4 Password spray lambat vs brute force cepat

Pertanyaan kedua Dimas benar: rule ambang per akun memang melewatkan spray. Brute force klasik mencoba banyak password ke satu akun, sehingga memicu lockout dan mudah dideteksi dengan "lebih dari N gagal untuk satu akun dalam M menit". Password spraying (T1110.003) membalik arah: satu password umum dicoba ke banyak akun, sehingga tiap akun hanya melihat satu atau dua kegagalan dan tidak pernah terkunci [S2]. ATT&CK mencatat penyerang bahkan menahan laju agar tetap di bawah ambang deteksi, dan memilih LDAP atau Kerberos karena lebih jarang menghasilkan event mencolok [S2]. Karena itu sinyal spray bukan "banyak gagal per akun" melainkan "banyak akun gagal dari satu sumber", diukur pada rentang panjang.

Untuk membaca alasan kegagalan, pakai kode `Status`/`SubStatus` pada 4625 dan `Error Code` pada 4776. Tabel berikut memuat kode yang paling berguna; baca kolom "Petunjuk", karena pola kode membedakan spray dari masalah operasional.

| Kode | Arti | Petunjuk |
|---|---|---|
| `0xC000006A` | Password salah untuk akun yang ada | Inti spray: akun valid, password salah [S10][S15] |
| `0xC0000064` | Username tidak ada | Banyak kode ini berturut menandai enumerasi akun [S10][S15] |
| `0xC0000234` | Akun terkunci | Bila banyak, tanda brute force cepat; spray justru menghindarinya [S10] |
| `0xC0000072` | Akun dinonaktifkan admin | Percobaan ke akun mati, patut dicek [S10] |
| `0xC0000070` | Logon dari workstation tidak diizinkan | Pembatasan workstation, bisa salah konfigurasi atau penyalahgunaan [S10] |
| `0xC0000193` | Akun kedaluwarsa | Sering operasional (akun lama) |

Di sisi Kerberos, 4771 di DC memuat `Failure Code`: `0x18` (KDC_ERR_PREAUTH_FAILED) berarti password salah, dan banyak `0x18` dalam waktu singkat untuk akun kritis dapat menandai brute force [S14]. Untuk username yang tidak ada, bukan 4771 yang muncul melainkan 4768 dengan `Result Code` `0x6` (KDC_ERR_C_PRINCIPAL_UNKNOWN), karena 4771 tidak dibuat untuk akun yang tidak dikenal [S13]. Di sisi NTLM, 4776 di DC memuat `Error Code` dengan makna serupa 4625, tetapi hanya memuat `Source Workstation` (nama komputer), bukan IP [S15].

PT JAB menyinkronkan AD ke Entra ID, jadi spray dari internet terhadap akun cloud muncul sebagai sign-in Entra di `index=o365` (sourcetype `azure:monitor:aad`), yang di Splunk diretensi satu tahun. Kode hasilnya memakai format AADSTS [S19]:

- `AADSTS50126` InvalidUserNameOrPassword: username atau password salah, padanan cloud dari spray yang gagal.
- `AADSTS50053` IdsLocked: akun terkunci karena terlalu banyak percobaan salah, atau sign-in diblokir.
- `AADSTS50055` password kedaluwarsa; `AADSTS50057` akun dinonaktifkan; `AADSTS50034` akun tidak ada (enumerasi); `AADSTS50076` perlu MFA.

### 1.5 Lateral movement: satu sumber ke banyak tujuan dan eksekusi remote

Pertanyaan kelima Dimas menyentuh backlog yang nyangkut dari Day 01: eksekusi WMI dari host selain `JKT-JUMP01`. Untuk menjawabnya perlu dua pola.

Pola pertama, satu sumber ke banyak tujuan. Lateral movement yang meluas memperlihatkan satu akun atau satu host sumber yang melakukan logon jaringan (tipe 3) atau RDP (tipe 10) ke banyak host tujuan dalam waktu singkat, sering dengan akun yang sama. Masalahnya, admin dan akun service sah melakukan hal yang sama persis: patch, inventaris, backup. Pembedanya bukan jumlah tujuan, melainkan apakah sumbernya host yang memang diizinkan. Di PT JAB, kebijakan menyatakan akun admin hanya masuk ke server dari `JKT-JUMP01`; maka "banyak tujuan dari `JKT-JUMP01` oleh akun admin" adalah pola yang diharapkan, dan "banyak tujuan dari workstation biasa" adalah yang dicari. Konteks itu disimpan sebagai dua lookup: aset (host, kategori workstation/server/jump host, kota, OU) dan identitas (akun, kategori admin/service/user). Tanpa keduanya, "satu sumber ke banyak tujuan" tidak punya arti.

Pola kedua, logon jaringan diikuti eksekusi remote. Beberapa teknik meninggalkan jejak eksekusi yang khas di host target, tepat setelah logon jaringan [S3][S4][S5][S6]:

| Teknik | Jejak eksekusi di target | Tanda tambahan |
|---|---|---|
| WMI remote (T1047) | Proses anak dari `WmiPrvSE.exe` (mis. `cmd.exe`, `powershell.exe`) | DCOM lewat port 135, atau WinRM 5985/5986 [S3] |
| SMB/Admin Shares (T1021.002) | Service binary disalin ke `ADMIN$` lalu service dibuat | 4624 tipe 3 lalu 7045 (service) [S4] |
| WinRM (T1021.006) | Proses `wsmprovhost.exe` memunculkan proses anak | 4624 tipe 3 [S6] |
| DCOM (T1021.003) | Objek COM (mis. aplikasi Office) memunculkan proses | Hanya admin yang bisa mengaktifkan COM remote secara default [S5] |

Satu catatan penting dari Day 01: pola `WmiPrvSE.exe` yang memunculkan `cmd.exe` di `JKT-WS-0517` ternyata berasal dari `JKT-JUMP01` (akun admin helpdesk menjalankan inventaris software), dan 4624 tipe 3 dari jump host muncul satu menit sebelumnya. Itu jinak justru karena sumbernya jump host. Backlog yang ditinggalkan adalah pertanyaan yang lebih luas: adakah pola yang sama dari sumber yang bukan `JKT-JUMP01`?

Pass the hash dan pass the ticket (T1550) adalah cara memakai kredensial curian tanpa password asli. Jejaknya halus: ATT&CK untuk pass the hash menyoroti logon jaringan NTLM (tipe 3) yang terjadi tanpa event logon domain yang menyertainya, dan untuk overpass-the-hash muncul penerbitan tiket Kerberos yang tidak lazim; tipe logon 9 (NewCredentials) juga patut diperiksa karena menandai pemakaian kredensial alternatif untuk koneksi keluar [S7]. Tanpa Defender for Identity, deteksi ini bertumpu pada korelasi manual, bukan analitik siap pakai.

### 1.6 Dari sinyal ke keputusan: insiden, pelanggaran kebijakan, atau jinak

Pertanyaan terakhir Dimas adalah yang paling praktis. Credential access dan lateral movement lebih sering berakhir di IR daripada teknik Day sebelumnya, karena keduanya dekat dengan intrusi aktif. Tetapi "admin bergerak antar host" punya tiga kemungkinan hasil, dan membedakannya adalah inti pekerjaan:

| Hasil | Ciri | Tindak lanjut |
|---|---|---|
| Insiden | Pola cocok hipotesis serangan: sumber tak dikenal, akun yang tidak seharusnya, diikuti eksekusi atau akses data | Handover ke IR (Dimas sebagai IC), dengan bukti dan lini waktu |
| Pelanggaran kebijakan | Aktivitas sah oleh orang sah, tetapi melanggar aturan (mis. akun admin dipakai dari workstation biasa) | Handover ke pemilik proses (IT) untuk diperbaiki; usulan detection agar terpantau |
| Jinak | Sesuai kebijakan dan terkonfirmasi (admin dari jump host, akun service ke server-nya) | Masuk daftar friendly intelligence, dikecualikan dari hunt berikutnya |

Pelanggaran kebijakan bukan sekadar catatan administratif. Pada `INC-2026-017`, penyerang bergerak lateral karena password local administrator yang sama dipakai ulang; akun admin yang tertinggal di memori workstation biasa adalah persis bahan bakar untuk itu. Jadi admin yang memakai akun admin dari workstation biasa (bukan jump host) menciptakan risiko yang sama dengan yang membuat insiden itu mungkin, walaupun niatnya praktis.

Korelasi credential access lalu lateral movement adalah rantai paling bernilai: satu akun membuka LSASS di host A, lalu dalam waktu dekat logon jaringan dari host A ke host B dan menjalankan proses di sana. Di SIEM yang punya risk-based alerting (RBA, di Splunk ES), tiap sinyal lemah menulis risk event berisi objek yang dinilai, skor, dan teknik ATT&CK; search kedua menjumlahkan skor per objek dalam jendela waktu dan baru memberi alert bila objek mengumpulkan sinyal dari beberapa taktik. PT JAB belum memakai RBA untuk kasus ini, jadi korelasinya dikerjakan manual: ambil host dengan akses LSASS tidak lazim, lalu cari logon jaringan keluar dari host itu dalam jendela pendek. Day 14 membahas mengubah pola yang terbukti menjadi detection.

## 2. Contoh dan langkah praktis: tiga hunt hari Kamis

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Query ditulis untuk Splunk PT JAB; untuk latihan, jalankan versi yang disesuaikan di lab pribadi (bagian 3). Semua rentang absolut berada di Februari 2027 supaya hunt bisa diulang dengan hasil yang sama.

**Asumsi data:** log DC masuk `index=wineventlog` (`JKT-DC01`, `JKT-DC02`) dengan field 4624/4625/4648/4672/4768/4769/4771/4776 terekstrak (`LogonType`, `TargetUserName`, `IpAddress`, `Status`, `SubStatus`, `TicketEncryptionType`, `Failure Code`); Sysmon di `index=sysmon` (`sourcetype=XmlWinEventLog`) dengan EID 10 difilter ke `TargetImage` `lsass.exe` dan field `SourceImage`, `GrantedAccess`, `CallTrace`; sign-in Entra di `index=o365` (`sourcetype=azure:monitor:aad`). Lookup `jab_assets.csv` (field `nt_host`, `category`, `city`, `ou`) dan `jab_identity.csv` (field `account`, `acct_type`) dipakai untuk konteks. Cek nama index, sourcetype, dan field ini di lingkunganmu sebelum menjalankan.

### 2.1 `HUNT-2027-017`: abstract akses LSASS tidak lazim

Pemicunya pelajaran `INC-2026-017` (dumping kredensial) dan pertanyaan ketiga Dimas. Abstract mengikuti langkah Initiate dan disimpan di `jab-hunt/backlog/BACKLOG.md`.

```
ID             : HUNT-2027-017
Dibuat         : 2027-03-04 (Kamis), pemilik: <kamu>, reviewer: Dimas Prasetyo
Trigger        : Pelajaran INC-2026-017 (dumping kredensial lalu reuse local admin);
                 celah deteksi untuk akses LSASS dari proses tidak lazim
Tipe (PEAK)    : Baseline (stacking), dilanjutkan hypothesis-driven per temuan
Hipotesis      : Ada proses di host ber-Sysmon yang membuka handle ke lsass.exe dengan hak
                 baca memori, dari image yang tidak dikenal sebagai tool keamanan sah (T1003.001)
ATT&CK         : T1003.001 OS Credential Dumping: LSASS Memory (Credential Access, TA0006)
Data           : index=sysmon EID 10 TargetImage lsass.exe, 214 host ber-Sysmon,
                 Senin 2027-02-01 00:00 sampai Senin 2027-03-01 00:00 WIB (Februari 2027)
Di luar cakupan: sekitar 229 workstation tanpa Sysmon (hanya terlihat bila ada MDE);
                 dumping yang tidak membuka handle ke LSASS (mis. dump SAM, DCSync)
Kriteria sukses: Semua SourceImage yang mengakses lsass dengan bit 0x0010 sudah ditinjau;
                 tiap image berlabel jinak / perlu investigasi / data tidak cukup
Handover       : IR (Dimas) bila ditemukan; Sari Kusuma untuk usulan detection; Infrastruktur
                 untuk celah Sysmon
Target selesai : Kamis 2027-03-04
```

**Kapan gagal:** profil Sysmon tidak memuat rule `ProcessAccess` untuk `lsass.exe`, sehingga EID 10 kosong; itu celah visibilitas, bukan hasil bersih.

### 2.2 `HUNT-2027-017`: stacking SourceImage yang mengakses LSASS

**Tujuan:** menemukan proses yang membuka handle ke `lsass.exe` dengan hak baca memori dari image yang bukan tool keamanan sah.

```
index=sysmon sourcetype=XmlWinEventLog EventCode=10 TargetImage="*\\lsass.exe"
    earliest="02/01/2027:00:00:00" latest="03/01/2027:00:00:00"
| stats count AS akses dc(host) AS hosts values(GrantedAccess) AS access values(host) AS host_list BY SourceImage
| sort akses
```

Tabel berikut menjelaskan tiap baris; perhatikan bahwa `GrantedAccess` hanya dikumpulkan, lalu dinilai manual.

| Baris | Fungsi |
|---|---|
| `EventCode=10 TargetImage="*\\lsass.exe"` | Hanya akses proses ke LSASS |
| `earliest=... latest=...` | Februari 2027, rentang absolut agar hunt bisa diulang |
| `stats count dc(host) values(GrantedAccess) BY SourceImage` | Stacking: proses pembuka handle, seberapa tersebar, dengan hak apa |
| `sort akses` | Yang paling jarang di atas, karena tool keamanan sah akan dominan |

`GrantedAccess` sengaja tidak difilter dengan regex. Nilainya berupa string heksadesimal dengan panjang yang bervariasi, sehingga regex untuk "bit `0x0010` menyala" mudah salah dan diam-diam membuang temuan. Jumlah SourceImage biasanya kecil, jadi lebih aman membaca daftar nilai per image lalu menilai bit baca memori dengan tabel di bagian 1.2.

Keluaran ilustrasi (ringkas):

```
SourceImage                                                                 akses      hosts  access
C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe     2.412.088  214    0x1000, 0x1410, 0x1fffff
C:\ProgramData\Microsoft\Windows Defender\Platform\...\MsMpEng.exe          1.284.502  214    0x1400, 0x1410
C:\Windows\System32\svchost.exe                                             61.204     214    0x1410, 0x1010
C:\Windows\System32\wininit.exe                                            428        214    0x1410
C:\Windows\System32\csrss.exe                                              214        214    0x1038
```

```
Total event EID 10 (target lsass) dalam rentang : 3.758.436
SourceImage unik                                : 5
```

**Cara membaca hasil:** lima SourceImage, semuanya proses Microsoft yang ditandatangani dan hadir di seluruh atau hampir seluruh host. `MsSense.exe` dan `MsMpEng.exe` adalah sensor dan engine MDE, yang memang membaca LSASS terus-menerus; `wininit.exe`, `csrss.exe`, dan `svchost.exe` adalah komponen Windows. Hampir semua nilai memuat bit baca memori `0x0010` (`0x1410`, `0x1010`, `0x1038`, `0x1fffff`), dan itu wajar untuk sensor EDR serta komponen inti Windows; justru karena itu bit tersebut hanya menyaring, bukan memutuskan. Tidak ada image dari folder yang bisa ditulis pengguna, tidak ada yang hanya muncul di satu host dengan hak baca memori. Hasil: tidak ditemukan. Cakupan nyata: 214 host ber-Sysmon selama Februari; di luar cakupan 229 workstation tanpa Sysmon dan teknik dumping yang tidak membuka handle ke LSASS.

**Variasi:** tambahkan `CallTrace` ke `values()` untuk melihat DLL yang dilewati; akses dari `UNKNOWN` di `CallTrace` (memori tanpa modul) adalah sinyal tambahan yang sering dikaitkan dengan tool injeksi. Atau stacking `SourceImage` dengan `host` untuk menemukan image yang hanya muncul di satu host.

**Kapan gagal:** EDR diwakili banyak path berversi (folder `Platform\<versi>`), sehingga satu produk terpecah menjadi banyak SourceImage; normalkan path versi sebelum stacking. Atau LSA protection aktif sehingga upaya dumping ditolak sebelum handle terbuka dengan hak penuh, dan yang tercatat hanya query terbatas.

### 2.3 `HUNT-2027-018`: password spray lambat

Pemicunya pertanyaan kedua Dimas. Abstract diringkas; fokusnya pada query dan cara membaca.

```
ID             : HUNT-2027-018
Dibuat         : 2027-03-04 (Kamis), pemilik: <kamu>, reviewer: Dimas Prasetyo
Trigger        : Celah deteksi - rule brute force hanya menghitung gagal per akun;
                 spray lambat (banyak akun, sedikit percobaan) lolos
Tipe (PEAK)    : Baseline (stacking per sumber), dilanjutkan hypothesis-driven per kandidat
Hipotesis      : Ada satu sumber yang gagal login ke banyak akun berbeda dengan sedikit
                 percobaan per akun selama Februari (T1110.003), lolos ambang per akun
ATT&CK         : T1110.003 Brute Force: Password Spraying (Credential Access, TA0006)
Data           : 4625/4776/4771 di index=wineventlog (DC); sign-in Entra di index=o365;
                 Senin 2027-02-01 00:00 sampai Senin 2027-03-01 00:00 WIB
Di luar cakupan: spray terhadap layanan yang tidak lewat DC (mis. VPN lokal), akun yang
                 autentikasinya tidak sampai ke DC
Kriteria sukses: Semua sumber dengan banyak akun gagal ditinjau per sumber; tiap item
                 berlabel insiden / jinak / inkonklusif
Handover       : IR bila ditemukan; IAM untuk akun cloud; Sari untuk usulan detection
Target selesai : Kamis 2027-03-04
```

**Tujuan:** menemukan satu sumber yang gagal login ke banyak akun berbeda dengan sedikit percobaan per akun.

```
index=wineventlog EventCode=4625
    earliest="02/01/2027:00:00:00" latest="03/01/2027:00:00:00"
    NOT TargetUserName="*$"
| bin span=1d _time AS hari
| stats count AS gagal dc(TargetUserName) AS akun_unik values(SubStatus) AS substatus
    BY IpAddress hari
| eval per_akun=round(gagal/akun_unik,1)
| where akun_unik>=15 AND per_akun<=3
| sort - akun_unik
```

| Baris | Fungsi |
|---|---|
| `EventCode=4625` | Logon gagal, tercatat di host target; di DC untuk logon jaringan domain |
| `NOT TargetUserName="*$"` | Buang akun komputer (nama berakhiran `$`), yang sering gagal karena alasan operasional |
| `bin span=1d` | Agregasi per hari, karena spray lambat tersebar sepanjang hari |
| `stats dc(TargetUserName) BY IpAddress hari` | Banyak akun unik per sumber per hari adalah tanda spray |
| `eval per_akun` lalu `where per_akun<=3` | Sedikit percobaan per akun membedakan spray dari brute force per akun |

Keluaran ilustrasi:

```
IpAddress        hari         gagal  akun_unik  per_akun  substatus
10.20.4.30       2027-02-09   64     31         2.1       0xC000006A, 0xC0000234
```

Satu kandidat ditinjau:

- **`10.20.4.30` (`jkt-mon01`, server monitoring), 9 Februari, 31 akun, jinak.** Walaupun akun berakhiran `$` sudah dibuang, 28 dari 31 "akun" ternyata akun komputer yang tanda `$`-nya hilang karena bug parsing field di satu sumber log; sisanya tiga akun service pemantauan yang kredensialnya kedaluwarsa setelah rotasi password. Diperbaiki bersama Infrastruktur. Label: jinak, plus catatan celah parsing ke tim data.

Query Kerberos dan Entra menutup jalur lain. Di DC, `index=wineventlog EventCode=4771` dengan `Failure Code` `0x18`, di-stacking per `Client Address` dengan ambang yang sama, tidak menunjukkan satu sumber dengan banyak akun. Di `index=o365`, sign-in Entra dengan kode `50126` di-stacking per IP sumber per hari menghasilkan dua kandidat:

- **`198.51.100.120` (NAT kantor Jakarta), Selasa 2 Februari, 22 akun, jinak.** Sehari sebelumnya PT JAB memberlakukan ganti password massal, dan kegagalan berasal dari aplikasi email dan Teams di ponsel serta laptop yang masih menyimpan password lama; setelah pengguna masuk ulang, kegagalan berhenti. Karena semua karyawan kantor Jakarta keluar lewat satu IP NAT, pivot ke nama perangkat dan user agent di event sign-in menunjukkan 19 perangkat berbeda, konsisten dengan banyak pengguna, bukan satu penyerang. Cek nama field perangkat di add-on versi-mu.
- **`203.0.113.210`, tiga akun sepanjang Februari, di bawah ambang.** Ditelusuri ke skrip kontraktor lama yang memakai kredensial basi; diteruskan ke IAM sebagai kebersihan akun, bukan insiden.

Hasil `HUNT-2027-018`: tidak ditemukan.

**Kapan gagal:** spray memakai NTLM murni yang hanya memunculkan 4776 tanpa 4625 pada sebagian konfigurasi, atau spray memakai Kerberos sehingga jejaknya di 4771, bukan 4625; jalankan ketiga query, jangan hanya 4625. Atau spray dari internet terhadap VPN yang auth-nya tidak sampai ke DC, di luar cakupan dan perlu log VPN.

### 2.4 `HUNT-2027-019`: eksekusi WMI atau remote dari host selain `JKT-JUMP01`

Ini menutup backlog Day 01 dan pertanyaan kelima Dimas. Pemicunya baseline (backlog) ditambah kebijakan jump host.

```
ID             : HUNT-2027-019
Dibuat         : 2027-03-04 (Kamis), pemilik: <kamu>, reviewer: Dimas Prasetyo
Trigger        : Backlog HUNT-2027-001 (eksekusi WMI dari host selain JKT-JUMP01);
                 kebijakan akun admin hanya dari JKT-JUMP01
Tipe (PEAK)    : Hypothesis-driven
Hipotesis      : Ada host selain JKT-JUMP01 yang memicu eksekusi remote (WmiPrvSE, wsmprovhost,
                 atau pembuatan service) di workstation lain lewat logon jaringan (T1047, T1021)
ATT&CK         : T1047 WMI; T1021.002 SMB/Admin Shares; T1021.006 WinRM (Lateral Movement, TA0008)
Data           : Sysmon EID 1 (parent WmiPrvSE/wsmprovhost) + 4624 tipe 3 + 7045, di host
                 ber-Sysmon dan DC; Senin 2027-02-01 00:00 sampai Senin 2027-03-01 00:00 WIB
Di luar cakupan: eksekusi remote ke workstation tanpa Sysmon (hanya terlihat bila ada MDE)
Kriteria sukses: Semua sumber selain JKT-JUMP01 yang memicu eksekusi remote ditinjau;
                 tiap item berlabel insiden / pelanggaran kebijakan / jinak
Handover       : IR bila insiden; IT (Manajer Layanan TI) bila pelanggaran kebijakan; Sari
Target selesai : Kamis 2027-03-04
```

**Tujuan:** menemukan host sumber (selain `JKT-JUMP01`) yang memunculkan proses lewat WMI, WinRM, atau service pada host lain, diikuti logon jaringan.

```
index=sysmon sourcetype=XmlWinEventLog EventCode=1
    (ParentImage="*\\WmiPrvSE.exe" OR ParentImage="*\\wsmprovhost.exe")
    Image IN ("*\\cmd.exe","*\\powershell.exe","*\\pwsh.exe","*\\wscript.exe","*\\cscript.exe")
    earliest="02/01/2027:00:00:00" latest="03/01/2027:00:00:00"
| join type=inner host max=0
    [ search index=wineventlog EventCode=4624 LogonType=3
        earliest="02/01/2027:00:00:00" latest="03/01/2027:00:00:00"
    | rename Computer AS host, IpAddress AS src_ip, TargetUserName AS akun
    | fields host src_ip akun ]
| search NOT akun="*$"
| stats dc(host) AS tujuan values(host) AS tujuan_list values(akun) AS akun count AS eksekusi BY src_ip
| sort - tujuan
```

Query ini menyederhanakan korelasi: proses anak `WmiPrvSE.exe`/`wsmprovhost.exe` di target dikaitkan dengan 4624 tipe 3 pada host yang sama, akun komputer (berakhiran `$`) dibuang, lalu hasilnya di-stacking per IP sumber. Join per host saja belum memastikan logon terjadi tepat sebelum eksekusi; untuk itu urutkan event per host lalu pakai `streamstats` dengan jendela waktu (cara kerjanya di Day 05 bagian 2.2) dan ambil hanya logon jaringan yang terjadi dalam dua menit sebelum proses anak. Join di atas disederhanakan untuk keterbacaan dan cukup untuk menyusun daftar kandidat yang lalu ditinjau satu per satu. Perhatian: `IpAddress` dipetakan ke nama host dengan log DHCP atau inventaris aset pada rentang yang sama, karena IP bisa berganti; di keluaran berikut kolom `src_host` adalah hasil pemetaan itu.

Keluaran ilustrasi:

```
src_ip        src_host      tujuan  eksekusi  akun
10.10.1.10    JKT-JUMP01    34      512       JAB\adm.helpdesk
10.10.27.63   JKT-WS-0671   7       14        JAB\adm.ilham
```

Kedua sumber ditinjau:

- **`JKT-JUMP01` (`10.10.1.10`), 34 tujuan, jinak.** Ini pola yang diharapkan: akun admin helpdesk menjalankan inventaris software dan perbaikan dari jump host, sesuai kebijakan. Ini juga yang menjelaskan temuan jinak `JKT-WS-0517` di Day 01. Dikecualikan.
- **`JKT-WS-0671` (`10.10.27.63`), 7 tujuan, 14 eksekusi, PELANGGARAN KEBIJAKAN.** `JKT-WS-0671` adalah workstation biasa di OU `Workstations-EDR`, bukan jump host. Akun yang dipakai adalah `adm.ilham`, akun admin Ilham Ramadhan, staf IT Helpdesk yang baru bergabung Januari 2027. Pivot ke `CommandLine` menunjukkan `wmic /node:<host> process call create` dan `wmic /node:<host> product` ke tujuh workstation (`JKT-WS-0614`, `JKT-WS-0619`, `JKT-WS-0627`, `JKT-WS-0633`, `JKT-WS-0645`, `JKT-WS-0652`, `JKT-WS-0658`) untuk memasang perbaikan printer dan mengumpulkan inventaris. Dikonfirmasi ke Ilham: ia melakukannya langsung dari workstation-nya sendiri dengan akun admin karena lebih cepat daripada lewat `JKT-JUMP01`. Tidak ada tanda jahat: tujuannya workstation internal, perintahnya administratif, dan 4672 menunjukkan hak admin yang wajar untuk akun admin. Tetapi ini melanggar kebijakan dan berbahaya: akun admin yang dipakai interaktif di workstation biasa meninggalkan kredensial di memori host yang juga membuka web dan email, persis bahan bakar reuse yang membuat `INC-2026-017` meluas. Label: pelanggaran kebijakan, bukan insiden.

Hasil `HUNT-2027-019`: ditemukan pelanggaran kebijakan. Handover ke Dimas dan ke Hadi Santoso (Manajer Layanan TI, atasan IT Helpdesk): Ilham diarahkan memakai `JKT-JUMP01` untuk tugas administratif, akun `adm.ilham` dipantau, dan kredensial admin di `JKT-WS-0671` dibersihkan (logout, reboot, rotasi password admin). Usulan detection ke Sari Kusuma: "JAB - Logon akun admin ke workstation dari host selain `JKT-JUMP01`" (4624 akun berpola `adm.*` ke host kategori workstation dengan `IpAddress` bukan `JKT-JUMP01`), dan pelengkapnya "JAB - WmiPrvSE memunculkan shell di workstation dari sumber selain `JKT-JUMP01`".

**Kapan gagal:** workstation tujuan tanpa Sysmon tidak menghasilkan EID 1, sehingga eksekusi di sana tidak terlihat (celah visibilitas); atau eksekusi remote memakai WinRM dengan `wsmprovhost.exe` yang tidak memunculkan proses anak yang difilter, sehingga lolos daftar `Image`. Subsearch di dalam `join` juga dibatasi jumlah barisnya secara default, jadi untuk sebulan data 4624 pecah rentang per minggu atau ganti join dengan `stats` atas kedua sumber sekaligus.

### 2.5 Korelasi credential access lalu lateral movement

Ketiga hunt di atas berdiri sendiri, tetapi rantai yang paling bernilai menggabungkannya: akun yang membuka LSASS di satu host lalu logon jaringan keluar dari host itu. Tanpa risk-based alerting, korelasinya manual:

```
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
    earliest="02/01/2027:00:00:00" latest="03/01/2027:00:00:00"
| search NOT SourceImage IN ("*\\MsSense.exe","*\\MsMpEng.exe","*\\wininit.exe","*\\csrss.exe","*\\svchost.exe")
| stats min(_time) AS lsass_time values(SourceImage) AS src BY host
| join type=inner host
    [ search index=wineventlog EventCode=4624 LogonType=3
        earliest="02/01/2027:00:00:00" latest="03/01/2027:00:00:00"
    | rename Computer AS host | stats min(_time) AS netlogon_time values(IpAddress) AS dest BY host TargetUserName ]
| where netlogon_time > lsass_time AND (netlogon_time - lsass_time) <= 3600
```

Logikanya: host dengan akses LSASS dari image yang bukan daftar keamanan sah, lalu dalam satu jam ada logon jaringan keluar dari host itu. Di PT JAB bulan Februari, setelah membuang image keamanan sah, bagian pertama kosong, sehingga rantai ini tidak menghasilkan baris. Itu konsisten dengan `HUNT-2027-017` yang tidak menemukan apa pun; rantai hanya berarti bila sinyal credential access-nya ada lebih dulu. Angka skor (misalnya 40 untuk akses LSASS tak lazim, 30 untuk logon jaringan ke host baru) ditetapkan dari jumlah FP masing-masing sinyal di lab, bukan ditebak.

### 2.6 Laporan tiga hunt dan jawaban untuk Dimas

Tiga laporan berikut adalah langkah Finalize TaHiTI dan fase Act PEAK.

```
ID            : HUNT-2027-017                        Selesai: Kamis 2027-03-04
Hasil         : Tidak ditemukan akses LSASS tidak lazim
Cakupan nyata : Sysmon EID 10 (target lsass), 214 host ber-Sysmon, Februari 2027
                (3.758.436 event, 5 SourceImage, semua Microsoft tertanda)
Di luar cakupan: 229 workstation tanpa Sysmon; dumping yang tidak membuka handle ke LSASS
Jinak terkonfirmasi: MsSense, MsMpEng (MDE), svchost/wininit/csrss (komponen Windows)
Celah data    : EID 10 hanya di host ber-Sysmon -> ke Infrastruktur (perluasan Sysmon)
Deteksi       : Belum; pola LSASS dari image tak lazim disiapkan sebagai kandidat untuk Day 14
```

```
ID            : HUNT-2027-018                        Selesai: Kamis 2027-03-04
Hasil         : Tidak ditemukan password spray
Cakupan nyata : 4625/4771/4776 di DC + sign-in Entra, Februari 2027
Ambang        : akun_unik >= 15 per sumber per hari, percobaan per akun <= 3
Jinak terkonfirmasi: jkt-mon01 (akun komputer + service basi), NAT Jakarta di Entra (ganti password
                massal), skrip kontraktor lama (3 akun Entra, di bawah ambang)
Celah data    : Spray ke VPN lokal di luar cakupan -> perlu log VPN; celah parsing field akun$
Deteksi       : Usulan laporan mingguan "TH - kandidat spray per sumber" ke Sari (bukan alert L1)
```

```
ID            : HUNT-2027-019                        Selesai: Kamis 2027-03-04
Hasil         : DITEMUKAN pelanggaran kebijakan (bukan insiden)
Cakupan nyata : Sysmon EID 1 (parent WmiPrvSE/wsmprovhost) + 4624 tipe 3, host ber-Sysmon, Februari 2027
Temuan        : adm.ilham (Ilham Ramadhan, IT Helpdesk baru) menjalankan WMI dari workstation
                sendiri JKT-WS-0671 ke 7 workstation, 14 eksekusi; bukan jahat, melanggar kebijakan
Di luar cakupan: workstation tujuan tanpa Sysmon
Jinak terkonfirmasi: JKT-JUMP01 (admin helpdesk dari jump host, 34 tujuan) -> dikecualikan
Handover      : Dimas + Hadi Santoso (Manajer Layanan TI): hentikan admin dari workstation,
                bersihkan kredensial adm.ilham di JKT-WS-0671
Deteksi       : Usulan "JAB - Logon akun admin ke workstation dari host selain JKT-JUMP01" ke Sari
```

Tabel berikut adalah jawaban yang dikirim ke Dimas Kamis sore. Setiap baris merujuk subbagian di atas.

| Pertanyaan Dimas | Jawaban singkat | Dasar |
|---|---|---|
| Bisa diburu tanpa Defender for Identity? | Bisa; datanya ada di log DC, Sysmon, dan EDR, yang hilang hanya analitik siap pakai | Bagian 1.1 |
| Spray lambat lolos rule? | Ya; rule hitung gagal per akun, spray disebar ke banyak akun; diburu per sumber | Bagian 1.4, 2.3 |
| Akses LSASS vs antivirus | Pembedanya SourceImage, GrantedAccess (bit baca memori), dan CallTrace, bukan ada/tidak | Bagian 1.2, 2.2 |
| Tipe logon mana yang penting | Tipe 3 (network) dan 10 (RDP) untuk lateral; tipe 9 untuk kredensial alternatif | Bagian 1.3 |
| WMI dari selain JKT-JUMP01 | Ada: helpdesk baru menjalankan WMI dari workstation sendiri; pelanggaran kebijakan, bukan insiden | Bagian 2.4 |
| Insiden, pelanggaran, atau wajar | Insiden ke IR; pelanggaran ke IT dengan detection; jinak ke friendly intelligence | Bagian 1.6 |

**Kapan gagal:** melaporkan `HUNT-2027-019` sebagai "tidak ada insiden" tanpa menindaklanjuti pelanggaran kebijakan. Akun admin di workstation biasa adalah risiko nyata yang membuat insiden berikutnya lebih mudah; mengabaikannya berarti mengulang pelajaran `INC-2026-017`.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** Splunk lab dengan Sysmon (rule `ProcessAccess` untuk `TargetImage` `lsass.exe` aktif), Security 4624/4625/4648/4672/4768/4769/4771/4776, dan minimal dua VM Windows dalam satu domain lab; VM dengan snapshot. Jangan memakai data, nama, atau kejadian dari pekerjaan nyata; PT JAB hanya contoh fiktif. Sesuaikan index, sourcetype, dan rentang absolut dengan data lab-mu.

1. **Peta teknik ke data.** Untuk setiap teknik di bagian 1.1, isi data lab dan blind spot. Tandai yang datanya belum ada (mis. audit Kerberos di DC lab).
2. **Aktifkan EID 10.** Pastikan profil Sysmon lab memuat rule `ProcessAccess` ber-`TargetImage` `lsass.exe`. Jalankan bagian 2.2. Bila kosong, rule belum ada; catat sebagai celah visibilitas lalu tambahkan dan ulangi.
3. **Baseline akses LSASS.** Stacking `SourceImage` selama beberapa hari aktivitas normal; catat image keamanan sah lab-mu (Defender atau EDR lain) dan hak akses yang mereka minta. Itu allowlist-mu.
4. **Uji positif LSASS (hati-hati).** Semua test Atomic Red Team di halaman T1003.001 membuat dump memori LSASS sungguhan, bukan sekadar membuka handle, jadi jalankan hanya di VM terisolasi tanpa kredensial nyata dan kembalikan snapshot setelahnya. Dari sisi telemetri, yang harus terlihat adalah EID 10 dengan `SourceImage` di luar allowlist-mu, `GrantedAccess` yang memuat bit `0x0010`, lalu EID 11 (FileCreate) berupa file dump. Bila ragu, lewati; mengamati akses sah EDR di langkah 3 sudah cukup untuk memahami bentuk sinyalnya.
5. **Tipe logon.** Buat tabel 4624 per `LogonType` dari lab-mu. Lakukan satu logon RDP (tipe 10), satu akses share lewat `net use` (tipe 3), dan satu `runas /netonly` (tipe 9), lalu temukan ketiganya di log dengan tipe yang benar.
6. **Spray lambat.** Atomic Red Team T1110.003 Test 1 (`Password Spray all Domain Users`, GUID `90bc2e54-6c84-47a5-9439-0a2a92b4b175`) memakai `net use` berulang ke IPC$ DC dengan satu password; test ini dapat mengunci akun, jadi jalankan hanya di domain lab dengan akun uji [S23]. Dari sisi telemetri, yang harus terlihat: banyak 4625 (dan 4776 di DC) dengan `SubStatus` `0xC000006A` untuk banyak `TargetUserName` dari satu sumber. Jalankan bagian 2.3 dan pastikan sumber itu muncul.
7. **Eksekusi remote.** Atomic T1047 Test 6 (`WMI Execute Remote Process`, GUID `9c8ef159-c666-472f-9874-90c8d60d136b`) memakai `wmic /node` bawaan; parameter `node` default `127.0.0.1`, jadi ubah ke VM kedua [S20]. Yang harus terlihat di target: 4624 tipe 3 lalu Sysmon EID 1 dengan parent `WmiPrvSE.exe`. Untuk WinRM, Atomic T1021.006 Test 2 (`Remote Code Execution with PS Credentials Using Invoke-Command`, GUID `5295bd61-bd7e-4744-9d52-85962a4cf2d6`) memunculkan `wsmprovhost.exe` di target; default-nya menargetkan mesin lokal [S22]. Katalog T1021.002 memuat test pemetaan admin share `C$` lewat `net use` dan test penyalinan service binary ke `ADMIN$`; yang harus terlihat di target adalah 4624 tipe 3, akses share, lalu 7045 untuk service baru [S21]. Jalankan bagian 2.4 (untuk jalur service, ganti sisi Sysmon EID 1 dengan 7045 di `wineventlog`) dan pastikan sumbernya tertangkap.
8. **Korelasi dan laporan.** Jalankan bagian 2.5 untuk merantai akses LSASS lab-mu (langkah 4) dengan logon jaringan keluar (langkah 7). Tulis laporan ketiga hunt dengan hasil, cakupan, ambang, dan label.

**Hasil yang sebaiknya tersimpan:**

- Peta teknik ke data dengan blind spot terisi dan celah visibilitas ditandai.
- Allowlist SourceImage LSASS lab dengan hak akses yang biasa diminta tiap tool.
- Tabel 4624 per tipe logon, dengan bukti tipe 3, 9, dan 10 dari percobaan sendiri.
- Angka spray lab: jumlah 4625/4776 per akun dan per sumber, dengan GUID test.
- Bukti eksekusi remote tertangkap (parent WmiPrvSE/wsmprovhost) dengan GUID test.
- Laporan tiga hunt dengan cakupan, ambang, dan label; temuan untuk IR atau IT ditandai.

**Variasi tantangan:** nilai visibilitas Kerberos lab-mu. Bila ada DC dengan audit 4769, rancang hunt Kerberoasting (T1558.003): permintaan tiket 4769 dengan `TicketEncryptionType` `0x17` (RC4), buang akun komputer dan akun service yang memang masih RC4, lalu cari satu akun yang meminta banyak SPN berbeda [S8][S13]. Bila tidak ada DC atau audit, dokumentasikan sebagai celah visibilitas dan tulis rekomendasi telemetri.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| EID 10 kosong | Profil Sysmon tanpa rule `ProcessAccess` untuk lsass | Tambah rule ber-`TargetImage` `lsass.exe`; sampai aktif, catat sebagai celah visibilitas |
| Akses LSASS penuh FP | Tool keamanan sah dominan | Allowlist image keamanan (path + signer); fokus yang jarang dan dari folder user |
| EDR terpecah jadi banyak SourceImage | Path berversi (`Platform\<versi>`) | Normalkan path versi sebelum stacking |
| 4624 tanpa IP sumber | Logon Kerberos jaringan atau NTLM tanpa detail TCP/IP | Cek field per protokol; untuk NTLM pakai `Source Workstation` di 4776 [S9][S15] |
| Query 4625 kosong padahal ada spray | Spray memakai Kerberos atau NTLM murni | Jalankan juga 4771 (`0x18`) dan 4776; jangan hanya 4625 |
| Satu NAT terlihat sebagai satu penyerang | Banyak host di belakang satu IP | Pivot ke `Source Workstation` 4776 atau log DHCP untuk memisahkan host |
| Satu-sumber-banyak-tujuan penuh admin | Tidak ada daftar sumber yang diizinkan | Pakai `jab_assets.csv` dan kecualikan jump host; bandingkan dengan kebijakan |
| 4771 kosong untuk username yang ditebak | 4771 tidak dibuat untuk akun tak dikenal | Cari 4768 `Result Code` `0x6` untuk enumerasi username [S13] |
| Rantai korelasi selalu kosong | Bagian credential access tidak ada temuan | Wajar; rantai hanya berisi bila sinyal LSASS ada lebih dulu |

## 5. Kesalahan umum dan jebakan

- **Menganggap akses LSASS apa pun jahat.** Banyak tool keamanan sah membacanya; fokus pada SourceImage tak lazim, bit `0x0010`, dan konteks, bukan ada/tidak [S1][S16].
- **Memaksakan regex rumit pada GrantedAccess.** Nilai bitmask lebih aman dibaca manual; regex yang salah membuang temuan atau membanjiri FP.
- **Hanya memburu brute force cepat.** Spray lambat lolos ambang per akun; hunt per sumber pada rentang panjang [S2].
- **Mencari 4625 di DC untuk semua kasus.** 4625 ada di host target; untuk logon jaringan domain memang sampai ke DC, tetapi logon lokal ada di host-nya. 4776 NTLM dan 4771 Kerberos ada di DC [S10][S14][S15].
- **Mengabaikan baseline dan daftar aset untuk lateral movement.** Admin dan akun service meniru pola penyerang; tanpa daftar sumber yang diizinkan, "banyak tujuan" tidak bermakna.
- **Mencampur tipe logon.** Tipe 3, 9, dan 10 punya arti tajam yang berbeda; tanpa `LogonType` hunt logon kehilangan arah [S9].
- **Membaca akun yang salah di 4624.** `Subject` berbeda dari `New Logon`; untuk lateral movement yang dicari akun di `New Logon` [S9].
- **Menutup pelanggaran kebijakan sebagai "bukan insiden" lalu berhenti.** Akun admin di workstation biasa adalah risiko reuse kredensial; handover ke pemilik proses dan usulkan detection.
- **Mencampur celah deteksi dan celah visibilitas.** EID 10 tidak dicatat atau audit Kerberos mati adalah celah visibilitas, bukan hasil bersih.
- `[komunitas, belum terkonfirmasi]` Praktisi menekankan deteksi akses LSASS bergantung pada daftar proses sah yang matang dan nilai `GrantedAccess` yang diamati di lingkungan sendiri; tanpa allowlist proses keamanan, FP membanjiri. Pola ini konsisten dengan sifat EID 10 yang mencatat tiap pembukaan handle tanpa menilai niat; bangun allowlist dari data lab-mu.

## 6. Catatan terkini

Bagian ini menampung detail versi dan terminologi yang tidak mengubah langkah kerja di atas.

- ATT&CK v20: T1003.001 (v1.5, 12 Mei 2026), T1110.003 (v1.8, 24 Okt 2025), T1047 (v1.6, 12 Mei 2026), T1021.002/.003/.006, T1550 (v2.0), dan T1558.003 (v1.3) stabil [S1][S2][S3][S4][S5][S6][S7][S8]. T1550 kini bertaktik tunggal Lateral Movement di v20; dokumentasi lama yang menyebut taktik ganda (termasuk Defense Evasion) sudah tidak sesuai [S7].
- Sysmon versi stabil adalah v15.2 (26 Maret 2026), yang memperbaiki penanganan antrean event internal agar lebih tahan event terbuang saat beban tinggi; halaman Sysinternals diperbarui 10 September 2026 [S16][S24]. EID 10 (ProcessAccess) tetap sinyal utama dumping LSASS, dengan FP tinggi yang menuntut filter dan allowlist.
- LSA protection (RunAsPPL) dan Credential Guard aktif secara default pada instalasi baru Windows 11 versi 22H2 dan setelahnya yang memenuhi syarat [S18]. Keduanya mengurangi keberhasilan dumping, tetapi upaya akses tetap tercatat di EID 10.
- Event 4768/4769 diperbarui pada Windows Server 2016 dan setelahnya sejak cumulative update Januari 2025, menambah field enkripsi dan hash tiket; `TicketEncryptionType` `0x17` tetap menandai RC4 [S13].
- Korelasi credential access lalu lateral movement paling efektif dengan risk-based alerting. Di SIEM tanpa akumulasi skor per entitas bawaan, korelasi lintas host lebih realistis sebagai query hunt manual (bagian 2.5).
- Day 12 melanjutkan ke C2 dan exfiltration, dua taktik akhir yang sering mengikuti pergerakan lateral.

## 7. Cheat sheet

```
CRED ACCESS  T1003.001 LSASS (Sysmon EID10: SourceImage, GrantedAccess bit 0x0010, CallTrace) | T1110.003 spray (4625/4776/4771) | T1558.003 kerberoast (4769 etype 0x17)
GRANTEDACC   0x0010 VM_READ | 0x0008 VM_OP | 0x0020 VM_WRITE | 0x0400 QUERY_INFO | 0x1000 QUERY_LIMITED | 0x1fffff / 0x1f0fff ALL ; dumping sering 0x1010/0x1410/0x143a
LATERAL      T1021.002 SMB/share (4624 t3, 7045) | T1021.003 DCOM (admin, port135) | T1021.006 WinRM (wsmprovhost) | T1047 WMI (WmiPrvSE child) | T1550 PtH/PtT (t3 NTLM tanpa logon domain, t9)
LOGONTYPE    2 interaktif | 3 network | 4 batch | 5 service | 7 unlock | 8 cleartext | 9 new creds (runas /netonly) | 10 RDP | 11 cached ; +4648 (eksplisit, host sumber), 4672 (hak admin)
LOG DI MANA  4624/4625/4648/4672 di host TARGET | 4768/4769/4771 di DC | 4776 (NTLM) di DC, tanpa IP, ada Source Workstation | sign-in Entra di index=o365
SPRAY CODE   4625/4776 0xC000006A pwd salah | 0xC0000064 user tak ada | 0xC0000234 terkunci ; 4771 0x18 pwd salah ; 4768 0x6 user tak ada ; Entra AADSTS50126/50053/50034
POLA         LSASS dari image tak lazim | spray: dc(user) banyak per sumber, percobaan/akun sedikit | 1 sumber -> banyak tujuan (dc dest) | logon t3 lalu WmiPrvSE/wsmprovhost/7045
KONTEKS      jab_assets (host, kategori, jump host) + jab_identity (akun: admin/service/user) ; kebijakan: akun admin ke server HANYA dari JKT-JUMP01
HASIL        insiden -> IR | pelanggaran kebijakan -> IT + usulan detection | jinak -> friendly intel | EID10/audit mati -> celah visibilitas
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Sysmon EID 10 menunjukkan `MsSense.exe` membuka handle ke `lsass.exe` dengan `GrantedAccess` `0x1410` di 214 host. Itu dumping kredensial massal." Benarkah?

<details><summary>Jawaban</summary>

Tidak. `MsSense.exe` adalah sensor Microsoft Defender for Endpoint, tool keamanan sah yang memang membaca LSASS terus-menerus di semua host ber-EDR; kemunculan di 214 host justru menandai software yang tersebar luas, bukan serangan. Akses LSASS adalah sinyal, bukan bukti: yang dinilai adalah SourceImage (dikenal sah atau tidak), GrantedAccess, dan CallTrace. `0x1410` memang memuat bit baca memori `0x0010`, tetapi untuk proses keamanan yang ditandatangani dan ada di allowlist, itu diharapkan. Lihat bagian 1.2 dan 2.2.

</details>

**2. Skenario keputusan.** Rule brute force PT JAB tidak berbunyi, tetapi kamu curiga ada password spray. Query mana yang paling tepat untuk memburunya?

- A. `index=wineventlog EventCode=4625 | stats count BY TargetUserName | where count > 10` lalu lihat akun dengan gagal terbanyak.
- B. Per sumber per hari, hitung jumlah akun unik yang gagal dan percobaan per akun, lalu ambil sumber dengan banyak akun dan sedikit percobaan per akun.
- C. `index=wineventlog EventCode=4625 | stats count` lalu bandingkan totalnya dengan minggu lalu.

<details><summary>Jawaban</summary>

B. Password spray menyebar sedikit percobaan ke banyak akun agar tidak memicu lockout per akun, sehingga sinyalnya adalah banyak akun unik gagal dari satu sumber, bukan banyak gagal per akun. A justru mengulang logika rule ambang per akun yang sudah dilewati spray. C hanya melihat total dan kehilangan pola per sumber. Lihat bagian 1.4 dan 2.3.

</details>

**3. Pertanyaan jebakan.** "PT JAB tidak punya Microsoft Defender for Identity, jadi serangan Active Directory seperti Kerberoasting dan password spray tidak bisa diburu." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Defender for Identity menyediakan analitik siap pakai, bukan data mentahnya. Datanya tetap ada: 4768/4769/4771 di domain controller untuk Kerberos, 4625 dan 4776 untuk spray, dan EDR di endpoint. Yang hilang hanya kemudahan; hunting justru memakai data mentah itu dengan query dan konteks. Cakupan Sysmon yang tidak merata adalah batas yang lebih nyata daripada ketiadaan Defender for Identity. Lihat bagian 1.1.

</details>

**4. Skenario keputusan.** Kamu menemukan `adm.ilham` menjalankan WMI dari workstation-nya sendiri (`JKT-WS-0671`, bukan jump host) ke tujuh workstation lain, dan Ilham mengonfirmasi itu untuk memperbaiki printer. Apa langkah yang tepat?

- A. Nyatakan insiden, buka tiket IR, dan isolasi `JKT-WS-0671`.
- B. Tutup sebagai jinak karena Ilham mengonfirmasi dan niatnya administratif.
- C. Labeli pelanggaran kebijakan, handover ke IT untuk menghentikan admin dari workstation dan membersihkan kredensial, lalu usulkan detection untuk logon admin ke workstation dari selain jump host.

<details><summary>Jawaban</summary>

C. Aktivitasnya sah dan bukan serangan, jadi bukan insiden (A keliru). Tetapi memakai akun admin dari workstation biasa melanggar kebijakan dan meninggalkan kredensial admin di host yang juga membuka web dan email, risiko reuse yang sama dengan yang membuat `INC-2026-017` meluas, jadi menutupnya sebagai jinak (B) mengulang pelajaran itu. Pelanggaran kebijakan punya tindak lanjut sendiri: perbaikan oleh pemilik proses dan detection agar terpantau. Lihat bagian 1.6 dan 2.4.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Gilang Ramadhan (analyst L1), dalam tiga kalimat, kenapa tipe logon penting saat memburu lateral movement.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Field LogonType di event 4624 memberi tahu sifat sesi: tipe 2 itu orang login lokal di depan mesin, tipe 3 itu dari jaringan seperti akses share atau WMI, dan tipe 10 itu RDP. Lateral movement hampir selalu memakai tipe 3 atau 10, karena penyerang berpindah dari jauh, bukan duduk di depan mesin. Kalau kita tidak memakai tipe logon, satu akun yang tiba-tiba logon jaringan ke banyak host akan tercampur dengan logon lokal biasa, dan kita kehilangan pola yang paling penting."

Kesalahan yang sering muncul:
- Menyebut semua tipe logon sama pentingnya, padahal tipe 3 dan 10 yang menandai pergerakan.
- Lupa bahwa tipe 9 (NewCredentials) juga relevan untuk pemakaian kredensial alternatif.
- Membaca akun `Subject` alih-alih `New Logon` pada 4624.

</details>

**6. Pertanyaan jebakan.** "Password spray selalu memunculkan event 4625 di domain controller, jadi cukup pantau 4625 di DC." Benarkah?

<details><summary>Jawaban</summary>

Tidak sepenuhnya. 4625 tercatat di host tempat logon gagal; untuk logon jaringan domain memang sampai ke DC, tetapi spray lewat Kerberos justru muncul sebagai 4771 dengan `Failure Code` `0x18`, dan validasi NTLM muncul sebagai 4776, keduanya di DC. Spray terhadap akun cloud lewat Entra muncul sebagai sign-in dengan kode AADSTS di `index=o365`, bukan di 4625 sama sekali. Jalankan ketiga jalur, jangan hanya 4625. Lihat bagian 1.4 dan 2.3.

</details>

**7. Interview question (English).** "Your organization doesn't have a dedicated identity threat detection product. How would you hunt for lateral movement using just Windows logs and Sysmon?"

<details><summary>Sample answer</summary>

"I start from the data I actually have: logon events on the target hosts and domain controllers, plus Sysmon process and process-access events. For lateral movement the key field is LogonType in event 4624, where type 3 is network and type 10 is RDP, so I look for one source authenticating to many destinations in a short window, and for accounts suddenly logging on with a type they never used before. I always join that with asset and identity context, because admins and service accounts legitimately move across many hosts, so the real signal is movement from a source that policy doesn't allow, like an admin account coming from a normal workstation instead of the jump host. Then I chain it to credential access: a process opening a handle to lsass.exe with memory-read rights on one host, followed by a network logon out of that host within a short window. Even without an identity analytics product, the raw events are there; what I'm providing is the correlation and the context, and a negative result still documents scope and data gaps."

What makes this answer strong: it names concrete events and the LogonType field, insists on asset and identity context to separate admins from attackers, builds the credential-access-to-lateral-movement chain manually, and treats a negative result as a scoped finding.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | MITRE ATT&CK: T1003.001 OS Credential Dumping: LSASS Memory | https://attack.mitre.org/techniques/T1003/001/ | primer | ATT&CK v20, v1.5 (12 Mei 2026); diakses 2026-10-18 | Tinggi. Analitik akses handle penuh (`0x1F0FFF`) ke lsass lalu dump |
| S2 | MITRE ATT&CK: T1110.003 Brute Force: Password Spraying | https://attack.mitre.org/techniques/T1110/003/ | primer | ATT&CK v20, v1.8 (24 Okt 2025); diakses 2026-10-18 | Tinggi. Satu password ke banyak akun, menghindari lockout, menyebut 4625 |
| S3 | MITRE ATT&CK: T1047 Windows Management Instrumentation | https://attack.mitre.org/techniques/T1047/ | primer | ATT&CK v20, v1.6 (12 Mei 2026); diakses 2026-10-18 | Tinggi. Remote WMI via DCOM port 135, WinRM 5985/5986 |
| S4 | MITRE ATT&CK: T1021.002 Remote Services: SMB/Windows Admin Shares | https://attack.mitre.org/techniques/T1021/002/ | primer | ATT&CK v20, v1.3; diakses 2026-10-18 | Tinggi. Admin share C$/ADMIN$/IPC$, perlu kredensial admin |
| S5 | MITRE ATT&CK: T1021.003 Remote Services: DCOM | https://attack.mitre.org/techniques/T1021/003/ | primer | ATT&CK v20, v1.3 (24 Okt 2025); diakses 2026-10-18 | Tinggi. Hanya admin yang bisa aktivasi COM remote secara default |
| S6 | MITRE ATT&CK: T1021.006 Remote Services: WinRM | https://attack.mitre.org/techniques/T1021/006/ | primer | ATT&CK v20, v1.2 (24 Okt 2025); diakses 2026-10-18 | Tinggi. WinRM jalankan perintah, modifikasi service/registry remote |
| S7 | MITRE ATT&CK: T1550 Use Alternate Auth Material dan T1550.002 Pass the Hash | https://attack.mitre.org/techniques/T1550/ ; https://attack.mitre.org/techniques/T1550/002/ | primer | ATT&CK v20, v2.0 (12 Mei 2026); diakses 2026-10-18 | Tinggi. Taktik tunggal Lateral Movement; NTLM LogonType 3 tanpa logon domain |
| S8 | MITRE ATT&CK: T1558.003 Kerberoasting | https://attack.mitre.org/techniques/T1558/003/ | primer | ATT&CK v20, v1.3 (24 Okt 2025); diakses 2026-10-18 | Tinggi. 4769 etype 0x17, satu akun banyak SPN |
| S9 | Microsoft Learn: 4624(S) An account was successfully logged on | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624 | primer | arsip, diperbarui 2026; diakses 2026-10-18 | Tinggi. Tabel LogonType, Subject vs New Logon, catatan IP/workstation per protokol |
| S10 | Microsoft Learn: 4625(F) An account failed to log on | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625 | primer | arsip, diperbarui 2026; diakses 2026-10-18 | Tinggi. Kode Status/SubStatus, tercatat di host tempat logon gagal |
| S11 | Microsoft Learn: 4648(S) A logon was attempted using explicit credentials | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4648 | primer | arsip; diakses 2026-10-18 | Tinggi. Kredensial eksplisit (runas, scheduled task), Target Server Name |
| S12 | Microsoft Learn: 4672(S) Special privileges assigned to new logon | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672 | primer | arsip; diakses 2026-10-18 | Tinggi. Daftar hak sensitif, korelasi 4624 lewat Logon ID |
| S13 | Microsoft Learn: 4768 dan 4769 (Kerberos TGT/TGS) | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768 ; https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769 | primer | arsip; diakses 2026-10-18 | Tinggi. Hanya di DC, etype (0x17 RC4), 0x6 untuk username tak dikenal, 0x10/0x18 pindah ke 4771 |
| S14 | Microsoft Learn: 4771(F) Kerberos pre-authentication failed | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771 | primer | arsip; diakses 2026-10-18 | Tinggi. Hanya di DC, Failure Code 0x18, tidak dibuat untuk akun tak dikenal |
| S15 | Microsoft Learn: 4776(S, F) The computer attempted to validate the credentials | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4776 | primer | arsip; diakses 2026-10-18 | Tinggi. NTLM, di DC untuk akun domain, Source Workstation tanpa IP |
| S16 | Microsoft Learn: Sysmon (EID 10 ProcessAccess) | https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon | primer | diperbarui 2026-09-10; diakses 2026-10-18 | Tinggi. EID 10 untuk deteksi baca memori LSASS, perlu filter |
| S17 | Microsoft Learn: Process Security and Access Rights | https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights | primer | diperbarui 2025-07-14; diakses 2026-10-18 | Tinggi. Nilai PROCESS_VM_READ 0x0010 dll., PROCESS_ALL_ACCESS |
| S18 | Microsoft Learn: Configure added LSA protection | https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection | primer | diperbarui 2026-10-12; diakses 2026-10-18 | Tinggi. RunAsPPL, default di Windows 11 22H2, Credential Guard/LSAIso |
| S19 | Microsoft Entra: authentication and authorization error codes | https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes | primer | diperbarui 2026-06-15; diakses 2026-10-18 | Tinggi. AADSTS50126/50053/50034/50055/50057/50076 |
| S20 | Atomic Red Team: T1047 | https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md | primer | diakses 2026-10-18 | Tinggi. Test dan GUID; node default 127.0.0.1 (lokal kecuali diubah) |
| S21 | Atomic Red Team: T1021.002 | https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.002/T1021.002.md | primer | diakses 2026-10-10 | Tinggi. Test SMB/admin share; default lokal, perlu admin |
| S22 | Atomic Red Team: T1021.006 | https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.006/T1021.006.md | primer | diakses 2026-10-18 | Tinggi. Test WinRM; Invoke-Command dan Evil-WinRM dengan GUID |
| S23 | Atomic Red Team: T1110.003 | https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1110.003/T1110.003.md | primer | diakses 2026-10-18 | Tinggi. Test spray; Test 1 native net use (dapat mengunci akun) |
| S24 | Microsoft Learn: Sysinternals (What's New, versi Sysmon) | https://learn.microsoft.com/en-us/sysinternals/ | primer | diperbarui 2026-10-15; diakses 2026-10-18 | Tinggi. Sysmon v15.2 (26 Mar 2026) |

**Catatan sumber:** makna bit `GrantedAccess` mengikuti konstanta hak akses proses Windows [S17]; nilai mana yang dianggap mencurigakan bergantung tool keamanan di lingkunganmu, jadi bangun allowlist dari data lab. Nama field 4624/4625/4776 dan perilaku parsing bergantung add-on, cek di lingkunganmu. Halaman event Microsoft adalah arsip Windows 10 yang tetap berlaku untuk Event ID dan field yang stabil; field baru 4768/4769 (enkripsi dan hash tiket) ditambahkan sejak cumulative update Januari 2025 [S13]. Default test Atomic Red Team (node `127.0.0.1`) menjalankan test secara lokal kecuali parameter diubah, dan beberapa test spray dapat mengunci akun [S20][S23]. Seluruh isi `HUNT-2027-017`, `HUNT-2027-018`, dan `HUNT-2027-019` (host, angka, akun, label) adalah penerapan catatan ini pada organisasi fiktif, bukan hasil eksekusi nyata.
