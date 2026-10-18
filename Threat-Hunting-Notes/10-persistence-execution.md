---
day: 10
title: 'Hunting persistence dan execution: autostart, scheduled task, service, WMI subscription, dan interpreter, lintas log dan endpoint'
researched_on: 2026-10-18
versions_checked: 'MITRE ATT&CK v20 (T1547.001 v2.1, T1053.005 v1.8, T1543.003 v1.6, T1546.003 v1.5, T1059.001 v1.6; DET0365, DET0441, DET0552, DET0086, DET0455); Sysmon (halaman Microsoft Learn 2026-09-10; EID 1/11/12/13/19-21); Microsoft Learn event 4697, 4698, 4699, 4702 (arsip Windows 10, diperbarui 2026-04-27); about_Logging (Windows PowerShell 5.1) dan about_Logging_Windows (PowerShell 7.6); Velociraptor 0.77.3 (5 Okt 2026; artifact Windows.Sys.StartupItems, Windows.System.TaskScheduler, Windows.Sysinternals.Autoruns, Windows.Persistence.PermanentWMIEvents, Windows.EventLogs.PowershellScriptblock); Atomic Red Team (T1547.001, T1053.005, T1059.001, T1543.003, T1546.003); Splunk Enterprise 10.6 (SPL; streamstats dicek di dokumentasi 10.2)'
---

# Day 10: Hunting persistence dan execution (autostart, scheduled task, service, WMI, dan interpreter)

Cakupan: hunting teknik persistence dan execution Windows yang paling sering dipakai penyerang (Run key dan folder Startup, scheduled task, service, WMI event subscription, PowerShell), data yang menangkap masing-masing beserta blind spot-nya, cara membedakan persistence sah dari penyerang, rantai execution lalu persistence, dan jalur dari hunt ke detection.

## Ide inti

Penyerang bisa mengganti domain C2, IP, dan hash setiap kampanye, tetapi ia tidak bisa menghindari satu hal bila ingin bertahan setelah reboot: ia harus menulis sesuatu ke konfigurasi host. Nilai di Run key, file XML di folder Tasks, entri service di registry, atau objek di repositori WMI. Jejak itu ada di disk selama persistence-nya hidup, dan bisa dibaca serta dibandingkan antar host tanpa tahu satu IOC pun. Karena itu hunting persistence bekerja dengan dua pertanyaan sederhana: entri autostart mana yang baru atau hanya ada di sedikit host, dan siapa yang membuatnya. Execution memberi konteks yang membuat jawaban itu bisa dinilai: proses apa yang berjalan tepat sebelum entri itu ditulis, dan apa yang dijalankan entri itu setelahnya. Setiap sumber data hanya melihat sebagian rantai ini, jadi peta "teknik ke data ke blind spot" harus ditulis dulu sebelum kesimpulan "tidak ditemukan" berani diucapkan.

Kamu sudah melakukan ini di NOC. Saat mencari perangkat dengan konfigurasi paling langka di inventaris, kamu tidak menunggu alarm; kamu menarik startup-config semua router satu POP, membandingkannya dengan template, lalu bertanya siapa yang menambahkan baris yang tidak ada di template itu. Proses yang berjalan di router bisa hilang setelah reload, tetapi baris di startup-config membuatnya kembali. Batas analoginya ada dua. Pertama, di endpoint Windows "template" tidak pernah bersih: installer, updater per-user, dan agent sah terus menulis autostart baru, jadi yang langka atau baru belum tentu jahat. Kedua, penyerang bisa menyembunyikan barisnya dari alat baca biasa (task yang disembunyikan dari `schtasks /query`, objek WMI yang tidak terlihat di daftar startup), sehingga pembacaan harus memakai lebih dari satu cara.

```
   EXECUTION (sekali)                      PERSISTENCE (bertahan)               EXECUTION (berulang)
   dokumen / installer / skrip  -------->  menulis konfigurasi autostart -----> dijalankan ulang saat
   PowerShell, wscript, cmd                Run key, Startup, task, service,     logon, jadwal, boot,
          |                                WMI subscription                     atau event WMI
          |                                          |                                  |
   Sysmon EID 1, 4688, 4104               Sysmon EID 11/12/13/19-21, 4698/4702,   EID 1 dengan parent
   (siapa menjalankan apa)                7045, keadaan di disk (Velociraptor)    svchost/services/WmiPrvSE
          |                                          |                                  |
          +---------------- korelasi waktu pada satu host ---------------------------+
                                                     |
                     stacking: baru? langka? lokasi yang bisa ditulis pengguna? pembuatnya siapa?
                                                     |
                 label: jinak | perlu investigasi | inkonklusif | data tidak cukup  ->  laporan, detection
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan. SOC PT JAB memakai Splunk Enterprise dengan Enterprise Security (ES). Sysmon terpasang di 61 server Windows dan 153 workstation Jakarta (OU `Workstations-EDR`); GPO audit `JAB-WS-Audit`, yang menghasilkan 4688 dengan command line dan 4698 saat scheduled task dibuat, hanya ditautkan ke OU itu, sedangkan server punya baseline audit sendiri. Sebanyak 229 workstation lain (Jakarta 148, Bandung 58, POP Surabaya dan Medan 23) tidak punya Sysmon dan tidak menghasilkan 4698. Sejak akhir Februari 2027, server Velociraptor `jkt-velo02` dipakai khusus untuk hunting dan client-nya dipasang ke workstation dan server Windows, sehingga keadaan host tanpa Sysmon kini bisa dibaca langsung. Kamis 2027-02-25, hunt Velociraptor `HUNT-2027-013` menemukan scheduled task `\PDFSuite Updater` dan folder `C:\Users\rani.oktaviani\AppData\Local\PDFSuite\` di laptop sales POP Surabaya `SBY-WS-0107`. Installer-nya dijalankan dari rumah Sabtu 2026-12-05, sehari setelah kasus installer PDF palsu `INC-2026-026`, dan konfigurasinya menunjuk domain C2 yang tidak ada di daftar IOC kasus itu. IR membuka `INC-2027-040` (SEV-3, team lead Rudi Hartanto). Selasa 2027-03-02 pukul 08:10, SOC lead Dimas Prasetyo menulis kepadamu:

> "Pak Hendra baca ringkasan `INC-2027-040` kemarin sore dan tanyanya tajam: laptop Surabaya itu lolos dari pencarian IOC, ketemunya justru dari pola scheduled task. Jadi dia mau tahu, teknik persistence apa lagi yang mungkin masih nongkrong di laptop kita tanpa ketahuan? Kalau banyak, mana yang kita buru dulu, dan caranya bagaimana kalau kita tidak punya IOC? Data apa yang menangkap masing-masing, dan di mana kita buta, mengingat Sysmon cuma di Jakarta dan audit task juga cuma di OU itu? Satu lagi dari aku: tiap installer dan updater juga bikin task dan Run key, jadi bagaimana kamu membedakan yang sah dengan yang dari penyerang? PDFSuite itu kan juga awalnya cuma installer yang dijalankan user. Terakhir, dari hunt hari ini apa yang layak jadi detection supaya kasus seperti Surabaya tidak menunggu kebetulan hunt lagi? Tolong kirim jawabannya sore ini bareng hasil hunt."

Pesan itu memuat tujuh pertanyaan:

1. Teknik persistence apa saja yang umum, dan mana yang bisa lolos seperti `\PDFSuite Updater`?
2. Apa hubungan execution dengan persistence, dan teknik execution mana yang perlu diburu bersama?
3. Mana yang diburu lebih dulu?
4. Bagaimana memburunya tanpa IOC?
5. Data apa yang menangkap tiap teknik di PT JAB, dan di mana blind spot-nya?
6. Bagaimana membedakan persistence sah (installer, updater, agent) dari penyerang?
7. Apa yang layak menjadi detection?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2 dan 1.5, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4 dan 1.5, pertanyaan 5 di bagian 1.6, pertanyaan 6 di bagian 1.7, dan pertanyaan 7 di bagian 1.8. Bagian 2 menjalankan tiga hunt hari Selasa itu (`HUNT-2027-014` Run key, `HUNT-2027-015` pembuat scheduled task, `HUNT-2027-016` PowerShell 4104), satu pencarian rantai execution lalu persistence, laporan, usulan detection untuk Sari Kusuma, dan jawaban untuk Dimas.

**Kapan relevan:** saat ada temuan atau intel yang menyebut persistence (seperti `INC-2027-040`), saat pencarian IOC sudah dijalankan tetapi kamu ingin tahu apa yang tidak tertangkap IOC, saat menilai celah detection untuk taktik Persistence dan Execution, dan saat alat baru (di sini Velociraptor) membuka akses ke host yang sebelumnya buta.
**Kapan bukan jawaban:** saat rule yang ada sudah menutup prosedur yang dimaksud dan pertanyaannya hanya "apakah rule ini jalan" (itu validasi atau triage); saat host sudah dinyatakan bagian insiden (itu scoping IR di bawah IC); dan saat data untuk teknik itu belum ada sama sekali, karena hasilnya hanya bisa "data tidak cukup" dan yang dibutuhkan adalah perbaikan telemetri (Day 04).

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (threat hunting, hipotesis, stacking, long tail, baseline, first-seen, normalisasi, prevalence, handover) tidak diulang. Tabel ini hanya memuat istilah baru di Day ini; kolom kanan memetakannya ke pengalaman NOC dan SOC.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Persistence (TA0003) | Taktik ATT&CK untuk tetap bertahan di sistem setelah reboot, logoff, atau ganti kredensial | Baris yang ditambahkan ke startup-config router |
| Execution (TA0002) | Taktik ATT&CK untuk menjalankan kode di sistem | Perintah yang diketik di sesi CLI aktif |
| Autostart (ASEP) | Lokasi konfigurasi yang membuat program berjalan otomatis saat boot atau logon, misalnya Run key dan folder Startup | Startup-config dan skrip boot perangkat |
| Run key | Kunci registry `...\CurrentVersion\Run` dan variannya yang menjalankan program saat logon | Baris `boot system` atau EEM applet yang dijalankan saat boot |
| Scheduled task | Pekerjaan terjadwal Windows yang didefinisikan sebagai XML di `C:\Windows\System32\Tasks` dan registry `TaskCache` | Cron job atau `kron` di router |
| Task root | Task yang berada langsung di akar Task Scheduler Library, dengan nama seperti `\NAMA_TASK` | Job yang tidak berada di folder standar vendor |
| Hidden task | Task yang disembunyikan dari `schtasks /query` dan UI dengan menghapus atau mengubah nilai Security Descriptor (SD) di registry | Job yang tidak muncul di `show` biasa tetapi tetap jalan |
| Windows service | Program yang dijalankan Service Control Manager (`services.exe`), didefinisikan di `HKLM\SYSTEM\CurrentControlSet\Services` | Daemon yang didaftarkan ke init sistem |
| WMI event subscription | Tiga objek WMI (filter, consumer, binding) yang menjalankan perintah saat event tertentu terjadi | Trigger EEM: bila kondisi X terjadi, jalankan aksi Y |
| Script block logging | Pencatatan isi blok skrip PowerShell ke event 4104 | Logging perintah CLI lengkap (AAA accounting command) |
| Download cradle | Pola PowerShell satu baris yang mengunduh lalu menjalankan skrip dari jaringan | Perintah `copy tftp: run` dalam satu baris |
| AMSI | Antimalware Scan Interface: antarmuka yang membuat engine skrip menyerahkan isi skrip ke antivirus sebelum dijalankan | Inspeksi konten di proxy sebelum diteruskan |
| User-writable location | Folder yang bisa ditulis pengguna biasa tanpa hak admin, misalnya `AppData`, `Temp`, `Users\Public` | Partisi flash yang bisa ditulis siapa pun yang punya akses CLI |
| Positive control | Uji yang memastikan query sanggup menangkap pola yang dicari, memakai kasus yang diketahui positif | Loopback test sebelum menyalahkan link |

### 1.1 Teknik persistence yang umum diburu

Pertanyaan pertama Dimas lahir dari `\PDFSuite Updater`: task itu tidak membawa IOC yang dikenal, tetapi ia tetap harus terdaftar di Task Scheduler agar berjalan. Pertanyaannya, lokasi konfigurasi apa lagi yang punya sifat sama.

ATT&CK menyusun persistence sebagai taktik TA0003 dengan banyak teknik [S1]. Tabel berikut memuat lima yang paling sering diburu di Windows, beserta data utama dan blind spot umumnya; baca kolom kanan, karena setiap baris di sana adalah kandidat hunt [S1][S2].

| Teknik | ID | Data utama | Blind spot umum |
|---|---|---|---|
| Boot/Logon Autostart (Run key, Startup) | T1547.001 | Sysmon EID 13 (registry), EID 11 (Startup), autoruns | Lokasi autostart yang jarang; file tanpa ekstensi dicari |
| Scheduled Task | T1053.005 | Security 4698, TaskScheduler 106, Sysmon EID 1 (schtasks) | Task via COM/API tanpa schtasks.exe |
| Service | T1543.003 | System 7045, Sysmon EID 1 (sc.exe) | Service dari binary di lokasi sah |
| Event-Triggered (WMI subscription) | T1546.003 | Sysmon EID 19/20/21, WMI artifact | Butuh WMI logging aktif |
| Winlogon/registry lain | T1547.004 dan lainnya | Sysmon EID 13, autoruns | Banyak kunci; perlu baseline |

Detail per teknik yang menentukan cara memburunya, menurut halaman teknik ATT&CK v20:

- **T1547.001 Registry Run Keys / Startup Folder** (taktik Persistence dan Privilege Escalation). Kunci bawaan yang dipakai: `Run` dan `RunOnce` di `HKCU` dan `HKLM` (`...\Software\Microsoft\Windows\CurrentVersion\`), serta `RunOnceEx` di `HKLM` yang tidak dibuat secara default sejak Vista [S8]. Folder Startup per pengguna ada di `C:\Users\<nama>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`, dan untuk semua pengguna di `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp` [S8]. ATT&CK juga mencatat kunci yang lebih jarang dipantau: `RunServices` dan `RunServicesOnce`, `...\Policies\Explorer\Run`, nilai `Load` di `...\Windows NT\CurrentVersion\Windows`, nilai `BootExecute` di `Session Manager`, dan kunci `User Shell Folders`/`Shell Folders` yang bisa memindahkan lokasi folder Startup itu sendiri [S8].
- **T1053.005 Scheduled Task** (taktik Execution, Persistence, dan Privilege Escalation). Task bisa dibuat lewat `schtasks`, wrapper .NET, library netapi32, WMI, atau cmdlet PowerShell seperti `Invoke-CimMethod` [S9]. Task juga bisa disembunyikan dari `schtasks /query` dan UI Task Scheduler dengan menghapus nilai Security Descriptor (SD) di registry, yang butuh hak SYSTEM, atau dengan mengubah metadata seperti nilai `Index` [S9].
- **T1543.003 Windows Service** (Persistence dan Privilege Escalation). Konfigurasi service disimpan di registry, dan `sc.exe` adalah salah satu utilitas untuk membuat atau mengubahnya [S10]. Analytic ATT&CK untuk teknik ini memantau perubahan registry di bawah `HKLM\System\CurrentControlSet\Services` [S10].
- **T1546.003 WMI Event Subscription** (Persistence dan Privilege Escalation). Penyerang memasang event filter, consumer, dan binding yang menjalankan kode saat event terjadi; eksekusinya diproksikan oleh WMI Provider Host (`WmiPrvSE.exe`) dan bisa berjalan sebagai SYSTEM [S11]. Analytic-nya memantau pembuatan objek `EventFilter`, `EventConsumer`, dan `FilterToConsumerBinding`, pemakaian `mofcomp.exe`, `Register-WmiEvent`, dan child process tidak lazim dari `WmiPrvSE.exe` [S11].

Task tersembunyi butuh penjelasan sendiri karena ia menyerang cara kita membaca. Saat task dibuat, Windows menulis tiga tempat: kunci `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<nama task>` (nilai `Id`, `Index`, `SD`), kunci `...\TaskCache\Tasks\{GUID}` berisi parameter eksekusi, dan file XML tanpa ekstensi di `C:\Windows\System32\Tasks` [S21]. Malware Tarrask, yang dilaporkan Microsoft pada April 2022 dan dikaitkan dengan HAFNIUM (kini dilacak sebagai Silk Typhoon), menghapus nilai `SD` dengan hak SYSTEM sehingga task hilang dari `schtasks /query` dan Task Scheduler, tetapi tetap berjalan sesuai trigger-nya [S21]. Kunci `Tasks` dan file XML-nya tetap ada kecuali ikut dihapus, dan perintah task tercatat di keduanya [S21]. Akibat praktisnya: pembacaan lewat daftar task biasa bisa buta, sedangkan pembacaan file XML dan pemeriksaan kunci `Tree` tanpa nilai `SD` masih melihatnya.

Prinsip Day 01 berlaku di sini: hunting bergerak ke prosedur yang belum tertutup rule, bukan mengulang yang sudah terdeteksi. `\PDFSuite Updater` adalah contoh yang paling biasa dari T1053.005, bukan yang tersembunyi. Ia lolos bukan karena tekniknya canggih, tetapi karena host-nya tidak punya data untuk teknik itu dan IOC-nya berbeda. Jadi jawaban untuk pertanyaan pertama Dimas: kelima teknik di tabel bisa lolos dengan cara yang sama di 229 workstation tanpa Sysmon dan tanpa 4698, dan yang paling mungkin dipakai varian `INC-2026-026` lain adalah yang paling sederhana, karena itu yang terbukti berhasil.

### 1.2 Teknik execution yang umum diburu

Dimas bertanya bagaimana execution dirangkai dengan persistence. Di `SBY-WS-0107`, urutannya jelas: pengguna menjalankan installer (execution), installer membuat task (persistence), lalu task menjalankan biner di `AppData` secara berkala (execution lagi).

Tabel berikut memuat teknik execution yang paling sering muncul di rantai seperti itu; baca kolom Catatan untuk tahu sisi mana yang terlihat di data [S1].

| Teknik | ID | Data utama | Catatan |
|---|---|---|---|
| Command/Scripting Interpreter (PowerShell) | T1059.001 | PowerShell 4104, Sysmon EID 1 | Script block yang dijalankan engine, termasuk kode yang dibentuk saat runtime |
| Windows Command Shell | T1059.003 | Sysmon EID 1, 4688 | Parent-child dan command line |
| WMI | T1047 | Sysmon EID 1 (WmiPrvSE parent, wmic) | Dua sisi: diluncurkan WMI dan utilitas wmic |
| Scheduled Task (sebagai execution) | T1053.005 | sama dengan persistence | Teknik yang sama dipetakan ke beberapa taktik |
| User Execution | T1204 | Sysmon EID 1 (parent Office/browser), EID 11 | Dokumen atau unduhan yang dijalankan user |

Untuk PowerShell, halaman T1059.001 v20 mencatat dua hal yang penting untuk hunting [S12]. Pertama, perintah ter-encode Base64 dan download cradle (unduh lalu jalankan) muncul berulang di contoh prosedur. Kedua, PowerShell bisa dijalankan tanpa memanggil `powershell.exe` sama sekali, lewat antarmuka ke assembly `System.Management.Automation`. Hunt yang hanya mencari `powershell.exe` di Sysmon EID 1 akan buta terhadap cara kedua; 4104 ditulis oleh engine PowerShell, sehingga menjadi sumber yang lebih dekat ke isi yang dijalankan (bagian 1.6).

Execution dan persistence sering tumpang tindih: scheduled task adalah keduanya. Hunting yang baik mengikuti rantai: proses dieksekusi, lalu membuat persistence, atau persistence menjalankan sesuatu yang kemudian berperilaku aneh. Rantai itu dibahas di bagian 1.5.

### 1.3 Memilih urutan hunt

Pertanyaan ketiga Dimas ("kalau banyak, mana dulu") butuh alasan yang bisa dipertahankan di depan Hendra, bukan selera. Waktu yang tersedia satu hari hunting, dan tiga hunt sudah dialokasikan.

Tiga kriteria dipakai, berurutan:

1. **Bukti dari lingkungan sendiri.** Teknik yang sudah terbukti dipakai di PT JAB didahulukan. `INC-2027-040` memakai scheduled task dengan biner di `AppData`; varian lain dari kampanye yang sama kemungkinan besar memakai pola yang sama.
2. **Celah data yang baru tertutup.** Velociraptor baru menjangkau 229 workstation tanpa Sysmon. Teknik yang jejaknya ada di disk (task, Run key, folder Startup) kini bisa diperiksa di host itu untuk pertama kalinya; teknik yang hanya terlihat sebagai event sesaat tetap buta di sana.
3. **Biaya dan kebisingan.** Hunt yang datanya sudah siap dan volumenya bisa ditinjau satu orang dalam satu hari didahulukan dari hunt yang butuh perbaikan telemetri dulu.

Tabel berikut menerapkan ketiga kriteria ke lima teknik di bagian 1.1; baca kolom Keputusan.

| Teknik | Bukti di PT JAB | Data siap (log + disk) | Biaya | Keputusan |
|---|---|---|---|---|
| Scheduled task T1053.005 | Ya (`INC-2027-040`) | 4698 di 214 host; XML task di semua client Velociraptor | Sedang | `HUNT-2027-015`, pertama |
| Run key dan Startup T1547.001 | Pola umum installer PDF palsu; belum terlihat di PT JAB | EID 13 di host ber-Sysmon; `Windows.Sys.StartupItems` di semua client | Sedang | `HUNT-2027-014`, kedua |
| PowerShell T1059.001 | Tahap unduh di banyak kampanye; backlog unduhan PowerShell dari `HUNT-2027-002` | 4104 di 214 host; log lokal di host lain | Tinggi (volume besar) | `HUNT-2027-016`, ketiga |
| Service T1543.003 | Belum ada | 7045 dari System log; registry Services | Rendah | Backlog |
| WMI subscription T1546.003 | Belum ada | Sysmon EID 19-21 jarang; artifact Velociraptor | Rendah | Backlog |

Service dan WMI subscription bukan tidak penting; keduanya butuh hak admin, sedangkan kampanye installer palsu berjalan di konteks pengguna biasa. Itu alasan urutan, bukan alasan mengabaikan. Keduanya masuk backlog dengan abstract singkat di laporan (bagian 2.8).

### 1.4 Pola hunting untuk persistence

Pertanyaan keempat Dimas adalah inti Day ini: bagaimana menemukan `\PDFSuite Updater` berikutnya tanpa tahu namanya. Jawabannya dua pendekatan dari Day 05, diterapkan ke konfigurasi autostart.

1. **First-seen autostart lintas fleet.** Kumpulkan semua entri autostart (autoruns via Velociraptor, atau Sysmon EID 13 di SIEM), lalu cari yang baru dibanding baseline atau hanya ada di sedikit host. Persistence penyerang biasanya unik per host, sedangkan software sah biasanya tersebar di banyak host karena dipasang lewat paket resmi.
2. **Stacking pembuat persistence.** Untuk scheduled task dan service, hitung siapa yang membuatnya: akun, proses induk, dan lokasi biner yang dijalankan. Task yang dibuat akun pengguna biasa, di root Task Scheduler Library, dan menjalankan biner dari folder yang bisa ditulis pengguna adalah kombinasi yang menonjol. Microsoft sendiri menyarankan memantau task baru di root, karena task yang dibuat manual atau oleh malware sering berada di sana [S3].

Kekuatan menjangkau endpoint ada di sini: autostart dan scheduled task dibaca dari disk, sehingga menangkap yang dibuat via COM/API yang tidak muncul di log command line. Ini blind spot klasik telemetri proses: Sysmon EID 1 dan 4688 hanya mencatat proses baru, sedangkan task yang didaftarkan lewat Task Scheduler COM API dari dalam proses yang sudah berjalan tidak memunculkan `schtasks.exe` sama sekali.

Ada bedanya antara dua pendekatan itu untuk host tanpa Sysmon. Pembacaan disk lewat Velociraptor adalah snapshot: ia melihat apa yang terpasang saat hunt dijalankan, tanpa tahu kapan entri itu dibuat. Artifact `Windows.Sys.StartupItems`, misalnya, mengeluarkan kolom `Name`, `OSPath`, `Details`, `Enabled`, dan `Upload`, tanpa timestamp [S23]. Di host seperti itu, "first-seen" diganti dengan "prevalence rendah": entri yang hanya ada di satu sampai tiga host dari ratusan. Di host ber-Sysmon, EID 13 memberi waktu penulisan, sehingga first-seen sungguhan bisa dihitung terhadap baseline.

### 1.5 Pola hunting untuk execution, dan rantainya dengan persistence

Pertanyaan kedua Dimas punya sisi praktis: di `SBY-WS-0107` tidak ada data execution sama sekali, jadi rantai hanya bisa direkonstruksi dari disk. Di 214 host ber-Sysmon, rantai itu bisa dicari langsung di log.

Tiga pola execution yang dipakai:

1. **Parent-child tidak lazim.** Stacking pasangan parent-child (Day 05 dan 06): Office memunculkan shell, `WmiPrvSE` memunculkan interpreter, `services.exe` memunculkan proses dari lokasi aneh.
2. **Interpreter dengan ciri mencurigakan.** PowerShell 4104 dengan encoding, download cradle, eksekusi string di memori (`Invoke-Expression`), atau rujukan ke AMSI; `cmd`/`wscript` dengan argumen tidak lazim.
3. **Eksekusi dari lokasi user-writable.** Proses yang image-nya di `\Users\Public\`, `\AppData\`, `\Temp\`.

Rantai yang sering diburu bersama: user execution (Office atau script host memunculkan sesuatu) yang diikuti persistence (Run key atau task dibuat) dalam waktu dekat. Ini korelasi temporal pada satu host. Sisi sebaliknya juga berguna: proses yang dijalankan oleh persistence punya parent yang khas. Task dijalankan dari `svchost.exe` (layanan Schedule) atau `taskeng.exe` di Windows lama, dan detection strategy ATT&CK untuk T1053.005 memakai urutan "task dibuat atau diubah, lalu dieksekusi dari `svchost.exe` atau `taskeng.exe`" [S9]. Service dijalankan dari `services.exe`, dan WMI subscription dari `WmiPrvSE.exe` [S11].

Batas korelasi temporal perlu ditulis. Jendela 10 menit menangkap installer yang langsung menulis Run key, tetapi tidak menangkap tahap kedua yang menunggu berjam-jam, dan installer sah yang dijalankan pengguna menghasilkan rantai yang persis sama. Rantai menaikkan prioritas tinjauan, bukan vonis.

### 1.6 Data dan blind spot per teknik di PT JAB

Pertanyaan kelima Dimas paling sering dijawab terlalu optimis. Setiap sumber punya batas (Day 04):

- **Command line (Sysmon EID 1, 4688):** melihat eksekusi lewat proses, buta terhadap aksi via API tanpa proses baru.
- **Log event spesifik (4698, 7045):** menangkap pembuatan apa pun caranya, tetapi tidak memberi command line pembuat. Event 4698 (Security log, "A scheduled task was created") ditulis setiap kali task baru dibuat dan hanya muncul bila subcategory audit `Other Object Access Events` aktif; isinya `SubjectUserName` (pembuat), `TaskName`, dan `TaskContent` berupa XML definisi task termasuk trigger dan action [S3]. Sejak Windows 10 1903, 4698 juga membawa `ClientProcessId` dan `ParentProcessId` [S3], tetapi itu hanya angka PID; nama prosesnya tetap harus dicari di Sysmon EID 1 atau 4688 pada host yang sama. Subcategory yang sama juga menghasilkan 4699 saat task dihapus (dengan `TaskContent` task yang dihapus) dan 4702 saat task diubah (dengan isi baru di `TaskContentNew`) [S14][S13]. Event 7045 (System log, sumber Service Control Manager) mencatat service baru beserta nama, path image, tipe start, dan akun, dan muncul tanpa perlu audit policy tambahan; subject-nya sering SYSTEM sehingga tidak menunjukkan siapa yang memulai pemasangan [S16]. Padanannya di Security log adalah 4697 dari subcategory `Audit Security System Extension`, dengan field `ServiceName`, `ServiceFileName`, `ServiceType`, `ServiceStartType`, dan `ServiceAccount`; path yang diubah setelah service dibuat tidak dicatat di event itu [S15].
- **Artifact endpoint (autoruns, task di disk):** paling lengkap untuk state persistence, tetapi snapshot (Day 09). `Windows.System.TaskScheduler` membaca file XML di `C:/Windows/System32/Tasks/**` lalu mengeluarkan `TaskName`, `Command`, `Arguments`, `UserId`, `ComHandler`, `RegistrationTime`, `Authenticode`, dan kolom lain [S22]. Artifact itu tidak membaca registry `TaskCache` [S22], jadi task yang file XML-nya sudah dihapus tetapi masih terdaftar di registry butuh pemeriksaan registry terpisah.
- **PowerShell 4104:** isi script block di log `Microsoft-Windows-PowerShell/Operational` untuk Windows PowerShell 5.1. Pencatatan penuh butuh policy `Turn on PowerShell Script Block Logging` (`Administrative Templates > Windows Components > Windows PowerShell`) [S17]. Tanpa policy itu, engine tetap mencatat script block yang mengandung kata kunci dari daftar internal PowerShell sebagai 4104 level Warning (level 3), jadi data yang ada tidak lengkap [S18][S19]. PowerShell 7 (`pwsh.exe`) menulis ke log terpisah, `PowerShellCore/Operational`, dengan setting Group Policy-nya sendiri di `Administrative Templates > PowerShell Core` [S4][S18]. Kode yang disamarkan tercatat dalam bentuk aslinya; kode yang dibentuk saat runtime lalu dijalankan (misalnya string hasil decode yang diberikan ke `Invoke-Expression`) tercatat sebagai script block tersendiri, sehingga lapisan penyamaran terlihat bertahap di beberapa event [S18]. Script panjang dipecah ke beberapa event 4104 dengan `ScriptBlockId` yang sama [S18][S19].

Untuk Sysmon, event yang dipakai Day ini: EID 1 (process create, dengan `CommandLine`, `ParentImage`, `User`, hash), EID 11 (file create; Microsoft menyebutnya berguna untuk memantau lokasi autostart seperti folder Startup), EID 12 (pembuatan dan penghapusan kunci atau nilai registry), EID 13 (registry value set, dengan `TargetObject` berisi path kunci dan `Details` berisi data yang ditulis), dan EID 19/20/21 (WMI EventFilter, EventConsumer, dan binding keduanya) [S2]. Sysmon menyingkat root key: `HKEY_LOCAL_MACHINE` menjadi `HKLM` dan `HKEY_USERS` menjadi `HKU`, sehingga Run key per pengguna terlihat sebagai `HKU\<SID>\...`, bukan `HKCU` [S2]. Semua bergantung pada konfigurasi Sysmon: event yang tidak dimasukkan filter konfigurasi tidak tercatat [S2].

Tabel berikut adalah peta PT JAB per Februari 2027; baca kolom Blind spot, karena itulah yang wajib ditulis di setiap laporan "tidak ditemukan".

| Teknik | Log di Splunk (host) | Keadaan di disk (Velociraptor) | Blind spot PT JAB |
|---|---|---|---|
| T1547.001 Run key, Startup | Sysmon EID 12/13 dan 11 dari 214 host (213 sepanjang Februari, `JKT-WS-0532` diam sejak 2 Feb) | `Windows.Sys.StartupItems`, `Windows.Sysinternals.Autoruns` | 229 workstation hanya punya snapshot tanpa waktu; entri yang dibuat lalu dihapus sebelum snapshot tidak terlihat |
| T1053.005 Scheduled task | 4698/4699/4702 dari 214 host (OU `Workstations-EDR` dan server); Sysmon EID 1 `schtasks.exe` | `Windows.System.TaskScheduler` (file XML) | 229 workstation tanpa 4698; task tersembunyi butuh cek registry `TaskCache\Tree`; channel TaskScheduler Operational (106) tidak dikirim ke Splunk |
| T1543.003 Service | 7045 dari System log semua host Windows; 4697 belum dicek | Daftar service dan registry `Services` | Perubahan `ImagePath` service yang sudah ada tidak menghasilkan event pemasangan |
| T1546.003 WMI subscription | Sysmon EID 19-21 (jarang) dari 214 host | `Windows.Persistence.PermanentWMIEvents` | 229 workstation hanya lewat snapshot |
| T1059.001 PowerShell | 4104 dari 214 host (Windows PowerShell 5.1) | Log lokal `Microsoft-Windows-PowerShell/Operational` (level Warning saja di host tanpa policy) | 229 workstation tanpa policy SBL; log PowerShell 7 tidak dikumpulkan dari host mana pun |

Hunting yang baik memadukan sumber: 4698 untuk "task dibuat", Sysmon EID 1 untuk "siapa membuatnya", autoruns atau file XML untuk "apa yang masih terpasang". Untuk `SBY-WS-0107`, hanya kolom ketiga yang tersedia, dan itu cukup untuk menemukan task-nya. Yang tidak bisa dijawab di host itu adalah kapan dan dari proses apa task dibuat; jawaban itu datang dari IR lewat artefak forensik lain.

### 1.7 Persistence sah atau penyerang

Pertanyaan keenam Dimas paling sulit, karena `\PDFSuite Updater` sendiri dibuat oleh installer yang dijalankan pengguna, persis seperti updater sah. Tidak ada satu sinyal yang memisahkan keduanya; yang ada adalah gabungan sinyal, dan tiap sinyal punya pengecualian yang diketahui.

Tabel berikut adalah sinyal yang dipakai di Day ini; baca kolom "Pengecualian sah yang diketahui" sebelum memakai sinyal itu sebagai filter.

| Sinyal | Kenapa menarik | Pengecualian sah yang diketahui |
|---|---|---|
| Prevalence rendah (1 sampai 3 host) | Software resmi dipasang massal; persistence penyerang unik per host | Aplikasi yang dipakai satu tim kecil; tool portabel admin |
| Biner di folder yang bisa ditulis pengguna | Tidak butuh hak admin untuk menaruh dan mengganti biner | Updater per-user (OneDrive, aplikasi rapat), yang memang dipasang di `AppData` |
| Task di root Task Scheduler Library [S3] | Vendor besar biasanya memakai subfolder sendiri | Beberapa updater per-user juga menaruh task di root |
| Pembuat akun pengguna biasa | Admin dan SYSTEM adalah pembuat yang lazim untuk paket resmi | Installer per-user yang sah selalu berjalan sebagai pengguna |
| Biner tanpa tanda tangan atau penerbit tidak dikenal | Software resmi biasanya ditandatangani vendor | Skrip internal; tool open-source; tanda tangan tidak membuktikan niat baik |
| Nama meniru vendor atau komponen sistem | Penyamaran (`Updater`, `Update Service`, nama mirip Microsoft) | Banyak vendor sah memang menamai task "Updater" |
| Tidak ada di daftar software resmi atau tiket change | Paket resmi punya jejak administratif | Shadow IT jinak (aplikasi yang dipasang pengguna sendiri) |
| Rantai dengan dokumen atau unduhan sesaat sebelumnya | Pola user execution lalu persistence (bagian 1.5) | Installer yang diunduh pengguna dari situs resmi |

Cara memakainya: hitung berapa sinyal yang menyala, lalu konfirmasi ke pemilik (pengguna, atasannya, atau tim IT) untuk setiap kandidat yang tersisa. `\PDFSuite Updater` menyalakan lima sinyal sekaligus: satu host, biner di `AppData\Local`, task di root, dibuat pengguna biasa, dan tidak ada di daftar software resmi. Updater OneDrive menyalakan tiga (folder pengguna, root, pembuat pengguna), tetapi prevalence-nya ratusan host dan bineranya ditandatangani Microsoft. Bedanya bukan satu sinyal, tetapi kombinasi dan konfirmasi.

Satu hal yang tidak boleh dipakai sebagai pembeda: nama task atau nama file. Nama sepenuhnya dikendalikan pembuatnya. Nama hanya berguna untuk mengelompokkan setelah normalisasi, bukan untuk memutuskan jinak atau tidak.

### 1.8 Dari hunt ke deteksi

Pertanyaan terakhir Dimas meminta sesuatu yang permanen. Teknik persistence dan execution adalah tempat hunting paling sering melahirkan deteksi, karena rule untuk T1053.005, T1547.001, T1543.003, dan T1047 biasanya sudah ada tetapi hanya menutup prosedur paling umum (misalnya `schtasks.exe /create` atau Run key HKCU). Bila hunt menemukan prosedur yang belum tertutup rule (misalnya autostart di lokasi yang belum dipantau, atau WMI execution tanpa rule), itu handover langsung ke tim atau backlog detection engineering (Day 02 bagian 1.6). Day 14 memperdalam alur hunt ke deteksi.

Syarat sebuah pola dari hunt menjadi detection, sebelum diserahkan ke Sari Kusuma (pemilik konten detection `JAB - ...` di ES):

1. **Volume yang bisa ditriase.** Hitung dari data hunt berapa kali pola itu akan menyala per minggu setelah pengecualian. Pola yang menyala ratusan kali per hari tetap menjadi laporan hunting berkala, bukan alert L1.
2. **Pengecualian yang sempit dan bernama.** Pengecualian ditulis per command line atau path lengkap yang sudah dikonfirmasi, bukan per host atau per pengguna.
3. **Cakupan ditulis jujur.** Detection berbasis 4698 hanya hidup di 214 host yang diaudit. Untuk host lain, kontrolnya adalah hunt berkala lewat Velociraptor, dan itu harus tertulis di usulan, supaya tidak ada yang mengira laptop seperti `SBY-WS-0107` sudah tertutup.
4. **Diuji positif.** Pola diuji di lab dengan aktivitas yang mirip (bagian 3) dan, bila ada, dengan kasus nyata yang diketahui positif.

Detection strategy ATT&CK v20 untuk teknik-teknik ini (DET0365 untuk Run key dan Startup, DET0441 untuk scheduled task, DET0552 untuk service, DET0086 untuk WMI subscription, DET0455 untuk PowerShell) berguna sebagai daftar periksa apakah usulanmu sudah menyentuh sisi pembuatan dan sisi eksekusi [S8][S9][S10][S11][S12].

## 2. Contoh dan langkah praktis: tiga hunt hari Selasa

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Query ditulis untuk Splunk dan Velociraptor PT JAB dengan rentang absolut Februari 2027 (`earliest="02/01/2027:00:00:00" latest="03/01/2027:00:00:00"`, WIB); untuk latihan, jalankan versi yang disesuaikan di lab pribadi (bagian 3). `SBY-WS-0107` sudah ditangani IR di `INC-2027-040` dan tidak dihitung ulang sebagai temuan; host itu hanya dipakai sebagai pembanding dan positive control.

### 2.1 Cek data sebelum berburu: event persistence per sumber

Query ini adalah langkah pertama hari itu, untuk menjawab pertanyaan kelima Dimas dengan angka, bukan dengan asumsi.

**Tujuan:** menghitung event persistence dan execution per sumber dan jumlah host pengirimnya sepanjang Februari 2027.

```
(index=sysmon sourcetype=XmlWinEventLog EventCode IN (12, 13, 19, 20, 21))
OR (index=wineventlog EventCode IN (4698, 4699, 4702, 7045))
OR (index=powershell EventCode=4104)
    earliest="02/01/2027:00:00:00" latest="03/01/2027:00:00:00"
| stats count dc(host) AS hosts BY index EventCode
| sort index EventCode
```

| Bagian | Fungsi |
|---|---|
| Tiga kelompok dalam kurung digabung `OR` | Satu search untuk tiga index dengan Event ID berbeda |
| `EventCode IN (...)` | Operator `IN` di command `search` |
| `stats count dc(host) AS hosts BY index EventCode` | Volume dan sebaran host per Event ID |

Keluaran ilustrasi:

```
index        EventCode   count        hosts
powershell   4104        8.903.442    214
sysmon       12          1.904.377    213
sysmon       13          9.611.208    213
sysmon       19          3            2
sysmon       20          3            2
sysmon       21          3            2
wineventlog  4698        6.482        209
wineventlog  4699        5.917        206
wineventlog  4702        21.336       214
wineventlog  7045        1.288        391
```

**Cara membaca hasil:** Sysmon dari 213 host, bukan 214, karena `JKT-WS-0532` diam sejak Selasa 2027-02-02 (temuan Day 04 yang belum dipulihkan); host itu dipindah ke sisi Velociraptor untuk hunt hari ini. 4698 dari 209 host dan 7045 dari 391 host tidak berarti sisanya tidak diaudit: task dan service baru memang tidak dibuat di setiap host setiap bulan (Day 04 bagian 2.4). Scope ditentukan dari konfigurasi: 4698 hanya mungkin dari 214 host yang diaudit, dan 7045 dari semua host Windows yang mengirim System log. EID 19-21 hanya sembilan event dari dua server, `jkt-app03` dan `jkt-app04`; pemeriksaan profil Sysmon memastikan `WmiEvent` dicatat tanpa filter exclude, jadi angka kecil itu berarti memang jarang, bukan tidak dikonfigurasi. Kesembilannya adalah registrasi ulang subscription milik agent monitoring aplikasi vendor setelah agent dipasang ulang Rabu 2027-02-10, dikonfirmasi ke tim Infrastruktur.

**Variasi:** ganti rentang ke Januari untuk melihat apakah volume Februari wajar; lonjakan 4698 atau 7045 di satu host adalah petunjuk tersendiri.

**Kapan gagal:** search ini berat karena membaca event mentah tiga index selama sebulan. Jalankan di luar jam sibuk atau pecah per minggu. Event ID yang tidak diekstrak sebagai `EventCode` di sourcetype-mu membuat baris hilang tanpa error.

### 2.2 `HUNT-2027-014`: first-seen Run key di host ber-Sysmon

Hunt ini menjawab pertanyaan keempat Dimas untuk T1547.001: mencari nilai Run key yang belum pernah terlihat, tanpa IOC.

```
ID             : HUNT-2027-014
Dibuat         : 2027-03-02 (Selasa) 08:40, pemilik: <kamu>, reviewer: Dimas Prasetyo
Trigger        : Temuan HUNT-2027-013 / INC-2027-040 - persistence lolos dari pencarian IOC
Tipe (PEAK)    : Baseline (first-seen) + stacking prevalence
Hipotesis      : Ada nilai Run key atau entri folder Startup di host Windows PT JAB yang baru muncul
                 dan menunjuk ke lokasi yang bisa ditulis pengguna, menandakan persistence tanpa alert.
ATT&CK         : T1547.001 Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
Data           : (a) Sysmon EID 13, 213 host, 1-28 Feb 2027, dibanding baseline Januari 2027
                 (b) Velociraptor Windows.Sys.StartupItems, snapshot 2 Mar 2027, semua client Windows
Di luar cakupan: kunci autostart selain Run/RunOnce/RunOnceEx/Policies\Explorer\Run dan folder Startup;
                 entri yang dibuat lalu dihapus sebelum snapshot di host tanpa Sysmon; SBY-WS-0107 (IR)
Kriteria sukses: semua kombinasi kunci+data baru dengan data di lokasi user-writable dan host <= 2
                 (Splunk) atau host <= 3 (Velociraptor) ditinjau dan diberi label
Handover       : IR (Dimas) bila ditemukan; Sari untuk usulan detection; IT untuk shadow IT
```

Baseline dibangun pagi itu dari Januari 2027, dengan aturan normalisasi yang sama seperti `jab_norm_parentchild` di Day 05 bagian 2.4, disimpan sebagai macro baru `jab_norm_runkey` supaya baseline dan hunt memakai aturan yang persis sama:

```
eval key_n=replace(lower(TargetObject), "\\\\", "/"), data_n=replace(lower(Details), "\\\\", "/")
| eval key_n=replace(key_n, "^hku/s-1-5-21-[0-9-]+(_classes)?/", "hku/<sid>/")
| eval data_n=replace(data_n, "c:/users/[^/]+/", "c:/users/<user>/")
| eval data_n=replace(data_n, "/[a-z_-]*\d+(\.\d+)+/", "/<ver>/")
| eval data_n=replace(data_n, "/temp/[^/]+/", "/temp/<rnd>/")
```

| Aturan | Fungsi |
|---|---|
| `replace(lower(...), "\\\\", "/")` | Huruf kecil dan backslash menjadi `/`; di string SPL, `\\\\` menjadi regex `\\` yang cocok dengan satu backslash |
| `^hku/s-1-5-21-[0-9-]+(_classes)?/` | SID pengguna di `HKU\<SID>` menjadi `<sid>`, supaya Run key per pengguna yang sama dari banyak orang menjadi satu kunci |
| `c:/users/[^/]+/` tanpa `^` | Profil pengguna menjadi `<user>`; tanpa jangkar awal karena `Details` sering diawali tanda kutip |
| `<ver>` dan `temp/<rnd>` | Sama dengan Day 05 bagian 2.4 |

Pembuatan baseline:

```
index=sysmon sourcetype=XmlWinEventLog EventCode=13
    (TargetObject="*\\CurrentVersion\\Run*" OR TargetObject="*\\Policies\\Explorer\\Run\\*")
    earliest="01/01/2027:00:00:00" latest="02/01/2027:00:00:00"
| `jab_norm_runkey`
| stats count AS writes dc(host) AS hosts min(_time) AS first_seen max(_time) AS last_seen BY key_n data_n
| outputlookup jab_hunt_baseline_runkeys.csv
```

Keluaran ilustrasi: 41.772 event, 1.318 kombinasi `key_n` dan `data_n` disimpan. Pola `*\\CurrentVersion\\Run*` mencakup `Run`, `RunOnce`, `RunOnceEx`, dan `RunServices*`; `Policies\Explorer\Run` ditambahkan terpisah karena tidak mengandung `\CurrentVersion\Run`. Januari dipakai karena `INC-2027-001` tidak melibatkan workstation dan hunt Januari tidak menemukan eksekusi berbahaya (alasan yang sama dengan baseline parent-child di Day 05).

**Tujuan hunt:** kombinasi kunci dan data Run key yang ditulis di Februari dan tidak ada di baseline.

```
index=sysmon sourcetype=XmlWinEventLog EventCode=13
    (TargetObject="*\\CurrentVersion\\Run*" OR TargetObject="*\\Policies\\Explorer\\Run\\*")
    earliest="02/01/2027:00:00:00" latest="03/01/2027:00:00:00"
| `jab_norm_runkey`
| stats count AS writes dc(host) AS hosts values(host) AS host_list values(Image) AS writer
        min(_time) AS firstTime BY key_n data_n
| lookup jab_hunt_baseline_runkeys.csv key_n data_n OUTPUT first_seen AS seenBefore
| where isnull(seenBefore)
| eval loc=case(match(data_n, "c:/users/"), "user",
                match(data_n, "c:/programdata/|/temp/"), "shared-writable",
                true(), "system")
| stats count AS combos sum(writes) AS writes BY loc
```

| Bagian | Fungsi |
|---|---|
| `values(Image) AS writer` | Proses yang menulis nilai itu; EID 13 mencatat `Image` penulis |
| `lookup ... key_n data_n OUTPUT first_seen AS seenBefore` | Dua field pencocokan sekaligus |
| `where isnull(seenBefore)` | Hanya kombinasi yang tidak ada di baseline |
| `eval loc=case(...)` | Kelas lokasi data: folder pengguna, folder bersama yang sering bisa ditulis, atau lokasi sistem |

Keluaran ilustrasi:

```
Event EID 13 Run key Februari : 46.205 dari 213 host
Kombinasi unik                : 1.341 ; tidak ada di baseline: 61

loc              combos   writes
system           38       1.904
user             19       2.377
shared-writable  4        12
```

Langkah berikutnya mempersempit 23 kombinasi di folder yang bisa ditulis ke yang hanya muncul di satu atau dua host:

```
... (sama sampai baris eval loc)
| where loc!="system" AND hosts <= 2
| table firstTime key_n data_n writer hosts host_list writes
| sort firstTime
```

Hasilnya 17 kombinasi. Enam sisanya ada di tiga host atau lebih, dan semuanya rollout aplikasi resmi; yang terbesar klien rapat versi baru per-user di 147 host sejak Senin 2027-02-15. Ke-17 kombinasi ditinjau dengan pivot ke Sysmon EID 1 proses penulis (`writer`) dan konfirmasi pemilik:

- **9 kombinasi:** updater per-user aplikasi dari daftar software resmi, ditulis oleh installer-nya sendiri di folder `AppData\Local\Programs`. Jinak.
- **4 kombinasi:** nilai `RunOnce` sisa installer, yang dihapus otomatis setelah reboot berikutnya (terlihat sebagai EID 12 delete pada kunci yang sama). Jinak.
- **3 kombinasi:** tool portabel admin IT di `Downloads`, dijalankan staf IT dan dikonfirmasi ke atasannya. Jinak.
- **1 kombinasi:** `hku/<sid>/software/microsoft/windows/currentversion/run/calsync` dengan data `c:/users/<user>/appdata/local/calsync/calsync.exe --tray` di `JKT-WS-0583` (`fitri.handayani`, Marketing Jakarta), ditulis Senin 2027-02-22 10:41 oleh installer yang diunduh pengguna dari situs vendor aplikasi sinkron kalender pribadi. Aplikasi itu tidak ada di daftar software resmi. Label: jinak, pelanggaran kebijakan software, diteruskan ke IT; bukan insiden.

**Cara membaca hasil:** 61 kombinasi baru dari 1.341 terdengar banyak, tetapi normalisasi dan dua syarat (lokasi dan prevalence) memperkecilnya menjadi 17 yang benar-benar ditinjau. Tidak ada yang cocok dengan hipotesis. Pola yang sama dengan `\PDFSuite Updater` (biner di `AppData\Local\<nama vendor>`, satu host, tidak ada di daftar software) muncul sekali, dan itu jinak; itulah kenapa konfirmasi pemilik wajib, bukan opsional.

**Variasi:** first-seen folder Startup lewat Sysmon EID 11:

```
index=sysmon sourcetype=XmlWinEventLog EventCode=11
    TargetFilename="*\\Start Menu\\Programs\\Startup\\*"
    earliest="02/01/2027:00:00:00" latest="03/01/2027:00:00:00"
| eval file_n=replace(replace(lower(TargetFilename), "\\\\", "/"), "c:/users/[^/]+/", "c:/users/<user>/")
| stats count dc(host) AS hosts values(Image) AS writer BY file_n
| sort hosts
```

Kunci yang lebih jarang (`Winlogon`, `BootExecute`, `User Shell Folders`) ditambahkan ke filter `TargetObject` dengan baseline sendiri; jangan menggabungkannya dengan baseline Run key, karena volume dan penulis normalnya berbeda.

**Kapan gagal:** baseline dibangun dengan normalisasi berbeda dari hunt, sehingga semua kombinasi terlihat baru; `Details` berisi variabel lingkungan yang belum diekspansi (`%LOCALAPPDATA%\...`), sehingga pola `c:/users/` tidak cocok (tambahkan `%localappdata%|%appdata%|%userprofile%` ke kelas `user`); host yang Sysmon-nya diam (`JKT-WS-0532`) dihitung sebagai "tidak ada yang baru" padahal tidak ada data.

### 2.3 `HUNT-2027-014` sisi Velociraptor: prevalence entri autostart

Bagian ini menutup baris Data (b) di abstract: 229 workstation tanpa Sysmon ditambah `JKT-WS-0532`, yang hanya bisa dibaca dari disk.

**Tujuan:** menemukan entri Run key dan folder Startup yang menunjuk ke lokasi yang bisa ditulis pengguna dan hanya ada di satu sampai tiga host.

Hunt `Windows.Sys.StartupItems` dikirim pukul 09:30 ke semua client Windows. Artifact itu membaca Run key di `HKLM` dan `HKU\*` (termasuk `WOW6432Node` dan `Policies\Explorer\Run*`), status `StartupApproved`, serta folder Startup per pengguna dan `ProgramData` [S23]. Ia dipilih alih-alih `Windows.Sysinternals.Autoruns` karena tidak menjalankan biner apa pun di endpoint; artifact Autoruns mengambil `autorunsc` dari server lalu menjalankannya dengan izin `EXECVE` [S20], yang lebih berat untuk 400-an host sekaligus. Autoruns tetap dipakai untuk host yang perlu cakupan kategori lebih luas.

Di notebook hunt, stacking dilakukan dua tahap seperti di Day 09, karena VQL tidak punya fungsi distinct count:

```
LET rows = SELECT ClientId, Name, OSPath,
       regex_replace(source=lowcase(string=Details),
                     re='users.[a-z0-9._-]+.appdata', replace='users/<user>/appdata') AS DetailsN
FROM source(artifact="Windows.Sys.StartupItems")
WHERE Details =~ '(?i)users.|programdata|temp'

LET per_host = SELECT ClientId, DetailsN,
       format(format="%v|%v", args=[ClientId, DetailsN]) AS Key
FROM rows GROUP BY Key

SELECT DetailsN, count() AS hosts
FROM per_host
GROUP BY DetailsN
ORDER BY hosts
```

| Bagian | Fungsi |
|---|---|
| `source(artifact="Windows.Sys.StartupItems")` | Hasil gabungan hunt dari semua client; `ClientId` menandai asal tiap baris |
| `regex_replace(... re='users.[a-z0-9._-]+.appdata' ...)` | Nama profil menjadi `<user>`. Titik pertama dan terakhir cocok dengan backslash, sehingga tidak perlu escape berlapis; kelas karakter di tengah tetap menerima nama berisi titik seperti `rani.oktaviani` |
| `WHERE Details =~ '(?i)users.\|programdata\|temp'` | Hanya entri yang menunjuk ke folder pengguna, `ProgramData`, atau `Temp` |
| `GROUP BY Key` lalu `count()` per `DetailsN` | Satu baris per pasangan host dan entri, lalu jumlah host per entri |

Keluaran ilustrasi:

```
Client yang menjawab sampai 14:00 : 431 dari 443 host Windows
Baris StartupItems                : 9.884 ; lolos filter lokasi: 2.106
DetailsN unik                     : 1.203 ; dengan hosts <= 3: 58
```

Jumlah client yang menjawab naik dari 379 pada 25 Februari karena laptop yang belum terdaftar sudah dipasangi client selama sepekan terakhir; 12 host yang belum menjawab tetap ditulis sebagai di luar cakupan.

Ke-58 entri ditinjau dengan pivot ke `OSPath`, `Name`, dan hash (untuk file di folder Startup), lalu dicocokkan dengan daftar software resmi:

- **47 entri:** updater per-user aplikasi resmi yang sama dengan sisi Splunk, hanya di path yang belum dinormalisasi (versi di nama folder). Jinak.
- **6 entri:** tool portabel admin IT. Jinak.
- **3 entri:** shortcut `.bat` di folder Startup tiga workstation Bandung yang menjalankan `net use` ke share cabang, dipasang IT lokal Bandung. Jinak; diusulkan dipindah ke logon script GPO.
- **2 entri:** `calsync.exe` di `BDG-WS-0207` dan `BDG-WS-0211`, aplikasi sinkron kalender yang sama dengan `JKT-WS-0583`. Jinak, pelanggaran kebijakan software, ikut diteruskan ke IT.

**Cara membaca hasil:** 47 dari 58 entri langka adalah artefak normalisasi yang lebih lemah di VQL dibanding macro SPL. Itu biaya yang diterima demi query yang sederhana; bila hunt ini diulang, tambahkan aturan `<ver>` ke `regex_replace`. Snapshot ini menjawab "apa yang terpasang per 2 Maret", bukan "apa yang terjadi di Februari".

**Variasi:** cakupan kategori lebih luas dengan `Windows.Sysinternals.Autoruns` untuk sekelompok host prioritas (misalnya 23 workstation POP). Kolomnya berasal dari header CSV `autorunsc` (misalnya `Entry Location`, `Image Path`, `Signer`, `Launch String`), jadi cek nama kolom di tabel hasil sebelum menulis query; daftar persisnya tidak dirinci di dokumentasi artifact [S20]. Kolom `Signer` membantu memisahkan entri bertanda tangan vendor dari yang tidak.

```
LET rows = SELECT ClientId, `Image Path` AS ImagePath,
       format(format="%v|%v", args=[ClientId, `Image Path`]) AS Key
FROM source(artifact="Windows.Sysinternals.Autoruns")

LET per_host = SELECT ClientId, ImagePath FROM rows GROUP BY Key

SELECT ImagePath, count() AS hosts
FROM per_host
GROUP BY ImagePath
ORDER BY hosts
```

**Kapan gagal:** client offline saat hunt (12 host tidak menjawab; Velociraptor menjalankannya saat client kembali online, jadi cek ulang hasil sebelum laporan final); filter `users.` juga cocok dengan path lain yang kebetulan berisi kata itu; entri yang memakai variabel lingkungan tidak cocok dengan pola `users.` sehingga perlu ditambahkan `%localappdata%`.

### 2.4 `HUNT-2027-015`: stacking pembuat scheduled task dari 4698

Hunt ini adalah prioritas pertama hari itu (bagian 1.3). `HUNT-2027-004` (dijalankan Kamis 2027-02-18) memakai 4698 dan Sysmon EID 1 dari host yang diaudit; `HUNT-2027-015` memakai Februari penuh, menambahkan kelas lokasi biner yang dijalankan task, dan menambahkan sisi Velociraptor untuk host tanpa audit (bagian 2.5).

```
ID             : HUNT-2027-015
Dibuat         : 2027-03-02 (Selasa) 08:40, pemilik: <kamu>, reviewer: Dimas Prasetyo
Trigger        : INC-2027-040 (\PDFSuite Updater lolos IOC); kelanjutan HUNT-2027-004
Tipe (PEAK)    : Hypothesis-driven, dengan stacking pembuat dan lokasi command
Hipotesis      : Ada scheduled task di host Windows PT JAB, selain SBY-WS-0107, yang dibuat akun pengguna
                 biasa dan menjalankan biner dari folder yang bisa ditulis pengguna, tanpa alert.
ATT&CK         : T1053.005 Scheduled Task/Job: Scheduled Task (Execution, Persistence, Privilege Escalation)
Data           : (a) Security 4698, 214 host diaudit, 1-28 Feb 2027
                 (b) Velociraptor Windows.System.TaskScheduler/Analysis, snapshot 2 Mar 2027, semua client
                 (c) cek task tersembunyi: TaskCache\Tree tanpa nilai SD
Di luar cakupan: task yang dibuat lalu dihapus di host tanpa audit; channel TaskScheduler Operational
Kriteria sukses: semua kombinasi task+command dengan command di lokasi user-writable dan host <= 3 ditinjau;
                 positive control: query sisi (b) menandai \PDFSuite Updater pada hasil HUNT-2027-013
Handover       : IR (Dimas) bila ditemukan; Sari untuk usulan detection; Agung untuk celah audit
```

**Tujuan:** mengelompokkan semua task yang dibuat di Februari menurut kelas pembuat, posisi task (root atau subfolder), dan lokasi biner yang dijalankan.

```
index=wineventlog EventCode=4698
    earliest="02/01/2027:00:00:00" latest="03/01/2027:00:00:00"
| rex field=TaskContent "(?:<|&lt;)Command(?:>|&gt;)(?<task_cmd>[^<&]+)"
| rex field=TaskContent "(?:<|&lt;)Arguments(?:>|&gt;)(?<task_args>[^<&]*)"
| eval creator_class=case(like(SubjectUserName, "%$"), "computer",
                          like(SubjectUserName, "adm.%"), "admin",
                          true(), "user")
| eval task_root=if(match(TaskName, "^\\\\[^\\\\]+$"), "root", "subfolder")
| eval cmd_n=replace(replace(lower(task_cmd), "\\\\", "/"), "c:/users/[^/]+/", "c:/users/<user>/")
| eval cmd_loc=case(match(cmd_n, "c:/users/|%localappdata%|%appdata%|%userprofile%"), "user",
                    match(cmd_n, "c:/programdata/|/temp/"), "shared-writable",
                    true(), "system")
| stats count AS creations dc(host) AS hosts dc(SubjectUserName) AS creators BY creator_class task_root cmd_loc
| sort - creations
```

| Bagian | Fungsi |
|---|---|
| `rex field=TaskContent "(?:<\|&lt;)Command..."` | Mengambil isi elemen `<Command>` dari XML task. Pola menerima `<` dan bentuk ter-escape `&lt;`, karena sebagian parsing menyimpan XML di dalam event dalam bentuk ter-escape; cek bentuknya di event mentah-mu |
| `like(SubjectUserName, "%$")` | Akun komputer (`HOST$`), yang muncul saat task dibuat oleh SYSTEM |
| `like(SubjectUserName, "adm.%")` | Akun admin PT JAB berpola `adm.<nama>` |
| `match(TaskName, "^\\\\[^\\\\]+$")` | Task di root: satu backslash di awal, tanpa backslash lain. Di string SPL `\\\\` menjadi regex `\\` |
| `cmd_loc` dengan variabel lingkungan | Task per-user sering menyimpan path sebagai `%LocalAppData%\...` yang belum diekspansi |

Keluaran ilustrasi (total 6.482 event dari 209 host):

```
creator_class  task_root  cmd_loc          creations  hosts  creators
computer       subfolder  system           5.488      209    209
user           root       user             412        142    151
computer       root       system           214        96     96
admin          subfolder  system           131        61     4
computer       subfolder  shared-writable  96         58     58
admin          root       system           83         37     3
user           root       system           37         19     21
user           subfolder  system           21         14     14
```

**Cara membaca hasil:** kelas yang menjawab hipotesis adalah `user / root / user` (412 event): persis bentuk `\PDFSuite Updater`. Kelas `user / root / system` (37 event) juga ditinjau lewat `task_args`, karena biner sistem seperti `powershell.exe` atau `wscript.exe` bisa menjalankan skrip di `AppData` lewat argumennya: 35 berargumen ke skrip pengingat backup laptop di share `\\corp.jab.example\it\` yang disebarkan tim IT, dan 2 adalah task pembersihan sementara milik installer di `Temp`. Jinak.

Kelas `user / root / user` dipecah per task dan command:

```
... (sama sampai baris eval cmd_loc)
| where creator_class="user" AND task_root="root" AND cmd_loc="user"
| eval task_n=replace(lower(TaskName), "s-1-5-21-[0-9-]+", "<sid>")
| stats count AS creations dc(host) AS hosts values(host) AS host_list values(SubjectUserName) AS creators
        BY task_n cmd_n
| sort hosts
```

```
task_n                                   cmd_n                                                               creations hosts
\calsync autostart                       c:/users/<user>/appdata/local/calsync/calsync.exe                   4         1
\noc-probe-check                         c:/users/<user>/appdata/local/netprobe/probecheck.exe               2         1
\designsuite updater                     c:/users/<user>/appdata/local/designsuite/updater/dsupdate.exe      2         2
\meetingclient updater                   c:/users/<user>/appdata/roaming/meetingclient/bin/updater.exe       19        14
\onedrive reporting task-<sid>           %localappdata%/microsoft/onedrive/onedrivestandaloneupdater.exe     97        96
\onedrive standalone update task-<sid>   %localappdata%/microsoft/onedrive/onedrivestandaloneupdater.exe     288       131
```

Jumlahnya 412 (4 + 2 + 2 + 19 + 97 + 288). Tiga baris teratas ada di satu atau dua host dan ditinjau:

- **`\calsync autostart` di `JKT-WS-0583`:** aplikasi sinkron kalender yang sama dengan temuan Run key (bagian 2.2), task dibuat ulang tiap kali aplikasi memperbarui diri. Jinak, shadow IT, sudah diteruskan.
- **`\noc-probe-check` di `JKT-WS-0552` (`arif.kurniawan`, engineer NOC):** tool pemeriksa agent synthetic monitoring buatan tim Service Assurance NOC, dikonfirmasi Bambang Hartono. Jinak; dicatat sebagai software internal yang belum terdaftar di inventaris aset SOC.
- **`\designsuite updater` di dua workstation Marketing:** updater per-user aplikasi desain dari daftar software resmi, biner ditandatangani vendor (diperiksa lewat kolom `Authenticode` di sisi Velociraptor). Jinak.

Nama task OneDrive di keluaran mengikuti pola updater per-user OneDrive yang diakhiri SID pengguna; cek nama persisnya di host-mu, karena pola itu milik produk dan bisa berubah.

**Variasi:** pivot ke proses pembuat lewat `ClientProcessId` dan `ParentProcessId` di 4698, dicocokkan dengan `ProcessId` Sysmon EID 1 di host dan menit yang sama. PID bisa dipakai ulang Windows, jadi batasi jendela waktunya sempit dan cocokkan juga nama host. Variasi kedua: 4699 untuk task yang dihapus tidak lama setelah dibuat, pola pembersihan jejak.

**Kapan gagal:** `TaskContent` tidak terekstrak sebagai field (sebagian konfigurasi input memotong field panjang; cek panjangnya); task dibuat lewat 4702 (task lama diubah action-nya) tidak muncul di 4698, sehingga perlu query yang sama atas 4702 dengan field `TaskContentNew` [S13]; host tanpa audit tidak pernah muncul sama sekali, dan itulah alasan bagian 2.5 ada.

### 2.5 `HUNT-2027-015` sisi Velociraptor: task di disk, positive control, dan task tersembunyi

Bagian ini menjawab pertanyaan Hendra secara langsung: apakah ada `\PDFSuite Updater` lain di host yang sama butanya dengan `SBY-WS-0107`.

**Tujuan:** mencari task di semua client yang command atau argumennya menunjuk ke lokasi yang bisa ditulis pengguna, lalu menghitung prevalence-nya.

Hunt `Windows.System.TaskScheduler` dikirim 09:35 ke semua client Windows. Kolom `Command` di artifact ini sudah dinormalisasi: variabel lingkungan diekspansi, hanya path biner yang diambil, dan semuanya huruf kecil; argumen ada di kolom `Arguments` (Day 09).

```
LET tasks = SELECT ClientId, TaskName, Command, Arguments, UserId, ComHandler, Authenticode,
       regex_replace(source=Command,
                     re='users.[a-z0-9._-]+.appdata', replace='users/<user>/appdata') AS CmdN
FROM source(artifact="Windows.System.TaskScheduler/Analysis")
WHERE Command =~ '(?i)users.|programdata|temp'
   OR Arguments =~ '(?i)users.|programdata|temp'

LET per_host = SELECT ClientId, CmdN,
       format(format="%v|%v", args=[ClientId, CmdN]) AS Key
FROM tasks GROUP BY Key

SELECT CmdN, count() AS hosts
FROM per_host
GROUP BY CmdN
ORDER BY hosts
```

Keluaran ilustrasi:

```
Client yang menjawab sampai 14:00 : 431 dari 443 host Windows
Baris task                        : 61.947 ; lolos filter lokasi: 1.871
CmdN unik                         : 22 ; dengan hosts <= 3: 4

CmdN                                                                   hosts
c:\programdata\printvendor\tools\cleanup.exe                           1
c:\users/<user>/appdata\local\netprobe\probecheck.exe                  1
c:\users/<user>/appdata\local\designsuite\updater\dsupdate.exe         2
c:\users/<user>/appdata\local\calsync\calsync.exe                      3
```

Campuran `\` dan `/` di `CmdN` adalah akibat `regex_replace` hanya mengganti bagian nama profil; untuk stacking itu tidak masalah selama aturan yang sama dipakai di semua baris.

Keempatnya ditinjau. Tiga sudah dikenal dari sisi 4698 dan Run key: `calsync.exe` kini terlihat di tiga host (`JKT-WS-0583`, `BDG-WS-0207`, `BDG-WS-0211`), `probecheck.exe` di `JKT-WS-0552`, dan updater aplikasi desain di dua host Marketing. Yang baru adalah `cleanup.exe` di `SBY-WS-0112`, workstation POP Surabaya: task pembersihan antrean cetak dari paket driver printer vendor, biner ditandatangani vendor, dan model printer yang sama ada di POP itu. Jinak.

**Positive control:** query yang sama dijalankan atas hasil `HUNT-2027-013` (koleksi Kamis 2027-02-25). Hasilnya menandai `\PDFSuite Updater` di `SBY-WS-0107` dengan command di folder `AppData\Local\PDFSuite` milik `rani.oktaviani`, `hosts` 1. Itu bukti bahwa filter dan normalisasi hari ini sanggup menangkap pola yang dicari; tanpa uji ini, "tidak ditemukan" bisa berarti query-nya yang buta.

**Task dengan COM handler:** task yang action-nya COM handler punya `Command` kosong dan `ComHandler` berisi CLSID, sehingga lolos dari filter lokasi. Stacking terpisah `SELECT ComHandler, count() ... GROUP BY ComHandler` memberi 41 CLSID unik; yang paling langka ada di 17 host (komponen Windows dari build lama). Tidak ada CLSID yang hanya ada di satu sampai tiga host.

**Task tersembunyi:** artifact komunitas `Windows.Registry.TaskCache.HiddenTasks` dari Artifact Exchange mencari task di `TaskCache` tanpa nilai `SD`, lalu mencoba mengambil detailnya dari registry dan file XML lewat `Windows.System.TaskScheduler` [S25]. Karena ini artifact komunitas, VQL-nya dibaca dulu sebelum diimpor ke `jkt-velo02`. Hasilnya nol baris di 431 client. Microsoft menyarankan pemeriksaan yang sama: enumerasi `TaskCache\Tree` dan tandai task tanpa nilai `SD` [S21].

**Cara membaca hasil:** tidak ada task di disk yang cocok dengan hipotesis selain yang sudah ditangani IR. Batasnya: snapshot hanya melihat task yang masih ada pada 2 Maret; task yang dibuat dan dihapus di Februari pada 229 workstation tanpa audit tidak bisa dilihat dengan cara apa pun yang dimiliki PT JAB saat ini.

**Kapan gagal:** task yang file XML-nya dihapus tetapi masih berjalan dari registry tidak terlihat oleh `Windows.System.TaskScheduler` [S22][S21]; artifact Exchange berubah tanpa kamu tahu (simpan versi yang diimpor di repo `jab-hunt`); hasil client yang terlambat online tidak ikut dihitung bila notebook tidak dijalankan ulang.

### 2.6 `HUNT-2027-016`: PowerShell 4104 mencurigakan

Hunt ini menjawab sisi execution dari pertanyaan kedua Dimas, dan menindaklanjuti backlog "unduhan lewat PowerShell" dari `HUNT-2027-002`.

```
ID             : HUNT-2027-016
Dibuat         : 2027-03-02 (Selasa) 08:45, pemilik: <kamu>, reviewer: Dimas Prasetyo
Trigger        : Backlog HUNT-2027-002 (unduhan lewat PowerShell); tahap unduh kampanye installer palsu
Tipe (PEAK)    : Hypothesis-driven
Hipotesis      : Ada script block PowerShell di host Windows PT JAB yang menggabungkan decode Base64,
                 unduhan, eksekusi string di memori, atau rujukan ke AMSI, yang bukan milik skrip internal
                 atau software yang dikenal.
ATT&CK         : T1059.001 Command and Scripting Interpreter: PowerShell
Data           : (a) index=powershell EventCode 4104, 214 host, 1-28 Feb 2027
                 (b) Velociraptor Windows.EventLogs.PowershellScriptblock level Warning, 229 workstation
Di luar cakupan: PowerShell 7 (log PowerShellCore tidak dikumpulkan); event lokal yang sudah tertimpa
Kriteria sukses: semua kombinasi Path+skor >= 2 ditinjau dan diberi label
Handover       : IR (Dimas) bila ditemukan; Sari untuk detection; Agung untuk celah log PowerShell 7
```

Pola yang dicari dibagi empat kategori. Pola itu ditulis sebagai string deteksi, bukan sebagai contoh kode yang bisa dijalankan.

| Kategori | Pola (huruf kecil) | Kenapa |
|---|---|---|
| `c_enc` | `frombase64string`, `gnirts46esabmorf`, `-e`/`-enc`/`-encodedcommand` di dalam script | Decode Base64; versi terbalik dipakai untuk menghindari pencarian kata utuh, dan detection Splunk Security Content memeriksa keduanya [S24] |
| `c_cradle` | `downloadstring`, `downloadfile`, `downloaddata`, `net.webclient`, `invoke-webrequest`, `invoke-restmethod`, `iwr`, `irm`, `start-bitstransfer` | Unduhan dari jaringan |
| `c_mem` | `invoke-expression`, `iex` | Menjalankan string sebagai kode |
| `c_amsi` | `amsiutils`, `amsiinitfailed`, `amsiscanbuffer`, `amsicontext` | Nama komponen AMSI yang dirujuk skrip yang mencoba melemahkannya; skrip biasa hampir tidak pernah menyebutnya |

**Tujuan:** memberi skor setiap script block menurut kategori yang menyala, lalu meninjau yang skornya minimal 2.

```
index=powershell sourcetype=XmlWinEventLog EventCode=4104
    earliest="02/01/2027:00:00:00" latest="03/01/2027:00:00:00"
| eval sb=lower(ScriptBlockText)
| eval c_enc=if(match(sb, "frombase64string|gnirts46esabmorf|\s[-/]e(c|nc|ncodedcommand)?\s"), 1, 0),
       c_cradle=if(match(sb, "download(string|file|data)|net\.webclient|invoke-webrequest|invoke-restmethod|start-bitstransfer|\biwr\b|\birm\b"), 1, 0),
       c_mem=if(match(sb, "invoke-expression|\biex\b"), 1, 0),
       c_amsi=if(match(sb, "amsiutils|amsiinitfailed|amsiscanbuffer|amsicontext"), 1, 0)
| eval score=c_enc + c_cradle + c_mem + 2*c_amsi
| where score >= 2
| stats count dc(host) AS hosts values(host) AS host_list dc(ScriptBlockId) AS blocks min(_time) AS firstTime
        BY Path score
| sort - score - hosts
```

| Bagian | Fungsi |
|---|---|
| `eval sb=lower(ScriptBlockText)` | Satu kali lower, supaya semua pola cukup ditulis huruf kecil |
| `\s[-/]e(c\|nc\|ncodedcommand)?\s` | Parameter encoded di dalam skrip yang memanggil PowerShell lagi; PowerShell menerima singkatan parameter, sehingga `-e` dan `-ec` juga dicari. Pola ini perkiraan, bukan daftar lengkap semua singkatan |
| `\biex\b`, `\biwr\b`, `\birm\b` | Alias pendek dengan batas kata, supaya tidak cocok dengan bagian dari kata lain |
| `score` dengan bobot AMSI 2 | Satu rujukan AMSI cukup untuk ditinjau; kategori lain butuh kombinasi |
| `BY Path score` | `Path` adalah file skrip asal script block; kosong untuk perintah interaktif |

Pola versi awal hunt ini (dari catatan lama) juga menandai setiap script block yang panjangnya lebih dari 1.000 karakter. Di PT JAB itu menandai sekitar dua juta event, hampir semuanya modul bawaan dan modul vendor, sehingga syarat panjang dibuang dan diganti skor kombinasi.

Keluaran ilustrasi:

```
Event 4104 Februari     : 8.903.442 dari 214 host
Cocok minimal 1 kategori: 21.604 ; skor >= 2: 1.163 ; rujukan AMSI: 0

Path                                                  score  count  hosts  blocks
\\corp.jab.example\netlogon\inv\inventaris.ps1        2      1.071  153    2
C:\Program Files\WindowsPowerShell\Modules\<agent backup>\...  2   61   61     1
C:\Program Files\JAB DocSync\tools\diag.ps1           2      23     19     1
(kosong, interaktif)                                  2      8      1      3
```

Jumlahnya 1.163 (1.071 + 61 + 23 + 8). Keempat baris ditinjau:

- **Skrip inventaris software tim IT** (logon script workstation Jakarta): unduh daftar paket dari repo internal `jkt-repo01` lalu decode konfigurasi Base64. Jinak, dikonfirmasi pemiliknya.
- **Modul agent backup server** di 61 server: modul vendor bertanda tangan. Jinak.
- **Skrip diagnostik JAB DocSync** di 19 host: mengirim log diagnostik ke `docsync-update.jab.example`. Jinak.
- **Tiga script block interaktif di `JKT-WS-0552`** (`arif.kurniawan`), Rabu 2027-02-17 13:05: installer satu baris `irm ... | iex` dari situs alat open-source monitoring jaringan `tools.netvendor.example`. Dikonfirmasi ke pengguna dan Bambang. Label: jinak, tetapi praktik berisiko (menjalankan skrip dari internet tanpa ditinjau); dicatat ke Dimas sebagai bahan edukasi, bukan insiden.

**Sisi (b), host tanpa policy SBL:** artifact `Windows.EventLogs.PowershellScriptblock` membaca file EVTX PowerShell Operational lokal, dengan parameter `LogLevel` (default Warning), `SearchStrings` (regex atas `ScriptBlockText`), `DateAfter`/`DateBefore`, dan keluaran seperti `EventTime`, `Computer`, `ScriptBlockId`, `ScriptBlockText`, `Path` [S19]. Dokumentasinya menyebut event level Warning tetap tercatat walaupun script block logging dimatikan, bila kata kunci mencurigakan terdeteksi [S19]. Hunt dikirim ke 229 workstation dengan `DateAfter=2027-01-31T17:00:00Z` dan `DateBefore=2027-02-28T17:00:00Z`, karena waktu artifact memakai UTC: 1 Februari 00:00 WIB adalah 31 Januari 17:00 UTC.

Keluaran ilustrasi: 218 dari 229 client menjawab, 1.377 event Warning dari 164 host. Stacking per `Path` memberi empat skrip, semuanya dikenal (skrip pemetaan printer cabang, modul driver vendor, dan dua skrip helpdesk), dan tidak ada rujukan AMSI. Event tertua yang masih ada di log lokal berbeda per host, dengan median 23 hari ke belakang: log lokal berukuran terbatas sehingga event lama tertimpa, dan sebagian awal Februari sudah hilang di banyak host.

**Cara membaca hasil:** tidak ditemukan untuk 214 host dengan log lengkap. Untuk 229 workstation lain, hasilnya hanya berlaku untuk script block yang memicu kata kunci internal PowerShell dan masih ada di log lokal; itu ditulis sebagai cakupan sebagian, bukan bersih.

**Variasi:** susun ulang script block yang dipecah dengan `stats values(ScriptBlockText) BY host ScriptBlockId` sebelum mencocokkan pola, supaya pola yang terbelah di batas dua event tetap tertangkap. Urutan bagian tidak dijamin oleh `values()`, jadi cek field nomor urut bagian di event mentah-mu sebelum menggabungkan teksnya.

**Kapan gagal:** penyerang memakai PowerShell 7 dan log-nya tidak dikumpulkan; pola dipecah dengan penggabungan string sehingga kata kunci utuh tidak pernah muncul di satu script block (cari juga script block hasil runtime yang muncul sesudahnya); Protected Event Logging aktif sehingga `ScriptBlockText` terenkripsi [S17]; field `Path` kosong untuk banyak hal sehingga stacking per `Path` menggumpalkan semua perintah interaktif menjadi satu baris (pecah dengan `host` dan `UserID`).

### 2.7 Rantai execution lalu persistence di host ber-Sysmon

Query ini menjawab bagian kedua pertanyaan kedua Dimas untuk 213 host ber-Sysmon: apakah ada Run key yang ditulis tidak lama setelah dokumen Office atau script host menjalankan sesuatu.

**Tujuan:** mencari pembuatan Run key (EID 13) yang didahului proses anak dari parent Office atau script host dalam 10 menit, pada host yang sama.

```
index=sysmon sourcetype=XmlWinEventLog
    ((EventCode=1 (ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe" OR ParentImage="*\\powerpnt.exe"
                   OR ParentImage="*\\outlook.exe" OR ParentImage="*\\mshta.exe" OR ParentImage="*\\wscript.exe"
                   OR ParentImage="*\\cscript.exe"))
     OR (EventCode=13 TargetObject="*\\CurrentVersion\\Run*"))
    earliest="02/01/2027:00:00:00" latest="03/01/2027:00:00:00"
| sort 0 _time
| streamstats time_window=10m count(eval(EventCode=1)) AS recent_exec BY host
| where EventCode=13 AND recent_exec > 0
| table _time host Image TargetObject Details recent_exec
```

| Bagian | Fungsi |
|---|---|
| Filter EID 1 hanya untuk parent berisiko di base search | Mengecilkan data sebelum `sort`; tanpa ini, search mengurutkan seluruh EID 1 sebulan |
| `sort 0 _time` | `time_window` mensyaratkan event terurut menurut waktu [S28]; `0` menghapus batas jumlah hasil `sort` |
| `streamstats time_window=10m count(eval(EventCode=1)) ... BY host` | Jumlah eksekusi dari parent berisiko dalam 10 menit terakhir, per host |
| `where EventCode=13 AND recent_exec > 0` | Run key yang ditulis saat ada eksekusi seperti itu di jendela yang sama |

Versi query di catatan lama memakai `sort 0 host _time`. Urutan itu mengelompokkan per host lalu waktu, sehingga event secara keseluruhan tidak lagi terurut waktu dan syarat `time_window` tidak terpenuhi; `BY host` di `streamstats` sudah memisahkan hitungan per host.

Keluaran ilustrasi:

```
_time                host          Image                                        TargetObject                                                      recent_exec
2027-02-15 08:02:11  JKT-WS-0606   C:\Windows\Temp\PrnInst\setup.exe            HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\PrnCfg     1
...                  (6 baris, 6 workstation Keuangan, Senin 2027-02-15 08:01-08:09)
```

**Cara membaca hasil:** enam rantai, semuanya logon script printer Keuangan: `wscript.exe` menjalankan installer driver dari share IT, lalu installer menulis `RunOnce` untuk konfigurasi setelah reboot. Jinak, sesuai jadwal pembaruan driver printer Keuangan dari tim IT. Tidak ada rantai dari Office.

**Variasi:** sisi execution saja, lewat data model Endpoint (Day 06 bagian 1.1). Query ini menghitung semua child dari parent dokumen dan script host, termasuk child yang jarang seperti `regsvr32.exe` atau `certutil.exe`:

```
| tstats summariesonly=true count dc(Processes.dest) AS hosts
    FROM datamodel=Endpoint.Processes
    WHERE Processes.parent_process_name IN (winword.exe, excel.exe, powerpnt.exe, outlook.exe, mshta.exe, wscript.exe)
        earliest="02/01/2027:00:00:00" latest="03/01/2027:00:00:00"
    BY Processes.parent_process_name Processes.process_name
| `drop_dm_object_name(Processes)`
| sort count
```

Di `jkt-splunk-sh01`, `summariesonly=true` ditulis eksplisit, tidak lewat macro `security_content_summariesonly` yang nilainya bisa diubah orang lain, karena search head itu adalah reader ringkasan data model dari `jkt-splunk-es01` (Day 06 bagian 1.1). Februari masih berada di dalam summary range `Endpoint` 90 hari, tetapi kelengkapan ringkasannya tetap dicek sebelum menyimpulkan (Day 06 bagian 2.7). Variasi lain: ganti EID 13 dengan EID 1 `schtasks.exe` yang memuat `/create`, untuk rantai execution lalu scheduled task.

**Kapan gagal:** jendela terlalu sempit untuk tahap kedua yang menunggu; installer dijalankan dari Explorer, bukan dari parent di daftar, sehingga rantai `SBY-WS-0107` (installer dari unduhan) tidak akan tertangkap pola ini sama sekali. Untuk rantai seperti itu, variasi dengan parent `explorer.exe` dan child di `Downloads` lebih tepat, dengan volume yang jauh lebih besar.

### 2.8 Laporan tiga hunt dan usulan detection untuk Sari

Laporan ini adalah langkah Finalize. Ketiga hunt dilaporkan dalam satu dokumen karena berbagi pemicu dan cakupan.

```
Hunt          : HUNT-2027-014, -015, -016          Selesai: Selasa 2027-03-02 17:30
Hasil         : Tidak ditemukan aktivitas berbahaya (selain SBY-WS-0107, sudah di INC-2027-040)
Cakupan nyata : Log 1-28 Feb 2027: Sysmon EID 1/11/12/13 dari 213 host, 4698 dari 214 host diaudit,
                4104 dari 214 host. Snapshot disk 2 Mar 2027: 431 dari 443 host Windows
                (StartupItems, TaskScheduler, TaskCache tanpa SD).
                Di luar cakupan: task/Run key yang dibuat lalu dihapus di Februari pada 229 workstation
                tanpa Sysmon/4698; PowerShell 7 di semua host; 4104 lengkap di 229 workstation (hanya
                Warning lokal, median 23 hari); 12 host offline saat snapshot; service dan WMI subscription
Positive ctrl : Query TaskScheduler menandai \PDFSuite Updater pada koleksi HUNT-2027-013
Jinak terkonfirmasi: 17 kombinasi Run key (Splunk), 58 entri StartupItems, 3 task langka (4698),
                4 command task langka (disk), 4 skrip PowerShell, 6 rantai logon script printer
Lain-lain     : Shadow IT calsync.exe di JKT-WS-0583, BDG-WS-0207, BDG-WS-0211 -> IT;
                installer irm|iex di JKT-WS-0552 -> catatan edukasi ke Dimas;
                probecheck.exe NOC belum di inventaris aset SOC -> Bambang
Celah data    : (1) 4698 dan Sysmon hanya di 214 host -> Agung (tautkan JAB-WS-Audit ke OU lain);
                (2) PowerShellCore/Operational tidak dikumpulkan (pwsh.exe ada di 37 host) -> Agung;
                (3) Sysmon JKT-WS-0532 masih diam sejak 2 Feb -> Agung
Detection     : "JAB - Scheduled task menjalankan biner dari folder AppData pengguna" -> Sari
Backlog baru  : (a) stacking 7045 dengan ImagePath di lokasi user-writable (T1543.003);
                (b) WMI subscription lintas fleet lewat Windows.Persistence.PermanentWMIEvents (T1546.003);
                (c) hunt Velociraptor TaskScheduler berkala untuk host tanpa audit (kontrol pengganti)
```

Angka `pwsh.exe` di 37 host berasal dari `Windows.Search.FileFinder` dengan glob `C:\Program Files\PowerShell\7\pwsh.exe` (29 server dan 8 workstation tim IT).

Usulan detection diserahkan ke Sari dengan format yang sama seperti usulan hunt sebelumnya:

```
Nama          : JAB - Scheduled task menjalankan biner dari folder AppData pengguna
Asal          : HUNT-2027-015 (INC-2027-040 sebagai kasus positif)
Logika        : 4698 dan 4702; Command atau Arguments di TaskContent/TaskContentNew menunjuk ke
                \Users\<x>\AppData\ (termasuk %LocalAppData%, %AppData%); SubjectUserName bukan akun
                komputer; task di root dinaikkan prioritasnya, bukan syarat
Pengecualian  : command persis updater per-user OneDrive dan klien rapat resmi (2 path, dikonfirmasi)
Volume        : Februari 2027: 412 event cocok; setelah pengecualian 8 event (sekitar 2 per minggu)
Cakupan       : hanya 214 host dengan audit 4698. TIDAK mencakup 229 workstation lain, termasuk tipe
                laptop seperti SBY-WS-0107; untuk itu kontrolnya hunt Velociraptor berkala (backlog c)
Uji           : lab: Atomic T1053.005 "Scheduled task Local" dengan task_command diarahkan ke folder
                AppData VM lab; plus kasus positif hasil HUNT-2027-013 (data disk, bukan 4698)
Triage L1     : cek pemilik dan software resmi; cek Authenticode biner lewat Velociraptor;
                eskalasi ke L2 bila tidak ada di daftar software dan tidak dikenal pengguna
```

**Cara membaca usulan:** baris Cakupan paling penting. Detection ini tidak akan menangkap `SBY-WS-0107` versi berikutnya karena laptop seperti itu tidak menghasilkan 4698. Menuliskannya terang-terangan mencegah rasa aman palsu, dan sekaligus menjadi argumen untuk celah data nomor (1).

**Kapan gagal:** usulan dikirim tanpa angka volume, sehingga Sari harus menebak apakah rule ini akan membanjiri L1; atau pengecualian ditulis per host ("kecuali JKT-WS-0583"), sehingga penyerang yang masuk ke host itu ikut dikecualikan.

### 2.9 Jawaban untuk Dimas

Ringkasan berikut dikirim Selasa sore bersama laporan. Setiap baris merujuk subbagian di atas, supaya Dimas bisa membaca alasannya bila ditanya Hendra.

| Pertanyaan | Jawaban singkat | Dasar |
|---|---|---|
| Teknik persistence apa lagi yang bisa lolos | Run key/Startup, scheduled task, service, WMI subscription, kunci autostart lain; semuanya lolos dengan cara yang sama di 229 workstation tanpa data | Bagian 1.1 |
| Hubungan execution dan persistence | Rantai: dijalankan sekali, menulis autostart, dijalankan ulang; dicari lewat korelasi waktu dan parent khas | Bagian 1.2, 1.5, 2.7 |
| Mana dulu | Scheduled task (terbukti di PT JAB), lalu Run key, lalu PowerShell; service dan WMI ke backlog | Bagian 1.3 |
| Cara tanpa IOC | First-seen dan prevalence entri autostart, stacking pembuat task | Bagian 1.4, 2.2 sampai 2.5 |
| Data dan blind spot | Peta per teknik; buta terbesar: riwayat di 229 workstation dan PowerShell 7 | Bagian 1.6, 2.1 |
| Sah atau penyerang | Kombinasi sinyal plus konfirmasi pemilik; nama bukan pembeda | Bagian 1.7 |
| Detection | "JAB - Scheduled task menjalankan biner dari folder AppData pengguna", sekitar 2 per minggu, cakupan 214 host; host lain lewat hunt berkala | Bagian 1.8, 2.8 |

**Kapan gagal:** jawaban menyebut "tidak ada persistence lain di PT JAB". Yang benar: tidak ditemukan di cakupan yang ditulis, dengan celah yang juga ditulis.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** Splunk lab dengan Sysmon (konfigurasi yang mencatat EID 1, 11, 12, 13, 19-21), Security log dengan subcategory `Other Object Access Events` aktif, PowerShell 4104 dengan policy script block logging; server Velociraptor lab dengan minimal dua client Windows; satu VM Windows dengan snapshot bersih untuk Atomic Red Team. Jangan memakai data dari pekerjaan nyata; PT JAB hanya contoh fiktif.

1. **Peta teknik ke data.** Untuk lima teknik persistence (bagian 1.1) dan lima execution (bagian 1.2), isi data yang tersedia di lab dan blind spot-nya, dengan format tabel bagian 1.6. Jalankan query bagian 2.1 untuk mengisi kolom host dengan angka.
2. **Baseline dan hunt persistence.** Bangun baseline Run key dari satu minggu data lab dengan macro bagian 2.2, lalu jalankan hunt first-seen untuk minggu berikutnya. Bila lab sepi, pasang dua atau tiga aplikasi per-user sungguhan di minggu kedua dan pastikan muncul sebagai kombinasi baru.
3. **Sisi endpoint.** Jalankan `Windows.Sys.StartupItems` dan `Windows.System.TaskScheduler` sebagai hunt Velociraptor, lalu stacking dengan VQL bagian 2.3 dan 2.5. Bandingkan apa yang terlihat di disk dengan apa yang terlihat di log.
4. **Hunt execution.** Jalankan query skor 4104 (bagian 2.6). Catat jumlah event per kategori, lalu ubah ambang skor dan catat perubahannya.
5. **Rantai.** Jalankan query bagian 2.7 setelah membuka dokumen Office yang menjalankan installer uji, atau setelah test Atomic di bawah.
6. **Buktikan menangkap target.** Di VM lab dengan snapshot, jalankan test Atomic dari tabel di bawah. Jalankan ulang hunt dan pastikan jejak di kolom "Yang harus terlihat" muncul. Jalankan cleanup test, lalu kembalikan snapshot.
7. **Bandingkan dengan rule.** Untuk tiap jejak, cek apakah rule yang aktif di lab sudah menangkapnya. Yang lolos adalah celah deteksi.
8. **Handover.** Tulis usulan deteksi untuk satu celah dengan format bagian 2.8, termasuk baris volume dan cakupan, dan laporan hunt dengan cakupan dan positive control.

Tabel berikut menjelaskan isi test yang dirujuk, bukan resepnya. Baca kolom kanan, karena itulah yang harus kamu cari di telemetri.

| Teknik | Test dan GUID | Apa yang terjadi | Yang harus terlihat di log |
|---|---|---|---|
| T1547.001 | Reg Key Run, `e55be3fd-3521-4610-9d1a-e210e42dcf05` [S5] | Menambah value bernama `Atomic Red Team` di `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` yang menunjuk ke path exe fiktif (default `C:\Path\AtomicRedTeam.exe`). Dijalankan lewat `cmd.exe` dengan `REG ADD`. Tidak ada program yang benar-benar dijalankan; cleanup menghapus value itu | Sysmon EID 1 `reg.exe` (parent `cmd.exe`) dengan command line `ADD` ke kunci Run; EID 13 dengan `TargetObject` berakhiran `\Run\Atomic Red Team` (di bawah `HKU\<SID>`) dan `Details` berisi path fiktif; `Windows.Sys.StartupItems` memuat entri baru sampai cleanup. Perhatian: path default tidak berada di lokasi user-writable, jadi filter lokasi di bagian 2.2 melewatkannya; ganti input path ke folder di bawah `AppData` atau uji tanpa filter lokasi |
| T1547.001 | Reg Key RunOnce, `554cbd88-cde1-4b56-8168-0be552eed9eb` [S5] | Butuh admin. Menulis value `1` di `HKLM\...\RunOnceEx\0001\Depend` yang menunjuk ke DLL fiktif, sehingga DLL dimuat saat logon berikutnya | EID 13 di kunci `RunOnceEx`, kunci yang sering tidak dipantau rule Run key biasa; cocok untuk menguji bahwa pola `*\\CurrentVersion\\Run*` di bagian 2.2 memang mencakupnya |
| T1053.005 | Scheduled task Local, `42f53695-ad4a-4546-abb6-7d837f644a71` [S6] | Membuat task bernama `spawn` yang berjalan sekali pada jam tertentu (default 20:10) dengan action default `cmd.exe` | Sysmon EID 1 `schtasks.exe` dengan `/create`; Security 4698 dengan `TaskName` `\spawn` (root) dan `TaskContent` berisi action `cmd.exe`; bila jamnya tercapai, `cmd.exe` dengan parent `svchost.exe` (layanan Schedule). Untuk menguji usulan detection bagian 2.8, ubah input `task_command` ke biner jinak yang disalin ke `AppData` VM lab |
| T1053.005 | Powershell Cmdlet Scheduled Task, `af9fd58f-c4ac-4bf2-a9ba-224b71ff25fd` [S6] | Membuat task lewat cmdlet `Register-ScheduledTask`, tanpa `schtasks.exe` | 4698 tetap muncul; Sysmon EID 1 hanya memperlihatkan `powershell.exe`, tidak ada `schtasks.exe`; 4104 memuat cmdlet itu. Ini membuktikan blind spot hunt yang hanya mencari `schtasks.exe` (bagian 1.4) |
| T1059.001 | PowerShell Command Execution, `a538de64-1c74-46ed-aa60-b995ed302598` [S7] | Dari `cmd.exe`, menjalankan PowerShell dengan switch `-e` (bentuk singkat `-EncodedCommand`) dan perintah ter-encode Base64 yang membungkus `Invoke-Expression` atas perintah yang hanya menampilkan pesan sapaan | EID 1 `powershell.exe` dengan parent `cmd.exe` dan `-e` diikuti blob Base64 di command line; 4104 berisi teks perintah yang sudah di-decode, ditambah script block hasil runtime dari `Invoke-Expression`. Skornya di bagian 2.6 bisa 1 saja (hanya `c_mem`), jadi jejak terkuatnya ada di command line EID 1. Rule yang hanya mencari `-enc` juga melewatkan alias `-e` |
| T1059.001 | PowerShell Invoke Known Malicious Cmdlets, `49eb9404-5e0f-4031-a179-b40f7be385e3` [S7] | Butuh admin, executor PowerShell. Membuat function kosong yang namanya meniru cmdlet tool ofensif terkenal, lalu hanya mencetak pesan. Tidak ada tool asli yang dijalankan | 4104 memuat nama-nama cmdlet itu; berguna untuk menguji apakah hunt bagian 2.6 atau rule berbasis nama cmdlet bereaksi. Skor bagian 2.6 bernilai 0, sehingga test ini juga memperlihatkan apa yang tidak dicari hunt itu |
| T1546.003 | Persistence via WMI Event Subscription - CommandLineEventConsumer, `3c64f177-28e2-49eb-a799-d767b24dd1e0` [S26] | Butuh admin. Membuat event filter berbasis uptime, CommandLineEventConsumer, dan binding; consumer default menjalankan `notepad.exe`. Cleanup menghapus ketiganya | Sysmon EID 19, 20, 21 berurutan; bila filter terpicu, `notepad.exe` dengan parent proses WMI; `Windows.Persistence.PermanentWMIEvents` memuat filter dan consumer-nya di namespace `root/subscription` [S27] |
| T1543.003 | Modify Service to Run Arbitrary Binary (Powershell), `1f896ce4-8070-4959-8a25-2658856a70c9` [S29] | Butuh admin. Menghentikan service `fax`, mengubah path binernya ke `notepad.exe`, lalu menjalankannya; cleanup mengembalikan path asli | EID 13 pada `HKLM\System\CurrentControlSet\Services\fax\ImagePath`; `notepad.exe` dengan parent `services.exe`. Cek apakah 7045 muncul: service-nya tidak baru, dan dokumentasi 4697 menyebut perubahan path setelah pembuatan tidak dicatat di event pemasangan [S15] |

Baca definisi test di repo sebelum menjalankan, karena parameter default (path, nama task, jam) bisa berubah antar versi katalog. Test lain di halaman yang sama (misalnya yang mengunduh script dari internet, mengunduh biner service dari GitHub, atau menjalankan tool kredensial) tidak dipakai di Day ini. Di VM lab tanpa internet, test yang punya langkah prasyarat unduhan akan gagal; itu disengaja.

**Hasil yang sebaiknya tersimpan:**

- Peta teknik ke data dengan blind spot dan angka host terisi.
- Baseline Run key lab dan hasil first-seen minggu berikutnya, dengan label tiap kombinasi.
- Hasil stacking StartupItems dan TaskScheduler dari Velociraptor, dibandingkan dengan log.
- Tabel jumlah event 4104 per kategori dan per ambang skor.
- GUID setiap test Atomic, waktu eksekusi, dan bukti tiap hunt menangkap (atau tidak menangkap) jejaknya.
- Daftar celah: jejak yang tidak tertangkap rule yang aktif.
- Satu usulan detection dengan volume, pengecualian, cakupan, dan uji; satu laporan hunt dengan positive control.

**Variasi tantangan:** pilih satu teknik persistence yang lab-mu belum punya rule-nya (misalnya WMI event subscription T1546.003). Nilai apakah datanya ada (Sysmon EID 19-21, artifact Velociraptor). Bila ada, jalankan hunt; bila tidak, tulis rekomendasi telemetri (Day 04). Dokumentasikan sebagai hunt "data tidak cukup" bila memang datanya belum ada; itu hasil yang sah (Day 01 bagian 1.6). Tantangan kedua: buat task di VM lab, catat jejaknya di registry `TaskCache\Tree`, lalu (dengan hak SYSTEM, di snapshot yang akan dibuang) amati apa yang terjadi pada `schtasks /query` dan pada `Windows.System.TaskScheduler` bila nilai `SD` dihapus. Kembalikan snapshot setelahnya.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat menjalankan hunt persistence dan execution. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| First-seen menandai semua Run key | Baseline kosong, rentang tumpang tindih, atau normalisasi berbeda | Bangun baseline dulu dengan macro yang sama (bagian 2.2); cek `\| inputlookup jab_hunt_baseline_runkeys.csv \| stats count` |
| Run key per pengguna tidak cocok dengan pola `HKCU` | Sysmon menulis `HKU\<SID>`, bukan `HKCU` [S2] | Pakai pola `*\\CurrentVersion\\Run*` dan normalisasi SID |
| 4698 tidak muncul atau tanpa field pembuat | Audit policy atau parsing | Aktifkan subcategory `Other Object Access Events` (Success); cek parsing `SubjectUserName` dan `TaskContent` |
| `task_cmd` kosong padahal 4698 ada | XML di `TaskContent` ter-escape atau terpotong | Lihat event mentah; sesuaikan `rex` (bagian 2.4) atau batas panjang field di input |
| Hunt scheduled task lewatkan COM/API | Hanya memakai command line | Tambah 4698 dan Velociraptor TaskScheduler (bagian 2.4, 2.5) |
| Task terlihat di disk tetapi tidak di `schtasks /query` | Task tersembunyi (nilai `SD` dihapus) [S21] | Cek `TaskCache\Tree` tanpa `SD` (bagian 2.5) |
| PowerShell 4104 kosong atau hanya sebagian | Script Block Logging nonaktif (hanya auto-log Warning) | Aktifkan policy `Turn on PowerShell Script Block Logging`; catat sebagai celah visibilitas sampai aktif |
| Aktivitas `pwsh.exe` tidak ada di 4104 | PowerShell 7 menulis ke `PowerShellCore/Operational` [S4] | Tambah channel itu ke input; aktifkan policy di `Administrative Templates > PowerShell Core` |
| Pola 4104 tidak cocok padahal skrip jelas berbahaya | Script block dipecah atau kata kunci dipecah dengan penggabungan string | Susun ulang per `ScriptBlockId`; cari script block runtime sesudahnya (bagian 2.6) |
| Rantai execution-persistence nol | Jendela terlalu sempit; event tidak terurut waktu | Perlebar `time_window`; pakai `sort 0 _time` [S28] |
| Hasil Velociraptor berubah setelah laporan | Client yang tadinya offline baru menjawab | Jalankan ulang notebook sebelum laporan final; tulis jumlah client yang menjawab |
| Terlalu banyak FP parent-child | Installer/updater sah | Allowlist sempit; bandingkan dengan baseline |

## 5. Kesalahan umum dan jebakan

- **Mengulang yang sudah terdeteksi.** Hunting mencari yang lolos rule, bukan memvalidasi rule (itu triage).
- **Hanya memakai command line** untuk persistence; task/service via API lolos. Tambah log event dan artifact endpoint.
- **Mengabaikan lokasi autostart yang jarang.** Penyerang memakai kunci yang tidak dipantau; autoruns lintas fleet menutupnya.
- **Tidak mengikuti rantai.** Execution dan persistence sering bersama; korelasi temporal memperkuat temuan.
- **Menandai teknik sebagai tertutup dari satu prosedur.** Satu teknik ATT&CK punya banyak prosedur (Run key HKCU, RunOnceEx, folder Startup); rule untuk satu prosedur tidak menutup yang lain. Hitung cakupan per prosedur.
- **Menyimpulkan "bersih" dari snapshot.** Snapshot disk hanya melihat yang masih terpasang saat hunt. Persistence yang sudah dihapus penyerang setelah dipakai, atau yang dibuat sesudah snapshot, tidak terlihat.
- **Memakai nama task atau nama file sebagai pembeda jinak dan jahat.** Nama dikendalikan pembuatnya; `\PDFSuite Updater` terdengar sama sahnya dengan updater vendor mana pun (bagian 1.7).
- **Menulis detection berbasis 4698 tanpa menyebut cakupannya.** Rule itu buta di host tanpa audit, dan justru di sanalah `SBY-WS-0107` berada.
- **Mengecualikan per host atau per pengguna.** Pengecualian yang lebar ikut melindungi penyerang yang masuk ke host itu; kecualikan command line atau path lengkap yang sudah dikonfirmasi.
- **Lupa PowerShell 7.** Hunt 4104 yang hanya membaca `Microsoft-Windows-PowerShell/Operational` tidak melihat `pwsh.exe` sama sekali.
- `[komunitas, belum terkonfirmasi]` Praktisi sering menyebut first-seen autostart lintas fleet sebagai salah satu hunt persistence paling produktif, karena persistence penyerang cenderung unik per host. Ini konsisten dengan prinsip stacking (Day 05); ukur di lab-mu.

## 6. Catatan terkini

Bagian ini menampung detail versi dan perubahan sumber yang berguna saat membuka dokumentasinya, tetapi tidak mengubah alur kerja di atas.

- ATT&CK v19 memecah taktik Defense Evasion menjadi Stealth dan Defense Impairment. Di ATT&CK v20, ID teknik di Day ini tidak berubah: T1547.001 (versi teknik 2.1), T1053.005 (1.8), T1543.003 (1.6), T1546.003 (1.5), dan T1059.001 (1.6) [S8][S9][S10][S11][S12]. Nama teknik juga tetap. Halaman teknik kini mencantumkan detection strategy (DET0365, DET0441, DET0552, DET0086, DET0455) dengan analytic di bawahnya; dokumentasi lama yang menulis "Data Source" per teknik masih beredar.
- Halaman event 4697, 4698, 4699, dan 4702 di Microsoft Learn kini berada di bagian arsip dokumentasi Windows 10 (`previous-versions`), dengan tanggal pembaruan 2026-04-27 [S3][S13][S14][S15]. Isinya tetap acuan field yang dipakai.
- Microsoft Learn tidak punya halaman referensi khusus untuk event 7045 seperti untuk event Security; keterangan field di Day ini berasal dari sumber sekunder [S16] dan perlu dicocokkan dengan event mentah di host-mu.
- Halaman Sysmon di Microsoft Learn bertanggal 10 September 2026 dan menyebut dukungan Windows 11 ke atas serta Windows Server 2019 ke atas [S2].
- Dokumentasi PowerShell memisahkan logging Windows PowerShell 5.1 (`about_Logging`, log `Microsoft-Windows-PowerShell/Operational`) dari PowerShell 7 (`about_Logging_Windows`, log `PowerShellCore/Operational`); versi 7.6 adalah versi default halaman itu per Januari 2026 [S4][S17].
- Velociraptor 0.77.3 dirilis 5 Oktober 2026 dan halaman artifact menganjurkan pembaruan ke versi itu karena beberapa CVE [S30]. Artifact `Windows.Registry.TaskCache.HiddenTasks` berada di Artifact Exchange, bukan artifact bawaan [S25].
- Rule untuk teknik umum ini biasanya sudah ada di content pack SIEM (Sigma, Splunk Security Content); hunting berfokus pada prosedur yang belum tertutup.

## 7. Cheat sheet

```
PERSISTENCE  T1547.001 Run key/Startup (EID 13/12/11, StartupItems, Autoruns)
             T1053.005 task (4698/4699/4702, EID1 schtasks, TaskScheduler XML, TaskCache\Tree tanpa SD)
             T1543.003 service (7045, 4697, EID 13 Services\*\ImagePath)
             T1546.003 WMI sub (EID 19-21, PermanentWMIEvents) | kunci lain (Winlogon, BootExecute, Shell Folders)
EXECUTION    T1059.001 PowerShell (4104; PS7 = PowerShellCore/Operational) | T1059.003 cmd (EID1/4688)
             T1047 WMI (WmiPrvSE parent, wmic) | T1204 user exec (parent Office/Explorer)
POLA         first-seen vs baseline (host ber-log) | prevalence <= 3 host (snapshot disk)
             stacking pembuat task: akun x root/subfolder x lokasi command (+ Arguments!)
RANTAI       EID1 parent berisiko -> EID13 Run key dalam 10m: sort 0 _time | streamstats time_window=10m ... BY host
PEMBEDA      kombinasi: prevalence, lokasi user-writable, root, pembuat user, tanda tangan, daftar software,
             rantai; NAMA BUKAN PEMBEDA; konfirmasi pemilik wajib
DATA         command line (buta API) | 4698/7045 (tanpa cmdline pembuat; 4698 butuh audit)
             disk (lengkap, snapshot, tanpa waktu) | 4104 (butuh SBL; tanpa itu hanya Warning)
SPL          rex TaskContent "(?:<|&lt;)Command(?:>|&gt;)(?<task_cmd>[^<&]+)"
             root task: match(TaskName, "^\\\\[^\\\\]+$") | HKU\<SID>: normalisasi ke <sid>
VQL          stacking 2 tahap: GROUP BY "ClientId|nilai" lalu count() per nilai
HANDOVER     volume/minggu + pengecualian sempit + cakupan jujur + uji positif -> Sari (Day 14)
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Rule `JAB - Scheduled task menjalankan biner dari folder AppData pengguna` sudah aktif, jadi kasus seperti `SBY-WS-0107` sekarang akan langsung menjadi alert." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Rule itu dibangun dari event 4698, yang hanya dihasilkan 214 host dengan audit `Other Object Access Events` (OU `Workstations-EDR` dan server). `SBY-WS-0107` dan 228 workstation lain di luar OU itu tidak menghasilkan 4698, sehingga task yang sama persis di sana tidak akan pernah memicu rule. Untuk host itu, kontrolnya adalah hunt Velociraptor `Windows.System.TaskScheduler` berkala, sampai GPO audit ditautkan ke OU lain. Karena itulah baris Cakupan ditulis terang di usulan. Lihat bagian 1.8 dan 2.8.

</details>

**2. Skenario keputusan.** Stacking 4698 menunjukkan task di root yang dibuat akun pengguna biasa dan menjalankan biner di `AppData\Local`, di 96 host, dengan biner ditandatangani vendor besar. Apa langkah yang paling tepat?

- A. Tandai sebagai kandidat kuat, karena tiga sinyal (root, pembuat pengguna, folder `AppData`) menyala sekaligus.
- B. Tandai sebagai kemungkinan besar updater per-user yang sah, konfirmasi path persisnya ke daftar software atau tim IT, lalu jadikan pengecualian bernama dengan command line persis bila terkonfirmasi.
- C. Kecualikan semua task dari akun pengguna di 96 host itu supaya tidak muncul lagi di hunt berikutnya.

<details><summary>Jawaban</summary>

B. Prevalence ratusan host dan tanda tangan vendor adalah sinyal kuat bahwa itu software yang dipasang massal, seperti updater per-user OneDrive di keluaran bagian 2.4, tetapi tetap dikonfirmasi sebelum dikecualikan, dan pengecualiannya sempit (command line persis). A keliru karena menghitung sinyal tanpa melihat prevalence dan tanda tangan; kombinasi yang menentukan, bukan satu-dua sinyal. C keliru karena pengecualian per pengguna atau per host ikut melindungi penyerang yang masuk ke host itu. Lihat bagian 1.7 dan 2.4.

</details>

**3. Pertanyaan jebakan.** "Hunt `Windows.Sys.StartupItems` di 431 host tidak menemukan entri autostart mencurigakan, jadi tidak ada persistence Run key di Februari di host tanpa Sysmon." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Snapshot disk hanya melihat apa yang terpasang saat hunt dijalankan (2 Maret), tanpa timestamp. Entri yang dibuat lalu dihapus di Februari tidak terlihat, dan 12 host offline belum menjawab. Kesimpulan yang benar: tidak ada entri mencurigakan yang masih terpasang per 2 Maret di 431 host, dengan riwayat Februari di 229 workstation di luar cakupan. Lihat bagian 1.4 dan 2.3.

</details>

**4. Skenario keputusan.** Kamu ingin hunt PowerShell yang paling sedikit blind spot-nya di PT JAB dengan kondisi sekarang. Mana yang paling tepat?

- A. Cari `powershell.exe` dengan `-enc` di Sysmon EID 1, karena command line tidak bisa dipalsukan.
- B. Pakai 4104 di 214 host dengan skor kombinasi pola, ditambah pembacaan log Warning lokal lewat Velociraptor di 229 workstation, dan tulis PowerShell 7 serta log lokal yang tertimpa sebagai di luar cakupan.
- C. Pakai 4104 dengan syarat panjang script block lebih dari 1.000 karakter, karena skrip berbahaya biasanya panjang.

<details><summary>Jawaban</summary>

B. 4104 ditulis oleh engine PowerShell sehingga juga melihat PowerShell yang dijalankan tanpa `powershell.exe` dan kode hasil runtime, dan pembacaan Warning lokal memberi cakupan sebagian di host tanpa policy; celah sisanya ditulis. A keliru karena buta terhadap PowerShell tanpa `powershell.exe`, terhadap alias `-e`, dan terhadap 229 host tanpa Sysmon. C keliru karena syarat panjang menandai sekitar dua juta event modul sah di PT JAB dan tidak ada hubungannya dengan niat. Lihat bagian 1.2, 1.6, dan 2.6.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Gilang Ramadhan (analyst L1), dalam tiga kalimat, kenapa `\PDFSuite Updater` ditemukan lewat pola persistence padahal pencarian IOC gagal.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "IOC itu domain, IP, dan hash yang bisa diganti penyerang tiap kampanye, dan varian di Surabaya memang memakai domain C2 yang tidak ada di daftar kasus Bandung. Yang tidak bisa diganti adalah kebutuhan untuk tetap jalan setelah reboot, jadi installer-nya harus mendaftarkan scheduled task yang menjalankan biner dari folder AppData pengguna, dan file task itu ada di disk. Hunt membaca file task di semua laptop lewat Velociraptor dan mencari yang hanya ada di satu host, di folder yang bisa ditulis pengguna, dan tidak ada di daftar software, sehingga ketemu tanpa perlu tahu namanya."

Kesalahan yang sering muncul:
- Mengatakan pola persistence "selalu" lebih baik dari IOC, padahal pola butuh konfirmasi pemilik dan menghasilkan banyak kandidat jinak.
- Lupa menyebut kenapa laptop itu tidak punya log (tanpa Sysmon, tanpa 4698), padahal itu alasan pembacaan disk dibutuhkan.
- Menyebut nama task sebagai alasan kecurigaan.

</details>

**6. Pertanyaan jebakan.** "Query rantai di bagian 2.7 tidak menemukan apa pun dari Office di Februari, jadi installer PDF palsu seperti `INC-2026-026` pasti tidak dijalankan di host ber-Sysmon." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Query itu hanya mencari Run key yang didahului eksekusi dari parent Office atau script host dalam 10 menit. Installer yang diunduh lalu dijalankan pengguna biasanya ber-parent `explorer.exe`, bukan Office, dan installer PDF palsu membuat scheduled task, bukan Run key, sehingga rantai seperti `SBY-WS-0107` tidak akan tertangkap pola ini sama sekali. Untuk itu dibutuhkan variasi dengan parent `explorer.exe` dan child di `Downloads`, atau hunt pembuat task (bagian 2.4). Lihat bagian 1.5 dan 2.7.

</details>

**7. Interview question (English).** "How would you hunt for persistence in a Windows fleet when you have no IOCs, and only part of the fleet has Sysmon?"

<details><summary>Sample answer</summary>

"I start from the fact that persistence has to live somewhere in host configuration, so I hunt the configuration, not indicators. First I map techniques to data: Run keys and Startup from Sysmon registry and file events, scheduled tasks from 4698 and the task XML files on disk, services from 7045, WMI subscriptions from Sysmon 19 to 21, and PowerShell from 4104. Where I have Sysmon, I do first-seen against a stored baseline with normalized paths and SIDs. Where I don't, I collect the current state with an endpoint tool like Velociraptor and stack by prevalence, because legitimate software is deployed widely and attacker persistence tends to be unique to a host. For scheduled tasks I stack the creator account, root versus vendor folder, and whether the command or its arguments point to a user-writable path. I review the small set that remains with the owner, run a positive control against a known case, and write down what the snapshot cannot see, such as tasks that were created and deleted before collection. If a pattern is stable, I hand it to detection engineering with volume, narrow exclusions and an honest coverage statement."

What makes this answer strong: it explains why configuration-based hunting survives IOC rotation, adapts the method to uneven telemetry instead of ignoring the blind part of the fleet, and ends with positive controls and explicit coverage limits rather than a claim that the fleet is clean.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | MITRE ATT&CK: Persistence (TA0003) dan Execution (TA0002) | https://attack.mitre.org/tactics/TA0003/ | primer | diakses 2026-10-09, dicek ulang 2026-10-18 | Tinggi. Teknik dan prosedur |
| S2 | Microsoft Learn: Sysmon (daftar event ID dan konfigurasi) | https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon | primer | halaman 2026-09-10; diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi. EID 1/11/12/13/19-21, singkatan root key HKLM/HKU, filter konfigurasi |
| S3 | Microsoft Learn: 4698(S) A scheduled task was created | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698 | primer (arsip Windows 10) | diperbarui 2026-04-27; diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi. Field dan subcategory audit; ClientProcessId/ParentProcessId sejak 1903; saran pantau task di root |
| S4 | Microsoft Learn: about_Logging_Windows (PowerShell 7.6, Script Block Logging, 4104) | https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows | primer | 2026-01-18; diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi. Log PowerShellCore/Operational dan policy PowerShell Core. Klaim auto-logging Warning tidak ada di halaman ini; lihat S18 dan S19 |
| S5 | Atomic Red Team: T1547.001 | https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.001/T1547.001.md | primer | diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi. Isi test dan GUID (21 test) |
| S6 | Atomic Red Team: T1053.005 | https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md | primer | diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi. Isi test dan GUID, termasuk Powershell Cmdlet Scheduled Task |
| S7 | Atomic Red Team: T1059.001 | https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md | primer | diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi. Isi test dan GUID |
| S8 | MITRE ATT&CK v20: T1547.001 Registry Run Keys / Startup Folder | https://attack.mitre.org/techniques/T1547/001/ | primer | versi teknik 2.1, diubah 2026-05-12; diakses 2026-10-18 | Tinggi. Kunci Run/RunOnce/RunOnceEx, folder Startup, kunci lain; DET0365 |
| S9 | MITRE ATT&CK v20: T1053.005 Scheduled Task | https://attack.mitre.org/techniques/T1053/005/ | primer | versi teknik 1.8, diubah 2026-05-12; diakses 2026-10-18 | Tinggi. Tiga taktik, cara pembuatan, task tersembunyi (SD, Index); DET0441/AN1221 |
| S10 | MITRE ATT&CK v20: T1543.003 Windows Service | https://attack.mitre.org/techniques/T1543/003/ | primer | versi teknik 1.6, diubah 2026-05-12; diakses 2026-10-18 | Tinggi. Registry Services, sc.exe; DET0552/AN1527 |
| S11 | MITRE ATT&CK v20: T1546.003 WMI Event Subscription | https://attack.mitre.org/techniques/T1546/003/ | primer | versi teknik 1.5, diubah 2025-10-24; diakses 2026-10-18 | Tinggi. Filter/consumer/binding, WmiPrvSE; DET0086/AN0236 |
| S12 | MITRE ATT&CK v20: T1059.001 PowerShell | https://attack.mitre.org/techniques/T1059/001/ | primer | versi teknik 1.6, diubah 2026-09-18; diakses 2026-10-18 | Tinggi. Encoded command, download cradle, eksekusi tanpa powershell.exe; DET0455 |
| S13 | Microsoft Learn: 4702(S) A scheduled task was updated | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4702 | primer (arsip Windows 10) | diperbarui 2026-04-27; diakses 2026-10-18 | Tinggi. Field TaskContentNew, subcategory sama dengan 4698 |
| S14 | Microsoft Learn: 4699(S) A scheduled task was deleted | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4699 | primer (arsip Windows 10) | diperbarui 2026-04-27; diakses 2026-10-18 | Tinggi. TaskContent task yang dihapus |
| S15 | Microsoft Learn: 4697(S) A service was installed in the system | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4697 | primer (arsip Windows 10) | diperbarui 2026-04-27; diakses 2026-10-18 | Tinggi. Subcategory Audit Security System Extension; field; perubahan path tidak dicatat |
| S16 | ManageEngine ADAudit Plus: Event ID 7045 | https://www.manageengine.com/products/active-directory-audit/kb/system-events/event-id-7045.html | sekunder (vendor) | diakses 2026-10-18 | Sedang. Service baru, subject sering SYSTEM; tidak menyebut log, provider, atau kebutuhan audit policy |
| S17 | Microsoft Learn: about_Logging (Windows PowerShell 5.1) | https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1 | primer | 2024-01-09, diperbarui 2025-09-29; diakses 2026-10-18 | Tinggi. Log Microsoft-Windows-PowerShell/Operational, path GPO, Protected Event Logging |
| S18 | TrustedSec: Building a Detection Foundation Part 3, PowerShell and Script Logging (Carlos Perez) | https://trustedsec.com/blog/building-a-detection-foundation-part-3-powershell-and-script-logging | sekunder (blog praktisi) | 2026-03-10; diakses 2026-10-18 | Sedang-tinggi. Auto-logging Warning dari daftar kata kunci engine, log PowerShell 7 terpisah, pemecahan script panjang, AMSI dan logging |
| S19 | Velociraptor: Windows.EventLogs.PowershellScriptblock | https://docs.velociraptor.app/artifact_references/pages/windows.eventlogs.powershellscriptblock/ | primer (dokumentasi alat) | diakses 2026-10-18 | Tinggi. Parameter, kolom, catatan level Warning tercatat tanpa SBL |
| S20 | Velociraptor: Windows.Sysinternals.Autoruns | https://docs.velociraptor.app/artifact_references/pages/windows.sysinternals.autoruns/ | primer (dokumentasi alat) | diakses 2026-10-18 | Tinggi. Menjalankan autorunsc, izin EXECVE, kategori; kolom keluaran tidak dirinci |
| S21 | Microsoft Security Blog: Tarrask malware uses scheduled tasks for defense evasion | https://www.microsoft.com/en-us/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/ | primer (vendor, pemilik telemetri) | 2022-04-12 (pembaruan nama aktor April 2023); diakses 2026-10-18 | Tinggi. Tree/Tasks/XML, penghapusan SD butuh SYSTEM, task tetap berjalan, saran deteksi. Lebih dari 3 tahun, tetapi mekanismenya masih dirujuk ATT&CK v20 |
| S22 | Velociraptor: Windows.System.TaskScheduler | https://docs.velociraptor.app/artifact_references/pages/windows.system.taskscheduler/ | primer (dokumentasi alat) | diakses 2026-10-18 | Tinggi. Membaca file XML Tasks saja, kolom keluaran |
| S23 | Velociraptor: Windows.Sys.StartupItems | https://docs.velociraptor.app/artifact_references/pages/windows.sys.startupitems/ | primer (dokumentasi alat) | diakses 2026-10-18 | Tinggi. Kunci dan folder yang dibaca, kolom tanpa timestamp |
| S24 | Splunk Security Content: Powershell Fileless Script Contains Base64 Encoded Content | https://research.splunk.com/endpoint/8acbc04c-c882-11eb-b060-acde48001122/ | sekunder (content vendor) | versi 22, diperbarui 2026-06-25; diakses 2026-10-18 | Tinggi untuk pola dan field: FromBase64String dan versi terbaliknya, ScriptBlockText, ScriptBlockId |
| S25 | Velociraptor Artifact Exchange: Windows.Registry.TaskCache.HiddenTasks | https://docs.velociraptor.app/exchange/artifacts/pages/windows.registry.taskcache.hiddentasks/ | komunitas (Artifact Exchange) | diakses 2026-10-18 | Sedang. Artifact komunitas; baca VQL sebelum impor |
| S26 | Atomic Red Team: T1546.003 | https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.003/T1546.003.md | primer | diakses 2026-10-18 | Tinggi. Isi test dan GUID |
| S27 | Velociraptor: Windows.Persistence.PermanentWMIEvents | https://docs.velociraptor.app/artifact_references/pages/windows.persistence.permanentwmievents/ | primer (dokumentasi alat) | diakses 2026-10-18 | Tinggi. Binding, filter, consumer; namespace default root/subscription dan root/default |
| S28 | Splunk Docs: streamstats (Search Reference 10.2) | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.2/search-commands/streamstats | primer | diperbarui 2026-01-09; diakses 2026-10-18 | Tinggi. time_window mensyaratkan event terurut waktu. Halaman 10.6 tidak dibuka; cek di versi-mu |
| S29 | Atomic Red Team: T1543.003 | https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md | primer | diakses 2026-10-18 | Tinggi. Isi test dan GUID |
| S30 | Velociraptor releases (GitHub) | https://github.com/Velocidex/velociraptor/releases | primer | v0.77.3, 2026-10-05; diakses 2026-10-18 | Tinggi. Versi stabil terbaru |

**Catatan sumber:** parameter default test Atomic (nama value, path, nama task, jam) diambil dari definisi test per 2026-10-18 dan bisa berubah; cocokkan dengan repo sebelum lab. Klaim bahwa PowerShell mencatat script block mencurigakan sebagai Warning tanpa policy tidak ada di dokumentasi Microsoft yang diperiksa (S4, S17); klaim itu berasal dari blog praktisi (S18) dan dokumentasi artifact Velociraptor (S19), dan daftar kata kuncinya internal PowerShell sehingga bisa berubah antar versi. Keterangan field event 7045 berasal dari sumber sekunder (S16); cocokkan dengan event mentah. Nama field 4698 dan bentuk `TaskContent` (ter-escape atau tidak) bergantung add-on dan parsing; cek di lab. Nama task updater per-user OneDrive di keluaran ilustrasi mengikuti pola produk dan perlu dicek di host nyata. Perilaku `streamstats time_window` dicek di dokumentasi 10.2, bukan 10.6. Seluruh isi `HUNT-2027-014` sampai `-016` (host, akun, angka, label, nama aplikasi seperti `calsync`, `meetingclient`, `designsuite`) adalah penerapan catatan ini pada organisasi fiktif, bukan hasil eksekusi nyata.
