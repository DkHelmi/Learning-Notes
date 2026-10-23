---
day: 25
title: 'ETW dan Sysmon sebagai sumber forensik: arsitektur, jejak di disk, konfigurasi sebagai peta celah, dan membedakan sabotase dari masalah operasional'
researched_on: 2026-10-23
versions_checked: 'Sysmon Sysinternals (halaman Microsoft Learn terbit 2026-09-10, event ID 1-29 dan 255, contoh schemaversion 4.82, Windows 11 dan Server 2019 ke atas; nomor versi 15.22 bertanggal sama dari listing pihak ketiga); Sysmon bawaan Windows 11 (Insider build 26300.7733 Februari 2026, pembaruan opsional KB5077241 build 26100/26200.7922 Februari 2026, pembaruan keamanan KB5079473 build 26100/26200.8037 Maret 2026, mati secara bawaan); About Event Tracing (Microsoft Learn ms.date 2025-07-14, diperbarui 2026-07-17); Configuring and Starting an AutoLogger Session (ms.date 2018-05-31, diperbarui 2025-07-09); logman query dan logman create trace (ms.date 2017-10-16); Windows 11 Enterprise 23H2 (pembaruan terakhir November 2026) dan 25H2 build 26200; EZ Tools 2026.5.0 (EvtxECmd, RECmd); MITRE ATT&CK v20 (T1685 Disable or Modify Tools, T1685.001)'
---

# Day 25: ETW dan Sysmon sebagai sumber forensik

Cakupan: bagaimana telemetri Windows dibangkitkan lewat ETW dan Sysmon, apa yang tersisa di host untuk dianalisis, bagaimana konfigurasi menentukan apa yang mungkin ada, dan bagaimana membuktikan dari host apakah perekaman yang berhenti adalah sabotase atau masalah operasional.

## Ide inti

Hampir semua telemetri Windows yang kamu andalkan saat investigasi, termasuk sebagian besar channel di Event Viewer dan seluruh keluaran Sysmon, lahir dari Event Tracing for Windows (ETW): provider menulis event, sesi menampung event di buffer, dan consumer (layanan Event Log, agen EDR, forwarder SIEM) membacanya. Rantai ini punya beberapa titik yang bisa putus, dan setiap titik putus dengan cara berbeda. Provider bisa tidak menulis karena konfigurasinya memang tidak memasukkan event itu. Sesi bisa kehilangan event karena buffer penuh atau consumer lambat. Driver bisa gagal dimuat setelah crash. Service bisa dihentikan admin. Konfigurasi bisa diganti dengan versi yang salah. Dari sisi Splunk, semuanya terlihat sama: grafik event Sysmon turun ke nol. Dari sisi host, semuanya berbeda, karena hampir setiap jalur putus meninggalkan jejaknya sendiri: event Sysmon 4 dan 16 yang tidak bisa difilter, event 255 saat Sysmon kewalahan, event Service Control Manager di System, nilai registry konfigurasi Sysmon dan sesi AutoLogger, dan log alat penyebar konfigurasi. Kerja forensiknya adalah membaca jejak itu sebelum memakai kata "sabotase", lalu menulis periode diam sebagai celah yang punya awal, akhir, sebab, dan sumber pengganti.

Kamu sudah mengenal pola ini dari NOC. Ketika grafik NetFlow dari satu router tiba-tiba datar, engineer berpengalaman tidak langsung menulis "ada yang mematikan exporter". Ia membuka log konfigurasi untuk melihat apakah ada `flow exporter` yang diubah dan oleh siapa, memeriksa counter drop di exporter untuk melihat apakah paket ekspor dibuang karena beban, membaca crashinfo dan uptime untuk tahu apakah line card sempat reboot, lalu mencocokkan dengan jadwal change: kalau sepuluh router yang baru menerima template ACL baru datar pada menit yang sama, penyebabnya template itu, bukan sepuluh penyusup. Batas analoginya ada dua. Pertama, di Windows, penyerang dengan hak admin memang bisa memakai jalur yang sama dengan admin sah (`sysmon64 -c`, registry, service control), jadi yang membedakan bukan alatnya, melainkan siapa, kapan, dari proses apa, dan apakah polanya cocok dengan change. Kedua, ada gangguan ETW yang terjadi di dalam memori proses dan tidak meninggalkan jejak di registry atau event log; untuk itu hanya memori yang bisa menjawab.

```
provider (Sysmon, Security, PowerShell, ...)        <- konfigurasi: apa yang BOLEH ditulis
   |   EID 16 = konfigurasi Sysmon berubah            (registry SysmonDrv\Parameters, sysmon64 -c)
   v
sesi ETW (buffer)                                   <- AutoLogger di registry: sesi apa start saat boot
   |   event hilang: buffer kecil, consumer lambat,     (Start, Enabled, Status per sesi/provider)
   |   disk lambat, kuota 8 sesi per provider
   v
consumer: Event Log service -> file .evtx           <- channel Sysmon/Operational
   |                          -> universal forwarder -> Splunk index sysmon
   v
ANALYST: Splunk diam?  -> cek host dulu:
   1. channel di host berisi?            (pipeline vs Sysmon)
   2. EID 4 Stopped / EID 16 / EID 255?  (service, konfigurasi, beban)
   3. System: 7036, 7026, 7000, 6008, 41, 1001  (service, driver, crash)
   4. registry: SysmonDrv Start, Parameters, AutoLogger
   5. siapa yang menjalankan apa (4688, Defender) dan cocok dengan change?
   -> sabotase | operasional | tidak dapat ditentukan  + celah: awal, akhir, sumber pengganti
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan dan data pribadi sekitar 400 ribu pelanggan broadband. Setelah empat kasus di akhir 2026 menunjukkan Sysmon yang tidak seragam dan sempit, rencana kapabilitas SOC 2027 menetapkan dua tindakan telemetri teratas: GPO audit setara `JAB-WS-Audit` untuk semua OU workstation (target Maret 2027), dan onboarding Defender for Endpoint serta Sysmon ke semua workstation dengan konfigurasi Sysmon yang ditinjau ulang, dengan Sari Kusuma (technical lead) sebagai pemilik konfigurasi Sysmon (target Juni 2027). Sejak Februari 2027 Sysmon 15.22 dan konfigurasi baru `jab-sysmon-ws` versi 2.0 disebar bergelombang ke workstation Jakarta dan Bandung. Setiap workstation punya scheduled task `\JAB\SysmonConfigSync` (berjalan sebagai SYSTEM saat startup dan setiap hari pukul 09:30 dan 13:30 dengan jeda acak sampai 10 menit) yang membandingkan hash berkas konfigurasi di `\\corp.jab.example\NETLOGON\Sysmon\` dengan salinan lokal, lalu menjalankan `sysmon64 -c` bila berbeda. Laptop di ring pilot `Pilot-Sysmon` membaca subfolder `pilot\`.

Rabu 2027-03-03, rule Splunk "Sysmon diam" dan "Sysmon error berulang" menyalakan sepuluh alert, `SOC-2027-0130` sampai `SOC-2027-0139`, dari sembilan host: enam laptop staf SOC dan IT di ring pilot pukul 10:15, dua laptop Bandung pukul 10:02 dan 10:09, dan `JKT-WS-0536` pukul 12:30 dan 17:04. `JKT-WS-0536` (`10.10.53.36`, Windows 11 Enterprise 25H2 build 26200) adalah laptop staf Keuangan Jakarta yang di-reimage Jumat 2027-02-26 dan diserahkan ke pemilik baru, Yuni Astuti (`yuni.astuti`), yang mulai bekerja Senin 2027-03-01; Sysmon di laptop itu diam lebih dari lima jam. Rudi Hartanto (analyst L2, primary on-call) menautkan alert pilot ke change konfigurasi siang itu, tetapi `JKT-WS-0536` tidak ada di ring pilot. Dimas Prasetyo (SOC lead) membuka `INC-2027-013` (SEV-3, dugaan gangguan telemetri) Rabu 17:20; Yoga Pratama mengambil paket investigasi Defender dan koleksi triage laptop itu lewat live response Rabu sore. Kamis 2027-03-04 pukul 08:30, Sari menulis kepadamu di kanal `#inc-2027-013`:

> "Pagi. Sembilan host Sysmon-nya diam kemarin dan saya pemilik konfigurasinya, jadi saya mau jawaban yang tidak berpihak, termasuk kalau ternyata salah saya. Pertama, apakah Sysmon di host itu benar berhenti mencatat, atau event-nya cuma tidak sampai ke Splunk? Kedua, konfigurasi apa yang sebenarnya berlaku di tiap host selama periode diam, dan ada tidak perubahan di luar jalur change saya? Ketiga, apakah ada yang menyentuh ETW di luar Sysmon, misalnya sesi AutoLogger atau provider yang dicabut? Keempat, untuk tiap kelompok host, ini sabotase atau masalah operasional, dan buktinya apa dari host sendiri, bukan dari Splunk saja? Kelima, apa yang hilang selama periode diam dan sumber apa yang bisa menggantikannya? Terakhir, 0536: kenapa diam lima jam padahal tidak ikut pilot, dan perlu kita perlakukan sebagai insiden atau bisa ditutup? Pak Dimas mau memutuskan jam 15:30, jadi tolong kirim sebelum jam 15:00."

Pesan itu memuat enam pertanyaan:

1. Apakah Sysmon benar berhenti mencatat di host, atau event-nya tidak sampai ke Splunk?
2. Konfigurasi apa yang berlaku di tiap host selama periode diam, dan adakah perubahan di luar jalur change?
3. Adakah yang menyentuh ETW di luar Sysmon, seperti sesi AutoLogger atau provider yang dicabut?
4. Untuk tiap kelompok host, sabotase atau masalah operasional, dan apa buktinya dari host?
5. Apa yang hilang selama periode diam, dan sumber apa yang menggantikannya?
6. Kenapa `JKT-WS-0536` diam lima jam, dan apakah perlu diperlakukan sebagai insiden?

Pertanyaan 1 dijawab di bagian 1.1 dan 1.2, pertanyaan 2 di bagian 1.5, pertanyaan 3 di bagian 1.6, pertanyaan 4 di bagian 1.7 dan 1.8, pertanyaan 5 di bagian 1.3 dan 1.4, dan pertanyaan 6 di bagian 1.8. Bagian 2 berisi perintah, keluaran ilustrasi, dan jawaban tertulis yang kamu kirim ke Sari.

**Kapan relevan:** saat telemetri dari host berhenti atau menipis (alert "Sysmon diam", grafik index turun, kekosongan di timeline), saat menilai apa yang mungkin ada di sebuah host sebelum menyimpulkan dari ketiadaan event, saat menulis batas bukti untuk laporan, dan saat merancang atau mengubah konfigurasi Sysmon untuk fleet.
**Kapan bukan jawaban:** Day ini bukan tentang membersihkan log atau menghapus jejak setelah kejadian (itu Day 21), bukan panduan menulis aturan deteksi dari event Sysmon, dan bukan cara memeriksa gangguan ETW di dalam memori proses (teknik itu hanya disebut arah pemeriksaannya; pembuktiannya butuh akuisisi dan analisis memori seperti Day 14 dan 15).

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (Sysmon, event log dan channel `.evtx`, audit policy, 4688, 7036, 7045, 1102, 104, 4719, Logon ID, telemetry EDR, retensi telemetry, jejak responder, salinan kerja, live response, lembar batas bukti, celah telemetri, hipotesis tandingan) tidak diulang. Tabel ini hanya memuat istilah baru Day ini; kolom padanan memakai analogi NOC dan SOC yang sama di semua Day.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| ETW (Event Tracing for Windows) | Fasilitas penelusuran tingkat kernel tempat sebagian besar log Windows modern dibangkitkan | Mesin `logging` dan `debug` di router: semua pesan syslog lahir di sini sebelum dikirim ke buffer atau collector |
| Provider | Komponen yang memuat instrumentasi dan menulis event bila diaktifkan | Fitur di router yang punya pesan log sendiri (`%LINK`, `%SYS`, `%SEC`) |
| Sesi (trace session) | Wadah berbuffer yang menampung event dari provider yang diaktifkan untuknya | Satu tujuan logging (buffer lokal, satu syslog server) dengan ukuran buffer sendiri |
| Controller | Komponen yang memulai, menghentikan, dan mengatur sesi serta mengaktifkan provider | Perintah konfigurasi `logging host` dan `logging buffered` |
| Consumer | Komponen yang membaca event dari sesi, real time atau dari berkas | Syslog collector atau NMS yang membaca pesan |
| Sesi AutoLogger | Sesi yang didefinisikan di registry dan dimulai otomatis saat boot | Baris `logging` di startup-config yang aktif setiap kali perangkat boot |
| `logman` | Alat bawaan Windows untuk melihat dan mengatur sesi trace | `show logging` dan konfigurasi logging dari CLI |
| Konfigurasi Sysmon (`Rules`) | Aturan include dan exclude per event, disimpan di registry dan dibaca driver | ACL atau filter template pada flow exporter: yang tidak cocok tidak pernah diekspor |
| EID 4, 16, 255 Sysmon | Service Sysmon start atau stop; konfigurasi berubah; error di dalam Sysmon | `%SYS-5-RESTART`, `%SYS-5-CONFIG_I`, dan counter drop di exporter |
| Direktori arsip Sysmon | Folder di akar volume tempat Sysmon menyimpan salinan berkas yang dihapus bila dikonfigurasi | Folder `archive` di flash yang menyimpan salinan konfigurasi sebelum ditimpa |
| Periode diam | Rentang waktu ketika sumber telemetri tidak menghasilkan atau tidak mengirim event | Gap di grafik NetFlow: punya awal, akhir, dan sebab yang harus dicari |
| Sabotase vs masalah operasional | Dua hipotesis untuk periode diam: dimatikan atau dilemahkan sengaja, atau sebab teknis atau change yang sah | Fiber dipotong orang vs link turun karena maintenance terjadwal atau modul rusak |

### 1.1 Dari provider ke Splunk: arsitektur ETW dan jalur event Sysmon

Pertanyaan pertama Sari ("benar berhenti, atau tidak sampai ke Splunk?") hanya bisa dijawab bila kamu tahu jalur yang dilewati satu event Sysmon sebelum muncul di index `sysmon`. Jalur itu punya beberapa sambungan, dan setiap sambungan bisa putus sendiri-sendiri.

ETW adalah fasilitas penelusuran tingkat kernel yang mencatat event kernel maupun event yang didefinisikan aplikasi, dan bisa dinyalakan atau dimatikan secara dinamis tanpa me-restart komputer atau aplikasi [S2]. Tiga komponennya [S2]:

- **Controller.** Memulai dan menghentikan sesi, mengaktifkan provider, menentukan ukuran dan lokasi berkas log, mengelola kolam buffer, dan mengambil statistik sesi, termasuk jumlah buffer yang dipakai, yang dikirim, serta event dan buffer yang hilang.
- **Provider.** Aplikasi atau komponen yang memuat instrumentasi; setelah diaktifkan controller, ia menghasilkan event.
- **Consumer.** Membaca event dari satu atau beberapa sesi, dari berkas log atau real time, dan menerimanya dalam urutan kronologis.

Ada empat jenis provider, dan perbedaannya punya akibat praktis [S2]. Provider MOF (klasik) dan WPP hanya bisa diaktifkan oleh satu sesi pada satu waktu. Provider berbasis manifest dan provider TraceLogging bisa diaktifkan sampai delapan sesi sekaligus. Batas delapan sesi itu layak diingat: pada host dengan beberapa produk keamanan dan alat diagnostik yang berlangganan provider yang sama, kuota bisa habis, dan sesi berikutnya tidak menerima event. Itu salah satu sebab kekosongan telemetri yang bukan ulah penyerang.

Untuk Sysmon, jalurnya bisa digambarkan sebagai empat sambungan. Driver Sysmon (boot-start, nama bawaan `SysmonDrv`) menangkap aktivitas sejak awal boot, dan service Sysmon menulis event ke event log begitu service berjalan [S1]. Event ditulis ke channel `Microsoft-Windows-Sysmon/Operational` di Vista ke atas, dengan timestamp UTC [S1]. Channel disimpan layanan Event Log sebagai `Microsoft-Windows-Sysmon%4Operational.evtx` (Day 05 bagian 1.1). Terakhir, universal forwarder Splunk membaca channel itu dan mengirimnya ke index `sysmon`. Grafik di Splunk yang turun ke nol bisa berasal dari sambungan mana pun:

| Sambungan putus | Yang terlihat di host | Yang terlihat di Splunk |
|---|---|---|
| Sysmon tidak menulis (service berhenti, driver tidak termuat, konfigurasi mengecualikan) | Channel Sysmon kosong atau menipis pada periode itu; ada atau tidak ada EID 4, 16, 255 | Index `sysmon` kosong atau menipis |
| Event hilang di sesi (beban tinggi, buffer, consumer lambat) | Channel berisi tetapi lebih jarang dari biasanya; EID 255 bisa muncul | Menipis, tidak nol |
| Event Log service bermasalah | Channel tidak bertambah; jejak di System | Semua channel host itu ikut diam, bukan hanya Sysmon |
| Forwarder tidak mengirim | Channel di host berisi lengkap | Kosong untuk semua index host itu, atau hanya `sysmon` bila input-nya yang rusak |

Tabel ini dibaca dari kolom tengah: kalau channel di host berisi lengkap, masalahnya di pipeline, bukan di Sysmon, dan pertanyaan sabotase pindah ke forwarder. Karena itu langkah pertama selalu membandingkan isi channel di host (dari koleksi atau live response) dengan isi index pada periode yang sama (bagian 2.2).

Satu hal lagi dari arsitektur ini: event bisa hilang tanpa ada yang mengganggu. Dokumentasi menyebut empat sebab [S2]: ukuran total event melebihi 64K termasuk header; buffer ETW lebih kecil daripada ukuran event; consumer real time tidak cukup cepat atau tidak ada sama sekali, termasuk saat layanan Event Log dihentikan dan dijalankan lagi ketika event sedang ditulis; dan disk terlalu lambat mengikuti laju pencatatan. Sebab ketiga dan keempat relevan untuk host yang sedang sangat sibuk, seperti dua laptop Bandung di kasus ini (bagian 1.7).

### 1.2 Di mana jejaknya tersimpan

Masih untuk pertanyaan pertama, setelah tahu jalurnya, kamu perlu tahu di mana jalur itu meninggalkan sesuatu yang bisa dibaca dari image, koleksi triage, atau live response. Event yang sudah sampai ke Splunk hanyalah salah satu tempat; konfigurasi dan keadaan pipeline tersimpan di host.

Tabel ini memetakan tempat jejak ETW dan Sysmon tersimpan, dan nilai forensiknya; perhatikan kolom tengah, karena sebagian besar tempat itu adalah konfigurasi, bukan event.

| Tempat | Isi | Nilai forensik |
|---|---|---|
| Channel di event log (`.evtx`) | Event dari provider berbasis manifest yang dialirkan ke layanan Event Log, termasuk Sysmon/Operational dan System | Tinggi; dibaca EvtxECmd (Day 05) |
| Berkas trace `.etl` | Keluaran sesi yang menulis ke berkas; bawaan AutoLogger ada di `%SystemRoot%\System32\LogFiles\WMI\` [S3] | Bervariasi; perlu alat khusus, isinya bergantung sesi |
| Registry sesi AutoLogger | `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\<sesi>`, satu subkey per provider ber-GUID [S3] | Tinggi; menjelaskan sesi apa yang start saat boot dan provider apa yang aktif |
| Registry konfigurasi Sysmon | `HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters` (nilai `Rules`, `HashingAlgorithm`, `Options`) [S13] | Tinggi; konfigurasi yang benar-benar dibaca driver, bukan berkas XML yang mungkin sudah berubah |
| Registry service dan driver | `Services\Sysmon64` dan `Services\SysmonDrv` (nilai `Start`, `ImagePath`) | Tinggi; mengubah `Start` adalah cara mematikan perekaman tanpa menghapus |
| Direktori arsip Sysmon | Salinan berkas yang dihapus, bila EID 23 dikonfigurasi [S1] | Tinggi bila ada (bagian 1.4) |
| Buffer di memori | Event yang belum ditulis ke mana pun, dan keadaan provider di dalam proses | Hanya lewat akuisisi memori (Day 14) |

Dua baris di tengah tabel paling sering terlewat. Sesi AutoLogger dikonfigurasi lewat registry, sehingga daftar sesi yang berjalan sejak boot dan provider yang diaktifkannya bisa dibaca dari hive SYSTEM secara offline [S3]. Konfigurasi Sysmon juga tersimpan di registry, dan service Sysmon memuat ulang konfigurasinya secara otomatis bila nilai registry itu berubah [S1][S13]. Akibatnya ada dua jalur untuk mengubah apa yang dicatat Sysmon: perintah `sysmon64 -c` dan penulisan langsung ke registry (misalnya lewat Group Policy Preferences, seperti yang dipakai sebagian organisasi untuk menyebar aturan) [S13]. Pemeriksa harus melihat keduanya.

Di luar tempat bawaan Windows, ada jejak milik prosesmu sendiri: log alat penyebar konfigurasi. Di PT JAB, task `\JAB\SysmonConfigSync` menulis log ringkas di `C:\ProgramData\JAB\SysmonSync\sync.log` (waktu jalan, hash berkas di share, hash lokal, hasil `sysmon64 -c`). Log semacam ini tidak dijamin utuh (siapa pun dengan hak admin bisa mengeditnya), tetapi bila isinya cocok dengan EID 16 di channel Sysmon dan dengan history task, tiga sumber itu saling menguatkan.

Jawaban pertanyaan pertama untuk kasus ini dibangun dari perbandingan isi channel di host dengan isi index (bagian 2.2). Di semua sembilan host, channel Sysmon di host menunjukkan pola yang sama dengan Splunk: Sysmon memang tidak menulis atau menulis lebih sedikit, dan forwarder tetap mengirim channel lain. Masalahnya ada di Sysmon, bukan di pipeline.

### 1.3 Sysmon sebagai sumber bukti dan apa yang hilang saat ia diam

Pertanyaan kelima Sari ("apa yang hilang dan apa penggantinya?") membutuhkan daftar apa yang biasanya disumbangkan Sysmon. Nilai Sysmon bagi pemeriksa terletak pada hal yang tidak dicatat Windows secara bawaan; ketika ia diam, itulah yang hilang.

Sysmon adalah service dan driver yang bertahan melewati reboot dan mencatat aktivitas sistem ke event log [S1]. Service-nya berjalan sebagai protected process, sehingga banyak interaksi dari user mode tidak diizinkan, dan Sysmon tidak mencoba menyembunyikan diri dari penyerang [S1]. Tabel berikut memuat event yang paling berguna di pekerjaan forensik dari daftar resmi event ID 1 sampai 29 dan 255 [S1]; baca kolom kanan, karena itulah sumber pengganti saat Sysmon diam di host PT JAB yang ber-EDR dan ber-GPO audit.

| ID | Event | Kenapa berharga | Sumber pengganti bila Sysmon diam |
|---|---|---|---|
| 1 | Process creation | Command line proses dan induknya, hash, `ProcessGuid` yang unik walau PID dipakai ulang [S1] | Security 4688 dengan command line (tanpa hash dan GUID); Defender `DeviceProcessEvents` |
| 2 | Waktu pembuatan berkas diubah | Timestomping (Day 21 bagian 1.6); banyak proses sah juga melakukannya [S1] | `$MFT` SI vs FN dan `$J` (Day 08) |
| 3 | Network connection | Koneksi per proses; mati secara bawaan [S1] | Defender `DeviceNetworkEvents`; log firewall dan proxy |
| 4 | Service Sysmon start atau stop | Tidak bisa difilter [S1] | System 7036 untuk service Sysmon |
| 8 | CreateRemoteThread | Injeksi; `StartModule` dan `StartFunction` disimpulkan dan bisa kosong [S1] | Defender (alert dan sebagian event); memori bila diambil |
| 9 | RawAccessRead | Pembacaan lewat notasi `\\.\` untuk mengambil berkas terkunci [S1] | Hampir tidak ada di host; Defender bila mendeteksi alatnya |
| 10 | ProcessAccess | Pembukaan proses lain, termasuk LSASS [S1] | Defender (alert akses kredensial); memori hanya untuk detik akuisisi |
| 11 | FileCreate | Berkas dijatuhkan di Downloads, Temp, Startup [S1] | `$J` dan `$MFT` (Day 08); Defender `DeviceFileEvents` |
| 12, 13, 14 | Registry | Perubahan key autostart [S1] | Last write time key (Day 09); Defender `DeviceRegistryEvents` |
| 16 | Konfigurasi Sysmon berubah | Tidak bisa difilter [S1] | Log alat penyebar konfigurasi; last write `SysmonDrv\Parameters` |
| 19, 20, 21 | WMI filter, consumer, binding | Persistence WMI (Day 11 bagian 1.5) [S1] | `OBJECTS.DATA` offline; WMI-Activity |
| 22 | DNS query | Resolusi nama per proses; tidak ada di Windows 7 ke bawah [S1] | Log resolver internal (index `dns`) tanpa nama proses; Defender |
| 23 | FileDelete dengan arsip | Berkas yang dihapus disimpan ke direktori arsip [S1] | `$J` dan Recycle Bin (Day 08), tanpa isi berkas |
| 25 | ProcessTampering | Hollowing dan teknik penyembunyian proses [S1] | Memori (Day 15) |
| 26 | FileDeleteDetected | Penghapusan dicatat tanpa menyimpan berkas [S1] | `$J` |
| 28 | FileBlockShredding | Memblokir shredding oleh alat seperti SDelete [S1] | Tidak ada pengganti untuk efek blokirnya |
| 255 | Error | Sysmon mengalami error: beban berat, bug, atau syarat keamanan dan integritas tidak terpenuhi [S1] | Tidak ada; ini justru penanda gangguan |

Ada pola yang perlu disadari dari kolom kanan. Untuk eksekusi proses, host PT JAB yang berada di OU dengan GPO audit masih punya 4688 dengan command line, sehingga kehilangan terbesarnya adalah hash dan `ProcessGuid`, bukan peristiwanya. Untuk koneksi jaringan per proses dan akses ke LSASS, pengganti di host hampir tidak ada; yang tersisa adalah Defender for Endpoint. Untuk host tanpa audit dan tanpa EDR, periode diam Sysmon berarti kehilangan hampir seluruh visibilitas proses. Jadi "apa yang hilang" tidak bisa dijawab untuk semua host sekaligus; ia dijawab per host dari kombinasi Sysmon, audit, dan EDR yang ada di host itu (bagian 2.7).

Satu batas lagi yang sering dilupakan: sumber pengganti juga punya konfigurasi dan retensi sendiri. Data mentah advanced hunting Defender hanya tersedia sampai 30 hari (Day 17 bagian 1.3), jadi pemeriksaan sumber pengganti untuk periode diam harus dilakukan, atau hasilnya diekspor, sebelum jendela itu lewat.

### 1.4 Direktori arsip Sysmon

Bagian lain dari pertanyaan kelima adalah apakah ada berkas yang bisa dipulihkan dari periode di sekitar celah. Sysmon punya fitur yang jarang dikenal dan sering menyelamatkan kasus: copy-on-delete.

Ketika EID 23 aktif, berkas yang dihapus disalin ke direktori arsip, dan direktori itu dilindungi ACL System sehingga tidak mudah dibuka; dokumentasi menyarankan PsExec dengan opsi `-sid` untuk membukanya dari konteks System [S1]. Entri konfigurasi yang mengaturnya [S1]:

| Entri | Fungsi |
|---|---|
| `ArchiveDirectory` | Nama direktori di akar volume tempat berkas hasil copy-on-delete dipindahkan |
| `CopyOnDeletePE` | Menyimpan berkas image executable saat dihapus (bawaan `False`) |
| `CopyOnDeleteExtensions` | Ekstensi berkas yang disimpan saat dihapus |
| `CopyOnDeleteProcesses` | Nama proses yang penghapusan berkasnya disimpan |
| `CopyOnDeleteSIDs` | Daftar SID akun yang penghapusan berkasnya disimpan |

Dokumentasinya tidak konsisten soal nilai bawaan: penjelasan EID 23 menyebut direktori arsip bawaan `C:\Sysmon`, sedangkan tabel entri konfigurasi menyebut nilai bawaan `Sysmon` [S1]. Karena entri itu didefinisikan sebagai nama direktori di akar volume, keduanya mungkin berarti hal yang sama untuk volume `C:`, tetapi jangan bergantung pada tafsir itu: baca nilai `ArchiveDirectory` dari konfigurasi aktif host, lalu cari direktori dengan nama itu di akar setiap volume.

Dokumentasi juga memperingatkan bahwa dalam kondisi normal direktori ini bisa tumbuh sampai ukuran yang tidak wajar, dan menyarankan EID 26 untuk perilaku serupa tanpa menyimpan berkas [S1]. Itu alasan banyak organisasi memilih EID 26 saja. Konsekuensinya bagi pemeriksa: sebelum berharap menemukan berkas di arsip, baca konfigurasi host untuk melihat apakah EID 23 aktif, ekstensi apa yang disimpan, dan sejak kapan.

Ada satu batas yang langsung relevan dengan periode diam: arsip hanya terisi selama Sysmon berjalan dan konfigurasinya memasukkan penghapusan itu. Penghapusan yang terjadi saat driver tidak termuat, atau saat konfigurasi yang berlaku tidak memuat EID 23, tidak pernah masuk arsip. Di PT JAB, konfigurasi 2.0 belum memakai EID 23 (hanya EID 26 untuk folder pengguna); EID 23 dengan `ArchiveDirectory` `JabSysmonArc` untuk skrip dan executable di folder pengguna baru ditambahkan di versi 2.1 yang dipilotkan, sehingga di `JKT-WS-0536` tidak ada direktori arsip sama sekali (bagian 2.7).

### 1.5 Konfigurasi sebagai peta celah

Pertanyaan kedua Sari ("konfigurasi apa yang berlaku, dan ada perubahan di luar change?") menempatkan konfigurasi Sysmon sebagai artefak tersendiri. Konfigurasi menentukan apa yang mungkin ada dan apa yang pasti tidak ada, sehingga satu baris konfigurasi bisa menjelaskan kekosongan yang terlihat seperti sabotase.

Aturan dasar filter Sysmon [S1]:

- Setiap event punya tag filter sendiri di bawah `EventFiltering`, dengan atribut `onmatch` bernilai `include` atau `exclude`.
- `include` berarti hanya event yang cocok aturan yang dicatat; `exclude` berarti semua event dicatat kecuali yang cocok aturan.
- Bila ada filter include dan exclude untuk event yang sama, exclude yang menang.
- Aturan pada field yang sama berperilaku OR, aturan pada field berbeda berperilaku AND, kecuali diatur ulang dengan `RuleGroup` (`groupRelation` `and` atau `or`).
- Filter include tanpa aturan berarti event itu tidak dicatat sama sekali; contoh resmi memakai `<ProcessTerminate onmatch="include" />` dengan komentar "jangan catat process termination".
- EID 4 dan EID 16 tidak bisa difilter.
- Atribut `schemaversion` di berkas konfigurasi tidak terikat ke versi biner Sysmon, sehingga konfigurasi lama tetap bisa diurai; artinya versi skema di berkas tidak bisa dipakai untuk menyimpulkan versi Sysmon yang terpasang.

Aturan keempat dan kelima adalah sumber kesalahan operasional yang paling mudah terjadi. Membalik `onmatch="exclude"` menjadi `onmatch="include"` pada event yang berbasis exclude ("catat semua kecuali yang bising") mengubah maknanya menjadi "catat hanya yang bising". Volume event turun drastis tanpa satu pun EID 4, karena service tidak pernah berhenti. Yang tercatat hanya EID 16 saat konfigurasi berganti. Itulah yang terjadi di enam laptop pilot PT JAB (bagian 2.4).

Yang dicari saat membaca konfigurasi:

- **Aturan exclude yang terlalu lebar.** Pengecualian berdasarkan nama image saja (`Image condition="end with"` sebuah nama berkas) bisa disalahgunakan proses lain dengan nama sama di path berbeda; pengecualian seluruh direktori menutup apa pun yang berjalan dari direktori itu. Penyerang yang bisa mengubah konfigurasi cenderung menambahkan pengecualian daripada mematikan Sysmon, karena jauh lebih senyap; ini penalaran dan pengamatan praktisi, bukan klaim dokumentasi.
- **Event yang dimatikan.** EID 3 mati secara bawaan, dan EID 7 perlu dikonfigurasi khusus karena volumenya besar [S1].
- **`HashAlgorithms`.** Tabel entri konfigurasi menulis bawaannya `None`, sedangkan bagian contoh pemasangan menyebut image di-hash SHA1 dengan pengaturan bawaan [S1]. Dua pernyataan ini tidak sejalan; tentukan dari isi event host itu (ada atau tidaknya field `Hashes` di EID 1), bukan dari asumsi.
- **`DriverName`.** Nama driver dan service bisa diganti [S1]. Ini dipakai secara sah untuk menyamarkan keberadaan Sysmon, tetapi juga berarti ketiadaan service `Sysmon64` tidak membuktikan Sysmon tidak terpasang.
- **`ArchiveDirectory` dan `CopyOnDelete*`.** Menentukan apakah berkas yang dihapus bisa dipulihkan (bagian 1.4).

Konfigurasi juga harus dibaca dari tempat yang tepat. Berkas XML di share atau di folder lokal adalah apa yang dimaksud penyebar; nilai `Rules` di `SysmonDrv\Parameters` adalah apa yang benar-benar dibaca driver [S13]; keluaran `sysmon64 -c` tanpa argumen menampilkan konfigurasi yang sedang aktif [S1]. Pada image, kamu hanya punya registry dan berkas. Pada host hidup, dump `sysmon64 -c` adalah potret yang paling dekat dengan kenyataan, dan harus disimpan sebagai bukti karena konfigurasi bisa berubah setelahnya.

Untuk menjawab "ada perubahan di luar change?", yang dicocokkan adalah tiga hal: setiap EID 16 di channel (waktu, path berkas konfigurasi, dan hash berkas), log alat penyebar, dan jadwal change. EID 16 yang waktunya sama dengan jalannya task sinkronisasi dan hash-nya sama dengan versi yang dirilis pemilik konfigurasi adalah perubahan di jalur change. EID 16 di luar jadwal, dengan path berkas yang tidak dikenal, atau dengan hash yang tidak cocok dengan versi mana pun, adalah temuan. Nama field persis di EID 16 (misalnya path dan hash berkas konfigurasi) cek di keluaran `sysmon64 -s` versi-mu, karena skema memuat nama dan tipe field tiap event [S1].

### 1.6 Sesi AutoLogger dan ETW di luar Sysmon

Pertanyaan ketiga Sari menanyakan sesuatu yang lebih luas daripada Sysmon: adakah yang menyentuh mesin ETW sendiri. Sysmon hanya salah satu provider; channel Security, System, PowerShell, dan sensor Defender juga bergantung pada sesi ETW yang berjalan sejak boot.

Sesi AutoLogger merekam event sejak awal proses boot dan dikonfigurasi lewat registry di `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger`, satu key per sesi dan satu subkey bernama GUID untuk setiap provider yang diaktifkan [S3]. Tabel ini memuat nilai yang paling berarti bagi pemeriksa; cari baris yang nilainya bisa mematikan perekaman tanpa menghapus apa pun.

| Nilai | Tingkat | Arti [S3] | Yang dicari pemeriksa |
|---|---|---|---|
| `Start` | Sesi | 1 = sesi dimulai saat restart berikutnya, 0 = tidak | `Start` 0 pada sesi yang di host sejenis bernilai 1 |
| `Guid` | Sesi | GUID sesi; bersama `Start`, satu-satunya nilai wajib | Sesi tanpa `Guid` tidak akan start |
| `Status` | Sesi | Status startup: 0 bila berhasil, kode error Win32 bila gagal | Kode error memberi sebab teknis, bukan sabotase |
| `FileName`, `MaxFileSize`, `FileMax` | Sesi | Lokasi dan ukuran berkas `.etl`; bawaan di `%SystemRoot%\System32\LogFiles\WMI\` | Berkas trace yang bisa diambil |
| `Enabled` | Provider | 1 = provider diaktifkan untuk sesi, 0 = tidak (bawaan 0) | Provider yang dimatikan di satu host saja |
| `EnableLevel`, `MatchAnyKeyword` | Provider | Tingkat detail dan kategori event yang ditulis provider | Nilai yang menyempit dibanding baseline |

Dua sifat AutoLogger menentukan cara membaca waktunya. Pertama, perubahan registry baru berlaku saat restart berikutnya [S3], sehingga gangguan lewat AutoLogger baru terlihat efeknya setelah reboot; cari reboot di antara perubahan dan periode diam. Kedua, karena nilai `Status` ditulis saat sesi mencoba start, last write time key sesi bisa ikut berubah setiap boot; bandingkan nilai dengan host sejenis, jangan hanya membaca waktunya. Perilaku pembaruan last write ini cek di lab dengan build yang sama.

Ada juga gangguan yang tidak lewat registry. Controller bisa menghentikan sesi atau mencabut provider dari sesi yang sedang berjalan, misalnya dengan `logman` dan opsi `-ets` yang mengirim perintah langsung ke sesi tanpa menyimpan atau menjadwalkan apa pun [S7][S8]. Perubahan semacam ini hilang saat reboot berikutnya, tetapi selama berlaku, provider tidak menulis ke sesi itu. Di host hidup, `logman query -ets` menampilkan sesi yang sedang berjalan, dan `logman query <nama sesi> -ets` menampilkan detail sesi termasuk provider-nya [S7]; bandingkan dengan host sejenis yang sehat. Dari image saja, perubahan sementara semacam ini hanya terlihat dari eksekusi alatnya (4688, Prefetch, Defender), bukan dari registry.

Lapisan paling dalam adalah gangguan di dalam memori proses, yaitu mengubah kode penulis event di proses tertentu supaya proses itu berhenti menghasilkan event. ATT&CK v20 memasukkan gangguan ETW ke dalam deskripsi teknik T1685 Disable or Modify Tools (taktik Defense Impairment, TA0112), dengan sub-teknik terdekat T1685.001 Disable or Modify Windows Event Log; tidak ada sub-teknik khusus ETW [S15]. Teknik ini tidak meninggalkan jejak di registry AutoLogger atau di konfigurasi Sysmon. Tanda tidak langsungnya adalah satu proses yang "sunyi" di satu sumber padahal terlihat aktif di sumber lain (misalnya ada di 4688 dan di Defender tetapi tidak menghasilkan event PowerShell yang seharusnya ada); pembuktiannya butuh memori. Day ini hanya menyebut arah pemeriksaan itu, bukan tekniknya.

Komunitas deteksi sudah menulis aturan untuk jalur registry ini: aturan Sigma yang eksperimental memantau `reg.exe` atau PowerShell yang menulis nilai `Start` atau `Enabled` di bawah `\Control\WMI\Autologger\`, dan menandainya dengan T1685.001 [S14]. Bagi pemeriksa, aturan itu menunjukkan dua hal: nilai mana yang paling sering dipakai penyerang, dan bahwa eksekusi alatnya (bukan hanya nilai registry) adalah bukti yang dicari.

Di kasus ini, hive SYSTEM `JKT-WS-0536` dibandingkan dengan laptop sejenis dari gold image yang sama (bagian 2.5): daftar sesi, `Start`, `Enabled`, dan level provider sama; `Status` semua sesi 0. Untuk enam laptop pilot dan dua laptop Bandung, `logman query -ets` lewat live response menunjukkan daftar sesi yang sama dengan baseline. Jawaban untuk Sari: tidak ada tanda ETW di luar Sysmon disentuh di sembilan host, dengan batas bahwa gangguan di dalam memori proses tidak diperiksa karena tidak ada indikasi yang mengarah ke sana.

### 1.7 Mengetahui perekaman diganggu: EID 4, 16, 255, dan Service Control Manager

Pertanyaan keempat Sari meminta bukti dari host. Jejak gangguan perekaman tersebar di dua channel yang saling melengkapi: channel Sysmon sendiri (yang hanya bisa bercerita selama Sysmon hidup) dan channel System (yang tetap menulis ketika Sysmon mati).

Tabel ini memetakan jalur putus ke jejak yang ditinggalkannya; baca kolom "Yang tidak ada", karena ketiadaan jejak tertentu sering lebih informatif daripada keberadaannya.

| Jalur putus | Jejak di channel Sysmon | Jejak di System dan registry | Yang tidak ada |
|---|---|---|---|
| Service dihentikan atau Sysmon dihapus (`sysmon64 -u`) | EID 4 Stopped sebagai event terakhir [S1] (Day 21 bagian 2.5) | 7036 service berhenti; driver dilepas | Tidak ada crash (6008, 41) |
| Konfigurasi diganti (`sysmon64 -c` atau registry) | EID 16 dengan berkas dan hash konfigurasi baru [S1] | Last write `SysmonDrv\Parameters` | Tidak ada EID 4; service tetap jalan |
| Beban berat atau bug | EID 255 berulang; event menipis [S1] | Biasanya tidak ada | Tidak ada EID 4 atau 16 |
| Driver tidak termuat saat boot | Tidak ada event sama sekali sejak boot; tidak ada EID 4 Stopped sebelumnya | 7026 (boot-start driver tidak termuat) dan error start service | Tidak ada EID 4 Stopped atau 16 |
| Driver atau service dimatikan lewat `Start` 4, lalu reboot | Tidak ada event sejak boot | Nilai `Start` berubah, last write key service; tidak ada 7026 karena driver tidak dicoba dimuat | Tidak ada EID 4 Stopped bila host langsung dimatikan |
| Host crash | Event berhenti tiba-tiba tanpa EID 4 | 41 Kernel-Power dan 6008 saat boot berikutnya; 1001 BugCheck bila ada dump | Tidak ada EID 4 Stopped |

Tiga hal dari tabel ini dipakai berulang di bagian 2. Pertama, EID 4 dan EID 16 tidak bisa difilter [S1], sehingga penghentian service yang bersih atau penggantian konfigurasi selalu meninggalkan jejak di channel Sysmon selama event log berjalan. Kekosongan yang dimulai tanpa EID 4 Stopped berarti Sysmon tidak berhenti secara bersih: host crash, driver tidak termuat, atau event log sendiri berhenti. Kedua, 7026 dan nilai `Start` membedakan "dicoba dimuat tetapi gagal" dari "tidak pernah dicoba"; penalaran ini mengikuti cara Service Control Manager memperlakukan driver boot-start, dan perilakunya cek di lab. Ketiga, EID 255 dipicu beban berat, bug, atau syarat keamanan dan integritas yang tidak terpenuhi [S1]; isinya menunjukkan Sysmon masih hidup tetapi kewalahan atau terganggu, dan beban berat harus dicocokkan dengan sesuatu yang membebani host pada waktu yang sama.

Untuk perubahan yang dilakukan orang, pertanyaan "siapa" dijawab di luar Sysmon. Panduan aktivitas mencurigakan Sysmon dari Microsoft menyarankan, untuk EID 4 Stopped, mencari event dari Service Control Manager di System log untuk tahu kenapa service berhenti [S13]. Di host dengan GPO audit, 4688 memuat proses yang menjalankan `sysmon64`, `sc.exe`, `reg.exe`, `logman.exe`, `wevtutil.exe`, atau `fltmc.exe` beserta induk dan akunnya, dan 4672 menunjukkan sesi yang memegang hak admin. Defender `DeviceProcessEvents` dan `DeviceRegistryEvents` memberi salinan dari luar host. Perubahan yang sah punya induk yang bisa dijelaskan (task sinkronisasi yang berjalan sebagai SYSTEM dari layanan Task Scheduler), waktu yang cocok dengan jadwal, dan pola yang sama di banyak host. Perubahan yang tidak sah biasanya berasal dari sesi interaktif atau jarak jauh dengan akun admin, di satu host, di luar jadwal.

Di kasus ini, ketiga kelompok host menunjukkan tiga jalur yang berbeda: enam laptop pilot punya EID 16 tanpa EID 4 (konfigurasi diganti), dua laptop Bandung punya EID 255 berulang tanpa EID 4 atau 16 (beban), dan `JKT-WS-0536` punya kekosongan tanpa EID 4 Stopped, didahului crash dan diikuti 7026 untuk driver Sysmon (driver tidak termuat).

### 1.8 Membedakan sabotase dari masalah operasional

Pertanyaan keempat dan keenam bermuara pada satu keputusan per host, dan keputusan itu harus bisa dipertanggungjawabkan ke dua arah: menuduh sabotase tanpa bukti merugikan orang (di `JKT-WS-0536`, pemilik baru yang baru bekerja tiga hari), dan menutup sebagai "operasional" tanpa bukti bisa melewatkan penyerang yang memang memilih cara yang terlihat operasional.

Keduanya diuji sejajar sebagai hipotesis tandingan, dengan pertanyaan yang sama untuk setiap periode diam. Tabel ini adalah daftar pertanyaan itu; kolom tengah dan kanan menunjukkan jawaban yang mendukung masing-masing hipotesis.

| Pertanyaan | Mendukung operasional | Mendukung sabotase |
|---|---|---|
| Apa peristiwa awalnya? | Change, crash, beban, pembaruan, reboot yang terjadwal atau terjelaskan | `sysmon64 -u`, `sc stop`, perubahan registry, `logman ... -ets` dari sesi interaktif |
| Siapa atau proses apa yang melakukannya? | SYSTEM dari task atau agen pengelola yang dikenal | Akun admin di sesi interaktif atau jarak jauh, alat di folder pengguna |
| Polanya? | Banyak host, waktu berdekatan, sesuai ring atau gelombang | Satu host, waktu tidak terkait jadwal mana pun |
| Apakah sebab teknisnya terdokumentasi? | Event error dengan kode, `Status` AutoLogger bukan 0, kehilangan event sesuai sebab di [S2] | Tidak ada error, tetapi ada perubahan nilai |
| Apa yang terjadi di periode diam? | Aktivitas biasa pengguna di sumber pengganti | Aktivitas yang memang diuntungkan oleh kebutaan (eksekusi alat, akses kredensial, persistence) |
| Bagaimana periode itu berakhir? | Perbaikan change, reboot, beban selesai | Penyerang menyalakan kembali untuk menutupi, atau tidak berakhir |

Hasil yang sah ada tiga, bukan dua: operasional, sabotase, dan tidak dapat ditentukan. "Tidak dapat ditentukan" bukan kegagalan; ia memberi tahu IC bahwa perlu langkah tambahan (analisis dump crash, uji di lab, tanya vendor) sebelum kasus ditutup. Yang tidak boleh dilakukan adalah menulis "tidak ada sabotase" padahal yang terbukti hanyalah "tidak ditemukan tindakan yang menyentuh Sysmon atau ETW pada sumber yang tersedia".

Untuk `JKT-WS-0536`, jawabannya terbagi. Sabotase tidak didukung bukti: tidak ada EID 4 Stopped, tidak ada EID 16 di luar jadwal sebelum kekosongan, tidak ada eksekusi alat yang menyentuh Sysmon, service, registry, atau ETW di 4688 maupun Defender, nilai `Start` driver dan service tidak berubah sejak reimage, sesi AutoLogger sama dengan baseline, dan periode diam berisi aktivitas kerja biasa Yuni di sumber pengganti. Sebab langsungnya terlihat jelas dari System: laptop crash Rabu 11:52 WIB, dan saat boot berikutnya driver Sysmon tidak termuat (7026), sehingga Sysmon tidak mencatat sampai reboot normal sore harinya. Sebab dasarnya, kenapa driver gagal dimuat setelah crash, tidak dapat ditentukan dari bukti yang ada dan diteruskan ke tim IT bersama dump crash. Rekomendasinya: turunkan `INC-2027-013` ke SEV-4, tutup bagian sabotase untuk sembilan host, dan biarkan satu tindak lanjut teknis terbuka untuk `JKT-WS-0536` (bagian 2.9).

## 2. Contoh dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi yang disusun agar angka dan waktunya konsisten. Perintah atas salinan kerja dijalankan di workstation analisis `JKT-DFIR01`; perintah atas host hidup dijalankan lewat live response Defender for Endpoint (berjalan sebagai SYSTEM) dan hanya membaca; kueri Splunk dijalankan di search head `jkt-splunk-sh01` dengan zona waktu pengguna WIB. Narasi memakai WIB (UTC+7). EvtxECmd dan RECmd menulis waktu dalam UTC, dan event Sysmon sendiri ber-timestamp UTC [S1], jadi setiap keluaran diberi label zonanya (UTC = WIB dikurangi 7 jam). Alat dibekukan untuk kasus ini: EZ Tools 2026.5.0 dan Sysmon 15.22 yang sedang disebar. Cocokkan nama field, pesan event, dan format keluaran dengan versi di lab-mu.

Nomor bukti yang ditetapkan untuk `INC-2027-013`:

| Nomor | Isi | Diambil oleh dan kapan (WIB) |
|---|---|---|
| `INC-2027-013-E01` | Paket investigasi Defender `JKT-WS-0536` | Yoga, Rabu 2027-03-03 17:35-17:41, dari halaman perangkat |
| `INC-2027-013-E02` | Koleksi triage KAPE `JKT-WS-0536` lewat live response (event log, hive registry, `$MFT` dan `$J`, SRUM, folder `C:\ProgramData\JAB\SysmonSync\`, folder `C:\Windows\Minidump\`), container VHDX dalam zip, sekitar 1,2 GB | Yoga, Rabu 17:50-18:12; SHA-256 dihitung di host 18:13 (`5d0c...`), ditarik dengan `getfile` dan cocok di `jkt-evid01` 18:33 |
| `INC-2027-013-E03` | Ekspor Splunk index `sysmon` dan `wineventlog` (System, serta Security 4624, 4672, 4688) untuk sembilan host, Rabu 07:00-19:00 WIB, CSV beserta berkas `.sha256` | Rudi, Rabu 18:30-18:52 |
| `INC-2027-013-E04` | Keluaran live response baca-saja dari delapan host lain dan dari laptop pembanding `JKT-WS-0537` (`sysmon64 -c`, `logman query -ets`, hitungan event Sysmon 4, 16, 255, ekspor key AutoLogger pembanding) | Kamu, Kamis 2027-03-04 09:05-09:50 |

Salinan kerja `E02-W1` dibuat Yoga Rabu 18:40 di `/cases/INC-2027-013/work/`. `JKT-WS-0537` adalah laptop Keuangan lain dari gold image `JAB-WS-GOLD-25H2-2027.02` yang sama, di OU yang sama, dengan konfigurasi Sysmon 2.0, dan tidak ada di daftar alert; ia dipakai sebagai pembanding "host sejenis yang sehat".

### 2.1 Menyiapkan salinan kerja dan profil cakupan `JKT-WS-0536`

Langkah ini menyiapkan E02-W1 untuk pertanyaan 1, 4, dan 6 tanpa menyentuh master, lalu memproses event log dengan cara yang sama seperti Day 05.

**Tujuan:** memastikan salinan kerja identik dengan master, me-mount-nya read-only, dan menghasilkan CSV event log yang menjadi bahan bagian 2.2, 2.3, dan 2.6.

```
# di JKT-DFIR01, Kamis 08:50 WIB
Get-FileHash -Path \\jkt-evid01\cases\INC-2027-013\work\E02-W1\INC-2027-013-E02_JKT-WS-0536.zip -Algorithm SHA256
# ekstrak VHDX ke C:\DFIR\work\INC-2027-013\E02-W1\, mount read-only sebagai G:
EvtxECmd.exe -d G:\C\Windows\System32\winevt\Logs ^
  --csv \\jkt-evid01\cases\INC-2027-013\analysis\E02-W1\EZ-2026.5.0\EventLogs --csvf E02-W1_evtx.csv
```

- `Get-FileHash ... SHA256`: hasilnya dibandingkan dengan `5d0c...` di evidence log; hash cocok berarti salinan kerja siap.
- `G:\C\...`: KAPE menyimpan path asli di bawah folder huruf drive di dalam container.
- `-d`: memproses semua `.evtx` di folder itu sekaligus; `--csv` dan `--csvf`: folder dan nama berkas keluaran di share kasus, bukan di salinan kerja.

Keluaran ilustrasi (ringkasan console):

```
Processed 142 files in 61.0442 seconds
Microsoft-Windows-Sysmon%4Operational.evtx        11,904 events  2027-02-26 03:41:20 - 2027-03-03 11:11:58 (UTC)
Security.evtx                                     38,615 events  2027-02-26 03:12:45 - 2027-03-03 11:12:03 (UTC)
System.evtx                                        3,217 events  2027-02-26 03:10:58 - 2027-03-03 11:11:40 (UTC)
```

**Cara membaca hasil:** semua channel penting mencakup sejak reimage Jumat 2027-02-26 (sekitar 10:10 WIB) sampai koleksi Rabu sekitar 18:12 WIB, karena laptop baru lima hari sejak reimage dan log belum berputar. Event Sysmon pertama 03:41:20 UTC (10:41:20 WIB) adalah saat Sysmon dipasang setelah reimage. Profil ini menjawab "apa yang mungkin ada": Security punya 4688 karena laptop berada di OU dengan GPO audit, dan Sysmon punya seluruh jendela kecuali periode diam.

**Variasi:** bila hanya channel Sysmon yang diperlukan, proses satu berkas: `EvtxECmd.exe -f "G:\C\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx" --csv <folder> --csvf sysmon.csv`. Untuk delapan host lain, profil yang sama dibuat dari E04 (live response) dengan `Get-WinEvent -ListLog Microsoft-Windows-Sysmon/Operational` untuk ukuran dan jumlah record, dan dari E03 untuk isi.

**Kapan gagal:** container ditarik tanpa hash di host, sehingga kesamaan isi antara yang dikoleksi dan yang dianalisis tidak bisa ditunjukkan; atau VHDX di-mount read-write secara bawaan. Hash di titik koleksi dan mount read-only adalah dua langkah yang dulu menjadi celah (Day 20 bagian 1.11), dan di kasus ini keduanya dikerjakan.

### 2.2 Host atau pipeline: membandingkan channel di host dengan index

Langkah ini menjawab pertanyaan pertama: apakah Sysmon berhenti menulis, atau event-nya tidak sampai ke Splunk.

**Tujuan:** untuk setiap host, hitung event Sysmon per jam di index dan di host pada jendela yang sama, dan bandingkan Sysmon EID 1 dengan Security 4688 sebagai pembanding yang tidak bergantung Sysmon.

```
(index=sysmon EventCode=1) OR (index=wineventlog source="WinEventLog:Security" EventCode=4688)
host=JKT-WS-0536 earliest="03/03/2027:07:00:00" latest="03/03/2027:19:00:00"
| eval sumber=if(index=="sysmon","sysmon_eid1","sec_4688")
| timechart span=1h count by sumber
```

- Dua pencarian digabung dengan `OR` supaya keduanya berada di sumbu waktu yang sama.
- `earliest` dan `latest` ditulis absolut (data kasus statis), dalam zona waktu pengguna WIB.
- `eval sumber=if(...)` memberi label; `timechart span=1h count by sumber` menghitung per jam.

Keluaran ilustrasi (WIB):

```
_time              sec_4688  sysmon_eid1
2027-03-03 07:00      107        98
2027-03-03 08:00      152       141
2027-03-03 09:00      127       118
2027-03-03 10:00      104        96
2027-03-03 11:00      168        71
2027-03-03 12:00       88         0
2027-03-03 13:00       79         0
2027-03-03 14:00       97         0
2027-03-03 15:00       84         0
2027-03-03 16:00       76         0
2027-03-03 17:00      171        64
2027-03-03 18:00       58        52
total                1311       640
```

**Cara membaca hasil:** sampai pukul 11:00, EID 1 sedikit di bawah 4688, karena konfigurasi 2.0 mengecualikan beberapa updater yang bising; perbandingan ini normal untuk laptop itu. Jam 11 menunjukkan 4688 melonjak (proses boot setelah crash, bagian 2.6) sementara EID 1 turun; jam 12 sampai 16 EID 1 nol padahal 4688 terus mengalir; jam 17 keduanya kembali. Security dan forwarder tetap bekerja, jadi pipeline host ke Splunk hidup. Langkah berikutnya memastikan bahwa nol ini juga nol di host.

Hitungan dari channel di host (E02-W1, CSV bagian 2.1) untuk Rabu 07:00-19:00 WIB:

| Sumber | Event Sysmon (semua EID) | Event Sysmon 11:52:31-17:03:51 |
|---|---|---|
| Channel di host (E02-W1) | 2.418 | 0 |
| Index `sysmon` (E03) | 2.418 | 0 |

Angkanya sama, termasuk nol di periode diam: Sysmon di `JKT-WS-0536` memang tidak menulis, bukan event-nya tertahan di forwarder.

Untuk enam laptop pilot, pola Splunk berbeda. Contoh `JKT-WS-0503` (WIB):

```
_time              sec_4688  sysmon_eid1
2027-03-03 09:00      141       131
2027-03-03 10:00      118         7
2027-03-03 11:00      126         9
2027-03-03 12:00       97         5
2027-03-03 13:00      133        71
2027-03-03 14:00      122       116
```

EID 1 tidak nol, tetapi turun ke satu digit per jam antara konfigurasi 2.1 diterapkan (09:33:52) dan 2.2 diterapkan (13:30:58); yang masih tercatat hanya proses di daftar "bising". Hitungan `Get-WinEvent` dari E04 untuk jendela yang sama sama dengan index di keenam host. Dua laptop Bandung menunjukkan pola ketiga: EID 1 turun, tidak hilang (bagian 2.8).

**Variasi:** bila channel di host berisi tetapi index kosong, periksa forwarder: kesehatan input di `_internal` dan apakah index lain dari host itu juga diam. Itu pertanyaan berbeda dengan jawaban berbeda.

**Kapan gagal:** membandingkan Sysmon dengan dirinya sendiri (jumlah event Sysmon kemarin vs hari ini) tanpa pembanding independen. Penurunan karena konfigurasi, beban, atau driver terlihat sama; 4688 membedakan "host sepi" dari "Sysmon tidak mencatat".

### 2.3 Garis waktu EID 4, 16, 255 dan Service Control Manager di sembilan host

Langkah ini mengumpulkan jejak yang tidak bisa difilter dan jejak di System untuk pertanyaan keempat, sehingga tiap host bisa dikelompokkan menurut jalur putusnya.

**Tujuan:** satu garis waktu peristiwa yang menandai perubahan keadaan Sysmon di sembilan host.

```
(index=sysmon EventCode IN (4,16,255))
OR (index=wineventlog source="WinEventLog:System" EventCode IN (7036,7026,7000,6008,41,1001,1074)
    (Message="*Sysmon*" OR EventCode IN (6008,41,1001,1074)))
host IN (JKT-WS-0501,JKT-WS-0503,JKT-WS-0507,JKT-WS-0509,JKT-WS-0511,JKT-WS-0514,BDG-WS-0177,BDG-WS-0179,JKT-WS-0536)
earliest="03/03/2027:07:00:00" latest="03/03/2027:19:00:00"
| stats count min(_time) as pertama max(_time) as terakhir by host index EventCode
| convert ctime(pertama) ctime(terakhir)
| sort host pertama
```

- `EventCode IN (4,16,255)` di index `sysmon`: service start atau stop, konfigurasi berubah, error [S1].
- Event System: 7036 hanya yang menyebut Sysmon; 7026 dan 7000 untuk driver dan service yang gagal; 6008, 41, 1001, 1074 untuk shutdown, crash, dan restart.
- `stats ... by host index EventCode` meringkas jumlah serta waktu pertama dan terakhir; detail per event dibuka setelah pola terlihat.

Keluaran ilustrasi (WIB):

```
host         index        EventCode  count  pertama              terakhir
BDG-WS-0177  sysmon       255          214  2027-03-03 09:41:12  2027-03-03 11:22:47
BDG-WS-0179  sysmon       255          167  2027-03-03 09:47:30  2027-03-03 11:36:05
JKT-WS-0501  sysmon       16             2  2027-03-03 09:31:05  2027-03-03 13:32:40
JKT-WS-0503  sysmon       16             2  2027-03-03 09:33:52  2027-03-03 13:30:58
JKT-WS-0507  sysmon       16             2  2027-03-03 09:36:17  2027-03-03 13:38:11
JKT-WS-0509  sysmon       16             2  2027-03-03 09:34:40  2027-03-03 13:35:27
JKT-WS-0511  sysmon       16             2  2027-03-03 09:39:48  2027-03-03 13:33:02
JKT-WS-0514  sysmon       16             2  2027-03-03 09:32:26  2027-03-03 13:39:15
JKT-WS-0536  wineventlog  41             1  2027-03-03 11:58:02  2027-03-03 11:58:02
JKT-WS-0536  wineventlog  7026           1  2027-03-03 11:58:09  2027-03-03 11:58:09
JKT-WS-0536  wineventlog  6008           1  2027-03-03 11:58:15  2027-03-03 11:58:15
JKT-WS-0536  wineventlog  7000           1  2027-03-03 11:58:31  2027-03-03 11:58:31
JKT-WS-0536  wineventlog  1001           1  2027-03-03 11:58:40  2027-03-03 11:58:40
JKT-WS-0536  wineventlog  1074           1  2027-03-03 17:02:10  2027-03-03 17:02:10
JKT-WS-0536  wineventlog  7036           1  2027-03-03 17:03:50  2027-03-03 17:03:50
JKT-WS-0536  sysmon       4              1  2027-03-03 17:03:51  2027-03-03 17:03:51
```

**Cara membaca hasil:** tiga kelompok terpisah dengan sendirinya.

- **Enam laptop pilot:** tepat dua EID 16 per host, yang pertama antara 09:31:05 dan 09:39:48 (task sinkronisasi pukul 09:30 dengan jeda acak sampai 10 menit) dan yang kedua antara 13:30:58 dan 13:39:15 (task pukul 13:30). Tidak ada EID 4 dan tidak ada event System yang menyebut Sysmon: service tidak pernah berhenti, hanya konfigurasinya yang berganti dua kali.
- **Dua laptop Bandung:** ratusan EID 255 dalam rentang sekitar satu setengah jam, tanpa EID 4 atau 16: Sysmon hidup dengan konfigurasi yang sama, tetapi mengalami error berulang.
- **`JKT-WS-0536`:** tidak ada EID 4 Stopped sebelum kekosongan. Yang ada adalah crash (41 dan 6008 saat boot 11:58, 1001 BugCheck), driver boot-start gagal (7026) dan service gagal start (7000) pada boot yang sama, lalu restart oleh pengguna 17:02:10, service berjalan 17:03:50 (7036), dan Sysmon menulis EID 4 Started 17:03:51.

Durasi periode diam per host dihitung dari waktu di atas:

| Host | Mulai (WIB) | Selesai (WIB) | Durasi | Jenis |
|---|---|---|---|---|
| `JKT-WS-0501` | 09:31:05 | 13:32:40 | 4 jam 01 menit 35 detik | EID 1, 3, 22 menipis |
| `JKT-WS-0503` | 09:33:52 | 13:30:58 | 3 jam 57 menit 06 detik | EID 1, 3, 22 menipis |
| `JKT-WS-0507` | 09:36:17 | 13:38:11 | 4 jam 01 menit 54 detik | EID 1, 3, 22 menipis |
| `JKT-WS-0509` | 09:34:40 | 13:35:27 | 4 jam 00 menit 47 detik | EID 1, 3, 22 menipis |
| `JKT-WS-0511` | 09:39:48 | 13:33:02 | 3 jam 53 menit 14 detik | EID 1, 3, 22 menipis |
| `JKT-WS-0514` | 09:32:26 | 13:39:15 | 4 jam 06 menit 49 detik | EID 1, 3, 22 menipis |
| `BDG-WS-0177` | 09:41:12 | 11:22:47 | 1 jam 41 menit 35 detik | Event hilang sebagian |
| `BDG-WS-0179` | 09:47:30 | 11:36:05 | 1 jam 48 menit 35 detik | Event hilang sebagian |
| `JKT-WS-0536` | 11:52:31 | 17:03:51 | 5 jam 11 menit 20 detik | Tidak ada event Sysmon sama sekali |

Untuk `JKT-WS-0536`, awal periode adalah event Sysmon terakhir sebelum crash (11:52:31, bagian 2.6), bukan waktu crash di 6008, karena yang bisa dibuktikan hanyalah kapan Sysmon terakhir menulis. Untuk Bandung, awal dan akhir adalah EID 255 pertama dan terakhir; kehilangan event bisa sudah dimulai sedikit sebelum error pertama tercatat.

**Variasi:** di host tanpa forwarder, jalankan pencarian yang sama atas CSV EvtxECmd dengan filter `Channel` dan `EventId`; di host hidup, `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=4,16,255}`.

**Kapan gagal:** hanya mencari EID 4. Penggantian konfigurasi tidak menulis EID 4, dan crash atau driver yang gagal dimuat juga tidak; tanpa EID 16, 255, dan System, enam laptop pilot dan `JKT-WS-0536` akan terlihat sama-sama "berhenti tanpa jejak".

### 2.4 Konfigurasi yang benar-benar berlaku: EID 16, `sysmon64 -c`, registry, dan diff versi

Langkah ini menjawab pertanyaan kedua untuk tiap kelompok: konfigurasi apa yang berlaku selama periode diam, dan apakah perubahan berasal dari jalur change.

**Tujuan:** mencocokkan setiap EID 16 dengan berkas dan hash versi yang dirilis, membaca konfigurasi aktif dari host hidup, dan menemukan perbedaan antar versi yang menjelaskan penurunan event.

Pertama, isi EID 16 dari index (E03):

```
index=sysmon EventCode=16 host IN (JKT-WS-05*,BDG-WS-01*) earliest="03/03/2027:07:00:00" latest="03/03/2027:19:00:00"
| table _time host Configuration ConfigurationFileHash
```

Keluaran ilustrasi (WIB; dua dari dua belas baris):

```
_time                host         Configuration                                        ConfigurationFileHash
2027-03-03 09:33:52  JKT-WS-0503  C:\ProgramData\JAB\SysmonSync\jab-sysmon-ws.xml      SHA256=7B21...
2027-03-03 13:30:58  JKT-WS-0503  C:\ProgramData\JAB\SysmonSync\jab-sysmon-ws.xml      SHA256=C94E...
```

Nama field `Configuration` dan `ConfigurationFileHash` mengikuti ekstraksi Splunk di PT JAB; nama field asli EID 16 di versi-mu cek dengan `sysmon64 -s` [S1].

**Cara membaca hasil:** dua belas EID 16 di enam laptop pilot memakai path berkas yang sama dengan yang ditulis task sinkronisasi, dan hanya dua hash: `7B21...` (versi 2.1, dirilis Sari Selasa 2027-03-02 17:10 di subfolder `pilot\`, change `CHG-2027-0047`) dan `C94E...` (versi 2.2, perbaikan yang dirilis Rabu 11:20). Log `sync.log` di keenam host (E04) mencatat hash share dan hash lokal yang sama pada detik yang sama. Tidak ada EID 16 dengan path atau hash lain, dan tidak ada EID 16 sama sekali di `JKT-WS-0536` atau di dua laptop Bandung pada hari itu.

Kedua, konfigurasi aktif di host hidup. Kamis 09:12 lewat live response di `JKT-WS-0503`:

```
sysmon64 -c
```

Tanpa argumen lain, perintah ini menampilkan konfigurasi yang sedang aktif [S1]. Keluaran ilustrasi (dipotong; format persis berbeda antar versi, cek di lab):

```
System Monitor v15.22 - System activity monitor
Current configuration:
 - Service name:                  Sysmon64
 - Driver name:                   SysmonDrv
 - Config file:                   C:\ProgramData\JAB\SysmonSync\jab-sysmon-ws.xml
 - Config hash:                   SHA256=C94E...
 - HashingAlgorithms:             SHA1,SHA256
 - Network connection:            enabled
 - Archive Directory:             JabSysmonArc
Rule configuration (version 4.82):
 - ProcessCreate          onmatch: exclude   combine rules using 'Or'
 - NetworkConnect         onmatch: include   combine rules using 'Or'
 - DnsQuery               onmatch: exclude   combine rules using 'Or'
 ...
```

**Cara membaca hasil:** service dan driver memakai nama bawaan (tidak ada `DriverName` khusus), hash konfigurasi aktif sama dengan versi 2.2 di share, dan arsip memakai `JabSysmonArc`. Keluaran ini disimpan ke E04 sebagai bukti keadaan Kamis pagi; jalankan `sysmon64 -c` hanya tanpa argumen di host bukti, karena dengan argumen berkas ia mengganti konfigurasi. Perintah itu sendiri tercatat sebagai EID 1 dan 4688 di host; catat waktunya sebagai jejak responder.

Ketiga, beda antar versi. Sari menyimpan konfigurasi di repositori GitLab internal `jab-sysmon-config` dengan tag per versi:

```
git diff v2.0 v2.1 -- jab-sysmon-ws.xml
```

Keluaran ilustrasi (dipotong ke bagian yang relevan):

```
@@ -41,7 +41,7 @@
-    <ProcessCreate onmatch="exclude">
+    <ProcessCreate onmatch="include">
       <Image condition="is">C:\Program Files\JAB\DocSync\jabdocsync.exe</Image>
@@ -118,7 +118,7 @@
-    <NetworkConnect onmatch="exclude">
+    <NetworkConnect onmatch="include">
@@ -203,7 +203,7 @@
-    <DnsQuery onmatch="exclude">
+    <DnsQuery onmatch="include">
@@ -260,0 +261,12 @@
+    <FileDelete onmatch="include">
+    <FileBlockShredding onmatch="include">
```

**Cara membaca hasil:** tiga event yang di versi 2.0 berbasis exclude ("catat semua kecuali daftar bising") berubah menjadi include dengan daftar yang sama, sehingga maknanya terbalik menjadi "catat hanya daftar bising" (bagian 1.5). Itu menjelaskan EID 1 satu digit per jam di bagian 2.2: yang tersisa hanya `jabdocsync.exe` dan updater lain di daftar itu. Penambahan yang memang dimaksud change (EID 23 dengan arsip dan EID 28 FileBlockShredding, rekomendasi dari kasus anti-forensik Februari) bekerja seperti seharusnya. Penyebabnya, menurut tiket change, adalah skrip penggabung modul konfigurasi versi baru yang salah memilih atribut `onmatch` untuk event yang aturannya tersebar di beberapa modul; versi 2.2 mengembalikan ketiga atribut. Dengan demikian, konfigurasi yang berlaku di enam laptop pilot selama periode diam adalah 2.1, yang dirilis lewat jalur change, dan tidak ada perubahan di luar jalur itu.

Keempat, untuk `JKT-WS-0536` yang hanya punya image registry (E02), konfigurasi dibaca dari hive SYSTEM:

```
RECmd.exe -f G:\C\Windows\System32\config\SYSTEM --kn "ControlSet001\Services\SysmonDrv" ^
  --csv \\jkt-evid01\cases\INC-2027-013\analysis\E02-W1\EZ-2026.5.0\Registry --csvf E02-W1_SysmonDrv.csv
```

- `--kn`: key yang diekspor beserta subkey-nya; offline, `CurrentControlSet` adalah `ControlSet00x` yang ditunjuk `Select\Current` (di image ini 1).
- Lakukan hal yang sama untuk `ControlSet001\Services\Sysmon64`.

Keluaran ilustrasi (UTC):

```
KeyPath                                        ValueName         ValueData                     LastWrite (UTC)
ControlSet001\Services\SysmonDrv               Start             0                             2027-02-26 03:41:12
ControlSet001\Services\SysmonDrv\Parameters    HashingAlgorithm  (DWORD)                       2027-02-26 03:41:18
ControlSet001\Services\SysmonDrv\Parameters    Options           (DWORD)                       2027-02-26 03:41:18
ControlSet001\Services\SysmonDrv\Parameters    Rules             (REG_BINARY, 9.344 byte)      2027-02-26 03:41:18
ControlSet001\Services\Sysmon64                Start             2                             2027-02-26 03:41:12
```

**Cara membaca hasil:** driver boot-start (`Start` 0) dan service otomatis (`Start` 2) tidak berubah sejak Sysmon dipasang Jumat 2027-02-26 10:41 WIB; key `Parameters` juga tidak ditulis lagi setelah itu, cocok dengan nol EID 16 dan dengan `sync.log` yang hanya mencatat "hash sama, tidak ada perubahan" setiap pukul 09:30 dan 13:30 sejak Senin. Nilai `Rules` adalah blob biner yang dibaca driver; isinya tidak diurai di sini, tetapi ukurannya sama dengan `Rules` di `JKT-WS-0537` yang memakai versi 2.0, dan last write-nya mengikat waktu konfigurasi terakhir ditulis.

**Variasi:** di laptop 25H2, cek juga apakah Sysmon bawaan Windows dinyalakan, karena Sysmon bawaan dan Sysmon Sysinternals tidak boleh terpasang bersamaan [S9]: `Dism /Online /Get-FeatureInfo /FeatureName:Sysmon` lewat live response. Di `JKT-WS-0537` hasilnya fitur dalam keadaan Disabled, sesuai keputusan PT JAB memakai Sysmon Sysinternals selama fleet masih campuran (bagian 6). Nama fitur `Sysmon` diambil dari pengumuman Insider; keluaran dan nama service Sysmon bawaan cek di build-mu.

**Kapan gagal:** membaca berkas XML di share dan menganggapnya konfigurasi host. Berkas di share bisa sudah diganti versi perbaikan, sedangkan host masih menjalankan versi lama sampai task berikutnya berjalan; yang menentukan adalah EID 16, `Parameters`, dan `sysmon64 -c`. Kegagalan lain: `DriverName` diubah, sehingga key yang dicari bernama lain [S1]; cari service yang `ImagePath`-nya menunjuk biner Sysmon.

### 2.5 Sesi AutoLogger dan sesi yang sedang berjalan

Langkah ini menjawab pertanyaan ketiga: adakah yang menyentuh ETW di luar Sysmon.

**Tujuan:** membandingkan definisi sesi AutoLogger di hive SYSTEM `JKT-WS-0536` dengan `JKT-WS-0537`, dan membandingkan sesi yang sedang berjalan di host hidup.

```
RECmd.exe -f G:\C\Windows\System32\config\SYSTEM --kn "ControlSet001\Control\WMI\Autologger" --recover ^
  --csv \\jkt-evid01\cases\INC-2027-013\analysis\E02-W1\EZ-2026.5.0\Registry --csvf E02-W1_Autologger.csv
```

- `--kn "ControlSet001\Control\WMI\Autologger"`: key induk semua sesi AutoLogger [S3]; offline memakai control set aktif, bukan `CurrentControlSet`.
- `--recover`: ikut mengambil key dan nilai yang terhapus tetapi masih bisa dipulihkan dari hive; cek nama opsi ini di versi RECmd-mu.
- Ekspor key yang sama dari `JKT-WS-0537` ada di E04 (`reg export` lewat live response), lalu diproses dengan perintah yang sama.

Perbandingan dua CSV dengan PowerShell di `JKT-DFIR01`:

```
$a = Import-Csv .\E02-W1_Autologger.csv | Select-Object KeyPath,ValueName,ValueData
$b = Import-Csv .\WS0537_Autologger.csv | Select-Object KeyPath,ValueName,ValueData
Compare-Object $a $b -Property KeyPath,ValueName,ValueData | Sort-Object KeyPath
```

Keluaran ilustrasi (ringkasan):

```
Sesi AutoLogger                0536: 47   0537: 47   (nama sama)
Subkey provider                0536: 612  0537: 612
Nilai Start=0 pada sesi        0536: 9    0537: 9    (sesi yang sama)
Nilai Enabled=0 pada provider  0536: 38   0537: 38   (provider yang sama)
Status != 0                    0536: 0    0537: 0
Selisih Compare-Object:        6 baris, semuanya ValueName FileCounter (3 sesi)
Key atau nilai terhapus (--recover): 0
```

**Cara membaca hasil:** daftar sesi, provider, nilai `Start`, nilai `Enabled`, dan level sama dengan laptop pembanding dari gold image yang sama. Satu-satunya selisih adalah `FileCounter`, nilai yang ditulis ETW sendiri untuk menomori berkas log berurutan dan tidak boleh diubah manual [S3]; nilainya berbeda karena jumlah boot kedua laptop berbeda. `Status` 0 di semua sesi berarti semua sesi AutoLogger start tanpa error pada boot terakhir sebelum koleksi [S3]. Sesi dengan `Start` 0 di kedua laptop adalah sesi bawaan yang memang tidak aktif di gold image; yang dicari adalah perbedaan terhadap pembanding, bukan nilai 0 itu sendiri. Nama sesi bawaan (misalnya sesi Event Log untuk channel Application dan System, dan sesi milik Defender) dan jumlahnya bergantung build; ambil dari pembanding-mu sendiri.

Lalu sesi yang sedang berjalan, Kamis 09:40 lewat live response di kedua laptop:

```
logman query -ets
```

- `query` tanpa nama menampilkan daftar; `-ets` mengirim perintah langsung ke sesi trace yang berjalan [S7].
- Untuk detail satu sesi termasuk provider-nya: `logman query "<nama sesi>" -ets`.

Keluaran ilustrasi (dipotong):

```
Data Collector Set                      Type                          Status
-------------------------------------------------------------------------------
EventLog-Application                    Trace                         Running
EventLog-System                         Trace                         Running
...
The command completed successfully.
```

**Cara membaca hasil:** `JKT-WS-0536` dan `JKT-WS-0537` menampilkan 58 sesi berjalan dengan nama yang sama; tidak ada sesi milik Defender atau Event Log yang hilang di salah satunya. Sysmon dan produk keamanan lain bisa punya sesi sendiri di daftar ini; nama sesi milik Sysmon di versi-mu cek di lab, jangan ditebak. Untuk enam laptop pilot dan dua laptop Bandung, daftar sesi yang sama dibandingkan dengan pembanding Jakarta dan Bandung masing-masing (E04); tidak ada selisih nama sesi.

**Variasi:** di host yang dicurigai, jalankan `logman query providers` untuk melihat provider terdaftar, dan bandingkan detail sesi `EventLog-*` yang mengaktifkan provider penting dengan pembanding.

**Kapan gagal:** membandingkan dengan host yang perannya berbeda (laptop dengan server, gold image berbeda, build berbeda), sehingga perbedaan yang sah tampak seperti gangguan. Kegagalan kedua: menganggap AutoLogger yang sama berarti ETW utuh. Perubahan lewat `-ets` hilang saat reboot, dan `JKT-WS-0536` di-restart dua kali Rabu; untuk periode diam, bukti ada atau tidaknya perubahan semacam itu adalah eksekusi `logman.exe` di 4688 dan Defender (bagian 2.6), bukan registry.

### 2.6 `JKT-WS-0536`: crash, driver yang tidak termuat, dan tidak ada tindakan yang menyentuh Sysmon

Langkah ini adalah inti pertanyaan keenam: apa yang terjadi di laptop yang tidak ikut pilot, dan apakah ada tanda seseorang menyebabkannya.

**Tujuan:** menyusun urutan peristiwa di sekitar periode diam dari System dan Sysmon, lalu mencari secara eksplisit tindakan yang bisa mematikan perekaman.

Event Sysmon terakhir sebelum diam dan event System di sekitar kedua boot, dari CSV E02-W1:

```
$e = Import-Csv \\jkt-evid01\cases\INC-2027-013\analysis\E02-W1\EZ-2026.5.0\EventLogs\E02-W1_evtx.csv
$e | Where-Object { $_.TimeCreated -ge '2027-03-03 04:50:00' -and $_.TimeCreated -le '2027-03-03 10:05:00' -and
     ( ($_.Channel -eq 'System' -and $_.EventId -in '12','41','1001','1074','6005','6006','6008','7000','7026','7036') -or
       ($_.Channel -like '*Sysmon*') ) } |
  Select-Object TimeCreated,Channel,EventId,MapDescription,PayloadData1 | Sort-Object TimeCreated
```

- Rentang `04:50:00` sampai `10:05:00` UTC (11:50 sampai 17:05 WIB) mencakup akhir event Sysmon, crash, dua boot, dan kembalinya Sysmon.
- 7036 diambil semua lalu disaring manual, karena isinya banyak service lain.

Keluaran ilustrasi (UTC; baris 7036 yang tidak menyebut Sysmon dibuang):

```
TimeCreated          Channel   EventId  Ringkasan
2027-03-03 04:52:31  Sysmon    3        Network connection, ms-teams.exe (event Sysmon terakhir)
2027-03-03 04:57:49  System    12       Kernel-General: sistem operasi mulai
2027-03-03 04:58:02  System    41       Kernel-Power: reboot tanpa shutdown bersih
2027-03-03 04:58:09  System    7026     Boot-start atau system-start driver tidak termuat: SysmonDrv
2027-03-03 04:58:15  System    6008     Shutdown sebelumnya pada 11:52:44 03/03/2027 tidak terduga
2027-03-03 04:58:31  System    7000     Service Sysmon64 gagal start (pesan error di Payload)
2027-03-03 04:58:40  System    1001     BugCheck 0x0000009f, dump C:\Windows\Minidump\030327-11203-01.dmp
2027-03-03 10:02:10  System    1074     Restart oleh JAB\yuni.astuti melalui explorer.exe
2027-03-03 10:02:41  System    6006     Event log service dihentikan
2027-03-03 10:03:22  System    12       Kernel-General: sistem operasi mulai
2027-03-03 10:03:50  System    7036     Sysmon64 masuk keadaan running
2027-03-03 10:03:51  Sysmon    4        Sysmon service state changed: Started
```

**Cara membaca hasil:** konversi ke WIB dulu. Event Sysmon terakhir 11:52:31 WIB. Laptop crash sekitar 11:52:44 WIB; waktu itu ditulis di pesan 6008 dalam waktu lokal laptop, bukan UTC, jadi jangan dikurangi tujuh jam lagi. Boot berikutnya 11:57:49 WIB, dan pada boot itu driver `SysmonDrv` tercatat sebagai driver boot-start yang tidak termuat (7026), lalu service `Sysmon64` gagal start (7000). Laptop berjalan tanpa Sysmon sampai Yuni me-restart lewat menu Start pukul 17:02:10 WIB (1074, shutdown bersih dengan 6006); pada boot 17:03:22, driver termuat dan Sysmon menulis EID 4 Started pukul 17:03:51. Tidak ada EID 4 Stopped di mana pun hari itu: Sysmon tidak dihentikan, ia berhenti bersama host yang crash dan tidak bisa hidup lagi sampai boot berikutnya. Kode BugCheck `0x9F` dan dump di folder Minidump menunjukkan crash yang ditangani Windows Error Reporting; penyebab crash dan apakah crash berkaitan dengan driver Sysmon tidak bisa dibaca dari event log, dan dump-nya ada di E02 untuk dianalisis.

Lalu pencarian tindakan yang bisa mematikan perekaman, di Security 4688 (laptop ini punya audit Process Creation dengan command line):

```
$e | Where-Object { $_.EventId -eq '4688' -and
     $_.TimeCreated -ge '2027-02-26 03:00:00' -and $_.TimeCreated -le '2027-03-04 02:00:00' -and
     $_.ExecutableInfo -match 'sysmon|\\sc\.exe|\\reg\.exe|logman|wevtutil|fltmc|auditpol|bcdedit|Set-ItemProperty|New-ItemProperty' } |
  Select-Object TimeCreated,UserName,ExecutableInfo
```

- Jendela sengaja seluruh umur image (sejak reimage sampai koleksi), bukan hanya periode diam, karena perubahan `Start` atau AutoLogger bisa dilakukan jauh sebelum reboot yang membuatnya berlaku (bagian 1.6).
- Pola mencakup alat yang mengubah service, registry, sesi ETW, channel event log, filter driver, dan audit policy.

Keluaran ilustrasi:

```
TimeCreated          UserName              ExecutableInfo
2027-02-26 03:41:05  JAB\JKT-WS-0536$     "C:\ProgramData\JAB\SysmonSync\Sysmon64.exe" -accepteula -i C:\ProgramData\JAB\SysmonSync\jab-sysmon-ws.xml
2027-03-03 10:50:12  JAB\JKT-WS-0536$     ... (koleksi KAPE lewat live response Rabu sore, responder)
```

Baris pertama adalah pemasangan Sysmon oleh task saat reimage, dengan command line yang sama di laptop lain; baris Rabu sore 17:35 sampai 18:12 WIB adalah jejak responder (Yoga), dicocokkan dengan case notes. Nol baris lain. Pada pencarian yang sama di Defender (`DeviceProcessEvents` dan `DeviceRegistryEvents` untuk key `Services\SysmonDrv`, `Services\Sysmon64`, dan `Control\WMI\Autologger`) hasilnya juga nol di luar pemasangan dan jejak responder, padahal sensor mengirim event sepanjang periode diam.

Terakhir, siapa yang memegang hak admin. Di periode diam, 4672 hanya untuk SYSTEM dan akun service; 4624 hanya Yuni (logon interaktif 12:01:44 WIB setelah boot, dua unlock) dan logon service; nol logon jaringan atau RDP dari host lain. Yuni adalah pengguna biasa tanpa 4672 di seluruh jendela image. Mematikan Sysmon, mengubah `Start`, atau menyentuh AutoLogger butuh hak admin, dan tidak ada sesi admin selain SYSTEM di laptop itu sejak reimage selain responder.

**Kapan gagal:** menyimpulkan "tidak ada tindakan" dari jendela periode diam saja, padahal perubahan `Start` atau AutoLogger berlaku pada reboot berikutnya dan bisa dibuat berhari-hari sebelumnya; atau dari host tanpa audit Process Creation, di mana pencarian 4688 tidak berarti apa-apa. Di host seperti itu, bebannya pindah ke Defender, Prefetch, dan Amcache (Day 07), dan keyakinannya harus diturunkan.

### 2.7 Apa yang hilang, sumber pengganti, dan direktori arsip

Langkah ini menjawab pertanyaan kelima per kelompok host, dan memeriksa apakah ada berkas yang bisa dipulihkan dari arsip Sysmon.

**Tujuan:** untuk tiap periode diam, menyebut event Sysmon yang hilang, memperkirakan jumlahnya dari baseline, dan menunjuk sumber pengganti yang benar-benar tersedia untuk host itu.

Perkiraan dihitung dari jam yang sama pada hari Selasa (laptop pilot dan Bandung) dan dari jam kerja Senin dan Selasa (`JKT-WS-0536`), di E03:

```
index=sysmon host=JKT-WS-0536 earliest="03/01/2027:11:00:00" latest="03/02/2027:18:00:00" date_hour>=11 date_hour<17
| stats count by date_mday EventCode
```

Ringkasan per kelompok; baca kolom terakhir, karena itulah yang dipakai untuk menjawab pertanyaan apa pun tentang periode itu.

| Kelompok | Periode diam (WIB) | Yang hilang | Perkiraan dari baseline | Sumber pengganti yang tersedia |
|---|---|---|---|---|
| Enam laptop pilot | sekitar 09:31-13:39, per host di bagian 2.3 | EID 1, 3, 22 kecuali proses di daftar bising; EID lain tetap tercatat | Sekitar 300 sampai 500 EID 1 per host | 4688 dengan command line (tanpa hash dan `ProcessGuid`); Defender `DeviceProcessEvents`, `DeviceNetworkEvents`; index `dns` dan `proxy` tanpa nama proses |
| Dua laptop Bandung | 09:41-11:22 dan 09:47-11:36 | Sebagian event semua jenis; rasio EID 1 terhadap 4688 turun ke 0,71 dan 0,78 | Sekitar 340 dan 200 EID 1 per host (bagian 2.8) | 4688; Defender; `$J` bila dibutuhkan |
| `JKT-WS-0536` | 11:52:31-17:03:51 | Semua event Sysmon, termasuk EID 10 ke LSASS, 11, 12, 13, 22, dan arsip | Sekitar 2.100 event (Senin dan Selasa rata-rata sekitar 400 per jam pada jam yang sama) | 625 event 4688 dengan command line; Defender (sensor sehat sepanjang periode); `$MFT` dan `$J` di E02; SRUM per aplikasi; index `dns` dan `proxy` |

**Cara membaca hasil:** "hilang" berarti tidak ada di Sysmon, bukan tidak diketahui sama sekali. Untuk eksekusi proses, `JKT-WS-0536` masih punya 625 event 4688 di periode diam (97 di sisa jam 11 setelah 11:52:31, 424 di jam 12 sampai 16, dan 104 di jam 17 sebelum 17:03:51), sehingga pertanyaan "apa yang dijalankan" tetap terjawab dengan keyakinan tinggi; yang hilang adalah hash dan `ProcessGuid`. Untuk koneksi jaringan per proses, penggantinya hanya Defender. Untuk akses ke LSASS, tidak ada pengganti setara di host; yang bisa ditulis hanyalah bahwa Defender tidak menghasilkan alert akses kredensial di periode itu. Pemeriksaan ringkas atas sumber pengganti di periode diam `JKT-WS-0536` hanya menemukan aplikasi kerja Keuangan (Excel, Outlook, Teams, Edge, aplikasi penagihan berbasis web), proses Windows setelah boot, dan task terjadwal yang dikenal.

Direktori arsip dicek karena konfigurasi 2.1 dan 2.2 di laptop pilot menyalakan EID 23. Di `JKT-WS-0503`, Kamis 09:15 lewat live response (sudah berjalan sebagai SYSTEM, sehingga ACL System tidak menghalangi [S1]):

```
cmd /c dir /a /s C:\JabSysmonArc
```

Keluaran ilustrasi (dipotong):

```
 Directory of C:\JabSysmonArc
               4 File(s)         18,432 bytes
```

Di host yang memakai nama bawaan, perintah yang sama diarahkan ke `C:\Sysmon` (`dir /a /s C:\Sysmon`), lalu ke akar volume lain bila tidak ada.

**Cara membaca hasil:** empat berkas, dan di channel Sysmon host itu ada empat EID 23 sejak 09:33:52 Rabu, semuanya untuk berkas sementara `__PSScriptPolicyTest_*.ps1` yang dibuat dan dihapus PowerShell sendiri (Day 08 bagian 2.4 memakai pola berkas yang sama untuk menghitung eksekusi PowerShell). Dua di antaranya terjadi di dalam periode diam 2.1: EID 23 tetap berfungsi karena hanya EID 1, 3, dan 22 yang terbalik, sehingga "periode diam" di laptop pilot tidak berarti semua event Sysmon diam. Bagi rancangan konfigurasi, empat berkas sehari dari pola yang sama adalah contoh kecil kenapa arsip bisa membengkak [S1]; pola itu layak dikecualikan dengan aturan berdasarkan path dan image sekaligus. Di `JKT-WS-0536`, `$MFT` E02 tidak memuat direktori `JabSysmonArc` atau `Sysmon` di akar `C:`, cocok dengan konfigurasi 2.0 yang belum memakai EID 23.

Cara memakai arsip bila suatu saat berkas yang dicari ada di sana: cocokkan setiap berkas dengan EID 23 di log. Event memberi waktu penghapusan, proses pelaku, path asli, dan hash; direktori arsip memberi isinya. Format nama berkas di direktori arsip cek di lab, karena dokumentasi tidak menjelaskannya.

**Kapan gagal:** menulis "tidak ada aktivitas mencurigakan selama periode diam" padahal sumber pengganti tidak mencakup jenis aktivitas yang ditanyakan. Kalimat yang benar menyebut sumbernya, misalnya "tidak ada eksekusi proses yang tidak dikenal di 4688 dan Defender; koneksi per proses hanya dari Defender; akses ke LSASS tidak bisa dinilai di host".

### 2.8 Dua laptop Bandung: EID 255 dan beban dari alat lain

Langkah ini menyelesaikan kelompok ketiga untuk pertanyaan keempat: Sysmon hidup dengan konfigurasi yang benar, tetapi error berulang dan event menipis.

**Tujuan:** mencocokkan EID 255 dengan sesuatu yang membebani host pada waktu yang sama, dan mengukur seberapa banyak event yang hilang.

Pertama, siapa yang menghasilkan event terbanyak di sekitar error:

```
index=sysmon host IN (BDG-WS-0177,BDG-WS-0179) EventCode=11 earliest="03/03/2027:09:00:00" latest="03/03/2027:12:00:00"
| bin _time span=10m
| stats count by host _time Image
| sort host _time - count
| dedup host _time
```

- `EventCode=11`: konfigurasi 2.0 memperluas FileCreate (rencana peninjauan EID 11), sehingga event ini yang paling mungkin membanjir.
- `dedup host _time` setelah `sort`: hanya image teratas per host per sepuluh menit.

Keluaran ilustrasi (WIB, sebagian baris `BDG-WS-0177`):

```
host         _time              Image                                      count
BDG-WS-0177  2027-03-03 09:00   C:\Program Files\EBAgent\ebagent.exe        4211
BDG-WS-0177  2027-03-03 09:30   C:\Program Files\EBAgent\ebagent.exe       17904
BDG-WS-0177  2027-03-03 09:40   C:\Program Files\EBAgent\ebagent.exe       19017
BDG-WS-0177  2027-03-03 11:20   C:\Program Files\EBAgent\ebagent.exe       12388
BDG-WS-0177  2027-03-03 11:30   C:\Windows\explorer.exe                       41
```

**Cara membaca hasil:** `ebagent.exe` adalah agen backup endpoint (produk fiktif) yang sedang dipilotkan tim IT Bandung di dua laptop itu lewat change terpisah; kedua laptop menjalankan backup penuh pertama Rabu pagi. Log job agen (E04, dari folder data agen) mencatat job `BDG-WS-0177` 09:00:04 sampai 11:27:51 dan `BDG-WS-0179` 09:00:06 sampai 11:41:30. Semua EID 255 di kedua host (214 dan 167) berada di dalam jendela job, dimulai ketika laju FileCreate dari agen mendekati dua ribu per menit, dan berhenti sebelum job selesai. Tidak ada EID 4 atau 16, `sysmon64 -c` (E04) menunjukkan konfigurasi 2.0 dengan hash `3E9A...` seperti laptop Bandung lain, dan daftar sesi `logman` sama dengan pembanding Bandung.

Kedua, besarnya kehilangan, dengan 4688 sebagai pembanding:

| Host | Jendela | 4688 | Sysmon EID 1 | Rasio | Rasio jam yang sama hari Selasa |
|---|---|---|---|---|---|
| `BDG-WS-0177` | 09:41:12-11:22:47 | 1.318 | 936 | 0,71 | 0,97 |
| `BDG-WS-0179` | 09:47:30-11:36:05 | 1.044 | 814 | 0,78 | 0,97 |

**Cara membaca hasil:** di hari biasa EID 1 sekitar 97 persen dari 4688 (selisihnya daftar bising yang dikecualikan). Selama beban, sekitar 29 persen dan 22 persen proses yang tercatat di 4688 tidak muncul sebagai EID 1. Kalau rasio hari biasa dipakai sebagai acuan, yang hilang sekitar 1.318 x 0,97 - 936 = 342 EID 1 di `BDG-WS-0177` dan 1.044 x 0,97 - 814 = 199 di `BDG-WS-0179` (dibulatkan); event jenis lain kemungkinan hilang dengan pola serupa, tetapi tidak punya pembanding independen untuk dihitung. Ini sesuai sebab yang didokumentasikan untuk EID 255 (beban berat) [S1] dan dengan sebab kehilangan event di ETW saat consumer atau disk tidak bisa mengikuti laju pencatatan [S2]. Masalahnya operasional dan sebabnya ganda: konfigurasi 2.0 tidak mengecualikan folder cache agen backup, dan job backup penuh berjalan di jam kerja.

**Variasi:** perbaikan konfigurasi untuk kasus seperti ini memakai aturan exclude yang menggabungkan dua field berbeda (AND): `Image` dengan path lengkap agen dan `TargetFilename` yang diawali folder cache agen. Mengecualikan berdasarkan nama image saja akan ikut menutup proses lain bernama sama di path lain (bagian 1.5).

**Kapan gagal:** menganggap EID 255 sebagai tanda serangan hanya karena ia "error di alat keamanan". Dokumentasi menyebut tiga sebab (beban, bug, syarat keamanan dan integritas) [S1]; sebab ketiga memang layak dicurigai, tetapi ia tidak akan sejalan dengan jendela job dua laptop yang sama-sama sedang menjalankan backup penuh. Cocokkan dulu dengan beban yang terjadwal.

### 2.9 Peta celah konfigurasi dan jawaban untuk Sari

Langkah terakhir menyusun dua lampiran: peta celah konfigurasi yang berlaku di fleet (supaya "tidak ditemukan" di kasus berikutnya punya batas yang jelas), dan jawaban enam pertanyaan.

Peta celah konfigurasi `jab-sysmon-ws` 2.0 (yang berlaku di semua workstation hasil rollout kecuali ring pilot). Tabel ini dibaca dari kolom kanan: itulah kalimat yang harus muncul di setiap laporan yang mengandalkan Sysmon.

| Event | Aktif di 2.0 | Pengecualian yang berpengaruh | Akibat bagi pemeriksaan |
|---|---|---|---|
| 1 Process creation | Ya, berbasis exclude | Daftar updater bertanda tangan (path lengkap) | Proses di daftar itu tidak terlihat di EID 1; tetap ada di 4688 |
| 3 Network connection | Ya, berbasis exclude untuk peramban dan Teams | Peramban, Teams, OneDrive | Koneksi peramban tidak terlihat per proses; pakai proxy dan Defender |
| 7 Image loaded | Tidak | | Pemuatan DLL tidak terlihat; side-loading hanya dari EDR atau memori |
| 10 ProcessAccess | Ya, hanya target `lsass.exe` | `MsMpEng.exe` dan `MsSense.exe` dengan path lengkap | Akses ke proses selain LSASS tidak terlihat |
| 11 FileCreate | Ya, diperluas | Folder cache agen backup belum dikecualikan | Banjir event di laptop pilot backup (bagian 2.8) |
| 23 FileDelete (arsip) | Tidak (baru di 2.1) | | Berkas yang dihapus tidak tersimpan; hanya EID 26 di folder pengguna |
| 28 FileBlockShredding | Tidak (baru di 2.1) | | Wiping tidak diblokir |
| `HashAlgorithms` | SHA1, SHA256 | | Korelasi hash tersedia di EID 1 |

Jawaban yang dikirim ke Sari Kamis 14:20, disimpan di `\\jkt-evid01\cases\INC-2027-013\notes\jawaban-sysmon-diam-2027-03-04.md`:

| No | Pertanyaan | Jawaban | Keyakinan | Dasar |
|---|---|---|---|---|
| 1 | Berhenti di host atau tidak sampai ke Splunk? | Di host. Sembilan host: channel Sysmon di host sama dengan index, termasuk kekosongannya; forwarder tetap mengirim Security dan System | Tinggi | Bagian 2.2 |
| 2 | Konfigurasi apa yang berlaku, ada perubahan di luar change? | Pilot: 2.1 (`7B21...`) dari sekitar 09:31 sampai 13:39, lalu 2.2 (`C94E...`); Bandung dan `JKT-WS-0536`: 2.0 (`3E9A...`) tanpa perubahan sejak dipasang. Tidak ada EID 16 atau perubahan `Parameters` di luar task sinkronisasi | Tinggi | Bagian 2.4 |
| 3 | ETW di luar Sysmon disentuh? | Tidak ditemukan: AutoLogger `JKT-WS-0536` sama dengan pembanding kecuali `FileCounter`; sesi berjalan di sembilan host sama dengan pembanding; tidak ada eksekusi `logman` atau penulisan key AutoLogger. Gangguan di dalam memori proses tidak diperiksa | Tinggi untuk registry dan sesi; tidak dinilai untuk memori | Bagian 2.5, 2.6 |
| 4 | Sabotase atau operasional? | Pilot: operasional, konfigurasi 2.1 membalik `onmatch` tiga event. Bandung: operasional, beban job backup penuh dan EID 11 tanpa pengecualian cache. `JKT-WS-0536`: crash lalu driver tidak termuat; sabotase tidak didukung bukti | Tinggi (pilot, Bandung); tinggi untuk "tidak ada tindakan yang menyentuh Sysmon atau ETW", sebab dasar driver gagal tidak dapat ditentukan (`JKT-WS-0536`) | Bagian 2.3, 2.4, 2.6, 2.8 |
| 5 | Apa yang hilang dan penggantinya? | Per kelompok di tabel bagian 2.7; eksekusi proses tergantikan 4688; koneksi per proses hanya Defender; akses LSASS tidak tergantikan di host | Sedang-tinggi | Bagian 2.7 |
| 6 | `JKT-WS-0536` insiden atau tutup? | Turunkan ke SEV-4 dan tutup bagian dugaan gangguan telemetri; buka tindak lanjut teknis ke tim IT: analisis dump `030327-11203-01.dmp` dan uji crash serupa di lab untuk melihat apakah `SysmonDrv` gagal dimuat lagi | Sedang untuk sebab; tinggi untuk tidak adanya tindakan manusia | Bagian 1.8, 2.6 |

Rekomendasi yang menyertai jawaban, dengan pemilik:

- Rule Splunk baru: 7026 atau 7000 yang menyebut Sysmon langsung menjadi alert P2, karena itu satu-satunya jejak saat Sysmon tidak bisa hidup setelah boot (Sari, bersama pengelola Splunk).
- Rule "Sysmon diam" mempertahankan perbandingan EID 1 dengan 4688, dan ditambah pengecualian otomatis untuk host yang punya EID 16 dengan hash versi pilot pada jam yang sama, supaya change pilot tidak menghasilkan alert yang sama berulang (Sari).
- Uji konfigurasi baru di `LAB-WS01` dengan pembanding 4688 sebelum masuk ring pilot, termasuk pemeriksaan otomatis bahwa atribut `onmatch` tiap event sama dengan versi sebelumnya kecuali disengaja (Sari).
- Pengecualian folder cache agen backup di 2.3, dan job backup penuh dipindah ke luar jam kerja (Sari, tim IT Bandung).
- Laporan ke tim IT tentang crash `JKT-WS-0536`; bila dump menunjuk driver Sysmon, tiket ke dukungan Microsoft dicatat di kasus (tim IT, Teguh Wibowo).

Kalimat untuk laporan, untuk `JKT-WS-0536`: "Sysmon di `JKT-WS-0536` tidak mencatat dari Rabu 2027-03-03 11:52:31 sampai 17:03:51 WIB (5 jam 11 menit 20 detik) karena laptop crash pukul 11:52 dan driver Sysmon tidak termuat pada boot berikutnya. Tidak ditemukan tindakan yang menghentikan Sysmon, mengubah konfigurasi, service, driver, atau sesi ETW, pada Security 4688, Defender, registry, dan channel Sysmon sejak reimage 2027-02-26 sampai koleksi. Eksekusi proses selama periode itu tersedia dari 4688 dan Defender; akses ke LSASS dan koneksi per proses di luar Defender tidak bisa dinilai untuk periode itu. Penyebab driver gagal dimuat belum ditentukan dan ditindaklanjuti tim IT."

**Kapan gagal:** satu kalimat penutup untuk sembilan host ("semua operasional"), padahal tiga kelompok punya sebab, keyakinan, dan sisa pekerjaan yang berbeda; atau rekomendasi tanpa pemilik, sehingga 7026 berikutnya kembali hanya terlihat setelah lima jam dari grafik yang datar.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** `LAB-WS01` (`172.16.50.10`, Windows 11, Sysmon Sysinternals dengan konfigurasi dasar yang mengaktifkan EID 1, 3, 11, 22, 26, audit Process Creation dengan command line, snapshot bersih), `LAB-WS02` (`172.16.50.11`, Windows 11 dari snapshot yang sama, sebagai host pembanding yang tidak diubah), dan `LAB-DFIR01` (`172.16.50.20`) dengan EZ Tools; jaringan host-only `172.16.50.0/24`. Folder kasus `CASE-2026-LAB-025` di `LAB-DFIR01` dengan `evidence\`, `analysis\`, `notes\`. Semua aktivitas jinak, dan jam (WIB) setiap langkah dicatat di `notes\case-notes.md` sebelum dijalankan, karena lab ini adalah tentang membandingkan apa yang terjadi dengan apa yang tercatat. Perintah ditulis sebagai teks untuk dijalankan di VM lab.

1. **Keadaan awal.** Di `LAB-WS01` dan `LAB-WS02`, simpan keluaran `sysmon64 -c`, `sysmon64 -s`, `logman query -ets`, dan `reg export HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger`. Ini baseline "apa yang seharusnya ada" (bagian 1.2 dan 1.6).
2. **Pembanding independen.** Jalankan sepuluh program jinak (`notepad.exe`, `calc.exe`, `ipconfig.exe`, dan sejenisnya) dan hitung EID 1 terhadap 4688 untuk jendela itu. Rasio ini adalah acuan untuk langkah berikutnya (bagian 2.2).
3. **Konfigurasi terbalik.** Salin konfigurasi, ubah `onmatch` pada `ProcessCreate` dari `exclude` menjadi `include` tanpa mengubah aturannya, terapkan dengan `sysmon64 -c <berkas>`, ulangi sepuluh program, lalu kembalikan. Buktikan dari EID 16 (berkas dan hash), dari rasio EID 1 terhadap 4688, dan dari tidak adanya EID 4 (bagian 1.5 dan 2.4).
4. **Penghentian bersih.** Hentikan service Sysmon selama lima menit dengan cara yang diizinkan di lab-mu (misalnya `sysmon64 -u` lalu pasang ulang dengan konfigurasi yang sama), jalankan beberapa program, lalu hidupkan lagi. Hitung durasi periode diam dari EID 4 dan System 7036, dan cari proses yang menghentikannya di 4688 (bagian 1.7).
5. **Driver tidak dicoba dimuat.** Di snapshot terpisah, ubah `Start` driver Sysmon menjadi 4, reboot, jalankan beberapa program, lalu kembalikan dan reboot lagi. Catat: ada atau tidak ada 7026, ada atau tidak ada EID 4 Stopped, dan last write key service. Ini pembanding untuk kasus driver yang gagal termuat (bagian 1.7).
6. **Crash.** Di snapshot terpisah, buat crash yang terkendali (misalnya dengan alat Sysinternals NotMyFault, hanya di VM lab), lalu boot ulang. Catat 41, 6008, 1001, dan apakah Sysmon hidup kembali dengan sendirinya. Bandingkan urutannya dengan bagian 2.6, dan catat apakah 7026 untuk driver Sysmon muncul atau tidak di build-mu.
7. **Beban.** Jalankan skrip jinak yang membuat dan menghapus puluhan ribu berkas kecil di satu folder dalam beberapa menit, dengan konfigurasi yang mencatat EID 11 untuk folder itu. Amati apakah EID 255 muncul dan bagaimana rasio EID 1 terhadap 4688 berubah selama beban. Tulis bagaimana kamu membedakannya dari sabotase (bagian 2.8).
8. **Direktori arsip.** Aktifkan EID 23 dengan `ArchiveDirectory` yang kamu tentukan dan `CopyOnDeleteExtensions` untuk `.txt`, hapus beberapa berkas uji, lalu pulihkan isinya dari direktori arsip (dari konteks System) dan cocokkan dengan EID 23. Ulangi dengan EID 26 saja dan buktikan berkasnya tidak lagi tersimpan. Catat juga apakah `__PSScriptPolicyTest_*` ikut terarsip (bagian 1.4 dan 2.7).
9. **Exclude yang terlalu lebar.** Tambahkan aturan exclude berdasarkan nama image saja untuk `notepad.exe`, lalu jalankan salinan `notepad.exe` dari folder lain dengan nama yang sama. Buktikan aktivitas itu hilang dari EID 1 tetapi ada di 4688, dan temukan perubahannya lewat EID 16.
10. **Perubahan lewat registry.** Ekspor `HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters` dari `LAB-WS02` (konfigurasi berbeda), impor ke `LAB-WS01`, lalu amati apakah Sysmon memuat ulang konfigurasi tanpa `sysmon64 -c` dan apakah EID 16 ditulis, dengan path berkas apa [S1][S13].
11. **Nama berbeda.** Pasang ulang Sysmon dengan `DriverName` yang berbeda, lalu temukan keberadaannya tanpa nama bawaan (dari `ImagePath` service, daftar driver, dan channel event log). Tulis cara yang berhasil.
12. **AutoLogger dan sesi berjalan.** Di `LAB-WS01`, ubah `Enabled` satu provider di salah satu sesi AutoLogger menjadi 0 lalu reboot; di boot yang sama, cabut provider lain dari sesi yang berjalan dengan `logman` dan opsi `-ets`. Bandingkan dengan `LAB-WS02` lewat ekspor registry dan `logman query -ets`, dan catat jejak mana yang selamat di image (registry, 4688, Prefetch) dan mana yang hilang setelah reboot berikutnya (bagian 1.6 dan 2.5). Kembalikan snapshot setelah langkah ini.
13. **Laporan.** Susun tabel periode diam seperti bagian 2.3 untuk langkah 3 sampai 7, peta celah konfigurasi akhir seperti bagian 2.9, dan satu paragraf laporan untuk satu periode diam yang menyebut awal, akhir, sebab, keyakinan, dan sumber pengganti.

**Hasil yang sebaiknya tersimpan:**

- Baseline konfigurasi, skema, sesi berjalan, dan ekspor AutoLogger kedua VM.
- Rasio EID 1 terhadap 4688 untuk kondisi normal, konfigurasi terbalik, dan beban.
- Tabel jejak untuk penghentian bersih, `Start` 4, dan crash: EID 4, 7036, 7026, 41, 6008, 1001, last write key.
- Berkas yang dipulihkan dari direktori arsip beserta EID 23, dan bukti perbedaan EID 23 dan EID 26.
- Bukti exclude berdasarkan nama image saja, beserta EID 16 yang menandainya.
- Catatan apakah perubahan lewat registry menulis EID 16 di build-mu.
- Cara menemukan Sysmon yang namanya diubah.
- Perbandingan AutoLogger dan sesi berjalan, dengan catatan jejak yang selamat setelah reboot.
- Paragraf laporan periode diam.

**Variasi tantangan:** minta rekan menjalankan satu dari langkah 3 sampai 7 tanpa memberi tahu yang mana, di jam yang kamu tidak tahu. Dari koleksi KAPE `EventLogs,RegistryHives` saja, tentukan jalur putusnya, waktunya, dan keyakinanmu, lalu bandingkan dengan catatan rekan.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat membaca ETW dan Sysmon sebagai sumber bukti. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Tidak ada event Sysmon sama sekali di host | Sysmon tidak terpasang, namanya diubah lewat `DriverName` [S1], atau driver tidak termuat sejak boot | Cari service dari `ImagePath`; cek 7026 dan 7000 di System; cek `Start` key service dan driver |
| Index `sysmon` kosong, channel di host berisi | Forwarder atau input-nya bermasalah | Bandingkan hitungan host dan index (bagian 2.2); cek index lain host itu |
| EID 1 menipis tanpa EID 4 | Konfigurasi berganti (EID 16) atau beban (EID 255) | Cari EID 16 dan 255 pada jendela yang sama (bagian 2.3) |
| Kekosongan tanpa EID 4 Stopped | Crash, driver tidak termuat, atau event log berhenti | Cari 41, 6008, 1001, 7026, 6006 di System (bagian 2.6) |
| Event jaringan tidak ada | EID 3 memang mati secara bawaan [S1] | Periksa konfigurasi sebelum menyimpulkan |
| Tidak ada hash di event proses | `HashAlgorithms` tidak diset; dokumentasi tidak sejalan soal nilai bawaan [S1] | Periksa konfigurasi dan isi field `Hashes` di EID 1 |
| Berkas yang dihapus tidak ada di arsip | Konfigurasi memakai EID 26 saja, ekstensi tidak termasuk, Sysmon tidak berjalan saat itu, atau arsip dibersihkan [S1] | Periksa konfigurasi pada waktu penghapusan dan ukuran direktori arsip |
| Direktori arsip tidak bisa dibuka | Dilindungi ACL System [S1] | Akses dari konteks System, atau baca dari image |
| Direktori arsip tidak ada di `C:\Sysmon` | Dua nilai bawaan berbeda di dokumentasi [S1], atau `ArchiveDirectory` diganti | Baca nilai dari konfigurasi aktif, lalu cari di akar tiap volume |
| Last write key AutoLogger berubah tiap boot | Nilai yang ditulis ETW sendiri (`Status`, `FileCounter`) [S3] | Bandingkan nilai dengan host sejenis, bukan waktunya |
| `logman query -ets` di host bukti berbeda dari image | Perubahan lewat `-ets` hilang saat reboot [S7] | Untuk masa lalu, cari eksekusi `logman.exe` di 4688 dan Defender |
| Satu sesi tidak menerima event dari provider | Kuota sesi provider habis (manifest dan TraceLogging maksimal delapan) [S2] | Hitung sesi yang mengaktifkan provider itu |
| Nama field tidak cocok dengan kueri | Skema berbeda antar versi Sysmon [S1] | Ambil skema dengan `sysmon64 -s` dari versi yang sama |
| Sysmon bawaan Windows gagal dinyalakan | Sysmon Sysinternals masih terpasang [S9] | Cek service Sysmon Sysinternals dan status fitur dengan DISM |

## 5. Kesalahan umum dan jebakan

- **Menyimpulkan dari Splunk saja.** Grafik datar di index bisa berarti Sysmon diam, forwarder rusak, atau host mati; bandingkan dengan channel di host dan dengan 4688 sebelum menulis apa pun.
- **Hanya mencari EID 4.** Penggantian konfigurasi, beban, crash, dan driver yang gagal dimuat tidak menulis EID 4 Stopped; EID 16, 255, dan System harus ikut dicari.
- **Menganggap kekosongan sebagai sabotase.** Kekosongan saja bukan bukti; cari peristiwa awalnya, siapa yang melakukannya, dan apakah polanya cocok dengan change [S2].
- **Menutup sebagai operasional tanpa bukti.** "Mungkin pembaruan" bukan sebab; sebab operasional juga harus ditunjukkan dengan event, log alat, atau change yang cocok.
- **Mencari tindakan hanya di periode diam.** Perubahan `Start` dan AutoLogger berlaku di reboot berikutnya; jendela pencarian harus mundur sampai perubahan konfigurasi terakhir yang diketahui.
- **Membaca konfigurasi dari share.** Yang berlaku adalah EID 16, `SysmonDrv\Parameters`, dan `sysmon64 -c` di host pada waktu itu.
- **Menjalankan `sysmon64 -c <berkas>` di host bukti.** Dengan argumen berkas, perintah itu mengganti konfigurasi; dump hanya tanpa argumen, dan catat sebagai jejak responder.
- **Menyimpulkan Sysmon tidak terpasang dari nama service.** `DriverName` bisa mengubah nama driver dan service [S1].
- **Membalik `onmatch` tanpa sadar.** Include dengan daftar yang ditulis untuk exclude berarti hanya mencatat yang ingin dibuang; uji konfigurasi baru dengan pembanding 4688.
- **Mengecualikan berdasarkan nama image saja.** Proses lain dengan nama sama di path berbeda ikut tidak tercatat.
- **Melewatkan direktori arsip, atau mencarinya padahal tidak pernah dikonfigurasi.** Baca konfigurasi dulu.
- **Melaporkan periode diam tanpa durasi dan sumber pengganti.** Kalimatnya harus menyebut awal, akhir, sebab, keyakinan, dan apa yang tetap bisa dijawab.
- **Mengabaikan konfigurasi AutoLogger,** padahal ia menjelaskan telemetri apa yang seharusnya aktif sejak boot.

## 6. Catatan terkini

Bagian ini menampung detail versi, status rilis, dan perubahan istilah yang bisa bergeser; alur analisis di atas tidak bergantung padanya kecuali disebut.

- **Sysmon Sysinternals.** Halaman Microsoft Learn terbit 2026-09-10, menyebut Sysmon berjalan di Windows 11 ke atas dan Windows Server 2019 ke atas, memuat event ID 1 sampai 29 dan 255, dan memakai contoh `schemaversion` 4.82 [S1]. Halaman itu tidak menampilkan nomor versi biner; listing perangkat lunak pihak ketiga mencatat versi 15.22 dengan tanggal yang sama [S16]. Nomor versi yang terpasang dibaca dari baris pertama keluaran `sysmon64 -c` di host. PT JAB membekukan 15.22 untuk rollout 2027; versi yang lebih baru diuji di lab dulu sebelum masuk ring pilot.
- **Dua ketidakkonsistenan di dokumentasi Sysmon** [S1]: direktori arsip bawaan ditulis `C:\Sysmon` di penjelasan EID 23 dan `Sysmon` di tabel entri konfigurasi; `HashAlgorithms` bawaan ditulis `None` di tabel entri, sedangkan contoh pemasangan menyebut image di-hash SHA1 dengan pengaturan bawaan. Tentukan keduanya dari host, bukan dari halaman.
- **Sysmon bawaan Windows 11.** Diumumkan untuk Windows 11 dan Windows Server 2025, diuji di Insider build 26300.7733 (Dev, 2026-02-03): mati secara bawaan, dinyalakan lewat Settings > System > Optional features > More Windows features atau `Dism /Online /Enable-Feature /FeatureName:Sysmon`, lalu `sysmon -i`; Sysmon dari situs Sysinternals harus di-uninstall dulu; dokumentasinya baru dijanjikan [S9]. Media melaporkan fitur yang sama masuk ke pembaruan opsional KB5077241 (build 26100.7922 dan 26200.7922, Februari 2026) [S10] dan ke pembaruan keamanan Maret 2026 KB5079473 (build 26100.8037 untuk 24H2 dan 26200.8037 untuk 25H2) [S11]. Untuk 23H2, sumber yang diperiksa tidak menyebut fitur ini. Halaman Microsoft Learn khusus Sysmon bawaan belum ditemukan per 2026-10-23, jadi nama service, nama driver, channel, dan cara pembaruannya cek di build-mu sebelum menulis kueri atau membaca image.
- **Keputusan PT JAB.** Rollout 2027 memakai Sysmon Sysinternals karena fleet masih campuran: sebagian laptop masih 23H2 sambil menunggu upgrade, sementara laptop hasil reimage sejak Februari 2027 memakai 25H2. Windows 11 Enterprise dan Education 23H2 menerima pembaruan terakhir pada pembaruan keamanan November 2026 [S12], sehingga upgrade itu juga kebutuhan keamanan. Peralihan ke Sysmon bawaan dinilai ulang setelah seluruh fleet di 25H2; bagi pemeriksa, di laptop 25H2 selalu cek dua kemungkinan (Sysinternals atau bawaan) sebelum mencari service dan channel.
- **ETW.** Halaman About Event Tracing (ms.date 2025-07-14, diperbarui 2026-07-17) memuat empat jenis provider, batas satu sesi untuk MOF dan WPP serta delapan sesi untuk manifest dan TraceLogging, dan daftar sebab event hilang, termasuk layanan Event Log yang dihentikan dan dijalankan saat event sedang ditulis [S2]. Halaman AutoLogger (ms.date 2018-05-31, diperbarui 2025-07-09) memuat nilai `Status`, `FileCounter`, dan `Boot` (`Boot` hanya untuk debugging, didukung sejak Windows Server 2022) [S3].
- **ATT&CK.** Di ATT&CK v20, gangguan terhadap alat dan log pertahanan ada di T1685 Disable or Modify Tools (taktik Defense Impairment, TA0112), dengan T1685.001 Disable or Modify Windows Event Log dan T1685.005 Clear Windows Event Logs; gangguan ETW dibahas di deskripsi teknik induk, tanpa sub-teknik sendiri [S15]. Aturan dan laporan lama memakai nomor T1562.002 dan T1070.001 untuk hal yang sama (Day 21 bagian 6).
- **Sysmon for Linux** ada sebagai proyek terpisah dengan cakupan event yang berbeda dari versi Windows [S5]; relevan untuk host Linux di Day 23, tidak dipakai di Day ini.

## 7. Cheat sheet

```
ETW        controller (start/stop sesi, aktifkan provider, statistik event/buffer hilang)
           provider (tulis event) | consumer (baca: Event Log service, EDR, forwarder)
           provider MOF/WPP = 1 sesi ; manifest/TraceLogging = maks 8 sesi
           EVENT HILANG tanpa sabotase: event >64K | buffer < event | consumer lambat/tiada
                                         (termasuk Event Log service restart) | disk lambat

JALUR      driver SysmonDrv (boot-start) -> service Sysmon64 -> channel Sysmon/Operational (UTC)
           -> .evtx -> universal forwarder -> index sysmon
           Splunk diam? bandingkan: channel di HOST vs INDEX, dan Sysmon EID 1 vs Security 4688

JEJAK      channel .evtx | .etl (%SystemRoot%\System32\LogFiles\WMI\) | buffer memori
           HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\<sesi>\{GUID provider}
             sesi: Start (1/0), Guid, Status (0 = OK), FileCounter (ditulis ETW)
             provider: Enabled (1/0), EnableLevel, MatchAnyKeyword
             berlaku saat REBOOT berikutnya ; logman ... -ets = sesaat, hilang saat reboot
           HKLM\...\Services\SysmonDrv\Parameters  Rules | HashingAlgorithm | Options
             service memuat ulang otomatis bila registry berubah
           Services\SysmonDrv Start 0 (boot) | Services\Sysmon64 Start 2 (auto)

SYSMON     sysmon64 -c (tanpa argumen = DUMP, simpan) | -c <file> = GANTI | -s skema | -u copot
           1 proses | 2 waktu buat diubah | 3 jaringan (MATI default) | 4 service start/stop
           8 CreateRemoteThread | 9 RawAccessRead | 10 ProcessAccess | 11 FileCreate
           12-14 registry | 15 stream | 16 konfigurasi berubah | 17/18 pipe | 19-21 WMI
           22 DNS | 23 FileDelete+ARSIP | 25 ProcessTampering | 26 FileDeleteDetected
           27 blok executable | 28 blok shredding | 29 executable terdeteksi | 255 error
           EID 4 dan 16 TIDAK BISA DIFILTER

FILTER     include = hanya yang cocok | exclude = semua kecuali yang cocok | exclude menang
           field sama = OR, field beda = AND (atau RuleGroup) | include kosong = tidak dicatat
           include<->exclude TERBALIK = "catat hanya yang bising"
           exclude by nama image saja = celah ; DriverName bisa diganti

ARSIP      EID 23 -> ArchiveDirectory (ACL System; psexec -sid) ; CopyOnDeletePE/Extensions/Processes/SIDs
           dokumentasi: "C:\Sysmon" vs "Sysmon" -> baca dari konfigurasi, cari di akar volume
           hanya terisi saat Sysmon jalan DAN konfigurasi memuat EID 23

JALUR PUTUS -> JEJAK
           service stop/uninstall   EID 4 Stopped + 7036               (4688 siapa)
           konfigurasi ganti        EID 16 (berkas + hash), tanpa EID 4 (cocokkan change)
           beban/bug                EID 255 berulang, event menipis    (cocokkan beban)
           driver gagal dimuat      7026 + 7000, tanpa EID 4 Stopped   (cek Start tetap 0)
           Start=4 lalu reboot      tanpa 7026, Start berubah + last write
           crash                    41 + 6008 (waktu LOKAL di pesan) + 1001

KEPUTUSAN  operasional | sabotase | TIDAK DAPAT DITENTUKAN
           siapa/proses apa | pola banyak host vs satu | sebab terdokumentasi | isi periode diam
           jendela pencarian mundur sampai perubahan konfigurasi terakhir, bukan hanya periode diam

LAPORAN    periode diam: AWAL, AKHIR, DURASI, SEBAB, KEYAKINAN, SUMBER PENGGANTI
           "tidak ada bukti pada telemetri yang tersedia, dengan celah: <peta celah>"

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Di `JKT-WS-0536` tidak ada EID 4 Stopped sebelum periode diam, jadi Sysmon tidak pernah berhenti dan kekosongan itu pasti masalah forwarder." Benarkah?

<details><summary>Jawaban</summary>

Tidak. EID 4 Stopped hanya ditulis bila service berhenti secara bersih (dihentikan atau di-uninstall). Host yang crash, atau driver yang gagal dimuat saat boot, tidak menulis EID 4 Stopped sama sekali. Masalah forwarder disingkirkan dengan cara lain: channel Sysmon di host (E02-W1) juga kosong pada periode yang sama, persis seperti index, sementara Security tetap terkirim. Di `JKT-WS-0536`, System menunjukkan crash (41, 6008, 1001) lalu 7026 untuk `SysmonDrv` pada boot berikutnya. Lihat bagian 1.7, 2.2, dan 2.6.

</details>

**2. Skenario keputusan.** Enam laptop pilot menunjukkan EID 1 turun ke satu digit per jam selama sekitar empat jam, masing-masing dengan dua EID 16 pada jam task sinkronisasi dan tanpa EID 4. Langkah mana yang paling tepat sebelum menulis kesimpulan?

- A. Tulis sebagai sabotase terkoordinasi, karena enam host berubah hampir bersamaan.
- B. Cocokkan hash di EID 16 dengan versi konfigurasi yang dirilis, baca diff antar versi, dan bandingkan EID 1 dengan 4688 di jendela itu.
- C. Abaikan, karena tidak ada EID 4 berarti Sysmon berjalan normal.

<details><summary>Jawaban</summary>

B. EID 16 di jam task, dengan path berkas task dan hash yang sama dengan versi 2.1 yang dirilis lewat change, menunjukkan perubahan di jalur change; diff menemukan tiga `onmatch` yang terbalik dari exclude ke include, yang menjelaskan EID 1 satu digit per jam; 4688 menunjukkan host tetap aktif. A keliru karena pola banyak host pada jam yang sama, sesuai ring pilot, justru tanda change, dan tuduhan butuh bukti tindakan di luar jalur itu. C keliru karena konfigurasi bisa membuat Sysmon "hidup tetapi buta" tanpa pernah menulis EID 4. Lihat bagian 1.5 dan 2.4.

</details>

**3. Pertanyaan jebakan.** "Konfigurasi di `\\corp.jab.example\NETLOGON\Sysmon\pilot\` sekarang versi 2.2 yang benar, jadi itulah konfigurasi yang berlaku di laptop pilot Rabu pukul 11:00." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Berkas di share menunjukkan apa yang dimaksud penyebar sekarang, bukan apa yang dibaca driver di host pada waktu tertentu. Versi 2.2 dirilis Rabu 11:20 tetapi baru diterapkan saat task pukul 13:30 berjalan; pukul 11:00 laptop pilot masih menjalankan 2.1. Yang menentukan adalah EID 16 (waktu, berkas, hash) di host, nilai `SysmonDrv\Parameters`, dan dump `sysmon64 -c` saat itu. Lihat bagian 1.5 dan 2.4.

</details>

**4. Skenario keputusan.** Kamu menemukan nilai `Start` 0 pada sebuah sesi AutoLogger di image host yang dicurigai. Apa langkah berikutnya yang paling tepat?

- A. Tulis sebagai temuan gangguan ETW, karena `Start` 0 berarti sesi tidak dimulai saat boot.
- B. Bandingkan dengan host sejenis dari gold image dan build yang sama; bila berbeda, cari waktu perubahan, reboot sesudahnya, dan eksekusi alat yang menulisnya.
- C. Abaikan registry dan jalankan `logman query -ets` di image.

<details><summary>Jawaban</summary>

B. Banyak sesi bawaan memang bernilai `Start` 0 di gold image; yang menjadi temuan adalah perbedaan terhadap host sejenis, bukan nilai 0 itu sendiri. Bila berbeda, perubahan baru berlaku setelah reboot, sehingga urutan perubahan, reboot, dan periode diam harus terbukti, dan pelakunya dicari di 4688 atau Defender. A keliru karena menilai satu nilai tanpa pembanding. C keliru karena `logman ... -ets` bekerja pada sesi yang sedang berjalan di host hidup, bukan pada image. Lihat bagian 1.6 dan 2.5.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Dimas, dalam tiga kalimat, kenapa `JKT-WS-0536` direkomendasikan turun ke SEV-4 walaupun penyebab driver Sysmon gagal dimuat belum diketahui.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Periode diam lima jam di `JKT-WS-0536` dimulai oleh crash, dan tidak ada tindakan manusia yang menyentuh Sysmon, service, registry, atau ETW sejak laptop di-reimage, baik di Security 4688, Defender, maupun registry; Yuni pengguna biasa dan tidak ada sesi admin selain responder. Selama periode itu, eksekusi proses tetap tercatat di 4688 dan Defender dan isinya hanya aplikasi kerja, jadi tidak ada indikasi kompromi yang memanfaatkan kebutaan itu. Yang belum diketahui adalah sebab teknis driver gagal dimuat setelah crash, dan itu pekerjaan tim IT dengan dump crash, bukan pertanyaan insiden keamanan."

Kesalahan yang sering muncul:
- Menulis "tidak ada sabotase" tanpa menyebut sumber yang diperiksa dan batasnya (akses LSASS tidak bisa dinilai untuk periode itu).
- Menyembunyikan bahwa sebab teknisnya belum ditentukan.
- Menyebut pemilik baru sebagai faktor tanpa bukti apa pun yang mengarah ke tindakannya.

</details>

**6. Pertanyaan jebakan.** "EID 255 adalah error di alat keamanan, jadi ratusan EID 255 di dua laptop Bandung menandakan ada yang mencoba melumpuhkan Sysmon." Benarkah?

<details><summary>Jawaban</summary>

Tidak otomatis. Dokumentasi menyebut EID 255 bisa muncul karena beban berat, bug, atau syarat keamanan dan integritas yang tidak terpenuhi. Di dua laptop Bandung, semua EID 255 berada di dalam jendela job backup penuh agen yang sedang dipilotkan, dimulai saat laju FileCreate dari agen itu mendekati dua ribu per menit, tanpa EID 4 atau 16, dengan konfigurasi dan sesi ETW yang sama dengan pembanding. Itu pola beban, dan kehilangannya terukur dari rasio EID 1 terhadap 4688 (turun dari 0,97 ke 0,71 dan 0,78). Lihat bagian 1.7 dan 2.8.

</details>

**7. Interview question (English).** "Your SIEM shows that Sysmon on a workstation went silent for five hours. How do you determine whether it was tampering or an operational problem?"

<details><summary>Sample answer</summary>

"First I check where the gap actually is: I compare the Sysmon channel on the host with what reached the SIEM, and I compare Sysmon process creation with Security 4688, which doesn't depend on Sysmon. If the host channel is also empty, the problem is on the endpoint, not the forwarder. Then I look for the events that can't be filtered out: Sysmon event 4 for service stop or start, event 16 for configuration changes, and event 255 for internal errors, plus Service Control Manager and crash events in the System log, like 7026 for a boot driver that failed to load, 41 and 6008 for an unexpected shutdown. I read the active configuration from the registry or a sysmon -c dump, compare it with the released versions, and diff the AutoLogger sessions against a known-good host from the same image. Then I ask who did what: 4688 and EDR telemetry for anything touching sysmon, sc, reg, logman or wevtutil, going back to the last configuration change, not just the silent window, because some changes only take effect after a reboot. Finally I classify it as tampering, operational, or undetermined, and I write the gap with start, end, cause, confidence, and the replacement sources that still cover that period."

What makes this answer strong: it separates pipeline from endpoint with an independent baseline, uses the events Sysmon cannot filter plus System log evidence, treats configuration as an artifact, extends the search window beyond the gap, allows "undetermined" as a valid outcome, and ends with how the gap is reported rather than just a verdict.

</details>

## 9. Sumber

| # | Judul | URL | Tipe | Tanggal / diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Sysinternals: Sysmon | https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon | primer | terbit 2026-09-10; dilihat 2026-10-09, diakses ulang 2026-10-23 | Tinggi. Daftar event ID 1 sampai 29 dan 255 beserta deskripsinya (EID 4 dan 16 tidak bisa difilter, sebab EID 255), channel dan timestamp UTC, opsi `-i -c -m -s -u`, driver boot-start, service sebagai protected process, konfigurasi dimuat ulang otomatis bila registry berubah, entri konfigurasi termasuk `ArchiveDirectory`, `CopyOnDelete*`, `DriverName`, `HashAlgorithms`, perilaku `onmatch` dan `RuleGroup`, contoh include kosong, syarat Windows 11 dan Server 2019 ke atas. Memuat dua ketidakkonsistenan nilai bawaan (direktori arsip, hash). Tidak menampilkan nomor versi biner |
| S2 | Microsoft Learn: About Event Tracing | https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing | primer | ms.date 2025-07-14, diperbarui 2026-07-17; diakses 2026-10-23 | Tinggi. Controller, provider, consumer; statistik buffer dan event hilang; empat jenis provider; batas satu sesi untuk MOF dan WPP serta delapan sesi untuk manifest dan TraceLogging; empat sebab event hilang termasuk batas 64K dan layanan Event Log yang di-restart |
| S3 | Microsoft Learn: Configuring and Starting an AutoLogger Session | https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-an-autologger-session | primer | ms.date 2018-05-31, diperbarui 2025-07-09; diakses 2026-10-23 | Tinggi. Path registry `Control\WMI\Autologger`, satu key per sesi dan subkey GUID per provider; nilai `Start`, `Guid`, `Status`, `FileName`, `FileCounter`, `FileMax`, `Boot`; nilai provider `Enabled`, `EnableLevel`, `MatchAnyKeyword`; perubahan berlaku saat restart berikutnya; lokasi `.etl` bawaan |
| S4 | Microsoft Learn: Event Tracing Sessions | https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-sessions | primer | dirujuk 2026-10-09 | Tinggi untuk konsep sesi, buffer, dan berkas log |
| S5 | Sysmon for Linux | https://github.com/microsoft/SysmonForLinux | primer | dirujuk 2026-10-09 | Sedang-tinggi. Relevan untuk host Linux di Day 23; cakupan event berbeda dari versi Windows |
| S6 | Endpoint-Forensics-Notes Day 05, 07, 08, 14, 15, 17, 20, 21, 23 | (lokal) | rujukan internal | 2026-10-23 | Keterkaitan antar Day: profil cakupan event log, artefak eksekusi, `$J`, memori, retensi Defender, rencana telemetri 2027, penghapusan Sysmon oleh penyerang |
| S7 | Microsoft Learn: logman query | https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/logman-query | primer | ms.date 2017-10-16, diperbarui 2026-02-16; diakses 2026-10-23 | Tinggi. Sintaks `logman query [providers\|nama]`, opsi `-ets` yang mengirim perintah langsung ke sesi trace tanpa menyimpan atau menjadwalkan |
| S8 | Microsoft Learn: logman create trace | https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/logman-create-trace | primer | ms.date 2017-10-16, diperbarui 2026-02-16; diakses 2026-10-23 | Tinggi. Opsi `-ets`, `-p` provider, `-rt`, ukuran buffer, mode logger. Halaman tidak menyebut AutoLogger |
| S9 | Windows Insider Blog: Announcing Windows 11 Insider Preview Build 26300.7733 (Dev Channel) | https://blogs.windows.com/windows-insider/?p=178587 | primer | 2026-02-03; diakses 2026-10-23 | Tinggi untuk status Insider: Sysmon bawaan mati secara bawaan, cara menyalakan lewat Optional features atau DISM lalu `sysmon -i`, Sysmon dari situs Sysinternals harus di-uninstall dulu, dokumentasi menyusul |
| S10 | BleepingComputer: Windows 11 KB5077241 update improves BitLocker, adds Sysmon tool | https://www.bleepingcomputer.com/news/microsoft/windows-11-kb5077241-update-improves-bitlocker-adds-sysmon-tool/ | sekunder (media) | 2026-02-25; diakses 2026-10-23 | Sedang. Pembaruan opsional Februari 2026, build 26100.7922 dan 26200.7922, Sysmon bawaan mati secara bawaan |
| S11 | Pureinfotech: KB5079473 Windows 11 March 2026 update | https://pureinfotech.com/KB5079473-windows-11-march-2026-update/ | sekunder (media) | 2026-03-10, diperbarui 2026-03-22; diakses 2026-10-23 | Sedang. Build 26100.8037 dan 26200.8037 membawa Sysmon bawaan; cara menyalakan; build 23H2 di pembaruan terpisah tanpa menyebut Sysmon |
| S12 | BleepingComputer: Microsoft: Windows 11 23H2 reaches end of support in 30 days | https://bleepingcomputer.com/news/microsoft/microsoft-windows-11-23h2-reaches-end-of-support-in-30-days | sekunder (media) | 2026-10-12; diakses 2026-10-23 | Sedang-tinggi. Windows 11 23H2 Enterprise, Education, dan IoT Enterprise menerima pembaruan terakhir pada pembaruan keamanan November 2026; mengutip pernyataan Microsoft |
| S13 | Microsoft (arsip blog): Sysinternals Sysmon suspicious activity guide | https://learn.microsoft.com/en-us/archive/blogs/motiba/sysinternals-sysmon-suspicious-activity-guide | sekunder (blog Microsoft yang diarsipkan) | 2017-12-07; diakses 2026-10-23 | Sedang-tinggi. Aturan dan konfigurasi Sysmon tersimpan di `SysmonDrv\Parameters` (`HashingAlgorithm`, `Options`, `Rules`), service memantau key itu dan memperbarui otomatis, penyebaran lewat Group Policy Preferences; untuk EID 4 Stopped, cari event Service Control Manager di System. Lama, jadi perilaku registry dibuktikan di lab dengan versi sekarang |
| S14 | Sigma rule: Windows EventLog Autologger Session Registry Modification Via CommandLine | https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_autologger_session_registry_modification/ | komunitas | rule 2025-12-25, halaman 2026-04-28; diakses 2026-10-23 | Sedang. Status experimental; memantau `reg.exe` atau PowerShell yang menulis `Start` atau `Enabled` di bawah `\Control\WMI\Autologger\`; tag T1685.001 |
| S15 | MITRE ATT&CK: Disable or Modify Tools (T1685) | https://attack.mitre.org/techniques/T1685/ | primer | versi 1.0 (ATT&CK v20), dimodifikasi 2026-09-11; diakses 2026-10-23 | Tinggi. Taktik Defense Impairment (TA0112); sub-teknik T1685.001 Disable or Modify Windows Event Log dan T1685.005 Clear Windows Event Logs; gangguan ETW di deskripsi induk tanpa sub-teknik sendiri |
| S16 | Madonoforest (Impress): Sysmon | https://forest.watch.impress.co.jp/library/software/sysmon/ | komunitas (listing perangkat lunak) | diakses 2026-10-23 | Sedang-rendah. Mencatat versi 15.22 bertanggal 2026-09-10; satu-satunya sumber nomor versi yang ditemukan, dipakai hanya untuk nomor versi |

**Catatan sumber:** nomor versi Sysmon 15.22 hanya dari listing pihak ketiga [S16], karena halaman resmi tidak mencantumkan nomor versi; tanggalnya cocok dengan tanggal terbit halaman resmi [S1], dan nomor versi yang terpasang dibaca dari keluaran `sysmon64 -c` di host. Status Sysmon bawaan Windows 11 di luar Insider dan cakupan build-nya berasal dari media [S10][S11]; halaman Microsoft Learn khusus fitur itu belum ditemukan, jadi nama service, driver, dan channel-nya belum ditulis di Day ini. Lokasi registry konfigurasi Sysmon dan pemuatan ulang otomatis berasal dari blog Microsoft 2017 yang diarsipkan [S13] dan dikuatkan pernyataan umum di halaman Sysmon [S1]; nama nilai di `Parameters` pada versi 15.x dicek di lab. Perbedaan 7026 (driver dicoba dimuat dan gagal) dengan nilai `Start` 4 (driver tidak dicoba dimuat) adalah penalaran dari cara kerja Service Control Manager, bukan kutipan dokumentasi; langkah 5 dan 6 lab dibuat untuk membuktikannya. Pernyataan bahwa penyerang lebih sering menambah pengecualian daripada mematikan Sysmon adalah penalaran operasional. Format keluaran `sysmon64 -c`, nama field EID 16 di Splunk, nama sesi ETW di keluaran `logman`, nama opsi `--recover` di RECmd, dan format nama berkas di direktori arsip adalah ilustrasi yang perlu dicocokkan di lab. Sebagian teknik gangguan ETW terjadi di dalam memori proses; Day ini hanya menyebut arah pemeriksaannya. Semua isi PT JAB, termasuk host, akun, versi konfigurasi, hash, change, agen backup `EBAgent`, waktu, dan jumlah event, adalah contoh fiktif yang disusun agar konsisten, bukan kejadian nyata.
