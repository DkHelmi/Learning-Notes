---
day: 12
title: 'Review Minggu 2: apa yang dibuktikan artefak host dan apa yang tidak, dari artefak eksekusi sampai persistence dan lateral movement, dengan peta konsep, glosarium, dan lab gabungan'
researched_on: 2026-10-16
versions_checked: 'Merangkum Day 07-11 tanpa riset baru. EZ Tools 2026.5.0 (PECmd, AmcacheParser, AppCompatCacheParser, SrumECmd, MFTECmd, RBCmd, RECmd, SBECmd, LECmd, JLECmd, EvtxECmd; CLI .NET 4.7.2 dan .NET 9, GUI hanya .NET 9); RECmd DFIRBatch.reb v2.22; dokumentasi format Prefetch libscca 0.0.24 (Juli 2026, versi format 31 untuk Windows 11); [MS-SHLLINK] revisi 10.0 (2025-11-21); spesifikasi format registry msuhanov/regf; Windows 11 23H2 (build 22631); Sysmon (halaman terbit 2026-09-10); Velociraptor 0.77.3; MITRE ATT&CK T1547.001 v2.1 (ATT&CK v20)'
---

# Day 12: Review Minggu 2 (artefak eksekusi, file system, registry, aktivitas pengguna, persistence dan lateral movement)

Cakupan: ringkasan Day 07-11, peta konsep yang menghubungkan artefak host dengan pertanyaan investigasi, tabel artefak ke pertanyaan ke keterbatasan, lembar "apa yang dibuktikan dan apa yang tidak" untuk tiga laptop `INC-2026-019` beserta pelajaran dari bedah `INC-2026-017`, glosarium, dan lab gabungan satu mini-kasus yang memakai semua kelompok artefak minggu ini.

## Ide inti

Setiap artefak host ditulis oleh komponen Windows tertentu untuk keperluannya sendiri, dan hanya bisa membuktikan hal yang dilihat komponen itu. Prefetch ditulis saat executable dimulai, jadi ia membuktikan program berjalan tetapi tidak tahu akun dan argumennya. `$J` ditulis saat file berubah, jadi ia membuktikan perubahan tetapi tidak pernah melihat pembacaan. Registry menyimpan keadaan terakhir dan sebagian waktu "pertama" dan "terakhir", bukan riwayat. ShellBags, LNK, dan Jump List ditulis oleh antarmuka, jadi skrip yang membaca file lewat API tidak meninggalkan apa pun di sana. Event logon, service, dan task di host tujuan menunjukkan host itu dimasuki, sedangkan artefak klien di host lain menunjukkan dari mana. Kalimat temuan yang benar selalu dimulai dari pertanyaan "siapa yang menulis artefak ini, dan apa yang tidak pernah ia lihat". Bila pertanyaan itu dilewati, laporan menulis "tidak dibaca", "tidak ada aktivitas lain", atau "tidak ada USB" padahal yang benar adalah "artefak ini tidak mencatat hal itu".

Kamu sudah mengenal pola ini dari NOC saat menulis lampiran RFO untuk gangguan besar. Setiap sumber data punya kolom sendiri: counter interface membuktikan port aktif, tabel MAC membuktikan perangkat pernah terlihat, log perubahan konfigurasi membuktikan baris diubah, accounting TACACS membuktikan perintah diketik, NetFlow membuktikan trafik mengalir. Engineer yang berpengalaman menulis RFO dengan satu tabel tambahan: untuk setiap perangkat, sumber data apa yang tersedia, apa yang bisa dibuktikan darinya, dan apa yang tidak. Tabel itu mencegah rapat review menarik kesimpulan seperti "tidak ada yang login ke router" padahal accounting di router itu memang tidak aktif. Lembar batas bukti forensik adalah tabel yang sama untuk host Windows. Bedanya, di forensik ada satu kolom lagi yang wajib: jejak tim responder sendiri, yang terlihat persis seperti jejak penyerang bila tidak dilabeli.

```
pertanyaan PIR: "apa yang terjadi di host H?"
        |
        v
SIAPA YANG MENULIS ARTEFAK INI, DAN APA YANG TIDAK IA LIHAT?
  eksekusi     Prefetch, BAM, UserAssist, Amcache, Shimcache, SRUM, PCA   (Day 07)
               lihat: proses baru        | tidak lihat: argumen, kerja di dalam proses
  file system  $MFT, $J, Recycle Bin, $I30, $LogFile                     (Day 08)
               lihat: perubahan file     | tidak lihat: pembacaan, pelaku
  registry     hive + log, NetworkList, USB, autostart, SAM              (Day 09)
               lihat: keadaan terakhir   | tidak lihat: riwayat lengkap, isi trafik, file disalin
  antarmuka    ShellBags, LNK, Jump List, RecentDocs, TypedPaths         (Day 10)
               lihat: kerja lewat GUI    | tidak lihat: skrip, operator lewat C2
  pergerakan   Run, service, task, WMI; 4624/1149/7045; MRU klien        (Day 11)
               lihat: masuk, keluar, bertahan | tidak lihat: trafik yang tidak menyentuh host
        |
        v
PISAHKAN PELAKU: pengguna | penyerang | responder (catatan saat itu, akun, media, hash)
        |
        v
LEMBAR BATAS BUKTI per host: terbukti (sumber, keyakinan) | tidak terbukti (dan sumber yang bisa menjawab)
```

Situasi yang dipakai di Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan dan data pribadi sekitar 400 ribu pelanggan broadband di sistem billing. Kasus utamanya `INC-2026-019`: lampiran `Tagihan-Okt-2026.zip` (berisi `Tagihan-Okt-2026.js`) dari `billing@vendor-tagihan.example` masuk ke 9 mailbox Senin 2026-10-12 pukul 15:58 dan dijalankan di tiga laptop staf penagihan. `JKT-WS-0388` (`andi.pratama`, Microsoft Defender for Endpoint dan Sysmon, audit lengkap) menjalankannya Senin 16:05. `JKT-WS-0412` (`rizky.saputra`, tanpa EDR, tanpa Sysmon, audit bawaan) menjalankannya Senin 20:14 saat dibawa ke luar kantor. `BDG-WS-0142` (`dewi.anggraini`, kantor Bandung, tanpa EDR, tanpa Sysmon) menjalankannya Selasa 08:51. Persistence-nya scheduled task `\SysCacheUpdate` yang menjalankan `C:\Users\<user>\AppData\Roaming\SysCache\upd.ps1`, C2-nya `cdn-sync.example.net` (`203.0.113.77:443`), dan password akun service `svc_billing` di skrip `export-tagihan.ps1` milik Andi dipakai untuk SSH ke server billing `jkt-billing01`. Selama minggu kedua ini kamu, analyst L2 yang memegang forensik endpoint, membaca image ketiga laptop dari salinan kerja `E18-W2` (Dewi, artefak eksekusi), `E15-W1` (Andi, file system dan aktivitas pengguna), dan `E16-W1` (Rizky, registry), lalu membedah dua workstation `INC-2026-017` (ransomware share `Keuangan`) untuk post-incident review kasus itu. Ketiga laptop `INC-2026-019` sudah di-reimage; yang tersisa adalah image dan salinan kerjanya.

Selasa 2026-10-27 pukul 08:30, Sari Kusuma, technical lead, menulis kepadamu di kanal `#inc-2026-019`:

> "Pagi. PIR `INC-2026-019` jam 13:00 sampai 15:00, fasilitatornya Bu Nina Kartika. Pesertanya banyak dan tidak semuanya teknis: Pak Dimas, Pak Agus (DPO), Yoga, tim IT, dan retainer. Aku khawatir ada yang menarik kesimpulan lebih jauh dari bukti, misalnya 'laptop Dewi bersih selain beacon', 'file Andi tidak dibaca', atau 'laptop Rizky tidak tersentuh selain task'. Tolong siapkan satu lembar untuk ketiga laptop: apa yang dibuktikan artefak host dan dari mana, apa yang tidak, dan kalimat apa yang boleh dipakai. Masukkan juga jejak kita sendiri di ketiga laptop supaya tidak muncul lagi sebagai temuan, dan pelajaran dari bedah `INC-2026-017` kemarin yang berlaku untuk kasus ini. Aku perlu sebelum 11:30 supaya sempat kubaca."

Pesan itu memuat lima permintaan:

1. Untuk tiap laptop, apa yang dibuktikan artefak host, dari sumber apa, dan dengan keyakinan apa?
2. Untuk tiap laptop, apa yang tidak dibuktikan, sumber apa yang bisa menjawabnya, dan kalimat apa yang tidak boleh keluar di PIR?
3. Jejak responder apa saja yang ada di ketiga laptop, dan bagaimana dasarnya dipisahkan?
4. Pelajaran apa dari bedah `INC-2026-017` yang berlaku untuk `INC-2026-019`?
5. Seperti apa lembar satu halaman yang dibawa ke PIR?

Permintaan 1 dan 2 dijawab di bagian 1.8, permintaan 3 di bagian 1.9, permintaan 4 di bagian 1.10, dan permintaan 5 di bagian 1.11. Bagian 1.1 sampai 1.5 meringkas Day 07-11 sebagai bahannya, bagian 1.6 dan 1.7 menyusunnya menjadi peta dan tabel, dan bagian 2-4 memintamu menjalankan satu mini-kasus lab yang memakai semua kelompok artefak sekaligus, lalu menulis lembar batas bukti untuk kasus lab-mu sendiri.

**Kapan relevan:** sebelum post-incident review atau rapat dengan DPO, Legal, dan manajemen yang akan mengutip temuan forensik; sebelum menggabungkan artefak host ke super-timeline (Day 13), karena setiap kolom timeline harus tahu apa yang tidak bisa dicatatnya; dan sebelum interview yang meminta kamu menjelaskan beda bukti eksekusi, bukti keberadaan, dan bukti akses.
**Kapan bukan jawaban:** review ini tidak menambah aturan baru; bila ada yang terasa baru, kembali ke Day asalnya. Review ini juga tidak membahas analisis memori (Day 14 sampai 16) dan tidak menggantikan log jaringan, proxy, atau log server untuk pertanyaan trafik dan data yang keluar.

## 1. Ringkasan, peta konsep, dan glosarium

### 1.1 Day 07: artefak eksekusi

- Tidak ada satu artefak yang menjawab "dijalankan, kapan, oleh siapa, dan apa yang dilakukan". Prefetch menyimpan bukti eksekusi paling jelas: run count, sampai delapan waktu run terakhir di Windows 8 ke atas, volume tempat program dijalankan beserta nomor serinya, dan file yang dirujuk saat run [S3]. Waktu pembuatan file `.pf` menandai run pertama selama file itu tidak pernah dibuat ulang, sehingga program yang berjalan lebih dari delapan kali masih punya jangkar run pertama (Day 07 bagian 1.2).
- Prefetch tidak mencatat akun, argumen, atau parent process, dan bisa nonaktif; nilainya dibaca dari `EnablePrefetcher` di SYSTEM hive, bukan ditebak dari jenis disk (Day 07 bagian 1.2).
- Shimcache dan Amcache lebih kuat untuk keberadaan daripada eksekusi. Waktu di Shimcache adalah last modified file, bukan waktu run, dan cache baru ditulis ke hive saat shutdown atau reboot. Di Windows 10 dan 11, nilai "Executed: Yes" adalah indikator kuat, sedangkan "No" tidak membuktikan apa pun [S5]. Amcache bukan log eksekusi; SHA-1-nya hanya dihitung atas 31.457.280 byte pertama file, dan `InventoryDriverBinary` berarti driver dimuat [S4] (Day 07 bagian 1.3).
- BAM menyimpan waktu eksekusi terakhir per executable per SID sejak Windows 10 1709 [S6], sehingga SID mesin (akun lokal) dan SID domain bisa dibedakan walaupun nama akun tidak di-resolve. UserAssist hanya mencatat peluncuran lewat Explorer (Day 07 bagian 1.4).
- SRUM mencatat byte jaringan per aplikasi per user per sekitar satu jam, tanpa tujuan dan isi, dan waktu barisnya bisa meleset sampai sekitar satu jam [S7] (Day 07 bagian 1.6). PCA Windows 11 hanya mencatat sebagian peluncuran lewat GUI; ketiadaannya tidak konklusif [S8] (Day 07 bagian 1.7).
- Jejak responder dipisahkan dengan minimal dua dari empat jangkar yang dicatat saat tindakan: daftar tindakan dan waktu, akun, lokasi dan media (nomor seri volume di Prefetch), serta identitas file (SHA-1 Amcache cocok dengan toolkit) (Day 07 bagian 1.5).
- Artefak eksekusi hanya melihat proses baru. Kerja yang dilakukan di dalam proses PowerShell yang sudah berjalan tidak meninggalkan artefak eksekusi, sehingga daftar program yang ditemukan adalah batas bawah, bukan daftar lengkap (Day 07 bagian 1.8).
- Di PT JAB (`BDG-WS-0142`, `E18-W2`): `WSCRIPT.EXE` dengan `Tagihan-Okt-2026.js` Selasa 08:51:16 WIB, `POWERSHELL.EXE` run pertama 08:51:19 lalu task tiap 15 menit sampai Rabu 17:36:31 (run count 132), enumerasi `whoami`, `systeminfo`, `ipconfig`, `net`/`net1` Selasa 09:06:44 sampai 09:07:10, semuanya di bawah SID Dewi. Jawaban dikirim ke Sari pukul 13:10 (Day 07 bagian 2.2, 2.5, 2.8).

### 1.2 Day 08: file system

- NTFS mencatat perubahan, bukan pembacaan. `$MFT` menyimpan keadaan terakhir setiap file dengan dua set timestamp; `$J` menyimpan urutan perubahan dalam jendela terbatas; Recycle Bin menyimpan file yang dihapus lewat Explorer beserta asal dan waktunya (Day 08 bagian 1.1 dan 1.4).
- Huruf C di MACB adalah perubahan entry `$MFT`, bukan Created. Timestamp Accessed tidak menjawab "dibuka atau tidak": pembaruannya bisa mati dan bisa ditunda sampai satu jam. Nilai `NtfsDisableLastAccessUpdate` dibaca dari hive SYSTEM [S10] (Day 08 bagian 1.2).
- SI bisa diubah dari user mode, sedangkan FN ditulis kernel saat file dibuat, dipindah, atau di-rename. SI Created yang jauh lebih tua dari FN Created adalah indikasi timestomping, bukan bukti, karena FN bisa mewarisi SI palsu setelah file dipindah [S11]. Sumber yang mencatat kejadian (`FileCreate`, rename, dan `BasicInfoChange` di `$J`) lebih kuat daripada sumber yang mencatat keadaan (Day 08 bagian 1.3).
- `$J` tidak punya reason untuk membaca, dan `SecurityId` di record USN milik file, bukan akun yang mengubahnya [S9]. Jendela jawabannya adalah record tertua sampai terbaru (Day 08 bagian 1.4).
- Recycle Bin mengikat penghapusan ke SID pengguna dan menyimpan isi di `$R`; Shift+Delete dan penghapusan oleh proses tidak lewat sana [S12] (Day 08 bagian 1.6). `$LogFile` dan slack `$I30` adalah sumber tambahan dengan jendela pendek dan tidak lengkap (Day 08 bagian 1.5).
- Setiap jawaban file system ditulis dengan empat unsur: klaim, jendela, dasar dan korelasi, keyakinan dan batas (Day 08 bagian 1.7).
- Di PT JAB (`JKT-WS-0388`, `E15-W1`): jendela `$J` Minggu 10:17 sampai Kamis 08:47 WIB; `export-tagihan.ps1` tidak diubah, dipindah, atau dihapus; `upd.ps1` tanpa indikasi timestomping (SI = FN, `FileCreate` pada detik yang sama, tidak ada `BasicInfoChange` setelahnya); last access mati (`0x80000003`); 41 file di Documents dan Desktop diperlakukan berpotensi terpapar; ZIP dihapus Andi ke Recycle Bin Selasa 11:12:40 setelah ditelepon L1 Gilang 11:08, isi `$R` cocok dengan lampiran asli. Jawaban dikirim ke Sari pukul 15:40 untuk DPO (Day 08 bagian 2.2 sampai 2.7).

### 1.3 Day 09: registry

- Registry adalah database konfigurasi, bukan log. Last write time adalah satu FILETIME UTC per key yang berubah bila key atau salah satu nilainya berubah; nilai sendiri tidak punya timestamp [S13][S14] (Day 09 bagian 1.2).
- Hive dari sistem hidup sering kotor. Sejak Windows 8.1, perubahan bisa tersimpan di `.LOG1` dan `.LOG2` sampai sekitar satu jam sebelum ditulis ke file hive utama [S13]. Koleksi live wajib membawa transaction log, dan parser harus memainkannya ulang (RECmd default, RLA untuk alat lain) (Day 09 bagian 1.2).
- Waktu di dalam nilai tidak seragam zonanya. Properti perangkat USB dan SAM memakai UTC, sedangkan `NetworkList` dan `setupapi.dev.log` memakai waktu lokal host [S15]. Zona waktu host tidak mengubah artefak yang sudah UTC seperti Prefetch dan `$MFT` (Day 09 bagian 1.3 dan 1.4).
- Event 4616 selalu dicatat terlepas dari subcategory audit, tetapi koreksi kecil di bawah ambang W32Time tidak menghasilkan event; ketiadaan 4616 berarti tidak ada lompatan besar, bukan selisih nol [S18] (Day 09 bagian 1.3).
- USB dibaca dari USBSTOR, SCSI, dan USB sekaligus; waktu pertama dicolok ada di properti `0065` (FirstInstallDate), bukan `0064` yang berubah saat driver diperbarui [S16]. `MountPoints2` menunjuk sesi tempat volume di-mount, bukan orang yang mencolok, dan registry tidak membuktikan file disalin [S17] (Day 09 bagian 1.5).
- Autostart registry mencakup Run dan RunOnce (mesin dan tiap profil), Winlogon, IFEO, Services, dan TaskCache; key `Tree` tanpa nilai `SD` adalah tanda task yang disembunyikan [S29] (Day 09 bagian 1.6). SAM hanya akun lokal dan menyimpan hash; image disk adalah bukti yang berisi kredensial (Day 09 bagian 1.7).
- Di PT JAB (`JKT-WS-0412`, `E16-W1`, dibandingkan dengan hive `E14`): zona WIB sejak pemasangan, `tzautoupdate` mati, tanpa 4616 di jendela insiden, jam laptop +2 detik Selasa 17:10 dan +3 detik Kamis 08:40; lampiran dijalankan saat laptop tersambung ke Wi-Fi hotel `Kenanga-Hotel`, dan beacon berjalan lewat tiga jaringan di luar PT JAB sampai laptop masuk jaringan kantor Selasa 17:10:29. Jawaban dikirim ke Sari pukul 13:40 (Day 09 bagian 2.3 sampai 2.8).

### 1.4 Day 10: aktivitas pengguna

- Artefak aktivitas pengguna adalah efek samping fitur kenyamanan yang ditulis antarmuka: Explorer, dialog Open/Save, dan shell lewat `SHAddToRecentDocs` [S19]. Skrip yang membaca file lewat API tidak memanggil antarmuka itu, sehingga biasanya tidak meninggalkan jejak di sini [S20] (Day 10 bagian 1.1).
- Ada empat tingkat bukti yang perlu dibedakan: TypedPaths (path diketik), ShellBags (folder dilihat), LNK, Jump List, RecentDocs, dan OpenSavePidlMRU (file dibuka atau dipilih) [S2], serta WordWheelQuery (kata dicari di Explorer) (Day 10 bagian 1.5).
- Waktu ShellBags (`FirstInteracted`, `LastInteracted`) adalah inferensi parser dari last write time key, bukan fakta yang dijamin [S20]. Waktu target di header LNK adalah potret target saat LNK ditulis, bukan keadaan terakhir file; waktu pembukaan dibaca dari waktu file `.lnk` itu sendiri (Day 10 bagian 1.2 dan 1.3).
- Search LNK muncul bila hasil pencarian Explorer dibuka; namanya sama dengan kata kunci dan berpasangan dengan WordWheelQuery [S22] (Day 10 bagian 1.3).
- Nomor seri volume di LNK berbeda dari nomor seri perangkat di USBSTOR [S21]; keduanya dihubungkan lewat jembatan seperti event 1006 Partition/Diagnostic (salinan boot record yang memuat nomor seri volume [S27]), EMDMgmt, dan MountedDevices (Day 10 bagian 1.6).
- Hands-on-keyboard tidak selalu berarti desktop. Operator yang mengetik perintah lewat kanal C2 tidak meninggalkan artefak shell; pembedaannya butuh pola 4104, EDR, memori, dan trafik (Day 10 bagian 1.6).
- Di PT JAB (`JKT-WS-0388`, `E15-W1`): semua artefak shell di profil Andi cocok dengan pekerjaan Andi sendiri (share tim September, Documents Senin 14:01, simpan lampiran lewat dialog Outlook 16:04:48, buka ZIP 16:05:04, Excel Selasa 08:24, hapus ZIP 11:12); tidak ada unlock atau RDP antara Senin 13:02:40 dan Selasa 08:12:05; jejak Yoga ada di profil `ir-admin`. Jawaban dikirim ke Sari pukul 14:50 (Day 10 bagian 2.2 sampai 2.7).

### 1.5 Day 11: persistence dan lateral movement

- Persistence dan lateral movement adalah dua pertanyaan berbeda dari kumpulan artefak yang hampir sama. Setiap mekanisme persistence punya lebih dari satu jejak: Run key (empat key Run dan RunOnce resmi di HKLM dan HKCU [S28]), service (7045 dan key Services), scheduled task (XML di `Tasks\`, TaskScheduler 106, 4698, TaskCache), Startup folder, dan WMI event subscription (Day 11 bagian 1.1).
- "Kapan" dan "oleh apa" dijawab dari korelasi. Last write key Run lemah karena bergeser bila nilai lain berubah; 4698 sejak Windows 10 1903 memuat `ClientProcessId` dan `ParentProcessId` serta XML lengkap saat pembuatan [S23] (Day 11 bagian 1.1).
- Lateral movement dibaca dari dua sisi. Di host tujuan: 4624 type 3 untuk akses jaringan, type 10 untuk RDP, ditambah jejak pendukung per metode [S30]. Di host sumber: artefak klien seperti MRU `Terminal Server Client\Default` [S26], Prefetch alat remote, dan 4648 (Day 11 bagian 1.2 dan 1.3).
- Metode dikenali dari kombinasi, bukan satu tanda: service sementara ditambah named pipe untuk pola PsExec, `WmiPrvSE.exe` tanpa service baru untuk WMI, `wsmprovhost.exe` dan port 5985/5986 untuk WinRM, type 10 ditambah 1149 dan LocalSessionManager 21 untuk RDP [S24] (Day 11 bagian 1.4).
- WMI event subscription terdiri dari filter, consumer, dan binding [S25]; ia tidak muncul di Run key atau task, dan dibuktikan dari Sysmon 19 sampai 21 atau parsing `OBJECTS.DATA` offline (Day 11 bagian 1.5).
- Persistence yang dihapus masih bisa dibuktikan pernah ada dari 7045, 4698 (XML awal), TaskScheduler 141, record `FileDelete` di `$J`, dan VSS (Day 11 bagian 1.6).
- Disk workstation tidak membuktikan trafik yang tidak menyentuh host atau isi yang ditulis ke host lain; bukti itu ada di log jaringan dan log server (Day 11 bagian 1.7).
- Di PT JAB (`INC-2026-017`, `E05-W1` untuk `JKT-WS-0457` dan `E06-W1` untuk `JKT-WS-0441`): rantai bertingkat `jkt-dmz-app01` ke `JKT-WS-0441` lewat pola service sementara dengan local admin yang dipakai ulang, lalu `JKT-WS-0441` ke `JKT-WS-0457` lewat RDP akun `budi.santoso`, lalu `JKT-WS-0457` ke share `\\JKT-FS01\Keuangan`. Jawaban dikirim ke Sari Senin 2026-10-26 untuk PIR kasus itu (Day 11 bagian 2.6 sampai 2.8).

### 1.6 Peta konsep

Peta berikut menggabungkan diagram Day 07-11 dalam satu gambar. Kolom kanan adalah hal yang tidak pernah dilihat penulis artefak; pakai peta ini sebagai satu-satunya bantuan saat uji lisan di bagian 2-4.

```
PERTANYAAN                  ARTEFAK (penulis)                         TIDAK PERNAH DILIHAT
program dijalankan?         Prefetch (prefetcher), BAM (SCM latar),   argumen, parent, kerja di dalam
                            UserAssist (Explorer), Amcache/Shimcache  proses yang sudah berjalan
                            (appcompat), PCA (GUI), SRUM (jam)        tujuan dan isi trafik
      |
      v
file dibuat/diubah/dihapus? $MFT (keadaan), $J (perubahan),           PEMBACAAN, pelaku perubahan,
                            Recycle Bin (Explorer delete),            kejadian di luar jendela $J
                            $I30 slack, $LogFile
      |
      v
konfigurasi dan riwayat     hive + .LOG1/.LOG2 -> replay              riwayat lengkap (hanya pertama/
mesin?                      zona/jam, NetworkList, USB, autostart,    terakhir), file disalin ke USB,
                            SAM, ProfileList                          isi trafik
      |
      v
orang di desktop?           ShellBags, LNK, Jump List, RecentDocs,    skrip yang membaca lewat API,
                            OpenSave/LastVisited, TypedPaths,         operator lewat C2
                            WordWheelQuery (antarmuka)
      |
      v
bertahan? masuk? keluar?    Run/service/task/WMI ; 4624 3/10, 1149,   trafik tanpa jejak host, isi
                            7045, 5145 di tujuan ; MRU, Prefetch,     yang ditulis ke host lain
                            4648 di sumber
      |
      v
PELAKU      pengguna | penyerang | responder  (catatan saat itu + akun/SID + media/volume serial + hash)
      |
      v
LEMBAR      terbukti: klaim + sumber + jendela + keyakinan | tidak terbukti: + sumber yang bisa menjawab
```

Tiga benang dipakai untuk menguji peta ini dengan `INC-2026-019` dan `INC-2026-017`:

1. **Benang host:** setiap laptop punya daftar yang terbukti dan yang tidak, masing-masing dengan sumber dan keyakinan (bagian 1.8).
2. **Benang pelaku:** setiap jejak responder di setiap laptop punya pasangan di catatan yang dibuat saat itu (bagian 1.9).
3. **Benang pelajaran:** cara berpikir dari kasus lain yang mencegah kesimpulan keliru di kasus ini (bagian 1.10).

### 1.7 Artefak, pertanyaan investigasi, dan keterbatasan

Tabel ini adalah rangkuman paling padat minggu ini: setiap kelompok artefak, pertanyaan yang bisa dijawabnya, dan keterbatasan yang wajib ikut tertulis. Baca kolom kanan lebih dulu sebelum menulis kalimat "tidak".

| Artefak | Pertanyaan yang dijawab | Keterbatasan | Day |
|---|---|---|---|
| Prefetch (`.pf`) | Program apa dijalankan, berapa kali, kapan (8 waktu terakhir + waktu pembuatan `.pf`), dari volume mana | Tanpa akun dan argumen; bisa nonaktif; waktu lama tertimpa pada program yang sering berjalan | 07 |
| Amcache | Path dan SHA-1 executable, driver yang dimuat | Bukan log eksekusi; SHA-1 hanya 30 MiB awal; butuh transaction log | 07 |
| Shimcache (AppCompatCache) | File dikenal sistem, urutan relatif | Waktu = last modified file; ditulis saat shutdown; "No" tidak membuktikan apa pun | 07 |
| BAM | Waktu eksekusi terakhir per executable per SID | Satu waktu saja; device path, bukan huruf drive | 07 |
| UserAssist | Program yang diluncurkan lewat Explorer oleh user itu | Command line, skrip, dan task tidak tercatat | 07 |
| SRUM | Byte jaringan per aplikasi per user per jam | Tanpa tujuan dan isi; waktu meleset sampai sekitar satu jam; database sering dirty | 07 |
| PCA (Windows 11) | Sebagian peluncuran lewat GUI | Format tidak didokumentasikan vendor; tidak dijamin ada | 07 |
| `$MFT` (SI dan FN) | Keadaan terakhir file: nama, induk, ukuran, dua set timestamp | Bukan riwayat; SI bisa dipalsukan; FN bisa ikut berubah setelah move | 08 |
| `$J` (USN journal) | Perubahan file dalam jendela: dibuat, ditulis, rename, dihapus, timestamp diubah | Tidak mencatat pembacaan dan pelaku; jendela terbatas | 08 |
| Recycle Bin (`$I`, `$R`) | Siapa (SID), kapan, dari mana, dan isi file yang dihapus lewat Explorer | Shift+Delete dan penghapusan oleh proses tidak lewat sini | 08 |
| `$I30` slack dan `$LogFile` | Nama file lama; transaksi NTFS terbaru | Tidak lengkap; timestamp slack bukan waktu hapus; `$LogFile` cepat berputar | 08 |
| Last write time key | Kapan key atau salah satu nilainya terakhir berubah | Tidak menunjuk nilai tertentu; bisa dipalsukan; diperbarui Windows sendiri | 09 |
| Hive + transaction log | Keadaan registry yang lengkap | Tanpa replay, perubahan menit terakhir sebelum koleksi live hilang | 09 |
| `NetworkList`, interface TCP/IP | Jaringan yang pernah dikenal, pertama dan terakhir tersambung, lease terakhir | Waktu lokal host; bukan setiap sesi; tanpa isi trafik | 09 |
| USB (USBSTOR, SCSI, USB, `0065`-`0067`, MountedDevices, MountPoints2) | Perangkat yang dikenali, colok pertama dan terakhir, sesi tempat di-mount | Hanya kejadian terakhir; tidak membuktikan file disalin; MountPoints2 bukan pelaku | 09 |
| Autostart registry dan TaskCache | Run, Winlogon, service, task (termasuk yang disembunyikan tanpa `SD`) | Folder Startup dan WMI tidak ada di registry | 09 |
| SAM, ProfileList | Akun lokal, logon terakhir, anggota grup lokal, SID ke profil | Hanya akun lokal; tidak mencatat eskalasi hak; berisi hash | 09 |
| ShellBags | Folder yang dilihat lewat Explorer atau dialog, termasuk USB, share, dan arsip | Bukan file dibuka; waktu adalah inferensi parser | 10 |
| LNK dan Jump List | File yang dibuka lewat shell, dari volume mana, oleh aplikasi apa, berapa kali | Bukan isi atau perubahan; bisa dihapus; perilaku untuk file dari dalam ZIP perlu diuji | 10 |
| RecentDocs, OpenSave, LastVisited, TypedPaths, WordWheelQuery | File dibuka, file dipilih di dialog, path diketik, kata dicari | Last write milik key (biasanya MRU 0 saja); tidak mencatat skrip | 10 |
| Persistence (Run, service, task, Startup, WMI) | Cara kode bertahan setelah reboot atau logoff, kapan, oleh proses apa | Satu artefak jarang cukup; WMI butuh Sysmon atau `OBJECTS.DATA` | 11 |
| Logon masuk (4624 type 3/10, 1149, LSM 21, 7045, 5145) | Host ini dimasuki dari mana, dengan metode apa | Bergantung audit dan channel yang aktif; 5145 sering mati | 11 |
| Artefak klien (MRU RDP, bitmap cache, Prefetch alat remote, 4648) | Host ini dipakai ke mana | Bisa dibersihkan; `UsernameHint` dari analisis praktisi | 11 |

### 1.8 Benang host: apa yang dibuktikan dan apa yang tidak di tiga laptop `INC-2026-019`

Permintaan pertama dan kedua Sari dijawab per laptop, karena sumber yang tersedia berbeda jauh. `JKT-WS-0388` punya EDR, Sysmon, dan audit lengkap; `JKT-WS-0412` dan `BDG-WS-0142` tidak punya keduanya dan memakai audit bawaan. Ketiga tabel di bawah dibaca dengan aturan yang sama: kolom "Keyakinan dan batas" adalah batas atas, dan kalimat yang lebih kuat dari itu tidak didukung bukti.

**`JKT-WS-0388` (Andi, `E15-W1`).** Ini laptop dengan sumber paling lengkap, sehingga artefak host paling banyak dikuatkan oleh sumber lain.

| Klaim | Terbukti? | Sumber | Keyakinan dan batas |
|---|---|---|---|
| Andi sendiri menyimpan dan membuka lampiran | Ya: simpan lewat dialog Outlook 16:04:48, ZIP dibuka di Explorer 16:05:04 | OpenSavePidlMRU, LastVisitedPidlMRU, LNK, ShellBags, RecentDocs, Jump List, Sysmon EID 11 (Day 10 bagian 2.3 dan 2.5) | Tinggi |
| Lampiran dijalankan dan loader terpasang | Ya: `.js` diekstrak 16:05:09, `wscript.exe` 16:05:11, `upd.ps1` 16:05:19, file task 16:06:02 | `$J`, `$MFT`, Sysmon, event log (Day 08 bagian 2.4) | Tinggi |
| Waktu `upd.ps1` tidak dipalsukan | Tidak ada indikasi | SI = FN, `FileCreate` pada detik yang sama, tidak ada `BasicInfoChange` setelahnya (Day 08 bagian 2.4) | Sedang-tinggi; pemalsuan SI dan FN sekaligus tetap mungkin tetapi bertentangan dengan `$J` dan telemetry |
| `export-tagihan.ps1` diubah, dipindah, atau dihapus | Tidak, dalam jendela Minggu 10:17 sampai Kamis 08:47 WIB | `$J` tanpa record (Day 08 bagian 2.4) | Tinggi untuk perubahan; sebelum Minggu pagi hanya dari `$MFT` |
| `export-tagihan.ps1` dibaca | Ya, Senin 23:40:17 | PowerShell 4104, bukan file system (Day 08 bagian 2.7) | Tinggi; disk tidak bisa menunjukkan pembacaan |
| Penyerang bekerja di desktop Andi | Tidak ada jejak | Tidak ada unlock atau RDP Senin 13:02:40 sampai Selasa 08:12:05; artefak shell cocok dengan pekerjaan Andi (Day 10 bagian 2.7) | Tinggi untuk desktop; operator lewat C2 tidak terlihat di artefak shell |
| Lampiran dihapus | Ya, oleh Andi Selasa 11:12:40, setelah telepon Gilang 11:08 | `$I`, `$J`, hash `$R` cocok dengan lampiran asli (Day 08 bagian 2.5) | Tinggi; penghapusan oleh pengguna, bukan anti-forensik |

Yang tidak dibuktikan artefak host di laptop ini: file mana di antara 41 file Documents dan Desktop yang dibaca loader (last access mati, `$J` tidak mencatat baca; jawabannya ada di memori retainer), apakah ada data dikirim keluar (log proxy, firewall, dan memori), dan apakah operator penyerang mengetik perintah langsung lewat C2, termasuk SSH Selasa 02:14 (pola 4104, EDR, memori, log jaringan). Kalimat yang tidak boleh keluar di PIR: "file Andi tidak dibaca" dan "penyerang tidak mengakses Documents". Kalimat yang benar: "penyerang tidak membuka Documents lewat Explorer; skrip penyerang membaca `export-tagihan.ps1`, dan 41 file di dua folder itu diperlakukan berpotensi terpapar sampai isinya diklasifikasi."

**`JKT-WS-0412` (Rizky, `E16-W1` dan `E14`).** Laptop tanpa EDR dan dengan audit bawaan, jadi registry menjadi sumber utama tentang konfigurasi, jaringan, perangkat, autostart, dan akun.

| Klaim | Terbukti? | Sumber | Keyakinan dan batas |
|---|---|---|---|
| Waktu Senin 20:14:21 WIB bisa dipegang | Ya, dengan ketelitian beberapa detik | Prefetch UTC; zona WIB sejak pemasangan; `tzautoupdate` mati; tanpa 4616; selisih +2 s Selasa 17:10 dan +3 s Kamis 08:40 (Day 09 bagian 2.3) | Tinggi untuk zona; jam Senin malam disimpulkan dari batas Selasa dan Kamis |
| Laptop di jaringan apa saat lampiran dijalankan | `Kenanga-Hotel`; beacon berlanjut lewat `BajaRaya-Guest` dan `HP-Rizky` sampai jaringan kantor 17:10:29 | `NetworkList`, WLAN-AutoConfig, interface TCP/IP (Day 09 bagian 2.4) | Tinggi; menjelaskan kenapa beacon tidak ada di log proxy, DNS, dan firewall PT JAB |
| Perangkat USB yang pernah dicolok | Kingston milik Rizky (terakhir Jumat 9 Oktober); `USB-E-10` 17:43-17:59 dan `USB-E-11` 18:01-18:35 milik responder | USBSTOR, SCSI, USB, `0065`-`0067`, MountedDevices, MountPoints2, label, VSN event 1006 (Day 09 bagian 2.5) | Tinggi untuk perangkat; registry tidak membuktikan file disalin ke perangkat mana pun |
| Autostart lain milik penyerang di registry | Tidak ditemukan; hanya `\SysCacheUpdate`, entri image standar, OneDrive, dan driver WinPmem responder | Run, RunOnce, Winlogon, IFEO, Services, TaskCache tanpa key `Tree` tanpa `SD` (Day 09 bagian 2.6) | Tinggi untuk registry; folder Startup dan WMI tidak ada di registry |
| Akun lokal baru | Tidak ada; `ir-admin` dipakai sekali Selasa 17:44 | SAM, SAMBuiltin, ProfileList, `$MFT` profil (Day 09 bagian 2.7) | Tinggi; SAM tidak mencatat eskalasi hak |

Yang tidak dibuktikan artefak host di laptop ini: data apa yang dikirim ke C2 lewat jaringan hotel dan hotspot (tidak ada di log PT JAB; volume per aplikasi hanya dari SRUM bila diolah), apakah ada file disalin ke USB, persistence di luar registry (folder Startup dan WMI belum dilaporkan dari `E16-W1`), dan eksekusi serta pembuatan task dari event log, karena audit bawaan tidak mencatat 4688 dan 4698 dan tidak ada Sysmon (Day 05 bagian 2.7). Kalimat yang tidak boleh keluar di PIR: "laptop Rizky tidak tersentuh selain task" dan "tidak ada USB". Kalimat yang benar: "di registry tidak ditemukan autostart lain milik penyerang dan tidak ada akun lokal baru; dua USB yang tercatat di jendela insiden milik responder; data yang mungkin dikirim lewat jaringan di luar kantor tidak bisa dinilai dari log PT JAB."

**`BDG-WS-0142` (Dewi, `E18-W2`).** Laptop tanpa EDR dan tanpa Sysmon, sehingga tidak ada process tree; yang menjawab eksekusi hanya artefak eksekusi di disk dan memori `E08`.

| Klaim | Terbukti? | Sumber | Keyakinan dan batas |
|---|---|---|---|
| Lampiran dijalankan di bawah akun Dewi | Ya, `wscript.exe` dengan `Tagihan-Okt-2026.js` Selasa 08:51:16 | Prefetch `FilesLoaded` + BAM SID Dewi (Day 07 bagian 2.2 dan 2.5) | Tinggi |
| Loader dan task berjalan | Ya: `powershell.exe` sejak 08:51:19, 132 run sampai Rabu 17:36:31 | Prefetch (waktu pembuatan `.pf` dan run count), BAM (Day 07 bagian 2.2) | Tinggi; run hari Selasa tertimpa di delapan waktu Prefetch, diwakili run count dan waktu pembuatan `.pf` |
| Program apa yang dijalankan penyerang | `whoami`, `systeminfo`, `ipconfig`, `net`/`net1`, Selasa 09:06:44-09:07:10 | Prefetch + BAM (Day 07 bagian 2.8) | Tinggi untuk program; argumen tidak diketahui |
| Data keluar dalam jumlah besar | Tidak ada tanda dari sisi host: `powershell.exe` mengirim 311.040 byte 08:00-16:00 WIB, tidak ada aplikasi lain yang menonjol | SRUM (Day 07 bagian 2.6) | Sedang; tanpa tujuan dan isi, waktu baris meleset sampai sekitar satu jam; konfirmasi dengan log jaringan |
| Entri Amcache dan Shimcache dari memo retainer | Membuktikan keberadaan, bukan eksekusi | Amcache, Shimcache (Day 07 bagian 2.3 dan 2.4) | Tinggi untuk tafsir; eksekusi dibuktikan Prefetch dan BAM |

Yang tidak dibuktikan artefak host di laptop ini: apa yang dikerjakan di dalam proses PowerShell tanpa membuat proses baru (membaca file, mengumpulkan informasi lewat .NET, mengirim data ke C2), argumen setiap program, dan tujuan serta isi trafik. PCA kosong untuk program-program itu adalah hasil yang diharapkan, bukan tanda bersih. Kalimat yang tidak boleh keluar di PIR: "laptop Dewi bersih selain beacon" dan "tidak ada aktivitas lain". Kalimat yang benar: "artefak eksekusi menunjukkan program X, Y, Z di bawah akun Dewi; tidak ditemukan executable penyerang lain di artefak yang diperiksa; aktivitas di dalam proses PowerShell tidak tercatat di artefak ini, sehingga cakupan penuh bergantung pada memori `E08` dan log jaringan" (Day 07 bagian 1.8).

Satu pola terlihat bila ketiga tabel dibaca berdampingan: kekuatan kalimat "tidak ditemukan" turun mengikuti sumber yang tersedia. Di laptop Andi, ketiadaan jejak interaktif dikunci oleh event logon dan Sysmon; di laptop Rizky dan Dewi, ketiadaan hanya berlaku untuk artefak yang diperiksa, karena audit bawaan dan ketiadaan Sysmon membuat banyak kejadian tidak pernah ditulis. Aturan ini sama dengan profil cakupan di Day 05 bagian 1.5, sekarang diterapkan ke artefak disk.

### 1.9 Benang pelaku: jejak responder di ketiga laptop

Permintaan ketiga Sari mencegah satu kesalahan yang sangat mudah terjadi di PIR: peserta yang membaca daftar artefak tanpa konteks akan melihat alat akuisisi memori, driver kernel, akun admin lokal, dan USB asing, lalu menyebutnya temuan. Tabel berikut mengumpulkan semua jejak responder yang dilabeli minggu ini. Baca kolom "Dasar pemisahan": setiap baris punya minimal dua jangkar, dan salah satunya selalu catatan yang dibuat saat tindakan dilakukan.

| Laptop | Waktu (WIB) | Jejak di artefak host | Pelaku | Dasar pemisahan |
|---|---|---|---|---|
| `JKT-WS-0388` | Selasa 12:38-12:55 | Profil `ir-admin` lahir 12:38:41; ShellBags `E:` dan `E:\INC-2026-019` (12:41:22, 12:54:12); event 1006 `USB-E-07` volume `2F6B8D10` (12:40:58-12:55:31); WinPmem dari `E:\tools\` | Yoga | Case notes Yoga; evidence log E01; akun dan profil terpisah dari Andi; VSN cocok inventaris toolkit (Day 10 bagian 2.6) |
| `JKT-WS-0388` | Kamis 08:46-08:47 | Logon `ir-admin`, shutdown sebelum image | Yoga | Case notes; jadwal image E15 09:00 |
| `JKT-WS-0412` | Selasa 17:43-17:59 | `USB-E-10` di USBSTOR dan di `MountPoints2` milik `rizky.saputra`; `ir-admin` LastLogon 17:44:02, profil lahir 17:44:05; driver WinPmem 17:45:06 | Yoga | Case notes; label dan VSN `USB-E-10`; sesi Rizky masih terbuka dan dipakai dengan elevasi UAC (Day 09 bagian 2.5 dan 2.7) |
| `JKT-WS-0412` | Selasa 18:00-18:35 | Logon `adm.yoga` dengan cached logon; `USB-E-11` di `Enum\SCSI` dan `MountPoints2` `adm.yoga`; last write Winlogon 18:00:12 | Yoga | Case notes E14; label dan VSN `USB-E-11`; huruf `E:` sama dengan perintah KAPE (Day 09 bagian 2.5 dan 2.6) |
| `JKT-WS-0412` | Kamis 08:44:52 | `ShutdownTime` | Yoga | Case notes konteks waktu 08:40 (Day 09 bagian 2.3) |
| `BDG-WS-0142` | Selasa 14:04-14:21 | `cmd.exe`, WinPmem, `autorunsc64.exe`, `schtasks`, `wevtutil`, `robocopy`, `certutil` di bawah SID akun lokal RID 1003; driver di Amcache; volume `5C2E91A4` | Fajar, dipandu Yoga | Panduan telepon 13:55; CoC E08; SID mesin vs SID domain; VSN `USB-E-09`; SHA-1 Amcache cocok toolkit (Day 07 bagian 2.8) |

Tiga hal dari tabel ini perlu disebut eksplisit di PIR:

- **Jejak responder bisa jatuh di profil pengguna.** `USB-E-10` muncul di `MountPoints2` milik Rizky karena Yoga memakai sesi Rizky yang masih terbuka. Tanpa case notes, baris itu terbaca "Rizky mencolok USB pukul 17:43" (Day 09 bagian 2.5).
- **Tindakan responder bisa menimpa jejak penyerang.** Prefetch hanya menyimpan delapan waktu run; setiap kali responder menjalankan program yang sama dengan penyerang, waktu lama hilang. Panduan telepon yang pendek dan terdaftar adalah kontrolnya (Day 07 bagian 1.5).
- **Koleksi live membawa jejaknya sendiri ke dalam hive kotor.** Data dua USB responder di `JKT-WS-0412` ada di transaction log saat E14 diambil; daftar USB retainer yang dibuat tanpa replay kehilangan keduanya (Day 09 bagian 2.2). Menit-menit terakhir sebelum koleksi live sering berisi jejak tim sendiri.

### 1.10 Benang pelajaran: dari bedah `INC-2026-017` ke `INC-2026-019`

Permintaan keempat Sari meminta cara berpikir, bukan fakta 017, karena fakta 017 sudah ada di laporan PIR-nya sendiri. Bedah dua workstation Keuangan menghasilkan empat pelajaran yang berlaku langsung untuk tiga laptop 019.

| Pelajaran dari 017 | Contoh di 017 | Penerapan di 019 |
|---|---|---|
| Satu artefak jarang cukup; keyakinan tinggi butuh beberapa sumber independen yang sepakat | Task di `JKT-WS-0441` didukung file XML, TaskScheduler 106, 4698 dengan `ClientProcessId`, dan `$MFT` (Day 11 bagian 2.4) | Task `\SysCacheUpdate` di `JKT-WS-0412` didukung XML, `Tree` TaskCache, dan `$MFT` `upd.ps1` (Day 09 bagian 2.6); di host tanpa 4698, tiga sumber itulah yang tersisa |
| Arah dibaca dari jenis artefak: logon masuk di tujuan, artefak klien di sumber | MRU RDP di `JKT-WS-0441` berarti RDP keluar ke `JKT-WS-0457`, bukan masuk (Day 11 bagian 2.7) | Di laptop Andi tidak ada RDP atau logon jaringan dari host lain (Day 06 bagian 1.9), sehingga laptop itu bukan tujuan lateral movement; artefak klien keluar di ketiga laptop belum dilaporkan dan diperiksa dengan cara Day 11 bagian 2.7 sebelum menulis "bukan sumber". Pergerakan ke `jkt-billing01` lewat SSH dari proses PowerShell, bukan lewat mekanisme Windows yang dibahas Day 11 |
| Persistence bisa berada di luar registry dan task | WMI subscription di `JKT-WS-0457` hanya terlihat dari Sysmon 19-21 dan `OBJECTS.DATA` (Day 11 bagian 2.5) | Folder Startup dan WMI di `E16-W1` belum diperiksa; di laptop tanpa Sysmon, `OBJECTS.DATA` adalah satu-satunya sumber, jadi tulis "belum diperiksa", bukan "tidak ada" |
| Disk tidak membuktikan apa yang terjadi di host lain atau di jaringan | Penulisan `.lck` ke `JKT-FS01` dari 5145 di file server; exfil 6 GB dari log proxy dan firewall (Day 11 bagian 1.7) | Data yang dibaca loader dan yang dikirim ke C2 dijawab memori dan log jaringan; untuk `JKT-WS-0412` di luar kantor, log PT JAB tidak ada sama sekali |

Satu pelajaran lagi bersifat penulisan. Di 017, setiap host punya satu payload dengan dua jalur bertahan (`sync.exe` lewat Run key dan task di `JKT-WS-0441`, `hlpsvc.exe` lewat service dan WMI subscription di `JKT-WS-0457`), dan masing-masing ditulis sebagai satu payload dengan beberapa jalur, bukan sebagai beberapa ancaman (Day 11 bagian 2.8). Di 019, task `\SysCacheUpdate` di tiga laptop adalah satu mekanisme yang sama di tiga host; menghitungnya sebagai "tiga persistence" di PIR akan memberi kesan skala yang salah.

### 1.11 Lembar batas bukti untuk PIR

Permintaan kelima Sari dijawab dengan dokumen satu halaman. Isinya disusun dari bagian 1.8 sampai 1.10 dan disimpan di `notes/` area kerja kasus, supaya yang dibaca di PIR sama dengan yang tersimpan, bukan salinan di chat.

```
INC-2026-019 | Batas bukti artefak host untuk PIR | dari: <kamu> ke: Sari Kusuma | Selasa 2026-10-27 11:20 WIB
Lokasi: \\jkt-evid01\cases\INC-2026-019\notes\pir-batas-bukti-host-2026-10-27.md
Dasar: jawaban tertulis ke Sari 20 Okt (E18-W2), 21 Okt (E15-W1, file system), 22 Okt (E16-W1), 23 Okt (E15-W1, aktivitas pengguna)

ATURAN BACA: kolom "boleh ditulis" adalah batas atas. "Tidak ditemukan" berlaku untuk artefak yang disebut saja.

JKT-WS-0388 (Andi; EDR + Sysmon + audit lengkap)
  TERBUKTI  Andi simpan & buka lampiran 16:04:48-16:05:04 | loader 16:05:11-16:06:02 | export-tagihan.ps1 DIBACA 23:40:17
            (4104) tapi tidak diubah/dihapus | tidak ada kerja penyerang di desktop | ZIP dihapus Andi 11:12:40
  TIDAK     file mana dari 41 file yang dibaca loader | data keluar | operator mengetik lewat C2 (SSH 02:14)
  BOLEH     "penyerang tidak membuka Documents lewat Explorer; 41 file diperlakukan berpotensi terpapar"
  JANGAN    "file Andi tidak dibaca" | "penyerang tidak mengakses Documents"

JKT-WS-0412 (Rizky; tanpa EDR, tanpa Sysmon, audit bawaan)
  TERBUKTI  waktu 20:14:21 WIB benar (+/- detik) | lampiran dijalankan di Wi-Fi hotel; beacon lewat 3 jaringan luar
            sampai 17:10:29 | tanpa autostart lain di registry | tanpa akun lokal baru | 2 USB di jendela = responder
  TIDAK     data ke C2 dari luar kantor | file disalin ke USB | Startup folder dan WMI (belum diperiksa)
            | eksekusi dan pembuatan task dari event log (audit bawaan)
  BOLEH     "di registry tidak ditemukan autostart lain milik penyerang"
  JANGAN    "laptop Rizky tidak tersentuh selain task" | "tidak ada USB"

BDG-WS-0142 (Dewi; tanpa EDR, tanpa Sysmon)
  TERBUKTI  wscript+js 08:51:16 | PowerShell 132 run s/d Rabu 17:36:31 | whoami/systeminfo/ipconfig/net 09:06-09:07
            (semua SID Dewi) | SRUM PowerShell ~0,30 MiB terkirim 08:00-16:00
  TIDAK     kerja di dalam proses PowerShell | argumen | tujuan & isi trafik
  BOLEH     "tidak ditemukan executable penyerang lain di artefak eksekusi; cakupan penuh dari memori E08 dan log jaringan"
  JANGAN    "laptop Dewi bersih selain beacon" | "tidak ada aktivitas lain" | "Amcache membuktikan dijalankan"

JEJAK KITA (dilabeli, bukan dihapus): ir-admin + USB-E-07 (0388) | USB-E-10, ir-admin, driver WinPmem, adm.yoga,
  USB-E-11 (0412) | akun lokal RID 1003, USB-E-09, WinPmem, autorunsc, certutil (0142). Dasar: case notes + CoC.

DARI 017: >1 sumber per kesimpulan | arah dari jenis artefak | persistence bisa di luar registry |
  disk tidak membuktikan jaringan | satu mekanisme di 3 host = 1 persistence, bukan 3

TERBUKA: Startup + WMI (OBJECTS.DATA) di E16-W1 | SRUM E16-W1 | uji lab: LNK untuk .js dari ZIP (CASE-2026-LAB-010)
  | password ir-admin unik per host (tim IT)
```

Cara membaca elemennya:

- **Baris "Dasar"** menunjuk empat jawaban tertulis yang sudah dikirim. Lembar ini tidak menambah analisis baru; ia memadatkan batas yang sudah ditulis supaya tidak hilang saat dikutip.
- **Baris "JANGAN"** berisi kalimat yang benar-benar muncul atau hampir muncul selama kasus, termasuk di pesan Sari. Menuliskannya eksplisit lebih efektif daripada berharap peserta membaca kolom batas.
- **Baris "TERBUKA"** memisahkan pekerjaan yang belum dilakukan dari hal yang memang tidak bisa dijawab disk. Keduanya sama-sama "tidak diketahui" di PIR, tetapi tindak lanjutnya berbeda.

**Kapan gagal:** lembar ditulis sebagai daftar temuan tanpa kolom "TIDAK", sehingga peserta PIR menganggap yang tidak disebut berarti tidak terjadi; atau jejak responder dibuang dari lembar supaya ringkas, lalu muncul lagi sebagai pertanyaan "USB siapa ini" dari retainer.

### 1.12 Glosarium

Definisi di bawah ditulis dengan kata sendiri untuk keperluan belajar. Kolom terakhir adalah pasangan yang paling sering membuat jawaban interview atau laporan keliru.

| Istilah | Arti singkat | Sering tertukar dengan |
|---|---|---|
| Artefak eksekusi | Catatan Windows yang kebetulan menyimpan jejak program yang dijalankan | Log eksekusi lengkap |
| Prefetch | File `.pf` berisi run count, sampai 8 waktu run, volume, dan file yang dirujuk | Bukti akun yang menjalankan |
| Waktu pembuatan `.pf` | Penanda run pertama selama file tidak dibuat ulang | Waktu run terakhir |
| Shimcache (AppCompatCache) | Daftar file yang ditemui subsistem kompatibilitas, ditulis saat shutdown | Bukti eksekusi dengan waktu run |
| Amcache | Hive inventaris file dan driver dengan SHA-1 (30 MiB awal) | Log eksekusi |
| BAM | Waktu eksekusi terakhir per executable per SID | Riwayat semua run |
| UserAssist | Program yang diluncurkan lewat Explorer per user, ROT13 | Semua program yang dijalankan user |
| SRUM | Pemakaian resource dan byte jaringan per aplikasi per jam | Log koneksi dengan tujuan |
| PCA | File teks Windows 11 berisi sebagian peluncuran GUI | Sumber eksekusi yang lengkap |
| Bukti keberadaan vs bukti eksekusi | File pernah ada atau dikenal vs file benar-benar dijalankan | Satu kategori yang sama |
| `$MFT` | Tabel entry per file berisi keadaan terakhir | Riwayat perubahan file |
| SI dan FN | Dua set timestamp: yang bisa diubah API dan yang ditulis kernel | FN sebagai jaminan anti-pemalsuan |
| MACB | Modified, Accessed, Changed (entry `$MFT`), Born | C sebagai Created |
| Timestomping | Mengubah timestamp file supaya tampak lebih tua | Modified lebih tua dari Created pada salinan |
| `$J` (USN journal) | Log perubahan file per volume dengan jendela terbatas | Log akses file |
| `BasicInfoChange` | Reason USN untuk perubahan atribut atau timestamp | Bukti timestomping |
| Recycle Bin (`$I`, `$R`) | Metadata dan isi file yang dihapus lewat Explorer, per SID | Semua penghapusan |
| `$I30` slack | Sisa entry nama file di index folder | Waktu penghapusan |
| Last write time | Waktu terakhir key atau salah satu nilainya berubah | Waktu nilai tertentu ditambahkan |
| Hive kotor dan transaction log | Hive yang perubahannya masih di `.LOG1`/`.LOG2` | Hive rusak |
| Control set dan `Select\Current` | Set konfigurasi SYSTEM yang dipakai saat boot terakhir | `CurrentControlSet` di hive offline |
| `NetworkList` | Profil jaringan yang pernah dikenal, waktu lokal | Daftar setiap sesi jaringan |
| `0065` dan `0064` | FirstInstallDate dan InstallDate properti perangkat | Keduanya sebagai waktu colok pertama |
| `MountPoints2` | Volume yang di-mount di sesi user tertentu | Orang yang mencolok USB |
| Nomor seri volume vs perangkat | Serial file system (LNK, Prefetch) vs serial hardware (USBSTOR) | Nilai yang bisa dicocokkan langsung |
| TaskCache (`Tree`, `Tasks`, `SD`) | Registrasi task di registry; `Tree` tanpa `SD` berarti task disembunyikan | XML task di `Tasks\` |
| SAM dan RID | Hive akun lokal; RID adalah bagian akhir SID | Daftar semua akun yang pernah login |
| Cached logon | Verifier logon akun domain yang disimpan lokal | Password tersimpan biasa |
| Artefak shell | Jejak per profil yang ditulis antarmuka Windows | Log akses file |
| ShellBags | Folder yang dilihat lewat Explorer atau dialog | File yang dibuka |
| LNK (source vs target time) | Waktu file `.lnk` vs potret waktu target saat LNK ditulis | Satu set waktu yang sama |
| Jump List | Item terbaru per aplikasi, dengan hitungan dan waktu terakhir | Riwayat isi file |
| WordWheelQuery dan search LNK | Kata yang dicari di Explorer, dan LNK yang dibuat saat hasil pencarian dibuka | Pencarian oleh skrip |
| Hands-on-keyboard | Aktivitas yang dikerjakan orang secara langsung | Kerja di desktop saja |
| Persistence | Cara kode bertahan setelah reboot atau logoff | Akses awal |
| Host tujuan vs host sumber | Host yang dimasuki vs host yang dipakai untuk masuk ke host lain | Satu arah yang sama |
| WMI event subscription | Filter, consumer, dan binding yang menjalankan aksi saat pemicu terpenuhi | Scheduled task |
| PSEXESVC dan named pipe | Service sementara dan kanal stdin/stdout/stderr pola PsExec | Nama service sebagai satu-satunya tanda |
| Jejak responder | Artefak dari tindakan tim sendiri, dilabeli dengan dasar | Temuan penyerang |
| Lembar batas bukti | Daftar per host: terbukti, tidak terbukti, kalimat boleh dan dilarang | Ringkasan temuan |

## 2-4. Lab gabungan dan troubleshooting

Lab ini menjalankan satu mini-kasus yang memakai semua kelompok artefak minggu ini: eksekusi, file system, registry, aktivitas pengguna, persistence, dan lateral movement. Semua aktivitas jinak, dijalankan di VM lab terisolasi dengan snapshot, dan dicatat jamnya (WIB dan UTC) sebelum dijalankan. Perintah di bawah ditulis sebagai teks untuk dijalankan di VM lab. Jangan memakai data, nama, atau kejadian dari pekerjaan nyata.

**Prasyarat:** `LAB-WS01` (`172.16.50.10`, Windows 11, Sysmon dengan event 3, 11, 12, 13, dan 19-21 aktif, audit policy diperluas termasuk Process Creation dengan command line, Other Object Access Events, dan Security System Extension, snapshot `bersih-2026-10-15`) sebagai host "korban". `LAB-WS02` (`172.16.50.11`, Windows 11, Sysmon, snapshot `bersih-2026-10-15`) sebagai host "sumber" untuk lateral movement jinak; Remote Desktop di `LAB-WS01` diaktifkan hanya untuk jaringan host-only. `LAB-DFIR01` (`172.16.50.20`) dengan KAPE dan EZ Tools di folder bertanggal, ditambah share baca saja `\\LAB-DFIR01\lab-src` berisi `uji-lab.zip` (memuat `uji-lab.js` dengan satu baris `WScript.Echo("lab");` dan `catatan-zip.txt`). Disk virtual `LAB-USB` berisi `\tools\autorunsc64.exe`. Akun lab: `lab.user` (pengguna biasa, dipakai juga sebagai akun "penyerang tiruan" dari `LAB-WS02`) dan `lab.ir` (admin lokal "responder"). Folder kasus `CASE-2026-LAB-012` di `LAB-DFIR01` dengan `evidence\`, `work\`, `analysis\`, `notes\`, `tools\`.

### Bagian A: skenario jinak dengan tiga pelaku

1. **Inventaris dan konteks waktu.** Catat versi alat di `tools\` dan konteks waktu kedua VM (Day 01 bagian 2.1). Catat nilai `EnablePrefetcher` dan `NtfsDisableLastAccessUpdate` `LAB-WS01` dari registry.
2. **Pengguna.** Login konsol `LAB-WS01` sebagai `lab.user`. Ketik `\\LAB-DFIR01\lab-src` di address bar Explorer, salin `uji-lab.zip` ke Downloads, buka ZIP di Explorer, buka `catatan-zip.txt` lalu jalankan `uji-lab.js` dari dalam ZIP. Buat `C:\Users\lab.user\Documents\rahasia-lab.txt` dan `catatan-lab.txt`, lalu hapus `catatan-lab.txt` lewat Explorer ke Recycle Bin. Kunci layar. Catat jam setiap langkah.
3. **Penyerang tiruan, interaktif.** Satu jam kemudian, dari `LAB-WS02` lakukan RDP ke `172.16.50.10` dengan akun `lab.user` (sesi terkunci akan diambil alih). Di Explorer, cari `rahasia` di kotak pencarian Documents dan buka hasilnya.
4. **Penyerang tiruan, skrip.** Masih di sesi RDP, jalankan satu `powershell.exe -EncodedCommand` jinak yang membuat `C:\Users\lab.user\AppData\Roaming\LabCache\uji.ps1` berisi `Write-Output "lab"`, mengubah SI Created file itu ke `2021-03-14 09:00:00` (seperti Day 08 bagian 3), mendaftarkan task `\LabTask12` yang menjalankan `powershell.exe -NoProfile -File` ke file itu setiap 15 menit, dan menambahkan nilai Run `LabRun12` di HKCU yang menjalankan `notepad.exe`. Di skrip yang sama, jalankan `Get-ChildItem C:\Users\lab.user\Documents -Recurse -File | Select-String -Pattern rahasia`. Putuskan sesi RDP tanpa sign out.
5. **Responder.** Di konsol `LAB-WS01`, Switch user ke `lab.ir` dan ketik password salah sekali. Colok `LAB-USB`, catat nomor seri volumenya dengan `vol E:`, jalankan `E:\tools\autorunsc64.exe -a * -c -h -s -t` ke file di `E:\`, lalu `certutil -hashfile` atas hasilnya. Sign out, cabut `LAB-USB`.
6. **Keputusan tertulis.** Tulis di case notes: pola koleksi (image disk VM setelah shutdown normal, bukan koleksi live) beserta alasannya, dan apa yang sengaja tidak diambil (memori, karena pertanyaan lab hanya artefak disk; risikonya kerja di dalam proses PowerShell tidak terlihat).

### Bagian B: koleksi dan parse

7. **Shutdown dan mount.** Matikan `LAB-WS01` dengan shutdown normal. Di `LAB-DFIR01`, salin disk VM ke `evidence\` sebagai master, hitung SHA-256, buat salinan kerja di `work\`, verifikasi, lalu mount read-only (Day 02 bagian 1.5).
8. **Targets.** Jalankan KAPE ke folder kerja dengan target yang mencakup semua kelompok artefak minggu ini:

```
<folder KAPE>\kape.exe --tsource <huruf mount> --target EvidenceOfExecution,RegistryHivesSystem,RegistryHivesUser,SRUM,FileSystem,RecycleBin_InfoFiles,LNKFilesAndJumpLists,EventLogs --tdest C:\CASE-2026-LAB-012\work\K1\tdest --tflush
```

   Isi persis setiap target cek dengan `kape.exe --tdetail` di versi KapeFiles lab-mu. `EvidenceOfExecution` tidak memuat SYSTEM hive, sehingga Shimcache dan BAM butuh `RegistryHivesSystem` (Day 07 bagian 2.1). Folder `C:\Windows\System32\Tasks\` dan `C:\Windows\System32\wbem\Repository\` disalin terpisah dari volume read-only bila target-mu tidak memuatnya; catat caranya.
9. **Parse.** Jalankan PECmd, AmcacheParser, AppCompatCacheParser, SrumECmd (Day 07 bagian 2.2 sampai 2.6), MFTECmd untuk `$MFT` (`--at`) dan `$J`, RBCmd (Day 08 bagian 2.2 sampai 2.5), RECmd dengan `DFIRBatch.reb` untuk semua hive dan `UserActivity.reb` untuk NTUSER `lab.user` (Day 09 bagian 2.2, Day 10 bagian 2.5), SBECmd, LECmd, JLECmd untuk kedua profil (Day 10 bagian 2.2 sampai 2.4), dan EvtxECmd dengan `--maps` eksplisit. Semua output ke `analysis\K1\EZ-<versi>\`.
10. **Sisi sumber.** Matikan `LAB-WS02`, ambil NTUSER `lab.user` dan folder Prefetch dari disk-nya dengan cara yang sama, lalu parse dengan RECmd dan PECmd.

### Bagian C: mini-kasus

Jawab tujuh pertanyaan berikut, masing-masing dengan artefak, nilai yang ditemukan, waktu UTC dan WIB, pelaku (pengguna, penyerang tiruan, responder), dan satu kalimat keterbatasan.

11. Program apa yang dijalankan di bawah akun `lab.user`, kapan, dan berapa kali? Mana yang terbukti dijalankan dan mana yang hanya terbukti ada?
12. Apakah ada file yang waktunya dipalsukan? Buktikan dengan lebih dari satu lapis.
13. File apa yang dihapus, oleh siapa, dan apakah isinya masih ada?
14. Perangkat USB apa yang tersambung, di sesi siapa, dan siapa yang memakainya?
15. Persistence apa yang dipasang, kapan, dan oleh proses apa?
16. Apakah `LAB-WS01` dimasuki dari host lain? Dari mana, dengan metode apa, dan apa bukti di sisi sumber?
17. Mana aktivitas yang dikerjakan lewat antarmuka dan mana lewat skrip, dan apa yang tidak bisa dibuktikan disk tentang pembacaan `rahasia-lab.txt`?

### Bagian D: variasi sumber yang lebih miskin

18. Ulangi Bagian A dan B dari snapshot `LAB-WS01` lain yang memakai audit bawaan dan tanpa Sysmon. Tulis ulang jawaban pertanyaan 12, 15, dan 16 hanya dari artefak disk dan event yang tersisa, lalu tandai keyakinan yang turun beserta alasannya. Ini padanan lab untuk perbedaan `JKT-WS-0388` dan `JKT-WS-0412`.
19. Ulangi pengambilan registry dengan koleksi live (KAPE `RegistryHivesSystem,RegistryHivesUser` dari dalam sesi `lab.ir`, beberapa menit setelah `LAB-USB` dicolok), lalu parse dengan dan tanpa `--nl`. Catat entri USB yang hanya muncul dengan replay (Day 09 bagian 2.2).

### Bagian E: lembar batas bukti kasus lab

20. Tulis lembar batas bukti untuk `CASE-2026-LAB-012` dengan susunan bagian 1.11: terbukti, tidak terbukti, kalimat boleh, kalimat dilarang, jejak responder, dan pekerjaan terbuka. Minta satu orang lain (atau dirimu sendiri seminggu kemudian) membacanya dan mencoba menulis satu kalimat yang lebih kuat dari buktinya; bila lolos, perbaiki lembarnya.

### Contoh kerangka solusi (buka setelah mencoba sendiri)

<details><summary>Pemetaan pertanyaan mini-kasus ke artefak</summary>

11. Prefetch (`WSCRIPT.EXE` dengan `uji-lab.js` di `FilesLoaded`, `POWERSHELL.EXE`) dan BAM di bawah SID `lab.user` untuk eksekusi dan akun. Amcache dan Shimcache hanya keberadaan, dan "Executed: No" tidak membuktikan apa pun. UserAssist hanya untuk peluncuran lewat Explorer. Argumen PowerShell dibaca dari Sysmon 1 atau 4688 di snapshot penuh, tidak dari artefak eksekusi (Day 07 bagian 1.1 dan 1.8).
12. `uji.ps1`: SI Created 2021 jauh lebih tua dari FN Created; `$J` mencatat `FileCreate` pada waktu nyata lalu `BasicInfoChange` beberapa detik kemudian; Sysmon 11 mencatat file dibuat pada waktu nyata. `catatan-zip.txt` dan `uji-lab.js` hasil ekstraksi punya Modified lebih tua dari Created dan subdetik nol: pola wajar file dari arsip, bukan timestomping (Day 08 bagian 1.3).
13. `catatan-lab.txt` lewat Recycle Bin: `$I` di folder SID `lab.user`, `$J` `RenameOldName` dan `RenameNewName` ditambah `FileCreate` `$I`, isi masih di `$R`. Penghapusan oleh pengguna, bukan penyerang tiruan, menurut waktu dan case notes (Day 08 bagian 1.6).
14. `LAB-USB` di USBSTOR atau `Enum\SCSI`, properti `0065` sampai `0067`, `MountPoints2` di NTUSER `lab.ir`, event 1006 dengan VSN yang sama dengan `vol E:`, Prefetch `AUTORUNSC64.EXE` dengan nomor seri volume `LAB-USB`, BAM di bawah SID lokal `lab.ir`. Semuanya responder, dengan dasar case notes, akun, VSN, dan hash (Day 09 bagian 1.5, Day 07 bagian 1.5).
15. Task `\LabTask12`: XML di `Tasks\`, TaskScheduler 106, 4698 dengan `ClientProcessId` sama dengan PID PowerShell di Sysmon 1, `Tree` dan `Tasks` di TaskCache. Run `LabRun12`: nilai di NTUSER `lab.user`, last write key pada detik yang sama, Sysmon 13. Waktu pembuatan paling kuat dari FN file XML dan 4698, bukan dari last write Run key (Day 11 bagian 1.1, Day 09 bagian 1.6).
16. Di `LAB-WS01`: 4624 type 10 dari `172.16.50.11`, RemoteConnectionManager 1149, LocalSessionManager 21 dan 25 (sesi terkunci diambil alih), lalu 24 saat diputus. Di `LAB-WS02`: `Terminal Server Client\Default` `MRU0` `172.16.50.10` dan Prefetch `MSTSC.EXE` pada menit yang sama (Day 11 bagian 1.2 dan 1.3).
17. Lewat antarmuka: TypedPaths `\\LAB-DFIR01\lab-src`, ShellBags share (NTUSER) dan ZIP, LNK dan Jump List ZIP, Recycle Bin, WordWheelQuery `rahasia` dan search LNK, LNK `rahasia-lab.txt.lnk` pada jam RDP. Lewat skrip: pembuatan `uji.ps1`, task, Run key, dan pencarian `Select-String`, yang tidak meninggalkan ShellBags atau LNK. Pembacaan `rahasia-lab.txt` oleh skrip tidak terlihat di `$J` dan, bila last access mati, tidak terlihat di `$MFT`; hanya Sysmon atau 4104 yang bisa menunjukkannya (Day 10 bagian 1.1, Day 08 bagian 1.4).

</details>

<details><summary>Timeline mini (ilustrasi)</summary>

Keluaran ilustrasi untuk lab pada Sabtu 2026-10-31; Logon ID, PID, dan jam akan berbeda di lab-mu.

```
UTC                  WIB       Sumber                               Kejadian                                          Pelaku
2026-10-31 02:00:10  09:00:10  Security 4624 type 2                 lab.user login konsol                             pengguna
2026-10-31 02:04:12  09:04:12  TypedPaths + ShellBags (NTUSER)      \\LAB-DFIR01\lab-src diketik dan dibuka           pengguna
2026-10-31 02:04:20  09:04:20  $J FileCreate                        Downloads\uji-lab.zip                             pengguna
2026-10-31 02:05:02  09:05:02  ShellBags + LNK + Jump List          uji-lab.zip dibuka di Explorer                    pengguna
2026-10-31 02:05:09  09:05:09  Prefetch WSCRIPT.EXE + BAM           uji-lab.js dari folder sementara, SID lab.user    pengguna
2026-10-31 02:12:40  09:12:40  $I + $J Rename*                      catatan-lab.txt ke Recycle Bin                    pengguna
2026-10-31 03:20:28  10:20:28  LAB-WS02: MRU0 + Prefetch MSTSC.EXE  tujuan 172.16.50.10                               penyerang (tiruan)
2026-10-31 03:20:31  10:20:31  1149 + 4624 type 10 + LSM 25         RDP dari 172.16.50.11, sesi lab.user diambil      penyerang (tiruan)
2026-10-31 03:22:05  10:22:05  WordWheelQuery + search LNK + LNK    "rahasia", rahasia-lab.txt dibuka dari hasil cari penyerang (tiruan)
2026-10-31 03:24:40  10:24:40  Sysmon 1                             powershell.exe -EncodedCommand ..., PID 5120      penyerang (tiruan)
2026-10-31 03:24:43  10:24:43  $J FileCreate + Sysmon 11            LabCache\uji.ps1                                  penyerang (tiruan)
2026-10-31 03:24:44  10:24:44  $J BasicInfoChange                   SI Created uji.ps1 menjadi 2021-03-14             penyerang (tiruan)
2026-10-31 03:24:46  10:24:46  4698 + TS 106 + TaskCache Tree       \LabTask12, ClientProcessId 5120                  penyerang (tiruan)
2026-10-31 03:24:47  10:24:47  Run LabRun12 last write + Sysmon 13  HKCU Run notepad.exe                              penyerang (tiruan)
2026-10-31 03:26:10  10:26:10  LSM 24                               sesi RDP diputus                                  penyerang (tiruan)
2026-10-31 03:40:04  10:40:04  Security 4625                        lab.ir, password salah                            responder
2026-10-31 03:40:15  10:40:15  Security 4624 x2 + 4672              lab.ir type 2, pasangan elevated                  responder
2026-10-31 03:41:02  10:41:02  Partition/Diagnostic 1006            LAB-USB, VSN cocok dengan "vol E:"                responder
2026-10-31 03:42:30  10:42:30  Prefetch AUTORUNSC64.EXE + BAM       volume LAB-USB, SID lokal lab.ir                  responder
2026-10-31 03:48:55  10:48:55  Prefetch CERTUTIL.EXE                hash hasil autorunsc                              responder
2026-10-31 03:50:20  10:50:20  Security 4647                        lab.ir sign out                                   responder
```

Rekonstruksi: pengguna mengambil arsip dari share, membuka dan menjalankan isinya lewat Explorer, lalu menghapus satu file. Satu jam kemudian sesi yang sama diambil alih lewat RDP dari `LAB-WS02`: ada kerja lewat antarmuka (pencarian dan pembukaan `rahasia-lab.txt`) dan kerja lewat skrip (loader, timestomp, task, Run key, pencarian `Select-String`). Responder masuk dengan sesi terpisah dan menjalankan alat dari USB bukti. Perhatikan baris 10:20:28 di `LAB-WS02` yang jatuh tiga detik sebelum 10:20:31 di `LAB-WS01`: urutan sumber lalu tujuan, dalam batas selisih jam kedua VM yang dicatat di langkah 1. Di snapshot audit bawaan (Bagian D), baris Sysmon, 4698, dan 106 hilang; yang tersisa untuk task adalah XML dan TaskCache, untuk loader adalah `$J`, `$MFT`, dan Prefetch, dan untuk RDP tetap ada 4624 type 10 dan channel RDP.

</details>

**Hasil yang sebaiknya tersimpan:**

- Case notes `CASE-2026-LAB-012` dengan inventaris versi, konteks waktu kedua VM, jam setiap aktivitas tiga pelaku, dan keputusan koleksi.
- Master, salinan kerja, dan hash keduanya; copylog KAPE.
- CSV semua parser di `analysis\K1\EZ-<versi>\` dan hasil parse sisi sumber `LAB-WS02`.
- Jawaban tujuh pertanyaan mini-kasus, masing-masing dengan artefak, nilai, waktu UTC dan WIB, pelaku, dan satu kalimat keterbatasan.
- Timeline gabungan dengan kolom UTC, WIB, Sumber, Kejadian, dan Pelaku.
- Tabel "apa yang hilang" dari snapshot audit bawaan dan daftar entri USB yang hanya muncul dengan replay transaction log.
- Lembar batas bukti kasus lab, ditambah catatan kalimat yang berhasil "lolos" saat diuji orang lain dan perbaikannya.

### Bagian F: latihan skenario dengan pembahasan

Tulis kalimat temuanmu sebelum membuka pembahasan. Kalimat temuan yang baik menyebut artefak, nilai, waktu dengan zona, dan batas klaimnya.

**Skenario 1.** Analyst junior menulis: "`dumper.exe` dijalankan pada 2026-03-14 08:12 karena ada di Shimcache dengan waktu itu." Apa yang salah dan bagaimana memperbaikinya?

<details><summary>Pembahasan</summary>

Dua kesalahan. Shimcache tidak membuktikan eksekusi, dan waktu di Shimcache adalah last modified file, bukan waktu run. Kalimat yang bisa dipertahankan: "File `dumper.exe` di path X dikenal sistem (Shimcache) dengan last modified 2026-03-14 08:12 UTC." Lalu cari bukti eksekusi: Prefetch, BAM untuk akun, Amcache untuk SHA-1 identifikasi (ingat batas 30 MiB), dan 4688 atau Sysmon 1 bila tersedia. Bila tidak ada satu pun, nyatakan bahwa eksekusi tidak dapat dibuktikan dari artefak yang tersedia, bukan bahwa program tidak dijalankan.

</details>

**Skenario 2.** File `Laporan-Keuangan-Q3.docx` di share `\\JKT-FS01\Keuangan` punya SI Created 2019-06-01, FN Created 2026-10-02 10:05, dan `$J` `FileCreate` 2026-10-02 10:05. Apakah ini timestomping?

<details><summary>Pembahasan</summary>

Belum tentu. File yang disalin dengan alat yang mempertahankan timestamp, atau hasil ekstraksi arsip, juga bisa punya SI lama dan FN baru. Bedakan dengan konteks: dokumen yang memang dibuat 2019 lalu dipindah ke share ini wajar; executable di `AppData` dengan SI 2019 dan FN kemarin tanpa alasan bisnis lebih mencurigakan. Periksa juga `BasicInfoChange` setelah `FileCreate`, subdetik SI, sumber file (LNK dan ShellBags ke lokasi asal di workstation yang menyalin), dan jejak alat timestomp di artefak eksekusi. Kalimat temuan menyebut ketidaksesuaian SI dan FN sebagai indikasi, lalu korroborasinya.

</details>

**Skenario 3.** Kamu harus membuktikan karyawan menyalin dokumen ke USB. Yang kamu punya: USBSTOR SanDisk, `MountPoints2` di NTUSER karyawan, ShellBags ke `E:\backup`, dan LNK ke `E:\backup\kontrak.pdf`. Apa yang sudah terbukti dan apa yang belum?

<details><summary>Pembahasan</summary>

Terbukti: perangkat SanDisk pernah tersambung, sebuah volume di-mount di sesi karyawan, `E:\backup` dilihat lewat Explorer di profil karyawan, dan `kontrak.pdf` dibuka lewat shell dari `E:`. Belum terbukti: bahwa `E:` saat itu adalah SanDisk yang sama (butuh jembatan nomor seri volume di LNK ke perangkat lewat event 1006 atau EMDMgmt, ditambah MountedDevices), bahwa karyawan sendiri yang memegang perangkat (`MountPoints2` menunjuk sesi, bukan orang), dan bahwa file disalin dari host ke USB. Untuk penyalinan, cari jejak di sisi sumber (`$J` dan LNK file asal di share atau disk lokal pada waktu berdekatan, Jump List Explorer) dan, bila perangkat USB berhasil diperoleh, `$MFT` di volume USB yang menunjukkan kapan `kontrak.pdf` dibuat di sana.

</details>

**Skenario 4.** Di sebuah server, ada 7045 untuk service `WinUpdSvc` dengan ImagePath `C:\ProgramData\wu\svc.exe`, tetapi key service sudah tidak ada di registry dan file `svc.exe` tidak ada di disk. Apa yang bisa kamu tetapkan?

<details><summary>Pembahasan</summary>

Event 7045 membuktikan service itu pernah dipasang pada waktu event, dengan nama dan path tersebut; akun pemasang tidak ada di 7045 dan dicari di 4697 bila Audit Security System Extension aktif. Ketiadaan key dan file menunjukkan pembersihan setelahnya. Cari record `FileDelete` `svc.exe` dan pembuatan folder `wu` di `$J`, entry `$MFT` yang mungkin belum dipakai ulang, Amcache untuk SHA-1, Prefetch `SVC.EXE-*.pf`, 7036 untuk start dan stop service, serta VSS bila ada. SHA-1 di Amcache adalah jalan untuk identifikasi biner meski file hilang, dan untuk mencari file yang sama di host lain lewat hunt.

</details>

**Skenario 5.** Di `JKT-JUMP01`, NTUSER `adm.rina` berisi `Terminal Server Client\Default` `MRU0` `JKT-FS01` dan ada Prefetch `PSEXEC.EXE` dengan run terakhir 2026-10-02 10:04 UTC. Di `JKT-FS01` ada 4624 type 3 dari `JKT-JUMP01` pada 10:04 dan 7045 `PSEXESVC` pada 10:04. Bagaimana kamu menuliskan arah pergerakan?

<details><summary>Pembahasan</summary>

`JKT-JUMP01` adalah sumber dan `JKT-FS01` adalah tujuan. Bukti sisi sumber: Prefetch PsExec dan MRU RDP ke `JKT-FS01` di profil `adm.rina`. Bukti sisi tujuan: logon jaringan dari `JKT-JUMP01` dan service `PSEXESVC` pada menit yang sama. Kalimat temuan menyebut keempat artefak dan waktunya, lalu menyatakan batas: artefak ini membuktikan pemakaian alat remote dari `JKT-JUMP01` ke `JKT-FS01`, bukan bahwa pemakaian itu tidak sah. `adm.rina` memang akun admin yang hanya login dari `JKT-JUMP01`; cek tiket change dan jadwal kerja sebelum menyebutnya lateral movement penyerang.

</details>

### Troubleshooting gabungan

Tabel ini memuat masalah yang biasa muncul saat semua artefak minggu ini digabung dalam satu analisis. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Bukti eksekusi lemah | Hanya Shimcache atau Amcache | Cari Prefetch dan BAM; nyatakan keberadaan saja bila tidak ada (Day 07 bagian 1.3) |
| Program jelas berjalan tetapi Shimcache "No" | Flag eksekusi Windows 10/11 heuristik | Abaikan "No"; pakai Prefetch dan BAM (Day 07 bagian 2.4) |
| Shimcache dan SRUM tidak memuat hari terakhir | Host dimatikan paksa atau di-image menyala | Cek cara host dimatikan di case notes (Day 07 bagian 2.1) |
| Waktu file mencurigakan | SI dipalsukan, atau file salinan dan hasil ekstraksi | Bandingkan FN; cari `FileCreate` dan `BasicInfoChange` di `$J` (Day 08 bagian 1.3) |
| "Tidak ada record" di `$J` dipakai untuk menyatakan file tidak dibaca | `$J` tidak punya reason untuk membaca | Tulis "tidak diubah dalam jendela ..."; pembacaan dari 4104, EDR, memori (Day 08 bagian 1.4) |
| Perangkat atau nilai Run terbaru tidak muncul | Hive kotor dibaca tanpa replay | `.LOG1`/`.LOG2` ikut dikoleksi; RECmd tanpa `--nl` atau RLA (Day 09 bagian 2.2) |
| SSD eksternal tidak ada di daftar USB | Perangkat UASP di `Enum\SCSI` | Baca USBSTOR, SCSI, dan USB (Day 09 bagian 2.5) |
| Timeline bergeser tujuh jam di sebagian baris | Kolom waktu lokal (`NetworkList`, `setupapi`) dicampur kolom UTC | Tulis zona per kolom; jangan konversi kolom lokal (Day 09 bagian 1.4) |
| USB tidak tertaut ke pengguna | NTUSER profil tertentu tidak diparse, atau dibaca sebagai pelaku | Parse semua profil di `ProfileList`; `MountPoints2` = sesi (Day 09 bagian 1.5) |
| ShellBags kosong | `UsrClass.dat` tidak dikoleksi | Target `RegistryHivesUser` (Day 10 bagian 2.1) |
| Tidak ada LNK untuk file yang jelas dibuka | Dibuka oleh proses, Recent dibersihkan, atau file dari dalam ZIP | Cek mekanisme dan uji di lab (Day 10 bagian 1.7) |
| Persistence tanpa waktu atau pembuat | Audit registry mati; hanya last write key | FN file payload dan XML, 7045, 106, 4698 (Day 11 bagian 1.1) |
| Persistence tidak terlihat di registry dan task | WMI subscription | Sysmon 19-21 atau parsing `OBJECTS.DATA` offline (Day 11 bagian 1.5) |
| Arah lateral terbalik | MRU klien dibaca sebagai koneksi masuk | MRU = keluar dari host ini; masuk dari 4624 type 10/3 di tujuan (Day 11 bagian 1.3) |
| Driver, akun admin lokal, atau USB asing tanpa penjelasan | Jejak responder yang tidak dicocokkan | Cocokkan dengan case notes, CoC, VSN, dan hash toolkit (bagian 1.9) |
| Peserta rapat mengutip kalimat lebih kuat dari bukti | Laporan tanpa kolom "tidak terbukti" | Lembar batas bukti dengan kalimat boleh dan dilarang (bagian 1.11) |

## 5. Kesalahan umum dan jebakan

Kesalahan berikut muncul di lebih dari satu Day minggu ini; tiap butir menyebut Day asalnya.

- Menyebut Shimcache atau Amcache sebagai bukti eksekusi, atau membaca waktu Shimcache sebagai waktu run (Day 07) [S4][S5].
- Membaca delapan waktu Prefetch sebagai seluruh riwayat, padahal program yang sering berjalan kehilangan waktu lama (Day 07) [S3].
- Menulis "tidak ada aktivitas lain" dari artefak eksekusi, padahal kerja di dalam proses yang sudah berjalan tidak tercatat (Day 07).
- Membaca C di MACB sebagai Created, atau LastAccess lama sebagai "tidak dibuka" (Day 08) [S10].
- Menyimpulkan "tidak dibaca" dari `$J` yang kosong, atau menganggap `$J` mencatat pelaku (Day 08) [S9].
- Menyimpulkan timestomping dari satu tanda, atau menyimpulkan "aman" dari SI = FN (Day 08) [S11].
- Membaca last write time sebagai waktu nilai tertentu ditambahkan (Day 09, Day 10) [S14].
- Membaca hive dari koleksi live tanpa replay transaction log (Day 09) [S13].
- Mencampur kolom waktu lokal dan UTC dalam satu timeline (Day 09) [S15].
- Menyamakan `MountPoints2` dengan orang yang mencolok, atau menganggap registry membuktikan file disalin ke USB (Day 09, Day 10) [S17].
- Mengira ShellBags berarti file dibuka, atau menyimpulkan "tidak ada akses" dari artefak shell yang kosong (Day 10) [S19][S20].
- Menyamakan hands-on-keyboard dengan kerja di desktop (Day 10).
- Mencocokkan nomor seri volume LNK langsung dengan nomor seri USBSTOR (Day 10) [S21].
- Mengandalkan satu artefak atau satu lokasi untuk persistence dan lateral movement, dan melupakan WMI (Day 11) [S25].
- Membaca artefak klien sebagai koneksi masuk (Day 11) [S26].
- Menghitung satu mekanisme yang sama di beberapa host, atau beberapa jalur untuk satu payload, sebagai beberapa ancaman (Day 11).
- Melaporkan jejak responder sebagai temuan, di laptop mana pun dan di artefak apa pun (Day 07, 09, 10, 11).

## 6. Catatan terkini

Bagian ini mengumpulkan status versi dan dokumen acuan yang dipakai Day 07-11. Tidak mengubah isi review, tetapi berguna saat ditanya "versi mana yang kamu pakai".

- **EZ Tools 2026.5.0** per 2026-10-16: CLI tersedia untuk .NET 4.7.2 dan .NET 9; ShellBags Explorer, JumpList Explorer, Registry Explorer, dan Timeline Explorer hanya .NET 9 [S1]. Nama kolom CSV dan banner versi di README masing-masing alat bisa berbeda dari nomor paket.
- **RECmd:** batch komprehensif bernama `DFIRBatch.reb` (sebelumnya Kroll Batch), v2.22 per 2026-10-16. Dokumentasi atau perintah lama yang menyebut nama batch lama perlu disesuaikan dengan nama file di folder `BatchExamples` instalasi-mu.
- **Prefetch:** dokumentasi format libscca revisi 0.0.24 (Juli 2026) mencantumkan versi format 31 untuk Windows 11, dikompresi seperti versi 30 [S3].
- **Shimcache:** flag eksekusi Windows 10/11 dibaca AppCompatCacheParser sejak Maret 2023; dokumentasi sebelum itu masih menulis Windows 10 tidak punya indikator eksekusi [S5].
- **PCA Windows 11:** belum ada dokumentasi Microsoft untuk format file; sumber praktisi tidak sepakat soal encoding [S8].
- **[MS-SHLLINK]** revisi 10.0 terbit 2025-11-21 [S21]. Halaman `SHAddToRecentDocs` diperbarui 2025-07-01 [S19].
- **Windows 11 23H2** (build 22631) dijadwalkan berakhir layanannya untuk edisi Enterprise dan Education pada 2026-11-10; nilai `ProductName` di registry tetap menulis Windows 10, jadi versi OS dibaca dari `CurrentBuild` dan `DisplayVersion` (Day 09 bagian 2.3).
- **WMI-Activity 5861** dipetakan map EvtxECmd sebagai registrasi permanent event consumer; halaman Microsoft khusus event itu belum diperoleh, jadi maknanya dibuktikan di lab (Day 11 bagian 1.5).
- Super-timeline (Day 13) menyatukan semua artefak minggu ini; Day 14 sampai 16 menambah memori, yang menjawab sebagian besar baris "tidak terbukti" di bagian 1.8.

## 7. Cheat sheet

```
PRINSIP    siapa MENULIS artefak ini, dan apa yang TIDAK PERNAH ia lihat? -> batas kalimat temuan
EKSEKUSI   Prefetch (run, 8 waktu + .pf created, volume) | BAM (SID, terakhir) | UserAssist (Explorer)
           Amcache/Shimcache = ADA, bukan run (Shim: mtime, ditulis saat shutdown; "No" = tidak berarti)
           SRUM (byte/app/jam, tanpa tujuan) | PCA (GUI saja) | kerja DI DALAM proses = tidak tercatat
FILESYSTEM $MFT keadaan (SI vs FN) | $J perubahan, TANPA baca, TANPA pelaku, dalam jendela | Recycle Bin per SID
           MACB: C = entry berubah ; LastAccess sering mati (NtfsDisableLastAccessUpdate)
REGISTRY   last write per KEY (UTC) ; hive live -> .LOG1/.LOG2 + replay ; Select\Current
           UTC: last write, 0064-0067, SAM ; LOKAL: NetworkList, setupapi.dev.log
           USB: USBSTOR + SCSI + USB ; 0065 first ; MountPoints2 = sesi, bukan orang ; bukan "file disalin"
           autostart: Run (mesin + tiap profil), Winlogon, IFEO, Services, TaskCache (Tree tanpa SD)
SHELL      TypedPaths diketik | ShellBags dilihat | LNK/JL/RecentDocs/OpenSave dibuka | WordWheel dicari
           ditulis ANTARMUKA ; skrip dan operator lewat C2 tidak tercatat ; waktu ShellBags = inferensi
PERGERAKAN tujuan: 4624 type3/10, 1149, LSM 21, 7045, 5145 | sumber: MRU RDP, Prefetch alat, 4648
           metode = kombinasi ; WMI tanpa service ; persistence bisa di WMI (Sysmon 19-21, OBJECTS.DATA)
PELAKU     pengguna | penyerang | responder ; >= 2 jangkar: catatan saat itu + akun/SID + VSN/media + hash
LEMBAR     per host: TERBUKTI (sumber, jendela, keyakinan) | TIDAK (sumber yang bisa) | BOLEH | JANGAN | TERBUKA
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "`$J` E15 tidak punya record untuk `export-tagihan.ps1`, ShellBags Documents di profil Andi tidak berubah malam itu, dan tidak ada LNK untuk skrip itu. Tiga sumber sepakat, jadi penyerang tidak menyentuh `export-tagihan.ps1`." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Ketiga sumber itu tidak pernah melihat pembacaan oleh skrip: `$J` hanya mencatat perubahan, dan ShellBags serta LNK ditulis antarmuka, bukan oleh PowerShell yang membaca file lewat API. Tiga sumber yang sama-sama buta terhadap satu jenis kejadian tidak saling menguatkan untuk kejadian itu. Event 4104 mencatat `upd.ps1` membaca isi skrip itu Senin 23:40:17. Yang benar: file tidak diubah, dipindah, atau dihapus dalam jendela `$J`, dan dibuka bukan lewat Explorer, tetapi dibaca skrip penyerang. Lihat bagian 1.2, 1.4, dan 1.8.

</details>

**2. Skenario keputusan.** Di PIR, seorang peserta mengusulkan kalimat untuk laporan: "Laptop Dewi hanya digunakan penyerang untuk beacon dan enumerasi dasar." Kalimat mana yang tepat dipakai?

- A. Kalimat itu dipakai apa adanya, karena memo retainer dan artefak eksekusi sepakat.
- B. "Artefak eksekusi di `BDG-WS-0142` menunjukkan `wscript.exe`, `powershell.exe`, dan enumerasi `whoami`, `systeminfo`, `ipconfig`, `net` di bawah akun Dewi; tidak ditemukan executable penyerang lain di artefak yang diperiksa. Aktivitas di dalam proses PowerShell tidak tercatat di artefak ini, sehingga cakupan penuh bergantung pada memori E08 dan log jaringan."
- C. "Penyerang menjalankan program yang tercatat di Amcache dan Shimcache laptop Dewi."

<details><summary>Jawaban</summary>

B. Artefak eksekusi hanya melihat proses baru, sehingga hasilnya adalah batas bawah; kalimat yang benar menyebut apa yang ditemukan, cakupannya, dan sumber yang masih bisa menambah. A keliru karena "hanya" mengubah batas bawah menjadi daftar lengkap. C keliru karena Amcache dan Shimcache membuktikan keberadaan, dan sebagian entrinya adalah alat responder dari `USB-E-09`. Lihat bagian 1.1 dan 1.8.

</details>

**3. Pertanyaan jebakan.** "`USB-E-10` ada di `MountPoints2` milik Rizky, dan BAM di laptop Dewi mencatat WinPmem di bawah SID dengan RID 1003. Keduanya aktivitas pemilik laptop atau penyerang yang menumpang akunnya." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Keduanya jejak responder. `USB-E-10` di-mount di sesi Rizky karena Yoga memakai sesi yang masih terbuka untuk mengambil memori, dan `MountPoints2` menunjuk sesi, bukan orang; dasar pemisahannya case notes, label, VSN, dan waktu. RID 1003 dengan awalan SID mesin adalah akun admin lokal khusus IR yang dipakai Fajar, bukan SID domain Dewi; dasar pemisahannya panduan telepon, CoC E08, nomor seri volume `USB-E-09`, dan SHA-1 toolkit. Lihat bagian 1.3, 1.1, dan 1.9.

</details>

**4. Skenario keputusan.** Saat menyusun lembar PIR, Yoga mengusulkan baris "Startup folder dan WMI di `JKT-WS-0412`: tidak ada persistence lain", dengan alasan registry sudah bersih. Mana yang tepat?

- A. Setujui, karena autostart registry sudah diperiksa lengkap.
- B. Tulis "belum diperiksa" untuk folder Startup dan WMI di `E16-W1`, masukkan ke baris pekerjaan terbuka, dan bila diperiksa, gunakan `$MFT` untuk folder Startup dan parsing `OBJECTS.DATA` untuk WMI, karena laptop itu tanpa Sysmon.
- C. Tulis "tidak ditemukan", karena hunt di enam penerima lain juga tidak menemukan apa pun.

<details><summary>Jawaban</summary>

B. Folder Startup dan WMI subscription tidak tersimpan di registry, jadi registry yang bersih tidak berkata apa pun tentang keduanya. Di laptop tanpa Sysmon, `OBJECTS.DATA` adalah satu-satunya sumber untuk WMI, seperti pelajaran dari `JKT-WS-0457`. A keliru karena menulis "tidak ada" untuk lokasi yang tidak diperiksa. C keliru karena hasil hunt di host lain tidak berlaku untuk host ini. Lihat bagian 1.3, 1.8, dan 1.10.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Nina Kartika, fasilitator PIR, dalam tiga kalimat, kenapa lembar batas bukti memuat kolom "tidak terbukti" dan "kalimat yang dilarang", bukan hanya daftar temuan.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Setiap catatan di laptop ditulis oleh bagian Windows yang berbeda, dan masing-masing hanya melihat sebagian kejadian, misalnya catatan perubahan file tidak pernah mencatat file yang dibaca. Kalau lembar hanya berisi temuan, peserta akan membaca hal yang tidak disebut sebagai hal yang tidak terjadi, padahal sebagian memang tidak pernah bisa tercatat di laptop itu. Karena itu kami menulis batasnya dan kalimat yang sudah hampir terucap selama kasus, supaya keputusan di rapat ini, termasuk soal data pribadi, tidak lebih kuat dari buktinya."

Kesalahan yang sering muncul:
- Menjelaskan nama artefak dan alat, padahal fasilitator butuh alasan bentuk dokumennya.
- Tidak menyebut contoh konkret dari kasus ini.
- Lupa menyebut dampaknya ke keputusan yang diambil di PIR.

</details>

**6. Pertanyaan jebakan.** "Task `\SysCacheUpdate` ditemukan di tiga laptop, jadi PIR mencatat tiga mekanisme persistence yang harus ditangani terpisah." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Itu satu mekanisme persistence yang sama, dipasang loader yang sama di tiga host. Pelajaran dari `INC-2026-017` berlaku: beberapa jalur yang menunjuk payload yang sama ditulis sebagai satu payload, bukan beberapa ancaman, dan satu mekanisme di beberapa host ditulis sebagai satu mekanisme dengan daftar host. Yang berbeda per host adalah sumber yang membuktikannya (4698 dan Sysmon di laptop Andi; XML, TaskCache, dan `$MFT` di laptop Rizky; Prefetch dan run count di laptop Dewi) dan keyakinannya. Lihat bagian 1.8 dan 1.10.

</details>

**7. Interview question (English).** "You're preparing for a post-incident review with non-technical stakeholders. How do you present what host forensic artifacts prove and don't prove, especially for hosts without EDR?"

<details><summary>Sample answer</summary>

"I start from who writes each artifact and what it never sees, because that defines the ceiling of every sentence. Prefetch and BAM prove a program started but not its arguments or what ran inside an existing PowerShell process; the USN journal proves changes but never reads; registry keeps last state and first or last times, not history; shell artifacts like ShellBags and LNK files only record work done through the GUI, not scripts. For each host I write one sheet: what's proven, from which sources, in what time window and with what confidence; what isn't proven and which source could answer it, such as memory or network logs; the exact sentences people may and may not use; and our own responder activity, labelled with the case notes, accounts, USB volume serials and tool hashes that tie it to us. On hosts without EDR or full audit, I lower confidence explicitly and say 'not recorded on this host' instead of 'didn't happen'. That keeps the review from turning a lower bound into a complete story, which matters most when the outcome is a data protection decision."

What makes this answer strong: it grounds every claim in how the artifact is written, separates proven from unproven with the source that could close the gap, treats responder activity as part of the evidence, and connects the limits to the decision the review has to make.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Eric Zimmerman tools (EZ Tools, Get-ZimmermanTools) | https://ericzimmerman.github.io/ | primer | diakses 2026-10-09, dicek ulang 2026-10-16 | Tinggi. Versi 2026.5.0; CLI .NET 4.7.2 dan .NET 9, GUI hanya .NET 9 |
| S2 | SANS: Windows Forensic Analysis poster | https://www.sans.org/posters/windows-forensic-analysis/ | sekunder (SANS) | diakses 2026-10-09, dicek ulang 2026-10-16 | Sedang-tinggi. Makna artefak eksekusi, file system, registry, dan aktivitas pengguna; tiga tingkat bukti (diketik, dilihat, dibuka). Isi poster di balik login |
| S3 | libscca: Windows Prefetch File (PF) format | https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc | primer (spesifikasi hasil reverse engineering) | revisi 0.0.24, Juli 2026; diakses 2026-10-16 | Tinggi. Versi format 17/23/26/30/31, delapan waktu run, hash nama file dari path, kompresi MAM, informasi volume |
| S4 | Kaspersky Securelist: Forensic journey, hunting evil within AmCache | https://securelist.com/amcache-forensic-artifact/117622/ | sekunder (peneliti vendor) | 2025-10-01; diakses 2026-10-16 | Sedang-tinggi. Key Inventory*, makna eksekusi per key, SHA-1 atas 31.457.280 byte pertama |
| S5 | nullsec.us: AppCompatCache Deep Dive | https://nullsec.us/windows-10-11-appcompatcache-deep-dive/ | sekunder (praktisi) | 2024-08-21; diakses 2026-10-16 | Sedang-tinggi. Flag eksekusi empat byte terakhir, dukungan parser sejak Maret 2023, pengujian Windows 11 23H2 |
| S6 | Velociraptor artifact: Windows.Forensics.Bam | https://docs.velociraptor.app/artifact_references/pages/windows.forensics.bam | primer | diakses 2026-10-16 | Tinggi. Dua path key BAM, Windows 10 1709 ke atas, output SID dan waktu |
| S7 | Magnet Forensics: SRUM forensic analysis | https://www.magnetforensics.com/blog/srum-forensic-analysis-of-windows-system-resource-utilization-monitor/ | sekunder (vendor alat) | 2022-10-05; diakses 2026-10-16 | Sedang. Byte per aplikasi dan SID, penulisan tiap jam dan saat shutdown, batas atribusi |
| S8 | Sygnia: Diving into the new Windows 11 PCA artifact | https://www.sygnia.co/?p=133 | sekunder (peneliti) | 2023-11-15; diakses 2026-10-09, dicek ulang 2026-10-16 | Sedang-tinggi. Lokasi, isi, cakupan peluncuran GUI; berbasis pengujian, bukan dokumentasi Microsoft |
| S9 | Microsoft Learn: USN_RECORD_V2 structure (winioctl.h) | https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2 | primer (dokumentasi vendor) | ms.date 2018-12-05; diakses 2026-10-16 | Tinggi. Field record, daftar reason, definisi `BASIC_INFO_CHANGE`, `SecurityId` milik file |
| S10 | Microsoft Learn: fsutil behavior | https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-behavior | primer (dokumentasi vendor) | diperbarui 2026-02-16; diakses 2026-10-16 | Tinggi. `disablelastaccess`, registry `NtfsDisableLastAccessUpdate`, penundaan maksimal 1 jam |
| S11 | Inversecos: Defence Evasion Technique: Timestomping Detection, NTFS Forensics | https://inversecos.com/2022/04/defence-evasion-technique-timestomping.html | sekunder (blog praktisi) | 2022-04-28 (>3 tahun); diakses 2026-10-16 | Sedang-tinggi. SI vs FN, FN mewarisi SI setelah move atau rename, `$J` dan `$LogFile` untuk deteksi |
| S12 | RBCmd README (GitHub) | https://github.com/EricZimmerman/RBCmd | primer (repo resmi) | diakses 2026-10-16 | Tinggi. `$I` format 1 dan 2, INFO2, isi folder `$R`, waktu UTC |
| S13 | Windows registry file format specification (msuhanov/regf) | https://raw.githubusercontent.com/msuhanov/regf/master/Windows%20registry%20file%20format%20specification.md | primer (spesifikasi hasil reverse engineering) | diakses 2026-10-16 | Tinggi. Hive kotor, format log baru sejak Windows 8.1, penundaan tulis hingga sekitar satu jam, last written timestamp di key node, value tanpa timestamp |
| S14 | Microsoft Learn: RegQueryInfoKeyW | https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeyw | primer | ms.date 2018-12-05, diperbarui 2026-05-15; diakses 2026-10-16 | Tinggi. Last write time = terakhir key atau salah satu nilainya diubah |
| S15 | RegistryPlugin.KnownNetworks (KnownNetworks.cs) | https://raw.githubusercontent.com/EricZimmerman/RegistryPlugins/master/RegistryPlugin.KnownNetworks/KnownNetworks.cs | primer (kode sumber plugin) | diakses 2026-10-16 | Tinggi. Profiles dan Signatures; SYSTEMTIME tanpa konversi, ditampilkan sebagai waktu lokal |
| S16 | Microsoft Learn: DEVPKEY_Device_FirstInstallDate | https://learn.microsoft.com/en-us/windows-hardware/drivers/install/devpkey-device-firstinstalldate | primer | ms.date 2022-06-23; diakses 2026-10-16 | Tinggi. Waktu pertama di-install; tidak berubah oleh pembaruan driver |
| S17 | IT-Connect: Forensic Windows Part 15, Tracing USB Device History | https://www.it-connect.tech/forensic-windows-part-15-tracing-usb-device-history/ | sekunder (praktisi) | 2026-10-09; diakses 2026-10-16 | Sedang. Rantai MountPoints2, MountedDevices, USBSTOR, setupapi; MountPoints2 bukan bukti pencolok; registry hanya koneksi terakhir |
| S18 | Microsoft Learn: 4616(S) The system time was changed | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616 | primer (arsip) | ms.date 2021-09-07; diakses 2026-10-16 | Tinggi. Selalu dicatat terlepas dari subcategory; PreviousTime dan NewTime UTC |
| S19 | Microsoft Learn: SHAddToRecentDocs function (shlobj_core.h) | https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shaddtorecentdocs | primer | ms.date 2018-12-05, diperbarui 2025-07-01; diakses 2026-10-16 | Tinggi. Recent dan Jump List; dipanggil shell untuk Explorer dan dialog umum; `.exe` disaring; `NoRecentDocs` default |
| S20 | Cyber Triage: ShellBags Forensic Analysis 2026 | https://www.cybertriage.com/blog/shellbags-forensic-analysis-2026/ | sekunder (vendor DFIR) | 2025-03-21, ditinjau 2026; diakses 2026-10-16 | Sedang-tinggi. Lokasi per hive, apa yang dibuktikan dan tidak, timestamp sebagai inferensi, navigasi lewat command line tidak tercatat |
| S21 | [MS-SHLLINK] VolumeID | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/b7b3eea7-dbff-4275-bd58-83ba3f12d87a | primer | 2025-06-10; diakses 2026-10-16 | Tinggi. `DriveType`, `DriveSerialNumber`, label volume tempat target berada saat link dibuat |
| S22 | Mandiant: The Missing LNK: Correlating User Search LNK Files | https://cloud.google.com/blog/topics/threat-intelligence/the-missing-lnk-correlating-user-search-lnk-files | sekunder (vendor IR) | 2020-02-19 (lebih dari 3 tahun); diakses 2026-10-16 | Sedang-tinggi. Search LNK, korelasi dengan WordWheelQuery dan `MRUListEx` |
| S23 | Microsoft Learn: 4698(S) A scheduled task was created | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698 | primer | ms.date 2021-09-07; diakses 2026-10-16 | Tinggi. Task Content XML, field 1903 (ClientProcessId, ParentProcessId) |
| S24 | JPCERT/CC: Tool Analysis Result Sheet (PsExec, wmic, WinRM, mstsc, schtasks) | https://jpcertcc.github.io/ToolAnalysisResultSheet/ | sekunder (CERT) | diakses 2026-10-16 | Tinggi. Jejak sumber dan tujuan per alat; OS uji tidak selalu disebut |
| S25 | Microsoft Learn: Receiving Events at All Times (permanent event consumer) | https://learn.microsoft.com/en-us/windows/win32/wmisdk/receiving-events-at-all-times | primer | ms.date 2018-05-31; diakses 2026-10-16 | Tinggi. Tiga komponen (__EventFilter, consumer, __FilterToConsumerBinding) |
| S26 | Microsoft Learn: Remove entries from Remote Desktop Connection Computer box | https://learn.microsoft.com/en-us/troubleshoot/windows-server/remote/remove-entries-from-remote-desktop-connection-computer | primer | ms.date 2026-02-12; diakses 2026-10-16 | Tinggi. `HKCU\...\Terminal Server Client\Default` nilai MRU, FQDN atau IP tujuan RDP |
| S27 | Elcomsoft: USB Device Forensics on Windows 10 and 11 | https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/ | sekunder (vendor forensik) | 2026-02-25; diakses 2026-10-16 | Sedang-tinggi. Partition/Diagnostic 1006 dan offset VSN, bukti perangkat bukan transfer file |
| S28 | Microsoft Learn: Run and RunOnce Registry Keys | https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys | primer | ms.date 2024-07-19; diakses 2026-10-16 | Tinggi. Empat key Run/RunOnce, perilaku RunOnce, urutan tak tentu |
| S29 | Microsoft Security Blog: Tarrask malware uses scheduled tasks for defense evasion | https://www.microsoft.com/en-us/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/ | primer (vendor) | 2022-04-12 (>3 tahun); diakses 2026-10-16 | Tinggi. TaskCache `Tree` (`Id`, `Index`, `SD`) dan `Tasks\{GUID}`, task tersembunyi tanpa `SD` |
| S30 | Microsoft Learn: 4624(S) An account was successfully logged on | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624 | primer | ms.date 2021-09-07; diakses 2026-10-16 | Tinggi. Logon type 3 dan 10, field Network Information |

**Catatan sumber:** Day ini tidak memakai sumber baru; setiap klaim berasal dari Day 07-11 dan sumber yang sama dirujuk ulang dengan nomor baru. Hal yang masih perlu dicek mengikuti catatan di Day asalnya, terutama perilaku shell untuk file yang dibuka dari dalam ZIP, apakah waktu BAM mencatat awal atau akhir proses, perilaku flag eksekusi Shimcache untuk binary bawaan, perilaku perangkat UASP di `Enum\SCSI`, kode `NameType` NetworkList, ID event WLAN sukses sambung dan putus, pembaruan last write `Tasks\{GUID}` saat task berjalan, efek elevasi UAC terhadap SAM, dan makna WMI-Activity 5861. Peta konsep di bagian 1.6, tiga benang di bagian 1.8 sampai 1.10, lembar batas bukti di bagian 1.11, dan glosarium adalah susunan catatan ini, bukan model resmi salah satu sumber. Pembahasan skenario di bagian 2-4 adalah penalaran praktik umum dengan data fiktif. Semua isi PT JAB, termasuk waktu, nomor bukti, nomor seri volume, SID, SSID, nama file di folder kasus, isi lembar PIR, dan timeline lab, adalah contoh fiktif.
