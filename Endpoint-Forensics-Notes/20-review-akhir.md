---
day: 20
title: 'Review akhir: peta kemampuan forensik endpoint, tabel artefak master, celah telemetri yang berulang, glosarium, latihan skenario, dan rencana memperkuat kelemahan'
researched_on: 2026-10-22
versions_checked: 'Merangkum Day 01-19. Volatility 3 2.28.2 (17 Sep 2026, masih rilis stabil terbaru per 2026-10-22); Plaso 20260720 (rilis stabil terbaru, 20260928 masih pre-release); Velociraptor 0.77.3 (5 Okt 2026); Timesketch 20261014; EZ Tools 2026.5.0 (.NET 9 bawaan, sebagian CLI .NET 4.7.2); Microsoft Defender for Endpoint live response (ms.date 2026-07-28; getfile 3 GB, putfile 300 MB, run dan getfile 30 menit); NIST SP 800-61 Rev. 3 (April 2025, ID.IM-01 sampai ID.IM-04); NIST SP 800-86 (2006); RFC 3227 (2002); NIST CFReDS'
---

# Day 20: Review akhir (peta kemampuan forensik endpoint, tabel artefak master, celah telemetri, glosarium, latihan skenario, dan rencana memperkuat kelemahan)

Cakupan: ringkasan Day 01-19 sebagai satu peta kemampuan forensik endpoint, tabel artefak master dari pertanyaan investigasi ke artefak, keterbatasan, dan telemetri yang harus ada sebelum insiden, pembacaan ulang empat kasus PT JAB untuk memisahkan pekerjaan internal dari pekerjaan retainer dan menemukan celah yang berulang, glosarium, lab gabungan, latihan skenario dengan pembahasan, cara menilai kesiapan, rencana memperkuat kelemahan, dan posisi Day 21-26.

## Ide inti

Kemampuan forensik endpoint bukan daftar alat yang dikuasai, melainkan daftar pertanyaan investigasi yang bisa dijawab, sampai batas tertentu, oleh orang tertentu, di host dengan telemetri tertentu. Pertanyaan "proses apa yang membuat scheduled task ini" bisa dijawab dengan keyakinan tinggi di laptop yang mencatat 4698 dan Sysmon, hanya bisa dijawab sebagian di laptop yang tidak mencatatnya, dan sama sekali tidak bisa dijawab bila task sudah dihapus dan disk sudah di-reimage. Analyst yang sama, dengan alat yang sama, menghasilkan kalimat temuan yang berbeda kekuatannya. Karena itu peta kemampuan selalu punya dua sumbu: kemampuan orang (apa yang tim bisa kerjakan sendiri dan apa yang masih butuh retainer) dan kemampuan lingkungan (sumber apa yang memang ada di host dan berapa lama ia disimpan). Sumbu kedua punya sifat yang paling sering dilupakan saat menyusun anggaran: telemetri tidak bisa ditambahkan mundur. Audit policy yang dipasang besok tidak mencatat insiden kemarin. Celah yang muncul berulang di beberapa kasus adalah bahan rencana yang paling berharga, karena ia menunjuk tempat di mana jawaban akan tetap lemah di kasus berikutnya, sepandai apa pun analyst-nya.

Kamu sudah mengenal pola ini dari NOC. Setiap tahun manajer NOC menyusun matriks kemampuan: jenis gangguan apa yang bisa ditangani engineer L2 sendiri, mana yang harus dieskalasi ke TAC vendor, dan mana yang tidak bisa didiagnosis sama sekali karena perangkatnya tidak dikonfigurasi mengirim syslog, NetFlow tidak diaktifkan di link itu, atau buffer log-nya terlalu kecil. Matriks itu disusun dari RFO gangguan tahun lalu, bukan dari brosur perangkat. Engineer berpengalaman tahu bahwa membeli lisensi TAC yang lebih mahal tidak menolong bila router yang bermasalah tidak menyimpan log sebelum crash. Peta kemampuan forensik dibaca dengan cara yang sama. Batasnya ada di dua tempat. Pertama, retainer forensik bukan TAC yang bisa melihat ke dalam perangkat dari jauh: ia hanya bisa bekerja dengan bukti yang sempat diambil dan telemetri yang sempat dicatat. Kedua, "bisa dikerjakan internal" tidak berarti "selalu dikerjakan internal": kasus yang naik ke proses hukum, insiden SEV-1 dengan banyak host sekaligus, atau platform yang belum pernah dilatih tetap punya alasan sendiri untuk memanggil pihak luar.

```
PERTANYAAN INVESTIGASI (dari IC, TL, DPO, HR, Legal)
        |
        v
ARTEFAK MANA yang menjawabnya?            tabel master (bagian 1.8)
        |
        v
APA YANG TIDAK PERNAH IA LIHAT?           keterbatasan per artefak (Day 05-18)
        |
        v
ADA DI HOST INI?  ----- tidak ----->      CELAH LINGKUNGAN: audit, Sysmon, EDR, retensi
        |                                 (tidak bisa ditambah mundur; bagian 1.11)
        ya
        v
SIAPA YANG MENGERJAKAN?                   internal | internal dengan syarat | retainer (bagian 1.10)
        |
        v
KALIMAT TEMUAN + keyakinan + batas        (Day 19)
        |
        v
RENCANA: latih orangnya (Bagian G, H) | perbaiki lingkungannya (bagian 1.13)
```

Situasi yang dipakai di Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan dan data pribadi sekitar 400 ribu pelanggan broadband di sistem billing. PT JAB tidak punya tim IR khusus; insiden ditangani analyst SOC yang ditarik masuk, dengan retainer DFIR PT Forensik Digital Contoh untuk pekerjaan di luar kemampuan internal. Kamu adalah analyst L2 yang memegang forensik endpoint, bersama Yoga Pratama (L2, pemegang bukti), Sari Kusuma (technical lead), dan Rudi Hartanto (L2). Dalam tiga bulan terakhir tim menangani empat kasus dengan kemampuan forensik internal:

- `INC-2026-019` (Oktober 2026): lampiran `Tagihan-Okt-2026.zip` dijalankan di tiga laptop staf penagihan, persistence scheduled task `\SysCacheUpdate`, password akun service `svc_billing` dibaca dari skrip dan dipakai untuk SSH ke `jkt-billing01`. Tiga laptop punya tiga profil telemetri yang berbeda (Day 01-15).
- `INC-2026-017` (Oktober 2026, SEV-1): ransomware share `Keuangan` di `JKT-FS01`, rantai lateral movement dari `jkt-dmz-app01` ke `JKT-WS-0441` lalu `JKT-WS-0457`, exfil sekitar 6 GB yang proses pengirimnya tidak teridentifikasi (Day 11 dan 16).
- `INC-2026-026` (Desember 2026, SEV-2): installer palsu dengan DLL side-loading `version.dll` di `BDG-WS-0163` yang berjalan tiga hari tanpa alert, memori diambil lewat live response (Day 18).
- `INC-2027-010` (Januari 2027, SEV-3): dugaan pencurian data harga kontrak oleh karyawan yang mengundurkan diri, laptop `JKT-WS-0516` (Day 17).

Senin 2027-01-18 Dimas Prasetyo (SOC lead, incident commander) meminta laporan forensik baku untuk dua kasus terakhir (Day 19), dan laporannya sudah diserahkan minggu ini. Jumat 2027-01-22 pukul 09:00, Dimas menulis kepadamu lewat pesan langsung:

> "Pagi. Tiga bulan ini kita pegang empat kasus dengan forensik sendiri: 019, 017, 026, dan 010 kemarin. Saya sedang menyusun rencana kapabilitas SOC 2027 untuk Pak Hendra, rapatnya Kamis 28 Januari. Mulai 1 Februari rotasi on-call forensik dipegang Rudi dan Yudha Prakoso, yang naik dari L1 ke L2 bulan itu; kamu jadi eskalasinya. Saya perlu peta kemampuan forensik endpoint kita: apa yang sekarang bisa kita kerjakan sendiri dan apa yang masih harus ke retainer. Untuk Yudha dan analyst berikutnya, saya mau satu tabel artefak per pertanyaan investigasi yang bisa dibuka jam dua pagi saat on-call. Lalu daftar celah alat dan telemetri yang muncul berulang di empat kasus itu; yang saya ingat: audit dan Sysmon beda antar OU, laptop tanpa EDR, Timesketch belum ada, akuisisi memori lewat live response, dan retensi log. Saya juga butuh latihan skenario untuk Rudi dan Yudha sebelum rotasi, cara menilai siapa sudah siap memegang apa, dan rencana memperkuat kelemahan yang bisa saya bawa ke anggaran, urut prioritas, lengkap dengan pemiliknya. Terakhir, apa yang belum pernah kita hadapi tapi bisa datang tahun ini. Tolong kirim Selasa sebelum jam 12:00."

Pesan itu memuat tujuh pertanyaan:

1. Apa yang kini bisa dikerjakan internal, apa yang bisa dikerjakan internal dengan syarat, dan apa yang masih ke retainer?
2. Untuk satu pertanyaan investigasi, artefak mana yang dibuka dulu, apa batasnya, dan telemetri apa yang harus sudah ada sebelum insiden?
3. Celah alat dan telemetri apa yang muncul berulang di keempat kasus, dan apa akibatnya pada kalimat temuan?
4. Latihan skenario apa untuk Rudi dan Yudha sebelum rotasi?
5. Bagaimana menilai kesiapan, dan siapa boleh memegang apa saat on-call?
6. Rencana memperkuat kelemahan apa untuk 2027, urut prioritas, dengan pemilik dan ukuran selesai?
7. Situasi apa yang belum pernah dihadapi tetapi bisa datang tahun ini?

Pertanyaan 1 dijawab di bagian 1.10, pertanyaan 2 di bagian 1.8, pertanyaan 3 di bagian 1.11, pertanyaan 4 di Bagian G (latihan skenario) dan bagian 1.12, pertanyaan 5 di bagian 1.12 dan Bagian H, pertanyaan 6 di bagian 1.13, dan pertanyaan 7 di bagian 1.14. Bagian 1.1 sampai 1.6 meringkas Day 01-19 sebagai bahannya, bagian 1.7 menyusunnya menjadi peta, bagian 1.9 membaca ulang empat kasus berdampingan, dan Bagian A sampai I sesudahnya memintamu menjalankan satu kasus lab campuran, mengerjakan latihan skenario berwaktu, menilai dirimu sendiri, dan menyusun rencana pribadi.

**Kapan relevan:** setelah menyelesaikan Day 01-19 dan sebelum masuk Day 21-26; saat menyusun rencana kapabilitas, anggaran telemetri, atau lingkup kontrak retainer; saat menyiapkan rotasi on-call dan analyst baru; dan sebelum interview yang menanyakan "apa yang bisa kamu kerjakan sendiri dan di mana batasnya".
**Kapan bukan jawaban:** review ini tidak menambah aturan teknis baru; bila ada yang terasa baru, kembali ke Day asalnya. Peta kemampuan di sini juga bukan penilaian kinerja orang, bukan pengganti kontrak retainer atau keputusan Legal tentang kapan kasus butuh ahli dari luar, dan tidak menjawab topik yang belum dilatih (anti-forensics, disk terenkripsi, Linux dan macOS, browser dan cloud sync, ETW dan Sysmon, korelasi banyak host), yang baru dibahas di Day 21-26.

## 1. Ringkasan, peta konsep, dan glosarium

### 1.1 Day 01-06: keputusan akuisisi, lab, triage, dan event log

Blok pertama membangun rantai bukti: setiap mata rantai menghasilkan bukti atau olahan, dan catatan cakupan yang menjelaskan batasnya (Day 06 bagian 1.6).

- Proses forensik punya empat tahap: collection, examination, analysis, reporting [S1]. Tahap itu tidak terikat satu fase IR; memori bisa diambil sebelum containment dan image setelahnya (Day 01 bagian 1.1).
- Pola akuisisi dipilih per host, bukan per kasus: full disk image, triage collection, atau adaptive collection. Image dibenarkan oleh kemungkinan proses hukum atau regulator, kebutuhan file terhapus, atau host yang akan dihapus (Day 01 bagian 1.2).
- Order of volatility RFC 3227 mengurutkan bukti dari yang paling cepat hilang: register dan cache, tabel routing dan proses serta memori, file system sementara, disk, log jarak jauh, konfigurasi fisik, media arsip [S2]. Isi urutannya disesuaikan dengan pertanyaan yang masih terbuka (Day 01 bagian 1.3).
- Hash membuktikan bukti tidak berubah sejak hash dihitung, bukan bahwa cara pengambilannya benar. Versi minimal yang bisa dipertanggungjawabkan: case notes kronologis dengan zona waktu, chain of custody satu baris per perpindahan, dan penyimpanan dengan kontrol akses (Day 01 bagian 1.4 dan 1.5).
- Workstation analisis (`JKT-DFIR01` Windows 11 dan `jkt-dfir02` Ubuntu LTS) tidak join domain dan tanpa internet kecuali jendela proxy; versi alat diperbarui sebelum kasus, diuji di lab, lalu dibekukan sampai kasus ditutup (Day 02 bagian 1.3).
- KAPE memisahkan Targets (bukti yang di-hash) dari Modules (olahan yang bisa dibuat ulang); copylog membuktikan apa yang benar-benar disalin, dan laporan triage membedakan "ada", "tidak diambil", dan "tidak ditemukan di yang diambil" (Day 03 bagian 1.7).
- Velociraptor menjalankan koleksi yang sama ke banyak host lewat hunt, atau lewat offline collector untuk host yang tidak terjangkau. Hasil negatif yang jujur menyebut apa yang dicari, dengan artifact dan parameter apa, kapan, dan apa yang tidak tercakup (Day 04 bagian 1.7).
- Event log adalah rekaman apa yang host dikonfigurasi untuk dicatat. Profil cakupan (channel, rentang, audit policy, Sysmon, 1102, 104, 4719) dibuat sebelum cerita disusun; ketiadaan event dimulai dari cek konfigurasi (Day 05 bagian 1.5 dan 1.6).
- Di PT JAB, GPO audit `JAB-WS-Audit` hanya terpasang di OU `Workstations-EDR` Jakarta. Laptop yang belum di-onboard tetap di OU lama dengan audit bawaan, sehingga `JKT-WS-0412` tidak punya 4688, 4698, Sysmon, dan history Task Scheduler (Day 05 bagian 2.7).
- Serah terima kasus forensik menyerahkan bukti, catatan cakupan, dan pekerjaan terbuka sekaligus, sehingga penerima bisa melanjutkan tanpa bertanya ke penulisnya (Day 06 bagian 1.11).

### 1.2 Day 07-12: artefak disk

Blok kedua menjawab satu pertanyaan untuk setiap artefak: siapa yang menulisnya, dan apa yang tidak pernah ia lihat (Day 12 bagian 1.6).

- Prefetch membuktikan eksekusi, run count, sampai delapan waktu run, dan volume asal, tetapi tanpa akun dan argumen. Shimcache dan Amcache kuat untuk keberadaan, bukan eksekusi. BAM menambah SID, UserAssist hanya peluncuran lewat Explorer, SRUM memberi byte jaringan per aplikasi per sekitar satu jam tanpa tujuan (Day 07 bagian 1.2 sampai 1.6).
- Artefak eksekusi hanya melihat proses baru. Kerja di dalam proses PowerShell yang sudah berjalan tidak tercatat, sehingga daftar program yang ditemukan adalah batas bawah (Day 07 bagian 1.8).
- `$MFT` menyimpan keadaan terakhir dengan dua set timestamp; `$J` mencatat perubahan dalam jendela terbatas tanpa pembacaan dan tanpa pelaku; Recycle Bin mengikat penghapusan lewat Explorer ke SID (Day 08 bagian 1.1, 1.4, 1.6). SI yang jauh lebih tua dari FN adalah indikasi timestomping, bukan bukti (Day 08 bagian 1.3).
- Registry menyimpan keadaan, bukan riwayat. Hive dari sistem hidup sering kotor dan perubahan terakhirnya ada di transaction log; tanpa replay, jejak menit terakhir hilang (Day 09 bagian 1.2). USB dibaca dari USBSTOR, SCSI, dan USB; `0065` untuk colok pertama; `MountPoints2` menunjuk sesi, bukan orang (Day 09 bagian 1.5).
- Artefak aktivitas pengguna (ShellBags, LNK, Jump List, RecentDocs, TypedPaths) ditulis antarmuka. Skrip dan operator lewat C2 tidak meninggalkan jejak di sana (Day 10 bagian 1.1).
- Lateral movement dibaca dari dua sisi: logon masuk di host tujuan, artefak klien di host sumber. Persistence punya lebih dari satu jejak, dan WMI subscription tidak ada di registry atau task (Day 11 bagian 1.2, 1.3, 1.5).
- Jejak responder dipisahkan dengan minimal dua jangkar: catatan saat tindakan, akun atau SID, media dan nomor seri volume, serta hash toolkit (Day 12 bagian 1.9).
- Lembar batas bukti per host untuk PIR memuat yang terbukti, yang tidak, kalimat yang boleh, kalimat yang dilarang, jejak responder, dan pekerjaan terbuka (Day 12 bagian 1.11).

### 1.3 Day 13: super-timeline

- Super-timeline menaruh event berwaktu dari banyak artefak di satu sumbu UTC. Nilainya ada di urutan lintas artefak dan di celah, bukan di jumlah baris (Day 13 bagian 1.1).
- Preset parser Plaso untuk Windows (`win7`) tidak memuat `mft` dan `esedb`; `win7_slow` harus diminta. Parser yang tidak dipilih tidak muncul, dan tidak ada galat yang memberi tahu (Day 13 bagian 1.2).
- Zona waktu dan jam host adalah dua koreksi yang berbeda. Zona hanya untuk sumber yang menyimpan waktu lokal; selisih jam host (laptop Rizky +2 detik terhadap NOC) dicatat sebagai kolom dan toleransi, bukan dengan menggeser timestamp (Day 13 bagian 1.3).
- Setiap penyaringan adalah keputusan yang dicatat. Di `JKT-WS-0412`, jendela Senin 18:45 sampai Kamis 08:45 berisi 612.447 baris; corong tagging (rutin dikenal, detak task, responder, rutin lain, pengguna) menyisakan 1.354 baris untuk review manual, dan tidak ada yang tak terjelaskan (Day 13 bagian 1.5).
- Detak task adalah bukti: 241 slot 15 menit dari Senin malam sampai Kamis pagi, 36 terlewat saat laptop tidur. Folder Startup, WMI `OBJECTS.DATA`, dan SRUM diperiksa dan negatif untuk aktivitas lain (Day 13 bagian 1.6).
- PT JAB belum punya Timesketch. Kasus dibaca lewat CSV di Timeline Explorer, `.plaso` dan file tag diserahkan ke retainer, dan Timesketch dipraktikkan di lab (Day 13 bagian 1.7).

### 1.4 Day 14-16: memori

- Image memori adalah potret satu jendela waktu, bukan rekaman. WinPmem membaca halaman satu per satu selama beberapa menit sementara sistem berjalan (smear), dan memori tidak bisa menjawab apa pun tentang waktu sebelum jendela itu (Day 14 bagian 1.1 dan 1.2).
- Ukuran file raw mengikuti alamat fisik tertinggi, bukan RAM: E01 `JKT-WS-0388` berukuran 19.318.964.224 byte dari RAM 16 GB, diambil 12:42:07 sampai 12:52:41 WIB (Day 14 bagian 1.2).
- Volatility 3 memakai symbol table, bukan profil. Analisis dasar selalu berurutan: `windows.info`, lalu daftar proses dari dua arah (`pslist` dan `psscan`), lalu command line dan sesi, lalu korelasi ke event log dan disk [S3] (Day 14 bagian 1.3 sampai 1.7).
- Plugin analisis proses menghasilkan kandidat. `windows.malware.malfind` menandai region JIT .NET dan antivirus; di E01, lima region RWX milik `MsMpEng.exe` dan `powershell.exe` task ternyata pola sah setelah dibandingkan dengan lab (Day 15 bagian 1.1).
- Kalimat retainer "tidak menemukan akses ke LSASS" hanya berlaku untuk handle yang terbuka di detik image diambil. Credential Guard aktif melindungi rahasia domain di `LsaIso.exe`, tetapi tidak melindungi password yang tersimpan di skrip (Day 15 bagian 1.5).
- Isi `upd.ps1` dipulihkan dari file cache memori dan hash-nya cocok dengan file yang diambil lewat `getfile` (E03) setelah padding dipotong ke 4.812 byte (Day 15 bagian 1.6).
- Di `INC-2026-017`, memori `JKT-WS-0457` menautkan `hlpsvc.exe` PID 6412 ke C2 `203.0.113.205:443` dengan beacon sekitar 5 menit, termasuk percobaan `SYN_SENT` setelah isolasi. Sisa koneksi ke IP exfil tanpa pemilik (Owner N/A), sehingga proses pengirim exfil tetap tidak teridentifikasi (Day 16 bagian 1.3 dan 1.8).
- `netstat` butuh symbol table `tcpip.sys`; di `INC-2026-017` jendela proxy dibuka khusus untuk mengunduhnya (Day 16 bagian 2.3).

### 1.5 Day 17-18: simulasi kasus

- Kasus orang dalam tidak punya artefak yang jahat. Tangga bukti memisahkan data diakses, berkas dibuka, berkas disalin ke media tertentu, data keluar organisasi, dan niat; artefak host kuat untuk dua anak tangga pertama dan tidak pernah menjawab niat (Day 17 bagian 1.4).
- Di `INC-2027-010`, 19 berkas disalin dari share ke folder lokal `Kontrak-Ref` (terbukti), dua di antaranya dibuka dari flashdisk pribadi (sedang), dan 17 sisanya di flashdisk hanya disimpulkan rendah, karena isi media tidak tersedia (Day 17 bagian 1.6).
- Nomor seri volume di LNK bukan nomor seri perangkat di USBSTOR; jembatannya event 1006, label, huruf drive, dan waktu (Day 17 bagian 1.5). Hipotesis tandingan yang tidak menyalahkan karyawan diuji dengan artefak, dan hasil parsial ditulis (Day 17 bagian 1.8).
- Di `INC-2026-026`, tiga sumber dibagi kerja: disk membuktikan eksekusi dan waktu tanpa argumen, memori membuktikan `version.dll` dimuat dari folder aplikasi dan tahap kedua di proses native, EDR menyimpan command line discovery. Host Bandung itu ber-EDR tetapi tanpa GPO audit Jakarta, jadi tanpa 4688, 4698, dan Sysmon (Day 18 bagian 1.1).
- `version.dll` dipakai sah di 214 perangkat JAB DocSync, sehingga IOC "DLL di luar System32" membanjiri tim. Yang diserahkan adalah IOC atomik untuk hari ini dan IOC perilaku dengan pengecualian known-good untuk varian berikutnya (Day 18 bagian 1.3 dan 1.5).
- Memori `BDG-WS-0163` diambil lewat live response: image terkompresi sekitar 2,6 GB dari RAM 8 GB, karena `getfile` dibatasi 3 GB [S11] (Day 18 bagian 2.1).

### 1.6 Day 19: pelaporan forensik

Day 19 menulis laporan baku PT JAB untuk `INC-2027-010` (Day 17) dan `INC-2026-026` (Day 18), dari permintaan Dimas Senin 2027-01-18. Isinya yang dipakai di review ini:

- Template laporan forensik baku PT JAB `JAB-DFIR-TPL-01` memisahkan inti dan ringkasan untuk pembaca non-teknis dari temuan teknis, menulis temuan beserta keyakinan dan keterbatasannya, punya bagian hipotesis alternatif, bagian data pribadi untuk DPO, dan bagian "yang belum diketahui", lalu melampirkan chain of custody bukti dan versi alat (Day 19 bagian 2.1 dan 2.9).
- Executive summary ditulis berbeda untuk audiens yang berbeda: manajemen butuh dampak dan keputusan, HR dan Legal butuh fakta dan batas, tim teknis butuh IOC dan langkah.
- Bahasa keyakinan dipakai konsisten, dan setiap kalimat dipisahkan menjadi fakta (yang dicatat artefak), interpretasi (yang disimpulkan dari beberapa fakta), dan pendapat (penilaian analyst yang diberi label).
- Defensibility: orang lain dengan bukti dan versi alat yang sama bisa mengikuti penalaran dan mendapatkan hasil yang sama.
- Kasus orang dalam butuh nada netral: aksi akun dan sesi, bukan niat orang (Day 19 bagian 1.9). Laporan interim dipakai saat keputusan tidak bisa menunggu laporan akhir, dengan batas yang ditulis lebih tegas; contohnya interim `INC-2026-026` Selasa 2026-12-08 pukul 12:00 (Day 19 bagian 2.11).

Satu pelajaran Day 19 menjadi dasar bagian 1.11: setiap bagian "Keterbatasan" di laporan menunjuk celah yang sebagian besar berasal dari lingkungan, bukan dari analisis.

### 1.7 Peta konsep

Peta berikut menggabungkan peta Day 06 (rantai bukti) dan Day 12 (penulis artefak) dengan blok timeline, memori, kasus, dan laporan. Kolom kanan adalah hal yang wajib ikut tertulis; pakai peta ini sebagai satu-satunya bantuan saat latihan skenario berwaktu di Bagian G.

```
LANGKAH                          SUMBER DAN ALAT                              WAJIB IKUT TERTULIS
PERTANYAAN + HIPOTESIS           dari IC/TL/DPO/HR/Legal; tandingan sejak awal  lingkup izin (kasus orang dalam)
      |
      v
KEPUTUSAN AKUISISI (01)          per host: memori? triage? image? OOV          yang sengaja tidak diambil + risiko
  memori dulu bila hidup         konsol+USB | live response | agen             jendela mulai-selesai, hash di titik koleksi
      |
      v
KOLEKSI (03-04)                  KAPE (1 host) | Velociraptor hunt/offline     copylog | artifact+parameter+waktu
      |
      v
SIMPAN (01-02)                   hash -> CoC -> master read-only -> salinan    evidence log, versi alat beku
      |
      v
BACA PER SUMBER                  event log (05) | eksekusi (07) | FS (08)     profil cakupan: apa yang DIKONFIGURASI
  "siapa menulis, apa            registry (09) | shell (10) | pergerakan (11)  dicatat; apa yang TIDAK PERNAH dilihat
   yang tidak ia lihat"          memori: proses (14) | dalam proses (15) |     memori = satu jendela; plugin = kandidat
                                 jaringan dan persistence (16)
      |
      v
SATUKAN                          super-timeline (13): zona, jam host, corong   keputusan filter dicatat; 0 tak terjelaskan
      |
      v
PELAKU                           pengguna | penyerang | responder              >= 2 jangkar per jejak responder
      |
      v
TEMUAN                           tangga bukti (17) | IOC atomik+perilaku (18)  terbukti | disimpulkan | tidak bisa dijawab
      |
      v
LAPORAN (19)                     fakta | interpretasi | pendapat ; audiens     keyakinan + keterbatasan + defensibility
      |
      v
PERBAIKAN                        celah berulang -> telemetri, alat, retensi,   tidak bisa ditambah mundur; pemilik +
                                 latihan (bagian 1.11 sampai 1.13)             ukuran selesai
```

Tiga benang dipakai untuk menguji peta ini dengan empat kasus PT JAB:

1. **Benang pertanyaan:** setiap pertanyaan investigasi punya artefak utama, keterbatasan, dan telemetri prasyarat (bagian 1.8).
2. **Benang kasus:** keempat kasus dibaca berdampingan untuk melihat siapa yang mengerjakan apa dan di mana jawaban berhenti (bagian 1.9 dan 1.10).
3. **Benang celah:** batas yang sama muncul lagi di kasus yang berbeda, dan itulah bahan rencana (bagian 1.11 sampai 1.13).

### 1.8 Tabel artefak master: pertanyaan, artefak, keterbatasan, dan telemetri prasyarat

Permintaan kedua Dimas dijawab dengan tabel ini, yang disusun untuk dibuka saat on-call. Bedanya dengan tabel di Day 06 bagian 1.7 dan Day 12 bagian 1.7: baris diurutkan per pertanyaan, bukan per artefak, dan ada kolom terakhir yang menyebut apa yang harus sudah dikonfigurasi sebelum insiden supaya artefak itu ada. Baca kolom keterbatasan sebelum menulis kalimat "tidak", dan kolom prasyarat sebelum menyimpulkan apa pun dari ketiadaan.

| Pertanyaan investigasi | Artefak utama (Day) | Keterbatasan yang wajib ikut tertulis | Telemetri prasyarat |
|---|---|---|---|
| Siapa login, kapan, dengan cara apa | 4624/4625 dengan logon type, Logon ID, 4672, 4647 (05); 1149 dan LSM 21 untuk RDP (11) | Kolom `UserName` CSV untuk 4624 adalah Subject; sesi bukan orang; Security berputar | Audit logon (bawaan aktif); ukuran Security log cukup |
| Program apa dijalankan, kapan, berapa kali | Prefetch, BAM, UserAssist (07); 4688, Sysmon 1 (05); `pslist`, `psscan` (14); timeline EDR (18) | Prefetch tanpa akun dan argumen; Amcache dan Shimcache hanya keberadaan; kerja di dalam proses tidak tercatat | Audit Process Creation, Sysmon, EDR; Prefetch aktif |
| Apa persisnya yang diketik atau dijalankan | Command line 4688 dan Sysmon 1 (05); 4104 (05); `windows.cmdline` (14); process timeline EDR (18) | 4688 butuh setting command line terpisah; 4104 lengkap hanya dengan script block logging; memori hanya proses yang hidup | Command line di 4688, script block logging, EDR |
| File dibuat, diubah, di-rename, dihapus | `$MFT`, `$J`, Recycle Bin (08) | `$J` tanpa pembacaan dan pelaku, dalam jendela terbatas; Shift+Delete tidak lewat Recycle Bin | Bawaan NTFS; ukuran `$J` menentukan jendela |
| File dibaca atau dibuka | LNK, Jump List, RecentDocs (10); 4104 (05); 5145 di file server (17); handle dan file cache (15) | Disk tidak mencatat pembacaan oleh skrip; last access sering mati; artefak shell hanya untuk kerja lewat GUI | Audit Detailed File Share di server; script block logging |
| Folder dilihat, path diketik, kata dicari | ShellBags, TypedPaths, WordWheelQuery (10) | Waktu ShellBags adalah inferensi parser; skrip tidak tercatat | Bawaan (per profil) |
| Perangkat USB tersambung, kapan, di sesi siapa | USBSTOR, SCSI, USB, `0065`-`0067`, MountedDevices, `MountPoints2`, `setupapi.dev.log`, event 1006 (09, 17) | `MountPoints2` menunjuk sesi; tidak membuktikan file disalin; `setupapi` waktu lokal | Channel Partition/Diagnostic; event mount USB EDR |
| Berkas disalin ke media lepasan | Nama dan ukuran sama ditambah TargetCreated di media, LNK dan Jump List ke media (17) | Isi butuh media; `$J` volume C: tidak melihat penulisan ke volume lain | Audit Removable Storage (tidak ada di `JAB-WS-Audit`); file event EDR saat sensor online |
| Host tersambung ke jaringan apa | NetworkList, interface TCP/IP, WLAN-AutoConfig (09) | Hanya pertama dan terakhir per profil, waktu lokal | Bawaan |
| Berapa banyak data dikirim aplikasi | SRUM (07, 13) | Tanpa tujuan dan isi; waktu baris bisa meleset sekitar satu jam | Bawaan; database sering dirty |
| Bagaimana kode bertahan | Run key, service (7045, key), task (XML, TaskCache, 106, 4698), Startup, WMI (09, 11, 13); `svcscan`, `printkey`, `scheduled_tasks` (16) | Satu artefak jarang cukup; WMI hanya dari Sysmon 19-21 atau `OBJECTS.DATA` | Audit Other Object Access dan Security System Extension, channel TaskScheduler, Sysmon 12/13/19-21 |
| Host dimasuki dari mana, atau dipakai ke mana | Tujuan: 4624 type 3/10, 1149, 7045, 5145; sumber: MRU RDP, Prefetch alat remote, 4648 (11) | Arah dibaca dari jenis artefak; MRU berarti keluar | Audit di kedua sisi; log server |
| Ada injeksi, hollowing, atau proses tersembunyi | `windows.malware.malfind`, `hollowprocesses`, `pebmasquerade`, `ldrmodules`, `psxview` (15) | Hasil adalah kandidat; JIT dan antivirus memicu malfind; hanya detik image | Memori diambil sebelum reboot; Sysmon 8 dan 25 untuk jendela panjang |
| Ada akses ke kredensial atau LSASS | `windows.handles` ke `lsass.exe`, Credential Guard (`LsaIso.exe`), WinInit 12 (15); Sysmon 10 (15) | Handle hanya yang terbuka saat dump; Credential Guard tidak melindungi password di skrip, akun lokal, atau sesi aktif | Sysmon 10 dengan TargetImage `lsass.exe` |
| Proses mana bicara ke IP mana | `windows.netscan`, `windows.netstat` (16); Sysmon 3 dan 22 (05); paket investigasi EDR (16, 18); log firewall dan proxy | Sisa `CLOSED` bisa tanpa pemilik; riwayat koneksi hanya dari log jaringan; laptop di luar kantor tidak lewat log PT JAB | Sysmon 3/22, EDR, retensi log firewall, proxy, DNS |
| DLL apa dimuat, dari mana | `windows.dlllist`, `ldrmodules` (15, 18); image load EDR (18) | Satu detik; DLL bernama sama bisa sah di banyak host, jadi butuh prevalence dan signer | EDR atau Sysmon 7 (volume besar) |
| Urutan lintas artefak dan celah waktu | Super-timeline Plaso dan garis waktu kurasi (13) | Zona waktu, jam host, preset parser, noise; diamnya sumber bisa karena tidak dikonfigurasi | Sumber di atas; Timesketch untuk kerja bersama |
| Log dibersihkan atau audit diubah | 1102, 104, 4719, celah EventRecordID (05) | Ketiadaannya bukan bukti log utuh | Log forwarding ke SIEM |
| Data keluar organisasi | Proxy, firewall, gateway email, SRUM (16, 17) | Host lemah untuk anak tangga ini; jalur pribadi di luar lingkup | Retensi `proxy` dan `dns`; EDR untuk laptop di luar kantor |
| Jejak siapa ini: pengguna, penyerang, atau responder | Case notes, evidence log, akun `ir-admin` dan `adm.<nama>`, nomor seri volume media bukti, hash toolkit (06, 12) | Hanya sebaik catatan yang dibuat saat tindakan | Prosedur responder, inventaris toolkit |

Tiga pola terlihat bila kolom terakhir dibaca dari atas ke bawah. Pertama, artefak disk bawaan (NTFS, registry, Prefetch, artefak shell, SRUM) ada di hampir semua host, sehingga pertanyaan "apa yang berubah" dan "apa yang dijalankan" hampir selalu bisa dijawab sebagian. Kedua, pertanyaan "siapa, dengan argumen apa, dan proses mana" bergantung pada telemetri yang harus dikonfigurasi dulu: audit policy, Sysmon, EDR. Ketiga, pertanyaan tentang data yang keluar hampir selalu bergantung pada sumber di luar host dan pada retensinya. Ketiga pola itu adalah kerangka bagian 1.11.

**Kapan gagal:** tabel dipakai sebagai daftar periksa tanpa membaca kolom prasyarat, sehingga analyst on-call mencari 4698 di host tanpa GPO audit dan menulis "tidak ada task dibuat". Atau baris dibaca terpisah, padahal setiap kesimpulan dengan keyakinan tinggi butuh minimal dua baris dari sumber yang tidak sama-sama buta terhadap kejadian itu (Day 12 bagian 1.10).

### 1.9 Benang kasus: empat kasus berdampingan

Tabel ini membaca empat kasus dengan kolom yang sama, supaya terlihat di mana tiap kasus berhenti dan kenapa. Cari kolom "Jawaban berhenti di", karena di situlah bahan bagian 1.10 dan 1.11.

| Kasus | Host dan telemetri | Bukti utama dan pengambil | Yang dijawab internal | Jawaban berhenti di | Day |
|---|---|---|---|---|---|
| `INC-2026-019` | `JKT-WS-0388`: EDR, Sysmon, audit lengkap. `JKT-WS-0412`: tanpa EDR, audit bawaan, hanya Defender Antivirus. `BDG-WS-0142`: tanpa EDR dan Sysmon. Enam penerima lain campuran | Memori E01, E08, E13 lewat konsol dan USB (Yoga; Fajar dipandu telepon); triage E14; image E15 dan E16; image E17 dan E18 oleh retainer; hunt E19 dan offline collector E20 | Rantai eksekusi tiga laptop, task, pembacaan `export-tagihan.ps1`, SSH, jejak responder, super-timeline laptop Rizky, verifikasi ulang memori E01 | Data yang dikirim laptop Rizky lewat jaringan hotel dan hotspot (tidak ada log PT JAB); kerja di dalam PowerShell di laptop Dewi; memori E08 dan E13 hanya dianalisis retainer | 01-15 |
| `INC-2026-017` | `JKT-WS-0441` dan `JKT-WS-0457` di OU `Workstations-EDR` (EDR, Sysmon, audit lengkap); `jkt-dmz-app01` tanpa EDR | Memori E01 dan E03 lewat konsol dan USB, paket investigasi E02 dan E04 (Yoga); image E05 dan E06 | Rantai PsExec dan RDP, dua jalur persistence per payload, beacon `hlpsvc.exe`, tidak ada service tersembunyi atau persistence kernel, daftar IOC | Proses pengirim exfil sekitar 6 GB: memori diambil sekitar 16 jam setelah exfil selesai, sisa koneksi tanpa pemilik | 11, 16 |
| `INC-2026-026` | `BDG-WS-0163`: EDR, tetapi tanpa GPO audit Jakarta (tanpa 4688, 4698, Sysmon, history Task Scheduler) | Paket investigasi E04 dan memori E05 lewat live response (Yoga); image E06 di POP Bandung (Fajar) | Titik masuk, side-loading, tahap kedua di memori, C2, persistence dari XML dan TaskCache, discovery dari timeline EDR, IOC perilaku untuk 214 host | Isi `update.dat` dan tahap kedua (analisis sampel di luar forensik endpoint); kredensial Bima di host lain (log DC, hunting fleet) | 18 |
| `INC-2027-010` | `JKT-WS-0516`: EDR, Sysmon, audit lengkap; tanpa Audit Removable Storage; Sysmon EID 11 hanya folder tertentu | Image E01 (Yoga); log 5145 `JKT-FS01`, proxy, advanced hunting Defender | Pola akses di luar kebiasaan, berkas dibuka, rantai USB, 19 berkas disalin ke folder lokal | Isi flashdisk pribadi (17 berkas hanya disimpulkan rendah); laptop offline saat sesi USB kedua sehingga Defender tidak punya data; jalur pribadi di luar lingkup izin | 17 |

Pola yang paling penting: jawaban hampir tidak pernah berhenti karena analyst tidak tahu artefaknya. Jawaban berhenti karena sumbernya tidak ada (audit, Sysmon, EDR), sudah lewat (memori diambil terlambat untuk exfil, retensi), berada di luar host (jaringan di luar kantor, media pribadi), atau di luar keahlian forensik endpoint (isi sampel). Hanya satu baris yang berhenti karena kapasitas tim: memori E08 dan E13 di `INC-2026-019`, yang dianalisis retainer karena saat itu PT JAB belum membaca memori sendiri.

### 1.10 Peta kemampuan: internal, internal dengan syarat, dan retainer

Permintaan pertama Dimas dijawab dengan tiga status, bukan dua. "Internal" berarti sudah dikerjakan di kasus nyata dan bisa diulang oleh lebih dari satu orang. "Internal dengan syarat" berarti sudah dikerjakan, tetapi bergantung pada satu orang, satu kondisi host, atau satu prosedur yang belum diuji untuk semua ukuran host. "Retainer" berarti belum dilatih, butuh keahlian di luar forensik endpoint, atau ada alasan non-teknis untuk memakai pihak luar. Kolom "Dasar" menunjuk kasus yang membuktikannya, karena peta kemampuan yang tidak bisa ditunjuk ke kasus adalah brosur.

| Kemampuan | Status per Januari 2027 | Dasar | Syarat atau alasan ke retainer |
|---|---|---|---|
| Keputusan akuisisi, case notes, chain of custody | Internal | `INC-2026-019`, `INC-2027-010` (Day 01, 17) | Bila kasus kemungkinan naik ke proses hukum, Legal memutuskan apakah pengambilan didampingi pihak luar |
| Akuisisi memori lewat konsol dan USB bukti | Internal | E01, E13 (Yoga), E08 (Fajar dipandu telepon), E01 dan E03 `INC-2026-017` | Butuh orang di lokasi dengan hak admin; host di POP bergantung teknisi setempat |
| Akuisisi memori lewat live response | Internal dengan syarat | E05 `INC-2026-026`, RAM 8 GB, image terkompresi sekitar 2,6 GB | `getfile` dibatasi 3 GB dan 30 menit per perintah [S11]; host RAM 16 GB belum pernah dicoba; format terkompresi dan pemecahan file belum diuji di lab |
| Triage satu host (KAPE) | Internal | E14 (Day 03) | Versi KapeFiles dibekukan per kasus; lisensi tidak dipakai di jaringan pihak lain |
| Koleksi banyak host (Velociraptor hunt, offline collector) | Internal dengan syarat | E19 dan E20 (Day 04) | Server `jkt-velo01` dibuat sementara per kasus; prosedur pembangunan dan pembongkaran baru sekali dijalankan |
| Image disk penuh | Internal | E15, E16, E01 `INC-2027-010`, E06 `INC-2026-026` (Fajar) | E17 dan E18 `INC-2026-019` diambil retainer |
| Event log, artefak eksekusi, file system, registry, aktivitas pengguna, persistence dan lateral movement | Internal | Day 05, 07-11 di `INC-2026-019` dan `INC-2026-017` | Kalimat negatif tetap dibatasi profil cakupan host |
| Super-timeline satu host | Internal dengan syarat | `JKT-WS-0412` (Day 13) | Dibaca lewat CSV di Timeline Explorer; tanpa Timesketch, kerja bersama retainer berarti menyerahkan `.plaso` dan file tag |
| Analisis memori Windows (proses, injeksi, LSASS, jaringan, service, kernel) | Internal | E01 `INC-2026-019`, E01 `INC-2026-017`, E05 `INC-2026-026` (Day 14-16, 18) | Symbol table untuk build baru dan `tcpip.sys` butuh jendela proxy; pembanding lab untuk pola JIT |
| Kasus orang dalam | Internal | `INC-2027-010` (Day 17) | Hanya dengan memo lingkup Legal; HR dan Legal yang menilai perbuatan |
| Kasus malware satu host dan IOC untuk fleet | Internal | `INC-2026-026` (Day 18) | Isi sampel dan tahap kedua dianalisis di luar forensik endpoint |
| Laporan forensik baku | Internal | `INC-2027-010`, `INC-2026-026` (Day 19) | |
| Forensik server Linux | Retainer | E17 `jkt-billing01` (`INC-2026-019`) | Belum dilatih internal; dibahas di Day 23 |
| Disk atau volume terenkripsi, macOS, anti-forensik mendalam | Retainer | Belum pernah muncul di empat kasus | Belum dilatih; Day 21-23 |
| Lonjakan kerja: SEV-1 dengan banyak host sekaligus | Retainer sebagai tambahan tenaga | `INC-2026-019`: image E17 dan E18 diambil retainer saat tim internal memegang tiga laptop dan enam penerima lain sekaligus | Kontrak retainer menentukan waktu respons dan pembagian kerja |
| Analisis sampel malware | Di luar forensik endpoint | `update.dat` `INC-2026-026` | Siapa yang memegangnya diputuskan Dimas (internal lain atau retainer) |

Pembagian ini sejalan dengan cara NIST SP 800-61 Rev. 3 menggambarkan incident handler: banyak organisasi mengerjakan respons dasar secara internal dan memakai pihak ketiga untuk insiden tertentu, dan pembagian tanggung jawab dengan penyedia luar perlu ditulis jelas di kontrak, termasuk aliran informasi dan wewenang bertindak [S5].

Tiga catatan untuk Dimas yang tidak terlihat dari tabel:

- **Ketergantungan pada satu orang.** Akuisisi memori dan pegangan bukti di keempat kasus dikerjakan Yoga, kecuali yang dikerjakan Fajar dengan panduan telepon. Status "internal" untuk akuisisi turun menjadi "internal dengan syarat" bila Yoga sedang cuti. Rotasi on-call di bagian 1.12 dirancang untuk mengurangi ketergantungan ini.
- **Laporan retainer.** Ringkasan dua halaman retainer untuk E01 ("tidak menemukan akses ke LSASS") tidak memuat cara kerja, versi alat, dan batas, sehingga harus diverifikasi ulang (Day 14 bagian 2.8). Kemampuan internal membaca memori kini dipakai juga untuk memeriksa hasil retainer, bukan hanya menggantikannya.
- **Status bisa turun.** Kemampuan yang tidak dipakai beberapa bulan, terutama yang jarang (offline collector, server Velociraptor sementara), kembali ke "dengan syarat" bila tidak dilatih. Itu alasan latihan berkala di bagian 1.13.

**Kapan gagal:** peta ditulis dari daftar alat yang dimiliki ("kita punya Volatility, jadi bisa analisis memori"), bukan dari kasus yang sudah dikerjakan; atau kolom syarat dikosongkan supaya tabel tampak lebih hijau, lalu rotasi on-call menerima kasus host RAM 16 GB lewat live response tanpa prosedur yang teruji.

### 1.11 Celah alat dan telemetri yang berulang

Permintaan ketiga Dimas adalah inti review ini. Tabel berikut hanya memuat celah yang muncul di lebih dari satu kasus atau di satu kasus dengan akibat besar. Baca kolom "Akibat pada kalimat temuan", karena celah lingkungan baru terasa ketika kalimat yang ingin ditulis ternyata tidak didukung.

| Celah | Muncul di | Akibat pada kalimat temuan |
|---|---|---|
| Audit policy tidak seragam: GPO `JAB-WS-Audit` hanya di OU `Workstations-EDR` Jakarta | `INC-2026-019` (`JKT-WS-0412`, `BDG-WS-0142`, dan kemungkinan `JKT-WS-0418`, `BDG-WS-0147`); `INC-2026-026` (`BDG-WS-0163`) | Tanpa 4688, 4698, 4697, dan channel TaskScheduler. Pembuatan task dibuktikan dari XML, TaskCache, dan `$MFT`; "proses apa yang membuat" tidak bisa dijawab dari event log. Keyakinan diturunkan per host (Day 05 bagian 2.7; Day 18 bagian 2.4) |
| Sysmon tidak terpasang di host di luar OU itu, dan konfigurasinya sempit | `INC-2026-019`, `INC-2026-026`; `INC-2027-010` (EID 11 hanya Downloads, folder Temp, Startup, ekstensi skrip dan executable) | Tanpa process tree dan koneksi per proses di host tanpa Sysmon; di laptop Arif, penyalinan ke `Documents\Kontrak-Ref` terlihat dari `$J`, Defender, dan 5145, bukan dari Sysmon (Day 17 bagian 2.6) |
| Laptop tanpa EDR | `INC-2026-019` (`JKT-WS-0412`, `BDG-WS-0142`, `JKT-WS-0418`, `BDG-WS-0147`) | Tanpa live response, sehingga akuisisi butuh orang di lokasi; tanpa telemetri saat laptop di luar kantor; scope enam penerima ditulis "keyakinan sedang" untuk host tanpa EDR (Day 04 bagian 2.8) |
| Akuisisi memori jarak jauh belum teruji untuk semua ukuran host | `INC-2026-026` (live response, image terkompresi); `INC-2026-019` dan `INC-2026-017` (konsol dan USB, orang di lokasi) | Host RAM 16 GB menghasilkan raw sekitar 18 GiB; tanpa prosedur kompresi atau pemecahan file yang teruji, pilihan yang tersisa adalah menunggu orang datang, dan memori bisa hilang lebih dulu |
| Memori diambil terlambat untuk pertanyaan tertentu | `INC-2026-017` (sekitar 16 jam setelah exfil) | "Proses pengirim exfil tidak teridentifikasi" adalah kalimat akhir yang jujur; memori tidak bisa menjawab sebelum jendelanya (Day 16 bagian 1.3) |
| Hash tidak selalu dihitung di titik koleksi | `INC-2026-019` (E14 dihitung 19 menit setelah KAPE selesai, E13 43 menit setelah WinPmem selesai) | Rentang antara akhir koleksi dan hash harus ditutup oleh case notes dan pemeriksaan isi tambahan (Day 06 bagian 1.8; Day 14 bagian 2.1) |
| Timesketch belum ada | `INC-2026-019` (Day 13); semua kasus dengan lebih dari satu host | Garis waktu banyak host disatukan manual; retainer tidak bisa melihat data yang sama secara bersamaan; anotasi tersebar di case notes |
| Retensi log pendek | `INC-2027-010` (`proxy` dan `dns` 30 hari, advanced hunting Defender 30 hari); `INC-2026-019` (Sysmon `JKT-WS-0388` hanya tersisa sejak 2026-10-04, Security sejak 2026-09-29) | Baseline pola kerja dan pencarian jalur keluar dibatasi jendela retensi; kejadian di luar jendela ditulis "tidak bisa dinilai", bukan "tidak ada" (Day 17 bagian 1.3) |
| Laptop di luar kantor tidak lewat log jaringan PT JAB | `INC-2026-019` (`JKT-WS-0412` di Wi-Fi hotel, Wi-Fi tamu pelanggan, hotspot) | Data yang mungkin dikirim ke C2 tidak bisa dinilai dari log PT JAB sama sekali (Day 09 bagian 2.4) |
| Audit Removable Storage tidak ada di `JAB-WS-Audit` | `INC-2027-010` | Penyalinan ke flashdisk hanya disimpulkan dari LNK, Jump List, dan nama serta ukuran berkas; isi media tidak tersedia (Day 17 bagian 1.6) |
| Password `ir-admin` tidak dijamin unik per host | `INC-2026-019` (`JKT-WS-0412`, belum diganti sejak 2026-03-02) | Akun responder sendiri menjadi risiko kredensial; jejaknya harus selalu dilabeli (Day 09 bagian 2.7) |
| Symbol table Volatility tidak lengkap secara offline | `INC-2026-017` (`tcpip.sys`) | Plugin gagal sampai jendela proxy dibuka; di malam hari tanpa NOC, analisis jaringan dari memori tertunda (Day 16 bagian 2.3) |
| Laporan retainer tanpa metodologi | `INC-2026-019` (E01) | Kalimat retainer tidak bisa dikutip sampai diverifikasi ulang (Day 14 bagian 2.8) |

Celah-celah ini dibaca dengan satu aturan yang membedakannya dari kekurangan analyst: celah telemetri tidak bisa ditutup setelah insiden terjadi. Analyst bisa belajar plugin baru dalam satu sore, tetapi audit policy yang dipasang hari ini tidak akan pernah mencatat 4698 untuk task yang dibuat kemarin. Karena itu celah dikelompokkan menjadi tiga jenis untuk rencana di bagian 1.13:

1. **Telemetri sebelum insiden:** audit policy, Sysmon, EDR, retensi, Audit Removable Storage. Mahal ditunda, karena setiap insiden yang terjadi sebelum diperbaiki akan punya batas yang sama.
2. **Alat dan prosedur saat insiden:** akuisisi memori jarak jauh, symbol table offline, hash di titik koleksi, Timesketch, server Velociraptor siap pakai. Bisa diperbaiki kapan saja, tetapi harus diuji di lab sebelum dipercaya.
3. **Kontrak dan tata kelola:** syarat laporan retainer, password akun responder, lingkup izin. Diperbaiki dengan dokumen, bukan teknologi.

Satu celah sengaja tidak dimasukkan: "analyst kurang paham artefak X". Di keempat kasus, keterbatasan yang tertulis di laporan berasal dari lingkungan atau dari waktu, bukan dari salah baca artefak. Kemampuan orang tetap diukur, tetapi di bagian 1.12 dan Bagian H, dengan latihan berwaktu.

**Kapan gagal:** celah dicatat per kasus di laporan masing-masing dan tidak pernah dibaca berdampingan, sehingga "4698 tidak ada karena audit bawaan" muncul di tiga laporan tanpa pernah menjadi satu baris anggaran. Atau celah ditulis sebagai kesalahan orang ("Yoga terlambat menghitung hash"), padahal yang perlu diperbaiki adalah prosedur dan alatnya.

### 1.12 Kesiapan dan rotasi on-call: siapa boleh memegang apa

Permintaan keempat dan kelima Dimas menyangkut orang. Kesiapan tidak dinilai dari Day yang sudah dibaca atau lab yang sudah dikerjakan, tetapi dari apa yang bisa dilakukan di bawah tekanan waktu tanpa catatan. Tiga tingkat dipakai di seluruh review ini:

- **Paham:** bisa menjelaskan konsep, artefak, dan keterbatasannya ke rekan kerja.
- **Bisa melakukan:** bisa mengerjakannya di lab dengan catatan dan tanpa batas waktu.
- **Mahir:** bisa mengerjakannya di skenario berwaktu tanpa catatan, menulis kalimat temuan dengan batas yang benar, dan menjelaskan keterbatasannya ke orang non-teknis.

Tabel berikut menetapkan tingkat minimum per area untuk dua peran on-call. Baca kolom "Secondary (bulan pertama)" bersama kolom terakhir: yang tidak boleh dikerjakan sendiri sama pentingnya dengan yang boleh.

| Area | Primary on-call | Secondary (bulan pertama) | Yang tidak dikerjakan sendirian oleh secondary |
|---|---|---|---|
| Keputusan akuisisi, case notes, chain of custody (Day 01) | Mahir | Bisa melakukan | Memutuskan tidak mengambil memori host yang masih hidup |
| Akuisisi memori konsol dan USB, panduan telepon untuk teknisi POP (Day 01, 14) | Mahir | Bisa melakukan, didampingi | Memegang media bukti tanpa Yoga atau primary |
| Akuisisi memori lewat live response (Day 18) | Bisa melakukan, dengan prosedur teruji | Paham | Seluruhnya, sampai prosedur bagian 1.13 selesai diuji |
| Triage KAPE dan koleksi Velociraptor (Day 03, 04) | Mahir | Bisa melakukan | Memberi label hunt aktif ke client baru |
| Profil cakupan dan timeline event log (Day 05) | Mahir | Bisa melakukan | Menulis kalimat "tidak terjadi" untuk host tanpa GPO audit |
| Artefak disk (Day 07-11) | Mahir | Paham sampai bisa melakukan | Menyerahkan kesimpulan negatif ke DPO, HR, atau Legal |
| Super-timeline (Day 13) | Bisa melakukan | Paham | Membuang baris lewat filter tanpa mencatat keputusan |
| Analisis memori (Day 14-16) | Bisa melakukan | Paham | Menyebut hasil plugin sebagai temuan |
| Jejak responder dan lembar batas bukti (Day 06, 12) | Mahir | Bisa melakukan | Menghapus jejak responder dari daftar temuan |
| Laporan dan bahasa keyakinan (Day 19) | Mahir | Paham | Mengirim laporan interim tanpa review eskalasi |

Penerapan untuk rotasi Februari:

- **Rudi Hartanto (primary).** Sejak menerima serah terima `INC-2026-019` di Oktober (Day 06 bagian 1.11), Rudi menjalankan pembanding lab memori untuk E01 (Day 15) dan menjadi technical lead `INC-2026-026` (Day 18). Area yang belum pernah ia kerjakan di kasus nyata adalah akuisisi memori lewat live response dan koleksi banyak host dengan Velociraptor; keduanya masuk latihan sebelum 1 Februari.
- **Yudha Prakoso (secondary).** Datang dari antrean L1, jadi kuat di triage alert dan kueri SIEM, tetapi belum pernah memegang bukti. Bulan pertama ia mendampingi setiap akuisisi, mengerjakan triage dan timeline event log dengan review primary, dan tidak menulis kalimat negatif ke pihak di luar tim.
- **Eskalasi (kamu).** Dipanggil untuk keputusan akuisisi yang tidak biasa, analisis memori, dan setiap kalimat yang akan dibaca DPO, HR, atau Legal. Yoga tetap pemegang bukti dan satu-satunya yang menulis ke share bukti.

Kesiapan diukur dengan latihan, bukan wawancara: latihan skenario berwaktu di Bagian G untuk semua area, dan lab gabungan di Bagian A sampai F untuk alur penuh. Jadwal yang diusulkan ke Dimas: Rabu 2027-01-27 dan Jumat 2027-01-29, masing-masing setengah hari, difasilitasi kamu; hasilnya dicatat per area dengan tiga tingkat di atas, lalu dinilai ulang akhir Maret. Prosedur yang diuji dan dilatih berkala juga dipakai untuk melatih personel baru, seperti disebut NIST SP 800-61 Rev. 3 untuk prosedur respons [S5].

**Kapan gagal:** kesiapan dinilai dari daftar Day yang sudah dibaca, sehingga analyst yang belum pernah memegang media bukti dijadwalkan sendirian di malam hari; atau secondary dilarang mengerjakan apa pun, sehingga setelah satu bulan ia tetap tidak bisa melakukan apa-apa tanpa primary.

### 1.13 Rencana memperkuat kelemahan 2027 dan dokumen untuk Dimas

Permintaan keenam Dimas dijawab dengan rencana yang diurutkan dari tiga jenis celah di bagian 1.11. Urutannya mengikuti dua pertanyaan: apakah celah ini membatasi jawaban di lebih dari satu kasus, dan apakah ia bisa diperbaiki setelah insiden berikutnya terjadi. Celah telemetri menang di kedua pertanyaan, sehingga ada di urutan teratas walaupun paling sulit dikerjakan. Tabel ini dibaca per baris: setiap tindakan punya pemilik dan ukuran selesai yang bisa diperiksa orang lain.

| No | Tindakan | Celah yang ditutup | Pemilik | Ukuran selesai | Target |
|---|---|---|---|---|---|
| 1 | Pasang GPO audit yang setara `JAB-WS-Audit` di semua OU workstation Jakarta dan Bandung tanpa menunggu EDR, termasuk channel TaskScheduler/Operational; uji volume Audit Removable Storage lalu putuskan | Audit tidak seragam; Audit Removable Storage | Sari Kusuma (rancangan), Agung Prabowo, Lead Infrastruktur (GPO) | Profil cakupan sampel lima host per OU sama dengan `JKT-WS-0388` (hitung event per subcategory seperti Day 05 bagian 2.7) | Maret 2027 |
| 2 | Onboard Defender for Endpoint dan Sysmon ke semua workstation; tinjau konfigurasi Sysmon EID 11 dan EID 10 | Laptop tanpa EDR; Sysmon tidak seragam dan sempit | Dimas (anggaran), tim IT (onboarding), Sari (konfigurasi Sysmon) | Daftar inventaris dibandingkan dengan portal: nol workstation tanpa sensor | Juni 2027 |
| 3 | Uji prosedur akuisisi memori jarak jauh untuk RAM 8 dan 16 GB: image terkompresi, pemecahan file untuk `getfile`, alternatif `Windows.Memory.Acquisition` Velociraptor; hash dihitung di titik koleksi | Akuisisi memori jarak jauh; hash tidak di titik koleksi | Yoga Pratama, Rudi Hartanto | Dua uji lab per ukuran RAM dengan hash cocok di host dan di `jkt-evid01`; prosedur tersimpan di repositori `jab-ir-tools` | Februari 2027 |
| 4 | Naikkan retensi index `proxy` dan `dns`; teruskan tabel advanced hunting Defender yang dipakai forensik ke Splunk lewat streaming API | Retensi pendek | Dimas, bersama pengelola Splunk | Retensi baru tercatat di konfigurasi index; angka final mengikuti biaya penyimpanan | Juni 2027 |
| 5 | Pasang symbol table Volatility untuk semua build Windows di fleet, termasuk `tcpip.sys`, di cache offline `jkt-dfir02`; perbarui di setiap jendela pembaruan alat | Symbol table tidak lengkap | Kamu | `windows.info` dan `windows.netstat` berhasil tanpa internet pada image lab dari tiap build | Februari 2027 |
| 6 | Password akun responder `ir-admin` unik per host dan diganti setelah setiap pemakaian | Kredensial akun responder | Tim IT (Agung Prabowo) | Sampel host menunjukkan password berbeda; tanggal ganti tercatat | Februari 2027 |
| 7 | Syarat laporan retainer di kontrak: metodologi, versi alat, hash bukti yang dianalisis, batas setiap kesimpulan; pembagian kerja dan aliran informasi tertulis | Laporan retainer tanpa metodologi | Dimas, Legal (Ratna Sari) | Klausul ada di kontrak perpanjangan | Saat perpanjangan kontrak |
| 8 | Pilot Timesketch di jaringan manajemen dengan akses terbatas; DPO meninjau karena timeline memuat data pribadi karyawan | Timesketch belum ada | Kamu, Sari; Agus Setiawan (DPO) untuk data pribadi | `.plaso` E16-W1 diimpor ulang dan corong tagging menghasilkan angka yang sama dengan Day 13 | April 2027 |
| 9 | Latihan berkala: satu skenario berwaktu per bulan, satu latihan gabungan per kuartal bersama retainer | Status kemampuan turun bila tidak dipakai | Nina Kartika (fasilitator), kamu | Hasil latihan per area tercatat; tingkat secondary naik di penilaian Maret | Mulai Februari 2027 |
| 10 | Kemampuan baru: triage Linux untuk server billing dan portal; cek bersama tim IT status enkripsi disk workstation dan lokasi recovery key | Forensik Linux masih retainer; disk terenkripsi belum pernah dihadapi | Kamu | Satu lab triage Linux selesai; status enkripsi dan prosedur kunci tertulis | Juni 2027 |

Rencana ini mengikuti kategori Improvement di NIST SP 800-61 Rev. 3: perbaikan diidentifikasi dari evaluasi program (ID.IM-01), dari latihan dan pengujian termasuk bersama pihak ketiga (ID.IM-02), dan dari pelaksanaan respons, misalnya pertemuan lessons learned (ID.IM-03); rencana respons dipelihara dan setiap rencana menyebut sumber daya dan dukungan manajemen yang dibutuhkan (ID.IM-04) [S5]. Bagian "Keterbatasan" di empat laporan kasus adalah bahan ID.IM-03, dan Bagian G adalah bahan ID.IM-02.

Dokumen yang dikirim ke Dimas memadatkan bagian 1.8 sampai 1.13 menjadi dua halaman. Ia disimpan di repositori, bukan di chat, supaya versi yang dibawa ke rapat Kamis sama dengan yang dibaca Rudi dan Yudha.

```
Peta kemampuan forensik endpoint PT JAB | dari: <kamu> ke: Dimas Prasetyo | Selasa 2027-01-26 11:40 WIB
Lokasi: repositori jab-ir-tools, docs/forensik/peta-kemampuan-forensik-2027-01.md
Dasar: laporan dan case notes INC-2026-019, INC-2026-017, INC-2026-026, INC-2027-010

1. KEMAMPUAN (detail di lampiran A)
   INTERNAL        keputusan akuisisi + CoC | memori konsol/USB | triage KAPE | image | event log | artefak disk
                   | analisis memori Windows | kasus orang dalam | kasus malware 1 host + IOC | laporan
   DENGAN SYARAT   memori lewat live response (uji RAM 16 GB belum) | Velociraptor multi-host (server sementara)
                   | super-timeline (tanpa Timesketch)
   RETAINER        forensik Linux | disk terenkripsi, macOS, anti-forensik mendalam | tenaga tambahan SEV-1
   DI LUAR         analisis sampel malware (pemilik diputuskan IC)
   RISIKO          akuisisi dan pegangan bukti bergantung pada Yoga

2. TABEL ARTEFAK MASTER untuk on-call (lampiran B): pertanyaan | artefak | keterbatasan | telemetri prasyarat

3. CELAH BERULANG (lampiran C)
   TELEMETRI   audit tidak seragam antar OU (019, 026) | Sysmon tidak seragam dan sempit (019, 026, 010)
               | laptop tanpa EDR (019) | retensi proxy/dns/AH 30 hari (010) | tanpa Audit Removable Storage (010)
   ALAT        memori jarak jauh belum teruji semua ukuran (026) | symbol offline tidak lengkap (017)
               | hash tidak selalu di titik koleksi (019) | tanpa Timesketch (019)
   TATA KELOLA laporan retainer tanpa metodologi (019) | password ir-admin tidak unik (019)
   ATURAN      telemetri tidak bisa ditambah mundur -> prioritas anggaran

4. ROTASI mulai 1 Feb: Rudi primary | Yudha secondary (dampingi akuisisi, tidak pegang bukti sendiri)
   | eskalasi: <kamu> | pemegang bukti: Yoga. Latihan Rabu 27 dan Jumat 29 Jan; nilai ulang akhir Maret.

5. RENCANA 2027 (urut prioritas, pemilik, ukuran selesai di lampiran D)
   1 GPO audit semua OU workstation | 2 EDR + Sysmon semua workstation | 3 prosedur memori jarak jauh
   | 4 retensi | 5 symbol offline | 6 password ir-admin unik | 7 syarat laporan retainer | 8 pilot Timesketch
   | 9 latihan berkala | 10 triage Linux + status enkripsi disk

6. BELUM PERNAH DIHADAPI (lampiran E): anti-forensik | disk terenkripsi | Linux dan macOS | browser dan cloud sync
   | telemetri yang diganggu | korelasi banyak host
```

Cara membaca elemennya:

- **Bagian 1** memakai tiga status dan satu baris risiko. Baris risiko adalah satu-satunya hal tentang orang di dokumen ini, dan ditulis sebagai ketergantungan, bukan penilaian.
- **Bagian 3** menulis nomor kasus di setiap celah. Dimas akan ditanya "dari mana angka ini"; jawabannya laporan kasus, bukan perasaan tim.
- **Baris ATURAN** adalah kalimat yang paling perlu sampai ke Pak Hendra: celah telemetri tidak bisa ditutup setelah insiden, jadi menundanya sama dengan menerima batas yang sama di insiden berikutnya.
- **Tidak ada temuan kasus baru di dokumen ini.** Seperti serah terima di Day 06, dokumen ini memindahkan status dan batas, bukan menambah kesimpulan.

**Kapan gagal:** rencana disusun dari daftar keinginan alat (lisensi alat forensik komersial, perangkat keras baru) tanpa menunjuk celah di kasus, sehingga anggaran habis untuk hal yang tidak mengubah satu pun kalimat "Keterbatasan" di laporan berikutnya; atau setiap tindakan punya pemilik "tim SOC", sehingga tidak ada yang bisa ditanya di review Maret.

### 1.14 Yang belum pernah dihadapi: posisi Day 21-26

Permintaan terakhir Dimas dijawab dari dua arah: apa yang belum muncul di empat kasus tetapi realistis untuk ISP seperti PT JAB, dan Day mana di catatan ini yang membahasnya. Tabel ini menunjukkan bahwa sebagian besar topik Day 21-26 bukan topik baru, melainkan perluasan dari celah yang sudah terlihat.

| Day | Topik | Kenapa relevan untuk PT JAB | Hubungan dengan empat kasus |
|---|---|---|---|
| 21 | Anti-forensics: pembersihan log, penghapusan jejak file system, timestomping lanjutan | Penyerang yang lebih hati-hati menghapus satu lapis bukti dan meninggalkan lapis lain; penghapusan adalah penulisan yang meninggalkan jejaknya sendiri | `INC-2026-017` sudah menunjukkan tamper antivirus dan penghapusan shadow copy; `INC-2027-010` punya penghapusan ke Recycle Bin |
| 22 | Disk dan volume terenkripsi: BitLocker, VeraCrypt, akuisisi | Pada sistem terenkripsi yang hidup dan ter-unlock, mematikan host bisa membuat seluruh bukti tidak terjangkau | Belum muncul; status enkripsi workstation dan lokasi recovery key belum tercatat di berkas kasus (rencana nomor 10) |
| 23 | Triage Linux dan macOS | Server billing, portal, dan RADIUS adalah Linux; tanpa registry, triage bergantung pada koleksi yang menyeluruh dan konsisten | `jkt-billing01` di `INC-2026-019` dianalisis retainer (E17); server Linux PT JAB belum memakai EDR |
| 24 | Browser dan artefak cloud sync: riwayat, unduhan, OneDrive, Teams | Pertanyaan bisnis di kasus kebocoran adalah "berkas apa keluar lewat mana", dan jawabannya sering di browser dan klien sinkronisasi | `INC-2027-010`: tiga sesi webmail hanya terlihat dari proxy; `INC-2026-026` berawal dari unduhan browser |
| 25 | ETW dan Sysmon sebagai sumber forensik | Konfigurasi Sysmon adalah peta celah, dan gangguan terhadap perekaman meninggalkan jejaknya sendiri | Sysmon yang tidak seragam dan sempit muncul di tiga kasus (bagian 1.11) |
| 26 | Korelasi multi-host dan timeline kolaboratif | Satu garis waktu untuk banyak host dan banyak analyst, termasuk retainer | `INC-2026-017` (rantai tiga host), `INC-2026-026` (hunting 214 host), dan pilot Timesketch (rencana nomor 8) |

Urutan belajar yang disarankan mengikuti rencana bagian 1.13: Day 25 dan 26 paling dekat dengan celah yang sudah terjadi, Day 23 menutup kemampuan yang masih ke retainer, Day 21 dan 24 memperdalam dua kasus terakhir, dan Day 22 disiapkan sebelum kejadiannya, karena keputusan terpentingnya diambil di menit pertama di lokasi.

### 1.15 Glosarium

Definisi di bawah ditulis dengan kata sendiri untuk keperluan belajar dan melengkapi glosarium Day 06 bagian 1.12 dan Day 12 bagian 1.12. Kolom terakhir adalah pasangan yang paling sering membuat jawaban interview atau laporan keliru.

| Istilah | Arti singkat | Sering tertukar dengan |
|---|---|---|
| Order of volatility | Urutan pengambilan dari bukti yang paling cepat hilang ke yang paling stabil, disesuaikan dengan pertanyaan | Urutan tetap yang sama untuk semua kasus |
| Triage, adaptive, full image | Koleksi daftar target, daftar target ditambah file yang dirujuk, dan salinan penuh disk | Tingkat kualitas, padahal pilihan per host |
| Chain of custody | Catatan setiap perpindahan bukti: siapa, kapan, apa yang dilakukan | Hash bukti |
| Profil cakupan | Daftar apa yang dikonfigurasi untuk dicatat di satu host, beserta rentang waktunya | Daftar event yang ditemukan |
| Jejak responder | Artefak dari tindakan tim sendiri, dilabeli dengan minimal dua jangkar | Temuan penyerang |
| Lembar batas bukti | Per host: terbukti, tidak terbukti, kalimat boleh, kalimat dilarang, pekerjaan terbuka | Ringkasan temuan |
| Super-timeline | Event berwaktu dari banyak artefak di satu sumbu UTC | Laporan kronologi untuk pembaca |
| Garis waktu kurasi | Beberapa puluh baris berlabel pelaku dan keyakinan yang menunjuk baris sumber | Hasil filter super-timeline tanpa catatan keputusan |
| Preset parser | Kumpulan parser Plaso yang dipilih otomatis per OS | Semua parser yang tersedia |
| Detak task | Baris berulang dari task terjadwal yang dipisah dan dihitung | Noise yang dibuang |
| Zona waktu vs jam host | Label zona untuk sumber waktu lokal vs selisih jam host terhadap sumber waktu lain | Satu koreksi yang sama |
| Image memori raw | Salinan memori fisik dengan offset sama dengan alamat fisik | Salinan seukuran RAM |
| Smear | Ketidakkonsistenan image karena halaman dibaca pada waktu berbeda | Image rusak |
| Symbol table | Deskripsi struktur kernel yang dipakai Volatility 3 untuk membaca image | Profil Volatility 2 |
| `pslist` vs `psscan` | Daftar proses aktif vs pemindaian sisa struktur proses | Bukti proses tidak pernah ada bila tidak ditemukan |
| Kandidat malfind | Region executable yang bukan image file, perlu dinilai dengan konteks | Bukti injeksi |
| JIT | Runtime yang mengompilasi kode ke memori privat yang bisa dieksekusi | Kode asing di proses |
| Credential Guard | Fitur yang memindahkan rahasia kredensial domain ke `LsaIso.exe` yang terisolasi | Perlindungan semua kredensial |
| Handle dan GrantedAccess | Referensi terbuka ke objek kernel beserta hak aksesnya, saat image diambil | Riwayat akses |
| `netscan` vs `netstat` | Pemindaian koneksi aktif dan sisa vs daftar koneksi aktif dari tabel kernel | Log koneksi dari waktu ke waktu |
| Owner N/A | Sisa koneksi yang pemiliknya tidak lagi bisa dibaca | Koneksi milik System |
| Beacon | Koneksi berulang dari implant ke C2 dengan interval relatif teratur | Satu koneksi C2 |
| Kasus orang dalam | Penyalahgunaan akses sah oleh orang yang punya atau pernah punya akses | Kasus malware dengan akun internal |
| Tangga bukti | Diakses, dibuka, disalin, keluar, niat; tiap anak tangga butuh artefak berbeda | Satu kesimpulan "mencuri data" |
| Hipotesis tandingan | Penjelasan yang sama-sama cocok dengan artefak tetapi tidak menyalahkan orang yang diduga | Pembelaan karyawan |
| Lingkup izin | Memo tertulis yang membatasi perangkat, sumber, periode, dan data yang boleh diperiksa | Akses teknis yang dimiliki analyst |
| DLL side-loading | Program sah memuat DLL penyerang dari folder yang dicari lebih dulu | Injeksi kode |
| Tahap kedua | Kode yang dimuat atau didekode di memori setelah tahap pertama | Payload di disk |
| IOC atomik vs perilaku | Nilai tunggal (hash, IP, domain) vs pola kombinasi proses, folder, signer, dan tujuan | Dua daftar yang setara |
| Pyramid of Pain | Urutan indikator menurut biaya penyerang menggantinya, dari hash sampai TTP | Urutan prioritas pemblokiran |
| Fakta, interpretasi, pendapat | Yang dicatat artefak, yang disimpulkan dari beberapa fakta, dan penilaian analyst yang diberi label | Satu kalimat temuan |
| Defensibility | Penalaran dan hasil bisa diikuti dan diulang orang lain dari bukti dan versi alat yang sama | Keyakinan tinggi |
| Laporan interim | Laporan sementara untuk keputusan yang tidak bisa menunggu, dengan batas yang lebih tegas | Draf laporan akhir |
| Peta kemampuan | Pertanyaan yang bisa dijawab, oleh siapa, dengan syarat apa, dan dasar kasusnya | Daftar alat yang dimiliki |
| Celah telemetri | Sumber yang tidak dikonfigurasi atau tidak disimpan cukup lama sebelum insiden | Kekurangan keahlian analyst |
| Internal dengan syarat | Sudah dikerjakan, tetapi bergantung satu orang, satu kondisi, atau prosedur yang belum diuji penuh | Belum bisa |
| Retainer | Penyedia DFIR luar dengan kontrak, dipanggil untuk pekerjaan di luar kemampuan atau kapasitas internal | TAC vendor yang bisa melihat ke dalam perangkat dari jauh |

## 2-4. Lab gabungan dan troubleshooting

Lab ini menjalankan satu kasus campuran di dua host dengan tiga pelaku (pengguna, penyerang tiruan, responder), dari keputusan akuisisi sampai laporan ringkas, lalu membandingkan hasilnya dengan kebenaran dasar yang disimpan terpisah. Semua aktivitas jinak, dijalankan di VM lab terisolasi dengan snapshot, dan jamnya dicatat (WIB dan UTC) sebelum dijalankan. Perintah ditulis sebagai teks untuk dijalankan di VM lab. Jangan memakai data, nama, atau kejadian dari pekerjaan nyata, dan jangan memakai sampel malware: "beacon" di lab ini hanya permintaan HTTP biasa ke server web lab.

**Prasyarat:** `LAB-WS01` (`172.16.50.10`, Windows 11, Sysmon dengan event 1, 3, 11, 12, 13, 19-21, audit policy diperluas termasuk Process Creation dengan command line dan Other Object Access Events, snapshot `bersih-2026-10-15`) sebagai host "korban". `LAB-WS02` (`172.16.50.11`, Windows 11, Sysmon, snapshot `bersih-2026-10-15`) sebagai host sumber RDP. `LAB-DFIR01` (`172.16.50.20`) dengan KAPE, EZ Tools, dan Volatility 3 di folder bertanggal, server web lab di port 8080 dari lab Day 16, dan share baca saja `\\LAB-DFIR01\lab-src` berisi `uji-lab.zip` (memuat `uji-lab.js` dengan satu baris `WScript.Echo("lab");` dan `catatan-zip.txt`). `LAB-VELO01` (`172.16.50.30`) dengan server Velociraptor dari lab Day 04. Disk virtual `LAB-USB` (FAT32, peran flashdisk pengguna) dan `LAB-IR20` (NTFS, peran media bukti responder, berisi `\tools\winpmem_mini_x64.exe` dan `\tools\autorunsc64.exe` yang SHA-256-nya dicatat di inventaris lab). Akun lab: `lab.user` (pengguna biasa, juga dipakai penyerang tiruan lewat RDP) dan `lab.ir` (admin lokal responder). Folder kasus `CASE-2026-LAB-020` di `LAB-DFIR01` dengan `evidence\`, `work\`, `analysis\`, `notes\`, `tools\`. Bila VM timeline dari lab Day 13 (`LAB-TL01`, `172.16.50.40`, Plaso dan Timesketch) masih ada, ia dipakai di Bagian E.

### Bagian A: kebenaran dasar dan skenario jinak

1. **Pisahkan penyusun dan pemeriksa.** Minta satu rekan, atau dirimu sendiri seminggu sebelumnya, menjalankan skenario di bawah dan menulis setiap langkah beserta jamnya ke `kebenaran-dasar.md` yang disimpan di luar folder kasus dan tidak dibuka sampai Bagian F. Bila kamu menjalankan sendiri, tunda analisis minimal beberapa hari supaya kamu membaca artefak, bukan ingatan.
2. **Pengguna.** Login konsol `LAB-WS01` sebagai `lab.user`. Ketik `\\LAB-DFIR01\lab-src` di address bar Explorer, salin `uji-lab.zip` ke Downloads, buka ZIP, jalankan `uji-lab.js` dari dalamnya. Colok `LAB-USB`, buat folder `E:\LAB`, salin `C:\Users\lab.user\Documents\rahasia-lab.txt` ke sana lewat Explorer, lalu buka salinannya dari `E:`. Cabut `LAB-USB`, kunci layar.
3. **Penyerang tiruan.** Sekitar satu jam kemudian, dari `LAB-WS02` lakukan RDP ke `172.16.50.10` dengan `lab.user`. Jalankan satu `powershell.exe -EncodedCommand` jinak yang membuat `C:\Users\lab.user\AppData\Roaming\LabCache\beacon20.ps1` (isinya satu `Invoke-WebRequest` ke `http://172.16.50.20:8080/` lalu selesai) dan mendaftarkan task `\LabTask20` yang menjalankan `powershell.exe -NoProfile -File` ke file itu setiap 5 menit. Putuskan sesi RDP tanpa sign out.
4. **Responder.** Sekitar 20 menit kemudian, di konsol `LAB-WS01`, Switch user ke `lab.ir`. Colok `LAB-IR20`, catat nomor seri volumenya dengan `vol F:`, lalu lanjut ke Bagian B.

### Bagian B: keputusan akuisisi dan koleksi

5. **Keputusan tertulis.** Sebelum menyentuh apa pun, tulis di case notes: pertanyaan yang ingin dijawab, hipotesis termasuk tandingannya ("aktivitas sah pengguna"), urutan pengambilan menurut order of volatility, dan apa yang sengaja tidak diambil beserta risikonya (Day 01 bagian 1.3 dan 1.6).
6. **Memori lokal (M1).** Dari `F:\tools\` jalankan WinPmem ke `F:\LAB020-M1_LAB-WS01.raw`, catat jam mulai dan selesai, lalu hitung SHA-256 di host dengan `certutil -hashfile` sebelum media dicabut (Day 14 bagian 1.1 dan 1.2).
7. **Variasi memori jarak jauh (M2).** Ulangi akuisisi dari `LAB-VELO01` dengan artifact `Windows.Memory.Acquisition` ke client `LAB-WS01` (pasang client lebih dulu, dan catat pemasangannya sebagai jejak responder). Bandingkan durasi, ukuran, tempat hash dihitung, dan jejak yang ditinggalkan masing-masing cara. Langkah ini meniru keputusan yang dihadapi PT JAB untuk host yang jauh (bagian 1.11).
8. **Triage dan hunt.** Jalankan KAPE dari `LAB-IR20` dengan target `!SANS_Triage` ke `F:\LAB020-K1\` dengan `--vhdx`, lalu dari `LAB-VELO01` jalankan hunt berlabel `lab-020` ke kedua host dengan `Windows.System.TaskScheduler` dan `Windows.Triage.Targets` (`_Live`, `EventLogs`). Sign out `lab.ir`, cabut `LAB-IR20`.
9. **Image dan master.** Matikan `LAB-WS01` dengan shutdown normal. Di `LAB-DFIR01`, salin disk VM, M1, M2, container KAPE, dan ekspor hunt ke `evidence\` sebagai master, hitung SHA-256, buat salinan kerja di `work\`, verifikasi, dan isi evidence log satu baris per bukti (Day 02 bagian 1.5 dan 1.6).

### Bagian C: analisis berwaktu

10. **Batas 90 menit.** Mulai pengukur waktu. Jawab tujuh pertanyaan berikut hanya dengan peta konsep bagian 1.7 dan tabel bagian 1.8 sebagai bantuan, tanpa membuka Day lain. Setiap jawaban memuat artefak, nilai, waktu UTC dan WIB, pelaku, keyakinan, dan satu kalimat keterbatasan.
    1. Program apa yang dijalankan di bawah akun `lab.user`, kapan, dan mana yang terbukti dijalankan, bukan hanya ada?
    2. Apakah `LAB-WS01` dimasuki dari host lain, dari mana, dengan metode apa, dan apa buktinya di sisi sumber?
    3. Persistence apa yang dipasang, kapan, dan oleh proses apa?
    4. Ke mana host berkomunikasi secara berkala, dari proses apa, dengan interval berapa?
    5. Media lepasan apa yang tersambung, di sesi siapa, dan berkas apa yang bisa dikaitkan dengannya?
    6. Mana jejak responder, dan apa dasar pemisahannya?
    7. Apa yang tidak bisa dijawab dari bukti yang ada, dan sumber apa yang bisa menjawabnya?
11. **Tandai keraguan.** Untuk setiap pertanyaan, tulis artefak yang kamu pilih dan beri tanda pada pilihan yang kamu ragukan sebelum melihat hasilnya.

### Bagian D: memori dan korelasi lintas sumber

12. Dari salinan kerja M1, jalankan `windows.info`, `windows.pslist`, `windows.psscan`, `windows.cmdline`, `windows.netscan`, dan `windows.malware.malfind` (Day 14 bagian 2.2, Day 15 bagian 2.2, Day 16 bagian 2.2). Tulis jendela akuisisi dari case notes, bukan dari `SystemTime`.
13. Tautkan minimal satu temuan memori ke disk dan event log dengan tiga kunci: PID, waktu dibuat, dan command line atau tujuan koneksi (Day 14 bagian 2.7). Tulis juga satu hal yang terlihat di event log tetapi mustahil ada di memori, dan alasannya.
14. Bandingkan M1 dan M2: apakah daftar proses dan sisa koneksi sama, dan bagian mana yang berbeda karena waktu akuisisinya berbeda?

### Bagian E: garis waktu dan laporan ringkas

15. Susun garis waktu kurasi dengan kolom UTC, WIB, Sumber, Kejadian, dan Pelaku. Bila `LAB-TL01` tersedia, buat super-timeline dengan Plaso dari image disk dan catat setiap keputusan filter dan tagging (Day 13 bagian 2.5); bila tidak, susun dari CSV EZ Tools di Timeline Explorer.
16. Tulis laporan ringkas dua halaman dengan format Day 19: ringkasan untuk pembaca non-teknis, temuan dengan keyakinan dan keterbatasan, pemisahan fakta, interpretasi, dan pendapat, serta lampiran bukti dan hash.
17. Tulis lembar batas bukti untuk `LAB-WS01` dengan susunan Day 12 bagian 1.11.

### Bagian F: bandingkan dengan kebenaran dasar dan variasi

18. Buka `kebenaran-dasar.md`. Untuk setiap langkah yang terlewat atau salah, tulis penyebabnya dengan salah satu dari tiga label: tekanan waktu (kamu tahu caranya tetapi tidak sempat), belum dikuasai (kamu tidak tahu artefak atau caranya), atau tidak ada sumbernya (artefak memang tidak mencatatnya). Label ketiga adalah padanan lab untuk celah lingkungan di bagian 1.11.
19. **Variasi lingkungan miskin.** Ulangi Bagian A sampai C dari snapshot `LAB-WS01` dengan audit bawaan dan tanpa Sysmon. Tulis ulang jawaban pertanyaan 3 dan 4 dari artefak yang tersisa dan tandai keyakinan yang turun. Ini padanan lab untuk `BDG-WS-0163` dan `JKT-WS-0412`.
20. **Variasi tanpa batas waktu.** Kerjakan ulang pertanyaan yang gagal di Bagian C tanpa pengukur waktu. Yang berhasil tanpa batas waktu masuk label "tekanan waktu", dan bahannya latihan skenario berwaktu; yang tetap gagal masuk "belum dikuasai", dan bahannya lab ulang Day asalnya.

### Contoh kerangka solusi (buka setelah mencoba sendiri)

<details><summary>Pemetaan pertanyaan Bagian C ke artefak</summary>

1. Prefetch `WSCRIPT.EXE` dengan `uji-lab.js` di file yang dirujuk dan BAM di bawah SID `lab.user` untuk eksekusi dan akun; Sysmon 1 untuk command line. Amcache dan Shimcache hanya keberadaan. `powershell.exe` dari task berjalan di bawah akun yang sama, sehingga akun saja tidak memisahkan pengguna dari penyerang tiruan; pemisahnya rantai induk dan waktu (Day 07 bagian 1.8, Day 05 bagian 1.2).
2. Di `LAB-WS01`: 4624 type 10 dari `172.16.50.11`, RemoteConnectionManager 1149, LocalSessionManager 25 (sesi terkunci diambil alih) dan 24 saat diputus. Di `LAB-WS02`: `Terminal Server Client\Default` `MRU0` `172.16.50.10` dan Prefetch `MSTSC.EXE` pada menit yang sama (Day 11 bagian 1.2 dan 1.3).
3. Task `\LabTask20`: XML di `Tasks\`, TaskScheduler 106, 4698 dengan `ClientProcessId` sama dengan PID PowerShell di Sysmon 1, `Tree` dan `Tasks` di TaskCache, `$J` `FileCreate` untuk `beacon20.ps1` (Day 11 bagian 1.1).
4. Sysmon 3 ke `172.16.50.20:8080` setiap 5 menit dari `powershell.exe` dengan PID berbeda tiap run, TaskScheduler 200/201 pada detik yang sama, dan sisa koneksi di `windows.netscan` M1. Interval dibaca dari Sysmon, bukan dari memori yang hanya memuat satu atau dua titik (Day 16 bagian 1.2).
5. `LAB-USB` di USBSTOR, `0065` sampai `0067`, `MountPoints2` di NTUSER `lab.user`, event 1006; `rahasia-lab.txt.lnk` dengan VolumeID yang cocok dengan nomor seri volume `LAB-USB` di event 1006; ShellBags `E:\LAB`. Penyalinan ke `E:` disimpulkan dari nama dan ukuran yang sama ditambah waktu pembuatan di volume FAT32 bila media tersedia; `$J` volume C: tidak melihat penulisan ke `E:` (Day 17 bagian 1.5 dan 1.6). `LAB-IR20` juga muncul di registry, tetapi di sesi `lab.ir`.
6. Sesi `lab.ir` terpisah, `LAB-IR20` dengan nomor seri volume yang cocok dengan `vol F:`, WinPmem dan driver-nya, `certutil`, client dan service Velociraptor, hunt `lab-020`. Dasar: case notes dengan jam, akun dan SID lokal, nomor seri volume media bukti, dan hash toolkit (Day 12 bagian 1.9).
7. Isi `rahasia-lab.txt` di `LAB-USB` setelah dicabut (butuh media), apa yang dilakukan penyerang tiruan di sesi RDP di luar proses yang tercatat, dan seluruh isi trafik ke server web lab (butuh log server web di `LAB-DFIR01`).

</details>

<details><summary>Garis waktu kurasi (ilustrasi)</summary>

Keluaran ilustrasi untuk lab Sabtu 2026-11-14; PID, Logon ID, dan jam akan berbeda di lab-mu. UTC = WIB dikurangi 7 jam.

```
UTC                  WIB       Sumber                                    Kejadian                                        Pelaku
2026-11-14 02:00:05  09:00:05  Security 4624 type 2                      lab.user login konsol LAB-WS01                  pengguna
2026-11-14 02:03:10  09:03:10  TypedPaths + ShellBags (NTUSER)           \\LAB-DFIR01\lab-src diketik dan dibuka         pengguna
2026-11-14 02:03:22  09:03:22  $J FileCreate + Sysmon 11                 Downloads\uji-lab.zip                           pengguna
2026-11-14 02:04:01  09:04:01  ShellBags + LNK + Jump List               uji-lab.zip dibuka di Explorer                  pengguna
2026-11-14 02:04:09  09:04:09  Prefetch WSCRIPT.EXE + BAM + Sysmon 1     uji-lab.js dari folder sementara                pengguna
2026-11-14 02:10:30  09:10:30  Partition/Diagnostic 1006 + 0066          LAB-USB tersambung, sesi lab.user               pengguna
2026-11-14 02:11:20  09:11:20  ShellBags (UsrClass)                      E:\LAB dilihat                                  pengguna
2026-11-14 02:11:40  09:11:40  LNK rahasia-lab.txt.lnk                   rahasia-lab.txt dibuka dari E: (VSN LAB-USB)    pengguna
2026-11-14 03:20:15  10:20:15  LAB-WS02: MRU0 + Prefetch MSTSC.EXE       tujuan 172.16.50.10                             penyerang (tiruan)
2026-11-14 03:20:18  10:20:18  1149 + 4624 type 10 + LSM 25              RDP dari 172.16.50.11, sesi lab.user diambil    penyerang (tiruan)
2026-11-14 03:22:30  10:22:30  Sysmon 1                                  powershell.exe -EncodedCommand ..., PID 6240    penyerang (tiruan)
2026-11-14 03:22:33  10:22:33  $J FileCreate + Sysmon 11                 LabCache\beacon20.ps1                           penyerang (tiruan)
2026-11-14 03:22:35  10:22:35  4698 + TS 106 + TaskCache Tree            \LabTask20, ClientProcessId 6240                penyerang (tiruan)
2026-11-14 03:24:10  10:24:10  LSM 24                                    sesi RDP diputus                                penyerang (tiruan)
2026-11-14 03:27:35  10:27:35  TS 200 + Sysmon 1                         run task pertama, powershell.exe PID 7316       penyerang (task)
2026-11-14 03:27:38  10:27:38  Sysmon 3                                  PID 7316 ke 172.16.50.20:8080                   penyerang (task)
2026-11-14 03:45:02  10:45:02  Security 4624 x2 + 4672                   lab.ir type 2, pasangan elevated                responder
2026-11-14 03:46:20  10:46:20  Partition/Diagnostic 1006                 LAB-IR20, VSN cocok dengan "vol F:"             responder
2026-11-14 03:47:05  10:47:05  Sysmon 1 + System 7045                    winpmem_mini_x64.exe PID 7712 + driver (M1)     responder
2026-11-14 03:47:35  10:47:35  TS 200 + Sysmon 1                         run task, powershell.exe PID 8120               penyerang (task)
2026-11-14 03:47:38  10:47:38  Sysmon 3 + netscan M1 (CLOSED)            PID 8120 ke 172.16.50.20:8080                   penyerang (task)
2026-11-14 03:52:40  10:52:40  case notes                                WinPmem selesai; certutil 10:53:30              responder
2026-11-14 03:58:10  10:58:10  System 7045                               service velociraptor (client lab)               responder
2026-11-14 04:12:30  11:12:30  Security 4647                             lab.ir sign out                                 responder
```

Rekonstruksi: pengguna mengambil arsip dari share, menjalankan isinya lewat Explorer, dan menyalin satu dokumen ke flashdisk. Satu jam kemudian sesi yang sama diambil alih lewat RDP dari `LAB-WS02`, dan penyerang tiruan memasang task yang menghubungi server web lab setiap 5 menit. Responder masuk dengan sesi terpisah, mengambil memori dari media bukti, memasang client Velociraptor, dan menjalankan hunt. Tiga hal yang perlu kamu temukan sendiri: run task 10:47:35 jatuh di tengah jendela akuisisi M1 (10:47:05 sampai 10:52:40), sehingga PID 8120 terlihat di `psscan` dengan Exit Time beberapa detik setelah dibuat dan sisa koneksinya terlihat `CLOSED` di `netscan`, sedangkan run sebelumnya tidak terlihat sama sekali; WinPmem muncul di `pslist` dengan nama terpotong `winpmem_mini_x`; dan selang lima menit antar run dibaca dari Sysmon 3 dan TaskScheduler 200, bukan dari memori. Di snapshot audit bawaan (Bagian F), baris Sysmon, 4698, 106, dan 200 hilang; yang tersisa untuk task adalah XML, TaskCache, dan `$MFT`, dan untuk koneksi hanya sisa di memori dan log server web lab.

</details>

**Hasil yang sebaiknya tersimpan:**

- `kebenaran-dasar.md` (dibuka hanya di Bagian F) dan case notes `CASE-2026-LAB-020` dengan keputusan akuisisi, jam setiap tindakan responder, dan yang sengaja tidak diambil.
- Evidence log, hash master dan salinan kerja untuk image disk, M1, M2, container KAPE, dan ekspor hunt; catatan perbandingan M1 dan M2 (durasi, ukuran, tempat hash dihitung, jejak).
- Jawaban tujuh pertanyaan Bagian C dengan tanda keraguan, dan waktu yang benar-benar terpakai.
- Satu temuan memori yang tertaut ke disk dan event log dengan PID, waktu, dan tujuan koneksi.
- Garis waktu kurasi, laporan ringkas format Day 19, dan lembar batas bukti `LAB-WS01`.
- Tabel selisih dengan kebenaran dasar berlabel "tekanan waktu", "belum dikuasai", atau "tidak ada sumbernya", ditambah hasil variasi audit bawaan.

### Bagian G: latihan skenario dengan pembahasan

Bagian ini menjawab permintaan keempat Dimas dan dipakai untuk latihan Rudi dan Yudha. Kerjakan setiap skenario dalam 10 menit tanpa catatan, tulis kalimat temuanmu, baru buka pembahasannya. Kalimat temuan yang baik menyebut artefak, nilai, waktu dengan zona, keyakinan, dan batas klaimnya. Skenario 1 sampai 5 berasal dari latihan lama yang diperbarui; skenario 6 sampai 8 berasal dari celah di bagian 1.11. Nama host latihan (`LATIH-*`) sengaja bukan host PT JAB.

**Skenario 1.** Amcache `LATIH-WS01` memuat `C:\Users\uji\Downloads\tool.exe` dengan SHA-1. Prefetch untuk `TOOL.EXE` tidak ada. IC bertanya apakah program itu dijalankan.

<details><summary>Pembahasan</summary>

Amcache membuktikan berkas dikenal sistem, tidak selalu dijalankan. Ketiadaan Prefetch melemahkan dugaan eksekusi tetapi tidak menyingkirkannya, karena Prefetch bisa nonaktif, terhapus, atau tergeser. Periksa BAM dan UserAssist untuk akun pengguna, 4688 atau Sysmon 1 bila host mencatatnya (lihat profil cakupan dulu), dan PCA bila Windows 11. Kalimat yang bisa dipertahankan: "Berkas ada di sistem dan dikenal Amcache dengan SHA-1 X; eksekusi tidak dapat dipastikan dari Amcache saja", lalu sebut artefak tambahan yang diperiksa dan hasilnya (Day 07 bagian 1.3).

</details>

**Skenario 2.** Berkas `report.docx` di `LATIH-WS02` punya SI Created 2023-01-05 dan FN Created 2026-09-30. Rekan menulis "timestomping terkonfirmasi".

<details><summary>Pembahasan</summary>

Belum terkonfirmasi. FN ditulis kernel saat berkas dibuat, dipindah, atau di-rename dan lebih sulit diubah dari user mode, sehingga SI yang jauh lebih tua dari FN adalah indikasi, bukan bukti: penyalinan dengan alat yang mempertahankan timestamp dan ekstraksi arsip menghasilkan pola serupa. Cek `$J` untuk berkas itu: `FileCreate` pada waktu nyata lalu `BasicInfoChange` tanpa perubahan isi beberapa detik kemudian menguatkan manipulasi; periksa juga subdetik SI, asal berkas (LNK dan ShellBags ke lokasi asal), dan jejak alat timestomp di artefak eksekusi (Day 08 bagian 1.3).

</details>

**Skenario 3.** `windows.malware.malfind` pada image memori `LATIH-WS03` menandai 14 region RWX di `msedge.exe` dan satu region RWX berheader `MZ` di `rundll32.exe`.

<details><summary>Pembahasan</summary>

Browser berbasis Chromium memakai JIT, sehingga region RWX di sana umum dan tidak bermakna tanpa sinyal lain; pembanding lab dengan versi browser yang sama menyelesaikan sebagian besar keraguan. `rundll32.exe` tidak memakai JIT, dan region privat ber-`MZ` di sana adalah kandidat kuat. Nilai dengan command line dan induk `rundll32.exe`, DLL yang dimuat dan path-nya, handle, dan koneksi di `netscan`, lalu cari pasangannya di disk (Prefetch, Amcache) dan event log. Hasil plugin tetap ditulis sebagai kandidat sampai sinyal itu saling mengunci (Day 15 bagian 1.1 dan 1.7).

</details>

**Skenario 4.** Security log `LATIH-SRV01` berisi event hanya sejak kemarin pukul 22:14, dan event pertamanya 1102.

<details><summary>Pembahasan</summary>

Log dibersihkan pukul 22:14 oleh akun yang tercatat di 1102; semua event Security sebelum itu di host ini hilang. Pembersihan adalah temuan tersendiri. Cari salinan di luar host (SIEM, log forwarding), periksa 104 di System untuk channel lain, dan andalkan artefak yang tidak terhapus (Prefetch, `$MFT`, `$J`, registry). Kalimat yang benar menyebut jendela yang hilang, bukan "tidak ada logon sebelum 22:14" (Day 05 bagian 1.6).

</details>

**Skenario 5.** Kamu hanya punya triage KAPE laptop karyawan yang mengundurkan diri. HR bertanya apakah karyawan itu "mengirim data ke kompetitor".

<details><summary>Pembahasan</summary>

Pertanyaan itu memuat penerima dan niat, dua anak tangga yang tidak bisa dijawab artefak endpoint. Pecah ke tangga bukti: berkas apa yang diakses (butuh log file server), dibuka (LNK, Jump List), disalin ke media apa (rantai USB), dan jalur keluar apa yang terlihat (proxy, gateway email, di luar host). Pastikan dulu ada memo lingkup dari Legal. Laporkan anak tangga yang diperiksa, sampai mana bukti membawa, dan nyatakan bahwa penerima dan niat di luar cakupan bukti (Day 17 bagian 1.2 dan 1.4).

</details>

**Skenario 6.** Pukul 02:00 kamu on-call. EDR memberi alert beacon dari `LATIH-WS04`, laptop Jakarta ber-EDR dengan RAM 16 GB, pengguna sedang dinas di luar kota. IC ingin host diisolasi sekarang. Pilihan:

- A. Isolasi dulu, lalu ambil memori lewat live response dengan `getfile` atas file raw sekitar 18 GiB.
- B. Ambil paket investigasi dan memori lewat live response dengan prosedur image terkompresi dan pemecahan file yang sudah diuji di lab, hitung hash di host, lalu isolasi; catat semua perintah sebagai jejak responder.
- C. Matikan laptop dari jarak jauh supaya beacon berhenti, lalu image disk saat pengguna kembali.

<details><summary>Pembahasan</summary>

B, dengan syarat prosedurnya sudah teruji; bila belum, lakukan B sebaik mungkin dan tulis risikonya di case notes, lalu eskalasi. Koneksi aktif dan tahap kedua di memori hanya terlihat selama proses hidup dan sebelum isolasi memutus koneksinya. A keliru karena `getfile` dibatasi 3 GB dan 30 menit per perintah [S11], sehingga file raw sebesar itu tidak bisa ditarik utuh; isolasi lebih dulu juga mengubah state koneksi yang ingin dilihat. C keliru karena mematikan host menghapus memori dan tidak memberi bukti apa pun tentang proses pemilik beacon. Skenario ini adalah celah "akuisisi memori jarak jauh" di bagian 1.11 (Day 18 bagian 2.1).

</details>

**Skenario 7.** Di `LATIH-WS05`, laptop kantor cabang yang tidak menerima GPO audit Jakarta, ditemukan file XML task baru di `C:\Windows\System32\Tasks\` dan key di TaskCache. Tidak ada 4698 dan tidak ada event TaskScheduler. TL meminta kalimat "task dibuat oleh proses X pada pukul Y".

<details><summary>Pembahasan</summary>

Waktu pendaftaran bisa ditulis dari `RegistrationInfo` di XML, last write key `Tree` di TaskCache, dan FN `$MFT` file XML; tiga sumber yang sepakat memberi keyakinan tinggi untuk waktu. "Proses X yang membuat" tidak bisa ditulis dari event log, karena host tidak dikonfigurasi mencatat 4698 dan channel TaskScheduler mati; ketiadaan itu adalah batas konfigurasi, bukan petunjuk bahwa task dibuat sebelum insiden. Bila host ber-EDR, process timeline EDR atau paket investigasi bisa menjawab; bila tidak, tulis "proses pembuat tidak tercatat di host ini" dan masukkan celah audit ke laporan (Day 18 bagian 2.4, Day 05 bagian 1.5).

</details>

**Skenario 8.** Memori `LATIH-WS06` diambil sekitar 16 jam setelah firewall mencatat exfil ke `198.51.100.250`. `windows.netscan` hanya menunjukkan satu sisa koneksi `CLOSED` ke IP itu, kolom Owner N/A. Manajer bertanya proses mana yang mengirim data.

<details><summary>Pembahasan</summary>

Memori tidak bisa menjawabnya. Sisa koneksi tanpa pemilik membuktikan host pernah membuat koneksi ke IP itu (cocok dengan log firewall), tetapi pemiliknya tidak terbaca, dan proses yang mungkin sudah berakhir jauh sebelum jendela akuisisi. Jangan menebak pemilik dari proses lain yang kebetulan berkomunikasi ke luar. Cari dari sumber dengan jendela panjang: Sysmon 3 dan 22, EDR network events, SRUM untuk volume per aplikasi per jam, dan artefak eksekusi pada jam exfil. Bila semuanya tidak menjawab, kalimat akhirnya "proses pengirim tidak teridentifikasi", dengan sumber yang sudah diperiksa (Day 16 bagian 1.3).

</details>

### Bagian H: menilai kesiapan dirimu

Bagian ini menerapkan tiga tingkat di bagian 1.12 ke dirimu sendiri. Tabel berikut tidak diisi di catatan ini; ia menunjukkan cara mengukur tiap area dan target minimum untuk peran eskalasi forensik. Tulis hasil penilaianmu di catatan pribadi bertanggal, supaya bisa dibandingkan dengan penilaian berikutnya.

| Area | Day | Cara mengukur | Target |
|---|---|---|---|
| Keputusan akuisisi dan CoC | 01 | Tulis keputusan akuisisi dua host berbeda dalam 15 menit, lengkap dengan yang tidak diambil dan risikonya | Mahir |
| Lab dan pembekuan versi | 02 | Inventaris versi dan uji regresi satu alat baru tanpa catatan | Bisa melakukan |
| Triage KAPE dan Velociraptor | 03, 04 | Bagian B langkah 8 tanpa catatan; hasil negatif hunt ditulis dengan cakupannya | Mahir |
| Event log | 05 | Profil cakupan dan sesi logon satu host dalam 30 menit | Mahir |
| Artefak disk | 07-11 | Pertanyaan 1, 2, 3, dan 5 Bagian C dalam batas waktu | Mahir |
| Super-timeline | 13 | Corong tagging yang bisa diulang orang lain dari catatanmu | Bisa melakukan |
| Memori | 14-16 | Bagian D dalam 45 menit, termasuk satu korelasi ke disk | Bisa melakukan, menuju mahir |
| Kasus dan laporan | 17-19 | Laporan ringkas Bagian E dibaca orang lain tanpa menemukan kalimat yang lebih kuat dari bukti | Mahir |
| Latihan skenario | 01-19 | Skenario 1 sampai 8 Bagian G masing-masing dalam 10 menit | Minimal enam dari delapan benar dengan batas yang tepat |

Dua aturan pengukuran: ukuran yang dipakai adalah hasil skenario berwaktu dan pembacaan orang lain, bukan perasaan sudah paham; dan area yang gagal karena "tidak ada sumbernya" (Bagian F) tidak dihitung sebagai kelemahanmu, tetapi dicatat sebagai contoh celah lingkungan.

### Bagian I: rencana memperkuat kelemahan pribadi dan portofolio

Susun rencana dari Bagian H dengan kolom: area, tingkat saat ini, tindakan spesifik, dan cara mengukur ulang. Tindakan yang spesifik menyebut apa persisnya: mengulang lab Day tertentu dengan variasi yang belum dicoba, mengerjakan dataset publik, atau skenario buta yang disiapkan orang lain. Dua jenis dataset publik cocok untuk latihan tanpa data kerja:

- **Dataset referensi terdokumentasi.** Portal CFReDS dari NIST menyediakan image forensik terdokumentasi untuk menguji alat dan berlatih; sebagian besar dataset disertai deskripsi artefak penting dan lokasinya [S12]. Cocok untuk mengukur apakah alat dan pembacaanmu menemukan yang memang ada.
- **Kasus latihan berbentuk insiden.** Kasus komunitas seperti "The Stolen Szechuan Sauce" dari DFIR Madness menyediakan image disk dan memori domain controller Windows Server 2012 dan desktop Windows 10, output Autoruns, dan satu PCAP, dengan pertanyaan inti tentang titik masuk, malware, infrastruktur penyerang, lateral movement, dan pencurian data, serta jawaban terpisah [S13]. Cocok untuk Bagian C versi lebih besar; pilih tingkat kesulitan yang hanya memberi disk untuk melatih batas tanpa memori. Beberapa komentar 2026 di halaman itu melaporkan tautan PCAP tidak selalu bisa diunduh, jadi cek ketersediaannya.

Portofolio yang meyakinkan untuk interview:

- Dua tulisan kasus dari versi lab Day 17 dan Day 18 dengan format laporan Day 19, termasuk bagian keterbatasan yang jujur.
- Satu tulisan publik dari dataset publik, tanpa data kerja atau klien, yang menunjukkan cara kerja dan batas, bukan hanya jawaban.
- Catatan lab yang menunjukkan versi alat, perbedaan perilaku antar versi yang kamu ukur sendiri, dan satu contoh "hasil negatif yang ditulis dengan benar".
- Satu peta kemampuan versi pribadi dengan struktur bagian 1.10: apa yang bisa kamu kerjakan sendiri, dengan syarat apa, dan dasar kasus atau lab-nya.

### Troubleshooting gabungan

Tabel ini memuat masalah yang muncul saat seluruh rangkaian Day 01-19 dipakai dalam satu kasus atau satu rencana. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Bingung memilih artefak di bawah tekanan | Tabel master belum dilatih per pertanyaan | Latih pemetaan pertanyaan ke artefak dengan bagian 1.8 dan Bagian G |
| Kesimpulan lebih kuat dari bukti | Fakta, interpretasi, dan pendapat tidak dipisah | Templat temuan Day 17 dan 18, bahasa keyakinan Day 19 |
| "Tidak ditemukan" di host tanpa audit | Profil cakupan tidak dibuat | Hitung event per subcategory dulu (Day 05 bagian 2.7) |
| Timeline salah urut atau bergeser tujuh jam | Kolom waktu lokal dicampur UTC, atau jam host tidak dikalibrasi | Zona per kolom, kolom jam sumber dan selisih terukur (Day 13 bagian 1.3) |
| Plugin memori gagal di host baru | Symbol table untuk build atau `tcpip.sys` tidak ada di cache offline | Siapkan cache per build (bagian 1.13 nomor 5; Day 14 bagian 1.3) |
| Memori tidak bisa ditarik lewat live response | File melebihi batas `getfile` 3 GB atau 30 menit [S11] | Image terkompresi dan pemecahan file yang sudah diuji; atau akuisisi lokal ke media bukti (Day 18 bagian 2.1) |
| Hasil plugin dilaporkan sebagai temuan | Plugin dibaca sebagai bukti, bukan kandidat | Pembanding lab dan sinyal yang saling mengunci (Day 15 bagian 1.7) |
| Jejak responder muncul sebagai temuan | Case notes tidak dicocokkan | Dua jangkar per jejak (Day 12 bagian 1.9) |
| Kemampuan dinilai dari alat yang dimiliki | Peta kemampuan tanpa dasar kasus | Tiga status dengan kolom dasar dan syarat (bagian 1.10) |
| Celah yang sama muncul lagi di kasus berikutnya | Celah dicatat per laporan, tidak pernah dibaca berdampingan | Tabel celah berulang dan rencana berpemilik (bagian 1.11 dan 1.13) |
| Lambat di skenario berwaktu | Kurang latihan berwaktu, bukan kurang paham | Skenario 10 menit berkala; label "tekanan waktu" di Bagian F |
| Penilaian kesiapan selalu "sudah bisa" | Diukur dengan perasaan | Ukur dengan skenario berwaktu dan pembacaan orang lain (Bagian H) |

## 5. Kesalahan umum dan jebakan

Kesalahan berikut muncul di lebih dari satu blok Day 01-19, atau baru terlihat saat semua blok dipakai bersama; tiap butir menyebut Day asalnya.

- Menulis "tidak ditemukan" untuk sesuatu yang tidak diambil, atau "tidak terjadi" untuk sesuatu yang tidak dikonfigurasi untuk dicatat (Day 03, 05).
- Menyebut Shimcache atau Amcache sebagai bukti eksekusi, atau membaca delapan waktu Prefetch sebagai seluruh riwayat (Day 07).
- Menyimpulkan "tidak dibaca" dari `$J` yang kosong atau dari artefak shell yang kosong; keduanya tidak pernah melihat pembacaan oleh skrip (Day 08, 10).
- Membaca hive dari koleksi live tanpa replay transaction log, sehingga jejak menit terakhir, sering milik responder sendiri, hilang (Day 09).
- Menyamakan `MountPoints2` dengan orang yang mencolok, atau nomor seri volume di LNK dengan nomor seri perangkat (Day 09, 17).
- Mengandalkan satu artefak untuk persistence atau lateral movement, dan melupakan WMI (Day 11).
- Menggeser timestamp untuk mengoreksi jam host, atau mengonversi kolom yang sudah waktu lokal (Day 13).
- Membuang baris timeline lewat filter tanpa mencatat keputusannya, termasuk membuang detak task yang sebenarnya bukti (Day 13).
- Memakai memori untuk menjawab kejadian sebelum jendela akuisisi, atau mempercayai `SystemTime` sebagai jam akuisisi (Day 14).
- Melaporkan hasil malfind atau psxview sebagai temuan tanpa pembanding JIT, antivirus, dan proses yang sudah berakhir (Day 15).
- Mengutip "tidak menemukan akses ke LSASS" tanpa batas waktu dan batas teknik, atau mengira Credential Guard melindungi password di skrip (Day 15).
- Menebak pemilik sisa koneksi `CLOSED` yang Owner-nya N/A (Day 16).
- Melompat dari "berkas dibuka" ke "data dicuri", atau menulis niat di laporan kasus orang dalam (Day 17).
- Menjadikan nama DLL yang juga dipakai sah di ratusan host sebagai IOC tunggal (Day 18).
- Mencampur fakta, interpretasi, dan pendapat dalam satu kalimat temuan (Day 19).
- Melaporkan jejak responder sebagai temuan, di host mana pun dan di artefak apa pun (Day 05-18).
- Menulis peta kemampuan dari daftar alat, bukan dari kasus yang sudah dikerjakan (bagian 1.10).
- Menganggap celah telemetri sebagai kelemahan analyst, lalu menutupnya dengan pelatihan, padahal yang dibutuhkan konfigurasi sebelum insiden (bagian 1.11).
- Menilai kesiapan dari jumlah Day yang sudah dibaca, bukan dari skenario berwaktu (bagian 1.12).

## 6. Catatan terkini

Bagian ini mengumpulkan status versi dan dokumen acuan per tanggal pemeriksaan 2026-10-22; narasi Day ini terjadi Januari 2027, jadi cek ulang halaman rilis sebelum rencana di bagian 1.13 dijalankan.

- **Volatility 3 2.28.2** (17 September 2026) masih rilis stabil terbaru; rilis sebelumnya 2.28.0 (30 April) dan 2.27.0 (29 Januari) [S6]. Plugin terkait malware ada di subpaket `windows.malware.*` sejak 2.26.2, dan nama lama berjalan sebagai alias usang (Day 14 bagian 6).
- **Plaso 20260720** masih rilis stabil terbaru; 20260928 berstatus pre-release untuk pengujian dan tidak dipakai untuk kasus [S7].
- **Velociraptor 0.77.3** (5 Oktober 2026) masih rilis terbaru; rilis sebelumnya 0.77.2 dan 0.76.7 (10 Agustus) [S8]. Toolkit PT JAB sudah memakai 0.77.3 sejak 2026-10-15 (Day 02 bagian 2.2).
- **Timesketch 20261014** (14 Oktober 2026), rilis sebelumnya 20260630 [S9]. Persyaratan versi Plaso minimum dan perubahan nama atribut yang dicatat di Day 13 bagian 6 perlu dicek ulang saat pilot Timesketch dimulai.
- **EZ Tools 2026.5.0** masih versi yang tercantum untuk hampir semua alat; .NET 9 adalah target bawaan, sebagian CLI juga tersedia untuk .NET 4.7.2, dan alat GUI hanya .NET 9 [S10].
- **Live response Defender for Endpoint** (ms.date 2026-07-28): `getfile` 3 GB, `putfile` 300 MB di Windows, library 250 MB, perintah umum 10 menit dan `getfile`, `findfile`, `run` 30 menit, satu perangkat satu sesi. Halaman itu juga mengingatkan bahwa di bandwidth rendah transfer bisa melewati batas waktu walaupun ukurannya di bawah batas, dan menyarankan memecah file besar [S11]. Dua hal ini adalah dasar rencana nomor 3.
- **NIST SP 800-61 Rev. 3** (April 2025) menyusun rekomendasi respons insiden sebagai Community Profile CSF 2.0 dan memetakan fase lama: Preparation ke Govern, Identify, dan Protect; Post-Incident Activity ke kategori Improvement di Identify [S5]. Kategori ID.IM dipakai di bagian 1.13.
- **NIST SP 800-86** (2006) tetap dipakai untuk empat tahap proses forensik [S1], dan RFC 3227 (2002) untuk order of volatility [S2]; keduanya belum diganti dokumen yang lebih baru di catatan ini.
- **Day 21-26** memakai versi alat yang dicek pada tanggal penulisan masing-masing; bila versinya lebih baru dari versi beku kasus PT JAB, keputusan pembekuan di Day 02 bagian 1.3 tetap berlaku.

## 7. Cheat sheet

```
PETA        pertanyaan -> artefak -> keterbatasan -> telemetri prasyarat -> siapa (internal | dengan syarat | retainer)
TABEL       bagian 1.8: baca kolom KETERBATASAN sebelum "tidak", kolom PRASYARAT sebelum menyimpulkan dari ketiadaan
PRINSIP     siapa MENULIS artefak, apa yang TIDAK PERNAH ia lihat ; >= 2 sumber yang tidak sama-sama buta
            ada | tidak diambil | tidak ditemukan oleh ... pada ..., batas ..., keyakinan ...
AKUISISI    OOV sesuai pertanyaan ; memori dulu bila host hidup ; hash di TITIK KOLEKSI ; CoC per perpindahan
            konsol+USB (orang di lokasi) | live response (getfile 3 GB, 30 mnt; kompres/pecah, uji dulu) | agen
DISK        Prefetch/BAM = eksekusi ; Amcache/Shimcache = ada ; $J = ubah, TANPA baca/pelaku ; registry = keadaan
            shell = kerja GUI saja ; USB: 0065 first, MountPoints2 = sesi ; MRU = keluar, 4624 type 3/10 = masuk
TIMELINE    zona (sumber lokal) != jam host (selisih terukur) ; win7 tanpa mft/esedb ; corong dicatat ; detak = bukti
MEMORI      satu jendela + smear ; symbol table ; pslist vs psscan ; plugin = kandidat ; handle = saat dump saja
            netscan sisa CLOSED, Owner N/A jangan ditebak ; CG tidak lindungi password di skrip
KASUS       tangga: diakses | dibuka | disalin | keluar | NIAT (tidak dijawab) ; hipotesis tandingan diuji
            IOC atomik (hari ini) + perilaku dengan pengecualian known-good (varian berikutnya)
LAPORAN     fakta | interpretasi | pendapat ; keyakinan konsisten ; defensible = bisa diulang orang lain
CELAH       TELEMETRI (tidak bisa ditambah mundur) | ALAT dan PROSEDUR (uji di lab) | TATA KELOLA (dokumen)
PT JAB      audit/Sysmon tidak seragam | laptop tanpa EDR | memori jarak jauh belum teruji | tanpa Timesketch
            | retensi 30 hari | tanpa Audit Removable Storage | symbol offline | laporan retainer tanpa metode
KESIAPAN    paham | bisa melakukan | mahir (berwaktu, tanpa catatan, bisa jelaskan batas) ; ukur, jangan merasa
ROTASI      primary mahir di akuisisi/CoC/event log/disk ; secondary dampingi, tidak pegang bukti sendiri
RENCANA     tiap baris: tindakan + celah + PEMILIK + ukuran selesai + target ; urut: lintas kasus dan tidak retroaktif
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Sejak Oktober kita sudah membaca memori sendiri, jadi untuk kasus memori apa pun PT JAB tidak butuh retainer lagi." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Analisis memori Windows memang sudah internal dan terbukti di tiga image (E01 `INC-2026-019`, E01 `INC-2026-017`, E05 `INC-2026-026`), tetapi akuisisi memori lewat live response baru teruji untuk RAM 8 GB, server Linux seperti `jkt-billing01` masih dianalisis retainer, dan insiden SEV-1 dengan banyak host bisa melebihi kapasitas tim. Peta kemampuan ditulis per kemampuan dan per kondisi, dengan status "internal dengan syarat" untuk yang bergantung pada prosedur belum teruji. Lihat bagian 1.10.

</details>

**2. Skenario keputusan.** Minggu pertama rotasi, pukul 02:00, Yudha menerima laporan bahwa laptop di POP Bandung tanpa EDR menjalankan proses mencurigakan. Rudi sedang di jalan dan baru bisa membuka laptop 30 menit lagi. Apa yang Yudha lakukan?

- A. Memulai live response dari portal Defender untuk mengambil memori.
- B. Memandu teknisi POP lewat telepon untuk tidak mematikan laptop, mencatat jam dan kondisi, menyiapkan media bukti dan akuisisi memori sesuai panduan telepon bersama primary, lalu mengeskalasi ke primary dan eskalasi forensik.
- C. Meminta teknisi mematikan laptop supaya proses berhenti, lalu menjadwalkan image besok pagi.

<details><summary>Jawaban</summary>

B. Laptop tanpa EDR tidak bisa dijangkau live response, sehingga akuisisi memori butuh orang di lokasi, persis seperti E08 `BDG-WS-0142` yang diambil Fajar dengan panduan telepon. Secondary di bulan pertama tidak memegang media bukti sendiri dan tidak memutuskan untuk tidak mengambil memori, jadi ia menjaga host tetap hidup dan mengeskalasi. A keliru karena host tanpa sensor tidak muncul di portal. C keliru karena mematikan host menghapus memori yang mungkin satu-satunya sumber proses pemilik koneksi. Lihat bagian 1.10, 1.11, dan 1.12.

</details>

**3. Pertanyaan jebakan.** "Empat kasus punya keterbatasan yang berbeda-beda: hotel, exfil, side-loading, flashdisk. Itu kebetulan per kasus, jadi tidak perlu masuk anggaran." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Dibaca berdampingan, keterbatasan itu mengelompok ke sebab yang sama: audit dan Sysmon yang tidak seragam (`INC-2026-019`, `INC-2026-026`, dan konfigurasi sempit di `INC-2027-010`), laptop tanpa EDR, retensi pendek, akuisisi memori yang terlambat atau belum teruji dari jauh. Jawaban hampir tidak pernah berhenti karena analyst salah baca artefak, melainkan karena sumbernya tidak ada, sudah lewat, atau di luar host. Celah telemetri tidak bisa ditambah mundur, sehingga tanpa anggaran batas yang sama akan muncul di kasus berikutnya. Lihat bagian 1.9 dan 1.11.

</details>

**4. Skenario keputusan.** Dimas hanya bisa mendanai satu hal di kuartal pertama. Mana yang diusulkan paling atas?

- A. Server Timesketch, karena kerja bersama retainer lebih mudah.
- B. GPO audit yang setara `JAB-WS-Audit` di semua OU workstation Jakarta dan Bandung, karena celah itu membatasi jawaban di lebih dari satu kasus dan tidak bisa diperbaiki setelah insiden.
- C. Lisensi alat forensik komersial baru, karena alatnya lebih lengkap.

<details><summary>Jawaban</summary>

B. Audit yang tidak seragam membuat 4688, 4698, dan history Task Scheduler tidak ada di `JKT-WS-0412`, `BDG-WS-0142`, dan `BDG-WS-0163`, dan audit yang dipasang setelah insiden tidak mencatat insiden itu; biayanya juga terutama kerja konfigurasi, bukan lisensi. A tetap ada di rencana, tetapi Timesketch adalah alat penyajian yang bisa dipasang kapan saja dan tidak menambah satu pun sumber bukti. C keliru karena tidak ada keterbatasan di empat laporan yang disebabkan kurangnya fitur alat. Lihat bagian 1.11 dan 1.13.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Pak Hendra Wijaya, Direktur Teknologi, dalam tiga kalimat, kenapa kemampuan forensik PT JAB tidak cukup ditingkatkan dengan melatih analyst saja.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Analyst hanya bisa membaca apa yang dicatat laptop atau server sebelum kejadian, dan di tiga dari empat kasus terakhir sebagian laptop memang tidak dikonfigurasi mencatat proses yang dijalankan atau sudah membuang log-nya setelah 30 hari. Pengaturan pencatatan itu tidak bisa dinyalakan mundur, jadi kalau kita menunda, insiden berikutnya akan punya lubang yang sama sepandai apa pun analyst-nya. Karena itu rencana kami menaruh penyeragaman pencatatan dan pemasangan EDR di urutan pertama, lalu latihan analyst dan alat kerja sesudahnya."

Kesalahan yang sering muncul:
- Menyebut nama event ID dan alat, padahal direktur butuh hubungan antara biaya dan keputusan.
- Tidak memberi contoh dari kasus PT JAB sendiri.
- Menyiratkan analyst tidak mampu, padahal pesan intinya adalah celah lingkungan.

</details>

**6. Pertanyaan jebakan.** "Yudha sudah mengerjakan semua lab Day 01-19 dengan hasil yang benar, jadi ia siap menjadi primary on-call mulai 1 Februari." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Lab yang dikerjakan dengan catatan dan tanpa batas waktu menunjukkan tingkat "bisa melakukan", bukan "mahir". Primary on-call butuh tingkat mahir di keputusan akuisisi, chain of custody, triage, event log, artefak disk, jejak responder, dan laporan, diukur dengan skenario berwaktu tanpa catatan dan dengan pembacaan orang lain atas kalimat temuannya. Yudha juga belum pernah memegang bukti, jadi bulan pertamanya sebagai secondary yang mendampingi. Lihat bagian 1.12.

</details>

**7. Interview question (English).** "After a handful of incidents handled in-house, how would you assess your organization's endpoint forensic capability and decide what to improve first?"

<details><summary>Sample answer</summary>

"I'd build the assessment from the cases, not from the tool list. For each investigative question, like who created this scheduled task or which process talked to this IP, I map the artifacts that answer it, their limits, and the telemetry that has to exist before the incident for those artifacts to be there. Then I read the recent cases side by side and ask where each answer stopped. In my experience it rarely stops because an analyst misread an artifact; it stops because the source was never configured, was already rotated out, or lived outside the host, for example a laptop without process auditing or Sysmon, proxy logs kept for only thirty days, or memory captured too late. I split capabilities into in-house, in-house with conditions, such as remote memory capture that's only been tested on 8 GB machines, and retainer, each backed by a case. For priorities, telemetry gaps that recur across cases go first, because you can't turn logging on retroactively; tools and procedures come next and get tested in a lab; contract terms, like requiring the retainer to report methodology and tool versions, are fixed on paper. People are measured with timed scenarios, and every improvement has an owner and a definition of done."

What makes this answer strong: it grounds capability in real cases, separates environmental limits from analyst skill, explains why non-retroactive telemetry is prioritized, gives a concrete three-level status, and ends with owners and measurable outcomes rather than a wish list.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response | https://csrc.nist.gov/pubs/sp/800/86/final | primer | 2006; dirujuk 2026-10-10 | Tinggi. Empat tahap: collection, examination, analysis, reporting |
| S2 | RFC 3227: Guidelines for Evidence Collection and Archiving | https://datatracker.ietf.org/doc/html/rfc3227 | primer | 2002; dirujuk 2026-10-10 | Tinggi. Order of volatility |
| S3 | Volatility 3 documentation | https://volatility3.readthedocs.io/ | primer | 2.28.2; dirujuk 2026-10-10 | Tinggi. Symbol table dan plugin |
| S4 | Endpoint-Forensics-Notes Day 01-19 | (lokal) | rujukan internal | 2026-10-22 | Materi yang diringkas; setiap klaim teknis di bagian 1.1 sampai 1.6 mengikuti sumber di Day asalnya |
| S5 | NIST SP 800-61 Rev. 3: Incident Response Recommendations and Considerations for Cybersecurity Risk Management, A CSF 2.0 Community Profile | https://csrc.nist.gov/pubs/sp/800/61/r3/final | primer | April 2025; diakses 2026-10-22 | Tinggi. Pemetaan fase lama ke fungsi CSF 2.0; incident handler internal, kontrak, atau sesuai kebutuhan; pembagian tanggung jawab dengan penyedia; prosedur diuji dan dipakai melatih personel baru; ID.IM-01 sampai ID.IM-04 |
| S6 | GitHub volatilityfoundation/volatility3: Releases | https://github.com/volatilityfoundation/volatility3/releases | primer | 2.28.2 (17 Sep 2026); diakses 2026-10-22 | Tinggi. Urutan rilis 2.27.0, 2.28.0, 2.28.2 |
| S7 | GitHub log2timeline/plaso: Releases | https://github.com/log2timeline/plaso/releases | primer | 20260720 stabil, 20260928 pre-release; diakses 2026-10-22 | Tinggi. Status Latest dan pre-release |
| S8 | GitHub Velocidex/velociraptor: Releases | https://github.com/Velocidex/velociraptor/releases | primer | 0.77.3 (5 Okt 2026); diakses 2026-10-22 | Tinggi. Rilis terbaru dan dua rilis sebelumnya |
| S9 | GitHub google/timesketch: Releases | https://github.com/google/timesketch/releases | primer | 20261014 (14 Okt 2026); diakses 2026-10-22 | Tinggi. Rilis terbaru dan sebelumnya (20260630) |
| S10 | Eric Zimmerman tools | https://ericzimmerman.github.io/ | primer | 2026.5.0; diakses 2026-10-22 | Tinggi. Versi alat, .NET 9 bawaan, sebagian CLI .NET 4.7.2, GUI hanya .NET 9 |
| S11 | Microsoft Learn: Investigate entities on devices using live response in Microsoft Defender for Endpoint | https://learn.microsoft.com/en-us/defender-endpoint/live-response | primer | ms.date 2026-07-28; diakses 2026-10-22 | Tinggi. Batas `getfile`, `putfile`, library, timeout perintah, satu perangkat satu sesi, saran memecah file besar di bandwidth rendah |
| S12 | NIST: Computer Forensic Reference Data Set Portal (CFReDS), catatan katalog data.gov | https://catalog.data.gov/dataset/computer-forensic-reference-data-set-portal | primer (pemerintah) | issued 2022-09-07; diakses 2026-10-22 | Tinggi. Portal dataset image forensik terdokumentasi untuk uji alat dan pelatihan; sebagian besar dataset dengan deskripsi artefak dan lokasinya |
| S13 | DFIR Madness: Case 001, The Stolen Szechuan Sauce | https://dfirmadness.com/the-stolen-szechuan-sauce/ | komunitas | 2020-09-21 (lebih dari 3 tahun); diakses 2026-10-22 | Sedang. Kasus latihan dengan image disk dan memori DC Windows Server 2012 dan desktop Windows 10, Autoruns, PCAP, tingkat kesulitan, jawaban terpisah; komentar 2026 melaporkan tautan PCAP kadang gagal |

**Catatan sumber:** Day ini meringkas Day 01-19 tanpa klaim teknis baru di luar yang sudah ada di Day asalnya; detail yang bergantung versi (Prefetch di server, PCA, nama plugin Volatility, opsi Plaso) mengikuti catatan di Day asal masing-masing. Sumber baru dipakai untuk tiga hal: status versi alat per 2026-10-22 [S6] sampai [S10], batas live response yang menjadi dasar celah akuisisi memori jarak jauh [S11], dan kerangka perbaikan serta pembagian kerja dengan pihak ketiga dari NIST SP 800-61 Rev. 3 [S5], yang isinya dibaca dari naskah PDF resminya. Peta konsep di bagian 1.7, tabel master di bagian 1.8, tiga status kemampuan di bagian 1.10, pengelompokan celah di bagian 1.11, tiga tingkat kesiapan di bagian 1.12, dan urutan prioritas di bagian 1.13 adalah susunan catatan ini, bukan model resmi salah satu sumber. Ringkasan Day 19 di bagian 1.6 ditulis dari cakupan Day itu dan tidak merujuk nomor bagiannya. Semua isi PT JAB, termasuk nama Yudha Prakoso, jadwal rotasi dan latihan, rencana 2027, pemilik dan target, isi dokumen untuk Dimas, nama host latihan `LATIH-*`, dan garis waktu lab, adalah contoh fiktif.
