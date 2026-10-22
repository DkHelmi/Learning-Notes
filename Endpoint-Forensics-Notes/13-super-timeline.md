---
day: 13
title: 'Super-timeline: Plaso (log2timeline, psort, pinfo), zona waktu dan jam host, output, Timesketch, dan mengelola noise'
researched_on: 2026-10-22
versions_checked: 'Plaso 20260720 (rilis stabil terbaru per 2026-10-22; 20260928 masih pre-release); preset parser win7, win7_slow, win_gen (presets.yaml); event filter Plaso (atribut parser dihapus sejak 20230724); Timesketch 20261014 (minimum Plaso 20260720; computer_name menjadi hostname, body menjadi message_body); EZ Tools 2026.5.0 (Timeline Explorer hanya .NET 9, SrumECmd); wmi-parser v0.0.1; CLDR windowsZones (SE Asia Standard Time); Windows 11 23H2 build 22631'
---

# Day 13: Super-timeline dengan Plaso dan Timesketch (zona waktu, jam host, output, dan mengelola noise)

Cakupan: membuat, mempersempit, dan menyajikan super-timeline satu host dengan Plaso (log2timeline, pinfo, psort) dan Timesketch, termasuk kalibrasi zona waktu dan jam host, pemilihan parser, pemisahan noise dengan tagging, dan penggabungan sumber yang tidak dibaca Plaso menjadi garis waktu kurasi yang bisa dibaca orang lain.

## Ide inti

Super-timeline menaruh event berwaktu dari banyak artefak di satu sumbu waktu UTC: event log, `$MFT`, `$J`, registry, Prefetch, LNK, SRUM, dan lainnya, diurutkan menjadi satu daftar. Nilainya bukan jumlah barisnya. Nilainya ada pada dua hal yang tidak terlihat saat artefak dibaca satu per satu: urutan lintas artefak (apa terjadi sebelum apa, dengan selisih berapa detik), dan celah (jam ketika tidak ada yang tercatat, dan alasannya). Tiga hal membuat super-timeline bisa dipercaya. Pertama, setiap baris membawa sumber dan arti timestamp-nya, karena satu file menghasilkan beberapa baris dengan arti berbeda. Kedua, zona waktu dan jam host dikalibrasi sebelum urutan disimpulkan, karena sebagian artefak menyimpan waktu lokal dan jam host tidak pernah persis sama dengan jam server lain. Ketiga, setiap penyaringan dicatat sebagai keputusan yang bisa diulang, karena setiap filter bisa membuang bukti. Produk akhirnya bukan CSV jutaan baris, melainkan garis waktu kurasi: beberapa puluh baris berlabel pelaku (pengguna, penyerang, responder), ditambah daftar apa yang sengaja dikeluarkan dan apa yang memang tidak bisa dicatat oleh sumber yang ada.

Kamu sudah mengenal pola ini dari NOC saat menyusun RFO gangguan besar. Syslog router, switch, OLT, RADIUS, dan alarm NMS ditarik ke satu collector, lalu disusun menjadi satu urutan. Sebelum menyimpulkan apa pun, kamu menyamakan dulu zona waktu dan jam: ada perangkat yang mengirim waktu lokal, ada yang NTP-nya meleset beberapa detik, dan salah label zona tidak membuat galat, hanya membuat laporan salah. Lalu kamu menyingkirkan noise yang sudah dikenal: keepalive, flapping yang sudah dijelaskan, jadwal maintenance. Yang tersisa untuk RFO hanya belasan baris, masing-masing menunjuk baris log aslinya. Super-timeline forensik bekerja dengan logika yang sama, dengan dua perbedaan penting. Sebagian besar sumbernya bukan log, melainkan keadaan yang menyimpan waktu (`$MFT`, registry), sehingga satu "kejadian" bisa berarti dibuat, diubah, atau sekadar dilihat. Dan diamnya sebuah sumber sering bukan karena tidak ada kejadian, tetapi karena sumber itu memang tidak dikonfigurasi untuk mencatatnya.

```
SUMBER DI IMAGE (E16-W1)                     SUMBER DI LUAR PLASO
 evtx | $MFT | $J | hive | Prefetch           XML task (RegistrationInfo)
 LNK | Jump List | SRUM | setupapi            OBJECTS.DATA (wmi-parser)
        |                                     log DHCP dan sinkhole NOC (jam NOC)
        v                                     case notes responder
 log2timeline.py  --parsers / -f / --timezone         |
        |                                             |
        v                                             |
 .plaso (UTC) --> pinfo.py -v  (parser, jumlah, zona, peringatan)
        |                                             |
        v                                             |
 psort.py  jendela waktu + event filter + tagging     |
        |   (detak task | responder | rutin dikenal | pengguna)
        v                                             v
 CSV / JSONL --> Timeline Explorer / Timesketch --> GARIS WAKTU KURASI
                                                   waktu WIB+UTC | jam sumber | kejadian
                                                   pelaku | artefak | keyakinan | batas
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan dan data pribadi sekitar 400 ribu pelanggan broadband. Kasusnya `INC-2026-019`: lampiran `Tagihan-Okt-2026.zip` (berisi `Tagihan-Okt-2026.js`) dari `billing@vendor-tagihan.example` masuk ke sembilan mailbox Senin 2026-10-12 pukul 15:58 dan dijalankan di tiga laptop staf penagihan. Persistence-nya scheduled task `\SysCacheUpdate` yang menjalankan `C:\Users\<user>\AppData\Roaming\SysCache\upd.ps1` tiap 15 menit, dengan C2 `cdn-sync.example.net` (`203.0.113.77:443`). Laptop yang paling miskin sumber adalah `JKT-WS-0412` milik `rizky.saputra`: Windows 11 23H2 (build 22631), masih di OU `Workstations` sehingga tidak menerima GPO audit `JAB-WS-Audit` (audit bawaan, tanpa 4688 dan 4698), tanpa Sysmon, tanpa history Task Scheduler, dan tidak di-onboard ke EDR; yang aktif hanya Microsoft Defender Antivirus bawaan. Laptop itu dibawa rapat ke kantor pelanggan PT Baja Raya Contoh di Cikarang dan menginap di Hotel Kenanga Contoh. Dari salinan kerja yang sudah diolah, fakta yang dipegang: lampiran dijalankan Senin 20:14:21 WIB saat laptop tersambung ke Wi-Fi hotel (Prefetch `WSCRIPT.EXE`), `upd.ps1` dibuat 20:14:37, task terdaftar 20:14:39, event 4104 pertama 20:14:52 lalu berulang sekitar tiap 15 menit (Day 03 bagian 2.5); beacon berjalan lewat Wi-Fi hotel, Wi-Fi tamu `BajaRaya-Guest`, dan hotspot `HP-Rizky` sampai laptop masuk jaringan kabel kantor Selasa 17:10:29 (Day 09 bagian 2.4); responder menyentuh laptop itu Selasa 17:43 sampai 18:35 (memori E13 dengan `USB-E-10`, elevasi `ir-admin`, driver WinPmem, logon `adm.yoga`, KAPE E14 dari `USB-E-11`) dan mematikannya Kamis 2026-10-15 pukul 08:44:52 sebelum image E16 (Day 09 bagian 2.3 sampai 2.7). Ketiga laptop sudah di-reimage; yang tersisa image dan salinan kerjanya, termasuk `E16-W1`.

Selasa 2026-10-27 pukul 13:00 sampai 15:00 post-incident review `INC-2026-019` berlangsung dengan fasilitator Nina Kartika, memakai lembar batas bukti yang kamu kirim pagi itu (Day 12 bagian 1.11). Rabu 2026-10-28 pukul 09:00, Sari Kusuma (technical lead) menulis kepadamu di kanal `#inc-2026-019`:

> "Pagi. Kemarin Bu Nina mencatat dua action item untuk forensik. Pertama, tutup pekerjaan terbuka E16-W1 yang ada di lembar batas bukti: folder Startup dan WMI `OBJECTS.DATA` belum diperiksa, SRUM belum diolah. Kedua, laporan akhir butuh satu garis waktu gabungan laptop Rizky. Laptop itu tanpa Sysmon dan tanpa audit lengkap, jadi tidak ada satu sumber pun yang lengkap; registry, `$MFT`, Prefetch, 4104, SRUM, dan log NOC harus disatukan. Pertanyaan pokoknya: selain task `\SysCacheUpdate`, adakah aktivitas lain, entah penyerang, Rizky sendiri, atau kita, dari Senin 20:14 sampai laptop dimatikan Kamis 08:44:52? Lalu soal waktu: jam laptop lebih cepat 2 detik dari NOC, dan sebagian artefak menyimpan waktu lokal. Bagaimana menyatukannya tanpa salah urut? Terakhir, buat timeline yang bisa dibaca orang lain, termasuk retainer dan Pak Agus, bukan CSV sejuta baris. Drafnya aku tunggu Kamis jam 16:00."

Pesan itu memuat tujuh pertanyaan:

1. Sumber apa di `E16-W1` yang bisa digabung otomatis, dan sumber apa yang harus ditambahkan manual karena tidak dibaca alat super-timeline?
2. Bagaimana memastikan ekstraksi benar-benar mencakup artefak yang dibutuhkan dan bisa diulang orang lain dengan hasil yang sama?
3. Bagaimana menyatukan zona waktu, artefak yang menyimpan waktu lokal, dan selisih jam laptop +2 detik terhadap log NOC tanpa salah urut?
4. Format output apa untuk analisis, untuk retainer, dan untuk lampiran laporan?
5. Bagaimana mempersempit jutaan baris menjadi sesuatu yang bisa dibaca tanpa diam-diam membuang bukti?
6. Selain task, adakah aktivitas penyerang, pengguna, atau responder lain di jendela itu, termasuk hasil folder Startup, WMI, dan SRUM, dan bagaimana menulis hasil negatifnya?
7. Seperti apa timeline yang bisa dibaca orang lain, dan di mana Timesketch berperan?

Pertanyaan 1 dijawab di bagian 1.1 dan 1.2, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, pertanyaan 6 di bagian 1.6, dan pertanyaan 7 di bagian 1.7. Bagian 2 berisi perintah, keluaran ilustrasi, dan draf garis waktu yang kamu kirim ke Sari.

**Kapan relevan:** rekonstruksi urutan kejadian lintas artefak pada satu host, terutama host tanpa EDR atau Sysmon yang tidak punya satu sumber lengkap; penyusunan lampiran laporan akhir atau after-action report; pencarian celah dan kejadian di sekitar titik pivot yang sudah diketahui dari analisis artefak (Day 07 sampai 11); dan pekerjaan bersama dengan retainer yang perlu melihat data yang sama.
**Kapan bukan jawaban:** pertanyaan sempit yang sudah dijawab satu artefak (misalnya "kapan task dibuat", cukup XML task dan TaskCache); isi memori, proses yang berjalan, dan koneksi aktif (Day 14 sampai 16); korelasi banyak host sekaligus (Day 26); dan pertanyaan tentang isi trafik atau data yang keluar, yang dijawab log jaringan, bukan timeline disk.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (`$MFT`, `$J`, SI dan FN, MACB, Prefetch, SRUM, hive kotor, last write time, NetworkList, 4104, TaskCache, WMI event subscription, jejak responder, salinan kerja, pembekuan versi per kasus, lembar batas bukti) tidak diulang. Tabel berikut hanya memuat istilah baru Day ini; kolom padanan memakai analogi NOC dan SOC yang sama di semua Day.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Super-timeline | Gabungan event berwaktu dari banyak artefak ke satu sumbu waktu terurut | Syslog semua perangkat yang ditarik ke satu collector untuk menyusun RFO |
| Storage file `.plaso` | File hasil ekstraksi `log2timeline.py` yang menyimpan semua event dalam UTC, dibaca ulang oleh `psort.py` dan `pinfo.py` | Arsip raw syslog di collector, sebelum disaring untuk laporan |
| Parser dan plugin | Modul Plaso yang membaca satu format (misalnya `winevtx`, `mft`) atau satu bagian format (`winreg/windows_task_cache`, `esedb/srum`) | Template parsing per jenis perangkat di collector |
| Parser preset | Kumpulan parser yang dipilih otomatis sesuai sistem operasi hasil preprocessing (`win7` untuk Windows NT) | Profil polling bawaan per tipe perangkat di NMS |
| Preprocessing | Tahap awal log2timeline yang membaca informasi host dari image: nama host, sistem operasi, zona waktu, pengguna | Membaca `show version` dan konfigurasi `clock timezone` sebelum mem-parse log perangkat |
| `data_type` | Jenis event data Plaso (misalnya `windows:evtx:record`, `fs:ntfs:usn_change`) yang dipakai di filter dan tagging | Facility dan severity syslog yang dipakai untuk menyaring |
| `timestamp_desc` | Arti timestamp pada satu baris: Creation Time, Content Modification Time, Last Time Executed, dan sebagainya | Kolom jenis event di log: link down, config change, login |
| Event filter | Ekspresi psort untuk memilih event (`date`, `data_type`, `event_identifier`, `DATETIME()`) | Filter tampilan di collector syslog |
| Tagging | Analysis plugin psort yang memberi label pada event yang cocok dengan aturan di file tag | Aturan suppress dan klasifikasi alarm di NMS |
| Detak task | Baris berulang yang ditimbulkan setiap eksekusi task terjadwal (4104, file sementara PowerShell, Prefetch, SRUM) | Keepalive atau hello packet: berulang, diketahui sumbernya, menenggelamkan kejadian lain bila tidak dipisah |
| Known-good filter | Daftar pola baris rutin yang sudah dijelaskan (Windows Update, definisi Defender, cache aplikasi) dan dikeluarkan dari tampilan review | Daftar maintenance window dan flapping yang sudah punya penjelasan |
| Garis waktu kurasi | Ringkasan berlabel pelaku dan keyakinan yang menunjuk baris sumber, untuk dibaca orang lain | Bagian kronologi di RFO, tiap baris menunjuk log perangkat |
| Sketch (Timesketch) | Wadah investigasi di Timesketch berisi satu atau lebih timeline, pencarian tersimpan, tag, komentar, dan story | Satu tiket gangguan besar di platform kolaborasi NOC, lengkap dengan log terlampir dan catatan tiap engineer |

### 1.1 Super-timeline: apa yang digabung, dan apa yang tidak bisa digabung otomatis

Pertanyaan pertama Sari menyentuh hal yang sering dilewati: sebelum menjalankan alat, tentukan dulu sumber apa saja yang ada untuk laptop ini, dan mana yang tidak akan pernah muncul di timeline otomatis.

Super-timeline adalah gabungan event berwaktu dari banyak artefak ke satu garis waktu terurut [S1]. Berbeda dari timeline file system saja (hanya MFT) atau timeline event log saja (Day 05), super-timeline memadukan semuanya: MFT, USN, registry, event log, Prefetch, browser, LNK, dan lainnya. Satu baris timeline adalah satu event berwaktu dari satu artefak.

Nilainya: melihat, misalnya, Prefetch `WSCRIPT.EXE` (20:14:21), lalu file sementara PowerShell di `$J` (20:14:33), lalu `upd.ps1` dibuat di `$MFT` (20:14:37), lalu key `Tree\SysCacheUpdate` di TaskCache (20:14:39), lalu 4104 (20:14:52) dalam satu pandangan terurut, tanpa melompat antar alat. Di `JKT-WS-0412` ini lebih penting daripada di laptop Andi, karena tidak ada 4688, Sysmon, atau 4698 yang mengikat rangkaian itu dengan Process ID (Day 05 bagian 2.7). Yang mengikatnya hanya urutan dan jarak waktu antar artefak.

Untuk host ini, sumber dibagi tiga, berdasarkan hasil analisis per artefak di Day 03 sampai 12 [S7]. Tabel berikut dipakai sebagai daftar periksa sebelum ekstraksi; kolom terakhir menentukan apakah baris itu masuk timeline otomatis atau harus ditambahkan sendiri.

| Sumber | Ada di `E16-W1`? | Masuk timeline otomatis? |
|---|---|---|
| Event log (Security dengan audit bawaan, System, PowerShell/Operational, WLAN-AutoConfig, WMI-Activity, Defender) | Ya | Ya, parser `winevtx` |
| `$MFT`, `$J` | Ya | Ya, parser `mft` dan `usnjrnl` (lihat bagian 1.2 soal preset) |
| Hive SYSTEM, SOFTWARE, SAM, NTUSER, UsrClass, Amcache | Ya, bersih (Day 09 bagian 2.2) | Ya, parser `winreg` dengan plugin per key |
| Prefetch, LNK, Jump List, `setupapi.dev.log`, PCA | Ya | Ya |
| SRUM (`SRUDB.dat`) | Ya | Ya, plugin `esedb/srum`, hanya bila dipilih |
| File XML task di `C:\Windows\System32\Tasks\` | Ya | Tidak: daftar parser Plaso tidak memuat parser untuk XML task; `winjob` untuk format job lama [S9] |
| Repository WMI `OBJECTS.DATA` | Ya | Tidak: tidak ada parser repository WMI di daftar parser Plaso [S9] |
| Log DHCP server dan DNS sinkhole NOC, log email | Di luar laptop | Tidak; ditambahkan manual dengan label jam sumbernya |
| Case notes responder (Yoga, kamu) | Di `notes/` kasus | Tidak; ditambahkan manual sebagai sumber pemisah pelaku |

Konsekuensinya: garis waktu akhir selalu gabungan dua jenis baris, baris hasil Plaso dan baris manual. Baris manual bukan kelas dua, tetapi harus menyebut sumbernya sama jelasnya, termasuk jam siapa yang dipakai (laptop atau NOC).

Kapan super-timeline lebih baik daripada analisis artefak terpisah dirangkum di tabel berikut. Cari baris "Urutan lintas artefak", karena itulah alasan pekerjaan ini dilakukan untuk laptop Rizky.

| Aspek | Analisis artefak terpisah (Day 07-11) | Super-timeline |
|---|---|---|
| Pertanyaan sempit | Cepat dan langsung | Berlebihan |
| Urutan lintas artefak | Sulit (lompat antar tool) | Kuat (satu pandangan) |
| Noise | Rendah (fokus) | Tinggi (perlu dipersempit) |
| Waktu pembuatan | Cepat per artefak | Ekstraksi lambat |

Keduanya saling melengkapi: analisis artefak menjawab pertanyaan spesifik dan menemukan titik pivot; super-timeline merekonstruksi urutan di sekitar titik itu. Alur yang baik sering: triage artefak menemukan "sesuatu terjadi sekitar 20:14", lalu super-timeline dipersempit ke jendela di sekitarnya untuk melihat urutan lengkapnya, lalu jendela diperlebar untuk mencari yang belum diketahui.

### 1.2 Alur Plaso, preset parser, dan cakupan yang bisa diulang

Pertanyaan kedua Sari ("benar-benar mencakup, dan bisa diulang") dijawab dengan memahami tiga tool Plaso, cara Plaso memilih parser, dan apa yang harus dicatat.

Plaso (20260720) punya tiga tool utama [S1][S3]. Tabel berikut adalah peta kerjanya; baca kolom "Fungsi" untuk melihat kenapa ekstraksi dilakukan sekali dan output dibuat berkali-kali.

| Tool | Fungsi |
|---|---|
| `log2timeline.py` | Mengekstrak event berwaktu dari sumber (image, folder, file) ke penyimpanan `.plaso` |
| `psort.py` | Memproses `.plaso`: filter, urutkan, dedup, dan keluarkan ke format tertentu (CSV, JSON, OpenSearch untuk Timesketch) |
| `pinfo.py` | Menampilkan info tentang isi `.plaso` (parser yang jalan, jumlah event per parser, dan dengan `-v` informasi preprocessing) |

Alur: `log2timeline.py` sekali untuk mengekstrak semuanya ke `.plaso` (lambat, menyeluruh), lalu `psort.py` berkali-kali untuk menghasilkan tampilan berbeda (jendela waktu, filter, format) tanpa mengekstrak ulang. Pemisahan ini penting: ekstraksi mahal dilakukan sekali, analisis cepat diulang. Sumber yang bisa diberikan ke `log2timeline.py` adalah file, image media penyimpanan, atau folder seperti titik mount [S6]; untuk `E16-W1` yang dipakai adalah file image, supaya `$MFT`, `$J`, dan preprocessing terbaca dari volume aslinya.

**Preset: yang tidak dipilih tidak ada.** Plaso tidak menjalankan "semua parser" secara bawaan. Saat preprocessing mengenali sistem operasi, Plaso memilih preset yang cocok; `--parsers` menimpa pilihan itu [S6][S14]. File definisi preset di repo Plaso menunjukkan isinya [S10]:

| Preset | Untuk | Isi yang penting untuk kasus ini |
|---|---|---|
| `win7` | Windows NT (dipakai untuk Windows Vista dan setelahnya, termasuk Windows 11) | `winevtx`, `recycle_bin`, Jump List (`olecf/olecf_automatic_destinations`, `custom_destinations`), PCA, ditambah semua isi `win_gen` |
| `win_gen` | Template Windows | `filestat`, `lnk`, `prefetch`, `usnjrnl`, `winjob`, `winreg`, `text/setupapi`, `pe`, dan beberapa parser log aplikasi |
| `win7_slow` | Tidak dipilih otomatis | `esedb`, `mft`, ditambah `win7` |

Akibatnya langsung terasa di laptop Rizky: tanpa `--parsers`, log2timeline memakai `win7`, sehingga `$MFT` (parser `mft`) dan SRUM (`esedb/srum`) tidak diparse sama sekali. Atribut `$FILE_NAME` hanya datang dari parser `mft`, yang memproses atribut `$STANDARD_INFORMATION` dan `$FILE_NAME` setiap entry [S20]; parser `filestat` hanya memberi timestamp file yang dijelajahi lewat file system. Untuk pertanyaan Sari, `$MFT` dan SRUM justru inti, jadi ekstraksi menyeluruh memakai `win7_slow`.

**Nama parser dan plugin.** Daftar lengkap ada di keluaran `log2timeline.py --info` [S6]. Plugin ditulis dengan nama induknya, misalnya `winreg/userassist`, `text/setupapi`, atau `esedb/srum` [S6][S9]. Plugin registry yang dipakai Day ini antara lain `windows_task_cache`, `windows_run`, `windows_usbstor_devices`, `networks`, `bam`, `windows_shutdown`, dan `windows_timezone` [S9].

**Membatasi file, bukan hanya parser.** Opsi `-f` memberi file filter berisi pola path, sehingga hanya file yang cocok yang diproses; hasilnya diperiksa dengan `pinfo.py --sections sources` [S6]. Ini cara cepat membuat timeline terarah (event log, hive, Prefetch, SRUM) sementara ekstraksi menyeluruh berjalan.

**Volume dan shadow copy.** Untuk image berisi beberapa partisi, `--partitions` memilih partisi tanpa prompt, `--vss_stores` memilih shadow copy (`all`, daftar, rentang, atau `none`), dan `--unattended` membuat log2timeline berhenti dengan galat alih-alih bertanya [S6]. Memproses VSS memperbesar timeline tetapi bisa memunculkan event dari keadaan sebelum penyerang membersihkan jejak. Opsi `--logfile` menyimpan log proses (ekstensi `.log.gz` untuk log terkompresi) [S6].

**Apa yang membuat hasil bisa diulang.** Orang lain mendapat hasil yang sama bila memakai image yang sama (hash), versi Plaso yang sama (digest image Docker, bukan tag), parser atau preset yang sama, file filter yang sama, zona waktu yang sama, dan pilihan partisi serta VSS yang sama. Semua itu ditulis di case notes dan disimpan berdampingan dengan `.plaso`. Gunakan `pinfo.py` setelah ekstraksi untuk membuktikan cakupan: per parser berapa event yang dihasilkan, dan dengan `-v` informasi preprocessing termasuk zona waktu dan nama host [S12]. Parser yang menghasilkan nol event bisa berarti artefaknya tidak ada atau parser gagal; keduanya perlu dicek, bukan diasumsikan [S29].

### 1.3 Zona waktu dan jam host: dua koreksi yang berbeda

Pertanyaan ketiga Sari berisi dua masalah yang sering dicampur: zona waktu (bagaimana waktu lokal diterjemahkan ke UTC) dan jam host (apakah jam UTC laptop itu benar dibanding sumber lain).

**Plaso menyimpan UTC; zona host hanya berpengaruh pada sumber yang menyimpan waktu lokal.** Plaso menyimpan event dalam UTC secara internal [S1]. Sebagian besar artefak NTFS, registry, dan event log sudah UTC (FILETIME), tetapi beberapa sumber menyimpan waktu lokal, misalnya sebagian log teks aplikasi, log setupapi, dan beberapa format browser lama; untuk sumber seperti itu zona yang salah menggeser event beberapa jam. Di laptop Rizky, sumber waktu lokal yang sudah diketahui adalah `NetworkList` (Day 09 bagian 1.4), `setupapi.dev.log` (Day 09 bagian 2.5), dan `RegistrationInfo` di XML task (Day 03 bagian 2.5). Kesalahan zona waktu merusak seluruh timeline: event dari artefak berbeda bisa bergeser relatif satu sama lain bila sebagian ditafsirkan UTC dan sebagian lokal.

**Dari mana Plaso tahu zonanya.** Dokumentasi Plaso menyebut bahwa zona waktu diambil otomatis saat preprocessing, opsinya tetap ada, dan bila zona tidak teridentifikasi dan opsi tidak diberikan, UTC yang dipakai [S14]. Untuk image Windows, preprocessing membaca zona dari hive SYSTEM. Untuk sumber tanpa hive itu (satu file `.evtx`, folder berisi log teks, koleksi triage yang tidak membawa SYSTEM), tidak ada yang bisa dibaca, sehingga sumber berwaktu lokal diam-diam ditafsirkan sebagai UTC. Karena itu ambil zona waktu host dari registry (Day 09 bagian 2.3), berikan ke log2timeline secara eksplisit (`--timezone`, bentuk pendek `-z`; cek nama flag dengan `log2timeline.py -h` di versi lab), lalu buktikan dengan `pinfo.py -v` zona mana yang tercatat [S12]. Catat zona yang dipakai di catatan kasus.

**Nama zona Windows dan nama IANA.** Registry menyimpan nama zona Windows (`SE Asia Standard Time`), sedangkan opsi Plaso memakai nama zona gaya IANA. Tabel pemetaan CLDR memetakan `SE Asia Standard Time` ke `Asia/Bangkok` sebagai zona wakil umum, ke `Asia/Jakarta Asia/Pontianak` untuk wilayah Indonesia, dan ke `Etc/GMT-7` sebagai zona tanpa wilayah [S23]. Ketiganya UTC+7 tanpa daylight saving, jadi hasil konversinya sama; yang berbeda hanya label. Dua hal perlu diingat. Pertama, keluaran preprocessing bisa menampilkan nama yang berbeda dari yang kamu harapkan, dan itu belum tentu salah. Kedua, `Etc/GMT-7` berarti UTC+7: tanda pada zona `Etc/` sengaja terbalik, sehingga orang yang mengetik `Etc/GMT+7` karena mengira itu "GMT plus tujuh" justru mendapat UTC-7, selisih 14 jam tanpa pesan galat. Untuk kasus PT JAB, tulis `Asia/Jakarta`.

**Zona tampilan saat output.** Saat output, psort menampilkan UTC secara default; `--output-time-zone` mengubah zona tampilan untuk format seperti `dynamic` dan `l2tcsv`, dan `--output-time-zone list` menampilkan daftar zona [S5]. Ini hanya tampilan; isi `.plaso` tetap UTC. Untuk analisis, praktik yang aman adalah tetap UTC dan menyebut offset zona host sekali di bagian metodologi; untuk pembaca non-teknis, keluarkan versi WIB dengan offset tertulis di setiap timestamp, sehingga tidak ada yang perlu menebak.

**Jam host bukan masalah zona.** Selisih +2 detik yang disebut Sari adalah jam UTC laptop yang lebih cepat dari jam server NOC (registry DHCP 17:10:33 vs log DHCP server 17:10:31 pada Selasa sore; +3 detik Kamis 08:40 dibanding jam analyst; Day 09 bagian 2.3). Zona yang benar tidak memperbaiki selisih ini, dan selisih ini tidak memengaruhi urutan antar artefak di dalam laptop yang sama, karena semuanya ditulis jam yang sama. Ia baru penting saat baris laptop disandingkan dengan baris dari mesin lain: log DHCP, DNS sinkhole, log email. Aturannya:

- Jangan menggeser timestamp asli. Baris dari laptop tetap memakai jam laptop, baris dari NOC tetap memakai jam NOC, dan setiap baris diberi kolom "jam sumber".
- Saat membandingkan, terapkan selisih yang terukur dengan toleransi. Di kasus ini, kejadian di log NOC pukul X sebanding dengan kejadian di laptop sekitar X + 2 detik pada Selasa sore; untuk Senin malam, selisihnya tidak terukur langsung, sehingga pakai toleransi beberapa detik dan tulis bahwa nilai itu disimpulkan dari pengukuran Selasa dan Kamis tanpa penyetelan jam di antaranya.
- Periksa bahwa jam tidak melompat di dalam jendela. Selain 4616 di log Security (Day 09 bagian 1.3), aturan tagging bawaan Plaso memberi label `time_change` pada event System `Microsoft-Windows-Kernel-General` ID 1 [S22]; nol baris dengan label itu di jendela berarti tidak ada penyetelan jam langsung.

### 1.4 Output dan format: satu `.plaso`, beberapa bentuk untuk pembaca berbeda

Pertanyaan keempat Sari muncul karena tiga pembaca butuh bentuk berbeda: kamu untuk analisis, retainer untuk pemeriksaan ulang, dan pembaca laporan untuk memahami cerita.

psort.py mengeluarkan ke beberapa format [S1][S5]. Daftar format yang tersedia di instalasimu ditampilkan dengan `psort.py -o list` [S5]. Tabel berikut memetakan format ke pemakaiannya; cari kolom "Untuk" saat memilih.

| Format | Untuk |
|---|---|
| `dynamic` (CSV) | Dibuka di Timeline Explorer atau spreadsheet; kolom bisa dipilih |
| `l2tcsv` | Format CSV klasik log2timeline dengan 17 kolom tetap [S11] |
| `json`/`json_line` | Pemrosesan lanjut dengan skrip, dan semua atribut event ikut |
| `xlsx` | Spreadsheet untuk jumlah baris kecil [S5] |
| `opensearch_ts` | Menulis langsung ke OpenSearch milik Timesketch [S5]; butuh dependensi dan konfigurasi server |

Untuk timeline kecil, CSV di Timeline Explorer cukup. Timeline Explorer di EZ Tools 2026.5.0 hanya tersedia untuk .NET 9 [S27]. Untuk timeline besar (jutaan baris) atau kerja bersama beberapa analyst, Timesketch jauh lebih baik karena dirancang untuk pencarian dan kolaborasi atas timeline besar. Cara paling umum memasukkan data ke Timesketch adalah mengunggah file `.plaso` langsung (lewat web UI atau `timesketch_importer.py`), bukan lewat psort [S4].

Kolom penting di output `dynamic` yang perlu kamu kenali saat membaca. Kolom bawaan modul ini adalah `datetime`, `timestamp_desc`, `source`, `source_long`, `message`, `parser`, `display_name`, dan `tag`; opsi `--fields` mengganti daftar itu [S11]. Tabel berikut menjelaskan arti tiap kolom; baca baris `timestamp_desc` dua kali.

| Kolom | Arti |
|---|---|
| `datetime` | Waktu event dalam ISO 8601 dengan presisi mikrodetik dan offset zona (UTC kecuali `--output-time-zone` diubah) [S11] |
| `timestamp_desc` | Arti timestamp: `Creation Time`, `Content Modification Time`, `Last Access Time`, `Metadata Modification Time`, `Last Time Executed`, dan sebagainya |
| `source` / `source_long` | Kelompok sumber (FILE, REG, EVT, LOG) dan nama sumber yang lebih rinci |
| `message` | Ringkasan event yang dibentuk dari atribut event |
| `parser` | Parser yang menghasilkan baris itu (`mft`, `winevtx`, `prefetch`, `winreg/...`); kolom output, bukan atribut filter (bagian 1.5) |
| `display_name` / `filename` | File sumber artefak (misalnya path `$MFT` atau `Security.evtx`) |
| `tag` | Label dari analysis plugin tagging (bagian 1.5) |

`timestamp_desc` adalah kolom yang paling sering diabaikan. Satu file di MFT menghasilkan hingga delapan baris (MACB untuk SI dan FN), masing-masing dengan `timestamp_desc` berbeda; tanpa membacanya, baris `Last Access Time` bisa tertukar dengan waktu eksekusi. Opsi `--dynamic-time` membuat `datetime` mengikuti presisi asli sumbernya, sehingga nilai seperti "Not set" bisa muncul alih-alih nol palsu [S11].

**Nama atribut berubah antar versi.** Plaso 20260720 mengganti nama atribut `computer_name` menjadi `hostname` dan `body` menjadi `message_body` [S15]. Di kode parser `winevtx`, nilai nama komputer dari record event disimpan sebagai `hostname`, dengan catatan bahwa nilainya belum tentu sama dengan nama host sistem [S21]. Query, filter, atau tampilan tersimpan yang ditulis dari panduan lama dan memakai `computer_name` akan kosong tanpa galat. Sebelum menulis filter atau tagging, keluarkan beberapa baris dengan `-o json_line` dan baca nama atribut yang benar-benar ada di versi-mu.

**Format untuk lampiran.** Lampiran laporan tidak diambil langsung dari psort. Ia CSV kurasi yang ditulis analyst, dengan kolom yang sengaja dipilih supaya bisa diimpor ke Timesketch kelak: Timesketch mewajibkan `message`, `datetime` (ISO 8601, misalnya `2015-07-24T19:01:01+00:00`), dan `timestamp_desc` untuk impor CSV atau JSONL [S16]. Kolom tambahan (pelaku, sumber, keyakinan, jam sumber) ikut terbawa sebagai atribut.

### 1.5 Mengelola noise: jendela, filter, tagging, dan corong yang dicatat

Pertanyaan kelima Sari adalah keterampilan inti Day ini. Super-timeline penuh (semua parser, seluruh rentang) terlalu besar untuk dibaca langsung; laptop yang menyala beberapa hari bisa menghasilkan jutaan baris. Keterampilannya bukan membuat timeline, tetapi mempersempitnya menjadi jendela dan sumber yang relevan sehingga bisa dibaca manusia, tanpa membuang bukti diam-diam.

Tabel berikut adalah daftar teknik yang dipakai; urutannya juga urutan yang disarankan.

| Teknik | Cara |
|---|---|
| Batasi waktu | psort dengan filter rentang waktu di sekitar kejadian yang diketahui, atau `--slice` di sekitar satu titik |
| Pilih parser | log2timeline dengan parser tertentu (mis. hanya winevtx, mft, prefetch, winreg) daripada semua |
| Filter field | psort filter untuk `data_type`, `event_identifier`, atau atribut lain |
| Mulai dari pivot | Mulai dari satu event yang diketahui (alert, logon, Prefetch lampiran), lalu lihat sekitarnya |
| Known-good filtering | Buang event rutin yang diketahui jinak dari tampilan review, bukan dari `.plaso` |
| Pisahkan detak berulang | Beri tag pada baris yang ditimbulkan task terjadwal, lalu ringkas sebagai pola |

**Sintaks event filter.** Ekspresi filter berbentuk `ATRIBUT [not] OPERATOR [not] NILAI`, digabung dengan `and` atau `or`, dengan operator antara lain `is`, `==`, `!=`, `contains` (substring tanpa membedakan huruf besar kecil), `>`, `<`, `regexp`, dan `iregexp` [S8]. Untuk waktu, atribut `date` atau `timestamp` dibandingkan dengan fungsi `DATETIME()` yang menerima string ISO 8601 sampai presisi mikrodetik [S8]; dokumentasi psort juga masih memuat contoh string tanggal biasa (`date < '2004-09-20 16:20:00'`) [S5]. Tulis nilai waktu dalam UTC, karena itulah isi `.plaso`, lalu uji dengan satu event yang waktunya sudah kamu ketahui.

Dua perubahan versi memengaruhi filter yang ditulis dari panduan lama. Atribut `parser` sudah dihapus dari event sejak 20230724, sehingga filter `parser is 'winevtx'` tidak lagi bekerja; pakai `data_type`, misalnya `data_type is 'windows:evtx:record'` [S8][S21]. Atribut seperti `message`, `source`, dan `source_long` adalah field output dan tidak diperluas di filter [S8]. `data_type` yang dipakai Day ini: `windows:evtx:record` [S21], `fs:stat:ntfs` dan `fs:ntfs:usn_change` [S20], `windows:prefetch:execution`, `windows:registry:key_value` [S17], dan `windows:srum:network_usage` [S19].

**Slice dan slicer.** `--slice` mengambil event di sekitar satu waktu ISO 8601; ukuran default lima menit sebelum dan sesudah, diubah dengan `--slice_size` [S5]. `--slicer` mengambil event di sekitar setiap event yang cocok dengan filter, default lima event sebelum dan sesudah, juga diatur dengan `--slice_size` [S5]. Satuan `--slice_size` berbeda antara keduanya (menit untuk `--slice`, jumlah event untuk `--slicer`), jadi cek di versi lab sebelum dipakai di laporan.

**Tagging.** Analysis plugin `tagging` memberi label pada event yang cocok dengan aturan di file tag: `psort.py -o null --analysis tagging --tagging-file <file> <storage>` [S5]. Format file tag sederhana: nama label di awal baris, diikuti satu atau lebih baris filter yang diindentasi [S22]. Plaso membawa file tag bawaan untuk Windows dengan label seperti `application_execution`, `service_new`, `task_schedule`, `time_change`, `shutdown`, `system_sleep`, dan `system_wake` [S22]. Label kasus (misalnya `syscache_run`, `responder`, `rutin_dikenal`, `pengguna`) ditulis sendiri dengan sintaks yang sama. Event bertag kemudian bisa dipilih atau dikeluarkan dengan filter `tag contains '<label>'` [S5]. Hasil analysis plugin disimpan ke storage, sehingga file `.plaso` berubah setelah tagging; hash dulu, lalu tag salinannya.

**Detak task.** Di laptop Rizky, setiap run task `\SysCacheUpdate` meninggalkan beberapa baris: blok 4104 PowerShell, pasangan file `__PSScriptPolicyTest_*` yang dibuat lalu dihapus di folder Temp (Day 08 bagian 2.4), pembaruan file Prefetch `POWERSHELL.EXE`, dan baris SRUM. Selama lebih dari dua hari, baris itu berjumlah ribuan dan menenggelamkan kejadian lain. Detak ini bukan noise dalam arti "tidak penting": ia bukti task berjalan, dan jumlah serta jedanya adalah temuan. Yang dilakukan adalah memisahkannya ke tampilan sendiri, menghitungnya, membandingkan jedanya dengan sesi bangun dan tidur laptop, lalu menuliskannya sebagai satu pola di garis waktu kurasi.

**Corong yang dicatat.** Setiap langkah penyaringan adalah keputusan yang bisa membuang bukti. Aturan yang dipakai:

- Simpan `.plaso` lengkap dan jangan pernah menghapus event dari situ; penyaringan hanya terjadi di tampilan.
- Catat setiap langkah dengan perintah, file tag, dan jumlah baris sebelum dan sesudah, sehingga corong bisa diulang dan diperiksa.
- Known-good hanya berdasarkan pola yang sudah dijelaskan, dan diperiksa bahwa polanya tidak menyentuh path yang relevan dengan kasus (profil pengguna, `AppData`, `Tasks`, `wbem`).
- Baris yang tersisa setelah semua tag harus habis dijelaskan satu per satu. Hasil "nol baris tidak terjelaskan" adalah dasar hasil negatif.
- Sebelum menutup analisis, ulangi satu psort dengan jendela yang lebih lebar (misalnya 24 jam sebelum pivot) tanpa filter path, untuk memastikan tidak ada aktivitas awal yang terlewat.

### 1.6 Membaca timeline untuk "adakah aktivitas lain": pelaku, sumber yang buta, dan hasil negatif

Pertanyaan keenam Sari adalah pertanyaan yang paling mudah dijawab terlalu kuat. "Tidak ada aktivitas lain" adalah salah satu kalimat yang dilarang di PIR (Day 12 bagian 1.8), dan super-timeline tidak mengubah alasannya: timeline hanya menggabungkan sumber, tidak membuat sumber yang buta menjadi melihat.

**Tiga pelaku, tiga jenis bukti pemisah.** Setiap baris yang menunjukkan aktivitas diberi salah satu label: pengguna (Rizky), penyerang (lampiran, loader, task, dan apa pun yang berasal darinya), atau responder (NOC, Yoga, kamu). Pemisahnya bukan isi baris, tetapi jangkar di luar baris: case notes responder dan nomor bukti, akun dan profil (`ir-admin`, `adm.yoga`), media (`USB-E-10`, `USB-E-11`), serta pola yang sudah dibuktikan (jadwal task tiap 15 menit). Baris yang tidak punya jangkar tidak diberi label sampai jangkarnya ditemukan.

**Peta buta laptop ini.** Tabel berikut adalah alasan kalimat negatif harus selalu disertai sumber. Baca kolom "Tidak melihat": itulah yang tidak boleh disimpulkan dari ketiadaan baris.

| Sumber di `E16-W1` | Melihat | Tidak melihat |
|---|---|---|
| Security dengan audit bawaan | Logon dan unlock (4624 type 7), logoff, 4616 | Proses baru (4688), task dibuat (4698), service dengan akun pemasang (4697) |
| System | Service baru (7045), shutdown, tidur dan bangun, perubahan jam | Apa yang dijalankan di dalam service atau task |
| PowerShell/Operational 4104 tanpa kebijakan script block logging | Blok skrip yang dianggap mencurigakan oleh PowerShell, berlevel Warning (Day 05 bagian 2.7) | Blok yang tidak dianggap mencurigakan, termasuk perintah C2 yang tampak biasa |
| Prefetch, Amcache, BAM, SRUM | Program yang mulai berjalan, keberadaan file executable, volume jaringan per aplikasi per sekitar satu jam (Day 07) | Argumen, kerja di dalam proses yang sudah berjalan, tujuan dan isi trafik |
| `$MFT`, `$J` | File dibuat, diubah, dihapus, diganti nama di dalam jendela `$J` | Pembacaan file, pelaku perubahan |
| Registry | Keadaan terakhir autostart, jaringan, perangkat, akun (Day 09) | Riwayat lengkap, pembacaan |
| Artefak shell (LNK, Jump List, ShellBags) | Kerja lewat antarmuka (Day 10) | Skrip dan operator lewat C2 |

**Tiga pekerjaan terbuka dan sumber pengisinya.** Lembar batas bukti PIR mencatat tiga hal yang belum diperiksa di `E16-W1` (Day 12 bagian 1.11). Masing-masing dijawab dengan sumber yang berbeda, dan hanya sebagian lewat Plaso:

- **Folder Startup.** Lokasinya per pengguna di `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup` dan untuk semua pengguna di `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp` (Day 11 bagian 1.1). Jawaban datang dari `$MFT` (isi folder sekarang, termasuk entry yang sudah tidak dipakai) dan `$J` (perubahan di dalam jendela journal), yang keduanya ada di timeline bila parser `mft` dan `usnjrnl` dipilih. Perhatikan huruf besar kecil yang berbeda (`Startup` dan `StartUp`), sehingga filter memakai `iregexp`.
- **WMI.** Laptop tanpa Sysmon tidak punya event 19 sampai 21, dan Plaso tidak mem-parse `OBJECTS.DATA` (bagian 1.1). Repository dibaca terpisah dengan parser offline seperti wmi-parser, yang membaca `OBJECTS.DATA` dan menampilkan consumer, filter, dan binding, termasuk catatan bila pasangan namanya umum dan mungkin sah, seperti `SCM Event Log Consumer` dengan `SCM Event Log Filter` [S26]. Alat ini mencari berdasarkan pola, bukan parsing penuh, jadi binding yang sudah dihapus dan tertimpa sebagian tidak dijamin terlihat (Day 11 bagian 2.5). Hasilnya masuk timeline sebagai baris manual. Event WMI-Activity/Operational 5861 di event log, bila ada, ikut terbaca `winevtx`.
- **SRUM.** Dibaca dua jalan yang saling memeriksa: plugin `esedb/srum` di Plaso, yang menghasilkan event `windows:srum:network_usage` dengan `application`, `bytes_sent`, `bytes_received`, `user_identifier`, dan `l2_profile_identifier`, berwaktu dari kolom `TimeStamp` [S19]; dan SrumECmd seperti di Day 07 bagian 2.6, yang bisa memetakan profil jaringan dengan bantuan hive SOFTWARE. Batasnya tetap sama: total per interval sekitar satu jam, waktu baris bisa meleset sampai sekitar satu jam, tanpa tujuan dan isi (Day 07 bagian 1.6).

**Hasil negatif yang sah.** "Tidak ditemukan aktivitas penyerang lain di luar task dan loader" adalah hasil yang sah, asalkan tiga hal ikut tertulis: sumber apa yang diperiksa dan jendelanya, bagaimana semua baris di jendela itu habis dijelaskan (corong bagian 1.5), dan apa yang tidak bisa dicatat oleh sumber-sumber itu (tabel di atas). Kalimat "laptop Rizky tidak tersentuh selain task" tetap dilarang, karena ia menyatakan sesuatu tentang hal yang tidak pernah dicatat: kerja di dalam proses PowerShell, blok skrip yang tidak dianggap mencurigakan, dan isi trafik lewat jaringan hotel dan hotspot.

**Celah juga temuan.** Super-timeline memperlihatkan jam-jam tanpa event dari task. Celah seperti itu harus dijelaskan, bukan dilewati: laptop yang tidur tidak menjalankan task, dan slot yang terlewat tidak dijalankan susulan bila XML task tidak menyetel `StartWhenAvailable`, yang nilai bawaannya `false` [S24]. Event tidur dan bangun di log System (`Microsoft-Windows-Kernel-Power` ID 42 dan `Microsoft-Windows-Power-Troubleshooter` ID 1) dikenali file tag bawaan Plaso sebagai `system_sleep` dan `system_wake` [S22]. `[komunitas]` Contoh event 1 yang dibagikan pengguna memuat field `Sleep Time` dan `Wake Time` dalam UTC [S28]; isi field persisnya cek di build laptop yang sama, dan laptop yang memakai Modern Standby bisa mencatat event lain.

### 1.7 Timesketch dan penyajian: dari timeline mentah ke garis waktu yang dibaca orang lain

Pertanyaan ketujuh Sari menentukan bentuk akhir pekerjaan ini. Pembaca laporan akhir tidak akan membuka 600 ribu baris, dan retainer tidak akan percaya 30 baris tanpa jalan kembali ke sumbernya.

Timesketch adalah platform analisis timeline kolaboratif [S2]. Konsepnya [S18]:

- **Sketch** adalah wadah investigasi, biasanya satu kasus, berisi beberapa timeline dan tampilan.
- **Timeline** adalah kumpulan event yang diimpor dari `.plaso`, CSV, atau JSONL; datanya disimpan di OpenSearch.
- **View** adalah pencarian tersimpan. **Star** menandai event penting. **Comment** melekat pada event tetapi disimpan per sketch.
- **Tag** adalah label di field `tag` setiap event; bisa ditambah dari UI, API, atau sumber data seperti tagging Plaso.
- **Story** adalah dokumen naratif yang menggabungkan teks markdown dengan view dan agregasi tersimpan.
- **Analyzer** adalah proses latar yang memperkaya data, misalnya analyzer Sigma yang memberi tag pada event yang cocok dengan aturan.

Pencarian di Timesketch memakai query string bergaya Lucene: `data_type:"windows:evtx:record" AND event_identifier:4624`, rentang waktu `datetime:[2021-08-29 TO 2021-08-31]`, wildcard dan regex dengan aturan escape sendiri [S17]. Timesketch mengubah jutaan baris menjadi sesuatu yang bisa dicari dan dianotasi, mirip SIEM untuk timeline forensik. Untuk catatan ini, Timesketch dipakai menganalisis super-timeline yang dibuat Plaso.

Impor `.plaso` dilakukan lewat web UI (tombol tambah timeline) atau `timesketch_importer.py`; koneksi dan kredensial disimpan di `~/.timesketchrc`, `--sketch-name` memakai sketch yang sudah ada dengan nama itu, dan `--plaso-event-filter` mengimpor sebagian event saja dengan sintaks filter Plaso [S4]. Mulai rilis 20261014, Timesketch menegakkan versi Plaso minimum 20260720 di sisi worker [S15].

**Keputusan PT JAB untuk kasus ini.** PT JAB belum punya server Timesketch. Membangunnya di tengah kasus berarti menambah server dengan OpenSearch, akun, dan kontrol akses baru di jaringan manajemen, sementara versi alat kasus sudah dibekukan (Day 02 bagian 1.3). Karena itu timeline kasus dibaca lewat CSV di Timeline Explorer di `JKT-DFIR01`, dan file `.plaso` beserta digest versi Plaso diserahkan ke retainer supaya mereka bisa mengimpornya ke Timesketch mereka sendiri bila perlu. Timesketch dipraktikkan di lab (bagian 3) dan diusulkan sebagai kapabilitas di after-action report, dengan catatan kebutuhan kontrol akses, karena timeline berisi data pribadi.

**Garis waktu kurasi.** Bentuk akhir untuk laporan adalah tabel berisi beberapa puluh baris dengan kolom: waktu WIB dan UTC, jam sumber (laptop atau NOC), kejadian, pelaku, artefak dan sumbernya, keyakinan, dan catatan batas. Kejadian berulang (detak task, sesi tidur) ditulis sebagai satu baris pola dengan jumlah dan rentangnya, bukan diulang. Setiap baris menunjuk kembali ke view atau filter yang menghasilkannya. Di bawah tabel ada tiga daftar: tidak ditemukan (dengan sumber dan jendela), tidak bisa dijawab dari sumber yang ada, dan pekerjaan terbuka yang ditutup.

**Minimisasi.** Timeline laptop karyawan memuat nama dokumen kerja, jaringan rumah, nama hotel, dan jam tidur. Lampiran hanya memuat baris yang relevan untuk pertanyaan insiden. Nama hotel dan jaringan luar tetap ditulis karena menjelaskan kenapa beacon tidak terlihat di log PT JAB; flashdisk pribadi Rizky yang terakhir dipakai Jumat 9 Oktober (Day 09 bagian 2.5) dan isi dokumen kerjanya tidak dimasukkan. Pemilahan ini dibicarakan dengan DPO Agus Setiawan sebelum lampiran dibagikan ke retainer.

## 2. Contoh dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi; angka di keluaran dihitung agar konsisten antar tabel. Plaso dijalankan di `jkt-dfir02` (Ubuntu LTS) lewat image Docker `log2timeline/plaso` versi 20260720 yang dibekukan untuk kasus ini, dengan digest yang tercatat di inventaris alat (Day 02 bagian 2.6). Timeline Explorer, KAPE, SrumECmd, dan wmi-parser dijalankan di `JKT-DFIR01` atas `E16-W1` yang di-mount read-only sebagai `G:` seperti di Day 09 bagian 2.1. Narasi memakai WIB (UTC+7); keluaran Plaso dan EZ Tools ditulis dalam UTC dan diberi label, jadi UTC sama dengan WIB dikurangi 7 jam. Nama atribut, format keluaran console, dan nomor partisi berbeda antar versi dan image; cocokkan dengan lab-mu sebelum dipakai.

### 2.1 Menyiapkan salinan kerja di `jkt-dfir02` dan mencatat versi

Langkah ini menjawab bagian "bisa diulang" dari pertanyaan kedua Sari sebelum satu event pun diekstrak. Rabu 2026-10-28 pukul 09:15 kamu menyalin `E16-W1` dari area kerja kasus ke disk lokal `jkt-dfir02`, karena membaca image puluhan gigabyte lewat SMB berulang kali lambat, dan menulis storage Plaso ke share jaringan rawan lambat serta masalah penguncian file.

```bash
sudo mount -t cifs //jkt-evid01/cases /mnt/cases -o rw,username=<akun-analyst>
mkdir -p /srv/dfir/work/INC-2026-019/E16-W1 /srv/dfir/out/INC-2026-019/E16-W1 /srv/dfir/conf/INC-2026-019
rsync -a /mnt/cases/INC-2026-019/work/E16-W1/ /srv/dfir/work/INC-2026-019/E16-W1/
cd /srv/dfir/work/INC-2026-019/E16-W1 && sha256sum -c E16-W1.sha256
docker images --digests log2timeline/plaso
PLASO='log2timeline/plaso@sha256:<digest dari tool-inventory-2026-10-15.csv>'
```

- `mount -t cifs ... rw`: area kerja kasus `\\jkt-evid01\cases` di-mount read-write dengan akun analyst biasa; share bukti master tetap di `/mnt/evidence` read-only (Day 02 bagian 2.8).
- `rsync -a`: menyalin folder salinan kerja berisi segmen image `E16-W1.E01` dan seterusnya beserta berkas `.sha256`.
- `sha256sum -c`: membuktikan salinan lokal identik dengan salinan kerja yang sudah diverifikasi terhadap master (`d3a8...`).
- `docker images --digests`: menampilkan digest image yang terpasang; nilainya harus sama dengan yang dicatat di inventaris.
- `PLASO=...`: semua perintah di bawah memanggil image berdasarkan digest, bukan tag, sehingga tag yang berpindah tidak mengubah alat di tengah kasus.

Keluaran ilustrasi:

```
E16-W1.E01: OK
E16-W1.E02: OK
...
E16-W1.E07: OK
REPOSITORY           TAG        DIGEST
log2timeline/plaso   20260720   sha256:e4b7...   (sama dengan inventaris)
```

Case notes untuk langkah ini:

```
INC-2026-019 | Case notes forensik | <kamu> | TZ catatan: UTC+7 (WIB)
2026-10-28 09:00  Permintaan Sari (action item PIR 27 Okt): tutup Startup, WMI OBJECTS.DATA, SRUM E16-W1;
                  garis waktu gabungan JKT-WS-0412 Senin 20:14 s/d Kamis 08:44:52; tenggat Kamis 29 Okt 16:00.
2026-10-28 09:15  Salin E16-W1 ke jkt-dfir02:/srv/dfir/work/INC-2026-019/E16-W1. 09:41 sha256sum -c OK (7 segmen).
                  Plaso image digest sha256:e4b7... = inventaris (20260720). Output lokal /srv/dfir/out/...,
                  disalin ke /cases/INC-2026-019/analysis/E16-W1/plaso-20260720/ setelah selesai + sha256.
                  Rencana: run terarah (cepat) lalu run menyeluruh win7_slow; zona --timezone Asia/Jakarta
                  (SE Asia Standard Time, bias -420, Day 09); VSS tidak diproses (jendela insiden saja).
```

**Cara membaca hasil:** semua segmen OK berarti salinan lokal boleh diproses. Folder hasil memuat versi alat (`plaso-20260720`), mengikuti pola `analysis/<bukti>/<versi alat>/` supaya retainer tidak perlu bertanya versi (Day 02 bagian 1.6).

**Kapan gagal:** container Docker berjalan sebagai root, sehingga file yang ditulisnya ke folder yang di-mount dimiliki root dan perlu diubah kepemilikannya sebelum disalin [S29]; dan output ditulis langsung ke `/mnt/cases`, sehingga ekstraksi berjam-jam melambat atau gagal di tengah karena koneksi share terputus.

### 2.2 Ekstraksi terarah dulu, lalu `pinfo.py`

Langkah ini memberi bahan kerja dalam setengah jam, sementara ekstraksi menyeluruh berjalan berjam-jam. Kamu menulis file filter berisi path artefak yang pasti dibutuhkan.

```
# /srv/dfir/conf/INC-2026-019/filter-terarah.txt
/Windows/System32/winevt/Logs/.+
/Windows/System32/config/(SYSTEM|SOFTWARE|SAM|SECURITY)
/Users/.+/NTUSER.DAT
/Users/.+/AppData/Local/Microsoft/Windows/UsrClass.dat
/Windows/AppCompat/Programs/Amcache.hve
/Windows/Prefetch/.+
/Windows/System32/sru/SRUDB.dat
/Users/.+/AppData/Roaming/Microsoft/Windows/Recent/.+
/Windows/INF/setupapi.dev.log
```

Pola mengikuti contoh dokumentasi (`/Users/.+/NTUSER.DAT`) [S6]; apakah satu baris boleh memakai alternatif dalam kurung dan apakah titik perlu di-escape, cek dengan `pinfo.py --sections sources` setelah run. Lalu ekstraksi Rabu 09:42:

```bash
docker run --rm \
  -v /srv/dfir/work/INC-2026-019/E16-W1:/data:ro \
  -v /srv/dfir/conf/INC-2026-019:/conf:ro \
  -v /srv/dfir/out/INC-2026-019/E16-W1:/out \
  "$PLASO" log2timeline.py \
    --storage-file /out/E16-W1_terarah.plaso \
    --parsers "winevtx,winreg,prefetch,lnk,olecf/olecf_automatic_destinations,esedb/srum,text/setupapi" \
    -f /conf/filter-terarah.txt \
    --timezone Asia/Jakarta \
    --partitions 3 --vss_stores none --unattended \
    --logfile /out/E16-W1_terarah.log.gz \
    /data/E16-W1.E01
```

- `-v ...:/data:ro`: image dibaca dari volume yang di-mount read-only ke container; `/conf` juga read-only; hanya `/out` yang bisa ditulis [S13].
- `--storage-file`: file `.plaso` keluaran; sumber diberikan di akhir [S6].
- `--parsers`: parser dan plugin yang dipilih; plugin ditulis dengan nama induknya [S6][S9].
- `-f`: hanya file yang cocok dengan pola di file filter yang diproses [S6].
- `--timezone Asia/Jakarta`: zona untuk sumber yang menyimpan waktu lokal (bagian 1.3).
- `--partitions 3`: partisi sistem di image ini (partisi lain: EFI, MSR, Recovery); nomornya dibaca dari prompt log2timeline sekali di sesi interaktif, lalu ditulis eksplisit [S6].
- `--vss_stores none` dan `--unattended`: tidak memproses shadow copy dan tidak menunggu jawaban prompt [S6].
- `--logfile`: log proses terkompresi, disimpan bersama hasil [S6].

Selesai pukul 10:06. Verifikasi cakupan:

```bash
docker run --rm -v /srv/dfir/out/INC-2026-019/E16-W1:/out "$PLASO" pinfo.py -v /out/E16-W1_terarah.plaso
```

Keluaran ilustrasi, diringkas:

```
Preprocessing information:
  Hostname            : JKT-WS-0412
  Operating system    : Windows 10 Enterprise
  Time zone           : Asia/Jakarta
  Users               : rizky.saputra, adm.yoga, ir-admin, ...

Parser counter information:
  winevtx                               386214
  winreg                                512077
  esedb/srum                             46318
  text/setupapi                           2844
  lnk                                     2481
  prefetch                                1736
  olecf/olecf_automatic_destinations      1152
  total                                 952822
```

**Cara membaca hasil:**

- `Operating system` menulis Windows 10 karena preprocessing membaca nilai produk dari registry, yang memang tidak diubah saat upgrade ke Windows 11; versi OS yang benar diambil dari build 22631 (Day 09 bagian 2.3). Jangan menyalin baris ini ke laporan apa adanya.
- `Time zone` menunjukkan zona yang dipakai Plaso untuk sumber waktu lokal. Di sini nilainya dari `--timezone`; tanpa opsi itu, nilai hasil preprocessing yang tampil, dan namanya bisa berupa nama wakil seperti `Asia/Bangkok` dengan offset yang sama (bagian 1.3).
- Tujuh parser yang dipilih semuanya menghasilkan event. Jumlah per parser dicatat di case notes; angka yang sama harus muncul lagi di run menyeluruh untuk file yang sama.
- `mft` dan `usnjrnl` tidak ada, sesuai pilihan. Timeline terarah ini tidak boleh dipakai untuk menyimpulkan apa pun tentang file yang dibuat atau dihapus.

**Variasi:** tanpa `--timezone`, bandingkan nilai `Time zone` di `pinfo.py -v` dengan `TimeZoneKeyName` di registry. Untuk koleksi triage berupa folder (misalnya hasil KAPE E14), preprocessing bisa tidak menemukan zona dan memakai UTC [S14]; di kasus seperti itu `--timezone` wajib.

**Kapan gagal:** pola filter tidak cocok sehingga satu kelompok file tidak diproses tanpa galat (misalnya `Amcache.hve` hilang karena huruf besar kecil); jumlah per parser di `pinfo.py` adalah satu-satunya tanda. Atau `--partitions` diisi nomor yang salah, sehingga yang diproses partisi Recovery dan hampir semua parser menghasilkan nol.

### 2.3 Ekstraksi menyeluruh dengan `win7_slow`

Langkah ini memberi `$MFT`, `$J`, dan semua sumber Windows lain yang dibutuhkan untuk pertanyaan "adakah aktivitas lain". Dijalankan Rabu 10:15 dengan perintah yang sama, tanpa `-f`, dengan preset yang memuat `mft` dan `esedb` (bagian 1.2):

```bash
docker run --rm \
  -v /srv/dfir/work/INC-2026-019/E16-W1:/data:ro \
  -v /srv/dfir/out/INC-2026-019/E16-W1:/out \
  "$PLASO" log2timeline.py \
    --storage-file /out/E16-W1_lengkap.plaso \
    --parsers win7_slow \
    --timezone Asia/Jakarta \
    --partitions 3 --vss_stores none --unattended \
    --logfile /out/E16-W1_lengkap.log.gz \
    /data/E16-W1.E01
```

- `--parsers win7_slow`: preset `esedb`, `mft`, dan `win7` [S10]; nama preset diterima di `--parsers` seperti nama parser.
- Opsi lain sama dengan bagian 2.2, sehingga perbedaan hasil hanya berasal dari parser dan file filter.

Selesai Rabu 17:51 (7 jam 36 menit). Kamis 2026-10-29 pukul 08:30, `pinfo.py` atas `E16-W1_lengkap.plaso` (keluaran ilustrasi, diringkas):

```
Parser counter information:
  mft                                 2938512
  filestat                            1204388
  winreg                               512077
  winevtx                              386214
  usnjrnl                              241903
  esedb/srum                            46318
  pe                                    18660
  esedb (plugin lain)                    3420
  text/setupapi                          2844
  lnk                                    2481
  prefetch                               1736
  olecf/olecf_automatic_destinations     1152
  winpca_db0 + winpca_dic                 214
  custom_destinations                      96
  recycle_bin                               6
  lainnya (webhist, sqlite, text, ...)  61873
  total                               5421894
```

**Cara membaca hasil:**

- Total 5.421.894 event dari satu laptop. Lebih dari separuhnya (`mft` 2.938.512) adalah timestamp SI dan FN dari semua entry `$MFT`, dan seperlima lagi `filestat`; itulah sumber noise utama.
- Tujuh parser yang juga ada di run terarah menghasilkan angka yang sama persis (misalnya `winevtx` 386.214, `esedb/srum` 46.318). Ini bukti bahwa file filter run terarah mencakup semua file yang relevan untuk parser-parser itu.
- `usnjrnl` 241.903 adalah jumlah record `$J`. Rentangnya dibaca dari baris tertua dan termuda: Sabtu 2026-10-10 07:22:07 UTC (14:22:07 WIB) sampai Kamis 2026-10-15 01:44:50 UTC (08:44:50 WIB), jadi jendela insiden tercakup penuh.
- Bagian peringatan ekstraksi di keluaran `pinfo.py` dibaca sebelum analisis; peringatan parser pada file yang relevan (hive, `.evtx`, `SRUDB.dat`) bisa berarti event hilang. Nama bagian dan formatnya cek di versi-mu.

Setelah selesai, kedua `.plaso`, log proses, file filter, dan case notes disalin ke `/cases/INC-2026-019/analysis/E16-W1/plaso-20260720/` dan di-hash:

```bash
cd /srv/dfir/out/INC-2026-019/E16-W1 && sha256sum E16-W1_terarah.plaso E16-W1_lengkap.plaso > plaso.sha256
rsync -a /srv/dfir/out/INC-2026-019/E16-W1/ /mnt/cases/INC-2026-019/analysis/E16-W1/plaso-20260720/
```

**Kapan gagal:** preset atau parser ditulis salah eja; log2timeline bisa berhenti dengan galat atau, untuk nama plugin yang tidak dikenal, memproses lebih sedikit dari yang dikira. Selalu bandingkan daftar parser di `pinfo.py` dengan yang kamu minta.

### 2.4 Kalibrasi zona waktu dan jam laptop sebelum membaca urutan

Langkah ini menjawab pertanyaan ketiga Sari dengan uji, bukan asumsi. Prinsipnya: ambil beberapa titik yang nilainya sudah kamu ketahui dari analisis per artefak (Day 03 dan Day 09), dari sumber UTC dan sumber waktu lokal, lalu periksa bahwa Plaso menaruhnya di waktu UTC yang benar.

```bash
docker run --rm -v /srv/dfir/out/INC-2026-019/E16-W1:/out "$PLASO" psort.py -o dynamic \
  --slice "2026-10-13T10:43:12" -w /out/kal_usb10.csv /out/E16-W1_lengkap.plaso
docker run --rm -v /srv/dfir/out/INC-2026-019/E16-W1:/out "$PLASO" psort.py -o dynamic \
  -w /out/kal_network.csv /out/E16-W1_lengkap.plaso 'data_type is "windows:registry:network"'
```

- `--slice "2026-10-13T10:43:12"`: event lima menit sebelum dan sesudah waktu colok `USB-E-10` dalam UTC [S5]. Baris `setupapi` (waktu lokal) dan properti perangkat di registry (UTC) harus jatuh di jendela yang sama.
- `data_type is "windows:registry:network"`: semua baris NetworkList [S8]. Nilainya dibandingkan dengan tabel Day 09 bagian 2.4.

Tabel berikut adalah hasil kalibrasi (keluaran ilustrasi). Cari kolom "Hasil": satu baris yang meleset tujuh jam berarti zona tidak diterapkan pada parser itu.

| Titik kalibrasi | Jenis waktu di artefak | Nilai yang diketahui | Baris Plaso (UTC) | Hasil |
|---|---|---|---|---|
| Prefetch `WSCRIPT.EXE` dengan `Tagihan-Okt-2026.js` | UTC | 20:14:21 WIB (Day 03) | 2026-10-12T13:14:21 | Cocok |
| TaskCache `Tree\SysCacheUpdate` last write | UTC | 20:14:39 WIB (Day 09) | 2026-10-12T13:14:39 | Cocok |
| NetworkList `Kenanga-Hotel` dibuat | Lokal | 18:47:05 WIB (Day 09) | 2026-10-12T11:47:05 | Cocok setelah konversi |
| `setupapi.dev.log` Device Install `USB-E-10` | Lokal | 17:43:12 WIB (Day 09) | 2026-10-13T10:43:12 | Cocok setelah konversi |
| USBSTOR `0066` `USB-E-10` | UTC | 17:43:12 WIB (Day 09) | 2026-10-13T10:43:12 | Cocok |
| `ShutdownTime` | UTC | 08:44:52 WIB (Day 09) | 2026-10-15T01:44:52 | Cocok |

**Cara membaca hasil:** sumber UTC dan sumber waktu lokal sepakat setelah konversi, sehingga urutan antar artefak di timeline ini bisa dipercaya untuk sumber-sumber yang diuji. Bila baris NetworkList muncul di 2026-10-12T18:47:05 UTC, artinya nilai lokal dibaca sebagai UTC, dan lampiran akan tampak dijalankan sebelum laptop tiba di hotel. Keluaran ilustrasi ini menganggap versi yang dibekukan menerapkan zona dari `--timezone` pada kedua sumber waktu lokal; perilaku per parser itulah yang diuji di lab bagian 3 sebelum dipercaya, dan XML task tetap dibaca manual (Day 03 bagian 2.5).

Lalu jam laptop terhadap NOC. Tabel berikut menyandingkan baris dari mesin berbeda; baca kolom "Selisih" bersama kolom "Sumber jam".

| Kejadian | Sumber jam | Waktu di sumber itu | Pasangan di laptop (jam laptop) | Selisih |
|---|---|---|---|---|
| Lease DHCP kabel `10.10.41.23` | Log DHCP server `10.10.0.10` (NOC, tersinkron `jkt-ntp01`) | Selasa 17:10:31 | `LeaseObtainedTime` 17:10:33 | +2 s |
| Query `cdn-sync.example.net` pertama ke sinkhole | Log `jkt-sink01` (NOC) | Selasa 17:12:04 | Tidak ada baris host pada 17:12:03 sampai 17:12:09 | Tidak bisa dipasangkan |
| Query `cdn-sync.example.net` kedua ke sinkhole | Log `jkt-sink01` (NOC) | Selasa 17:14:51 | Blok 4104 run 17:14:39 tercatat 17:14:53 | +2 s, cocok |
| Konteks waktu sebelum shutdown | Jam analyst Yoga (case notes) | Kamis 08:40 | Layar laptop | +3 s |

**Cara membaca hasil:**

- Query kedua di sinkhole dan blok 4104 run 17:14:39 jatuh di detik yang sama setelah selisih +2 detik diterapkan; itu pasangan dengan keyakinan tinggi bahwa query itu berasal dari run task.
- Query pertama 17:12:04 tidak punya pasangan di host. Tanpa Sysmon dan tanpa log DNS Client, proses penanya tidak tercatat. Penjelasan yang paling mungkin adalah loader dari run 16:59:39 yang masih mencoba tersambung setelah hotspot putus 17:04:55, tetapi itu inferensi dan ditulis sebagai inferensi.
- Timestamp asli tidak digeser. Kolom "jam sumber" ditambahkan di garis waktu kurasi, dan selisih +2 detik ditulis sekali di metodologi.
- Hasil tagging `time_change` (Kernel-General ID 1) dan hitungan 4616 di jendela sama-sama nol, sehingga tidak ada penyetelan jam langsung selama jendela; koreksi kecil yang perlahan tetap mungkin (Day 09 bagian 1.3).

**Kapan gagal:** selisih jam dipakai untuk menggeser semua timestamp laptop di CSV, sehingga baris laptop tidak lagi cocok dengan artefak aslinya saat retainer memeriksa ulang; atau kalibrasi hanya memakai sumber UTC, sehingga kesalahan zona pada sumber waktu lokal tidak pernah terlihat.

### 2.5 Jendela, tagging, dan corong yang dicatat

Langkah ini menjawab pertanyaan kelima Sari. Jendela kerja ditetapkan Senin 18:45 WIB (sebelum laptop bangun di hotel) sampai Kamis 08:45 WIB, yaitu 2026-10-12 11:45:00 sampai 2026-10-15 01:45:00 UTC.

Pertama, keluaran jendela tanpa filter lain, sebagai dasar hitungan:

```bash
docker run --rm -v /srv/dfir/out/INC-2026-019/E16-W1:/out "$PLASO" psort.py -o dynamic \
  -w /out/E16-W1_jendela_utc.csv /out/E16-W1_lengkap.plaso \
  'date >= DATETIME("2026-10-12T11:45:00") and date <= DATETIME("2026-10-15T01:45:00")'
```

- `-o dynamic -w ...csv`: CSV dengan kolom bawaan modul `dynamic` [S5][S11].
- Filter `date >= DATETIME(...) and date <= DATETIME(...)`: batas jendela dalam UTC [S8].
- Deduplikasi bawaan psort tetap aktif; `-a` dipakai hanya bila ingin melihat semua duplikat [S5].

Keluaran: 612.447 baris. Tabel berikut adalah komposisinya per kelompok sumber; baca baris file system untuk melihat kenapa jendela saja belum cukup.

| Kelompok sumber | Baris di jendela |
|---|---|
| File system (`filestat` + `mft`) | 418.926 |
| `usnjrnl` | 97.412 |
| `winevtx` | 61.385 |
| `winreg` | 21.904 |
| `esedb/srum` | 9.677 |
| `prefetch` | 412 |
| LNK dan Jump List | 386 |
| `text/setupapi` | 96 |
| Lainnya | 2.249 |
| Total | 612.447 |

Kedua, file tag kasus. Nama atribut di bawah (`xml_string`, `filename`, `executable`, `application`, `source_name`) dibaca dulu dari keluaran `-o json_line` beberapa baris, karena nama atribut bisa berubah antar versi (bagian 1.4); pemisah path di atribut `filename` juga dicek di situ.

```
# /srv/dfir/conf/INC-2026-019/tag-inc019.txt  (v1, Kamis 2026-10-29 09:05)
# detak task \SysCacheUpdate
syscache_run
  data_type is 'windows:evtx:record' AND event_identifier is 4104 AND xml_string contains 'SysCache'
  data_type is 'fs:ntfs:usn_change' AND filename contains '__PSScriptPolicyTest_'
  data_type is 'windows:prefetch:execution' AND executable contains 'POWERSHELL.EXE'
  data_type is 'windows:srum:network_usage' AND application contains 'powershell.exe'

# jejak responder (dasar: case notes Yoga E13/E14, shutdown Kamis)
responder
  date >= DATETIME('2026-10-13T10:43:00') AND date <= DATETIME('2026-10-13T11:36:00')
  filename contains '/Users/ir-admin/'
  filename contains '/Users/adm.yoga/'
  date >= DATETIME('2026-10-15T01:44:00')

# rutin sistem yang sudah dijelaskan (tidak menyentuh profil pengguna)
rutin_dikenal
  filename contains '/Windows/WinSxS/'
  filename contains '/Windows/SoftwareDistribution/'
  filename contains '/Windows/servicing/'
  filename contains '/ProgramData/Microsoft/Windows Defender/Definition Updates/'
  data_type is 'windows:evtx:record' AND source_name is 'Microsoft-Windows-Windows Defender' AND (event_identifier is 1000 OR event_identifier is 2000)

# kerja Rizky (Downloads sengaja TIDAK dimasukkan)
pengguna
  data_type is 'windows:evtx:record' AND event_identifier is 4624 AND xml_string contains 'rizky.saputra'
  filename contains '/Users/rizky.saputra/Documents/'
  filename contains '/Users/rizky.saputra/AppData/Roaming/Microsoft/Windows/Recent/'
  data_type is 'windows:prefetch:execution' AND (executable contains 'OUTLOOK.EXE' OR executable contains 'EXCEL.EXE' OR executable contains 'MSEDGE.EXE' OR executable contains 'MS-TEAMS.EXE')

# daya (disalin dari aturan bawaan Plaso)
system_sleep
  data_type is 'windows:evtx:record' AND source_name is 'Microsoft-Windows-Kernel-Power' AND event_identifier is 42
system_wake
  data_type is 'windows:evtx:record' AND source_name is 'Microsoft-Windows-Power-Troubleshooter' AND event_identifier is 1
```

- Format label lalu baris filter yang diindentasi mengikuti file tag bawaan Plaso [S22]; aturan `system_sleep` dan `system_wake` disalin dari sana [S22].
- Event ID 1000 (pemindaian dimulai) dan 2000 (definisi diperbarui) Defender Antivirus adalah kegiatan rutin; 1116 (malware terdeteksi) sengaja tidak dimasukkan [S25].
- Folder `Downloads` Rizky tidak masuk tag `pengguna`, supaya baris lampiran tetap jatuh ke tampilan review.
- Rentang waktu responder kasar dan ikut menangkap run task 17:44, 17:59, 18:14, dan 18:29; baris yang punya dua tag dihitung di tag yang lebih dulu di urutan corong.

Lalu tagging pada salinan, karena hasil analysis plugin disimpan ke storage (bagian 1.5):

```bash
cd /srv/dfir/out/INC-2026-019/E16-W1 && cp E16-W1_lengkap.plaso E16-W1_lengkap_tag.plaso
docker run --rm -v /srv/dfir/conf/INC-2026-019:/conf:ro -v /srv/dfir/out/INC-2026-019/E16-W1:/out "$PLASO" \
  psort.py -o null --analysis tagging --tagging-file /conf/tag-inc019.txt /out/E16-W1_lengkap_tag.plaso
docker run --rm -v /srv/dfir/out/INC-2026-019/E16-W1:/out "$PLASO" psort.py -o dynamic \
  -w /out/E16-W1_review_utc.csv /out/E16-W1_lengkap_tag.plaso \
  'date >= DATETIME("2026-10-12T11:45:00") and date <= DATETIME("2026-10-15T01:45:00") and tag not contains "syscache_run" and tag not contains "responder" and tag not contains "rutin_dikenal" and tag not contains "pengguna"'
```

- `-o null --analysis tagging --tagging-file`: menjalankan tagging tanpa menulis output [S5].
- `tag not contains "..."`: bentuk negasi `ATRIBUT not OPERATOR NILAI` [S8]. Apakah baris yang sama sekali tidak bertag ikut terpilih oleh ekspresi ini perlu dibuktikan di lab; bila tidak, keluarkan semua baris jendela dengan kolom `tag` lalu saring di Timeline Explorer.

Hasilnya dicatat sebagai corong. Tabel berikut adalah inti jawaban pertanyaan kelima; baca kolom "Dasar", karena setiap langkah adalah keputusan yang bisa diperiksa.

| Langkah | Baris tersisa | Dikeluarkan dari review | Dasar |
|---|---|---|---|
| 0. Jendela Senin 18:45 sampai Kamis 08:45 WIB | 612.447 | - | Pertanyaan Sari, ditambah sesi hotel sebelum lampiran |
| 1. `rutin_dikenal` | 109.329 | 503.118 | Path komponen sistem dan event Defender rutin; dicek nol baris di profil pengguna, `Tasks`, `wbem` |
| 2. `syscache_run` (detak task) | 101.508 | 7.821 | Pola task 15 menit (bagian 2.7); dipindah ke tampilan sendiri, bukan dibuang |
| 3. `responder` | 87.141 | 14.367 | Case notes E13, E14, shutdown; profil `ir-admin` dan `adm.yoga` |
| 4. Rutin lain yang dijelaskan saat review pertama (pengindeksan, cache font, telemetri, pembaruan Edge dan OneDrive) | 15.256 | 71.885 | Ditambahkan ke `tag-inc019.txt` v2 setelah dicek satu per satu polanya |
| 5. `pengguna` | 1.354 | 13.902 | Unlock Rizky, Documents, Recent, aplikasi kerja |
| 6. Review manual baris tersisa | 0 tidak terjelaskan | - | 1.203 komponen Windows, 108 aplikasi JAB DocSync dan OneDrive, 34 rantai lampiran, 9 tidur dan bangun |

**Cara membaca hasil:**

- Dari 612.447 baris, 1.354 dibaca satu per satu, dan semuanya bisa dijelaskan. 34 di antaranya adalah rantai lampiran Senin 20:14:02 sampai 20:14:41, dan 9 adalah event tidur dan bangun yang menjelaskan celah run task.
- Langkah 2 tidak menghilangkan informasi: 7.821 baris detak task dihitung dan diringkas di bagian 2.7. Bila detak itu dibuang begitu saja, celah run saat laptop tidur tidak akan pernah terlihat.
- Langkah 4 terjadi setelah review pertama, jadi file tag punya versi. Versi file tag yang dipakai untuk angka akhir disebut di case notes, dan versi lama disimpan.
- Pemeriksaan jendela lebar: psort yang sama dengan jendela Senin 00:00 sampai 18:45 WIB tanpa filter path tidak menemukan baris yang terkait `SysCache`, `Tagihan-Okt-2026`, atau `cdn-sync` sebelum 20:14:02 selain email yang tersinkron di cache Outlook.

**Variasi:** di kasus dengan banyak host, file tag yang sama dipakai untuk setiap host, sehingga corong bisa dibandingkan; untuk pivot cepat di sekitar satu kejadian, `--slicer` dengan filter `tag contains "syscache_run"` menampilkan lima event sebelum dan sesudah setiap run [S5].

**Kapan gagal:** known-good ditulis dengan pola terlalu lebar (misalnya semua path yang mengandung `AppData`), sehingga folder `SysCache` ikut keluar dari review; atau tagging dijalankan pada `.plaso` asli tanpa salinan, sehingga hash yang tercatat di case notes tidak lagi cocok.

### 2.6 Folder Startup dan WMI: menutup dua pekerjaan terbuka

Langkah ini menjawab bagian pertama pertanyaan keenam Sari untuk dua lokasi persistence di luar registry yang belum diperiksa saat PIR.

Folder Startup dibaca dari timeline menyeluruh. Filter memakai `iregexp` karena folder semua pengguna bernama `StartUp` dan folder per pengguna `Startup`:

```bash
docker run --rm -v /srv/dfir/out/INC-2026-019/E16-W1:/out "$PLASO" psort.py -o dynamic \
  -w /out/startup_mft.csv /out/E16-W1_lengkap.plaso \
  'data_type is "fs:stat:ntfs" and filename iregexp "start menu/programs/startup/"'
```

Keluaran ilustrasi (hanya `Creation Time` atribut SI; baris MACB lain dan FN sepakat):

```
datetime (UTC)              timestamp_desc  filename
2026-03-02T03:37:12+00:00   Creation Time   /ProgramData/Microsoft/Windows/Start Menu/Programs/StartUp/desktop.ini
2026-03-02T05:21:14+00:00   Creation Time   /Users/rizky.saputra/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/desktop.ini
2026-06-18T02:40:55+00:00   Creation Time   /Users/adm.yoga/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/desktop.ini
2026-10-13T10:44:06+00:00   Creation Time   /Users/ir-admin/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/desktop.ini
```

**Cara membaca hasil:**

- Keempat folder Startup hanya berisi `desktop.ini`, tanpa shortcut, skrip, atau executable, termasuk entry `$MFT` yang sudah tidak dipakai.
- Waktu pembuatan masing-masing jatuh beberapa detik setelah folder profilnya dibuat (Day 09 bagian 2.7): profil Rizky 2026-03-02 05:21:09 UTC, `adm.yoga` 2026-06-18 02:40:52, `ir-admin` 2026-10-13 10:44:05 (17:44:05 WIB). Folder Startup `ir-admin` adalah bagian dari profil yang dibuat saat elevasi Yoga, jadi jejak responder.
- Record `$J` yang induknya entry keempat folder itu, dalam jendela `$J` Sabtu 14:22:07 sampai Kamis 08:44:50 WIB, hanya pembuatan folder dan `desktop.ini` `ir-admin` pada 17:44:06 WIB. Atribut referensi induk pada event USN dibaca dari `json_line`; nama atributnya cek di versi-mu.

Repository WMI dibaca di `JKT-DFIR01`, karena Plaso tidak mem-parse `OBJECTS.DATA` (bagian 1.1):

```powershell
$wb = 'C:\DFIR\work\INC-2026-019\E16-W1\wbem'
New-Item -ItemType Directory -Path $wb | Out-Null
Copy-Item 'G:\Windows\System32\wbem\Repository\*' -Destination $wb
Get-FileHash "$wb\OBJECTS.DATA" -Algorithm SHA256
& 'C:\DFIR\tools\wmi-parser\wmi-parser.exe' -i "$wb\OBJECTS.DATA"
```

- `Copy-Item` dari `G:` yang read-only: file repository tidak terkunci karena dibaca dari image, bukan dari sistem yang berjalan.
- `Get-FileHash`: hash salinan dicatat sebagai turunan.
- `wmi-parser.exe -i`: membaca `OBJECTS.DATA` dan mencetak consumer, filter, dan binding [S26]; versi yang sama dengan yang dipakai saat bedah `INC-2026-017` (Day 11 bagian 2.5).

Keluaran ilustrasi, diringkas:

```
wmi-parser v0.0.1
SCM Event Log Consumer-SCM Event Log Filter   (binding umum, kemungkinan sah)
  Consumer : NTEventLogEventConsumer ~ SCM Event Log Consumer
  Filter   : SCM Event Log Filter ~ select * from MSFT_SCMEventLogEvent
(tidak ada CommandLineEventConsumer atau ActiveScriptEventConsumer)
```

Pembanding dari timeline: event WMI-Activity/Operational 5861 di jendela berjumlah nol; channel itu di `E16-W1` mencakup sejak 2026-09-14, jauh sebelum insiden.

**Cara membaca hasil:** satu-satunya binding adalah pasangan yang lazim ada di Windows dan dicatat alat sebagai kemungkinan sah [S26]. Tidak ada consumer yang menjalankan perintah atau skrip. Dengan dua sumber yang sepakat (repository dan event log), kalimat yang boleh ditulis: "tidak ditemukan WMI event subscription milik penyerang di repository dan event log `E16-W1`". Batasnya: wmi-parser mencari pola, bukan parsing penuh, sehingga binding yang dibuat lalu dihapus dan sebagian tertimpa tidak dijamin terlihat (Day 11 bagian 2.5).

**Kapan gagal:** folder Startup dicari dengan pola huruf kecil saja dan folder `StartUp` semua pengguna terlewat; atau ketiadaan Sysmon 19 sampai 21 ditulis sebagai "tidak ada WMI persistence", padahal Sysmon memang tidak terpasang.

### 2.7 Detak task dan SRUM per jam: membaca celah dan volume

Langkah ini menjawab dua hal sekaligus: berapa kali task berjalan dan kenapa ada celah, serta berapa banyak data yang dikirim `powershell.exe` di tiap jaringan. Pekerjaan terbuka ketiga (SRUM) ditutup di sini.

Detak task diambil dari tampilan `syscache_run` dan event daya:

```bash
docker run --rm -v /srv/dfir/out/INC-2026-019/E16-W1:/out "$PLASO" psort.py -o dynamic \
  -w /out/detak_daya_utc.csv /out/E16-W1_lengkap_tag.plaso \
  '(tag contains "syscache_run" or tag contains "system_sleep" or tag contains "system_wake") and date >= DATETIME("2026-10-12T11:45:00") and date <= DATETIME("2026-10-15T01:45:00")'
```

Run dihitung dari blok 4104 bertag `syscache_run`, dikelompokkan per menit. Hasilnya diringkas per sesi bangun di tabel berikut (WIB, keluaran ilustrasi); cocokkan kolom "Jaringan" dengan tabel sesi Day 09 bagian 2.4.

| Sesi laptop (WIB) | Jaringan | Run terjadwal | Slot terlewat |
|---|---|---|---|
| Senin 18:46:49 (bangun) sampai Selasa 00:12:44 (tidur) | `Kenanga-Hotel` | 15 (20:29:39 sampai 23:59:39), ditambah kelompok awal 20:14:52 | - |
| Selasa 00:12:44 sampai 06:58:14 (tidur) | - | 0 | 27 (00:14:39 sampai 06:44:39) |
| Selasa 06:58:14 sampai 07:46:25 | `Kenanga-Hotel` | 4 (06:59:39 sampai 07:44:39) | - |
| Selasa 07:46:25 sampai 08:52:21 (tidur) | - | 0 | 4 |
| Selasa 08:52:21 sampai 12:05:31 | `BajaRaya-Guest` | 13 (08:59:39 sampai 11:59:39) | - |
| Selasa 12:05:31 sampai 13:02:30 (tidur) | - | 0 | 4 |
| Selasa 13:02:30 sampai 15:40:16 | `BajaRaya-Guest` | 10 (13:14:39 sampai 15:29:39) | - |
| Selasa 15:40:16 sampai 15:51:58 (tidur) | - | 0 | 1 |
| Selasa 15:51:58 sampai Kamis 08:44:33 (shutdown dimulai) | `HP-Rizky`, kabel kantor 17:10:29, lalu tanpa jaringan sejak 17:20 | 163 (15:59:39 sampai Kamis 08:29:39) | - |
| Total | | 205 run terjadwal + kelompok awal | 36 |

**Cara membaca hasil:**

- Slot task berada di menit :14:39, :29:39, :44:39, dan :59:39, mengikuti pendaftaran 20:14:39; blok 4104 muncul sekitar 14 detik setelah slot. Dari slot pertama Senin 20:29:39 sampai slot terakhir sebelum shutdown Kamis 08:29:39 ada 241 slot; 36 terlewat saat laptop tidur, sisanya 205 run.
- Setiap celah run tepat berada di antara event tidur (Kernel-Power 42) dan bangun (Power-Troubleshooter 1), dan tidak ada run susulan setelah bangun. Itu cocok dengan XML task yang tidak menyetel `StartWhenAvailable`, yang bawaannya `false` [S24]. Celah ini dijelaskan oleh laptop yang tidur, bukan oleh penyerang yang menghentikan task.
- Slot Kamis 08:44:39 tidak berjalan karena shutdown sudah dimulai 08:44:33 (System 1074); `Tasks\{GUID}` last write 08:29:41 di Day 09 bagian 2.6 adalah run terakhir.
- Blok 4104 bertag `syscache_run` berjumlah 822: dua blok kelompok awal 20:14:52 ditambah 205 run masing-masing empat blok. Teks blok hanya punya empat nilai berbeda, dan dua blok awal sama dengan dua blok pertama setiap run, jadi tidak ada blok loader yang menyimpang di jendela ini. Hitungan E14 cocok: sampai run Selasa 17:59:39 ada 51 run, sehingga 2 + 51 x 4 = 206 blok SysCache, ditambah 8 blok 4104 lain, sama dengan 214 event 4104 di E14 (Day 05 bagian 2.7).
- Pasangan `__PSScriptPolicyTest_*` di `$J` berjumlah 206: satu kelompok untuk PowerShell awal (file pertama 20:14:33) dan satu per run. Ini hitungan independen dari 4104 dan cocok, pola yang sama dengan laptop Andi (Day 08 bagian 2.4).
- Prefetch `POWERSHELL.EXE` hanya menyimpan delapan waktu terakhir: Kamis 06:44 sampai 08:29. Run Senin dan Selasa diwakili 4104 dan `$J`, bukan Prefetch.

Lalu SRUM. Dari timeline, filter `data_type is "windows:srum:network_usage" and application contains "powershell.exe"`; dari EZ Tools, SrumECmd di `JKT-DFIR01` seperti Day 07 bagian 2.6:

```powershell
C:\DFIR\tools\KAPE\kape.exe --tsource G: --target SRUM --tdest C:\DFIR\work\INC-2026-019\E16-W1\srum --tflush
& "$ez\SrumECmd.exe" -f "C:\DFIR\work\INC-2026-019\E16-W1\srum\G\Windows\System32\sru\SRUDB.dat" `
  -r "C:\DFIR\work\INC-2026-019\E16-W1\reg\G\Windows\System32\config\SOFTWARE" `
  --csv "\\jkt-evid01\cases\INC-2026-019\analysis\E16-W1\EZ-2026.5.0\SRUM"
```

- `--target SRUM`: target yang sama dengan Day 07 bagian 2.1; nama subfolder volume di hasil KAPE cek di folder output.
- `-r`: hive SOFTWARE dari folder `reg` yang diambil di Day 09 bagian 2.1, untuk memetakan profil jaringan [S27].
- SrumECmd selesai tanpa galat database dirty, sesuai shutdown normal.

Keluaran ilustrasi, `powershell.exe` di bawah SID `rizky.saputra`, digabung dari kedua alat (jumlahnya sama). Tabel ini adalah jawaban pekerjaan terbuka SRUM; baca kolom "Beacon" sebagai hasil bagi byte dengan pola per run, bukan hitungan koneksi.

| Timestamp baris (UTC) | WIB | Profil jaringan | Terkirim (byte) | Diterima (byte) | Beacon |
|---|---|---|---|---|---|
| 2026-10-12 14:00 | Senin 21:00 | `Kenanga-Hotel` | 40.960 | 61.440 | 4 |
| 2026-10-12 15:00 | Senin 22:00 | `Kenanga-Hotel` | 40.960 | 61.440 | 4 |
| 2026-10-12 16:00 | Senin 23:00 | `Kenanga-Hotel` | 40.960 | 61.440 | 4 |
| 2026-10-12 17:00 | Selasa 00:00 | `Kenanga-Hotel` | 40.960 | 61.440 | 4 |
| 2026-10-13 00:00 | Selasa 07:00 | `Kenanga-Hotel` | 10.240 | 15.360 | 1 |
| 2026-10-13 01:00 | Selasa 08:00 | `Kenanga-Hotel` | 30.720 | 46.080 | 3 |
| 2026-10-13 02:00 | Selasa 09:00 | `BajaRaya-Guest` | 10.240 | 15.360 | 1 |
| 2026-10-13 03:00 | Selasa 10:00 | `BajaRaya-Guest` | 40.960 | 61.440 | 4 |
| 2026-10-13 04:00 | Selasa 11:00 | `BajaRaya-Guest` | 40.960 | 61.440 | 4 |
| 2026-10-13 05:00 | Selasa 12:00 | `BajaRaya-Guest` | 40.960 | 61.440 | 4 |
| 2026-10-13 07:00 | Selasa 14:00 | `BajaRaya-Guest` | 40.960 | 61.440 | 4 |
| 2026-10-13 08:00 | Selasa 15:00 | `BajaRaya-Guest` | 40.960 | 61.440 | 4 |
| 2026-10-13 09:00 | Selasa 16:00 | `BajaRaya-Guest` | 20.480 | 30.720 | 2 |
| 2026-10-13 09:00 | Selasa 16:00 | `HP-Rizky` | 10.240 | 15.360 | 1 |
| 2026-10-13 10:00 | Selasa 17:00 | `HP-Rizky` | 40.960 | 61.440 | 4 |
| Total | | | 491.520 | 737.280 | 48 |

**Cara membaca hasil:**

- Setiap baris menutup sekitar satu jam sebelum timestamp-nya, seperti di laptop Dewi (Day 07 bagian 2.6). Per beacon polanya 10.240 byte terkirim dan 15.360 byte diterima, sama dengan pola beacon di laptop Dewi; semua baris adalah kelipatan pola itu, tanpa jam yang menonjol.
- Hitungan beacon per jaringan cocok dengan hitungan run: `Kenanga-Hotel` 20 (kelompok awal + 15 run Senin + 4 run Selasa pagi), `BajaRaya-Guest` 23 (13 + 10), `HP-Rizky` 5 (run 15:59:39 sampai 16:59:39). Total 48 beacon berhasil, sekitar 0,47 MiB terkirim dan 0,70 MiB diterima.
- Tidak ada baris `powershell.exe` untuk profil kabel kantor dan tidak ada baris setelah Selasa 17:00 WIB: run 17:14:39 hanya mencapai sinkhole, dan sejak port dimatikan 17:20 tidak ada jaringan. Task tetap berjalan sampai Kamis (bagian atas), tetapi tanpa byte.
- Aplikasi lain di SRUM selama jendela adalah aplikasi kerja Rizky (Outlook, Edge, Teams, OneDrive) dengan pola jam kerja, ditambah `kape.exe` dan WinPmem dari volume USB pada Selasa sore (responder). Tidak ada aplikasi yang belum dikenal.
- Batasnya tetap: SRUM tidak menunjukkan tujuan dan isi, dan setiap beacon bisa membawa data kecil. Yang bisa ditulis: tidak ada lonjakan volume di luar pola beacon.

**Kapan gagal:** SRUM dibaca per menit atau per koneksi, atau baris jam 16:00 yang berisi dua profil dijumlahkan sebagai satu jaringan; atau profil jaringan tidak dipetakan karena SOFTWARE hive tidak diberikan, sehingga jaringan hotel dan kantor tidak bisa dibedakan.

### 2.8 Garis waktu kurasi dan draf untuk Sari

Tabel ini adalah keluaran akhir yang dikirim ke Sari Kamis 2026-10-29 pukul 15:20, disimpan sebagai `\\jkt-evid01\cases\INC-2026-019\analysis\E16-W1\plaso-20260720\lampiran\INC-2026-019_timeline_JKT-WS-0412_v1.csv` dengan kolom `datetime`, `timestamp_desc`, dan `message` supaya bisa diimpor ke Timesketch kelak [S16]. Kolom "Jam sumber" menyebut jam mesin yang menulis kejadian itu; baris laptop memakai jam laptop (+2 sampai +3 detik terhadap NOC).

| Waktu (WIB) | Jam sumber | Kejadian | Pelaku | Artefak | Keyakinan |
|---|---|---|---|---|---|
| Senin 15:58 | Server email | Email dengan lampiran diterima sembilan mailbox | Penyerang (pengiriman) | Log email | Tinggi |
| Senin 17:33:08 sampai 18:46:49 | Laptop | Laptop tidur, bangun di hotel; unlock Rizky 18:46:58 | Pengguna | Kernel-Power 42, Power-Troubleshooter 1, 4624 type 7 | Tinggi |
| Senin 18:47:05 | Laptop (waktu lokal) | Tersambung `Kenanga-Hotel` | Pengguna | NetworkList, WLAN-AutoConfig | Tinggi |
| Senin 20:14:02 | Laptop | `Tagihan-Okt-2026.zip` dibuat di Downloads Rizky | Pengguna (menyimpan lampiran) | `$MFT`, `$J` | Tinggi |
| Senin 20:14:15 | Laptop | ZIP dibuka di Explorer | Pengguna | LNK `Tagihan-Okt-2026.zip.lnk`, `$J` | Tinggi |
| Senin 20:14:19 | Laptop | `.js` diekstrak ke folder `Temp1_...` | Pengguna (tindakan), penyerang (isi) | `$MFT`, `$J` | Tinggi |
| Senin 20:14:21 | Laptop | `wscript.exe` menjalankan `Tagihan-Okt-2026.js` | Penyerang lewat lampiran | Prefetch | Tinggi |
| Senin 20:14:33 | Laptop | PowerShell pertama mulai (file `__PSScriptPolicyTest_*`) | Penyerang | `$J` (inferensi dari pola) | Sedang-tinggi |
| Senin 20:14:37 | Laptop | `upd.ps1` dibuat, 4.812 byte | Penyerang | `$MFT`, `$J` | Tinggi |
| Senin 20:14:39 | Laptop | Task `\SysCacheUpdate` terdaftar | Penyerang | XML `RegistrationInfo` (manual), TaskCache `Tree`, `$J` file task | Tinggi |
| Senin 20:14:52 | Laptop | 4104 pertama (dua blok) | Penyerang | PowerShell/Operational | Tinggi |
| Senin 20:29:39 sampai Kamis 08:29:39 | Laptop | 205 run task tiap 15 menit saat laptop bangun; 36 slot terlewat saat tidur | Penyerang | 4104 (822 blok), `$J` (206 pasang), Prefetch, `Tasks\{GUID}` | Tinggi |
| Senin 20:14 sampai Selasa 17:00 | Laptop | 48 beacon berhasil lewat `Kenanga-Hotel`, `BajaRaya-Guest`, `HP-Rizky`; 491.520 byte terkirim | Penyerang | SRUM | Sedang (volume per jam, tanpa tujuan dan isi) |
| Selasa 00:12:44 sampai 15:51:58 | Laptop | Empat sesi tidur dan bangun; Rizky bekerja di BajaRaya (Outlook, Excel, Edge, Teams), unlock tiap bangun | Pengguna | Event daya, 4624 type 7, Prefetch, LNK, Jump List | Tinggi |
| Selasa 17:10:29 | Laptop (waktu lokal) | Tersambung jaringan kabel kantor; lease 17:10:33 (NOC 17:10:31) | Pengguna | NetworkList, interface TCP/IP, log DHCP NOC | Tinggi |
| Selasa 17:12:04 | NOC | Query `cdn-sync.example.net` ke sinkhole; proses penanya tidak tercatat di host | Penyerang (diduga loader run 16:59:39) | Log `jkt-sink01` | Sedang (inferensi) |
| Selasa 17:14:51 | NOC | Query kedua ke sinkhole, cocok dengan 4104 run 17:14:39 (laptop 17:14:53) | Penyerang | Log `jkt-sink01`, 4104 | Tinggi |
| Selasa 17:20 | NOC | Port switch dimatikan; task terus berjalan tanpa jaringan | Responder (NOC) | Log NOC, SRUM tanpa baris | Tinggi |
| Selasa 17:43:12 sampai 17:59:20 | Laptop | `USB-E-10` dicolok di sesi Rizky; elevasi `ir-admin` 17:44:02; profil `ir-admin` 17:44:05; driver WinPmem 17:45:06 | Responder (Yoga) | USBSTOR, setupapi, SAM, `$MFT`, 7045, case notes | Tinggi |
| Selasa 18:00 sampai 18:35:18 | Laptop | `adm.yoga` cached logon 18:00; `USB-E-11` 18:01:03; KAPE E14 18:02 sampai 18:29 | Responder (Yoga) | Winlogon, SCSI, MountPoints2, Prefetch, SRUM, case notes | Tinggi |
| Selasa 18:35 sampai Kamis 08:44 | Laptop | Tidak ada unlock, logon, atau artefak shell; hanya task dan rutin sistem | - | 4624, LNK, Jump List, corong bagian 2.5 | Tinggi untuk logon dan antarmuka |
| Kamis 08:40 | Jam analyst | Konteks waktu dicatat (+3 s) | Responder (Yoga) | Case notes | Tinggi |
| Kamis 08:44:33 sampai 08:44:52 | Laptop | Shutdown dimulai (1074), `ShutdownTime` 08:44:52; slot 08:44:39 tidak berjalan | Responder (Yoga) | System 1074, Kernel-General 13, registry | Tinggi |

Pernyataan yang menyertai tabel:

- **Tidak ditemukan, dengan sumber dan jendela:** aktivitas penyerang lain di luar lampiran, loader, task, dan beacon, dalam jendela Senin 18:45 sampai Kamis 08:45 WIB, setelah 612.447 baris timeline habis dijelaskan; autostart di folder Startup (`$MFT` dan `$J`); WMI event subscription milik penyerang (`OBJECTS.DATA`, 5861); program penyerang lain di Prefetch, Amcache, dan SRUM; blok 4104 loader yang menyimpang; lonjakan volume SRUM; penyetelan jam (4616, Kernel-General 1); logon atau unlock setelah Selasa 18:35.
- **Tidak bisa dijawab dari sumber yang ada:** kerja di dalam proses PowerShell yang tidak membuat proses atau file baru; blok skrip yang tidak dianggap mencurigakan oleh PowerShell (script block logging tidak diwajibkan kebijakan di laptop ini); isi trafik ke C2 lewat jaringan hotel, tamu pelanggan, dan hotspot (tidak ada di log PT JAB); proses yang mengirim query sinkhole 17:12:04.
- **Pekerjaan terbuka yang ditutup:** folder Startup (bagian 2.6), WMI `OBJECTS.DATA` (bagian 2.6), SRUM `E16-W1` (bagian 2.7). Yang masih terbuka dari lembar PIR tidak berubah: uji lab LNK `.js` dari ZIP dan keunikan password `ir-admin` per host.
- **Metodologi:** Plaso 20260720 (digest di inventaris), preset `win7_slow`, `--timezone Asia/Jakarta`, partisi 3, VSS tidak diproses, file tag `tag-inc019.txt` v2; output UTC, ditampilkan WIB; selisih jam laptop +2 detik terhadap NOC Selasa sore dan +3 detik Kamis pagi, timestamp asli tidak digeser.

Kalimat pengantar ke Sari: "Garis waktu laptop Rizky terlampir, 23 baris, masing-masing menunjuk sumbernya. Dari sumber yang ada di image, tidak ditemukan aktivitas penyerang lain di luar lampiran, task, dan beacon; folder Startup, WMI, dan SRUM sudah diperiksa dan hasilnya negatif, dengan batas yang ditulis di bawah tabel. Celah run task dijelaskan oleh laptop yang tidur, dan jam laptop disandingkan dengan log NOC tanpa menggeser timestamp asli. Yang tetap tidak bisa dijawab adalah apa yang dikerjakan di dalam proses PowerShell dan isi trafik di jaringan luar kantor, jadi kalimat 'laptop Rizky tidak tersentuh selain task' tetap tidak boleh dipakai. Untuk retainer, file `.plaso`, file tag, dan digest Plaso ada di folder yang sama, siap diimpor ke Timesketch mereka."

**Kapan gagal:** tabel dikirim tanpa tiga daftar di bawahnya, sehingga pembaca menganggap yang tidak tercantum berarti tidak terjadi; atau baris detak task diulang 205 kali, sehingga kejadian lain tenggelam lagi di lampiran.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** `LAB-WS01` (`172.16.50.10`, Windows 11 dengan Sysmon, snapshot bersih), `LAB-DFIR01` (`172.16.50.20`, Windows dengan EZ Tools 2026.5.0, KAPE, wmi-parser), dan satu VM Linux lab untuk Plaso dan Timesketch, misalnya `LAB-TL01` (`172.16.50.40`, Ubuntu LTS dengan Docker), semuanya di jaringan host-only `172.16.50.0/24` tanpa jalur ke internet saat lab berjalan. Image Docker Plaso dan Timesketch diunduh lebih dulu di luar lab, dicatat digest-nya, lalu dibawa masuk lewat disk virtual (Day 02 bagian 1.4). Folder kasus `CASE-2026-LAB-013` dengan struktur `evidence\`, `work\`, `analysis\<bukti>\<versi alat>\`, `notes\`. Semua aktivitas jinak dan jamnya kamu catat sendiri di case notes lab, karena catatan itulah kunci jawabanmu.

1. **Zona dan jam.** Di `LAB-WS01`, catat zona waktu (`tzutil /g`) dan set ke `SE Asia Standard Time` bila belum. Catat selisih jam `LAB-WS01` terhadap `LAB-TL01` dengan membaca keduanya pada saat yang sama; nilai ini adalah "selisih jam host" versi lab-mu.
2. **Aktivitas berwaktu.** Ambil snapshot, lalu kerjakan dan catat jamnya: buat task jinak `\LabTask13` tiap 15 menit yang menjalankan `powershell.exe -NoProfile -Command "Get-Date | Out-File C:\Users\Public\lab13.txt"`; taruh shortcut `notepad.exe` di folder Startup pengguna `lab.user`; colok disk virtual `LAB-USB13` dan salin satu file teks ke sana; tambahkan adapter host-only kedua sebagai "jaringan baru"; bila hypervisor-mu mendukung sleep di guest, tidurkan `LAB-WS01` 40 menit lalu bangunkan (bila tidak, catat bahwa langkah ini dilewati). Login dengan akun admin lokal `lab.ir` sekali sebagai "responder".
3. **Koleksi.** Matikan `LAB-WS01` normal. Salin disk VM ke `CASE-2026-LAB-013\evidence\`, hash, buat salinan kerja di `work\`, lalu bawa salinan kerja ke `LAB-TL01` dan verifikasi hash di sana.
4. **Ekstraksi bawaan vs `win7_slow`.** Jalankan log2timeline tanpa `--parsers` (run A) dan dengan `--parsers win7_slow` (run B), keduanya dengan `--timezone Asia/Jakarta`, `--partitions`, `--vss_stores none`, `--unattended`, dan `--logfile` (bagian 2.2 dan 2.3). Bandingkan `pinfo.py` keduanya: catat parser yang hanya ada di run B dan jumlah eventnya.
5. **Preprocessing.** Jalankan run C seperti run A tetapi tanpa `--timezone`, lalu bandingkan nilai zona di `pinfo.py -v` run A dan C. Catat nama yang ditampilkan dan pastikan offset-nya UTC+7.
6. **Kalibrasi.** Pilih minimal empat titik dari case notes-mu: dua dari sumber UTC (Prefetch notepad, TaskCache `LabTask13`) dan dua dari sumber waktu lokal (NetworkList adapter baru, `setupapi.dev.log` untuk `LAB-USB13`). Pakai `--slice` dan filter `data_type` (bagian 2.4) untuk membuktikan keempatnya jatuh di UTC yang benar. Inilah uji perilaku parser waktu lokal di versi Plaso-mu.
7. **Zona salah.** Buat run D dengan `--timezone UTC` dan run E dengan `--timezone Etc/GMT+7`. Ulangi kalibrasi; tunjukkan baris mana yang bergeser dan berapa jam, dan baris mana yang tidak bergeser sama sekali.
8. **Output.** Dari run B, keluarkan `dynamic` dua kali: default UTC dan `--output-time-zone Asia/Jakarta`. Pastikan selisihnya tepat tujuh jam di semua baris dan offset tertulis di kolom `datetime`.
9. **Tagging dan corong.** Tulis `tag-lab013.txt` dengan label `labtask13_run`, `responder` (login `lab.ir` dan koleksimu), `rutin_dikenal`, `pengguna`, `system_sleep`, dan `system_wake` (bagian 2.5). Tag salinan `.plaso`, bukan aslinya; bandingkan hash sebelum dan sesudah. Buktikan apakah ekspresi `tag not contains` ikut memilih baris tanpa tag. Catat corong: jumlah baris di setiap langkah sampai baris tersisa habis dijelaskan.
10. **Detak dan celah.** Hitung run `\LabTask13` dari 4104 atau dari pasangan `__PSScriptPolicyTest_*` di `$J`, lalu cocokkan dengan jam di case notes dan dengan event tidur dan bangun. Hitung slot yang terlewat.
11. **Startup dan WMI.** Temukan shortcut Startup-mu di timeline (`iregexp`, bagian 2.6). Salin `OBJECTS.DATA` dari salinan kerja di `LAB-DFIR01`, jalankan wmi-parser, dan catat binding bawaan yang muncul di VM bersih.
12. **SRUM.** Bandingkan baris `windows:srum:network_usage` dari Plaso dengan keluaran SrumECmd untuk aplikasi yang sama; jumlah byte per baris harus sama.
13. **Timesketch.** Pasang Timesketch di `LAB-TL01` mengikuti panduan instalasi resminya, impor `.plaso` run B dengan `timesketch_importer.py` atau web UI, dan impor juga CSV garis waktu kurasi lab-mu (kolom `datetime`, `timestamp_desc`, `message`) sebagai timeline kedua di sketch yang sama. Coba query `data_type:"windows:evtx:record" AND event_identifier:4624`, buat view untuk run task, beri tag, dan tulis story pendek yang menjelaskan urutan aktivitas lab.
14. **Garis waktu kurasi.** Susun tabel seperti bagian 2.8 untuk lab-mu, termasuk tiga daftar di bawahnya, lalu bandingkan dengan timeline manual yang kamu susun di Day 12.

**Hasil yang sebaiknya tersimpan:**

- Case notes lab dengan jam setiap aktivitas, zona dan selisih jam host, digest image Plaso dan Timesketch.
- Lima storage file (run A sampai E) beserta `pinfo.py`, file filter, log proses, dan hash; catatan parser yang hanya ada di `win7_slow`.
- Tabel kalibrasi: titik, jenis waktu, nilai yang diketahui, baris Plaso, hasil; untuk run B, D, dan E.
- Dua CSV `dynamic` (UTC dan WIB) dengan bukti selisih tujuh jam.
- File tag lab, hash `.plaso` sebelum dan sesudah tagging, hasil uji `tag not contains`, dan tabel corong.
- Hitungan run `\LabTask13`, slot terlewat, dan event daya yang menjelaskannya.
- Hasil Startup, wmi-parser, dan perbandingan SRUM dua alat.
- Sketch Timesketch dengan dua timeline, satu view, tag, dan story.
- Garis waktu kurasi lab dengan daftar tidak ditemukan, tidak bisa dijawab, dan metodologi.

**Variasi tambahan:** buat output `dynamic` yang sama dua kali, sekali dengan default UTC dan sekali dengan `--output-time-zone Asia/Jakarta`. Pastikan selisihnya tepat tujuh jam di semua baris; bila ada baris yang tidak bergeser atau bergeser berbeda, cari parser-nya dan catat sebagai sumber yang menyimpan waktu lokal.

**Variasi tantangan:** buat dua timeline dari koleksi yang sama dengan zona waktu berbeda (benar vs salah, misalnya UTC vs Asia/Jakarta). Tunjukkan bagaimana zona yang salah menggeser event relatif terhadap event lain dan bisa mengubah urutan yang disimpulkan, misalnya colok `LAB-USB13` tampak terjadi sebelum atau sesudah file disalin ke sana. Tulis kenapa menetapkan zona dengan benar dari registry adalah langkah wajib. Sebagai tambahan, jalankan Plaso atas koleksi triage KAPE lab (folder, bukan image) tanpa `--timezone` dan periksa zona yang dipakai.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat membuat dan membaca super-timeline. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Ekstraksi sangat lama | Semua parser atas data besar | Batasi parser dan sumber (bagian 2.2) |
| Event bergeser relatif | Zona waktu salah | Set `--timezone` dari registry (Day 09) dan kalibrasi (bagian 2.4) |
| Timeline terlalu besar dibaca | Tidak difilter | psort dengan filter waktu/field dan tagging (bagian 2.5) |
| Parser yang diharapkan tidak jalan | Nama parser salah atau artefak tidak ada | Cek `pinfo.py` dan `log2timeline.py --info` |
| `$MFT` dan SRUM sama sekali tidak muncul | Preset otomatis `win7` tidak memuat `mft` dan `esedb` | `--parsers win7_slow` atau tambahkan `mft` dan `esedb/srum` (bagian 1.2) |
| Banyak baris per satu kejadian | Satu artefak punya banyak timestamp (MFT MACB) | Pahami sumber baris; jangan salah hitung |
| Filter `parser is 'winevtx'` tidak menghasilkan apa pun | Atribut `parser` dihapus dari event sejak 20230724 | Pakai `data_type` (bagian 1.5) |
| Query atau view dari panduan lama dengan `computer_name` kosong | Plaso 20260720 mengganti nama menjadi `hostname` | Baca nama atribut dari `-o json_line` (bagian 1.4) |
| Hash `.plaso` berubah setelah analisis | Analysis plugin (tagging) menulis ke storage | Hash dulu, tag salinan (bagian 2.5) |
| Timesketch tidak menerima impor | Koneksi atau kredensial salah; memakai `psort -o timesketch` dari panduan lama; versi Plaso di worker di bawah 20260720 | Periksa `~/.timesketchrc`; pakai `timesketch_importer.py` atau unggah lewat web UI; samakan versi Plaso |
| log2timeline di container berhenti atau menunggu input | Prompt partisi atau VSS | `--partitions`, `--vss_stores`, `--unattended` (bagian 2.2) |
| File output tidak bisa disalin atau diubah | Container menulis sebagai root | Ubah kepemilikan sebelum disalin [S29] |
| Zona di `pinfo.py -v` tampil `Asia/Bangkok` | Pemetaan nama zona Windows ke nama wakil | Pastikan offset UTC+7 tanpa DST; tulis `Asia/Jakarta` eksplisit bila perlu (bagian 1.3) |
| Jam-jam tanpa run task | Laptop tidur; slot tidak dijalankan susulan | Cocokkan dengan event tidur dan bangun (bagian 2.7) |

## 5. Kesalahan umum dan jebakan

- **Salah zona waktu.** Menggeser event relatif dan merusak urutan; set dari registry dan buktikan dengan kalibrasi.
- **Mencampur zona dengan jam host.** Zona yang benar tidak memperbaiki jam yang meleset, dan selisih jam tidak dikoreksi dengan menggeser semua timestamp.
- **Membaca seluruh timeline dari awal.** Persempit ke jendela kejadian dari pivot artefak (Day 07-11).
- **Mengekstrak ulang untuk tiap tampilan.** Ekstrak sekali ke `.plaso`, psort berkali-kali.
- **Mengira tanpa `--parsers` berarti semua parser.** Yang dipakai preset hasil preprocessing, dan untuk Windows itu `win7` tanpa `mft` dan `esedb`.
- **Mengira satu baris timeline = satu kejadian unik.** Satu artefak (MFT) menghasilkan beberapa baris per file.
- **Membuang detak task.** Baris berulang adalah bukti task berjalan dan kunci membaca celah; pisahkan ke tampilan sendiri, jangan dihapus.
- **Known-good terlalu lebar.** Pola seperti "semua `AppData`" ikut membuang folder penyerang; pola known-good harus dicek tidak menyentuh path kasus.
- **Menulis "tidak ada aktivitas lain".** Tulis "tidak ditemukan di sumber X dalam jendela Y" dan sebut apa yang tidak dicatat sumber-sumber itu.
- **Melupakan sumber di luar Plaso.** XML task, `OBJECTS.DATA`, log NOC, dan case notes tidak muncul di timeline otomatis.
- **Memakai super-timeline untuk pertanyaan sempit.** Analisis artefak terpisah lebih cepat (Day 07-11).
- `[komunitas, belum terkonfirmasi]` Praktisi umumnya mengekstrak menyeluruh sekali lalu mempersempit dengan psort dan Timesketch, dan selalu menetapkan zona waktu dari registry host. Pendekatan ini konsisten dengan desain Plaso [S1]; konfirmasi flag di versi lab, perlu dicek.

## 6. Catatan terkini

Bagian ini mencatat versi dan perubahan alat per 2026-10-22 yang tidak mengubah alur kerja di atas, kecuali yang disebut.

- **Plaso 20260720** masih rilis stabil terbaru; 20260928 berstatus pre-release untuk pengujian [S1]. Rilis Plaso diberi tanggal (YYYYMMDD). Keputusan untuk `INC-2026-019`: tetap memakai 20260720 yang dibekukan sejak 2026-10-15 (Day 02 bagian 1.3), karena tidak ada rilis stabil yang lebih baru dan pre-release tidak dipakai untuk kasus.
- **Timesketch 20261014** (14 Oktober 2026) menegakkan versi Plaso minimum 20260720 di sisi worker, dan mencatat bahwa Plaso 20260720 mengganti `computer_name` menjadi `hostname` serta `body` menjadi `message_body`; analyzer bawaan mendukung kedua nama, tetapi view dan query buatan sendiri perlu diperbarui [S15]. Versi Plaso kasus ini memenuhi syarat itu, sehingga `.plaso` yang diserahkan ke retainer bisa diimpor ke Timesketch versi terbaru.
- **Event filter Plaso:** atribut `parser` dihapus sejak 20230724, dan atribut output (`message`, `source`, `source_long`) tidak diperluas di filter sejak 20190512 [S8].
- **psort** tidak lagi menulis ke stdout sejak versi 1.5.0; output selalu lewat `-w` [S5]. Panduan lama menyebut `psort.py -o timesketch`; output module itu tidak lagi ada di daftar modul Plaso terbaru. Yang tersedia adalah `opensearch_ts`, yang menulis langsung ke OpenSearch Timesketch dan butuh konfigurasi server [S5].
- **Preset parser** didefinisikan di `presets.yaml` repo Plaso; `win7` dipilih untuk keluarga Windows NT, sedangkan `win7_slow` tidak punya pemetaan OS sehingga hanya dipakai bila diminta [S10].
- **EZ Tools 2026.5.0:** Timeline Explorer hanya .NET 9; alat CLI seperti SrumECmd tersedia untuk .NET 4.7.2 dan .NET 9 [S27].
- Sebuah materi kuliah forensik 2026 menyarankan instalasi Plaso lewat `uv` karena paket distribusi sering tertinggal [S29]; PT JAB tetap memakai image Docker yang dibekukan dengan digest.
- Day 14 beralih ke memori: akuisisi dan Volatility 3 dasar, dimensi yang tidak ada di timeline disk.

## 7. Cheat sheet

```
SUPER-TIMELINE gabungan event berwaktu lintas artefak (MFT, USN, registry, event log, Prefetch, LNK, SRUM) ke 1 garis waktu UTC
PLASO       log2timeline.py (ekstrak ke .plaso) -> psort.py (filter/urut/output) ; pinfo.py (info) ; ekstrak sekali, psort berkali-kali
DOCKER      docker run --rm -v <img>:/data:ro -v <out>:/out log2timeline/plaso@sha256:<digest> log2timeline.py ...
PRESET      tanpa --parsers = preset OS (Windows: win7, TANPA mft dan esedb) ; --parsers win7_slow = esedb + mft + win7
OPSI L2T    --storage-file | --parsers | -f <filter file> | --timezone Asia/Jakarta | --partitions N | --vss_stores none|all
            --unattended | --logfile x.log.gz | --info
PINFO       pinfo.py -v x.plaso (zona, host, OS, jumlah per parser) ; pinfo.py --sections sources ; --compare a b
ZONA WAKTU  Plaso internal UTC ; zona host hanya untuk sumber waktu LOKAL (NetworkList, setupapi, log teks)
            preprocessing baca SYSTEM; tanpa itu = UTC ; Etc/GMT-7 = UTC+7 (tanda terbalik) ; salah zona = urutan rusak
JAM HOST    beda dari zona ; jangan geser timestamp ; kolom "jam sumber" + selisih terukur (+2 s vs NOC) + toleransi
OUTPUT      -o dynamic (CSV) | l2tcsv | json_line | xlsx | opensearch_ts ; --output-time-zone ; -o list ; -a = semua duplikat
FILTER      'date >= DATETIME("2026-10-12T11:45:00") and data_type is "windows:evtx:record" and event_identifier == 4104'
            parser TIDAK bisa difilter (dihapus 20230724) ; pakai data_type ; nama atribut cek -o json_line
SLICE       psort --slice "<ISO8601>" (default +-5 menit) | --slicer + filter (default +-5 event) ; --slice_size
TAGGING     psort -o null --analysis tagging --tagging-file tag.txt SALINAN.plaso ; lalu "tag contains 'x'"
            format: label di kolom 1, filter diindentasi ; bawaan: system_sleep (Kernel-Power 42), system_wake (PT 1)
CORONG      jendela -> rutin_dikenal -> detak task -> responder -> rutin lain -> pengguna -> review manual = 0 tak terjelaskan
DI LUAR     XML task | OBJECTS.DATA (wmi-parser) | log NOC/sinkhole/email | case notes  -> baris manual + jam sumber
TIMESKETCH  sketch / timeline / view / star / tag / comment / story / analyzer ; query Lucene
            timesketch_importer.py --sketch-name <nama> x.plaso | web UI ; CSV/JSONL wajib message, datetime, timestamp_desc
            Timesketch 20261014 butuh Plaso >= 20260720 ; computer_name -> hostname
VS ARTEFAK  pertanyaan sempit -> artefak terpisah (Day 07-11) | urutan lintas artefak dan celah -> super-timeline
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Aku menjalankan `log2timeline.py` atas image `E16-W1` tanpa `--parsers`, jadi semua parser ikut jalan. Karena tidak ada satu pun baris `$FILE_NAME` di timeline, berarti tidak ada file yang dibuat penyerang yang perlu dibandingkan SI dan FN-nya." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Tanpa `--parsers`, Plaso tidak menjalankan semua parser; ia memakai preset yang cocok dengan sistem operasi hasil preprocessing, dan untuk Windows itu `win7`. Preset `win7` tidak memuat parser `mft` dan `esedb`; keduanya baru ada di `win7_slow`. Atribut `$FILE_NAME` hanya datang dari parser `mft`, jadi ketiadaannya adalah akibat pilihan preset, bukan tanda tidak ada file. Buktikan cakupan dengan daftar parser di `pinfo.py`, lalu ekstrak ulang dengan `win7_slow` atau tambahkan `mft`. Lihat bagian 1.2.

</details>

**2. Skenario keputusan.** Log sinkhole NOC mencatat query `cdn-sync.example.net` pukul 17:14:51, dan di timeline laptop ada blok 4104 run task pukul 17:14:53 (jam laptop). Jam laptop diketahui +2 detik terhadap NOC Selasa sore. Apa yang kamu lakukan di garis waktu gabungan?

- A. Geser semua timestamp laptop di CSV mundur 2 detik supaya seragam dengan NOC, lalu tulis keduanya di 17:14:51.
- B. Biarkan timestamp asli, tambahkan kolom jam sumber, tulis selisih +2 detik di metodologi, dan pasangkan kedua baris dengan menyebut selisih itu.
- C. Abaikan selisih 2 detik karena terlalu kecil untuk berpengaruh.

<details><summary>Jawaban</summary>

B. Timestamp asli harus tetap cocok dengan artefak sumbernya, supaya retainer bisa memeriksa ulang setiap baris; selisih jam dicatat sebagai kolom dan metodologi, lalu dipakai saat menyandingkan baris dari mesin berbeda. A keliru karena CSV yang digeser tidak lagi cocok dengan `.evtx` dan `.plaso` aslinya, dan selisih itu hanya terukur untuk Selasa sore. C keliru karena 2 detik menentukan apakah dua baris jatuh di detik yang sama; di kasus ini justru selisih itulah yang membuat query kedua bisa dipasangkan dengan run 17:14:39, sementara query 17:12:04 tidak punya pasangan. Lihat bagian 1.3 dan 2.4.

</details>

**3. Pertanyaan jebakan.** "Untuk menyaring baris event log, cukup tulis filter psort `parser is 'winevtx'`, seperti di panduan yang aku pakai dulu." Benarkah?

<details><summary>Jawaban</summary>

Tidak untuk Plaso versi sekarang. Atribut `parser` sudah dihapus dari event sejak 20230724, sehingga filter itu tidak memilih apa pun; `parser` masih ada sebagai kolom output `dynamic`, tetapi bukan atribut filter. Yang dipakai adalah `data_type`, misalnya `data_type is 'windows:evtx:record'`. Hal yang sama berlaku untuk `message` dan `source`, yang adalah field output. Sebelum menulis filter atau file tag, baca nama atribut dari beberapa baris `-o json_line`, karena nama juga bisa berubah (misalnya `computer_name` menjadi `hostname` di 20260720). Lihat bagian 1.4 dan 1.5.

</details>

**4. Skenario keputusan.** Di jendela Senin sampai Kamis ada 7.821 baris yang ditimbulkan run task `\SysCacheUpdate` setiap 15 menit, dan baris itu menenggelamkan kejadian lain. Apa yang kamu lakukan?

- A. Hapus event itu dari `.plaso` supaya timeline bersih, karena task sudah diketahui.
- B. Beri tag pada baris itu di salinan `.plaso`, keluarkan dari tampilan review, hitung dan ringkas sebagai pola (jumlah run, slot terlewat, beacon), lalu cocokkan celahnya dengan event tidur dan bangun.
- C. Biarkan semua baris di tampilan review dan baca satu per satu.

<details><summary>Jawaban</summary>

B. Detak task adalah bukti dan polanya adalah temuan: 205 run, 36 slot terlewat tepat saat laptop tidur, 48 beacon berhasil di tiga jaringan luar. Memisahkannya dengan tag membuat review bisa dibaca tanpa membuang informasi. A keliru karena `.plaso` lengkap harus disimpan utuh dan penyaringan hanya terjadi di tampilan; tanpa baris itu, celah dan jumlah run tidak bisa dibuktikan. C keliru karena ribuan baris berulang membuat kejadian lain, misalnya rantai lampiran atau baris yang belum dijelaskan, terlewat. Lihat bagian 1.5, 2.5, dan 2.7.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Pak Agus (DPO), dalam tiga kalimat, kenapa garis waktu boleh menulis "tidak ditemukan aktivitas penyerang lain di luar task dan loader" tetapi tidak boleh menulis "laptop Rizky tidak tersentuh selain task".

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Kalimat pertama menyebut apa yang kami periksa: semua baris timeline dari Senin malam sampai Kamis pagi sudah dijelaskan satu per satu, dan folder Startup, WMI, SRUM, serta Prefetch tidak menunjukkan program atau persistence lain. Kalimat kedua menyatakan sesuatu tentang hal yang tidak pernah dicatat laptop itu, yaitu apa yang dikerjakan di dalam proses PowerShell dan apa isi trafik ke server penyerang lewat Wi-Fi hotel dan hotspot, karena laptop itu tanpa Sysmon, tanpa audit lengkap, dan di luar jaringan PT JAB. Jadi data yang mungkin terkirim kecil menurut volume SRUM, tetapi isinya tidak bisa dipastikan dari laptop."

Kesalahan yang sering muncul:
- Menganggap "tidak ditemukan" dan "tidak terjadi" sama.
- Tidak menyebut sumber dan jendela waktu yang diperiksa.
- Lupa bahwa volume SRUM kecil bukan bukti tidak ada data yang dikirim.

</details>

**6. Pertanyaan jebakan.** "Plaso menyimpan semua event dalam UTC, jadi kolom `datetime` di output pasti benar untuk semua artefak, tanpa perlu memeriksa zona waktu host." Benarkah?

<details><summary>Jawaban</summary>

Tidak. UTC di storage hanya benar bila nilai aslinya UTC, atau bila nilai waktu lokal diterjemahkan dengan zona yang benar saat ekstraksi. Sumber seperti NetworkList, `setupapi.dev.log`, dan log teks menyimpan waktu lokal; bila zona tidak terbaca (misalnya sumber berupa folder tanpa hive SYSTEM), Plaso memakai UTC dan nilai itu bergeser tujuh jam tanpa pesan galat. Karena itu zona diambil dari registry, diberikan dengan `--timezone`, dibuktikan di `pinfo.py -v`, lalu diuji dengan kalibrasi titik yang nilainya sudah diketahui dari sumber UTC dan sumber waktu lokal. Lihat bagian 1.3 dan 2.4.

</details>

**7. Interview question (English).** "You're asked to build a super-timeline for a compromised laptop that had no EDR and no Sysmon. How do you make sure the timeline is complete, correctly time-aligned, and defensible when someone else reviews it?"

<details><summary>Sample answer</summary>

"I start by listing sources before running anything: what Plaso will parse, and what it won't, like scheduled task XML files, the WMI repository, and network-side logs, which I add as manual rows with their own clock labeled. I extract once from the image with a pinned Plaso version, an explicit parser preset that includes the MFT and SRUM, and the host's time zone taken from the registry, then I use pinfo to prove which parsers produced events. Before reading any sequence, I calibrate: I check a few known timestamps from UTC sources and local-time sources, and I measure the host clock offset against a synchronized server without rewriting the original timestamps. Then I narrow the data through a documented funnel: a time window, tags for known-good noise, the recurring task heartbeat, responder activity and the user's own work, until every remaining row is explained. The deliverable is a short curated timeline labeled by actor and confidence, plus explicit lists of what wasn't found, what the sources can't show, and the exact commands, tag file, and hashes so anyone can reproduce it."

What makes this answer strong: it separates time zone from clock offset, treats parser coverage as something to prove rather than assume, keeps the raw storage intact while filtering only views, and ends with a reproducible package and stated limits instead of a bare conclusion.

</details>

## 9. Sumber

| # | Judul | URL | Tipe | Tanggal / diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Plaso (log2timeline) releases dan dokumentasi | https://github.com/log2timeline/plaso/releases | primer | 20260720; diakses 2026-10-09, dicek ulang 2026-10-22 | Tinggi untuk versi; 20260720 Latest, 20260928 pre-release; detail tool dari dokumentasi plaso.readthedocs.io |
| S2 | Timesketch | https://timesketch.org/ | primer | diakses 2026-10-09 | Tinggi. Analisis timeline |
| S3 | Plaso documentation (log2timeline, psort, pinfo, parsers) | https://plaso.readthedocs.io/ | primer | diakses 2026-10-09 | Tinggi; flag persis, cek di versi |
| S4 | Timesketch: Upload data | https://timesketch.org/guides/user/upload-data/ | primer | diakses 2026-10-10, dicek ulang 2026-10-22 | Tinggi. Impor .plaso, `timesketch_importer`, `--sketch-name`, `--sketch-strategy`, `--plaso-event-filter`, `~/.timesketchrc` |
| S5 | Plaso: Using psort.py | https://plaso.readthedocs.io/en/latest/sources/user/Using-psort.html | primer | diakses 2026-10-10, dicek ulang 2026-10-22 | Tinggi. Output module (`-o list`, `opensearch_ts`), `--output-time-zone`, dedup `-a`, `--slice`, `--slicer`, `--slice_size`, filter tanggal, tagging dengan `--tagging-file`, `tag contains` |
| S6 | Plaso: Using log2timeline.py | https://plaso.readthedocs.io/en/latest/sources/user/Using-log2timeline.html | primer | diakses 2026-10-10, dicek ulang 2026-10-22 | Tinggi. `--storage-file`, `--parsers`, `--info`, `-f` filter file, `--partitions`, `--vss_stores`, `--unattended`, `--logfile`, `pinfo.py --sections sources`; tidak memuat opsi zona |
| S7 | Endpoint-Forensics Day 05-12 (artefak yang digabung, timezone dari registry) | (lokal) | rujukan internal | 2026-10-09 | Sumber timeline |
| S8 | Plaso: Event filters | https://plaso.readthedocs.io/en/latest/sources/user/Event-filters.html | primer | diakses 2026-10-22 | Tinggi. Sintaks `ATRIBUT [not] OPERATOR NILAI`, operator, `DATETIME()`, atribut `parser` dihapus 20230724, field output tidak diperluas sejak 20190512 |
| S9 | Plaso: Parsers and plugins | https://plaso.readthedocs.io/en/latest/sources/user/Parsers-and-plugins.html | primer | diakses 2026-10-22 | Tinggi. Daftar parser dan plugin Windows (winevtx, mft, usnjrnl, prefetch, winjob, esedb/srum, winreg plugins); tidak ada parser repository WMI atau XML task |
| S10 | Plaso: presets.yaml (GitHub) | https://raw.githubusercontent.com/log2timeline/plaso/main/plaso/data/presets.yaml | primer (repo resmi) | diakses 2026-10-22 | Tinggi. Isi preset `win7` (keluarga Windows NT), `win7_slow` (esedb, mft, win7), `win_gen`, `winxp`; cabang main, bisa berbeda dari rilis 20260720 |
| S11 | Plaso: Output and formatting | https://plaso.readthedocs.io/en/latest/sources/user/Output-and-formatting.html | primer | diakses 2026-10-22 | Tinggi. Field `dynamic`, `--fields`, `--additional_fields`, `--dynamic-time`, format `datetime` ISO 8601 mikrodetik, l2tcsv 17 kolom |
| S12 | Plaso: Using pinfo.py | https://plaso.readthedocs.io/en/latest/sources/user/Using-pinfo.html | primer | diakses 2026-10-22 | Tinggi. Counter per parser, `-v` (preprocessing: zona, hostname, OS), `--compare` |
| S13 | Plaso: Installing with Docker | https://plaso.readthedocs.io/en/latest/sources/user/Installing-with-docker.html | primer | diakses 2026-10-22 | Tinggi. Contoh `docker run -v /data/:/data log2timeline/plaso log2timeline ...`, psort lewat Docker, `--entrypoint`, `:z` untuk SELinux; tidak mendokumentasikan tag versi |
| S14 | Plaso: Switching from Log2Timeline Perl (Legacy) | https://plaso.readthedocs.io/en/latest/sources/user/Log2Timeline-Perl-(Legacy).html | primer | diakses 2026-10-22 | Sedang-tinggi. Zona waktu diambil otomatis saat preprocessing, opsi `-z` tetap ada, UTC bila zona tidak teridentifikasi; preset dipilih otomatis; halaman perbandingan lama |
| S15 | Timesketch release 20261014 (GitHub) | https://github.com/google/timesketch/releases/tag/20261014 | primer | 2026-10-14; diakses 2026-10-22 | Tinggi. Minimum Plaso 20260720; `computer_name` menjadi `hostname`, `body` menjadi `message_body` |
| S16 | Timesketch: Import from JSON or CSV | https://timesketch.org/guides/user/import-from-json-csv/ | primer | diakses 2026-10-22 | Tinggi. Field wajib `message`, `datetime` (ISO 8601), `timestamp_desc` |
| S17 | Timesketch: Search query guide | https://timesketch.org/guides/user/search-query-guide/ | primer | diakses 2026-10-22 | Tinggi. Query string `data_type:"windows:evtx:record" AND event_identifier:4624`, rentang `datetime:[... TO ...]`, wildcard dan regex |
| S18 | Timesketch: Basic concepts | https://timesketch.org/guides/user/basic-concepts/ | primer | diakses 2026-10-22 | Tinggi. Sketch, timeline, view, star, comment, tag, story, analyzer; data di OpenSearch |
| S19 | Plaso source: SRUM ESE database plugin | https://plaso.readthedocs.io/en/stable/_modules/plaso/parsers/esedb_plugins/srum.html | primer (kode sumber) | diakses 2026-10-22 | Tinggi. `windows:srum:network_usage`, field `application`, `bytes_sent`, `bytes_received`, `user_identifier`, `l2_profile_identifier`; waktu dari kolom `TimeStamp` |
| S20 | Plaso source: NTFS parsers (mft, usnjrnl) | https://plaso.readthedocs.io/en/stable/_modules/plaso/parsers/ntfs.html | primer (kode sumber) | diakses 2026-10-22 | Tinggi. `fs:stat:ntfs`, `fs:ntfs:usn_change`; atribut SI dan FN keduanya diproses parser `mft` |
| S21 | Plaso source: winevtx parser | https://plaso.readthedocs.io/en/stable/_modules/plaso/parsers/winevtx.html | primer (kode sumber) | diakses 2026-10-22 | Tinggi. `windows:evtx:record`, `event_identifier`, `hostname` (dari nama komputer record), `source_name`, `strings`, `xml_string` |
| S22 | Plaso: tag_windows.txt (GitHub) | https://raw.githubusercontent.com/log2timeline/plaso/main/plaso/data/tag_windows.txt | primer (repo resmi) | diakses 2026-10-22 | Tinggi. Format file tag; label `system_sleep` (Kernel-Power 42), `system_wake` (Power-Troubleshooter 1), `shutdown` (Kernel-General 13), `time_change` (Kernel-General 1), `service_new`, `task_schedule` |
| S23 | Unicode CLDR: windowsZones.xml | https://raw.githubusercontent.com/unicode-org/cldr/main/common/supplemental/windowsZones.xml | primer | diakses 2026-10-22 | Tinggi. `SE Asia Standard Time` ke `Asia/Bangkok` (001), `Asia/Jakarta Asia/Pontianak` (ID), `Etc/GMT-7` (ZZ) |
| S24 | Microsoft Learn: StartWhenAvailable (settingsType) Element | https://learn.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-startwhenavailable-settingstype-element | primer | ms.date 2018-05-31; diakses 2026-10-22 | Tinggi. Task boleh dijalankan setelah waktu jadwal lewat; default `false`; hanya untuk task berwaktu |
| S25 | Microsoft Learn: Microsoft Defender Antivirus event IDs and error codes | https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus | primer | ms.date 2026-05-11; diakses 2026-10-22 | Tinggi. Channel `Microsoft-Windows-Windows Defender/Operational`; 1000 scan dimulai, 1116 malware terdeteksi, 2000 definisi diperbarui |
| S26 | GitHub: woanware/wmi-parser | https://github.com/woanware/wmi-parser | primer (repo) | v0.0.1; diakses 2026-10-22 | Sedang. Parse `OBJECTS.DATA` (`-i`), consumer, filter, binding; tanda binding umum yang mungkin sah (`SCM Event Log Consumer`); port C# dari WMI_Forensics |
| S27 | Eric Zimmerman tools (EZ Tools) | https://ericzimmerman.github.io/ | primer | diakses 2026-10-22 | Tinggi. Versi 2026.5.0; Timeline Explorer hanya .NET 9; SrumECmd, MFTECmd, EvtxECmd, RECmd .NET 4.7.2 dan .NET 9 |
| S28 | Microsoft Q&A: "The system has returned from a low power state - was my pc asleep?" | https://learn.microsoft.com/en-us/answers/a/7237344 | komunitas | 2023-09-24; diakses 2026-10-22 | Rendah-sedang. Contoh Kernel-Power 42 dan Power-Troubleshooter 1 dengan field Sleep Time dan Wake Time dalam UTC; bukan dokumentasi resmi |
| S29 | Portland State University, materi kuliah forensik: Plaso Super-Timeline Forensics | https://web.cecs.pdx.edu/~dmcgrath/courses/Su26/forensics/plaso.html | sekunder (materi kuliah) | Summer 2026 (dari URL); diakses 2026-10-22 | Sedang. Alur log2timeline, pinfo, psort; parser nol event perlu dicek; container Docker menulis sebagai root; saran instalasi `uv`. Penulis dan tanggal tidak tertulis di halaman; halaman ini menulis `--output_time_zone`, berbeda dengan dokumentasi resmi `--output-time-zone` [S5] |

**Catatan sumber:** flag dan output module di Day ini dicocokkan dengan dokumentasi Plaso [S5][S6][S8][S11][S12] dan Timesketch [S4][S16][S17][S18], yang tidak selalu mengikuti rilis terbaru 20260720; definisi preset dan file tag dibaca dari cabang main repo Plaso [S10][S22], yang bisa berbeda dari rilis yang dibekukan, jadi cocokkan dengan `log2timeline.py --info` di versi lab. Opsi zona waktu log2timeline tidak tercantum di halaman Using log2timeline [S6]; keberadaannya dan perilaku bawaannya berasal dari halaman perbandingan dengan log2timeline lama [S14], sehingga nama flag `--timezone`/`-z`, satuan `--slice_size`, sintaks pola file filter, perilaku `tag not contains` pada baris tanpa tag, dan opsi `timesketch_importer.py` perlu dicek dengan `-h` di versi lab. Apakah setiap parser sumber waktu lokal (NetworkList, setupapi) menerapkan zona dari `--timezone` tidak dinyatakan eksplisit di sumber yang diperiksa; itulah alasan kalibrasi bagian 2.4 dan langkah lab 6. Event tidur dan bangun dikenali dari file tag Plaso [S22], tetapi isi field-nya hanya dari contoh komunitas [S28]. Materi kuliah [S29] dipakai hanya untuk saran praktis yang tidak mengubah perintah. Semua isi PT JAB, termasuk waktu, jumlah event, hitungan corong, jadwal tidur, angka SRUM, isi file tag, nama file output, dan log sinkhole kedua, adalah contoh fiktif yang disusun agar konsisten dengan fakta insiden di Day sebelumnya, bukan kejadian nyata.
