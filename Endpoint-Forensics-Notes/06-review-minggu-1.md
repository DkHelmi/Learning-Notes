---
day: 06
title: 'Review Minggu 1: alur bukti dari keputusan akuisisi sampai timeline event log, peta konsep, glosarium, dan lab gabungan'
researched_on: 2026-10-16
versions_checked: 'Merangkum Day 01-05 tanpa riset baru. RFC 3227 (BCP 55, Feb 2002); NIST SP 800-86 (Agu 2006); NIST SP 800-61 Rev. 3 (Apr 2025, RS.AN-07); EZ Tools 2026.5.0 (CLI .NET 4.7.2 dan .NET 9, GUI hanya .NET 9); KAPE (EULA Solo 2020-06-04; FAQ dokumentasi 2026-02-11; changelog terakhir 1.3.0.2); KapeFiles !SANS_Triage v1.5 dan !EZParser v1.5 per 2026-10-16; Velociraptor 0.77.3 (5 Okt 2026; Windows.Triage.Targets tidak bawaan sejak 0.75); Volatility 3 2.28.2 (17 Sep 2026); Plaso 20260720; Sysmon (halaman terbit 2026-09-10); halaman event Security Microsoft Learn (arsip Windows 10); System Audit Policy recommendations (ms.date 2025-06-13); repo evtx maps (dicek 2026-10-16)'
---

# Day 06: Review Minggu 1 (akuisisi, lab, KAPE, Velociraptor, dan event log)

Cakupan: ringkasan Day 01-05, peta konsep satu alur bukti dari keputusan akuisisi sampai kalimat temuan, tabel artefak ke pertanyaan investigasi ke keterbatasan, benang bukti dan celah `INC-2026-019` (E01-E20) dalam bentuk serah terima kasus, glosarium, dan lab gabungan dari koleksi triage sampai timeline event log.

## Ide inti

Day 01-05 bukan lima alat, tetapi satu rantai yang menghasilkan dua hal di setiap mata rantainya: bukti atau hasil olahan, dan catatan cakupan yang menjelaskan batasnya. Keputusan akuisisi menghasilkan bukti dan daftar yang sengaja tidak diambil. Workstation analisis menghasilkan CSV dan inventaris versi alat yang dibekukan. Koleksi KAPE menghasilkan container dan copylog yang membuktikan file apa saja yang disalin. Hunt Velociraptor menghasilkan baris hasil dan daftar artifact, parameter, serta waktu koleksi. Event log menghasilkan timeline dan profil apa yang memang dikonfigurasi untuk dicatat. Setiap kalimat temuan, terutama "tidak ditemukan", hanya sekuat catatan cakupan terlemah di rantai yang menghasilkannya. Karena itu serah terima kasus forensik yang baik menyerahkan keduanya sekaligus, sehingga penerima bisa memverifikasi bukti dan melanjutkan pekerjaan tanpa bertanya ke penulisnya.

Kamu sudah mengenal pola ini dari serah terima shift NOC saat gangguan besar masih terbuka. Engineer yang pulang tidak cukup menulis "link Bandung masih down". Ia menulis capture apa yang sudah diambil dari perangkat mana, dengan skrip versi berapa, file mana yang sudah dikirim ke TAC, perangkat mana yang belum sempat di-capture dan kenapa, dan jam berapa teknisi lapangan dijadwalkan datang. Engineer shift berikutnya bisa melanjutkan tanpa menelepon orang yang sedang tidur. Bedanya di forensik: penerima juga harus bisa membuktikan sendiri bahwa bukti yang ia terima tidak berubah (hash dan chain of custody), dan setiap celah cakupan ditulis bersama risikonya, bukan hanya statusnya.

```
pertanyaan: "apakah X terjadi di host H?"
        |
        v
jawaban hanya sekuat catatan cakupan TERLEMAH di rantainya:
  keputusan    apa yang sengaja tidak diambil, dan risikonya    (case notes, Day 01)
  alat         versi beku, diuji di lab pada data yang dikenal   (inventaris, Day 02)
  koleksi      target yang disalin | artifact + parameter + waktu (copylog, Day 03 | hunt, Day 04)
  integritas   hash di titik koleksi + chain of custody         (evidence log, Day 01)
  pencatatan   audit policy, channel, rentang tiap file .evtx   (profil cakupan, Day 05)
        |
        v
"ada" | "tidak diambil" | "tidak ditemukan oleh ... pada ..., batas ..., keyakinan ..."
        |
        v
SERAH TERIMA = bukti + catatan cakupan + pekerjaan terbuka (bisa diverifikasi tanpa penulisnya)
```

Situasi yang dipakai di Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan dan data pribadi sekitar 400 ribu pelanggan broadband di sistem billing. Kasusnya `INC-2026-019`: lampiran `Tagihan-Okt-2026.zip` (berisi `Tagihan-Okt-2026.js`) dari `billing@vendor-tagihan.example` masuk ke 9 mailbox Senin 2026-10-12 pukul 15:58 dan dijalankan di tiga laptop staf penagihan: `JKT-WS-0388` (`andi.pratama`), `BDG-WS-0142` (`dewi.anggraini`, tanpa EDR), dan `JKT-WS-0412` (`rizky.saputra`, tanpa EDR). Persistence-nya scheduled task `\SysCacheUpdate` yang menjalankan `C:\Users\<user>\AppData\Roaming\SysCache\upd.ps1`, C2-nya `cdn-sync.example.net` (`203.0.113.77:443`), dan password akun service `svc_billing` yang dibaca dari skrip `export-tagihan.ps1` di laptop Andi dipakai untuk SSH ke server billing `jkt-billing01`. Sepanjang minggu ini kamu, analyst L2 yang memegang forensik endpoint, sudah memutuskan image (Day 01), menyiapkan workstation analisis (Day 02), mengolah triage `JKT-WS-0412` (Day 03), menjalankan koleksi ringan di enam penerima lain (Day 04), dan menyusun timeline event log laptop Andi (Day 05). Bukti kasus kini bernomor `INC-2026-019-E01` sampai `-E20`.

Jumat 2026-10-16 pukul 16:30, Dimas Prasetyo, SOC lead dan incident commander (IC), menulis kepadamu di kanal `#inc-2026-019`:

> "Minggu depan Rudi Hartanto jadi primary on-call L2, dan dia belum pernah pegang berkas forensik `INC-2026-019`. Tolong siapkan serah terima singkat sebelum pulang. Saya mau Rudi tahu: E01 sampai E20 itu apa saja, siapa yang ambil dan pakai apa, sekarang ada di mana, dan bagaimana membukanya tanpa merusak master. Bagaimana hasilnya dibaca sampai jadi timeline, termasuk memisahkan jejak tim kita sendiri. Celah apa yang masih ada: E14 yang tidak lengkap, enam penerima lain, laptop yang tanpa EDR, audit yang tidak sama di semua laptop, dan kalimat apa yang boleh dipakai untuk masing-masing. Terakhir, apa yang menunggu hari Senin. Kalau kamu tidak masuk Senin, Rudi harus bisa melanjutkan tanpa menelepon kamu."

Pesan itu memuat lima permintaan:

1. Bukti apa saja yang ada (E01-E20), siapa yang mengambil dengan alat apa, dan di mana sekarang?
2. Bagaimana bukti dibuka tanpa mengubah master, dan dengan alat versi berapa?
3. Bagaimana hasil olahan dibaca sampai menjadi timeline, termasuk memisahkan jejak responder?
4. Celah apa yang masih ada, dan kalimat apa yang boleh ditulis untuk tiap celah?
5. Apa yang menunggu Senin, dan apa isi dokumen serah terimanya?

Permintaan 1 dan 2 dijawab di bagian 1.8, permintaan 3 di bagian 1.9, permintaan 4 di bagian 1.10, dan permintaan 5 di bagian 1.11. Bagian 1.1 sampai 1.5 meringkas Day 01-05 sebagai bahannya, bagian 1.6 dan 1.7 menyusunnya menjadi peta, dan bagian 2-4 memintamu menjalankan seluruh alur di lab dan menulis serah terima untuk kasus lab-mu sendiri.

**Kapan relevan:** sebelum masuk artefak disk mendalam (Day 07 dan seterusnya, yang semuanya memakai koleksi dan salinan kerja dari minggu ini), sebelum menyerahkan kasus ke rekan, shift lain, atau retainer, dan sebelum interview yang meminta kamu menceritakan alur bukti dari koleksi sampai temuan.
**Kapan bukan jawaban:** review ini tidak menambah aturan baru; bila ada yang terasa baru, kembali ke Day asalnya. Review ini juga tidak membahas analisis memori (Day 14) dan artefak disk seperti Prefetch, `$MFT`, dan registry (Day 07-11); E01, E05, E08, E13, dan isi image E15-E18 di luar event log baru diolah di Day itu.

## 1. Ringkasan, peta konsep, dan glosarium

### 1.1 Day 01: alur kerja DFIR swasta

- Proses forensik punya empat tahap: collection, examination, analysis, reporting [S2]. Tahap itu tidak terikat satu fase IR: memori Selasa diambil sebelum containment, image Kamis setelahnya (Day 01 bagian 1.1).
- NIST SP 800-61 Rev. 3 (April 2025) menyebut data insiden tetap dianggap bukti walaupun chain of custody formal tidak selalu dijalankan, dan pengumpulannya mengikuti prosedur preservasi serta kebijakan retensi (RS.AN-07) [S3].
- Tiga pola akuisisi: full disk image (lengkap, termasuk unallocated, lambat), triage collection (cepat, hanya daftar target), dan adaptive collection (triage ditambah file yang dirujuk artefak saat koleksi) [S4]. Pola dipilih per host, bukan per kasus. Image dibenarkan oleh kemungkinan proses hukum atau regulator, kebutuhan file terhapus, atau host yang akan dihapus: "ambil sekarang atau tidak pernah" (Day 01 bagian 1.2 dan 2.5).
- Order of volatility RFC 3227: register dan cache; routing table, ARP cache, process table, memori; temporary file system; disk; remote logging; konfigurasi fisik; media arsip [S1]. Isi urutan disesuaikan dengan pertanyaan yang masih terbuka: sebelum `jkt-billing01` dimatikan, yang diambil hanya snapshot volatil singkat, bukan memori ulang (Day 01 bagian 1.3).
- Files On-Demand menaruh placeholder di disk: image offline hanya menangkap metadata, dan membuka file saat triage live memicu unduhan [S5].
- Hash SHA-256 membuktikan berkas tidak berubah sejak hash dihitung, bukan bahwa isinya benar, lengkap, atau diambil dengan cara yang tepat. `Get-FileHash` memakai SHA256 bila algoritma tidak disebut, dan MD5 serta SHA1 hanya cocok untuk validasi perubahan sederhana [S6]. Untuk perangkat fisik, integritas sebelum image dibuat dijaga segel, nomor kantong, foto segel, dan formulir chain of custody (Day 01 bagian 1.4 dan 2.4).
- Versi minimal yang bisa dipertanggungjawabkan: case notes kronologis dengan zona waktu, formulir chain of custody satu baris per perpindahan, dan penyimpanan dengan kontrol akses [S1]. Melewati sesuatu boleh, asal disengaja, dicatat, dan risikonya ditulis (Day 01 bagian 1.5 dan 1.6).
- Keputusan PT JAB Rabu 2026-10-14 18:40, disetujui Dimas 19:05: image `JKT-WS-0388` (E15) dan `JKT-WS-0412` (E16) Kamis 09:00, `jkt-billing01` (E17) Jumat 00:30 oleh retainer, `BDG-WS-0142` (E18) Senin 2026-10-19 09:00 oleh retainer; enam penerima email lain tidak di-image (Day 01 bagian 2.3 dan 2.5).

### 1.2 Day 02: setup lab dan workstation analisis

- Tiga ruang dipisahkan: bukti (master read-only), analisis (`JKT-DFIR01` Windows 11 dan `jkt-dfir02` Ubuntu LTS, keduanya tidak join domain dan tanpa internet kecuali proxy per jendela), dan lab terisolasi (`LAB-WS01` dengan Sysmon, `LAB-DFIR01`, host-only `172.16.50.0/24`; alat masuk lewat disk virtual) (Day 02 bagian 1.1).
- EZ Tools 2026.5.0: CLI untuk .NET 4.7.2 dan .NET 9, GUI termasuk Timeline Explorer hanya .NET 9 dan butuh Desktop runtime [S7]. Volatility 3 2.28.2 [S34], Velociraptor 0.77.3 karena perbaikan CVE [S23], Plaso 20260720 sebagai rilis stabil [S35].
- Lisensi KAPE punya dua sumber yang tidak sejalan. EULA KAPE Solo (terakhir diubah 2020-06-04) membatasi edisi gratis untuk tujuan non-komersial dan mengarahkan tujuan bisnis ke Enterprise License [S8]. FAQ dokumentasi KAPE (diperbarui 2026-02-11) menyebut penggunaan internal perusahaan gratis dan penggunaan komersial (jaringan pihak ketiga atau engagement berbayar) tidak lagi tersedia sejak 2026-01-01 [S9]. PT JAB memakai tafsir yang lebih ketat: Enterprise License, dipakai di jaringan pemegang lisensi dengan jumlah pengguna sesuai order [S10] (Day 02 bagian 1.2).
- Update punya tiga lapis: biner, definisi dan ancillary files (KapeFiles lewat `--sync`, maps EvtxECmd), dan data yang diunduh saat alat berjalan (symbol table Volatility). Salinan EZ Tools di `KAPE\Modules\bin` terpisah dari EZ Tools berdiri sendiri. Prinsipnya: update sebelum kasus, uji di lab, catat, lalu bekukan; folder alat disimpan per tanggal (Day 02 bagian 1.3).
- Kamis 2026-10-15 di PT JAB: jendela proxy 07:00 sampai 07:30, EZ Tools tetap 2026.5.0, `kape.exe --sync` 07:09, ancillary updater 07:15, Velociraptor toolkit 0.77.1 menjadi 0.77.3. Uji regresi 07:35 sampai 08:15 dengan `LabTask01` 07:42 WIB: 412 baris Sysmon dan 1.287 baris Security di kedua versi EvtxECmd. Versi dibekukan sampai kasus ditutup sejak 08:45 (Day 02 bagian 2.2, 2.3, 2.8).
- Bukti dibuka dengan tiga lapis kontrol: izin share (`\\jkt-evid01\evidence` read-only untuk analyst, hanya `adm.yoga` yang menulis), mount read-only di klien, dan hash. Lapis kedua bukan jaminan: ext3 dan ext4 bisa me-replay journal walau di-mount `ro` [S12], dan `Mount-DiskImage` me-mount VHD/VHDX read-write bila `-Access` tidak ditulis [S11] (Day 02 bagian 1.5).
- Struktur kasus: `/evidence/INC-2026-019/` untuk master dan `.sha256`, `/cases/INC-2026-019/` untuk `work/`, `analysis/<bukti>/<versi alat>/`, `notes/case-notes.md`, dan `tools/tool-inventory-2026-10-15.csv` (Day 02 bagian 1.6 dan 2.8).

### 1.3 Day 03: triage dengan KAPE

- Targets mengumpulkan file dan hasilnya adalah bukti yang di-hash; Modules memproses salinan dan hasilnya olahan yang bisa dibuat ulang (Day 03 bagian 1.1).
- `!SANS_Triage` v1.5 mengumpulkan artefak dengan lokasi yang dikenal (event log, registry hive, Prefetch, `$MFT`, `$J`, XML scheduled task, dan lainnya), bukan folder sembarang di profil pengguna. Target `Syscache` mengumpulkan `Syscache.hve`, bukan folder `SysCache` penyerang [S15] (Day 03 bagian 1.2).
- File terkunci dibaca lewat raw read (kolom `DeferredCopy` di copylog). Copylog mencatat setiap file yang disalin dengan `SourceFileSha1`; skiplog mencatat yang dilewati (`Deduped` atau `Excluded`) [S14]. `--vss` bernilai false secara bawaan, dan `--zv` bernilai true sehingga `--vhdx` menghasilkan VHDX yang dikompres [S13] (Day 03 bagian 1.3 dan 1.4).
- Ada tiga lapis hash yang berbeda: arsip `.zip`, file `.vhdx` di dalamnya, dan SHA-1 per file di copylog (Day 03 bagian 1.4).
- `!EZParser` v1.5 menjalankan rangkaian EZ Tools atas koleksi, tetapi tidak punya parser untuk XML scheduled task dan tidak bisa memunculkan isi file yang tidak dikumpulkan [S16] (Day 03 bagian 1.6).
- Laporan triage membedakan tiga kategori: ada, tidak ada karena tidak diambil, dan tidak ditemukan di yang diambil. Copylog adalah alat ukurnya (Day 03 bagian 1.7).
- E14 di PT JAB: Yoga login konsol dengan `adm.yoga` Selasa 18:00, KAPE dari `USB-E-11` 18:02 sampai 18:29 dengan `!SANS_Triage` tanpa `--vss` dan tanpa target custom (keputusan tertulis), 3.118 file disalin, 46 deferred, 14 deduped. SHA-256 arsip dihitung 18:48 (`4c7e...`), master di `jkt-evid01` 19:05. Kamis: salinan kerja `E14-W1`, `!EZParser` 10:56 sampai 11:31, daftar "ada, tidak diambil, menunggu E16" ke Sari 12:40 (Day 03 bagian 2.1, 2.4, 2.6).
- Temuan E14: Prefetch `WSCRIPT.EXE` dengan `Tagihan-Okt-2026.js` Senin 20:14:21 WIB, `upd.ps1` dibuat 20:14:37 WIB (4.812 byte, hanya metadata dari `$MFT`), task terdaftar 20:14:39, 4104 pertama 20:14:52, tanpa 4698 (Day 03 bagian 2.5). Retainer yang menawarkan menjalankan KAPE di laptop Dewi tidak memakai lisensi PT JAB; Legal yang memutuskan (Day 03 bagian 1.5).

### 1.4 Day 04: Velociraptor dasar

- Velociraptor terdiri dari client, server, VQL, dan artifact. Collection menjalankan artifact di satu client; hunt menjalankannya ke semua client yang cocok kondisi. Hunt dibuat dalam keadaan `Paused`, kedaluwarsa (bawaan satu minggu), dan terjadwal otomatis ke client baru yang diberi label yang cocok selama masih aktif [S19] (Day 04 bagian 1.4).
- `Windows.Triage.Targets` adalah nama baru `Windows.KapeFiles.Targets` dan tidak bawaan sejak 0.75, sehingga harus diimpor, misalnya lewat `Server.Import.Extras` [S4][S18]. Parameternya menentukan isi koleksi: `CollectionPolicy` (`ExcludeSigned` bawaan, `HashOnly`, `AllFiles`), meta-target `_Live` untuk aturan adaptive, dan `VSS_MAX_AGE_DAYS` bawaan 0 [S17] (Day 04 bagian 1.3).
- Server sementara `jkt-velo01` (`10.20.1.30`) dengan TCP 8000 untuk client dan 8889 untuk GUI. Client sampai ke host lewat tiga jalan: live response Defender (`putfile` lalu `run`) untuk empat host ber-EDR [S22], admin share dan eksekusi jarak jauh dari `JKT-JUMP01` dengan `adm.yoga` untuk `JKT-WS-0418`, dan offline collector untuk `BDG-WS-0147` (Day 04 bagian 1.2).
- Offline collector dijalankan tanpa argumen dan sebagai administrator [S21]; SHA-256 container ditulis di log dengan pesan `Container hash`, container X.509 dengan sertifikat server didekripsi otomatis saat diimpor dengan `Server.Utils.ImportCollection`, dan `Windows.KapeFiles.Extract` mempertahankan timestamp saat mengekstrak [S20] (Day 04 bagian 1.5 dan 1.6).
- Hasil negatif yang jujur menyebut apa yang dicari, dengan artifact dan parameter apa, kapan, dan apa yang tidak tercakup, ditambah kontrol positif di lab dan tingkat keyakinan per kelompok host (Day 04 bagian 1.7).
- Di PT JAB: hunt `H.D1K7Q3` dibuat Kamis 19:10, di-Start Jumat 09:00, kedaluwarsa Jumat 17:00. Ekspor lima host menjadi E19 (Prepare Download 11:30 sampai 11:44, sekitar 1,09 GB, `a7c3...`). Offline collector dijalankan Fajar Nugraha di POP Bandung 13:40 sampai 14:06 dari `USB-E-12` menjadi E20 (`Container hash` `5be1...`). Satu-satunya kecocokan IOC: `Tagihan-Okt-2026.zip` di folder Downloads `eko.prasetyo` tanpa tanda eksekusi, dihapus IT 11:40 setelah hash dicatat (Day 04 bagian 2.5 sampai 2.8).

### 1.5 Day 05: Windows event log untuk forensik

- Event log adalah rekaman apa yang host dikonfigurasi untuk dicatat, selama file-nya belum berputar. Urutannya selalu: petakan dulu apa yang dicatat (file per channel, rentang waktu, audit policy, Sysmon, 1102, 104, 4719), baru susun cerita (Day 05 bagian Ide inti dan 1.6).
- Sesi disusun dari 4624 dan 4625 dengan logon type, `TargetLogonId`, `TargetLinkedLogonId`, dan `ElevatedToken`; satu login admin dengan UAC menghasilkan dua 4624 yang saling menunjuk [S24]. Penyerang yang menumpang sesi pengguna memakai Logon ID pengguna itu, sehingga pelakunya dibedakan lewat rantai proses (Day 05 bagian 1.2).
- Eksekusi dan persistence datang dari beberapa sumber: 4688 (butuh audit dan setting command line yang terpisah) [S28], Sysmon 1 dengan command line, induk, dan hash [S29], 4698 berisi XML task dan sejak Windows 10 1903 juga `ClientProcessId` [S25], TaskScheduler 106/200/201, System 7045 (tanpa pemasang) dan 4697 (dengan pemasang), serta 4104 yang menyimpan isi script block, termasuk password dari skrip sah [S30] (Day 05 bagian 1.3).
- Nilai bawaan audit Windows client tidak mengaktifkan Process Creation, Other Object Access Events, Security Group Management, dan Security System Extension [S27]. Tanpa script block logging, Windows PowerShell tetap mencatat blok yang dianggap mencurigakan dengan level Warning [S31] (Day 05 bagian 1.5).
- 1102 (Security) dan 104 (System) ditulis saat log dibersihkan, dan 4719 saat audit policy berubah [S26][S28]. Ketiadaannya bukan bukti log utuh (Day 05 bagian 1.6).
- Di CSV EvtxECmd, kolom `UserName` untuk 4624 berisi Subject (akun yang melaporkan), sedangkan akun yang login ada di `PayloadData1` [S33]. Lokasi maps ditulis eksplisit dengan `--maps`, dan semua waktu dalam UTC [S32] (Day 05 bagian 1.7 dan 2.1).
- Di PT JAB: GPO audit `JAB-WS-Audit` hanya terpasang di `OU=Workstations-EDR,OU=Jakarta,DC=corp,DC=jab,DC=example`; `JKT-WS-0412` masih di OU lama dengan audit bawaan, tanpa Sysmon, tanpa history Task Scheduler (Day 05 bagian 1.5 dan 2.7).
- E15-W1 (dibuat Yoga Jumat 08:10): 138 file `.evtx`, 174.306 event, nol 1102, 104, dan 4719. Andi login Senin 07:58:14 WIB (sesi `0x3A1F2C`, tanpa 4672). Rantai Senin 16:04:48 sampai 16:06:05, task berjalan 258 kali, pembacaan `export-tagihan.ps1` 23:40:17 hanya terlihat dari 4104, SSH Selasa 02:14:31. Jejak responder: akun admin lokal khusus IR `ir-admin` Selasa 12:38 sampai 12:55 dan Kamis 08:46 sampai 08:47. Timeline dikirim ke Sari 13:20 (Day 05 bagian 2.2 sampai 2.8).

### 1.6 Peta konsep

Peta berikut menggabungkan diagram Day 01-05 dalam satu gambar. Kolom kanan adalah catatan cakupan yang dihasilkan setiap langkah; pakai peta ini sebagai satu-satunya bantuan saat uji lisan di bagian 2-4.

```
LANGKAH                     HASIL                                      CATATAN CAKUPAN
KEPUTUSAN (Day 01)          pola per host: triage | adaptive | image   case notes: yang dilewati + risiko
  order of volatility       urutan pengambilan, isi sesuai pertanyaan
      |
      v
TEMPAT KERJA (Day 02)       JKT-DFIR01, jkt-dfir02, lab LAB-WS01       inventaris versi + hasil uji regresi
  update -> uji -> bekukan  folder alat bertanggal                     (versi dibekukan per kasus)
      |
      v
KOLEKSI
  1 host, akses langsung    KAPE Targets -> VHDX/zip (Day 03)          copylog, skiplog, console log
  banyak host / jauh        Velociraptor hunt -> ekspor (Day 04)       artifact + parameter + waktu + host
  host tak terjangkau       offline collector -> container (Day 04)    Container hash di log collector
      |
      v
SIMPAN (Day 01-02)          hash di titik koleksi -> CoC -> master     evidence-log.csv, .sha256
                            /evidence (read-only) -> salinan kerja
      |
      v
OLAH (Day 02-05)            mount read-only -> !EZParser / EvtxECmd    folder analysis/<bukti>/<versi alat>
                            --maps -> CSV (UTC)
      |
      v
BACA (Day 05)               profil cakupan -> sesi (Logon ID) ->       profil audit per host; rentang file
                            isi sesi -> pelaku (pengguna | penyerang |
                            responder) -> timeline WIB
      |
      v
TEMUAN                      ada | tidak diambil | tidak ditemukan oleh ... pada ..., batas ..., keyakinan ...
      |
      v
SERAH TERIMA                bukti + catatan cakupan + pekerjaan terbuka + kontak
```

Tiga benang dipakai untuk menguji peta ini dengan `INC-2026-019`:

1. **Benang bukti:** setiap nomor bukti punya pengambil, alat, waktu, hash, lokasi master, salinan kerja, dan status olah (bagian 1.8).
2. **Benang pembacaan:** setiap hasil olahan bisa ditelusuri dari CSV ke kalimat temuan, dan jejak tim sendiri dipisahkan dengan cara yang bisa diperiksa (bagian 1.9).
3. **Benang celah:** setiap celah punya penyebab yang tertulis, yang tetap bisa dijawab, kalimat yang boleh dipakai, dan cara menutupnya (bagian 1.10).

### 1.7 Artefak, pertanyaan investigasi, dan keterbatasan

Tabel ini adalah rangkuman paling padat minggu ini: setiap sumber bukti yang sudah dipakai, pertanyaan yang bisa dijawabnya, dan keterbatasan yang wajib ikut tertulis di laporan. Baca kolom kanan lebih dulu saat menulis kalimat "tidak ditemukan".

| Artefak atau bukti | Pertanyaan yang dijawab | Keterbatasan | Day |
|---|---|---|---|
| Memori (E01, E05, E08, E13) | Proses, koneksi, dan kode yang hanya ada di RAM saat itu | Hanya kondisi saat diambil; analisisnya di Day 14 | 01 |
| Full disk image (E15-E18) | File terhapus, unallocated space, shadow copy, semua artefak disk | Besar dan lambat; tidak berisi memori; perlu salinan kerja dan mount read-only | 01, 02 |
| Koleksi triage KAPE (E14) | Artefak kunci satu host dengan cepat | Hanya path di daftar target; tanpa unallocated; tanpa shadow copy bila `--vss` tidak dipakai; koleksi live mengubah sebagian timestamp | 03 |
| Copylog dan skiplog | File apa yang benar-benar disalin, dari mana, dengan SHA-1 apa | Membuktikan cakupan dan isi saat disalin, bukan kelengkapan host | 03 |
| Hasil hunt Velociraptor (E19) | Ada atau tidaknya IOC di banyak host sekaligus | Hanya artifact, parameter, dan waktu yang dipakai; hanya client yang online selama hunt aktif | 04 |
| Container offline collector (E20) | Pertanyaan yang sama untuk host yang tidak terjangkau server | Cakupan dikunci saat collector dibangun; tidak bisa diulang dari jauh | 04 |
| Hash SHA-256 | Apakah bukti berubah sejak hash dihitung | Tidak membuktikan cara pengambilan atau kelengkapan; perangkat fisik butuh segel dan CoC sampai image dibuat | 01 |
| Case notes dan chain of custody | Siapa melakukan apa, kapan, kenapa; siapa memegang bukti di setiap perpindahan | Hanya sebaik saat ditulis; celah satu baris bisa membuat seluruh rantai dipertanyakan | 01 |
| Security 4624, 4625, 4672, 4647 | Siapa login, kapan, dengan cara apa, dengan hak apa | Logon type wajib ditafsirkan; `UserName` di CSV untuk 4624 adalah Subject; rotasi | 05 |
| Security 4688 dan Sysmon 1 | Proses apa yang dijalankan, dengan command line dan induknya | 4688 butuh Audit Process Creation dan setting command line; Sysmon hanya bila terpasang | 05 |
| Security 4698, TaskScheduler 106/200/201 | Task dibuat oleh proses apa, dan kapan dijalankan | 4698 butuh Audit Other Object Access Events; channel TaskScheduler bisa tidak aktif | 05 |
| System 7045, Security 4697 | Service atau driver dipasang | 7045 tanpa pemasang; 4697 butuh Audit Security System Extension; alat akuisisi memori juga memuat driver | 05 |
| PowerShell 4104 | Isi kode PowerShell, termasuk hasil decode `-enc` | Lengkap hanya bila script block logging aktif; tanpa itu hanya blok Warning; bisa menyimpan password | 05 |
| Security 1102, System 104, Security 4719 | Log dibersihkan atau audit policy diubah | Ketiadaannya bukan bukti log utuh; pembacaan file tidak tercatat sama sekali | 05 |
| `$MFT` dan `$J` dari triage | Nama, path, ukuran, dan waktu file, termasuk entri file terhapus yang belum tertimpa | Tidak membawa isi file; tafsir timestamp di Day 08 | 03 |
| Prefetch dari triage atau hunt | Program apa yang dijalankan dan file apa yang disentuhnya | File `.pf` bisa tertimpa atau dihapus; dibahas mendalam di Day 07 | 03, 04 |
| Cache DNS dari hunt | Entri yang masih ada di cache saat koleksi | Lookup hari-hari sebelumnya hampir pasti sudah hilang; ketiadaan entri tidak membuktikan apa pun | 04 |

### 1.8 Benang bukti: E01-E20, dari koleksi ke master dan salinan kerja

Permintaan pertama Dimas dijawab tabel berikut. Semua waktu WIB; kolom "Status" menyebut apakah bukti sudah diolah minggu ini. Baca per baris dari kiri ke kanan: setiap bukti harus bisa ditelusuri dari pengambil sampai salinan kerjanya.

| Bukti | Isi | Diambil oleh, waktu, alat | Disimpan | Status per Jumat 16:30 | Asal |
|---|---|---|---|---|---|
| E01 | Memori `JKT-WS-0388` | Yoga, Selasa 12:42-12:53, WinPmem dari `USB-E-07` dengan `ir-admin` | Master `jkt-evid01` | Dianalisis retainer; tidak menemukan akses ke LSASS | Day 05 bagian 1.4 dan 2.6 |
| E02 | Paket investigasi Defender `JKT-WS-0388` | Live response Defender, Selasa 12:31 | Master `jkt-evid01` | Belum diolah di Day ini | Day 05 bagian 2.6 |
| E03 | File penyerang dan skrip kredensial dari `JKT-WS-0388` | `getfile` live response, Selasa 12:36 | Master, akses terbatas (berisi password `svc_billing`) | Bahan pembanding isi `upd.ps1` | Day 01 bagian 2.5 |
| E04-E07 | `jkt-billing01`: output live response, memori, biner penyerang, `/var/log` | Selasa; memori dengan AVML 13:20-13:41 | Master `jkt-evid01` | Di luar cakupan endpoint Windows minggu ini | Day 01 bagian 1.3 dan 2.5 |
| E08 | Memori `BDG-WS-0142` | Fajar Nugraha, Selasa 14:05-14:13, WinPmem dari `USB-E-09` | Master `jkt-evid01` | Diserahkan ke retainer | Day 01 bagian 2.5 |
| E09-E12 | Bukti pendukung lain hari Selasa (antara lain email asli dan ekspor log jaringan) | Selasa | Master `jkt-evid01` | Tidak diolah minggu ini | Day 01 bagian Ide inti |
| E13 | Memori `JKT-WS-0412` | Yoga, Selasa 17:45-17:58, WinPmem dari `USB-E-10` dengan elevasi `ir-admin` | Master `jkt-evid01` | Diserahkan ke retainer | Day 03 bagian 2.1 |
| E14 | Triage KAPE `JKT-WS-0412` (`INC-2026-019-E14_JKT-WS-0412_triage.zip`) | Yoga, Selasa 18:02-18:29, KAPE `!SANS_Triage` dari `USB-E-11`, `adm.yoga` | Master 19:05 (`4c7e...`), diverifikasi ulang Kamis 08:52; salinan kerja `E14-W1` | Diolah Kamis dengan `!EZParser`; hasil di `analysis/E14-W1/EZ-2026.5.0/` | Day 03 bagian 2.1 sampai 2.6 |
| E15 | Image disk `JKT-WS-0388` | Kamis 09:00, sebelum reimage | Master; salinan kerja `E15-W1` Jumat 08:10 | Event log diolah Jumat; artefak lain belum | Day 05 bagian 2.1 sampai 2.8 |
| E16 | Image disk `JKT-WS-0412` | Kamis 09:00, sebelum reimage | Master | Belum diolah; menjawab kolom "menunggu E16" | Day 03 bagian 2.6 |
| E17 | Image disk `jkt-billing01` | Retainer, Jumat 00:30, setelah snapshot volatil singkat | Master | Di tangan retainer | Day 01 bagian 2.5 |
| E18 | Image disk `BDG-WS-0142` (perangkat fisik `E18-D`) | Dijadwalkan retainer Senin 2026-10-19 09:00 | Laptop dalam kurir sejak 10:10 (kantong No. 0092, resi `INT-1016-023`) | Menunggu; diterima Yoga sore ini lalu lemari bukti SOC | Day 01 bagian 2.4 |
| E19 | Ekspor hunt `H.D1K7Q3`, lima host | Hunt Jumat 09:00-11:30; Prepare Download 11:30-11:44 | Master (`a7c3...`, sekitar 1,09 GB) | Dibaca di notebook; nol IOC selain ZIP di Downloads Eko | Day 04 bagian 2.5 dan 2.7 |
| E20 | Container offline `BDG-WS-0147` | Fajar, Jumat 13:40-14:06, offline collector dari `USB-E-12` | Salinan elektronik `E20-C` di `jkt-evid01` 14:40 (`5be1...`, cocok); `USB-E-12` dalam kurir (kantong No. 0093, resi `INT-1016-027`) | `E20-C` diimpor dan dibaca; master fisik tiba Senin 08:45 | Day 04 bagian 2.6 dan 2.7 |

Tiga hal terlihat bila tabel dibaca dari atas ke bawah:

- **Hash mulai di titik yang berbeda.** E14 di-hash 19 menit setelah KAPE selesai, sehingga SHA-1 per file di copylog menjadi pemeriksaan tambahan atas isi (Day 03 bagian 1.4). E20 sudah punya hash di titik koleksi lewat `Container hash` [S20]. E18 belum punya hash sama sekali: sampai image dibuat Senin, yang melindunginya adalah segel, nomor kantong, dan formulir chain of custody (Day 01 bagian 1.4).
- **Yang diolah selalu salinan kerja.** E14-W1 dan E15-W1 dibuat Yoga dari master setelah verifikasi hash; master hanya dibaca untuk diverifikasi dan disalin (Day 02 bagian 1.5).
- **Satu bukti, beberapa lokasi.** E20 punya salinan elektronik yang sudah dianalisis dan media fisik yang masih di perjalanan. Keduanya harus cocok dengan nilai `Container hash` yang sama sebelum media fisik menjadi master.

Permintaan kedua Dimas ("bagaimana membukanya tanpa merusak master, dengan alat versi berapa") dijawab dengan aturan yang sudah berlaku sejak Kamis pagi:

1. Mount share bukti dengan akun analyst biasa, bukan `adm.<nama>`, supaya lapis izin server tetap bekerja (Day 02 bagian 2.8).
2. Verifikasi hash salinan kerja terhadap `.sha256` master sebelum dipakai; bila `FAILED`, ambil ulang dari master (Day 01 bagian 2.2).
3. Container VHDX di-mount dengan `Mount-DiskImage -Access ReadOnly` [S11]; image disk di-mount dengan alat yang sudah diuji tim dan mode read-only dicatat (Day 05 bagian 2.1).
4. Alat dijalankan dari folder yang dibekukan: EZ Tools 2026.5.0 di `C:\DFIR\tools\EZTools-2026-10-15`, KAPE dengan definisi hasil sync Kamis 07:09, Velociraptor 0.77.3, Volatility 3 2.28.2 di `jkt-dfir02`. Hasil ditulis ke `analysis/<bukti>/<versi alat>/` supaya retainer tahu versi parser tanpa bertanya (Day 02 bagian 1.3 dan 1.6).
5. Data sensitif diberi akses terbatas: E03 berisi skrip dengan password, dan CSV event log E15-W1 memuat password `svc_billing` di 4104 dari eksekusi skrip sah [S30] (Day 05 bagian 2.5).

### 1.9 Benang pembacaan: dari CSV ke kalimat temuan, dan jejak tim sendiri

Permintaan ketiga Dimas menyangkut cara membaca. Urutannya sama untuk setiap bukti, apa pun mesin koleksinya, karena hasil KAPE dan Velociraptor masuk ke pipeline EZ Tools yang sama (Day 04 bagian 1.6):

1. **Profil cakupan dulu.** Untuk koleksi KAPE, baca console log dan copylog (jumlah file, deferred copy, baris `VSS*`). Untuk hunt, tulis artifact, parameter, waktu, dan host yang selesai. Untuk event log, hitung event dan rentang waktu per channel, cari 1102, 104, dan 4719, dan hitung event per subcategory audit (Day 03 bagian 2.3, Day 04 bagian 2.5, Day 05 bagian 2.2 dan 2.7).
2. **Parse dengan alat beku.** `!EZParser` untuk volume KAPE, EvtxECmd dengan `--maps` eksplisit untuk folder log image, dan `Windows.KapeFiles.Extract` lebih dulu untuk container Velociraptor karena struktur foldernya (`uploads/ntfs/`, path di-escape) berbeda dari KAPE [S20].
3. **Susun sesi dan rantai proses.** Akun dari `PayloadData1`, bukan `UserName`; Logon ID mengikat proses, task, dan logoff ke sesinya; `ClientProcessId` di 4698 mengikat pembuatan task ke proses yang membuatnya [S25][S33].
4. **Pisahkan pelaku.** Setiap baris timeline diberi salah satu dari tiga nilai: pengguna, penyerang, atau responder.
5. **Tulis UTC dan WIB sekali, lalu WIB saja.** CSV EZ Tools, Sysmon, dan Velociraptor dalam UTC; laporan PT JAB dalam WIB. Selasa 02:14 WIB adalah Senin 19:14 UTC.
6. **Tulis kalimat temuan dengan cakupannya.** "Ada", "tidak diambil", atau "tidak ditemukan oleh ... pada ..., batas ..., keyakinan ...".

Langkah keempat paling sering ditanyakan orang di luar tim, karena jejak tim sendiri terlihat persis seperti jejak penyerang bila dibaca tanpa konteks. Tabel berikut mengumpulkan semua jejak responder yang sudah diketahui di `INC-2026-019`. Baca kolom "Pasangan di catatan": setiap jejak harus punya baris di case notes, evidence log, atau Command log EDR.

| Host | Waktu (WIB) | Jejak di host | Pelaku | Pasangan di catatan |
|---|---|---|---|---|
| `JKT-WS-0388` | Selasa 12:31-12:37 | Proses sensor Defender sebagai SYSTEM (paket investigasi, `getfile`) | Yoga lewat live response | Riwayat Action center |
| `JKT-WS-0388` | Selasa 12:38-12:55 | 4625 salah ketik, 4624 type 2 berpasangan dengan elevated token, 4672, `cmd.exe` `%%1937`, WinPmem dari `E:\tools\`, 7045 dan 4697 kernel driver, `certutil`, 4647 | Yoga dengan `ir-admin` | Case notes Yoga; evidence log E01 12:42-12:53 |
| `JKT-WS-0388` | Kamis 08:46-08:47 | 4624 `ir-admin`, 4672, System 1074 dan 6006 | Yoga mematikan laptop sebelum image | Case notes; jadwal image E15 09:00 |
| `JKT-WS-0412` | Selasa 17:43-18:35 | `USB-E-10` dicolok 17:43 di sesi Rizky, elevasi UAC dengan `ir-admin` 17:44 untuk WinPmem (memori E13 17:45-17:58), logon konsol `adm.yoga` 18:00, KAPE dari `USB-E-11` 18:02 (tanpa 4688 karena audit bawaan) | Yoga | Case notes E13 dan E14 |
| `JKT-WS-0395`, `-0397`, `BDG-WS-0151` | Kamis 17:48, 17:55, 18:12 | MSI Velociraptor, service `velociraptor` di `C:\Program Files\Velociraptor\` | Pemasangan lewat live response | Command log Defender; case notes per host |
| `JKT-WS-0405` | Jumat 10:24 | Idem | Live response diulang 10:20 | Command log Defender |
| `JKT-WS-0418` | Kamis 17:35 | MSI disalin lewat admin share, `msiexec` dari jarak jauh | Yoga dengan `adm.yoga` dari `JKT-JUMP01` | Case notes |
| `BDG-WS-0147` | Jumat 13:40-14:06 | Offline collector dari `USB-E-12` sebagai admin | Fajar dengan akun admin teknisi POP | Formulir CoC E20; `Container hash` |

Pemisahan itu tidak bergantung pada satu tanda. Untuk `JKT-WS-0388`, kombinasinya adalah akun dan Logon ID (`ir-admin` dengan sesi sendiri, terpisah dari sesi Andi `0x3A1F2C`), waktu yang cocok menit demi menit dengan case notes, path di drive USB bukti, dan induk proses serta tipe token (proses responder `%%1937` berinduk `cmd.exe` di sesi `ir-admin`, proses penyerang `%%1938` berinduk `wscript.exe`, `powershell.exe`, atau layanan Task Scheduler) (Day 05 bagian 1.4). Driver akuisisi memori yang memicu 7045 kernel driver adalah contoh yang paling mudah disalahbaca; nama service-nya bergantung versi WinPmem dan harus dicocokkan dengan uji alat di lab (Day 05 bagian 1.4). Untuk host yang dipasangi client Velociraptor, jejak pemasangan juga harus dicatat supaya analisis berikutnya tidak membacanya sebagai persistence penyerang (Day 04 bagian 1.2).

Hasil pembacaan minggu ini untuk laptop Andi sudah berbentuk timeline dengan kolom Pelaku dan Sumber (Day 05 bagian 2.8). Kalimat terkuatnya ("tidak ada RDP atau logon jaringan dari host lain, tidak ada akun baru, tidak ada pembersihan log") sah karena semua subcategory yang relevan diaudit dan semua channel mencakup periode kasus. Kalimat yang sama tidak boleh disalin ke host lain sebelum profil cakupannya dibuat.

### 1.10 Benang celah: empat celah dan kalimat yang boleh ditulis

Permintaan keempat Dimas adalah bagian yang paling berbahaya bila diserahkan secara lisan. Tabel berikut memuat empat celah yang ia sebut. Baca kolom "Kalimat yang boleh ditulis" sebagai batas atas: kalimat yang lebih kuat dari itu tidak didukung bukti.

| Celah | Penyebab yang tertulis | Yang tetap bisa dijawab | Kalimat yang boleh ditulis | Penutup celah |
|---|---|---|---|---|
| E14 tidak lengkap | Keputusan Yoga Selasa 18:02: target standar tanpa target custom IOC dan tanpa `--vss`, karena host baru ditemukan dan target custom belum teruji | Kapan lampiran dijalankan (Prefetch), task dan perintahnya (XML), metadata `upd.ps1` (`$MFT`, `$J`), sebagian isi loader (4104 Warning) | "Isi `upd.ps1`, lampiran di profil pengguna, versi dari shadow copy, dan file terhapus tidak diambil di E14; dijawab dari E16." | Olah salinan kerja E16 yang di-mount read-only dengan Targets yang sama (`--tsource` diisi huruf drive mount) ditambah `INC2026019_IOC` yang sudah diuji di lab, lalu bandingkan dengan copylog E14 (Day 03 bagian 1.7 dan 2.7) |
| Enam penerima lain | Keputusan Rabu: tidak di-image karena pivot SIEM dan EDR tidak menemukan eksekusi atau koneksi C2 | Ada atau tidaknya task, file, eksekusi script host, string IOC, dan cache DNS saat koleksi Jumat | "Tidak ditemukan task `\SysCacheUpdate`, `upd.ps1`, eksekusi `Tagihan-Okt-2026.js`, atau string IOC pada koleksi Jumat; tidak mencakup memori, file terhapus, VSS, log yang sudah dirotasi; keyakinan sedang-tinggi untuk empat host ber-EDR dan sedang untuk dua host tanpa EDR." | Host yang terindikasi pindah ke pola memori dan image (Day 04 bagian 2.8) |
| Host tanpa EDR (`BDG-WS-0142`, `JKT-WS-0412`, `JKT-WS-0418`, `BDG-WS-0147`) | Belum di-onboard Defender dan Sysmon | Artefak disk dan memori bila diambil; log jaringan di luar host | Untuk `BDG-WS-0142`: sumber di host hanya memori E08 dan image E18. Untuk `JKT-WS-0418` dan `BDG-WS-0147`: "hanya artefak host dan log jaringan" | Artefak eksekusi di image (Day 07); keyakinan diturunkan dan ditulis per host |
| Audit tidak seragam | GPO `JAB-WS-Audit` hanya terpasang di OU `Workstations-EDR`; laptop yang belum di-onboard tetap di OU lama dengan audit bawaan | Logon, logoff, special logon, manajemen akun (bawaan); 4104 Warning | "Event X tidak ada karena host ini tidak dikonfigurasi mencatatnya", bukan "X tidak terjadi" | Profil cakupan per host sebagai baris pertama laporan; usulan memindahkan workstation ke cakupan audit yang sama tanpa menunggu EDR (Day 05 bagian 2.7) |

Satu hubungan antar celah perlu ditulis eksplisit untuk Rudi. Mengikuti aturan OU di Day 05, laptop tanpa EDR seperti `JKT-WS-0418` kemungkinan besar juga berjalan dengan audit bawaan dan tanpa Sysmon, sehingga regex IOC di `Windows.EventLogs.EvtxHunter` hanya mencari di channel yang memang aktif di laptop itu (Day 04 bagian 1.7). OU `JKT-WS-0418` dan `BDG-WS-0147` belum dicek di AD; cek keduanya, dan hitung event per subcategory dari event log yang ikut terkumpul di E19 dan E20 seperti Day 05 bagian 2.7, sebelum menulis keyakinan akhir untuk dua host itu.

Pola yang sama muncul di keempat baris: celah tidak disembunyikan, tetapi ditulis bersama penyebabnya, sehingga pembaca bisa membedakan keputusan yang disengaja dari kelalaian. Celah pertama dan kedua adalah keputusan; celah ketiga dan keempat adalah kondisi lingkungan yang membatasi semua keputusan itu.

### 1.11 Pekerjaan terbuka dan dokumen serah terima untuk Rudi

Permintaan kelima Dimas dijawab dengan dokumen serah terima. Isinya disusun dari bagian 1.8 sampai 1.10 dan disimpan di `notes/` area kerja kasus, supaya Rudi membaca versi yang sama dengan yang tersimpan, bukan salinan di chat.

```
INC-2026-019 | Serah terima forensik endpoint | dari: <kamu> ke: Rudi Hartanto | Jumat 2026-10-16 17:20 WIB
Lokasi: \\jkt-evid01\cases\INC-2026-019\notes\serah-terima-2026-10-16.md (dasar: case-notes.md, evidence-log.csv)

1. AKSES DAN ATURAN
   Master: \\jkt-evid01\evidence (read-only; hanya Yoga/adm.yoga menulis). Area kerja: \\jkt-evid01\cases\INC-2026-019\
   Mount dengan akun analyst biasa. VHDX: Mount-DiskImage -Access ReadOnly. Verifikasi .sha256 sebelum dipakai.
   Versi BEKU sampai kasus ditutup: EZ Tools 2026.5.0 (C:\DFIR\tools\EZTools-2026-10-15), KAPE + KapeFiles sync Kamis 07:09,
   Velociraptor 0.77.3, Volatility 3 2.28.2. Inventaris: tools\tool-inventory-2026-10-15.csv
   Sensitif: E03 (skrip berisi password) dan CSV event log E15-W1 (4104 memuat password svc_billing).
2. STATUS BUKTI: tabel E01-E20 terlampir (pengambil, alat, hash, master, salinan kerja, status olah).
   Diolah: E14 (!EZParser), E15 event log (timeline ke Sari 13:20), E19 dan E20-C (notebook jkt-velo01).
3. CELAH (kalimat yang boleh dipakai ada di lampiran; jangan diperkuat)
   E14 tidak lengkap -> tunggu E16 | enam penerima -> nol IOC, keyakinan per kelompok host
   host tanpa EDR -> keyakinan diturunkan | audit tidak seragam -> profil cakupan per host dulu
4. JADWAL
   Jumat 17:00   hunt H.D1K7Q3 kedaluwarsa. Sebelum itu jangan beri label inc-2026-019 ke client lain.
   Jumat sore    laptop Dewi (E18-D, kantong 0092, resi INT-1016-023) diterima Yoga -> lemari bukti SOC.
   Senin 08:45   USB-E-12 (E20, kantong 0093, resi INT-1016-027) diterima Yoga: cek segel, cocokkan dengan
                 Container hash 5be1..., isi CoC, master ke jkt-evid01.
   Senin 09:00   image E18 oleh retainer di ruang bukti; retainer TIDAK menjalankan KAPE dengan lisensi PT JAB.
   Senin 09:30   draf temuan enam penerima ke Pak Dimas (notes\temuan-enam-penerima.md). Baris "Batas" jangan dihapus.
   Belum dijadwalkan: olah E16 (salinan kerja dulu; target !SANS_Triage + INC2026019_IOC; bandingkan copylog E14).
                      cek OU JKT-WS-0418 dan BDG-WS-0147 di AD.
   Setelah kasus ditutup: copot client Velociraptor (msiexec /x), matikan jkt-velo01, hapus aturan TCP 8000.
5. JANGAN
   update alat | mount atau olah master | menulis "bersih" | menulis "tidak ditemukan" untuk yang tidak diambil |
   melaporkan jejak responder (ir-admin, driver WinPmem, service velociraptor, logon adm.yoga) sebagai temuan
6. KONTAK
   Yoga Pratama (pemegang bukti) | Sari Kusuma (technical lead) | Pak Dimas (IC) | Fajar Nugraha (POP Bandung) |
   retainer PT Forensik Digital Contoh (lewat Sari)
```

Cara membaca elemennya:

- **Bagian 1 dan 5** membuat Rudi tidak mengulang kesalahan yang sudah dicegah minggu ini: alat yang di-update di tengah kasus, master yang di-mount, dan kalimat yang lebih kuat dari buktinya.
- **Bagian 4** memuat jam dan nomor fisik (kantong, resi), karena dua bukti masih di perjalanan saat dokumen ditulis. Rudi harus bisa menerima E20 tanpa bertanya hash mana yang dipakai pembanding.
- **Hunt yang belum kedaluwarsa** adalah jebakan kecil: memberi label `inc-2026-019` pada client baru sebelum Jumat 17:00 membuat hunt yang sama terjadwal di sana [S19].
- **Tidak ada analisis baru di dokumen ini.** Serah terima memindahkan status dan cakupan, bukan menambah kesimpulan.

**Kapan gagal:** dokumen hanya berisi status ("E14 sudah diolah, hunt bersih"), sehingga Rudi meneruskan kalimat "hunt bersih" ke DPO tanpa batasnya; atau dokumen dikirim lewat chat dan tidak tersimpan di folder kasus, sehingga tidak ada versi yang bisa dicocokkan dengan case notes.

### 1.12 Glosarium

Definisi di bawah ditulis dengan kata sendiri untuk keperluan belajar. Kolom terakhir adalah pasangan yang paling sering membuat jawaban interview atau laporan keliru.

| Istilah | Arti singkat | Sering tertukar dengan |
|---|---|---|
| Collection, examination, analysis, reporting | Empat tahap proses forensik | Fase IR (forensik bisa berjalan sebelum dan sesudah containment) |
| Full disk image | Salinan bit-per-bit seluruh media, termasuk unallocated | Triage yang "cukup lengkap" |
| Triage collection | Koleksi artefak terpilih sesuai daftar target | Image penuh |
| Adaptive collection | Triage ditambah file yang dirujuk artefak saat koleksi | Full image |
| Order of volatility | Urutan pengambilan dari yang paling cepat hilang | Urutan pentingnya data |
| Hash bukti | Bukti berkas tidak berubah sejak hash dihitung | Bukti isi lengkap atau cara pengambilan benar |
| Salinan kerja | Salinan bukti yang diolah; master tetap utuh untuk verifikasi ulang | Backup |
| Case notes | Log kronologis tindakan, perintah, hasil, dan alasan, dengan zona waktu | Timeline temuan |
| Chain of custody | Catatan setiap perpindahan bukti: siapa, kapan, ke mana, dengan hash apa | Evidence log |
| Evidence log | Daftar bukti: nomor, hash, waktu, pemegang (`evidence-log.csv`) | Chain of custody |
| Files On-Demand | File cloud sync yang di disk hanya berupa placeholder | File lokal biasa |
| Workstation analisis forensik | Mesin khusus pengolah bukti, tidak join domain, tanpa internet umum | Laptop analyst biasa |
| Pembekuan versi | Versi alat tidak diubah selama satu kasus diolah, kecuali dengan uji dan catatan | Larangan update selamanya |
| Ancillary files | Maps, batch file, definisi Target dan Module yang menentukan isi CSV | Biner alat |
| Read-only mount | Satu dari tiga lapis kontrol membuka bukti | Jaminan bahwa bukti tidak berubah |
| Target dan Module KAPE | Definisi apa yang dikumpulkan dan program apa yang memprosesnya | Satu langkah yang sama |
| Compound target | Target yang merujuk target lain, misalnya `!SANS_Triage` | Target yang mengambil semua file pengguna |
| Deferred copy | File terkunci yang dibaca lewat raw read | Salinan dari shadow copy |
| Volume Shadow Copy | Snapshot volume yang bisa berisi versi lama file; dibaca KAPE hanya dengan `--vss` | Backup terpusat |
| Copylog dan skiplog | CSV file yang disalin (dengan SHA-1) dan yang dilewati | Daftar file yang ada di host |
| Container KAPE | VHD, VHDX, atau ZIP berisi hasil Targets | Hasil olahan Modules |
| `!EZParser` | Compound module yang menjalankan rangkaian EZ Tools | Parser untuk semua isi koleksi |
| Tidak diambil | Lokasinya di luar target atau opsi tidak aktif | Tidak ditemukan |
| Tidak ditemukan | Lokasinya diambil atau diperiksa, tetapi tidak memuat jejak yang dicari | Tidak ada di host |
| Client dan server Velociraptor | Agent di endpoint yang menjalankan query, dan tempat tugas serta hasil dikelola | EDR |
| VQL dan artifact | Bahasa query di endpoint, dan file YAML yang membungkus query beserta parameternya | Rule deteksi |
| Collection dan hunt | Artifact di satu client, dan artifact ke semua client yang cocok kondisi | Threat hunting |
| Label | Tanda pada client yang menentukan target hunt | Nama host |
| Offline collector | Biner Velociraptor dengan konfigurasi tertanam, dijalankan tanpa argumen dan tanpa client | KAPE |
| `Container hash` | SHA-256 container offline yang ditulis di log collector | Hash yang dihitung belakangan di server bukti |
| `CollectionPolicy` | `ExcludeSigned` (bawaan), `HashOnly`, atau `AllFiles` di `Windows.Triage.Targets` | Filter hasil |
| LOLBin | Program bawaan Windows bertanda tangan yang disalahgunakan penyerang | Malware |
| Kontrol positif | Bukti bahwa artifact dan parameter yang sama menemukan IOC tiruan di lab | Uji bahwa alat berjalan tanpa error |
| Live response (EDR) | Shell jarak jauh dari konsol EDR, satu sesi per perangkat | Hunt |
| Channel dan file `.evtx` | Satu aliran log dan file tempat ia disimpan, dengan ukuran maksimum | Seluruh log host |
| Audit policy | Konfigurasi subcategory yang menentukan event Security apa yang ditulis | Bukti aktivitas |
| Logon ID | Nilai yang mengikat event lain ke satu sesi logon | Nama akun |
| Logon type | Cara logon di 4624 dan 4625 (2 konsol, 3 jaringan, 7 unlock, 10 RDP) | Jenis akun |
| Linked Logon ID dan elevated token | Pasangan sesi akun admin dengan UAC; satu terbatas, satu penuh | Dua orang login |
| Script block logging (4104) | Pencatatan isi kode PowerShell yang diproses | Riwayat perintah PSReadLine |
| Sysmon | Service dan driver yang menulis event proses, jaringan, dan file ke channel sendiri | Event bawaan Windows |
| Map EvtxECmd dan `MapDescription` | Pemetaan field XML per event ke kolom CSV, dan deskripsi event yang ditambahkannya | Arti kolom yang sama untuk semua event |
| 1102, 104, 4719 | Log Security dibersihkan, log lain dibersihkan, audit policy diubah | Bukti log utuh bila tidak ada |
| Profil cakupan | Daftar apa yang bisa dicatat atau diambil di satu host, dan sampai kapan | Hasil pencarian IOC |
| Jejak responder | Logon, proses, driver, service, dan file dari tindakan tim sendiri | Temuan penyerang |
| Serah terima kasus | Pemindahan bukti, catatan cakupan, dan pekerjaan terbuka ke orang lain | Update status |

## 2-4. Lab gabungan dan troubleshooting

Lab ini menjalankan seluruh alur minggu ini sebagai satu kasus lab, dari keputusan akuisisi sampai serah terima. Semua aktivitas jinak, dijalankan di VM lab terisolasi dengan snapshot, dan dicatat jamnya (WIB) sebelum dijalankan. Perintah di bawah ditulis sebagai teks untuk dijalankan di VM lab. Jangan memakai data, nama, atau kejadian dari pekerjaan nyata.

**Prasyarat:** `LAB-WS01` (Windows 11, Sysmon dengan event 3 dan 22 aktif, audit policy diperluas seperti Day 02 bagian 1.4, `172.16.50.10`) dikembalikan ke snapshot `bersih-2026-10-15`, dengan disk virtual kedua sebagai media bukti (`E:`) berisi KAPE, target custom `INC2026019_IOC` dari Day 03 bagian 2.7, dan alat jinak di `E:\tools\`; `LAB-DFIR01` (`172.16.50.20`) dengan EZ Tools dan KAPE di folder bertanggal; `LAB-VELO01` (`172.16.50.30`) dengan `Windows.Triage.Targets` sudah diimpor (Day 04 bagian 3). Folder kasus `CASE-2026-LAB-006` di `LAB-DFIR01` dengan struktur `evidence\`, `work\`, `analysis\`, `notes\`, `tools\` (Day 02 bagian 2.8). Akun lab: `lab-user06` (pengguna biasa) dan `lab-ir06` (admin lokal khusus "responder").

### Bagian A: skenario jinak dan keputusan akuisisi

1. **Inventaris.** Salin inventaris alat `LAB-DFIR01` ke `tools\` dan tulis di case notes bahwa versi dibekukan untuk kasus ini (Day 02 bagian 1.3).
2. **Aktivitas "pengguna" dan "penyerang".** Di `LAB-WS01`, login konsol sebagai `lab-user06`. Dari sesi itu jalankan satu `powershell.exe -EncodedCommand` jinak yang membuat folder `C:\Users\lab-user06\AppData\Roaming\SysCache\`, menulis `upd.ps1` berisi `Write-Output "lab"`, lalu mendaftarkan task `\LabSysCache06` yang menjalankan `powershell.exe -NoProfile -File` ke file itu setiap 15 menit. Jalankan task sekali dengan `schtasks /run`. Catat jam setiap langkah.
3. **Aktivitas "responder".** Kunci layar, lalu Switch user ke `lab-ir06`. Ketik password salah sekali dengan sengaja. Buka Command Prompt sebagai administrator dan catat konteks waktu (Day 01 bagian 2.1):

```powershell
Get-Date -Format o
Get-TimeZone
w32tm /query /status
```

4. **Keputusan tertulis.** Tulis satu paragraf di case notes: pola akuisisi untuk host ini (triage atau adaptive, bukan image) beserta alasannya, dan daftar yang sengaja tidak diambil beserta risikonya, minimal dua butir (Day 01 bagian 1.6).

### Bagian B: koleksi dua jalur dan hash di titik koleksi

5. **KAPE.** Masih sebagai `lab-ir06`, jalankan dari media bukti:

```
E:\kape\kape.exe --tsource C: --target !SANS_Triage,INC2026019_IOC --tdest E:\CASE-2026-LAB-006\K1\tdest --tflush --vhdx LAB006-K1_LAB-WS01
```

   Catat dari console log: jumlah file, deferred copy, deduped, dan `VSS: False`. Hitung SHA-256 arsip hasil dengan `Get-FileHash` dan tulis di `hashes.txt` di media bukti (Day 03 bagian 2.1).
6. **Velociraptor offline collector.** Di `LAB-VELO01`, bangun collector Windows 64-bit dengan enkripsi X.509, Zip Archive, Pause For Prompt, nama `LAB006-V1_%Hostname%_%TIMESTAMP%`, berisi `Windows.Triage.Targets` (`HighLevelTargets=_Live`, `Targets=EventLogs`, `CollectionPolicy=ExcludeSigned`), `Windows.System.TaskScheduler`, dan `Windows.EventLogs.EvtxHunter` dengan regex `(?i)SysCache|upd\.ps1` (Day 04 bagian 2.4 dan 2.6). Salin ke `E:\`, jalankan sebagai administrator tanpa argumen, lalu catat `Container hash` dari log collector.
7. **Sign out dan chain of custody.** Sign out dari `lab-ir06`. Lepas disk virtual kedua dari `LAB-WS01`, pasang ke `LAB-DFIR01`, dan isi formulir chain of custody untuk kedua item (K1 dan V1), termasuk satu baris perpindahan "fisik" disk virtual itu (Day 01 bagian 2.4).

### Bagian C: master, salinan kerja, dan parse

8. **Master dan salinan kerja.** Salin kedua item ke `evidence\` sebagai master, verifikasi hash terhadap `hashes.txt` dan `Container hash`, lalu buat salinan kerja K1-W1 dan V1-W1 di `work\` dan verifikasi lagi (Day 02 bagian 1.5).
9. **KAPE ke CSV.** Ekstrak VHDX dari arsip K1-W1, catat hash VHDX sebagai turunan, mount read-only, lalu proses:

```powershell
Mount-DiskImage -ImagePath <path VHDX K1-W1> -Access ReadOnly -PassThru | Get-Volume
```

```
<folder KAPE>\kape.exe --msource F:\ --module !EZParser --mdest C:\CASE-2026-LAB-006\analysis\K1-W1\EZ-<versi> --mflush
```

10. **Velociraptor ke CSV.** Impor V1-W1 ke `LAB-VELO01` dengan `Server.Utils.ImportCollection` dan baca hasil `EvtxHunter` dan `TaskScheduler` di notebook. Dekripsi lalu ekstrak salinan kerja dengan `Windows.KapeFiles.Extract`, kemudian jalankan EvtxECmd dengan `--maps` eksplisit ke folder log hasil ekstraksi; sesuaikan path karena struktur Velociraptor berbeda dari KAPE (Day 04 bagian 2.7, Day 05 bagian 2.1).
11. **Bandingkan dua jalur.** Apakah kedua koleksi memuat set `.evtx` yang sama? Apakah `upd.ps1` ada di keduanya? Di K1 ia datang dari target custom; di V1, Day 04 bagian 1.3 mengharapkannya ikut lewat aturan adaptive `AdaptiveScheduledTasks`, padahal biner yang dijalankan task adalah `powershell.exe` yang bertanda tangan dan `upd.ps1` hanya argumennya. Ukur, jangan berasumsi, dan catat hasilnya. Catat juga perbedaan struktur folder yang memengaruhi path parser.

### Bagian D: membaca sampai timeline

12. **Profil cakupan.** Jalankan profil per channel dan pemeriksaan 1102, 104, 4719 seperti Day 05 bagian 2.2, dan hitung baris copylog berawalan `VSS` seperti Day 03 bagian 2.3.
13. **Sesi.** Susun sesi `lab-user06` dan `lab-ir06` dari `PayloadData1`, logon type, dan Logon ID (Day 05 bagian 2.3). Pastikan login `lab-ir06` menghasilkan dua 4624 yang saling menunjuk dan satu 4672.
14. **Rantai dan task.** Temukan `powershell.exe -EncodedCommand`, `upd.ps1` dibuat, 4104 dengan isi terbaca, 4698 dengan `ClientProcessId` yang sama dengan PID PowerShell, dan 106/200/201 (Day 05 bagian 2.4).
15. **Pelaku.** Beri setiap baris nilai pengguna, penyerang (tiruan), atau responder. Masukkan jejak KAPE dan offline collector yang kamu jalankan sendiri sebagai responder.
16. **Timeline.** Tulis timeline dengan kolom Waktu (UTC), Waktu (WIB), Channel, Event ID, Kejadian, Pelaku, Sumber.

### Bagian E: variasi audit tidak seragam

17. Pakai snapshot `LAB-WS01` lain yang hanya memakai audit bawaan dan tanpa Sysmon. Ulangi langkah 2 dan 5 (KAPE saja), parse, lalu hitung 4624, 4688, 4697, 4698, 4104, 106, dan event Sysmon seperti Day 05 bagian 2.7. Tulis tabel "apa yang hilang" dan satu kalimat "tidak ditemukan" untuk task di host ini, lengkap dengan batasnya. Bandingkan kalimat itu dengan kalimat untuk host berkonfigurasi penuh.

### Bagian F: serah terima kasus lab

18. Tulis dokumen serah terima untuk `CASE-2026-LAB-006` dengan enam bagian seperti bagian 1.11: akses dan aturan, status bukti (K1, V1, salinan kerja, hash), celah dan kalimat yang boleh dipakai, jadwal atau pekerjaan terbuka, larangan, dan kontak. Minta satu orang lain (atau dirimu sendiri seminggu kemudian) memverifikasi hash dan mengulang satu query hanya dari dokumen itu.

### Contoh kerangka solusi (buka setelah mencoba sendiri)

<details><summary>Keputusan akuisisi</summary>

Triage dengan target custom tepat karena host bisa diakses langsung, pertanyaannya sempit (task, file loader, eksekusi PowerShell), dan semua jawabannya ada di artefak yang dikenal: event log, XML task, `$MFT`, dan Prefetch. Image tidak diambil karena tidak ada kebutuhan file terhapus atau unallocated space dan host lab tidak akan dihapus sebelum keputusan berubah (Day 01 bagian 1.2). Yang sengaja tidak diambil: memori (tidak ada pertanyaan tentang kode di RAM; risiko: teknik fileless tidak terlihat) dan shadow copy (`--vss` tidak dipakai; risiko: versi lama hive dan log tidak tersedia). Koleksi dilakukan pada sistem hidup, sehingga sebagian timestamp berubah.

</details>

<details><summary>Timeline lab (ilustrasi)</summary>

Keluaran ilustrasi untuk lab pada Sabtu 2026-10-17; Logon ID, PID, dan jam akan berbeda di lab-mu.

```
UTC                  WIB       Channel / EID          Kejadian                                                Pelaku
2026-10-17 02:02:10  09:02:10  Security 4624 type 2   lab-user06 login konsol, LogonId 0x1A2B3C               pengguna
2026-10-17 02:05:31  09:05:31  Sysmon 1               powershell.exe -EncodedCommand ..., PID 4410            penyerang (tiruan)
2026-10-17 02:05:33  09:05:33  Sysmon 11              upd.ps1 dibuat di AppData\Roaming\SysCache\             penyerang (tiruan)
2026-10-17 02:05:34  09:05:34  PowerShell 4104        isi blok terbaca: menulis upd.ps1, mendaftarkan task    penyerang (tiruan)
2026-10-17 02:05:40  09:05:40  Security 4698 + TS 106 \LabSysCache06, ClientProcessId 4410                    penyerang (tiruan)
2026-10-17 02:06:12  09:06:12  TS 200 / 201           task dijalankan lewat schtasks /run                     penyerang (tiruan)
2026-10-17 02:20:04  09:20:04  Security 4625          lab-ir06, password salah                                responder
2026-10-17 02:20:15  09:20:15  Security 4624 x2, 4672 lab-ir06 type 2, pasangan elevated                      responder
2026-10-17 02:24:50  09:24:50  Sysmon 1               E:\kape\kape.exe --tsource C: ...                       responder
2026-10-17 02:47:30  09:47:30  Sysmon 1               E:\Collector_velociraptor-...exe                       responder
2026-10-17 03:01:05  10:01:05  Security 4647          lab-ir06 sign out                                       responder
```

Rekonstruksi: pengguna login, lalu satu perintah PowerShell yang di-encode menaruh loader dan mendaftarkan task dari proses yang sama (dibuktikan `ClientProcessId` 4410), lalu responder masuk dengan sesi admin terpisah dan menjalankan dua alat koleksi dari media bukti. Semua baris responder punya pasangan di case notes. Di snapshot audit bawaan (Bagian E), baris Sysmon, 4698, dan 106 hilang; yang tersisa untuk task adalah XML di `C:\Windows\System32\Tasks\` dan, bila blok dianggap mencurigakan, 4104 berlevel Warning.

</details>

**Hasil yang sebaiknya tersimpan:**

- Case notes `CASE-2026-LAB-006` dengan inventaris versi, konteks waktu, paragraf keputusan akuisisi, dan daftar yang sengaja tidak diambil beserta risikonya.
- K1 (VHDX dalam arsip) dan V1 (container offline) dengan `hashes.txt`, nilai `Container hash`, formulir chain of custody, dan bukti verifikasi hash master serta salinan kerja.
- Console log, copylog, dan skiplog K1; daftar artifact dan parameter V1.
- CSV hasil `!EZParser` dan EvtxECmd di `analysis\<bukti>\EZ-<versi>\`.
- Profil cakupan per channel, hasil pemeriksaan 1102, 104, 4719, dan perbandingan dua jalur koleksi.
- Timeline dengan kolom UTC, WIB, Pelaku, dan Sumber.
- Tabel "apa yang hilang" dari snapshot audit bawaan dan dua kalimat "tidak ditemukan" yang dibandingkan.
- Dokumen serah terima kasus lab, plus catatan apakah orang lain bisa memverifikasi dan mengulang query hanya dari dokumen itu.

### Bagian G: latihan skenario dengan pembahasan

Jawab setiap skenario dalam tiga sampai lima kalimat sebelum membuka pembahasannya.

**Skenario 1.** Laptop manajer keuangan dicurigai dipakai untuk mengirim data ke pihak luar. Laptop masih menyala, OneDrive Files On-Demand aktif, BitLocker aktif, dan HR sudah dilibatkan. Apa urutan koleksimu?

<details><summary>Pembahasan</summary>

Kasus berpotensi ke HR dan sengketa, jadi libatkan Legal dan perketat chain of custody sejak awal. Jangan matikan laptop: memori berisi proses, koneksi, dan kemungkinan kunci BitLocker. Urutan yang masuk akal adalah memori lebih dulu, lalu image atau koleksi disk saat volume masih terbuka (BitLocker tidak menjadi penghalang selama sistem berjalan), dan hindari membuka file di folder OneDrive karena placeholder akan terunduh [S5]. Isi file yang hanya berupa placeholder diambil dari sisi cloud dengan otorisasi. Semua keputusan, termasuk yang dilewati, ditulis di case notes.

</details>

**Skenario 2.** Alert EDR muncul di 40 workstation dengan pola command line yang sama. Tim hanya dua orang dan manajemen ingin tahu host mana yang benar-benar terdampak dalam beberapa jam. KAPE atau Velociraptor?

<details><summary>Pembahasan</summary>

Velociraptor. Jumlah host dan kebutuhan waktu menuntut koleksi jarak jauh: hunt dengan artifact yang ringan (misalnya scheduled task, Prefetch, atau pencarian string di event log) untuk scoping, lalu collection triage penuh hanya di host yang terbukti terdampak. Uji artifact dan parameter di satu atau dua host dulu, dan siapkan kontrol positif di lab sebelum mempercayai hasil nol. KAPE tetap bisa dipakai untuk satu atau dua host yang perlu diperiksa langsung. Hasil hunt dan collection diperlakukan sebagai bukti: dicatat waktu, artifact, parameter, dan di-hash setelah diekspor.

</details>

**Skenario 3.** Hash container VHDX di VM analisis tidak cocok dengan hash yang dicatat di host korban. Apa yang kamu lakukan?

<details><summary>Pembahasan</summary>

Jangan menganalisis salinan itu. Pastikan dulu kamu membandingkan lapis yang sama: hash arsip `.zip` berbeda dengan hash `.vhdx` di dalamnya (Day 03 bagian 1.4). Bila lapisnya sama, periksa ukuran byte kedua berkas, ulangi transfer dalam mode biner dari master, lalu hitung ulang. Bila master sendiri berbeda dari hash di case notes, catat temuan ini apa adanya, cari penyebabnya (salah berkas, container yang sempat di-mount tanpa `-Access ReadOnly`, antivirus), dan pertimbangkan koleksi ulang. Setiap langkah ditulis di case notes karena perbedaan hash adalah pertanyaan pertama yang akan diajukan bila temuan dipersoalkan.

</details>

**Skenario 4.** Di koleksi sebuah server, Security log hanya mencakup 36 jam terakhir dan tidak ada satu pun 4688. Ada satu 1102 dua hari lalu. Apa yang bisa dan tidak bisa kamu simpulkan?

<details><summary>Pembahasan</summary>

Rentang 36 jam bisa berarti rotasi karena ukuran log kecil di server sibuk; cek ukuran maksimum channel dan jumlah event per jam sebelum menyimpulkan apa pun. Tidak adanya 4688 sama sekali menunjukkan Process Creation tidak diaudit, bukan bahwa tidak ada proses [S27]. Event 1102 dua hari lalu berada di luar rentang 36 jam, jadi kemungkinan besar berasal dari channel lain yang retensinya lebih panjang atau dari koleksi VSS; pastikan sumbernya. 1102 membuktikan log pernah dibersihkan oleh akun tertentu pada waktu tertentu [S26], tetapi tidak memberi tahu isi yang hilang. Langkah lanjut: cari salinan log di VSS, periksa SIEM bila log pernah diteruskan, dan beralih ke artefak non-log (Prefetch, Amcache, MFT) untuk eksekusi.

</details>

**Skenario 5.** Kamu menemukan 4624 LogonType 3 dari IP workstation admin ke server file, diikuti 7045 dengan nama service acak satu menit kemudian. Apa tafsir awalmu dan artefak apa yang kamu cari berikutnya?

<details><summary>Pembahasan</summary>

Pola logon jaringan lalu service baru dengan nama acak cocok dengan eksekusi jarak jauh lewat service (pola PsExec dan alat sejenis, T1569.002). Ini belum bukti jahat, karena admin juga memakai alat seperti ini, dan tim responder sendiri bisa meninggalkan pola yang sama (bagian 1.9). Langkah berikutnya: periksa `ImagePath` di 7045 (lokasi dan nama biner), pasangkan dengan 4697 bila Audit Security System Extension aktif untuk tahu akun pemasangnya, cari biner itu di MFT dan Amcache, cek apakah akun di 4624 lazim melakukan administrasi ke server itu dan apakah ada di case notes tim, lalu lihat di workstation admin apakah ada jejak eksekusi alat remote pada waktu yang sama. Artefak eksekusi dan persistence dibahas mendalam di Day 07 dan Day 11.

</details>

### Troubleshooting gabungan

Tabel ini memuat masalah yang biasa muncul saat alur di atas dijalankan dari awal sampai akhir. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Koleksi tidak berisi event log | Target tidak mencakup atau path salah | Pakai `!SANS_Triage` atau `Targets=EventLogs`; cek `winevt\Logs` di copylog (Day 03 bagian 2.3) |
| File loader tidak ada di koleksi KAPE | Folder di luar target | Tulis "tidak diambil"; pakai target custom yang sudah diuji (Day 03 bagian 1.2 dan 2.7) |
| `Windows.Triage.Targets` tidak ada di daftar artifact | Tidak bawaan sejak 0.75 | Impor lewat `Server.Import.Extras` [S18] |
| Hash tidak cocok setelah pindah | Transfer rusak, salah berkas, atau lapis hash berbeda (`.zip` vs `.vhdx`) | Bandingkan lapis yang sama; salin ulang dari master (Day 01 bagian 2.2) |
| Hash VHDX berubah setelah dibuka | Di-mount tanpa `-Access ReadOnly` atau dengan klik ganda | Salinan kerja baru dari master; mount read-only [S11] |
| Offline collector menutup seketika | Dijalankan tanpa hak admin atau dengan argumen | Run as administrator, tanpa argumen [S21] |
| Path EvtxECmd tidak cocok untuk container Velociraptor | Struktur `uploads/` dan path yang di-escape | Ekstrak dengan `Windows.KapeFiles.Extract`; sesuaikan path [S20] |
| `PayloadData` kosong walau `Payload` terisi | Maps tidak dimuat | Tulis `--maps` eksplisit [S32] |
| Semua 4624 tampak milik akun komputer | Membaca `UserName` (Subject) | Pakai `PayloadData1` [S33] |
| Event yang diharapkan tidak ada | Audit mati, channel mati, atau rotasi | Profil cakupan dan hitung per subcategory (Day 05 bagian 1.5 dan 2.7) |
| 4688 tanpa command line | Setting command line tidak aktif | Normal bila setting tidak aktif [S28]; pakai Sysmon 1 bila ada |
| Timeline membingungkan | UTC dan WIB tercampur | Tulis keduanya sekali, lalu WIB; super-timeline di Day 13 |
| Jejak admin atau driver tanpa penjelasan | Jejak responder yang tidak dicatat | Cocokkan dengan case notes dan Command log EDR (bagian 1.9) |
| Penerima serah terima tidak bisa melanjutkan | Dokumen hanya berisi status | Tambahkan lokasi, hash pembanding, versi beku, celah, dan jadwal (bagian 1.11) |

## 5. Kesalahan umum dan jebakan

Kesalahan berikut muncul di lebih dari satu Day minggu ini; tiap butir menyebut Day asalnya.

- Mengumpulkan tanpa memutuskan pola akuisisi per host dan tanpa mencatat yang sengaja dilewati (Day 01).
- Mengira hash membuktikan isi lengkap, cara pengambilan, atau keutuhan perangkat fisik selama perjalanan (Day 01) [S6].
- Menganalisis di VM korban atau atas master, bukan salinan kerja (Day 02, Day 03).
- Meng-update alat di tengah kasus tanpa uji dan catatan, atau lupa bahwa `Modules\bin` dan maps berubah terpisah dari biner (Day 02).
- Menganggap read-only mount sebagai jaminan; `Mount-DiskImage` tanpa `-Access` me-mount VHDX read-write (Day 02, Day 03) [S11].
- Menganggap triage menangkap segalanya, mengira `--vss` aktif, atau tertipu nama target `Syscache` (Day 03) [S13][S15].
- Menulis "tidak ditemukan" untuk sesuatu yang tidak diambil (Day 03, Day 04).
- Menulis hasil hunt sebagai "bersih", atau mempercayai hasil nol tanpa kontrol positif (Day 04).
- Mengira `Windows.Triage.Targets` bawaan, atau lupa bahwa `ExcludeSigned` dan `HashOnly` membuat sebagian file tidak utuh (Day 04) [S17][S18].
- Menyimpulkan dari satu event tanpa sesi dan rangkaian lintas channel, atau membaca Subject sebagai orang yang login (Day 05).
- Mengira ketiadaan event berarti ketiadaan aktivitas, padahal audit policy berbeda per OU (Day 05) [S27].
- Melaporkan jejak responder sebagai temuan, di host mana pun dan dengan alat apa pun (Day 04, Day 05).
- Lupa zona waktu saat menggabungkan output EZ Tools, Velociraptor, dan SIEM (Day 01, Day 03, Day 05).
- Menyerahkan kasus hanya dengan status, tanpa catatan cakupan dan bukti yang bisa diverifikasi penerima (Day 01, Day 04).

## 6. Catatan terkini

Bagian ini mengumpulkan status versi dan dokumen acuan yang dipakai Day 01-05. Tidak mengubah isi review, tetapi berguna saat ditanya "versi mana yang kamu pakai".

- **NIST SP 800-61 Rev. 3** (April 2025) menggantikan Rev. 2; pernyataan tentang data insiden sebagai bukti ada di RS.AN-07 [S3]. RFC 3227 (2002) dan SP 800-86 (2006) sudah lama, tetapi prinsipnya masih menjadi rujukan; contoh alatnya usang [S1][S2].
- **EZ Tools 2026.5.0** per 2026-10-16: CLI untuk .NET 4.7.2 dan .NET 9, GUI hanya .NET 9 [S7].
- **KAPE:** EULA Solo terakhir diubah 2020-06-04 [S8]; FAQ dokumentasi diperbarui 2026-02-11 dan menyebut KAPE tidak lagi tersedia untuk penggunaan komersial sejak 2026-01-01 [S9]. Perbedaan soal penggunaan internal perusahaan perlu dipantau. `!SANS_Triage` v1.5 dan `!EZParser` v1.5 per 2026-10-16 [S15][S16].
- **Velociraptor 0.77.3** (5 Oktober 2026) adalah rilis bugfix untuk CVE [S23]; `Windows.Triage.Targets` dikelola di proyek terpisah sejak 0.75 [S4][S18].
- **Volatility 3 2.28.2** (17 September 2026) [S34] dan **Plaso 20260720** (rilis stabil; 20260928 masih pre-release) [S35] disiapkan di `jkt-dfir02`, belum dipakai minggu ini.
- **Halaman event Security Microsoft Learn** kini berada di arsip Windows 10 tetapi isinya masih berlaku untuk Windows 11 [S24][S25][S26]. Audit Logon bawaan menjadi Success dan Failure sejak Windows 10 1809 [S27]. Halaman Sysmon terbit 2026-09-10 [S29].
- **Maps EvtxECmd** diperbarui terpisah dari biner; isi kolom per event dicek 2026-10-16 dan bisa berubah [S32][S33].

## 7. Cheat sheet

```
RANTAI     keputusan -> tempat kerja -> koleksi -> simpan -> olah -> baca -> temuan -> serah terima
           tiap langkah = HASIL + CATATAN CAKUPAN ; temuan hanya sekuat cakupan terlemah
KEPUTUSAN  per host: triage | adaptive | image ; image bila hukum/regulator, file terhapus, host akan dihapus
           order of volatility (RFC 3227) ; isi urutan sesuai pertanyaan terbuka ; yang dilewati + risiko
HASH       SHA-256 di titik koleksi ; verifikasi tiap pindah ; perangkat fisik: segel + kantong + CoC sampai image
           lapis berbeda: arsip .zip | .vhdx | SHA-1 per file (copylog) | Container hash (offline collector)
LAB        JKT-DFIR01 / jkt-dfir02 tidak join domain ; update -> uji di LAB-WS01 -> catat -> BEKUKAN
           EZ Tools 2026.5.0 | Velociraptor 0.77.3 | Vol3 2.28.2 | Plaso 20260720 | KAPE: Enterprise (tafsir ketat)
READ-ONLY  izin share | mount ro (Mount-DiskImage -Access ReadOnly) | hash ; olah SALINAN KERJA, bukan master
KAPE       Targets = bukti | Modules = olahan ; !SANS_Triage tidak ambil folder sembarang ; --vss false ; --zv true
           ada | tidak diambil (cek copylog) | tidak ditemukan di yang diambil
VELO       Windows.Triage.Targets harus diimpor (Server.Import.Extras) ; ExcludeSigned bawaan ; _Live adaptive
           hunt: Paused -> Start ; kedaluwarsa ; label = jadwal ke client baru ; offline: admin, TANPA argumen
           negatif = apa + artifact/param + kapan + tidak tercakup + kontrol positif + keyakinan
EVENT LOG  petakan dulu: file, rentang, audit/OU, Sysmon, 1102/104/4719 -> sesi (Logon ID) -> isi -> pelaku
           4624: UserName=Subject, PayloadData1=Target ; 4698 ClientProcessId ; 4104 isi (+password) ; UTC
           bawaan client TIDAK: Process Creation, Other Object Access, Security Group Mgmt, Security System Ext
PELAKU     pengguna | penyerang | responder ; responder: ir-admin, adm.yoga, driver WinPmem, service velociraptor
SERAH      akses+aturan | status bukti | celah + kalimat | jadwal | jangan | kontak ; simpan di folder kasus
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Hash E14 cocok saat diverifikasi Kamis 08:52, jadi E14 lengkap dan bisa dipakai untuk membandingkan isi `upd.ps1` di laptop Rizky dengan laptop Andi." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Hash hanya membuktikan E14 tidak berubah sejak dihitung Selasa 18:48, bukan bahwa isinya lengkap. Copylog E14 tidak punya baris untuk `AppData\Roaming\SysCache\upd.ps1`, karena folder itu di luar target `!SANS_Triage` dan Yoga sengaja tidak menambahkan target custom malam itu. E14 hanya membawa metadata file itu dari `$MFT` dan `$J` serta sebagian isi loader dari 4104 berlevel Warning. Isi lengkapnya ditulis "tidak diambil" dan menunggu E16. Lihat bagian 1.3, 1.8, dan 1.10.

</details>

**2. Skenario keputusan.** Senin 08:45, `USB-E-12` (E20) tiba dari kurir saat Rudi yang berjaga. Langkah mana yang tepat?

- A. Langsung impor isi USB ke `jkt-velo01` dan baca hasilnya, karena salinan `E20-C` sudah pernah diimpor Jumat.
- B. Periksa segel dan nomor kantong, hitung SHA-256 container di USB dan cocokkan dengan `Container hash` `5be1...` dari log collector, isi baris chain of custody, lalu simpan sebagai master di `jkt-evid01`; analisis tetap dari salinan kerja.
- C. Simpan USB di lemari tanpa verifikasi, karena `E20-C` di `jkt-evid01` sudah cocok sejak Jumat 14:40.

<details><summary>Jawaban</summary>

B. Media fisik yang berpindah tangan harus diverifikasi terhadap hash di titik koleksi sebelum menjadi master, dan perpindahannya dicatat satu baris di chain of custody. A keliru karena memakai media fisik langsung untuk analisis dan melewatkan verifikasi; yang diolah selalu salinan kerja. C keliru karena kecocokan `E20-C` hanya membuktikan salinan elektronik, bukan media yang baru menempuh perjalanan kurir. Lihat bagian 1.8 dan 1.11.

</details>

**3. Pertanyaan jebakan.** "Laporan event log `JKT-WS-0388` menulis tidak ada akun baru dan tidak ada pembersihan log, dan hunt di `JKT-WS-0418` juga tidak menemukan string IOC di event log. Keduanya kalimat 'tidak ditemukan' yang sama kuatnya." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Di `JKT-WS-0388`, semua subcategory yang relevan diaudit lewat GPO `JAB-WS-Audit`, Sysmon terpasang, dan semua channel mencakup periode kasus, sehingga ketiadaan event bermakna. `JKT-WS-0418` tanpa EDR, kemungkinan besar di OU lama dengan audit bawaan dan tanpa Sysmon, sehingga regex IOC hanya mencari di channel yang memang aktif; sumbernya hanya artefak host dan log jaringan, dan keyakinannya sedang. Sebelum menulis keyakinan akhir, OU host itu dicek di AD dan event per subcategory dihitung dari event log di E19. Lihat bagian 1.9 dan 1.10.

</details>

**4. Skenario keputusan.** Retainer meminta Rudi mengisi kolom "menunggu E16" dari daftar E14. Langkah mana yang tepat?

- A. Mount master E16 dari `\\jkt-evid01\evidence` karena share itu sudah read-only, lalu jalankan EZ Tools versi terbaru supaya hasilnya paling akurat.
- B. Buat salinan kerja E16 setelah verifikasi hash, mount read-only, jalankan KAPE Targets `!SANS_Triage` ditambah target custom `INC2026019_IOC` yang sudah diuji dengan `--tsource` huruf drive mount, proses dengan versi alat yang dibekukan ke `analysis/E16-W1/EZ-2026.5.0/`, lalu bandingkan copylog-nya dengan copylog E14.
- C. Tulis ke retainer bahwa isi `upd.ps1` dan lampiran tidak ditemukan di `JKT-WS-0412`, karena E14 tidak memuatnya.

<details><summary>Jawaban</summary>

B. Yang diolah selalu salinan kerja, alat tetap di versi beku supaya hasil sebanding dengan E14 dan dengan retainer, dan target custom yang sudah diuji di lab menutup celah yang sengaja dibiarkan Selasa malam. A keliru dua kali: master tidak diolah, dan update alat di tengah kasus membuat hasil tidak sebanding. C keliru karena "tidak diambil" bukan "tidak ditemukan". Lihat bagian 1.2, 1.3, 1.8, dan 1.10.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Rudi Hartanto, dalam tiga kalimat, kenapa setiap kalimat "tidak ditemukan" di berkas `INC-2026-019` selalu disertai catatan cakupan.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Setiap bukti kita hanya melihat sebagian host: E14 hanya menyalin target standar, hunt hanya menjalankan artifact dan parameter tertentu pada Jumat pagi, dan event log hanya mencatat yang dikonfigurasi lewat GPO yang tidak terpasang di semua laptop. Jadi 'tidak ditemukan' tanpa cakupan akan dibaca DPO atau retainer sebagai 'tidak terjadi', padahal bisa saja tidak diambil atau tidak pernah dicatat. Karena itu setiap kalimat menyebut apa yang dicari, dengan apa, kapan, apa yang tidak tercakup, dan keyakinannya, dan kalimat itu jangan diperkuat saat kamu meneruskannya."

Kesalahan yang sering muncul:
- Menjelaskan nama artifact, flag KAPE, dan subcategory audit, padahal Rudi butuh aturan menulis kalimatnya.
- Tidak menyebut contoh dari kasus ini, sehingga terdengar seperti teori.
- Lupa memperingatkan bahwa kalimat itu sering diperkuat tanpa sengaja saat diteruskan ke pihak lain.

</details>

**6. Pertanyaan jebakan.** "Ada 7045 kernel driver di `JKT-WS-0388` Selasa 12:42 dan service `velociraptor` baru di `JKT-WS-0418` Kamis 17:35. Keduanya service baru di workstation, jadi harus dilaporkan sebagai persistence penyerang." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Driver Selasa 12:42 dimuat WinPmem yang dijalankan Yoga dari `USB-E-07` dalam sesi `ir-admin`, cocok dengan 4697, case notes, dan evidence log E01. Service `velociraptor` di `JKT-WS-0418` dipasang Yoga lewat admin share dari `JKT-JUMP01` untuk koleksi enam penerima, dan waktunya ada di case notes. Keduanya jejak responder; yang membuatnya bisa dipisahkan adalah catatan yang dibuat saat tindakan dilakukan. Lihat bagian 1.9.

</details>

**7. Interview question (English).** "Walk me through how you collect, preserve, and analyse endpoint evidence in an incident, from the first decision to a timeline someone else can verify."

<details><summary>Sample answer</summary>

"I decide per host first: triage, adaptive or full image, based on the question, the chance of legal or regulatory follow-up, and whether the host is about to be wiped, and I write down what I'm deliberately not collecting and why. Before touching evidence, my analysis workstation has tools at known versions that I've tested in an isolated lab, and I freeze those versions for the case. For one host I can reach directly I use KAPE to a container, and for many or remote hosts I use Velociraptor hunts or an offline collector; either way I hash at the point of collection, keep chain of custody, store the original as a read-only master, and work only on a verified working copy mounted read-only. When I read the results, I first map coverage: what the copy log shows was collected, which artifacts and parameters a hunt ran, and what the audit policy actually recorded on each host. Then I build logon sessions and process chains, separate user, attacker and our own responder activity, and convert UTC to local time explicitly. Every finding is written as found, not collected, or not found with its scope and confidence, so that a colleague can pick up the case from my notes and verify everything without calling me."

What makes this answer strong: it presents one chain from decision to handover, puts coverage before searching, keeps integrity controls in the flow, treats responder activity as part of the analysis, and ends with work that someone else can verify.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | RFC 3227: Guidelines for Evidence Collection and Archiving (BCP 55) | https://datatracker.ietf.org/doc/html/rfc3227 | primer | 2002-02 (>3 tahun); diakses 2026-10-07 | Tinggi untuk prinsip; contoh alat usang |
| S2 | NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response | https://csrc.nist.gov/pubs/sp/800/86/final | primer | 2006-09 (>3 tahun); diakses 2026-10-07 | Tinggi untuk kerangka empat tahap proses forensik |
| S3 | NIST SP 800-61 Rev. 3: Incident Response Recommendations and Considerations for Cybersecurity Risk Management (PDF) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf | primer | April 2025; diakses 2026-10-15 | Tinggi. RS.AN-07: data insiden tetap bukti walau CoC formal tidak selalu dijalankan; preservasi dan retensi dengan menimbang penuntutan dan biaya |
| S4 | Velociraptor: Adaptive Collections with Velociraptor | https://docs.velociraptor.app/blog/2025/2025-09-28-adaptive-collections/ | primer (blog proyek resmi) | 2025-09-28; diakses 2026-10-16 | Tinggi; ada sudut pandang proyek. Penggantian nama, aturan adaptive, meta-target, kebijakan koleksi |
| S5 | Elcomsoft: The Cloud Gap: Forensic Triage vs. Disk Imaging in the Age of On-Demand Sync | https://blog.elcomsoft.com/2026/01/the-cloud-gap-forensic-triage-vs-disk-imaging-in-the-age-of-on-demand-sync/ | sekunder (vendor forensik) | 2026-01-08; diakses 2026-10-07 | Sedang-tinggi; vendor punya kepentingan produk |
| S6 | Microsoft Learn: Get-FileHash (Microsoft.PowerShell.Utility) | https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash | primer (dokumentasi vendor) | PowerShell 7.6, ms.date 2022-12-12; diakses 2026-10-15 | Tinggi. Default SHA256, algoritma yang diterima, MD5 dan SHA1 hanya untuk validasi perubahan sederhana |
| S7 | Eric Zimmerman tools (daftar dan Get-ZimmermanTools) | https://ericzimmerman.github.io/ | primer | diakses 2026-10-09, dicek ulang 2026-10-16 | Tinggi. Tool, .NET 4.7.2 dan .NET 9, GUI hanya .NET 9, Desktop runtime, `-Dest`, `-NetVersion`, versi 2026.5.0 |
| S8 | Kroll: End User License Agreement (KAPE Solo Edition) | https://www.kroll.com/en/end-user-license-agreement | primer (vendor) | terakhir diubah 2020-06-04; diakses 2026-10-16 | Tinggi. Solo untuk non-komersial; komersial butuh Enterprise License |
| S9 | KAPE documentation: Frequently asked questions | https://raw.githubusercontent.com/EricZimmerman/KapeDocs/master/Pages/50-Frequently-asked-questions.md | primer (dokumentasi resmi) | diperbarui 2026-02-11; diakses 2026-10-16 | Tinggi. Gratis untuk pemerintah, pendidikan, riset, dan penggunaan internal perusahaan; tidak lagi tersedia untuk penggunaan komersial sejak 2026-01-01. Tidak sejalan dengan EULA Solo [S8] |
| S10 | Kroll: KAPE Enterprise License Terms and Conditions | https://www.kroll.com/en/kape-enterprise-license-terms-conditions | primer (vendor) | diakses 2026-10-16 | Tinggi. Pemakaian di jaringan pemegang lisensi, jumlah pengguna sesuai order, tidak bisa dialihkan tanpa persetujuan tertulis |
| S11 | Microsoft Learn: Mount-DiskImage | https://learn.microsoft.com/en-us/powershell/module/storage/mount-diskimage | primer | ms.date 2016-12-20 (lebih dari 3 tahun, dokumen Windows Server 2025); diakses 2026-10-16 | Tinggi. `-Access` ReadOnly/ReadWrite, default read-write untuk VHD, ISO selalu read-only, butuh administrator |
| S12 | mount(8), Linux manual page | https://man7.org/linux/man-pages/man8/mount.8.html | primer | diakses 2026-10-16 | Tinggi. `ro` bisa tetap menulis; ext3/ext4 replay journal; `ro,noload`, `blockdev` |
| S13 | KAPE documentation: Using KAPE (daftar switch) | https://raw.githubusercontent.com/EricZimmerman/KapeDocs/master/Pages/3.-Using-KAPE.md | primer (dokumentasi resmi) | diakses 2026-10-16 | Tinggi. `--tsource`, `--target`, `--tdest`, `--tflush`, `--tdd`, `--vss` (default false), `--vhd`/`--vhdx`/`--zip`, `--zv` (default true), `--msource`, `--module`, `--mdest`, `--mflush`, `--mef`, `--sync`, `--guids`, `--debug`/`--trace` |
| S14 | KAPE documentation: Log files | https://raw.githubusercontent.com/EricZimmerman/KapeDocs/master/Pages/4.-Log-files.md | primer (dokumentasi resmi) | diakses 2026-10-16 | Tinggi. Kolom copylog termasuk `SourceFileSha1` dan `DeferredCopy`; skiplog `Deduped`/`Excluded`; awalan `VSS` |
| S15 | KapeFiles: `!SANS_Triage.tkape` | https://raw.githubusercontent.com/EricZimmerman/KapeFiles/master/Targets/Compound/!SANS_Triage.tkape | primer | diakses 2026-10-16 | Tinggi. Versi 1.5, daftar target aktif dan tiga target yang dikomentari |
| S16 | KapeFiles: `!EZParser.mkape` dan `MFTECmd.mkape` | https://raw.githubusercontent.com/EricZimmerman/KapeFiles/master/Modules/Compound/!EZParser.mkape | primer | diakses 2026-10-16 | Tinggi. Versi 1.5, daftar module; MFTECmd memproses `$Boot`, `$MFT`, `$J`, `$SDS` |
| S17 | Velociraptor Triage Artifacts: Windows.Triage.Targets | https://triage.velocidex.com/docs/windows.triage.targets/ | primer (proyek resmi) | diakses 2026-10-16 | Tinggi untuk nama parameter; deskripsi `MaxFileSize` tidak konsisten di halaman itu sendiri |
| S18 | Velociraptor docs: Bulk File Acquisition | https://docs.velociraptor.app/docs/file_collection/bulk/ | primer | diakses 2026-10-16 | Tinggi. `Windows.Triage.Targets` tidak bawaan, contoh hitungan volume |
| S19 | Velociraptor docs: Hunting | https://docs.velociraptor.app/docs/hunting/ | primer | diakses 2026-10-16 | Tinggi. Hunt `Paused`, kedaluwarsa, label, client baru |
| S20 | Velociraptor docs: Working with offline collection data | https://docs.velociraptor.app/docs/deployment/offline_collections/collection_data/ | primer | diakses 2026-10-16 | Tinggi. `Server.Utils.ImportCollection`, struktur container, `Container hash`, `Windows.KapeFiles.Extract` |
| S21 | Velociraptor docs: Running offline collectors | https://docs.velociraptor.app/docs/deployment/offline_collections/running/ | primer | diakses 2026-10-16 | Tinggi. Hak admin, log, deployment lewat GPO, PsExec, WinRM, EDR |
| S22 | Microsoft Learn: Investigate entities on devices using live response in Microsoft Defender for Endpoint | https://learn.microsoft.com/en-us/defender-endpoint/live-response | primer (dokumentasi vendor) | ms.date 2026-07-28; diakses 2026-10-16 | Tinggi. Perintah, batas ukuran dan waktu, pengaturan unsigned script |
| S23 | Velociraptor releases | https://github.com/Velocidex/velociraptor/releases | primer | 0.77.3 (5 Okt 2026); diakses 2026-10-09, dicek ulang 2026-10-16 | Tinggi. 0.77.3 masih Latest per 2026-10-16 |
| S24 | Microsoft Learn: 4624(S) An account was successfully logged on | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624 | primer | ms.date 2021-09-07; diakses 2026-10-10, dicek ulang 2026-10-16 | Tinggi. Logon type 0-13, field versi 2, Linked Logon ID, Elevated Token, catatan isi field jaringan |
| S25 | Microsoft Learn: 4698(S) A scheduled task was created | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698 | primer | ms.date 2021-09-07; diakses 2026-10-16 | Tinggi. Task Content XML, field tambahan sejak 1903, saran task di root dan LogonType Password |
| S26 | Microsoft Learn: 1102(S) The audit log was cleared | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102 | primer | ms.date 2021-09-07; diakses 2026-10-16 | Tinggi. Provider Microsoft-Windows-Eventlog, field Subject, saran investigasi |
| S27 | Microsoft Learn: System Audit Policy recommendations | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations | primer | ms.date 2025-06-13; diakses 2026-10-16 | Tinggi. Tabel nilai bawaan Windows client dan server; Audit Logon Success dan Failure sejak 1809 |
| S28 | Microsoft Learn: Command line process auditing | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing | primer | ms.date 2025-05-12; diakses 2026-10-10, dicek ulang 2026-10-16 | Tinggi. Dua setting untuk command line 4688, peringatan password di command line, 4719, force subcategory settings |
| S29 | Microsoft Learn: Sysmon | https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon | primer | terbit 2026-09-10; diakses 2026-10-10, dicek ulang 2026-10-16 | Tinggi. Event ID 1-29 dan 255, UTC, ProcessGuid, event 3 mati bawaan, SHA1 bawaan |
| S30 | Microsoft Learn: about_Logging_Windows (PowerShell 7.6) | https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows | primer | ms.date 2026-01-18; diakses 2026-10-10, dicek ulang 2026-10-16 | Tinggi. Module logging, script block logging, channel `PowerShellCore/Operational`, Protected Event Logging |
| S31 | Velociraptor: Windows.EventLogs.PowershellScriptblock | https://docs.velociraptor.app/artifact_references/pages/windows.eventlogs.powershellscriptblock | primer (dokumentasi proyek) | diakses 2026-10-16 | Sedang-tinggi. Level Warning tercatat walau script block logging mati bila kata kunci mencurigakan terdeteksi; parameter `LogLevel`, `VSSAnalysisAge` |
| S32 | GitHub: EricZimmerman/evtx (README EvtxECmd) | https://github.com/EricZimmerman/evtx | primer (repo resmi) | diakses 2026-10-16 | Tinggi. Opsi `-f`, `-d`, `--csv`, `--csvf`, `--inc`, `--exc`, `--sd`, `--ed`, `--maps`, `--vss`, `--dedupe`, `--sync`, `--tdt`, `--met` |
| S33 | GitHub: evtx Maps (map 4624, 4698, 7045, 104, 106, 201, 4104, Sysmon 1, 1149, 21) | https://github.com/EricZimmerman/evtx/tree/master/evtx/Maps | primer (repo resmi) | diakses 2026-10-16 | Tinggi untuk isi kolom per map pada tanggal akses; map bisa berubah |
| S34 | Volatility 3 releases (2.28.2) | https://github.com/volatilityfoundation/volatility3/releases | primer | 2.28.2, 17 Sep 2026; diakses 2026-10-09, dicek ulang 2026-10-16 | Tinggi. Versi, plugin, perubahan; rename plugin ke subpaket `malware` di 2.26.2 |
| S35 | Plaso releases (GitHub) | https://github.com/log2timeline/plaso/releases | primer | diakses 2026-10-16 | Tinggi. 20260720 rilis stabil; 20260928 pre-release |

**Catatan sumber:** Day ini tidak memakai sumber baru; setiap klaim berasal dari Day 01-05 dan sumber yang sama dirujuk ulang dengan nomor baru. Hal yang masih perlu dicek mengikuti catatan di Day asalnya, terutama nama service driver WinPmem dan perilaku 7045/4697 saat driver dimuat, status bawaan channel TaskScheduler/Operational, pola nama VHDX untuk compound target, perilaku `TrustedPathRegex` dan nilai `MaxFileSize` di `Windows.Triage.Targets`, dan nama kolom CSV EvtxECmd di luar yang dipetakan map. Dua dokumen lisensi KAPE tidak sejalan soal penggunaan internal perusahaan [S8][S9]; tafsir ketat PT JAB adalah pilihan kasus fiktif, bukan kesimpulan hukum. Peta konsep di bagian 1.6, tiga benang di bagian 1.8 sampai 1.10, dokumen serah terima di bagian 1.11, dan glosarium adalah susunan catatan ini, bukan model resmi salah satu sumber. Status OU `JKT-WS-0418` dan `BDG-WS-0147` belum ditetapkan di kasus; kesimpulan audit bawaan untuk keduanya adalah penalaran dari aturan OU PT JAB. Pembahasan skenario di bagian 2-4 adalah penalaran praktik umum, bukan prosedur standar. Semua isi PT JAB, termasuk nomor bukti, waktu, nilai hash, nomor kantong dan resi, isi serah terima, dan timeline lab, adalah contoh fiktif.
