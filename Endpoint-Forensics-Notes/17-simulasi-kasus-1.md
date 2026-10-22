---
day: 17
title: 'Simulasi kasus 1: dugaan pencurian data oleh orang dalam, dari triage sampai temuan terkorelasi'
researched_on: 2026-10-22
versions_checked: 'Windows 11 23H2 (build 22631); EZ Tools 2026.5.0 (LECmd, JLECmd, SBECmd, RECmd dengan DFIRBatch v2.22, MFTECmd, EvtxECmd, RBCmd; .NET 4.7.2 dan .NET 9); KAPE dengan target bawaan; Microsoft Defender for Endpoint Plan 2 (advanced hunting overview ms.date 2026-08-07, data 30 hari; DeviceFileEvents ms.date 2025-03-28; device control report ms.date 2024-06-25; Investigate devices ms.date 2026-07-23); Microsoft Learn event 5140 dan 5145 (ms.date 2021-09-08), Audit Removable Storage (ms.date 2021-09-06), File Times, DEVPKEY_Device_FirstInstallDate (ms.date 2022-06-23); [MS-SHLLINK] VolumeID (2025-06-10); CISA Defining Insider Threats'
---

# Day 17: Simulasi kasus 1, dugaan pencurian data oleh orang dalam

Cakupan: satu kasus fiktif dugaan penyalinan data harga kontrak dan data PIC pelanggan korporat oleh karyawan yang mengundurkan diri, dikerjakan dari permintaan HR dan Legal sampai ringkasan kasus, dengan pembedaan tegas antara yang terbukti, yang disimpulkan, dan yang tidak bisa disimpulkan.

## Ide inti

Kasus orang dalam tidak punya artefak yang jahat. Semua aksi dilakukan dengan akun yang sah, lewat aplikasi yang sah (Explorer, Excel, browser), sering di jam kerja, ke data yang memang boleh dibuka akun itu. Karena itu kasus ini tidak dijawab dengan mencari "yang aneh" di satu artefak, tetapi dengan menyusun tangga bukti dan melihat sampai anak tangga mana artefak benar-benar membawamu: data diakses, berkas dibuka, berkas disalin ke media tertentu, media atau data keluar dari organisasi, dan niat. Artefak host biasanya kuat untuk dua anak tangga pertama, cukup kuat secara tidak langsung untuk anak tangga ketiga, lemah untuk anak tangga keempat, dan tidak pernah menjawab yang kelima. Pekerjaan forensik di kasus ini adalah menyatakan dengan jujur di anak tangga mana bukti berhenti.

Hal kedua yang membuat kasus ini berbeda adalah akibatnya. Hasil analisismu bisa dipakai untuk keputusan hubungan kerja dan mungkin langkah hukum, jadi setiap kalimat harus bisa ditunjuk ke artefak, setiap dugaan diuji bersama hipotesis tandingan yang tidak menyalahkan karyawan, dan lingkup pemeriksaan dibatasi oleh izin tertulis. Analyst menyediakan fakta dan batasnya; HR dan Legal yang menilai perbuatan.

Polanya sudah kamu kenal dari NOC. Saat ada dugaan engineer internal membocorkan konfigurasi perangkat pelanggan, log TACACS bisa menunjukkan ia login dan menjalankan `show running-config` di perangkat yang bukan tanggungannya, di jam yang tidak biasa. Itu bukti akses dan pembacaan. Log itu tidak membuktikan ia menyimpan output ke laptopnya, apalagi mengirimnya ke pihak lain, dan tidak mengatakan apa pun tentang niatnya. Engineer senior memperlakukan dugaan itu seperti dugaan penyebab gangguan: beberapa hipotesis ditulis sejak awal (termasuk "ia sedang mengerjakan tiket yang sah"), lalu diuji satu per satu. Hipotesis yang belum diuji tidak ditulis sebagai fakta, dan penjelasan bisa lebih dari satu sekaligus.

```
dugaan HR/Legal: "data dicuri sebelum keluar"
        |
        v
pertanyaan investigasi + hipotesis (termasuk tandingan)
        |
        v
TANGGA BUKTI                         sumber utama                      kekuatan dari host
 1. data DIAKSES                     5140/5145 file server, TypedPaths  kuat (butuh log server)
 2. berkas DIBUKA                    LNK, Jump List, 4688/Sysmon 1      kuat
 3. berkas DISALIN ke media X        rantai USB + LNK/Jump List di X    tidak langsung (isi butuh media X)
 4. data KELUAR organisasi           proxy, gateway email, media fisik  lemah dari host; sumber di luar host
 5. NIAT                             tidak ada artefak                  tidak dijawab forensik
        |
        v
temuan per pertanyaan + keyakinan + batas -> ringkasan untuk HR/Legal (kalimat aman, kalimat dilarang)
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan, layanan broadband rumah dan dedicated internet untuk pelanggan korporat. Kasusnya `INC-2027-010`, SEV-3, kategori dugaan pencurian data oleh orang dalam. Arif Wicaksono (`arif.wicaksono`), account manager pelanggan korporat di Divisi Enterprise Sales Jakarta, mengundurkan diri dengan hari kerja terakhir Jumat 2027-01-08. Laptopnya `JKT-WS-0516` (`10.10.51.16`, Windows 11 23H2 build 22631) berada di OU `Workstations-EDR`, sehingga memakai Microsoft Defender for Endpoint, Sysmon, dan GPO audit `JAB-WS-Audit`. Laptop dikembalikan Jumat sore, diterima IT Helpdesk dalam keadaan mati, dan ditahan atas permintaan HR tanpa di-reimage. Senin 2027-01-11 pagi, PIC PT Samudra Logistik Contoh, pelanggan korporat yang dipegang account manager lain, memberi tahu bahwa mereka ditawari ISP pesaing dengan harga yang sama persis dengan harga kontrak PT JAB. Senin sore, setelah keputusan Legal, Yoga Pratama mengambil image disk penuh `INC-2027-010-E01` dan membuat salinan kerja `E01-W1`. Selasa 2027-01-12 pukul 09:00, setelah rapat dengan HR Business Partner Larasati Wibisono dan Legal Ratna Sari, Dimas Prasetyo (SOC lead, incident commander) menulis kepadamu di kanal `#inc-2027-010`:

> "Barusan rapat dengan Bu Larasati dan Bu Ratna. Legal sudah kasih izin tertulis untuk periksa laptop kantor Arif (JKT-WS-0516, image E01 diambil Yoga kemarin sore), log akses share Enterprise-Sales di JKT-FS01, proxy, dan Defender. Akun pribadi dan HP-nya tidak termasuk. Yang HR dan Legal butuh: apakah Arif membuka data harga kontrak atau daftar PIC pelanggan di luar kebiasaan kerjanya, dan kapan? Berkas apa saja yang dibuka? Ada flashdisk atau perangkat lain yang dicolok, kapan, dan di sesi siapa? Ada bukti berkas itu disalin keluar? Bagaimana dengan email pribadi atau cloud, apa yang bisa kita lihat dari laptop dan apa yang tidak? Ada yang dihapus? Terakhir, seberapa yakin kita, dan kalimat apa yang aman ditulis untuk HR, karena ini bisa dipakai untuk keputusan dan mungkin langkah hukum. Draf saya perlu Kamis jam 10:00, rapat dengan HR dan Legal jam 13:00. Pak Agus ikut karena daftar PIC itu data pribadi."

Pesan itu memuat tujuh pertanyaan:

1. Apakah akun Arif mengakses data harga kontrak atau daftar PIC di luar pola kerjanya, dan kapan?
2. Berkas apa yang dibuka, dan dari lokasi mana (share, disk lokal, media lepasan)?
3. Perangkat USB apa yang tersambung, kapan, dan di sesi siapa?
4. Apakah ada bukti berkas itu disalin ke perangkat tersebut?
5. Bagaimana jalur lain (email pribadi, cloud, unggahan browser): apa yang terlihat dari laptop, dan apa yang butuh sumber di luar laptop?
6. Apakah ada upaya menghapus jejak?
7. Seberapa yakin jawabannya, apa batasnya, dan kalimat apa yang aman untuk HR dan Legal?

Bagian 1.1 dan 1.2 membingkai kasus orang dalam dan tata kelolanya. Pertanyaan 1 dijawab konsepnya di bagian 1.3, pertanyaan 2 di bagian 1.4, pertanyaan 3 di bagian 1.5, pertanyaan 4 di bagian 1.6, pertanyaan 5 dan 6 di bagian 1.7, dan pertanyaan 7 di bagian 1.8. Bagian 2 berisi pengerjaan kasusnya: perintah, keluaran ilustrasi, temuan per pertanyaan, pengujian hipotesis, garis waktu, ringkasan untuk HR dan Legal, dan rubrik penilaian diri.

**Kapan relevan:** dugaan pencurian atau penyalahgunaan data oleh karyawan, kontraktor, atau mantan karyawan; pelanggaran kebijakan media lepasan; permintaan HR atau Legal yang hasilnya bisa dipakai untuk keputusan kepegawaian atau sengketa.
**Kapan bukan jawaban:** kasus malware atau penyerang eksternal (Day 18 merekonstruksi infeksi installer palsu dengan DLL side-loading sampai C2 dan persistence); penilaian niat, kesalahan, atau sanksi (wewenang HR dan Legal, bukan forensik); pemeriksaan perangkat atau akun pribadi karyawan tanpa dasar dan izin yang jelas; dan penilaian kewajiban hukum seperti pelaporan pelindungan data pribadi (wewenang DPO dan Legal; Day ini menulis praktik, bukan nasihat hukum).

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (LNK, Jump List, ShellBags, TypedPaths, RecentDocs, `MountPoints2`, device properties `0064` sampai `0067`, `MountedDevices`, VolumeID dan DriveSerialNumber, `$J`, Recycle Bin, Logon ID, logon type, 4688, Sysmon, telemetry EDR, retensi telemetry, lembar batas bukti, garis waktu kurasi, hipotesis investigasi) tidak diulang. Tabel ini hanya memuat istilah baru Day ini; kolom padanan memakai analogi NOC dan SOC yang sama di semua Day.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Kasus orang dalam (insider threat) | Risiko orang yang punya atau pernah punya akses sah memakai akses itu untuk merugikan organisasi, sengaja atau tidak | Engineer internal dengan akun TACACS sah yang menjalankan perintah di perangkat yang memang bisa ia masuki |
| Pola kerja (baseline akses) | Gambaran akses normal satu akun: data apa, berapa banyak, jam berapa, dalam jendela log yang tersedia | Baseline trafik per pelanggan di MRTG; lonjakan dinilai terhadap pola biasanya |
| Tangga bukti (akses, pembukaan, penyalinan, keluar, niat) | Tingkat klaim yang berbeda, masing-masing butuh artefak berbeda | `show running-config` di log TACACS membuktikan pembacaan, bukan penyimpanan atau pembocoran konfigurasi |
| Hipotesis tandingan | Penjelasan yang sama-sama cocok dengan artefak tetapi tidak menyalahkan orang yang diduga | Penjelasan gangguan "maintenance terjadwal" yang diuji sejajar dengan "sabotase" |
| Lingkup izin (memo Legal) | Dokumen tertulis yang menetapkan perangkat, sumber data, periode, dan batas pemeriksaan | Change ticket yang menyebut perangkat dan perintah yang boleh disentuh selama maintenance |
| Audit Detailed File Share (5145) | Subkategori audit di file server yang mencatat setiap akses ke objek di share (file atau folder) | Accounting per perintah di perangkat, bukan hanya catatan login |
| Media kerja terdaftar | Media lepasan yang tercatat sebagai aset perusahaan beserta nomor serinya | Modul spare yang terdaftar di inventaris dengan nomor seri |

### 1.1 Kasus orang dalam: berbeda dari kasus malware

Dimas tidak menyebut satu pun alert. Yang ia bawa adalah dugaan HR dan Legal, dan dugaan "Arif mencuri data" tidak bisa dijawab langsung oleh artefak mana pun. Pekerjaan pertama adalah menerjemahkannya menjadi pertanyaan yang masing-masing punya artefak penjawab, seperti tujuh pertanyaan di Ide inti.

CISA mendefinisikan insider sebagai siapa pun yang punya, atau pernah punya, akses sah ke aset organisasi, termasuk karyawan, kontraktor, dan vendor; insider threat adalah risiko orang itu memakai akses atau pengetahuannya untuk merugikan organisasi, secara sadar maupun tidak [S15]. CISA membagi jenisnya menjadi tidak disengaja (lalai atau kecelakaan, misalnya mengirim berkas ke alamat yang salah), disengaja (misalnya membocorkan informasi atau mencuri data), kolusif (orang dalam bekerja sama dengan pihak luar), dan pihak ketiga [S15]. Pembagian ini berguna bukan untuk memberi label pada Arif, tetapi untuk mengingatkan bahwa satu kumpulan artefak yang sama bisa berasal dari kelalaian, pekerjaan sah, atau kesengajaan. Forensik tidak memilih di antara ketiganya; forensik menunjukkan apa yang terjadi di perangkat.

Tabel berikut membandingkan kasus ini dengan kasus malware yang sudah kamu kerjakan di Day sebelumnya; baca kolom kanan untuk memahami kenapa cara kerjanya bergeser.

| Aspek | Kasus malware (`INC-2026-019`, `INC-2026-017`) | Kasus orang dalam (`INC-2027-010`) |
|---|---|---|
| Pelaku | Kode atau operator penyerang yang menumpang akun korban | Pemilik akun itu sendiri, atau orang yang memakai sesinya |
| Artefak | Ada yang jahat dengan sendirinya: loader, task tersembunyi, beacon | Tidak ada; Explorer, Excel, flashdisk, dan browser semuanya sah |
| Nilai bukti | Dari keberadaan artefak penyerang | Dari urutan dan konteks: akses di luar pola, perangkat yang disambung pada waktu berdekatan, berkas yang sama muncul di dua lokasi |
| Pemisahan pelaku | Pengguna, penyerang, responder | Pemilik akun, rekan kerja yang sah (serah terima), responder; identitas orang di depan keyboard tidak bisa dibuktikan artefak |
| Pembaca hasil | IC, technical lead, PIR | HR, Legal, DPO; hasil bisa dipakai untuk keputusan kepegawaian atau sengketa |
| Kesalahan paling mahal | Melewatkan persistence | Menulis lebih kuat dari bukti, atau memeriksa di luar lingkup izin |

Konsekuensi praktisnya ada tiga. Pertama, setiap temuan menyebut anak tangga bukti yang dicapainya (bagian 1.4). Kedua, hipotesis tandingan ditulis sejak awal dan diuji dengan artefak yang sama (bagian 1.8). Ketiga, jejak tim sendiri tetap dipisahkan: di kasus ini Yoga mengambil image dari laptop yang mati, sehingga jejak responder di disk hampir nol, tetapi pembacaan share oleh Yoga untuk menghitung hash berkas asli tercatat di log `JKT-FS01` dan harus diberi label.

### 1.2 Tata kelola: izin, lingkup, dan data pribadi

Kalimat Dimas "akun pribadi dan HP-nya tidak termasuk" adalah bagian dari bukti, bukan basa-basi. Di kasus orang dalam, cara bukti diperoleh sama pentingnya dengan isinya, karena hasilnya bisa diuji pihak lain dalam proses kepegawaian atau sengketa. Isi bagian ini adalah praktik kerja yang dipakai PT JAB, bukan nasihat hukum.

Praktik yang dipegang di kasus ini:

- **Izin tertulis sebelum analisis.** Memo Legal Senin 2027-01-11 14:30 menyebut perangkat (`JKT-WS-0516`), sumber pendukung (log akses share `Enterprise-Sales` di `JKT-FS01` untuk akun Arif sejak Oktober 2026, log proxy 4 sampai 8 Januari 2027, dan data Defender untuk perangkat itu), periode, dan batasnya (tanpa akun email atau cloud pribadi, tanpa ponsel, tanpa isi email korporat). Isi email korporat butuh izin terpisah karena menyangkut pihak lain di kotak surat yang sama.
- **Hanya perangkat dan data milik perusahaan.** Laptop kantor dan log server PT JAB diperiksa. Flashdisk pribadi tidak ada di tangan PT JAB dan tidak diminta oleh tim forensik; memintanya adalah keputusan HR dan Legal.
- **Prinsip kebutuhan.** Pertanyaan menentukan artefak, bukan sebaliknya. Di laptop ada foto, dokumen pribadi, dan riwayat browser pribadi. Yang dibaca hanya yang menjawab tujuh pertanyaan: nama, path, ukuran, dan waktu. Bila artefak memperlihatkan nama folder pribadi (misalnya di ShellBags flashdisk), nama itu dicatat di case notes sebagai keberadaan, isinya tidak dibuka, dan ia tidak masuk lampiran.
- **Data pribadi dua arah.** Daftar PIC berisi nama, nomor telepon, dan email PIC pelanggan korporat. PT JAB adalah pengendali data pribadi menurut UU PDP, jadi DPO Agus Setiawan menilai dampak dan kewajiban yang mungkin timbul; tim forensik menyediakan fakta (berkas apa, berapa baris, kapan, ke mana). Di sisi lain, timeline laptop Arif juga data pribadi karyawan: jam kerja, jaringan rumah, aplikasi pribadi. Lampiran laporan hanya memuat baris yang relevan, sama seperti minimisasi di Day 13 bagian 1.7.
- **Keterangan orang bukan artefak.** Keterangan atasan (Kepala Divisi Enterprise Sales Surya Atmaja), penerima serah terima (Galih Pramudya), atau IT ditulis sebagai keterangan dengan nama dan waktu, terpisah dari temuan artefak. Analyst forensik tidak mewawancarai subjek; itu proses HR.
- **Chain of custody dan hash.** Laptop dipegang IT sejak Jumat dan Yoga sejak Senin; serah terima dicatat di formulir chain of custody (Day 01 bagian 1.5) supaya pertanyaan "siapa yang menyalakan laptop sejak dikembalikan" bisa dijawab dengan dokumen, bukan ingatan.

**Kapan gagal:** analyst "sekalian" membuka email pribadi yang tersimpan di cache browser karena terlihat di timeline, atau menulis isi dokumen pribadi ke lampiran. Selain melanggar lingkup, temuan semacam itu bisa membuat seluruh laporan dipersoalkan.

### 1.3 Pola kerja: mendefinisikan "di luar kebiasaan" dengan angka

Pertanyaan pertama Dimas memakai kata "di luar kebiasaan kerja". Kata itu harus diubah menjadi ukuran yang bisa dihitung, karena account manager memang membuka berkas harga setiap minggu. Akses ke data sensitif bukan temuan; akses yang berbeda dari pola akun itu sendiri, dalam dimensi yang bisa dijelaskan, baru temuan.

Empat dimensi pola yang dipakai di kasus ini:

| Dimensi | Pertanyaan | Sumber di PT JAB |
|---|---|---|
| Data apa | Berkas milik portofolio sendiri atau portofolio orang lain? | 5145 `Relative Target Name` di `JKT-FS01` + daftar portofolio account manager dari Kepala Divisi |
| Berapa banyak | Berapa berkas berbeda dan berapa event per hari? | 5145, dihitung per hari |
| Kapan | Jam dan hari, dibanding jam kerja biasanya | 5145, 4624 di laptop, ShellBags |
| Bagaimana | Diketik langsung, dijelajah, atau dibuka lewat aplikasi? | TypedPaths, ShellBags, LNK, Jump List (Day 10 bagian 1.5) |

Sumber utama pola adalah file server, bukan laptop. Event 5140 di file server ditulis sekali per sesi saat akun pertama kali mengakses sebuah share, dan selalu dengan akses ReadData [S1]. Event 5145 ditulis setiap kali objek di share (file atau folder) diakses, dari subkategori Audit Detailed File Share, dengan field `Share Name`, `Relative Target Name` (path relatif terhadap share), `Source Address`, dan `Accesses` (misalnya ReadData atau WriteData) [S2]. Event gagal hanya ditulis bila akses ditolak di tingkat share, bukan bila ditolak oleh izin NTFS [S2]. Kedua event tercatat di server pemilik share, bukan di workstation; bila kamu hanya punya laptop, kamu bergantung pada TypedPaths dan ShellBags, dan ShellBags hanya membuktikan folder pernah dilihat, bukan waktu persis setiap kunjungan (Day 10 bagian 1.2).

Tiga batas harus ditulis bersama angka pola:

- **5145 adalah pemeriksaan akses, bukan bukti berkas dibuka di aplikasi.** Panel preview Explorer, pembuatan thumbnail, pemindaian antivirus, dan penyalinan sama-sama membaca berkas. Jumlah event 5145 menunjukkan intensitas akses, sedangkan berkas mana yang dibuka di Excel dijawab LNK, Jump List, dan 4688 di laptop (bagian 1.4).
- **Jendela baseline mengikuti retensi.** Pola hanya bisa dihitung dari log yang masih ada. Di PT JAB, event 5145 `JKT-FS01` bisa dicari di Splunk index `wineventlog` selama 180 hari; advanced hunting Defender hanya 30 hari [S11]. Baseline yang ditulis "Oktober sampai awal Januari" harus menyebut jendela persisnya.
- **Perubahan peran yang sah menggeser pola.** Karyawan yang akan keluar mengerjakan serah terima, dan serah terima memang membuat akses yang tidak biasa: membuka semua berkas portofolio, menyalinnya ke folder serah terima, mengirimnya ke pengganti. Ini bukan gangguan bagi analisis; ini hipotesis tandingan pertama yang harus diuji (bagian 1.8).

### 1.4 Tangga bukti: diakses, dibuka, disalin, keluar, dan niat

Pertanyaan kedua dan keempat Dimas sering tercampur dalam satu kalimat ("Arif membuka dan menyalin berkas harga"). Padahal keduanya ada di anak tangga yang berbeda dan dijawab artefak yang berbeda.

Tabel berikut adalah pegangan kerja untuk seluruh kasus; baca kolom "Tidak membuktikan", karena kalimat laporan yang salah hampir selalu melompati kolom itu.

| Anak tangga | Artefak utama | Membuktikan | Tidak membuktikan |
|---|---|---|---|
| 1. Diakses | 5140/5145 di file server; TypedPaths (path diketik); ShellBags (folder dilihat) | Akun meminta akses ke share, folder, atau berkas tertentu pada waktu tertentu | Berkas dibuka di aplikasi; isi dibaca orang |
| 2. Dibuka | LNK dan Jump List (Day 10 bagian 1.3 dan 1.4); RecentDocs; 4688/Sysmon 1 dengan command line aplikasi | Berkas dibuka lewat shell atau aplikasi, dari path tertentu, di profil tertentu | Apa yang dilakukan pada berkas setelah dibuka |
| 3. Disalin ke media X | Berkas bernama dan berukuran sama dengan waktu pembuatan baru di media X; rantai media X ke perangkat fisik (bagian 1.5); `$J`/`$MFT` bila tujuannya volume NTFS yang journal-nya kamu punya; telemetry EDR bila sensor sempat mengirim | Ada berkas dengan nama dan metadata yang sama di media X pada waktu tertentu | Isi identik (butuh media X); keberadaan berkas saat ini |
| 4. Keluar organisasi | Media fisik dibawa pulang; proxy dan gateway email; log layanan cloud | Media atau koneksi meninggalkan perimeter pada waktu tertentu | Apa isi yang terkirim, kecuali sumbernya mencatat isi |
| 5. Niat | Tidak ada | Tidak ada | Selalu di luar jangkauan forensik |

Rangkaian tiga tingkat dari Day 10 tetap berlaku sebagai dasar: TypedPaths membuktikan path diketik, ShellBags membuktikan folder dilihat, dan LNK, Jump List, serta RecentDocs membuktikan berkas dibuka atau dipilih [S3]. Kasus ini menambah dua anak tangga di atasnya. Yang paling sering dilompati adalah dari anak tangga 2 ke 3: membuka berkas dari share bukan bukti penyalinan. Yang mendekati bukti penyalinan adalah berkas bernama sama dengan waktu pembuatan baru di media tujuan (bagian 1.6).

Satu artefak pembukaan yang sering dilupakan ada di event log, bukan di profil pengguna. Karena `JAB-WS-Audit` mengaktifkan Process Creation dengan command line, 4688 dan Sysmon EID 1 untuk `EXCEL.EXE` memuat path berkas yang dibuka bila Excel baru dijalankan untuk berkas itu. Bila Excel sudah berjalan, berkas berikutnya dibuka di proses yang sama dan tidak menghasilkan 4688 baru. Jadi 4688 menguatkan pembukaan pertama di satu sesi Excel, dan ketiadaannya untuk berkas kedua bukan tanda berkas itu tidak dibuka. Format persis command line saat Office dipanggil dari Explorer cek di build lab.

### 1.5 Rantai USB: nomor seri volume bukan nomor seri perangkat

Pertanyaan ketiga Dimas ("flashdisk apa, kapan, di sesi siapa") punya jebakan yang sering membuat laporan salah: nomor seri volume yang tersimpan di LNK bukan nomor seri perangkat yang tersimpan di USBSTOR. Tabel ini membedakan keduanya; perhatikan kolom "Di mana tercatat", karena di situlah kebutuhan jembatan terlihat.

| Nilai | Asal | Contoh di kasus ini | Di mana tercatat |
|---|---|---|---|
| Device serial number | Firmware perangkat USB (iSerialNumber) | `0019E06B4A21C5F0A7` | Nama subkey USBSTOR, nama perangkat di Windows Portable Devices, `UsbDriveMounted` Defender |
| Volume serial number (VSN) | Dibuat saat volume diformat | `5A1C-0E37` | LNK dan Jump List (`DriveSerialNumber`), EMDMgmt bila ada, data boot record di event 1006 |

LNK menyimpan struktur VolumeID berisi `DriveType` (misalnya `DRIVE_REMOVABLE` untuk thumb drive), `DriveSerialNumber` volume tempat target berada, dan label volume [S7]. USBSTOR menyimpan serial perangkat. Keduanya tidak bisa langsung "dicocokkan"; jembatannya harus ditunjukkan. Jembatan yang tersedia, dari yang paling kuat:

1. **Event `Microsoft-Windows-Partition/Diagnostic` 1006.** Event ini dicatat saat disk tersambung dan memuat informasi perangkat beserta salinan boot record volume (`Vbr0`); VSN dibaca dari offset `0x48` untuk NTFS, `0x43` untuk FAT32, dan `0x64` untuk exFAT, sebagai nilai 4 byte little-endian [S9][S4]. Satu event memuat serial perangkat dan VSN sekaligus, sehingga ini jembatan langsung. Channel ini sering tersedia tetapi tidak dijamin, dan pembaruan besar Windows bisa mengosongkannya [S9]. Tata letak datanya tidak didokumentasikan resmi oleh Microsoft [S4], jadi uji dulu dengan flashdisk milikmu sendiri di build yang sama sebelum memakainya di laporan.
2. **Label dan huruf drive pada waktu yang sama.** LNK memuat label volume; `Windows Portable Devices\Devices` memetakan serial perangkat ke `FriendlyName` (label); `MountedDevices` memetakan huruf drive dan volume GUID ke perangkat; `MountPoints2` di NTUSER menautkan volume GUID ke profil pengguna (Day 09 bagian 1.5). Label bisa sama di banyak perangkat, jadi kekuatannya datang dari kombinasi label, huruf drive, dan waktu.
3. **EMDMgmt.** `SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt` memuat label dan VSN bila ada. Key ini terkait ReadyBoost dan sering tidak ada di laptop dengan SSD, jadi ketiadaannya bukan temuan (Day 10 bagian 1.6).
4. **Telemetry EDR di luar host.** Defender mencatat event audit saat drive USB di-mount dan saat perangkat Plug and Play tersambung, secara default untuk perangkat yang onboard [S13]. Kueri komunitas yang banyak dipakai membaca `DeviceEvents` dengan `ActionType` `UsbDriveMounted` dan mengambil huruf drive, nama produk, nomor seri, dan pabrikan dari `AdditionalFields` [S17]. Jembatan ini hanya ada untuk sesi ketika sensor sempat mengirim data ke cloud (bagian 1.6).

Waktu per perangkat dibaca dari device properties di subkey `Properties\{83da6326-97a6-4088-9453-a1923f573b29}`: `0064` InstallDate, `0065` FirstInstallDate, `0066` LastArrivalDate, `0067` LastRemovalDate, semuanya UTC [S9]. Untuk "kapan pertama kali dicolok di laptop ini", pakai `0065`, karena `0064` berubah setiap kali driver perangkat diperbarui, sedangkan FirstInstallDate tidak [S8]. `0066` dan `0067` hanya menyimpan colok dan cabut terakhir; sesi sebelumnya dicari di event 1006, `setupapi.dev.log` (hanya instalasi pertama, dalam waktu lokal), dan telemetry EDR. Akses ke subkey Properties di sistem hidup butuh hak SYSTEM; di hive dari image bisa dibaca biasa.

Dua aturan baca lagi. Serial yang karakter keduanya `&` adalah serial buatan Windows karena perangkat tidak melaporkan serial unik; serial seperti itu hanya unik per host dan tidak bisa dipakai untuk mencocokkan antar host [S9]. Dan `MountPoints2` membuktikan volume di-mount di sesi profil tertentu, bukan siapa yang memegang flashdisk (Day 09 bagian 1.5). Registry dan event log membuktikan perangkat dikenali dan di-mount, bukan berkas apa yang disalin [S9].

### 1.6 Bukti penyalinan: titik paling halus

Pertanyaan keempat Dimas ("ada bukti berkas itu disalin keluar?") adalah tempat laporan paling sering melampaui bukti. Jawabannya hampir selalu dibagi tiga: yang terbukti, yang disimpulkan, dan yang tidak bisa disimpulkan.

Artefak yang bisa menunjukkan penyalinan ke media lepasan, beserta syaratnya:

| Sumber | Yang terlihat | Syarat dan batas |
|---|---|---|
| LNK dan Jump List yang menunjuk media | Berkas di media dibuka; `TargetCreated`, `TargetModified`, ukuran, `DriveType`, VSN, label | Hanya berkas yang dibuka dari media; berkas yang disalin tetapi tidak pernah dibuka tidak meninggalkan LNK |
| ShellBags | Folder di media dijelajahi | Bukan isi; bukan penyalinan |
| `$J` dan `$MFT` | Berkas lahir sebagai `FileCreate` di volume | Hanya untuk volume yang journal dan MFT-nya kamu punya; penyalinan dari `C:` ke flashdisk tidak menulis apa pun ke `C:` (Day 08 bagian 1.4) |
| Security 4663 (Audit Removable Storage) | Setiap akses ke objek di media lepasan, tanpa bergantung SACL | Hanya bila subkategori itu diaktifkan [S10]; tidak ada di `JAB-WS-Audit` |
| Sysmon EID 11 (FileCreate) | Berkas dibuat beserta prosesnya | Hanya lokasi dan ekstensi yang masuk konfigurasi; konfigurasi Sysmon PT JAB untuk EID 11 mencatat Downloads, folder Temp, Startup, dan ekstensi skrip serta executable, bukan dokumen Office di media lepasan |
| Defender `DeviceFileEvents` | `FileCreated` dengan path, ukuran, proses, kadang hash | Hanya data yang sudah dikirim sensor; advanced hunting menerima data setelah sensor berhasil mengirimkannya [S11]; hash bisa kosong [S12]; komunitas mencatat tidak semua tipe berkas dipantau [S17] |

Perilaku waktu di media FAT membuat `TargetCreated` berguna. Saat Explorer menyalin berkas, waktu modifikasi umumnya ikut dibawa sedangkan waktu pembuatan di tujuan adalah waktu penyalinan, sehingga berkas di media yang dibuat beberapa menit setelah media dicolok, dengan nama, ukuran, dan waktu modifikasi yang sama dengan berkas sumber, konsisten dengan penyalinan pada saat itu. Perilaku ini sebaiknya kamu amati sendiri di lab, karena bisa berbeda bila penyalinan memakai alat selain Explorer. Dua sifat FAT perlu diingat saat membandingkan waktu [S6]: FAT menyimpan waktu dalam waktu lokal komputer (NTFS dalam UTC), dan resolusinya kasar, 10 milidetik untuk waktu pembuatan dan 2 detik untuk waktu tulis. Jadi `TargetModified` di LNK untuk berkas di FAT bisa berbeda satu detik dari waktu modifikasi berkas NTFS asalnya tanpa berarti berkasnya berbeda; arah pembulatannya cek di lab.

Pola kalimat yang dipakai untuk temuan penyalinan:

- **Terbukti:** berkas bernama dan berukuran sama berada di volume dengan VSN tertentu dan dibuka dari sana pada waktu tertentu; volume itu milik perangkat dengan serial tertentu; berkas itu dibuat di volume tersebut pada waktu tertentu, saat volume tersambung dan sesi akun tertentu aktif.
- **Disimpulkan:** berkas di media adalah salinan berkas sumber. Kesimpulan ini wajar bila nama, ukuran, waktu modifikasi, dan urutan konsisten, tetapi isi tidak bisa dibandingkan tanpa media.
- **Tidak bisa disimpulkan:** isi berkas lain yang tidak pernah dibuka dari media, apakah berkas masih ada di media sekarang, ke mana media dibawa, siapa yang menerima isinya, dan niat.

USN journal laptop tidak membantu untuk penyalinan ke flashdisk, karena penyalinan dari `C:` ke `E:` hanya membaca `C:`. USN hanya mencatat perubahan di volume NTFS yang journal-nya kamu punya. Menulis kenapa sebuah artefak tidak relevan sama pentingnya dengan mendaftar artefak yang relevan.

### 1.7 Jalur lain dan hapus jejak: sumber di luar host dan hasil negatif

Pertanyaan kelima dan keenam Dimas mencegah kesalahan paling umum di kasus orang dalam: bila kamu hanya mencari USB, kamu hanya akan menemukan USB. Menutup jalur lain, atau menyatakan dengan jelas bahwa jalur itu tidak diperiksa dan kenapa, membuat kesimpulan lebih kuat.

Tabel berikut memetakan jalur keluar ke sumber yang bisa melihatnya; baca kolom "Di luar host" untuk mengetahui apa yang harus diminta, karena sebagian besar jalur selain media fisik tidak bisa dijawab dari laptop saja.

| Jalur | Di laptop (image) | Di luar host | Batas |
|---|---|---|---|
| Email korporat | Cache Outlook (OST) | Message trace dan audit Microsoft 365 | Isi butuh izin terpisah; menyangkut pihak lain di kotak surat |
| Email pribadi lewat browser | Riwayat browser (domain, waktu, judul) | Proxy: domain, kategori, volume; isi hanya di penyedia | Proxy PT JAB mendekripsi TLS hanya untuk domain baru dan tidak terkategori, jadi webmail yang terkategori tidak terlihat isinya |
| Cloud pribadi | Klien sync (Prefetch, folder, log klien), riwayat browser | Proxy; log penyedia | Klien yang tidak terpasang tidak meninggalkan artefak klien |
| OneDrive korporat | Folder dan log klien OneDrive | Audit Microsoft 365 | Berkas di OneDrive korporat tetap di tenant PT JAB |
| Media fisik | Rantai USB, LNK, Jump List, ShellBags | Telemetry EDR bila sensor mengirim | Isi butuh media |
| Cetak, foto layar dengan ponsel, ketik ulang | Antrean cetak bila ada; tidak ada artefak untuk foto layar | Log printer | Sebagian jalur tidak meninggalkan artefak apa pun |

Untuk hapus jejak, pemeriksaan yang hasilnya negatif tetap ditulis bersama cakupannya: Recycle Bin per SID (Day 08 bagian 1.6), `FileDelete` di `$J` dalam jendela journal, Security 1102 dan System 104 serta kesinambungan `EventRecordID` (Day 05 bagian 1.6), dan Prefetch untuk alat penghapus atau pembersih (Day 07 bagian 1.2). Dua aturan berlaku untuk temuan hapus jejak:

- **Penghapusan bukan otomatis menutupi jejak.** Karyawan yang akan mengembalikan laptop wajar membersihkan berkas lokal, apalagi bila salinan aslinya tetap ada di share. "Berkas dihapus" ditulis sebagai aksi dengan waktu dan cara (Recycle Bin, Shift+Delete, alat), tanpa kata "menutupi" atau "menghilangkan bukti" kecuali ada bukti lain.
- **Recycle Bin yang belum dikosongkan adalah bukti isi.** `$R` adalah berkas aslinya (Day 08 bagian 1.6), sehingga isi salinan lokal bisa di-hash dan dibandingkan dengan berkas asli di share. Ini satu-satunya titik di kasus seperti ini tempat kesamaan isi bisa dibuktikan, untuk salinan lokal, bukan untuk media.

### 1.8 Hipotesis tandingan, keyakinan, dan bahasa untuk HR

Pertanyaan ketujuh Dimas menentukan apakah hasilmu bisa dipakai. Kerjakan kasus sebagai pengujian beberapa hipotesis, bukan pembuktian satu dugaan, dan tuliskan semuanya di case notes sebelum membuka artefak supaya analisis tidak berat sebelah.

Empat hipotesis untuk kasus ini:

- **H1:** Arif menyalin berkas harga kontrak di luar portofolionya dan daftar PIC ke flashdisk pribadi untuk dibawa keluar.
- **H2 (tandingan):** aktivitas yang terlihat adalah pekerjaan serah terima ke pengganti, dan flashdisk dipakai untuk keperluan lain atau untuk serah terima.
- **H3 (tandingan):** flashdisk adalah media kerja resmi yang dipinjamkan perusahaan, sehingga keberadaan berkas di sana sesuai prosedur.
- **H4 (tandingan):** aktivitas di sesi Arif dilakukan orang lain yang memakai sesi atau akunnya.

Aturan menguji hipotesis: artefak yang mendukung H1 tetapi juga konsisten dengan H2 tidak membedakan keduanya. Yang membedakan adalah artefak yang hanya cocok dengan satu hipotesis, misalnya berkas yang tidak ada di daftar serah terima tetapi muncul di media, atau berkas yang dibuka dari huruf drive flashdisk. Sebagian hipotesis tidak dijawab artefak sama sekali: H3 dijawab dengan bertanya ke IT apakah serial perangkat terdaftar sebagai aset, dan H4 hanya bisa dipersempit (siapa yang membuka kunci layar, dari mana, dengan kredensial apa), tidak bisa dibuktikan atau disingkirkan oleh artefak, karena artefak mencatat akun dan sesi, bukan orang. Hasil yang jujur sering berbentuk "H2 menjelaskan sebagian aktivitas, tetapi tidak menjelaskan bagian lain".

Skala keyakinan yang dipakai di temuan:

| Keyakinan | Syarat |
|---|---|
| Tinggi | Minimal dua sumber independen sepakat (misalnya artefak laptop dan log file server), tanpa penjelasan lain yang masuk akal untuk fakta itu sendiri |
| Sedang | Rantai bukti lengkap tetapi tidak langsung, atau satu sumber kuat tanpa pembanding; penjelasan lain masih mungkin untuk sebagian |
| Rendah | Satu sumber yang lemah, atau inferensi dari ketiadaan |

Bahasa untuk HR dan Legal mengikuti lembar batas bukti di Day 12 bagian 1.11: kalimat yang boleh ditulis adalah batas atas, dan kalimat yang dilarang ditulis eksplisit karena biasanya justru kalimat itu yang muncul di rapat. Ringkasan kasus tidak memuat kata "mencuri", "menyalahgunakan", "sengaja", atau dugaan motif. Ia menyebut apa yang terlihat, apa yang tidak bisa diverifikasi, dan langkah yang bisa menaikkan kepastian. Identitas orang di depan keyboard, motif, dan kesalahan adalah pertanyaan HR dan Legal yang dijawab dengan proses mereka sendiri, dengan temuanmu sebagai salah satu masukan.

## 2. Contoh dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi yang disusun untuk kasus ini, bukan hasil eksekusi. Perintah EZ Tools dijalankan di workstation analisis forensik `JKT-DFIR01` atas salinan kerja `E01-W1` yang di-mount read-only; kueri Splunk dijalankan di search head SOC dan kueri advanced hunting di portal Defender, keduanya dengan akun analyst sesuai memo Legal. Nama kolom CSV dan nama field bisa berbeda antar versi alat dan add-on; cocokkan dengan versi di lab-mu. Narasi memakai WIB (UTC+7). EZ Tools dan advanced hunting menulis waktu dalam UTC (UTC = WIB dikurangi 7 jam), Splunk menampilkan waktu sesuai zona akun (di sini WIB), dan `setupapi.dev.log` menulis waktu lokal; setiap keluaran diberi label zonanya.

Alat untuk kasus ini dibekukan saat kasus dibuka (Day 02 bagian 1.3): EZ Tools 2026.5.0 build .NET 9 di `C:\DFIR\tools\EZTools-2026-10-15\net9\`, KAPE dengan KapeFiles yang disinkronkan terakhir sebelum kasus dibuka.

### 2.1 Menyiapkan E01-W1 dan sumber di luar host

Langkah ini menyiapkan bahan untuk semua jawaban ke Dimas, dan mencatat kondisi laptop sejak dikembalikan karena pertanyaan pertama Legal biasanya "apakah laptop disentuh setelah Arif menyerahkannya".

Case notes pembuka (zona waktu catatan WIB):

```
INC-2027-010 | Case notes forensik | <kamu> | TZ catatan: UTC+7 (WIB)
2027-01-12 09:00  Permintaan Dimas (#inc-2027-010): 7 pertanyaan, draf Kamis 2027-01-14 10:00,
                  rapat HR (Larasati Wibisono), Legal (Ratna Sari), DPO (Agus Setiawan) 13:00.
                  Lingkup: memo Legal 2027-01-11 14:30 (JKT-WS-0516; 5145 JKT-FS01 akun arif.wicaksono
                  sejak 2026-10-01; proxy 2027-01-04 s/d 2027-01-08; Defender perangkat JKT-WS-0516).
                  Di luar lingkup: akun pribadi, ponsel, isi email korporat.
2027-01-12 09:05  Riwayat perangkat (CoC + keterangan IT): Jumat 2027-01-08 16:20 laptop diterima
                  Teguh Wibowo (IT Helpdesk) dalam keadaan mati, tidak dinyalakan; 16:40 HR minta ditahan;
                  disimpan di lemari IT. Senin 2027-01-11 15:10 diambil Yoga (kantong bukti No. 0107),
                  image 15:40-18:25, SHA-256 akuisisi = verifikasi (7f3e...), master /evidence/INC-2027-010/E01/,
                  salinan kerja E01-W1 dibuat 19:20.
2027-01-12 09:15  E01-W1: hash 9 segmen cocok manifest. Mount read-only sebagai G: di JKT-DFIR01.
2027-01-12 09:20  Hipotesis H1-H4 ditulis sebelum membuka artefak (lihat 2.2).
```

Hash dan mount:

```powershell
$w = '\\jkt-evid01\cases\INC-2027-010\work\E01-W1'
Get-FileHash -Algorithm SHA256 -Path "$w\INC-2027-010-E01-W1.E0*" |
  Compare-Object -ReferenceObject (Import-Csv "$w\E01-W1.sha256.csv") -Property Hash -IncludeEqual
```

- `Get-FileHash` menghitung SHA-256 tiap segmen EWF; `Compare-Object -IncludeEqual` menampilkan yang sama (`==`) dan yang berbeda, sehingga sembilan baris `==` berarti salinan kerja identik dengan manifest Yoga.
- Mount read-only memakai alat mount image yang sama seperti Day 08; volume sistem muncul sebagai `G:`.

Ambil artefak dengan KAPE supaya ada copylog berisi SHA-1 tiap file (Day 03 bagian 1.3):

```
C:\DFIR\tools\KAPE\kape.exe --tsource G: --target RegistryHives,EventLogs,LNKFilesAndJumpLists,FileSystem,Prefetch,RecycleBin_InfoFiles,RecycleBin_DataFiles --tdest C:\DFIR\work\INC-2027-010\E01-W1\tdest --tflush
```

- `RegistryHives`: hive sistem dan hive pengguna beserta transaction log, untuk USB, TypedPaths, RecentDocs, ShellBags.
- `EventLogs`: semua `.evtx`, termasuk Security, System, Sysmon, dan `Microsoft-Windows-Partition/Diagnostic`.
- `LNKFilesAndJumpLists`: folder Recent tiap profil, termasuk `AutomaticDestinations` dan `CustomDestinations`.
- `FileSystem`: `$MFT`, `$J`, dan metafile lain untuk `C:`.
- `RecycleBin_InfoFiles` dan `RecycleBin_DataFiles`: berkas `$I` dan `$R` di `C:\$Recycle.Bin\`, termasuk isi folder `$R` [S5].
- `setupapi.dev.log` dan riwayat Edge (`G:\Users\arif.wicaksono\AppData\Local\Microsoft\Edge\User Data\Default\History`) disalin terpisah dari mount read-only ke folder kerja, lalu di-hash.

Keluaran ilustrasi (ringkas):

```
2027-01-12 09:25:41  Using Targets: RegistryHives,EventLogs,LNKFilesAndJumpLists,FileSystem,Prefetch,RecycleBin_InfoFiles,RecycleBin_DataFiles
2027-01-12 09:31:06  Copied 1,412 files (deferred: 0). Skipped (deduped): 3
```

Variabel yang dipakai ulang:

```powershell
$ez  = 'C:\DFIR\tools\EZTools-2026-10-15\net9'
$t   = 'C:\DFIR\work\INC-2027-010\E01-W1\tdest\G'       # nama subfolder volume cek di hasil KAPE
$out = '\\jkt-evid01\cases\INC-2027-010\analysis\E01-W1\EZ-2026.5.0'
```

**Cara membaca hasil:** dua fakta di case notes menentukan apa yang bisa dipercaya. Laptop mati sejak Kamis malam dan tidak dinyalakan sampai di-image, sehingga artefak terakhir di disk adalah artefak Arif, dan hampir tidak ada jejak responder di dalam image. Profil yang ada di image: `arif.wicaksono`, `Default`, `Public`; tidak ada profil akun IT atau responder yang dibuat setelah Jumat.

**Kapan gagal:** IT menyalakan laptop "untuk mengecek" sebelum ditahan. Satu kali boot menambah event, memperbarui hive, dan bisa mendorong record lama keluar dari `$J`. Bila itu terjadi, catat waktu dan siapa, lalu tandai semua artefak setelah waktu itu sebagai jejak pihak lain.

### 2.2 Pertanyaan, hipotesis, peta artefak, dan templat temuan

Pukul 09:20, sebelum membuka satu artefak pun, kamu menulis empat hipotesis dari bagian 1.8 di case notes dan memetakan tiap pertanyaan Dimas ke sumbernya. Tabel ini dipakai sebagai daftar kerja; kolom "Di luar laptop" menunjukkan apa yang harus diminta lewat lingkup memo Legal.

| Pertanyaan | Artefak di laptop (Day) | Di luar laptop |
|---|---|---|
| 1. Akses di luar pola | TypedPaths, ShellBags (10) | 5140 dan 5145 `JKT-FS01` di Splunk, daftar portofolio dari Kepala Divisi |
| 2. Berkas dibuka | LNK, Jump List, RecentDocs (10); 4688 dan Sysmon 1 `EXCEL.EXE` (05) | 5145 untuk berkas yang sama |
| 3. USB | USBSTOR, Properties, `MountedDevices`, Windows Portable Devices, `MountPoints2` (09); Partition/Diagnostic 1006; `setupapi.dev.log` | Defender `UsbDriveMounted`; daftar media terdaftar IT |
| 4. Penyalinan | LNK dan Jump List di volume flashdisk (10); `$MFT`, `$J` untuk salinan lokal (08); Recycle Bin (08) | Defender `DeviceFileEvents`; flashdisk itu sendiri bila nanti diperoleh secara sah |
| 5. Jalur lain | Riwayat Edge, klien OneDrive, Prefetch klien cloud (07) | Proxy, message trace Microsoft 365 (perlu izin terpisah), log penyedia |
| 6. Hapus jejak | Recycle Bin, `$J` `FileDelete`, 1102 dan 104, `EventRecordID` (05, 08); Prefetch alat pembersih (07) | Tidak ada |
| 7. Urutan dan keyakinan | Garis waktu kurasi (13) | Semua sumber di atas digabung ke garis waktu |

Templat temuan yang dipakai untuk setiap pertanyaan. Baris terakhir menjaga temuan tetap terhubung ke hipotesis.

```
# Temuan <n>: <judul singkat>

## Pertanyaan
<pertanyaan investigasi yang dijawab>

## Bukti
<artefak, lokasi, dan nilai konkret; sebut alat dan versinya; label zona waktu>

## Analisis
<apa yang ditunjukkan bukti, anak tangga yang dicapai, dan bagaimana artefak dikorelasikan>

## Keyakinan
Tinggi | Sedang | Rendah, dengan alasan

## Keterbatasan
<apa yang tidak dibuktikan, asumsi, data yang tidak tersedia, jendela waktu>

## Hipotesis yang terpengaruh
<H1/H2/H3/H4 mana yang didukung, dilemahkan, atau tidak terpengaruh>
```

### 2.3 Pola akses dari log `JKT-FS01` dan artefak navigasi (Temuan 1)

Langkah ini menjawab pertanyaan pertama Dimas. Daftar portofolio account manager diterima dari Surya Atmaja Selasa 10:10 dan dimuat sebagai lookup `jab_portofolio_am.csv` (kolom `kode`, `account_manager`); Arif memegang 11 dari 64 pelanggan yang berkas harga kontraknya ada di `\\JKT-FS01\Enterprise-Sales\Harga-Kontrak\2026\`.

**Tujuan:** menghitung akses akun Arif ke berkas harga kontrak, dipisah per portofolio, untuk jendela baseline dan jendela 4 sampai 7 Januari.

```
index=wineventlog host=JKT-FS01 EventCode=5145 Account_Name="arif.wicaksono"
    Share_Name="\\\\*\\Enterprise-Sales" Relative_Target_Name="Harga-Kontrak\\2026\\HK-2026-*"
    earliest="10/05/2026:00:00:00" latest="01/08/2027:00:00:00"
| rex field=Relative_Target_Name "HK-2026-(?<kode>[A-Z]{4})\.xlsx$"
| lookup jab_portofolio_am.csv kode OUTPUT account_manager
| eval portofolio=if(account_manager=="arif.wicaksono","sendiri","lain")
| eval periode=if(_time<strptime("2027-01-04","%Y-%m-%d"),"baseline","jan4-7")
| eval hari=strftime(_time,"%Y-%m-%d")
| stats count AS event dc(kode) AS berkas dc(hari) AS hari by periode portofolio
```

- `EventCode=5145` dan `Share_Name`: hanya pemeriksaan akses per objek di share `Enterprise-Sales` [S2]; backslash di nilai pencarian ditulis ganda.
- `Relative_Target_Name`: path relatif berkas terhadap share; filter ke berkas harga kontrak 2026.
- `earliest` dan `latest` absolut: 5 Oktober 2026 sampai sebelum 8 Januari 2027. Baseline adalah 13 minggu penuh sebelum 4 Januari (5 Oktober sampai 3 Januari, 91 hari), di dalam retensi 180 hari index `wineventlog` dan di dalam lingkup memo Legal (sejak 1 Oktober).
- `rex` mengambil kode pelanggan empat huruf; `lookup` menambahkan pemilik portofolio; baris tanpa pasangan di lookup jatuh ke "lain" dan harus diperiksa manual.
- `stats`: jumlah event, jumlah berkas berbeda, dan jumlah hari, per periode dan portofolio.

Keluaran ilustrasi (Splunk, WIB):

```
periode   portofolio  event  berkas  hari
baseline  sendiri        41       9    17
jan4-7    lain          103      14     2
jan4-7    sendiri        58      11     2
```

Rincian per hari untuk portofolio "lain" (kueri sama, `stats ... by hari kode`, diringkas):

```
hari        berkas  event  pertama    terakhir   kode
2027-01-04      14     96  16:42:05   17:06:40   SMLC 12, ADPT 11, BRKS 10, PLMA 10, TKMD 10, RJWL 9, NSCP 5,
                                                 CKRW 4, DMNS 4, HRMN 5, JYKT 4, MKRS 4, PSDN 4, SRYA 4
2027-01-06       7      7  15:12:31   15:12:39   SMLC, ADPT, BRKS, NSCP, PLMA, RJWL, TKMD (masing-masing 1)
```

Pembanding untuk daftar PIC (`Kontak-PIC\Daftar-PIC-Korporat-2026.xlsx`): baseline 5 event di 2 hari (2026-10-12 dan 2026-11-30), lalu 1 event Rabu 2027-01-06 15:12:39. Satu kueri lagi untuk penulisan (`Accesses` memuat `WriteData`) menunjukkan Selasa 2027-01-05 10:05:12 sampai 10:09:47 akun Arif menulis 214 berkas ke `Serah-Terima\arif.wicaksono\`: 11 berkas harga kontrak portofolionya dan folder `Akun` berisi 203 berkas untuk 11 pelanggan yang sama. Selain itu, 5145 dari akun `adm.yoga` Selasa 2027-01-12 13:20 sampai 13:24 membaca 19 berkas asli untuk perbandingan hash (bagian 2.6); baris itu dilabeli responder.

Di laptop, artefak navigasi menguatkan cara aksesnya. RECmd dengan batch DFIRBatch atas `NTUSER.DAT` Arif (cara menjalankannya sama seperti Day 10 bagian 2.5) memberi:

```
Key (NTUSER arif.wicaksono)                          Value  Data                                               LastWrite (UTC)
...\Explorer\TypedPaths                              url1   \\JKT-FS01\Enterprise-Sales\Harga-Kontrak\2026      2027-01-04 09:41:22
```

SBECmd atas `NTUSER.DAT` dan `UsrClass.dat` Arif (ringkas, waktu UTC, LastInteracted adalah inferensi parser):

```
AbsolutePath                                                      LastInteracted (UTC)
\\JKT-FS01\Enterprise-Sales\Harga-Kontrak\2026                     2027-01-04 09:41:30
\\JKT-FS01\Enterprise-Sales\Serah-Terima\arif.wicaksono            2027-01-05 03:05:01
C:\Users\arif.wicaksono\Documents\Kontrak-Ref                      2027-01-07 12:29:58
```

**Cara membaca hasil:**

- Dalam 91 hari baseline, akun Arif hanya menyentuh berkas harga milik portofolionya sendiri (9 dari 11 berkas, 41 event, 17 hari kerja), semuanya di jam kerja. Nol event ke berkas portofolio lain.
- Senin 2027-01-04 pukul 16:41:22 WIB path folder harga diketik langsung di address bar Explorer (TypedPaths, navigasi sengaja), lalu dalam 25 menit (16:42:05 sampai 17:06:40) akun Arif menyentuh 14 berkas harga milik portofolio lain, 96 event. Rabu sore 7 dari 14 berkas itu dibaca lagi, satu event per berkas dalam delapan detik, bersama 11 berkas portofolio sendiri dan daftar PIC; pola satu event per berkas dalam hitungan detik cocok dengan penyalinan, yang dikonfirmasi di bagian 2.6.
- Selasa pagi ada pekerjaan serah terima yang terlihat jelas: 214 berkas ditulis ke folder serah terima di share. Ini akses tidak biasa yang sah, dan dicatat untuk H2.
- 5145 tidak membedakan berkas yang dibuka di Excel dari berkas yang hanya ditampilkan di panel preview Explorer (bagian 1.3). Itu dijawab di bagian 2.4.

**Temuan 1 (ringkas):** akun Arif mengakses 14 berkas harga kontrak milik portofolio account manager lain pada Senin 2027-01-04 16:42 sampai 17:06 WIB, setelah mengetik path folder harga di Explorer, dan 7 di antaranya lagi pada Rabu 2027-01-06 15:12 WIB; selama 91 hari sebelumnya akun itu tidak pernah mengakses berkas portofolio lain. Keyakinan tinggi (log file server dan artefak laptop sepakat). Keterbatasan: pola dihitung dari 91 hari log yang tersedia; daftar portofolio adalah keterangan Kepala Divisi per 12 Januari; akses itu sendiri tidak membuktikan penyalinan. Hipotesis: tidak membedakan H1 dari H2 untuk berkas portofolio sendiri; untuk berkas portofolio lain, H2 perlu penjelasan tambahan (bagian 2.8).

**Variasi:** ulangi kueri untuk semua account manager tim (tanpa filter `Account_Name`) dan hitung berapa akun yang pernah mengakses berkas portofolio lain dalam baseline. Bila ternyata lazim (misalnya analis pricing atau atasan), kalimat "di luar pola" harus menyebut pola akun Arif sendiri, bukan pola tim.

**Kapan gagal:** subkategori Detailed File Share tidak aktif di file server, sehingga 5145 tidak ada; tulis sebagai keterbatasan dan andalkan 5140 (sekali per sesi, tanpa nama berkas [S1]) serta artefak laptop. Atau baseline dihitung dari jendela yang lebih pendek dari yang ditulis karena retensi index sudah memotong data lama.

### 2.4 Berkas yang dibuka: LNK, Jump List, dan 4688 (Temuan 2)

Langkah ini menjawab pertanyaan kedua Dimas: dari 14 berkas yang disentuh Senin, mana yang benar-benar dibuka di aplikasi, dan adakah yang dibuka dari lokasi lain.

```powershell
& "$ez\LECmd.exe" -d "$t\Users\arif.wicaksono\AppData\Roaming\Microsoft\Windows\Recent" --csv "$out\UserActivity" --csvf E01-W1_LNK_arif.csv -q
& "$ez\LECmd.exe" -d "$t\Users\arif.wicaksono\AppData\Roaming\Microsoft\Windows\Recent" -r --csv "$out\UserActivity" --csvf E01-W1_LNK_arif_removable.csv -q
& "$ez\JLECmd.exe" -d "$t\Users\arif.wicaksono\AppData\Roaming\Microsoft\Windows\Recent" --csv "$out\UserActivity" --csvf E01-W1_JL_arif.csv -q
```

- `-d`: folder Recent diproses rekursif; LECmd mengambil `*.lnk`, JLECmd mengambil berkas Jump List.
- `-r`: hanya LNK yang menunjuk drive removable, filter pertama untuk kasus pencurian data.
- `--csv` dan `--csvf`: folder dan nama CSV; `-q` mempercepat ekspor.

Keluaran ilustrasi LECmd, LNK yang dibuat atau diperbarui 4 sampai 7 Januari dan menunjuk berkas harga atau daftar PIC (UTC; kolom diringkas):

```
SourceFile               : HK-2026-SMLC.xlsx.lnk
SourceCreated/Modified   : 2027-01-04 09:43:13 / 2027-01-04 09:43:13
NetworkPath              : \\JKT-FS01\Enterprise-Sales\Harga-Kontrak\2026\HK-2026-SMLC.xlsx
TargetModified           : 2026-11-19 07:03:23
FileSize                 : 68096
DriveType                : (target jaringan, tanpa VolumeID)

SourceFile               : HK-2026-SMLC (2).xlsx.lnk
SourceCreated/Modified   : 2027-01-07 12:33:48 / 2027-01-07 12:33:48
LocalPath                : E:\JAB\Kontrak-Ref\HK-2026-SMLC.xlsx
TargetCreated            : 2027-01-07 12:31:12
TargetModified           : 2026-11-19 07:03:24
FileSize                 : 68096
DriveType                : Removable storage media (Floppy, USB)
VolumeSerialNumber       : 5A1C0E37
VolumeLabel              : KINGSTON
MachineID                : jkt-ws-0516

SourceFile               : Daftar-PIC-Korporat-2026 (2).xlsx.lnk
SourceCreated/Modified   : 2027-01-07 12:36:03 / 2027-01-07 12:36:03
LocalPath                : E:\JAB\Kontrak-Ref\Daftar-PIC-Korporat-2026.xlsx
TargetCreated            : 2027-01-07 12:31:14
TargetModified           : 2026-12-28 03:15:42
FileSize                 : 1187840
DriveType                : Removable storage media (Floppy, USB)
VolumeSerialNumber       : 5A1C0E37
VolumeLabel              : KINGSTON
```

Selain itu ada lima LNK lain dari share untuk Senin: `HK-2026-ADPT.xlsx.lnk` 09:46:31, `HK-2026-BRKS.xlsx.lnk` 09:49:06, `HK-2026-PLMA.xlsx.lnk` 09:52:48, `HK-2026-RJWL.xlsx.lnk` 10:01:59, dan `HK-2026-TKMD.xlsx.lnk` 10:05:22 UTC (16:46:31 sampai 17:05:22 WIB). LNK `Daftar-PIC-Korporat-2026.xlsx.lnk` yang pertama (dari share) terakhir diperbarui 2026-11-30, cocok dengan baseline 5145.

Keluaran ilustrasi JLECmd, item Jump List Excel yang dipakai sejak 4 Januari (UTC; nilai `AppId` lihat di CSV-mu):

```
AppIdDescription  Path                                                              MRU  Count  LastModified (UTC)   VolumeSerialNumber
Microsoft Excel   E:\JAB\Kontrak-Ref\Daftar-PIC-Korporat-2026.xlsx                  0    1      2027-01-07 12:36:03  5A1C0E37
Microsoft Excel   E:\JAB\Kontrak-Ref\HK-2026-SMLC.xlsx                              1    1      2027-01-07 12:33:48  5A1C0E37
Microsoft Excel   \\JKT-FS01\Enterprise-Sales\Harga-Kontrak\2026\HK-2026-TKMD.xlsx  2    1      2027-01-04 10:05:22
Microsoft Excel   \\JKT-FS01\Enterprise-Sales\Harga-Kontrak\2026\HK-2026-RJWL.xlsx  3    1      2027-01-04 10:01:59
Microsoft Excel   \\JKT-FS01\Enterprise-Sales\Harga-Kontrak\2026\HK-2026-PLMA.xlsx  4    1      2027-01-04 09:52:48
Microsoft Excel   \\JKT-FS01\Enterprise-Sales\Harga-Kontrak\2026\HK-2026-BRKS.xlsx  5    1      2027-01-04 09:49:06
Microsoft Excel   \\JKT-FS01\Enterprise-Sales\Harga-Kontrak\2026\HK-2026-ADPT.xlsx  6    1      2027-01-04 09:46:31
Microsoft Excel   \\JKT-FS01\Enterprise-Sales\Harga-Kontrak\2026\HK-2026-SMLC.xlsx  7    1      2027-01-04 09:43:13
```

Lalu event log, untuk pembukaan dari flashdisk (EvtxECmd atas Security dan Sysmon, filter `EXCEL.EXE`, Kamis):

```
TimeCreated (UTC)     EventId  Channel  ProcessId  CommandLine (diringkas)
2027-01-07 12:33:46   4688     Security 0x1CB0     "...\Office16\EXCEL.EXE" ... "E:\JAB\Kontrak-Ref\HK-2026-SMLC.xlsx"
2027-01-07 12:33:46   1        Sysmon   7344       "...\Office16\EXCEL.EXE" ... "E:\JAB\Kontrak-Ref\HK-2026-SMLC.xlsx"
```

**Cara membaca hasil:**

- Dari 14 berkas portofolio lain yang disentuh Senin, enam dibuka di Excel (SMLC, ADPT, BRKS, PLMA, RJWL, TKMD), terlihat sepakat di LNK dan Jump List. Delapan sisanya hanya muncul di 5145 dengan 4 sampai 5 event, pola yang lebih cocok dengan preview atau penelusuran folder daripada pembukaan di Excel.
- Kamis malam, dua berkas dibuka dari `E:\JAB\Kontrak-Ref\` di volume removable berlabel `KINGSTON` dengan VSN `5A1C0E37` (ditampilkan `vol` sebagai `5A1C-0E37`): `HK-2026-SMLC.xlsx` 19:33:48 WIB dan `Daftar-PIC-Korporat-2026.xlsx` 19:36:03 WIB. Ukuran keduanya sama persis dengan berkas di share (68.096 dan 1.187.840 byte).
- 4688 dan Sysmon 1 pukul 19:33:46 WIB menunjukkan Excel dijalankan dengan path berkas SMLC di `E:`, PID 7344 (`0x1CB0`). Daftar PIC dibuka di proses Excel yang sama, sehingga tidak ada 4688 baru untuknya (bagian 1.4).
- Nama LNK kedua berakhiran `(2)` karena berkas bernama sama sudah punya LNK dari pembukaan Senin. Apakah build-mu membuat LNK kedua atau menimpa yang lama saat berkas bernama sama dibuka dari lokasi berbeda, cek di lab; Jump List tetap menyimpan kedua path sebagai item terpisah, sehingga ia korroborasi yang lebih tahan.
- `TargetModified` berkas SMLC di `E:` (07:03:24) satu detik berbeda dari berkas di share (07:03:23). Itu konsisten dengan resolusi waktu tulis FAT 2 detik [S6], bukan tanda berkasnya berbeda.

**Temuan 2 (ringkas):** enam berkas harga kontrak portofolio lain dibuka di Excel dari share Senin 2027-01-04 16:43 sampai 17:05 WIB; Kamis 2027-01-07 berkas `HK-2026-SMLC.xlsx` (19:33:48 WIB) dan `Daftar-PIC-Korporat-2026.xlsx` (19:36:03 WIB) dibuka dari `E:\JAB\Kontrak-Ref\` di volume removable `KINGSTON` VSN `5A1C-0E37`, dengan ukuran sama dengan berkas di share. Keyakinan tinggi untuk pembukaan. Keterbatasan: LNK dan Jump List tidak membuktikan apa yang dilakukan setelah berkas dibuka; kesamaan nama dan ukuran tidak membuktikan isi identik.

**Variasi:** jalankan JLECmd dengan `--dumpTo` untuk mengekspor LNK yang tertanam di Jump List bila LNK di Recent sudah hilang [S5], lalu proses dengan LECmd.

**Kapan gagal:** `TargetModified` dibaca sebagai waktu berkas dibuka, atau `SourceAccessed` dipakai sebagai waktu akses padahal pembaruan last access di laptop Windows 11 dengan SSD biasanya mati (`NtfsDisableLastAccessUpdate` `0x80000003`; baca nilainya dari hive SYSTEM seperti di Day 08 bagian 1.2).

### 2.5 Perangkat USB: rantai dari serial ke VSN (Temuan 3)

Langkah ini menjawab pertanyaan ketiga Dimas. RECmd dengan DFIRBatch atas hive SYSTEM, SOFTWARE, dan NTUSER Arif, lalu ambil baris kategori Devices (cara sama dengan Day 09 bagian 2.5):

```powershell
& "$ez\RECmd\RECmd.exe" -d "$t\Windows\System32\config" --bn "$ez\RECmd\BatchExamples\DFIRBatch.reb" --csv "$out\Registry" --csvf E01-W1_RECmd_sys.csv
$r = Import-Csv "$out\Registry\E01-W1_RECmd_sys.csv"
$r | Where-Object Category -eq 'Devices' | Select-Object Description, KeyPath, ValueName, ValueData, LastWriteTimestamp
```

- `-d` ke folder `config`: SYSTEM dan SOFTWARE; jalankan sekali lagi untuk `NTUSER.DAT` Arif supaya `MountPoints2` ikut.
- `--bn DFIRBatch.reb`: batch yang memuat plugin USBSTOR, USB, SCSI, WindowsPortableDevices, VolumeInfoCache, dan MountedDevices.

Keluaran ilustrasi, disusun ulang dari file detail plugin (waktu properti UTC, WIB di kurung):

```
[A] Enum\USBSTOR\Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP\0019E06B4A21C5F0A7&0
    Label volume (WPD FriendlyName): KINGSTON          Volume GUID: {3c8e5b1a-...}
    0065 FirstInstall   2027-01-04 09:58:10   (Senin 16:58:10)
    0064 Install        2027-01-04 09:58:10
    0066 LastArrival    2027-01-07 12:26:41   (Kamis 19:26:41)
    0067 LastRemoval    2027-01-07 12:52:18   (Kamis 19:52:18)

MountedDevices: \DosDevices\E:          -> _??_USBSTOR#Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP#0019E06B4A21C5F0A7&0#{53f56307-...}
                \??\Volume{3c8e5b1a-...} -> sama
Enum\SCSI: tidak ada perangkat penyimpanan eksternal
EMDMgmt: key tidak ada
```

```
arif.wicaksono  ...\Explorer\MountPoints2\{3c8e5b1a-...}   LastWrite 2027-01-07 12:26:44   (Kamis 19:26:44)
```

`setupapi.dev.log` (waktu lokal, WIB):

```
>>>  [Device Install (Hardware initiated) - USBSTOR\Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP\0019E06B4A21C5F0A7&0]
>>>  Section start 2027/01/04 16:58:09.882
```

Event 1006 dari channel `Microsoft-Windows-Partition/Diagnostic` (EvtxECmd; kolom payload diringkas, nama kolom cek di map versi-mu):

```
TimeCreated (UTC)     Manufacturer  Model             SerialNumber          Capacity       Vbr0
2027-01-04 09:58:10   Kingston      DataTraveler 3.0  0019E06B4A21C5F0A7    31004295168    (512 byte)
2027-01-04 10:01:44   Kingston      DataTraveler 3.0  0019E06B4A21C5F0A7    0              (kosong)
2027-01-07 12:26:41   Kingston      DataTraveler 3.0  0019E06B4A21C5F0A7    31004295168    (512 byte)
2027-01-07 12:52:18   Kingston      DataTraveler 3.0  0019E06B4A21C5F0A7    0              (kosong)
```

VSN dibaca dari `Vbr0` dengan PowerShell 7 (volume FAT32, offset `0x43`, 4 byte little-endian [S9]):

```powershell
$b = [Convert]::FromHexString($vbr0Hex)      # $vbr0Hex: isi Vbr0 dari kolom payload, sebagai teks heksadesimal
'{0:X2}{1:X2}-{2:X2}{3:X2}' -f $b[0x46], $b[0x45], $b[0x44], $b[0x43]
```

- `[Convert]::FromHexString`: mengubah teks heksadesimal menjadi array byte (tersedia di PowerShell 7).
- Byte `0x43` sampai `0x46` dibaca terbalik karena little-endian; untuk NTFS pakai `0x48`, untuk exFAT `0x64` [S9].

Keluaran ilustrasi untuk kedua event bertanda sambung: `5A1C-0E37`.

Terakhir, sumber di luar host. Kueri advanced hunting (waktu UTC):

```
DeviceEvents
| where Timestamp between (datetime(2027-01-03 17:00:00) .. datetime(2027-01-08 17:00:00))
| where DeviceName startswith "jkt-ws-0516"
| where ActionType == "UsbDriveMounted"
| extend af = parse_json(AdditionalFields)
| project Timestamp, ActionType, DriveLetter = tostring(af.DriveLetter), Manufacturer = tostring(af.Manufacturer),
          ProductName = tostring(af.ProductName), SerialNumber = tostring(af.SerialNumber)
```

- Rentang `2027-01-03 17:00` sampai `2027-01-08 17:00` UTC sama dengan Senin 00:00 sampai Sabtu 00:00 WIB; advanced hunting memakai UTC untuk kueri [S11].
- Kunci `DriveLetter`, `Manufacturer`, `ProductName`, dan `SerialNumber` di `AdditionalFields` mengikuti kueri komunitas [S17]; cek isi JSON-nya di tenant-mu.

Keluaran ilustrasi:

```
Timestamp (UTC)       ActionType       DriveLetter  Manufacturer  ProductName       SerialNumber
2027-01-04 09:58:12   UsbDriveMounted  E:           Kingston      DataTraveler 3.0  0019E06B4A21C5F0A7
```

Kueri pembanding untuk event terakhir apa pun dari perangkat ini:

```
union DeviceProcessEvents, DeviceNetworkEvents, DeviceFileEvents, DeviceEvents, DeviceLogonEvents
| where Timestamp > datetime(2027-01-03 17:00:00)
| where DeviceName startswith "jkt-ws-0516"
| summarize LastEvent = max(Timestamp)
```

Keluaran ilustrasi: `LastEvent` 2027-01-07 10:38:31 UTC (Kamis 17:38:31 WIB).

**Cara membaca hasil:**

- Satu-satunya perangkat penyimpanan USB di laptop ini adalah Kingston DataTraveler 3.0 dengan serial `0019E06B4A21C5F0A7`. Karakter keduanya bukan `&`, jadi serial berasal dari perangkat, dan serial yang sama tercatat di registry, di event 1006, dan di Defender.
- Flashdisk pertama kali dicolok Senin 2027-01-04 16:58:10 WIB (`0065`, `setupapi.dev.log` 16:58:09.882 waktu lokal, event 1006, Defender 16:58:12) dan dilepas 17:01:44. Sesi kedua dan terakhir Kamis 2027-01-07 19:26:41 sampai 19:52:18 WIB (`0066`, `0067`, event 1006). Registry hanya menyimpan sesi terakhir; sesi Senin diketahui dari event 1006 dan Defender. Untuk perangkat ini `0064` sama dengan `0065`, karena driver belum pernah diperbarui.
- Kedua sesi memakai huruf `E:` dan volume yang sama. `MountPoints2` di profil Arif diperbarui Kamis 19:26:44, tiga detik setelah kedatangan: volume di-mount di sesi profil Arif.
- Jembatan VSN ke serial: event 1006 memuat serial perangkat dan boot record dengan VSN `5A1C-0E37` dalam satu event, sama dengan VSN di LNK dan Jump List (`5A1C0E37`). Jembatan kedua: label `KINGSTON` di LNK sama dengan `FriendlyName` perangkat, dan `E:` di LNK sama dengan pemetaan `MountedDevices` ke serial itu pada sesi yang sama. Dua jembatan independen lebih kuat daripada satu.
- Defender hanya punya sesi Senin. Event terakhir dari laptop di portal adalah Kamis 17:38:31 WIB, saat Arif masih di kantor; sesi Kamis malam tidak ada di Defender sama sekali (penyebabnya di bagian 2.6).
- Sesi Senin hanya 3 menit 34 detik. ShellBags memperlihatkan root `E:\` dibuka pukul 16:58:31 dan satu subfolder yang namanya menunjukkan isi pribadi; nama itu dicatat di case notes sebagai keberadaan dan tidak dianalisis (bagian 1.2). Tidak ada `E:\JAB` di ShellBags sebelum Kamis.

**Temuan 3 (ringkas):** flashdisk Kingston DataTraveler 3.0 serial `0019E06B4A21C5F0A7`, volume FAT32 label `KINGSTON` VSN `5A1C-0E37`, tersambung ke `JKT-WS-0516` dua kali, Senin 2027-01-04 16:58:10 sampai 17:01:44 WIB dan Kamis 2027-01-07 19:26:41 sampai 19:52:18 WIB, keduanya sebagai `E:` dan di-mount di sesi profil `arif.wicaksono`. Keyakinan tinggi. Keterbatasan: `MountPoints2` menunjuk sesi profil, bukan orang yang memegang flashdisk; registry dan event log tidak membuktikan berkas disalin.

**Variasi:** bila event 1006 tidak ada (log sudah berputar atau dikosongkan pembaruan besar Windows [S9]), jembatan tinggal label, huruf drive, dan waktu. Tulis keyakinan rantai menjadi sedang dan sebutkan alasannya.

**Kapan gagal:** VSN di LNK disamakan dengan serial USBSTOR; `0064` dipakai sebagai waktu pertama dicolok; atau kueri hanya membaca USBSTOR sehingga SSD eksternal UASP di `Enum\SCSI` terlewat (Day 09 bagian 1.5).

### 2.6 Bukti penyalinan: salinan lokal yang terbukti, salinan di flashdisk yang disimpulkan (Temuan 4)

Langkah ini menjawab pertanyaan keempat Dimas, titik paling halus kasus ini. Pertanyaannya dipecah dua: bagaimana berkas sampai ke folder lokal `Kontrak-Ref`, dan bagaimana sampai ke flashdisk.

Pertama, salinan dari share ke laptop. MFTECmd atas `$J` dan `$MFT`:

```powershell
& "$ez\MFTECmd.exe" -f "$t\`$Extend\`$J" -m "$t\`$MFT" --csv "$out\FileSystem" --csvf E01-W1_J.csv
& "$ez\MFTECmd.exe" -f "$t\`$MFT" --csv "$out\FileSystem" --csvf E01-W1_MFT.csv
Import-Csv "$out\FileSystem\E01-W1_J.csv" | Where-Object { $_.ParentPath -like '*Kontrak-Ref*' -or $_.Name -eq 'Kontrak-Ref' } |
  Select-Object UpdateTimestamp, Name, UpdateReasons
```

- `-f` ke `$J` dengan `-m` ke `$MFT`: MFTECmd melengkapi path induk dari `$MFT` (Day 08 bagian 2.4); backtick meng-escape `$` di PowerShell.
- Filter ke folder `Kontrak-Ref` dan isinya.

Keluaran ilustrasi (UTC, ringkas):

```
UpdateTimestamp (UTC)   Name                              UpdateReasons
2027-01-06 08:12:05     Kontrak-Ref                       FileCreate
2027-01-06 08:12:31     HK-2026-ADPT.xlsx                 FileCreate|DataExtend|Close
...                     (19 berkas, 08:12:31 sampai 08:12:40)
2027-01-06 08:12:40     Daftar-PIC-Korporat-2026.xlsx     FileCreate|DataExtend|Close
2027-01-07 12:55:40     Kontrak-Ref                       RenameOldName
2027-01-07 12:55:40     $RQ7M2KD                          RenameNewName
2027-01-07 12:55:40     $IQ7M2KD                          FileCreate|DataExtend|Close
```

Defender mencatat kejadian yang sama karena laptop sedang di kantor dan tersambung (advanced hunting, UTC):

```
DeviceFileEvents
| where Timestamp between (datetime(2027-01-03 17:00:00) .. datetime(2027-01-08 17:00:00))
| where DeviceName startswith "jkt-ws-0516"
| where FolderPath startswith @"C:\Users\arif.wicaksono\Documents\Kontrak-Ref" or FolderPath startswith @"E:\"
| summarize Baris = count(), Mulai = min(Timestamp), Selesai = max(Timestamp), Proses = make_set(InitiatingProcessFileName)
    by Lokasi = iff(FolderPath startswith @"E:\", "E:", "Kontrak-Ref"), ActionType
```

Keluaran ilustrasi:

```
Lokasi       ActionType   Baris  Mulai (UTC)          Selesai (UTC)        Proses
Kontrak-Ref  FileCreated  19     2027-01-06 08:12:31  2027-01-06 08:12:40  ["explorer.exe"]
```

Lalu Recycle Bin dengan RBCmd:

```powershell
& "$ez\RBCmd.exe" -d "$t\`$Recycle.Bin" --csv "$out\FileDeletion" --csvf E01-W1_RB.csv
```

Keluaran ilustrasi (UTC):

```
SourceName                                                            FileName                                        FileSize  DeletedOn (UTC)
...\S-1-5-21-2847193650-1938475021-3765120984-6230\$IQ7M2KD           C:\Users\arif.wicaksono\Documents\Kontrak-Ref   2209792   2027-01-07 12:55:40
   isi $RQ7M2KD: 19 berkas (18 HK-2026-*.xlsx, 1 Daftar-PIC-Korporat-2026.xlsx)
```

Perbandingan isi: SHA-256 dihitung untuk 19 berkas di `$RQ7M2KD` dari salinan kerja, dan Yoga menghitung SHA-256 19 berkas asli di share Selasa 13:20 sampai 13:24 dengan akun `adm.yoga` (jejak responder di 5145, bagian 2.3).

```powershell
$rb  = Get-ChildItem "$t\`$Recycle.Bin\S-1-5-21-2847193650-1938475021-3765120984-6230\`$RQ7M2KD" -File | Get-FileHash -Algorithm SHA256
$asl = Import-Csv '\\jkt-evid01\cases\INC-2027-010\analysis\share-asli\hash-19-asli.csv'     # kolom Name, Hash
Compare-Object $rb $asl -Property Hash -IncludeEqual | Group-Object SideIndicator | Select-Object Name, Count
```

Keluaran ilustrasi: satu kelompok `==` dengan `Count` 19.

Ringkasan 19 berkas (ukuran dari `$MFT`, cocok dengan `$R`):

| Kelompok | Berkas | Byte |
|---|---|---|
| Harga kontrak portofolio Arif | 11 | 611.328 |
| Harga kontrak portofolio lain (SMLC, ADPT, BRKS, NSCP, PLMA, RJWL, TKMD) | 7 | 410.624 |
| Daftar PIC pelanggan korporat | 1 | 1.187.840 |
| Jumlah | 19 | 2.209.792 |

Sekarang sisi flashdisk. Di event log System dan WLAN-AutoConfig (EvtxECmd, UTC):

```
TimeCreated (UTC)     Channel / EventId                       Isi
2027-01-07 10:38:47   WLAN-AutoConfig 8003                    terputus dari JAB-Corp
2027-01-07 10:39:10   System, Kernel-Power 42                 masuk tidur
2027-01-07 12:24:03   System, Power-Troubleshooter 1          bangun
2027-01-07 12:24:15   Security 4624 type 7                    unlock JAB\arif.wicaksono
(tidak ada WLAN-AutoConfig 8001 atau perubahan NetworkList sampai shutdown)
2027-01-07 14:47:12   System 1074                             shutdown oleh JAB\arif.wicaksono
2027-01-07 14:47:30   System 6006                             Event Log service berhenti; tidak ada event setelahnya
```

**Cara membaca hasil:**

- Salinan lokal terbukti. Rabu 2027-01-06 15:12:05 WIB folder `Documents\Kontrak-Ref` dibuat, lalu 15:12:31 sampai 15:12:40 sembilan belas berkas lahir di sana oleh `explorer.exe`, pada detik yang sama dengan 5145 di `JKT-FS01` (bagian 2.3). Tiga sumber independen (`$J`, Defender, log file server) sepakat. Isi salinan lokal identik dengan berkas asli di share: 19 dari 19 hash sama.
- Folder lokal itu dipindah ke Recycle Bin Kamis 19:55:40 WIB, tiga menit setelah flashdisk dilepas, oleh profil Arif. Recycle Bin tidak dikosongkan, sehingga isinya masih utuh.
- Laptop tidak tersambung ke jaringan mana pun dari Kamis 17:38:47 WIB sampai dimatikan 21:47:12. Advanced hunting hanya menerima data setelah sensor berhasil mengirimkannya [S11], dan laptop tidak pernah tersambung lagi setelah itu, sehingga sesi flashdisk Kamis malam tidak ada di Defender. Apakah sensor menyimpan data yang belum terkirim di disk tidak ditetapkan dan tidak diperiksa di kasus ini. Alasan laptop tidak tersambung tidak terlihat di artefak dan tidak ditafsirkan.
- Penyalinan ke flashdisk tidak langsung. Yang ada: dua berkas di `E:\JAB\Kontrak-Ref\` dengan nama dan ukuran sama dengan berkas di folder lokal, `TargetCreated` Kamis 19:31:12 dan 19:31:14 WIB (empat menit setelah flashdisk dicolok, saat folder lokal masih ada dan sesi Arif aktif), dan `TargetModified` yang sama dengan waktu modifikasi berkas asal dalam resolusi FAT. ShellBags menunjukkan `Documents\Kontrak-Ref` dilihat 19:29:58, lalu `E:\JAB` 19:31:05 dan `E:\JAB\Kontrak-Ref` 19:33:40. Nama folder tujuan sama dengan folder lokal. Polanya cocok dengan penyalinan folder `Kontrak-Ref` ke `E:\JAB\` lewat Explorer sekitar 19:31.
- Yang tidak terlihat sama sekali: 17 berkas lain di flashdisk. Tidak ada LNK, Jump List, atau sumber lain yang menunjuk berkas itu di `E:`, karena tidak dibuka dari sana. USN laptop tidak membantu: penyalinan ke `E:` hanya membaca `C:`. Audit Removable Storage tidak aktif di `JAB-WS-Audit` [S10], dan konfigurasi Sysmon tidak mencatat dokumen Office di media lepasan.

**Temuan 4 (ringkas):**

- **Terbukti:** 19 berkas (11 harga portofolio Arif, 7 harga portofolio lain, daftar PIC; 2.209.792 byte) disalin dari share ke `C:\Users\arif.wicaksono\Documents\Kontrak-Ref\` Rabu 2027-01-06 15:12 WIB, isinya identik dengan berkas asli. Dua berkas bernama dan berukuran sama (`HK-2026-SMLC.xlsx`, `Daftar-PIC-Korporat-2026.xlsx`) berada di `E:\JAB\Kontrak-Ref\` di volume `KINGSTON` VSN `5A1C-0E37` milik flashdisk serial `0019E06B4A21C5F0A7`, tercatat dibuat di volume itu Kamis 19:31:12 dan 19:31:14 WIB, dan dibuka dari sana 19:33 dan 19:36 WIB di sesi profil Arif.
- **Disimpulkan:** kedua berkas di flashdisk adalah salinan dari folder lokal, dan seluruh folder `Kontrak-Ref` (19 berkas) kemungkinan disalin ke `E:\JAB\` sekitar 19:31 WIB. Kesimpulan pertama wajar karena nama, ukuran, waktu modifikasi, dan urutan konsisten; kesimpulan kedua lebih lemah karena 17 berkas lain tidak meninggalkan artefak di laptop.
- **Tidak bisa disimpulkan:** isi berkas di flashdisk, apakah berkas masih ada di flashdisk, ke mana flashdisk dibawa, siapa yang menerima isinya, dan niat.
- **Keyakinan:** tinggi untuk salinan lokal; sedang untuk dua berkas di flashdisk; rendah untuk 17 berkas lain di flashdisk.

**Variasi:** bila flashdisk kelak diserahkan secara sah, image flashdisk dan hash isinya dibandingkan dengan 19 hash berkas asli. Itu satu-satunya cara menaikkan keyakinan penyalinan ke flashdisk menjadi tinggi.

**Kapan gagal:** kalimat "19 berkas terbukti disalin ke flashdisk" ditulis karena salinan lokal terbukti; atau ketiadaan baris Defender untuk `E:` dibaca sebagai "tidak ada yang ditulis ke flashdisk" padahal laptop tidak tersambung saat itu.

### 2.7 Jalur lain dan hapus jejak (Temuan 5 dan 6)

Langkah ini menjawab pertanyaan kelima dan keenam Dimas, dan sebagian besar hasilnya negatif. Hasil negatif ditulis bersama cakupannya.

**Proxy.** Kueri Splunk index `proxy` (retensi 30 hari; waktu WIB):

```
index=proxy src_ip=10.10.51.16 earliest="01/04/2027:00:00:00" latest="01/09/2027:00:00:00"
| where match(category,"(?i)web-based email|file sharing|online storage")
| stats count AS sesi min(_time) AS mulai max(_time) AS selesai sum(bytes_out) AS kirim sum(bytes_in) AS terima by dest_host category
| convert ctime(mulai) ctime(selesai)
```

- `src_ip=10.10.51.16`: alamat laptop di jaringan kantor; trafik dari jaringan rumah tidak lewat proxy PT JAB.
- `match(category, ...)`: hanya kategori email berbasis web, berbagi berkas, dan penyimpanan online; nama kategori cek di proxy-mu.
- `sum(bytes_out)`: volume yang dikirim laptop, satu-satunya indikasi unggahan bila TLS tidak didekripsi.

Keluaran ilustrasi:

```
dest_host        category          sesi  mulai                selesai              kirim    terima
webmail.example  Web-based Email   3     01/06/2027 15:20:14  01/06/2027 15:41:02  182336   2418991
```

**Riwayat Edge** (salinan `History`, dibaca read-only): kunjungan ke `webmail.example` Rabu 15:20:14, 15:33:02, dan 15:40:51 WIB; tidak ada kunjungan ke layanan penyimpanan atau berbagi berkas umum pada 4 sampai 7 Januari (daftar domain yang dicari dicatat di case notes); tidak ada kunjungan apa pun Kamis setelah 17:38. Isi halaman dan cache tidak dibuka (bagian 1.2).

**OneDrive dan klien cloud.** Folder OneDrive korporat Arif tidak memuat berkas `HK-2026-*` atau daftar PIC, dan `$J` tidak mencatat pembuatan berkas itu di sana. Prefetch (PECmd atas `$t\Windows\Prefetch`) tidak memuat klien penyimpanan cloud lain.

**Hapus jejak.** EvtxECmd atas Security dan System: nol 1102, nol 104, `EventRecordID` Security berurutan tanpa celah sejak record tertua (2026-11-22 09:14 WIB, Security 256 MB). Prefetch: tidak ada `SDELETE`, `CIPHER`, alat pembersih, `ROBOCOPY`, `XCOPY`, atau pengarsip. `$J` (jendela 2026-12-29 08:14 sampai 2027-01-07 21:47 WIB): tidak ada `FileDelete` untuk nama `HK-2026-*` atau `Daftar-PIC*`; satu-satunya penghapusan terkait adalah pemindahan folder `Kontrak-Ref` ke Recycle Bin (bagian 2.6).

**Cara membaca hasil:**

- Tiga sesi ke webmail pribadi dari kantor pada Rabu sore, sekitar 8 sampai 28 menit setelah salinan lokal dibuat, dengan total kirim 182.336 byte. Angka itu cukup untuk beberapa berkas harga yang kecil (berkas terkecil 39.936 byte), tidak cukup untuk daftar PIC (1.187.840 byte), dan juga cocok dengan aktivitas email biasa. Proxy tidak mendekripsi TLS untuk webmail yang terkategori, jadi isi tidak terlihat. Ini tidak membuktikan apa pun ke arah mana pun; ia menunjukkan sumber yang perlu diminta bila Legal memutuskan perlu.
- Kamis malam laptop tidak tersambung, jadi tidak ada jalur jaringan dari laptop dalam sesi flashdisk. Jaringan rumah, ponsel, dan perangkat pribadi lain di luar lingkup dan tidak terlihat dari laptop.
- Penghapusan folder `Kontrak-Ref` adalah aksi yang terlihat jelas: profil Arif, Recycle Bin, Kamis 19:55:40 WIB. Isinya utuh, dan berkas aslinya tetap ada di share. Artefak tidak menjelaskan alasannya.

**Temuan 5 (ringkas):** dari laptop dan proxy tidak terlihat unggahan berkas ke layanan penyimpanan online atau berbagi berkas pada 4 sampai 8 Januari; ada tiga sesi webmail pribadi dari kantor Rabu 15:20 sampai 15:41 WIB dengan total kirim 182.336 byte, isinya tidak terlihat. Keyakinan rendah sampai sedang untuk kalimat "tidak terlihat unggahan dari laptop di kantor", dan tidak ada keyakinan apa pun untuk jalur di luar laptop. Butuh sumber di luar host: message trace dan audit Microsoft 365 (izin Legal terpisah), dan data penyedia webmail (hanya lewat proses hukum, keputusan Legal).

**Temuan 6 (ringkas):** tidak ditemukan pembersihan log, alat penghapus, atau penghapusan permanen berkas harga dan daftar PIC di laptop. Folder salinan lokal `Kontrak-Ref` dipindah ke Recycle Bin oleh profil Arif Kamis 19:55:40 WIB dan isinya masih utuh. Keyakinan tinggi untuk fakta-fakta itu dalam jendela yang disebut. Hipotesis: penghapusan ini tidak membedakan H1 dari H2, karena membersihkan salinan lokal sebelum mengembalikan laptop juga wajar.

**Kapan gagal:** hasil "tidak ada unggahan" ditulis tanpa menyebut bahwa proxy hanya melihat trafik dari kantor, atau riwayat browser dibaca sampai ke isi email pribadi.

### 2.8 Menguji hipotesis tandingan

Langkah ini menutup pertanyaan ketujuh dari sisi analisis. Keterangan orang dikumpulkan HR dan Surya Atmaja, lalu diteruskan ke kanal kasus; analyst forensik tidak mewawancarai siapa pun.

Keterangan yang diterima:

- **Surya Atmaja (Kepala Divisi), Selasa 10:10:** daftar serah terima Arif hanya 11 pelanggan portofolionya, diserahkan ke Galih Pramudya. Tidak ada penugasan kepada Arif yang membutuhkan berkas harga portofolio lain atau daftar PIC lengkap.
- **Galih Pramudya, lewat HR, Rabu 2027-01-13 11:00:** menerima serah terima lewat folder `Serah-Terima\arif.wicaksono\` dan email Arif Selasa 2027-01-05 10:44; tidak menerima flashdisk atau berkas di luar 11 pelanggan itu.
- **IT, Selasa 11:30:** serial `0019E06B4A21C5F0A7` tidak ada di daftar media kerja terdaftar PT JAB.

Tabel berikut menyatukan hasil pengujian; baca kolom "Artefak yang membedakan", karena hanya artefak di kolom itu yang menggeser keseimbangan antar hipotesis.

| Hipotesis | Artefak yang membedakan | Hasil |
|---|---|---|
| H1: menyalin data portofolio lain dan daftar PIC ke flashdisk pribadi untuk dibawa keluar | Berkas portofolio lain dan daftar PIC di folder lokal dan di `E:`; flashdisk tidak terdaftar | Didukung untuk bagian yang terlihat: 7 berkas portofolio lain dan daftar PIC disalin ke laptop, dua berkas berada dan dibuka di flashdisk pribadi. Penyalinan 17 berkas lain ke flashdisk hanya disimpulkan. "Dibawa keluar" dan pemakaian berikutnya tidak terlihat |
| H2: pekerjaan serah terima | Isi serah terima di share dan email vs isi `Kontrak-Ref` dan flashdisk | Menjelaskan 11 berkas portofolio sendiri (diserahkan lewat share Selasa) dan sebagian pola akses tidak biasa. Tidak menjelaskan 7 berkas portofolio lain, daftar PIC lengkap, dan flashdisk: tidak ada di daftar serah terima, tidak diterima Galih |
| H3: flashdisk media kerja resmi | Daftar media terdaftar IT | Tidak didukung: serial tidak terdaftar |
| H4: orang lain memakai sesi atau akun Arif | 4624, RDP, profil lain, lokasi | Tidak bisa disingkirkan oleh artefak, tetapi dipersempit: kunci layar dibuka dengan kredensial akun Arif (4624 type 7, 19:24:15 WIB) di laptop yang tidak tersambung jaringan, tanpa RDP dan tanpa logon akun lain sejak Kamis sore. Siapa yang duduk di depan laptop adalah pertanyaan proses HR |

**Cara membaca hasil:** H2 tidak "kalah"; ia menjelaskan sebagian aktivitas, dan bagian itu harus ditulis di laporan supaya HR tidak memperlakukan semua akses tidak biasa sebagai temuan. Yang tersisa setelah H2 dikurangi adalah inti kasus: 7 berkas harga portofolio lain, daftar PIC, dan flashdisk pribadi.

**Kapan gagal:** hipotesis tandingan ditulis setelah kesimpulan, hanya untuk "ditolak". Tandanya: tidak ada satu pun artefak yang pernah dicari untuk mendukungnya.

### 2.9 Garis waktu kurasi dan ringkasan untuk HR dan Legal

Garis waktu ini adalah bentuk akhir yang dibaca rapat Kamis, mengikuti pola garis waktu kurasi di Day 13 bagian 1.7: satu baris per kejadian, sumber per baris, pelaku, dan keyakinan. Tabel ini memuat semua baris yang menopang temuan; baca kolom "Sumber" untuk melihat baris mana yang bertumpu pada lebih dari satu sumber.

| WIB | UTC | Kejadian | Pelaku (akun/sesi) | Sumber | Keyakinan |
|---|---|---|---|---|---|
| 2026-10-05 sampai 2027-01-03 | | Akses harga hanya portofolio sendiri (9 berkas, 41 event, 17 hari) | arif.wicaksono | 5145 `JKT-FS01` | Tinggi |
| Sen 04-01 16:41:22 | 09:41:22 | Path folder harga diketik di Explorer | arif.wicaksono | TypedPaths, ShellBags | Tinggi |
| Sen 16:42:05 sampai 17:06:40 | 09:42:05 sampai 10:06:40 | 14 berkas harga portofolio lain disentuh (96 event); 6 dibuka di Excel 16:43:13 sampai 17:05:22 | arif.wicaksono | 5145, LNK, Jump List | Tinggi |
| Sen 16:58:10 sampai 17:01:44 | 09:58:10 sampai 10:01:44 | Flashdisk Kingston `0019E06B4A21C5F0A7` pertama dicolok, `E:`; root dibuka 16:58:31 | sesi arif.wicaksono | `0065`, setupapi, 1006, Defender, ShellBags | Tinggi |
| Sel 05-01 10:05:12 sampai 10:09:47 | 03:05:12 sampai 03:09:47 | 214 berkas serah terima ditulis ke share (11 pelanggan) | arif.wicaksono | 5145 WriteData; keterangan Surya dan Galih | Tinggi |
| Rab 06-01 15:12:05 sampai 15:12:40 | 08:12:05 sampai 08:12:40 | 19 berkas disalin ke `Documents\Kontrak-Ref` (11 sendiri, 7 lain, daftar PIC) | arif.wicaksono, `explorer.exe` | `$J`, Defender, 5145 | Tinggi |
| Rab 15:20:14 sampai 15:41:02 | 08:20:14 sampai 08:41:02 | 3 sesi webmail pribadi, kirim 182.336 byte, isi tidak terlihat | laptop 10.10.51.16 | Proxy, riwayat Edge | Tinggi untuk sesi; tidak ada untuk isi |
| Kam 07-01 17:38:31 | 10:38:31 | Event terakhir laptop di Defender | | Defender | Tinggi |
| Kam 17:38:47 dan 17:39:10 | 10:38:47 dan 10:39:10 | Terputus dari `JAB-Corp`, tidur | | WLAN-AutoConfig 8003, Kernel-Power 42 | Tinggi |
| Kam 19:24:03 dan 19:24:15 | 12:24:03 dan 12:24:15 | Bangun; kunci layar dibuka akun Arif; tanpa jaringan sampai shutdown | arif.wicaksono | Power-Troubleshooter 1, 4624 type 7 | Tinggi |
| Kam 19:26:41 | 12:26:41 | Flashdisk yang sama dicolok, `E:`, mount di sesi Arif 19:26:44 | sesi arif.wicaksono | `0066`, 1006, `MountPoints2` | Tinggi |
| Kam 19:31:12 dan 19:31:14 | 12:31:12 dan 12:31:14 | `HK-2026-SMLC.xlsx` dan daftar PIC tercatat dibuat di `E:\JAB\Kontrak-Ref\` | | `TargetCreated` LNK | Sedang (penyalinan disimpulkan) |
| Kam 19:33:46 sampai 19:36:03 | 12:33:46 sampai 12:36:03 | Kedua berkas dibuka dari `E:` di Excel (PID 7344) | arif.wicaksono | 4688, Sysmon 1, LNK, Jump List | Tinggi |
| Kam 19:52:18 | 12:52:18 | Flashdisk dilepas | | `0067`, 1006 | Tinggi |
| Kam 19:55:40 | 12:55:40 | Folder lokal `Kontrak-Ref` ke Recycle Bin (isi utuh, 19 hash cocok asli) | arif.wicaksono | `$I`/`$R`, `$J` | Tinggi |
| Kam 21:47:12 | 14:47:12 | Laptop dimatikan; tidak dinyalakan lagi sampai di-image | arif.wicaksono | System 1074, 6006; CoC dan keterangan IT | Tinggi |
| Sel 12-01 13:20 sampai 13:24 | 06:20 sampai 06:24 | Pembacaan 19 berkas asli untuk hash | adm.yoga (responder) | 5145, case notes | Tinggi |

Daftar di bawah garis waktu, seperti Day 13 bagian 1.7:

- **Tidak ditemukan (dengan cakupan):** unggahan ke layanan penyimpanan atau berbagi berkas dari kantor (proxy 4 sampai 8 Januari, riwayat Edge); berkas harga di OneDrive korporat; pembersihan log (1102, 104, `EventRecordID` sejak 2026-11-22); alat penghapus atau penyalin di Prefetch; penghapusan permanen berkas harga di `$J` (jendela 2026-12-29 sampai 2027-01-07).
- **Tidak bisa dijawab dari sumber yang ada:** isi flashdisk; 17 berkas lain di flashdisk; isi sesi webmail; trafik dari jaringan rumah dan perangkat pribadi; siapa orang di depan laptop; niat.
- **Bisa dijawab dengan sumber tambahan (keputusan Legal):** message trace dan audit Microsoft 365 untuk akun Arif 4 sampai 8 Januari; flashdisk bila diserahkan secara sah.

Ringkasan kasus yang dikirim ke Dimas Rabu 2027-01-13 17:10, disimpan di `\\jkt-evid01\cases\INC-2027-010\notes\ringkasan-forensik-2027-01-13.md`:

```
INC-2027-010 | Ringkasan forensik untuk HR, Legal, DPO | Rabu 2027-01-13 | Semua waktu WIB (UTC+7)
Dasar: image E01 laptop JKT-WS-0516 (salinan kerja E01-W1), log akses share JKT-FS01, proxy, Defender.
Lingkup sesuai memo Legal 2027-01-11 14:30.

RINGKASAN
Pada Senin 4 Januari 2027, akun arif.wicaksono membuka folder harga kontrak di file server dan menyentuh
14 berkas harga milik portofolio account manager lain; selama 91 hari sebelumnya akun ini tidak pernah
mengakses berkas portofolio lain. Pada Rabu 6 Januari, 19 berkas (11 harga portofolio sendiri, 7 harga
portofolio lain, dan daftar PIC pelanggan korporat) disalin dari file server ke folder di laptop; isinya
identik dengan berkas asli. Pada Kamis 7 Januari malam, saat laptop tidak tersambung ke jaringan, sebuah
flashdisk pribadi Kingston (serial 0019E06B4A21C5F0A7, tidak terdaftar sebagai media kerja) disambungkan
di sesi akun tersebut. Dua berkas bernama dan berukuran sama dengan berkas di folder laptop, yaitu harga
kontrak PT Samudra Logistik Contoh dan daftar PIC, tercatat dibuat di flashdisk pukul 19:31 dan dibuka
dari flashdisk pukul 19:33 dan 19:36. Flashdisk dilepas 19:52, folder di laptop dipindah ke Recycle Bin
19:55 (isinya masih utuh), dan laptop dimatikan 21:47 lalu tidak dinyalakan lagi sampai diperiksa.

KESIMPULAN
Bukti mendukung bahwa salinan kedua berkas tersebut berada di flashdisk tersebut. Kemungkinan seluruh 19
berkas disalin ke flashdisk, tetapi untuk 17 berkas lainnya tidak ada catatan di laptop. Isi flashdisk
tidak dapat diverifikasi karena perangkat tidak tersedia. Sebagian aktivitas (11 berkas portofolio
sendiri) cocok dengan pekerjaan serah terima yang sah; 7 berkas portofolio lain, daftar PIC lengkap, dan
flashdisk tidak tercakup serah terima menurut keterangan atasan dan penerima. Tidak ditemukan pembersihan
log atau alat penghapus. Dari laptop dan proxy kantor tidak terlihat unggahan ke layanan penyimpanan
online; ada tiga sesi webmail pribadi Rabu sore yang isinya tidak terlihat. Data dari jaringan rumah,
ponsel, dan akun pribadi tidak termasuk pemeriksaan.

BATAS
Artefak menunjukkan akun, sesi, dan perangkat, bukan orang yang mengoperasikannya, dan tidak menunjukkan
tujuan atau niat. Laporan ini tidak menyatakan bahwa data diberikan kepada pihak mana pun.

YANG DAPAT MENAIKKAN KEPASTIAN
1. Pemeriksaan flashdisk serial 0019E06B4A21C5F0A7 bila dapat diperoleh secara sah.
2. Message trace dan audit Microsoft 365 untuk akun arif.wicaksono 4-8 Januari 2027 (izin Legal terpisah).
3. Penilaian DPO atas daftar PIC (jumlah baris dan kategori data pribadi tercatat di lampiran).
```

Kalimat dilarang yang ditulis di lembar batas bukti untuk rapat, karena paling mungkin muncul:

- "Arif mencuri data" atau "Arif memberikan harga ke pesaing" (niat dan penerima tidak terlihat).
- "19 berkas terbukti disalin ke flashdisk" (hanya dua yang punya artefak di flashdisk).
- "Arif sengaja memutus jaringan supaya tidak terpantau" (alasan tidak terlihat).
- "Arif menghapus jejak" (Recycle Bin, isi utuh, asli tetap di share).
- "Tidak ada data yang keluar lewat email" (isi webmail dan email korporat tidak diperiksa).
- "Hanya Arif yang bisa melakukannya" (artefak menunjuk akun dan sesi).

**Cara membaca hasil:** ringkasan tidak memuat kata "mencuri", "menyalahgunakan", atau dugaan motif. Setiap kalimat bisa ditunjuk ke baris garis waktu, dan setiap batas punya langkah yang bisa menaikkan kepastian.

### 2.10 Rubrik penilaian diri

Rubrik ini dipakai untuk menilai pengerjaan kasus, baik kasus PT JAB di atas maupun hasil lab-mu sendiri; baca kolom "Kuat" sebagai standar yang dituju.

| Aspek | Belum memadai | Memadai | Kuat |
|---|---|---|---|
| Pertanyaan | Langsung ke artefak tanpa pertanyaan | Pertanyaan ditulis | Pertanyaan plus hipotesis tandingan dan jalur lain, ditulis sebelum analisis |
| Pola kerja | "Mengakses data sensitif" tanpa pembanding | Pembanding disebut | Baseline dengan jendela, dimensi, dan sumber; perubahan peran yang sah dipisahkan |
| Rantai USB | Menyamakan VSN dengan serial perangkat | Menautkan lewat satu jembatan | Dua jembatan independen, keterbatasan tiap jembatan disebut |
| Penyalinan | "Terbukti disalin" | Membedakan dibuka dan disalin | Menyebut yang terbukti, disimpulkan, dan tidak bisa disimpulkan, per berkas |
| Hipotesis tandingan | Tidak ada | Ditulis lalu ditolak | Diuji dengan artefak; hasil parsial ditulis jujur |
| Hasil negatif | Tidak ditulis | Ditulis | Ditulis beserta cakupan dan jendelanya |
| Timeline | Tanpa zona waktu | Zona waktu disebut | WIB dan UTC, sumber dan pelaku per baris, jejak responder dilabeli |
| Lingkup dan data pribadi | Membaca apa saja yang terlihat | Lingkup disebut | Lingkup diikuti, data pribadi diminimalkan, keterangan orang dipisah dari artefak |
| Bahasa | Menyebut motif | Netral | Netral, ada kalimat dilarang, dan menyebut langkah untuk menaikkan kepastian |

## 3. Lab praktik (di VM lab terisolasi)

Lab ini mereproduksi kasus dalam bentuk jinak dengan data tiruan, lalu meminta kamu mengerjakannya dari pertanyaan sampai ringkasan dan membandingkan hasilnya dengan catatan kebenaran dasar yang kamu tulis sendiri. Folder kasus lab `CASE-2026-LAB-017`.

**Prasyarat:**

- `LAB-WS01` (`172.16.50.10`, Windows 11, Sysmon, audit Process Creation dengan command line) sebagai laptop subjek, snapshot bersih sebelum mulai; akun `lab.user` (pengguna biasa) dan `lab.ir` (admin lokal untuk responder).
- `LAB-WS02` (`172.16.50.11`) sebagai file server: share `lab-sales` dengan subfolder `Harga\` (sepuluh berkas `.xlsx` tiruan, dua di antaranya ditetapkan sebagai "portofolio `lab.user`") dan `Kontak\daftar-tiruan.xlsx`; aktifkan Audit File Share dan Audit Detailed File Share.
- `LAB-DFIR01` (`172.16.50.20`) dengan EZ Tools untuk analisis.
- Satu flashdisk fisik milikmu yang boleh diformat, diteruskan ke VM lewat USB passthrough, diformat FAT32 dengan label `LAB-USB`. Jaringan host-only `172.16.50.0/24`.

Langkah:

1. **Catatan kebenaran dasar.** Buka catatan terpisah di host-mu (bukan di VM) dan tulis setiap langkah berikut beserta waktunya dalam WIB. Ini yang nanti dibandingkan dengan hasil analisis.
2. **Bangun baseline.** Selama beberapa hari lab (atau beberapa sesi dengan jam berbeda), login sebagai `lab.user` dan buka hanya dua berkas "portofolio sendiri" dari `\\LAB-WS02\lab-sales\Harga\`.
3. **Skenario.** Sesi A (tersambung): ketik path `\\LAB-WS02\lab-sales\Harga` di address bar, buka empat berkas "portofolio lain", colok flashdisk sebentar, buka root-nya, cabut. Sesi B (tersambung): salin enam berkas dan `daftar-tiruan.xlsx` ke `Documents\Ref-Lab\`. Sesi C: putuskan adapter jaringan VM, colok flashdisk, salin folder `Ref-Lab` ke `E:\LAB\` lewat Explorer, buka dua berkas dari `E:`, cabut, pindahkan `Documents\Ref-Lab` ke Recycle Bin, matikan VM.
4. **Kumpulkan.** Dari snapshot atau disk `LAB-WS01` yang di-mount read-only di `LAB-DFIR01`, ambil hive, event log, Recent, `$MFT`, `$J`, Prefetch, Recycle Bin, dan `setupapi.dev.log` (pola bagian 2.1). Ekspor Security log `LAB-WS02`.
5. **Pertanyaan dan hipotesis.** Tulis tujuh pertanyaan (Ide inti) dan empat hipotesis (bagian 1.8) sebelum membuka artefak.
6. **Pola akses.** Hitung baseline dan jendela skenario dari 5145 `LAB-WS02` per "portofolio" (bagian 2.3).
7. **Berkas dibuka.** Urai LNK, Jump List, dan 4688 atau Sysmon 1 untuk `EXCEL.EXE` atau aplikasi spreadsheet yang kamu pakai (bagian 2.4). Catat `DriveType`, VSN, label, `TargetCreated`, dan apakah LNK kedua untuk nama yang sama dibuat dengan akhiran `(2)` atau menimpa yang lama.
8. **USB.** Urai USBSTOR, Properties, `MountedDevices`, Windows Portable Devices, `MountPoints2`, `setupapi.dev.log`, dan event 1006; baca VSN dari `Vbr0` di offset `0x43` (bagian 2.5). Bangun rantai VSN ke serial dan tulis jembatan yang kamu pakai.
9. **Verifikasi rantai.** Baca VSN flashdisk langsung (misalnya dari keluaran `vol E:` di sistem yang memasangnya read-only) dan bandingkan dengan LNK dan event 1006.
10. **Penyalinan, jalur lain, hapus jejak.** Nilai bukti penyalinan per berkas (bagian 2.6), hash isi `$R` terhadap berkas asli di `LAB-WS02`, dan periksa hapus jejak serta jalur lain (bagian 2.7).
11. **Hipotesis, garis waktu, ringkasan.** Uji keempat hipotesis (bagian 2.8), susun garis waktu dan ringkasan dengan format bagian 2.9, lalu nilai dengan rubrik bagian 2.10. Bandingkan dengan catatan kebenaran dasar dari langkah 1.

**Variasi:**

- Ulangi dengan flashdisk yang sudah pernah tersambung sebelumnya. Amati bagaimana `0065` dan `0066` berbeda, dan bagaimana itu mengubah kalimat temuan.
- Salin berkas, lalu hapus dari flashdisk sebelum mencabut. Periksa apakah LNK dan Jump List masih menunjukkan berkas di `E:`.
- Hapus berkas lokal dengan Shift+Delete, lalu cari jejaknya di `$J` dan `$MFT` (Day 08). Tulis bagaimana kamu menyajikan "berkas dihapus" tanpa menyebut motif.
- Format flashdisk ulang dengan label yang sama. Tunjukkan bahwa VSN berubah sementara serial perangkat tetap, dan tulis implikasinya untuk rantai bukti.
- Bila lab-mu punya sensor EDR atau Sysmon dengan EID 11 tanpa filter, ulangi sesi C dalam keadaan tersambung dan bandingkan apa yang tercatat untuk penulisan ke `E:`.
- Salin satu berkas dengan alat selain Explorer (misalnya `robocopy` dengan opsi bawaan) dan bandingkan `TargetCreated` dan `TargetModified` di LNK dengan hasil penyalinan Explorer.

**Hasil yang sebaiknya tersimpan:**

- Catatan kebenaran dasar skenario dengan waktu tiap langkah.
- Pertanyaan investigasi dan empat hipotesis, ditulis sebelum analisis.
- Tabel pola akses (baseline dan jendela skenario) dari 5145.
- Tabel rantai USB (LNK, event 1006, Windows Portable Devices, USBSTOR, `MountedDevices`, `MountPoints2`, `setupapi.dev.log`) dengan nilai konkret.
- Temuan per pertanyaan memakai templat bagian 2.2, termasuk pembagian terbukti, disimpulkan, tidak bisa disimpulkan.
- Hasil pengujian hipotesis dan garis waktu WIB dan UTC dengan sumber per baris.
- Ringkasan kasus dan daftar kalimat dilarang.
- Penilaian diri dengan rubrik bagian 2.10 dan selisih antara hasil analisis dan kebenaran dasar.

## 4. Troubleshooting

Tabel ini memuat masalah yang paling sering muncul saat mengerjakan kasus orang dalam. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Tidak ada bukti akses share di laptop | TypedPaths kosong karena share dibuka lewat shortcut atau drive yang di-map | Pakai ShellBags dan log server; minta ekspor Security log file server |
| 5145 tidak ada di file server | Subkategori Detailed File Share tidak diaktifkan | Tulis sebagai keterbatasan; andalkan 5140 (sekali per sesi, tanpa nama berkas) dan artefak laptop |
| 5145 sangat banyak untuk satu berkas | Preview, thumbnail, antivirus, dan penyalinan sama-sama membaca | Hitung berkas berbeda dan pola per detik; pembukaan dijawab LNK, Jump List, 4688 |
| Baseline lebih pendek dari yang direncanakan | Retensi index atau lingkup memo lebih sempit | Tulis jendela yang benar-benar tersedia di setiap kalimat pola |
| VSN di LNK tidak ada di registry | VSN memang tidak disimpan di USBSTOR | Bangun jembatan lewat event 1006, label dan huruf drive pada waktu yang sama, EMDMgmt bila ada |
| Event 1006 tidak ada | Log berputar, dikosongkan pembaruan besar Windows, atau build berbeda | Jembatan tinggal label, huruf drive, dan waktu; turunkan keyakinan rantai |
| Serial USBSTOR dengan karakter kedua `&` | Perangkat tidak punya serial unik, Windows membuat ID | Serial itu hanya unik per host; jangan pakai untuk mencocokkan antar host |
| Waktu Properties tidak terbaca | Alat atau hak akses tidak mendukung | Baca dari hive offline; cocokkan dengan `setupapi.dev.log` dan event 1006 |
| Defender tidak punya data untuk satu sesi | Laptop tidak tersambung, atau data di luar 30 hari advanced hunting | Cek event terakhir perangkat di portal dan event jaringan di laptop; tulis sebagai batas, bukan hasil negatif |
| LNK untuk berkas di flashdisk tidak ditemukan dengan nama biasa | Nama sama dengan LNK lama, sehingga berakhiran `(2)` atau menimpa | Cari berdasarkan `LocalPath` dan `DriveType`, atau pakai LECmd `-r`; cek Jump List |
| Timeline membingungkan | Campuran UTC, WIB, dan waktu lokal FAT | Ambil zona dari `TimeZoneInformation` (Day 09) dan beri label per sumber |
| Berkas dihapus tidak ditemukan di Recycle Bin | Shift+Delete, dihapus proses, atau dihapus dari media lepasan | Cek `$J` dan `$MFT` untuk volume lokal; media lepasan tidak punya Recycle Bin di koleksi |

## 5. Kesalahan umum dan jebakan

- **Menyamakan volume serial number dengan serial perangkat.** LNK menyimpan VSN volume, USBSTOR menyimpan serial perangkat. Tunjukkan jembatannya (bagian 1.5).
- **Menyimpulkan penyalinan dari akses.** Membuka berkas dari share bukan bukti penyalinan. Yang mendekati bukti adalah berkas bernama sama dengan waktu pembuatan baru di media lepasan.
- **Memperluas bukti dari satu berkas ke semua.** Dua berkas yang dibuka dari flashdisk tidak membuktikan 17 berkas lain ada di sana; tulis per berkas.
- **Memakai USN laptop untuk membuktikan penyalinan ke USB.** USN hanya mencatat volume yang journal-nya kamu punya.
- **Membaca ketiadaan telemetry sebagai hasil negatif.** EDR yang tidak menerima data karena laptop tidak tersambung tidak berkata apa-apa tentang sesi itu.
- **Over-claim motif.** Artefak menunjukkan aksi, bukan niat. "Berkas dihapus" bukan "menutupi jejak", dan "laptop tidak tersambung" bukan "sengaja menghindari pemantauan", tanpa bukti lain.
- **Hipotesis tandingan sebagai formalitas.** Serah terima yang sah menjelaskan sebagian aktivitas; bagian itu harus ditulis, bukan ditolak begitu saja.
- **Menyebut orang, bukan akun.** Artefak menunjuk akun, sesi, dan perangkat. "Sesi profil `arif.wicaksono`" lebih tepat daripada "Arif" di kalimat temuan teknis.
- **Keluar dari lingkup.** Membuka email pribadi di cache browser atau isi folder pribadi di flashdisk karena "terlihat" bisa membuat seluruh laporan dipersoalkan.
- **Lupa hasil negatif.** Jalur lain yang diperiksa dan tidak menghasilkan apa-apa memperkuat kesimpulan bila ditulis beserta cakupannya.
- **Lupa log di luar host.** 5140 dan 5145 ada di file server, bukan di laptop.
- **Timeline tanpa zona waktu.** Laporan untuk Legal harus menyebut zona waktu secara eksplisit.

## 6. Catatan terkini

Bagian ini menampung detail versi, retensi, dan sumber yang bisa berubah; isinya tidak mengubah alur analisis di atas.

- **EZ Tools 2026.5.0** (LECmd, JLECmd, SBECmd, RECmd, MFTECmd, EvtxECmd, RBCmd) masih versi terbaru di halaman resmi saat diperiksa 2026-10-22, tersedia untuk .NET 4.7.2 dan .NET 9; Timeline Explorer hanya .NET 9 [S16]. Kasus Januari 2027 tetap memakai versi yang dibekukan saat kasus dibuka; cek halaman rilis sebelum membuka kasus baru.
- **Device properties USB.** Windows 10 dan 11 menyimpan `0064` InstallDate, `0065` FirstInstallDate, `0066` LastArrivalDate, dan `0067` LastRemovalDate di subkey Properties perangkat. Versi lama Day ini memakai `0064` sebagai waktu instalasi pertama; yang benar adalah `0065`, karena `0064` berubah saat driver diperbarui [S8][S9].
- **Event `Microsoft-Windows-Partition/Diagnostic` 1006** di Windows 10/11 dipakai praktisi sebagai sumber pemasangan USB dan VSN dari `Vbr0`; tata letak datanya tidak didokumentasikan resmi oleh Microsoft [S4], dan pembaruan besar Windows bisa mengosongkan channel ini [S9].
- **EMDMgmt** sering tidak ada di sistem dengan SSD, sehingga jembatan VSN ke perangkat lebih sering dibangun dari event 1006, label, huruf drive, dan waktu.
- **Defender for Endpoint.** Advanced hunting bisa mencari data mentah sampai 30 hari ke belakang; retensi lebih panjang butuh workspace Microsoft Sentinel atau streaming API [S11]. Halaman investigasi perangkat menyebut timeline perangkat secara default menampilkan 30 hari terakhir dan data keamanan disimpan 90 hari secara default, serta mengingatkan bahwa nilai "Last seen" di halaman perangkat bisa lebih tua dari data terbaru di timeline [S14]. Event audit mount dan unmount drive USB aktif secara default untuk perangkat yang onboard; laporan device control menampilkan event mentah 30 hari terakhir dan butuh langganan dengan pelaporan Microsoft 365 E5 [S13]. PT JAB memakai Microsoft 365 E3 dengan Defender for Endpoint Plan 2, jadi kasus ini memakai advanced hunting, bukan laporan device control; ketersediaan laporan itu di tenant PT JAB cek di portal.
- **`DeviceFileEvents`.** Kolom `SHA256` biasanya kosong dan Microsoft menyarankan memakai `SHA1`; hash bisa kosong bila berkas di remote storage, terkunci, terkompresi, atau virtual [S12]. Kueri komunitas untuk berkas yang disalin ke USB mencatat bahwa tidak semua tipe berkas dipantau [S17]; perilakunya untuk dokumen Office di media lepasan cek di lab dengan sensor yang sama.
- **Audit Removable Storage** menghasilkan 4656, 4658, dan 4663 untuk semua objek dan jenis akses di media lepasan tanpa bergantung SACL [S10]. Subkategori ini tidak ada di `JAB-WS-Audit`; menambahkannya adalah usulan perbaikan setelah kasus, dengan pertimbangan volume log.
- **Event 5140 dan 5145** didokumentasikan di halaman arsip Microsoft Learn untuk Windows 10; tautan lama di `windows/security/threat-protection/auditing/` kini diarahkan ke halaman arsip itu [S1][S2].
- **Day 18** adalah simulasi kasus kedua, infeksi installer palsu dengan DLL side-loading (`INC-2026-026`), yang menekankan eksekusi, C2, persistence, dan IOC.

## 7. Cheat sheet

```
ALUR KASUS   dugaan HR/Legal -> pertanyaan + hipotesis (H1 + tandingan) -> lingkup memo -> artefak -> korelasi
             -> temuan (terbukti/disimpulkan/tidak bisa) -> garis waktu -> ringkasan + kalimat dilarang
TANGGA       1 diakses (5140/5145 SERVER, TypedPaths, ShellBags) | 2 dibuka (LNK, Jump List, 4688/Sysmon 1 cmdline)
             3 disalin ke X (nama+ukuran sama, TargetCreated baru di X, rantai X) | 4 keluar (proxy, gateway, media) | 5 niat: -
POLA         baseline per akun: data apa, berapa, kapan, bagaimana ; jendela = retensi ; serah terima menggeser pola
5145         setiap akses objek share (Detailed File Share) ; bukan bukti dibuka di aplikasi ; 5140 sekali per sesi
USB          USBSTOR\Disk&Ven_..&Prod_..\<serial>&0 ; Properties 0065 first / 0064 install / 0066 arrival / 0067 removal (UTC)
             setupapi.dev.log (LOKAL) ; MountedDevices (huruf) ; WPD (serial -> label) ; MountPoints2 (sesi, bukan orang)
JEMBATAN     VSN (LNK) != serial (USBSTOR) ; 1006 Vbr0 VSN @0x48 NTFS / 0x43 FAT32 / 0x64 exFAT ; label + huruf + waktu ;
             EMDMgmt bila ada ; Defender UsbDriveMounted (bila sensor kirim)
PENYALINAN   nama+ukuran sama + TargetCreated baru di media = indikasi kuat UNTUK BERKAS ITU ; isi butuh media
             USN C: tidak melihat salinan ke E: ; FAT: waktu lokal, tulis 2 s ; Recycle Bin $R = bukti isi salinan lokal
EDR          AH 30 hari ; data ada hanya bila sensor sempat kirim ; tidak ada data != tidak ada kejadian
JALUR LAIN   proxy (hanya kantor/VPN, TLS terkategori tidak didekripsi) ; riwayat browser (domain, bukan isi) ;
             OneDrive/klien cloud ; M365 message trace (izin terpisah) ; ponsel/rumah: di luar host
NEGATIF      Recycle Bin, $J FileDelete, 1102/104, EventRecordID, Prefetch alat ; tulis cakupan + jendela
HIPOTESIS    H2 serah terima | H3 media terdaftar | H4 orang lain di sesi ; uji dengan artefak, hasil parsial ditulis
JUJUR        akun/sesi bukan orang ; aksi bukan niat ; lingkup izin ; data pribadi minimal ; zona waktu eksplisit
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Advanced hunting Defender tidak punya satu pun `FileCreated` di `E:` untuk Kamis malam, jadi tidak ada berkas yang ditulis ke flashdisk." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Advanced hunting hanya menerima data setelah sensor berhasil mengirimkannya, dan laptop tidak tersambung ke jaringan mana pun sejak Kamis 17:38:47 WIB sampai dimatikan dan tidak pernah tersambung lagi. Event terakhir perangkat di portal adalah 17:38:31 WIB, sebelum flashdisk dicolok. Ketiadaan data untuk sesi itu adalah batas sumber, bukan hasil negatif. Bukti tentang `E:` datang dari artefak di image: LNK, Jump List, ShellBags, event 1006, dan registry. Lihat bagian 1.6 dan 2.6.

</details>

**2. Skenario keputusan.** Kamu harus menulis satu kalimat tentang penyalinan ke flashdisk untuk ringkasan HR. Mana yang paling tepat?

- A. "Arif menyalin 19 berkas harga kontrak dan daftar PIC ke flashdisk pribadinya."
- B. "Dua berkas bernama dan berukuran sama dengan berkas di folder laptop tercatat dibuat dan dibuka di flashdisk tersebut; kemungkinan seluruh 19 berkas disalin, tetapi 17 lainnya tidak tercatat di laptop, dan isi flashdisk tidak dapat diverifikasi."
- C. "Tidak ada bukti penyalinan karena flashdisk tidak ada di tangan PT JAB."

<details><summary>Jawaban</summary>

B. Kalimat itu memisahkan yang terbukti (dua berkas, lewat LNK, Jump List, dan rantai USB), yang disimpulkan (seluruh folder), dan yang tidak bisa diverifikasi (isi). A keliru karena memperluas bukti dua berkas ke 19 berkas dan menyebut orang, bukan sesi akun. C keliru karena artefak di laptop tetap memberi bukti tidak langsung yang kuat untuk dua berkas; ketiadaan media hanya membatasi verifikasi isi. Lihat bagian 1.6 dan 2.6.

</details>

**3. Pertanyaan jebakan.** "VSN `5A1C-0E37` di LNK sama dengan serial perangkat di USBSTOR, jadi LNK langsung membuktikan flashdisk Kingston `0019E06B4A21C5F0A7`." Benarkah?

<details><summary>Jawaban</summary>

Tidak. VSN dibuat saat volume diformat dan disimpan di LNK dan Jump List; serial perangkat berasal dari firmware dan disimpan di USBSTOR. Keduanya berbeda dan butuh jembatan. Di kasus ini jembatannya event 1006, yang memuat serial perangkat dan boot record berisi VSN dalam satu event, ditambah label `KINGSTON` dan huruf `E:` yang cocok dengan `MountedDevices` pada sesi yang sama. Bila flashdisk diformat ulang, VSN berubah tetapi serial perangkat tetap. Lihat bagian 1.5 dan 2.5.

</details>

**4. Skenario keputusan.** HR menyebut Arif sedang menyerahkan portofolionya ke pengganti minggu itu. Apa yang kamu lakukan dengan informasi ini?

- A. Abaikan, karena Arif sudah mengundurkan diri dan dugaan HR sudah jelas.
- B. Jadikan hipotesis tandingan dan uji: bandingkan isi folder serah terima di share dan keterangan penerima dengan berkas yang disalin ke laptop dan yang muncul di flashdisk.
- C. Anggap seluruh aktivitas sah, karena ada folder `Serah-Terima` di share.

<details><summary>Jawaban</summary>

B. Serah terima yang sah memang membuat akses yang tidak biasa, jadi ia harus diuji dengan artefak, bukan diabaikan atau diterima mentah. Di kasus ini H2 menjelaskan 11 berkas portofolio sendiri yang diserahkan lewat share Selasa, tetapi tidak menjelaskan 7 berkas portofolio lain, daftar PIC lengkap, dan flashdisk. A keliru karena membuat analisis berat sebelah. C keliru karena keberadaan folder serah terima tidak menjelaskan berkas yang tidak ada di dalamnya. Lihat bagian 1.8 dan 2.8.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Bu Larasati (HR), dalam tiga kalimat, kenapa temuan "folder `Kontrak-Ref` dipindah ke Recycle Bin pukul 19:55" tidak ditulis sebagai "Arif menghapus jejak".

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Artefak menunjukkan folder salinan di laptop dipindah ke Recycle Bin oleh profil Arif pukul 19:55, tetapi isinya masih utuh di sana dan berkas aslinya tetap ada di file server, jadi tidak ada data yang hilang karena tindakan itu. Membersihkan salinan lokal sebelum mengembalikan laptop juga hal yang wajar, dan artefak tidak menunjukkan alasan orang melakukannya. Yang penting untuk HR adalah urutannya: berkas yang sama sempat berada di flashdisk sebelum folder lokal dipindah, dan itu ditulis di temuan penyalinan, bukan di temuan penghapusan."

Kesalahan yang sering muncul:
- Memakai kata "menghilangkan bukti" padahal isi Recycle Bin justru menjadi bukti isi salinan lokal.
- Tidak menyebut bahwa berkas asli tetap ada di share.
- Mencampur temuan penghapusan dengan temuan penyalinan, sehingga dua hal yang berbeda kekuatannya terdengar sama.

</details>

**6. Pertanyaan jebakan.** "Log 5145 menunjukkan akun Arif menyentuh 14 berkas harga portofolio lain hari Senin, jadi ia membuka 14 berkas itu." Benarkah?

<details><summary>Jawaban</summary>

Tidak. 5145 mencatat pemeriksaan akses ke objek di share, dan panel preview Explorer, thumbnail, antivirus, serta penyalinan sama-sama membaca berkas. Berkas yang dibuka di aplikasi dijawab artefak laptop: LNK dan Jump List Excel menunjukkan enam berkas dibuka Senin (SMLC, ADPT, BRKS, PLMA, RJWL, TKMD); delapan sisanya hanya punya 4 sampai 5 event 5145. Kalimat yang tepat: akun menyentuh 14 berkas, enam di antaranya dibuka di Excel. Lihat bagian 1.3 dan 2.4.

</details>

**7. Interview question (English).** "HR asks you to prove that a departing employee copied confidential files to a USB drive. How do you approach the investigation and the report?"

<details><summary>Sample answer</summary>

"First I turn the allegation into answerable questions and write down competing hypotheses before I touch any artifact, including innocent ones such as a legitimate handover, an approved company drive, or someone else using the session. I confirm the legal scope in writing, work only on company devices and logs, and keep personal content out. Then I climb an evidence ladder: file server audit logs like 5145 against a baseline for access, LNK, Jump Lists and process creation for opening, and the USB chain for the device itself, where I bridge the volume serial in the LNK to the device serial using Partition/Diagnostic 1006, label and drive letter, because those two serials are different things. For copying, a file with the same name and size and a fresh creation time on the removable volume is strong but indirect, and I state it per file; without the drive I cannot verify content, and EDR silence during an offline session is a gap, not a negative. The report separates proven, inferred, and unknown, lists out-of-scope paths like personal email, and never states intent."

What makes this answer strong: it starts with hypotheses and legal scope rather than tools, distinguishes access, opening, copying, exfiltration, and intent, explains the volume serial versus device serial trap, treats missing telemetry correctly, and ends with neutral, per-file reporting language suited to HR and Legal.

</details>

## 9. Sumber

Tabel ini adalah rujukan verifikasi; semua isi yang dibutuhkan untuk memahami Day ini sudah ditulis di atas.

| # | Judul | URL | Tipe | Tanggal / diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Microsoft Learn: 5140(S, F) A network share object was accessed | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5140 | primer (arsip) | ms.date 2021-09-08; dirujuk 2026-10-10, diakses ulang 2026-10-22 | Tinggi. Subkategori Audit File Share; sekali per sesi saat akses pertama; akses selalu ReadData; tercatat di server pemilik share. Tautan lama di jalur `windows/security/...` diarahkan ke halaman ini |
| S2 | Microsoft Learn: 5145(S, F) A network share object was checked to see whether client can be granted desired access | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5145 | primer (arsip) | ms.date 2021-09-08; dirujuk 2026-10-10, diakses ulang 2026-10-22 | Tinggi. Subkategori Audit Detailed File Share; setiap akses objek share; field Share Name, Relative Target Name, Source Address, Accesses; gagal hanya bila ditolak di tingkat share |
| S3 | SANS: Windows Forensic Analysis poster (USB, LNK, ShellBags) | https://www.sans.org/posters/windows-forensic-analysis/ | sekunder | dirujuk 2026-10-10 | Sedang-tinggi. Lokasi artefak USB dan aktivitas pengguna |
| S4 | Provider Microsoft-Windows-Partition (winevt-kb) | https://winevt-kb.readthedocs.io/en/stable/sources/eventlog-providers/Provider-Microsoft-Windows-Partition.html | sekunder | dirujuk 2026-10-10 | Sedang. Keberadaan provider dan event; tata letak data 1006 tidak didokumentasikan resmi |
| S5 | Endpoint-Forensics-Notes Day 01, 02, 03, 05, 07, 08, 09, 10, 12, 13 | (lokal) | rujukan internal | 2026-10-22 | Artefak, alat, dan pola laporan yang dipakai di kasus; target KAPE `RecycleBin_DataFiles` mengambil `$R*` di `C:\$Recycle.Bin\` termasuk isi folder `$R` (KapeFiles, diakses 2026-10-22); opsi `--dumpTo` JLECmd dari README resmi seperti di Day 10 |
| S6 | Microsoft Learn: File Times | https://learn.microsoft.com/en-us/windows/win32/sysinfo/file-times | primer | ms.date 2018-05-31, diperbarui 2025-04-15; diakses 2026-10-22 | Tinggi. NTFS menyimpan UTC, FAT menyimpan waktu lokal; resolusi FAT: buat 10 ms, tulis 2 detik, akses 1 hari; NTFS menunda pembaruan last access sampai 1 jam |
| S7 | Microsoft Open Specifications: [MS-SHLLINK] VolumeID | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/b7b3eea7-dbff-4275-bd58-83ba3f12d87a | primer | 2025-06-10; diakses 2026-10-22 | Tinggi. `DriveType` (termasuk `DRIVE_REMOVABLE` untuk thumb drive), `DriveSerialNumber` volume tempat target berada, label volume |
| S8 | Microsoft Learn: DEVPKEY_Device_FirstInstallDate | https://learn.microsoft.com/en-us/windows-hardware/drivers/install/devpkey-device-firstinstalldate | primer | ms.date 2022-06-23; diakses 2026-10-22 | Tinggi. Waktu instance perangkat pertama di-install; tidak berubah oleh pembaruan driver, berbeda dari InstallDate |
| S9 | Elcomsoft: USB Device Forensics on Windows 10 and 11 | https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/ | sekunder (vendor forensik) | 2026-02-25; diakses 2026-10-22 | Sedang-tinggi. Event 1006 dengan `Vbr0`, offset VSN NTFS `0x48`, FAT32 `0x43`, exFAT `0x64`; properti `0x64`-`0x67`; serial dengan `&` sebagai indikator heuristik; registry dan event log tidak membuktikan berkas disalin; channel bisa dikosongkan pembaruan besar |
| S10 | Microsoft Learn: Audit Removable Storage | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-removable-storage | primer (arsip) | ms.date 2021-09-06; diakses 2026-10-22 | Tinggi. Event untuk semua objek dan jenis akses di media lepasan tanpa bergantung SACL; event 4656, 4658, 4663 |
| S11 | Microsoft Learn: Advanced hunting overview in Microsoft Defender XDR | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview | primer | ms.date 2026-08-07; diakses 2026-10-22 | Tinggi. Data mentah sampai 30 hari; data diterima setelah sensor berhasil mengirim; kueri dalam UTC; retensi lebih panjang lewat Sentinel atau streaming API |
| S12 | Microsoft Learn: DeviceFileEvents table in the advanced hunting schema | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table | primer | ms.date 2025-03-28, diperbarui 2026-06-26; diakses 2026-10-22 | Tinggi. Kolom `FolderPath`, `FileSize`, `SHA1`, `InitiatingProcessFileName`; `SHA256` biasanya kosong; hash bisa kosong untuk berkas remote, terkunci, terkompresi, atau virtual |
| S13 | Microsoft Learn: View device control events and information in Microsoft Defender for Endpoint | https://learn.microsoft.com/en-us/defender-endpoint/device-control-report | primer | ms.date 2024-06-25, diperbarui 2026-06-14; diakses 2026-10-22 | Tinggi. Event audit mount dan unmount drive USB serta PnP aktif default untuk perangkat onboard; laporan menampilkan event mentah 30 hari; butuh pelaporan Microsoft 365 E5; batas 300 event per perangkat per hari untuk `RemovableStoragePolicyTriggered` di advanced hunting |
| S14 | Microsoft Learn: Investigate devices in Microsoft Defender for Endpoint | https://learn.microsoft.com/en-us/defender-endpoint/investigate-machines | primer | ms.date 2026-07-23; diakses 2026-10-22 | Tinggi. Timeline perangkat default menampilkan 30 hari; data keamanan disimpan 90 hari secara default; nilai "Last seen" bisa lebih tua dari data terbaru di timeline |
| S15 | CISA: Defining Insider Threats | https://www.cisa.gov/topics/physical-security/insider-threat-mitigation/defining-insider-threats | primer (lembaga pemerintah) | diakses 2026-10-22 | Tinggi. Definisi insider dan insider threat (sadar atau tidak); jenis tidak disengaja, disengaja, kolusif, pihak ketiga |
| S16 | Eric Zimmerman tools (EZ Tools) | https://ericzimmerman.github.io/ | primer | diakses 2026-10-22 | Tinggi. Versi 2026.5.0 untuk LECmd, JLECmd, SBECmd, RECmd, MFTECmd, EvtxECmd, RBCmd; .NET 4.7.2 dan .NET 9; Timeline Explorer hanya .NET 9 |
| S17 | Microsoft Tech Community: Monitoring copied files on external drive (USB) | https://techcommunity.microsoft.com/discussions/microsoftthreatprotection/monitoring-copied-files-on-external-drive---usb/3764979 | komunitas | 2023-03 (lebih dari 3 tahun); diakses 2026-10-22 | Sedang-rendah. Kueri komunitas `UsbDriveMounted` dengan `DriveLetter`, `ProductName`, `SerialNumber`, `Manufacturer` di `AdditionalFields`, digabung dengan `DeviceFileEvents` `FileCreated`; catatan bahwa tidak semua tipe berkas dipantau |

**Catatan sumber:** nilai, waktu, nama, dan konfigurasi dalam kasus adalah fiktif, termasuk konfigurasi Sysmon PT JAB untuk EID 11, retensi index Splunk, dan daftar portofolio. Pemakaian event 1006 untuk mengekstrak VSN berasal dari tulisan praktisi dan vendor forensik, bukan dokumentasi Microsoft, jadi uji per build. Perilaku waktu pembuatan baru dan waktu modifikasi yang dibawa saat menyalin ke volume FAT, arah pembulatan waktu tulis FAT, dan penamaan LNK kedua untuk berkas bernama sama dari lokasi berbeda sebaiknya kamu amati sendiri di lab, karena sumber yang diperiksa tidak mendokumentasikannya. Nama kunci di `AdditionalFields` untuk `UsbDriveMounted` berasal dari kueri komunitas [S17]; cek isi JSON di tenant-mu. Bagian tata kelola dan data pribadi adalah praktik kerja, bukan nasihat hukum.
