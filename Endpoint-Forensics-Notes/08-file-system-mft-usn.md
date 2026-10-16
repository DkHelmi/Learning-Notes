---
day: 08
title: 'File system forensics: $MFT, MACB, $STANDARD_INFORMATION vs $FILE_NAME, USN journal, $LogFile, $I30, dan Recycle Bin'
researched_on: 2026-10-16
versions_checked: 'EZ Tools 2026.5.0 (MFTECmd dan RBCmd untuk .NET 4.7.2 dan .NET 9, Timeline Explorer dan Registry Explorer hanya .NET 9); README MFTECmd menampilkan banner 0.5.0.1 dan menerima $MFT, $J, $LogFile, $Boot, $SDS, sedangkan halaman resmi EZ Tools menulis $I30 didukung dan $LogFile coming soon; README RBCmd ($I format 1 Vista sampai 8.1, format 2 Windows 10 dan 11); NTFS di Windows 10 dan 11; Microsoft Learn USN_RECORD_V2 (ms.date 2018-12-05), Change Journals dan Creating, Modifying, and Deleting a Change Journal (diperbarui 2025-03-12), fsutil usn dan fsutil behavior (diperbarui 2026-02-16), File Times (diperbarui 2025-04-15), Master File Table (ms.date 2024-09-05), Use App Control to secure PowerShell (PowerShell 7.6, ms.date 2026-08-17)'
---

# Day 08: File system forensics ($MFT, MACB, SI vs FN, USN journal, $LogFile, $I30, Recycle Bin)

Cakupan: membaca metadata NTFS dari image disk ($MFT dengan dua set timestamp, USN journal, $LogFile, index direktori $I30, dan Recycle Bin) untuk menjawab apa yang terjadi pada file, apa yang tidak bisa dijawab file system, dan bagaimana menulis kesimpulannya untuk pembaca non-teknis.

## Ide inti

File system NTFS mencatat perubahan, bukan pembacaan. `$MFT` menyimpan keadaan terakhir setiap file (nama, induk, ukuran, dua set timestamp), USN journal (`$J`) menyimpan daftar perubahan yang terjadi pada file selama jendela waktu yang terbatas, dan Recycle Bin menyimpan file yang dihapus pengguna lewat Explorer beserta asal dan waktu hapusnya. Ketiganya sangat kuat untuk pertanyaan "kapan file ini dibuat, diubah, dipindah, atau dihapus". Ketiganya hampir tidak berguna untuk pertanyaan "apakah file ini dibaca atau disalin keluar": membuka dan membaca file tidak menulis record ke `$J`, dan pembaruan last access time di Windows modern sering dimatikan. Karena itu pekerjaan file system forensics selalu punya dua keluaran: jawaban tentang perubahan, dengan jendela waktunya, dan pernyataan jujur tentang pertanyaan yang harus dijawab sumber lain (event log, EDR, memori).

Kamu sudah mengenal pola ini dari NOC. Router menyimpan log perubahan konfigurasi: setiap baris yang ditambah, diubah, atau dihapus tercatat dengan waktunya, dan buffernya berputar sehingga perubahan lama hilang. Log itu tidak mencatat siapa yang menjalankan `show running-config`. Kalau manajer bertanya "apakah konfigurasi router ini dilihat orang luar?", log perubahan konfigurasi tidak bisa menjawab; yang bisa menjawab adalah accounting TACACS untuk perintah `show`. Bila accounting itu tidak aktif, jawaban yang benar adalah "tidak bisa dipastikan", bukan "tidak dilihat". `$J` adalah log perubahan konfigurasi milik file system, dan event log PowerShell atau EDR adalah accounting-nya.

```
pertanyaan tentang file
  |
  +-- dibuat / diubah / dipindah / dihapus?  --> $MFT (keadaan terakhir, SI dan FN)
  |                                             $J  (urutan perubahan, jendela terbatas)
  |                                             Recycle Bin ($I, $R), $I30 slack, $LogFile
  |
  +-- dibaca / dibuka / disalin keluar?      --> BUKAN file system:
  |                                             event log (4104), EDR, memori, log jaringan
  |
  +-- waktu bisa dipercaya?                  --> SI vs FN, $J FileCreate, BasicInfoChange,
                                                korelasi dengan Sysmon/EDR
hasil: jawaban + jendela waktu + keyakinan + "tidak bisa dijawab dari disk"
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan dan data pribadi 400 ribu pelanggan broadband. Kasusnya `INC-2026-019`: email dari `billing@vendor-tagihan.example` dengan lampiran `Tagihan-Okt-2026.zip` (berisi `Tagihan-Okt-2026.js`) diterima sembilan mailbox Senin 2026-10-12 pukul 15:58. Di laptop `JKT-WS-0388` milik staf penagihan `andi.pratama` (Windows 11, Microsoft Defender for Endpoint, Sysmon), ZIP disimpan ke folder Downloads pukul 16:04:48, `.js` dijalankan `wscript.exe` pukul 16:05:11, `upd.ps1` ditulis ke `C:\Users\andi.pratama\AppData\Roaming\SysCache\` pukul 16:05:19, dan scheduled task `\SysCacheUpdate` terdaftar pukul 16:06:02. Pukul 23:40 PowerShell script block logging mencatat isi `C:\Users\andi.pratama\Documents\export-tagihan.ps1` dibaca; skrip itu berisi password akun service `svc_billing`, yang dipakai untuk SSH ke server billing pukul 02:14 Selasa. Analisis memori oleh retainer PT Forensik Digital Contoh menambahkan satu temuan: loader di laptop Andi menjalankan pencarian file di Documents dan Desktop dengan kata kunci seperti password, svc, dan ssh. Laptop di-image (E15) Kamis 2026-10-15 pukul 09:00 lalu di-reimage; Jumat 08:10 Yoga Pratama, analyst L2 yang memegang bukti, membuat salinan kerja `E15-W1` di `\\jkt-evid01\cases\INC-2026-019\work\` setelah memverifikasi hash master. Rabu 2026-10-21 pukul 10:00, Sari Kusuma (technical lead) meneruskan pesan dari DPO PT JAB, Agus Setiawan, ke kanal `#inc-2026-019`:

> "Pak Agus butuh jawaban tertulis untuk rapat dengan Legal besok pagi, dan beliau minta dari disk laptop Andi, bukan dari dugaan. Tolong pakai E15-W1. Pertanyaannya: apakah `export-tagihan.ps1` disalin, diubah, atau dihapus penyerang? Apakah ada file lain di Documents atau Desktop Andi yang disalin, diubah, atau dihapus? Retainer bilang loader mencari file di dua folder itu; bisa tidak kita tahu file mana yang dibuka? Ada tanda waktu file dipalsukan, misalnya `upd.ps1` dibuat seolah-olah sudah lama ada? Ada file yang dihapus, dan kalau ada, isinya masih bisa diambil? Terakhir, seberapa yakin kita, dan apa yang memang tidak bisa dijawab dari disk?"

Pesan itu memuat enam pertanyaan:

1. Apakah `export-tagihan.ps1` diubah, dipindah, disalin di disk, atau dihapus?
2. Apakah file lain di Documents dan Desktop Andi berubah selama insiden?
3. Bisakah disk menunjukkan file mana yang dibuka atau dibaca loader?
4. Adakah tanda timestomping pada file penyerang?
5. Adakah file yang dihapus, dan apakah isinya masih bisa dipulihkan?
6. Seberapa yakin jawabannya, dan apa yang tidak bisa dijawab dari disk?

Pertanyaan 1 dijawab di bagian 1.1 dan 1.4, pertanyaan 2 di bagian 1.4, pertanyaan 3 di bagian 1.2, pertanyaan 4 di bagian 1.3, pertanyaan 5 di bagian 1.5 dan 1.6, dan pertanyaan 6 di bagian 1.7. Bagian 2 berisi perintah, hasil parse, dan jawaban tertulis yang kamu kirim ke Agus lewat Sari.

**Kapan relevan:** saat pertanyaan investigasi menyangkut file tertentu (kapan dibuat, diubah, dipindah, dihapus), saat waktu sebuah file dicurigai dipalsukan, saat file yang dihapus perlu ditemukan atau dipulihkan, dan saat membangun timeline aktivitas file dari triage atau image.
**Kapan bukan jawaban:** untuk membuktikan file dibaca, dibuka, atau dikirim keluar (pakai event log, EDR, memori, dan log jaringan; Day 05), untuk menentukan proses atau akun yang membuat perubahan (USN tidak mencatat pelakunya), dan untuk kejadian yang lebih tua dari jendela `$J` atau `$LogFile`. Isi file terhapus yang sudah ditimpa butuh carving dari image penuh (Day 01 bagian 1.2), di luar cakupan Day ini.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (salinan kerja, hash bukti, triage, copylog, `!EZParser`, container) tidak diulang. Tabel ini memuat istilah NTFS dan artefak file yang dipakai di Day ini; kolom padanan memakai analogi NOC dan SOC.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| `$MFT` (Master File Table) | Tabel berisi minimal satu entry untuk setiap file dan direktori di volume NTFS, termasuk `$MFT` sendiri | Inventaris perangkat di CMDB, satu baris per perangkat dengan atributnya |
| Entry number dan sequence number | Nomor baris di `$MFT` dan penghitung berapa kali baris itu dipakai ulang | Nomor rak di gudang dan nomor penghuni ke berapa |
| Resident dan non-resident | Isi file kecil disimpan di dalam entry `$MFT`; isi file besar di cluster lain yang dirujuk data runs | Konfigurasi pendek yang ditulis langsung di tiket vs lampiran terpisah |
| `$STANDARD_INFORMATION` (SI, `0x10`) | Atribut berisi empat timestamp yang ditampilkan Explorer dan bisa diubah lewat API biasa | Waktu di header file konfigurasi yang bisa diedit admin |
| `$FILE_NAME` (FN, `0x30`) | Atribut berisi nama, referensi induk, dan set timestamp kedua yang ditulis kernel saat file dibuat, dipindah, atau di-rename | Waktu commit yang dicatat perangkat saat konfigurasi disimpan |
| MACB | Modified, Accessed, Changed (entry `$MFT` berubah), Born (dibuat) | Waktu ubah isi, waktu dilihat, waktu metadata berubah, waktu dibuat |
| Timestomping | Mengubah timestamp file supaya terlihat lebih tua atau menyatu dengan file sistem | Mengubah jam router sebelum membuat perubahan supaya log tampak lama |
| USN change journal (`$UsnJrnl:$J`) | Log perubahan per volume: setiap perubahan pada file atau direktori dicatat dengan alasan dan waktunya | Log perubahan konfigurasi (`archive log config`), bukan accounting perintah `show` |
| Reason flags | Kode alasan di record USN, misalnya `FileCreate`, `DataExtend`, `RenameNewName`, `FileDelete`, `BasicInfoChange`, `Close` | Jenis perubahan di log konfigurasi: tambah, ubah, hapus |
| `$LogFile` | Log transaksi NTFS untuk pemulihan konsistensi volume; berputar cepat | Buffer debug yang sangat detail tetapi hanya menyimpan beberapa menit terakhir |
| `$I30` dan index slack | Index direktori berisi entry nama file anak; ruang sisa di index bisa masih memuat entry file yang sudah dihapus | Baris lama di tabel ARP yang sudah dilepas tetapi belum tertimpa |
| Recycle Bin (`$I`, `$R`) | Pasangan file per item yang dihapus lewat Explorer: `$I` metadata (path asal, ukuran, waktu hapus), `$R` isi | Rak barang retur sebelum dibuang, lengkap dengan label asal |
| Last access update | Pengaturan NTFS (`NtfsDisableLastAccessUpdate`) yang menentukan apakah timestamp Accessed diperbarui | Counter "last used" di NMS yang polling-nya bisa dimatikan |

### 1.1 `$MFT`: keadaan terakhir setiap file, bukan riwayatnya

Pertanyaan pertama Agus ("apakah `export-tagihan.ps1` diubah, dipindah, atau dihapus?") dimulai dari `$MFT`, karena di sanalah keadaan terakhir file itu tercatat.

NTFS adalah file system utama Windows dan Windows Server [S3], dan menyimpan `$MFT` sebagai file. Setiap file dan direktori punya minimal satu entry, termasuk `$MFT` itu sendiri; ukuran, timestamp, izin, dan isi file disimpan di entry `$MFT` atau di ruang luar yang dirujuk entry itu [S10]. Entry biasanya berukuran 1.024 byte [S1][S18]. Saat file dihapus, entry-nya ditandai bebas dan bisa dipakai ulang, tetapi ruang `$MFT` tidak menyusut [S10]. Selama entry belum dipakai ulang, metadata file yang dihapus masih bisa dibaca, dan MFTECmd menandainya dengan `InUse` false [S2].

Setiap entry memuat atribut. Tabel berikut berisi atribut yang dipakai Day ini; cari baris yang menyebut timestamp, karena keduanya akan dibandingkan di bagian 1.3.

| Atribut | Isi | Kegunaan forensik |
|---|---|---|
| `$STANDARD_INFORMATION` (`0x10`) | Empat timestamp MACB, flag atribut, ID security | Waktu yang biasa dilihat pengguna dan alat; mudah diubah |
| `$FILE_NAME` (`0x30`) | Nama, referensi entry induk, empat timestamp MACB kedua | Merekonstruksi path; pembanding untuk timestomping |
| `$DATA` | Isi file: resident bila kecil, non-resident bila besar | File resident yang dihapus kadang masih bisa diambil isinya dari entry |
| `$INDEX_ROOT` dan `$INDEX_ALLOCATION` | Index direktori (`$I30`) | Daftar isi folder, termasuk sisa entry file terhapus (bagian 1.5) |

Dua konsep lain sering menentukan kebenaran jawaban:

- **Resident dan non-resident.** File yang sangat kecil disimpan langsung di entry `$MFT`, kira-kira di bawah 700 byte menurut praktisi [S18]; angka persisnya bergantung isi entry, jadi jangan dipakai sebagai batas pasti. Bila file resident dihapus, tidak ada cluster yang dibebaskan, dan isinya bertahan sampai entry dipakai ulang [S18].
- **Path direkonstruksi dari referensi induk.** Atribut FN menyimpan nomor entry induk, bukan path lengkap. Alat seperti MFTECmd menyusun path dengan menelusuri induk satu per satu. Bila entry induk sudah dipakai ulang, path bisa salah atau kosong, sehingga dua file bernama sama di folder berbeda harus dibedakan lewat entry number dan sequence number.

Untuk Agus, `$MFT` hanya menjawab separuh pertanyaan. Ia menunjukkan bahwa `export-tagihan.ps1` masih ada di Documents saat image dibuat, dengan ukuran dan timestamp terakhirnya. Ia tidak menunjukkan apa yang terjadi pada file itu di antara dua titik waktu. Untuk itu dibutuhkan `$J` (bagian 1.4).

### 1.2 MACB dan last access: kenapa "Accessed" tidak bisa menjawab "dibuka atau tidak"

Pertanyaan ketiga Agus ("bisa tidak kita tahu file mana yang dibuka loader?") paling sering dijawab keliru dengan menunjuk kolom Accessed.

Atribut SI dan FN masing-masing menyimpan empat timestamp. Tabel ini menjelaskan arti tiap huruf; perhatikan baris C, karena huruf itu paling sering salah dibaca.

| Huruf | Nama di MFTECmd | Arti | Catatan |
|---|---|---|---|
| M | `LastModified` | Isi file terakhir diubah | Bisa lebih tua dari Born pada file salinan atau hasil ekstrak arsip (bagian 1.3) |
| A | `LastAccess` | File terakhir diakses | Bergantung pengaturan last access; pembaruan ke disk bisa ditunda sampai 1 jam |
| C | `LastRecordChange` | Entry `$MFT` terakhir berubah (metadata) | Bukan "Created"; berubah saat rename, perubahan atribut, atau perubahan timestamp lain |
| B | `Created` | File dibuat di volume ini | Untuk file salinan, ini waktu salinan dibuat, bukan waktu file aslinya |

NTFS menyimpan waktu dalam UTC sebagai jumlah interval 100 nanodetik, sehingga timestamp NTFS tidak terpengaruh zona waktu host [S9]. Semua keluaran EZ Tools juga UTC; laporan PT JAB memakai WIB (UTC+7).

Untuk timestamp A, dokumentasi Microsoft menulis dua hal. Pertama, NTFS menunda pembaruan last access time sampai paling lama 1 jam setelah akses terakhir [S9][S8]. Kedua, perilaku pembaruan diatur `fsutil behavior ... disablelastaccess`, yang menulis nilai registry `HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\NtfsDisableLastAccessUpdate` [S8]. Sejak Windows 10 1803, nilai registry itu berbentuk `0x8000000N` [S15], dan `fsutil` menampilkan empat mode [S14]:

| Nilai (`fsutil`) | Registry | Mode |
|---|---|---|
| 0 | `0x80000000` | User Managed, Last Access Updates Enabled |
| 1 | `0x80000001` | User Managed, Last Access Updates Disabled |
| 2 | `0x80000002` | System Managed, Last Access Updates Enabled |
| 3 | `0x80000003` | System Managed, Last Access Updates Disabled |

Pada mode System Managed, Windows yang memutuskan saat volume di-mount waktu boot. Sumber sekunder menyebut Windows tidak mengaktifkan pembaruan untuk volume besar, di atas 128 GB [S14]. Aturan ukuran ini tidak tercantum di dokumentasi Microsoft yang diperiksa, jadi jangan dipakai sebagai dasar; baca nilai registry dari hive SYSTEM di image dan uji perilakunya di build lab.

Konsekuensinya untuk Agus ada dua. Bila pembaruan last access mati, timestamp A berhenti di nilai lama (sering sama dengan waktu file dibuat), sehingga A yang lama tidak membuktikan file tidak dibaca. Bila pembaruan menyala, A hanya menyimpan akses terakhir, bukan daftar akses, dan bisa ditimpa oleh akses sah berikutnya (Andi sendiri, antivirus, indexer, atau responder yang mengambil file). Di `JKT-WS-0388`, nilai di hive SYSTEM E15 adalah `0x80000003` (bagian 2.3). Pencarian file oleh loader juga tidak menulis apa pun yang bisa dibaca dari `$J`, karena membaca dan mendaftar isi folder bukan perubahan (bagian 1.4). Jawaban jujurnya: disk tidak bisa menunjukkan file mana yang dibuka loader. Yang bisa ditunjukkan disk adalah daftar file yang ada di Documents dan Desktop saat itu, yaitu kumpulan file yang berpotensi terpapar.

### 1.3 SI vs FN: membaca indikasi timestomping dengan hati-hati

Pertanyaan keempat Agus ("`upd.ps1` dibuat seolah-olah sudah lama ada?") adalah pertanyaan tentang timestomping (MITRE ATT&CK T1070.006).

Dua set timestamp diperbarui oleh mekanisme yang berbeda:

- **SI** bisa diubah dari user mode. Fungsi Windows `SetFileTime` mengubah creation, last access, dan last write time tanpa mengubah isi file [S9]. Alat timestomping umum (yang disebut praktisi antara lain Cobalt Strike, Metasploit, dan Timestomp.exe) bekerja di atribut ini [S13].
- **FN** ditulis kernel saat file dibuat dan diperbarui pada keadaan yang lebih sempit, misalnya saat file di-rename atau dipindah [S13][S18]. FN tidak bisa diubah langsung lewat API Win32 standar [S18].

Dari perbedaan itu lahir heuristik dasar: bila SI Created jauh lebih tua daripada FN Created, SI kemungkinan diubah, karena dalam operasi normal file tidak bisa lahir sebelum entry namanya dibuat [S18]. MFTECmd menampilkan kedua set timestamp; secara default kolom `0x30` hanya diisi bila nilainya berbeda dari `0x10`, dan opsi `--at` memaksa semua timestamp FN ditampilkan [S11]. Praktisi juga memakai kolom penanda seperti `SI<FN` dan `uSecZeros` (subdetik nol di SI); nama dan logika kedua kolom ini perlu dicek di versi MFTECmd-mu.

Heuristik ini punya tiga batas yang harus ditulis setiap kali dipakai:

1. **FN bisa ikut berubah.** Inversecos (April 2022) mendemonstrasikan bahwa bila SI dipalsukan lalu file dipindah atau di-rename, Windows menyalin nilai SI yang palsu ke FN, sehingga keduanya sama-sama palsu dan perbandingan SI vs FN tidak menemukan apa pun [S13]. Di Windows lama tanpa PatchGuard, FN juga bisa diubah lewat native API [S13].
2. **Subdetik nol bisa dipalsukan, dan bisa wajar.** Alat yang lebih baru bisa menulis nilai subdetik sembarang, sehingga cek `.0000000` mudah dilewati [S13]. Sebaliknya, nilai bulat juga muncul secara wajar: format waktu FAT punya resolusi 2 detik untuk write time [S9], dan banyak format arsip menyimpan waktu dengan resolusi serupa, sehingga file hasil ekstrak arsip bisa punya Modified dengan subdetik nol. Perilaku ekstraksi Explorer di build lab perlu dicek.
3. **Modified lebih tua dari Created itu normal pada banyak file.** File salinan dan hasil ekstrak sering membawa Modified dari sumbernya, sementara Created adalah waktu file dibuat di volume ini. Pola ini dilaporkan luas oleh praktisi untuk salinan lokal di Windows; buktikan di lab untuk alat salin yang kamu pakai.

Karena itu deteksi yang lebih kuat datang dari sumber yang mencatat kejadian, bukan keadaan. Inversecos menyebut `$J` sebagai cara yang lebih andal: record `FileCreate` dan rename di `$J` membawa waktu nyata yang bertentangan dengan timestamp palsu di `$MFT` [S13]. Microsoft juga mendefinisikan reason `USN_REASON_BASIC_INFO_CHANGE` sebagai perubahan atribut atau satu atau lebih timestamp [S4], sehingga pemalsuan timestamp pada file yang masih di dalam jendela `$J` meninggalkan record `BasicInfoChange`. Record itu juga muncul untuk perubahan sah (alat ekstraksi atau salin yang memasang waktu dari sumbernya, perubahan atribut read-only), jadi ia penanda untuk diperiksa, bukan bukti. `$LogFile` bisa memuat operasi pembuatan atribut `$FILE_NAME` dengan nilai lama dan baru, tetapi sering cepat tertimpa di sistem sibuk [S13]. Korelasi terakhir datang dari luar file system: Sysmon EID 11 (file dibuat) dan timeline EDR untuk `upd.ps1`, Prefetch dan Amcache untuk executable (Day 07).

Untuk `INC-2026-019`, jawaban ke Agus dibangun dari empat lapis: SI dan FN `upd.ps1` sama, record `FileCreate` di `$J` jatuh pada detik yang sama, tidak ada `BasicInfoChange` setelahnya, dan Sysmon serta EDR mencatat penulisan file pada menit yang sama. Tidak ada satu lapis pun yang cukup sendirian (bagian 2.2 dan 2.4).

### 1.4 USN journal (`$J`): log perubahan dengan jendela terbatas dan tanpa pelaku

Pertanyaan pertama dan kedua Agus ("diubah, dipindah, atau dihapus?" untuk `export-tagihan.ps1` dan file lain di Documents dan Desktop) adalah pertanyaan tentang perubahan dalam rentang waktu. Itu pekerjaan `$J`.

NTFS memelihara satu USN change journal per volume. Setiap kali file atau direktori berubah, record baru ditambahkan di akhir journal berisi jenis perubahan dan nama objeknya [S5][S7]. Journal ini disimpan di `$Extend\$UsnJrnl`, stream `$J`, dan diparse MFTECmd [S2][S11]. Tabel berikut berisi reason flag yang paling sering dipakai dalam investigasi; kolom kanan menyebut cara membacanya [S4].

| Reason (MFTECmd) | Konstanta Microsoft | Arti | Cara membaca |
|---|---|---|---|
| `FileCreate` | `USN_REASON_FILE_CREATE` (`0x100`) | File atau direktori dibuat pertama kali | Waktu lahir yang dicatat kejadian, pembanding SI Created |
| `DataOverwrite`, `DataExtend`, `DataTruncation` | `0x1`, `0x2`, `0x4` | Isi ditimpa, ditambah, atau dipotong | Isi file berubah |
| `RenameOldName`, `RenameNewName` | `0x1000`, `0x2000` | Nama lama dan nama baru | Rename dan move menghasilkan dua record: induk lama dan induk baru |
| `FileDelete` | `0x200` | File atau direktori dihapus | Termasuk penghapusan oleh proses, yang tidak lewat Recycle Bin |
| `BasicInfoChange` | `0x8000` | Atribut atau satu atau lebih timestamp diubah | Penanda untuk diperiksa pada kasus timestomping |
| `SecurityChange` | `0x800` | Hak akses berubah | ACL diubah |
| `StreamChange`, `NamedData*` | `0x200000`, `0x10` sampai `0x40` | Stream bernama ditambah, dihapus, atau diubah | Misalnya alternate data stream |
| `Close` | `0x80000000` | File ditutup | Record penutup yang merangkum reason yang terkumpul sejak file dibuka |

Tiga sifat `$J` menentukan apa yang boleh ditulis di laporan:

1. **Tidak ada reason untuk membaca.** Daftar reason Microsoft hanya berisi perubahan: data, nama, atribut, timestamp, keamanan, stream [S4]. Membuka file, membaca isinya, atau mendaftar isi folder tidak menghasilkan record. Itu sebabnya pembacaan `export-tagihan.ps1` pukul 23:40 hanya terlihat di event log PowerShell 4104, dan pencarian file oleh loader hanya terlihat di memori.
2. **Tidak ada pelaku.** Record USN memuat nomor referensi file, nomor referensi induk, USN, timestamp UTC, reason, `SourceInfo`, `SecurityId`, atribut, dan nama [S4]. `SecurityId` adalah identitas security milik file atau direktori itu, bukan akun yang mengubahnya [S4], dan `SourceInfo` hanya berisi penanda sumber seperti manajemen data atau replikasi yang diset aplikasi tertentu [S4]. Siapa dan proses apa yang membuat perubahan harus dicari di Sysmon EID 11, EDR, atau artefak aplikasi.
3. **Jendela terbatas.** Journal punya `MaximumSize` dan `AllocationDelta`; pada checkpoint NTFS, journal dipangkas dari awal saat ukurannya melewati jumlah keduanya [S6][S7]. Berapa hari yang masih tersisa bergantung pada seberapa sibuk volume, jadi selalu ukur dari data: record pertama dan terakhir di `$J` adalah jendela jawabanmu. `fsutil usn queryjournal` menampilkan kapasitas journal di host hidup [S7]; di image, cukup baca record tertua.

Satu catatan anti-forensik: `fsutil usn deletejournal` menonaktifkan atau menghapus journal aktif, prosesnya lama karena seluruh entry `$MFT` disetel ulang USN-nya ke nol [S7]. Journal yang tiba-tiba hanya berisi beberapa jam terakhir di laptop yang sudah lama dipakai adalah alasan untuk mencari jejak penghapusan journal di event log dan Prefetch `FSUTIL.EXE` (Day 05, Day 07).

Di laptop Andi, `$J` memberi jawaban yang bisa dipegang untuk pertanyaan perubahan dalam jendela Minggu 2026-10-11 10:17 WIB sampai Kamis 2026-10-15 08:47 WIB: tidak ada record untuk `export-tagihan.ps1`, dan perubahan di Documents dan Desktop hanya pola simpan Excel milik Andi Selasa pagi (bagian 2.4). Satu jenis "salinan" juga bisa diperiksa dari `$J`: bila file disalin ke lokasi lain di volume yang sama, salinannya lahir sebagai `FileCreate` baru. Tidak ada record pembuatan file dengan nama, ukuran, atau ekstensi arsip yang cocok di profil Andi selama jendela itu. Penyalinan isi ke memori lalu pengiriman lewat kanal C2 tidak meninggalkan record apa pun.

### 1.5 `$LogFile` dan `$I30`: sumber tambahan dengan jendela dan bentuk yang berbeda

Pertanyaan kelima Agus ("ada file yang dihapus?") tidak cukup dijawab dengan `$J`, karena `$J` bisa sudah berputar dan hanya memuat nama, bukan isi. Dua sumber lain melengkapinya.

**`$LogFile`** adalah log transaksi NTFS yang dipakai untuk memulihkan konsistensi volume setelah kegagalan; NTFS menulis record ke file ini pada checkpoint [S6]. Isinya lebih rinci daripada `$J` (operasi redo dan undo pada atribut), tetapi ukurannya tetap dan cepat tertimpa di sistem yang sibuk [S13]. Nilainya terbesar saat image atau triage diambil tidak lama setelah kejadian, misalnya untuk melihat atribut `$FILE_NAME` yang dibuat ulang saat timestomping atau rename [S13]. Dukungan parser masih berubah: halaman resmi EZ Tools menulis dukungan `$LogFile` di MFTECmd sebagai "coming soon", sementara README MFTECmd sudah mencantumkan `$LogFile` sebagai input `-f` [S2][S11]. Cek di versi lab-mu sebelum mengandalkannya, dan catat alat yang dipakai bila memakai parser lain.

**`$I30`** adalah index direktori: daftar entry `$FILE_NAME` untuk anak-anak sebuah folder [S1]. Saat file dihapus, entry-nya dikeluarkan dari index, tetapi ruang sisa (slack) di blok index bisa masih memuat salinan entry lama sampai tertimpa [S1]. Dari slack itu kamu bisa menemukan nama file yang pernah ada di folder, beserta ukuran dan empat timestamp FN pada saat entry ditulis, meskipun entry `$MFT`-nya sudah dipakai ulang. Dua hal perlu diingat. Pertama, timestamp di entry slack adalah salinan timestamp FN, bukan waktu penghapusan. Kedua, slack tidak lengkap dan tidak berurutan; ketiadaan entry tidak membuktikan file tidak pernah ada. Halaman resmi EZ Tools mencantumkan `$I30` sebagai input MFTECmd [S2]; cara mengekspor atribut index dari image bergantung pada alat image yang kamu pakai, jadi uji di lab.

Untuk `INC-2026-019`, kedua sumber ini mengonfirmasi batas, bukan menambah temuan: `$LogFile` E15 hanya memuat aktivitas terakhir sebelum laptop dimatikan, dan slack `$I30` Documents dan Desktop hanya memuat nama file lama yang dihapus jauh sebelum insiden (bagian 2.6).

### 1.6 Recycle Bin: penghapusan oleh pengguna, terikat SID, isi masih ada

Pertanyaan kelima Agus punya jawaban konkret di Recycle Bin, dan jawabannya bukan dari penyerang.

Saat pengguna menghapus file lewat Explorer, Windows (Vista ke atas) membuat dua file di `C:\$Recycle.Bin\<SID pengguna>\` [S17]:

- `$I<6 karakter acak><ekstensi asli>`: metadata, berisi path asal, ukuran, dan waktu hapus (FILETIME).
- `$R<6 karakter yang sama><ekstensi asli>`: isi file atau folder yang dihapus.

Format `$I` berbeda antar versi Windows. Format 1 (Vista sampai 8.1) menyimpan path di field tetap 520 byte setelah header 24 byte; format 2 (Windows 10 dan 11) menyimpan path dengan panjang variabel mulai offset 28, didahului field 4 byte di offset 24 [S17][S12]. Field 4 byte itu dipakai parser sebagai panjang nama; posisinya cukup kamu ketahui untuk membaca hex bila parser gagal. RBCmd mem-parse kedua format beserta INFO2 dari Windows lama, mengeluarkan waktu dalam UTC, dan bila item yang dihapus adalah folder, ikut mendaftar isi folder `$R`-nya [S12].

Apa yang dibuktikan Recycle Bin:

- **Siapa:** folder per SID mengikat penghapusan ke profil pengguna yang menghapus.
- **Kapan dan dari mana:** waktu hapus dan path asal dari `$I`.
- **Isi:** selama Recycle Bin belum dikosongkan, `$R` adalah file aslinya. Penghapusan ke Recycle Bin di volume yang sama pada dasarnya adalah rename dan move, sehingga di `$J` terlihat sebagai pasangan `RenameOldName` di folder asal dan `RenameNewName` di folder Recycle Bin, ditambah `FileCreate` untuk `$I` [S4].

Apa yang tidak dibuktikan: penghapusan dengan Shift+Delete, penghapusan dari command line, atau penghapusan oleh proses tidak melewati Recycle Bin. Jejaknya hanya `FileDelete` di `$J`, entry `$MFT` dengan `InUse` false, dan mungkin slack `$I30`.

Di laptop Andi, `$I` menunjukkan `Tagihan-Okt-2026.zip` dari `C:\Users\andi.pratama\Downloads\` dihapus ke Recycle Bin Selasa 2026-10-13 pukul 11:12:40 WIB oleh profil `andi.pratama`. Waktunya empat menit setelah analyst L1 Gilang Ramadhan, atas permintaan Sari, menelepon Andi pukul 11:08 untuk memintanya tidak me-restart laptop dan menanyakan email "Tagihan Oktober 2026". Andi mengaku menghapus ZIP itu karena khawatir. Ini penghapusan oleh pengguna, bukan anti-forensik penyerang, dan isinya masih utuh di `$R` (bagian 2.5). Pelajarannya masuk ke panduan telepon SOC: minta pengguna tidak menghapus apa pun, bukan hanya tidak me-restart.

### 1.7 Menulis jawaban: jendela, keyakinan, dan yang tidak bisa dijawab disk

Pertanyaan keenam Agus ("seberapa yakin, dan apa yang tidak bisa dijawab dari disk?") adalah bagian yang menentukan apakah laporan file system bisa dipakai untuk keputusan UU PDP.

Setiap jawaban file system ditulis dengan empat unsur:

1. **Klaim:** apa yang terjadi atau tidak terjadi pada file.
2. **Jendela:** rentang waktu sumber yang dipakai (record pertama dan terakhir `$J`, waktu image).
3. **Dasar dan korelasi:** artefak mana, dan sumber di luar file system yang menguatkan atau membatasi.
4. **Keyakinan dan batas:** tinggi, sedang, atau rendah, dengan alasan, dan pertanyaan yang tidak bisa dijawab dari disk.

Tabel berikut memetakan pertanyaan umum ke sumber yang bisa dan tidak bisa menjawabnya. Baca kolom kanan sebelum menulis kata "tidak".

| Pertanyaan | File system bisa menjawab | File system tidak bisa menjawab |
|---|---|---|
| Apakah file diubah? | Ya, dalam jendela `$J`; di luar jendela hanya M dari SI yang bisa dipalsukan | Perubahan sebelum record tertua `$J` |
| Apakah file dihapus? | Ya: Recycle Bin, `FileDelete`, `InUse` false, slack `$I30` | Penghapusan di luar jendela yang entry-nya sudah dipakai ulang |
| Apakah file disalin di disk yang sama? | Sebagian: `FileCreate` file baru dengan nama, ukuran, atau ekstensi yang cocok | Salinan dengan nama dan format berbeda tanpa korelasi isi |
| Apakah file dibaca, dibuka, atau dikirim keluar? | Tidak | Butuh event log (4104), EDR, memori, log proxy dan firewall |
| Siapa yang mengubah? | Hanya untuk Recycle Bin (SID) | Untuk `$J` dan `$MFT`: butuh Sysmon EID 11, EDR, artefak aplikasi |
| Apakah waktu file asli? | Indikasi: SI vs FN, `FileCreate`, `BasicInfoChange` | Bukti pasti bila FN ikut dipalsukan dan `$J` sudah berputar |

Satu kelompok perubahan lagi wajib dipisahkan: tindakan responder. Di laptop Andi, Sari membaca isi `export-tagihan.ps1` lewat EDR Selasa sekitar 11:35, Yoga mengambil paket investigasi Defender pukul 12:31 dan menyalin `upd.ps1`, XML task, serta `export-tagihan.ps1` lewat live response `getfile` pukul 12:36, lalu mengambil memori dengan WinPmem dari `USB-E-07` pukul 12:42 sampai 12:53 dengan output ke USB. Pembacaan file oleh responder sama tidak terlihatnya di `$J` seperti pembacaan oleh penyerang, sedangkan file kerja sensor Defender dan file sementara alat bisa muncul sebagai `FileCreate` dan `FileDelete`. Daftar tindakan responder dengan waktunya adalah syarat untuk memisahkan keduanya; folder kerja persis yang ditulis paket investigasi dan alat akuisisi perlu dicek di lab atau dokumentasi Defender.

Untuk Agus, kalimat inti jawabannya: disk menunjukkan `export-tagihan.ps1` dan file lain di Documents dan Desktop tidak diubah, dipindah, atau dihapus selama insiden, kecuali penyimpanan rutin oleh Andi, dan tidak ada tanda waktu file dipalsukan; disk tidak bisa menunjukkan file mana yang dibaca atau dikirim keluar, sehingga `export-tagihan.ps1` diperlakukan sebagai terbaca (bukti dari event log), dan seluruh file di kedua folder diperlakukan sebagai berpotensi terpapar sampai sumber lain menunjukkan sebaliknya.

## 2. Contoh dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Nama kolom CSV dan format nilai bisa berbeda antar versi MFTECmd dan RBCmd; cocokkan dengan versi di lab-mu. Semua timestamp dari EZ Tools dalam UTC; laporan PT JAB memakai WIB (UTC+7), jadi setiap waktu penting ditulis keduanya sekali. Perintah ditulis untuk lingkungan PT JAB; untuk latihan, jalankan hanya di VM lab terisolasi (bagian 3).

### 2.1 Menyiapkan E15-W1 dan mengambil metafile tanpa menulis ke salinan kerja

Langkah ini menyiapkan bahan untuk semua jawaban ke Agus. Salinan kerja `E15-W1` sudah diverifikasi Yoga terhadap hash master Jumat 08:10. Di `JKT-DFIR01`, kamu menghitung ulang hash salinan kerja, me-mount volume sistemnya read-only sebagai `G:` dengan alat mount image yang sudah diuji di lab (alat dan format image dicatat di case notes; prinsipnya di Day 02 bagian 1.5), lalu menyalin metafile dengan KAPE supaya ada copylog.

```
C:\DFIR\tools\KAPE\kape.exe --tsource G: --target FileSystem,RegistryHives,RecycleBin_InfoFiles --tdest C:\DFIR\work\INC-2026-019\E15-W1\meta --tflush
```

- `--tsource G:`: volume sistem E15-W1 yang di-mount read-only.
- `--target FileSystem,RegistryHives,RecycleBin_InfoFiles`: target individual dari KapeFiles; `FileSystem` mengambil `$MFT`, `$LogFile`, `$J`, `$SDS`, `$Boot`, dan `$T`, `RecycleBin_InfoFiles` mengambil file `$I` (Day 03 bagian 1.2). Isi `$R` tidak diambil; RBCmd dan hash `$R` dijalankan langsung atas volume read-only (bagian 2.5).
- `--tdest ... --tflush`: folder baru khusus metafile E15-W1, jadi aman dikosongkan.

Keluaran ilustrasi (ringkas):

```
2026-10-21 10:22:05  Using Targets: FileSystem,RegistryHives,RecycleBin_InfoFiles
2026-10-21 10:24:51  Copied 31 files (deferred: 0). Skipped (deduped): 0
```

**Cara membaca hasil:** deferred copy nol karena volume image tidak sedang dipakai Windows mana pun, sehingga tidak ada file terkunci. Copylog mencatat `$MFT`, `$J`, `$LogFile`, hive SYSTEM, dan file `$I` dengan SHA-1 masing-masing; simpan bersama hasil analisis.

**Variasi:** MFTECmd juga bisa membaca `G:\$MFT` langsung dari volume yang di-mount, karena alat itu menangani file terkunci [S2]. Menyalin dengan KAPE lebih dulu memberi copylog sebagai bukti apa yang diparse.

**Kapan gagal:** volume di-mount read-write. Windows yang me-mount volume NTFS bisa menulis metadata, termasuk ke `$LogFile` dan `$J`, sehingga artefak yang sedang kamu periksa berubah. Hash salinan kerja sebelum dan sesudah mount, dan bila berubah, buat salinan kerja baru dari master.

### 2.2 `$MFT`: tiga file kasus, SI vs FN

Langkah ini menjawab pertanyaan pertama dan keempat Agus dari sisi `$MFT`.

```
MFTECmd.exe -f "C:\DFIR\work\INC-2026-019\E15-W1\meta\C\$MFT" --csv "\\jkt-evid01\cases\INC-2026-019\analysis\E15-W1\EZ-2026.5.0\FileSystem" --csvf E15-W1_MFT.csv --at
```

- `-f`: file yang diproses; path `C\$MFT` mengikuti struktur folder hasil KAPE.
- `--csv` dan `--csvf`: folder dan nama CSV, di area kerja kasus dengan nomor bukti dan versi alat (Day 02).
- `--at`: menampilkan semua timestamp `0x30`, bukan hanya yang berbeda dari `0x10` [S11]. Tanpa opsi ini kolom FN kosong untuk file yang SI dan FN-nya sama, dan kolom kosong mudah dibaca keliru sebagai "tidak ada data".

Filter tiga file kasus dengan PowerShell:

```powershell
$m = Import-Csv '\\jkt-evid01\cases\INC-2026-019\analysis\E15-W1\EZ-2026.5.0\FileSystem\E15-W1_MFT.csv'
$m | Where-Object { $_.FileName -in 'export-tagihan.ps1','upd.ps1','Tagihan-Okt-2026.js' } |
  Select-Object EntryNumber, SequenceNumber, InUse, ParentPath, FileName, FileSize,
    Created0x10, Created0x30, LastModified0x10, LastModified0x30,
    LastRecordChange0x10, LastAccess0x10
```

- `Import-Csv`: membaca CSV menjadi objek per baris.
- `-in`: mencocokkan nama file persis; tidak peka huruf besar-kecil.
- `Select-Object`: memilih entry dan sequence (identitas file), path induk, ukuran, dan timestamp SI serta FN.

Keluaran ilustrasi (UTC):

```
EntryNumber          : 118734
SequenceNumber       : 4
InUse                : True
ParentPath           : .\Users\andi.pratama\Documents
FileName             : export-tagihan.ps1
FileSize             : 2316
Created0x10          : 2026-09-11 07:20:33.4182297
Created0x30          : 2026-09-11 07:20:33.4182297
LastModified0x10     : 2026-08-24 03:02:51.7731904
LastModified0x30     : 2026-09-11 07:20:33.4182297
LastRecordChange0x10 : 2026-09-11 07:20:33.4182297
LastAccess0x10       : 2026-09-11 07:20:33.4182297

EntryNumber          : 287903
SequenceNumber       : 2
InUse                : True
ParentPath           : .\Users\andi.pratama\AppData\Roaming\SysCache
FileName             : upd.ps1
FileSize             : 4812
Created0x10          : 2026-10-12 09:05:19.2207415
Created0x30          : 2026-10-12 09:05:19.2207415
LastModified0x10     : 2026-10-12 09:05:19.2681093
LastModified0x30     : 2026-10-12 09:05:19.2207415
LastRecordChange0x10 : 2026-10-12 09:05:19.2681093
LastAccess0x10       : 2026-10-12 09:05:19.2207415

EntryNumber          : 287896
SequenceNumber       : 3
InUse                : True
ParentPath           : .\Users\andi.pratama\AppData\Local\Temp\Temp1_Tagihan-Okt-2026.zip
FileName             : Tagihan-Okt-2026.js
FileSize             : 9216
Created0x10          : 2026-10-12 09:05:09.6635170
Created0x30          : 2026-10-12 09:05:09.6635170
LastModified0x10     : 2026-10-12 00:58:14.0000000
LastModified0x30     : 2026-10-12 09:05:09.6635170
LastRecordChange0x10 : 2026-10-12 09:05:09.6702281
LastAccess0x10       : 2026-10-12 09:05:09.6635170
```

**Cara membaca hasil:**

- **`export-tagihan.ps1`:** file masih ada (`InUse` True) di Documents. Dibuat di volume ini Jumat 2026-09-11 14:20:33 WIB; Modified 2026-08-24 10:02:51 WIB lebih tua dari Created, pola khas file yang disalin dari tempat lain (staf penagihan memakai skrip yang sama dari share tim). SI dan FN Created sama. LastRecordChange tidak berubah sejak file dibuat, artinya tidak ada rename atau perubahan atribut yang tercatat di entry. LastAccess juga berhenti di waktu pembuatan, padahal Andi menjalankan skrip ini berkali-kali sejak September dan terakhir Senin 14:02; itu konsisten dengan pembaruan last access yang mati (bagian 2.3), bukan bukti file tidak dibuka.
- **`upd.ps1`:** dibuat Senin 2026-10-12 16:05:19 WIB, ukuran 4.812 byte. SI dan FN Created identik sampai subdetik, dan Modified hanya 47 milidetik setelah Created, konsisten dengan file yang ditulis sekali oleh proses. Tidak ada indikasi timestomping dari `$MFT`; konfirmasi dengan `$J` (bagian 2.4).
- **`Tagihan-Okt-2026.js`:** diekstrak ke folder sementara Senin 16:05:09 WIB, dua detik sebelum `wscript.exe` mulai 16:05:11 (Day 05). Modified Senin 07:58:14 WIB lebih tua dari Created dan subdetiknya nol. Ini pola wajar file hasil ekstrak arsip yang membawa waktu dari dalam ZIP (bagian 1.3), bukan timestomping: SI dan FN Created sama, dan Created cocok dengan kejadian lain di detik yang sama. Nama folder `Temp1_<nama arsip>` adalah perilaku umum Explorer saat file dibuka dari dalam ZIP; nama persisnya perlu dicek di build lab.

**Variasi:** inventaris kedua folder Andi untuk Agus:

```powershell
$m | Where-Object { $_.InUse -eq 'True' -and $_.IsDirectory -eq 'False' -and
     ($_.ParentPath -like '.\Users\andi.pratama\Documents*' -or
      $_.ParentPath -like '.\Users\andi.pratama\Desktop*') } |
  Select-Object ParentPath, FileName, FileSize, Created0x10, LastModified0x10 |
  Export-Csv '\\jkt-evid01\cases\INC-2026-019\analysis\E15-W1\inventaris-documents-desktop.csv' -NoTypeInformation
```

Keluaran ilustrasi: 41 baris (29 di Documents dan subfoldernya, 12 di Desktop). Daftar ini adalah kumpulan file yang berpotensi terpapar oleh pencarian loader; klasifikasi isinya (mengandung data pribadi atau tidak) dikerjakan DPO bersama Andi dan atasannya, bukan dari metadata.

**Kapan gagal:** `--at` tidak dipakai lalu kolom `0x30` kosong dibaca sebagai "FN tidak ada"; atau zona waktu tidak dikonversi sehingga Modified `00:58:14` UTC dibaca sebagai dini hari WIB dan dikira aktivitas malam.

### 2.3 Membaca pengaturan last access dari hive SYSTEM

Langkah ini memberi dasar untuk jawaban pertanyaan ketiga: kolom LastAccess bisa atau tidak bisa dipakai di host ini.

Buka hive `SYSTEM` hasil koleksi (`...\meta\C\Windows\System32\config\SYSTEM`) di Registry Explorer, bukan dengan `reg load` di workstation analisis, supaya hive tidak dimodifikasi. Tentukan control set aktif dari `Select\Current`, lalu baca:

```
ControlSet001\Control\FileSystem
  NtfsDisableLastAccessUpdate    REG_DWORD    0x80000003
```

- `Select\Current` bernilai 1 di contoh ini, sehingga control set yang relevan adalah `ControlSet001`. Di host hidup, path yang sama terlihat sebagai `CurrentControlSet` [S8].
- `0x80000003`: System Managed, Last Access Updates Disabled [S14][S15].

**Cara membaca hasil:** pembaruan last access mati di laptop Andi (SSD 512 GB). Kolom LastAccess di `$MFT` E15 tidak boleh dipakai untuk menyatakan file dibuka atau tidak dibuka, dan nilai LastAccess `export-tagihan.ps1` yang berhenti di 11 September (bagian 2.2) sesuai dengan pengaturan ini.

**Variasi:** di host hidup atau VM lab, `fsutil behavior query disablelastaccess` menampilkan mode yang sama dalam bentuk teks [S8][S14]. Bandingkan dengan nilai registry dan catat keduanya.

**Kapan gagal:** nilai dibaca dari control set yang salah, atau mode berubah setelah reboot karena System Managed (diputuskan saat volume di-mount waktu boot [S14]). Catat waktu boot terakhir dari event log (Day 05) bersama nilainya.

### 2.4 `$J`: jendela, file kasus, Documents dan Desktop, dan penghapusan

Langkah ini menjawab pertanyaan pertama, kedua, keempat, dan kelima Agus dari sisi perubahan.

```
MFTECmd.exe -f "C:\DFIR\work\INC-2026-019\E15-W1\meta\C\$Extend\$J" --csv "\\jkt-evid01\cases\INC-2026-019\analysis\E15-W1\EZ-2026.5.0\FileSystem" --csvf E15-W1_J.csv
```

- `-f`: stream `$J` yang disalin KAPE; lokasinya di dalam folder `$Extend` hasil koleksi perlu dicek di copylog.
- Kolom `ParentPath` di output `$J` diisi dengan merujuk entry induk; untuk induk yang sudah dihapus, path bisa kosong. Cek di versi MFTECmd-mu apakah resolusi path butuh `$MFT` dari koleksi yang sama.

**Kueri 1: jendela journal.**

```powershell
$j = Import-Csv '\\jkt-evid01\cases\INC-2026-019\analysis\E15-W1\EZ-2026.5.0\FileSystem\E15-W1_J.csv'
$j.Count
($j | Sort-Object UpdateTimestamp | Select-Object -First 1).UpdateTimestamp
($j | Sort-Object UpdateTimestamp | Select-Object -Last 1).UpdateTimestamp
```

Keluaran ilustrasi:

```
287416
2026-10-11 03:17:52.0845519
2026-10-15 01:46:30.9917702
```

**Cara membaca hasil:** jendela `$J` E15 adalah Minggu 2026-10-11 10:17:52 WIB sampai Kamis 2026-10-15 08:47:50 WIB, saat laptop dimatikan untuk image. Seluruh insiden (Senin 15:58 sampai containment) ada di dalam jendela, sehingga "tidak ada record" di bawah berarti tidak ada perubahan selama jendela itu, bukan "tidak tahu". Perubahan sebelum Minggu pagi tidak bisa dinilai dari `$J`.

**Kueri 2: record untuk `export-tagihan.ps1`.**

```powershell
$j | Where-Object Name -eq 'export-tagihan.ps1' | Measure-Object
```

Keluaran ilustrasi: `Count : 0`.

**Cara membaca hasil:** dalam jendela di atas, file itu tidak dibuat, tidak ditulis, tidak di-rename atau dipindah, tidak berubah timestamp atau atributnya, dan tidak dihapus. Pembacaan pukul 23:40:17 Senin (event 4104, Day 05), eksekusi oleh Andi, serta pembacaan oleh Sari dan Yoga Selasa siang tidak muncul, karena membaca bukan perubahan (bagian 1.4).

**Kueri 3: perubahan di Documents dan Desktop selama insiden.**

```powershell
$j | Where-Object { ($_.ParentPath -like '*\andi.pratama\Documents*' -or $_.ParentPath -like '*\andi.pratama\Desktop*') -and
                    $_.UpdateTimestamp -ge '2026-10-12 08:58' -and $_.UpdateTimestamp -lt '2026-10-13 09:00' } |
  Select-Object UpdateTimestamp, ParentPath, Name, UpdateReasons
```

- Rentang `2026-10-12 08:58` sampai `2026-10-13 09:00` UTC adalah Senin 15:58 WIB (email diterima) sampai Selasa 16:00 WIB (isolasi). Format waktu MFTECmd (`yyyy-MM-dd HH:mm:ss.fffffff`) bisa dibandingkan sebagai teks karena urutannya tahun ke detik.

Keluaran ilustrasi:

```
UpdateTimestamp              ParentPath                       Name                              UpdateReasons
2026-10-13 01:24:07.1183920  .\Users\andi.pratama\Desktop     ~$Rekap-Penagihan-Okt-2026.xlsx   FileCreate|DataExtend|Close
2026-10-13 01:31:44.5520671  .\Users\andi.pratama\Desktop     Rekap-Penagihan-Okt-2026.xlsx     DataOverwrite|DataExtend|Close
2026-10-13 01:52:18.0047395  .\Users\andi.pratama\Desktop     ~$Rekap-Penagihan-Okt-2026.xlsx   FileDelete|Close
```

**Cara membaca hasil:** satu-satunya aktivitas adalah buku kerja Excel di Desktop yang dibuka dan disimpan Selasa 08:24 sampai 08:52 WIB, beserta file pemilik `~$` yang dibuat dan dihapus Excel. Jam kerja, nama file, dan pola ini cocok dengan pekerjaan rutin Andi, dan Andi mengonfirmasinya; jump list Excel bisa menguatkan (Day 10). Pola simpan Office persisnya (file sementara, rename) bergantung versi Office; cek di lab sebelum menjadikannya patokan. `$J` sendiri tidak menyebut proses atau akun pelakunya (bagian 1.4).

**Kueri 4: urutan file kasus dan tanda timestomping.**

```powershell
$names = 'Tagihan-Okt-2026.zip','Temp1_Tagihan-Okt-2026.zip','Tagihan-Okt-2026.js','SysCache','upd.ps1','SysCacheUpdate'
$j | Where-Object { $_.Name -in $names -or $_.Name -like '$?7K2QXD*' } |
  Sort-Object UpdateTimestamp | Select-Object UpdateTimestamp, ParentPath, Name, UpdateReasons
```

- `$names`: nama yang dikenal dari kasus, termasuk folder.
- `-like '$?7K2QXD*'`: menangkap pasangan file Recycle Bin (`$I7K2QXD.zip` dan `$R7K2QXD.zip`) yang namanya diketahui dari RBCmd (bagian 2.5). Tanda kutip tunggal mencegah PowerShell membaca `$` sebagai variabel.

Keluaran ilustrasi (diringkas; record `Close` yang hanya mengulang reason dihilangkan kecuali yang penting):

```
UpdateTimestamp              ParentPath                                        Name                         UpdateReasons
2026-10-12 09:04:48.1093321  .\Users\andi.pratama\Downloads                    Tagihan-Okt-2026.zip         FileCreate
2026-10-12 09:04:48.3920117  .\Users\andi.pratama\Downloads                    Tagihan-Okt-2026.zip         DataExtend|FileCreate|Close
2026-10-12 09:05:09.6635170  .\Users\andi.pratama\AppData\Local\Temp           Temp1_Tagihan-Okt-2026.zip   FileCreate|Close
2026-10-12 09:05:09.6635170  .\Users\...\Temp\Temp1_Tagihan-Okt-2026.zip       Tagihan-Okt-2026.js          FileCreate
2026-10-12 09:05:09.6702281  .\Users\...\Temp\Temp1_Tagihan-Okt-2026.zip       Tagihan-Okt-2026.js          DataExtend|BasicInfoChange|FileCreate|Close
2026-10-12 09:05:19.2207415  .\Users\andi.pratama\AppData\Roaming              SysCache                     FileCreate|Close
2026-10-12 09:05:19.2207415  .\Users\andi.pratama\AppData\Roaming\SysCache     upd.ps1                      FileCreate
2026-10-12 09:05:19.2681093  .\Users\andi.pratama\AppData\Roaming\SysCache     upd.ps1                      DataExtend|FileCreate|Close
2026-10-12 09:06:02.4417730  .\Windows\System32\Tasks                          SysCacheUpdate               FileCreate|DataExtend|Close
2026-10-13 04:12:40.5498730  .\$Recycle.Bin\S-1-5-21-...-4127                  $I7K2QXD.zip                 FileCreate|DataExtend|Close
2026-10-13 04:12:40.5512068  .\Users\andi.pratama\Downloads                    Tagihan-Okt-2026.zip         RenameOldName
2026-10-13 04:12:40.5512068  .\$Recycle.Bin\S-1-5-21-...-4127                  $R7K2QXD.zip                 RenameNewName
2026-10-13 04:12:40.5530119  .\$Recycle.Bin\S-1-5-21-...-4127                  $R7K2QXD.zip                 RenameNewName|Close
```

**Cara membaca hasil:**

- **Urutan Senin (WIB):** ZIP disimpan 16:04:48, folder sementara dan `.js` dibuat 16:05:09, folder `SysCache` dan `upd.ps1` 16:05:19, file task 16:06:02. Waktu `FileCreate` sama dengan SI Created di `$MFT` sampai subdetik, dan cocok dengan Sysmon EID 11 serta timeline EDR. Ini lapis kedua yang mematahkan dugaan timestomping `upd.ps1` (bagian 1.3).
- **`BasicInfoChange` pada `.js`:** muncul satu kali, di detik yang sama dengan pembuatannya. Itu konsisten dengan proses ekstraksi yang memasang Modified dari dalam ZIP (bagian 2.2), bukan pemalsuan belakangan. Bila Explorer di build lab ternyata tidak memasang waktu dari arsip, record ini perlu dijelaskan ulang.
- **Tidak ada `BasicInfoChange` untuk `upd.ps1`** setelah dibuat. File itu juga tidak di-rename atau dipindah, sehingga skenario "SI dipalsukan lalu dipindah supaya FN ikut" (bagian 1.3) tidak terjadi dalam jendela `$J`.
- **Selasa 11:12:40 WIB:** `$I7K2QXD.zip` dibuat dan ZIP berpindah dari Downloads ke folder Recycle Bin milik SID Andi sebagai `$R7K2QXD.zip`. Ini pola penghapusan ke Recycle Bin (bagian 1.6). `$R` mempertahankan entry `$MFT` yang sama dengan ZIP asal, karena yang terjadi adalah rename.

**Kueri 5: penghapusan di profil Andi selama insiden.**

```powershell
$j | Where-Object { $_.UpdateReasons -like '*FileDelete*' -and $_.ParentPath -like '*\Users\andi.pratama*' -and
                    $_.UpdateTimestamp -ge '2026-10-12 08:58' -and $_.UpdateTimestamp -lt '2026-10-13 09:00' } |
  Group-Object { $_.Name -replace '_[a-z0-9]{8}\.[a-z0-9]{3}', '_<acak>' } | Select-Object Count, Name
```

- `Group-Object` dengan `-replace`: menyatukan nama file sementara yang hanya berbeda di bagian acak, supaya pola berulang terlihat sebagai satu baris.

Keluaran ilustrasi:

```
Count Name
----- ----
   96 __PSScriptPolicyTest_<acak>.ps1
   96 __PSScriptPolicyTest_<acak>.psm1
    1 ~$Rekap-Penagihan-Okt-2026.xlsx
   23 (file cache browser dan Office, diringkas)
```

**Cara membaca hasil:** penghapusan terbanyak adalah pasangan `__PSScriptPolicyTest_*.ps1` dan `.psm1` di folder Temp. PowerShell membuat dua file sementara dengan pola nama itu dan mencoba menjalankannya untuk mendeteksi apakah AppLocker menegakkan kebijakan [S16]; setiap kali task `\SysCacheUpdate` menjalankan `powershell.exe`, pasangan itu dibuat lalu dihapus lagi. Jumlah 96 pasang cocok dengan satu `powershell.exe -enc` awal dari `wscript.exe` ditambah 95 eksekusi task tiap 15 menit dalam rentang filter, yang berakhir saat isolasi Selasa 16:00 WIB (jam trigger pertama dibaca dari XML task). Isolasi tidak menghentikan task; ia tetap berjalan sampai laptop dimatikan Kamis pagi (Day 05), jadi pasangan file yang sama terus muncul di luar rentang ini. Ini jejak tak langsung bahwa PowerShell berjalan berulang, bukan file penyerang yang dihapus. Tidak ada `FileDelete` di Documents, Desktop, atau folder `SysCache` selain file pemilik Excel. Apakah PowerShell di build-mu membuat file itu di setiap start perlu dicek di lab.

**Variasi:** cari arsip baru di seluruh volume selama insiden dengan `$_.Name -match '\.(zip|7z|rar|cab)$' -and $_.UpdateReasons -like '*FileCreate*'`, untuk menguji hipotesis "data dikemas sebelum dikirim". Di E15 hasilnya hanya ZIP lampiran dan pasangan `$I`/`$R`-nya.

**Kapan gagal:** filter `ParentPath` dipakai untuk record yang induknya tidak terselesaikan sehingga baris penting tidak ikut; untuk pertanyaan yang menentukan, filter juga dengan `ParentEntryNumber` folder dari `$MFT`. Atau rentang waktu ditulis dalam WIB padahal kolomnya UTC.

### 2.5 Recycle Bin: siapa, kapan, dan isi yang masih ada

Langkah ini menjawab pertanyaan kelima Agus untuk satu-satunya file kasus yang dihapus.

```
RBCmd.exe -d "G:\$Recycle.Bin" --csv "\\jkt-evid01\cases\INC-2026-019\analysis\E15-W1\EZ-2026.5.0\FileDeletion" --csvf E15-W1_RB.csv
```

- `-d`: memproses folder secara rekursif, semua subfolder SID [S12]. Volume `G:` read-only, jadi RBCmd hanya membaca.
- `--csv` dan `--csvf`: folder dan nama hasil [S12].

Keluaran ilustrasi (kolom diringkas; cek nama kolom di versi-mu):

```
SourceName                                                       FileSize  DeletedOn             FileName
G:\$Recycle.Bin\S-1-5-21-2847193650-1938475021-3765120984-4127\  3371      2026-10-13 04:12:40   C:\Users\andi.pratama\Downloads\Tagihan-Okt-2026.zip
  $I7K2QXD.zip
```

Lalu hash isi `$R` dan bandingkan dengan lampiran asli yang diekspor dari mailbox (E10):

```powershell
Get-FileHash -Path 'G:\$Recycle.Bin\S-1-5-21-2847193650-1938475021-3765120984-4127\$R7K2QXD.zip' -Algorithm SHA256 |
  Format-List Hash, Path
```

Keluaran ilustrasi: `Hash : B3F0...` (cocok dengan hash `Tagihan-Okt-2026.zip` di E10).

**Cara membaca hasil:**

- SID dengan RID `4127` dipetakan ke `andi.pratama` lewat `ProfileList` di hive SOFTWARE (Day 09). Penghapusan dilakukan dari profil Andi, Selasa 11:12:40 WIB, empat menit setelah telepon Gilang (bagian 1.6).
- `$R` masih ada, sehingga isinya tidak perlu dipulihkan dengan carving. Hash yang cocok dengan E10 membuktikan file di disk adalah lampiran yang sama dengan yang diterima. Salinan `$R` boleh diserahkan ke retainer sebagai item turunan dengan hash-nya sendiri; jangan dibuka di `JKT-DFIR01`.
- Tidak ada item lain di Recycle Bin profil Andi dengan waktu hapus di jendela insiden.

**Variasi:** bila RBCmd gagal membaca satu `$I`, buka file itu di hex viewer: 8 byte versi (`02` untuk Windows 10 dan 11), 8 byte ukuran, 8 byte FILETIME waktu hapus, 4 byte di offset 24, lalu path UTF-16 (bagian 1.6) [S17].

**Kapan gagal:** Recycle Bin sudah dikosongkan. Pasangan `$I` dan `$R` hilang, dan yang tersisa hanya `FileDelete` untuk keduanya di `$J`, entry `$MFT` dengan `InUse` false, dan kemungkinan isi di unallocated yang butuh carving.

### 2.6 `$LogFile` dan `$I30`: memastikan batas, bukan mencari temuan baru

Langkah ini melengkapi jawaban pertanyaan kelima dan keenam dengan pernyataan batas yang bisa diperiksa orang lain.

Untuk `$LogFile`, ukuran dan jendela dibaca dari data:

```powershell
$m | Where-Object { $_.FileName -eq '$LogFile' -and $_.ParentPath -eq '.' } | Select-Object EntryNumber, FileSize
```

Keluaran ilustrasi: `EntryNumber 2, FileSize 67108864` (64 MiB). Parse dengan parser `$LogFile` yang sudah diuji di lab menunjukkan transaksi tertua yang masih terbaca Kamis 2026-10-15 sekitar 05:10 WIB. Laptop terus menulis meski terisolasi (task tiap 15 menit, event log, sensor EDR), sehingga `$LogFile` sudah berputar jauh melewati Senin dan Selasa. Kesimpulannya ditulis sebagai batas: `$LogFile` E15 tidak mencakup jendela insiden.

Untuk `$I30`, index folder Documents dan Desktop diekspor dari image dengan alat yang bisa menampilkan atribut index, lalu diparse:

```
MFTECmd.exe -f "C:\DFIR\work\INC-2026-019\E15-W1\I30\Documents_$I30" --csv "\\jkt-evid01\cases\INC-2026-019\analysis\E15-W1\EZ-2026.5.0\FileSystem" --csvf E15-W1_I30_Documents.csv
```

Keluaran ilustrasi (entry dari slack saja):

```
FromSlack  FileName                       FileSize  Created0x30           LastModified0x30
True       Draft-Surat-Tagihan-Sep.docx   48211     2026-09-02 02:11:40   2026-09-02 02:11:40
True       Rekap-Penagihan-Agu-2026.xlsx  71830     2026-08-03 01:05:22   2026-08-03 01:05:22
```

**Cara membaca hasil:** slack memuat dua nama file lama dengan timestamp FN dari Agustus dan September; timestamp itu adalah waktu entry ditulis, bukan waktu penghapusan (bagian 1.5). Tidak ada nama yang berkaitan dengan insiden atau dengan `export-tagihan.ps1`. Ketiadaan entry tidak membuktikan tidak ada penghapusan, tetapi untuk jendela insiden `$J` sudah menjawab lebih kuat. Nama kolom dan cara MFTECmd menandai entry slack perlu dicek di versi-mu.

**Kapan gagal:** alat ekspor `$I30` tidak tersedia atau formatnya tidak dikenali MFTECmd. Catat sebagai "tidak diperiksa" beserta alasannya; jangan menulis "tidak ada".

### 2.7 Jawaban tertulis untuk Agus

Jawaban ini dikirim ke Sari pukul 15:40 untuk diteruskan ke Agus. Baca kolom "Keyakinan dan batas" lebih dulu, karena kolom itulah yang dipakai Legal.

| Pertanyaan | Jawaban | Dasar | Keyakinan dan batas |
|---|---|---|---|
| `export-tagihan.ps1` diubah, dipindah, disalin di disk, atau dihapus? | Tidak, dalam jendela Minggu 10:17 sampai Kamis 08:47 WIB. File masih utuh di Documents saat image dibuat | `$J` tanpa record; `$MFT` (M 24 Agustus, C tidak berubah); tidak ada `FileCreate` salinan atau arsip | Tinggi untuk perubahan di disk. Sebelum Minggu pagi hanya dari `$MFT` |
| `export-tagihan.ps1` dibaca? | Ya, Senin 23:40:17 WIB | PowerShell 4104 (Day 05), bukan file system | Tinggi. Disk tidak bisa menunjukkan pembacaan; anggap isinya terpapar |
| File lain di Documents dan Desktop berubah? | Tidak, kecuali penyimpanan rutin `Rekap-Penagihan-Okt-2026.xlsx` oleh Andi Selasa 08:24 sampai 08:52 | `$J` kueri 3; konfirmasi Andi | Tinggi untuk perubahan. Pelaku tidak tercatat di `$J` |
| File mana yang dibuka loader? | Tidak bisa ditentukan dari disk. 41 file ada di kedua folder saat itu (daftar terlampir) | Inventaris `$MFT`; last access mati (`0x80000003`); memori retainer menunjukkan pencarian dengan kata kunci | Seluruh 41 file diperlakukan berpotensi terpapar sampai klasifikasi isi selesai |
| Timestomping? | Tidak ada indikasi pada `upd.ps1`, `.js`, dan file task | SI = FN; `FileCreate` cocok dengan SI dan Sysmon/EDR; tidak ada `BasicInfoChange` setelah pembuatan selain ekstraksi `.js` | Sedang-tinggi. Teknik yang memalsukan SI dan FN sekaligus tetap mungkin, tetapi bertentangan dengan `$J` dan telemetry |
| File dihapus, dan isinya? | `Tagihan-Okt-2026.zip` dihapus Andi ke Recycle Bin Selasa 11:12:40 WIB setelah ditelepon SOC; isi utuh, hash cocok dengan lampiran asli. Tidak ada penghapusan oleh penyerang di profil Andi | RBCmd, `$J`, hash `$R` | Tinggi dalam jendela `$J`. `$LogFile` tidak mencakup jendela insiden |
| Disalin keluar lewat jaringan? | Tidak bisa dijawab dari disk | Butuh log proxy dan firewall, memori | Lihat temuan jaringan; volume per aplikasi dari SRUM (Day 07) |

Kalimat pengantar ke Agus: "Dari disk laptop Andi kami bisa menyatakan file skrip berpassword dan file lain di Documents dan Desktop tidak diubah atau dihapus penyerang selama insiden, dan tidak ada tanda waktu file dipalsukan. Disk tidak mencatat pembacaan file, jadi file skrip itu kami perlakukan sebagai terbaca, karena log PowerShell mencatatnya dibaca Senin 23:40, dan 41 file lain di dua folder itu kami perlakukan sebagai berpotensi terpapar sampai isinya diklasifikasi."

**Kapan gagal:** jawaban ditulis tanpa jendela waktu atau tanpa kolom batas, lalu dibaca sebagai "file tidak disentuh sama sekali". Kalimat "tidak ada jejak di file system" harus selalu diikuti "file system tidak mencatat pembacaan".

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** lab dari Day 02: VM korban `LAB-WS01` (Windows 11, Sysmon, snapshot `bersih-2026-10-15`), VM analisis `LAB-DFIR01` dengan KAPE, MFTECmd, RBCmd, Timeline Explorer, dan Registry Explorer, jaringan host-only `172.16.50.0/24`. Folder kasus lab `CASE-2026-LAB-008`. Semua file uji adalah teks jinak buatanmu sendiri. Jangan memakai data, nama, atau kejadian dari pekerjaan nyata.

1. **Catat kondisi awal.** Di `LAB-WS01`, jalankan `fsutil behavior query disablelastaccess` dan `fsutil usn queryjournal C:`, lalu catat mode last access dan kapasitas journal. Catat juga ukuran volume C:.
2. **Baca tanpa ubah.** Buat `C:\Users\<user lab>\Documents\rahasia-lab.txt` berisi satu baris. Tunggu satu menit, lalu baca isinya tiga kali dengan `Get-Content`. Catat waktu setiap langkah.
3. **Ubah dan rename.** Tambahkan satu baris ke file itu, lalu rename menjadi `rahasia-lab2.txt`, lalu pindahkan ke `C:\Users\<user lab>\Desktop\`.
4. **Timestomp jinak.** Buat `C:\Users\<user lab>\AppData\Roaming\LabCache\uji.ps1` berisi `Write-Output "lab"`. Ubah SI Created dengan `(Get-Item <path>).CreationTime = '2021-03-14 09:00:00'` dan catat waktunya. Lalu pindahkan file itu ke folder `C:\Users\<user lab>\AppData\Local\Temp\` dan catat waktunya.
5. **Hapus dua cara.** Hapus `rahasia-lab2.txt` lewat Explorer (Recycle Bin). Buat `buang-lab.txt` lalu hapus dengan Shift+Delete.
6. **Ekstrak arsip.** Buat ZIP berisi satu file teks di VM analisis, salin ke `LAB-WS01`, buka file teks dari dalam ZIP lewat Explorer. Catat nama folder sementara yang dibuat dan Modified file hasil ekstrak.
7. **Koleksi.** Ambil `$MFT`, `$J`, `$LogFile`, hive SYSTEM, dan `$I` dengan target KAPE seperti bagian 2.1 ke disk bukti lab, lalu proses di `LAB-DFIR01` dengan MFTECmd (`--at`) dan RBCmd.
8. **Baca.** Untuk setiap langkah 2 sampai 6, cari record di `$J` dan entry di `$MFT`. Isi tabel: langkah, record `$J` yang muncul (reason), perubahan SI, perubahan FN, catatan.
9. **Uji klaim.** Jawab dari datamu sendiri, bukan dari teks Day ini: apakah langkah 2 menghasilkan record `$J`? Apakah LastAccess berubah? Apakah langkah 4 menghasilkan `BasicInfoChange`, dan apakah FN berubah setelah file dipindah? Apakah langkah 6 menghasilkan `BasicInfoChange` dan Modified dengan subdetik nol?
10. **Recycle Bin.** Cocokkan `$I` dengan langkah 5, hash `$R`, dan buktikan `buang-lab.txt` hanya muncul sebagai `FileDelete` di `$J`.
11. **PowerShell.** Hitung pasangan `__PSScriptPolicyTest_*` di `$J` dan bandingkan dengan jumlah `powershell.exe` yang kamu jalankan (Sysmon EID 1).
12. **Laporan.** Tulis tabel jawaban seperti bagian 2.7 untuk pertanyaan "apakah `rahasia-lab.txt` dibaca, diubah, atau dihapus?", lengkap dengan jendela `$J` dan batasnya.

**Hasil yang sebaiknya tersimpan:**

- Mode last access dan kapasitas journal `LAB-WS01`, beserta ukuran volume.
- Tabel langkah ke record `$J` dan perubahan SI/FN dari data lab.
- Bukti bahwa pembacaan (langkah 2) tidak menghasilkan record `$J`, atau catatan bila hasil lab-mu berbeda.
- Hasil uji timestomp jinak: SI vs FN sebelum dan sesudah file dipindah, dan ada atau tidaknya `BasicInfoChange`.
- Nama folder sementara Explorer dan Modified file hasil ekstrak di build lab.
- Hasil RBCmd, hash `$R`, dan record `FileDelete` untuk Shift+Delete.
- Tabel jawaban dengan jendela dan batas.

**Variasi tantangan:** setelah langkah 7, jalankan `fsutil usn deletejournal /d C:` di `LAB-WS01` (hanya di lab, snapshot siap), tunggu sampai selesai, buat satu file baru, lalu koleksi ulang. Catat jendela `$J` yang tersisa, jejak penghapusan journal yang bisa ditemukan di Prefetch `FSUTIL.EXE` dan Sysmon EID 1, dan apakah `$LogFile` masih memuat jejak langkah 3 dan 4. Kembalikan snapshot setelah selesai.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat membaca metadata NTFS. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| LastAccess tidak berubah walau file jelas dibuka | Pembaruan last access mati, atau ditunda sampai 1 jam [S8][S9] | Baca `NtfsDisableLastAccessUpdate` di hive SYSTEM; jangan pakai A sebagai bukti |
| Kolom `Created0x30` kosong | MFTECmd hanya menulis FN yang berbeda dari SI | Jalankan ulang dengan `--at` [S11] |
| SI dan FN sama-sama "lama" pada file mencurigakan | Tidak ada timestomp, atau SI dipalsukan lalu file dipindah sehingga FN ikut [S13] | Cari `FileCreate`, rename, dan `BasicInfoChange` di `$J`; korelasi Sysmon/EDR |
| Modified lebih tua dari Created | File salinan atau hasil ekstrak arsip | Normal; cek SI vs FN Created dan record `$J` |
| `$J` tidak memuat kejadian yang dicari | Journal sudah dipangkas, atau dihapus dengan `fsutil usn deletejournal` [S6][S7] | Catat record tertua; cek shadow copy (Day 03) dan jejak `FSUTIL.EXE` |
| `ParentPath` kosong atau aneh di output `$J` | Induk sudah dihapus atau entry dipakai ulang | Filter dengan entry number dan sequence number; cocokkan dengan `$MFT` |
| Recycle Bin kosong padahal file hilang | Shift+Delete, penghapusan oleh proses, atau Recycle Bin dikosongkan | `FileDelete` di `$J`, entry `InUse` false, slack `$I30` |
| RBCmd gagal membaca satu `$I` | File rusak atau format tak dikenal | Baca hex manual (bagian 2.5); RBCmd tetap menampilkan data yang terbaca [S12] |
| Banyak create lalu delete di Temp tiap beberapa menit | `__PSScriptPolicyTest_*` dari PowerShell [S16] | Kelompokkan; korelasikan dengan jadwal task atau eksekusi PowerShell |
| Hash salinan kerja berubah setelah dianalisis | Volume di-mount read-write | Buat salinan kerja baru dari master; mount read-only (Day 02 bagian 1.5) |
| Parse `$LogFile` gagal | Parser tidak mendukung versi atau belum tersedia di versi alat | Cek dukungan di versi MFTECmd [S2][S11]; catat "tidak diperiksa" |

## 5. Kesalahan umum dan jebakan

- **Membaca C di MACB sebagai Created.** C adalah perubahan entry `$MFT`; B (Born) adalah Created.
- **Menulis "tidak dibaca" karena tidak ada jejak di `$J` atau LastAccess lama.** `$J` tidak punya reason untuk membaca [S4], dan last access sering mati. Pembacaan dijawab event log, EDR, dan memori.
- **Menganggap USN mencatat pelaku.** `SecurityId` milik file, bukan akun pengubah [S4]. Pelaku dicari di Sysmon EID 11 dan EDR.
- **Menyimpulkan timestomping dari satu tanda.** SI vs FN bisa sama-sama palsu, subdetik nol bisa dipalsukan atau wajar, dan Modified lebih tua dari Created umum pada salinan [S13]. Pakai beberapa lapis dan korelasi.
- **Menyimpulkan "aman" dari SI = FN.** FN bisa mewarisi SI palsu setelah file dipindah [S13]. Cek `$J` untuk rename dan `BasicInfoChange`.
- **Lupa jendela waktu.** "Tidak ada record" hanya berlaku antara record tertua dan terbaru `$J`. Tulis jendelanya di setiap jawaban.
- **Mengira Recycle Bin memuat semua file terhapus.** Shift+Delete dan penghapusan oleh proses tidak lewat Recycle Bin.
- **Menyalahkan penyerang untuk penghapusan oleh pengguna atau responder.** Cocokkan SID, waktu, dan daftar tindakan responder sebelum menyebut anti-forensik.
- **Lupa zona waktu.** Keluaran EZ Tools UTC; laporan PT JAB WIB.
- `[komunitas, belum terkonfirmasi]` Praktisi membandingkan SI dan FN untuk mendeteksi timestomping dan memakai USN untuk mengungkap rename atau delete yang tidak terlihat di `$MFT`. Heuristik subdetik nol pada SI juga dipakai, tetapi tidak selalu andal; selalu korroborasi, dan cek keandalannya di versi Windows dan alat lab.

## 6. Catatan terkini

Bagian ini menampung detail versi dan perubahan sumber yang bisa berubah lagi. Berguna saat memperbarui toolkit, tetapi tidak mengubah cara membaca artefak di atas.

- **EZ Tools 2026.5.0:** MFTECmd dan RBCmd tersedia untuk .NET 4.7.2 dan .NET 9; semua GUI, termasuk Timeline Explorer, hanya .NET 9 [S2]. README RBCmd menyebut build .NET 10 yang bisa jalan di Linux dan macOS [S12]; cocokkan dengan halaman unduhan sebelum mengandalkannya.
- **Dukungan `$LogFile` dan `$I30` di MFTECmd:** halaman resmi menulis `$I30` didukung dan `$LogFile` "coming soon" [S2], sedangkan README (banner 0.5.0.1) mencantumkan `$LogFile` di input `-f` dan tidak menyebut `$I30` [S11]. Halaman resmi lebih baru; README kemungkinan belum diperbarui. Uji di versi lab-mu.
- **Last access sejak Windows 10 1803:** registry memakai nilai `0x8000000N` dan `fsutil` menampilkan empat mode User/System Managed [S14][S15]. Dokumentasi `fsutil behavior` Microsoft (diperbarui Februari 2026) masih menjelaskan parameter `{1|0}` dan penundaan 1 jam, tanpa menjelaskan mode System Managed [S8].
- **USN record:** Microsoft mendokumentasikan `USN_RECORD_V2`, `V3`, dan `V4`; struktur V2 dinamai `USN_RECORD` sebelum Windows 8 [S4].
- **PowerShell dan AppLocker:** Microsoft tidak lagi berinvestasi di AppLocker dan menyarankan App Control for Business, tetapi PowerShell tetap mendeteksi keduanya, termasuk lewat file `__PSScriptPolicyTest_*` [S16].
- **Inversecos (April 2022)** dan posting Champlain (Maret 2015) berusia lebih dari tiga tahun. Klaim FN mewarisi SI setelah file dipindah dan tata letak `$I` format 2 sebaiknya diuji ulang di Windows 11 lab-mu.

## 7. Cheat sheet

```
$MFT       1 entry/file (~1024 B) ; SI 0x10 (API bisa ubah) | FN 0x30 (kernel; create/rename/move) | $DATA (resident kecil)
           MFTECmd -f <$MFT> --csv <dir> --csvf <nama> --at     (--at = tampilkan semua FN)
MACB       M modified | A accessed (sering mati; tunda <=1 jam) | C entry $MFT berubah (BUKAN created) | B born
           UTC, 100 ns ; M < B wajar pada salinan & hasil ekstrak arsip
LASTACCESS SYSTEM\ControlSet00N\Control\FileSystem\NtfsDisableLastAccessUpdate
           0x80000000 user/on | 0x80000001 user/off | 0x80000002 system/on | 0x80000003 system/off
TIMESTOMP  SI Created << FN Created = indikasi ; SI=FN belum tentu aman (move menyalin SI ke FN)
           $J: FileCreate (waktu nyata), BasicInfoChange (timestamp/atribut diubah), Rename* ; + Sysmon 11 / EDR
$J         $Extend\$UsnJrnl:$J ; MFTECmd -f <$J> ; per volume ; dipangkas (MaximumSize + AllocationDelta)
           TIDAK mencatat baca ; TIDAK mencatat pelaku (SecurityId = milik file)
           tulis jendela: record tertua s/d terbaru ; fsutil usn queryjournal | deletejournal (anti-forensik)
$LogFile   transaksi NTFS, rinci, cepat berputar ; parser: cek versi
$I30       index folder ; slack = nama file lama + timestamp FN (BUKAN waktu hapus)
RECYCLE    C:\$Recycle.Bin\<SID>\$I<6>.<ext> (path, ukuran, waktu hapus) + $R<6>.<ext> (isi)
           $I v2: versi 8 | ukuran 8 | FILETIME 8 | 4 B @24 | path UTF-16 @28
           RBCmd -d <dir> --csv <dir> --csvf <nama> ; $J: RenameOldName + RenameNewName + FileCreate $I
           Shift+Delete / proses: tidak lewat Recycle Bin -> FileDelete di $J
NOISE      __PSScriptPolicyTest_*.ps1/.psm1 di Temp = start PowerShell ; ~$*.xlsx = Excel
JAWABAN    klaim + jendela + dasar/korelasi + keyakinan + "tidak bisa dijawab dari disk"
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "`$J` E15 tidak punya satu record pun untuk `export-tagihan.ps1`, jadi penyerang tidak pernah menyentuh file itu." Benarkah?

<details><summary>Jawaban</summary>

Tidak. `$J` hanya mencatat perubahan: data, nama, atribut, timestamp, keamanan, dan stream. Tidak ada reason untuk membaca, sehingga pembacaan pukul 23:40:17 Senin yang tercatat di event PowerShell 4104 tidak meninggalkan record. Yang bisa dinyatakan dari `$J` adalah file itu tidak diubah, dipindah, atau dihapus dalam jendela Minggu 10:17 sampai Kamis 08:47 WIB. Lihat bagian 1.4 dan 2.4.

</details>

**2. Skenario keputusan.** Rekan setim melihat SI Created dan FN Created `upd.ps1` identik lalu menulis "tidak ada timestomping, terbukti". Respons mana yang paling tepat?

- A. Setuju, karena FN tidak bisa diubah sama sekali.
- B. Terima sebagai satu lapis, lalu tambahkan lapis lain: `FileCreate` di `$J` pada detik yang sama, tidak ada `BasicInfoChange` atau rename setelahnya, dan Sysmon EID 11 serta EDR mencatat penulisan pada menit yang sama; tulis keyakinannya sedang-tinggi beserta batasnya.
- C. Tolak, karena SI = FN justru tanda pemalsuan yang canggih.

<details><summary>Jawaban</summary>

B. SI = FN konsisten dengan tidak ada timestomping, tetapi FN bisa mewarisi SI palsu bila file dipindah atau di-rename setelah SI diubah, jadi perlu sumber yang mencatat kejadian. A keliru karena FN bisa berubah lewat move atau rename dan lewat native API di Windows lama. C keliru karena SI = FN adalah keadaan normal untuk hampir semua file; tanpa tanda lain, menganggapnya bukti pemalsuan membalik beban pembuktian. Lihat bagian 1.3 dan 2.4.

</details>

**3. Pertanyaan jebakan.** "LastAccess `export-tagihan.ps1` masih 11 September, jadi file itu tidak dibuka sejak hari itu." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Hive SYSTEM E15 menunjukkan `NtfsDisableLastAccessUpdate` bernilai `0x80000003` (System Managed, pembaruan mati), sehingga timestamp A berhenti di waktu pembuatan. Andi sendiri menjalankan skrip itu berkali-kali sejak September, dan event 4104 mencatat isinya dibaca Senin 23:40. Bahkan bila pembaruan menyala, A hanya menyimpan akses terakhir dan bisa ditunda sampai 1 jam. Lihat bagian 1.2 dan 2.3.

</details>

**4. Skenario keputusan.** RBCmd menunjukkan `Tagihan-Okt-2026.zip` dihapus ke Recycle Bin dari profil Andi Selasa 11:12:40 WIB. Bagaimana menuliskannya?

- A. Sebagai anti-forensik penyerang yang menghapus lampiran untuk menghilangkan jejak.
- B. Sebagai penghapusan oleh pengguna: cocokkan SID dengan profil Andi, cocokkan waktunya dengan telepon SOC pukul 11:08 dan pengakuan Andi, hash `$R` dan bandingkan dengan lampiran di E10, lalu tambahkan pelajaran untuk panduan telepon SOC.
- C. Abaikan, karena penghapusan ke Recycle Bin tidak penting untuk pertanyaan DPO.

<details><summary>Jawaban</summary>

B. Recycle Bin mengikat penghapusan ke SID pengguna dan menyimpan waktu serta path asal, dan konteks telepon menjelaskan motifnya; `$R` yang masih utuh dan hash yang cocok membuktikan isinya adalah lampiran asli. A keliru karena penyerang yang menghapus lewat proses biasanya tidak melewati Recycle Bin, dan waktu serta SID-nya cocok dengan Andi. C keliru karena Agus bertanya tentang file yang dihapus; jawaban ini sekaligus memisahkan tindakan pengguna dari tindakan penyerang. Lihat bagian 1.6 dan 2.5.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Agus Setiawan (DPO), dalam tiga kalimat, kenapa disk laptop Andi tidak bisa membuktikan bahwa `export-tagihan.ps1` atau file lain tidak disalin keluar.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Catatan file system di laptop hanya mencatat file yang dibuat, diubah, dipindah, atau dihapus, tidak mencatat file yang dibuka atau dibaca, dan pencatatan waktu akses juga dimatikan di laptop itu. Penyerang cukup membaca isi file ke memori lalu mengirimnya lewat koneksinya sendiri, dan itu tidak meninggalkan perubahan apa pun di disk. Jadi skrip berpassword itu kami anggap terbaca karena log PowerShell mencatatnya, dan 41 file lain di Documents dan Desktop kami anggap berpotensi terpapar sampai isinya diklasifikasi."

Kesalahan yang sering muncul:
- Menjelaskan struktur `$MFT` dan USN, padahal DPO butuh batas bukti dan dampaknya.
- Menulis "tidak ditemukan jejak penyalinan" tanpa menyebut bahwa pembacaan memang tidak tercatat.
- Tidak menyebut apa yang diperlakukan sebagai terpapar dan apa dasarnya.

</details>

**6. Pertanyaan jebakan.** "`Tagihan-Okt-2026.js` punya Modified lebih tua dari Created dan subdetiknya nol, dan `$J` mencatat `BasicInfoChange` untuknya. Itu tiga tanda timestomping." Benarkah?

<details><summary>Jawaban</summary>

Tidak. File hasil ekstrak arsip sering membawa Modified dari dalam arsip, dan resolusi waktu format arsip yang mirip FAT membuat subdetik nol wajar; `BasicInfoChange` muncul di detik yang sama dengan `FileCreate`, konsisten dengan proses ekstraksi yang memasang waktu itu. SI Created dan FN Created sama dan cocok dengan kejadian lain di detik yang sama, termasuk `wscript.exe` dua detik kemudian. Perilaku ekstraksi Explorer tetap perlu dibuktikan di build lab. Lihat bagian 1.3, 2.2, dan 2.4.

</details>

**7. Interview question (English).** "How do you detect timestomping on NTFS, and what are the limits of each method?"

<details><summary>Sample answer</summary>

"I start with the MFT, comparing the four timestamps in STANDARD_INFORMATION with the ones in FILE_NAME. SI can be set from user mode with normal APIs, while FN is written by the kernel on create, rename and move, so an SI creation time far older than FN is a strong lead. But it's only a lead: if someone timestomps SI and then moves the file, Windows copies the fake SI values into FN, and zeroed sub-seconds can be faked or can be perfectly normal for files extracted from archives. So I go to sources that record events rather than state. The USN journal gives me the real FileCreate time, renames, and BasicInfoChange records, which is the reason code for timestamp or attribute changes, though it also fires for legitimate tools and only covers a limited window. LogFile can show the FN attribute being rewritten, but on a busy system it rolls over in hours. Then I correlate outside the file system, Sysmon file-create events, EDR timelines, Prefetch or Amcache for executables. I report the conclusion with the journal window and a confidence level, never as proof from a single flag."

What makes this answer strong: it explains why SI and FN behave differently, names the move or rename bypass and the sub-second caveat, moves to event-based evidence with its own limits, and ends with how the finding is reported.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | SANS: Windows Forensic Analysis poster (NTFS, $MFT, MACB, SI/FN, USN, $LogFile, $I30) | https://www.sans.org/posters/windows-forensic-analysis/ | sekunder (SANS) | diakses 2026-10-09 | Sedang-tinggi. Struktur dan makna; dipakai untuk ukuran entry dan konsep `$I30` |
| S2 | Eric Zimmerman tools (MFTECmd, RBCmd, Timeline Explorer) | https://ericzimmerman.github.io/ | primer | diakses 2026-10-09, dicek ulang 2026-10-16 | Tinggi. Versi 2026.5.0; MFTECmd: `$MFT`, `$Boot`, `$J`, `$SDS`, `$I30`, `$LogFile` (coming soon), menangani file terkunci; RBCmd: INFO2/`$I` |
| S3 | Microsoft Learn: NTFS overview | https://learn.microsoft.com/en-us/windows-server/storage/file-server/ntfs-overview | primer | diakses 2026-10-09 | Tinggi untuk struktur dasar NTFS |
| S4 | Microsoft Learn: USN_RECORD_V2 structure (winioctl.h) | https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2 | primer (dokumentasi vendor) | ms.date 2018-12-05; diakses 2026-10-16 | Tinggi. Field record, daftar reason dan nilai hex, definisi `BASIC_INFO_CHANGE`, rename menghasilkan dua record, `SecurityId` milik file, `SourceInfo` |
| S5 | Microsoft Learn: Change Journals | https://learn.microsoft.com/en-us/windows/win32/fileio/change-journals | primer (dokumentasi vendor) | diperbarui 2025-03-12; diakses 2026-10-16 | Tinggi. Journal per volume, dicatat untuk setiap perubahan file atau direktori |
| S6 | Microsoft Learn: Creating, Modifying, and Deleting a Change Journal | https://learn.microsoft.com/en-us/windows/win32/fileio/creating-modifying-and-deleting-a-change-journal | primer (dokumentasi vendor) | diperbarui 2025-03-12; diakses 2026-10-16 | Tinggi. `MaximumSize`, `AllocationDelta`, pemangkasan pada checkpoint NTFS, record ke log file NTFS pada checkpoint |
| S7 | Microsoft Learn: fsutil usn | https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn | primer (dokumentasi vendor) | diperbarui 2026-02-16; diakses 2026-10-16 | Tinggi. `queryjournal`, `readjournal`, `deletejournal /d` dan `/n`, satu journal per volume, proses hapus journal mengubah USN entry `$MFT` |
| S8 | Microsoft Learn: fsutil behavior | https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-behavior | primer (dokumentasi vendor) | diperbarui 2026-02-16; diakses 2026-10-16 | Tinggi. `disablelastaccess`, registry `NtfsDisableLastAccessUpdate`, penundaan maksimal 1 jam; tidak menjelaskan mode System Managed |
| S9 | Microsoft Learn: File Times | https://learn.microsoft.com/en-us/windows/win32/sysinfo/file-times | primer (dokumentasi vendor) | diperbarui 2025-04-15; diakses 2026-10-16 | Tinggi. UTC, interval 100 ns, penundaan last access 1 jam, `SetFileTime` mengubah tiga timestamp, resolusi waktu FAT |
| S10 | Microsoft Learn: Master File Table (Local File Systems) | https://learn.microsoft.com/en-us/windows/win32/fileio/master-file-table | primer (dokumentasi vendor) | ms.date 2024-09-05; diakses 2026-10-16 | Tinggi. Minimal satu entry per file termasuk `$MFT`, entry bebas dipakai ulang, `$MFT` tidak menyusut |
| S11 | MFTECmd README (GitHub) | https://github.com/EricZimmerman/MFTECmd | primer (repo resmi) | banner 0.5.0.1; diakses 2026-10-16 | Tinggi untuk opsi CLI: `-f`, `--csv`, `--csvf`, `--json`, `--body`, `--de`, `--fl`, `--at`, `--vss`, `--dedupe`; README mungkin tertinggal dari rilis 2026.5.0 |
| S12 | RBCmd README (GitHub) | https://github.com/EricZimmerman/RBCmd | primer (repo resmi) | diakses 2026-10-16 | Tinggi. `-d`, `-f`, `--csv`, `--csvf`, `--dt`, `-q`; `$I` format 1 dan 2, INFO2, isi folder `$R`, waktu UTC |
| S13 | Inversecos: Defence Evasion Technique: Timestomping Detection, NTFS Forensics | https://inversecos.com/2022/04/defence-evasion-technique-timestomping.html | sekunder (blog praktisi) | 2022-04-28 (>3 tahun); diakses 2026-10-16 | Sedang-tinggi. SI vs FN, FN mewarisi SI setelah move atau rename, subdetik bisa dipalsukan, `$J` dan `$LogFile` untuk deteksi; demonstrasi di Windows yang diuji penulis |
| S14 | Winaero: How to Enable or Disable NTFS Last Access Time Updates in Windows 10 | https://winaero.com/disable-ntfs-last-access-time-updates-in-windows-10 | sekunder (blog teknologi) | diperbarui 2019-08-28 (>3 tahun); diakses 2026-10-16 | Sedang. Empat mode `fsutil`, keputusan saat boot, klaim volume di atas 128 GB; komentar pembaca melaporkan tampilan yang tertukar |
| S15 | Citrix: PVS and MCS devices cache disk quickly consumed by NTFSDisableLastAccessUpdate (CTX338425) | https://support.citrix.com/external/article/CTX338425/pvs-and-mcs-devices-cache-disk-quickly-c.html | sekunder (vendor) | tanggal tidak tercantum; diakses 2026-10-16 | Sedang. Nilai `0x80000001` untuk Windows 10 1803 ke atas; label mode dari bantuan `fsutil` |
| S16 | Microsoft Learn: Use App Control to secure PowerShell | https://learn.microsoft.com/powershell/scripting/learn/application-control | primer (dokumentasi vendor) | PowerShell 7.6, ms.date 2026-08-17; diakses 2026-10-16 | Tinggi. PowerShell membuat `__PSScriptPolicyTest_<acak>.ps1` dan `.psm1` di `$Env:TEMP` untuk mendeteksi AppLocker |
| S17 | Champlain College Leahy Center: Windows 10 Recycle Bin Activity Introduction | https://leahycenterblog.champlain.edu/?p=1250 | sekunder (riset akademik) | 2015-03-28 (>3 tahun, Windows 10 pra-rilis); diakses 2026-10-16 | Sedang. Tata letak `$I` Windows 8.1 dan 10, penamaan `$I`/`$R`, folder per SID |
| S18 | Andrea Fortuna: Going beneath NTFS: USN Journal, dfir_ntfs, and artefact-driven investigations | https://andreafortuna.org/2026/07/06/ntfs-forensics-deep-dive/ | sekunder (blog praktisi) | 2026-07-06; diakses 2026-10-16 | Sedang. Entry 1.024 byte, file resident sekitar di bawah 700 byte, FN tidak bisa diubah lewat API Win32 standar, SI Born lebih tua dari FN Born sebagai indikasi |

**Catatan sumber:** fakta reason USN, isi record, pemangkasan journal, penundaan last access, dan pembuatan file `__PSScriptPolicyTest_*` berasal dari dokumentasi Microsoft [S4][S6][S7][S8][S9][S16]. Mode System Managed untuk last access dan klaim 128 GB hanya dari sumber sekunder [S14][S15]; dokumentasi Microsoft yang diperiksa tidak menjelaskannya, jadi baca nilai registry di image dan uji di build lab. Perilaku FN yang mewarisi SI setelah file dipindah didemonstrasikan Inversecos pada 2022 [S13] dan perlu diuji ulang di Windows 11. Pola Modified lebih tua dari Created untuk file salinan dan hasil ekstrak, nama folder `Temp1_<arsip>` dari Explorer, dan munculnya `BasicInfoChange` saat ekstraksi adalah praktik dan perilaku yang dilaporkan praktisi, belum dikonfirmasi dokumentasi Microsoft; buktikan di lab (bagian 3). Tata letak `$I` format 2 berasal dari riset 2015 [S17] dan README RBCmd [S12]; arti field 4 byte di offset 24 sebagai panjang nama perlu dicek pada sampel lab. Dua sumber resmi Eric Zimmerman tidak sejalan soal dukungan `$LogFile` dan `$I30` di MFTECmd [S2][S11]; Day ini memakai halaman resmi yang lebih baru dan meminta uji di versi lab. Nama kolom output MFTECmd dan RBCmd (termasuk `SI<FN`, `uSecZeros`, dan penanda slack `$I30`) perlu dicocokkan dengan versi yang dipakai. Semua isi PT JAB, termasuk SID, entry number, waktu, ukuran, jumlah record, isi Recycle Bin, dan nilai hash, adalah contoh fiktif.
