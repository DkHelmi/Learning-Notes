---
day: 08
title: 'File system forensics: $MFT, timestamp MACB, $STANDARD_INFORMATION vs $FILE_NAME, USN journal, $LogFile, dan Recycle Bin'
researched_on: 2026-10-10
versions_checked: 'NTFS di Windows 10/11; EZ Tools MFTECmd, RBCmd (.NET 9); rujukan Day 02-07'
---

# Day 08: File system forensics (MFT, USN, $LogFile, Recycle Bin)

Cakupan: membaca metadata NTFS ($MFT, timestamp MACB, SI dan FN, USN journal, $LogFile, Recycle Bin) untuk merekonstruksi apa yang terjadi pada file.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan struktur `$MFT`: record, atribut resident vs non-resident, dan data runs.
- membaca empat timestamp MACB dan membedakan `$STANDARD_INFORMATION` dari `$FILE_NAME`.
- mendeteksi indikasi timestomping dengan membandingkan dua set timestamp.
- memakai USN journal (`$J`) dan `$LogFile` untuk melihat perubahan file yang tidak lagi tampak di MFT.
- menganalisis Recycle Bin (`$I`/`$R`) untuk file yang dihapus user.

## 2. Konteks singkat

File system NTFS mencatat jauh lebih banyak daripada daftar file. `$MFT` memegang metadata tiap file termasuk empat timestamp per dua atribut, USN journal mencatat aliran perubahan, dan Recycle Bin menyimpan file yang dihapus user dengan metadata asalnya. Artefak ini menjawab "kapan file dibuat, diubah, diakses, dan dihapus", dan mengungkap upaya memanipulasi waktu (timestomping) yang sering dipakai penyerang.

Day 07 menjawab "apa yang dijalankan"; Day ini menjawab "apa yang terjadi pada file". Keduanya digabung di super-timeline (Day 13). Topik timestamp menuntut kehati-hatian: salah membaca MACB atau mengabaikan perbedaan dua atribut waktu menghasilkan kesimpulan yang salah.

**Kapan dipakai:** rekonstruksi aktivitas file, deteksi timestomping, pemulihan file terhapus (metadata), menentukan urutan kejadian.
**Kapan terbatas:** MFT bisa dirotasi/ditimpa untuk file lama; timestamp bisa dimanipulasi; file yang dihapus dan ditimpa mungkin tak terpulihkan tanpa carving (full image, Day 01).

## 3. Konsep inti

### 3.1 Struktur $MFT

`$MFT` (Master File Table) adalah basis data NTFS; tiap file dan direktori punya satu atau lebih record (biasanya 1024 byte) [S1]. Tiap record berisi atribut:

| Atribut | Isi |
|---|---|
| `$STANDARD_INFORMATION` (SI) | Timestamp MACB, flag, owner ID |
| `$FILE_NAME` (FN) | Nama file, parent reference, dan set timestamp MACB kedua |
| `$DATA` | Isi file (resident bila kecil, non-resident bila besar) |
| `$INDEX_ROOT`/`$INDEX_ALLOCATION` | Isi direktori (`$I30`) |

Konsep penting:
- **Resident vs non-resident:** file kecil disimpan isinya di dalam record MFT (resident); file besar isinya di cluster lain, dirujuk lewat data runs (non-resident). File resident yang dihapus kadang masih bisa dipulihkan dari MFT.
- **Parent reference** di FN memungkinkan merekonstruksi path lengkap.

### 3.2 Empat timestamp MACB

Tiap atribut SI dan FN menyimpan empat timestamp [S1]:

| Huruf | Nama | Arti |
|---|---|---|
| M | Modified | Isi file terakhir diubah |
| A | Accessed | File terakhir diakses (update bisa dinonaktifkan) |
| C | Changed (MFT entry modified) | Record MFT terakhir diubah (metadata) |
| B | Born (Created) | File dibuat |

Catatan: huruf C di MACB adalah "MFT changed" (perubahan metadata), bukan "Created"; B (Born) adalah created. Update timestamp Accessed bisa dinonaktifkan di Windows untuk performa, cek default per versi. Timestamp NTFS presisi 100-nanodetik, UTC.

### 3.3 SI vs FN: kunci deteksi timestomping

Dua set timestamp (SI dan FN) berperilaku berbeda [S1]:
- **SI** bisa diubah lewat API biasa (termasuk oleh malware yang melakukan timestomping).
- **FN** lebih sulit diubah lewat API standar; FN diperbarui oleh operasi file system (rename, move), bukan oleh API set-time biasa.

Deteksi timestomping: bandingkan SI dan FN. Bila SI jauh lebih lama daripada FN (file "dibuat" bertahun lalu menurut SI, tetapi FN menunjukkan baru-baru ini), itu indikasi timestomping. Juga curigai timestamp SI dengan subsecond nol (00000000) padahal operasi normal menghasilkan subsecond non-nol, cek keandalan heuristik subsecond di versi dan tool. MFTECmd menampilkan kedua set untuk perbandingan.

Ini salah satu analisis paling halus di DFIR; selalu nyatakan heuristik yang dipakai dan keterbatasannya, jangan menyimpulkan timestomping dari satu tanda saja.

### 3.4 USN Journal ($J)

USN Journal (`$Extend\$UsnJrnl:$J`) mencatat aliran perubahan file system: create, delete, rename, data overwrite, dan lainnya, dengan timestamp dan nomor urut (USN) [S1]. Nilainya:
- Melihat perubahan file yang terjadi lalu file-nya dihapus (MFT record mungkin sudah dipakai ulang, tetapi jejak di USN tetap ada untuk sementara).
- Merekonstruksi rename dan move (penyerang sering mengganti nama tool).
- Urutan operasi lewat nomor USN.

Keterbatasan: `$J` dirotasi (ukuran terbatas), sehingga hanya menyimpan perubahan beberapa waktu terakhir. MFTECmd memparse `$J`.

### 3.5 $LogFile

`$LogFile` adalah transaction log NTFS untuk menjaga konsistensi file system [S1]. Secara forensik, ia bisa memuat detail operasi yang lebih kaya daripada USN untuk periode sangat singkat (sebelum dirotasi), termasuk perubahan yang di-roll back. Parsing `$LogFile` lebih kompleks dan sering memakai tool khusus; untuk catatan ini, pahami bahwa ia ada dan melengkapi `$J` untuk jendela waktu pendek, cek tool parsing `$LogFile` yang dipakai.

### 3.6 $I30 (directory index)

`$I30` adalah atribut indeks direktori yang menyimpan entri FILE_NAME anak sebuah direktori, termasuk kadang entri untuk file yang sudah dihapus (slack di index) [S1]. Berguna untuk menemukan jejak file yang pernah ada di sebuah folder meski MFT record-nya sudah dipakai ulang. Analisis `$I30` lebih lanjut; ketahui keberadaannya sebagai sumber file terhapus.

### 3.7 Recycle Bin ($I/$R)

Saat user menghapus file ke Recycle Bin (Windows Vista ke atas), dibuat dua file di `C:\$Recycle.Bin\<SID>\` [S1]:
- `$I<id>`: metadata, berisi nama dan path asli file serta waktu dihapus.
- `$R<id>`: isi file yang dihapus.

RBCmd memparse file `$I` untuk mendapat nama asli, ukuran, dan waktu hapus [S2]. Recycle Bin membuktikan user menghapus file tertentu (per SID, sehingga terikat user), dan `$R` memulihkan isinya. File yang dihapus dengan Shift+Delete atau oleh proses (bukan ke Recycle Bin) tidak muncul di sini.

## 4. Artefak, perintah, dan cara membacanya

> Perintah dijalankan di VM analisis atas koleksi (Day 03-04). Keluaran berlabel ilustrasi. Path perlu dicek terhadap struktur koleksi.

### 4.1 Parse $MFT dengan MFTECmd

```
MFTECmd.exe -f ".\triage\C\$MFT" --csv ".\analysis" --csvf mft.csv
```

- Output CSV memuat satu baris per record dengan path lengkap (direkonstruksi dari parent reference), ukuran, dan timestamp SI dan FN terpisah.
- Untuk melihat kedua set timestamp dan flag timestomping, MFTECmd punya kolom SI dan FN (mis. `Created0x10` untuk SI, `Created0x30` untuk FN), cek nama kolom di versi lab.
- Buka di Timeline Explorer; sortir kolom created/modified.

Keluaran ilustrasi (ringkas):

```
EntryNumber  FileName       ParentPath          Created0x10           Created0x30           SI<FN?
45231        evil.exe       \Users\Public       2019-01-01 00:00:00   2026-10-02 14:00:05   YES (timestomp?)
```

Kolom `SI<FN` menandai bila created SI lebih lama dari FN, indikasi timestomping, cek nama kolom.

### 4.2 Membaca MACB dan timestomping

Di Timeline Explorer atas CSV MFT:
- Bandingkan `Created0x10` (SI) dan `Created0x30` (FN). SI jauh lebih lama dari FN pada file yang dicurigai adalah indikasi timestomping (bagian 3.3).
- Periksa subsecond: nilai `.0000000` pada SI created/modified bisa menandakan set-time programatik, perlu dicek.
- Jangan simpulkan dari satu tanda; cari korroborasi (file di lokasi aneh, tidak ada di Prefetch padahal diklaim lama, dll.).

### 4.3 Parse USN Journal dengan MFTECmd

```
MFTECmd.exe -f ".\triage\C\$Extend\$J" --csv ".\analysis" --csvf usn.csv
```

- Output: aliran perubahan dengan timestamp, nama file, dan reason flags (create, delete, rename old/new name, data extend, dll.).
- Cara membaca: cari rename (penyerang mengganti nama tool), delete (file dihapus), dan create diikuti delete dalam waktu singkat (tool dijalankan lalu dibersihkan).
- Cek path `$Extend\$J` dan nama di koleksi; sebagian koleksi menyimpannya sebagai `$J` terpisah.

Keluaran ilustrasi:

```
UpdateTimestamp       Name          UpdateReasons
2026-10-02 14:00:05Z  evil.exe      FileCreate
2026-10-02 14:10:12Z  evil.exe      RenameOldName
2026-10-02 14:10:12Z  svchost2.exe  RenameNewName|DataExtend
2026-10-02 14:30:00Z  svchost2.exe  FileDelete|Close
```

Cerita: evil.exe dibuat, di-rename menjadi svchost2.exe (masquerading), lalu dihapus. USN menangkap rename yang tidak terlihat dari MFT saja.

### 4.4 Recycle Bin dengan RBCmd

```
RBCmd.exe -d ".\triage\C\$Recycle.Bin" --csv ".\analysis" --csvf recyclebin.csv
```

- Memparse file `$I` menjadi CSV: nama dan path asli, ukuran, waktu dihapus, dan SID (user yang menghapus).
- Cara membaca: file sensitif yang dihapus user tertentu pada waktu tertentu; `$R` yang bersesuaian memulihkan isinya.
- Cek path `$Recycle.Bin` dalam koleksi.

### 4.5 Rekonstruksi aktivitas file

Gabungkan MFT, USN, dan Recycle Bin untuk satu file:

| Sumber | Temuan untuk evil.exe | Arti |
|---|---|---|
| MFT SI | Created 2019 (mencurigakan) | Kemungkinan timestomp |
| MFT FN | Created 2026-10-02 14:00 | Waktu sebenarnya file masuk folder |
| USN | Create 14:00, Rename ke svchost2.exe 14:10, Delete 14:30 | Urutan hidup file |
| Recycle Bin | (tidak ada) | Tidak dihapus ke Recycle Bin (dihapus proses) |

Kesimpulan: file muncul 14:00 (FN, bukan SI yang di-timestomp), di-rename untuk menyamar, lalu dihapus langsung (bukan ke Recycle Bin). MFT sendiri akan menyesatkan (SI 2019); USN mengungkap kebenarannya.

### 4.6 Menemukan jejak file terhapus

- MFT: record file terhapus kadang masih utuh sampai dipakai ulang; MFTECmd menandai entri `InUse=false`.
- USN: `FileDelete` mencatat file yang dihapus meski MFT record sudah dipakai ulang.
- `$I30`: slack index direktori kadang memuat entri file yang dihapus, cek tool parsing `$I30`.
- Carving (full image, Day 01) untuk isi file yang MFT-nya hilang.

## 5. Lab praktik

**Prasyarat:** koleksi triage dari VM korban (Day 03-04) yang mencakup `$MFT`, `$J`, dan `$Recycle.Bin`; VM analisis dengan MFTECmd dan RBCmd; aktivitas file uji di korban.

1. **Buat aktivitas file.** Di VM korban (snapshot): salin sebuah executable ke `C:\Users\Public`, rename, jalankan, hapus (sebagian ke Recycle Bin, sebagian Shift+Delete). Catat waktu.
2. **Parse MFT.** Jalankan MFTECmd atas `$MFT` (bagian 4.1). Temukan file uji; bandingkan SI dan FN.
3. **Timestomp (opsional).** Ubah timestamp satu file uji dengan tool yang mengubah SI (atau catat bila kamu tidak melakukannya), kumpulkan ulang, dan lihat apakah SI dan FN berbeda (bagian 4.2).
4. **Parse USN.** Jalankan MFTECmd atas `$J` (bagian 4.3). Temukan create, rename, dan delete file uji. Susun urutannya.
5. **Recycle Bin.** Jalankan RBCmd (bagian 4.4). Temukan file yang kamu hapus ke Recycle Bin; catat nama asli, waktu, dan SID.
6. **Rekonstruksi.** Isi tabel bagian 4.5 untuk satu file uji, memadukan MFT, USN, dan Recycle Bin.
7. **Catat.** Tulis cheat sheet MACB pribadi: apa arti tiap huruf dan kapan tiap timestamp berubah.

**Hasil yang sebaiknya tersimpan:**
- MFT diparse; file uji ditemukan dengan SI dan FN terpisah.
- Perbedaan SI vs FN dipahami sebagai indikasi timestomping.
- USN menunjukkan create, rename, dan delete file uji dalam urutan.
- Recycle Bin menampilkan file yang dihapus dengan nama asli dan SID.
- Tabel rekonstruksi satu file dibuat dari tiga sumber.
- Cheat sheet MACB tersimpan.

**Variasi tantangan:** buat dua file dengan nama sama di dua folder berbeda, jalankan dan hapus keduanya, lalu buktikan dari MFT dan USN bahwa keduanya adalah file berbeda (entry number, parent path berbeda). Ini melatih membaca path dari parent reference dan tidak tertukar antara dua file bernama sama.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Accessed time tidak berubah | Update last access dinonaktifkan | Normal di banyak Windows; jangan andalkan A, perlu dicek |
| SI dan FN sama-sama "baru" | Tidak ada timestomp, atau tool menyamakan keduanya | Timestomp canggih bisa menyamakan; cari korroborasi lain |
| USN tidak memuat kejadian lama | `$J` dirotasi | Rentang terbatas; padukan MFT dan artefak lain |
| Recycle Bin kosong | File dihapus Shift+Delete atau oleh proses | Tidak ke Recycle Bin; cek USN FileDelete |
| Path file tidak terbaca | Parent reference putus | MFTECmd merekonstruksi; cek entri parent |
| MFT record file terhapus hilang | Record sudah dipakai ulang | Cek USN; carving dari image (Day 01) |

## 7. Kesalahan umum dan jebakan

- **Membaca C di MACB sebagai Created.** C adalah MFT-entry Changed; B (Born) adalah Created.
- **Mengandalkan SI timestamp saja.** SI mudah dimanipulasi; bandingkan dengan FN untuk timestomping.
- **Menyimpulkan timestomping dari satu tanda.** Pakai beberapa heuristik dan korroborasi.
- **Mengandalkan Accessed time.** Update last access sering dinonaktifkan.
- **Mengira Recycle Bin memuat semua file terhapus.** Shift+Delete dan hapus oleh proses tidak masuk.
- `[komunitas, belum terkonfirmasi]` Praktisi membandingkan SI dan FN untuk mendeteksi timestomping, dan memakai USN untuk mengungkap rename/delete yang tak terlihat di MFT. Heuristik subsecond nol pada SI juga dipakai, tetapi tidak selalu andal; selalu korroborasi, cek keandalan di versi dan tool lab.

## 8. Catatan terkini

- Struktur NTFS ($MFT, SI/FN, $J, $LogFile, $I30, Recycle Bin $I/$R) stabil antar Windows 10/11; perilaku update last access dan flush bisa berbeda, perlu dicek.
- MFTECmd memparse `$MFT`, `$J`, dan `$Boot`; RBCmd memparse Recycle Bin [S2].
- Timestomping tetap teknik anti-forensik umum; perbandingan SI vs FN adalah deteksi utama [S1].
- Day 09 masuk ke registry, sumber metadata dan konfigurasi yang melengkapi file system.

## 9. Cheat sheet

```
$MFT       1 record/file (~1024B) ; atribut SI (timestamp, mudah diubah) | FN (nama, parent, timestamp, sulit diubah) | $DATA (resident/non-resident)
MACB       M modified | A accessed (sering off) | C MFT-entry changed (BUKAN created) | B born/created ; UTC, 100ns
TIMESTOMP  bandingkan SI vs FN: SI jauh lebih lama dari FN = indikasi ; subsecond .0000000 = curiga ; korroborasi
USN ($J)   $Extend\$UsnJrnl:$J ; MFTECmd ; create/delete/rename/data ; mengungkap rename & delete yg tak tampak di MFT ; dirotasi
$LogFile   transaction log ; detail kaya jendela pendek ; parsing khusus
$I30       index direktori ; slack memuat entri file terhapus
RECYCLE    C:\$Recycle.Bin\<SID>\ ; $I metadata (nama asli, waktu, SID) + $R isi ; RBCmd ; bukan Shift+Delete
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | NTFS forensics: $MFT, MACB, SI/FN, USN, $LogFile, $I30 (referensi DFIR) | https://www.sans.org/posters/windows-forensic-analysis/ | sekunder (SANS) | diakses 2026-10-09 | Sedang-tinggi. Struktur dan makna |
| S2 | Eric Zimmerman tools: MFTECmd, RBCmd | https://ericzimmerman.github.io/ | primer | diakses 2026-10-09 (Day 02) | Tinggi. Parser dan kolom |
| S3 | Microsoft: NTFS dan file system (referensi struktur) | https://learn.microsoft.com/en-us/windows-server/storage/file-server/ntfs-overview | primer | diakses 2026-10-09 | Tinggi untuk struktur dasar |
| S4 | Endpoint-Forensics Day 03-04 (koleksi $MFT, $J) | (lokal) | rujukan internal | 2026-10-09 | Sumber yang diparse |
| S5 | Endpoint-Forensics Day 07 (artefak eksekusi untuk korroborasi) | (lokal) | rujukan internal | 2026-10-09 | Korroborasi timestomping |

**Catatan sumber:** struktur NTFS dan makna MACB adalah pengetahuan DFIR yang mapan [S1][S3]. Nama kolom MFTECmd untuk SI dan FN, perilaku update last access, heuristik subsecond nol untuk timestomping, dan tool parsing `$LogFile`/`$I30` bergantung versi tool dan perlu dicocokkan dengan output MFTECmd di lab. Path artefak di dalam koleksi juga perlu dicek.
