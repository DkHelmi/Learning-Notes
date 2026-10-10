---
day: 03
title: 'Triage dengan KAPE: Targets dan Modules, compound target, VSS, container output, dan membaca hasil'
researched_on: 2026-10-10
versions_checked: 'KAPE (Kroll); EZ Tools (.NET 9); rujukan Day 01-02; KapeFiles (Targets/Modules komunitas)'
---

# Day 03: Triage dengan KAPE

Cakupan: koleksi triage satu host Windows dengan KAPE, dari Targets dan Modules sampai container VHDX, hashing, dan membaca CSV hasil parse.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- membedakan Targets (apa yang dikumpulkan) dan Modules (pemrosesan) di KAPE.
- menjalankan koleksi triage dengan compound target dan output container (VHDX) yang bersih.
- memahami peran Volume Shadow Copy (VSS) dan file yang terkunci saat koleksi.
- memproses koleksi dengan Modules (EZ Tools) dan membaca hasilnya di Timeline Explorer.
- menjaga kebersihan bukti: hashing, container read-only, dan catatan kasus.

## 2. Konteks singkat

Day 01 memutuskan triage sebagai pola akuisisi awal yang umum; Day 02 memasang KAPE. Day ini menjalankannya. KAPE adalah alat triage paling banyak dipakai di DFIR karena cepat mengumpulkan artefak kunci dari host yang hidup, termasuk file yang terkunci OS, lalu bisa langsung memprosesnya menjadi CSV yang bisa dibaca.

KAPE punya dua mesin: Targets (mengumpulkan file) dan Modules (menjalankan tool atas file itu). Memahami pemisahan ini adalah kunci memakai KAPE dengan benar: kumpulkan dulu (preservasi), proses kemudian (analisis), idealnya di tempat berbeda (Day 02).

**Kapan dipakai:** koleksi triage awal di host Windows yang hidup; scoping banyak host; preservasi cepat sebelum image penuh (Day 01).
**Kapan tidak:** saat butuh unallocated space atau file terhapus (perlu full image); saat host tidak bisa diakses langsung (Velociraptor lintas jaringan, Day 04).

## 3. Konsep inti

### 3.1 Targets vs Modules

| Mesin | Fungsi | Masukan | Keluaran |
|---|---|---|---|
| **Targets** | Mengumpulkan file/artefak dari sumber (disk hidup, image mounted) | `--tsource` (sumber), `--target` (apa) | File tersalin ke `--tdest` |
| **Modules** | Menjalankan program (EZ Tools, dll.) atas file | `--msource` (biasanya hasil Targets), `--module` | Hasil parse ke `--mdest` |

Alur paling umum: Targets mengumpulkan ke folder, lalu Modules memproses folder itu. Keduanya bisa dijalankan sekaligus atau terpisah. Pemisahan ini penting: koleksi Targets adalah bukti yang dipreservasi dan di-hash (Day 01); Modules bekerja atas salinannya.

Definisi Target (`.tkape`) dan Module (`.mkape`) adalah file teks dari repo KapeFiles komunitas, diperbarui dengan `kape.exe --sync` [S3][S5]. Target menentukan path file yang dikumpulkan; Module menentukan tool dan argumennya.

### 3.2 Compound target

Compound target menggabungkan banyak target menjadi satu, ditandai awalan `!` [S4]:

| Compound target | Isi |
|---|---|
| `!BasicCollection` | Set artefak dasar untuk triage cepat [S4] |
| `!SANS_Triage` | Set artefak lebih lengkap sesuai rekomendasi kelas SANS [S4] |

`!SANS_Triage` adalah titik awal yang umum: mengumpulkan registry hive, event log, Prefetch, `$MFT`, `$J`, dan banyak artefak lain dalam satu perintah [S4]. Untuk belajar, mulai dari sini, lalu pelajari target individual yang membentuknya.

### 3.3 Volume Shadow Copy dan file terkunci

Banyak artefak kunci (registry hive aktif, `$MFT`) terkunci OS saat sistem hidup, sehingga tidak bisa disalin biasa. KAPE membaca file terkunci dengan akses tingkat rendah ke volume (raw disk), bukan lewat API file biasa, sehingga file yang sedang dipegang OS tetap bisa disalin. Detail implementasinya tidak perlu dihafal; yang penting, jalankan KAPE sebagai administrator agar akses ini berhasil. KAPE juga bisa mengumpulkan dari Volume Shadow Copy (VSS) untuk mendapat versi historis artefak, yang berguna melihat keadaan di masa lampau, cek flag VSS persis (`--vss`) di `kape.exe --help`.

Implikasi forensik: koleksi dari sistem hidup mengubah beberapa timestamp dan tidak menangkap unallocated space. Itu trade-off triage yang disadari (Day 01); catat di catatan kasus bahwa koleksi dilakukan pada sistem hidup.

### 3.4 Container output

KAPE bisa menulis hasil Targets ke container, bukan file lepas [S4]:

| Output | Catatan |
|---|---|
| No container | File lepas di `--tdest` |
| VHD / VHDX | Satu file disk virtual berisi koleksi; rapi, mudah di-hash dan dipindah |
| ZIP | Arsip; cek dukungan di versi lab |

Container VHDX disarankan untuk koleksi: satu file yang bisa di-hash sebagai bukti, dipindah ke VM analisis, lalu di-mount read-only untuk diproses. Ini menjaga kebersihan bukti (Day 01).

### 3.5 CLI dan GUI

KAPE punya CLI (`kape.exe`) dan GUI (`gkape.exe`) [S1]. Cara belajar yang disarankan: pakai gkape untuk menyusun koleksi, dan baca command line yang terbentuk di kotak bawah GUI, yang menunjukkan perintah persis yang akan dijalankan [S1]. Ini cara andal memastikan nama flag yang benar di versimu.

Flag inti (umum; cek di `kape.exe --help` versi lab):

| Flag | Fungsi |
|---|---|
| `--tsource` | Sumber Targets (drive, mis. C:) |
| `--target` | Nama target atau compound target (mis. `!SANS_Triage`) |
| `--tdest` | Tujuan koleksi Targets |
| `--tflush` | Kosongkan `--tdest` dulu |
| `--vhdx` | Tulis koleksi ke container VHDX |
| `--module` | Nama module (mis. `!EZParser`) |
| `--msource` | Sumber Modules (biasanya hasil Targets) |
| `--mdest` | Tujuan hasil Modules |
| `--mflush` | Kosongkan `--mdest` dulu |
| `--tlist`, `--mlist` | Daftar Target dan Module (Day 02) |
| `--sync` | Perbarui definisi Targets/Modules dari KapeFiles [S4] |

### 3.6 Module !EZParser

Module `!EZParser` menjalankan rangkaian EZ Tools atas koleksi, menghasilkan CSV per artefak (MFT, registry, Prefetch, event log, dan lainnya), cek nama module persis. Ini jembatan dari koleksi mentah ke data yang bisa dibaca: Targets mengumpulkan `$MFT`, `!EZParser` menjalankan MFTECmd atasnya, hasilnya CSV untuk Timeline Explorer. Output CSV ini yang kamu baca di Day 07-10.

### 3.7 Keterbatasan triage KAPE

- Tidak menangkap unallocated space atau file terhapus yang tidak ada di `$MFT`/artefak (butuh full image, Day 01).
- Bergantung pada daftar target: artefak yang tidak ada di target tidak dikumpulkan (adaptive collection Velociraptor menambal sebagian, Day 04).
- Koleksi dari sistem hidup mengubah sebagian timestamp dan metadata.
- Memproses dengan Module bergantung versi EZ Tools; catat versi (Day 02).

## 4. Artefak, perintah, dan cara membacanya

> Perintah dijalankan di VM lab-mu. Keluaran berlabel ilustrasi. Flag perlu dicek terhadap `kape.exe --help` versi lab.

### 4.1 Memperbarui definisi

```
kape.exe --sync
```

- Mengunduh Targets dan Modules terbaru dari repo KapeFiles [S4]. Jalankan sekali sebelum koleksi agar definisi mutakhir.

### 4.2 Koleksi triage ke container VHDX

```
kape.exe --tsource C: --target !SANS_Triage --tdest E:\cases\CASE-2026-001\evidence --vhdx CASE-2026-001 --tflush
```

- `--tsource C:` sumber drive sistem; `--target !SANS_Triage` compound target lengkap [S4].
- `--tdest` tujuan; `--vhdx CASE-2026-001` menulis koleksi ke satu container VHDX bernama itu.
- `--tflush` mengosongkan tujuan dulu agar bersih.
- Jalankan di VM korban (atau host yang diinvestigasi), tulis ke drive eksternal/terpisah (`E:`), bukan ke drive sistem, agar tidak menimpa bukti.
- Cek nama flag `--vhdx` dan perilaku di versi lab lewat gkape (bagian 3.5).

Keluaran ilustrasi (ringkas):

```
Collecting files...
Total files copied: 3,412
VHDX created: E:\cases\CASE-2026-001\evidence\CASE-2026-001.vhdx
```

### 4.3 Hash koleksi

Setelah koleksi, segera hash container (Day 01):

```
Get-FileHash -Algorithm SHA256 E:\cases\CASE-2026-001\evidence\CASE-2026-001.vhdx | Tee-Object E:\cases\CASE-2026-001\evidence\hashes.txt
```

- Hash container VHDX adalah bukti integritas koleksi. Simpan `hashes.txt` bersama bukti.
- Verifikasi ulang hash setelah memindah container ke VM analisis.

### 4.4 Memproses dengan Modules

Mount VHDX read-only di VM analisis, lalu jalankan Modules atas isinya:

```
kape.exe --msource F:\ --module !EZParser --mdest E:\cases\CASE-2026-001\analysis --mflush
```

- `--msource F:\` adalah VHDX yang sudah di-mount (read-only) di VM analisis.
- `--module !EZParser` menjalankan rangkaian EZ Tools; `--mdest` tujuan CSV hasil.
- Memproses di VM analisis atas salinan (VHDX), bukan di korban atas bukti asli (Day 01-02).
- Cek nama module `!EZParser` dan cara mount VHDX read-only di versi lab.

Keluaran ilustrasi:

```
Processing with !EZParser...
MFTECmd: $MFT -> 20260109_MFTECmd_MFTECmd_Output.csv
EvtxECmd: 18 logs -> ...EvtxECmd_Output.csv
RECmd: SOFTWARE, SYSTEM, NTUSER -> ...
```

### 4.5 Membaca hasil di Timeline Explorer

Buka CSV hasil (misalnya output MFTECmd atau EvtxECmd) di Timeline Explorer (Day 02). Cara membaca:
- Timeline Explorer menampilkan CSV sebagai tabel yang bisa difilter dan disortir per kolom.
- Untuk event log, filter kolom Event ID dan Channel; untuk MFT, sortir kolom timestamp.
- Hasil parse ini menjadi masukan Day 05 (event log), 07 (eksekusi), 08 (file system).

### 4.6 Koleksi target tunggal

Untuk belajar apa yang dikumpulkan tiap target, jalankan target individual, bukan compound:

```
kape.exe --tsource C: --target RegistryHives --tdest E:\test\reg --tflush
```

- Mengumpulkan hanya registry hive. Bandingkan isinya dengan apa yang `!SANS_Triage` kumpulkan untuk memahami cakupan compound target.
- Cek nama target `RegistryHives` di `--tlist`; nama bisa berbeda antar versi KapeFiles.

## 5. Lab praktik

**Prasyarat:** VM korban Windows dengan Sysmon dan audit policy (Day 02) serta aktivitas jinak (jalankan beberapa program agar ada artefak); VM analisis dengan KAPE dan EZ Tools (Day 02); drive/share terpisah untuk bukti; snapshot.

1. **Sync.** Jalankan `kape.exe --sync` (bagian 4.1). Catat waktu dan bahwa definisi mutakhir.
2. **Koleksi.** Dari VM korban, jalankan koleksi `!SANS_Triage` ke container VHDX di drive terpisah (bagian 4.2). Catat jumlah file dan lokasi.
3. **Hash.** Hash container segera (bagian 4.3). Simpan `hashes.txt`.
4. **Pindah dan verifikasi.** Pindahkan VHDX ke VM analisis, verifikasi hash cocok, mount read-only.
5. **Proses.** Jalankan `!EZParser` atas VHDX yang di-mount (bagian 4.4). Catat CSV yang dihasilkan.
6. **Baca.** Buka output MFTECmd dan EvtxECmd di Timeline Explorer. Temukan satu program yang kamu jalankan di langkah prasyarat, di MFT atau event log.
7. **Target tunggal.** Jalankan satu target individual (bagian 4.6) dan bandingkan isinya dengan bagian dari `!SANS_Triage`.
8. **Catat kasus.** Tulis catatan kasus: waktu koleksi, sistem hidup (ya), hash, versi KAPE dan EZ Tools.

**Hasil yang sebaiknya tersimpan:**
- Definisi KAPE diperbarui dengan `--sync`.
- Koleksi `!SANS_Triage` ke VHDX berhasil; jumlah file dicatat.
- Container di-hash; hash cocok setelah dipindah.
- `!EZParser` menghasilkan CSV; dibaca di Timeline Explorer.
- Satu aktivitas uji ditemukan di MFT atau event log hasil parse.
- Catatan kasus dengan waktu, hash, dan versi tersimpan.

**Variasi tantangan:** jalankan koleksi dengan dan tanpa opsi VSS (bila didukung versimu), lalu bandingkan apakah ada versi historis artefak (mis. NTUSER.DAT lama) yang muncul dari VSS tetapi tidak dari live. Tulis apa yang VSS tambahkan dan kapan itu berguna (misalnya melihat registry sebelum penyerang membersihkan jejak).

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Target tidak dikenal | Definisi lama | `kape.exe --sync`; cek `--tlist` [S4] |
| File terkunci tidak tersalin | Akses raw gagal | Jalankan sebagai administrator; pastikan tujuan koleksi bukan volume yang sama |
| VHDX tidak bisa di-mount | Belum didukung OS atau korup | Verifikasi hash; mount di Windows yang mendukung VHDX |
| `!EZParser` tidak menghasilkan CSV | EZ Tools tidak ditemukan Module | Pastikan path EZ Tools sesuai yang diharapkan Module [S2] |
| Flag ditolak | Nama flag beda versi | Pakai gkape; baca command line yang terbentuk [S1] |
| Timestamp koleksi berubah | Koleksi dari sistem hidup | Normal untuk triage; catat di catatan kasus (Day 01) |

## 7. Kesalahan umum dan jebakan

- **Menulis koleksi ke drive sistem korban.** Bisa menimpa bukti; tulis ke drive/share terpisah.
- **Memproses (Modules) di korban atas bukti asli.** Proses di VM analisis atas salinan (VHDX).
- **Lupa hash koleksi.** Hash segera setelah koleksi dan verifikasi setelah pindah (Day 01).
- **Menganggap triage menangkap segalanya.** Tidak ada unallocated/file terhapus; itu butuh image (Day 01).
- **Mengandalkan nama flag dari tutorial lama.** Nama bisa berubah; konfirmasi lewat gkape atau `--help`.
- `[komunitas, belum terkonfirmasi]` Banyak praktisi memulai dari `!SANS_Triage` ke VHDX lalu `!EZParser`, memisahkan koleksi (di korban) dan pemrosesan (di analisis). Pola ini umum dan sejalan dengan pemisahan Targets/Modules [S1][S4]; konfirmasi nama target/module di versimu.

## 8. Catatan terkini

- KAPE memisahkan Targets (koleksi) dan Modules (pemrosesan); definisi dari KapeFiles diperbarui dengan `--sync` [S4].
- Compound target `!SANS_Triage` dan `!BasicCollection` tetap titik awal umum; output container VHD/VHDX didukung [S4].
- EZ Tools yang dijalankan Module kini default .NET 9 (Day 02) [S2]; catat versi karena memengaruhi hasil parse.
- gkape menampilkan command line yang terbentuk, cara andal memastikan flag di versimu [S1].

## 9. Cheat sheet

```
DUA MESIN  Targets (kumpulkan file: --tsource --target --tdest --vhdx) | Modules (proses: --msource --module --mdest)
COMPOUND   !SANS_Triage (lengkap) | !BasicCollection (dasar) ; awalan ! ; --tlist / --mlist
ALUR       --sync -> koleksi Targets ke VHDX (di korban) -> HASH -> pindah -> mount RO -> Modules !EZParser (di analisis) -> CSV -> Timeline Explorer
FILE KUNCI akses raw utk file terkunci ($MFT, hive aktif) ; VSS utk versi historis (cek flag)
CONTAINER  VHDX disarankan: satu file, di-hash, dipindah, mount read-only
BUKTI      tulis ke drive terpisah (bukan sistem) ; hash segera ; proses atas salinan
BATAS      tanpa unallocated/file terhapus (butuh image) ; bergantung daftar target ; live ubah timestamp
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Kroll: Exploring KAPE's graphical user interface | https://www.kroll.com/en/publications/cyber/exploring-kapes-graphical-user-interface | primer (vendor) | diakses 2026-10-09; situs bisa menolak akses otomatis | Sedang-tinggi. gkape menampilkan command line |
| S2 | Eric Zimmerman tools (EZ Tools yang dijalankan Module) | https://ericzimmerman.github.io/ | primer | diakses 2026-10-09 (Day 02) | Tinggi |
| S3 | KapeFiles (Targets/Modules komunitas) | https://github.com/EricZimmerman/KapeFiles | primer | diakses 2026-10-09 | Tinggi. Definisi .tkape/.mkape, --sync |
| S4 | Cyber Triage docs: Add KAPE output (!BasicCollection, !SANS_Triage, VHD/VHDX) | https://docs.cybertriage.com/en/latest/chapters/importing/kape.html | sekunder | diakses 2026-10-09 | Sedang. Compound target dan container |
| S5 | SANS ISC: KAPE (Kroll Artifact Parser and Extractor) | https://isc.sans.edu/diary/25258 | sekunder | diakses 2026-10-09 | Sedang. Konsep KAPE |

**Catatan sumber:** nama flag (`--tsource`, `--target`, `--tdest`, `--vhdx`, `--module`, `--mdest`, `--vss`) dan nama module `!EZParser` belum dicocokkan dengan dokumentasi flag resmi KAPE; konfirmasi lewat `kape.exe --help` atau command line yang dibentuk gkape. Compound target dan container VHD/VHDX dikonfirmasi dari sumber sekunder [S4]. Penjelasan akses file terkunci bersifat umum, bukan dari dokumentasi primer KAPE.
