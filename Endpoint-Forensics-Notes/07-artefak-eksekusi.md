---
day: 07
title: 'Artefak eksekusi: Prefetch, Amcache, Shimcache, UserAssist, BAM, SRUM, dan PCA Windows 11'
researched_on: 2026-10-10
versions_checked: 'Windows 10/11; EZ Tools PECmd, AmcacheParser, AppCompatCacheParser, RECmd, SrumECmd (.NET 9); PCA artifact Windows 11 22H2/23H2 (Sygnia); rujukan Day 02-06'
---

# Day 07: Artefak eksekusi

Cakupan: artefak Windows yang menjawab program apa yang dijalankan, kapan, dan oleh siapa, beserta batas apa yang dibuktikan tiap artefak.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menyebut artefak eksekusi Windows utama dan apa yang masing-masing buktikan dan tidak buktikan.
- memparse Prefetch, Amcache, Shimcache, UserAssist, BAM, dan SRUM dengan EZ Tools.
- membedakan "bukti eksekusi" dari "bukti keberadaan file", terutama untuk Shimcache dan Amcache.
- mengorelasikan beberapa artefak untuk memperkuat atau menyangkal klaim bahwa program dijalankan.
- memahami keterbatasan tiap artefak: retensi, versi Windows, dan apa yang tidak tercakup.

## 2. Konteks singkat

"Apakah program ini dijalankan, kapan, dan berapa kali?" adalah salah satu pertanyaan paling sering di DFIR. Windows meninggalkan banyak artefak eksekusi, masing-masing dengan cakupan dan keterbatasan berbeda. Tidak ada satu artefak yang menjawab semuanya; kekuatan forensik datang dari mengorelasikan beberapa.

Bahaya terbesar di sini adalah salah tafsir: beberapa artefak yang sering disebut "bukti eksekusi" sebenarnya hanya membuktikan file ada atau terdaftar, bukan dijalankan. Day ini menekankan apa yang benar-benar dibuktikan tiap artefak, karena kesimpulan yang salah di titik ini merusak seluruh investigasi.

**Kapan dipakai:** hampir setiap investigasi yang menanyakan program apa yang berjalan, kapan, oleh siapa.
**Kapan terbatas:** artefak eksekusi bisa dinonaktifkan, dirotasi, atau tidak ada di versi Windows tertentu; selalu padukan dengan event log (Day 05) dan artefak lain.

## 3. Konsep inti

### 3.1 Peta artefak eksekusi

| Artefak | Lokasi | Membuktikan | Tidak membuktikan | Parser EZ |
|---|---|---|---|---|
| Prefetch | `C:\Windows\Prefetch\*.pf` | Program dijalankan; run count; sampai 8 waktu run terakhir; file yang dimuat | Siapa user; bisa nonaktif di server/SSD tertentu | PECmd |
| Amcache | `C:\Windows\appcompat\Programs\Amcache.hve` | Metadata program (path, SHA1, first seen) | Belum tentu dijalankan; keberadaan di cache | AmcacheParser |
| Shimcache (AppCompatCache) | SYSTEM hive | File ada dan di-shim; path, last modified, urutan | BUKAN bukti eksekusi; waktu = last modified file, bukan waktu run | AppCompatCacheParser |
| UserAssist | NTUSER.DAT per user | Program diluncurkan lewat GUI; run count; last run; focus time | Program non-GUI; per user saja | RECmd |
| BAM/DAM | SYSTEM hive | Last execution time per user SID | Run count; hanya sebagian proses | RECmd |
| SRUM | `C:\Windows\System32\sru\SRUDB.dat` | Pemakaian resource dan jaringan per aplikasi (sekitar 30-60 hari) | Waktu run presisi | SrumECmd |
| PCA (Windows 11) | `C:\Windows\appcompat\pca\*.txt` | Peluncuran GUI; last execution time | Sebagian peluncuran saja; baru, retensi terbatas | teks/parser |

Tidak ada artefak tunggal yang cukup. Korelasi beberapa artefak yang menunjuk program yang sama memperkuat kesimpulan.

### 3.2 Prefetch: yang paling jelas

Prefetch (`*.pf`) dibuat OS untuk mempercepat start program [S1]. Untuk forensik, PECmd mengekstrak [S2]:
- Nama dan path executable.
- Run count (berapa kali dijalankan).
- Sampai delapan waktu run terakhir (versi Windows modern; versi lama hanya satu), cek jumlah per versi.
- Daftar file dan direktori yang dirujuk saat run (berguna melihat DLL atau file yang dibuka).

Keterbatasan: Prefetch bisa dinonaktifkan (sering di server, atau pada sebagian konfigurasi SSD), dan jumlah entri terbatas (historisnya 1024 di Windows 10/11, lebih kecil di versi lama), perlu dicek. Nama file `.pf` memuat hash path, sehingga dua executable bernama sama di path berbeda punya `.pf` berbeda.

Prefetch adalah bukti eksekusi yang kuat: keberadaan `.pf` untuk sebuah executable berarti executable itu dijalankan.

### 3.3 Shimcache dan Amcache: hati-hati menafsir

Dua artefak ini paling sering disalahtafsirkan:

- **Shimcache (AppCompatCache)** di SYSTEM hive mencatat file yang ditemui subsistem kompatibilitas aplikasi. Yang dicatat: path dan **last modified time file** (bukan waktu eksekusi), plus urutan entri [S3]. Keberadaan di Shimcache **bukan** bukti eksekusi; file bisa masuk Shimcache tanpa dijalankan. Shimcache ditulis ke registry saat shutdown, sehingga entri terbaru mungkin belum tersimpan sampai reboot, cek perilaku flush per versi.
- **Amcache** (`Amcache.hve`) mencatat metadata program termasuk SHA1 dan waktu first-seen [S3]. Berguna untuk mendapat hash executable yang mungkin sudah terhapus, tetapi keberadaan di Amcache juga tidak selalu berarti dijalankan.

Pesan utama: Shimcache dan Amcache menjawab "file ini ada/dikenal sistem" lebih kuat daripada "file ini dijalankan". Untuk eksekusi, padukan dengan Prefetch, UserAssist, atau event log.

### 3.4 UserAssist dan BAM: per user dan waktu

- **UserAssist** (NTUSER.DAT per user) mencatat program yang diluncurkan lewat GUI (Explorer), dengan run count, last run time, dan focus time [S3]. Karena per user (di hive NTUSER masing-masing), ia menjawab "user ini meluncurkan program itu". Nilainya ROT13-encoded di registry; RECmd mendekodekannya.
- **BAM/DAM (Background/Desktop Activity Moderator)** di SYSTEM hive mencatat last execution time per user SID untuk sebagian proses [S3]. Berguna untuk waktu eksekusi terakhir yang terikat ke user.

Keduanya menambah dimensi "siapa" yang tidak ada di Prefetch (yang tidak mencatat user).

### 3.5 SRUM: resource dan jaringan per aplikasi

SRUM (System Resource Usage Monitor, `SRUDB.dat`) mencatat pemakaian resource per aplikasi selama sekitar 30-60 hari: CPU, byte jaringan terkirim/diterima per aplikasi, dan profil jaringan [S3]. Untuk forensik:
- Membuktikan aplikasi aktif pada rentang waktu (per jam).
- Byte jaringan per aplikasi berguna untuk exfiltration (T1041, T1567): aplikasi apa yang mengirim banyak data, misalnya `rclone.exe` atau browser yang mengunggah ratusan MB di luar jam kerja.
- SrumECmd memparse SRUDB.dat (butuh juga SOFTWARE hive untuk resolusi), cek input yang dibutuhkan.

SRUM unik karena memberi volume jaringan per aplikasi, yang jarang ada di artefak lain.

### 3.6 PCA: artefak eksekusi baru Windows 11

PCA (Program Compatibility Assistant) di Windows 11 menyimpan data di `C:\Windows\appcompat\pca\`, termasuk `PcaAppLaunchDic.txt` yang memetakan path file ke last execution time [S4][S5]. Ciri:
- File teks (ANSI/CP-1252, CRLF), tidak perlu parser khusus [S4][S5].
- Menangkap sebagian peluncuran GUI (lewat Explorer); bukan semua cara eksekusi [S4][S5].
- Entri diperbarui (last execution), bukan ditambahkan; retensi terbatas [S5].
- Kehadiran tidak dijamin: sebagian build/host tidak memiliki file ini; ketiadaan tidak konklusif [S5].
- Lebih baru dari artefak klasik, sehingga sebagian anti-forensik mungkin melewatkannya [S6].

PCA melengkapi, bukan menggantikan, Prefetch/Amcache/UserAssist [S4]. Velociraptor punya artifact `Windows.System.AppCompatPCA` untuk memparsenya [S6], cek nama di versi lab.

### 3.7 Korelasi: memperkuat kesimpulan

Karena tiap artefak punya cakupan berbeda, korelasi adalah kuncinya. Contoh klaim "malware.exe dijalankan di WIN-LAB01 pada 14:03":
- Prefetch `MALWARE.EXE-xxxx.pf` dengan last run 14:03: bukti kuat eksekusi.
- UserAssist di NTUSER alice: diluncurkan GUI oleh alice.
- Amcache: SHA1 untuk dicocokkan ke intel (meski file terhapus).
- SRUM: aktivitas jaringan aplikasi itu.
- Shimcache: file dikenal sistem (mendukung, bukan membuktikan run).
- Security 4688 (bila audit): proses dibuat dengan command line.

Beberapa artefak yang sepakat membuat kesimpulan jauh lebih kuat daripada satu. Bila artefak bertentangan (mis. Shimcache ada tetapi tidak ada Prefetch/UserAssist), itu justru petunjuk (file ada tetapi mungkin tidak dijalankan, atau Prefetch nonaktif).

## 4. Artefak, perintah, dan cara membacanya

> Perintah dijalankan di VM analisis atas koleksi (Day 03-04). Keluaran berlabel ilustrasi. Input hive/path perlu dicek terhadap struktur koleksi lab.

### 4.1 Prefetch dengan PECmd

```
PECmd.exe -d ".\triage\C\Windows\Prefetch" --csv ".\analysis" --csvf prefetch.csv
```

- `-d` memproses semua `.pf` di folder; `-f` untuk satu file.
- Output CSV memuat executable, run count, dan waktu run (kolom RunLast dan sampai delapan sebelumnya).
- Buka di Timeline Explorer; sortir kolom LastRun untuk melihat eksekusi terbaru.

Keluaran ilustrasi:

```
Executable        RunCount  LastRun               PreviousRun0          FilesLoaded
MALWARE.EXE       3         2026-10-02 14:03:01Z  2026-10-02 13:55:10Z  \VOLUME\...\malware.exe; ...
```

### 4.2 Amcache dengan AmcacheParser

```
AmcacheParser.exe -f ".\triage\C\Windows\appcompat\Programs\Amcache.hve" --csv ".\analysis"
```

- Menghasilkan beberapa CSV (associated file entries, dll.). Yang penting: path, SHA1, dan waktu.
- SHA1 berguna mencocokkan ke intel/VirusTotal meski file sudah terhapus (tetapi keberadaan di Amcache bukan bukti run).
- Cek path `Amcache.hve` dalam koleksi.

### 4.3 Shimcache dengan AppCompatCacheParser

```
AppCompatCacheParser.exe -f ".\triage\C\Windows\System32\config\SYSTEM" --csv ".\analysis" --csvf shimcache.csv
```

- Input adalah SYSTEM hive. Output: path, last modified time file, dan posisi (urutan) entri.
- **Cara membaca:** kolom waktu adalah last modified file, BUKAN waktu eksekusi. Posisi/urutan bisa menunjukkan kebaruan relatif. Jangan simpulkan eksekusi dari Shimcache sendiri [S3].

### 4.4 UserAssist dan BAM dengan RECmd

```
RECmd.exe -f ".\triage\C\Users\alice\NTUSER.DAT" --bn BatchExamples\UserActivity.reb --csv ".\analysis"
```

- RECmd memakai batch file (`.reb`) yang berisi kumpulan key yang diparse, termasuk UserAssist. EZ Tools menyediakan batch contoh, cek nama batch file yang mencakup UserAssist/BAM di versi lab.
- UserAssist terdekode (dari ROT13) menunjukkan program GUI, run count, last run, focus time.
- BAM/DAM dari SYSTEM hive (`-f ...\SYSTEM` dengan batch yang sesuai) memberi last execution per SID.

### 4.5 SRUM dengan SrumECmd

```
SrumECmd.exe -f ".\triage\C\Windows\System32\sru\SRUDB.dat" --csv ".\analysis"
```

- Memparse SRUDB.dat menjadi CSV: app resource usage dan network usage per aplikasi.
- Cek apakah SrumECmd butuh SOFTWARE hive untuk resolusi nama; sediakan bila diminta.
- Cara membaca: cari aplikasi dengan byte jaringan keluar (`BytesSent`) yang besar dibanding kebiasaannya, atau aktivitas pada jam yang relevan. Ingat SRUM mencatat per interval sekitar satu jam, jadi angka adalah total per interval, bukan per koneksi.

### 4.6 PCA (Windows 11)

```
# PcaAppLaunchDic.txt adalah teks; baca langsung atau impor ke Timeline Explorer
type ".\triage\C\Windows\appcompat\pca\PcaAppLaunchDic.txt"
```

- File teks memetakan path executable ke last execution time [S4][S5].
- Berguna di host Windows 11; padukan dengan Prefetch/UserAssist.
- Cek keberadaan file (tidak dijamin ada) dan format delimiter di build lab [S5].

### 4.7 Tabel korelasi satu program

Buat tabel yang menyatukan bukti untuk satu executable:

| Artefak | Temuan untuk malware.exe | Membuktikan |
|---|---|---|
| Prefetch | RunCount 3, LastRun 14:03 | Dijalankan, 3x, waktu |
| UserAssist (alice) | Ada, LastRun 14:03 | Diluncurkan GUI oleh alice |
| Amcache | SHA1 abc... | Hash (untuk intel), bukan run |
| Shimcache | Ada, LM 10:00 | File dikenal sistem |
| SRUM | 50 MB keluar 14:00-15:00 | Aktivitas jaringan |
| Security 4688 | Ada (bila audit) | Proses + command line |

Kesimpulan: beberapa artefak sepakat bahwa malware.exe dijalankan oleh alice pada 14:03 dan mengirim data. Satu artefak saja (mis. Shimcache) tidak cukup.

## 5. Lab praktik

**Prasyarat:** koleksi triage dari VM korban (Day 03-04) yang mencakup Prefetch, Amcache, SYSTEM, NTUSER, SRUM, dan (bila Windows 11) PCA; VM analisis dengan EZ Tools; satu program uji yang kamu jalankan di korban.

1. **Jalankan program uji.** Di VM korban (snapshot), jalankan satu program jinak beberapa kali lewat Explorer (GUI) dan catat waktunya. Kumpulkan triage.
2. **Parse semua artefak eksekusi.** Jalankan PECmd, AmcacheParser, AppCompatCacheParser, RECmd (UserAssist/BAM), SrumECmd (bagian 4.1-4.5). Bila Windows 11, baca PCA (bagian 4.6).
3. **Temukan program uji.** Di tiap artefak, temukan program yang kamu jalankan. Catat apa yang tiap artefak tunjukkan.
4. **Korelasi.** Isi tabel korelasi (bagian 4.7) untuk program uji. Tandai mana yang membuktikan eksekusi dan mana yang hanya keberadaan.
5. **Uji salah tafsir.** Salin (bukan jalankan) satu executable ke disk korban, kumpulkan ulang, dan periksa: apakah muncul di Shimcache/Amcache tanpa Prefetch/UserAssist? Buktikan bahwa keberadaan di Shimcache bukan eksekusi.
6. **Catat keterbatasan.** Untuk tiap artefak, tulis satu kalimat keterbatasannya di cheat sheet pribadi.

**Hasil yang sebaiknya tersimpan:**
- Enam artefak eksekusi (plus PCA bila ada) diparse.
- Program uji ditemukan di minimal Prefetch dan UserAssist.
- Tabel korelasi terisi dengan pembedaan "eksekusi" vs "keberadaan".
- Dibuktikan bahwa keberadaan di Shimcache bukan bukti eksekusi.
- Keterbatasan tiap artefak tercatat.

**Variasi tantangan:** nonaktifkan Prefetch di VM korban (snapshot), jalankan program, kumpulkan, dan tunjukkan bagaimana kamu masih membuktikan eksekusi dari artefak lain (UserAssist, Amcache plus event log, SRUM). Tulis kombinasi minimal yang kamu percaya untuk menyimpulkan eksekusi tanpa Prefetch.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Tidak ada Prefetch | Dinonaktifkan (server/SSD) atau dibersihkan | Pakai artefak lain; catat Prefetch nonaktif |
| Shimcache terbaru tidak ada | Belum di-flush ke registry (sebelum reboot) | Sadari perilaku flush; jangan simpulkan ketiadaan, perlu dicek |
| UserAssist kosong | Program non-GUI; user berbeda | Cek NTUSER user yang benar; UserAssist hanya GUI |
| AmcacheParser error | Hive korup atau path salah | Verifikasi path; cek versi parser |
| SRUM tidak ter-resolve nama | Butuh SOFTWARE hive | Sediakan SOFTWARE hive bila diminta, perlu dicek |
| PCA tidak ada | Build tidak membuat file; bukan Windows 11 | Ketiadaan tidak konklusif [S5] |

## 7. Kesalahan umum dan jebakan

- **Menyebut Shimcache sebagai bukti eksekusi.** Shimcache membuktikan file dikenal sistem dan last modified-nya, bukan run [S3].
- **Menganggap waktu Shimcache sebagai waktu eksekusi.** Itu last modified file.
- **Mengira Amcache = dijalankan.** Amcache memberi metadata dan hash, tidak selalu eksekusi.
- **Mengandalkan satu artefak.** Korelasikan beberapa; satu bisa menyesatkan.
- **Mengira ketiadaan Prefetch/PCA berarti tidak dijalankan.** Bisa nonaktif, dirotasi, atau tidak dibuat.
- `[komunitas, belum terkonfirmasi]` Komunitas DFIR menekankan bahwa Shimcache dan Amcache sering disalahtafsirkan sebagai bukti eksekusi; keduanya lebih kuat sebagai bukti keberadaan [S3]. PCA Windows 11 adalah sumber baru yang melengkapi artefak klasik [S4][S6]; formatnya bisa berubah antar build, perlu dicek.

## 8. Catatan terkini

- PCA Windows 11 (22H2/23H2) menyimpan last execution time peluncuran GUI di `C:\Windows\appcompat\pca\PcaAppLaunchDic.txt`; baru, retensi terbatas, kehadiran tidak dijamin [S4][S5].
- Velociraptor punya artifact untuk memparse PCA [S6].
- Artefak klasik (Prefetch, Amcache, Shimcache, UserAssist, BAM, SRUM) tetap inti; perilaku dan jumlah entri bisa berbeda antar versi Windows, perlu dicek.
- Day 08 masuk ke file system (MFT, USN, $LogFile) yang melengkapi bukti eksekusi dengan bukti keberadaan dan waktu file.

## 9. Cheat sheet

```
PREFETCH   C:\Windows\Prefetch\*.pf ; PECmd ; BUKTI run + run count + 8 waktu + file dimuat ; bisa nonaktif
AMCACHE    Amcache.hve ; AmcacheParser ; metadata + SHA1 + first seen ; bukan selalu run
SHIMCACHE  SYSTEM hive ; AppCompatCacheParser ; path + LAST MODIFIED file + urutan ; BUKAN bukti eksekusi ; flush saat shutdown
USERASSIST NTUSER.DAT ; RECmd ; program GUI per user, run count, last run, focus ; ROT13
BAM/DAM    SYSTEM hive ; RECmd ; last execution per user SID
SRUM       SRUDB.dat ; SrumECmd ; resource + byte jaringan per app (~30-60 hari)
PCA (Win11) C:\Windows\appcompat\pca\PcaAppLaunchDic.txt ; teks ; last execution GUI ; baru, tak dijamin ada
KORELASI   beberapa artefak sepakat = kuat ; Shimcache/Amcache = keberadaan, Prefetch/UserAssist = eksekusi
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Mekanisme Prefetch Windows (literatur DFIR umum) | (tanpa URL; dokumentasi resmi Microsoft untuk format Prefetch tidak tersedia) | sekunder | 2026-10-10 | Sedang. Fungsi Prefetch sebagai cache start program; detail format dari PECmd [S2] |
| S2 | Eric Zimmerman tools: PECmd, AmcacheParser, AppCompatCacheParser, RECmd, SrumECmd | https://ericzimmerman.github.io/ | primer | diakses 2026-10-09 (Day 02) | Tinggi. Parser dan output |
| S3 | Praktik DFIR: makna Shimcache/Amcache/UserAssist/BAM/SRUM | https://www.sans.org/posters/windows-forensic-analysis/ | sekunder (SANS) | diakses 2026-10-09 | Sedang-tinggi. Makna dan keterbatasan artefak |
| S4 | Sygnia: Diving into the new Windows 11 PCA artifact | https://www.sygnia.co/?p=133 | sekunder (peneliti) | 2026; diakses 2026-10-09 | Sedang-tinggi. Lokasi dan isi PCA |
| S5 | Andrea Fortuna: Windows 11 PCA artifact | https://andreafortuna.org/2026/03/19/windows11-pca-artifact/ | sekunder | 2026-03; diakses 2026-10-09 | Sedang. Last execution, keterbatasan |
| S6 | Velociraptor artifact: Windows.System.AppCompatPCA | https://docs.velociraptor.app/exchange/artifacts/pages/windows.system.appcompatpca | primer | diakses 2026-10-09 | Sedang-tinggi. Parser PCA |

**Catatan sumber:** Microsoft tidak mendokumentasikan format Prefetch, Shimcache, Amcache, atau BAM untuk keperluan forensik; makna artefak di Day ini berasal dari literatur DFIR (poster SANS [S3]) dan perilaku parser EZ Tools [S2]. Jumlah waktu run Prefetch per versi, batas jumlah entri, perilaku flush Shimcache, dan kebutuhan SOFTWARE hive untuk SrumECmd bergantung versi dan perlu diuji di lab. Informasi PCA berasal dari peneliti pihak ketiga [S4][S5]; formatnya bisa berubah antar build Windows 11.
