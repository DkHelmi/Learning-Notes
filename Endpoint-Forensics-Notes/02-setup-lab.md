---
day: 02
title: 'Setup lab DFIR: VM korban dan analisis, EZ Tools, KAPE, Velociraptor, Volatility 3, dan dataset publik'
researched_on: 2026-10-10
versions_checked: 'Volatility 3 2.28.2 (17 Sep); EZ Tools (.NET 9 default, Get-ZimmermanTools); KAPE (Kroll); Velociraptor 0.77.3 (5 Okt 2026); Plaso/Timesketch; rujukan Day 01'
---

# Day 02: Setup lab DFIR

Cakupan: membangun lab DFIR terisolasi berisi VM korban, VM analisis, rangkaian alat inti, dan struktur folder bukti yang dipakai di Day berikutnya.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- merancang topologi lab DFIR: VM korban, VM analisis, dan isolasi yang aman.
- memasang dan memverifikasi rangkaian alat inti: EZ Tools, KAPE, Velociraptor, Volatility 3, Plaso/Timesketch.
- mengambil dataset publik yang sah untuk latihan tanpa data kerja atau malware liar.
- menjaga kebersihan bukti dengan snapshot, hashing, dan folder kerja yang terpisah.
- mencatat versi dan lisensi alat agar hasil bisa direproduksi dan aman dipakai.

## 2. Konteks singkat

Day 01 adalah keputusan; Day ini membangun tempat untuk mempraktikkannya. Lab DFIR yang baik memisahkan tiga hal: tempat bukti dihasilkan (VM korban), tempat bukti dianalisis (VM analisis), dan bukti itu sendiri (disimpan read-only, di-hash). Tanpa pemisahan ini, mudah mencemari bukti atau menjalankan sesuatu yang berbahaya di tempat yang salah.

Lab ini dipakai sepanjang catatan ini: Day 03-13 memakai artefak disk dan registry, Day 14-16 memakai memori, Day 17-18 menjalankan simulasi kasus penuh. Membangunnya benar sekarang menghemat waktu nanti.

**Kapan dipakai:** sekali di awal, lalu dirawat (snapshot bersih, update alat).
**Kapan hati-hati:** saat menangani sampel atau image yang tidak dikenal; isolasi jaringan dan snapshot wajib sebelum menyentuhnya.

## 3. Konsep inti

### 3.1 Topologi lab

Tiga peran, idealnya tiga VM atau minimal dua plus penyimpanan terpisah:

| Peran | Isi | Catatan |
|---|---|---|
| VM korban (Windows) | Windows 10/11 dengan Sysmon dan audit policy yang diperluas (bagian 3.2), tempat aktivitas jinak dijalankan | Snapshot bersih sebelum tiap skenario |
| VM analisis | EZ Tools, KAPE, Volatility 3, Timeline Explorer, Registry Explorer; tempat artefak diparse | Tidak menjalankan sampel; hanya menganalisis |
| Server Velociraptor (opsional) | Server + client di VM korban (Day 04) | Untuk koleksi lintas host |

Penyimpanan bukti: folder read-only atau share terpisah tempat artefak yang dikumpulkan disimpan dan di-hash (Day 01). Jangan menganalisis di folder yang sama tempat bukti asli disimpan; bekerja di salinan.

### 3.2 Isolasi dan keamanan

- **Jaringan host-only atau internal.** VM korban tidak boleh menjangkau internet atau jaringan nyata saat menjalankan skenario, agar aktivitas uji tidak bocor dan sampel tidak menyebar.
- **Snapshot.** Ambil snapshot bersih VM korban sebelum tiap skenario, kembalikan setelahnya (Day 01, dan setiap lab di catatan ini).
- **VM analisis tidak menjalankan sampel.** Ia memparse artefak mati (file, hive, image memori), bukan mengeksekusi biner yang dicurigai.
- **Image memori dan sampel diperlakukan sebagai data.** Volatility 3 menganalisis image sebagai file; tidak menjalankan isinya.
- **Telemetri VM korban diperkaya.** Pasang Sysmon dengan konfigurasi komunitas yang umum (misalnya konfigurasi SwiftOnSecurity atau Olaf Hartong) agar ada event proses (EID 1), koneksi jaringan (EID 3), file dibuat (EID 11), dan perubahan registry (EID 12-14). Aktifkan juga audit policy yang tidak menyala secara default: Audit Process Creation beserta setting "Include command line in process creation events" (menghasilkan 4688 dengan command line), Audit User Account Management (4720, 4728, 4732), Audit Other Object Access Events (4698 untuk scheduled task), dan PowerShell Script Block Logging (4104). Tanpa ini, banyak event yang dipakai di Day 05 dan 11 tidak akan muncul di lab [S7][S8].

### 3.3 Rangkaian alat inti

| Alat | Fungsi | Lisensi/catatan |
|---|---|---|
| EZ Tools (Eric Zimmerman) | Parser artefak Windows (MFT, registry, Prefetch, event log, dll.) | Gratis; .NET 9 default; updater Get-ZimmermanTools [S2] |
| KAPE (Kroll) | Koleksi triage (Targets) dan pemrosesan (Modules) | Gratis untuk banyak penggunaan; cek lisensi komersial [S3] |
| Velociraptor | Koleksi dan hunting lintas endpoint (VQL, artifact) | Open source; 0.77.3 [S4] |
| Volatility 3 | Analisis memori | Open source; 2.28.2; Python [S1] |
| Plaso (log2timeline) + Timesketch | Super-timeline dan visualisasinya | Open source (Day 13) [S5] |
| Timeline Explorer, Registry Explorer (EZ) | GUI untuk membaca hasil parse | Bagian EZ Tools, .NET 9 [S2] |

Rangkaian ini menutup disk, registry, event log, memori, dan timeline, cukup untuk seluruh rangkaian Day.

### 3.4 EZ Tools dan Get-ZimmermanTools

EZ Tools adalah kumpulan parser command-line dan GUI dari Eric Zimmerman [S2]. Yang paling dipakai di catatan ini:

| Tool | Artefak | Day |
|---|---|---|
| MFTECmd | `$MFT`, `$J` (USN), `$LogFile` | 08 |
| RECmd, Registry Explorer | Registry hive | 09 |
| PECmd | Prefetch | 07 |
| AppCompatCacheParser, AmcacheParser | Shimcache, Amcache | 07 |
| EvtxECmd | Windows event log (.evtx ke CSV/JSON) | 05 |
| JLECmd, LECmd | Jump list, LNK | 10 |
| SBECmd, ShellBags Explorer | ShellBags | 10 |
| SrumECmd | SRUM | 07 |
| Timeline Explorer | Membaca CSV hasil parse | semua |

Dipasang dan diperbarui dengan skrip `Get-ZimmermanTools`: `-Dest` menetapkan lokasi, `-NetVersion` memilih 4 (.NET 4.7.2), 9 (.NET 9, default), atau 0 (semua) [S2]. Versi .NET 9 adalah default dan dipakai GUI; pastikan runtime .NET 9 terpasang di VM analisis.

### 3.5 Dataset publik untuk latihan

Karena catatan ini tidak memakai data kerja atau data klien, latihan memakai data lab sendiri atau dataset publik:

- **Aktivitas lab sendiri:** jalankan aktivitas jinak di VM korban, lalu kumpulkan artefaknya. Paling fleksibel dan aman. Untuk meniru teknik penyerang secara terkendali, katalog Atomic Red Team (Red Canary) berisi test kecil per teknik ATT&CK, masing-masing dengan ID teknik dan GUID, perintah yang dijalankan, dan perintah cleanup. Pilih test berdasarkan ID teknik, baca isinya untuk memahami jejak yang akan muncul (proses, file, key registry, event), lalu jalankan hanya di VM korban dengan snapshot [S9].
- **Dataset publik DFIR:** image dan koleksi latihan dari sumber seperti CyberDefenders, DFIR Report (artefak yang dipublikasikan), dan tantangan CTF forensik. Cek lisensi tiap dataset sebelum dipakai atau dipublikasikan ulang; banyak yang gratis untuk latihan tetapi tidak untuk redistribusi.
- **Image memori sampel:** sebagian tersedia untuk latihan Volatility (Day 14). Perlakukan sebagai data; jangan jalankan isinya.

Jangan mengunduh sampel malware liar ke lab yang tidak dirancang untuknya; analisis malware aktif berada di luar cakupan catatan ini dan butuh lab dengan isolasi tersendiri.

### 3.6 Kebersihan bukti di lab

Terapkan Day 01 secara konkret:
- Hash tiap koleksi artefak saat dibuat (`Get-FileHash` atau `sha256sum`), simpan daftar hash terpisah.
- Bekerja di salinan, bukan bukti asli.
- Catat waktu, sumber, dan metode tiap koleksi (catatan kasus).
- Folder kerja per kasus: `cases/<id>/evidence/`, `cases/<id>/analysis/`, `cases/<id>/notes.md`.

Meski ini lab latihan, membiasakan kebersihan bukti sekarang membuatnya refleks saat kasus nyata.

### 3.7 Mencatat versi dan lisensi

Hasil forensik bergantung versi alat (plugin Volatility, parser EZ berubah). Catat di `docs/lab-inventory.md`: nama alat, versi, tanggal pasang, dan lisensi. Ini memenuhi aturan akurasi (sebut versi) dan mencegah kejutan saat hasil berbeda setelah update.

## 4. Artefak, perintah, dan cara membacanya

> Perintah dijalankan di VM lab-mu sendiri, bukan dari materi ini di mesin kerja. Keluaran berlabel ilustrasi. Versi pin disebut.

### 4.1 Memasang EZ Tools

Di VM analisis Windows (PowerShell), dengan skrip resmi Get-ZimmermanTools [S2]:

```
.\Get-ZimmermanTools.ps1 -Dest C:\DFIR\EZTools -NetVersion 9
```

- `-Dest` menaruh semua tool di satu folder; `-NetVersion 9` mengambil build .NET 9 (default).
- Pastikan runtime .NET 9 terpasang lebih dulu.
- Verifikasi: jalankan `MFTECmd.exe` tanpa argumen; harus menampilkan bantuan dan versi.

Keluaran ilustrasi (versi):

```
MFTECmd version 1.x.x.x
Author: Eric Zimmerman
```

Catat versi tiap tool di `docs/lab-inventory.md` (bagian 3.7).

### 4.2 Verifikasi KAPE

KAPE dijalankan dari foldernya (gkape.exe GUI atau kape.exe CLI) [S3]. Verifikasi tanpa mengumpulkan apa pun berbahaya:

```
kape.exe --tlist
kape.exe --mlist
```

- `--tlist` menampilkan daftar Target (apa yang bisa dikumpulkan); `--mlist` daftar Module (pemrosesan).
- Pada Day 03 kamu menjalankan koleksi sebenarnya; hari ini cukup pastikan KAPE mengenali Target dan Module.
- Cek lisensi KAPE untuk penggunaan di konteksmu (gratis untuk banyak kasus, tetapi cek untuk komersial) [S3].

### 4.3 Verifikasi Volatility 3

Volatility 3 berjalan di Python [S1]. Verifikasi:

```
python3 vol.py -h
python3 vol.py -f /dev/null windows.info
```

- `-h` menampilkan bantuan dan daftar plugin.
- Perintah kedua akan gagal (bukan image valid), tetapi error yang benar menandakan Volatility berjalan. Image memori nyata dipakai di Day 14.
- Catat versi: `python3 vol.py --version` harus menunjukkan 2.28.x [S1].

Keluaran ilustrasi:

```
Volatility 3 Framework 2.28.2
```

### 4.4 Verifikasi Velociraptor

Velociraptor sebagai binary mandiri [S4]:

```
velociraptor version
velociraptor gui
```

- `version` memastikan biner berjalan (harus 0.77.x).
- `gui` menjalankan mode GUI mandiri untuk eksplorasi lokal; server penuh dengan client dibangun di Day 04.
- Cek perintah persis di versi lab; mode GUI mandiri berguna untuk belajar sebelum deploy server.

### 4.5 Dataset uji

Ambil satu dataset publik kecil (atau buat sendiri dari VM korban) dan buktikan tiap alat memparse-nya:

```
# contoh: parse $MFT dari koleksi triage (Day 03/08)
MFTECmd.exe -f "C:\DFIR\evidence\C\$MFT" --csv "C:\DFIR\analysis" --csvf mft.csv
```

- Hasil CSV dibuka di Timeline Explorer. Bila baris muncul dan timestamp terbaca, parser berfungsi.
- Ini sekaligus latihan alur: koleksi (Day 03), parse (EZ Tools), baca (Timeline Explorer).
- Cek path `$MFT` dalam struktur koleksi KAPE/Velociraptor lab-mu.

### 4.6 Struktur folder kasus

```
C:\DFIR\
  tools\            EZTools, KAPE, Velociraptor, Volatility
  cases\
    CASE-2026-001\
      evidence\     koleksi mentah (read-only), + hashes.txt
      analysis\     hasil parse (CSV, JSON)
      memory\       image memori (Day 14)
      notes.md      catatan kasus dan chain of custody (Day 01)
  datasets\         dataset publik untuk latihan
  docs\lab-inventory.md
```

- Pemisahan `evidence` (mentah, read-only) dan `analysis` (hasil kerja) mencegah pencemaran bukti (Day 01).
- `hashes.txt` di tiap folder evidence memegang hash koleksi.

## 5. Lab praktik

**Prasyarat:** hypervisor (VirtualBox/VMware/Hyper-V); ISO Windows untuk VM korban; VM analisis Windows dengan .NET 9; akses internet hanya di VM analisis untuk mengunduh alat (dari sumber resmi, oleh kamu sendiri).

1. **Topologi.** Buat VM korban (Windows + Sysmon + audit policy, bagian 3.2) dan VM analisis. Set jaringan VM korban ke host-only/internal. Ambil snapshot bersih keduanya.
2. **EZ Tools.** Jalankan Get-ZimmermanTools (bagian 4.1) di VM analisis. Verifikasi MFTECmd, EvtxECmd, RECmd, PECmd menampilkan versi.
3. **KAPE.** Pasang KAPE; jalankan `--tlist` dan `--mlist` (bagian 4.2). Catat lisensi.
4. **Volatility 3.** Pasang Volatility 3; verifikasi versi (bagian 4.3).
5. **Velociraptor.** Pasang biner Velociraptor; verifikasi versi dan mode GUI (bagian 4.4). Server penuh di Day 04.
6. **Dataset.** Ambil satu dataset publik kecil (cek lisensi) atau buat koleksi dari VM korban. Parse `$MFT` atau satu event log dengan EZ Tools dan buka di Timeline Explorer (bagian 4.5).
7. **Struktur dan hash.** Buat struktur folder kasus (bagian 4.6). Hash satu koleksi dan simpan ke `hashes.txt`.
8. **Inventaris.** Isi `docs/lab-inventory.md` dengan versi dan lisensi tiap alat.

**Hasil yang sebaiknya tersimpan:**
- VM korban dan analisis berjalan; VM korban terisolasi; snapshot bersih diambil.
- EZ Tools terpasang; minimal empat parser menampilkan versi.
- KAPE mengenali Target dan Module; lisensi dicatat.
- Volatility 3 2.28.x dan Velociraptor 0.77.x terverifikasi.
- Satu dataset diparse dan dibaca di Timeline Explorer.
- Struktur folder kasus dan hash dibuat; inventaris alat terisi.

**Variasi tantangan:** buat skrip koleksi hash sederhana yang menghitung SHA256 semua file di folder `evidence` dan menyimpannya ke `hashes.txt`, lalu skrip verifikasi yang membandingkan ulang. Jalankan verifikasi setelah menyalin bukti ke folder `analysis` dan pastikan hash cocok. Ini melatih kebersihan bukti Day 01 secara otomatis.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| EZ Tool tidak jalan | Runtime .NET 9 belum terpasang | Pasang .NET 9; atau pakai `-NetVersion 4` [S2] |
| Get-ZimmermanTools gagal | Eksekusi skrip diblokir; tanpa internet | Izinkan skrip; jalankan di VM analisis yang punya akses unduh |
| KAPE tidak menampilkan Target | Folder Targets/Modules tidak lengkap | Perbarui KAPE; cek struktur folder |
| Volatility error import | Dependensi Python kurang | Pasang di virtualenv; `pip install -r requirements.txt` dari folder Volatility 3 [S1] |
| Velociraptor GUI tidak terbuka | Perintah beda versi | `velociraptor -h` untuk melihat subcommand yang tersedia di versi lab [S4] |
| Timeline Explorer kosong | CSV salah atau parse gagal | Cek keluaran EZ Tool; pastikan path artefak benar |

## 7. Kesalahan umum dan jebakan

- **Menganalisis di VM korban.** Analisis di VM terpisah; korban hanya menghasilkan artefak.
- **VM korban terhubung internet saat skenario.** Isolasi; aktivitas uji dan sampel tidak boleh bocor.
- **Tidak snapshot sebelum skenario.** Tanpa snapshot bersih, lab cepat kotor dan hasil tidak bisa diulang.
- **Memakai dataset tanpa cek lisensi.** Banyak dataset gratis untuk latihan tetapi tidak untuk redistribusi; cek sebelum publikasi.
- **Tidak mencatat versi alat.** Hasil forensik bergantung versi; catat untuk reproduksibilitas.
- `[komunitas, belum terkonfirmasi]` Banyak praktisi memakai Get-ZimmermanTools untuk menjaga EZ Tools tetap terbarui, dan menjalankan KAPE plus EZ Tools di VM analisis Windows terpisah dari korban. Pola ini umum; sesuaikan dengan hypervisor dan sumber daya lab-mu [S2][S3].

## 8. Catatan terkini

- Volatility 3 2.28.2 (17 Sep) menambah renderer Mermaid dan verifikasi layer Intel Windows; analisis macOS kini memberi peringatan deprecation [S1].
- EZ Tools default ke build .NET 9; GUI (Timeline Explorer, Registry Explorer) hanya .NET 9 [S2].
- Velociraptor 0.77.3 adalah versi acuan; perbarui untuk CVE [S4].
- KAPE tetap gratis untuk banyak penggunaan; verifikasi lisensi untuk konteks komersial sebelum dipakai di pekerjaan [S3].

## 9. Cheat sheet

```
TOPOLOGI   VM korban (Windows+Sysmon, isolasi, snapshot) | VM analisis (parse, tidak jalankan sampel) | Velociraptor server (opsional)
ALAT       EZ Tools (.NET 9, Get-ZimmermanTools -Dest -NetVersion 9) | KAPE (--tlist --mlist) | Volatility3 2.28.x | Velociraptor 0.77.x | Plaso+Timesketch
EZ TOOLS   MFTECmd | RECmd/Registry Explorer | PECmd | AppCompatCacheParser | AmcacheParser | EvtxECmd | JLECmd/LECmd | SBECmd | SrumECmd | Timeline Explorer
DATASET    aktivitas lab sendiri (Atomic via katalog) | dataset publik (cek lisensi) | image memori sampel (data, jangan jalankan)
BUKTI      evidence/ read-only + hashes.txt | analysis/ (salinan) | notes.md (CoC) | hash saat dibuat
CATAT      docs/lab-inventory.md: nama, versi, tanggal, lisensi ; hasil forensik bergantung versi
AMAN       korban terisolasi + snapshot ; analisis tidak eksekusi sampel ; image/sampel = data
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Volatility 3 releases (2.28.2) | https://github.com/volatilityfoundation/volatility3/releases | primer | 2.28.2, 17 Sep; diakses 2026-10-09 | Tinggi. Versi, plugin, perubahan |
| S2 | Eric Zimmerman tools (daftar dan Get-ZimmermanTools) | https://ericzimmerman.github.io/ | primer | diakses 2026-10-09 | Tinggi. Tool, .NET 9, updater |
| S3 | KAPE (Kroll) | https://www.kroll.com/en/services/cyber/incident-response-litigation-support/kroll-artifact-parser-extractor-kape | primer (vendor) | diakses 2026-10-09; situs bisa menolak akses otomatis | Tinggi untuk fungsi; lisensi perlu dicek |
| S4 | Velociraptor releases dan dokumentasi | https://github.com/Velocidex/velociraptor/releases | primer | 0.77.3; diakses 2026-10-09 | Tinggi |
| S5 | Plaso / Timesketch (untuk Day 13) | https://plaso.readthedocs.io/ | primer | diakses 2026-10-09 | Tinggi; dipakai di Day 13 |
| S6 | Endpoint-Forensics Day 01 (akuisisi, hashing, CoC) | (lokal) | rujukan internal | 2026-10-09 | Kebersihan bukti |
| S7 | Microsoft Learn: Sysmon | https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon | primer | diakses 2026-10-10 | Tinggi. Daftar event ID Sysmon |
| S8 | Microsoft Learn: Command line process auditing | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing | primer | diakses 2026-10-10 | Tinggi. Setting command line di 4688 |
| S9 | Atomic Red Team (Red Canary) | https://github.com/redcanaryco/atomic-red-team | primer | diakses 2026-10-10 | Tinggi. Struktur test per teknik, GUID, cleanup |

**Catatan sumber:** lisensi KAPE untuk penggunaan komersial perlu dikonfirmasi langsung ke Kroll sebelum dipakai di pekerjaan. Dataset publik spesifik tidak diinventarisasi di sini; lisensi tiap dataset harus dicek sendiri. Kebutuhan versi Python untuk Volatility 3 2.28.x tidak tercantum di catatan rilis; versi lama mensyaratkan 3.8 ke atas. Perintah Velociraptor persis (`gui`, `version`) perlu dicek dengan `velociraptor -h` di versi lab.
