---
day: 07
title: 'Artefak eksekusi: Prefetch, Amcache, Shimcache, UserAssist, BAM, SRUM, dan PCA Windows 11'
researched_on: 2026-10-16
versions_checked: 'Windows 11 23H2 (host kasus) dan Windows 10/11 umumnya; EZ Tools 2026.5.0 (PECmd, AmcacheParser, AppCompatCacheParser, RECmd, SrumECmd; README repo masing-masing menyebut PECmd 1.4.0.0, AmcacheParser 1.4.0.0, AppCompatCache Parser 1.4.4.0, RECmd 1.6.0.0, SrumECmd 0.5.0.1); RECmd DFIRBatch.reb v2.22; KapeFiles EvidenceOfExecution.tkape v1.1; dokumentasi format Prefetch libscca 0.0.24 (Juli 2026, versi format 31 untuk Windows 11); artefak PCA Windows 11 22H2/23H2 (Sygnia, November 2023; Andrea Fortuna, Maret 2026); referensi artifact Velociraptor 0.77.3'
---

# Day 07: Artefak eksekusi (Prefetch, Amcache, Shimcache, UserAssist, BAM, SRUM, PCA)

Cakupan: artefak Windows yang menjawab program apa yang dijalankan, kapan, oleh akun siapa, dan berapa banyak data jaringan yang dipakainya, beserta batas apa yang dibuktikan dan tidak dibuktikan tiap artefak, cara memisahkan jejak responder dari jejak penyerang, dan cara menulis kesimpulan eksekusi di host tanpa EDR.

## Ide inti

Tidak ada satu artefak Windows yang menjawab "program ini dijalankan, kapan, oleh siapa, dan apa yang dilakukannya". Yang ada adalah beberapa catatan yang dibuat Windows untuk keperluannya sendiri (mempercepat start program, memeriksa kompatibilitas, mengatur proses latar belakang, mengukur pemakaian resource), dan masing-masing kebetulan menyimpan sebagian jawaban. Prefetch menyimpan bukti kuat bahwa sebuah executable dijalankan dan sampai delapan waktu run terakhir, tetapi tidak mencatat akun. BAM dan UserAssist mencatat akun, tetapi hanya waktu terakhir atau hanya peluncuran lewat Explorer. Shimcache dan Amcache mencatat bahwa file pernah dikenal sistem, lengkap dengan path dan hash, tetapi kehadiran di sana bukan bukti eksekusi. SRUM mencatat volume jaringan per aplikasi per jam, tanpa tujuan dan tanpa isi. PCA di Windows 11 mencatat sebagian peluncuran lewat antarmuka grafis. Kesimpulan eksekusi dibangun dari beberapa artefak yang sepakat, dan setiap kesimpulan harus menyebut apa yang tidak bisa dijawab, karena perintah yang dikerjakan di dalam proses yang sudah berjalan tidak meninggalkan artefak eksekusi sama sekali.

Kamu sudah mengenal pola ini dari NOC. Untuk membuktikan sebuah perangkat pelanggan benar-benar dipakai di port tertentu, tidak ada satu tabel yang cukup. Tabel MAC menunjukkan perangkat itu pernah terlihat di port, tetapi terlihat belum tentu mengirim trafik yang dicari. Counter interface menunjukkan port pernah aktif dan berapa kali flap, tetapi tidak tahu siapa penggunanya. RADIUS accounting menunjukkan akun siapa yang tersambung, tetapi hanya untuk sesi yang lewat AAA. Grafik MRTG per port menunjukkan berapa banyak trafik per lima menit, tetapi tidak tahu isinya atau tujuannya. Engineer yang berpengalaman tidak menulis "pelanggan ini memakai link pukul 14:03" dari satu tabel saja; ia menyusun beberapa sumber yang saling menguatkan, dan menyebut apa yang tidak tercatat di mana pun. Artefak eksekusi Windows dibaca dengan cara yang sama.

```
pertanyaan                     artefak utama                 batas utama
-----------------------------  ----------------------------  ---------------------------------------
dijalankan? kapan? berapa kali  Prefetch (.pf)                tanpa akun; 8 waktu terakhir; bisa nonaktif
oleh akun siapa?                BAM (per SID), UserAssist     BAM: waktu terakhir saja; UA: lewat Explorer saja
file pernah ada? hash?          Amcache, Shimcache            ada != dijalankan; waktu Shimcache = mtime file
data jaringan berapa banyak?    SRUM                          per jam, per aplikasi; tanpa tujuan, tanpa isi
peluncuran GUI (Windows 11)     PCA                           sebagian peluncuran saja; format tidak resmi
argumen dan perintah?           (tidak ada di artefak ini)    event log, memori
                 |
                 v
     tabel korelasi per program: dijalankan | hanya ada | jejak responder | tidak terjawab
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan dan data pribadi 400 ribu pelanggan broadband. Kasusnya `INC-2026-019`: email dari `billing@vendor-tagihan.example` dengan lampiran `Tagihan-Okt-2026.zip` (berisi `Tagihan-Okt-2026.js`) masuk ke 9 mailbox pada Senin 2026-10-12 pukul 15:58. Salah satu yang menjalankannya adalah `dewi.anggraini`, staf penagihan di kantor Bandung, pada laptop `BDG-WS-0142` (`10.30.14.42`, Windows 11 23H2, tanpa EDR, tanpa Sysmon), Selasa 2026-10-13 pukul 08:51. Laptop itu mulai menghubungi C2 `cdn-sync.example.net` (`203.0.113.77:443`) pukul 08:52. Selasa siang, teknisi POP Bandung Fajar Nugraha, dipandu Yoga Pratama lewat telepon, mengambil memori laptop dengan WinPmem dari USB bukti `USB-E-09` (E08, 14:05 sampai 14:13) memakai akun admin lokal khusus IR, lalu menjalankan skrip koleksi SOC dari USB yang sama. Pukul 16:00 laptop diisolasi dengan mematikan port switch dan Wi-Fi tanpa restart. Retainer PT Forensik Digital Contoh menganalisis memori E08 dan menyimpulkan loader yang sama dengan laptop lain, "hanya beacon dan enumerasi sistem dasar". Laptop dikirim ke Jakarta Jumat, di-image retainer Senin 2026-10-19 pukul 09:00 (E18), dan Yoga membuat salinan kerja internal `E18-W2` pukul 15:30 hari yang sama. Selasa 2026-10-20 pukul 09:00, Sari Kusuma (technical lead) menulis kepadamu di kanal `#inc-2026-019`:

> "Pagi. Laptop Dewi dijadwalkan reimage Kamis, jadi ini kesempatan terakhir kita memverifikasi sendiri dari disk. Pak Dimas tidak mau hanya pegang kesimpulan retainer dari memori, karena laptop itu tanpa EDR dan tanpa Sysmon: tidak ada process tree, jadi yang bisa menjawab cuma artefak eksekusi di E18-W2. Pertanyaannya: memo retainer menyebut 'entri di Amcache dan Shimcache', itu artinya dijalankan atau tidak? Program apa saja yang dijalankan penyerang, kapan, dan pakai akun siapa? Jejak Fajar waktu ambil memori Selasa siang jangan sampai tercampur dengan jejak penyerang. Pak Agus (DPO) tanya apakah ada tanda data dikirim keluar dalam jumlah besar dari laptop itu. Terakhir, laptop ini Windows 11, katanya ada artefak baru; apa gunanya, dan kalau tidak ketemu apa-apa lagi, boleh kita tulis 'tidak ada aktivitas lain'? Aku butuh jawabannya sebelum rapat jam 14:00."

Pesan itu memuat enam pertanyaan:

1. Artefak mana yang membuktikan program dijalankan, dan mana yang hanya membuktikan file pernah ada?
2. Program apa saja yang dijalankan di laptop Dewi, dan kapan?
3. Dengan akun siapa program itu dijalankan?
4. Bagaimana memisahkan jejak responder (Fajar dan WinPmem) dari jejak penyerang?
5. Apakah ada tanda data dikirim keluar dalam jumlah besar?
6. Apa guna PCA Windows 11, dan bolehkah menulis "tidak ada aktivitas lain" bila artefak tidak menunjukkan apa-apa?

Pertanyaan 1 dijawab di bagian 1.1 dan 1.3, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.4, pertanyaan 4 di bagian 1.5, pertanyaan 5 di bagian 1.6, dan pertanyaan 6 di bagian 1.7 dan 1.8. Bagian 2 berisi perintah, hasil parse, dan tabel korelasi yang kamu kirim ke Sari.

**Kapan relevan:** hampir setiap investigasi host Windows yang menanyakan program apa yang berjalan, kapan, dan oleh siapa, terutama di host tanpa EDR, Sysmon, atau audit process creation, dan saat log sudah dirotasi atau dibersihkan.
**Kapan bukan jawaban:** saat yang dibutuhkan adalah argumen command line, isi skrip, parent process, atau apa yang dikerjakan di dalam proses yang sudah berjalan (event log di Day 05, memori di Day 14 dan 15); saat yang ditanya adalah apa yang terjadi pada file (Day 08); dan saat yang dibutuhkan adalah tujuan atau isi koneksi jaringan (log jaringan dan memori).

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day 01 sampai 04 (salinan kerja, case notes, target dan module KAPE, `!EZParser`, read-only mount) tidak diulang. Tabel ini memuat artefak dan istilah yang dipakai Day ini; kolom padanan memakai analogi NOC dan SOC.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Artefak eksekusi | Catatan yang dibuat Windows untuk keperluannya sendiri dan kebetulan menyimpan jejak program yang dijalankan | Beberapa tabel perangkat yang bersama-sama membuktikan link dipakai |
| Prefetch (`.pf`) | File di `C:\Windows\Prefetch\` yang dibuat OS untuk mempercepat start program; menyimpan run count, sampai delapan waktu run, volume, dan file yang dirujuk | Counter interface: kapan terakhir aktif dan berapa kali, tanpa nama pengguna |
| Shimcache (AppCompatCache) | Daftar file yang ditemui subsistem kompatibilitas aplikasi, disimpan di SYSTEM hive saat shutdown | Tabel MAC di switch: pernah terlihat di port, belum tentu mengirim trafik |
| Amcache (`Amcache.hve`) | Hive inventaris aplikasi dan file executable, termasuk SHA-1, path, ukuran, dan driver yang dimuat | Inventaris CMDB yang terisi otomatis dari scan berkala |
| UserAssist | Nilai di NTUSER.DAT per user tentang program yang diluncurkan lewat Explorer (nama ROT13, run count, waktu terakhir) | RADIUS accounting untuk sesi yang lewat AAA saja |
| BAM (Background Activity Moderator) | Key di SYSTEM hive yang menyimpan waktu eksekusi terakhir per executable per SID user | Log login per akun yang hanya menyimpan sesi terakhir |
| SRUM (`SRUDB.dat`) | Database ESE pemakaian resource dan jaringan per aplikasi, per user, per jam | Grafik MRTG per port: volume per interval, tanpa isi dan tujuan |
| PCA (Program Compatibility Assistant) | File teks di `C:\Windows\appcompat\pca\` (Windows 11 22H2 ke atas) dengan waktu peluncuran sebagian program lewat GUI | Log fitur baru di firmware versi baru: berguna, tetapi cakupan dan formatnya belum didokumentasikan vendor |
| Jejak responder | Artefak yang dibuat oleh tindakan tim IR sendiri (alat akuisisi, skrip koleksi, akun admin IR) | Perubahan konfigurasi engineer saat troubleshooting yang harus dipisahkan dari penyebab gangguan |
| Bukti keberadaan vs bukti eksekusi | Artefak yang membuktikan file pernah ada dibandingkan artefak yang membuktikan file dijalankan | "Perangkat terlihat di port" dibandingkan "perangkat mengirim trafik" |

### 1.1 Peta artefak eksekusi: apa yang dibuktikan dan apa yang tidak

Pertanyaan pertama Sari ("entri di Amcache dan Shimcache, itu artinya dijalankan atau tidak?") hanya bisa dijawab bila setiap artefak sudah dipetakan ke apa yang ia buktikan. Tabel berikut adalah peta itu; baca dua kolom tengah dengan teliti, karena kesalahan paling mahal di Day ini adalah menulis isi kolom "Tidak membuktikan" sebagai kesimpulan.

| Artefak | Lokasi | Membuktikan | Tidak membuktikan | Parser EZ |
|---|---|---|---|---|
| Prefetch | `C:\Windows\Prefetch\*.pf` | Program dijalankan; run count; sampai 8 waktu run terakhir; volume dan file yang dirujuk | Siapa user; argumen; bisa nonaktif di server atau konfigurasi tertentu | PECmd |
| Amcache | `C:\Windows\appcompat\Programs\Amcache.hve` | Metadata program (path, SHA-1, ukuran, waktu tulis key); driver yang dimuat | Belum tentu dijalankan; keberadaan di cache | AmcacheParser |
| Shimcache (AppCompatCache) | SYSTEM hive | File dikenal sistem; path, last modified file, urutan; flag eksekusi heuristik di Windows 10/11 | Waktu eksekusi; flag "No" tidak membuktikan tidak dijalankan | AppCompatCacheParser |
| UserAssist | NTUSER.DAT per user | Program diluncurkan lewat GUI oleh user itu; run count; last run | Program yang dijalankan dari command line, skrip, atau task | RECmd |
| BAM/DAM | SYSTEM hive | Last execution time per user SID | Run count; waktu run sebelumnya | RECmd |
| SRUM | `C:\Windows\System32\sru\SRUDB.dat` | Pemakaian resource dan byte jaringan per aplikasi per user, per sekitar satu jam (sekitar 30-60 hari) | Waktu run presisi; tujuan dan isi koneksi | SrumECmd |
| PCA (Windows 11) | `C:\Windows\appcompat\pca\*.txt` | Peluncuran GUI; last execution time | Peluncuran lewat command line, task, layanan, atau eksekusi jarak jauh; tidak dijamin ada | teks atau parser |

Dua hal dari peta ini menentukan jawaban untuk Sari. Pertama, dua artefak yang disebut retainer, Amcache dan Shimcache, ada di kelompok yang lebih kuat untuk keberadaan daripada untuk eksekusi; kalimat "ada entri di Amcache" belum menjawab pertanyaan Pak Dimas. Kedua, tidak satu pun artefak di tabel ini mencatat argumen command line atau parent process. Di laptop tanpa EDR, Sysmon, atau audit process creation, pertanyaan "perintah apa persisnya" tidak bisa dijawab dari disk, dan itu harus tertulis di jawaban.

Tidak ada artefak tunggal yang cukup. Korelasi beberapa artefak yang menunjuk program yang sama memperkuat kesimpulan (bagian 1.8).

### 1.2 Prefetch: bukti eksekusi yang paling jelas, tanpa akun

Pertanyaan kedua Sari ("program apa saja yang dijalankan, dan kapan?") paling banyak dijawab Prefetch, karena hanya Prefetch yang menyimpan beberapa waktu run sekaligus.

Prefetch (`*.pf`) dibuat OS untuk mempercepat start program [S1]. Untuk forensik, PECmd mengekstrak [S2][S7]:

- Nama dan path executable.
- Run count (berapa kali dijalankan).
- Sampai delapan waktu run terakhir di Windows 8 ke atas, dengan yang terbaru lebih dulu; versi format lama (XP sampai Windows 7) hanya menyimpan satu [S13][S14].
- Informasi volume: device path, waktu pembuatan volume, dan nomor seri volume tempat program dijalankan [S13].
- Daftar file dan direktori yang dirujuk saat run (berguna melihat DLL, skrip, atau file data yang dibuka).

Waktu pembuatan file `.pf` di file system juga bermakna. forensics.wiki menyebut waktu pembuatan `.pf` menandai eksekusi pertama dan waktu modifikasinya menandai eksekusi terakhir [S14]; artifact Prefetch Velociraptor menulisnya sebagai delapan waktu run terakhir ditambah creation time, jadi sembilan kemungkinan eksekusi [S15]. Ini penting untuk program yang dijalankan lebih dari delapan kali: waktu run yang lebih lama sudah tertimpa di dalam `.pf`, tetapi waktu pembuatan file masih menunjuk run pertama, selama file `.pf` itu tidak pernah dihapus dan dibuat ulang.

Versi format berubah per Windows: 17 (XP dan 2003), 23 (Vista dan 7), 26 (8 dan 8.1), 30 (Windows 10), dan 31 (Windows 11) menurut dokumentasi format libscca revisi Juli 2026 [S13]. Sejak Windows 10, isi `.pf` dikompresi (format MAM, XPRESS Huffman), sehingga parser lama atau editor hex tidak bisa membacanya langsung [S13]. README PECmd menyatakan semua versi prefetch termasuk file terkompresi Windows 10/11 didukung, dan opsi `-o` bisa menyimpan byte hasil dekompresi untuk diperiksa [S7].

Nama file `.pf` memuat hash dari path lengkap executable (bentuk device path huruf besar), sehingga dua executable bernama sama di path berbeda punya `.pf` berbeda [S13]. Akibatnya untuk investigasi: `WSCRIPT.EXE` dari `C:\Windows\System32` dan dari `C:\Windows\SysWOW64` adalah dua file `.pf`, dan program yang disalin ke folder lain lalu dijalankan menghasilkan `.pf` baru dengan hash lain.

Keterbatasan:

- Prefetch bisa dinonaktifkan (sering di server, atau pada sebagian konfigurasi SSD). Pengaturannya ada di value `EnablePrefetcher` di `SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters`, dan nilai 0 berarti nonaktif [S14]. forensics.wiki menyebut Prefetch mati secara default di SSD [S14], tetapi pernyataan itu berasal dari era Windows 7 dan banyak praktisi melaporkan Prefetch tetap aktif di Windows 10/11 dengan SSD. Jangan menebak dari jenis disk; baca value itu di SYSTEM hive image.
- Jumlah entri terbatas. Angka yang sering disebut untuk Windows 8 ke atas adalah 1024 file, sedangkan forensics.wiki mengutip angka 128 dari dokumentasi Microsoft lama [S14]. Sumber yang diperiksa tidak sepakat; hitung isi folder Prefetch di build lab-mu sebelum memakai jumlah file sebagai petunjuk penghapusan.
- Prefetch tidak mencatat user, argumen command line, atau parent process.

Prefetch adalah bukti eksekusi yang kuat: keberadaan `.pf` untuk sebuah executable berarti executable itu dijalankan.

Untuk laptop Dewi, Prefetch adalah titik awal. Ia akan menunjukkan `WSCRIPT.EXE` dengan file yang dirujuk `Tagihan-Okt-2026.js`, `POWERSHELL.EXE` dengan run count yang besar karena task berjalan tiap 15 menit, dan program enumerasi seperti `WHOAMI.EXE` (bagian 2.2). Ia tidak akan menunjukkan akun yang menjalankannya; itu tugas bagian 1.4.

### 1.3 Shimcache dan Amcache: kuat untuk keberadaan, hati-hati untuk eksekusi

Kalimat retainer "ada entri di Amcache dan Shimcache" adalah tempat salah tafsir paling sering terjadi. Dua artefak ini paling sering disalahtafsirkan.

**Shimcache (AppCompatCache)** di SYSTEM hive mencatat file yang ditemui subsistem kompatibilitas aplikasi. Yang dicatat: path, last modified time file (bukan waktu eksekusi), dan urutan entri, dengan nomor posisi yang lebih kecil umumnya lebih baru [S3][S18][S19]. Keberadaan di Shimcache bukan bukti eksekusi; file bisa masuk Shimcache tanpa dijalankan. Cache ini hidup di memori dan ditulis ke registry saat shutdown atau reboot [S19][S20], sehingga entri yang terjadi setelah boot terakhir tidak ada di hive bila host dimatikan paksa atau di-image dalam keadaan menyala. Jumlah entri maksimal yang disebut sumber sekunder 1024 [S19]; cek di build lab-mu.

Ada satu perkembangan di Windows 10/11 yang perlu dipahami, bukan dipercaya buta. Windows 7 dan 8 punya Insert Flag yang cukup andal menunjukkan eksekusi; Windows 10 menghapusnya, sehingga lama sekali AppCompatCacheParser menampilkan "NA" di kolom eksekusi [S16]. Sejak Maret 2023, AppCompatCacheParser membaca empat byte terakhir field data setiap entri: bila nilainya 1, kolom eksekusi menjadi "Yes" [S16]. Artifact AppCompatCache Velociraptor memakai aturan yang sama untuk Windows 10 ke atas [S17]. Pengujian di Windows 11 23H2 menunjukkan "Yes" cocok dengan program yang memang dijalankan, tetapi banyak program yang jelas berjalan, misalnya `lsass.exe`, `cmd.exe`, dan `explorer.exe`, bernilai "No" [S16]. Jadi bacanya begini: "Yes" adalah indikator kuat yang tetap perlu dikonfirmasi artefak lain, dan "No" tidak membuktikan apa pun [S16][S19]. Sebagian praktisi mencatat bahwa flag ini tampaknya hanya terisi untuk binary non-bawaan Windows; klaim itu belum terkonfirmasi sumber primer, jadi uji di lab (bagian 3).

**Amcache** (`Amcache.hve`) mencatat metadata program termasuk SHA-1 dan waktu tulis key [S3][S9]. Isinya dibagi ke beberapa key; empat yang paling sering dipakai: `InventoryApplicationFile` (file executable dengan path, SHA-1, ukuran, versi, `LinkDate`), `InventoryApplication` (aplikasi terpasang), `InventoryDriverBinary` (driver kernel yang dimuat), dan `InventoryApplicationShortcut` (shortcut di Start Menu dan Desktop) [S18]. Beberapa fakta yang menentukan cara membacanya:

- Amcache bukan log eksekusi. Penelitian Kaspersky (Oktober 2025) menyebut isinya berasal dari tiga sumber: file di folder yang dipindai Microsoft Compatibility Appraiser, executable dan driver yang disalin saat program berjalan, dan aplikasi GUI yang butuh shim kompatibilitas; hanya kelompok terakhir yang andal menunjukkan eksekusi [S18]. Untuk `InventoryApplicationFile` kesimpulannya "mungkin dijalankan", sedangkan `InventoryDriverBinary` berarti driver dimuat ke memori [S18].
- Sumber praktisi tidak sepakat soal kekuatan Amcache. Magnet Forensics (2024) menyebut Amcache indikator eksekusi yang lebih andal daripada Shimcache dan membaca waktu tulis key sebagai waktu eksekusi pertama [S20]; Cyber Triage (2025, ditinjau 2026) menyarankan memperlakukannya sebagai bukti keberadaan [S19]. Catatan ini memakai tafsir yang lebih hati-hati: Amcache menguatkan, tidak membuktikan sendirian.
- SHA-1 di field `FileId` hanya dihitung atas 31.457.280 byte pertama file (sekitar 30 MiB) [S18]. Untuk file yang lebih besar, hash di Amcache tidak sama dengan SHA-1 file utuh; cek ukuran sebelum mencocokkan hash ke threat intelligence.
- AmcacheParser secara default hanya mengekspor file entry yang tidak terkait program terpasang (unassociated); opsi `-i` menambahkan program terpasang dan file terkaitnya [S9]. Executable yang dibawa penyerang biasanya berada di kelompok unassociated, sehingga default ini cocok untuk triage.

Pesan utama: Shimcache dan Amcache menjawab "file ini ada atau dikenal sistem" lebih kuat daripada "file ini dijalankan". Kekuatannya ada di hal lain: path dan hash executable yang mungkin sudah dihapus, dan untuk Amcache, driver yang pernah dimuat. Untuk eksekusi, padukan dengan Prefetch, UserAssist, BAM, atau event log.

Untuk laptop Dewi, jawaban ke pertanyaan pertama Sari menjadi: entri Amcache dan Shimcache menunjukkan file itu ada dan dikenal Windows; apakah dijalankan ditentukan oleh Prefetch dan BAM, dan untuk `WINPMEM_MINI_X64.EXE` milik Fajar justru Amcache yang memberi SHA-1 untuk membuktikan itu alat PT JAB (bagian 1.5).

### 1.4 UserAssist dan BAM: menambah dimensi akun

Pertanyaan ketiga Sari ("pakai akun siapa?") tidak bisa dijawab Prefetch. Dua artefak registry menambah dimensi itu, masing-masing dengan cakupan sempit.

**UserAssist** (NTUSER.DAT per user) mencatat program yang diluncurkan lewat GUI (Explorer), dengan run count, last run time, dan focus time [S3]. Key-nya `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<GUID>\Count`, dan batch DFIR RECmd mencatatnya dengan komentar "GUI-based programs launched from the desktop" [S12]. Karena per user (di hive NTUSER masing-masing), ia menjawab "user ini meluncurkan program itu". Nama programnya ROT13-encoded di registry; RECmd dan artifact Velociraptor mendekodekannya [S12][S23]. Batasnya tegas: program yang diluncurkan lewat command line tidak muncul di UserAssist, sebagian cara membuka program memperbarui entri tanpa menambah hitungan, dan focus count serta focus time dinilai tidak andal oleh dokumentasi artifact Velociraptor [S23].

**BAM/DAM (Background/Desktop Activity Moderator)** di SYSTEM hive mencatat last execution time per user SID untuk executable yang dijalankan [S3][S21]. Lokasinya `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>` (build tertentu memakai `bam\UserSettings\<SID>`), satu value per executable dengan nama berupa device path seperti `\Device\HarddiskVolume3\Windows\System32\...` [S21][S22]. Delapan byte pertama data value adalah FILETIME waktu eksekusi [S22]. BAM ada sejak Windows 10 1709 [S21][S22]. Yang tidak ada di BAM: run count dan waktu run sebelumnya. Beberapa sumber sekunder menyebut entri BAM dihapus setelah sekitar tujuh hari tidak dipakai; klaim ini tidak ditemukan di sumber primer yang diperiksa, jadi perlakukan sebagai `[komunitas, belum terkonfirmasi]` dan uji di lab bila retensi BAM penting untuk kasusmu.

Keduanya menambah dimensi "siapa" yang tidak ada di Prefetch. Di laptop Dewi, BAM adalah artefak yang paling berguna untuk dua hal sekaligus: menunjukkan bahwa program enumerasi berjalan di bawah SID akun `dewi.anggraini` (artinya dari sesi atau task milik Dewi, bukan akun lain), dan menunjukkan bahwa `cmd.exe`, WinPmem, dan alat koleksi berjalan di bawah SID akun admin lokal khusus IR. SID akun lokal memakai SID mesin `BDG-WS-0142` sebagai awalan, sedangkan SID akun domain memakai SID domain `JAB`; perbedaan awalan ini terlihat walaupun nama akunnya tidak di-resolve. UserAssist melengkapi dari sisi lain: bila Dewi membuka sesuatu lewat Explorer, entri itu ada di NTUSER.DAT miliknya.

### 1.5 Memisahkan jejak responder dari jejak penyerang

Pertanyaan keempat Sari adalah yang paling sering terlupa. Setiap tindakan IR di host meninggalkan artefak eksekusi yang sama persis dengan tindakan penyerang: alat dijalankan, file baru muncul, driver dimuat. Bila tidak dipisahkan, laporan bisa menulis "penyerang menjalankan alat dump memori" padahal itu Fajar, atau sebaliknya, aktivitas penyerang tersembunyi di antara baris responder yang dianggap noise.

Pemisahan yang bisa dipertanggungjawabkan memakai empat jangkar, dan semuanya harus berasal dari catatan yang dibuat saat tindakan berlangsung, bukan dari ingatan:

1. **Daftar tindakan dan waktu.** Panduan telepon Yoga dan formulir chain of custody E08 mencatat bahwa Fajar mulai pukul 13:55, WinPmem berjalan 14:05 sampai 14:13, lalu skrip koleksi dan `certutil -hashfile`, dan USB disimpan pukul 14:30. Isi skrip `koleksi-triage.cmd` di toolkit menyebut program yang dipanggilnya. Daftar itu adalah daftar "jejak yang diharapkan".
2. **Akun.** Fajar membuka Command Prompt "Run as administrator" dengan akun admin lokal khusus IR, `ir-admin`, yang ada di setiap workstation PT JAB dengan password yang diganti setelah tiap pemakaian. BAM menyimpan entri per SID, sehingga program responder muncul di bawah SID akun itu, terpisah dari SID `dewi.anggraini` [S21][S22].
3. **Lokasi dan media.** Alat responder dijalankan dari `USB-E-09` (`E:\tools\`). Prefetch menyimpan nomor seri volume tempat program dijalankan [S13], dan Shimcache serta Amcache menyimpan path `E:\tools\...`. Nomor seri volume yang dicatat Yoga saat menerima `USB-E-09` bisa dicocokkan dengan nomor di Prefetch.
4. **Identitas file.** SHA-1 di Amcache untuk `winpmem_mini_x64.exe` dicocokkan dengan SHA-1 salinan alat yang sama di toolkit PT JAB [S18]. Hash yang cocok membuktikan file yang dijalankan adalah alat PT JAB, bukan file lain dengan nama sama.

Prinsipnya sama dengan memisahkan perubahan konfigurasi engineer saat troubleshooting dari perubahan yang menyebabkan gangguan: keduanya ada di log yang sama, dan yang membedakan hanya catatan change yang dibuat saat itu juga. Jejak responder tidak dihapus dari timeline; ia diberi label "responder" beserta dasar pelabelannya, supaya pembaca laporan bisa memeriksa ulang. Program yang muncul di jendela waktu responder tetapi tidak ada di daftar tindakan, tidak berjalan di bawah akun IR, atau tidak berasal dari `USB-E-09`, tetap diperlakukan sebagai temuan yang belum dijelaskan.

Satu konsekuensi lagi: tindakan responder bisa menimpa jejak penyerang. Contohnya Prefetch hanya menyimpan delapan waktu run; bila responder menjalankan `cmd.exe` atau `certutil.exe` beberapa kali, waktu run lama program yang sama hilang dari `.pf`. Itu salah satu alasan panduan Yoga sengaja pendek, dan alasan analisis memeriksa run count serta waktu pembuatan `.pf`, bukan hanya delapan waktu terakhir.

### 1.6 SRUM: volume jaringan per aplikasi

Pertanyaan Pak Agus ("ada tanda data dikirim keluar dalam jumlah besar?") tidak bisa dijawab dari log proxy untuk laptop Bandung secara lengkap, karena sebagian trafik bisa lewat jalur lain. SRUM memberi sudut pandang dari dalam host.

SRUM (System Resource Usage Monitor, `SRUDB.dat`) mencatat pemakaian resource per aplikasi selama sekitar 30-60 hari: CPU, byte jaringan terkirim/diterima per aplikasi, dan profil jaringan [S3]. Sumber yang lebih baru menyebut retensi "sampai 30 hari" [S25]; angka persisnya bergantung build, jadi lihat rentang tanggal tertua di hasil parse. Untuk forensik:

- Membuktikan aplikasi aktif pada rentang waktu (per jam).
- Byte jaringan per aplikasi berguna untuk exfiltration (T1041, T1567): aplikasi apa yang mengirim banyak data, misalnya `rclone.exe` atau browser yang mengunggah ratusan MB di luar jam kerja.
- Setiap baris membawa SID user yang menjalankan aplikasi [S24], sehingga SRUM juga menambah dimensi akun.
- SrumECmd memparse `SRUDB.dat`; SOFTWARE hive bersifat opsional tetapi disarankan [S10], dan dipakai antara lain untuk memetakan interface LUID ke nama jaringan (SSID) [S25].

SRUM unik karena memberi volume jaringan per aplikasi, yang jarang ada di artefak lain. Batasnya juga jelas:

- Data ditulis ke database sekitar tiap jam dan saat shutdown; yang belum ditulis disimpan sementara di registry [S24]. Waktu sebuah kejadian bisa meleset sampai sekitar satu jam dari waktu rekam barisnya [S24], dan angka adalah total per interval, bukan per koneksi.
- SRUM tidak menyimpan alamat tujuan, port, atau isi trafik.
- Aktivitas yang berjalan di bawah akun System lebih sulit diatribusikan [S24].
- `SRUDB.dat` dikunci di sistem hidup dan sering dalam keadaan "dirty"; perbaikannya dilakukan pada salinan, bukan pada bukti (bagian 4) [S10].

Untuk laptop Dewi, SRUM menjawab Agus dengan volume: berapa byte yang dikirim `powershell.exe` di bawah akun Dewi per jam sejak 08:51 sampai isolasi pukul 16:00, dan apakah ada aplikasi lain yang tiba-tiba mengirim jauh lebih banyak dari kebiasaannya (bagian 2.6). Ia tidak menjawab apa isi yang dikirim.

### 1.7 PCA: artefak eksekusi baru di Windows 11

Laptop Dewi memakai Windows 11 23H2, jadi pertanyaan "katanya ada artefak baru" merujuk ke PCA.

PCA (Program Compatibility Assistant) di Windows 11 menyimpan data di `C:\Windows\appcompat\pca\`, termasuk `PcaAppLaunchDic.txt` yang memetakan path file ke last execution time [S4][S5]. Layanan di baliknya adalah `PcaSvc`, yang sudah ada sejak Vista; file teks ini muncul di pembaruan 2022 untuk Windows 11 22H2 dan diuji peneliti di 22H2 dan 23H2 [S4]. Ciri:

- File teks, satu baris per path, dipisah tanda pipe, dengan waktu UTC [S4][S5]. Sygnia (2023) mencatat encoding ANSI (CP-1252) dengan akhir baris CRLF [S4], sedangkan tulisan Andrea Fortuna (2026) menyebut UTF-16 LE [S5]. Kedua sumber sekunder ini tidak sepakat; buka file di build lab-mu dengan editor hex sebelum menulis parser.
- Menangkap sebagian peluncuran GUI (lewat Explorer), termasuk lewat RDP dan dari halaman unduhan browser; bukan semua cara eksekusi [S4][S5]. Peluncuran dari command line, scheduled task, eksekusi jarak jauh, dan PsExec tidak tercatat [S4].
- Sebagian program bawaan tidak tercatat bila dijalankan dari lokasi aslinya, tetapi tercatat bila disalin ke folder lain [S4].
- Entri diperbarui (last execution), bukan ditambahkan; retensi terbatas [S5].
- Kehadiran tidak dijamin: sebagian build/host tidak memiliki file ini; ketiadaan tidak konklusif [S5].
- Ada bug yang dilaporkan: path dengan karakter non-ANSI terpotong tanpa timestamp, dan setelah itu baris baru tampaknya berhenti dibuat walaupun baris lama tetap diperbarui [S4].
- Lebih baru dari artefak klasik, sehingga sebagian anti-forensik mungkin melewatkannya [S5][S6].

Di folder yang sama ada `PcaGeneralDb0.txt` dan `PcaGeneralDb1.txt` (UTF-16 LE), yang bergantian dipakai sampai sekitar 2 MB dan berisi catatan seperti installer yang gagal, proses yang keluar dengan kode tidak nol, dan driver yang diblokir [S4]. Path di file ini disamarkan sebagian (huruf kecil, huruf drive dihapus, nama user diganti `%USERNAME%`), sehingga folder asal tidak selalu bisa dipastikan [S4].

PCA melengkapi, bukan menggantikan, Prefetch/Amcache/UserAssist [S4]. Velociraptor punya artifact `Windows.System.AppCompatPCA` (artifact Exchange dari komunitas, bukan bawaan) untuk memparse `PcaAppLaunchDic.txt` [S6]; cek nama di versi lab. Untuk koleksi, compound target KAPE `EvidenceOfExecution` sudah memuat target `AppCompatPCA` [S26].

Untuk laptop Dewi, ekspektasinya perlu ditulis sebelum membuka file: lampiran dibuka dari Outlook dan Explorer, lalu `wscript.exe` dan `powershell.exe` dijalankan dari System32, program enumerasi dijalankan oleh PowerShell, dan WinPmem dijalankan dari command prompt. Hampir semua jalur itu termasuk kategori yang tidak dicatat PCA. Jadi PCA yang kosong untuk program-program itu adalah hasil yang diharapkan, bukan tanda bersih (bagian 2.7).

### 1.8 Korelasi dan batas: "tidak ditemukan" bukan "tidak terjadi"

Pertanyaan terakhir Sari ("boleh kita tulis tidak ada aktivitas lain?") dijawab dengan dua langkah: korelasi untuk yang ditemukan, dan batas untuk yang tidak ditemukan.

Karena tiap artefak punya cakupan berbeda, korelasi adalah kuncinya. Contoh klaim "malware.exe dijalankan di WIN-LAB01 pada 14:03":

- Prefetch `MALWARE.EXE-xxxx.pf` dengan last run 14:03: bukti kuat eksekusi.
- UserAssist di NTUSER alice: diluncurkan GUI oleh alice.
- Amcache: SHA1 untuk dicocokkan ke intel (meski file terhapus).
- SRUM: aktivitas jaringan aplikasi itu.
- Shimcache: file dikenal sistem (mendukung, bukan membuktikan run).
- Security 4688 (bila audit): proses dibuat dengan command line.

Beberapa artefak yang sepakat membuat kesimpulan jauh lebih kuat daripada satu. Bila artefak bertentangan (mis. Shimcache ada tetapi tidak ada Prefetch/UserAssist), itu justru petunjuk (file ada tetapi mungkin tidak dijalankan, atau Prefetch nonaktif).

Untuk yang tidak ditemukan, ada tiga hal yang membatasi kesimpulan di laptop Dewi:

1. **Artefak eksekusi hanya melihat proses baru.** Prefetch, BAM, Shimcache, dan Amcache bekerja di tingkat executable. Loader `upd.ps1` adalah skrip PowerShell: membaca file, mengumpulkan informasi lewat .NET atau cmdlet, dan mengirim data ke C2 bisa dilakukan di dalam proses `powershell.exe` yang sama tanpa membuat proses baru. Semua itu tidak meninggalkan artefak eksekusi. Hasil "hanya `whoami`, `systeminfo`, `ipconfig`, dan `net`" adalah batas bawah dari apa yang dilakukan, bukan daftar lengkap.
2. **Setiap artefak punya retensi dan kondisi sendiri.** Prefetch menyimpan delapan waktu, BAM satu, Shimcache hanya isi sampai shutdown terakhir, SRUM sekitar satu bulan, PCA hanya jalur GUI.
3. **Ketiadaan di satu artefak bisa dijelaskan oleh cakupannya.** Tidak ada entri UserAssist untuk `wscript.exe` tidak berarti Dewi tidak membuka lampiran; berarti jalur pembukaannya mungkin tidak dicatat UserAssist.

Kalimat yang bisa dipertanggungjawabkan: "Artefak eksekusi di E18-W2 menunjukkan program X, Y, Z dijalankan pada waktu ... di bawah akun ...; tidak ditemukan executable lain dari penyerang di artefak yang diperiksa. Aktivitas yang dikerjakan di dalam proses PowerShell tanpa membuat proses baru tidak tercatat di artefak ini, sehingga cakupan penuh aktivitas loader bergantung pada analisis memori E08 dan event log." Kalimat "tidak ada aktivitas lain" tidak boleh ditulis.

## 2. Contoh dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Nama kolom CSV, nama file output, dan teks console bisa berbeda antar versi EZ Tools dan KapeFiles; cocokkan dengan versi di lab-mu. Semua waktu dari EZ Tools dalam UTC; laporan PT JAB memakai WIB (UTC+7), jadi setiap waktu kunci ditulis keduanya sekali, lalu WIB. Perintah ditulis untuk lingkungan PT JAB; untuk latihan, jalankan hanya di VM lab terisolasi (bagian 3).

### 2.1 Menyiapkan E18-W2 dan mengambil artefak eksekusi

Langkah ini menyiapkan semua jawaban untuk Sari. E18-W2 adalah salinan kerja internal image disk laptop Dewi di `\\jkt-evid01\cases\INC-2026-019\work\`, dibuat Yoga Senin 2026-10-19 pukul 15:30 dari master E18 setelah verifikasi hash `9d04...`. Pukul 09:10 kamu memverifikasi hash E18-W2, lalu me-mount image read-only di `JKT-DFIR01` sebagai volume `G:` dengan alat mount image yang tercatat di inventaris alat `JKT-DFIR01` (Day 02 bagian 2.8 membahas prinsip mount read-only). Setelah itu, artefak eksekusi diambil dengan KAPE Targets ke folder kerja lokal, supaya setiap file yang dibaca tercatat di copylog dengan SHA-1-nya (Day 03 bagian 2.3).

```
C:\DFIR\tools\KAPE\kape.exe --tsource G: --target EvidenceOfExecution,RegistryHivesSystem,RegistryHivesUser,SRUM --tdest C:\DFIR\work\INC-2026-019\E18-W2\tdest --tflush
```

- `--tsource G:`: volume Windows dari image E18-W2 yang di-mount read-only.
- `EvidenceOfExecution`: compound target berisi `Amcache`, `AppCompatPCA`, `Prefetch`, `RecentFileCache`, dan `Syscache` [S26].
- `RegistryHivesSystem`: ditambahkan karena `EvidenceOfExecution` sengaja tidak memuat Shimcache; dokumentasinya menyebut Shimcache butuh seluruh SYSTEM hive, dan menyarankan target hive SYSTEM bersama module AppCompatCacheParser [S26]. SYSTEM hive juga memuat BAM.
- `RegistryHivesUser`: NTUSER.DAT tiap profil, untuk UserAssist.
- `SRUM`: `SRUDB.dat` dan file pendampingnya. Ketiga target individual ini ada di folder `Targets\Windows` KapeFiles [S26]; cek isinya dengan `kape.exe --tlist` dan `--tdetail` di versi-mu.
- `--tdest` ke folder kerja lokal tanpa container: hasil ini turunan dari salinan kerja, bukan bukti baru. Copylog tetap disimpan bersama hasil olahan.

Folder output parser yang dipakai di bagian 2.2 sampai 2.7, dan variabel PowerShell yang dipakai ulang:

```powershell
$ez  = 'C:\DFIR\tools\EZTools-2026-10-15'                       # EZ Tools 2026.5.0, dibekukan selama kasus
$t   = 'C:\DFIR\work\INC-2026-019\E18-W2\tdest\G'                # hasil Targets; nama subfolder volume cek di hasil KAPE
$out = '\\jkt-evid01\cases\INC-2026-019\analysis\E18-W2\EZ-2026.5.0'
```

Case notes untuk langkah ini:

```
INC-2026-019 | Case notes forensik | <kamu> | TZ catatan: UTC+7 (WIB)
2026-10-20 09:00  Permintaan Sari: verifikasi eksekusi BDG-WS-0142 dari E18-W2 sebelum reimage Kamis; tenggat 14:00.
2026-10-20 09:10  E18-W2: hash cocok dengan 9d04... (master E18). Mount read-only sebagai G: di JKT-DFIR01.
2026-10-20 09:18  KAPE Targets EvidenceOfExecution,RegistryHivesSystem,RegistryHivesUser,SRUM -> tdest lokal.
                  Konteks dari case notes lain: laptop dimatikan normal oleh Fajar Rabu 2026-10-14 17:45
                  (instruksi Yoga, setelah containment dinyatakan berhasil 17:20); tidak dinyalakan lagi
                  sampai di-image. Akibat: Shimcache dan SRUM sudah ditulis ke disk saat shutdown.
                  Daftar tindakan responder di laptop ini: panduan telepon Yoga 13:55, CoC E08, isi
                  koleksi-triage.cmd v1.2 di USB-E-09 (memanggil autorunsc64, schtasks, wevtutil, robocopy).
2026-10-20 09:31  Targets selesai. Mulai parsing (2.2-2.7).
```

**Cara membaca hasil:** baris 09:18 adalah bagian yang paling penting untuk analisis, karena dua fakta di dalamnya menentukan apa yang bisa dipercaya. Shutdown normal berarti Shimcache dari sesi terakhir sudah ditulis ke SYSTEM hive [S19][S20]; bila laptop dimatikan paksa, entri sejak boot terakhir hilang. Daftar tindakan responder adalah dasar pelabelan di bagian 2.8.

**Kapan gagal:** image di-mount read-write lalu Windows di workstation analisis menulis ke volume itu, atau KAPE dijalankan dengan `--tsource` ke volume `C:` milik `JKT-DFIR01` sendiri, sehingga artefak workstation analisis ikut terbaca sebagai artefak laptop Dewi. Periksa nama host di SYSTEM hive hasil koleksi sebelum parsing.

### 2.2 Prefetch dengan PECmd

Langkah ini menjawab pertanyaan kedua Sari: program apa yang dijalankan, dan kapan.

```powershell
& "$ez\PECmd.exe" -d "$t\Windows\Prefetch" --csv "$out\ProgramExecution" --csvf E18-W2_PECmd.csv -q
```

- `-d`: memproses semua `.pf` di folder; `-f` untuk satu file [S7].
- `--csv` dan `--csvf`: folder dan nama file output CSV [S7].
- `-q`: tidak menampilkan detail per file di console, mempercepat proses saat output ke CSV [S7].
- Output CSV memuat executable, run count, dan waktu run (kolom `LastRun` dan sampai tujuh waktu sebelumnya, `PreviousRun0` sampai `PreviousRun6`). PECmd juga menulis file timeline terpisah dengan satu baris per waktu run; nama persisnya cek di folder output.
- Buka di Timeline Explorer; sortir kolom `LastRun` untuk melihat eksekusi terbaru.

Keluaran ilustrasi (ringkasan beberapa kolom, waktu UTC):

```
ExecutableName        RunCount  SourceCreated         LastRun               PreviousRun0          Volume0Serial
WSCRIPT.EXE           214       2026-03-02 02:40:11   2026-10-13 01:51:16   2026-10-13 01:12:05   6E1A04F2
POWERSHELL.EXE        132       2026-10-13 01:51:29   2026-10-14 10:36:31   2026-10-14 10:21:31   6E1A04F2
WHOAMI.EXE            1         2026-10-13 02:06:54   2026-10-13 02:06:44                         6E1A04F2
SYSTEMINFO.EXE        1         2026-10-13 02:06:57   2026-10-13 02:06:46                         6E1A04F2
IPCONFIG.EXE          2         2026-09-03 03:15:22   2026-10-13 02:07:05   2026-09-03 03:15:12   6E1A04F2
NET.EXE               2         2026-10-13 02:07:17   2026-10-13 02:07:10   2026-10-13 02:07:07   6E1A04F2
NET1.EXE              2         2026-10-13 02:07:17   2026-10-13 02:07:10   2026-10-13 02:07:07   6E1A04F2
CMD.EXE               37        2026-03-02 02:38:50   2026-10-13 07:04:10   2026-10-09 06:22:41   6E1A04F2
WINPMEM_MINI_X64.EXE  1         2026-10-13 07:05:12   2026-10-13 07:05:02                         5C2E91A4
AUTORUNSC64.EXE       1         2026-10-13 07:14:32   2026-10-13 07:14:22                         5C2E91A4
SCHTASKS.EXE          1         2026-10-13 07:14:51   2026-10-13 07:14:41                         6E1A04F2
WEVTUTIL.EXE          6         2026-10-13 07:14:55   2026-10-13 07:15:20   2026-10-13 07:15:13   6E1A04F2
ROBOCOPY.EXE          3         2026-10-13 07:15:41   2026-10-13 07:18:50   2026-10-13 07:16:58   6E1A04F2
CERTUTIL.EXE          9         2026-10-13 07:19:40   2026-10-13 07:21:10   2026-10-13 07:20:58   6E1A04F2
```

Isi kolom `FilesLoaded` untuk `WSCRIPT.EXE` (dipotong):

```
\VOLUME{01dc8a1e6e1a04f2-6e1a04f2}\USERS\DEWI.ANGGRAINI\APPDATA\LOCAL\TEMP\TEMP1_TAGIHAN-OKT-2026.ZIP\TAGIHAN-OKT-2026.JS
\VOLUME{01dc8a1e6e1a04f2-6e1a04f2}\WINDOWS\SYSTEM32\JSCRIPT.DLL
...
```

**Cara membaca hasil:**

- `WSCRIPT.EXE`: run terakhir Selasa 01:51:16 UTC (08:51:16 WIB), dengan `Tagihan-Okt-2026.js` dari folder sementara di `AppData\Local\Temp` di daftar file yang dirujuk. Run sebelumnya 08:12:05 WIB adalah logon script `map-drive.vbs` yang dijalankan PT JAB di setiap logon; run count 214 mencerminkan logon sejak laptop dipasang Maret, bukan aktivitas penyerang. Nama folder `Temp1_...` adalah perilaku umum Explorer saat file dibuka dari dalam ZIP; nama persisnya cek di build lab. Apakah `FilesLoaded` hanya berasal dari run terakhir atau gabungan beberapa run juga perlu dicek di lab sebelum dipakai sebagai bukti per run.
- `POWERSHELL.EXE`: file `.pf` dibuat Selasa 08:51:29 WIB, beberapa detik setelah lampiran dijalankan, dan tidak ada `.pf` PowerShell sebelumnya: itu run pertama PowerShell di laptop ini. Run count 132 cocok dengan perhitungan: satu run `powershell.exe -enc` pukul 08:51:19, lalu task `\SysCacheUpdate` tiap 15 menit dari Selasa 09:06:31 sampai Rabu 17:36:31 WIB (32 jam 30 menit, 130 interval, 131 run). Delapan waktu yang tersimpan semuanya Rabu sore, 15:51:31 sampai 17:36:31 WIB; run hari Selasa sudah tertimpa. Run terakhir 17:36:31 dan shutdown 17:45 cocok dengan case notes.
- `WHOAMI.EXE`, `SYSTEMINFO.EXE`, `NET.EXE`, `NET1.EXE`: semuanya run pertama dan satu-satunya di laptop ini, Selasa 09:06:44 sampai 09:07:10 WIB, sekitar 13 detik setelah task berjalan pertama kali. `NET1.EXE` muncul bersamaan dengan `NET.EXE` karena `net.exe` sering memanggil `net1.exe` untuk subperintah yang sama; cek perilaku ini di lab.
- `IPCONFIG.EXE`: `.pf` dibuat 3 September (teknisi helpdesk), run terakhir Selasa 09:07:05 WIB. Waktu pembuatan `.pf` bukan waktu penyerang; waktu run terakhir yang cocok dengan rangkaian enumerasi.
- Baris `CMD.EXE` sampai `CERTUTIL.EXE` jatuh di jendela 14:04 sampai 14:21 WIB. `WINPMEM_MINI_X64.EXE` dan `AUTORUNSC64.EXE` dijalankan dari volume dengan nomor seri `5C2E91A4`, berbeda dari volume sistem `6E1A04F2` (bagian 2.8).
- Tidak satu pun baris ini memberi akun atau argumen command line.

**Variasi:** filter file timeline PECmd ke jendela Selasa 01:00 sampai 09:00 UTC untuk melihat semua run yang masih tercatat dalam urutan waktu. Ingat bahwa run PowerShell hari Selasa tidak akan muncul di timeline itu karena sudah tertimpa; yang mewakilinya adalah `SourceCreated` dan run count. Untuk host dengan shadow copy, `--vss` memproses Prefetch dari semua shadow copy (Windows saja) [S7].

**Kapan gagal:** Prefetch nonaktif (cek `EnablePrefetcher` di SYSTEM hive) atau folder Prefetch dibersihkan; atau `SourceCreated` dibaca dari salinan yang dibuat dengan alat yang tidak mempertahankan timestamp. Waktu pembuatan `.pf` yang valid berasal dari `$MFT` image, bukan dari file hasil salinan; bandingkan dengan output MFTECmd (Day 08).

### 2.3 Amcache dengan AmcacheParser

Langkah ini menjawab bagian pertama pertanyaan Sari dan menyiapkan jangkar identitas file untuk bagian 2.8.

```powershell
& "$ez\AmcacheParser.exe" -f "$t\Windows\appcompat\Programs\Amcache.hve" --csv "$out\ProgramExecution" -i
```

- `-f`: file `Amcache.hve`; wajib [S9].
- `--csv`: folder output; wajib [S9]. Menghasilkan beberapa CSV (file entries yang terkait dan tidak terkait program, program entries, driver, shortcut, dan lainnya). Yang penting: path, SHA1, dan waktu.
- `-i`: menyertakan program terpasang dan file entry terkaitnya; tanpa opsi ini hanya file yang tidak terkait program terpasang yang diekspor [S9].
- Transaction log (`.LOG1`, `.LOG2`) dipakai otomatis untuk hive yang dirty; `-nl` mematikannya [S9][S18]. Pastikan target KAPE ikut mengambil file log itu.
- Cek path `Amcache.hve` dalam koleksi.

Keluaran ilustrasi dari CSV file entry yang tidak terkait program (beberapa kolom, waktu UTC; nama kolom waktu tulis key cek di versi-mu):

```
FullPath                         SHA1                                      Size      IsOsComponent  KeyLastWrite
e:\tools\winpmem_mini_x64.exe    4be17c0e9a52d3f8016b2c7ae9d4f15b38c0a7e2  2731520   False          2026-10-13 07:05:03
e:\tools\autorunsc64.exe         91d06a3e7f24c8b1d5e0f9a2c6b47e13d8a5f0c9  1124808   False          2026-10-13 07:14:23
```

Keluaran ilustrasi dari CSV driver binary: satu baris driver yang dimuat WinPmem dari folder sementara akun admin lokal IR, dengan waktu tulis key 2026-10-13 07:05:04 UTC. Nama file driver WinPmem bergantung versi WinPmem di toolkit; cocokkan dengan dokumentasi versi itu.

**Cara membaca hasil:**

- Dua executable dari `e:\tools\` adalah alat di `USB-E-09`. SHA-1 keduanya dicocokkan dengan SHA-1 salinan alat di toolkit PT JAB (bagian 2.8). Ukurannya jauh di bawah 31.457.280 byte, sehingga SHA-1 Amcache bisa dibandingkan langsung dengan SHA-1 file utuh [S18].
- Baris driver menunjukkan driver dimuat ke memori [S18], konsisten dengan cara kerja alat akuisisi memori. Tanpa konteks responder, baris seperti ini akan terlihat seperti rootkit.
- Tidak ada executable lain di luar folder sistem dan aplikasi terpasang yang muncul di jendela Selasa. Loader penyerang berupa skrip (`.js` lalu `.ps1`), dan Amcache diharapkan mencatat file executable, bukan skrip; apakah `.js` atau `.ps1` pernah muncul di Amcache perlu dicek di lab.
- Program bawaan seperti `whoami.exe` bisa muncul dengan `IsOsComponent` True atau tidak muncul sama sekali; ketiadaannya di sini tidak mengurangi bukti Prefetch.

**Variasi:** siapkan file berisi SHA-1 alat responder dan pakai `-w` untuk mengecualikannya dari output, atau `-b` berisi SHA-1 IOC untuk hanya menampilkan yang cocok; bila keduanya dipakai, daftar `-b` yang menang [S9]. Untuk kasus dengan executable penyerang, SHA-1 dari Amcache bisa dipakai mencari file yang sama di host lain lewat hunt (Day 04), meski file aslinya sudah dihapus.

**Kapan gagal:** hive dirty dan file `.LOG1`/`.LOG2` tidak ikut terkoleksi, sehingga entri terbaru belum tergabung; atau SHA-1 Amcache dicocokkan ke threat intelligence untuk file di atas sekitar 30 MiB, sehingga hasil "tidak dikenal" tidak berarti apa-apa.

### 2.4 Shimcache dengan AppCompatCacheParser

Langkah ini melengkapi jawaban pertanyaan pertama dan menguji klaim retainer soal Shimcache.

```powershell
& "$ez\AppCompatCacheParser.exe" -f "$t\Windows\System32\config\SYSTEM" --csv "$out\ProgramExecution" --csvf E18-W2_AppCompatCache.csv
```

- `-f`: path SYSTEM hive; tanpa `-f` alat membaca registry live mesin analisis, yang bukan bukti [S8].
- `--csv` wajib, `--csvf` nama file output [S8].
- Tanpa `-c`, semua ControlSet diekstrak; `-c` memilih satu ControlSet [S8].
- `-t` mengurutkan berdasarkan last modified menurun [S8]; tidak dipakai di sini karena urutan posisi cache yang ingin dibaca.
- Transaction log hive dirty dipakai secara default; `--nl` mematikannya [S8].

Keluaran ilustrasi (ControlSet001, beberapa baris, waktu UTC):

```
CacheEntryPosition  Path                                                   LastModifiedTimeUTC   Executed
3                   C:\Windows\system32\certutil.exe                       2026-09-10 05:12:40   No
4                   C:\Windows\system32\Robocopy.exe                       2026-09-10 05:12:44   No
7                   E:\tools\autorunsc64.exe                               2026-06-02 03:41:10   Yes
8                   E:\tools\winpmem_mini_x64.exe                          2026-06-02 03:40:55   Yes
11                  C:\Windows\system32\NET1.exe                           2026-09-10 05:12:41   No
13                  C:\Windows\system32\ipconfig.exe                       2026-09-10 05:12:41   No
14                  C:\Windows\system32\systeminfo.exe                     2026-09-10 05:12:44   No
15                  C:\Windows\system32\whoami.exe                         2026-09-10 05:12:45   No
19                  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe  2026-09-10 05:13:02   No
```

**Cara membaca hasil:**

- Kolom waktu adalah last modified file, bukan waktu eksekusi [S3][S19][S20]. Tanggal 10 September di semua binary sistem adalah waktu file diganti pembaruan Windows; tanggal 2 Juni di dua alat `E:\tools\` adalah waktu salinan alat disiapkan di toolkit. Tidak satu pun tanggal ini memberi tahu kapan program dijalankan.
- Posisi kecil umumnya lebih baru [S17][S19]. Urutan di contoh ini sejalan dengan Prefetch (alat responder lebih baru daripada program enumerasi), tetapi posisi hanya memberi urutan relatif, bukan waktu.
- Kolom `Executed`: "Yes" untuk dua alat dari USB, "No" untuk `whoami.exe` dan `powershell.exe` yang pasti berjalan menurut Prefetch. Ini contoh nyata kenapa "No" tidak membuktikan apa pun [S16].
- Jawaban untuk retainer: entri Shimcache menunjukkan file-file ini dikenal sistem sampai shutdown Rabu 17:45. Eksekusinya dibuktikan oleh Prefetch dan BAM, bukan oleh Shimcache.

**Variasi:** jalankan dengan `-t` untuk melihat file dengan last modified terbaru. Executable yang dibuat penyerang biasanya punya last modified yang dekat dengan waktu kompromi, sehingga muncul di atas daftar; biner sistem bawaan tidak.

**Kapan gagal:** laptop dimatikan paksa atau di-image dalam keadaan menyala, sehingga entri sejak boot terakhir belum ditulis ke hive [S19][S20]. Di kasus itu, ketiadaan entri baru di Shimcache tidak bermakna apa pun. Di E18 hal ini tidak terjadi karena shutdown Rabu dilakukan normal.

### 2.5 UserAssist dan BAM dengan RECmd

Langkah ini menjawab pertanyaan ketiga Sari: akun siapa.

```powershell
& "$ez\RECmd\RECmd.exe" -d "$t" --bn "$ez\RECmd\BatchExamples\DFIRBatch.reb" --csv "$out\Registry"
```

- `-d`: mencari hive secara rekursif di folder hasil Targets, jadi SYSTEM dan semua NTUSER.DAT diproses sekaligus [S11].
- `--bn`: batch file yang menentukan key dan value yang dibaca; wajib bersama `--csv` [S11]. `DFIRBatch.reb` (sebelumnya bernama Kroll Batch, versi 2.22) memuat entri UserAssist (NTUSER), BAM dan DAM (SYSTEM), dan AppCompatCache, semuanya berkategori Program Execution, dengan plugin `UserAssist` dan `Bam` untuk mendekode nilainya [S11][S12]. Folder `BatchExamples` juga berisi contoh yang lebih sempit seperti `BatchExampleUserAssist.reb` dan `UserActivity.reb` [S12]; lokasi folder `RECmd` dan `BatchExamples` di hasil Get-ZimmermanTools cek di instalasi-mu.
- Transaction log hive dirty dipakai secara default; `--nl` mematikannya [S11].
- UserAssist terdekode (dari ROT13) menunjukkan program GUI, run count, last run, focus time.
- BAM/DAM dari SYSTEM hive memberi last execution per SID.

Keluaran ilustrasi BAM, disederhanakan dari file detail plugin (waktu UTC; `<SID domain JAB>` dan `<SID mesin>` menggantikan bagian tengah SID):

```
SID                                     Program                                                          LastExecution
S-1-5-21-<SID domain JAB>-6142          \Device\HarddiskVolume3\Windows\System32\wscript.exe             2026-10-13 01:51:17
S-1-5-21-<SID domain JAB>-6142          \Device\HarddiskVolume3\Windows\System32\whoami.exe              2026-10-13 02:06:45
S-1-5-21-<SID domain JAB>-6142          \Device\HarddiskVolume3\Windows\System32\systeminfo.exe          2026-10-13 02:06:52
S-1-5-21-<SID domain JAB>-6142          \Device\HarddiskVolume3\Windows\System32\ipconfig.exe            2026-10-13 02:07:05
S-1-5-21-<SID domain JAB>-6142          \Device\HarddiskVolume3\Windows\System32\net.exe                 2026-10-13 02:07:10
S-1-5-21-<SID domain JAB>-6142          \Device\HarddiskVolume3\Windows\System32\WindowsPowerShell\v1.0\powershell.exe  2026-10-14 10:36:33
S-1-5-21-<SID mesin>-1003               \Device\HarddiskVolume3\Windows\System32\cmd.exe                 2026-10-13 07:21:15
S-1-5-21-<SID mesin>-1003               \Device\HarddiskVolume5\tools\winpmem_mini_x64.exe               2026-10-13 07:13:04
S-1-5-21-<SID mesin>-1003               \Device\HarddiskVolume5\tools\autorunsc64.exe                    2026-10-13 07:14:30
S-1-5-21-<SID mesin>-1003               \Device\HarddiskVolume3\Windows\System32\certutil.exe            2026-10-13 07:21:11
```

Keluaran ilustrasi UserAssist untuk NTUSER.DAT `dewi.anggraini` (beberapa baris, waktu UTC):

```
ProgramName                                                RunCounter  LastExecuted
Microsoft.Office.OUTLOOK.EXE.15                            188         2026-10-13 01:12:31
MSEdge                                                     241         2026-10-13 06:40:18
```

**Cara membaca hasil:**

- Program enumerasi, `wscript.exe`, dan `powershell.exe` ada di bawah SID domain milik `dewi.anggraini` (RID `6142` di contoh; resolusi SID ke nama dicek dari SAM, profil, atau AD). Artinya program itu berjalan dalam konteks akun Dewi: dari sesinya dan dari task yang terdaftar atas namanya. Ini tidak berarti Dewi mengetiknya; loader berjalan dengan hak akun yang menjalankan lampiran.
- `cmd.exe`, WinPmem, autorunsc, dan `certutil.exe` ada di bawah SID dengan awalan SID mesin dan RID `1003`, yaitu akun lokal. Itu cocok dengan akun admin lokal khusus IR yang dipakai Fajar. `\Device\HarddiskVolume5` adalah USB; huruf `E:` tidak dipakai BAM, jadi path ini dicocokkan lewat nama folder dan waktu, bukan huruf drive.
- Waktu BAM `powershell.exe` (Rabu 17:36:33 WIB) cocok dengan run terakhir di Prefetch. Waktu BAM WinPmem (14:13:04 WIB) lebih dekat ke akhir akuisisi (14:13) daripada ke awal run di Prefetch (14:05:02); `cmd.exe` juga tercatat 14:21:15, setelah `certutil` terakhir. Ini bisa berarti BAM mencatat saat proses berakhir, bukan saat mulai. Sumber yang diperiksa hanya menyebut "last execution time" [S21][S22], jadi perilaku ini diuji di lab sebelum dipakai untuk kesimpulan presisi detik (bagian 3).
- UserAssist Dewi tidak punya entri untuk `wscript.exe`, file `.js`, atau program enumerasi. Program enumerasi dijalankan oleh PowerShell, bukan Explorer, sehingga memang tidak diharapkan ada [S23]. Untuk lampiran yang dibuka dari dalam ZIP di Explorer, apakah UserAssist mencatat sesuatu perlu diuji di lab; ketiadaan di sini tidak berarti lampiran tidak dibuka, karena Prefetch dan BAM sudah membuktikan `wscript.exe` berjalan dengan file itu.

**Variasi:** jalankan RECmd dengan `-f` ke satu NTUSER.DAT dan batch `UserActivity.reb` untuk melihat aktivitas satu user saja. Untuk profil akun admin lokal IR, NTUSER.DAT miliknya mungkin baru terbentuk Selasa siang saat "Run as administrator" dipakai pertama kali; keberadaan profil baru itu juga jejak responder yang dicatat (Day 08 untuk sisi file system).

**Kapan gagal:** batch file yang dipakai tidak memuat key BAM atau UserAssist, sehingga hasil kosong dibaca sebagai "tidak ada eksekusi". Selalu cek isi batch (`Description` dan `KeyPath`) sebelum membaca hasil kosong.

### 2.6 SRUM dengan SrumECmd

Langkah ini menjawab pertanyaan Pak Agus.

```powershell
& "$ez\SrumECmd.exe" -f "$t\Windows\System32\sru\SRUDB.dat" -r "$t\Windows\System32\config\SOFTWARE" --csv "$out\SRUM"
```

- `-f`: path `SRUDB.dat`; alternatifnya `-d` untuk mencari `SRUDB.dat` dan SOFTWARE hive secara rekursif, pola yang dipakai bersama KAPE [S10].
- `-r`: SOFTWARE hive, opsional tetapi disarankan [S10].
- `--csv`: folder output [S10]. Hasilnya beberapa CSV per tabel SRUM, antara lain pemakaian jaringan per aplikasi dan pemakaian resource per aplikasi; nama file persisnya cek di folder output.
- Bila SrumECmd berhenti dengan galat yang menandakan database dirty, perbaiki salinan (bukan bukti) dengan langkah di bagian 4 [S10].

Keluaran ilustrasi dari CSV pemakaian jaringan, difilter ke `powershell.exe` di bawah SID `dewi.anggraini` (waktu rekam UTC):

```
Timestamp             ExeInfo                                                          BytesSent  BytesReceived
2026-10-13 02:00:00   \device\harddiskvolume3\...\windowspowershell\v1.0\powershell.exe   6912       10240
2026-10-13 03:00:00   (idem)                                                             58368      61440
2026-10-13 04:00:00   (idem)                                                             40960      61440
2026-10-13 05:00:00   (idem)                                                             40960      61440
2026-10-13 06:00:00   (idem)                                                             40960      61440
2026-10-13 07:00:00   (idem)                                                             40960      61440
2026-10-13 08:00:00   (idem)                                                             40960      61440
2026-10-13 09:00:00   (idem)                                                             40960      61440
```

Ringkasan per aplikasi untuk Selasa 01:00 sampai 09:00 UTC (08:00 sampai 16:00 WIB), semua user, dihitung dari CSV yang sama (MiB):

```
App               Sent     Received
outlook.exe       3,62     41,87
msedge.exe        1,94     88,15
onedrive.exe      0,41     2,06
powershell.exe    0,30     0,42
```

**Cara membaca hasil:**

- `powershell.exe` di bawah akun Dewi mengirim total 311.040 byte (6.912 + 58.368 + 6 x 40.960) dan menerima 440.320 byte (10.240 + 7 x 61.440), sekitar 0,30 MiB dan 0,42 MiB, dalam delapan baris dari jam 08:00 sampai 16:00 WIB. Baris pertama kecil karena PowerShell baru berjalan sejak 08:51. Baris 10:00 WIB (03:00 UTC) lebih besar sekitar 17 KB dari baris biasa, konsisten dengan hasil enumerasi 09:06 yang dikirim ke C2, tetapi SRUM tidak bisa membuktikan isinya.
- Tidak ada baris setelah 16:00 WIB: laptop diisolasi pukul 16:00. Task tetap berjalan sampai Rabu sore menurut Prefetch, tetapi tanpa jaringan, sehingga tidak ada byte yang tercatat.
- Aplikasi dengan kiriman terbesar adalah Outlook dan Edge, yang dipakai Dewi bekerja. Untuk menilai apakah angka itu wajar, bandingkan dengan jam yang sama hari Senin sebelum kompromi; di contoh ini polanya serupa.
- Jawaban untuk Agus: dari sisi host, proses penyerang mengirim sekitar 0,3 MiB selama sekitar tujuh jam, pola yang cocok dengan beacon dan enumerasi kecil, dan tidak ada aplikasi lain yang mengirim jauh di atas kebiasaannya. SRUM tidak menunjukkan tujuan atau isi, dan waktu per baris bisa meleset sampai sekitar satu jam [S24]; konfirmasi dengan log proxy atau firewall untuk `203.0.113.77`.

**Variasi:** buka CSV pemakaian resource per aplikasi untuk melihat `powershell.exe` aktif di latar belakang pada jam-jam yang sama walaupun tidak ada jendela yang terlihat. Untuk host yang dicurigai exfiltration, urutkan seluruh aplikasi berdasarkan `BytesSent` per jam, lalu cari aplikasi yang jarang muncul.

**Kapan gagal:** database dirty dan diperbaiki langsung di folder hasil koleksi tanpa salinan, sehingga file yang di-hash di copylog berubah; atau angka SRUM dibaca per koneksi atau per menit. SRUM adalah total per interval sekitar satu jam per aplikasi per interface.

### 2.7 PCA (Windows 11)

Langkah ini menjawab bagian pertama pertanyaan keenam Sari.

```powershell
$pca = "$t\Windows\appcompat\pca\PcaAppLaunchDic.txt"
Format-Hex -Path $pca -Count 32
Import-Csv -Path $pca -Delimiter '|' -Header ExePath, LastExecutedUtc | Sort-Object LastExecutedUtc -Descending | Select-Object -First 5
```

- `Format-Hex -Count 32`: melihat 32 byte pertama untuk menentukan encoding sebelum membaca. Byte `FF FE` di awal atau byte nol di antara huruf menandakan UTF-16 LE; huruf tanpa byte nol menandakan ANSI. Sumber yang diperiksa tidak sepakat soal encoding [S4][S5].
- `Import-Csv -Delimiter '|' -Header ...`: setiap baris berisi path dan waktu UTC dipisah pipe [S4]. File ini tidak punya baris header, jadi nama kolom diberikan sendiri. Bila encoding ternyata UTF-16 tanpa BOM, tambahkan `-Encoding Unicode`.

Keluaran ilustrasi:

```
ExePath                                                          LastExecutedUtc
C:\Users\dewi.anggraini\Downloads\JAB-Printer-Bdg-Setup.exe      2026-09-14 03:21:07.512
C:\Program Files\JAB DocSync\jabdocsync.exe                      2026-08-11 02:05:44.090
...
```

**Cara membaca hasil:** tidak ada baris untuk `wscript.exe`, `powershell.exe`, program enumerasi, atau WinPmem. Itu sesuai ekspektasi di bagian 1.7: program bawaan dari lokasi aslinya, program yang dijalankan PowerShell atau task, dan program yang dijalankan dari command prompt termasuk kategori yang tidak dicatat PCA [S4]. Hasil ini tidak menambah bukti eksekusi untuk kasus ini dan tidak mengurangi bukti dari artefak lain. Di kasus lain, misalnya installer palsu yang diklik pengguna dari folder Downloads, PCA justru bisa menjadi satu-satunya sumber waktu peluncuran di host tanpa EDR.

**Variasi:** di host dengan Velociraptor, artifact `Windows.System.AppCompatPCA` membaca file ini dengan parameter `ExecutableRegex` untuk menyaring dan `SearchVSS` untuk ikut membaca salinan dari shadow copy [S6]. Baca juga `PcaGeneralDb0.txt` dan `PcaGeneralDb1.txt` (UTF-16 LE) untuk catatan proses yang keluar dengan kode tidak nol [S4].

**Kapan gagal:** file tidak ada karena build belum membuatnya, atau berhenti diperbarui setelah sebuah path dengan karakter non-ANSI tercatat [S4]. Ketiadaan tidak konklusif [S5].

### 2.8 Tabel korelasi dan jawaban untuk Sari

Tabel ini adalah keluaran akhir yang dikirim ke Sari pukul 13:10, sebelum rapat. Setiap baris adalah satu program, setiap kolom satu artefak, dan kolom terakhir menyatakan kesimpulan beserta labelnya. Baca kolom "Label" dengan teliti: tiga label yang berbeda sengaja dipakai.

| Program | Prefetch | BAM | Amcache / Shimcache | SRUM | Label dan kesimpulan |
|---|---|---|---|---|---|
| `wscript.exe` + `Tagihan-Okt-2026.js` | Run Selasa 08:51:16, file `.js` dirujuk | SID Dewi, 08:51:17 | Shimcache ada | tidak relevan | Penyerang (eksekusi lampiran). Bukti: Prefetch + BAM |
| `powershell.exe` | `.pf` dibuat 08:51:29; 132 run; terakhir Rabu 17:36:31 | SID Dewi, Rabu 17:36:33 | Shimcache ada, Executed No | 0,30 MiB terkirim, 08:51-16:00 | Penyerang (loader dan task tiap 15 menit). Bukti: Prefetch + BAM + SRUM |
| `whoami.exe`, `systeminfo.exe`, `ipconfig.exe`, `net.exe`/`net1.exe` | Run Selasa 09:06:44 sampai 09:07:10 | SID Dewi, waktu sama | Shimcache ada, Executed No | tidak ada baris sendiri | Penyerang (enumerasi dasar). Bukti: Prefetch + BAM. Argumen tidak diketahui |
| `cmd.exe` | Run 14:04:10 | SID akun lokal `-1003`, 14:21:15 | tidak relevan | tidak ada | Responder. Dasar: panduan telepon 13:55, akun admin lokal IR |
| `winpmem_mini_x64.exe` | Run 14:05:02, volume `5C2E91A4` | SID `-1003`, `HarddiskVolume5\tools` | Amcache SHA-1 `4be1...` cocok toolkit; driver dimuat | tidak ada | Responder (E08). Dasar: CoC E08 14:05-14:13, volume `USB-E-09`, SHA-1 |
| `autorunsc64.exe`, `schtasks.exe`, `wevtutil.exe`, `robocopy.exe`, `certutil.exe` | Run 14:14:22 sampai 14:21:10 | SID `-1003` | autorunsc SHA-1 cocok toolkit | tidak ada | Responder (skrip koleksi dan hash). Dasar: isi `koleksi-triage.cmd` v1.2, panduan langkah 6-7 |
| Aktivitas di dalam proses PowerShell tanpa proses baru | tidak tercatat | tidak tercatat | tidak tercatat | sebagian (volume saja) | Tidak terjawab dari artefak eksekusi. Bergantung memori E08 dan event log |

Jangkar volume untuk baris WinPmem: nomor seri volume `5C2E91A4` di Prefetch sama dengan nomor seri volume `USB-E-09` yang dicatat Yoga di case notes saat USB itu diterima di Jakarta, Jumat 2026-10-16 17:55, sebelum disimpan di lemari bukti. SHA-1 di Amcache dicocokkan dengan SHA-1 salinan `winpmem_mini_x64.exe` dan `autorunsc64.exe` di toolkit PT JAB yang dipakai mengisi `USB-E-09`.

Kalimat pengantar ke Sari:

```
BDG-WS-0142 (E18-W2), artefak eksekusi, untuk rapat 14:00:
1. Dijalankan penyerang di bawah akun dewi.anggraini: wscript.exe dengan Tagihan-Okt-2026.js
   (Selasa 08:51:16 WIB), powershell.exe (mulai 08:51:19, lalu tiap 15 menit sampai Rabu 17:36:31),
   dan enumerasi whoami, systeminfo, ipconfig, net/net1 (Selasa 09:06:44-09:07:10).
   Argumen perintah tidak tercatat di artefak ini.
2. Jejak Fajar (14:04-14:21, akun admin lokal IR, alat dari USB-E-09) sudah dipisahkan dan dilabeli;
   dasar: panduan telepon, CoC E08, akun, nomor seri volume, SHA-1 Amcache.
3. Entri Amcache/Shimcache sendiri bukan bukti eksekusi; eksekusi dibuktikan Prefetch dan BAM.
4. SRUM: powershell.exe mengirim ~0,30 MiB (08:51-16:00), tidak ada aplikasi lain yang menonjol.
   SRUM tidak memberi tujuan atau isi.
5. PCA (Windows 11): tidak ada entri terkait; sesuai jalur eksekusi yang dipakai, bukan tanda bersih.
6. Tidak ditemukan executable penyerang lain di artefak eksekusi. Aktivitas di dalam proses PowerShell
   tidak tercatat di sini; cakupan penuh mengikuti memori E08 dan event log. Hasil disk konsisten
   dengan kesimpulan retainer "beacon dan enumerasi dasar".
```

**Kapan gagal:** tabel diisi dari satu artefak lalu kolom lain diisi "sesuai", tanpa benar-benar dibuka; atau label responder diberikan berdasarkan waktu saja. Setiap label responder harus punya minimal dua jangkar dari bagian 1.5.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** VM korban `LAB-WS01` (Windows 11, Sysmon, snapshot `bersih-2026-10-15`), VM analisis `LAB-DFIR01` dengan EZ Tools dan KAPE, jaringan host-only `172.16.50.0/24`, folder kasus `CASE-2026-LAB-007`. Sysmon di `LAB-WS01` berfungsi sebagai kunci jawaban: setiap kesimpulan dari artefak eksekusi dicocokkan dengan Sysmon Event ID 1 (process creation) untuk program yang sama. Jangan memakai sampel berbahaya; semua program uji jinak.

1. **Siapkan catatan.** Buat `case-notes.md` di `CASE-2026-LAB-007`. Catat versi EZ Tools dan nilai `EnablePrefetcher` di `LAB-WS01` (dibaca dari registry, bukan ditebak).
2. **Jalankan program uji.** Kembalikan `LAB-WS01` ke snapshot. Login sebagai user biasa `lab.user`. Jalankan satu program jinak beberapa kali lewat Explorer (GUI), misalnya `notepad.exe`, dan catat waktunya. Dari PowerShell (user yang sama), jalankan `whoami.exe`, `ipconfig.exe`, dan `net.exe user` masing-masing sekali, catat waktunya.
3. **Uji lampiran skrip dari ZIP.** Buat file `uji-lab.js` berisi satu baris `WScript.Echo("lab");`, kompres ke `uji-lab.zip`, salin ke `Downloads`, buka ZIP di Explorer, lalu klik ganda file `.js`. Catat nama folder sementara yang dibuat Explorer.
4. **Simulasikan responder.** Tambahkan virtual disk kedua sebagai pengganti USB bukti, beri label `LAB-USB`, dan salin satu program jinak (misalnya `autorunsc64.exe` dari Sysinternals) ke `\tools\`. Buka Command Prompt dengan "Run as administrator" memakai akun admin lokal kedua `lab.ir`, jalankan program itu dari disk kedua, lalu `certutil -hashfile` atas satu file. Catat nomor seri volume disk kedua dengan `vol`.
5. **Uji salah tafsir.** Salin (bukan jalankan) satu executable lain ke `C:\Users\lab.user\Desktop\` dan buka foldernya di Explorer.
6. **Shutdown normal dan koleksi.** Matikan `LAB-WS01` dengan shutdown normal. Di `LAB-DFIR01`, mount disk VM read-only dan jalankan KAPE Targets seperti bagian 2.1, lalu parse semua artefak eksekusi dengan PECmd, AmcacheParser, AppCompatCacheParser, RECmd (`DFIRBatch.reb`), SrumECmd, dan baca PCA (bagian 2.2 sampai 2.7).
7. **Temukan program uji.** Di tiap artefak, temukan program dari langkah 2 sampai 5. Catat apa yang tiap artefak tunjukkan, lalu cocokkan waktu dengan Sysmon Event ID 1.
8. **Korelasi dan label.** Isi tabel seperti bagian 2.8. Tandai mana yang membuktikan eksekusi dan mana yang hanya keberadaan, dan beri label "uji user", "responder lab", atau "salinan saja" beserta jangkarnya (akun, nomor seri volume, SHA-1).
9. **Uji pertanyaan terbuka.** Jawab dengan data lab: (a) apakah UserAssist dan PCA mencatat klik ganda `.js` dari dalam ZIP; (b) apakah waktu BAM lebih dekat ke awal atau akhir proses (bandingkan program yang berjalan lama dengan Sysmon Event ID 1 dan 5); (c) nilai `Executed` di Shimcache untuk program bawaan dan untuk program dari disk kedua; (d) apakah file yang hanya disalin di langkah 5 muncul di Shimcache atau Amcache tanpa Prefetch.
10. **Catat keterbatasan.** Untuk tiap artefak, tulis satu kalimat keterbatasannya di cheat sheet pribadi.

**Hasil yang sebaiknya tersimpan:**

- Semua artefak eksekusi (plus PCA) diparse, dengan versi alat tercatat.
- Program uji ditemukan di minimal Prefetch dan BAM, dan waktunya dicocokkan dengan Sysmon.
- Tabel korelasi terisi dengan pembedaan "eksekusi", "keberadaan", dan "responder", masing-masing dengan jangkar.
- Dibuktikan atau dibantah bahwa keberadaan di Shimcache bukan eksekusi untuk build lab-mu.
- Jawaban untuk empat pertanyaan terbuka di langkah 9, dengan build Windows yang diuji.
- Keterbatasan tiap artefak tercatat.

**Variasi tantangan:** nonaktifkan Prefetch di VM korban (snapshot), jalankan program, kumpulkan, dan tunjukkan bagaimana kamu masih membuktikan eksekusi dari artefak lain (UserAssist, Amcache plus event log, SRUM). Tulis kombinasi minimal yang kamu percaya untuk menyimpulkan eksekusi tanpa Prefetch. Variasi kedua: ulangi langkah 2 dan 6 tetapi matikan VM dengan power off paksa, lalu bandingkan isi Shimcache dan SRUM dengan hasil shutdown normal.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat mengambil dan memparse artefak eksekusi. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Tidak ada Prefetch | Dinonaktifkan (server/SSD) atau dibersihkan | Baca `EnablePrefetcher` di SYSTEM hive [S14]; pakai artefak lain; catat Prefetch nonaktif |
| PECmd gagal membaca `.pf` Windows 10/11 | Parser lama yang tidak mendukung kompresi MAM atau format versi 31 | Pakai PECmd versi terbaru yang dibekukan untuk kasus [S7][S13]; uji dulu di `.pf` lab |
| Shimcache terbaru tidak ada | Belum di-flush ke registry (host dimatikan paksa atau di-image menyala) | Cek cara host dimatikan di case notes; jangan simpulkan ketiadaan [S19][S20] |
| UserAssist kosong | Program non-GUI; user berbeda | Cek NTUSER user yang benar; UserAssist hanya peluncuran lewat Explorer [S23] |
| AmcacheParser error | Hive korup, path salah, atau file `.LOG1`/`.LOG2` tidak ikut | Verifikasi path; koleksi ulang hive bersama log; cek versi parser [S9] |
| Hash Amcache tidak dikenal di threat intelligence | File lebih besar dari sekitar 30 MiB, hash hanya bagian awal | Bandingkan kolom ukuran; hash file utuh dari image bila file masih ada [S18] |
| SrumECmd galat "Object reference not set to an instance of an object" | Database dirty [S10] | Salin folder `sru` ke folder kerja terpisah, pastikan tidak read-only, jalankan `esentutl.exe /r sru /i` lalu `esentutl.exe /p SRUDB.dat` pada salinan, catat langkahnya, parse ulang [S10] |
| SRUM tidak ter-resolve nama jaringan | SOFTWARE hive tidak diberikan | Tambahkan `-r` ke SOFTWARE hive [S10][S25] |
| BAM tidak ada | Windows 10 sebelum 1709, atau path key berbeda per build | Cek kedua path `bam\UserSettings` dan `bam\State\UserSettings` [S21][S22] |
| PCA tidak ada | Build tidak membuat file; bukan Windows 11 22H2 ke atas | Ketiadaan tidak konklusif [S4][S5] |
| Hasil RECmd kosong untuk UserAssist/BAM | Batch file tidak memuat key itu, atau plugin gagal dimuat | Cek isi batch; buka blokir DLL di folder `Plugins` bila muncul galat memuat plugin [S11] |

## 5. Kesalahan umum dan jebakan

- **Menyebut Shimcache sebagai bukti eksekusi.** Shimcache membuktikan file dikenal sistem dan last modified-nya, bukan run [S3][S19].
- **Menganggap waktu Shimcache sebagai waktu eksekusi.** Itu last modified file [S20].
- **Membaca "Executed: No" di Shimcache Windows 10/11 sebagai tidak dijalankan.** Flag itu heuristik; banyak program yang jelas berjalan bernilai "No" [S16].
- **Mengira Amcache = dijalankan.** Amcache memberi metadata dan hash, tidak selalu eksekusi [S18][S19].
- **Mengandalkan satu artefak.** Korelasikan beberapa; satu bisa menyesatkan.
- **Mengira ketiadaan Prefetch/PCA berarti tidak dijalankan.** Bisa nonaktif, dirotasi, atau tidak dibuat.
- **Membaca delapan waktu Prefetch sebagai seluruh riwayat.** Program yang sering berjalan (PowerShell dari task) kehilangan waktu run lama; pakai run count dan waktu pembuatan `.pf` [S14][S15].
- **Mencampur jejak responder dengan jejak penyerang.** WinPmem, driver akuisisi, `certutil`, dan skrip koleksi terlihat sama mencurigakannya dengan alat penyerang; labeli dengan jangkar (bagian 1.5), jangan dihapus dan jangan dibiarkan tanpa label.
- **Menulis "tidak ada aktivitas lain".** Artefak eksekusi tidak melihat kerja di dalam proses yang sudah berjalan; tulis batas bawah dan sumber yang masih bisa menambah (bagian 1.8).
- **Memperbaiki `SRUDB.dat` di folder bukti.** Perbaikan `esentutl` mengubah file; kerjakan di salinan terpisah [S10].
- **Lupa zona waktu.** Semua waktu EZ Tools dalam UTC; 01:51 UTC adalah 08:51 WIB.
- `[komunitas, belum terkonfirmasi]` Komunitas DFIR menekankan bahwa Shimcache dan Amcache sering disalahtafsirkan sebagai bukti eksekusi; keduanya lebih kuat sebagai bukti keberadaan [S3][S19]. Untuk Amcache, sumber praktisi tidak sepakat [S18][S20]. PCA Windows 11 adalah sumber baru yang melengkapi artefak klasik [S4][S6]; formatnya bisa berubah antar build, perlu dicek. Klaim bahwa flag eksekusi Shimcache hanya terisi untuk binary non-bawaan dan bahwa entri BAM dihapus setelah sekitar tujuh hari juga belum terkonfirmasi sumber primer.

## 6. Catatan terkini

Bagian ini menampung detail versi dan perubahan yang bisa berubah lagi. Berguna saat memperbarui toolkit atau membaca dokumentasi lama, tetapi tidak mengubah cara membaca artefak di atas.

- **Format Prefetch versi 31 untuk Windows 11** tercantum di dokumentasi format libscca revisi 0.0.24 (Juli 2026), digambarkan mirip versi 30 varian 2 [S13]. Jumlah waktu run untuk versi 31 tidak dinyatakan eksplisit di dokumen itu; cek dengan PECmd di `.pf` build lab-mu.
- **README PECmd** di repo menyebut build .NET 10 yang berjalan di Linux dan macOS serta opsi `--ads` untuk mencari data prefetch di alternate data stream [S7], sedangkan halaman unduhan EZ Tools mencantumkan semua alat di versi 2026.5.0 untuk .NET 4 dan .NET 9 [S2]. Cek dengan `PECmd.exe -h` di versi yang kamu bekukan apakah opsi itu sudah ada.
- **Flag eksekusi Shimcache Windows 10/11** dibaca AppCompatCacheParser sejak Maret 2023; sebelumnya kolom itu "NA" [S16]. Velociraptor memakai aturan yang sama [S17]. Dokumentasi dan blog sebelum 2023 masih menulis Windows 10 tidak punya indikator eksekusi.
- **Penelitian Amcache Kaspersky** (1 Oktober 2025) merinci kategori key dan batas 31.457.280 byte untuk SHA-1, dan merilis alat AmCache-EvilHunter [S18].
- **PCA Windows 11:** Sygnia (15 November 2023) menguji 22H2 dan 23H2 [S4]; Andrea Fortuna (19 Maret 2026) menulis ulang dengan contoh PowerShell dan menyebut encoding yang berbeda [S5]. Belum ada dokumentasi Microsoft untuk format file ini. Velociraptor punya artifact Exchange `Windows.System.AppCompatPCA` [S6], dan KapeFiles mengoleksinya lewat target `AppCompatPCA` di `EvidenceOfExecution` [S26].
- **RECmd `DFIRBatch.reb`** (sebelumnya Kroll Batch) versi 2.22 memuat UserAssist, BAM, DAM, dan AppCompatCache [S11][S12].
- Artefak klasik (Prefetch, Amcache, Shimcache, UserAssist, BAM, SRUM) tetap inti; perilaku dan jumlah entri bisa berbeda antar versi Windows, perlu dicek.
- Day 08 masuk ke file system (MFT, USN, $LogFile) yang melengkapi bukti eksekusi dengan bukti keberadaan dan waktu file.

## 7. Cheat sheet

```
PREFETCH   C:\Windows\Prefetch\*.pf ; PECmd -d <dir> --csv <out> -q ; BUKTI run + run count + 8 waktu + volume + file dimuat
           .pf created = run pertama (bila .pf tak pernah dibuat ulang) ; v30 Win10, v31 Win11, terkompresi MAM
           tanpa user, tanpa argumen ; EnablePrefetcher=0 -> nonaktif (baca di SYSTEM, jangan tebak dari SSD)
AMCACHE    Amcache.hve (+.LOG1/.LOG2) ; AmcacheParser -f <hve> --csv <out> [-i] [-w putih] [-b IOC]
           InventoryApplicationFile = mungkin run ; InventoryDriverBinary = driver dimuat ; SHA-1 hanya 30 MiB awal
SHIMCACHE  SYSTEM hive ; AppCompatCacheParser -f SYSTEM --csv <out> [-c n] [-t]
           path + LAST MODIFIED file + posisi (kecil = baru) ; ditulis saat shutdown/reboot
           Executed Yes = indikator kuat (Win10/11, sejak 2023) ; No = tidak membuktikan apa pun
USERASSIST NTUSER.DAT ; RECmd --bn DFIRBatch.reb ; program GUI lewat Explorer per user, run count, last run ; ROT13
           cmd/PowerShell/task TIDAK tercatat ; focus data tidak andal
BAM/DAM    SYSTEM\...\Services\bam\State\UserSettings\<SID> ; last execution per SID ; Win10 1709+
           SID mesin vs SID domain -> akun lokal (IR) vs akun domain ; device path, bukan huruf drive
SRUM       SRUDB.dat ; SrumECmd -f SRUDB.dat -r SOFTWARE --csv <out> ; byte jaringan per app per user per ~jam
           tanpa tujuan/isi ; ditulis tiap ~jam + shutdown ; dirty -> esentutl /r sru /i ; /p SRUDB.dat DI SALINAN
PCA (Win11) C:\Windows\appcompat\pca\PcaAppLaunchDic.txt ; teks, pipe, UTC ; GUI saja ; encoding cek (ANSI vs UTF-16LE)
           PcaGeneralDb0/1.txt ; tidak dijamin ada ; Velociraptor Windows.System.AppCompatPCA (Exchange)
KOLEKSI    KAPE EvidenceOfExecution TIDAK memuat SYSTEM (Shimcache/BAM), NTUSER, SRUM -> tambah
           RegistryHivesSystem, RegistryHivesUser, SRUM
RESPONDER  label dengan >=2 jangkar: catatan tindakan + waktu | SID akun IR | volume serial/path USB | SHA-1
KORELASI   beberapa artefak sepakat = kuat ; Shimcache/Amcache = keberadaan, Prefetch/BAM/UserAssist = eksekusi
BATAS      kerja di dalam proses (PowerShell, .NET) tidak tercatat ; tulis batas bawah, bukan "tidak ada aktivitas lain"
WAKTU      EZ Tools = UTC ; laporan PT JAB = WIB (UTC+7)
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Memo retainer menyebut `autorunsc64.exe` ada di Amcache dan Shimcache laptop Dewi. Jadi terbukti program itu dijalankan, dan karena kita tidak mengenalnya, itu alat penyerang." Benarkah?

<details><summary>Jawaban</summary>

Tidak, untuk dua alasan. Pertama, Amcache dan Shimcache lebih kuat untuk keberadaan daripada eksekusi: Amcache bukan log eksekusi, dan entri Shimcache hanya berarti file dikenal sistem. Eksekusi dibuktikan Prefetch (run 14:14:22 WIB) dan BAM. Kedua, program itu berjalan di bawah SID akun admin lokal IR, dari `E:\tools\` di `USB-E-09`, di jendela waktu responder, dan SHA-1 Amcache-nya cocok dengan salinan di toolkit PT JAB. Itu jejak responder dari skrip `koleksi-triage.cmd`, bukan alat penyerang. Lihat bagian 1.3, 1.5, dan 2.8.

</details>

**2. Skenario keputusan.** Prefetch `POWERSHELL.EXE` di E18-W2 menunjukkan delapan waktu run, semuanya Rabu sore, dengan run count 132. Tidak ada waktu run hari Selasa. Kesimpulan mana yang tepat?

- A. PowerShell tidak berjalan hari Selasa, jadi loader baru aktif Rabu sore.
- B. Run hari Selasa sudah tertimpa karena Prefetch hanya menyimpan delapan waktu terakhir; run pertama ditunjukkan waktu pembuatan `.pf` (Selasa 08:51:29), dan run count 132 cocok dengan task tiap 15 menit dari Selasa pagi sampai shutdown Rabu.
- C. Prefetch tidak bisa dipercaya untuk PowerShell, jadi abaikan dan pakai Shimcache.

<details><summary>Jawaban</summary>

B. Prefetch menyimpan sampai delapan waktu run terakhir, ditambah waktu pembuatan file `.pf` yang menandai run pertama bila file itu tidak pernah dibuat ulang. Run count yang cocok dengan perhitungan interval task menguatkan kesimpulan. A keliru karena membaca delapan waktu sebagai seluruh riwayat. C keliru karena Shimcache tidak menyimpan waktu eksekusi sama sekali; kolom waktunya adalah last modified file. Lihat bagian 1.2 dan 2.2.

</details>

**3. Pertanyaan jebakan.** "Artefak eksekusi hanya menunjukkan `whoami`, `systeminfo`, `ipconfig`, dan `net`, jadi kita bisa menulis bahwa penyerang tidak melakukan apa pun selain enumerasi dasar di laptop Dewi." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Artefak eksekusi bekerja di tingkat executable dan hanya melihat proses baru. Loader PowerShell bisa membaca file, mengumpulkan informasi, dan mengirim data di dalam proses `powershell.exe` yang sama tanpa membuat proses baru, dan itu tidak tercatat di Prefetch, BAM, Shimcache, atau Amcache. Hasilnya adalah batas bawah; kalimat yang benar menyebut apa yang ditemukan, bahwa tidak ditemukan executable penyerang lain di artefak yang diperiksa, dan bahwa cakupan penuh bergantung pada memori E08 dan event log. Lihat bagian 1.8.

</details>

**4. Skenario keputusan.** Saat menyusun timeline, rekanmu mengusulkan menghapus semua baris antara 14:04 dan 14:21 WIB karena "itu cuma Fajar". Mana yang tepat?

- A. Hapus barisnya supaya timeline bersih untuk retainer.
- B. Pertahankan barisnya dengan label "responder" dan dasar pelabelannya (catatan tindakan, SID akun admin lokal IR, nomor seri volume `USB-E-09`, SHA-1 toolkit), lalu periksa apakah ada program di jendela itu yang tidak cocok dengan daftar tindakan.
- C. Biarkan tanpa label; pembaca laporan akan mengerti sendiri.

<details><summary>Jawaban</summary>

B. Jejak responder dilabeli, bukan dihapus, supaya pembaca bisa memeriksa ulang, dan program yang muncul di jendela responder tetapi tidak ada di daftar tindakan tetap diperlakukan sebagai temuan yang belum dijelaskan. A keliru karena menghapus data membuat timeline tidak bisa diverifikasi dan bisa menyembunyikan aktivitas penyerang yang kebetulan di jendela yang sama. C keliru karena WinPmem, driver akuisisi, dan `certutil` terlihat sama mencurigakannya dengan alat penyerang. Lihat bagian 1.5 dan 2.8.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Agus Setiawan (DPO), dalam tiga kalimat, apa yang ditunjukkan SRUM tentang kemungkinan data dikirim keluar dari laptop Dewi, dan apa yang tidak.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Laptop mencatat sendiri berapa banyak data yang dikirim setiap aplikasi per jam, dan program penyerang di laptop Dewi mengirim sekitar 0,3 MB selama sekitar tujuh jam sebelum laptop diputus dari jaringan, pola yang cocok dengan sinyal 'saya masih hidup' dan hasil pengecekan sistem yang kecil. Tidak ada aplikasi lain di laptop itu yang mengirim jauh lebih banyak dari kebiasaannya. Catatan ini tidak menunjukkan isi data atau tujuannya, jadi kami mengonfirmasinya dengan log jaringan, dan kesimpulan untuk laptop ini terpisah dari penilaian data pelanggan di server billing."

Kesalahan yang sering muncul:
- Menyebut SRUM membuktikan "tidak ada data pribadi yang bocor", padahal SRUM tidak melihat isi.
- Menjelaskan struktur database ESE atau tabel SRUM, padahal DPO butuh arti dan batasnya.
- Lupa memisahkan laptop Dewi dari pertanyaan data pelanggan di `jkt-billing01`.

</details>

**6. Pertanyaan jebakan.** "AppCompatCacheParser menampilkan `Executed: No` untuk `whoami.exe` di laptop Dewi, jadi `whoami.exe` tidak dijalankan dan baris Prefetch-nya pasti salah." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Di Windows 10/11, kolom itu dibaca dari empat byte terakhir data entri; nilai 1 ("Yes") adalah indikator kuat eksekusi, tetapi "No" tidak membuktikan apa pun. Pengujian di Windows 11 menunjukkan program yang jelas berjalan seperti `cmd.exe` dan `explorer.exe` juga bernilai "No". Prefetch `WHOAMI.EXE` dan entri BAM di bawah SID Dewi tetap menjadi bukti eksekusi. Lihat bagian 1.3 dan 2.4.

</details>

**7. Interview question (English).** "How do you prove a program executed on a Windows host that has no EDR and no Sysmon?"

<details><summary>Sample answer</summary>

"I build it from several artifacts, because none of them answers everything. Prefetch is my strongest evidence of execution: run count, up to eight last run times, the volume it ran from, and the files it touched, plus the .pf creation time for the first run. Prefetch has no user, so I add BAM, which keeps a last execution time per user SID, and UserAssist for anything launched through Explorer. Shimcache and Amcache I treat mainly as evidence of presence: they give me paths and SHA-1 hashes, and on Windows 10 and 11 a Shimcache 'executed' value of one is a strong hint, but a zero proves nothing. SRUM tells me how many bytes each application sent per hour, and on Windows 11 I check the PCA files for GUI launches. I also label my own team's activity, like the memory acquisition tool, using the account, the USB volume serial and the tool hash, so it doesn't get confused with the attacker. Finally I state the limits: none of these record command-line arguments, and anything done inside an already-running process like PowerShell leaves no execution artifact, so my findings are a lower bound."

What makes this answer strong: it maps each artifact to the question it answers, separates presence from execution with the current Windows 10/11 nuance, handles responder artifacts explicitly, and ends with the limits instead of overclaiming.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Mekanisme Prefetch Windows (literatur DFIR umum) | (tanpa URL; dokumentasi resmi Microsoft untuk format Prefetch tidak tersedia) | sekunder | 2026-10-10 | Sedang. Fungsi Prefetch sebagai cache start program; detail format dari PECmd [S2][S7] dan libscca [S13] |
| S2 | Eric Zimmerman tools: PECmd, AmcacheParser, AppCompatCacheParser, RECmd, SrumECmd | https://ericzimmerman.github.io/ | primer | diakses 2026-10-09, dicek ulang 2026-10-16 | Tinggi. Parser dan output; semua alat versi 2026.5.0 (.NET 4 dan .NET 9) per 2026-10-16 |
| S3 | Praktik DFIR: makna Shimcache/Amcache/UserAssist/BAM/SRUM | https://www.sans.org/posters/windows-forensic-analysis/ | sekunder (SANS) | diakses 2026-10-09, dicek ulang 2026-10-16 | Sedang-tinggi. Makna dan keterbatasan artefak. Isi poster di balik login; halaman publik hanya menyebut pertanyaan "Which programs ran?" dan tanggal terbit 13 Oktober 2026 |
| S4 | Sygnia: Diving into the new Windows 11 PCA artifact | https://www.sygnia.co/?p=133 | sekunder (peneliti) | 2023-11-15; diakses 2026-10-09, dicek ulang 2026-10-16 | Sedang-tinggi. Lokasi, isi, encoding ANSI, cakupan peluncuran GUI, `PcaGeneralDb0/1`, pengujian 22H2 dan 23H2; berbasis pengujian, bukan dokumentasi Microsoft |
| S5 | Andrea Fortuna: Windows 11 PCA artifact | https://andreafortuna.org/2026/03/19/windows11-pca-artifact/ | sekunder | 2026-03-19; diakses 2026-10-09, dicek ulang 2026-10-16 | Sedang. Last execution, keterbatasan; menyebut encoding UTF-16 LE, berbeda dengan [S4] |
| S6 | Velociraptor artifact: Windows.System.AppCompatPCA | https://docs.velociraptor.app/exchange/artifacts/pages/windows.system.appcompatpca | primer | diakses 2026-10-09, dicek ulang 2026-10-16 | Sedang-tinggi. Artifact Exchange komunitas (bukan bawaan); parameter `FileGlob`, `ExecutableRegex`, `SearchVSS` |
| S7 | PECmd README (GitHub) | https://raw.githubusercontent.com/EricZimmerman/PECmd/master/README.md | primer | diakses 2026-10-16 | Tinggi. Opsi `-d`, `-f`, `-q`, `--csv`, `--csvf`, `-o`, `--vss`, `--ads`; header README 1.4.0.0 dan build .NET 10 tidak sama dengan halaman unduhan [S2] |
| S8 | AppCompatCacheParser README (GitHub) | https://raw.githubusercontent.com/EricZimmerman/AppCompatCacheParser/master/README.md | primer | diakses 2026-10-16 | Tinggi. Opsi `-f`, `-c`, `-t`, `--csv`, `--csvf`, `--nl`; dukungan Windows XP sampai 11 |
| S9 | AmcacheParser README (GitHub) | https://raw.githubusercontent.com/EricZimmerman/AmcacheParser/master/README.md | primer | diakses 2026-10-16 | Tinggi. Opsi `-f`, `--csv`, `-i`, `-w`, `-b`, `--nl`; default hanya unassociated file entries |
| S10 | SrumECmd README (GitHub) | https://raw.githubusercontent.com/EricZimmerman/Srum/master/README.md | primer | diakses 2026-10-16 | Tinggi. Opsi `-f`, `-d`, `-r` (SOFTWARE opsional tetapi disarankan), `--csv`; galat database dirty dan langkah `esentutl` pada salinan |
| S11 | RECmd README (GitHub) | https://raw.githubusercontent.com/EricZimmerman/RECmd/master/README.md | primer | diakses 2026-10-16 | Tinggi. Opsi `-d`, `-f`, `--bn`, `--csv`, `--nl`; `DFIRBatch.reb` (sebelumnya Kroll Batch); galat memuat plugin |
| S12 | RECmd BatchExamples dan DFIRBatch.reb | https://github.com/EricZimmerman/RECmd/tree/master/BatchExamples | primer | diakses 2026-10-16 | Tinggi. Daftar batch contoh; `DFIRBatch.reb` v2.22 memuat UserAssist, BAM, DAM, AppCompatCache dengan plugin masing-masing |
| S13 | libscca: Windows Prefetch File (PF) format | https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc | primer (spesifikasi hasil reverse engineering) | revisi 0.0.24, Juli 2026; diakses 2026-10-16 | Tinggi. Versi format 17/23/26/30/31, delapan waktu run, hash nama file dari path, kompresi MAM, informasi volume (waktu pembuatan, nomor seri) |
| S14 | forensics.wiki: Prefetch | https://forensics.wiki/prefetch/ | sekunder (wiki komunitas) | diakses 2026-10-16 | Sedang. `EnablePrefetcher`, waktu pembuatan dan modifikasi `.pf`, angka 128 file dari dokumentasi lama, SSD; sebagian isi berasal dari era Windows 7 |
| S15 | Velociraptor artifact: Windows.Forensics.Prefetch | https://docs.velociraptor.app/artifact_references/pages/windows.forensics.prefetch | primer | diakses 2026-10-16 | Tinggi. Delapan waktu run terakhir plus creation time di Windows 10 |
| S16 | nullsec.us: AppCompatCache Deep Dive | https://nullsec.us/windows-10-11-appcompatcache-deep-dive/ | sekunder (praktisi) | 2024-08-21; diakses 2026-10-16 | Sedang-tinggi. Flag eksekusi empat byte terakhir, dukungan parser sejak Maret 2023, pengujian Windows 11 23H2 |
| S17 | Velociraptor artifact: Windows.Registry.AppCompatCache | https://docs.velociraptor.app/artifact_references/pages/windows.registry.appcompatcache | primer | diakses 2026-10-16 | Tinggi. Flag eksekusi Windows 10 ke atas; posisi kecil lebih baru |
| S18 | Kaspersky Securelist: Forensic journey, hunting evil within AmCache | https://securelist.com/amcache-forensic-artifact/117622/ | sekunder (peneliti vendor) | 2025-10-01; diakses 2026-10-16 | Sedang-tinggi. Key Inventory*, makna eksekusi per key, SHA-1 atas 31.457.280 byte pertama, transaction log |
| S19 | Cyber Triage: ShimCache and AmCache Forensic Analysis 2026 | https://www.cybertriage.com/blog/shimcache-and-amcache-forensic-analysis-2026/ | sekunder (vendor alat) | 2025-05-02, ditinjau 2026; diakses 2026-10-16 | Sedang. Shimcache ditulis saat shutdown, maksimal 1024 entri, heuristik empat byte; Amcache sebagai bukti keberadaan |
| S20 | Magnet Forensics: ShimCache vs AmCache | https://www.magnetforensics.com/blog/shimcache-vs-amcache-key-windows-forensic-artifacts/ | sekunder (vendor alat) | 2024-10-25; diakses 2026-10-16 | Sedang. Shimcache ditulis saat shutdown, waktu = last modified; menilai Amcache lebih andal untuk eksekusi (tidak sejalan dengan [S18][S19]) |
| S21 | Velociraptor artifact: Windows.Forensics.Bam | https://docs.velociraptor.app/artifact_references/pages/windows.forensics.bam | primer | diakses 2026-10-16 | Tinggi. Dua path key BAM, Windows 10 1709 ke atas, output SID dan waktu |
| S22 | winreg-kb: Background activity moderator (BAM) | https://winreg-kb.readthedocs.io/en/latest/sources/system-keys/Background-activity-moderator.html | primer (dokumentasi format, reverse engineering) | diakses 2026-10-16 | Sedang-tinggi. Struktur value, FILETIME di delapan byte pertama, nama value berupa device path |
| S23 | Velociraptor artifact: Windows.Registry.UserAssist | https://docs.velociraptor.app/artifact_references/pages/windows.registry.userassist | primer | diakses 2026-10-16 | Tinggi. ROT13, run count, last execution; peluncuran command line tidak tercatat; focus data tidak andal |
| S24 | Magnet Forensics: SRUM forensic analysis | https://www.magnetforensics.com/blog/srum-forensic-analysis-of-windows-system-resource-utilization-monitor/ | sekunder (vendor alat) | 2022-10-05; diakses 2026-10-16 | Sedang. Byte per aplikasi dan SID, penulisan tiap jam dan saat shutdown, data belum tertulis di registry, batas atribusi akun System |
| S25 | SANS ISC: SRUM-DUMP Version 3 | https://isc.sans.edu/diary/31896 | sekunder (SANS) | 2025-04-27; diakses 2026-10-16 | Sedang. Retensi sampai 30 hari, SOFTWARE hive untuk memetakan interface ke SSID |
| S26 | KapeFiles: EvidenceOfExecution.tkape dan folder Targets\Windows | https://raw.githubusercontent.com/EricZimmerman/KapeFiles/master/Targets/Compound/EvidenceOfExecution.tkape | primer | diakses 2026-10-16 | Tinggi. Versi 1.1 berisi Amcache, AppCompatPCA, Prefetch, RecentFileCache, Syscache; Shimcache sengaja tidak dimuat; target `SRUM`, `RegistryHivesSystem`, `RegistryHivesUser` ada di `Targets\Windows` |

**Catatan sumber:** Microsoft tidak mendokumentasikan format Prefetch, Shimcache, Amcache, BAM, atau PCA untuk keperluan forensik; makna artefak di Day ini berasal dari literatur DFIR (poster SANS [S3]), dokumentasi format hasil reverse engineering [S13][S22], perilaku parser EZ Tools dan artifact Velociraptor [S2][S7]-[S12][S15][S17][S21][S23], dan riset praktisi [S16][S18]-[S20][S24][S25]. Beberapa klaim bertentangan antar sumber dan ditulis apa adanya: jumlah maksimal file Prefetch (1024 yang sering disebut vs 128 di [S14]), perilaku Prefetch di SSD, kekuatan Amcache sebagai bukti eksekusi ([S20] vs [S18][S19]), dan encoding `PcaAppLaunchDic.txt` ([S4] vs [S5]); untuk yang terakhir catatan ini mengikuti pengujian Sygnia yang lebih rinci tetapi menyarankan cek byte di build lab. Yang masih perlu diuji di lab: apakah `FilesLoaded` Prefetch hanya mencerminkan run terakhir, jeda antara start program dan pembuatan `.pf`, apakah waktu BAM mencatat awal atau akhir proses, retensi BAM, nilai flag eksekusi Shimcache untuk binary bawaan, perilaku UserAssist dan PCA untuk skrip yang dibuka dari dalam ZIP, apakah `net.exe` selalu memanggil `net1.exe`, nama file output dan kolom tiap parser, dan apakah opsi `--ads` PECmd sudah ada di versi 2026.5.0. Semua isi PT JAB, termasuk waktu, run count, SID, nomor seri volume, SHA-1, angka SRUM, isi PCA, dan versi skrip koleksi, adalah contoh fiktif.
