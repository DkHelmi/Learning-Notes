---
day: 04
title: 'Velociraptor dasar untuk forensik: server dan client, koleksi triage dan adaptive, offline collector, dan ekspor'
researched_on: 2026-10-10
versions_checked: 'Velociraptor 0.77.3 (5 Okt 2026); dokumentasi Velociraptor (overview, artifacts, offline collector); rujukan Day 01-03'
---

# Day 04: Velociraptor dasar untuk forensik

Cakupan: memakai Velociraptor sebagai mesin akuisisi forensik untuk satu atau banyak host, termasuk offline collector dan ekspor hasil ke pipeline EZ Tools.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan peran Velociraptor dalam akuisisi forensik: triage dan adaptive collection lintas host.
- membangun server dan client lab, lalu menjalankan koleksi artifact dari satu atau banyak endpoint.
- memakai artifact koleksi triage (penerus KapeFiles) dengan kebijakan seperti ExcludeSigned dan HashOnly.
- membuat offline collector untuk host tanpa agent.
- mengekspor hasil koleksi agar bisa diparse dengan EZ Tools dan dianalisis (Day 07-10).

## 2. Konteks singkat

Day 03 memakai KAPE untuk triage satu host yang diakses langsung. Velociraptor menambah dua hal: koleksi lintas banyak host dari jarak jauh (lewat agent), dan adaptive collection yang memutuskan file tambahan berdasarkan artefak saat koleksi (Day 01). Di DFIR nyata, Velociraptor sering jadi mesin akuisisi untuk banyak endpoint, lalu artefaknya diparse dengan EZ Tools yang sama seperti KAPE.

Velociraptor juga banyak dipakai untuk threat hunting, yaitu menjalankan query ke seluruh fleet untuk menemukan host yang mencurigakan. Day ini memakainya untuk forensik (mengumpulkan dan mempreservasi bukti dari host yang sudah ditentukan). Alat sama, tujuan berbeda: hunting mencari, forensik mengumpulkan dan menganalisis.

**Kapan dipakai:** koleksi dari banyak host atau host jarak jauh; adaptive collection; saat KAPE tidak praktis (host tidak bisa diakses langsung).
**Kapan KAPE cukup:** satu host yang bisa diakses langsung dengan media (Day 03).

## 3. Konsep inti

### 3.1 Velociraptor untuk akuisisi

Velociraptor adalah platform endpoint dengan client (agent), server, VQL, dan artifact [S2]. VQL (Velociraptor Query Language) adalah bahasa query mirip SQL yang dijalankan di endpoint: query bisa membaca file, registry, event log, atau memanggil parser bawaan. Artifact adalah file YAML yang membungkus satu atau beberapa query VQL beserta parameternya, sehingga investigator cukup memilih artifact dan mengisi parameter tanpa menulis VQL sendiri. Untuk forensik, yang dipakai:

| Komponen | Peran forensik |
|---|---|
| Client (agent) | Dipasang di endpoint; menjalankan koleksi dan mengirim hasil ke server |
| Server | Tempat investigator memberi tugas koleksi dan menyimpan hasil |
| Artifact koleksi | Mendefinisikan apa yang dikumpulkan (triage targets, file spesifik) |
| Offline collector | Paket mandiri untuk host tanpa agent |

Velociraptor memetakan ke pola akuisisi Day 01: triage collection (artifact triage), adaptive collection (artifact yang memparse lalu mengambil file tambahan), dan bukan full image (untuk itu tetap perlu tool imaging).

### 3.2 Artifact koleksi triage

Velociraptor punya artifact yang mengumpulkan artefak forensik, penerus pendekatan KapeFiles (Day 01) [S1]. Artifact `Windows.Triage.Targets` (atau sejenisnya) mengumpulkan set artefak kunci dengan kebijakan [S1]:

| Kebijakan | Arti |
|---|---|
| ExcludeSigned (default) | Tidak mengambil biner bertanda tangan tepercaya (mengurangi ukuran) [S1] |
| HashOnly | Hanya mencatat hash dan keberadaan file, bukan isinya [S1] |

Cek nama artifact dan opsi persis di versi 0.77.x lab (Day 01 juga menandai ini). Artifact koleksi menghasilkan set file yang serupa dengan KAPE `!SANS_Triage`, tetapi bisa dijalankan ke banyak host dari server.

### 3.3 Adaptive collection

Adaptive collection (Day 01) memparse artefak saat koleksi untuk memutuskan file tambahan yang diambil, misalnya biner yang dirujuk Prefetch atau scheduled task [S1]. Ini jalan tengah antara triage (cepat, bisa melewatkan) dan full image (lengkap, berat). Velociraptor mengimplementasikannya lewat VQL di artifact koleksi: query memeriksa satu artefak, lalu mengumpulkan file yang dirujuknya.

### 3.4 Koleksi vs hunt

| Aksi | Tujuan | Kapan |
|---|---|---|
| Collection (satu client) | Kumpulkan artefak dari satu host yang sudah ditentukan | Forensik mendalam satu host |
| Hunt (banyak client) | Jalankan artifact ke banyak host sekaligus | Triage luas, scoping, hunting |

Untuk forensik, alur umum: hunt luas untuk menemukan host relevan, lalu collection mendalam dari host itu untuk preservasi (Day 01 pola lapangan). Hasil collection diperlakukan sebagai bukti: di-hash, disimpan read-only.

### 3.5 Offline collector

Offline collector adalah paket mandiri yang dijalankan di host tanpa memasang agent permanen [S2]. Collector ini adalah biner Velociraptor yang konfigurasinya sudah berisi artifact dan parameter yang dipilih, sehingga di host target cukup dijalankan sebagai administrator lalu menunggu arsip hasil selesai ditulis. Untuk forensik, berguna saat:
- Host tidak boleh dipasangi agent permanen.
- Akuisisi satu kali di host yang diakses lewat media (mirip KAPE, tetapi dengan logika VQL Velociraptor).
- Host terisolasi dari server.

Collector menghasilkan file hasil (biasanya ZIP atau koleksi) yang dibawa ke server atau VM analisis untuk diparse.

### 3.6 Mengekspor untuk analisis EZ Tools

Velociraptor bisa mengumpulkan dan sebagian memparse di VQL, tetapi untuk analisis mendalam artefak Windows, alur umum adalah mengekspor file mentah yang dikumpulkan (hive, `$MFT`, event log) lalu memparse dengan EZ Tools (Day 02-03). Velociraptor sebagai mesin akuisisi, EZ Tools sebagai mesin parsing, Timeline Explorer sebagai pembaca. Ini menyatukan Day 02-04: apa pun mesin koleksinya (KAPE atau Velociraptor), hasilnya masuk ke pipeline EZ Tools yang sama.

### 3.7 Kebersihan bukti di Velociraptor

- Hasil collection di server adalah bukti; catat waktu, client, dan artifact yang dipakai (Day 01).
- Ekspor hasil, hash, lalu analisis atas salinan.
- Koleksi lewat agent mengubah sebagian state host (proses Velociraptor berjalan); catat ini, seperti koleksi live KAPE (Day 03).
- ExcludeSigned dan HashOnly mengurangi ukuran tetapi berarti sebagian file tidak dikumpulkan utuh; sadari saat analisis (file yang hanya di-hash tidak bisa diparse isinya).

## 4. Artefak, perintah, dan cara membacanya

> Perintah dijalankan di lab-mu. Keluaran berlabel ilustrasi. Nama artifact dan perintah perlu dicek terhadap versi 0.77.x.

### 4.1 Membangun server dan client lab

Velociraptor berjalan sebagai biner tunggal; peran server atau client ditentukan oleh konfigurasi dan subcommand [S2]. Alur lab:

1. Hasilkan konfigurasi server dan client (wizard konfigurasi Velociraptor).
2. Jalankan server; akses GUI lewat browser.
3. Pasang client di VM korban dengan konfigurasi client.

```
velociraptor config generate -i
velociraptor --config server.config.yaml frontend
velociraptor --config client.config.yaml client
```

- `config generate -i` menjalankan wizard interaktif untuk membuat konfigurasi, cek perintah persis di versi lab.
- Server dan client terhubung; client muncul di GUI server.
- Di lab, server dan client bisa di VM berbeda dalam jaringan host-only (Day 02).

### 4.2 Koleksi triage dari satu client

Di GUI server, pilih client, lalu Collect, pilih artifact koleksi triage:

```
Artifact: Windows.Triage.Targets   (atau Windows.KapeFiles.Targets)
Parameters: _SANS_Triage (atau set target), ExcludeSigned=Y, VSSAnalysis sesuai kebutuhan
```

- Memilih set target yang setara `!SANS_Triage` KAPE, cek nama parameter dan target di versi lab.
- Hasil koleksi tersimpan di server, bisa diunduh sebagai arsip.

Lewat CLI (koleksi lokal tanpa server, mirip offline):

```
velociraptor artifacts collect Windows.Triage.Targets --args Device=C: --output triage.zip
```

- `artifacts collect` menjalankan artifact secara lokal dan menulis hasil ke arsip, cek sintaks persis dan nama argumen.

### 4.3 Hunt untuk triage lintas host

Untuk triage banyak host sekaligus (scoping, Day 01):

```
Hunt: jalankan Windows.Triage.Targets ke semua client berlabel "windows"
```

- Di GUI, buat hunt dengan artifact koleksi dan kondisi client (misalnya label atau OS), lalu jalankan; tiap client yang online mengeksekusi artifact dan mengirim hasilnya.
- Berbeda dari hunt hunting (mencari), ini hunt koleksi (mengumpulkan artefak dari banyak host untuk preservasi dan analisis).
- Cek perilaku koleksi besar lintas banyak host; batasi agar tidak membebani jaringan.

### 4.4 Offline collector

Buat offline collector di GUI server (Server Artifacts, Offline Collector) atau CLI, lalu jalankan di host target:

```
# di host target, jalankan collector yang sudah dikonfigurasi
Collector_velociraptor.exe
```

- Collector mengumpulkan sesuai artifact yang dikonfigurasi dan menghasilkan arsip hasil.
- Bawa arsip ke VM analisis; hash dulu (Day 01).
- Cek cara membuat collector persis di versi lab; umumnya lewat artifact `Server.Utils.CreateCollector` atau menu GUI.

### 4.5 Ekspor dan parse dengan EZ Tools

Setelah koleksi (dari server, CLI, atau offline collector):

1. Unduh/salin arsip hasil ke VM analisis.
2. Hash arsip (`Get-FileHash`), simpan ke `hashes.txt` (Day 01).
3. Ekstrak ke folder `analysis` (salinan, bukan bukti asli).
4. Parse artefak dengan EZ Tools, misalnya `$MFT`:

```
MFTECmd.exe -f ".\triage\C\$MFT" --csv ".\analysis" --csvf mft.csv
```

- Struktur folder di dalam arsip Velociraptor berbeda dari KAPE; sesuaikan path. Cek struktur arsip di versi lab.
- Hasil CSV dibaca di Timeline Explorer, sama seperti alur KAPE (Day 03).

### 4.6 Memilih KAPE atau Velociraptor

| Situasi | Pilihan |
|---|---|
| Satu host, akses langsung dengan media | KAPE (Day 03) |
| Banyak host, dari jarak jauh | Velociraptor hunt koleksi |
| Butuh adaptive collection (file berdasarkan artefak) | Velociraptor |
| Host tanpa agent, satu kali | Velociraptor offline collector atau KAPE |
| Lingkungan sudah ada agent Velociraptor | Velociraptor |

Keduanya menghasilkan artefak yang diparse pipeline EZ Tools yang sama; pilihan soal jangkauan dan akses, bukan hasil akhir.

## 5. Lab praktik

**Prasyarat:** VM analisis dan VM korban (Day 02); biner Velociraptor (Day 02); jaringan host-only; snapshot.

1. **Server dan client.** Hasilkan konfigurasi, jalankan server, pasang client di VM korban (bagian 4.1). Pastikan client muncul di GUI server.
2. **Koleksi triage.** Jalankan artifact koleksi triage dari client (bagian 4.2) dengan set setara `!SANS_Triage`. Catat artifact dan parameter.
3. **Hash dan ekspor.** Unduh arsip hasil, hash, simpan ke `hashes.txt`, ekstrak ke folder analysis (bagian 4.5).
4. **Parse.** Parse `$MFT` dan satu event log dari koleksi dengan EZ Tools; baca di Timeline Explorer. Bandingkan dengan koleksi KAPE Day 03 (artefak yang sama?).
5. **Offline collector.** Buat offline collector, jalankan di VM korban (bagian 4.4), bandingkan hasilnya dengan koleksi lewat agent.
6. **Adaptive (opsional).** Jalankan artifact koleksi yang memparse Prefetch lalu mengambil biner yang dirujuk; amati file tambahan yang dikumpulkan dibanding triage polos, cek artifact yang tepat.
7. **Catat.** Tulis catatan kasus: artifact, parameter (ExcludeSigned/HashOnly), waktu, hash, versi Velociraptor.

**Hasil yang sebaiknya tersimpan:**
- Server dan client berjalan; client terlihat di GUI.
- Koleksi triage berhasil; arsip di-hash.
- Artefak diparse dengan EZ Tools dan dibaca di Timeline Explorer.
- Offline collector dibuat dan dijalankan; hasil dibandingkan dengan agent.
- Catatan kasus dengan artifact, parameter, hash, dan versi tersimpan.

**Variasi tantangan:** jalankan koleksi dengan `ExcludeSigned` aktif dan nonaktif, lalu bandingkan ukuran arsip dan jumlah file. Tulis trade-off: ExcludeSigned memperkecil koleksi tetapi melewatkan biner bertanda tangan yang kadang disalahgunakan. Biner seperti ini disebut LOLBin (living-off-the-land binary): program bawaan Windows bertanda tangan Microsoft, misalnya `certutil.exe`, `rundll32.exe`, atau `mshta.exe`, yang dipakai penyerang untuk mengunduh atau menjalankan sesuatu tanpa membawa tool sendiri. Bila penyerang menyalin LOLBin ke lokasi lain atau mengganti nama, salinan itu tetap bertanda tangan dan bisa terlewat oleh ExcludeSigned. Putuskan kapan kamu akan menonaktifkannya.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Client tidak muncul di server | Konfigurasi atau jaringan | Cek konfigurasi client; jaringan host-only menjangkau server |
| Artifact koleksi tidak ditemukan | Nama beda versi | Cari di daftar artifact GUI; cek nama [S1] |
| Koleksi sangat besar | ExcludeSigned nonaktif; target luas | Aktifkan ExcludeSigned; persempit target [S1] |
| File hanya hash, tidak bisa diparse | HashOnly aktif untuk file itu | Nonaktifkan HashOnly untuk artefak yang perlu diparse [S1] |
| Struktur arsip tak cocok path EZ Tool | Layout Velociraptor beda dari KAPE | Sesuaikan path; cek isi arsip |
| Offline collector gagal | Konfigurasi collector salah | Buat ulang lewat GUI/artifact; cek cara di versi |

## 7. Kesalahan umum dan jebakan

- **Menganggap koleksi lewat agent tidak mengubah host.** Proses Velociraptor berjalan; catat seperti koleksi live (Day 03).
- **Lupa ExcludeSigned/HashOnly berarti sebagian file tidak utuh.** File yang hanya di-hash tidak bisa diparse isinya.
- **Tidak hash hasil koleksi.** Perlakukan hasil sebagai bukti; hash dan analisis atas salinan (Day 01).
- **Memakai Velociraptor untuk satu host yang mudah diakses langsung** padahal KAPE lebih sederhana.
- **Mengira Velociraptor menggantikan full image.** Untuk unallocated/file terhapus tetap perlu imaging (Day 01).
- `[komunitas, belum terkonfirmasi]` Velociraptor banyak dipakai sebagai mesin akuisisi lintas fleet lalu artefaknya diparse EZ Tools; nama artifact dan parameter berubah antar versi, jadi konfirmasi di versi lab [S1][S2].

## 8. Catatan terkini

- Velociraptor 0.77.3 adalah versi acuan; perbarui untuk CVE [S3].
- Artifact koleksi triage (penerus KapeFiles) dengan ExcludeSigned dan HashOnly adalah pendekatan adaptive collection yang direkomendasikan (Day 01) [S1].
- Apa pun mesin koleksi (KAPE atau Velociraptor), pipeline parsing EZ Tools dan pembacaan Timeline Explorer sama (Day 02-03).
- Day 05 masuk ke artefak pertama yang dianalisis mendalam: Windows event log.

## 9. Cheat sheet

```
PERAN      client (agent di endpoint) | server (tugas + simpan) | artifact koleksi | offline collector
AKUISISI   triage (Windows.Triage.Targets) | adaptive (parse lalu ambil file dirujuk) | bukan full image
KEBIJAKAN  ExcludeSigned (default; lewati biner bertanda tangan) | HashOnly (hanya hash + keberadaan)
KOLEKSI    collection (1 host) | hunt koleksi (banyak host) ; hasil = bukti (hash, read-only)
OFFLINE    collector mandiri utk host tanpa agent ; bawa arsip ke analisis, hash dulu
EKSPOR     unduh arsip -> hash -> ekstrak ke salinan -> EZ Tools parse -> Timeline Explorer
PILIH      1 host akses langsung -> KAPE | banyak/jauh/adaptive -> Velociraptor ; hasil ke pipeline EZ yang sama
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Velociraptor: Adaptive Collections / Triage artifacts (Day 01) | https://docs.velociraptor.app/ | primer | diakses 2026-10-09 | Tinggi untuk konsep; nama artifact, perlu dicek |
| S2 | Velociraptor documentation: Overview (client, server, offline collector) | https://docs.velociraptor.app/docs/overview/ | primer | diakses 2026-10-09 | Tinggi |
| S3 | Velociraptor releases (0.77.3) | https://github.com/Velocidex/velociraptor/releases | primer | 0.77.3; diakses 2026-10-09 | Tinggi |
| S4 | Endpoint-Forensics Day 01-03 (akuisisi, hashing, KAPE) | (lokal) | rujukan internal | 2026-10-09 | Pola akuisisi dan pipeline |
| S5 | Eric Zimmerman tools (parsing hasil koleksi) | https://ericzimmerman.github.io/ | primer | diakses 2026-10-09 (Day 02) | Tinggi |

**Catatan sumber:** nama artifact koleksi (`Windows.Triage.Targets` atau `Windows.KapeFiles.Targets`), parameter (ExcludeSigned, HashOnly, set target), perintah CLI (`config generate`, `artifacts collect`), dan cara membuat offline collector berubah antar versi; cocokkan dengan daftar artifact di GUI dan `velociraptor -h` versi 0.77.x. Struktur arsip hasil Velociraptor berbeda dari KAPE dan perlu dicek dengan membuka satu arsip di lab.
