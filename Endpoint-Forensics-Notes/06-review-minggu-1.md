---
day: 06
title: 'Review Minggu 1: alur akuisisi, lab, KAPE, Velociraptor, dan event log, dengan mini-lab triage ke timeline'
researched_on: 2026-10-10
versions_checked: 'KAPE, EZ Tools (.NET 9), Velociraptor 0.77.3, Volatility 3 2.28.2 (rujukan Day 02); rujukan Endpoint-Forensics Day 01-05'
---

# Day 06: Review Minggu 1 (akuisisi dan event log)

Cakupan: rangkuman akuisisi, lab, KAPE, Velociraptor, dan event log, dengan peta alur, glosarium, mini-lab triage sampai timeline, dan latihan skenario berpembahasan.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan alur akuisisi dari keputusan (triage vs image) sampai hasil yang diparse, tanpa melihat catatan.
- memilih KAPE atau Velociraptor untuk sebuah situasi akuisisi dengan alasan.
- memparse koleksi dengan EZ Tools dan membaca event log untuk menjawab pertanyaan investigasi.
- menjaga kebersihan bukti di seluruh alur: hashing, salinan, catatan kasus.
- mengenali kelemahan pribadi di fondasi akuisisi dan event log sebelum masuk artefak mendalam (Minggu 2).

## 2. Konteks singkat

Minggu 1 membangun fondasi forensik endpoint: keputusan akuisisi dan kebersihan bukti (Day 01), lab (Day 02), triage dengan KAPE (Day 03), koleksi dengan Velociraptor (Day 04), dan event log (Day 05). Minggu 2 masuk ke artefak disk mendalam: eksekusi (Day 07), file system (Day 08), registry (Day 09), aktivitas pengguna (Day 10), dan persistence/lateral (Day 11).

Hari ini menguji apakah alur akuisisi sampai pembacaan sudah menjadi kebiasaan. Kesalahan di fondasi ini mahal: koleksi yang tidak di-hash tidak bisa dipertahankan, koleksi tanpa event log tidak bisa direkonstruksi, dan salah zona waktu merusak semua timeline yang dibangun di atasnya. Mini-lab menjalankan satu kasus dari koleksi sampai timeline event log, lalu latihan skenario menguji keputusan yang tidak bisa dijawab dengan menghafal perintah.

## 3. Ringkasan per topik

| Day | Topik | Inti yang harus diingat |
|---|---|---|
| 01 | Alur DFIR swasta | Triage / adaptive / full image; order of volatility (RFC 3227); hashing (apa yang dibuktikan); chain of custody praktis; apa yang sengaja dilewati |
| 02 | Setup lab | VM korban (isolasi, snapshot, Sysmon, audit policy) vs analisis (tidak jalankan sampel); EZ Tools (.NET 9, Get-ZimmermanTools), KAPE, Velociraptor 0.77.3, Volatility 3 2.28.2; dataset publik (cek lisensi); catat versi |
| 03 | Triage KAPE | Targets (kumpulkan) vs Modules (proses); `!SANS_Triage`; VHDX container; VSS; `--sync`; hash; proses atas salinan |
| 04 | Velociraptor | Client/server; VQL dan artifact; artifact koleksi triage (ExcludeSigned, HashOnly); adaptive collection; hunt vs collection; offline collector; ekspor ke pipeline EZ Tools |
| 05 | Event log | Channel (Security, System, PowerShell, TaskScheduler, TerminalServices); event ID kunci; LogonType; audit policy; EvtxECmd; rekonstruksi lintas channel; 1102/104 pembersihan; ketiadaan event ditafsirkan hati-hati |

### 3a. Ringkasan per sub-topik

**Keputusan akuisisi (Day 01).** Tiga pola akuisisi punya trade-off yang jelas. Full disk image paling lengkap dan satu-satunya yang menyimpan unallocated space, tetapi lambat dan sulit diskalakan. Triage collection cepat dan bisa ke banyak host, tetapi hanya mengambil yang ada di daftar target. Adaptive collection menambah file yang dirujuk artefak (misalnya biner yang disebut Prefetch atau scheduled task) saat koleksi berjalan. Pola lapangan yang umum: scoping luas dengan hunt atau triage, koleksi mendalam di host yang relevan, dan image hanya bila ada alasan (litigasi, carving, pemulihan file terhapus). Order of volatility RFC 3227 menentukan urutan: memori dan data volatil dulu, lalu disk, lalu pastikan retensi log remote. Pengecualian yang perlu diingat adalah perangkat dengan cloud sync Files On-Demand, karena membuka placeholder saat live memicu unduhan dan menimpa unallocated space.

**Hash dan dokumentasi (Day 01).** Hash SHA-256 membuktikan satu hal: berkas tidak berubah sejak hash dihitung. Hash tidak membuktikan isi benar, lengkap, atau diambil dengan cara yang tepat. Bagian itu dijawab case notes kronologis (waktu dan zona, tindakan, alasan) dan formulir chain of custody (satu baris per perpindahan). Prinsip "melewati boleh asal disengaja dan dicatat" berlaku untuk semua hal yang tidak dikerjakan: tidak mengambil memori, tidak membuat image, tidak memakai write-blocker.

**Lab (Day 02).** Tiga ruang dipisahkan: VM korban yang menghasilkan artefak, VM analisis yang memparse, dan folder bukti read-only. VM korban harus terisolasi dan punya snapshot bersih. Telemetri di VM korban sengaja diperkaya (Sysmon, audit Process Creation dengan command line, Script Block Logging, audit task dan akun) supaya lab menghasilkan event yang sama dengan lingkungan yang dikonfigurasi baik. Versi tiap alat dicatat karena hasil parse bisa berubah antar versi.

**KAPE (Day 03).** KAPE punya dua mesin. Targets menyalin file (termasuk file terkunci lewat akses raw), Modules menjalankan program atas file itu. Pola bersih: Targets di host korban ke container VHDX di drive terpisah, hash container, pindah ke VM analisis, mount read-only, lalu Modules (`!EZParser`) menghasilkan CSV. Compound target `!SANS_Triage` adalah titik awal; target individual dipakai untuk memahami isinya. VSS memberi versi historis artefak, berguna bila penyerang sudah membersihkan sesuatu.

**Velociraptor (Day 04).** Velociraptor menambah jangkauan: banyak host dari jarak jauh, adaptive collection lewat VQL, dan offline collector untuk host tanpa agent. Kebijakan ExcludeSigned dan HashOnly memperkecil koleksi dengan konsekuensi: biner bertanda tangan (termasuk LOLBin yang disalin ke lokasi lain) tidak diambil, dan file yang hanya di-hash tidak bisa diparse. Apa pun mesin koleksinya, hasilnya masuk pipeline EZ Tools yang sama.

**Event log (Day 05).** Event log menjawab siapa, kapan, dari mana, dan dengan hak apa. Tafsir 4624 bergantung LogonType (2 konsol, 3 network, 10 RDP, 5 service). Rekonstruksi selalu lintas channel: Security untuk logon dan akun, System untuk service dan pembersihan, TaskScheduler untuk task, PowerShell untuk isi script, TerminalServices untuk RDP. Isi Security log ditentukan audit policy, jadi ketiadaan 4688 atau 4698 lebih sering berarti kategori itu tidak diaudit daripada aktivitasnya tidak ada. Event log disimpan UTC.

### 3b. Tabel artefak ke pertanyaan ke keterbatasan

| Artefak | Pertanyaan yang dijawab | Keterbatasan |
|---|---|---|
| Koleksi triage (KAPE/Velociraptor) | Apa artefak kunci di host ini? | Tanpa unallocated/file terhapus; bergantung daftar target |
| Hash koleksi | Apakah bukti berubah sejak dikumpulkan? | Hanya membuktikan integritas sejak hashing, bukan keaslian isi |
| Security 4624/4625 | Siapa login, kapan, dari mana, gagal/berhasil | LogonType wajib ditafsirkan; audit dan rotasi |
| Security 4720/4728 | Akun dibuat/ditambah ke grup | Butuh audit User Account Management |
| System 7045 | Service baru dipasang | Tidak memberi command line pembuat |
| TaskScheduler 106 / Security 4698 | Task dibuat | 4698 butuh audit; 106 bawaan |
| PowerShell 4104 | Isi script PowerShell | Butuh Script Block Logging |
| Security 1102 / System 104 | Apakah log dibersihkan | Hanya menandai pembersihan, bukan isi yang hilang |

### 3c. Peta alur akuisisi

```
 KEPUTUSAN (Day 01: triage | adaptive | full image ; order of volatility)
        |
        v
 KOLEKSI  KAPE (!SANS_Triage -> VHDX, 1 host akses langsung)  ATAU  Velociraptor (artifact triage, banyak host/jauh, adaptive)
        |
        v
 HASH koleksi (Day 01) -> pindah ke VM analisis -> verifikasi hash -> mount/ekstrak READ-ONLY
        |
        v
 PARSE  EZ Tools (MFTECmd, EvtxECmd, RECmd, PECmd, ...)  -> CSV
        |
        v
 BACA   Timeline Explorer (filter, sort)  -> jawab pertanyaan investigasi (Day 05 event log; Day 07+ artefak lain)
        |
        v
 CATAT  catatan kasus + chain of custody (Day 01)
```

### 3d. Glosarium

| Istilah | Arti singkat |
|---|---|
| Order of volatility | Urutan mengumpulkan bukti dari paling mudah hilang (memori) ke paling awet (disk), RFC 3227 |
| Triage collection | Koleksi artefak terpilih, cepat, bisa banyak host |
| Adaptive collection | Triage plus file tambahan berdasarkan parsing artefak saat koleksi |
| Full disk image | Salinan bit-per-bit seluruh media, termasuk unallocated |
| Chain of custody | Catatan siapa memegang bukti, kapan, dan apa yang dilakukan |
| Targets (KAPE) | Definisi file yang dikumpulkan |
| Modules (KAPE) | Definisi tool yang memproses koleksi |
| Compound target | Gabungan target, awalan `!` (mis. `!SANS_Triage`) |
| VSS | Volume Shadow Copy; versi historis file |
| ExcludeSigned | Kebijakan Velociraptor: lewati biner bertanda tangan tepercaya |
| HashOnly | Kebijakan: catat hash dan keberadaan, bukan isi |
| LogonType | Sifat logon 4624 (2 interaktif, 3 network, 10 RDP) |
| MapDescription | Deskripsi event yang ditambahkan EvtxECmd dari XML |
| Case notes | Log kronologis tindakan, perintah, hasil, dan alasan, dengan zona waktu |
| Salinan kerja | Salinan bukti yang dianalisis; master tetap utuh untuk verifikasi ulang |
| VHDX | Container disk virtual keluaran KAPE; satu file yang di-hash dan di-mount read-only |
| VQL | Bahasa query Velociraptor yang dijalankan di endpoint |
| Artifact (Velociraptor) | Paket YAML berisi query VQL dan parameter |
| Hunt | Menjalankan artifact ke banyak client sekaligus |
| Offline collector | Biner Velociraptor yang sudah dikonfigurasi untuk koleksi sekali jalan tanpa agent |
| LOLBin | Biner bawaan Windows bertanda tangan yang disalahgunakan penyerang |
| Audit policy | Pengaturan kategori yang dicatat di Security log; menentukan event apa yang mungkin ada |
| Script Block Logging | Pencatatan isi script PowerShell ke event 4104 |
| Files On-Demand | Fitur cloud sync yang menaruh placeholder di disk, bukan isi file |

## 4-6. Mini-lab dan troubleshooting

### Skenario

Analyst melaporkan aktivitas mencurigakan di WIN-LAB01. Kamu diminta melakukan triage, memparse, dan merekonstruksi apa yang terjadi dari event log, dengan bukti yang bersih.

Semua data fiktif, dari lab. Aktivitas uji jinak dijalankan di VM korban dengan snapshot; aktivitas yang meniru penyerang cukup berupa pembuatan akun, task, dan perintah PowerShell biasa yang dilakukan dengan sengaja, bukan teknik serangan sungguhan.

### Target hasil

1. Koleksi triage ke VHDX, di-hash.
2. Koleksi diparse dengan EZ Tools; event log dibaca.
3. Timeline mini yang merekonstruksi satu rangkaian (logon sampai persistence).
4. Catatan kasus dengan chain of custody.

### Langkah

1. **Siapkan.** Di VM korban (snapshot), jalankan rangkaian jinak: login, buat user lab, buat scheduled task atau service, jalankan satu perintah PowerShell. Catat waktu.
2. **Keputusan.** Tulis satu paragraf: kenapa triage (bukan full image) tepat untuk kasus ini (Day 01).
3. **Koleksi.** Jalankan KAPE `!SANS_Triage` ke VHDX di drive terpisah (Day 03), atau koleksi Velociraptor (Day 04). Hash container.
4. **Pindah dan verifikasi.** Pindahkan ke VM analisis, verifikasi hash, mount/ekstrak read-only.
5. **Parse.** Jalankan `!EZParser` atau EvtxECmd langsung atas event log (Day 05). Buka di Timeline Explorer.
6. **Rekonstruksi.** Temukan logon (4624 + LogonType), pembuatan akun (4720/4728), service (7045) atau task (106/4698), dan PowerShell (4104). Susun timeline mini.
7. **Catat.** Tulis catatan kasus: keputusan, waktu koleksi (live), hash, versi alat, dan timeline temuan.

### Contoh kerangka solusi (buka setelah mencoba sendiri)

<details><summary>Keputusan akuisisi</summary>

Triage tepat karena: perlu cepat, host bisa diakses, dan pertanyaan awal (apa yang terjadi) bisa dijawab artefak kunci (event log, registry, Prefetch). Full image ditunda kecuali muncul kebutuhan unallocated/file terhapus atau potensi litigasi (Day 01). Koleksi dilakukan pada sistem hidup; dicatat bahwa sebagian timestamp berubah.

</details>

<details><summary>Timeline mini (ilustrasi)</summary>

```
2026-10-02 14:01:10Z  Security 4624 LogonType 10  LAB\alice dari 192.168.56.20  (RDP logon)
2026-10-02 14:01:11Z  Security 4672               hak istimewa (admin)
2026-10-02 14:03:05Z  PowerShell 4104             script block dengan DownloadString
2026-10-02 14:04:20Z  Security 4720               akun "svc_lab" dibuat
2026-10-02 14:04:25Z  Security 4732               svc_lab ditambah ke Administrators lokal
2026-10-02 14:05:40Z  TaskScheduler 106           task "Updater" didaftarkan
```

Rekonstruksi: logon RDP admin, lalu PowerShell mengunduh sesuatu, lalu akun baru dibuat dan dinaikkan ke admin (persistence + privilege), lalu scheduled task (persistence). Rangkaian ini menyentuh lima channel/event dan menceritakan satu alur, bukan satu event.

</details>

### Troubleshooting ringkas

| Gejala | Kemungkinan penyebab | Perbaikan |
|---|---|---|
| Koleksi tidak berisi event log | Target tidak mencakup atau path salah | Pakai `!SANS_Triage`; cek `winevt\Logs` (Day 03, 05) |
| Hash tidak cocok setelah pindah | Transfer rusak atau salah file | Salin ulang; verifikasi sumber (Day 01) |
| Event yang diharapkan tidak ada | Audit mati atau rotasi | Cek audit policy (Day 05 bagian 3.7); tafsirkan hati-hati |
| Timeline membingungkan | Zona waktu campur | Event log UTC; samakan zona (Day 13 nanti) |
| 4688 tanpa command line | Setting command line tidak aktif | Normal; catat keterbatasan (Day 05) |

### Hasil yang sebaiknya tersimpan

- Paragraf keputusan akuisisi beserta daftar yang sengaja dilewati dan risikonya.
- Container VHDX atau arsip Velociraptor dengan `hashes.txt` dan bukti verifikasi setelah dipindah.
- CSV hasil EvtxECmd untuk minimal Security, System, TaskScheduler, dan PowerShell/Operational.
- Timeline mini dengan kolom waktu (UTC), channel, event ID, dan tafsir satu baris.
- Catatan kasus berisi versi KAPE, EZ Tools, dan Velociraptor yang dipakai.

**Variasi:** ulangi mini-lab dengan Velociraptor offline collector bila sebelumnya memakai KAPE, atau sebaliknya. Bandingkan apakah kedua koleksi memuat set event log yang sama, dan catat perbedaan struktur folder yang memengaruhi path EvtxECmd. Variasi kedua: matikan Script Block Logging di snapshot korban, jalankan perintah PowerShell yang sama, dan catat apa yang masih tersisa (4103 bila Module Logging aktif, Sysmon EID 1, atau tidak ada sama sekali).

### Latihan skenario dengan pembahasan

Jawab setiap skenario dalam tiga sampai lima kalimat sebelum membuka pembahasannya.

**Skenario 1.** Laptop manajer keuangan dicurigai dipakai untuk mengirim data ke pihak luar. Laptop masih menyala, OneDrive Files On-Demand aktif, BitLocker aktif, dan HR sudah dilibatkan. Apa urutan koleksimu?

<details><summary>Pembahasan</summary>

Kasus berpotensi ke HR dan sengketa, jadi libatkan legal dan perketat chain of custody sejak awal. Jangan matikan laptop: memori berisi proses, koneksi, dan kemungkinan kunci BitLocker. Urutan yang masuk akal adalah memori lebih dulu, lalu image atau koleksi disk saat volume masih terbuka (BitLocker tidak menjadi penghalang selama sistem berjalan), dan hindari membuka file di folder OneDrive karena placeholder akan terunduh. Isi file yang hanya berupa placeholder diambil dari sisi cloud dengan otorisasi. Semua keputusan, termasuk yang dilewati, ditulis di case notes.

</details>

**Skenario 2.** Alert EDR muncul di 40 workstation dengan pola command line yang sama. Tim hanya dua orang dan manajemen ingin tahu host mana yang benar-benar terdampak dalam beberapa jam. KAPE atau Velociraptor?

<details><summary>Pembahasan</summary>

Velociraptor. Jumlah host dan kebutuhan waktu menuntut koleksi jarak jauh: hunt dengan artifact yang ringan (misalnya proses, Prefetch, atau event log tertentu) untuk scoping, lalu collection triage penuh hanya di host yang terbukti terdampak. KAPE tetap bisa dipakai untuk satu atau dua host yang perlu diperiksa langsung. Hasil hunt dan collection diperlakukan sebagai bukti: dicatat waktu, artifact, parameter, dan di-hash setelah diekspor.

</details>

**Skenario 3.** Hash container VHDX di VM analisis tidak cocok dengan hash yang dicatat di host korban. Apa yang kamu lakukan?

<details><summary>Pembahasan</summary>

Jangan menganalisis salinan itu. Periksa ukuran byte kedua berkas, ulangi transfer dalam mode biner dari master, lalu hitung ulang. Bila master sendiri berbeda dari hash di case notes, catat temuan ini apa adanya, cari penyebabnya (salah berkas, container yang sempat di-mount read-write, antivirus), dan pertimbangkan koleksi ulang. Setiap langkah ditulis di case notes karena perbedaan hash adalah pertanyaan pertama yang akan diajukan bila temuan dipersoalkan.

</details>

**Skenario 4.** Di koleksi sebuah server, Security log hanya mencakup 36 jam terakhir dan tidak ada satu pun 4688. Ada satu 1102 dua hari lalu. Apa yang bisa dan tidak bisa kamu simpulkan?

<details><summary>Pembahasan</summary>

Rentang 36 jam bisa berarti rotasi karena ukuran log kecil di server sibuk; cek ukuran maksimum channel dan jumlah event per jam sebelum menyimpulkan apa pun. Tidak adanya 4688 sama sekali menunjukkan Process Creation tidak diaudit, bukan bahwa tidak ada proses. Event 1102 dua hari lalu berada di luar rentang 36 jam, jadi kemungkinan besar berasal dari channel lain yang retensinya lebih panjang atau dari koleksi VSS; pastikan sumbernya. 1102 membuktikan log pernah dibersihkan oleh akun tertentu pada waktu tertentu, tetapi tidak memberi tahu isi yang hilang. Langkah lanjut: cari salinan log di VSS, periksa SIEM bila log pernah diteruskan, dan beralih ke artefak non-log (Prefetch, Amcache, MFT) untuk eksekusi.

</details>

**Skenario 5.** Kamu menemukan 4624 LogonType 3 dari IP workstation admin ke server file, diikuti 7045 dengan nama service acak satu menit kemudian. Apa tafsir awalmu dan artefak apa yang kamu cari berikutnya?

<details><summary>Pembahasan</summary>

Pola logon network lalu service baru dengan nama acak cocok dengan eksekusi remote lewat service (pola PsExec dan tool sejenis, T1569.002). Ini belum bukti jahat karena admin juga memakai tool seperti ini. Langkah berikutnya: periksa `ServiceFileName` di 7045 (lokasi dan nama biner), cari biner itu di MFT dan Amcache, cek apakah akun di 4624 lazim melakukan administrasi ke server itu, lalu lihat di workstation admin apakah ada jejak eksekusi tool remote pada waktu yang sama. Artefak eksekusi dan persistence dibahas mendalam di Minggu 2.

</details>

## 7. Kesalahan umum dan jebakan (rangkuman Minggu 1)

- Mengumpulkan tanpa memutuskan pola akuisisi dan mencatat alasannya (Day 01).
- Menganalisis di VM korban atau atas bukti asli, bukan salinan (Day 02-03).
- Lupa hash koleksi dan verifikasi setelah pindah (Day 01, 03).
- Menganggap triage menangkap segalanya (tanpa unallocated/file terhapus) (Day 01, 03).
- Menyimpulkan dari satu event tanpa rekonstruksi lintas channel (Day 05).
- Mengira ketiadaan event berarti ketiadaan aktivitas (Day 05).
- Memakai ExcludeSigned tanpa sadar bahwa LOLBin yang disalin ke lokasi lain ikut terlewat (Day 04).
- Membuka file di folder cloud sync saat triage live, sehingga placeholder terunduh dan unallocated space tertimpa (Day 01).

## 8. Catatan terkini

- Versi acuan Minggu 1: KAPE (Kroll), EZ Tools (.NET 9), Velociraptor 0.77.3, Volatility 3 2.28.2 (Day 02).
- Apa pun mesin koleksi (KAPE atau Velociraptor), pipeline parsing EZ Tools dan pembacaan Timeline Explorer sama (Day 02-04).
- Event log UTC; rekonstruksi butuh beberapa channel (Day 05).
- Minggu 2 (Day 07-11) masuk ke artefak disk: eksekusi, file system, registry, aktivitas pengguna, persistence/lateral.

## 9. Cheat sheet Minggu 1

```
KEPUTUSAN  triage | adaptive | full image ; order of volatility (memori dulu) ; hash ; CoC ; apa yang dilewati
LAB        korban (isolasi, snapshot) vs analisis (tak jalankan sampel) ; catat versi alat
KAPE       Targets (--tsource --target !SANS_Triage --tdest --vhdx) | Modules (--msource --module !EZParser --mdest) ; --sync
VELOCIRAPTOR client/server ; artifact triage (ExcludeSigned/HashOnly) ; adaptive ; offline collector
PIPELINE   koleksi -> HASH -> pindah -> verifikasi -> mount/ekstrak RO -> EZ Tools -> CSV -> Timeline Explorer
EVENT LOG  4624/4625 logon | 4720/4728 akun | 7045 service | 106/4698 task | 4104 PowerShell | 1102/104 clear
PRINSIP    rekonstruksi lintas channel ; ketiadaan event != ketiadaan aktivitas ; waktu UTC
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Endpoint-Forensics Day 01-02 (akuisisi, lab) | (lokal) | rujukan internal | 2026-10-09 | Keputusan dan lab |
| S2 | Endpoint-Forensics Day 03-04 (KAPE, Velociraptor) | (lokal) | rujukan internal | 2026-10-09 | Koleksi |
| S3 | Endpoint-Forensics Day 05 (event log) | (lokal) | rujukan internal | 2026-10-09 | Event ID dan rekonstruksi |
| S4 | RFC 3227: Guidelines for Evidence Collection and Archiving | https://datatracker.ietf.org/doc/html/rfc3227 | primer | 2002-02; diakses 2026-10-10 | Tinggi untuk order of volatility |
| S5 | Microsoft Learn: 4624(S) An account was successfully logged on | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624 | primer | diakses 2026-10-10 | Tinggi. LogonType |

**Catatan sumber:** Day review ini merangkum Day 01-05; klaim yang masih perlu dicek (nama flag KAPE, nama artifact Velociraptor, status default audit per versi Windows) mengikuti catatan di Day asalnya. Pembahasan skenario adalah penalaran praktik umum, bukan prosedur standar.
