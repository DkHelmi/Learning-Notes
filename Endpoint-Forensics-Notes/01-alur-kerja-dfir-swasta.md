---
day: 01
title: 'Alur kerja DFIR swasta: triage vs full image, order of volatility, hashing, dokumentasi, chain of custody praktis'
researched_on: 2026-10-10
versions_checked: RFC 3227 (BCP 55, Feb 2002); NIST SP 800-86 (Agu 2006); NIST SP 800-61r3 (Apr 2025, menggantikan r2); Velociraptor docs (artikel Adaptive Collections, Sep 2025); PowerShell Get-FileHash, GNU sha256sum (perilaku umum; cek versi di lab)
---

# Day 01: Alur kerja DFIR swasta (triage vs full image, order of volatility, hashing, chain of custody)

Cakupan: keputusan akuisisi bukti di endpoint untuk investigasi sektor swasta, dari memilih pola koleksi sampai hashing dan chain of custody.

> Konteks: investigasi di sektor swasta (internal/IR vendor), bukan prosedur court-ready. Ini bukan nasihat hukum. Jika kasus berpotensi ke ranah hukum, libatkan legal sejak awal.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- memilih antara triage collection, adaptive collection, dan full disk image untuk sebuah kasus, lengkap dengan alasannya.
- menyusun urutan pengumpulan bukti di endpoint Windows berdasarkan order of volatility (RFC 3227).
- melakukan dan memverifikasi hashing bukti, serta menjelaskan apa yang dibuktikan dan tidak dibuktikan oleh hash.
- menulis catatan kasus dan chain of custody yang ringkas tetapi bisa dipertanggungjawabkan.
- menyebut apa yang biasanya dilewati di DFIR swasta, kenapa itu sah, dan risikonya.

## 2. Konteks singkat

Kamu sudah terbiasa dengan investigasi berbasis log di SIEM. Log memberi tahu *apa yang dilaporkan sistem*. Artefak endpoint memberi tahu *apa yang benar-benar terjadi di disk dan memori*, termasuk hal yang tidak pernah dikirim ke SIEM. Kurikulum ini memindahkanmu ke endpoint.

Day 01 bukan tentang alat. Topiknya adalah keputusan: apa yang dikumpulkan, dalam urutan apa, bagaimana membuktikan bukti tidak berubah, dan apa yang sengaja tidak dilakukan. Alat (KAPE, Velociraptor, Volatility 3) masuk di Day 02-04 dan Day 14.

**Posisi dalam IR:** NIST SP 800-61r3 (April 2025) menggantikan r2 (2012). Ia menempatkan incident response sebagai bagian dari manajemen risiko keamanan dan menyusunnya sebagai Community Profile dari NIST CSF 2.0 [S3]. Forensik endpoint adalah kemampuan yang mendukung tahap deteksi, analisis, dan respons di dalamnya. Proses forensik itu sendiri biasa dipecah menjadi empat tahap: collection, examination, analysis, dan reporting [S2].

## 3. Konsep inti

### 3.1 Tiga pola akuisisi

| Pola | Apa yang diambil | Kelebihan | Kekurangan | Kapan |
|---|---|---|---|---|
| Full disk image | Salinan bit-per-bit seluruh media, termasuk unallocated | Paling lengkap; bisa memulihkan file terhapus; analisis ulang kapan saja | Lambat, besar, sulit di banyak host/cloud | Host kunci yang sudah dipersempit; potensi litigasi; kebutuhan carving |
| Triage collection | File/artefak terpilih (registry hive, event log, Prefetch, $MFT, dll.) | Cepat, kecil, bisa ke banyak host | Bisa melewatkan bukti yang tidak masuk daftar target | Awal kasus, scoping, banyak host |
| Adaptive collection | Triage + file tambahan yang dipilih berdasarkan parsing artefak saat koleksi (mis. biner yang dirujuk Prefetch/scheduled task) | Jalan tengah: lebih lengkap dari triage, jauh lebih kecil dari image | Bergantung pada logika alat; tetap bukan image | Host yang dicurigai, saat image tidak praktis |

Velociraptor (Sep 2025) berpendapat bahwa full image makin tidak praktis karena ukuran dan kecepatan, dan triage dasar saja sering kurang. *Adaptive collection* adalah jalan tengah [S4]. Di Velociraptor, artefak `Windows.Triage.Targets` disebut sebagai penerus pendekatan KapeFiles, dengan kebijakan koleksi seperti `ExcludeSigned` (default; tidak mengambil biner bertanda tangan tepercaya) dan `HashOnly` (hanya mencatat hash dan keberadaan file) [S4], cek nama artefak dan opsi di versi Velociraptor lab-mu (Day 04).

Pola yang umum di lapangan [S5]:
1. Hunt atau triage luas ke banyak endpoint untuk mempersempit host yang relevan.
2. Triage atau adaptive collection mendalam di host tersebut untuk preservasi.
3. Full image hanya bila severity, kebutuhan hukum, atau pertanyaan analisis (mis. pemulihan file terhapus) membenarkannya.

### 3.2 Order of volatility (RFC 3227)

RFC 3227 (BCP 55, 2002) menyusun urutan dari paling cepat hilang ke paling stabil [S1]:

1. Register, cache
2. Routing table, ARP cache, process table, kernel statistics, memory
3. Temporary file systems
4. Disk
5. Remote logging dan monitoring data
6. Konfigurasi fisik, topologi jaringan
7. Media arsip

Prinsip yang menyertainya [S1]:
- Catatan bertimestamp.
- Minimalkan perubahan pada data.
- Utamakan pengumpulan sebelum analisis.
- Jangan mematikan sistem sebelum koleksi selesai.
- Jangan memercayai program di sistem yang dikompromikan.
- Hindari alat yang mengubah access time.
- Hati-hati memutus jaringan, karena penyerang bisa memasang mekanisme destruktif (*deadman switch*).

**Penerapan praktis di endpoint Windows:**
1. Memori (RAM) lebih dulu (alat dan cara dibahas di Day 14).
2. Data volatil yang murah: proses, koneksi jaringan, sesi logon. Ini bisa juga diambil lewat Velociraptor (Day 04).
3. Triage disk (Day 03).
4. Image, bila diputuskan perlu.

Log remote (SIEM, DC, EDR) berada di urutan 5. Log itu biasanya aman di tempat lain, tetapi retensinya terbatas. Jadi ekspor atau pastikan retensinya sejak awal kasus.

**Catatan terbaru (Jan 2026):** Elcomsoft menyoroti bahwa layanan sinkronisasi cloud dengan *Files On-Demand* (OneDrive, Dropbox) menaruh placeholder di disk, bukan isi file. Akibatnya, image offline hanya menangkap metadata. Sebaliknya, membuka file tersebut saat triage live memicu unduhan yang bisa menimpa unallocated space. Rekomendasi mereka: ikuti order of volatility: RAM dan kunci enkripsi dulu, lalu image, baru triage aktif, lalu ekstraksi dari sisi cloud [S6]. `[sekunder, vendor forensik]`, cek perilaku placeholder pada build Windows/OneDrive di lab-mu.

### 3.3 Hashing: apa yang dibuktikan

- Hash kriptografis (praktik umum: SHA-256) dihitung saat koleksi, lalu diverifikasi sebelum analisis dan setiap kali bukti berpindah tangan.
- Hash membuktikan bahwa berkas bukti tidak berubah sejak hash dihitung. Hash tidak membuktikan bahwa isinya benar, lengkap, atau diambil dengan cara yang tepat. Itu tugas dokumentasi.
- Untuk triage, yang di-hash biasanya arsip koleksi (mis. ZIP keluaran collector) plus manifest per file bila alat menyediakannya.
- MD5/SHA-1 masih muncul di alat lama. Sertakan SHA-256 untuk ketahanan terhadap kolisi.

### 3.4 Dokumentasi dan chain of custody (praktis)

RFC 3227 meminta pencatatan: di mana, kapan, dan oleh siapa bukti ditemukan dan dikumpulkan; di mana, kapan, dan oleh siapa ditangani atau diperiksa; siapa yang memegangnya, berapa lama, dan bagaimana disimpan; serta setiap perpindahan [S1].

Untuk konteks swasta, versi minimal yang masih bisa dipertanggungjawabkan:
- **Catatan kasus (case notes):** log kronologis dengan waktu dan zona waktu. Tulis tindakan, perintah, hasil, dan alasan.
- **Formulir chain of custody:** satu baris per perpindahan. Kolomnya: ID bukti, deskripsi, hash, dari, ke, waktu, tujuan, tanda tangan/approval.
- **Penyimpanan:** lokasi dengan kontrol akses (share terbatas atau bucket dengan logging), salinan kerja terpisah dari master.

Kenapa tetap perlu di swasta: kasus internal bisa berujung ke PHK, klaim asuransi, pelaporan regulator, atau sengketa. Saat itu, pertanyaan "bagaimana kamu tahu ini tidak diubah?" harus bisa dijawab [S7].

### 3.5 Apa yang biasanya dilewati, dan kenapa sah

| Dilewati | Kenapa sah di swasta | Risiko yang diterima |
|---|---|---|
| Full image setiap host | Waktu dan skala; triage menjawab sebagian besar pertanyaan IR | File terhapus/unallocated tidak bisa dipulihkan nanti |
| Write-blocker hardware untuk triage live | Koleksi live memang mengubah sistem minimal; dicatat | Perubahan kecil pada sistem (dokumentasikan) |
| Dua pemeriksa independen | Tim kecil | Kurang verifikasi silang; kompensasi dengan catatan rinci |
| Analisis memori di semua host | Mahal | Teknik fileless di host yang tidak di-dump bisa terlewat |

Prinsipnya: melewati boleh, asal disengaja dan tercatat. Tulis keputusan dan alasannya di case notes.

## 4. Artefak, perintah, dan cara membacanya

> Semua perintah dijalankan di VM lab. Keluaran berlabel ilustrasi.

### 4.1 Mencatat konteks waktu sebelum koleksi (Windows, PowerShell)

```powershell
Get-Date -Format o
Get-TimeZone
w32tm /query /status
```

| Perintah | Tujuan | Kenapa penting |
|---|---|---|
| `Get-Date -Format o` | Waktu sistem dalam format ISO 8601 dengan offset | Menyamakan timeline dengan SIEM |
| `Get-TimeZone` | Zona waktu host | Artefak bisa UTC atau lokal; salah zona menggeser timeline |
| `w32tm /query /status` | Sumber dan status sinkronisasi waktu | Clock drift mengacaukan korelasi |

Keluaran ilustrasi: `2026-10-07T16:40:12.3456789+07:00`, `(UTC+07:00) Bangkok, Hanoi, Jakarta`, `Source: time.windows.com`.
**Kapan gagal:** sistem yang dikompromikan bisa memalsukan keluaran. Bandingkan dengan sumber waktu eksternal (jam workstation analyst, log SIEM) dan catat selisihnya.

### 4.2 Hashing arsip koleksi

Windows (PowerShell):

```powershell
Get-FileHash -Path .\WIN-LAB01_triage_20261007.zip -Algorithm SHA256 |
  Format-List Algorithm, Hash, Path
```

Linux (workstation analisis):

```bash
sha256sum WIN-LAB01_triage_20261007.zip | tee WIN-LAB01_triage_20261007.zip.sha256
# verifikasi kemudian:
sha256sum -c WIN-LAB01_triage_20261007.zip.sha256
```

- `Get-FileHash -Algorithm SHA256`: menghitung SHA-256 berkas.
- `tee`: menyimpan hash ke file sambil menampilkannya.
- `sha256sum -c`: membaca file hash lalu memeriksa ulang. Keluaran ilustrasi: `WIN-LAB01_triage_20261007.zip: OK`.

**Cara membaca hasil:** `OK` berarti berkas identik dengan saat hash dicatat. `FAILED` berarti berkas berubah (rusak saat transfer atau dimodifikasi), sehingga salinan itu tidak boleh dianalisis sebagai bukti. Ambil dari master.
**Kapan gagal:** hash dihitung setelah berkas dipindah dari host. Rantai bukti sebelum titik itu tidak terlindungi. Hitung secepat mungkin, idealnya oleh collector itu sendiri.

### 4.3 Templat case notes (fiktif)

```
CASE-2026-LAB-001 | Analyst: <nama> | TZ catatan: UTC+7
2026-10-07 16:38  Terima laporan: alert SIEM rule <id> di WIN-LAB01 (lab). Severity: medium.
2026-10-07 16:40  Konteks waktu host dicatat (4.1). Selisih vs jam analyst: +3 s.
2026-10-07 16:45  Keputusan: triage collection (bukan image). Alasan: lab, scoping awal, satu host.
                  Memori: TIDAK diambil - dicatat sebagai risiko (fileless tidak tercakup).
2026-10-07 16:52  Koleksi selesai: WIN-LAB01_triage_20261007.zip, SHA256 <hash>.
2026-10-07 16:55  Disalin ke storage bukti lab (/evidence/CASE-2026-LAB-001/). Verifikasi hash: OK.
```

### 4.4 Formulir chain of custody (fiktif, minimal)

| Item | Deskripsi | SHA-256 | Dari | Ke | Waktu (UTC+7) | Tujuan |
|---|---|---|---|---|---|---|
| E-001 | Triage ZIP WIN-LAB01 | `ab12...` | Collector di WIN-LAB01 | Analyst A (USB terenkripsi) | 2026-10-07 16:52 | Preservasi |
| E-001 | idem | `ab12...` (verifikasi OK) | Analyst A | Storage bukti lab | 2026-10-07 16:55 | Penyimpanan master |
| E-001-W | Salinan kerja | `ab12...` | Storage bukti | Workstation analisis | 2026-10-07 17:10 | Analisis |

**Kenapa ada salinan kerja:** analisis dilakukan pada salinan, sehingga master tetap utuh dan bisa diverifikasi ulang.

### 4.5 Matriks keputusan (ringkas)

```
Apakah ada kemungkinan proses hukum/HR/asuransi?  -> ya: libatkan legal; condong ke image + CoC ketat
Berapa host?  >10 -> hunt/triage luas dulu; persempit
Apakah dicurigai fileless/injeksi?  -> ambil memori SEBELUM apa pun yang berat di disk
Cloud sync/Files On-Demand aktif?   -> jangan buka file placeholder saat live; pertimbangkan sisi cloud [S6]
Butuh file terhapus/unallocated?    -> image
Lainnya                             -> triage/adaptive collection + dokumentasikan yang dilewati
```

## 5. Lab praktik

**Prasyarat:** VM Windows lab + Sysmon (snapshot bersih), workstation analisis (VM Linux), folder `/evidence` dengan izin terbatas.

1. Buat folder kasus `CASE-2026-LAB-001` dan file `case-notes.md` (templat bagian 4.3).
2. Di VM Windows, jalankan bagian 4.1 dan salin keluarannya ke case notes.
3. Buat "bukti" sederhana tanpa alat forensik: kompres `C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx` ke ZIP. Cek file log yang sedang aktif bisa terkunci. Jika gagal, ekspor dulu dengan `wevtutil epl Microsoft-Windows-Sysmon/Operational C:\Temp\sysmon.evtx`. Ini latihan hashing, bukan koleksi forensik yang benar. Day 03 memakai KAPE.
4. Hash ZIP di Windows (bagian 4.2), lalu salin ke VM Linux dan verifikasi dengan `sha256sum -c`. Hasil yang diharapkan: `OK`.
5. Ubah salinannya, misalnya tambahkan beberapa byte ke akhir file dengan `echo x >> copy.zip`, lalu verifikasi ulang. Hasil yang diharapkan: `FAILED`. Catat di case notes bahwa ini uji sengaja.
6. Isi formulir chain of custody (bagian 4.4) untuk tiap perpindahan.
7. Tulis keputusan "apa yang dilewati" (bagian 3.5) untuk kasus lab ini, minimal dua butir.
8. Korelasi: cari di SIEM lab (bila ada) satu event dari host yang sama pada rentang waktu catatan. Pastikan zona waktu cocok, atau catat selisihnya.

**Hasil yang sebaiknya tersimpan:**
- Case notes kronologis dengan zona waktu.
- Hash cocok (OK) pada salinan utuh dan gagal pada salinan yang diubah.
- CoC berisi setiap perpindahan.
- Ada daftar "yang dilewati + risiko".

**Variasi tantangan:** susun urutan koleksi untuk skenario "laptop eksekutif, dicurigai pencurian data, OneDrive Files On-Demand aktif, mungkin berujung ke HR". Jelaskan urutan dan alasannya dengan merujuk RFC 3227 dan temuan cloud gap [S1][S6].

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Hash berbeda antara Windows dan Linux | Berkas berubah saat transfer (mode teks/ASCII, AV memodifikasi, salinan belum selesai) | Transfer biner; cek ukuran byte; hash ulang dari master |
| Timeline host dan SIEM selisih jam-an | Zona waktu atau UTC vs lokal tercampur | Normalisasi ke UTC; catat offset (bagian 4.1) |
| Tidak bisa menyalin `.evtx` aktif | File terkunci oleh layanan Event Log | `wevtutil epl` atau collector forensik (Day 03) |
| Triage tidak menemukan file yang dirujuk artefak | File sudah terhapus atau di luar target | Adaptive collection / `HashOnly` untuk mencatat keberadaan [S4]; pertimbangkan image |
| File di folder sync "ada" tetapi isinya kosong saat analisis | Placeholder Files On-Demand | Lihat bagian 3.2 dan [S6]; ambil dari sisi cloud dengan otorisasi |

## 7. Kesalahan umum dan jebakan

- Menganalisis sebelum mengumpulkan. RFC 3227 menempatkan koleksi lebih dulu [S1]. Menjalankan alat berat di host bisa menghapus bukti volatil.
- Mematikan host "agar aman" sebelum memori diambil. Proses, koneksi, dan kunci enkripsi hilang [S1][S6].
- Hash dihitung terlambat. Lindungi bukti sejak titik koleksi.
- Menganggap triage = lengkap. Triage hanya melihat yang ada di daftar target. Tulis apa yang tidak diambil.
- Lupa zona waktu. Ini kesalahan klasik saat menggabungkan artefak endpoint dengan log SIEM.
- `[komunitas, belum terkonfirmasi]` Praktisi sering menyebut pola "triage live dulu, image belakangan" sebagai default modern [S5]. Ini konsisten dengan Velociraptor [S4], tetapi bertentangan dengan rekomendasi Elcomsoft untuk perangkat dengan cloud sync (image dulu setelah RAM) [S6]. Konflik ini nyata. Pilih berdasarkan konteks kasus, dan dokumentasikan alasanmu.

## 8. Catatan terkini

- NIST SP 800-61r3 (3 Apr 2025) menggantikan r2 (2012) dan menyelaraskan IR dengan CSF 2.0 [S3]. r3 menyusun rekomendasinya mengikuti enam fungsi CSF 2.0 (Govern, Identify, Protect, Detect, Respond, Recover), sehingga empat fase r2 (preparation; detection and analysis; containment, eradication, and recovery; post-incident activity) sebaiknya dibaca sebagai konteks historis. Untuk catatan ini cukup diingat bahwa kegiatan forensik endpoint paling banyak berada di fungsi Detect dan Respond.
- **Velociraptor "Adaptive Collections" (28 Sep 2025):** pergeseran dari daftar target statis ke koleksi yang diputuskan berdasarkan parsing artefak [S4].
- **Elcomsoft "The Cloud Gap" (8 Jan 2026):** Files On-Demand membuat image offline dan triage live sama-sama berisiko kehilangan isi file [S6].
- RFC 3227 (2002) dan SP 800-86 (2006) berusia lebih dari 3 tahun, tetapi masih menjadi rujukan prinsip. Contoh teknisnya (alat, media) sudah usang.

## 9. Cheat sheet

```
POLA      full image (lengkap, lambat) | triage (cepat, terbatas) | adaptive (jalan tengah)
URUTAN    RAM/proses/jaringan -> temp FS -> disk -> log remote (amankan retensi!) -> arsip
PRINSIP   catat bertimestamp | koleksi sebelum analisis | jangan matikan dulu | jangan percaya biner host
HASH      SHA-256 saat koleksi; verifikasi sebelum analisis & tiap transfer; analisis pada SALINAN
          Win: Get-FileHash -Path <f> -Algorithm SHA256   Linux: sha256sum <f> ; sha256sum -c <f>.sha256
WAKTU     Get-Date -Format o | Get-TimeZone | w32tm /query /status  -> normalisasi UTC
CoC       siapa, kapan, di mana, apa (hash), dari->ke, tujuan  (setiap perpindahan)
DILEWATI  boleh, asal DISENGAJA + DICATAT + risikonya ditulis
CLOUD     Files On-Demand: placeholder != isi file; hati-hati membuka saat live
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | RFC 3227: Guidelines for Evidence Collection and Archiving (BCP 55) | https://datatracker.ietf.org/doc/html/rfc3227 | primer | 2002-02 (>3 tahun); diakses 2026-10-07 | Tinggi untuk prinsip; contoh alat usang |
| S2 | NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response | https://csrc.nist.gov/pubs/sp/800/86/final | primer | 2006-09 (>3 tahun); diakses 2026-10-07 | Tinggi untuk kerangka empat tahap proses forensik |
| S3 | NIST SP 800-61 Rev. 3 (halaman publikasi) | https://csrc.nist.gov/pubs/sp/800/61/r3/final | primer | 2025-04; diakses 2026-10-07 | Tinggi untuk posisi IR dalam CSF 2.0; rincian pemetaan fase ada di dokumen penuh |
| S4 | Velociraptor: Adaptive Collections with Velociraptor | https://docs.velociraptor.app/blog/2025/2025-09-28-adaptive-collections/ | primer (blog proyek resmi) | 2025-09-28; diakses 2026-10-07 | Tinggi untuk fitur Velociraptor; ada sudut pandang proyek |
| S5 | Cado Security / Forensic Focus: The differences between full disk and triage acquisition | https://www.forensicfocus.com/articles/the-differences-between-full-disk-and-triage-acquisition/ | sekunder | diakses 2026-10-07; situs bisa menolak akses otomatis | Sedang. Dipakai hanya untuk pola umum hunt, triage, lalu image |
| S6 | Elcomsoft: The Cloud Gap: Forensic Triage vs. Disk Imaging in the Age of On-Demand Sync | https://blog.elcomsoft.com/2026/01/the-cloud-gap-forensic-triage-vs-disk-imaging-in-the-age-of-on-demand-sync/ | sekunder (vendor forensik) | 2026-01-08; diakses 2026-10-07 | Sedang-tinggi; vendor punya kepentingan produk |
| S7 | Cado Security wiki: Chain of custody, a digital forensics case study | https://cadosecurity.com/wiki/chain-of-custody-a-digital-forensics-case-study | sekunder | diakses 2026-10-07 | Rendah-sedang. Dipakai hanya untuk alasan kenapa CoC tetap perlu di kasus korporat |

**Catatan sumber:** klaim pola "hunt atau triage luas dulu, image belakangan" [S5] dan alasan bisnis chain of custody [S7] berasal dari sumber sekunder; perlakukan sebagai praktik umum, bukan standar. Pemetaan rinci rekomendasi SP 800-61r3 ke enam fungsi CSF 2.0 dan isi lengkap SP 800-86 sebaiknya dicocokkan dengan dokumen penuhnya bila dibutuhkan untuk laporan formal. Nama artefak dan opsi Velociraptor [S4] dapat berubah antar versi.
