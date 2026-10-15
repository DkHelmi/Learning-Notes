---
day: 21
title: 'Otomasi kecil untuk IR: PowerShell dan Python yang aman, tercatat, dan bisa diulang'
researched_on: 2026-10-15
versions_checked: 'PowerShell 7.6 (Get-WinEvent ms.date 2026-08-12; Creating Get-WinEvent queries with FilterHashtable ms.date 2023-06-28; Making the second hop in PowerShell Remoting ms.date 2025-12-09; JEA overview ms.date 2022-11-16; Everything you wanted to know about ShouldProcess ms.date 2024-09-24); Microsoft Graph PowerShell v1.0 Get-MgAuditLogSignIn (ms.date 2026-09-22); Microsoft Entra ID Revoke user access in an emergency (ms.date 2026-06-19); Exchange Online Search-UnifiedAuditLog (halaman diperbarui 2026-06-01); Python 3 hashlib (file_digest sejak 3.11) dan zoneinfo (sejak 3.9); Splunk Enterprise 10.0 REST API tutorial dan reference; RFC 3227; NIST SP 800-61 Rev. 3 (April 2025)'
---

# Day 21: Otomasi kecil untuk IR dengan PowerShell dan Python (aman, tercatat, dan bisa diulang)

Cakupan: memilih langkah IR yang layak diotomasi, menulis skrip kecil PowerShell dan Python untuk koleksi event Windows, pemeriksaan dan pencabutan sesi banyak akun, hash dan manifest bukti, timeline lintas zona waktu, dan pengecekan indikator ke daftar lokal dan Splunk, serta pagar pengaman yang membuat skrip itu sendiri tidak menjadi insiden berikutnya.

## Ide inti

Otomasi di IR bukan soal membuat semuanya cepat, tetapi soal membuat langkah yang sudah terbukti benar bisa diulang dengan hasil yang sama, oleh siapa pun, pada jam berapa pun. Langkah yang hanya membaca (menarik log, meringkas sign-in, menghitung hash, menggabungkan timeline) layak diotomasi penuh karena salahnya mudah dilihat dan tidak merusak apa pun. Langkah yang mengubah sesuatu (mencabut sesi, menonaktifkan akun, mengisolasi host) boleh diotomasi hanya dengan pagar: mode uji coba, konfirmasi, batas jumlah target, dan catatan setiap aksi. Keputusan (severity, kapan containment, apa yang dilaporkan) tetap di tangan manusia. Skrip yang baik juga dijalankan dari tempat yang tepat, tidak menyimpan rahasia, dan disimpan di repositori ber-versi, karena skrip IR yang ceroboh bisa membocorkan kredensial yang sama yang sedang kamu lindungi.

Kamu sudah mengenal pola ini dari NOC. Engineer yang menulis skrip untuk mengubah konfigurasi 200 OLT tahu dua hal. Pertama, skrip yang baik selalu punya mode pembanding (`compare` atau `commit check`) sebelum benar-benar mengubah, dijalankan dari server manajemen, dan mencatat setiap perubahan di TACACS accounting. Kedua, skrip yang buruk mengulang satu kesalahan ke 200 perangkat dalam 30 detik, jauh lebih cepat daripada engineer mana pun bisa membatalkannya. IR memakai pola yang sama dengan satu tambahan: sebagian host yang kamu sentuh mungkin sedang dikuasai penyerang, sehingga cara skrip masuk ke host itu sama pentingnya dengan apa yang dikerjakan skripnya.

```
langkah manual yang berulang di insiden ke-2, ke-3
  |
  v
jenis langkah?
  +-- BACA      koleksi, ringkasan, hash, timeline   -> otomasi penuh, hasil diverifikasi
  +-- UBAH      revoke, disable, isolasi             -> -WhatIf dulu, konfirmasi, batas jumlah
  +-- PUTUSKAN  severity, containment, pelaporan     -> tetap manusia
  |
  v
jalan dari JKT-JUMP01 / jkt-bastion01, akun admin terpisah, rahasia diminta saat jalan
  |
  v
setiap aksi tercatat ke case notes + skrip di repositori ber-versi dan di-review
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif yang menangani insiden dengan CSIRT virtual: SOC lead Dimas Prasetyo sebagai incident commander (IC), analyst L2 Sari Kusuma, Yoga Pratama, dan Rudi Hartanto. Sejak Oktober 2026 PT JAB menangani beberapa insiden: kompromi server billing lewat lampiran email (`INC-2026-019`), phishing kredensial ke 34 mailbox (`INC-2026-020`), pencurian sesi akun Entra ID (`INC-2026-022`), dan installer palsu yang dibongkar lewat EDR (`INC-2026-026`). Jumat 18 Desember 2026 pukul 09:00, sehari setelah tabletop `TTX-2026-01`, Dimas menulis ke Sari dan Yoga:

> "Sar, Yog, saya baca ulang case notes tiga bulan terakhir. Langkah yang sama kita kerjakan manual berulang kali: menarik event logon dari beberapa laptop, mengecek sign-in puluhan penerima phishing satu per satu, menghitung ulang hash bukti sebelum diserahkan ke retainer, dan menyusun timeline dari EDR, Splunk, dan M365 yang jamnya beda-beda. Saya mau ini jadi skrip sebelum akhir bulan. Tapi saya tidak mau ada `export-tagihan.ps1` kedua, dan saya tidak mau satu salah ketik mencabut sesi seribu orang. Mana yang boleh diotomasi dan mana yang tidak? Kalau kita menarik log dari laptop yang mungkin sudah dibobol, kredensial kita aman? Bagaimana memeriksa dan mencabut sesi banyak akun tanpa salah sasaran? Hash dan timeline dari skrip bisa dipercaya untuk laporan? Indikator dari laporan luar boleh dicek ke mana saja? Dan bagaimana kita tahu skrip itu sendiri tidak jadi masalah baru?"

Pesan itu memuat tujuh pertanyaan:

1. Langkah mana yang boleh diotomasi, dan mana yang tidak?
2. Bagaimana menarik log dari host yang mungkin dibobol tanpa membocorkan kredensial?
3. Bagaimana memeriksa dan mencabut sesi banyak akun tanpa salah sasaran?
4. Bagaimana membuat hash bukti yang bisa dipertanggungjawabkan?
5. Bagaimana menggabungkan timeline dari sumber yang zona waktunya berbeda?
6. Bagaimana mengecek indikator dari luar tanpa membocorkan data, termasuk ke Splunk?
7. Bagaimana memastikan skrip itu sendiri tidak menjadi masalah baru?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, pertanyaan 6 di bagian 1.6, dan pertanyaan 7 di bagian 1.7. Bagian 2 berisi enam skrip yang disusun Sari dan Yoga, masing-masing dengan cara membaca hasil dan batasnya.

**Kapan relevan:** saat langkah yang sama sudah dikerjakan manual di dua atau tiga insiden, saat jumlah host atau akun yang harus diperiksa melebihi yang masuk akal dikerjakan dengan tangan, dan saat hasil harus bisa diulang orang lain dengan angka yang sama untuk laporan atau bukti.
**Kapan bukan jawaban:** otomasi tidak menggantikan analisis dan keputusan. Skrip yang mencabut sesi tidak tahu apakah scope sudah cukup (Day 05 bagian 1.3), dan skrip yang meringkas sign-in tidak tahu apakah sebuah IP tethering itu wajar. Day ini juga bukan tutorial SOAR atau pemrograman dari nol; diasumsikan kamu sudah bisa membaca PowerShell dan Python dasar.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (live response, chain of custody, hash, evidence log, revoke sessions, sign-in log, Unified Audit Log, IOC, scoping, case notes) tidak diulang. Tabel berikut memuat istilah baru Day ini. Kolom padanan memakai analogi NOC dan SOC yang sama di semua Day IR.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Idempoten | Skrip yang hasilnya sama walau dijalankan dua kali, sehingga aman diulang setelah gagal di tengah | Skrip push konfigurasi yang tidak menggandakan baris bila dijalankan ulang |
| Dry-run (`-WhatIf`) | Mode yang menampilkan apa yang akan dilakukan tanpa benar-benar mengubah apa pun | `commit check` atau `show compare` sebelum `commit` di router |
| `ShouldProcess` dan `ConfirmImpact` | Mekanisme PowerShell untuk mendukung `-WhatIf` dan `-Confirm` di fungsi buatan sendiri | Prompt "Proceed? [confirm]" sebelum perintah berbahaya di perangkat |
| `FilterHashtable` | Filter `Get-WinEvent` yang dijalankan saat event dibaca, bukan setelah semua event diambil | Filter ACL di perangkat, bukan menyaring di collector setelah semua trafik dikirim |
| JEA (Just Enough Administration) | Endpoint PowerShell yang hanya mengizinkan perintah tertentu, dengan akun virtual dan transkrip | Command authorization TACACS per role |
| CredSSP dan second hop | Cara meneruskan kredensial dari host jarak jauh ke host ketiga; CredSSP menyimpan kredensial di host jarak jauh | Login ke router yang dicurigai disusupi memakai password enable global |
| Manifest hash | Daftar file bukti beserta hash dan statusnya terhadap evidence log, dibuat oleh skrip | Daftar checksum firmware di repositori image |
| Timestamp naif | Waktu tanpa keterangan zona waktu, misalnya `2026-10-13 09:47` | Syslog dari perangkat yang NTP-nya tidak jelas |
| Enrichment lokal | Mencocokkan indikator dengan daftar milik sendiri tanpa mengirimnya ke layanan luar | Mencocokkan IP dengan daftar blackhole internal sebelum bertanya ke forum operator |
| Search job (sid) | Search Splunk yang dibuat lewat REST API dan diberi ID untuk mengambil hasilnya | Job polling NMS yang hasilnya diambil setelah selesai |
| Log aksi skrip | Catatan setiap aksi yang dilakukan skrip: siapa, kapan, target, hasil | TACACS accounting untuk perintah yang dijalankan skrip |

### 1.1 Mana yang boleh diotomasi

Pertanyaan pertama Dimas adalah pertanyaan desain, dan jawabannya bergantung pada jenis langkah, bukan pada seberapa sering langkah itu muncul.

NIST SP 800-61 Rev. 3 menyarankan sebagian containment diotomatiskan, misalnya karantina malware atau memindahkan endpoint ke jaringan remediasi, tetapi tetap memberi handler kemampuan memilih dan menjalankan containment secara manual [S14]. Dari prinsip itu, PT JAB membagi langkah IR menjadi tiga kelas:

| Kelas | Contoh di insiden PT JAB | Boleh diotomasi? | Syarat |
|---|---|---|---|
| Baca | Menarik event logon, meringkas sign-in penerima phishing, menghitung hash, menggabungkan timeline | Ya, penuh | Hasil diverifikasi manual sekali untuk insiden yang jawabannya sudah diketahui |
| Ubah | Revoke sessions, disable akun, isolasi host, blok IOC | Ya, dengan pagar | `-WhatIf` dulu, konfirmasi, batas jumlah target, log setiap aksi, dijalankan atas perintah IC |
| Putuskan | Severity, kapan jam H, apakah data pribadi terdampak, apa yang dilaporkan | Tidak | Skrip menyiapkan data; manusia memutuskan |

Ada juga situasi ketika otomasi lebih buruk daripada kerja manual:

- **Langkah yang baru dikerjakan sekali.** Skrip untuk kasus yang belum dipahami hanya memindahkan kebingungan ke kode.
- **Langkah yang butuh penilaian di setiap baris**, seperti memutuskan apakah sign-in dari ASN seluler itu tethering yang sah (Day 10 bagian 2.7). Skrip bisa menandai, tetapi penandaan itu tetap harus dibaca orang.
- **Aksi ubah dengan target dari input yang belum diperiksa.** Salah satu kolom kosong di CSV bisa membuat filter mencakup semua pengguna.
- **Saat API atau format log sering berubah**, sehingga skrip diam-diam mengembalikan hasil kosong yang terlihat seperti "tidak ada temuan".

### 1.2 Menarik log dari host yang mungkin dibobol

Pertanyaan kedua Dimas menyentuh risiko yang khas IR: host tempat skrip dijalankan dari jarak jauh mungkin sudah dikuasai penyerang.

**Ambil secukupnya, di sumbernya.** `Get-WinEvent` dengan parameter `FilterHashtable` menyaring event saat dibaca. Dokumentasinya menyebut cara ini lebih efisien daripada mengambil semua event lalu menyaring dengan `Where-Object` [S1][S2]. Kunci yang dipakai di catatan ini adalah `LogName`, `ID`, `StartTime`, dan `EndTime`; `ID` menerima array, sehingga satu filter bisa mencakup 4624, 4625, 4688, dan 4698 sekaligus [S2]. Event 4688 hanya muncul bila audit process creation aktif di host itu.

**Pilih jalur koneksi yang tidak meninggalkan kredensial.** Ada dua cara umum menarik event dari host lain:

- `Get-WinEvent -ComputerName` memakai layanan event log jarak jauh, tidak bergantung pada PowerShell remoting, dan butuh port firewall untuk layanan itu; parameternya hanya menerima satu komputer per panggilan [S1].
- `Invoke-Command` lewat WinRM menjalankan perintah di host tujuan dan mengembalikan objek hasilnya.

Yang harus dihindari adalah CredSSP. Dokumentasi PowerShell menyebut CredSSP menyimpan kredensial di server jarak jauh, sehingga bila server itu terkompromi, penyerang mendapat kredensial pengguna; CredSSP mati secara default dan hanya disarankan di lingkungan yang sangat tepercaya [S3]. Host dalam scope insiden adalah kebalikan dari lingkungan tepercaya. Kebutuhan "second hop" (dari host tujuan ke host ketiga, misalnya menyalin hasil ke file share) diselesaikan dengan membawa hasil kembali ke jump host, bukan dengan meneruskan kredensial.

**Batasi apa yang bisa dilakukan akun skrip.** JEA membuat endpoint PowerShell yang hanya mengizinkan cmdlet, fungsi, dan perintah tertentu, bisa memakai akun virtual sehingga pengguna tidak perlu menjadi admin, dan mencatat transkrip perintah yang dijalankan [S4]. Untuk triage, endpoint JEA yang hanya mengizinkan fungsi pembaca event jauh lebih aman daripada akun admin lokal penuh. Dokumentasi second hop juga menyebut JEA sebagai pilihan dengan keamanan terbaik walau butuh konfigurasi lebih rinci [S3].

Di PT JAB, aturannya: skrip koleksi dijalankan dari `JKT-JUMP01` dengan akun `adm.<nama>` yang tidak pernah login interaktif ke host dalam scope, tanpa CredSSP, dan hasilnya disimpan di jump host lalu dipindah ke `jkt-evid01` dengan prosedur bukti. Untuk host dengan EDR, live response Defender tetap menjadi pilihan pertama karena tidak memakai kredensial domain sama sekali (Day 04 bagian 1.3).

### 1.3 Banyak akun sekaligus: membaca dulu, mengubah dengan pagar

Pertanyaan ketiga Dimas punya dua bagian: memeriksa banyak akun, dan mencabut sesi banyak akun.

**Membaca sign-in lewat Graph.** `Get-MgAuditLogSignIn` membaca sign-in log Entra ID, mendukung `-Filter` dan `-All` untuk mengambil semua halaman, dan butuh izin `AuditLog.Read.All` [S6]. Dua batas harus diingat. Pertama, deskripsi cmdlet versi v1.0 menyebut yang tersedia adalah sign-in yang bersifat interaktif dan sign-in federasi yang sukses [S6], sehingga sign-in non-interaktif (pemakaian refresh token, yang penting untuk pencurian token di Day 10 bagian 1.2) tidak ikut. Kedua, Entra ID P1 milik PT JAB menyimpan sign-in log 30 hari (Day 10 bagian 1.2). Pertanyaan tentang kejadian yang lebih tua dijawab dari salinan log di Splunk, bukan dari Graph.

**Membaca audit M365 lewat Exchange Online.** `Search-UnifiedAuditLog` secara default hanya mengembalikan 100 record; `-ResultSize` maksimal 5.000; `-SessionCommand ReturnLargeSet` dengan `-SessionId` yang sama memungkinkan sampai 50.000 hasil tetapi tidak diurutkan; dan nilai `SessionCommand` tidak boleh diganti di tengah satu `SessionId`, karena hasilnya lalu dibatasi 10.000 [S8]. Waktu di unified audit log disimpan dalam UTC, dan tanggal tanpa zona waktu di parameter `-StartDate` dan `-EndDate` dianggap UTC [S8]. Untuk mengunduh audit log secara terprogram dan rutin, Microsoft menyarankan Management Activity API, bukan cmdlet ini di dalam skrip [S8]. Untuk insiden, cmdlet ini tetap praktis selama batasnya diketahui.

**Mencabut sesi dengan pagar.** `Revoke-MgUserSignInSession` mencabut refresh token pengguna di Entra ID (Day 05 bagian 1.5) [S7]. Masalahnya bukan perintahnya, tetapi targetnya. PowerShell menyediakan `SupportsShouldProcess` di `CmdletBinding` dan `$PSCmdlet.ShouldProcess()` di sekitar aksi yang mengubah sesuatu; dengan itu fungsi otomatis mendukung `-WhatIf` (menampilkan apa yang akan dilakukan lalu tidak melakukannya) dan `-Confirm` (meminta persetujuan per target) [S5]. `ConfirmImpact = 'High'` membuat fungsi selalu meminta konfirmasi karena nilai bawaan `$ConfirmPreference` adalah `High` [S5]. Satu jebakan penting: nilai `-WhatIf` dan `-Confirm` tidak diteruskan dari satu script module ke fungsi di script module lain, sehingga `ShouldProcess` sebaiknya diletakkan langsung di sekitar perintah yang mengubah, dan nilai `-WhatIf` diteruskan secara eksplisit bila memanggil fungsi lain [S5].

Pagar yang dipakai PT JAB untuk semua skrip "ubah":

1. `-WhatIf` dijalankan dulu, keluarannya ditempel ke kanal insiden, dan IC menyetujui daftar target.
2. Batas jumlah target (`-MaxUsers`, default 10). Lebih dari itu butuh parameter eksplisit, supaya CSV yang salah tidak mencakup seluruh perusahaan.
3. Target diambil dari file yang di-review, bukan dari hasil query yang langsung dialirkan ke aksi.
4. Setiap aksi, termasuk yang dilewati, dicatat ke log aksi skrip di folder insiden.

### 1.4 Hash dan manifest bukti yang bisa dipertanggungjawabkan

Pertanyaan keempat Dimas menyambung ke Day 04 bagian 1.6: hash membuktikan isi file tidak berubah sejak di-hash, bukan bahwa cara pengambilannya benar.

RFC 3227 meminta prosedur pengambilan bukti yang transparan dan bisa diulang, dengan checksum dibuat bila memungkinkan [S13]. Skrip membantu di bagian "bisa diulang": hash dihitung dengan algoritma dan cara yang sama setiap kali, dan hasilnya dicocokkan otomatis dengan hash yang dicatat saat akuisisi. Python menyediakan `hashlib.file_digest()` sejak versi 3.11, yang menerima objek file yang dibuka dalam mode biner dan nama algoritma seperti `"sha256"`, lalu mengembalikan objek hash; pemanggil tetap bertanggung jawab menutup file-nya [S9].

Manifest yang berguna tidak hanya berisi hash, tetapi status setiap file terhadap evidence log:

- **COCOK:** hash sama dengan yang dicatat.
- **BERBEDA:** hash berbeda. File berubah, atau evidence log salah catat; keduanya harus dijelaskan sebelum bukti dipakai.
- **TIDAK_ADA_DI_LOG:** ada file di folder bukti yang tidak tercatat. Bisa catatan kerja yang salah simpan, bisa juga sesuatu yang tidak semestinya ada di sana.
- **HILANG:** tercatat di evidence log tetapi tidak ada di folder.

Dua aturan teknis menjaga manifest tetap bersih: file manifest ditulis di luar folder yang di-hash (kalau tidak, manifest ikut menghitung dirinya sendiri), dan skrip dijalankan di `jkt-evid01` terhadap salinan kerja, sesuai prinsip bekerja dari salinan di Day 04 bagian 2.5.

### 1.5 Timeline dari sumber dengan jam berbeda

Pertanyaan kelima Dimas adalah sumber kesalahan paling sering dalam laporan insiden: urutan kejadian yang salah karena jam dari sumber berbeda dicampur begitu saja.

Di insiden PT JAB, setiap sumber punya kebiasaan sendiri. Unified audit log dan message trace M365 memakai UTC [S8]; timeline EDR ditampilkan dalam UTC (case notes Day 03 bagian 2.5 menulis konvensi ini di baris pertama); Splunk menampilkan waktu sesuai zona waktu pengguna, di PT JAB WIB; dan case notes ditulis dalam WIB tanpa keterangan zona. Kalau semua kolom waktu dibaca sebagai "jam", alert pukul 09:47 WIB dan event EDR pukul 09:05 UTC terlihat berdekatan, padahal selisihnya hampir 18 jam.

Aturan yang dipakai skrip timeline PT JAB:

1. **Simpan dalam UTC, tampilkan dalam WIB.** Semua waktu diubah ke UTC dengan offset eksplisit untuk diurutkan; kolom WIB ditambahkan hanya untuk dibaca.
2. **Timestamp naif tidak pernah ditebak.** Setiap sumber yang waktunya tanpa zona harus diberi label zona secara eksplisit di konfigurasi skrip. Bila label tidak ada, skrip berhenti dengan error, bukan memakai asumsi.
3. **Pakai nama zona IANA, bukan offset tetap.** Modul `zoneinfo` di Python (sejak 3.9) memakai database zona IANA, misalnya `Asia/Jakarta`. Di Windows, database itu sering tidak ada di sistem, sehingga dokumentasi Python menyarankan paket `tzdata`; tanpa keduanya, `ZoneInfo` gagal dengan error [S10]. WIB tidak memakai daylight saving, tetapi data dari mitra di luar negeri bisa memakainya, dan offset tetap akan salah di setengah tahun.

### 1.6 Indikator dari luar: dicek di dalam dulu

Pertanyaan keenam Dimas punya jawaban yang sudah muncul di Day 08 bagian 1.5: layanan pemindai publik bisa membocorkan apa yang kamu kirim ke sana, termasuk URL yang memuat identitas penerima. Untuk indikator dari laporan luar, urutannya dibalik: dicocokkan dulu dengan daftar milik sendiri dan log sendiri, baru dikirim ke layanan luar bila memang perlu dan diizinkan.

**Daftar lokal.** PT JAB menyimpan indikator dari setiap insiden di `ioc_jab.csv` (nilai, jenis, nomor insiden, tanggal). Skrip enrichment melakukan dua hal yang sering dilupakan saat dicocokkan manual: membersihkan bentuk "defanged" seperti `hxxps` dan `[.]`, dan menyamakan huruf besar kecil dan titik di akhir nama domain.

**Log sendiri lewat Splunk REST API.** Search dibuat dengan `POST` ke endpoint `search/jobs`, yang mengembalikan search ID (sid) untuk mengambil hasil; hasilnya diambil dari endpoint `results` dengan `output_mode` CSV, JSON, atau XML (default XML) [S11]. Tutorial Splunk mengingatkan bahwa search lewat REST API secara default berjalan atas seluruh rentang waktu, sehingga `earliest_time` dan `latest_time` sebaiknya selalu diisi [S11]. Referensi REST API Splunk 10.0 mendokumentasikan endpoint hasil versi `v2` (`search/v2/jobs/{search_id}/results`) dan menyebut versi lamanya sudah deprecated [S12]; cek path yang berlaku di versi Splunk-mu.

Satu risiko khas: indikator dari luar adalah input yang tidak tepercaya. Bila nilainya langsung ditempel ke string search, tanda kutip atau pipe di dalamnya bisa mengubah search. Skrip PT JAB hanya menerima indikator yang lolos pola ketat (nama domain atau alamat IPv4) dan menolak sisanya.

### 1.7 Skrip yang tidak menjadi masalah baru

Pertanyaan terakhir Dimas merujuk pada akar masalah `INC-2026-019`: password `svc_billing` tersimpan di skrip `export-tagihan.ps1` di laptop staf, dibaca penyerang, dan dipakai masuk ke server billing (Day 06 bagian 1.3). Skrip IR membawa risiko yang sama, bahkan lebih besar, karena biasanya dijalankan dengan hak tinggi.

Aturan PT JAB untuk skrip IR, disusun dari pelajaran insiden dan sumber di atas:

1. **Tidak ada rahasia di skrip atau di file konfigurasi di sebelahnya.** Kredensial diminta saat dijalankan (`Get-Credential`, `getpass`), atau diambil dari autentikasi interaktif seperti `Connect-MgGraph`.
2. **Dijalankan dari tempat yang tepat.** `JKT-JUMP01` untuk Windows dan M365, `jkt-bastion01` untuk Linux, `jkt-evid01` untuk bukti. Tidak pernah dari laptop analyst atau host dalam scope.
3. **Idempoten.** Menjalankan ulang setelah gagal di tengah tidak menggandakan aksi atau merusak hasil sebelumnya; folder output yang sudah ada dipakai ulang, revoke yang sudah dijalankan aman dijalankan lagi.
4. **Setiap aksi tercatat.** Log aksi skrip berisi waktu UTC, operator, nama dan versi skrip, target, aksi, dan hasil, disimpan di folder insiden dan dirujuk dari case notes.
5. **Repositori ber-versi dengan review.** Skrip disimpan di repositori `jab-ir-tools` di GitLab internal; perubahan di-review satu orang lain, dan versi yang dipakai di insiden dicatat di log aksi.
6. **Diuji dengan insiden yang jawabannya sudah diketahui.** Skrip ringkasan sign-in dicoba terhadap data yang hasilnya sudah ada di case notes sebelum dipercaya untuk insiden baru.

Skrip kecil seperti ini juga menjadi bahan SOAR. Lab pemilik catatan ini memakai Shuffle dan TheHive; skrip yang sudah idempoten, punya parameter jelas, dan mengembalikan kode keluar yang bisa dibaca mesin bisa dipanggil dari workflow SOAR tanpa diubah. Yang tidak berubah di SOAR adalah aturan bagian 1.1: aksi "ubah" tetap butuh langkah persetujuan manusia di workflow.

## 2. Contoh artefak dan langkah praktis di PT JAB

Semua skrip di bagian ini adalah contoh untuk dibaca dan diuji di lab; semua keluarannya adalah keluaran ilustrasi. Skrip PowerShell ditulis untuk PowerShell 7 dan dijalankan dari `JKT-JUMP01`; skrip Python untuk Python 3.11 atau lebih baru, dijalankan di `jkt-evid01` atau `jkt-bastion01`. Semua skrip disimpan di repositori `jab-ir-tools` dan menulis log aksi ke folder insiden.

### 2.1 Triage event Windows dari beberapa host

Skrip ini menjawab pertanyaan kedua Dimas untuk host tanpa live response EDR atau saat perlu event yang sama dari banyak host sekaligus.

**Tujuan:** menarik event logon (4624, 4625), pembuatan proses (4688), scheduled task baru (4698), dan service baru (7045) dari beberapa host dalam rentang waktu tertentu, menyimpan hasilnya sebagai CSV di folder insiden, dan mencatat host yang gagal dihubungi.

```powershell
<#
  Get-JabTriageEvent.ps1  (jab-ir-tools v1.0.0)
  Dijalankan dari JKT-JUMP01 dengan akun adm.<nama>. Tanpa CredSSP.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string[]] $ComputerName,
    [Parameter(Mandatory)] [datetime] $Start,
    [datetime] $End = (Get-Date),
    [Parameter(Mandatory)] [ValidatePattern('^(INC|LAB)-\d{4}-\d{3}$')] [string] $CaseId,
    [string] $ConfigurationName = 'Microsoft.PowerShell'
)

$out = Join-Path 'D:\IR' $CaseId
New-Item -ItemType Directory -Path $out -Force | Out-Null   # idempoten: folder lama dipakai ulang
$cred = Get-Credential -Message 'Akun adm.<nama> untuk triage'

$filters = @(
    @{ LogName = 'Security'; ID = 4624, 4625, 4688, 4698; StartTime = $Start; EndTime = $End },
    @{ LogName = 'System';   ID = 7045;                   StartTime = $Start; EndTime = $End }
)
$ambil = {
    param($Filters)
    foreach ($f in $Filters) {
        Get-WinEvent -FilterHashtable $f -ErrorAction SilentlyContinue |
            Select-Object TimeCreated, Id, LogName, RecordId,
                @{ n = 'Ringkasan'; e = { ($_.Message -split "`r?`n")[0] } }
    }
}

$hasil = [System.Collections.Generic.List[object]]::new()
$gagal = [System.Collections.Generic.List[string]]::new()
foreach ($c in $ComputerName) {
    try {
        $ev = Invoke-Command -ComputerName $c -Credential $cred -ConfigurationName $ConfigurationName `
                -ScriptBlock $ambil -ArgumentList (, $filters) -ErrorAction Stop
        foreach ($e in $ev) { $hasil.Add($e) }
    } catch {
        $gagal.Add("$c ($($_.Exception.Message -split "`r?`n" | Select-Object -First 1))")
    }
}

$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$hasil | Select-Object PSComputerName, TimeCreated, Id, LogName, RecordId, Ringkasan |
    Export-Csv (Join-Path $out "triage-events-$stamp.csv") -NoTypeInformation -Encoding utf8

[pscustomobject]@{
    WaktuUtc = (Get-Date).ToUniversalTime().ToString('o'); Operator = $env:USERNAME
    Skrip    = 'Get-JabTriageEvent.ps1 v1.0.0'; Aksi = 'baca-event'
    Target   = $ComputerName -join ';'
    Hasil    = "$($hasil.Count) event; gagal: $($gagal -join '; ')"
} | Export-Csv (Join-Path $out 'aksi-skrip.csv') -Append -NoTypeInformation -Encoding utf8

$hasil | Group-Object PSComputerName, Id -NoElement | Sort-Object Name | Format-Table Count, Name
if ($gagal.Count) { Write-Warning ("Gagal: " + ($gagal -join '; ')) }
```

Penjelasan tiap bagian:

- `ValidatePattern` di `CaseId` mencegah folder output salah nama, misalnya karena salah ketik nomor insiden.
- `New-Item -Force` membuat folder bila belum ada dan tidak gagal bila sudah ada, sehingga skrip aman dijalankan ulang.
- `Get-Credential` meminta kredensial saat dijalankan; tidak ada password di skrip atau di file di sebelahnya.
- `$filters` berisi dua hash table karena 7045 ada di log System, bukan Security. `ID` menerima array, sehingga empat event Security diambil dengan satu filter [S2]. Filter ini dijalankan di host tujuan saat event dibaca, sehingga hanya event yang cocok yang dikirim kembali [S1].
- `Invoke-Command` dijalankan per host di dalam `try`, sehingga satu host yang mati tidak menghentikan host lain, dan nama host yang gagal tercatat jelas. Hasil dari `Invoke-Command` membawa properti `PSComputerName`, yang dipakai untuk mengelompokkan.
- Kolom `Ringkasan` hanya mengambil baris pertama pesan event supaya CSV tetap terbaca; event lengkap tetap ada di host dan bisa diambil ulang lewat `RecordId`.
- Baris `aksi-skrip.csv` adalah log aksi skrip (bagian 1.7).

Keluaran ilustrasi, uji coba Jumat 18 Desember pada tiga laptop yang dulu terdampak `INC-2026-019`, rentang 48 jam:

```
Count Name
----- ----
  186 JKT-WS-0388, 4624
    2 JKT-WS-0388, 4625
 1544 JKT-WS-0388, 4688
    1 JKT-WS-0388, 7045
  143 JKT-WS-0412, 4624
 1210 JKT-WS-0412, 4688

WARNING: Gagal: BDG-WS-0142 (WinRM cannot complete the operation...)
```

Cara membaca hasil:

- Total 3.086 event dari dua host (186 + 2 + 1.544 + 1 + 143 + 1.210). Angka ini juga yang ditulis di kolom `Hasil` log aksi.
- Tidak ada baris 4698, artinya tidak ada scheduled task baru di rentang itu. `Group-Object` tidak menampilkan kombinasi yang jumlahnya nol, jadi "tidak muncul" berarti nol untuk host yang berhasil dihubungi, bukan untuk host yang gagal.
- Satu 7045 di `JKT-WS-0388` dicocokkan dengan change request (pembaruan agen backup), lalu dicatat sebagai sudah dijelaskan.
- `JKT-WS-0412` tidak punya 4625. Itu wajar, tetapi juga perlu dicek bahwa audit logon gagal memang aktif di host itu sebelum disimpulkan.
- `BDG-WS-0142` gagal dihubungi karena laptop sedang dibawa ke lokasi POP. Host itu tercatat sebagai belum diperiksa, bukan sebagai bersih.

**Variasi:** di host yang sudah punya endpoint JEA, ganti `-ConfigurationName` dengan nama endpoint itu (misalnya `JAB.IRTriage`) yang hanya mengizinkan fungsi pembaca event; akun analyst tidak perlu admin lokal [S4]. Untuk host dengan EDR, ambil data yang sama lewat live response atau advanced hunting (Day 04 bagian 1.3), tanpa kredensial domain.

**Kapan gagal:** audit 4688 tidak aktif sehingga kolomnya selalu kosong; log Security di host sudah berputar sehingga rentang awal tidak ada lagi; atau skrip dijalankan dengan CredSSP "supaya bisa menyimpan langsung ke share", yang meninggalkan kredensial di host yang mungkin dikuasai penyerang [S3].

### 2.2 Ringkasan sign-in banyak akun lewat Graph

Skrip ini menjawab bagian pertama pertanyaan ketiga Dimas: memeriksa sign-in puluhan akun tanpa membuka portal satu per satu.

**Tujuan:** untuk setiap UPN di daftar, menghitung sign-in interaktif sejak waktu tertentu, memisahkan yang berasal dari luar IP kantor, dan menghitung sukses dan gagal dari luar.

```powershell
<#
  Get-JabSignInSummary.ps1  (jab-ir-tools v1.1.0)
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]   $UserListCsv,     # satu kolom: upn
    [Parameter(Mandatory)] [datetime] $SinceUtc,
    [Parameter(Mandatory)] [ValidatePattern('^(INC|LAB)-\d{4}-\d{3}$')] [string] $CaseId,
    [string[]] $KantorIp = @('198.51.100.120')
)

if ($SinceUtc -lt (Get-Date).ToUniversalTime().AddDays(-30)) {
    Write-Warning 'Rentang lebih tua dari 30 hari: di luar retensi sign-in log Entra ID P1. Pakai salinan log di Splunk.'
}
Connect-MgGraph -Scopes 'AuditLog.Read.All' -NoWelcome
$since = $SinceUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

$ringkas = foreach ($row in Import-Csv $UserListCsv) {
    $upn = $row.upn.Trim().ToLower()
    if ($upn -notmatch '^[a-z0-9._-]+@jab\.example$') { Write-Warning "Dilewati, UPN tidak valid: $upn"; continue }
    $s    = @(Get-MgAuditLogSignIn -All -Filter "userPrincipalName eq '$upn' and createdDateTime ge $since")
    $luar = @($s | Where-Object { $_.IpAddress -notin $KantorIp })
    [pscustomobject]@{
        upn         = $upn
        total       = $s.Count
        luar_kantor = $luar.Count
        sukses_luar = @($luar | Where-Object { $_.Status.ErrorCode -eq 0 }).Count
        gagal_luar  = @($luar | Where-Object { $_.Status.ErrorCode -ne 0 }).Count
        ip_luar     = ($luar.IpAddress | Sort-Object -Unique) -join ' '
    }
}
$ringkas | Sort-Object luar_kantor -Descending |
    Export-Csv "D:\IR\$CaseId\signin-ringkas.csv" -NoTypeInformation -Encoding utf8
$ringkas | Sort-Object luar_kantor -Descending | Format-Table
```

Penjelasan tiap bagian:

- Peringatan 30 hari muncul sebelum query dijalankan, karena hasil kosong dari rentang di luar retensi terlihat persis seperti "tidak ada sign-in" (bagian 1.3).
- `Connect-MgGraph -Scopes 'AuditLog.Read.All'` meminta izin baca yang dibutuhkan `Get-MgAuditLogSignIn` [S6] lewat login interaktif; tidak ada secret aplikasi di skrip.
- UPN divalidasi dengan pola sebelum dimasukkan ke filter. Filter Graph adalah string; nilai yang tidak diperiksa bisa merusak filter.
- `-All` mengambil semua halaman hasil [S6]. `@(...)` memastikan hasil selalu berupa array, sehingga `.Count` benar walau hanya ada satu sign-in.
- `KantorIp` adalah IP NAT kantor Jakarta; sign-in dari IP lain dihitung "luar kantor", bukan otomatis mencurigakan.

Keluaran ilustrasi, uji coba terhadap tujuh penerima email `INC-2026-022` untuk 11 sampai 18 Desember:

```
upn                          total luar_kantor sukses_luar gagal_luar ip_luar
---                          ----- ----------- ----------- ---------- -------
fajar.nugraha@jab.example       18           6           6          0 203.0.113.144
rina.wulandari@jab.example      41           0           0          0
(5 baris lain: luar_kantor 0)
```

Cara membaca hasil:

- Fajar Nugraha punya enam sign-in sukses dari `203.0.113.144`, IP operator seluler yang sudah dijelaskan sebagai tethering di lokasi POP (Day 10 bagian 2.7). Skrip menandai; penjelasannya tetap dari manusia dan case notes.
- Uji coba yang sama dengan `-SinceUtc` 28 Oktober memunculkan peringatan retensi dan mengembalikan nol baris untuk Rina, padahal Day 10 mencatat sign-in penyerang dari `198.51.100.152` pada tanggal itu. Uji coba ini sengaja dijalankan untuk membuktikan bahwa nol dari Graph untuk rentang lama tidak berarti apa-apa; pertanyaan itu dijawab dari Splunk (bagian 2.6 dan Day 10 bagian 2.7).

**Variasi:** tambahkan IP NAT kantor Bandung dan POP ke `KantorIp`; tambahkan kolom `dc` dari `CorrelationId` untuk menghitung jumlah sesi. Untuk sign-in non-interaktif, pakai salinan log di Splunk, karena cmdlet versi v1.0 hanya mencakup sign-in interaktif dan federasi yang sukses [S6].

**Kapan gagal:** daftar UPN tidak lengkap (penerima lewat grup distribusi), IP kantor berubah, atau akun yang menjalankan skrip tidak punya role untuk membaca sign-in log.

### 2.3 Mencabut sesi banyak akun dengan pagar

Skrip ini menjawab bagian kedua pertanyaan ketiga Dimas: "tidak mau satu salah ketik mencabut sesi seribu orang".

**Tujuan:** mencabut sesi Entra ID untuk daftar akun yang sudah disetujui IC, dengan dukungan `-WhatIf`, konfirmasi per akun, batas jumlah, dan log setiap aksi.

```powershell
<#
  Revoke-JabSession.ps1  (jab-ir-tools v1.0.2)
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)] [string] $UserListCsv,   # satu kolom: upn, file yang sudah di-review IC
    [Parameter(Mandatory)] [ValidatePattern('^(INC|LAB)-\d{4}-\d{3}$')] [string] $CaseId,
    [ValidateRange(1, 200)] [int] $MaxUsers = 10
)

$targets = @(Import-Csv $UserListCsv | ForEach-Object { $_.upn.Trim().ToLower() } |
             Where-Object { $_ -match '^[a-z0-9._-]+@jab\.example$' } | Sort-Object -Unique)
if ($targets.Count -eq 0)        { throw 'Tidak ada UPN valid di file target.' }
if ($targets.Count -gt $MaxUsers) { throw "Target $($targets.Count) akun melebihi -MaxUsers $MaxUsers. Periksa file target." }

Connect-MgGraph -Scopes 'User.ReadWrite.All', 'Directory.AccessAsUser.All' -NoWelcome
$log = "D:\IR\$CaseId\aksi-skrip.csv"

foreach ($upn in $targets) {
    $hasil = 'dilewati'
    if ($PSCmdlet.ShouldProcess($upn, 'Revoke-MgUserSignInSession')) {
        try {
            $user  = Get-MgUser -UserId $upn -ErrorAction Stop
            $r     = Revoke-MgUserSignInSession -UserId $user.Id -ErrorAction Stop
            $hasil = "ok ($($r.Value))"
        } catch { $hasil = "gagal: $($_.Exception.Message)" }
    } elseif ($WhatIfPreference) { $hasil = 'whatif' }

    [pscustomobject]@{
        WaktuUtc = (Get-Date).ToUniversalTime().ToString('o'); Operator = $env:USERNAME
        Skrip = 'Revoke-JabSession.ps1 v1.0.2'; Aksi = 'revoke-sessions'; Target = $upn; Hasil = $hasil
    } | Export-Csv $log -Append -NoTypeInformation -Encoding utf8
}
```

Penjelasan tiap bagian:

- `SupportsShouldProcess` menambahkan `-WhatIf` dan `-Confirm` ke skrip; `ConfirmImpact = 'High'` membuat skrip selalu meminta konfirmasi per akun kecuali dijalankan dengan `-Confirm:$false` [S5].
- `ShouldProcess` diletakkan tepat di sekitar perintah yang mengubah, di dalam loop, sehingga pesan `-WhatIf` dan konfirmasi muncul untuk setiap akun [S5].
- Daftar target dibersihkan (huruf kecil, unik, pola UPN) lalu diperiksa jumlahnya sebelum login ke Graph. Skrip berhenti sebelum menyentuh apa pun bila jumlahnya di luar batas.
- Izin Graph mengikuti langkah pencabutan akses darurat Microsoft (Day 05 bagian 2.3) [S7].
- Setiap akun menghasilkan satu baris log, termasuk yang dilewati dan yang dijalankan dengan `-WhatIf`, sehingga log menunjukkan apa yang dipertimbangkan, bukan hanya apa yang dikerjakan.
- Mencabut sesi akun yang sesinya sudah dicabut tidak merusak apa pun, jadi skrip aman dijalankan ulang bila terputus di tengah.

Keluaran ilustrasi, latihan di lab dengan tiga akun uji (`LAB-2026-001`):

```
PS> .\Revoke-JabSession.ps1 -UserListCsv .\target.csv -CaseId LAB-2026-001 -WhatIf
What if: Performing the operation "Revoke-MgUserSignInSession" on target "uji.ir01@jab.example".
What if: Performing the operation "Revoke-MgUserSignInSession" on target "uji.ir02@jab.example".
What if: Performing the operation "Revoke-MgUserSignInSession" on target "uji.ir03@jab.example".

PS> .\Revoke-JabSession.ps1 -UserListCsv .\semua-karyawan.csv -CaseId LAB-2026-001
Exception: Target 1187 akun melebihi -MaxUsers 10. Periksa file target.
```

Cara membaca hasil:

- Keluaran `-WhatIf` adalah daftar yang ditempel ke kanal insiden untuk disetujui IC. Tiga baris, tiga akun, sesuai file target.
- Percobaan kedua memakai file yang salah (ekspor semua karyawan). Skrip berhenti di pemeriksaan jumlah, sebelum login ke Graph. Pagar ini yang menjawab kekhawatiran Dimas.

**Variasi:** tambahkan langkah `Disable-ADAccount` dan reset password dua kali untuk akun yang tersinkron, masing-masing dengan `ShouldProcess` sendiri, mengikuti urutan di Day 05 bagian 1.5. Untuk dijalankan dari SOAR, hasil `-WhatIf` menjadi tugas persetujuan dan eksekusi baru berjalan setelah disetujui.

**Kapan gagal:** fungsi ini dibungkus di script module lain yang memanggil modul berbeda; nilai `-WhatIf` tidak diteruskan antar script module, sehingga "uji coba" ternyata mengeksekusi sungguhan [S5]. Selalu uji `-WhatIf` pada bentuk akhir yang akan dipakai, dengan akun uji.

### 2.4 Manifest hash bukti

Skrip ini menjawab pertanyaan keempat Dimas: hash yang dihitung ulang dengan cara yang sama setiap kali, dan langsung dicocokkan dengan evidence log.

**Tujuan:** menghitung SHA-256 semua file di folder bukti satu insiden, membandingkannya dengan hash di evidence log, dan menandai file yang berbeda, tidak tercatat, atau hilang.

```python
#!/usr/bin/env python3
"""buat_manifest.py (jab-ir-tools v1.2.0)
Contoh: python3 buat_manifest.py /evidence/INC-2026-019 /srv/ir/evidence-log/INC-2026-019.csv \
        --out-dir /srv/ir/manifest
Evidence log CSV berkolom: id,file,sha256 (file relatif terhadap folder bukti).
"""
import argparse
import csv
import hashlib
import sys
from datetime import datetime, timezone
from pathlib import Path


def sha256(path: Path) -> str:
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("folder")
    p.add_argument("evidence_log")
    p.add_argument("--out-dir", required=True)
    a = p.parse_args()

    root = Path(a.folder).resolve()
    out_dir = Path(a.out_dir).resolve()
    if out_dir == root or root in out_dir.parents:
        sys.exit("out-dir tidak boleh berada di dalam folder bukti")

    with open(a.evidence_log, newline="", encoding="utf-8") as f:
        tercatat = {r["file"]: r for r in csv.DictReader(f)}

    baris = []
    for path in sorted(x for x in root.rglob("*") if x.is_file()):
        rel = path.relative_to(root).as_posix()
        h = sha256(path)
        log = tercatat.get(rel)
        if log is None:
            status = "TIDAK_ADA_DI_LOG"
        elif log["sha256"].strip().lower() == h:
            status = "COCOK"
        else:
            status = "BERBEDA"
        baris.append({"id": log["id"] if log else "", "file": rel,
                      "bytes": path.stat().st_size, "sha256": h, "status": status})

    ada = {b["file"] for b in baris}
    for rel, log in tercatat.items():
        if rel not in ada:
            baris.append({"id": log["id"], "file": rel, "bytes": "", "sha256": "", "status": "HILANG"})

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{root.name}-manifest-{stamp}.csv"
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["id", "file", "bytes", "sha256", "status"])
        w.writeheader()
        w.writerows(baris)

    hitung = {s: sum(1 for b in baris if b["status"] == s)
              for s in ("COCOK", "BERBEDA", "TIDAK_ADA_DI_LOG", "HILANG")}
    print(f"{len(baris)} baris | " + " | ".join(f"{k} {v}" for k, v in hitung.items()))
    for b in baris:
        if b["status"] != "COCOK":
            print(f"  {b['status']:<17} {b['id'] or '-':<18} {b['file']}")
    print(f"Manifest: {out}")
    return 1 if hitung["BERBEDA"] or hitung["HILANG"] else 0


if __name__ == "__main__":
    sys.exit(main())
```

Penjelasan tiap bagian:

- `hashlib.file_digest(f, "sha256")` menghitung hash dari file yang dibuka dalam mode biner; `with` memastikan file ditutup [S9].
- Pemeriksaan `out_dir` mencegah manifest ditulis ke dalam folder bukti. Manifest yang ikut di-hash akan muncul sebagai `TIDAK_ADA_DI_LOG` di putaran berikutnya dan mengubah isi folder bukti.
- Empat status mengikuti bagian 1.4. `HILANG` dicari dari arah sebaliknya: tercatat di log tetapi tidak ada di folder.
- Nama manifest memuat waktu UTC, sehingga setiap putaran menghasilkan file baru dan manifest lama tidak tertimpa. Skrip bisa dijalankan ulang kapan saja tanpa mengubah folder bukti.
- Kode keluar 1 bila ada `BERBEDA` atau `HILANG`, supaya skrip lain atau workflow SOAR bisa berhenti otomatis. `TIDAK_ADA_DI_LOG` ditampilkan tetapi tidak menghentikan proses, karena perlu dijelaskan manusia.

Keluaran ilustrasi, dijalankan Yoga sebelum salinan bukti `INC-2026-019` diserahkan untuk arsip:

```
19 baris | COCOK 18 | BERBEDA 0 | TIDAK_ADA_DI_LOG 1 | HILANG 0
  TIDAK_ADA_DI_LOG  -                  catatan_yoga.txt
Manifest: /srv/ir/manifest/INC-2026-019-manifest-20261218T041530Z.csv
```

Cara membaca hasil:

- 18 item bukti (`E01` sampai `E18`, beberapa item seperti kumpulan file live response disimpan sebagai satu arsip) cocok dengan hash di evidence log.
- `catatan_yoga.txt` adalah catatan kerja yang tersimpan di folder bukti. File itu dipindah ke folder kerja dan dicatat di case notes, lalu skrip dijalankan ulang sampai bersih. Membiarkannya membuat orang lain bertanya apakah folder bukti pernah diubah.
- Kode keluar 0, karena tidak ada `BERBEDA` atau `HILANG`.

**Variasi:** tambahkan kolom waktu modifikasi file dan bandingkan dengan waktu akuisisi di evidence log; file yang dimodifikasi setelah akuisisi patut dicurigai walau hash-nya dihitung ulang.

**Kapan gagal:** evidence log mencatat hash yang dipotong (misalnya hanya 8 karakter awal seperti di tabel ringkas Day 04 bagian 2.5), sehingga semua baris tampak `BERBEDA`. Evidence log untuk skrip harus berisi hash lengkap. Hash yang cocok juga hanya membuktikan file tidak berubah sejak hash pertama dicatat, bukan bahwa pengambilannya benar (Day 04 bagian 1.6).

### 2.5 Menggabungkan timeline dari beberapa sumber

Skrip ini menjawab pertanyaan kelima Dimas memakai cuplikan timeline `INC-2026-019` yang sudah diketahui jawabannya (Day 03 bagian 2.3), sehingga hasilnya bisa diperiksa.

**Tujuan:** membaca ekspor dari beberapa sumber, mengubah semua waktu ke UTC dengan aturan zona yang eksplisit, lalu menulis satu timeline urut dengan kolom WIB untuk dibaca.

```python
#!/usr/bin/env python3
"""gabung_timeline.py (jab-ir-tools v0.9.1)
Contoh: python3 gabung_timeline.py /srv/ir/INC-2026-019/timeline-input timeline.csv
"""
import csv
import sys
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

WIB = ZoneInfo("Asia/Jakarta")

# nama: (file, kolom waktu, format strptime, zona untuk waktu TANPA offset, kolom deskripsi)
SUMBER = {
    "m365_trace": ("message_trace.csv", "Received", "%m/%d/%Y %I:%M:%S %p", "UTC", "Subject"),
    "edr":        ("edr_timeline.csv", "Timestamp", "%Y-%m-%dT%H:%M:%S%z", None, "Ringkasan"),
    "splunk":     ("splunk_export.csv", "_time", "%Y-%m-%dT%H:%M:%S.%f%z", None, "ringkasan"),
    "case_notes": ("case_notes.csv", "waktu", "%Y-%m-%d %H:%M", "Asia/Jakarta", "catatan"),
}


def ke_utc(teks: str, fmt: str, zona_naif: str | None) -> datetime:
    dt = datetime.strptime(teks.strip(), fmt)
    if dt.tzinfo is None:
        if zona_naif is None:
            raise ValueError(f"waktu tanpa zona dan sumber tidak diberi label zona: {teks!r}")
        dt = dt.replace(tzinfo=ZoneInfo(zona_naif))
    return dt.astimezone(timezone.utc)


def main() -> int:
    folder, keluaran = Path(sys.argv[1]), Path(sys.argv[2])
    baris = []
    for nama, (file, kolom, fmt, zona, desk) in SUMBER.items():
        path = folder / file
        if not path.exists():
            print(f"peringatan: {file} tidak ada, sumber {nama} dilewati", file=sys.stderr)
            continue
        with path.open(newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                utc = ke_utc(r[kolom], fmt, zona)
                baris.append((utc, nama, r[desk]))
    baris.sort(key=lambda x: x[0])
    with keluaran.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["waktu_wib", "waktu_utc", "sumber", "deskripsi"])
        for utc, nama, desk in baris:
            w.writerow([utc.astimezone(WIB).strftime("%Y-%m-%d %H:%M:%S"),
                        utc.strftime("%Y-%m-%dT%H:%M:%SZ"), nama, desk])
    print(f"{len(baris)} baris ditulis ke {keluaran}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

Penjelasan tiap bagian:

- `SUMBER` adalah satu-satunya tempat aturan zona ditulis. Message trace M365 ditulis tanpa offset tetapi dalam UTC [S8], sehingga diberi label `"UTC"`; case notes PT JAB ditulis dalam WIB tanpa offset, sehingga diberi label `"Asia/Jakarta"`; EDR dan ekspor Splunk sudah membawa offset, sehingga labelnya `None`.
- `ke_utc` menolak waktu tanpa offset dari sumber yang labelnya `None`. Lebih baik skrip berhenti daripada menebak zona.
- `ZoneInfo("Asia/Jakarta")` memakai database zona IANA; di Windows, pasang paket `tzdata` bila database sistem tidak ada [S10].
- Semua baris diurutkan berdasarkan UTC, lalu kolom WIB ditambahkan saat ditulis. Urutan tidak pernah dihitung dari kolom WIB.

Keluaran ilustrasi (`timeline.csv`, diringkas):

```
waktu_wib            waktu_utc             sumber      deskripsi
2026-10-12 15:58:14  2026-10-12T08:58:14Z  m365_trace  Tagihan Oktober 2026 (ke andi.pratama@jab.example)
2026-10-12 16:05:31  2026-10-12T09:05:31Z  edr         wscript.exe menjalankan Tagihan-Okt-2026.js (JKT-WS-0388)
2026-10-12 23:40:12  2026-10-12T16:40:12Z  splunk      4104 Get-Content export-tagihan.ps1 (JKT-WS-0388)
2026-10-13 02:14:37  2026-10-12T19:14:37Z  splunk      Accepted password svc_billing dari 10.10.23.88 (jkt-billing01)
2026-10-13 02:20:03  2026-10-12T19:20:03Z  splunk      10.20.5.21 ke 203.0.113.77:443, koneksi pertama
2026-10-13 09:47:00  2026-10-13T02:47:00Z  case_notes  Alert SOC-2026-0203
```

Cara membaca hasil:

- Urutan dan jam WIB sama dengan timeline Day 03 bagian 2.3: email 15:58, eksekusi 16:05, skrip kredensial dibaca 23:40, SSH 02:14, beacon 02:20, alert 09:47. Skrip lolos uji dengan data yang jawabannya sudah diketahui.
- Kolom UTC menunjukkan kenapa dua kejadian Selasa dini hari tercatat di tanggal 12 dalam UTC: 02:14:37 WIB sama dengan 19:14:37 UTC hari sebelumnya. Analyst yang membaca kolom UTC harus tahu ini sebelum menulis "Senin" atau "Selasa" di laporan.
- Seandainya case notes diberi label `"UTC"` karena salah salin, alert akan tampil pukul 16:47 WIB, setelah insiden dinyatakan pukul 10:40. Kesalahan seperti ini tidak membuat skrip error, tetapi membuat laporan salah, sehingga label zona di `SUMBER` di-review seperti kode lain.

**Variasi:** tambahkan sumber unified audit log (`CreationDate`, UTC) dan sign-in log Entra ID (`createdDateTime`, UTC dengan `Z`); tambahkan kolom `host` dan `akun` supaya timeline bisa disaring per entitas.

**Kapan gagal:** ekspor memakai format waktu yang berbeda dari yang ditulis di `SUMBER` (misalnya pecahan detik di ekspor EDR), sehingga `strptime` gagal; atau satu sumber diam-diam memakai zona yang lain dari kebiasaannya, misalnya ekspor Splunk yang dibuat oleh akun dengan preferensi zona UTC.

### 2.6 Indikator dari luar: daftar lokal dulu, lalu Splunk

Skrip ini menjawab pertanyaan keenam Dimas. Jumat siang, sebuah laporan intelijen dari vendor keamanan memuat empat indikator; Sari ingin tahu apakah ada yang pernah muncul di PT JAB, tanpa mengirim apa pun ke layanan luar.

**Tujuan:** membersihkan indikator, mencocokkannya dengan `ioc_jab.csv`, menolak input yang tidak berbentuk domain atau IPv4, lalu menghitung host yang menyentuh setiap indikator dalam 30 hari terakhir lewat Splunk REST API.

```python
#!/usr/bin/env python3
"""cek_ioc.py (jab-ir-tools v1.0.0)
Contoh: python3 cek_ioc.py indikator.txt /srv/ir/ioc_jab.csv --splunk --cafile /etc/ssl/jab-ca.pem
"""
import argparse
import csv
import getpass
import ipaddress
import json
import re
import ssl
import urllib.parse
import urllib.request

BASE = "https://jkt-splunk-sh01.corp.jab.example:8089"
POLA_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")
TEMPLATE = {
    "domain": 'search (index=dns query="*{v}") OR (index=proxy url="*{v}*") | stats dc(src) as host_unik',
    "ip":     'search index=firewall dest_ip="{v}" | stats dc(src_ip) as host_unik',
}


def bersihkan(nilai: str) -> str:
    v = nilai.strip().lower().replace("hxxp", "http").replace("[.]", ".").replace("(.)", ".")
    v = re.sub(r"^https?://", "", v).split("/")[0].split(":")[0]
    return v.rstrip(".")


def jenis(v: str) -> str | None:
    try:
        ipaddress.IPv4Address(v)
        return "ip"
    except ValueError:
        return "domain" if POLA_DOMAIN.match(v) else None


def splunk(search: str, token: str, ctx: ssl.SSLContext) -> list:
    hdr = {"Authorization": f"Bearer {token}"}
    data = urllib.parse.urlencode({"search": search, "earliest_time": "-30d@d", "latest_time": "now",
                                   "exec_mode": "blocking", "output_mode": "json"}).encode()
    req = urllib.request.Request(f"{BASE}/services/search/jobs", data=data, headers=hdr)
    with urllib.request.urlopen(req, context=ctx) as r:
        sid = json.load(r)["sid"]
    url = f"{BASE}/services/search/v2/jobs/{sid}/results?output_mode=json&count=0"
    with urllib.request.urlopen(urllib.request.Request(url, headers=hdr), context=ctx) as r:
        return json.load(r)["results"]


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("indikator")
    p.add_argument("ioc_lokal")
    p.add_argument("--splunk", action="store_true")
    p.add_argument("--cafile")
    a = p.parse_args()

    with open(a.ioc_lokal, newline="", encoding="utf-8") as f:
        lokal = {r["nilai"].lower(): r for r in csv.DictReader(f)}
    token = getpass.getpass("Token Splunk: ") if a.splunk else None
    ctx = ssl.create_default_context(cafile=a.cafile)

    print(f"{'bersih':<28} {'jenis':<7} {'status':<14} {'insiden':<13} splunk_30hari")
    for mentah in open(a.indikator, encoding="utf-8").read().splitlines():
        if not mentah.strip():
            continue
        v = bersihkan(mentah)
        j = jenis(v)
        if j is None:
            print(f"{mentah.strip()[:28]:<28} {'-':<7} {'DITOLAK':<14} {'-':<13} tidak dijalankan")
            continue
        cocok = lokal.get(v)
        status = "COCOK" if cocok else "TIDAK_DIKENAL"
        hasil = "-"
        if token:
            r = splunk(TEMPLATE[j].format(v=v), token, ctx)
            hasil = f"{r[0]['host_unik'] if r else 0} host"
        print(f"{v:<28} {j:<7} {status:<14} {cocok['insiden'] if cocok else '-':<13} {hasil}")


if __name__ == "__main__":
    main()
```

Penjelasan tiap bagian:

- `bersihkan` mengembalikan bentuk defanged (`hxxps`, `[.]`) ke bentuk asli, membuang skema, path, dan port, lalu menyamakan huruf kecil dan titik di akhir.
- `jenis` hanya menerima IPv4 yang sah atau nama domain yang lolos pola ketat. Nilai lain ditolak dan tidak pernah sampai ke string search, sehingga tanda kutip atau pipe dari laporan luar tidak bisa mengubah search Splunk.
- Pencocokan lokal terjadi sebelum apa pun dikirim ke mana pun. Tidak ada layanan luar yang dipanggil.
- `splunk()` membuat search job dengan `POST` ke `search/jobs`, mengisi `earliest_time` dan `latest_time` karena tanpa itu search berjalan atas seluruh waktu [S11], lalu mengambil hasil dari endpoint `v2` dalam format JSON [S11][S12]. `exec_mode=blocking` membuat permintaan pertama baru kembali setelah search selesai; cek perilaku dan nama parameter ini di referensi REST versi Splunk-mu.
- Token Splunk diminta dengan `getpass` saat dijalankan, tidak disimpan di skrip, di file, atau di riwayat shell. Sertifikat TLS diverifikasi dengan CA internal PT JAB lewat `--cafile`, tidak dimatikan.

Keluaran ilustrasi (`indikator.txt` berisi empat baris dari laporan):

```
bersih                       jenis   status         insiden       splunk_30hari
sync-win.example.net         domain  COCOK          INC-2026-017  0 host
203.0.113.77                 ip      COCOK          INC-2026-019  0 host
192.0.2.150                  ip      TIDAK_DIKENAL  -             0 host
update.example.net" | delet  -       DITOLAK        -             tidak dijalankan
```

Cara membaca hasil:

- Dua indikator pernah muncul di insiden PT JAB: domain C2 `INC-2026-017` dan IP C2 `INC-2026-019`. Laporan vendor itu kemungkinan membahas pelaku atau infrastruktur yang sama, dan informasi itu berguna untuk konteks, bukan alarm baru.
- Ketiga indikator yang sah tidak disentuh host mana pun dalam 30 hari terakhir. Kesimpulan ini berlaku untuk host yang lognya masuk Splunk dan memakai resolver serta proxy PT JAB; DNS over HTTPS dan perangkat di luar jaringan tetap tidak terlihat (Day 05 bagian 1.6).
- Baris keempat berisi tanda kutip dan pipe karena kesalahan salin dari laporan. Skrip menolaknya, dan search tidak dijalankan.

**Variasi:** tambahkan jenis `sha256` yang dicocokkan dengan daftar lokal dan dicari di index EDR; simpan hasil sebagai CSV di folder insiden dan tambahkan baris log aksi seperti skrip PowerShell di atas.

**Kapan gagal:** `ioc_jab.csv` tidak diperbarui setelah insiden, sehingga indikator lama terlihat "tidak dikenal"; field index (`query`, `url`, `src`, `dest_ip`, `src_ip`) berbeda dengan add-on yang dipakai; atau token yang dipakai punya hak lebih besar daripada membaca index tersebut. Buat token khusus untuk skrip ini dengan role yang hanya bisa search index yang dibutuhkan.

## 3. Lab praktik (di VM lab terisolasi)

Lab ini memakai VM Windows dengan audit Security aktif, VM Windows kedua sebagai target WinRM, VM Linux dengan Python 3.11 atau lebih baru, dan Splunk lab. Bila ada domain controller lab dan tenant uji Microsoft 365, pakai akun uji saja. Semua langkah di VM dengan snapshot, dan jangan memakai data atau akun dari pekerjaan nyata.

1. **Triage event.** Aktifkan audit process creation di VM target, buat satu scheduled task uji dan satu service uji, lalu jalankan skrip bagian 2.1 dari VM pertama ke VM target lewat WinRM tanpa CredSSP. Cocokkan jumlah event per ID dengan Event Viewer. Matikan VM target dan jalankan ulang; pastikan host itu tercatat gagal, bukan bersih.
2. **Pagar aksi ubah.** Tanpa tenant, buat fungsi uji yang "menonaktifkan" akun dengan menulis nama akun ke file, dibungkus `SupportsShouldProcess` dan `ConfirmImpact = 'High'`. Coba `-WhatIf`, `-Confirm`, dan file target berisi 50 nama dengan `-MaxUsers 10`. Bila ada DC lab, ganti aksi tiruannya dengan `Disable-ADAccount` pada akun uji.
3. **Jebakan `-WhatIf` antar modul.** Letakkan fungsi langkah 2 di satu script module, lalu panggil dari fungsi di script module lain dengan `-WhatIf`. Catat apakah aksi tetap terjadi, lalu perbaiki dengan meneruskan `-WhatIf:$WhatIfPreference` secara eksplisit.
4. **Manifest.** Buat folder bukti tiruan berisi lima file dan evidence log CSV dengan hash lengkap. Jalankan skrip bagian 2.4. Ubah satu byte di satu file, tambahkan satu file, hapus satu file, lalu jalankan lagi dan pastikan ketiga status muncul dengan kode keluar 1.
5. **Timeline.** Buat tiga CSV kecil: satu dengan offset (`+07:00`), satu dengan `Z`, dan satu tanpa zona. Jalankan skrip bagian 2.5 dengan label yang benar, lalu dengan label yang salah untuk file tanpa zona, dan catat baris mana yang pindah urutan.
6. **Splunk REST.** Buat token di Splunk lab untuk role yang hanya bisa membaca satu index. Masukkan beberapa event uji, lalu jalankan skrip bagian 2.6 dengan indikator lab. Tambahkan satu baris berisi tanda kutip dan pipe, dan pastikan baris itu ditolak sebelum search dikirim.

**Hasil yang sebaiknya tersimpan:**

- Folder `latihan/day21/` berisi keenam skrip versi lab-mu, masing-masing dengan nomor versi di header.
- Log aksi skrip dari langkah 1 dan 2, termasuk baris `whatif` dan baris gagal.
- Catatan langkah 3 tentang perilaku `-WhatIf` antar script module.
- Dua manifest dari langkah 4 (sebelum dan sesudah perubahan) dan dua timeline dari langkah 5.
- `latihan/day21-aturan-skrip.md` berisi aturan skrip IR versi organisasimu, disusun dari bagian 1.7.

**Variasi tantangan:** panggil skrip bagian 2.4 dari workflow Shuffle di lab, dan buat workflow berhenti dan membuat tugas di TheHive bila kode keluarnya 1.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat skrip IR dipakai. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| `Get-WinEvent` jarak jauh lambat atau mengembalikan terlalu banyak data | Filter dilakukan dengan `Where-Object` setelah semua event diambil | Pindahkan filter ke `FilterHashtable` [S1][S2] |
| Hasil 4688 selalu kosong | Audit process creation tidak aktif di host | Cek kebijakan audit host sebelum menyimpulkan |
| Skrip butuh akses ke share dari host tujuan | Masalah second hop | Bawa hasil kembali ke jump host; jangan aktifkan CredSSP ke host dalam scope [S3] |
| Graph mengembalikan nol sign-in untuk kejadian yang diketahui | Rentang di luar retensi 30 hari, atau sign-in non-interaktif | Pakai salinan log di Splunk; cek jenis sign-in [S6] |
| `Search-UnifiedAuditLog` hanya mengembalikan 100 baris | Tanpa `-SessionCommand` dan `-ResultSize` | Pakai `ReturnLargeSet` dengan `SessionId` tetap, maksimal 50.000 [S8] |
| `-WhatIf` tetap mengeksekusi aksi | Nilai `-WhatIf` tidak diteruskan antar script module | `ShouldProcess` tepat di sekitar perintah; teruskan `-WhatIf` eksplisit [S5] |
| `ZoneInfoNotFoundError` di Windows | Database zona IANA tidak ada | Pasang paket `tzdata` [S10] |
| Manifest menandai semua file `BERBEDA` | Evidence log berisi hash terpotong | Simpan hash lengkap di evidence log |
| Search lewat REST lambat sekali | `earliest_time` dan `latest_time` tidak diisi | Isi rentang waktu; default REST adalah seluruh waktu [S11] |

## 5. Kesalahan umum dan jebakan

- Menyimpan password, token, atau secret aplikasi di skrip IR atau file konfigurasi di sebelahnya. Itu persis akar masalah `INC-2026-019`.
- Menjalankan skrip dari laptop analyst atau dari host dalam scope, bukan dari jump host atau bastion.
- Mengaktifkan CredSSP supaya skrip "bisa jalan", lalu meninggalkan kredensial admin di host yang mungkin dikuasai penyerang [S3].
- Mengalirkan hasil query langsung ke aksi ubah tanpa file target yang di-review dan tanpa batas jumlah.
- Menganggap `-WhatIf` di fungsi luar pasti diteruskan ke fungsi di modul lain [S5].
- Membaca hasil kosong sebagai "tidak ada", padahal host gagal dihubungi, retensi sudah lewat, atau audit tidak aktif.
- Mencampur jam dari sumber berbeda tanpa label zona, atau mengurutkan timeline berdasarkan kolom WIB yang sudah diformat.
- Mengirim indikator atau URL internal ke layanan publik sebelum mencocokkannya dengan daftar dan log sendiri.
- Memakai skrip yang tidak ada di repositori atau tidak punya nomor versi, sehingga tidak bisa dibuktikan skrip mana yang menghasilkan angka di laporan.

## 6. Catatan terkini

Bagian ini menampung detail versi yang bisa berubah. Berguna saat menulis ulang skrip, tetapi tidak mengubah aturan di bagian 1.

- **PowerShell**: halaman `Get-WinEvent` yang diperiksa adalah versi PowerShell 7.6 (ms.date 2026-08-12) dan menyebut kunci `SuppressHashFilter` di `FilterHashtable` untuk mengecualikan event tertentu; kunci named data ditambahkan sejak PowerShell 6 [S1][S2].
- **Microsoft Graph PowerShell**: `Get-MgAuditLogSignIn` di modul `Microsoft.Graph.Reports` (ms.date 2026-09-22) tetap merujuk ke cmdlet beta untuk fitur yang belum ada di v1.0 [S6]. Nama cmdlet beta dan cakupan sign-in non-interaktifnya perlu dicek di versi modul yang terpasang.
- **Exchange Online**: dokumentasi `Search-UnifiedAuditLog` menyebut switch `-HighCompleteness` yang masih preview, yang mengutamakan kelengkapan hasil di atas kecepatan [S8].
- **Python**: sejak 3.14, `hashlib.file_digest()` memunculkan `BlockingIOError` untuk file non-blocking [S9]. `zoneinfo` tersedia sejak 3.9 [S10].
- **Splunk 10.0**: referensi REST mendokumentasikan endpoint hasil `v2` dan menandai versi lamanya deprecated [S12], sementara tutorial REST masih memakai path tanpa `v2` [S11]. Path yang berlaku perlu dicek di versi Splunk-mu sebelum skrip dipakai.

## 7. Cheat sheet

```
KELAS LANGKAH
  BACA (koleksi, ringkasan, hash, timeline)   otomasi penuh; uji dengan insiden yang jawabannya diketahui
  UBAH (revoke, disable, isolasi, blok)       -WhatIf -> IC setuju -> eksekusi; batas jumlah; log tiap target
  PUTUSKAN (severity, jam H, lapor)           manusia

ATURAN SKRIP IR
  tanpa rahasia di skrip (Get-Credential, getpass, login interaktif)
  jalan dari JKT-JUMP01 / jkt-bastion01 / jkt-evid01, akun adm terpisah
  idempoten | log aksi (waktu UTC, operator, skrip+versi, target, aksi, hasil)
  repositori jab-ir-tools + review | kode keluar bisa dibaca SOAR

WINDOWS
  Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4625,4688,4698; StartTime=..}
  System 7045 terpisah | 4688 butuh audit process creation
  Invoke-Command per host di try/catch | JEA untuk batasi perintah | JANGAN CredSSP ke host scope

M365 / ENTRA
  Get-MgAuditLogSignIn -All -Filter "userPrincipalName eq '..' and createdDateTime ge ..Z"
    scope AuditLog.Read.All | v1.0 = interaktif | retensi P1 30 hari -> lebih tua: Splunk
  Search-UnifiedAuditLog: default 100 | ResultSize maks 5.000 | ReturnLargeSet maks 50.000
    SessionId sama, SessionCommand jangan diganti | waktu UTC
  ShouldProcess + ConfirmImpact High | -WhatIf tidak menyeberang antar script module

PYTHON
  hashlib.file_digest(f, "sha256") (3.11+) | manifest DI LUAR folder bukti
  status: COCOK | BERBEDA | TIDAK_ADA_DI_LOG | HILANG ; exit 1 bila BERBEDA/HILANG
  timeline: semua ke UTC, label zona eksplisit untuk waktu naif, ZoneInfo("Asia/Jakarta")
  IOC: refang + validasi ketat sebelum masuk search | daftar lokal dulu, layanan luar belakangan
  Splunk REST: POST search/jobs + earliest_time/latest_time | results output_mode=json
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Fungsi pembungkus kita sudah memakai `SupportsShouldProcess` dan diuji dengan `-WhatIf`. Jadi semua perintah di modul lain yang dipanggilnya pasti ikut dalam mode uji coba." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Nilai `-WhatIf` dan `-Confirm` tidak diteruskan dari satu script module ke fungsi di script module lain, sehingga perintah di modul lain bisa tetap mengeksekusi. Karena itu `ShouldProcess` diletakkan tepat di sekitar perintah yang mengubah, nilai `-WhatIf` diteruskan secara eksplisit, dan uji coba dilakukan pada bentuk akhir skrip dengan akun uji. Lihat bagian 1.3 dan 2.3.

</details>

**2. Skenario keputusan.** Yoga perlu menarik event logon dari sebuah laptop tanpa EDR yang diduga masih dikuasai penyerang. Cara mana yang paling tepat?

- A. `Invoke-Command` dengan CredSSP memakai akun admin domain, supaya hasilnya bisa langsung disimpan ke share bukti dari laptop itu.
- B. Dari `JKT-JUMP01` dengan akun `adm.yoga`, tanpa CredSSP, memakai skrip bagian 2.1 (atau endpoint JEA bila ada), lalu membawa hasil kembali ke jump host.
- C. Login RDP ke laptop itu, menjalankan skrip secara lokal, lalu menyalin CSV lewat clipboard.

<details><summary>Jawaban</summary>

B. Hasil dibawa kembali ke jump host sehingga tidak ada second hop dari host tujuan, dan akun yang dipakai terpisah serta tidak meneruskan kredensial. A keliru karena CredSSP menyimpan kredensial di host jarak jauh, dan bila host itu dikuasai penyerang, kredensial admin domain ikut dicuri. C keliru karena logon interaktif ke host dalam scope meninggalkan kredensial di sana dan mengubah lebih banyak artefak. Lihat bagian 1.2 dan 2.1.

</details>

**3. Pertanyaan jebakan.** "Skrip ringkasan sign-in untuk 28 Oktober mengembalikan nol baris untuk Rina, jadi tidak ada sign-in mencurigakan dari luar kantor." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Pada 18 Desember, rentang 28 Oktober sudah di luar retensi sign-in log Entra ID P1 yang 30 hari, sehingga Graph tidak punya data untuk dikembalikan. Cmdlet v1.0 juga hanya mencakup sign-in interaktif dan federasi yang sukses. Pertanyaan itu dijawab dari salinan log di Splunk, dan skrip sengaja memunculkan peringatan retensi sebelum query. Lihat bagian 1.3 dan 2.2.

</details>

**4. Skenario keputusan.** Saat menyusun timeline, Sari menemukan case notes ditulis tanpa zona waktu (`2026-10-13 09:47`). Apa yang dilakukan skrip?

- A. Menganggapnya UTC seperti sumber lain, supaya konsisten.
- B. Menolak sumber itu sampai diberi label zona eksplisit di konfigurasi skrip; untuk case notes PT JAB labelnya `Asia/Jakarta`.
- C. Mengubah semua sumber ke string WIB tanpa offset, lalu mengurutkan berdasarkan string itu.

<details><summary>Jawaban</summary>

B. Waktu tanpa zona tidak boleh ditebak; label zona ditulis eksplisit dan di-review, dan semua waktu diurutkan dalam UTC. A keliru karena alert 09:47 WIB akan tampil pukul 16:47 WIB, setelah declare, dan laporan menjadi salah tanpa skrip error. C keliru karena membuang offset menghilangkan informasi yang dibutuhkan untuk memeriksa ulang dan rawan salah urut saat sumber baru ditambahkan. Lihat bagian 1.5 dan 2.5.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Bambang Hartono (Manajer NOC), dalam tiga kalimat, kenapa skrip pencabutan sesi PT JAB selalu dijalankan dengan `-WhatIf` dulu dan dibatasi sepuluh akun.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Sama seperti `commit check` sebelum push konfigurasi ke banyak OLT, `-WhatIf` menampilkan daftar akun yang akan diputus tanpa memutus apa pun, dan daftar itu disetujui IC dulu. Batas sepuluh akun menjaga supaya file yang salah, misalnya ekspor semua karyawan, membuat skrip berhenti sebelum menyentuh siapa pun, bukan memutus sesi seribu orang dalam semenit. Kalau memang perlu lebih banyak, batasnya dinaikkan secara sengaja dan tercatat, dan setiap akun yang diproses masuk log yang bisa dicek ulang."

Kesalahan yang sering muncul:
- Menjelaskan sintaks PowerShell, padahal yang dibutuhkan Bambang adalah alasannya.
- Tidak menyebut bahwa daftar target disetujui IC, sehingga terdengar seperti skrip berjalan sendiri.
- Tidak menyebut log aksi, padahal itu yang membuat tindakan bisa diaudit.

</details>

**6. Pertanyaan jebakan.** "Manifest menyatakan semua 18 item bukti `COCOK`, jadi bukti `INC-2026-019` pasti diterima bila suatu saat dipakai di proses hukum." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Hash yang cocok membuktikan isi file tidak berubah sejak hash pertama dicatat, bukan bahwa cara pengambilannya benar atau rantai serah terimanya utuh. Itu tetap dibuktikan oleh evidence log dan formulir chain of custody. Manifest hanya membuat pemeriksaan hash bisa diulang dengan cara yang sama. Lihat bagian 1.4 dan 2.4.

</details>

**7. Interview question (English).** "How do you use scripting during incident response, and what guardrails do you put around it?"

<details><summary>Sample answer</summary>

"I script the steps that only read data and that we keep repeating: pulling Windows events from a set of hosts with Get-WinEvent and a filter hashtable, summarising sign-ins for a list of phishing recipients through Microsoft Graph, hashing evidence and checking it against the evidence log, and merging timelines from EDR, the SIEM and Microsoft 365 into UTC with explicit time zone labels. Before I trust a script, I run it against an old incident where I already know the answer. For anything that changes state, like revoking sessions or disabling accounts, the script supports WhatIf and confirmation, takes its targets from a reviewed file, refuses to run above a set number of targets, and logs every target it touched or skipped. I never put secrets in scripts; credentials are prompted at run time or come from interactive sign-in. I run them from a hardened jump host with a separate admin account and avoid CredSSP to hosts in scope, because that leaves credentials on a machine the attacker may control. Scripts live in a versioned repository with review, and the version is recorded in the case notes so the numbers in the report can be reproduced."

What makes this answer strong: it separates read-only automation from state-changing actions, shows validation against known results, names concrete guardrails, addresses credential exposure on compromised hosts, and ties scripts back to evidence and reproducibility.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Microsoft Learn: Get-WinEvent (Microsoft.PowerShell.Diagnostics) | https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent | primer (dokumentasi vendor) | PowerShell 7.6, ms.date 2026-08-12; diakses 2026-10-15 | Tinggi. `FilterHashtable`, `-ComputerName` tanpa remoting dan satu komputer per panggilan, filter lebih efisien dari `Where-Object`, `SuppressHashFilter` |
| S2 | Microsoft Learn: Creating Get-WinEvent queries with FilterHashtable | https://learn.microsoft.com/en-us/powershell/scripting/samples/creating-get-winevent-queries-with-filterhashtable | primer (dokumentasi vendor) | ms.date 2023-06-28; diakses 2026-10-15 | Tinggi. Kunci dan tipe nilai, `ID` sebagai array, named data sejak PowerShell 6 |
| S3 | Microsoft Learn: Making the second hop in PowerShell Remoting | https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/ps-remoting-second-hop | primer (dokumentasi vendor) | ms.date 2025-12-09; diakses 2026-10-15 | Tinggi. CredSSP menyimpan kredensial di server jarak jauh, mati secara default; JEA sebagai pilihan paling aman |
| S4 | Microsoft Learn: Overview of Just Enough Administration (JEA) | https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/overview | primer (dokumentasi vendor) | ms.date 2022-11-16; diakses 2026-10-15 | Tinggi. Membatasi perintah, akun virtual, transkrip |
| S5 | Microsoft Learn: Everything you wanted to know about ShouldProcess | https://learn.microsoft.com/en-us/powershell/scripting/learn/deep-dives/everything-about-shouldprocess | komunitas (artikel kontributor Kevin Marquette, dipublikasikan di Microsoft Learn) | ms.date 2024-09-24; diakses 2026-10-15 | Sedang sampai tinggi. `SupportsShouldProcess`, `ShouldProcess`, `ConfirmImpact`, `$ConfirmPreference` default `High`, masalah `-WhatIf` antar script module |
| S6 | Microsoft Learn: Get-MgAuditLogSignIn (Microsoft.Graph.Reports) | https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.reports/get-mgauditlogsignin | primer (dokumentasi vendor) | ms.date 2026-09-22; diakses 2026-10-15 | Tinggi. Izin `AuditLog.Read.All`, `-Filter`, `-All`, cakupan sign-in interaktif dan federasi sukses |
| S7 | Microsoft Learn: Revoke user access in an emergency in Microsoft Entra ID | https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access | primer (dokumentasi vendor) | ms.date 2026-06-19; diakses 2026-10-15 | Tinggi. `Revoke-MgUserSignInSession` dan izin Graph yang dipakai |
| S8 | Microsoft Learn: Search-UnifiedAuditLog | https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/search-unifiedauditlog | primer (dokumentasi vendor) | diperbarui 2026-06-01; diakses 2026-10-15 | Tinggi. Default 100, `ResultSize` maksimal 5.000, `ReturnLargeSet` maksimal 50.000, waktu UTC, saran Management Activity API, `HighCompleteness` preview |
| S9 | Python documentation: hashlib | https://docs.python.org/3/library/hashlib.html | primer | Python 3; diakses 2026-10-15 | Tinggi. `file_digest()` sejak 3.11, perubahan di 3.14 |
| S10 | Python documentation: zoneinfo | https://docs.python.org/3/library/zoneinfo.html | primer | Python 3; diakses 2026-10-15 | Tinggi. `ZoneInfo` sejak 3.9, paket `tzdata` bila database sistem tidak ada |
| S11 | Splunk Enterprise 10.0 REST API Tutorials: Creating searches using the REST API | https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-tutorials/10.0/rest-api-tutorials/creating-searches-using-the-rest-api | primer (dokumentasi vendor) | Splunk 10.0; diakses 2026-10-15 | Tinggi. `search/jobs` mengembalikan sid, `output_mode` CSV/JSON/XML, rentang default seluruh waktu |
| S12 | Splunk Enterprise 10.0 REST API Reference: Search endpoint descriptions | https://help.splunk.com/en/splunk-enterprise/rest-api-reference/10.0/search-endpoints/search-endpoint-descriptions | primer (dokumentasi vendor) | Splunk 10.0; diakses 2026-10-15 | Tinggi. Endpoint hasil `v2` dan status deprecated versi lama |
| S13 | RFC 3227: Guidelines for Evidence Collection and Archiving (BCP 55) | https://www.rfc-editor.org/rfc/rfc3227.txt | primer | Februari 2002; diakses 2026-10-15 | Tinggi. Prosedur yang transparan dan bisa diulang, checksum |
| S14 | NIST SP 800-61 Rev. 3 (PDF) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf | primer | April 2025; diakses 2026-10-15 | Tinggi. Otomasi sebagian containment dengan tetap memberi handler kemampuan manual |

**Catatan sumber:** pembagian langkah menjadi baca, ubah, dan putuskan di bagian 1.1, aturan skrip IR di bagian 1.7, dan pagar aksi ubah di bagian 1.3 adalah susunan catatan ini dari sumber yang disebut dan pelajaran insiden PT JAB, bukan daftar resmi. Parameter `exec_mode=blocking` dan `count=0` di bagian 2.6, sintaks filter Graph `userPrincipalName eq` dan `createdDateTime ge`, nama properti `IpAddress` dan `Status.ErrorCode` di objek sign-in, dan properti `PSComputerName` di hasil `Invoke-Command` ditulis dari bentuk umum API dan cmdlet tersebut; cocokkan dengan versi yang terpasang sebelum skrip dipakai. Nama field Splunk di bagian 2.6 mengikuti CIM dan bergantung pada add-on. Semua isi PT JAB, termasuk nama skrip, repositori `jab-ir-tools`, host `jkt-splunk-sh01`, akun uji, jumlah event, dan hasil query, adalah contoh fiktif.
