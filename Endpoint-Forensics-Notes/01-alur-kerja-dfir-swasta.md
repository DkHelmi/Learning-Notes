---
day: 01
title: 'Alur kerja DFIR swasta: triage vs full image, order of volatility, hashing, dokumentasi, chain of custody praktis'
researched_on: 2026-10-15
versions_checked: 'RFC 3227 (BCP 55, Feb 2002); NIST SP 800-86 (Agu 2006); NIST SP 800-61 Rev. 3 (Apr 2025, menggantikan r2), kategori RS.AN-07; Velociraptor docs (artikel Adaptive Collections, Sep 2025; Windows.KapeFiles.Targets tidak lagi bawaan sejak 0.75); PowerShell Get-FileHash (dokumentasi PowerShell 7.6, ms.date 2022-12-12); GNU sha256sum (perilaku umum; cek versi di lab)'
---

# Day 01: Alur kerja DFIR swasta (triage vs full image, order of volatility, hashing, chain of custody)

Cakupan: keputusan akuisisi bukti di endpoint untuk investigasi sektor swasta, dari memilih pola koleksi, menentukan urutan pengambilan, menghitung dan memverifikasi hash, sampai mencatat chain of custody dan hal yang sengaja dilewati.

## Ide inti

Forensik endpoint di organisasi swasta adalah rangkaian keputusan, bukan rangkaian alat. Setiap kasus menjawab empat pertanyaan yang sama: apa yang diambil (triage, adaptive, atau image penuh), dalam urutan apa (yang paling cepat hilang lebih dulu), bagaimana membuktikan bahwa yang diambil tidak berubah (hash, dihitung sedini mungkin dan diverifikasi di setiap perpindahan), dan apa yang sengaja tidak diambil beserta risikonya. Keempat jawaban itu harus tertulis, karena kasus internal yang tampak sederhana bisa berakhir di HR, klaim asuransi, laporan ke regulator, atau sengketa, dan saat itu pertanyaan "bagaimana kamu tahu ini tidak berubah?" hanya bisa dijawab oleh catatan yang dibuat saat itu juga.

Kamu sudah mengenal pola ini dari NOC. Sebelum router agregasi yang bermasalah di-reboot atau dikirim RMA, engineer yang berpengalaman mengambil `show tech` dan crashinfo lebih dulu, karena isi buffer dan memori hilang saat reboot. Ia tidak menyalin seluruh flash setiap router; salinan penuh hanya untuk perangkat yang benar-benar perlu dibedah vendor. Checksum file dicatat, nomor seri ditulis di tanda terima, dan setiap serah terima ke kurir atau gudang spare tercatat. Forensik endpoint memakai pola yang sama dengan satu perbedaan: lawannya bukan kerusakan perangkat, tetapi orang yang mungkin sedang menghapus jejak, dan hasilnya mungkin dibaca orang di luar tim teknis.

```
kasus masuk (alert, laporan, keputusan IR)
  |
  v
PILIH POLA per host        triage  |  adaptive  |  full image
  |                        (dasarnya: pertanyaan, jumlah host, kemungkinan proses hukum/HR)
  v
URUTAN (order of volatility)
  memori, proses, koneksi --> temp FS --> disk --> log remote (amankan retensi)
  |
  v
HASH saat koleksi --> verifikasi tiap perpindahan --> analisis pada SALINAN
  |
  v
CATAT: case notes + chain of custody + "yang sengaja dilewati dan risikonya"
  |
  v
examination --> analysis --> reporting
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan dan data pribadi 400 ribu pelanggan broadband di sistem billing. Kasusnya `INC-2026-019`: lampiran email `Tagihan-Okt-2026.zip` dijalankan di laptop staf penagihan `JKT-WS-0388` (`andi.pratama`), `BDG-WS-0142` (`dewi.anggraini`, tanpa EDR, di kantor Bandung), dan `JKT-WS-0412` (`rizky.saputra`). Password akun service `svc_billing` dibaca dari skrip `export-tagihan.ps1` di laptop Andi, lalu dipakai untuk SSH ke server billing Linux `jkt-billing01`. Selasa 2026-10-13, bukti volatil sudah diambil: memori ketiga laptop dan `jkt-billing01`, paket investigasi EDR, file penyerang, dan output live response, tercatat sebagai `INC-2026-019-E01` sampai `-E14` di server bukti `jkt-evid01`. Rabu 2026-10-14 pukul 17:20 containment dinyatakan berhasil. Pukul 18:10, Yoga Pratama, analyst L2 yang memegang bukti, menulis kepadamu di kanal `#inc-2026-019`:

> "Besok jam 09:00 laptop Andi dan Rizky ditarik untuk reimage. Laptop Dewi dikirim kurir dari Bandung Jumat. `jkt-billing01` dimatikan setelah cutover Kamis malam. Retainer minta image disk penuh keempatnya. Pak Dimas tanya beberapa hal sebelum setuju. Pak Agus (DPO) juga bingung: containment kan sudah selesai, forensik ini sebenarnya di tahap mana? Kita sudah punya memori dan triage, masih perlu image penuh semua? Sebelum `jkt-billing01` dimatikan, ada yang harus diambil lagi? Hash apa yang dipakai dan kapan dicek ulang, apalagi laptop Dewi lewat kurir? Catatan dan CoC-nya harus bagaimana supaya bisa dipertanggungjawabkan ke DPO dan retainer? Terakhir, apa yang sengaja kita lewati, dan apa risikonya?"

Pesan itu memuat enam pertanyaan:

1. Di tahap mana pekerjaan forensik ini, setelah containment selesai?
2. Masih perlu image penuh semua host, atau memori dan triage sudah cukup?
3. Sebelum server dimatikan, apa yang harus diambil dan dalam urutan apa?
4. Hash apa yang dipakai, dan kapan diverifikasi ulang?
5. Catatan dan chain of custody seperti apa yang bisa dipertanggungjawabkan?
6. Apa yang sengaja dilewati, dan apa risikonya?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, dan pertanyaan 6 di bagian 1.6. Bagian 2 berisi perintah, catatan kasus, formulir chain of custody, dan matriks keputusan yang kamu pakai untuk menjawab Yoga.

**Kapan relevan:** setiap kali bukti diambil dari endpoint untuk investigasi internal atau IR di organisasi swasta, terutama saat host akan dimatikan, di-reimage, atau dikirim ke tempat lain, dan saat kasus mungkin menyentuh HR, asuransi, regulator, atau sengketa.
**Kapan bukan jawaban:** Day ini bukan prosedur court-ready dan bukan nasihat hukum; bila kasus berpotensi ke ranah hukum, libatkan Legal sejak awal. Day ini juga tidak mengajarkan alat: KAPE, Velociraptor, dan Volatility 3 dibahas di Day 02-04 dan Day 14.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Ini Day pertama topik ini, jadi semua istilah yang dipakai dimuat di sini. Kolom padanan memakai analogi NOC dan SOC yang dipakai di semua Day Endpoint-Forensics.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Collection, examination, analysis, reporting | Empat tahap proses forensik: mengumpulkan, mengolah, menganalisis, melaporkan | Ambil `show tech`, saring log, cari penyebab, tulis RFO |
| Full disk image | Salinan bit-per-bit seluruh media, termasuk ruang yang tidak dialokasikan | Salinan penuh flash dan NVRAM router sebelum RMA |
| Triage collection | Koleksi artefak terpilih (registry hive, event log, Prefetch, `$MFT`, dan sejenisnya) | Paket `show tech-support` yang dikirim ke TAC vendor |
| Adaptive collection | Triage ditambah file yang dipilih otomatis dari hasil parsing artefak saat koleksi | `show tech` ditambah file yang dirujuk log crash |
| Order of volatility | Urutan pengambilan dari data yang paling cepat hilang ke yang paling stabil | Capture buffer log dan `show tech` dulu, konfigurasi tersimpan belakangan |
| Hash bukti | Nilai SHA-256 yang membuktikan berkas tidak berubah sejak dihitung | Checksum file firmware sebelum upgrade |
| Salinan kerja (working copy) | Salinan bukti yang dianalisis; master disimpan dan tidak disentuh | Menguji konfigurasi di lab, bukan di perangkat produksi |
| Case notes | Log kronologis tindakan, perintah, hasil, dan alasan, dengan waktu dan zona waktu | Log kerja engineer di tiket gangguan |
| Chain of custody | Catatan setiap perpindahan bukti: siapa, kapan, ke mana, dengan hash apa | Serah terima perangkat RMA dengan tanda terima dan nomor seri |
| Penyimpanan bukti | Lokasi dengan kontrol akses tempat master bukti disimpan | Gudang spare dengan log keluar masuk |
| Files On-Demand (placeholder) | File cloud sync yang di disk hanya berupa metadata sampai dibuka | Entri inventaris yang barangnya masih di gudang pusat |

### 1.1 Posisi forensik dalam IR: pekerjaan yang berjalan sendiri setelah containment

Pertanyaan Agus wajar dari luar tim teknis: bila penyerang sudah ditahan, kenapa masih ada pekerjaan forensik? Jawabannya ada di dua kerangka yang dipakai bersama.

Proses forensik biasa dipecah menjadi empat tahap: collection (mengumpulkan data), examination (mengolah data yang terkumpul menjadi bentuk yang bisa dibaca), analysis (menarik kesimpulan dari hasil olahan), dan reporting (menyampaikan hasilnya) [S2]. Keempat tahap itu tidak terikat pada satu fase IR. Pengambilan memori Selasa siang adalah collection yang dikerjakan sebelum containment; image disk Kamis adalah collection yang dijadwalkan setelahnya; analisis memori oleh retainer adalah analysis yang hasilnya menentukan eradication.

Di sisi IR, NIST SP 800-61 Rev. 3 (April 2025) menggantikan Rev. 2 (2012). Ia menempatkan incident response sebagai bagian dari manajemen risiko keamanan dan menyusunnya sebagai Community Profile dari NIST CSF 2.0 [S3]. Forensik endpoint adalah kemampuan yang mendukung tahap deteksi, analisis, dan respons di dalamnya. Rev. 3 juga menulis satu kalimat yang menjawab Agus secara langsung: tidak setiap insiden membutuhkan pengumpulan bukti formal dengan chain of custody, misalnya sebagian besar insiden malware tidak berujung penuntutan, tetapi data insiden yang dikumpulkan tetap dianggap bukti, dan pengumpulan serta penyimpanannya mengikuti prosedur preservasi bukti dan kebijakan retensi organisasi, dengan menimbang kemungkinan penuntutan serta biaya menyimpan data dan perangkat keras atau lunak yang dibutuhkan untuk membukanya nanti (RS.AN-07) [S8].

Untuk `INC-2026-019`, jawabannya ke Agus: containment menutup akses penyerang, sedangkan pekerjaan forensik menjawab pertanyaan yang menentukan kewajiban PT JAB, misalnya data apa yang benar-benar diambil dan sejak kapan. Bukti yang hilang sekarang tidak bisa diambil lagi nanti, karena host akan di-reimage.

### 1.2 Tiga pola akuisisi: pilih per host, bukan per kasus

Pertanyaan Dimas ("masih perlu image penuh semua?") adalah pilihan antara tiga pola. Tabel berikut membandingkannya; baca kolom "Kapan" untuk menentukan pola tiap host.

| Pola | Apa yang diambil | Kelebihan | Kekurangan | Kapan |
|---|---|---|---|---|
| Full disk image | Salinan bit-per-bit seluruh media, termasuk unallocated | Paling lengkap; bisa memulihkan file terhapus; analisis ulang kapan saja | Lambat, besar, sulit di banyak host/cloud | Host kunci yang sudah dipersempit; potensi litigasi; kebutuhan carving |
| Triage collection | File/artefak terpilih (registry hive, event log, Prefetch, $MFT, dll.) | Cepat, kecil, bisa ke banyak host | Bisa melewatkan bukti yang tidak masuk daftar target | Awal kasus, scoping, banyak host |
| Adaptive collection | Triage + file tambahan yang dipilih berdasarkan parsing artefak saat koleksi (mis. biner yang dirujuk Prefetch/scheduled task) | Jalan tengah: lebih lengkap dari triage, jauh lebih kecil dari image | Bergantung pada logika alat; tetap bukan image | Host yang dicurigai, saat image tidak praktis |

Velociraptor (Sep 2025) berpendapat bahwa full image makin tidak praktis karena ukuran dan kecepatan, dan triage dasar saja sering kurang. Adaptive collection adalah jalan tengah [S4]. Di Velociraptor, artefak `Windows.Triage.Targets` disebut sebagai penerus pendekatan KapeFiles, dengan kebijakan koleksi seperti `ExcludeSigned` (default; tidak mengambil biner bertanda tangan tepercaya) dan `HashOnly` (hanya mencatat hash dan keberadaan file) [S4]. Artikel yang sama menyebut `Windows.KapeFiles.Targets` tidak lagi dibawa bawaan sejak versi 0.75, dan menyebut kebijakan ketiga, `AllFiles`, yang tidak disarankan untuk adaptive collection karena ikut mengambil file sistem dan biner tepercaya [S4]. Cek nama artefak dan opsi di versi Velociraptor lab-mu (Day 04).

Pola yang umum di lapangan [S5]:

1. Hunt atau triage luas ke banyak endpoint untuk mempersempit host yang relevan.
2. Triage atau adaptive collection mendalam di host tersebut untuk preservasi.
3. Full image hanya bila severity, kebutuhan hukum, atau pertanyaan analisis (mis. pemulihan file terhapus) membenarkannya.

Di `INC-2026-019`, langkah 1 dan 2 sudah terjadi Selasa: pivot dari IOC dan log DNS sinkhole mempersempit ke tiga laptop dan satu server, lalu memori dan triage diambil. Langkah 3 dibenarkan oleh tiga hal sekaligus: data pribadi pelanggan kemungkinan diambil sehingga DPO menilai kewajiban UU PDP, ada pertanyaan yang hanya bisa dijawab disk (file yang dihapus penyerang di `jkt-billing01`, misalnya arsip yang dibuat lalu dihapus), dan keempat host akan dihapus oleh reimage atau rebuild. Image yang diambil sesaat sebelum reimage murah; image yang tidak diambil tidak bisa dibuat lagi. Jadi jawabannya ke Dimas: ya untuk keempat host, tetapi tidak untuk enam penerima email lain yang tidak menjalankan lampiran (bagian 1.6).

### 1.3 Order of volatility: urutan yang ditentukan oleh apa yang hilang lebih dulu

Pertanyaan ketiga Dimas ("sebelum `jkt-billing01` dimatikan, ada yang harus diambil lagi?") dijawab dengan urutan volatilitas.

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
- Hati-hati memutus jaringan, karena penyerang bisa memasang mekanisme destruktif (deadman switch).

Penerapan praktis di endpoint Windows:

1. Memori (RAM) lebih dulu (alat dan cara dibahas di Day 14).
2. Data volatil yang murah: proses, koneksi jaringan, sesi logon. Ini bisa juga diambil lewat Velociraptor (Day 04).
3. Triage disk (Day 03).
4. Image, bila diputuskan perlu.

Log remote (SIEM, DC, EDR) berada di urutan 5. Log itu biasanya aman di tempat lain, tetapi retensinya terbatas. Jadi ekspor atau pastikan retensinya sejak awal kasus.

Untuk `jkt-billing01`, urutan ini sudah dijalankan Selasa: memori diambil dengan AVML pukul 13:20 sampai 13:41, output live response dan salinan biner penyerang menyusul, dan `/var/log` diarsipkan. Yang tersisa di urutan 1 dan 2 pada Kamis malam adalah keadaan setelah containment: proses penyerang sudah dihentikan Selasa dan server kini hanya berbicara ke tujuan yang diizinkan. Mengambil memori ulang sebelum mematikan server tidak menambah jawaban atas pertanyaan investigasi, sehingga keputusannya ditulis: ambil snapshot volatil singkat (jam sistem, proses, koneksi) untuk dokumentasi kondisi saat dimatikan, lalu matikan, lalu image disk. Urutan tetap dihormati, tetapi isinya disesuaikan dengan pertanyaan yang masih terbuka.

Catatan untuk laptop dengan cloud sync: Elcomsoft (Januari 2026) menyoroti bahwa layanan sinkronisasi cloud dengan Files On-Demand (OneDrive, Dropbox) menaruh placeholder di disk, bukan isi file. Akibatnya, image offline hanya menangkap metadata. Sebaliknya, membuka file tersebut saat triage live memicu unduhan yang bisa menimpa unallocated space. Rekomendasi mereka: ikuti order of volatility, yaitu RAM dan kunci enkripsi dulu, lalu image, baru triage aktif, lalu ekstraksi dari sisi cloud [S6]. Sumber ini sekunder dari vendor forensik; cek perilaku placeholder pada build Windows dan OneDrive di lab-mu.

### 1.4 Hashing: apa yang dibuktikan, dan kapan dihitung

Pertanyaan keempat Dimas menyangkut integritas, terutama untuk laptop Dewi yang berpindah tangan beberapa kali sebelum di-image.

- Hash kriptografis (praktik umum: SHA-256) dihitung saat koleksi, lalu diverifikasi sebelum analisis dan setiap kali bukti berpindah tangan.
- Hash membuktikan bahwa berkas bukti tidak berubah sejak hash dihitung. Hash tidak membuktikan bahwa isinya benar, lengkap, atau diambil dengan cara yang tepat. Itu tugas dokumentasi.
- Untuk triage, yang di-hash biasanya arsip koleksi (mis. ZIP keluaran collector) plus manifest per file bila alat menyediakannya.
- MD5/SHA-1 masih muncul di alat lama. Sertakan SHA-256 untuk ketahanan terhadap kolisi.

Dokumentasi PowerShell menegaskan dua hal yang berguna di sini: `Get-FileHash` memakai SHA256 bila algoritma tidak disebut, dan MD5 serta SHA1 tidak lagi dianggap aman sehingga hanya cocok untuk validasi perubahan sederhana, bukan untuk file yang perlu dilindungi dari pemalsuan [S9].

Untuk laptop Dewi ada satu perbedaan: yang berpindah adalah perangkat fisik, bukan berkas, sehingga hash belum bisa dihitung sebelum image diambil di Jakarta. Integritas selama perjalanan dijaga oleh segel kantong bukti, nomor seri, dan formulir chain of custody per perpindahan; hash baru melindungi bukti sejak image E18 dibuat. Kalimat itu harus muncul di catatan, supaya tidak ada yang mengira hash membuktikan sesuatu tentang perjalanan kurir.

### 1.5 Dokumentasi dan chain of custody: versi minimal yang masih bisa dipertanggungjawabkan

Pertanyaan kelima Dimas adalah soal pembaca catatan: DPO, Legal, retainer, dan mungkin regulator.

RFC 3227 meminta pencatatan: di mana, kapan, dan oleh siapa bukti ditemukan dan dikumpulkan; di mana, kapan, dan oleh siapa ditangani atau diperiksa; siapa yang memegangnya, berapa lama, dan bagaimana disimpan; serta setiap perpindahan [S1].

Untuk konteks swasta, versi minimal yang masih bisa dipertanggungjawabkan:

- **Catatan kasus (case notes):** log kronologis dengan waktu dan zona waktu. Tulis tindakan, perintah, hasil, dan alasan.
- **Formulir chain of custody:** satu baris per perpindahan. Kolomnya: ID bukti, deskripsi, hash, dari, ke, waktu, tujuan, tanda tangan/approval.
- **Penyimpanan:** lokasi dengan kontrol akses (share terbatas atau bucket dengan logging), salinan kerja terpisah dari master.

Kenapa tetap perlu di swasta: kasus internal bisa berujung ke PHK, klaim asuransi, pelaporan regulator, atau sengketa. Saat itu, pertanyaan "bagaimana kamu tahu ini tidak diubah?" harus bisa dijawab [S7]. Di `INC-2026-019`, pembacanya sudah jelas sejak Rabu pagi: DPO menilai kewajiban UU PDP atas sekitar 5.000 baris data pelanggan yang kemungkinan besar diambil. Kesimpulan itu berasal dari analisis memori dan akan diperkuat atau dikoreksi oleh analisis disk; bila rantai buktinya bolong, kesimpulan yang dipakai untuk memberi tahu pelanggan ikut dipertanyakan.

### 1.6 Apa yang biasanya dilewati, dan kenapa sah

Pertanyaan terakhir Dimas adalah yang paling sering lupa ditulis. Tabel berikut berisi hal yang lazim dilewati di DFIR swasta; baca kolom kanan, karena risiko itulah yang harus tertulis di case notes.

| Dilewati | Kenapa sah di swasta | Risiko yang diterima |
|---|---|---|
| Full image setiap host | Waktu dan skala; triage menjawab sebagian besar pertanyaan IR | File terhapus/unallocated tidak bisa dipulihkan nanti |
| Write-blocker hardware untuk triage live | Koleksi live memang mengubah sistem minimal; dicatat | Perubahan kecil pada sistem (dokumentasikan) |
| Dua pemeriksa independen | Tim kecil | Kurang verifikasi silang; kompensasi dengan catatan rinci |
| Analisis memori di semua host | Mahal | Teknik fileless di host yang tidak di-dump bisa terlewat |

Prinsipnya: melewati boleh, asal disengaja dan tercatat. Tulis keputusan dan alasannya di case notes.

Di `INC-2026-019`, daftar yang dilewati malam itu ada tiga. Enam penerima email lain tidak di-image dan tidak diambil memorinya, karena pivot di SIEM dan EDR tidak menemukan eksekusi lampiran atau koneksi ke C2 di laptop mereka; risikonya, laptop tanpa Sysmon atau EDR di antara mereka hanya terlihat dari log jaringan. Memori `jkt-billing01` tidak diambil ulang sebelum dimatikan (bagian 1.3). Pemeriksaan kedua oleh orang lain hanya dilakukan untuk hash, bukan untuk seluruh analisis, karena analisis diserahkan ke retainer.

## 2. Contoh artefak dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Perintah ditulis untuk lingkungan PT JAB; untuk latihan, jalankan hanya di VM lab terisolasi (bagian 3).

### 2.1 Mencatat konteks waktu sebelum koleksi (Windows, PowerShell)

Langkah ini dijalankan Yoga di `JKT-WS-0412` Kamis pukul 08:40, sebelum laptop dimatikan untuk di-image. Tujuannya menjawab pertanyaan yang selalu muncul belakangan: jam di artefak laptop ini cocok dengan jam di SIEM atau tidak.

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

Keluaran ilustrasi: `2026-10-15T08:40:12.3456789+07:00`, `(UTC+07:00) Bangkok, Hanoi, Jakarta`, `Source: JKT-DC01.corp.jab.example`.

**Cara membaca hasil:** waktu laptop dibandingkan dengan jam workstation Yoga yang tersinkron ke server NTP internal; selisihnya (+3 detik di contoh ini) ditulis di case notes. Sumber waktu domain controller berarti laptop mengikuti hierarki waktu domain, sehingga artefak laptop bisa dikorelasikan dengan log DC tanpa koreksi besar.

**Kapan gagal:** sistem yang dikompromikan bisa memalsukan keluaran. Bandingkan dengan sumber waktu eksternal (jam workstation analyst, log SIEM) dan catat selisihnya.

### 2.2 Hashing arsip koleksi

Langkah ini menjawab pertanyaan keempat Yoga untuk bukti berbentuk berkas. Contohnya arsip triage `JKT-WS-0412` (E14) yang diambil Selasa sore, diverifikasi ulang sebelum diserahkan ke retainer.

Windows (PowerShell):

```powershell
Get-FileHash -Path .\INC-2026-019-E14_JKT-WS-0412_triage.zip -Algorithm SHA256 |
  Format-List Algorithm, Hash, Path
```

Linux (`jkt-evid01`, workstation analisis):

```bash
sha256sum INC-2026-019-E14_JKT-WS-0412_triage.zip | tee INC-2026-019-E14_JKT-WS-0412_triage.zip.sha256
# verifikasi kemudian:
sha256sum -c INC-2026-019-E14_JKT-WS-0412_triage.zip.sha256
```

- `Get-FileHash -Algorithm SHA256`: menghitung SHA-256 berkas. SHA256 juga nilai default bila `-Algorithm` tidak ditulis; menuliskannya tetap berguna supaya catatan tidak bergantung pada ingatan pembaca [S9].
- `tee`: menyimpan hash ke file sambil menampilkannya.
- `sha256sum -c`: membaca file hash lalu memeriksa ulang. Keluaran ilustrasi: `INC-2026-019-E14_JKT-WS-0412_triage.zip: OK`.

**Cara membaca hasil:** `OK` berarti berkas identik dengan saat hash dicatat. `FAILED` berarti berkas berubah (rusak saat transfer atau dimodifikasi), sehingga salinan itu tidak boleh dianalisis sebagai bukti. Ambil dari master.

**Variasi:** untuk image disk, alat akuisisi biasanya menghitung hash saat image dibuat dan menyimpannya bersama image; catat nilai itu di evidence log, lalu verifikasi ulang dengan alat yang berbeda saat image tiba di `jkt-evid01`, supaya pemeriksaan tidak bergantung pada satu program.

**Kapan gagal:** hash dihitung setelah berkas dipindah dari host. Rantai bukti sebelum titik itu tidak terlindungi. Hitung secepat mungkin, idealnya oleh collector itu sendiri.

### 2.3 Templat case notes

Catatan berikut adalah cuplikan case notes forensik `INC-2026-019` untuk Rabu malam dan Kamis pagi. Bandingkan setiap baris dengan prinsip RFC 3227 di bagian 1.3: bertimestamp, mencatat keputusan, dan mencatat yang tidak diambil.

```
INC-2026-019 | Case notes forensik | Analyst: <kamu>, Yoga Pratama | TZ catatan: UTC+7 (WIB)
2026-10-14 18:10  Permintaan retainer: image disk JKT-WS-0388, JKT-WS-0412, BDG-WS-0142, jkt-billing01.
2026-10-14 18:40  Keputusan (disetujui Dimas 19:05): image penuh keempat host sebelum reimage/rebuild.
                  Alasan: data pribadi kemungkinan diambil (penilaian DPO berjalan); pertanyaan file
                  terhapus di jkt-billing01; host akan dihapus reimage.
                  Tidak di-image: 6 penerima email lain. Alasan: tidak ada eksekusi lampiran atau
                  koneksi C2 di EDR/SIEM. Risiko: laptop tanpa EDR/Sysmon hanya terlihat dari log jaringan.
                  Memori jkt-billing01 TIDAK diambil ulang: proses penyerang sudah dihentikan Selasa;
                  diganti snapshot volatil singkat sebelum shutdown.
2026-10-15 08:40  JKT-WS-0412: konteks waktu dicatat (2.1). Selisih vs jam analyst: +3 s.
2026-10-15 08:52  E14 diverifikasi ulang sebelum diserahkan ke retainer: sha256sum -c OK.
2026-10-15 09:00  Image disk JKT-WS-0388 (E15) dan JKT-WS-0412 (E16) dimulai.
```

### 2.4 Formulir chain of custody untuk perangkat fisik

Formulir ini menjawab pertanyaan kelima Yoga untuk laptop Dewi, satu-satunya bukti yang berpindah sebagai perangkat fisik. Perhatikan kapan kolom SHA-256 mulai terisi.

| Item | Deskripsi | SHA-256 | Dari | Ke | Waktu (WIB) | Tujuan |
|---|---|---|---|---|---|---|
| E18-D | Laptop `BDG-WS-0142`, S/N dari CMDB, kantong bukti No. 0092 | belum ada (perangkat fisik) | Fajar Nugraha (POP Bandung) | Kurir internal, resi `INT-1016-023` | 2026-10-16 10:10 | Pengiriman ke Jakarta, segel utuh |
| E18-D | idem | belum ada | Kurir internal | Yoga Pratama | 2026-10-16 17:40 | Diterima, segel utuh, foto segel |
| E18-D | idem | belum ada | Yoga Pratama | Lemari bukti SOC | 2026-10-16 17:55 | Disimpan sampai image |
| E18 | Image disk `BDG-WS-0142` | `9d04...` (dicatat alat akuisisi) | Lemari bukti SOC | Retainer, di ruang bukti | 2026-10-19 09:00 | Akuisisi image |
| E18 | idem | `9d04...` (verifikasi alat kedua: cocok) | Retainer | `jkt-evid01` master | 2026-10-19 12:20 | Penyimpanan master |
| E18-W | Salinan kerja image | `9d04...` | `jkt-evid01` master | Workstation analisis retainer | 2026-10-19 13:00 | Analisis |

Cara membaca elemennya:

- **Tiga baris pertama tanpa hash** bukan kekurangan: hash baru ada setelah image dibuat. Selama perjalanan, integritas dibuktikan oleh segel, nomor kantong, dan foto segel di setiap serah terima.
- **Baris kelima** memakai alat yang berbeda untuk verifikasi, supaya kesalahan satu alat tidak lolos.
- **Salinan kerja** (`E18-W`) dibuat supaya master tetap utuh dan bisa diverifikasi ulang kapan saja.

**Kapan gagal:** satu perpindahan tidak tercatat, misalnya laptop "dititipkan" ke resepsionis karena Yoga sedang rapat. Celah satu baris membuat seluruh rantai bisa dipertanyakan.

### 2.5 Matriks keputusan dan hasilnya untuk empat host

Matriks ringkas berikut dipakai setiap kali memilih pola akuisisi. Setelah itu, tabel kedua menunjukkan hasilnya untuk `INC-2026-019`.

```
Apakah ada kemungkinan proses hukum/HR/asuransi/regulator?  -> ya: libatkan Legal; condong ke image + CoC ketat
Berapa host?  >10 -> hunt/triage luas dulu; persempit
Apakah dicurigai fileless/injeksi?  -> ambil memori SEBELUM apa pun yang berat di disk
Cloud sync/Files On-Demand aktif?   -> jangan buka file placeholder saat live; pertimbangkan sisi cloud [S6]
Butuh file terhapus/unallocated?    -> image
Host akan di-reimage/dihapus?       -> ambil sekarang atau tidak pernah
Lainnya                             -> triage/adaptive collection + dokumentasikan yang dilewati
```

Tabel hasil berikut merangkum bukti per host. Kolom "Sudah ada" adalah koleksi Selasa; kolom "Ditambah" adalah keputusan Rabu malam.

| Host | Sudah ada (Selasa) | Ditambah | Alasan |
|---|---|---|---|
| `JKT-WS-0388` | E01 memori, E02 paket investigasi EDR, E03 file penyerang dan skrip kredensial | E15 image disk, Kamis 09:00 | Laptop di-reimage; host awal infeksi dan tempat skrip kredensial |
| `JKT-WS-0412` | E13 memori, E14 triage | E16 image disk, Kamis 09:00 | Laptop di-reimage; host ditemukan belakangan, triage tidak lengkap |
| `BDG-WS-0142` | E08 memori | E18 image disk, Senin 2026-10-19 | Tanpa EDR, sumber artefak hanya disk dan memori |
| `jkt-billing01` | E04 output live response, E05 memori, E06 biner penyerang, E07 `/var/log` | Snapshot volatil singkat, lalu E17 image disk oleh retainer, Jumat 00:30 | Server dibangun ulang; file yang dihapus penyerang hanya mungkin dipulihkan dari disk |

**Kapan gagal:** matriks dipakai untuk membenarkan keputusan yang sudah diambil, bukan untuk memutuskan. Isi baris "Alasan" sebelum tindakan, bukan sesudahnya.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** VM Windows lab + Sysmon (snapshot bersih), workstation analisis (VM Linux), folder `/evidence` dengan izin terbatas. Jangan memakai data, nama, atau kejadian dari pekerjaan nyata.

1. Buat folder kasus `CASE-2026-LAB-001` dan file `case-notes.md` (templat bagian 2.3).
2. Di VM Windows, jalankan bagian 2.1 dan salin keluarannya ke case notes.
3. Buat "bukti" sederhana tanpa alat forensik: kompres `C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx` ke ZIP. Cek file log yang sedang aktif bisa terkunci. Jika gagal, ekspor dulu dengan `wevtutil epl Microsoft-Windows-Sysmon/Operational C:\Temp\sysmon.evtx`. Ini latihan hashing, bukan koleksi forensik yang benar. Day 03 memakai KAPE.
4. Hash ZIP di Windows (bagian 2.2), lalu salin ke VM Linux dan verifikasi dengan `sha256sum -c`. Hasil yang diharapkan: `OK`.
5. Ubah salinannya, misalnya tambahkan beberapa byte ke akhir file dengan `echo x >> copy.zip`, lalu verifikasi ulang. Hasil yang diharapkan: `FAILED`. Catat di case notes bahwa ini uji sengaja.
6. Isi formulir chain of custody (bagian 2.4) untuk tiap perpindahan, termasuk satu perpindahan "fisik" (misalnya menyalin ZIP ke USB yang kamu beri label dan pindahkan ke VM lain), lengkap dengan kolom hash yang baru terisi setelah berkas dibuat.
7. Tulis keputusan "apa yang dilewati" (bagian 1.6) untuk kasus lab ini, minimal dua butir, masing-masing dengan risikonya.
8. Korelasi: cari di SIEM lab (bila ada) satu event dari host yang sama pada rentang waktu catatan. Pastikan zona waktu cocok, atau catat selisihnya.

**Hasil yang sebaiknya tersimpan:**

- Case notes kronologis dengan zona waktu.
- Hash cocok (OK) pada salinan utuh dan gagal pada salinan yang diubah.
- CoC berisi setiap perpindahan.
- Ada daftar "yang dilewati + risiko".

**Variasi tantangan:** susun urutan koleksi untuk skenario "laptop eksekutif, dicurigai pencurian data, OneDrive Files On-Demand aktif, mungkin berujung ke HR". Jelaskan urutan dan alasannya dengan merujuk RFC 3227 dan temuan cloud gap [S1][S6].

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat mengambil dan memindahkan bukti endpoint. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Hash berbeda antara Windows dan Linux | Berkas berubah saat transfer (mode teks/ASCII, AV memodifikasi, salinan belum selesai) | Transfer biner; cek ukuran byte; hash ulang dari master |
| Timeline host dan SIEM selisih jam-an | Zona waktu atau UTC vs lokal tercampur | Normalisasi ke UTC; catat offset (bagian 2.1) |
| Tidak bisa menyalin `.evtx` aktif | File terkunci oleh layanan Event Log | `wevtutil epl` atau collector forensik (Day 03) |
| Triage tidak menemukan file yang dirujuk artefak | File sudah terhapus atau di luar target | Adaptive collection / `HashOnly` untuk mencatat keberadaan [S4]; pertimbangkan image |
| File di folder sync "ada" tetapi isinya kosong saat analisis | Placeholder Files On-Demand | Lihat bagian 1.3 dan [S6]; ambil dari sisi cloud dengan otorisasi |
| Perangkat fisik tiba dengan segel rusak | Kantong dibuka di perjalanan atau segel tidak kuat | Foto kondisi, catat di CoC, beri tahu IC dan Legal; jangan diam-diam melanjutkan seolah utuh |
| Retainer meminta bukti yang ternyata tidak diambil | Keputusan "dilewati" tidak tertulis | Tunjukkan baris keputusan di case notes; bila tidak ada, catat celahnya apa adanya |

## 5. Kesalahan umum dan jebakan

- Menganalisis sebelum mengumpulkan. RFC 3227 menempatkan koleksi lebih dulu [S1]. Menjalankan alat berat di host bisa menghapus bukti volatil.
- Mematikan host "agar aman" sebelum memori diambil. Proses, koneksi, dan kunci enkripsi hilang [S1][S6].
- Hash dihitung terlambat. Lindungi bukti sejak titik koleksi.
- Mengira hash melindungi perangkat fisik selama perjalanan. Hash baru ada setelah image dibuat; sebelum itu yang bekerja adalah segel dan formulir.
- Menganggap triage = lengkap. Triage hanya melihat yang ada di daftar target. Tulis apa yang tidak diambil.
- Me-reimage host sebelum keputusan image ditulis. Disk yang sudah dihapus tidak bisa di-image lagi.
- Lupa zona waktu. Ini kesalahan klasik saat menggabungkan artefak endpoint dengan log SIEM.
- `[komunitas, belum terkonfirmasi]` Praktisi sering menyebut pola "triage live dulu, image belakangan" sebagai default modern [S5]. Ini konsisten dengan Velociraptor [S4], tetapi bertentangan dengan rekomendasi Elcomsoft untuk perangkat dengan cloud sync (image dulu setelah RAM) [S6]. Konflik ini nyata. Pilih berdasarkan konteks kasus, dan dokumentasikan alasanmu.

## 6. Catatan terkini

Bagian ini menampung detail versi dan perubahan sumber yang bisa berubah lagi. Berguna saat membuka dokumen sumbernya, tetapi tidak mengubah alur keputusan di atas.

- NIST SP 800-61r3 (3 Apr 2025) menggantikan r2 (2012) dan menyelaraskan IR dengan CSF 2.0 [S3]. r3 menyusun rekomendasinya mengikuti enam fungsi CSF 2.0 (Govern, Identify, Protect, Detect, Respond, Recover), sehingga empat fase r2 (preparation; detection and analysis; containment, eradication, and recovery; post-incident activity) sebaiknya dibaca sebagai konteks historis. Untuk catatan ini cukup diingat bahwa kegiatan forensik endpoint paling banyak berada di fungsi Detect dan Respond. Pernyataan tentang data insiden sebagai bukti ada di subkategori RS.AN-07 [S8].
- **Velociraptor "Adaptive Collections" (28 Sep 2025):** pergeseran dari daftar target statis ke koleksi yang diputuskan berdasarkan parsing artefak [S4]. Sejak 0.75, `Windows.KapeFiles.Targets` tidak lagi bawaan dan penerusnya bernama `Windows.Triage.Targets` [S4].
- **Elcomsoft "The Cloud Gap" (8 Jan 2026):** Files On-Demand membuat image offline dan triage live sama-sama berisiko kehilangan isi file [S6].
- **`Get-FileHash`:** halaman dokumentasi PowerShell 7.6 yang diperiksa bertanggal 2022-12-12; algoritma yang diterima SHA1, SHA256, SHA384, SHA512, dan MD5 [S9].
- RFC 3227 (2002) dan SP 800-86 (2006) berusia lebih dari 3 tahun, tetapi masih menjadi rujukan prinsip. Contoh teknisnya (alat, media) sudah usang.

## 7. Cheat sheet

```
POLA      full image (lengkap, lambat) | triage (cepat, terbatas) | adaptive (jalan tengah)
          pilih per host; host yang akan di-reimage: ambil sekarang atau tidak pernah
URUTAN    RAM/proses/jaringan -> temp FS -> disk -> log remote (amankan retensi!) -> arsip
          isi urutan disesuaikan pertanyaan yang masih terbuka; keputusan ditulis
PRINSIP   catat bertimestamp | koleksi sebelum analisis | jangan matikan dulu | jangan percaya biner host
HASH      SHA-256 saat koleksi; verifikasi sebelum analisis & tiap transfer; analisis pada SALINAN
          Win: Get-FileHash -Path <f> -Algorithm SHA256   Linux: sha256sum <f> ; sha256sum -c <f>.sha256
          MD5/SHA1: hanya validasi perubahan sederhana
          perangkat fisik: segel + S/N + CoC sampai image dibuat; hash mulai dari image
WAKTU     Get-Date -Format o | Get-TimeZone | w32tm /query /status  -> normalisasi UTC
CoC       siapa, kapan, di mana, apa (hash), dari->ke, tujuan  (setiap perpindahan)
DILEWATI  boleh, asal DISENGAJA + DICATAT + risikonya ditulis
CLOUD     Files On-Demand: placeholder != isi file; hati-hati membuka saat live
NIST r3   RS.AN-07: data insiden = bukti, walau CoC formal tidak selalu dijalankan
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Containment `INC-2026-019` sudah dinyatakan berhasil, jadi bukti yang tersisa di laptop tidak penting lagi dan laptop bisa langsung di-reimage." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Containment menutup akses penyerang, sedangkan pekerjaan forensik menjawab pertanyaan yang belum selesai, termasuk data apa yang diambil, yang menentukan kewajiban PT JAB. NIST SP 800-61 Rev. 3 menyebut data insiden yang dikumpulkan tetap dianggap bukti dan dikelola sesuai prosedur preservasi, walaupun chain of custody formal tidak selalu dijalankan. Reimage menghapus disk, jadi keputusan image harus diambil sebelumnya. Lihat bagian 1.1 dan 1.2.

</details>

**2. Skenario keputusan.** Retainer meminta image disk penuh untuk empat host dan juga untuk enam penerima email lain "supaya aman". Respons mana yang paling tepat?

- A. Setujui semua sepuluh host, karena lebih banyak bukti selalu lebih baik.
- B. Image keempat host yang terdampak sebelum reimage atau rebuild; tidak meng-image enam penerima lain karena pivot SIEM dan EDR tidak menemukan eksekusi atau koneksi C2, dan tulis keputusan serta risikonya di case notes.
- C. Tolak semua image, karena memori dan triage sudah diambil Selasa.

<details><summary>Jawaban</summary>

B. Pola akuisisi dipilih per host berdasarkan pertanyaan investigasi, kemungkinan proses hukum atau regulator, dan apakah host akan dihapus. Keempat host memenuhi ketiganya, enam lainnya tidak punya indikasi eksekusi. A keliru karena image punya biaya waktu dan penyimpanan yang tidak dibenarkan oleh pertanyaan apa pun. C keliru karena triage tidak bisa memulihkan file terhapus dan host akan dihapus reimage. Lihat bagian 1.2 dan 1.6.

</details>

**3. Pertanyaan jebakan.** "Hash image laptop Dewi cocok saat diverifikasi, jadi terbukti laptop itu tidak diubah selama dikirim kurir dari Bandung." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Hash baru ada setelah image dibuat di Jakarta, jadi hash hanya membuktikan image tidak berubah sejak saat itu. Integritas selama perjalanan dibuktikan oleh segel kantong bukti, nomor seri, foto segel, dan baris chain of custody di setiap serah terima. Lihat bagian 1.4 dan 2.4.

</details>

**4. Skenario keputusan.** Kamis malam, sebelum `jkt-billing01` dimatikan, Yoga bertanya apakah memori perlu diambil lagi. Pilihan mana yang tepat?

- A. Ambil memori penuh lagi karena order of volatility selalu dimulai dari memori.
- B. Ambil snapshot volatil singkat (jam, proses, koneksi) untuk mendokumentasikan kondisi saat dimatikan, karena memori saat penyerang aktif sudah diambil Selasa dan proses penyerang sudah dihentikan; tulis keputusannya.
- C. Langsung matikan, karena memori lama sudah cukup dan tidak ada yang perlu dicatat.

<details><summary>Jawaban</summary>

B. Order of volatility menentukan urutan, tetapi isi yang diambil mengikuti pertanyaan yang masih terbuka. Kondisi yang relevan untuk investigasi sudah ada di memori Selasa; snapshot singkat cukup untuk mencatat kondisi saat dimatikan. A keliru karena mengambil memori tanpa pertanyaan yang dijawab hanya menambah beban. C keliru karena mematikan tanpa mencatat kondisi dan keputusan meninggalkan celah dokumentasi. Lihat bagian 1.3.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Agus Setiawan (DPO), dalam tiga kalimat, kenapa hash dan chain of custody penting untuk penilaian UU PDP yang sedang ia kerjakan.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Kesimpulan bahwa sekitar 5.000 baris data pelanggan kemungkinan diambil berasal dari bukti yang kami kumpulkan dari laptop dan server. Hash membuktikan bukti itu tidak berubah sejak kami ambil, dan catatan serah terima menunjukkan siapa yang memegangnya di setiap tahap. Kalau nanti regulator atau pelanggan menanyakan dasar kesimpulan yang Bapak laporkan, dua hal itu yang membuat kita bisa menjawab tanpa ragu."

Kesalahan yang sering muncul:
- Menjelaskan cara kerja SHA-256, padahal yang dibutuhkan DPO adalah fungsinya.
- Tidak mengaitkan dengan keputusan yang sedang ia buat.
- Menjanjikan bahwa bukti "pasti diterima pengadilan", padahal catatan ini bukan prosedur court-ready.

</details>

**6. Pertanyaan jebakan.** "Kita memakai triage, jadi tidak perlu menulis apa yang tidak diambil; triage memang terbatas dan semua orang tahu itu." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Melewati boleh, asal disengaja dan tercatat bersama risikonya. Tanpa catatan, pembaca laporan tidak tahu apakah sesuatu tidak ditemukan karena memang tidak ada atau karena tidak pernah diambil, dan pertanyaan retainer atau regulator tentang bukti yang hilang tidak bisa dijawab. Lihat bagian 1.6 dan 2.3.

</details>

**7. Interview question (English).** "Walk me through how you decide between triage collection and a full disk image."

<details><summary>Sample answer</summary>

"I decide per host, not per case. First, what question am I trying to answer? Most IR questions, what ran, when, and from where, are answered by triage or adaptive collection, which is fast and scales to many hosts, so I use it to scope. I go to a full image when the question needs it, for example recovering deleted files or unallocated space, when the case may go to HR, insurance, a regulator or court, or when the host is about to be reimaged or rebuilt, because that's the last chance. Whatever I choose, I follow order of volatility, memory and volatile state first, hash at the point of collection, verify on every transfer, and work on a copy. And I write down what I deliberately didn't collect and the risk that creates, so nobody later confuses 'not found' with 'not collected'."

What makes this answer strong: it ties the choice to the investigative question and the possible audience, names the irreversible trigger (reimage), keeps integrity practices in the flow, and treats documented omissions as part of the method.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | RFC 3227: Guidelines for Evidence Collection and Archiving (BCP 55) | https://datatracker.ietf.org/doc/html/rfc3227 | primer | 2002-02 (>3 tahun); diakses 2026-10-07 | Tinggi untuk prinsip; contoh alat usang |
| S2 | NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response | https://csrc.nist.gov/pubs/sp/800/86/final | primer | 2006-09 (>3 tahun); diakses 2026-10-07 | Tinggi untuk kerangka empat tahap proses forensik |
| S3 | NIST SP 800-61 Rev. 3 (halaman publikasi) | https://csrc.nist.gov/pubs/sp/800/61/r3/final | primer | 2025-04; diakses 2026-10-07 | Tinggi untuk posisi IR dalam CSF 2.0; rincian pemetaan fase ada di dokumen penuh |
| S4 | Velociraptor: Adaptive Collections with Velociraptor | https://docs.velociraptor.app/blog/2025/2025-09-28-adaptive-collections/ | primer (blog proyek resmi) | 2025-09-28; diakses 2026-10-07, dicek ulang 2026-10-15 | Tinggi untuk fitur Velociraptor; ada sudut pandang proyek. Kebijakan `ExcludeSigned`, `HashOnly`, `AllFiles`; `Windows.KapeFiles.Targets` tidak lagi bawaan sejak 0.75 |
| S5 | Cado Security / Forensic Focus: The differences between full disk and triage acquisition | https://www.forensicfocus.com/articles/the-differences-between-full-disk-and-triage-acquisition/ | sekunder | diakses 2026-10-07; situs bisa menolak akses otomatis | Sedang. Dipakai hanya untuk pola umum hunt, triage, lalu image |
| S6 | Elcomsoft: The Cloud Gap: Forensic Triage vs. Disk Imaging in the Age of On-Demand Sync | https://blog.elcomsoft.com/2026/01/the-cloud-gap-forensic-triage-vs-disk-imaging-in-the-age-of-on-demand-sync/ | sekunder (vendor forensik) | 2026-01-08; diakses 2026-10-07 | Sedang-tinggi; vendor punya kepentingan produk |
| S7 | Cado Security wiki: Chain of custody, a digital forensics case study | https://cadosecurity.com/wiki/chain-of-custody-a-digital-forensics-case-study | sekunder | diakses 2026-10-07 | Rendah-sedang. Dipakai hanya untuk alasan kenapa CoC tetap perlu di kasus korporat |
| S8 | NIST SP 800-61 Rev. 3: Incident Response Recommendations and Considerations for Cybersecurity Risk Management (PDF) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf | primer | April 2025; diakses 2026-10-15 | Tinggi. RS.AN-07: data insiden tetap bukti walau CoC formal tidak selalu dijalankan; preservasi dan retensi dengan menimbang penuntutan dan biaya |
| S9 | Microsoft Learn: Get-FileHash (Microsoft.PowerShell.Utility) | https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash | primer (dokumentasi vendor) | PowerShell 7.6, ms.date 2022-12-12; diakses 2026-10-15 | Tinggi. Default SHA256, algoritma yang diterima, MD5 dan SHA1 hanya untuk validasi perubahan sederhana |

**Catatan sumber:** klaim pola "hunt atau triage luas dulu, image belakangan" [S5] dan alasan bisnis chain of custody [S7] berasal dari sumber sekunder; perlakukan sebagai praktik umum, bukan standar. Pemetaan rinci rekomendasi SP 800-61r3 ke enam fungsi CSF 2.0 dan isi lengkap SP 800-86 sebaiknya dicocokkan dengan dokumen penuhnya bila dibutuhkan untuk laporan formal. Nama artefak dan opsi Velociraptor [S4] dapat berubah antar versi. Keputusan per host, urutan Kamis malam, dan formulir untuk perangkat fisik di bagian 1.2 sampai 2.5 adalah penerapan catatan ini pada kasus fiktif, bukan prosedur resmi sumber mana pun. Semua isi PT JAB, termasuk nama, waktu, nomor kantong, dan nilai hash, adalah contoh fiktif.
