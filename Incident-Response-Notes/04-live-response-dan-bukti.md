---
day: 04
title: 'Live response dan pengamanan bukti sebelum containment: order of volatility, Windows dan Linux, memori, dan chain of custody'
researched_on: 2026-10-15
versions_checked: 'RFC 3227 Guidelines for Evidence Collection and Archiving (BCP 55, Februari 2002); NIST SP 800-86 (Agustus 2006); NIST SP 800-61 Rev. 3 (April 2025) dan Rev. 2 (Agustus 2012, digantikan Rev. 3); CISA AA20-245A (1 September 2020, revisi 24 September 2020); CISA Cybersecurity Incident and Vulnerability Response Playbooks (November 2021); Microsoft Defender for Endpoint, halaman Take response actions on a device (ms.date 2026-07-23) dan Live response (ms.date 2026-07-28); repo GitHub AVML, LiME, dan WinPmem (dicek 2026-10-15)'
---

# Day 04: Live response dan pengamanan bukti sebelum containment (order of volatility, Windows dan Linux, memori, dan chain of custody)

Cakupan: kenapa bukti diamankan sebelum containment, urutan pengambilan data dari yang paling cepat hilang, live response dan akuisisi memori di Windows lewat EDR dan di Linux tanpa EDR, hal yang harus dihindari supaya bukti tidak rusak dan penyerang tidak sadar, hash, evidence log, dan chain of custody, serta cara menentukan seberapa jauh pengambilan bukti perlu dilakukan.

## Ide inti

Containment mengubah keadaan sistem. Mengisolasi host memutus koneksi yang sedang berjalan, mematikan server menghapus isi memori, menghapus file malware menghilangkan sampel, dan me-reset akun menghentikan sesi yang sedang dipakai penyerang. Semua itu adalah informasi yang hanya ada selama sistem masih dalam keadaan saat ini. Karena itu urutannya: putuskan bukti apa yang dibutuhkan, ambil yang paling cepat hilang lebih dulu, buktikan bahwa bukti itu tidak berubah, baru jalankan containment. Pengecualiannya hanya satu: bila kerusakan sedang berjalan cepat, menahan kerusakan didahulukan dan bukti diambil dari apa yang tersisa.

Kamu sudah mengenal pola ini dari NOC. Sebelum me-reboot router yang hang, engineer yang berpengalaman mengambil `show tech-support`, buffer log, dan crashinfo dulu, karena setelah reboot semua itu hilang dan vendor tidak bisa menganalisis penyebabnya. Paket `show tech` dikirim ke TAC dengan nomor kasus dan checksum. IR memakai kebiasaan yang sama dengan dua tambahan. Pertama, setiap perintah yang kamu jalankan di host yang dikuasai penyerang ikut mengubah host itu dan bisa terlihat oleh penyerang, jadi perintahnya dipilih dan dicatat. Kedua, hasilnya bisa menjadi bukti di proses hukum atau pemeriksaan regulator, jadi setiap perpindahan bukti harus bisa dipertanggungjawabkan.

```
host terdampak, belum di-contain
  |
  v
putuskan: bukti apa, seberapa formal (proporsional dengan insiden)
  |
  v
catat yang terlihat + jam sistem dan selisihnya
  |
  v
VOLATIL dulu   koneksi jaringan -> sesi login -> memori -> proses
               -> file terbuka -> konfigurasi jaringan
  |
  v
NON-VOLATIL    file persistence, sampel, log lokal
  |
  v
LOG TERPUSAT   ekspor dari SIEM, firewall, proxy; jaga retensinya
  |
  v
hash + evidence log + chain of custody -> server bukti
  |
  v
containment (Day 05)
```

Situasi yang dipakai sepanjang Day ini melanjutkan `INC-2026-019` di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif. Ringkasnya: lampiran email berbahaya dijalankan staf penagihan `andi.pratama` di `JKT-WS-0388` pada Senin 12 Oktober 2026. Penyerang membaca password akun service `svc_billing` dari skrip di laptop itu, lalu masuk lewat SSH ke server billing `jkt-billing01` pada Selasa dini hari. Workstation kedua, `BDG-WS-0142` milik `dewi.anggraini` di Bandung, terinfeksi dari email yang sama. Ketiga host masih beacon ke `cdn-sync.example.net` (`203.0.113.77`). Insiden berstatus SEV-2 sejak 11:50. `JKT-WS-0388` punya EDR (Microsoft Defender for Endpoint); `BDG-WS-0142` dan `jkt-billing01` tidak. Selasa 13 Oktober pukul 12:10, IC Dimas Prasetyo menulis ke analyst L2 Yoga Pratama:

> "Yog, containment rencananya serentak jam 16:00. Sebelum itu tolong amankan bukti dari tiga host. Laptop Andi di lantai 3. Laptop Dewi di Bandung, di sana cuma ada teknisi POP. `jkt-billing01` tidak boleh mati, pelanggan bayar tagihan lewat portal. Apa yang diambil duluan di tiap host? Pakai apa, disimpan di mana? Bagaimana kita buktikan nanti file-nya tidak berubah? Jangan sampai penyerang sadar. Dan tolong jangan kebablasan, kita tidak sedang bikin kasus pengadilan, tapi DPO bilang ini bisa jadi urusan UU PDP."

Pesan itu memuat tujuh pertanyaan:

1. Kenapa bukti harus diambil sebelum containment?
2. Apa yang diambil lebih dulu?
3. Bagaimana mengambilnya di Windows yang punya EDR?
4. Bagaimana mengambilnya di Linux tanpa EDR, termasuk memori, tanpa mematikan server?
5. Bagaimana supaya bukti tidak rusak dan penyerang tidak sadar?
6. Bagaimana membuktikan file tidak berubah?
7. Seberapa jauh pengambilan bukti perlu dilakukan?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, pertanyaan 6 di bagian 1.6, dan pertanyaan 7 di bagian 1.7. Bagian 2 berisi rencana dan dokumen yang dihasilkan Yoga siang itu.

**Kapan relevan:** setelah scope cukup untuk containment dan sebelum containment dijalankan; saat host akan di-reimage, dimatikan, atau dikembalikan ke pengguna; dan saat insiden mungkin berujung pada pelaporan ke regulator, klaim asuransi, sengketa kontrak, atau proses hukum.
**Kapan bukan jawaban:** bila enkripsi atau penghapusan data sedang berjalan cepat, menahan kerusakan didahulukan (Day 01 bagian 2.4), dan bukti diambil dari yang tersisa. Live response juga bukan analisis forensik: tujuannya mengamankan data sebelum hilang, sedangkan analisis mendalam dikerjakan belakangan dari salinannya.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (insiden, severity, IC, scoping, IOC, scope statement, case notes) tidak diulang. Tabel berikut memuat istilah baru Day ini. Kolom padanan memakai analogi NOC dan SOC yang sama di semua Day IR.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Bukti (evidence) | Data yang menjadi dasar untuk membuktikan atau membantah apa yang terjadi | Data gangguan yang dikirim ke vendor sebagai dasar analisis |
| Data volatil | Data yang hilang saat sistem dimatikan atau seiring waktu: memori, koneksi, proses, sesi | Buffer log dan tabel di RAM router yang hilang saat reboot |
| Order of volatility | Urutan pengambilan data dari yang paling cepat hilang ke yang paling tahan | Urutan capture: buffer log dan `show tech` dulu, konfigurasi tersimpan belakangan |
| Live response | Pengambilan data dan pemeriksaan dari sistem yang masih menyala | Masuk lewat console untuk menjalankan perintah `show` sebelum reboot |
| Akuisisi memori | Menyalin isi RAM ke file image untuk dianalisis | Core dump atau crashinfo router sebelum reboot |
| Paket triage (investigation package) | Kumpulan artefak penting yang diambil otomatis oleh alat, tanpa image penuh | Paket `show tech-support` yang dikirim ke TAC vendor |
| Toolkit IR | Kumpulan alat terpercaya yang disiapkan sebelum insiden dan dijalankan dari media terlindungi | Kit troubleshooting engineer lapangan dengan firmware dan kabel console sendiri |
| Hash | Sidik jari kriptografis file (catatan ini memakai SHA-256) untuk membuktikan file tidak berubah | Checksum file firmware sebelum upgrade |
| Evidence log | Daftar semua bukti: apa, dari mana, kapan, oleh siapa, disimpan di mana | Daftar perangkat RMA dengan nomor seri dan lokasinya |
| Chain of custody | Catatan setiap perpindahan bukti antar orang dan tempat, dengan waktu dan tanda tangan | Serah terima perangkat RMA dengan tanda terima |
| Server bukti | Penyimpanan khusus bukti dengan akses terbatas dan tercatat | Gudang spare dengan log keluar masuk |

### 1.1 Kenapa bukti diambil sebelum containment

Dimas menetapkan containment pukul 16:00 dan meminta bukti diambil sebelum itu. Pertanyaan yang wajar dari pihak bisnis adalah: kalau penyerang sudah di dalam, kenapa tidak langsung diputus?

NIST SP 800-86 menjawabnya dari sisi data. Data volatil terkait sebuah kejadian hanya bisa diambil dari sistem yang belum di-reboot atau dimatikan sejak kejadian itu, dan mematikan sistem atau bahkan memutusnya dari jaringan bisa menghilangkan kesempatan mengambil informasi penting [S2]. NIST SP 800-61 Rev. 2 menambahkan bahwa dari sudut pembuktian jauh lebih baik mengambil potret sistem apa adanya daripada setelah handler, admin, dan orang lain tanpa sengaja mengubah keadaannya selama investigasi [S3]. Advisory gabungan AA20-245A menempatkan pengambilan artefak, log, dan data sebagai langkah pertama proses IR, dan menyebut mitigasi sistem sebelum responder sempat melindungi dan mengambil data sebagai kesalahan umum: memori dan artefak volatil lain hilang, dan penyerang bisa mengubah taktik [S5].

Di `INC-2026-019`, yang dipertaruhkan konkret:

- **Memori `jkt-billing01`** bisa menunjukkan apa yang dijalankan proses `/dev/shm/.cache/kworkerd`, perintah yang diterima dari C2, dan apakah ada koneksi ke database pelanggan. Ini satu-satunya sumber yang bisa membantu menjawab hipotesis "data pelanggan diambil atau tidak" selain log audit database.
- **Biner di `/dev/shm`** tersimpan di tmpfs, yaitu di RAM. File itu hilang saat server di-reboot.
- **Koneksi dan sesi yang sedang aktif** menunjukkan apakah penyerang sedang login dan dari mana.
- **Sampel dan scheduled task di kedua workstation** dibutuhkan untuk mencari host lain dengan perilaku sama, dan hilang bila EDR atau tim IT menghapusnya lebih dulu.

Rev. 2 memberi alasan yang lebih jauh: sebagian serangan justru menimbulkan kerusakan tambahan saat ditahan. Contohnya proses berbahaya yang secara berkala menghubungi host lain, dan menimpa atau mengenkripsi data di disk begitu koneksinya gagal [S3]. RFC 3227 menyebut hal yang sama: memutus atau memfilter akses jaringan bisa memicu "dead man switch" yang menghapus bukti [S1]. Mengetahui apa yang dilakukan malware sebelum memutusnya mengurangi kejutan semacam ini.

### 1.2 Order of volatility: yang paling cepat hilang diambil lebih dulu

Pertanyaan kedua Dimas ("apa yang diambil duluan?") punya jawaban baku sejak 2002, dengan penyesuaian per situasi.

RFC 3227 (Guidelines for Evidence Collection and Archiving, BCP 55) menyusun urutan volatilitas dari yang paling cepat hilang [S1]:

1. Register dan cache CPU.
2. Routing table, ARP cache, process table, statistik kernel, dan memori.
3. Filesystem sementara.
4. Disk.
5. Logging jarak jauh dan data monitoring yang relevan.
6. Konfigurasi fisik dan topologi jaringan.
7. Media arsip.

NIST SP 800-86 memberi urutan yang lebih operasional untuk data volatil sistem operasi, dari yang pertama sampai terakhir: koneksi jaringan, sesi login, isi memori, proses yang berjalan, file yang terbuka, konfigurasi jaringan, dan waktu sistem. Alasannya, koneksi jaringan bisa time out atau terputus dan daftar pengguna yang login berubah dari waktu ke waktu, sedangkan konfigurasi jaringan jarang berubah [S2]. NIST juga menyebut jenis data yang diprioritaskan bergantung pada pertanyaan investigasinya, dan bila ragu, kumpulkan data volatil sebanyak mungkin karena kesempatannya hilang begitu sistem mati [S2].

Dua urutan itu tidak bertentangan. RFC 3227 menyusun berdasarkan jenis media, NIST SP 800-86 menyusun urutan kerja di sistem operasi. PT JAB memakai urutan kerja berikut, dengan satu langkah tambahan di depan dari prinsip RFC 3227 untuk mencatat selisih jam sistem [S1]:

| Urutan | Data | Kenapa di posisi ini |
|---|---|---|
| 0 | Jam sistem, zona waktu, dan selisihnya terhadap NTP | Perintahnya instan dan dibutuhkan untuk membaca semua data lain |
| 1 | Koneksi jaringan | Bisa time out atau terputus dalam detik sampai menit |
| 2 | Sesi login | Bisa berakhir kapan saja |
| 3 | Memori | Ukurannya besar dan lama diambil, tetapi memuat hampir semua hal di bawahnya |
| 4 | Proses yang berjalan, termasuk salinan biner proses yang mencurigakan | Proses bisa berhenti atau diganti |
| 5 | File yang terbuka | Berubah mengikuti proses |
| 6 | Konfigurasi jaringan dan routing | Jarang berubah |
| 7 | File di filesystem sementara (`/dev/shm`, `/tmp`, folder Temp) | Hilang saat reboot atau dibersihkan otomatis |
| 8 | Artefak persistence dan log lokal di disk | Bertahan setelah reboot, tetapi bisa dihapus penyerang atau tertimpa rotasi |
| 9 | Log terpusat (SIEM, firewall, proxy) | Paling tahan, tetapi tetap tunduk pada retensi |

Urutan ini disesuaikan dengan pertanyaan investigasi. Untuk `jkt-billing01`, pertanyaan "apakah data diambil" membuat memori dan koneksi ke database lebih penting daripada konfigurasi jaringan. Untuk `BDG-WS-0142` tanpa EDR, memori dan artefak persistence penting karena tidak ada telemetri lain dari host itu.

### 1.3 Windows dengan EDR: paket triage, live response, dan memori

Untuk `JKT-WS-0388`, Yoga tidak perlu datang ke lantai 3 untuk sebagian besar pekerjaan, karena Defender for Endpoint sudah menyediakan dua fasilitas jarak jauh.

**Paket investigasi (Collect investigation package).** Aksi ini mengambil kumpulan artefak yang menggambarkan keadaan perangkat, lalu menyediakannya sebagai file zip di Action center. Untuk Windows, isinya antara lain folder Autoruns (isi registry di titik auto-start yang dipakai untuk persistence), Network connections (koneksi TCP/IP aktif, ARP cache, DNS cache, konfigurasi IP, dan log firewall), Prefetch, daftar scheduled task dalam CSV, log dukungan Defender, dan `CollectionSummaryReport.xls` yang mencatat perintah pengambilan setiap data beserta status dan error-nya [S7]. Laporan ringkasan itu perlu dicek, karena paket yang sebagian datanya gagal diambil tetap terlihat seperti paket utuh. Pengambilan bisa gagal bila baterai perangkat rendah atau koneksinya metered [S7].

**Live response.** Sesi shell jarak jauh dari portal Defender. Perintah dasar mencakup `processes`, `connections`, `persistence`, `scheduledtasks`, `services`, `fileinfo`, `findfile`, dan `getfile`; perintah lanjutan mencakup `run` (menjalankan skrip dari library), `putfile`, `library`, dan `remediate` [S8]. Setiap perintah dalam sesi tercatat di Command log beserta ID, baris perintah, durasi, dan statusnya [S8], yang berguna sebagai catatan tindakan responder. Batas yang perlu diingat saat merencanakan [S8]:

- `getfile` maksimal 3 GB per file; `putfile` maksimal 300 MB untuk Windows.
- Sesi berakhir setelah 30 menit tidak aktif; satu perintah dibatasi 10 menit, kecuali `getfile`, `findfile`, dan `run` yang dibatasi 30 menit.
- Satu perangkat hanya bisa berada di satu sesi; satu pengguna maksimal lima sesi bersamaan.
- Live response bisa dibatasi pada perangkat yang di-onboard sebagai high-value asset, dan perintah yang tersedia bergantung pada peran RBAC pengguna.

Perhatian: `remediate` menghapus file, menghentikan proses, atau menghapus scheduled task. Itu tindakan eradication, bukan pengambilan bukti, dan tidak dijalankan di tahap ini.

**Memori.** Batas `getfile` 3 GB membuat image memori laptop 16 GB tidak bisa ditarik lewat live response. Menulis image ke disk laptop sendiri juga tidak ideal, karena file sebesar itu menimpa ruang kosong disk yang mungkin berisi artefak terhapus. Untuk `JKT-WS-0388`, Yoga mengambil memori langsung di lantai 3 dengan WinPmem dari drive USB bukti. WinPmem adalah alat akuisisi memori Windows open source (lisensi Apache 2.0) yang memuat driver kernel, mengambil memori dalam format raw, lalu melepas driver itu setelah selesai [S11]. Prinsipnya sama dengan anjuran NIST SP 800-86: alat dijalankan dari media yang disiapkan dan dilindungi, hasil ditulis ke media lain, dan setiap alat dicatat versi serta hash-nya [S2].

Satu hal yang memudahkan urutan kerja: isolasi perangkat di Defender memutus perangkat dari jaringan tetapi tetap mempertahankan koneksi ke layanan Defender, sehingga perangkat tetap dipantau [S7] dan live response tetap bisa dipakai. Jadi untuk host ber-EDR, paket investigasi dan sebagian live response masih bisa dikerjakan setelah isolasi. Yang tidak bisa diulang adalah koneksi jaringan dan sesi yang terputus saat isolasi, serta pekerjaan yang butuh jalur jaringan lain, misalnya menulis image memori ke share di server bukti.

### 1.4 Linux tanpa EDR: live response lewat SSH dan memori dengan AVML atau LiME

`jkt-billing01` tidak punya EDR dan tidak boleh mati. Satu-satunya jalur adalah SSH dari `jkt-bastion01` dengan akun admin, dan semua yang dijalankan di sana harus dipikirkan dulu.

**Alat dan tempat menulis.** NIST SP 800-86 menyarankan alat dijalankan dari media yang terlindung dari perubahan, memakai biner statically linked supaya tidak bergantung pada library sistem, dan hanya memakai alat terpercaya karena perintah sistem bisa sudah diganti penyerang dengan versi yang memberi informasi palsu. Hash setiap alat dihitung dan disimpan, dan perintah persis yang dijalankan dicatat [S2]. RFC 3227 meminta hal yang sama: jangan percaya program di sistem yang diperiksa, jangan menulis transkrip otomatis ke media yang menjadi bukti, dan ingat bahwa rootkit tingkat kernel bisa menyembunyikan aktivitas dari alat apa pun [S1]. Di PT JAB, toolkit Linux disimpan di export NFS read-only dari server bukti `jkt-evid01`, dan hasilnya ditulis ke export kedua yang writable, juga di `jkt-evid01`. Output perintah teks ditangkap di sisi bastion, bukan ditulis ke disk `jkt-billing01`.

**Artefak yang dicari.** AA20-245A memberi daftar khusus Linux: arsipkan `/var/log` dan output journald, ambil skrip atau biner ELF dari `/dev/shm`, `/tmp`, dan `/var/tmp`, cari akun dengan nama mirip akun sistem tetapi punya shell interaktif, dan cek entri `authorized_keys` yang tidak dikenal [S5]. Daftar ini ditambah cron dan unit systemd sebagai tempat persistence yang umum, serta salinan biner proses mencurigakan lewat `/proc/<PID>/exe`, yang masih bisa dibaca walaupun file aslinya sudah dihapus dari disk.

**Memori dengan AVML.** AVML (Acquire Volatile Memory for Linux) dari Microsoft adalah alat akuisisi memori userland untuk x86_64, ditulis dalam Rust dan didistribusikan sebagai biner statis. Ia tidak membutuhkan pengetahuan tentang distro atau kernel target, tidak perlu dikompilasi di target, dan membaca memori dari `/dev/crash`, `/proc/kcore`, atau `/dev/mem`, mencoba satu per satu bila sumbernya tidak ditentukan. Hasilnya berformat LiME, dengan opsi kompresi Snappy dan opsi mengunggah hasil langsung ke tujuan jarak jauh. Dokumentasinya menyebut kernel lockdown menghalangi akuisisi [S9]. Karena itu, sebelum menjalankan AVML, Yoga mengecek mode lockdown di `/sys/kernel/security/lockdown`; bila mode selain `none` aktif, akuisisi memori dari userland kemungkinan gagal, dan rencana cadangannya ditentukan sebelum waktu habis.

**Memori dengan LiME.** LiME (Linux Memory Extractor) adalah loadable kernel module untuk akuisisi memori Linux dan Android. Modulnya dimuat dengan `insmod` dan harus cocok dengan kernel yang berjalan, sehingga biasanya disiapkan sebelum insiden untuk setiap versi kernel server standar. Formatnya `raw`, `padded`, atau `lime`, dan hasilnya bisa ditulis ke file atau dikirim lewat port TCP. Proyeknya menyebut LiME meminimalkan interaksi antara user space dan kernel space selama akuisisi; opsi hash bawaannya menambah kode yang berjalan dan menimpa lebih banyak memori, jadi dipakai hanya bila dibutuhkan [S10]. Mengompilasi modul di server yang sedang diperiksa bukan pilihan yang baik, karena memasang compiler dan header mengubah disk dan memori server itu.

Tabel berikut membantu memilih alat memori Linux; baca kolom "Prasyarat", karena di situ biasanya rencana gagal.

| Alat | Cara kerja | Prasyarat | Kelebihan | Risiko |
|---|---|---|---|---|
| AVML | Userland, biner statis | Salah satu dari `/dev/crash`, `/proc/kcore`, `/dev/mem` bisa dibaca; lockdown tidak aktif | Tidak perlu modul per kernel; bisa langsung dipakai di distro apa pun | Gagal bila lockdown aktif atau sumber memori dibatasi [S9] |
| LiME | Kernel module | Modul yang sudah dikompilasi untuk kernel persis yang berjalan | Interaksi minimal saat akuisisi; bisa kirim lewat TCP [S10] | Modul tidak cocok berarti tidak bisa dimuat; kernel yang mewajibkan modul bertanda tangan bisa menolak modul tidak bertanda tangan (cek kebijakan distro-mu) |

### 1.5 Jangan merusak bukti dan jangan membangunkan penyerang

Pesan Dimas "jangan sampai penyerang sadar" dan teknisi Bandung yang tidak berpengalaman forensik membuat bagian ini penting. Kebanyakan bukti rusak bukan karena penyerang, tetapi karena orang yang berniat baik.

RFC 3227 memberi daftar hal yang dihindari [S1]:

- Jangan mematikan sistem sebelum pengambilan selesai. Banyak bukti hilang, dan penyerang bisa sudah mengubah skrip startup atau shutdown untuk menghancurkan bukti.
- Jangan memercayai program di sistem yang diperiksa.
- Jangan menjalankan program yang mengubah access time semua file di sistem, misalnya `tar` atau `xcopy` atas seluruh disk.
- Ingat bahwa memutus atau memfilter jaringan bisa memicu penghapusan bukti.

NIST SP 800-86 menambahkan pilihan saat sistem akhirnya harus dimatikan: shutdown normal menjalankan pembersihan (menutup file, menghapus file sementara, mungkin membersihkan swap) dan bisa memicu malware membersihkan jejaknya, sedangkan mencabut daya mempertahankan swap dan file sementara tetapi berisiko merusak data di sebagian sistem [S2]. Bila bukti mungkin dibutuhkan, apa yang terlihat di layar didokumentasikan dulu sebelum sistem disentuh [S2].

AA20-245A menambahkan dua hal yang menyangkut penyerang [S5]: jangan menyentuh infrastruktur penyerang, dan jangan berkomunikasi lewat jaringan yang sedang diinvestigasi; koordinasi respons memakai kanal out-of-band. Untuk PT JAB artinya instruksi ke teknisi Bandung disampaikan lewat telepon, bukan lewat email atau chat korporat yang mungkin dibaca dari laptop yang terinfeksi.

Dari prinsip-prinsip itu, PT JAB menulis larangan praktis untuk siapa pun yang menyentuh host terdampak sebelum bukti selesai diambil:

| Jangan | Kenapa | Gantinya |
|---|---|---|
| Restart, shutdown, atau logoff | Memori, koneksi, dan file di tmpfs hilang; skrip shutdown bisa menghapus jejak [S1] | Biarkan menyala; bila perlu, kunci layar |
| Menjalankan full scan antivirus | Mengubah access time banyak file dan bisa menghapus atau mengkarantina sampel | Tunggu sampai bukti selesai; scan dijalankan saat eradication |
| Mencabut kabel jaringan atas inisiatif sendiri | Koneksi aktif hilang, dan malware bisa bereaksi terhadap putusnya koneksi [S1][S3] | Containment dijalankan sesuai rencana IC |
| Membuka file mencurigakan atau domain C2 | Menjalankan malware lagi atau memberi tahu penyerang [S5] | Catat nama dan lokasinya saja |
| Login interaktif dengan akun admin domain ke host terdampak | Kredensial akun berhak tinggi bisa tertinggal di memori host yang dikuasai penyerang | Pakai live response EDR, akun admin lokal khusus IR, atau akun admin dengan hak terbatas |
| Membahas insiden lewat email atau chat korporat dari host terdampak | Penyerang bisa membaca percakapan [S5] | Telepon atau kanal out-of-band |
| Menyalin file dengan alat yang mengubah timestamp tanpa dicatat | Timeline menjadi tidak bisa dipercaya [S1] | Pakai toolkit yang disiapkan; catat setiap perintah |

Pengambilan bukti sendiri bisa terlihat oleh penyerang. Sesi SSH admin muncul di `w`, dan AVML yang membaca 64 GB memori memakan CPU dan I/O. Karena itu jarak antara pengambilan bukti dan containment dibuat sependek mungkin, dan rencana pengambilan bukti memuat pemicu containment segera: bila penyerang terlihat bereaksi (menghapus file, mengganti C2, membuat akun baru), IC memajukan containment tanpa menunggu pukul 16:00.

### 1.6 Hash, evidence log, chain of custody, dan penyimpanan

Pertanyaan keenam Dimas ("bagaimana kita buktikan file-nya tidak berubah?") dijawab dengan tiga hal yang saling melengkapi: hash membuktikan isi file tidak berubah sejak di-hash, evidence log membuktikan apa yang diambil dan bagaimana, dan chain of custody membuktikan siapa memegang bukti di setiap waktu.

RFC 3227 meminta prosedur pengambilan yang transparan dan bisa diulang, dengan checksum dan tanda tangan kriptografis dibuat bila memungkinkan tanpa mengubah bukti [S1]. Ia juga menyebut syarat bukti agar berguna di proses hukum: dapat diterima menurut aturan hukum (admissible), dapat dikaitkan dengan insiden (authentic), menceritakan keseluruhan, bukan satu sudut pandang (complete), tidak meragukan cara pengambilan dan penanganannya (reliable), dan mudah dipahami pengadilan (believable) [S1]. Hash hanya menjawab sebagian dari syarat reliable. File yang diambil dengan cara salah tetap punya hash yang konsisten.

Rev. 2 memberi isi minimal log bukti [S3]:

- Informasi identitas: lokasi, nomor seri, model, hostname, alamat MAC, dan alamat IP komputer.
- Nama, jabatan, dan nomor telepon setiap orang yang mengambil atau menangani bukti.
- Waktu dan tanggal, termasuk zona waktu, setiap kali bukti ditangani.
- Lokasi penyimpanan bukti.

Setiap kali bukti berpindah tangan, formulir chain of custody mencatat perpindahan itu dengan tanda tangan kedua pihak [S3]. RFC 3227 merinci isinya: di mana, kapan, dan oleh siapa bukti ditemukan dan diambil; di mana, kapan, dan oleh siapa bukti ditangani atau diperiksa; siapa memegangnya selama periode berapa dan bagaimana disimpan; dan kapan serta bagaimana bukti berpindah tangan, termasuk nomor pengiriman bila dikirim [S1]. Playbook CISA meringkasnya untuk responder: catat setiap bukti beserta cara, waktu, dan orang yang mengambilnya [S6].

Untuk penyimpanan, RFC 3227 meminta bukti diamankan ketat, akses dibatasi dan dicatat, dan akses tanpa izin bisa dideteksi [S1]. Rev. 3 menambahkan bahwa catatan dan data insiden bisa memuat informasi sensitif (celah yang dieksploitasi, kebocoran terbaru, pengguna yang mungkin bertindak tidak pantas), sehingga kerahasiaan dan integritasnya dijaga dan hanya orang berwenang yang bisa mengaksesnya [S4]. Di PT JAB, server bukti `jkt-evid01` berada di jaringan manajemen, tidak join domain (karena kredensial domain bisa ikut terkompromi), dan setiap akses tercatat. Bukti yang memuat kredensial atau data pelanggan, seperti skrip `export-tagihan.ps1` dan image memori `jkt-billing01`, diberi tanda khusus di evidence log.

### 1.7 Seberapa jauh: proporsional dengan insiden

Kalimat terakhir Dimas ("jangan kebablasan, tapi DPO bilang bisa jadi urusan UU PDP") adalah pertanyaan proporsionalitas. Tidak setiap insiden butuh image memori dan chain of custody formal, tetapi keputusan untuk tidak mengambilnya harus disengaja dan dicatat.

Rev. 2 menyebut pengambilan dan penanganan bukti formal tidak dilakukan untuk setiap insiden; sebagian besar insiden malware tidak memerlukan akuisisi bukti, dan banyak organisasi tidak membutuhkan forensik digital untuk sebagian besar insidennya [S3]. Rev. 3 menegaskan sisi lainnya: walaupun chain of custody formal tidak selalu dijalankan, data insiden yang dikumpulkan tetap dianggap bukti, dan pengambilan serta penyimpanannya mengikuti prosedur preservasi bukti dan kebijakan retensi organisasi, dengan mempertimbangkan kemungkinan penuntutan serta biaya menyimpan data dan perangkat keras atau lunak yang dibutuhkan untuk membukanya di masa depan (RS.AN-07) [S4]. NIST SP 800-86 menyarankan kriteria keputusan mengambil data volatil ditulis sebelumnya, supaya analyst bisa memutuskan cepat, dan risiko pengambilan dari sistem yang menyala ditimbang terhadap nilai informasinya [S2].

PT JAB memakai tiga tingkat yang dipilih IC berdasarkan severity dan kemungkinan dampak hukum:

| Tingkat | Kapan dipakai | Isi | Contoh |
|---|---|---|---|
| Dasar | SEV-3 dan SEV-4 tanpa data pribadi, malware komoditas di satu endpoint | Paket investigasi EDR, sampel, ekspor log; evidence log sederhana | Infostealer yang diblok EDR di satu laptop |
| Lengkap | SEV-2, atau ada kemungkinan kewajiban pelaporan ke regulator, klaim asuransi, atau sengketa kontrak | Dasar ditambah memori setiap host terdampak, artefak persistence, chain of custody formal untuk setiap item | `INC-2026-019` |
| Forensik penuh | SEV-1, dugaan orang dalam, atau kemungkinan proses hukum | Lengkap ditambah image disk penuh, segel fisik, dan biasanya retainer DFIR | Ransomware dengan dugaan pencurian data besar |

`INC-2026-019` masuk tingkat lengkap: SEV-2, server dengan data pribadi pelanggan, dan DPO sudah menilai kemungkinan kewajiban UU PDP. Chain of custody formal di sini murah, cukup satu formulir per item, sedangkan kehilangannya mahal bila nanti regulator atau pelanggan korporat menanyakan dasar kesimpulan PT JAB. Image disk ditunda ke saat host dikeluarkan dari produksi untuk di-reimage atau dibangun ulang, dan retainer PT Forensik Digital Contoh diminta siaga, dipanggil bila pemicu SEV-1 di scope statement terpenuhi. Pukul 13:35 severity memang naik ke SEV-1 setelah koneksi ke database ditemukan (bagian 2.3), dan retainer diaktifkan untuk menganalisis image memori `jkt-billing01`.

## 2. Contoh artefak dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Perintah dijalankan di lingkungan fiktif PT JAB; untuk latihan, jalankan hanya di VM lab terisolasi (bagian 3). Opsi baris perintah AVML, LiME, dan WinPmem bisa berubah antar versi, jadi cek `--help` atau README versi yang kamu pakai sebelum memakai contoh di bawah.

### 2.1 Rencana pengambilan bukti `INC-2026-019`

Rencana ini adalah jawaban Yoga atas pertanyaan 2 sampai 5 Dimas, dikirim 12:25 dan disetujui Dimas 12:28. Baca kolom "Ditunda" dan "Pemicu containment segera", karena dua kolom itu yang biasanya terlupa.

| Host | Siapa dan dari mana | Urutan pengambilan | Ditulis ke | Ditunda (alasan) |
|---|---|---|---|---|
| `JKT-WS-0388` (Windows, EDR) | Yoga: live response dari portal, lalu datang ke lantai 3 untuk memori | Paket investigasi; `connections`, `processes`, `scheduledtasks`, `persistence`; memori WinPmem ke USB bukti; `getfile` sampel, task, dan skrip kredensial | Action center, lalu `jkt-evid01`; USB bukti `USB-E-07` | Image disk: diambil saat laptop ditarik untuk reimage |
| `BDG-WS-0142` (Windows, tanpa EDR) | Teknisi POP Bandung Fajar Nugraha, dipandu Yoga lewat telepon | Foto layar; memori WinPmem; skrip koleksi triage SOC (task, autoruns, event log, Prefetch, profil pengguna) | USB bukti `USB-E-09`, diunggah ke `jkt-evid01` lewat VPN teknisi | Image disk: idem |
| `jkt-billing01` (Linux, tanpa EDR, tidak boleh mati) | Yoga: SSH dari `jkt-bastion01` dengan akun `adm.yoga` | Jam dan selisih NTP; `ss`; `w` dan `last`; cek lockdown; memori AVML; proses dan salinan `/proc/<PID>/exe`; `lsof`; konfigurasi jaringan; `/dev/shm`, `/tmp`, `/var/tmp`; cron, systemd, `authorized_keys`, history; `/var/log` dan journal | Output teks ditangkap di bastion; memori dan arsip ke export NFS `jkt-evid01` | Image disk: diambil saat rebuild (Day 06) |
| Email | Sari: ekspor dari M365 | File `.eml` asli dengan header lengkap dan lampiran | `jkt-evid01` | Purge email dari 9 mailbox menunggu ekspor selesai |
| Log terpusat | Sari | Ekspor hasil query pivot (Day 03); ekspor log firewall dan proxy 30 hari untuk IP terkait | `jkt-evid01` | Tidak ada |

Pemicu containment segera, berlaku sejak 12:30: penyerang terlihat menghapus file atau log, membuat akun atau kunci SSH baru, mengganti domain atau IP C2, atau trafik keluar `jkt-billing01` melonjak. Bila salah satu terjadi, Yoga menghentikan pengambilan dan menelepon Dimas.

Cara membaca elemennya:

- **Siapa dan dari mana** memisahkan pekerjaan jarak jauh dari pekerjaan di tempat. Teknisi Bandung bukan analyst forensik, sehingga tugasnya dibatasi pada langkah yang sudah ditulis dan dijalankan dengan panduan telepon.
- **Ditulis ke** tidak pernah disk host yang diperiksa.
- **Ditunda** menunjukkan bahwa image disk tidak dilupakan, hanya dijadwalkan ke saat yang tidak mengganggu layanan.

**Kapan gagal:** rencana tidak menyebut batas waktu. Pengambilan memori yang molor membuat containment mundur, dan jarak waktu itu memberi penyerang kesempatan melihat aktivitas responder.

### 2.2 Live response `JKT-WS-0388` lewat Defender for Endpoint

Langkah ini menjawab pertanyaan ketiga Dimas untuk host ber-EDR.

**Tujuan:** mengambil keadaan volatil dan artefak persistence `JKT-WS-0388` dari jarak jauh tanpa mengubah host lebih dari yang perlu.

Urutan di portal Defender:

1. Buka halaman perangkat `JKT-WS-0388`, pilih **Collect investigation package**, isi komentar `INC-2026-019 E02`. Paket diunduh dari **Action center** setelah selesai [S7].
2. Pilih **Initiate live response session**, lalu jalankan perintah berikut dan simpan output ke file dengan redirection [S8]:

```
connections -output json > inc019_jkt-ws-0388_connections.json
processes -output json > inc019_jkt-ws-0388_processes.json
scheduledtasks -output json > inc019_jkt-ws-0388_tasks.json
persistence -output json > inc019_jkt-ws-0388_persistence.json
fileinfo "C:\Users\andi.pratama\AppData\Roaming\SysCache\upd.ps1"
getfile "C:\Users\andi.pratama\AppData\Roaming\SysCache\upd.ps1"
getfile "C:\Windows\System32\Tasks\SysCacheUpdate"
getfile "C:\Users\andi.pratama\Documents\export-tagihan.ps1"
```

Penjelasan tiap bagian:

- `connections` dan `processes` dijalankan lebih dulu sesuai order of volatility. `-output json` memberi lebih banyak field daripada tampilan tabel [S8].
- `scheduledtasks` dan `persistence` merekam mekanisme bertahan sebelum ada yang menghapusnya.
- `fileinfo` sebelum `getfile` mencatat metadata dan hash file di perangkat, sehingga hash file yang diunduh bisa dicocokkan.
- `C:\Windows\System32\Tasks\SysCacheUpdate` adalah definisi XML scheduled task, berisi perintah dan jadwal yang dijalankan task itu.
- `export-tagihan.ps1` berisi password `svc_billing`. File ini diambil sebagai bukti cara kredensial bocor, lalu ditandai sensitif di evidence log.

Keluaran ilustrasi dari `connections` (diringkas):

```
process          pid   protocol  local_address      remote_address       state
powershell.exe   7412  TCP       10.10.23.88:52811  203.0.113.77:443     ESTABLISHED
OUTLOOK.EXE      5120  TCP       10.10.23.88:52790  (layanan M365)       ESTABLISHED
```

Cara membaca hasil: `powershell.exe` PID 7412 memegang koneksi ke C2 saat itu. PID ini dicari di output `processes` untuk melihat parent dan baris perintahnya, dan dicatat untuk dicocokkan dengan image memori.

3. Ambil memori di tempat. Yoga datang ke lantai 3 pukul 12:38 dengan drive USB bukti `USB-E-07`, yang berisi WinPmem dengan hash yang sudah dicatat dan ruang kosong untuk output. Andi diminta menyimpan pekerjaannya, tidak me-restart laptop, dan memakai laptop cadangan sampai sore; atasannya sudah diberi tahu. Perintahnya dijalankan dari command prompt administrator yang dibuka dengan akun admin lokal khusus IR:

```
E:\tools\winpmem_mini_x64.exe E:\INC-2026-019\E01_JKT-WS-0388_mem.raw
```

Penjelasan: alat dan output sama-sama di drive USB `E:`, sehingga disk laptop tidak ditulisi image. Nama file output memuat nomor insiden, nomor bukti, dan hostname. Nama biner dan opsi WinPmem berbeda antar rilis; cek README rilis yang kamu pakai [S11].

Setelah selesai, hash dihitung di drive yang sama dan dicatat:

```
certutil -hashfile E:\INC-2026-019\E01_JKT-WS-0388_mem.raw SHA256
```

**Variasi:** bila host ber-EDR berada di lokasi tanpa orang yang bisa datang, sebagian tim menjalankan alat akuisisi lewat `putfile` dan `run`, lalu menulis image ke share jaringan khusus bukti. Cara ini harus selesai sebelum isolasi, karena isolasi memutus jalur ke share itu.

**Kapan gagal:** paket investigasi gagal karena baterai rendah atau koneksi metered [S7]; live response tidak tersedia karena perangkat di-onboard sebagai high-value asset dengan aksi terbatas atau peran RBAC-mu tidak mencakup perintah lanjutan [S8]; atau WinPmem diblok oleh kebijakan driver. Untuk yang terakhir, cek kebijakan driver di lab sebelum insiden, bukan saat insiden.

### 2.3 Live response `jkt-billing01` lewat SSH

Langkah ini menjawab pertanyaan keempat Dimas: mengambil bukti dari server Linux yang tidak boleh mati, tanpa EDR.

**Tujuan:** menangkap data volatil, memori, dan artefak persistence `jkt-billing01` dengan alat terpercaya, tanpa menulis output ke disk server.

Persiapan di `jkt-billing01` (dengan `sudo`, dicatat di case notes): mount export toolkit read-only dan export output dari `jkt-evid01`.

```
sudo mkdir -p /mnt/irkit /mnt/irout
sudo mount -o ro,nolock jkt-evid01:/export/irkit /mnt/irkit
sudo mount -o rw,nolock jkt-evid01:/export/irout/INC-2026-019 /mnt/irout
```

Perintah volatil dijalankan dari `jkt-bastion01`, dengan output ditangkap di bastion. `$K` adalah folder biner statis di toolkit (versi dan hash-nya tercatat di daftar toolkit):

```
K=/mnt/irkit/bin
H=jkt-billing01
ssh adm.yoga@$H "date -u; date; chronyc tracking"      > E04_00_waktu.txt
ssh adm.yoga@$H "sudo $K/ss -tanp"                      > E04_01_koneksi.txt
ssh adm.yoga@$H "$K/w; $K/last -Fw -n 50"               > E04_02_sesi.txt
ssh adm.yoga@$H "cat /sys/kernel/security/lockdown"     > E04_03_lockdown.txt
```

Bila lockdown menunjukkan `[none]`, memori diambil dengan AVML dari toolkit, ditulis ke export output:

```
ssh adm.yoga@$H "sudo /mnt/irkit/avml --compress /mnt/irout/E05_jkt-billing01_mem.lime.snappy"
```

Lalu proses, biner, dan file terbuka:

```
ssh adm.yoga@$H "sudo $K/ps -eo pid,ppid,user,lstart,args --forest" > E04_04_proses.txt
ssh adm.yoga@$H "sudo ls -l /proc/23817/exe /proc/23817/cwd; sudo cat /proc/23817/cmdline | tr '\0' ' '" > E04_05_pid23817.txt
ssh adm.yoga@$H "sudo cp /proc/23817/exe /mnt/irout/E06_kworkerd_pid23817.bin"
ssh adm.yoga@$H "sudo $K/lsof -p 23817"                 > E04_06_lsof.txt
ssh adm.yoga@$H "$K/ip addr; $K/ip route"               > E04_07_jaringan.txt
```

Terakhir artefak di disk dan log:

```
ssh adm.yoga@$H "sudo ls -la --time-style=full-iso /dev/shm /dev/shm/.cache /tmp /var/tmp" > E04_08_tmpfs.txt
ssh adm.yoga@$H "sudo crontab -l -u svc_billing; sudo ls -la /var/spool/cron/crontabs" > E04_09_cron.txt
ssh adm.yoga@$H "sudo cat /home/svc_billing/.ssh/authorized_keys /home/svc_billing/.bash_history" > E04_10_svc_billing.txt
ssh adm.yoga@$H "sudo tar -czf /mnt/irout/E07_var_log.tar.gz -C / var/log"
ssh adm.yoga@$H "sudo journalctl --since '2026-10-12 00:00' -o short-iso" > E07_journal.txt
```

Penjelasan tiap bagian:

- Biner dipanggil dari `$K` (toolkit), bukan dari `PATH` server, sesuai anjuran memakai alat terpercaya [S1][S2]. Perintah sederhana seperti `date`, `cat`, dan `chronyc` di sini memakai biner sistem; ini dicatat sebagai keterbatasan.
- `date -u; date` dan `chronyc tracking` mencatat jam UTC, jam lokal, dan selisih terhadap sumber NTP (langkah 0). Bila server memakai layanan waktu lain, ganti perintah ketiga.
- `ss -tanp` menampilkan koneksi TCP beserta proses pemiliknya; `sudo` dibutuhkan untuk melihat proses milik pengguna lain.
- AVML ditulis langsung ke export NFS, bukan ke disk server. `--compress` memakai kompresi Snappy [S9].
- PID 23817 adalah `kworkerd` yang terlihat di output `ss`. Menyalin `/proc/23817/exe` mengambil biner yang sedang berjalan walaupun file aslinya sudah dihapus.
- Lokasi crontab berbeda antar distro: `/var/spool/cron/crontabs` di Debian dan Ubuntu, `/var/spool/cron` di keluarga RHEL.
- `tar` dijalankan untuk `/var/log` saja, bukan seluruh disk, karena `tar` mengubah access time file yang dibacanya [S1]. Perubahan itu dicatat.

Keluaran ilustrasi dari `E04_01_koneksi.txt` (diringkas):

```
State  Local Address:Port   Peer Address:Port    Process
ESTAB  10.20.5.21:44102     203.0.113.77:443     users:(("kworkerd",pid=23817,fd=5))
ESTAB  10.20.5.21:41876     10.20.5.30:5432      users:(("kworkerd",pid=23817,fd=7))
ESTAB  10.20.5.21:22        10.20.1.20:50544     users:(("sshd",pid=24410,fd=4))
ESTAB  10.20.5.21:8443      10.20.1.40:61022     users:(("java",pid=1822,fd=211))
```

Cara membaca hasil:

- Baris pertama: `kworkerd` memegang koneksi ke C2. Nama prosesnya meniru thread kernel (`kworker`), tetapi thread kernel asli tidak membuka socket jaringan dari user space.
- Baris kedua adalah temuan terpenting: proses yang sama terhubung ke `10.20.5.30:5432`, port PostgreSQL di server database billing. Ini bukti bahwa penyerang punya koneksi aktif ke database pelanggan, dan memori AVML menjadi bukti kunci untuk menilai apakah data diambil. Log database hanya mencatat koneksi, bukan query, sehingga akses ke tabel pelanggan tidak bisa disingkirkan. Yoga langsung meneruskannya ke Sari dan Dimas, dan Dimas menaikkan severity ke SEV-1 pukul 13:35 dengan aturan "ragu, pilih lebih tinggi" (Day 05).
- Baris ketiga adalah sesi Yoga sendiri dari `jkt-bastion01` (`10.20.1.20`). Sesi responder harus dikenali supaya tidak dibaca sebagai aktivitas penyerang.
- Baris keempat adalah aplikasi billing yang melayani portal; koneksi ini normal.

**Variasi:** bila lockdown aktif sehingga AVML gagal, dan modul LiME untuk kernel itu sudah disiapkan di toolkit, LiME dimuat dari toolkit dengan output ke export NFS atau ke port TCP di `jkt-evid01` [S10]. Bila keduanya tidak bisa, catat alasannya, ambil salinan biner proses dan `/proc/<PID>/maps` sebagai pengganti terbatas, dan pertimbangkan bantuan retainer.

**Kapan gagal:** export NFS tidak bisa di-mount karena firewall data center atau paket klien NFS tidak terpasang. Uji mount ini setiap kuartal bersama uji akses on-call, bukan saat insiden. Kegagalan lain: AVML menghasilkan file jauh lebih kecil dari RAM. Cek ukuran dan pesan error sebelum menganggap memori sudah aman.

### 2.4 Panduan telepon untuk teknisi Bandung

`BDG-WS-0142` tidak punya EDR dan tidak ada analyst di Bandung. Panduan ini dibacakan Yoga lewat telepon ke teknisi POP Bandung Fajar Nugraha pukul 13:55. Panduannya sengaja pendek dan hanya berisi langkah yang sudah diuji di lab.

```
PANDUAN BUKTI BDG-WS-0142 | INC-2026-019 | disampaikan lewat telepon, bukan chat

SEBELUM MENYENTUH
1. Foto layar laptop apa adanya dengan ponsel, termasuk jam di pojok layar.
2. Jangan restart, jangan shutdown, jangan cabut kabel, jangan jalankan antivirus.
3. Catat jam mulai di formulir chain of custody (format WIB, tanggal lengkap).

PENGAMBILAN (dari USB bukti USB-E-09, tidak ada file yang disalin ke laptop)
4. Colokkan USB-E-09. Buka Command Prompt "Run as administrator"
   dengan akun admin lokal IR (password dibacakan, langsung diganti setelah selesai).
5. Jalankan E:\tools\winpmem_mini_x64.exe E:\INC-2026-019\E08_BDG-WS-0142_mem.raw
   Tunggu sampai selesai. Bacakan ukuran file ke saya.
6. Jalankan E:\tools\koleksi-triage.cmd  (output ke E:\INC-2026-019\E09\)
7. Jalankan certutil -hashfile untuk setiap file hasil; bacakan 8 karakter
   pertama tiap hash, saya catat di sisi Jakarta.

SESUDAH
8. Lepas USB dengan aman. Masukkan ke kantong bukti, segel, tanda tangan di segel.
9. Unggah isi USB ke jkt-evid01 lewat VPN teknisi; saya cocokkan hash.
10. USB disimpan di lemari terkunci POP Bandung sampai diambil kurir Jumat.
```

Cara membaca elemennya:

- **Foto layar dulu** mengikuti anjuran mendokumentasikan apa yang terlihat sebelum menyentuh sistem [S2].
- **Hash dibacakan sebagian** memberi pengecekan independen di Jakarta: bila hash di `jkt-evid01` setelah unggah cocok dengan yang dibacakan, file tidak berubah dalam perjalanan.
- **Panduan lewat telepon** mengikuti anjuran berkomunikasi di luar jaringan yang sedang diinvestigasi [S5].

**Kapan gagal:** teknisi diberi terlalu banyak pilihan atau istilah forensik, lalu improvisasi. Panduan untuk non-analyst harus satu jalur, dengan titik berhenti yang jelas ("bacakan ke saya").

### 2.5 Evidence log dan formulir chain of custody

Evidence log menjawab pertanyaan keenam Dimas. Tabel berikut adalah cuplikan evidence log `INC-2026-019` di `jkt-evid01`; hash ditulis disingkat di sini, sedangkan di log aslinya ditulis lengkap.

| ID | Deskripsi | Sumber (host, IP, identitas) | Diambil oleh, waktu WIB | Metode dan alat | SHA-256 (awal) | Lokasi | Catatan |
|---|---|---|---|---|---|---|---|
| E01 | Memori `JKT-WS-0388`, 16 GB raw | `JKT-WS-0388`, `10.10.23.88`, S/N laptop dari CMDB | Yoga Pratama, 13 Okt 12:42 sampai 12:53 | WinPmem dari `USB-E-07` | `5c1e09a4...` | `USB-E-07`, salinan di `jkt-evid01` | Sensitif |
| E02 | Paket investigasi EDR | `JKT-WS-0388` | Yoga Pratama, 12:31 | Defender Collect investigation package | `a83f7d20...` | `jkt-evid01` | `CollectionSummaryReport.xls` dicek, tidak ada error |
| E03 | `upd.ps1`, task `SysCacheUpdate`, `export-tagihan.ps1` | `JKT-WS-0388` | Yoga Pratama, 12:36 | Live response `getfile` | per file | `jkt-evid01` | `export-tagihan.ps1` berisi kredensial: akses terbatas |
| E04 | Output live response teks | `jkt-billing01`, `10.20.5.21` | Yoga Pratama, 13:12 sampai 13:58 | SSH dari `jkt-bastion01`, toolkit `/mnt/irkit` | per file | `jkt-evid01` | Daftar perintah di case notes |
| E05 | Memori `jkt-billing01`, LiME terkompresi | `jkt-billing01` | Yoga Pratama, 13:20 sampai 13:41 | AVML `--compress` ke NFS | `e7720b5f...` | `jkt-evid01` | Sensitif: data pelanggan mungkin ada di memori |
| E08 | Memori `BDG-WS-0142`, 8 GB raw | `BDG-WS-0142`, `10.30.14.42` | Fajar Nugraha, 14:05 sampai 14:13, dipandu Yoga | WinPmem dari `USB-E-09` | `31b6c0de...` | `USB-E-09` (POP Bandung), salinan di `jkt-evid01` | Hash dibacakan lewat telepon dan cocok |
| E10 | Email asli `.eml` dan lampiran | Mailbox `andi.pratama` | Sari Kusuma, 13:05 | Ekspor dari M365 | per file | `jkt-evid01` | Purge setelah ekspor |
| E12 | Log firewall dan proxy 30 hari untuk IP terkait | Splunk index `firewall`, `proxy` | Sari Kusuma, 15:20 | Ekspor hasil search | per file | `jkt-evid01` | Retensi diperpanjang 1 tahun |

Formulir chain of custody untuk satu item, mengikuti isi minimal Rev. 2 dan RFC 3227 [S3][S1]:

```
CHAIN OF CUSTODY | INC-2026-019-E08 | Memori BDG-WS-0142 (raw, 8 GB)
Identitas sumber : BDG-WS-0142, IP 10.30.14.42, MAC dan S/N dari CMDB,
                   lokasi: kantor Bandung lantai 2
Media            : USB-E-09 (S/N dicatat), disegel kantong bukti No. 0091
SHA-256          : 31b6c0de... (lengkap di evidence log)

No  Waktu (WIB)         Dari              Ke                 Tujuan / kondisi              Tanda tangan
1   2026-10-13 14:13    (diambil)         Fajar Nugraha      Akuisisi selesai, segel utuh   FN
2   2026-10-13 14:30    Fajar Nugraha     Lemari POP Bdg     Disimpan, kunci dipegang FN    FN
3   2026-10-16 10:05    Lemari POP Bdg    Kurir internal     Dikirim, resi INT-1016-022     FN, kurir
4   2026-10-16 17:40    Kurir internal    Yoga Pratama       Diterima Jakarta, segel utuh   kurir, YP
5   2026-10-16 17:55    Yoga Pratama      Lemari bukti SOC   Hash dicek ulang: cocok        YP
```

Cara membaca elemennya:

- **Setiap baris adalah satu perpindahan**, dengan waktu lengkap dan zona waktu, dari siapa ke siapa, dan kondisi segel.
- **Baris 5** menunjukkan hash dicek ulang setelah perjalanan. Hash yang cocok dengan yang dicatat saat akuisisi membuktikan isi tidak berubah selama dipindahkan.
- Salinan di `jkt-evid01` dipakai untuk analisis; media aslinya disimpan dan tidak dianalisis langsung, sesuai prinsip bekerja dari salinan [S1].

**Kapan gagal:** satu perpindahan tidak tercatat, misalnya USB "dititipkan" ke rekan tanpa formulir. Celah satu baris membuat seluruh rantai bisa dipertanyakan.

## 3. Lab praktik (di VM lab terisolasi)

Semua langkah dijalankan di VM lab dengan snapshot. Pakai beacon tiruan dari lab Day 03 sebagai "aktivitas penyerang". Jangan memakai data, nama, atau kejadian dari pekerjaan nyata.

1. **Siapkan toolkit.** Buat folder toolkit untuk Linux (AVML dan beberapa biner statis) dan untuk Windows (WinPmem). Catat versi, sumber unduhan resmi, dan SHA-256 setiap alat di `latihan/day04-toolkit.md`. Untuk Linux, sajikan toolkit dari VM terpisah lewat NFS read-only, dengan export kedua untuk output.
2. **Cek prasyarat Linux.** Di VM Linux, baca `/sys/kernel/security/lockdown` dan catat hasilnya. Bila memungkinkan, ulangi di VM dengan Secure Boot aktif dan catat perbedaannya.
3. **Live response Linux.** Dari VM lain yang berperan sebagai bastion, jalankan urutan perintah bagian 2.3 terhadap VM Linux yang menjalankan beacon tiruan. Tangkap output di sisi bastion. Pastikan proses beacon, koneksinya, dan cron-nya terlihat di output.
4. **Memori Linux.** Ambil memori dengan AVML ke export NFS. Hitung SHA-256 di VM bukti. Cari string domain beacon tiruan di image dengan `strings` dan `grep` untuk memastikan image berisi data yang masuk akal.
5. **Memori Windows.** Tambahkan virtual disk kedua ke VM Windows sebagai pengganti USB bukti. Jalankan WinPmem dari disk itu dengan output ke disk yang sama, lalu hitung hash dengan `certutil`. Catat waktu yang dibutuhkan dan ukuran hasil dibandingkan RAM VM.
6. **Bandingkan urutan.** Ulangi langkah 3 dengan urutan terbalik (konfigurasi dan file dulu, koneksi terakhir) sambil beacon tiruan diatur hanya hidup 2 menit setiap 10 menit. Catat apa yang hilang dari output.
7. **Dokumen.** Isi evidence log untuk semua item dengan kolom bagian 2.5, dan satu formulir chain of custody untuk image memori Linux yang dipindahkan dari VM bukti ke penyimpanan lain, lengkap dengan cek ulang hash.

**Hasil yang sebaiknya tersimpan:**

- `latihan/day04-toolkit.md` berisi daftar alat dengan versi, sumber, dan hash.
- Output live response Linux per file, dengan nama yang memuat nomor bukti.
- Hash SHA-256 image memori Linux dan Windows, dan hasil pengecekan `strings`.
- Satu paragraf hasil langkah 6 tentang data yang hilang karena urutan salah.
- Evidence log dan satu formulir chain of custody yang lengkap.

**Variasi tantangan:** anggap VM Linux tidak boleh di-mount NFS. Rancang cara mengambil memori tanpa menulis ke disk VM itu (misalnya lewat jaringan ke VM bukti) dan catat risiko serta jejak yang ditinggalkan cara itu.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat pengambilan bukti dikerjakan di bawah tekanan waktu. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| AVML gagal membaca memori | Kernel lockdown aktif atau sumber memori dibatasi | Cek `/sys/kernel/security/lockdown`; siapkan LiME per kernel atau rencana cadangan sebelum insiden [S9][S10] |
| Modul LiME tidak bisa dimuat | Modul tidak cocok dengan kernel yang berjalan, atau kebijakan modul bertanda tangan | Siapkan modul per versi kernel standar; jangan mengompilasi di server yang diperiksa [S10] |
| `getfile` gagal untuk image memori | Ukuran melebihi batas 3 GB | Ambil di tempat ke media bukti, atau ke share bukti sebelum isolasi [S8] |
| Paket investigasi tidak lengkap | Baterai rendah, koneksi metered, atau sebagian perintah gagal | Cek `CollectionSummaryReport.xls`; ulangi atau ambil artefak yang hilang lewat live response [S7] |
| Live response tidak tersedia di perangkat | High-value asset dengan aksi terbatas, atau peran RBAC tidak mencukupi | Cek konfigurasi aksi terpilih dan peran sebelum insiden [S8] |
| Hash file di server bukti berbeda dengan hash saat akuisisi | File rusak saat transfer, atau hash dihitung atas file yang berbeda | Ulangi transfer dari media asli; catat kedua hash dan penyebabnya |
| Timeline dari image memori tidak cocok dengan log | Jam sistem tidak tersinkron atau zona waktu tidak dicatat | Catat jam dan selisih NTP sebelum pengambilan (langkah 0) [S1] |
| Penyerang terlihat bereaksi saat bukti diambil | Aktivitas responder terlihat (sesi SSH, beban CPU) | Jalankan pemicu containment segera; catat waktu dan reaksinya |

## 5. Kesalahan umum dan jebakan

- Mematikan atau me-restart host "supaya aman" sebelum bukti diambil. Memori, koneksi, dan file di tmpfs hilang, dan skrip shutdown bisa menghapus jejak [S1][S2].
- Mengisolasi atau menghapus malware sebelum artefak diambil. AA20-245A menyebut ini kesalahan umum yang menghilangkan data volatil dan membuat penyerang mengubah taktik [S5].
- Menjalankan alat dari host yang diperiksa atau menulis output ke disknya [S1][S2].
- Menganggap hash membuktikan bukti diambil dengan benar. Hash hanya membuktikan isi tidak berubah sejak di-hash [S1].
- Menjalankan `remediate` atau full scan antivirus di tahap pengambilan bukti.
- Mengompilasi modul LiME atau memasang paket di server yang sedang diperiksa [S10].
- Login interaktif dengan akun admin domain ke host yang dikuasai penyerang.
- Memberi instruksi ke orang non-forensik lewat chat korporat, atau dengan banyak pilihan [S5].
- Melewatkan chain of custody karena "tidak akan ke pengadilan". Data insiden tetap bukti, dan regulator, auditor, atau pelanggan bisa menanyakan dasarnya [S4].
- Tidak mencatat keputusan untuk tidak mengambil bukti tertentu. Keputusan proporsional tetap harus tertulis beserta alasannya [S2][S3].
- Lupa log terpusat. Ekspor dan perpanjang retensi log yang relevan, karena retensi tetap berjalan selama investigasi [S5].

## 6. Catatan terkini

Bagian ini menampung umur dokumen acuan dan detail versi alat. Berguna saat mengutip sumber atau memilih alat, tetapi tidak mengubah urutan kerja di Day ini.

- **RFC 3227** terbit Februari 2002 sebagai BCP 55, ditulis Dominique Brezinski dan Tom Killalea [S1]. Contoh alatnya (CD read-only, The Coroner's Toolkit) sudah usang, tetapi prinsip dan urutan volatilitasnya masih menjadi rujukan baku.
- **NIST SP 800-86** terbit Agustus 2006 [S2]. Contoh medianya (disket, CD-R) dan hash SHA-1 sudah usang; catatan ini memakai SHA-256. Urutan pengambilan data volatilnya masih dipakai luas.
- **NIST SP 800-61 Rev. 3** (April 2025) meringkas pengambilan bukti di RS.AN-06 dan RS.AN-07 dan tidak lagi memuat bagian Evidence Gathering and Handling seperti Rev. 2 bagian 3.3.2 [S3][S4].
- **Dokumentasi Defender for Endpoint** yang diperiksa bertanggal 23 Juli 2026 (response actions) dan 28 Juli 2026 (live response) [S7][S8]. Batas ukuran, timeout, dan dukungan OS sering berubah; cek halaman terbaru sebelum mengandalkan angka di Day ini. Halaman response actions juga menyebut isolasi otomatis dilepas setelah tujuh hari; cek apakah ini berlaku untuk OS dan tenant-mu sebelum merencanakan isolasi panjang.
- **AVML, LiME, dan WinPmem** tidak menampilkan nomor rilis di halaman repo yang diperiksa; versi yang dipakai dicatat dari halaman rilis saat menyiapkan toolkit [S9][S10][S11]. Matriks pengujian AVML mencakup antara lain Ubuntu 16.04 sampai 26.04, RHEL 7.9 sampai 10.2, dan Debian 11 sampai 13 [S9].

## 7. Cheat sheet

```
PRINSIP: bukti dulu, containment kemudian (kecuali kerusakan berjalan cepat)
  ambil yang paling cepat hilang dulu | alat dari media terpercaya
  output BUKAN ke disk host | catat setiap perintah | kerja dari salinan

URUTAN (PT JAB, dari NIST SP 800-86 + RFC 3227):
  0 jam + selisih NTP | 1 koneksi | 2 sesi login | 3 memori | 4 proses + /proc/PID/exe
  5 file terbuka | 6 konfigurasi jaringan | 7 tmpfs (/dev/shm,/tmp,/var/tmp, Temp)
  8 persistence + log lokal | 9 log terpusat (ekspor, perpanjang retensi)

WINDOWS + DEFENDER: Collect investigation package (cek CollectionSummaryReport.xls)
  live response: connections, processes, scheduledtasks, persistence, fileinfo, getfile
  getfile maks 3 GB | putfile Windows 300 MB | idle 30 mnt | 1 sesi per perangkat
  isolasi tetap terhubung ke Defender | JANGAN remediate saat ambil bukti
  memori: WinPmem dari USB bukti, output ke USB, certutil -hashfile SHA256

LINUX TANPA EDR: SSH dari bastion, toolkit NFS read-only, output ke NFS lain
  ss -tanp | w; last | cek /sys/kernel/security/lockdown | AVML | ps --forest
  cp /proc/PID/exe | lsof -p | ip addr/route | /dev/shm /tmp /var/tmp
  cron, systemd, authorized_keys, history | tar /var/log | journalctl
  AVML: userland, tanpa modul, gagal bila lockdown | LiME: modul per kernel, siapkan dulu

JANGAN: restart/shutdown | full scan AV | cabut kabel sendiri | buka file/domain C2
  login admin domain ke host terdampak | instruksi lewat chat korporat

INTEGRITAS: hash (isi tidak berubah) + evidence log (apa, bagaimana)
  + chain of custody (siapa memegang kapan) + server bukti (akses tercatat)
  log bukti: identitas sumber | siapa (nama, jabatan, telepon) | waktu + zona | lokasi

PROPORSIONAL: dasar (SEV-3/4) | lengkap (SEV-2, regulator/kontrak) | forensik penuh (SEV-1, hukum)
  keputusan TIDAK mengambil bukti juga dicatat + alasan
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Manajer NOC Bambang Hartono berkata, "Matikan saja `jkt-billing01` sekarang supaya penyerang langsung berhenti, nanti disk-nya di-image. Semua bukti ada di disk." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Banyak bukti hanya ada di memori dan keadaan berjalan: proses `kworkerd`, koneksinya ke C2 dan ke database, sesi login, dan biner di `/dev/shm` yang tersimpan di tmpfs. Semua itu hilang saat server dimatikan. RFC 3227 juga mengingatkan bahwa skrip startup atau shutdown bisa sudah diubah penyerang untuk menghancurkan bukti. Selain itu, mematikan layanan pelanggan adalah keputusan executive sponsor, bukan keputusan teknis. Lihat bagian 1.1, 1.2, dan 1.5.

</details>

**2. Skenario keputusan.** Pukul 13:50 teknisi Bandung menelepon: "Laptop Dewi lambat sekali. Saya restart dulu dan jalankan full scan antivirus ya, biar bersih sebelum diambil datanya?" Jawaban mana yang tepat?

- A. Boleh, karena scan antivirus membantu menemukan malware sebelum memori diambil.
- B. Jangan restart dan jangan scan. Foto layar, biarkan laptop menyala, lalu ikuti panduan pengambilan memori dan triage dari USB bukti.
- C. Cabut kabel jaringan dulu supaya aman, baru tunggu instruksi.

<details><summary>Jawaban</summary>

B. Restart menghapus memori dan koneksi yang sedang berjalan, dan full scan mengubah access time banyak file serta bisa menghapus atau mengkarantina sampel. Foto layar dulu mengikuti anjuran mendokumentasikan apa yang terlihat sebelum menyentuh sistem. A keliru karena menghancurkan bukti volatil dan mencampur tahap eradication ke tahap pengambilan bukti. C keliru karena mencabut kabel adalah containment yang diputuskan IC, menghilangkan koneksi aktif, dan bisa memicu reaksi malware. Lihat bagian 1.5 dan 2.4.

</details>

**3. Pertanyaan jebakan.** "Hash SHA-256 image memori sudah dicatat, jadi bukti itu sah dan pasti diterima siapa pun." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Hash hanya membuktikan isi file tidak berubah sejak hash dihitung. Hash tidak membuktikan file diambil dengan cara yang benar, dari host yang benar, dengan alat yang terpercaya, atau bahwa tidak ada perpindahan tanpa catatan. Itu dijawab evidence log (identitas sumber, siapa, kapan, metode, lokasi) dan chain of custody (setiap perpindahan dengan waktu dan tanda tangan). RFC 3227 menyebut syarat bukti mencakup admissible, authentic, complete, reliable, dan believable. Lihat bagian 1.6 dan 2.5.

</details>

**4. Skenario keputusan.** Yoga harus mengambil memori `jkt-billing01` (Linux, tanpa EDR, tidak boleh mati). Lockdown menunjukkan `[none]`. Pilihan mana yang paling tepat?

- A. Memasang compiler dan header kernel di `jkt-billing01`, mengompilasi LiME di sana, lalu menulis image ke `/var/tmp` server.
- B. Menjalankan AVML dari toolkit read-only, menulis image langsung ke export NFS di `jkt-evid01`, lalu menghitung hash di server bukti dan mencatat perintahnya.
- C. Melewatkan memori dan langsung menyalin seluruh disk dengan `tar` supaya cepat.

<details><summary>Jawaban</summary>

B. AVML adalah alat userland berbentuk biner statis yang tidak perlu dikompilasi untuk kernel target, dan bisa dipakai karena lockdown tidak aktif. Alat dijalankan dari media terpercaya dan output ditulis ke luar disk server. A keliru karena memasang paket dan mengompilasi modul mengubah disk dan memori server yang sedang diperiksa, dan menulis image ke disk server menimpa artefak. C keliru karena memori adalah bukti kunci untuk koneksi ke database, dan `tar` atas seluruh disk mengubah access time semua file yang dibaca. Lihat bagian 1.4, 1.5, dan 2.3.

</details>

**5. Jelaskan ulang.** Jelaskan kepada teknisi POP Bandung Fajar Nugraha, dalam tiga kalimat, kenapa laptop Dewi tidak boleh di-restart dan apa yang harus ia lakukan.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Laptop ini sedang dipakai penyerang, dan jejak yang paling penting ada di memori yang langsung hilang begitu laptop di-restart atau dimatikan. Jadi tolong biarkan menyala, jangan cabut kabel, jangan jalankan antivirus, dan foto layarnya dulu. Setelah itu kita ambil datanya bersama dari USB yang sudah disiapkan, langkah demi langkah lewat telepon ini, dan setiap selesai satu langkah tolong bacakan hasilnya ke saya."

Kesalahan yang sering muncul:
- Memakai istilah seperti "volatile", "order of volatility", atau "akuisisi" yang tidak dipahami teknisi.
- Memberi beberapa pilihan alat atau cara sehingga teknisi berimprovisasi.
- Tidak memberi titik berhenti yang jelas, sehingga teknisi melanjutkan sendiri saat ada error.

</details>

**6. Pertanyaan jebakan.** "PT JAB tidak berniat menuntut siapa pun, jadi chain of custody untuk `INC-2026-019` tidak perlu." Benarkah?

<details><summary>Jawaban</summary>

Tidak tepat. Rev. 2 memang menyebut bukti formal tidak dibutuhkan untuk setiap insiden, tetapi Rev. 3 menegaskan data insiden tetap dianggap bukti, dan pengambilannya mempertimbangkan kemungkinan penuntutan serta biaya penyimpanan. `INC-2026-019` adalah SEV-2 dengan server berisi data pribadi pelanggan, dan DPO menilai kemungkinan kewajiban UU PDP, sehingga regulator atau pelanggan korporat bisa menanyakan dasar kesimpulan PT JAB. Chain of custody di sini murah, sedangkan kehilangannya mahal; keputusan proporsionalnya adalah tingkat lengkap. Lihat bagian 1.7.

</details>

**7. Interview question (English).** "You need to contain a compromised Linux server that can't be taken offline and has no EDR. How do you preserve evidence first?"

<details><summary>Sample answer</summary>

"First I agree a short time box with the incident commander and set triggers for containing immediately if the attacker reacts, because collecting evidence can itself be noticed. I connect over SSH from a bastion with a dedicated admin account and run trusted static tools from a read-only share, capturing text output on my side and writing large files to a separate evidence share, never to the server's own disk. I follow the order of volatility: system time and clock offset, network connections, logged-in sessions, then memory, then processes, including a copy of any suspicious binary from /proc, open files, network configuration, temporary filesystems like /dev/shm, persistence locations such as cron, systemd and authorized_keys, and finally /var/log and the journal. For memory I prefer AVML because it needs no kernel-specific module, after checking kernel lockdown; if that blocks it, I use a LiME module prepared in advance for that kernel rather than compiling on the box. Every item gets a SHA-256 hash, an evidence log entry with who, when, how and where it's stored, and a chain of custody record, and I also export the relevant central logs before containment."

What makes this answer strong: it balances evidence against the risk of tipping off the attacker, keeps writes off the suspect disk, follows a justified order, names a realistic memory tool with its prerequisite and fallback, and closes with integrity and documentation.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | RFC 3227: Guidelines for Evidence Collection and Archiving (BCP 55) | https://www.rfc-editor.org/rfc/rfc3227.txt | primer | Februari 2002 (lebih dari 3 tahun); diakses 2026-10-15 | Tinggi untuk prinsip: urutan volatilitas, hal yang dihindari, syarat bukti, prosedur pengambilan, chain of custody, penyimpanan, toolkit |
| S2 | NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response (PDF) | https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-86.pdf | primer | Agustus 2006 (lebih dari 3 tahun); diakses 2026-10-15 | Tinggi. Bagian 5.2.1 (keputusan mengambil data volatil, persiapan alat, jenis data, urutan pengambilan) dan 5.2.2 (shutdown normal vs cabut daya) |
| S3 | NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide (PDF) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf | primer | Agustus 2012 (lebih dari 3 tahun, digantikan Rev. 3); diakses 2026-10-15 | Tinggi untuk bagian 3.3.1 (kerusakan tambahan saat containment) dan 3.3.2 (isi log bukti, chain of custody, catatan kaki tentang insiden malware) |
| S4 | NIST SP 800-61 Rev. 3 (PDF) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf | primer | April 2025; diakses 2026-10-15 | Tinggi. RS.AN-06 dan RS.AN-07 |
| S5 | CISA: Technical Approaches to Uncovering and Remediating Malicious Activity (AA20-245A) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-245a | primer | 2020-09-01, revisi 2020-09-24 (lebih dari 3 tahun); diakses 2026-10-15 | Tinggi. Ambil artefak dulu, kesalahan umum, artefak Linux (`/var/log`, journald, `/dev/shm`, `/tmp`, `/var/tmp`, `authorized_keys`), komunikasi out-of-band |
| S6 | CISA: Cybersecurity Incident and Vulnerability Response Playbooks (PDF) | https://www.cisa.gov/sites/default/files/publications/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf | primer | November 2021; diakses 2026-10-15 | Tinggi. Collect and Preserve Data; Appendix B langkah 3a dan 3b |
| S7 | Microsoft Learn: Take response actions on a device in Microsoft Defender for Endpoint | https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts | primer (dokumentasi vendor) | ms.date 2026-07-23; diakses 2026-10-15 | Tinggi. Isi paket investigasi Windows, syarat pengambilan, perilaku isolasi |
| S8 | Microsoft Learn: Investigate entities on devices using live response in Microsoft Defender for Endpoint | https://learn.microsoft.com/en-us/defender-endpoint/live-response | primer (dokumentasi vendor) | ms.date 2026-07-28; diakses 2026-10-15 | Tinggi. Daftar perintah dasar dan lanjutan, Command log, batas ukuran file, timeout, sesi |
| S9 | GitHub microsoft/avml: Acquire Volatile Memory for Linux | https://github.com/microsoft/avml | primer (repo resmi alat) | diakses 2026-10-15 | Tinggi. Cara kerja, sumber memori, format LiME, kompresi Snappy, kendala lockdown, matriks pengujian distro |
| S10 | GitHub 504ensicsLabs/LiME: Linux Memory Extractor | https://github.com/504ensicsLabs/LiME | primer (repo resmi alat) | diakses 2026-10-15 | Tinggi. Kernel module, format output, akuisisi lewat TCP, catatan opsi digest |
| S11 | GitHub Velocidex/WinPmem | https://github.com/Velocidex/WinPmem | primer (repo resmi alat) | diakses 2026-10-15 | Sedang-tinggi. Lisensi, driver kernel, output raw. Nama biner dan opsi berubah antar rilis |

**Catatan sumber:** tabel urutan kerja PT JAB di bagian 1.2 adalah gabungan urutan NIST SP 800-86 dengan langkah pencatatan jam dari RFC 3227 dan penambahan tmpfs serta persistence oleh catatan ini; bukan urutan resmi salah satu sumber. Larangan login interaktif dengan akun admin domain ke host terdampak di bagian 1.5 adalah praktik umum IR yang tidak bersumber dari dokumen di tabel ini. Penolakan modul tidak bertanda tangan oleh kernel dengan kebijakan modul bertanda tangan perlu dicek di dokumentasi distro yang dipakai. Opsi baris perintah AVML, LiME, dan WinPmem di bagian 2 adalah contoh; cocokkan dengan README dan `--help` versi yang dipakai. Tiga tingkat pengambilan bukti di bagian 1.7 dan semua isi PT JAB adalah contoh fiktif.
