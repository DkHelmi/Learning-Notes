---
day: 03
title: 'Triage awal dan scoping: pertanyaan jam pertama, hipotesis, pivot, blast radius, dan case notes'
researched_on: 2026-10-15
versions_checked: 'NIST SP 800-61 Rev. 3 (April 2025); NIST SP 800-61 Rev. 2 (Agustus 2012, digantikan Rev. 3); CISA Cybersecurity Incident and Vulnerability Response Playbooks (November 2021); CISA AA20-245A Technical Approaches to Uncovering and Remediating Malicious Activity (1 September 2020, revisi 24 September 2020); Mandiant M-Trends 2026 (24 Maret 2026)'
---

# Day 03: Triage awal dan scoping (pertanyaan jam pertama, hipotesis, pivot, blast radius, dan case notes)

Cakupan: apa yang harus dijawab pada jam pertama setelah insiden dinyatakan, cara menyusun dan menguji hipotesis, pivot dari satu IOC ke host, akun, dan waktu lain, cara menilai blast radius, kapan scope cukup untuk memutuskan containment, dan cara mencatat semuanya sebagai case notes.

## Ide inti

Alert yang memicu insiden hampir tidak pernah menunjukkan seluruh insiden. Ia hanya titik pertama yang kebetulan terlihat. Scoping adalah pekerjaan memperluas titik itu menjadi gambaran: host mana, akun mana, sejak kapan, lewat jalur apa, dan data apa yang terjangkau penyerang. Keputusan berikutnya (containment, eradication, siapa yang harus diberi tahu) hanya sebaik scope yang menopangnya. Containment yang dijalankan berdasarkan scope satu host akan membersihkan satu host, sementara penyerang tetap duduk di host lain dan sekarang tahu ia sedang dicari.

Kamu sudah mengenal pola ini dari NOC. Saat satu OLT alarm, engineer tidak langsung mengganti kartu. Ia mengecek dulu POP dan pelanggan mana yang ada di belakang router agregasi yang sama, sejak kapan alarm mulai, dan apakah ada perangkat lain yang diam-diam ikut bermasalah. Bedanya, sebaran gangguan jaringan mengikuti topologi yang tergambar di peta. Sebaran insiden mengikuti kredensial, akses, dan pilihan penyerang, sehingga tidak terlihat di peta mana pun. Jalurnya harus ditelusuri dari log, satu pivot demi satu pivot.

```
titik awal (alert)         JKT-WS-0388 beacon ke cdn-sync.example.net
   |
   v
pivot IOC    -> host lain yang menghubungi IOC yang sama
pivot host   -> akun yang login, proses, koneksi keluar, file yang dibaca
pivot akun   -> host lain tempat akun itu dipakai
pivot waktu  -> aktivitas sebelum alert pertama
   |
   v
temuan baru = titik awal baru   (ulangi sampai tidak ada temuan baru)
   |
   v
scope statement (bertanggal, dengan tingkat keyakinan) -> keputusan containment
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan dan 400 ribu pelanggan broadband. Data pelanggan (nama, NIK, alamat, data tagihan) ada di server billing `jkt-billing01`. Selasa, 13 Oktober 2026, pukul 09:47 WIB, EDR (Microsoft Defender for Endpoint) mengirim alert `SOC-2026-0203`: `powershell.exe` dengan perintah terenkode, dijalankan oleh scheduled task di workstation `JKT-WS-0388` milik `andi.pratama` (staf penagihan), berulang kali menghubungi `cdn-sync.example.net`. Domain itu baru pagi tadi ditandai berbahaya oleh threat intelligence vendor EDR. Analyst L2 Sari Kusuma memvalidasi alert itu pukul 10:30, dan SOC lead Dimas Prasetyo, incident commander (IC) PT JAB, menyatakan `INC-2026-019` sebagai SEV-3 pukul 10:40. Lima menit kemudian Dimas menulis di kanal `#inc-2026-019`:

> "Sar, `INC-2026-019` SEV-3 dulu, satu laptop. Jangan diisolasi dulu. Sebelum saya putuskan containment, saya perlu tahu: apa yang sebenarnya sudah kita pegang dan apa yang belum? Dugaanmu penyerang masuk dari mana? Ini cuma laptop Andi atau ada host dan akun lain? Sejak kapan? Ada data pelanggan yang kena? Kapan kamu bisa bilang scope-nya cukup buat kita contain? Tolong semuanya dicatat, siang ini saya update Pak Hendra."

Pesan itu memuat tujuh permintaan:

1. Apa yang sudah diketahui dan apa yang belum?
2. Dugaan jalur masuk dan cara mengujinya.
3. Host dan akun lain yang terlibat.
4. Sejak kapan penyerang ada di dalam.
5. Data pelanggan yang terjangkau, dan seberapa parah dampaknya.
6. Kapan scope cukup untuk containment.
7. Catatan yang bisa diteruskan ke pimpinan.

Permintaan 1 dijawab di bagian 1.1, permintaan 2 di bagian 1.2, permintaan 3 di bagian 1.3, permintaan 4 di bagian 1.4, permintaan 5 di bagian 1.5, permintaan 6 di bagian 1.6, dan permintaan 7 di bagian 1.7. Bagian 2 berisi artefak yang dihasilkan Sari hari itu.

**Kapan relevan:** setiap kali insiden dinyatakan dan tindakan berikutnya bergantung pada seberapa luas insiden itu, terutama bila ada akun, kredensial, atau sistem bersama yang bisa dipakai penyerang untuk berpindah.
**Kapan bukan jawaban:** scoping tidak menunda tindakan darurat ketika kerusakan sedang berjalan cepat, misalnya enkripsi ransomware yang aktif atau penghapusan data. Di situ host yang sedang merusak ditahan dulu (Day 01 bagian 2.4), lalu scoping berjalan paralel. Scoping juga bukan riset atribusi: mencari siapa penyerangnya jarang membantu menahan insiden.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (event, alert, insiden, declare, severity, IC, technical lead, scribe) tidak diulang. Tabel berikut memuat istilah baru Day ini. Kolom padanan memakai analogi NOC dan SOC yang sama di semua Day IR.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Analisis awal (initial analysis) | Analisis cepat setelah insiden dinyatakan untuk mendapat cukup informasi guna memprioritaskan tindakan berikutnya | Cek cepat saat gangguan dinyatakan, sebelum memutuskan perbaikan |
| Scoping | Menentukan cakupan insiden: host, akun, layanan, data, dan rentang waktu yang terlibat | Menentukan sebaran gangguan: POP dan pelanggan mana yang terdampak |
| Hipotesis investigasi | Dugaan yang bisa diuji tentang apa yang terjadi, dengan bukti pendukung dan status uji | Dugaan penyebab gangguan yang diuji satu per satu |
| IOC (indicator of compromise) | Artefak yang menandakan kompromi: IP, domain, hash, nama file, nama task | Tanda khas gangguan, misalnya MAC atau IP perangkat yang bermasalah |
| Pivot | Memakai satu temuan untuk mencari temuan berikutnya di sumber data lain | Menelusuri satu MAC atau IP di tabel ARP dan log semua perangkat |
| Titik masuk awal (initial access) | Cara dan saat pertama penyerang mendapat akses | Perangkat pertama yang alarm saat gangguan merambat |
| Dwell time | Selisih waktu antara awal aktivitas penyerang dan saat aktivitas itu terdeteksi | Lama gangguan berjalan sebelum ada yang menyadari |
| Blast radius | Semua yang bisa dijangkau penyerang dari akses yang sudah ia pegang | Semua pelanggan di belakang satu router agregasi yang mati |
| Scope statement | Pernyataan cakupan insiden yang bertanggal, berisi yang terkonfirmasi, yang sudah diperiksa, yang belum diketahui, dan tingkat keyakinan | Laporan sebaran gangguan yang diperbarui berkala di bridge |
| Case notes | Catatan kerja investigasi: fakta, waktu, sumber, tindakan, dan siapa yang melakukannya | Log kerja engineer di tiket gangguan |

### 1.1 Jam pertama: apa yang harus sudah bisa dijawab

Dimas tidak meminta Sari menyelesaikan investigasi. Ia meminta cukup informasi untuk memutuskan langkah berikutnya. Pembedaan ini penting, karena analyst yang terbiasa dengan forensik cenderung ingin memahami semuanya dulu sebelum bicara.

NIST SP 800-61 Rev. 2 menyebut tujuan analisis awal dengan jelas: begitu tim yakin insiden terjadi, tim segera menentukan cakupannya (jaringan, sistem, atau aplikasi mana yang terdampak), siapa atau apa yang memulainya, dan bagaimana insiden itu berlangsung (alat atau metode serangan, kerentanan yang dieksploitasi). Hasil analisis awal harus cukup untuk memprioritaskan kegiatan berikutnya, yaitu containment dan analisis yang lebih dalam [S2]. Playbook IR CISA merumuskan hal yang sama dari sisi data: dari data yang ada, tentukan jenis akses penyerang, sejauh mana aset terdampak, tingkat hak akses yang sudah ia dapat, dan dampak operasional atau informasinya [S3]. Rev. 3 menempatkan ini di dua tempat: pemeriksaan awal untuk memastikan insiden dan memperkirakan severity serta urgensinya (RS.MA-02), dan perkiraan dampak serta cakupan yang terus disempurnakan (DE.AE-04) [S1].

Dari tiga sumber itu, jam pertama di PT JAB harus menghasilkan jawaban singkat untuk lima hal:

1. **Apa yang terkonfirmasi**, dan dari sumber apa. Di `INC-2026-019`: proses, scheduled task, dan koneksi berulang ke `cdn-sync.example.net` di `JKT-WS-0388`, terlihat di EDR.
2. **Jenis akses penyerang.** Kode yang berjalan di workstation dengan hak pengguna biasa, dan kanal command and control (C2) yang aktif.
3. **Hak akses yang sudah dicapai.** Sejauh ini hak `andi.pratama`, akun karyawan biasa. Ini yang paling cepat berubah selama scoping.
4. **Apa yang belum diketahui.** Jalur masuk, host lain, akun lain, rentang waktu, data yang terjangkau.
5. **Sumber data apa yang tersedia dan di mana batasnya.** Di PT JAB: Splunk dengan index `dns`, `proxy`, `firewall`, `wineventlog`, `sysmon`, `powershell`, `linux`, dan `o365`; EDR di server Windows dan sebagian workstation; Sysmon hanya di sekitar 40% workstation; server Linux belum memakai EDR. Batas visibilitas ini ikut menentukan seberapa yakin scope bisa dinyatakan.

Hasilnya ditulis sebagai kartu jam pertama (bagian 2.1), bukan dibawa di kepala. Daftar "belum diketahui" adalah rencana kerja scoping, dan daftar sumber data adalah alat yang dipakai untuk mengerjakannya.

### 1.2 Hipotesis: dugaan yang ditulis supaya bisa diuji

Dimas bertanya "dugaanmu penyerang masuk dari mana?". Sari punya dugaan dari process tree: `wscript.exe` menjalankan PowerShell, pola yang umum untuk lampiran skrip dari email. Dugaan itu berguna selama ia diperlakukan sebagai dugaan.

Playbook CISA meminta tim, berdasarkan analisis sejauh itu dan intelijen ancaman yang tersedia, menyusun hipotesis tentang apa yang ingin dicapai penyerang [S3]. Playbook yang sama memberi daftar pertanyaan kunci yang harus dijawab selama analisis [S3]:

- Apa vektor serangan awal, dan bagaimana penyerang masuk ke jaringan?
- Bagaimana penyerang mengakses lingkungan sekarang?
- Apakah ada kerentanan yang dieksploitasi untuk mendapat akses atau hak lebih tinggi?
- Bagaimana penyerang menjaga command and control?
- Apakah ada persistence di jaringan atau di perangkat, dan dengan metode apa (backdoor, web shell, kredensial sah, remote tool)?
- Akun apa yang terkompromi, dan pada tingkat hak apa?
- Metode reconnaissance apa yang dipakai?
- Apakah lateral movement dicurigai atau sudah diketahui, dan dengan cara apa?
- Apakah ada data yang dikeluarkan, jenisnya apa, dan lewat mekanisme apa?

Daftar ini berguna sebagai pengecek kelengkapan: setiap pertanyaan yang belum terjawab adalah lubang di scope. Cara memakainya adalah mengubah setiap pertanyaan menjadi hipotesis yang bisa dibuktikan atau dipatahkan dengan data. Tabel berikut adalah hipotesis awal Sari pukul 10:50; perhatikan kolom "Cara menguji", karena hipotesis tanpa cara menguji hanyalah opini.

| ID | Hipotesis | Bukti pendukung saat ini | Cara menguji | Status 10:50 |
|---|---|---|---|---|
| H1 | Masuk lewat lampiran email yang dijalankan `andi.pratama` | `wscript.exe` menjalankan PowerShell; skrip dari folder unduhan | Cari file `.js` atau arsip di profil Andi dan email masuk sekitar waktu itu | Belum diuji |
| H2 | Host lain ikut terinfeksi dari kampanye email yang sama | Kampanye email jarang menyasar satu orang | Cari host lain yang menghubungi IOC yang sama; cek penerima email yang sama | Belum diuji |
| H3 | Penyerang sudah memakai kredensial dari `JKT-WS-0388` untuk masuk ke sistem lain | Staf penagihan sering menyimpan skrip dan kredensial untuk ekspor laporan | Cari logon akun yang ada di `JKT-WS-0388` ke host lain; cek file kredensial yang dibaca | Belum diuji |
| H4 | Ada data yang sudah dikeluarkan | Belum ada | Volume trafik keluar ke IOC; akses ke data sensitif dari host terdampak | Belum diuji |

Dua aturan menjaga hipotesis tetap jujur. Pertama, hipotesis yang belum diuji tidak masuk ke laporan sebagai fakta; di case notes ia tetap berlabel hipotesis sampai ada bukti. Kedua, hipotesis yang dipatahkan juga dicatat beserta datanya. Bila nanti pimpinan bertanya "apakah sudah dicek ke VPN?", catatan "H5 penyerang masuk lewat VPN: dipatahkan, tidak ada login VPN `andi.pratama` di luar pola selama 30 hari" lebih berguna daripada diam.

### 1.3 Pivot: dari satu titik ke titik berikutnya

Permintaan ketiga Dimas ("cuma laptop Andi atau ada yang lain?") dijawab dengan pivot. Setiap temuan baru dipakai sebagai kunci pencarian di sumber data lain, sampai pencarian tidak lagi menghasilkan temuan baru.

NIST Rev. 2 menjelaskan kenapa pivot lintas sumber dibutuhkan: bukti satu insiden tersebar di beberapa log yang masing-masing memuat jenis data berbeda. Log firewall memuat IP sumber, log aplikasi memuat username, dan IDPS tahu serangan diluncurkan tetapi tidak tahu apakah berhasil, sehingga analyst harus mengkorelasikan semuanya [S2]. Rev. 3 meminta hal yang sama dalam DE.AE-03 (korelasi informasi dari banyak sumber) dan DE.AE-07 (memadukan intelijen ancaman dan konteks lain seperti inventaris aset ke dalam analisis) [S1].

Ada empat jenis pivot yang dipakai berulang:

- **Pivot IOC:** dari domain, IP, hash, nama file, atau nama scheduled task ke semua host yang memilikinya. Contoh: siapa lagi yang menghubungi `cdn-sync.example.net` atau `203.0.113.77`?
- **Pivot host:** dari satu host ke semua akun yang login di sana, proses yang berjalan, koneksi keluar, dan file sensitif yang dibaca.
- **Pivot akun:** dari satu akun ke semua host dan layanan tempat akun itu dipakai, terutama di luar pola biasanya.
- **Pivot waktu:** dari satu titik waktu ke aktivitas sebelum dan sesudahnya di host yang sama.

Advisory gabungan CISA dan lembaga siber Australia, Kanada, Selandia Baru, dan Inggris (AA20-245A) memberi empat teknik untuk mengerjakan pivot di data yang besar [S4]:

1. **Pencarian IOC:** kumpulkan indikator dari berbagai sumber, cari di artefak jaringan dan host, lalu nilai setiap hit untuk membuang false positive.
2. **Frequency analysis:** pakai data dalam jumlah besar untuk mengenali pola normal, lalu cari penyimpangan dalam waktu, lokasi, port, protokol, hash, ukuran, dan penamaan.
3. **Pattern analysis:** cari pola berulang yang menandakan skrip atau malware otomatis, misalnya koneksi dengan interval tetap, dibandingkan aktivitas manusia yang tidak teratur.
4. **Anomaly detection:** analyst yang paham administrasi sistem meninjau nilai unik di dataset untuk menemukan yang ganjil.

Pivot IOC cepat, tetapi rapuh. Penyerang bisa memakai domain atau IP berbeda untuk setiap korban, sehingga pencarian IOC yang tidak menemukan apa-apa bukan bukti bahwa host lain bersih. Karena itu pivot IOC selalu dilengkapi pivot akun dan pivot perilaku (misalnya scheduled task baru yang menjalankan PowerShell terenkode, di host mana pun).

Perhatian: pivot dilakukan di data milikmu, bukan di infrastruktur penyerang. AA20-245A menyebut menyentuh infrastruktur penyerang (ping, `nslookup`, membuka domainnya di browser) sebagai kesalahan, karena bisa memberi tahu penyerang bahwa ia sudah terdeteksi [S4]. NIST Rev. 2 juga mengingatkan bahwa memvalidasi IP penyerang dengan ping atau traceroute hampir tidak memberi informasi, dan mengidentifikasi host penyerang bisa menghabiskan waktu tanpa mengurangi dampak; fokus tetap pada menahan dan memulihkan [S2]. Bila perlu meneliti domain atau IP di internet, Rev. 2 menyarankan memakai workstation terpisah untuk riset [S2].

### 1.4 Sejak kapan: alert pertama bukan awal insiden

Alert `SOC-2026-0203` berbunyi pukul 09:47 Selasa. Itu waktu deteksi, bukan waktu masuknya penyerang. Bila scope dihitung mulai 09:47, semua yang dilakukan penyerang sebelumnya tidak ikut ditelusuri.

Laporan Mandiant M-Trends 2026, yang disusun dari investigasi insiden sepanjang 2025, mencatat median dwell time global 14 hari, naik dari 11 hari di laporan sebelumnya. Sebanyak 52% investigasi tahun itu pertama kali terdeteksi oleh organisasi sendiri [S5]. Angka ini median dari kasus yang ditangani satu penyedia layanan IR, jadi tidak bisa dipakai untuk menebak dwell time insiden tertentu. Yang bisa dipakai adalah kebiasaannya: jendela pencarian awal dibuat jauh lebih panjang daripada beberapa jam sebelum alert. PT JAB memakai 30 hari sebagai jendela awal pivot, lalu diperpanjang bila temuan paling awal ternyata dekat dengan batas jendela.

Tiga hal menentukan apakah jendela itu bisa dipakai:

- **Retensi log.** Rev. 2 menyarankan kebijakan retensi log karena insiden sering baru ditemukan berhari-hari, berminggu-minggu, bahkan berbulan-bulan kemudian, dan log lama bisa menunjukkan reconnaissance atau serangan serupa sebelumnya [S2]. AA20-245A menyebut gagal menyimpan log sebagai kesalahan umum dan menyarankan log disimpan minimal satu tahun [S4]. Bila retensi index `dns` PT JAB hanya 14 hari, jendela 30 hari tidak bisa ditelusuri di sana, dan batas itu harus ditulis di scope statement.
- **Sinkronisasi waktu.** Rev. 2 menekankan jam semua host harus tersinkron, misalnya dengan NTP, karena korelasi menjadi rumit dan lemah sebagai bukti bila tiga log menunjukkan waktu berbeda untuk satu kejadian [S2].
- **Zona waktu.** Playbook CISA meminta timeline insiden mencatat waktu dalam UTC beserta sumber datanya [S3]. PT JAB memakai WIB di semua catatan karena pembacanya orang lokal, tetapi setiap sumber yang memakai UTC (misalnya timeline EDR) dicatat selisihnya sekali di awal: WIB sama dengan UTC ditambah 7 jam. Alert 09:47 WIB tampil sebagai 02:47 UTC di konsol EDR.

Untuk `INC-2026-019`, pivot waktu di `JKT-WS-0388` menemukan `wscript.exe` membuka `Tagihan-Okt-2026.js` pada Senin 12 Oktober pukul 16:05, hampir 18 jam sebelum alert. Itu yang sekarang menjadi titik paling awal, dan jendela pencarian untuk host dan akun lain dihitung dari sana, dengan cadangan beberapa hari ke belakang.

### 1.5 Blast radius: apa yang bisa dijangkau dari akses yang sudah dipegang penyerang

Permintaan kelima Dimas ("ada data pelanggan yang kena?") tidak bisa dijawab dengan menghitung host yang beacon. Pertanyaannya adalah apa yang bisa dijangkau penyerang dari akses yang sudah ia pegang, bukan hanya apa yang sudah terbukti ia sentuh.

Rev. 3 menyebut penentuan besaran (magnitude) insiden sebagai salah satu bagian IR yang paling sulit. Rekomendasinya: cari IOC, tanda persistence, dan tanda insiden lain, baik di aset yang diketahui menjadi target maupun di target potensial lain. Melewatkan langkah ini atau mengerjakannya dangkal membuat besaran insiden diremehkan, sehingga insiden bisa terus berjalan di target lain tanpa diketahui dan tanpa dipantau (RS.AN-08) [S1]. Playbook CISA meminta tim menilai kedalaman dan keluasan akses penyerang, yaitu semua sistem, pengguna, layanan, dan jaringan yang terkompromi, serta tingkat akses kredensial atau eskalasi hak yang sudah ia capai [S3].

Cara praktis menilai blast radius adalah bertanya dari sudut penyerang yang duduk di host terdampak:

1. **Akun apa yang aktif atau tersimpan di host ini?** Akun pengguna yang login, akun service yang berjalan, kredensial di browser, file skrip, atau file konfigurasi.
2. **Ke mana saja akun dan kredensial itu bisa masuk?** Grup AD, akses ke share, akses SSH, akses aplikasi.
3. **Data apa yang ada di tujuan itu?** Data pribadi pelanggan, data keuangan, kredensial lain.
4. **Ke mana jalur jaringannya terbuka?** Segmen mana yang bisa dicapai dari host itu.

Untuk `JKT-WS-0388`, pertanyaan pertama yang mengubah segalanya. Andi adalah staf penagihan yang setiap hari menjalankan skrip ekspor laporan ke `jkt-billing01`, dan skrip itu menyimpan password akun service `svc_billing` dalam teks biasa. Begitu PowerShell log menunjukkan file itu dibaca pada Senin 23:40, blast radius bukan lagi satu laptop, tetapi server yang menyimpan data tagihan 400 ribu pelanggan.

Blast radius lalu dipetakan ke severity dengan kriteria yang sudah ada (Day 01 bagian 1.7). Sistem kritis ISP yang terkompromi dan akun service yang disalahgunakan memenuhi kriteria SEV-2. Kriteria SEV-1 untuk data ("data pribadi pelanggan dalam jumlah besar terindikasi bocor") belum terpenuhi selama belum ada indikasi data diambil, tetapi kemungkinan itu ditulis sebagai pemicu kenaikan yang eksplisit, bukan dibiarkan menggantung. Bagian 2.4 menunjukkan bentuknya.

### 1.6 Kapan scope cukup untuk containment

Pertanyaan keenam Dimas paling sulit, karena scope tidak pernah benar-benar selesai. Yang dicari bukan scope sempurna, tetapi scope yang cukup untuk containment yang tidak meninggalkan akses penyerang yang sudah diketahui.

Playbook CISA menyebut insiden "di-scope dari waktu ke waktu": setiap temuan baru dari kegiatan respons dipakai untuk mencari sistem, perangkat, dan akun lain yang terdampak, lalu scope diperbarui dan dikomunikasikan ke semua pemangku kepentingan supaya semua memegang gambaran yang sama (common operating picture) [S3]. Playbook itu juga memberi kondisi selesai untuk analisis teknis: insiden terverifikasi, scope sudah ditentukan, metode persistence sudah teridentifikasi, dampak sudah dinilai, hipotesis narasi serangan (TTP dan IOC) sudah tersusun, dan semua pihak bergerak dengan gambaran yang sama [S3].

Dari kondisi itu, PT JAB memakai empat pertanyaan sebagai syarat minimal sebelum IC memutuskan containment terkoordinasi:

1. Apakah semua host yang diketahui menghubungi C2 sudah masuk daftar?
2. Apakah semua akun dan kredensial yang diketahui terekspos sudah masuk daftar?
3. Apakah mekanisme persistence di setiap host terdampak sudah diketahui, minimal jenisnya?
4. Apakah batas visibilitas (host tanpa EDR, log yang tidak ada, retensi yang pendek) sudah ditulis?

Bila keempatnya terjawab, containment bisa disiapkan walaupun hal lain belum diketahui, misalnya apakah data sudah diambil. Rev. 3 mengakui bahwa setiap strategi respons punya trade-off: menyeimbangkan kebutuhan cepat pulih dengan kebutuhan mengamati penyerang atau menginvestigasi lebih menyeluruh (RS.MA-03) [S1]. Scope yang menunggu sempurna berarti penyerang diberi waktu. Scope yang terlalu dini berarti containment setengah jalan. Keputusan kapan berhenti ada di IC, berdasarkan scope statement dari technical lead.

Satu hal yang membedakan situasi ini dari ransomware Jumat malam di Day 01: di `INC-2026-019` tidak ada kerusakan yang sedang berjalan cepat. Beacon yang sunyi memberi waktu beberapa jam untuk scoping. Sebaliknya, mengisolasi `JKT-WS-0388` pukul 10:45 akan memutus satu beacon, memberi tahu penyerang, dan meninggalkan `jkt-billing01` yang belum ditemukan. Scoping tetap berjalan setelah containment, karena temuan baru bisa membuka containment lagi (Day 01 bagian 1.5).

### 1.7 Case notes dan status insiden

Permintaan terakhir Dimas ("tolong semuanya dicatat") bukan formalitas. Siang itu ia harus menjelaskan ke Direktur Teknologi Hendra Wijaya apa yang terjadi, dan beberapa minggu kemudian catatan yang sama bisa dibaca DPO, auditor, atau penegak hukum.

Rev. 2 meminta tim yang menduga insiden segera mencatat semua fakta, setiap langkah diberi waktu, setiap dokumen diberi tanggal dan tanda tangan handler, dan catatan hanya berisi fakta, bukan opini atau kesimpulan; materi subjektif masuk ke laporan, bukan ke catatan bukti [S2]. Rev. 2 juga memberi isi minimal sistem pelacakan insiden: status, ringkasan, indikator terkait, insiden lain yang berkaitan, tindakan setiap handler, chain of custody bila ada, penilaian dampak, kontak pihak terkait, daftar bukti yang dikumpulkan, komentar handler, dan langkah berikutnya [S2]. Rev. 3 meminta status setiap insiden dilacak bersama ringkasan, IOC terkait, status dan kerangka waktu setiap tindakan yang ditugaskan, serta langkah berikutnya [S1], dan meminta catatan IR dijaga kerahasiaan dan integritasnya serta hanya bisa diakses orang yang berwenang (RS.AN-06) [S1].

Di PT JAB, case notes technical lead dan timeline scribe (Day 01 bagian 2.4) adalah dua hal yang berbeda tetapi saling mengisi:

| Catatan | Ditulis oleh | Isi utama | Dipakai untuk |
|---|---|---|---|
| Timeline scribe | Scribe | Keputusan, tindakan, siapa memutuskan, kapan | Laporan akhir, review keputusan |
| Case notes | Technical lead dan analyst | Query yang dijalankan, hasilnya, IOC baru, hipotesis dan statusnya, batas visibilitas | Mengulang analisis, handover, bukti teknis |
| Scope statement | Technical lead, disetujui IC | Ringkasan cakupan pada satu titik waktu | Keputusan containment, update ke pimpinan |

Case notes yang baik bisa dipakai orang lain untuk mengulang analisis: setiap temuan menyebut query atau langkah yang menghasilkannya, rentang waktu, dan sumber datanya. Karena isinya sensitif (nama karyawan, kredensial yang bocor, celah yang dieksploitasi), case notes disimpan di tiket insiden dengan akses terbatas, bukan di kanal chat umum.

## 2. Contoh artefak dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Query Splunk memakai nama index PT JAB dan field yang mengikuti Common Information Model (CIM) dari add-on Splunk: `query` dan `src` untuk DNS, `url` dan `src` untuk proxy, `src_ip` dan `dest_ip` untuk firewall. Cek nama field di add-on yang kamu pakai sebelum menjalankan query ini di lab-mu.

### 2.1 Kartu jam pertama `INC-2026-019`

Kartu ini adalah jawaban Sari atas permintaan pertama Dimas, ditulis pukul 10:55 di tiket insiden. Isinya mengikuti lima hal di bagian 1.1.

```
INC-2026-019 | Kartu jam pertama | Selasa 2026-10-13 10:55 WIB | Sari Kusuma (technical lead)
Severity saat ini : SEV-3 (declare 10:40 oleh Dimas)

TERKONFIRMASI (sumber)
- 09:47 alert SOC-2026-0203: powershell.exe -enc dijalankan scheduled task
  \SysCacheUpdate di JKT-WS-0388, koneksi berulang ke cdn-sync.example.net (EDR)
- Process tree: wscript.exe -> powershell.exe (EDR)
- Pengguna aktif: andi.pratama, staf penagihan (EDR, AD)
- Domain cdn-sync.example.net resolve ke 203.0.113.77 menurut log resolver
  internal jkt-res01 (index dns). Tidak dicek langsung ke domain.

JENIS AKSES PENYERANG : eksekusi kode di workstation, kanal C2 HTTPS aktif
HAK AKSES DICAPAI     : setidaknya hak andi.pratama (pengguna biasa)

BELUM DIKETAHUI
- jalur masuk (dugaan H1: lampiran email)
- host lain yang terinfeksi (H2)
- kredensial lain yang terekspos dari JKT-WS-0388 (H3)
- data yang sudah dikeluarkan (H4)
- waktu paling awal aktivitas

SUMBER DATA DAN BATASNYA
- Splunk: dns, proxy, firewall, wineventlog, sysmon, powershell, linux, o365
- Sysmon hanya ~40% workstation; JKT-WS-0388 punya Sysmon dan EDR
- Server Linux tanpa EDR; hanya linux_secure dan linux_audit di Splunk
- Retensi dns 30 hari (cek dulu sebelum menyatakan "tidak ditemukan")

SENGAJA BELUM DILAKUKAN (alasan)
- Isolasi JKT-WS-0388: scope belum diketahui; isolasi dini memberi tahu penyerang
- Reset password andi.pratama: sama; bila ada kredensial lain yang bocor, reset
  satu akun tidak menutup akses
- Blok domain/IP C2: sama; blok tanpa scope juga menghilangkan visibilitas beacon
- Tidak ada ping/nslookup/browse ke domain atau IP C2 dari jaringan PT JAB

60 MENIT KE DEPAN
1. Pivot IOC 30 hari di dns, proxy, firewall (bagian 2.2)
2. Pivot waktu di JKT-WS-0388: aktivitas sebelum 09:47 (sysmon, powershell)
3. Cek penerima email dengan lampiran serupa (message trace M365)
Update berikutnya ke IC: 11:50
```

Cara membaca elemennya:

- **Terkonfirmasi** hanya berisi hal yang dilihat sendiri, dengan sumbernya. Resolusi domain diambil dari log resolver internal, bukan dari `nslookup` ke internet.
- **Sengaja belum dilakukan** menjawab pertanyaan yang pasti muncul ("kenapa laptopnya belum diisolasi?") sebelum ditanyakan, dan setiap butir punya alasan yang bisa dinilai ulang IC.
- **60 menit ke depan** membuat IC tahu kapan update berikutnya datang dan apa isinya.

**Kapan gagal:** kartu ditulis sebagai paragraf panjang yang mencampur fakta dan dugaan. IC tidak bisa membedakan mana yang sudah pasti, lalu pimpinan menerima dugaan sebagai fakta.

### 2.2 Pivot IOC di Splunk: siapa lagi yang menghubungi C2

Query ini menjawab H2 dan permintaan ketiga Dimas: host mana saja yang menghubungi `cdn-sync.example.net` atau `203.0.113.77` dalam 30 hari terakhir.

**Tujuan:** menemukan semua host internal yang menghubungi IOC jaringan, dari tiga sumber sekaligus, beserta waktu pertama dan terakhirnya.

```
(index=dns query="*cdn-sync.example.net") OR (index=proxy url="*cdn-sync.example.net*")
OR (index=firewall dest_ip="203.0.113.77")
earliest="09/13/2026:00:00:00" latest="10/13/2026:11:00:00"
| eval host_src=coalesce(src, src_ip)
| stats min(_time) as first_seen max(_time) as last_seen count values(index) as sumber by host_src
| sort first_seen
| convert ctime(first_seen) ctime(last_seen)
```

Penjelasan tiap bagian:

- Tiga kondisi dalam tanda kurung digabung `OR`, sehingga satu search membaca log resolver, proxy karyawan, dan firewall. Firewall perlu ikut karena server di data center tidak lewat proxy karyawan.
- `query="*cdn-sync.example.net"` memakai wildcard di depan supaya subdomain ikut tertangkap. Wildcard di depan membuat search lebih lambat; untuk jendela 30 hari ini masih wajar.
- `earliest` dan `latest` ditulis absolut, supaya hasilnya sama bila query diulang besok untuk laporan.
- `coalesce(src, src_ip)` menyatukan nama field sumber yang berbeda antar sumber data.
- `stats ... by host_src` meringkas jutaan event menjadi satu baris per host. `values(index)` menunjukkan host itu terlihat di sumber mana saja.
- `sort` dijalankan sebelum `convert`, supaya urutan memakai angka waktu, bukan teks tanggal.

Keluaran ilustrasi:

```
host_src      first_seen            last_seen             count  sumber
10.10.23.88   10/12/2026 16:06:12   10/13/2026 10:58:40    1360  dns proxy
10.20.5.21    10/13/2026 02:20:03   10/13/2026 10:59:12     520  firewall
10.30.14.42   10/13/2026 08:52:30   10/13/2026 10:57:55     152  dns proxy
```

Cara membaca hasil:

- `10.10.23.88` adalah `JKT-WS-0388`, sesuai alert. Waktu pertamanya Senin 16:06:12, hampir 18 jam sebelum alert.
- `10.20.5.21` adalah `jkt-billing01` di segmen data center. Ini temuan terbesar: server billing menghubungi C2 sejak Selasa 02:20, dan hanya terlihat di firewall karena tidak memakai proxy.
- `10.30.14.42` adalah `BDG-WS-0142`, workstation staf penagihan Bandung `dewi.anggraini`, tanpa EDR, sejak Selasa 08:52.
- Angka `count` cocok dengan beacon tiap 60 detik ditambah query DNS tiap 5 menit (TTL 300 detik). Contoh `10.30.14.42`: dari 08:52:30 sampai 10:57:55 ada 7.525 detik, yaitu 126 request proxy dan 26 query DNS, total 152. Interval yang serapi ini adalah tanda pattern analysis untuk proses otomatis, bukan manusia.
- Nama host di atas diperoleh dari lookup aset dan log DHCP, bukan dari tebakan. Untuk workstation dengan IP dinamis, cocokkan IP dengan waktu sewa DHCP-nya.

**Variasi:** ganti kondisi IOC dengan perilaku, misalnya semua host yang menghasilkan koneksi keluar dengan interval tetap ke domain yang belum pernah terlihat sebelum 30 hari terakhir. Variasi ini menangkap host yang memakai domain C2 berbeda.

**Kapan gagal:** host memakai DNS over HTTPS atau koneksi langsung ke IP sehingga tidak muncul di index `dns`; laptop sedang mati atau di luar kantor tanpa VPN; retensi index lebih pendek dari jendela waktu. Ketiganya ditulis sebagai batas visibilitas di scope statement.

### 2.3 Pivot akun dan host: dari `jkt-billing01` kembali ke laptop Andi

Temuan `jkt-billing01` memunculkan pertanyaan baru: siapa yang masuk ke server itu, dan dari mana. Query berikut adalah pivot host ke akun.

**Tujuan:** melihat semua login SSH yang berhasil ke `jkt-billing01` dalam 30 hari, dikelompokkan per akun, sumber, dan metode.

```
index=linux sourcetype=linux_secure host=jkt-billing01 "Accepted"
earliest="09/13/2026:00:00:00" latest="10/13/2026:12:00:00"
| rex "Accepted (?<auth_method>\S+) for (?<acct>\S+) from (?<src_ip>\S+) port"
| stats count min(_time) as first_seen max(_time) as last_seen by acct src_ip auth_method
| sort - count
| convert ctime(first_seen) ctime(last_seen)
```

Penjelasan tiap bagian:

- Baris log sshd untuk login berhasil berbentuk `Accepted password for svc_billing from 10.10.23.88 port 51544 ssh2`. `rex` mengambil metode, akun, dan IP sumber dari teks itu, karena add-on belum tentu sudah mengekstraknya.
- `by acct src_ip auth_method` memisahkan login dengan kunci (`publickey`) dan dengan password, karena keduanya biasanya punya pemakai yang berbeda.

Keluaran ilustrasi:

```
acct          src_ip        auth_method  count  first_seen            last_seen
svc_billing   10.20.1.15    publickey     8784  09/13/2026 00:00:41   10/13/2026 11:55:41
svc_billing   10.10.23.88   password        23  09/14/2026 08:31:10   10/13/2026 02:14:37
svc_billing   10.10.23.41   password        19  09/14/2026 08:35:52   10/12/2026 15:12:08
adm.rina      10.20.1.30    publickey        6  09/22/2026 10:02:14   10/09/2026 14:40:51
```

Cara membaca hasil:

- `10.20.1.15` adalah server job ekspor laporan yang login tiap 5 menit dengan kunci. 8.784 adalah 30 hari kali 288 login per hari, ditambah 144 login pada 13 Oktober sampai 11:55. Pola normal.
- `10.10.23.88` (`JKT-WS-0388`) dan `10.10.23.41` (workstation staf penagihan lain) login dengan password. Ini pemakaian sah: staf penagihan menjalankan skrip ekspor manual dari laptopnya. Sumber IP saja tidak membedakan login penyerang dari login Andi.
- Yang membedakan adalah waktu. `last_seen` untuk `10.10.23.88` adalah 02:14:37 Selasa, jam ketika Andi tidak bekerja. Variasi di bawah memisahkannya.
- `adm.rina` dari jump host adalah administrasi rutin; tetap dicatat sebagai sudah diperiksa.

**Variasi:** tambahkan `| eval jam=tonumber(strftime(_time,"%H"))` sebelum `stats`, lalu `| where jam<7 OR jam>=19` untuk melihat login di luar jam kerja saja. Untuk akun yang sama, ulangi pivot ke `index=wineventlog` dengan EventCode 4624 untuk melihat apakah akun itu juga dipakai di host Windows.

**Kapan gagal:** sshd di server lain menulis ke file log berbeda atau tidak dikirim ke Splunk. Sebelum menyatakan "`svc_billing` tidak dipakai di server lain", pastikan server lain memang mengirim `linux_secure`.

Hasil pivot ini lalu dibawa kembali ke `JKT-WS-0388` sebagai pivot waktu. Tabel berikut adalah timeline host yang disusun Sari dari EDR (dikonversi dari UTC ke WIB), Sysmon, dan PowerShell log; baca kolom sumber untuk tahu dari mana setiap baris berasal.

| Waktu (WIB) | Kejadian | Sumber |
|---|---|---|
| Senin 15:58 | Email "Tagihan Oktober 2026" dengan lampiran `Tagihan-Okt-2026.zip` dari `billing@vendor-tagihan.example` diterima 9 mailbox, termasuk Andi | Message trace M365 |
| Senin 16:05 | `wscript.exe` menjalankan `Tagihan-Okt-2026.js` dari folder sementara arsip | Sysmon EventID 1, EDR |
| Senin 16:05 | `powershell.exe -enc` dijalankan `wscript.exe`; file `upd.ps1` ditulis ke `AppData\Roaming\SysCache\` | EDR, Sysmon EventID 11 |
| Senin 16:06 | Scheduled task `\SysCacheUpdate` dibuat; koneksi pertama ke `cdn-sync.example.net` | EDR, proxy |
| Senin 23:40 | Script block PowerShell membaca `Documents\export-tagihan.ps1`, berisi password `svc_billing` | PowerShell EventID 4104 |
| Selasa 02:14 | `ssh.exe` dijalankan dari `JKT-WS-0388` dengan akun `svc_billing` ke `10.20.5.21` | Sysmon EventID 1; `linux_secure` di `jkt-billing01` |
| Selasa 02:20 | `jkt-billing01` mulai menghubungi `203.0.113.77:443` | Firewall data center |
| Selasa 08:52 | `BDG-WS-0142` mulai menghubungi `cdn-sync.example.net` | DNS, proxy |
| Selasa 09:47 | Alert `SOC-2026-0203` | EDR |

Timeline ini mengubah H1 dan H3 dari hipotesis menjadi temuan yang didukung data, dan memindahkan titik paling awal ke Senin 15:58.

### 2.4 Scope statement v2

Scope statement ini menjawab permintaan keenam Dimas dan menjadi dasar keputusan containment di Day 05. Versi pertama dikirim 11:50, saat `jkt-billing01` ditemukan dan severity dinaikkan ke SEV-2; versi kedua di bawah dikirim 13:00 setelah pivot akun dan email selesai.

```
INC-2026-019 | Scope statement v2 | Selasa 2026-10-13 13:00 WIB
Disusun: Sari Kusuma (technical lead) | Disetujui: Dimas Prasetyo (IC)
Severity: SEV-2 sejak 11:50 (sistem kritis jkt-billing01 terkompromi; akun service
          svc_billing disalahgunakan; data pribadi pelanggan mungkin terdampak)
Keyakinan: SEDANG (alasan di "Batas visibilitas")

TERKONFIRMASI TERDAMPAK
Host : JKT-WS-0388  (andi.pratama)    sejak Senin 16:05, beacon aktif
       BDG-WS-0142  (dewi.anggraini)  sejak Selasa 08:51, beacon aktif, tanpa EDR
       jkt-billing01                  sejak Selasa 02:14, beacon aktif, tanpa EDR
Akun : andi.pratama, dewi.anggraini   (sesi di host terdampak)
       svc_billing                    (password dibaca Senin 23:40, dipakai SSH 02:14)
IOC  : cdn-sync.example.net, 203.0.113.77:443, Tagihan-Okt-2026.zip/.js,
       task \SysCacheUpdate, AppData\Roaming\SysCache\upd.ps1,
       proses /dev/shm/.cache/kworkerd dan cron svc_billing di jkt-billing01
Jalur: email -> JKT-WS-0388 -> kredensial di skrip -> SSH svc_billing -> jkt-billing01

SUDAH DIPERIKSA, TIDAK DITEMUKAN (30 hari: dns, proxy, firewall, wineventlog, linux, vpn)
- host lain yang menghubungi IOC jaringan
- login svc_billing ke server lain selain jkt-billing01
- logon andi.pratama dan dewi.anggraini ke host lain; login VPN di luar pola
- 7 penerima email lain: tidak ada eksekusi lampiran di host ber-EDR atau Sysmon,
  tidak ada koneksi ke IOC

BELUM DIKETAHUI
- apakah database pelanggan di jkt-billing01 dibaca atau diambil
  (log audit database belum diperiksa; trafik keluar ke 203.0.113.77 dari
  jkt-billing01 sekitar 3 MB, tidak menunjukkan transfer besar, tetapi bukan bukti)
- kredensial lain yang tersimpan di BDG-WS-0142
- apakah penyerang punya C2 kedua dengan IOC berbeda

BATAS VISIBILITAS
- 3 dari 7 penerima email lain memakai laptop tanpa Sysmon/EDR; laptop
  fitri.handayani mati sejak Jumat (cuti)
- jkt-billing01 dan BDG-WS-0142 tanpa EDR; hanya log yang dikirim ke Splunk
- DNS over HTTPS tidak terlihat di index dns

PEMICU KENAIKAN KE SEV-1 (tertulis)
- bukti query atau ekspor tabel pelanggan oleh svc_billing atau proses tak dikenal
- trafik keluar dari jkt-billing01 di atas pola normal ke tujuan mana pun
- host atau akun berhak tinggi baru (adm.*, domain admin) dalam scope

KESIAPAN CONTAINMENT: syarat minimal bagian 1.6 terpenuhi (host C2, akun dan
kredensial, jenis persistence, batas visibilitas). Pengamanan bukti berjalan
sejak 12:30; containment serentak setelah bukti aman. Review scope berikutnya: 16:00.
```

Tabel berikut merangkum perubahan dari v1 (11:50) ke v2 (13:00). Perhatikan bahwa scope hampir selalu bertambah dan jarang berkurang.

| Elemen | v1 11:50 | v2 13:00 |
|---|---|---|
| Host | 3 host dari pivot IOC | Sama, ditambah daftar host yang sudah diperiksa dan batas visibilitas |
| Akun | `andi.pratama`, `svc_billing` dugaan | `svc_billing` terkonfirmasi dengan waktu baca dan waktu pakai; `dewi.anggraini` |
| Jalur masuk | Dugaan email | Email terkonfirmasi lewat message trace dan Sysmon |
| Severity | Naik ke SEV-2 | SEV-2 dengan pemicu SEV-1 tertulis |
| Notifikasi | IC ke Direktur Teknologi | DPO Agus Setiawan dan Legal Ratna Sari diberi tahu 12:20 |

Cara membaca elemennya:

- **Keyakinan** tidak dibiarkan kosong. "Sedang" berarti scope cukup untuk bertindak, tetapi ada area yang tidak terlihat dan bisa menambah host.
- **Sudah diperiksa, tidak ditemukan** sama pentingnya dengan yang ditemukan. Bagian ini menunjukkan apa yang sudah dicari, sehingga "tidak ditemukan" punya arti.
- **Pemicu kenaikan ke SEV-1** mengubah ketidakpastian menjadi aturan. Siapa pun yang menemukan salah satu pemicu tahu bahwa severity naik, tanpa perdebatan ulang.

**Kapan gagal:** scope statement tidak bertanggal atau tidak diberi versi. Dua orang membaca versi berbeda dan berdebat tentang fakta yang sebenarnya sudah berubah.

### 2.5 Cuplikan case notes

Case notes berikut ditulis Sari di tiket `INC-2026-019`. Bandingkan dengan timeline scribe di Day 01 bagian 2.4: case notes memuat langkah teknis yang bisa diulang orang lain.

```
INC-2026-019 | Case notes | Sari Kusuma
Konvensi waktu: WIB. Timeline EDR tampil dalam UTC (WIB = UTC + 7 jam).
NTP: workstation, DC, dan server Linux ke jkt-ntp01; selisih jam jkt-billing01
saat dicek 11:25 = +2 detik terhadap jkt-ntp01.

10:50  QUERY  Pivot IOC 30 hari (dns, proxy, firewall), query tersimpan
              "INC-2026-019 pivot IOC" di Splunk. Hasil: 3 host (lihat 2.2).
11:05  FAKTA  10.20.5.21 = jkt-billing01 (lookup aset). 520 koneksi ke
              203.0.113.77:443 sejak 02:20:03, interval ~60 detik.
11:20  QUERY  Login SSH jkt-billing01 30 hari (linux_secure). svc_billing dari
              10.10.23.88 pukul 02:14:37 dengan password, di luar jam kerja.
11:35  FAKTA  PowerShell 4104 JKT-WS-0388 Senin 23:40:12 Get-Content
              Documents\export-tagihan.ps1. File berisi password svc_billing
              (dibaca lewat EDR, isi tidak disalin ke catatan ini).
11:40  HIPOTESIS H3 didukung. H4 belum diuji: perlu log audit DB billing.
11:50  KEPUTUSAN (Dimas) SEV-3 naik ke SEV-2. Lihat timeline scribe.
12:05  HIPOTESIS H5 (masuk lewat VPN) DIPATAHKAN: tidak ada login VPN
              andi.pratama di luar pola 30 hari (index vpn).
12:50  FAKTA  Message trace: 9 penerima Senin 15:58. Eksekusi lampiran hanya
              di JKT-WS-0388 dan BDG-WS-0142 (EDR, Sysmon, DNS).
```

Elemen yang perlu diperhatikan:

- **Konvensi waktu dan selisih jam** dicatat sekali di atas, sesuai saran Rev. 2 tentang sinkronisasi waktu [S2].
- **Query disimpan dengan nama** di Splunk, sehingga orang lain bisa menjalankan ulang dengan rentang waktu yang sama.
- **Kredensial yang ditemukan tidak disalin** ke catatan. Catatan menyebut keberadaannya, bukan isinya.
- **Hipotesis yang dipatahkan ikut dicatat** (H5), sehingga pertanyaan "sudah dicek ke VPN?" punya jawaban.

## 3. Lab praktik (di VM lab terisolasi)

Lab ini memakai lab pribadi dengan Splunk, satu VM Windows dengan Sysmon, dan satu VM Linux yang mengirim log ke Splunk. Tidak ada malware: beacon disimulasikan dengan skrip yang memanggil web server lab sendiri. Jangan memakai data, nama, atau kejadian dari pekerjaan nyata.

1. **Siapkan beacon tiruan.** Di VM Linux lab, jalankan web server sederhana yang hanya bisa dicapai dari jaringan lab, dan beri nama `c2.lab.test` di DNS lab. Di VM Windows, buat scheduled task yang setiap 60 detik menjalankan PowerShell untuk memanggil `http://c2.lab.test/ping`. Di VM Linux kedua (atau VM yang sama), buat cron yang memanggil alamat yang sama setiap menit dari akun biasa. Biarkan berjalan minimal dua jam.
2. **Kartu jam pertama.** Anggap hanya beacon Windows yang memicu alert. Tulis kartu jam pertama dengan format bagian 2.1, termasuk bagian "sengaja belum dilakukan".
3. **Pivot IOC.** Sesuaikan query bagian 2.2 dengan index dan field di lab-mu. Temukan kedua host, lalu hitung ulang `count` dari interval beacon dan pastikan cocok dengan hasil query. Bila tidak cocok, cari tahu kenapa (cache DNS, retry, jam yang tidak sinkron).
4. **Pivot akun.** Login SSH ke VM Linux dengan password dari VM Windows di luar jam yang kamu anggap jam kerja lab, lalu jalankan query bagian 2.3 dan variasi jam kerjanya. Pastikan login itu terpisah dari login lain.
5. **Timeline dan scope statement.** Susun timeline dua host dengan format tabel bagian 2.3, lalu tulis scope statement dengan format bagian 2.4, termasuk tingkat keyakinan, daftar yang sudah diperiksa, batas visibilitas, dan pemicu kenaikan severity.
6. **Uji batas visibilitas.** Ubah beacon di VM Linux agar memanggil IP langsung tanpa DNS. Jalankan ulang pivot IOC berdasarkan domain dan catat apa yang hilang. Tulis satu paragraf tentang bagaimana scope statement-mu seharusnya berubah.

**Hasil yang sebaiknya tersimpan:**

- `latihan/day03-kartu-jam-pertama.md` dengan fakta bersumber, daftar belum diketahui, dan alasan setiap hal yang sengaja belum dilakukan.
- Query pivot IOC dan pivot akun yang sudah disesuaikan, beserta hitungan ulang `count` yang cocok dengan interval beacon.
- `latihan/day03-scope.md` berisi timeline dan scope statement dengan keyakinan dan batas visibilitas.
- Satu paragraf hasil langkah 6 tentang host yang tidak terlihat oleh pivot domain.

**Variasi tantangan:** ubah interval beacon menjadi acak antara 45 dan 90 detik. Apakah pattern analysis masih bisa membedakannya dari aktivitas manusia? Fitur apa (jumlah koneksi per jam, ukuran request yang sama, jam aktif yang tidak pernah berhenti) yang tetap menonjol?

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat scoping pertama kali dikerjakan dengan tekanan waktu. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Pivot IOC tidak menemukan host lain, tetapi kemudian host lain ditemukan dari laporan pengguna | IOC berbeda per korban, DoH, atau host di luar visibilitas | Lengkapi dengan pivot akun dan perilaku; tulis batas visibilitas di scope statement [S4] |
| Waktu di timeline tidak cocok antar sumber | Zona waktu berbeda atau jam tidak sinkron | Catat konvensi zona waktu dan selisih jam di awal case notes; cek NTP [S2][S3] |
| Query 30 hari kosong untuk index tertentu | Retensi index lebih pendek dari jendela | Cek retensi sebelum menulis "tidak ditemukan"; tulis batasnya |
| IP sumber tidak bisa dipetakan ke host | DHCP dinamis, NAT, atau proxy menyembunyikan sumber | Cocokkan dengan log DHCP pada waktu kejadian; ambil IP asli dari header proxy bila tersedia |
| Scope terus melebar dan IC tidak bisa memutuskan | Tidak ada syarat minimal untuk containment | Pakai empat syarat bagian 1.6; tulis keyakinan dan batas, lalu biarkan IC memutuskan |
| Pimpinan menerima dugaan sebagai fakta | Kartu atau update mencampur fakta dan hipotesis | Pisahkan bagian terkonfirmasi, hipotesis, dan belum diketahui di setiap update |
| Analyst lain mengulang query yang sama | Case notes tidak menyimpan query dan rentang waktu | Simpan query dengan nama insiden; tulis rentang absolut di case notes |

## 5. Kesalahan umum dan jebakan

- Menganggap waktu alert sebagai awal insiden. Dwell time median global di M-Trends 2026 adalah 14 hari [S5]; jendela pencarian harus jauh ke belakang.
- Langsung mengisolasi host pertama saat tidak ada kerusakan yang sedang berjalan cepat. Containment berdasarkan scope satu host meninggalkan host lain dan memberi tahu penyerang [S3].
- Melakukan `nslookup`, ping, atau membuka domain C2 dari jaringan kantor. Itu menyentuh infrastruktur penyerang dan bisa memberi tahu bahwa ia terdeteksi [S4].
- Menghabiskan waktu mencari siapa pemilik IP penyerang. Fokus IR adalah menahan dan memulihkan, bukan mengidentifikasi host penyerang [S2].
- Menyatakan "tidak ada host lain" hanya dari pivot IOC. IOC bisa berbeda per korban; pivot akun dan perilaku harus ikut [S4].
- Menghitung blast radius dari host yang beacon saja. Blast radius dihitung dari akses dan kredensial yang dipegang penyerang [S1][S3].
- Menulis scope statement tanpa tanggal, versi, tingkat keyakinan, atau batas visibilitas.
- Menulis "tidak ditemukan" tanpa menyebut sumber dan rentang yang diperiksa.
- Menyalin kredensial yang ditemukan ke case notes atau chat. Catatan IR sendiri harus dijaga kerahasiaannya [S1].
- Membiarkan hipotesis yang belum diuji masuk ke update pimpinan sebagai fakta [S2].

## 6. Catatan terkini

Bagian ini menampung tanggal terbit dan edisi dokumen acuan. Berguna saat mengutip angka atau menjawab "sumbernya versi mana", tetapi tidak mengubah cara scoping.

- **Mandiant M-Trends 2026** terbit 24 Maret 2026 dan memakai data investigasi sepanjang 2025: median dwell time global 14 hari (sebelumnya 11 hari di M-Trends 2025), 52% investigasi pertama kali terdeteksi internal (43% pada 2024), dan vektor awal terbanyak adalah exploit (32%), disusul voice phishing (11%), prior compromise (10%), dan email phishing (6%) [S5]. Angka ini bergeser setiap tahun; kutip edisi dan tahun datanya.
- **Playbook IR dan vulnerability CISA** terbit November 2021, ditulis untuk instansi sipil federal AS atas mandat Executive Order 14028, dan memakai siklus NIST SP 800-61 Rev. 2 [S3]. Daftar pertanyaan kunci dan checklist-nya tetap berguna di luar konteks federal.
- **AA20-245A** terbit 1 September 2020 dan direvisi 24 September 2020, disusun bersama lembaga siber Australia, Kanada, Selandia Baru, Inggris, dan Amerika Serikat [S4].
- **NIST SP 800-61 Rev. 3** (April 2025) tidak lagi memuat rekomendasi analisis langkah demi langkah seperti Rev. 2 bagian 3.2.4; isinya kini rekomendasi per subkategori CSF 2.0 seperti DE.AE-03, DE.AE-04, RS.AN-03, dan RS.AN-08 [S1]. Daftar saran analisis Rev. 2 (profil jaringan, retensi log, korelasi, sinkronisasi jam, knowledge base) masih dipakai luas di materi pelatihan [S2].

## 7. Cheat sheet

```
JAM PERTAMA (cukup untuk memutuskan, bukan selesai):
  terkonfirmasi (sumber) | jenis akses | hak yang dicapai | belum diketahui
  sumber data + batasnya | sengaja belum dilakukan + alasan | update berikutnya

HIPOTESIS: ID | dugaan | bukti | cara menguji | status (diuji/didukung/dipatahkan)
  pertanyaan kunci CISA: vektor awal, akses sekarang, eksploit, C2, persistence,
  akun + hak, recon, lateral movement, exfiltration

PIVOT: IOC -> host | host -> akun, proses, koneksi, file | akun -> host lain
       waktu -> sebelum alert   (ulangi sampai tidak ada temuan baru)
  teknik AA20-245A: IOC search | frequency | pattern | anomaly
  JANGAN ping/nslookup/browse infrastruktur penyerang

WAKTU: alert != awal. Jendela awal 30 hari, perpanjang bila temuan dekat batas
  cek retensi | NTP | konvensi zona (WIB = UTC + 7)

BLAST RADIUS: akun/kredensial di host -> ke mana bisa masuk -> data di sana
  -> jalur jaringan. Petakan ke kriteria SEV; tulis pemicu kenaikan

SCOPE CUKUP UNTUK CONTAINMENT bila:
  semua host C2 diketahui | akun + kredensial terekspos | jenis persistence
  | batas visibilitas tertulis
SCOPE STATEMENT: versi + jam | keyakinan | terdampak | sudah diperiksa
  | belum diketahui | batas visibilitas | pemicu SEV | kesiapan containment

CASE NOTES: waktu + konvensi zona | QUERY tersimpan | FAKTA bersumber
  | HIPOTESIS + status | kredensial tidak disalin | akses terbatas
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Alert pertama `INC-2026-019` berbunyi Selasa 09:47, jadi pencarian cukup dari Selasa pagi." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Alert adalah waktu deteksi, bukan waktu penyerang masuk. Di `INC-2026-019`, pivot waktu menemukan lampiran dijalankan Senin 16:05 dan kredensial `svc_billing` dibaca Senin 23:40, jauh sebelum alert. M-Trends 2026 mencatat median dwell time global 14 hari, jadi PT JAB memakai jendela awal 30 hari dan memperpanjangnya bila temuan paling awal dekat dengan batas. Jendela itu juga harus dicocokkan dengan retensi log. Lihat bagian 1.4.

</details>

**2. Skenario keputusan.** Pukul 10:50 Sari ingin memastikan `cdn-sync.example.net` memang C2. Langkah mana yang tepat?

- A. Membuka domain itu di browser laptop kantornya untuk melihat isinya.
- B. Memakai log resolver internal untuk melihat IP tujuan, memeriksa reputasi dari intelijen yang sudah ada atau dari workstation riset terpisah, tanpa menghubungi domain atau IP-nya.
- C. Menjalankan ping dan `nslookup` ke domain itu dari jaringan PT JAB untuk memastikan servernya masih hidup.

<details><summary>Jawaban</summary>

B. Pivot dilakukan di data milik sendiri. AA20-245A menyebut menyentuh infrastruktur penyerang, termasuk ping, `nslookup`, dan membuka domainnya, sebagai kesalahan karena bisa memberi tahu penyerang bahwa ia terdeteksi. Rev. 2 juga menyebut ping ke IP penyerang hampir tidak memberi informasi dan menyarankan workstation terpisah untuk riset. A dan C keliru karena menyentuh infrastruktur penyerang dari jaringan korban, dan A juga berisiko bagi laptop Sari. Lihat bagian 1.3 dan 2.1.

</details>

**3. Pertanyaan jebakan.** "Pivot IOC 30 hari di dns, proxy, dan firewall hanya menemukan tiga host, jadi insiden ini pasti hanya tiga host." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Pivot IOC hanya menemukan host yang memakai IOC yang sama dan terlihat di sumber yang diperiksa. Penyerang bisa memakai domain atau IP berbeda per korban, host bisa memakai DNS over HTTPS atau koneksi langsung ke IP, laptop bisa sedang mati, dan sebagian host tidak punya EDR atau Sysmon. Karena itu pivot IOC dilengkapi pivot akun dan perilaku, dan scope statement menulis tingkat keyakinan, daftar yang sudah diperiksa, dan batas visibilitas. Lihat bagian 1.3, 2.2, dan 2.4.

</details>

**4. Skenario keputusan.** Pukul 11:50 Sari menemukan `jkt-billing01` beacon ke C2 setelah login SSH `svc_billing` dari laptop Andi. Belum ada bukti data pelanggan diambil. Apa yang sebaiknya dilakukan Dimas?

- A. Mempertahankan SEV-3, karena belum ada bukti data diambil.
- B. Menaikkan ke SEV-2, memberi tahu DPO dan Legal, dan menulis pemicu kenaikan ke SEV-1 secara eksplisit (misalnya bukti query tabel pelanggan atau trafik keluar di atas pola).
- C. Langsung menyatakan SEV-1 dan memerintahkan `jkt-billing01` dimatikan.

<details><summary>Jawaban</summary>

B. Sistem kritis ISP yang terkompromi dan akun service yang disalahgunakan memenuhi kriteria SEV-2, dan data pribadi pelanggan mungkin terdampak sehingga DPO dan Legal perlu tahu. Kriteria SEV-1 untuk data menuntut indikasi kebocoran dalam jumlah besar, yang belum ada, jadi ketidakpastian itu diubah menjadi pemicu tertulis. A keliru karena blast radius sudah mencakup server data tagihan, walau belum terbukti ada data diambil. C keliru karena mematikan layanan pelanggan adalah keputusan executive sponsor, dan mematikan server sebelum bukti diamankan menghapus memori serta memberi tahu penyerang. Lihat bagian 1.5 dan 2.4.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Hendra Wijaya (Direktur Teknologi), dalam tiga kalimat, arti "keyakinan sedang" di scope statement v2 dan kenapa itu tetap cukup untuk bertindak.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Kami sudah menemukan tiga perangkat dan satu akun server yang dipakai penyerang, dan kami sudah memeriksa 30 hari log dari semua sumber utama tanpa menemukan perangkat lain. Keyakinan kami sedang, bukan tinggi, karena dua perangkat yang terdampak dan beberapa laptop tidak punya alat pemantau yang lengkap, jadi masih mungkin ada yang belum terlihat. Gambaran ini sudah cukup untuk menahan penyerang di semua titik yang kami ketahui sekaligus, dan pencarian tetap berjalan; bila ada temuan baru, kami tambahkan ke langkah penahanan."

Kesalahan yang sering muncul:
- Menyebut "sedang" tanpa alasan, sehingga terdengar seperti tebakan.
- Menjanjikan bahwa tidak ada perangkat lain, padahal batas visibilitas sudah ditulis.
- Memakai istilah teknis (DoH, Sysmon, pivot) yang tidak dibutuhkan direktur.

</details>

**6. Pertanyaan jebakan.** "Case notes cukup disusun sesudah insiden selesai dari riwayat chat `#inc-2026-019`." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Rev. 2 meminta fakta dicatat segera dengan waktu setiap langkah, dan catatan hanya berisi fakta, bukan opini. Riwayat chat mencampur dugaan, pertanyaan, dan fakta, sering tanpa query dan rentang waktu yang menghasilkan temuan, sehingga analisis tidak bisa diulang. Case notes yang baik menyimpan query beserta rentang absolut, fakta bersumber, status hipotesis termasuk yang dipatahkan, dan disimpan dengan akses terbatas karena isinya sensitif. Lihat bagian 1.7 dan 2.5.

</details>

**7. Interview question (English).** "You receive an EDR alert showing a workstation beaconing to a known malicious domain. Walk me through how you scope the incident before containment."

<details><summary>Sample answer</summary>

"First I write down what is confirmed and what isn't, and I deliberately hold off on isolating the host unless something destructive is happening, because containing one host before I know the scope tips off the attacker and leaves the rest of their access in place. Then I pivot: from the domain and IP to every host that contacted them in DNS, proxy, and firewall logs over a wide window, at least a few weeks, because the alert time is not the start of the intrusion. From each host I pivot to the accounts and stored credentials on it, and from each account to every other system it touched, looking at timing and behavior, not just IOCs, since indicators can differ per victim. I never touch the attacker's infrastructure directly. I assess blast radius by asking what the attacker can reach with the access they hold, map that to our severity criteria, and write a dated scope statement with a confidence level, what we checked and found nothing, visibility gaps, and explicit triggers for raising severity. When we know all beaconing hosts, exposed accounts, the persistence types, and our blind spots, I recommend coordinated containment to the incident commander, and scoping continues after that."

What makes this answer strong: it explains why containment waits, shows concrete pivots across data sources and time, separates IOC-based from behavior-based searching, and ends with a clear, defensible condition for moving to containment.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | NIST SP 800-61 Rev. 3: Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile (PDF) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf | primer | April 2025; diakses 2026-10-15 | Tinggi. DE.AE-03, DE.AE-04, DE.AE-07, RS.MA (pelacakan status), RS.MA-02, RS.MA-03 (trade-off strategi), RS.AN-06, RS.AN-08 |
| S2 | NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide (PDF) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf | primer | Agustus 2012 (lebih dari 3 tahun, digantikan Rev. 3); diakses 2026-10-15 | Tinggi untuk isi Rev. 2: bagian 3.2.4 (analisis awal dan saran analisis), 3.2.5 (dokumentasi dan isi sistem pelacakan), 3.3.3 (identifikasi host penyerang) |
| S3 | CISA: Cybersecurity Incident and Vulnerability Response Playbooks (PDF) | https://www.cisa.gov/sites/default/files/publications/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf | primer | November 2021; diakses 2026-10-15 | Tinggi. Detection & Analysis: Determine Investigation Scope, Validate and Refine Investigation Scope, Key Questions to Answer; Appendix B langkah 2, 4b, 4d, 4f, 4m, 4w. Konteks instansi federal AS |
| S4 | CISA: Technical Approaches to Uncovering and Remediating Malicious Activity (AA20-245A) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-245a | primer | 2020-09-01, revisi 2020-09-24 (lebih dari 3 tahun); diakses 2026-10-15 | Tinggi. Teknik IOC search, frequency, pattern, anomaly; kesalahan umum (menyentuh infrastruktur penyerang, retensi log) |
| S5 | Google Cloud Blog: M-Trends 2026 | https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/ | sekunder (laporan vendor IR) | 2026-03-24; diakses 2026-10-15 | Sedang-tinggi. Median dwell time global 14 hari, deteksi internal 52%, vektor awal 2025. Data dari kasus yang ditangani Mandiant, bukan populasi umum |

**Catatan sumber:** empat syarat minimal containment di bagian 1.6 adalah susunan catatan ini dari kondisi selesai analisis teknis di playbook CISA [S3], bukan daftar resmi. Jendela pivot awal 30 hari, interval beacon, dan semua isi PT JAB adalah contoh fiktif. Nama field CIM pada query bagian 2.2 dan 2.3 perlu dicocokkan dengan add-on yang dipakai.
