---
day: 09
title: 'Manajemen risiko praktik: ISO/IEC 27005, skenario risiko, risk appetite, dan risk register mini'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 27005:2022 (edisi 4); ISO Guide 73:2009 (kosakata risiko); EBIOS Risk Manager (ANSSI, panduan terbaru 2024); Open FAIR O-RA/O-RT (versi berbeda antar sumber, lihat bagian 3.5); Verizon DBIR 2026'
---

# Day 09: Manajemen risiko praktik dengan ISO/IEC 27005

> Catatan pribadi, bukan materi resmi ISO, dan bukan nasihat hukum atau audit. Semua organisasi, angka, dan skenario adalah fiktif.

Cakupan: praktik risk assessment memakai panduan ISO/IEC 27005:2022, meliputi risk appetite dan toleransi, penyusunan skenario risiko berbasis kejadian dan aset, estimasi kemungkinan dengan data, pengantar analisis kuantitatif (Open FAIR), key risk indicator, dan pelaporan. Dasar klausul 6.1.2 dan 6.1.3 ada di Day 04.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- membedakan risk appetite, risk tolerance, dan kriteria penerimaan risiko, lalu menerjemahkannya ke pita level risiko.
- menulis skenario risiko berbasis kejadian (sumber risiko, tujuan, jalur) dan berbasis aset dengan format yang konsisten.
- mengestimasi kemungkinan dengan data internal SOC dan laporan industri, sambil menyadari keterbatasan masing-masing.
- menjelaskan ide dasar analisis kuantitatif Open FAIR dan kapan pendekatan itu sepadan dengan usahanya.
- merancang key risk indicator dan laporan risiko yang bisa dibaca pimpinan.

## 2. Konteks singkat

Risk register yang buruk biasanya punya dua gejala: berisi ratusan baris generik ("malware", "hacker", "bencana alam"), dan angkanya ditebak dalam rapat tanpa data. Keduanya membuat pimpinan sulit memutuskan apa pun.

SOC bisa memperbaiki keduanya. Pertama, SOC tahu skenario serangan nyata, sehingga risiko bisa ditulis sebagai cerita yang spesifik. Kedua, SOC punya data: jumlah insiden, near miss, temuan hunting, dan hasil vulnerability scan. Data itu membuat estimasi kemungkinan bisa dipertanggungjawabkan.

Kapan dipakai: risk assessment tahunan (8.2), setelah insiden besar, saat ada perubahan arsitektur, dan saat menyiapkan management review.
Kapan tidak cukup: risk assessment tidak menggantikan threat modeling teknis per sistem atau penetration test. Keduanya justru menjadi input.

## 3. Konsep inti

### 3.1 Proses 27005:2022 secara ringkas

ISO/IEC 27005:2022 (edisi 4, terbit 25 Oktober 2022) adalah panduan untuk memenuhi persyaratan risiko di 27001 [S2]. Prosesnya diselaraskan dengan ISO 31000:2018 [S1]:

```
penetapan konteks -> identifikasi -> analisis -> evaluasi -> treatment
          ^                                                   |
          +---- monitoring dan review, komunikasi dan konsultasi, pencatatan ----+
```

Beberapa perubahan dari edisi 2018 [S1]:

- tahap penerimaan risiko tidak lagi berdiri sendiri; penerimaan risiko sisa menjadi keputusan setelah treatment;
- istilah "consequence" menggantikan "impact";
- konsep risk scenario dipakai untuk identifikasi;
- teknik semi-kuantitatif ditambahkan di samping kualitatif dan kuantitatif;
- enam lampiran digabung menjadi satu lampiran berisi teknik penilaian.

Situs ISO27k (Agustus 2026) melaporkan working group sedang membahas pendekatan revisi berikutnya [S8].

### 3.2 Risk appetite, risk tolerance, dan kriteria penerimaan

Tiga istilah ini sering dipakai bergantian, padahal fungsinya berbeda. ISO Guide 73:2009 (kosakata manajemen risiko) mendefinisikan risk appetite kira-kira sebagai jumlah dan jenis risiko yang bersedia dikejar atau dipertahankan organisasi, dan risk tolerance sebagai kesiapan menanggung risiko setelah treatment untuk mencapai tujuan [S3].

| Istilah | Level | Contoh PT AN |
|---|---|---|
| Risk appetite | Strategis, ditetapkan pimpinan | "Kami tidak menerima risiko kebocoran data pelanggan; kami menerima risiko gangguan layanan singkat demi kecepatan rilis fitur" |
| Risk tolerance | Batas variasi yang masih diterima | "Gangguan layanan maksimal 4 jam per kuartal" |
| Kriteria penerimaan (27001 6.1.2) | Operasional, dipakai di risk register | "Level 1-6 boleh diterima risk owner; level 15 ke atas wajib treatment" |

Kriteria penerimaan adalah terjemahan teknis dari appetite. Bila appetite pimpinan berkata "tidak menerima kebocoran data", tetapi matriks risiko membolehkan risiko kebocoran data level 12 diterima risk owner, ada ketidakcocokan yang akan muncul di management review atau audit.

Appetite juga bisa berbeda per kategori. Appetite untuk risiko kerahasiaan data pelanggan bisa sangat rendah, sementara appetite untuk risiko availability sistem internal lebih longgar. Matriks tunggal tetap bisa dipakai, asalkan ada aturan tambahan per kategori.

### 3.3 Menulis skenario risiko

Skenario yang baik bisa dibaca sebagai satu kalimat cerita. Format yang dipakai catatan ini:

```
<sumber risiko> memanfaatkan <jalur atau kerentanan> untuk <aksi>
terhadap <aset atau proses>, sehingga <konsekuensi pada C, I, atau A>
```

**Berbasis kejadian (event-based).** Pendekatan ini dimulai dari siapa yang bisa menyerang dan apa tujuannya, lalu menyusun jalur serangan tingkat tinggi. 27005:2022 menyebut pendekatan ini cocok untuk penilaian strategis [S1]. Metode EBIOS Risk Manager dari ANSSI (Prancis) menyusunnya dalam lima lokakarya: cakupan dan baseline keamanan, sumber risiko dan tujuannya, skenario strategis di tingkat ekosistem, skenario operasional teknis beserta estimasi kemungkinan, lalu treatment [S4]. Pasangan "sumber risiko dan tujuan" adalah inti pendekatan ini. Contohnya, operator ransomware bertujuan memeras uang, sedangkan insider yang tidak puas bertujuan merusak reputasi.

**Berbasis aset (asset-based).** Pendekatan ini dimulai dari aset penting (misalnya cluster hypervisor atau SIEM), lalu ancaman dan kerentanannya. Cara ini lebih rinci dan cocok untuk sistem kritis.

Keduanya sah untuk 27001, yang tidak menentukan metodologi asalkan metodologinya ditetapkan dan didokumentasikan [S7]. Dalam praktik, pendekatan berbasis kejadian dipakai untuk 10-20 skenario tingkat atas, lalu pendekatan berbasis aset dipakai untuk mendalami beberapa sistem kritis.

Untuk SOC, langkah operasional di EBIOS terasa akrab karena mirip memetakan jalur serangan ke teknik ATT&CK. Keuntungannya, setiap skenario langsung menunjukkan titik deteksi yang dibutuhkan.

### 3.4 Mengestimasi kemungkinan dengan data

Kemungkinan adalah bagian yang paling sering ditebak. Ada tiga sumber data yang bisa membuatnya lebih jujur:

1. **Data internal SOC:** jumlah insiden dan near miss per kategori, temuan hunting, waktu rata-rata kerentanan kritis tetap terbuka, dan jumlah percobaan login gagal dari internet. Data ini paling relevan, tetapi sering sedikit.
2. **Laporan industri:** DBIR 2026 (periode data November 2024 sampai Oktober 2025) melaporkan eksploitasi kerentanan sebagai vektor akses awal teratas (31%), melampaui kredensial curian, dan ransomware muncul di 48% breach [S6]. Ringkasan pihak ketiga juga menyebut keterlibatan pihak ketiga (pemasok) di sekitar 48% breach; angka ini perlu dicocokkan dengan laporan DBIR lengkap sebelum dikutip.
3. **Threat intelligence:** advisori tentang kerentanan yang sedang dieksploitasi pada produk yang kamu pakai (Day 12).

Perhatian: angka industri adalah proporsi di antara breach yang dianalisis, bukan peluang organisasimu diserang. Angka 31% tidak berarti peluang PT AN dibobol lewat kerentanan adalah 31%. Gunakan angka industri untuk menentukan skenario mana yang layak masuk register dan untuk menguji apakah estimasimu masuk akal, bukan sebagai skor langsung.

Tuliskan alasan setiap skor kemungkinan di kolom tersendiri. Alasan seperti "VPN appliance kita punya 2 CVE kritis yang terbuka lebih dari 30 hari, dan advisori menyebut produk ini sedang dieksploitasi" jauh lebih kuat daripada "menurut diskusi tim".

### 3.5 Kualitatif, semi-kuantitatif, dan kuantitatif

| Pendekatan | Bentuk | Kelebihan | Kekurangan |
|---|---|---|---|
| Kualitatif | Rendah, sedang, tinggi | Cepat, mudah dipahami | Sulit dibandingkan dan dijumlahkan |
| Semi-kuantitatif | Skor 1-5 dan perkalian | Bisa diurutkan, umum dipakai | Angka terlihat presisi padahal tetap penilaian |
| Kuantitatif | Frekuensi per tahun dan rentang kerugian dalam uang | Bisa dibandingkan dengan biaya kontrol | Butuh data dan keahlian, memakan waktu |

Open FAIR dari The Open Group adalah standar populer untuk analisis kuantitatif. Isinya taksonomi risiko (O-RT) dan proses analisis (O-RA) [S5]. Ide dasarnya: risiko diuraikan menjadi frekuensi kejadian kerugian dan besaran kerugian, keduanya diestimasi sebagai rentang (bukan satu angka), lalu digabung untuk menghasilkan sebaran kemungkinan kerugian.

Konflik versi: halaman Open FAIR di situs The Open Group menyebut O-RA 2.0.1 dan O-RT 3.0.1 [S5], sedangkan beberapa sumber sekunder menyebut O-RA 2.1 dan O-RT 3.1 terbit Mei 2025. Cek versi terbaru di katalog publikasi The Open Group. Untuk belajar, perbedaan versi ini tidak mengubah ide dasarnya.

Contoh kuantitatif yang disederhanakan (bukan analisis FAIR lengkap): bila skenario terjadi rata-rata sekali dalam 5 tahun (frekuensi 0,2 per tahun) dan kerugian paling mungkin Rp 5 miliar, perkiraan kerugian tahunan adalah 0,2 x Rp 5 miliar = Rp 1 miliar. Bila kontrol seharga Rp 300 juta per tahun bisa menurunkan frekuensi menjadi 0,05 per tahun, perkiraan kerugian menjadi 0,05 x Rp 5 miliar = Rp 250 juta. Pengurangannya Rp 750 juta per tahun, lebih besar daripada biaya kontrol. Analisis FAIR yang sebenarnya memakai rentang dan simulasi, sehingga hasilnya berupa sebaran, bukan satu angka.

Kuantitatif sepadan dengan usahanya untuk beberapa risiko teratas yang butuh keputusan anggaran besar. Untuk puluhan risiko lain, semi-kuantitatif biasanya cukup.

### 3.6 Monitoring risiko dan key risk indicator

27005:2022 menambahkan panduan pemantauan kejadian yang terkait risiko [S1]. Alat praktisnya adalah key risk indicator (KRI): metrik yang memberi tanda awal bahwa kemungkinan atau konsekuensi sebuah risiko berubah.

| Risiko | KRI | Ambang peringatan |
|---|---|---|
| Ransomware lewat kerentanan perimeter | Jumlah CVE kritis pada aset yang menghadap internet dan terbuka lebih dari 14 hari | Lebih dari 0 |
| Serangan tidak terdeteksi | Persentase server in-scope yang tidak mengirim log 24 jam | Lebih dari 2% |
| Phishing kredensial | Rasio laporan phishing oleh karyawan dibanding klik pada simulasi | Turun dua bulan berturut-turut |

Bedanya dengan metrik 9.1 (Day 06): metrik 9.1 mengukur kinerja kontrol dan sasaran, sedangkan KRI mengukur perubahan kondisi risiko. Satu angka bisa berfungsi sebagai keduanya, misalnya cakupan log.

### 3.7 Struktur risk register

Kolom minimum yang sebaiknya ada: ID, skenario, kategori CIA, risk owner, kontrol yang sudah ada, kemungkinan (dengan alasan), konsekuensi (dengan alasan), level awal, opsi treatment, kontrol tambahan, level sisa, status penerimaan, KRI, dan tanggal tinjau.

Satu register atau banyak? Standar tidak menentukan. Satu register memberi pandangan menyeluruh tetapi lebih kompleks; beberapa register (misalnya keamanan dan kelangsungan bisnis) lebih fokus tetapi butuh usaha administrasi lebih [S7]. Untuk organisasi kecil sampai menengah, satu register dengan kolom kategori biasanya lebih mudah dikelola.

### 3.8 Melaporkan risiko ke pimpinan

Pimpinan butuh tiga hal: risiko teratas, arah perubahannya (naik atau turun), dan keputusan yang diminta. Heat map 5x5 berguna untuk gambaran cepat, tetapi sebaiknya disertai daftar 5-10 risiko teratas dengan satu kalimat keputusan per risiko.

## 4. Contoh dokumen / artefak (organisasi fiktif)

Organisasi fiktif: PT Awan Nusantara (PT AN). Kriteria memakai skala 1-5 dari Day 04 (Rendah 1-6, Sedang 8-12, Tinggi 15-25).

### 4.1 Pernyataan risk appetite (cuplikan)

```
Risk appetite PT AN 2026 (disetujui Direksi, 2026-02-10)
- Kerahasiaan data pelanggan : sangat rendah. Risiko kebocoran data pelanggan level Sedang ke atas
                               wajib treatment; tidak boleh diterima risk owner tanpa persetujuan Direksi.
- Ketersediaan layanan       : sedang. Gangguan maksimal 4 jam per kuartal dapat ditoleransi.
- Kepatuhan regulasi         : sangat rendah.
- Inovasi produk             : sedang-tinggi. Menerima risiko operasional terkendali demi rilis lebih cepat.
```

Aturan tambahan di baris pertama membuat matriks umum mengikuti appetite: risiko kerahasiaan data pelanggan level 8-12 tidak lagi boleh diterima risk owner, berbeda dari aturan pita Sedang biasa.

### 4.2 Register risiko berbasis skenario (cuplikan)

| ID | Skenario | CIA | Owner | K | Alasan K | C | L awal | Opsi | Kontrol tambahan | K' | C' | L sisa |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| R-21 | Operator ransomware memanfaatkan CVE kritis di VPN appliance untuk akses awal, lalu mengenkripsi VM pelanggan | A, C | Head of Platform | 4 | 2 CVE kritis terbuka lebih dari 30 hari; advisori eksploitasi aktif; vektor teratas di DBIR 2026 | 5 | 20 Tinggi | Modify | SLA patch 7 hari untuk aset internet (8.8); deteksi anomali VPN (8.16) | 2 | 5 | 10 Sedang |
| R-22 | Penyedia SIEM cloud mengalami kebocoran, sehingga log berisi data pribadi pelanggan terekspos | C | ISMS Manager | 2 | Penyedia punya laporan audit pihak ketiga; tidak ada insiden tercatat | 4 | 8 Sedang | Share + Modify | Klausul kontrak dan notifikasi (5.20, 5.23); masking data pribadi di log (8.11) | 2 | 3 | 6 Rendah |
| R-23 | Admin yang tidak puas menghapus log untuk menutupi akses tidak sah | I | Lead SOC | 2 | 1 kasus akses berlebih tahun lalu; belum ada pemisahan peran admin SIEM | 4 | 8 Sedang | Modify | Kirim log ke penyimpanan write-once (8.15); pemisahan tugas admin (5.3) | 1 | 4 | 4 Rendah |
| R-24 | Penipu memakai SMS phishing ke staf service desk untuk mereset akun pelanggan | C, I | Head of Service Desk | 3 | 3 percobaan tercatat di tiket Q2; tren phishing seluler meningkat | 4 | 12 Sedang | Modify | Verifikasi callback wajib; awareness khusus (6.3) | 2 | 4 | 8 Sedang |
| R-25 | SIEM tidak tersedia lebih dari 24 jam, sehingga deteksi buta | A | Lead SOC | 2 | 1 gangguan 6 jam dalam 12 bulan | 3 | 6 Rendah | Retain | Uji pemulihan tahunan (5.30) tetap jalan | 2 | 3 | 6 Rendah |

Cara membaca:

- **Perkalian:** 4x5 = 20, 2x4 = 8, 2x4 = 8, 3x4 = 12, 2x3 = 6. Sisa: 2x5 = 10, 2x3 = 6, 1x4 = 4, 2x4 = 8, 2x3 = 6.
- **R-21 tetap Sedang setelah treatment.** Konsekuensi ransomware tetap 5. Karena skenario ini menyangkut kerahasiaan data pelanggan (C), aturan appetite di 4.1 berlaku: penerimaan level 10 butuh persetujuan Direksi, bukan cukup Head of Platform.
- **R-24 di level 8 juga menyangkut kerahasiaan data pelanggan,** jadi aturan yang sama berlaku. Keputusan ini harus muncul di management review.
- **Kolom "Alasan K"** memakai data internal (CVE terbuka, tiket) dan data industri sebagai pendukung, bukan sebagai skor langsung.

### 4.3 Heat map level awal dan level sisa

```
Level awal (K = kemungkinan, C = konsekuensi)      Level sisa
K\C  1   2   3     4         5                     K\C  1   2   3         4     5
5    -   -   -     -         -                     5    -   -   -         -     -
4    -   -   -     -         R21                   4    -   -   -         -     -
3    -   -   -     R24       -                     3    -   -   -         -     -
2    -   -   R25   R22,R23   -                     2    -   -   R22,R25   R24   R21
1    -   -   -     -         -                     1    -   -   -         R23   -
```

Di level awal, R-22 dan R-23 sama-sama berada di sel K2/C4, dan R-25 di K2/C3. Di level sisa, R-22 dan R-25 berada di K2/C3, R-24 di K2/C4, R-21 di K2/C5, dan R-23 di K1/C4. Pergeseran ke bawah dan ke kiri menunjukkan efek treatment. Satu-satunya risiko yang tetap di kolom C5 adalah R-21, sehingga ia layak dibahas khusus di management review.

### 4.4 Key risk indicator

| Risiko | KRI | Sumber data | Ambang | Nilai Sep 2026 (fiktif) | Status |
|---|---|---|---|---|---|
| R-21 | CVE kritis pada aset internet terbuka lebih dari 7 hari | Vulnerability scanner | 0 | 1 | Peringatan |
| R-23 | Perubahan konfigurasi retensi SIEM tanpa tiket | Audit log SIEM | 0 | 0 | Normal |
| R-24 | Percobaan rekayasa sosial ke service desk per bulan | Tiket | Lebih dari 5 | 2 | Normal |

## 5. Lab praktik

Latihan untuk organisasi fiktifmu. Simpan di `ISO27001-note/latihan/day09-<nama-org-fiktif>.md`.

1. Tulis pernyataan risk appetite untuk 4 kategori. Tambahkan minimal satu aturan yang mengubah kriteria penerimaan matriks Day 04.
2. Buat 4 pasangan "sumber risiko dan tujuan" (gaya EBIOS), misalnya operator ransomware dengan tujuan pemerasan, atau pesaing dengan tujuan pencurian data.
3. Tulis 8 skenario risiko dengan format bagian 3.3: 4 berbasis kejadian dari langkah 2 dan 4 berbasis aset untuk 2 sistem kritis.
4. Isi register dengan kolom "Alasan K" dan "Alasan C". Minimal 3 alasan memakai data internal dan 1 memakai data industri.
5. Hitung level awal dan sisa, lalu cek setiap risiko terhadap appetite di langkah 1. Siapa yang berwenang menerima tiap risiko sisa?
6. Gambar heat map awal dan sisa. Hitung ulang posisi setiap risiko.
7. Untuk 1 risiko teratas, buat estimasi kuantitatif sederhana seperti bagian 3.5: frekuensi per tahun, kerugian paling mungkin, perkiraan kerugian tahunan sebelum dan sesudah kontrol, dan biaya kontrol.
8. Rancang KRI untuk 3 risiko teratas, lengkap dengan sumber data dan ambangnya.
9. Hubungkan ke lab: tentukan dari mana data KRI bisa diambil di lab-mu. Contohnya, modul vulnerability detection di Wazuh untuk KRI kerentanan, dan audit log Splunk untuk perubahan konfigurasi. Cek nama modul dan menu di versi Wazuh lab-mu. Cukup rancang; pengambilan data dilakukan di sesi lab terpisah.

**Hasil yang seharusnya teramati:** register 8 risiko dengan alasan berbasis data, heat map yang dihitung, satu analisis kuantitatif sederhana, dan KRI untuk risiko teratas.

**Hasil yang sebaiknya tersimpan:**
- Appetite punya minimal satu aturan per kategori yang tercermin di register.
- Setiap skenario ditulis dengan format sumber, jalur, aksi, aset, dan konsekuensi.
- Setiap skor kemungkinan punya alasan, dan angka industri tidak dipakai sebagai skor langsung.
- Semua perkalian dan posisi heat map dihitung ulang.
- Contoh kuantitatif menyebut asumsi frekuensi dan kerugian.
- KRI punya sumber data dan ambang.

**Variasi tantangan:** dua anggota tim memberi skor kemungkinan berbeda (2 dan 4) untuk R-21. Tulis langkah kalibrasi yang akan kamu jalankan, misalnya data apa yang diminta dan siapa yang memutuskan, serta bagaimana hasilnya dicatat agar penilaian tetap konsisten (6.1.2).

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Register berisi risiko generik ("malware") | Tidak memakai format skenario | Tulis ulang dengan sumber, jalur, aksi, aset, dan konsekuensi |
| Semua skor kemungkinan 3 | Tidak ada data, takut salah | Minta data insiden dan kerentanan; tulis alasan per skor |
| Appetite pimpinan bertentangan dengan matriks | Appetite dan kriteria dibuat terpisah | Tambahkan aturan per kategori di kriteria penerimaan |
| Analisis kuantitatif memakan waktu berminggu-minggu | Dipakai untuk semua risiko | Batasi ke 3-5 risiko yang butuh keputusan anggaran besar |
| KRI tidak pernah berubah | Ambang terlalu longgar atau data tidak diperbarui | Kalibrasi ambang dengan data 6-12 bulan terakhir |

## 7. Kesalahan umum dan jebakan

- Memakai persentase laporan industri sebagai probabilitas organisasi sendiri.
- Menyamakan risk appetite dengan kriteria penerimaan, lalu tidak ada yang menerjemahkan appetite ke aturan matriks.
- Menganggap angka semi-kuantitatif presisi. Level 12 bukan "dua kali lebih berisiko" daripada level 6.
- Register dengan ratusan baris per aset yang tidak pernah ditinjau. Mulai dari skenario tingkat atas [S7].
- Menghitung kerugian kuantitatif dengan satu angka tanpa rentang, lalu memperlakukannya sebagai kepastian.
- `[komunitas, belum terkonfirmasi]` Forum Advisera menyebut pendekatan berbasis aset paling umum karena seimbang antara presisi dan usaha [S7]. Ini opini satu konsultan, dan 27005:2022 sendiri memberi tempat yang setara untuk pendekatan berbasis kejadian [S1].

## 8. Catatan terkini

- DBIR 2026 (periode data November 2024 sampai Oktober 2025): eksploitasi kerentanan menjadi vektor akses awal teratas (31%) dan ransomware muncul di 48% breach [S6]. Laporan itu juga menyoroti serangan yang dibantu AI generatif dan phishing lewat perangkat seluler.
- ANSSI memperbarui panduan EBIOS Risk Manager pada 2024 [S4]. Cek nomor versi panduan terbaru.
- Versi Open FAIR berbeda antar sumber (2.0.1/3.0.1 vs 2.1/3.1) [S5]. Cek di situs The Open Group.
- Revisi 27005 masih dalam tahap pembahasan pendekatan menurut ISO27k (Agustus 2026) [S8].

## 9. Cheat sheet

```
27005:2022: konteks -> identifikasi -> analisis -> evaluasi -> treatment (+ monitoring, komunikasi, pencatatan)
            "consequence" bukan "impact" | risk scenario | semi-kuantitatif | 1 lampiran teknik
Appetite (strategis, pimpinan) -> tolerance (batas variasi) -> kriteria penerimaan (matriks register)
Skenario: <sumber> memanfaatkan <jalur> untuk <aksi> terhadap <aset>, sehingga <konsekuensi CIA>
Event-based (EBIOS RM): sumber risiko + tujuan -> skenario strategis -> skenario operasional -> treatment
Asset-based: aset -> ancaman -> kerentanan
Kemungkinan: data internal SOC > threat intel > laporan industri (pendukung, bukan skor)
Kuantitatif (Open FAIR): frekuensi kejadian kerugian x besaran kerugian, sebagai RENTANG
  contoh sederhana: 0,2/tahun x Rp 5 M = Rp 1 M/tahun
KRI = tanda awal perubahan risiko (beda dengan metrik kinerja 9.1)
Laporan: heat map + top 5-10 + arah tren + keputusan yang diminta
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | PECB: ISO/IEC 27005:2022 main changes and implications | https://pecb.com/en/article/iso-iec-270052022-main-changes-and-implications | sekunder (lembaga pelatihan) | sekitar 2022; diakses 2026-10-08 | Sedang-tinggi. Dipakai juga di Day 04 |
| S2 | IEC Webstore: ISO/IEC 27005:2022 | https://webstore.iec.ch/publication/79713 | primer (katalog penerbit) | 2022-10-25; diakses 2026-10-08 | Tinggi untuk judul, edisi, tanggal, abstrak |
| S3 | Wikipedia: Risk appetite (memuat definisi ISO Guide 73) | https://en.wikipedia.org/wiki/Risk_appetite | sekunder (ensiklopedia) | diakses 2026-10-08 | Sedang. Definisi Guide 73 dikutip ulang; cocokkan dengan teks Guide 73 atau ISO 31073:2022 bila butuh definisi resmi |
| S4 | ANSSI: La méthode EBIOS Risk Manager | https://cyber.gouv.fr/la-methode-ebios-risk-manager | primer (lembaga pemerintah Prancis) | panduan 2024; diakses 2026-10-08 | Tinggi. Lima lokakarya. Halaman tidak menyebut nomor versi secara eksplisit |
| S5 | The Open Group: Open FAIR | https://www.opengroup.org/open-fair | primer (penerbit standar) | diakses 2026-10-08 | Tinggi untuk O-RA dan O-RT; nomor versi berbeda dengan sumber sekunder (bagian 3.5) |
| S6 | Verizon: Data Breach Investigations Report 2026 | https://www.verizon.com/business/resources/reports/dbir/ | primer (penerbit laporan) | 2026; diakses 2026-10-08 | Tinggi untuk angka utama. Angka pihak ketiga hanya dari ringkasan sekunder |
| S7 | Advisera Expert Advice Community: Risk registers | https://community.advisera.com/topic/risk-registers/ | komunitas (forum tanya-jawab) | 2019-06-12 (lebih dari 3 tahun); diakses 2026-10-08 | Rendah-sedang. Opini konsultan; topiknya stabil |
| S8 | ISO27k: ISO/IEC 27005 | https://www.iso27001security.com/html/27005 | sekunder (komentar praktisi) | diperbarui 2026-08-19; diakses 2026-10-08 | Sedang. Status pembahasan revisi |

**Catatan sumber:** definisi risk appetite dan risk tolerance di bagian 3.2 berasal dari kutipan sekunder atas ISO Guide 73:2009, jadi diparafrasekan dan tidak dikutip kata per kata. Nomor versi Open FAIR dan EBIOS Risk Manager perlu dicek di situs penerbitnya. Angka keterlibatan pihak ketiga di DBIR 2026 berasal dari ringkasan pihak ketiga. Contoh kuantitatif adalah penyederhanaan untuk belajar, bukan metode Open FAIR lengkap.
