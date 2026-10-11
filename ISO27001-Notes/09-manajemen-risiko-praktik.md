---
day: 09
title: 'Manajemen risiko praktik: ISO/IEC 27005, skenario risiko, risk appetite, dan risk register mini'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 27005:2022 (edisi 4, 2022-10-25); ISO 31073:2022 (kosakata risiko, pengganti ISO Guide 73:2009 yang ditarik 2023-11-02); EBIOS Risk Manager (ANSSI); Open FAIR O-RA 2.0.1 dan O-RT 3.0.1 menurut halaman Open FAIR The Open Group (sumber sekunder menyebut 2.1 dan 3.1, Mei 2025); Verizon DBIR 2026'
---

# Day 09: Manajemen risiko praktik dengan ISO/IEC 27005

Cakupan: praktik risk assessment dengan panduan ISO/IEC 27005:2022, dari risk appetite, skenario risiko, dan estimasi kemungkinan berbasis data sampai pengantar Open FAIR, key risk indicator, dan pelaporan, sebagai lanjutan klausul 6.1.2 dan 6.1.3 di Day 04.

## Ide inti

Day 04 menjelaskan kerangka yang diminta klausul 6: kriteria tetap, risk owner, treatment, dan SoA. Day ini menjawab pertanyaan berikutnya, yaitu bagaimana mengisi kerangka itu supaya hasilnya bisa dipercaya. Risk register yang buruk biasanya berisi ratusan baris generik ("malware", "hacker") dengan angka yang ditebak dalam rapat. Register yang baik berisi skenario spesifik, skor dengan alasan berbasis data, aturan penerimaan yang diturunkan dari keinginan pimpinan, dan indikator yang memberi tanda sebelum risiko benar-benar terjadi.

SOC bisa memperbaiki kedua kelemahan itu. Sejak Day 04, risiko dipadankan dengan threat model dan kriteria risiko dengan matriks severity alert. Threat model yang baik ditulis sebagai jalur serangan spesifik, bukan daftar kata kunci, dan severity yang baik dikalibrasi dengan data, bukan perasaan. SOC punya keduanya: pengetahuan tentang skenario serangan nyata, serta data insiden, near miss, temuan hunting, dan hasil scan yang membuat estimasi kemungkinan bisa dipertanggungjawabkan.

```
risk appetite (pimpinan)  -> aturan di kriteria penerimaan (6.1.2 a)
skenario risiko (sumber, jalur, aksi, aset, konsekuensi)
  -> kemungkinan dan konsekuensi, masing-masing dengan alasan berbasis data
  -> level awal -> treatment -> level sisa -> siapa boleh menerima (appetite)
  -> KRI memantau perubahan kondisi risiko (8.2, 9.1)
  -> laporan ke pimpinan (input 9.3.2) -> siklus berikutnya
```

Situasi yang dipakai sepanjang Day ini: PT Awan Nusantara (PT AN, penyedia hosting fiktif) menjalankan risk assessment tahunan (8.2) menjelang management review 20 November 2026. Register Day 04 (R-04 sampai R-20) sudah ada, dan risk appetite 2026 sudah disetujui Direksi pada Februari. Direktur Operasional meminta Lead SOC membantu ISMS Manager menambah skenario dari sisi SOC:

> "Saya ingin lima hal dari SOC. Pertama, pastikan appetite yang disetujui Direksi benar-benar terlihat di aturan penerimaan risiko, bukan hanya di dokumen Direksi. Kedua, tulis risiko sebagai kejadian yang bisa saya bayangkan, bukan 'malware' atau 'hacker'. Ketiga, setiap angka kemungkinan harus ada dasarnya. Keempat, untuk risiko yang butuh anggaran besar, beri saya angka rupiah supaya bisa dibandingkan dengan biaya kontrolnya. Kelima, saya mau tahu lebih awal kalau sebuah risiko memburuk, jangan menunggu tahun depan."

Permintaan pertama dijawab di bagian 1.2 (appetite dan kriteria penerimaan), kedua di bagian 1.3 (skenario risiko), ketiga di bagian 1.4 (estimasi kemungkinan), keempat di bagian 1.5 (analisis kuantitatif), dan kelima di bagian 1.6 (KRI). Hasilnya dirangkum di register dan laporan untuk rapat 20 November (bagian 1.7, 1.8, dan bagian 2).

**Kapan relevan:** risk assessment terencana yang diwajibkan klausul 8.2 (biasanya tahunan), setelah insiden besar atau perubahan arsitektur, dan menjelang management review.
**Kapan bukan jawaban:** risk assessment tidak menggantikan threat modeling per sistem atau penetration test; keduanya justru menjadi input.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Tabel ini memuat istilah yang muncul di Day ini. Kolom padanan memakai analogi SOC yang sama di semua Day. Risiko, kriteria risiko, risk owner, opsi treatment, risiko sisa, serta identifikasi berbasis kejadian dan berbasis aset sudah dijelaskan di Day 04 dan tidak diulang.

| Istilah | Arti singkat | Padanan di SOC |
|---|---|---|
| Risk appetite | Jumlah dan jenis risiko yang bersedia dikejar atau dipertahankan organisasi, ditetapkan pimpinan | Arahan pimpinan: "tidak ada toleransi untuk data pelanggan bocor" |
| Risk tolerance | Batas variasi yang masih diterima setelah treatment | SLA yang boleh meleset dalam batas tertentu |
| Kriteria penerimaan | Aturan operasional di matriks: level mana boleh diterima dan oleh siapa | Aturan severity dan eskalasi di matriks triage |
| Risk scenario | Urutan kejadian dari penyebab awal sampai konsekuensi yang tidak diinginkan | Jalur serangan di threat model |
| Sumber risiko dan tujuan | Siapa yang bisa menyerang dan apa yang ingin dicapainya (gaya EBIOS) | Profil pelaku di threat intel |
| Skenario strategis vs operasional | Jalur tingkat tinggi di ekosistem vs jalur rinci di sistem tertentu | Kill chain ringkas vs rangkaian teknik ATT&CK |
| Semi-kuantitatif | Skor angka (misalnya 1-5) yang hanya mengurutkan | Skor severity numerik |
| Open FAIR | Standar analisis risiko kuantitatif dari The Open Group (O-RT dan O-RA) | Model biaya insiden per tahun |
| Loss Event Frequency dan Loss Magnitude | Seberapa sering kejadian kerugian dan seberapa besar kerugiannya | Frekuensi insiden per tahun dan biaya per insiden |
| Loss prevention vs loss mitigation | Kontrol yang menurunkan frekuensi vs kontrol yang menurunkan besaran kerugian | Hardening dan patch vs backup dan containment cepat |
| Key risk indicator (KRI) | Metrik yang memberi tanda awal bahwa kemungkinan atau konsekuensi risiko berubah | Alert early warning, misalnya CVE kritis melewati SLA patch |
| Heat map | Matriks kemungkinan x konsekuensi yang menunjukkan posisi setiap risiko | Matriks severity yang diisi tiket |

### 1.1 Proses 27005:2022 secara ringkas

Sebelum menulis satu skenario pun, Lead SOC perlu tahu di mana pekerjaannya berada dalam proses risiko. ISO/IEC 27005:2022 adalah panduan untuk memenuhi persyaratan risiko di 27001 [S2], dan proses serta istilahnya diselaraskan dengan ISO 31000:2018 [S1]:

```
penetapan konteks -> identifikasi -> analisis -> evaluasi -> treatment
          ^                                                   |
          +---- monitoring dan review, komunikasi dan konsultasi, pencatatan ----+
```

Beberapa ciri edisi 2022 yang langsung memengaruhi cara kamu menulis register [S1]:

- penerimaan risiko sisa adalah titik keputusan setelah treatment, bukan tahap tersendiri;
- istilah yang dipakai adalah "consequence" (bukan "impact") dan "risk scenario";
- identifikasi punya dua pendekatan, berbasis kejadian dan berbasis aset;
- teknik semi-kuantitatif termasuk yang dibahas;
- contoh teknik penilaian dikumpulkan dalam satu lampiran.

Permintaan Direktur Operasional menyentuh hampir semua kotak di diagram: appetite masuk penetapan konteks, skenario masuk identifikasi, kemungkinan dan rupiah masuk analisis, aturan penerimaan masuk evaluasi, dan KRI masuk monitoring. Perbandingan dengan edisi 2018 ada di bagian 6.

### 1.2 Risk appetite, risk tolerance, dan kriteria penerimaan

Permintaan pertama Direktur Operasional menyentuh masalah yang sering ditemukan auditor: pimpinan menulis appetite di satu dokumen, sementara register memakai matriks yang tidak tahu apa-apa tentang appetite itu.

Definisi yang paling sering dikutip berasal dari ISO Guide 73:2009: risk appetite kira-kira jumlah dan jenis risiko yang bersedia dikejar atau dipertahankan organisasi, dan risk tolerance kesiapan menanggung risiko setelah treatment demi tujuannya [S3]. Guide 73 sudah digantikan ISO 31073:2022 [S9], jadi dokumen resmi sebaiknya mengutip 31073 (tanggal penarikannya di bagian 6).

Ketiga istilah berada di level yang berbeda. Tabel berikut membantu kamu melihat siapa yang menetapkan masing-masing dan seperti apa bunyinya di PT AN.

| Istilah | Level | Contoh PT AN |
|---|---|---|
| Risk appetite | Strategis, ditetapkan pimpinan | "Kami tidak menerima risiko kebocoran data pelanggan; kami menerima risiko gangguan layanan singkat demi kecepatan rilis fitur" |
| Risk tolerance | Batas variasi yang masih diterima | "Gangguan layanan maksimal 4 jam per kuartal" |
| Kriteria penerimaan (27001 6.1.2) | Operasional, dipakai di risk register | "Level 1-6 boleh diterima risk owner; level 15 ke atas wajib treatment" |

Klausul 6.1.2 meminta kriteria penerimaan ditetapkan dan dipelihara, dan appetite pimpinan adalah dasarnya. Bila appetite menolak kebocoran data, tetapi matriks membolehkan risiko kebocoran data level 12 diterima risk owner, ketidakcocokan itu akan terlihat saat audit. Appetite juga bisa berbeda per kategori (kerahasiaan data pelanggan sangat rendah, availability sistem internal lebih longgar); matriks tunggal tetap bisa dipakai dengan aturan tambahan per kategori. Contoh aturan seperti itu ada di bagian 2.1.

### 1.3 Menulis skenario risiko

Permintaan kedua, "tulis risiko sebagai kejadian yang bisa saya bayangkan", adalah persis yang diminta 27005:2022. Standar itu mendefinisikan risk scenario sebagai urutan atau kombinasi kejadian dari penyebab awal sampai konsekuensi yang tidak diinginkan [S1]. Skenario yang baik bisa dibaca sebagai satu kalimat cerita:

```
<sumber risiko> memanfaatkan <jalur atau kerentanan> untuk <aksi>
terhadap <aset atau proses>, sehingga <konsekuensi pada C, I, atau A>
```

Day 04 sudah memperkenalkan dua cara mencari risiko. Di sini keduanya dipakai untuk menulis skenario:

**Berbasis kejadian (event-based).** Dimulai dari siapa yang bisa menyerang dan apa tujuannya, lalu jalur serangan tingkat tinggi; 27005:2022 memposisikannya untuk skenario strategis [S1]. EBIOS Risk Manager dari ANSSI (Prancis) menyusunnya dalam lima lokakarya: cakupan dan baseline keamanan, sumber risiko, skenario strategis di tingkat ekosistem, skenario operasional, lalu treatment [S4]. Intinya pasangan "sumber risiko dan tujuan": operator ransomware ingin memeras, insider yang tidak puas ingin merusak reputasi.

**Berbasis aset (asset-based).** Dimulai dari aset penting (cluster hypervisor, SIEM), lalu ancaman dan kerentanannya. Hasilnya skenario operasional yang rinci, cocok untuk sistem kritis [S1].

27001 tidak menentukan metodologi, asalkan proses penilaiannya memberi hasil yang konsisten, valid, dan bisa dibandingkan (6.1.2). Dalam praktik, pendekatan berbasis kejadian dipakai untuk 10-20 skenario tingkat atas, lalu pendekatan berbasis aset untuk mendalami beberapa sistem kritis. Bagi SOC, skenario operasional mirip memetakan jalur serangan ke teknik ATT&CK, sehingga titik deteksi yang dibutuhkan langsung terlihat. Skenario R-21 sampai R-25 di bagian 2.2 ditulis dengan format ini.

### 1.4 Mengestimasi kemungkinan dengan data

Permintaan ketiga, "setiap angka kemungkinan harus ada dasarnya", adalah tempat SOC paling banyak menyumbang. Tiga sumber data membuat estimasi kemungkinan lebih jujur:

1. **Data internal SOC:** insiden dan near miss per kategori, temuan hunting, umur kerentanan kritis yang terbuka, percobaan login gagal dari internet. Paling relevan, tetapi sering sedikit.
2. **Laporan industri:** DBIR 2026 (data November 2024 sampai Oktober 2025) melaporkan eksploitasi kerentanan sebagai vektor akses awal teratas (31%), melampaui kredensial curian, dan ransomware muncul di 48% breach [S6]. Keterlibatan pihak ketiga hampir separuh breach, naik sekitar 60% dari tahun sebelumnya [S10].
3. **Threat intelligence:** advisori tentang kerentanan yang sedang dieksploitasi pada produk yang kamu pakai (Day 12).

Perhatian: angka industri adalah proporsi di antara breach yang dianalisis, bukan peluang organisasimu diserang. Angka 31% tidak berarti peluang PT AN dibobol lewat kerentanan adalah 31%. Pakai angka industri untuk memilih skenario dan menguji kewajaran estimasi, bukan sebagai skor. Tulis alasan setiap skor di kolom tersendiri: "2 CVE kritis di VPN terbuka lebih dari 30 hari, dan advisori menyebut produk ini sedang dieksploitasi" jauh lebih kuat daripada "menurut diskusi tim". Kolom "Alasan K" di bagian 2.2 menunjukkan bentuknya.

### 1.5 Kualitatif, semi-kuantitatif, dan kuantitatif

Permintaan keempat, angka rupiah, tidak bisa dijawab dengan matriks 5x5. Skor 1-5 hanya mengurutkan risiko; untuk membandingkan risiko dengan biaya kontrol, kamu butuh pendekatan kuantitatif. Tabel berikut membandingkan ketiga pendekatan supaya kamu bisa memilih yang sepadan dengan keputusannya.

| Pendekatan | Bentuk | Kelebihan | Kekurangan |
|---|---|---|---|
| Kualitatif | Rendah, sedang, tinggi | Cepat, mudah dipahami | Sulit dibandingkan dan dijumlahkan |
| Semi-kuantitatif | Skor 1-5 dan perkalian | Bisa diurutkan | Terlihat presisi padahal tetap penilaian |
| Kuantitatif | Frekuensi per tahun dan rentang kerugian (uang) | Bisa dibandingkan dengan biaya kontrol | Butuh data, keahlian, dan waktu |

Open FAIR dari The Open Group adalah standar populer untuk analisis kuantitatif, terdiri dari taksonomi risiko (O-RT) dan proses analisis (O-RA) [S5]. Struktur dasarnya [S11]:

- risiko diuraikan menjadi Loss Event Frequency (seberapa sering kejadian kerugian) dan Loss Magnitude (seberapa besar kerugiannya);
- besaran kerugian terdiri dari kerugian primer (akibat langsung) dan sekunder (reaksi regulator, pelanggan, atau pihak lain);
- setiap faktor diestimasi sebagai rentang dengan distribusi, cukup presisi untuk keputusan yang diambil, lalu digabung, biasanya lewat simulasi;
- kontrol dikelompokkan menjadi loss prevention (menurunkan frekuensi) dan loss mitigation (menurunkan besaran).

Nomor versi Open FAIR berbeda antara halaman The Open Group dan sumber sekunder (bagian 6), jadi cek di katalog publikasi The Open Group sebelum mengutipnya. Struktur dasarnya tidak berubah.

Contoh yang disederhanakan (satu nilai, bukan analisis FAIR lengkap, dan bukan hitungan untuk risiko tertentu di register): skenario terjadi sekali dalam 5 tahun (0,2 per tahun) dengan kerugian paling mungkin Rp 5 miliar, sehingga perkiraan kerugian tahunan 0,2 x Rp 5 miliar = Rp 1 miliar. Kontrol seharga Rp 300 juta per tahun menurunkan frekuensi menjadi 0,05 per tahun, sehingga perkiraan kerugian menjadi Rp 250 juta. Pengurangannya Rp 750 juta, atau manfaat bersih Rp 450 juta setelah biaya kontrol. Ini kontrol loss prevention karena yang turun frekuensinya. Analisis seperti ini sepadan untuk beberapa risiko teratas yang butuh keputusan anggaran besar; sisanya cukup semi-kuantitatif.

### 1.6 Monitoring risiko dan key risk indicator

Permintaan kelima, "saya mau tahu lebih awal kalau risiko memburuk", tidak terjawab oleh penilaian tahunan. Yang dibutuhkan adalah indikator yang dipantau terus, mirip alert early warning di SOC yang berbunyi sebelum insiden terjadi.

27005:2022 memuat panduan pemantauan kejadian yang terkait risiko, yaitu faktor yang bisa mengubah sebuah skenario [S1]. Di 27001, kebutuhan ini datang dari 8.2 (penilaian ulang saat ada perubahan signifikan) dan 9.1. Alat praktisnya adalah key risk indicator (KRI): metrik yang memberi tanda awal bahwa kemungkinan atau konsekuensi sebuah risiko berubah (contoh di bagian 2.4). Metrik 9.1 (Day 06) mengukur kinerja kontrol dan sasaran, sedangkan KRI mengukur perubahan kondisi risiko; cakupan log bisa berfungsi sebagai keduanya.

### 1.7 Struktur risk register

Semua jawaban untuk Direktur Operasional berakhir di satu tempat: risk register. Kolom-kolomnya menentukan apakah register itu bisa menjawab pertanyaan auditor atau hanya daftar.

Kolom minimum: ID, skenario, kategori CIA, risk owner, kontrol yang sudah ada, kemungkinan (dengan alasan), konsekuensi (dengan alasan), level awal, opsi treatment, kontrol tambahan, level sisa, status penerimaan, KRI, dan tanggal tinjau. Kolom risk owner dan status penerimaan menjawab 6.1.3, yang meminta risk owner menyetujui rencana treatment dan menerima risiko sisa.

Standar tidak menentukan satu atau beberapa register; organisasi kecil sampai menengah biasanya cukup dengan satu register berkolom kategori [S7].

### 1.8 Melaporkan risiko ke pimpinan

Rapat 20 November tidak akan membaca seluruh register. Pimpinan butuh risiko teratas, arah perubahannya, dan keputusan yang diminta.

Heat map 5x5 memberi gambaran cepat, tetapi sertakan daftar 5-10 risiko teratas dengan satu kalimat keputusan per risiko. Laporan ini menjadi input management review (9.3.2: hasil risk assessment dan status rencana treatment). Contoh heat map ada di bagian 2.3.

## 2. Contoh dokumen / artefak (organisasi fiktif)

Organisasi fiktif: PT Awan Nusantara (PT AN). Semua angka di bawah adalah ilustrasi. Keempat artefak ini adalah bahan yang disiapkan Lead SOC dan ISMS Manager untuk menjawab lima permintaan Direktur Operasional di bagian Ide inti. Kriteria memakai skala 1-5 dari Day 04 (Rendah 1-6, Sedang 8-12, Tinggi 15-25); level 7, 11, 13, 14, dan 17-19 tidak mungkin muncul pada matriks 5x5, jadi pita ini tanpa celah.

### 2.1 Pernyataan risk appetite (cuplikan)

Cuplikan ini menjawab permintaan pertama. Perhatikan baris pertama, yang menambah aturan di atas kriteria penerimaan Day 04.

```
Risk appetite PT AN 2026 (disetujui Direksi, 2026-02-10)
- Kerahasiaan data pelanggan : sangat rendah. Risiko kebocoran data pelanggan level Sedang ke atas
                               wajib treatment; tidak boleh diterima risk owner tanpa persetujuan Direksi.
- Ketersediaan layanan       : sedang. Gangguan maksimal 4 jam per kuartal dapat ditoleransi.
- Kepatuhan regulasi         : sangat rendah.
- Inovasi produk             : sedang-tinggi. Menerima risiko operasional yang dikelola demi rilis lebih cepat.
```

Baris pertama membuat risiko kerahasiaan data pelanggan level 8-12 tidak lagi boleh diterima risk owner sendiri, berbeda dari pita Sedang di Day 04.

### 2.2 Register risiko berbasis skenario (cuplikan)

Register ini menjawab permintaan kedua dan ketiga: setiap baris adalah skenario, dan setiap skor kemungkinan punya alasan. Nomornya melanjutkan register Day 04 (R-04 sampai R-20). Cari kolom "Alasan K" dan bandingkan level sisa dengan aturan appetite di bagian 2.1.

| ID | Skenario | CIA | Owner | K | Alasan K | C | L awal | Opsi | Kontrol tambahan | K' | C' | L sisa |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| R-21 | Operator ransomware memanfaatkan CVE kritis di VPN appliance untuk akses awal, lalu mengenkripsi VM pelanggan | A, C | Head of Platform | 4 | 2 CVE kritis terbuka lebih dari 30 hari; advisori eksploitasi aktif; DBIR 2026 | 5 | 20 Tinggi | Modify | SLA patch 7 hari untuk aset internet (8.8); deteksi anomali VPN (8.16) | 2 | 5 | 10 Sedang |
| R-22 | Penyedia SIEM cloud mengalami kebocoran, sehingga log berisi data pribadi pelanggan terekspos | C | ISMS Manager | 2 | Penyedia punya laporan audit pihak ketiga; tidak ada insiden tercatat | 4 | 8 Sedang | Share + Modify | Klausul kontrak dan notifikasi (5.20, 5.23); masking data pribadi di log (8.11) | 2 | 3 | 6 Rendah |
| R-23 | Admin yang tidak puas menghapus log untuk menutupi akses tidak sah | I | Lead SOC | 2 | 1 kasus akses berlebih tahun lalu; belum ada pemisahan peran admin SIEM | 4 | 8 Sedang | Modify | Kirim log ke penyimpanan write-once (8.15); pemisahan tugas admin (5.3) | 1 | 4 | 4 Rendah |
| R-24 | Penipu memakai SMS phishing ke staf service desk untuk mereset akun pelanggan | C, I | Head of Service Desk | 3 | 3 percobaan tercatat di tiket Q2; tren phishing seluler meningkat | 4 | 12 Sedang | Modify | Verifikasi callback wajib; awareness khusus (6.3) | 2 | 4 | 8 Sedang |
| R-25 | SIEM tidak tersedia lebih dari 24 jam, sehingga deteksi buta | A | Lead SOC | 2 | 1 gangguan 6 jam dalam 12 bulan | 3 | 6 Rendah | Retain | Uji pemulihan tahunan (5.30) tetap jalan | 2 | 3 | 6 Rendah |

Cara membaca:

- **Perkalian:** awal 4x5 = 20, 2x4 = 8, 2x4 = 8, 3x4 = 12, 2x3 = 6. Sisa 2x5 = 10, 2x3 = 6, 1x4 = 4, 2x4 = 8, 2x3 = 6.
- **R-21 (sisa 10) dan R-24 (sisa 8) tetap Sedang** dan menyangkut kerahasiaan data pelanggan, sehingga aturan appetite di bagian 2.1 berlaku: penerimaannya butuh persetujuan Direksi dan harus muncul di management review.
- **R-22 turun ke Rendah (6)** karena masking menurunkan konsekuensi dari 4 ke 3; risk owner boleh menerimanya.

### 2.3 Heat map level awal dan level sisa

Heat map ini adalah halaman pertama laporan untuk rapat 20 November. Bandingkan posisi setiap risiko di kedua matriks untuk melihat efek treatment.

```
Level awal (K = kemungkinan, C = konsekuensi)      Level sisa
K\C  1   2   3     4         5                     K\C  1   2   3         4     5
5    -   -   -     -         -                     5    -   -   -         -     -
4    -   -   -     -         R21                   4    -   -   -         -     -
3    -   -   -     R24       -                     3    -   -   -         -     -
2    -   -   R25   R22,R23   -                     2    -   -   R22,R25   R24   R21
1    -   -   -     -         -                     1    -   -   -         R23   -
```

Pergeseran ke bawah dan ke kiri menunjukkan efek treatment. Hanya R-21 yang tetap di kolom C5.

### 2.4 Key risk indicator

Tabel ini menjawab permintaan kelima. Cari kolom Status: baris "Peringatan" adalah tanda awal yang diminta Direktur Operasional.

| Risiko | KRI | Sumber data | Ambang | Nilai Sep 2026 (fiktif) | Status |
|---|---|---|---|---|---|
| R-21 | CVE kritis pada aset internet terbuka lebih dari 7 hari (SLA di R-21) | Vulnerability scanner | 0 | 1 | Peringatan |
| R-23 | Perubahan konfigurasi retensi SIEM tanpa tiket | Audit log SIEM | 0 | 0 | Normal |
| R-24 | Percobaan rekayasa sosial ke service desk per bulan | Tiket | Lebih dari 5 | 2 | Normal |

## 3. Lab praktik

Latihan untuk organisasi fiktifmu. Simpan di `latihan/day09-<nama-org-fiktif>.md`.

1. Tulis pernyataan risk appetite untuk 4 kategori. Tambahkan minimal satu aturan yang mengubah kriteria penerimaan matriks Day 04.
2. Buat 4 pasangan "sumber risiko dan tujuan" (gaya EBIOS), misalnya pesaing dengan tujuan pencurian data.
3. Tulis 8 skenario risiko dengan format bagian 1.3: 4 berbasis kejadian dari langkah 2 dan 4 berbasis aset untuk 2 sistem kritis.
4. Isi register dengan kolom "Alasan K" dan "Alasan C". Minimal 3 alasan memakai data internal dan 1 memakai data industri.
5. Hitung level awal dan sisa, lalu cek setiap risiko terhadap appetite di langkah 1. Siapa yang berwenang menerima tiap risiko sisa?
6. Gambar heat map awal dan sisa. Hitung ulang posisi setiap risiko.
7. Untuk 1 risiko teratas, buat estimasi kuantitatif seperti bagian 1.5 (frekuensi, kerugian, kerugian tahunan sebelum dan sesudah kontrol, biaya, manfaat bersih), dan tandai jenis kontrolnya.
8. Rancang KRI untuk 3 risiko teratas, lengkap dengan sumber data dan ambangnya.
9. Tentukan sumber data KRI di lab-mu, misalnya modul vulnerability detection di Wazuh dan audit log Splunk (index `_audit`). Cek nama modul di versi Wazuh lab-mu. Cukup rancang dulu.

**Hasil yang sebaiknya tersimpan:**
- Register 8 risiko dengan alasan berbasis data dan appetite yang tercermin di kriteria penerimaan.
- Perkalian dan posisi heat map yang sudah dihitung ulang.
- Satu analisis kuantitatif dengan asumsi frekuensi dan kerugian tertulis.
- KRI untuk risiko teratas dengan sumber data dan ambang.

**Variasi tantangan:** dua anggota tim memberi skor kemungkinan berbeda (2 dan 4) untuk R-21. Tulis langkah kalibrasi: data apa yang diminta, siapa yang memutuskan, dan bagaimana hasilnya dicatat agar penilaian konsisten (6.1.2).

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Register berisi risiko generik ("malware") | Tidak memakai format skenario | Tulis ulang dengan sumber, jalur, aksi, aset, dan konsekuensi |
| Semua skor kemungkinan 3 | Tidak ada data, takut salah | Minta data insiden dan kerentanan; tulis alasan per skor |
| Appetite pimpinan bertentangan dengan matriks | Appetite dan kriteria dibuat terpisah | Tambahkan aturan per kategori di kriteria penerimaan |
| Analisis kuantitatif makan waktu berminggu-minggu | Dipakai untuk semua risiko | Batasi ke 3-5 risiko dengan keputusan anggaran besar |
| KRI tidak pernah berubah | Ambang terlalu longgar atau data basi | Kalibrasi dengan data 6-12 bulan terakhir |

## 5. Kesalahan umum dan jebakan

- Memakai persentase laporan industri sebagai probabilitas organisasi sendiri.
- Menyamakan appetite dengan kriteria penerimaan, sehingga appetite tidak pernah diterjemahkan ke aturan matriks.
- Menganggap angka semi-kuantitatif presisi. Level 12 bukan "dua kali lebih berisiko" daripada level 6.
- Menghitung kerugian kuantitatif dengan satu angka tanpa rentang, lalu menganggapnya pasti.
- `[komunitas, belum terkonfirmasi]` Forum Advisera menyebut pendekatan berbasis aset paling umum [S7]. Itu opini satu konsultan; 27005:2022 memberi tempat setara untuk pendekatan berbasis kejadian [S1].

## 6. Catatan terkini

Bagian ini menampung perubahan edisi, status dokumen acuan, dan angka yang diperbarui tiap tahun. Berguna saat membaca metodologi risiko lama atau memperbarui kolom alasan di register.

- ISO/IEC 27005:2022 adalah edisi 4, terbit 25 Oktober 2022 [S2]. Dibanding edisi 2018, penerimaan risiko sisa tidak lagi tahap tersendiri; "consequence" menggantikan "impact" dan "risk scenario" menggantikan "incident scenario"; pendekatan identifikasi berbasis kejadian ditambahkan di samping berbasis aset; teknik semi-kuantitatif ditambahkan; dan lampiran A sampai F digabung menjadi satu lampiran contoh teknik penilaian [S1].
- DBIR 2026 untuk pertama kalinya menempatkan eksploitasi kerentanan di atas kredensial curian sebagai vektor akses awal [S6][S10]. Perbarui kolom "Alasan K" setiap DBIR baru terbit.
- ISO Guide 73:2009 ditarik 2 November 2023; ISO 31073:2022 menjadi kosakata risiko yang berlaku [S9].
- Halaman Open FAIR The Open Group per Oktober 2026 menyebut O-RA 2.0.1 dan O-RT 3.0.1 [S5], sedangkan sumber sekunder menyebut versi 2.1 dan 3.1 terbit Mei 2025.
- Halaman EBIOS Risk Manager tidak menyebut nomor versi panduan [S4]; cek tanggal di dokumen panduannya.
- Revisi 27005 masih dalam tahap pembahasan pendekatan menurut ISO27k (Agustus 2026) [S8].

## 7. Cheat sheet

```
27005:2022: konteks -> identifikasi -> analisis -> evaluasi -> treatment (+ monitoring, komunikasi, pencatatan)
            "consequence" bukan "impact" | risk scenario | semi-kuantitatif | 1 lampiran teknik
            penerimaan risiko sisa = keputusan setelah treatment
Appetite (strategis, pimpinan) -> tolerance (batas variasi) -> kriteria penerimaan (matriks register, 6.1.2)
Kosakata: ISO 31073:2022 (Guide 73:2009 ditarik 2023)
Skenario: <sumber> memanfaatkan <jalur> untuk <aksi> terhadap <aset>, sehingga <konsekuensi CIA>
Event-based (EBIOS RM): cakupan -> sumber risiko -> skenario strategis -> skenario operasional -> treatment
Asset-based: aset -> ancaman -> kerentanan
Kemungkinan: data internal SOC > threat intel > laporan industri (pendukung, bukan skor)
Open FAIR: Risk = Loss Event Frequency x Loss Magnitude (primer + sekunder), sebagai RENTANG
  kontrol: loss prevention (frekuensi) | loss mitigation (besaran)
  contoh sederhana: 0,2/tahun x Rp 5 M = Rp 1 M/tahun; kontrol Rp 300 jt -> 0,05/tahun = Rp 250 jt
KRI = tanda awal perubahan risiko (beda dengan metrik kinerja 9.1)
Laporan: heat map + top 5-10 + arah tren + keputusan yang diminta (input 9.3.2)
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** DBIR 2026 melaporkan eksploitasi kerentanan sebagai vektor akses awal di 31% breach. Seorang analyst menulis di register: "kemungkinan PT AN dibobol lewat kerentanan = 31%, jadi skor K = 2". Apa yang salah?

<details><summary>Jawaban</summary>

Angka DBIR adalah proporsi di antara breach yang dianalisis, bukan peluang organisasi tertentu diserang. Angka itu berguna untuk memilih skenario yang layak ditulis dan menguji kewajaran estimasi, bukan untuk dijadikan skor. Dasar skor kemungkinan yang lebih kuat adalah data internal SOC (insiden, near miss, umur kerentanan kritis yang terbuka) dan threat intelligence tentang produk yang dipakai, misalnya "2 CVE kritis di VPN terbuka lebih dari 30 hari, dan advisori menyebut produk ini sedang dieksploitasi". Lihat bagian 1.4.

</details>

**2. Pertanyaan jebakan.** Setelah treatment, R-24 (penipu memakai SMS phishing ke service desk untuk mereset akun pelanggan) turun dari 12 ke 8. Menurut kriteria Day 04, level 8 masuk pita Sedang dan boleh diterima risk owner dengan alasan tertulis. Head of Service Desk langsung menandatangani penerimaannya. Apakah itu cukup di PT AN?

<details><summary>Jawaban</summary>

Tidak. Risk appetite PT AN 2026 menambah aturan untuk kerahasiaan data pelanggan: risiko level Sedang ke atas wajib treatment dan tidak boleh diterima risk owner tanpa persetujuan Direksi. R-24 menyangkut kerahasiaan data pelanggan, sehingga penerimaan level 8 butuh persetujuan Direksi dan harus muncul di management review. Karena itu appetite harus diterjemahkan ke aturan di kriteria penerimaan; bila tidak, risk owner akan mengikuti matriks lama. Lihat bagian 1.2, 2.1, dan 2.2.

</details>

**3. Skenario keputusan.** ISMS Manager ingin semua 25 risiko di register PT AN dianalisis dengan Open FAIR supaya laporan ke Direksi "terlihat profesional". Apa sikap yang paling tepat?

- A. Setuju. Analisis kuantitatif selalu lebih akurat daripada skor 1-5, jadi semua risiko sebaiknya dihitung dalam rupiah.
- B. Batasi analisis kuantitatif ke beberapa risiko teratas yang butuh keputusan anggaran besar; sisanya cukup semi-kuantitatif.
- C. Tolak. 27001 hanya menerima matriks kemungkinan x konsekuensi, jadi analisis rupiah tidak bisa dipakai untuk ISMS.

<details><summary>Jawaban</summary>

B. Analisis kuantitatif bisa dibandingkan langsung dengan biaya kontrol, tetapi butuh data, keahlian, dan waktu; dipakai untuk semua risiko, pekerjaannya bisa makan waktu berminggu-minggu. A keliru karena hasil kuantitatif juga bergantung pada estimasi rentang dan asumsi; menghitung dengan satu angka lalu menganggapnya pasti adalah kesalahan umum. C keliru karena 27001 tidak menentukan metodologi, asalkan hasil penilaiannya konsisten, valid, dan bisa dibandingkan. Lihat bagian 1.3, 1.5, dan 4.

</details>

**4. Skenario keputusan.** Direktur Operasional meminta indikator yang memberi tanda awal bahwa R-21 (ransomware lewat CVE kritis di VPN appliance) memburuk. Mana yang paling tepat sebagai KRI?

- A. Persentase alert prioritas tinggi yang ditriage dalam 15 menit.
- B. Jumlah CVE kritis pada aset internet yang terbuka lebih dari 7 hari, dengan ambang 0, dari vulnerability scanner.
- C. Jumlah breach ransomware secara global menurut laporan industri tahun ini.

<details><summary>Jawaban</summary>

B. KRI mengukur perubahan kondisi sebuah risiko, dan CVE kritis yang melewati SLA patch 7 hari langsung menaikkan kemungkinan R-21. Indikator ini punya sumber data dan ambang, dan nilai September 2026 (1) sudah memicu status Peringatan. A adalah metrik kinerja kontrol 9.1 (seperti M-03 di Day 06), bukan indikator kondisi R-21. C adalah angka industri yang tidak berubah karena kondisi PT AN; angka seperti itu berguna untuk memilih skenario, bukan sebagai tanda awal untuk satu risiko. Lihat bagian 1.6 dan 2.4.

</details>

**5. Pertanyaan jebakan.** Di laporan, Lead SOC menulis "R-24 (level 12) dua kali lebih berisiko daripada R-25 (level 6)". Apakah kalimat itu benar?

<details><summary>Jawaban</summary>

Tidak. Skor 1-5 dan hasil perkaliannya adalah pendekatan semi-kuantitatif: angkanya hanya mengurutkan, terlihat presisi padahal tetap penilaian. Level 12 berada di atas level 6 dalam urutan prioritas, tetapi tidak bisa dibaca sebagai "dua kali lipat". Bila perbandingan besaran dibutuhkan, misalnya untuk anggaran, pakai pendekatan kuantitatif dengan frekuensi dan rentang kerugian. Lihat bagian 1.5 dan 5.

</details>

**6. Jelaskan ulang.** Jelaskan kepada Direktur Operasional dalam tiga kalimat beda risk appetite dan kriteria penerimaan risiko, tanpa memakai kata "klausul" atau "matriks".

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Risk appetite adalah sikap Direksi tentang risiko apa yang mau kita ambil, misalnya 'kebocoran data pelanggan tidak kita terima, gangguan layanan singkat kita terima demi rilis cepat'. Kriteria penerimaan adalah aturan harian yang dipakai tim saat menilai risiko: dari level berapa risiko wajib ditangani dan siapa yang boleh menyetujui sisanya. Tugas kami memastikan aturan harian itu mengikuti sikap Direksi, sehingga risiko kebocoran data pelanggan tingkat sedang tidak bisa diterima seorang manajer tanpa persetujuan Direksi."

Kesalahan yang sering muncul:
- Menganggap keduanya sama, sehingga appetite tidak pernah diterjemahkan ke aturan penerimaan.
- Lupa bahwa appetite bisa berbeda per kategori, misalnya kerahasiaan data pelanggan sangat rendah tetapi inovasi produk sedang-tinggi.
- Mencampur risk tolerance (batas variasi seperti "gangguan maksimal 4 jam per kuartal") dengan appetite.

</details>

**7. Interview question (English).** "How can a SOC improve the quality of an organization's risk register?"

<details><summary>Sample answer</summary>

"In two ways. First, by turning generic entries like 'malware' into concrete risk scenarios: a risk source, the path or vulnerability it exploits, the action, the asset, and the consequence for confidentiality, integrity, or availability. That is close to mapping an attack path to ATT&CK, so it also shows where detection is needed. Second, by grounding likelihood scores in data: incidents and near misses, hunting findings, how long critical vulnerabilities stay open, and threat intel on products we actually run. Industry reports like the DBIR help choose scenarios, but I wouldn't use their percentages as our probability. On top of that, the SOC can feed key risk indicators, for example critical CVEs on internet-facing assets past the patch SLA, so management gets an early warning between annual assessments."

What makes this answer strong: it names both contributions (specific scenarios and data-based likelihood), avoids the common mistake of treating industry percentages as probability, and adds KRIs as continuous monitoring instead of a once-a-year exercise.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | PECB: ISO/IEC 27005:2022 main changes and implications | https://pecb.com/en/article/iso-iec-270052022-main-changes-and-implications | sekunder (lembaga pelatihan) | sekitar 2022; diakses 2026-10-10 | Sedang-tinggi. Perubahan dari edisi 2018 |
| S2 | IEC Webstore: ISO/IEC 27005:2022 | https://webstore.iec.ch/publication/79713 | primer (katalog penerbit) | 2022-10-25; diakses 2026-10-10 | Tinggi untuk edisi dan tanggal |
| S3 | Wikipedia: Risk appetite (memuat definisi ISO Guide 73) | https://en.wikipedia.org/wiki/Risk_appetite | sekunder (ensiklopedia) | diakses 2026-10-08 | Sedang. Definisi Guide 73 dikutip ulang |
| S4 | ANSSI: La méthode EBIOS Risk Manager | https://cyber.gouv.fr/la-methode-ebios-risk-manager | primer (lembaga pemerintah Prancis) | diakses 2026-10-10 | Tinggi. Lima lokakarya; halaman tidak menyebut nomor versi |
| S5 | The Open Group: Open FAIR | https://www.opengroup.org/open-fair | primer (penerbit standar) | diakses 2026-10-10 | Tinggi untuk nama dan versi yang tercantum |
| S6 | Verizon: Data Breach Investigations Report 2026 | https://www.verizon.com/business/resources/reports/dbir/ | primer (penerbit laporan) | 2026; diakses 2026-10-08 | Tinggi untuk angka utama |
| S7 | Advisera Expert Advice Community: Risk registers | https://community.advisera.com/topic/risk-registers/ | komunitas (forum tanya-jawab) | 2019-06-12; diakses 2026-10-08 | Rendah-sedang. Opini konsultan; topiknya stabil |
| S8 | ISO27k: ISO/IEC 27005 | https://www.iso27001security.com/html/27005 | sekunder (komentar praktisi) | diperbarui 2026-08-19; diakses 2026-10-08 | Sedang. Status pembahasan revisi |
| S9 | ISO committee: ISO Guide 73:2009 (status withdrawn) | https://committee.iso.org/standard/44651.html | primer (katalog ISO) | ditarik 2023-11-02; diakses 2026-10-10 | Tinggi. Menunjuk ISO 31073:2022 sebagai pengganti |
| S10 | Help Net Security: Verizon DBIR, vulnerability exploitation is the dominant initial access vector | https://helpnetsecurity.com/2026/05/20/verizon-2026-dbir-findings | sekunder (media keamanan) | 2026-05-20; diakses 2026-10-10 | Sedang. Ringkasan angka DBIR 2026 |
| S11 | The Open Group Blog: Updates to the Open FAIR Body of Knowledge, Part 2 | https://blog.opengroup.org/2020/12/02/updates-to-the-open-fair-body-of-knowledge-part-2 | sekunder (blog penerbit standar) | 2020-12-02; diakses 2026-10-10 | Sedang-tinggi. Struktur kerugian dan kategori kontrol O-RA 2.0 |

**Catatan sumber:** definisi appetite dan tolerance di bagian 1.2 berasal dari kutipan sekunder atas ISO Guide 73:2009; rumusan di ISO 31073:2022 belum dicocokkan. Nomor versi Open FAIR terbaru belum terkonfirmasi di halaman publik The Open Group.
