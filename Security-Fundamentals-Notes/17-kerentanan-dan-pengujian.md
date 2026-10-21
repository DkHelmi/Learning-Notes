---
day: 17
title: 'Kerentanan dan pengujian: zero-day, CVE, CWE, CVSS, EPSS, KEV, patch management, VA, pentest, dan red team'
researched_on: 2026-10-21
versions_checked: 'CVSS v4.0 Specification Document v1.2 (FIRST, Juni 2024; v4.0 terbit 1 November 2023); CVSS v3.1; EPSS v5 (model v2026.06.15) dan v4 (model v2025.03.14); CISA KEV Catalog (1.754 entri, dilihat 2026-10-21); CISA BOD 26-04 (10 Juni 2026, mencabut BOD 22-01); CWE Top 25 edisi 2025; CVE CNA Operational Rules 4.2.0 (berlaku 25 Agustus 2026); NIST SP 800-40 Rev. 4 (April 2022); NIST SP 800-115 (September 2008); NIST CSRC Glossary (diakses 2026-10-21); OWASP Virtual Patching Cheat Sheet'
---

# Day 17: Kerentanan dan pengujian (zero-day, CVE, CWE, CVSS, EPSS, KEV, patch management, VA, pentest, dan red team)

Cakupan: bahasa yang dipakai untuk menamai, menilai, mengurutkan, dan menutup kerentanan (vulnerability, exploit, zero-day, CVE, CWE, CVSS, EPSS, CISA KEV, patch management, virtual patching, compensating control), cara organisasi mencari kerentanannya sendiri (vulnerability scanner, vulnerability assessment, penetration test, red team, blue team, purple team), dan jalur kerentanan dari penemu ke pemilik sistem (responsible atau coordinated disclosure, bug bounty, SBOM).

## Ide inti

Setiap tahun puluhan ribu kerentanan baru diumumkan, dan setiap organisasi punya ratusan sampai ribuan temuan yang belum ditutup. Tidak ada tim yang bisa menutup semuanya sekaligus, jadi pertanyaan yang sebenarnya bukan "ada kerentanan atau tidak", melainkan "mana yang ditutup lebih dulu, dan apa yang dilakukan sementara belum bisa ditutup". Untuk menjawabnya dibutuhkan tiga hal: nama yang sama untuk kerentanan yang sama (CVE dan CWE), ukuran seberapa parah akibatnya bila dimanfaatkan (CVSS), dan bukti atau perkiraan seberapa mungkin kerentanan itu benar-benar dipakai penyerang (EPSS dan KEV). Ketiganya baru berarti setelah digabung dengan konteks aset sendiri: apakah perangkat itu terlihat dari internet, dan seberapa penting isinya.

Sisi kedua adalah mencari kerentanan sendiri sebelum penyerang menemukannya, dari scanner yang memeriksa ribuan aset sampai red team yang meniru penyerang sungguhan. Hasilnya kembali ke proses yang sama: urutkan, tutup dengan patch, atau lindungi sementara sampai patch bisa dipasang.

Bayangkan lagi rumah dari Day 01. Kerentanan adalah jendela yang tidak terkunci, dan exploit adalah cara mencongkelnya. Zero-day adalah celah yang belum diketahui pemilik rumah maupun tukang kunci. CVE adalah nomor laporan resmi untuk satu celah, supaya semua orang membicarakan celah yang sama. CVSS menilai seberapa parah kerusakannya bila celah itu dimanfaatkan, EPSS adalah prakiraan cuaca tentang peluang celah itu dimanfaatkan dalam waktu dekat, dan KEV adalah daftar modus yang sudah terbukti dipakai maling. Vulnerability assessment adalah inspeksi rumah dengan checklist, penetration test adalah maling bayaran yang diizinkan mencoba masuk, dan red team adalah latihan perampokan penuh tanpa memberi tahu satpam. Batas analogi ini: di internet satu "modus maling" bisa dipakai otomatis ke ribuan rumah dalam hitungan jam setelah diumumkan, satu rumah digital punya ribuan jendela yang berubah setiap bulan, dan "tukang kunci" (vendor) kadang butuh berminggu-minggu untuk membuat kunci baru.

```
  penemu celah (peneliti, vendor, penyerang)
        |
        |  disclosure: dilaporkan ke vendor dulu, diumumkan setelah ada perbaikan
        v
  CVE ID + CVE Record  ----  CWE: jenis kelemahannya
        |
        +--> CVSS : seberapa parah bila dimanfaatkan        (severity)
        +--> EPSS : seberapa mungkin dimanfaatkan 30 hari    (prakiraan)
        +--> KEV  : sudah terbukti dimanfaatkan?             (fakta)
        |
        +  konteks PT JAB: aset terekspos internet? isinya penting?
        v
  prioritas  -->  patch (perbaikan permanen)
             -->  virtual patch / compensating control (sementara)
             -->  verifikasi: scan ulang, pantau log

  pengujian sendiri:  scanner / VA (luas, otomatis)  ->  pentest (bukti, terbatas)  ->  red team (uji deteksi dan respons)
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan dan sekitar 400 ribu pelanggan internet rumah. Kamu adalah analyst L1 (lini pertama yang memeriksa alert) yang sedang menjalani minggu keempat orientasi di SOC (Security Operations Center) PT JAB. Karyawan yang bekerja dari rumah masuk ke jaringan kantor lewat VPN `jkt-vpn01` (`198.51.100.20`), perangkat dari vendor fiktif dengan produk bernama AksesGate. Senin malam 2027-08-23 vendor mengumumkan kerentanan kritis di firmware AksesGate. Dalam Day ini nomornya ditulis `CVE-2027-XXXXX`, sebuah nomor fiktif yang sengaja tidak mengikuti nomor sungguhan. Rabu 2027-08-25 pukul 07:30, mentormu Sari Kusuma (analyst L2) mengirim pesan:

> "Pagi. Antrean kita hari ini didominasi satu hal: `jkt-vpn01`. Pukul 06:41 ada alert `SOC-2027-0892`, percobaan eksploitasi `CVE-2027-XXXXX` dari `192.0.2.241`. Advisory vendor bilang celah ini sempat dipakai penyerang sebelum diumumkan; apakah itu artinya zero-day, dan apa bedanya dengan exploit? Nomor CVE itu dari mana, dan kenapa advisory juga menyebut CWE? Vendor memberi skor 9.3, tapi sumber lain menulis 9.8; mana yang benar? Kemarin celah ini masuk KEV dan skor EPSS-nya 0,94; kenapa dua hal itu membuat Pak Dimas memutuskan patch malam ini, padahal laporan scan bulanan kita berisi 612 temuan yang sebagian besar menunggu jadwal biasa? Patch-nya baru bisa dipasang pukul 22:00; apa yang melindungi kita sampai saat itu? Lalu tolong bantu aku membaca laporan scan Agustus; Pak Agung bilang beberapa temuannya salah. Bulan depan ada pentest tahunan, dan Pak Hendra menyebut latihan red team tahun depan; apa bedanya, dan apa peran kita di SOC? Terakhir, kemarin ada email dari peneliti luar yang melaporkan celah di portal, dan Lutfi minta SBOM dari vendor aplikasi MyJAB. Istilahnya banyak; kita urai satu per satu."

Pesan itu memuat delapan pertanyaan:

1. Apa bedanya vulnerability, exploit, dan zero-day, dan apakah `CVE-2027-XXXXX` termasuk zero-day?
2. Dari mana nomor CVE berasal, dan apa itu CWE?
3. Apa arti skor 9.3, dan kenapa ada sumber yang menulis 9.8?
4. Apa arti EPSS 0,94 dan status KEV, dan kenapa keduanya mengubah prioritas?
5. Bagaimana patch dijadwalkan, dan apa yang melindungi sampai patch terpasang?
6. Bagaimana membaca laporan scan, dan kenapa ada temuan yang salah?
7. Apa bedanya vulnerability assessment, pentest, dan red team, dan apa peran SOC?
8. Bagaimana kerentanan dari peneliti luar seharusnya dilaporkan, dan apa itu SBOM?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2 dan 1.3, pertanyaan 3 di bagian 1.4, pertanyaan 4 di bagian 1.5 dan 1.6, pertanyaan 5 di bagian 1.7 dan 1.8, pertanyaan 6 di bagian 1.9, pertanyaan 7 di bagian 1.10 dan 1.11, dan pertanyaan 8 di bagian 1.12 dan 1.13. Bagian 2 membaca advisory dan CVE Record fiktif, alert `SOC-2027-0892` beserta insiden `INC-2027-096`, laporan scan Agustus, dan aturan main pentest September.

**Kapan relevan:** saat membaca advisory vendor atau berita kerentanan baru, saat alert menyebut nomor CVE, saat menilai seberapa mendesak sebuah temuan scan, saat menjelaskan ke atasan kenapa satu patch harus dipasang malam ini sementara yang lain menunggu, saat menerima laporan pentest, dan saat interview yang menanyakan "bagaimana kamu memprioritaskan kerentanan".
**Kapan bukan jawaban:** skor dan daftar tidak memberi tahu apakah sebuah sistem sudah dibobol. Bila ada tanda eksploitasi berhasil, pekerjaannya pindah ke penanganan insiden (Day 19); memasang patch saja tidak cukup. Istilah Day ini juga tidak menggantikan pengujian dan prosedur perubahan di tim infrastruktur; patch yang dipasang tergesa tanpa uji bisa mematikan layanan.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya yang dipakai di sini (asset, threat, risk, likelihood, impact, control, compensating control, attack surface, WAF, IPS, IDS, VPN, SIEM, EDR, alert, prioritas P1 sampai P4) tidak dimuat di tabel; definisinya diulang satu kalimat saat pertama muncul. Tabel berikut memuat istilah baru Day ini; cari kolom padanan bila sebuah istilah terasa abstrak.

| Istilah | Arti singkat | Padanan sehari-hari |
|---|---|---|
| Vulnerability | Kelemahan yang bisa dimanfaatkan untuk merusak kerahasiaan, keutuhan, atau ketersediaan | Jendela yang tidak terkunci |
| Exploit | Cara, kode, atau alat untuk memanfaatkan vulnerability | Cara mencongkel jendela itu |
| Zero-day | Kerentanan yang dimanfaatkan sebelum pembuatnya tahu atau sebelum ada perbaikan | Celah yang belum diketahui pemilik rumah dan tukang kunci |
| CVE | Sistem penamaan publik untuk kerentanan; satu celah, satu nomor | Nomor laporan resmi |
| CNA | Organisasi yang berwenang memberi nomor CVE dan menerbitkan CVE Record | Kantor yang berwenang mengeluarkan nomor laporan |
| CWE | Daftar jenis kelemahan (akar masalah) di perangkat lunak dan perangkat keras | Jenis cacat bangunan, misalnya "engsel model lama mudah dicongkel" |
| CVSS | Standar skor 0,0 sampai 10,0 untuk keparahan teknis kerentanan | Tingkat keparahan kerusakan bila celah dimanfaatkan |
| EPSS | Perkiraan peluang sebuah CVE dieksploitasi dalam 30 hari ke depan | Prakiraan cuaca peluang dimanfaatkan |
| CISA KEV | Katalog kerentanan yang sudah terbukti dieksploitasi di dunia nyata | Daftar modus yang sudah terbukti dipakai maling |
| NVD | Basis data kerentanan milik NIST yang memperkaya CVE dengan skor dan daftar produk | Arsip yang menambahkan catatan teknis ke setiap nomor laporan |
| Patch management | Proses menemukan, memprioritaskan, memasang, dan memverifikasi pembaruan | Jadwal perawatan rumah oleh tukang |
| Virtual patching | Aturan di WAF atau IPS yang menghadang eksploitasi tanpa mengubah kode yang rentan | Teralis sementara di depan jendela sampai kunci baru datang |
| Vulnerability scanner | Alat otomatis yang memeriksa aset terhadap daftar kerentanan yang dikenal | Petugas inspeksi yang membawa checklist |
| False positive scan | Temuan scanner yang menyatakan ada kerentanan padahal tidak ada | Checklist bilang kunci model lama, padahal dalamnya sudah diganti |
| Vulnerability assessment (VA) | Pemeriksaan sistematis untuk menemukan dan menilai kelemahan | Inspeksi rumah dengan checklist |
| Penetration test (pentest) | Pengujian yang meniru serangan nyata untuk membuktikan celah bisa ditembus | Maling bayaran yang diizinkan mencoba masuk |
| Red team | Tim yang meniru penyerang sungguhan untuk menguji deteksi dan respons | Latihan perampokan penuh tanpa memberi tahu satpam |
| Blue team | Tim yang bertahan: memantau, mendeteksi, dan merespons | Satpam dan petugas ruang CCTV |
| Purple team | Cara kerja di mana red team dan blue team berlatih bersama secara terbuka | Satpam dan maling bayaran membahas setiap percobaan bersama |
| Rules of engagement (RoE) | Aturan tertulis pengujian: cakupan, waktu, cara, dan kontak | Surat izin dan batas wilayah untuk maling bayaran |
| Coordinated disclosure | Penemu melapor ke pemilik dulu, lalu diumumkan bersama setelah ada perbaikan | Tetangga memberi tahu kamu dulu, bukan mengumumkan di grup RT |
| Bug bounty | Program yang memberi imbalan bagi pelapor kerentanan yang sah | Hadiah bagi yang menemukan dan melaporkan jendela terbuka |
| SBOM | Daftar komponen yang menyusun sebuah perangkat lunak | Daftar komposisi di kemasan makanan |

### 1.1 Vulnerability, exploit, dan zero-day

Pertanyaan pertama Sari menyangkut kalimat di advisory vendor: celah AksesGate sempat dipakai penyerang sebelum diumumkan. Tiga istilah ini sering dipakai bergantian di berita, padahal artinya berbeda dan konsekuensinya bagi SOC juga berbeda.

**Apa itu:** vulnerability (kerentanan) adalah kelemahan pada sistem, prosedur, atau cara penerapannya yang bisa dimanfaatkan sumber ancaman, dan sudah dibahas di Day 01 bagian 1.3. Program CVE memakai definisi yang lebih spesifik: satu atau lebih kelemahan dalam sebuah produk yang bisa dieksploitasi dan berdampak buruk pada kerahasiaan, keutuhan, atau ketersediaan [S2]. Exploit adalah cara, kode, atau alat yang memanfaatkan kerentanan itu. Zero-day attack adalah serangan yang memanfaatkan kerentanan perangkat keras, firmware, atau perangkat lunak yang sebelumnya belum diketahui [S1]. "Zero-day" merujuk pada jumlah hari yang dimiliki pembuat perangkat untuk memperbaiki: nol, karena serangan sudah terjadi sebelum ia tahu.

**Analogi:** jendela yang tidak terkunci adalah vulnerability, dan cara mencongkelnya adalah exploit. Zero-day adalah celah yang belum diketahui pemilik rumah maupun tukang kunci, padahal maling sudah memakainya. Batasnya: begitu tukang kunci mengumumkan celahnya dan menjual kunci baru, celah itu tidak lagi zero-day, tetapi rumah yang belum mengganti kunci tetap terbuka. Di internet, justru setelah pengumuman itulah jumlah maling yang mencoba biasanya melonjak.

**Cara kerja:** satu kerentanan berpindah status seiring waktu.

```
 kerentanan ada (belum diketahui siapa pun)
   |
   +-- penyerang menemukan dan memakainya duluan   -> serangan zero-day
   |
 vendor tahu (dilaporkan peneliti atau melihat serangan)
   |
 advisory + CVE + patch diumumkan                  -> celah publik, patch tersedia
   |
 exploit publik beredar, pemindaian massal dimulai  -> risiko organisasi yang belum patch naik tajam
   |
 patch terpasang dan diverifikasi                   -> celah tertutup di aset itu
```

NIST mencatat bahwa setiap organisasi secara default menerima risiko dari kerentanan yang belum diketahui di perangkat lunaknya, dan bahwa risiko biasanya naik setelah kerentanan diumumkan karena penyerang lebih mungkin membuat exploit untuk celah itu [S14].

**Contoh di PT JAB:** advisory AksesGate (Senin 2027-08-23 21:00 WIB) menyebut vendor mengetahui "eksploitasi terbatas" sebelum advisory terbit. Bagi korban sebelum tanggal itu, serangannya adalah zero-day: tidak ada patch, tidak ada signature, dan tidak ada nomor CVE untuk dicari. Bagi PT JAB pada Rabu pagi, celah ini sudah publik dan patch-nya ada, jadi bukan zero-day lagi. Yang membuatnya mendesak justru kebalikannya: semua penyerang sekarang tahu celahnya, sedangkan `jkt-vpn01` belum di-patch.

**Beda zero-day dengan "kerentanan baru":** kerentanan yang baru diumumkan bersama patch-nya bukan zero-day, walaupun berita sering menyebutnya begitu. Yang menentukan adalah apakah serangan terjadi sebelum pembuatnya tahu atau sebelum perbaikan ada.

**Salah paham umum:**
- "Zero-day tidak bisa dideteksi sama sekali." Signature memang tidak bisa menangkap pola yang belum dikenal (Day 03 bagian 1.4), tetapi akibatnya sering terlihat: akun admin baru di perangkat VPN, proses aneh di server, atau koneksi keluar ke alamat yang tidak biasa. Deteksi berbasis perilaku dan log yang lengkap tetap berguna.

### 1.2 CVE dan CNA

Pertanyaan kedua Sari dimulai dari nomor di judul alert. Tanpa nomor bersama, vendor, scanner, IDS, dan berita bisa menyebut satu celah dengan sepuluh nama berbeda, dan SOC tidak bisa mencocokkan apakah alert pagi ini menyangkut celah yang sama dengan yang ada di laporan scan.

**Apa itu:** CVE (Common Vulnerabilities and Exposures) adalah daftar entri untuk kerentanan yang sudah diketahui publik; setiap entri berisi nomor identifikasi, deskripsi, dan minimal satu rujukan publik [S3]. Nomornya disebut CVE ID, dan informasinya disebut CVE Record. Tujuannya agar banyak pihak bisa berdiskusi dengan yakin bahwa mereka membicarakan kerentanan yang sama [S2]. Nomor diberikan oleh CNA (CVE Numbering Authority), organisasi yang diberi wewenang memberi CVE ID dan menerbitkan CVE Record, idealnya saat kerentanan pertama kali diumumkan [S2]. Banyak CNA adalah vendor yang menomori kerentanan di produknya sendiri; ada juga proyek open source, peneliti, dan CSIRT nasional [S2]. Format CVE ID adalah `CVE-<tahun>-<nomor urut>`, misalnya `CVE-2020-29380` yang dipakai sebagai contoh di aturan CNA [S2].

**Analogi:** nomor laporan resmi. Dua orang yang melapor kehilangan di kantor polisi berbeda bisa saling mencocokkan karena ada nomor laporan, bukan karena cerita mereka mirip. Batasnya: nomor laporan tidak menilai seberapa parah kejadiannya dan tidak menyelesaikan kasusnya. CVE hanya memberi nama; penilaian dan perbaikan datang dari tempat lain.

**Cara kerja:**

1. Kerentanan ditemukan, biasanya oleh vendor sendiri atau peneliti yang melapor ke vendor.
2. CNA yang cakupannya paling sesuai (sering vendor produk itu) mendapat hak pertama untuk memberi nomor. Bila CNA itu menolak atau tidak menjawab dalam 72 jam untuk kerentanan yang sudah publik, Root (CNA pengawas di atasnya) memutuskan dan menunjuk CNA lain [S2].
3. CNA menerbitkan CVE Record berisi deskripsi, produk dan versi terdampak, dan rujukan.
4. Basis data lain, seperti NVD milik NIST, menambahkan informasi seperti skor CVSS, jenis CWE, dan daftar produk dalam format baku (CPE). Proses penambahan ini disebut enrichment.

Program CVE dijalankan MITRE dengan kontrak dari CISA (badan keamanan siber pemerintah Amerika Serikat) [S23][S24]. Perkembangan pendanaan program ini sejak 2025 ada di bagian 5.

**Contoh di PT JAB:** advisory AksesGate memuat `CVE-2027-XXXXX` yang diberikan vendor sendiri sebagai CNA. Nomor yang sama dipakai di rule deteksi yang dibuat Yoga Pratama di SIEM untuk `SOC-2027-0892`, di plugin scanner yang dirilis Selasa, dan di entri KEV. Karena nomornya sama, kamu bisa menjawab tiga pertanyaan dengan cepat: apakah scanner sudah bisa mendeteksi celah ini, apakah ada di KEV, dan berapa EPSS-nya.

### 1.3 CWE

Advisory AksesGate menyebut jenis kelemahan CWE-22. Pertanyaan kedua Sari yang tersisa: apa hubungan CWE dengan CVE?

**Apa itu:** CWE (Common Weakness Enumeration) adalah daftar jenis kelemahan perangkat lunak dan perangkat keras yang disusun komunitas, beserta taksonominya [S4]. Kelemahan (weakness) di sini adalah kondisi pada komponen yang, dalam keadaan tertentu, bisa ikut menyebabkan kerentanan [S4]. CVE menamai satu kejadian kerentanan di produk tertentu; CWE menamai jenis kesalahan yang menjadi akarnya. CWE disponsori CISA dan dijalankan MITRE [S4].

**Analogi:** jenis cacat bangunan, misalnya "engsel model lama yang bisa diangkat dari luar". Satu jenis cacat bisa muncul di ribuan rumah; setiap rumah yang terkena punya nomor laporannya sendiri (CVE). Batasnya: CWE tidak memberi tahu rumah mana yang terkena, hanya pola kesalahannya.

**Cara kerja:** setiap tahun MITRE menerbitkan CWE Top 25, peringkat kelemahan paling berbahaya berdasarkan data CVE. Edisi 2025 dihitung dari 39.080 CVE Record [S5]. Tabel berikut memuat lima teratas edisi 2025; perhatikan bahwa tiga di antaranya adalah kesalahan aplikasi web yang dibahas di Day 15.

| Peringkat | CWE | Nama ringkas | Contoh dampak |
|---|---|---|---|
| 1 | CWE-79 | Cross-site scripting (XSS) | Skrip penyerang berjalan di browser korban |
| 2 | CWE-89 | SQL injection | Perintah database disisipkan lewat isian aplikasi |
| 3 | CWE-352 | Cross-site request forgery (CSRF) | Browser korban dipaksa mengirim permintaan sah |
| 4 | CWE-862 | Missing authorization | Pengguna mengakses fungsi tanpa pemeriksaan hak |
| 5 | CWE-787 | Out-of-bounds write | Program menulis di luar batas memori yang disediakan |

Sumber: daftar CWE Top 25 2025 [S5].

**Contoh di PT JAB:** `CVE-2027-XXXXX` tergolong CWE-22 (path traversal, peringkat 6 di Top 25 2025 [S5]): permintaan dengan pola `../` membuat portal VPN membaca file di luar folder yang seharusnya, termasuk file konfigurasi. Bagi SOC, CWE memberi petunjuk apa yang dicari di log: permintaan dengan `../` atau versi ter-encode-nya. Bagi tim aplikasi PT JAB, CWE Top 25 dipakai sebagai daftar kesalahan yang dicek saat review kode portal.

### 1.4 CVSS

Pertanyaan ketiga Sari menyangkut dua angka: vendor menulis 9.3, sedangkan basis data lain menulis 9.8. Keduanya bisa benar, karena dihitung dengan versi CVSS yang berbeda.

**Apa itu:** CVSS (Common Vulnerability Scoring System) adalah standar terbuka milik FIRST untuk menilai karakteristik dan keparahan kerentanan dengan skor 0,0 sampai 10,0. Versi terbaru, CVSS v4.0, terbit 1 November 2023 dan punya empat kelompok metrik: Base, Threat, Environmental, dan Supplemental [S6]. Skor dipetakan ke lima kategori: None 0,0; Low 0,1 sampai 3,9; Medium 4,0 sampai 6,9; High 7,0 sampai 8,9; Critical 9,0 sampai 10,0 [S6]. Panduan resminya menegaskan bahwa skor Base mengukur keparahan, bukan risiko, dan tidak boleh dipakai sendirian untuk menilai risiko [S7].

**Analogi:** tingkat keparahan kerusakan bila celah dimanfaatkan, seperti penilaian "kalau jendela ini dicongkel, maling bisa masuk ke seluruh rumah atau hanya ke gudang". Batasnya: penilaian itu tidak mengatakan apakah ada maling di kompleksmu, atau apakah jendela itu menghadap jalan raya atau tembok. Dua hal itu urusan EPSS, KEV, dan konteks asetmu.

**Cara kerja:** skor dihitung dari metrik yang ditulis sebagai vector string. Tabel berikut menjelaskan metrik Base CVSS v4.0; baca kolom Pertanyaan untuk memahami apa yang dinilai tiap metrik [S6][S7].

| Metrik | Kode | Pertanyaan | Nilai |
|---|---|---|---|
| Attack Vector | AV | Dari mana penyerang harus berada? | Network, Adjacent, Local, Physical |
| Attack Complexity | AC | Apakah penyerang harus mengakali pertahanan tertentu? | Low, High |
| Attack Requirements | AT | Apakah butuh kondisi khusus di sistem target? | None, Present |
| Privileges Required | PR | Apakah penyerang harus sudah login? | None, Low, High |
| User Interaction | UI | Apakah butuh tindakan korban? | None, Passive, Active |
| VC, VI, VA | | Dampak pada kerahasiaan, keutuhan, ketersediaan sistem yang rentan | High, Low, None |
| SC, SI, SA | | Dampak pada sistem lain sesudahnya (subsequent system) | High, Low, None |

Siapa mengisi apa juga berbeda. Pembuat produk dan basis data seperti NVD biasanya hanya menerbitkan skor Base. Metrik Threat (misalnya Exploit Maturity: apakah sudah ada serangan) dan Environmental (seberapa penting sistem itu bagi organisasimu, control apa yang ada) diisi oleh pemakai, karena bergantung pada keadaan masing-masing [S7]. Untuk menandai skor mana yang dipakai, v4.0 memakai nama CVSS-B (Base saja), CVSS-BT (Base dan Threat), CVSS-BE (Base dan Environmental), dan CVSS-BTE (ketiganya) [S6]. Metrik Supplemental, seperti Automatable (apakah seluruh langkah eksploitasi bisa diotomatiskan) dan Safety, hanya memberi informasi tambahan dan tidak mengubah skor [S7].

Perbedaan utama v4.0 dengan v3.1 [S6][S7]:

- Metrik Scope di v3.1 dihapus dan diganti pemisahan dampak pada sistem yang rentan (VC, VI, VA) dan sistem sesudahnya (SC, SI, SA).
- Metrik Attack Requirements (AT) baru, memisahkan "butuh kondisi khusus" dari Attack Complexity.
- User Interaction kini punya tiga nilai: None, Passive, Active.
- Kelompok Temporal berganti nama menjadi Threat, dan dua metriknya (Remediation Level, Report Confidence) dihapus.
- Kelompok Supplemental ditambahkan.

**Contoh di PT JAB:** advisory AksesGate memberi vektor berikut. Vektor ini sama persis dengan vektor Base untuk dua kerentanan eksekusi kode jarak jauh tanpa login (Log4Shell dan Shellshock) di dokumen contoh resmi FIRST, yang skornya 9.3 [S8].

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N      -> 9.3 Critical (CVSS-B)
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H                         -> 9.8 Critical
```

Cara membacanya: bisa diserang lewat jaringan (AV:N), tanpa trik khusus (AC:L), tanpa kondisi khusus (AT:N), tanpa login (PR:N), tanpa tindakan korban (UI:N), dan dampaknya tinggi untuk ketiga sifat di perangkat VPN itu sendiri. Angka 9.8 berasal dari vektor setara di CVSS v3.1; contoh Shellshock di dokumen FIRST juga bernilai 9.8 di v3.1 dan 9.3 di v4.0 [S8]. Jadi keduanya benar untuk versinya masing-masing. Yang penting dicatat adalah versinya, dan bahwa keduanya sama-sama Critical.

**Beda CVSS dengan risiko:** CVSS menilai celahnya, risiko menilai celah itu di rumahmu. Kerentanan CVSS 9.8 di server lab yang tidak tersambung ke mana pun bisa berisiko rendah; kerentanan CVSS 7.5 di perangkat yang menghadap internet dan sedang dieksploitasi bisa jauh lebih mendesak.

**Salah paham umum:**
- "Urutkan saja temuan dari CVSS tertinggi." NIST SP 800-115 mengingatkan penguji untuk tidak begitu saja menerima tingkat risiko yang diberikan scanner, karena konteks bisa membuat risiko sebenarnya jauh lebih rendah atau lebih tinggi [S15].

### 1.5 EPSS

Pertanyaan keempat Sari punya dua bagian. Bagian pertama: angka 0,94 di samping nomor CVE.

**Apa itu:** EPSS (Exploit Prediction Scoring System) adalah model berbasis data yang memperkirakan peluang sebuah CVE yang sudah dipublikasikan akan dieksploitasi di dunia nyata dalam 30 hari ke depan [S9]. Skornya berupa peluang 0 sampai 1, dihitung ulang setiap hari untuk semua CVE, dan dikelola EPSS Special Interest Group di FIRST [S9]. Selain peluang, EPSS menerbitkan persentil: CVE dengan persentil 90 punya skor lebih tinggi dari 90 persen CVE lain [S9]. Peluang adalah ukuran mutlak, persentil adalah peringkat relatif.

**Analogi:** prakiraan cuaca tentang peluang celah ini dimanfaatkan. "Peluang hujan 94 persen" tidak berarti rumahmu pasti kebanjiran; itu berarti hampir pasti hujan turun di wilayah itu, dan rumah yang atapnya bocor sebaiknya ditambal hari ini. Batasnya: prakiraan berlaku untuk wilayah luas (seluruh internet), bukan untuk rumahmu. EPSS tidak tahu apakah perangkatmu terekspos atau sudah dilindungi.

**Cara kerja:** model melatih dirinya dari data eksploitasi yang teramati dan ciri-ciri setiap CVE, lalu menghitung skor harian. FAQ EPSS menyebut tiga batasan yang harus diingat [S9]:

- EPSS tidak memperhitungkan konteks instalasi tertentu, control yang ada, atau faktor khusus organisasi; ia hanya mengukur sisi peluang ancaman dari risiko, bukan dampak atau nilai aset.
- CVSS dan EPSS mengukur hal yang berbeda dan secara empiris tidak berkorelasi.
- Mengalikan EPSS dengan CVSS tidak menghasilkan peluang yang bermakna, jadi jangan dilakukan.

Model EPSS diperbarui berkala. Versi 4 mulai dipakai 17 Maret 2025 dan versi 5 mulai 15 Juni 2026; skor bisa bergeser pada tanggal pergantian versi karena metodenya berubah, bukan karena kerentanannya berubah [S10].

**Contoh di PT JAB:** Rabu pagi, EPSS untuk `CVE-2027-XXXXX` adalah 0,94 dengan persentil 99,9. Bandingkan dengan temuan browser di laptop `JKT-WS-1172` di laporan scan, yang CVSS-nya 8.8 tetapi EPSS-nya 0,03. Keduanya High atau Critical, tetapi hanya satu yang hampir pasti sedang diburu penyerang.

**Beda EPSS dengan KEV:** EPSS adalah perkiraan ("kemungkinan besar akan dipakai"), KEV adalah catatan fakta ("sudah terbukti dipakai"). CVE bisa punya EPSS tinggi sebelum masuk KEV, dan entri KEV biasanya juga punya EPSS tinggi.

**Salah paham umum:**
- "EPSS 0,94 berarti 94 persen server kita akan dibobol." EPSS memperkirakan apakah aktivitas eksploitasi terhadap CVE itu akan teramati di mana pun dalam 30 hari, bukan peluang perangkat tertentu berhasil dibobol.

### 1.6 CISA KEV

Bagian kedua pertanyaan keempat Sari: Selasa siang, `CVE-2027-XXXXX` masuk katalog KEV.

**Apa itu:** KEV (Known Exploited Vulnerabilities) Catalog adalah katalog milik CISA yang menjadi sumber rujukan kerentanan yang sudah dieksploitasi di dunia nyata [S11]. Sebuah kerentanan masuk KEV bila memenuhi tiga syarat: punya CVE ID, ada bukti yang dapat diandalkan bahwa ia sedang atau pernah dieksploitasi, dan ada langkah perbaikan yang jelas, misalnya pembaruan dari vendor [S11]. Pemindaian, riset keamanan, atau proof-of-concept publik saja tidak cukup sebagai bukti eksploitasi [S11]. Setiap entri memuat tanggal masuk, tanggal tenggat untuk instansi pemerintah AS, tindakan yang diminta, dan kolom apakah kerentanan itu diketahui dipakai dalam kampanye ransomware [S11]. Per 21 Oktober 2026 katalog memuat 1.754 entri [S11].

**Analogi:** daftar modus yang sudah terbukti dipakai maling, yang diedarkan polisi ke semua warga. Batasnya: daftar itu hanya memuat modus yang sudah tertangkap basah dan dilaporkan. Modus yang belum ketahuan tidak ada di sana, jadi "tidak ada di KEV" tidak berarti "tidak pernah dipakai".

**Cara kerja:** KEV awalnya dibentuk oleh BOD 22-01 (November 2021), perintah CISA kepada instansi sipil federal AS untuk menutup kerentanan di katalog dalam dua minggu untuk CVE tahun 2021 ke atas dan enam bulan untuk CVE yang lebih lama, kecuali CISA menetapkan lain [S12]. Pada 10 Juni 2026, CISA menerbitkan BOD 26-04 yang mencabut BOD 22-01 dan BOD 19-02 [S13]. Katalog KEV dan kriterianya tetap; yang berubah adalah cara menghitung tenggat. BOD 26-04 memakai empat pertanyaan [S13]:

1. Apakah aset terekspos ke internet?
2. Apakah CVE-nya ada di KEV?
3. Apakah seluruh langkah eksploitasi bisa diotomatiskan?
4. Apakah eksploitasi memberi kendali sebagian atau penuh atas sistem?

Kombinasi paling berbahaya (terekspos, di KEV, bisa diotomatiskan, memberi kendali penuh) mendapat tenggat tiga hari ditambah forensic triage, yaitu pemeriksaan apakah aset sudah telanjur dibobol sebelum diperbaiki [S13]. Tingkat lain mendapat tenggat lebih panjang, sampai pilihan memperbaiki saat upgrade sistem berikutnya [S13][S26]. Tenggat juga dinamis: aset yang dicabut dari internet bisa mendapat waktu lebih panjang [S13]. Aturan ini hanya mengikat instansi sipil federal AS, tetapi CISA mendorong semua organisasi memakai KEV sebagai masukan prioritas [S11].

**Contoh di PT JAB:** PT JAB bukan instansi AS, tetapi kebijakan patch-nya meniru logika yang sama (bagian 1.7). `CVE-2027-XXXXX` memenuhi keempat syarat: `jkt-vpn01` menghadap internet, celahnya di KEV, exploit-nya bisa dijalankan otomatis tanpa login, dan berhasil berarti penyerang bisa membaca konfigurasi dan menjalankan perintah di perangkat. Karena itu Dimas Prasetyo (SOC lead) memasukkannya ke kategori darurat dan meminta forensic triage, yang menjadi insiden `INC-2027-096` di bagian 2.2.

**Beda KEV dengan daftar "Critical":** KEV memuat kerentanan dari semua tingkat CVSS selama terbukti dieksploitasi. Kerentanan Medium yang sedang dipakai penyerang bisa lebih mendesak daripada Critical yang tidak pernah disentuh.

### 1.7 Patch management

Pertanyaan kelima Sari dimulai dari keputusan Dimas: patch `jkt-vpn01` malam ini pukul 22:00, bukan pagi ini dan bukan bulan depan.

**Apa itu:** patch adalah pembaruan perangkat lunak yang menutup kelemahan (Day 01). Patch management (enterprise patch management) adalah proses mengidentifikasi, memprioritaskan, mendapatkan, memasang, dan memverifikasi patch, pembaruan, dan upgrade di seluruh organisasi [S14]. NIST menyebut patching sebagai perawatan pencegahan yang wajib bagi teknologi, setara dengan servis berkala armada kendaraan, dan sebagai biaya menjalankan bisnis [S14].

**Analogi:** jadwal perawatan rumah oleh tukang. Ada perawatan rutin bulanan, ada panggilan darurat saat kunci jendela ternyata bisa dicongkel dan maling sedang berkeliaran. Batasnya: tukang rumah tidak membuat rumahmu tidak bisa dipakai saat bekerja, sedangkan patch sering butuh restart dan bisa merusak aplikasi lain bila tidak diuji.

**Cara kerja:** NIST SP 800-40 Rev. 4 menyebut patch sebagai salah satu dari empat respons risiko kerentanan [S14]:

| Respons | Contoh dari NIST | Contoh di PT JAB |
|---|---|---|
| Accept (terima) | Mengandalkan control yang ada, atau dampaknya dinilai cukup rendah | Temuan Low di server lab tertutup |
| Mitigate (kurangi) | Patch, mematikan fitur yang rentan, upgrade, atau control tambahan seperti segmentasi | Patch `jkt-vpn01`; mematikan fitur clientless sementara |
| Transfer (alihkan) | Asuransi siber, atau pindah ke SaaS yang patch-nya diurus penyedia | Email sudah di Microsoft 365, patch server email diurus Microsoft |
| Avoid (hindari) | Menghapus perangkat lunak atau mematikan aset yang rentan | Mematikan server uji lama yang tidak dipakai |

NIST juga membagi skenario yang harus disiapkan setiap organisasi [S14]: patching rutin (sebagian besar patch, sesuai siklus rilis), patching darurat (kerentanan berat atau sedang dieksploitasi), mitigasi darurat (perlindungan sementara sebelum patch tersedia atau bila patch bermasalah), dan aset yang tidak bisa di-patch (diisolasi atau dilindungi cara lain). NIST mengingatkan bahwa patching rutin sering ditunda karena terasa tidak mendesak, padahal penundaan membuka banyak kesempatan bagi penyerang dan membuat patching darurat lebih sulit karena patch lama harus dipasang dulu [S14]. Siklusnya selalu sama: ketahui kerentanan yang mengenai asetmu, rencanakan respons, siapkan dan pasang, lalu verifikasi [S14].

Patch tidak selalu bisa dipasang seketika. NIST menyebut alasan yang umum: patch belum tersedia, produk sudah tidak didukung vendor, harus menunggu jendela pemeliharaan atau uji dulu, atau sumber daya terbatas sehingga patch lain didahulukan [S14].

**Contoh di PT JAB:** kebijakan patch PT JAB, disusun Nina Kartika (Manajer Risiko dan Kepatuhan TI) dan Agung Prabowo (Lead Infrastruktur), memakai tabel berikut. Baca dari atas: kategori pertama yang cocok menentukan tenggat.

| Kategori | Syarat | Tenggat sejak diketahui |
|---|---|---|
| Darurat | Di KEV atau ada bukti eksploitasi, dan aset terekspos internet | 72 jam; mitigasi sementara dalam 24 jam; forensic triage |
| Tinggi | Di KEV pada aset internal, atau Critical pada aset terekspos internet | 7 hari |
| Sedang | Critical atau High pada aset internal, tanpa KEV | 30 hari |
| Rutin | Medium dan Low | Siklus patch bulanan, maksimal 90 hari |

`jkt-vpn01` masuk kategori Darurat. Patch dijadwalkan pukul 22:00 karena saat patch dipasang VPN mati sekitar 30 menit, dan sebagian engineer NOC bekerja dari rumah di jam kerja. Itu keputusan availability yang sah, selama celah dilindungi sementara (bagian 1.8).

**Beda patch dengan upgrade dan mitigasi:** patch menutup kerentanan di versi yang sama, upgrade pindah ke versi yang lebih baru (kadang satu-satunya cara bila versi lama tidak didukung lagi), mitigasi mengurangi peluang eksploitasi tanpa menghilangkan kerentanannya. NIST mencatat hanya patch, update, dan upgrade yang benar-benar menghilangkan kerentanan tanpa mengorbankan fungsi [S14].

### 1.8 Virtual patching dan compensating control

Bagian kedua pertanyaan kelima Sari: dari Senin malam sampai Rabu pukul 22:00, apa yang melindungi `jkt-vpn01`?

**Apa itu:** virtual patching adalah lapisan penegakan yang mendeteksi dan menghadang upaya eksploitasi kerentanan yang dikenal tanpa mengubah kode yang rentan [S18]. Alatnya biasanya perangkat perantara seperti WAF (penyaring isi permintaan web, Day 03 bagian 1.8) atau IPS (sistem yang menghadang lalu lintas berbahaya di jalur, Day 03 bagian 1.3), atau modul di server web [S18]. Compensating control adalah pengaman pengganti yang memberi perlindungan setara ketika pengaman utama tidak bisa dipasang (Day 01 bagian 1.5). Virtual patch adalah salah satu bentuknya; bentuk lain adalah membatasi siapa yang bisa menjangkau aset, mematikan fitur, atau menambah pemantauan.

**Analogi:** teralis sementara yang dipasang di depan jendela sampai kunci baru datang. Maling yang memakai cara mencongkel yang dikenal tertahan teralis. Batasnya: teralis tidak memperbaiki jendelanya. Maling dengan cara lain yang tidak tertahan teralis tetap bisa masuk, jadi kunci baru tetap harus dipasang.

**Cara kerja:** OWASP menyusun langkah virtual patching mirip penanganan insiden [S18]: siapkan alat dan prosesnya sebelum dibutuhkan; identifikasi kerentanan (dari advisory, pentest, atau insiden); analisis apakah virtual patch cocok untuk celah itu; buat aturan, sebaiknya berupa daftar input yang sah daripada daftar pola serangan karena daftar pola mudah diakali; pasang dulu dalam mode mencatat saja untuk melihat false positive (permintaan sah yang ikut tertolak), lalu aktifkan; terakhir, catat di tiket dan hapus aturannya setelah perbaikan permanen terpasang. OWASP menegaskan virtual patch tidak menghilangkan kerentanannya [S18].

```
 Senin 21:00   advisory + patch vendor             celah publik
 Selasa 10:00  masuk KEV                            kategori Darurat
 Selasa 23:10  mitigasi darurat:                    fitur clientless dimatikan (rekomendasi vendor)
               + aturan IPS jkt-fw01 mode blokir    pola path traversal ke portal VPN
               + rule SIEM dari advisory            -> SOC-2027-0892 pagi ini
 Rabu 22:00    patch firmware 7.2.5                 perbaikan permanen
 Kamis 08:00   scan ulang + cek log                 verifikasi; aturan sementara ditinjau
```

**Contoh di PT JAB:** perlindungan sementara `jkt-vpn01` berlapis tiga, sesuai prinsip defense in depth. Pertama, fitur portal clientless dimatikan sesuai mitigasi di advisory; ini mitigasi, bukan virtual patch, karena fiturnya benar-benar dihentikan. Kedua, signature IPS di `jkt-fw01` diaktifkan untuk pola path traversal ke alamat portal VPN; ini virtual patch. Ketiga, rule SIEM baru memantau pola yang sama di log web `jkt-vpn01`; ini detective control. Karena `jkt-fw01` tidak membuka enkripsi TLS ke `jkt-vpn01`, efektivitas signature IPS masih harus dicek Agung, jadi mematikan fitur rentan dinilai sebagai lapisan yang paling bisa diandalkan.

Untuk aset yang tidak bisa di-patch sama sekali, compensating control yang lazim adalah isolasi. Server uji lama yang tidak lagi didukung vendor dipindah ke segmen terpisah yang hanya bisa dijangkau dari jump host admin.

**Beda virtual patching dengan patch:** patch mengubah kode yang rentan; virtual patch menghadang permintaan sebelum sampai ke kode itu. Virtual patch cepat dan tidak butuh restart, tetapi hanya melindungi jalur yang lewat alatnya dan hanya varian yang dikenali aturannya.

**Salah paham umum:**
- "Sudah ada virtual patch di WAF, patch bisa menunggu tahun depan." Day 03 memperlihatkan tiga permintaan SQL injection yang lolos WAF karena penyamaran. Virtual patch adalah jembatan sampai patch terpasang, bukan pengganti, dan OWASP meminta aturannya dihapus setelah kode diperbaiki [S18].

### 1.9 Vulnerability scanner, vulnerability assessment, dan false positive scan

Pertanyaan keenam Sari membawa laporan scan Agustus: 612 temuan dari pemindaian 21 Agustus, dan Agung bilang beberapa di antaranya salah.

**Apa itu:** vulnerability scanner adalah alat otomatis yang memeriksa aset (server, laptop, perangkat jaringan, aplikasi web) terhadap basis data kerentanan yang dikenal: versi perangkat lunak, konfigurasi, layanan yang terbuka. Vulnerability assessment (VA) adalah pemeriksaan sistematis atas sistem untuk menilai kecukupan pengamannya dan menemukan kekurangannya [S16]; scanning adalah alat utamanya, ditambah verifikasi manual dan penilaian konteks. False positive scan adalah temuan yang menyatakan kerentanan ada padahal tidak ada [S15].

**Analogi:** inspeksi rumah dengan checklist. Petugas berkeliling, mencatat model kunci, jenis jendela, dan umur instalasi listrik, lalu mencocokkannya dengan daftar model bermasalah. Batasnya: petugas tidak mencoba membuka jendela, jadi ia bisa salah mencatat kunci yang tampak model lama padahal dalamnya sudah diganti (false positive), dan bisa melewatkan jendela yang tidak ada di checklist (false negative).

**Cara kerja:** NIST SP 800-115 mencatat sifat scanner yang perlu dipahami [S15]:

- Scanner hanya melihat sistem yang aktif saat dipindai, dan cenderung menemukan kerentanan di permukaan.
- Seperti antivirus dan IDS, scanner bergantung pada basis data signature yang harus diperbarui sebelum setiap pemindaian; kerentanan yang diumumkan setelah pemindaian tidak ada di laporan.
- Tingkat false positive-nya tinggi, jadi hasilnya harus ditafsirkan orang yang paham jaringan dan sistem operasi. False negative juga tinggi; memakai lebih dari satu scanner atau metode lain membantu.
- Tingkat risiko dari scanner tidak boleh diterima mentah-mentah; penguji menentukan risiko sebenarnya sesuai konteks.

Penyebab false positive yang paling sering adalah pemeriksaan berdasarkan nomor versi. Banyak distribusi Linux memasang perbaikan keamanan ke versi lama (backport) tanpa mengubah nomor versi utama, sehingga scanner yang hanya membaca banner versi mengira paket itu belum diperbaiki.

**Contoh di PT JAB:** scanner PT JAB berjalan dari server `jkt-vscan01` di data center setiap Sabtu ketiga tiap bulan. Ada tiga pelajaran dari laporan Agustus, dibaca lengkap di bagian 2.3. Pertama, `CVE-2027-XXXXX` tidak ada di laporan karena diumumkan dua hari setelah pemindaian; itu sebabnya Selasa pagi tim menjalankan scan khusus untuk perangkat AksesGate setelah plugin scanner diperbarui. Kedua, temuan OpenSSH di bastion Linux `jkt-bastion01` ternyata false positive: scanner membaca nomor versi, padahal paket distribusinya sudah berisi perbaikan (backport). Ketiga, saat pemindaian 21 Agustus malam, sensor IDS `jkt-ids01` memunculkan alert `SOC-2027-0893` karena lalu lintas scanner mirip serangan; Dwi Cahyono (analyst L1) menutupnya setelah mencocokkan alamat sumber dan jendela waktunya dengan jadwal scan yang tercatat di kalender SOC.

**Salah paham umum:**
- "Temuan yang terbukti false positive dihapus saja dari scanner untuk semua aset." Pengecualian sebaiknya sempit (satu temuan, satu aset, dengan alasan dan tanggal tinjau ulang), supaya kerentanan sungguhan di aset lain tidak ikut tersembunyi. Pola yang sama berlaku untuk alert: alamat scanner dicatat dan dijadwalkan, tetapi tidak dikecualikan dari semua deteksi tanpa batas waktu.

### 1.10 Penetration test dan red team

Pertanyaan ketujuh Sari menyebut dua kegiatan: pentest tahunan September 2027 dan rencana latihan red team 2028. Keduanya memakai orang yang "menyerang", tetapi tujuannya berbeda.

**Apa itu:** penetration test adalah pengujian keamanan di mana penguji meniru serangan nyata untuk menemukan cara melewati pengaman aplikasi, sistem, atau jaringan; penguji sering menggabungkan beberapa kerentanan untuk mendapat akses lebih besar daripada yang bisa diberikan satu kerentanan [S15][S16]. Pentest juga berguna untuk mengukur seberapa canggih penyerang yang dibutuhkan, control tambahan apa yang perlu, dan apakah pertahanan mampu mendeteksi dan merespons [S15]. Red team adalah kelompok yang diizinkan dan diorganisasi untuk meniru kemampuan serangan calon musuh terhadap organisasi, dengan tujuan memperbaiki keamanan dengan memperlihatkan dampak serangan yang berhasil dan apa yang berhasil bagi pihak bertahan [S17].

**Analogi:** pentest adalah maling bayaran yang diizinkan mencoba masuk lewat pintu dan jendela yang disepakati, lalu melaporkan setiap celah yang berhasil ditembus. Red team adalah latihan perampokan penuh tanpa memberi tahu satpam: "perampok" bebas memilih jalan (termasuk menipu resepsionis), dan yang diuji adalah apakah satpam dan ruang CCTV menyadarinya. Batasnya: keduanya tetap terikat izin dan aturan tertulis; tanpa izin, kegiatan yang sama adalah serangan sungguhan.

**Cara kerja:** NIST SP 800-115 membagi pentest menjadi empat fase [S15]:

```
 Planning ---> Discovery ---> Attack ---> Reporting
 (aturan,       (cari info,      (coba tembus,
  persetujuan,   scan, cari       naikkan akses;
  tujuan)        kerentanan)      bila dapat info baru,
                     ^            kembali ke Discovery)
                     +----------------+
```

Pada fase Planning, aturan ditetapkan, persetujuan manajemen dicatat, dan tujuan pengujian disepakati; belum ada pengujian sama sekali [S15]. Dokumen aturannya disebut rules of engagement (RoE): cakupan alamat dan aplikasi, jendela waktu, teknik yang dilarang, dan kontak darurat. NIST juga mengingatkan bahwa pentest bisa merusak atau mematikan sistem walaupun dilakukan penguji berpengalaman, jadi harus direncanakan dan diberitahukan dengan hati-hati [S15]. Pentest bisa memakai cara non-teknis seperti social engineering dan uji keamanan fisik [S15].

Red team biasanya berjalan lebih lama, punya tujuan yang dirumuskan seperti penyerang ("dapatkan data pelanggan" atau "kuasai domain AD"), dan sengaja tidak diberitahukan kepada sebagian besar tim pertahanan. Pihak netral yang mengawasi aturan main sering disebut white team [S17].

**Contoh di PT JAB:** pentest tahunan dijadwalkan 13 sampai 24 September 2027 oleh firma luar, dengan cakupan portal pelanggan, `jkt-vpn01`, dan rentang `198.51.100.0/24`; RoE-nya dibaca di bagian 2.4. SOC diberi tahu jadwal dan alamat sumber penguji. Rencana red team 2028 berbeda: Hendra Wijaya (Direktur Teknologi) ingin menguji apakah SOC menyadari serangan yang dimulai dari phishing sampai akses ke `JKT-FS01`, jadi hanya Dimas dan Hendra yang tahu jadwalnya.

**Beda pentest dengan red team:** pentest mencari sebanyak mungkin celah di cakupan tertentu dan biasanya diketahui tim pertahanan; red team mengejar satu tujuan dengan jalan apa pun yang diizinkan dan menguji deteksi serta respons. Hasil pentest adalah daftar temuan; hasil red team adalah cerita serangan dan daftar titik di mana pertahanan melihat atau tidak melihat.

**Salah paham umum:**
- "Pentest lulus berarti sistem aman." Pentest hanya menguji cakupan dan waktu yang disepakati, dengan kerentanan yang dikenal saat itu. `CVE-2027-XXXXX` diumumkan sebulan sebelum pentest; seandainya pentest dilakukan Juli, celah ini tidak akan ada di laporannya.

### 1.11 Blue team dan purple team

Bagian akhir pertanyaan ketujuh Sari: bila ada red team, siapa lawannya, dan apa peran SOC?

**Apa itu:** blue team adalah kelompok yang mempertahankan sistem informasi organisasi dengan menjaga postur keamanannya terhadap penyerang tiruan (red team) [S17]. Dalam pekerjaan sehari-hari, blue team adalah SOC, tim respons insiden, dan tim yang memasang dan merawat control. Purple team bukan tim ketiga yang permanen, melainkan cara kerja di mana anggota red team dan blue team berbagi pengetahuan secara terbuka untuk memperbaiki keamanan [S22]. Polanya: red team menjalankan satu teknik, blue team memeriksa apakah teknik itu terlihat di log dan alert, lalu keduanya memperbaiki deteksi bersama sebelum teknik berikutnya.

**Analogi:** blue team adalah satpam dan petugas ruang CCTV. Purple team adalah satpam dan maling bayaran yang duduk bersama, mencoba satu jendela, lalu memeriksa rekaman CCTV bersama untuk melihat apakah percobaan itu terekam. Batasnya: purple team tidak menguji apakah satpam waspada tanpa diberi tahu; untuk itu tetap butuh red team.

**Contoh di PT JAB:** setelah pentest September, Sari mengusulkan satu hari purple team: penguji mengulang lima teknik yang berhasil di laporan, dan SOC memeriksa apakah setiap teknik memunculkan alert di Splunk. Teknik yang tidak terlihat menjadi bahan rule deteksi baru.

### 1.12 Responsible atau coordinated disclosure dan bug bounty

Pertanyaan kedelapan Sari dimulai dari email yang masuk Selasa ke `abuse@jab.example`: seorang peneliti menulis bahwa halaman lupa password `portal.jab.example` membocorkan apakah sebuah nomor pelanggan terdaftar, dan menyatakan akan menunggu jawaban sebelum mempublikasikannya.

**Apa itu:** coordinated vulnerability disclosure (CVD) adalah cara menyebarkan informasi kerentanan secara terkoordinasi dan serentak bersama mitigasinya, supaya semua pihak yang berkepentingan menerimanya pada waktu yang sama [S20]. Istilah lama "responsible disclosure" merujuk gagasan yang sama: penemu melapor ke pemilik dulu, memberi waktu untuk memperbaiki, lalu mengumumkan. Vulnerability disclosure policy (VDP) adalah kebijakan tertulis organisasi yang menyediakan saluran pelaporan dan melindungi peneliti yang beritikad baik; bug bounty berbeda dari VDP karena memberi imbalan kepada pelapor berdasarkan aturan yang ditetapkan [S21].

**Analogi:** tetangga yang melihat jendelamu terbuka memberi tahu kamu dulu, bukan mengumumkannya di grup RT. Bug bounty adalah hadiah yang kamu umumkan untuk siapa pun yang menemukan dan melaporkan jendela terbuka dengan cara yang benar. Batasnya: tetangga yang baik tetap boleh mengumumkan bila kamu bertahun-tahun tidak memperbaiki, dan hadiah tidak membenarkan orang memanjat masuk rumahmu.

**Cara kerja:** proses CVD yang dijalankan CISA sebagai koordinator berjalan kira-kira begini [S20]: laporan masuk, diperiksa apakah sah dan belum publik, vendor dihubungi dan detail teknis dikonfirmasi, nomor CVE ditentukan bila memenuhi aturan program CVE, teks advisory dan waktu publikasi disepakati, advisory diterbitkan, lalu kerentanannya dievaluasi untuk KEV. Bila vendor tidak menanggapi atau tidak mau berkomitmen pada waktu perbaikan yang wajar, CISA bisa mengumumkan secepatnya 45 hari setelah upaya kontak pertama, ada atau tidak ada patch [S20]. Batas waktu seperti ini mendorong vendor bergerak tanpa membiarkan pengguna buta terlalu lama.

**Contoh di PT JAB:** PT JAB belum punya VDP resmi, jadi email peneliti masuk ke kotak abuse. Sari meneruskannya ke Lutfi Hakim (Lead DevOps) dan Nina, lalu membalas peneliti dengan terima kasih dan kontak. Celah di aplikasi buatan sendiri seperti ini biasanya tidak mendapat CVE, karena tidak ada produk yang dipakai pihak lain. Laporan ini menjadi alasan Nina mengusulkan VDP dengan alamat khusus `security@jab.example` dan kebijakan tertulis tentang apa yang boleh diuji peneliti. Bug bounty berbayar ditunda sampai VDP berjalan, karena bug bounty tanpa proses penanganan laporan hanya menghasilkan antrean.

### 1.13 SBOM

Permintaan Lutfi kepada vendor aplikasi MyJAB menutup pertanyaan kedelapan Sari. Saat advisory komponen open source populer keluar, pertanyaan pertama yang sulit dijawab adalah "aplikasi kita yang mana yang memakai komponen ini?"

**Apa itu:** SBOM (Software Bill of Materials) adalah inventaris bersarang, daftar bahan yang menyusun komponen perangkat lunak [S19]. CISA menyebutnya salah satu fondasi keamanan perangkat lunak dan manajemen risiko rantai pasok perangkat lunak [S19]. Dokumen pendampingnya, VEX (Vulnerability Exploitability eXchange), menyatakan apakah sebuah produk terdampak kerentanan tertentu atau tidak [S19].

**Analogi:** daftar komposisi di kemasan makanan. Saat ada penarikan satu bahan yang tercemar, kamu cukup membaca label untuk tahu apakah makanan di lemarimu memakainya. Batasnya: label hanya berguna bila lengkap dan diperbarui setiap resep berubah, dan label tidak memberi tahu apakah bahan itu benar-benar berbahaya dalam resep tersebut; untuk itu ada VEX.

**Contoh di PT JAB:** dengan SBOM aplikasi MyJAB, tim DevOps bisa mencocokkan nomor CVE baru dengan daftar komponen dalam hitungan menit, bukan menunggu jawaban vendor. SBOM juga membantu scanner: komponen yang tidak terlihat dari luar tetap tercatat.

## 2. Contoh nyata

Semua contoh di bagian ini adalah keluaran ilustrasi dari organisasi fiktif PT JAB, bukan hasil eksekusi nyata. Produk AksesGate, `CVE-2027-XXXXX`, nama host, alamat IP, nomor alert dan insiden, skor EPSS, dan isi laporan dibuat untuk latihan. Vektor CVSS di bagian 2.1 mengikuti contoh resmi FIRST.

### 2.1 Membaca advisory vendor dan CVE Record fiktif

Pertanyaan pertama sampai keempat Sari bermula dari satu halaman advisory. Ringkasannya, ditambah data KEV dan EPSS yang dicari Rabu pagi, terlihat seperti ini:

```
Advisory    : AKSG-2027-014 (vendor AksesGate), terbit 2027-08-23 21:00 WIB
CVE ID      : CVE-2027-XXXXX   (CNA: vendor AksesGate)
Produk      : AksesGate SSL VPN firmware 7.0.0 sampai 7.2.4
Diperbaiki  : firmware 7.2.5
CWE         : CWE-22 (path traversal)
Ringkasan   : permintaan HTTP khusus ke portal clientless tanpa login dapat membaca
              file di luar folder web, termasuk file konfigurasi, dan menjalankan perintah
CVSS v4.0   : 9.3 Critical  CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
Eksploitasi : vendor mengetahui eksploitasi terbatas sebelum advisory terbit
Mitigasi    : bila belum bisa upgrade, matikan fitur portal clientless
Indikator   : permintaan ke /portal/clientless/ berisi "../" atau "%2e%2e%2f"

Data pendukung (dicari 2027-08-25 07:00 WIB)
KEV         : ditambahkan 2027-08-24; ransomware: Unknown
EPSS        : 0,94 (persentil 99,9)
Basis data lain : CVSS v3.1 9.8  AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

**Cara membaca:** mulai dari baris Produk. `jkt-vpn01` menjalankan firmware 7.2.4, jadi terdampak; firmware 7.2.5 aman. Baris CWE memberi tahu jenis kesalahannya dan sekaligus pola yang dicari di log (`../`). Baris CVSS memberi keparahan teknis: bisa diserang dari internet, tanpa login, tanpa bantuan korban, dampak tinggi di perangkat itu. Baris Eksploitasi menunjukkan fase zero-day sudah lewat tetapi celahnya sudah dipakai. KEV dan EPSS menambah dua fakta yang tidak ada di CVSS: sudah terbukti dieksploitasi, dan hampir pasti akan terus dicoba dalam 30 hari. Angka 9.8 di baris terakhir berasal dari CVSS v3.1 dengan vektor setara, jadi tidak bertentangan dengan 9.3 di v4.0 (bagian 1.4).

**Keputusan:** empat syarat kategori Darurat terpenuhi (bagian 1.7): terekspos internet, di KEV, bisa diotomatiskan, memberi kendali atas perangkat. Mitigasi sementara dalam 24 jam, patch dalam 72 jam, dan forensic triage.

### 2.2 Alert `SOC-2027-0892` dan insiden `INC-2027-096`

Alert yang disebut Sari di pesannya dibuat dari baris Indikator advisory. Ringkasannya di antrean SOC:

```
Alert     : SOC-2027-0892
Prioritas : P1
Waktu     : 2027-08-25 06:41:12 sampai 06:49:37 WIB
Rule      : Pola eksploitasi CVE-2027-XXXXX di log web jkt-vpn01 (dari advisory AKSG-2027-014)
Host      : jkt-vpn01 (198.51.100.20), firmware 7.2.4
Sumber    : 192.0.2.241
Ringkasan : 14 permintaan ke /portal/clientless/ dengan pola path traversal
            14 dijawab 404, 0 dijawab 200
```

Tiga baris log web `jkt-vpn01` di balik alert itu:

```
2027-08-25T06:41:12+07:00 jkt-vpn01 web src=192.0.2.241 method=GET uri=/portal/clientless/../../../etc/aksg/system.conf status=404 bytes=0
2027-08-25T06:44:58+07:00 jkt-vpn01 web src=192.0.2.241 method=GET uri=/portal/clientless/%2e%2e%2f%2e%2e%2fetc/aksg/users.db status=404 bytes=0
2027-08-25T06:49:37+07:00 jkt-vpn01 web src=192.0.2.241 method=POST uri=/portal/clientless/../../bin/cmd status=404 bytes=0
```

**Cara membaca:** semua permintaan cocok dengan indikator di advisory: path traversal biasa, versi ter-encode (`%2e%2e%2f` adalah `../` dalam URL encoding), dan percobaan menjalankan perintah. Semuanya dijawab `404` dengan nol byte, karena fitur clientless sudah dimatikan Selasa pukul 23:10, jadi jalurnya tidak ada lagi. Ada 14 permintaan dalam 8 menit 25 detik dari satu alamat, tanpa jeda khas manusia; polanya cocok dengan pemindaian otomatis yang mencari perangkat AksesGate yang rentan.

**Keputusan:** mitigasi bekerja untuk percobaan pagi ini, tetapi itu tidak menjawab pertanyaan yang lebih penting: apakah `jkt-vpn01` sudah dibobol sebelum Selasa pukul 23:10, saat fiturnya masih menyala dan celahnya sudah dieksploitasi di tempat lain. Dimas membuka insiden `INC-2027-096` (SEV-2) untuk forensic triage dengan tiga langkah:

| Langkah | Yang diperiksa | Hasil sementara (Rabu 11:00) |
|---|---|---|
| 1 | Log web `jkt-vpn01` sejak 2027-08-01 untuk pola indikator, termasuk sebelum advisory terbit | Tidak ada pola indikator sebelum 06:41 hari ini |
| 2 | Akun admin, perubahan konfigurasi, dan file di perangkat dengan alat pemeriksa integritas dari vendor | Akun admin sama dengan daftar; alat vendor belum dijalankan karena butuh restart, dijadwalkan bersama patch 22:00 |
| 3 | Login VPN yang janggal sejak 2027-08-01: akun yang login dari alamat atau jam tidak biasa | Dua login luar negeri, keduanya karyawan yang sedang dinas dan terkonfirmasi lewat telepon |

`192.0.2.241` diblokir di `jkt-fw01` sebagai langkah kecil; blokir satu alamat mudah diakali penyerang yang berganti alamat, jadi tidak dianggap perlindungan utama. Insiden tetap terbuka sampai alat integritas vendor dijalankan dan patch diverifikasi. Bila langkah 2 menemukan file asing atau akun baru, penanganannya berubah menjadi respons insiden penuh (Day 19), dan patch saja tidak cukup karena penyerang yang sudah masuk tidak keluar hanya karena pintunya dikunci.

### 2.3 Membaca laporan scan Agustus 2027

Pertanyaan keenam Sari dijawab dengan laporan pemindaian 21 Agustus. Ringkasannya:

```
Laporan scan   : jkt-vscan01, 2027-08-21 21:00 sampai 2027-08-22 03:40 WIB
Aset dipindai  : 1.143   (server 212, workstation 896, perangkat jaringan 35)
Total temuan   : 612
  Critical       18
  High           97
  Medium        301
  Low           196
Temuan di KEV  : 9 (di 7 aset; 2 aset terekspos internet)
Aset tidak ada di inventaris : 1 (10.20.30.77)
```

Hitung dulu: 18 + 97 + 301 + 196 = 612, dan 212 + 896 + 35 = 1.143, jadi angka ringkasan konsisten. Critical dan High saja berjumlah 115; mengerjakan semuanya dengan tenggat yang sama tidak realistis. Tabel berikut memuat enam baris contoh yang dipilih Sari untuk latihan membaca; cari kolom Keputusan untuk melihat bagaimana CVSS, EPSS, KEV, dan paparan internet digabung.

| No | Aset | Temuan (ringkas) | CVSS | EPSS | KEV | Terekspos internet | Keputusan |
|---|---|---|---|---|---|---|---|
| 1 | Server mail lama `198.51.100.11` | Kerentanan eksekusi kode tanpa login di perangkat lunak mail | 9.8 (v3.1) | 0,71 | Ya | Ya | Darurat: 72 jam; dipatch Senin 2027-08-23 malam |
| 2 | `JKT-FS01` | Kenaikan hak lokal di Windows | 7.8 (v3.1) | 0,12 | Ya | Tidak | Tinggi: 7 hari |
| 3 | `JKT-WS-1172` (`10.10.47.115`) | Browser versi lama, eksekusi kode bila user membuka halaman jahat | 8.8 (v3.1) | 0,03 | Tidak | Tidak | Sedang: 30 hari; browser auto-update, cek kenapa tertahan |
| 4 | `jkt-bastion01` | Versi OpenSSH dianggap rentan dari banner | 5.9 (v3.1) | 0,02 | Tidak | Tidak | False positive: paket sudah berisi backport; pengecualian untuk aset ini saja, ditinjau ulang 6 bulan |
| 5 | Server lab `JKT-LAB-DB02` | Database versi lama tanpa dukungan vendor | 9.8 (v3.1) | 0,05 | Tidak | Tidak | Sedang, tetapi tidak bisa di-patch: isolasi ke segmen lab sebagai compensating control, rencana penghentian |
| 6 | `10.20.30.77` | Aset tidak ada di inventaris, layanan web admin terbuka | - | - | - | Tidak | Cari pemiliknya hari ini; aset tanpa pemilik tidak bisa dipatch siapa pun |

**Cara membaca:** baris 1 dan 2 sama-sama ada di KEV, tetapi tenggatnya berbeda karena baris 1 terekspos internet. Baris 3 punya CVSS lebih tinggi dari baris 2, tetapi tenggatnya lebih longgar karena tidak ada bukti eksploitasi dan EPSS-nya rendah. Baris 4 dan 5 sama-sama tidak dipatch, dengan alasan berbeda: baris 4 karena kerentanannya tidak ada, baris 5 karena patch-nya tidak ada. Baris 6 adalah temuan yang paling sering diremehkan: scanner tidak hanya menemukan kerentanan, tetapi juga attack surface yang tidak diketahui (Day 01 bagian 1.9).

**Kapan gagal:** laporan ini adalah potret satu malam. `CVE-2027-XXXXX` diumumkan dua hari kemudian dan tidak ada di sini. Aset yang mati saat pemindaian, laptop yang sedang di rumah, dan perangkat yang memblokir scanner juga tidak terlihat. Karena itu laporan scan dibaca bersama advisory baru dan daftar KEV harian, bukan sekali sebulan.

### 2.4 Rules of engagement pentest September 2027

Pertanyaan ketujuh Sari terjawab paling jelas lewat dokumen yang SOC terima sebelum pentest. Petikan RoE:

```
RoE Pentest Eksternal dan Aplikasi PT JAB 2027
Periode      : 2027-09-13 s.d. 2027-09-24, Senin-Jumat 09:00-17:00 WIB
Cakupan      : 198.51.100.0/24; portal.jab.example (203.0.113.8); jkt-vpn01 (198.51.100.20)
Di luar cakupan : jaringan pelanggan; layanan Microsoft 365; AWS MyJAB; serangan DoS;
                  social engineering ke karyawan
Sumber uji   : 192.0.2.245 dan 192.0.2.246 (firma penguji)
Akun uji     : 2 akun pelanggan uji di portal, dibuat tim aplikasi
Data         : dilarang mengunduh data pelanggan sungguhan; bukti cukup tangkapan layar terbatas
Kontak darurat : Agung Prabowo (infrastruktur), Dimas Prasetyo (SOC), ext. 1199
Penghentian  : penguji berhenti dan menelepon bila menemukan tanda kompromi pihak lain
Persetujuan  : Hendra Wijaya, 2027-08-20
```

**Cara membaca:** setiap baris membatasi kegiatan yang tanpa izin adalah serangan. Cakupan dan alamat sumber memberi tahu SOC alert mana yang berasal dari penguji. DoS dan social engineering sengaja dikeluarkan: yang pertama berisiko mematikan layanan pelanggan, yang kedua akan diuji terpisah dalam latihan red team. Baris Penghentian penting bagi SOC: bila penguji menemukan jejak penyerang lain di `jkt-vpn01`, itu masuk ke `INC-2027-096`.

**Keputusan untuk SOC:** alert dari `192.0.2.245` dan `192.0.2.246` selama jendela waktu tetap diperiksa dan dicatat, bukan dimatikan. Tujuannya dua: memastikan alert itu memang dari penguji, dan mencatat teknik mana yang terdeteksi sebagai bahan hari purple team. Alert dari alamat lain dengan pola serupa diperlakukan sebagai serangan sungguhan.

## 3. Perbandingan istilah yang sering tertukar

### 3.1 CVE, CWE, CVSS, EPSS, dan KEV

Lima singkatan ini sering muncul dalam satu kalimat. Tabel berikut membedakannya dengan satu pertanyaan kunci; cari kolom Tidak menjawab untuk menghindari salah pakai.

| Istilah | Pertanyaan kunci | Bentuk | Pengelola | Tidak menjawab |
|---|---|---|---|---|
| CVE | Celah yang mana? | ID dan record | Program CVE, CNA | Seberapa parah atau mendesak |
| CWE | Jenis kesalahannya apa? | ID jenis kelemahan | MITRE, disponsori CISA | Produk mana yang terkena |
| CVSS | Seberapa parah bila dimanfaatkan? | Skor 0,0 sampai 10,0 dan vektor | FIRST (standar); skor dari vendor, NVD | Apakah sedang dieksploitasi; risiko di organisasimu |
| EPSS | Seberapa mungkin dieksploitasi 30 hari ke depan? | Peluang 0 sampai 1 dan persentil | FIRST | Apakah asetmu terekspos; dampaknya |
| KEV | Sudah terbukti dieksploitasi? | Katalog ya atau tidak, dengan tenggat | CISA | Kerentanan yang dieksploitasi tetapi belum terkonfirmasi |

### 3.2 Vulnerability assessment, pentest, red team, purple team, dan bug bounty

Semua kegiatan ini mencari kelemahan, tetapi berbeda cakupan, kedalaman, dan siapa yang diuji. Tabel berikut membantu memilih kegiatan yang tepat untuk pertanyaan yang ingin dijawab.

| Kegiatan | Pertanyaan yang dijawab | Cakupan | Kedalaman | Diberi tahu ke SOC? | Analogi |
|---|---|---|---|---|---|
| Vulnerability assessment / scan | Kelemahan apa saja yang ada? | Luas, semua aset, rutin | Dangkal, otomatis, perlu verifikasi | Ya, terjadwal | Inspeksi dengan checklist |
| Pentest | Apakah celah benar-benar bisa ditembus dan sejauh mana? | Terbatas, disepakati di RoE | Dalam, manual, menggabungkan celah | Ya | Maling bayaran yang diizinkan mencoba |
| Red team | Apakah serangan realistis terdeteksi dan direspons? | Mengejar tujuan, jalur bebas dalam batas | Dalam dan lama | Tidak (hanya pimpinan) | Latihan perampokan tanpa memberi tahu satpam |
| Purple team | Teknik mana yang belum terlihat oleh deteksi kita? | Teknik terpilih | Per teknik, terbuka | Ya, bekerja bersama | Satpam dan maling bayaran membahas rekaman CCTV |
| Bug bounty / VDP | Celah apa yang ditemukan orang luar? | Sesuai kebijakan program | Bervariasi | Laporan masuk lewat saluran resmi | Hadiah bagi yang melapor jendela terbuka |

## 4. Salah paham umum

- **Anggapan:** semua kerentanan Critical harus ditutup dalam satu hari. **Kenyataannya:** ratusan temuan Critical dan High tidak bisa ditutup bersamaan, dan memaksakannya mengorbankan pengujian dan availability. Kebijakan yang menggabungkan KEV, paparan internet, dan dampak (bagian 1.7) memberi urutan yang bisa dikerjakan, dan CISA sendiri beralih dari tenggat seragam ke tenggat berbasis risiko lewat BOD 26-04 [S13].
- **Anggapan:** tidak masuk KEV berarti aman ditunda. **Kenyataannya:** KEV hanya memuat eksploitasi yang terkonfirmasi dengan bukti andal [S11]. EPSS tinggi, exploit publik, atau advisory vendor yang menyebut eksploitasi adalah sinyal untuk bergerak sebelum KEV menyusul.
- **Anggapan:** setelah patch dipasang, insiden selesai. **Kenyataannya:** patch menutup pintu, tetapi tidak mengusir penyerang yang sudah masuk sebelum patch. Untuk kerentanan yang sudah dieksploitasi di aset terekspos, forensic triage dibutuhkan, seperti di `INC-2027-096` [S13].

## 5. Catatan terkini

Bagian ini mencatat versi standar, perubahan kelembagaan, dan angka yang berubah dari waktu ke waktu, semuanya per tanggal riset 21 Oktober 2026.

- **CVSS v4.0** terbit 1 November 2023; dokumen spesifikasinya sudah direvisi sampai v1.2 (Juni 2024) [S6]. Banyak basis data, scanner, dan advisory masih memakai CVSS v3.1, jadi kedua versi akan terlihat berdampingan untuk waktu yang lama. Saat membandingkan skor, pastikan versinya sama.
- **EPSS** mengganti model secara berkala: v1 mulai April 2021, v2 Februari 2022, v3 Maret 2023, v4 (model v2025.03.14) mulai 17 Maret 2025, dan v5 (model v2026.06.15) mulai 15 Juni 2026 [S10]. Halaman data FIRST tidak merinci perubahan di v5; yang dicatat hanya bahwa skor bergeser pada tanggal pergantian. Cek kolom versi model di data EPSS sebelum membandingkan skor lama dan baru.
- **CISA KEV** memuat 1.754 entri saat dilihat 21 Oktober 2026, dengan entri terbaru bertanggal 20 Oktober 2026 [S11].
- **BOD 26-04** (10 Juni 2026) mencabut BOD 22-01 dan BOD 19-02. Katalog KEV dan kriterianya tetap; tenggat dua minggu dan enam bulan dari BOD 22-01 diganti tenggat berbasis empat faktor (paparan, KEV, otomasi, dampak), dengan tingkat tercepat tiga hari plus forensic triage [S12][S13]. Fase penerapannya bertahap sampai sekitar Desember 2026 [S13]. Pemetaan lengkap kombinasi faktor ke tenggat 14 hari, 60 hari, atau saat upgrade ada di tabel panduan CISA; sumber sekunder yang membahasnya tidak sepenuhnya seragam, jadi cek tabel resmi CISA sebelum mengutip angka untuk kombinasi tertentu [S26].
- **Program CVE:** kontrak CISA dengan MITRE nyaris berakhir 16 April 2025; CISA memperpanjangnya 11 bulan sampai Maret 2026, dan sebagian anggota CVE Board membentuk CVE Foundation sebagai organisasi nirlaba untuk menjaga kelangsungan program [S23]. Pada Maret 2026 dilaporkan kontrak dinegosiasi ulang tanpa tanggal kedaluwarsa seperti sebelumnya dan CISA menyatakan program didanai penuh; rincian kontraknya tidak dipublikasikan, dan CVE Foundation sedang menimbang langkah berikutnya [S24]. Aturan operasional CNA versi 4.2.0 berlaku sejak 25 Agustus 2026 [S2].
- **NVD:** pada April 2026 NIST beralih ke enrichment berbasis prioritas. Enrichment penuh diutamakan untuk CVE yang ada di KEV, perangkat lunak yang dipakai pemerintah federal AS, dan perangkat lunak kritis menurut EO 14028; CVE lain diberi status "Not Scheduled", CVE dengan tanggal terbit NVD sebelum 1 Maret 2026 tidak lagi diperkaya, dan NIST berhenti rutin menambah skor sendiri bila CNA sudah memberi skor [S25]. Pengajuan CVE naik 263 persen antara 2020 dan 2025 [S25].
- **NIST SP 800-40 Rev. 4** (April 2022) menggantikan Rev. 3 (2013) dan membahas perencanaan patch tingkat organisasi [S14]. **NIST SP 800-115** masih versi September 2008 tanpa revisi; konsep dasarnya (fase pentest, keterbatasan scanner) tetap dipakai, tetapi contoh praktiknya mencerminkan keadaan 2008 [S15].

## 6. Cheat sheet

```
Vulnerability        : kelemahan yang bisa dimanfaatkan (jendela tidak terkunci)
Exploit              : cara/kode memanfaatkan kelemahan (cara mencongkel)
Zero-day             : dieksploitasi sebelum pembuat tahu / sebelum ada perbaikan
CVE / CVE ID         : nama publik satu celah, CVE-<tahun>-<nomor>; record = deskripsi + rujukan
CNA                  : organisasi yang boleh memberi CVE ID (sering vendor produk)
CWE                  : jenis kelemahan/akar masalah (CWE-22 path traversal, CWE-89 SQLi)
CVSS v4.0            : keparahan 0.0-10.0; Base/Threat/Environmental/Supplemental; bukan risiko
  skala              : None 0 | Low 0.1-3.9 | Medium 4-6.9 | High 7-8.9 | Critical 9-10
  v4 vs v3.1         : Scope dihapus (VC/VI/VA + SC/SI/SA), AT baru, UI N/P/A, Temporal -> Threat
EPSS                 : peluang dieksploitasi 30 hari (0-1) + persentil; harian; FIRST; jangan dikali CVSS
CISA KEV             : sudah terbukti dieksploitasi; syarat: CVE ID, bukti andal, perbaikan jelas
BOD 26-04            : pengganti BOD 22-01 (Jun 2026); paparan + KEV + otomasi + dampak; 3 hari + forensic triage
NVD                  : NIST memperkaya CVE (CVSS, CWE, CPE); sejak Apr 2026 hanya prioritas
Patch management     : identifikasi, prioritaskan, pasang, verifikasi (NIST SP 800-40r4)
Respons risiko       : accept, mitigate, transfer, avoid
Skenario patch       : rutin | darurat | mitigasi darurat | aset tak bisa di-patch
Virtual patching     : aturan WAF/IPS menghadang eksploitasi; tidak menghilangkan celah
Compensating control : pengganti setara saat control utama tak bisa dipasang (isolasi, pantau)
Vulnerability scanner: cek otomatis berbasis signature; false positive dan false negative tinggi
False positive scan  : celah dilaporkan padahal tidak ada (sering: backport, banner versi)
VA                   : pemeriksaan sistematis, luas, rutin
Pentest              : meniru serangan nyata, terbatas RoE; Planning > Discovery > Attack > Reporting
Red team             : meniru musuh menuju tujuan; uji deteksi dan respons; blue team tidak diberi tahu
Blue team            : pertahanan (SOC, IR, pemilik control)
Purple team          : red + blue berlatih terbuka; hasil = deteksi baru
RoE                  : cakupan, waktu, sumber uji, larangan, kontak darurat
Coordinated disclosure: lapor ke pemilik dulu, umumkan bersama perbaikan
VDP vs bug bounty    : VDP = saluran dan aturan pelaporan; bug bounty = VDP + imbalan
SBOM                 : daftar komponen perangkat lunak; VEX = terdampak atau tidak
```

## 7. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "`CVE-2027-XXXXX` adalah zero-day, karena patch-nya baru keluar dua hari lalu." Benarkah?

<details><summary>Jawaban</summary>

Tidak, setidaknya tidak pada Rabu pagi. Zero-day adalah serangan yang memanfaatkan kerentanan yang belum diketahui pembuatnya atau belum punya perbaikan. Serangan terhadap korban sebelum advisory terbit Senin malam memang zero-day, karena vendor menyebut ada eksploitasi terbatas sebelum pengumuman. Setelah advisory, nomor CVE, dan firmware 7.2.5 tersedia, celahnya sudah publik dan patch-nya ada. Yang membuatnya mendesak bagi PT JAB justru karena celah itu sekarang diketahui semua penyerang, sementara `jkt-vpn01` belum di-patch. Lihat bagian 1.1.

</details>

**2. Skenario keputusan.** Tiga temuan muncul di hari yang sama, dan tim infrastruktur hanya sanggup mengerjakan satu hari ini. Mana yang didahulukan?

- A. Server lab internal tanpa akses internet, CVSS 9.8, EPSS 0,02, tidak di KEV.
- B. Server mail yang menghadap internet, CVSS 7.5, EPSS 0,89, masuk KEV kemarin.
- C. Laptop staf, CVSS 8.8, EPSS 0,03, tidak di KEV, browser auto-update aktif.

<details><summary>Jawaban</summary>

B. Kerentanan itu sudah terbukti dieksploitasi (KEV), hampir pasti terus dicoba (EPSS tinggi), dan asetnya bisa dijangkau siapa pun dari internet; di kebijakan PT JAB itu kategori Darurat. A keliru karena CVSS tinggi hanya mengukur keparahan teknis; tanpa paparan dan tanpa tanda eksploitasi, risikonya jauh lebih rendah. C keliru karena CVSS 8.8 tanpa bukti eksploitasi dan dengan auto-update cukup masuk siklus 30 hari. Lihat bagian 1.4, 1.5, 1.6, dan 1.7.

</details>

**3. Pertanyaan jebakan.** "EPSS `CVE-2027-XXXXX` adalah 0,94, jadi peluang `jkt-vpn01` dibobol bulan ini 94 persen." Benarkah?

<details><summary>Jawaban</summary>

Tidak. EPSS memperkirakan peluang aktivitas eksploitasi terhadap CVE itu teramati di dunia nyata dalam 30 hari, di mana pun, bukan peluang perangkat tertentu berhasil dibobol. EPSS tidak tahu apakah `jkt-vpn01` terekspos, sudah dimitigasi, atau sudah di-patch; FIRST sendiri menyebut EPSS tidak memperhitungkan konteks dan control organisasi. Angka 0,94 artinya "hampir pasti dicoba di internet", yang menjadi alasan untuk bergerak cepat, bukan ramalan nasib satu perangkat. Lihat bagian 1.5.

</details>

**4. Skenario keputusan.** Selasa siang `CVE-2027-XXXXX` masuk KEV, tetapi patch `jkt-vpn01` baru bisa dipasang Rabu pukul 22:00 karena VPN akan mati 30 menit. Apa langkah yang paling tepat sampai saat itu?

- A. Menunggu saja, karena patch sudah dijadwalkan dan perangkat VPN memakai TLS.
- B. Menjalankan mitigasi dari advisory (mematikan fitur clientless), menambah signature IPS dan rule SIEM untuk pola eksploitasinya, lalu memeriksa apakah perangkat sudah telanjur dibobol.
- C. Mematikan VPN untuk semua karyawan sampai vendor merilis produk baru yang bebas celah.

<details><summary>Jawaban</summary>

B. Mitigasi dari vendor menutup jalur eksploitasi, virtual patch dan rule SIEM menambah lapisan hadang dan deteksi, dan forensic triage menjawab pertanyaan yang tidak dijawab patch: apakah penyerang sudah masuk sebelumnya. A keliru karena TLS hanya melindungi perjalanan data, bukan celah di perangkat, dan celah yang di KEV sedang aktif dicari penyerang. C keliru karena mengorbankan availability tanpa alasan ketika ada mitigasi dan patch yang tersedia; tidak ada produk yang bebas celah selamanya. Lihat bagian 1.7, 1.8, dan 2.2.

</details>

**5. Jelaskan ulang.** Jelaskan kepada anggota keluargamu yang bukan orang IT, dalam tiga kalimat, beda pemindaian kerentanan, pentest, dan red team.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Pemindaian kerentanan itu seperti petugas inspeksi yang keliling rumah membawa checklist dan mencatat kunci atau jendela model lama, cepat dan rutin, tapi kadang salah catat. Pentest itu seperti menyewa maling profesional yang diizinkan mencoba masuk lewat pintu dan jendela yang disepakati, lalu melaporkan mana yang berhasil dibobol. Red team itu latihan perampokan sungguhan yang sengaja tidak diberitahukan ke satpam, supaya ketahuan apakah satpam dan CCTV benar-benar menyadari ada yang masuk."

Kesalahan yang sering muncul:
- Menyebut ketiganya sama-sama "hacking" tanpa menjelaskan bahwa ketiganya punya izin tertulis dan batas.
- Lupa menyebut bahwa red team menguji orang dan proses pertahanan, bukan hanya mencari celah teknis.
- Memakai istilah seperti CVE, CVSS, atau RoE tanpa penjelasan.

</details>

**6. Pertanyaan jebakan.** "Scanner melaporkan OpenSSH di `jkt-bastion01` rentan, dan Agung membuktikan itu false positive. Supaya laporan bersih, aturan pemeriksaan OpenSSH itu dimatikan untuk semua server." Tepatkah?

<details><summary>Jawaban</summary>

Tidak. Temuan itu false positive karena paket di `jkt-bastion01` sudah berisi perbaikan backport, sementara scanner hanya membaca nomor versi. Server lain belum tentu memakai paket yang sama; mematikan pemeriksaan untuk semua server bisa menyembunyikan kerentanan sungguhan. Pengecualian yang tepat sempit: satu temuan, satu aset, dengan alasan tertulis dan tanggal tinjau ulang. Lihat bagian 1.9 dan 2.3.

</details>

**7. Interview question (English).** "You have a vulnerability scan with 600 findings and a new critical advisory for your VPN appliance. How do you decide what to fix first?"

<details><summary>Sample answer</summary>

"I would not sort by CVSS alone, because CVSS measures technical severity, not risk in our environment. I would combine four signals: whether the vulnerability is in CISA's KEV catalog, meaning exploitation is confirmed; its EPSS probability, which estimates the chance of exploitation in the next 30 days; whether the asset is reachable from the internet; and what an attacker gains, such as full control of the device. A KEV-listed flaw on an internet-facing VPN appliance goes first, even if a lab server has a higher CVSS. If the patch needs a maintenance window, I would apply the vendor's mitigation, add a virtual patch or detection rule for the exploit pattern, and check logs for signs that the device was already compromised before the fix. For the rest of the scan, I would weed out false positives and push the remaining findings through the routine patch cycle with deadlines per category. Finally, I would rescan after patching to verify the fix actually landed."

What makes this answer strong: it separates severity from risk, names the specific data sources and what each one measures, shows a concrete interim plan instead of waiting for the patch, remembers that patching does not undo a prior compromise, and closes the loop with verification.

</details>

## 8. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | NIST CSRC Glossary: zero day attack | https://csrc.nist.gov/glossary/term/zero_day_attack | primer (glosarium NIST) | diakses 2026-10-21 | Tinggi. Definisi dari CNSSI 4009-2022 dan NISTIR 8011 Vol. 3 |
| S2 | CVE Program: CNA Operational Rules 4.2.0 | https://www.cve.org/Resources/Roles/Cnas/CNA_Rules_v4.2.0.pdf | primer (aturan program CVE) | disetujui 2026-08-20, berlaku 2026-08-25; diakses 2026-10-21 | Tinggi. Definisi CVE ID, CVE Record, CNA, definisi vulnerability program CVE, hak pertama dan batas 72 jam, contoh CVE ID |
| S3 | NIST CSRC Glossary: common vulnerabilities and exposures (CVE) | https://csrc.nist.gov/glossary/term/common_vulnerabilities_and_exposures | primer (glosarium NIST) | diakses 2026-10-21 | Tinggi. Definisi CVE sebagai daftar entri dengan nomor, deskripsi, dan rujukan |
| S4 | MITRE CWE: About CWE | https://cwe.mitre.org/about/index.html | primer (pengelola CWE) | halaman diperbarui 2026-09-30; diakses 2026-10-21 | Tinggi. Definisi CWE dan weakness, sponsor CISA, pengelola MITRE, frekuensi pembaruan |
| S5 | MITRE CWE: 2025 CWE Top 25 Most Dangerous Software Weaknesses | https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html<br>https://cwe.mitre.org/top25/ | primer (pengelola CWE) | halaman diperbarui 2025-12-15 dan 2026-01-29; diakses 2026-10-21 | Tinggi. Peringkat 1 sampai 10, jumlah 39.080 CVE Record |
| S6 | FIRST: CVSS v4.0 Specification Document | https://www.first.org/cvss/v4-0/specification-document | primer (standar FIRST) | v1.0 2023-11-01, v1.2 2024-06-18; diakses 2026-10-21 | Tinggi. Kelompok metrik, metrik Base, nomenklatur CVSS-B/BT/BE/BTE, skala keparahan, subsequent system pengganti Scope |
| S7 | FIRST: CVSS v4.0 User Guide | https://www.first.org/cvss/v4-0/user-guide | primer (standar FIRST) | diakses 2026-10-21 | Tinggi. Severity bukan risiko, siapa mengisi metrik, perubahan dari v3.1, Supplemental |
| S8 | FIRST: CVSS v4.0 Examples | https://www.first.org/cvss/v4-0/examples | primer (standar FIRST) | diakses 2026-10-21 | Tinggi. Vektor dan skor Log4Shell dan Shellshock (v4.0 9.3; v3.1 Shellshock 9.8) |
| S9 | FIRST: Exploit Prediction Scoring System (EPSS) dan EPSS FAQ | https://www.first.org/epss/<br>https://www.first.org/epss/faq | primer (pengelola EPSS) | diakses 2026-10-21 | Tinggi. Definisi 30 hari, pembaruan harian, persentil, batasan konteks, larangan mengalikan dengan CVSS |
| S10 | FIRST: EPSS Get the Data | https://www.first.org/epss/data | primer (pengelola EPSS) | diakses 2026-10-21 | Tinggi. Tanggal mulai model v1 sampai v5 |
| S11 | CISA: Known Exploited Vulnerabilities Catalog dan halaman KEV | https://www.cisa.gov/known-exploited-vulnerabilities-catalog<br>https://www.cisa.gov/known-exploited-vulnerabilities | primer (lembaga pemerintah AS) | dilihat 2026-10-21 | Tinggi. Tiga kriteria, kolom entri, 1.754 entri, anjuran untuk semua organisasi |
| S12 | CISA: BOD 22-01 Reducing the Significant Risk of Known Exploited Vulnerabilities | https://www.cisa.gov/news-events/directives/bod-22-01-reducing-significant-risk-known-exploited-vulnerabilities | primer (direktif CISA, sudah dicabut) | 2021-11-03; diakses 2026-10-21 | Tinggi untuk sejarah. Halaman menyatakan dicabut dan digantikan BOD 26-04; tenggat dua minggu dan enam bulan |
| S13 | CISA: BOD 26-04 Prioritizing Security Updates Based on Risk | https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk | primer (direktif CISA) | 2026-06-10; diakses 2026-10-21 | Tinggi. Empat faktor, tenggat tiga hari dengan forensic triage, tenggat dinamis, fase penerapan. Tabel tenggat berupa gambar dan tidak terbaca utuh |
| S14 | NIST SP 800-40 Rev. 4: Guide to Enterprise Patch Management Planning | https://csrc.nist.gov/pubs/sp/800/40/r4/final<br>https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-40r4.pdf | primer (publikasi NIST) | 2022-04; diakses 2026-10-21 | Tinggi. Definisi patch management, empat respons risiko, siklus, empat skenario, alasan patch tertunda, zero-day |
| S15 | NIST SP 800-115: Technical Guide to Information Security Testing and Assessment | https://csrc.nist.gov/pubs/sp/800/115/final<br>https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf | primer (publikasi NIST) | 2008-09; diakses 2026-10-21 | Tinggi untuk konsep. Keterbatasan scanner, false positive, definisi dan empat fase pentest. Dokumen lama tanpa revisi |
| S16 | NIST CSRC Glossary: penetration testing, vulnerability assessment | https://csrc.nist.gov/glossary/term/penetration_testing<br>https://csrc.nist.gov/glossary/term/vulnerability_assessment | primer (glosarium NIST) | diakses 2026-10-21 | Tinggi |
| S17 | NIST CSRC Glossary: red team, blue team | https://csrc.nist.gov/glossary/term/red_team<br>https://csrc.nist.gov/glossary/term/blue_team | primer (glosarium NIST) | diakses 2026-10-21 | Tinggi. Definisi dari CNSSI 4009-2022, termasuk white team sebagai pengawas netral |
| S18 | OWASP Cheat Sheet Series: Virtual Patching Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Virtual_Patching_Cheat_Sheet.html | primer (proyek OWASP) | diakses 2026-10-21 | Tinggi. Definisi, alasan, langkah, alat, dan batasan virtual patching |
| S19 | CISA: Software Bill of Materials (SBOM) | https://www.cisa.gov/sbom | primer (lembaga pemerintah AS) | diakses 2026-10-21 | Tinggi. Definisi SBOM dan VEX; pembaruan minimum elements 2025-2026 |
| S20 | CISA: Coordinated Vulnerability Disclosure Process | https://www.cisa.gov/coordinated-vulnerability-disclosure-process | primer (lembaga pemerintah AS) | diakses 2026-10-21 | Tinggi. Langkah CVD dan batas 45 hari bila vendor tidak menanggapi |
| S21 | OMB M-20-32: Improving Vulnerability Identification, Management, and Remediation | https://www.whitehouse.gov/wp-content/uploads/2020/09/M-20-32.pdf | primer (memo pemerintah AS) | 2020-09-02; diakses 2026-10-21 | Tinggi. Beda VDP dan bug bounty, perlindungan peneliti beritikad baik |
| S22 | IANS: Understand the Roles of Red, Blue and Purple Teams | https://www.ians.com/blog/ians-research/understand-the-roles-of-red-blue-and-purple-teams | sekunder (firma riset) | 2022-04-19; diakses 2026-10-21 | Sedang. Dipakai untuk purple team sebagai kerja sama sementara, karena glosarium NIST tidak punya entri purple team |
| S23 | The Record: CISA extends CVE program contract with MITRE for 11 months | https://therecord.media/cisa-extends-cve-program-contract-with-mitre | sekunder (media) | 2025-04-16; diakses 2026-10-21 | Sedang sampai tinggi. Perpanjangan kontrak, CVE Foundation |
| S24 | CSO Online: CVE program funding secured, easing fears of repeat crisis | https://www.csoonline.com/article/4142600/cve-program-funding-secured-easing-fears-of-repeat-crisis.html | sekunder (media) | 2026-03-09; diakses 2026-10-21 | Sedang. Sebagian klaim dari sumber anonim; pernyataan CISA bahwa program didanai penuh dikutip langsung dari pejabat CISA |
| S25 | Help Net Security: NIST will enrich only highest-risk CVEs going forward | https://www.helpnetsecurity.com/2026/04/16/nist-national-vulnerability-database-nvd-enrichment/ | sekunder (media) | 2026-04-16; diakses 2026-10-21 | Sedang. Pengumuman resmi NIST di situs NVD tidak berhasil dibuka; isi dicocokkan dengan beberapa laporan media yang seragam |
| S26 | Cloud Security Alliance: CSA Research Note, CISA BOD 26-04 | https://labs.cloudsecurityalliance.org/research/csa-research-note-cisa-bod-26-04-risk-based-vulnerability-re/ | sekunder (catatan riset) | 2026-08-20; diakses 2026-10-21 | Rendah sampai sedang. Dipakai hanya untuk keberadaan tingkat tenggat 14 hari, 60 hari, dan saat upgrade; pemetaan per kombinasi tidak konsisten antar sumber sekunder |

**Catatan sumber:** pemetaan lengkap kombinasi empat faktor BOD 26-04 ke tenggat 14 hari, 60 hari, atau saat upgrade tidak terbaca dari halaman CISA (tabelnya berupa gambar), dan sumber sekunder tidak seragam; yang ditulis di Day ini hanya tingkat tercepat (tiga hari plus forensic triage) yang tercantum di teks direktif [S13][S26]. Status program CVE setelah Maret 2026 bersumber dari laporan media yang sebagian mengandalkan sumber anonim [S24]; cek pengumuman resmi di cve.org atau CISA bila dibutuhkan untuk dokumen formal. Perubahan NVD April 2026 juga dari laporan media [S25]. Purple team didefinisikan dari sumber sekunder [S22]. Format CVE ID ditulis berdasarkan contoh CVE ID di aturan CNA [S2], bukan dari teks definisi format. Penjelasan backport sebagai penyebab false positive adalah pengetahuan praktik umum yang tidak berasal dari satu sumber di tabel. Seluruh isi PT JAB (produk AksesGate, advisory AKSG-2027-014, `CVE-2027-XXXXX`, skor EPSS, alert `SOC-2027-0892` dan `SOC-2027-0893`, insiden `INC-2027-096`, laporan scan, kebijakan patch, RoE pentest, dan email peneliti) adalah contoh fiktif; vektor CVSS di bagian 2.1 mengikuti contoh resmi FIRST [S8].
