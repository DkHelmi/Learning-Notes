---
day: 01
title: 'Gambaran incident response: event vs insiden, siklus NIST dan PICERL, peran tim, dan severity'
researched_on: 2026-10-14
versions_checked: 'NIST SP 800-61 Rev. 3 (final 3 April 2025); NIST SP 800-61 Rev. 2 (Agustus 2012, withdrawn 3 April 2025); NIST CSF 2.0 (CSWP 29, 26 Februari 2024); SANS Incident Handler''s Handbook (Kral, 21 Februari 2012); CISA National Cyber Incident Scoring System (halaman CISA, diakses 2026-10-14); UU 27/2022 tentang Pelindungan Data Pribadi (diundangkan 17 Oktober 2022)'
---

# Day 01: Gambaran incident response (event vs insiden, siklus NIST dan PICERL, peran tim, dan severity)

Cakupan: beda event, alert, dan insiden, arti menyatakan insiden, siklus IR menurut NIST SP 800-61 Rev. 2 dan Rev. 3 serta PICERL dari SANS, peran orang saat insiden dengan incident commander sebagai pusatnya, dan cara menetapkan severity insiden.

## Ide inti

Triage di SOC menjawab pertanyaan "apakah alert ini benar, dan apa yang sebenarnya terjadi?". Incident response (IR) dimulai tepat setelah itu dan menjawab tiga pertanyaan lain: apa yang harus kita lakukan sekarang, siapa yang memutuskan, dan seberapa parah. Pertanyaan pertama dijawab oleh siklus IR (tahap apa yang sedang berjalan dan apa berikutnya), pertanyaan kedua oleh peran yang jelas (terutama incident commander), dan pertanyaan ketiga oleh severity. Kemampuan triage dan forensik yang sudah kamu punya tetap dipakai, tetapi di IR keduanya menjadi masukan untuk keputusan, bukan hasil akhir.

Kamu sudah mengenal pola ini dari NOC. Alarm NMS berbunyi ratusan kali semalam, tetapi hanya sebagian yang dinyatakan sebagai gangguan massal. Begitu gangguan dinyatakan, bridge call dibuka, incident manager NOC memimpin tanpa ikut mengetik perintah, satu orang mencatat timeline untuk laporan RFO, dan prioritas P1 sampai P4 ditentukan dari jumlah pelanggan terdampak. IR memakai pola yang sama dengan dua perbedaan penting. Pertama, insiden keamanan sering sunyi: data bisa diambil tanpa satu layanan pun turun. Kedua, menyatakan insiden memicu kewajiban (pelaporan, penyimpanan bukti, pemberitahuan), sehingga kriterianya harus tertulis dan keputusannya tercatat.

```
event                 login, query DNS, file berubah         (jutaan per hari)
  -> alert            detection menilai event mencurigakan    (ditriage SOC)
  -> adverse event    dianalisis: ada dampak negatif?         (L1/L2)
  -> DECLARE          memenuhi kriteria insiden tertulis      (keputusan, tercatat)
       -> nomor INC, severity awal, incident commander, peran diaktifkan
       -> containment / eradication / recovery     <- bisa kembali ke analisis
       -> lessons learned                          <- masukan ke persiapan
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan dan 400 ribu pelanggan broadband. PT JAB tidak punya tim IR khusus; insiden ditangani CSIRT virtual, yaitu orang-orang dengan pekerjaan harian lain yang ditarik masuk saat insiden dinyatakan. Jumat, 9 Oktober 2026, pukul 21:41 WIB, analyst L1 shift malam menulis ke analyst L2 on-call, Yoga Pratama:

> "Mas, dari 21:32 ada lima alert EDR, `SOC-2026-0187` sampai `SOC-2026-0191`, semuanya di `JKT-FS01`. Banyak file di share `Keuangan` berganti ekstensi jadi `.lck`, dan muncul `BACA-INI.txt` di tiap folder. Ini sudah insiden belum? Jam segini saya harus telepon siapa? Seberapa parah? Saya boleh cabut kabel `JKT-FS01` sekarang atau tunggu?"

Pesan itu memuat lima pertanyaan:

1. Ini sudah insiden atau masih alert?
2. Kalau insiden, siapa yang menyatakannya dan apa akibatnya?
3. Langkah apa yang sedang berjalan sekarang, dan apa berikutnya?
4. Siapa yang ditelepon, dan siapa yang memutuskan tindakan seperti mencabut kabel?
5. Seberapa parah?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3 sampai 1.5, pertanyaan 4 di bagian 1.6, dan pertanyaan 5 di bagian 1.7 dan 1.8. Bagian 2 berisi dokumen yang dihasilkan PT JAB malam itu.

**Kapan relevan:** saat alert atau laporan menunjukkan dampak nyata atau ancaman yang dekat, saat lebih dari satu tim harus bergerak bersama, dan saat ada keputusan yang berdampak ke bisnis atau kewajiban hukum.
**Kapan bukan jawaban:** untuk alert yang selesai di triage (false positive, aktivitas admin yang sah, upaya yang gagal tanpa dampak). Membuka proses insiden penuh untuk semua alert membuat orang lelah dan proses IR tidak dianggap serius lagi.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Tabel ini memuat istilah IR yang muncul di Day ini. Kolom padanan memakai analogi NOC dan SOC yang sama di semua Day IR. Baca kolom kedua dulu, lalu kembali ke tabel ini saat menemukan istilah yang terlupa.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Event | Kejadian apa pun yang bisa diamati pada aset komputasi | Setiap baris syslog atau trap dari perangkat |
| Adverse event | Event yang berdampak negatif, apa pun penyebabnya | Alarm yang memang menandakan masalah, belum tentu gangguan massal |
| Alert | Pemberitahuan dari alat deteksi ke analyst bahwa ada event yang perlu dilihat | Alarm NMS di layar NOC |
| Triage | Pemeriksaan awal untuk memastikan alert benar dan memahami apa yang terjadi | Cek awal alarm sebelum membuka tiket gangguan |
| Insiden (cybersecurity incident) | Kejadian yang membahayakan kerahasiaan, integritas, atau ketersediaan informasi tanpa wewenang, atau melanggar hukum dan kebijakan | Gangguan yang dinyatakan (bisa terjadi tanpa layanan turun) |
| Declare (menyatakan insiden) | Keputusan tercatat bahwa sebuah kejadian adalah insiden, yang menyalakan proses IR | Menyatakan gangguan massal dan membuka bridge call |
| IR plan | Dokumen yang menetapkan wewenang, peran, dan langkah IR organisasi | Prosedur penanganan gangguan major dan BCP NOC |
| Siklus IR | Urutan tahap penanganan insiden (NIST, PICERL) | Alur gangguan: deteksi, isolasi, perbaikan, normal, RFO |
| Fungsi CSF 2.0 | Enam kelompok hasil keamanan tertinggi di NIST CSF 2.0 (Govern, Identify, Protect, Detect, Respond, Recover) | Tidak ada padanan langsung; anggap sebagai bab besar katalog |
| PICERL | Enam tahap SANS: Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned | Alur gangguan yang sama, dengan isolasi dan perbaikan dipisah |
| Containment | Mencegah insiden meluas | Isolasi link atau blackhole route saat DDoS |
| Eradication | Menghilangkan sisa penyerang: malware, akun, persistence, celah | Mengganti modul rusak setelah penyebabnya diketahui |
| Recovery | Mengembalikan sistem ke operasi normal dan memastikan bersih | Restore layanan lalu memantau sampai stabil |
| Lessons learned | Pelajaran dari insiden yang dipakai untuk memperbaiki sistem dan proses | RFO dan post-mortem gangguan |
| CSIRT virtual | Tim IR yang anggotanya punya pekerjaan harian lain dan ditarik saat insiden | Tim gangguan lintas divisi saat gangguan besar |
| Incident commander (IC) | Orang yang mengoordinasi respons dan mengambil keputusan, tanpa mengerjakan teknis | Incident manager NOC yang memimpin bridge |
| Technical lead | Orang yang memimpin analisis teknis dan memberi rekomendasi ke IC | Engineer yang memegang troubleshooting di bridge |
| Scribe | Pencatat timeline, keputusan, dan tindak lanjut | Pencatat timeline bridge untuk laporan RFO |
| Executive sponsor | Pimpinan yang memutuskan tindakan berdampak bisnis besar | Manajemen yang menyetujui maintenance darurat berdampak pelanggan |
| IR retainer | Kontrak dengan penyedia DFIR luar yang siap dipanggil | Kontrak support vendor dengan SLA respons |
| Severity insiden | Tingkat keparahan insiden bagi organisasi; menentukan siapa terlibat dan seberapa cepat | Prioritas gangguan P1-P4 berdasarkan pelanggan terdampak |
| Prioritas alert | Urutan alert di antrean SOC, ditentukan rule dan aset | Tingkat alarm NMS (critical, major, minor) |

### 1.1 Event, alert, dan insiden: kapan event menjadi insiden

Analyst L1 PT JAB bertanya "ini sudah insiden belum?". Lima alert itu belum otomatis insiden, tetapi juga tidak boleh menunggu sampai semua pertanyaan terjawab. Jawabannya bergantung pada definisi yang dipakai organisasi, jadi definisinya perlu jelas dulu.

NIST SP 800-61 Rev. 3 memakai tiga lapis istilah [S1]:

- **Event:** kejadian apa pun yang bisa diamati pada aset komputasi, termasuk platform fisik dan virtual, jaringan, layanan, dan lingkungan cloud. Contohnya percobaan login, pemasangan update, atau aplikasi yang menjawab permintaan transaksi.
- **Adverse event:** event yang membawa konsekuensi negatif, apa pun penyebabnya, termasuk bencana alam dan listrik padam. Dokumen NIST hanya membahas adverse event yang terkait keamanan siber, dan menyebut bahwa sering dibutuhkan analisis tambahan untuk menentukan apakah adverse event itu berarti insiden sudah terjadi.
- **Insiden keamanan siber (cybersecurity incident):** kejadian yang benar-benar atau hampir pasti membahayakan kerahasiaan, integritas, atau ketersediaan informasi atau sistem informasi tanpa wewenang yang sah, atau yang merupakan pelanggaran (atau ancaman pelanggaran yang dekat) terhadap hukum, kebijakan keamanan, prosedur keamanan, atau acceptable use policy. Definisi ini diambil NIST dari FISMA 2014 [S1].

Alert tidak punya definisi tersendiri di glosarium Rev. 3. Di CSF 2.0 Community Profile, alert adalah cara informasi tentang adverse event disampaikan ke staf dan alat yang berwenang, misalnya SOC dan incident responder [S1]. Jadi alert adalah pemberitahuan, bukan kesimpulan.

Tiga hal dari definisi insiden yang sering terlewat:

1. Tidak perlu ada layanan yang turun. Data yang disalin diam-diam sudah memenuhi definisi karena kerahasiaan terganggu.
2. Ancaman yang dekat sudah cukup. Rev. 2 memberi penjelasan "imminent threat": organisasi punya dasar faktual untuk percaya insiden spesifik akan terjadi [S3].
3. Pelanggaran kebijakan juga insiden. SANS Incident Handler's Handbook memakai definisi yang serupa: pelanggaran kebijakan, hukum, atau tindakan yang tidak dapat diterima yang melibatkan aset informasi [S6].

Dalam situasi PT JAB, file di share berganti ekstensi dan muncul catatan tebusan. Itu tanda kuat integritas dan ketersediaan data terganggu tanpa wewenang. Begitu L2 memastikan bahwa ini bukan aktivitas sah (misalnya migrasi atau enkripsi oleh aplikasi backup terjadwal), kejadian ini memenuhi definisi insiden. Yang belum diketahui (sumbernya, luasnya, apakah ada data yang dicuri) tidak menunda pernyataan insiden; pertanyaan itu dijawab setelah insiden dinyatakan.

### 1.2 Declare: keputusan yang menyalakan proses dan kewajiban

Pertanyaan berikutnya dari L1 adalah "siapa yang menentukan ini insiden?". Di PT JAB, Yoga (L2 on-call) memvalidasi dan mengusulkan, lalu SOC lead Dimas Prasetyo, yang juga incident commander default, menyatakan insiden. Siapa yang berwenang menyatakan insiden ditulis di IR plan PT JAB (`JAB-IRP-01`), yang dibahas di Day 02.

CSF 2.0 Community Profile di Rev. 3 menjadikan langkah ini hasil tersendiri: insiden dinyatakan ketika adverse event memenuhi kriteria insiden yang sudah ditetapkan (DE.AE-08). Rekomendasinya adalah menerapkan kriteria itu pada ciri aktivitas yang diketahui maupun yang diduga, sambil memperhitungkan false positive yang sudah dikenal [S1]. Rev. 2 juga menyarankan setiap organisasi membuat definisi "insiden" versinya sendiri supaya cakupannya jelas [S3].

Menyatakan insiden adalah keputusan, bukan label. Setelah keputusan itu, beberapa hal mulai berjalan:

- IR plan dijalankan bersama pihak ketiga yang relevan (RS.MA-01). NIST juga menyarankan menunjuk satu incident lead untuk tiap insiden [S1].
- Laporan insiden ditriage dan divalidasi, termasuk perkiraan severity dan urgensi (RS.MA-02) [S1].
- Tindakan dan temuan dicatat, dan integritas catatan serta bukti dijaga (RS.AN-06, RS.AN-07) [S1].
- Pihak internal dan eksternal diberi tahu sesuai prosedur dan aturan yang berlaku (RS.CO-02) [S1].

Poin terakhir yang membuat kriteria harus tertulis. Di Indonesia, misalnya, UU 27/2022 tentang Pelindungan Data Pribadi Pasal 46 mewajibkan pengendali data pribadi menyampaikan pemberitahuan tertulis paling lambat 3 x 24 jam kepada subjek data dan lembaga bila terjadi kegagalan pelindungan data pribadi [S14][S13]. Teks pasal dan penjelasannya tidak menyebut kapan hitungan 3 x 24 jam dimulai; cara menetapkan titik mulai dan detail pelaporan dibahas di Day 18 bagian 1.4. Untuk Day ini cukup dipegang: catatan waktu declare dan isi catatannya bisa ikut menentukan apakah kewajiban seperti ini terpenuhi.

Dua kesalahan yang berlawanan sama-sama mahal. Terlambat menyatakan insiden berarti orang yang dibutuhkan tidak dipanggil dan bukti hilang. Menyatakan insiden untuk setiap alert membuat CSIRT virtual lelah. Insiden yang sudah dinyatakan tetap boleh ditutup bila ternyata bukan insiden, asalkan alasannya dicatat.

### 1.3 Siklus NIST SP 800-61 Rev. 2: empat fase

Setelah insiden dinyatakan, L1 bertanya "terus sekarang ngapain?". Kerangka yang paling banyak dikenal, dan yang masih muncul di banyak lowongan dan materi, adalah siklus empat fase dari NIST SP 800-61 Rev. 2 (Computer Security Incident Handling Guide, Agustus 2012) [S3][S4].

Empat fase Rev. 2 [S3]:

1. **Preparation:** membangun dan melatih tim, menyiapkan alat dan sumber daya, serta mengurangi jumlah insiden lewat kontrol yang dipilih dari penilaian risiko.
2. **Detection & Analysis:** menemukan tanda insiden, memvalidasinya, menentukan cakupan, mendokumentasikan, dan memprioritaskan.
3. **Containment, Eradication & Recovery:** membatasi dampak, menghilangkan penyebab, dan memulihkan sistem. Ketiganya digabung menjadi satu fase.
4. **Post-Incident Activity:** laporan penyebab dan biaya insiden, serta langkah untuk mencegah insiden serupa.

Gambar siklus di Rev. 2 (Figure 3-1) punya dua panah balik. Panah pertama dari Containment, Eradication & Recovery kembali ke Detection & Analysis, karena saat membersihkan malware tim sering perlu memeriksa apakah ada host lain yang terinfeksi. Panah kedua dari Post-Incident Activity kembali ke Preparation [S3]. Untuk `INC-2026-017`, panah pertama berarti: saat `JKT-FS01` diisolasi, analisis tetap berjalan untuk mencari sumber enkripsi di host lain.

Rev. 2 sudah ditarik (withdrawn) pada 3 April 2025 dan digantikan Rev. 3 [S4]. Meski begitu, empat fase ini tetap perlu dikuasai karena banyak IR plan, lowongan, dan soal interview masih memakainya.

### 1.4 NIST SP 800-61 Rev. 3: IR sebagai bagian dari manajemen risiko

Bila Direktur Teknologi PT JAB bertanya "kita ikut NIST yang terbaru?", jawabannya tidak lagi berupa empat kotak. Rev. 3 terbit final pada April 2025 dengan judul "Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile" [S1][S2].

Alasan perubahan dijelaskan di Rev. 3 sendiri. Saat Rev. 2 ditulis, insiden relatif jarang, cakupannya sempit, dan biasanya selesai dalam satu atau dua hari, sehingga IR masuk akal dipandang sebagai kegiatan terpisah oleh tim terpisah. Sekarang insiden lebih sering, dampaknya lebih besar, dan pemulihan bisa memakan waktu berminggu-minggu atau berbulan-bulan. Karena itu IR diposisikan sebagai bagian dari manajemen risiko keamanan siber, dan lessons learned sebaiknya dibagikan segera setelah ditemukan, bukan menunggu pemulihan selesai [S1].

Rev. 3 memakai enam fungsi NIST Cybersecurity Framework (CSF) 2.0, kerangka hasil keamanan siber dari NIST yang terbit 26 Februari 2024 [S5]. Model siklusnya (Fig. 2, "Incident response life cycle model based on CSF 2.0 Functions") punya tiga lapis [S1]:

```
Incident Response   :  Detect  ->  Respond  ->  Recover
                              \       |       /
Lessons Learned     :      (Identify) Improvement  (ID.IM)
                              /       |       \
Preparation         :  Govern     Identify     Protect
```

Lapis bawah (Govern, Identify, Protect) adalah kegiatan manajemen risiko yang lebih luas dan mendukung IR, tetapi bukan bagian dari respons itu sendiri. Lapis atas adalah respons. Lapis tengah adalah kategori Improvement (ID.IM) di dalam fungsi Identify: pelajaran dari semua fungsi masuk ke sana, dianalisis, diprioritaskan, lalu dipakai untuk memperbaiki semua fungsi [S1].

Tabel berikut merangkum arti tiap fungsi dan kategori CSF yang paling sering disentuh saat menangani insiden. Cari kolom terakhir saat membaca dokumen atau laporan yang memakai kode seperti `RS.MA` atau `DE.AE`.

| Fungsi | Arti singkat di CSF 2.0 | Lapis di model Rev. 3 | Kategori yang sering disentuh saat insiden |
|---|---|---|---|
| Govern (GV) | Strategi, ekspektasi, dan kebijakan manajemen risiko ditetapkan, dikomunikasikan, dan dipantau | Preparation | Kebijakan IR, peran, dan wewenang |
| Identify (ID) | Risiko keamanan siber organisasi dipahami | Preparation, dan Improvement di lapis tengah | ID.IM Improvement |
| Protect (PR) | Perlindungan untuk mengelola risiko dipakai | Preparation | Kontrol yang mencegah dan membatasi insiden |
| Detect (DE) | Kemungkinan serangan dan kompromi ditemukan dan dianalisis | Incident Response | DE.CM Continuous Monitoring, DE.AE Adverse Event Analysis |
| Respond (RS) | Tindakan atas insiden yang terdeteksi dilakukan | Incident Response | RS.MA Incident Management, RS.AN Incident Analysis, RS.CO Incident Response Reporting and Communication, RS.MI Incident Mitigation |
| Recover (RC) | Aset dan operasi yang terdampak dipulihkan | Incident Response | RC.RP Incident Recovery Plan Execution, RC.CO Incident Recovery Communication |

Sumber isi tabel: [S1].

Dua hal praktis dari Rev. 3. Pertama, isinya bukan lagi panduan langkah demi langkah; isinya rekomendasi dan pertimbangan per kategori dan subkategori CSF, sementara detail teknis dipindahkan ke halaman proyek NIST supaya bisa diperbarui tanpa revisi dokumen [S1]. Kedua, Rev. 3 menegaskan organisasi boleh memakai model siklus yang paling cocok untuknya; model berbasis CSF dipilih karena banyak organisasi sudah memakai CSF [S1].

### 1.5 PICERL dan pemetaannya ke NIST

Yoga sendiri terbiasa berpikir dengan enam tahap, bukan empat. Model enam tahap ini berasal dari SANS Incident Handler's Handbook karya Patrick Kral (diterbitkan SANS 21 Februari 2012) dan dikenal dengan singkatan PICERL [S6][S7]:

1. **Preparation:** kebijakan, tim, alat, akses, dan latihan disiapkan sebelum insiden.
2. **Identification:** menentukan apakah sebuah kejadian adalah insiden, lalu mengumpulkan bukti dan menentukan cakupan awal.
3. **Containment:** membatasi kerusakan dan mencegah penyebaran.
4. **Eradication:** menghilangkan penyebab dan sisa penyerang.
5. **Recovery:** mengembalikan sistem ke produksi dan memantaunya.
6. **Lessons Learned:** meninjau insiden dan proses, lalu memperbaiki.

Bedanya dengan Rev. 2 terutama ada di fase ketiga: PICERL memisahkan containment, eradication, dan recovery menjadi tiga tahap. Pemisahan ini berguna di lapangan karena tiap tahap punya pemilik keputusan dan kriteria selesai yang berbeda.

Tabel berikut memetakan tiga kerangka itu. Kolom Rev. 2 dan Rev. 3 untuk empat fase lama mengikuti Table 1 di Rev. 3; kolom PICERL dan pemetaan ke kategori Rev. 3 adalah susunan catatan ini. Pakai tabel ini untuk menerjemahkan istilah saat IR plan, lowongan, atau lawan bicara memakai kerangka yang berbeda.

| PICERL (SANS) | NIST SP 800-61 Rev. 2 | NIST SP 800-61 Rev. 3 (fungsi CSF 2.0) | Contoh di `INC-2026-017` |
|---|---|---|---|
| Preparation | Preparation | Govern, Identify, Protect | IR plan `JAB-IRP-01`, EDR terpasang di `JKT-FS01`, nomor on-call |
| Identification | Detection & Analysis | Detect (DE.CM, DE.AE), awal Respond (RS.MA-02 triage dan validasi) | Lima alert, validasi L2, declare |
| Containment | Containment, Eradication & Recovery | Respond (RS.MI-01) | Isolasi jaringan `JKT-FS01` lewat EDR |
| Eradication | Containment, Eradication & Recovery | Respond (RS.MI-02) | Menghapus akses penyerang setelah sumbernya diketahui |
| Recovery | Containment, Eradication & Recovery | Recover (RC.RP, RC.CO) | Restore share dari backup yang sudah dicek integritasnya |
| Lessons Learned | Post-Incident Activity | Identify, kategori Improvement (ID.IM) | Review setelah insiden, perbaikan IR plan |

Sumber: [S1][S3][S6][S7].

Perhatian: dalam praktik, tahap-tahap ini tumpang tindih dan berulang. Rev. 2 sudah menggambar panah balik dari containment ke analisis [S3], dan Rev. 3 menegaskan bahwa pelajaran bisa didapat kapan saja, tidak hanya di akhir [S1]. Di `INC-2026-017`, containment `JKT-FS01` berjalan sementara identification masih mencari sumber enkripsi. Bila analisis menemukan host kedua, containment dibuka lagi untuk host itu.

### 1.6 Peran saat insiden: incident commander di tengah

L1 bertanya "jam segini saya harus telepon siapa?" dan "boleh cabut kabel?". Dua pertanyaan itu sebenarnya satu: siapa memegang peran apa, dan siapa yang berwenang memutuskan.

Rev. 3 menyebut bahwa IR dulu dikerjakan hampir sepenuhnya oleh incident handler dari tim IR sendiri. Sekarang keberhasilan IR bergantung pada banyak pihak internal dan eksternal: pimpinan (yang bisa berwenang atas tindakan berdampak besar seperti mematikan atau membangun ulang layanan kritis), incident handler, profesional teknologi, legal, humas dan media, HR, keamanan fisik, pemilik aset, dan pihak ketiga seperti MSSP atau penyedia layanan IR [S1]. Rev. 3 juga menyebut bahwa kebijakan IR perlu menetapkan peran mana yang berwenang menyita, memutus, atau mematikan aset teknologi [S1]. Jadi jawaban untuk "boleh cabut kabel?" ada di IR plan, bukan di keberanian analyst yang sedang piket.

Pusat koordinasi adalah incident commander (IC). Konsep ini berasal dari Incident Command System (ICS), sistem komando yang lahir di layanan darurat publik, dan dipakai sebagai dasar praktik manajemen insiden di perusahaan seperti Google, Heroku, dan PagerDuty [S11]. Dokumentasi IR PagerDuty menjelaskan peran IC dengan tegas [S8][S9]:

- IC menjaga agar insiden terus bergerak ke penyelesaian: mengambil keputusan, mendelegasikan tugas, dan menimbang masukan para ahli.
- IC tidak mengerjakan remediasi, tidak membuka grafik, dan tidak menelusuri log. Pekerjaan itu didelegasikan ke subject matter expert (SME).
- Selama insiden, IC adalah pemegang komando di bridge, apa pun jabatan hariannya. Kedatangan orang yang lebih senior tidak otomatis memindahkan komando.
- IC punya deputy (cadangan IC) dan bisa menyerahkan komando secara eksplisit, misalnya karena lelah.
- Scribe mencatat timeline, tindakan, keputusan, dan tindak lanjut supaya yang lain bisa fokus; scribe juga tidak mengerjakan remediasi [S10].

Rev. 2 punya alasan yang sama untuk scribe: handler sebaiknya bekerja berdua, satu mencatat dan satu mengerjakan teknis, karena catatan itu bisa dipakai sebagai bukti di pengadilan [S3].

Tabel berikut adalah daftar peran yang diaktifkan PT JAB saat insiden. Perhatikan kolom "Tidak mengerjakan", karena kesalahan peran paling sering terjadi di sana.

| Peran | Tugas utama | Tidak mengerjakan | Dipegang di PT JAB |
|---|---|---|---|
| Incident commander | Koordinasi, keputusan, ritme update, persetujuan komunikasi keluar | Analisis log, perintah teknis | SOC lead Dimas Prasetyo; cadangan analyst L2 senior |
| Technical lead | Memimpin analisis dan scoping, memberi rekomendasi containment | Keputusan bisnis, komunikasi ke luar | Analyst L2 Sari Kusuma atau Yoga Pratama |
| Scribe | Timeline, keputusan beserta pengambil keputusan, daftar tindak lanjut | Remediasi, opini di catatan | Analyst L1 shift yang tidak memegang antrean |
| Operasi IT dan NOC | Menjalankan containment di jaringan dan server: blokir, isolasi, reset | Memutuskan containment sendiri | Manajer NOC Bambang Hartono, tim Infrastruktur |
| Komunikasi | Pesan ke pelanggan dan publik, satu pintu | Menyebar dugaan yang belum dikonfirmasi | Corporate Communication Maya Lestari |
| Legal dan DPO | Menilai kewajiban hukum, pelaporan, kontrak pelanggan korporat | Analisis teknis | Legal Ratna Sari, DPO Agus Setiawan |
| Executive sponsor | Keputusan berdampak bisnis: mematikan layanan pelanggan, biaya pihak ketiga, pengumuman publik | Memimpin bridge sehari-hari | Direktur Teknologi Hendra Wijaya |
| HR | Bila pelaku orang dalam atau akun karyawan terlibat | Investigasi teknis | HR Business Partner |
| Pihak ketiga (retainer) | Forensik dan tenaga tambahan di luar kemampuan internal | Keputusan atas nama PT JAB tanpa persetujuan | PT Forensik Digital Contoh |

Untuk SEV-1 di PT JAB, IC tetap SOC lead, tetapi keputusan bisnis besar diambil executive sponsor. Ini tidak bertentangan dengan prinsip PagerDuty: IC memimpin jalannya respons, dan untuk keputusan yang di luar wewenangnya IC meminta keputusan ke executive sponsor, sejalan dengan Rev. 3 yang menyebut pimpinan bisa berwenang atas tindakan berdampak tinggi [S1]. Siapa mengerjakan apa secara rinci (RACI) dan jalur eskalasi dari L1 ke L2 ke IC ditulis di Day 02.

Kembali ke pertanyaan L1: ia menelepon L2 on-call (Yoga), tidak mencabut kabel sendiri, dan mencatat apa yang sudah ia lihat beserta jamnya. Mencabut kabel atau mematikan server adalah keputusan containment yang punya konsekuensi, misalnya hilangnya isi memori yang bisa menjadi bukti; keputusan itu diambil IC berdasarkan rekomendasi technical lead.

### 1.7 Severity insiden: dimensi dampak dan skala SEV PT JAB

Pertanyaan terakhir L1 adalah "seberapa parah?". Severity menentukan siapa yang dibangunkan malam itu, seberapa cepat mereka harus bergerak, dan seberapa sering update dikirim. Supaya tidak bergantung pada perasaan, severity diturunkan dari dimensi dampak.

Rev. 2 menyebut tiga dimensi untuk memprioritaskan insiden [S3]:

- **Functional impact:** dampak ke fungsi bisnis yang disediakan sistem, sekarang dan yang mungkin terjadi bila insiden tidak segera ditahan. Kategorinya None, Low, Medium, High.
- **Information impact:** dampak ke kerahasiaan, integritas, dan ketersediaan informasi. Kategorinya None, Privacy Breach, Proprietary Breach, Integrity Loss, dan selain None boleh dipilih lebih dari satu.
- **Recoverability:** waktu dan sumber daya untuk pulih. Kategorinya Regular, Supplemented, Extended, Not Recoverable. Contoh Not Recoverable adalah data sensitif yang sudah dicuri dan dipublikasikan.

Rev. 3 memperluas daftarnya menjadi faktor evaluasi risiko: kekritisan aset, functional impact, dampak data, tahap aktivitas yang teramati, karakterisasi aktor ancaman, dan recoverability [S1]. CISA National Cyber Incident Scoring System (NCISS), yang dibangun di atas Rev. 2, memakai delapan faktor serupa (antara lain functional impact, observed activity, lokasi aktivitas di jaringan, karakterisasi aktor, information impact, dan recoverability) untuk menilai risiko insiden di tingkat nasional AS, dengan tingkat dari Baseline sampai Emergency [S12]. PT JAB tidak memakai NCISS, tetapi dimensinya sama: dampak ke layanan, dampak ke data, dan kesulitan pulih.

Tabel berikut adalah skala severity PT JAB yang dipakai di semua Day. Baca kolom kriteria sebagai "salah satu cukup".

| Severity | Nama | Kriteria (salah satu cukup) | Contoh | Target waktu |
|---|---|---|---|---|
| SEV-1 | Kritis | Layanan pelanggan terganggu luas; data pribadi pelanggan dalam jumlah besar terindikasi bocor; ransomware menyebar; akun domain admin dikuasai penyerang | Ransomware di server billing; RADIUS dimatikan penyerang | IC aktif maks 15 menit, executive sponsor diberi tahu maks 30 menit, update setiap 1 jam |
| SEV-2 | Tinggi | Kompromi terkonfirmasi tetapi terbatas; data pribadi mungkin terdampak dalam jumlah terbatas; akun berhak tinggi disalahgunakan | Satu server portal terkompromi web shell; mailbox direksi diambil alih | IC aktif maks 30 menit, update setiap 4 jam |
| SEV-3 | Sedang | Kompromi satu endpoint atau akun biasa tanpa tanda penyebaran; tidak ada data pribadi terdampak sejauh ini | Malware di satu laptop karyawan; akun karyawan login dari luar negeri setelah phishing | Ditangani L2 pada jam kerja, update harian |
| SEV-4 | Rendah | Aktivitas mencurigakan tanpa dampak, upaya yang gagal, pelanggaran kebijakan kecil | Brute force VPN yang gagal semua; USB tidak terdaftar | Ditangani di antrean SOC biasa |

Kolom target waktu tetap berlaku walau belum ada kemajuan: update dikirim sesuai jadwal dan berisi fakta yang sudah ada, bukan dugaan.

Kriteria PT JAB memetakan dimensi NIST ke bahasa bisnis ISP: "layanan pelanggan terganggu luas" adalah functional impact High, "data pribadi pelanggan bocor" adalah information impact Privacy Breach, dan "ransomware menyebar" atau "domain admin dikuasai" adalah recoverability yang cenderung Extended. Untuk `INC-2026-017` pukul 22:03, sumber enkripsi belum diketahui, sehingga kriteria "ransomware menyebar" belum bisa disingkirkan, dan share `Keuangan` mungkin berisi data tagihan pelanggan. Bagian 1.8 menjelaskan kenapa itu cukup untuk SEV-1.

### 1.8 Severity bukan prioritas alert, dan boleh berubah

Alert `SOC-2026-0187` masuk ke ticketing SOC dengan prioritas P2, karena rule "mass file rename" memang diberi prioritas bawaan P2. Insidennya dinyatakan SEV-1. Keduanya tidak bertentangan, karena keduanya mengukur hal yang berbeda.

- **Prioritas alert (P1-P4 di ticketing SOC PT JAB)** menjawab "alert mana yang dilihat lebih dulu di antrean". Nilainya ditentukan rule dan aset, sebelum ada analisis manusia.
- **Severity insiden (SEV-1 sampai SEV-4)** menjawab "seberapa parah insiden ini bagi PT JAB". Nilainya ditentukan IC dari dimensi dampak setelah analisis, dan menentukan siapa terlibat serta ritme update.

Satu insiden bisa berawal dari banyak alert dengan prioritas berbeda, dan alert berprioritas rendah bisa menjadi bagian dari insiden SEV-1. Rev. 3 juga menyebut bahwa insiden tidak boleh ditangani berdasarkan urutan datang, melainkan berdasarkan faktor risiko [S1], dan Rev. 2 menyebut hal yang sama [S3].

Dua aturan severity PT JAB:

1. **Bila ragu antara dua tingkat, pilih yang lebih tinggi dulu, lalu turunkan setelah ada bukti.** Alasannya asimetris: severity yang terlalu tinggi membuang beberapa jam tidur beberapa orang, sedangkan severity yang terlalu rendah bisa berarti eksekutif, legal, dan DPO baru tahu setelah batas waktu kewajiban terlewat.
2. **Severity boleh naik atau turun sepanjang insiden, dan setiap perubahan dicatat beserta alasannya.** Rev. 3 membedakan escalation (menambah sumber daya atau mempercepat waktu) dan elevation (melibatkan manajemen yang lebih tinggi), dan menyarankan status semua insiden dilacak supaya kebutuhan perubahan strategi cepat terlihat (RS.MA-04) [S1].

Dengan aturan pertama, `INC-2026-017` dinyatakan SEV-1 pada 22:03. Bila scoping kemudian membuktikan enkripsi hanya dari satu workstation, tanpa akun berhak tinggi dan tanpa data pribadi di share, IC boleh menurunkannya ke SEV-2 dengan alasan tertulis. Bila ditemukan tanda data disalin keluar sebelum enkripsi, severity tetap SEV-1 dan DPO harus sudah ikut sejak awal.

## 2. Contoh artefak dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Nama orang, host, akun, dan nomor tiket mengikuti organisasi fiktif PT JAB. Keempat artefak di bawah dihasilkan dari situasi Jumat malam di bagian Ide inti.

### 2.1 Catatan keputusan declare `INC-2026-017`

Catatan ini menjawab pertanyaan pertama dan kedua L1: kapan kejadian menjadi insiden, siapa yang menyatakan, dan apa dasarnya. Catatan ditulis oleh scribe dan disetujui IC dalam beberapa menit setelah declare, di tiket insiden dan kanal `#inc-2026-017`.

```
INC-2026-017 | Catatan keputusan declare
Waktu declare       : Jumat 2026-10-09 22:03 WIB
Dinyatakan oleh     : Dimas Prasetyo (SOC lead, incident commander)
Diusulkan oleh      : Yoga Pratama (analyst L2 on-call)
Alert terkait       : SOC-2026-0187, -0188, -0189, -0190, -0191 (EDR, JKT-FS01)
Fakta saat declare  : Sejak 21:32 file di share Keuangan pada JKT-FS01 berganti
                      ekstensi .lck; BACA-INI.txt muncul di tiap folder.
                      Diverifikasi L2 pukul 21:52 (baca saja, tanpa mengubah file).
                      Tidak ada change request atau job backup yang menjelaskannya.
Kriteria terpenuhi  : integritas dan ketersediaan data terganggu tanpa wewenang
Jenis awal          : ransomware (dugaan)
Severity awal       : SEV-1
Alasan severity     : sumber enkripsi belum diketahui, jadi "ransomware menyebar"
                      belum bisa disingkirkan; share Keuangan mungkin berisi data
                      tagihan pelanggan; aturan ragu pilih lebih tinggi
Belum diketahui     : host sumber enkripsi, akun yang dipakai, host lain yang
                      terdampak, apakah ada data yang disalin keluar
Peran diaktifkan    : lihat log aktivasi peran (bagian 2.3)
Kanal               : #inc-2026-017 (utama), bridge NOC
Review severity     : setiap 1 jam atau saat ada fakta baru
```

Cara membaca elemennya:

- **Waktu declare** dipisah dari waktu alert pertama (21:32). Selisih 31 menit itu adalah waktu triage dan validasi, dan keduanya bisa ditanyakan auditor atau regulator.
- **Dinyatakan oleh** dan **Diusulkan oleh** dipisah, supaya jelas siapa yang memegang keputusan.
- **Fakta saat declare** hanya berisi hal yang sudah dicek, beserta cara mengeceknya. Dugaan masuk ke "Jenis awal" dan "Belum diketahui".
- **Alasan severity** menyebut kriteria SEV yang belum bisa disingkirkan, bukan hanya label. Tanpa alasan, penurunan severity nanti tidak bisa dinilai.
- **Belum diketahui** adalah daftar pertanyaan untuk technical lead, dan sekaligus pengingat bahwa declare tidak menunggu semuanya terjawab.

**Kapan gagal:** catatan ditulis besok paginya dari ingatan. Jam dan urutan menjadi tidak akurat, dan alasan severity hilang.

### 2.2 Pemetaan kejadian ke severity

Tabel ini dipakai L2 dan IC PT JAB sebagai acuan cepat saat menjawab "seberapa parah?" pada malam seperti `INC-2026-017`. Baca kolom dimensi dulu, lalu kriteria SEV yang terpenuhi.

| Kejadian | Functional impact | Information impact | Recoverability | SEV | Kriteria yang menentukan |
|---|---|---|---|---|---|
| Enkripsi file di `JKT-FS01`, sumber belum diketahui | Medium (share Keuangan tidak bisa dipakai) | Integrity Loss, mungkin Privacy Breach | Belum diketahui | SEV-1 | Ransomware menyebar belum bisa disingkirkan; ragu pilih lebih tinggi |
| `jkt-radius01` dimatikan penyerang, pelanggan broadband tidak bisa login | High | Belum diketahui | Supplemented sampai Extended | SEV-1 | Layanan pelanggan terganggu luas |
| Web shell di `jkt-portal01`, belum ada tanda akses ke database pelanggan | Low | Belum diketahui, data pribadi mungkin terdampak terbatas | Supplemented | SEV-2 | Kompromi terkonfirmasi tetapi terbatas |
| Laptop `BDG-WS-0213` menjalankan infostealer, diblokir EDR, tidak ada login aneh | None | None sejauh ini | Regular | SEV-3 | Satu endpoint, tanpa tanda penyebaran |
| Brute force VPN dari `203.0.113.45`, semua gagal | None | None | Regular | SEV-4 | Upaya gagal tanpa dampak |
| Akun `adm.rina` dipakai login dari luar negeri tengah malam | Belum diketahui | Belum diketahui | Belum diketahui | SEV-2 | Akun berhak tinggi disalahgunakan |

Cara membaca hasil: SEV ditentukan oleh kriteria terberat yang terpenuhi, bukan rata-rata ketiga dimensi. Baris terakhir menunjukkan bahwa "belum diketahui" di semua dimensi tetap bisa menghasilkan SEV-2, karena jenis akunnya sendiri sudah memenuhi kriteria. Bila nanti terbukti `adm.rina` dipakai untuk masuk ke `JKT-DC01`, severity naik ke SEV-1.

**Variasi:** tambahkan kolom "Apa yang bisa menaikkan severity" untuk tiap baris. Kolom itu menjadi daftar pertanyaan scoping.

### 2.3 Log aktivasi peran

Log ini menjawab pertanyaan "harus telepon siapa?" untuk `INC-2026-017` dan membuktikan target waktu SEV-1 terpenuhi. Diisi scribe di tiket insiden.

| Waktu (WIB) | Peran | Nama | Cara dihubungi | Status |
|---|---|---|---|---|
| 21:44 | Technical lead (awal) | Yoga Pratama | Telepon on-call L2 | Bergabung 21:46 |
| 21:55 | Incident commander | Dimas Prasetyo | Telepon | Aktif 22:03 saat declare |
| 22:04 | Scribe | Analyst L1 kedua shift malam | Langsung di ruang SOC | Aktif 22:05, antrean dipegang L1 pertama |
| 22:08 | Executive sponsor | Hendra Wijaya | Telepon, lalu pesan ringkas | Diberi tahu 22:08 |
| 22:10 | Operasi IT dan NOC | Bambang Hartono | Bridge NOC | Bergabung 22:14 |
| 22:25 | DPO | Agus Setiawan | Telepon | Diberi tahu 22:27; Legal dihubungi DPO |
| 22:32 | Technical lead (scoping) | Sari Kusuma | Telepon | Bergabung 22:40 |
| 23:45 | Pihak ketiga | PT Forensik Digital Contoh | Nomor retainer | Diminta siaga, belum dikerahkan |

Cara membaca hasil:

- IC aktif saat declare dan executive sponsor diberi tahu 5 menit setelah declare, jadi target SEV-1 (IC maks 15 menit, executive sponsor maks 30 menit) terpenuhi.
- Corporate Communication belum dihubungi karena belum ada dampak ke pelanggan yang terlihat dari luar. Keputusan ini sengaja, dan dicatat di timeline supaya tidak terlihat seperti kelalaian.
- Scribe diambil dari L1 yang tidak memegang antrean, sehingga pemantauan alert lain tetap berjalan.

**Kapan gagal:** nomor telepon di daftar on-call sudah tidak berlaku, atau orang yang dihubungi tidak punya akses ke EDR dan bridge. Jadwal on-call dan kesiapan aksesnya dibahas di Day 02.

### 2.4 Timeline awal oleh scribe

Timeline ini adalah catatan yang dibuat scribe sejak 22:05 untuk `INC-2026-017`, termasuk kejadian sebelum declare yang direkonstruksi dari alert dan chat. Bagian ini juga menunjukkan jawaban untuk pertanyaan "boleh cabut kabel?".

| Waktu (WIB) | Jenis | Isi | Sumber atau oleh |
|---|---|---|---|
| 21:32 | FAKTA | Alert `SOC-2026-0187`: rename file massal di `JKT-FS01` | EDR |
| 21:34-21:38 | FAKTA | Alert `SOC-2026-0188` sampai `-0191`, pola sama | EDR |
| 21:41 | TINDAKAN | L1 melapor ke L2 on-call lewat chat, lalu telepon 21:44 | L1 shift malam |
| 21:52 | FAKTA | File `.lck` dan `BACA-INI.txt` dikonfirmasi di share `Keuangan` (baca saja) | Yoga |
| 22:03 | KEPUTUSAN | Declare `INC-2026-017`, SEV-1, IC Dimas | Dimas |
| 22:15 | KEPUTUSAN | Isolasi jaringan `JKT-FS01` lewat EDR, server tidak dimatikan supaya memori tetap ada | Dimas, atas rekomendasi Yoga |
| 22:17 | TINDAKAN | Isolasi `JKT-FS01` dijalankan | Yoga |
| 22:21 | FAKTA | Tidak ada file baru yang berganti ekstensi sejak isolasi | EDR |
| 22:25 | KEPUTUSAN | DPO diberi tahu karena share `Keuangan` mungkin berisi data tagihan pelanggan | Dimas |
| 22:30 | KEPUTUSAN | Corporate Communication belum dihubungi; ditinjau ulang bila ada dampak ke pelanggan | Dimas |
| 23:10 | FAKTA | Koneksi SMB yang menulis file `.lck` berasal dari `JKT-WS-0457` dengan akun `budi.santoso` | Sari |
| 23:15 | KEPUTUSAN | Isolasi `JKT-WS-0457`; akun `budi.santoso` dinonaktifkan | Dimas |
| 23:18 | TINDAKAN | Isolasi `JKT-WS-0457` lewat EDR (Yoga); akun dinonaktifkan tim Infrastruktur 23:24 | Yoga, Infrastruktur |
| 23:40 | KEPUTUSAN | Severity tetap SEV-1: cara `JKT-WS-0457` terkompromi dan host lain belum diketahui. Review berikutnya 00:40 | Dimas |
| 23:45 | TODO | Legal dan DPO menilai kewajiban pemberitahuan setelah isi share diketahui | Agus |
| 23:45 | TODO | Retainer diminta siaga | Dimas |

Elemen yang perlu diperhatikan:

- **Kolom Jenis** memisahkan FAKTA, KEPUTUSAN, TINDAKAN, dan TODO. Gaya ini mengikuti saran PagerDuty untuk menandai tindak lanjut dengan awalan yang mudah dicari [S10]. Pemisahan ini membuat laporan akhir dan review setelah insiden jauh lebih mudah.
- **Keputusan selalu punya pengambil keputusan dan alasan.** Baris 22:15 menjawab pertanyaan L1 tentang mencabut kabel: containment dilakukan dengan isolasi jaringan, bukan mematikan server, dan alasannya tertulis.
- **Fakta selalu punya sumber.** Rev. 2 menyarankan catatan hanya berisi fakta, bukan opini, dan setiap langkah diberi waktu, karena catatan seperti ini bisa menjadi bukti [S3].
- **Waktu memakai satu zona (WIB)** dan jam dari sumber yang tersinkron. Bila jam EDR dan jam chat berbeda, catat selisihnya sekali di awal timeline.

**Kapan gagal:** scribe ikut menganalisis log sehingga timeline bolong; atau catatan berisi "sepertinya penyerang masuk lewat VPN" tanpa sumber, yang kemudian dibaca orang lain sebagai fakta.

## 3. Lab praktik

Latihan Day ini berupa dokumen untuk PT JAB. Tulis jawaban di folder `latihan/` pribadi. Jangan memakai data, nama, atau kejadian dari pekerjaan nyata; bila mengambil pengalaman sendiri, samarkan menjadi kejadian fiktif.

**Latihan 1: menilai severity enam skenario.** Untuk setiap skenario, tulis functional impact, information impact, recoverability, SEV, kriteria yang menentukan, dan satu fakta yang bisa menaikkan atau menurunkan severity. Simpan di `latihan/day01-severity.md`.

1. Akun `svc_billing` login interaktif ke `JKT-JUMP01` pukul 02:10, padahal akun ini hanya dipakai aplikasi billing.
2. Pelanggan korporat mengirim email: file tagihan mereka bulan lalu beredar di grup chat publik.
3. USB tidak terdaftar dicolokkan ke `BDG-WS-0118`, EDR memblokir, tidak ada file yang tersalin.
4. EDR mendeteksi dan mengkarantina file uji EICAR di `JKT-WS-0302` saat tim IT menguji antivirus, sesuai change request.
5. Akun `rina.wulandari` membuat inbox rule yang meneruskan semua email ke alamat `@example.net`, setelah klik tautan phishing.
6. POP Surabaya diserang DDoS, sekitar 30 ribu pelanggan broadband terputus selama 40 menit.

Petunjuk: tentukan dulu apakah setiap skenario adalah insiden (bagian 1.1). Satu skenario di atas bukan insiden.

**Latihan 2: menulis catatan declare.** Pilih skenario 2 atau 5, lalu tulis catatan declare dengan format bagian 2.1. Pakai nomor `INC-2026-018`. Pastikan "Fakta saat declare" tidak memuat dugaan, dan "Alasan severity" menyebut kriteria SEV. Simpan di `latihan/day01-declare.md`.

**Latihan 3: memperbaiki timeline.** Tulis ulang lima entri buruk berikut menjadi entri timeline yang baik (waktu, jenis, isi, sumber atau oleh). Simpan di `latihan/day01-timeline.md`.

1. "Malam itu server diisolasi."
2. "Sepertinya penyerang masuk dari VPN."
3. "22:40 diskusi panjang soal perlu matikan server atau tidak, 5 setuju 2 tidak."
4. "Yoga cek log."
5. "Severity diturunkan."

**Latihan 4: memetakan satu gangguan lama ke PICERL dan Rev. 3.** Ambil satu gangguan besar yang pernah kamu tangani di NOC atau SOC, lalu samarkan semua detailnya menjadi kejadian fiktif di PT JAB. Petakan setiap langkah penanganannya ke tahap PICERL, fase Rev. 2, dan fungsi CSF 2.0 dengan format tabel bagian 1.5. Tandai langkah yang tumpang tindih atau berulang, dan tulis siapa yang sebenarnya menjadi IC saat itu, walaupun tidak disebut demikian. Simpan di `latihan/day01-picerl.md`.

**Latihan 5: peran yang kosong.** Untuk `INC-2026-017`, bayangkan Dimas tidak bisa dihubungi sampai 23:00. Tulis tiga paragraf: siapa yang sebaiknya memegang IC sementara, apa yang hilang bila Yoga merangkap IC dan technical lead, dan bagaimana serah terima komando dilakukan saat Dimas bergabung. Simpan di `latihan/day01-peran.md`.

**Hasil yang sebaiknya tersimpan:**

- Tabel enam skenario dengan SEV dan alasan, dengan skenario 4 ditandai bukan insiden beserta alasannya.
- Satu catatan declare lengkap yang memisahkan fakta, dugaan, dan hal yang belum diketahui.
- Lima entri timeline yang sudah diperbaiki, masing-masing dengan jenis dan sumber.
- Satu tabel pemetaan PICERL, Rev. 2, dan Rev. 3 dari pengalaman yang sudah disamarkan.
- Tiga paragraf tentang IC sementara dan serah terima komando.

## 4. Troubleshooting

Tabel ini berisi masalah yang sering muncul saat proses IR dijalankan pertama kali di organisasi tanpa tim IR khusus. Cari gejala yang mirip dengan yang kamu alami, lalu periksa kolom terakhir.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| L1 tidak yakin kapan harus eskalasi atau menyatakan insiden | Kriteria insiden tidak tertulis atau terlalu umum | Tulis kriteria insiden di IR plan dengan contoh; NIST menyarankan definisi insiden khusus organisasi [S3] |
| Semua orang di bridge bicara, tidak ada keputusan | Tidak ada IC yang ditunjuk secara eksplisit | Umumkan di awal siapa IC; IC yang mendelegasikan tugas [S9] |
| IC tenggelam di log dan berhenti mengirim update | IC merangkap technical lead | Pisahkan peran; IC menunjuk technical lead dan deputy [S8] |
| Severity diperdebatkan lama sebelum respons dimulai | Kriteria SEV tidak dipakai, atau orang menunggu kepastian | Pakai aturan ragu pilih lebih tinggi, lalu jadwalkan review severity |
| Laporan akhir tidak bisa menjawab "siapa memutuskan apa dan kapan" | Tidak ada scribe, atau timeline ditulis dari ingatan | Tunjuk scribe saat declare; catat keputusan beserta pengambil keputusan [S10] |
| Legal atau DPO baru tahu setelah beberapa hari | Severity awal terlalu rendah, atau notifikasi legal tidak terkait dengan jenis data | Tambahkan pemicu notifikasi DPO berdasarkan jenis data, bukan hanya SEV |
| Insiden "selesai" tetapi kembali beberapa hari kemudian | Eradication dilakukan sebelum scoping lengkap | Kembali ke analisis; tahap IR berulang [S3] |

## 5. Kesalahan umum dan jebakan

- Menyamakan alert dengan insiden. Alert adalah pemberitahuan; insiden adalah keputusan yang memenuhi kriteria [S1].
- Menunggu layanan turun sebelum menyatakan insiden. Definisi insiden mencakup kerahasiaan dan ancaman yang dekat, bukan hanya ketersediaan [S1].
- Menunda declare sampai semua pertanyaan terjawab. Pertanyaan scoping justru dijawab setelah declare, dengan orang dan wewenang yang lengkap.
- Menganggap severity insiden sama dengan prioritas alert. Prioritas alert diberi rule; severity diberi IC dari dimensi dampak.
- IC ikut mengetik perintah. Begitu IC sibuk teknis, tidak ada yang memegang keputusan dan komunikasi [S9].
- Scribe menulis opini atau hanya menulis "diskusi". Timeline berisi fakta bersumber, keputusan beserta pengambilnya, dan tindak lanjut [S10][S3].
- Mengira Rev. 3 hanya mengganti nama empat fase. Rev. 3 adalah profil CSF 2.0 berisi rekomendasi per kategori, dengan model tiga lapis, dan menempatkan IR di dalam manajemen risiko [S1].
- Menganggap PICERL dan siklus NIST berjalan lurus. Containment, analisis, dan pelajaran sering berjalan bersamaan dan berulang [S3][S1].
- Menurunkan severity tanpa alasan tertulis. Penurunan severity tanpa catatan sulit dipertanggungjawabkan saat review atau audit.
- Menghubungi pihak luar (pelanggan, media, regulator) tanpa melewati IC, komunikasi, dan legal. Rev. 3 menyebut notifikasi ke penegak hukum dan regulator dilakukan oleh orang yang ditunjuk, berdasarkan IR plan dan persetujuan manajemen [S1].

## 6. Catatan terkini

Bagian ini menampung tanggal, edisi, dan status dokumen acuan. Berguna saat mengutip sumber atau menjawab pertanyaan "versi mana yang kamu pakai", tetapi tidak mengubah cara menangani insiden.

- **NIST SP 800-61 Rev. 3** terbit final pada April 2025 (riwayat dokumen di CSRC mencatat 3 April 2025), setelah draf publik pada 3 April 2024. Penulisnya Alex Nelson, Sanjay Rekhi, Murugiah Souppaya, dan Karen Scarfone [S1][S2].
- **NIST SP 800-61 Rev. 2** (Computer Security Incident Handling Guide, Agustus 2012) berstatus withdrawn sejak 3 April 2025 dan digantikan Rev. 3 [S4].
- Change log Rev. 3 mencatat lima perubahan besar: isi ditulis ulang total dan materi usang dibuang; fokus bergeser dari panduan mendeteksi, menganalisis, memprioritaskan, dan menangani insiden ke rekomendasi untuk memasukkan IR ke seluruh manajemen risiko; isi disusun ulang sebagai CSF 2.0 Community Profile; sebagian besar tautan dipindah ke situs proyek SP 800-61; dan format mengikuti template laporan teknis NIST terbaru [S1].
- Karena isi teknis Rev. 2 (daftar periksa, contoh skenario tabletop, tabel kategori dampak) tidak dipindah ke Rev. 3, banyak materi pelatihan masih merujuk Rev. 2. Tabel functional impact, information impact, dan recoverability di bagian 1.7 berasal dari Rev. 2 [S3].
- **NIST CSF 2.0** terbit 26 Februari 2024 sebagai NIST CSWP 29 [S5].
- **SANS Incident Handler's Handbook** (Patrick Kral) diterbitkan SANS pada 21 Februari 2012, jadi lebih dari sepuluh tahun. Enam tahapnya tetap menjadi kosakata umum di lowongan dan diskusi IR [S6][S7].
- **CISA NCISS** dibangun di atas Rev. 2 dan diselaraskan dengan Cyber Incident Severity Schema; halaman CISA yang diperiksa tidak mencantumkan tanggal terbit [S12].
- **UU 27/2022 tentang Pelindungan Data Pribadi** ditetapkan dan diundangkan 17 Oktober 2022. Halaman BPK mencatat Putusan MK Nomor 151/PUU-XXII/2024 yang menyangkut Pasal 53, bukan Pasal 46 [S13].

## 7. Cheat sheet

```
TRIAGE : apakah alert ini benar, apa yang terjadi?
IR     : apa yang kita lakukan sekarang, siapa memutuskan, seberapa parah?

event -> alert -> adverse event -> DECLARE insiden (kriteria tertulis, tercatat)
Insiden = CIA terganggu tanpa wewenang (atau ancaman dekat) ATAU langgar hukum/kebijakan
Declare memicu: IR plan jalan, IC ditunjuk, timeline, bukti dijaga, notifikasi

NIST r2 (2012, withdrawn 3 Apr 2025):  Preparation | Detection & Analysis |
                                       Containment, Eradication & Recovery | Post-Incident
NIST r3 (Apr 2025, CSF 2.0 profile):   Preparation  = Govern, Identify, Protect
                                       Lessons      = Identify > Improvement (ID.IM)
                                       Response     = Detect > Respond > Recover
   DE.CM DE.AE | RS.MA RS.AN RS.CO RS.MI | RC.RP RC.CO
PICERL (SANS): Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned
   tahap tumpang tindih dan berulang

PERAN: IC (koordinasi, keputusan, TIDAK teknis) | technical lead | scribe | NOC/infra
       komunikasi | legal + DPO | executive sponsor | HR | retainer
PT JAB: IC Dimas | L2 Sari, Yoga | NOC Bambang | Comms Maya | Legal Ratna | DPO Agus
        Exec Hendra | retainer PT Forensik Digital Contoh

SEVERITY: dimensi = functional impact | information impact | recoverability (r2)
  SEV-1 layanan luas / data pribadi besar / ransomware menyebar / domain admin
  SEV-2 kompromi terbatas / akun berhak tinggi
  SEV-3 satu endpoint atau akun biasa, tanpa penyebaran
  SEV-4 upaya gagal, tanpa dampak
  Ragu? pilih lebih tinggi, turunkan dengan bukti. Setiap perubahan dicatat + alasan.
  Severity insiden != prioritas alert (P1-P4 dari rule)
UU PDP Pasal 46: pemberitahuan tertulis maks 3 x 24 jam (titik mulai: Day 18 bagian 1.4)
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Bambang dari NOC berkata, "Semua layanan pelanggan normal, jadi enkripsi file di `JKT-FS01` belum bisa disebut insiden." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Definisi insiden di NIST mencakup kejadian yang membahayakan kerahasiaan, integritas, atau ketersediaan informasi tanpa wewenang, termasuk ancaman yang dekat, dan juga pelanggaran hukum atau kebijakan. Tidak perlu ada layanan yang turun. File share yang dienkripsi tanpa wewenang sudah mengganggu integritas dan ketersediaan data, dan insiden keamanan sering sunyi dari sisi layanan. Lihat bagian 1.1.

</details>

**2. Skenario keputusan.** Pukul 22:03, Dimas harus menetapkan severity awal `INC-2026-017`. Sumber enkripsi belum diketahui dan share `Keuangan` mungkin berisi data tagihan pelanggan. Pilihan mana yang paling tepat?

- A. SEV-3, karena baru satu server yang terlihat terdampak.
- B. SEV-1, karena kriteria "ransomware menyebar" belum bisa disingkirkan dan data pribadi mungkin terlibat, lalu severity ditinjau ulang secara berkala.
- C. Belum menetapkan severity sampai scoping selesai, supaya tidak salah.

<details><summary>Jawaban</summary>

B. Di PT JAB, bila ragu antara dua tingkat, pilih yang lebih tinggi lalu turunkan dengan bukti. Severity yang terlalu tinggi hanya membangunkan beberapa orang, sedangkan severity terlalu rendah bisa membuat eksekutif, legal, dan DPO terlambat tahu. A keliru karena "satu server terlihat" bukan berarti hanya satu server terdampak; sumbernya belum diketahui. C keliru karena severity menentukan siapa dipanggil dan ritme update; menunda severity berarti menunda semua itu. Lihat bagian 1.7 dan 1.8.

</details>

**3. Pertanyaan jebakan.** Seorang rekan berkata, "NIST SP 800-61 Rev. 3 sudah menggantikan Rev. 2, jadi siklus empat fase dan PICERL tidak perlu dipelajari lagi." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Rev. 2 memang withdrawn sejak 3 April 2025, tetapi banyak IR plan, lowongan, dan materi masih memakai empat fasenya, dan tabel dimensi dampak yang dipakai luas berasal dari Rev. 2. Rev. 3 sendiri memetakan empat fase lama ke fungsi CSF 2.0 dan menyatakan organisasi boleh memakai model siklus yang paling cocok. PICERL tetap menjadi kosakata umum, dan memisahkan containment, eradication, dan recovery yang di Rev. 2 digabung. Yang perlu dikuasai adalah cara menerjemahkan di antara ketiganya. Lihat bagian 1.3, 1.4, 1.5, dan 6.

</details>

**4. Skenario keputusan.** Pukul 23:00, Dimas (IC) melihat Yoga lambat menelusuri log EDR, sementara Hendra meminta update. Apa yang sebaiknya dilakukan Dimas?

- A. Mengambil alih konsol EDR karena ia lebih senior, lalu memberi update ke Hendra setelah analisis selesai.
- B. Tetap di peran IC: menambah orang untuk analisis (Sari, atau retainer bila perlu), mengirim update fakta yang ada ke Hendra sesuai ritme SEV-1, dan meminta scribe mencatat keputusannya.
- C. Menghentikan update ke Hendra sampai ada temuan baru, supaya tidak mengganggu tim.

<details><summary>Jawaban</summary>

B. IC mengoordinasi dan memutuskan, tidak mengerjakan analisis log; bila analisis lambat, IC menambah sumber daya, bukan mengambil alih keyboard. SEV-1 di PT JAB menuntut update setiap 1 jam, dan update tetap dikirim walau belum ada kemajuan besar. A keliru karena begitu IC sibuk teknis, tidak ada yang memegang keputusan dan komunikasi. C keliru karena melanggar ritme update dan membuat executive sponsor mengambil keputusan tanpa informasi. Lihat bagian 1.6 dan 1.7.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Hendra Wijaya (Direktur Teknologi) dalam tiga kalimat kenapa SOC menyatakan insiden SEV-1 Jumat malam padahal belum pasti ada data pelanggan yang bocor.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Kami menyatakan insiden karena file di server Keuangan dienkripsi tanpa wewenang, dan itu sudah memenuhi definisi insiden walaupun layanan pelanggan normal. Kami memilih SEV-1 karena sumber enkripsi belum diketahui dan share itu mungkin berisi data tagihan pelanggan, dan aturan kami adalah memilih tingkat lebih tinggi saat ragu lalu menurunkannya setelah ada bukti. Dengan menyatakan insiden lebih awal, Bapak, DPO, dan NOC sudah terlibat sebelum batas waktu kewajiban seperti pemberitahuan menurut UU PDP berjalan terlalu jauh, dan severity akan kami tinjau setiap jam."

Kesalahan yang sering muncul:
- Menjelaskan dengan istilah teknis (EDR, SMB, ekstensi file) yang tidak dibutuhkan direktur.
- Menyebut SEV-1 sebagai kepastian bahwa data bocor, padahal itu keputusan karena ketidakpastian.
- Tidak menyebut bahwa severity bisa turun, sehingga terdengar seperti alarm yang tidak bisa dicabut.

</details>

**6. Pertanyaan jebakan.** "Alert `SOC-2026-0187` berprioritas P2 di ticketing, jadi insiden `INC-2026-017` cukup SEV-2." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Prioritas alert (P1-P4) ditentukan rule dan aset untuk mengurutkan antrean, sebelum ada analisis manusia. Severity insiden ditentukan IC dari dimensi dampak (fungsional, informasi, kemampuan pulih) setelah analisis, dan menentukan siapa terlibat serta ritme update. Satu insiden bisa berasal dari banyak alert berprioritas berbeda, dan alert P2 bisa menjadi bagian insiden SEV-1. Lihat bagian 1.8.

</details>

**7. Interview question (English).** "Which incident response lifecycle do you follow: NIST or SANS?"

<details><summary>Sample answer</summary>

"I'm comfortable with both, and I treat them as different vocabularies for the same work. NIST SP 800-61 Revision 2 used four phases, with containment, eradication, and recovery combined into one; SANS PICERL splits those into separate steps, which I find useful because each has its own decision owner and exit criteria. Revision 3, published in April 2025, replaced Revision 2 and reframes incident response as part of cybersecurity risk management using the six CSF 2.0 Functions, with Govern, Identify, and Protect as preparation, Detect, Respond, and Recover as the response itself, and continuous improvement feeding all of them. In practice I follow whatever the organisation's IR plan defines, and I keep in mind that phases overlap: we often contain one host while still scoping for others."

What makes this answer strong: it shows awareness of the current NIST revision and why it changed, maps the frameworks to each other instead of picking a side, and ends with a practical point about overlapping phases.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | NIST SP 800-61 Rev. 3: Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile (PDF) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf | primer | April 2025; diakses 2026-10-14 | Tinggi. Definisi event, adverse event, insiden; Fig. 1, Fig. 2, Table 1; bagian 2.2 dan 2.3; kategori DE, RS, RC; change log |
| S2 | NIST CSRC: SP 800-61 Rev. 3 (halaman publikasi) | https://csrc.nist.gov/pubs/sp/800/61/r3/final | primer | final 2025-04-03; diakses 2026-10-14 | Tinggi untuk tanggal final, draf publik, dan penulis |
| S3 | NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide (PDF) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf | primer | Agustus 2012 (lebih dari 3 tahun, withdrawn); diakses 2026-10-14 | Tinggi untuk siklus empat fase (Figure 3-1), bagian 2.1, 3.2.5, dan 3.2.6 (Table 3-2, 3-3, 3-4) |
| S4 | NIST CSRC: SP 800-61 Rev. 2 (halaman publikasi) | https://csrc.nist.gov/pubs/sp/800/61/r2/final | primer | withdrawn 2025-04-03; diakses 2026-10-14 | Tinggi untuk status withdrawn dan penggantinya |
| S5 | NIST CSRC: The NIST Cybersecurity Framework (CSF) 2.0, CSWP 29 | https://csrc.nist.gov/pubs/cswp/29/the-nist-cybersecurity-framework-csf-20/final | primer | 2024-02-26; diakses 2026-10-14 | Tinggi untuk tanggal terbit dan identitas dokumen |
| S6 | SANS: Incident Handler's Handbook (Patrick Kral) | https://www.sans.org/white-papers/33901 | sekunder | 2012-02-21 (lebih dari 3 tahun); diakses 2026-10-14 | Sedang-tinggi. Halaman abstrak: definisi insiden, cakupan enam tahap, penulis, dan tanggal |
| S7 | Palo Alto Networks Cortex Marketplace: SANS content pack | https://cortex.marketplace.pan.dev/marketplace/details/SANS | sekunder (vendor) | diakses 2026-10-14 | Sedang. Menyebut nama enam tahap SANS secara berurutan |
| S8 | PagerDuty Incident Response Documentation: Different Roles | https://response.pagerduty.com/before/different_roles/ | sekunder (vendor, dokumentasi praktik) | diakses 2026-10-14 | Sedang-tinggi. Definisi IC, deputy, scribe, SME, liaison |
| S9 | PagerDuty Incident Response Documentation: Incident Commander training | https://response.pagerduty.com/training/incident_commander/ | sekunder (vendor, dokumentasi praktik) | diakses 2026-10-14 | Sedang-tinggi. IC tidak mengerjakan remediasi, otoritas IC, serah terima komando |
| S10 | PagerDuty Incident Response Documentation: Scribe training | https://response.pagerduty.com/training/scribe/ | sekunder (vendor, dokumentasi praktik) | diakses 2026-10-14 | Sedang-tinggi. Isi catatan scribe dan awalan TODO |
| S11 | USENIX SREcon18 Americas: Incident Command for IT, What We've Learned from the Fire Department (Brent Chapman) | https://www.usenix.org/conference/srecon18americas/presentation/chapman | sekunder (abstrak konferensi) | 2018 (lebih dari 3 tahun); diakses 2026-10-14 | Sedang. Menyebut Google, Heroku, dan PagerDuty membangun praktik insiden di atas ICS |
| S12 | CISA: National Cyber Incident Scoring System (NCISS) | https://www.cisa.gov/news-events/news/cisa-national-cyber-incident-scoring-system-nciss | primer | tanggal tidak tercantum; diakses 2026-10-14 | Tinggi untuk faktor penilaian dan tingkat prioritas; konteksnya risiko nasional AS |
| S13 | BPK JDIH: UU Nomor 27 Tahun 2022 tentang Pelindungan Data Pribadi | https://peraturan.bpk.go.id/Details/229798/uu-no-27-tahun-2022 | primer (metadata regulasi) | ditetapkan dan diundangkan 2022-10-17; diakses 2026-10-14 | Tinggi untuk identitas dan tanggal UU; teks pasal ada di PDF resmi yang ditautkan halaman ini |
| S14 | Pasal.id: UU 27/2022 Pasal 46 | https://pasal.id/peraturan/uu/uu-no-27-tahun-2022/pasal-46 | sekunder (agregator regulasi) | diakses 2026-10-14 | Sedang. Teks Pasal 46 ayat (1) sampai (3); penjelasan pasal tidak tampil |

**Catatan sumber:** isi tiap tahap PICERL di bagian 1.5 ditulis umum dan selaras dengan NIST, karena rincian per tahap dari teks lengkap SANS Incident Handler's Handbook tidak ikut diperiksa; nama dan urutan enam tahapnya diambil dari halaman SANS dan Cortex Marketplace. Pemetaan PICERL ke kategori CSF 2.0 di tabel bagian 1.5 adalah susunan catatan ini berdasarkan Table 1 dan deskripsi kategori di Rev. 3, bukan tabel resmi NIST. Hubungan IC dengan Incident Command System bersumber dari abstrak konferensi, bukan dari dokumen ICS resmi (FEMA). Teks UU PDP Pasal 46 diambil dari situs agregator; cocokkan dengan PDF resmi di peraturan.bpk.go.id, dan cek penjelasan pasal serta peraturan pelaksana untuk titik mulai hitungan 3 x 24 jam.
