---
day: 11
title: 'Alert dan triage: event, alert, incident, true/false positive, benign positive, severity, priority, eskalasi, tuning, dan alert fatigue'
researched_on: 2026-10-21
versions_checked: 'NIST CSRC Glossary (event, incident, false positive, false negative; diakses 2026-10-21); NIST SP 800-61r3 (Apr 2025); Microsoft Sentinel docs (incident tasks dan false positives, diperbarui 2026-08-08); Microsoft Defender XDR manage incidents (diperbarui 2026-09-23); Microsoft Defender for Identity security alerts (diperbarui 2026-08-08); Splunk Enterprise Security 8.5 docs (glossary, dispositions, suppression); Splunk Enterprise Security 7.2 docs (urgency); SANS 2025 Detection and Response Survey'
---

# Day 11: Alert dan triage (event, alert, incident, true/false positive, benign positive, severity, priority, eskalasi, tuning, dan alert fatigue)

Cakupan: cara memutuskan nasib sebuah alert, yaitu membedakan event, alert, dan incident, memberi klasifikasi hasil (true positive, false positive, benign positive, false negative), membedakan severity dari priority, menjalankan triage yang bisa diulang, menentukan kapan eskalasi, dan merawat deteksi lewat tuning, allowlist, dan suppression supaya tim tidak jatuh ke alert fatigue.

## Ide inti

Day 10 menjelaskan pabrik alert: log masuk ke SIEM, rule berjalan, alert muncul di antrean dan menjadi tiket. Day ini menjelaskan apa yang terjadi di ujung pabrik itu, ketika seorang analyst membuka satu alert dan harus menjawab dua pertanyaan dalam beberapa menit. Pertama, apakah alert ini benar, dan kalau benar, apakah ia berbahaya. Kedua, seberapa cepat dan oleh siapa ia harus ditangani. Seluruh istilah Day ini (true positive, false positive, benign positive, false negative, severity, priority, triage, eskalasi) adalah bahasa untuk menjawab dua pertanyaan itu dengan cara yang sama setiap kali, dan istilah sisanya (tuning, allowlist, suppression, alert fatigue) adalah bahasa untuk memperbaiki pabriknya supaya pertanyaan yang sama tidak harus dijawab ratusan kali.

Gagasan pengikatnya: alert adalah dugaan, bukan fakta. Rule tidak tahu niat orang; ia hanya tahu pola. Karena itu setiap alert punya dua kemungkinan salah. Alarm bisa berbunyi padahal tidak ada apa-apa (false positive), dan yang jauh lebih berbahaya, serangan bisa terjadi tanpa alarm sama sekali (false negative). Di antara keduanya ada wilayah abu-abu yang paling sering ditemui di SOC: alarm yang benar secara teknis, tetapi pelakunya orang yang memang berhak (benign positive). Triage yang baik tidak berhenti di "alert ini benar atau salah", tetapi juga bertanya "apa yang mungkin terjadi tanpa memunculkan alert".

Bayangkan rumah dengan CCTV dan alarm. Setiap orang yang lewat di depan kamera terekam (event). Alarm berbunyi bila sensor mendeteksi sesuatu yang mencurigakan (alert). Pencurian sungguhan yang merugikan pemilik rumah adalah incident. Alarm yang berbunyi karena kucing melompat ke jendela adalah false positive. Maling yang masuk tanpa membuat alarm berbunyi adalah false negative, dan itu yang paling berbahaya karena tidak ada yang tahu. Alarm yang berbunyi karena memang ada orang masuk lewat jendela, tetapi orang itu pemilik rumah yang lupa membawa kunci, adalah benign positive: sensornya benar, kejadiannya nyata, tetapi tidak ada kejahatan. Satpam yang setiap malam mendengar alarm karena kucing lama-lama berhenti menoleh; itulah alert fatigue. Batas analogi ini perlu diingat sejak awal: di jaringan kamu hanya melihat jejak di log, bukan wajah orangnya. "Pemilik rumah yang lupa kunci" harus dibuktikan (tiket perubahan, konfirmasi orangnya), bukan diasumsikan dari nama akun, karena penyerang yang mencuri akun juga memakai nama pemiliknya.

```
  38 juta event dalam satu shift   (semua yang tercatat: login, koneksi, proses, email)
          |   rule dan analitik (Day 10)
          v
  9 alert di antrean               (dugaan yang perlu diperiksa manusia)
          |   triage: konteks -> validasi -> cakupan -> keputusan -> dokumentasi
          v
  klasifikasi tiap alert           true positive | benign positive | false positive | duplikat
          |
          v
  1 incident                       (kejadian yang benar-benar mengancam CIA atau melanggar kebijakan)

  dan yang tidak terlihat di corong ini: false negative (serangan yang tidak pernah menjadi alert)
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP (penyedia layanan internet) fiktif dengan sekitar 1.200 karyawan yang punya SOC (Security Operations Center, tim pemantau keamanan) internal dengan Splunk Enterprise Security sebagai SIEM (sistem pengumpul dan pengolah log, Day 10). Kamu adalah analyst L1 (lapis pertama yang memeriksa alert) yang mulai orientasi Senin 2027-08-02. Senin 2027-08-16, awal minggu ketiga, kamu pertama kali memegang antrean sendiri di shift pagi (07:00 sampai 15:00) bersama Gilang Ramadhan, analyst L1 lain. Mentormu Sari Kusuma (analyst L2) duduk di meja sebelah dan hanya memantau. Pukul 07:05, setelah serah terima dari shift malam, Sari mengirim pesan:

> "Mulai hari ini antrean pagi milikmu dan Gilang; aku di sebelah, tapi anggap aku tidak ada kecuali kalian eskalasi. Semalam Splunk menerima puluhan juta event, antrean kita cuma beberapa alert, dan insiden biasanya nol atau satu; bedakan ketiganya. Setiap tiket yang ditutup wajib diberi kode TP, BP, atau FP, kadang DUP atau UND; jangan tertukar BP dan FP. Yang paling berbahaya justru yang tidak muncul di antrean. Defender menulis 'High', tiket 'P1', insiden 'SEV-3'; jangan campur tiga skala itu. Kerjakan setiap alert dengan urutan yang sama, dan kalau ragu, eskalasi; kapan ke aku dan kapan ke Dimas ada aturannya. Alert pemindai yang berulang setiap Senin jangan cuma ditutup: pikirkan apakah rule-nya perlu disetel, diberi pengecualian, atau dibisukan sementara. Terakhir, kalau sore nanti kalian mulai menutup alert tanpa membaca isinya, berhenti dulu. Itu tanda bahaya, bukan tanda kalian sudah mahir."

Pesan itu memuat sepuluh pertanyaan:

1. Apa beda event, alert, dan incident, dan kenapa puluhan juta event hanya menjadi beberapa alert dan satu insiden?
2. Apa arti true positive dan false positive?
3. Apa itu benign positive, dan kenapa sering tertukar dengan false positive?
4. Kenapa serangan yang tidak memunculkan alert (false negative) paling berbahaya?
5. Bagaimana menilai mutu sebuah rule dengan angka?
6. Kenapa ada tiga skala (severity alat, priority tiket, severity insiden)?
7. Apa urutan triage yang bisa diulang untuk setiap alert?
8. Kapan dan ke siapa eskalasi?
9. Apa arti kode penutupan seperti DUP dan UND, dan apa itu duplikat?
10. Kapan memakai tuning, allowlist, atau suppression, dan kenapa tim bisa jatuh ke alert fatigue?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, pertanyaan 6 di bagian 1.6, pertanyaan 7 di bagian 1.7, pertanyaan 8 di bagian 1.8, pertanyaan 9 di bagian 1.9, dan pertanyaan 10 di bagian 1.10, 1.11, dan 1.12. Bagian 2 mengikuti antrean pagi itu: sembilan alert `SOC-2027-0858` sampai `SOC-2027-0866`, satu yang berujung insiden `INC-2027-090`, dan satu serangan yang berjalan hampir enam jam tanpa alert.

**Kapan relevan:** setiap kali kamu membuka alert di antrean, menutup tiket dan harus memilih kode penutupan, menimbang apakah perlu memanggil L2, membaca laporan bulanan tentang jumlah false positive sebuah rule, mengusulkan perubahan rule, dan saat interview yang menanyakan beda true positive dan benign positive, severity dan priority, atau cara melawan alert fatigue.

**Kapan bukan jawaban:** Day ini tidak mengajarkan cara menulis rule atau query deteksi, dan tidak membahas penanganan insiden sampai tuntas (penahanan, pembersihan, pemulihan, pelajaran) yang dibahas di Day 19. Indikator seperti IP dan hash dibahas di Day 12, dan mencari ancaman tanpa menunggu alert (threat hunting) dibahas di Day 13.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (log, SIEM, correlation rule, use case, ticketing, SLA, tier L1/L2/L3, EDR) dipakai tanpa diulang panjang; definisi satu kalimatnya muncul di subbagian yang memakainya. Tabel ini memuat istilah yang dipakai untuk memilah dan merawat alert; cari kolom ketiga bila sebuah istilah terasa abstrak.

| Istilah | Arti singkat | Padanan sehari-hari |
|---|---|---|
| Event | Kejadian apa pun yang bisa diamati di sistem atau jaringan | Setiap orang yang lewat terekam CCTV |
| Adverse event | Event yang membawa akibat negatif, apa pun penyebabnya | Rekaman orang mencoba membuka pintu |
| Alert | Pemberitahuan dari alat atau rule bahwa satu atau beberapa event perlu diperiksa | Alarm berbunyi |
| Incident | Kejadian yang benar-benar atau hampir pasti mengancam CIA, atau melanggar hukum atau kebijakan | Benar ada pencurian |
| Notable event / finding | Nama alert di Splunk Enterprise Security: notable event (ES 7 dan sebelumnya), finding (ES 8) | Catatan alarm di buku jaga |
| True positive (TP) | Alert berbunyi dan memang ada aktivitas jahat | Alarm berbunyi karena maling |
| False positive (FP) | Alert berbunyi, tetapi aktivitas yang dituduhkan tidak ada atau salah dibaca | Alarm berbunyi karena kucing |
| Benign positive (BP) | Alert benar mendeteksi aktivitas nyata, tetapi aktivitas itu sah dan diharapkan; disebut juga benign true positive | Pemilik rumah masuk lewat jendela karena lupa kunci |
| False negative (FN) | Aktivitas jahat terjadi, tetapi tidak ada alert | Maling masuk, alarm diam |
| True negative (TN) | Aktivitas normal, dan memang tidak ada alert | Tetangga lewat, alarm diam |
| Confusion matrix | Tabel empat kotak yang menghitung TP, FP, FN, dan TN | Rekap bulanan alarm satpam |
| Precision | Dari semua alert, berapa persen yang benar | Dari semua alarm yang berbunyi, berapa yang benar ada maling |
| Severity | Seberapa parah sesuatu bila benar terjadi | Seberapa besar kebakarannya |
| Priority | Urutan dan kecepatan penanganan, dari severity digabung konteks | Kebakaran mana yang dipadamkan dulu |
| Triage | Pemeriksaan awal untuk memilah alert: benar atau tidak, penting atau tidak, ditangani siapa | Petugas IGD memilah pasien |
| Eskalasi | Menaikkan kasus ke orang atau tim dengan wewenang atau keahlian lebih | Satpam memanggil kepala regu |
| Elevasi | Melibatkan manajemen yang lebih tinggi | Kepala regu melapor ke pengelola gedung |
| Disposisi / closure code | Kode yang menyatakan hasil akhir sebuah alert saat ditutup | Kolom "hasil pemeriksaan" di buku jaga |
| Duplikat (dedup) | Alert kedua untuk kejadian yang sama, digabung ke tiket pertama | Dua satpam melaporkan kebakaran yang sama |
| Tuning | Menyetel logika, ambang, atau cakupan rule supaya lebih akurat | Mengatur sensitivitas alarm |
| Allowlist | Daftar entitas yang sudah diketahui sah dan dikecualikan dari rule tertentu | Daftar penghuni yang boleh lewat pintu samping |
| Suppression | Menyembunyikan alert yang cocok dengan kondisi tertentu, biasanya untuk sementara | Mematikan alarm ruang yang sedang direnovasi |
| Throttling | Menahan rule supaya tidak membuat alert baru untuk hal yang sama dalam rentang waktu tertentu | Alarm hanya berbunyi sekali per jam untuk pintu yang sama |
| Alert fatigue | Kelelahan dan kebal terhadap alert karena terlalu banyak alert yang tidak berarti | Satpam yang terbiasa mengabaikan alarm karena terlalu sering salah |

### 1.1 Event, alert, dan incident

Pertanyaan pertama Sari berangkat dari angka di layar serah terima: semalam sampai pagi Splunk menerima puluhan juta catatan, antrean pagi berisi beberapa alert, dan di akhir shift hanya ada satu insiden. Ketiga kata itu sering dipakai bergantian dalam percakapan, padahal di SOC artinya berbeda dan konsekuensinya juga berbeda.

**Apa itu:**
- **Event** adalah kejadian apa pun yang bisa diamati. NIST SP 800-61r3 mendefinisikannya sebagai kejadian teramati yang melibatkan aset komputasi, termasuk platform fisik dan virtual, jaringan, layanan, dan cloud, dengan contoh percobaan login, pemasangan update, dan aplikasi yang menjawab permintaan [S1][S2]. Event tidak berarti buruk; hampir semua event adalah aktivitas normal.
- **Adverse event** adalah event yang membawa akibat negatif, apa pun penyebabnya, termasuk bencana alam, listrik padam, atau serangan [S2]. NIST menambahkan bahwa analisis lanjutan sering dibutuhkan untuk memastikan apakah adverse event menandakan insiden [S2].
- **Alert** adalah pemberitahuan bahwa satu atau beberapa event perlu diperiksa manusia. Alert dihasilkan oleh alat (EDR, IDS, filter email) atau oleh rule di SIEM. NIST SP 800-61r3 merekomendasikan agar alert dibuat dan disalurkan ke alat dan staf yang berwenang, misalnya SOC [S2]. Alert adalah dugaan, bukan keputusan.
- **Incident** (cybersecurity incident) adalah kejadian yang benar-benar atau hampir pasti membahayakan, tanpa wewenang yang sah, integritas, kerahasiaan, atau ketersediaan informasi atau sistem; atau yang merupakan pelanggaran, atau ancaman pelanggaran yang segera, terhadap hukum, kebijakan keamanan, prosedur keamanan, atau kebijakan pemakaian yang wajar [S1][S2]. Definisi ini berasal dari undang-undang FISMA Amerika Serikat dan dipakai ulang di SP 800-61r3 [S1]. Sebuah insiden dinyatakan (declared) ketika adverse event memenuhi kriteria insiden yang sudah ditetapkan organisasi [S2].

**Analogi:** CCTV rumah merekam setiap orang yang lewat (event). Rekaman orang yang mencoba membuka pagar adalah adverse event. Alarm yang berbunyi karena sensor jendela terpicu adalah alert. Pencurian yang benar terjadi adalah incident. Batasnya: di rumah, pencurian biasanya jelas begitu terjadi. Di jaringan, insiden sering baru terlihat setelah beberapa alert digabung dan diperiksa, dan sebagian insiden sama sekali tidak diawali alert (bagian 1.4).

**Cara kerja:** corong di Ide inti berlaku di hampir semua SOC. NIST mencatat volume event yang harus dianalisis biasanya sangat besar, sehingga organisasi perlu solusi teknis yang menyaring kumpulan event besar menjadi bagian kecil yang layak dilihat manusia [S2]. Saringannya tiga: rule dan analitik di SIEM (Day 10 bagian 1.5 dan 1.7), triage oleh analyst (bagian 1.7), lalu keputusan menyatakan insiden oleh L2 atau SOC lead dengan kriteria tertulis.

**Contoh di PT JAB:** shift pagi Senin 2027-08-16 menerima sekitar 38 juta event di Splunk (login, koneksi firewall, query DNS, proses di laptop, email). Rule memunculkan 9 alert, `SOC-2027-0858` sampai `SOC-2027-0866`. Dari sembilan itu, tiga alert yang sebenarnya satu cerita digabung menjadi satu insiden, `INC-2027-090`. Rinciannya ada di bagian 2.1.

**Beda nama di produk:** setiap produk memakai kata sendiri, dan ini sumber kebingungan yang nyata.
- Di Splunk Enterprise Security 8, alert di antrean analyst disebut finding; versi lama menyebutnya notable event atau risk notable [S7]. Glosarium ES 8 mendefinisikan finding sebagai satu atau lebih kejadian atau alert anomali yang dihasilkan detection berbasis event, lengkap dengan timestamp, entitas, teknik MITRE, dan skor risiko [S7]. Ada juga intermediate finding, catatan anomali yang tidak tampil di antrean analyst tetapi dipakai sebagai bahan detection lain [S7].
- Di Microsoft Sentinel dan Defender XDR, incident adalah wadah yang mengumpulkan alert dan bukti terkait [S3][S5], dan belum tentu insiden menurut definisi NIST; banyak yang ditutup sebagai false positive atau aktivitas yang diharapkan [S5].

**Salah paham umum:**
- "Setiap alert adalah insiden kecil." Alert adalah pertanyaan, insiden adalah jawaban yang sudah diperiksa. Menyebut setiap alert "insiden" membuat laporan bulanan tidak bermakna dan membuat pihak lain panik tanpa alasan.

### 1.2 True positive dan false positive

Pertanyaan kedua Sari menyangkut kode penutupan. Di PT JAB, tiket tidak bisa ditutup sebelum kolom disposisi diisi. Dua kode yang paling dasar adalah TP dan FP, dan maknanya datang dari dua pertanyaan yang dijawab berurutan: apakah alert berbunyi (positive), dan apakah bunyinya benar (true) atau keliru (false).

**Apa itu:**
- **True positive** adalah alert yang menunjuk ancaman nyata. Microsoft Defender XDR meminta klasifikasi ini dipakai untuk insiden yang secara akurat menunjukkan ancaman nyata, disertai jenis ancamannya [S5]. Splunk ES 8 menamainya "True Positive - Suspicious Activity", yaitu finding yang menunjukkan aktivitas ancaman [S8].
- **False positive** adalah alert yang keliru: aktivitas wajar salah diklasifikasikan sebagai jahat [S1]. Glosarium NIST memuat beberapa rumusan, misalnya alat keamanan yang salah menggolongkan konten jinak sebagai berbahaya, atau alert yang salah menyatakan sebuah kerentanan ada [S1].

Sumber produk membagi false positive menurut penyebabnya, dan pembagian ini berguna karena menentukan perbaikannya [S3][S8]:
- **FP karena logika salah (incorrect alert logic):** rule-nya yang keliru. Data benar, tetapi cara rule membacanya salah.
- **FP karena data salah (incorrect/inaccurate data):** rule-nya benar, tetapi data yang dibaca keliru, misalnya lokasi IP yang salah di database geolokasi, atau field yang salah di-parsing (Day 10 bagian 1.4).

**Analogi:** alarm berbunyi karena maling adalah true positive. Alarm berbunyi karena kucing adalah false positive. Batasnya: di rumah, penyebab salah bunyi biasanya satu (sensor terlalu peka). Di SOC, penyebabnya bisa di rule, di data, atau di cara sumber log mencatat, dan masing-masing butuh perbaikan berbeda.

**Cara kerja:** tanyakan dua hal berurutan.

```
  1. Apakah hal yang dituduhkan alert benar-benar terjadi seperti yang tertulis?
       tidak  -> FALSE POSITIVE   (cek: logika rule salah, atau data salah?)
       ya     -> lanjut ke 2
  2. Apakah aktivitas itu jahat atau tidak diizinkan?
       ya     -> TRUE POSITIVE    (ancaman nyata; berhasil atau tidak, itu soal dampak)
       tidak  -> BENIGN POSITIVE  (nyata, tetapi sah dan diharapkan; bagian 1.3)
```

Perhatikan bahwa true positive tidak sama dengan "serangan berhasil". Percobaan login yang gagal semua tetap true positive bila memang ada pihak yang mencoba masuk tanpa hak. Keberhasilan dan dampaknya dicatat terpisah, dan menentukan apakah alert dinaikkan menjadi insiden.

**Contoh di PT JAB:** pagi itu ada dua false positive dengan penyebab berbeda (bagian 2.1). `SOC-2027-0860` adalah "perjalanan mustahil" (login dari Jakarta lalu dari Belanda dalam 7 menit) yang ternyata disebabkan database geolokasi yang masih mencatat alamat publik baru kantor Bandung `198.51.100.82` sebagai milik pemilik lamanya di Belanda: FP karena data. `SOC-2027-0861` adalah alert "kemungkinan pengiriman data keluar besar" yang ternyata rule-nya menjumlahkan byte masuk dan byte keluar, sehingga unduhan video 3,8 GB terbaca sebagai unggahan: FP karena logika. Sementara itu `SOC-2027-0862`, percobaan login VPN ke 146 akun dari `192.0.2.183` yang semuanya gagal, adalah true positive tanpa dampak.

**Salah paham umum:**
- "False positive berarti alatnya rusak." Tidak ada alat deteksi tanpa false positive. NIST sendiri menyarankan monitoring disetel supaya false positive dan false negative turun ke tingkat yang bisa diterima, bukan ke nol [S2].

### 1.3 Benign positive

Pertanyaan ketiga Sari adalah sumber perdebatan paling sering di SOC. Pagi itu antrean dibuka dengan `SOC-2027-0858`: pemindaian port dari satu alamat ke ribuan alamat internal. Rule-nya benar, pemindaiannya nyata, tetapi pelakunya `jkt-vscan01`, mesin pemindai kerentanan milik tim Agung Prabowo, yang selain pemindaian bulanan juga memindai subnet kantor setiap Senin dini hari.

**Apa itu:** benign positive adalah alert yang mendeteksi aktivitas nyata dengan benar, tetapi aktivitas itu sah dan diharapkan, sehingga tidak perlu ditindak sebagai ancaman. Microsoft Sentinel dan Splunk ES 8 menyebutnya benign positive, "suspicious but expected": awalnya mencurigakan, lalu digolongkan tidak berbahaya dan memang diharapkan [S3][S8]. Microsoft Defender for Identity memakai nama benign true positive (B-TP), dengan contoh uji penetrasi atau aktivitas aplikasi yang sudah disetujui [S6], dan Defender XDR memakai label "Informational, expected activity" untuk uji keamanan, red team, dan perilaku tidak biasa yang diharapkan dari aplikasi atau user tepercaya [S5].

**Analogi:** alarm berbunyi karena sensor jendela mendeteksi orang masuk, dan memang ada orang masuk. Orang itu pemilik rumah yang lupa membawa kunci. Sensornya bekerja sempurna; tidak ada pencurian. Batasnya: di rumah kamu mengenali wajah pemiliknya. Di SOC, "pemiliknya" hanya terlihat sebagai nama akun atau alamat IP, dan penyerang yang mencuri akun admin juga muncul dengan nama admin. Benign positive harus dibuktikan dengan sesuatu di luar alert itu sendiri: tiket perubahan, jadwal resmi, atau konfirmasi langsung ke orangnya lewat saluran lain.

**Cara kerja:** benign positive punya tiga ciri yang harus dicek semuanya.

1. **Kejadiannya nyata.** Data dan logika rule benar (kalau tidak, itu false positive).
2. **Pelakunya sah.** Akun atau mesinnya memang milik pihak yang berhak.
3. **Aktivitasnya diharapkan.** Ada bukti di luar alert: jadwal, tiket perubahan, atau konfirmasi pemilik.

Bila ciri 2 benar tetapi ciri 3 tidak (orang yang berhak melakukan hal di luar prosedur), PT JAB tidak menyebutnya benign positive, melainkan true positive pelanggaran kebijakan (bagian 1.9). Contohnya `SOC-2027-0838` di Day 07: admin yang sah menambahkan akun layanan ke Domain Admins tanpa change request.

**Contoh di PT JAB:** tiga alert pagi itu ditutup sebagai benign positive. `SOC-2027-0858` (pemindaian `jkt-vscan01` yang molor sampai 06:35 karena subnet baru ditambahkan ke jadwal), `SOC-2027-0859` (skrip PowerShell inventaris lisensi yang dijalankan `adm.bayu` dari tim IT Support dengan tiket `CHG-2027-0428`), dan `SOC-2027-0865` (alat admin dan service baru di server `jkt-intranet02` yang sedang dibangun ulang dalam jendela perubahan `CHG-2027-0431`). Dari minggu lalu, `SOC-2027-0855` di Day 10 (unduhan arsip Ratna untuk auditor, dikonfirmasi atasannya) dan `SOC-2027-0837` di Day 06 (perubahan konfigurasi RADIUS yang cocok dengan tiket) juga termasuk benign positive.

**Beda dengan false positive:** di false positive, yang dituduhkan alert tidak terjadi atau salah dibaca, jadi perbaikannya ada di rule atau di data. Di benign positive, yang dituduhkan benar-benar terjadi, jadi rule-nya tidak salah; yang perlu dipikirkan adalah apakah aktivitas sah itu perlu dikecualikan (allowlist), dibisukan sementara (suppression), atau dibiarkan tetap memunculkan alert karena terlalu berisiko untuk dikecualikan (bagian 1.11).

Penelitian terhadap analyst SOC di Universitas Oxford (USENIX Security 2022) menemukan bahwa sebagian besar alert yang oleh praktisi disebut "false positive" sebenarnya dipicu aktivitas sah di lingkungan organisasi, yaitu alarm yang benar tetapi tidak jahat, dan para peneliti meminta vendor serta peneliti membedakan jenis-jenis false positive itu saat menilai alat [S11]. Menggabungkan BP ke FP membuat rule yang bekerja benar terlihat buruk, dan mendorong orang mematikan rule yang sebenarnya berguna.

**Salah paham umum:**
- "Akunnya admin, jadi pasti benign." Nama akun bukan bukti. Bukti benign positive datang dari luar alert: tiket, jadwal, atau konfirmasi orangnya lewat telepon kantor.

### 1.4 False negative dan true negative

Pertanyaan keempat Sari ("yang paling berbahaya justru yang tidak muncul di antrean") baru terasa maknanya pukul 13:52. Alert pemindaian port dari laptop `JKT-WS-1117` milik Fitri Rahmawati (staf Keuangan) membuka fakta bahwa laptop itu sudah dikendalikan penyerang sejak 08:06, hampir enam jam, tanpa satu alert pun.

**Apa itu:**
- **False negative** adalah aktivitas jahat yang salah digolongkan sebagai jinak, atau alat deteksi yang gagal mendeteksi ancaman yang seharusnya ia tangkap [S1]. Di SOC, wujudnya sederhana: serangan terjadi, antrean tetap kosong.
- **True negative** adalah aktivitas normal yang memang tidak memunculkan alert. Ini kotak paling besar dan paling jarang dibicarakan.

**Analogi:** maling masuk dan alarm diam. Tidak ada yang menelepon polisi, tidak ada rekaman yang diperiksa, dan pemilik rumah baru tahu ketika barangnya sudah hilang. Batasnya: di rumah, kehilangan biasanya ketahuan cepat. Di jaringan, penyerang bisa tinggal berminggu-minggu tanpa ada yang "hilang" secara kasat mata, sehingga false negative bisa bertahan sangat lama.

**Cara kerja:** false negative muncul dari beberapa sebab yang berbeda, dan masing-masing ditutup dengan cara berbeda.

| Sebab | Contoh | Cara menutup |
|---|---|---|
| Tidak ada rule untuk teknik itu | Penyerang memakai program bawaan Windows yang bertanda tangan, rule hanya mencari program tidak dikenal | Tambah use case (Day 10 bagian 1.6) |
| Rule ada, ambang terlalu tinggi | Pemindaian pelan satu port per 10 detik tidak melewati ambang "100 dalam 5 menit" | Tuning, tambah rule pendamping |
| Log tidak masuk | Sumber log diam (Day 10 bagian 1.5) | Pantau kesehatan sumber |
| Data salah | Field user salah di-parsing sehingga rule tidak pernah cocok | Perbaiki parsing dan normalisasi |
| Terlalu banyak pengecualian | Allowlist terlalu luas, suppression lupa diakhiri | Tinjau berkala, beri masa berlaku |

Karena false negative tidak menghasilkan tiket, ia hanya bisa ditemukan dengan cara di luar antrean: saat menelusuri cakupan sebuah alert lain (seperti pagi itu), saat menguji rule dengan simulasi, atau saat threat hunting (Day 13).

**Contoh di PT JAB:** email "Konfirmasi remitansi pembayaran Agustus" dengan lampiran image disk `Remitansi_Agustus.iso` dikirim ke tiga staf Keuangan pukul 07:41. Filter email meloloskannya; itu false negative pertama. Fitri membukanya pukul 08:05, dan program pemuat di dalamnya memakai cara yang tidak dikenali EDR, sehingga laptopnya mulai menghubungi `192.0.2.187` setiap sekitar 60 detik sejak 08:06 tanpa alert; itu false negative kedua. Yusuf Hidayat membuka email yang sama pukul 09:08, dan di laptopnya EDR berbunyi (`SOC-2027-0863`). Saat menelusuri cakupan pukul 09:40, tim memeriksa alert EDR di laptop dua penerima lain dan tidak menemukan apa-apa, lalu menyimpulkan keduanya tidak membuka lampiran. Kesimpulan "tidak ada alert berarti tidak terjadi apa-apa" itulah yang keliru. Penelusuran lengkapnya ada di bagian 2.3.

**Beda dengan false positive:** false positive membuang waktu; false negative membuang kesempatan. Biaya false positive terlihat setiap hari di antrean. Biaya false negative tidak terlihat sampai terlambat, dan karena itu sering diremehkan.

**Salah paham umum:**
- "Antrean kosong berarti aman." Antrean kosong bisa berarti tidak ada serangan, atau berarti serangan memakai cara yang tidak punya rule, sumber log diam, atau pengecualian terlalu luas. Kalimat yang tepat adalah "tidak ada yang terdeteksi".

### 1.5 Confusion matrix dan precision

Pertanyaan kelima Sari berasal dari rapat bulanan. Dimas Prasetyo (SOC lead) ingin tahu rule mana yang paling "berisik" dan mana yang paling berguna. Untuk itu hasil setiap alert dihitung dengan satu tabel sederhana.

**Apa itu:** confusion matrix adalah tabel empat kotak yang membandingkan kenyataan (jahat atau tidak) dengan keputusan alat (alert atau tidak). Istilah ini berasal dari dunia klasifikasi dan machine learning: TP adalah positif yang diprediksi positif, TN negatif yang diprediksi negatif, FP negatif yang diprediksi positif (alarm palsu), dan FN positif yang diprediksi negatif (terlewat) [S13]. Dari tabel itu lahir dua ukuran yang paling berguna di SOC [S13]:
- **Precision** = TP / (TP + FP): dari semua alert, berapa yang benar.
- **Recall** (true positive rate, disebut juga probability of detection) = TP / (TP + FN): dari semua aktivitas jahat, berapa yang tertangkap.

**Analogi:** rekap bulanan satpam. Precision menjawab "dari 50 kali alarm berbunyi, berapa kali memang ada maling". Recall menjawab "dari semua maling yang datang bulan ini, berapa yang membuat alarm berbunyi". Batasnya: satpam tidak tahu jumlah maling yang tidak ketahuan, jadi recall hampir tidak pernah bisa dihitung dengan pasti. Yang bisa dihitung hanya recall dari uji coba (maling bohongan yang sengaja dikirim).

**Cara kerja:**

```
                        alert berbunyi            tidak ada alert
  aktivitas jahat       TP  (tertangkap)           FN  (terlewat, tidak terlihat di antrean)
  aktivitas normal      FP  (alarm palsu)          TN  (normal, sangat banyak, tidak dihitung)

  precision = TP / (TP + FP)      bisa dihitung dari tiket yang ditutup
  recall    = TP / (TP + FN)      butuh FN; hanya diketahui dari uji simulasi, hunting, atau insiden
```

Dua catatan penting untuk SOC:

- **Akurasi menyesatkan.** Akurasi = (TP + TN) / semua. Karena TN jumlahnya jutaan, akurasi hampir selalu mendekati 100%. Materi Google tentang metrik klasifikasi memberi contoh: bila hanya 1% data yang positif, model yang selalu menjawab "negatif" tetap mendapat akurasi 99% padahal tidak berguna [S13]. Di SOC, aktivitas jahat jauh lebih jarang dari 1%.
- **Benign positive harus diputuskan masuk kotak mana.** Dari sudut pandang "apakah rule bekerja benar", BP dihitung bersama TP. Dari sudut pandang "apakah alert ini butuh tindakan", BP dihitung bersama FP. Laporan yang jujur menampilkan keduanya.

**Contoh di PT JAB:** rekap Juli 2027 use case UC-034 "Port scan internal" (rule: satu host internal mencoba lebih dari 100 kombinasi IP dan port dalam 5 menit, Day 10 bagian 1.5) dan rekap sembilan alert pagi ini dibahas di bagian 2.4.

**Salah paham umum:**
- "Rule dengan false positive nol adalah rule terbaik." Rule bisa dibuat nol false positive dengan menaikkan ambang setinggi mungkin, dan sekaligus menjadi buta. Menurunkan false positive biasanya menaikkan risiko false negative; tuning mencari titik tengah yang bisa diterima [S2].

### 1.6 Severity vs priority

Pertanyaan keenam Sari: di alert `SOC-2027-0863`, Defender menulis "High", tiketnya menulis "P1", dan insiden yang dibuka menulis "SEV-3". Tiga label untuk satu kejadian, masing-masing menjawab pertanyaan yang berbeda.

**Apa itu:**
- **Severity** adalah seberapa parah sesuatu bila benar terjadi. Severity alat diberikan produk atau rule berdasarkan jenis kejadian; Defender for Identity, misalnya, memperhitungkan seberapa jauh akses penyerang, dampak bila berhasil, dan kemungkinan alert itu true positive [S6]. Defender XDR memakai skala high, medium, low, dan informational, dan severity sebuah incident di Defender diambil dari alert tertinggi di dalamnya [S5].
- **Priority** adalah urutan dan kecepatan penanganan. Priority menggabungkan severity dengan konteks: seberapa penting aset atau orang yang terkena, dan seberapa mendesak waktunya. Kerangka layanan TI yang umum (ITIL) menghitung priority dari dampak (seberapa luas) dan urgensi (seberapa mendesak) [S14]. Splunk ES menghitung urgency sebuah notable event dari severity yang ditetapkan rule dan priority aset atau identitas yang terlibat; bila aset dan identitas sama-sama punya priority, yang lebih tinggi dipakai [S10].
- **Severity insiden** adalah penilaian dampak insiden secara keseluruhan setelah diperiksa, dipakai untuk menentukan siapa dilibatkan dan seberapa sering manajemen diberi kabar.

NIST SP 800-61r3 menekankan bahwa insiden tidak ditangani berdasarkan siapa datang duluan, dan bahwa triage, prioritas, eskalasi, dan elevasi harus berdasarkan faktor evaluasi risiko, misalnya kritikalitas aset, dampak fungsional, dampak data, tahap aktivitas yang teramati, karakter pelaku, dan kemampuan pulih [S2].

**Analogi:** severity adalah seberapa besar kebakarannya; priority adalah kebakaran mana yang dipadamkan dulu. Api kecil di ruang server yang menyimpan data pelanggan bisa didahulukan dari api sedang di gudang kardus bekas. Batasnya: kebakaran kelihatan sejak awal, sedangkan severity alert digital sering baru bisa dinilai setelah triage, dan priority bisa naik atau turun ketika konteks baru ditemukan.

**Cara kerja:** PT JAB memakai tiga skala yang sengaja dipisah.

| Skala | Siapa yang menentukan | Nilai | Dipakai untuk |
|---|---|---|---|
| Severity alat atau rule | Produk (Defender, Wazuh, IDS) atau penulis rule | Informational, Low, Medium, High (kadang Critical) | Bahan awal priority |
| Priority alert | Otomatis dari matriks, bisa diubah analyst setelah triage | P1 sampai P4 | Urutan antrean dan SLA (Day 10 bagian 1.12) |
| Severity insiden | L2 atau SOC lead saat menyatakan insiden | SEV-1 sampai SEV-4 | Siapa dilibatkan, frekuensi laporan ke manajemen |

Priority awal dihitung otomatis dari matriks berikut; cari baris severity alat lalu kolom kelas aset.

| Severity alat | Aset kritis | Aset standar | Aset rendah |
|---|---|---|---|
| High / Critical | P1 | P2 | P3 |
| Medium | P2 | P3 | P4 |
| Low | P3 | P4 | P4 |
| Informational | P4 | P4 | P4 |

Aset kritis di PT JAB antara lain domain controller, server pembayaran dan billing, gateway VPN, akun admin, dan laptop staf pemberi persetujuan pembayaran; aset rendah antara lain mesin lab dan jaringan tamu. Severity insiden: SEV-1 layanan inti pelanggan lumpuh, kebocoran data pelanggan massal, atau domain dikuasai; SEV-2 penyerang aktif di lebih dari satu sistem internal atau layanan penting terganggu sebagian; SEV-3 terbatas pada satu host atau satu akun yang bisa ditahan SOC; SEV-4 dampak minimal.

**Contoh di PT JAB:** `SOC-2027-0863` diberi High oleh Defender. Laptop `JKT-WS-1118` milik Yusuf Hidayat masuk kelas aset kritis karena Yusuf berwenang menyetujui pembayaran vendor, jadi matriks memberi P1. Insiden `INC-2027-090` dibuka pukul 09:30 dengan SEV-3 (satu laptop, sudah diisolasi), lalu dinaikkan ke SEV-2 pukul 14:05 setelah laptop kedua ditemukan memindai server (bagian 2.3). Sebaliknya, `SOC-2027-0866` (pemindaian port dari laptop Fitri) mendapat P3 dari matriks (Medium, aset standar), tetapi kamu menaikkannya secara manual begitu terlihat terkait insiden yang sedang berjalan.

**Beda severity dengan priority:** severity melekat pada jenis kejadian dan relatif tetap; priority melekat pada situasi dan boleh berubah. Dua alert dengan severity sama bisa punya priority berbeda karena asetnya berbeda.

**Salah paham umum:**
- "Severity Low berarti boleh diabaikan." Low di aset kritis, atau Low yang berulang dari banyak host sekaligus, bisa lebih penting dari High di mesin lab.

### 1.7 Triage

Pertanyaan ketujuh Sari ("kerjakan setiap alert dengan urutan yang sama, jangan loncat") adalah inti pekerjaan L1. Sembilan alert pagi itu berbeda jenis, tetapi semuanya diperiksa dengan lima langkah yang sama.

**Apa itu:** triage adalah pemeriksaan awal yang cepat untuk memutuskan apakah alert benar, seberapa penting, dan siapa yang harus menanganinya. NIST SP 800-61r3 merumuskannya sebagai tinjauan awal atas laporan insiden baru untuk memastikan insiden memang terjadi, lalu memperkirakan severity dan tingkat urgensi respons [S2]. Saat menyatakan insiden, NIST juga meminta kriteria insiden diterapkan pada ciri aktivitas yang diketahui maupun yang diduga, dengan mempertimbangkan false positive yang sudah dikenal [S2].

**Analogi:** petugas IGD rumah sakit. Ia tidak mengobati semua pasien sampai sembuh; ia memeriksa tanda vital, menanyakan keluhan, lalu memutuskan pasien ini pulang, dirawat biasa, atau langsung ke ruang tindakan. Batasnya: di IGD pasien datang sendiri dan mengeluh. Di SOC, "pasien" yang paling parah (false negative) tidak pernah datang ke meja triage; karena itu langkah cakupan harus aktif mencari yang tidak datang.

**Cara kerja:** lima langkah triage PT JAB, berlaku untuk alert apa pun.

```
 1. KONTEKS      Apa yang dideteksi rule ini dan kenapa? Siapa user dan host-nya, seberapa penting?
                 Riwayat: alert serupa sebelumnya, tiket perubahan, jadwal, catatan serah terima.
 2. VALIDASI     Apakah kejadiannya benar terjadi seperti tertulis? Buka log mentahnya.
                 Apakah datanya benar (jam, user, IP, lokasi)? Di sini FP tersaring.
 3. CAKUPAN      Sebelum dan sesudah: apa yang dilakukan user/host/IP ini 24 jam terakhir?
                 Ke samping: siapa lagi yang terkena ciri yang sama (penerima email, IP, hash, pola)?
                 Cari dengan beberapa ciri; jangan hanya mencari alert lain.
 4. KEPUTUSAN    Klasifikasi (TP / BP / FP / DUP / UND), priority (ubah bila konteks menuntut),
                 tutup atau eskalasi (bagian 1.8). Tindakan cepat yang diizinkan runbook.
 5. DOKUMENTASI  Tulis di tiket: apa yang dicek, hasilnya, bukti, keputusan, dan alasannya.
                 Orang lain harus bisa sampai ke keputusan yang sama hanya dari catatanmu.
```

Catatan per langkah. Konteks sering sudah disiapkan enrichment otomatis (Day 10 bagian 1.8); Microsoft Sentinel juga menampilkan "top insights" untuk entitas sebuah incident supaya prioritas dan cakupan cepat dinilai [S3]. Validasi berarti membuka bukti, bukan membaca judul; Defender for Identity menyarankan bertanya apakah alert ini TP, B-TP, atau FP, seberapa umum alert ini di lingkungan kita, dan apakah dipicu jenis komputer atau user yang sama [S6]. Cakupan adalah langkah yang paling sering dipotong saat antrean penuh dan paling sering menjadi sumber kesalahan besar; NIST meminta dampak dan cakupan diperkirakan lalu terus diperbarui [S2]. Dokumentasi mengikuti field tiket di Day 10 bagian 1.11, dan Microsoft meminta alasan tertulis saat incident diselesaikan atau ditutup [S3][S5].

**Contoh di PT JAB:** lima langkah untuk `SOC-2027-0863` dijalankan lengkap dengan jam di bagian 2.2. Untuk alert sederhana seperti `SOC-2027-0858`, kelima langkah selesai dalam sepuluh menit: konteks (sumbernya `jkt-vscan01`), validasi (log firewall internal menunjukkan pola pemindaian kerentanan dari jadwal yang dikenal, bukan eksploitasi), cakupan (tidak ada sumber lain yang memindai pada jam itu), keputusan (BP, ditutup), dokumentasi (termasuk catatan bahwa jadwal pemindaian molor).

**Beda triage dengan investigasi:** triage menjawab "apa ini dan siapa yang menangani" dalam hitungan menit. Investigasi menjawab "apa saja yang terjadi, bagaimana, dan sejauh mana" dan bisa berlangsung berhari-hari. Triage yang baik menghasilkan bahan awal investigasi, bukan menggantikannya.

**Salah paham umum:**
- "Triage cepat berarti melewati langkah." Triage cepat berarti setiap langkah dikerjakan secukupnya. Melewati langkah cakupan menghemat lima menit dan bisa menyembunyikan laptop kedua selama berjam-jam (bagian 2.3).

### 1.8 Eskalasi

Pertanyaan kedelapan Sari: kapan ke L2, kapan ke SOC lead. Pukul 09:21 kamu mengeskalasi `SOC-2027-0863` ke Sari. Pukul 14:15 Dimas menelepon Hendra Wijaya (Direktur Teknologi). Keduanya "naik", tetapi naiknya berbeda.

**Apa itu:** NIST SP 800-61r3 membedakan dua hal [S2]:
- **Eskalasi** umumnya berarti menambah sumber daya atau waktu untuk menangani kasus, misalnya menyerahkannya ke analyst yang lebih berpengalaman atau tim yang punya wewenang teknis.
- **Elevasi** biasanya berarti melibatkan tingkat manajemen yang lebih tinggi dalam respons.

Di lapangan, keduanya sering sama-sama disebut "eskalasi", dengan pembeda eskalasi fungsional (ke keahlian atau wewenang yang lebih tinggi) dan eskalasi hierarkis (ke atasan). NIST juga meminta status setiap insiden dipantau supaya insiden yang butuh sumber daya lebih atau perubahan strategi segera ketahuan [S2].

**Analogi:** satpam memanggil kepala regu (eskalasi), lalu kepala regu melapor ke pengelola gedung (elevasi). Batasnya: satpam yang memanggil kepala regu tidak dianggap gagal. Di SOC yang sehat, eskalasi yang tepat waktu dinilai sebagai keputusan yang baik, dan eskalasi yang ternyata tidak perlu tetap lebih murah daripada eskalasi yang terlambat.

**Cara kerja:** aturan eskalasi PT JAB ditulis di setiap playbook (Day 10 bagian 1.9), dengan kriteria umum berikut.

| Ke siapa | Kapan (cukup satu kriteria) |
|---|---|
| L1 ke L2 (eskalasi) | Ada tanda eksekusi atau pengambilalihan di host atau akun; aset kritis terlibat; butuh tindakan penahanan (isolasi host, nonaktifkan akun) yang di luar wewenang L1; lebih dari satu host atau akun terkena; L1 ragu lebih dari 30 menit |
| L2 ke SOC lead (elevasi) | Insiden SEV-1 atau SEV-2; data pribadi pelanggan atau karyawan mungkin terlibat (DPO Agus Setiawan ikut diberi tahu); butuh keputusan bisnis (mematikan layanan); pihak luar (media, regulator, pelanggan korporat) terlibat |
| SOC lead ke Direktur Teknologi | SEV-1 dan SEV-2, dengan kabar berkala |

Eskalasi yang baik membawa paket, bukan hanya nomor tiket: apa yang terlihat, apa yang sudah dicek, apa yang belum, apa yang kamu sarankan, dan seberapa mendesak. L2 yang menerima paket lengkap bisa langsung bertindak; L2 yang menerima "tolong cek 0863" harus mengulang triage dari awal.

**Contoh di PT JAB:** eskalasi `SOC-2027-0863` pukul 09:21 memenuhi dua kriteria sekaligus (aset kritis, perlu isolasi). Kamu menulis paket lima baris di tiket dan memanggil Sari langsung. Pukul 14:05, setelah laptop kedua ditemukan, insiden menjadi SEV-2; Dimas melakukan elevasi ke Hendra pukul 14:15 (bagian 2.3).

**Salah paham umum:**
- "Eskalasi berarti aku tidak bisa." Eskalasi adalah keputusan triage yang sah. Yang salah adalah eskalasi tanpa isi, atau menunda eskalasi demi terlihat mandiri.

### 1.9 Disposisi, kode penutupan, dan duplikat

Pertanyaan kesembilan Sari menyangkut dua kode tambahan di daftar penutupan PT JAB: DUP dan UND. Pukul 09:15, tiga menit setelah `SOC-2027-0863`, muncul `SOC-2027-0864` untuk laptop yang sama.

**Apa itu:** disposisi (disposition) atau closure code adalah kode yang menyatakan hasil akhir sebuah alert saat ditutup. Splunk ES 8 menyediakan disposisi bawaan Undetermined, True Positive, Benign Positive, dua jenis False Positive (logika dan data), Other, dan Testing, dan bisa ditambah disposisi sendiri [S8]; Microsoft Sentinel mewajibkan klasifikasi serupa saat incident ditutup [S3].

**Duplikat** adalah alert kedua (atau ketiga) untuk kejadian yang sama. Ada dua cara menanganinya. Sebelum alert dibuat, rule bisa diberi throttling supaya tidak membuat alert baru untuk hal yang sama dalam rentang waktu tertentu; Splunk ES menyebut throttling bekerja sebelum event masuk index notable, sehingga finding tidak pernah dibuat [S9]. Setelah alert dibuat, analyst menggabungkannya ke tiket pertama dan menutupnya dengan kode duplikat. Penggabungan di tingkat SIEM (aggregation) dibahas di Day 10 bagian 1.3.

**Analogi:** kolom "hasil pemeriksaan" di buku jaga satpam: maling, kucing, penghuni yang lupa kunci, laporan ganda, atau "tidak bisa dipastikan". Batasnya: kode penutupan SOC dibaca mesin untuk statistik bulanan, sehingga kode yang asal pilih merusak keputusan tuning berikutnya.

**Cara kerja:** daftar kode penutupan PT JAB disusun mengikuti disposisi bawaan Splunk ES, dengan dua tambahan.

| Kode | Arti | Contoh |
|---|---|---|
| TP | True positive, aktivitas jahat; dicatat juga "tanpa dampak" atau "dieskalasi ke INC-..." | `SOC-2027-0862`, `0863` |
| TP-POL | True positive, pelanggaran kebijakan oleh orang yang berhak | `SOC-2027-0838` (Day 07) |
| BP | Benign positive, nyata tetapi sah dan diharapkan; wajib menyebut bukti (tiket, jadwal, konfirmasi) | `SOC-2027-0858`, `0859`, `0865` |
| FP-LOGIC | False positive karena logika rule | `SOC-2027-0861` |
| FP-DATA | False positive karena data salah | `SOC-2027-0860` |
| DUP | Duplikat, digabung ke tiket lain (nomor tiket induk wajib ditulis) | `SOC-2027-0864` |
| UND | Undetermined, data tidak cukup untuk memutuskan; hanya boleh dengan persetujuan L2 | (tidak ada pagi ini) |
| TEST | Uji rule atau simulasi | Uji UC-017 bulan Juni (Day 10) |

Kode UND sengaja dipersulit. Alert yang ditutup "tidak bisa dipastikan" terlalu mudah menjadi tempat sampah, padahal sebagian di antaranya adalah false negative yang menunggu ditemukan.

**Contoh di PT JAB:** `SOC-2027-0864` adalah alert Defender kedua di `JKT-WS-1118` (komunikasi jaringan berkala yang mencurigakan ke `192.0.2.186`), bagian dari rangkaian yang sama dengan `0863`. Kamu menggabungkannya ke `0863` dengan kode DUP, dan bukti di dalamnya (pola koneksi tiap sekitar 60 detik) disalin ke tiket induk. Defender sendiri sudah mengelompokkan kedua alert ke satu "incident" di portalnya, karena Defender memang mengumpulkan alert terkait ke satu wadah [S5].

**Beda DUP dengan BP:** DUP tidak mengatakan apa pun tentang jahat atau tidaknya kejadian; ia hanya mengatakan "kejadian ini sudah ditangani di tiket lain". Klasifikasi sebenarnya mengikuti tiket induk.

**Salah paham umum:**
- "Kode penutupan hanya formalitas." Kode inilah bahan laporan precision per rule (bagian 1.5) dan keputusan tuning (bagian 1.10). Microsoft juga menyebut klasifikasi insiden membantu Defender memperbaiki penentuan deteksinya dari waktu ke waktu [S5].

### 1.10 Tuning

Bagian pertama pertanyaan kesepuluh: `SOC-2027-0861` (unduhan video yang dianggap unggahan) bukan kesalahan sekali. Rule yang sama memunculkan 23 alert serupa di bulan Juli, dan semuanya ditutup FP.

**Apa itu:** tuning adalah menyetel rule atau alat deteksi supaya lebih akurat: mengubah logika, ambang, rentang waktu, sumber data, atau pengecualian. NIST merekomendasikan teknologi monitoring disetel untuk menurunkan false positive dan false negative ke tingkat yang bisa diterima [S2]. Microsoft Defender for Identity menyebut tuning alert sebagai cara mengurangi false positive supaya tim bisa fokus pada alert prioritas tinggi [S6].

**Analogi:** mengatur sensitivitas alarm. Sensor yang terlalu peka berbunyi karena kucing; sensor yang terlalu tumpul diam saat maling lewat. Batasnya: alarm rumah punya satu tombol sensitivitas. Rule SIEM punya banyak "tombol" (logika, ambang, sumber, pengecualian), dan setiap perubahan bisa membuka celah yang tidak terlihat sampai ada serangan yang lolos.

**Cara kerja:** tuning yang baik mengikuti urutan kecil yang bisa diulang.

1. **Kumpulkan bukti.** Ambil semua alert rule itu dalam satu periode beserta kode penutupannya. Kode yang rapi (bagian 1.9) membuat langkah ini mudah.
2. **Temukan penyebabnya.** FP-LOGIC diperbaiki di logika; FP-DATA diperbaiki di sumber data atau parsing; BP yang berulang dipertimbangkan untuk allowlist atau suppression (bagian 1.11).
3. **Ubah sesempit mungkin.** Perbaiki yang salah tanpa mengubah hal lain.
4. **Uji dua arah.** Jalankan rule baru terhadap data lama: alert palsu harus hilang, dan alert yang benar (termasuk simulasi) harus tetap muncul.
5. **Catat.** Siapa mengubah apa, kapan, dan kenapa, di kartu use case (Day 10 bagian 1.6).

**Contoh di PT JAB:** rule UC-041 "Pengiriman data keluar besar" menghitung `bytes`, field yang di log `jkt-proxy01` berisi jumlah byte masuk dan keluar. Unduhan 3,8 GB oleh Andre Kurniawan (Pemasaran) dari situs agensi `media-agency.example` (`192.0.2.184`), dengan unggahan hanya 52 MB, melewati ambang 1 GB. Usulan tuning yang kamu tulis untuk Sari: ganti `bytes` dengan `bytes_out`, tetap dengan ambang 1 GB, lalu uji pada data Juli. Hasil uji: 23 alert palsu Juli hilang, dan satu simulasi unggahan 1,2 GB ke situs berbagi file tetap tertangkap.

**Beda tuning dengan mematikan rule:** tuning memperbaiki rule supaya tetap menangkap yang benar. Mematikan rule menghapus deteksi sama sekali. Rule yang sangat berisik kadang dimatikan sementara, tetapi keputusan itu harus dicatat sebagai celah deteksi, bukan sebagai perbaikan.

**Salah paham umum:**
- "Tuning berarti menaikkan ambang sampai alert berkurang." Menaikkan ambang memang mengurangi alert, tetapi juga mengurangi apa yang tertangkap. Pemindaian pelan yang melewati UC-034 (bagian 2.4) adalah contoh harga dari ambang yang terlalu tinggi.

### 1.11 Allowlist dan suppression

Bagian kedua pertanyaan kesepuluh: tiga benign positive pagi itu masing-masing butuh perlakuan berbeda. Pemindai `jkt-vscan01` muncul setiap Senin, skrip `adm.bayu` muncul sesekali, dan server `jkt-intranet02` hanya ramai selama dibangun ulang hari ini.

**Apa itu:**
- **Allowlist** (dalam konteks deteksi) adalah daftar entitas yang sudah diketahui sah dan dikecualikan dari rule tertentu: IP, host, user, aplikasi, atau kombinasinya. Microsoft Sentinel mencatat alert keliru sering datang dari entitas tertentu, misalnya identitas otomatis milik aplikasi atau pemindaian keamanan yang disengaja dari IP yang dikenal, dan menyarankan pengecualian dikelola di watchlist (daftar terpisah yang dibaca rule) supaya bisa ditambah tanpa mengubah rule dan dipakai banyak rule sekaligus [S4]. Jangan tertukar dengan application allowlisting di Day 06 bagian 1.6, yang mengatur program apa yang boleh berjalan di komputer.
- **Suppression** adalah menyembunyikan alert yang cocok dengan kondisi tertentu, biasanya untuk sementara. Di Splunk ES 8, suppression adalah filter pencarian yang menyembunyikan finding yang cocok; finding itu tetap dibuat dan disimpan, hanya tidak ditampilkan, dan tetap dihitung di dashboard audit suppression [S9]. Microsoft Sentinel memakai automation rule untuk pengecualian sementara yang menutup incident yang cocok secara otomatis dengan alasan tercatat; masa berlaku bawaannya 24 jam, dan Microsoft menyebut batas waktu itu mengurangi risiko false negative [S4].

**Analogi:** allowlist adalah daftar penghuni yang boleh lewat pintu samping tanpa membunyikan alarm. Suppression adalah mematikan alarm sementara untuk ruang yang sedang direnovasi. Batasnya ada dua. Pertama, penghuni di daftar bisa dicuri kartunya; allowlist yang terlalu luas membuat penyerang yang memakai entitas itu tidak terlihat sama sekali. Kedua, renovasi yang selesai tidak mematikan pengecualian dengan sendirinya; suppression tanpa tanggal berakhir menjadi pintu yang dibiarkan terbuka.

**Cara kerja:** pilih alat yang paling sempit untuk masalahnya.

| Situasi | Alat | Kenapa |
|---|---|---|
| Rule salah membaca data | Tuning (bagian 1.10) | Akar masalahnya di rule, bukan di entitasnya |
| Aktivitas sah yang berulang dari entitas tetap, dengan pola dan jadwal jelas | Allowlist yang sempit: entitas plus kondisi (jam, tujuan, jenis aktivitas) | Mengurangi BP berulang tanpa membutakan rule untuk entitas lain |
| Aktivitas sah yang sementara (perubahan, uji penetrasi, migrasi) | Suppression dengan tanggal berakhir dan nomor tiket perubahan | Otomatis kembali normal setelah jendela selesai |
| Rule terlalu sering berbunyi untuk kejadian yang sama | Throttling (bagian 1.9) | Satu kejadian, satu alert |

Prinsip yang dipegang PT JAB: setiap pengecualian punya pemilik, alasan, nomor tiket, dan tanggal tinjau; pengecualian dibuat dengan kombinasi ciri sesempit mungkin (Microsoft juga menyarankan menggabungkan atribut supaya pengecualian lebih halus dan peluang false negative berkurang [S4]); dan entitas yang sangat berkuasa (pemindai kerentanan, akun admin, alat manajemen) tidak pernah dikecualikan dari semua rule sekaligus, karena entitas itulah yang paling diincar penyerang.

**Contoh di PT JAB:**
- `jkt-vscan01` sudah punya suppression berulang untuk UC-034 setiap Senin 01:00 sampai 05:00. Pemindaian minggu ini molor sampai 06:35 karena subnet `10.10.41.0/24` baru ditambahkan, sehingga deteksi setelah 05:00 tidak tersembunyi dan menjadi `SOC-2027-0858`. Sari menolak usulan Gilang untuk mengecualikan `jkt-vscan01` dari UC-034 sepanjang waktu. Keputusannya: tim Agung memberi tahu SOC bila jadwal berubah, dan jendela diperpanjang menjadi 01:00 sampai 07:00 hanya untuk pola pemindaian, tidak untuk rule lain.
- `adm.bayu` tidak dimasukkan allowlist. PowerShell dengan `-ExecutionPolicy Bypass` dan jendela tersembunyi adalah pola yang juga dipakai penyerang. Perbaikannya di sisi proses: skrip ditandatangani dan dijalankan dari server manajemen, dan IT Support memberi tahu SOC sebelum menjalankannya.
- `jkt-intranet02` diberi suppression untuk tiga rule Defender (service baru, alat admin, perubahan firewall lokal) sampai 16:00, sesuai jendela `CHG-2027-0431`, dengan nomor tiket di kolom alasan.

**Beda allowlist dengan suppression:** allowlist mengatakan "entitas ini memang begini, terus-menerus"; suppression mengatakan "untuk sementara, jangan tampilkan ini". Di Splunk ES, alert yang disuppress tetap tersimpan dan bisa diperiksa ulang [S9], sedangkan pengecualian di logika rule (termasuk allowlist yang dibaca rule) membuat alert tidak pernah dibuat. Bedanya penting saat investigasi: yang disuppress masih bisa ditemukan; yang dikecualikan di rule tidak pernah ada.

**Salah paham umum:**
- "Suppression adalah tuning." Suppression menyembunyikan gejala dan cocok untuk keadaan sementara. Bila suppression yang sama diperpanjang terus setiap bulan, itu tanda rule atau prosesnya perlu diperbaiki.

### 1.12 Alert fatigue

Bagian terakhir pertanyaan kesepuluh terjadi pukul 13:52. Alert UC-034 "Port scan internal" muncul lagi. Gilang, yang sejak pagi sudah melihat judul yang sama, berkata, "Scanner Senin lagi, tutup saja kayak tadi." Kamu membukanya dulu. Sumbernya bukan `jkt-vscan01`.

**Apa itu:** alert fatigue adalah keadaan ketika analyst menjadi lelah dan kebal terhadap alert karena terlalu banyak alert yang tidak berarti, sehingga alert yang benar ikut terabaikan atau ditangani asal-asalan. Penelitian Oxford terhadap praktisi SOC mencatat bahwa memvalidasi alarm secara manual itu melelahkan dan bisa berujung pada kejenuhan (alarm burnout) yang akhirnya membuat analyst kebal terhadap alert [S11]. Survei SANS 2025 tentang deteksi dan respons mencatat 73% responden menyebut false positive sebagai tantangan deteksi utama, naik dari 64% pada 2024, dan sekitar 60% menghadapi false positive sering atau sangat sering [S12]. Day 03 bagian 1.3 sudah menyinggung bahwa false positive tetap mahal walaupun tidak memblokir apa pun, karena alasan ini.

**Analogi:** satpam yang terbiasa mengabaikan alarm karena terlalu sering salah. Malam pertama ia lari ke setiap pintu. Bulan ketiga ia hanya melirik layar. Pada malam maling benar-benar datang, ia melirik, melihat judul yang sama, dan kembali minum kopi. Batasnya: satpam yang lelah biasanya sadar ia lelah. Analyst yang mengalami alert fatigue sering merasa justru semakin mahir, karena ia menutup alert semakin cepat.

**Cara kerja:** alert fatigue tumbuh dari lingkaran yang memperkuat dirinya sendiri.

```
  banyak FP dan BP berulang  ->  analyst menutup cepat dari judul  ->  kode penutupan asal
          ^                                                                  |
          |                                                                  v
  rule tidak pernah disetel  <-  statistik per rule tidak berarti  <-  tuning tidak punya bahan
```

Lingkaran itu diputus dari beberapa titik sekaligus:
- **Kurangi suara palsu:** tuning untuk FP, allowlist sempit dan suppression berjangka untuk BP (bagian 1.10 dan 1.11).
- **Buat alert lebih mudah divalidasi:** penelitian Oxford mengusulkan lima sifat alarm yang baik, yaitu reliable, explainable, analytical, contextual, dan transferable [S11]. Di PT JAB wujudnya enrichment otomatis dan deskripsi rule yang menjelaskan "kenapa ini mencurigakan".
- **Lindungi kebiasaan:** aturan PT JAB, alert tidak boleh ditutup dari daftar antrean; tiket harus dibuka dan sumber serta targetnya dibaca. Penutupan massal hanya untuk alert dengan kode DUP atau dengan suppression yang tercatat.
- **Ukur:** jumlah alert per analyst per shift dan precision per rule dipantau Dimas setiap bulan.

**Contoh di PT JAB:** alert `SOC-2027-0866` pukul 13:52 punya judul yang persis sama dengan `0858` pagi tadi. Bedanya ada di dua field yang tidak terlihat di daftar antrean: sumbernya `JKT-WS-1117` (`10.10.41.77`), laptop Keuangan, dan targetnya `10.20.10.0/24` (segmen server) di port 445 dan 3389, bukan pola pemindaian kerentanan. Lima menit kemudian, alert itu sudah menjadi bagian dari `INC-2027-090` (bagian 2.3). Seandainya ditutup dari judul, laptop itu akan tetap terhubung ke penyerang sampai shift malam.

**Beda alert fatigue dengan beban kerja tinggi:** beban kerja tinggi adalah jumlah alert yang banyak; alert fatigue adalah perubahan perilaku (orang berhenti membaca) akibat alert yang tidak berarti, dan bisa terjadi walaupun jumlah alert sedikit.

**Salah paham umum:**
- "Alert fatigue diatasi dengan menambah orang." Orang baru akan lelah dengan cara yang sama bila sumber kebisingannya tidak diperbaiki. Menambah orang membantu sementara; tuning dan kebiasaan membaca isi alert yang menyelesaikan.

## 2. Contoh nyata

Semua contoh di bagian ini adalah keluaran ilustrasi dari organisasi fiktif PT JAB, bukan hasil eksekusi nyata. Nama host, alamat IP, akun, nomor, jam, dan angka dibuat untuk latihan, dan format log disederhanakan supaya mudah dibaca.

### 2.1 Antrean pagi: sembilan alert dan hasilnya

Tabel ini adalah papan antrean shift pagi Senin 2027-08-16 setelah semua alert ditutup (pertanyaan 1, 2, 3, 6, dan 9). Baca kolom "Kode" bersama kolom "Bukti penentu" untuk melihat bahwa setiap keputusan berdiri di atas sesuatu di luar judul alert.

| Alert | Jam | Judul singkat | Severity alat | Priority | Kode | Bukti penentu |
|---|---|---|---|---|---|---|
| `SOC-2027-0858` | 05:12 | UC-034 Port scan internal dari `jkt-vscan01` (`10.20.10.61`) | Medium | P3 | BP | Jadwal pemindaian mingguan; tim Agung mengonfirmasi pemindaian molor sampai 06:35 karena subnet baru |
| `SOC-2027-0859` | 07:26 | Defender: PowerShell mencurigakan di `JKT-WS-1112` (`10.10.41.12`), akun `adm.bayu` | Medium | P3 | BP | Tiket `CHG-2027-0428` inventaris lisensi; Bayu Setiadi dikonfirmasi lewat telepon kantor |
| `SOC-2027-0860` | 07:48 | Perjalanan mustahil: `nadia.putri` Jakarta lalu "Belanda" dalam 7 menit | Medium | P3 | FP-DATA | `198.51.100.82` adalah NAT baru kantor Bandung; database geolokasi belum diperbarui |
| `SOC-2027-0861` | 08:15 | UC-041 Pengiriman data keluar besar, `JKT-WS-1115` (`10.10.41.55`) | High | P2 | FP-LOGIC | Unduhan 3,8 GB, unggahan 52 MB; rule menjumlahkan byte dua arah |
| `SOC-2027-0862` | 08:30 | Password spraying VPN dari `192.0.2.183` | Medium | P2 | TP | 146 akun, 0 berhasil; IP diblok di `jkt-vpn01` 7 hari dan masuk watchlist |
| `SOC-2027-0863` | 09:12 | Defender: rundll32 memuat DLL dari image ISO, `JKT-WS-1118` (`10.10.41.88`) | High | P1 | TP | Rantai proses dan koneksi berkala ke `192.0.2.186`; dieskalasi, `INC-2027-090` |
| `SOC-2027-0864` | 09:15 | Defender: komunikasi jaringan berkala mencurigakan, `JKT-WS-1118` | Medium | P2 | DUP | Kejadian yang sama dengan `0863`; digabung |
| `SOC-2027-0865` | 10:30 | Defender: service baru dan alat admin di `jkt-intranet02` (`10.20.15.42`) | Low | P4 | BP | Jendela perubahan `CHG-2027-0431` 10:00 sampai 16:00; suppression dibuat sampai 16:00 |
| `SOC-2027-0866` | 13:52 | UC-034 Port scan internal dari `JKT-WS-1117` (`10.10.41.77`) | Medium | P3, dinaikkan ke P1 | TP | Laptop Keuangan memindai `10.20.10.0/24` port 445 dan 3389; terkait `INC-2027-090` |

**Cara membaca:**

- **Hitungan kode:** TP 4 (`0862`, `0863`, `0866`, ditambah `0864` yang klasifikasinya mengikuti induknya), BP 3, FP 2. Jumlahnya 4 + 3 + 2 = 9.
- **Priority dari matriks:** `0861` High di aset standar menjadi P2; `0862` Medium di gateway VPN (aset kritis) menjadi P2; `0863` High di laptop pemberi persetujuan pembayaran (aset kritis) menjadi P1; `0865` Low di aset standar menjadi P4. Hanya `0866` yang priority-nya diubah manual, dari P3 ke P1, karena triage menemukan kaitannya dengan insiden aktif.
- **SLA acknowledge (Day 10 bagian 1.12):** `0858` (05:12, shift malam) diambil 07:10, 1 jam 58 menit, di dalam batas P3 4 jam; `0861` diambil Gilang 5 menit setelah muncul (batas P2 30 menit); `0863` diambil 2 menit setelah muncul (batas P1 15 menit).
- **Satu insiden dari tiga alert:** `0863`, `0864`, dan `0866` adalah satu cerita. Tanpa kebiasaan menggabungkan, laporan bulanan akan menghitung tiga kejadian terpisah.

### 2.2 `SOC-2027-0863`: lima langkah triage sampai insiden

Alert ini menjawab pertanyaan 7 dan 8, dan menunjukkan lima langkah triage dikerjakan berurutan dalam sembilan menit. Berikut cuplikan rantai proses dari Defender for Endpoint.

```
Alert   : SOC-2027-0863   P1   Defender for Endpoint, severity High
Judul   : Suspicious rundll32 behavior / DLL loaded from mounted disk image
Host    : JKT-WS-1118 (10.10.41.88)   User: CORP\yusuf.hidayat (Keuangan, penyetuju pembayaran vendor)

09:08:14  OUTLOOK.EXE  membuka lampiran  Remitansi_Agustus.iso  (dipasang sebagai drive E:)
09:08:31  explorer.exe -> E:\Remitansi_Agustus.lnk
09:08:32  cmd.exe /c start rundll32.exe E:\data\remit.dll,Start
09:08:33  rundll32.exe  memuat  E:\data\remit.dll   (tidak bertanda tangan, reputasi tidak dikenal)
09:09:02  rundll32.exe  -> 192.0.2.186:443   (lalu berulang tiap sekitar 60 detik)
09:11:40  Defender membuat alert; Splunk membuat tiket 09:12
```

**Langkah 1, konteks (09:14 sampai 09:16).** Enrichment otomatis menunjukkan Yusuf staf Keuangan yang berwenang menyetujui pembayaran vendor (aset kritis). Tidak ada tiket perubahan, uji keamanan, atau alert lain di laptop itu selama tujuh hari.

**Langkah 2, validasi (09:16 sampai 09:18).** Rantai proses dibuka di Defender, bukan hanya judulnya. Image disk dari lampiran email yang menjalankan pintasan, lalu program bawaan Windows (`rundll32.exe`) memuat DLL tak bertanda tangan dari image itu, lalu koneksi keluar berulang: pola yang tidak punya penjelasan sah. Koneksi pertama 09:09:02 dan alert 09:11:40, jadi sampai 09:14 sudah ada sekitar 6 koneksi dengan jeda sekitar 60 detik (09:09, 09:10, 09:11, 09:12, 09:13, 09:14). Data cocok dengan log proxy `jkt-proxy01`. Bukan false positive, bukan benign positive.

**Langkah 3, cakupan (09:18 sampai 09:21, lalu dilanjutkan L2).** Email yang sama dikirim 07:41 dari `finance@vendor-remit.example` (server pengirim `192.0.2.181`) ke Yusuf, Fitri Rahmawati, dan Rina Anggraini. Alamat `192.0.2.186` di log proxy dan firewall hanya terlihat dari `JKT-WS-1118`. Alert EDR di laptop Fitri (`JKT-WS-1117`) dan Rina: tidak ada. Kamu menulis di tiket "Fitri dan Rina belum terbukti aman; belum dicek langsung", tetapi tindak lanjutnya kemudian terlewat (bagian 2.3).

**Langkah 4, keputusan (09:21).** Klasifikasi TP. Kriteria eskalasi terpenuhi dua kali: aset kritis dan perlu isolasi. Paket eskalasi ke Sari:

```
SOC-2027-0863  ESKALASI ke L2 (Sari)  09:21
Apa      : JKT-WS-1118 (Yusuf, Keuangan, aset kritis) menjalankan DLL tak bertanda tangan dari lampiran
           ISO; koneksi berkala ke 192.0.2.186:443 tiap ~60 detik sejak 09:09:02.
Sudah    : rantai proses divalidasi; cocok dengan log proxy; tidak ada tiket perubahan.
           Email sama ke 3 penerima (Yusuf, Fitri, Rina) 07:41; 192.0.2.186 hanya terlihat dari JKT-WS-1118.
Belum    : status laptop Fitri (JKT-WS-1117) dan Rina; apakah lampiran dibuka.
Saran    : isolasi JKT-WS-1118; tarik email dari 3 mailbox; blok 192.0.2.186 dan domain pengirim.
Mendesak : ya (P1). Yusuf sedang di mejanya; jangan minta ia mematikan laptop.
```

**Langkah 5, dokumentasi.** Catatan kerja tiket berisi setiap pemeriksaan dengan jam, termasuk pencarian yang hasilnya kosong. Tabel berikut adalah jejak waktunya; perhatikan langkah 09:40 yang nanti terbukti kurang.

| Waktu | Pelaku | Catatan | Status |
|---|---|---|---|
| 09:12 | Splunk | Tiket `SOC-2027-0863` dibuat, P1 | New |
| 09:14 | Kamu (L1) | Diambil, mulai triage | In progress |
| 09:15 | Splunk | `SOC-2027-0864` (host sama) muncul; kamu gabungkan sebagai DUP 09:17 | In progress |
| 09:21 | Kamu | Eskalasi ke Sari dengan paket di atas | Escalated |
| 09:24 | Sari (L2) | `JKT-WS-1118` diisolasi lewat EDR | Escalated |
| 09:30 | Sari | `INC-2027-090` dibuka, SEV-3; Dimas diberi tahu karena P1 | Escalated |
| 09:35 | Yoga Pratama (L2) | Email ditarik dari 3 mailbox; `192.0.2.186` dan `vendor-remit.example` diblok | Escalated |
| 09:40 | Sari | Cakupan: cek alert EDR di laptop Fitri dan Rina, tidak ada; disimpulkan lampiran tidak dibuka | Escalated |

**Cara membaca:** waktu ack 2 menit dan eskalasi 7 menit setelah ack (09:14 sampai 09:21) jauh di dalam batas P1. Langkah yang lemah adalah baris 09:40: "tidak ada alert" dipakai sebagai bukti "tidak dibuka". Pemeriksaan yang benar adalah melihat langsung ke laptop itu (riwayat file yang dibuka, proses, koneksi keluar ke alamat mana pun yang tidak biasa), bukan hanya mencari alert.

### 2.3 `SOC-2027-0866`: hampir ditutup, ternyata false negative selama hampir enam jam

Alert ini menjawab pertanyaan 4 dan 10, dan memperlihatkan alert fatigue dan false negative di satu kasus.

```
Alert   : SOC-2027-0866   P3 (matriks)   UC-034 Port scan internal, severity Medium
Waktu   : 13:47:10 sampai 13:51:55 (jendela 5 menit), alert 13:52
Sumber  : 10.10.41.77 (JKT-WS-1117, user CORP\fitri.rahmawati, Keuangan)
Target  : 10.20.10.0/24, port 445 dan 3389
Hitungan: 508 kombinasi IP dan port   (254 host x 2 port)   ambang rule: lebih dari 100
```

**13:54, ack dan godaan menutup.** Gilang: "Scanner Senin lagi." Daftar antrean memang hanya menampilkan judul yang sama dengan `0858`. Kamu membuka tiket dan membaca dua field: sumber `10.10.41.77`, bukan `10.20.10.61` (`jkt-vscan01`); target port 445 (berbagi file Windows) dan 3389 (remote desktop) di segmen server, pola yang cocok dengan mencari pintu untuk bergerak ke server lain, bukan pemindaian kerentanan yang memeriksa banyak port.

**13:55 sampai 13:59, konteks dan cakupan.** Nama `JKT-WS-1117` mengingatkanmu pada catatan di tiket `0863`: Fitri adalah salah satu penerima email. Pencarian log proxy untuk `JKT-WS-1117` sejak pagi menunjukkan ini:

```
jkt-proxy01, src=10.10.41.77 (JKT-WS-1117), disederhanakan
08:05:12  user membuka lampiran (dari timeline Defender, dicek kemudian)
08:06:03  CONNECT 192.0.2.187:443   ua="Mozilla/5.0 (compatible; Sync/2.1)"   uri=/api/v2/sync
08:07:04  CONNECT 192.0.2.187:443   ua="Mozilla/5.0 (compatible; Sync/2.1)"   uri=/api/v2/sync
  ... berulang tiap sekitar 60 detik ...
13:51:58  CONNECT 192.0.2.187:443   ua="Mozilla/5.0 (compatible; Sync/2.1)"   uri=/api/v2/sync

jkt-proxy01, src=10.10.41.88 (JKT-WS-1118), untuk perbandingan
09:09:02  CONNECT 192.0.2.186:443   ua="Mozilla/5.0 (compatible; Sync/2.1)"   uri=/api/v2/sync
```

User-Agent dan path-nya sama persis dengan laptop Yusuf; hanya alamat IP tujuannya yang berbeda. Pencarian pukul 09:40 hanya memakai alamat `192.0.2.186`, sehingga laptop Fitri, yang berbicara ke `192.0.2.187`, tidak ikut tertangkap.

**14:00 sampai 14:15, keputusan dan eskalasi.** Kamu menaikkan priority ke P1, mengklasifikasi TP, dan mengeskalasi ke Sari dengan catatan "terkait `INC-2027-090`, host kedua, ciri pengenal: User-Agent dan path, bukan IP". Sari mengisolasi `JKT-WS-1117` pukul 14:02. Pukul 14:05 insiden dinaikkan ke SEV-2 (dua host, aktivitas pemindaian ke segmen server). Pukul 14:15 Dimas melakukan elevasi ke Hendra Wijaya. Yoga memblok `192.0.2.187` dan mencari User-Agent itu di seluruh log proxy 30 hari: hanya dua laptop itu.

**Cara membaca:**

- **Lama false negative:** aktivitas penyerang di `JKT-WS-1117` dimulai 08:06:03 dan alert pertama yang berkaitan muncul 13:52. Selisihnya 5 jam 46 menit (08:06 sampai 13:06 adalah 5 jam, ditambah 46 menit). Selama itu tidak ada satu alert pun dari EDR, proxy, atau SIEM.
- **Ada tiga false negative berbeda:** filter email meloloskan lampiran ISO (sejak 07:41), EDR tidak mengenali cara pemuat di laptop Fitri, dan tidak ada rule yang mencari koneksi keluar berkala dengan User-Agent tidak biasa. Masing-masing dicatat sebagai celah deteksi di insiden, untuk ditindaklanjuti setelah insiden selesai (Day 19).
- **Alert fatigue hampir menang:** yang membedakan hasilnya adalah kebiasaan membuka tiket dan membaca sumber, bukan alat yang lebih canggih.
- **Pelajaran cakupan:** cari dengan beberapa ciri sekaligus (penerima email, User-Agent, path, hash, nama file), dan periksa langsung setiap host yang mungkin terkena. "Tidak ada alert" bukan bukti "tidak terjadi".

### 2.4 Menghitung mutu rule: pagi ini dan UC-034 bulan Juli

Bagian ini menjawab pertanyaan 5 dengan dua hitungan: satu dari sembilan alert pagi ini, satu dari rekap bulanan sebuah rule.

**Sembilan alert pagi ini.** Hitungan memakai kode di bagian 2.1.

```
TP 4   BP 3   FP 2   (total 9)

Precision "butuh tindakan"         = TP / total            = 4 / 9  = 44,4%
Precision "deteksi benar secara teknis" = (TP + BP) / total  = 7 / 9  = 77,8%
False negative yang diketahui hari ini: 1 host (JKT-WS-1117), selama 5 jam 46 menit
```

Dua angka precision itu sama-sama benar; keduanya menjawab pertanyaan berbeda. Angka pertama menggambarkan beban analyst, angka kedua menggambarkan apakah rule-rule itu bekerja sesuai rancangannya.

**UC-034 "Port scan internal", Juli 2027.** Tabel ini dipakai Dimas untuk memutuskan apakah UC-034 perlu disetel; cari baris BP untuk melihat dari mana kebisingannya.

| Kode | Jumlah | Penyebab utama |
|---|---|---|
| TP | 2 | Dua laptop kontraktor yang menjalankan alat pemindai jaringan tanpa izin |
| BP | 44 | `jkt-vscan01` di luar jendela suppression (jadwal sering molor) |
| FP | 6 | Printer baru yang mencari perangkat lain dengan broadcast, terbaca sebagai ratusan tujuan |
| Total | 52 | |

```
Precision butuh tindakan  = 2 / 52        = 3,8%
Deteksi benar secara teknis = (2 + 44) / 52 = 46 / 52 = 88,5%

Uji simulasi Juni (3 skenario pemindaian):
  pemindaian cepat 500 tujuan dalam 2 menit     : tertangkap
  pemindaian 254 host x 2 port dalam 5 menit     : tertangkap
  pemindaian pelan 1 port tiap 10 detik (30 per 5 menit, di bawah ambang 100): TIDAK tertangkap
Recall dari uji = 2 / 3 = 66,7%
```

**Cara membaca:**

- **Masalah UC-034 bukan rule-nya salah, tetapi BP yang tidak terkelola.** Dari 52 alert, 44 berasal dari satu entitas dengan jadwal yang diketahui. Perbaikannya ada di suppression yang lebih tepat dan komunikasi jadwal (bagian 1.11), bukan di menaikkan ambang.
- **FP printer adalah urusan logika.** Rule perlu mengabaikan lalu lintas broadcast; itu tuning (bagian 1.10).
- **Recall 66,7% hanya dari tiga uji.** Angka sekecil itu tidak bisa digeneralisasi, tetapi cukup untuk menunjukkan celah: pemindaian pelan lolos. Menurunkan ambang akan menambah alert; pilihan yang lebih baik adalah rule pendamping dengan jendela waktu lebih panjang (misalnya jumlah tujuan berbeda dalam satu jam).
- **Precision 3,8% adalah resep alert fatigue.** Analyst yang melihat 50 alert UC-034 sebulan dan hanya 2 yang penting akan belajar menutupnya dari judul, persis godaan pukul 13:54 (bagian 2.3).

## 3. Perbandingan istilah yang sering tertukar

### 3.1 TP, FP, BP, FN, dan TN

Lima hasil ini sering diucapkan dengan singkatan saja. Tabel berikut memakai dua pertanyaan yang sama untuk semuanya; cari kolom "Yang diperbaiki" untuk tahu tindak lanjutnya.

| Hasil | Ada alert? | Kejadian nyata? | Jahat atau tidak diizinkan? | Analogi | Yang diperbaiki |
|---|---|---|---|---|---|
| TP | Ya | Ya | Ya | Alarm karena maling | Tangani ancamannya |
| BP | Ya | Ya | Tidak, sah dan diharapkan | Pemilik rumah masuk lewat jendela | Allowlist sempit atau suppression berjangka, atau biarkan |
| FP | Ya | Tidak, atau salah dibaca | Tidak berlaku | Alarm karena kucing | Logika rule (FP-LOGIC) atau data (FP-DATA) |
| FN | Tidak | Ya | Ya | Maling masuk, alarm diam | Tambah atau setel deteksi, perbaiki sumber log |
| TN | Tidak | Ya (aktivitas normal) | Tidak | Tetangga lewat, alarm diam | Tidak ada |

### 3.2 Tuning, allowlist, suppression, dan throttling

Keempatnya mengurangi alert, tetapi dengan cara dan risiko yang berbeda. Tabel berikut membantu memilih; cari kolom "Risiko bila salah pakai".

| Alat | Bekerja di | Alert tetap dibuat? | Cocok untuk | Risiko bila salah pakai |
|---|---|---|---|---|
| Tuning | Logika, ambang, sumber rule | Tergantung perubahan | FP-LOGIC, FP-DATA, ambang yang keliru | Ambang terlalu tinggi menambah false negative |
| Allowlist | Daftar pengecualian yang dibaca rule | Tidak untuk entitas di daftar | BP berulang dari entitas tetap | Entitas di daftar yang dicuri penyerang menjadi tak terlihat |
| Suppression | Tampilan antrean (Splunk ES); finding tetap disimpan | Ya, tetapi disembunyikan | BP sementara: perubahan, migrasi, uji penetrasi | Lupa diakhiri, menjadi celah permanen |
| Throttling | Pembuatan alert | Tidak untuk pengulangan dalam rentang waktu | Satu kejadian yang memicu rule berkali-kali | Kejadian kedua yang berbeda tetapi mirip ikut tertahan |

## 4. Salah paham umum

- **Anggapan:** semua alert yang ternyata bukan serangan adalah false positive. **Kenyataannya:** alert yang mendeteksi aktivitas nyata yang sah adalah benign positive, dan perbaikannya berbeda. Menggabungkan keduanya membuat rule yang bekerja benar terlihat buruk dan mendorong orang mematikannya (bagian 1.3).
- **Anggapan:** precision tinggi berarti deteksi bagus. **Kenyataannya:** precision hanya melihat alert yang muncul. Rule bisa punya precision 100% dan tetap melewatkan sebagian besar serangan; recall hanya bisa diperkirakan dari uji simulasi, hunting, atau insiden (bagian 1.5 dan 2.4).
- **Anggapan:** priority sama dengan severity. **Kenyataannya:** severity datang dari jenis kejadian, priority dari jenis kejadian ditambah konteks aset dan waktu, dan NIST meminta prioritas berdasarkan faktor risiko, bukan urutan kedatangan [S2] (bagian 1.6).
- **Anggapan:** alert yang dieskalasi selesai urusannya bagi L1. **Kenyataannya:** catatan L1 dan langkah cakupan yang belum selesai menentukan arah investigasi; kalimat "belum dicek langsung" di tiket `0863` adalah benih yang menyelamatkan sore itu (bagian 1.8 dan 2.2).
- **Anggapan:** semakin banyak pengecualian, semakin tenang antrean, semakin baik. **Kenyataannya:** setiap pengecualian adalah tempat bersembunyi yang potensial. Pengecualian yang baik sempit, punya pemilik, punya alasan, dan punya tanggal berakhir atau tanggal tinjau [S4] (bagian 1.11).

## 5. Catatan terkini

Bagian ini mencatat versi dokumen acuan, perubahan istilah antar produk, dan angka survei yang bisa berubah.

- NIST SP 800-61 Revision 3 terbit April 2025 dan disusun mengikuti CSF 2.0. Rekomendasi tentang alert, triage, kriteria insiden, prioritas berbasis faktor risiko, eskalasi dan elevasi, serta tuning untuk menurunkan false positive dan false negative di Day ini berasal dari versi ini [S2]. Definisi incident di SP 800-61r3 mengikuti FISMA 2014; glosarium NIST juga memuat definisi lain, misalnya dari FIPS 200 yang menyebut potensi kompromi dan pelanggaran kebijakan [S1].
- Splunk Enterprise Security 8 mengganti istilah notable event dan risk notable menjadi finding, correlation search menjadi detection, dan memperkenalkan intermediate finding dan finding group [S7]. Halaman disposisi dan suppression yang dipakai di Day ini adalah versi 8.5 [S8][S9]; halaman urgency yang dipakai adalah versi 7.2, karena konsep perhitungan urgency dari severity dan priority aset dijelaskan paling lengkap di sana [S10]. Cek matriks urgency di versi-mu, karena isinya bisa berbeda antar versi.
- Nama klasifikasi berbeda antar produk Microsoft: Sentinel memakai True Positive, Benign Positive, False Positive (dua jenis), dan Undetermined [S3]; Defender XDR memakai True positive, Informational expected activity, dan False positive [S5]; Defender for Identity memakai TP, B-TP, dan FP, dengan FP dirumuskan sebagai "aktivitasnya tidak terjadi" [S6]. Saat memindahkan statistik antar alat, petakan dulu kodenya.
- Angka survei SANS (73% responden menyebut false positive sebagai tantangan deteksi utama, naik dari 64% pada 2024) berasal dari SANS 2025 Detection and Response Survey; analisis survei 2026 disebut sedang berjalan [S12]. Cek angka terbaru sebelum mengutipnya.

## 6. Cheat sheet

```
Event              : kejadian teramati apa pun; hampir semua normal
Adverse event      : event dengan akibat negatif, apa pun penyebabnya
Alert              : dugaan dari alat/rule bahwa event perlu diperiksa
Finding / notable  : nama alert di Splunk ES 8 / ES 7
Incident           : mengancam CIA atau melanggar hukum/kebijakan; DINYATAKAN setelah diperiksa
TP                 : alert benar, aktivitas jahat (berhasil atau tidak, catat dampaknya terpisah)
FP                 : alert salah; FP-LOGIC (rule) atau FP-DATA (data)
BP                 : nyata, sah, diharapkan; butuh bukti di luar alert (tiket, jadwal, konfirmasi)
FN                 : serangan tanpa alert; paling berbahaya; ditemukan lewat cakupan, uji, hunting
TN                 : normal tanpa alert; sangat banyak; tidak dihitung
Precision          : TP / (TP + FP)        recall: TP / (TP + FN)   akurasi menyesatkan
Severity           : seberapa parah jenis kejadian (alat: Low/Medium/High; insiden: SEV-1..4)
Priority           : seberapa cepat dikerjakan = severity + kritikalitas aset + waktu (P1..P4)
Triage             : konteks -> validasi -> cakupan -> keputusan -> dokumentasi
Eskalasi / elevasi : tambah sumber daya atau keahlian / libatkan manajemen
Disposisi          : TP, TP-POL, BP, FP-LOGIC, FP-DATA, DUP, UND (persetujuan L2), TEST
Dedup / throttling : gabungkan duplikat / cegah alert berulang untuk hal yang sama
Tuning             : setel logika, ambang, sumber; uji dua arah; catat
Allowlist          : pengecualian entitas sah yang tetap; sempit, berpemilik, ditinjau
Suppression        : sembunyikan sementara (perubahan, migrasi); WAJIB tanggal berakhir
Alert fatigue      : kebal karena alert tak berarti; obat: kurangi suara palsu + baca isi, bukan judul
```

## 7. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Alert `SOC-2027-0858` (pemindaian port dari `jkt-vscan01`) ditutup sebagai false positive, karena pemindainya milik kita sendiri." Benarkah kodenya?

<details><summary>Jawaban</summary>

Tidak. Pemindaiannya benar-benar terjadi dan rule membacanya dengan benar, jadi ini bukan false positive. Pelakunya sah dan aktivitasnya diharapkan menurut jadwal yang dikonfirmasi tim Agung, sehingga kodenya benign positive. Bedanya penting: FP berarti rule atau data perlu diperbaiki, sedangkan BP berarti rule bekerja benar dan yang perlu dipikirkan adalah pengecualian sempit atau suppression berjangka. Menandai BP sebagai FP membuat UC-034 terlihat salah padahal tidak. Lihat bagian 1.2, 1.3, dan 1.11.

</details>

**2. Skenario keputusan.** Pukul 09:40, saat menelusuri cakupan `SOC-2027-0863`, tim menemukan email yang sama juga diterima Fitri dan Rina. Tidak ada alert EDR di laptop keduanya. Langkah mana yang paling tepat?

- A. Simpulkan keduanya tidak membuka lampiran, karena EDR pasti berbunyi bila lampiran dijalankan.
- B. Periksa langsung kedua laptop dan cari di log dengan beberapa ciri sekaligus (nama file, User-Agent, path, koneksi berkala ke alamat mana pun), bukan hanya alamat `192.0.2.186`.
- C. Isolasi semua laptop Keuangan sampai insiden selesai.

<details><summary>Jawaban</summary>

B. Tidak adanya alert bukan bukti tidak adanya serangan; EDR bisa melewatkan cara pemuat yang berbeda (false negative), dan penyerang bisa memakai alamat lain untuk setiap korban. Mencari dengan beberapa ciri dan memeriksa host secara langsung adalah inti langkah cakupan. A keliru karena itulah kesalahan yang membuat laptop Fitri terhubung ke penyerang selama 5 jam 46 menit. C keliru karena terlalu luas: menghentikan kerja seluruh Keuangan tanpa bukti, padahal pemeriksaan terarah ke dua laptop bisa dilakukan dalam menit. Lihat bagian 1.4, 1.7, dan 2.3.

</details>

**3. Pertanyaan jebakan.** "Defender memberi severity High, jadi alert ini otomatis P1." Benarkah?

<details><summary>Jawaban</summary>

Tidak selalu. Severity adalah seberapa parah jenis kejadian; priority menggabungkan severity dengan kritikalitas aset dan konteks waktu. Di matriks PT JAB, High di aset kritis menjadi P1, di aset standar P2, dan di aset rendah P3. `SOC-2027-0861` adalah High tetapi P2 karena laptopnya aset standar. Priority juga bisa diubah analyst setelah triage, seperti `SOC-2027-0866` yang naik dari P3 ke P1. Lihat bagian 1.6 dan 2.1.

</details>

**4. Skenario keputusan.** Server `jkt-intranet02` sedang dibangun ulang dari 10:00 sampai 16:00 dengan tiket `CHG-2027-0431`, dan Defender terus memunculkan alert service baru dan alat admin. Apa yang paling tepat?

- A. Masukkan `jkt-intranet02` ke allowlist permanen untuk semua rule Defender.
- B. Buat suppression untuk rule yang terdampak di host itu, berlaku sampai 16:00, dengan nomor tiket perubahan sebagai alasan.
- C. Matikan sementara rule service baru untuk seluruh PT JAB sampai server selesai.

<details><summary>Jawaban</summary>

B. Aktivitasnya sah tetapi sementara, sehingga alat yang cocok adalah suppression sempit dengan tanggal berakhir dan alasan tertulis; setelah 16:00 deteksi kembali normal dengan sendirinya. A keliru karena allowlist permanen untuk semua rule membuat server itu tak terlihat selamanya, termasuk bila nanti benar-benar disusupi. C keliru karena membutakan seluruh organisasi demi satu server. Lihat bagian 1.11.

</details>

**5. Jelaskan ulang.** Jelaskan kepada anggota keluargamu yang bukan orang IT, dalam tiga kalimat, beda false positive, benign positive, dan false negative.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Di kantor kami ada sistem alarm untuk komputer, mirip alarm rumah. Kadang alarm bunyi karena kucing, itu salah bunyi; kadang bunyi karena memang ada orang masuk lewat jendela tapi ternyata pemilik rumah yang lupa kunci, itu benar bunyi tapi bukan maling. Yang paling kami takutkan justru kalau maling masuk dan alarmnya diam, karena tidak ada yang tahu sampai barangnya hilang."

Kesalahan yang sering muncul:
- Memakai istilah seperti positive, rule, atau SIEM tanpa penjelasan.
- Menyamakan "pemilik rumah lupa kunci" dengan "alarm rusak"; padahal alarmnya bekerja benar.
- Lupa menyebut kenapa alarm yang diam paling berbahaya.

</details>

**6. Pertanyaan jebakan.** "Precision UC-034 bulan Juli 88,5%, jadi rule ini tidak perlu disentuh." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Angka 88,5% adalah (TP + BP) / total, yaitu seberapa sering rule mendeteksi aktivitas yang benar-benar terjadi. Dari sisi beban analyst, hanya 2 dari 52 alert yang butuh tindakan (3,8%), dan 44 BP dari satu pemindai adalah resep alert fatigue. Uji simulasi juga menunjukkan pemindaian pelan tidak tertangkap (recall dari uji 2 / 3). Rule ini perlu pengelolaan suppression yang lebih tepat, tuning untuk broadcast printer, dan rule pendamping untuk pemindaian pelan. Lihat bagian 1.5, 1.12, dan 2.4.

</details>

**7. Interview question (English).** "Walk me through how you triage an alert, and how you tell a false positive from a benign positive."

<details><summary>Sample answer</summary>

"I use the same five steps every time. First context: what the rule is meant to catch, who the user and host are, how critical the asset is, and whether there is a change ticket or schedule. Second validation: I open the raw evidence, not just the title. If the activity did not happen, or the rule or data is wrong, it is a false positive and the fix belongs in the rule or the data pipeline. If it did happen but was legitimate and expected, like a scheduled vulnerability scan or an admin script backed by a change ticket and a phone confirmation, it is a benign positive, and the question becomes whether a narrow exception or a time-bound suppression fits. Third scope: before and after on the same entity, and sideways to anything sharing an indicator, using several attributes, because no alert on another host is not proof that nothing happened. Fourth the decision: disposition, priority adjusted for context, then close or escalate with a clear package. Fifth documentation, so someone else reaches the same conclusion from my notes alone."

What makes this answer strong: it gives a repeatable process rather than a list of tools, separates false positive from benign positive by what needs fixing, explicitly guards against false negatives during scoping, and treats documentation and escalation as part of triage rather than afterthoughts.

</details>

## 8. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | NIST CSRC Glossary: event, incident, false positive, false negative | https://csrc.nist.gov/glossary/term/event<br>https://csrc.nist.gov/glossary/term/incident<br>https://csrc.nist.gov/glossary/term/false_positive<br>https://csrc.nist.gov/glossary/term/false_negative | primer (glosarium NIST) | diakses 2026-10-21 | Tinggi. Definisi event (SP 800-61r3 dan lainnya), incident (FISMA via SP 800-61r3, FIPS 200), false positive (SP 800-83r1, SP 800-86, SP 800-115), false negative (SP 800-83r1, SP 800-86) |
| S2 | NIST SP 800-61r3: Incident Response Recommendations and Considerations for Cybersecurity Risk Management | https://doi.org/10.6028/NIST.SP.800-61r3<br>https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf | primer | 2025-04; diakses 2026-10-21 | Tinggi. Event, adverse event, incident; penyaringan event (DE.AE); alert ke SOC (DE.AE-06); deklarasi insiden dengan mempertimbangkan FP yang dikenal (DE.AE-08); tuning FP dan FN (DE.CM); triage dan validasi (RS.MA-02); prioritas berbasis faktor risiko (RS.MA); eskalasi vs elevasi (RS.MA-04) |
| S3 | Microsoft Learn: Basic incident tasks for Microsoft Sentinel incidents in the Azure portal | https://learn.microsoft.com/en-us/azure/sentinel/incident-navigate-triage | primer (dokumentasi vendor) | diperbarui 2026-08-08; diakses 2026-10-21 | Tinggi. Klasifikasi wajib saat menutup: True Positive, Benign Positive, False Positive (logika, data), Undetermined; komentar penutupan |
| S4 | Microsoft Learn: Handle false positives in Microsoft Sentinel | https://learn.microsoft.com/en-us/azure/sentinel/false-positives | primer (dokumentasi vendor) | diperbarui 2026-08-08; diakses 2026-10-21 | Tinggi. Penyebab FP dari entitas tertentu dan pemindaian yang disengaja; automation rule dengan masa berlaku bawaan 24 jam; pengecualian di rule dan watchlist; menggabungkan atribut untuk mengurangi FN |
| S5 | Microsoft Learn: Manage incidents in the Microsoft Defender portal (legacy) | https://learn.microsoft.com/en-us/defender-xdr/manage-incidents | primer (dokumentasi vendor) | diperbarui 2026-09-23; diakses 2026-10-21 | Tinggi. Severity incident dari alert tertinggi; klasifikasi True positive, Informational expected activity, False positive; catatan resolusi; klasifikasi membantu penyetelan deteksi |
| S6 | Microsoft Learn: View and manage Microsoft Defender for Identity security alerts | https://learn.microsoft.com/en-us/defender-for-identity/understanding-security-alerts | primer (dokumentasi vendor) | diperbarui 2026-08-08; diakses 2026-10-21 | Tinggi. Definisi TP, B-TP, FP; faktor severity alert; tiga pertanyaan klasifikasi; tuning alert |
| S7 | Splunk Enterprise Security 8.5: Glossary | https://help.splunk.com/en/splunk-enterprise-security-8/release-notes-and-resources/8.5/where-to-find-help/glossary | primer (dokumentasi vendor) | diakses 2026-10-21 | Tinggi. Finding (dulu notable event, risk notable), intermediate finding, finding group, detection, analyst queue |
| S8 | Splunk Enterprise Security 8.5: Configure dispositions for findings | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/investigations/configure-dispositions-for-findings-in-splunk-enterprise-security | primer (dokumentasi vendor) | diakses 2026-10-21 | Tinggi. Daftar disposisi bawaan dan artinya; disposisi buatan sendiri |
| S9 | Splunk Enterprise Security 8.5: Create suppression rules for findings | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/investigations/create-suppression-rules-for-findings-in-splunk-enterprise-security | primer (dokumentasi vendor) | diakses 2026-10-21 | Tinggi. Suppression menyembunyikan finding yang tetap dibuat dan disimpan; throttling mencegah finding dibuat; masa berlaku; hitungan di dashboard audit |
| S10 | Splunk Enterprise Security 7.2: How urgency is assigned to notable events | https://help.splunk.com/en/splunk-enterprise-security-7/user-guide/7.2/incident-review/how-urgency-is-assigned-to-notable-events-in-splunk-enterprise-security | primer (dokumentasi vendor) | diakses 2026-10-21 | Tinggi untuk konsep urgency dari severity dan priority aset/identitas. Versi lama (ES 7.2); matriks bisa berbeda di versi lain |
| S11 | Alahmadi, Axon, Martinovic: 99% False Positives: A Qualitative Study of SOC Analysts' Perspectives on Security Alarms (USENIX Security 2022) | https://www.usenix.org/conference/usenixsecurity22/presentation/alahmadi | primer (penelitian peer-reviewed) | 2022-08; diakses 2026-10-21 | Tinggi untuk temuan kualitatif. Survei 20 praktisi dan studi kualitatif 21 praktisi; sebagian besar FP dipicu aktivitas sah; alarm burnout; lima sifat alarm. Sampel kecil |
| S12 | SANS: 2025 Detection and Response Survey (halaman ringkasan) | https://www.sans.org/research/detection-response-report | sekunder (survei industri) | 2025; diakses 2026-10-21 | Sedang. 73% responden menyebut FP tantangan utama (64% pada 2024); sekitar 60% sering menghadapi FP. Survei responden, bukan pengukuran |
| S13 | Google for Developers, Machine Learning Crash Course: Classification, accuracy, recall, precision | https://developers.google.com/machine-learning/crash-course/classification/accuracy-precision-recall | sekunder (materi pendidikan) | diakses 2026-10-21 | Tinggi untuk definisi umum. Confusion matrix, precision, recall, akurasi menyesatkan pada data tidak seimbang |
| S14 | PagerDuty: Incident Priority Matrix | https://www.pagerduty.com/resources/learn/incident-priority-matrix/ | sekunder (materi vendor) | diakses 2026-10-21 | Sedang. Priority dari dampak dan urgensi (ITIL). Tidak membedakan severity dari priority secara eksplisit |

**Catatan sumber:** pembedaan severity dan priority di bagian 1.6 disusun dari prinsip prioritas berbasis risiko NIST [S2], perhitungan urgency Splunk ES [S10], dan matriks dampak-urgensi ITIL [S14]; tidak ada definisi baku lintas organisasi yang memisahkan kedua kata itu, dan matriks priority, skala SEV, serta daftar kode penutupan PT JAB adalah susunan catatan ini. Lima langkah triage (konteks, validasi, cakupan, keputusan, dokumentasi) adalah susunan catatan ini berdasarkan rekomendasi NIST tentang tinjauan awal, dampak dan cakupan, dan kriteria insiden [S2]; NIST tidak memberi urutan langkah yang bernama sama. Penerapan confusion matrix ke alert SOC dan pembedaan dua jenis precision (butuh tindakan dan benar secara teknis) adalah penafsiran catatan ini atas definisi umum [S13]. Definisi alert fatigue ditulis dengan kata sendiri dari temuan penelitian [S11]; tidak ada entri glosarium NIST untuk istilah itu. Seluruh isi PT JAB (alert `SOC-2027-0858` sampai `0866`, insiden `INC-2027-090`, host, akun, tiket perubahan, angka antrean, dan rekap UC-034) adalah contoh fiktif.
