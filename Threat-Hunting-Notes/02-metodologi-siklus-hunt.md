---
day: 02
title: 'Metodologi hunting dan siklus hunt: hunting loop, fase PEAK, TaHiTI, tiga tipe hunt, dan handover'
researched_on: 2026-10-18
versions_checked: 'PEAK framework (Splunk: pengantar 2023-04-18, hypothesis-driven 2023-05-08, baseline 2023-07-11, Hierarchy of Detection Outputs 2023-07-26, metrik 2023-08-02, deliverables 2023-08-25); Sqrrl The Threat Hunting Reference Model Part 2: The Hunting Loop (2015-10-28); TaHiTI whitepaper (berkas di-host 2026-03); Sysmon v15.22 (halaman Microsoft Learn 2026-09-10); MITRE ATT&CK v20 (T1105 versi 2.6, diubah 2026-09-11); Atomic Red Team T1105 (test 7-9); LOLBAS (Certutil, Bitsadmin); Splunk Enterprise 10.6 (SPL)'
---

# Day 02: Metodologi hunting dan siklus hunt (hunting loop, PEAK, TaHiTI, dan handover)

Cakupan: urutan kerja sebuah hunt dari pemicu sampai serah terima, yaitu hunting loop, fase dan langkah PEAK, tiga fase dan enam langkah TaHiTI, tiga tipe hunt, kriteria sukses dan empat hasil, isi handover deteksi, dan peran knowledge, dipraktikkan lewat satu hunt LOLBin di PT JAB.

## Ide inti

Hunt bukan kegiatan sekali jalan yang berhenti saat analyst selesai mengetik query. Ia adalah siklus: dugaan dirumuskan, diuji dengan data, hasilnya dinilai, lalu hasil itu diserahkan ke pihak yang bisa bertindak dan memunculkan pertanyaan berikutnya. Hunting loop dari Sqrrl memberi bentuk paling sederhana dari siklus itu (empat tahap), sedangkan PEAK dan TaHiTI adalah dua cara mengoperasikannya: PEAK merinci langkah kerja tiap fase dan membedakan tiga tipe hunt, TaHiTI menegaskan abstract, backlog, validasi hipotesis, dan handover. Yang membuat sebuah hunt "selesai" bukan rasa capek, melainkan kriteria sukses yang ditulis sebelum Execute dan satu dari empat hasil yang dinyatakan bersama cakupannya. Yang membuat hunt bernilai adalah tahap terakhirnya: temuan ke IR, usulan deteksi ke pemilik konten detection, celah data ke pemilik telemetri, dan pertanyaan baru ke backlog.

Dari NOC kamu sudah mengenal dua hal yang sejajar dengan ini. Untuk gangguan yang belum punya prosedur, engineer senior tetap bekerja dengan metode baku: kumpulkan gejala, tentukan dugaan, uji satu per satu, catat hasil, lalu perbarui runbook. Di sisi administrasi, setiap pekerjaan mengikuti alur tiket: dibuka dengan deskripsi, dikerjakan, lalu diserahkan ke tim lapangan atau dijadikan alarm permanen di NMS. PEAK adalah metode kerja baku itu, TaHiTI adalah alur tiketnya, dan handover adalah serah terima ke tim lapangan atau ke konfigurasi alarm. Batas analoginya ada tiga. Langkah PEAK boleh dilewati atau diubah urutannya, jadi ia bukan checklist kaku. Fase Hunt di TaHiTI bolak-balik antara define/refine dan execute, tidak linear seperti tiket yang hanya maju. Dan query hunt jarang bisa langsung dipasang sebagai alarm: ia butuh ambang, pengecualian, dan uji, sama seperti threshold NMS baru yang tidak dipasang sebelum diukur dulu berapa kali ia akan berbunyi.

```
   pemicu (intel, insiden lama, celah deteksi, baseline, ATT&CK)
      |
      v
 +---------------------------+     TaHiTI: Initiate      PEAK: Prepare
 | 1 Create Hypothesis       |     (trigger -> abstract -> backlog)
 +---------------------------+
      |
      v
 +---------------------------+     TaHiTI: Hunt          PEAK: Execute
 | 2 Investigate             |<--+ (define/refine <-> execute)
 |   (tools & techniques)    |   |
 +---------------------------+   | refine
      |                          |
      v                          |
 +---------------------------+   |
 | 3 Uncover patterns & TTPs |---+   validasi: terbukti | tidak terbukti | inkonklusif | data tidak cukup
 +---------------------------+         |
      |                                +--> temuan berbahaya: eskalasi ke IR SEKARANG, jangan tunggu laporan
      v
 +---------------------------+     TaHiTI: Finalize      PEAK: Act
 | 4 Inform & enrich         |     (document -> handover; backlog di-update)
 |   automated analytics     |
 +---------------------------+
      |
      +--> IR | detection (Sari) | telemetri (Infrastruktur) | intel | backlog --> kembali ke 1
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan. SOC PT JAB memakai Splunk Enterprise 10.6 dengan Enterprise Security (ES) di search head terpisah. Sysmon terpasang di semua server Windows dan di workstation OU `Workstations-EDR`, sekitar 40% workstation; total sekitar 214 host mengirim Sysmon ke `index=sysmon`, tetapi event koneksi jaringan Sysmon (Event ID 3) hanya datang dari 198 host karena konfigurasi di 16 host lain tidak menyalakannya. Sejak Senin 2027-02-01, kamu, analyst L2, memegang "Program hunt PT JAB" setiap Selasa dan Kamis, dengan SOC lead Dimas Prasetyo sebagai sponsor. Hunt pertama, `HUNT-2027-001` (baseline pasangan parent-child proses), sedang berjalan. Senin sore kamu juga menulis abstract kedua, `HUNT-2027-002`, setelah membaca laporan intel publik tentang kampanye yang memakai program bawaan Windows untuk mengunduh tahap kedua. Selasa 2027-02-02 pukul 08:30, Sari Kusuma, analyst L2 yang memegang konten detection `JAB - ...` di ES, menulis di chat SOC:

> "Pagi. Kata Dimas, mulai bulan ini aku yang menerima usulan detection dari program hunt. Sebelum ada yang masuk, aku mau paham alurnya dulu. Satu hunt itu urutannya bagaimana dari awal sampai selesai? Di abstract `HUNT-2027-001` aku lihat tertulis PEAK dan TaHiTI; bedanya apa, dan kenapa dipakai dua-duanya? Kapan hunt pakai hipotesis dan kapan cuma melihat baseline? Kapan sebuah hunt dianggap selesai, apalagi kalau tidak menemukan apa-apa? Yang paling penting buatku: bentuk usulan yang akan aku terima seperti apa? Aku tidak mau menerima query mentah yang lalu fire ratusan kali sehari. Terakhir, kamu sering menulis 'jinak, sudah dikonfirmasi'. Dari mana kamu tahu mana yang normal di sini?"

Pesan itu memuat enam pertanyaan:

1. Bagaimana urutan langkah sebuah hunt dari awal sampai selesai?
2. Apa beda fase PEAK dan TaHiTI, dan kenapa keduanya dipakai bersama?
3. Tipe hunt mana yang dipakai untuk pemicu apa?
4. Kapan sebuah hunt dianggap selesai, termasuk bila tidak menemukan apa-apa?
5. Apa persisnya isi dan bentuk usulan deteksi yang diterima Sari?
6. Dari mana hunter tahu mana yang normal, dan apa peran knowledge?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2 dan 1.3, pertanyaan 3 di bagian 1.4 dan 2.8, pertanyaan 4 di bagian 1.5, pertanyaan 5 di bagian 1.6 dan 2.7, dan pertanyaan 6 di bagian 1.7. Bagian 2 menelusuri `HUNT-2027-002` melalui keempat tahap loop, dari abstract sampai handover ke Sari, dan ditutup dengan jawaban ringkas untuk Sari di bagian 2.9.

**Kapan relevan:** setiap hunt terencana, dari menit pertama (menulis abstract) sampai handover; saat menjelaskan ke penerima hasil hunt (IR, pemilik konten detection, tim telemetri) apa yang akan mereka terima; dan saat menilai apakah sebuah hunt sudah boleh ditutup.
**Kapan bukan jawaban:** eksplorasi data cepat untuk memutuskan apakah sebuah hunt layak dijadwalkan (siklus penuh baru berlaku setelah diputuskan layak); insiden yang sedang berjalan (itu IR dengan aturan main dan IC sendiri); dan pekerjaan yang hanya menjalankan ulang rule yang sudah ada.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah yang sudah dijelaskan di Day 01 (threat hunting, hipotesis, hunt abstract, backlog, stacking, long tail, PEAK, TaHiTI, HMM, handover) tidak diulang. Tabel ini memuat istilah baru yang dipakai Day ini; kolom kanan memetakannya ke pekerjaan NOC dan SOC.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Hunting loop | Model Sqrrl (2015): empat tahap hunt yang berulang, dari hipotesis sampai memperkaya deteksi otomatis | Siklus gangguan berulang: dugaan, uji, temuan, perbaikan alarm, lalu dugaan baru |
| Trailhead | Istilah Sqrrl untuk titik awal sebuah hunt | Gejala awal yang membuat engineer membuka tiket preventive maintenance |
| Define/refine | Langkah TaHiTI yang menajamkan abstract menjadi investigasi: hipotesis, sumber data, teknik analisis | Menyempitkan dugaan penyebab setelah tes pertama |
| Validasi hipotesis | Langkah akhir fase Hunt TaHiTI: hipotesis dinyatakan terbukti, tidak terbukti, atau inkonklusif | Menutup dugaan: "penyebabnya memang ini" atau "bukan ini" |
| Structured vs unstructured hunting | TaHiTI: hunting berbasis hipotesis dan cakupan vs menggali data tanpa hipotesis | Troubleshooting terarah vs menyisir log tanpa dugaan |
| Escalate Critical Findings | Langkah PEAK di fase Execute: aktivitas yang kemungkinan berbahaya diserahkan ke IR saat itu juga | Gangguan besar ditemukan saat patroli langsung jadi tiket P1, tidak menunggu laporan patroli |
| Time-box | Batas durasi hunt yang ditetapkan saat Scope Hunt | Jendela kerja maintenance yang sudah disetujui |
| Kriteria sukses | Kondisi tertulis yang menandai hunt boleh ditutup | Definisi "selesai" di tiket preventive maintenance |
| Celah deteksi | Data ada dan perilaku terlihat, tetapi belum ada rule | Counter error terbaca di NMS, tetapi belum ada threshold alarmnya |
| Celah visibilitas | Data tidak dikumpulkan, sehingga perilaku tidak mungkin terlihat | Router yang tidak mengirim syslog sama sekali |
| Hierarchy of Detection Outputs | Urutan PEAK untuk bentuk deteksi hasil hunt: report, dashboard, analytics in code, signatures and rules | Laporan mingguan, panel NMS, skrip pengecek, atau alarm otomatis |
| Abstract deteksi | Usulan deteksi tertulis dari hunt untuk pemilik konten detection; bukan rule jadi | Usulan threshold alarm baru beserta data pengukurannya |
| Friendly intelligence | Pengetahuan tentang lingkungan sendiri: inventaris, peta jaringan, aktivitas sah yang sudah dikonfirmasi | Inventaris perangkat dan daftar pekerjaan rutin yang diketahui NOC |
| LOLBin | Living-off-the-land binary: program bawaan sistem operasi yang bisa disalahgunakan, misalnya `certutil.exe` dan `bitsadmin.exe` | Tool diagnostik bawaan router yang juga bisa dipakai penyusup |
| Ingress Tool Transfer (T1105) | Teknik ATT&CK (taktik Command and Control): penyerang memindahkan tool atau file dari luar ke sistem korban | Perangkat asing yang diselundupkan masuk lewat jalur perawatan |
| `ProcessGuid` | Field Sysmon yang unik per proses, muncul di Event ID 1 dan diulang di event lain milik proses yang sama | Nomor tiket unik yang dipakai semua catatan terkait satu gangguan |

### 1.1 Hunting loop: urutan langkah sebuah hunt

Pertanyaan pertama Sari adalah pertanyaan urutan. Ia melihat `HUNT-2027-001` dimulai Senin dan ditargetkan selesai Kamis, tetapi tidak tahu apa yang terjadi di antaranya, dan di titik mana ia akan terlibat.

Model rujukan Sqrrl, yang diterbitkan Sqrrl Team pada 28 Oktober 2015, menggambarkan hunting sebagai loop empat tahap [S2]. Sqrrl menyebut titik awal sebuah hunt sebagai trailhead [S2].

```
   [1 Create Hypotheses]
            |
            v
   [2 Investigate via Tools & Techniques]
            |
            v
   [3 Uncover New Patterns & TTPs]
            |
            v
   [4 Inform & Enrich Analytics]
            |
            +-----------> kembali ke 1 (deteksi baru memunculkan hipotesis baru)
```

1. **Create Hypothesis.** Dugaan terdidik tentang aktivitas yang mungkin terjadi di lingkungan. Sqrrl menyarankan cara menyusunnya: petakan model serangan dan taktik yang mungkin dipakai, tentukan bagian mana yang sudah ditangkap alert otomatis, lalu rumuskan investigasi untuk sisanya [S2]. Day 03 membahas cara menulisnya.
2. **Investigate.** Uji hipotesis dengan data dan teknik analisis. Sqrrl menyebut visualisasi, analisis statistik, machine learning, serta teknik berbasis baris seperti stack counting dan clustering [S2]. Stacking dibahas di Day 05.
3. **Uncover Patterns and TTPs.** Temukan pola jahat baru dan rekonstruksi jalur serangan untuk mengungkap TTP penyerang. Sqrrl menyebut tahap ini kriteria sukses utama sebuah hunt [S2].
4. **Inform and Enrich Analytics.** Hunt yang berhasil menjadi dasar deteksi otomatis baru. Sqrrl menulis bahwa teknik yang terbukti berhasil sebaiknya diotomasi supaya tim tidak mengulang hunt yang sama terus-menerus, dan bahwa keluaran tahap ini bisa berupa pembaruan rule SIEM, intel atau indikator baru, maupun informasi tentang lingkungan sendiri [S2].

Kenapa loop: kamu tidak akan pernah mengamankan jaringan sepenuhnya dalam satu hunt [S2]. Tiap hunt memperbaiki deteksi, dan tiap perbaikan memunculkan hipotesis baru tentang apa yang masih lolos. Tahap 4 adalah titik temu hunting dengan detection engineering: pola yang ditemukan secara manual diserahkan untuk dijadikan rule otomatis, yang lalu ditulis, diuji terhadap data, di-tuning untuk false positive, dan dipantau kinerjanya. Begitu rule itu berjalan, hunter tidak perlu lagi mencari pola yang sama secara manual dan bisa mengejar pertanyaan berikutnya.

Ada satu hal di model Sqrrl yang perlu dibaca dengan hati-hati. Menyebut "uncover" sebagai kriteria sukses utama mudah disalahartikan menjadi "hunt hanya sukses bila menemukan penyerang". Kerangka yang lebih baru, termasuk PEAK, tidak mengukur hunt dari jumlah insiden yang ditemukan, karena hunter tidak mengendalikan kapan penyerang beraksi [S11]. Yang ditemukan di tahap 3 bisa juga berupa pola sah yang sekarang dipahami, atau celah data yang sekarang diketahui. Bagian 1.5 membahas ini.

Untuk Sari, jawabannya: ia masuk di tahap 4. Tahap 1 sampai 3 adalah pekerjaan hunter; yang sampai ke Sari adalah keluaran tahap 4 berupa usulan deteksi, bukan query mentah dari tahap 2.

### 1.2 PEAK: hunting loop yang dioperasionalkan

Pertanyaan kedua Sari datang dari abstract `HUNT-2027-001`, yang menulis "Tipe (PEAK): Baseline" sekaligus memakai format abstract TaHiTI. Subbagian ini menjelaskan PEAK; subbagian berikutnya menjelaskan TaHiTI dan kenapa keduanya dipakai bersama.

PEAK (Prepare, Execute, and Act with Knowledge) diperkenalkan Splunk pada 18 April 2023 oleh David Bianco bersama Ryan Fetterman [S1]. Ia membungkus loop ke dalam tiga fase, dengan Knowledge meresap di semuanya [S1]:

- **Prepare:** pilih topik, riset, tentukan cakupan, dan rencanakan hunt. Padanannya tahap 1 loop.
- **Execute:** masuk ke data dan analisis; pivot mengikuti temuan. Padanannya tahap 2 dan 3.
- **Act:** dokumentasi, komunikasi, dan otomasi (deteksi). Padanannya tahap 4.
- **Knowledge:** keahlian bisnis atau organisasi, threat intel, pengalaman hunter, dan temuan hunt yang sedang berjalan; dipakai di setiap fase. Bagian 1.7 membahasnya.

Untuk hunt hypothesis-driven, PEAK memecah tiap fase menjadi langkah berikut [S6]. Tabel ini adalah daftar periksa paling rinci yang tersedia untuk sebuah hunt; baca kolom "Isi singkat" untuk tahu apa yang harus ada di akhir tiap langkah.

| Fase | Langkah | Isi singkat |
|---|---|---|
| Prepare | Select Topic | Pilih area minat yang masih luas, misalnya data exfiltration; belum hipotesis |
| Prepare | Research Topic | Pelajari mekanisme umum, tool, celah deteksi yang ada, dan hunt serupa yang pernah dipublikasikan |
| Prepare | Generate Hypothesis | Ubah hasil riset menjadi pernyataan spesifik yang bisa dikonfirmasi atau dibantah (Day 03) |
| Prepare | Scope Hunt | Tentukan sistem, data, rentang waktu, dan bila perlu batas durasi hunt |
| Prepare | Plan | Rencanakan cara mengambil data, teknik analisis, dan pembagian kerja |
| Execute | Gather Data | Kumpulkan evidence yang dibutuhkan ke satu tempat |
| Execute | Pre-Process Data | Rapikan dan normalisasi data, buang record rusak |
| Execute | Analyze | Cari pola, anomali, dan bukti yang mendukung atau membantah hipotesis |
| Execute | Refine Hypothesis | Revisi hipotesis berdasarkan apa yang ditemukan atau tidak ditemukan |
| Execute | Escalate Critical Findings | Serahkan segera aktivitas yang kemungkinan atau pasti berbahaya ke IR, tanpa menunggu hunt selesai |
| Act | Preserve Hunt | Arsipkan data, query, dan teknik agar hunt bisa dirujuk atau diulang |
| Act | Document Findings | Tulis laporan: hipotesis terbukti atau tidak, celah, salah konfigurasi, insiden yang dieskalasi |
| Act | Create Detections | Ubah temuan menjadi rule produksi atau serahkan ke detection engineer |
| Act | Re-Add Topic to Backlog | Catat ide baru yang muncul sebagai topik atau hipotesis berikutnya |
| Act | Communicate Findings | Sampaikan hasil ke pihak terkait dalam format yang cocok untuk mereka |

Tiga langkah layak diingat karena sering dilupakan:

- **Escalate Critical Findings** berada di fase Execute, bukan Act. Artinya temuan berbahaya tidak menunggu laporan akhir; waktu menentukan dampak [S6].
- **Scope Hunt** boleh memuat batas durasi. Contoh di blog PEAK: hunt dijalankan tiga hari, dan bila tidak ada yang berbahaya dalam waktu itu, disimpulkan aktivitas itu kemungkinan tidak terjadi [S6]. Batas ini yang membuat hunt satu orang dua hari per minggu tetap bisa selesai.
- **Re-Add Topic to Backlog** adalah wujud konkret sifat siklus hunting loop. Preserve Hunt juga konkret: banyak tim memakai halaman wiki yang menautkan data, menjelaskan proses analisis, dan merangkum temuan [S6]. Di PT JAB, perannya diambil folder `hunts/HUNT-2027-NNN/` di repositori `jab-hunt` (abstract, laporan, dan folder `queries/`).

Langkah untuk tipe hunt lain berbeda. Hunt baseline, misalnya, memakai langkah Prepare: Select Data Source, Research Data Source, Scope Hunt, Plan; Execute: Gather Data, Create Data Dictionary, Review Distributions, Investigate Outliers, Gap Analysis, Identify Relationships; Act: Preserve Hunt, Document Baseline, Create Detections, Communicate Findings [S9]. Perbedaannya jelas: hunt baseline dimulai dari sumber data, bukan dari topik ancaman, dan menghasilkan data dictionary serta deskripsi "normal".

PEAK menegaskan langkah di tiap fase boleh dilewati, diubah urutannya, atau ditambah [S1]. Jadi fase bukan checklist kaku, melainkan pengingat bahwa hunt yang matang selalu punya persiapan, eksekusi, dan tindak lanjut.

### 1.3 TaHiTI: siklus yang sama dengan penekanan backlog, validasi, dan handover

TaHiTI (Targeted Hunting integrating Threat Intelligence) disusun bersama oleh beberapa bank di sektor keuangan Belanda; daftar penulisnya di whitepaper berasal dari de Volksbank, Rabobank, ING, dan ABN AMRO, dengan Rob van Os sebagai penulis utama [S3]. Blog pengantar PEAK menyebut TaHiTI berasal dari 2018 [S1]. "Targeted" karena hunt digerakkan hipotesis; "integrating threat intelligence" karena intel menjadi sumber utama hipotesis, dipakai untuk memperkaya hunt, dan juga dihasilkan oleh hunt [S3].

TaHiTI memecah hunt menjadi tiga fase dan enam langkah [S3]:

- **Initiate:** (1) pemicu hunt (trigger), lalu (2) trigger ditulis menjadi investigation abstract dan disimpan di backlog. Abstract hanya deskripsi dasar; sebagian besar isinya dirinci ulang saat hunt dipilih untuk dikerjakan. Backlog tidak perlu alat rumit; SharePoint atau JIRA cukup, asalkan tim bisa memilih abstract paling relevan untuk hunt berikutnya [S3].
- **Hunt:** (3) define/refine: perkaya abstract, tentukan hipotesis, sumber data, dan teknik analisis; lalu (4) execute: ambil data, analisis, dan validasi hipotesis. Bila analisis menemukan kekurangan pada definisi, hunter kembali ke define/refine. Perbaikan bisa menyentuh hipotesis, cakupan, sumber data, atau teknik analisis, dan diulang sampai investigasinya optimal [S3].
- **Finalize:** (5) dokumentasikan temuan, lalu (6) handover ke proses lain. Backlog diperbarui di fase ini [S3].

Diagram proses TaHiTI memuat satu garis putus-putus yang mudah terlewat: dari langkah analisis data langsung ke handover [S3]. Itu padanan Escalate Critical Findings di PEAK: temuan berbahaya diserahkan saat itu juga, tanpa menunggu Finalize.

TaHiTI juga membedakan dua jenis hunting. Unstructured hunting adalah hunting berbasis data: hunter menggali data untuk mencari anomali tanpa hipotesis dan tanpa jalur yang ditentukan. Structured hunting berbasis hipotesis: hipotesis dibuat, cakupan ditentukan, lalu hunt dijalankan. TaHiTI sendiri adalah pendekatan terstruktur [S3]. Bagian 1.4 menghubungkan pembedaan ini dengan tiga tipe hunt PEAK.

Tabel berikut menempatkan tiga kerangka itu berdampingan. Cari baris "Paling kuat di", karena di situlah alasan PT JAB memakai dua kerangka sekaligus.

| Aspek | Hunting loop (Sqrrl, 2015) | PEAK (Splunk, 2023) | TaHiTI (sektor keuangan Belanda, 2018) |
|---|---|---|---|
| Bentuk | Empat tahap berulang | Tiga fase, langkah rinci per tipe hunt, Knowledge di semua fase | Tiga fase, enam langkah |
| Awal | Create Hypothesis | Prepare | Initiate: trigger, abstract, backlog |
| Tengah | Investigate, Uncover | Execute (termasuk eskalasi segera) | Hunt: define/refine dan execute, bolak-balik, diakhiri validasi |
| Akhir | Inform and Enrich | Act | Finalize: document, handover, backlog di-update |
| Paling kuat di | Menjelaskan kenapa hunting berulang | Langkah kerja dan tipe hunt | Format abstract, backlog, validasi, handover, peran intel |

Ketiganya bukan pesaing. Hunting loop adalah ide intinya; PEAK dan TaHiTI adalah dua cara mengoperasikannya. Keputusan PT JAB sejak Day 01: PEAK dipakai untuk memilih tipe hunt dan alur kerja, TaHiTI untuk format abstract, backlog, dan handover. Kosakata itu dipakai konsisten di repositori `jab-hunt`, supaya Sari, Dimas, dan tim Infrastruktur membaca istilah yang sama di setiap laporan.

Supaya pemetaan ini tidak abstrak, tabel berikut menelusuri `HUNT-2027-001` (Day 01, selesai Kamis 2027-02-04) melalui ketiga kerangka. Baca kolom kanan dan perhatikan bahwa baris "persempit" kembali ke define/refine di tengah eksekusi.

| Kejadian di `HUNT-2027-001` | Loop | PEAK | TaHiTI |
|---|---|---|---|
| Abstract ditulis Senin 2027-02-01: pemicu celah deteksi dari `INC-2026-026`, tipe baseline, Sysmon EID 1, 7 hari | 1 Create Hypothesis | Prepare | Initiate |
| Stacking 4.812.330 event menjadi 3.214 pasangan unik, 1.146 pasangan langka | 2 Investigate | Execute: Gather Data, Analyze | Hunt: execute |
| Long tail terlalu panjang, pertanyaan dipersempit ke parent Office, pembaca PDF, browser, dan WMI | 2 Investigate | Execute: Refine Hypothesis | Hunt: kembali ke define/refine |
| Tiga pasangan ditinjau lewat `CommandLine`; semuanya jinak terkonfirmasi | 3 Uncover | Execute: Analyze | Hunt: validasi hipotesis (tidak terbukti) |
| Laporan, usulan rule ke Sari, celah Sysmon ke tim Infrastruktur, dua hipotesis baru ke backlog | 4 Inform and Enrich | Act | Finalize: document, handover |

### 1.4 Tiga tipe hunt dan pemicunya

Pertanyaan ketiga Sari ("kapan pakai hipotesis, kapan cuma melihat baseline") menyangkut tipe hunt. Jawabannya ditentukan oleh seberapa jelas pertanyaanmu dan seberapa kenal kamu dengan datanya.

PEAK membedakan tiga tipe hunt [S1]. Tabel ini menunjukkan kapan tiap tipe dipakai; kolom "Keluaran khas" adalah apa yang bisa diharapkan penerima hasil.

| Tipe | Cara kerja | Kapan dipakai | Keluaran khas |
|---|---|---|---|
| Hypothesis-Driven | Rumuskan dugaan ancaman, lalu konfirmasi atau bantah dengan data [S1] | Ada ide spesifik dari intel, ATT&CK, insiden lama, atau celah deteksi | Hipotesis terbukti atau tidak terbukti; usulan deteksi |
| Baseline (EDA) | Bangun gambaran "normal", lalu cari penyimpangan [S1] | Belum ada hipotesis spesifik; sumber data baru atau lingkungan baru | Data dictionary, baseline, daftar outlier berlabel, hipotesis turunan [S9] |
| Model-Assisted (M-ATH) | Model machine learning atas perilaku baik atau jahat, cari yang menyimpang atau cocok [S1] | Data besar, pola sulit dinyatakan sebagai aturan | Kandidat berperingkat; hipotesis turunan |

Blog PEAK tentang baseline menyebut pemicu yang khas untuk tipe ini: onboarding sumber log baru, supaya field dan nilainya dipahami sebelum dipakai untuk deteksi, dan mulai bekerja di lingkungan baru, misalnya setelah akuisisi atau saat menerima pelanggan managed security baru. Baseline juga disebut sebagai pendahulu yang sangat baik untuk hunt yang lebih terfokus [S9].

Hubungan dengan pembedaan TaHiTI (bagian 1.3): hypothesis-driven adalah structured hunting. Baseline lebih dekat ke unstructured hunting karena tidak dimulai dari hipotesis, tetapi di PEAK ia tetap punya cakupan, rencana, dan keluaran tertulis, sehingga tidak sama dengan "mengaduk data sampai bosan".

Hubungan antar tipe: baseline dan M-ATH sering menghasilkan hipotesis yang lalu dikejar secara hypothesis-driven. Day 01 memulai `HUNT-2027-001` dengan baseline (stacking parent-child), yang bila menemukan sesuatu berubah menjadi hunt hypothesis-driven. M-ATH dibahas ringkas di Day 05; catatan ini berfokus pada dua tipe pertama karena paling bisa dibuktikan tanpa infrastruktur ML.

Pemicu (trigger) juga ikut menentukan tipe. TaHiTI mendaftar pemicu dari beberapa proses: intel tentang aktor ancaman, hunt lain, use case monitoring yang belum lengkap, insiden historis, red teaming, analisis crown jewel, keahlian domain, dan ATT&CK. TaHiTI menyebut ATT&CK sebagai pemicu yang sangat penting karena memuat vektor dan teknik serangan [S3]. TaHiTI juga mencatat bahwa proses yang memberi pemicu tumpang tindih dengan proses yang menerima hasil hunt; hunting yang berjalan baik mempercepat perbaikan proses-proses itu [S3]. Bagian 2.8 memetakan tiga pemicu nyata PT JAB ke tipe hunt.

### 1.5 Kriteria sukses, time-box, dan empat hasil

Pertanyaan keempat Sari ("kapan dianggap selesai, apalagi kalau tidak menemukan apa-apa") adalah pertanyaan yang juga akan diajukan Dimas setiap Kamis.

Sebelum mengeksekusi, abstract harus menyatakan kriteria sukses: kondisi yang menandai hunt selesai, bukan "sampai capek". Contoh: "semua pasangan parent-child langka dari parent berisiko dalam 7 hari sudah ditinjau dan diberi label". Kriteria sukses yang baik punya tiga ciri:

- Bisa diperiksa orang lain: "semua X ditinjau dan dilabeli" bisa dicek di laporan, "sampai tidak ada yang mencurigakan" tidak.
- Terikat pada cakupan: data apa, rentang kapan, host mana.
- Disertai time-box bila sumber dayanya terbatas. PEAK menyarankan batas durasi opsional saat Scope Hunt [S6]. Bila time-box habis sebelum kriteria terpenuhi, yang dilaporkan adalah apa yang sudah ditinjau, dan sisanya ditulis sebagai di luar cakupan atau inkonklusif. Melaporkan "tidak ditemukan" untuk baris yang tidak pernah dibuka adalah kesalahan.

TaHiTI menyebut hasil validasi hipotesis secara eksplisit: terbukti (aktivitas berbahaya ditemukan, IR dimulai), tidak terbukti (tidak ada aktivitas berbahaya), atau inkonklusif (kembali ke define/refine untuk mengubah parameter dan mengulang). Bila data yang dibutuhkan tidak tersedia, hunt dianggap gagal, tetapi tetap bisa menghasilkan pelajaran [S3]. Tabel ini menghubungkan empat hasil itu dengan penerimanya; kolom kanan adalah siapa yang menerima apa.

| Hasil | Arti | Handover |
|---|---|---|
| Terbukti (proven) | Hipotesis terkonfirmasi; ada aktivitas berbahaya | IR, segera (tidak menunggu laporan) |
| Tidak terbukti (disproven) | Hipotesis terbantah dengan cakupan jelas | Dokumentasi; sering usulan deteksi pencegah |
| Inkonklusif | Data ada tetapi tidak cukup untuk menyimpulkan | Ulangi define/refine |
| Gagal (data tidak ada) | Telemetri tidak tersedia | Rekomendasi perbaikan data; pelajaran |

Ada satu kasus yang sering membingungkan: aktivitas yang cocok dengan pola hipotesis tetapi ternyata sah. Contohnya admin yang memakai `certutil.exe` untuk mengunduh installer dari situs vendor (bagian 2.5). Pola yang dicari ditemukan, tetapi hipotesis tentang aktivitas berbahaya tetap tidak terbukti. Di laporan, kejadian itu dicatat sebagai "ditemukan, jinak terkonfirmasi", lengkap dengan buktinya, dan hasil hunt secara keseluruhan tetap "tidak terbukti". Kejadian semacam ini justru bahan paling berharga untuk Sari, karena ia adalah false positive pertama yang akan muncul bila polanya dijadikan rule.

"Tidak terbukti" dan "gagal karena data" bukan kegagalan hunter; keduanya menghasilkan nilai. Bedakan dua jenis celah yang dihasilkannya:

- **Celah deteksi:** datanya ada dan perilakunya terlihat di log, tetapi belum ada rule yang memicu alert. Perbaikannya menulis rule. Penerimanya Sari.
- **Celah visibilitas:** datanya tidak dikumpulkan sama sekali, sehingga perilaku tidak mungkin terlihat. Perbaikannya menambah atau mengonfigurasi telemetri lebih dulu; menulis rule sebelum itu sia-sia. Penerimanya tim Infrastruktur (Agung Prabowo) atau pemilik sistem.

Memisahkan keduanya di laporan membuat rekomendasi hunt langsung bisa ditindaklanjuti oleh tim yang tepat.

Cara mengukur keberhasilan juga ikut menentukan kapan hunt "selesai". Blog metrik PEAK (2 Agustus 2023) menyatakan bahwa jumlah insiden yang ditemukan selama hunt adalah ukuran yang lemah: hunter tidak mengendalikan kapan penyerang beraksi, sehingga hunt yang tidak menemukan apa-apa bukan berarti gagal atau tidak bernilai [S11]. Metrik yang diusulkan berfokus pada dampak, bukan aktivitas [S11]:

- deteksi yang dibuat atau diperbarui dari hunt (termasuk yang berkurang false positive-nya);
- insiden yang terbuka karena deteksi hasil hunt, bukan insiden yang ditemukan saat hunt;
- celah yang dilaporkan dan yang kemudian ditutup (sumber data hilang, akses, dokumentasi, alat);
- kerentanan dan salah konfigurasi yang dilaporkan dan yang diperbaiki;
- jumlah teknik unik yang sudah di-hunt, idealnya dipetakan ke ATT&CK.

Konsekuensinya untuk PT JAB: hunt dianggap selesai bila kriteria sukses terpenuhi (atau time-box habis dan sisanya tertulis), hasilnya satu dari empat di atas, dan setiap keluaran sudah punya penerima. Metrik program dibahas di Day 15.

### 1.6 Handover: apa yang diterima IR, Sari, dan tim lain

Pertanyaan kelima Sari adalah inti kekhawatirannya: ia tidak mau menerima query mentah yang lalu fire ratusan kali sehari. Kekhawatiran itu tepat, karena query hunt dioptimalkan untuk ditinjau manusia satu kali, bukan untuk berjalan setiap lima menit.

Hunt yang berakhir tanpa handover adalah pekerjaan yang hilang. TaHiTI mendaftar proses penerima hasil hunt: security incident response (memulai IR), security monitoring (membuat atau memperbarui use case), threat intelligence (menghasilkan TTP dan menyebarkannya), vulnerability management (menutup kerentanan), dan rekomendasi lain [S3]. Dokumentasi di fase Finalize memuat hasil terpenting, kesimpulan, rekomendasi (perbaikan preventif, logging, use case monitoring, proses), dan bagian lessons learned tentang bagaimana hunt membuat hunter lebih baik [S3]. PEAK merumuskan hal serupa sebagai enam deliverable: insiden keamanan (dieskalasi segera, idealnya sudah dilengkapi konteks user, host, dan aktivitas di sekitarnya), dokumentasi hunt, deteksi baru atau yang diperbaiki, celah dan risiko, ide hunt untuk backlog, serta laporan dan briefing untuk pemangku kepentingan [S12]. Tidak semua deliverable berlaku untuk setiap hunt [S12].

Diringkas per tujuan:

- **Ke IR:** saat menemukan aktivitas berbahaya. Serahkan bukti, waktu, host, akun, dan hipotesis. Di PT JAB penerimanya Dimas sebagai IC atau L2 on-call.
- **Ke pemilik konten detection:** saat menemukan pola yang bisa dideteksi otomatis. Ini tahap 4 loop; serahkan sebagai abstract deteksi, bukan rule jadi. Di PT JAB penerimanya Sari.
- **Ke pemilik sistem atau vulnerability management:** saat menemukan salah konfigurasi atau kerentanan, bukan serangan.
- **Ke pemilik telemetri:** saat menemukan celah visibilitas. Di PT JAB penerimanya tim Infrastruktur (Agung Prabowo) dan NOC.
- **Ke intel:** saat menemukan TTP atau indikator baru yang memperkaya pengetahuan ancaman.
- **Ke dirimu sendiri (backlog):** saat hunt memunculkan pertanyaan baru. PEAK menekankan bahwa pekerjaan di luar cakupan dicatat sebagai ide, bukan dikejar saat itu juga, untuk mencegah scope creep [S12].

Untuk Sari, keputusan penting berikutnya adalah bentuk deteksinya. PEAK menyusun Hierarchy of Detection Outputs, empat bentuk keluaran dari yang paling sedikit sampai paling banyak otomasi [S10]. Tabel ini dipakai untuk memilih bentuk; baca kolom "Pilih bila".

| Level | Bentuk | Pilih bila | Catatan |
|---|---|---|---|
| 1 | Reports | Hasil pencarian banyak berisi aktivitas jinak dan butuh penilaian analyst | Dijadwalkan harian, mingguan, atau bulanan ke antrean tiket; level paling tidak diinginkan, ditinjau ulang secara berkala |
| 2 | Dashboards dan visualisasi | Ringkasan lebih berguna daripada event satu per satu, tetapi hasil belum cukup yakin untuk alert | Masih butuh perhatian manusia rutin |
| 3 | Analytics in code | Aktivitasnya jelas, tetapi butuh skrip atau program untuk menghitungnya; umum pada hunt M-ATH | Keluarannya harus cukup akurat untuk alert SIEM; pastikan jadwalnya andal |
| 4 | Signatures dan rules | Hasil cukup yakin untuk langsung ditaruh di depan analyst sebagai alert | Paling diutamakan bila memungkinkan |

Cara memilihnya menurut PEAK: di akhir hunt, tanyakan apakah kamu sudah tahu cara menemukan aktivitas itu, walaupun tidak menemukan apa-apa. Lalu tanyakan apakah kamu yakin menaruh hasilnya di depan analyst SOC sebagai alert. Bila ya, pakai level 3 atau 4; bila tidak, level 1 atau 2. Selalu pilih level tertinggi yang realistis, dan satu hunt boleh menghasilkan beberapa level sekaligus [S10]. Pertanyaan pertama itu penting: hunt yang hasilnya "tidak terbukti" tetap bisa menghasilkan deteksi, karena hunter sudah tahu seperti apa jejak aktivitas itu di data.

Bentuk serah terima ke Sari adalah abstract deteksi. Isi minimalnya:

- tujuan deteksi (perilaku apa) dan teknik ATT&CK;
- sumber data dan field yang dipakai;
- logika kasar (kondisi yang memicu), bukan query final;
- level di Hierarchy of Detection Outputs yang diusulkan;
- perkiraan volume dari data hunt (berapa kali pola itu muncul dalam rentang hunt);
- contoh event positif dari hunt atau dari uji lab;
- sumber false positive yang sudah terlihat saat hunting (misalnya tool admin yang memang memakai LOLBin) dan usulan pengecualian yang sempit;
- saran tindakan analyst saat alert muncul;
- celah yang membatasi deteksi (host tanpa data, field yang tidak lengkap).

Abstract seperti ini memungkinkan Sari menilai kelayakan sebelum menulis rule, dan menjawab langsung kekhawatirannya: angka volume dan daftar false positive ada sebelum rule dipasang. Contoh lengkapnya ada di bagian 2.7. Proses dari usulan sampai rule produksi dibahas di Day 14.

### 1.7 Knowledge: dari mana hunter tahu yang normal

Pertanyaan terakhir Sari menyentuh hal yang membuat label "jinak, sudah dikonfirmasi" bisa dipercaya. Label itu tidak datang dari query; ia datang dari pengetahuan tentang PT JAB.

PEAK menempatkan Knowledge di pusat karena hunt yang baik berdiri di atas empat sumber pengetahuan [S1]:

- **Keahlian organisasi atau bisnis:** apa yang normal di lingkungan ini, aset mana yang penting.
- **Threat intelligence:** aktor dan TTP yang relevan dengan sektor dan teknologi organisasi, dari laporan publik, feed, atau tim CTI internal.
- **Pengalaman hunter:** pola yang pernah kamu lihat. Pengalaman SOC dan forensikmu masuk di sini.
- **Temuan hunt berjalan:** apa yang baru saja kamu pelajari, dipakai untuk pivot.

Sqrrl memberi nama untuk jenis pertama: friendly intelligence, yaitu informasi tentang lingkungan sendiri dan cara lingkungan itu seharusnya berjalan, seperti peta jaringan, inventaris software, dan daftar web server resmi. Makin banyak yang kamu tahu tentang jaringanmu, makin baik kamu bisa mempertahankannya, jadi temuan seperti ini layak dicatat setiap kali muncul saat hunt [S2]. Di PT JAB, friendly intelligence yang sudah terkumpul dari hunt pertama antara lain: makro rekonsiliasi Keuangan yang memanggil `cmd.exe`, inventaris software helpdesk lewat WMI dari `JKT-JUMP01`, dan add-in tanda tangan email Customer Service. Ditambah aplikasi sah yang dikenal di 214 perangkat, `JAB DocSync`. Daftar ini disimpan di repositori `jab-hunt` supaya hunt berikutnya tidak mengonfirmasi ulang hal yang sama, dan supaya Sari punya daftar pengecualian yang sudah diperiksa.

Hunt baseline adalah cara sistematis membangun knowledge itu. PEAK menyebut keluaran hunt baseline: data dictionary (nama field, deskripsi, tipe data, arti nilai), deskripsi statistik "normal" (rata-rata, nilai umum, kardinalitas), hubungan antar field, dan daftar outlier yang terbukti jinak beserta hasil investigasinya. Baseline itu bisa dibagi ke analyst SOC, incident responder, dan detection engineer [S9].

TaHiTI menambahkan sisi intel. Ada tiga hubungan antara intel dan hunting [S3]:

- **Intel sebagai titik awal:** laporan tentang kelompok penyerang yang beroperasi di sektor dan wilayahmu bisa memicu hunt dan memberi konteks ancamannya.
- **Intel untuk memberi konteks dan mengarahkan hunt:** saat hunt menemukan satu TTP, intel dan ATT&CK membantu mencari TTP terkait. Proses ini disebut pivoting, dan bisa memperluas cakupan, menambah data, menajamkan hipotesis, atau menghasilkan ide hunt berikutnya.
- **Hunting untuk menghasilkan intel:** hunt bisa mengungkap TTP yang belum dikenal, yang lalu masuk ke profil penyerang dan bisa dibagi ke komunitas.

Tanpa Knowledge, baseline tidak bisa ditafsirkan (mana yang "aneh" bila kamu tidak tahu yang "normal") dan hipotesis menjadi tebakan buta. Itu juga jawaban untuk Sari: "jinak, sudah dikonfirmasi" berarti ada bukti di luar query, misalnya tiket change, konfirmasi pemilik sistem, atau pola yang sudah tercatat sebagai friendly intelligence.

## 2. Contoh dan langkah praktis: `HUNT-2027-002` dari abstract sampai handover

Bagian ini menelusuri satu hunt PT JAB melalui empat tahap loop, sekaligus contoh konkret dari apa yang akan diterima Sari. Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi; query ditulis untuk Splunk PT JAB, dan versi yang disesuaikan untuk lab pribadi ada di bagian 3.

Asumsi data untuk semua query di bagian ini: Sysmon dikirim universal forwarder dan diparsing Splunk Add-on for Sysmon ke `index=sysmon` dengan `sourcetype=XmlWinEventLog`; field `Image`, `CommandLine`, `ParentImage`, `User`, `ProcessGuid`, `DestinationIp`, `DestinationHostname`, dan `DestinationPort` terekstrak dengan nama aslinya dari XML Sysmon. Sebagian data model CIM memakai nama lain (misalnya `process_guid`); cek nama field di lingkunganmu sebelum menjalankan.

### 2.1 Abstract: dari trigger ke rencana (Prepare / Initiate)

Abstract ini ditulis Senin 2027-02-01 sore, setelah kamu membaca laporan intel publik dari sebuah vendor keamanan tentang kampanye yang menargetkan operator telekomunikasi di Asia Tenggara. Laporan itu menyebut bahwa setelah akses awal, penyerang memakai program bawaan Windows untuk mengunduh tahap kedua, bukan malware khusus untuk tahap itu. Pemicunya intel aktor ancaman, salah satu pemicu di daftar TaHiTI (bagian 1.4).

```
ID             : HUNT-2027-002
Dibuat         : 2027-02-01 (Senin), pemilik: <kamu>, reviewer: Dimas Prasetyo
Trigger        : Threat intel - laporan publik vendor keamanan: kampanye terhadap operator telekomunikasi
                 di Asia Tenggara memakai LOLBin Windows untuk mengunduh tahap kedua
Tipe (PEAK)    : Hypothesis-driven (diturunkan dari intel)
Hipotesis      : Di host Windows ber-Sysmon PT JAB, ada proses LOLBin (certutil, bitsadmin, mshta,
                 regsvr32, rundll32) yang mengunduh file dari alamat eksternal atau membuat koneksi keluar
                 ke alamat eksternal, tanpa memicu alert apa pun.
ATT&CK         : T1105 Ingress Tool Transfer (Command and Control, TA0011)
Data           : Sysmon EID 1 (process creation) dan EID 3 (network connection), index=sysmon,
                 semua host ber-Sysmon (sekitar 214: server Windows + workstation OU Workstations-EDR),
                 Senin 2027-01-18 00:00 sampai Senin 2027-02-01 00:00 WIB (14 hari)
Di luar cakupan: host tanpa Sysmon (sekitar 60% workstation); bagian koneksi di host yang tidak
                 mengirim EID 3 (dicek sebelum pivot); unduhan lewat PowerShell atau curl.exe;
                 LOLBin yang diganti nama
Teknik analisis: Filter LOLBin, tandai argumen unduhan atau URL, stacking per program,
                 pivot EID 1 ke EID 3 lewat ProcessGuid, tinjau tujuan koneksi
Kriteria sukses: Semua eksekusi LOLBin dalam daftar yang memuat URL atau switch unduhan ditinjau dan
                 dilabeli (jinak / perlu investigasi / data tidak cukup); semua koneksi keluar dari
                 proses itu ditinjau. Time-box: satu hari hunting (Selasa 2027-02-02)
Hasil mungkin  : terbukti (ke IR) | tidak terbukti | inkonklusif | gagal (data EID 3 tidak ada)
Handover       : IR (Dimas) bila terbukti; Sari Kusuma (konten detection ES) untuk usulan deteksi;
                 tim Infrastruktur (Agung Prabowo) untuk celah telemetri; backlog bila muncul pertanyaan baru
```

Abstract ini adalah seluruh fase Prepare dalam satu halaman. Menulisnya memaksa kamu memutuskan cakupan sebelum tergoda mengaduk data. Cara membaca elemen yang baru dibanding abstract Day 01:

- **Hipotesis** menyebut perilaku (mengunduh, koneksi keluar), tempat (host Windows ber-Sysmon), dan kondisi celah (tanpa alert). Bentuk ini membuatnya bisa dibantah oleh data.
- **Di luar cakupan** sudah menyebut celah EID 3, walaupun jumlah host persisnya baru dicek di bagian 2.3. Celah yang sudah diketahui ditulis di depan.
- **Time-box** satu hari membuat hunt ini realistis untuk satu orang. Bila tidak selesai, sisanya ditulis sebagai di luar cakupan (bagian 1.5).

Daftar LOLBin di hipotesis adalah pilihan, bukan daftar lengkap. Proyek LOLBAS, katalog komunitas untuk binary bawaan Windows yang bisa disalahgunakan, memetakan fungsi unduh `certutil.exe` dan `bitsadmin.exe` ke T1105; keduanya cukup dengan hak akses user biasa dan ada di `System32` maupun `SysWOW64` [S14][S15]. ATT&CK juga menyebut certutil dan perintah unduh PowerShell sebagai contoh di Windows, dan BITSAdmin sebagai contoh prosedur [S13].

**Kapan gagal:** hipotesis memakai daftar LOLBin dari ingatan tanpa memeriksa sumber, sehingga program yang justru disebut di laporan intel tidak masuk filter. Cocokkan daftar dengan laporan pemicunya dan dengan katalog seperti LOLBAS sebelum Execute.

### 2.2 Investigate: stacking eksekusi LOLBin (Execute, tahap 2)

Query ini adalah langkah Execute pertama `HUNT-2027-002`: menghitung berapa kali tiap LOLBin dijalankan dan berapa di antaranya membawa URL atau switch unduhan.

**Tujuan:** melihat skala tiap LOLBin dalam 14 hari dan memisahkan eksekusi yang memuat indikator unduhan dari yang tidak.

```
index=sysmon sourcetype=XmlWinEventLog EventCode=1
    earliest="01/18/2027:00:00:00" latest="02/01/2027:00:00:00"
    (Image="*\\certutil.exe" OR Image="*\\bitsadmin.exe" OR Image="*\\mshta.exe"
     OR Image="*\\regsvr32.exe" OR Image="*\\rundll32.exe")
| eval proc=lower(mvindex(split(Image, "\\"), -1))
| eval dl=if(match(lower(CommandLine), "https?://|urlcache|verifyctl|/transfer"), 1, 0)
| stats count AS runs sum(dl) AS runs_dl dc(host) AS hosts
        dc(eval(if(dl=1, host, null()))) AS hosts_dl BY proc
| sort runs
```

Tabel berikut menjelaskan tiap bagian query; perhatikan baris `eval dl`, karena di situlah hipotesis diterjemahkan menjadi kondisi.

| Bagian | Fungsi |
|---|---|
| `EventCode=1` dan rentang absolut | Hanya process creation, 14 hari tetap, supaya hunt bisa diulang dengan hasil yang sama |
| Filter `Image="*\\certutil.exe" OR ...` | Batasi ke LOLBin yang jadi fokus hipotesis. Pencocokan nilai field di command `search` tidak peka huruf besar/kecil |
| `eval proc=lower(mvindex(split(Image, "\\"), -1))` | Ambil nama file saja, supaya versi `System32` dan `SysWOW64` tergabung dalam satu baris |
| `eval dl=if(match(...), 1, 0)` | Tandai eksekusi yang memuat URL (`http://` atau `https://`) atau switch unduhan (`urlcache`, `verifyctl` untuk certutil, `/transfer` untuk bitsadmin). Pola tanpa tanda minus juga menangkap `/urlcache`, karena certutil menerima kedua awalan |
| `sum(dl)` dan `dc(eval(if(dl=1, host, null())))` | Jumlah eksekusi bertanda unduhan dan jumlah host tempat itu terjadi |
| `sort runs` | Paling jarang di atas |

Keluaran ilustrasi:

```
proc            runs     runs_dl  hosts  hosts_dl
mshta.exe       2        0        2      0
bitsadmin.exe   6        6        3      3
certutil.exe    41       2        9      1
regsvr32.exe    1388     0        176    0
rundll32.exe    212640   57       214    31
```

**Cara membaca hasil:** ada 65 eksekusi bertanda unduhan (6 + 2 + 57). Tiga hal langsung terlihat:

- `rundll32.exe` dijalankan di semua 214 host karena Windows memakainya terus-menerus; 57 eksekusinya membawa URL. Itu terlalu banyak untuk diabaikan, tetapi terlalu banyak juga untuk dianggap mencurigakan sebelum command line-nya dibaca.
- `certutil.exe` muncul 41 kali di 9 host, tetapi hanya 2 yang membawa indikator unduhan, dan keduanya di satu host. Sisanya perlu dilihat sekilas (misalnya pemeriksaan hash file oleh skrip admin) untuk memastikan tidak ada bentuk unduhan lain yang lolos dari pola.
- `mshta.exe` hanya 2 kali tanpa URL. Ia tidak memenuhi kriteria unduhan, tetapi dua baris itu murah untuk ditinjau dan dicatat.

**Variasi:** stacking `ParentImage` untuk 65 eksekusi itu (`| where dl=1 | stats count BY proc ParentImage`), karena parent sering langsung menjelaskan konteks: LOLBin yang dijalankan aplikasi email berbeda maknanya dengan yang dijalankan `cmd.exe` dari sesi admin.

**Kapan gagal:** penyerang memakai salinan LOLBin yang diganti nama, sehingga `Image` tidak cocok dengan filter (Sysmon juga mencatat `OriginalFileName`; pemakaiannya dibahas di Day 13); argumen unduhan memakai bentuk yang tidak ada di pola (misalnya URL tanpa skema); atau unduhan dilakukan lewat PowerShell dan `curl.exe`, yang memang sudah ditulis di luar cakupan.

### 2.3 Cek data sebelum pivot: host mana yang mengirim EID 3

Sebelum memakai EID 3 untuk menjawab "apakah proses ini membuat koneksi keluar", pastikan dulu host-nya memang mengirim EID 3. Tanpa langkah ini, "tidak ada koneksi" bisa berarti "tidak ada data".

**Tujuan:** menghitung host ber-Sysmon yang mengirim EID 1 tetapi tidak mengirim EID 3 dalam rentang hunt.

```
index=sysmon sourcetype=XmlWinEventLog (EventCode=1 OR EventCode=3)
    earliest="01/18/2027:00:00:00" latest="02/01/2027:00:00:00"
| stats count(eval(EventCode=1)) AS eid1 count(eval(EventCode=3)) AS eid3 BY host
| eval eid3_status=if(eid3>0, "ada EID 3", "tanpa EID 3")
| stats count AS host_count values(eval(if(eid3=0, host, null()))) AS host_tanpa_eid3 BY eid3_status
```

| Bagian | Fungsi |
|---|---|
| `count(eval(EventCode=1))` | Jumlah EID 1 per host; host dengan nilai 0 tidak mengirim process creation sama sekali |
| `count(eval(EventCode=3))` | Jumlah EID 3 per host |
| `eval eid3_status=...` | Label per host |
| `stats count ... BY eid3_status` | Ringkasan, dengan daftar host yang tidak punya EID 3 |

Keluaran ilustrasi:

```
eid3_status    host_count  host_tanpa_eid3
ada EID 3      198
tanpa EID 3    16          (16 nama host)
```

**Cara membaca hasil:** 214 host mengirim Sysmon, 198 di antaranya mengirim EID 3, dan 16 tidak. Microsoft mendokumentasikan bahwa event koneksi jaringan Sysmon nonaktif secara default dan hanya tercatat bila konfigurasi menyalakan `NetworkConnect` [S7]; jadi 16 host ini kemungkinan besar memakai konfigurasi Sysmon tanpa tag itu. Saat daftar 16 host dicocokkan dengan 31 host tempat `rundll32.exe` membawa URL (bagian 2.2), 4 host ada di daftar itu, dengan 9 dari 57 eksekusi. Host `certutil.exe` dan ketiga host `bitsadmin.exe` mengirim EID 3.

**Variasi:** tambahkan `count(eval(EventCode=22))` untuk melihat cakupan `DnsQuery` sekaligus; Day 04 membahas pemeriksaan kesiapan data secara lengkap.

**Kapan gagal:** host yang baru dipasang Sysmon di tengah rentang terlihat "punya EID 3" walaupun hanya beberapa hari; host yang mati sebagian besar rentang terlihat normal. Untuk keputusan yang lebih tegas, lihat juga tanggal event pertama dan terakhir per host.

### 2.4 Pivot: menghubungkan eksekusi dengan koneksi keluarnya lewat `ProcessGuid`

Langkah ini menjawab bagian kedua hipotesis: apakah proses LOLBin yang membawa indikator unduhan memang membuat koneksi keluar, dan ke mana.

**Tujuan:** menggabungkan EID 1 dan EID 3 per proses, lalu melihat proses bertanda unduhan mana yang punya koneksi.

Sysmon memberi setiap proses sebuah GUID unik di EID 1, dan GUID yang sama muncul di event lain milik proses itu, termasuk EID 3 [S7]. Microsoft menulis bahwa `ProcessGuid` disertakan supaya korelasi event tetap bisa dilakukan walaupun Windows memakai ulang process ID [S7]. Berbeda dengan `ProcessId` yang bisa dipakai ulang setelah proses berakhir, GUID tidak bertabrakan, sehingga korelasi antar event tetap tepat walau rentangnya 14 hari.

```
index=sysmon sourcetype=XmlWinEventLog (EventCode=1 OR EventCode=3)
    earliest="01/18/2027:00:00:00" latest="02/01/2027:00:00:00"
    (Image="*\\certutil.exe" OR Image="*\\bitsadmin.exe" OR Image="*\\mshta.exe"
     OR Image="*\\regsvr32.exe" OR Image="*\\rundll32.exe")
| eval dl=if(EventCode=1 AND match(lower(CommandLine), "https?://|urlcache|verifyctl|/transfer"), 1, 0)
| stats min(_time) AS first_seen values(host) AS host values(User) AS user
        values(ParentImage) AS parent values(CommandLine) AS cmd max(dl) AS dl
        count(eval(EventCode=3)) AS conns values(DestinationIp) AS dest_ip
        values(DestinationHostname) AS dest_host values(DestinationPort) AS dest_port
        BY ProcessGuid
| where dl=1
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S")
| sort - conns first_seen
```

| Bagian | Fungsi |
|---|---|
| `(EventCode=1 OR EventCode=3)` dengan filter `Image` yang sama | Ambil process creation dan koneksi dari LOLBin yang sama. EID 3 juga membawa field `Image` |
| `eval dl=if(EventCode=1 AND ...)` | Tanda unduhan hanya dihitung dari EID 1, karena EID 3 tidak punya `CommandLine` |
| `stats ... BY ProcessGuid` | Satu baris per proses: data eksekusi dari EID 1 dan semua tujuan koneksi dari EID 3 |
| `count(eval(EventCode=3)) AS conns` | Berapa koneksi yang dicatat untuk proses itu |
| `where dl=1` | Hanya 65 proses bertanda unduhan |
| `sort - conns first_seen` | Proses dengan koneksi di atas |

Keluaran ilustrasi (dua baris teratas, lalu ringkasan):

```
first_seen           host        user           cmd                                                                                                   conns dest_ip       dest_host                    dest_port
2027-01-21 10:14:07  jkt-mgmt01  JAB\adm.hari  certutil.exe -urlcache -split -f https://downloads.nicvendor.example/tools/nicutil-4.2.zip C:\Tools\nicutil-4.2.zip               1     203.0.113.148  downloads.nicvendor.example  443
2027-01-21 10:15:02  jkt-mgmt01  JAB\adm.hari  certutil.exe -urlcache -split -f https://downloads.nicvendor.example/tools/nicutil-4.2.zip.sha256 C:\Tools\nicutil-4.2.zip.sha256 1     203.0.113.148  downloads.nicvendor.example  443

Ringkasan 65 proses bertanda unduhan:
proses dengan conns > 0 : 2   (certutil.exe, jkt-mgmt01)
proses dengan conns = 0 : 63  (bitsadmin.exe 6, rundll32.exe 57; 9 dari 57 rundll32 di 4 host tanpa EID 3)
```

**Cara membaca hasil:** hanya dua proses yang benar-benar terlihat mengunduh dari luar, keduanya `certutil.exe` di server `jkt-mgmt01` oleh akun admin `adm.hari`, ke `downloads.nicvendor.example` (`203.0.113.148`) port 443. Sysmon menulis waktu event dalam UTC [S7]; Splunk menampilkan `_time` sesuai zona waktu akun pengguna, yang di PT JAB disetel WIB, jadi 10:14:07 di atas adalah WIB. Sisanya, 63 proses tanpa koneksi, tidak bisa dibaca sebagai satu kelompok:

- **`bitsadmin.exe` (6):** host-nya mengirim EID 3, tetapi `bitsadmin.exe` hanya membuat job BITS. Transfer dijalankan layanan BITS yang berjalan di dalam `svchost.exe`, sehingga koneksi tercatat atas nama `svchost.exe`, bukan `bitsadmin.exe`. Pivot lewat `ProcessGuid` secara desain tidak akan pernah menemukan koneksi itu. Ini keterbatasan metode, bukan bukti tidak ada unduhan.
- **`rundll32.exe` di 27 host ber-EID 3 (48 eksekusi):** tidak ada koneksi dari proses itu sendiri. Ini konsisten dengan pola yang dibahas di bagian 2.5.
- **`rundll32.exe` di 4 host tanpa EID 3 (9 eksekusi):** "tidak ada koneksi" di sini berarti "tidak ada data". Penilaian untuk 9 eksekusi ini hanya bisa memakai command line dan parent.

**Variasi:** versi dengan `join`, yang lebih mudah dibaca tetapi lebih rapuh:

```
index=sysmon sourcetype=XmlWinEventLog EventCode=1 Image="*\\certutil.exe"
    earliest="01/18/2027:00:00:00" latest="02/01/2027:00:00:00"
| join type=inner ProcessGuid
    [ search index=sysmon sourcetype=XmlWinEventLog EventCode=3 Image="*\\certutil.exe"
        earliest="01/18/2027:00:00:00" latest="02/01/2027:00:00:00"
      | fields ProcessGuid DestinationIp DestinationPort DestinationHostname ]
| table _time host User CommandLine DestinationIp DestinationPort DestinationHostname
```

`join` menjalankan subsearch untuk sisi kanan, dan hasil subsearch untuk `join` dibatasi secara default 50.000 baris dan 60 detik sebelum dihentikan; nilai itu diatur di `limits.conf` stanza `[join]` (`subsearch_maxout`, `subsearch_maxtime`) [S16]. Untuk satu LOLBin langka seperti certutil, batas itu aman. Untuk `rundll32.exe` dengan ratusan ribu event, subsearch bisa terpotong diam-diam dan hasil join tampak lengkap padahal tidak. Karena itu versi `stats ... BY ProcessGuid` di atas dipakai sebagai query utama. Cek nilai batas di versi Splunk-mu, karena dokumentasi yang dibaca adalah tabel batas Splunk Cloud.

**Kapan gagal:** field GUID diekstrak dengan nama lain setelah normalisasi add-on (misalnya `process_guid`), sehingga `BY ProcessGuid` mengelompokkan semuanya ke nilai kosong; filter `Image` membuang EID 3 milik `svchost.exe`, sehingga unduhan BITS tidak pernah terlihat; atau host tidak mengirim EID 3 (bagian 2.3).

### 2.5 Uncover: validasi dan label (Execute, tahap 3)

Tahap ini mengubah baris query menjadi pernyataan yang bisa dipertanggungjawabkan. Setiap kelompok diberi label dengan bukti di luar query, sesuai jawaban untuk pertanyaan keenam Sari (bagian 1.7).

- **`certutil.exe` di `jkt-mgmt01` (2 proses), ditemukan, jinak terkonfirmasi.** `jkt-mgmt01` adalah server manajemen tim Infrastruktur yang berjalan tanpa antarmuka grafis, jadi tidak ada browser untuk mengunduh file. `adm.hari` adalah akun admin Fajar Nugroho, engineer Infrastruktur. Kamis 2027-01-21 ia mengunduh utilitas konfigurasi kartu jaringan dari situs vendor beserta file checksum-nya, sesuai tiket change yang disetujui Agung Prabowo untuk pembaruan firmware NIC server virtualisasi. Pivot tambahan mendukung cerita itu: EID 11 (FileCreate) mencatat dua file di `C:\Tools\` dari proses yang sama; tidak ada proses anak dari `certutil.exe`; dan tidak ada koneksi lain ke `203.0.113.148` dari host mana pun dalam 14 hari. Fajar mengonfirmasi lewat chat, dan menyebut bahwa ia memakai certutil karena memang itu yang tersedia di server. Label: jinak. Catatan: ini persis pola yang dicari hipotesis. Bila polanya dijadikan rule, kejadian seperti ini akan menjadi false positive pertama, dan penanganannya bukan pengecualian per host (bagian 2.7).
- **`bitsadmin.exe` (6 proses di 3 workstation), jinak terkonfirmasi untuk bagian eksekusi.** Command line menunjukkan `/transfer` ke `http://jkt-repo01.corp.jab.example/drivers/...`, repositori driver internal, dijalankan skrip lama tim IT saat memasang driver printer. Tujuan internal, bukan eksternal. Bagian transfer yang dijalankan `svchost.exe` tidak diuji (bagian 2.4); itu ditulis sebagai keterbatasan dan masuk backlog.
- **`rundll32.exe` dengan URL (57 proses di 31 host), jinak sebagai kelompok.** Semua 57 command line memakai bentuk `rundll32.exe url.dll,FileProtocolHandler https://...`, dengan parent `OUTLOOK.EXE` atau aplikasi chat kantor. Ini cara aplikasi membuka tautan di browser default: `rundll32.exe` hanya meneruskan URL ke browser, dan koneksi dibuat oleh browser. Untuk 48 eksekusi di 27 host ber-EID 3, tidak adanya koneksi dari `rundll32.exe` sendiri cocok dengan penjelasan itu. Untuk 9 eksekusi di 4 host tanpa EID 3, label didasarkan pada command line dan parent saja. Label: jinak; untuk 9 eksekusi itu, dicatat bahwa bukti koneksi tidak tersedia.
- **`mshta.exe` (2 proses, tanpa URL), di luar kriteria, dicatat.** Keduanya menjalankan file HTA lokal dari folder installer driver printer. Tidak ada argumen URL.

Validasi hipotesis (langkah akhir fase Hunt TaHiTI): tidak terbukti. Di host ber-Sysmon, selama 14 hari, untuk lima LOLBin dalam daftar, tidak ada unduhan dari alamat eksternal selain dua unduhan admin yang sah. Itu belum berarti PT JAB bersih dari T1105; artinya, pertanyaan ini, dengan data dan cakupan ini, terjawab "tidak".

Bila hasilnya berbeda, misalnya `certutil.exe` dijalankan oleh `WINWORD.EXE` di workstation Customer Service ke domain yang baru terdaftar, langkahnya adalah Escalate Critical Findings: hubungi Dimas saat itu juga dengan host, akun, waktu, command line, dan tujuan koneksi, tanpa menunggu laporan (bagian 1.2). Laporan hunt tetap ditulis kemudian, dan hunt itu berpindah aturan main menjadi IR.

**Kapan gagal:** label "jinak" diberikan karena akunnya admin. Akun admin adalah target favorit penyerang; yang membuat kejadian `jkt-mgmt01` jinak adalah tiket change, konfirmasi orangnya, dan jejak file yang konsisten, bukan nama akunnya.

### 2.6 Laporan `HUNT-2027-002` (Act / Finalize)

Laporan ini adalah langkah Document Findings PEAK dan Finalize TaHiTI. Formatnya sama dengan laporan `HUNT-2027-001` (Day 01 bagian 2.4), ditambah baris handover per penerima.

```
ID            : HUNT-2027-002                          Selesai: Selasa 2027-02-02
Hasil         : Tidak terbukti
Cakupan nyata : Host Windows ber-Sysmon (214), Sysmon EID 1 dan EID 3,
                Senin 2027-01-18 00:00 - Senin 2027-02-01 00:00 WIB (14 hari)
                LOLBin: certutil, bitsadmin, mshta, regsvr32, rundll32
Di luar cakupan: Host tanpa Sysmon (sekitar 60% workstation); koneksi dari 16 host tanpa EID 3
                (9 eksekusi rundll32 dinilai dari command line saja); transfer BITS (koneksi atas nama
                svchost.exe); unduhan lewat PowerShell dan curl.exe; LOLBin yang diganti nama
Angka         : 65 eksekusi bertanda unduhan (certutil 2, bitsadmin 6, rundll32 57); 2 dengan koneksi keluar
Ditemukan, jinak terkonfirmasi:
                certutil -urlcache di jkt-mgmt01 oleh adm.hari, 2027-01-21 10:14 dan 10:15 WIB,
                ke downloads.nicvendor.example (203.0.113.148:443), sesuai tiket change Infrastruktur
Jinak lain    : bitsadmin /transfer ke jkt-repo01 (skrip driver tim IT); rundll32 url.dll,FileProtocolHandler
                (membuka tautan dari Outlook dan aplikasi chat); mshta dengan HTA lokal installer
Celah data    : 16 host ber-Sysmon tanpa NetworkConnect -> tim Infrastruktur (Agung Prabowo)
Deteksi       : Abstract deteksi "JAB - certutil atau bitsadmin mengunduh dari URL eksternal" -> Sari Kusuma
Intel         : Tidak ada indikator atau TTP baru untuk diteruskan
Hipotesis baru: (1) unduhan tahap kedua lewat PowerShell dan curl.exe; (2) transfer BITS ke tujuan
                eksternal dilihat dari sisi layanan BITS -> backlog
Friendly intel: Server manajemen tanpa GUI memakai certutil untuk unduhan vendor; dicatat di jab-hunt
Pelajaran     : Pivot ProcessGuid buta terhadap transfer BITS; cek cakupan EID 3 sebelum menyimpulkan
                "tidak ada koneksi"
```

"Tidak terbukti" di laporan ini punya cakupan, angka, jinak yang terkonfirmasi, celah data, dan empat tindak lanjut dengan penerima masing-masing. Itulah yang membuatnya bisa dipertanggungjawabkan, dan sekaligus jawaban konkret untuk pertanyaan keempat Sari.

**Kapan gagal:** baris "Di luar cakupan" hanya menyebut "host tanpa Sysmon" dan melupakan keterbatasan metode (BITS, PowerShell). Celah metode sama pentingnya dengan celah data, karena pembaca laporan tidak bisa menebaknya sendiri.

### 2.7 Handover ke Sari dan ke backlog

Ini artefak yang ditanyakan Sari di pertanyaan kelima: bentuk usulan yang akan ia terima. Pertanyaan PEAK untuk memilih bentuk deteksi (bagian 1.6) dijawab dulu: apakah kita tahu cara menemukan aktivitas ini? Ya, untuk certutil dan bitsadmin dengan URL eksternal. Apakah kita yakin menaruhnya di depan analyst sebagai alert? Ya, karena volumenya 2 kejadian dalam 14 hari dan keduanya mudah diverifikasi. Jadi level yang diusulkan adalah signatures dan rules. Untuk `rundll32.exe` dengan FileProtocolHandler, jawabannya tidak: 57 kejadian jinak dalam 14 hari dan tidak ada pembeda yang jelas, sehingga tidak diusulkan sebagai rule.

```
Usulan deteksi : JAB - certutil atau bitsadmin mengunduh dari URL eksternal
Asal           : HUNT-2027-002 (tidak terbukti), selesai Selasa 2027-02-02
Tujuan         : Alert saat LOLBin unduhan dipakai mengambil file dari luar jaringan PT JAB
ATT&CK         : T1105 Ingress Tool Transfer (Command and Control)
Data dan field : index=sysmon, EID 1: host, User, Image (atau OriginalFileName), CommandLine,
                 ParentImage, ProcessGuid. Opsional: EID 3 (tujuan koneksi), EID 11 (file yang dibuat)
Logika kasar   : nama proses certutil.exe DAN CommandLine memuat urlcache atau verifyctl DAN URL
                 ATAU nama proses bitsadmin.exe DAN CommandLine memuat /transfer DAN URL
                 DAN host di URL bukan *.corp.jab.example
Level (PEAK)   : Signatures & rules; urgensi rendah-sedang
Volume dari hunt: 2 kejadian dalam 14 hari di 214 host (keduanya certutil, jkt-mgmt01, sah);
                 bitsadmin ke tujuan eksternal: 0
Contoh positif : 2 event jkt-mgmt01 2027-01-21 (jinak); uji lab Atomic Red Team T1105 test 7, 8, 9
                 (GUID dicocokkan dengan katalog) sebelum rule diaktifkan
FP diketahui   : Unduhan admin Infrastruktur dari server manajemen tanpa GUI, dengan tiket change
Pengecualian   : Tidak ada di awal. Volume rendah; analyst memverifikasi tiket change. Bila nanti
                 perlu, pengecualian sempit per kombinasi akun + domain tujuan, bukan per host
Triage         : Cek tiket change; tanya pemilik akun; cek domain tujuan dan umur domain;
                 cek file yang dibuat (EID 11) dan proses anak; eskalasi ke IR bila tidak ada penjelasan
Celah          : Hanya host ber-Sysmon (214); rename binary lolos bila rule hanya memakai Image;
                 bitsadmin /addfile dan job BITS dari PowerShell tidak tertangkap logika ini
Tidak diusulkan: rundll32 url.dll,FileProtocolHandler (57 kejadian jinak dalam 14 hari, tanpa pembeda)
```

Cara membaca elemennya dari sisi Sari:

- **Volume dari hunt** menjawab kekhawatiran "fire ratusan kali sehari": data 14 hari menunjukkan 2 kejadian.
- **Pengecualian** sengaja kosong. Dengan volume serendah ini, verifikasi manual lebih murah daripada risiko pengecualian yang terlalu lebar. Pengecualian per host (`jkt-mgmt01`) akan membutakan rule tepat di server yang paling menarik bagi penyerang.
- **Tidak diusulkan** sama pentingnya dengan yang diusulkan. Sari tidak perlu menebak kenapa rundll32 tidak masuk.
- **Logika kasar** bukan query final. Sari yang memutuskan apakah rule dibangun di atas data model, apakah memakai risk-based alerting, dan berapa interval jadwalnya. Proses itu dibahas di Day 14.

Dua hipotesis baru masuk backlog di `jab-hunt/backlog/BACKLOG.md`, belum diberi nomor hunt karena belum dijadwalkan:

```
Masuk backlog (dari HUNT-2027-002, 2027-02-02)
(a) Unduhan tahap kedua lewat PowerShell (Invoke-WebRequest, Net.WebClient) dan curl.exe
    Trigger: celah cakupan HUNT-2027-002; ATT&CK T1105, T1059.001
    Data   : Sysmon EID 1 (curl.exe, powershell.exe), index=powershell (script block)
(b) Transfer BITS ke tujuan eksternal, dilihat dari sisi layanan BITS, bukan bitsadmin.exe
    Trigger: keterbatasan metode HUNT-2027-002; ATT&CK T1105, T1197 BITS Jobs
    Data   : perlu dicek sumber yang mencatat job BITS di Splunk; EID 3 dari svchost.exe
             dengan tujuan eksternal sebagai pendekatan awal
```

Handover ketiga ke Agung Prabowo berupa satu paragraf dan daftar 16 host ber-Sysmon tanpa `NetworkConnect` dari query bagian 2.3, dengan alasan bisnisnya: tanpa EID 3, setiap hunt yang bergantung pada koneksi proses di host itu hanya bisa berakhir "data tidak cukup".

**Kapan gagal:** abstract deteksi dikirim tanpa angka volume, atau dikirim sebagai query hunt apa adanya. Sari lalu harus mengulang pekerjaan hunt untuk mengukur sendiri, dan usulan itu menumpuk di antrean.

### 2.8 Memilih tipe hunt untuk tiga pemicu PT JAB

Tabel ini menjawab pertanyaan ketiga Sari dengan pemicu nyata di PT JAB. Baca kolom "Alasan", karena alasannya yang bisa dipakai ulang untuk pemicu lain.

| Pemicu | Tipe yang cocok | Alasan |
|---|---|---|
| Laporan intel: aktor memakai LOLBin untuk unduh tahap kedua (`HUNT-2027-002`) | Hypothesis-driven | Hipotesis sudah jelas dari intel; perilaku dan teknik ATT&CK bisa ditulis sebelum melihat data |
| Wazuh 4.14 di `jkt-wazuh01` baru mengirim alert dari server Linux sejak Desember 2026, dan belum ada yang tahu seperti apa normalnya | Baseline (EDA) | Sumber data baru; kenali field, nilai umum, dan outlier jinak dulu, lalu turunkan hipotesis [S9] |
| Pasangan parent-child di 214 host terlalu banyak untuk ditinjau manual (`HUNT-2027-001` menemukan 1.146 pasangan langka) | Baseline sekarang; model-assisted bila kelak ada infrastruktur ML | M-ATH memberi peringkat kandidat, tetapi PT JAB belum punya infrastruktur ML; persempit dengan pertanyaan dulu |

**Kapan gagal:** hipotesis dipaksakan untuk sumber data yang belum dikenal. Hunt hypothesis-driven atas alert Wazuh tanpa tahu field dan volume normalnya akan menghasilkan "tidak terbukti" yang tidak berarti apa-apa, karena hunter tidak tahu apakah query-nya buta.

### 2.9 Jawaban untuk Sari

Ringkasan berikut kamu kirim ke Sari Selasa sore bersama laporan `HUNT-2027-002`. Setiap baris merujuk subbagian di atas, supaya Sari bisa membaca alasannya bila perlu.

| Pertanyaan Sari | Jawaban singkat | Dasar |
|---|---|---|
| Urutan sebuah hunt | Hipotesis, investigasi, temuan dan validasi, lalu inform and enrich; berulang | Bagian 1.1 |
| PEAK dan TaHiTI | Dua cara mengoperasikan loop yang sama; PEAK untuk langkah kerja dan tipe hunt, TaHiTI untuk abstract, backlog, validasi, dan handover | Bagian 1.2, 1.3 |
| Hipotesis atau baseline | Hipotesis bila pertanyaan sudah jelas (intel, ATT&CK, insiden lama); baseline untuk sumber data atau lingkungan baru | Bagian 1.4, 2.8 |
| Kapan selesai | Kriteria sukses dan time-box ditulis sebelum Execute; hasil salah satu dari empat, dengan cakupan; setiap keluaran punya penerima | Bagian 1.5, 2.6 |
| Bentuk usulan untuk Sari | Abstract deteksi dengan volume dari data hunt, FP yang terlihat, level PEAK, dan yang tidak diusulkan; bukan query mentah | Bagian 1.6, 2.7 |
| Dari mana tahu yang normal | Knowledge: friendly intelligence, intel, pengalaman, temuan berjalan; "jinak" butuh bukti di luar query | Bagian 1.7, 2.5 |

**Kapan gagal:** jawaban dikirim tanpa contoh nyata. Sari bertanya bentuk usulan; contoh bagian 2.7 menjawabnya lebih baik daripada penjelasan kerangka mana pun.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** Splunk lab dengan Sysmon dari minimal satu VM Windows (snapshot bersih), konfigurasi Sysmon yang menyalakan `NetworkConnect` dan `FileCreate`, dan `hunts/BACKLOG.md` di repo portofolio pribadi berisi tiga abstract dari lab Day 01. Jangan memakai data, nama, atau kejadian dari pekerjaan nyata; PT JAB hanya contoh fiktif.

1. **Petakan kerangka.** Gambar hunting loop, lalu di sampingnya tulis fase PEAK dan langkah TaHiTI yang bersesuaian, seperti tabel bagian 1.3. Petakan juga satu hunt dari lab Day 01 ke tabel itu. Simpan sebagai `docs/hunt-frameworks.md`.
2. **Anotasi backlog.** Untuk tiap abstract di backlog, tambahkan baris Tipe (hypothesis-driven, baseline, atau M-ATH) dan alasannya memakai bagian 1.4. Tambahkan kriteria sukses dan time-box ke setiap abstract.
3. **Tulis abstract hunt LOLBin.** Pakai format bagian 2.1 dengan rentang absolut yang sesuai data lab-mu. Isi "Di luar cakupan" sebelum menjalankan query apa pun.
4. **Cek data dulu.** Jalankan query bagian 2.3 di lab. Catat berapa host yang mengirim EID 1 dan EID 3. Bila EID 3 tidak ada, hentikan bagian koneksi dan tulis hasilnya sebagai "data tidak cukup" untuk bagian itu.
5. **Buktikan query menangkap target.** Di VM lab dengan snapshot, jalankan satu test jinak Atomic Red Team untuk T1105 Ingress Tool Transfer. Tiga test Windows yang relevan dengan hipotesis ini ada di tabel berikut [S8]; kolom GUID dipakai untuk mencocokkan, karena nomor urut test bisa bergeser.

   | Test | Nama | GUID | Yang terjadi |
   |---|---|---|---|
   | T1105-7 | certutil download (urlcache) | `dd3b61dd-7bbc-48cd-ab51-49ad1a776df0` | `certutil.exe` dengan switch `-urlcache` mengunduh file teks lisensi dari web ke folder lokal |
   | T1105-8 | certutil download (verifyctl) | `ffd492e3-0455-4518-9fb1-46527c9f241b` | `certutil.exe` dengan switch `-verifyctl` mengunduh file ke folder bertanggal, lalu file dipindah |
   | T1105-9 | Windows - BITSAdmin BITS Download | `a1921cd3-9a2d-47d5-a891-f1d0f2a7a31b` | `bitsadmin.exe /transfer` membuat job BITS yang mengunduh file ke `%temp%` |

   Yang harus terlihat di log: EID 1 dengan `Image` berakhiran `certutil.exe` atau `bitsadmin.exe` dan `CommandLine` memuat switch di atas plus sebuah URL; EID 3 dari proses yang sama (atau dari service BITS untuk test 9, karena unduhan BITS dijalankan oleh `svchost.exe`, bukan oleh `bitsadmin.exe`); dan EID 11 (FileCreate) untuk file hasil unduhan bila konfigurasi Sysmon mencatatnya. Ulangi query bagian 2.2 dan pastikan `runs_dl` naik untuk LOLBin itu. Tidak ada test mshta di katalog T1105. Jalankan cleanup test (menghapus file unduhan), lalu kembalikan snapshot.
6. **Pivot.** Jalankan query bagian 2.4 untuk rentang yang mencakup uji langkah 5. Pastikan test 7 dan 8 menghasilkan `conns` lebih dari 0 dan test 9 tidak. Lalu cari koneksi test 9 dari sisi `svchost.exe` pada menit yang sama, dan catat field apa yang bisa menghubungkannya dengan job BITS (dan yang tidak bisa).
7. **Bandingkan `stats` dan `join`.** Jalankan versi `join` di bagian 2.4 untuk certutil, lalu untuk `rundll32.exe`. Catat waktu eksekusi dan apakah Splunk menampilkan pesan bahwa subsearch dipotong.
8. **Label dan laporan.** Beri label setiap baris (jinak, perlu investigasi, data tidak cukup) dengan bukti satu kalimat. Isi laporan dengan format bagian 2.6, termasuk bila hasilnya "tidak terbukti".
9. **Handover.** Tulis satu abstract deteksi ke `handover/` dengan format bagian 2.7, termasuk level di Hierarchy of Detection Outputs, angka volume dari lab, dan bagian "Tidak diusulkan". Tulis minimal satu hipotesis baru ke backlog.

**Hasil yang sebaiknya tersimpan:**

- Peta tiga kerangka dengan satu hunt yang sudah dipetakan.
- Setiap abstract backlog punya tipe hunt, alasan, kriteria sukses, dan time-box.
- Angka cakupan EID 1 dan EID 3 di lab.
- GUID test yang dijalankan, waktu eksekusi, dan bukti query bagian 2.2 dan 2.4 menangkapnya.
- Catatan perbandingan `stats` dan `join` (waktu, pesan subsearch).
- Laporan hunt lengkap dengan hasil, cakupan, dan keterbatasan metode.
- Satu abstract deteksi dan satu hipotesis baru di backlog.

**Variasi tantangan:** jalankan hunt yang sama sebagai baseline murni (tanpa daftar LOLBin): stacking semua `Image` yang membuat koneksi keluar (EID 3) berdasarkan `dc(DestinationIp)`, lalu cari proses yang menghubungi banyak IP unik. Bandingkan temuan dengan pendekatan hypothesis-driven, dan catat tipe mana yang lebih cepat menemukan sesuatu di lab-mu. Variasi kedua: ubah pola `eval dl` di bagian 2.2 supaya juga menangkap `bitsadmin /addfile`, lalu uji dengan kasus positif dan negatif yang kamu tulis sendiri.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat menjalankan siklus hunt penuh. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Hunt tidak pernah selesai | Tidak ada kriteria sukses atau time-box | Tetapkan di abstract sebelum Execute (bagian 1.5, 2.1) |
| Investigasi melebar tanpa arah | Pivot tanpa mencatat pertanyaan | Tulis pertanyaan tiap pivot; simpan ke backlog, bukan dikejar semua [S12] |
| `join` EID 1 dan EID 3 lambat atau hasilnya kurang | Subsearch terpotong di batas default 50.000 baris atau 60 detik | Pakai `stats ... BY ProcessGuid` (bagian 2.4); cek `limits.conf` stanza `[join]` [S16] |
| Pivot `BY ProcessGuid` menghasilkan satu baris besar | Field GUID beda nama atau kosong | Cek nama field di event mentah; samakan dengan `coalesce` bila perlu |
| LOLBin bertanda unduhan tanpa koneksi | Host tanpa EID 3, atau transfer dijalankan proses lain (BITS) | Jalankan cek cakupan (bagian 2.3); cari koneksi dari `svchost.exe` pada waktu yang sama |
| Query EID 3 kosong di lab | `NetworkConnect` tidak dinyalakan di konfigurasi Sysmon | EID 3 nonaktif default [S7]; perbarui konfigurasi dan uji ulang |
| Temuan tidak diserahkan | Handover tidak direncanakan | Tentukan penerima di abstract [S3] |
| Usulan deteksi tidak pernah dipasang | Dikirim sebagai query mentah tanpa volume dan FP | Pakai format abstract deteksi (bagian 2.7) |
| Tipe hunt salah pilih | Hipotesis dipaksakan padahal data belum dikenal | Mulai baseline untuk mengenal normal, baru hypothesis-driven [S9] |
| Baseline tidak bermakna | Lab terlalu sepi (Day 01) | Perpanjang rentang atau tambah aktivitas normal |

## 5. Kesalahan umum dan jebakan

- **Melewati fase Act.** Hunt tanpa handover dan dokumentasi hilang nilainya; tahap 4 loop yang membuat hunting menjadi siklus [S2].
- **Menunda eskalasi sampai laporan selesai.** Escalate Critical Findings ada di fase Execute PEAK, dan TaHiTI menggambar jalur langsung dari analisis ke handover [S6][S3].
- **Menyamakan ketiga kerangka sebagai hal berbeda.** Hunting loop adalah intinya; PEAK dan TaHiTI mengoperasikannya [S1][S3].
- **Hypothesis-driven untuk semua hal.** Saat kamu tidak tahu normal, baseline lebih dulu [S1][S9].
- **Kriteria sukses yang kabur.** "Sampai tidak menemukan apa-apa" bukan kriteria; "semua X ditinjau dan dilabeli" adalah kriteria.
- **Melaporkan "tidak ditemukan" saat time-box habis.** Baris yang belum ditinjau ditulis sebagai di luar cakupan atau inkonklusif.
- **Membaca "tidak ada koneksi" sebagai bukti.** Tanpa cek cakupan EID 3, ketiadaan event bisa berarti ketiadaan data. Transfer BITS juga tidak tercatat atas nama `bitsadmin.exe`.
- **Memberi label "jinak" karena akunnya admin.** Bukti jinak datang dari tiket, konfirmasi orang, dan jejak yang konsisten.
- **Mengirim query hunt sebagai rule.** Query hunt dioptimalkan untuk ditinjau sekali; deteksi butuh volume, FP, pengecualian sempit, dan uji (bagian 1.6) [S10].
- **Mengukur hunt dari jumlah insiden yang ditemukan.** Hunter tidak mengendalikan kapan penyerang beraksi; ukur deteksi, celah, dan teknik yang sudah di-hunt [S11].
- **Mengabaikan Knowledge.** Baseline tanpa pengetahuan lingkungan menghasilkan daftar anomali yang tidak bisa ditafsirkan [S1].
- `[komunitas, belum terkonfirmasi]` Ringkasan sekunder sering menamai ulang tahap atau fase (misalnya memberi PEAK urutan berbeda, atau menyebut TaHiTI dengan Trigger/Investigation/Resolution) [S4]. Nama yang dipakai di catatan ini mengikuti dokumen primer: Prepare, Execute, Act untuk PEAK dan Initiate, Hunt, Finalize untuk TaHiTI.

## 6. Catatan terkini

Bagian ini menampung tanggal terbit, versi, dan sejarah kerangka serta alat yang dipakai di Day ini. Berguna saat membuka sumbernya, tetapi tidak mengubah alur kerja di atas.

- **PEAK** diperkenalkan 18 April 2023 [S1], lalu dirinci dalam seri blog Splunk: hypothesis-driven (8 Mei 2023) [S6], baseline (11 Juli 2023) [S9], Hierarchy of Detection Outputs (26 Juli 2023) [S10], metrik (2 Agustus 2023) [S11], dan deliverable (25 Agustus 2023) [S12]. Blog pengantar menyebut model Sqrrl dan TaHiTI mulai terasa usang, dan PEAK memasukkan pelajaran beberapa tahun terakhir [S1].
- PEAK memperbarui model rujukan Sqrrl (2015) dan menambahkan tipe hunt eksplisit serta artikel pendamping tentang pengukuran [S1][S11].
- **Model rujukan Sqrrl, bagian 2 (Hunting Loop),** bertanggal 28 Oktober 2015 dan ditulis Sqrrl Team [S2]. Ia tetap menjadi sumber "hunting loop" yang paling banyak dirujuk, meski Sqrrl tidak lagi menjadi produk aktif [S2][S4].
- **TaHiTI** tetap tiga fase dan enam langkah; versi whitepaper yang dibaca di-host ulang Maret 2026. Whitepaper itu mengutip survei SANS 2017 yang mencatat hanya 4,6% organisasi yang melakukan hunting memakai metodologi eksternal yang dipublikasikan [S3]. Dokumentasi lengkap dan alat pendukungnya (MaGMa for threat hunting) disebut tersedia dari situs Betaalvereniging [S3].
- Survei SANS 2026: hanya 37% organisasi memakai metodologi formal, sehingga menguasai satu siklus yang konsisten adalah pembeda [S5].
- **Sysmon v15.22** adalah versi di halaman Microsoft Learn yang diperbarui 10 September 2026; halaman itu menyebut dukungan Windows 11 dan Windows Server 2019 ke atas, dan daftar event sampai Event ID 29 (FileExecutableDetected) [S7]. EID 3 tetap nonaktif secara default [S7].
- **ATT&CK v20:** T1105 Ingress Tool Transfer versi 2.6, diubah 11 September 2026, kini memuat detection strategy DET0060 yang memandang unduhan sebagai rangkaian perilaku: proses yang tidak lazim membuat koneksi ke tujuan eksternal, lalu membuat file [S13]. Rangkaian itu sejajar dengan pivot EID 1, EID 3, dan EID 11 di bagian 2.4 dan 2.5.

## 7. Cheat sheet

```
LOOP       1 Hypothesis -> 2 Investigate -> 3 Uncover TTP -> 4 Inform/Enrich -> (kembali ke 1)   [Sqrrl 2015]
PEAK       Prepare (topik, riset, hipotesis, cakupan+time-box, rencana)
           Execute (gather, pre-process, analyze, refine, ESCALATE SEGERA)
           Act (preserve, document, detections, re-add backlog, communicate)
           Knowledge di semua fase: bisnis/friendly intel + intel + pengalaman + temuan berjalan
TaHiTI     Initiate (trigger -> abstract -> backlog) | Hunt (define/refine <-> execute -> validasi)
           | Finalize (document -> handover; backlog di-update); analyze -> handover langsung bila kritis
TIPE       hypothesis-driven (ada dugaan) | baseline/EDA (sumber/lingkungan baru) | M-ATH (ML, data besar)
HASIL      terbukti (IR) | tidak terbukti (+cakupan) | inkonklusif (refine) | gagal data (telemetri)
           cocok pola tapi sah = "ditemukan, jinak terkonfirmasi"; hipotesis tetap tidak terbukti
CELAH      deteksi (data ada, rule belum) -> pemilik detection | visibilitas (data tidak ada) -> telemetri
HANDOVER   IR | detection (abstract deteksi) | pemilik sistem/vuln | telemetri | intel | backlog
OUTPUT     Reports < Dashboards < Analytics in code < Signatures & rules; pilih level tertinggi yang realistis
ABSTRACT   tujuan | ATT&CK | data+field | logika kasar | level | VOLUME | contoh positif | FP | pengecualian
DETEKSI    | triage | celah | tidak diusulkan
PIVOT      (EventCode=1 OR EventCode=3) ... | stats ... BY ProcessGuid   (bukan join untuk data besar)
           cek dulu: host mana yang mengirim EID 3; BITS -> koneksi atas nama svchost.exe
METRIK     deteksi dibuat/diperbarui | insiden dari deteksi hasil hunt | celah | vuln/misconfig | teknik
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Kalau saat hunt aku menemukan `certutil.exe` dijalankan Word di laptop Customer Service ke domain yang baru terdaftar, aku selesaikan dulu analisisnya dan tulis laporan, baru serahkan ke IR di fase Act." Benarkah?

<details><summary>Jawaban</summary>

Tidak. PEAK menempatkan Escalate Critical Findings di fase Execute: aktivitas yang kemungkinan atau pasti berbahaya diserahkan ke IR saat itu juga, karena waktu menentukan dampak. Diagram TaHiTI juga punya jalur langsung dari analisis data ke handover. Laporan hunt tetap ditulis kemudian, tetapi kasusnya sudah berpindah ke aturan main IR. Lihat bagian 1.2, 1.3, dan 2.5.

</details>

**2. Skenario keputusan.** Di `HUNT-2027-002`, enam eksekusi `bitsadmin.exe /transfer` tidak punya satu pun EID 3 dengan `ProcessGuid` yang sama, padahal ketiga host-nya mengirim EID 3. Apa kesimpulan yang tepat?

- A. Tidak ada unduhan; label keenamnya "tidak terbukti" karena tidak ada koneksi.
- B. Tidak ada koneksi atas nama `bitsadmin.exe` karena transfer BITS dijalankan layanan di `svchost.exe`; nilai eksekusinya dari command line dan tujuan URL, tulis keterbatasan metode di laporan, dan masukkan transfer BITS dari sisi layanan ke backlog.
- C. Keluarkan `bitsadmin.exe` dari hunt karena pivot tidak berfungsi untuknya.

<details><summary>Jawaban</summary>

B. Pivot lewat `ProcessGuid` secara desain buta terhadap transfer BITS, jadi ketiadaan koneksi bukan bukti. Penilaian tetap bisa dilakukan dari command line (di kasus ini tujuannya repositori internal `jkt-repo01`), dan celah metodenya ditulis serta dijadikan hipotesis baru. A keliru karena membaca ketiadaan event sebagai bukti tanpa memahami bagaimana data dihasilkan. C keliru karena membuang bagian hipotesis diam-diam; yang benar adalah menuliskan keterbatasannya. Lihat bagian 2.4, 2.5, dan 2.7.

</details>

**3. Pertanyaan jebakan.** "`HUNT-2027-002` hasilnya tidak terbukti, jadi tidak ada yang perlu diserahkan ke Sari." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Pertanyaan PEAK untuk memilih bentuk deteksi adalah apakah kamu sudah tahu cara menemukan aktivitas itu, walaupun tidak menemukan apa-apa. Hunt ini tahu persis jejak certutil dan bitsadmin yang mengunduh dari luar, punya angka volume (2 dalam 14 hari), dan punya contoh false positive yang sudah dikonfirmasi, sehingga menghasilkan abstract deteksi untuk Sari. Metrik PEAK juga menghitung deteksi yang dibuat dari hunt, bukan jumlah insiden yang ditemukan. Lihat bagian 1.5, 1.6, dan 2.7.

</details>

**4. Skenario keputusan.** Wazuh di `jkt-wazuh01` baru mengirim alert dari empat server Linux sejak Desember 2026, dan belum ada yang tahu field dan volume normalnya. Dimas ingin hunt pertama atas data itu. Tipe hunt mana yang paling tepat?

- A. Hypothesis-driven: ambil satu teknik ATT&CK untuk Linux dan langsung uji.
- B. Baseline (EDA): susun data dictionary, lihat distribusi, tinjau outlier, lalu turunkan hipotesis.
- C. Model-assisted: latih model ML atas alert Wazuh supaya kandidat langsung berperingkat.

<details><summary>Jawaban</summary>

B. PEAK menyebut onboarding sumber log baru sebagai pemicu khas hunt baseline, dan baseline adalah pendahulu yang baik untuk hunt yang lebih terfokus. A keliru karena hasil "tidak terbukti" atas data yang belum dikenal tidak bisa dibedakan dari query yang buta. C keliru karena PT JAB belum punya infrastruktur ML, dan model butuh pemahaman data yang justru dihasilkan baseline. Lihat bagian 1.4 dan 2.8.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Dwi Cahyono (analyst L1), dalam tiga kalimat, kenapa dari `HUNT-2027-002` hanya certutil dan bitsadmin yang diusulkan menjadi rule, sedangkan rundll32 dengan URL tidak.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Dalam 14 hari, certutil dan bitsadmin yang mengunduh dari luar hanya muncul 2 kali dan keduanya mudah dicek ke tiket change, jadi cukup yakin untuk dijadikan alert yang masuk ke antreanmu. Rundll32 dengan URL muncul 57 kali, semuanya karena Outlook atau aplikasi chat membuka tautan di browser, dan tidak ada pembeda yang jelas antara yang jinak dan yang jahat. Kalau itu dijadikan rule, kamu akan menutup puluhan alert jinak tiap dua minggu tanpa belajar apa pun, jadi lebih baik tidak dibuat sampai ada cara membedakannya."

Kesalahan yang sering muncul:
- Mengatakan rundll32 "aman" secara umum, padahal yang jinak adalah pola FileProtocolHandler dalam cakupan hunt ini.
- Tidak menyebut angka volume, padahal itu dasar keputusan.
- Lupa bahwa keputusan bentuk deteksi mengikuti pertanyaan "yakin ditaruh di depan analyst sebagai alert atau tidak".

</details>

**6. Pertanyaan jebakan.** "Time-box `HUNT-2027-002` satu hari habis saat 9 eksekusi rundll32 di host tanpa EID 3 belum diperiksa koneksinya. Karena sisanya bersih, laporannya cukup ditulis 'tidak ditemukan' untuk semua 214 host." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Hasil hanya berlaku untuk apa yang benar-benar diperiksa. Untuk 9 eksekusi itu tidak ada data koneksi, jadi laporannya menulis bahwa penilaian hanya memakai command line dan parent, dan 16 host tanpa EID 3 masuk "Di luar cakupan" serta diserahkan ke tim Infrastruktur sebagai celah visibilitas. Melaporkan "tidak ditemukan" untuk baris yang tidak bisa diuji membuat pembaca menganggap cakupan lebih luas dari kenyataan. Lihat bagian 1.5, 2.3, dan 2.6.

</details>

**7. Interview question (English).** "Walk me through how you run a threat hunt from start to finish, and what you hand over at the end."

<details><summary>Sample answer</summary>

"I follow the hunting loop, operationalised with PEAK and TaHiTI. A trigger, for example a public intel report on LOLBins downloading second stages, becomes an abstract in the backlog: hypothesis, ATT&CK technique, data sources, an absolute time range, what is out of scope, success criteria and a time-box. Before analysing, I check that the data actually exists, for instance which hosts send Sysmon network events, so that 'no connection' is not just 'no data'. Then I execute: stack the executions, pivot from process creation to network connections on ProcessGuid, refine the hypothesis when the long tail is too big, and escalate to IR immediately if something looks malicious rather than waiting for the report. I validate the hypothesis as proven, disproven, inconclusive or failed for lack of data, and document benign matches with the evidence that made them benign. At the end I hand over by recipient: IR for findings, a detection abstract with volume, known false positives and a proposed output level for the detection owner, data gaps for the telemetry owner, and new hypotheses for the backlog."

What makes this answer strong: it shows the full cycle with a concrete example, treats data readiness and scope as part of the method, separates escalation from reporting, and describes the handover as something a detection engineer can act on rather than a raw query.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Splunk: Introducing the PEAK Threat Hunting Framework | https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html | sekunder (blog vendor, penulis kerangka) | 2023-04-18; diakses 2026-10-08, dicek ulang 2026-10-18 | Tinggi untuk PEAK; langkah rinci hanya di diagram gambar. Menyebut model Sqrrl (2015) dan TaHiTI (2018) |
| S2 | Sqrrl: The Threat Hunting Reference Model Part 2: The Hunting Loop | https://www.threathunting.net/files/The%20Threat%20Hunting%20Reference%20Model%20Part%202_%20The%20Hunting%20Loop%20_%20Sqrrl.pdf | primer (model rujukan Sqrrl) | 2015-10-28 (Sqrrl Team); diakses 2026-10-08, dicek ulang 2026-10-18 | Tinggi untuk hunting loop, trailhead, friendly intelligence; dokumen lama era Sqrrl |
| S3 | TaHiTI: a threat hunting methodology (whitepaper) | https://www.betaalvereniging.nl/wp-content/uploads/2026/03/TaHiTI-Threat-Hunting-Methodology-whitepaper.pdf | primer | di-host 2026-03; diakses 2026-10-07, dibaca ulang 2026-10-18 | Tinggi. Tiga fase, enam langkah, backlog, validasi, handover, structured vs unstructured, tiga hubungan intel dan hunting, penulis |
| S4 | Expel: What are threat hunting frameworks? | https://expel.com/cyberspeak/what-are-threat-hunting-frameworks/ | sekunder | diakses 2026-10-08 | Sedang. Dipakai untuk penamaan tahap loop; nama fase bervariasi antar sumber |
| S5 | SANS 2026 Threat Hunting Survey (rilis pers) | https://www.sans.org/press/announcements/threat-hunters-call-data-their-biggest-barrier-overtaking-staffing-first-time-survey-finds | sekunder | 2026-09-23; diakses 2026-10-07 | Sedang-tinggi. Angka metodologi formal 37% |
| S6 | Splunk: Hypothesis-Driven Hunting with the PEAK Framework | https://www.splunk.com/en_us/blog/security/peak-hypothesis-driven-threat-hunting.html | sekunder (blog vendor, penulis kerangka) | 2023-05-08 (David Bianco); diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi. Nama dan isi langkah tiap fase PEAK untuk hunt hypothesis-driven, time-box di Scope Hunt, isi Preserve Hunt |
| S7 | Microsoft Learn: Sysmon (Sysinternals) | https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon | primer | halaman diperbarui 2026-09-10 (Sysmon v15.22); diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi. ProcessGuid, EID 1, 3 (nonaktif default), 11, 22, waktu event UTC |
| S8 | Atomic Red Team: T1105 Ingress Tool Transfer | https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md | primer (katalog test) | diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi. Nomor, nama, dan GUID test 7-9; nomor urut test bisa bergeser bila katalog diperbarui, GUID tetap |
| S9 | Splunk: Baseline Hunting with the PEAK Framework | https://www.splunk.com/en_us/blog/security/peak-baseline-hunting.html | sekunder (blog vendor, penulis kerangka) | 2023-07-11 (David Bianco); diakses 2026-10-18 | Tinggi. Pemicu hunt baseline, langkah per fase, keluaran (data dictionary, baseline, outlier jinak) |
| S10 | Splunk: Turning Hunts Into Detections with PEAK | https://www.splunk.com/en_us/blog/security/peak-turning-hunts-into-detections.html | sekunder (blog vendor, penulis kerangka) | 2023-07-26 (David Bianco); diakses 2026-10-18 | Tinggi. Hierarchy of Detection Outputs dan cara memilih level |
| S11 | Splunk: Measuring Hunting Success with PEAK | https://www.splunk.com/en_us/blog/security/peak-threat-hunting-metrics.html | sekunder (blog vendor, penulis kerangka) | 2023-08-02 (David Bianco); diakses 2026-10-18 | Tinggi. Lima metrik dan alasan jumlah insiden adalah ukuran lemah |
| S12 | Splunk: Key Threat Hunting Deliverables with PEAK | https://www.splunk.com/en_us/blog/security/key-threat-hunting-deliverables-with-peak.html | sekunder (blog vendor) | 2023-08-25 (Sydney Marrone); diakses 2026-10-18 | Tinggi. Enam deliverable hunt, ide di luar cakupan ke backlog |
| S13 | MITRE ATT&CK: T1105 Ingress Tool Transfer | https://attack.mitre.org/techniques/T1105/ | primer | ATT&CK v20; teknik versi 2.6, diubah 2026-09-11; diakses 2026-10-18 | Tinggi. Taktik Command and Control, contoh certutil dan BITSAdmin, detection strategy DET0060 |
| S14 | LOLBAS Project: Certutil | https://lolbas-project.github.io/lolbas/Binaries/Certutil/ | komunitas (katalog terkurasi) | diakses 2026-10-18 | Sedang-tinggi. Fungsi unduh dipetakan ke T1105, hak akses user, path System32 dan SysWOW64 |
| S15 | LOLBAS Project: Bitsadmin | https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/ | komunitas (katalog terkurasi) | diakses 2026-10-18 | Sedang-tinggi. Fungsi unduh dan copy dipetakan ke T1105, IOC file baru dan proses anak |
| S16 | Splunk Cloud Platform Admin Manual 10.4.2604: Configure limits using Splunk Web | https://help.splunk.com/en/splunk-cloud-platform/administer/admin-manual/10.4.2604/configure-your-splunk-cloud-platform-deployment/configure-limits-using-splunk-web | primer (dokumentasi vendor) | diakses 2026-10-18 | Tinggi untuk Splunk Cloud: `[join]` `subsearch_maxout` default 50.000, `subsearch_maxtime` default 60 detik. Nilai di Splunk Enterprise perlu dicek di `limits.conf` |

**Catatan sumber:** blog pengantar PEAK [S1] menampilkan langkah rinci hanya sebagai diagram; tabel langkah di bagian 1.2 mengikuti teks blog hypothesis-driven [S6]. Nama tahap loop bervariasi antar sumber sekunder; nama di catatan ini mengikuti model Sqrrl. Nomor urut test Atomic Red Team bisa berubah, jadi cocokkan GUID sebelum menjalankan test. Batas `join` [S16] diambil dari tabel batas Splunk Cloud; untuk Splunk Enterprise 10.6, cek nilai efektif di `limits.conf` instance-mu. Keterangan bahwa transfer BITS tercatat atas nama `svchost.exe` berasal dari pengamatan uji lab yang lazim dan perlu dikonfirmasi di lab-mu sendiri (langkah 6 bagian 3). Laporan intel pemicu `HUNT-2027-002`, seluruh isi hunt itu (host, akun, angka, label), dan abstract deteksi untuk Sari adalah penerapan catatan ini pada organisasi fiktif, bukan hasil eksekusi nyata.
