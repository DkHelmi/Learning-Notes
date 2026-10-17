---
day: 01
title: 'Apa itu threat hunting: hunt vs detect vs IR, kematangan, dan posisi di pasar kerja'
researched_on: 2026-10-18
versions_checked: 'PEAK framework (Splunk, Apr 2023); TaHiTI methodology whitepaper (Betaalvereniging/FI-ISAC, berkas di-host 2026-03); Hunting Maturity Model (Sqrrl "Hunt Evil" guide); SANS 2026 Threat Hunting Survey (rilis pers 23 Sep 2026); SANS 2025 Threat Hunting Survey (13 Mar 2025); Mandiant M-Trends 2026 (24 Mar 2026); Splunk Enterprise 10.6 (SPL)'
---

# Day 01: Apa itu threat hunting (hunt vs detect vs IR, kematangan, dan pasar kerja)

Cakupan: definisi threat hunting, bedanya dengan detection dan incident response, alasan sebuah SOC yang sudah punya detection tetap butuh hunting, kerangka PEAK, TaHiTI, dan HMM, empat hasil sebuah hunt, serta posisi hunting di pasar kerja.

## Ide inti

Detection hanya menangkap perilaku yang sudah pernah dirumuskan seseorang menjadi aturan. Threat hunting mengerjakan sisanya: pencarian yang dimulai dari pertanyaan atau hipotesis, bukan dari alert, dengan asumsi bahwa penyerang yang cukup sabar bisa berada di dalam jaringan tanpa memicu satu rule pun. Karena dimulai dari pertanyaan, hunt yang baik punya batas yang jelas (data apa, rentang kapan, host mana) dan selalu berakhir dengan keluaran tertulis: temuan yang diserahkan ke IR, deteksi baru, celah data, atau pernyataan "tidak ditemukan" yang menyebut persis apa yang sudah diperiksa. Hasil terakhir itu sama sahnya dengan yang pertama, selama cakupannya ditulis.

Kamu sudah mengenal pola ini dari NOC. Alarm NMS hanya berbunyi untuk ambang yang sudah diset: link down, CPU di atas 90%, optical power di bawah batas. Engineer yang berpengalaman tetap menyisir segmen yang belum pernah dikeluhkan pelanggan, misalnya membandingkan error counter semua port uplink satu POP, karena degradasi pelan bisa berjalan berminggu-minggu di bawah ambang alarm. Patroli itu tidak menunggu tiket, punya daftar titik yang diperiksa, dan hasilnya dicatat walaupun semuanya normal. Batas analoginya: degradasi fiber tidak berusaha bersembunyi, sedangkan penyerang sengaja bergerak di bawah ambang dan meniru aktivitas sah. Karena itu "tidak ditemukan" dalam hunting hanya berarti bersih untuk pertanyaan, data, dan rentang yang diuji, bukan bersih secara umum.

```
              ada alert?
             /          \
           ya            tidak
           |               |
     TRIAGE (detection)   ada pertanyaan/hipotesis + data + waktu terencana?
           |               |
   insiden terkonfirmasi?  ya --> HUNT: hipotesis -> data -> analisis -> hasil
           |                                                      |
           v                       +--------------+---------------+-------------+
          IR                       |              |               |             |
           ^                    ditemukan    tidak ditemukan   inkonklusif   data tidak ada
           |                       |         (cakupan ditulis)  (ulangi)     (celah data)
           +-------- handover -----+              |               |             |
                                                  +---- deteksi baru, intel, perbaikan telemetri,
                                                        hipotesis baru ke backlog
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan dan data pribadi sekitar 400 ribu pelanggan broadband. SOC PT JAB memakai Splunk Enterprise dengan Enterprise Security (ES), Sysmon di server Windows dan sekitar 40% workstation, serta Microsoft Defender for Endpoint di sebagian besar endpoint. Sepanjang 2026, dua insiden membuat Direktur Teknologi, Hendra Wijaya, bertanya hal yang sama berulang kali. Pada `INC-2026-017` (ransomware share Keuangan), akses awal ke server aplikasi lama `jkt-dmz-app01` terjadi Rabu 2026-10-07 sekitar 03:10, sedangkan alert pertama tentang enkripsi baru muncul Jumat 2026-10-09 21:32, kira-kira 66 jam kemudian. Pada `INC-2026-026` (installer PDF palsu), laptop sales Bandung `BDG-WS-0163` menghubungi server C2 73 kali dari Jumat sore sampai Senin tanpa satu alert pun; laptop itu baru ketahuan karena seorang analyst sengaja mencarinya saat scoping. Jumat 2027-01-29, Hendra menyetujui percobaan "Program hunt PT JAB" selama dua kuartal (Februari sampai Juli 2027). Kamu, analyst L2, ditunjuk memegangnya dua hari per minggu, Selasa dan Kamis. Senin 2027-02-01 pukul 09:00, SOC lead Dimas Prasetyo menulis kepadamu:

> "Program hunt resmi jalan mulai hari ini, kamu pegang tiap Selasa dan Kamis. Sebelum Senin depan aku harus menjelaskan ke anak-anak L1 dan ke Pak Hendra, jadi tolong bantu jawab beberapa hal. Apa bedanya hunting dengan yang kita kerjakan tiap hari, triage alert dan pivot waktu insiden? Kenapa kita perlu ini, ES kita kan sudah punya ratusan detection? Kita pakai kerangka apa, supaya ini tidak terlihat seperti iseng cari-cari? Posisi kita sekarang di mana, dan apa target yang masuk akal sampai Juli? Kalau hunt tidak menemukan apa-apa, apa yang aku laporkan ke Pak Hendra? Terakhir, Pak Hendra tanya apakah kita perlu merekrut threat hunter khusus. Kalau bisa, mulai satu hunt minggu ini supaya ada contoh nyata."

Pesan itu memuat enam pertanyaan:

1. Apa bedanya hunting dengan triage alert dan investigasi insiden?
2. Kenapa hunting perlu, padahal detection di ES sudah banyak?
3. Kerangka apa yang dipakai supaya hunting terarah dan bisa dipertanggungjawabkan?
4. Di tingkat kematangan mana SOC PT JAB sekarang, dan target apa yang realistis sampai Juli?
5. Bila hunt tidak menemukan apa-apa, apa yang dilaporkan?
6. Perlukah merekrut threat hunter khusus?

Pertanyaan 1 dijawab di bagian 1.1 dan 1.2, pertanyaan 2 di bagian 1.3, pertanyaan 3 di bagian 1.4, pertanyaan 4 di bagian 1.5, pertanyaan 5 di bagian 1.6, dan pertanyaan 6 di bagian 1.7. Bagian 2 berisi hunt pertama PT JAB (`HUNT-2027-001`) dari abstract sampai laporan, plus satu halaman jawaban untuk Dimas.

**Kapan relevan:** saat ada pertanyaan tentang ancaman yang belum dijawab detection otomatis, datanya tersedia, dan ada waktu yang dialokasikan untuk mencari; saat menjelaskan ke manajemen kenapa SOC menghabiskan waktu di luar antrean alert; dan saat menilai apakah sebuah kegiatan layak disebut hunting.
**Kapan bukan jawaban:** saat ada insiden aktif (itu IR, walaupun teknik pencariannya mirip); saat datanya belum ada (perbaiki telemetri dulu, Day 04); dan saat pertanyaannya bisa dijawab rule yang sudah ada, karena menjalankan ulang rule secara manual bukan hunting.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Ini Day pertama topik ini, jadi semua istilah yang dipakai dimuat di sini. Kolom padanan memakai analogi NOC dan SOC yang dipakai di semua Day Threat-Hunting.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Threat hunting | Pencarian proaktif, dipimpin manusia, dan iteratif untuk menemukan aktivitas berbahaya yang lolos dari pertahanan yang ada | Patroli preventif: menyisir segmen yang belum pernah dikeluhkan pelanggan, bukan menunggu tiket gangguan |
| Detection (monitoring) | Logika otomatis yang menghasilkan alert saat event cocok dengan pola yang sudah diketahui | Threshold alarm NMS (link down, CPU di atas 90%) |
| Hipotesis | Dugaan yang bisa diuji tentang perilaku penyerang di lingkungan tertentu | Dugaan penyebab gangguan yang diuji satu per satu |
| Dwell time | Jarak waktu antara kompromi awal dan ditemukannya penyerang; TaHiTI menyebutnya breach detection gap | Waktu antara fiber mulai degradasi dan tiket pertama masuk |
| Hunt abstract | Ringkasan rencana hunt: pemicu, hipotesis, data, kriteria selesai | Tiket preventive maintenance yang menulis apa yang diperiksa dan kapan dianggap selesai |
| Backlog hunt | Daftar abstract yang menunggu dikerjakan, diprioritaskan | Antrean tiket preventive maintenance |
| Stacking | Menghitung kemunculan kombinasi nilai lalu melihat yang paling jarang | Mencari perangkat dengan konfigurasi paling langka di inventaris |
| Long tail | Kombinasi yang muncul sangat jarang di ujung distribusi frekuensi | Satu POP dengan setelan yang tidak sama dengan yang lain |
| PEAK | Kerangka hunting Splunk (2023): Prepare, Execute, and Act with Knowledge | Metode kerja baku untuk gangguan yang belum punya prosedur |
| TaHiTI | Metodologi hunting sektor keuangan Belanda: Initiate, Hunt, Finalize | Alur tiket dari pembukaan, pengerjaan, sampai serah terima |
| Hunting Maturity Model (HMM) | Lima tingkat kematangan hunting, HMM0 sampai HMM4 | Tingkat kematangan proses NOC dari reaktif ke prediktif |
| Handover | Penyerahan hasil hunt ke penerima yang bertindak: IR, detection, pemilik sistem, intel | Temuan patroli diteruskan ke tim lapangan atau dijadikan alarm permanen |

### 1.1 Definisi: tiga kata kunci yang membedakan hunting

Pertanyaan pertama Dimas lahir dari kenyataan bahwa L1 sudah merasa "mencari" setiap hari: membuka alert, melihat event di sekitarnya, lalu memutuskan. Bedanya ada di definisi.

Dua definisi primer saling menguatkan:

- **TaHiTI:** hunting adalah upaya proaktif mencari tanda aktivitas berbahaya, saat ini maupun historis, yang lolos dari pertahanan yang ada [S2]. TaHiTI juga menegaskan bahwa hunting mengandaikan proses security monitoring sudah berjalan. Hunting bukan pengganti SOC.
- **Sqrrl (Hunt Evil):** hunting adalah pencarian yang digerakkan manusia, proaktif, dan iteratif di jaringan, endpoint, atau dataset, untuk menemukan aktivitas berbahaya atau berisiko yang lolos dari alat otomatis [S3].

Kata kuncinya ada tiga. Proaktif: tidak menunggu alert. Dipimpin manusia: alat membantu, tetapi pertanyaan dan penilaiannya datang dari analyst. Asumsi celah: deteksi otomatis pasti punya bagian yang tidak tertutup, dan hunt sengaja diarahkan ke bagian itu.

Tujuan utamanya menurut TaHiTI adalah memperpendek breach detection gap, yaitu jarak antara kompromi awal dan ditemukannya penyerang, yang di tempat lain disebut dwell time [S2]. Manfaat sampingannya tidak kalah penting: menemukan celah visibilitas, celah deteksi, ide use case atau deteksi baru, intel baru, dan rekomendasi preventif [S2].

Untuk L1 PT JAB, kalimat yang paling mudah dipegang: triage menjawab "alert ini benar atau tidak", hunting menjawab "apa yang mungkin terjadi tanpa alert sama sekali".

### 1.2 Hunt vs detect vs IR: lima pembeda

Dimas juga menyebut pivot saat insiden. Saat `INC-2026-026`, analyst mencari laptop lain yang menghubungi domain C2 yang sama; kegiatan itu memakai teknik pencarian, tetapi pemicunya insiden yang sudah dinyatakan. Tabel berikut memisahkan ketiganya; baca baris "Pemicu" dan "Selesai saat", karena dua baris itulah yang paling sering dicampur.

| Aspek | Detection (monitoring) | Threat hunting | Incident response |
|---|---|---|---|
| Pemicu | Rule/alert otomatis fire | Hipotesis, intel, baseline, celah deteksi; terjadwal | Insiden terkonfirmasi atau dicurigai kuat |
| Sifat | Reaktif terhadap alert | Proaktif, iteratif | Reaktif, terikat waktu |
| Input | Event yang cocok dengan logika yang sudah diketahui | Data mentah/teragregasi; pertanyaan terbuka | Bukti di sekitar insiden |
| Output | Alert, triage, disposisi | Temuan (atau tidak), celah data, deteksi baru, intel | Containment, eradication, recovery, laporan |
| Selesai saat | Alert ditutup | Hipotesis terbukti / tidak terbukti / inkonklusif | Insiden ditutup dan lessons learned selesai |

Keterkaitannya:

- Hunting yang menemukan sesuatu menyerahkannya ke IR [S2]. Begitu ada indikasi kuat, pekerjaan berpindah aturan main: ada IC, ada jam, ada keputusan containment.
- Hunting yang berhasil dan diulang sebaiknya diotomasi menjadi deteksi; itulah ciri HMM tingkat atas [S3] dan fase Act di PEAK [S1].
- Mitos yang dibantah Sqrrl: "hunting bisa sepenuhnya diotomasi". Bila input manusianya hanya menyelesaikan apa yang sudah ditemukan alat, itu triage, bukan hunting [S3].

Dengan tabel itu, pencarian laptop lain saat `INC-2026-026` adalah bagian dari IR (scoping), walaupun dilakukan dengan cara yang mirip hunting. Bedanya bukan di query, tetapi di pemicu dan di siapa yang memegang keputusan.

### 1.3 Kenapa hunting tetap perlu walaupun detection sudah banyak

Pertanyaan kedua Dimas adalah pertanyaan yang akan diulang Hendra: ES sudah punya ratusan detection, jadi apa yang masih bisa lolos?

Ada tiga alasan, dan semuanya bisa ditunjukkan dengan kasus PT JAB sendiri.

Pertama, detection hanya menangkap pola yang sudah dirumuskan. Pada `INC-2026-026`, beacon dari `BDG-WS-0163` berjalan tiap lima menit ke domain baru selama akhir pekan. Tidak ada rule yang salah; memang belum ada rule untuk kombinasi itu. Detection kustom untuk kampanye tersebut baru lahir setelah insiden.

Kedua, alert yang ada bisa terlewat karena prioritas. Pada `INC-2026-017`, alert tamper antivirus di `JKT-WS-0457` muncul pukul 20:52, berprioritas P3, dan tidak dieskalasi; enkripsi dimulai 21:31. Hunting tidak memperbaiki triage, tetapi hunt yang menyisir sinyal lemah berprioritas rendah secara berkala bisa menemukan pola yang tidak terlihat dari satu alert.

Ketiga, jarak antara kompromi dan ditemukannya penyerang masih panjang di industri. Mandiant M-Trends 2026, yang merangkum investigasi Mandiant atas serangan terarah sepanjang 2025, mencatat median global dwell time naik menjadi 14 hari dari 11 hari tahun sebelumnya, dan menyebut bahwa organisasi menemukan sendiri tanda aktivitas berbahaya pada 52% kasus, naik dari 43% pada 2024 [S7]. Laporan yang sama mencatat bahwa jeda antara akses awal dan penyerahan akses ke kelompok penyerang kedua menyusut dari lebih dari 8 jam pada 2022 menjadi 22 detik pada 2025 [S7]. Angka itu berasal dari kasus yang ditangani satu vendor, jadi pakai sebagai arah, bukan ukuran pasti untuk PT JAB.

Angka PT JAB sendiri lebih meyakinkan untuk Hendra: sekitar 66 jam pada `INC-2026-017`, dan sekitar tiga hari untuk `BDG-WS-0163` pada `INC-2026-026`. Hunting tidak menjanjikan angka itu turun, tetapi ia satu-satunya kegiatan SOC yang sengaja mencari di dalam jarak waktu tersebut.

### 1.4 Kerangka yang dipakai: PEAK dan TaHiTI

Pertanyaan ketiga Dimas ("supaya tidak terlihat iseng cari-cari") dijawab dengan kerangka. Kerangka memaksa setiap hunt punya pemicu, rencana, kriteria selesai, dan keluaran yang ditulis.

PEAK (Splunk, April 2023; David Bianco dan Ryan Fetterman) [S1]:

- Singkatan dari Prepare, Execute, and Act with Knowledge. Prepare: memilih topik, riset, dan menyusun rencana. Execute: mengambil dan menganalisis data. Act: mendokumentasikan, mengotomasi, dan mengomunikasikan hasil. Knowledge bukan fase tersendiri; pengetahuan organisasi, intel, dan pengalaman hunter dipakai di semua fase [S1].
- Tiga tipe hunt: Hypothesis-Driven (menguji dugaan tentang perilaku penyerang), Baseline (exploratory data analysis: kenali normal, cari penyimpangan), dan Model-Assisted (M-ATH) yang memakai machine learning [S1].
- Langkah di tiap fase boleh dilewati, diubah urutannya, atau ditambah [S1].
- PEAK memperbarui Sqrrl Threat Hunting Reference Model (2015) [S1].

TaHiTI (Targeted Hunting integrating Threat Intelligence; konsorsium sektor keuangan Belanda) [S2]:

- Tiga fase dan enam langkah:
  - **Initiate:** pemicu dituliskan menjadi investigation abstract, lalu disimpan di backlog.
  - **Hunt:** define/refine (hipotesis, sumber data, teknik analisis) dan execute (ambil data, analisis, validasi hipotesis), bolak-balik sampai hipotesis terjawab.
  - **Finalize:** dokumentasikan temuan, lalu handover ke proses lain (IR, monitoring, intel, vulnerability management).
- TaHiTI fokus pada tiga lapisan atas Pyramid of Pain, yaitu TTP, tools, dan artefak host atau jaringan [S2]. Pyramid of Pain adalah urutan jenis indikator dari yang paling mudah diganti penyerang (hash, IP, domain) sampai yang paling sulit (TTP, cara penyerang bekerja). Makin tinggi lapisannya, makin mahal bagi penyerang untuk menghindar.
- Pemicu yang disebut: intel aktor, hunt lain, use case monitoring yang belum lengkap, insiden historis, red teaming, analisis crown jewel, keahlian domain, dan ATT&CK [S2].

Kesamaan keduanya: hunt berakhir dengan tindakan dan dokumentasi, bukan hanya "selesai mencari". Untuk PT JAB, keputusan praktisnya: PEAK dipakai untuk memilih tipe hunt dan alur kerja, TaHiTI dipakai untuk format abstract, backlog, dan handover. Pemicu pertama yang jelas ada di daftar TaHiTI: insiden historis (`INC-2026-017`, `INC-2026-026`) dan use case monitoring yang belum lengkap. Langkah tiap fase dibahas di Day 02.

### 1.5 Hunting Maturity Model: posisi PT JAB dan target Juli

Pertanyaan keempat Dimas butuh alat ukur. HMM dibuat David J. Bianco sekitar 2015 dan dipopulerkan Sqrrl lewat panduan "Hunt Evil" [S3]. Tabel berikut adalah lima tingkatnya; baca kolom "Langkah naik", karena itu yang menjadi target.

| Level | Nama | Ciri utama | Langkah naik |
|---|---|---|---|
| HMM0 | Initial | Bergantung pada alert otomatis; sedikit/tanpa koleksi data rutin | Kumpulkan data dari tiga domain (network, host, aplikasi); mulai cari indikator |
| HMM1 | Minimal | Memakai pencarian indikator dari threat intel; koleksi data sedang-tinggi | Temukan dan jalankan prosedur hunting yang sudah dipublikasikan, terjadwal |
| HMM2 | Procedural | Mengikuti prosedur analisis data buatan pihak lain; koleksi data tinggi | Bentuk tim dengan keahlian keamanan dan analisis data; buat prosedur sendiri |
| HMM3 | Innovative | Membuat prosedur analisis baru | Otomasi prosedur yang terbukti berhasil |
| HMM4 | Leading | Mengotomasi sebagian besar prosedur yang berhasil | Skala dan efisiensi |

Catatan tentang model ini:

- Model ini preskriptif. Organisasi bisa kuat di satu kriteria dan lemah di kriteria lain [S3].
- Beberapa ringkasan web modern menambahkan hal seperti "memakai AI untuk hipotesis" ke HMM4. Itu tidak ada di dokumen Sqrrl [S3] dan merupakan interpretasi penulis sekunder.
- Dokumen Hunt Evil tidak mencantumkan tanggal terbit; dokumen ini berasal dari era Sqrrl, sebelum diakuisisi Amazon pada 2018.

Untuk menilai posisi, pakai pertanyaan berikut. Pertanyaan ini disusun dari ciri tiap level di tabel di atas, bukan kuesioner resmi. Kolom kanan menunjukkan bukti yang harus bisa ditunjukkan; jawaban "ya" tanpa bukti tidak dihitung.

| Level | Pertanyaan penilaian diri | Bukti yang bisa ditunjukkan |
|---|---|---|
| HMM0 | Apakah satu-satunya cara menemukan ancaman adalah alert dari alat? Apakah data network, host, dan aplikasi belum dikumpulkan secara rutin? | Tidak ada index/retensi untuk log endpoint atau proxy |
| HMM1 | Apakah kamu rutin mencari IOC dari feed atau laporan intel di data historis? | Riwayat search IOC, daftar feed yang dipakai |
| HMM2 | Apakah kamu menjalankan prosedur hunt buatan pihak lain (playbook publik, query vendor) secara terjadwal? | Kalender hunt, daftar prosedur dan tanggal eksekusi |
| HMM3 | Apakah kamu menulis prosedur analisis sendiri (hipotesis, query, kriteria) yang belum ada di sumber publik? | Laporan hunt orisinal dengan hipotesis dan hasilnya |
| HMM4 | Apakah prosedur hunt yang berhasil berubah menjadi deteksi atau job otomatis, sehingga hunter bebas mengerjakan pertanyaan baru? | Rule atau saved search yang asalnya hunt, dengan tanggal aktif |

Level ditentukan oleh pertanyaan tertinggi yang bisa dijawab "ya" dengan bukti.

Penilaian PT JAB per 1 Februari 2027:

- HMM0 terlewati: data host (Security log, Sysmon, PowerShell), jaringan (firewall, proxy, DNS), dan aplikasi (Entra ID, M365, cloud) sudah masuk Splunk dengan retensi.
- HMM1 terpenuhi: SOC rutin mencocokkan indikator dari laporan intel ke data historis lewat threat intelligence di ES, dan buktinya ada di riwayat search dan daftar threat source.
- HMM2 belum: tidak ada kalender hunt dan tidak ada prosedur publik yang dijalankan terjadwal. Pencarian saat `INC-2026-026` dilakukan di dalam IR, bukan sebagai prosedur berulang.
- Kriteria koleksi data tidak merata. Sysmon hanya di sekitar 40% workstation, dan sebagian laptop di Bandung tidak punya EDR maupun Sysmon. Ini contoh "kuat di satu kriteria, lemah di kriteria lain".

Jadi posisinya HMM1. Target realistis sampai Juli: perilaku HMM2 yang konsisten (prosedur publik dijalankan menurut kalender) dan awal HMM3 (beberapa hunt orisinal dengan laporan, termasuk minimal satu deteksi yang lahir dari hunt). Lompatan ke HMM4 dalam enam bulan dengan satu orang dua hari per minggu tidak realistis, dan menjanjikannya ke Hendra hanya membuat evaluasi Juli terlihat gagal.

### 1.6 Empat hasil sebuah hunt, termasuk "tidak ditemukan"

Pertanyaan kelima Dimas adalah yang paling menentukan apakah program ini bertahan: apa yang dilaporkan bila hunt tidak menemukan apa-apa?

TaHiTI menyebut hasil validasi hipotesis secara eksplisit: terbukti (masuk IR), tidak terbukti, atau inkonklusif (ulangi define/refine). Bila data tidak tersedia, hunt dianggap gagal, tetapi tetap menghasilkan pelajaran [S2]. Tabel berikut menerjemahkan empat hasil itu ke kalimat laporan; baca kolom kanan, karena itulah yang membuat setiap hasil berguna.

| Hasil | Arti | Yang tetap dilaporkan |
|---|---|---|
| Ditemukan (terbukti) | Ada aktivitas berbahaya yang cocok dengan hipotesis | Handover ke IR, lalu deteksi untuk pola itu |
| Tidak ditemukan (tidak terbukti) | Data yang cukup sudah diperiksa dan tidak ada aktivitas yang cocok | Cakupan nyata (host, rentang, sumber), ambang yang dipakai, jinak yang dikonfirmasi, usulan deteksi bila polanya layak dijaga |
| Inkonklusif | Data ada, tetapi belum cukup untuk memutuskan | Apa yang kurang dan rencana define/refine berikutnya |
| Data tidak cukup (gagal) | Sumber data yang dibutuhkan tidak ada atau rusak | Celah telemetri, siapa pemiliknya, dan usulan perbaikan |

Kalimat untuk Hendra: hunt yang tidak menemukan penyerang tetap menghasilkan tiga hal yang bisa diaudit, yaitu daftar apa yang sudah diperiksa, celah data yang sekarang diketahui, dan deteksi atau perbaikan yang diusulkan. "Tidak ditemukan" tanpa cakupan adalah pernyataan kosong; "tidak ditemukan pada 7 hari Sysmon dari workstation ber-Sysmon, dengan sekitar 60% workstation di luar cakupan" adalah temuan.

### 1.7 Posisi hunting di pasar kerja secara realistis

Pertanyaan terakhir Dimas datang dari Hendra: perlukah merekrut threat hunter khusus? Data survei membantu menjawabnya, dengan catatan bahwa survei berbasis responden yang memilih ikut, jadi angkanya adalah arah tren, bukan ukuran pasar yang presisi.

SANS 2026 Threat Hunting Survey (rilis pers 23 September 2026) [S4]:

- Data (kualitas/kuantitas) untuk pertama kalinya menjadi hambatan nomor satu (50%), di atas staf terampil (45%).
- 58% punya program in-house. Outsourcing turun dari 30% (2025) ke 18%.
- Hanya 37% memakai metodologi formal (turun dari 46%); 39% ad hoc.
- Hanya 40% mengukur efektivitas hunting secara formal.
- Cloud dinilai lingkungan tersulit (32%).

Tabel berikut membandingkannya dengan survei tahun sebelumnya, SANS 2025 Threat Hunting Survey (terbit 13 Maret 2025, penulis Josh Lemon) [S6]. Baca kolom kanan untuk arah perubahannya.

| Indikator | 2025 [S6] | 2026 [S4] | Cara membacanya |
|---|---|---|---|
| Hambatan utama | Kekurangan staf terampil, 61% | Data, 50%; staf 45% | Masalah bergeser dari orang ke data |
| Hunting di-outsource penuh | 30% (2024: 37%) | 18% | Hunting makin dikerjakan sendiri |
| Dikelola penuh in-house | 58% | 58% punya program in-house | Stabil |
| Mengukur efektivitas secara formal | 51% (2024: 64%) | 40% | Pengukuran terus turun |
| Cloud sebagai lingkungan tersulit | 39% | 32% | Tetap paling sulit |
| AI/ML sebagai prioritas perbaikan | 48% | 39% | Minat AI mendingin |

Survei 2025 juga mencatat bahwa teknik living-off-the-land muncul di 76% serangan nation-state yang ditemukan responden, dan pemakaian tool buatan internal naik dari 33% ke 48% [S6]. Definisi "in-house" di dua tahun itu belum tentu identik; cocokkan dengan laporan lengkap bila angka ini dipakai untuk argumen formal.

Interpretasi untuk PT JAB dan untuk karier (penilaian, bukan fakta):

- Judul "Threat Hunter" murni relatif jarang. Hunting biasanya menjadi tanggung jawab analyst L2/L3, IR, atau detection engineer. Sumber karier sekunder juga menyebut jalur masuk umum lewat SOC, IR, dan detection engineering [S5].
- Hambatan utama kini data, bukan orang [S4]. Untuk PT JAB, merekrut hunter khusus sebelum cakupan Sysmon dan EDR merata berarti membayar orang untuk menemukan celah yang sudah diketahui. Jawaban ke Hendra: belum perlu; evaluasi lagi di akhir percobaan berdasarkan metrik program.
- Karena banyak organisasi masih ad hoc dan jarang mengukur, analyst yang bisa menunjukkan hunt terdokumentasi, metrik, dan deteksi yang lahir dari hunt menonjol di pasar kerja. Kemampuan menilai kualitas telemetri (Day 04) sama berharganya dengan menulis query.

## 2. Contoh dan langkah praktis: hunt pertama PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Query ditulis untuk Splunk PT JAB; untuk latihan, jalankan versi yang disesuaikan di lab pribadi (bagian 3).

### 2.1 Abstract `HUNT-2027-001` untuk backlog

Abstract ini menjawab permintaan Dimas "mulai satu hunt minggu ini". Pemicunya celah deteksi yang terlihat di `INC-2026-026`: rantai aplikasi sah memunculkan shell tidak punya rule. Formatnya mengikuti langkah Initiate TaHiTI (bagian 1.4) dan disimpan di `jab-hunt/backlog/BACKLOG.md`, repositori GitLab internal yang dibuat untuk program ini.

```
ID             : HUNT-2027-001
Dibuat         : 2027-02-01 (Senin), pemilik: <kamu>, reviewer: Dimas Prasetyo
Trigger        : Celah deteksi - belum ada rule untuk kombinasi parent/child proses yang langka
                 (pelajaran INC-2026-026: rantai program sah -> cmd.exe tanpa alert)
Tipe (PEAK)    : Baseline (exploratory), dilanjutkan hypothesis-driven bila ada temuan
Hipotesis awal : Di workstation PT JAB ada proses anak yang dijalankan oleh parent yang tidak lazim
                 (mis. Office/browser/WMI memunculkan shell), yang tidak memicu alert apa pun.
ATT&CK         : Execution (TA0002) - teknik spesifik ditentukan setelah temuan
Data           : Sysmon Event ID 1 (process creation), index=sysmon, workstation di OU Workstations-EDR,
                 Senin 2027-01-25 00:00 sampai Senin 2027-02-01 00:00 WIB (7 hari)
Di luar cakupan: workstation tanpa Sysmon (ditulis jumlahnya di laporan), server, Linux
Kriteria sukses: Semua pasangan parent->child langka dari parent "berisiko" sudah ditinjau;
                 tiap pasangan berlabel jinak / perlu investigasi / data tidak cukup
Hasil mungkin  : ditemukan | tidak ditemukan | inkonklusif | data tidak cukup
Handover       : IR (Dimas) bila ditemukan; Sari Kusuma (konten detection ES) untuk usulan rule;
                 tim Infrastruktur untuk celah Sysmon
Target selesai : Kamis 2027-02-04
```

Cara membaca elemennya:

- **Trigger** ditulis dengan asalnya, supaya pembaca laporan tahu kenapa hunt ini didahulukan.
- **Di luar cakupan** sengaja ditulis di abstract, bukan baru di laporan. Saat hasilnya "tidak ditemukan", baris ini yang mencegah kesimpulan berlebihan.
- **Kriteria sukses** membuat hunt bisa selesai. Tanpa itu, stacking bisa diteruskan tanpa ujung.

**Kapan gagal:** abstract ditulis setelah hunt selesai untuk merapikan laporan. Abstract yang ditulis belakangan cenderung menyesuaikan hipotesis dengan hasil, sehingga "tidak terbukti" tidak pernah muncul.

### 2.2 Stacking parent-child di Splunk

Query ini adalah langkah Execute pertama `HUNT-2027-001`: menghitung setiap pasangan parent dan child, lalu melihat ujung yang paling jarang.

**Tujuan:** menemukan pasangan proses induk dan anak yang jarang muncul di workstation ber-Sysmon selama 7 hari.

**Asumsi data:** Sysmon dikirim universal forwarder dan diparsing Splunk Add-on for Sysmon ke `index=sysmon` dengan `sourcetype=XmlWinEventLog`; field `ParentImage`, `Image`, dan `host` terekstrak. Cek nama index dan sourcetype di lingkunganmu sebelum menjalankan.

```
index=sysmon sourcetype=XmlWinEventLog EventCode=1
    earliest="01/25/2027:00:00:00" latest="02/01/2027:00:00:00"
| stats count AS executions dc(host) AS hosts values(host) AS host_list BY ParentImage Image
| where executions <= 3
| sort executions
```

Tabel berikut menjelaskan tiap baris query.

| Baris | Fungsi |
|---|---|
| `index=sysmon sourcetype=XmlWinEventLog EventCode=1` | Hanya event process creation dari Sysmon |
| `earliest="01/25/2027:00:00:00" latest="02/01/2027:00:00:00"` | Rentang absolut 7 hari, supaya hunt bisa diulang dengan hasil yang sama (format `%m/%d/%Y:%H:%M:%S`) |
| `stats count ... BY ParentImage Image` | Stacking: hitung tiap pasangan parent dan child |
| `dc(host)` / `values(host)` | Seberapa tersebar pasangan itu, dan di host mana |
| `where executions <= 3` | Ambil long tail. Ambang 3 adalah asumsi awal, bukan nilai baku |
| `sort executions` | Paling langka di atas |

Keluaran ilustrasi (ringkas):

```
Jumlah event EID 1 dalam rentang : 4.812.330
Pasangan ParentImage+Image unik  : 3.214
Pasangan dengan executions <= 3  : 1.146
```

**Cara membaca hasil:** 1.146 pasangan langka terlalu banyak untuk ditinjau satu orang dalam dua hari. Sebagian besar adalah installer dengan nama folder acak di `Temp`, proses update aplikasi dengan path berversi, dan program yang dipakai satu karyawan saja. Ini temuan pertama yang wajar: long tail di lingkungan nyata panjang, dan langka belum tentu jahat. Abstract perlu dipersempit (define/refine di TaHiTI), bukan ambangnya diturunkan sampai hasilnya terasa nyaman.

**Variasi:** stacking `Image` dengan `User` untuk melihat siapa menjalankan biner langka.

**Kapan gagal:** Sysmon tidak terpasang di host yang kamu kira; `ParentImage` kosong di sebagian event; path berversi (misalnya folder aplikasi dengan nomor build) memecah satu program menjadi puluhan "pasangan langka".

### 2.3 Mempersempit ke parent berisiko

Langkah ini adalah define/refine pertama `HUNT-2027-001`. Pertanyaannya dipersempit ke parent yang semestinya jarang memunculkan shell atau script host: aplikasi Office, pembaca PDF, browser, dan `WmiPrvSE.exe` (proses yang menjalankan perintah WMI, termasuk perintah yang dikirim dari host lain).

```
index=sysmon sourcetype=XmlWinEventLog EventCode=1
    earliest="01/25/2027:00:00:00" latest="02/01/2027:00:00:00"
| eval parent=lower(ParentImage), child=lower(Image)
| where match(parent, "\\\\(winword|excel|powerpnt|outlook|acrord32|msedge|chrome|wmiprvse)\.exe$")
    AND match(child, "\\\\(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)\.exe$")
| stats count AS executions dc(host) AS hosts values(host) AS host_list values(User) AS users
    BY ParentImage Image
| sort executions
```

| Bagian | Fungsi |
|---|---|
| `eval parent=lower(...)` | Menyamakan huruf, karena path di Windows tidak peka huruf besar/kecil |
| `match(parent, "\\\\(...)\.exe$")` | Nama file parent di ujung path. Di string SPL, `\\\\` menjadi regex `\\` yang cocok dengan satu backslash |
| `match(child, ...)` | Hanya child berupa shell, script host, atau binary yang sering disalahgunakan |
| `values(User)` | Siapa yang menjalankannya, untuk pivot berikutnya |

Keluaran ilustrasi:

```
ParentImage                                              Image                                               executions hosts host_list     users
C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE  C:\Windows\System32\cmd.exe                            1          1     JKT-WS-0471   JAB\nur.aini
C:\Windows\System32\wbem\WmiPrvSE.exe                     C:\Windows\System32\cmd.exe                            3          1     JKT-WS-0517   NT AUTHORITY\SYSTEM
C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe 2      2     JKT-WS-0403, JKT-WS-0466 JAB\yuni.astuti, JAB\lestari.putri
```

Ketiga baris ditinjau satu per satu dengan pivot ke `CommandLine`, waktu, dan event di sekitarnya:

- **EXCEL.EXE ke cmd.exe di `JKT-WS-0471`:** `CommandLine` menunjukkan `cmd.exe /c copy` dari folder lokal ke share Keuangan, dijalankan oleh makro rekonsiliasi bulanan. Dikonfirmasi ke pengguna dan atasannya. Label: jinak. Catatan: makro yang menjalankan `cmd.exe` adalah pola yang sama dengan dokumen berbahaya, jadi bila nanti ada rule, makro ini butuh pengecualian yang sempit (path dokumen dan command line persis), bukan pengecualian per host.
- **WmiPrvSE.exe ke cmd.exe di `JKT-WS-0517`:** tiga eksekusi `cmd.exe /c` yang menjalankan perintah inventaris software, sebagai SYSTEM. Pivot ke `wineventlog` menunjukkan logon jaringan (4624 tipe 3) dari `JKT-JUMP01` oleh akun admin helpdesk satu menit sebelumnya, sesuai tiket helpdesk. Label: jinak. Catatan: eksekusi WMI dari jarak jauh juga cara umum lateral movement; ini memunculkan hipotesis baru untuk backlog.
- **OUTLOOK.EXE ke powershell.exe di dua host:** `CommandLine` menunjukkan add-in tanda tangan email yang memanggil skrip lokal saat Outlook dibuka. Dua host itu sama-sama di Customer Service, dan skrip berasal dari paket yang didistribusikan tim IT. Label: jinak, dikonfirmasi ke tim IT.

**Cara membaca hasil:** tiga pasangan, semua jinak setelah dikonfirmasi. Itu belum berarti workstation PT JAB bersih; artinya, di workstation ber-Sysmon, selama 7 hari, untuk parent dan child dalam daftar ini, tidak ada pola yang cocok dengan hipotesis.

**Kapan gagal:** daftar parent atau child terlalu sempit sehingga pola yang dicari tidak masuk filter (misalnya pembaca PDF lain selain `acrord32.exe`); atau penyerang memakai binary yang diganti nama, karena `Image` mencatat path file, bukan nama asli program. Sysmon juga mencatat `OriginalFileName` untuk kasus itu; pemakaiannya dibahas di Day 13.

### 2.4 Laporan hasil `HUNT-2027-001`

Laporan ini adalah langkah Finalize TaHiTI dan fase Act PEAK. Ia juga contoh nyata jawaban pertanyaan kelima Dimas.

```
ID            : HUNT-2027-001                         Selesai: Kamis 2027-02-04
Hasil         : Tidak ditemukan aktivitas berbahaya
Cakupan nyata : Workstation ber-Sysmon (OU Workstations-EDR), 25 Jan - 1 Feb 2027, Sysmon EID 1
                Di luar cakupan: workstation tanpa Sysmon (sekitar 60% workstation, termasuk sebagian
                laptop Bandung yang juga tanpa EDR), server, Linux
Ambang        : Parent dan child dari daftar bagian 2.3; long tail umum (1.146 pasangan) tidak ditinjau
Jinak terkonfirmasi : 3 pasangan (makro Keuangan, inventaris helpdesk via WMI, add-in Outlook)
Celah data    : Cakupan Sysmon 40% workstation -> ke tim Infrastruktur (Agung Prabowo)
Deteksi       : Usulan rule "JAB - Office atau WMI memunculkan shell" dengan pengecualian sempit
                -> ke Sari Kusuma, setelah pola diuji di lab
Hipotesis baru: (1) eksekusi WMI dari host selain JKT-JUMP01; (2) long tail di luar daftar parent,
                dengan path dinormalisasi -> backlog
Pelajaran     : Long tail mentah tidak bisa ditinjau satu orang; persempit dulu dengan pertanyaan
```

"Tidak ditemukan" di laporan ini punya cakupan, ambang, jinak yang terkonfirmasi, dan tiga tindak lanjut. Itulah yang membuatnya bisa dipertanggungjawabkan. TaHiTI menyebut hasil disproven dan inconclusive secara eksplisit [S2].

**Kapan gagal:** baris "Di luar cakupan" dihapus karena terlihat seperti kelemahan. Tanpa baris itu, pembaca akan menganggap seluruh workstation sudah diperiksa.

### 2.5 Satu halaman jawaban untuk Dimas

Ringkasan berikut adalah apa yang kamu kirim ke Dimas Senin sore, sebelum `HUNT-2027-001` dijalankan. Setiap baris merujuk subbagian di atas, supaya Dimas bisa membaca alasannya bila ditanya Hendra.

| Pertanyaan Dimas | Jawaban singkat | Dasar |
|---|---|---|
| Beda dengan triage dan IR | Triage dimulai dari alert, IR dari insiden; hunting dimulai dari pertanyaan, tanpa alert | Bagian 1.1, 1.2 |
| Kenapa perlu walau ES sudah banyak detection | Detection hanya menangkap pola yang sudah dirumuskan; kasus 2026 menunjukkan 66 jam dan sekitar 3 hari tanpa alert | Bagian 1.3 |
| Kerangka | PEAK untuk tipe hunt dan alur, TaHiTI untuk abstract, backlog, dan handover | Bagian 1.4 |
| Posisi dan target Juli | HMM1 sekarang; target perilaku HMM2 konsisten dan awal HMM3 | Bagian 1.5 |
| Bila tidak ditemukan | Laporkan cakupan, jinak terkonfirmasi, celah data, dan usulan deteksi | Bagian 1.6, 2.4 |
| Rekrut threat hunter | Belum; hambatan utama data, bukan orang; evaluasi di akhir percobaan | Bagian 1.7 |

**Kapan gagal:** jawaban dikirim dengan janji angka ("dwell time turun 50%"). Program hunting belum punya data dasar untuk angka seperti itu; metrik program dibahas di Day 15.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** Splunk lab dengan Sysmon dari minimal satu VM Windows (snapshot bersih), dan folder repo portofolio pribadi untuk menyimpan hasil. Jangan memakai data, nama, atau kejadian dari pekerjaan nyata; PT JAB hanya contoh fiktif.

1. **Klasifikasi.** Tulis 10 aktivitas SOC dari pengalamanmu sendiri (disamarkan, tanpa data kerja), lalu beri label detection, hunting, atau IR. Tulis alasannya memakai baris "Pemicu" dan "Selesai saat" di bagian 1.2. Sertakan minimal satu kasus yang mirip pivot saat insiden, dan jelaskan kenapa itu IR.
2. **Self-assessment HMM.** Jawab pertanyaan per level di tabel bagian 1.5 untuk lab-mu, lengkap dengan buktinya. Catat level saat ini, satu kriteria yang kuat, satu yang lemah, dan satu langkah naik dari kolom "Langkah naik".
3. **Backlog.** Buat `hunts/BACKLOG.md` di repo portofolio. Isi tiga abstract dengan format bagian 2.1 dan pemicu berbeda: celah deteksi, intel (laporan publik), dan baseline. Setiap abstract wajib punya baris "Di luar cakupan".
4. **Hunt pertama.** Jalankan query bagian 2.2 di Splunk lab dengan rentang absolut yang sesuai datamu. Catat tiga angka seperti keluaran ilustrasi (jumlah event, pasangan unik, pasangan langka). Bila lab baru, hampir semuanya akan langka; catat itu sebagai pelajaran.
5. **Persempit.** Jalankan query bagian 2.3. Untuk tiap baris, pivot ke `CommandLine` dan beri label jinak, perlu investigasi, atau data tidak cukup, dengan alasan satu kalimat.
6. **Laporan.** Isi template bagian 2.4 dengan hasil nyata, termasuk bila "tidak ditemukan". Tulis cakupan nyata dan yang di luar cakupan.
7. **Uji positif (opsional).** Di VM Windows lab dengan snapshot dan Microsoft Office terpasang, jalankan uji jinak di mana dokumen Office memunculkan `cmd.exe`. Katalog Atomic Red Team memuat test seperti ini di bawah T1204.002 (User Execution: Malicious File); pilih test yang hanya menjalankan perintah tidak berbahaya dan catat GUID-nya. Yang harus terlihat di telemetri: Sysmon EID 1 dengan `ParentImage` berakhiran `WINWORD.EXE` (atau `EXCEL.EXE`) dan `Image` berakhiran `cmd.exe` atau `powershell.exe`, pada user yang membuka dokumen. Ulangi query bagian 2.3 dan pastikan pasangan baru muncul dengan `executions` 1. Ini membuktikan query sanggup menangkap pola yang dicari; tanpa uji ini, "tidak ditemukan" bisa berarti query-nya yang buta.

**Hasil yang sebaiknya tersimpan:**

- 10 aktivitas terklasifikasi dengan alasan.
- Level HMM lab tercatat dengan bukti, kriteria kuat, dan kriteria lemah.
- Tiga abstract di backlog, masing-masing dengan "Di luar cakupan".
- Satu laporan hunt lengkap dengan hasil, cakupan, dan celah data.
- Bila langkah 7 dikerjakan: GUID test, waktu eksekusi, dan bukti query menangkapnya.

**Variasi tantangan:** jalankan stacking yang sama untuk `Image` dan `User` (siapa menjalankan biner langka), lalu bandingkan mana yang lebih informatif di lab-mu. Tambahkan normalisasi path dengan `rex` atau `replace` untuk folder berversi, lalu ukur berapa pasangan langka yang hilang setelah normalisasi.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat menjalankan hunt pertama. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Query bagian 2.2 kosong | Index/sourcetype berbeda, Sysmon tidak terkirim | `index=* EventCode=1 \| stats count by index, sourcetype` |
| Semua pasangan "langka" | Data terlalu sedikit atau baru | Perpanjang rentang, tambah aktivitas normal di VM, atau turunkan ekspektasi |
| Ribuan pasangan langka | Lingkungan besar dan path berversi | Persempit dengan pertanyaan (bagian 2.3); normalisasi path |
| `ParentImage` kosong | Versi/konfigurasi Sysmon atau add-on | Cek event mentah; cek field extraction add-on |
| Hunt tidak pernah "selesai" | Tidak ada kriteria sukses atau cakupan | Tetapkan kriteria di abstract sebelum mulai (bagian 2.1) |
| Temuan tidak ditindaklanjuti | Tidak ada handover | Tentukan penerima: IR, detection, pemilik sistem [S2] |
| Hasil tidak bisa diulang minggu depan | Rentang relatif (`-7d`) di laporan | Tulis rentang absolut di query dan laporan |

## 5. Kesalahan umum dan jebakan

- Menyebut pencarian IOC dari alert sebagai "hunting". Pencarian indikator adalah ciri HMM1. Hunting bernilai tinggi bergerak ke TTP, puncak Pyramid of Pain [S2][S3].
- Menyebut scoping saat insiden sebagai hunting. Tekniknya mirip, tetapi pemicunya insiden dan keputusannya di tangan IC (bagian 1.2).
- Hunting tanpa dokumentasi. Tanpa abstract, kriteria, dan laporan, hunt tidak bisa diulang, diukur, atau ditunjukkan. Hanya 40% organisasi yang mengukur efektivitas hunting secara formal [S4].
- Menganggap "tidak ditemukan" sebagai kegagalan. Itu hasil sah selama cakupan dan celah datanya dinyatakan [S2].
- Hunting di atas data yang buruk. Data kini hambatan nomor satu menurut survei SANS 2026 [S4]. Nilai kualitas data sebelum menyimpulkan (Day 04).
- Menurunkan ambang long tail sampai hasilnya sedikit, bukan mempersempit pertanyaan. Hasilnya terlihat rapi, tetapi yang terbuang tidak pernah ditinjau.
- Mengutip HMM dari ringkasan sekunder. Detail seperti "AI di HMM4" bukan dari sumber asli [S3]. Selalu cek dokumen primer.
- `[komunitas, belum terkonfirmasi]` Pandangan "judul threat hunter jarang; hunting adalah bagian peran L2/L3/DE" berasal dari sumber karier sekunder [S5]; cek dengan memindai lowongan lokal (Indonesia/regional) sendiri.

## 6. Catatan terkini

Bagian ini menampung detail versi, tanggal terbit, dan perubahan sumber. Berguna saat membuka dokumen sumbernya, tetapi tidak mengubah alur kerja di atas.

- **SANS 2026 Threat Hunting Survey (23 Sep 2026):** data melampaui staf sebagai hambatan utama; metodologi formal turun ke 37%; minat AI/ML sebagai rencana perbaikan turun dari 48% ke 39% [S4].
- SANS 2025 (Maret 2025): 61% menyebut kekurangan staf terampil sebagai hambatan utama; outsourcing penuh turun ke 30% [S6]. Pergeseran ke 2026 dirangkum di tabel bagian 1.7.
- **Mandiant M-Trends 2026 (24 Mar 2026):** median global dwell time 14 hari (sebelumnya 11), deteksi internal 52% (2024: 43%), exploit tetap vektor awal paling umum selama enam tahun berturut-turut (32% intrusi) [S7]. Angka berasal dari investigasi Mandiant atas serangan terarah sepanjang 2025, bukan seluruh insiden industri.
- PEAK (2023) tetap kerangka terbaru yang paling banyak dirujuk vendor besar [S1]. Sebagian situs pihak ketiga menulis singkatannya "Act on Knowledge"; Splunk sendiri menulis "Act with Knowledge" [S1]. TaHiTI whitepaper versi yang dibaca di-host ulang Maret 2026, dengan isi metodologi tetap tiga fase dan enam langkah [S2].
- Beberapa ringkasan di web menyebut fase TaHiTI dengan nama lain (Trigger/Investigation/Resolution). PDF aslinya memakai Initiate, Hunt, dan Finalize [S2]. Untuk metodologi, selalu rujuk dokumen primer.

## 7. Cheat sheet

```
DEFINISI  proaktif + dipimpin manusia + iteratif + asumsi deteksi otomatis punya celah
TUJUAN    perpendek breach detection gap (dwell time); hasilkan deteksi, intel, celah data
VS        detect = alert dari logika yang diketahui | hunt = pertanyaan terbuka | IR = insiden
          scoping saat insiden = IR (pemicu insiden, keputusan di IC), walau tekniknya mirip hunt
PEAK      Prepare -> Execute -> Act (with Knowledge); tipe: Hypothesis | Baseline | M-ATH
TaHiTI    Initiate (trigger, abstract, backlog) -> Hunt (define/refine <-> execute) -> Finalize (document, handover)
HASIL     ditemukan | tidak ditemukan (+cakupan) | inkonklusif | data tidak cukup -- semua didokumentasikan
HMM       0 Initial | 1 Minimal | 2 Procedural | 3 Innovative | 4 Leading ; level = "ya" tertinggi DENGAN bukti
ABSTRACT  ID | trigger | tipe | hipotesis | ATT&CK | data+rentang absolut | di luar cakupan | kriteria | handover
STACKING  stats count BY <field-kombinasi> | where count <= N | sort count
          long tail terlalu panjang -> persempit pertanyaan, jangan hanya turunkan ambang
WAKTU     earliest="MM/DD/YYYY:HH:MM:SS" latest="..." untuk hunt yang bisa diulang
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Saat `INC-2026-026`, analyst mencari laptop lain yang menghubungi domain C2 yang sama. Itu threat hunting." Benarkah?

<details><summary>Jawaban</summary>

Tidak tepat. Tekniknya mirip hunting, tetapi pemicunya insiden yang sudah dinyatakan dan keputusannya berada di bawah IC, sehingga kegiatan itu adalah scoping dalam IR. Hunting dimulai dari pertanyaan atau hipotesis tanpa alert atau insiden sebagai pemicu. Pembedanya ada di baris "Pemicu" dan "Selesai saat", bukan di query. Lihat bagian 1.2.

</details>

**2. Skenario keputusan.** `HUNT-2027-001` menghasilkan 1.146 pasangan parent-child langka, dan kamu hanya punya sisa satu hari. Langkah mana yang paling tepat?

- A. Turunkan ambang dari `executions <= 3` menjadi `executions <= 1` supaya daftarnya cukup pendek untuk ditinjau hari ini.
- B. Persempit pertanyaan ke parent dan child yang berisiko, tinjau semua hasilnya, lalu tulis bahwa long tail di luar daftar itu tidak ditinjau dan masukkan sebagai hipotesis baru ke backlog.
- C. Tinjau 50 baris teratas saja, lalu laporkan "tidak ditemukan" untuk seluruh hunt.

<details><summary>Jawaban</summary>

B. Mempersempit pertanyaan adalah define/refine dalam TaHiTI, dan bagian yang tidak ditinjau ditulis sebagai di luar cakupan sehingga hasil "tidak ditemukan" tetap jujur. A keliru karena ambang yang diturunkan membuang data tanpa alasan analitis dan tanpa catatan. C keliru karena hasil "tidak ditemukan" dilaporkan untuk data yang tidak pernah diperiksa. Lihat bagian 2.2 dan 2.3.

</details>

**3. Pertanyaan jebakan.** "SOC PT JAB rutin mencocokkan IOC dari laporan intel ke data historis, punya Sysmon, EDR, dan log jaringan di Splunk. Jadi PT JAB sudah HMM2." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Pencarian IOC dari intel adalah ciri HMM1. HMM2 membutuhkan prosedur hunting buatan pihak lain yang dijalankan secara terjadwal, dengan bukti seperti kalender hunt dan daftar tanggal eksekusi, dan PT JAB belum punya itu. Data yang lengkap memenuhi kriteria koleksi data, tetapi level ditentukan oleh pertanyaan tertinggi yang bisa dijawab "ya" dengan bukti. Cakupan Sysmon 40% juga menunjukkan kriteria data pun belum merata. Lihat bagian 1.5.

</details>

**4. Skenario keputusan.** Hendra bertanya, "Kalau ES sudah punya ratusan detection, kenapa saya harus mengalokasikan dua hari per minggu analyst untuk hunting?" Jawaban mana yang paling kuat?

- A. "Karena vendor dan survei menyarankan setiap SOC melakukan hunting."
- B. "Karena detection hanya menangkap pola yang sudah dirumuskan. Di `INC-2026-017` penyerang di dalam sekitar 66 jam sebelum alert enkripsi, dan di `INC-2026-026` satu laptop beacon tiga hari tanpa alert. Hunting sengaja mencari di jarak waktu itu, dan hasilnya juga menjadi detection baru."
- C. "Karena hunting akan menurunkan dwell time kita sampai di bawah median industri 14 hari."

<details><summary>Jawaban</summary>

B. Jawaban itu memakai bukti dari lingkungan PT JAB sendiri dan menjelaskan mekanismenya: celah antara pola yang sudah dirumuskan dan perilaku penyerang. A keliru karena tidak menjawab kenapa PT JAB khususnya membutuhkannya. C keliru karena menjanjikan angka tanpa data dasar, dan median M-Trends berasal dari kasus yang ditangani satu vendor, bukan ukuran yang bisa dibandingkan langsung dengan PT JAB. Lihat bagian 1.3.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Gilang Ramadhan (analyst L1), dalam tiga kalimat, kenapa laporan `HUNT-2027-001` yang hasilnya "tidak ditemukan" tetap berguna.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Laporan itu menulis persis apa yang sudah diperiksa: Sysmon 7 hari dari workstation yang punya Sysmon, untuk Office, browser, dan WMI yang memunculkan shell, dan semuanya jinak setelah dicek. Laporan yang sama juga menulis apa yang belum bisa diperiksa, yaitu sekitar 60% workstation tanpa Sysmon, sehingga tim Infrastruktur tahu apa yang harus dibereskan. Dari situ lahir satu usulan rule untuk Office atau WMI yang memunculkan shell, jadi pola yang kita cari kali ini akan langsung jadi alert di antreanmu bila muncul nanti."

Kesalahan yang sering muncul:
- Mengatakan "tidak ditemukan berarti aman", padahal hanya berlaku untuk cakupan yang diperiksa.
- Lupa menyebut celah data, padahal itu keluaran paling konkret hunt ini.
- Tidak mengaitkan dengan pekerjaan L1, yaitu alert baru yang akan muncul dari usulan rule.

</details>

**6. Pertanyaan jebakan.** "Hunt yang berhasil sebaiknya terus dijalankan manual setiap minggu oleh hunter, supaya pengetahuannya tidak hilang." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Hunt yang berhasil dan berulang sebaiknya diotomasi menjadi deteksi atau job terjadwal, sehingga hunter bebas mengerjakan pertanyaan baru. Itu ciri HMM tingkat atas dan bagian dari fase Act di PEAK. Menjalankan ulang query yang sama secara manual tanpa pertanyaan baru adalah triage, bukan hunting. Lihat bagian 1.2 dan 1.5.

</details>

**7. Interview question (English).** "How is threat hunting different from what a SOC analyst does when triaging alerts?"

<details><summary>Sample answer</summary>

"The difference is the trigger and the definition of done. Triage starts from an alert and ends when the alert is dispositioned. Hunting starts from a hypothesis, built from intel, a past incident or a known detection gap, assumes our detections have blind spots, and ends when the hypothesis is proven, disproven or found inconclusive. A good hunt has a written scope before it starts: data source, time range, hosts in and out of scope, and success criteria. The outputs are also different: a hunt can hand a finding to IR, but even a negative result produces a documented scope, confirmed benign activity, data gaps for the infrastructure team and often a new detection. If a hunt keeps working, I want it automated as a detection, so the hunter moves on to the next question."

What makes this answer strong: it separates hunting from triage by trigger and exit criteria rather than by tooling, treats negative results as valuable when scoped, and closes the loop to detection engineering.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Splunk: Introducing the PEAK Threat Hunting Framework | https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html | sekunder (blog vendor, penulis kerangka) | 2023-04-18; diakses 2026-10-07, dicek ulang 2026-10-18 | Tinggi untuk definisi PEAK, fase, tiga tipe hunt, dan posisi Knowledge |
| S2 | TaHiTI: a threat hunting methodology (whitepaper) | https://www.betaalvereniging.nl/wp-content/uploads/2026/03/TaHiTI-Threat-Hunting-Methodology-whitepaper.pdf | primer (pemilik metodologi) | di-host 2026-03; diakses 2026-10-07 | Tinggi |
| S3 | Sqrrl: Hunt Evil: Your Practical Guide to Threat Hunting (berisi HMM) | https://www.threathunting.net/files/hunt-evil-practical-guide-threat-hunting.pdf | primer (panduan Sqrrl yang memuat HMM) | tahun tidak tercantum; diakses 2026-10-07 | Tinggi untuk HMM. Dokumen vendor lama (lebih dari 3 tahun), ada konten pemasaran produk |
| S4 | SANS: Threat hunters call data their biggest barrier (2026 survey) | https://www.sans.org/press/announcements/threat-hunters-call-data-their-biggest-barrier-overtaking-staffing-first-time-survey-finds | sekunder (rilis pers survei) | 2026-09-23; diakses 2026-10-07 | Sedang-tinggi. Angka dari rilis pers, bukan laporan lengkap |
| S5 | Wiz Academy: Threat Hunters: Responsibilities, Salary, Career Progression | https://www.wiz.io/academy/threat-hunters | sekunder | diakses 2026-10-10 | Rendah-sedang. Konten vendor tentang karier |
| S6 | SANS 2025 Threat Hunting Survey: Advancements in Threat Hunting Amid AI and Cloud Challenges (Josh Lemon) | https://www.sans.org/white-papers/sans-2025-threat-hunting-survey-advancements-threat-hunting-amid-ai-cloud-challenges | sekunder (halaman ringkasan survei) | 2025-03-13; diakses 2026-10-10 | Sedang-tinggi. Angka dari halaman ringkasan; salinan lama di giac.org tidak lagi tersedia |
| S7 | Google Cloud / Mandiant: M-Trends 2026: Data, Insights, and Strategies From the Frontlines | https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/ | sekunder (laporan vendor IR) | 2026-03-24; diakses 2026-10-18 | Sedang-tinggi. Median dwell time 14 hari (sebelumnya 11), deteksi internal 52% (2024: 43%), jeda hand-off 22 detik pada 2025, exploit 32% vektor awal. Hanya kasus yang ditangani Mandiant |

**Catatan sumber:** angka survei SANS 2025 dan 2026 diambil dari halaman ringkasan dan rilis pers, bukan laporan lengkap; cocokkan dengan laporan bila angka dipakai di presentasi atau dokumen formal. Angka M-Trends [S7] diambil dari halaman blog ringkasan, bukan laporan penuh, dan menggambarkan kasus satu vendor. Tahun terbit dokumen Hunt Evil tidak tercantum di dokumennya. Klaim tentang jarangnya judul "Threat Hunter" berasal dari konten karier vendor [S5] dan perlu dicek terhadap lowongan di pasar kerja-mu sendiri. Penilaian HMM PT JAB, jawaban untuk Dimas, dan seluruh isi `HUNT-2027-001` (host, angka, label) adalah penerapan catatan ini pada organisasi fiktif, bukan hasil eksekusi nyata.
