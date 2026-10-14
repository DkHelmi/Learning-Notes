---
day: 34
title: 'Investigasi lima tahap dan metrik: continuous monitoring, Review events sampai Re-assess, MTTD, MTTR, dan dwell time'
researched_on: 2026-10-10
versions_checked: 'Splunk Lantern "Creating an incident workflow in Splunk Enterprise Security" (lima tahap); Splunk blog "The Continuous Monitoring Ultimate Guide" (7 Mei 2024); Splunk blog "SOC Metrics" (18 Mei 2023); ES 8.4 response plans (Mission Control); ES 8.7; ES 7.3 Investigations; NIST SP 800-61r3 (Apr 2025); TaHiTI whitepaper (breach detection gap); SANS 2026 Threat Hunting Survey'
---

# Day 34: Investigasi lima tahap dan metrik

Cakupan: continuous monitoring sebagai pemasok antrean, lima tahap alur kerja insiden menurut Splunk beserta hasil yang ditinggalkan tiap tahap, response plan di ES 8, lalu metrik yang mengukur semuanya (MTTD, MTTA, MTTI, MTTR, dwell time, FP rate) dan cara menghitungnya dari data Splunk.

## Ide inti

Triage berhenti saat sebuah alert terbukti nyata atau diserahkan ke orang lain. Yang terjadi setelah itu menentukan apakah kasusnya benar-benar selesai: menentukan ruang lingkup, bertindak, lalu memperbaiki hal yang membuat kasus itu bisa terjadi dan terlambat terlihat. Lima tahap alur kerja insiden adalah kerangka untuk semua itu, dan gunanya bukan supaya terlihat rapi, tetapi supaya tiap tahap meninggalkan satu hasil yang bisa dipakai orang lain: daftar yang perlu dinilai, disposisi dan prioritas, ruang lingkup yang terdokumentasi, tindakan beserta pemiliknya, dan satu perubahan konkret pada detection atau data.

Lapisan kedua Day ini adalah metrik. Kerangka tahap menjawab "apa yang dikerjakan", metrik menjawab "seberapa cepat dan seberapa benar kita mengerjakannya". Keduanya satu paket, karena metrik waktu hanya bisa dihitung bila setiap tahap mencatat waktunya, dan metrik kualitas hanya bisa dihitung bila setiap kasus ditutup dengan disposisi yang benar. Itu sebabnya Day ini membahas keduanya bersama, lalu diakhiri dengan bagian yang paling sering dilewati: apa yang bisa salah ketika angka itu dibawa ke rapat.

Kamu sudah mengenal keduanya dari NOC. Penanganan gangguan punya urutan baku (alarm, verifikasi, menentukan segmen yang terdampak, perbaikan, post-mortem) dan laporan bulanan punya MTTR per kategori gangguan yang dipakai manajemen untuk menilai tim. Batas analogi: di NOC titik awal MTTR hampir selalu diketahui persis karena alarm atau laporan pelanggan menjadi penanda mulai, sedangkan di SOC titik awal yang sebenarnya adalah saat penyerang masuk, dan itu hanya ditemukan setelah investigasi atau forensik. Konsekuensinya, satu angka metrik SOC bisa terlihat bagus hanya karena kompromi yang lama tidak pernah ditemukan.

```
monitoring berkelanjutan  ->  alert / finding masuk antrean
  1 Review events    hasil: daftar yang perlu dinilai
  2 Assessment       hasil: disposisi awal, prioritas, owner
  3 Determine risk   hasil: ruang lingkup (host, akun, data yang terkena)
  4 Mitigate         hasil: tindakan beserta pemiliknya, atau penyerahan
  5 Re-assess        hasil: satu perubahan pada detection, data, atau prosedur

T0 kompromi --- T1 deteksi --- T2 attend/analisis --- T3 investigasi mulai --- T4 resolusi
|<------- dwell time ------->|
                             |<-- MTTA&A -->|
                             |<--------- MTTI --------->|
                             |<------------------- MTTR ------------------->|
|<---------------- MTTD (kejadian sampai deteksi) ----->|
```

Situasi yang dipakai sepanjang Day ini: pukul 08.15 di PT Jaringan Anak Bangsa (PT JAB, ISP menengah fiktif dengan SOC internal enam analyst L1 tiga shift, dua analyst L2, satu detection engineer, dan satu SOC lead), SOC-2026-0217 masih berstatus In-progress di tangan L2 on-call. Kasusnya sudah jelas: IP `203.0.113.45` menebak password VPN 180 kali ke 25 akun antara 01.52 dan 02.06, satu login berhasil atas nama `rina.wulandari` pada 02.04.13, lalu akun `adm.rina` dipakai masuk ke `JKT-JUMP01` dari pool IP VPN. Shift malam sudah menutup triage dengan disposisi True Positive dan mengeskalasi pada 02.42. SOC lead menulis:

> "SOC-2026-0217 sudah di tangan L2 sejak subuh dan belum selesai. Aku butuh dua hal. Pertama, apa saja yang masih harus dikerjakan sampai kasus ini benar-benar tuntas, dan hasil apa yang harus ada di tiket saat kita menutupnya. Kedua, untuk rapat kuartalan minggu depan: berapa lama kita biasanya mendeteksi dan menyelesaikan kasus, dan angka mana yang boleh aku bawa ke manajemen tanpa menyesatkan mereka."

Pesan itu memuat enam pertanyaan:

1. Apa yang memasok antrean setiap hari, dan kenapa monitoring harus berkelanjutan?
2. Kenapa investigasi perlu kerangka tetap, bukan kebiasaan masing-masing analyst?
3. Tahap apa yang tersisa setelah triage, dan hasil apa yang ditinggalkan tiap tahap?
4. Bagaimana memastikan dua analyst mengerjakan tahap yang sama dengan cara yang sama?
5. Metrik apa yang mengukur semua itu, dan di mana titik awal serta titik akhirnya?
6. Angka mana yang menyesatkan bila dibawa ke rapat tanpa penjelasan?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3 dan 1.4, pertanyaan 4 di bagian 1.5, pertanyaan 5 di bagian 1.6 dan 1.7, dan pertanyaan 6 di bagian 1.8. Bagian 2 menjalankan query per tahap dan query metriknya untuk PT JAB.

**Kapan relevan:** saat sebuah kasus sudah lewat triage dan harus dibawa sampai tuntas, saat menyusun atau menilai response plan dan prosedur investigasi, dan saat menyiapkan angka kinerja SOC untuk rapat manajemen atau laporan kuartalan.
**Kapan bukan jawaban:** ini bukan panduan forensik mendalam (akuisisi memori, timeline disk) dan bukan prosedur manajemen krisis yang melibatkan legal dan komunikasi publik. Metrik di sini juga tidak menilai apakah detection-mu menutupi teknik yang benar; cakupan detection dinilai dengan cara lain (Day 27 dan Day 30).

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah triage, disposisi, status, urgency, dan finding dari Day 07 tidak diulang di sini. Tabel ini memuat istilah alur kerja investigasi dan metrik yang dipakai Day ini; cari kolom padanan bila sebuah istilah terasa jauh dari pekerjaan harian.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Continuous monitoring | Proses berjalan terus untuk mengumpulkan, menganalisis, dan menindaklanjuti data lingkungan TI | Polling NMS 24 jam dibanding audit konfigurasi bulanan |
| Lima tahap alur kerja insiden | Review events, Assessment, Determine risk, Mitigate, Re-assess | Urutan baku penanganan gangguan: alarm, verifikasi, cari ruang lingkup, perbaiki, post-mortem |
| Investigation | Wadah kerja untuk satu kasus: artefak, timeline, catatan, tugas | Satu tiket gangguan besar dengan lampiran dan kronologi |
| Response plan | Daftar fase dan tugas yang harus diselesaikan analyst untuk satu jenis kasus | SOP penanganan per jenis gangguan di NOC |
| T0 sampai T4 | Titik waktu di satu insiden: kompromi, deteksi, mulai ditangani, investigasi dibuka, selesai | Jam kejadian, jam alarm, jam diambil teknisi, jam perbaikan selesai di tiket |
| MTTD | Rata-rata waktu dari kejadian sampai terdeteksi | Rata-rata jeda antara gangguan mulai dan alarm muncul |
| MTTA&A | Rata-rata waktu dari deteksi sampai kasus ditangani dan dianalisis | Waktu alarm menganggur sebelum dipegang operator |
| MTTI | Rata-rata waktu dari deteksi sampai investigasi dimulai | Jeda sebelum teknisi mulai menelusuri penyebab |
| MTTR | Rata-rata waktu dari deteksi sampai kasus selesai | MTTR gangguan di laporan SLA bulanan |
| MTRS | Rata-rata waktu dari deteksi sampai layanan pulih | Waktu layanan pelanggan kembali normal |
| Dwell time (breach detection gap) | Jarak waktu antara kompromi awal dan saat penyerang ditemukan | Lama gangguan berjalan tanpa terpantau karena titik monitoring tidak ada |
| FP rate dan FN rate | Proporsi yang salah dinilai sebagai insiden, dan proporsi ancaman yang terlewat | Proporsi alarm palsu dan gangguan yang tidak pernah memicu alarm |
| Median dan p90 | Nilai tengah dan nilai yang dilampaui satu dari sepuluh kasus | Angka yang dipakai agar satu gangguan panjang tidak menyetir laporan |
| Reopen rate | Proporsi kasus yang dibuka kembali setelah ditutup | Tiket gangguan yang kambuh setelah dinyatakan selesai |

### 1.1 Continuous monitoring: kenapa antrean tidak pernah kosong

Pertanyaan pertama SOC lead sebenarnya tentang pasokan: dari mana kasus seperti SOC-2026-0217 datang setiap hari. Jawabannya adalah monitoring yang tidak berhenti.

Blog Splunk mendefinisikan continuous monitoring sebagai proses berkelanjutan dan real-time untuk mengumpulkan, menganalisis, dan bertindak atas data di seluruh lingkungan TI, dengan tujuan mendeteksi dan menangani ancaman, kerentanan, serta masalah performa sebelum berdampak [S2].

Empat komponennya [S2]:

1. **Data collection:** log, trafik jaringan, dan aktivitas aplikasi (Day 21).
2. **Analysis:** mencari pola, anomali, dan ancaman lewat detection (Day 36).
3. **Reporting:** dashboard kesehatan dan keamanan yang dibaca rutin (Day 32).
4. **Response:** alert dan tindakan protektif (Day 41 dan Day 42).

Langkah penerapannya [S2]:

1. tetapkan tujuan monitoring;
2. pilih teknologi untuk sumber data yang dibutuhkan;
3. tetapkan ambang dan parameter alert;
4. siapkan prosedur respons insiden;
5. tinjau efektivitasnya secara rutin.

Tantangan yang disebut sumber yang sama: volume data, kebutuhan sumber daya, kompleksitas integrasi, dan alert fatigue akibat false positive [S2]. Tiga di antaranya terasa langsung di PT JAB. Index `dns` saja sekitar 42 GB per hari dari total sekitar 94 GB, jadi setiap detection baru di atasnya langsung menjadi perkara biaya dan kecepatan, dan antrean L1 yang penuh membuat kasus seperti SOC-2026-0217 bisa menunggu. Jawaban untuk alert fatigue bukan menambah analyst, melainkan mengubah cara sinyal kecil diakumulasi sebelum menjadi alert (Day 35).

Kata "berkelanjutan" menanggung beban penting di sini. Penyerang tidak menyesuaikan jadwalnya dengan jadwal tinjauan. Monitoring periodik, misalnya tinjauan log bulanan, menyisakan celah waktu, dan celah itu persis yang diukur sebagai dwell time di bagian 1.6. Perhatian yang perlu dipegang: continuous monitoring adalah proses (koleksi, analisis, pelaporan, respons, peninjauan), bukan sebuah layar yang menyala terus [S2].

### 1.2 Kenapa investigasi perlu kerangka

Di PT JAB, dua analyst L2 bekerja di shift berbeda dan jarang bertemu. Tanpa kerangka, cara mereka menangani kasus yang sama berbeda: satu orang langsung memblokir IP dan menutup tiket, satu orang lagi menghabiskan tiga jam mencari host lain yang terdampak. Keduanya terasa benar bagi pelakunya, tetapi hasilnya tidak bisa dibandingkan, tidak bisa diukur, dan tidak bisa diambil alih di tengah jalan.

Kerangka tahap menyelesaikan tiga masalah sekaligus. Pertama, konsistensi: setiap kasus melewati pertanyaan yang sama, sehingga kasus yang ditangani analyst berbeda tetap sebanding. Kedua, keterambilalihan: karena tiap tahap meninggalkan hasil tertulis, kasus bisa pindah tangan saat shift berganti tanpa kehilangan konteks. Ketiga, keterukuran: titik perpindahan antar tahap adalah titik waktu, dan titik waktu itulah yang menjadi bahan metrik di bagian 1.6. Tanpa tahap yang jelas, pertanyaan "berapa MTTI kita" tidak punya jawaban, karena tidak ada peristiwa yang bisa disebut "investigasi dimulai".

Lantern menyebut tujuan alur kerjanya dengan tiga kata: analyst menyelesaikan investigasi secara konsisten, efisien, dan kolaboratif [S1]. Tiga kata itu pas dengan tiga masalah di atas.

### 1.3 Lima tahap dan hasil tiap tahap

Nama dan urutan lima tahap di Day ini mengikuti artikel Lantern tentang alur kerja insiden di ES [S1]. Materi pelatihan resmi Splunk bisa memakai nama yang sedikit berbeda; bila itu terjadi, pegang konsepnya (triage, analisis, mitigasi, evaluasi ulang), karena konsep itu konsisten lintas kerangka.

Tabel berikut menyusun kelima tahap beserta pertanyaan yang dijawab analyst, hasil yang harus ada di tiket setelah tahap itu, dan tempat pengerjaannya di ES. Kolom "Hasil yang ditinggalkan" adalah kolom yang paling sering diabaikan, padahal itulah yang membuat tahap berikutnya mungkin.

| # | Tahap | Pertanyaan analyst | Hasil yang ditinggalkan | Tempat di ES (7 lalu 8) |
|---|---|---|---|---|
| 1 | Review events | "Apa yang masuk ke antreanku?" | Daftar alert, finding, email, atau tiket yang perlu dinilai, beserta sumber pemicunya | Incident Review (ES 7), analyst queue di Mission Control (ES 8) |
| 2 | Assessment | "Asli atau tidak, dan seberapa penting?" | Disposisi awal, urgency, dan owner; alasan satu kalimat di note | Ubah status, urgency, owner; konteks aset dan identitas (Day 26) |
| 3 | Determine risk | "Seberapa luas, dan apa yang terkena?" | Daftar host, akun, dan data yang terdampak, beserta artefak dan rentang waktunya | Investigation workbench (ES 7) [S5], investigation di Mission Control (ES 8), risk analysis dan pivot (Day 24) |
| 4 | Mitigate | "Apa yang dilakukan sekarang, dan oleh siapa?" | Tindakan yang dijalankan beserta waktu dan pelakunya, atau penyerahan ke pemilik lain | Adaptive response (Day 41), SOAR playbook (Day 42), response plan |
| 5 | Re-assess | "Apa pelajarannya, dan apa yang diubah?" | Satu perubahan konkret: tuning detection, detection baru, perbaikan data, atau perubahan prosedur | Tinjauan kasus yang sudah ditutup, tuning, dan metrik (bagian 1.6) |

Tahap 1 dan 2 adalah wilayah triage L1 dan dibahas sebagai pekerjaan utuh di Day 07, termasuk lima pertanyaan pertama, enrichment, dan kriteria eskalasi. Day ini memakainya sebagai titik masuk saja, lalu menghabiskan waktu di tahap 3 sampai 5.

Dua catatan yang membuat tabel ini berguna di lapangan. Tahap 3 menjawab pertanyaan ruang lingkup dengan daftar yang bisa dihitung, bukan berhenti pada "mencari tahu lebih banyak", karena daftar itulah yang menentukan luas tindakan di tahap 4. Pada SOC-2026-0217, ruang lingkupnya bukan satu akun: ada `rina.wulandari` di VPN, `adm.rina` di `JKT-JUMP01`, dan `JKT-FS01` yang diakses lewat logon jaringan. Menutup kasus dengan hanya mereset satu password berarti menyelesaikan satu dari tiga hal. Tahap 5 juga bukan formalitas: tanpa tahap ini, detection yang berisik tetap berisik dan celah yang sama terulang [S1].

### 1.4 Hubungan dengan siklus NIST

SOC lead akan ditanya auditor dengan kosakata lain, jadi pemetaannya perlu dipegang. NIST SP 800-61r3 (April 2025) tidak lagi memakai siklus empat fase lama (preparation; detection and analysis; containment, eradication and recovery; post-incident activity). Revisi ini menempatkan respons insiden di dalam manajemen risiko siber organisasi dan memetakannya ke enam fungsi CSF 2.0: Govern, Identify, dan Protect untuk persiapan, lalu Detect, Respond, dan Recover untuk responsnya, dengan perbaikan berkelanjutan yang berasal dari setiap fungsi [S4].

ES 8 sendiri menyediakan response plan bawaan, termasuk template "NIST 800-61" dan "Generic Incident Response" dengan fase detect, analyze, contain, eradicate, recover, dan review [S3]. Pemetaan kasar antara lima tahap Splunk dan fase itu:

- Review events dan Assessment kira-kira setara detect dan analisis awal;
- Determine risk kira-kira setara analyze dalam arti scoping;
- Mitigate kira-kira setara contain, eradicate, dan recover;
- Re-assess kira-kira setara review atau lessons learned.

Yang perlu disadari saat memakai pemetaan ini di laporan: lima tahap Splunk adalah alur kerja satu kasus di satu alat, sedangkan CSF 2.0 adalah kerangka program keamanan organisasi. Keduanya bisa diselaraskan, tetapi menyebut lima tahap sebagai "implementasi NIST" terlalu jauh.

### 1.5 Response plan di ES 8

Pertanyaan keempat SOC lead, bagaimana memastikan dua analyst mengerjakan tahap yang sama dengan cara yang sama, dijawab ES 8 secara teknis lewat response plan.

- Response plan berisi fase dan tugas yang harus diselesaikan analyst saat menyelidiki dan merespons sebuah kasus [S3].
- ES 8 menyertakan delapan template: Account Compromise, Data Breach, Network Indicator Enrichment, NIST 800-61, Generic Incident Response, Self-Replicating Malware, Suspicious Email, dan Vulnerability Disclosure [S3].
- Penerapannya: di Mission Control, pilih investigation, buka View details, masuk ke tab Response, lalu tetapkan response plan. Response plan juga bisa dikaitkan dengan investigation type agar otomatis diterapkan ke kasus berikutnya dengan jenis yang sama [S3].

Untuk SOC-2026-0217, template yang paling dekat adalah Account Compromise, dan nilainya bukan pada daftar tugasnya saja, melainkan pada jejaknya: tugas yang selesai dan waktunya tercatat, sehingga tahap mana yang memakan waktu bisa dilihat belakangan. Response plan adalah cara ES 8 membuat tahap 3 sampai 5 konsisten tanpa bergantung pada ingatan analyst.

**Tanpa ES:** di PT JAB, sebagian kasus tidak pernah lewat ES karena alert terjadwal dari Search & Reporting masuk langsung ke sistem tiket. Lima tahap tetap berlaku, hanya wadahnya berbeda: antrean adalah daftar tiket, investigation adalah satu tiket dengan lampiran dan kronologi, response plan diganti checklist tahap di template tiket, dan tindakan dijalankan manual lalu dicatat sebagai komentar bertanggal. Metriknya pun dihitung dari data sistem tiket, bukan dari field finding (bagian 2.8). Yang hilang tanpa ES adalah konteks aset dan identitas otomatis, perhitungan urgency, akumulasi risiko per entity, dan dashboard SOC bawaan (Day 32). Yang tidak boleh hilang adalah kosakata disposisinya, supaya angka dari dua jalur itu masih bisa digabung.

### 1.6 Timeline insiden dan metrik yang mengukurnya

Semua metrik di bagian ini adalah jarak antara dua titik waktu di satu insiden. Karena itu urutannya perlu dipegang lebih dulu, lalu nama metriknya menyusul.

```
T0 kompromi awal ---- T1 deteksi ---- T2 di-attend/analisis ---- T3 investigasi mulai ---- T4 resolusi/pemulihan
|<------------- dwell time / breach detection gap ------>|
                                      |<-- MTTA&A -->|
                                      |<--------- MTTI --------->|
                                      |<------------------- MTTR (resolve) ------------------------>|
|<---- MTTD (dari kejadian/kompromi sampai deteksi) ---->|
```

Definisi berikut mengikuti blog SOC Metrics dari Splunk [S6]:

- **MTTD (Mean Time to Detect):** rata-rata waktu yang dibutuhkan SOC untuk mendeteksi insiden atau breach.
- **MTTA&A (Mean Time to Attend and Analyze):** rata-rata waktu merespons dan menganalisis insiden, sejak terdeteksi sampai prioritas, dampak, dan kemungkinan resolusinya dipastikan.
- **MTTI (Mean Time to Investigate):** rata-rata waktu dari deteksi sampai investigasi dimulai.
- **MTTR (Mean Time to Resolution):** rata-rata waktu menyelesaikan insiden sepenuhnya, dihitung sejak terdeteksi.
- **MTRS (Mean Time to Restore Service):** dari deteksi sampai layanan pulih sepenuhnya.
- **FP rate:** persentase yang diklasifikasikan sebagai insiden padahal bukan ancaman. **FN rate:** persentase yang diklasifikasikan bukan ancaman padahal ancaman nyata [S6].

Singkatan MTTR adalah sumber kekacauan paling sering, karena di organisasi lain dibaca sebagai Mean Time to Respond, to Repair, atau to Recover. Sebelum membandingkan angka dengan siapa pun, tulis titik awal dan titik akhirnya.

**Dwell time** berdiri sendiri karena bukan rata-rata. Dwell time adalah jarak antara kompromi awal dan saat penyerang ditemukan, dan metodologi TaHiTI menyebutnya breach detection gap sekaligus menyebut memperpendeknya sebagai tujuan utama threat hunting [S7]. Dua konsekuensi praktisnya: dwell time dihitung per insiden, bukan sebagai rata-rata antrean, dan angkanya baru ada setelah investigasi atau forensik menemukan T0. Pada SOC-2026-0217, T0 adalah login VPN berhasil pada 02.04.13 dan T1 adalah alert pada 02.10, sehingga dwell time-nya hanya sekitar enam menit. Pada kasus persistence seperti SOC-2026-0263, T0 ditemukan belakangan dari jejak scheduled task, dan dwell time-nya terhitung dalam minggu. Keduanya dihitung di bagian 2.7.

Satu angka untuk konteks: survei SANS 2026 Threat Hunting dengan 500 responden mencatat hanya 40 persen program hunting yang mengukur efektivitasnya secara formal, turun dari 64 persen pada 2024 [S10]. Kemampuan mengukur ternyata bukan hal yang dimiliki semua SOC, dan itu membuatnya pembeda yang murah.

### 1.7 Disposisi sebagai sumber data metrik

Metrik waktu memerlukan jejak waktu, metrik kualitas memerlukan disposisi. FP rate per detection tidak bisa dihitung bila analyst menutup kasus tanpa memilih label, atau memilih label yang salah, dan MTTR tidak bermakna bila status serta waktu tutupnya tidak konsisten. Kosakata disposisi, tujuh label bawaan ES 8.7, kriteria bukti minimumnya, dan siapa yang menindaklanjuti setiap label dibahas di Day 07 bagian 1.4 sampai 1.6; Day ini hanya memakainya sebagai kolom data di query bagian 2.5.

### 1.8 Metrik yang berguna dan metrik yang menyesatkan

Pertanyaan terakhir SOC lead adalah yang paling penting: angka mana yang boleh dibawa ke rapat. Setiap metrik punya cara gagal yang khas, dan hampir semuanya gagal lewat jalur yang sama, yaitu orang mengoptimalkan angkanya, bukan hal yang diukurnya.

Tabel berikut memasangkan setiap metrik dengan apa yang sebenarnya diukurnya dan cara metrik itu rusak saat dijadikan target. Kolom terakhir adalah yang perlu kamu sebut sendiri di rapat sebelum ada yang menyimpulkan terlalu jauh.

| Metrik | Mengukur | Risiko salah pakai |
|---|---|---|
| MTTD | Kecepatan deteksi | Bergantung pada T0 yang sering baru diketahui belakangan, jadi angkanya hanya mencakup insiden yang sudah dipahami |
| MTTA&A dan MTTI | Kecepatan mengambil dan mulai menelusuri | Mendorong kebiasaan mengklaim kasus cepat tanpa analisis supaya angka terlihat bagus |
| MTTR | Kecepatan penyelesaian | Mendorong penutupan dini, sehingga resolusi palsu terbaca sebagai perbaikan |
| MTRS | Kecepatan layanan pulih | Layanan pulih bukan berarti penyerang hilang; keduanya sering dicampur |
| Dwell time | Efektivitas deteksi dari ujung ke ujung | Sampel kecil dan hanya berasal dari insiden yang ditemukan, jadi rata-ratanya mudah menyesatkan |
| FP rate per detection | Kualitas detection | Butuh disposisi yang konsisten; satu label untuk semua jenis FP membuat angkanya tidak bisa ditindaklanjuti |
| Volume kasus per analyst | Beban kerja | Tidak mencerminkan kualitas, dan mudah dinaikkan dengan menutup kasus mudah lebih dulu |

Tiga prinsip yang membuat tabel itu bisa dipakai:

1. **Pasangkan kecepatan dengan kualitas.** MTTR yang turun bersamaan dengan reopen rate atau FN yang naik bukan perbaikan, melainkan pergeseran masalah.
2. **Laporkan median dan p90, bukan hanya rata-rata.** Satu kasus panjang cukup untuk merusak rata-rata, dan p90 menjawab pertanyaan yang sebenarnya ingin diketahui manajemen: seberapa buruk kasus yang paling lambat.
3. **Tulis definisi di laporan.** Definisi metrik di catatan ini berasal dari blog vendor tahun 2023 [S6], bukan standar yang disepakati industri. Organisasi lain memakai titik awal dan akhir yang berbeda untuk nama yang sama, jadi angka tanpa definisi tidak bisa dibandingkan dan tidak bisa dibantah.

## 2. Contoh SPL dan langkah untuk SOC-2026-0217 dan rapat kuartalan

Semua keluaran di bagian ini adalah keluaran ilustrasi dari lingkungan PT JAB, bukan hasil eksekusi. Query dengan macro `` `notable` `` adalah pola ES 7.x; di ES 8 antrean berada di analyst queue Mission Control, dan sumber data finding beserta nama fieldnya perlu dicek di instance sendiri sebelum query ini dipakai. Bagian 2.1 sampai 2.5 mengikuti lima tahap, bagian 2.6 sampai 2.8 menghitung metriknya, dan bagian 2.9 merangkum langkah di ES 8.7.

### 2.1 Tahap 1, Review events: apa yang baru di antrean

**Tujuan:** melihat isi antrean pagi ini sebelum memilih kasus, supaya SOC-2026-0217 tidak dikerjakan sambil menumpuk kasus critical lain.

```
`notable` earliest=-24h
| where status_label="New"
| stats count BY rule_name urgency
| sort - count
```

- `` `notable` `` adalah macro ES 7.x yang membuka index notable event; `earliest=-24h` dipakai karena ini data live.
- `where status_label="New"` menyisakan yang belum diambil siapa pun.
- `stats count BY rule_name urgency` menjawab dua hal sekaligus: detection mana yang paling banyak menyumbang, dan apakah ada yang berprioritas tinggi tersembunyi di bawah tumpukan.

Keluaran ilustrasi:

```
rule_name                                      urgency    count
JAB - Eksekusi dari direktori temp             medium        23
JAB - Login berhasil setelah rangkaian gagal   high           4
JAB - Akun baru masuk grup admin               critical       1
```

**Cara membaca hasil:** 28 finding baru, dan yang paling banyak bukan yang paling penting. Satu baris critical di dasar daftar itulah yang menentukan urutan kerja, bukan 23 baris medium di atasnya. Kalau diurutkan hanya dengan `sort - count`, baris critical justru tenggelam, jadi di layar sehari-hari urutkan berdasarkan urgency lalu waktu.

**Variasi:** ganti `BY rule_name urgency` menjadi `BY owner status_label` untuk melihat distribusi beban antar analyst, berguna saat shift berganti.

**Kapan gagal:** bila sebagian alert tidak pernah menjadi notable karena hanya dikirim sebagai email atau webhook ke sistem tiket, antrean di query ini tidak lengkap. Di PT JAB kasus itu nyata, jadi dua sumber antrean harus dilihat berdampingan.

### 2.2 Tahap 2, Assessment: konteks cepat untuk satu kasus

**Tujuan:** memastikan gambaran aktivitas dari `203.0.113.45` dalam satu tabel, sebagai dasar menilai prioritas sebelum investigasi dibuka.

```
| tstats summariesonly=false count dc(Authentication.user) AS users
    min(_time) AS first max(_time) AS last
    from datamodel=Authentication.Authentication
    where Authentication.src="203.0.113.45" earliest="10/14/2026:00:00:00" latest="10/14/2026:06:00:00"
    by Authentication.action Authentication.dest Authentication.dest_priority
| rename Authentication.* AS *
| convert ctime(first) ctime(last)
```

- `summariesonly=false` dipakai karena ini investigasi: kelengkapan lebih penting daripada kecepatan (Day 25).
- `dc(Authentication.user)` menjawab apakah ini satu akun yang dicoba berulang atau banyak akun sekaligus.
- `earliest` dan `latest` absolut mengunci rentang di sekitar kejadian, sehingga query yang sama bisa diulang minggu depan untuk rapat dan hasilnya tetap sama. Format defaultnya `%m/%d/%Y:%H:%M:%S`.
- `Authentication.dest_priority` adalah field enrichment dari Asset & Identity (Day 26).
- `convert ctime(...)` mengubah epoch menjadi waktu yang bisa dibaca.

Keluaran ilustrasi:

```
action    dest         dest_priority  users  count  first                 last
failure   jkt-vpn01    unknown           25    180  10/14/2026 01:52:07   10/14/2026 02:06:41
success   jkt-vpn01    unknown            1      1  10/14/2026 02:04:13   10/14/2026 02:04:13
```

**Cara membaca hasil:** 180 gagal ke 25 akun dalam 14 menit lalu satu sukses adalah pola spraying yang berhasil, bukan pengguna yang lupa password. Yang juga penting: `dest_priority` bernilai `unknown` karena gateway VPN belum terdaftar di Asset & Identity PT JAB, sehingga urgency otomatis akan terlalu rendah untuk aset yang sebenarnya menjadi pintu masuk seluruh karyawan. Itu temuan untuk tahap Re-assess, bukan hanya catatan teknis.

**Keputusan di tahap ini:** tutup sebagai false positive dengan bukti, turunkan prioritas, atau lanjut ke tahap 3. Kriteria memilihnya ada di Day 07 bagian 1.6.

**Kapan gagal:** bila add-on VPN belum menormalkan field ke CIM, data ini tidak masuk data model Authentication dan `tstats` mengembalikan nol baris. Jalankan `| tstats count from datamodel=Authentication.Authentication by Authentication.app` lebih dulu untuk melihat sumber apa saja yang benar-benar masuk model itu.

### 2.3 Tahap 3, Determine risk: ruang lingkup lintas data

Tahap ini punya dua pertanyaan berbeda, dan keduanya butuh query berbeda. Pertanyaan pertama: apa saja yang menyentuh entity yang sudah diketahui. Pertanyaan kedua: entity lain mana yang menyentuh indikator yang sama.

Untuk pertanyaan pertama, pivot satu IP atau satu akun ke semua data model yang relevan dengan field CIM bersama (Day 24 bagian 2.1 sampai 2.3), lalu lihat akumulasi risikonya:

```
index=risk earliest=-7d
  (risk_object="rina.wulandari" OR risk_object="adm.rina" OR risk_object="JKT-JUMP01" OR risk_object="JKT-FS01")
| stats sum(risk_score) AS total_risk dc(source) AS detections values(source) AS which
    BY risk_object risk_object_type
| sort - total_risk
```

- `index=risk` adalah risk index ES tempat detection menuliskan kontribusi risiko per entity (Day 35).
- `values(source)` menghasilkan field multivalue: satu entity bisa disentuh beberapa detection, dan daftar itulah yang menjelaskan skornya.
- Nama field risk di ES 8.7 perlu dicek sebelum query ini dipakai, karena istilah risk object berganti menjadi entity.

Keluaran ilustrasi:

```
risk_object       risk_object_type  total_risk  detections  which
adm.rina          user                     120           3  JAB - Login berhasil setelah rangkaian gagal
                                                            JAB - Logon RemoteInteractive ke jump host
                                                            JAB - Akun admin aktif di luar jam kerja
rina.wulandari    user                      75           2  JAB - Login berhasil setelah rangkaian gagal
                                                            JAB - Login VPN dari negara baru
JKT-JUMP01        system                    45           1  JAB - Logon RemoteInteractive ke jump host
```

**Cara membaca hasil:** `adm.rina` menumpuk tiga sinyal dari detection berbeda, dan itu memindahkan pusat kasus dari akun karyawan biasa ke akun admin. `JKT-FS01` tidak muncul sama sekali, yang berarti dua hal berbeda: bisa jadi memang tidak ada detection yang menyentuhnya, bisa juga tidak ada detection yang memantaunya. Kemungkinan kedua lebih penting untuk ditulis di tiket.

**Variasi untuk pertanyaan kedua:** ganti filter entity menjadi filter indikator, misalnya hash, domain, atau IP sumber, lalu cari host dan akun lain yang menyentuh indikator yang sama dalam 30 hari. Inilah langkah yang membedakan scoping dari sekadar memeriksa satu host.

**Kapan gagal:** entity yang tidak pernah ditulis ke risk index tidak akan muncul walaupun terdampak, jadi query ini melengkapi pivot data model, bukan menggantikannya.

### 2.4 Tahap 4, Mitigate: tindakan dan jejaknya

Tahap ini tidak selalu berupa query. Yang penting adalah tindakan dijalankan oleh yang berwenang dan jejaknya tercatat dengan waktu, karena jejak itulah yang menjadi T4 di perhitungan MTTR.

Untuk SOC-2026-0217, urutan tindakan yang masuk akal di PT JAB:

1. Putus sesi VPN aktif dari `203.0.113.45` dan blokir IP di gateway, dikerjakan tim infrastruktur atas permintaan SOC.
2. Reset kredensial `rina.wulandari` dan `adm.rina`, lalu cabut sesi yang masih berjalan.
3. Periksa dan bila perlu isolasi `JKT-JUMP01`, karena akun admin dipakai masuk ke sana.
4. Jalankan adaptive response atau playbook SOAR untuk langkah yang sudah disepakati dan berulang (Day 41 dan Day 42).
5. Perbarui status investigasi dan tandai tugas yang selesai di response plan Mission Control [S3].

Dua hal yang sering terlewat di tahap ini. Pertama, tindakan yang dijalankan otomatis perlu dibedakan dari tindakan manusia saat metrik dihitung, karena kalau tidak, MTTR akan membaik tanpa ada yang benar-benar membaik. Kedua, tindakan yang tidak boleh dijalankan L1 maupun L2 (misalnya mematikan layanan pelanggan) tetap perlu dicatat sebagai rekomendasi dengan jam permintaan, supaya jeda persetujuan terlihat di data, bukan tersembunyi sebagai "waktu penyelesaian analyst".

### 2.5 Tahap 5, Re-assess: detection mana yang perlu di-tuning

**Tujuan:** menemukan detection yang mayoritas kasusnya berakhir bukan sebagai ancaman, memakai disposisi yang diisi analyst selama 30 hari terakhir.

```
`notable` earliest=-30d
| where in(status_label,"Resolved","Closed")
| eval fp=if(like(disposition_label,"False Positive%"),1,0),
       bp=if(like(disposition_label,"Benign Positive%"),1,0),
       tp=if(like(disposition_label,"True Positive%"),1,0)
| stats count sum(tp) AS tp sum(bp) AS bp sum(fp) AS fp BY rule_name
| eval fp_rate=round(fp/count*100,1), precision=round(tp/count*100,1)
| sort - fp_rate
```

- `in(status_label,...)` dipakai di dalam `where` sebagai fungsi eval, bukan operator, supaya tidak bergantung versi.
- `like(disposition_label,"False Positive%")` mengelompokkan dua label FP sekaligus (Incorrect Analytic Logic dan Inaccurate Data), sedangkan rinciannya dilihat dengan menambahkan `disposition_label` ke `BY`.
- `disposition_label` dan `status_label` adalah nama field ES 7.x; nama field finding di ES 8.7 perlu dicek lebih dulu.

Keluaran ilustrasi:

```
rule_name                                      count   tp   bp    fp  fp_rate  precision
JAB - Eksekusi dari direktori temp               142    3    9   128     90.1        2.1
JAB - Login berhasil setelah rangkaian gagal      96   11   18    63     65.6       11.5
JAB - Akun baru masuk grup admin                  24   14    8     2      8.3       58.3
```

**Cara membaca hasil:** baris pertama adalah kandidat tuning yang jelas, karena 128 dari 142 kasus berakhir sebagai false positive dan hanya 3 yang nyata. Baris kedua lebih halus: FP rate 65,6 persen terlihat buruk, tetapi 11 kasus nyata dalam 30 hari termasuk SOC-2026-0217, jadi detection ini tidak boleh dimatikan, hanya dipersempit. Perhatikan juga selisih yang tidak terlihat di kolom mana pun: pada baris pertama 3 ditambah 9 ditambah 128 sama dengan 140, padahal `count` 142, sehingga ada 2 kasus yang ditutup tanpa salah satu dari tiga label itu. Pada baris kedua selisihnya 4. Proporsi kasus yang ditutup tanpa disposisi yang berarti adalah angka yang perlu ikut dilaporkan, karena itu yang membatasi kepercayaan pada seluruh tabel.

**Variasi:** untuk menandai kandidat tuning secara otomatis, hitung proporsinya per detection lalu saring:

```
`notable` earliest=-30d
| where in(status_label,"Resolved","Closed")
| stats count BY rule_name disposition_label
| eventstats sum(count) AS total BY rule_name
| eval pct=round(count/total*100,1)
| where like(disposition_label,"False Positive%") AND pct>50
```

**Kapan gagal:** bila sebagian besar kasus ditutup dengan Undetermined, seluruh tabel ini tidak bisa dipakai. Itu masalah proses, bukan query (Day 07 bagian 1.5).

### 2.6 MTTA dan MTTR dari jejak waktu kasus

**Tujuan:** menghasilkan angka kecepatan penyelesaian per urgency untuk rapat kuartalan, dengan median dan p90, bukan hanya rata-rata.

```
`notable` earliest=-30d
| where in(status_label,"Resolved","Closed")
| eval detect_time=_time
| eval close_time=strptime(status_end, "%Y-%m-%dT%H:%M:%S")
| eval ttr_hours=round((close_time-detect_time)/3600,2)
| stats count median(ttr_hours) AS median_ttr p90(ttr_hours) AS p90_ttr avg(ttr_hours) AS avg_ttr
    BY urgency
```

- `_time` pada notable adalah waktu finding dibuat, jadi dipakai sebagai T1.
- `status_end` dan formatnya hanyalah contoh nama field. Banyak deployment menghitung waktu tutup dari riwayat audit review (lookup atau index `incident_review`), dan itu perlu dicek di instance sendiri sebelum angkanya dipakai.
- Prinsip yang sama dipakai untuk MTTA&A dan MTTI: ganti `close_time` dengan waktu kasus diambil owner atau waktu investigation dibuka.

Keluaran ilustrasi:

```
urgency    count  median_ttr  p90_ttr  avg_ttr
critical      12        3.10     9.80     4.25
high          48        6.40    21.30     8.70
medium       165       18.90    52.40    24.10
```

**Cara membaca hasil:** untuk urgency high, median 6,40 jam dan p90 21,30 jam berarti satu dari sepuluh kasus high memakan lebih dari tiga kali waktu kasus khasnya (21,30 dibagi 6,40 sama dengan 3,3). Angka itulah yang perlu dijelaskan di rapat, karena rata-rata 8,70 jam menyembunyikannya. Pada urgency medium, median 18,90 jam hampir pasti berarti kasus medium menginap sampai shift berikutnya, dan itu keputusan prioritas, bukan kelalaian.

**Kapan gagal:** kasus yang dibuka kembali setelah ditutup membuat satu kasus punya dua waktu tutup. Bila reopen tidak ditangani di query, MTTR justru terlihat lebih baik saat kualitas penutupan memburuk.

### 2.7 Dwell time per insiden dari temuan investigasi

**Tujuan:** menghitung dwell time dan TTR untuk tiga kasus yang T0-nya sudah diketahui, lalu menunjukkan kenapa rata-rata tidak boleh dipakai untuk metrik ini. T0 tidak bisa diambil dari antrean; ia berasal dari temuan investigasi atau forensik dan dicatat manual di tiket.

```
| makeresults format=csv data="case,t0_compromise,t1_detect,t4_resolve
SOC-2026-0217,2026-10-14T02:04:13,2026-10-14T02:10:00,2026-10-14T11:30:00
SOC-2026-0231,2026-09-18T01:45:00,2026-09-18T02:10:00,2026-09-18T09:15:00
SOC-2026-0263,2026-09-26T09:12:00,2026-10-12T10:05:00,2026-10-13T16:40:00"
| foreach t0_compromise t1_detect t4_resolve [eval <<FIELD>>_e=strptime('<<FIELD>>',"%Y-%m-%dT%H:%M:%S")]
| eval dwell_h=round((t1_detect_e-t0_compromise_e)/3600,1),
       ttr_h=round((t4_resolve_e-t1_detect_e)/3600,1)
| table case dwell_h ttr_h
```

- `makeresults format=csv` membuat data sintetis untuk latihan dan untuk memeriksa rumus sebelum dipakai ke data nyata; `foreach` dan `makeresults` dibahas di Day 12.
- T0 ketiga kasus berasal dari sumber berbeda: login VPN berhasil pada SOC-2026-0217, awal aktivitas spraying pada SOC-2026-0231, dan jejak scheduled task yang ditemukan saat hunting pada SOC-2026-0263.

Keluaran ilustrasi:

```
case            dwell_h   ttr_h
SOC-2026-0217       0.1     9.3
SOC-2026-0231       0.4     7.1
SOC-2026-0263     384.9    30.6
```

Lalu ringkas ketiganya dengan mengganti baris `table` menjadi:

```
| stats avg(dwell_h) AS avg_dwell median(dwell_h) AS median_dwell
        avg(ttr_h) AS avg_ttr median(ttr_h) AS median_ttr
```

Keluaran ilustrasi:

```
avg_dwell  median_dwell  avg_ttr  median_ttr
   128.47           0.4    15.67         9.3
```

**Cara membaca hasil:** rata-rata dwell time 128,47 jam dan median 0,4 jam menggambarkan dua SOC yang sangat berbeda, padahal datanya sama. Satu kasus persistence berusia 16 hari cukup untuk menarik rata-rata tiga kasus menjadi lima hari. Untuk rapat, laporkan median, sebaran, dan kasus terburuk secara terpisah, dan jelaskan kenapa kasus terburuk itu lama ditemukan. Perhatikan juga bahwa dwell time dan TTR tidak bergerak searah: SOC-2026-0263 punya dwell time terpanjang tetapi TTR yang masih wajar, karena setelah ditemukan, penanganannya lancar.

**Kapan gagal:** kasus tanpa T0 tidak bisa masuk hitungan sama sekali, dan itulah mayoritas kasus di SOC mana pun. Jangan menyebut hasil hitungan ini sebagai dwell time organisasi; sebut sebagai dwell time pada kasus yang T0-nya berhasil ditentukan.

### 2.8 Metrik tanpa ES: dari sistem tiket yang di-ingest ke Splunk

**Tujuan:** menghitung metrik yang sama untuk kasus yang tidak pernah lewat ES, dengan data sistem tiket (di lab, TheHive) yang dikirim ke Splunk.

```
index=thehive sourcetype=thehive:case
| eval created=createdAt/1000, closed=endDate/1000
| eval ttr_h=(closed-created)/3600
| stats count median(ttr_h) AS median_ttr BY resolutionStatus
```

Nama index, sourcetype, dan field di sini sepenuhnya asumsi, karena bergantung pada cara data tiket dikirim ke Splunk. Pembagian dengan 1000 mengasumsikan waktu disimpan sebagai epoch milidetik, yang umum di API TheHive. Periksa format waktu di data lab-mu dengan membuka satu event mentah lebih dulu; contoh ini hanya menunjukkan polanya.

**Cara membaca hasil:** `resolutionStatus` di sistem tiket menempati posisi yang sama dengan disposisi di ES, jadi inilah kolom yang menyambungkan metrik dua jalur. Supaya angkanya bisa digabung, label penutupan di sistem tiket harus memakai kosakata yang sama dengan disposisi ES (Day 07 bagian 1.5).

### 2.9 Langkah di ES 8.7 (generik)

1. Pastikan disposisi wajib diisi sebelum finding bisa ditutup, lewat toggle Required di Configure > Findings and investigations > Dispositions, karena seluruh metrik kualitas bergantung pada itu (Day 07).
2. Kaitkan response plan dengan investigation type agar tahap 3 sampai 5 konsisten tanpa perlu diingat [S3].
3. Tambahkan satu field untuk T0 di template investigasi atau response plan, supaya dwell time bisa dihitung belakangan.
4. Tinjau metrik mingguan dengan tiga angka tetap: FP rate per detection, median dan p90 TTR per urgency, serta proporsi kasus yang ditutup tanpa disposisi yang berarti.
5. Baca metrik itu berdampingan dengan dashboard SOC bawaan ES, bukan sebagai pengganti (Day 32).

## 3. Lab praktik (di VM lab terisolasi)

Tanpa ES, dengan Splunk dan sistem tiket di lab:

1. Buat alert terjadwal `JAB - Login berhasil setelah rangkaian gagal` memakai pola rangkaian gagal lalu sukses dari Day 13 bagian 2.3, dengan cara membuat dan menjadwalkan alert dari Day 09, lalu kirim hasilnya ke sistem tiket lewat webhook.
2. Picu alert itu dari VM Windows lab: login gagal berkali-kali, lalu satu login berhasil.
3. Jalani lima tahap sampai selesai. Tulis satu catatan per tahap, dan pastikan setiap catatan memuat hasil yang disebut di tabel bagian 1.3, bukan hanya cerita.
4. Catat T0, T1, T2, T3, dan T4 dengan jam yang sebenarnya, lalu hitung dwell time, MTTA&A, MTTI, dan TTR untuk kasus itu.
5. Jalankan query bagian 2.7 dengan tiga kasus lab-mu sendiri, lalu bandingkan rata-rata dan median keduanya.
6. Tutup lima kasus lab dengan disposisi berbeda, lalu jalankan bagian 2.5 (atau versi sistem tiketnya) dan lihat apakah detection lab-mu sendiri sudah terlihat berisik.

Bila ada ES 8:

1. Picu detection yang sama, buka finding di analyst queue, buat investigation, lalu terapkan response plan Account Compromise [S3].
2. Selesaikan tugas per fase dan perhatikan tahap mana yang paling lama, karena itu yang nanti muncul sebagai selisih median dan p90.

**Hasil yang sebaiknya tersimpan:**

- Satu kasus lab dengan catatan lengkap lima tahap beserta hasil tiap tahap.
- Tabel T0 sampai T4 untuk minimal tiga kasus, dengan dwell time dan TTR terhitung.
- Satu rancangan dashboard metrik SOC mini berisi empat panel: FP rate per detection, median dan p90 TTR, jumlah kasus per disposisi, dan tren mingguan.
- Satu rekomendasi Re-assess yang konkret dan punya pemilik: tuning detection, perbaikan data, detection baru, atau perubahan prosedur.

**Variasi tantangan:** petakan lima tahap Splunk ke fase response plan Generic Incident Response (detect, analyze, contain, eradicate, recover, review) [S3] dan tunjukkan di mana keduanya tidak bertemu. Lalu buat satu aturan Re-assess otomatis: detection dengan FP berjenis Incorrect Analytic Logic di atas 30 persen dalam 30 hari masuk backlog tuning lewat saved search yang membuat tiket.

## 4. Troubleshooting

Tabel ini memuat gejala yang paling sering muncul saat kerangka tahap dan metriknya dipakai sungguhan; cari gejalanya dulu, karena penyebabnya sering bukan di query.

| Gejala | Kemungkinan penyebab | Perbaikan |
|---|---|---|
| Antrean menumpuk di status New | Volume finding terlalu tinggi dan tidak ada target waktu triage | Akumulasi sinyal dengan RBA (Day 35), tuning dari bagian 2.5, lalu ukur MTTA&A |
| Assessment lambat untuk semua kasus | Konteks aset dan identitas kosong, analyst mengumpulkan manual | Lengkapi Asset & Identity (Day 26); di PT JAB mulai dari aset POP dan gateway |
| Dua analyst menangani kasus serupa dengan cara berbeda | Tidak ada response plan atau checklist tahap | Response plan dikaitkan ke investigation type [S3] |
| Tahap Re-assess tidak pernah terjadi | Tidak ada waktu dan tidak ada pemilik | Jadwalkan tinjauan mingguan dengan query bagian 2.5 sebagai agenda tetap |
| MTTR membaik tetapi insiden berulang | Penutupan dini, kasus ditutup sebelum ruang lingkup jelas | Lacak reopen rate dan FN; laporkan median dan p90, bukan rata-rata |
| Dwell time tidak bisa dihitung untuk hampir semua kasus | T0 tidak pernah dicatat | Tambahkan field T0 di template kasus atau response plan |
| FP rate per detection tidak bisa ditindaklanjuti | Semua FP diberi satu label yang sama | Pakai pembedaan Incorrect Analytic Logic, Inaccurate Data, dan Benign Positive (Day 07 bagian 1.6) |
| Sebagian TTR terlihat sangat cepat tanpa penjelasan | Tindakan otomatis tidak dibedakan dari tindakan manusia | Tandai kasus yang ditangani playbook, lalu hitung dua kelompok itu terpisah |

## 5. Kesalahan umum dan jebakan

- Melompat dari Assessment ke Mitigate tanpa Determine risk. Akibatnya satu host ditangani dan host lain yang terdampak terlewat, lalu kasus yang sama muncul lagi seminggu kemudian.
- Menganggap Re-assess opsional. Tanpa tahap ini, detection berisik tetap berisik dan celah yang sama berulang [S1].
- Menutup kasus tanpa disposisi yang benar. Metrik kualitas dan prioritas tuning langsung menjadi bias, dan tabel di bagian 2.5 kehilangan arti.
- Menyamakan continuous monitoring dengan dashboard real-time. Yang dimaksud adalah proses koleksi, analisis, pelaporan, respons, dan peninjauan, bukan sebuah tampilan [S2].
- Membandingkan MTTR dengan organisasi lain tanpa menyepakati titik awal dan titik akhir. Nama yang sama dipakai untuk pengukuran yang berbeda.
- Memakai rata-rata sebagai satu-satunya angka. Median dan p90 lebih jujur, dan selisih keduanya sendiri adalah informasi.
- Mengejar MTTR rendah dengan mengorbankan kedalaman investigasi. Itu memindahkan biaya ke insiden berikutnya.
- Menganggap dwell time sama dengan MTTD. MTTD adalah rata-rata kecepatan deteksi di banyak kasus, sedangkan dwell time dihitung per insiden dari kompromi awal yang sering baru diketahui lewat forensik.
- Menyajikan metrik tanpa definisi. Definisi yang dipakai di catatan ini berasal dari blog vendor tahun 2023 [S6], bukan standar industri, jadi tulis titik awal dan akhirnya di setiap laporan.

## 6. Catatan terkini

Bagian ini memuat detail versi dan perubahan istilah yang memengaruhi cara query dan prosedur di atas dipakai.

- ES 8.x mengganti Incident Review menjadi analyst queue, dan investigation beserta response plan berada di Mission Control dengan delapan template bawaan [S3].
- NIST SP 800-61r3 (April 2025) menggantikan r2 dan meninggalkan siklus empat fase lama [S4]. Response plan ES masih menyediakan template bernama "NIST 800-61" dengan fase klasik, jadi cek revisi mana yang dirujuk template itu di instance sendiri.
- Nama field finding di ES 8.7 untuk status, disposisi, dan waktu tutup, serta daftar status yang tersedia, perlu dicek sebelum query bagian 2.1, 2.5, dan 2.6 dipakai di ES 8.
- Release notes ES 8.7 menyebut AI SOC Analyst yang dapat menjalankan tindakan respons yang diizinkan dan merekomendasikan langkah berikutnya. Dua hal yang perlu dicek di instance sendiri: cakupan izinnya, karena itu mengubah tahap Mitigate, dan cara ES mencatat tindakan otomatis, karena metrik waktu bisa membaik secara artifisial bila tindakan mesin tidak dibedakan dari tindakan manusia.

## 7. Cheat sheet

```
CONTINUOUS MONITORING  koleksi -> analisis -> pelaporan -> respons (berkelanjutan, bukan sebuah layar)
  langkah: tujuan -> teknologi -> ambang alert -> prosedur IR -> tinjau rutin
  tantangan: volume, sumber daya, integrasi, alert fatigue
5 TAHAP (Lantern, alur insiden ES) dan hasil yang wajib ada di tiket:
  1 Review events   antrean           -> daftar yang perlu dinilai (notable/finding, alert, email, tiket)
  2 Assessment      triage            -> disposisi awal + urgency + owner + alasan
  3 Determine risk  scoping           -> daftar host/akun/data terdampak + artefak + rentang waktu
  4 Mitigate        tindakan          -> apa dilakukan, oleh siapa, jam berapa (AR, SOAR, response plan)
  5 Re-assess       perbaikan         -> satu perubahan: tuning / detection baru / data / prosedur
ES8 RESPONSE PLAN  fase + tugas ; 8 template (Account Compromise, Data Breach, Network Indicator
  Enrichment, NIST 800-61, Generic IR, Self-Replicating Malware, Suspicious Email, Vulnerability Disclosure)
  Mission Control > investigation > View details > Response ; kaitkan ke investigation type
TIMELINE  T0 kompromi -> T1 deteksi -> T2 attend/analyze -> T3 investigasi -> T4 resolusi/pulih
  DWELL   T0->T1 (breach detection gap; per insiden; butuh forensik)   MTTD  kejadian->deteksi
  MTTA&A  T1->T2      MTTI  T1->T3      MTTR  T1->T4      MTRS  T1->layanan pulih
  FPR/FNR salah dinilai insiden / ancaman terlewat
ATURAN ANGKA  median + p90, bukan hanya rata-rata ; kecepatan selalu dipasangkan dengan kualitas
  (reopen rate, FN, proporsi ditutup tanpa disposisi) ; DEFINISIKAN titik awal dan akhir di laporan
SPL  antrean: `notable` | where status_label="New" | stats count BY rule_name urgency
     FP rate: like(disposition_label,"False Positive%") -> stats BY rule_name -> round(fp/count*100,1)
     TTR    : strptime(waktu_tutup) - _time -> median()/p90() BY urgency
     dwell  : makeresults + foreach + strptime (T0 dicatat manual dari temuan forensik)
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Di draf laporan kuartalan, seseorang menulis "MTTD kami 0,4 jam, jadi dwell time rata-rata kami 0,4 jam". Benarkah?

<details><summary>Jawaban</summary>

Tidak. Keduanya mengukur hal yang berbeda dan tidak bisa dipertukarkan. MTTD adalah rata-rata waktu dari kejadian sampai terdeteksi di banyak kasus, dihitung dari data antrean. Dwell time dihitung per insiden dari kompromi awal (T0) sampai penyerang ditemukan, dan T0 hanya diketahui setelah investigasi atau forensik, sehingga sebagian besar kasus tidak punya angka ini sama sekali. Menyebut dwell time sebagai rata-rata juga menyembunyikan bentuk sebarannya: pada contoh di catatan ini, median dwell 0,4 jam berdampingan dengan rata-rata 128,47 jam karena satu kasus persistence berusia 16 hari. Lihat bagian 1.6 dan 2.7.

</details>

**2. Skenario keputusan.** Kuartal ini MTTR turun dari 14 jam menjadi 8 jam, tetapi reopen rate naik dari 3 persen menjadi 11 persen dan proporsi kasus yang ditutup dengan Undetermined naik menjadi 18 persen. Apa yang kamu bawa ke rapat?

- A. Laporkan perbaikan MTTR 43 persen sebagai capaian kuartal, lalu bahas reopen rate di rapat terpisah.
- B. Laporkan ketiga angka bersama, sebut penurunan MTTR sebagai indikasi penutupan dini, lalu usulkan median dan p90 TTR, reopen rate, serta proporsi Undetermined sebagai satu set tetap.
- C. Tahan laporan sampai reopen rate turun, karena angka yang bercampur akan membingungkan manajemen.

<details><summary>Jawaban</summary>

B. Metrik kecepatan hanya bermakna bila dibaca bersama metrik kualitas, dan pola ini (MTTR turun, reopen dan Undetermined naik) adalah tanda khas kasus ditutup sebelum tuntas, bukan tanda tim membaik. A keliru karena memisahkan dua angka yang justru saling menjelaskan, dan itu menghasilkan kesimpulan yang salah di rapat yang sama. C keliru karena menunda laporan berarti menyembunyikan masalah yang sedang berjalan, dan tidak ada yang memperbaiki apa pun selama penundaan itu. Lihat bagian 1.8 dan 2.6.

</details>

**3. Pertanyaan jebakan.** Pada SOC-2026-0217, L2 langsung memblokir `203.0.113.45` dan mereset password `rina.wulandari` pada pukul 03.00, lalu menutup kasus sebagai selesai. Apa yang salah?

<details><summary>Jawaban</summary>

Tahap Determine risk dilewati, sehingga ruang lingkupnya tidak pernah ditetapkan. Bukti di kasus itu menyebut tiga hal, bukan satu: akun `rina.wulandari` di VPN, akun admin `adm.rina` yang dipakai masuk ke `JKT-JUMP01`, dan `JKT-FS01` yang diakses lewat logon jaringan. Memblokir IP dan mereset satu password menyelesaikan jalan masuk pertama saja dan membiarkan akun admin beserta host yang sudah disentuh. Tindakan di tahap Mitigate hanya seluas daftar yang dihasilkan tahap sebelumnya. Lihat bagian 1.3 dan 2.3.

</details>

**4. Skenario keputusan.** Query bagian 2.5 menunjukkan `JAB - Login berhasil setelah rangkaian gagal` punya FP rate 65,6 persen dari 96 kasus, dengan 11 true positive termasuk SOC-2026-0217. Apa langkah yang paling tepat?

- A. Nonaktifkan detection itu, karena dua dari tiga kasusnya bukan ancaman dan analyst kewalahan.
- B. Periksa rincian labelnya, lalu persempit logika atau datanya sesuai jenis FP yang dominan, dan pertahankan detectionnya karena presisi 11,5 persen masih menghasilkan 11 kasus nyata dalam 30 hari.
- C. Biarkan apa adanya dan perbaiki dengan menaikkan ambang jumlah login gagal sampai FP rate di bawah 20 persen.

<details><summary>Jawaban</summary>

B. FP rate tinggi adalah alasan untuk tuning, bukan untuk mematikan detection yang terbukti menangkap kasus nyata, dan arah tuningnya ditentukan oleh jenis FP: logika yang salah ditangani detection engineer, sedangkan data yang tidak akurat ditangani pengelola add-on dan onboarding. A keliru karena menukar kebisingan dengan titik buta pada jalur serangan yang sudah terbukti dipakai. C keliru karena menaikkan ambang tanpa melihat jenis FP adalah menebak, dan ambang yang lebih tinggi justru melewatkan spraying yang pelan dan sabar. Lihat bagian 1.7 dan 2.5.

</details>

**5. Pertanyaan jebakan.** "Kita sudah punya continuous monitoring, buktinya ada dashboard yang menyala 24 jam di layar SOC." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Continuous monitoring adalah proses mengumpulkan, menganalisis, melaporkan, dan menindaklanjuti data secara berkelanjutan, lalu meninjau efektivitasnya secara rutin; dashboard hanya komponen pelaporannya. Dashboard yang menyala tanpa ambang alert yang ditetapkan, tanpa prosedur respons, dan tanpa peninjauan rutin tidak menghasilkan tindakan apa pun. Pertanyaan pengujinya sederhana: kalau panel di layar itu berubah warna pukul tiga pagi, siapa yang melakukan apa, dan dari mana dia tahu. Lihat bagian 1.1.

</details>

**6. Jelaskan ulang.** Jelaskan kepada SOC lead PT JAB dalam tiga kalimat apa yang diukur MTTA&A, MTTR, dan dwell time, lengkap dengan titik awal dan akhir masing-masing, lalu sebut satu angka yang tidak boleh ia bawa ke rapat tanpa penjelasan.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "MTTA&A dihitung dari saat finding muncul sampai analyst benar-benar memegangnya dan menyelesaikan penilaian awal, jadi ini mengukur jeda antrean kita, bukan kecepatan investigasi. MTTR dihitung dari saat finding muncul sampai kasus dinyatakan selesai, dan karena itu angkanya ikut memuat waktu tunggu persetujuan dan waktu tim lain bekerja, bukan hanya waktu analyst. Dwell time berbeda sifatnya: dihitung per insiden dari saat penyerang pertama masuk sampai kita menemukannya, dan angkanya hanya ada untuk kasus yang T0-nya berhasil ditentukan lewat investigasi. Yang tidak boleh dibawa ke rapat tanpa penjelasan adalah rata-rata dwell time, karena satu kasus persistence lama cukup untuk membuat angka itu mewakili kasus yang tidak ada."

Kesalahan yang sering muncul:

- Menyebut nama metrik tanpa titik awal dan akhir, sehingga tetap tidak bisa dibandingkan dengan angka pihak lain.
- Menjelaskan MTTR seolah seluruhnya di bawah kendali analyst, padahal di dalamnya ada waktu persetujuan dan waktu tim lain.
- Lupa menyebut bahwa dwell time hanya tersedia untuk sebagian kasus, sehingga terdengar seperti metrik organisasi yang utuh.

</details>

**7. Interview question (English).** "How would you know whether your SOC is actually getting better?"

<details><summary>Sample answer</summary>

"I'd never answer that with a single number. I pair speed metrics with quality metrics, because each of them can be gamed on its own. On the speed side I report mean time to attend and analyse, mean time to investigate, and time to resolution, and I always report median and p90 rather than the average, because one long case moves an average and hides the worst ten percent. On the quality side I report false positive rate per detection, reopen rate, and the share of cases closed without a meaningful disposition, which tells me how much I can trust the first number. Dwell time I treat separately and per incident, because it starts at initial compromise, and we only know that time after an investigation or forensics, so I present it as dwell time on the cases where we established the start, never as an organisational average. And I write the start and end point of every metric in the report, because in the last place I worked, two teams used mean time to resolution for two different measurements and spent a quarter arguing about a difference that wasn't real."

What makes this answer strong: it refuses the single-number framing, shows the speed and quality pairing with concrete named metrics, demonstrates statistical care with median and p90, treats dwell time with the honesty it requires instead of inflating it into an average, and ends with a practical consequence of undefined metrics rather than a slogan.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Splunk Lantern: Creating an incident workflow in Splunk Enterprise Security | https://lantern.splunk.com/Security_Use_Cases/Advanced_Threat_Detection/Creating_an_incident_workflow_in_Splunk_Enterprise_Security | primer | tanggal tidak terlihat; diakses 2026-10-07 | Tinggi untuk lima tahap. Kesesuaian dengan materi pelatihan resmi perlu dicek |
| S2 | Splunk blog: The Continuous Monitoring Ultimate Guide | https://www.splunk.com/en_us/blog/learn/continuous-monitoring.html | primer (vendor) | 2024-05-07; diakses 2026-10-07 | Tinggi. Definisi, empat komponen, langkah penerapan, tantangan |
| S3 | ES 8.4: Respond to investigations with response plans | https://help.splunk.com/en/splunk-enterprise-security-8/user-guide/8.4/mission-control/respond-to-investigations-with-response-plans-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi. Delapan template dan cara menetapkannya |
| S4 | NIST SP 800-61r3: Incident Response Recommendations and Considerations for Cybersecurity Risk Management | https://csrc.nist.gov/pubs/sp/800/61/r3/final | primer | 2025-04; diakses 2026-10-07 | Tinggi. Pemetaan ke enam fungsi CSF 2.0 |
| S5 | ES 7.3: Investigations in Splunk Enterprise Security | https://help.splunk.com/en/splunk-enterprise-security-7/user-guide/7.3/investigations/investigations-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Sedang-tinggi. Konteks istilah ES 7 (investigation workbench) |
| S6 | Splunk blog: SOC Metrics: Security Metrics & KPIs for Measuring SOC Success | https://www.splunk.com/en_us/blog/learn/security-operations-metrics.html | primer (vendor) | 2023-05-18; diakses 2026-10-07 | Tinggi untuk definisi metrik; bukan standar industri |
| S7 | TaHiTI whitepaper (breach detection gap dan dwell time) | https://www.betaalvereniging.nl/wp-content/uploads/2026/03/TaHiTI-Threat-Hunting-Methodology-whitepaper.pdf | primer | diakses 2026-10-07 | Tinggi |
| S8 | Splunk blog: What is MTTD? | https://www.splunk.com/en_us/blog/learn/mean-time-to-detect-mttd.html | primer (vendor) | diakses 2026-10-07 | Sedang; dipakai sebagai pembanding definisi |
| S9 | Splunk blog: Top 8 incident response metrics | https://www.splunk.com/en_us/blog/learn/incident-response-metrics?p=2 | primer (vendor) | diakses 2026-10-07 | Sedang; dipakai sebagai pembanding definisi |
| S10 | SANS: siaran pers SANS 2026 Threat Hunting Survey | https://www.sans.org/press/announcements/threat-hunters-call-data-their-biggest-barrier-overtaking-staffing-first-time-survey-finds | sekunder | 2026-09-23; diakses 2026-10-10 | Sedang-tinggi; angka dari siaran pers, bukan laporan lengkap |

**Catatan sumber:** nama dan urutan lima tahap mengikuti Lantern [S1], dan materi pelatihan resmi Splunk bisa memakai nama berbeda. Nama field notable dan finding di ES 8.7 (status, disposisi, waktu tutup) serta daftar status yang tersedia perlu dicek di instance sebelum query di bagian 2 dipakai di ES 8. Revisi NIST yang dirujuk template response plan "NIST 800-61" juga perlu dicek. Definisi metrik di bagian 1.6 berasal dari blog vendor [S6] dengan [S8] dan [S9] sebagai pembanding, bukan dari standar, jadi titik awal dan akhirnya harus ditulis ulang di setiap laporan. Angka survei SANS [S10] berasal dari siaran pers; cocokkan dengan laporan lengkapnya bila dipakai di presentasi. Kasus SOC-2026-0217, SOC-2026-0231, dan SOC-2026-0263 beserta tanggal, nama detection, dan seluruh keluaran di bagian 2 adalah ilustrasi fiktif untuk PT JAB, bukan hasil eksekusi; angka waktu di bagian 2.7 dihitung dari tanggal di query itu sendiri.
