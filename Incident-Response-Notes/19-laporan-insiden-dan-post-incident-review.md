---
day: 19
title: 'Laporan insiden dan post-incident review: after-action report, metrik, faktor penyebab, PIR blameless, dan action item'
researched_on: 2026-10-15
versions_checked: 'NIST SP 800-61 Rev. 3 (April 2025); NIST SP 800-61 Rev. 2 (Agustus 2012, digantikan Rev. 3); CISA Cybersecurity Incident and Vulnerability Response Playbooks (November 2021); Google SRE Book (2016), bab 15 Postmortem Culture; PagerDuty Postmortem Documentation (halaman Blameless Postmortem, Step by Step, Postmortem Meeting, diakses 2026-10-15); John Allspaw, The Infinite Hows (Kitchen Soap, 14 November 2014)'
---

# Day 19: Laporan insiden dan post-incident review (after-action report, metrik, faktor penyebab, PIR blameless, dan action item)

Cakupan: menyusun laporan insiden untuk pembaca yang berbeda, membedakannya dari pemberitahuan ke regulator, menghitung metrik waktu dari timeline yang bersumber, menganalisis faktor penyebab tanpa berhenti di satu orang, menjalankan post-incident review yang blameless, dan menulis action item yang punya pemilik, tenggat, dan bukti selesai sampai insiden bisa ditutup.

## Ide inti

Insiden tidak selesai saat layanan pulih. Recovery mengembalikan sistem; laporan insiden dan post-incident review (PIR) mengembalikan sesuatu yang lebih mahal, yaitu kesempatan untuk tidak mengalami insiden yang sama lagi. Kualitas tahap ini ditentukan oleh tiga hal. Pertama, fakta: timeline dengan jam dan sumber, sehingga angka seperti "berapa lama penyerang ada di dalam" bisa dihitung, bukan dikira. Kedua, analisis yang mencari kondisi yang memungkinkan kejadian, bukan orang yang bisa disalahkan, karena orang yang takut disalahkan berhenti bercerita jujur. Ketiga, tindak lanjut yang punya pemilik, tenggat, dan bukti selesai; temuan tanpa pemilik hanya menjadi daftar keinginan yang dibaca ulang di insiden berikutnya.

Kamu sudah mengenal pola ini dari NOC. Setelah gangguan besar, tim menulis RFO (Reason for Outage) untuk pelanggan korporat dan post-mortem untuk internal. RFO yang baik tidak berbunyi "engineer salah konfigurasi", tetapi menjelaskan kenapa prosedur change memungkinkan konfigurasi itu lolos tanpa review, kenapa alarm tidak membangunkan siapa pun, dan apa yang diubah supaya tidak terulang, lengkap dengan PIC dan due date di tiket. IR memakai pola yang sama dengan dua perbedaan. Awal insiden keamanan sering baru diketahui setelah investigasi, sehingga metrik waktunya bisa berubah saat bukti baru muncul. Laporannya juga bisa menjadi dokumen hukum, sehingga isi, distribusi, dan penyimpanannya diputuskan bersama Legal.

```
recovery dinyatakan selesai (Day 06 bagian 1.7)
  |
  v
timeline akhir (jam + sumber)  -->  metrik waktu (dihitung, dengan rumus)
  |
  v
analisis faktor penyebab   langsung | memungkinkan | visibilitas | respons
  |                        (pertanyaan "bagaimana", bukan "siapa")
  v
draft laporan --> PIR blameless --> action item (pemilik, tenggat, bukti selesai)
  |                                        |
  v                                        v
laporan final ke pembaca masing-masing    dilacak sampai selesai
  |                                        |
  +----------------> insiden ditutup <-----+
                     (pemantauan dan action item jangka panjang tetap dilacak)
```

Situasi yang dipakai sepanjang Day ini menutup `INC-2026-019` di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 400 ribu pelanggan broadband. Ringkasnya: email berisi lampiran berbahaya diterima 9 mailbox Senin 2026-10-12 15:58 dan dibuka staf penagihan Andi pukul 16:05. Password akun service `svc_billing` dibaca dari skrip di laptopnya dan dipakai untuk masuk ke server billing `jkt-billing01`, tempat penyerang mengambil sekitar 5.000 baris data pelanggan. Alert pertama baru muncul Selasa 09:47. Containment serentak dijalankan pukul 16:00, server billing dibangun ulang dan cutover Kamis 23:00, dan recovery dinyatakan selesai Jumat 2026-10-23 pukul 10:00. Post-incident review dijadwalkan Selasa 2026-10-27, dan after-action report disusun technical lead Sari Kusuma. Jumat itu pukul 14:00, Direktur Teknologi Hendra Wijaya menulis kepada IC Dimas Prasetyo dan Sari:

> "Pernyataan akhir sudah saya terima, terima kasih. Sekarang soal laporannya. Direksi minta ringkasan yang bisa dibaca lima menit, tapi auditor dan Legal pasti minta versi lengkap; isinya apa saja? Apakah laporan ini sama dengan yang nanti dikirim Pak Agus ke regulator? Saya mau angka yang jujur: berapa lama penyerang ada di dalam sebelum kita sadar, dan berapa lama kita bertindak. Akar masalahnya apa? Jangan sampai kesimpulannya cuma 'Andi klik lampiran'. Rapat Selasa tolong jangan jadi ajang saling menyalahkan, tapi saya juga mau jelas siapa yang memperbaiki apa. Terakhir, bagaimana saya tahu perbaikannya benar-benar dikerjakan dan kapan insiden ini boleh ditutup?"

Pesan itu memuat tujuh pertanyaan:

1. Laporan apa saja yang dibutuhkan, dan apa isinya?
2. Apakah laporan internal sama dengan pemberitahuan ke regulator?
3. Berapa lama penyerang ada di dalam, dan berapa lama tim bertindak?
4. Apa akar masalahnya, tanpa berhenti di satu orang?
5. Bagaimana rapat Selasa tidak menjadi ajang saling menyalahkan?
6. Siapa memperbaiki apa?
7. Bagaimana memastikan perbaikan dikerjakan, dan kapan insiden ditutup?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, pertanyaan 6 di bagian 1.6, dan pertanyaan 7 di bagian 1.7. Bagian 2 berisi kerangka laporan, executive summary, timeline akhir dan metrik, analisis faktor penyebab, agenda PIR, dan daftar action item PT JAB.

**Kapan relevan:** setelah recovery dinyatakan selesai untuk setiap insiden besar, dan dalam bentuk ringkas untuk insiden kecil yang memakai cara serangan baru; juga saat menyusun template laporan dan aturan PIR di IR plan sebelum insiden terjadi.
**Kapan bukan jawaban:** laporan insiden internal bukan pemberitahuan resmi ke regulator atau subjek data; isi, tenggat, dan jalurnya diatur sendiri dan dibahas di Day 18 bagian 1.4 dan 1.5. PIR juga bukan proses disiplin atau penilaian kinerja individu; bila ada dugaan pelanggaran sengaja, itu ditangani terpisah oleh HR dan Legal.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (severity, IC, technical lead, scribe, scope statement, case notes, containment, eradication, recovery, akar masalah, after-action report, pemantauan pasca pemulihan) tidak diulang. Tabel berikut memuat istilah baru Day ini. Kolom padanan memakai analogi NOC dan SOC yang sama di semua Day IR.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Laporan insiden lengkap | Dokumen yang mencatat apa yang terjadi, tindakan respons dan recovery, serta pelajaran; di catatan ini sama dengan after-action report | Laporan post-mortem gangguan untuk internal |
| Executive summary | Ringkasan satu halaman untuk pimpinan: apa yang terjadi, dampak, status, keputusan yang dibutuhkan | Ringkasan RFO untuk direksi |
| Timeline akhir | Urutan kejadian bertanggal, setiap baris dengan sumber, disusun dari case notes, timeline scribe, dan bukti | Kronologi gangguan di RFO |
| Post-incident review (PIR) | Rapat semua pihak setelah insiden untuk meninjau apa yang terjadi, apa yang dilakukan, dan seberapa baik; juga disebut lessons learned meeting atau hotwash | Rapat post-mortem gangguan |
| Blameless | Cara meninjau yang mencari kondisi dan sistem yang memungkinkan kejadian, bukan orang untuk dihukum | RFO yang membahas kenapa prosedur change meloloskan kesalahan, bukan siapa yang mengetik |
| Faktor penyebab | Kondisi yang ikut membuat insiden terjadi, lambat terdeteksi, atau sulit ditangani; biasanya lebih dari satu | Faktor gangguan: fiber tua, jalur tanpa redundansi, alarm yang tidak dibaca |
| Lima kali kenapa (5 whys) | Teknik bertanya "kenapa" berulang untuk mencari satu penyebab | Teknik RCA yang umum di tim operasi |
| Hindsight bias | Kecenderungan menilai keputusan masa lalu memakai informasi yang baru diketahui sesudahnya | "Harusnya sudah kelihatan dari alarm itu", padahal saat itu alarmnya tenggelam di antara ratusan alarm lain |
| Action item | Tindakan perbaikan yang spesifik, punya pemilik, tenggat, dan kriteria selesai | Tiket perbaikan pasca-RFO dengan PIC dan due date |
| Dwell time | Selang waktu dari awal aktivitas penyerang sampai terdeteksi | Waktu dari gangguan mulai sampai alarm NMS berbunyi |

### 1.1 Satu insiden, beberapa laporan: pembaca menentukan isi

Pertanyaan pertama Hendra menyentuh salah paham yang umum: menganggap laporan insiden adalah satu dokumen untuk semua orang. Yang terjadi justru sebaliknya. Direksi butuh lima menit, auditor dan Legal butuh jejak lengkap, tim teknis butuh detail yang bisa dipakai di insiden berikutnya.

Rev. 3 meminta akhir recovery dinyatakan berdasarkan kriteria dan dokumentasi insiden diselesaikan, dengan rekomendasi menyiapkan after-action report yang mendokumentasikan insiden, tindakan respons dan recovery, serta pelajarannya (RC.RP-06) [S1]. Rev. 2 menyebut laporan tindak lanjut untuk setiap insiden berguna sebagai rujukan saat menangani insiden serupa, bahwa kronologi formal dengan informasi bertanda waktu, termasuk data log, penting untuk alasan hukum, begitu juga perkiraan nilai kerugian, dan bahwa laporan itu disimpan sesuai kebijakan retensi dokumen [S2]. Playbook CISA meminta laporan pasca-insiden berisi tinjauan langkah demi langkah seluruh insiden yang menjawab pertanyaan siapa, apa, di mana, kenapa, dan bagaimana [S3].

Dari sumber-sumber itu, PT JAB membuat dua dokumen dari satu bahan:

| Dokumen | Pembaca | Panjang | Isi utama |
|---|---|---|---|
| Executive summary | Direksi, executive sponsor | Satu halaman | Apa yang terjadi, dampak ke pelanggan dan data, status, apa yang sudah dan belum diperbaiki, keputusan atau dukungan yang dibutuhkan |
| Laporan insiden lengkap (after-action report) | IC, tim teknis, auditor, Legal, DPO | Sepanjang yang dibutuhkan | Timeline akhir dengan sumber, scope dan dampak, metrik, faktor penyebab, tindakan respons dan recovery beserta alasan keputusannya, action item, lampiran bukti |

Executive summary ditulis terakhir, setelah laporan lengkap selesai, supaya ringkasannya tidak memuat hal yang belum dibuktikan. Kerangka keduanya ada di bagian 2.1 dan 2.2.

### 1.2 Laporan internal bukan pemberitahuan regulator

Pertanyaan kedua Hendra punya jawaban pendek: tidak sama, walaupun bahannya sama.

Laporan insiden internal ditulis untuk belajar dan memperbaiki: ia memuat hipotesis yang dipatahkan, keputusan yang ternyata kurang tepat, dan kelemahan kontrol PT JAB. Pemberitahuan ke regulator atau subjek data punya isi, tenggat, dan kanal yang ditentukan aturan, dan disusun DPO bersama Legal. Rev. 2 menyebut organisasi yang wajib melaporkan informasi insiden perlu mengumpulkan data yang dibutuhkan untuk memenuhi kewajiban itu [S2], dan playbook CISA memisahkan pembaruan pasca-insiden yang diwajibkan hukum dan kebijakan dari laporan pasca-insiden itu sendiri [S3].

Di `INC-2026-019`, kesimpulan "5.000 baris data pelanggan kemungkinan besar diambil" diteruskan ke DPO Agus Setiawan dan Legal Ratna Sari pada Rabu 10:20 (Day 06 bagian 2.1), jauh sebelum laporan insiden selesai. Pemberitahuan berjalan di jalurnya sendiri dan tidak menunggu PIR; cara menyusun dan kapan mengirimnya dibahas di Day 18. Konsekuensinya untuk laporan internal:

- **Fakta tentang data harus sama** di laporan internal dan di pemberitahuan. Angka yang berbeda antara dua dokumen adalah masalah kredibilitas.
- **Klasifikasi dan distribusi** laporan lengkap diputuskan bersama Legal, karena dokumen itu bisa diminta dalam sengketa atau pemeriksaan. Catatan ini tidak memberi nasihat hukum; aturan distribusinya ditetapkan Legal PT JAB.
- **Laporan disimpan** sesuai kebijakan retensi dokumen bersama bukti, mengikuti saran Rev. 2 [S2].

### 1.3 Metrik waktu: dihitung dari timeline, dengan titik awal yang ditulis

Pertanyaan ketiga Hendra ("berapa lama penyerang di dalam, berapa lama kita bertindak") adalah pertanyaan metrik, dan metrik hanya sebaik timeline yang menopangnya.

Rev. 2 menyarankan mengukur waktu per insiden dengan beberapa cara: total jam kerja yang dipakai, selang waktu dari awal insiden ke penemuan, ke penilaian dampak awal, dan ke setiap tahap penanganan seperti containment dan recovery, berapa lama tim merespons laporan awal, serta berapa lama sampai insiden dilaporkan ke manajemen dan pihak luar yang perlu [S2]. Rev. 2 juga memperingatkan agar organisasi mengumpulkan data yang bisa ditindaklanjuti, bukan data hanya karena tersedia [S2].

Tiga aturan PT JAB untuk metrik:

1. **Setiap metrik menyebut titik awal dan titik akhirnya.** "Dwell time 18 jam" tidak berarti apa-apa tanpa keterangan dihitung dari email diterima, lampiran dibuka, atau akses ke server.
2. **Setiap titik waktu punya sumber** di timeline akhir (bagian 2.3), sehingga angka bisa dihitung ulang orang lain.
3. **Metrik bisa berubah** saat bukti baru muncul, misalnya bila analisis forensik menemukan aktivitas sebelum email Senin. Versi laporan dan tanggalnya dicatat.

Hasil untuk `INC-2026-019`, dihitung di bagian 2.3: penyerang aktif sekitar 17 jam 42 menit sebelum alert pertama, dengan data sudah diambil 6 jam 35 menit sebelum alert. Sejak alert, tim butuh 53 menit untuk declare, 6 jam 13 menit sampai jam H, dan 7 jam 33 menit sampai semua host yang diketahui ditahan. Angka pertama adalah masalah deteksi; angka berikutnya adalah kinerja respons. Laporan memisahkan keduanya supaya perbaikan diarahkan ke tempat yang benar.

### 1.4 Faktor penyebab: berhenti di satu orang berarti berhenti terlalu cepat

Pertanyaan keempat Hendra ("jangan sampai cuma 'Andi klik lampiran'") menunjuk ke kelemahan teknik analisis yang paling populer.

Lima kali kenapa terlihat sederhana: tanyakan "kenapa" sampai menemukan satu penyebab. Praktisi John Allspaw mengkritik teknik ini karena menghasilkan satu rantai lurus padahal kegagalan biasanya punya banyak kondisi yang ikut berperan, karena pertanyaan "kenapa" cenderung menghasilkan jawaban "siapa" seperti kesalahan individu atau kurang pelatihan, dan karena titik berhenti rantai ditentukan oleh di mana penanya memulai dan berhenti bertanya [S8]. Ia menyarankan pertanyaan "bagaimana" yang menggali kondisi dan alasan yang masuk akal bagi orang saat itu, dan menerima beberapa faktor penyebab sekaligus [S8]. [komunitas] Arah yang sama ada di panduan postmortem PagerDuty, yang meminta analisis mencari faktor penyebab, bukan satu akar masalah, dengan fokus pada sistem dan proses [S6].

Sumber primer menempatkan analisis penyebab sebagai bagian dari respons: Rev. 3 meminta urutan kejadian ditentukan, kerentanan dan pelaku yang terlibat dicari, dan insiden dianalisis untuk menemukan akar masalah yang mendasar atau sistemik (RS.AN-03) [S1]. Kata "sistemik" di situ penting: yang dicari adalah kondisi yang bisa diperbaiki, bukan individu.

Untuk `INC-2026-019`, rantai lima kali kenapa berbunyi: data diambil karena penyerang masuk ke server billing, karena password `svc_billing` bocor, karena skrip berisi password ada di laptop Andi, karena Andi menjalankan lampiran, karena Andi tidak waspada. Rantai itu berakhir di satu orang dan menghasilkan satu tindakan, pelatihan ulang Andi, yang tidak mengubah apa pun untuk staf lain, skrip lain, atau server lain. Tabel faktor penyebab di bagian 2.4 menghasilkan sepuluh perbaikan dari bahan yang sama, karena bertanya "bagaimana kondisi ini bisa ada" di setiap titik.

PT JAB memakai empat kelompok faktor. Tiga kelompok pertama sama dengan pembagian akar masalah di Day 06 bagian 1.3; kelompok keempat ditambahkan untuk PIR karena menyangkut cara tim merespons:

- **Penyebab langsung:** tanpanya insiden tidak terjadi.
- **Faktor yang memungkinkan:** membuat serangan lebih mudah.
- **Celah visibilitas:** membuat deteksi terlambat atau scope tidak pasti.
- **Faktor respons:** hal dalam penanganan yang mempercepat atau memperlambat, termasuk yang berjalan baik.

Lima kali kenapa tetap boleh dipakai sebagai alat bantu di dalam satu faktor, misalnya untuk menelusuri kenapa skrip berisi password bisa tersimpan di share. Batasnya: jangan dijadikan satu-satunya analisis, dan jangan berhenti di nama orang.

### 1.5 PIR yang blameless: jujur tanpa takut, tetapi tetap ada yang bertanggung jawab

Pertanyaan kelima Hendra memuat dua permintaan yang terdengar bertentangan: jangan saling menyalahkan, tetapi harus jelas siapa memperbaiki apa. Keduanya justru saling membutuhkan.

Google SRE mendefinisikan postmortem sebagai catatan tertulis insiden yang memuat dampak, tindakan mitigasi, akar masalah, dan tindak lanjut untuk mencegah terulang, dan menyebut postmortem yang blameless berfokus pada faktor penyebab tanpa menunjuk individu, dengan asumsi setiap orang bertindak dengan niat baik berdasarkan informasi yang dimilikinya saat itu [S4]. Alasannya praktis: budaya menyalahkan membuat orang menyembunyikan masalah [S4]. PagerDuty menyebut postmortem blameless berfokus pada bagaimana kesalahan terjadi, bukan siapa pelakunya; menyarankan pertanyaan "apa" dan "bagaimana" alih-alih "kenapa" yang memaksa orang membela diri; tidak menyebut nama individu dalam analisis; menyusun timeline dari sebelum insiden ke depan untuk mengurangi hindsight bias; dan juga mencatat hal yang berjalan baik [S5].

Rev. 2 memberi aturan praktis rapatnya: libatkan semua pihak yang terlibat, kumpulkan masukan dan topik dari peserta sebelum rapat, tetapkan aturan rapat di awal, pakai moderator yang terampil memfasilitasi, dan dokumentasikan kesepakatan serta action item lalu kirim ke yang tidak hadir [S2]. Rev. 2 juga menyarankan rapat diadakan dalam beberapa hari setelah insiden berakhir dan memberi daftar pertanyaan yang harus dijawab, antara lain apa tepatnya yang terjadi dan kapan, seberapa baik staf dan manajemen menangani, informasi apa yang dibutuhkan lebih cepat, apakah ada tindakan yang menghambat recovery, apa yang akan dilakukan berbeda, dan precursor atau indikator apa yang perlu dipantau ke depan [S2]. Playbook CISA menyebut tujuan hotwash: memastikan akar masalah sudah dihilangkan atau dimitigasi, menemukan masalah infrastruktur, kebijakan, dan prosedur, meninjau ulang peran dan wewenang, mengidentifikasi kebutuhan pelatihan, dan memperbaiki alat [S3].

Dari sumber-sumber itu, aturan PIR PT JAB:

| Aturan | Kenapa |
|---|---|
| Fasilitator bukan orang yang aktif di insiden | Fasilitator tidak membela keputusannya sendiri; PagerDuty menyarankan fasilitator yang tidak memberi opini dan tidak berperan aktif [S7] |
| Draft laporan dikirim minimal 24 jam sebelum rapat | Rapat membahas analisis, bukan membaca timeline bersama [S6][S7] |
| Analisis menyebut peran, bukan nama ("staf penagihan", "analyst on-call") | Siapa pun di posisi itu bisa melakukan hal yang sama [S5] |
| Setiap pernyataan "harusnya" diganti pertanyaan "apa yang terlihat saat itu?" | Mengurangi hindsight bias [S5] |
| Hal yang berjalan baik dicatat sama seriusnya | Praktik baik perlu dipertahankan, dan tim butuh pengakuan [S5] |
| Action item punya satu pemilik dan tenggat | Blameless berarti tidak menghukum, bukan tidak ada yang bertanggung jawab memperbaiki |

Di `INC-2026-019` ada dua orang yang mudah disalahkan: Andi yang membuka lampiran, dan Yudi Hermawan yang masih menjalankan skrip lama dari share (Day 06 bagian 2.3). Laporan menulis keduanya sebagai "staf penagihan", dan pertanyaannya menjadi: bagaimana lampiran `.js` bisa sampai ke inbox dan berjalan saat diklik, dan bagaimana skrip berisi password bisa menjadi alat kerja resmi tim penagihan. Kedua pertanyaan itu menghasilkan perbaikan yang berlaku untuk semua orang.

### 1.6 Action item: spesifik, satu pemilik, tenggat, dan kriteria selesai

Pertanyaan keenam Hendra ("siapa memperbaiki apa") dijawab dengan daftar action item, dan kualitas daftar itu menentukan apakah PIR berguna.

PagerDuty meminta setiap action item bisa dikerjakan (diawali kata kerja), spesifik (cakupannya sempit, dengan yang termasuk dan tidak termasuk), dan terbatas (punya kriteria selesai yang jelas); dibuat sebagai tiket di proyek tim pemiliknya; dan keputusan untuk tidak mengerjakan sesuatu juga didokumentasikan supaya trade-off-nya dipahami [S6]. Playbook CISA meminta deteksi untuk teknik penyerang yang berhasil ditambahkan ke seluruh organisasi dan "blind spot" ditutup [S3]. Rev. 3 menyebut perbaikan bisa menyasar program IR sendiri (plan, kebijakan, proses) atau aspek lain manajemen risiko, misalnya teknik penyerang yang belum diblok atau belum terdeteksi (ID.IM-03) [S1].

Bandingkan dua cara menulis tindakan yang sama:

| Lemah | Kuat |
|---|---|
| "Tingkatkan keamanan akun service" | "Ubah semua akun service Linux yang bisa login SSH dengan password menjadi publickey dari sumber tertentu; pemilik Infrastruktur; tenggat 2026-11-30; selesai bila query login password akun service 30 hari terakhir kosong" |
| "Edukasi pengguna soal phishing" | "Ubah asosiasi file `.js` dan skrip sejenis agar tidak dijalankan `wscript.exe` di semua workstation; pemilik Infrastruktur; selesai bila uji membuka `.js` di workstation sampel tidak menjalankan apa pun" |

Kolom kanan bisa diperiksa oleh orang yang tidak ikut rapat. Kolom kiri tidak bisa diperiksa sama sekali, sehingga tidak pernah selesai dan tidak pernah gagal.

Prioritasnya mengikuti pembagian di Day 06 bagian 1.3: penyebab langsung sudah ditutup sebelum sistem pengganti masuk produksi, faktor yang memungkinkan ditutup dalam hitungan hari sampai minggu, dan celah visibilitas boleh jangka panjang dengan pemilik dan tanggal. Daftar lengkap `INC-2026-019` ada di bagian 2.6.

### 1.7 Melacak sampai selesai, lalu menutup insiden

Pertanyaan terakhir Hendra memisahkan dua hal yang sering dicampur: PIR selesai, dan perbaikan selesai.

Rev. 3 menekankan bahwa pelajaran dari respons sebaiknya dibagikan begitu ditemukan, tidak ditunda sampai recovery selesai, dan bahwa perbaikan diidentifikasi dari evaluasi, latihan, dan pelaksanaan proses respons itu sendiri (ID.IM-01 sampai ID.IM-03) [S1]. Google SRE menyebut postmortem yang tidak ditinjau sama saja dengan tidak pernah ada, dan menyarankan postmortem dibagikan seluas berguna dan disimpan di repositori bersama [S4]. Rev. 2 menambahkan bahwa laporan PIR adalah bahan pelatihan anggota tim baru dan bahwa pembaruan kebijakan dan prosedur IR adalah bagian penting dari proses lessons learned [S2].

PT JAB memakai aturan penutupan berikut, yang juga tertulis di pernyataan akhir recovery (Day 06 bagian 2.5):

1. **Insiden ditutup** setelah PIR selesai, laporan final disetujui IC, dan setiap action item sudah menjadi tiket dengan pemilik dan tenggat. Penutupan insiden tidak menunggu semua action item jangka panjang selesai.
2. **Action item dilacak terpisah** dari tiket insiden, dan statusnya dibahas di rapat mingguan SOC sampai selesai. Item yang lewat tenggat dieskalasi ke executive sponsor.
3. **Bukti selesai** ditempel di tiketnya: hasil query, tangkapan konfigurasi, atau hasil uji. "Sudah dikerjakan" tanpa bukti tidak dihitung selesai.
4. **Pemantauan pasca pemulihan** tetap berjalan sampai tanggal yang ditetapkan (2026-11-14 untuk `INC-2026-019`), dan temuan selama pemantauan membuka insiden baru atau membuka kembali insiden ini.
5. **IR plan dan playbook** diperbarui bila PIR menemukan langkah yang hilang atau keliru, dengan nomor versi baru.

Hendra tahu perbaikan dikerjakan bukan dari laporan PIR, tetapi dari status action item yang dikirim setiap minggu dengan bukti.

## 2. Contoh artefak dan langkah praktis di PT JAB

Semua isi bagian ini fiktif. Fakta kasus diambil dari Day 03 sampai Day 06; detail baru yang ditambahkan di Day ini (durasi gangguan saat cutover, jam kerja, peserta dan fasilitator PIR, nomor dan tenggat action item) juga fiktif.

### 2.1 Kerangka laporan insiden lengkap

Kerangka ini menjawab bagian "isinya apa saja" dari pertanyaan pertama Hendra. Disimpan sebagai template `JAB-IRP-01` Lampiran F dan dipakai untuk setiap insiden SEV-1 dan SEV-2.

```
LAPORAN INSIDEN <nomor> | versi <n> | <tanggal> | Klasifikasi: <ditetapkan Legal>
Pemilik laporan: <technical lead> | Disetujui: <IC>

0. Executive summary (satu halaman, ditulis terakhir)
1. Ringkasan insiden: jenis, severity dan perubahannya, aset dan data terdampak
2. Timeline akhir: waktu WIB, kejadian, sumber (log, bukti, case notes)
3. Scope dan dampak
   - host, akun, data (jenis dan jumlah, dengan tingkat keyakinan)
   - gangguan layanan pelanggan (mulai, selesai, durasi)
   - pihak luar terdampak; status pemberitahuan (rujuk dokumen DPO, bukan disalin)
4. Metrik waktu: titik awal, titik akhir, cara hitung, hasil
5. Tindakan respons dan recovery: keputusan, pemilik keputusan, alasan, alternatif
   yang ditolak
6. Faktor penyebab: langsung | memungkinkan | visibilitas | respons (termasuk yang
   berjalan baik)
7. Action item: nomor, tindakan, pemilik, tenggat, kriteria selesai, status
8. Keputusan untuk tidak mengerjakan sesuatu, dengan alasannya
9. Lampiran: daftar bukti dan chain of custody, scope statement per versi,
   memo keputusan, laporan pihak ketiga
```

Cara membaca elemennya:

- **Klasifikasi ditetapkan Legal** di baris pertama, karena dokumen ini memuat kelemahan kontrol dan fakta data pribadi (bagian 1.2).
- **Status pemberitahuan dirujuk, bukan disalin.** Laporan internal menyebut bahwa DPO menangani pemberitahuan dan di dokumen mana; isi pemberitahuan tetap di jalurnya sendiri.
- **Bagian 5 menyimpan alasan dan alternatif yang ditolak**, seperti memo containment di Day 05 bagian 2.1. Pertanyaan "kenapa tidak dimatikan saja" setahun kemudian tetap punya jawaban.
- **Bagian 8** mengikuti saran PagerDuty untuk mendokumentasikan keputusan tidak bertindak [S6].

### 2.2 Executive summary `INC-2026-019`

Ringkasan ini menjawab permintaan Hendra untuk direksi. Bandingkan panjangnya dengan laporan lengkap: semua yang tidak membantu direksi memutuskan atau memahami risiko dibuang.

```
INC-2026-019 | Executive summary | versi 1 | Selasa 2026-10-27 | Rahasia
Disusun: Sari Kusuma | Disetujui: Dimas Prasetyo (IC)

APA YANG TERJADI
Senin 12 Oktober, email tagihan palsu berisi lampiran berbahaya dibuka di laptop
staf penagihan. Penyerang menemukan password akun sistem billing yang tersimpan di
sebuah skrip kerja, masuk ke server billing pada dini hari, dan mengambil sekitar
5.000 baris data pelanggan (nama, NIK, alamat, telepon). Serangan terdeteksi Selasa
pagi, sekitar 18 jam setelah lampiran dibuka.

DAMPAK
- Data pribadi: 5.000 pelanggan, keyakinan sedang-tinggi. Pemberitahuan ditangani
  DPO dan Legal (dokumen terpisah).
- Layanan: pembayaran online berhenti 9 menit (Selasa 16:02-16:11) dan 20 menit
  (Kamis 23:00-23:20). Tidak ada gangguan broadband.
- Tidak ada bukti kompromi akun administrator domain.

PENANGANAN
Akses penyerang ditutup serentak Selasa 16:00, semua host yang diketahui ditahan
pukul 17:20. Server billing dibangun ulang dan aktif Kamis 23:00, di dalam batas
72 jam yang ditetapkan. Recovery dinyatakan selesai Jumat 23 Oktober.

PENYEBAB UTAMA
Password akun sistem tersimpan dalam teks biasa di skrip yang dibagikan ke staf;
lampiran skrip dalam arsip lolos filter email; deteksi bergantung pada reputasi
domain dari vendor; sebagian server dan laptop belum memakai EDR.

STATUS PERBAIKAN (12 action item)
Selesai 2: skrip berisi password dihapus; lampiran skrip diblok.
Berjalan 10, tenggat terakhir 15 Desember 2026. Tiga butuh dukungan direksi:
EDR untuk server Linux dan laptop yang belum tercakup, dan blokir DNS terenkripsi.

KEPUTUSAN YANG DIMINTA
Persetujuan anggaran lisensi EDR tambahan (item 7 dan 8) sebelum 6 November.
```

Cara membaca elemennya:

- **Bahasa bisnis.** Tidak ada `svc_billing`, `kworkerd`, atau nama domain C2. Yang ada: data apa, berapa, layanan apa, berapa lama.
- **Keyakinan ditulis** untuk angka data, sama seperti di laporan retainer, karena angka itu akan dipakai di pemberitahuan.
- **Penyebab ditulis sebagai kondisi**, tidak menyebut nama staf.
- **Diakhiri keputusan yang diminta**, dengan tenggat. Ringkasan untuk direksi yang tidak meminta apa pun sering hanya dibaca, lalu dilupakan.

**Kapan gagal:** executive summary ditulis sebelum laporan lengkap selesai, lalu angka di dalamnya berubah. Direksi sudah mengutip angka lama di rapat lain.

### 2.3 Timeline akhir dan metrik waktu

Timeline ini menjawab pertanyaan ketiga Hendra. Disusun dari timeline scribe, case notes, evidence log, dan laporan retainer; setiap baris menyebut sumbernya supaya metrik bisa dihitung ulang.

| Waktu (WIB) | Kejadian | Sumber |
|---|---|---|
| Sen 12/10 15:58 | Email `Tagihan-Okt-2026.zip` diterima 9 mailbox | Message trace, E10 |
| Sen 16:05 | Lampiran dijalankan di `JKT-WS-0388`; scheduled task `\SysCacheUpdate` dibuat; beacon ke `cdn-sync.example.net` dimulai | Timeline EDR, E02 |
| Sen 23:40 | `export-tagihan.ps1` (berisi password `svc_billing`) dibaca | PowerShell 4104 |
| Sel 13/10 02:14 | SSH `svc_billing` dengan password dari `10.10.23.88` ke `jkt-billing01` | `linux_secure` |
| Sel 02:20 | `jkt-billing01` beacon ke `203.0.113.77` dari `kworkerd` | Firewall, E05 |
| Sel 03:06 sampai 03:12 | Query 5.000 baris tabel pelanggan, dikompres, dikirim keluar, file dihapus | Analisis memori retainer (E05) |
| Sel 08:51 | Lampiran dijalankan di `BDG-WS-0142` | Sysmon dan DNS |
| Sel 09:47 | Alert pertama `SOC-2026-0203` | EDR |
| Sel 10:30 | Validasi oleh technical lead | Case notes |
| Sel 10:40 | Declare SEV-3 | Timeline scribe |
| Sel 11:50 | SEV-2; scope statement v1 | Timeline scribe |
| Sel 12:20 | DPO dan Legal diberi tahu | Timeline scribe |
| Sel 12:30 | Pengamanan bukti dimulai | Evidence log |
| Sel 13:35 | SEV-1; executive sponsor diberi tahu; retainer diaktifkan | Timeline scribe |
| Sel 15:10 | Keputusan containment pilihan B oleh executive sponsor | Memo keputusan |
| Sel 16:00 | Jam H: containment serentak dimulai | Rencana jam H |
| Sel 16:02 sampai 16:11 | Pembayaran online berhenti (rotasi `billing_app`) | Tiket Tim Aplikasi Billing |
| Sel 17:20 | `JKT-WS-0412` ditahan (terdeteksi lewat sinkhole 17:12) | Query validasi, timeline scribe |
| Rab 14/10 10:20 | Kesimpulan 5.000 baris diteruskan ke DPO dan Legal | Timeline scribe |
| Rab 17:20 | Containment dinyatakan berhasil; SEV-2 | Timeline scribe |
| Kam 15/10 23:00 sampai 23:20 | Cutover ke `jkt-billing02`; pembayaran online berhenti | Tiket change |
| Jum 23/10 10:00 | Recovery dinyatakan selesai | Pernyataan akhir recovery |

Dari timeline itu, metrik dihitung dengan titik awal dan akhir yang disebut. Kolom "Hitungan" ada supaya pembaca bisa memeriksa angka tanpa percaya begitu saja.

| Metrik | Dari | Sampai | Hitungan | Hasil |
|---|---|---|---|---|
| Dwell time | Lampiran dijalankan, Sen 16:05 | Alert pertama, Sel 09:47 | 7 j 55 m (sampai tengah malam) + 9 j 47 m | 17 j 42 m |
| Data diambil sampai terdeteksi | Data dikirim keluar, Sel 03:12 | Sel 09:47 | 09:47 dikurangi 03:12 | 6 j 35 m |
| Alert sampai validasi | Sel 09:47 | Sel 10:30 | | 43 m |
| Alert sampai declare | Sel 09:47 | Sel 10:40 | | 53 m |
| Alert sampai containment dimulai | Sel 09:47 | Jam H, Sel 16:00 | 6 j + 13 m | 6 j 13 m |
| Alert sampai semua host yang diketahui ditahan | Sel 09:47 | Sel 17:20 | 7 j + 33 m | 7 j 33 m |
| Alert sampai containment berhasil | Sel 09:47 | Rab 17:20 | 24 j + 7 j 33 m | 31 j 33 m |
| Jam H sampai layanan pulih di server baru | Sel 16:00 | Kam 23:00 | 48 j + 7 j | 55 j (batas 72 j) |
| Alert sampai recovery selesai | Sel 13/10 09:47 | Jum 23/10 10:00 | 10 hari + 13 m | 10 hari 0 j 13 m |
| Gangguan layanan pelanggan | | | 9 m + 20 m | 29 m |
| SEV-1 sampai executive sponsor diberi tahu | Sel 13:35 | Sel 13:35 | | 0 m (target maks 30 m) |

Cara membaca hasil:

- **Dwell time dihitung dari 16:05, bukan 15:58**, karena aktivitas penyerang di dalam dimulai saat lampiran dijalankan. Bila dihitung dari email diterima, hasilnya 17 j 49 m. Pilihan titik awal ditulis di laporan supaya angka tidak dibandingkan secara keliru dengan insiden lain.
- **Masalah terbesar ada sebelum alert**, bukan sesudahnya: data sudah keluar 6 j 35 m sebelum alert pertama. Mempercepat declare dari 53 menit menjadi 20 menit tidak akan menyelamatkan data itu; mendeteksi eksekusi lampiran pada Senin 16:05 mungkin bisa.
- **Selang alert sampai jam H (6 j 13 m)** adalah penundaan yang disengaja untuk scoping dan bukti, dengan batas dan pemicu tertulis (Day 05 bagian 1.3). Laporan menulisnya sebagai keputusan, bukan sebagai kelambatan.
- **Metrik ini versi 1.** Bila analisis lanjutan menemukan aktivitas sebelum Senin 16:05, dwell time berubah dan laporan diberi versi baru.

**Variasi:** catat juga total jam kerja dari tiket (di contoh ini 186 jam-orang internal ditambah jam retainer sesuai tagihan), yang menurut Rev. 2 berguna untuk menilai kebutuhan sumber daya tim [S2].

**Kapan gagal:** timeline disusun dari ingatan setelah insiden, tanpa sumber per baris. Metrik terlihat presisi sampai menit, padahal titik-titiknya hasil perkiraan.

### 2.4 Analisis faktor penyebab

Tabel ini menjawab pertanyaan keempat Hendra. Kolom tengah adalah inti analisis: setiap faktor dijawab dengan "bagaimana kondisi ini bisa ada", bukan "siapa yang salah". Kolom kanan menunjuk nomor action item di bagian 2.6.

| Kelompok | Faktor | Bagaimana kondisi ini bisa ada | Action item |
|---|---|---|---|
| Langsung | Password `svc_billing` dalam teks biasa di skrip yang dipakai staf penagihan, termasuk di share tim | Skrip ekspor laporan dibuat bertahun-tahun lalu sebagai jalan pintas dan menjadi alat kerja resmi; tidak ada proses review skrip yang menyimpan kredensial | 1, 2 |
| Langsung | `svc_billing` boleh login SSH dengan password dari jaringan workstation | Tidak ada standar akun service Linux; konfigurasi SSH bawaan tidak pernah dibatasi | 3 |
| Memungkinkan | Lampiran `.js` di dalam `.zip` lolos filter email dan dijalankan `wscript.exe` saat diklik | Filter hanya memeriksa ekstensi lampiran di tingkat atas; asosiasi file bawaan Windows tidak diubah | 4 |
| Memungkinkan | Server billing bisa terhubung ke tujuan mana pun di internet | Egress server data center tidak dibatasi sebelum insiden | Selesai: egress allowlist dijadikan permanen (Day 06 bagian 2.5) |
| Visibilitas | Alert pertama baru muncul saat domain C2 ditandai vendor; eksekusi lampiran Senin 16:05 tidak menghasilkan alert yang ditindaklanjuti | Belum ada rule perilaku untuk skrip yang dijalankan `wscript.exe` dari arsip dan PowerShell terenkode dari induk itu | 5 |
| Visibilitas | Login SSH dengan password oleh akun service dari workstation pukul 02:14 tidak dialert | Tidak ada rule untuk pola itu; baseline login akun service baru dibuat saat scoping | 6 |
| Visibilitas | `jkt-billing01`, `BDG-WS-0142`, `JKT-WS-0412`, dan 3 dari 7 penerima lain tanpa EDR atau Sysmon | Cakupan EDR mengikuti pengadaan bertahap; server Linux dan sebagian laptop belum masuk | 7, 8 |
| Visibilitas | DNS over HTTPS dan resolver luar tidak terlihat | Egress DNS dari jaringan kantor tidak dibatasi | 9 |
| Visibilitas | Log database hanya mencatat koneksi, sehingga akses data tidak bisa dibuktikan atau disingkirkan | Audit query dianggap terlalu berat dan tidak pernah dinilai ulang | Selesai: audit tabel pelanggan aktif (Day 06 bagian 2.5) |
| Respons, perlu diperbaiki | Daftar penerima email baru lengkap 12:50, dan laptop tanpa EDR yang dibawa ke luar kantor baru terlihat 17:12 lewat sinkhole | Playbook phishing tidak punya langkah menghubungi langsung penerima yang host-nya tidak terpantau | 10 |
| Respons, perlu diperbaiki | Salinan kedua implant di subfolder tersembunyi `/var/tmp` tidak terlihat di live response, baru ditemukan retainer | Checklist live response Linux hanya memeriksa tingkat atas direktori sementara | 11 |
| Respons, perlu diperbaiki | Server pengganti dari gold image mencoba NTP publik dan memicu `SOC-2026-0205` | Gold image Linux belum memakai `jkt-ntp01` | 12 |
| Respons, berjalan baik | Bukti volatil tiga host aman sebelum jam H; containment serentak dengan rencana per menit; delegasi bersyarat; sinkhole yang mencatat menemukan host ketiga; cutover di jam ke-55 dari batas 72 jam; laptop cadangan sebelum reimage | Prosedur bukti, RACI, dan wewenang di muka sudah disiapkan di IR plan versi 2.0 dan dipakai | Dipertahankan; dijadikan contoh di pelatihan |

Cara membaca elemennya:

- **Tidak ada nama staf** di kolom mana pun. Lampiran yang dibuka dan skrip yang dijalankan muncul sebagai kondisi filter, asosiasi file, dan proses kerja.
- **Baris "berjalan baik"** ada karena PIR yang hanya mencatat kekurangan membuat tim lupa bahwa banyak keputusan sulit malam itu tepat, dan praktik itu bisa hilang bila tidak disebut.
- **Satu faktor bisa punya beberapa action item**, dan dua faktor sudah ditutup selama recovery. Keduanya tetap ditulis supaya analisisnya lengkap.

**Variasi:** pakai lima kali kenapa di dalam satu baris untuk menggali lebih dalam, misalnya "bagaimana skrip berisi password menjadi alat kerja resmi?", lalu berhenti saat jawabannya adalah kondisi yang bisa diubah, bukan nama orang [S8].

**Kapan gagal:** tabel diisi oleh satu orang sebelum rapat lalu dibacakan. Faktor respons yang hanya diketahui NOC, Tim Aplikasi Billing, atau teknisi Bandung tidak pernah muncul.

### 2.5 Agenda dan aturan PIR Selasa 27 Oktober

Dokumen ini menjawab pertanyaan kelima Hendra. Draft laporan dan undangan dikirim Sari Senin 2026-10-26 pukul 12:00, lebih dari 24 jam sebelum rapat. Fasilitatornya Nina Kartika, Manajer Risiko dan Kepatuhan TI, yang tidak terlibat dalam penanganan.

```
INC-2026-019 | Post-incident review | Selasa 2026-10-27 13:00-15:00 WIB
Ruang rapat lantai 5 + bridge untuk Bandung | Fasilitator: Nina Kartika
Pemilik laporan: Sari Kusuma | Notulis: analyst L1 (scribe insiden)
Peserta: Dimas (IC), Sari (TL), Yoga (bukti), scribe, Bambang Hartono (NOC),
         Wahyu Nugroho (Aplikasi Billing), perwakilan Infrastruktur, Agus Setiawan
         (DPO), Ratna Sari (Legal), Maya Lestari (Komunikasi), Fajar Nugraha (POP
         Bandung, via bridge), perwakilan retainer
Hendra Wijaya bergabung 14:45 untuk komitmen dukungan.

ATURAN (dibacakan fasilitator di awal)
1. Kita mencari kondisi yang membuat kejadian mungkin, bukan orang untuk disalahkan.
2. Sebut peran, bukan nama. Ganti "harusnya" dengan "apa yang terlihat saat itu?".
3. Fakta di timeline dikoreksi dengan sumber; pendapat ditandai sebagai pendapat.
4. Setiap usulan perbaikan keluar dari rapat dengan satu pemilik dan tenggat,
   atau dicatat sebagai keputusan untuk tidak dikerjakan.

AGENDA
13:00-13:10  Tujuan dan aturan                                  fasilitator
13:10-13:35  Timeline dan metrik; koreksi fakta                 Sari
13:35-14:15  Faktor penyebab per kelompok, termasuk yang
             berjalan baik; pertanyaan "bagaimana" per titik    semua, dipandu fasilitator
14:15-14:45  Action item: pemilik, tenggat, kriteria selesai;
             keputusan tidak dikerjakan                         Sari, pemilik tiap item
14:45-15:00  Dampak ke pelanggan dan status pemberitahuan
             (ringkas, oleh DPO); dukungan yang dibutuhkan      Hendra, Agus

PERTANYAAN PEMANDU (dari NIST Rev. 2 bagian 3.4.1)
- Apa tepatnya yang terjadi, dan kapan?
- Apakah prosedur yang tertulis diikuti, dan apakah cukup?
- Informasi apa yang seharusnya didapat lebih cepat?
- Adakah tindakan yang menghambat recovery?
- Apa yang akan dilakukan berbeda di insiden serupa?
- Precursor atau indikator apa yang perlu dipantau ke depan?
- Alat atau sumber daya apa yang dibutuhkan?
```

Cara membaca elemennya:

- **Fasilitator dari luar tim respons** mengikuti saran PagerDuty bahwa fasilitator tidak memberi opini, tidak memutuskan, dan tidak berperan aktif di insiden [S7].
- **Hendra hadir di 15 menit terakhir**, untuk bagian yang membutuhkan keputusannya. Kehadiran pimpinan sepanjang rapat sering membuat peserta lebih berhati-hati bercerita; itu pertimbangan PT JAB, bukan aturan dari sumber.
- **Pertanyaan pemandu** diambil dari daftar Rev. 2 [S2]; agenda waktu per bagian mengikuti saran PagerDuty untuk membatasi waktu setiap topik [S7].
- **Teknisi Bandung diundang** walaupun perannya kecil, karena Rev. 2 meminta semua pihak yang terlibat hadir [S2], dan pengalaman mengirim bukti dari POP adalah bahan perbaikan prosedur cabang.

**Kapan gagal:** PIR dijadwalkan berminggu-minggu setelah insiden. Detail sudah dilupakan, peserta sudah sibuk dengan insiden berikutnya, dan yang tersisa hanya kesimpulan umum.

### 2.6 Daftar action item dan pelacakannya

Daftar ini menjawab pertanyaan keenam dan ketujuh Hendra, disepakati di PIR dan disalin ke tiket tim masing-masing. Baca kolom "Kriteria selesai": setiap item harus bisa dibuktikan oleh orang yang tidak ikut rapat.

| No | Tindakan | Pemilik | Tenggat | Kriteria selesai | Status 27/10 |
|---|---|---|---|---|---|
| 1 | Hapus `export-tagihan.ps1` dari laptop dan share; ekspor laporan staf lewat job terjadwal `10.20.1.15` | Tim Aplikasi Billing | 2026-10-15 | Pencarian ulang kosong | Selesai |
| 2 | Cari skrip lain berisi password teks biasa di share dan endpoint; setiap temuan diberi tiket ke pemiliknya | SOC (Sari) | 2026-11-13 | Laporan pencarian; setiap temuan punya tiket | Berjalan |
| 3 | Ubah semua akun service Linux yang bisa SSH dengan password menjadi publickey dari sumber tertentu | Infrastruktur | 2026-11-30 | Query login password akun service 30 hari terakhir kosong | Berjalan (`svc_billing` selesai) |
| 4 | Blok `.js` dan skrip sejenis di lampiran termasuk dalam arsip; ubah asosiasi `.js` | Infrastruktur | 2026-10-16 | Uji kirim dari luar ditolak; uji buka tidak menjalankan apa pun | Selesai |
| 5 | Rule deteksi: skrip dijalankan `wscript.exe` atau `cscript.exe` dari folder unduhan atau arsip, dan PowerShell terenkode dari induk itu; prioritas P2 | SOC (Yoga) | 2026-11-06 | Rule aktif; diuji dengan simulasi di lab | Berjalan |
| 6 | Rule deteksi: login SSH dengan password oleh akun service dari subnet workstation | SOC (Sari) | 2026-11-06 | Rule aktif; diuji di lab | Berjalan |
| 7 | EDR Linux untuk `jkt-portal01` dan `jkt-radius01` | Infrastruktur | 2026-11-30 | Perangkat aktif dan melapor di konsol | Berjalan |
| 8 | EDR untuk laptop yang belum tercakup, termasuk laptop penagihan dan cabang | Infrastruktur | 2026-12-15 | Laporan cakupan EDR semua laptop aktif | Menunggu anggaran |
| 9 | Blok DNS over HTTPS dan resolver luar dari jaringan kantor | NOC | 2026-11-15 | Uji DoH dari workstation sampel gagal; deny tercatat | Berjalan |
| 10 | Perbarui `JAB-PB-02`: setelah message trace, penerima yang host-nya tanpa EDR dihubungi langsung dalam 1 jam | SOC lead (Dimas) | 2026-11-06 | Playbook versi baru disetujui dan disosialisasikan | Berjalan |
| 11 | Perbarui checklist live response Linux: cari file eksekusi di seluruh direktori sementara termasuk subfolder tersembunyi | SOC (Yoga) | 2026-11-06 | Checklist versi baru diuji di lab | Berjalan |
| 12 | Gold image Linux memakai `jkt-ntp01` | Infrastruktur | 2026-10-30 | Image baru dengan hash tercatat | Berjalan |

Keputusan untuk tidak dikerjakan, dicatat di laporan bagian 8: audit query penuh untuk semua tabel database billing tidak diaktifkan karena beban kinerja; yang aktif adalah audit tabel pelanggan, dan keputusan ini ditinjau ulang setelah enam bulan.

Cara membaca elemennya:

- **Setiap item punya satu pemilik**, berupa tim dan, bila perlu, nama penanggung jawab di tim itu. Dua pemilik untuk satu item sama dengan tidak ada pemilik, prinsip yang sama dengan satu A di RACI (Day 02 bagian 1.3).
- **Tenggat mengikuti kelompok faktor.** Item langsung dan yang memungkinkan bertenggat hari sampai minggu; item visibilitas boleh lebih panjang, sesuai pembagian di Day 06 bagian 1.3.
- **Item 5 dan 6 menutup celah deteksi** yang ditemukan, sesuai permintaan playbook CISA untuk menambah deteksi bagi teknik penyerang yang berhasil [S3].
- **Status "menunggu anggaran"** ditulis apa adanya dan menjadi isi "keputusan yang diminta" di executive summary.

Status dikirim Sari setiap Jumat ke Dimas dan Hendra, dengan bukti untuk item yang ditandai selesai. `INC-2026-019` ditutup Dimas pada Selasa 2026-10-27 pukul 16:30, setelah laporan final disetujui dan kedua belas item menjadi tiket; pemantauan pasca pemulihan dan action item tetap dilacak sampai selesai.

**Kapan gagal:** action item ditulis di notulen rapat tetapi tidak pernah menjadi tiket di tim pemiliknya. Tiga bulan kemudian, insiden serupa terjadi lewat skrip lain yang sama-sama menyimpan password, dan PIR berikutnya menemukan item nomor 2 yang tidak pernah dikerjakan.

## 3. Lab praktik

Lab ini berupa latihan dokumen. Bahannya kasus di catatan ini atau insiden latihan di lab-mu sendiri; jangan memakai data, nama, atau kejadian dari pekerjaan nyata.

1. **Metrik dari timeline lain.** Pakai fakta `INC-2026-012` (Day 02 dan Day 15): alert 01:40, declare 02:55, blokir IP 04:31, portal dialihkan ke halaman pemeliharaan 12:00, portal online Minggu 13 September 21:40, dan web shell pertama dibuat 01:38:02. Hitung dwell time, alert sampai declare, declare sampai blokir, dan blokir sampai containment yang benar-benar menutup akses penyerang. Tulis titik awal, titik akhir, dan hitungan untuk setiap metrik seperti tabel bagian 2.3.
2. **Lima kali kenapa vs faktor penyebab.** Untuk `INC-2026-012`, tulis dulu rantai lima kali kenapa. Lalu tulis tabel faktor penyebab dengan empat kelompok seperti bagian 2.4. Bandingkan jumlah dan jenis action item yang dihasilkan masing-masing.
3. **Menulis ulang kalimat yang menyalahkan.** Ubah kalimat berikut menjadi kalimat blameless yang menyebut kondisi: "Analyst L1 lalai karena tidak menelepon SOC lead"; "Andi ceroboh membuka lampiran"; "NOC menghambat containment karena menolak blokir". Untuk setiap kalimat, tulis satu action item yang dihasilkan.
4. **Executive summary.** Tulis executive summary satu halaman untuk insiden lab atau untuk `INC-2026-012` dengan format bagian 2.2, termasuk satu keputusan yang diminta.
5. **Action item yang bisa diperiksa.** Ambil lima action item dari PIR atau RFO yang pernah kamu lihat (tanpa detail pekerjaan), tulis ulang masing-masing dengan pemilik, tenggat, dan kriteria selesai seperti bagian 2.6.
6. **Simulasi PIR.** Bila punya rekan belajar, jalankan PIR 45 menit untuk insiden lab dengan agenda bagian 2.5; satu orang menjadi fasilitator yang tidak boleh memberi opini. Catat berapa kali kata "harusnya" muncul dan bagaimana fasilitator mengubahnya.

**Hasil yang sebaiknya tersimpan:**

- `latihan/day19-metrik.md` berisi tabel metrik langkah 1 dengan hitungannya.
- Rantai lima kali kenapa dan tabel faktor penyebab dari langkah 2, beserta perbandingannya.
- Kalimat hasil penulisan ulang dan action item dari langkah 3.
- `latihan/day19-exec-summary.md` dari langkah 4.
- Daftar action item hasil langkah 5 dan catatan simulasi PIR dari langkah 6 bila dikerjakan.

**Variasi tantangan:** anggap analisis forensik lanjutan `INC-2026-019` menemukan bahwa `JKT-WS-0388` sudah beacon ke domain lain sejak Kamis sebelumnya. Metrik mana yang berubah, bagaimana menandai versi laporan, dan siapa yang harus diberi tahu bahwa angka sebelumnya keliru?

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat menyusun laporan dan menjalankan PIR. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Metrik di laporan berbeda dengan angka di presentasi lain | Titik awal tidak ditulis, atau dihitung dari timeline berbeda | Tulis titik awal, titik akhir, dan hitungan; satu timeline akhir sebagai acuan |
| Angka data di laporan internal berbeda dengan pemberitahuan DPO | Dua dokumen disusun terpisah tanpa sinkronisasi | Satu sumber fakta tentang data; laporan merujuk dokumen DPO |
| PIR berubah menjadi saling membela diri | Pertanyaan "kenapa kamu", fasilitator ikut terlibat di insiden | Fasilitator netral; aturan dibacakan di awal; pertanyaan "apa" dan "bagaimana" [S5][S7] |
| Kesimpulan PIR hanya "pelatihan pengguna" | Analisis berhenti di satu orang | Tabel faktor penyebab empat kelompok; tanyakan kondisi di setiap titik [S8] |
| Action item tidak pernah selesai | Tidak ada pemilik tunggal, tenggat, atau kriteria selesai; tidak menjadi tiket | Format bagian 2.6; status mingguan dengan bukti [S6] |
| Peserta tidak membaca draft sebelum rapat | Draft dikirim terlambat | Kirim minimal 24 jam sebelum rapat [S6][S7] |
| Pelajaran baru dibagikan berminggu-minggu kemudian | Menunggu PIR untuk semua hal | Bagikan pelajaran mendesak begitu ditemukan [S1] |

## 5. Kesalahan umum dan jebakan

- Menulis satu laporan untuk semua pembaca. Direksi tidak membaca 30 halaman, dan auditor tidak puas dengan satu halaman.
- Menganggap laporan internal sama dengan pemberitahuan ke regulator, atau menunda pemberitahuan sampai PIR selesai.
- Menulis metrik tanpa titik awal, atau menyamakan "alert pertama" dengan "awal insiden".
- Berhenti di "pengguna membuka lampiran" sebagai akar masalah. Itu titik di rantai, bukan kondisi yang bisa diperbaiki [S8].
- Menyebut nama individu di analisis, atau menilai keputusan memakai informasi yang baru diketahui belakangan [S5].
- Hanya mencatat kekurangan, sehingga praktik yang berhasil tidak dipertahankan [S5].
- Action item tanpa pemilik, tenggat, atau kriteria selesai, atau dengan dua pemilik.
- Menutup insiden sebelum action item menjadi tiket, atau sebaliknya menahan insiden terbuka berbulan-bulan sampai semua perbaikan jangka panjang selesai.
- Tidak memperbarui IR plan dan playbook setelah PIR menemukan langkah yang hilang [S2].

## 6. Catatan terkini

Bagian ini menampung latar dokumen acuan. Berguna saat membuka sumbernya lagi, tetapi tidak mengubah cara menyusun laporan di atas.

- **NIST SP 800-61 Rev. 3** (April 2025) tidak lagi memakai fase "post-incident activity" tersendiri. Perbaikan ditempatkan di kategori Improvement (ID.IM) fungsi Identify CSF 2.0, dan Rev. 3 menekankan pelajaran dibagikan begitu ditemukan, bukan ditunda sampai recovery selesai. After-action report kini muncul sebagai rekomendasi di RC.RP-06 [S1].
- **NIST SP 800-61 Rev. 2** (2012, sudah digantikan) masih banyak dirujuk karena daftar pertanyaan lessons learned dan contoh metriknya di bagian 3.4 lebih rinci [S2].
- **Playbook CISA** November 2021 memakai istilah hotwash untuk rapat lessons learned [S3].
- **Google SRE Book** terbit 2016; bab Postmortem Culture menjadi rujukan umum untuk istilah blameless postmortem di dunia operasi [S4]. **Dokumentasi PagerDuty** diperbarui berkala; tenggat rapat yang disebutnya (3 hari kalender untuk insiden paling berat, 5 hari kerja untuk tingkat berikutnya) adalah praktik PagerDuty, bukan standar [S6].

## 7. Cheat sheet

```
DUA DOKUMEN, SATU BAHAN
  executive summary: 1 halaman, ditulis terakhir, bahasa bisnis, diakhiri keputusan diminta
  laporan lengkap (after-action report, RC.RP-06): timeline+sumber | scope+dampak |
    metrik | tindakan+alasan+alternatif | faktor | action item | tidak dikerjakan | lampiran
  laporan internal != pemberitahuan regulator (Day 18); fakta data harus sama

METRIK: titik awal + titik akhir + hitungan + versi
  dwell time | data keluar -> deteksi | alert -> validasi/declare/contain | jam H -> pulih
  pisahkan masalah deteksi (sebelum alert) dari kinerja respons (sesudah alert)

FAKTOR PENYEBAB: langsung | memungkinkan | visibilitas | respons (+ yang berjalan baik)
  tanya "bagaimana kondisi ini bisa ada", bukan "siapa"
  5 whys: boleh di dalam satu faktor, jangan berhenti di nama orang

PIR BLAMELESS: dalam beberapa hari | draft >= 24 jam sebelumnya | fasilitator netral
  aturan dibacakan | peran bukan nama | "apa yang terlihat saat itu?" | agenda bertimebox
  pertanyaan r2 3.4.1 | pimpinan untuk komitmen

ACTION ITEM: kata kerja | spesifik | satu pemilik | tenggat | kriteria selesai | tiket
  langsung/memungkinkan: hari-minggu | visibilitas: boleh jangka panjang
  catat juga keputusan TIDAK dikerjakan

TUTUP INSIDEN: PIR selesai + laporan final disetujui IC + semua item jadi tiket
  action item dan pemantauan dilacak terpisah, status mingguan dengan bukti
  perbarui IR plan/playbook bila ada langkah yang hilang
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Laporan insiden `INC-2026-019` belum selesai, jadi DPO sebaiknya menunggu laporan itu sebelum menyiapkan pemberitahuan." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Laporan insiden internal ditulis untuk belajar dan memperbaiki, sedangkan pemberitahuan punya isi, tenggat, dan jalurnya sendiri. Di `INC-2026-019`, kesimpulan tentang 5.000 baris data diteruskan ke DPO dan Legal pada Rabu 10:20, jauh sebelum laporan dan PIR. Yang harus dijaga adalah fakta tentang data sama di kedua dokumen. Lihat bagian 1.2.

</details>

**2. Skenario keputusan.** Draft laporan menulis "dwell time 18 jam". Hendra bertanya angka itu dari mana. Respons mana yang tepat?

- A. Membulatkan saja menjadi "sekitar satu hari" supaya mudah diingat direksi.
- B. Menulis titik awal (lampiran dijalankan Senin 16:05), titik akhir (alert pertama Selasa 09:47), hitungannya, hasilnya 17 jam 42 menit, dan catatan bahwa angka bisa berubah bila ditemukan aktivitas lebih awal.
- C. Memakai waktu email diterima sebagai titik awal karena itu waktu paling awal yang tercatat.

<details><summary>Jawaban</summary>

B. Metrik hanya bisa diperiksa dan dibandingkan bila titik awal, titik akhir, dan hitungannya ditulis, dan versinya dicatat karena bukti baru bisa menggeser titik awal. A keliru karena angka bulat tanpa dasar tidak bisa diperiksa dan mudah dibandingkan secara salah dengan insiden lain. C tidak salah bila ditulis eksplisit (hasilnya 17 jam 49 menit), tetapi aktivitas penyerang di dalam dimulai saat lampiran dijalankan, dan pilihan apa pun harus disebut, bukan diam-diam. Lihat bagian 1.3 dan 2.3.

</details>

**3. Pertanyaan jebakan.** "Kalau PIR harus blameless, berarti tidak ada yang bertanggung jawab atas perbaikan." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Blameless berarti analisis mencari kondisi yang memungkinkan kejadian dan tidak menghukum individu atas keputusan yang masuk akal saat itu. Tanggung jawab tetap ada dalam bentuk action item: setiap perbaikan punya satu pemilik, tenggat, dan kriteria selesai, dan statusnya dilacak setiap minggu. Lihat bagian 1.5 dan 1.6.

</details>

**4. Skenario keputusan.** Di PIR, peserta dari Tim Aplikasi Billing berkata, "Akar masalahnya jelas, staf penagihan membuka lampiran. Usulan saya: pelatihan phishing ulang untuk staf itu." Apa yang sebaiknya dilakukan fasilitator?

- A. Mencatat usulan itu sebagai action item utama dan pindah ke topik berikutnya.
- B. Mengarahkan diskusi ke kondisi: bagaimana lampiran `.js` dalam arsip bisa lolos filter dan berjalan saat diklik, dan bagaimana skrip berisi password bisa menjadi alat kerja resmi, lalu mencatat perbaikan untuk kondisi itu.
- C. Meminta staf tersebut menjelaskan di rapat kenapa ia membuka lampiran.

<details><summary>Jawaban</summary>

B. Berhenti di satu orang menghasilkan satu tindakan yang tidak mengubah apa pun untuk staf lain, skrip lain, atau server lain; pertanyaan tentang kondisi menghasilkan perbaikan filter, asosiasi file, dan penghapusan skrip berisi password yang berlaku untuk semua. A keliru karena berhenti di nama orang. C keliru karena memaksa orang membela diri, yang membuat peserta lain berhenti bercerita jujur. Lihat bagian 1.4, 1.5, dan 2.4.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Wahyu Nugroho (Lead Aplikasi Billing), dalam tiga kalimat, kenapa action item "tingkatkan keamanan akun service" ditolak dan diminta ditulis ulang.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Kalimat itu tidak bisa diperiksa: tidak jelas akun mana, apa yang diubah, dan kapan dianggap selesai, jadi tidak akan pernah selesai dan juga tidak pernah gagal. Coba tulis jadi tindakan yang spesifik, misalnya semua akun service Linux yang masih bisa SSH dengan password diubah ke publickey dari sumber tertentu, dengan satu pemilik dan tenggat. Lalu tulis cara membuktikannya, misalnya query login password akun service 30 hari terakhir kosong, supaya orang yang tidak ikut rapat bisa memeriksa."

Kesalahan yang sering muncul:
- Hanya bilang "terlalu umum" tanpa memberi contoh bentuk yang benar.
- Lupa menyebut kriteria selesai, yang justru membuat item bisa dilacak.
- Memberi dua pemilik ("Infrastruktur dan Aplikasi") sehingga tidak ada pemilik sebenarnya.

</details>

**6. Pertanyaan jebakan.** "Insiden `INC-2026-019` belum boleh ditutup karena EDR untuk laptop baru selesai pertengahan Desember." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Di PT JAB, insiden ditutup setelah PIR selesai, laporan final disetujui IC, dan setiap action item sudah menjadi tiket dengan pemilik dan tenggat. Action item jangka panjang dan pemantauan pasca pemulihan dilacak terpisah sampai selesai; menahan insiden terbuka berbulan-bulan membuat status insiden tidak bermakna. Lihat bagian 1.7 dan 2.6.

</details>

**7. Interview question (English).** "How do you run a post-incident review, and how do you make sure it leads to real improvements?"

<details><summary>Sample answer</summary>

"I start before the meeting. The incident owner builds a final timeline where every entry has a time and a source, and calculates metrics like dwell time and time to containment with the start and end points written down, because those numbers will be quoted. The draft goes out at least a day ahead so the meeting is spent on analysis, not reading. A facilitator who wasn't part of the response opens with the ground rules: we look for the conditions that made the incident possible, not for someone to blame, we refer to roles rather than names, and we ask what was visible at the time instead of what someone should have done. We go through contributing factors in groups, direct causes, enabling factors, visibility gaps, and how the response went, including what worked well so we keep doing it. Every improvement leaves the room as a specific action with one owner, a deadline, and a way to prove it's done, or as a documented decision not to do it. Then they become tickets in the owning teams, I send a weekly status with evidence, and overdue items go to the executive sponsor. I keep the internal report separate from regulatory notifications, but make sure the facts in both match."

What makes this answer strong: it covers preparation, a blameless structure with concrete rules, analysis beyond a single root cause, verifiable action items with tracking, and the distinction between internal reporting and regulatory notification.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | NIST SP 800-61 Rev. 3 (PDF) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf | primer | April 2025; diakses 2026-10-15 | Tinggi. Pelajaran dibagikan segera, ID.IM-01 sampai ID.IM-03, RS.AN-03 (akar masalah sistemik), RC.RP-06 (after-action report) |
| S2 | NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide (PDF) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf | primer | Agustus 2012 (lebih dari 3 tahun, digantikan Rev. 3); diakses 2026-10-15 | Tinggi untuk bagian 3.4: pertanyaan lessons learned, aturan rapat, laporan tindak lanjut, metrik waktu per insiden, data yang bisa ditindaklanjuti |
| S3 | CISA: Cybersecurity Incident and Vulnerability Response Playbooks (PDF) | https://www.cisa.gov/sites/default/files/publications/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf | primer | November 2021; diakses 2026-10-15 | Tinggi. Post-incident activities, hotwash, laporan pasca-insiden, deteksi untuk TTP yang berhasil |
| S4 | Google SRE Book, bab 15: Postmortem Culture, Learning from Failure | https://sre.google/sre-book/postmortem-culture/ | sekunder | 2016; diakses 2026-10-15 | Tinggi untuk praktik operasi. Definisi postmortem, blameless, review dan berbagi |
| S5 | PagerDuty Postmortem Documentation: The Blameless Postmortem | https://postmortems.pagerduty.com/culture/blameless/ | sekunder (vendor) | diakses 2026-10-15 | Sedang sampai tinggi. Bagaimana bukan siapa, pertanyaan apa dan bagaimana, bias, mencatat yang berjalan baik |
| S6 | PagerDuty Postmortem Documentation: How to Write a Postmortem, Step by Step | https://postmortems.pagerduty.com/how_to_write/writing/ | sekunder (vendor) | diakses 2026-10-15 | Sedang sampai tinggi. Pemilik postmortem, faktor penyebab, format action item, keputusan tidak bertindak, tenggat rapat |
| S7 | PagerDuty Postmortem Documentation: Postmortem Meeting | https://postmortems.pagerduty.com/meeting/ | sekunder (vendor) | diakses 2026-10-15 | Sedang sampai tinggi. Draft 24 jam sebelumnya, peserta, fasilitator netral, agenda bertimebox |
| S8 | John Allspaw: The Infinite Hows (or, the Dangers of the Five Whys) | https://www.kitchensoap.com/2014/11/14/the-infinite-hows-or-the-dangers-of-the-five-whys/ | komunitas | 2014-11-14; diakses 2026-10-15 | Sedang. Kritik lima kali kenapa dan pertanyaan bagaimana; konsisten dengan arah faktor penyebab di [S6] |

**Catatan sumber:** pembagian dua dokumen di bagian 1.1, tiga aturan metrik di bagian 1.3, empat kelompok faktor penyebab di bagian 1.4, tabel aturan PIR di bagian 1.5, dan aturan penutupan insiden di bagian 1.7 adalah susunan catatan ini dari sumber yang disebut, bukan daftar resmi. Kritik terhadap lima kali kenapa berasal dari praktisi [S8] dan sejalan dengan panduan vendor [S6], tetapi tidak dari sumber primer. Pertimbangan agar pimpinan hadir hanya di bagian akhir PIR adalah pilihan PT JAB. Semua isi PT JAB, termasuk durasi gangguan saat cutover, jam kerja, peserta, dan action item, adalah contoh fiktif.
