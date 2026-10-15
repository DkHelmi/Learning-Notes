---
day: 06
title: 'Eradication dan recovery: rebuild atau clean, akar masalah, rotasi kredensial dan krbtgt, validasi, dan akhir recovery'
researched_on: 2026-10-15
versions_checked: 'NIST SP 800-61 Rev. 3 (April 2025); NIST SP 800-61 Rev. 2 (Agustus 2012, digantikan Rev. 3); CISA Cybersecurity Incident and Vulnerability Response Playbooks (November 2021); CISA AA20-245A (1 September 2020, revisi 24 September 2020); CISA Eviction Strategies Tool, countermeasure CM0027 dan CM0050 (Maret 2025); Microsoft Learn, AD Forest Recovery: Reset the krbtgt password (ms.date 2025-05-21); NCSC UK, Recovering from a highly disruptive cyber attack, Section 2 (terbit 28 Juli 2026, direview 1 Oktober 2026)'
---

# Day 06: Eradication dan recovery (rebuild atau clean, akar masalah, rotasi kredensial dan krbtgt, validasi, dan akhir recovery)

Cakupan: kapan eradication boleh dimulai, memilih antara membersihkan host di tempat dan membangun ulang, menemukan dan menutup akar masalah, menentukan kredensial dan rahasia mana yang harus dirotasi termasuk kapan dan bagaimana mereset krbtgt, memulihkan layanan dari sumber yang tepercaya dengan urutan yang benar, memvalidasi sebelum kembali ke produksi, memantau sesudahnya, dan menyatakan recovery selesai berdasarkan kriteria.

## Ide inti

Containment menahan penyerang di tempat; eradication mengeluarkannya, dan recovery mengembalikan layanan tanpa membawa penyerang ikut kembali. Kesalahan paling mahal di tahap ini bukan teknis, tetapi asumsi: menganggap yang sudah ditemukan adalah semua yang ditinggalkan penyerang. Karena itu eradication yang baik berisi tiga pekerjaan yang dijalankan bersama. Pertama, mengganti sistem yang tidak bisa dipercaya dengan sistem dari sumber yang diketahui bersih, bukan menghapus file yang kebetulan ditemukan. Kedua, menutup jalan masuknya, karena sistem yang dibangun ulang dengan celah yang sama akan dikompromikan lagi. Ketiga, mengganti setiap rahasia yang pernah terlihat oleh penyerang, termasuk rahasia yang baru dipasang saat containment. Recovery lalu baru dianggap selesai bila hasilnya divalidasi, dipantau, dan memenuhi kriteria tertulis, bukan saat layanan sudah menyala.

Kamu sudah mengenal pola ini dari NOC. Bayangkan router agregasi yang konfigurasinya diubah orang memakai akun TACACS yang bocor. Engineer yang berpengalaman tidak menghapus baris konfigurasi yang aneh lalu menganggap selesai, karena ia tidak tahu apa lagi yang diubah. Ia memuat ulang konfigurasi dari template standar, mengganti semua kunci yang pernah tersimpan di router itu (TACACS, SNMP community, kunci BGP), menutup cara akun itu bocor, menguji layanan sebelum trafik dikembalikan, lalu memantau ketat beberapa hari. IR memakai pola yang sama dengan satu perbedaan: penyerang di host bisa meninggalkan lebih banyak hal di luar yang terlihat, dan ia punya alasan untuk mencoba kembali.

```
containment berhasil (Day 05 bagian 1.7)
  |
  v
eradication   rebuild/reimage aset yang tak bisa dipercaya
              + tutup akar masalah dan jalan masuk
              + rotasi semua rahasia yang pernah terpapar
  |
  v
recovery      pulihkan dari sumber tepercaya, urut prioritas layanan
  |
  v
validasi sebelum produksi  -- gagal atau ada tanda baru --> kembali ke scoping
  |                                                         dan containment
  v
cutover dan pemantauan ketat
  |
  v
recovery dinyatakan selesai (kriteria) --> post-incident review
```

Situasi yang dipakai sepanjang Day ini melanjutkan `INC-2026-019` di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif. Ringkasnya: lampiran email dijalankan di laptop `JKT-WS-0388` (`andi.pratama`), `BDG-WS-0142` (`dewi.anggraini`), dan `JKT-WS-0412` (`rizky.saputra`). Password akun service `svc_billing` dibaca dari skrip `export-tagihan.ps1` di laptop Andi dan dipakai untuk SSH ke server billing `jkt-billing01`, tempat proses penyerang `kworkerd` beacon ke `cdn-sync.example.net` (`203.0.113.77`) dan terhubung ke database pelanggan `jkt-billingdb01`. Containment serentak dijalankan Selasa 2026-10-13 pukul 16:00, `jkt-billing01` tetap melayani pembayaran dengan containment parsial maksimal 72 jam sampai dibangun ulang, dan kriteria 24 jam tanpa tanda baru dihitung dari 17:20 setelah laptop ketiga ditemukan. Rabu 2026-10-14 pukul 10:00, retainer PT Forensik Digital Contoh mengirim hasil awal analisis memori. Pukul 11:15, Direktur Teknologi Hendra Wijaya menulis di kanal `#inc-2026-019`:

> "Dim, laporan retainer sudah saya baca. Wahyu bilang server billing cukup dibersihkan: file penyerang dan cron-nya dihapus, beres hari ini, tidak perlu bangun ulang. Laptop tiga orang itu juga cukup di-scan antivirus, kan? Kapan sebenarnya kita boleh mulai bersih-bersih? Bagaimana kita yakin penyerang tidak masuk lagi lewat jalan yang sama? Tim Infrastruktur tanya apakah semua password harus diganti, termasuk 'krbtgt' seperti di berita. Kapan portal pembayaran normal lagi tanpa pembatasan, dan bagaimana kita tahu server barunya bersih? Lalu kapan insiden ini boleh ditutup?"

Pesan itu memuat tujuh pertanyaan:

1. Kapan eradication boleh dimulai?
2. Cukup dibersihkan, atau harus dibangun ulang?
3. Bagaimana mencegah penyerang masuk lagi lewat jalan yang sama?
4. Kredensial apa saja yang harus diganti, dan perlukah krbtgt direset?
5. Bagaimana memulihkan layanan, dan dari mana?
6. Bagaimana tahu sistem yang dipulihkan bersih, sebelum dan sesudah kembali ke produksi?
7. Kapan recovery selesai dan insiden boleh pindah ke tahap berikutnya?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, pertanyaan 6 di bagian 1.6, dan pertanyaan 7 di bagian 1.7. Bagian 2 berisi laporan awal retainer, rencana eradication dan recovery, pencarian salinan kredensial, gerbang validasi, dan pernyataan akhir recovery PT JAB.

**Kapan relevan:** setelah containment dinyatakan berhasil dan sebelum layanan dikembalikan ke kondisi normal; juga saat menyiapkan gold image, prosedur rebuild, inventaris rahasia per sistem, dan kriteria akhir recovery sebelum insiden terjadi.
**Kapan bukan jawaban:** eradication dan recovery tidak menjawab kewajiban atas data yang sudah diambil penyerang; pemberitahuan ke regulator dan subjek data dibahas di Day 18. Tahap ini juga bukan lessons learned: perbaikan proses jangka panjang dan laporan insiden dibahas di Day 19, walaupun bahannya dikumpulkan sejak sekarang.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (containment, eradication, recovery, severity, IC, executive sponsor, scoping, scope statement, bukti, jam H, kriteria selesai containment) tidak diulang. Tabel berikut memuat istilah baru Day ini. Kolom padanan memakai analogi NOC dan SOC yang sama di semua Day IR.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Clean (remediasi di tempat) | Menghapus artefak penyerang yang diketahui dari host yang tetap dipakai | Menghapus baris konfigurasi aneh dari router yang disusupi |
| Rebuild dan reimage | Membangun ulang host dari sumber bersih; reimage memakai image standar, rebuild bisa dari nol | Memuat ulang konfigurasi router dari template standar, atau mengganti unitnya |
| Gold image | Image sistem operasi standar yang sudah diverifikasi integritasnya | Template konfigurasi standar perangkat |
| Akar masalah (root cause) | Kondisi yang memungkinkan insiden terjadi, termasuk celah teknis dan proses | Konektor yang kendur di balik link yang terus putus |
| Rotasi rahasia | Mengganti password, kunci, token, dan sertifikat yang mungkin diketahui penyerang | Mengganti kunci TACACS, SNMP community, dan kunci BGP setelah kebocoran |
| krbtgt | Akun AD yang kuncinya dipakai mengenkripsi dan menandatangani tiket Kerberos | Kunci master yang menandatangani semua kartu akses gedung |
| Golden ticket | Tiket Kerberos palsu yang dibuat penyerang yang memegang kunci krbtgt | Kartu akses palsu yang dicetak dengan kunci master curian |
| Integritas sumber pemulihan | Kepastian bahwa backup, image, dan paket yang dipakai memulihkan tidak ikut terkompromi | Memastikan backup konfigurasi diambil sebelum perubahan liar |
| Minimum viable operations (MVO) | Tingkat operasi terendah yang tetap aman, memenuhi kewajiban, dan menjaga kepercayaan | Layanan prioritas yang dipulihkan duluan saat gangguan besar |
| Cutover | Pemindahan layanan dari sistem lama ke sistem pengganti pada waktu yang direncanakan | Cutover link atau perangkat di maintenance window |
| Gerbang validasi | Daftar cek yang wajib lulus sebelum sistem masuk produksi | Uji layanan sebelum tiket gangguan ditutup |
| Pemantauan pasca pemulihan | Pemantauan ketat dengan detection tambahan selama periode tertentu setelah pemulihan | Masa pantau ketat setelah gangguan besar dipulihkan |
| After-action report | Laporan yang mendokumentasikan insiden, tindakan respons dan recovery, serta pelajarannya | RFO setelah gangguan besar |

### 1.1 Kapan eradication dimulai: setelah containment terbukti, bukan setelah containment dijalankan

Hendra bertanya "kapan boleh mulai bersih-bersih?". Jawabannya bergantung pada apa yang sudah terbukti, bukan pada berapa lama insiden sudah berjalan.

Playbook CISA meminta tiga hal dipastikan sebelum masuk eradication: semua cara akses persisten penyerang sudah diperhitungkan, aktivitas penyerang sudah cukup tertahan, dan semua bukti sudah dikumpulkan. Playbook itu juga menyebut prosesnya sering berulang, eradication dan recovery bisa berjalan bersamaan, dan koordinasi dengan penyedia layanan, vendor, dan penegak hukum dilakukan sebelum eradication dimulai [S3]. NIST SP 800-61 Rev. 3 menjelaskan eradication sebagai menghilangkan mekanisme persistence dan jalan masuk, misalnya menghapus malware, menonaktifkan akun yang dibobol, serta menemukan dan memitigasi semua kerentanan yang dieksploitasi, dan meminta semua host dan layanan terdampak diidentifikasi supaya semua kelemahan bisa diperbaiki (RS.MI-02) [S1]. Rev. 2 menambahkan bahwa untuk sebagian insiden eradication tidak diperlukan atau dikerjakan sekaligus saat recovery [S2].

Dua peringatan datang dari sisi sebaliknya. AA20-245A menyebut memitigasi sistem sebelum responder sempat melindungi dan memulihkan data sebagai kesalahan umum, karena data volatil hilang dan penyerang bisa mengubah taktik [S4]. NCSC UK menyebut memulihkan sebelum penyerang dipastikan sudah keluar membawa risiko insiden dimulai lagi [S8].

Untuk `INC-2026-019`, syarat masuk eradication adalah kriteria selesai containment yang ditulis di Day 05: semua tindakan jam H terverifikasi, 24 jam tanpa koneksi baru ke C2 atau sinkhole dari host yang belum dijelaskan, tidak ada login dari akun yang ditahan, tidak ada tanda reaksi penyerang, dan scope statement disetujui IC. Hitungannya mulai Selasa 17:20, sehingga paling cepat terpenuhi Rabu 17:20. Yang boleh dikerjakan sebelum itu adalah persiapan yang tidak menyentuh aset dalam scope: memeriksa gold image, menyiapkan laptop cadangan, menulis rencana. Pembedaan ini sama dengan menunda untuk bersiap di Day 05 bagian 1.3.

### 1.2 Clean atau rebuild: yang menentukan adalah apa yang tidak kamu ketahui

Pertanyaan kedua Hendra adalah perdebatan klasik antara pemilik sistem dan responder. Usul Wahyu Nugroho (Lead Aplikasi Billing) masuk akal dari sisi layanan: file dan cron penyerang sudah diketahui, menghapusnya cepat, dan server tidak perlu berhenti.

Masalahnya, clean hanya menghapus apa yang ditemukan. Playbook CISA menyebut penyerang sering punya beberapa akses persisten dan bisa kembali ke area yang sudah "bersih" bila eradication tidak diorkestrasi dengan baik atau tidak cukup ketat, dan meminta waktu yang cukup untuk memastikan semua sistem bebas dari mekanisme persistence karena penyerang sering memakai lebih dari satu [S3]. Daftar aktivitas eradication di playbook itu menyebut reimage dari sumber "gold", membangun ulang dari nol, membangun ulang hardware bila melibatkan rootkit, mengganti file terkompromi dengan versi bersih, memasang patch, dan mereset password akun terkompromi [S3]. Rev. 3 menambahkan bahwa pada penyerang yang sangat canggih dan cakupan taktiknya tidak terungkap penuh, organisasi bisa perlu mengganti hardware semua sistem terkompromi [S1]. Countermeasure CISA untuk rebuild menyebut tujuannya mengakhiri persistence, C2, dan eksekusi penyerang di host, dengan risiko kehilangan data sejak backup bersih terakhir dan gangguan bisnis selama downtime [S7].

Dari sumber-sumber itu, PT JAB memakai kriteria berikut. Baca kolom kanan sebagai syarat: clean hanya boleh dipilih bila semua syaratnya terpenuhi.

| Pertanyaan | Mengarah ke rebuild atau reimage bila | Clean masih bisa dipertimbangkan bila |
|---|---|---|
| Hak akses penyerang di host | Penyerang pernah atau mungkin punya hak admin atau root | Penyerang terbukti hanya punya hak pengguna biasa |
| Kelengkapan pengetahuan | Ada aktivitas yang tidak terlihat (tanpa EDR, log terbatas, waktu offline) | Aktivitas tercatat lengkap dari awal sampai containment |
| Jumlah dan jenis persistence | Lebih dari satu mekanisme, atau ada yang ditemukan terlambat | Satu mekanisme sederhana yang dipahami penuh |
| Malware | Implant interaktif, rootkit, atau perilaku yang belum dianalisis | Malware komoditas yang dikenal, diblok, dan dipahami |
| Biaya rebuild | Gold image dan prosedur build siap; layanan bisa dialihkan | Rebuild butuh waktu yang tidak bisa diterima dan tidak ada cara mengalihkan layanan |

Untuk `jkt-billing01`, hampir semua baris mengarah ke rebuild. Server tanpa EDR, penyerang berada di dalamnya sekitar 14 jam sebelum containment, analisis memori menemukan salinan kedua implant yang tidak terlihat saat live response (bagian 2.1), dan kemungkinan eskalasi ke root tidak bisa disingkirkan. Untuk tiga laptop, scan antivirus tidak cukup karena loader berjalan di memori lewat PowerShell, `BDG-WS-0142` dan `JKT-WS-0412` tanpa EDR, dan `JKT-WS-0412` sempat beberapa jam terhubung ke internet di luar kantor tanpa terlihat oleh SOC. Reimage laptop murah karena image standar dan laptop cadangan tersedia.

Rebuild tidak harus berarti downtime panjang. Server pengganti bisa dibangun berdampingan dengan server lama, divalidasi, lalu layanan dipindah dalam satu cutover singkat. Server lama dikeluarkan dari jaringan setelah cutover, dan saat itulah image disk yang ditunda di Day 04 diambil.

### 1.3 Akar masalah: rebuild tanpa menutup jalan masuk mengundang penyerang kembali

Pertanyaan ketiga Hendra ("bagaimana supaya tidak masuk lagi lewat jalan yang sama?") adalah alasan eradication tidak boleh berhenti di host.

Rev. 3 memasukkan jalan masuk dan kerentanan yang dieksploitasi ke dalam definisi eradication (RS.MI-02), dan meminta akar masalah insiden diperbaiki sebelum aset yang dipulihkan dipakai di produksi (RC.RP-05) [S1]. Rev. 2 mengingatkan bahwa sumber daya yang sekali berhasil diserang sering diserang lagi, atau sumber daya lain diserang dengan cara serupa [S2]. Harlan Carvey, praktisi forensik Windows, sudah lama mengkritik kebiasaan langsung menghapus dan memasang ulang sistem tanpa analisis akar masalah: tanpa tahu cara masuknya, sistem yang baru dipasang akan dikompromikan lagi lewat jalan yang sama, dan backup yang dipakai memulihkan bisa ikut membawa malware [S9]. NCSC UK menempatkan perbaikan hal yang ikut menyebabkan insiden sebagai bagian dari tahap membangun kembali yang lebih aman [S8].

Akar masalah jarang tunggal. Untuk menulis perbaikan yang tepat, PT JAB membagi temuan ke tiga kelompok:

- **Penyebab langsung:** tanpanya insiden tidak terjadi. Di `INC-2026-019`: password `svc_billing` tersimpan dalam teks biasa di skrip yang dibagikan ke staf penagihan, dan `svc_billing` boleh login SSH dengan password dari jaringan workstation.
- **Faktor yang memungkinkan:** membuat serangan lebih mudah. Lampiran `.js` di dalam `.zip` lolos filter email, dan file `.js` dijalankan `wscript.exe` saat diklik dua kali.
- **Celah visibilitas:** tidak menyebabkan insiden, tetapi membuat deteksi terlambat dan scope tidak pasti. Server Linux dan sebagian laptop tanpa EDR; DNS over HTTPS dan resolver luar tidak terlihat.

Penyebab langsung wajib ditutup sebelum sistem pengganti masuk produksi. Faktor yang memungkinkan ditutup secepatnya, idealnya di minggu yang sama. Celah visibilitas boleh masuk fase jangka panjang dengan pemilik dan tanggal. Pembagian fase ini mengikuti saran Rev. 2: fase awal berisi perubahan cepat bernilai tinggi dalam hitungan hari sampai minggu, fase berikutnya berisi perubahan jangka panjang seperti perubahan infrastruktur [S2].

Satu hal yang sering terlewat: akar masalah yang berbentuk rahasia harus dicari di semua tempat rahasia itu disalin. Skrip `export-tagihan.ps1` tidak hanya ada di laptop Andi. Pencarian di bagian 2.3 menemukan salinannya di laptop staf penagihan lain dan di share tim penagihan, sehingga menghapus file dari satu laptop tidak menutup apa-apa.

### 1.4 Rotasi kredensial: setiap rahasia yang pernah terlihat penyerang, termasuk krbtgt bila domain dikuasai

Pertanyaan keempat Hendra ("apakah semua password harus diganti?") dijawab dengan pertanyaan balik: rahasia apa saja yang pernah bisa dilihat penyerang? Jawabannya menentukan cakupan rotasi, bukan berita tentang insiden lain.

Playbook CISA menempatkan reset password akun terkompromi di eradication maupun recovery, ditambah MFA untuk semua metode akses [S3]. AA20-245A menyarankan reset password dipaksakan dan sertifikat dicabut lalu diterbitkan ulang untuk akun dan perangkat terdampak, password akun service dirotasi tanpa mengganggu layanan, dan aktivitas akun service dipantau terus [S4]. NCSC UK meminta kepercayaan terhadap sumber identitas dibangun ulang lebih dulu untuk mendukung recovery, dan kredensial direset bila perlu, termasuk akun berhak tinggi [S8].

Cara praktis menentukan cakupannya adalah membuat inventaris per host terkompromi: rahasia apa yang tersimpan di host itu, rahasia apa yang diketik di host itu selama penyerang ada, dan rahasia apa yang dipasang di host itu setelah kompromi. Kategori ketiga sering terlupa. Kredensial database `billing_app` sudah dirotasi di jam H, tetapi nilai barunya dipasang di `jkt-billing01` yang masih terkompromi, sehingga nilai itu juga harus dianggap terpapar dan dirotasi lagi saat cutover. Hal yang sama berlaku untuk akun admin responder yang mengetik password di host terkompromi, misalnya untuk `sudo`.

**krbtgt.** Akun `krbtgt` dipakai untuk mengenkripsi dan menandatangani tiket Kerberos [S4][S6]. Penyerang yang mendapatkan kuncinya bisa membuat golden ticket, yaitu tiket palsu yang diterima domain sampai kunci itu diganti; countermeasure CISA CM0050 ditujukan untuk mengakhiri akses semacam itu [S6]. Hal yang perlu diketahui sebelum mereset:

- **Harus dua kali.** Riwayat password krbtgt berisi dua password terakhir, sehingga satu kali reset masih menyisakan password lama yang bisa dipakai [S4][S5][S6].
- **Jeda di antara reset.** AA20-245A meminta reset pertama direplikasi dulu sebelum reset kedua [S4]. Panduan pemulihan forest AD dari Microsoft meminta jeda 10 jam, sesuai nilai default Maximum lifetime for user ticket dan Maximum lifetime for service ticket, dan lebih lama bila nilai itu diubah [S5]. CM0050 menggabungkan keduanya: cek kesehatan replikasi AD dulu, biarkan reset pertama tereplikasi penuh, dan tunggu minimal 10 jam [S6].
- **Dampak.** Reset krbtgt membatalkan tiket untuk semua aplikasi yang bergantung pada AD, klien non-Windows bisa gagal meminta tiket baru sampai tiket lamanya kedaluwarsa, dan krbtgt yang belum pernah dirotasi bisa memicu masalah replikasi karena cipher lama [S6].
- **Cakupan akun.** Prosedur Microsoft berlaku untuk DC writable; akun krbtgt milik RODC berformat `krbtgt_<angka>` dan ditangani terpisah [S5][S6]. Password filter kustom di DC bisa membuat reset gagal [S5].
- **Bila `ntds.dit` mungkin dicuri,** AA20-245A menyarankan semua password pengguna domain direset, dan bila penyerang mungkin mencapai DC, akun lokal di sana juga direset [S4].

Ada praktik yang beredar di forum untuk keadaan kompromi: mereset dua kali berturut-turut tanpa menunggu replikasi supaya semua tiket langsung gugur, dengan harga gangguan autentikasi yang lebih luas [S10]. [komunitas, belum terkonfirmasi] Cara ini tidak tertulis di panduan Microsoft maupun CISA yang dibaca untuk catatan ini, jadi bila dipertimbangkan, putuskan bersama tim AD dan uji dampaknya dulu.

**Keputusan untuk `INC-2026-019`.** Reset krbtgt tidak dimasukkan ke rencana, dengan alasan tertulis: akun yang dikuasai penyerang adalah dua akun pengguna biasa, satu akun lokal Linux (`svc_billing`), dan kredensial database; tidak ada bukti akses ke akun `adm.*`, domain admin, atau DC; analisis memori laptop tidak menemukan akses ke proses LSASS; dan pencarian aktivitas replikasi direktori dari host non-DC tidak menemukan apa pun (cara deteksinya dibahas di Day 12). Keputusan ini berubah bila salah satu ditemukan: akun berhak tinggi dipakai dari host dalam scope, tanda pencurian kredensial dari memori di host tempat admin pernah login, aktivitas replikasi direktori dari non-DC, atau tiket Kerberos dengan masa berlaku tidak wajar. Bila itu terjadi, krbtgt direset dua kali dengan prosedur di atas, dalam jendela yang disepakati dengan pemilik aplikasi yang bergantung pada AD.

### 1.5 Recovery: pulihkan dari sumber yang tepercaya, dengan urutan prioritas layanan

Pertanyaan kelima Hendra ("kapan portal normal lagi?") menyangkut dua hal: dari mana sistem dipulihkan, dan layanan mana yang dipulihkan lebih dulu.

**Sumber pemulihan.** Rev. 3 menyebut cara recovery meliputi restore dari backup bersih, membangun ulang sistem, mengganti file terkompromi dengan versi bersih, memasang patch, mengganti password, dan memperketat kontrol [S1]. Integritas backup dan aset pemulihan lain harus diverifikasi sebelum dipakai, termasuk dicek terhadap indikator kompromi dan kerusakan file (RC.RP-03) [S1]. Countermeasure rebuild CISA menambahkan langkahnya: verifikasi integritas image dan software bersih, hapus host terdampak dengan aman, pasang ulang dari salinan yang terverifikasi, lalu pasang patch; data yang diselamatkan dari host terdampak diperlakukan sangat hati-hati karena bisa membawa persistence [S7]. NCSC UK meminta organisasi menganggap backup mungkin sudah menjadi sasaran penyerang [S8].

Untuk `jkt-billing01`, ini berarti server pengganti tidak dipulihkan dari backup server lama. Sistem operasi berasal dari gold image yang hash-nya dicek, aplikasi dari rilis di repositori kode, konfigurasi dari configuration management dengan rahasia baru, dan data pelanggan tetap di `jkt-billingdb01`. Hanya file laporan ekspor yang diambil dari backup, dari backup Senin malam yang dibuat sebelum login penyerang Selasa 02:14, dan tetap dipindai sebelum dipakai. Rev. 3 juga meminta recovery mempertimbangkan ketepatan, misalnya hanya memulihkan file yang terdampak, bukan semua file (RC.RP-02) [S1].

**Urutan prioritas.** NCSC UK memperkenalkan minimum viable operations (MVO): tingkat kemampuan operasional terendah tempat organisasi masih bisa beroperasi dengan aman, memenuhi kewajiban hukum dan regulasi, dan menjaga kepercayaan pelanggan, mitra, dan staf. Program recovery bertujuan mencapai MVO secepat dan seaman mungkin, dan NCSC mengingatkan untuk menyeimbangkan kecepatan pemulihan dengan tingkat keyakinan yang dibutuhkan [S8]. Rev. 3 meminta layanan penting dipulihkan dalam urutan yang tepat, bersama pemilik sistem yang mengonfirmasi pemulihan berhasil (RC.RP-04) [S1].

Untuk PT JAB, MVO layanan billing adalah pelanggan bisa membayar tagihan secara online dan tagihan bulanan terbit tepat waktu. Ekspor laporan untuk staf penagihan boleh menyusul, sementara memakai ekspor dari job terjadwal di server `10.20.1.15`. Urutan ini menentukan apa yang divalidasi lebih dulu dan apa yang boleh ditunda.

### 1.6 Validasi sebelum produksi dan pemantauan sesudahnya

Pertanyaan keenam Hendra ("bagaimana tahu server barunya bersih?") punya dua waktu: sebelum layanan dipindah, dan sesudahnya.

**Sebelum produksi.** Rev. 3 meminta aset yang dipulihkan dicek terhadap indikator kompromi, akar masalah diperbaiki sebelum dipakai di produksi, dan kebenaran serta kecukupan tindakan pemulihan diverifikasi sebelum sistem dihubungkan (RC.RP-05) [S1]. Playbook CISA meminta sistem diuji menyeluruh, termasuk penilaian kontrol keamanan, sebelum kembali ke jaringan produksi, dan mempertimbangkan meniru teknik penyerang untuk memastikan penangkalnya efektif [S3]. NCSC UK meminta bukti bahwa kompromi sudah diperbaiki sebelum konektivitas dipulihkan [S8].

PT JAB menyusunnya menjadi gerbang validasi: daftar cek yang semuanya harus lulus, dengan bukti, sebelum cutover. Gerbang yang baik memuat tiga jenis cek: tidak ada jejak penyerang (IOC dan artefak dari insiden), akar masalah sudah tertutup (dicoba, bukan hanya dikonfigurasi), dan kontrol keamanan serta fungsi layanan berjalan. Contoh "dicoba": login SSH `svc_billing` dengan password dari jaringan workstation harus ditolak, dan koneksi keluar ke tujuan di luar allowlist harus diblok dan tercatat. Ini bentuk sederhana dari meniru teknik penyerang yang disarankan CISA. Gerbang lengkapnya ada di bagian 2.4.

**Sesudah produksi.** Playbook CISA meminta deteksi dan analisis dilanjutkan setelah eradication untuk mencari tanda penyerang kembali atau memakai cara akses baru; bila ditemukan, aktivitas itu ditahan dan tim kembali ke analisis teknis sampai cakupan sebenarnya diketahui [S3]. Recovery juga butuh kewaspadaan dan kontrol yang ditingkatkan untuk memastikan tidak ada tanda aktivitas penyerang [S3]. Rev. 2 menyebut logging dan pemantauan jaringan yang lebih tinggi sering menjadi bagian recovery [S2], dan AA20-245A menyarankan pemantauan terus-menerus atas aktivitas akun service serta alert untuk eskalasi hak dan perubahan peran [S4]. Rev. 3 meminta kinerja sistem yang dipulihkan dipantau untuk memastikan pemulihan memadai (RC.RP-04) [S1].

PT JAB menetapkan pemantauan pasca pemulihan selama 30 hari untuk semua aset dalam scope. Detection tambahannya ditulis dari jejak insiden ini: login `svc_billing` dari mana pun selain `10.20.1.15`, koneksi keluar server billing ke tujuan di luar allowlist, cron atau unit systemd baru di server billing, query ke tabel pelanggan di log database di luar pola aplikasi, dan resolusi domain yang belum pernah terlihat dari server billing. Setiap alert dari detection ini ditelusuri sampai jelas, termasuk yang ternyata konfigurasi biasa, karena hanya dengan cara itu "tidak ada tanda penyerang" punya arti.

### 1.7 Menyatakan recovery selesai: berdasarkan kriteria, lalu pindah ke post-incident

Pertanyaan terakhir Hendra ("kapan insiden boleh ditutup?") mirip dengan pertanyaan kapan containment berhasil di Day 05: jawabannya kriteria tertulis, bukan perasaan bahwa semuanya sudah normal.

Rev. 3 menempatkan akhir recovery sebagai keputusan yang dinyatakan berdasarkan kriteria, diikuti penyelesaian dokumentasi, dan menyarankan after-action report yang mendokumentasikan insiden, tindakan respons dan recovery, serta pelajarannya (RC.RP-06) [S1]. Rev. 3 juga meminta pimpinan diberi update rutin tentang status dan kemajuan recovery untuk insiden besar (RC.CO-03) [S1]. Playbook CISA meminta perubahan yang dibuat selama insiden dikembalikan, timeline diperbarui dengan semua kejadian penting dari tahap recovery, dan semua tindakan recovery diselesaikan [S3]. NCSC UK membedakan recovery ke MVO dari tahap membangun kembali organisasi menuju operasi normal yang lebih kuat, yang berjalan lebih lama [S8].

PT JAB menulis kriteria akhir recovery sebagai berikut:

1. Semua aset dalam scope sudah dibangun ulang atau di-reimage, divalidasi lewat gerbang, dan dikonfirmasi pemiliknya.
2. Aset lama sudah keluar dari jaringan, image disk-nya diambil, dan chain of custody-nya lengkap.
3. Semua rahasia di inventaris rotasi sudah diganti dan nilai lamanya terbukti ditolak.
4. Penyebab langsung sudah ditutup dan dicoba; faktor lain punya pemilik dan tanggal.
5. Minimal 7 hari setelah cutover tanpa tanda penyerang, dengan setiap alert detection tambahan sudah dijelaskan.
6. Perubahan sementara dari containment sudah diputuskan: dicabut, atau dijadikan permanen lewat change management.

Setelah kriteria terpenuhi, IC menyatakan recovery selesai, insiden pindah ke post-incident review, dan pemantauan pasca pemulihan tetap berjalan sampai 30 hari. Insiden baru ditutup setelah post-incident review dan tindak lanjutnya tercatat, sesuai RACI PT JAB (Day 02 bagian 2.2) yang menempatkan A untuk menutup insiden di IC. Bila tanda baru muncul di tengah jalan, insiden kembali ke scoping dan containment, sama seperti di Day 05.

## 2. Contoh artefak dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Query Splunk memakai index PT JAB dengan field mengikuti CIM untuk firewall (`src_ip`, `dest_ip`, `dest_port`, `action`) dan field event PowerShell dari add-on Windows (`ScriptBlockText`, `Path`); cocokkan dengan add-on yang kamu pakai.

### 2.1 Hasil awal analisis memori retainer

Laporan ini adalah dasar pertanyaan Hendra pukul 11:15. Perhatikan temuan nomor 2, karena itulah yang membuat clean tidak cukup, dan bagian kesimpulan yang memisahkan tingkat keyakinan.

```
PT Forensik Digital Contoh | INC-2026-019 | Hasil awal analisis memori
Rabu 2026-10-14 10:00 WIB | Untuk: Dimas Prasetyo (IC), Sari Kusuma (TL)
Item: E05 (memori jkt-billing01), E06 (biner kworkerd), E01 (memori JKT-WS-0388),
      salinan E08 di jkt-evid01 (memori BDG-WS-0142), E13 (memori JKT-WS-0412)

TEMUAN
1. kworkerd (E06): implant Linux, berjalan sebagai svc_billing. Konfigurasi C2
   tunggal cdn-sync.example.net, cadangan IP 203.0.113.77, interval 60 detik.
   Tidak ditemukan alamat C2 lain di konfigurasi maupun memori proses.
2. Riwayat perintah implant di memori proses (E05):
   Selasa 02:31  salinan kedua biner ditulis ke /var/tmp/.font-unix/kworkerd
                 (tidak berjalan, tidak ditemukan pemicu yang menjalankannya)
   Selasa 02:44  membaca /opt/billing/conf/app.env (berisi kredensial billing_app)
   Selasa 03:02  psql ke jkt-billingdb01: daftar tabel
   Selasa 03:06  SELECT nama, nik, alamat, telepon FROM pelanggan LIMIT 5000
   Selasa 03:10  hasil dikompres ke /dev/shm/.cache/p.gz (sekitar 1,4 MB)
   Selasa 03:12  p.gz dihapus; waktu cocok dengan kenaikan trafik ke 203.0.113.77
   Selasa 03:15  sesi psql kedua dibuka dan dibiarkan terbuka; tidak ada query
                 yang terlihat di memori untuk sesi ini
3. Tidak terlihat eskalasi ke root: tidak ada proses root turunan implant, tidak ada
   perubahan sudoers. Aturan sudo svc_billing hanya untuk restart layanan billing.
   Analisis memori tidak bisa menyingkirkan eskalasi yang tidak meninggalkan jejak.
4. JKT-WS-0388 (E01): loader upd.ps1 menjalankan pencarian file di Documents dan
   Desktop dengan kata kunci password, svc, ssh. Tidak terlihat akses ke proses
   LSASS atau ke penyimpanan kredensial browser.
5. BDG-WS-0142 (salinan E08) dan JKT-WS-0412 (E13): loader yang sama, hanya beacon
   dan enumerasi sistem dasar. Aktivitas JKT-WS-0412 saat di luar kantor tidak
   terlihat di memori maupun log.

KESIMPULAN SEMENTARA
- 5.000 baris data pelanggan (nama, NIK, alamat, telepon) kemungkinan besar
  diambil. Keyakinan: SEDANG-TINGGI (perintah terlihat; isi trafik terenkripsi).
- Tidak ada bukti kompromi akun domain berhak tinggi atau DC. Keyakinan: SEDANG.
REKOMENDASI: rebuild jkt-billing01; reimage tiga laptop; rotasi semua rahasia di
jkt-billing01 termasuk yang dipasang setelah kompromi; cari salinan lain
kredensial svc_billing. Laporan lengkap: Jumat 2026-10-16.
```

Cara membaca elemennya:

- **Salinan kedua di `/var/tmp`** tidak terlihat di live response Day 04 karena perintahnya memeriksa `/dev/shm`, `/tmp`, dan `/var/tmp` di tingkat atas, sedangkan salinan ini ada di dalam subfolder tersembunyi yang namanya mirip folder sistem. Ini contoh nyata kenapa clean hanya menghapus apa yang ditemukan.
- **Keyakinan ditulis per kesimpulan.** "Kemungkinan besar diambil" dan "tidak ada bukti kompromi domain" punya dasar dan batas yang berbeda, dan keduanya dipakai untuk keputusan yang berbeda: yang pertama oleh DPO untuk pelaporan, yang kedua untuk keputusan krbtgt.
- **Kesimpulan tentang data** langsung diteruskan Dimas ke DPO Agus Setiawan dan Legal Ratna Sari pukul 10:20. Kewajiban pelaporannya dibahas di Day 18; eradication tidak menunggu keputusan itu.

**Kapan gagal:** laporan retainer hanya berisi daftar IOC tanpa riwayat perintah dan tingkat keyakinan. Tim bisa menghapus IOC, tetapi tidak tahu apa yang diambil dan apa lagi yang mungkin ditinggalkan.

### 2.2 Rencana eradication dan recovery

Rencana ini menjawab pertanyaan 1, 2, 4, dan 5 Hendra, disusun Sari dan Dimas Rabu siang, dan dijalankan setelah Dimas menyatakan containment berhasil pukul 17:20. Pada saat yang sama Dimas menurunkan severity ke SEV-2 dengan alasan tertulis: akses penyerang yang diketahui sudah tertutup dan terverifikasi selama 24 jam, tidak ada kerusakan yang berjalan, dan dampak data yang tersisa ditangani jalur pelaporan DPO. Satu kejadian selama periode 24 jam, alert `SOC-2026-0204` Rabu 08:35 (login password `svc_billing` ditolak dari `10.10.23.41`), ditelusuri dan dijelaskan di bagian 2.3. Kolom R dan A mengikuti RACI PT JAB (Day 02 bagian 2.2).

| Waktu | Aset | Tindakan | R | A | Verifikasi |
|---|---|---|---|---|---|
| Rabu 13:00 | Laptop pengguna | Laptop cadangan untuk Andi, Rizky (Jakarta) dan Dewi (Bandung, oleh Fajar Nugraha); akun diaktifkan kembali dengan password baru dan MFA didaftarkan ulang | Infrastruktur | IC | Metode MFA lama dihapus; login dari laptop cadangan saja |
| Rabu 18:00 sampai Kamis 12:00 | `jkt-billing02` (`10.20.5.22`), pengganti `jkt-billing01` | Build dari gold image `JAB-LNX-GOLD-2026.09` (hash dicek), patch, aplikasi dari tag rilis di repositori, konfigurasi dari configuration management, Defender for Endpoint untuk Linux, auditd dan forwarder Splunk | Infrastruktur, Tim Aplikasi Billing | IC | Gerbang validasi bagian 2.4 |
| Kamis 09:00 | `JKT-WS-0388`, `JKT-WS-0412` | Image disk (E15, E16), lalu reimage dari image standar | Yoga | IC | Hash image tercatat; laptop hasil reimage lolos scan IOC |
| Kamis 10:00 | Rahasia di `jkt-billing01` | Rotasi kunci API payment gateway bersama penyedia gateway; terbitkan sertifikat TLS baru dengan kunci baru, cabut yang lama | Tim Aplikasi Billing | Hendra (pihak ketiga dan layanan) | Kunci lama ditolak gateway; sertifikat lama tercabut |
| Kamis 11:00 | Salinan kredensial | Hapus `export-tagihan.ps1` dari `JKT-WS-0341` dan share tim penagihan; ekspor laporan staf dipindah ke job terjadwal `10.20.1.15` | Tim Aplikasi Billing | IC | Pencarian ulang bagian 2.3 kosong |
| Kamis 12:00 | Akun responder | Rotasi password `adm.yoga` dan semua akun admin yang pernah mengetik password di `jkt-billing01` | Infrastruktur | IC | `PasswordLastSet` baru |
| Kamis 14:00 sampai 18:00 | `jkt-billing02` | Gerbang validasi dan uji fungsi oleh pemilik aplikasi | Sari, Wahyu | IC | Semua gerbang lulus dengan bukti |
| Kamis 23:00 | Layanan billing | Cutover ke `jkt-billing02`; rotasi ketiga `billing_app`; egress allowlist untuk `10.20.5.22`; `jkt-billing01` diputus dari jaringan lalu dimatikan | NOC, Tim Aplikasi Billing | Hendra (layanan pelanggan) | Pembayaran uji berhasil; login `billing_app` dengan nilai lama ditolak database |
| Jumat 00:30 | `jkt-billing01` | Image disk penuh (E17) oleh retainer, chain of custody | Retainer, Yoga | IC | Hash tercatat di evidence log |
| Jumat | Filter email dan endpoint | Blok `.js` dan skrip sejenis di lampiran termasuk di dalam arsip; asosiasi `.js` diubah agar tidak dijalankan `wscript.exe` | Infrastruktur | IC | Uji kirim lampiran `.js` di dalam `.zip` dari luar ditolak |
| Jumat | `BDG-WS-0142` | Laptop lama disegel dan dikirim ke Jakarta (resi `INT-1016-023`); image disk (E18) Senin 2026-10-19, lalu reimage | Fajar, Yoga | IC | Formulir chain of custody per perpindahan |

Cara membaca elemennya:

- **`jkt-billing02` dibangun berdampingan.** Pembayaran hanya berhenti selama cutover, bukan selama build. Cutover Kamis 23:00 berada 55 jam setelah jam H, di dalam batas 72 jam yang diputuskan Hendra di Day 05.
- **Rotasi ketiga `billing_app`** menutup nilai yang dipasang di jam H pada server yang masih terkompromi (bagian 1.4).
- **Laptop cadangan sebelum reimage** memisahkan kebutuhan pengguna untuk bekerja dari kebutuhan bukti. Pengguna bekerja lagi Rabu siang, sedangkan image disk diambil tanpa terburu-buru.
- **Tidak ada baris krbtgt.** Alasan dan pemicunya ditulis di catatan keputusan (bagian 1.4), sehingga ketiadaan baris ini adalah keputusan, bukan kelalaian.
- **Delegasi pilihan A di memo Day 05** berakhir saat `jkt-billing01` dimatikan setelah cutover, karena tidak ada lagi server yang perlu dimatikan.

**Kapan gagal:** rencana disusun per tim tanpa satu tabel bersama. Tim Aplikasi Billing merotasi `billing_app` sebelum cutover, server lama masih memegang nilai barunya, dan satu rahasia tetap terpapar tanpa ada yang menyadari.

### 2.3 Mencari semua salinan kredensial `svc_billing`

Langkah ini menjawab pertanyaan ketiga Hendra untuk penyebab langsung: di mana saja password `svc_billing` pernah tersimpan dan dipakai. Pemicunya alert `SOC-2026-0204`: Rabu 08:35 ada percobaan login password `svc_billing` ke `jkt-billing01` dari `10.10.23.41` yang ditolak, setelah login password dimatikan di jam H.

**Tujuan:** menemukan host yang menjalankan skrip berisi `svc_billing`, beserta lokasi skripnya, dalam 30 hari terakhir.

```
index=powershell EventCode=4104 ScriptBlockText="*svc_billing*"
earliest="09/14/2026:00:00:00" latest="10/14/2026:12:00:00"
| stats count min(_time) as first_seen max(_time) as last_seen values(Path) as path by host
| sort first_seen
| convert ctime(first_seen) ctime(last_seen)
```

Penjelasan tiap bagian:

- `EventCode=4104` adalah script block logging PowerShell. Event ini mencatat isi skrip yang dijalankan, sehingga skrip yang berisi nama akun dan password muncul di sini.
- `ScriptBlockText="*svc_billing*"` mencari isi skrip, bukan nama file, sehingga salinan dengan nama berbeda tetap tertangkap.
- `values(Path)` menunjukkan dari mana skrip dijalankan. Field ini kosong bila kode diketik langsung di konsol.
- Rentang waktu absolut mencakup 30 hari sebelum alert, sama dengan jendela scoping di Day 03.

Keluaran ilustrasi:

```
host          count  first_seen            last_seen             path
JKT-WS-0388      22  09/14/2026 08:31:05   10/12/2026 14:02:11   C:\Users\andi.pratama\Documents\export-tagihan.ps1
JKT-WS-0341      20  09/14/2026 08:35:47   10/14/2026 08:34:58   \\JKT-FS01\Penagihan\tools\export-tagihan.ps1
```

Cara membaca hasil:

- `JKT-WS-0388` adalah laptop Andi. Waktu pertama (08:31:05) beberapa detik sebelum login password pertama `svc_billing` dari `10.10.23.88` di data scoping Day 03 (08:31:10), cocok dengan skrip yang menjalankan SSH.
- `JKT-WS-0341` (`10.10.23.41`) adalah laptop staf penagihan Jakarta Yudi Hermawan. Skrip dijalankan langsung dari share `\\JKT-FS01\Penagihan\tools\`, dan eksekusi terakhir pukul 08:34:58 Rabu menjelaskan alert `SOC-2026-0204` empat detik kemudian. Ini pengguna sah dengan skrip lama, bukan penyerang; kejadian ini dicatat sebagai sudah dijelaskan di kriteria containment.
- Temuan pentingnya adalah share. Skrip berisi password tersimpan di folder bersama, sehingga siapa pun yang punya akses baca ke folder itu pernah bisa membaca password `svc_billing`. Tindak lanjutnya: file dihapus dari share dan laptop, daftar akses baca folder itu dicatat di case notes, dan password `svc_billing` dianggap terpapar ke semua pemegang akses itu. Password itu sudah dirotasi di jam H dan login password sudah dimatikan, jadi yang tersisa adalah perbaikan proses: ekspor laporan staf tidak lagi memakai akun service dari laptop.

**Variasi:** ganti `svc_billing` dengan nama akun service lain atau pola seperti `ConvertTo-SecureString` dengan `-AsPlainText` untuk mencari skrip lain yang menyimpan password dalam teks biasa. Hasilnya bahan perbaikan jangka panjang, bukan bagian dari insiden ini.

**Kapan gagal:** script block logging tidak aktif di semua workstation, atau skrip tersimpan tetapi tidak pernah dijalankan dalam jendela waktu. Lengkapi dengan pencarian nama file lewat EDR dan pencarian isi file di share, dan tulis batas itu di scope statement.

### 2.4 Gerbang validasi `jkt-billing02` dan pemantauan sesudah cutover

Gerbang ini menjawab bagian pertama pertanyaan keenam Hendra. Setiap baris punya bukti; baris tanpa bukti dianggap belum lulus.

| No | Gerbang | Cara memeriksa | Bukti |
|---|---|---|---|
| 1 | Sumber bersih | Hash gold image dicocokkan dengan nilai yang tercatat saat image dibuat; paket aplikasi dari tag rilis yang ditandatangani | Catatan hash dan tag rilis |
| 2 | Tidak ada jejak penyerang | Pindai hash `kworkerd` (E06), path `/dev/shm/.cache` dan `/var/tmp/.font-unix`, string domain C2; cek cron, unit systemd, `authorized_keys` | Output pemindaian |
| 3 | Penyebab langsung tertutup (dicoba) | Login SSH password `svc_billing` dari jaringan workstation; login `svc_billing` dengan kunci dari host selain `10.20.1.15` | Kedua percobaan ditolak dan tercatat di Splunk |
| 4 | Rahasia baru saja | Login `billing_app` dan kunci API gateway lama dicoba | Ditolak |
| 5 | Kontrol keamanan aktif | Defender for Endpoint melapor ke konsol; auditd dan forwarder mengirim event; egress allowlist siap untuk `10.20.5.22` | Event uji tiba di Splunk; status sensor sehat |
| 6 | Fungsi layanan | Uji pembayaran, terbit tagihan, dan job ekspor oleh Tim Aplikasi Billing | Tanda tangan Wahyu Nugroho di formulir uji |

Setelah cutover, query berikut dijalankan sebagai bagian pemantauan pasca pemulihan.

**Tujuan:** melihat semua koneksi keluar `jkt-billing02` yang ditolak egress allowlist sejak cutover.

```
index=firewall src_ip="10.20.5.22" action=blocked
earliest="10/15/2026:23:00:00" latest="10/16/2026:07:00:00"
| stats count min(_time) as first_seen max(_time) as last_seen by dest_ip dest_port
| sort first_seen
| convert ctime(first_seen) ctime(last_seen)
```

Penjelasan tiap bagian:

- `src_ip` adalah server pengganti, dan `action=blocked` memilih koneksi yang ditolak allowlist. Koneksi yang diizinkan diperiksa terpisah terhadap daftar tujuan sah.
- `by dest_ip dest_port` mengelompokkan per tujuan, sehingga pola konfigurasi terlihat berbeda dari pola beacon.

Keluaran ilustrasi:

```
dest_ip      dest_port  count  first_seen            last_seen
192.0.2.10   123           17  10/15/2026 23:01:12   10/16/2026 06:58:40
192.0.2.11   123           16  10/15/2026 23:01:14   10/16/2026 06:57:02
```

Cara membaca hasil:

- Port 123 adalah NTP. Dua tujuan publik dengan pola teratur sejak menit pertama setelah cutover lebih mirip konfigurasi bawaan daripada beacon. Alert `SOC-2026-0205` dibuat dan ditelusuri: gold image masih memakai pool NTP publik bawaan distribusi, padahal server PT JAB harus memakai `jkt-ntp01`.
- Tindak lanjutnya dua: konfigurasi `jkt-billing02` diubah ke `jkt-ntp01`, dan gold image diperbaiki supaya server berikutnya tidak membawa masalah yang sama. Gerbang nomor 5 juga ditambah cek tujuan NTP.
- Temuan ini tidak memundurkan hitungan 7 hari karena sudah dijelaskan sebagai konfigurasi. Tujuan yang tidak bisa dijelaskan akan memundurkannya.

**Variasi:** ganti index dan filter untuk detection tambahan lain di bagian 1.6, misalnya login `svc_billing` dari selain `10.20.1.15` di index `linux` atau cron baru di `linux_audit`.

**Kapan gagal:** allowlist dipasang dengan aturan deny tanpa logging, atau server pengganti memakai IP yang belum tercakup aturan firewall. Gerbang nomor 5 harus memastikan keduanya sebelum cutover.

### 2.5 Pernyataan akhir recovery

Pernyataan ini menjawab pertanyaan ketujuh Hendra. Dikirim Dimas Jumat 2026-10-23 pukul 10:00, setelah 7 hari tanpa tanda penyerang sejak cutover Kamis 2026-10-15 23:00.

```
INC-2026-019 | Pernyataan akhir recovery | Jumat 2026-10-23 10:00 WIB
Dari: Dimas Prasetyo (IC) | Untuk: Hendra Wijaya | Tembusan: Wahyu Nugroho, Bambang
Hartono, Agus Setiawan, Ratna Sari, Maya Lestari
Severity: SEV-2 sejak Rabu 2026-10-14 17:20

KRITERIA AKHIR RECOVERY
1. Aset dibangun ulang/reimage, divalidasi, dikonfirmasi pemilik   TERPENUHI
   jkt-billing02 (gerbang lulus Kamis 18:00; konfirmasi Wahyu), JKT-WS-0388,
   JKT-WS-0412 (Kamis), BDG-WS-0142 (Senin 19 Okt)
2. Aset lama keluar jaringan, image disk, chain of custody          TERPENUHI
   E15, E16, E17, E18 tercatat di evidence log
3. Rahasia dirotasi dan nilai lama ditolak                          TERPENUHI
   svc_billing, billing_app (3x), API payment gateway, TLS, adm.yoga,
   akun Andi, Dewi, Rizky
4. Penyebab langsung ditutup dan dicoba                             TERPENUHI
   skrip berisi password dihapus dari laptop dan share; svc_billing hanya
   publickey dari 10.20.1.15; filter lampiran .js aktif
   Belum (dengan pemilik dan tanggal): EDR Linux untuk jkt-portal01 dan
   jkt-radius01 (Infrastruktur, 2026-11-30); blok DoH dan resolver luar
   (NOC, 2026-11-15)
5. 7 hari tanpa tanda penyerang                                     TERPENUHI
   SOC-2026-0205 (NTP gold image) dijelaskan dan diperbaiki
6. Perubahan sementara containment                                  DIPUTUSKAN
   dijadikan permanen lewat change: egress allowlist server billing, SSH hanya
   dari bastion, sinkhole cdn-sync.example.net
   dicabut: logging query database tambahan diganti audit tabel pelanggan
   berakhir: delegasi pilihan A (memo 13 Okt 15:10)

STATUS: recovery dinyatakan selesai. Insiden pindah ke post-incident.
- Pemantauan pasca pemulihan tetap berjalan sampai 2026-11-14.
- Post-incident review: Selasa 2026-10-27; after-action report disusun Sari.
- Pelaporan data pribadi: ditangani DPO dan Legal (jalur terpisah).
Insiden ditutup setelah post-incident review dan tindak lanjutnya tercatat.
```

Cara membaca elemennya:

- **Setiap kriteria punya status dan bukti singkat.** Hendra tidak perlu percaya pada kata "selesai"; ia bisa menanyakan baris yang meragukan.
- **"Belum" ditulis terang-terangan** untuk perbaikan jangka panjang, dengan pemilik dan tanggal. Recovery selesai tidak berarti semua perbaikan selesai.
- **Perubahan sementara diputuskan satu per satu.** Mencabut egress allowlist hanya karena "insiden sudah selesai" akan membuka kembali jalur yang terbukti dipakai penyerang; sebaliknya, pembatasan yang dipertahankan tanpa change management menjadi konfigurasi yang tidak dimiliki siapa pun.
- **Recovery selesai dan insiden ditutup adalah dua titik berbeda.** Yang pertama menunggu kriteria teknis, yang kedua menunggu post-incident review.

## 3. Lab praktik (di VM lab terisolasi)

Lab ini memakai lab Day 03 sampai Day 05: VM Windows dan VM Linux dengan beacon tiruan ke `c2.lab.test`, Splunk, dan bila ada, domain controller lab. Semua langkah di VM lab dengan snapshot. Jangan memakai data, nama, atau kejadian dari pekerjaan nyata.

1. **Tanam persistence ganda.** Di VM Linux, buat sendiri tiga artefak tiruan untuk beacon: cron milik pengguna biasa, salinan biner di subfolder tersembunyi di `/var/tmp`, dan satu unit systemd. Catat semuanya di `latihan/day06-artefak.md` sebelum lanjut.
2. **Clean berdasarkan temuan pertama.** Minta rekan, atau dirimu sendiri seminggu kemudian, membersihkan VM hanya berdasarkan live response gaya Day 04 tanpa membaca catatan langkah 1. Reboot VM dan catat artefak mana yang tersisa dan apakah beacon muncul lagi di Splunk.
3. **Gold image.** Buat template VM Linux bersih, hitung hash disk template, dan simpan nilainya. Bangun VM pengganti dari template itu dan pastikan hash template sebelum dipakai masih sama.
4. **Inventaris rahasia.** Untuk VM Linux "terkompromi", tulis daftar rahasia dengan tiga kolom: tersimpan di host, diketik di host selama "kompromi", dan dipasang setelah kompromi. Contoh di lab: kunci SSH, password database uji, token forwarder Splunk.
5. **krbtgt (bila ada DC lab).** Cek `PasswordLastSet` akun krbtgt dan kesehatan replikasi. Bila lab punya dua DC, latih reset dua kali dengan jeda sesuai panduan Microsoft, dan catat apa yang terjadi pada sesi Kerberos yang sudah berjalan di VM Windows. Jangan lakukan ini di domain produksi untuk latihan.
6. **Gerbang validasi dan cutover.** Tulis gerbang validasi dengan format bagian 2.4 untuk VM pengganti, jalankan setiap cek termasuk percobaan login dan koneksi yang harus ditolak, lalu pindahkan alamat layanan tiruan ke VM pengganti.
7. **Pemantauan dan pernyataan akhir.** Jalankan query bagian 2.4 untuk VM pengganti selama satu jam, jelaskan setiap koneksi yang ditolak, lalu tulis pernyataan akhir recovery dengan format bagian 2.5.

**Hasil yang sebaiknya tersimpan:**

- `latihan/day06-artefak.md` berisi artefak yang ditanam dan hasil langkah 2: apa yang tersisa setelah clean.
- Catatan hash gold image dan bukti verifikasinya.
- Inventaris rahasia tiga kolom.
- Catatan langkah 5 tentang dampak reset krbtgt di lab (bila dikerjakan).
- `latihan/day06-recovery.md` berisi gerbang validasi dengan bukti, hasil query pemantauan, dan pernyataan akhir recovery.

**Variasi tantangan:** ubah langkah 1 supaya salah satu artefak hanya aktif setelah reboot. Apakah live response di VM yang menyala menemukannya? Apa yang harus ada di gerbang validasi supaya artefak semacam itu tertangkap sebelum produksi?

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat eradication dan recovery. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Beacon muncul lagi setelah host dibersihkan | Persistence kedua yang tidak ditemukan | Rebuild atau reimage; kembali ke scoping [S3] |
| Host hasil reimage dikompromikan lagi | Akar masalah atau kredensial yang bocor belum ditutup | Telusuri jalan masuk; rotasi rahasia yang terpapar [S1][S9] |
| Aplikasi gagal setelah cutover | Rahasia baru belum dipasang di semua komponen, atau tujuan baru belum ada di allowlist | Uji fungsi di gerbang validasi; rotasi bersama pemilik aplikasi |
| Restore dari backup membawa artefak penyerang | Backup diambil setelah kompromi, atau tidak dipindai | Pilih backup sebelum aktivitas penyerang pertama; verifikasi integritas sebelum dipakai [S1][S8] |
| Koneksi keluar yang ditolak muncul dari server pengganti | Konfigurasi bawaan gold image (NTP, repositori paket, telemetri) | Telusuri dan jelaskan; perbaiki gold image [S7] |
| Reset password krbtgt gagal | Password filter kustom di DC | Ikuti workaround Microsoft untuk password filter [S5] |
| Klien non-Windows gagal autentikasi setelah reset krbtgt | Tiket lama tidak valid lagi | Tunggu kedaluwarsa tiket atau restart layanan; jadwalkan reset dengan pemilik aplikasi [S6] |
| Replikasi bermasalah setelah reset krbtgt | krbtgt belum pernah dirotasi dan memakai cipher lama, atau replikasi sudah tidak sehat | Cek kesehatan replikasi sebelum reset [S6] |
| Pimpinan menganggap insiden selesai saat layanan menyala | Tidak ada kriteria akhir recovery tertulis | Tulis kriteria dan status terhadap kriteria itu [S1] |

## 5. Kesalahan umum dan jebakan

- Membersihkan host yang dikuasai penyerang dengan hak tinggi atau tanpa visibilitas penuh, lalu menganggapnya bersih. Clean hanya menghapus yang ditemukan [S3].
- Me-reimage tanpa mencari akar masalah. Sistem baru dikompromikan lewat jalan yang sama [S9].
- Merotasi rahasia sebelum server terkompromi keluar dari jaringan, lalu tidak merotasinya lagi setelah cutover.
- Lupa rahasia di luar akun pengguna: kunci API pihak ketiga, sertifikat TLS, kunci SSH, token forwarder, kredensial database.
- Mereset krbtgt sekali saja, atau dua kali tanpa menunggu replikasi dan tanpa memahami dampaknya [S4][S5][S6].
- Mereset krbtgt atau semua password domain karena berita, bukan karena bukti. Sebaliknya, tidak mereset krbtgt padahal ada tanda DC atau akun berhak tinggi dikuasai.
- Memulihkan dari backup tanpa tahu kapan aktivitas penyerang pertama, atau tanpa memindai backup [S1][S8].
- Mengambil image disk sebelum atau tanpa chain of custody karena terburu-buru reimage.
- Menyatakan selesai saat layanan menyala, tanpa gerbang validasi dan tanpa periode pemantauan [S1][S3].
- Mencabut semua pembatasan containment sekaligus saat insiden dianggap selesai, atau mempertahankannya tanpa pemilik [S3].

## 6. Catatan terkini

Bagian ini menampung detail edisi dan perubahan dokumen acuan. Berguna saat membaca materi lain, tetapi tidak mengubah langkah di atas.

- **NIST SP 800-61 Rev. 3** memindahkan eradication ke subkategori RS.MI-02 dan recovery ke fungsi RC CSF 2.0 (kategori RC.RP dan RC.CO), menambahkan saran otomatisasi sebagian tindakan eradication, wewenang pihak ketiga seperti ISP dan penyedia cloud untuk eradication jenis insiden tertentu, dan merujuk SP 800-184 untuk panduan recovery yang lebih rinci [S1]. Rev. 2 membahas eradication dan recovery bersama di bagian 3.3.4 dan menyebut pendekatan bertahap yang untuk insiden besar bisa berbulan-bulan [S2].
- **Playbook CISA** edisi November 2021 yang dipakai di sini memberi judul langkah 9 di Appendix B sama dengan langkah 8 ("Execute Eradication Plan"), padahal isinya langkah recovery [S3]. Countermeasure CISA CM0027 merujuk edisi playbook bertanggal Agustus 2024 [S7]; perbedaan isinya dengan edisi 2021 belum dicek untuk catatan ini.
- **CISA Eviction Strategies Tool** memuat countermeasure per teknik, termasuk CM0027 (rebuild host) dan CM0050 (reset krbtgt dua kali), dibuat Maret 2025 [S6][S7].
- **Microsoft** menyebut skrip `New-KrbtgtKeys` sebagai salah satu cara mereset krbtgt menurut CM0050 [S6]. Diskusi komunitas menyebut skrip ini tidak lagi dirawat aktif tetapi masih berfungsi [S10]; cek versi dan statusnya sebelum dipakai.
- **NCSC UK** menerbitkan panduan respons dan recovery untuk serangan yang sangat mengganggu pada 28 Juli 2026, dibagi tiga bagian: aktivitas segera, program recovery menuju MVO, dan membangun kembali organisasi [S8].

## 7. Cheat sheet

```
MULAI ERADICATION bila containment TERBUKTI (kriteria Day 05), bukan hanya dijalankan
  CISA: persistence diperhitungkan + tertahan + bukti terkumpul
  persiapan (gold image, laptop cadangan, rencana) boleh lebih awal

CLEAN vs REBUILD: yang menentukan adalah yang TIDAK diketahui
  rebuild bila: admin/root mungkin | tanpa EDR/log | >1 persistence | implant interaktif
  rebuild berdampingan + cutover singkat; image disk aset lama setelah cutover

AKAR MASALAH: penyebab langsung (tutup sebelum produksi) | faktor pemungkin (minggu ini)
  | celah visibilitas (jangka panjang, pemilik + tanggal)
  cari SEMUA salinan rahasia: laptop, share, repo, skrip

ROTASI: inventaris per host = tersimpan | diketik selama kompromi | dipasang SETELAH kompromi
  akun, service, DB, API pihak ketiga, TLS, SSH, token, akun responder

KRBTGT: hanya bila bukti kompromi domain (DA, DC, DCSync, ntds.dit, golden ticket)
  2x | cek replikasi dulu | replikasi penuh + jeda >= 10 jam (atau > max ticket lifetime)
  RODC krbtgt_<n> terpisah | dampak: tiket gugur, klien non-Windows | ntds.dit -> semua password

RECOVERY: sumber tepercaya (gold image + repo + config mgmt), bukan backup host lama
  backup: sebelum aktivitas pertama + dipindai | MVO dulu | pemilik sistem konfirmasi

GERBANG VALIDASI: sumber bersih | tanpa jejak | akar masalah DICOBA | rahasia baru saja
  | kontrol aktif | fungsi layanan

PASCA PEMULIHAN: detection dari jejak insiden, 30 hari; setiap alert dijelaskan

AKHIR RECOVERY (kriteria): aset valid + aset lama ter-image + rahasia dirotasi
  + penyebab langsung tertutup + 7 hari tanpa tanda + perubahan sementara diputuskan
  recovery selesai != insiden ditutup (tunggu post-incident review)
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Proses `kworkerd` sudah dihentikan, file di `/dev/shm/.cache` dan cron `svc_billing` sudah dihapus, jadi `jkt-billing01` sudah bersih dan tidak perlu dibangun ulang." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Clean hanya menghapus apa yang ditemukan. Di `INC-2026-019`, analisis memori menemukan salinan kedua biner di `/var/tmp/.font-unix` yang tidak terlihat saat live response, server tidak punya EDR sehingga sebagian aktivitas tidak terlihat, dan eskalasi ke root tidak bisa disingkirkan. Playbook CISA mengingatkan penyerang sering memakai lebih dari satu mekanisme persistence. Karena itu server dibangun ulang dari gold image, berdampingan, lalu dipindah lewat cutover. Lihat bagian 1.2 dan 2.1.

</details>

**2. Skenario keputusan.** Tim Infrastruktur bertanya apakah krbtgt harus direset untuk `INC-2026-019`. Pilihan mana yang paling tepat?

- A. Reset krbtgt dua kali malam ini juga, karena lebih aman mereset daripada menyesal.
- B. Tidak mereset krbtgt, menuliskan alasan berdasarkan bukti (tidak ada akses ke akun berhak tinggi, DC, LSASS, atau replikasi direktori), dan menuliskan pemicu yang akan mengubah keputusan.
- C. Mereset password semua pengguna domain, karena penyerang sempat berada di jaringan kantor.

<details><summary>Jawaban</summary>

B. Reset krbtgt ditujukan untuk kompromi domain seperti golden ticket, dan punya dampak: tiket untuk semua aplikasi yang bergantung pada AD gugur dan klien non-Windows bisa gagal autentikasi. Di insiden ini tidak ada bukti akun berhak tinggi atau DC dikuasai, jadi keputusan yang tepat adalah tidak mereset dengan alasan tertulis dan pemicu yang jelas. A keliru karena mengambil dampak operasional tanpa dasar bukti, dan bila dikerjakan terburu-buru tanpa cek replikasi bisa menimbulkan masalah baru. C keliru karena reset semua password domain disarankan AA20-245A bila `ntds.dit` mungkin dicuri, bukan karena penyerang sempat ada di jaringan. Lihat bagian 1.4.

</details>

**3. Pertanyaan jebakan.** "Kredensial database `billing_app` sudah dirotasi di jam H, jadi saat cutover ke `jkt-billing02` tidak perlu dirotasi lagi." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Nilai baru dari jam H dipasang di `jkt-billing01`, server yang masih terkompromi sampai dimatikan. Rahasia yang dipasang di host terkompromi setelah kompromi ikut dianggap terpapar, sehingga `billing_app` dirotasi lagi saat cutover dan nilai lama dicoba untuk memastikan ditolak. Prinsip yang sama berlaku untuk akun admin responder yang mengetik password di host itu. Lihat bagian 1.4 dan 2.2.

</details>

**4. Skenario keputusan.** Wahyu menawarkan cara cepat memulihkan server billing. Pilihan mana yang paling tepat?

- A. Restore seluruh `jkt-billing01` dari backup Rabu 01:00, karena itu backup terbaru dan paling lengkap.
- B. Restore seluruh `jkt-billing01` dari backup Senin malam, karena dibuat sebelum penyerang masuk.
- C. Bangun server pengganti dari gold image yang hash-nya dicek, aplikasi dari tag rilis, konfigurasi dengan rahasia baru, dan hanya file laporan yang diambil dari backup Senin malam setelah dipindai.

<details><summary>Jawaban</summary>

C. Sistem operasi dan aplikasi dari sumber tepercaya, sedangkan backup hanya dipakai untuk data yang memang dibutuhkan, dari titik sebelum aktivitas penyerang pertama, dan dipindai sebelum dipakai. A keliru karena backup Rabu 01:00 diambil setelah kompromi Selasa 02:14 dan bisa membawa salinan implant di `/var/tmp`. B lebih baik daripada A, tetapi memulihkan seluruh server dari backup membawa kembali konfigurasi yang menjadi penyebab langsung, misalnya login password `svc_billing`, dan rahasia lama yang sudah terpapar. Lihat bagian 1.3 dan 1.5.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Wahyu Nugroho (Lead Aplikasi Billing), dalam tiga kalimat, kenapa server billing dibangun ulang dan harus lolos gerbang validasi sebelum cutover, padahal file penyerang sudah diketahui.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Kita hanya bisa menghapus apa yang kita temukan, dan retainer sudah menemukan satu salinan program penyerang yang terlewat saat pemeriksaan pertama, sementara server itu tidak punya EDR sehingga kita tidak bisa memastikan tidak ada yang lain. Server baru dibangun dari image dan rilis aplikasi yang kita tahu bersih, berdampingan dengan server lama, jadi pembayaran hanya berhenti sebentar saat dipindah Kamis malam. Gerbang validasi memastikan server baru tidak membawa jejak penyerang, jalan masuk lama benar-benar tertutup, dan aplikasinya berjalan, dan tanda tanganmu di uji fungsi adalah salah satu syaratnya."

Kesalahan yang sering muncul:
- Menyiratkan bahwa tim aplikasi lalai, padahal yang dibahas adalah ketidakpastian teknis.
- Tidak menyebut dampak layanan yang sebenarnya kecil karena build berdampingan.
- Tidak menyebut peran Wahyu dalam validasi.

</details>

**6. Pertanyaan jebakan.** "Cutover ke `jkt-billing02` berhasil Kamis malam dan portal pembayaran berjalan normal, jadi recovery selesai dan insiden bisa ditutup Jumat pagi." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Rev. 3 meminta akhir recovery dinyatakan berdasarkan kriteria, diikuti dokumentasi dan after-action report. Kriteria PT JAB memuat validasi semua aset termasuk laptop Bandung yang baru di-reimage Senin, image disk aset lama, rotasi semua rahasia, penyebab langsung yang ditutup, minimal 7 hari tanpa tanda penyerang setelah cutover, dan keputusan atas perubahan sementara containment. Recovery dinyatakan selesai Jumat 2026-10-23, dan insiden baru ditutup setelah post-incident review. Lihat bagian 1.7 dan 2.5.

</details>

**7. Interview question (English).** "Walk me through how you decide between cleaning and rebuilding a compromised server, and what has to happen before it goes back into production."

<details><summary>Sample answer</summary>

"I start from what we don't know. If the attacker may have had admin or root, if the host had no EDR or limited logging, if we found more than one persistence mechanism, or if the malware was an interactive implant, I rebuild rather than clean, because cleaning only removes what we found. To keep downtime short, I build the replacement side by side from a verified gold image, deploy the application from a release tag and configuration with new secrets, and cut over in a short window. Before cutover the replacement has to pass a validation gate: no indicators from the incident, the root cause actually tested as closed, for example a password login with the abused service account must fail, only new secrets accepted, security controls reporting, and the system owner signing off on functional tests. I also rotate every secret the attacker could have seen, including secrets we installed on the compromised host during containment, and I only reset krbtgt when there's evidence of domain compromise. After cutover we run extra detections built from the incident for a set period, explain every alert, and declare recovery complete against written criteria before moving to the post-incident review."

What makes this answer strong: it ties the rebuild decision to uncertainty rather than habit, shows a way to limit business impact, lists concrete validation checks including testing the root cause fix, catches the often missed rotation of secrets installed during containment, treats krbtgt as evidence driven, and ends with criteria rather than a feeling.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | NIST SP 800-61 Rev. 3 (PDF) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf | primer | April 2025; diakses 2026-10-15 | Tinggi. RS.MI-02, fungsi RC (cara recovery, penggantian hardware), RC.RP-01 sampai RC.RP-06, RC.CO-03 |
| S2 | NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide (PDF) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf | primer | Agustus 2012 (lebih dari 3 tahun, digantikan Rev. 3); diakses 2026-10-15 | Tinggi untuk bagian 3.3.4: eradication kadang tidak perlu, recovery, logging lebih tinggi, serangan berulang, pendekatan bertahap |
| S3 | CISA: Cybersecurity Incident and Vulnerability Response Playbooks (PDF) | https://www.cisa.gov/sites/default/files/publications/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf | primer | November 2021; diakses 2026-10-15 | Tinggi. Bagian Eradication & Recovery dan Appendix B langkah 8a sampai 8m dan 9a sampai 9l |
| S4 | CISA: Technical Approaches to Uncovering and Remediating Malicious Activity (AA20-245A) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-245a | primer | 2020-09-01, revisi 2020-09-24 (lebih dari 3 tahun); diakses 2026-10-15 | Tinggi. krbtgt dua kali dengan replikasi di antaranya, reset semua password bila `ntds.dit` dicuri, reset akun lokal DC, sertifikat, akun service, kesalahan umum, pemantauan |
| S5 | Microsoft Learn: AD Forest Recovery, Reset the krbtgt password | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password | primer (dokumentasi vendor) | ms.date 2025-05-21; diakses 2026-10-15 | Tinggi. Reset dua kali, jeda 10 jam sesuai umur tiket maksimum, riwayat password dua, DC writable vs RODC, password filter |
| S6 | CISA Eviction Strategies Tool: CM0050 Reset Kerberos Ticket Granting Ticket (KRBTGT) Password Twice | https://www.cisa.gov/eviction-strategies-tool/info-countermeasures/CM0050 | primer | Maret 2025; diakses 2026-10-15 | Tinggi. Tujuan (golden ticket), cek replikasi, jeda minimal 10 jam, dampak ke aplikasi dan klien non-Windows, cipher lama, `New-KrbtgtKeys` |
| S7 | CISA Eviction Strategies Tool: CM0027 Rebuild Compromised Host | https://www.cisa.gov/eviction-strategies-tool/info-countermeasures/CM0027 | primer | Maret 2025; diakses 2026-10-15 | Tinggi. Tujuan rebuild, persiapan image bersih dan backup, langkah, risiko kehilangan data dan gangguan |
| S8 | NCSC UK: Recovering from a highly disruptive cyber attack, Section 2 (Recovery and ongoing investigations) | https://www.ncsc.gov.uk/collection/disruptive-cyber-attacks/recovering/2-recovery-ongoing-investigations | primer | Terbit 2026-07-28, direview 2026-10-01; diakses 2026-10-15 | Tinggi. Definisi MVO, backup dianggap mungkin disasar, sumber identitas tepercaya, reset kredensial termasuk berhak tinggi, bukti perbaikan sebelum konektivitas, risiko insiden dimulai lagi |
| S9 | Harlan Carvey: Incident Response Misconceptions (arsip blog Microsoft) | https://learn.microsoft.com/en-us/archive/blogs/industry_insiders/incident-response-misconceptions | sekunder (praktisi) | 2005-08-15 (lebih dari 3 tahun); diakses 2026-10-15 | Sedang. Opini praktisi tentang reinstall tanpa analisis akar masalah dan backup yang ikut terinfeksi; konsisten dengan RC.RP-05 [S1] |
| S10 | Microsoft Q&A: Reset krbtgt password (utas diskusi) | https://learn.microsoft.com/en-my/answers/questions/87978/reset-krbtgt-password | komunitas | Utas 2020-09-07 sampai 2024-10-30; diakses 2026-10-15 | Rendah sampai sedang. Pendapat penjawab anonim tentang reset beruntun saat kompromi; status skrip `New-KrbtgtKeys` menurut kontributor |

**Catatan sumber:** praktik mereset krbtgt dua kali berturut-turut tanpa menunggu replikasi saat kompromi hanya berasal dari diskusi komunitas [S10] dan tidak ditemukan di panduan Microsoft [S5] maupun CISA [S4][S6] yang dibaca; karena itu ditandai belum terkonfirmasi. Tabel kriteria clean atau rebuild di bagian 1.2, pembagian akar masalah menjadi tiga kelompok di bagian 1.3, inventaris rahasia tiga kolom di bagian 1.4, gerbang validasi di bagian 2.4, periode 7 dan 30 hari, serta enam kriteria akhir recovery di bagian 1.7 adalah susunan catatan ini dari sumber yang disebut, bukan daftar resmi. Semua isi PT JAB, termasuk hasil analisis memori dan jumlah data yang diambil, adalah contoh fiktif.
