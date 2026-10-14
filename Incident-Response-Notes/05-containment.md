---
day: 05
title: 'Containment: jangka pendek dan panjang, contain atau observe, isolasi host, akun, dan blok IOC'
researched_on: 2026-10-15
versions_checked: 'NIST SP 800-61 Rev. 3 (April 2025); NIST SP 800-61 Rev. 2 (Agustus 2012, digantikan Rev. 3); CISA Cybersecurity Incident and Vulnerability Response Playbooks (November 2021); CISA AA20-245A (1 September 2020, revisi 24 September 2020); Microsoft Defender for Endpoint, halaman Take response actions on a device (ms.date 2026-07-23); Microsoft Entra ID, halaman Revoke user access in an emergency (ms.date 2026-06-19); MS-KILE, Check Account Policy for Every Session Ticket Request (diperbarui 2026-04-27)'
---

# Day 05: Containment (jangka pendek dan panjang, contain atau observe, isolasi host, akun, dan blok IOC)

Cakupan: memilih strategi containment dengan kriteria tertulis, membedakan containment jangka pendek dan jangka panjang, memutuskan kapan menahan dan kapan menunda, menahan host, akun, dan jalur jaringan beserta batas masing-masing, menjalankan containment secara terkoordinasi, dan menilai kapan containment boleh dinyatakan berhasil.

## Ide inti

Containment bukan satu tombol, tetapi satu keputusan yang terdiri dari beberapa tindakan: memutus host, mencabut akses akun, menutup jalur jaringan penyerang, dan menahan dampak di sistem yang tidak bisa dimatikan. Setiap tindakan punya harga: layanan yang terganggu, bukti yang hilang, atau penyerang yang sadar sedang dicari. Karena itu containment yang baik ditentukan oleh tiga hal yang sudah disiapkan sebelumnya. Pertama, scope yang cukup, supaya semua akses penyerang yang diketahui ditutup sekaligus (Day 03). Kedua, bukti yang sudah diamankan (Day 04). Ketiga, kriteria tertulis untuk memilih tindakan dan memutuskan kapan containment dianggap berhasil.

Kamu sudah mengenal pola ini dari NOC. Saat DDoS menghantam satu prefix pelanggan, engineer memasang blackhole route secepatnya (jangka pendek), lalu mengalihkan trafik ke scrubbing sambil tetap melayani pelanggan (jangka panjang) sampai serangan reda dan konfigurasi permanen dipasang. Saat migrasi besar, perubahan di semua POP dijalankan serentak di satu maintenance window, bukan satu per satu sepanjang minggu. IR memakai pola yang sama dengan satu perbedaan penting: lawannya manusia yang bisa melihat respons kita. Tindakan yang dijalankan satu per satu memberi penyerang waktu untuk pindah ke akses lain, dan blackhole yang dipasang terlalu cepat bisa membuat kita kehilangan satu-satunya jendela untuk melihat ke mana ia pergi.

```
scope cukup (Day 03) + bukti aman (Day 04)
  |
  v
pilih strategi per aset   kriteria: kerusakan, bukti, layanan, sumber daya,
                          efektivitas, durasi
  |
  +-- contain sekarang      (kerusakan berjalan, data diambil, scope cukup)
  +-- tunda terbatas        (persiapan, dengan batas waktu dan pemicu)
  |
  v
tindakan serentak di jam H    host | akun | jaringan | sistem yang tak bisa mati
  |
  v
validasi: tidak ada tanda baru?  -- ya, selama periode yang ditetapkan --> eradication (Day 06)
  |
  tidak (host/akun baru)
  v
kembali ke scoping, perluas containment
```

Situasi yang dipakai sepanjang Day ini melanjutkan `INC-2026-019` di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif. Ringkasnya: lampiran email dijalankan di `JKT-WS-0388` (`andi.pratama`) dan `BDG-WS-0142` (`dewi.anggraini`), password akun service `svc_billing` dibaca dari skrip di laptop Andi, lalu dipakai untuk SSH ke server billing `jkt-billing01`. Ketiganya beacon ke `cdn-sync.example.net` (`203.0.113.77`). Bukti sudah diamankan antara 12:30 dan 15:20. Saat pengambilan bukti, Yoga menemukan proses penyerang `kworkerd` di `jkt-billing01` memegang koneksi aktif ke database billing `jkt-billingdb01` (`10.20.5.30`, PostgreSQL). Log database hanya mencatat koneksi, bukan query, sehingga akses ke data pelanggan tidak bisa disingkirkan. Pukul 13:35 IC Dimas Prasetyo menaikkan severity ke SEV-1 dengan aturan "ragu, pilih lebih tinggi", memberi tahu Direktur Teknologi Hendra Wijaya sebagai executive sponsor, dan mengaktifkan retainer PT Forensik Digital Contoh untuk analisis memori. Pukul 14:40, Hendra menulis di kanal `#inc-2026-019`:

> "Dim, saya sudah baca update 14:30. Saya harus memutuskan soal `jkt-billing01` sebelum jam 16:00. Pilihannya apa saja, dan apa risikonya? Kenapa tidak dari tadi pagi saja semuanya diputus? Kalau IP penyerang diblok di firewall, cukup tidak? Akun-akun itu dimatikan saja kan beres? Lalu bagaimana kita tahu containment-nya berhasil, dan kalau penyerang sadar lalu pindah ke tempat lain bagaimana?"

Pesan itu memuat tujuh pertanyaan:

1. Pilihan apa saja yang ada, dan mana yang sementara?
2. Bagaimana menimbang risiko tiap pilihan?
3. Kenapa tidak diputus sejak pagi?
4. Bagaimana menahan host, termasuk server yang tidak boleh mati?
5. Apakah mematikan akun sudah cukup?
6. Apakah blok IP sudah cukup?
7. Bagaimana menjalankan semuanya tanpa membuat penyerang pindah, dan bagaimana tahu berhasil?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, pertanyaan 6 di bagian 1.6, dan pertanyaan 7 di bagian 1.7. Bagian 2 berisi dokumen keputusan, rencana jam H, dan hasil validasi PT JAB sore itu.

**Kapan relevan:** setelah insiden dinyatakan dan sebelum eradication, setiap kali penyerang masih punya akses atau dampak masih bisa meluas; juga saat merancang playbook dan wewenang containment sebelum insiden.
**Kapan bukan jawaban:** containment tidak menghapus penyerang. Malware, persistence, dan celah masuk masih ada sampai eradication (Day 06). Containment juga tidak menggantikan scoping: menahan apa yang sudah diketahui tidak menutup akses yang belum ditemukan, jadi pencarian tetap berjalan sesudahnya.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (containment, eradication, recovery, severity, IC, executive sponsor, scoping, IOC, scope statement, bukti) tidak diulang. Tabel berikut memuat istilah baru Day ini. Kolom padanan memakai analogi NOC dan SOC yang sama di semua Day IR.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Containment jangka pendek | Tindakan cepat untuk menghentikan penyebaran dan dampak, biasanya berjam-jam | Reroute darurat atau blackhole route saat serangan |
| Containment jangka panjang | Pembatasan sementara yang membuat layanan tetap jalan sampai eradication selesai, berhari-hari sampai berminggu-minggu | Perbaikan sementara yang dipertahankan sampai link baru dipasang |
| Strategi containment | Kombinasi tindakan per aset yang dipilih dengan kriteria tertulis | Rencana penanganan gangguan per jenis perangkat |
| Contain atau observe | Keputusan menahan sekarang atau sengaja menunda untuk mengamati penyerang | Membiarkan link flapping hidup sementara untuk menangkap polanya |
| Tipping off | Penyerang menyadari ia terdeteksi karena tindakan responder | Pelanggan fraud yang langsung pindah ke akun lain begitu diputus |
| Sandbox redirection | Mengalihkan penyerang ke lingkungan terkendali untuk diamati | Memindahkan trafik mencurigakan ke port mirror untuk dianalisis |
| Isolasi host | Memutus host dari jaringan, kecuali jalur pengelolaan tertentu | Shutdown port switch, perangkat tetap dikelola lewat out-of-band |
| Isolasi penuh dan selektif | Isolasi yang memutus semua koneksi vs yang mengizinkan proses atau tujuan tertentu | Port shutdown vs ACL yang hanya membuka port manajemen |
| Egress allowlist | Aturan firewall yang hanya mengizinkan koneksi keluar ke tujuan yang disebut | ACL keluar yang hanya membuka peer BGP dan NTP tertentu |
| Revoke session | Mencabut refresh token dan sesi sehingga pengguna harus login ulang | Mencabut sesi TACACS yang sedang aktif |
| DNS sinkhole | Mengarahkan domain berbahaya di resolver internal ke IP pengganti yang mencatat setiap akses | Blackhole route ke null0, ditambah pencatatan |
| Jam H | Waktu yang disepakati untuk menjalankan semua tindakan containment secara serentak | Jam cutover di maintenance window |
| Kriteria selesai containment | Kondisi yang harus dipenuhi sebelum containment dinyatakan berhasil | Gangguan dinyatakan pulih setelah stabil selama periode pemantauan |

### 1.1 Jangka pendek dan jangka panjang: semua containment sementara

Hendra bertanya "pilihannya apa saja". Sebelum masuk ke pilihan per aset, perlu disepakati bahwa semua tindakan containment bersifat sementara. Yang berbeda adalah berapa lama tindakan itu harus bertahan dan apa harganya selama bertahan.

NIST SP 800-61 Rev. 2 memasukkan durasi sebagai salah satu kriteria memilih strategi, dengan contoh tiga tingkat: workaround darurat yang dicabut dalam empat jam, workaround sementara yang dicabut dalam dua minggu, dan solusi permanen [S2]. Rev. 3 memakai contoh yang serupa dalam catatan kategori RS.MI (Incident Mitigation), yaitu workaround darurat dalam hitungan jam, workaround sementara dalam dua minggu, atau solusi permanen, dan menyebut durasi eradication bisa dinilai dengan cara yang sama [S1]. Playbook CISA menyebut langkah awal containment sebagai mitigasi jangka pendek untuk mengisolasi aktivitas penyerang dan mencegah kerusakan atau perpindahan ke sistem lain [S3].

Di catatan ini dua istilah dipakai dengan arti berikut:

- **Containment jangka pendek** menghentikan penyebaran dan dampak secepatnya, dan boleh mengganggu layanan sebentar. Contohnya isolasi workstation lewat EDR, blok C2 di firewall, menonaktifkan akun.
- **Containment jangka panjang** mempertahankan pembatasan sambil layanan tetap jalan, sampai eradication dan recovery selesai. Contohnya server billing yang tetap melayani pelanggan, tetapi hanya boleh berbicara ke tujuan yang sudah ditentukan dan hanya bisa diakses dari bastion.

Perbedaan ini penting untuk `jkt-billing01`. Mematikan server adalah containment jangka pendek yang paling tuntas, tetapi menghentikan pembayaran online 400 ribu pelanggan sampai server dibangun ulang. Containment jangka panjang menjaga layanan, tetapi meninggalkan risiko yang harus dipantau. Pilihannya adalah keputusan bisnis, sehingga di RACI PT JAB (Day 02 bagian 2.2) A-nya Hendra, bukan Dimas.

### 1.2 Kriteria memilih strategi: tulis sebelum malam insiden

Pertanyaan kedua Hendra ("apa risikonya?") dijawab dengan kriteria yang sama untuk setiap pilihan, supaya pilihan bisa dibandingkan dan tidak bergantung pada siapa yang paling keras bicara di bridge.

Rev. 2 menyebut keputusan containment jauh lebih mudah bila strategi dan prosedurnya sudah ditentukan sebelumnya, menyarankan strategi terpisah untuk setiap jenis insiden besar, dan memberi enam kriteria [S2]:

1. Potensi kerusakan dan pencurian sumber daya.
2. Kebutuhan menjaga bukti.
3. Ketersediaan layanan, misalnya konektivitas dan layanan ke pihak luar.
4. Waktu dan sumber daya untuk menjalankan strategi.
5. Efektivitas strategi: containment parsial atau penuh.
6. Durasi solusi.

Rev. 3 menambahkan bahwa kriteria bisa memperhitungkan jenis insiden (misalnya kompromi layanan cloud dibanding ransomware di endpoint) dan memakai faktor evaluasi risiko yang sama dengan penentuan prioritas insiden, seperti kekritisan aset, dampak fungsional, dampak data, tahap aktivitas penyerang, karakter pelaku, dan kemampuan pulih [S1]. Playbook CISA menambahkan dampak tambahan pada operasi, dan meminta efektivitas dinilai termasuk kemungkinan tingkat containment yang tidak diketahui [S3].

Tabel berikut adalah bentuk kriteria itu di PT JAB. Pakai kolom "Pertanyaan" saat menilai setiap pilihan; jawaban "tidak tahu" di salah satu baris adalah tanda pilihan itu belum siap dijalankan.

| Kriteria | Pertanyaan | Untuk `jkt-billing01` |
|---|---|---|
| Kerusakan dan pencurian | Apa yang bisa terjadi bila pilihan ini dijalankan, dan bila tidak? | Penyerang punya koneksi ke database pelanggan; setiap jam tanpa containment adalah jam akses ke data pribadi |
| Bukti | Bukti apa yang hilang bila pilihan ini dijalankan? | Memori dan artefak sudah diambil (Day 04); image disk masih bisa diambil saat rebuild |
| Layanan | Siapa yang terdampak, berapa lama? | Mematikan server menghentikan pembayaran online sampai rebuild; containment parsial hanya mengganggu sekitar 10 menit saat rotasi kredensial |
| Waktu dan sumber daya | Siapa yang menjalankan, berapa lama, sudah diuji? | ACL firewall dan rotasi kredensial butuh NOC dan Tim Aplikasi Billing, sekitar 15 menit |
| Efektivitas | Penuh atau parsial? Apa yang tersisa? | Mematikan: penuh. Parsial: tergantung ACL dan apakah ada persistence lain yang belum ditemukan |
| Durasi | Sampai kapan pembatasan harus bertahan? | Sampai rebuild, direncanakan maksimal 72 jam |

### 1.3 Contain sekarang atau tunda: menunda untuk bersiap berbeda dengan mengamati

Pertanyaan ketiga Hendra ("kenapa tidak dari tadi pagi?") wajar dari sudut bisnis, dan punya dua jawaban yang harus dipisahkan: menunda untuk bersiap, dan menunda untuk mengamati.

Rev. 3 meminta strategi respons menyeimbangkan kebutuhan cepat pulih dengan kebutuhan mengamati penyerang atau menginvestigasi lebih menyeluruh, dan menyebut setiap pilihan punya trade-off (RS.MA-03) [S1]. Untuk mengamati, Rev. 2 dan Rev. 3 sama-sama menyebut sebagian organisasi mengalihkan penyerang ke sandbox untuk memantau aktivitasnya, yang berarti containment dan eradication tertunda; tim IR harus membahas kelayakannya dengan bagian legal lebih dulu, dan penundaan yang disengaja itu berbahaya karena penyerang bisa memperluas akses atau mengompromikan sistem lain [S1][S2]. Rev. 2 lebih tegas: cara memantau penyerang selain sandbox tidak boleh dipakai, karena organisasi yang tahu sistemnya dikuasai dan membiarkannya bisa ikut bertanggung jawab bila sistem itu dipakai menyerang pihak lain [S2]. Playbook CISA menyebut pengalihan ke sandbox terbatas untuk SOC yang matang [S3].

Di sisi lain, playbook CISA menyebut sebagian penyerang memantau langkah defender dan mengubah caranya untuk menghindari containment, sehingga defender perlu gambaran selengkap mungkin tentang kemampuan dan kemungkinan reaksi penyerang untuk menghindari tipping off. Containment sulit karena defender harus selengkap mungkin mengidentifikasi aktivitas penyerang, sambil menimbang risiko membiarkan penyerang bertahan sampai cakupan penuh diketahui [S3]. AA20-245A menempatkan mitigasi yang tidak membuat penyerang sadar sebagai salah satu langkah utama, dan menyebut hak akses bisa dikurangi alih-alih dicabut bila membuat penyerang sadar tidak diinginkan [S4].

Dari sumber-sumber itu, PT JAB memakai pembedaan berikut:

| | Menunda untuk bersiap | Menunda untuk mengamati |
|---|---|---|
| Tujuan | Menyelesaikan scope minimal dan mengamankan bukti, supaya containment serentak dan lengkap | Mempelajari tujuan dan cara penyerang |
| Lama | Jam, dengan batas waktu tertulis | Bisa berhari-hari |
| Syarat | Tidak ada kerusakan yang berjalan cepat; pemicu containment segera ditulis | Keputusan IC, Legal, dan executive sponsor; lingkungan terkendali seperti sandbox; kemampuan SOC yang matang |
| Di PT JAB | Dipakai di `INC-2026-019`, 10:40 sampai 16:00 | Tidak dipakai; PT JAB tidak punya sandbox redirection dan data pribadi pelanggan terlibat |

Penundaan pagi itu adalah penundaan untuk bersiap: tidak ada enkripsi atau penghapusan yang berjalan, scope belum diketahui, dan bukti belum diambil. Begitu `jkt-billing01` terlihat terhubung ke database pelanggan pukul 13:15, perhitungannya berubah: setiap jam penundaan sekarang adalah jam akses ke data pribadi. Karena itu Dimas mempertahankan jam H 16:00 hanya karena persiapan ACL dan rotasi kredensial membutuhkan waktu itu, dan menulis pemicu untuk memajukannya.

### 1.4 Menahan host: isolasi dan server yang tidak bisa diisolasi

Pertanyaan keempat Hendra punya dua bagian: workstation yang bisa diputus, dan server yang tidak boleh mati.

**Workstation dengan EDR.** Isolasi perangkat di Defender for Endpoint memutus perangkat dari jaringan tetapi mempertahankan koneksi ke layanan Defender, sehingga perangkat tetap dipantau dan live response tetap bisa dipakai. Isolasi selektif tersedia untuk memberi kontrol lebih, misalnya tetap mengizinkan Outlook dan Teams [S5]. Hal yang perlu diketahui sebelum menekan tombolnya [S5]:

- Isolasi penuh tersedia untuk Windows 11, Windows 10 versi 1703 atau lebih baru, Windows Server 2012 R2 atau lebih baru, dan Azure Stack HCI OS 23H2 atau lebih baru. Isolasi di Linux butuh `iptables`, `ip6tables`, dan konfigurasi kernel tertentu, dan isolasi Linux terlepas bila admin mengubah atau menambah aturan `iptables`.
- Di lingkungan yang memakai web proxy (termasuk PAC, WPAD, atau proxy statis), perangkat bisa gagal pulih dari isolasi; dokumentasi menyarankan isolasi selektif dalam kasus itu.
- Perangkat di belakang VPN full tunnel tidak bisa mencapai layanan Defender setelah diisolasi; disarankan split tunnel untuk trafik Defender.
- Mengisolasi server Hyper-V memutus trafik semua VM di dalamnya.
- Perangkat yang offline saat isolasi dikirim akan dicoba ulang sampai tiga hari.
- Dokumentasi juga menyebut isolasi otomatis dilepas setelah tujuh hari. Untuk containment jangka panjang, cek perilaku ini di tenant-mu dan jadwalkan pengecekan status.
- Aksi ini butuh peran dengan izin Active remediation actions dan akses ke grup perangkat terkait.

**Workstation tanpa EDR.** Isolasi dilakukan di jaringan: port switch dimatikan, atau port dipindah ke VLAN karantina, dan koneksi nirkabel diputus. Playbook CISA menyebut tiga lapis containment jaringan: perimeter, jaringan internal, dan host [S3]. Di PT JAB, NOC menjalankan bagian jaringan, dan teknisi lokal mematikan Wi-Fi laptop tanpa me-restart.

**Server yang tidak boleh mati.** Tindakan dipindah ke sekeliling server: firewall membatasi ke mana server boleh terhubung (egress allowlist) dan siapa yang boleh terhubung ke server, kredensial yang dipakai penyerang dirotasi, dan proses penyerang dihentikan setelah bukti diambil. Playbook CISA mencantumkan langkah-langkah ini: menutup port tertentu, memperbarui filter firewall, mencegah sistem yang terkompromi terhubung ke sistem lain, dan sementara memutus sistem yang menghadap internet bila perlu [S3]. Menghentikan proses penyerang ada di batas antara containment dan eradication; di sini dihitung containment karena tujuannya menghentikan akses aktif, sedangkan membersihkan file dan persistence dilakukan saat eradication.

Perhatian untuk semua host: isolasi jaringan tidak berarti kerusakan di host berhenti. Rev. 2 memberi contoh proses berbahaya yang menimpa atau mengenkripsi data di disk begitu koneksinya gagal, dan mengingatkan handler untuk tidak menganggap host yang sudah diputus pasti aman dari kerusakan lebih lanjut [S2]. Rev. 3 juga menyarankan sebagian containment diotomatiskan, misalnya karantina malware atau memindahkan endpoint ke jaringan remediasi, tetapi tetap memberi handler kemampuan memilih dan menjalankan containment secara manual [S1].

### 1.5 Menahan akun: disable saja belum cukup

Pertanyaan kelima Hendra ("akun-akun itu dimatikan saja kan beres?") punya jawaban "perlu, tetapi belum cukup", karena akses yang sudah terbit tidak langsung hilang saat akun dimatikan.

**Kerberos di AD.** Spesifikasi Kerberos Microsoft (MS-KILE) menyebut Kerberos V5 tidak menegakkan pencabutan akun sebelum tiket yang sudah terbit kedaluwarsa. Bila kebijakan validasi diaktifkan di KDC, dan TGT yang dipakai lebih tua dari batas waktu yang ditentukan implementasi, KDC di domain akun memeriksa apakah akun masih dalam keadaan baik (tidak kedaluwarsa, terkunci, atau dinonaktifkan) dan menolak dengan `KDC_ERR_CLIENT_REVOKED` bila tidak [S7]. Artinya, setelah akun dinonaktifkan, tiket yang sudah dipegang penyerang bisa tetap dipakai untuk sementara waktu. Pemeriksaan itu juga tidak bisa dilakukan oleh KDC di luar domain akun [S7].

**Password dan pass-the-hash.** Dokumentasi Microsoft untuk mencabut akses darurat di lingkungan hybrid menyarankan menonaktifkan akun di AD lalu me-reset password-nya dua kali, untuk mengurangi risiko pass-the-hash, terutama bila replikasi password on-premises tertunda; reset sekali cukup bila akun bisa dianggap tidak terkompromi [S6].

**Token di Entra ID.** Di Entra ID, akun dinonaktifkan dan Revoke sessions dijalankan untuk mencabut refresh token. Setelah itu pengguna tidak bisa mendapat token baru, tetapi aplikasi yang memakai access token baru kehilangan akses saat token itu kedaluwarsa, defaultnya satu jam, dan aplikasi yang memakai session token sendiri baru berhenti saat sesi itu berakhir atau aplikasi mencabutnya [S6]. Continuous Access Evaluation (CAE) memungkinkan pencabutan hampir seketika untuk aplikasi yang mendukungnya [S6].

**Akun service.** Akun seperti `svc_billing` tidak bisa dimatikan begitu saja karena aplikasi bergantung padanya. Playbook CISA menyebut mengganti password admin, merotasi private key, dan merotasi secret akun service atau aplikasi bila diduga terkompromi, serta mencabut akses berhak tinggi [S3]. Rotasi ini dikoordinasikan dengan pemilik aplikasi, karena aplikasi harus diberi kredensial baru pada saat yang sama.

AA20-245A menambahkan peringatan tentang waktu: reset kredensial yang dilakukan terlalu dini (sebelum scope diketahui) adalah kesalahan umum, karena penyerang sering memegang beberapa kredensial atau punya akses luas ke AD, dan bisa memakai kredensial lain atau membuat yang baru [S4]. Reset satu akun saat penyerang masih memegang akun lain hanya memberi tahu penyerang.

Dari sumber-sumber itu, containment akun di PT JAB selalu berisi empat langkah yang dijalankan bersama, bukan satu:

1. Nonaktifkan akun di AD, dan reset password dua kali.
2. Revoke sessions di Entra ID untuk akun yang tersinkron.
3. Putus akses dari host tempat akun dipakai penyerang (isolasi host), karena tiket dan token yang tersisa paling mungkin dipakai dari sana.
4. Untuk akun service: rotasi kredensial bersama pemilik aplikasi, dan batasi dari mana akun boleh login.

### 1.6 Memblok IOC: perlu, tetapi bukan containment sendirian

Pertanyaan keenam Hendra ("kalau IP penyerang diblok, cukup?") adalah salah paham yang paling sering muncul dari pimpinan dan juga dari analyst.

Playbook CISA mencantumkan blok dan pencatatan akses tidak sah, sumber malware, dan trafik keluar ke IP penyerang, serta mencegah resolusi DNS untuk domain penyerang, sebagai langkah containment [S3]. AA20-245A memberi dua peringatan di sisi lain [S4]:

- **Blok infrastruktur penyerang sebelum waktunya** adalah kesalahan umum. Penyerang bisa mengganti C2 dengan murah, dan defender kehilangan visibilitas atas aktivitasnya.
- **Memperbaiki gejala saja**, misalnya memblok satu IP tanpa memahami biner yang menghubunginya dan bagaimana biner itu masuk, membuat penyerang tetap punya akses.

Jadi blok IOC dijalankan di jam H bersama tindakan lain, bukan saat IOC pertama kali ditemukan. Blok juga dibuat sedemikian rupa sehingga tetap memberi visibilitas:

- **Firewall:** deny dengan logging, sehingga setiap percobaan koneksi tercatat dengan IP sumbernya.
- **DNS sinkhole:** di resolver internal, domain C2 diarahkan ke IP sinkhole internal (`10.20.99.99` di `jkt-sink01`) yang mencatat setiap koneksi. Host yang masih mencoba menghubungi C2, termasuk host yang belum ditemukan saat scoping, akan muncul di log sinkhole.

Batasnya: sinkhole hanya menangkap host yang memakai resolver internal. Host yang memakai DNS over HTTPS, resolver luar, atau langsung menghubungi IP tidak tertangkap di sinkhole, sehingga blok IP di firewall tetap diperlukan.

### 1.7 Serentak di jam H, lalu buktikan berhasil

Pertanyaan terakhir Hendra punya dua bagian: bagaimana supaya penyerang tidak pindah, dan bagaimana tahu containment berhasil.

**Serentak.** Bila tindakan dijalankan satu per satu, tindakan pertama memberi tahu penyerang, dan sisa aksesnya masih terbuka. Penyerang di `jkt-billing01` yang melihat beacon dari laptop Andi berhenti bisa memakai koneksi database yang masih ada untuk mengambil data secepatnya, atau membuat kunci SSH baru. Prinsip menghindari tipping off di playbook CISA dan AA20-245A [S3][S4] diterjemahkan PT JAB menjadi jam H: semua tindakan disiapkan, diuji bila mungkin, dibagi ke pelaksana dengan urutan menit, lalu dijalankan dalam jendela pendek. Urutan di dalam jendela juga dipikirkan: jalur C2 dan jalur keluar server diputus lebih dulu, supaya penyerang tidak bisa bereaksi lewat kanal itu selama akun dan host lain sedang ditahan.

**Terbukti berhasil.** Playbook CISA meminta tim memantau tanda reaksi penyerang terhadap containment, kembali ke analisis untuk memperbarui scope bila tanda kompromi baru ditemukan, dan memastikan cakupan containment meliputi semua aktivitas terkait. Kondisi selesainya adalah containment yang berhasil, yaitu tidak ada tanda kompromi baru; setelah itu bukti disimpan, alat deteksi disesuaikan, dan tim pindah ke eradication [S3]. Rev. 3 meminta status semua insiden dilacak dan divalidasi supaya kebutuhan perubahan strategi cepat terlihat (RS.MA-04) [S1].

PT JAB menuliskannya menjadi kriteria selesai containment:

1. Semua tindakan di rencana jam H terverifikasi berjalan (bukan hanya diperintahkan).
2. Tidak ada koneksi baru ke C2, sinkhole, atau tujuan yang diblok dari host mana pun selama 24 jam, kecuali dari host yang sudah ditahan dan sudah dijelaskan.
3. Tidak ada login berhasil dari akun yang ditahan, dan kegagalan login dari akun itu ditelusuri sumbernya.
4. Tidak ada tanda reaksi penyerang (akun baru, kunci SSH baru, persistence baru) di host dan sistem dalam scope.
5. Scope statement diperbarui dan disetujui IC.

Bila salah satu gagal, insiden kembali ke scoping dan containment diperluas. Mengikuti siklus di Day 01 bagian 1.5, ini bukan kegagalan proses; ini proses yang bekerja seperti seharusnya.

## 2. Contoh artefak dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Query Splunk memakai index PT JAB dengan field mengikuti CIM (`query` dan `src` untuk DNS, `src_ip`, `dest_ip`, dan `action` untuk firewall); cocokkan dengan add-on yang kamu pakai.

### 2.1 Memo keputusan containment `jkt-billing01`

Memo ini menjawab pertanyaan 1 sampai 3 Hendra. Disiapkan Dimas dan Sari, dikirim 14:55, diputuskan Hendra 15:10. Perhatikan bagian "Keputusan" yang mencatat delegasi bersyarat.

```
INC-2026-019 | Memo keputusan containment jkt-billing01 | Selasa 2026-10-13 14:55 WIB
Untuk: Hendra Wijaya (executive sponsor) | Dari: Dimas Prasetyo (IC), Sari Kusuma (TL)
Dikonsultasikan: Bambang Hartono (NOC), Wahyu Nugroho (Lead Aplikasi Billing),
                 Ratna Sari (Legal), Agus Setiawan (DPO)
Severity: SEV-1 sejak 13:35

SITUASI
- Proses penyerang kworkerd (PID 23817) di jkt-billing01 terhubung ke C2 dan ke
  database jkt-billingdb01:5432. Log database hanya mencatat koneksi, bukan query.
- Bukti memori dan artefak sudah diambil (E04 sampai E07). Retainer menganalisis E05.
- Persistence yang diketahui: cron milik svc_billing. Akses masuk: SSH svc_billing
  dengan password yang bocor dari skrip di JKT-WS-0388.

PILIHAN
A. Matikan jkt-billing01 sampai rebuild
   + Akses penyerang ke server dan database dari server ini berhenti total
   - Pembayaran dan tagihan online berhenti, perkiraan 24-48 jam sampai rebuild
   - Bukti: tidak ada tambahan yang hilang (memori sudah diambil)
B. Containment parsial, server tetap melayani (rekomendasi IC)
   1. Firewall data center: egress jkt-billing01 hanya ke jkt-billingdb01:5432,
      payment gateway 198.51.100.80:443, jkt-ntp01, dan Splunk forwarder; lainnya
      deny + log. SSH masuk hanya dari jkt-bastion01.
   2. Hentikan PID 23817 dan nonaktifkan cron svc_billing (setelah bukti, sudah).
   3. Rotasi password svc_billing; login svc_billing hanya publickey dari 10.20.1.15.
   4. Rotasi kredensial database billing_app bersama Tim Aplikasi Billing
      (portal pembayaran berhenti sekitar 10 menit, 16:02-16:12).
   5. Logging query database diaktifkan sementara; pemantauan proses tiap jam.
   + Layanan tetap jalan; akses penyerang yang diketahui tertutup
   - Parsial: persistence yang belum ditemukan bisa tersisa sampai rebuild
   Durasi: maksimal 72 jam, sampai rebuild (eradication)
C. Tunda containment 24 jam untuk mengamati penyerang (usulan awal retainer)
   - Ditolak IC dan Legal: data pribadi pelanggan; PT JAB tidak punya sandbox;
     membiarkan akses berlanjut menambah risiko dan tanggung jawab hukum

KEPUTUSAN (Hendra Wijaya, 15:10)
- Pilihan B, mulai jam H 16:00.
- Delegasi tertulis: IC boleh langsung menjalankan pilihan A tanpa menunggu
  executive sponsor bila salah satu terjadi: (1) koneksi keluar jkt-billing01 ke
  tujuan selain allowlist, (2) query ke tabel pelanggan oleh akun atau proses
  tak dikenal di log database, (3) proses atau cron penyerang muncul kembali.
- Corporate Communication (Maya Lestari) menyiapkan pemberitahuan pemeliharaan
  singkat portal pembayaran 16:00-16:15.
```

Cara membaca elemennya:

- **Setiap pilihan ditulis dengan plus, minus, dan durasi** mengikuti kriteria bagian 1.2, sehingga Hendra membandingkan hal yang sama untuk setiap pilihan.
- **Pilihan C tetap ditulis** beserta alasan penolakannya. Bila nanti ada yang bertanya kenapa penyerang tidak diamati lebih lama, jawabannya sudah tercatat.
- **Delegasi bersyarat** memindahkan keputusan yang sudah diambil ke depan: bila pemicu terjadi pukul 02:00, IC tidak perlu membangunkan Hendra untuk memutuskan hal yang sudah disepakati.

**Kapan gagal:** memo hanya menulis rekomendasi tanpa pilihan lain, atau menulis pilihan tanpa harga layanan. Executive sponsor tidak bisa memutuskan dengan sadar, dan keputusan itu kembali dipertanyakan setelah insiden.

### 2.2 Rencana containment jam H

Rencana ini menjawab pertanyaan 4 sampai 7 Hendra. Kolom R dan A mengikuti RACI PT JAB (Day 02 bagian 2.2). Baca kolom "Verifikasi", karena tindakan tanpa verifikasi hanya perintah, bukan containment.

| Menit | Tindakan | R (pelaksana) | A | Verifikasi | Rollback bila gagal |
|---|---|---|---|---|---|
| H-30 (15:30) | Go/no-go: semua pelaksana siap di bridge NOC, akses diuji, kredensial baru disiapkan | Semua | IC | Setiap pelaksana menjawab "siap" | Mundurkan jam H, catat alasan |
| H+0 | Firewall data center: egress allowlist dan SSH dari bastion saja untuk `jkt-billing01` | NOC | IC | Hit deny di log firewall; aplikasi masih menjawab | Kembalikan ACL lama, eskalasi ke IC |
| H+0 | Blok `203.0.113.77` di firewall perimeter dengan logging; sinkhole `cdn-sync.example.net` ke `10.20.99.99` di `jkt-res01`, `jkt-res02`, `bdg-res01` | NOC | IC | Query resolver mengembalikan `10.20.99.99`; log deny muncul | - |
| H+0 | Isolasi penuh `JKT-WS-0388` lewat Defender | Yoga | IC | Status isolasi di Action center | - |
| H+0 | Port switch `BDG-WS-0142` dimatikan; Wi-Fi laptop dimatikan tanpa restart | NOC Bandung, Fajar | IC | Tidak ada MAC di switch; tidak ada DHCP lease baru | - |
| H+2 | Hentikan PID 23817, nonaktifkan cron `svc_billing` | Yoga | IC | `ps` dan `crontab -l` dicek ulang; koneksi ke C2 hilang dari `ss` | - |
| H+2 | Rotasi password `svc_billing`, ubah login jadi publickey dari `10.20.1.15` saja | Tim Aplikasi Billing | IC | Login password ditolak; job ekspor tetap jalan | Job ekspor manual sementara |
| H+2 sampai H+12 | Rotasi kredensial `billing_app` di database dan aplikasi | Tim Aplikasi Billing | Hendra (dampak layanan) | Portal pembayaran pulih; login lama ditolak database | Prosedur rollback aplikasi |
| H+3 | `andi.pratama`, `dewi.anggraini`: disable AD, reset password dua kali, revoke sessions Entra | Infrastruktur | IC | Status akun; log sign-in Entra | - |
| H+5 | Purge email phishing dari 9 mailbox; blok pengirim dan hash lampiran | Sari | IC | Hasil purge per mailbox | - |
| H+10 | Validasi putaran 1 (bagian 2.4); update ke Hendra | Sari, Dimas | IC | Query validasi | Kembali ke scoping bila ada temuan |

Cara membaca elemennya:

- **Jalur C2 dan jalur keluar server di H+0** memutus kanal penyerang sebelum proses dihentikan dan akun ditahan, sesuai urutan di bagian 1.7.
- **Rotasi `billing_app` punya A Hendra**, karena menghentikan portal pembayaran 10 menit adalah dampak layanan pelanggan, walaupun sudah diputuskan di memo.
- **Rollback** ditulis untuk tindakan yang bisa merusak layanan. Tindakan tanpa rollback yang aman, seperti isolasi workstation, tidak perlu rollback karena dampaknya hanya ke satu pengguna.

**Kapan gagal:** rencana dijalankan tanpa go/no-go, lalu di menit H+2 ternyata Tim Aplikasi Billing belum menyiapkan kredensial baru. Tindakan lain sudah jalan, penyerang sudah tahu, dan satu akses tetap terbuka.

### 2.3 Containment akun: perintah dan cara membacanya

Langkah ini menjawab pertanyaan kelima Hendra untuk akun karyawan. Perintah dijalankan tim Infrastruktur dari jump host admin, mengikuti langkah di dokumentasi Microsoft [S6].

**Tujuan:** menonaktifkan akun di AD, mereset password dua kali dengan nilai acak, lalu mencabut refresh token di Entra ID.

```powershell
# AD on-premises (modul ActiveDirectory)
Disable-ADAccount -Identity andi.pratama
Set-ADAccountPassword -Identity andi.pratama -Reset -NewPassword (Read-Host -AsSecureString "Password acak 1")
Set-ADAccountPassword -Identity andi.pratama -Reset -NewPassword (Read-Host -AsSecureString "Password acak 2")

# Entra ID (Microsoft Graph PowerShell SDK)
Connect-MgGraph -Scopes "User.ReadWrite.All","Directory.AccessAsUser.All"
$User = Get-MgUser -Search UserPrincipalName:'andi.pratama@jab.example' -ConsistencyLevel eventual
Revoke-MgUserSignInSession -UserId $User.Id
```

Penjelasan tiap bagian:

- `Disable-ADAccount` mencegah logon baru. Tiket Kerberos yang sudah terbit bisa tetap dipakai sampai pemeriksaan akun dilakukan KDC atau tiket kedaluwarsa [S7].
- Dua kali `Set-ADAccountPassword` dengan nilai acak berbeda mengurangi risiko pass-the-hash dengan hash password lama [S6]. `Read-Host -AsSecureString` dipakai supaya password tidak tertulis di riwayat perintah; dokumentasi Microsoft memakai contoh teks biasa dan memperingatkan agar contoh itu tidak dipakai [S6].
- `Revoke-MgUserSignInSession` mencabut refresh token Entra ID. Access token yang sudah terbit tetap berlaku sampai kedaluwarsa, defaultnya satu jam [S6].
- Status disable di AD tersinkron ke Entra ID pada siklus sinkronisasi berikutnya. Revoke sessions dijalankan langsung supaya pencabutan token tidak menunggu siklus itu.

Keluaran ilustrasi (diringkas):

```
PS> Get-ADUser andi.pratama -Properties Enabled,PasswordLastSet | Select Name,Enabled,PasswordLastSet
Name            Enabled  PasswordLastSet
andi.pratama    False    13/10/2026 16:03:41

PS> Revoke-MgUserSignInSession -UserId $User.Id
Value
-----
True
```

Cara membaca hasil: `Enabled False` dan `PasswordLastSet` di jam H menunjukkan disable dan reset berjalan. `True` dari revoke berarti permintaan pencabutan diterima. Keduanya belum membuktikan penyerang tidak memakai akses lama; itu dicek di validasi bagian 2.4.

**Variasi:** untuk akun yang dipakai bersama banyak layanan dan tidak bisa langsung dinonaktifkan tanpa memberi tanda ke penyerang, AA20-245A menyebut hak akses bisa dikurangi alih-alih dicabut [S4], misalnya mengeluarkan akun dari grup berhak tinggi sambil memantau pemakaiannya, sampai jam H.

**Kapan gagal:** akun admin yang menjalankan perintah ini sendiri sudah terkompromi, atau perintah dijalankan dari workstation yang termasuk scope. Jalankan dari jump host admin yang tidak termasuk scope, dengan akun yang tidak pernah login ke host terdampak.

### 2.4 Validasi setelah jam H: siapa yang masih mencoba menghubungi C2

Query ini menjawab bagian kedua pertanyaan ketujuh: bagaimana tahu containment berhasil, dan apakah ada host yang terlewat.

**Tujuan:** melihat setiap host yang masih mencoba resolve domain C2 atau terhubung ke IP C2 dan sinkhole setelah jam H.

```
(index=dns query="*cdn-sync.example.net")
OR (index=firewall dest_ip IN ("203.0.113.77", "10.20.99.99"))
earliest="10/13/2026:16:00:00" latest="10/13/2026:18:00:00"
| eval host_src=coalesce(src, src_ip)
| eval status=if(index="dns", "dns_query", action)
| stats count min(_time) as first_seen max(_time) as last_seen values(status) as status by host_src
| sort first_seen
| convert ctime(first_seen) ctime(last_seen)
```

Penjelasan tiap bagian:

- `dest_ip IN (...)` dipakai di command `search`, mencakup IP C2 asli (yang sekarang diblok) dan IP sinkhole (yang menerima koneksi untuk dicatat).
- `status` membedakan query DNS dari koneksi firewall, dan untuk firewall menampilkan `action` (`blocked` atau `allowed`).
- Rentang waktu dimulai tepat di jam H, sehingga semua hasil adalah aktivitas setelah containment.

Keluaran ilustrasi:

```
host_src      first_seen            last_seen             count  status
10.20.5.21    10/13/2026 16:00:41   10/13/2026 16:01:41       2  blocked
10.10.41.23   10/13/2026 17:12:04   10/13/2026 17:19:05      10  allowed dns_query
```

Cara membaca hasil:

- `10.20.5.21` (`jkt-billing01`) mencoba dua kali ke `203.0.113.77` pada 16:00:41 dan 16:01:41, keduanya diblok egress allowlist, lalu berhenti setelah PID 23817 dihentikan pada H+2. Pola ini sesuai harapan.
- `JKT-WS-0388` dan `BDG-WS-0142` tidak muncul. Itu sesuai harapan karena keduanya terisolasi, tetapi ketiadaan hasil saja bukan bukti; status isolasi dicek terpisah di Action center dan switch.
- `10.10.41.23` adalah temuan baru: `JKT-WS-0412` milik staf penagihan `rizky.saputra`, salah satu dari 9 penerima email, laptop tanpa EDR yang dibawa rapat di luar kantor sejak Senin dan baru tersambung ke jaringan kantor pukul 17:10. Dua query DNS (17:12:04 dan 17:17:04) diarahkan ke sinkhole, lalu delapan koneksi tiap 60 detik ke `10.20.99.99` sampai 17:19:05. Sinkhole yang mencatat menemukan host yang tidak terlihat saat scoping.

Tindak lanjut temuan itu mengikuti bagian 1.7: Dimas memerintahkan port switch `JKT-WS-0412` dimatikan pukul 17:20, akun `rizky.saputra` ditahan dengan langkah bagian 2.3, Yoga mengambil memori dan triage dari laptop itu dengan prosedur Day 04, dan Sari memperbarui scope statement menjadi v3. Kriteria selesai containment dihitung ulang dari 17:20.

**Variasi:** ganti index dan IOC dengan log autentikasi untuk akun yang ditahan, misalnya event Kerberos dan sign-in Entra ID yang gagal untuk `andi.pratama` dan `dewi.anggraini` setelah jam H, lalu telusuri dari host mana kegagalan itu datang.

**Kapan gagal:** host memakai DNS over HTTPS atau resolver luar, sehingga tidak pernah sampai ke sinkhole. Karena itu blok IP di firewall tetap dipasang, dan egress ke resolver DNS luar dari jaringan kantor sebaiknya ditutup sebagai perbaikan jangka panjang.

### 2.5 Status containment ke executive sponsor

Update ini dikirim Dimas pukul 18:00 sesuai ritme SEV-1 (update setiap 1 jam). Isinya memakai pola yang sama dengan scope statement: yang terverifikasi, yang belum, dan langkah berikutnya.

```
INC-2026-019 | Update 18:00 | SEV-1 | untuk Hendra Wijaya
CONTAINMENT (jam H 16:00)
- Terverifikasi berjalan: egress allowlist dan SSH dari bastion saja di jkt-billing01;
  blok C2 + sinkhole; isolasi JKT-WS-0388 dan BDG-WS-0142; proses dan cron
  penyerang di jkt-billing01 dihentikan; rotasi svc_billing dan billing_app
  (portal pembayaran berhenti 16:02-16:11); akun Andi dan Dewi ditahan; email purge.
- Temuan baru 17:12: laptop ketiga JKT-WS-0412 (rizky.saputra) beacon, terdeteksi
  lewat sinkhole. Ditahan 17:20; memori dan triage diambil 17:45. Scope v3.
- Belum ada tanda reaksi penyerang (akun baru, kunci SSH baru, persistence baru).
- Retainer: analisis memori jkt-billing01 berjalan, hasil awal besok 10:00.
STATUS: containment belum dinyatakan berhasil. Kriteria 24 jam tanpa tanda baru
dihitung dari 17:20.
DELEGASI AKTIF: pemicu pilihan A untuk jkt-billing01 (memo 15:10) dipantau tiap jam.
BERIKUTNYA: rencana eradication dan rebuild jkt-billing01 disiapkan malam ini.
Update berikutnya: 19:00.
```

Cara membaca elemennya:

- **"Terverifikasi berjalan"** dipisah dari "diperintahkan". Hendra tahu tindakan mana yang sudah dicek.
- **Temuan baru ditulis terang-terangan**, beserta tindakannya. Menyembunyikan temuan supaya containment terlihat mulus adalah cara paling cepat kehilangan kepercayaan pimpinan.
- **Status ditulis "belum berhasil"** dengan kriteria dan titik mulainya, bukan "sudah aman".

## 3. Lab praktik (di VM lab terisolasi)

Lab ini memakai lab Day 03 dan Day 04: VM Windows dan VM Linux dengan beacon tiruan ke `c2.lab.test`, Splunk, dan bila ada, domain controller lab. Semua langkah di VM lab dengan snapshot. Jangan memakai data, nama, atau kejadian dari pekerjaan nyata.

1. **Memo pilihan.** Anggap VM Linux adalah server yang tidak boleh mati. Tulis memo keputusan dengan format bagian 2.1, minimal tiga pilihan, masing-masing dengan plus, minus, durasi, dan satu delegasi bersyarat.
2. **Egress allowlist.** Di VM Linux, buat aturan firewall host (`nftables` atau `iptables`) yang hanya mengizinkan koneksi keluar ke Splunk forwarder dan satu tujuan "sah" di lab, dengan logging untuk yang ditolak. Pastikan beacon tiruan ditolak dan tercatat, dan tujuan sah tetap jalan.
3. **DNS sinkhole.** Di DNS lab, arahkan `c2.lab.test` ke IP VM sinkhole yang menjalankan web server pencatat. Pastikan beacon Windows muncul di log sinkhole dan di Splunk.
4. **Containment akun (bila ada DC lab).** Buat akun uji, login di VM Windows, lalu nonaktifkan akun itu dari DC. Catat apa yang masih bisa dilakukan sesi yang sudah login (misalnya akses share yang sudah terbuka) dan event apa yang muncul di DC saat akun mencoba meminta tiket baru.
5. **Jam H.** Tulis rencana jam H dengan format bagian 2.2 untuk langkah 2 sampai 4, lalu jalankan semuanya dalam lima menit. Catat waktu aktual setiap tindakan.
6. **Validasi dan host terlewat.** Sebelum jam H, siapkan VM Windows kedua yang mati dengan beacon tiruan yang sama. Nyalakan VM itu 30 menit setelah jam H. Jalankan query bagian 2.4 dan pastikan host itu muncul lewat sinkhole. Tulis update status dengan format bagian 2.5.

**Hasil yang sebaiknya tersimpan:**

- `latihan/day05-memo.md` berisi memo keputusan dengan tiga pilihan dan delegasi bersyarat.
- Aturan egress allowlist dan cuplikan log yang menunjukkan beacon ditolak.
- Konfigurasi sinkhole dan cuplikan log sinkhole.
- Catatan langkah 4 tentang apa yang masih berjalan setelah akun dinonaktifkan.
- `latihan/day05-jam-h.md` berisi rencana jam H, waktu aktual, hasil validasi, dan update status.

**Variasi tantangan:** ubah beacon tiruan di VM kedua agar memakai DNS over HTTPS ke resolver di luar lab, atau langsung ke IP. Apakah sinkhole masih menangkapnya? Kontrol apa yang harus ada supaya host itu tetap terlihat?

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat containment dijalankan. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Perangkat tidak pulih setelah dilepas dari isolasi | Lingkungan dengan PAC, WPAD, atau proxy statis | Pakai isolasi selektif di lingkungan proxy [S5] |
| Perangkat terisolasi tidak lagi terlihat di konsol EDR | VPN full tunnel memutus jalur ke layanan Defender | Split tunnel untuk trafik Defender [S5] |
| Semua VM di satu host ikut terputus | Server Hyper-V diisolasi | Isolasi VM-nya, bukan host Hyper-V [S5] |
| Isolasi Linux terlepas sendiri | Admin mengubah atau menambah aturan `iptables` | Koordinasikan perubahan firewall host selama isolasi [S5] |
| Akun sudah dinonaktifkan tetapi aktivitas masih terlihat | Tiket Kerberos, access token, atau session token aplikasi yang sudah terbit | Isolasi host sumber; revoke sessions; tunggu dan pantau kedaluwarsa token [S6][S7] |
| Aplikasi berhenti setelah akun service dirotasi | Kredensial baru belum dipasang di aplikasi | Rotasi dikerjakan pemilik aplikasi dengan prosedur dan rollback |
| Penyerang muncul dari IP atau domain lain | Blok IOC tanpa menutup akses lain, atau blok terlalu dini | Kembali ke scoping; blok IOC hanya di jam H bersama tindakan lain [S4] |
| Host baru ditemukan setelah containment | Host di luar visibilitas saat scoping | Sinkhole dengan logging; perbarui scope; perluas containment [S3] |
| Pimpinan menganggap insiden selesai setelah jam H | Update tidak memisahkan "diperintahkan" dari "terverifikasi" | Tulis kriteria selesai containment dan status terhadap kriteria itu |

## 5. Kesalahan umum dan jebakan

- Menganggap host yang sudah diisolasi pasti aman dari kerusakan lebih lanjut. Malware lokal tetap bisa merusak data [S2].
- Mengisolasi atau memblok satu per satu sejak IOC pertama ditemukan. Penyerang diberi tahu, dan sisa aksesnya tetap terbuka [S3][S4].
- Mengira disable akun langsung memutus semua akses. Tiket Kerberos, access token, dan session token aplikasi bisa tetap berlaku untuk sementara [S6][S7].
- Me-reset kredensial sebelum scope diketahui. Penyerang yang memegang kredensial lain hanya diberi tahu [S4].
- Memblok IP C2 dan menganggap selesai. Itu memperbaiki gejala, bukan akses [S4].
- Memblok tanpa logging. Visibilitas atas host yang masih mencoba menghubungi C2 hilang.
- Menunda containment berhari-hari untuk mengamati penyerang tanpa sandbox, tanpa Legal, dan tanpa batas waktu. Rev. 2 menyebut organisasi bisa ikut bertanggung jawab [S1][S2].
- Membiarkan IC memutuskan mematikan layanan pelanggan. Itu keputusan executive sponsor, kecuali sudah didelegasikan tertulis dengan syarat.
- Menulis "containment selesai" saat tindakan baru diperintahkan, bukan diverifikasi, dan sebelum periode tanpa tanda baru terlewati [S3].
- Menjalankan containment akun dari workstation atau akun admin yang termasuk scope.

## 6. Catatan terkini

Bagian ini menampung detail versi dan perilaku produk yang bisa berubah. Berguna saat memakai fitur yang disebut, tetapi tidak mengubah cara memilih strategi.

- **Defender for Endpoint**: halaman response actions yang diperiksa bertanggal 23 Juli 2026. Selain isolasi manual, halaman itu menyebut isolasi otomatis lewat automatic attack disruption (preview) untuk workstation pengguna akhir, dengan pengecualian yang bisa diatur untuk perangkat kritis bisnis [S5]. Status preview dan cakupannya bisa berubah; cek di tenant-mu.
- **Defender for Endpoint Plan 1** hanya punya sebagian aksi respons manual (antara lain scan antivirus dan isolasi perangkat); aksi lengkap seperti live response dan paket investigasi butuh Plan 2 [S5].
- **Entra ID**: halaman pencabutan akses darurat bertanggal 19 Juni 2026. Modul PowerShell Azure AD dan MSOnline sudah usang; langkah di halaman itu memakai Microsoft Graph PowerShell SDK [S6].
- **MS-KILE**: rumusan pemeriksaan akun pada permintaan tiket memakai batas waktu yang ditentukan implementasi, dengan nilai Windows ada di catatan kaki spesifikasi [S7]. Versi lama spesifikasi menulis angka tetap; bila kamu menemukan angka berbeda di materi lain, cek tanggal dokumennya.
- **NIST SP 800-61 Rev. 3** memindahkan pembahasan strategi containment ke kategori RS.MI dan subkategori RS.MI-01, dan menambahkan saran otomatisasi containment serta wewenang pihak ketiga seperti ISP dan penyedia cloud untuk menahan jenis insiden tertentu, misalnya DDoS besar [S1].

## 7. Cheat sheet

```
SEMUA CONTAINMENT SEMENTARA
  jangka pendek: hentikan penyebaran sekarang (isolasi, blok, disable)
  jangka panjang: batasi sambil layanan jalan sampai eradication (ACL, rotasi, pantau)
  durasi contoh NIST: darurat (jam) | sementara (2 minggu) | permanen

KRITERIA (r2 + r3 + CISA): kerusakan/pencurian | bukti | layanan | waktu+sumber daya
  | efektivitas (parsial/penuh) | durasi | + jenis insiden, faktor risiko RS.MA

TUNDA: untuk BERSIAP (jam, batas waktu, pemicu segera)  !=  untuk MENGAMATI
  mengamati: sandbox + Legal + exec sponsor + SOC matang; selain sandbox jangan (r2)

HOST: EDR isolasi tetap terhubung ke Defender | selektif di lingkungan proxy
  full tunnel VPN putus dari Defender | Hyper-V host = semua VM | Linux: iptables
  tanpa EDR: port switch/VLAN karantina + matikan Wi-Fi tanpa restart
  server tak boleh mati: egress allowlist + akses masuk dibatasi + rotasi + hentikan proses
  isolasi != kerusakan lokal berhenti

AKUN: disable AD + reset 2x (pass-the-hash) + revoke sessions Entra + isolasi host sumber
  Kerberos: tiket terbit tetap berlaku sampai cek akun/kedaluwarsa (KDC_ERR_CLIENT_REVOKED)
  Entra: access token default 1 jam; session token aplikasi sendiri
  akun service: rotasi bersama pemilik aplikasi, batasi sumber login
  JANGAN reset dini sebelum scope

IOC: blok di jam H, bukan saat ditemukan | firewall deny + LOG | DNS sinkhole yang mencatat
  sinkhole buta terhadap DoH/resolver luar/IP langsung

JAM H: go/no-go H-30 | C2 + egress dulu | host + proses | akun | email | validasi H+10
  R/A per RACI | verifikasi per tindakan | rollback untuk yang menyentuh layanan

SELESAI bila: semua tindakan terverifikasi | 24 jam tanpa koneksi baru ke C2/sinkhole
  | tanpa login akun yang ditahan | tanpa reaksi penyerang | scope diperbarui
  temuan baru -> kembali ke scoping, hitung ulang dari awal
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "`JKT-WS-0388` sudah diisolasi lewat EDR, jadi malware di laptop itu sudah tidak bisa merusak apa-apa." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Isolasi memutus jaringan, tetapi proses di host tetap berjalan. Rev. 2 memberi contoh proses berbahaya yang menimpa atau mengenkripsi data di disk begitu koneksinya gagal, dan mengingatkan bahwa host yang sudah diputus belum tentu aman dari kerusakan lebih lanjut. Isolasi menahan penyebaran dan kendali dari luar; menghentikan dan membersihkan malware adalah pekerjaan berikutnya. Lihat bagian 1.4.

</details>

**2. Skenario keputusan.** Hendra harus memutuskan containment `jkt-billing01`. Pilihan mana yang paling tepat dalam situasi PT JAB pukul 15:10?

- A. Mematikan server sekarang juga dan menghentikan pembayaran online sampai rebuild, karena itu satu-satunya containment yang penuh.
- B. Containment parsial dengan egress allowlist, akses SSH dari bastion saja, penghentian proses penyerang, rotasi kredensial, dan logging query, berlaku sampai rebuild, ditambah delegasi bagi IC untuk mematikan server bila pemicu tertentu terjadi.
- C. Menunda containment 24 jam supaya retainer bisa mengamati penyerang dan mempelajari tujuannya.

<details><summary>Jawaban</summary>

B. Bukti sudah diamankan, akses penyerang yang diketahui bisa ditutup tanpa mematikan layanan, dan pemicu tertulis memastikan pilihan A tetap tersedia tanpa menunggu rapat bila keadaan memburuk. A tidak salah secara teknis, tetapi harganya pembayaran online berhenti 24-48 jam, padahal ada pilihan dengan risiko yang bisa dipantau; keputusan itu milik executive sponsor dan harus dibandingkan dengan pilihan lain. C keliru karena data pribadi pelanggan terlibat, PT JAB tidak punya sandbox, dan Rev. 2 menyebut pemantauan penyerang selain sandbox tidak boleh dipakai karena organisasi bisa ikut bertanggung jawab. Lihat bagian 1.1, 1.2, 1.3, dan 2.1.

</details>

**3. Pertanyaan jebakan.** "Akun `andi.pratama` dinonaktifkan di AD pukul 16:03, jadi sejak 16:03 penyerang tidak bisa memakai akun itu di mana pun." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Kerberos tidak mencabut tiket yang sudah terbit; KDC baru memeriksa status akun saat TGT yang dipakai lebih tua dari batas yang ditentukan implementasi, lalu menolak dengan `KDC_ERR_CLIENT_REVOKED`. Di Entra ID, revoke sessions mencabut refresh token, tetapi access token yang sudah terbit tetap berlaku sampai kedaluwarsa (default satu jam), dan aplikasi dengan session token sendiri baru berhenti saat sesinya berakhir. Karena itu disable akun dijalankan bersama reset password dua kali, revoke sessions, dan isolasi host sumber. Lihat bagian 1.5 dan 2.3.

</details>

**4. Skenario keputusan.** Pukul 10:50, saat scoping baru dimulai, Yoga mengusulkan, "Kita blok saja `203.0.113.77` di firewall sekarang, biar aman sambil scoping." Respons mana yang tepat?

- A. Setuju, karena blok IP murah dan tidak ada ruginya.
- B. Tunda blok ke jam H bersama tindakan lain, kecuali ada kerusakan yang sedang berjalan; sementara itu pastikan log firewall dan DNS untuk IOC itu terekam untuk scoping.
- C. Setuju, dan sekaligus reset password Andi supaya penyerang kehilangan akses.

<details><summary>Jawaban</summary>

B. AA20-245A menyebut blok infrastruktur penyerang sebelum waktunya sebagai kesalahan umum: penyerang mengganti C2 dengan murah dan defender kehilangan visibilitas, termasuk visibilitas atas host lain yang memakai C2 yang sama, yang di `INC-2026-019` justru dipakai untuk menemukan `jkt-billing01`. A keliru karena blok dini ada ruginya: tipping off dan hilangnya visibilitas. C keliru karena reset kredensial sebelum scope diketahui juga kesalahan umum; saat itu password `svc_billing` sudah bocor dan belum diketahui. Lihat bagian 1.3, 1.5, dan 1.6.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Maya Lestari (Corporate Communication), dalam tiga kalimat, kenapa semua tindakan dijalankan serentak pukul 16:00, bukan satu per satu sejak pagi.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Penyerang bisa melihat ketika salah satu jalurnya kita putus, dan kalau kita memutus satu per satu, ia punya waktu untuk pindah ke jalur lain yang belum kita tutup atau mempercepat pengambilan data. Pagi tadi kita juga belum tahu semua jalurnya, jadi kita pakai beberapa jam untuk menemukannya dan menyimpan bukti sambil memantau ketat, dengan aturan bahwa kita langsung bertindak kalau ada tanda bahaya. Jam 16:00 semua tim menutup semua jalur yang sudah kita ketahui dalam beberapa menit, termasuk pemeliharaan singkat portal pembayaran yang pengumumannya sedang kamu siapkan."

Kesalahan yang sering muncul:
- Memakai istilah seperti "tipping off", "scope", atau "IOC" yang tidak dibutuhkan tim komunikasi.
- Tidak menyebut bahwa penundaan punya batas dan pemicu, sehingga terdengar seperti membiarkan penyerang.
- Tidak mengaitkan dengan apa yang perlu dilakukan Maya.

</details>

**6. Pertanyaan jebakan.** "Semua tindakan di rencana jam H sudah dijalankan pukul 16:12, jadi containment `INC-2026-019` selesai dan tim bisa pindah ke eradication." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Tindakan yang dijalankan belum tentu terverifikasi, dan playbook CISA menetapkan containment berhasil bila tidak ada tanda kompromi baru, sambil memantau reaksi penyerang dan kembali ke scoping bila ada temuan baru. Di `INC-2026-019`, sinkhole menemukan `JKT-WS-0412` pukul 17:12, sehingga scope diperbarui, containment diperluas, dan hitungan 24 jam tanpa tanda baru dimulai ulang dari 17:20. Lihat bagian 1.7, 2.4, dan 2.5.

</details>

**7. Interview question (English).** "How do you decide between containing an attacker immediately and continuing to monitor them?"

<details><summary>Sample answer</summary>

"I separate two kinds of delay. If something destructive is happening, like encryption or data being pulled out, I contain immediately and accept that some evidence or visibility is lost. If the activity is quiet, I may delay for a few hours to prepare: finish enough scoping to know every host, account and persistence type we're aware of, and preserve volatile evidence, so that containment can be done in one coordinated window instead of piecemeal, which would tip the attacker off. That delay has a written time limit and triggers that bring containment forward. Deliberately leaving an attacker active to study them is a different decision: it needs legal and executive sign-off, a controlled environment like a sandbox, and a mature SOC, and NIST warns that the organization can be liable if the compromised system is used against others. When personal data is at risk I almost always choose containment. After the coordinated action I don't declare success until we've verified each step and seen no new signs of compromise for an agreed period, and new findings send us back to scoping."

What makes this answer strong: it distinguishes preparing from observing, ties the choice to damage and data at risk, mentions coordinated execution and its reason, cites the legal angle, and ends with a verifiable success condition.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | NIST SP 800-61 Rev. 3 (PDF) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf | primer | April 2025; diakses 2026-10-15 | Tinggi. RS.MA-03 (trade-off strategi), RS.MA-04, kategori RS.MI (kriteria, durasi, sandbox), RS.MI-01 |
| S2 | NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide (PDF) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf | primer | Agustus 2012 (lebih dari 3 tahun, digantikan Rev. 3); diakses 2026-10-15 | Tinggi untuk bagian 3.3.1: enam kriteria strategi, sandbox, tanggung jawab hukum, kerusakan tambahan saat containment |
| S3 | CISA: Cybersecurity Incident and Vulnerability Response Playbooks (PDF) | https://www.cisa.gov/sites/default/files/publications/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf | primer | November 2021; diakses 2026-10-15 | Tinggi. Bagian Containment (pertimbangan, tipping off, aktivitas) dan Appendix B langkah 7a sampai 7n |
| S4 | CISA: Technical Approaches to Uncovering and Remediating Malicious Activity (AA20-245A) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-245a | primer | 2020-09-01, revisi 2020-09-24 (lebih dari 3 tahun); diakses 2026-10-15 | Tinggi. Mitigasi tanpa membuat penyerang sadar, kesalahan umum (blok dini, reset kredensial dini, memperbaiki gejala), mengurangi hak alih-alih mencabut |
| S5 | Microsoft Learn: Take response actions on a device in Microsoft Defender for Endpoint | https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts | primer (dokumentasi vendor) | ms.date 2026-07-23; diakses 2026-10-15 | Tinggi. Isolasi penuh dan selektif, catatan proxy, VPN, Hyper-V, Linux, percobaan ulang, pelepasan tujuh hari, peran, Plan 1 vs Plan 2 |
| S6 | Microsoft Learn: Revoke user access in an emergency in Microsoft Entra ID | https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access | primer (dokumentasi vendor) | ms.date 2026-06-19; diakses 2026-10-15 | Tinggi. Disable dan reset dua kali di AD, revoke sessions, umur access token, session token aplikasi, CAE |
| S7 | Microsoft Learn: [MS-KILE] Check Account Policy for Every Session Ticket Request | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/e19be8b8-9130-40a4-9cd1-92d0cbd46a51 | primer (spesifikasi protokol) | diperbarui 2026-04-27; diakses 2026-10-15 | Tinggi. Kerberos tidak mencabut tiket sebelum kedaluwarsa; pemeriksaan akun saat TGT melewati batas waktu implementasi; `KDC_ERR_CLIENT_REVOKED` |

**Catatan sumber:** istilah containment jangka pendek dan jangka panjang di bagian 1.1 adalah pembagian catatan ini berdasarkan kriteria durasi di NIST [S1][S2] dan istilah mitigasi jangka pendek di playbook CISA [S3], bukan definisi resmi salah satu sumber. Pembedaan menunda untuk bersiap dan menunda untuk mengamati di bagian 1.3, urutan tindakan di jam H, dan lima kriteria selesai containment di bagian 1.7 adalah susunan catatan ini dari sumber yang disebut, bukan daftar resmi. Bahwa status disable di AD baru tersinkron ke Entra ID pada siklus sinkronisasi berikutnya ditulis dari cara kerja sinkronisasi umum; interval siklus di lingkunganmu perlu dicek di konfigurasi sinkronisasi. Semua isi PT JAB, termasuk durasi gangguan portal, adalah contoh fiktif.
