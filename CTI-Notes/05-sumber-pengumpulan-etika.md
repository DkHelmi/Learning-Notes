---
day: 05
title: 'Sumber pengumpulan intelijen: OSINT, vendor, ISAC, feed, dan batas etika serta legal'
researched_on: 2026-10-10
versions_checked: 'FIRST TLP 2.0 (berlaku Agustus 2022); UU 27/2022 tentang Pelindungan Data Pribadi; UU ITE (UU 11/2008 dengan perubahan UU 19/2016 dan UU 1/2024); MWR/CPNI 2015'
---

# Day 05: Sumber pengumpulan dan etika

Cakupan: jenis sumber intelijen dan cara menilainya dengan matriks sumber, evaluasi feed dengan angka, pelacakan circular reporting, pengumpulan pasif dan OPSEC, serta batas etika dan legal termasuk TLP 2.0, ToS, UU ITE, dan UU PDP.

## Ide inti

Collection (Day 02) butuh sumber, dan pilihan sumber menentukan kualitas sekaligus risiko intelijen. Sumber berbeda punya keandalan, bias, biaya, kecepatan, dan batas legal yang berbeda. Tim CTI yang baik tahu sumber mana menjawab PIR mana, tahu kapan sebuah sumber berhenti layak dibayar, dan tahu garis yang tidak boleh dilewati. Jadi setiap sumber diperlakukan sama: dinilai terhadap PIR dengan kriteria yang sama, dihitung independensinya sebelum dianggap konfirmasi, dan dikumpulkan dengan cara yang sah.

Garis itu jelas untuk catatan ini: tidak mengakses forum kriminal atau dark web, tidak berinteraksi dengan pelaku, tidak membeli data bocoran, dan tidak menyentuh infrastruktur penyerang secara aktif. Tim CTI besar kadang punya fungsi khusus untuk sebagian aktivitas tersebut, dengan persetujuan legal, kebijakan tertulis, dan infrastruktur terpisah. Itu bukan pekerjaan analis yang belajar mandiri.

Kamu sudah melakukan versi kecil pekerjaan ini saat memutuskan log source mana yang di-onboard ke SIEM. Setiap log source punya nilai (use case apa yang ditutupnya), biaya (lisensi ingest dan waktu parsing), dan kualitas (berapa banyak false positive yang dihasilkannya). Log source yang tidak pernah mendukung deteksi atau investigasi dicabut walaupun mahal. Satu event yang diteruskan oleh tiga tool juga tidak dihitung sebagai tiga insiden. Dan SOC punya batas kewenangan: boleh mengisolasi host sendiri, tetapi tidak boleh menyerang balik server penyerang. Sumber intelijen dinilai dengan logika yang sama.

```
PIR (Day 02) -> SIR
  -> pilih sumber : internal | pemerintah/CERT | OSINT | data pasif | vendor | ISAC | feed
  -> nilai        : matriks sumber (relevansi, Admiralty, waktu, independensi, biaya, TLP/legal)
  -> ukur feed    : volume, hit rate, FP rate, overlap, umur saat diterima (per kuartal)
  -> cek klaim    : telusuri kutipan -> hitung hanya sumber independen dengan akses langsung
  -> kumpulkan    : pasif dulu; OPSEC; tidak melewati garis etika dan legal
  -> tangani      : TLP, ToS/lisensi, minimisasi dan retensi data pribadi
```

Situasi yang dipakai sepanjang Day ini: pertengahan Oktober 2026, collection plan PIR-2026-003 di PT Logistik Contoh (PT LC, perusahaan logistik fiktif dengan gudang di Jakarta, Surabaya, dan Medan, dengan banyak vendor yang masuk lewat VPN) sudah berjalan. Tenggat jawabannya 2026-11-30, sebelum rapat anggaran. CISO PT LC mengirim pesan ke tim CTI:

> "Sebelum saya setujui biaya collection untuk PIR-2026-003, saya perlu beberapa jawaban. Sumber mana yang benar-benar layak dipakai dan dibayar? Feed IOC gratis yang kita pakai sekarang membuat SOC kebanjiran alert: dipertahankan atau tidak? Saya juga melihat klaim 'kelompok RANSOM-FICTA masuk lewat celah VPN merek Z' di beberapa artikel dan feed; seyakin apa kita? Tim IR ingin membuka domain phishing dan mengunggah lampiran ke sandbox publik; aman? Direktur komersial bertanya apakah kita bisa membeli dump database pelanggan yang dijual di forum untuk memastikan itu data kita. Terakhir, laporan ISAC berlabel AMBER+STRICT boleh kita teruskan ke MSSP?"

Pesan itu memuat enam pertanyaan:

1. Sumber mana yang layak dipakai dan dibayar untuk PIR-2026-003?
2. Feed IOC gratis yang membanjiri SOC: dipertahankan atau tidak?
3. Seberapa yakin klaim yang muncul di banyak artikel dan feed?
4. Amankah membuka domain phishing dan mengunggah lampiran ke layanan publik?
5. Bolehkah membeli data bocoran untuk verifikasi?
6. Bagaimana label TLP, lisensi, dan data pribadi membatasi apa yang boleh diteruskan dan disimpan?

Pertanyaan 1 dijawab di bagian 1.1 sampai 1.3 dan 2.1, pertanyaan 2 di bagian 1.5 dan 2.2, pertanyaan 3 di bagian 1.4 dan 2.3, pertanyaan 4 di bagian 1.6 dan 2.4, pertanyaan 5 di bagian 1.7 dan 2.5, dan pertanyaan 6 di bagian 1.8, 1.9, dan 2.4.

**Kapan relevan:** merancang collection plan, memutuskan langganan feed, menjawab "boleh tidak kita mengambil data ini", dan menyiapkan catatan kepatuhan.
**Kapan bukan jawaban:** ketersediaan dan syarat sumber berubah, dan detail hukum bergantung yurisdiksi. Bagian legal di sini adalah orientasi untuk analis, bukan nasihat hukum.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Tabel ini memuat istilah pengumpulan dan etika yang muncul di Day ini. Kolom padanan memakai analogi SOC yang sama di semua Day CTI. Istilah dari Day sebelumnya (feed IOC, PIR, SIR, collection plan, kode Admiralty) tidak diulang.

| Istilah | Arti singkat | Padanan di SOC |
|---|---|---|
| OSINT | Informasi dari sumber terbuka: blog peneliti, media, repositori publik | Membaca blog vendor dan advisori sebelum menulis rule |
| CERT/CSIRT | Tim tanggap insiden nasional atau sektor yang menerbitkan advisori | Pihak yang mengirim peringatan resmi ke SOC |
| ISAC | Forum berbagi informasi ancaman antar organisasi dalam satu sektor | Grup tepercaya antar SOC di sektor yang sama |
| Data infrastruktur pasif | WHOIS, passive DNS, certificate transparency, data scan yang sudah dikumpulkan pihak lain | Lookup historis yang tidak menyentuh server target |
| Matriks sumber | Tabel yang menilai setiap sumber terhadap PIR dengan kriteria yang sama | Review nilai dan biaya log source sebelum onboarding atau perpanjangan lisensi |
| Hit rate | Indikator yang cocok di telemetri dibagi volume | Seberapa sering sebuah lookup benar-benar match |
| False positive rate | Hit yang ternyata benign dibagi total hit | FP rate rule saat tuning |
| Tumpang tindih (overlap) | Indikator yang juga ada di feed lain dibagi volume | Dua log source yang mengirim event yang sama |
| Umur saat diterima | Selisih waktu first seen dan waktu masuk ke feed | Latensi ingest: event yang tiba terlambat kurang berguna untuk respons |
| Circular reporting | Beberapa sumber tampak saling mengonfirmasi padahal berakar pada satu sumber asal | Satu event yang diteruskan tiga tool dihitung tiga insiden |
| Pengumpulan pasif dan aktif | Membaca data yang sudah ada vs berinteraksi langsung dengan infrastruktur penyerang | Lookup historis vs mengklik URL phishing dari workstation |
| OPSEC | Menjaga agar aktivitas analisis tidak memberi tahu penyerang atau membuka data sendiri | Tidak memeriksa IOC dari jaringan produksi |
| TLP 2.0 | Label FIRST yang menentukan sejauh mana informasi boleh dibagikan | Klasifikasi kerahasiaan tiket insiden |
| ToS dan lisensi | Syarat penggunaan layanan, API, dan laporan berbayar | Syarat lisensi tool dan feed komersial |
| Minimisasi dan retensi | Simpan data pribadi seminimal yang dibutuhkan, dan tetapkan masa simpannya | Kebijakan retensi log per index |

### 1.1 Jenis sumber intelijen

Pertanyaan pertama CISO dimulai dari daftar: sumber apa saja yang bisa menjawab PIR-2026-003? Setiap jenis punya kekuatan dan bias yang berbeda, sehingga tidak ada satu jenis yang cukup sendirian.

Tabel berikut memetakan jenis sumber beserta kekuatan dan biasnya. Baca kolom terakhir dengan teliti, karena bias sumber yang ikut terbawa ke penilaianmu bila tidak dicatat.

| Jenis | Contoh | Kekuatan | Kelemahan dan bias |
|---|---|---|---|
| Internal | Telemetri SIEM dan EDR, laporan IR, hasil hunting, laporan phishing dari pegawai | Paling relevan; menjawab "apakah ini terjadi pada kita" | Hanya melihat yang terdeteksi; bias ke log source yang ada |
| Pemerintah dan CERT | Advisori CISA, CERT nasional, CSIRT sektor | Sering memuat TTP dan mitigasi; gratis | Bisa terlambat; fokus pada ancaman prioritas negara penerbit |
| OSINT umum | Blog peneliti, media, repositori publik | Luas dan cepat | Kualitas sangat beragam; rawan circular reporting |
| Data infrastruktur pasif | WHOIS, passive DNS, certificate transparency, data scan internet yang sudah dikumpulkan pihak lain | Bagus untuk pivot infrastruktur | Perlu keahlian membaca; sebagian berbayar |
| Vendor komersial | Laporan dan feed berbayar, layanan pemantauan kebocoran | Terkurasi, sering lebih dalam | Mahal; bias ke ancaman yang ditangani produknya; nama aktor eksklusif |
| ISAC dan komunitas | ISAC sektor, grup berbagi tepercaya | Relevan sektor; sering ada insiden yang tidak dipublikasikan | Cakupan terbatas pada anggota; terikat TLP |
| Feed teknis | Feed IOC domain, IP, hash, URL | Volume besar, mudah diotomasi | Banyak IOC basi dan false positive |

Sumber internal sering paling bernilai karena paling relevan. Dokumen MWR/CPNI mencatat bahwa insiden yang pernah dialami organisasi sendiri adalah sumber intel yang sering terlupakan, dan bahwa feed eksternal yang tidak dinilai jarang memberi manfaat [S5].

### 1.2 Matriks sumber

Setelah daftar sumber tersedia, CISO tetap perlu tahu mana yang layak dibayar. Jawabannya tidak bisa diambil dari reputasi; setiap sumber harus diukur dengan penggaris yang sama.

Untuk membandingkan sumber secara adil, nilai semuanya dengan kriteria yang sama. Tabel berikut memuat kriteria yang berguna; perhatikan baris Relevansi dan Independensi, karena keduanya yang paling sering terlewat.

| Kriteria | Pertanyaan |
|---|---|
| Relevansi | Sub-pertanyaan PIR mana yang dijawab sumber ini? |
| Keandalan | Kode Admiralty berdasarkan rekam jejak (Day 03) |
| Ketepatan waktu | Berapa jeda antara kejadian dan informasi sampai ke kita? |
| Kelengkapan | Apakah ada konteks (TTP, korban, waktu), atau hanya indikator? |
| Independensi | Apakah sumber ini punya akses langsung, atau mengutip sumber lain? |
| Format | Bisa diotomasi (STIX, CSV, API) atau harus dibaca manual? |
| Biaya | Lisensi plus waktu analis untuk memprosesnya |
| Batas legal dan TLP | Apa yang boleh dilakukan dengan informasinya? |

Matriks ini dipakai dua kali: saat menyusun collection plan, dan saat meninjau ulang langganan. Sumber yang dalam satu kuartal tidak pernah menjawab sub-pertanyaan apa pun adalah kandidat dihentikan, walaupun reputasinya bagus. Matriks untuk PIR-2026-003 ada di bagian 2.1.

### 1.3 Menilai keandalan dan bias per jenis sumber

Kode Admiralty di matriks butuh dasar. Tim CTI PT LC menerima laporan vendor, advisori, laporan ISAC, feed, dan artikel media; masing-masing dinilai dengan pertanyaan yang sedikit berbeda.

- **Laporan vendor:** perhatikan apakah klaim ditunjukkan buktinya (sampel, log, timeline) atau hanya dinyatakan. Atribusi dan perkiraan niat aktor sering dinyatakan lebih yakin daripada buktinya. Vendor juga menamai aktor dengan skema sendiri, sehingga satu kelompok bisa punya lima nama.
- **Advisori pemerintah:** biasanya kuat di TTP dan mitigasi. Indikator di advisori sering sudah berumur saat diterbitkan.
- **ISAC:** relevansinya tinggi, tetapi kualitas per laporan bergantung anggota pengirim; beri kode per laporan, bukan per ISAC.
- **Feed:** keandalan bergantung pada proses kurasi feed itu. Feed yang menerima kiriman siapa saja tanpa verifikasi perlu dinilai lebih rendah.
- **Media:** berguna sebagai sinyal awal, jarang sebagai sumber asal. Hampir selalu mengutip pihak lain.

### 1.4 Circular reporting

Pertanyaan ketiga CISO ("klaim ini muncul di beberapa artikel dan feed, seyakin apa kita?") adalah jebakan klasik. Jumlah tempat sebuah klaim muncul tidak sama dengan jumlah konfirmasi.

Circular reporting terjadi ketika beberapa sumber tampak saling mengonfirmasi padahal semuanya berakar pada satu sumber asal. Ilusi konfirmasi ini menaikkan keyakinan secara palsu. Polanya di CTI sangat umum: satu peneliti memposting temuan, dua media menulis ulang, satu vendor mengutip media, lalu feed memasukkan IOC dari blog vendor. Analis yang menghitung "empat sumber" sebenarnya punya satu.

Cara melacaknya: untuk setiap klaim penting, telusuri kutipan sampai ke pihak yang punya akses langsung ke data. Tulis rantainya. Hanya sumber yang punya akses langsung dan independen yang dihitung sebagai konfirmasi (kode kredibilitas 1 di Admiralty mensyaratkan konfirmasi oleh sumber independen). Bila semua cabang berujung ke satu titik, kredibilitas tetap dinilai dari titik itu saja. Rantai klaim RANSOM-FICTA ada di bagian 2.3.

### 1.5 Over-collection dan evaluasi feed

Pertanyaan kedua CISO menyangkut feed gratis yang membanjiri SOC. Keputusan mempertahankan atau menghentikan feed sebaiknya diambil dari angka, bukan dari kesan.

Mengumpulkan semua yang tersedia terasa produktif tetapi merusak: sinyal tenggelam, biaya penyimpanan naik, dan analis kelelahan oleh alert dari IOC basi. Collection harus dipandu PIR. Untuk feed teknis, ukur dengan angka setiap kuartal. Tabel berikut memuat lima metrik dan cara menghitungnya; kolom Arti menunjukkan pertanyaan yang dijawab tiap metrik.

| Metrik | Cara menghitung | Arti |
|---|---|---|
| Volume | Jumlah indikator baru per bulan | Beban processing |
| Hit rate | Indikator yang cocok di telemetri dibagi volume | Relevansi ke lingkungan sendiri |
| False positive rate | Hit yang ternyata benign dibagi total hit | Biaya triase |
| Tumpang tindih | Indikator yang juga ada di feed lain dibagi volume | Nilai unik feed |
| Umur saat diterima | Selisih waktu first seen dan waktu masuk ke feed | Apakah masih berguna untuk blokir |

MWR/CPNI mengutip riset yang menemukan tumpang tindih hanya sekitar 1% antar tiga feed IP populer [S5]. Angka itu sudah tua, tetapi pelajarannya tetap: tumpang tindih rendah tidak otomatis berarti cakupan luas; bisa juga berarti masing-masing feed melihat bagian kecil yang berbeda, sebagian besar tidak relevan bagimu. Evaluasi dua feed PT LC ada di bagian 2.2.

### 1.6 Pengumpulan pasif, aktif, dan OPSEC

Tim IR PT LC ingin membuka domain phishing dan mengunggah lampiran ke sandbox publik. Keduanya terasa seperti langkah investigasi biasa, tetapi keduanya termasuk pengumpulan yang bisa merugikan.

Pengumpulan pasif membaca data yang sudah ada tanpa menyentuh sistem penyerang: laporan, passive DNS, WHOIS historis, certificate transparency, data scan yang dikumpulkan pihak lain. Pengumpulan aktif berarti berinteraksi langsung dengan infrastruktur penyerang: mengunjungi URL phishing, me-resolve domain C2, memindai server, atau mengunduh file darinya.

Aktivitas aktif membawa tiga risiko. Pertama, risiko memberi tahu penyerang: kunjungan dari IP perusahaanmu ke domain yang hanya dikirim ke satu korban memberi tahu penyerang bahwa umpannya sedang diperiksa. Kedua, risiko keamanan: halaman bisa memuat exploit browser. Ketiga, risiko legal: memindai atau masuk ke server orang lain tanpa izin bisa masuk kategori akses tanpa hak, walaupun servernya dipakai penyerang.

Bentuk OPSEC yang sering terlupa:

- Mengunggah file ke sandbox atau layanan multi-antivirus publik membuat file itu bisa dilihat pelanggan layanan tersebut, termasuk penyerang yang memantau apakah malware-nya sudah ketahuan. Dokumen internal yang terlampir juga ikut terbuka. Cari hash-nya dulu; unggah hanya bila kebijakan organisasi mengizinkan.
- Me-resolve atau membuka domain mencurigakan dari jaringan kantor meninggalkan jejak di log penyerang. Bila perlu, pakai lingkungan analisis terpisah sesuai kebijakan tim.
- Akun pribadi di media sosial tidak dipakai untuk riset ancaman.

### 1.7 Garis etika dan legal

Permintaan direktur komersial untuk membeli dump database pelanggan adalah contoh permintaan yang terdengar masuk akal tetapi melewati garis. Garis itu perlu tertulis sebelum permintaan seperti ini datang.

Aktivitas berikut di luar lingkup catatan ini dan berisiko tinggi:

- **Mengakses forum kriminal atau dark web.** Risiko hukum, risiko malware, dan risiko terekspos ke pelaku. Informasi dari sana diperoleh lewat laporan vendor yang punya fungsi khusus untuk itu.
- **Berinteraksi dengan pelaku.** Negosiasi, penyamaran, atau membeli akses bukan aktivitas analis.
- **Membeli atau mengunduh data bocoran.** Selain membiayai kejahatan, memperoleh data pribadi orang lain secara melawan hukum diancam pidana. UU 27/2022 tentang Pelindungan Data Pribadi melarang memperoleh atau mengumpulkan data pribadi yang bukan miliknya secara melawan hukum untuk menguntungkan diri atau orang lain (Pasal 65 ayat 1), dengan ancaman pidana penjara paling lama lima tahun dan/atau denda paling banyak Rp5 miliar (Pasal 67 ayat 1) [S4].
- **Mengakses sistem tanpa izin,** termasuk server C2 atau panel penyerang. Di Indonesia, mengakses sistem elektronik orang lain tanpa hak diatur sebagai tindak pidana di UU ITE (Pasal 30) [S6]; sejak KUHP baru berlaku pada Januari 2026, sebagian ketentuan pidana ITE juga diatur di KUHP. Cek pasal yang berlaku dengan tim legal sebelum menulis kebijakan.

Bila sebuah PIR seolah butuh sumber terlarang, itu tanda untuk mengubah pendekatan: pakai laporan vendor yang memantau sumber itu secara sah, minta bantuan ISAC atau CERT, atau persempit PIR-nya. Catatan keputusan untuk permintaan dump database ada di bagian 2.5.

### 1.8 TLP 2.0

Pertanyaan terakhir CISO menyangkut laporan ISAC berlabel AMBER+STRICT. Label itu menentukan siapa yang boleh menerima isinya, termasuk dalam dokumen yang kamu tulis sendiri.

Traffic Light Protocol versi 2.0 dari FIRST dipakai luas oleh CERT, ISAC, dan vendor [S2]. Labelnya ditulis persis seperti ini, tanpa spasi, dalam huruf kapital, dan tidak diterjemahkan. Tabel berikut memuat kelima label; perhatikan beda AMBER+STRICT dan AMBER, karena di situlah batas antara organisasi sendiri dan kliennya ditentukan.

| Label | Boleh dibagikan ke | Contoh pemakaian |
|---|---|---|
| TLP:RED | Hanya penerima langsung; di rapat, hanya peserta rapat | Detail insiden yang sedang berjalan dengan nama korban |
| TLP:AMBER+STRICT | Hanya di dalam organisasi penerima, atas dasar need-to-know | Indikator yang bisa membuka identitas korban |
| TLP:AMBER | Di dalam organisasi penerima dan kliennya, atas dasar need-to-know | Laporan ISAC yang perlu ditindaklanjuti penyedia layanan |
| TLP:GREEN | Komunitas penerima (rekan dan mitra), tetapi tidak lewat kanal publik | Advisori untuk anggota sektor |
| TLP:CLEAR | Siapa saja, tunduk pada hak cipta | Laporan publik |

Dua hal praktis. TLP:CLEAR menggantikan TLP:WHITE di versi 1.0, jadi dokumen lama masih memakai WHITE. Label menempel pada informasi, bukan pada dokumen turunanmu: bila brief untuk CISO memuat satu paragraf dari laporan TLP:AMBER+STRICT, brief itu tidak boleh dikirim ke vendor MSSP walaupun sisanya CLEAR. Melanggar TLP merusak kepercayaan dan biasanya berakhir dengan dikeluarkan dari komunitas.

### 1.9 ToS, privasi, dan retensi

Selain TLP, laporan vendor berbayar dan data pribadi yang ikut terkumpul juga membatasi apa yang boleh disalin dan berapa lama disimpan. Di PT LC, contohnya adalah laporan Vendor A dan daftar akun pegawai yang muncul di kebocoran.

- **ToS dan lisensi:** patuhi syarat layanan dan batas API. Laporan berbayar biasanya melarang redistribusi; menyalin isinya ke wiki yang bisa dibaca kontraktor bisa melanggar lisensi.
- **Minimisasi:** intelijen sering menyentuh data pribadi (nama, email, nomor telepon, IP pengguna rumahan). Simpan seminimal yang dibutuhkan PIR. Daftar email pegawai yang muncul di kebocoran cukup disimpan sebagai daftar akun yang perlu reset, tanpa kata sandinya.
- **Retensi:** tetapkan masa simpan per jenis data, misalnya IOC teknis 12 bulan, catatan RFI dua tahun, data pribadi sampai tindakan selesai. UU PDP mewajibkan pengendali data memproses data pribadi secara terbatas dan spesifik sesuai tujuan; detail kewajiban untuk organisasimu perlu dicek dengan tim legal [S4].

## 2. Contoh artefak intelijen

Semua isi bagian ini fiktif dan berlabel ilustrasi, dan IOC di-defang. Konteksnya PIR-2026-003 dari Day 02 (teknik akses awal kelompok ransomware yang menyasar logistik Asia Tenggara). Artefak di bawah adalah bahan jawaban untuk pesan CISO di bagian Ide inti.

### 2.1 Matriks sumber untuk PIR-2026-003

Matriks ini menjawab pertanyaan pertama CISO: setiap sumber dinilai terhadap SIR PIR-2026-003 dengan kriteria bagian 1.2. Cari SIR yang hanya dijawab satu jenis sumber.

| Sumber | SIR yang dijawab | Admiralty | Waktu | Independen | Format | Biaya | TLP/legal | Keputusan |
|---|---|---|---|---|---|---|---|---|
| Laporan IR internal 24 bulan | 003.3 | A | Langsung | Ya | Manual | Waktu IR | Internal | Pakai |
| Inventaris rule SIEM | 003.3 | A | Langsung | Ya | Ekspor | Rendah | Internal | Pakai |
| Advisori CERT nasional dan CISA | 003.1, 003.2 | B | Minggu | Ya | Manual dan STIX | Gratis | CLEAR | Pakai |
| ISAC logistik regional | 003.1 | B (per laporan) | Hari | Ya | Email dan MISP | Iuran | GREEN dan AMBER | Ajukan keanggotaan |
| Vendor A, laporan berbayar | 003.1, 003.2 | B | Hari | Sebagian | PDF dan API | Tinggi | Lisensi melarang redistribusi | Pakai, catat lisensi |
| Feed IOC gratis X | 003.2 (lemah) | C | Bervariasi | Tidak jelas | CSV | Gratis | CLEAR | Evaluasi (bagian 2.2) |
| Akun media sosial peneliti | 003.1 | F | Jam | Tidak jelas | Manual | Gratis | CLEAR | Sinyal awal saja |

**Cara membaca hasil:** SIR-003.3 hanya bisa dijawab sumber internal. Tidak ada sumber yang menjawab insiden logistik lokal yang tidak dipublikasikan, kecuali ISAC; itu alasan konkret untuk mengajukan keanggotaan, dan bisa ditulis begitu ke CISO.

### 2.2 Evaluasi dua feed selama satu kuartal

Tabel ini menjawab pertanyaan kedua CISO dengan metrik bagian 1.5. Bandingkan baris false positive rate dan median umur, bukan baris volume.

| Metrik | Feed X (gratis) | Feed Y (komunitas terkurasi) |
|---|---|---|
| Indikator baru per bulan | 12.000 | 800 |
| Hit di telemetri (kuartal) | 45 | 20 |
| Hit benign setelah triase | 38 | 4 |
| Hit valid | 7 | 16 |
| False positive rate | 38/45 = 84% | 4/20 = 20% |
| Tumpang tindih dengan feed lain | 30 indikator sama dengan Y | 30 dari 800 = 3,75% |
| Median umur saat diterima | 21 hari | 2 hari |

**Cara membaca hasil:** Feed X menghasilkan 38 alert sia-sia untuk 7 temuan valid, dan indikatornya rata-rata sudah tiga minggu saat masuk, terlalu tua untuk blokir. Feed Y lebih kecil tetapi lebih segar dan lebih tepat. Keputusan: pertahankan Y untuk blokir otomatis; turunkan X menjadi sumber pengayaan saja (dicocokkan saat investigasi, tidak membuat alert).

### 2.3 Melacak circular reporting

Rantai ini menjawab pertanyaan ketiga CISO tentang klaim RANSOM-FICTA. Hitung berapa sumber yang punya akses langsung, lalu bandingkan dengan jumlah tempat klaim itu muncul.

```
Klaim: "Kelompok RANSOM-FICTA masuk lewat celah VPN merek Z"
  Artikel media A (2026-09-20)   -> mengutip blog Vendor B
  Artikel media C (2026-09-21)   -> mengutip media A
  Feed X (2026-09-22)            -> IOC diambil dari blog Vendor B
  Blog Vendor B (2026-09-19)     -> berdasarkan 1 insiden yang ditangani B
  Advisori CERT D (2026-09-25)   -> 3 insiden sendiri, menyebut celah yang sama
Sumber independen dengan akses langsung: Vendor B, CERT D  (bukan 5)
Penilaian: celah VPN merek Z sebagai vektor -> dikonfirmasi dua sumber
  independen (kredibilitas 1). Atribusi ke RANSOM-FICTA hanya dari
  Vendor B -> kredibilitas 3, keyakinan rendah.
```

### 2.4 Catatan kepatuhan pada collection plan

Catatan ini menjawab pertanyaan keempat dan keenam CISO sekaligus: aturan unggah file, perlakuan laporan ISAC AMBER+STRICT terhadap MSSP, lisensi Vendor A, dan data pribadi.

```
Catatan kepatuhan PIR-2026-003 (fiktif)
- Semua sumber pasif dan sah. Tidak ada akses ke situs kebocoran, forum,
  atau infrastruktur aktor; informasi situs kebocoran hanya lewat laporan Vendor A.
- Laporan Vendor A: lisensi internal, tidak disalin ke wiki kontraktor.
- Laporan ISAC TLP:AMBER+STRICT: hanya tim keamanan internal; ringkasan
  untuk MSSP ditulis ulang tanpa isi AMBER+STRICT.
- File mencurigakan: cari hash dulu; tidak diunggah ke layanan publik
  tanpa persetujuan lead.
- Data pribadi: daftar akun pegawai yang bocor disimpan tanpa kata sandi;
  dihapus 30 hari setelah reset selesai.
```

### 2.5 Catatan keputusan untuk permintaan di area abu-abu

Catatan ini menjawab pertanyaan kelima: permintaan direktur komersial untuk membeli dump database ditolak, dan penolakannya disertai alternatif sah.

```
Permintaan (fiktif): "Bisakah kita beli dump database pelanggan yang
  dijual di forum untuk memastikan itu data kita?"
Keputusan: TIDAK.
Alasan: memperoleh data pribadi secara melawan hukum (UU PDP); membiayai
  pelaku; risiko malware dan kontak dengan pelaku.
Alternatif sah:
  1. Minta Vendor A (layanan pemantauan kebocoran) memverifikasi sampel
     yang dipublikasikan penjual.
  2. Bandingkan struktur kolom yang diumumkan penjual dengan skema DB sendiri.
  3. Cek log akses DB untuk ekspor massal pada rentang waktu yang diklaim.
  4. Libatkan legal dan DPO untuk kewajiban notifikasi bila terkonfirmasi.
```

## 3. Lab praktik

Lab memakai editor teks dan akses baca ke sumber publik yang sah. PIR fiktif; jangan pakai data kerja; jangan mengakses forum kriminal atau mengunduh apa pun yang mencurigakan.

1. **Matriks sumber.** Untuk PIR fiktif-mu dari Day 02, susun matriks seperti bagian 2.1 dengan minimal enam sumber, termasuk dua internal.
2. **Evaluasi feed.** Pilih dua feed IOC publik gratis (cek syarat penggunaannya dulu). Catat jumlah indikator seminggu dan median umur indikator berdasarkan tanggal yang dicantumkan. Bila punya lab SIEM, cocokkan dengan log lab dan hitung hit rate.
3. **Circular reporting.** Ambil satu berita keamanan minggu ini, telusuri rantai kutipannya sampai ke sumber asal, dan tulis seperti bagian 2.3.
4. **TLP.** Tulis tiga butir informasi fiktif, beri label TLP 2.0 yang tepat, lalu tentukan siapa yang boleh menerima masing-masing.
5. **Catatan kepatuhan.** Tulis catatan seperti bagian 2.4 untuk collection plan-mu.
6. **Area abu-abu.** Tulis satu permintaan fiktif yang melewati garis (misalnya "masuk ke panel phishing untuk melihat daftar korban") dan catatan keputusannya dengan alternatif sah.

**Hasil yang sebaiknya tersimpan:**

- Matriks sumber dengan keputusan per sumber.
- Tabel evaluasi dua feed dengan angka dan keputusan.
- Rantai circular reporting dengan jumlah sumber independen yang sebenarnya.
- Tiga butir berlabel TLP dan daftar penerimanya.
- Catatan kepatuhan collection plan.
- Catatan keputusan untuk permintaan di area abu-abu.

**Variasi tantangan:** cari dua laporan vendor publik yang menamai kelompok yang tampaknya sama dengan nama berbeda. Buat tabel alias dan tulis dasar penyamaan nama itu, beserta keyakinanmu bahwa keduanya memang kelompok yang sama.

## 4. Troubleshooting

Tabel ini memuat gejala yang sering muncul saat menjalankan collection; cari gejala yang mirip dengan yang kamu alami.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Keyakinan naik tanpa dasar | Circular reporting | Telusuri rantai kutipan; hitung hanya sumber dengan akses langsung |
| Alert dari feed membanjir | False positive rate tinggi, IOC basi | Ukur metrik bagian 1.5; turunkan feed ke pengayaan saja |
| Langganan mahal tetapi jarang dipakai | Tidak dipetakan ke PIR | Nilai ulang dengan matriks sumber setiap kuartal |
| Atribusi vendor berbeda-beda | Skema penamaan berbeda dan bias | Buat tabel alias; nyatakan keyakinan penyamaan |
| Penyerang mengganti infrastruktur setelah dianalisis | Pengumpulan aktif dari jaringan kantor atau unggahan ke layanan publik | Utamakan sumber pasif; ikuti kebijakan unggah |
| Ragu apakah boleh berbagi | Label TLP tidak jelas | Tanya pemilik informasi; perlakukan sebagai label paling ketat sampai jelas |
| Data pribadi menumpuk | Tidak ada minimisasi dan retensi | Tetapkan masa simpan per jenis data |

## 5. Kesalahan umum dan jebakan

- Menganggap banyak sumber sama dengan lebih yakin. Hitung hanya sumber independen.
- Menilai feed dari volume. Feed besar dengan false positive rate tinggi menambah beban, bukan cakupan.
- Mengunggah lampiran email internal ke layanan analisis publik. Isinya bisa dibaca orang lain.
- Membuka URL phishing dari laptop kerja untuk "melihat sebentar".
- Menganggap TLP menempel pada dokumen. Label menempel pada informasi dan ikut ke dokumen turunan.
- Memakai TLP:WHITE di dokumen baru. Versi 2.0 memakai TLP:CLEAR.
- Membeli data bocoran "untuk verifikasi". Ada alternatif sah, dan risikonya pidana.

## 6. Catatan terkini

Bagian ini menampung tanggal berlaku dan perubahan regulasi. Berguna saat menulis kebijakan bersama tim legal, tetapi tidak mengubah garis etika di bagian 1.7.

- TLP 2.0 berlaku sejak Agustus 2022 dan menambahkan TLP:AMBER+STRICT serta mengganti WHITE menjadi CLEAR [S2].
- UU 27/2022 tentang Pelindungan Data Pribadi diundangkan 17 Oktober 2022 dengan masa penyesuaian dua tahun yang berakhir Oktober 2024. Beberapa pasal pidananya sedang diuji di Mahkamah Konstitusi pada 2025; cek status putusannya [S4].
- UU ITE mengalami perubahan kedua lewat UU 1/2024, dan KUHP baru (UU 1/2023) berlaku Januari 2026. Pasal yang mengatur akses tanpa hak perlu dicek ulang terhadap kedua undang-undang itu oleh tim legal [S6].
- Survei industri CTI 2026 (Day 01) mencatat lebih dari separuh organisasi belum punya proses berbagi CTI yang ditinjau aspek hukumnya, jadi catatan kepatuhan seperti bagian 2.4 masih jarang ada.

## 7. Cheat sheet

```
JENIS       internal | pemerintah/CERT | OSINT | data infrastruktur pasif | vendor | ISAC | feed
MATRIKS     relevansi(SIR) | Admiralty | waktu | kelengkapan | independensi | format | biaya | TLP/legal
FEED        volume | hit rate | FP rate = benign/hit | overlap | umur saat diterima ; tinjau per kuartal
CIRCULAR    telusuri kutipan -> hitung hanya sumber dengan akses langsung dan independen
PASIF/AKTIF pasif: baca data yang ada ; aktif: sentuh infra aktor (risiko tip-off, malware, legal)
OPSEC       cari hash dulu, jangan unggah sembarangan ; jangan buka IOC dari jaringan kantor
GARIS       TIDAK: dark web/forum, interaksi pelaku, beli data bocoran, akses sistem tanpa izin
TLP 2.0     RED (penerima saja) | AMBER+STRICT (organisasi) | AMBER (organisasi+klien) | GREEN (komunitas) | CLEAR (publik)
            label menempel pada INFORMASI ; WHITE (1.0) = CLEAR (2.0)
PRIVASI     minimisasi + retensi per jenis data ; UU PDP Pasal 65/67 ; cek dengan legal
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Klaim "kelompok RANSOM-FICTA masuk lewat celah VPN merek Z" muncul di dua artikel media, satu feed, satu blog vendor, dan satu advisori CERT. Seorang analyst menulis, "Dikonfirmasi lima sumber, keyakinan tinggi." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Kedua artikel media dan feed semuanya berakar pada blog Vendor B, jadi hanya ada dua sumber independen dengan akses langsung: Vendor B (satu insiden yang ditanganinya) dan CERT D (tiga insiden sendiri). Penilaiannya juga harus dipisah. Celah VPN merek Z sebagai vektor dikonfirmasi dua sumber independen (kredibilitas 1), tetapi atribusi ke RANSOM-FICTA hanya berasal dari Vendor B, sehingga kredibilitasnya 3 dengan keyakinan rendah. Lihat bagian 1.4 dan 2.3.

</details>

**2. Skenario keputusan.** Setelah satu kuartal, Feed X (gratis) menghasilkan 45 hit dengan 38 benign dan median umur 21 hari, sedangkan Feed Y (komunitas terkurasi) menghasilkan 20 hit dengan 4 benign dan median umur 2 hari. Apa keputusanmu?

- A. Pertahankan Feed X untuk blokir otomatis, karena volumenya 12.000 indikator per bulan sehingga cakupannya paling luas.
- B. Pertahankan Feed Y untuk blokir otomatis, dan turunkan Feed X menjadi sumber pengayaan yang dicocokkan saat investigasi tanpa membuat alert.
- C. Hentikan kedua feed dan pakai sumber internal saja, karena feed eksternal selalu basi.

<details><summary>Jawaban</summary>

B. Feed X punya false positive rate 84% (38/45) dan indikatornya rata-rata sudah tiga minggu saat masuk, terlalu tua untuk blokir; Feed Y punya false positive rate 20% dan jauh lebih segar. A keliru karena feed dinilai dari angka seperti hit rate, false positive rate, dan umur, bukan dari volume; feed besar dengan false positive rate tinggi menambah beban, bukan cakupan. C keliru karena Feed Y terbukti memberi 16 hit valid, dan Feed X pun masih berguna sebagai pengayaan. Lihat bagian 1.5 dan 2.2.

</details>

**3. Pertanyaan jebakan.** Brief untuk CISO PT LC hampir seluruhnya berisi informasi TLP:CLEAR, ditambah satu paragraf dari laporan ISAC berlabel TLP:AMBER+STRICT. Bolehkah brief itu diteruskan ke MSSP yang membantu SOC?

<details><summary>Jawaban</summary>

Tidak boleh. Label TLP menempel pada informasi, bukan pada dokumen, dan ikut ke dokumen turunan. TLP:AMBER+STRICT hanya boleh dibagikan di dalam organisasi penerima atas dasar need-to-know, sehingga vendor MSSP tidak termasuk walaupun sisa brief berlabel CLEAR. Yang dilakukan PT LC adalah menulis ulang ringkasan untuk MSSP tanpa isi AMBER+STRICT. Lihat bagian 1.8 dan 2.4.

</details>

**4. Skenario keputusan.** Seorang analyst IR menerima lampiran mencurigakan yang ditujukan ke staf keuangan. Ia ingin tahu secepatnya apakah file itu berbahaya. Langkah mana yang tepat?

- A. Unggah file ke layanan multi-antivirus publik, karena hasilnya paling cepat.
- B. Cari hash file itu dulu, lalu unggah ke layanan publik hanya bila kebijakan organisasi mengizinkan dan ada persetujuan lead.
- C. Buka URL di dalam lampiran dari laptop kerja sebentar untuk melihat isinya.

<details><summary>Jawaban</summary>

B. Mencari hash adalah pengumpulan pasif yang tidak membuka isi file ke pihak lain. A keliru karena file yang diunggah ke layanan publik bisa dilihat pelanggan layanan itu, termasuk penyerang yang memantau apakah malware-nya sudah ketahuan, dan dokumen internal yang terlampir ikut terbuka. C keliru karena itu pengumpulan aktif: kunjungan dari IP perusahaan bisa memberi tahu penyerang bahwa umpannya sedang diperiksa, dan halaman bisa memuat exploit browser. Lihat bagian 1.6 dan 2.4.

</details>

**5. Jelaskan ulang.** Direktur komersial PT LC bertanya kenapa tim tidak mau membeli dump database pelanggan yang dijual di forum, padahal tujuannya hanya memastikan apakah itu data PT LC. Jelaskan dalam tiga sampai empat kalimat, termasuk apa yang bisa dilakukan sebagai gantinya.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Membeli dump itu berarti memperoleh data pribadi orang lain secara melawan hukum, yang dilarang UU PDP (Pasal 65 ayat 1) dengan ancaman pidana penjara paling lama lima tahun dan/atau denda paling banyak Rp5 miliar (Pasal 67 ayat 1). Selain itu, uangnya membiayai pelaku, dan kita berisiko terkena malware serta berinteraksi langsung dengan pelaku. Sebagai gantinya, kita bisa meminta Vendor A yang memantau kebocoran memverifikasi sampel yang dipublikasikan penjual, membandingkan struktur kolom yang diumumkan dengan skema database kita, dan memeriksa log akses database untuk ekspor massal pada rentang waktu yang diklaim. Legal dan DPO dilibatkan untuk kewajiban notifikasi bila kebocoran terkonfirmasi."

Kesalahan yang sering muncul:
- Hanya menyebut "melanggar etika" tanpa menyebut risiko pidana dan risiko keamanan.
- Menolak tanpa memberi alternatif sah, sehingga pertanyaan direktur tidak terjawab.
- Mengira membeli "untuk verifikasi" membuat tindakan itu sah. Tujuan baik tidak mengubah cara memperoleh data.

</details>

**6. Pertanyaan jebakan.** Dalam satu kuartal, laporan berbayar dari sebuah vendor tidak pernah menjawab satu pun SIR PIR-2026-003. Seorang rekan berkata, "Tetap perpanjang, vendor itu reputasinya paling bagus di industri." Tepatkah?

<details><summary>Jawaban</summary>

Tidak tepat. Matriks sumber menilai setiap sumber terhadap PIR dengan kriteria yang sama, dan relevansi (SIR mana yang dijawab) adalah kriteria pertama. Sumber yang dalam satu kuartal tidak pernah menjawab sub-pertanyaan apa pun adalah kandidat dihentikan, walaupun reputasinya bagus. Keputusannya diambil saat meninjau ulang langganan dengan matriks yang sama. Lihat bagian 1.2.

</details>

**7. Interview question (English).** "How do you decide which threat intelligence sources to use, and where do you draw the ethical line in collection?"

<details><summary>Sample answer</summary>

"I start from the intelligence requirements and score every source against them with the same criteria: which sub-question it answers, its reliability track record, timeliness, independence, format, cost, and any TLP or licensing limits. Internal sources such as our own incident reports and detection inventory often answer the most important question, which is whether this is happening to us. For IOC feeds I look at numbers every quarter, like hit rate, false positive rate, overlap, and how old indicators are when they arrive, and I downgrade a noisy feed to enrichment instead of letting it drive alerts. Before raising confidence in a claim, I trace the citations to check for circular reporting. On ethics, I stick to passive and lawful collection: no dark web forums, no interaction with threat actors, no buying leaked data, and no touching attacker infrastructure. If a requirement seems to need those sources, I use a vendor that monitors them legitimately, ask the ISAC or CERT, or narrow the requirement."

What makes this answer strong: it ties source selection to requirements, uses measurable criteria for feeds, shows awareness of circular reporting, and states clear ethical boundaries along with lawful alternatives.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | CISA: Cybersecurity Advisories | https://www.cisa.gov/news-events/cybersecurity-advisories | primer | diakses 2026-10-10 | Tinggi. Contoh sumber pemerintah; situs menolak akses otomatis tetapi terbuka di browser |
| S2 | FIRST: Traffic Light Protocol (TLP) version 2.0 | https://www.first.org/tlp/ | primer | berlaku 2022-08; diakses 2026-10-10 | Tinggi. Definisi label |
| S3 | National Council of ISACs | https://www.nationalisacs.org/ | primer | diakses 2026-10-10 | Sedang-tinggi. Gambaran model ISAC (Amerika Serikat) |
| S4 | UU Nomor 27 Tahun 2022 tentang Pelindungan Data Pribadi (JDIH BPK) | https://peraturan.bpk.go.id/Details/229798/uu-no-27-tahun-2022 | primer (regulasi) | 2022-10-17; diakses 2026-10-10 | Tinggi. Pasal 65 dan 67 |
| S5 | MWR InfoSecurity, CPNI, CERT-UK: Threat Intelligence: Collecting, Analysing, Evaluating (salinan PDF) | https://www.ismsforum.es/ficheros/descargas/threat-intelligence--collecting-analysing.pdf | primer | 2015; diakses 2026-10-10 | Tinggi untuk prinsip; angka tumpang tindih feed sudah tua |
| S6 | UU Nomor 11 Tahun 2008 tentang Informasi dan Transaksi Elektronik, dengan perubahan UU 19/2016 dan UU 1/2024 | (naskah resmi di JDIH Setneg dan JDIH BPK) | primer (regulasi) | 2008, 2016, 2024 | Tinggi untuk keberadaan larangan akses tanpa hak; pasal yang berlaku setelah KUHP baru perlu dicek |

**Catatan sumber:** hubungan antara ketentuan pidana UU ITE dan KUHP baru yang berlaku Januari 2026 belum dirinci di catatan ini; cek naskah resmi dan pendapat legal. Status uji materi beberapa pasal UU PDP di Mahkamah Konstitusi (perkara 2025) perlu dicek. Angka evaluasi feed di bagian 2.2 adalah ilustrasi untuk cara menghitung, bukan data nyata.
