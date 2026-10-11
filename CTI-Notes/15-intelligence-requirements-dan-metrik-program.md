---
day: 15
title: 'Mengelola intelligence requirements dan mengukur program CTI'
researched_on: 2026-10-10
versions_checked: 'CTI-CMM (cti-cmm.org, versi 1.3 saat dirujuk 2026-10-09; 10 domain di versi 1.0, domain Fraud ditambahkan di versi 1.1; sponsor disebut di situsnya); SANS: Beyond Meh-trics (blog praktisi); rujukan Day 02, 05, 10, 11, 13, 14'
---

# Day 15: Intelligence requirements dan metrik program

Cakupan: mengubah daftar PIR menjadi register yang hidup, membaca tingkat kebutuhan, memilih dan menghentikan sumber karena kebutuhan, memakai model kematangan (CTI-CMM) sebagai peta, memilih metrik yang mudah dikumpulkan dan menghindari yang menyesatkan, serta menyajikan nilai program ke pimpinan.

## Ide inti

Program CTI tidak dinilai dari jumlah laporan yang diterbitkan atau jumlah indikator yang dikonsumsi, melainkan dari keputusan yang berubah karenanya. Supaya bisa menunjukkan itu, program butuh lapis manajemen: daftar kebutuhan yang tetap hidup setelah ditulis, sumber yang dipilih (dan dihentikan) karena kebutuhan, dan beberapa angka sederhana yang dilaporkan konsisten. Day 02 memperkenalkan siklus, PIR, dan collection plan sebagai konsep, dan Day 10 menunjukkan cara mengoperasionalkan produknya. Day ini mengurus apa yang terjadi sesudahnya: nasib daftar kebutuhan setelah tiga bulan, cara memutuskan berhenti berlangganan, dan jawaban saat seseorang bertanya apakah tim CTI sepadan dengan biayanya.

Pertanyaan terakhir itu yang paling sering mematikan program CTI kecil, dan kamu sudah mengenal versinya di SOC. Use case yang ditulis sekali lalu tidak pernah ditinjau berubah menjadi rule yang tidak dipakai siapa pun. Log source yang di-ingest tanpa satu pun use case yang memakainya hanya menambah biaya lisensi SIEM. Dan laporan bulanan berisi "jumlah alert ditutup" mengukur kesibukan, bukan keamanan. Requirements CTI, sumber CTI, dan metrik CTI punya penyakit yang sama, dengan obat yang sama: setiap item punya pemilik, punya jejak ke hasil, dan ditinjau berkala.

```
kebutuhan (PIR, pemilik, tanggal tinjau, status)
  -> sumber dipilih karena kebutuhan (matriks kebutuhan ke sumber)
  -> produk menyebut kebutuhan yang dijawabnya
  -> dampak: deteksi baru, hunt, keputusan yang berubah
  -> metrik sederhana + baseline tren -> laporan ke pimpinan
  -> tinjau: kebutuhan ditutup/diubah, sumber dihentikan/ditambah -> kembali ke atas
Kebutuhan tanpa produk dan produk tanpa kebutuhan sama-sama temuan.
```

Situasi yang dipakai sepanjang Day ini: awal Oktober 2026 di PT Logistik Contoh (PT LC, perusahaan logistik fiktif dengan gudang di Jakarta, Surabaya, dan Medan). PIR-2026-003 baru disetujui CISO pada 3 Oktober, dan jawabannya ditunggu untuk rapat anggaran 5 Desember. Menjelang rapat itu, Direktur Keuangan juga meninjau seluruh biaya keamanan, dan CISO meneruskan pesannya ke tim CTI:

> "Sebelum rapat anggaran, Direktur Keuangan minta justifikasi tim CTI. Tolong siapkan jawaban untuk ini:
> 1. PIR yang kalian tulis bulan ini, apa jaminannya tidak berakhir sebagai dokumen yang tidak pernah dibuka lagi?
> 2. Langganan A mau diperpanjang. Apa dasarnya, dan sumber mana yang sebetulnya bisa dihentikan?
> 3. Ada vendor yang menawarkan asesmen kematangan CTI dengan skor. Kita perlu itu?
> 4. Angka apa yang bisa saya tunjukkan bahwa tim CTI sepadan dengan biayanya?
> 5. Saya cuma punya lima menit di rapat. Apa yang harus ada di satu halaman itu?"

Pertanyaan 1 dijawab di bagian 1.1 dan 1.2, pertanyaan 2 di bagian 1.3, pertanyaan 3 di bagian 1.4, pertanyaan 4 di bagian 1.5 dan 1.6, dan pertanyaan 5 di bagian 1.7. Artefak yang dikirim balik ke CISO ada di bagian 2.

**Kapan relevan:** saat meninjau daftar PIR, memutuskan perpanjangan atau penghentian sumber, menyusun laporan program kuartalan, menghadapi tinjauan anggaran, dan mencari pemangku kepentingan yang belum dilayani.
**Kapan bukan jawaban:** saat program belum punya kebutuhan tertulis sama sekali. Mulai dulu dari wawancara pemangku kepentingan dan PIR (Day 02); register dan metrik tidak bisa dibangun di atas daftar kosong. Day ini juga tidak memberi patokan angka industri: angka perbaikan yang beredar di tulisan vendor tidak disertai sumber, jadi baseline dibangun sendiri.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Tabel ini memuat istilah yang muncul di Day ini. Kolom padanan memakai analogi SOC yang sama di semua Day CTI. Istilah dari Day sebelumnya (PIR, SIR, EEI, RFI, collection plan, TLP) tidak diulang.

| Istilah | Arti singkat | Padanan di SOC |
|---|---|---|
| Register kebutuhan | Daftar semua kebutuhan intelijen beserta pemilik, status, tanggal tinjau, dan produk terkait | Inventaris use case atau detection yang punya pemilik dan tanggal review |
| IR-2026-NN | Format ID kebutuhan di register PT LC (intelligence requirement), bukan incident response | Nomor use case di backlog |
| Tingkat kebutuhan | Strategis, operasional, atau taktis, menurut pembaca dan ritmenya | Laporan direksi vs laporan manajer SOC vs tiket untuk analyst |
| Matriks kebutuhan ke sumber | Tabel yang menunjukkan sumber mana menjawab kebutuhan mana | Peta log source ke use case |
| Celah pengumpulan | Kebutuhan yang tidak dijawab sumber mana pun | Use case tanpa log source |
| Biaya total sumber | Harga langganan ditambah waktu analis untuk mengolahnya | Biaya ingest ditambah jam tuning dan triage |
| Model kematangan | Kerangka untuk menilai dan merencanakan peningkatan kemampuan | Coverage map ATT&CK: dipakai untuk mencari celah, bukan dipamerkan sebagai persentase |
| CTI-CMM | Cyber Threat Intelligence Capability Maturity Model, model kematangan CTI yang disusun komunitas | Model kematangan seperti di atas, khusus CTI |
| Stakeholder First | Pendekatan CTI-CMM: kematangan diukur dari dukungan ke pemangku kepentingan | Nilai SOC diukur dari layanan ke pemilik aset, bukan dari jumlah alat |
| CTI0-CTI3 | Empat tingkat asesmen per pernyataan praktik di CTI-CMM | Status per technique: tidak ada, sebagian, sebagian besar, penuh |
| Baseline | Nilai pembanding dari periode sebelumnya | Baseline volume alert bulanan |
| Metrik dampak | Angka yang menunjukkan sesuatu berubah karena CTI | Detection baru yang lahir dari insiden, bukan jumlah alert ditutup |

### 1.1 Kebutuhan sebagai daftar hidup

Pertanyaan pertama Direktur Keuangan menyentuh masalah yang paling umum: bukan ketiadaan PIR, melainkan PIR yang ditulis sekali lalu tidak pernah disentuh. PIR-2026-003 baru berumur beberapa hari, jadi ini saat yang tepat untuk memastikan nasibnya berbeda.

Daftar yang hidup punya empat sifat:

- **Punya pemilik di sisi pemangku kepentingan.** Setiap kebutuhan ditautkan ke orang yang akan memakai jawabannya, bukan ke jabatan umum.
- **Punya tanggal tinjau.** Kebutuhan yang tidak ditinjau selama dua kuartal hampir pasti sudah tidak relevan atau sudah terjawab.
- **Punya status.** Aktif, terjawab sebagian, terjawab, atau ditutup karena tidak lagi relevan.
- **Punya jejak ke produk.** Setiap produk yang kamu terbitkan menyebut kebutuhan mana yang dijawabnya.

Sifat keempat yang paling banyak membawa manfaat. Ia memaksa dua hal sekaligus: produk yang tidak menjawab kebutuhan mana pun akan terlihat, dan kebutuhan yang tidak pernah menghasilkan produk juga akan terlihat. Keduanya adalah temuan.

PIR-2026-003 sudah memenuhi tiga sifat pertama: disetujui CISO, punya tanggal tinjau ulang 2027-01-15, dan berstatus aktif. Yang perlu ditambahkan saat ia masuk register adalah sifat keempat, yaitu daftar produk yang menjawabnya, misalnya brief CISO dan daftar teknik untuk detection engineer di rencana dissemination-nya. Register yang mencatat semua itu disebut register kebutuhan; contohnya di bagian 2.1.

### 1.2 Tiga tingkat kebutuhan, tiga jenis pembaca

Jaminan kedua bahwa PIR tidak mati adalah produk yang memang dibaca pemiliknya. Itu hanya terjadi bila tingkat produk cocok dengan tingkat kebutuhan.

Tabel berikut memetakan tiap tingkat kebutuhan ke pembaca dan ritmenya. Perhatikan kolom pembaca: itu yang menentukan bentuk produk, bukan topiknya.

| Tingkat | Pertanyaan khas | Pembaca | Ritme |
|---|---|---|---|
| Strategis | Ancaman apa yang paling relevan bagi bisnis kami tahun ini | Pimpinan, pemilik risiko | Kuartalan atau tahunan |
| Operasional | Aktor atau kampanye apa yang menyasar sektor kami sekarang | Manajer SOC, pemilik program | Bulanan |
| Taktis | Teknik dan indikator apa yang perlu kami deteksi | Analis, detection engineer, hunter | Mingguan atau harian |

Pembagian tiga tingkat ini dipakai untuk mengelola kebutuhan dan berbeda dari model empat tipe MWR di Day 01. "Operasional" di sini berarti aktor dan kampanye yang sedang aktif terhadap sektor, bukan detail serangan spesifik yang akan datang. Seperti di Day 01, yang penting adalah menyebut isinya.

Kesalahan yang berulang adalah menjawab kebutuhan satu tingkat dengan produk tingkat lain. Pimpinan yang bertanya soal risiko bisnis tidak terbantu oleh daftar indikator, dan detection engineer tidak terbantu oleh narasi lanskap. Sebelum menulis, tetapkan tingkatnya, lalu patuhi.

PIR-2026-003 contoh kebutuhan yang menyentuh dua tingkat: pertanyaannya operasional sampai taktis (kelompok mana, teknik akses awal apa, teknik mana yang belum terdeteksi), sedangkan keputusannya strategis (prioritas anggaran Q1). Karena itu produknya dipecah: brief satu halaman untuk CISO dan daftar teknik tanpa deteksi untuk detection engineer.

### 1.3 Memilih sumber karena kebutuhan

Perpanjangan Langganan A di pertanyaan kedua tidak bisa dijawab dengan "laporannya bagus". Yang ditanyakan sebenarnya: kebutuhan mana yang dijawabnya, dan berapa biayanya.

Urutannya satu arah: kebutuhan menentukan sumber, bukan sebaliknya. Program yang berlangganan dulu lalu mencari gunanya akan menumpuk biaya tanpa jawaban.

Tabel berikut adalah cara menilai satu sumber, dan bisa dikerjakan tanpa alat apa pun. Baca dari atas: bila baris pertama sudah gagal, baris lain tidak perlu diisi.

| Kriteria | Pertanyaan |
|---|---|
| Relevansi | Kebutuhan mana yang bisa dijawabnya? Bila tidak ada, selesai. |
| Ketepatan waktu | Apakah ia memberi tahu cukup cepat untuk mengubah keputusan? |
| Keunikan | Berapa persen isinya yang tidak kamu peroleh dari sumber lain? |
| Dapat ditindaklanjuti | Berapa produk atau deteksi yang lahir darinya dalam kuartal terakhir? |
| Biaya total | Termasuk waktu analis untuk mengolahnya, bukan hanya harga langganan |

Kolom terakhir sering menentukan. Sumber gratis yang butuh enam jam kerja per minggu lebih mahal daripada langganan yang siap pakai, dan perhitungan itu jarang dilakukan.

Keputusan menghentikan sumber harus senormal keputusan menambahnya. Tetapkan peninjauan tahunan untuk semua sumber, dengan kriteria yang sama bagi yang gratis maupun berbayar. Hasil penilaian Langganan A ada di bagian 2.3.

### 1.4 Model kematangan sebagai peta, bukan nilai

Tawaran asesmen kematangan dengan skor di pertanyaan ketiga terdengar menarik untuk rapat anggaran. Sebelum menerimanya, pahami dulu apa yang diukur model kematangan CTI dan cara memakainya yang benar-benar berguna.

CTI-CMM adalah kerangka yang disusun komunitas untuk memberi peta jalan peningkatan dukungan terhadap pemangku kepentingan [S1]. Pendekatannya disebut Stakeholder First, yaitu menyelaraskan praktik CTI dengan harapan kematangan tiap pemangku kepentingan [S1]. Setiap domain mendefinisikan praktik dukungan CTI untuk satu jenis pemangku kepentingan, dan dokumennya tersedia gratis [S1]. Riwayat versinya ada di bagian 6.

Sepuluh domain awalnya diambil dari fungsi organisasi yang lazim dalam model kematangan keamanan siber, dan masing-masing mewakili satu kelompok pemangku kepentingan yang dilayani CTI [S4]. Tabel berikut dipakai sebagai daftar periksa: cari baris yang pemangku kepentingannya belum pernah menerima produk dari timmu.

| Domain | Pemangku kepentingan dan contoh dukungan CTI |
|---|---|
| Asset, Change, and Configuration Management | Tim aset dan konfigurasi: teknologi mana yang sedang diincar penyerang |
| Threat and Vulnerability Management | Tim kerentanan: prioritas patch berbasis eksploitasi nyata (Day 13) |
| Risk Management | Pemilik risiko: skenario ancaman untuk penilaian risiko |
| Identity and Access Management | Tim identitas: pola penyalahgunaan kredensial dan akses |
| Situational Awareness | SOC dan pimpinan: gambaran ancaman terkini |
| Event and Incident Response, Continuity of Operations | IR: konteks aktor dan TTP saat insiden |
| Third-Party Risk Management | Pengadaan dan vendor management: ancaman lewat pemasok dan MSP |
| Workforce Management | SDM dan awareness: tema rekayasa sosial yang sedang dipakai |
| Cybersecurity Architecture | Arsitek: kontrol yang menutup TTP prioritas |
| Cybersecurity Program Management | CISO: arah program dan investasi |

Domain Fraud melayani tim anti-fraud, sehingga totalnya sebelas domain. Asesmennya memakai empat tingkat untuk setiap pernyataan praktik: CTI0 (belum ada kemampuan), CTI1 (sebagian), CTI2 (sebagian besar), dan CTI3 (penuh) [S5].

Gagasan intinya layak diambil terlepas dari kerangka mana yang kamu pakai: kematangan CTI diukur dari seberapa baik ia mendukung pemangku kepentingan, bukan dari seberapa canggih alatnya. Itu pembalikan yang berguna, karena banyak program menilai dirinya dari jumlah umpan dan platform.

Dua cara memakai model semacam ini, dan hanya satu yang berguna. Cara yang tidak berguna adalah mengejar angka kematangan sebagai target. Cara yang berguna adalah memakainya sebagai daftar periksa untuk menemukan pemangku kepentingan yang belum kamu layani sama sekali. Biasanya ada satu atau dua, dan itu peluang terbesar.

Satu peringatan sumber: penilaian berbasis skor sering menghasilkan angka yang rapi tetapi tidak bisa ditindaklanjuti. Yang perlu kamu hasilkan adalah daftar celah dan ketergantungan, bukan hanya skor. Untuk CISO PT LC, jawabannya: asesmen boleh dipakai bila keluarannya daftar celah, dan tidak perlu dibeli bila keluarannya hanya skor.

### 1.5 Metrik yang dimulai dari yang mudah

Pertanyaan keempat meminta angka. Godaannya adalah membangun dasbor lengkap sebelum rapat, padahal yang dibutuhkan adalah angka yang bisa dikumpulkan lagi kuartal depan.

Nasihat yang paling berguna soal metrik CTI justru yang paling sederhana: mulai dari metrik yang mudah diperoleh, tidak rumit, dan mudah ditafsirkan, misalnya data tiket seperti jumlah permintaan, frekuensi, dan jenis pekerjaan yang diminta; lalu mulailah dengan analisis tren tahun ke tahun untuk membangun baseline [S2].

Alasannya praktis. Metrik canggih yang tidak bisa kamu kumpulkan secara konsisten akan berhenti dilaporkan setelah dua bulan, dan program yang tidak melaporkan apa pun lebih buruk daripada program yang melaporkan dua angka sederhana secara konsisten.

Tabel berikut memuat empat kelompok metrik yang bisa kamu bangun bertahap. Kolom terakhir adalah pertanyaan yang dijawab tiap kelompok; pilih kelompok berdasarkan pertanyaan yang paling sering diajukan pimpinanmu.

| Kelompok | Contoh | Menjawab |
|---|---|---|
| Permintaan | Jumlah RFI, jenisnya, waktu penyelesaian | Siapa memakai kami dan untuk apa |
| Cakupan kebutuhan | Berapa persen kebutuhan aktif yang punya produk dalam kuartal ini | Apakah kami menjawab yang ditanyakan |
| Dampak | Deteksi yang lahir dari CTI, hunt yang dipicu CTI, keputusan yang berubah | Apakah kami mengubah sesuatu |
| Kesehatan sumber | Produk per sumber, keunikan, biaya total | Apakah belanja kami masuk akal |

Kelompok ketiga yang paling meyakinkan dan paling sulit dikumpulkan, karena butuh kerja sama tim lain. Mulailah dari yang paling mudah diukur di antaranya, yaitu jumlah deteksi yang lahir dari produk CTI, karena itu bisa dilacak dari repo deteksi, misalnya dengan mewajibkan setiap rule yang lahir dari produk CTI mencantumkan nomor produknya di metadata rule.

### 1.6 Metrik yang menyesatkan

Angka yang paling mudah ditunjukkan ke Direktur Keuangan sering justru yang paling menyesatkan. Di SOC, padanannya adalah "jumlah alert ditutup": besar, naik terus, dan tidak menjawab apakah organisasi lebih aman.

Hindari melaporkan tiga hal ini sendirian:

- **Jumlah indikator yang dikonsumsi.** Naik seiring belanja, bukan seiring nilai. Bila harus dilaporkan, pasangkan dengan berapa yang pernah cocok dengan sesuatu.
- **Jumlah laporan yang diterbitkan.** Mengukur kesibukan. Pasangkan dengan cakupan kebutuhan dan dengan bukti produk itu dibaca atau dipakai.
- **Skor kematangan.** Berguna untuk arah, tidak berguna sebagai target, dan mudah dimanipulasi.

Pengganti yang lebih jujur untuk ketiganya adalah satu pertanyaan: keputusan apa yang berbeda karena pekerjaan kami bulan ini. Bila jawabannya kosong tiga bulan berturut-turut, itu temuan tentang programmu sendiri, dan lebih baik kamu yang menemukannya lebih dulu.

### 1.7 Menyajikan ke pemangku kepentingan

Lima menit di rapat anggaran berarti satu halaman yang dibaca, bukan lampiran yang dibuka. Bentuk halaman itu ditentukan oleh tiga aturan.

Tiga aturan yang membuat laporan program diterima:

1. **Pakai bahasa keputusan mereka.** Untuk pimpinan, bicarakan risiko yang turun dan keputusan yang didukung, bukan jumlah umpan.
2. **Tunjukkan tren, bukan potret.** Satu angka tanpa pembanding tidak bisa ditafsirkan; tren tahun ke tahun bisa [S2].
3. **Sertakan apa yang tidak bisa kamu jawab.** Daftar kebutuhan yang belum terjawab beserta alasannya adalah cara paling efektif meminta sumber daya, jauh lebih baik daripada mengeluh kekurangan orang.

## 2. Contoh artefak intelijen

Seluruh isi bagian ini adalah ilustrasi dengan angka fiktif milik PT LC; sesuaikan bentuknya dengan alat pelacakan yang kamu pakai. Kelima artefak di bawah adalah bahan jawaban tim CTI untuk pesan CISO di bagian Ide inti.

### 2.1 Register kebutuhan intelijen

Register ini jawaban untuk pertanyaan pertama: bukti bahwa setiap kebutuhan punya pemilik, status, tanggal tinjau, dan produk. Dua entri di bawah adalah kebutuhan PT LC yang sudah berjalan sebelum PIR-2026-003; PIR-2026-003 masuk ke register yang sama dengan pemilik CISO dan tanggal tinjau 2027-01-15.

```yaml
- id: IR-2026-07
  tingkat: operasional
  pertanyaan: >
    Aktor atau kampanye mana yang menyasar perusahaan logistik di Asia Tenggara
    dengan teknik yang bisa mengenai arsitektur kami?
  pemilik_pemangku: Manajer SOC (nama)
  mengapa_penting: menentukan urutan pekerjaan deteksi kuartal depan
  sumber_yang_dipakai: [laporan lembaga, langganan A, berbagi sektor]
  produk_terkait: [PROD-2026-031, PROD-2026-044]
  status: aktif
  terakhir_ditinjau: 2026-09-30
  tinjau_berikutnya: 2026-12-31

- id: IR-2026-11
  tingkat: taktis
  pertanyaan: Teknik eksfiltrasi apa yang perlu kami deteksi lebih dulu?
  pemilik_pemangku: Detection engineering
  sumber_yang_dipakai: [laporan lembaga, hasil hunt internal]
  produk_terkait: [PROD-2026-052]
  status: terjawab sebagian
  terakhir_ditinjau: 2026-09-30
  tinjau_berikutnya: 2026-11-30
  catatan: tiga teknik sudah tertutup deteksi, dua belum
```

**Cara membaca hasil:** baris `produk_terkait` yang menutup siklus. Saat meninjau, kebutuhan tanpa produk dan produk tanpa kebutuhan sama-sama muncul ke permukaan.

### 2.2 Matriks kebutuhan ke sumber

Matriks ini menghubungkan register ke sumber, dan menjadi dasar jawaban pertanyaan kedua. Cari dua hal: baris yang kosong semua dan kolom yang jarang terisi.

| Kebutuhan | Lembaga publik | Langganan A | Berbagi sektor | Hasil internal | Terjawab? |
|---|---|---|---|---|---|
| IR-2026-07 | sebagian | ya | ya | tidak | sebagian |
| IR-2026-11 | ya | tidak | tidak | ya | sebagian |
| IR-2026-14 | tidak | tidak | tidak | tidak | belum |
| IR-2026-18 | ya | ya | sebagian | ya | ya |

**Cara membaca hasil:** baris IR-2026-14 tanpa satu pun sumber adalah celah pengumpulan, dan itu argumen konkret untuk menambah sumber atau mengubah kebutuhannya. Kolom Langganan A yang hanya berkontribusi pada dua baris adalah bahan untuk peninjauan tahunan sumber (bagian 1.3).

### 2.3 Lembar penilaian satu sumber

Lembar ini menerapkan kriteria bagian 1.3 ke Langganan A, dan menjadi lampiran untuk keputusan perpanjangan yang ditanyakan Direktur Keuangan.

```
SUMBER: Langganan A            periode tinjauan: 2025-10 sampai 2026-09

RELEVANSI          menjawab 2 dari 14 kebutuhan aktif
KETEPATAN WAKTU    rata-rata 3 hari lebih awal dari laporan publik untuk 4 kejadian
KEUNIKAN           sekitar 30 persen isi tidak ada di sumber lain (perkiraan dari sampel 40 laporan)
DITINDAKLANJUTI    7 deteksi baru, 3 hunt, 0 keputusan strategis
BIAYA TOTAL        biaya langganan + sekitar 4 jam analis per minggu

KEPUTUSAN          lanjutkan, dengan syarat: minta penyesuaian cakupan ke sektor kami
ALTERNATIF         sumber B belum diuji; jadwalkan uji coba kuartal depan
```

**Cara membaca hasil:** angka pada baris keunikan ditulis sebagai perkiraan beserta dasarnya, bukan sebagai angka pasti. Kebiasaan ini yang membedakan penilaian sumber dari kesan subjektif.

### 2.4 Lembar metrik kuartalan

Lembar ini jawaban untuk pertanyaan keempat. Angkanya dari Q3 2026, kuartal yang baru selesai saat pesan CISO masuk, dibandingkan dengan Q3 2025 sebagai baseline.

```
PROGRAM CTI, KUARTAL 3 2026

PERMINTAAN
  RFI masuk            41   (Q3 2025: 28)
  waktu selesai median 2 hari
  peminta terbanyak    SOC (22), manajemen risiko (9), infrastruktur (6)

CAKUPAN KEBUTUHAN
  kebutuhan aktif      14
  punya produk di Q3   9  (64 persen)
  tanpa sumber sama sekali  2   <- lihat matriks 2.2

DAMPAK
  deteksi baru dari CTI     11   (Q3 2025: 6)
  hunt yang dipicu CTI       4
  keputusan yang didukung    2   (penundaan satu proyek, perubahan prioritas tambalan)

KESEHATAN SUMBER
  sumber aktif  5 ; ditinjau tahun ini 5 ; dihentikan 1 ; ditambahkan 1

BELUM BISA KAMI JAWAB
  IR-2026-14 (visibilitas rantai pasok)  -> butuh sumber baru atau akses data pemasok
  IR-2026-09 (aktivitas di wilayah X)    -> butuh bahasa yang tidak dikuasai tim
```

**Cara membaca hasil:** blok terakhir yang paling sering dihilangkan dan paling berguna. Ia mengubah permintaan sumber daya menjadi pernyataan faktual tentang pertanyaan yang belum bisa dijawab, dan itu jauh lebih sulit diabaikan.

### 2.5 Satu halaman untuk pimpinan

Ini bentuk halaman yang dibawa CISO ke rapat lima menit di pertanyaan kelima.

```
Judul   : Dukungan intelijen kuartal ini, dan ke mana kami mengarahkan kuartal depan
TLP     : <penanda sesuai Day 11>

1. Tiga keputusan yang kami dukung kuartal ini, dan apa yang berubah
2. Satu risiko yang naik, satu yang turun, dengan alasannya
3. Dua pertanyaan yang belum bisa kami jawab, dan apa yang dibutuhkan
4. Satu permintaan konkret
```

**Cara membaca hasil:** empat butir, tidak lebih. Lampirkan lembar metrik bagian 2.4 sebagai lampiran, bukan sebagai isi utama, karena pimpinan jarang membaca tabel tetapi sering membaca empat butir.

## 3. Lab praktik

**Prasyarat:** hasil Day 02 (PIR dan collection plan), Day 10 (operasionalisasi), dan Day 13 (vulnerability intelligence).

1. Kumpulkan seluruh PIR yang pernah kamu tulis, lalu ubah menjadi register bagian 2.1 dengan kolom pemilik, status, dan tanggal tinjau terisi semua.
2. Untuk tiap kebutuhan, tautkan produk yang pernah kamu hasilkan. Hitung berapa kebutuhan tanpa produk dan berapa produk tanpa kebutuhan.
3. Susun matriks bagian 2.2 untuk seluruh kebutuhan dan seluruh sumber yang kamu pakai, termasuk sumber gratis.
4. Isi lembar penilaian bagian 2.3 untuk dua sumber, satu yang kamu anggap paling berguna dan satu yang paling diragukan. Pastikan biaya waktu analis ikut dihitung.
5. Ambil keputusan untuk sumber yang diragukan, lalu tulis alasannya dalam tiga kalimat yang bisa dibaca orang non-teknis.
6. Pakai tabel sebelas domain di bagian 1.4 sebagai daftar periksa untuk menemukan pemangku kepentingan yang belum kamu layani sama sekali. Tulis satu langkah untuk mulai melayani salah satunya.
7. Pilih tiga metrik dari bagian 1.5 yang benar-benar bisa kamu kumpulkan minggu ini tanpa alat baru, lalu kumpulkan datanya untuk dua kuartal terakhir sebagai baseline [S2].
8. Susun lembar metrik bagian 2.4 dengan angka nyata dari langkah 7, termasuk blok pertanyaan yang belum bisa dijawab.
9. Tulis satu halaman pimpinan bagian 2.5, lalu bacakan ke rekan non-teknis dan catat bagian mana yang tidak mereka pahami.
10. Tetapkan ritme peninjauan: kapan register ditinjau, kapan sumber dinilai, kapan metrik dilaporkan. Tulis sebagai jadwal dengan tanggal, bukan sebagai niat.

**Hasil yang sebaiknya tersimpan:**
- Register kebutuhan lengkap dengan pemilik, status, dan tanggal tinjau.
- Hitungan kebutuhan tanpa produk dan produk tanpa kebutuhan.
- Matriks kebutuhan ke sumber untuk seluruh sumber yang dipakai.
- Dua lembar penilaian sumber beserta keputusannya.
- Catatan pemangku kepentingan yang belum dilayani dan satu langkah untuk memulainya.
- Baseline tiga metrik untuk dua kuartal terakhir.
- Lembar metrik kuartalan lengkap dengan blok pertanyaan yang belum terjawab.
- Satu halaman pimpinan beserta catatan bagian yang tidak dipahami pembaca non-teknis.
- Jadwal peninjauan dengan tanggal konkret.

## 4. Troubleshooting

Tabel ini membantu mendiagnosis masalah yang paling sering muncul saat mengelola register, sumber, dan metrik. Cari gejala yang paling mirip dengan situasimu.

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Register penuh tetapi tidak ada yang dikerjakan | Kebutuhan ditulis terlalu umum untuk dijawab | Terapkan anatomi PIR dari Day 02; pecah menjadi pertanyaan yang bisa dijawab |
| Produk terbit terus tetapi tidak ditautkan ke kebutuhan | Tidak ada kebiasaan menautkan | Tambahkan baris kebutuhan ke templat produk |
| Beberapa kebutuhan tidak punya sumber sama sekali | Celah pengumpulan nyata | Pakai matriks 2.2 sebagai dasar permintaan sumber baru |
| Sumber berbiaya tinggi sulit dinilai | Biaya waktu analis tidak dihitung | Ukur jam kerja yang dipakai mengolahnya selama satu bulan |
| Metrik berhenti dilaporkan setelah dua bulan | Metriknya terlalu sulit dikumpulkan | Ganti dengan yang mudah diperoleh dan mudah ditafsirkan [S2] |
| Angka tidak bisa ditafsirkan | Tidak ada pembanding | Bangun baseline tren tahun ke tahun [S2] |
| Skor kematangan naik tetapi tidak ada yang membaik | Skor dikejar sebagai target | Hasilkan daftar celah, bukan skor |
| Pimpinan tidak merespons laporan | Bahasanya bahasa operasional, bukan bahasa keputusan | Pakai bentuk empat butir bagian 2.5 |
| Permintaan sumber daya selalu ditolak | Diajukan sebagai keluhan, bukan sebagai pertanyaan yang belum terjawab | Pakai blok terakhir bagian 2.4 |

## 5. Kesalahan umum dan jebakan

- Menulis PIR sekali lalu tidak pernah meninjaunya.
- Menjawab kebutuhan satu tingkat dengan produk tingkat lain.
- Berlangganan sumber lebih dulu lalu mencari gunanya.
- Menghitung biaya sumber tanpa memasukkan waktu analis.
- Memperlakukan penghentian sumber sebagai kegagalan, bukan sebagai keputusan normal.
- Mengejar skor kematangan sebagai target.
- Memilih metrik yang canggih tetapi tidak bisa dikumpulkan secara konsisten.
- Melaporkan jumlah indikator atau jumlah laporan sebagai bukti nilai.
- Menyajikan potret tanpa tren, sehingga angkanya tidak bisa ditafsirkan.
- Menyembunyikan pertanyaan yang belum bisa dijawab, sehingga kebutuhan sumber daya tidak pernah terlihat.

## 6. Catatan terkini

Bagian ini menampung versi kerangka dan catatan tentang literatur metrik. Isinya berguna saat mengutip CTI-CMM atau tulisan tentang metrik, tetapi tidak mengubah cara mengelola register.

- CTI-CMM adalah kerangka yang disusun komunitas dengan pendekatan Stakeholder First, versinya 1.3 saat dirujuk, dan dokumennya tersedia gratis [S1]. Pendekatan yang mengukur kematangan dari dukungan terhadap pemangku kepentingan layak diadopsi walaupun kamu tidak memakai kerangkanya secara formal.
- Versi 1.0 memuat sepuluh domain yang masing-masing mendefinisikan praktik dukungan untuk satu jenis pemangku kepentingan, dan domain Fraud ditambahkan di versi 1.1 [S1]. Daftar domain itu berguna sebagai daftar periksa pemangku kepentingan, dan biasanya mengungkap satu atau dua yang belum kamu layani.
- Nasihat memulai dari metrik yang mudah diperoleh dan membangun baseline tren tahun ke tahun [S2] bertentangan dengan dorongan umum untuk langsung membuat dasbor lengkap. Dalam praktik, program yang konsisten melaporkan dua angka sederhana lebih dipercaya daripada yang sekali membuat dasbor lalu meninggalkannya.
- Penilaian kematangan yang hanya menghasilkan skor tidak bisa ditindaklanjuti; yang dibutuhkan adalah daftar celah dan ketergantungan. Simpan skornya untuk arah, dan bawa daftar celahnya ke rapat.
- Sebagian besar tulisan tentang metrik CTI berasal dari vendor dan memuat angka perbaikan yang tidak disertai sumber. Jangan memakai angka semacam itu sebagai patokan; bangun baseline sendiri.

## 7. Cheat sheet

```
KEBUTUHAN SEBAGAI DAFTAR HIDUP
  tiap kebutuhan: PEMILIK (orang, bukan jabatan) | TANGGAL TINJAU | STATUS | PRODUK TERKAIT
  baris "produk terkait" menutup siklus:
    kebutuhan tanpa produk = kita tidak menjawabnya
    produk tanpa kebutuhan = kita menjawab yang tidak ditanya
  tak ditinjau 2 kuartal = hampir pasti sudah tidak relevan

TIGA TINGKAT, TIGA PEMBACA
  strategis  risiko bisnis       pimpinan        kuartalan/tahunan
  operasional aktor & kampanye   manajer SOC     bulanan
  taktis     teknik & indikator  analis/DE/hunter mingguan/harian
  JANGAN menjawab satu tingkat dengan produk tingkat lain

SUMBER mengikuti KEBUTUHAN, bukan sebaliknya
  nilai: relevansi (kebutuhan mana?) | ketepatan waktu | keunikan
         DITINDAKLANJUTI (produk/deteksi yang lahir) | BIAYA TOTAL (termasuk JAM ANALIS)
  menghentikan sumber = keputusan NORMAL; tinjau semua sumber setahun sekali

KEMATANGAN  pakai sebagai PETA (temukan pemangku yang belum dilayani), bukan sebagai TARGET
            keluarannya daftar CELAH dan KETERGANTUNGAN, bukan skor
            CTI-CMM: Stakeholder First; 10 domain (v1.0) + Fraud (v1.1); v1.3; gratis

METRIK  mulai dari yang MUDAH diperoleh dan MUDAH ditafsirkan (mis. data tiket)
        bangun BASELINE tren tahun ke tahun; satu angka tanpa pembanding tak bisa ditafsirkan
  kelompok: permintaan | cakupan kebutuhan | DAMPAK | kesehatan sumber
  dampak paling meyakinkan; mulai dari "deteksi yang lahir dari CTI" (paling mudah dilacak)

MENYESATKAN  jumlah indikator dikonsumsi | jumlah laporan terbit | skor kematangan
             pengganti: "keputusan apa yang BERBEDA karena pekerjaan kami bulan ini?"
             kosong 3 bulan berturut-turut = temuan tentang programmu sendiri

LAPOR KE PIMPINAN  4 butir: keputusan yang didukung | risiko naik/turun | yang BELUM bisa dijawab
                   | satu permintaan konkret
  blok "belum bisa dijawab" = cara paling efektif meminta sumber daya
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Tim CTI sebuah perusahaan melaporkan ke direksi: "Tahun ini kami menerbitkan 120 laporan dan mengonsumsi dua juta indikator." Apakah itu bukti program CTI bernilai?

<details><summary>Jawaban</summary>

Tidak, bila dilaporkan sendirian. Jumlah indikator naik seiring belanja, bukan seiring nilai, dan jumlah laporan mengukur kesibukan. Keduanya perlu dipasangkan: indikator dengan berapa yang pernah cocok dengan sesuatu, laporan dengan cakupan kebutuhan dan bukti produk itu dipakai. Pengganti yang lebih jujur adalah pertanyaan "keputusan apa yang berbeda karena pekerjaan kami", ditambah metrik dampak seperti deteksi yang lahir dari CTI. Lihat bagian 1.5 dan 1.6.

</details>

**2. Skenario keputusan.** Lembar penilaian Langganan A menunjukkan: menjawab 2 dari 14 kebutuhan aktif, rata-rata 3 hari lebih awal dari laporan publik, sekitar 30 persen isi unik, 7 deteksi baru dan 3 hunt, 0 keputusan strategis, ditambah sekitar 4 jam analis per minggu. Keputusan mana yang paling tepat?

- A. Hentikan langsung, karena hanya menjawab 2 dari 14 kebutuhan.
- B. Perpanjang tanpa syarat, karena sumber berbayar pasti lebih berkualitas daripada sumber gratis.
- C. Perpanjang dengan syarat penyesuaian cakupan ke sektor PT LC, dan jadwalkan uji coba sumber pembanding.

<details><summary>Jawaban</sub></summary>

C. Sumber itu tetap menghasilkan deteksi dan hunt, memberi peringatan lebih awal, dan sebagian isinya tidak ada di sumber lain, tetapi relevansinya sempit, jadi keputusan yang masuk akal adalah lanjut bersyarat sambil menguji alternatif. A keliru karena mengabaikan kriteria lain (ketepatan waktu, keunikan, dapat ditindaklanjuti); relevansi sempit adalah alasan untuk menegosiasikan cakupan, belum tentu untuk berhenti. B keliru karena kriteria penilaian berlaku sama untuk sumber gratis maupun berbayar, dan biaya total juga mencakup jam analis. Lihat bagian 1.3 dan 2.3.

</details>

**3. Pertanyaan jebakan.** "Feed gratis selalu lebih hemat daripada langganan berbayar, jadi tidak perlu dinilai." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Biaya total sumber mencakup waktu analis untuk mengolahnya, bukan hanya harga langganan. Sumber gratis yang butuh enam jam kerja per minggu bisa lebih mahal daripada langganan yang siap pakai. Karena itu semua sumber, gratis maupun berbayar, ditinjau setahun sekali dengan kriteria yang sama, dan menghentikan sumber adalah keputusan normal. Lihat bagian 1.3.

</details>

**4. Jelaskan ulang.** Jelaskan kepada Direktur Keuangan PT LC dalam tiga kalimat kenapa tim CTI tidak mengejar skor kematangan CTI-CMM.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "CTI-CMM mengukur seberapa baik kami mendukung tiap kelompok pemangku kepentingan, misalnya tim kerentanan, pengadaan, atau SDM, bukan seberapa canggih alat kami. Skor yang dikejar sebagai target mudah naik tanpa ada yang benar-benar membaik, jadi kami memakai model itu sebagai daftar periksa untuk menemukan pemangku kepentingan yang belum pernah kami layani. Keluaran yang kami bawa ke rapat adalah daftar celah dan ketergantungan beserta satu langkah perbaikan, karena itulah yang bisa ditindaklanjuti."

Kesalahan yang sering muncul:
- Menganggap kematangan diukur dari jumlah feed atau platform yang dimiliki.
- Membuang model kematangan sama sekali, padahal fungsinya sebagai peta tetap berguna.
- Melaporkan skor tanpa daftar celah, sehingga pimpinan tidak tahu apa yang harus didanai.

</details>

**5. Skenario keputusan.** CISO PT LC ingin mulai melaporkan metrik CTI bulan depan, padahal sebelumnya belum pernah ada metrik sama sekali. Pendekatan mana yang paling tepat?

- A. Bangun dasbor lengkap dengan dua puluh metrik dampak sekaligus supaya terlihat serius.
- B. Mulai dari data tiket yang sudah ada (jumlah RFI, jenis, waktu penyelesaian) ditambah jumlah deteksi yang lahir dari produk CTI, lalu bangun baseline tren tahun ke tahun.
- C. Laporkan jumlah laporan yang diterbitkan, karena angka itu paling mudah dihitung.

<details><summary>Jawaban</summary>

B. Metrik yang mudah diperoleh dan mudah ditafsirkan bisa dikumpulkan konsisten, dan baseline membuat angkanya bisa dibandingkan. Deteksi yang lahir dari CTI adalah metrik dampak yang paling mudah dilacak lewat metadata rule. A keliru karena metrik canggih yang tidak bisa dikumpulkan konsisten biasanya berhenti dilaporkan setelah dua bulan. C keliru karena jumlah laporan hanya mengukur kesibukan bila tidak dipasangkan dengan cakupan kebutuhan dan bukti pemakaian. Lihat bagian 1.5 dan 1.6.

</details>

**6. Pertanyaan jebakan.** "Di laporan untuk pimpinan, jangan tulis pertanyaan yang belum bisa kita jawab. Nanti tim CTI terlihat lemah." Tepatkah saran itu?

<details><summary>Jawaban</summary>

Tidak. Daftar kebutuhan yang belum terjawab beserta alasannya adalah cara paling efektif meminta sumber daya, jauh lebih baik daripada mengeluh kekurangan orang. Di lembar metrik PT LC, blok "belum bisa kami jawab" mengubah permintaan sumber daya menjadi pernyataan faktual, misalnya IR-2026-14 butuh sumber baru atau akses data pemasok, dan itu lebih sulit diabaikan. Halaman pimpinan pun menyediakan satu butir khusus untuk itu. Lihat bagian 1.7, 2.4, dan 2.5.

</details>

**7. Interview question (English).** "How would you show leadership that a CTI program is worth its cost?"

<details><summary>Sample answer</summary>

"I'd tie everything back to decisions. First, I keep requirements in a living register: each one has a named owner, a review date, a status, and the products that answered it, so I can show which questions we covered and which we didn't. Second, I report a few simple metrics consistently rather than a big dashboard: request volume and turnaround from our ticket data, the share of active requirements that got a product this quarter, and impact metrics like detections that came out of CTI, which I can trace because every CTI-driven rule carries the product ID in its metadata. I compare against the same quarter last year so the numbers mean something. I avoid reporting indicator counts or report counts on their own, because they measure spend and activity, not value. And on the one page for leadership, I include the questions we couldn't answer and what it would take, because that's the most credible way to ask for resources."

What makes this answer strong: it frames value as decisions supported, shows a concrete mechanism for traceability, picks metrics that can actually be collected and trended, avoids vanity metrics, and turns gaps into a resource request.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | CTI-CMM: Cyber Threat Intelligence Capability Maturity Model | https://www.cti-cmm.org/ | primer (situs kerangka) | versi 1.3 saat dilihat 2026-10-09 | Sedang-tinggi. Kerangka yang disusun komunitas, pendekatan Stakeholder First, sepuluh domain di versi 1.0 dengan domain Fraud ditambahkan di versi 1.1, dokumen tersedia gratis. Organisasi pemelihara dan tanggal terbit perlu dicek di dokumennya |
| S2 | SANS: Beyond Meh-trics, Examining How CTI Programs Demonstrate Value Using Metrics | https://www.sans.org/blog/beyond-meh-trics-examining-how-cti-programs-demonstrate-value-using-metrics | sekunder (blog praktisi) | dirujuk 2026-10-09 | Sedang. Anjuran memulai dari metrik yang mudah diperoleh dan mudah ditafsirkan, contoh data tiket, dan anjuran membangun baseline tren tahun ke tahun. Hanya anjuran umumnya yang dipakai |
| S3 | CTI-note Day 02 (siklus dan PIR), Day 05 (sumber dan etika), Day 10 (operasionalisasi), Day 11 (produk dan TLP), Day 13, Day 14 | (lokal) | rujukan internal | 2026-10-09 | Keterkaitan antar Day |
| S4 | Intel 471: Introducing the CTI Capability Maturity Model | https://www.intel471.com/blog/introducing-the-cti-capability-maturity-model-a-resource-for-measuring-and-building-mature-cti-programs | sekunder (blog salah satu penyusun) | diakses 2026-10-10 | Sedang-tinggi. Nama sepuluh domain versi 1.0 |
| S5 | CTI-CMM: assessor (repositori GitHub) | https://github.com/cti-cmm/assessor | primer | diakses 2026-10-10 | Tinggi. Sebelas domain, tingkat CTI0-CTI3 |

**Catatan sumber:** nama domain CTI-CMM di bagian 1.4 berasal dari tulisan salah satu penyusun dan repositori asesmennya; kolom contoh dukungan CTI adalah tafsiran sendiri, bukan teks kerangka. Cocokkan penamaan domain dengan dokumen versi terbaru bila dipakai untuk asesmen formal. Dari blog SANS hanya anjuran umumnya yang dipakai, bukan contoh rinci di dalamnya. Seluruh kriteria penilaian sumber di bagian 1.3, kelompok metrik di bagian 1.5, dan bentuk artefak di bagian 2 adalah susunan sendiri yang dikembangkan dari Day 02 dan Day 10, bukan kerangka baku dari sumber mana pun; pakai sebagai titik awal dan sesuaikan. Angka perbaikan yang beredar di tulisan vendor tentang program CTI sengaja tidak dipakai karena tidak disertai sumber yang bisa diverifikasi.
