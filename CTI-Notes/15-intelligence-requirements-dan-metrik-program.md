---
day: 15
title: 'Mengelola intelligence requirements dan mengukur program CTI'
researched_on: 2026-10-10
versions_checked: 'CTI-CMM (cti-cmm.org, versi 1.3 saat dirujuk 2026-10-09; 10 domain di versi 1.0, domain Fraud ditambahkan di versi 1.1; sponsor disebut di situsnya); SANS: Beyond Meh-trics (blog praktisi); rujukan Day 02, 05, 10, 11, 13, 14'
---

# Day 15: Intelligence requirements dan metrik program

Cakupan: mengubah daftar PIR menjadi sistem yang hidup, memilih sumber karena kebutuhan dan bukan sebaliknya, dan mengukur program dengan angka yang benar-benar memengaruhi keputusan.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- mengelola kebutuhan intelijen sebagai daftar hidup yang ditinjau berkala, bukan dokumen sekali jadi.
- menyusun matriks yang menghubungkan tiap kebutuhan ke sumber dan ke produk yang dihasilkannya.
- menilai sumber berdasarkan kemampuannya menjawab kebutuhan, lalu memutuskan menambah atau menghentikannya.
- menempatkan programmu pada model kematangan dan memilih satu langkah kenaikan yang realistis.
- memilih metrik yang mudah diperoleh dan mudah ditafsirkan sebagai titik awal.
- menyajikan nilai program CTI kepada pemangku kepentingan dengan bahasa keputusan mereka.

## 2. Konteks singkat

Day 02 memperkenalkan siklus intelijen, PIR, dan collection plan sebagai konsep. Day 10 menunjukkan cara mengoperasionalkan produknya. Yang belum dikerjakan adalah lapis manajemennya: apa yang terjadi pada daftar kebutuhan setelah tiga bulan, bagaimana memutuskan berhenti berlangganan satu sumber, dan apa yang kamu jawab ketika seseorang bertanya apakah tim CTI sepadan dengan biayanya.

Pertanyaan terakhir itu yang paling sering mematikan program CTI kecil. Tim yang sibuk menerbitkan laporan tetapi tidak bisa menunjukkan keputusan mana yang berubah karenanya akan selalu rentan saat anggaran ditinjau. Day ini membangun alat untuk menjawabnya, dan sekaligus alat untuk memperbaiki programnya sendiri.

## 3. Konsep inti

### 3.1 Kebutuhan sebagai daftar hidup

Masalah yang paling umum bukan ketiadaan PIR, melainkan PIR yang ditulis sekali lalu tidak pernah disentuh. Daftar yang hidup punya empat sifat:

- **Punya pemilik di sisi pemangku kepentingan.** Setiap kebutuhan ditautkan ke orang yang akan memakai jawabannya, bukan ke jabatan umum.
- **Punya tanggal tinjau.** Kebutuhan yang tidak ditinjau selama dua kuartal hampir pasti sudah tidak relevan atau sudah terjawab.
- **Punya status.** Aktif, terjawab sebagian, terjawab, atau ditutup karena tidak lagi relevan.
- **Punya jejak ke produk.** Setiap produk yang kamu terbitkan menyebut kebutuhan mana yang dijawabnya.

Sifat keempat yang paling banyak membawa manfaat. Ia memaksa dua hal sekaligus: produk yang tidak menjawab kebutuhan mana pun akan terlihat, dan kebutuhan yang tidak pernah menghasilkan produk juga akan terlihat. Keduanya adalah temuan.

### 3.2 Tiga tingkat kebutuhan, tiga jenis pembaca

| Tingkat | Pertanyaan khas | Pembaca | Ritme |
|---|---|---|---|
| Strategis | Ancaman apa yang paling relevan bagi bisnis kami tahun ini | Pimpinan, pemilik risiko | Kuartalan atau tahunan |
| Operasional | Aktor atau kampanye apa yang menyasar sektor kami sekarang | Manajer SOC, pemilik program | Bulanan |
| Taktis | Teknik dan indikator apa yang perlu kami deteksi | Analis, detection engineer, hunter | Mingguan atau harian |

Kesalahan yang berulang adalah menjawab kebutuhan satu tingkat dengan produk tingkat lain. Pimpinan yang bertanya soal risiko bisnis tidak terbantu oleh daftar indikator, dan detection engineer tidak terbantu oleh narasi lanskap. Sebelum menulis, tetapkan tingkatnya, lalu patuhi.

### 3.3 Memilih sumber karena kebutuhan

Urutannya satu arah: kebutuhan menentukan sumber, bukan sebaliknya. Program yang berlangganan dulu lalu mencari gunanya akan menumpuk biaya tanpa jawaban.

Cara menilai satu sumber, dan ini bisa dikerjakan tanpa alat apa pun:

| Kriteria | Pertanyaan |
|---|---|
| Relevansi | Kebutuhan mana yang bisa dijawabnya? Bila tidak ada, selesai. |
| Ketepatan waktu | Apakah ia memberi tahu cukup cepat untuk mengubah keputusan? |
| Keunikan | Berapa persen isinya yang tidak kamu peroleh dari sumber lain? |
| Dapat ditindaklanjuti | Berapa produk atau deteksi yang lahir darinya dalam kuartal terakhir? |
| Biaya total | Termasuk waktu analis untuk mengolahnya, bukan hanya harga langganan |

Kolom terakhir sering menentukan. Sumber gratis yang butuh enam jam kerja per minggu lebih mahal daripada langganan yang siap pakai, dan perhitungan itu jarang dilakukan.

Keputusan menghentikan sumber harus senormal keputusan menambahnya. Tetapkan peninjauan tahunan untuk semua sumber, dengan kriteria yang sama bagi yang gratis maupun berbayar.

### 3.4 Model kematangan sebagai peta, bukan nilai

CTI-CMM adalah kerangka yang disusun komunitas untuk memberi peta jalan peningkatan dukungan terhadap pemangku kepentingan [S1]. Pendekatannya disebut Stakeholder First, yaitu menyelaraskan praktik CTI dengan harapan kematangan tiap pemangku kepentingan [S1]. Versi 1.0 punya sepuluh domain yang masing-masing mendefinisikan praktik dukungan CTI untuk satu jenis pemangku kepentingan, dan domain Fraud ditambahkan di versi 1.1 [S1]. Versinya 1.3 saat dirujuk, dan dokumennya tersedia gratis [S1].

Kesepuluh domain di versi 1.0 diambil dari fungsi organisasi yang lazim dalam model kematangan keamanan siber, dan masing-masing mewakili satu kelompok pemangku kepentingan yang dilayani CTI [S4]:

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

Domain Fraud yang ditambahkan di versi 1.1 melayani tim anti-fraud, sehingga totalnya sebelas domain. Asesmennya memakai empat tingkat untuk setiap pernyataan praktik: CTI0 (belum ada kemampuan), CTI1 (sebagian), CTI2 (sebagian besar), dan CTI3 (penuh) [S5].

Gagasan intinya layak diambil terlepas dari kerangka mana yang kamu pakai: kematangan CTI diukur dari seberapa baik ia mendukung pemangku kepentingan, bukan dari seberapa canggih alatnya. Itu pembalikan yang berguna, karena banyak program menilai dirinya dari jumlah umpan dan platform.

Dua cara memakai model semacam ini, dan hanya satu yang berguna. Cara yang tidak berguna adalah mengejar angka kematangan sebagai target. Cara yang berguna adalah memakainya sebagai daftar periksa untuk menemukan pemangku kepentingan yang belum kamu layani sama sekali. Biasanya ada satu atau dua, dan itu peluang terbesar.

Satu peringatan sumber: penilaian berbasis skor sering menghasilkan angka yang rapi tetapi tidak bisa ditindaklanjuti. Yang perlu kamu hasilkan adalah daftar celah dan ketergantungan, bukan sekadar skor.

### 3.5 Metrik yang dimulai dari yang mudah

Nasihat yang paling berguna soal metrik CTI justru yang paling sederhana: mulai dari metrik yang mudah diperoleh, tidak rumit, dan mudah ditafsirkan, misalnya data tiket seperti jumlah permintaan, frekuensi, dan jenis pekerjaan yang diminta; lalu mulailah dengan analisis tren tahun ke tahun untuk membangun baseline [S2].

Alasannya praktis. Metrik canggih yang tidak bisa kamu kumpulkan secara konsisten akan berhenti dilaporkan setelah dua bulan, dan program yang tidak melaporkan apa pun lebih buruk daripada program yang melaporkan dua angka sederhana secara konsisten.

Empat kelompok metrik yang bisa kamu bangun bertahap:

| Kelompok | Contoh | Menjawab |
|---|---|---|
| Permintaan | Jumlah RFI, jenisnya, waktu penyelesaian | Siapa memakai kami dan untuk apa |
| Cakupan kebutuhan | Berapa persen kebutuhan aktif yang punya produk dalam kuartal ini | Apakah kami menjawab yang ditanyakan |
| Dampak | Deteksi yang lahir dari CTI, hunt yang dipicu CTI, keputusan yang berubah | Apakah kami mengubah sesuatu |
| Kesehatan sumber | Produk per sumber, keunikan, biaya total | Apakah belanja kami masuk akal |

Kelompok ketiga yang paling meyakinkan dan paling sulit dikumpulkan, karena butuh kerja sama tim lain. Mulailah dari yang paling mudah diukur di antaranya, yaitu jumlah deteksi yang lahir dari produk CTI, karena itu bisa dilacak dari repo deteksi, misalnya dengan mewajibkan setiap rule yang lahir dari produk CTI mencantumkan nomor produknya di metadata rule.

### 3.6 Metrik yang menyesatkan

Hindari melaporkan tiga hal ini sendirian:

- **Jumlah indikator yang dikonsumsi.** Naik seiring belanja, bukan seiring nilai. Bila harus dilaporkan, pasangkan dengan berapa yang pernah cocok dengan sesuatu.
- **Jumlah laporan yang diterbitkan.** Mengukur kesibukan. Pasangkan dengan cakupan kebutuhan dan dengan bukti produk itu dibaca atau dipakai.
- **Skor kematangan.** Berguna untuk arah, tidak berguna sebagai target, dan mudah dimanipulasi.

Pengganti yang lebih jujur untuk ketiganya adalah satu pertanyaan: keputusan apa yang berbeda karena pekerjaan kami bulan ini. Bila jawabannya kosong tiga bulan berturut-turut, itu temuan tentang programmu sendiri, dan lebih baik kamu yang menemukannya lebih dulu.

### 3.7 Menyajikan ke pemangku kepentingan

Tiga aturan yang membuat laporan program diterima:

1. **Pakai bahasa keputusan mereka.** Untuk pimpinan, bicarakan risiko yang turun dan keputusan yang didukung, bukan jumlah umpan.
2. **Tunjukkan tren, bukan potret.** Satu angka tanpa pembanding tidak bisa ditafsirkan; tren tahun ke tahun bisa [S2].
3. **Sertakan apa yang tidak bisa kamu jawab.** Daftar kebutuhan yang belum terjawab beserta alasannya adalah cara paling efektif meminta sumber daya, jauh lebih baik daripada mengeluh kekurangan orang.

## 4. Contoh artefak intelijen

> Seluruh isi bagian ini adalah ilustrasi dengan angka fiktif. Sesuaikan bentuknya dengan alat pelacakan yang kamu pakai.

### 4.1 Register kebutuhan intelijen

```yaml
- id: IR-2026-07
  tingkat: operasional
  pertanyaan: >
    Aktor atau kampanye mana yang menyasar penyedia layanan keuangan di Asia Tenggara
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

Cara memakainya: baris `produk_terkait` yang menutup siklus. Saat meninjau, kebutuhan tanpa produk dan produk tanpa kebutuhan sama-sama muncul ke permukaan.

### 4.2 Matriks kebutuhan ke sumber

| Kebutuhan | Lembaga publik | Langganan A | Berbagi sektor | Hasil internal | Terjawab? |
|---|---|---|---|---|---|
| IR-2026-07 | sebagian | ya | ya | tidak | sebagian |
| IR-2026-11 | ya | tidak | tidak | ya | sebagian |
| IR-2026-14 | tidak | tidak | tidak | tidak | belum |
| IR-2026-18 | ya | ya | sebagian | ya | ya |

Dua pembacaan yang langsung berguna. Baris IR-2026-14 tanpa satu pun sumber adalah celah pengumpulan, dan itu argumen konkret untuk menambah sumber atau mengubah kebutuhannya. Kolom Langganan A yang hanya berkontribusi pada dua baris adalah bahan untuk peninjauan tahunan sumber (bagian 3.3).

### 4.3 Lembar penilaian satu sumber

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

Angka pada baris keunikan ditulis sebagai perkiraan beserta dasarnya, bukan sebagai angka pasti. Kebiasaan ini yang membedakan penilaian sumber dari kesan subjektif.

### 4.4 Lembar metrik kuartalan

```
PROGRAM CTI, KUARTAL 3 2026

PERMINTAAN
  RFI masuk            41   (Q3 2025: 28)
  waktu selesai median 2 hari
  peminta terbanyak    SOC (22), manajemen risiko (9), infrastruktur (6)

CAKUPAN KEBUTUHAN
  kebutuhan aktif      14
  punya produk di Q3   9  (64 persen)
  tanpa sumber sama sekali  2   <- lihat matriks 4.2

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

Blok terakhir yang paling sering dihilangkan dan paling berguna. Ia mengubah permintaan sumber daya menjadi pernyataan faktual tentang pertanyaan yang belum bisa dijawab, dan itu jauh lebih sulit diabaikan.

### 4.5 Satu halaman untuk pimpinan

```
Judul   : Dukungan intelijen kuartal ini, dan ke mana kami mengarahkan kuartal depan
TLP     : <penanda sesuai Day 11>

1. Tiga keputusan yang kami dukung kuartal ini, dan apa yang berubah
2. Satu risiko yang naik, satu yang turun, dengan alasannya
3. Dua pertanyaan yang belum bisa kami jawab, dan apa yang dibutuhkan
4. Satu permintaan konkret
```

Empat butir, tidak lebih. Lampirkan lembar metrik bagian 4.4 sebagai lampiran, bukan sebagai isi utama, karena pimpinan jarang membaca tabel tetapi sering membaca empat butir.

## 5. Lab praktik

**Prasyarat:** hasil Day 02 (PIR dan collection plan), Day 10 (operasionalisasi), dan Day 13 (vulnerability intelligence).

1. Kumpulkan seluruh PIR yang pernah kamu tulis, lalu ubah menjadi register bagian 4.1 dengan kolom pemilik, status, dan tanggal tinjau terisi semua.
2. Untuk tiap kebutuhan, tautkan produk yang pernah kamu hasilkan. Hitung berapa kebutuhan tanpa produk dan berapa produk tanpa kebutuhan.
3. Susun matriks bagian 4.2 untuk seluruh kebutuhan dan seluruh sumber yang kamu pakai, termasuk sumber gratis.
4. Isi lembar penilaian bagian 4.3 untuk dua sumber, satu yang kamu anggap paling berguna dan satu yang paling diragukan. Pastikan biaya waktu analis ikut dihitung.
5. Ambil keputusan untuk sumber yang diragukan, lalu tulis alasannya dalam tiga kalimat yang bisa dibaca orang non-teknis.
6. Pakai tabel sebelas domain di bagian 3.4 sebagai daftar periksa untuk menemukan pemangku kepentingan yang belum kamu layani sama sekali. Tulis satu langkah untuk mulai melayani salah satunya.
7. Pilih tiga metrik dari bagian 3.5 yang benar-benar bisa kamu kumpulkan minggu ini tanpa alat baru, lalu kumpulkan datanya untuk dua kuartal terakhir sebagai baseline [S2].
8. Susun lembar metrik bagian 4.4 dengan angka nyata dari langkah 7, termasuk blok pertanyaan yang belum bisa dijawab.
9. Tulis satu halaman pimpinan bagian 4.5, lalu bacakan ke rekan non-teknis dan catat bagian mana yang tidak mereka pahami.
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

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Register penuh tetapi tidak ada yang dikerjakan | Kebutuhan ditulis terlalu umum untuk dijawab | Terapkan anatomi PIR dari Day 02; pecah menjadi pertanyaan yang bisa dijawab |
| Produk terbit terus tetapi tidak ditautkan ke kebutuhan | Tidak ada kebiasaan menautkan | Tambahkan baris kebutuhan ke templat produk |
| Beberapa kebutuhan tidak punya sumber sama sekali | Celah pengumpulan nyata | Pakai matriks 4.2 sebagai dasar permintaan sumber baru |
| Sumber berbiaya tinggi sulit dinilai | Biaya waktu analis tidak dihitung | Ukur jam kerja yang dipakai mengolahnya selama satu bulan |
| Metrik berhenti dilaporkan setelah dua bulan | Metriknya terlalu sulit dikumpulkan | Ganti dengan yang mudah diperoleh dan mudah ditafsirkan [S2] |
| Angka tidak bisa ditafsirkan | Tidak ada pembanding | Bangun baseline tren tahun ke tahun [S2] |
| Skor kematangan naik tetapi tidak ada yang membaik | Skor dikejar sebagai target | Hasilkan daftar celah, bukan skor |
| Pimpinan tidak merespons laporan | Bahasanya bahasa operasional, bukan bahasa keputusan | Pakai bentuk empat butir bagian 4.5 |
| Permintaan sumber daya selalu ditolak | Diajukan sebagai keluhan, bukan sebagai pertanyaan yang belum terjawab | Pakai blok terakhir bagian 4.4 |

## 7. Kesalahan umum dan jebakan

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

## 8. Catatan terkini

- CTI-CMM adalah kerangka yang disusun komunitas dengan pendekatan Stakeholder First, versinya 1.3 saat dirujuk, dan dokumennya tersedia gratis [S1]. Pendekatan yang mengukur kematangan dari dukungan terhadap pemangku kepentingan layak diadopsi walaupun kamu tidak memakai kerangkanya secara formal.
- Versi 1.0 memuat sepuluh domain yang masing-masing mendefinisikan praktik dukungan untuk satu jenis pemangku kepentingan, dan domain Fraud ditambahkan di versi 1.1 [S1]. Daftar domain itu berguna sebagai daftar periksa pemangku kepentingan, dan biasanya mengungkap satu atau dua yang belum kamu layani.
- Nasihat memulai dari metrik yang mudah diperoleh dan membangun baseline tren tahun ke tahun [S2] bertentangan dengan dorongan umum untuk langsung membuat dasbor lengkap. Dalam praktik, program yang konsisten melaporkan dua angka sederhana lebih dipercaya daripada yang sekali membuat dasbor lalu meninggalkannya.
- Penilaian kematangan yang hanya menghasilkan skor tidak bisa ditindaklanjuti; yang dibutuhkan adalah daftar celah dan ketergantungan. Simpan skornya untuk arah, dan bawa daftar celahnya ke rapat.
- Sebagian besar tulisan tentang metrik CTI berasal dari vendor dan memuat angka perbaikan yang tidak disertai sumber. Jangan memakai angka semacam itu sebagai patokan; bangun baseline sendiri.

## 9. Cheat sheet

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

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | CTI-CMM: Cyber Threat Intelligence Capability Maturity Model | https://www.cti-cmm.org/ | primer (situs kerangka) | versi 1.3 saat dilihat 2026-10-09 | Sedang-tinggi. Kerangka yang disusun komunitas, pendekatan Stakeholder First, sepuluh domain di versi 1.0 dengan domain Fraud ditambahkan di versi 1.1, dokumen tersedia gratis. Organisasi pemelihara dan tanggal terbit perlu dicek di dokumennya |
| S2 | SANS: Beyond Meh-trics, Examining How CTI Programs Demonstrate Value Using Metrics | https://www.sans.org/blog/beyond-meh-trics-examining-how-cti-programs-demonstrate-value-using-metrics | sekunder (blog praktisi) | dirujuk 2026-10-09 | Sedang. Anjuran memulai dari metrik yang mudah diperoleh dan mudah ditafsirkan, contoh data tiket, dan anjuran membangun baseline tren tahun ke tahun. Hanya anjuran umumnya yang dipakai |
| S3 | CTI-note Day 02 (siklus dan PIR), Day 05 (sumber dan etika), Day 10 (operasionalisasi), Day 11 (produk dan TLP), Day 13, Day 14 | (lokal) | rujukan internal | 2026-10-09 | Keterkaitan antar Day |
| S4 | Intel 471: Introducing the CTI Capability Maturity Model | https://www.intel471.com/blog/introducing-the-cti-capability-maturity-model-a-resource-for-measuring-and-building-mature-cti-programs | sekunder (blog salah satu penyusun) | diakses 2026-10-10 | Sedang-tinggi. Nama sepuluh domain versi 1.0 |
| S5 | CTI-CMM: assessor (repositori GitHub) | https://github.com/cti-cmm/assessor | primer | diakses 2026-10-10 | Tinggi. Sebelas domain, tingkat CTI0-CTI3 |

**Catatan sumber:** nama domain CTI-CMM di bagian 3.4 berasal dari tulisan salah satu penyusun dan repositori asesmennya; kolom contoh dukungan CTI adalah tafsiran sendiri, bukan teks kerangka. Cocokkan penamaan domain dengan dokumen versi terbaru bila dipakai untuk asesmen formal. Dari blog SANS hanya anjuran umumnya yang dipakai, bukan contoh rinci di dalamnya. Seluruh kriteria penilaian sumber di bagian 3.3, kelompok metrik di bagian 3.5, dan bentuk artefak di bagian 4 adalah susunan sendiri yang dikembangkan dari Day 02 dan Day 10, bukan kerangka baku dari sumber mana pun; pakai sebagai titik awal dan sesuaikan. Angka perbaikan yang beredar di tulisan vendor tentang program CTI sengaja tidak dipakai karena tidak disertai sumber yang bisa diverifikasi.
