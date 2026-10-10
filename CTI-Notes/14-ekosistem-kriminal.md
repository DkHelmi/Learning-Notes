---
day: 14
title: 'Ekosistem kriminal dibaca secara defensif: RaaS, access broker, dan data leak site'
researched_on: 2026-10-10
versions_checked: 'ENISA Threat Landscape 2026 (terbit 22 September 2026, mencakup insiden 2025); ENISA Threat Landscape 2025; #StopRansomware Guide (CISA, MS-ISAC, NSA, FBI, September 2023); ATT&CK T1486; rujukan Day 02, 03, 09, 10, 11, 13'
---

# Day 14: Ekosistem kriminal dibaca secara defensif

Cakupan: peran-peran yang membentuk ekonomi ransomware modern, cara membaca klaim di data leak site tanpa tertipu, dan apa yang bisa dilakukan tim defensif dengan pemahaman itu.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menyebutkan peran-peran dalam ekosistem ransomware dan menjelaskan kenapa pembagian peran itu mengubah cara bertahan.
- menjelaskan model RaaS dan akibat pemisahan operator dari afiliasi terhadap konsistensi TTP.
- membaca klaim di data leak site sebagai data yang diterbitkan penyerang, bukan sebagai fakta terverifikasi.
- menjelaskan pergeseran dari enkripsi ke pemerasan berbasis data dan artinya bagi deteksi.
- menetapkan batas etika dan hukum dalam mengumpulkan intelijen tentang ekosistem ini.
- mengubah pemahaman ekosistem menjadi prioritas defensif yang konkret.

## 2. Konteks singkat

Banyak laporan menyebut nama kelompok ransomware seolah-olah itu organisasi tunggal dengan cara kerja tetap. Kenyataannya lebih berupa pasar: ada yang menjual akses, ada yang menyewakan perangkat lunak, ada yang mengerjakan serangannya, dan ada yang mengurus pembayaran. ENISA menggambarkan ekonomi ransomware sebagai ekosistem kriminal matang yang dibangun di sekitar access broker, layanan khusus, kredensial curian, dan mekanisme monetisasi [S1].

Pemahaman itu bukan sekadar pengetahuan umum. Ia mengubah tiga hal praktis: cara kamu menafsirkan laporan tentang satu kelompok, cara kamu memprioritaskan pertahanan, dan cara kamu memperlakukan angka yang beredar. Day ini membahas ketiganya, dan sepenuhnya dari sisi defensif.

Batasnya ditetapkan sejak awal dan tidak dilanggar di Day ini. Catatan ini tidak membahas cara mengakses forum kriminal, cara berinteraksi dengan pelaku, atau cara memperoleh sampel atau alat mereka. Yang dibahas adalah membaca laporan publik dan hasil riset pihak lain, lalu memakainya untuk bertahan.

## 3. Konsep inti

### 3.1 Peran-peran dalam ekosistem

| Peran | Yang dikerjakan | Jejak yang bisa kamu lihat sebagai defender |
|---|---|---|
| Initial access broker | Memperoleh lalu menjual akses ke jaringan korban | Kredensial bocor, akses jarak jauh yang tidak dikenal, iklan akses di forum yang dilaporkan peneliti |
| Operator RaaS | Mengembangkan dan menyewakan perangkat lunak serta infrastrukturnya | Nama merek kelompok, situs kebocoran, catatan tebusan |
| Afiliasi | Mengerjakan serangan memakai perangkat lunak operator | TTP yang bervariasi walau nama kelompoknya sama |
| Penjual infostealer | Menjual malware pencuri kredensial dan hasilnya | Kredensial dan sesi yang bocor, lalu dipakai pihak lain |
| Layanan pendukung | Hosting, pencucian dana, negosiasi, dan sejenisnya | Jarang terlihat langsung dari sisi korban |

ENISA menyebut infostealer yang dijual di pasar kriminal terutama memungkinkan pencurian kredensial, pembajakan sesi, dan perantaraan akses [S1]. Rantai itu penting untuk dipahami karena ia menjelaskan kenapa pencurian kredensial di laptop satu karyawan bisa berakhir sebagai insiden ransomware berbulan-bulan kemudian, lewat tangan yang berbeda.

Laporan ENISA juga mencatat adanya persilangan dengan aktor yang disponsori negara, misalnya aktor yang dilaporkan memakai ransomware tertentu dan aktor lain yang dikaitkan dengan aktivitas ransomware kemungkinan sebagai afiliasi atau access broker [S2]. Artinya pembagian rapi antara kriminal dan negara tidak selalu berlaku, dan atribusi berdasarkan jenis malware saja menjadi lemah.

### 3.2 RaaS dan akibatnya pada TTP

Model RaaS memisahkan yang membuat perangkat lunak dari yang memakainya. ENISA menyebut proliferasi model RaaS, kebocoran builder, dan layanan access broker telah menurunkan hambatan masuk [S2].

Akibat yang paling penting bagi analis: TTP di bawah satu nama kelompok tidak konsisten. Dua insiden yang sama-sama dikaitkan ke satu nama bisa punya cara masuk, alat, dan pola gerakan yang sangat berbeda, karena yang mengerjakannya afiliasi yang berbeda. Kesimpulannya untuk pekerjaan sehari-hari:

- Jangan membangun pertahanan di sekitar nama kelompok. Bangunlah di sekitar teknik, karena teknik lebih stabil daripada merek.
- Saat membaca laporan, perhatikan apakah penulisnya menjelaskan tahap mana yang khas operator dan tahap mana yang khas afiliasi. Yang khas operator, misalnya perilaku enkripsi dan catatan tebusan, lebih konsisten.
- Saat memetakan ke ATT&CK (Day 04), petakan teknik yang teramati, bukan teknik yang pernah dikaitkan dengan nama itu di laporan lain.

### 3.3 Data leak site dan cara membacanya

Operator ransomware terus mengandalkan pemerasan dan pemaparan data lewat klaim publik di data leak site [S1]. Untuk analis, situs semacam ini adalah sumber data yang berguna sekaligus sumber kesalahan yang besar, dan dua sifatnya harus selalu diingat.

**Pertama, isinya diterbitkan pelaku.** Hitungan korban dari situs kebocoran mencerminkan apa yang dipublikasikan kriminal, bukan pelanggaran yang terkonfirmasi. ENISA sendiri mencatat datanya sebagian bersandar pada sumber terbuka dan banyak insiden bertumpu pada klaim pelaku. Konsekuensinya, setiap angka yang kamu kutip dari sumber semacam ini harus disertai kalimat yang menyatakan asalnya.

**Kedua, publikasi adalah bagian dari tekanan.** Daftar korban, hitung mundur, dan contoh berkas adalah alat negosiasi. Isi dan waktunya dipilih untuk menekan, bukan untuk akurasi. Klaim yang dilebih-lebihkan, korban yang dicantumkan padahal negosiasi masih berjalan, dan data lama yang disajikan sebagai baru adalah hal yang biasa.

Cara memakainya secara sah dan berguna: pantau lewat laporan peneliti dan layanan yang memang mengumpulkannya, catat tren sektor dan wilayah, dan pakai sebagai masukan untuk pertanyaan intelijen (Day 02), bukan sebagai bukti. Bila organisasimu muncul di sana, itu urusan respons insiden dan hukum, bukan urusan analisis.

### 3.4 Pergeseran dari enkripsi ke pemerasan data

ENISA membaca data tekniknya sebagai pergeseran menjauh dari enkripsi, dengan eksfiltrasi lewat kanal command and control disebut mencakup bagian terbesar dari teknik yang dilaporkan publik untuk operator paling aktif [S1]. Laporan sebelumnya juga mencatat sebagian besar intrusi yang terekam berakhir dengan data yang dibocorkan atau dijual di forum kriminal [S2].

Konsekuensinya untuk pertahanan cukup besar dan sering belum tercermin di banyak organisasi:

- **Deteksi tidak boleh bertumpu pada tahap enkripsi.** Enkripsi adalah tahap paling akhir dan paling terlambat. Bila deteksimu terbaik di situ, kamu akan selalu terlambat. Geser bobot deteksi ke tahap sebelumnya: akses awal, pemakaian alat administrasi jarak jauh, penghapusan shadow copy (T1490), dan pengumpulan data.
- **Eksfiltrasi menjadi tahap kunci.** Deteksi volume keluar yang tidak lazim, akses berkas massal, dan kanal keluar yang tidak biasa menjadi lebih berharga daripada deteksi perilaku enkripsi. Dalam praktik, mulailah dari total byte keluar per host per tujuan dibandingkan dengan baseline host itu sendiri, lalu periksa host yang tiba-tiba mengirim jauh lebih banyak dari biasanya ke layanan penyimpanan cloud atau alamat yang belum pernah dihubungi.
- **Pemulihan dari cadangan tidak lagi menyelesaikan masalah.** Bila yang dipertaruhkan adalah pembocoran data, cadangan yang sempurna tidak menghapus tekanannya. Ini mengubah perencanaan respons dan komunikasi, bukan hanya teknis.

### 3.5 Vektor masuk yang berulang

Panduan bersama CISA, MS-ISAC, NSA, dan FBI menyusun pencegahan berdasarkan vektor awal, dan menyebut enam yang utama [S3]: kerentanan dan salah konfigurasi yang menghadap internet termasuk layanan remote desktop yang terpapar, kredensial yang dikompromikan, phishing, infeksi malware pendahulu, rekayasa sosial lanjutan, serta pihak ketiga dan penyedia layanan terkelola.

Daftar itu praktis karena memberi tempat yang jelas untuk menaruh usaha. Tiga yang pertama bersentuhan langsung dengan Day 13: kerentanan yang menghadap internet adalah tepat sasaran prioritisasi berbasis paparan dan KEV, dan kredensial yang dikompromikan adalah titik temu dengan infostealer di bagian 3.1.

Vektor keenam, yaitu pihak ketiga dan penyedia layanan terkelola, adalah yang paling sering kurang diperhatikan dalam penilaian risiko internal, padahal jalur itu melewati seluruh kendali perimeter yang kamu bangun.

### 3.6 Etika dan hukum dalam mengumpulkan intelijen

Batas yang perlu kamu pegang, dan sebaiknya tertulis di prosedur timmu (lanjutan Day 05):

- **Jangan berinteraksi dengan pelaku.** Negosiasi, pembelian data, dan penyamaran adalah wilayah penegak hukum dan pihak yang memang berizin, bukan analis internal.
- **Jangan membeli apa pun dari pasar kriminal**, termasuk data yang katanya milik organisasimu sendiri. Selain masalah hukum, itu membiayai ekosistemnya.
- **Hati-hati menyimpan data bocoran.** Menyimpan data pribadi orang lain, walaupun untuk analisis, punya konsekuensi perlindungan data tersendiri (Day 16).
- **Pakai sumber sekunder yang sah.** Laporan peneliti, layanan komersial berizin, dan berbagi antar organisasi lewat jalur resmi.
- **Catat asal setiap klaim.** Terutama untuk klaim yang berasal dari pelaku.

Butir ketiga sering terlewat. Organisasi yang memeriksa apakah datanya bocor kadang mengunduh dan menyimpan kumpulan data besar berisi informasi pribadi pihak lain, dan dengan itu menciptakan masalah baru.

## 4. Contoh artefak intelijen

> Nama kelompok, angka, dan tanggal di bawah adalah ilustrasi. Untuk produk sungguhan, ambil dari laporan yang kamu baca sendiri dan sebutkan sumbernya.

### 4.1 Peta peran untuk satu insiden

Dipakai untuk memisahkan apa yang teramati dari apa yang disimpulkan:

```
INSIDEN: INC-2026-014

TERAMATI
  akses awal   : sesi VPN memakai kredensial karyawan, dari ASN tidak lazim, 2026-09-18
  gerakan      : SMB ke dua server berkas, named pipe pengelolaan layanan (pola eksekusi jarak jauh lewat service)
  eksfiltrasi  : 44 GB keluar lewat HTTPS ke penyedia penyimpanan, 2026-09-27
  dampak akhir : enkripsi sebagian, catatan tebusan bermerek <nama>

DISIMPULKAN (dengan tingkat keyakinan)
  akses kemungkinan dibeli dari access broker   [sedang]  alasan: jeda 9 hari antara
    kredensial muncul di laporan infostealer dan pemakaian pertama; tidak ada phishing teramati
  pelaksana kemungkinan afiliasi, bukan operator [sedang] alasan: TTP gerakan berbeda dari
    laporan publik untuk nama yang sama

TIDAK DIKETAHUI
  identitas afiliasi, cara akses diperoleh broker, apakah data benar-benar dipublikasikan
```

Cara memakainya: pemisahan tiga blok ini yang menjaga laporan tetap jujur. Blok kedua memakai tingkat keyakinan seperti di Day 03, dan selalu menyertakan alasannya.

### 4.2 Membaca klaim data leak site

Templat penilaian untuk satu klaim:

```
KLAIM        : <kelompok> mencantumkan <organisasi> pada <tanggal>
SUMBER       : laporan peneliti <X> tanggal <Y>  (bukan dari situsnya langsung)
SIFAT SUMBER : diterbitkan PELAKU; belum terverifikasi

YANG BISA DIPAKAI
  sinyal sektor dan wilayah yang sedang disasar
  perkiraan waktu: klaim biasanya muncul setelah negosiasi gagal
  nama kelompok sebagai petunjuk awal TTP operator (bukan afiliasi)

YANG TIDAK BISA DIPAKAI
  jumlah data sebagai fakta
  keberadaan di daftar sebagai bukti terjadinya pelanggaran
  ketiadaan di daftar sebagai bukti tidak terjadi apa-apa

TINDAKAN DEFENSIF
  bila organisasi di sektor yang sama: tinjau vektor masuk di bagian 3.5 untuk sektor itu
  bila organisasi sendiri yang dicantumkan: jalur respons insiden dan hukum, bukan analisis
```

### 4.3 Menerjemahkan tren menjadi prioritas

Bentuk produk yang paling sering diminta manajemen, dan yang paling sering ditulis terlalu umum:

| Temuan dari laporan | Artinya bagi kami | Tindakan | Pemilik |
|---|---|---|---|
| Pergeseran ke eksfiltrasi, bukan enkripsi [S1] | Deteksi kami terkuat di tahap enkripsi, yaitu terlambat | Tambah deteksi akses berkas massal dan volume keluar | Detection engineering |
| Access broker memakai kredensial dari infostealer [S1] | Laptop dengan kredensial tersimpan adalah titik awal | Pantau kredensial bocor, perketat akses jarak jauh | Identitas dan SOC |
| Layanan jarak jauh terpapar sebagai vektor utama [S3] | Dua layanan kami masih terpapar | Tutup atau beri kendali tambahan, tinjau tiap bulan | Infrastruktur |
| Pihak ketiga sebagai vektor [S3] | Tiga pemasok punya akses jaringan | Tinjau akses, batasi, catat | Pengadaan dan keamanan |

Kolom kedua yang membuat produk ini bernilai. Tanpa kolom itu, yang kamu kirim hanyalah ringkasan laporan orang lain.

### 4.4 Pertanyaan intelijen yang lahir dari ekosistem

Umpan balik ke daftar kebutuhan intelijen (Day 02 dan Day 15):

```
PIR: Apakah kredensial milik organisasi kami muncul dalam kumpulan yang diperdagangkan?
  sumber sah : layanan pemantauan berizin, pemberitahuan dari penyedia identitas
  bukan      : mengunduh sendiri kumpulan data dari sumber kriminal

PIR: Vektor masuk apa yang paling sering dipakai terhadap sektor kami dalam 12 bulan terakhir?
  sumber : laporan industri dan laporan lembaga; pakai ini untuk mengurutkan pekerjaan di 4.3

PIR: Apakah pemasok kami pernah dicantumkan di situs kebocoran?
  catatan: perlakukan sebagai sinyal risiko pihak ketiga, bukan sebagai kepastian
```

## 5. Lab praktik

**Prasyarat:** akses ke laporan publik lembaga dan peneliti. Seluruh lab ini bersifat membaca dan menulis, tanpa interaksi apa pun dengan infrastruktur atau pelaku kriminal.

1. Ambil satu laporan lanskap ancaman lembaga publik terbaru, baca bagian ransomware-nya, lalu tulis ringkasan setengah halaman yang memisahkan temuan dari metodologinya.
2. Untuk setiap angka yang kamu kutip, tulis dari mana datanya berasal dan apa denominatornya. Tandai angka yang denominatornya tidak jelas.
3. Pilih dua laporan dari penerbit berbeda tentang kelompok ransomware yang sama, lalu bandingkan TTP yang disebut masing-masing. Tulis perbedaannya dan jelaskan dengan model operator dan afiliasi di bagian 3.2.
4. Petakan teknik yang disebut kedua laporan ke ATT&CK (Day 04), lalu bandingkan dengan peta cakupan deteksimu (status per technique: tidak ada, sebagian, teruji). Tulis tiga celah terbesar.
5. Susun peta peran bagian 4.1 untuk satu insiden publik yang sudah dilaporkan lengkap, dengan ketiga blok terisi.
6. Isi templat penilaian klaim bagian 4.2 untuk satu klaim yang disebut di laporan peneliti. Jangan mengakses situs kebocorannya.
7. Susun tabel bagian 4.3 untuk organisasi fiktif dengan empat baris, pastikan kolom kedua benar-benar spesifik dan bukan pengulangan kolom pertama.
8. Tulis prosedur setengah halaman tentang batas etika pengumpulan intelijen di timmu, memakai daftar di bagian 3.6, lalu tandai bagian mana yang membutuhkan persetujuan hukum.
9. Rumuskan tiga pertanyaan intelijen baru dari apa yang kamu baca, lengkap dengan sumber yang sah untuk menjawabnya.

**Hasil yang sebaiknya tersimpan:**
- Ringkasan laporan yang memisahkan temuan dari metodologi.
- Daftar angka yang dikutip beserta sumber dan denominatornya.
- Perbandingan TTP dua laporan untuk kelompok yang sama.
- Pemetaan ATT&CK beserta tiga celah deteksi terbesar.
- Peta peran lengkap untuk satu insiden publik.
- Penilaian satu klaim data leak site memakai templat.
- Tabel terjemahan tren menjadi prioritas untuk organisasi fiktif.
- Prosedur batas etika pengumpulan intelijen.
- Tiga pertanyaan intelijen baru beserta sumber sahnya.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Dua laporan memberi angka ransomware yang berbeda jauh | Denominatornya berbeda | Baca metodologinya; jangan bandingkan angka dengan dasar berbeda |
| TTP satu kelompok tidak konsisten antar laporan | Afiliasi berbeda mengerjakan serangan berbeda [S2] | Pisahkan yang khas operator dari yang khas afiliasi (bagian 3.2) |
| Hitungan korban dari situs kebocoran tidak cocok dengan insiden yang diketahui | Isinya klaim pelaku, bukan pelanggaran terverifikasi | Nyatakan asal klaim di tiap angka |
| Atribusi berdasarkan jenis malware meleset | Persilangan aktor negara dan kriminal [S2] | Jangan atribusi dari malware saja |
| Produk CTI tidak ditindaklanjuti | Hanya meringkas laporan, tanpa kolom "artinya bagi kami" | Pakai bentuk tabel bagian 4.3 |
| Deteksi selalu terlambat pada kasus ransomware | Bertumpu pada tahap enkripsi | Geser ke tahap eksfiltrasi dan gerakan [S1] |
| Permintaan untuk memverifikasi klaim dengan mengakses situsnya | Batas etika dan hukum terlampaui | Rujuk prosedur bagian 3.6; serahkan ke jalur yang berwenang |
| Tim menyimpan kumpulan data bocoran untuk analisis | Masalah perlindungan data baru | Hentikan; pakai layanan berizin dan jalur resmi |

## 7. Kesalahan umum dan jebakan

- Memperlakukan nama kelompok ransomware sebagai organisasi dengan cara kerja tetap.
- Membangun pertahanan di sekitar nama kelompok, bukan di sekitar teknik.
- Mengutip angka dari situs kebocoran sebagai fakta terverifikasi.
- Menganggap ketiadaan organisasi di situs kebocoran sebagai bukti tidak terjadi apa-apa.
- Membandingkan persentase dari laporan berbeda tanpa memeriksa denominatornya.
- Mengatribusikan insiden berdasarkan jenis malware saja.
- Menumpukan deteksi pada tahap enkripsi, yang merupakan tahap paling akhir.
- Mengandalkan cadangan sebagai jawaban lengkap, padahal tekanannya berupa pembocoran data.
- Berinteraksi dengan pelaku atau membeli data, termasuk data organisasi sendiri.
- Menyimpan kumpulan data bocoran berisi informasi pribadi pihak lain untuk dianalisis sendiri.

## 8. Catatan terkini

- ENISA Threat Landscape 2026 terbit 22 September 2026 dan mencakup insiden sepanjang 2025, dengan ransomware sebagai ancaman paling berdampak dalam jangka pendek [S1]. Perbarui ringkasan ekosistem di timmu setahun sekali mengikuti terbitan semacam ini.
- Pembacaan ENISA atas data teknik menunjukkan pergeseran menjauh dari enkripsi menuju eksfiltrasi dan pemerasan data [S1]. Bila peta deteksimu masih berpusat pada tahap enkripsi, itu celah struktural, bukan sekadar kekurangan satu rule.
- Infostealer disebut terutama memungkinkan pencurian kredensial, pembajakan sesi, dan perantaraan akses [S1]. Rantai dari satu laptop terinfeksi sampai insiden ransomware melewati beberapa tangan, dan itu alasan kenapa penanganan kredensial bocor tidak bisa ditunda.
- Laporan sebelumnya mencatat persilangan antara aktor yang disponsori negara dan ekosistem ransomware, termasuk kemungkinan peran sebagai afiliasi atau access broker [S2]. Ini melemahkan atribusi berbasis alat dan memperkuat pentingnya bukti dari insidenmu sendiri.
- Panduan bersama lembaga menyusun pencegahan berdasarkan enam vektor awal, termasuk pihak ketiga dan penyedia layanan terkelola [S3]. Vektor terakhir itu paling sering luput dari penilaian risiko internal padahal melewati seluruh kendali perimeter.

## 9. Cheat sheet

```
EKOSISTEM, BUKAN ORGANISASI
  initial access broker (jual akses) | operator RaaS (sewakan perangkat lunak + merek)
  afiliasi (kerjakan serangan)       | penjual infostealer (kredensial + sesi)
  layanan pendukung (hosting, dana, negosiasi)
  rantai khas: infostealer -> kredensial -> broker -> afiliasi -> ransomware (berbulan-bulan)

RaaS -> TTP TIDAK KONSISTEN di bawah satu nama
  yang KHAS OPERATOR lebih stabil (perilaku enkripsi, catatan tebusan)
  yang KHAS AFILIASI berubah-ubah (cara masuk, alat, gerakan)
  => bertahan berdasarkan TEKNIK, bukan nama kelompok
  => petakan ke ATT&CK dari yang TERAMATI, bukan dari yang pernah dikaitkan ke nama itu

DATA LEAK SITE
  isinya DITERBITKAN PELAKU; hitungan = apa yang dipublikasikan, BUKAN pelanggaran terverifikasi
  publikasi = alat TEKANAN (waktu dan isi dipilih untuk menekan, bukan untuk akurat)
  BISA dipakai: sinyal sektor/wilayah, petunjuk awal TTP operator
  TIDAK bisa : jumlah data sebagai fakta | ada di daftar = terbukti | tidak ada = aman
  akses lewat laporan peneliti / layanan berizin, JANGAN langsung

PERGESERAN   dari enkripsi ke EKSFILTRASI + pemerasan data
  deteksi yang bertumpu pada tahap enkripsi = SELALU TERLAMBAT
  geser ke: akses berkas massal, volume keluar tak lazim, kanal keluar tak biasa
  cadangan sempurna TIDAK menghapus tekanan pembocoran -> ubah rencana respons & komunikasi

VEKTOR AWAL (panduan lembaga)
  1 kerentanan/salah konfigurasi menghadap internet (termasuk remote desktop terpapar)
  2 kredensial dikompromikan   3 phishing   4 malware pendahulu
  5 rekayasa sosial lanjutan   6 PIHAK KETIGA / MSP  <- paling sering luput

ETIKA (tertulis di prosedur tim)
  JANGAN berinteraksi dengan pelaku | JANGAN membeli apa pun (termasuk data sendiri)
  JANGAN menyimpan kumpulan data bocoran | pakai sumber sekunder yang sah
  catat ASAL setiap klaim, terutama yang berasal dari pelaku

PRODUK  tabel: temuan laporan | ARTINYA BAGI KAMI | tindakan | pemilik
        kolom kedua yang membuatnya bernilai; tanpa itu cuma ringkasan laporan orang
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | ENISA Threat Landscape 2026 | https://www.enisa.europa.eu/publications/enisa-threat-landscape-2026 | primer (laporan lembaga) | terbit 22 September 2026, mencakup insiden 2025; dirujuk 2026-10-09 | Sedang-tinggi. Ransomware sebagai ancaman paling berdampak jangka pendek, ekosistem yang dibangun di sekitar access broker dan layanan khusus, peran infostealer, pemakaian data leak site, dan pembacaan pergeseran menuju eksfiltrasi. Hanya pernyataan kualitatif yang dipakai |
| S2 | ENISA Threat Landscape 2025 | https://www.enisa.europa.eu/sites/default/files/2026-01/ENISA%20Threat%20Landscape%202025_v1.2.pdf | primer (laporan lembaga) | terbit Oktober 2025; dirujuk 2026-10-09 | Sedang-tinggi. Proliferasi RaaS dan kebocoran builder yang menurunkan hambatan masuk, penjualan data oleh access broker, dan persilangan aktor negara dengan ekosistem ransomware. Hanya pernyataan kualitatif yang dipakai |
| S3 | #StopRansomware Guide (CISA, MS-ISAC, NSA, FBI) | https://www.cisa.gov/stopransomware | primer (panduan lembaga) | September 2023; dirujuk 2026-10-09 | Tinggi. Dua bagian panduan, enam vektor masuk utama termasuk pihak ketiga dan MSP, serta jalur pelaporan. |
| S4 | MITRE ATT&CK: T1486 Data Encrypted for Impact | https://attack.mitre.org/techniques/T1486/ | primer | dirujuk 2026-10-09 | Tinggi untuk ID teknik |
| S5 | CTI-note Day 02, 03, 04, 05, 09, 10, 11, 13 | (lokal) | rujukan internal | 2026-10-09 | Keterkaitan antar Day |

**Catatan sumber:** dari kedua laporan ENISA hanya pernyataan kualitatif tentang struktur ekosistem dan arah pergeserannya yang dipakai; angka persentasenya sengaja tidak dikutip karena denominatornya perlu dicek langsung di laporan. Bila kamu membutuhkan angkanya untuk produk sungguhan, baca laporannya langsung dan catat denominatornya. Nama kelompok ransomware sengaja tidak disebut di bagian konsep, karena penyebutan nama tanpa konteks laporan yang kamu baca sendiri justru mendorong kesalahan yang dibahas di bagian 3.2. Seluruh isi bagian 4 adalah ilustrasi dengan nama, angka, dan tanggal fiktif. Day ini tidak memuat informasi tentang cara mengakses infrastruktur kriminal, dan itu disengaja.
