---
day: 14
title: 'Ekosistem kriminal dibaca secara defensif: RaaS, access broker, dan data leak site'
researched_on: 2026-10-10
versions_checked: 'ENISA Threat Landscape 2026 (terbit 22 September 2026, mencakup insiden 2025); ENISA Threat Landscape 2025; #StopRansomware Guide (CISA, MS-ISAC, NSA, FBI, September 2023); ATT&CK T1486; rujukan Day 02, 03, 09, 10, 11, 13'
---

# Day 14: Ekosistem kriminal dibaca secara defensif

Cakupan: peran-peran yang membentuk ekonomi ransomware modern, akibat model RaaS pada konsistensi TTP, cara membaca klaim di data leak site tanpa tertipu, pergeseran dari enkripsi ke pemerasan data, vektor masuk yang berulang, batas etika pengumpulan intelijen, dan cara mengubah semua itu menjadi prioritas defensif.

## Ide inti

Banyak laporan menyebut nama kelompok ransomware seolah-olah itu organisasi tunggal dengan cara kerja tetap. Kenyataannya lebih berupa pasar: ada yang menjual akses, ada yang menyewakan perangkat lunak, ada yang mengerjakan serangannya, dan ada yang mengurus pembayaran. ENISA menggambarkan ekonomi ransomware sebagai ekosistem kriminal matang yang dibangun di sekitar access broker, layanan khusus, kredensial curian, dan mekanisme monetisasi [S1]. Pemahaman itu mengubah tiga hal praktis: cara kamu menafsirkan laporan tentang satu kelompok, cara kamu memprioritaskan pertahanan, dan cara kamu memperlakukan angka yang beredar.

Kamu sudah mengenal polanya dari DFIR. Satu framework C2 bisa dipakai banyak tim yang berbeda: artefak alatnya sama, tetapi cara masuk, alat pendamping, dan pola gerakan lateral tiap tim berbeda. Karena itu kamu tidak menulis rule untuk "tim X", melainkan untuk perilaku yang teramati. Model RaaS bekerja dengan cara yang sama: operator menyediakan ransomware dan mereknya, afiliasi yang berbeda-beda mengerjakan serangannya. Situs kebocoran (data leak site) juga punya padanan yang kamu kenal: catatan tebusan yang dipajang di depan umum. Isinya pernyataan pelaku yang ditulis untuk menekan, bukan bukti forensik.

```
infostealer di laptop karyawan -> kredensial dan sesi dijual
  -> initial access broker menjual akses ke jaringan korban
  -> afiliasi membeli akses, memakai ransomware milik operator RaaS
  -> gerakan lateral -> eksfiltrasi data -> enkripsi (tahap paling akhir)
  -> klaim di data leak site sebagai alat tekanan
Tiap tahap bisa dikerjakan pihak berbeda, dengan jeda sampai berbulan-bulan.
Pertahanan dibangun di sekitar teknik di tiap tahap, bukan di sekitar merek di ujungnya.
```

Batasnya ditetapkan sejak awal dan tidak dilanggar di Day ini. Catatan ini tidak membahas cara mengakses forum kriminal, cara berinteraksi dengan pelaku, atau cara memperoleh sampel atau alat mereka. Yang dibahas adalah membaca laporan publik dan hasil riset pihak lain, lalu memakainya untuk bertahan.

Situasi yang dipakai sepanjang Day ini: Rabu pagi, CISO PT Logistik Contoh (PT LC, perusahaan logistik fiktif dengan gudang di Jakarta, Surabaya, dan Medan) menerima ringkasan dari vendor berlisensi yang memantau situs kebocoran. Ringkasan itu menyebut satu perusahaan logistik di Asia Tenggara dicantumkan di situs kebocoran kelompok di balik ransomware-lab (fiktif). Direksi sudah membaca beritanya, dan CISO meneruskan pertanyaan ke tim CTI:

> "Direksi bertanya apakah kita berikutnya. Sebelum rapat Kamis, tolong jawab:
> 1. Dua laporan vendor tentang kelompok ini menyebut cara masuk yang berbeda. Mana yang benar, dan apa yang kita blokir?
> 2. Berita menyebut kelompok ini sudah punya puluhan korban. Boleh saya kutip angka itu ke direksi?
> 3. Cadangan kita bagus. Kalau kena, kita cukup restore, kan?
> 4. Dari mana mereka biasanya masuk, dan apa yang kita tutup dulu?
> 5. Ada staf yang usul kita cek langsung ke situs dan forumnya, apakah data atau kredensial kita sudah dijual. Boleh?"

Pertanyaan 1 dijawab di bagian 1.1 dan 1.2, pertanyaan 2 di bagian 1.3, pertanyaan 3 di bagian 1.4, pertanyaan 4 di bagian 1.5, dan pertanyaan 5 di bagian 1.6. Produk yang dikirim balik ke CISO ada di bagian 2.

**Kapan relevan:** saat membaca laporan tentang kelompok ransomware, menilai klaim situs kebocoran yang dikutip media atau vendor, memprioritaskan deteksi dan kontrol terhadap ransomware, dan menulis prosedur batas pengumpulan intelijen di timmu.
**Kapan bukan jawaban:** saat organisasimu sendiri muncul di situs kebocoran. Itu urusan respons insiden dan hukum, bukan analisis ekosistem. Day ini juga bukan panduan memantau infrastruktur kriminal secara langsung; pemantauan semacam itu wilayah penegak hukum dan pihak yang memang berizin.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Tabel ini memuat istilah yang muncul di Day ini. Kolom padanan memakai analogi SOC yang sama di semua Day CTI. Istilah dari Day sebelumnya (TTP, ATT&CK, PIR, bahasa keyakinan, atribusi) tidak diulang.

| Istilah | Arti singkat | Padanan di SOC |
|---|---|---|
| Ekosistem kriminal | Pasar peran yang saling menjual layanan: akses, perangkat lunak, eksekusi serangan, pembayaran | Timeline insiden yang tahap-tahapnya bisa dikerjakan pihak berbeda |
| Initial access broker | Pihak yang memperoleh lalu menjual akses ke jaringan korban | Sumber login valid dari lokasi tak lazim: di log tampak sah, padahal aksesnya dijual pihak lain |
| RaaS | Ransomware-as-a-Service: model sewa yang memisahkan pembuat ransomware dari pemakainya | Satu framework C2 dipakai banyak tim: artefak alat sama, TTP berbeda |
| Operator RaaS | Pihak yang mengembangkan dan menyewakan ransomware, infrastruktur, dan merek | Pembuat framework C2 |
| Afiliasi | Pihak yang mengerjakan serangan memakai perangkat lunak operator | Tim yang memakai framework itu dengan cara kerjanya sendiri |
| Infostealer | Malware pencuri kredensial dan sesi, yang hasilnya dijual | Asal kredensial bocor yang muncul di alert identitas |
| Data leak site | Situs tempat operator mempublikasikan klaim korban dan contoh data | Catatan tebusan yang dipajang publik: pernyataan pelaku, bukan bukti |
| Pemerasan berbasis data | Tekanan lewat ancaman pembocoran data, bukan hanya lewat enkripsi | Insiden yang dinilai dari data yang keluar, bukan dari jumlah host terenkripsi |
| Eksfiltrasi | Pemindahan data ke luar jaringan korban | Volume keluar tak lazim per host per tujuan |
| Denominator | Dasar hitungan sebuah persentase | Persentase per alert vs per insiden: angkanya tidak bisa dibandingkan |

### 1.1 Peran-peran dalam ekosistem

Pertanyaan pertama CISO berangkat dari anggapan bahwa "kelompok ini" adalah satu organisasi. Sebelum menilai laporan mana yang benar, petakan dulu siapa saja yang terlibat dalam satu serangan ransomware.

Tabel berikut memetakan setiap peran ke jejak yang bisa kamu lihat dari sisi korban. Perhatikan kolom ketiga: hanya jejak itulah yang bisa kamu deteksi atau pantau.

| Peran | Yang dikerjakan | Jejak yang bisa kamu lihat sebagai defender |
|---|---|---|
| Initial access broker | Memperoleh lalu menjual akses ke jaringan korban | Kredensial bocor, akses jarak jauh yang tidak dikenal, iklan akses di forum yang dilaporkan peneliti |
| Operator RaaS | Mengembangkan dan menyewakan perangkat lunak serta infrastrukturnya | Nama merek kelompok, situs kebocoran, catatan tebusan |
| Afiliasi | Mengerjakan serangan memakai perangkat lunak operator | TTP yang bervariasi walau nama kelompoknya sama |
| Penjual infostealer | Menjual malware pencuri kredensial dan hasilnya | Kredensial dan sesi yang bocor, lalu dipakai pihak lain |
| Layanan pendukung | Hosting, pencucian dana, negosiasi, dan sejenisnya | Jarang terlihat langsung dari sisi korban |

ENISA menyebut infostealer yang dijual di pasar kriminal terutama memungkinkan pencurian kredensial, pembajakan sesi, dan perantaraan akses [S1]. Rantai itu menjelaskan kenapa pencurian kredensial di laptop satu karyawan bisa berakhir sebagai insiden ransomware berbulan-bulan kemudian, lewat tangan yang berbeda.

Laporan ENISA juga mencatat adanya persilangan dengan aktor yang disponsori negara, misalnya aktor yang dilaporkan memakai ransomware tertentu dan aktor lain yang dikaitkan dengan aktivitas ransomware kemungkinan sebagai afiliasi atau access broker [S2]. Akibatnya pembagian rapi antara kriminal dan negara tidak selalu berlaku, dan atribusi berdasarkan jenis malware saja menjadi lemah.

### 1.2 RaaS dan akibatnya pada TTP

Dua laporan vendor yang menyebut cara masuk berbeda untuk kelompok yang sama belum tentu salah satunya keliru. Bila kelompok itu memakai model RaaS, keduanya bisa benar sekaligus.

Model RaaS memisahkan yang membuat perangkat lunak dari yang memakainya. ENISA menyebut proliferasi model RaaS, kebocoran builder, dan layanan access broker telah menurunkan hambatan masuk [S2].

Akibat yang paling penting bagi analis: TTP di bawah satu nama kelompok tidak konsisten. Dua insiden yang sama-sama dikaitkan ke satu nama bisa punya cara masuk, alat, dan pola gerakan yang sangat berbeda, karena yang mengerjakannya afiliasi yang berbeda. Kesimpulannya untuk pekerjaan sehari-hari:

- Jangan membangun pertahanan di sekitar nama kelompok. Bangunlah di sekitar teknik, karena teknik lebih stabil daripada merek.
- Saat membaca laporan, perhatikan apakah penulisnya menjelaskan tahap mana yang khas operator dan tahap mana yang khas afiliasi. Yang khas operator, misalnya perilaku enkripsi dan catatan tebusan, lebih konsisten.
- Saat memetakan ke ATT&CK (Day 04), petakan teknik yang teramati, bukan teknik yang pernah dikaitkan dengan nama itu di laporan lain.

Untuk CISO PT LC, jawaban pertanyaan pertama jadi berbalik: yang diblokir dan dideteksi adalah kedua cara masuk itu, karena afiliasi berikutnya bisa memakai salah satunya atau cara ketiga.

### 1.3 Data leak site dan cara membacanya

Angka "puluhan korban" di berita yang dibaca direksi hampir pasti berasal dari situs kebocoran, artinya dari pelaku sendiri. Sebelum angka itu masuk ke slide direksi, kamu perlu tahu sifat sumbernya.

Operator ransomware terus mengandalkan pemerasan dan pemaparan data lewat klaim publik di data leak site [S1]. Untuk analis, situs semacam ini adalah sumber data yang berguna sekaligus sumber kesalahan yang besar, dan dua sifatnya harus selalu diingat.

**Pertama, isinya diterbitkan pelaku.** Hitungan korban dari situs kebocoran mencerminkan apa yang dipublikasikan kriminal, bukan pelanggaran yang terkonfirmasi. ENISA sendiri mencatat datanya sebagian bersandar pada sumber terbuka dan banyak insiden bertumpu pada klaim pelaku. Konsekuensinya, setiap angka yang kamu kutip dari sumber semacam ini harus disertai kalimat yang menyatakan asalnya.

**Kedua, publikasi adalah bagian dari tekanan.** Daftar korban, hitung mundur, dan contoh berkas adalah alat negosiasi. Isi dan waktunya dipilih untuk menekan, bukan untuk akurasi. Klaim yang dilebih-lebihkan, korban yang dicantumkan padahal negosiasi masih berjalan, dan data lama yang disajikan sebagai baru adalah hal yang biasa.

Cara memakainya secara sah dan berguna: pantau lewat laporan peneliti dan layanan yang memang mengumpulkannya, catat tren sektor dan wilayah, dan pakai sebagai masukan untuk pertanyaan intelijen (Day 02), bukan sebagai bukti. Ringkasan vendor berlisensi yang diterima CISO PT LC adalah contoh jalur yang sah. Bila organisasimu muncul di sana, itu urusan respons insiden dan hukum, bukan urusan analisis.

### 1.4 Pergeseran dari enkripsi ke pemerasan data

Anggapan "cukup restore dari cadangan" hanya benar bila ancamannya enkripsi saja. Insiden 3 Oktober di PT LC juga baru terlihat saat ratusan file di file server keuangan berubah ekstensi, yaitu di tahap enkripsi.

ENISA membaca data tekniknya sebagai pergeseran menjauh dari enkripsi, dengan eksfiltrasi lewat kanal command and control disebut mencakup bagian terbesar dari teknik yang dilaporkan publik untuk operator paling aktif [S1]. Laporan sebelumnya juga mencatat sebagian besar intrusi yang terekam berakhir dengan data yang dibocorkan atau dijual di forum kriminal [S2].

Konsekuensinya untuk pertahanan cukup besar dan sering belum tercermin di banyak organisasi:

- **Deteksi tidak boleh bertumpu pada tahap enkripsi.** Enkripsi (T1486 Data Encrypted for Impact [S4]) adalah tahap paling akhir dan paling terlambat. Bila deteksimu terbaik di situ, kamu akan selalu terlambat. Geser bobot deteksi ke tahap sebelumnya: akses awal, pemakaian alat administrasi jarak jauh, penghapusan shadow copy (T1490), dan pengumpulan data.
- **Eksfiltrasi menjadi tahap kunci.** Deteksi volume keluar yang tidak lazim, akses berkas massal, dan kanal keluar yang tidak biasa menjadi lebih berharga daripada deteksi perilaku enkripsi. Dalam praktik, mulailah dari total byte keluar per host per tujuan dibandingkan dengan baseline host itu sendiri, lalu periksa host yang tiba-tiba mengirim jauh lebih banyak dari biasanya ke layanan penyimpanan cloud atau alamat yang belum pernah dihubungi.
- **Pemulihan dari cadangan tidak lagi menyelesaikan masalah.** Bila yang dipertaruhkan adalah pembocoran data, cadangan yang sempurna tidak menghapus tekanannya. Ini mengubah perencanaan respons dan komunikasi, bukan hanya teknis.

### 1.5 Vektor masuk yang berulang

Pertanyaan keempat CISO butuh daftar yang bisa diurutkan, bukan daftar semua kemungkinan. Panduan lembaga memberi daftar pendek yang bisa langsung dicocokkan dengan kondisi PT LC.

Panduan bersama CISA, MS-ISAC, NSA, dan FBI menyusun pencegahan berdasarkan vektor awal, dan menyebut enam yang utama [S3]: kerentanan dan salah konfigurasi yang menghadap internet termasuk layanan remote desktop yang terpapar, kredensial yang dikompromikan, phishing, infeksi malware pendahulu, rekayasa sosial lanjutan, serta pihak ketiga dan penyedia layanan terkelola.

Daftar itu praktis karena memberi tempat yang jelas untuk menaruh usaha. Tiga yang pertama bersentuhan langsung dengan Day 13: kerentanan yang menghadap internet adalah tepat sasaran prioritisasi berbasis paparan dan KEV, dan kredensial yang dikompromikan adalah titik temu dengan infostealer di bagian 1.1.

Vektor keenam, yaitu pihak ketiga dan penyedia layanan terkelola, adalah yang paling sering kurang diperhatikan dalam penilaian risiko internal, padahal jalur itu melewati seluruh kendali perimeter yang kamu bangun. Bagi PT LC, yang banyak vendornya masuk lewat VPN, vektor ini bukan teori: penilaian insiden 3 Oktober menyebut akses kemungkinan besar lewat akun VPN vendor, dengan keyakinan sedang.

### 1.6 Etika dan hukum dalam mengumpulkan intelijen

Usul staf untuk "cek langsung ke situs dan forumnya" terdengar proaktif, tetapi melanggar beberapa batas sekaligus. Kebutuhannya sah (apakah data atau kredensial PT LC beredar), caranya yang harus diganti.

Batas yang perlu kamu pegang, dan sebaiknya tertulis di prosedur timmu (lanjutan Day 05):

- **Jangan berinteraksi dengan pelaku.** Negosiasi, pembelian data, dan penyamaran adalah wilayah penegak hukum dan pihak yang memang berizin, bukan analis internal.
- **Jangan membeli apa pun dari pasar kriminal**, termasuk data yang katanya milik organisasimu sendiri. Selain masalah hukum, itu membiayai ekosistemnya.
- **Hati-hati menyimpan data bocoran.** Menyimpan data pribadi orang lain, walaupun untuk analisis, punya konsekuensi perlindungan data tersendiri (Day 16).
- **Pakai sumber sekunder yang sah.** Laporan peneliti, layanan komersial berizin, dan berbagi antar organisasi lewat jalur resmi.
- **Catat asal setiap klaim.** Terutama untuk klaim yang berasal dari pelaku.

Butir ketiga sering terlewat. Organisasi yang memeriksa apakah datanya bocor kadang mengunduh dan menyimpan kumpulan data besar berisi informasi pribadi pihak lain, dan dengan itu menciptakan masalah baru.

## 2. Contoh artefak intelijen

Nama kelompok, angka, dan tanggal di bagian ini adalah ilustrasi fiktif; untuk produk sungguhan, ambil dari laporan yang kamu baca sendiri dan sebutkan sumbernya. Keempat artefak di bawah adalah bahan jawaban tim CTI untuk pertanyaan CISO PT LC di bagian Ide inti.

### 2.1 Peta peran untuk satu insiden

Peta peran memisahkan apa yang teramati dari apa yang disimpulkan, dan dipakai saat menjelaskan ke CISO kenapa nama kelompok tidak cukup sebagai dasar tindakan. Contohnya memakai INC-2026-014, insiden ilustrasi yang tidak terkait dengan insiden PT LC.

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

**Cara membaca hasil:** pemisahan tiga blok ini yang menjaga laporan tetap jujur. Blok kedua memakai tingkat keyakinan seperti di Day 03, dan selalu menyertakan alasannya.

### 2.2 Membaca klaim data leak site

Templat ini dipakai untuk klaim yang memicu pertanyaan kedua CISO: satu baris di ringkasan vendor tentang perusahaan logistik yang dicantumkan di situs kebocoran.

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
  bila organisasi di sektor yang sama: tinjau vektor masuk di bagian 1.5 untuk sektor itu
  bila organisasi sendiri yang dicantumkan: jalur respons insiden dan hukum, bukan analisis
```

**Cara membaca hasil:** PT LC berada di sektor yang sama dengan korban yang dicantumkan, jadi tindakan yang relevan adalah baris pertama di blok terakhir. Angka "puluhan korban" masuk ke blok "yang tidak bisa dipakai" sebagai fakta; bila tetap dikutip ke direksi, sertakan asalnya.

### 2.3 Menerjemahkan tren menjadi prioritas

Ini bentuk produk yang paling sering diminta manajemen, dan yang paling sering ditulis terlalu umum. Untuk PT LC, tabel ini menjawab pertanyaan ketiga dan keempat CISO sekaligus.

| Temuan dari laporan | Artinya bagi kami | Tindakan | Pemilik |
|---|---|---|---|
| Pergeseran ke eksfiltrasi, bukan enkripsi [S1] | Deteksi kami terkuat di tahap enkripsi, yaitu terlambat | Tambah deteksi akses berkas massal dan volume keluar | Detection engineering |
| Access broker memakai kredensial dari infostealer [S1] | Laptop dengan kredensial tersimpan adalah titik awal | Pantau kredensial bocor, perketat akses jarak jauh | Identitas dan SOC |
| Layanan jarak jauh terpapar sebagai vektor utama [S3] | Dua layanan kami masih terpapar | Tutup atau beri kendali tambahan, tinjau tiap bulan | Infrastruktur |
| Pihak ketiga sebagai vektor [S3] | Tiga pemasok punya akses jaringan | Tinjau akses, batasi, catat | Pengadaan dan keamanan |

**Cara membaca hasil:** kolom kedua yang membuat produk ini bernilai. Tanpa kolom itu, yang kamu kirim hanyalah ringkasan laporan orang lain.

### 2.4 Pertanyaan intelijen yang lahir dari ekosistem

Pertanyaan kelima CISO tidak ditolak begitu saja: kebutuhannya diubah menjadi pertanyaan intelijen dengan sumber yang sah. Hasilnya menjadi umpan balik ke daftar kebutuhan intelijen (Day 02 dan Day 15).

```
PIR: Apakah kredensial milik organisasi kami muncul dalam kumpulan yang diperdagangkan?
  sumber sah : layanan pemantauan berizin, pemberitahuan dari penyedia identitas
  bukan      : mengunduh sendiri kumpulan data dari sumber kriminal

PIR: Vektor masuk apa yang paling sering dipakai terhadap sektor kami dalam 12 bulan terakhir?
  sumber : laporan industri dan laporan lembaga; pakai ini untuk mengurutkan pekerjaan di 2.3

PIR: Apakah pemasok kami pernah dicantumkan di situs kebocoran?
  catatan: perlakukan sebagai sinyal risiko pihak ketiga, bukan sebagai kepastian
```

**Cara membaca hasil:** di PT LC, pertanyaan kedua tumpang tindih dengan PIR-2026-003 yang sudah aktif (teknik akses awal kelompok ransomware yang menyasar logistik Asia Tenggara). Lebih rapi bila jawabannya digabung ke PIR itu daripada membuka PIR baru dengan pertanyaan yang hampir sama.

## 3. Lab praktik

**Prasyarat:** akses ke laporan publik lembaga dan peneliti. Seluruh lab ini bersifat membaca dan menulis, tanpa interaksi apa pun dengan infrastruktur atau pelaku kriminal.

1. Ambil satu laporan lanskap ancaman lembaga publik terbaru, baca bagian ransomware-nya, lalu tulis ringkasan setengah halaman yang memisahkan temuan dari metodologinya.
2. Untuk setiap angka yang kamu kutip, tulis dari mana datanya berasal dan apa denominatornya. Tandai angka yang denominatornya tidak jelas.
3. Pilih dua laporan dari penerbit berbeda tentang kelompok ransomware yang sama, lalu bandingkan TTP yang disebut masing-masing. Tulis perbedaannya dan jelaskan dengan model operator dan afiliasi di bagian 1.2.
4. Petakan teknik yang disebut kedua laporan ke ATT&CK (Day 04), lalu bandingkan dengan peta cakupan deteksimu (status per technique: tidak ada, sebagian, teruji). Tulis tiga celah terbesar.
5. Susun peta peran bagian 2.1 untuk satu insiden publik yang sudah dilaporkan lengkap, dengan ketiga blok terisi.
6. Isi templat penilaian klaim bagian 2.2 untuk satu klaim yang disebut di laporan peneliti. Jangan mengakses situs kebocorannya.
7. Susun tabel bagian 2.3 untuk organisasi fiktif dengan empat baris, pastikan kolom kedua benar-benar spesifik dan bukan pengulangan kolom pertama.
8. Tulis prosedur setengah halaman tentang batas etika pengumpulan intelijen di timmu, memakai daftar di bagian 1.6, lalu tandai bagian mana yang membutuhkan persetujuan hukum.
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

## 4. Troubleshooting

Tabel ini membantu mendiagnosis masalah yang paling sering muncul saat memakai laporan ekosistem ransomware. Cari gejala yang paling mirip dengan situasimu.

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Dua laporan memberi angka ransomware yang berbeda jauh | Denominatornya berbeda | Baca metodologinya; jangan bandingkan angka dengan dasar berbeda |
| TTP satu kelompok tidak konsisten antar laporan | Afiliasi berbeda mengerjakan serangan berbeda [S2] | Pisahkan yang khas operator dari yang khas afiliasi (bagian 1.2) |
| Hitungan korban dari situs kebocoran tidak cocok dengan insiden yang diketahui | Isinya klaim pelaku, bukan pelanggaran terverifikasi | Nyatakan asal klaim di tiap angka |
| Atribusi berdasarkan jenis malware meleset | Persilangan aktor negara dan kriminal [S2] | Jangan atribusi dari malware saja |
| Produk CTI tidak ditindaklanjuti | Hanya meringkas laporan, tanpa kolom "artinya bagi kami" | Pakai bentuk tabel bagian 2.3 |
| Deteksi selalu terlambat pada kasus ransomware | Bertumpu pada tahap enkripsi | Geser ke tahap eksfiltrasi dan gerakan [S1] |
| Permintaan untuk memverifikasi klaim dengan mengakses situsnya | Batas etika dan hukum terlampaui | Rujuk prosedur bagian 1.6; serahkan ke jalur yang berwenang |
| Tim menyimpan kumpulan data bocoran untuk analisis | Masalah perlindungan data baru | Hentikan; pakai layanan berizin dan jalur resmi |

## 5. Kesalahan umum dan jebakan

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

## 6. Catatan terkini

Bagian ini menampung tanggal terbit laporan dan arah tren yang perlu diperbarui setiap tahun. Isinya tidak mengubah cara membaca ekosistem di bagian 1, tetapi menentukan seberapa segar ringkasan yang kamu kirim ke manajemen.

- ENISA Threat Landscape 2026 terbit 22 September 2026 dan mencakup insiden sepanjang 2025, dengan ransomware sebagai ancaman paling berdampak dalam jangka pendek [S1]. Perbarui ringkasan ekosistem di timmu setahun sekali mengikuti terbitan semacam ini.
- Pembacaan ENISA atas data teknik menunjukkan pergeseran menjauh dari enkripsi menuju eksfiltrasi dan pemerasan data [S1]. Bila peta deteksimu masih berpusat pada tahap enkripsi, itu celah struktural, bukan kekurangan satu rule.
- Infostealer disebut terutama memungkinkan pencurian kredensial, pembajakan sesi, dan perantaraan akses [S1]. Rantai dari satu laptop terinfeksi sampai insiden ransomware melewati beberapa tangan, dan itu alasan kenapa penanganan kredensial bocor tidak bisa ditunda.
- Laporan sebelumnya mencatat persilangan antara aktor yang disponsori negara dan ekosistem ransomware, termasuk kemungkinan peran sebagai afiliasi atau access broker [S2]. Ini melemahkan atribusi berbasis alat dan memperkuat pentingnya bukti dari insidenmu sendiri.
- Panduan bersama lembaga menyusun pencegahan berdasarkan enam vektor awal, termasuk pihak ketiga dan penyedia layanan terkelola [S3]. Vektor terakhir itu paling sering luput dari penilaian risiko internal padahal melewati seluruh kendali perimeter.

## 7. Cheat sheet

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

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Seorang manajer berkata, "Nama kita tidak pernah muncul di situs kebocoran mana pun, jadi kita belum pernah kena ransomware." Benarkah kesimpulan itu?

<details><summary>Jawaban</summary>

Tidak. Isi situs kebocoran diterbitkan pelaku dan dipilih untuk menekan, bukan untuk akurasi. Ketiadaan di daftar bukan bukti tidak terjadi apa-apa, sama seperti keberadaan di daftar bukan bukti pelanggaran. Korban bisa tidak dicantumkan karena berbagai alasan yang tidak kamu ketahui, jadi pertanyaan "apakah kita pernah kena" dijawab dari telemetri dan investigasi sendiri, bukan dari situs pelaku. Lihat bagian 1.3 dan 2.2.

</details>

**2. Skenario keputusan.** Detection engineer PT LC menerima dua laporan vendor tentang kelompok yang sama: laporan pertama menyebut cara masuk lewat phishing, laporan kedua lewat layanan jarak jauh yang terpapar. Apa langkah yang paling tepat?

- A. Pilih laporan yang paling baru, anggap laporan lain sudah usang, lalu bangun rule set "kelompok X" dari laporan itu.
- B. Perlakukan keduanya sebagai kemungkinan cara masuk afiliasi yang berbeda, petakan teknik yang teramati ke ATT&CK, lalu perkuat deteksi untuk kedua teknik itu.
- C. Tunda pekerjaan deteksi sampai atribusi kelompok dipastikan.

<details><summary>Jawaban</summary>

B. Dalam model RaaS, afiliasi yang berbeda mengerjakan serangan dengan cara masuk, alat, dan gerakan yang berbeda di bawah nama yang sama, jadi dua laporan yang berbeda bisa benar sekaligus. A keliru karena membangun pertahanan di sekitar nama kelompok, padahal teknik lebih stabil daripada merek, dan laporan yang lebih baru tidak otomatis menggugurkan yang lama. C keliru karena deteksi berbasis teknik tidak membutuhkan atribusi; menunggu atribusi justru membuang waktu untuk hal yang paling lemah buktinya. Lihat bagian 1.2.

</details>

**3. Pertanyaan jebakan.** "Cadangan kita teruji dan terpisah dari jaringan, jadi ransomware tidak lagi jadi risiko besar bagi kita." Benarkah?

<details><summary>Jawaban</summary>

Tidak sepenuhnya. Cadangan menjawab enkripsi, tetapi ENISA membaca data tekniknya sebagai pergeseran menjauh dari enkripsi menuju eksfiltrasi dan pemerasan data, dan sebagian besar intrusi yang terekam berakhir dengan data dibocorkan atau dijual. Bila yang dipertaruhkan adalah pembocoran data, cadangan yang sempurna tidak menghapus tekanannya. Karena itu perencanaan respons dan komunikasi ikut berubah, dan deteksi perlu digeser ke tahap sebelum enkripsi, terutama eksfiltrasi. Lihat bagian 1.4.

</details>

**4. Jelaskan ulang.** Jelaskan kepada direksi PT LC dalam tiga kalimat kenapa angka "puluhan korban" dari situs kebocoran tidak boleh dikutip sebagai fakta.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Angka itu diterbitkan sendiri oleh kelompok penyerang di situs mereka, jadi isinya klaim pelaku, bukan pelanggaran yang sudah dikonfirmasi. Situs itu dipakai untuk menekan korban saat negosiasi, sehingga klaim yang dilebih-lebihkan atau data lama yang disajikan sebagai baru adalah hal biasa. Kita tetap bisa memakainya sebagai sinyal bahwa sektor logistik sedang disasar, asalkan setiap angka disertai keterangan bahwa sumbernya adalah pelaku."

Kesalahan yang sering muncul:
- Menyimpulkan angka itu pasti terlalu tinggi; yang benar, angkanya belum terverifikasi dan bisa meleset ke dua arah.
- Membuang data situs kebocoran sepenuhnya, padahal masih berguna sebagai sinyal sektor dan wilayah.
- Lupa menyebut bahwa angka yang dikutip harus selalu disertai asalnya.

</details>

**5. Skenario keputusan.** Staf PT LC mengusulkan cara memeriksa apakah kredensial karyawan sudah diperdagangkan. Pilihan mana yang tepat?

- A. Analis membuat akun samaran di forum kriminal untuk mencari iklan yang menyebut PT LC.
- B. Membeli kumpulan data yang katanya berisi kredensial PT LC, lalu mencocokkannya sendiri dan menyimpan salinannya untuk analisis berikutnya.
- C. Memakai layanan pemantauan berizin dan pemberitahuan dari penyedia identitas, mencatat asal setiap klaim, dan menyerahkan temuan ke jalur respons insiden bila kredensial memang bocor.

<details><summary>Jawaban</summary>

C. Kebutuhannya sah, jadi diubah menjadi pertanyaan intelijen dengan sumber sekunder yang sah. A keliru karena berinteraksi dengan pelaku dan penyamaran adalah wilayah penegak hukum dan pihak yang berizin, bukan analis internal. B keliru dua kali: membeli dari pasar kriminal bermasalah secara hukum dan membiayai ekosistemnya, dan menyimpan kumpulan data bocoran berisi data pribadi orang lain menciptakan masalah perlindungan data baru. Lihat bagian 1.6 dan 2.4.

</details>

**6. Pertanyaan jebakan.** Analisis malware sebuah insiden ransomware menunjukkan keluarga ransomware yang pernah dilaporkan dipakai oleh aktor yang disponsori negara. "Berarti pelakunya aktor negara." Tepatkah kesimpulan itu?

<details><summary>Jawaban</summary>

Tidak. ENISA mencatat persilangan antara aktor yang disponsori negara dan ekosistem ransomware, termasuk aktor yang dikaitkan dengan aktivitas ransomware kemungkinan sebagai afiliasi atau access broker. Dalam model RaaS, perangkat lunak yang sama juga disewakan ke banyak afiliasi. Jadi atribusi berdasarkan jenis malware saja lemah; yang lebih kuat adalah bukti dari insiden sendiri, dipisahkan antara yang teramati, yang disimpulkan dengan tingkat keyakinan, dan yang tidak diketahui. Lihat bagian 1.1 dan 2.1.

</details>

**7. Interview question (English).** "How does the ransomware-as-a-service model change the way you defend against ransomware?"

<details><summary>Sample answer</summary>

"RaaS splits the people who build the ransomware from the affiliates who actually run the intrusions, and access is often bought from initial access brokers who got the credentials from infostealers. That means TTPs under one group name are inconsistent: two reports on the same brand can describe different entry points and both be right. So I don't build defences around group names. I map the techniques actually observed to ATT&CK and close gaps by technique, treating operator traits like the encryption behaviour and ransom note as the more stable part. I also shift detection weight away from encryption, which is the last and latest stage, towards initial access, remote admin tooling, shadow copy deletion, and especially exfiltration, because the pressure is increasingly about leaked data, and backups don't solve that. And when leak site numbers come up, I treat them as attacker-published claims, not confirmed breaches."

What makes this answer strong: it explains the role split and its effect on TTP consistency, turns that into a concrete technique-based defence strategy, reflects the shift towards data extortion, and shows sound judgement about leak site data.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | ENISA Threat Landscape 2026 | https://www.enisa.europa.eu/publications/enisa-threat-landscape-2026 | primer (laporan lembaga) | terbit 22 September 2026, mencakup insiden 2025; dirujuk 2026-10-09 | Sedang-tinggi. Ransomware sebagai ancaman paling berdampak jangka pendek, ekosistem yang dibangun di sekitar access broker dan layanan khusus, peran infostealer, pemakaian data leak site, dan pembacaan pergeseran menuju eksfiltrasi. Hanya pernyataan kualitatif yang dipakai |
| S2 | ENISA Threat Landscape 2025 | https://www.enisa.europa.eu/sites/default/files/2026-01/ENISA%20Threat%20Landscape%202025_v1.2.pdf | primer (laporan lembaga) | terbit Oktober 2025; dirujuk 2026-10-09 | Sedang-tinggi. Proliferasi RaaS dan kebocoran builder yang menurunkan hambatan masuk, penjualan data oleh access broker, dan persilangan aktor negara dengan ekosistem ransomware. Hanya pernyataan kualitatif yang dipakai |
| S3 | #StopRansomware Guide (CISA, MS-ISAC, NSA, FBI) | https://www.cisa.gov/stopransomware | primer (panduan lembaga) | September 2023; dirujuk 2026-10-09 | Tinggi. Dua bagian panduan, enam vektor masuk utama termasuk pihak ketiga dan MSP, serta jalur pelaporan. |
| S4 | MITRE ATT&CK: T1486 Data Encrypted for Impact | https://attack.mitre.org/techniques/T1486/ | primer | dirujuk 2026-10-09 | Tinggi untuk ID teknik |
| S5 | CTI-note Day 02, 03, 04, 05, 09, 10, 11, 13 | (lokal) | rujukan internal | 2026-10-09 | Keterkaitan antar Day |

**Catatan sumber:** dari kedua laporan ENISA hanya pernyataan kualitatif tentang struktur ekosistem dan arah pergeserannya yang dipakai; angka persentasenya sengaja tidak dikutip karena denominatornya perlu dicek langsung di laporan. Bila kamu membutuhkan angkanya untuk produk sungguhan, baca laporannya langsung dan catat denominatornya. Nama kelompok ransomware sengaja tidak disebut di bagian konsep, karena penyebutan nama tanpa konteks laporan yang kamu baca sendiri justru mendorong kesalahan yang dibahas di bagian 1.2. Seluruh isi bagian 2 adalah ilustrasi dengan nama, angka, dan tanggal fiktif. Day ini tidak memuat informasi tentang cara mengakses infrastruktur kriminal, dan itu disengaja.
