---
day: 01
title: 'Fondasi keamanan: CIA, AAA, threat, vulnerability, risk, control, dan prinsip desain'
researched_on: 2026-10-20
versions_checked: 'NIST CSRC Glossary (entri diakses 2026-10-20); NIST SP 800-12 Rev. 1 (Jun 2017); NIST SP 800-30 Rev. 1 (Sep 2012); NIST SP 800-207 (Agu 2020); NIST SP 800-207A (Sep 2023); NIST SP 1800-35 (Jun 2025); CISA Zero Trust Maturity Model 2.0 (Apr 2023); NIST CSF 2.0 (Feb 2024); RFC 2975 (Okt 2000); RFC 2865 (Jun 2000)'
---

# Day 01: Fondasi keamanan (CIA, AAA, threat, vulnerability, risk, control, dan prinsip desain)

Cakupan: istilah paling dasar di cyber security, yaitu sifat yang dijaga (CIA), cara sistem mengenali dan mencatat pengguna (AAA dan non-repudiation), bahasa ancaman dan risiko (asset, threat, threat actor, vulnerability, exploit, risk, likelihood, impact), jenis control, serta prinsip desain defense in depth, least privilege, separation of duties, zero trust, dan attack surface.

## Ide inti

Hampir semua pekerjaan keamanan menjawab tiga pertanyaan yang sama. Pertama, apa yang dilindungi dan sifat apa yang harus dijaga darinya: kerahasiaannya, keutuhannya, atau ketersediaannya. Kedua, apa yang bisa salah dan seberapa buruk akibatnya: siapa atau apa yang mengancam, lewat celah apa, seberapa mungkin terjadi, dan seberapa besar kerugiannya. Ketiga, apa yang dipasang untuk mencegah, mengetahui, dan memulihkan, dan bagaimana semua pengaman itu disusun. Semua istilah di Day ini adalah alat untuk menjawab tiga pertanyaan itu dengan bahasa yang sama dengan rekan kerja, auditor, dan atasan.

Penghubung ketiganya adalah risk. Tidak ada organisasi yang punya uang dan waktu untuk menutup semua celah, jadi pengaman dipilih berdasarkan risiko terbesar, bukan berdasarkan alat yang paling canggih. Karena itu analyst yang baik tidak berhenti di "ada serangan"; ia bertanya serangan itu mengenai apa, sifat apa yang rusak, dan pengaman mana yang bekerja atau gagal.

Bayangkan rumah. Rumah dan isinya adalah yang dilindungi. Kemungkinan rumah kemalingan adalah ancaman, dan malingnya adalah pelaku. Jendela belakang yang tidak terkunci adalah kelemahan, dan cara mencongkel jendela itu adalah alat untuk memanfaatkannya. Seberapa besar kamu perlu khawatir bergantung pada dua hal: seberapa sering maling berkeliaran di kompleksmu, dan seberapa berharga isi rumahmu. Pagar dan kunci mencegah, CCTV memberi tahu, asuransi dan tukang servis memulihkan. Batas analogi ini perlu diingat sejak awal: "maling" di internet bisa mencoba ribuan rumah per menit secara otomatis, data yang dicuri tetap ada di tempatnya sehingga pencurian bisa tidak terasa, dan risiko di dunia TI biasanya dinilai dengan kategori seperti rendah, sedang, tinggi, bukan angka pasti.

```
  threat actor  --memakai-->  exploit  --masuk lewat-->  vulnerability  --mengenai-->  asset
  (siapa)                     (cara)                     (celah)                      (yang dilindungi)
                                                                                          |
                                                          bila berhasil: kerahasiaan (C), keutuhan (I), atau ketersediaan (A) rusak (impact)

  risk    = seberapa mungkin terjadi (likelihood) digabung seberapa parah akibatnya (impact)
  control = preventive (cegah) | detective (ketahui) | corrective (pulihkan)
  prinsip = defense in depth, least privilege, separation of duties, zero trust, attack surface kecil
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), sebuah ISP (penyedia layanan internet) fiktif dengan sekitar 1.200 karyawan dan sekitar 400 ribu pelanggan internet rumah. PT JAB punya SOC (Security Operations Center), tim yang memantau keamanan perusahaan 24 jam dan menangani alert, yaitu peringatan otomatis dari sistem pemantauan. Perusahaan ini pernah kena ransomware (program yang mengunci file lalu meminta tebusan) pada Oktober 2026, insiden `INC-2026-017`; penyerang masuk lewat server aplikasi lama `jkt-dmz-app01` yang tidak punya pengaman di dalam servernya. Kamu baru bergabung sebagai analyst L1 (lapis pertama yang memeriksa alert) di SOC itu. Senin 2027-08-02 pukul 08:30, hari pertama orientasi, mentormu Sari Kusuma (analyst L2) mengirim pesan:

> "Selamat datang. Minggu ini kamu belum pegang antrean alert; tugasmu memahami bahasa yang kami pakai. Pakai `jkt-portal01` sebagai bahan, itu server portal pelanggan kita: tempat pelanggan login, melihat tagihan dan data pribadinya, membayar, dan mengganti paket. Coba jawab: apa yang harus dijaga di portal itu, dan dijaga dari kerusakan seperti apa? Bagaimana portal tahu siapa yang login, apa yang boleh dia lihat, dan apa yang dia lakukan? Kalau ada pelanggan yang bilang tidak pernah mengganti paketnya, bisakah kita membuktikan sebaliknya? Siapa yang mungkin menyerang portal, lewat celah apa, dan dengan cara apa? Dari semua itu, mana yang paling perlu dikhawatirkan, dan bagaimana kita menilainya? Pengaman apa saja yang sudah terpasang dan apa fungsinya? Kenapa akunmu tidak bisa masuk ke server portal, padahal kamu analyst keamanan? Tim Infrastruktur bilang admin portal sekarang diperiksa ulang setiap kali masuk, walaupun dari kantor; kenapa begitu? Terakhir, dari mana saja portal bisa diserang? Semalam ada alert `SOC-2027-0800` di portal. Siang ini kita bedah bareng pakai istilah-istilah itu."

Pesan itu memuat delapan pertanyaan:

1. Apa yang harus dijaga di portal, dan dari kerusakan seperti apa?
2. Bagaimana portal mengenali, membatasi, dan mencatat pengguna, dan bisakah pelanggan menyangkal tindakannya?
3. Siapa yang mungkin menyerang, lewat celah apa, dengan cara apa?
4. Mana yang paling perlu dikhawatirkan, dan bagaimana menilainya?
5. Pengaman apa yang terpasang, apa fungsinya, dan bagaimana disusun?
6. Kenapa akun analyst tidak bisa masuk ke server portal?
7. Kenapa admin diperiksa ulang walaupun masuk dari jaringan kantor?
8. Dari mana saja portal bisa diserang?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5 dan 1.6, pertanyaan 6 di bagian 1.7, pertanyaan 7 di bagian 1.8, dan pertanyaan 8 di bagian 1.9. Bagian 2 membedah alert `SOC-2027-0800` dan memakai semua istilah itu sekaligus.

**Kapan relevan:** setiap kali kamu harus menjelaskan kenapa sesuatu perlu diamankan, menilai seberapa serius sebuah temuan, memilih atau mengusulkan pengaman, menulis laporan untuk orang non-teknis, dan menjawab pertanyaan dasar saat interview. Saat memeriksa alert, istilah ini membantu menentukan sifat mana yang terdampak dan pengaman mana yang bekerja.
**Kapan bukan jawaban:** istilah ini tidak memberi tahu cara teknis memasang pengaman (aturan penyaring jaringan, rule deteksi, konfigurasi server) dan tidak menggantikan prosedur penanganan insiden. Saat serangan sedang berlangsung, yang dibutuhkan adalah langkah respons; istilah Day ini dipakai untuk melaporkan dan memutuskan prioritas, bukan alasan untuk menunda tindakan.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Ini Day pertama topik ini, jadi semua istilah yang dipakai di Day ini dimuat di sini, termasuk istilah pendukung yang muncul di contoh. Kolom padanan memakai analogi sehari-hari yang dipakai di seluruh topik; cari kolom itu bila sebuah istilah terasa abstrak.

| Istilah | Arti singkat | Padanan sehari-hari |
|---|---|---|
| CIA triad | Tiga sifat informasi yang dijaga: confidentiality, integrity, availability | Brankas, isi brankas, dan jam buka bank |
| Confidentiality | Hanya pihak yang berhak bisa melihat informasi | Brankas hanya bisa dibuka pegawai yang berwenang |
| Integrity | Informasi tidak berubah atau rusak tanpa izin, dan asalnya asli | Jumlah uang di brankas cocok dengan buku catatan |
| Availability | Informasi dan layanan bisa dipakai saat dibutuhkan | Bank buka di jam layanan sehingga nasabah bisa mengambil uang |
| Authentication | Membuktikan bahwa pengguna memang orang yang ia klaim | Resepsionis mencocokkan wajah tamu dengan KTP |
| Authorization | Menentukan apa yang boleh dilakukan pengguna yang sudah dikenali | Kartu tamu hanya membuka lantai yang dituju |
| Accounting | Mencatat siapa memakai apa, kapan, dan berapa banyak | Buku tamu dan catatan kartu akses gedung |
| AAA | Singkatan authentication, authorization, accounting | Resepsionis, kartu tamu, buku tamu |
| Non-repudiation | Bukti yang membuat pelaku tidak bisa menyangkal tindakannya | Tanda tangan di slip penarikan bank |
| Asset | Apa pun yang bernilai bagi organisasi: data, sistem, perangkat, orang, fasilitas | Rumah dan isinya |
| Threat | Keadaan atau kejadian yang berpotensi merugikan | Kemungkinan rumah kemalingan |
| Threat actor | Orang atau kelompok di balik ancaman yang disengaja | Maling |
| Vulnerability | Kelemahan yang bisa dimanfaatkan atau terpicu | Jendela yang tidak terkunci |
| Exploit | Cara, kode, atau alat untuk memanfaatkan kelemahan | Cara mencongkel jendela itu |
| Risk | Ukuran seberapa terancam, gabungan likelihood dan impact | Peluang dan kerugian kemalingan |
| Likelihood | Seberapa mungkin ancaman benar-benar terjadi | Seberapa sering maling berkeliaran di kompleks |
| Impact | Seberapa besar kerugian bila terjadi | Seberapa banyak barang berharga yang bisa hilang |
| Control | Pengaman (alat, aturan, atau proses) untuk menurunkan risiko | Pagar, kunci, CCTV, asuransi |
| Preventive control | Pengaman yang mencegah kejadian | Pagar dan kunci |
| Detective control | Pengaman yang mengetahui dan mencatat kejadian | CCTV dan alarm |
| Corrective control | Pengaman yang membatasi kerusakan dan memulihkan | Asuransi dan tukang servis |
| Defense in depth | Pengaman berlapis dengan jenis yang berbeda-beda | Pagar, satpam, pintu berkunci, brankas |
| Least privilege | Hak akses sekecil yang dibutuhkan untuk tugas | Kartu akses karyawan hanya membuka lantai kerjanya |
| Separation of duties | Tugas penting dipecah ke beberapa orang | Pencairan uang diajukan satu pegawai, disetujui pegawai lain |
| Zero trust | Tidak ada akses yang dipercaya otomatis hanya karena lokasinya | Gedung yang memeriksa kartu di setiap pintu, bukan hanya di lobi |
| Attack surface | Semua titik yang bisa dicoba penyerang untuk masuk atau mengambil data | Jumlah pintu, jendela, dan lubang ventilasi rumah |
| Alamat IP | Alamat sebuah perangkat di jaringan; dibahas di Day 02 | Alamat rumah lengkap |
| Log | Catatan kejadian yang ditulis otomatis oleh sistem | Buku catatan satpam |
| SIEM | Sistem yang mengumpulkan log dari banyak sumber, mencarinya, dan memunculkan alert | Ruang monitor CCTV seluruh gedung |
| Firewall | Penyaring koneksi jaringan berdasarkan alamat dan layanan tujuan | Penjaga gerbang yang cek KTP dan alamat tujuan tamu |
| WAF | Web application firewall, penyaring khusus isi permintaan ke aplikasi web | Petugas yang memeriksa isi formulir sebelum diteruskan ke loket |
| EDR | Endpoint detection and response, agen di komputer atau server yang mengawasi perilaku program | Satpam yang berpatroli di dalam ruangan |
| Patch | Pembaruan perangkat lunak yang menutup kelemahan | Tukang yang memperbaiki kunci jendela |
| Enkripsi | Mengacak data sehingga hanya pemegang kunci yang bisa membacanya | Surat bersandi yang hanya bisa dibaca penerima |
| OTP | One-time password, kode sekali pakai yang dikirim ke HP | Kode verifikasi yang dikirim bank saat transaksi |

### 1.1 CIA triad: confidentiality, integrity, availability

Pertanyaan pertama Sari adalah titik awal semua analisis: sebelum bicara serangan, tentukan dulu apa yang dijaga dari portal `jkt-portal01` dan kerusakan seperti apa yang tidak boleh terjadi.

**Apa itu:** CIA triad adalah tiga sifat yang dijaga oleh keamanan informasi. Confidentiality berarti menjaga batasan siapa yang boleh mengakses dan melihat informasi, termasuk melindungi privasi pribadi. Integrity berarti mencegah informasi diubah atau dirusak tanpa izin, termasuk memastikan informasi itu asli dan pengirimnya tidak bisa menyangkal. Availability berarti informasi bisa diakses dan dipakai tepat waktu dan andal [S1][S11]. Di dokumen resmi ketiganya disebut security objectives.

**Analogi:** bank dan brankasnya. Confidentiality: hanya pegawai berwenang yang bisa membuka brankas dan melihat isinya. Integrity: jumlah uang di brankas selalu cocok dengan buku catatan, tidak ada yang menambah atau mengurangi diam-diam. Availability: bank buka di jam layanan, jadi nasabah bisa mengambil uang saat butuh. Batasnya: tiga sifat ini saling tarik, tidak bisa dicentang satu per satu secara terpisah. Brankas yang terlalu sulit dibuka menjaga kerahasiaan, tetapi membuat nasabah menunggu lama; itu mengorbankan ketersediaan.

**Cara kerja:** setiap kali menilai sebuah sistem atau kejadian, ajukan tiga pertanyaan.

| Sifat | Pertanyaan yang diajukan | Contoh kerusakan |
|---|---|---|
| Confidentiality | Siapa yang bisa melihat ini, dan apakah hanya yang berhak? | Data pribadi pelanggan bocor, tagihan orang lain terlihat |
| Integrity | Bisakah ini berubah tanpa izin atau tanpa ketahuan? | Nominal tagihan diubah, halaman depan portal diganti tulisan penyerang |
| Availability | Bisakah ini dipakai saat dibutuhkan? | Portal mati, database terkunci ransomware, server penuh |

Contoh tarik-menarik di portal: mewajibkan OTP untuk setiap login memperkuat confidentiality, tetapi bila layanan pengirim SMS terganggu, pelanggan tidak bisa masuk sama sekali dan availability turun. Karena itu usulan mitigasi di bagian 2.2 mewajibkan OTP hanya untuk perubahan paket dan data pribadi, tempat risikonya paling tinggi.

Satu kejadian bisa merusak lebih dari satu sifat. Ransomware modern biasanya mengunci data (availability) sekaligus mencuri salinannya untuk diancam disebarkan (confidentiality).

**Contoh di PT JAB:** isi portal tidak sama pentingnya untuk ketiga sifat. Tabel berikut memetakan isi `jkt-portal01` ke sifat yang paling kritis; cari kolom Prioritas untuk melihat kenapa pengaman yang dibutuhkan setiap bagian berbeda.

| Isi atau fungsi portal | Prioritas | Alasan |
|---|---|---|
| Nama, NIK, alamat, nomor HP pelanggan | Confidentiality | Data pribadi; bocor berarti kerugian bagi pelanggan dan kewajiban hukum bagi PT JAB |
| Nominal tagihan dan riwayat pembayaran | Integrity | Angka yang berubah tanpa izin merugikan pelanggan atau perusahaan |
| Halaman pembayaran menjelang jatuh tempo | Availability | Bila mati saat ribuan pelanggan ingin membayar, layanan dan pendapatan terganggu |
| Perubahan paket langganan | Integrity | Perubahan harus benar-benar dilakukan pemilik akun |

**Beda dengan privasi:** privasi adalah hak seseorang atas data pribadinya (untuk apa dipakai, berapa lama disimpan, siapa yang diberi). Confidentiality adalah salah satu alat untuk memenuhi hak itu, tetapi privasi juga mencakup hal yang tidak diatur CIA, misalnya memakai data pelanggan untuk tujuan yang tidak pernah disetujui, walaupun data itu tidak bocor.

**Salah paham umum:**
- "CIA hanya rusak karena hacker." Kenyataannya, ancaman juga datang dari kesalahan manusia, perangkat yang rusak, dan bencana [S12]. Admin yang salah menghapus tabel merusak integrity dan availability tanpa ada penyerang.

### 1.2 AAA (authentication, authorization, accounting) dan non-repudiation

Pertanyaan kedua Sari menyangkut apa yang terjadi setiap kali pelanggan login ke portal, dan apa yang tersisa sebagai bukti setelahnya.

**Apa itu:** AAA adalah tiga layanan yang berjalan berurutan setiap kali seseorang memakai sistem [S3]. Authentication adalah proses memverifikasi identitas pengguna, proses, atau perangkat, biasanya sebagai syarat sebelum diberi akses [S3]. Authorization adalah hak akses yang diberikan kepada pengguna, program, atau proses, atau tindakan memberikan hak itu [S3]. Accounting adalah pengumpulan data pemakaian sumber daya untuk analisis kapasitas, audit, dan penagihan [S18]. Di dunia keamanan, sisi accounting yang paling dipakai adalah catatan audit: siapa melakukan apa, kapan, dan dari mana. NIST menyebut tujuan ini accountability, yaitu setiap tindakan bisa dilacak ke pelakunya, dan menyebut bahwa ini mendukung non-repudiation, deteksi, pemulihan, dan tindakan hukum [S11].

Non-repudiation adalah perlindungan terhadap seseorang yang menyangkal palsu bahwa ia melakukan sebuah tindakan, misalnya mengirim pesan, menyetujui sesuatu, atau mengubah data, disertai kemampuan untuk menentukan apakah orang itu memang melakukannya [S2].

**Analogi:** masuk gedung kantor sebagai tamu. Resepsionis mencocokkan wajahmu dengan KTP (authentication). Kamu diberi kartu tamu yang hanya membuka lantai 5 (authorization). Buku tamu dan sistem kartu mencatat jam masuk, lantai yang dibuka, dan jam keluar (accounting). Non-repudiation mirip tanda tangan di slip penarikan bank: kamu sulit menyangkal sudah menarik uang bila tanda tanganmu ada di slip. Batasnya: KTP bisa dipinjam, tanda tangan basah bisa ditiru, dan buku tamu bisa disobek bila disimpan di meja yang sama dengan penjaganya. Di sistem digital, kekuatan bukti bergantung pada seberapa sulit kredensial dipalsukan dan seberapa terlindungi catatannya.

**Cara kerja:** urutannya selalu sama, dan setiap langkah menjawab pertanyaan berbeda.

```
pelanggan --(username + password + OTP)----> [AUTHENTICATION]  "kamu siapa?"   gagal: login ditolak
          --(minta lihat tagihan no. 123)---> [AUTHORIZATION]   "boleh?"        gagal: akses ditolak
          --(setiap tindakan)---------------> [ACCOUNTING]      dicatat: siapa, apa, kapan, dari IP mana
                                                                    |
                                     catatan yang kuat dan terlindungi menjadi dasar NON-REPUDIATION
```

Authentication memakai satu atau lebih faktor: sesuatu yang kamu tahu (password), sesuatu yang kamu punya (HP yang menerima OTP), atau sesuatu yang melekat padamu (sidik jari). Gabungan beberapa faktor dibahas lebih dalam di Day 06. Authorization hanya berarti setelah authentication berhasil, karena sistem harus tahu dulu siapa yang meminta. Accounting berjalan sepanjang sesi.

**Contoh di PT JAB:** ada dua tempat AAA terlihat jelas.

- Di portal `jkt-portal01`, pelanggan login dengan nomor pelanggan, password, dan OTP bila fitur itu ia aktifkan. Setelah dikenali, portal hanya boleh menampilkan tagihan milik pelanggan itu. Setiap login, perubahan paket, dan pembayaran ditulis ke log, lalu log itu dikirim ke SIEM SOC (Splunk) di server yang dikelola tim lain.
- Untuk layanan internet rumah, PT JAB memakai server RADIUS `jkt-radius01`. RADIUS adalah protokol yang membawa informasi authentication dan authorization antara perangkat jaringan dan server pusat [S19]: modem pelanggan dikenali, diberi hak sesuai paket (misalnya 50 Mbps), lalu durasi sesi dan pemakaiannya dicatat untuk penagihan. Di ISP, accounting dalam arti penagihan adalah pekerjaan sehari-hari [S18].

Untuk pertanyaan Sari soal pelanggan yang menyangkal mengganti paket (pelanggan ini mengaktifkan OTP): log portal mencatat login dari alamat IP pelanggan, OTP yang terkirim ke nomor HP terdaftar dan dimasukkan dengan benar, waktu perubahan paket, dan email konfirmasi yang terkirim. Bukti itu kuat, tetapi belum mutlak, karena masih ada kemungkinan password dan HP pelanggan sama-sama dikuasai orang lain. Non-repudiation yang paling kuat di dunia digital memakai digital signature, yang memungkinkan pihak ketiga memverifikasi bahwa data berasal dari pemegang kunci tertentu [S2]; mekanismenya dibahas di Day 05.

**Beda dengan identification:** identification adalah mengklaim identitas (mengetik username), authentication adalah membuktikan klaim itu (memasukkan password dan OTP yang benar). Username saja tidak membuktikan apa pun.

**Beda authentication dengan authorization:** authentication menjawab "siapa", authorization menjawab "boleh apa". Kegagalan authorization bisa terjadi walaupun authentication sempurna: pelanggan yang login sah lalu mengganti nomor tagihan di alamat halaman dan bisa melihat tagihan orang lain adalah kegagalan authorization.

**Salah paham umum:**
- "Kalau log ada, non-repudiation pasti terpenuhi." Log yang bisa dihapus atau diubah oleh orang yang aksinya dicatat tidak bisa menjadi bukti kuat. Karena itu log portal dikirim ke SIEM yang dikelola tim lain, bukan hanya disimpan di server portal.

### 1.3 Asset, threat, threat actor, vulnerability, exploit

Pertanyaan ketiga Sari ("siapa, lewat celah apa, dengan cara apa") memakai lima istilah yang sering tertukar. Kalau kelimanya dipisahkan dengan rapi, laporan insiden dan penilaian risiko jadi jauh lebih jelas.

**Apa itu:**
- **Asset** adalah apa pun yang bernilai bagi organisasi: data, orang, perangkat, sistem, dan fasilitas yang membuat organisasi bisa menjalankan bisnisnya [S4].
- **Threat** adalah keadaan atau kejadian yang berpotensi merugikan operasi, aset, atau orang melalui akses tanpa izin, perusakan, pembocoran, pengubahan informasi, atau penghentian layanan [S4]. NIST membagi sumber ancaman menjadi empat: serangan yang disengaja, kesalahan manusia, kegagalan perangkat atau sistem milik organisasi sendiri, serta bencana dan kegagalan di luar kendali organisasi [S12].
- **Threat actor** adalah individu atau kelompok yang menjadi sumber ancaman [S4]. Istilah ini dipakai untuk ancaman yang disengaja; disk rusak adalah threat, tetapi bukan threat actor.
- **Vulnerability** adalah kelemahan pada sistem, prosedur keamanan, pengaman, atau cara penerapannya yang bisa dimanfaatkan atau terpicu oleh sumber ancaman [S5]. Kelemahan bisa berupa bug perangkat lunak, konfigurasi yang salah, password lemah, atau proses yang bolong.
- **Exploit** adalah cara, kode, atau alat yang memanfaatkan sebuah vulnerability untuk mencapai sesuatu yang tidak diizinkan, misalnya program kecil yang mengirim permintaan khusus ke aplikasi yang belum di-patch.

**Analogi:** rumahmu dan isinya adalah asset. Kemungkinan rumah kemalingan adalah threat. Malingnya adalah threat actor. Jendela belakang yang tidak terkunci adalah vulnerability. Cara mencongkel jendela itu, atau kunci duplikat yang dibeli maling, adalah exploit. Batasnya: di internet satu pelaku bisa mencoba ribuan "rumah" sekaligus dengan program otomatis, dan cara mencongkel yang ditemukan satu orang bisa disebarkan gratis ke semua orang dalam hitungan jam.

**Cara kerja:** urutan sebuah serangan yang disengaja kira-kira begini.

```
threat actor punya motif (uang, data, iseng, dendam)
   |
memilih asset yang bernilai baginya (data pelanggan portal)
   |
mencari vulnerability (password yang dipakai ulang, aplikasi belum di-patch)
   |
memakai exploit (daftar password bocor dicoba otomatis, kode untuk bug tertentu)
   |
bila berhasil: threat menjadi kejadian nyata, dan sifat C, I, atau A rusak
```

Tanpa vulnerability, exploit tidak punya pintu masuk. Itulah sebabnya pekerjaan menutup celah (patch, konfigurasi yang benar, password kuat) mengurangi banyak ancaman sekaligus. Ancaman yang tidak disengaja, seperti listrik padam atau disk rusak, tidak butuh exploit, tetapi tetap butuh kelemahan agar berdampak, misalnya hanya ada satu server tanpa cadangan.

**Contoh di PT JAB:** tabel berikut memetakan kelima istilah ke portal; baca per baris untuk melihat bagaimana satu ancaman tersusun dari pelaku, celah, dan cara.

| Threat | Threat actor | Vulnerability | Exploit | Asset |
|---|---|---|---|---|
| Pengambilalihan akun pelanggan | Penjahat siber yang mencari data untuk dijual | Pelanggan memakai ulang password dari situs lain; OTP tidak wajib | Daftar password bocor dari situs lain dicoba otomatis ke halaman login | Akun dan data pribadi pelanggan |
| Pencurian isi database pelanggan | Kelompok kriminal terorganisasi | Komponen aplikasi web portal belum di-patch | Kode publik yang memanfaatkan bug komponen itu | Database pelanggan |
| Pengintipan data oleh orang dalam | Karyawan yang penasaran | Akun admin bisa melihat semua data tanpa alasan tercatat | Login biasa dengan hak yang terlalu luas | Data pribadi pelanggan |
| Portal mati | Tidak ada (kegagalan perangkat) | Hanya satu server tanpa cadangan | Tidak ada | Layanan portal |

Insiden `INC-2026-017` adalah contoh nyata pola ini: server lama `jkt-dmz-app01` yang tidak diawasi pengaman di dalam servernya menjadi celah yang dipakai pelaku untuk masuk.

**Beda vulnerability dengan exploit:** vulnerability adalah lubangnya, exploit adalah alat atau cara untuk melewatinya. Lubang yang belum punya exploit publik tetap lubang; lubang yang sudah punya exploit publik menjadi jauh lebih berbahaya karena siapa pun bisa memakainya.

**Beda threat dengan threat actor:** threat adalah kemungkinan kejadiannya (pengambilalihan akun), threat actor adalah pelakunya (kelompok tertentu). Satu threat bisa dilakukan banyak actor, dan satu actor bisa membawa banyak threat.

### 1.4 Risk, likelihood, impact

Pertanyaan keempat Sari ("mana yang paling perlu dikhawatirkan") tidak bisa dijawab dengan daftar ancaman saja. Daftar di bagian 1.3 harus diurutkan, dan alat untuk mengurutkannya adalah risk.

**Apa itu:** risk adalah ukuran seberapa terancam sebuah organisasi oleh suatu keadaan atau kejadian, biasanya berupa gabungan dua hal: dampak merugikan bila kejadian itu terjadi (impact) dan kemungkinan kejadian itu terjadi (likelihood) [S6]. Likelihood adalah penilaian, sering subjektif, tentang seberapa mungkin sebuah ancaman memanfaatkan kelemahan tertentu [S6]. Impact adalah besarnya kerugian: data yang bocor, uang yang hilang, layanan yang berhenti, nama baik yang rusak, atau kewajiban hukum. NIST menyebut faktor risiko yang biasa dinilai adalah threat, vulnerability, impact, likelihood, dan predisposing condition, yaitu kondisi organisasi yang memperbesar atau memperkecil peluang ancaman berhasil [S12].

**Analogi:** dua rumah dengan jendela yang sama-sama tidak terkunci. Rumah pertama di kompleks yang sering didatangi maling dan berisi perhiasan; rumah kedua di desa yang aman dan kosong melompong. Kelemahannya sama, tetapi risikonya jauh berbeda karena likelihood dan impact-nya berbeda. Batasnya: di TI, angka "seberapa sering maling lewat" jarang diketahui pasti, jadi penilaian biasanya memakai kategori dan alasan tertulis.

**Cara kerja:** penilaian risiko sederhana berjalan dalam lima langkah.

1. Tentukan asset dan ancamannya (bagian 1.3).
2. Nilai likelihood: apakah ancaman ini sudah pernah dicoba, apakah exploit-nya mudah didapat, apakah celahnya terlihat dari internet, pengaman apa yang sudah ada.
3. Nilai impact: data apa dan berapa banyak yang terdampak, berapa lama layanan bisa berhenti, apa akibat hukumnya.
4. Gabungkan keduanya dengan tabel yang disepakati organisasi menjadi tingkat risiko.
5. Putuskan respons. NIST menyebut lima pilihan: menerima (acceptance), menghindari dengan menghentikan kegiatan berisiko (avoidance), menurunkan dengan menambah pengaman (mitigation), membagi risiko dengan pihak lain (sharing), atau memindahkannya ke pihak lain seperti asuransi (transfer) [S12].

Penilaian bisa kualitatif (kategori seperti sangat rendah sampai sangat tinggi) atau kuantitatif (angka uang dan probabilitas). Penilaian kualitatif lebih mudah dikomunikasikan ke pengambil keputusan, tetapi dua orang bisa memberi nilai berbeda bila setiap kategori tidak didefinisikan jelas [S12]. NIST SP 800-30 memakai lima tingkat, dari Very Low sampai Very High, dan menggabungkan likelihood dan impact dengan tabel [S12]; organisasi boleh menyederhanakannya. Risiko yang masih tersisa setelah pengaman dipasang disebut residual risk [S12].

**Contoh di PT JAB:** Nina Kartika, Manajer Risiko dan Kepatuhan TI, memakai tabel tiga tingkat; penilaian lengkap untuk tiga risiko portal ada di bagian 2.2. Pengambilalihan akun pelanggan dinilai likelihood tinggi karena alert `SOC-2027-0800` membuktikan sudah dicoba semalam, dan impact sedang karena setiap akun hanya membuka data satu pelanggan. Pencurian seluruh database dinilai likelihood sedang tetapi impact tinggi karena menyangkut data ratusan ribu orang.

**Beda risk dengan threat:** threat adalah "apa yang bisa terjadi", risk adalah "seberapa perlu kita khawatir tentang itu". Threat yang sama bisa menjadi risiko tinggi di satu organisasi dan rendah di organisasi lain.

**Salah paham umum:**
- "Risk tinggi berarti serangan pasti terjadi." Risk tinggi bisa datang dari impact yang sangat besar walaupun likelihood-nya sedang. Itu tanda prioritas, bukan ramalan.

### 1.5 Control: preventive, detective, corrective

Pertanyaan kelima Sari menanyakan pengaman yang sudah ada di portal. Pengaman itu disebut control, dan cara paling berguna untuk memahaminya adalah bertanya kapan ia bekerja: sebelum, saat, atau sesudah kejadian.

**Apa itu:** control (security control) adalah pengaman atau tindakan pencegah yang dipasang pada sistem atau organisasi untuk melindungi confidentiality, integrity, dan availability [S10]. Bentuknya bisa teknis (firewall, enkripsi), administratif (kebijakan, prosedur, pelatihan), atau fisik (pintu, penjaga) [S11]. Berdasarkan fungsinya, control biasa dikelompokkan menjadi tiga [S20]:
- **Preventive control** mencegah kejadian yang tidak diinginkan. Contoh: firewall, batas percobaan login, pembatasan hak akses.
- **Detective control** mengetahui dan mencatat bahwa kejadian sudah atau sedang terjadi. Contoh: log, alert SIEM, EDR yang memberi peringatan.
- **Corrective control** membatasi kerusakan dan mengembalikan keadaan. Contoh: reset password akun yang diambil alih, mengisolasi server, memulihkan dari backup.

Dua jenis tambahan sering muncul. **Deterrent control** membuat calon pelaku berpikir ulang tanpa menghalangi secara fisik, misalnya banner peringatan saat login admin [S20]. **Compensating control** adalah pengaman pengganti yang memberi perlindungan setara ketika pengaman utama tidak bisa dipasang [S10]. Beberapa sumber juga memisahkan recovery (khusus pemulihan) dan directive (kebijakan yang mengarahkan perilaku) [S20].

**Analogi:** pagar dan kunci mencegah (preventive), CCTV dan alarm memberi tahu (detective), asuransi dan tukang servis memulihkan (corrective). Batasnya: satu alat bisa punya lebih dari satu fungsi. CCTV yang terlihat jelas juga membuat maling ragu (deterrent), dan EDR bisa memberi peringatan sekaligus menghentikan program jahat.

**Cara kerja:**

```
   SEBELUM kejadian           SAAT / SESUDAH terjadi         SETELAH diketahui
  +----------------+          +------------------+           +------------------+
  |  PREVENTIVE    |  gagal   |   DETECTIVE      |  memicu   |   CORRECTIVE     |
  |  cegah         | -------> |   ketahui, catat | --------> |   batasi, pulihkan|
  +----------------+          +------------------+           +------------------+
   firewall, OTP,              log, alert SIEM,               reset password,
   batas login, patch          EDR                            isolasi, backup
```

Preventive control tidak pernah sempurna, jadi detective control dibutuhkan untuk menangkap yang lolos. Detective control tanpa corrective hanya menghasilkan laporan, jadi harus ada tindakan yang siap dijalankan setelah alert.

**Contoh di PT JAB:** compensating control punya sejarah di PT JAB. Server lama `jkt-dmz-app01` pada `INC-2026-017` tidak punya EDR. Bila sebuah server memang tidak bisa dipasangi EDR (misalnya sistem operasinya terlalu tua), pengganti yang masuk akal adalah membatasi koneksi ke dan dari server itu seketat mungkin dan mengirim seluruh lognya ke SIEM dengan aturan deteksi khusus. Pemetaan lengkap control di portal ada di bagian 2.3.

**Beda control dengan risk response:** control adalah alatnya, risk response adalah keputusannya. Memasang control adalah salah satu bentuk respons (mitigation); menerima risiko berarti sengaja tidak menambah control.

**Salah paham umum:**
- "Detective control tidak berguna karena tidak menghentikan apa pun." Tanpa detective control, organisasi tidak tahu bahwa preventive control-nya sudah ditembus, dan pelaku bisa tinggal berbulan-bulan.

### 1.6 Defense in depth

Bagian kedua dari pertanyaan kelima Sari adalah bagaimana semua control itu disusun. Satu control sekuat apa pun bisa gagal, jadi pertanyaannya adalah apa yang terjadi setelah ia gagal.

**Apa itu:** defense in depth adalah strategi yang memadukan orang, teknologi, dan operasi untuk membangun hambatan yang berbeda-beda di banyak lapisan organisasi [S8]. Lapisan itu sengaja dibuat dari jenis yang berbeda (heterogen) di sepanjang jalur serangan, supaya serangan yang lolos dari satu control tertangkap oleh control lain [S8]. NIST menyebut defense in depth memakai pengaman administratif (kebijakan, prosedur), teknologi (deteksi, firewall, konfigurasi, antivirus), dan fisik (gerbang, penjaga) bersama-sama [S11].

**Analogi:** pagar, satpam, pintu berkunci, lalu brankas. Maling yang melompati pagar masih harus melewati satpam, lalu pintu, lalu brankas. Batasnya: lapisan harus beda jenis. Lima gembok yang sama di satu pintu bukan berlapis, karena maling yang punya satu kunci duplikat bisa membuka semuanya.

**Cara kerja:** lapisan yang umum dipakai, dari luar ke dalam:

| Lapisan | Contoh control | Yang dihentikan atau dilihat |
|---|---|---|
| Orang dan proses | Kebijakan, pelatihan, prosedur perubahan | Kesalahan dan penipuan yang memanfaatkan manusia |
| Fisik | Pintu data center, kartu akses | Orang yang datang langsung ke perangkat |
| Jaringan | Firewall, pemisahan jaringan | Koneksi ke layanan yang tidak seharusnya terbuka |
| Host (server atau komputer) | Patch, EDR, konfigurasi aman | Program jahat dan kelemahan sistem operasi |
| Aplikasi | WAF, validasi input, pemeriksaan hak di setiap halaman | Permintaan web berbahaya dan penyalahgunaan fitur |
| Identitas | Password kuat, OTP, batas percobaan login | Pemakaian akun oleh orang yang bukan pemiliknya |
| Data | Enkripsi, backup | Pembacaan data curian, kehilangan data |

Tabel di atas dipakai untuk mencari lapisan yang kosong. Defense in depth yang sehat juga punya detective dan corrective control di beberapa lapisan, bukan hanya preventive di lapisan luar.

**Contoh di PT JAB:** pada `INC-2026-017`, pelaku masuk lewat server lama yang tidak punya EDR, jadi lapisan host di server itu kosong. Setelah lapisan luar ditembus, tidak ada yang melihat aktivitas di dalam server. Pelajaran dari insiden itu dipakai di portal: bagian 2.3 memperlihatkan control portal per lapisan.

**Beda dengan redundansi:** redundansi berarti menggandakan hal yang sama supaya tetap berjalan bila satu rusak (dua server portal), dan itu menjaga availability. Defense in depth berarti menyusun hal yang berbeda supaya kegagalan satu jenis pengaman ditutup jenis lain.

### 1.7 Least privilege dan separation of duties

Pertanyaan keenam Sari ("kenapa akunmu tidak bisa masuk ke server portal") dijawab dua prinsip yang membatasi hak akses: seberapa banyak hak satu orang, dan apakah satu orang boleh memegang seluruh proses penting sendirian.

**Apa itu:** least privilege adalah prinsip bahwa hak akses pengguna, atau program yang bekerja atas nama pengguna, dibatasi sampai batas minimum yang dibutuhkan untuk menyelesaikan tugasnya [S7]. Separation of duties (SoD) adalah prinsip bahwa tidak ada satu pengguna pun yang punya hak cukup untuk menyalahgunakan sistem sendirian; contoh klasiknya, orang yang menyetujui pembayaran gaji tidak boleh orang yang sama dengan yang menyiapkannya [S7]. SoD bisa diterapkan secara statis (dua peran yang bertentangan tidak boleh dipegang satu orang) atau dinamis, misalnya aturan dua orang yang mewajibkan orang kedua berbeda dari yang pertama [S7]. NIST menyebut SoD menurunkan risiko penyalahgunaan hak oleh satu orang yang bertindak tanpa persekongkolan [S11].

**Analogi:** kartu akses karyawan hanya membuka lantai tempat ia bekerja (least privilege). Batasnya: hak harus ditinjau ulang, bukan hanya diberikan sekali; karyawan yang pindah divisi tiga kali dan tetap memegang semua kartu lamanya sudah melanggar prinsip ini. Untuk separation of duties: di bank, pencairan uang diajukan satu pegawai lalu disetujui pegawai lain. Batasnya: bila dua pegawai itu bersekongkol, pemisahan tugas tidak lagi melindungi, jadi tetap butuh catatan audit dan pengawasan.

**Cara kerja:**

- Least privilege: mulai dari nol hak, tambahkan hanya yang dibutuhkan tugas, beri batas waktu untuk hak istimewa yang jarang dipakai, cabut saat tugas berubah, dan tinjau berkala. Tanpa tinjauan, hak menumpuk dari tahun ke tahun; fenomena ini disebut privilege creep.
- Separation of duties: daftar proses yang berbahaya bila dipegang satu orang (mengubah kode lalu memasangnya ke server produksi, membuat pembayaran lalu menyetujuinya, mengelola server lalu menghapus log audit server itu), lalu pecah setiap proses ke dua peran yang dipegang orang berbeda.

**Contoh di PT JAB:** akunmu sebagai analyst L1 bisa membaca log portal di Splunk, karena itu yang dibutuhkan untuk memeriksa alert. Akunmu tidak bisa login ke server `jkt-portal01`, karena memeriksa alert tidak membutuhkan hak mengubah server. Bila akunmu dicuri, kerugian maksimalnya adalah pembacaan log, bukan pengambilalihan server. Contoh separation of duties: admin portal mengelola server, tetapi log audit server dikirim ke Splunk yang dikelola SOC, jadi admin tidak bisa menghapus jejaknya sendiri. Dua permintaan akses yang ditolak karena kedua prinsip ini ada di bagian 2.4.

**Beda least privilege dengan separation of duties:** least privilege mengatur besarnya hak satu orang ("hanya yang dibutuhkan"). Separation of duties mengatur pembagian satu proses ke beberapa orang ("tidak ada yang memegang semua tahap"). Seseorang bisa punya hak yang sangat minimal tetapi tetap melanggar SoD bila hak minimal itu mencakup dua tahap yang bertentangan.

**Salah paham umum:**
- "Least privilege berarti perusahaan tidak percaya karyawannya." Prinsip ini membatasi kerugian bila akun dicuri atau salah pakai, dan justru melindungi pemegang akun dari tuduhan ketika terjadi insiden.

### 1.8 Zero trust

Pertanyaan ketujuh Sari menyangkut perubahan cara PT JAB memberi akses ke panel admin portal. Dulu, siapa pun yang berada di jaringan kantor dianggap aman. `INC-2026-017` membuktikan anggapan itu keliru: begitu pelaku berada di dalam, ia bisa bergerak sampai ke folder bersama (share) milik divisi Keuangan.

**Apa itu:** zero trust adalah sekumpulan prinsip yang memindahkan pertahanan dari batas jaringan yang statis ke pengguna, perangkat, dan sumber daya [S13]. Intinya, tidak ada kepercayaan otomatis yang diberikan kepada perangkat atau akun hanya karena lokasinya di jaringan atau karena perangkat itu milik perusahaan [S13]. Authentication dan authorization dilakukan sebelum setiap sesi ke sumber daya dibuka [S13]. Zero trust architecture (ZTA) adalah rencana keamanan organisasi yang menerapkan prinsip itu ke infrastruktur dan alur kerjanya [S13].

Prinsip dasar zero trust menurut NIST SP 800-207, diringkas [S13]:

1. Semua data dan layanan komputasi diperlakukan sebagai sumber daya yang dilindungi.
2. Semua komunikasi diamankan, di mana pun lokasinya; berada di jaringan perusahaan tidak berarti dipercaya.
3. Akses diberikan per sesi, dengan hak sekecil yang dibutuhkan; akses ke satu sumber daya tidak otomatis membuka sumber daya lain.
4. Akses ditentukan kebijakan dinamis: identitas, kondisi perangkat, jenis layanan, dan atribut lain seperti waktu dan perilaku.
5. Kesehatan dan keamanan semua perangkat dipantau terus; tidak ada perangkat yang dipercaya begitu saja.
6. Authentication dan authorization dinamis dan ditegakkan ketat sebelum akses, dan bisa diulang selama sesi.
7. Organisasi mengumpulkan sebanyak mungkin informasi tentang kondisi aset, jaringan, dan permintaan akses untuk memperbaiki kebijakannya.

**Analogi:** gedung yang memeriksa kartu di setiap pintu, bukan hanya di lobi. Tamu yang sudah lolos lobi tetap harus menempelkan kartu di pintu lantai, pintu ruangan, dan lemari arsip, dan kartunya bisa ditolak bila jam kerjanya sudah lewat. Batasnya: zero trust bukan satu produk yang bisa dibeli. Ia adalah arsitektur dan prinsip yang diterapkan bertahap, dan setiap "pintu" butuh sistem yang memutuskan dan menegakkan aturannya.

**Cara kerja:** NIST memisahkan dua peran. Policy decision point (PDP), yang terdiri dari policy engine dan policy administrator, memutuskan apakah akses diberikan. Policy enforcement point (PEP) membuka, memantau, dan memutus koneksi sesuai keputusan itu [S13].

```
admin (laptop) --minta akses--> [PEP: penjaga pintu] --tanya--> [PDP: penentu kebijakan]
                                        ^                          cek: siapa? OTP benar?
                                        |                          laptop terdaftar? EDR aktif?
                                        +------ izinkan / tolak ---  jam dan lokasi wajar?
                                        |
                         bila diizinkan: hanya ke panel admin jkt-portal01, untuk sesi ini saja
```

CISA menyusun Zero Trust Maturity Model versi 2.0 dengan lima pilar (Identity, Devices, Networks, Applications and Workloads, Data) dan empat tahap kematangan (Traditional, Initial, Advanced, Optimal) [S16]. Setiap pilar boleh maju dengan kecepatan berbeda, dan CISA menekankan bahwa perjalanannya bertahap dan bisa memakan waktu bertahun-tahun [S16].

**Contoh di PT JAB:** dulu panel admin portal bisa dibuka dari semua komputer di jaringan kantor Jakarta (`10.10.0.0/16`). Sejak 2027, admin harus login dengan password dan OTP setiap sesi, dari laptop kantor yang terdaftar dan EDR-nya aktif, dan akses ke panel admin tidak otomatis membuka akses ke database pelanggan. Bila salah satu syarat tidak terpenuhi, akses ditolak walaupun admin duduk di kantor.

**Beda dengan pertahanan perimeter:** pertahanan perimeter memusatkan pemeriksaan di batas luar dan mempercayai semua yang sudah di dalam, seperti kastel dengan parit. Zero trust tetap memakai pemeriksaan di batas luar, tetapi tidak berhenti di sana.

**Salah paham umum:**
- "Zero trust berarti semua firewall dibuang." NIST justru mencatat bahwa kebanyakan definisi zero trust tetap memakai batas dalam bentuk lain, misalnya pemisahan jaringan yang lebih kecil [S13].
- "Zero trust berlaku sama untuk pelanggan." Prinsip zero trust ditujukan untuk pekerjaan di dalam organisasi dan mitranya, bukan untuk layanan publik yang dipakai orang anonim; organisasi tidak bisa memaksakan kebijakan internal kepada pelanggan, walaupun sebagian prinsipnya bisa diterapkan kepada pelanggan terdaftar [S13].

### 1.9 Attack surface

Pertanyaan terakhir Sari ("dari mana saja portal bisa diserang") adalah pertanyaan tentang attack surface. Semakin banyak pintu masuk, semakin banyak yang harus dijaga.

**Apa itu:** attack surface adalah kumpulan titik di batas sebuah sistem, komponen, atau lingkungan tempat penyerang bisa mencoba masuk, menimbulkan dampak, atau mengambil data [S9]. Dalam praktik, titik itu mencakup layanan jaringan yang terbuka, halaman dan fitur aplikasi, akun yang bisa login, komponen pihak ketiga, perangkat fisik, dan orang yang bisa ditipu.

**Analogi:** jumlah pintu, jendela, dan lubang ventilasi rumah. Rumah dengan sepuluh jendela lebih sulit dijaga daripada rumah dengan dua jendela. Batasnya: attack surface digital berubah setiap hari (fitur baru, server baru, karyawan baru), dan sebagian "pintu" tidak terlihat oleh pemilik rumah, misalnya komponen pihak ketiga yang ikut terpasang di aplikasi.

**Cara kerja:** pengelolaan attack surface berjalan dalam tiga langkah.

1. Inventaris: daftar semua titik yang bisa dicapai penyerang, dari luar dan dari dalam.
2. Kurangi: matikan atau sembunyikan yang tidak dipakai. Titik yang tidak ada tidak perlu dijaga.
3. Lindungi dan pantau sisanya dengan control dari bagian 1.5 dan 1.6.

**Contoh di PT JAB:** attack surface portal `jkt-portal01` antara lain halaman login, fitur lupa password, form unggah foto KTP untuk pendaftaran, layanan yang dipakai aplikasi mobile PT JAB, panel admin, akses login jarak jauh admin ke server, komponen pihak ketiga di aplikasi web, dan akun-akun admin itu sendiri. Langkah pengurangan yang sudah dilakukan: panel admin tidak lagi bisa dibuka dari internet, dan login jarak jauh ke server hanya diizinkan dari laptop admin yang terdaftar.

**Beda attack surface dengan vulnerability:** attack surface adalah semua tempat yang bisa dicoba; vulnerability adalah celah nyata di salah satu tempat itu. Form unggah KTP adalah bagian dari attack surface walaupun aman; ia menjadi vulnerability bila ternyata bisa dipakai mengunggah file program.

## 2. Contoh nyata

Semua contoh di bagian ini adalah keluaran ilustrasi dari organisasi fiktif PT JAB, bukan hasil eksekusi nyata. Nama host, alamat IP, nomor, dan angka dibuat untuk latihan.

### 2.1 Membedah alert `SOC-2027-0800` dengan istilah Day ini

Siang hari pertama, Sari membuka alert yang ia sebut di pesannya. Ringkasannya di Splunk terlihat seperti ini:

```
Alert     : SOC-2027-0800
Waktu     : 2027-08-01 23:04 sampai 23:14 WIB
Judul     : Banyak login gagal ke portal pelanggan dari satu alamat IP
Host      : jkt-portal01 (portal.jab.example, 203.0.113.8)
Sumber    : 192.0.2.77
Ringkasan : 415 percobaan login ke 383 akun berbeda dalam 10 menit
            412 gagal; 3 akun berhasil login (23:09, 23:11, 23:13)
Severity  : High
```

Cara membacanya: 415 percobaan tersebar ke 383 akun, jadi 351 akun dicoba sekali dan 32 akun dicoba dua kali (351 + 64 = 415). Pelaku sengaja mencoba sedikit per akun. Akibatnya batas percobaan login portal (akun dikunci 15 menit setelah 5 kali gagal) tidak pernah terpicu. Tiga akun berhasil dibuka; ketiganya memakai password yang sama dengan yang bocor dari situs lain dan tidak mengaktifkan OTP. Tabel berikut memetakan alert itu ke istilah Day ini; pakai kolom kanan sebagai pola saat menulis ringkasan alert sendiri.

| Istilah | Di alert ini |
|---|---|
| Asset | Akun dan data pribadi pelanggan di `jkt-portal01` |
| Threat | Pengambilalihan akun pelanggan |
| Threat actor | Belum diketahui; polanya cocok dengan penjahat siber yang memakai daftar password bocor |
| Vulnerability | Password dipakai ulang oleh pelanggan, OTP tidak wajib, batas login hanya dihitung per akun |
| Exploit | Daftar pasangan email dan password bocor yang dicoba otomatis |
| Sifat CIA yang rusak | Confidentiality: data tiga pelanggan mungkin sudah dilihat pelaku |
| Preventive control yang bekerja | Password menolak 412 percobaan |
| Preventive control yang tidak cukup | Batas percobaan per akun, karena pelaku menyebar percobaan ke banyak akun |
| Detective control yang bekerja | Rule SIEM yang menghitung login gagal per alamat IP, bukan per akun |
| Corrective control yang dijalankan | Sesi tiga akun diputus, password direset, pemilik akun dihubungi |
| Accounting | Log portal mencatat waktu, akun, dan alamat setiap percobaan, sehingga angka di atas bisa dihitung |

Karena data tiga pelanggan mungkin sudah dilihat pihak yang tidak berhak, Sari membuka insiden `INC-2027-080` dan menyerahkan penilaian kewajiban pemberitahuan kepada Agus Setiawan (DPO, petugas pelindungan data pribadi). Alert ini menunjukkan defense in depth bekerja sebagian: satu control lemah (batas per akun) ditutup control dari jenis lain (deteksi per alamat IP), tetapi tidak sebelum tiga akun terbuka.

### 2.2 Menilai tiga risiko portal dengan tabel likelihood dan impact

Pertanyaan keempat Sari dijawab dengan penilaian sederhana milik Nina Kartika. Tabel pertama adalah aturan penggabungan yang disepakati PT JAB; baca baris likelihood lalu kolom impact untuk mendapat tingkat risiko.

| Likelihood \ Impact | Rendah | Sedang | Tinggi |
|---|---|---|---|
| Tinggi | Sedang | Tinggi | Tinggi |
| Sedang | Rendah | Sedang | Tinggi |
| Rendah | Rendah | Rendah | Sedang |

Tabel kedua adalah hasil penilaian tiga risiko portal; perhatikan kolom Respons, karena tingkat risiko yang sama bisa mendapat respons berbeda.

| ID | Risiko | Likelihood | Impact | Tingkat | Respons |
|---|---|---|---|---|---|
| R1 | Akun pelanggan diambil alih lewat password bocor | Tinggi (sudah dicoba, `SOC-2027-0800`) | Sedang (data satu pelanggan per akun) | Tinggi | Mitigation: OTP wajib untuk perubahan paket dan data pribadi; rule deteksi per alamat IP dipertahankan |
| R2 | Database pelanggan dicuri lewat komponen web yang belum di-patch | Sedang (kelemahan diumumkan, exploit publik belum terlihat) | Tinggi (data ratusan ribu pelanggan) | Tinggi | Mitigation: patch dalam 14 hari; sementara itu WAF diberi aturan yang menolak pola permintaan untuk kelemahan itu |
| R3 | Portal mati karena satu-satunya server rusak | Rendah (perangkat baru, ada garansi) | Sedang (pelanggan tidak bisa membayar lewat portal, kanal lain tetap ada) | Rendah | Acceptance: diterima sementara dengan persetujuan tertulis, server kedua masuk anggaran tahun depan |

Cara membacanya: R1 dan R2 sama-sama tinggi, tetapi alasannya berbeda. R1 tinggi karena sering dicoba, R2 tinggi karena kerugiannya sangat besar. R3 sengaja diterima: menerima risiko adalah keputusan sah selama tercatat dan disetujui orang yang berwenang. Bila PT JAB membeli asuransi siber untuk menanggung biaya insiden data, itu contoh transfer. Setelah OTP diwajibkan, R1 tidak hilang; yang tersisa (misalnya pelaku yang juga menguasai HP pelanggan) adalah residual risk.

### 2.3 Memetakan control portal ke fungsi dan lapisan

Pertanyaan kelima Sari ("pengaman apa yang terpasang dan apa fungsinya") dijawab dengan satu tabel. Cari kolom Fungsi untuk melihat keseimbangan preventive, detective, dan corrective, dan kolom Lapisan untuk mencari lapisan yang kosong.

| Control | Fungsi | Lapisan | Sifat yang paling dijaga |
|---|---|---|---|
| Firewall depan data center hanya mengizinkan koneksi web terenkripsi (HTTPS) ke `203.0.113.8` | Preventive | Jaringan | C, I |
| WAF di depan portal menolak permintaan web berbahaya dan mencatatnya | Preventive dan detective | Aplikasi | C, I |
| Pemeriksaan hak di setiap halaman (pelanggan hanya melihat tagihannya sendiri) | Preventive | Aplikasi | C |
| Password, OTP, batas 5 kali gagal per akun | Preventive | Identitas | C, I |
| Patch bulanan sistem operasi dan komponen web | Preventive | Host | C, I, A |
| EDR di `jkt-portal01` | Detective, kadang corrective (bisa menghentikan program) | Host | C, I, A |
| Log portal, WAF, dan firewall dikirim ke Splunk; rule login gagal per alamat IP | Detective | Lintas lapisan | C, I |
| Enkripsi kolom NIK di database | Preventive | Data | C |
| Backup database harian, uji pemulihan tiap bulan | Corrective | Data | I, A |
| Banner peringatan di halaman login admin | Deterrent | Identitas | C, I |
| Prosedur perubahan dan pelatihan admin | Preventive (administratif) | Orang dan proses | I, A |

Diagram berikut menyusun control yang sama sebagai lapisan dari arah internet.

```
internet
   |
[firewall]            jaringan    hanya HTTPS ke 203.0.113.8
   |
[WAF]                 aplikasi    saring dan catat permintaan web berbahaya
   |
[jkt-portal01]        host        patch bulanan, EDR
   |   login + OTP + batas percobaan, cek hak per halaman      identitas, aplikasi
   |
[database pelanggan]  data        enkripsi NIK, backup harian

di semua lapisan: log ke Splunk (detective)   |   di luar teknologi: prosedur dan pelatihan
```

Cara membacanya: control preventive cukup banyak, detective ada di beberapa lapisan, dan corrective terkuat ada di lapisan data (backup). Celah yang terlihat dari tabel ini adalah R3 di bagian 2.2: tidak ada server cadangan, jadi availability bergantung pada satu perangkat.

### 2.4 Dua permintaan akses yang ditolak

Pertanyaan keenam Sari punya dua contoh nyata pada minggu pertamamu. Tabel berikut merangkum keduanya; baca kolom Alasan untuk melihat prinsip mana yang dipakai.

| Permintaan | Keputusan | Alasan | Pengganti yang diberikan |
|---|---|---|---|
| Kamu meminta akses login jarak jauh ke server `jkt-portal01` "supaya bisa melihat log langsung saat memeriksa alert" | Ditolak oleh Sari | Least privilege: memeriksa alert hanya butuh membaca log, bukan mengubah server | Akses baca ke log portal di Splunk |
| Seorang developer portal meminta hak memasang kode ke server produksi tanpa review, dan hak menghapus log audit portal "untuk membersihkan log yang terlalu besar" | Ditolak oleh Agung Prabowo (Lead Infrastruktur) | Separation of duties: yang menulis kode tidak boleh sekaligus menyetujui dan memasangnya, dan pemilik aktivitas tidak boleh bisa menghapus catatan aktivitasnya sendiri | Pemasangan lewat review rekan dan persetujuan tim Infrastruktur; masa simpan log diatur tim SOC |

Penolakan kedua juga menjaga accounting dan non-repudiation (bagian 1.2): bila developer bisa menghapus log audit, catatan tentang siapa memasang kode apa tidak lagi bisa dipercaya.

## 3. Perbandingan istilah yang sering tertukar

### 3.1 Threat, threat actor, vulnerability, exploit, risk

Lima istilah ini sering dipakai bergantian di percakapan. Tabel berikut membedakannya dengan satu pertanyaan kunci per istilah; cari kolom Pertanyaan kunci saat ragu istilah mana yang tepat.

| Istilah | Pertanyaan kunci | Contoh portal | Analogi rumah |
|---|---|---|---|
| Threat | Apa yang bisa terjadi? | Akun pelanggan diambil alih | Rumah kemalingan |
| Threat actor | Siapa pelakunya? | Penjahat siber dengan daftar password bocor | Maling |
| Vulnerability | Lewat kelemahan apa? | Password dipakai ulang, OTP tidak wajib | Jendela tidak terkunci |
| Exploit | Dengan cara atau alat apa? | Percobaan login otomatis | Cara mencongkel jendela |
| Risk | Seberapa perlu dikhawatirkan? | Tinggi: sering dicoba, kerugian per akun sedang | Peluang dan kerugian kemalingan |

### 3.2 Authentication, authorization, accounting, non-repudiation

Empat istilah ini berjalan di setiap sesi login. Tabel berikut memperlihatkan pertanyaan, contoh kegagalan, dan contoh di portal; cari kolom Contoh kegagalan untuk menentukan istilah mana yang dilanggar sebuah temuan.

| Istilah | Pertanyaan | Contoh kegagalan | Di portal |
|---|---|---|---|
| Authentication | Kamu siapa? | Orang lain login dengan password curian | Password dan OTP |
| Authorization | Boleh apa? | Pelanggan sah bisa melihat tagihan orang lain | Cek hak di setiap halaman |
| Accounting | Apa yang sudah dilakukan, kapan, dari mana? | Tidak ada log, atau log tidak mencatat alamat asal | Log login dan transaksi ke Splunk |
| Non-repudiation | Bisakah pelaku menyangkal? | Log bisa dihapus oleh orang yang dicatat | Log di sistem terpisah, konfirmasi OTP dan email |

### 3.3 Preventive, detective, corrective (dan dua tambahan)

Jenis control dibedakan dari kapan dan bagaimana ia bekerja. Tabel berikut membantu mengelompokkan control yang kamu temui; ingat bahwa satu alat bisa masuk lebih dari satu baris.

| Jenis | Kapan bekerja | Tujuan | Contoh |
|---|---|---|---|
| Preventive | Sebelum kejadian | Mencegah | Firewall, OTP, batas login, patch |
| Detective | Saat atau sesudah kejadian | Mengetahui dan mencatat | Log, alert SIEM, EDR |
| Corrective | Setelah kejadian diketahui | Membatasi kerusakan, memulihkan | Reset password, isolasi server, restore backup |
| Deterrent | Sebelum kejadian | Membuat pelaku ragu | Banner peringatan, CCTV yang terlihat |
| Compensating | Saat control utama tidak bisa dipasang | Memberi perlindungan setara | Pembatasan jaringan ketat untuk server yang tidak bisa dipasangi EDR |

### 3.4 Defense in depth, least privilege, separation of duties, zero trust

Empat prinsip desain ini saling melengkapi, tetapi menjawab pertanyaan berbeda. Tabel berikut menunjukkan pertanyaan yang dijawab masing-masing; cari kolom Bukan berarti untuk menghindari salah paham yang paling sering.

| Prinsip | Pertanyaan yang dijawab | Bukan berarti |
|---|---|---|
| Defense in depth | Apa yang terjadi bila satu pengaman gagal? | Menumpuk banyak pengaman yang sama jenisnya |
| Least privilege | Seberapa besar hak satu akun? | Tidak percaya pada karyawan |
| Separation of duties | Bolehkah satu orang memegang seluruh proses penting? | Menggandakan pekerjaan tanpa alasan |
| Zero trust | Apakah lokasi di jaringan cukup untuk dipercaya? | Membuang firewall, atau membeli satu produk |

## 4. Salah paham umum

- **Anggapan:** keamanan adalah urusan teknologi saja. **Kenyataannya:** definisi defense in depth sejak awal memadukan orang, teknologi, dan operasi [S8], dan control administratif seperti kebijakan, prosedur, dan pelatihan berdiri sejajar dengan control teknis [S11]. Penolakan permintaan developer di bagian 2.4 adalah control proses, bukan alat.
- **Anggapan:** risiko bisa diturunkan sampai nol. **Kenyataannya:** selalu ada residual risk setelah control dipasang [S12]. Tujuannya menurunkan risiko ke tingkat yang bisa diterima organisasi, lalu mencatat sisanya.
- **Anggapan:** semakin banyak control, semakin aman. **Kenyataannya:** control yang tidak dipilih berdasarkan risiko memboroskan anggaran dan sering mengganggu availability atau kenyamanan pengguna, sehingga dicari jalan pintasnya. Control yang tidak dipantau juga bisa mati tanpa ketahuan.
- **Anggapan:** alert berarti serangan sudah berhasil. **Kenyataannya:** detective control juga melaporkan percobaan yang gagal. Pada `SOC-2027-0800`, 412 dari 415 percobaan gagal; yang menentukan apakah ada insiden adalah apakah sifat C, I, atau A benar-benar rusak, dan di alert itu jawabannya ya untuk tiga akun.
- **Anggapan:** data yang bocor bisa "dikembalikan" dengan backup. **Kenyataannya:** backup memulihkan integrity dan availability, bukan confidentiality. Data yang sudah disalin pelaku tidak bisa ditarik kembali, jadi untuk kerahasiaan, control preventive dan detective jauh lebih penting daripada corrective.
- **Anggapan:** pengaman yang sudah dipasang akan terus bekerja. **Kenyataannya:** hak akses menumpuk, aturan firewall menua, dan server baru menambah attack surface. Least privilege, attack surface, dan penilaian risiko harus ditinjau berkala, bukan sekali saat sistem dibangun.

## 5. Catatan terkini

Bagian ini mencatat versi dokumen acuan, tanggal terbit, dan perubahan yang perlu diketahui saat membaca sumber lain.

- Definisi confidentiality, integrity, dan availability di NIST berasal dari undang-undang federal AS. Glosarium NIST mencantumkan rujukan pasal lama (44 U.S.C. 3542) dan baru (44 U.S.C. 3552) untuk definisi yang isinya sama [S1].
- Glosarium NIST memuat beberapa definisi untuk satu istilah, dari publikasi yang berbeda. Untuk threat, misalnya, ada versi FIPS 200, SP 800-30, dan versi lain yang lebih singkat [S4]. Pilih definisi sesuai konteks dokumen yang sedang kamu tulis.
- NIST Cybersecurity Framework (CSF) 2.0 terbit 26 Februari 2024 dan menambah fungsi Govern di samping Identify, Protect, Detect, Respond, dan Recover, sehingga sekarang ada enam fungsi. Versi 2.0 juga ditujukan untuk organisasi di semua sektor, bukan hanya infrastruktur kritis [S17].
- NIST SP 800-207 (Zero Trust Architecture) terbit final Agustus 2020. Per 2026-10-20, halaman publikasinya tidak mencantumkan draf revisi; dokumen pendampingnya adalah SP 800-207A (September 2023), khusus untuk aplikasi yang berjalan di beberapa layanan cloud sekaligus [S13][S14]. NIST juga menerbitkan panduan praktik SP 1800-35 "Implementing a Zero Trust Architecture" pada 10 Juni 2025, hasil kerja dengan 24 vendor yang menghasilkan 19 contoh implementasi [S15].
- CISA Zero Trust Maturity Model versi 2.0 bertanggal April 2023, dengan lima pilar, tiga kemampuan lintas pilar (Visibility and Analytics, Automation and Orchestration, Governance), dan empat tahap; tahap Initial adalah tambahan di versi 2.0 [S16]. Halaman web CISA untuk model ini sekarang ditandai sebagai konten arsip, jadi cek apakah ada versi pengganti sebelum mengutipnya di dokumen formal.
- NIST SP 800-30 Rev. 1 (Guide for Conducting Risk Assessments) terbit September 2012 dan masih berstatus final tanpa revisi baru di halaman publikasinya [S12]. NIST SP 800-12 Rev. 1 (An Introduction to Information Security) terbit Juni 2017 [S11].
- Pembagian jenis control tidak seragam antar sumber. Materi pelatihan umumnya memakai tujuh jenis (directive, deterrent, preventive, detective, corrective, recovery, compensating) [S20], sedangkan di NIST istilah compensating control punya arti khusus: pengganti control dari baseline SP 800-53 yang memberi perlindungan setara [S10].

## 6. Cheat sheet

```
CIA triad            : tiga sifat yang dijaga: confidentiality, integrity, availability
Confidentiality      : hanya yang berhak bisa melihat
Integrity            : tidak berubah tanpa izin, asal-usul asli
Availability         : bisa dipakai saat dibutuhkan
Authentication       : membuktikan "kamu siapa" (password, OTP, sidik jari)
Authorization        : menentukan "boleh apa" setelah dikenali
Accounting           : mencatat siapa, apa, kapan, dari mana, berapa banyak
Non-repudiation      : bukti yang membuat pelaku tidak bisa menyangkal
Asset                : apa pun yang bernilai (data, sistem, orang, fasilitas)
Threat               : kejadian yang berpotensi merugikan (sengaja atau tidak)
Threat actor         : orang/kelompok di balik ancaman yang disengaja
Vulnerability        : kelemahan yang bisa dimanfaatkan atau terpicu
Exploit              : cara/kode/alat untuk memanfaatkan kelemahan
Risk                 : likelihood digabung impact; dasar memilih prioritas
Likelihood           : seberapa mungkin terjadi
Impact               : seberapa parah kerugiannya
Risk response        : accept, avoid, mitigate, share/transfer
Residual risk        : risiko yang tersisa setelah control dipasang
Control              : pengaman teknis, administratif, atau fisik
Preventive           : mencegah (firewall, OTP, patch)
Detective            : mengetahui dan mencatat (log, alert SIEM, EDR)
Corrective           : membatasi kerusakan dan memulihkan (reset, isolasi, backup)
Deterrent            : membuat pelaku ragu (banner, CCTV terlihat)
Compensating         : pengganti setara saat control utama tidak bisa dipasang
Defense in depth     : lapisan control berbeda jenis; satu gagal, lain menangkap
Least privilege      : hak sekecil yang dibutuhkan, ditinjau berkala
Separation of duties : satu proses penting dipecah ke beberapa orang
Zero trust           : tidak ada kepercayaan otomatis dari lokasi; cek setiap sesi
Attack surface       : semua titik yang bisa dicoba penyerang; kurangi, lindungi, pantau
```

## 7. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Portal pelanggan sudah memakai HTTPS dan password, jadi ketiga sifat CIA-nya sudah terjaga." Benarkah?

<details><summary>Jawaban</summary>

Tidak. HTTPS dan password terutama menjaga confidentiality dan sebagian integrity: data di perjalanan tidak bisa dibaca, dan hanya pemilik password yang bisa login. Availability butuh control lain seperti backup dan server cadangan, dan PT JAB justru menerima risiko portal mati karena hanya punya satu server. Integrity juga butuh pemeriksaan hak di setiap halaman dan catatan perubahan. Lihat bagian 1.1, 2.2, dan 2.3.

</details>

**2. Skenario keputusan.** Seorang pelanggan login dengan password dan OTP yang benar, lalu mengganti angka nomor tagihan di alamat halaman dan bisa melihat tagihan pelanggan lain. Di mana kegagalannya?

- A. Authentication, karena orang yang salah berhasil masuk.
- B. Authorization, karena pelanggan yang sudah dikenali diberi akses ke data yang bukan haknya.
- C. Accounting, karena portal tidak mencatat perpindahan halaman itu.

<details><summary>Jawaban</summary>

B. Pelanggan itu memang pemilik akunnya, jadi authentication berhasil dengan benar. Masalahnya ada di keputusan "boleh apa": portal tidak memeriksa apakah tagihan yang diminta milik pelanggan yang login. A keliru karena identitas pelanggan sudah terbukti. C keliru karena masalahnya bukan pencatatan; seandainya log lengkap pun, data orang lain tetap sudah terlihat. Lihat bagian 1.2.

</details>

**3. Pertanyaan jebakan.** "Komponen web portal punya kelemahan kritis, tetapi belum ada exploit publik. Jadi risikonya nol dan patch bisa menunggu tahun depan." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Kelemahan tanpa exploit publik tetap kelemahan; exploit bisa muncul kapan saja dan disebarkan ke banyak orang dalam waktu singkat. Ketiadaan exploit hanya menurunkan likelihood, bukan menghapusnya, sedangkan impact-nya tetap tinggi karena menyangkut data ratusan ribu pelanggan. Itulah kenapa R2 di PT JAB tetap dinilai tinggi dan mendapat patch dalam 14 hari plus aturan WAF sementara. Lihat bagian 1.3 dan 2.2.

</details>

**4. Skenario keputusan.** Untuk "menerapkan defense in depth", seorang engineer mengusulkan firewall kedua dengan aturan yang persis sama, dipasang tepat di belakang firewall pertama di depan portal. Apa tanggapan yang paling tepat?

- A. Setuju, karena dua lapisan selalu lebih aman daripada satu.
- B. Lebih baik menambah lapisan dari jenis lain, misalnya memperkuat pemantauan log atau pemeriksaan di lapisan aplikasi dan identitas, karena firewall kedua yang identik akan gagal dengan cara yang sama.
- C. Hapus firewall pertama, karena PT JAB sudah menerapkan zero trust.

<details><summary>Jawaban</summary>

B. Defense in depth menuntut lapisan yang berbeda jenis, supaya serangan yang lolos dari satu control tertangkap control lain. Firewall identik dengan aturan yang sama meloloskan permintaan yang sama, seperti lima gembok yang dibuka satu kunci duplikat. A keliru karena jumlah lapisan tidak berarti bila jenisnya sama. C keliru karena zero trust tidak membuang pemeriksaan di batas jaringan; ia menambah pemeriksaan di setiap akses. Lihat bagian 1.6 dan 1.8.

</details>

**5. Jelaskan ulang.** Jelaskan kepada anggota keluargamu yang bukan orang IT, dalam tiga kalimat, kenapa di hari pertama kerja akunmu tidak bisa masuk ke server portal padahal kamu bekerja di tim keamanan.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Di kantorku, setiap orang hanya diberi akses yang benar-benar dibutuhkan untuk pekerjaannya, seperti kartu karyawan yang hanya membuka lantai tempat kita bekerja. Pekerjaanku membaca catatan kejadian, jadi aku diberi akses baca catatan itu, bukan kunci untuk mengubah server. Kalau suatu hari akunku dicuri orang, kerugiannya jadi kecil karena akun itu memang tidak bisa mengubah apa-apa."

Kesalahan yang sering muncul:
- Menjelaskan seolah-olah perusahaan tidak percaya karyawan barunya, padahal tujuannya membatasi kerugian bila akun dicuri atau salah pakai.
- Memakai istilah teknis tanpa penjelasan (least privilege, SIEM, server produksi) kepada orang yang bukan orang IT.
- Lupa menyebut bahwa hak itu bisa bertambah bila tugas berubah dan ditinjau berkala.

</details>

**6. Pertanyaan jebakan.** "Karena PT JAB menerapkan zero trust, pelanggan portal juga harus login dari perangkat yang terdaftar dan diperiksa kondisinya, sama seperti admin." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Prinsip zero trust di NIST SP 800-207 ditujukan untuk pekerjaan di dalam organisasi dan mitranya, bukan untuk layanan publik yang dipakai orang anonim, karena organisasi tidak bisa memaksakan kebijakan internal kepada pelanggan. Sebagian gagasannya tetap bisa dipakai untuk pelanggan terdaftar, misalnya meminta OTP untuk perubahan paket. Pemeriksaan laptop terdaftar dan EDR aktif hanya masuk akal untuk admin yang memakai perangkat kantor. Lihat bagian 1.8.

</details>

**7. Interview question (English).** "Explain the CIA triad using a system you know, and give an example where two of the properties pull against each other."

<details><summary>Sample answer</summary>

"Take a customer portal at an ISP, where customers log in to see their bills and personal data. Confidentiality means only the account owner can see their ID number, address and bills. Integrity means bill amounts and plan changes cannot be altered without authorization, and we can prove who made a change. Availability means the portal is up when thousands of customers want to pay before the due date. The properties pull against each other all the time: requiring a one-time code for every login strengthens confidentiality, but if the SMS gateway is down, customers cannot get in, which hurts availability. So in practice we apply the stronger check where the risk is higher, such as plan changes and personal data edits, rather than everywhere. The same thinking applies to incidents: a backup restores integrity and availability after ransomware, but it does nothing for confidentiality once data has been copied out."

What makes this answer strong: it grounds each property in a concrete asset, shows a real trade-off instead of treating the triad as a checklist, ties the decision back to risk, and closes with a point many candidates miss about backups and confidentiality.

</details>

## 8. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | NIST CSRC Glossary: confidentiality, integrity, availability | https://csrc.nist.gov/glossary/term/confidentiality<br>https://csrc.nist.gov/glossary/term/integrity<br>https://csrc.nist.gov/glossary/term/availability | primer (glosarium NIST) | diakses 2026-10-20 | Tinggi. Definisi utama dari FIPS 200 dan 44 U.S.C. |
| S2 | NIST CSRC Glossary: non-repudiation | https://csrc.nist.gov/glossary/term/non_repudiation | primer (glosarium NIST) | diakses 2026-10-20 | Tinggi. Definisi SP 800-53 Rev. 5 dan FIPS 186-5 |
| S3 | NIST CSRC Glossary: authentication, authorization, AAA | https://csrc.nist.gov/glossary/term/authentication<br>https://csrc.nist.gov/glossary/term/authorization<br>https://csrc.nist.gov/glossary/term/authentication_authorization_and_accounting | primer (glosarium NIST) | diakses 2026-10-20 | Tinggi. Entri AAA hanya memuat singkatan dan sumbernya (SP 800-97), tanpa teks definisi |
| S4 | NIST CSRC Glossary: asset, threat, threat actor | https://csrc.nist.gov/glossary/term/asset<br>https://csrc.nist.gov/glossary/term/threat<br>https://csrc.nist.gov/glossary/term/threat_actor | primer (glosarium NIST) | diakses 2026-10-20 | Tinggi. Threat memakai versi FIPS 200; threat actor dari SP 800-150 |
| S5 | NIST CSRC Glossary: vulnerability | https://csrc.nist.gov/glossary/term/vulnerability | primer (glosarium NIST) | diakses 2026-10-20 | Tinggi. Definisi FIPS 200 dan SP 800-53 Rev. 5 |
| S6 | NIST CSRC Glossary: risk, likelihood of occurrence | https://csrc.nist.gov/glossary/term/risk<br>https://csrc.nist.gov/glossary/term/likelihood_of_occurrence | primer (glosarium NIST) | diakses 2026-10-20 | Tinggi |
| S7 | NIST CSRC Glossary: least privilege, separation of duty | https://csrc.nist.gov/glossary/term/least_privilege<br>https://csrc.nist.gov/glossary/term/separation_of_duty | primer (glosarium NIST) | diakses 2026-10-20 | Tinggi. Definisi SoD dari SP 800-192, termasuk contoh gaji dan aturan dua orang |
| S8 | NIST CSRC Glossary: defense-in-depth | https://csrc.nist.gov/glossary/term/defense_in_depth | primer (glosarium NIST) | diakses 2026-10-20 | Tinggi. Versi SP 800-53 Rev. 5 dan NISTIR 8183 (lapisan heterogen) |
| S9 | NIST CSRC Glossary: attack surface | https://csrc.nist.gov/glossary/term/attack_surface | primer (glosarium NIST) | diakses 2026-10-20 | Tinggi. Definisi SP 800-53 Rev. 5 |
| S10 | NIST CSRC Glossary: security control, compensating controls | https://csrc.nist.gov/glossary/term/security_control<br>https://csrc.nist.gov/glossary/term/compensating_controls | primer (glosarium NIST) | diakses 2026-10-20 | Tinggi |
| S11 | NIST SP 800-12 Rev. 1: An Introduction to Information Security | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-12r1.pdf<br>https://csrc.nist.gov/pubs/sp/800/12/r1/final | primer | 2017-06; diakses 2026-10-20 | Tinggi. Sumber defense in depth (administratif, teknologi, fisik), accountability, SoD, dan least privilege |
| S12 | NIST SP 800-30 Rev. 1: Guide for Conducting Risk Assessments | https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-30r1.pdf<br>https://csrc.nist.gov/pubs/sp/800/30/r1/final | primer | 2012-09; diakses 2026-10-20 | Tinggi. Faktor risiko, empat jenis sumber ancaman, skala lima tingkat (Tabel I-2), pilihan respons, residual risk. Lebih dari 10 tahun, tetapi masih versi final terbaru |
| S13 | NIST SP 800-207: Zero Trust Architecture | https://csrc.nist.gov/pubs/sp/800/207/final<br>https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf | primer | 2020-08; diakses 2026-10-20 | Tinggi. Tujuh prinsip, PDP/PEP, catatan bahwa prinsip tidak berlaku untuk layanan publik anonim |
| S14 | NIST SP 800-207A: A Zero Trust Architecture Model for Access Control in Cloud-Native Applications in Multi-Cloud Environments | https://csrc.nist.gov/pubs/sp/800/207/a/final | primer | 2023-09; diakses 2026-10-20 | Tinggi. Hanya dipakai untuk catatan versi |
| S15 | NIST CSRC News: Implementing a Zero Trust Architecture (SP 1800-35) | https://csrc.nist.gov/news/2025/implementing-a-zero-trust-architecture-sp-1800-35 | primer (pengumuman NIST) | 2025-06-10; diakses 2026-10-20 | Tinggi. Hanya dipakai untuk catatan versi |
| S16 | CISA: Zero Trust Maturity Model Version 2.0 | https://www.cisa.gov/sites/default/files/2023-04/zero_trust_maturity_model_v2_508.pdf<br>https://www.cisa.gov/zero-trust-maturity-model | primer | 2023-04; diakses 2026-10-20 | Tinggi. Halaman web ditandai arsip; tabel riwayat di PDF mencantumkan tanggal yang berbeda dengan sampulnya |
| S17 | NIST: NIST Releases Version 2.0 of Landmark Cybersecurity Framework; CSWP 29 | https://www.nist.gov/news-events/news/2024/02/nist-releases-version-20-landmark-cybersecurity-framework<br>https://csrc.nist.gov/pubs/cswp/29/the-nist-cybersecurity-framework-csf-20/final | primer | 2024-02-26; diakses 2026-10-20 | Tinggi |
| S18 | RFC 2975: Introduction to Accounting Management | https://www.rfc-editor.org/rfc/rfc2975 | primer (RFC Informational) | 2000-10; diakses 2026-10-20 | Tinggi untuk definisi accounting. Dokumen lama, tetapi definisinya stabil |
| S19 | RFC 2865: Remote Authentication Dial In User Service (RADIUS) | https://www.rfc-editor.org/rfc/rfc2865 | primer (RFC Standards Track) | 2000-06; diakses 2026-10-20 | Tinggi. Sudah diperbarui beberapa RFC lanjutan; accounting RADIUS diatur di dokumen terpisah |
| S20 | Destination Certification: Types of Security Controls: Preventive, Detective, Corrective and More | https://destcert.com/resources/types-security-controls/ | sekunder (materi pelatihan) | diperbarui 2026-07-01; diakses 2026-10-20 | Sedang. Dipakai untuk pembagian jenis control karena NIST tidak memakai pembagian preventive, detective, corrective sebagai kategori resmi |

**Catatan sumber:** definisi exploit di bagian 1.3 ditulis dengan kata sendiri karena glosarium NIST tidak punya entri terpisah untuk istilah itu; pengertiannya mengikuti definisi vulnerability yang menyebut kelemahan "dimanfaatkan" sumber ancaman [S5]. Pembagian preventive, detective, dan corrective berasal dari materi pelatihan [S20], bukan dari kategori resmi NIST, dan sumber lain bisa membaginya sedikit berbeda. Pengelompokan attack surface ke layanan jaringan, aplikasi, akun, pihak ketiga, fisik, dan orang di bagian 1.9 adalah susunan catatan ini, bukan daftar dari definisi NIST. Tabel risiko tiga tingkat di bagian 2.2 adalah penyederhanaan dari skala lima tingkat SP 800-30 [S12]. Seluruh isi PT JAB (alert `SOC-2027-0800`, insiden `INC-2027-080`, angka percobaan login, penilaian risiko, daftar control, dan permintaan akses) adalah contoh fiktif.
