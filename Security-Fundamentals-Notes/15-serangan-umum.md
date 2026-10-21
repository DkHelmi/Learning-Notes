---
day: 15
title: 'Serangan umum dari sisi pembela: tebak password, injeksi web, orang di tengah, pergerakan di dalam, dan jalur kepercayaan'
researched_on: 2026-10-21
versions_checked: 'MITRE ATT&CK v20.0 (13 Okt 2026); OWASP Top 10:2025 (A05 Injection); OWASP Cheat Sheet Series (SQL Injection Prevention, XSS Prevention, CSRF Prevention, Session Management; diakses 2026-10-21); NIST SP 800-63B-4; NIST CSRC Glossary (diakses 2026-10-21); RFC 5452 (Jan 2009); CERT/CC VU#800113 (revisi 2014); CISA dan NIST Defending Against Software Supply Chain Attacks (Apr 2021); CISA Defining Insider Threats'
---

# Day 15: Serangan umum dari sisi pembela (brute force sampai insider threat)

Cakupan: empat belas nama serangan yang paling sering muncul di antrean alert SOC, masing-masing dilihat dari definisinya, kelemahan di pihak korban yang dimanfaatkan, tandanya di log, cara membedakannya dari aktivitas sah, dan kontrol pencegahnya.

## Ide inti

Nama serangan di Day ini terdengar banyak, tetapi tujuannya hanya sedikit. Ada yang ingin mendapat kunci yang sah (brute force, password spraying, credential stuffing), ada yang membuat aplikasi menuruti isian yang bukan perintah pemiliknya (SQL injection, XSS, CSRF), ada yang menyelip di antara dua pihak yang sedang berkomunikasi (MITM, session hijacking, DNS spoofing), dan ada yang, setelah berada di dalam, menaikkan hak, berpindah ke komputer lain, lalu membawa data keluar (privilege escalation, lateral movement, exfiltration). Dua sisanya, supply chain attack dan insider threat, tidak datang lewat pintu yang dijaga, tetapi lewat pihak yang memang sudah dipercaya: pemasok dan orang dalam.

Bagi pembela, setiap serangan meninggalkan bentuk yang khas di log: berapa kali sesuatu dicoba, ke berapa akun atau tujuan, dari mana ke mana, jam berapa, dan berapa banyak data yang bergerak. Analyst L1 tidak perlu bisa melakukan serangan itu. Yang perlu dikuasai adalah membaca bentuknya, memberi nama yang tepat, dan memilih langkah berikutnya, karena nama serangan menentukan playbook, siapa yang dihubungi, dan kontrol apa yang diperiksa. Salah menamai sering berarti salah memeriksa: kamu mencari akun yang terkunci, padahal pelakunya justru sengaja menghindari penguncian.

Bayangkan sebuah gedung kantor. Ada maling yang mencoba semua kunci di satu gembok, ada yang mencoba satu kunci pasaran di semua pintu, ada yang memakai kunci curian dari gedung lain. Ada penipu yang mengisi formulir sehingga petugas loket membaca isinya sebagai perintah, ada brosur palsu yang ditempel di papan pengumuman resmi, dan ada kurir nakal yang membuka paket di jalan. Ada penyusup yang sudah di dalam lalu berpindah dari ruang ke ruang dan membawa barang keluar. Ada pula barang pemasok yang sudah disusupi sebelum diantar, dan karyawan sendiri yang menyalahgunakan kartu aksesnya. Batas analogi ini: di jaringan, satu pelaku bisa mencoba ribuan pintu per menit secara otomatis, data yang "dibawa keluar" tetap ada di tempat asalnya sehingga kehilangannya tidak terasa, dan jejaknya hanya terlihat di log yang memang dikumpulkan.

```
  MENDAPAT KUNCI          MENYURUH APLIKASI       MENYELIP DI TENGAH
  brute force             SQL injection           MITM
  password spraying       XSS                     session hijacking
  credential stuffing     CSRF                    DNS spoofing / poisoning
          \                     |                      /
           +---------- akses awal ke sistem ----------+
                               |
     SETELAH DI DALAM: privilege escalation -> lateral movement -> exfiltration

  LEWAT PIHAK YANG DIPERCAYA: supply chain attack (pemasok), insider threat (orang dalam)

  Yang dibaca pembela di setiap kotak: jumlah, sebaran, arah, jam, volume
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP fiktif dengan sekitar 1.200 karyawan dan sekitar 400 ribu pelanggan internet rumah. Kamu adalah analyst L1 (lapis pertama yang memeriksa alert) yang baru bergabung di SOC (Security Operations Center, tim yang memantau dan menangani kejadian keamanan) PT JAB. Senin 2027-08-23 pukul 08:30, minggu keempat orientasi, mentormu Sari Kusuma (analyst L2) membagikan tujuh kartu berisi ringkasan alert akhir pekan. Judul alert ditutup selotip.

> "Pagi. Latihan hari ini: tebak jenis serangannya. Tujuh kartu ini alert asli dari Sabtu sampai pagi tadi, judulnya saya tutup. Untuk tiap kartu, jawab empat hal: serangan apa ini, kelemahan apa di pihak kita yang dimanfaatkan, dari mana kamu tahu ini bukan aktivitas biasa, dan satu kontrol yang mencegahnya. Dua kartu ternyata satu cerita yang sama, dan cerita itu menjadi `INC-2027-094`. Cari yang mana. Hati-hati, ada kartu yang kelihatannya nyambung padahal tidak."

```
Kartu 1  SOC-2027-0880  jkt-vpn01: 1.236 login gagal dari 3 IP ke 412 nama akun, dalam 3 gelombang, Sabtu dini hari
Kartu 2  SOC-2027-0882  jkt-waf01: 18 kiriman formulir keluhan portal ditolak 403, semuanya dari 192.0.2.223
Kartu 3  SOC-2027-0883  jkt-res01: 52.400 jawaban DNS tidak cocok dalam 10 menit untuk satu domain bank
Kartu 4  SOC-2027-0884  RDP dari JKT-WS-1152 ke 3 workstation lain memakai akun it.helpdesk02, Minggu 23:14
Kartu 5  SOC-2027-0885  jkt-proxy01: unggahan lebih dari 1 GB dari JKT-WS-1157 ke penyimpanan cloud pribadi, tengah malam
Kartu 6  SOC-2027-0881  jkt-nms-stg01: koneksi keluar ditolak ke domain baru, 2 menit setelah pembaruan software vendor
Kartu 7  SOC-2027-0886  Karyawan yang sudah mengajukan resign membuka 2.870 file share Penjualan Korporat dalam 40 menit
```

Pesan dan kartu itu memuat tujuh pertanyaan:

1. Kartu 1: serangan menebak password jenis apa, dan apa bedanya dengan dua jenis lain yang mirip?
2. Kartu 2: apa yang ditolak WAF, siapa korbannya seandainya lolos, dan apa hubungannya dengan SQL injection dan CSRF?
3. Kartu 3: apa yang dicari pelaku dengan jawaban DNS palsu, dan apa hubungannya dengan "orang di tengah" dan pencurian sesi?
4. Kartu 4: bagaimana akun helpdesk bisa dipakai pelaku, dan kenapa RDP antar workstation patut dicurigai?
5. Kartu 5: bagaimana membedakan pencurian data dari unggahan kerja yang sah?
6. Kartu 6: kenapa pembaruan resmi yang bertanda tangan sah dari vendor bisa berbahaya?
7. Kartu 7: bagaimana menangani dugaan penyalahgunaan oleh orang dalam?

Pertanyaan 1 dijawab di bagian 1.1 sampai 1.3, pertanyaan 2 di bagian 1.4 sampai 1.6, pertanyaan 3 di bagian 1.7 sampai 1.9, pertanyaan 4 di bagian 1.10 dan 1.11, pertanyaan 5 di bagian 1.12, pertanyaan 6 di bagian 1.13, dan pertanyaan 7 di bagian 1.14. Bagian 2 membaca log di balik kartu-kartu itu, termasuk lini waktu `INC-2027-094`, dan bagian 2.6 berisi kunci latihan Sari.

**Kapan relevan:** saat memberi nama dan kategori pada alert, memilih playbook, menulis ringkasan alert yang dipahami L2, menjelaskan kejadian ke pemilik sistem, dan menjawab pertanyaan interview yang hampir selalu menanyakan beda brute force, password spraying, dan credential stuffing, atau beda SQL injection dan XSS.
**Kapan bukan jawaban:** Day ini membahas serangan dari sisi yang melihat log; tidak ada cara melakukan serangan dan tidak ada contoh muatan serangan. Jenis malware dibahas di Day 16, kerentanan dan pengujian di Day 17, kerangka seperti MITRE ATT&CK di Day 14, dan prosedur penanganan insiden di Day 19. Memberi nama juga bukan tujuan akhir: yang menentukan tindakan tetap dampaknya, yaitu apakah ada akun, data, atau sistem yang benar-benar terkena.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (firewall, WAF, VPN, proxy, SIEM, EDR, MFA, NTLM, DLP, MITRE ATT&CK) tidak diulang di tabel ini; definisinya diulang satu kalimat di subbagian yang memakainya. Tabel berikut memuat istilah serangan dan istilah pendukungnya; pakai kolom padanan bila sebuah istilah terasa abstrak.

| Istilah | Arti singkat | Padanan sehari-hari |
|---|---|---|
| Kredensial | Bukti identitas untuk login: password, kode MFA, kunci, tiket, cookie sesi | Kunci, kartu akses, dan PIN |
| Brute force | Mencoba banyak tebakan password sampai ada yang benar | Mencoba semua kunci di satu gembok |
| Password spraying | Mencoba satu atau sedikit password umum ke banyak akun | Mencoba satu kunci pasaran di semua pintu |
| Credential stuffing | Mencoba pasangan username dan password yang bocor dari layanan lain | Memakai kunci curian dari gedung lain |
| Account lockout | Akun dikunci sementara setelah sejumlah login gagal | Gembok yang macet setelah salah kunci berkali-kali |
| Injection | Isian pengguna terbaca sebagai perintah oleh aplikasi | Petugas yang membaca isi formulir sebagai perintah |
| SQL injection | Injection yang mengubah perintah ke database | Formulir yang membuat petugas arsip membuka lemari yang salah |
| XSS | Skrip pihak lain ikut tampil di halaman situs asli dan berjalan di browser pengunjung | Brosur palsu ditempel di papan pengumuman resmi |
| CSRF | Browser korban yang sudah login dibuat mengirim permintaan yang tidak ia maksud | Surat kuasa yang ditandatangani tanpa dibaca |
| Sesi dan session cookie | Status "sudah login" yang diingat situs lewat token kecil di browser | Gelang tanda masuk konser |
| MITM / AiTM | Pihak lain berada di antara dua pihak yang berkomunikasi | Kurir nakal yang membuka paket di jalan |
| Session hijacking | Memakai sesi milik orang lain yang sudah login | Memakai gelang konser milik orang lain |
| DNS spoofing | Memberi jawaban DNS palsu kepada penanya | Operator informasi yang memberi nomor telepon salah |
| DNS cache poisoning | Jawaban DNS palsu masuk ke cache resolver dan dibagikan ke banyak penanya | Buku telepon kantor yang halamannya ditempel nomor palsu |
| Privilege escalation | Mendapat hak lebih tinggi dari yang seharusnya | Tamu yang mendapat kunci master |
| Lateral movement | Berpindah dari satu sistem ke sistem lain di dalam jaringan | Penyusup yang pindah dari lobi ke ruang-ruang lain |
| RDP | Protokol Windows untuk memakai komputer lain dari jarak jauh, port 3389 | Remote kontrol layar komputer |
| Exfiltration | Pemindahan data keluar tanpa izin | Membawa barang keluar gedung tanpa izin |
| Egress filtering | Membatasi koneksi keluar hanya ke tujuan yang diizinkan | Satpam yang memeriksa siapa keluar membawa apa |
| Supply chain attack | Menyerang target lewat produk atau layanan pemasoknya | Barang pemasok yang sudah disusupi sebelum diantar |
| Code signing | Tanda tangan digital pembuat software pada programnya | Segel resmi pabrik di kemasan |
| Insider / insider threat | Orang dengan akses sah / risiko orang itu merugikan organisasi | Karyawan pemegang kartu akses |
| Baseline | Gambaran perilaku normal sebagai pembanding | Kebiasaan penghuni yang dihafal satpam lama |

### 1.1 Brute force

Kartu 1 berisi ribuan login gagal. Sebelum memberi nama, Sari meminta kamu mengenal tiga anggota keluarga serangan menebak password, mulai dari yang paling sederhana.

**Apa itu:** brute force adalah usaha mendapatkan akses ke akun dengan mencoba banyak tebakan password secara sistematis, karena password-nya tidak diketahui [S1]. MITRE ATT&CK (katalog teknik serangan, Day 14) mencatatnya sebagai technique T1110 di tactic Credential Access, dengan empat sub-technique: T1110.001 Password Guessing (menebak langsung ke layanan login), T1110.002 Password Cracking (menebak terhadap hash password yang sudah dicuri, di luar sistem korban), T1110.003 Password Spraying, dan T1110.004 Credential Stuffing [S1]. Di percakapan sehari-hari, "brute force" biasanya berarti T1110.001: banyak tebakan ke satu akun.

**Analogi:** mencoba semua kunci di satu gembok, satu per satu, sampai ada yang pas. Batasnya: gembok fisik tidak mengunci diri setelah salah lima kali, sedangkan layanan login yang baik melakukannya; dan di internet tebakan bisa dikirim puluhan kali per detik dari banyak alamat sekaligus.

**Kenapa bisa terjadi:** brute force hanya berhasil bila di pihak korban ada kombinasi kelemahan: password pendek atau umum, layanan login (SSH, RDP, VPN, portal web) yang terbuka ke internet padahal tidak perlu, tidak ada batas jumlah percobaan, dan tidak ada MFA (bukti kedua selain password, Day 06). Untuk cracking, kelemahannya ada lebih awal: hash password (sidik jari password, Day 05) bisa dicuri, dan password yang disimpan tanpa salt atau dengan algoritma lemah lebih cepat ditebak.

**Tanda di log:**
- Banyak login gagal untuk satu akun dalam waktu singkat, biasanya dari satu atau sedikit alamat IP.
- Di Windows, setiap login gagal dicatat sebagai Event 4625 di komputer tempat login dicoba. Field Status `0xC000006A` berarti password salah, `0xC0000064` berarti nama akun tidak ada, dan `0xC0000234` berarti akun terkunci [S5]. Microsoft menyarankan memperhatikan rentetan `0xC0000064`, karena itu tanda ada yang sedang menebak nama akun [S5].
- Pola paling berbahaya: rentetan gagal yang diakhiri satu login berhasil dari sumber yang sama.
- Password cracking tidak meninggalkan login gagal sama sekali, karena tebakan dilakukan di luar sistem korban. Petunjuknya datang lebih awal, saat hash atau tiket dicuri, misalnya pola Kerberoasting di Day 07 bagian 2.4.

**Contoh di PT JAB:** alert `SOC-2027-0821` di minggu pertama orientasi adalah brute force klasik: 1.240 percobaan login SSH dalam 20 menit dari `192.0.2.104` ke server SFTP mitra `jkt-sftp01`, semuanya gagal, lalu agen Wazuh memblokir alamat itu 10 menit (Day 03 bagian 2.2).

**Membedakan dari aktivitas sah:** user yang lupa password biasanya gagal 2 sampai 5 kali lalu berhasil atau menelepon helpdesk, dari IP yang biasa ia pakai. Skrip atau aplikasi yang menyimpan password lama juga bisa menghasilkan ribuan login gagal, tetapi polanya teratur (setiap beberapa menit tepat), dari satu host internal yang dikenal, ke akun layanan yang sama. Pemindai keamanan internal yang dijadwalkan juga dicek di daftar perubahan sebelum dianggap serangan.

**Pencegahan:** MFA, batas percobaan dan penguncian akun, menutup layanan login yang tidak perlu dari internet, dan password panjang yang dicek terhadap daftar password bocor [S1][S4]. NIST SP 800-63B-4 mewajibkan verifier membatasi percobaan gagal berturut-turut maksimal 100 kali per akun, dan boleh lebih ketat [S4]. MITRE mengingatkan bahwa penguncian yang terlalu ketat bisa dimanfaatkan untuk sengaja mengunci banyak akun sah, sehingga menjadi gangguan layanan [S1].

**Beda dengan password cracking:** guessing meninggalkan login gagal di server; cracking tidak, karena dikerjakan di luar. Kalau ada dugaan hash bocor, yang dicari adalah jejak pencurian hash, bukan login gagal.

### 1.2 Password spraying

Kartu 1 tidak cocok dengan pola bagian 1.1: tidak ada satu akun pun yang dicoba lebih dari tiga kali, tetapi jumlah akun yang dicoba mencapai 412.

**Apa itu:** password spraying adalah mencoba satu password umum, atau daftar kecil password umum, ke banyak akun yang berbeda [S2]. MITRE mencatatnya sebagai T1110.003 dan menyebut alasannya: dengan menyebar percobaan ke banyak akun, penguncian yang terjadi bila satu akun ditebak berkali-kali bisa dihindari [S2]. Layanan yang sering disasar menurut MITRE antara lain SSH, RDP, layanan web, SSO dan aplikasi cloud, serta email yang terbuka ke internet [S2].

**Analogi:** mencoba satu kunci pasaran di semua pintu gedung. Dari 400 pintu, cukup satu yang memakai kunci pasaran itu. Batasnya: di gedung nyata orang yang berkeliling mencoba pintu akan terlihat; di jaringan, percobaan bisa dijeda berjam-jam dan disebar dari banyak alamat sehingga tiap pintu hanya "diketuk" sekali dalam satu gelombang.

**Kenapa bisa terjadi:** di organisasi besar hampir selalu ada sebagian kecil karyawan yang memakai password yang mudah ditebak (nama musim, nama perusahaan, password bawaan). Kelemahan kedua ada di cara penguncian dihitung: bila batasnya hanya "gagal per akun", satu percobaan per akun tidak pernah memicu apa pun. Kelemahan ketiga adalah daftar nama akun yang mudah ditebak dari pola alamat email perusahaan, ditambah layanan login yang membedakan "akun tidak ada" dari "password salah".

**Tanda di log:**
- Satu sumber, atau sekelompok sumber, gagal login ke banyak akun berbeda dengan sedikit percobaan per akun [S2].
- Percobaan datang bergelombang: semua akun dicoba sekali, jeda, lalu semua akun dicoba lagi.
- Ada campuran "password salah" dan "akun tidak ada" (`0xC0000064` di Windows) karena daftar nama berasal dari tebakan [S5].
- Hitungan per akun tetap rendah, jadi rule yang menghitung per akun diam. Rule yang tepat menghitung jumlah akun berbeda per sumber, atau jumlah gagal di seluruh layanan dalam satu jendela waktu.

**Contoh di PT JAB:** Kartu 1 (`SOC-2027-0880`). Sabtu dini hari, `jkt-vpn01` menerima 1.236 login gagal dalam tiga gelombang, masing-masing ke 412 nama akun yang sama dengan urutan yang sama, dari tiga IP berbeda (`192.0.2.221`, `.222`, `.228`). Satu akun, milik Dodi Hermawan (staf Gudang Logistik), lolos tahap password di gelombang ketiga dan berhenti di MFA. Rinciannya di bagian 2.1.

**Membedakan dari aktivitas sah:** aktivitas sah hampir tidak pernah menghasilkan satu sumber yang gagal ke ratusan akun berbeda. Pengecualian yang perlu dicek: alamat NAT bersama (banyak karyawan di belakang satu IP kantor, atau satu IP Wi-Fi hotel saat acara perusahaan) yang menghasilkan beberapa gagal dari banyak akun, tetapi tersebar acak, bukan berurutan dan bergelombang; dan pengujian keamanan resmi yang punya surat izin dan jadwal.

**Pencegahan:** MFA yang wajib untuk semua layanan dari internet, penolakan password yang ada di daftar password umum atau bocor (SP 800-63B-4 mewajibkan verifier membandingkan password baru dengan blocklist seperti itu) [S4], deteksi berbasis jumlah akun per sumber, dan pesan login yang tidak membedakan "akun tidak ada" dari "password salah" [S2].

**Beda dengan brute force:** brute force banyak tebakan ke satu akun; spraying satu tebakan ke banyak akun. Konsekuensinya bagi analyst: pada brute force kamu melihat akun terkunci, pada spraying hampir tidak ada yang terkunci.

### 1.3 Credential stuffing

Untuk menutup Kartu 1, Sari membandingkannya dengan alert lama: `SOC-2027-0800` di hari pertama orientasi.

**Apa itu:** credential stuffing adalah mencoba pasangan username dan password yang bocor dari layanan lain, dengan harapan pemiliknya memakai pasangan yang sama di layanan sasaran [S3]. MITRE mencatatnya sebagai T1110.004 dan menyebut dasarnya: banyak orang memakai ulang password di berbagai akun [S3]. Bedanya dengan spraying, yang dicoba bukan tebakan, tetapi pasangan asli milik orang tertentu.

**Analogi:** memakai kunci rumah curian dari kompleks lain untuk mencoba pintu kantor pemiliknya, karena banyak orang memakai satu kunci untuk semua pintu. Batasnya: kunci fisik curian hanya satu; daftar password bocor di internet berisi jutaan pasangan, dan dicoba otomatis.

**Kenapa bisa terjadi:** kelemahannya adalah password yang dipakai ulang oleh pemilik akun, ditambah layanan yang tidak mewajibkan MFA. Organisasi korban tidak perlu bocor sama sekali; yang bocor adalah situs lain tempat karyawan atau pelanggannya mendaftar dengan password yang sama.

**Tanda di log:**
- Banyak akun dicoba, masing-masing sekali atau dua kali, mirip spraying, tetapi password-nya berbeda-beda per akun.
- Tingkat keberhasilan kecil tetapi tidak nol: beberapa login berhasil di tengah ratusan kegagalan, sering dari IP yang tidak pernah dipakai pemilik akun.
- Banyak "akun tidak ada", karena daftar bocor berisi alamat email yang tidak pernah terdaftar di layanan sasaran.
- Dari log saja, spraying dan stuffing sering sulit dibedakan karena password tidak dicatat (memang tidak boleh). Petunjuknya: spraying bergelombang dengan urutan nama yang sama; stuffing biasanya satu lintasan dengan daftar yang tidak berurutan.

**Contoh di PT JAB:** `SOC-2027-0800` (Day 01 bagian 2.1): 415 percobaan ke 383 akun pelanggan portal dalam 10 menit dari `192.0.2.77`, 412 gagal dan 3 berhasil. Ketiga akun yang berhasil memakai password yang sama dengan yang bocor dari situs lain dan tidak mengaktifkan OTP. Batas lima kali gagal per akun di portal tidak pernah terpicu.

**Membedakan dari aktivitas sah:** login pelanggan sah tersebar dari ribuan IP rumah, satu akun per IP, dengan tingkat keberhasilan tinggi. Stuffing memperlihatkan kebalikannya: banyak akun dari sedikit IP, keberhasilan sangat rendah. Aplikasi agregator yang login atas nama banyak pengguna (misalnya mitra resmi) juga memperlihatkan banyak akun dari satu IP; cek daftar mitra sebelum memblokir.

**Pencegahan:** MFA, pengecekan password terhadap daftar password bocor saat dibuat dan saat login [S4], pembatasan per IP dan per perangkat, serta edukasi agar karyawan dan pelanggan tidak memakai ulang password [S3]. Untuk karyawan, password manager resmi perusahaan mengurangi alasan memakai ulang password.

**Beda dengan password spraying:** spraying memakai satu password yang sama ke banyak akun; stuffing memakai password yang berbeda dan sudah benar untuk tiap akun di tempat lain. Karena itu stuffing bisa berhasil pada orang yang memakai password panjang, asalkan dipakai ulang.

### 1.4 SQL injection

Kartu 2 berisi kiriman formulir yang ditolak WAF (web application firewall, pemeriksa permintaan ke aplikasi web, Day 03 bagian 1.8). Empat dari 18 kiriman ditolak dengan kategori SQL injection, jadi Sari memulai dari sini.

**Apa itu:** injection adalah kelompok kelemahan di mana isian dari pengguna terbaca sebagai bagian dari perintah oleh aplikasi. OWASP Top 10:2025 menempatkan Injection di urutan A05, turun dari urutan ketiga di edisi 2021, dan kategori ini mencakup SQL injection maupun XSS [S6]. SQL injection secara khusus terjadi ketika isian pengguna ikut menyusun query SQL (bahasa untuk meminta dan mengubah data di database), sehingga isian itu bisa mengubah arti query [S7]. Akibatnya bisa berupa membaca data yang bukan haknya, mengubah atau menghapus data, sampai melewati login. MITRE mencatat SQL injection sebagai salah satu contoh T1190 Exploit Public-Facing Application, technique untuk masuk lewat aplikasi yang terbuka ke internet [S26].

**Analogi:** petugas arsip yang menerima formulir permintaan dokumen dan langsung mengerjakan apa pun yang tertulis di kolom "nomor pelanggan", termasuk kalimat tambahan "dan sekalian bukakan lemari semua pelanggan". Batasnya: petugas manusia biasanya curiga pada kalimat aneh; program menjalankan apa pun yang lolos menjadi perintah, tanpa curiga.

**Kenapa bisa terjadi:** aplikasi menyusun query dengan menempelkan isian pengguna langsung ke teks perintah, alih-alih memisahkan perintah dari data [S7]. Kelemahan pendukungnya: isian tidak divalidasi bentuknya (nomor pelanggan seharusnya hanya angka), akun database yang dipakai aplikasi punya hak terlalu luas, dan pesan error database ditampilkan ke pengunjung sehingga membantu orang memahami struktur database.

**Tanda di log:**
- WAF dan IDS memberi label kategori, misalnya "SQL injection", pada permintaan yang parameternya memuat karakter dan kata kunci khas bahasa query.
- Banyak permintaan dari satu sumber ke satu halaman dengan parameter yang berubah-ubah sedikit demi sedikit, sering dengan user-agent alat otomatis.
- Di sisi aplikasi: lonjakan error database atau jawaban `500`, dan yang paling penting, jawaban `200` yang ukurannya jauh lebih besar dari biasanya (tanda data ikut keluar).
- Di database: query yang tidak pernah dipakai aplikasi, atau akun aplikasi yang tiba-tiba membaca tabel lain.

**Contoh di PT JAB:** `SOC-2027-0820` (Day 03 bagian 2.1): 64 permintaan dari `192.0.2.101` ke portal, 61 ditolak WAF, 3 lolos dan ditolak aplikasi dengan `400`. Di Kartu 2, empat kiriman dari `192.0.2.223` ke formulir keluhan juga berlabel SQL injection, di samping 14 berlabel XSS (bagian 2.2).

**Membedakan dari aktivitas sah:** WAF kadang salah menandai isian sah, misalnya alamat yang memuat tanda petik atau kata seperti "select" di kolom keluhan. Bedanya: kiriman sah datang sekali dari satu pengguna dengan isi yang masuk akal, sedangkan percobaan injection datang beruntun dengan variasi isi dan sering dari alat otomatis. Pemindai kerentanan resmi juga menghasilkan pola ini, jadi cek jadwal pengujian dan IP pemindai milik PT JAB.

**Pencegahan:** OWASP menyebut pertahanan utama adalah prepared statement atau parameterized query, yaitu cara menulis query di mana perintah dan data dikirim terpisah sehingga isian selalu diperlakukan sebagai data [S7]. Pelengkapnya: validasi isian dengan daftar bentuk yang diizinkan, akun database dengan hak minimum, dan pesan error yang tidak membocorkan detail [S7]. WAF berguna sebagai lapisan tambahan, tetapi bisa dilewati varian yang belum dikenali, seperti tiga permintaan di `SOC-2027-0820`.

### 1.5 XSS (cross-site scripting)

Empat belas kiriman di Kartu 2 berlabel XSS. Pertanyaan Sari: siapa korbannya seandainya kiriman itu lolos? Jawabannya bukan server, tetapi orang yang kelak membuka keluhan itu.

**Apa itu:** XSS adalah jenis injection di mana skrip dari pihak lain ikut tampil di halaman situs yang sah, lalu dijalankan oleh browser pengunjung seolah-olah skrip itu bagian dari situs [S8]. Karena berjalan atas nama situs asli, skrip itu bisa membaca isi halaman, bertindak atas nama pengguna yang sedang login, atau mencuri cookie sesi yang tidak dilindungi [S8]. OWASP membagi XSS menjadi tiga: stored (isian berbahaya tersimpan di server dan tampil ke setiap orang yang membuka halamannya), reflected (isian dipantulkan langsung di jawaban, biasanya lewat tautan yang diklik korban), dan DOM-based (terjadi sepenuhnya di kode browser) [S8]. Di daftar CWE Top 25 2025, XSS ada di peringkat pertama (Day 17 bagian 1.3).

**Analogi:** brosur palsu yang ditempel di papan pengumuman resmi kantor. Karena ada di papan resmi, karyawan percaya dan mengikuti isinya. Batasnya: brosur hanya bisa dibaca; skrip di halaman web langsung bekerja begitu halaman dibuka, tanpa korban perlu mempercayai apa pun.

**Kenapa bisa terjadi:** aplikasi menampilkan kembali isian pengguna ke halaman tanpa mengubahnya menjadi teks biasa (output encoding), sehingga browser membacanya sebagai kode [S9]. Kelemahan pendukungnya: cookie sesi tanpa atribut `HttpOnly` sehingga bisa dibaca skrip, dan tidak adanya Content Security Policy (aturan dari situs yang membatasi skrip mana yang boleh berjalan) [S9].

**Tanda di log:**
- WAF memberi label kategori XSS pada isian yang memuat tag HTML atau atribut yang menjalankan skrip.
- Untuk stored XSS, tanda sesudah kejadian muncul di tempat lain: browser staf yang membuka halaman tiba-tiba menghubungi domain asing, atau ada tindakan atas nama staf yang tidak ia lakukan.
- Untuk reflected XSS, URL panjang dengan parameter berisi kode di log proxy atau email (tautan yang dikirim ke korban).

**Contoh di PT JAB:** formulir keluhan di `portal.jab.example/keluhan` terbuka tanpa login. Isi keluhan masuk ke dasbor back-office yang dibuka staf Customer Care beberapa kali sehari. Seandainya salah satu dari 14 kiriman lolos dan aplikasi tidak melakukan output encoding, skripnya akan berjalan di browser staf Customer Care yang sedang login ke dasbor, dengan hak staf itu: membaca data pelanggan, mengubah data, atau mencuri sesinya. Itu sebabnya stored XSS di formulir publik yang dibaca staf internal dinilai serius walaupun portal pelanggan sendiri tidak terdampak.

**Membedakan dari aktivitas sah:** pelanggan kadang menempelkan teks dari email atau dokumen yang memuat tag HTML, dan WAF bisa menandainya. Kiriman sah biasanya satu kali, isinya keluhan yang masuk akal, dan tag yang ikut tidak berisi skrip. Percobaan XSS datang beruntun dengan isi yang hanya berupa variasi kode, tanpa keluhan sungguhan.

**Pencegahan:** OWASP menempatkan output encoding sesuai konteks (HTML, atribut, JavaScript, URL) sebagai pertahanan utama, didukung framework yang otomatis melakukan encoding, sanitasi HTML bila isian memang boleh berformat, cookie `HttpOnly`, dan Content Security Policy sebagai lapisan tambahan [S9].

**Beda dengan SQL injection:** SQL injection menyerang server dan database; korbannya data di belakang aplikasi. XSS menyerang pengunjung; korbannya browser orang yang membuka halaman. Keduanya sama-sama berawal dari isian yang tidak dipisahkan dari kode.

### 1.6 CSRF (cross-site request forgery), singkat

Sari menambahkan satu nama yang sering tertukar dengan XSS karena singkatannya mirip.

**Apa itu:** CSRF adalah serangan yang membuat browser korban, yang sedang login ke sebuah situs, mengirim permintaan yang tidak ia maksud ke situs itu, misalnya mengganti alamat email akun atau mengubah paket [S10]. Situs menerima permintaan itu karena browser otomatis menyertakan cookie sesi korban. Di CWE Top 25 2025, CSRF ada di peringkat ketiga (Day 17 bagian 1.3).

**Analogi:** surat kuasa yang ditandatangani tanpa dibaca, terselip di tumpukan dokumen. Bank memprosesnya karena tanda tangannya asli. Batasnya: korban CSRF bahkan tidak "menandatangani" apa pun secara sadar; cukup membuka halaman lain saat sesinya masih aktif.

**Kenapa bisa terjadi:** aplikasi hanya memeriksa cookie sesi untuk tindakan penting, tanpa bukti tambahan bahwa permintaan benar-benar berasal dari halaman aplikasi itu sendiri [S10]. Sesi yang tetap aktif berjam-jam memperbesar peluangnya.

**Tanda di log:** sulit dilihat, karena permintaannya datang dari browser korban yang sah, dengan sesi yang sah. Petunjuknya: perubahan penting (ganti email, ganti password, transaksi) dengan header `Referer` atau `Origin` dari situs lain, atau tanpa melewati halaman formulir lebih dulu, dan keluhan pengguna bahwa pengaturannya berubah sendiri.

**Membedakan dari aktivitas sah:** perubahan sah hampir selalu didahului pembukaan halaman pengaturan di situs yang sama beberapa detik sebelumnya.

**Pencegahan:** token anti-CSRF (nilai acak di setiap formulir yang wajib dikirim kembali, disebut synchronizer token), atribut cookie `SameSite`, dan pemeriksaan header asal permintaan [S10]. OWASP mengingatkan bahwa XSS bisa mengalahkan semua mitigasi CSRF, karena skrip yang berjalan di dalam situs bisa membaca token itu [S10]. Jadi menutup XSS juga bagian dari pencegahan CSRF.

**Beda dengan XSS:** XSS menjalankan kode di halaman situs; CSRF tidak menjalankan kode di situs sasaran, hanya meminjam sesi korban untuk mengirim satu permintaan.

### 1.7 MITM (man-in-the-middle) dan AiTM

Kartu 3 menyangkut jawaban DNS palsu. Sebelum membahas DNS, Sari menjelaskan gagasan yang membuat jawaban palsu itu berbahaya: pihak ketiga yang berdiri di tengah percakapan.

**Apa itu:** MITM adalah serangan di mana pihak lain menempatkan diri di antara dua pihak yang sedang berkomunikasi, sehingga bisa membaca, mengubah, atau meneruskan pesan tanpa disadari keduanya [S12]. MITRE memakai nama yang lebih netral, adversary-in-the-middle (AiTM), sebagai technique T1557, dengan sub-technique antara lain peracunan resolusi nama (.001), ARP cache poisoning (.002), DHCP spoofing (.003), dan evil twin, yaitu titik Wi-Fi palsu yang meniru jaringan asli (.004) [S13]. Halaman phishing AiTM yang meneruskan login ke situs asli (Day 09 bagian 1.11) termasuk keluarga yang sama.

**Analogi:** kurir nakal yang menerima paket dari pengirim, membukanya di jalan, membaca atau mengganti isinya, lalu menyerahkan ke penerima seolah tidak terjadi apa-apa. Batasnya: kurir harus benar-benar memegang paket, sedangkan di jaringan posisi "di tengah" bisa dicapai dari jauh dengan membelokkan alamat, dan bila isinya terenkripsi dengan benar, kurir hanya bisa membaca label luarnya.

**Kenapa bisa terjadi:** protokol lama di jaringan lokal seperti ARP dan DHCP tidak memeriksa siapa yang menjawab (Day 02 bagian 1.5), sehingga jawaban palsu bisa dipercaya. Kelemahan lain: koneksi yang tidak terenkripsi, peringatan sertifikat yang diabaikan pengguna, Wi-Fi publik tanpa perlindungan, dan MFA yang hanya meminta kode sehingga kode itu ikut bisa diteruskan perantara.

**Tanda di log:**
- Satu MAC address mengaku memiliki banyak IP, atau MAC milik gateway tiba-tiba berganti (log switch, NAC, atau alat pemantau ARP).
- Peringatan sertifikat atau kegagalan TLS yang meningkat untuk situs yang biasanya normal.
- Untuk AiTM lewat phishing: login berhasil dari IP perantara, disusul pemakaian sesi yang sama dari IP lain dalam hitungan menit.
- Jawaban DNS untuk domain penting yang menunjuk ke alamat yang tidak biasa (bagian 1.9).

**Contoh di PT JAB:** latar `INC-2026-022` pada Oktober 2026 adalah AiTM lewat halaman phishing: password dan persetujuan MFA staf IT diteruskan ke halaman login asli, dan sesi yang terbentuk dipakai dari VPS di luar negeri. Kartu 3 adalah percobaan menempatkan diri di tengah lewat jalur lain, yaitu DNS.

**Membedakan dari aktivitas sah:** beberapa alat sah juga berdiri di tengah, misalnya `jkt-proxy01` yang membuka HTTPS dengan CA internal yang dipercaya laptop kantor (Day 03 bagian 1.9) atau load balancer. Bedanya, perantara sah tercatat di daftar aset, memakai sertifikat dari CA milik PT JAB, dan dipasang lewat proses perubahan. Perantara yang tidak dikenal, sertifikat dari penerbit asing, atau gateway yang berganti MAC di luar jadwal perlu diperiksa.

**Pencegahan:** enkripsi ujung ke ujung dengan pemeriksaan sertifikat yang benar (TLS, Day 05), HSTS agar browser tidak turun ke HTTP, perlindungan ARP dan DHCP di switch (misalnya DHCP snooping), NAC untuk perangkat yang masuk jaringan (Day 03 bagian 1.13), VPN di jaringan publik, dan MFA yang tahan phishing seperti FIDO2 yang terikat ke alamat situs asli (Day 06 bagian 1.8) [S13].

**Beda dengan session hijacking:** MITM adalah posisi; session hijacking adalah salah satu hasil yang bisa dicapai dari posisi itu (atau dari cara lain). Pelaku MITM bisa saja hanya membaca, tanpa membajak sesi.

### 1.8 Session hijacking

Pertanyaan ketiga Sari menyebut "pencurian sesi". Untuk memahaminya, kamu perlu tahu dulu apa yang diingat sebuah situs setelah kamu login.

**Apa itu:** setelah login berhasil, situs memberi browser sebuah tanda pengenal sesi (session ID), biasanya disimpan dalam cookie, supaya kamu tidak perlu memasukkan password di setiap halaman [S11]. Session hijacking adalah memakai tanda sesi milik orang lain yang sudah login, sehingga pelaku diperlakukan sebagai orang itu tanpa perlu tahu password-nya dan tanpa melewati MFA lagi [S11]. MITRE mencatat pencurian cookie sesi sebagai T1539 Steal Web Session Cookie dan pemakaiannya sebagai T1550.004 Web Session Cookie [S14].

**Analogi:** gelang tanda masuk konser. Penjaga hanya memeriksa gelang di pintu, bukan KTP. Siapa pun yang memakai gelang itu dianggap sudah membayar. Batasnya: gelang fisik hanya satu dan terasa bila dilepas; tanda sesi digital bisa disalin tanpa pemiliknya kehilangan apa pun, dan dua orang bisa memakainya bersamaan.

**Kenapa bisa terjadi:** tanda sesi bisa bocor lewat XSS bila cookie tidak memakai `HttpOnly` (bagian 1.5), lewat koneksi tanpa enkripsi, lewat malware pencuri data di laptop (Day 16), atau lewat halaman AiTM. Kelemahan di sisi aplikasi: sesi yang berlaku sangat lama, session ID yang tidak diganti setelah login, dan tidak ada pemeriksaan ketika sesi yang sama tiba-tiba dipakai dari tempat lain [S11].

**Tanda di log:**
- Session ID yang sama dipakai dari dua IP atau dua negara berbeda dalam waktu berdekatan, atau dari jaringan (ASN) yang berbeda.
- User-agent (jenis browser dan sistem operasi) yang berubah di tengah sesi.
- Aktivitas di sesi yang sudah lewat tanpa login baru, misalnya membuat aturan inbox atau mendaftarkan metode MFA baru.
- Laporan pengguna bahwa ia tidak sedang memakai akun saat aktivitas itu terjadi.

**Contoh di PT JAB:** di `INC-2026-022`, sesi staf IT yang dicuri lewat halaman AiTM dipakai ulang dari VPS lima menit setelah login asli. Rule harian SOC yang mencari session ID dari lebih dari satu ASN baru menangkapnya keesokan pagi. Sejak itu, rule itu dijalankan per jam.

**Membedakan dari aktivitas sah:** satu sesi memang bisa berpindah IP secara sah, misalnya laptop yang berpindah dari Wi-Fi kantor ke tethering HP, atau VPN yang tersambung di tengah sesi. Bedanya: perpindahan sah biasanya ke penyedia internet lokal yang wajar untuk pengguna itu, user-agent tetap sama, dan tidak disertai tindakan yang tidak biasa. Konfirmasi ke pengguna lewat saluran lain (telepon) tetap langkah paling cepat.

**Pencegahan:** cookie dengan atribut `Secure`, `HttpOnly`, dan `SameSite`; session ID baru setiap kali login; batas umur sesi dan logout otomatis saat menganggur; pemeriksaan perubahan IP atau perangkat di tengah sesi; dan kebijakan akses yang mewajibkan perangkat terkelola [S11]. Saat insiden, mencabut sesi (revoke sessions) sama pentingnya dengan mengganti password, karena mengganti password saja tidak membatalkan sesi yang sudah dicuri.

**Beda dengan credential stuffing:** stuffing mencuri cara masuk (password); session hijacking mencuri hasil masuk (sesi). Karena itu MFA menahan stuffing, tetapi tidak menahan sesi yang sudah dicuri setelah MFA lolos.

### 1.9 DNS spoofing dan DNS cache poisoning

Kembali ke Kartu 3: 52.400 jawaban DNS yang tidak cocok dalam 10 menit, semuanya tentang satu domain bank.

**Apa itu:** DNS (sistem yang menerjemahkan nama domain menjadi alamat IP, Day 02 bagian 1.9) bisa dipalsukan. DNS spoofing adalah memberi jawaban DNS palsu kepada penanya, sehingga nama yang benar diarahkan ke alamat milik pelaku. DNS cache poisoning adalah bentuk yang lebih luas dampaknya: jawaban palsu masuk ke cache (ingatan sementara) resolver, lalu dibagikan ke semua orang yang bertanya ke resolver itu sampai masa berlakunya (TTL) habis [S15][S16]. Pada 2008, CERT/CC menerbitkan peringatan VU#800113 bahwa banyak resolver rentan karena terlalu mudah menerima jawaban palsu [S16]. MITRE memasukkan peracunan resolusi nama di bawah T1557.001 [S13].

**Analogi:** operator informasi telepon yang mencatat nomor palsu di buku telepon kantor setelah ditelepon penipu yang mengaku dari bank. Sejak itu semua karyawan yang bertanya nomor bank diberi nomor penipu. Batasnya: operator manusia mungkin curiga pada penelepon; resolver hanya memeriksa beberapa kecocokan teknis, dan bila semuanya cocok ia percaya.

**Kenapa bisa terjadi:** DNS klasik berjalan di atas UDP, yang tidak memeriksa alamat asal (Day 02 bagian 1.7). Resolver menerima jawaban yang cocok dengan pertanyaannya, sehingga jawaban palsu yang kebetulan cocok bisa diterima. RFC 5452 menjelaskan pertahanannya: nomor transaksi (ID) dan port sumber yang acak, sehingga peluang jawaban palsu cocok menjadi sangat kecil [S15]. Resolver lama yang tidak mengacak port, atau tidak memakai DNSSEC (tanda tangan digital pada record DNS, Day 05), lebih rentan.

**Tanda di log:**
- Lonjakan jawaban DNS yang tidak cocok dengan pertanyaan mana pun (ID atau port salah) di resolver atau IDS [S15].
- Jawaban untuk domain penting yang menunjuk ke IP baru, dengan TTL yang tidak biasa.
- Pengguna melaporkan peringatan sertifikat saat membuka situs yang biasanya normal, karena server palsu tidak punya sertifikat sah untuk nama itu.

**Contoh di PT JAB:** Kartu 3 (`SOC-2027-0883`). Minggu 2027-08-22 02:10 sampai 02:20, `jkt-res01` menerima 52.400 jawaban untuk `ibanking.bank-contoh.example` yang tidak cocok dengan pertanyaan apa pun. Semuanya dibuang karena ID dan port tidak cocok, dan cache tetap berisi alamat asli bank. Percobaan ini gagal, tetapi tetap dilaporkan ke tim NOC dan bank terkait (bagian 2.3).

**Membedakan dari aktivitas sah:** jawaban yang terlambat sesekali (misalnya karena jaringan lambat dan pertanyaan sudah dikirim ulang) wajar dan jumlahnya kecil. Puluhan ribu jawaban tidak cocok untuk satu nama dalam beberapa menit tidak wajar. Perubahan IP sah sebuah situs juga terjadi (pindah hosting, CDN); itu dicek dengan membandingkan jawaban dari beberapa resolver publik dan informasi dari pemilik domain.

**Pencegahan:** resolver yang mengacak ID dan port sumber sesuai RFC 5452 [S15], validasi DNSSEC, resolver yang hanya melayani jaringan sendiri (tidak terbuka untuk umum), pemantauan jawaban tidak cocok, dan HTTPS dengan pemeriksaan sertifikat sebagai pengaman terakhir: walaupun DNS dibelokkan, browser menolak server yang tidak punya sertifikat sah untuk nama itu.

**Beda dengan phishing domain mirip:** pada phishing, pengguna diarahkan ke nama yang berbeda (domain mirip, Day 09). Pada DNS spoofing, pengguna mengetik nama yang benar, tetapi jawabannya yang dipalsukan.

### 1.10 Privilege escalation

Kartu 4 memperlihatkan akun `it.helpdesk02` dipakai dari laptop staf Penagihan. Sari bertanya: bagaimana akun staf biasa bisa berakhir dengan hak helpdesk?

**Apa itu:** privilege escalation adalah mendapatkan hak lebih tinggi dari yang seharusnya, misalnya dari user biasa menjadi administrator lokal, atau dari administrator lokal menjadi administrator domain [S17]. MITRE mencatatnya sebagai tactic TA0004, dengan technique seperti T1068 (memanfaatkan kerentanan software untuk menaikkan hak) dan T1078 (memakai akun sah yang hak-nya lebih tinggi) [S17]. Dua arah yang sering disebut: vertikal (naik ke hak lebih tinggi) dan horizontal (berpindah ke akun lain yang setara, misalnya dari satu pelanggan ke pelanggan lain).

**Analogi:** tamu yang masuk gedung dengan kartu tamu, lalu menemukan kunci master yang tertinggal di laci meja resepsionis. Batasnya: kunci master fisik hanya satu; di komputer, hak tinggi bisa didapat dari banyak tempat sekaligus, seperti password yang tersimpan di file, layanan yang salah konfigurasi, atau software yang belum di-patch.

**Kenapa bisa terjadi:** pelanggaran least privilege (hak minimum, Day 01 bagian 1.7): akun bersama dengan hak admin di banyak komputer, password admin yang sama di semua workstation, kredensial yang disimpan di file teks atau skrip, software dengan kerentanan yang belum di-patch (Day 17), dan pengguna sehari-hari yang memakai akun admin.

**Tanda di log:**
- User biasa ditambahkan ke grup administrator lokal atau grup berhak tinggi (Day 07 bagian 2.1 untuk contoh Domain Admins).
- Akun berhak tinggi dipakai dari perangkat yang biasanya tidak memakainya, atau pada jam yang tidak biasa.
- Proses yang tiba-tiba berjalan dengan hak SYSTEM atau administrator dari aplikasi pengguna biasa (alert EDR, Day 06).
- Pemakaian akun bersama tanpa tiket perubahan atau tiket helpdesk yang menyertainya.

**Contoh di PT JAB:** di Kartu 4, akun `it.helpdesk02` adalah akun bersama tim helpdesk yang menjadi admin lokal di semua workstation. Penyelidikan menemukan file `catatan-helpdesk.txt` berisi password akun itu di desktop laptop Bima Ardiansyah (staf Penagihan, `JKT-WS-1152`), tertinggal setelah kunjungan helpdesk dua minggu sebelumnya. Siapa pun yang menguasai laptop Bima otomatis mendapat hak admin di semua workstation. Ini privilege escalation tanpa satu pun exploit: cukup kredensial yang tercecer.

**Membedakan dari aktivitas sah:** helpdesk memang memakai akun admin untuk memasang software atau memperbaiki laptop. Bedanya, pemakaian sah punya tiket, terjadi di jam kerja, dari perangkat helpdesk atau jump host, dan orangnya bisa dikonfirmasi. Pemakaian dari laptop pengguna non-IT pada Minggu malam tidak punya satu pun ciri itu.

**Pencegahan:** least privilege, akun admin terpisah per orang (bukan akun bersama), password admin lokal yang unik per perangkat dan diputar otomatis (misalnya Windows LAPS), PAM untuk akun berhak tinggi (Day 06), patch rutin, dan pemantauan perubahan grup berhak tinggi.

### 1.11 Lateral movement

Kartu 4 juga berisi tiga sambungan RDP antar workstation. Itu bagian kedua cerita: setelah punya hak, pelaku berpindah.

**Apa itu:** lateral movement adalah berpindah dari satu sistem ke sistem lain di dalam jaringan untuk mendekati target, misalnya server berisi data atau akun yang lebih berharga [S18]. MITRE mencatatnya sebagai tactic TA0008, dengan technique seperti T1021 Remote Services, termasuk T1021.001 RDP (Remote Desktop Protocol, protokol Windows untuk memakai komputer lain dari jarak jauh lewat port 3389) [S18]. Pass-the-hash dan pass-the-ticket di Active Directory (Day 07 bagian 1.10) adalah cara memakai kredensial curian untuk berpindah, tanpa perlu tahu password aslinya.

**Analogi:** penyusup yang masuk lewat lobi, lalu berpindah dari satu ruang ke ruang lain memakai kunci yang ia temukan di sepanjang jalan, sampai tiba di ruang arsip. Batasnya: di gedung, satpam bisa melihat orang asing di koridor; di jaringan, perpindahan memakai akun dan protokol yang sah sehingga terlihat seperti pekerjaan admin biasa, kecuali kamu tahu pola normalnya.

**Kenapa bisa terjadi:** jaringan yang datar (semua workstation bisa saling menghubungi), layanan remote seperti RDP atau SMB yang terbuka antar workstation padahal tidak perlu, akun yang sama berlaku di banyak perangkat, dan kredensial yang bisa dicuri dari memori atau file (bagian 1.10).

**Tanda di log:**
- Login jarak jauh (Event 4624 Logon Type 10 untuk RDP, atau type 3 untuk akses jaringan) dari satu workstation ke workstation lain. Workstation pengguna biasa jarang menjadi sumber RDP ke workstation lain.
- Satu akun login ke banyak perangkat dalam waktu singkat (fan-out).
- Koneksi port 3389, 445, atau 5985 di dalam segmen kantor yang sebelumnya tidak pernah ada (log firewall internal atau EDR).
- Urutan: login baru di perangkat B tak lama setelah aktivitas mencurigakan di perangkat A.

**Contoh di PT JAB:** Kartu 4 (`SOC-2027-0884`): Minggu 2027-08-22 23:14 sampai 23:31, `JKT-WS-1152` membuka RDP memakai `it.helpdesk02` ke tiga workstation: `JKT-WS-1154`, `JKT-WS-1156`, dan `JKT-WS-1157`. Workstation terakhir milik Arief Nugraha, Manajer Penjualan Korporat. Dua puluh lima menit kemudian, Kartu 5 berbunyi dari `JKT-WS-1157` (bagian 2.4).

**Membedakan dari aktivitas sah:** RDP sah di PT JAB datang dari `JKT-JUMP01` (jump host admin, `10.20.10.50`) atau dari perangkat tim helpdesk, ke server atau ke laptop yang sedang punya tiket. RDP dari laptop staf Penagihan ke laptop manajer Penjualan, dengan akun bersama, di luar jam kerja, tidak cocok dengan pola itu.

**Pencegahan:** segmentasi (Day 03 bagian 1.11) dan firewall host yang menolak RDP dan SMB antar workstation, akses admin hanya lewat jump host, akun admin per orang dengan MFA, password admin lokal unik (LAPS), dan deteksi login jarak jauh antar workstation.

### 1.12 Exfiltration

Kartu 5: unggahan lebih dari 1 GB dari laptop manajer ke penyimpanan cloud pribadi, tengah malam. Pertanyaan Sari: bagaimana membedakan pencurian data dari unggahan kerja?

**Apa itu:** exfiltration adalah pemindahan data keluar dari organisasi tanpa izin [S19]. MITRE mencatatnya sebagai tactic TA0010, dengan technique seperti T1048 (lewat protokol lain di luar jalur kendali biasa) dan T1567.002 (unggah ke layanan penyimpanan cloud) [S20]. Pelaku sering mengemas data lebih dulu, misalnya dikompres dan diberi password, supaya isinya tidak terbaca oleh alat pemeriksa.

**Analogi:** membawa barang keluar gedung sedikit demi sedikit, atau sekaligus di malam hari. Batasnya: barang fisik yang dibawa keluar hilang dari rak; data yang disalin tetap ada di tempat asalnya, sehingga tidak ada yang merasa kehilangan sampai salinannya muncul di tempat lain.

**Kenapa bisa terjadi:** koneksi keluar ke internet dibiarkan bebas ke mana saja, layanan penyimpanan cloud pribadi tidak dibatasi, tidak ada DLP atau batas volume, dan data sensitif bisa diakses lebih banyak orang daripada yang perlu.

**Tanda di log:**
- Volume keluar (bytes out) dari satu perangkat jauh di atas kebiasaannya, terutama ke tujuan yang jarang dipakai.
- Unggahan ke layanan file sharing pribadi atau domain baru, di jam yang tidak biasa.
- Pembuatan arsip besar (zip atau 7z) tak lama sebelum unggahan (log EDR).
- DNS dengan subdomain panjang dan acak dalam jumlah besar, tanda data diselipkan di query DNS (Day 02 bagian 2.3).

**Contoh di PT JAB:** Kartu 5 (`SOC-2027-0885`) dipicu use case UC-041 "Pengiriman data keluar besar" di `jkt-proxy01`, yang sejak tuning minggu lalu hanya menghitung byte keluar (Day 11 bagian 1.10 membahas kenapa versi lamanya salah). Senin 2027-08-23 pukul 00:01 sampai 00:12, `JKT-WS-1157` mengunggah 1,6 GB ke `192.0.2.224`, layanan penyimpanan cloud pribadi, dari sesi RDP `it.helpdesk02`, bukan dari sesi Arief. L2 on-call mengisolasi laptop itu lewat EDR pukul 00:13.

**Membedakan dari aktivitas sah:** unggahan besar sah juga ada, misalnya bahan presentasi ke layanan cloud resmi perusahaan (OneDrive PT JAB) atau backup yang dijadwalkan. Pertanyaan yang membedakan: tujuannya layanan resmi atau pribadi? Siapa yang login saat itu? Apakah pemilik perangkat mengakui? Apakah jamnya cocok dengan kebiasaan? Untuk Kartu 5, tujuan pribadi, akun yang aktif bukan pemilik, dan jam tengah malam.

**Pencegahan:** egress filtering (hanya mengizinkan koneksi keluar ke tujuan yang perlu), blokir kategori penyimpanan pribadi di proxy, DLP (Day 06), batas volume dengan alert, klasifikasi data dan akses berbasis kebutuhan, serta pemantauan DNS.

### 1.13 Supply chain attack

Kartu 6 tampak paling tenang: satu koneksi keluar yang ditolak. Tetapi Sari menyebutnya kartu paling sulit.

**Apa itu:** supply chain attack adalah menyerang sebuah organisasi lewat pemasoknya: software, layanan, perangkat, atau penyedia jasa yang dipercaya organisasi itu [S21]. Bentuk yang paling dikenal adalah menyusupkan kode jahat ke pembaruan software resmi, sehingga pembaruan itu terpasang di ribuan pelanggan dengan tanda tangan digital yang sah [S22]. MITRE mencatatnya sebagai T1195 Supply Chain Compromise, dengan T1195.002 untuk software [S23]. Panduan CISA dan NIST menyebut kasus SolarWinds Orion pada 2020 sebagai contoh, saat pembaruan resmi yang disusupi terpasang di ribuan organisasi [S22].

**Analogi:** barang pemasok yang sudah disusupi di pabrik sebelum diantar, lengkap dengan segel resmi. Satpam gedung memeriksa segel, segelnya asli, jadi barang diterima. Batasnya: di dunia fisik barang yang disusupi biasanya hanya satu kiriman; satu pembaruan software yang disusupi bisa sampai ke ribuan organisasi dalam satu hari.

**Kenapa bisa terjadi:** organisasi memang harus mempercayai pemasoknya, dan kontrol seperti code signing (tanda tangan digital pembuat software) hanya membuktikan bahwa software berasal dari vendor, bukan bahwa isinya bersih. Kelemahan yang memperbesar dampak: software pihak ketiga diberi hak tinggi dan akses internet bebas, pembaruan dipasang otomatis langsung ke produksi, dan tidak ada daftar komponen software (SBOM, Day 17) [S22].

**Tanda di log:**
- Perilaku baru tak lama setelah pembaruan: proses baru, koneksi ke domain yang belum pernah dihubungi, terutama domain yang baru terdaftar.
- Software tepercaya yang tiba-tiba membaca kredensial atau menjelajah jaringan.
- Peringatan dari vendor, CERT, atau komunitas intel (Day 12) tentang build tertentu.

**Contoh di PT JAB:** Kartu 6 (`SOC-2027-0881`). Sabtu 2027-08-21 pukul 10:03, server staging sistem manajemen jaringan `jkt-nms-stg01` memasang pembaruan resmi dari vendornya. Dua menit kemudian, `jkt-fw01` menolak koneksi keluar dari server itu ke domain yang baru terdaftar sembilan hari sebelumnya, di `192.0.2.227`. Aturan egress server hanya mengizinkan server pembaruan vendor, sehingga koneksi itu tertahan. Bagian 2.5 membahas tindak lanjutnya.

**Membedakan dari aktivitas sah:** pembaruan memang sering menambah fitur yang menghubungi server baru, misalnya telemetri atau lisensi. Cara membedakannya: tanya vendor apakah domain itu milik mereka, cek catatan rilis, bandingkan hash file pembaruan dengan yang diumumkan vendor (Day 05), dan cek apakah pelanggan lain melaporkan hal yang sama.

**Pencegahan:** pasang pembaruan di staging dulu sebelum produksi (seperti yang dilakukan PT JAB), egress filtering untuk server, hak minimum untuk software pihak ketiga, inventaris software dan SBOM, penilaian keamanan vendor, dan pemantauan perilaku setelah setiap pembaruan [S22].

### 1.14 Insider threat

Kartu 7: karyawan yang sudah mengajukan resign membuka 2.870 file share Penjualan Korporat dalam 40 menit, Jumat sore.

**Apa itu:** insider adalah setiap orang yang punya atau pernah punya akses sah ke organisasi: karyawan, kontraktor, vendor, atau mantan karyawan yang aksesnya belum dicabut [S24]. Insider threat adalah risiko bahwa orang itu, sengaja atau tidak, memakai aksesnya sehingga merugikan organisasi [S24][S25]. CISA membagi insider threat menjadi yang disengaja (pencurian data, sabotase), yang tidak disengaja (kelalaian, salah kirim), dan pihak ketiga, serta mengingatkan bahwa sebagian besar kasus berawal dari kelalaian, bukan niat jahat [S24].

**Analogi:** karyawan pemegang kartu akses yang memakai kartunya sendiri untuk membawa pulang dokumen sebelum pindah ke pesaing. Batasnya: di kantor fisik, orang yang membawa kardus keluar terlihat; di jaringan, akses itu sah dan setiap file yang dibuka memang boleh dibuka olehnya, sehingga yang mencurigakan hanya jumlah, waktu, dan tujuannya.

**Kenapa bisa terjadi:** akses yang lebih luas daripada kebutuhan pekerjaan, hak yang tidak dicabut saat orang pindah bagian atau mengajukan resign, tidak adanya baseline perilaku normal per pengguna, dan budaya yang tidak memberi jalur aman untuk melaporkan kekhawatiran.

**Tanda di log:**
- Jumlah file yang dibuka atau disalin jauh di atas kebiasaan orang itu, terutama di luar bidang kerjanya.
- Waktu yang berdekatan dengan peristiwa HR: pengajuan resign, penilaian kinerja buruk, atau mutasi.
- Penyalinan ke USB, email pribadi, atau cloud pribadi (DLP, proxy).
- Akses yang tetap dipakai setelah tanggal kontrak berakhir.

**Contoh di PT JAB:** Kartu 7 (`SOC-2027-0886`) dibuat rule harian yang membandingkan akses file dengan daftar karyawan yang sedang dalam proses keluar dari HR. Jumat 2027-08-20 pukul 15:20 sampai 16:00, akun Benny Siregar (Sales Penjualan Korporat, `JKT-WS-1158`) membuka 2.870 file di share Penjualan Korporat; rata-rata hariannya 60 file. Benny mengajukan resign sepuluh hari sebelumnya.

**Membedakan dari aktivitas sah:** karyawan yang akan keluar sering memang ditugasi menyerahkan atau merapikan pekerjaannya, yang bisa berarti membuka banyak file. Pertanyaan yang membedakan: apakah ada penugasan serah terima dari atasannya? Apakah file yang dibuka miliknya atau milik timnya? Apakah ada penyalinan ke luar? Jawaban itu tidak dicari analyst sendirian: insider threat ditangani bersama HR, atasan, dan Legal sesuai prosedur, tanpa mengonfrontasi orangnya.

**Pencegahan:** least privilege dan peninjauan akses berkala, prosedur offboarding yang mencabut akses tepat waktu, DLP, baseline perilaku per pengguna (UEBA, Day 10), program insider threat lintas fungsi (HR, Legal, Keamanan), dan budaya pelaporan yang aman [S24].

## 2. Contoh nyata

Semua log di bagian ini adalah keluaran ilustrasi untuk organisasi fiktif PT JAB, disederhanakan supaya mudah dibaca. Isi parameter berbahaya sengaja ditulis `<disensor>`.

### 2.1 Kartu 1: membaca ringkasan login VPN `SOC-2027-0880`

Ringkasan ini dibuat Sari dari log `jkt-vpn01` untuk Sabtu 2027-08-21 dini hari, dikelompokkan per sumber.

```
Sumber          Mulai    Selesai  Percobaan  Nama akun  Hasil
192.0.2.221     01:10    01:24    412        412        389 bad-password, 23 unknown-user
192.0.2.222     02:05    02:19    412        412        389 bad-password, 23 unknown-user
192.0.2.228     03:00    03:14    412        412        388 bad-password, 23 unknown-user,
                                                            1 password benar lalu mfa-timeout (dodi.hermawan, 03:09:41)
Total                             1.236      412 nama berbeda (389 ada di AD, 23 tidak ada)

Penguncian akun VPN: 10 gagal dalam 30 menit per akun   -> tidak ada akun yang terkunci
```

**Cara membaca:**
- Setiap gelombang mencoba 412 nama yang sama dengan urutan yang sama, sekali per nama. Itu tanda password spraying, bukan brute force (bagian 1.2).
- Total `bad-password` adalah 389 + 389 + 388 = 1.166, ditambah 69 `unknown-user` (23 nama x 3 gelombang) dan satu `mfa-timeout`, jadi 1.236.
- Setiap akun hanya dicoba tiga kali dalam dua jam, jauh di bawah batas penguncian 10 kali per 30 menit. Itu sebabnya rule per akun diam, dan alert datang dari rule yang menghitung jumlah akun per sumber.
- Satu akun lolos tahap password. Dodi Hermawan (staf Gudang Logistik) memakai password musiman yang ada di daftar password umum. Ia tidak menyetujui notifikasi MFA pukul 03:09 karena sedang tidur, jadi login tidak selesai.

**Tindak lanjut:** password Dodi direset Senin pagi dan sesi VPN-nya dicabut, ketiga IP diblokir di `jkt-vpn01`, dan Sari mengusulkan agar password baru dicek terhadap daftar password bocor dan umum [S4]. Alert ini tidak dijadikan insiden karena tidak ada login yang selesai, tetapi dicatat sebagai true positive.

### 2.2 Kartu 2: log WAF formulir keluhan `SOC-2027-0882`

Potongan log `jkt-waf01` berikut memperlihatkan empat dari 18 kiriman yang ditolak, Sabtu 2027-08-21.

```
time      src_ip         method  uri                              action  status  rule_category        param
14:31:07  192.0.2.223    POST    /keluhan                         block   403     XSS                  isi_keluhan=<disensor>
14:31:19  192.0.2.223    POST    /keluhan                         block   403     XSS                  nama=<disensor>
14:35:42  192.0.2.223    POST    /keluhan                         block   403     SQL injection        no_pelanggan=<disensor>
14:38:10  192.0.2.223    POST    /keluhan                         block   403     XSS                  isi_keluhan=<disensor>

Ringkasan 14:31-14:38: 18 POST, 18 block (14 XSS, 4 SQL injection), 0 diteruskan ke jkt-portal01
User-Agent: sama di semua kiriman (pustaka HTTP otomatis, bukan browser)
```

**Cara membaca:**
- Kategori rule memberi tahu jenis percobaannya: 14 XSS (bagian 1.5) dan 4 SQL injection (bagian 1.4) ke formulir yang sama.
- XSS diarahkan ke kolom yang nanti tampil di dasbor Customer Care (`isi_keluhan`, `nama`), sedangkan SQL injection ke kolom yang dipakai mencari data (`no_pelanggan`). Pelaku menguji dua jalur sekaligus.
- Tidak ada kiriman yang diteruskan, dan user-agent yang sama di semua kiriman menunjukkan alat otomatis.
- Yang perlu dicek berikutnya: apakah ada kiriman dari IP ini sebelum 14:31 yang tidak ditolak (log WAF dengan `action=allow`), dan apakah tim aplikasi sudah memakai output encoding di dasbor back-office. Sari menulis permintaan ke tim aplikasi lewat tiket, karena WAF adalah lapisan tambahan, bukan perbaikan.

### 2.3 Kartu 3: statistik resolver `SOC-2027-0883`

Alert dibuat dari penghitung jawaban tidak cocok di `jkt-res01`, Minggu 2027-08-22.

```
Resolver           : jkt-res01
Jendela            : 02:10:00 - 02:20:00
Domain             : ibanking.bank-contoh.example
Jawaban diterima   : 52.400
  ID transaksi tidak cocok      : 52.392
  Port tujuan tidak cocok       : 8
  Diterima ke cache             : 0
Alamat di jawaban tidak cocok   : 192.0.2.225 (tidak pernah tercatat untuk domain ini)
Isi cache saat dicek 02:25      : ibanking.bank-contoh.example A 192.0.2.226, TTL sisa 2.811 detik
Jawaban dari 3 resolver publik  : 192.0.2.226
```

**Cara membaca:**
- 52.392 + 8 = 52.400 jawaban, dan tidak satu pun diterima. Pengacakan ID dan port sumber membuat jawaban palsu tidak cocok (bagian 1.9) [S15].
- Semua jawaban palsu menunjuk ke `192.0.2.225`, alamat yang tidak pernah tercatat untuk bank itu. Itu tujuan yang diinginkan pelaku.
- Cache masih berisi `192.0.2.226`, sama dengan jawaban resolver publik. Tidak ada karyawan yang diarahkan ke alamat palsu.
- Tindak lanjut: `192.0.2.225` dimasukkan ke daftar blokir proxy, NOC memeriksa apakah resolver pelanggan broadband menerima pola serupa, dan bank diberi tahu lewat kontak keamanan mereka. Kode penutupan: true positive, percobaan gagal.

### 2.4 Kartu 4 dan 5: lini waktu `INC-2027-094`

Lini waktu berikut disusun Rudi Hartanto (L2 on-call malam) dan dibaca ulang bersama Sari Senin pagi. Ini cerita yang menyatukan dua kartu.

```
Tanggal/jam              Sumber      Kejadian                                                     Istilah
2027-08-06 10:20         tiket HD    Toni Wijanarko (helpdesk) memperbaiki printer di JKT-WS-1152;
                                     file catatan-helpdesk.txt berisi password it.helpdesk02
                                     tertinggal di desktop                                        (kelemahan)
2027-08-22 (Mgg) 22:51   EDR         Proses tak dikenal di JKT-WS-1152 membaca catatan-helpdesk.txt  privilege escalation
2027-08-22 23:14         wineventlog RDP it.helpdesk02 dari JKT-WS-1152 ke JKT-WS-1154 (4624 type 10)  lateral movement
2027-08-22 23:16         Splunk      SOC-2027-0884 dibuat, P3, masuk antrean
2027-08-22 23:22         wineventlog RDP ke JKT-WS-1156                                             lateral movement
2027-08-22 23:31         wineventlog RDP ke JKT-WS-1157 (laptop Arief Nugraha)                       lateral movement
2027-08-22 23:40-23:58   EDR         Arsip penjualan-korporat.7z (1,6 GB) dibuat di JKT-WS-1157       persiapan exfiltration
2027-08-23 (Sen) 00:01   proxy       Unggahan ke 192.0.2.224 (penyimpanan cloud pribadi) dimulai      exfiltration
2027-08-23 00:12         Splunk      SOC-2027-0885 (UC-041), P2; unggahan selesai, 1,6 GB
2027-08-23 00:13         EDR         Rudi mengisolasi JKT-WS-1157
2027-08-23 00:25         Splunk      Rudi menautkan 0884 dan 0885 (akun dan host sama)
2027-08-23 00:28         EDR         JKT-WS-1152 diisolasi
2027-08-23 00:30         AD          it.helpdesk02 dinonaktifkan
2027-08-23 00:40         telepon     Dimas menyatakan INC-2027-094, SEV-2
```

**Cara membaca:**
- Urutannya mengikuti pola bagian 1.10 sampai 1.12: kredensial tercecer memberi hak lebih (privilege escalation), RDP antar workstation (lateral movement), lalu arsip dan unggahan (exfiltration).
- `SOC-2027-0884` berbunyi 23:16, tetapi baru dibaca 00:25, setelah `0885` berbunyi. Selisih 1 jam 9 menit itu menjadi bahan evaluasi: RDP antar workstation dengan akun bersama di luar jam kerja seharusnya P2, bukan P3.
- Unggahan sudah selesai saat alert UC-041 muncul, karena rule menghitung per jam. Isolasi menghentikan langkah berikutnya, tetapi data sudah keluar. Penilaian dampak data diserahkan ke DPO (Day 18).
- Cara awal `JKT-WS-1152` dikuasai belum diketahui saat latihan ini dan menjadi tugas L2. Day 19 membahas langkah penanganan insiden selanjutnya.

### 2.5 Kartu 6: tindak lanjut pembaruan vendor `SOC-2027-0881`

Kartu ini tidak berisi data yang keluar, tetapi Sari meminta kamu menuliskan langkahnya karena polanya sering terlewat.

```
Sabtu 2027-08-21
10:03  jkt-nms-stg01 memasang pembaruan vendor (file bertanda tangan sah, sertifikat vendor valid)
10:05  jkt-fw01 deny: jkt-nms-stg01 -> 192.0.2.227:443 (domain terdaftar 9 hari lalu)
10:05-10:35  41 percobaan ulang, semua deny
10:20  SOC-2027-0881 dibuat (koneksi keluar ditolak dari server dengan allowlist ketat)
11:10  NOC (Bambang Hartono) menahan pembaruan yang sama untuk server produksi
11:30  Hash file pembaruan dibandingkan dengan nilai di portal vendor: SAMA
11:45  Tiket dukungan ke vendor: apakah domain itu milik vendor?
Senin 2027-08-23 08:10  Vendor: domain bukan milik mereka; build sedang diselidiki
```

**Cara membaca:**
- Hash yang sama dengan nilai resmi vendor hanya membuktikan file tidak diubah di jalan. Bila build vendor sendiri yang disusupi, hash resmi pun ikut "benar" (bagian 1.13).
- Yang menyelamatkan PT JAB adalah dua kebiasaan: pembaruan dipasang di staging dulu, dan server punya egress allowlist. Tanpa itu, server produksi akan menghubungi domain asing tanpa ada yang tahu.
- Langkah berikutnya diserahkan ke L2 dan NOC: isolasi `jkt-nms-stg01`, kembalikan ke versi sebelumnya, dan pantau peringatan resmi vendor serta CERT.

### 2.6 Kunci latihan Sari

Tabel berikut adalah kunci jawaban Sari untuk tujuh kartu. Bandingkan dengan jawabanmu, terutama kolom kelemahan dan kontrol, karena dua kolom itu yang paling sering terlewat.

| Kartu | Alert | Nama serangan | Kelemahan di pihak PT JAB | Tanda yang membedakan | Satu kontrol |
|---|---|---|---|---|---|
| 1 | `SOC-2027-0880` | Password spraying | Password musiman, penguncian hanya per akun | Satu sumber, 412 akun, sekali per akun per gelombang | Blocklist password umum dan bocor |
| 2 | `SOC-2027-0882` | Percobaan XSS dan SQL injection | Formulir publik dibaca staf internal | Kategori rule WAF, user-agent otomatis | Output encoding dan parameterized query |
| 3 | `SOC-2027-0883` | Percobaan DNS cache poisoning (gagal) | Tidak ada; pengacakan ID dan port bekerja | 52.400 jawaban tidak cocok untuk satu nama | Validasi DNSSEC |
| 4 | `SOC-2027-0884` | Privilege escalation lalu lateral movement | Akun admin bersama, password tercecer | RDP antar workstation, akun bersama, Minggu malam | Akun admin per orang dan LAPS |
| 5 | `SOC-2027-0885` | Exfiltration | Penyimpanan pribadi tidak diblokir | 1,6 GB keluar dari sesi yang bukan milik pemilik laptop | Blokir kategori penyimpanan pribadi |
| 6 | `SOC-2027-0881` | Dugaan supply chain attack | Kepercayaan pada pembaruan bertanda tangan | Koneksi baru tak lama setelah pembaruan | Staging dan egress allowlist |
| 7 | `SOC-2027-0886` | Dugaan insider threat | Akses tidak dipersempit setelah resign diajukan | 2.870 file dalam 40 menit vs rata-rata 60 per hari | Offboarding dan peninjauan akses |

Kartu 4 dan 5 adalah satu cerita (`INC-2027-094`). Kartu 7 tampak terkait karena menyentuh data Penjualan Korporat yang sama dengan Kartu 5, tetapi akunnya berbeda, waktunya dua hari lebih awal, dan tidak ada data yang keluar dari perangkat Benny. Kartu 7 ditangani terpisah lewat jalur HR dan Legal.

## 3. Perbandingan istilah yang sering tertukar

### 3.1 Tiga serangan menebak password

Tabel ini membantu memberi nama yang tepat pada alert login gagal; perhatikan kolom "jumlah akun" dan "akun terkunci", karena dua kolom itu yang paling cepat terlihat di log.

| Aspek | Brute force | Password spraying | Credential stuffing |
|---|---|---|---|
| Yang dicoba | Banyak tebakan | Satu atau sedikit password umum | Pasangan username dan password bocor |
| Jumlah akun | Satu atau sedikit | Banyak | Banyak |
| Percobaan per akun | Banyak | Sedikit (sering sekali per gelombang) | Sedikit (sekali atau dua kali) |
| Akun terkunci | Sering | Jarang | Jarang |
| Kelemahan yang dimanfaatkan | Password lemah, tanpa batas percobaan | Password umum, penguncian per akun | Password dipakai ulang |
| ATT&CK | T1110.001 | T1110.003 | T1110.004 |
| Kontrol utama | Penguncian, MFA | Blocklist password, deteksi per sumber, MFA | MFA, cek password bocor |
| Contoh di Day ini | `SOC-2027-0821` (Day 03) | `SOC-2027-0880` | `SOC-2027-0800` (Day 01) |

### 3.2 Tiga serangan aplikasi web

Ketiganya sering disebut bersama di interview. Kolom "korban langsung" adalah cara tercepat mengingat bedanya.

| Aspek | SQL injection | XSS | CSRF |
|---|---|---|---|
| Yang disalahgunakan | Query ke database | Halaman yang tampil di browser | Sesi login korban |
| Korban langsung | Data di server | Pengunjung atau staf yang membuka halaman | Pengguna yang sedang login |
| Kode berjalan di | Database server | Browser korban | Tidak ada kode di situs sasaran |
| Pertahanan utama | Parameterized query | Output encoding, CSP, `HttpOnly` | Token anti-CSRF, `SameSite` |
| Terlihat di log WAF | Ya, kategori SQL injection | Ya, kategori XSS | Jarang; permintaan tampak sah |

### 3.3 Menyelip di tengah dan setelah di dalam

Tabel terakhir memisahkan istilah yang sering dipakai bergantian. Cari kolom "pertanyaan analyst" untuk tahu apa yang harus dicek pertama.

| Istilah | Inti | Pertanyaan analyst |
|---|---|---|
| MITM / AiTM | Posisi di antara dua pihak | Siapa perantara di jalur ini, dan apakah sah? |
| Session hijacking | Memakai sesi orang lain | Apakah sesi yang sama dipakai dari dua tempat? |
| DNS spoofing / poisoning | Jawaban DNS palsu, di satu penanya atau di cache resolver | Apakah nama penting menunjuk ke IP baru? |
| Privilege escalation | Naik hak | Dari mana hak tinggi ini didapat? |
| Lateral movement | Pindah sistem | Dari perangkat mana ke mana, dengan akun apa? |
| Exfiltration | Data keluar | Berapa banyak, ke mana, dan dari sesi siapa? |
| Supply chain attack | Lewat pemasok tepercaya | Apa yang berubah setelah pembaruan atau layanan pemasok? |
| Insider threat | Lewat akses sah orang dalam | Apakah aksesnya sesuai tugas dan waktunya? |

## 4. Salah paham umum

- **Anggapan:** semua login gagal dalam jumlah besar adalah brute force. **Kenyataannya:** tiga serangan menebak password punya pola berbeda, dan penamaan yang salah membuat kamu mencari akun terkunci padahal spraying sengaja menghindarinya (bagian 3.1).
- **Anggapan:** WAF sudah menolak, jadi kasusnya selesai. **Kenyataannya:** WAF menunjukkan ada yang mencoba; perbaikan sesungguhnya ada di kode aplikasi, dan kiriman yang tidak dikenali WAF bisa lolos (bagian 1.4 dan 2.2).
- **Anggapan:** MFA menghentikan semua serangan akun. **Kenyataannya:** MFA menahan password yang ditebak atau bocor, tetapi tidak menahan sesi yang dicuri setelah MFA lolos, dan MFA berbasis kode bisa diteruskan halaman AiTM (bagian 1.7 dan 1.8).
- **Anggapan:** serangan selalu memakai malware atau exploit. **Kenyataannya:** `INC-2027-094` berjalan dengan password yang tercecer, RDP, dan unggahan web, semuanya alat sah. Yang membedakan hanya konteksnya.
- **Anggapan:** software bertanda tangan resmi pasti aman. **Kenyataannya:** tanda tangan membuktikan asal, bukan isi; supply chain attack memakai jalur resmi itu (bagian 1.13).
- **Anggapan:** insider threat berarti karyawan jahat. **Kenyataannya:** sebagian besar kasus berawal dari kelalaian, dan penanganannya melibatkan HR dan Legal, bukan konfrontasi oleh analyst (bagian 1.14).

## 5. Catatan terkini

Bagian ini mencatat versi kerangka dan daftar yang dirujuk Day ini, karena nama dan nomornya bisa berubah.

- MITRE ATT&CK v20.0 terbit 13 Oktober 2026 [S27]. Sejak v19, tactic Defense Evasion di matriks Enterprise dipecah menjadi Stealth (tetap `TA0005`) dan Defense Impairment (`TA0112`); nomor technique di Day ini (T1110, T1190, T1557, T1539, T1068, T1021, T1048, T1567, T1195) tidak berubah. Tactic Exfiltration kini juga memuat technique baru T1700 AI-Enabled Exfiltration [S20]. Day 14 membahas kerangka ini.
- OWASP Top 10:2025 menurunkan Injection dari urutan ketiga (2021) ke A05, dengan XSS tetap di dalam kategori ini, dan menambah A03 Software Supply Chain Failures, kategori yang berkaitan dengan bagian 1.13 [S6].
- NIST SP 800-63B-4 mewajibkan pengecekan password baru terhadap daftar password umum atau bocor dan membatasi percobaan gagal maksimal 100 kali per akun [S4].
- Di CWE Top 25 2025, XSS berada di peringkat pertama dan CSRF di peringkat ketiga (Day 17 bagian 1.3).

## 6. Cheat sheet

```
BRUTE FORCE          banyak tebakan ke 1 akun; akun terkunci; T1110.001
PASSWORD SPRAYING    1 password umum ke banyak akun, bergelombang; jarang terkunci; T1110.003
CREDENTIAL STUFFING  pasangan bocor dari situs lain; banyak akun, sedikit berhasil; T1110.004
SQL INJECTION        isian jadi bagian query DB; korban = data; parameterized query
XSS                  skrip ikut tampil di halaman; korban = browser pengunjung; output encoding, CSP
CSRF                 browser login dipakai kirim permintaan; token anti-CSRF, SameSite
MITM / AiTM          posisi di tengah; TLS + cek sertifikat, MFA tahan phishing; T1557
SESSION HIJACKING    pakai sesi orang lain; session ID dari 2 IP/ASN; revoke sessions; T1539
DNS SPOOF/POISONING  jawaban DNS palsu / masuk cache; ID+port acak (RFC 5452), DNSSEC
PRIVILEGE ESCALATION naik hak; akun bersama, kredensial tercecer, patch; TA0004
LATERAL MOVEMENT     pindah sistem; RDP antar workstation (4624 type 10); segmentasi; TA0008
EXFILTRATION         data keluar; bytes_out, tujuan pribadi, jam aneh; egress filter, DLP; TA0010
SUPPLY CHAIN         lewat pemasok; perilaku baru setelah update; staging, egress allowlist; T1195
INSIDER THREAT       akses sah disalahgunakan/lalai; volume vs baseline + peristiwa HR; libatkan HR/Legal

Empat pertanyaan per alert: nama serangan? kelemahan kita? tanda beda dari normal? satu kontrol?
```

## 7. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Tidak ada satu pun akun yang terkunci setelah 1.236 login gagal ke VPN, jadi itu bukan serangan password." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Password spraying sengaja mencoba setiap akun hanya sekali per gelombang supaya tidak memicu penguncian per akun. Di `SOC-2027-0880`, setiap akun hanya dicoba tiga kali dalam dua jam, jauh di bawah batas 10 kali per 30 menit, dan satu akun tetap lolos tahap password. Yang menandai serangan adalah jumlah akun berbeda per sumber, bukan akun yang terkunci. Lihat bagian 1.2 dan 2.1.

</details>

**2. Skenario keputusan.** WAF menolak 18 kiriman berlabel XSS dan SQL injection ke formulir keluhan portal, dan tidak ada yang lolos. Langkah mana yang paling tepat?

- A. Tutup alert sebagai false positive karena WAF sudah menolak semuanya.
- B. Catat sebagai true positive yang tertahan, cek apakah ada kiriman dari sumber yang sama yang diizinkan sebelumnya, dan buat tiket ke tim aplikasi untuk memastikan output encoding dan parameterized query.
- C. Matikan formulir keluhan sampai ada audit penuh.

<details><summary>Jawaban</summary>

B. Percobaannya nyata (bukan false positive), jadi A keliru; WAF hanya lapisan tambahan dan bisa dilewati varian yang tidak dikenali, sehingga perbaikan di aplikasi tetap diperlukan. C berlebihan: formulir dipakai pelanggan setiap hari, dan tidak ada bukti ada kiriman yang lolos. Lihat bagian 1.4, 1.5, dan 2.2.

</details>

**3. Pertanyaan jebakan.** "Pengguna sudah memakai MFA dan password-nya sudah kita ganti, jadi akun yang dibajak lewat halaman AiTM sudah aman." Benarkah?

<details><summary>Jawaban</summary>

Belum tentu. Halaman AiTM mencuri sesi yang terbentuk setelah MFA lolos. Mengganti password tidak membatalkan sesi yang sudah dicuri, jadi sesi juga harus dicabut (revoke sessions), lalu metode MFA dan aturan inbox yang mungkin ditambahkan pelaku diperiksa. Lihat bagian 1.7 dan 1.8.

</details>

**4. Skenario keputusan.** Pukul 23:16 Minggu muncul alert P3: akun admin bersama helpdesk membuka RDP dari laptop staf Penagihan ke tiga laptop lain. Apa langkah yang paling tepat?

- A. Biarkan di antrean sampai Senin pagi karena prioritasnya P3 dan akun itu milik helpdesk.
- B. Konfirmasi ke helpdesk on-call apakah ada pekerjaan terjadwal; bila tidak ada, eskalasi segera ke L2 sebagai dugaan lateral movement dan minta penaikan prioritas.
- C. Hapus akun helpdesk itu dari AD supaya tidak bisa dipakai lagi.

<details><summary>Jawaban</summary>

B. RDP antar workstation dengan akun bersama di luar jam kerja dari laptop pengguna non-IT adalah pola lateral movement, dan setiap menit penundaan memberi waktu bagi langkah berikutnya: di `INC-2027-094`, unggahan 1,6 GB terjadi saat alert ini masih menunggu. A keliru karena prioritas alat tidak menggantikan konteks. C keliru karena menghapus akun menghilangkan jejak dan bisa memutus pekerjaan sah; menonaktifkan akun adalah langkah containment yang diputuskan bersama L2. Lihat bagian 1.10, 1.11, dan 2.4.

</details>

**5. Jelaskan ulang.** Jelaskan kepada anggota keluargamu yang bukan orang IT, dalam tiga kalimat, beda brute force, password spraying, dan credential stuffing.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Brute force itu seperti maling yang mencoba ribuan kunci di satu gembok rumahmu. Password spraying itu maling yang membawa satu kunci pasaran dan mencobanya di semua pintu satu kompleks, berharap ada satu rumah yang memakai gembok murahan. Credential stuffing itu maling yang menemukan kunci rumahmu di tempat lain, lalu mencobanya di pintu kantormu karena tahu banyak orang memakai satu kunci untuk semuanya."

Kesalahan yang sering muncul:
- Menyamakan ketiganya sebagai "menebak password", padahal credential stuffing tidak menebak; ia memakai password asli yang bocor.
- Lupa menyebut kenapa bedanya penting: cara mendeteksi dan mencegahnya berbeda.
- Memakai istilah teknis seperti "lockout threshold" yang membuat pendengar awam bingung.

</details>

**6. Pertanyaan jebakan.** "File pembaruan dari vendor punya tanda tangan digital yang sah dan hash-nya sama dengan yang diumumkan vendor, jadi koneksi aneh setelah pembaruan pasti bukan masalah keamanan." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Tanda tangan dan hash yang cocok hanya membuktikan file berasal dari vendor dan tidak diubah di jalan. Bila sistem build vendor sendiri disusupi, file berbahaya tetap bertanda tangan sah dan hash resminya ikut "benar". Perilaku baru setelah pembaruan, seperti koneksi ke domain yang baru terdaftar, harus ditanyakan ke vendor. Lihat bagian 1.13 dan 2.5.

</details>

**7. Interview question (English).** "You see a large outbound upload from a manager's laptop to a personal cloud storage service at midnight. How do you decide whether it is data exfiltration, and what do you do?"

<details><summary>Sample answer</summary>

"I would first check context rather than the volume alone. Who was logged on at that moment, the owner or another account? Is the destination a sanctioned company service or a personal one? Is the timing normal for this user, and was there anything just before it, such as a large archive being created or remote logons from other machines? I would also check whether the user is in an HR process like resignation. If the session is not the owner's, or it follows suspicious remote access, I treat it as likely exfiltration: escalate to L2, isolate the device through EDR to stop further transfer, preserve the proxy and endpoint logs, and identify the account used so it can be disabled. I would not contact the user directly if an insider case is possible; that goes through HR and Legal. Afterwards the questions are what data left, so the DPO can assess notification duties, and which control failed, for example personal storage not being blocked at the proxy."

What makes this answer strong: it separates legitimate uploads from theft using concrete signals (session owner, destination, timing, preceding events), takes a proportionate containment step, preserves evidence, involves the right people for insider and privacy questions, and ends with the control gap rather than stopping at the alert.

</details>

## 8. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | MITRE ATT&CK T1110: Brute Force | https://attack.mitre.org/techniques/T1110/ | primer (basis pengetahuan MITRE) | diakses 2026-10-21 | Tinggi. Definisi, empat sub-technique, mitigasi penguncian dan MFA |
| S2 | MITRE ATT&CK T1110.003: Password Spraying | https://attack.mitre.org/techniques/T1110/003/ | primer (basis pengetahuan MITRE) | diakses 2026-10-21 | Tinggi. Definisi, alasan menghindari penguncian, layanan sasaran |
| S3 | MITRE ATT&CK T1110.004: Credential Stuffing | https://attack.mitre.org/techniques/T1110/004/ | primer (basis pengetahuan MITRE) | diakses 2026-10-21 | Tinggi. Definisi dan dasar pemakaian ulang password |
| S4 | NIST SP 800-63B-4: Authentication and Authenticator Management | https://pages.nist.gov/800-63-4/sp800-63b.html | primer (publikasi NIST) | diakses 2026-10-21 | Tinggi. Batas 100 percobaan gagal, blocklist password umum dan bocor |
| S5 | Microsoft Learn: 4625(F) An account failed to log on | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625 | primer (dokumentasi Microsoft) | diakses 2026-10-21 | Tinggi. Kode Status 0xC000006A, 0xC0000064, 0xC0000234 |
| S6 | OWASP Top 10:2025, A05 Injection | https://top10.owasp.org/2025/A05_2025-Injection/ | primer (OWASP) | diakses 2026-10-22 | Tinggi. Urutan A05, cakupan SQL injection dan XSS, daftar Top 10:2025 |
| S7 | OWASP SQL Injection Prevention Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html | primer (OWASP) | diakses 2026-10-21 | Tinggi. Parameterized query sebagai pertahanan utama, validasi, hak minimum |
| S8 | OWASP Community: Cross Site Scripting (XSS) | https://community.owasp.org/attacks/xss | primer (OWASP) | diakses 2026-10-21 | Tinggi. Definisi dan tiga jenis XSS |
| S9 | OWASP Cross Site Scripting Prevention Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html | primer (OWASP) | diakses 2026-10-21 | Tinggi. Output encoding per konteks, sanitasi, CSP, `HttpOnly` |
| S10 | OWASP Cross-Site Request Forgery Prevention Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html | primer (OWASP) | diakses 2026-10-21 | Tinggi. Token anti-CSRF, `SameSite`, XSS mengalahkan mitigasi CSRF |
| S11 | OWASP Session Management Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html | primer (OWASP) | diakses 2026-10-21 | Tinggi. Atribut cookie, regenerasi session ID, deteksi perubahan di tengah sesi |
| S12 | NIST CSRC Glossary: man-in-the-middle attack | https://csrc.nist.gov/glossary/term/man_in_the_middle_attack | primer (NIST) | diakses 2026-10-21 | Tinggi. Definisi MITM |
| S13 | MITRE ATT&CK T1557: Adversary-in-the-Middle | https://attack.mitre.org/techniques/T1557/ | primer (basis pengetahuan MITRE) | diakses 2026-10-21 | Tinggi. Sub-technique .001 sampai .004, mitigasi |
| S14 | MITRE ATT&CK T1539: Steal Web Session Cookie | https://attack.mitre.org/techniques/T1539/ | primer (basis pengetahuan MITRE) | diakses 2026-10-21 | Tinggi. Pencurian cookie sesi; pemakaiannya di T1550.004 |
| S15 | RFC 5452: Measures for Making DNS More Resilient against Forged Answers | https://www.rfc-editor.org/rfc/rfc5452 | primer (standar IETF) | Januari 2009; diakses 2026-10-21 | Tinggi. Pengacakan ID dan port sumber, pemantauan jawaban tidak cocok |
| S16 | CERT/CC VU#800113: Multiple DNS implementations vulnerable to cache poisoning | https://www.kb.cert.org/vuls/id/800113 | primer (CERT/CC) | 2008, revisi 2014; diakses 2026-10-21 | Tinggi. Latar sejarah cache poisoning |
| S17 | MITRE ATT&CK TA0004: Privilege Escalation (dan T1068) | https://attack.mitre.org/tactics/TA0004/ | primer (basis pengetahuan MITRE) | diakses 2026-10-21 | Tinggi. Definisi tactic dan technique terkait |
| S18 | MITRE ATT&CK TA0008: Lateral Movement (dan T1021.001 RDP) | https://attack.mitre.org/tactics/TA0008/ | primer (basis pengetahuan MITRE) | diakses 2026-10-21 | Tinggi. Definisi tactic, Remote Services |
| S19 | NIST CSRC Glossary: exfiltration | https://csrc.nist.gov/glossary/term/exfiltration | primer (NIST) | diakses 2026-10-21 | Tinggi. Definisi exfiltration |
| S20 | MITRE ATT&CK TA0010: Exfiltration (T1048, T1567.002) | https://attack.mitre.org/tactics/TA0010/ | primer (basis pengetahuan MITRE) | diakses 2026-10-21 | Tinggi. Technique exfiltration, termasuk T1700 di v20.0 |
| S21 | NIST CSRC Glossary: supply chain attack | https://csrc.nist.gov/glossary/term/supply_chain_attack | primer (NIST) | diakses 2026-10-21 | Tinggi. Definisi |
| S22 | CISA dan NIST: Defending Against Software Supply Chain Attacks | https://www.cisa.gov/sites/default/files/publications/defending_against_software_supply_chain_attacks_508.pdf | primer (CISA, NIST) | April 2021; diakses 2026-10-21 | Tinggi. Contoh SolarWinds, rekomendasi pelanggan software |
| S23 | MITRE ATT&CK T1195.002: Compromise Software Supply Chain | https://attack.mitre.org/techniques/T1195/002/ | primer (basis pengetahuan MITRE) | diakses 2026-10-21 | Tinggi. Definisi sub-technique |
| S24 | CISA: Defining Insider Threats | https://www.cisa.gov/topics/physical-security/insider-threat-mitigation/defining-insider-threats | primer (CISA) | diakses 2026-10-21 | Tinggi. Definisi insider, jenis disengaja dan tidak disengaja |
| S25 | NIST CSRC Glossary: insider threat | https://csrc.nist.gov/glossary/term/insider_threat | primer (NIST) | diakses 2026-10-21 | Tinggi. Definisi |
| S26 | MITRE ATT&CK T1190: Exploit Public-Facing Application | https://attack.mitre.org/techniques/T1190/ | primer (basis pengetahuan MITRE) | diakses 2026-10-21 | Tinggi. SQL injection sebagai contoh technique |
| S27 | MITRE ATT&CK: Versions of ATT&CK | https://attack.mitre.org/resources/versions/ | primer (MITRE) | diakses 2026-10-21 | Tinggi. Versi v20.0 dan tanggal rilis |

**Catatan sumber:** pembedaan pola log spraying dan stuffing (bergelombang dengan urutan sama vs satu lintasan acak) adalah ringkasan praktik lapangan, bukan definisi dari MITRE [S2][S3]. Statistik CWE Top 25 dirujuk lewat Day 17. Seluruh log, nama host, orang, alamat, dan lini waktu di bagian 1 dan 2 adalah ilustrasi untuk organisasi fiktif PT JAB, bukan hasil eksekusi nyata.
