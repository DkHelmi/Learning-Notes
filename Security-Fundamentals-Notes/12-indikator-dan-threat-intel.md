---
day: 12
title: 'Indikator dan threat intelligence: IOC, IOA, TTP, Pyramid of Pain, feed, enrichment, dan STIX/TAXII'
researched_on: 2026-10-21
versions_checked: 'NIST CSRC Glossary (indicator, indicator of compromise, TTP, threat intelligence; diakses 2026-10-21); NIST SP 800-150 (Okt 2016); David Bianco, The Pyramid of Pain (Mar 2013, pembaruan Jan 2014); OASIS STIX 2.1 dan TAXII 2.1 (OASIS Standard, 10 Jun 2021); FIRST TLP 2.0 (Agu 2022); CISA TLP dan AIS; MITRE ATT&CK v20.0 (13 Okt 2026); Peraturan BSSN Nomor 10 Tahun 2020'
---

# Day 12: Indikator dan threat intelligence (IOC, IOA, TTP, Pyramid of Pain, feed, enrichment, dan STIX/TAXII)

Cakupan: istilah yang dipakai saat SOC menerima dan memakai informasi tentang penyerang, yaitu IOC (hash, IP, domain, URL), IOA, TTP, Pyramid of Pain, threat intelligence strategic, operational, dan tactical, feed, enrichment dan reputasi, false positive IOC seperti IP CDN, umur IOC, STIX dan TAXII, serta TLP dan komunitas berbagi seperti CSIRT sektor.

## Ide inti

Penyerang meninggalkan jejak, dan organisasi lain yang sudah diserang lebih dulu bisa memberi tahu jejak itu kepada kita. Jejak itu ada dua jenis. Yang pertama adalah benda: alamat IP server penyerang, nama domain situs palsunya, hash file lampirannya, URL halaman login tiruannya. Benda seperti ini disebut IOC (indicator of compromise), dan karena bentuknya pasti, ia mudah dicari di log. Yang kedua adalah kebiasaan: cara penyerang masuk, apa yang ia lakukan setelah masuk, dan urutan langkahnya. Kebiasaan ini disebut TTP (tactics, techniques, and procedures), dan tanda bahwa kebiasaan itu sedang berjalan disebut IOA (indicator of attack).

Gagasan yang mengikat semua istilah Day ini: benda mudah diganti, kebiasaan sulit diganti. Penyerang bisa menyewa IP baru dalam hitungan menit dan mengubah satu byte file supaya hash-nya berubah, tetapi jauh lebih sulit mengubah cara kerjanya. Karena itu IOC berguna untuk menyapu log dengan cepat, tetapi umurnya pendek dan sering salah sasaran; deteksi yang tahan lama dibangun dari perilaku. Threat intelligence, yaitu informasi tentang penyerang yang sudah diolah untuk keputusan, hanya bernilai bila relevan, masih berlaku, dan diperiksa dulu (enrichment) sebelum dipakai.

Bayangkan kompleks perumahan yang menerima buletin dari polisi sektor. Isinya plat nomor mobil komplotan maling dan sidik jari di rumah korban (IOC), ditambah modus komplotan itu: menyamar sebagai petugas PLN, datang siang hari saat penghuni bekerja (TTP). Satpam memakai buletin itu dua cara: mencocokkan plat setiap mobil yang masuk, dan memperhatikan siapa pun yang bertingkah seperti petugas PLN tanpa surat tugas (IOA). Sebelum menahan mobil yang platnya cocok, satpam mengecek plat ke database kendaraan (enrichment), karena plat bisa palsu, sudah dijual, atau milik mobil travel yang dipakai ratusan orang. Batas analogi ini: di internet plat nomor bisa diganti dalam hitungan menit dan gratis, satu "mobil" (IP) bisa dipakai ribuan orang tidak bersalah sekaligus, dan buletin datang dari banyak sumber dengan mutu yang berbeda-beda.

```
  SUMBER INTEL                      SOC PT JAB                                  KEPUTUSAN
  CSIRT sektor, feed komersial,     terima -> saring (relevan? masih berlaku?)
  laporan vendor, temuan sendiri    -> enrichment (siapa pemilik IP, umur domain,
        |                              reputasi, riwayat di log kita)
        |  format STIX,                -> cari di log (IOC: hash, IP, domain, URL)   cocok + konteks kuat -> alert, insiden
        |  dikirim lewat TAXII         -> rule perilaku (IOA, berdasar TTP)          cocok tapi infrastruktur bersama -> false positive
        |  diberi label TLP            -> umur IOC habis: arsipkan                   pola baru -> bagikan balik ke komunitas
        v
  Pyramid of Pain:  hash < IP < domain < artefak jaringan/host < tools < TTP
                    (makin ke atas, makin mahal bagi penyerang untuk mengganti)
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), sebuah ISP (penyedia layanan internet) fiktif dengan sekitar 1.200 karyawan dan sekitar 400 ribu pelanggan internet rumah. SOC (Security Operations Center, tim yang memantau dan menangani kejadian keamanan) PT JAB memakai Splunk Enterprise Security sebagai SIEM (sistem yang mengumpulkan log dan memunculkan alert) dan Microsoft 365 dengan Defender for Office 365 untuk email. Januari 2027 PT JAB pernah kena pencurian sesi yang melewati MFA terhadap seorang engineer NOC (`INC-2027-001`).

Kamu analyst L1 baru di minggu ketiga orientasi. Rabu 2027-08-18 pukul 08:10, SOC menerima buletin dari CSIRT sektor teknologi informasi dan komunikasi berlabel `TLP:AMBER`, berisi kampanye phishing bertema "pembaruan kontrak interkoneksi" yang menyasar ISP di Indonesia. Pukul 08:45 Sari Kusuma (analyst L2, mentormu) memasukkan daftar IOC dari buletin itu ke Splunk. Tujuh menit kemudian alert `SOC-2027-0867` muncul: salah satu IP di buletin cocok dengan 1.284 sambungan dari 211 komputer kantor. Pukul 09:00 Sari mengirim pesan:

> "Jangan panik dulu soal 0867. Hari ini tugasmu memeriksa buletin ini di log kita, sambil memahami bahasanya. Hash, IP, domain, URL di lampiran itu disebut apa? Kenapa ada cerita 'cara kerja kampanye' di bagian akhir? Dwi Cahyono (analyst L1) sejak pagi memegang alert aturan inbox mencurigakan yang mungkin tidak ada hubungannya dengan buletin ini; itu yang disebut IOA. Kalau kita cuma boleh memilih satu jenis untuk rule jangka panjang, pilih yang mana dan kenapa? Buletin seperti ini masuk jenis intel apa, dan laporan kuartalan yang kukirim ke Pak Hendra jenis apa? Feed di Splunk datang dari mana, dan bagaimana masuk otomatis? Gilang Ramadhan (analyst L1) mau langsung memblokir IP 0867; cek dulu milik siapa, aku curiga itu CDN. Ada juga satu IP dari buletin tahun lalu yang masih nyangkut di blocklist firewall; masih pantas di sana? Terakhir, Pak Bambang mau meneruskan buletin ini ke grup WhatsApp engineer NOC antar-ISP. Boleh?"

Pesan itu memuat sembilan pertanyaan:

1. Apa itu IOC, dan jenis apa saja yang ada di buletin (hash, IP, domain, URL)?
2. Apa itu TTP, dan kenapa buletin juga menulis cara kerja kampanye?
3. Apa itu IOA, dan apa bedanya dengan IOC?
4. Bila hanya boleh memilih satu jenis untuk rule jangka panjang, mana yang paling berharga?
5. Buletin ini dan laporan kuartalan ke direktur masuk jenis threat intelligence apa?
6. Dari mana feed datang, dan bagaimana IOC masuk ke Splunk secara otomatis?
7. Bagaimana memeriksa sebuah IP atau domain sebelum bertindak, dan kenapa IP di alert `SOC-2027-0867` dicurigai CDN?
8. Apakah IP dari buletin tahun lalu masih pantas diblokir?
9. Bolehkah buletin berlabel `TLP:AMBER` diteruskan ke grup WhatsApp antar-ISP?

Pertanyaan 1 dijawab di bagian 1.1 dan 1.2, pertanyaan 2 di bagian 1.3, pertanyaan 3 di bagian 1.4, pertanyaan 4 di bagian 1.5, pertanyaan 5 di bagian 1.6, pertanyaan 6 di bagian 1.7 dan 1.11, pertanyaan 7 di bagian 1.8 dan 1.9, pertanyaan 8 di bagian 1.10, dan pertanyaan 9 di bagian 1.12. Bagian 2 membaca buletin itu, membedah `SOC-2027-0867`, menyapu log dengan hash dan domain, lalu mengikuti alert perilaku yang berujung pada insiden `INC-2027-091`.

**Kapan relevan:** setiap kali kamu menerima buletin, advisory, atau laporan intel yang memuat daftar IOC; saat alert berbunyi karena IP, domain, atau hash cocok dengan daftar intel; saat menilai apakah sebuah IP atau domain berbahaya; saat ditanya kenapa SOC tidak cukup memblokir IP; dan saat interview yang menanyakan beda IOC dan IOA, Pyramid of Pain, atau STIX dan TAXII.
**Kapan bukan jawaban:** IOC yang cocok bukan bukti serangan, dan IOC yang tidak cocok bukan bukti aman. Cara memutuskan sebuah alert asli atau palsu secara umum dibahas di Day 11, cara mencari jejak penyerang tanpa menunggu alert dibahas di Day 13, dan katalog TTP yang lengkap (MITRE ATT&CK) dibahas di Day 14. Day ini juga tidak mengajarkan cara mengoperasikan platform intel tertentu.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (hash dan SHA-256 di Day 05, domain dan DNS di Day 02, phishing dan AiTM di Day 09, SIEM, SOAR, dan enrichment otomatis di Day 10) tidak diulang di tabel ini; definisinya diulang satu kalimat di subbagian bila dibutuhkan. Tabel ini memuat istilah utama Day ini; istilah pendukung (observable, defang, TIP, passive DNS, warninglist, sighting) dijelaskan di subbagiannya. Cari kolom ketiga bila sebuah istilah terasa abstrak.

| Istilah | Arti singkat | Padanan sehari-hari |
|---|---|---|
| IOC (indicator of compromise) | Artefak teknis yang menandakan serangan akan, sedang, atau sudah terjadi | Plat nomor mobil maling dan sidik jari yang tercatat |
| TTP | Tactics, techniques, and procedures: perilaku penyerang, dari tujuan umum sampai langkah rinci | Modus operandi komplotan maling |
| IOA (indicator of attack) | Tanda bahwa perilaku serangan sedang berjalan, terlepas dari alat atau alamat yang dipakai | Orang yang bertingkah seperti petugas PLN palsu, mobil apa pun yang ia pakai |
| Pyramid of Pain | Model enam tingkat jenis indikator, diurutkan dari yang paling murah sampai paling mahal diganti penyerang | Makin naik, makin mahal bagi maling untuk mengganti ciri dirinya |
| Threat intelligence | Informasi ancaman yang sudah dikumpulkan, dianalisis, dan diberi konteks untuk mengambil keputusan | Buletin polisi ke satpam kompleks |
| Strategic, operational, tactical | Tingkat intel menurut pembacanya: pimpinan, pengelola respons kampanye tertentu, tim teknis | Laporan tren tahunan polisi, peringatan komplotan minggu ini, daftar ciri dan plat untuk satpam |
| Feed | Aliran IOC yang dikirim berkala dan biasanya otomatis | Daftar plat nomor yang dikirim polisi setiap hari |
| Enrichment | Menambahkan konteks ke IOC atau alert (pemilik, umur, riwayat, reputasi) | Mengecek plat nomor ke database kendaraan |
| Reputasi | Penilaian layanan luar tentang seberapa sering sebuah IP, domain, atau file terlihat jahat | Catatan "pernah terlibat kejahatan" pada plat nomor |
| CDN (content delivery network) | Jaringan server bersama yang melayani banyak situs dari IP yang sama | Mobil travel yang ditumpangi ratusan orang berbeda |
| Umur IOC (indicator aging) | Masa berlaku IOC sebelum dianggap usang | Plat nomor yang sudah dijual ke pemilik baru |
| STIX | Format baku (JSON) untuk menulis informasi ancaman | Formulir laporan polisi yang bentuknya sama di semua kantor |
| TAXII | Protokol di atas HTTPS untuk mengirim dan mengambil data intel | Kotak surat langganan tempat formulir itu diambil |
| TLP (Traffic Light Protocol) | Label warna yang menyatakan sejauh mana informasi boleh dibagikan | Cap "rahasia, hanya untuk kepala satpam" di amplop buletin |
| CSIRT | Computer security incident response team, tim tanggap insiden siber | Pos polisi yang menerima laporan dan menyebar peringatan |
| ISAC | Information sharing and analysis center, wadah berbagi intel antarorganisasi satu sektor | Forum satpam se-kawasan industri |

### 1.1 IOC (indicator of compromise)

Pertanyaan pertama Sari menyangkut isi buletin: daftar hash, IP, domain, dan URL di tabel lampirannya. Semuanya adalah IOC.

**Apa itu:** IOC adalah artefak teknis atau hal yang bisa diamati (observable) yang menandakan serangan akan terjadi, sedang berlangsung, atau sebuah kompromi mungkin sudah terjadi [S1][S2]. "Compromise" berarti sistem sudah dibobol atau dikuasai pihak yang tidak berhak. NIST memberi contoh IOC: alamat IP server C2 (command and control, server tempat penyerang mengendalikan program jahatnya) yang dicurigai, nama domain DNS yang mencurigakan, URL yang menunjuk ke konten jahat, hash file program jahat, dan teks subjek email jahat [S2]. Di percakapan sehari-hari orang sering menyebutnya "indikator" saja.

**Analogi:** plat nomor mobil maling dan sidik jari di rumah korban. Bentuknya pasti, cocok atau tidak cocok, sehingga cepat dicocokkan satpam di gerbang. Batasnya: plat bisa diganti malam itu juga, mobil yang sama bisa dipinjam orang baik keesokan harinya, dan plat bisa tertulis keliru di buletin.

**Cara kerja:** IOC dipakai dengan dua arah waktu. NIST menyebut organisasi memakai indikator untuk menambah atau mengubah rule di firewall, IDS, dan alat lain supaya memblokir atau memberi alert pada aktivitas yang cocok, dan untuk menyapu log sebagai kunci pencarian guna menemukan sistem yang mungkin sudah dibobol [S2].

```
  ke depan (mulai sekarang)                ke belakang (sudah terjadi?)
  IOC dimasukkan ke SIEM, proxy,           IOC dicari di log 30-90 hari terakhir:
  firewall, EDR, filter email              DNS, proxy, firewall, email, EDR
        |                                          |
  cocok -> alert atau blokir               cocok -> cari host dan akun yang terlibat
```

Kata "compromise" di nama IOC sering menyesatkan. IOC yang cocok di log tidak berarti kompromi sudah terjadi; artinya hanya "sesuatu di lingkunganmu pernah bersentuhan dengan benda yang dikaitkan dengan penyerang". Bersentuhan bisa berarti email jahat ditolak filter, komputer membuka domain jahat tetapi tidak mengetik apa pun, atau IP yang cocok ternyata milik layanan bersama (bagian 1.9). Kompromi baru terbukti setelah konteks diperiksa.

NIST juga memberi lima ciri IOC yang baik: tepat waktu (timely), relevan untuk lingkungan penerima, akurat, spesifik sehingga sedikit false positive, dan bisa ditindaklanjuti (actionable) karena datang dengan konteks yang cukup [S2].

**Contoh di PT JAB:** buletin CSIRT sektor memuat 9 IOC: satu hash SHA-256 lampiran HTML, dua domain, dua URL, tiga IP, dan satu subjek email. Sari memasukkan semuanya ke Splunk sebagai daftar intel dan menyiapkan pencarian ke belakang 30 hari, karena buletin menyebut kampanye aktif sejak 2027-08-02. Satu IP langsung cocok dalam jumlah besar (`SOC-2027-0867`), dan itu yang pertama kali dicurigai Sari sebagai salah sasaran.

**Beda dengan observable:** observable adalah apa pun yang bisa diamati, misalnya setiap IP di log firewall. Observable menjadi IOC ketika ada yang menilainya berkaitan dengan aktivitas jahat.

**Salah paham umum:**
- "Tidak ada IOC yang cocok, berarti kita tidak diserang." Penyerang yang menyasar satu organisasi sering memakai infrastruktur baru yang belum ada di buletin mana pun. Ketiadaan kecocokan hanya berarti penyerang tidak memakai benda yang sama dengan yang sudah dilaporkan.

### 1.2 Jenis IOC: hash, IP, domain, URL, dan artefak lain

Buletin pagi itu memuat empat jenis IOC utama ditambah satu subjek email. Pertanyaan pertama Sari juga meminta kamu membedakan jenis-jenis itu, karena setiap jenis dicari di log yang berbeda dan punya kelemahan yang berbeda.

**Apa itu:** jenis IOC dibedakan dari benda yang diwakilinya. Hash mewakili satu file persis. IP mewakili satu alamat di jaringan. Domain mewakili nama yang didaftarkan penyerang. URL mewakili satu alamat halaman lengkap di sebuah domain. Di luar keempat jenis itu ada artefak lain seperti subjek email, alamat pengirim, nama file, user agent (identitas program yang dikirim di permintaan web), kunci registry, atau nama mutex (penanda unik yang dipakai program jahat supaya tidak berjalan dua kali) [S2][S3].

**Analogi:** hash seperti sidik jari satu barang bukti, IP seperti plat nomor mobil, domain seperti nama usaha palsu yang didaftarkan komplotan, dan URL seperti alamat lengkap sampai nomor ruangan di gedung milik usaha itu. Batasnya: di internet, plat nomor bisa disewa per jam, dan satu gedung (IP) bisa menampung ribuan usaha yang berbeda.

**Cara kerja:** tabel berikut merangkum setiap jenis dengan tempat mencarinya dan kelemahan utamanya; cari kolom "Kelemahan" sebelum memutuskan memblokir.

| Jenis | Contoh bentuk | Dicari di log | Kelemahan utama |
|---|---|---|---|
| Hash file | SHA-256 64 karakter heksadesimal | EDR, filter email, antivirus | Satu byte berubah, hash berubah total (Day 05 bagian 1.2) |
| IP | `192.0.2.190` | Firewall, proxy, VPN, sign-in log | Mudah diganti; sering dipakai bersama (CDN, hosting, VPN publik) |
| Domain | `isp-peering-portal.example` | DNS resolver, proxy, email | Domain baru murah; domain sah bisa dibobol dan dipakai |
| URL | `hxxps://isp-peering-portal[.]example/kontrak/login` | Proxy (bila HTTPS dibuka), email, browser | Path mudah diubah; di HTTPS tanpa dekripsi hanya domain yang terlihat |
| Subjek email, pengirim | "Pembaruan Kontrak Interkoneksi 2027" | Log email | Mudah diubah; subjek umum bisa mengenai email sah |

Hash yang dipakai sebaiknya SHA-256. MD5 dan SHA-1 masih muncul di laporan lama, tetapi untuk keputusan seperti blokir dan allowlist SHA-256 yang dipakai, alasannya dijelaskan di Day 05 bagian 1.2.

URL dan IP di buletin biasanya ditulis dalam bentuk defang: `https` ditulis `hxxps`, titik ditulis `[.]`. Tujuannya supaya tautan tidak bisa diklik tanpa sengaja dan tidak diubah otomatis menjadi tautan aktif oleh aplikasi email atau chat. Saat memasukkan IOC ke alat pencarian, bentuk defang dikembalikan ke bentuk asli; saat menulis tiket, laporan, atau pesan chat, pakai bentuk defang.

Domain paling andal dicari di log resolver DNS, karena hampir setiap sambungan diawali pertanyaan DNS (Day 02 bagian 1.9); URL lengkap hanya terlihat bila HTTPS dibuka, karena di jaringan biasa hanya nama domain dari SNI yang terlihat (Day 02 bagian 1.10).

**Contoh di PT JAB:** `jkt-proxy01` membuka HTTPS hanya untuk domain baru atau yang belum dikategorikan. Domain kampanye ini baru didaftarkan, jadi path `/kontrak/login` tercatat lengkap di log proxy. Untuk domain lama yang sudah dikategorikan, proxy hanya mencatat nama domain dan IP; URL IOC untuk domain seperti itu harus dicari di log endpoint.

**Beda IOC dengan signature IDS:** signature (Day 03) adalah pola isi paket, misalnya teks khas SQL injection, sehingga bisa mengenali penyerang baru yang memakai pola sama; IOC adalah nilai tunggal yang hanya mengenali benda yang sudah pernah dilaporkan.

**Salah paham umum:**
- "Kalau sudah blokir domain, URL-nya tidak perlu dicari." Blokir mencegah kunjungan baru. Pertanyaan yang lebih penting adalah siapa yang sudah berkunjung sebelum blokir dipasang, dan itu hanya terjawab dengan menyapu log ke belakang.

### 1.3 TTP (tactics, techniques, and procedures)

Pertanyaan kedua Sari menyangkut bagian akhir buletin yang tidak berbentuk daftar: paragraf "cara kerja kampanye". Bagian itu adalah TTP.

**Apa itu:** TTP adalah perilaku penyerang [S1]. Tactic adalah gambaran perilaku paling umum, yaitu tujuan yang ingin dicapai (misalnya masuk pertama kali ke jaringan). Technique adalah gambaran lebih rinci tentang cara mencapai tactic itu (misalnya phishing dengan tautan). Procedure adalah gambaran paling rinci tentang cara satu penyerang tertentu menjalankan technique itu (misalnya email bertema kontrak interkoneksi berisi lampiran HTML yang membuka halaman login palsu) [S1][S2]. NIST menyebut TTP bisa menggambarkan kecenderungan penyerang memakai varian malware tertentu, urutan langkah, alat, cara pengiriman, atau exploit [S2].

**Analogi:** modus operandi komplotan maling. Tactic: masuk ke rumah. Technique: menyamar sebagai petugas. Procedure: komplotan ini memakai seragam PLN, datang hari kerja pukul 10 sampai 14, membawa surat tugas palsu dengan kop yang sedikit miring, lalu membuka gembok dengan kunci T. Batasnya: modus maling bisa diamati satpam secara langsung, sedangkan TTP penyerang siber harus disimpulkan dari log yang tersebar di banyak sistem, dan sebagian langkahnya tidak tercatat di mana pun.

**Cara kerja:** cara paling umum menulis TTP adalah memetakannya ke MITRE ATT&CK, katalog publik tactic dan technique penyerang yang memberi setiap technique nomor tetap. Technique phishing, misalnya, bernomor T1566 di tactic Initial Access, dengan sub-technique T1566.002 untuk tautan [S9]. Pembahasan ATT&CK lengkap ada di Day 14; untuk Day ini cukup dipahami bahwa nomor seperti itu memungkinkan dua organisasi membicarakan perilaku yang sama tanpa salah paham.

Tabel berikut memetakan cara kerja kampanye di buletin ke tiga tingkat TTP; cari kolom Procedure untuk melihat bagian yang spesifik untuk kampanye ini.

| Tingkat | Isi di buletin | Nomor ATT&CK (bila ada) |
|---|---|---|
| Tactic | Initial Access, lalu Credential Access, lalu Stealth (menyembunyikan jejak) | TA0001, TA0006, TA0005 |
| Technique | Phishing dengan tautan; mencuri session cookie; membuat aturan inbox untuk menyembunyikan email | T1566.002, T1539, T1564.008 |
| Procedure | Email "Pembaruan Kontrak Interkoneksi 2027" dengan lampiran HTML yang membuka halaman AiTM tiruan login Microsoft 365; dalam satu jam setelah login, penyerang membuat aturan inbox bernama satu titik yang memindahkan email berisi "kontrak" atau "keamanan" ke folder RSS Feeds | (tidak bernomor; spesifik kampanye) |

AiTM (adversary-in-the-middle) adalah halaman phishing yang meneruskan login korban ke situs asli, sehingga MFA benar-benar terjadi, lalu menyalin session cookie (tiket bukti sudah login) untuk dipakai penyerang; mekanismenya dijelaskan di Day 09 bagian 1.11 [S9]. Aturan inbox yang menyembunyikan email tercatat sebagai technique tersendiri di ATT&CK, T1564.008 Email Hiding Rules [S9].

**Contoh di PT JAB:** procedure di atas tidak memuat satu pun IP atau hash, tetapi justru bagian ini yang bisa diubah menjadi rule deteksi tahan lama: "aturan inbox baru yang memindahkan email ke folder yang jarang dipakai, dibuat dari IP yang belum pernah dipakai akun itu". Rule semacam itu sudah ada di Splunk PT JAB sejak `INC-2027-001`, dan rule itu yang membunyikan alert yang dipegang Dwi pagi itu (bagian 2.4).

**Beda dengan IOC:** IOC menjawab "benda apa yang dipakai penyerang", TTP menjawab "apa yang dilakukan penyerang dan bagaimana". Satu TTP bisa dijalankan dengan ribuan IOC yang berbeda.

### 1.4 IOA (indicator of attack)

Pertanyaan ketiga Sari menyangkut alert yang dipegang Dwi: aturan inbox mencurigakan di mailbox seorang engineer NOC, yang muncul pukul 08:33, sebelum buletin dimasukkan ke Splunk. Alert itu tidak berasal dari IOC mana pun.

**Apa itu:** IOA adalah tanda bahwa sebuah serangan sedang berlangsung, dilihat dari perilakunya, bukan dari benda yang dipakai. Istilah ini dipopulerkan vendor keamanan, terutama CrowdStrike, yang menggambarkan IOA sebagai aktif sifatnya dan berfokus mengenali serangan yang sedang berjalan, sedangkan IOC dianggap reaktif karena biasanya menandakan kompromi yang sudah terjadi [S10]. CrowdStrike juga menekankan bahwa IOA berfokus pada niat penyerang, terlepas dari malware atau exploit yang dipakai [S10]. IOA tidak punya definisi resmi di glosarium NIST; dalam praktik, IOA adalah wujud TTP yang bisa dideteksi di log.

**Analogi:** satpam yang tidak lagi hanya mencocokkan plat nomor, tetapi juga memperhatikan orang berseragam PLN yang datang tanpa surat tugas dan langsung menuju meteran rumah yang penghuninya sedang bekerja. Mobil apa pun yang ia pakai, tingkahnya mencurigakan. Batasnya: petugas PLN asli kadang juga lupa membawa surat tugas. Deteksi perilaku juga punya false positive, dan biasanya lebih banyak daripada IOC yang spesifik.

**Cara kerja:** IOA dibangun dengan bertanya "langkah apa yang harus dilakukan penyerang dengan modus ini, apa pun alatnya?". Pada kampanye di buletin, penyerang harus memakai session cookie curian dari tempat lain (login dari IP baru tanpa MFA baru), lalu menyembunyikan email dari korban (aturan inbox baru). Keduanya bisa dicari tanpa tahu satu pun IP penyerang.

```
  IOC: "IP 192.0.2.190 ada di log?"          cocok hanya bila penyerang memakai IP yang sama
  IOA: "akun login dari IP baru dengan        cocok untuk penyerang mana pun yang memakai modus ini,
        sesi tanpa MFA baru, lalu membuat      termasuk yang belum pernah dilaporkan
        aturan inbox yang menyembunyikan
        email, dalam 1 jam?"
```

**Contoh di PT JAB:** alert Dwi (`SOC-2027-0870`) berbunyi karena akun `yudi.santoso@jab.example` (engineer NOC) membuat aturan inbox bernama "." dari IP `192.0.2.194`. IP itu tidak ada di buletin. Seandainya SOC hanya mengandalkan IOC, aktivitas ini baru ketahuan setelah CSIRT sektor menerbitkan buletin berikutnya, bila pernah. Hubungan alert ini dengan buletin baru terlihat ketika penyapuan domain menemukan bahwa komputer Yudi membuka domain kampanye 30 menit sebelumnya (bagian 2.3 dan 2.4).

**Beda dengan IOC:** tabel lengkap ada di bagian 3.1. Ringkasnya, IOC adalah benda dan biasanya ditemukan saat atau sesudah kejadian; IOA adalah perilaku dan bisa ditemukan saat serangan masih berlangsung, tetapi butuh pemahaman yang lebih dalam tentang apa yang normal di lingkunganmu.

**Salah paham umum:**
- "IOA adalah jenis produk atau fitur vendor tertentu." Nama IOA memang dipopulerkan vendor, tetapi gagasannya umum: deteksi berbasis perilaku. Rule SIEM, rule EDR, dan analitik yang ditulis dari TTP semuanya berada di sisi IOA.

### 1.5 Pyramid of Pain

Pertanyaan keempat Sari meminta pilihan: bila hanya satu jenis indikator yang boleh dijadikan rule jangka panjang, pilih yang mana. Jawabannya dijelaskan oleh satu gambar yang terkenal di dunia threat intelligence.

**Apa itu:** Pyramid of Pain adalah model yang diterbitkan David Bianco pada Maret 2013, yang mengurutkan enam jenis indikator berdasarkan seberapa besar "rasa sakit" yang dialami penyerang bila defender mendeteksi dan menolak indikator jenis itu [S3]. Dari bawah ke atas: hash, IP, domain, artefak jaringan dan host, tools, dan TTP [S3]. Pada versi awal hash dan IP belum dipisah; pemisahan tingkat hash ditambahkan dalam pembaruan Januari 2014 [S3].

**Analogi:** makin naik, makin mahal bagi maling untuk mengganti ciri dirinya. Mengganti plat nomor itu murah. Mengganti mobil lebih mahal. Mengganti alat pembuka gembok berarti membeli dan berlatih dengan alat baru. Mengganti seluruh modus (berhenti menyamar sebagai petugas, mencari cara lain masuk rumah) berarti belajar ulang dari awal, dan sebagian komplotan memilih pindah ke kompleks lain. Batasnya: makin tinggi tingkatnya, makin sulit pula bagi satpam untuk mendeteksi; mencocokkan plat bisa dilakukan mesin, mengenali modus butuh satpam yang berpengalaman.

**Cara kerja:** tabel berikut merangkum enam tingkat; label rasa sakit di kolom kedua adalah label pada gambar piramida asli, dan kolom ketiga adalah alasan menurut tulisan aslinya [S3].

| Tingkat (bawah ke atas) | Label pada gambar | Kenapa sakit atau tidak sakit bagi penyerang | Contoh di buletin PT JAB |
|---|---|---|---|
| Hash | Trivial | Sangat akurat, tetapi mengubah satu bit file menghasilkan hash baru | SHA-256 lampiran `Kontrak_Interkoneksi_2027.html` |
| IP address | Easy | Paling mudah diganti, apalagi bila memakai proxy anonim seperti Tor | `192.0.2.190`, `192.0.2.193`, `192.0.2.197` |
| Domain | Simple | Sedikit lebih sulit karena harus didaftarkan dan di-hosting, tetapi penyedia murah atau gratis membuatnya tetap mudah | `isp-peering-portal.example`, `peering-docs.example` |
| Artefak jaringan dan host | Annoying | Ciri khas seperti user agent atau kunci registry memaksa penyerang mencari tahu bagaimana ia ketahuan lalu memperbaiki alatnya | Path `/kontrak/login`, lampiran HTML dengan judul halaman "Portal Kontrak Interkoneksi", aturan inbox bernama "." |
| Tools | Challenging | Penyerang harus mencari, membuat, atau mempelajari alat pengganti | Kit phishing AiTM yang dipakai kampanye |
| TTP | Tough! | Penyerang harus mempelajari perilaku baru atau menyerah | Pencurian sesi lewat AiTM lalu aturan inbox penyembunyi email |

Piramida ini punya dua sisi. Bagi penyerang, makin tinggi makin mahal diganti. Bagi defender, makin tinggi makin sulit dideteksi dan makin perlu pemahaman, tetapi makin lama deteksinya bertahan. Bianco juga mencatat bahwa memblokir satu IP sering hampir tidak berdampak bagi penyerang [S3].

**Contoh di PT JAB:** jawaban untuk pertanyaan Sari: untuk rule jangka panjang, pilih tingkat TTP (perilaku pencurian sesi lalu aturan inbox), didukung artefak (aturan inbox bernama satu karakter, lampiran HTML yang membuka halaman login). Hash, IP, dan domain tetap dipakai, tetapi dengan masa berlaku pendek (bagian 1.10) dan terutama untuk menyapu log ke belakang. Usulan Sari untuk laporan sore: tambah satu rule yang memberi alert bila lampiran HTML dari pengirim luar dibuka lalu browser mengirim `POST` ke domain berumur kurang dari 30 hari.

**Beda dengan "nilai" indikator:** piramida tidak mengatakan hash atau IP tidak berguna. Hash yang cocok adalah bukti yang sangat kuat bahwa file yang sama persis ada di komputermu. Piramida hanya mengatakan bahwa mengandalkan tingkat bawah saja membuat defender selalu tertinggal satu langkah.

**Salah paham umum:**
- "Puncak piramida berarti TTP selalu bisa dideteksi dengan satu rule." TTP biasanya hanya terlihat sebagai gabungan beberapa kejadian dari beberapa sumber log, dan rule perilaku butuh tuning terus-menerus supaya tidak membanjiri antrean.

### 1.6 Threat intelligence: strategic, operational, dan tactical

Pertanyaan kelima Sari membandingkan dua dokumen: buletin CSIRT sektor pagi ini dan laporan kuartalan yang ia kirim ke Hendra Wijaya (Direktur Teknologi). Keduanya threat intelligence, tetapi untuk pembaca dan keputusan yang berbeda.

**Apa itu:** threat intelligence adalah informasi ancaman yang sudah dikumpulkan, diolah, dianalisis, ditafsirkan, atau diperkaya sehingga memberi konteks yang dibutuhkan untuk mengambil keputusan [S1][S2]. Kata kuncinya "untuk mengambil keputusan": daftar 10.000 IP tanpa keterangan adalah data, belum intelligence. Threat intelligence umumnya dibagi menurut pembacanya [S11][S12]:

- **Strategic:** untuk pimpinan dan pengambil keputusan bisnis. Isinya tren, motif, sasaran, dan risiko bisnis dalam jangka panjang, ditulis sebagai laporan naratif tanpa detail teknis [S12].
- **Operational:** tentang kampanye atau serangan tertentu: siapa pelakunya, sasarannya siapa, bagaimana dan kapan. Pembacanya manajer keamanan dan pimpinan tim respons [S12].
- **Tactical:** untuk tim teknis (analyst, engineer, incident responder). Isinya cara penyerang beroperasi dan apa yang bisa langsung dipakai untuk deteksi dan pencegahan [S11][S12].

**Analogi:** buletin polisi ke satpam kompleks punya tiga versi. Laporan tahunan polisi ke ketua RW tentang tren kejahatan di kota dan anggaran keamanan yang disarankan adalah strategic. Peringatan "komplotan yang menyamar petugas PLN sedang beroperasi di kecamatan ini minggu ini, menyasar rumah yang kosong siang hari" adalah operational. Lembar untuk satpam berisi ciri seragam, contoh surat tugas palsu, dan daftar plat mobilnya adalah tactical. Batasnya: di dunia siber satu dokumen sering memuat ketiganya sekaligus, dan intel siber datang jauh lebih banyak dan lebih cepat basi daripada buletin polisi.

**Cara kerja:** pembagian ini tidak seragam antar sumber, dan kamu akan menemui dua versi. Versi yang dipakai MWR InfoSecurity bersama CPNI dan CERT-UK (Inggris) membagi empat: strategic, operational, tactical (berisi TTP), dan technical (berisi IOC seperti hash, IP, domain, dan subjek email, biasanya dikonsumsi otomatis oleh alat dan paling cepat basi) [S12]. Versi yang dipakai banyak vendor membagi tiga: strategic, operational (berisi siapa, kenapa, dan TTP), dan tactical (berisi IOC yang bisa dibaca mesin dan berumur pendek) [S11]. Jadi IOC bisa disebut "technical" atau "tactical", dan TTP bisa disebut "tactical" atau "operational", bergantung sumbernya. Yang stabil adalah gagasannya: makin ke arah strategic, makin untuk manusia, makin jangka panjang, dan makin sedikit detail teknis.

Tabel berikut memetakan dokumen yang beredar di PT JAB ke tiga tingkat; cari kolom "Keputusan yang dihasilkan" untuk melihat kenapa pembedaan ini penting.

| Tingkat | Contoh di PT JAB | Pembaca | Keputusan yang dihasilkan |
|---|---|---|---|
| Strategic | Laporan kuartalan Sari: kampanye pencurian sesi menyasar engineer jaringan di sektor telekomunikasi meningkat sepanjang 2027 | Hendra Wijaya, Nina Kartika | Anggaran kunci FIDO2 untuk semua engineer NOC; prioritas risiko kuartal berikutnya |
| Operational | Buletin CSIRT sektor: kampanye "kontrak interkoneksi" aktif sejak 2027-08-02, menyasar ISP, bertujuan mengambil alih mailbox engineer | Dimas Prasetyo (SOC lead), Bambang Hartono (Manajer NOC) | Peringatan khusus ke tim NOC hari ini; penyapuan log 30 hari |
| Tactical | Bagian TTP dan daftar 9 IOC di lampiran buletin | Analyst SOC | Rule deteksi, daftar intel di Splunk, blokir sementara di proxy dan resolver |

**Contoh di PT JAB:** buletin pagi itu memuat dua tingkat sekaligus: paragraf pembukanya operational, lampirannya tactical. Laporan kuartalan Sari tidak memuat satu IP pun, tetapi keputusan anggarannya membuat seluruh kampanye sejenis jauh lebih sulit berhasil.

**Beda dengan threat information:** NIST memakai "threat information" untuk informasi ancaman apa pun, termasuk IOC mentah, dan "threat intelligence" untuk informasi yang sudah diolah dan diberi konteks [S2]. Feed berisi IP tanpa keterangan adalah threat information; buletin yang menjelaskan kampanye dan memberi tingkat keyakinan sudah threat intelligence.

**Salah paham umum:**
- "Threat intelligence adalah langganan feed." Feed hanya bahan mentah tingkat paling teknis. Intel yang paling berdampak bagi organisasi sering justru yang strategic, yang tidak bisa dimasukkan ke SIEM sama sekali.

### 1.7 Feed threat intelligence dan TIP

Pertanyaan keenam Sari menyangkut bagaimana IOC bisa masuk ke Splunk dan memicu `SOC-2027-0867` hanya tujuh menit setelah dimasukkan.

**Apa itu:** feed adalah aliran IOC yang dikirim berkala, biasanya otomatis dan dalam format yang bisa dibaca mesin. NIST menyebut tiga sumber umum indikator: repositori open source, feed komersial, dan mitra luar seperti komunitas berbagi [S2]. Organisasi juga menghasilkan IOC sendiri dari insiden yang ditanganinya. TIP (threat intelligence platform) adalah sistem yang mengumpulkan IOC dari banyak feed, membuang duplikat, memberi label sumber dan tingkat keyakinan, mencatat masa berlaku, lalu menyalurkannya ke SIEM, firewall, proxy, dan EDR. NIST menyebut catatan yang sebaiknya disimpan untuk setiap indikator: sumbernya, aturan pemakaian dan pembagiannya, waktu dikumpulkan, lamanya masih dianggap berlaku, sektor yang disasar, serta aktor dan TTP terkait [S2].

**Analogi:** daftar plat nomor yang dikirim polisi setiap hari ke pos satpam, ditambah map arsip di pos yang menyusun semua buletin itu, mencoret plat yang sudah kedaluwarsa, dan mencatat dari kantor polisi mana setiap plat berasal. Batasnya: feed siber bisa memuat ratusan ribu baris per hari, dan sebagian besar tidak relevan untuk organisasimu.

**Cara kerja:** alur di PT JAB, dari sumber sampai alert:

```
  sumber                           saring dan simpan                 dipakai
  CSIRT sektor (email, PDF)  --+                                     Splunk: cocokkan dengan log DNS,
  feed komersial (TAXII 2.1) --+--> daftar intel di Splunk     -->   proxy, firewall, email, EDR
  feed open source (CSV)     --+    (sumber, keyakinan, tanggal,     jkt-proxy01 dan jkt-res01: blokir
  temuan insiden sendiri     --+     masa berlaku, TLP)              domain (ke sinkhole jkt-sink01)
                                                                     jkt-fw01: blokir IP (hati-hati, 1.9)
```

NIST mencatat bahwa memproses indikator secara manual lambat dan rawan salah, sehingga otomasi membiarkan analyst fokus pada analisis [S2]. Tetapi otomasi juga mempercepat kesalahan: IOC yang keliru langsung menjadi alert atau blokir di seluruh jaringan. Karena itu NIST menyebut indikator dari sumber yang belum dipercaya perlu divalidasi atau diuji dulu sebelum dipakai [S2].

**Contoh di PT JAB:** PT JAB menerima tiga jenis sumber. Feed komersial masuk otomatis lewat TAXII setiap jam dan hanya dipakai untuk alert, tidak untuk blokir otomatis. Feed open source gratis masuk sebagai file CSV harian dan dipakai sebagai bahan enrichment saja, karena tingkat false positive-nya tinggi. Buletin CSIRT sektor datang lewat email dan dimasukkan manual oleh analyst L2, karena biasanya paling relevan untuk ISP. Daftar intel di Splunk menyimpan setiap IOC dengan sumber, keyakinan, tanggal masuk, tanggal kedaluwarsa, dan label TLP. Alert `SOC-2027-0867` muncul tujuh menit setelah input karena pencocokan intel di Splunk berjalan setiap lima menit, dan setiap IOC baru otomatis dicocokkan juga dengan log sejak hari sebelumnya.

**Salah paham umum:**
- "Makin banyak feed, makin aman." Setiap feed menambah false positive dan beban analyst. NIST menyebut indikator yang tidak relevan menambah pekerjaan dan memperlambat penentuan prioritas [S2]. Feed dipilih berdasarkan relevansi dan mutu, dan dievaluasi berkala: berapa IOC dari feed ini yang pernah menghasilkan temuan nyata?

### 1.8 Enrichment dan reputasi

Pertanyaan ketujuh Sari dimulai dengan permintaan sederhana: sebelum memblokir, cek dulu IP di `SOC-2027-0867` itu milik siapa.

**Apa itu:** enrichment adalah menambahkan konteks ke sebuah IOC atau alert supaya bisa dinilai: siapa pemilik IP, kapan domain didaftarkan, domain apa saja yang pernah memakai IP itu, apa kata layanan reputasi, dan seberapa sering ia muncul di log sendiri. Day 10 bagian 1.8 menyebut enrichment sebagai otomasi paling aman di SOC karena tidak mengubah apa pun. NIST memakai kata yang sama untuk sisi berbagi: indikator yang sendirian bisa ambigu, tetapi setelah digabung dan dianalisis bersama informasi dari sumber lain ia diperkaya dan nilainya bertambah [S2]. Reputasi adalah penilaian dari layanan luar tentang seberapa sering sebuah IP, domain, URL, atau hash terlihat terlibat aktivitas jahat, biasanya dalam bentuk skor atau vonis seperti berbahaya, mencurigakan, tidak dikenal, atau bersih.

**Analogi:** mengecek plat nomor ke database kendaraan. Satpam yang melihat plat cocok dengan buletin tidak langsung menahan mobilnya; ia mengecek dulu: mobil ini terdaftar atas nama siapa, sejak kapan, apakah mobil travel, apakah ada catatan pelanggaran sebelumnya, dan apakah mobil ini sudah keluar-masuk kompleks setiap hari selama setahun. Batasnya: database kendaraan bisa telat diperbarui, catatan pelanggaran bisa salah, dan "tidak ada catatan" tidak sama dengan "orang baik". Database reputasi siber punya masalah yang sama, ditambah fakta bahwa IP berpindah tangan jauh lebih cepat daripada mobil.

**Cara kerja:** pertanyaan enrichment yang paling berguna untuk IP dan domain:

| Pertanyaan | Sumber jawaban | Apa yang dicari |
|---|---|---|
| IP ini milik siapa? | Data ASN dan WHOIS IP | Penyedia CDN, cloud besar, hosting murah, ISP rumahan, atau jaringan perusahaan |
| Domain ini sejak kapan? | WHOIS domain | Domain berumur beberapa hari jauh lebih mencurigakan daripada domain berumur 10 tahun |
| Domain apa saja yang memakai IP ini? | Passive DNS | Satu domain saja (khusus) atau ribuan domain (infrastruktur bersama) |
| Apa kata layanan reputasi? | Layanan reputasi, feed | Skor dan alasan; perhatikan tanggal penilaian |
| Apakah IP ini ada di daftar infrastruktur dikenal? | Warninglist (bagian 1.9) | Range CDN, resolver DNS publik, layanan cloud besar |
| Seberapa sering terlihat di log sendiri, sejak kapan? | SIEM | Muncul setiap hari sejak berbulan-bulan (kemungkinan layanan biasa) atau baru kemarin |

ASN (autonomous system number) adalah nomor jaringan milik satu organisasi di internet, misalnya AS64500 milik PT JAB; dari ASN terlihat organisasi mana yang mengumumkan sebuah IP. Passive DNS adalah catatan historis jawaban DNS yang dikumpulkan dari banyak resolver, sehingga bisa menjawab "domain apa saja yang pernah menunjuk ke IP ini".

Jawaban-jawaban itu digabung, bukan dibaca satu per satu. Satu sinyal jarang cukup: reputasi "berbahaya" pada IP CDN tidak berarti apa-apa, sedangkan reputasi "tidak dikenal" pada domain berumur tiga hari yang dibuka tepat setelah email mencurigakan sangat berarti.

**Contoh di PT JAB:** enrichment otomatis di Splunk menempelkan jawaban keenam pertanyaan di tabel ke setiap alert pencocokan intel. Untuk `SOC-2027-0867`, hasilnya langsung menunjukkan IP milik penyedia CDN dengan lebih dari 14 ribu domain yang terlihat di log PT JAB setiap hari selama 180 hari (bagian 2.2).

**Beda enrichment dengan reputasi:** reputasi adalah salah satu bahan enrichment, berupa pendapat pihak luar. Enrichment juga mencakup fakta (pemilik, umur, riwayat) dan konteks internal (siapa di PT JAB yang tersambung, seberapa sering), yang tidak dimiliki layanan reputasi mana pun.

### 1.9 False positive IOC: IP CDN dan infrastruktur bersama

Kecurigaan Sari terbukti: IP `192.0.2.197` dari buletin adalah alamat CDN. Pertanyaan ketujuh Sari selesai di sini: kenapa IOC yang benar bisa menghasilkan alert yang salah.

**Apa itu:** false positive IOC terjadi ketika sebuah IOC cocok dengan aktivitas yang sebenarnya sah. Penyebab paling umum adalah infrastruktur bersama: satu IP atau domain dipakai oleh banyak pihak sekaligus, termasuk penyerang. CDN (content delivery network) adalah jaringan server di banyak lokasi yang melayani ribuan situs dari IP yang sama (Day 04 bagian 1.13); bila penyerang menaruh situs phishing di belakang CDN, IP yang terlihat adalah IP CDN, yang juga dipakai ribuan situs sah. Proyek open source MISP memelihara warninglist, yaitu daftar nilai yang dikenal sering menjadi false positive, termasuk range IP CDN dan cloud besar, resolver DNS publik, dan daftar domain paling populer [S13]. Warninglist itu membedakan dua kategori: nilai yang kemungkinan besar bukan indikator sama sekali, dan nilai yang merupakan infrastruktur bersama sehingga memblokirnya berdampak ke pengguna lain yang tidak terkait [S13].

**Analogi:** mobil travel yang ditumpangi ratusan orang berbeda. Polisi mencatat dengan benar bahwa seorang maling naik mobil travel berplat `B 7777 TRV`. Bila satpam kompleks menahan mobil itu setiap kali masuk, ia menahan puluhan penghuni yang pulang kerja. Catatan polisinya benar, tetapi plat itu tidak bisa membedakan maling dari penumpang lain. Batasnya: di internet "mobil travel"-nya ditumpangi puluhan ribu situs, dan menutupnya bisa memutus situs berita, toko daring, dan aplikasi kerja sekaligus.

**Cara kerja:** sumber false positive IOC yang paling sering, dan cara menanganinya:

| Sumber | Kenapa muncul di daftar IOC | Cara mengenali |
|---|---|---|
| IP CDN | Situs jahat di belakang CDN tercatat dengan IP CDN | ASN milik penyedia CDN, passive DNS ribuan domain, SNI di log proxy berbeda-beda |
| IP hosting atau cloud bersama | Server sewaan penyerang berbagi IP atau berpindah tangan | Banyak domain, riwayat pemilik berganti |
| Resolver DNS publik | Malware bertanya DNS ke resolver publik, lalu resolvernya ikut dicatat | Ada di warninglist resolver publik [S13] |
| Domain populer | Malware mengecek koneksi internet ke situs besar, lalu domainnya ikut dicatat | Ada di daftar domain paling populer [S13] |
| Layanan berbagi file sah | Penyerang menaruh file di layanan sah | Domain sah, yang jahat hanya URL tertentu |
| Hash alat sah | Penyerang memakai alat admin sah | Hash milik program bertanda tangan vendor sah |
| IOC usang | IP sudah berpindah ke pemilik baru | Lihat bagian 1.10 |

Solusinya bukan membuang IOC itu, tetapi memakainya di tingkat yang lebih spesifik. Untuk situs di belakang CDN, yang membedakan adalah nama domain (SNI di log proxy atau query DNS), bukan IP. NIST juga mengingatkan bahwa toleransi tiap organisasi berbeda: sebagian rela sesekali memblokir aktivitas sah demi keamanan, sebagian lain sangat bergantung pada ketersediaan layanan sehingga indikator yang meragukan hanya dipakai untuk pemantauan [S2]. Untuk ISP seperti PT JAB, memblokir IP CDN di firewall perimeter bisa memutus akses karyawan ke banyak layanan sekaligus.

**Contoh di PT JAB:** CSIRT sektor mencantumkan `192.0.2.197` karena domain `peering-docs.example` sempat ditaruh di belakang CDN. Catatannya benar, tetapi 1.284 sambungan dari 211 komputer PT JAB ke IP itu semuanya menuju situs berita dan penyedia font web, tidak ada satu pun ke domain kampanye. Sari menandai alert sebagai false positive, menurunkan IOC itu menjadi "hanya enrichment" di daftar intel, dan mengganti pencocokannya dengan nama domain. Sari juga mengirim catatan ke CSIRT sektor bahwa IP itu milik CDN, karena NIST mendorong penerima untuk memperkaya dan mengoreksi indikator lalu membagikan temuannya kembali [S2].

**Beda dengan false positive rule:** false positive rule terjadi karena logika deteksinya terlalu longgar; istilah true positive dan false positive secara umum dibahas di Day 11. False positive IOC terjadi walaupun logikanya benar ("cocokkan IP ini"), karena nilai IOC-nya sendiri tidak cukup spesifik.

### 1.10 Umur IOC (indicator aging)

Pertanyaan kedelapan Sari menyangkut satu IP dari buletin tahun 2026 yang masih ada di blocklist `jkt-fw01`. Pukul 10:05 IP itu memicu alert baru.

**Apa itu:** umur IOC adalah masa berlaku sebuah IOC sebelum dianggap usang dan diarsipkan. Konsep ini muncul karena benda yang dipakai penyerang berganti pemilik dan berganti fungsi. NIST menyebut "lamanya indikator masih dianggap valid" sebagai salah satu data yang perlu dicatat untuk setiap indikator, dan meminta organisasi punya kebijakan retensi dan pembuangan indikator [S2]. Format STIX menyediakan field `valid_from` dan `valid_until` untuk setiap indikator; setelah `valid_until`, indikator tidak lagi dianggap berlaku [S4]. Platform open source MISP menerapkan model decaying: setiap indikator punya skor awal sesuai mutunya, skor itu turun seiring waktu sampai nol di akhir masa hidupnya, dan setiap kali indikator terlihat lagi (sighting) skornya dikembalikan ke nilai awal [S14].

**Analogi:** plat nomor yang sudah dijual ke pemilik baru. Buletin tahun lalu mencatat plat itu dipakai maling; sekarang mobilnya dimiliki guru SD yang setiap pagi mengantar anaknya ke sekolah di dalam kompleks. Menahan mobil itu tidak menangkap siapa pun. Batasnya: plat mobil berganti pemilik dalam hitungan tahun, sedangkan IP server sewaan bisa berganti pemilik dalam hitungan hari.

**Cara kerja:** umur yang wajar berbeda per jenis, mengikuti Pyramid of Pain. IP paling cepat usang karena paling mudah diganti dan sering dipakai ulang penyedia hosting. Domain bertahan lebih lama, tetapi domain jahat yang diblokir registrar atau tidak diperpanjang bisa dibeli orang lain. Hash file tidak pernah berubah artinya (file itu tetap jahat), tetapi jarang terlihat lagi setelah kampanye selesai, sehingga biayanya hanya ruang simpan. Tidak ada angka baku yang berlaku untuk semua organisasi; setiap SOC menetapkan sendiri dan meninjaunya.

**Contoh di PT JAB:** kebijakan daftar intel PT JAB sejak `INC-2027-001`: IP berlaku 30 hari, domain 90 hari, URL 90 hari, hash 365 hari, kecuali diperpanjang karena terlihat lagi. Masalahnya, blocklist di `jkt-fw01` diisi manual sebelum kebijakan itu ada, dan `192.0.2.199` dari buletin Oktober 2026 masih tercantum. Alert `SOC-2027-0871` pukul 10:05 mencatat `jkt-fw01` menolak 46 sambungan dari `JKT-WS-1127` (`10.10.42.27`) ke IP itu. Enrichment menunjukkan IP sekarang dipakai server pembaruan `update.toolvendor.example`, milik vendor alat monitoring yang dipakai tim NOC, dan passive DNS mencatat domain itu menunjuk ke `192.0.2.199` sejak Maret 2027. Alert ditutup sebagai false positive karena IOC usang; Sari meminta tim firewall menghapus IP itu dan membuat tiket untuk meninjau seluruh blocklist manual yang tidak punya tanggal kedaluwarsa.

**Beda dengan retensi bukti:** IOC yang usang untuk deteksi tetap disimpan di arsip, karena berguna untuk memahami sejarah sebuah kelompok penyerang. NIST juga membedakan indikator yang sudah menjadi bukti insiden: yang ini disimpan mengikuti aturan bukti dan chain of custody, bukan aturan umur IOC [S2].

### 1.11 STIX dan TAXII

Pertanyaan keenam Sari juga menanyakan bagaimana feed komersial bisa masuk ke Splunk setiap jam tanpa ada yang menyalin. Jawabannya dua standar yang selalu disebut berpasangan.

**Apa itu:** STIX (Structured Threat Information Expression) adalah bahasa dan format baku untuk menulis informasi ancaman sehingga bisa dibaca mesin dan dipertukarkan antar alat. Versi 2.1 disahkan sebagai OASIS Standard pada 10 Juni 2021 dan ditulis dalam JSON [S4]. STIX punya objek untuk setiap konsep, antara lain Indicator, Malware, Threat Actor, Campaign, Attack Pattern (TTP), Intrusion Set, Infrastructure, Vulnerability, dan Report; objek-objek itu dihubungkan dengan objek Relationship, dan objek Sighting mencatat bahwa sebuah indikator benar-benar terlihat oleh seseorang [S4]. TAXII (Trusted Automated Exchange of Intelligence Information) adalah protokol lapisan aplikasi untuk bertukar threat intelligence lewat HTTPS dengan API bergaya REST [S5]. TAXII 2.1 juga disahkan 10 Juni 2021 [S5].

**Analogi:** STIX seperti formulir laporan polisi yang bentuknya sama di semua kantor: kolom plat nomor selalu di tempat yang sama, sehingga kantor mana pun bisa membaca laporan kantor lain tanpa menebak. TAXII seperti kotak surat langganan tempat formulir itu diambil secara rutin. Batasnya: formulir yang seragam tidak menjamin isinya benar, dan kotak surat yang rapi tidak menjamin pengirimnya bisa dipercaya.

**Cara kerja:** objek Indicator di STIX wajib punya tiga field: `pattern` (pola yang dicocokkan), `pattern_type` (bahasa polanya, biasanya `stix`, tetapi bisa juga Snort atau YARA), dan `valid_from` (sejak kapan berlaku); `valid_until` opsional [S4]. Pola STIX ditulis di dalam kurung siku, misalnya `[file:hashes.'SHA-256' = '...']` untuk hash atau `[domain-name:value = '...']` untuk domain [S4]. Contoh lengkap satu objek ada di bagian 2.1.

TAXII mendefinisikan Collection, yaitu kumpulan intel yang disimpan produsen dan diambil konsumen dengan pola permintaan dan jawaban [S5]. TAXII juga menyebut Channel untuk pola publish dan subscribe, tetapi versi 2.1 hanya mencadangkan namanya dan belum mendefinisikan layanannya [S5]. TAXII dirancang bersama STIX, tetapi tidak dibatasi hanya untuk STIX [S5].

```
  produsen (CSIRT, vendor)                       konsumen (PT JAB)
  menulis objek STIX (JSON)                      klien TAXII di TIP atau Splunk
        |                                                |
  server TAXII  <------ HTTPS: GET collection ----------+   setiap jam
  (Collection "kampanye-isp")  ---- objek STIX baru ---->   disimpan di daftar intel
```

Contoh berskala besar adalah AIS (Automated Indicator Sharing) milik CISA (badan keamanan siber Amerika Serikat), yang membagikan indikator gratis kepada organisasi pemerintah dan swasta lewat STIX/TAXII [S8].

**Contoh di PT JAB:** feed komersial PT JAB berjalan di atas TAXII 2.1: Splunk bertindak sebagai klien yang setiap jam mengambil objek baru dari satu Collection, lalu membaca objek Indicator dan `valid_until`-nya untuk mengisi tanggal kedaluwarsa di daftar intel. Buletin CSIRT sektor pagi ini datang sebagai PDF dengan tabel, jadi Sari mengetik ulang 9 IOC itu; seandainya CSIRT sektor juga menerbitkan STIX, langkah manual itu dan risiko salah ketiknya hilang.

**Beda STIX dengan TAXII:** STIX adalah isi (format), TAXII adalah pengangkutnya (protokol). Data STIX bisa dikirim lewat email atau diunduh sebagai file tanpa TAXII, dan TAXII bisa mengangkut format lain.

### 1.12 TLP dan komunitas berbagi (CSIRT, ISAC, BSSN)

Pertanyaan terakhir Sari menyangkut permintaan Bambang Hartono (Manajer NOC) untuk meneruskan buletin ke grup WhatsApp engineer NOC antar-ISP. Jawabannya ada di label merah-kuning-hijau di kepala buletin itu.

**Apa itu:** TLP (Traffic Light Protocol) adalah label baku dari FIRST (forum internasional tim respons insiden) yang menyatakan sejauh mana penerima boleh membagikan informasi. Versi 2.0 berlaku sejak Agustus 2022 dan menggantikan versi 1.0 [S6]. Labelnya empat warna ditambah satu varian `TLP:AMBER+STRICT`, ditulis huruf besar tanpa spasi [S6]:

| Label | Boleh dibagikan ke | Contoh pemakaian |
|---|---|---|
| `TLP:RED` | Hanya penerima pribadi, tidak boleh diteruskan | Briefing rapat tertutup tentang insiden yang sedang berjalan |
| `TLP:AMBER` | Anggota organisasi penerima dan kliennya, hanya yang perlu tahu | Buletin CSIRT sektor pagi ini |
| `TLP:AMBER+STRICT` | Hanya anggota organisasi penerima, tanpa klien | Buletin yang menyebut nama korban |
| `TLP:GREEN` | Komunitas penerima, tetapi tidak lewat saluran yang bisa diakses publik | Ringkasan kampanye untuk forum ISP |
| `TLP:CLEAR` | Siapa saja, tanpa batas (tetap tunduk hak cipta) | Advisory publik |

Di versi 1.0 label untuk informasi publik bernama `TLP:WHITE`, seperti tercantum di tabel NIST SP 800-150 [S2]; di versi 2.0 label publiknya `TLP:CLEAR` [S6]. CISA mengadopsi TLP 2.0 sejak 1 November 2022 [S7].

CSIRT (computer security incident response team) adalah tim yang menangani insiden siber dan menyebarkan peringatan, untuk satu organisasi, satu sektor, atau satu negara. ISAC (information sharing and analysis center) adalah wadah berbagi informasi ancaman antarorganisasi dalam satu sektor; NIST menyebut ISAC sebagai salah satu sumber advisory dan contoh mitra berbagi, bersama CSIRT nasional dan layanan AIS CISA [S2]. Di Indonesia, Peraturan BSSN (Badan Siber dan Sandi Negara) Nomor 10 Tahun 2020 membagi tim tanggap insiden siber menjadi tingkat nasional (dibentuk BSSN), sektoral, organisasi, dan khusus; tim sektoral dibentuk kementerian atau lembaga pengawas sektornya, dan salah satu sektor yang disebut adalah teknologi informasi dan komunikasi [S15]. Sebelum BSSN, peran CSIRT nasional untuk infrastruktur internet dijalankan Id-SIRTII/CC, yang dibentuk 2007 dan menjadi bagian BSSN sejak 2017 [S16].

**Analogi:** cap di amplop buletin polisi: "hanya untuk kepala satpam" (RED), "untuk satpam kompleks ini yang bertugas" (AMBER), "boleh ke forum satpam se-kawasan, tidak untuk papan pengumuman umum" (GREEN), "boleh ditempel di mana saja" (CLEAR). Batasnya: cap hanya bekerja bila penerima menghormatinya; tidak ada mekanisme teknis yang mencegah buletin difoto dan disebar.

**Cara kerja:** TLP diletakkan di tempat yang terlihat sebelum informasinya: di subjek email, di awal pesan, atau di kepala dan kaki setiap halaman dokumen [S6]. Yang menentukan label adalah sumber informasi; penerima yang ingin membagikan lebih luas harus meminta izin sumber atau meminta versi dengan label yang lebih longgar. Sumber memilih label sesuai risikonya: TLP:AMBER dipakai bila informasi butuh dukungan pihak lain untuk ditindaklanjuti, tetapi berisiko terhadap privasi, reputasi, atau operasi bila tersebar ke luar organisasi yang terlibat [S6].

Berbagi juga ada aturannya bagi pengirim. NIST mengingatkan bahwa indikator jaringan yang digabung bisa membuka struktur jaringan dan alat keamanan pengirimnya, sehingga sebelum dibagikan, IP atau MAC milik sistem korban dan alamat milik organisasi sendiri sebaiknya disamarkan [S2].

**Contoh di PT JAB:** buletin berlabel `TLP:AMBER`, jadi Bambang boleh meneruskannya ke engineer NOC PT JAB yang perlu tahu, tetapi tidak ke grup WhatsApp antar-ISP, karena grup itu komunitas di luar PT JAB. Sari menyarankan Bambang meminta CSIRT sektor menerbitkan versi `TLP:GREEN` untuk forum NOC antar-ISP, atau menunggu advisory publik. Sebaliknya, ketika PT JAB membagikan IP baru `192.0.2.194` temuan `INC-2027-091` ke CSIRT sektor, Sari membuang nama akun Yudi dan IP internal komputernya sebelum mengirim.

**Beda TLP dengan klasifikasi data internal:** klasifikasi internal mengatur dokumen milik organisasi sendiri; TLP mengatur informasi yang dipertukarkan dengan pihak lain dan dibaca sama oleh semua penerima.

## 2. Contoh nyata

Semua contoh di bagian ini adalah keluaran ilustrasi dari organisasi fiktif PT JAB, bukan hasil eksekusi nyata. Nama host, alamat IP, domain, hash, nomor, dan angka dibuat untuk latihan. Nilai hash dihitung dari teks contoh karena file fiktif tidak bisa di-hash; panjang dan formatnya sama dengan hash file sungguhan.

### 2.1 Buletin CSIRT sektor dan satu IOC dalam format STIX

Ini buletin yang diterima PT JAB pukul 08:10, ringkasan halaman pertama dan lampiran IOC-nya. Bentuk defang dipakai seperti aslinya.

```
TLP:AMBER
Buletin Kampanye  : BK-2027-031   (CSIRT sektor teknologi informasi dan komunikasi)
Tanggal           : 2027-08-18 07:30 WIB
Judul             : Kampanye phishing "Pembaruan Kontrak Interkoneksi 2027" menyasar ISP
Ringkasan         : Aktif sejak 2027-08-02. Sasaran: engineer jaringan dan NOC di ISP.
                    Tujuan: mengambil alih mailbox Microsoft 365 lewat halaman AiTM,
                    lalu menyembunyikan email dengan aturan inbox. Keyakinan: tinggi.
Cara kerja (TTP)  : 1. Email dari domain mirip mitra interkoneksi, lampiran HTML.
                    2. Lampiran membuka halaman AiTM tiruan login Microsoft 365.
                    3. Session cookie dipakai dari IP lain dalam 1 jam.
                    4. Aturan inbox bernama "." memindahkan email berisi "kontrak"
                       atau "keamanan" ke folder RSS Feeds.

Lampiran IOC
No  Jenis      Nilai                                                              Catatan
1   SHA-256    fab4c1eba037e0ddc4cb166bd5d421b18de86911682a826dfcabada5a55baa84  Kontrak_Interkoneksi_2027.html
2   domain     isp-peering-portal[.]example                                       halaman AiTM, didaftarkan 2027-07-29
3   domain     peering-docs[.]example                                             halaman AiTM, didaftarkan 2027-07-30
4   URL        hxxps://isp-peering-portal[.]example/kontrak/login
5   URL        hxxps://peering-docs[.]example/kontrak/login
6   IP         192.0.2[.]190                                                      hosting isp-peering-portal
7   IP         192.0.2[.]193                                                      server pengirim email
8   IP         192.0.2[.]197                                                      peering-docs (2027-08-05 s.d. 2027-08-09)
9   subjek     "Pembaruan Kontrak Interkoneksi 2027"
TLP:AMBER
```

**Cara membaca:**
- Label `TLP:AMBER` di awal dan akhir menandai batas informasi yang dilindungi (bagian 1.12).
- Ringkasan adalah intel operational (siapa disasar, sejak kapan, tujuannya); bagian "Cara kerja" adalah TTP; lampiran adalah IOC tactical atau technical (bagian 1.6).
- Petunjuk false positive sudah ada di buletin itu sendiri: IOC nomor 8 diberi rentang tanggal, artinya domain itu hanya sementara berada di IP tersebut. Keterangan seperti ini sering terlewat saat IOC disalin ke alat.
- SHA-256 panjangnya 64 karakter; cek panjangnya sebelum memasukkan ke alat (Day 05 bagian 2.2).

Seandainya CSIRT sektor menerbitkan IOC nomor 2 dalam format STIX 2.1, objeknya akan terlihat seperti ini:

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--204bce08-7ac0-4af4-a785-5a3e41ad9af1",
  "created": "2027-08-18T00:30:00.000Z",
  "modified": "2027-08-18T00:30:00.000Z",
  "name": "Domain AiTM kampanye kontrak interkoneksi",
  "indicator_types": ["malicious-activity"],
  "pattern": "[domain-name:value = 'isp-peering-portal.example']",
  "pattern_type": "stix",
  "valid_from": "2027-08-18T00:30:00Z",
  "valid_until": "2027-11-16T00:30:00Z",
  "object_marking_refs": ["marking-definition--<id TLP:AMBER>"]
}
```

**Cara membaca:** `pattern` memuat nilai asli tanpa defang, karena dibaca mesin. `valid_from` dan `valid_until` memberi masa berlaku 90 hari, sesuai prinsip umur IOC di bagian 1.10. Waktu ditulis dalam UTC: `00:30Z` sama dengan 07:30 WIB. `object_marking_refs` menunjuk objek penanda TLP; di STIX nilainya adalah ID objek penanda, yang di contoh ini disingkat. Field `type`, `id`, `pattern`, `pattern_type`, dan `valid_from` adalah bagian dari spesifikasi Indicator STIX 2.1 [S4].

### 2.2 Membedah `SOC-2027-0867`: IP yang cocok ternyata CDN

Alert pertama hari itu menjawab pertanyaan ketujuh Sari. Ringkasannya di Splunk, setelah enrichment otomatis menempelkan konteks:

```
Alert       : SOC-2027-0867   Threat intel match: IP
Waktu       : 2027-08-18 08:52 WIB
Sumber IOC  : BK-2027-031 no. 8 (CSIRT sektor, TLP:AMBER), keyakinan tinggi
Nilai       : 192.0.2.197
Log         : jkt-proxy01, 2027-08-17 00:00 s.d. 2027-08-18 08:50
Kecocokan   : 1.284 sambungan dari 211 host internal

Enrichment
  ASN            : AS64510 "Contoh CDN Global" (penyedia CDN)
  Warninglist    : cocok "range CDN dikenal"
  Passive DNS    : 14.380 domain menunjuk ke IP ini dalam 30 hari terakhir
  Reputasi A     : 2 dari 68 vendor menandai berbahaya (penilaian 2027-08-09)
  Reputasi B     : tidak ada laporan
  Riwayat SIEM   : terlihat setiap hari, 180 dari 180 hari terakhir

SNI di log proxy untuk 192.0.2.197 (periode yang sama)
  cdn.kabarnusantara.example     902
  fonts.webstatic.example        318
  assets.tokobuku.example         64
  isp-peering-portal.example       0
  peering-docs.example             0
```

**Cara membaca:**
- Jumlah SNI: 902 + 318 + 64 = 1.284, sama dengan total sambungan. Semua sambungan menuju tiga situs sah; tidak satu pun ke domain kampanye.
- Lima petunjuk menunjuk ke arah yang sama: ASN penyedia CDN, ada di warninglist, belasan ribu domain di passive DNS, terlihat setiap hari selama enam bulan, dan buletin sendiri memberi rentang tanggal 5 sampai 9 Agustus (bagian 1.9).
- Reputasi "2 dari 68" bukan alasan untuk memblokir. Dua penilai itu menilai IP CDN yang pernah dipakai situs jahat; penilaiannya bertanggal 9 Agustus, hari terakhir domain kampanye berada di sana.
- Pertanyaan yang tersisa adalah apakah ada komputer yang membuka `peering-docs.example` saat domain itu berada di IP ini. Jawabannya dicari dengan nama domain di log DNS, bukan dengan IP (bagian 2.3).

**Keputusan:** false positive karena infrastruktur bersama. Sari mengubah IOC nomor 8 menjadi "hanya enrichment" sehingga tidak lagi membunyikan alert, dan mengirim koreksi ke CSIRT sektor. Seandainya IP ini diblokir di `jkt-fw01` seperti usul Gilang, 211 karyawan kehilangan akses ke situs berita dan halaman yang memakai font web penyedia itu, tanpa menghambat satu pun penyerang.

**Kapan gagal:** pengecekan SNI hanya bekerja untuk lalu lintas yang lewat proxy; untuk sisanya, IP CDN tidak bisa dibedakan dari log firewall saja, sehingga jawabannya dicari di log DNS atau endpoint.

### 2.3 Menyapu dengan hash dan domain: `SOC-2027-0868` dan `SOC-2027-0869`

Setelah IP CDN disingkirkan, Sari menjalankan pencarian ke belakang 30 hari dengan IOC lain. Dua alert muncul hampir bersamaan.

```
Alert       : SOC-2027-0868   Threat intel match: file hash (email)
Waktu       : 2027-08-18 09:12 WIB
Sumber IOC  : BK-2027-031 no. 1
Log         : Defender for Office 365, 2027-07-19 s.d. 2027-08-18
Kecocokan   : 3 email, diterima 2027-08-17 16:22 s.d. 16:24 WIB
  Pengirim    : kontrak@isp-peering-portal.example  (IP pengirim 192.0.2.193)
  Subjek      : Pembaruan Kontrak Interkoneksi 2027
  Lampiran    : Kontrak_Interkoneksi_2027.html
  SHA-256     : fab4c1eba037e0ddc4cb166bd5d421b18de86911682a826dfcabada5a55baa84
  Penerima    : yudi.santoso@jab.example       Inbox   dibuka 2027-08-18 07:58
                reza.firmansyah@jab.example    Inbox   belum dibuka
                andi.kurniawan@jab.example     Inbox   belum dibuka

Alert       : SOC-2027-0869   Threat intel match: domain (DNS)
Waktu       : 2027-08-18 09:14 WIB
Sumber IOC  : BK-2027-031 no. 2
Log         : jkt-res01, jkt-res02, jkt-proxy01
  07:58:41  JKT-WS-1124 (10.10.42.24)  query A isp-peering-portal.example  jawaban 192.0.2.190
  07:58:43  jkt-proxy01  JKT-WS-1124  GET  https://isp-peering-portal.example/kontrak/login   200
  07:59:20  jkt-proxy01  JKT-WS-1124  POST https://isp-peering-portal.example/kontrak/login   302
Domain peering-docs.example: tidak ada query dalam 30 hari
```

**Cara membaca:**
- Tiga IOC dari tingkat berbeda saling menguatkan: hash (lampiran yang sama persis), domain (komputer membuka halaman kampanye), dan IP pengirim. Ketiganya mengarah ke satu orang, Yudi Santoso, engineer NOC.
- Urutan waktu menceritakan apa yang terjadi: email dibuka 07:58, dua detik kemudian browser bertanya DNS, halaman login dibuka, dan 37 detik kemudian ada `POST` ke halaman itu dengan jawaban `302` (pengalihan). `POST` ke halaman login berarti ada data formulir yang dikirim, kemungkinan besar username dan password.
- Path `/kontrak/login` terlihat karena domain ini baru dan tidak dikategorikan, sehingga `jkt-proxy01` membuka HTTPS-nya (bagian 1.2).
- Tidak ada query untuk `peering-docs.example`, jadi tidak ada komputer PT JAB yang membuka domain di belakang IP CDN di bagian 2.2. Pertanyaan yang tersisa dari `SOC-2027-0867` terjawab di sini.
- Dua penerima lain belum membuka email. Hash memungkinkan SOC mencari dan menghapus salinan email itu dari semua mailbox sekaligus, karena lampirannya identik.

**Kenapa hash dan domain lebih berguna di sini daripada IP:** keduanya spesifik untuk kampanye; tidak ada pengguna sah yang punya alasan menerima file itu atau membuka domain berumur 20 hari dengan nama mirip mitra interkoneksi.

**Kapan gagal:** penyerang yang mengirim lampiran sedikit berbeda ke setiap penerima menghasilkan hash yang berbeda-beda, dan pencarian hash hanya menemukan salinan yang persis sama. Domain juga bisa diganti untuk setiap gelombang. Itulah kenapa langkah berikutnya bergeser ke perilaku.

### 2.4 IOA tanpa IOC: `SOC-2027-0870` dan insiden `INC-2027-091`

Alert yang dipegang Dwi sejak pukul 08:33 ternyata adalah kelanjutan cerita yang sama. Ringkasannya:

```
Alert       : SOC-2027-0870   Aturan inbox mencurigakan setelah login dari IP baru
Waktu       : 2027-08-18 08:33 WIB
Rule        : perilaku (dibuat setelah INC-2027-001), bukan pencocokan intel
Akun        : yudi.santoso@jab.example
  08:27:10  Sign-in berhasil  IP 192.0.2.194  (belum pernah dipakai akun ini dalam 90 hari)
            Metode: sesi yang sudah ada, tanpa permintaan MFA baru
            Perangkat: tidak terdaftar
  08:31:52  New-InboxRule  Name "."  
            Kondisi : subjek atau isi memuat "kontrak" atau "keamanan"
            Tindakan: pindahkan ke folder "RSS Feeds", tandai sudah dibaca
Login Yudi sebelumnya hari itu: 07:45 dari 198.51.100.120 (NAT kantor), MFA berhasil
Enrichment 192.0.2.194: hosting VPS, domain di passive DNS: 1, tidak ada di daftar intel mana pun
```

**Cara membaca:**
- Rule ini tidak tahu apa pun tentang buletin. Ia mencari dua langkah yang harus dilakukan penyerang dengan modus pencurian sesi: memakai sesi dari IP dan perangkat baru tanpa MFA baru, lalu membuat aturan inbox yang menyembunyikan email. Itu IOA (bagian 1.4) yang dibangun dari tingkat TTP Pyramid of Pain (bagian 1.5).
- IP `192.0.2.194` tidak ada di buletin. Penyerang memakai IP berbeda untuk memakai sesi curian dari IP yang menjadi hosting halaman phishingnya. Deteksi berbasis IOC saja akan melewatkan langkah ini sepenuhnya.
- Nama aturan "." dan folder RSS Feeds cocok persis dengan procedure di buletin. Ini artefak tingkat "Annoying": tidak bernilai sebagai IOC untuk dicari di log lain, tetapi sangat kuat untuk menghubungkan alert ini dengan kampanye.
- Waktu 07:59 (password dan sesi dikirim ke halaman AiTM) lalu 08:27 (sesi dipakai dari IP lain) lalu 08:31 (aturan inbox) cocok dengan "dalam 1 jam" di buletin.

**Keputusan:** Sari menggabungkan `SOC-2027-0868`, `0869`, dan `0870` menjadi insiden `INC-2027-091` dengan severity SEV-2, karena mailbox engineer NOC sudah dikuasai pihak luar. Langkah yang diambil: mencabut semua sesi dan mereset password Yudi, menghapus aturan inbox, memeriksa email yang dikirim dari mailbox itu sejak 08:27, menghapus dua salinan email di mailbox Reza dan Andi, mengarahkan dua domain kampanye ke sinkhole `jkt-sink01` (`10.20.99.99`) di resolver, memblokir dua domain itu di `jkt-proxy01`, dan menambah `192.0.2.194` ke daftar intel dengan masa berlaku 30 hari. IP baru itu dibagikan ke CSIRT sektor dengan label `TLP:AMBER`, tanpa nama akun dan tanpa IP internal. Usulan migrasi engineer NOC ke kunci FIDO2 yang muncul setelah alert `SOC-2027-0835` (Day 06 bagian 2.3) dimasukkan Sari ke laporan kuartalan sebagai temuan strategic: dua insiden pencurian sesi di tim yang sama dalam tujuh bulan.

**Kapan gagal:** rule perilaku butuh data yang lengkap (sign-in log dan audit log mailbox harus masuk ke SIEM) dan butuh tahu apa yang normal. Engineer yang sering bekerja dari jaringan berbeda akan membuat rule "IP baru" sering berbunyi, sehingga rule ini digabung dengan syarat aturan inbox supaya tidak membanjiri antrean.

## 3. Perbandingan istilah yang sering tertukar

### 3.1 IOC, IOA, dan TTP

Tiga istilah ini paling sering ditukar di interview. Tabel berikut membedakannya dengan pertanyaan yang dijawab masing-masing; cari kolom "Umur" untuk melihat kenapa deteksi jangka panjang dibangun dari kolom kanan.

| Aspek | IOC | IOA | TTP |
|---|---|---|---|
| Menjawab | Benda apa yang dipakai? | Apakah perilaku serangan sedang terjadi? | Bagaimana penyerang bekerja? |
| Bentuk | Nilai pasti: hash, IP, domain, URL | Rule atau analitik perilaku di log | Deskripsi perilaku, sering dipetakan ke ATT&CK |
| Contoh di Day ini | `isp-peering-portal.example` | Login dari IP baru tanpa MFA, lalu aturan inbox penyembunyi | AiTM lalu aturan inbox (T1566.002, T1539, T1564.008) |
| Waktu ditemukan | Biasanya saat atau setelah kejadian | Bisa saat serangan masih berjalan | Dari analisis kejadian yang sudah terjadi |
| Umur | Pendek (hari sampai bulan) | Panjang, selama modusnya dipakai | Panjang |
| Risiko utama | False positive infrastruktur bersama, usang | False positive aktivitas normal yang mirip | Terlalu umum untuk dicari langsung |
| Dipakai oleh | Mesin (SIEM, proxy, EDR) | Analyst yang menulis dan merawat rule | Analyst, threat hunter, pimpinan |

### 3.2 Strategic, operational, tactical (dan technical)

Pembagian tingkat intel tidak seragam antar sumber (bagian 1.6). Tabel berikut menyandingkan dua versi yang paling sering ditemui; cari baris yang memuat IOC untuk melihat letak perbedaannya.

| Isi | Versi empat tingkat (MWR, CPNI, CERT-UK) [S12] | Versi tiga tingkat (banyak vendor) [S11] | Pembaca |
|---|---|---|---|
| Tren, motif, risiko bisnis | Strategic | Strategic | Pimpinan |
| Kampanye tertentu: siapa, menyasar siapa, kapan | Operational | Operational | Manajer keamanan, pimpinan respons |
| TTP | Tactical | Operational | Analyst, engineer |
| IOC (hash, IP, domain) | Technical | Tactical | Alat (otomatis), analyst |

## 4. Salah paham umum

- **Anggapan:** memblokir IP penyerang di firewall adalah respons utama terhadap kampanye. **Kenyataannya:** penyerang di `INC-2027-091` sudah memakai IP lain (`192.0.2.194`) untuk langkah berikutnya sebelum buletin terbit. Respons yang berdampak adalah mencabut sesi, mereset password, menghapus email dari mailbox lain, dan memperkuat MFA; blokir IP dan domain hanya pelengkap.
- **Anggapan:** threat intelligence hanya berguna untuk SOC. **Kenyataannya:** keputusan dengan dampak terbesar dari kampanye ini adalah keputusan anggaran FIDO2 untuk engineer NOC, yang diambil direktur dari intel strategic. Intel yang tidak pernah sampai ke pengambil keputusan hanya mengubah rule, bukan risiko.
- **Anggapan:** organisasi kecil cukup menerima intel, tidak perlu mengirim. **Kenyataannya:** IP `192.0.2.194` hanya diketahui PT JAB. Tanpa dikirim balik ke CSIRT sektor, ISP lain yang disasar kampanye yang sama tidak punya IOC itu. NIST mendorong penerima untuk membagikan wawasan baru dari indikator yang mereka perkaya [S2].
- **Anggapan:** buletin dengan label resmi dan keyakinan tinggi tidak perlu diperiksa. **Kenyataannya:** buletin yang sama memuat satu IP CDN, dan blocklist PT JAB masih menyimpan IP buletin tahun lalu yang kini milik vendor sah. Sumber terpercaya menurunkan kebutuhan validasi, tetapi tidak menghapusnya [S2].

## 5. Catatan terkini

Bagian ini mencatat versi dokumen acuan, tanggal terbit, dan perubahan nama yang perlu diketahui saat membaca sumber lain.

- NIST SP 800-150 (Guide to Cyber Threat Information Sharing) terbit Oktober 2016 dan per 2026-10-21 masih berstatus final tanpa revisi di halaman publikasinya [S2]. Definisi IOC di glosarium NIST kini juga dikutip oleh NIST SP 800-61 Rev. 3 dengan penyesuaian dari SP 800-150 [S1].
- Tulisan asli Pyramid of Pain terbit 1 Maret 2013 dan diperbarui 17 Januari 2014 dengan menambahkan tingkat hash sebagai tingkat tersendiri [S3]. Gambar yang beredar di banyak materi adalah versi setelah pembaruan itu.
- STIX 2.1 dan TAXII 2.1 sama-sama disahkan sebagai OASIS Standard pada 10 Juni 2021 [S4][S5]. TAXII 2.1 belum mendefinisikan layanan Channel [S5].
- TLP 2.0 berlaku sejak Agustus 2022, dan versi 1.0 dinyatakan usang pada bulan yang sama [S6]. CISA mengadopsi TLP 2.0 sejak 1 November 2022 [S7]. Dokumen yang ditulis sebelum itu, termasuk NIST SP 800-150, masih memakai `TLP:WHITE` dan belum mengenal `TLP:AMBER+STRICT` [S2].
- MITRE ATT&CK versi terbaru per 2026-10-21 adalah v20.0, rilis 13 Oktober 2026 [S9]. Di versi ini tactic TA0005 tampil dengan nama Stealth; dokumentasi lama menyebut tactic yang sama Defense Evasion. Technique T1566 (Phishing) per September 2026 memuat empat sub-technique, termasuk T1566.004 Spearphishing Voice [S9].
- Layanan AIS CISA disertifikasi beroperasi Maret 2016 berdasarkan Cybersecurity Information Sharing Act of 2015 [S8].
- Peraturan BSSN Nomor 10 Tahun 2020 tentang Tim Tanggap Insiden Siber ditetapkan 15 Desember 2020 dan diundangkan 16 Desember 2020 [S15]. Cek apakah ada peraturan BSSN yang lebih baru bila kamu perlu dasar hukum yang berlaku saat ini.

## 6. Cheat sheet

```
IOC                : benda teknis terkait serangan: hash, IP, domain, URL, subjek email
Observable         : apa pun yang terlihat di log; jadi IOC bila dikaitkan dengan aktivitas jahat
Defang             : hxxps, [.] supaya tidak bisa diklik; kembalikan saat dimasukkan ke alat
TTP                : perilaku penyerang: tactic (tujuan) > technique (cara) > procedure (rincian)
IOA                : tanda perilaku serangan sedang berjalan, apa pun IP/hash-nya
Pyramid of Pain    : hash < IP < domain < artefak < tools < TTP; makin atas makin mahal diganti
Threat intelligence: informasi ancaman yang sudah diolah dan diberi konteks untuk keputusan
Strategic          : pimpinan; tren, motif, risiko bisnis; jangka panjang
Operational        : kampanye tertentu; siapa, menyasar siapa, kapan
Tactical           : tim teknis; TTP dan IOC (sebagian sumber pisahkan IOC jadi "technical")
Feed               : aliran IOC berkala, sering otomatis; pilih yang relevan
TIP                : kumpulkan, saring, beri tanggal, salurkan IOC
Enrichment         : tambah konteks: ASN, umur domain, passive DNS, reputasi, riwayat log
Reputasi           : pendapat layanan luar; baca alasan dan tanggal; "tidak dikenal" != aman
Passive DNS        : riwayat domain mana pernah menunjuk ke IP mana
False positive IOC : IOC benar tapi tidak spesifik: IP CDN, hosting, resolver publik, domain populer
Warninglist        : daftar nilai yang sering jadi false positive (range CDN, resolver publik)
Umur IOC           : IP pendek, domain sedang, hash panjang; tetapkan valid_until
STIX               : format JSON informasi ancaman (Indicator, Malware, Threat Actor, Sighting, ...)
TAXII              : protokol HTTPS untuk ambil/kirim STIX (Collection)
TLP 2.0            : RED, AMBER+STRICT, AMBER, GREEN, CLEAR (dulu WHITE); sumber yang menentukan
CSIRT / ISAC       : tim tanggap insiden / wadah berbagi intel satu sektor
TTIS (Indonesia)   : nasional (BSSN), sektoral, organisasi, khusus (Peraturan BSSN 10/2020)
```

## 7. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "IP dari buletin CSIRT sektor cocok dengan 1.284 sambungan dari komputer kantor. Artinya 211 komputer itu sudah terinfeksi dan harus diisolasi." Benarkah?

<details><summary>Jawaban</summary>

Tidak. IOC yang cocok hanya berarti ada sambungan ke IP yang pernah dikaitkan dengan penyerang. Pada `SOC-2027-0867`, IP itu milik CDN yang melayani lebih dari 14 ribu domain, dan SNI di log proxy menunjukkan semua sambungan menuju situs berita, font web, dan toko daring, tidak ada yang ke domain kampanye. Langkah yang benar adalah enrichment (ASN, passive DNS, warninglist, riwayat log) lalu mencari dengan nama domain, bukan mengisolasi. Lihat bagian 1.8, 1.9, dan 2.2.

</details>

**2. Skenario keputusan.** Dimas meminta satu deteksi yang masih berguna enam bulan lagi untuk kampanye semacam `INC-2027-091`. Mana yang paling tepat?

- A. Memblokir permanen ketiga IP di buletin di `jkt-fw01`.
- B. Rule yang memberi alert bila akun login memakai sesi dari IP dan perangkat baru tanpa MFA baru, lalu membuat aturan inbox yang memindahkan atau menyembunyikan email dalam satu jam.
- C. Menyimpan SHA-256 lampiran HTML di EDR dan filter email tanpa masa berlaku.

<details><summary>Jawaban</summary>

B. Rule itu dibangun dari TTP (puncak Pyramid of Pain), sehingga tetap bekerja walaupun penyerang mengganti IP, domain, dan lampiran; buktinya, rule semacam itu menangkap `SOC-2027-0870` dari IP yang tidak ada di buletin. A keliru karena IP paling mudah diganti, salah satunya bahkan IP CDN, dan IP yang diblokir permanen akhirnya berpindah ke pemilik sah. C tidak salah sebagai pelengkap, tetapi penyerang cukup mengubah satu byte lampiran untuk lolos. Lihat bagian 1.4, 1.5, dan 2.4.

</details>

**3. Pertanyaan jebakan.** "IOC dari buletin resmi CSIRT tetap benar selamanya, jadi blocklist firewall tidak perlu diberi tanggal kedaluwarsa." Benarkah?

<details><summary>Jawaban</summary>

Tidak. IP dan domain berpindah tangan; `192.0.2.199` dari buletin Oktober 2026 kini dipakai server pembaruan vendor yang sah dan memicu `SOC-2027-0871`. NIST meminta setiap indikator dicatat beserta lamanya ia dianggap valid, STIX menyediakan `valid_until`, dan PT JAB menetapkan IP 30 hari, domain dan URL 90 hari, hash 365 hari kecuali terlihat lagi. IOC usang diarsipkan, tidak dibuang, karena masih berguna untuk sejarah. Lihat bagian 1.10.

</details>

**4. Skenario keputusan.** Buletin berlabel `TLP:AMBER`. Bambang ingin meneruskannya ke grup WhatsApp engineer NOC antar-ISP. Apa tanggapan yang tepat?

- A. Boleh, karena semua anggota grup adalah engineer ISP yang juga disasar.
- B. Tidak boleh ke grup itu; teruskan ke engineer NOC PT JAB yang perlu tahu, dan minta CSIRT sektor menerbitkan versi `TLP:GREEN` bila ingin dibagikan ke komunitas.
- C. Boleh, asalkan nama CSIRT pengirimnya dihapus dari buletin.

<details><summary>Jawaban</summary>

B. `TLP:AMBER` membatasi pembagian ke anggota organisasi penerima dan kliennya, hanya yang perlu tahu. Grup antar-ISP adalah komunitas di luar PT JAB, yang baru diizinkan pada `TLP:GREEN`, dan yang berhak mengubah label adalah sumbernya. A keliru karena relevansi tidak mengubah batas pembagian. C keliru karena menghapus nama sumber tidak mengubah label, malah menghilangkan informasi asal yang dibutuhkan penerima untuk menilai keandalannya. Lihat bagian 1.12.

</details>

**5. Jelaskan ulang.** Jelaskan kepada anggota keluargamu yang bukan orang IT, dalam tiga kalimat, kenapa tim keamanan tidak cukup memblokir alamat IP penyerang.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Alamat IP penyerang itu seperti plat nomor mobil maling: ia bisa menggantinya malam itu juga dengan biaya hampir nol, dan kadang plat itu ternyata milik mobil travel yang ditumpangi banyak orang tidak bersalah. Yang sulit diganti maling adalah caranya beraksi, misalnya selalu menyamar sebagai petugas PLN dan datang saat rumah kosong. Jadi kami tetap mencatat platnya, tetapi lebih mengandalkan satpam yang hafal modusnya, karena modus itu tetap sama walaupun mobilnya berganti."

Kesalahan yang sering muncul:
- Mengatakan IP sama sekali tidak berguna, padahal IP tetap dipakai untuk mencari jejak ke belakang dan sebagai salah satu petunjuk.
- Lupa menyebut masalah "mobil travel": satu IP bisa dipakai ribuan situs sah, sehingga memblokirnya bisa mengganggu orang tidak bersalah.
- Memakai istilah seperti TTP, IOA, atau CDN tanpa penjelasan kepada orang awam.

</details>

**6. Pertanyaan jebakan.** "STIX dan TAXII sama saja: keduanya nama lain untuk feed IOC." Benarkah?

<details><summary>Jawaban</summary>

Tidak. STIX adalah format penulisan informasi ancaman dalam JSON, dan isinya jauh lebih luas dari IOC: aktor, kampanye, TTP (Attack Pattern), malware, kerentanan, hubungan antarobjek, dan sighting. TAXII adalah protokol di atas HTTPS untuk mengambil dan mengirim data itu, misalnya lewat Collection. Feed adalah aliran IOC-nya; feed bisa memakai STIX dan TAXII, tetapi juga bisa berupa CSV atau email biasa. Lihat bagian 1.7 dan 1.11.

</details>

**7. Interview question (English).** "What is the difference between an IOC and an IOA, and how would you handle a threat intel bulletin that lists hashes, domains, and IP addresses for an active phishing campaign?"

<details><summary>Sample answer</summary>

"An IOC is a concrete artifact tied to an attack, like a file hash, a domain, a URL or an IP address. It is easy to search for, but it only matches what has already been reported and it ages quickly. An IOA is a behavioral signal that an attack is in progress regardless of the infrastructure used, for example a session being reused from a new IP without a fresh MFA prompt, followed by a new inbox rule that hides emails. That maps to the top of the Pyramid of Pain, so it survives the attacker changing IPs or files. With a bulletin, I first check its handling label, then load the IOCs with an expiry date and enrich them before acting: who owns the IP, whether it is a CDN or shared hosting, how old the domain is, and whether we have seen it daily for months. Then I search back over the campaign period, prioritizing hashes and domains because they are specific, and I use the IPs mainly as context. Matches are a starting point, so I rebuild the timeline: email opened, credentials posted, session reused, mailbox changed. Finally, anything new we find, such as a new attacker IP, goes back to the sharing community with our internal details removed."

What makes this answer strong: it defines both terms precisely, ties them to the Pyramid of Pain, shows a realistic workflow (TLP, expiry, enrichment, retro search, timeline), explicitly warns about shared infrastructure false positives, and closes the loop by sharing back.

</details>

## 8. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | NIST CSRC Glossary: indicator, indicator of compromise, tactics techniques and procedures, threat intelligence | https://csrc.nist.gov/glossary/term/indicator<br>https://csrc.nist.gov/glossary/term/indicator_of_compromise<br>https://csrc.nist.gov/glossary/term/tactics_techniques_and_procedures<br>https://csrc.nist.gov/glossary/term/threat_intelligence | primer (glosarium NIST) | diakses 2026-10-21 | Tinggi. Definisi dari SP 800-150, SP 800-61r3, CNSSI 4009-2022 |
| S2 | NIST SP 800-150: Guide to Cyber Threat Information Sharing | https://csrc.nist.gov/pubs/sp/800/150/final<br>https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-150.pdf | primer | 2016-10; diakses 2026-10-21 | Tinggi. Jenis threat information, contoh IOC, TTP, lima ciri indikator, pemakaian, kepercayaan sumber, data yang dicatat per indikator, retensi, TLP 1.0, sanitasi sebelum berbagi, ISAC dan AIS sebagai mitra |
| S3 | David J. Bianco: The Pyramid of Pain | https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html | primer (tulisan asli pencetus model) | 2013-03-01, pembaruan 2014-01-17; diakses 2026-10-21 | Tinggi untuk urutan dan alasan tiap tingkat. Label rasa sakit ada pada gambar, bukan di teks (lihat catatan sumber) |
| S4 | OASIS: STIX Version 2.1 (OASIS Standard) | https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html | primer (standar OASIS) | 2021-06-10; diakses 2026-10-21 | Tinggi. Daftar objek, Indicator (pattern, pattern_type, valid_from, valid_until), Relationship, Sighting, contoh pola hash |
| S5 | OASIS: TAXII Version 2.1 (OASIS Standard) | https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html | primer (standar OASIS) | 2021-06-10; diakses 2026-10-21 | Tinggi. Protokol HTTPS dan REST, Collection, Channel belum didefinisikan, tidak terbatas STIX |
| S6 | FIRST: Traffic Light Protocol (TLP) version 2.0 | https://www.first.org/tlp/ | primer (standar FIRST) | 2022-08; diakses 2026-10-21 | Tinggi. Empat label, AMBER+STRICT, cara penulisan dan penempatan label |
| S7 | CISA: Traffic Light Protocol (TLP) Definitions and Usage | https://www.cisa.gov/news-events/news/traffic-light-protocol-tlp-definitions-and-usage | primer | diakses 2026-10-21 | Tinggi. Adopsi TLP 2.0 oleh CISA sejak 2022-11-01 |
| S8 | CISA: Automated Indicator Sharing (AIS) | https://www.cisa.gov/topics/cyber-threats-and-advisories/information-sharing/automated-indicator-sharing-ais | primer | diakses 2026-10-21 | Tinggi. Layanan gratis, STIX/TAXII, klien TAXII 2.1, sertifikasi Maret 2016 |
| S9 | MITRE ATT&CK: T1566 Phishing, T1539 Steal Web Session Cookie, T1564.008 Email Hiding Rules, Versions | https://attack.mitre.org/techniques/T1566/<br>https://attack.mitre.org/techniques/T1539/<br>https://attack.mitre.org/techniques/T1564/008/<br>https://attack.mitre.org/resources/versions/ | primer | v20.0 (2026-10-13); diakses 2026-10-21 | Tinggi. Nomor technique, tactic (TA0005 bernama Stealth), sub-technique T1566 |
| S10 | CrowdStrike: What is an Indicator of Attack (IOA)? | https://www.crowdstrike.com/cybersecurity-101/threat-intelligence/indicators-of-attack-ioa/ | sekunder (vendor) | diakses 2026-10-21 | Sedang. Sumber istilah IOA yang paling sering dikutip; materi pemasaran sehingga condong memihak IOA |
| S11 | CrowdStrike: What is Cyber Threat Intelligence? | https://www.crowdstrike.com/en-us/cybersecurity-101/threat-intelligence/ | sekunder (vendor) | diakses 2026-10-21 | Sedang. Versi tiga tingkat: IOC di tactical, TTP di operational |
| S12 | MWR InfoSecurity (dengan CPNI dan CERT-UK): Threat Intelligence: Collecting, Analysing, Evaluating | https://nsarchive.gwu.edu/media/17212/ocr | sekunder (whitepaper industri bersama lembaga pemerintah Inggris; salinan OCR di arsip GWU) | sekitar 2015; diakses 2026-10-21 | Sedang-tinggi. Versi empat tingkat dan pembaca tiap tingkat. Tahun terbit tidak tercantum di salinan OCR |
| S13 | MISP Project: misp-warninglists | https://github.com/MISP/misp-warninglists | sekunder (proyek open source) | diakses 2026-10-21 | Sedang-tinggi. Daftar false positive umum: range CDN dan cloud, resolver publik, domain populer; kategori false_positive dan known |
| S14 | MISP Project: Decaying of Indicators | https://www.misp-project.org/2019/09/12/Decaying-Of-Indicators.html | sekunder (proyek open source) | 2019-09-12; diakses 2026-10-21 | Sedang-tinggi. Model base_score, lifetime, decay, sighting mengembalikan skor |
| S15 | Peraturan Badan Siber dan Sandi Negara Nomor 10 Tahun 2020 tentang Tim Tanggap Insiden Siber | https://csirt.patikab.go.id/./assets/event/Peraturan-BSSN-Nomor-10-Tahun-2020-_sign.pdf | primer (teks regulasi; salinan di situs CSIRT Kabupaten Pati) | ditetapkan 2020-12-15; diakses 2026-10-21 | Tinggi untuk isi pasal yang dikutip (jenis TTIS, sektor). Salinan bukan dari situs resmi BSSN |
| S16 | Cyber Policy Portal: ID-SIRTII/CC | https://database.cyberpolicyportal.org/en/entity/ctar6pjn1su | sekunder (basis data kebijakan siber) | diakses 2026-10-21 | Sedang. Tahun pembentukan 2007 dan status bagian BSSN sejak 2017 belum dikonfirmasi dari situs resmi BSSN |

**Catatan sumber:** label rasa sakit di tabel bagian 1.5 (Trivial, Easy, Simple, Annoying, Challenging, Tough!) tertulis pada gambar piramida di tulisan asli Bianco [S3], bukan di teks tulisannya, sehingga tidak bisa dikutip dari teks; urutan tingkat dan alasan tiap tingkat berasal dari teksnya. Istilah IOA tidak punya definisi di glosarium NIST; penjelasannya bersumber dari vendor [S10] dan ditulis ulang sebagai deteksi berbasis perilaku. Pembagian strategic, operational, dan tactical tidak seragam antar sumber [S11][S12]; tabel bagian 3.2 menyandingkan dua versi. Keterangan bahwa TLP:CLEAR adalah label publik pengganti TLP:WHITE disimpulkan dari perbandingan tabel TLP 1.0 di SP 800-150 [S2] dan daftar label TLP 2.0 [S6]; halaman FIRST yang diperiksa tidak menyebut WHITE secara langsung. Sejarah Id-SIRTII/CC [S16] belum dikonfirmasi dari situs BSSN. Angka umur IOC di bagian 1.10 adalah kebijakan fiktif PT JAB, bukan angka baku; tidak ada standar yang menetapkan umur IOC untuk semua organisasi. Seluruh isi PT JAB (buletin `BK-2027-031`, CSIRT sektor sebagai pengirim, alert `SOC-2027-0867` sampai `SOC-2027-0871`, insiden `INC-2027-091`, akun, host, IP, domain, hash, skor reputasi, dan angka sambungan) adalah contoh fiktif.
