---
day: 07
title: 'Active Directory dan autentikasi: domain, DC, akun, group, LDAP, Kerberos, NTLM, GPO, dan Domain Admins'
researched_on: 2026-10-21
versions_checked: 'Microsoft Learn: AD DS overview, Understanding the AD Logical Model, AD Security Groups, Privileged Accounts and Groups Guide, Best practices for securing AD, Group Policy overview, gMSA overview (diakses 2026-10-21); Kerberos authentication overview (ms.date 2026-09-14); NTLM overview (ms.date 2025-04-17); Deprecated features in the Windows client (ms.date 2026-09-23); audit event 4624, 4625, 4728, 4768, 4769, 4776; RFC 4120 (Kerberos V5, Juli 2005); RFC 4511 (LDAP, Juni 2006); MITRE ATT&CK T1558.003 v1.3, T1558.001 v1.2, T1550.002 v2.0; ASD ACSC dan mitra, Detecting and Mitigating Active Directory Compromises (revisi 2026-09-15)'
---

# Day 07: Active Directory dan autentikasi (domain, DC, akun, group, LDAP, Kerberos, NTLM, GPO, dan Domain Admins)

Cakupan: istilah dasar Active Directory yang muncul di hampir setiap alert dan insiden di jaringan kantor berbasis Windows, yaitu domain, domain controller, forest, OU, akun user, computer, dan service, group, LDAP, Kerberos dengan TGT dan service ticket, NTLM, GPO, privileged group seperti Domain Admins, serta alasan AD menjadi target utama penyerang.

## Ide inti

Di kantor yang memakai Windows, hampir semua pertanyaan "siapa kamu" dan "boleh apa" dijawab oleh satu sistem pusat: Active Directory (AD). AD menyimpan daftar semua orang, komputer, dan aplikasi yang dikenal perusahaan, mengelompokkan mereka, memeriksa password mereka saat login, menerbitkan bukti login yang dipakai ke server lain, dan menyebarkan aturan konfigurasi ke semua komputer. Karena semua keputusan itu berpusat di satu tempat, AD sekaligus menjadi titik paling kuat dan paling berbahaya di jaringan: siapa pun yang menguasai AD menguasai hampir seluruh komputer dan akun yang dikelolanya.

Untuk analyst, ini berarti dua hal. Pertama, banyak alert yang tampaknya kecil (satu nama ditambahkan ke sebuah grup, satu akun meminta banyak tiket) sebenarnya menyentuh kunci seluruh gedung. Kedua, untuk membaca alert itu kamu perlu tahu bagaimana login di jaringan Windows bekerja: siapa yang memeriksa password, bukti apa yang dibawa ke server, dan di komputer mana jejaknya tercatat.

Bayangkan satu gedung perkantoran besar dengan satu kantor administrasi pusat. Kantor administrasi menyimpan data semua penghuni, menerbitkan kartu akses, dan menetapkan peraturan gedung yang berlaku di semua lantai. Saat pagi kamu datang, kantor administrasi memeriksa identitasmu lalu memberimu gelang masuk gedung. Gelang itu kamu tunjukkan setiap kali ingin masuk ruangan tertentu, dan kantor administrasi menukarnya dengan tiket khusus ruangan itu; penjaga ruangan cukup memeriksa tiket, tanpa menelepon siapa pun. Di gedung lama, penjaga ruangan masih menelepon kantor pusat setiap kali ada tamu. Lalu ada segelintir orang pemegang kunci master yang bisa membuka semua pintu. Batas analogi ini perlu diingat sejak awal: di dunia digital, "kunci master" dan "stempel pembuat gelang" bisa disalin tanpa jejak fisik dan dipakai dari jauh, gelang yang sudah terbit tetap berlaku sampai kedaluwarsa walaupun pemiliknya sudah dipecat, dan hampir semua penghuni boleh membaca buku direktori gedung, termasuk penyusup yang berhasil memegang kartu siapa pun.

```
                      corp.jab.example (domain)
                                 |
              +------------------+------------------+
              |                                     |
         JKT-DC01                              JKT-DC02          domain controller:
   (salinan lengkap data AD)  <-- replikasi -->  (salinan lengkap)  data akun, password,
              |                                                    group, GPO; KDC Kerberos
   +----------+-----------+--------------+---------------+
   |          |           |              |               |
 user      computer     service        group            GPO
 account   account      account        (Domain Admins,  (aturan konfigurasi
 gilang.   JKT-WS-1072$ svc-backup     GG-SOC, ...)     ke OU)
 ramadhan

 login laptop  : laptop --(bukti password)--> DC: terbit TGT (gelang)      [4768 di DC]
 buka share    : laptop --(TGT)--> DC: terbit service ticket (tiket ruangan) [4769 di DC]
                 laptop --(service ticket)--> JKT-FS01: login berhasil       [4624 di server]
 cara lama     : laptop --> server --(tanya setiap kali)--> DC   (NTLM)      [4776 di DC]
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), sebuah ISP (penyedia layanan internet) fiktif dengan sekitar 1.200 karyawan dan sekitar 400 ribu pelanggan internet rumah. Semua laptop dan server Windows PT JAB tergabung dalam domain `corp.jab.example` yang dikelola dua domain controller, `JKT-DC01` dan `JKT-DC02`, di data center Jakarta. Akun karyawan memakai nama login seperti `gilang.ramadhan@jab.example`, sedangkan admin punya akun terpisah berawalan `adm.` yang hanya dipakai lewat jump host `JKT-JUMP01` (komputer khusus administrasi). Perusahaan ini pernah mengalami dua insiden yang menyentuh AD: `INC-2026-023`, ketika password sebuah akun layanan berhasil ditebak penyerang lewat teknik Kerberoasting, dan `INC-2026-024`, ketika penyerang menguasai seluruh domain dengan menyalahgunakan template sertifikat yang salah konfigurasi.

Kamu adalah analyst L1 (lini pertama yang memeriksa setiap alert) yang sedang menjalani minggu kedua orientasi di SOC (Security Operations Center) PT JAB. Selasa 2027-08-10 pukul 10:00, mentormu Sari Kusuma (analyst L2) dan Agung Prabowo (Lead Infrastruktur) mengajakmu duduk di depan konsol administrasi AD di `JKT-JUMP01` untuk melihat struktur `corp.jab.example`. Empat puluh enam menit kemudian, layar SOC memunculkan alert `SOC-2027-0838` berprioritas P1: akun layanan `svc-backup` baru saja ditambahkan ke grup `Domain Admins`, dan tidak ada change request (permintaan perubahan resmi) yang cocok. Sari menoleh ke kamu:

> "Pas sekali. Sebelum kita bedah alert ini, aku mau kamu paham dulu apa yang sedang kita lihat. Jadi: domain itu apa, dan kenapa ada dua DC? Kenapa akun-akun ini disusun dalam folder seperti OU, dan forest itu apa? Bedanya akun user, akun komputer, dan akun layanan seperti svc-backup? Grup itu buat apa, kenapa hak tidak diberikan langsung ke orang? VPN kita juga mengecek grup karyawan ke AD; caranya bagaimana? Waktu Gilang login di laptopnya tadi pagi, sebenarnya apa yang terjadi? Kenapa NTLM masih muncul di log padahal katanya sudah ada Kerberos? Aturan kunci layar 10 menit di semua laptop itu datang dari mana? Kenapa satu nama masuk ke Domain Admins langsung jadi P1? Terakhir, kenapa penyerang selalu mengincar AD?"

Pesan itu memuat sepuluh pertanyaan:

1. Apa itu domain dan domain controller, dan kenapa ada dua DC?
2. Apa itu OU dan forest?
3. Apa beda akun user, akun komputer, dan akun layanan?
4. Untuk apa group, dan kenapa hak diberikan lewat group?
5. Bagaimana aplikasi lain (misalnya VPN) membaca data AD?
6. Apa yang terjadi saat seseorang login di laptop domain?
7. Kenapa NTLM masih dipakai?
8. Dari mana aturan konfigurasi seperti kunci layar 10 menit datang?
9. Kenapa penambahan anggota `Domain Admins` diperlakukan sebagai P1?
10. Kenapa penyerang mengincar AD?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, pertanyaan 6 di bagian 1.6, pertanyaan 7 di bagian 1.7, pertanyaan 8 di bagian 1.8, pertanyaan 9 di bagian 1.9, dan pertanyaan 10 di bagian 1.10. Bagian 2 membedah alert `SOC-2027-0838`, jejak login Gilang, satu alert NTLM, dan satu alert yang berujung insiden.

**Kapan relevan:** setiap kali alert menyebut akun domain, grup, domain controller, Event ID Windows seperti 4624, 4625, 4728, 4768, 4769, atau 4776; saat menilai seberapa serius sebuah perubahan akun atau grup; saat menelusuri dari mana sebuah login berasal; dan saat menjawab pertanyaan interview tentang Kerberos, NTLM, atau serangan AD.
**Kapan bukan jawaban:** istilah Day ini tidak menjelaskan cara memasang atau mengonfigurasi AD langkah demi langkah, dan tidak menggantikan prosedur penanganan insiden. Untuk identitas di cloud (Microsoft Entra ID, login aplikasi web, MFA), dasarnya ada di Day 06 dan Day 08; AD hanya salah satu sumber identitas di perusahaan modern.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day 01 (authentication, authorization, accounting, least privilege, zero trust, attack surface) dan Day 02 (IP address, port, DNS) tidak diulang di tabel ini, tetapi definisinya diulang satu kalimat di tempat yang membutuhkan. Tabel ini memuat semua istilah AD yang dipakai Day ini; cari kolom ketiga bila sebuah istilah terasa abstrak.

| Istilah | Arti singkat | Padanan sehari-hari |
|---|---|---|
| Directory service | Basis data terstruktur berisi informasi orang, komputer, dan sumber daya jaringan, plus cara mencarinya | Buku direktori penghuni gedung |
| Active Directory (AD DS) | Directory service buatan Microsoft untuk jaringan Windows | Kantor administrasi gedung beserta arsipnya |
| Domain | Satu wilayah pengelolaan di AD dengan daftar akun dan aturan bersama | Satu gedung perkantoran |
| Domain controller (DC) | Server yang menyimpan salinan data AD dan melayani login | Kantor administrasi yang menyimpan data penghuni dan menerbitkan kartu akses |
| Replikasi | Penyalinan perubahan data AD antar DC | Dua kantor administrasi yang saling menyalin arsip setiap ada perubahan |
| Forest | Kumpulan satu atau lebih domain yang berbagi struktur dan katalog | Kawasan perkantoran beberapa gedung dengan aturan dasar yang sama |
| Organizational unit (OU) | Wadah di dalam domain untuk mengelompokkan objek demi pengaturan dan pendelegasian | Pembagian lantai atau sayap gedung |
| Object | Satu entri di AD: user, computer, group, OU, GPO | Satu kartu data di arsip |
| User account | Akun milik satu orang | Kartu identitas penghuni |
| Computer account | Akun milik satu komputer yang tergabung ke domain | Kartu registrasi perangkat milik gedung |
| Service account | Akun yang dipakai aplikasi atau layanan, bukan orang | Kartu akses untuk mesin otomatis |
| gMSA | Group Managed Service Account, akun layanan yang password-nya dikelola Windows | Kartu akses mesin yang diganti otomatis oleh kantor administrasi |
| SID | Security identifier, nomor unik permanen untuk setiap akun dan group | Nomor induk penghuni yang tidak pernah dipakai ulang |
| SPN | Service principal name, nama unik sebuah layanan untuk Kerberos | Nomor ruangan resmi yang tercatat di kantor administrasi |
| Security group | Kumpulan akun yang diberi hak atau izin bersama | Daftar akses per kelompok |
| Distribution group | Kumpulan alamat untuk email, tanpa fungsi keamanan | Milis pengumuman |
| LDAP | Protokol untuk membaca dan mengubah isi directory | Loket informasi direktori |
| Kerberos | Protokol autentikasi berbasis tiket yang menjadi bawaan AD | Sistem gelang masuk gedung dan tiket per ruangan |
| KDC | Key Distribution Center, layanan penerbit tiket Kerberos di setiap DC | Loket penerbit gelang dan tiket di kantor administrasi |
| TGT | Ticket-granting ticket, tiket awal setelah login, dipakai untuk meminta tiket lain | Gelang masuk gedung |
| Service ticket | Tiket untuk satu layanan tertentu | Tiket masuk satu ruangan |
| krbtgt | Akun khusus yang kuncinya dipakai KDC untuk mengamankan semua TGT | Stempel rahasia kantor administrasi untuk gelang |
| NTLM | Protokol autentikasi lama berbasis tantangan dan jawaban | Penjaga ruangan yang menelepon kantor pusat setiap kali ada tamu |
| Hash password | Nilai tetap hasil perhitungan satu arah dari password (dibahas di Day 05) | Sidik jari password |
| Negotiate | Mekanisme Windows yang memilih Kerberos dan memakai NTLM hanya bila perlu | Resepsionis yang memilih jalur gelang, dan memakai telepon hanya bila terpaksa |
| Group Policy / GPO | Fitur dan objek berisi aturan konfigurasi yang diterapkan ke komputer dan user | Peraturan gedung yang otomatis berlaku di semua lantai |
| Privileged group | Grup dengan hak sangat tinggi, misalnya Domain Admins | Kelompok pemegang kunci master |
| Domain Admins | Grup admin penuh satu domain | Pemegang kunci master |
| Event ID | Nomor jenis kejadian di log Windows, misalnya 4624 | Kode jenis catatan di buku satpam |

### 1.1 Active Directory, domain, dan domain controller

Pertanyaan pertama Sari muncul karena konsol di depanmu menampilkan nama `corp.jab.example` di paling atas, dan dua server, `JKT-DC01` dan `JKT-DC02`, di folder bernama Domain Controllers.

**Apa itu:** directory adalah struktur bertingkat yang menyimpan informasi tentang objek di jaringan, dan directory service seperti Active Directory Domain Services (AD DS) menyediakan cara menyimpan data itu dan membuatnya tersedia bagi user dan admin [S1]. AD DS menyimpan, misalnya, nama, password, dan nomor telepon akun user, serta data komputer, server, printer, dan group [S1]. Keamanan menyatu dengan AD DS lewat autentikasi saat login dan kontrol akses ke objek di directory: dengan satu username dan password, karyawan bisa mengakses sumber daya di mana pun di jaringan sesuai haknya [S1]. Sehari-hari orang menyingkatnya menjadi AD.

Domain adalah satu partisi (pembagian wilayah) di dalam AD. Domain memberi identitas yang dibuat sekali dan bisa dipakai di komputer mana pun yang tergabung, menyediakan layanan autentikasi, dan menjadi satuan replikasi [S2]. Domain controller (DC) adalah server yang menjalankan AD DS untuk sebuah domain: DC menyimpan akun dan kredensial user (seperti password atau sertifikat) dan melayani autentikasi, termasuk memberi data tambahan seperti keanggotaan group yang dipakai untuk menentukan akses [S2]. Semua DC dalam satu domain ikut replikasi dan masing-masing memegang salinan lengkap data domain; perubahan di satu DC disalin ke DC lain [S1]. Karena itu semua DC setara dan dikelola sebagai satu kesatuan [S2].

**Analogi:** domain adalah satu gedung perkantoran dengan satu kantor administrasi pusat. Kantor administrasi (DC) menyimpan data semua penghuni, memeriksa identitas saat penghuni datang, dan menerbitkan kartu akses. Batasnya ada dua. Pertama, "gedung" di dunia digital tidak terikat lokasi: domain `corp.jab.example` mencakup kantor Jakarta dan Bandung sekaligus. Kedua, kantor administrasinya bisa ada beberapa salinan, dan setiap salinan memegang arsip lengkap; mencuri arsip dari satu DC sama dengan mencuri arsip seluruh domain.

**Cara kerja:**

```
 1. Admin membuat akun "gilang.ramadhan" di JKT-DC01
 2. JKT-DC01 menyalin perubahan itu ke JKT-DC02 (replikasi)
 3. Pagi hari, laptop Gilang mencari DC terdekat yang aktif
 4. DC mana pun yang menjawab bisa memeriksa password Gilang,
    karena keduanya punya salinan lengkap
 5. Bila JKT-DC01 mati, JKT-DC02 tetap melayani login (availability)
```

Dua DC adalah bentuk redundansi untuk availability (Day 01): login seluruh kantor tidak berhenti hanya karena satu server rusak. Komputer biasanya menemukan DC lewat DNS (Day 02 bagian 1.9 menjelaskan DNS sebagai buku telepon jaringan), jadi DNS internal juga bagian penting dari AD.

**Contoh di PT JAB:** `corp.jab.example` adalah domain internal PT JAB. `JKT-DC01` dan `JKT-DC02` berada di data center Jakarta. Server `JKT-SYNC01` menjalankan Microsoft Entra Connect, yang menyalin sebagian besar akun karyawan ke Microsoft Entra ID (layanan identitas cloud Microsoft) supaya karyawan memakai akun yang sama untuk email Microsoft 365. Akibatnya, perubahan akun di AD ikut mengalir ke cloud; identitas cloud dibahas di Day 06 dan Day 08.

**Beda domain AD dengan nama domain internet:** `jab.example` adalah nama domain di DNS untuk situs dan email PT JAB. `corp.jab.example` adalah nama domain AD, yang kebetulan juga memakai format nama DNS. Keduanya berkaitan karena AD bergantung pada DNS, tetapi domain AD adalah wilayah pengelolaan akun, bukan alamat situs.

**Salah paham umum:**
- "DC hanya server biasa yang kebetulan menyimpan daftar user." Microsoft menyebut penyerang yang mendapat akses istimewa ke DC bisa mengubah, merusak, dan menghancurkan basis data AD, sehingga mengancam semua sistem dan akun yang dikelola AD [S5]. DC adalah aset paling kritis di jaringan Windows.

### 1.2 Forest, tree, dan OU (singkat)

Pertanyaan kedua Sari muncul karena di bawah `corp.jab.example` terlihat banyak "folder" seperti `Jakarta`, `Bandung`, `Admin`, dan `Akun-Layanan`. Folder itu adalah OU, sedangkan forest berada satu tingkat di atas domain.

**Apa itu:** AD menyusun objek dalam wadah bertingkat. Wadah teratas adalah forest, di dalam forest ada domain, dan di dalam domain ada organizational unit (OU) [S2]. Forest adalah kumpulan satu atau lebih domain yang berbagi struktur logis, schema (definisi jenis objek dan atributnya), konfigurasi, dan global catalog (katalog untuk mencari objek di seluruh forest) [S2]. Domain di dalam satu forest otomatis saling percaya dua arah [S2]. Beberapa domain yang namanya bersambung (misalnya `corp.jab.example` dan `bdg.corp.jab.example`) disebut tree; banyak organisasi menengah, termasuk PT JAB, cukup memakai satu forest dengan satu domain.

OU adalah wadah di dalam domain untuk mengelompokkan objek demi keperluan administrasi, terutama penerapan Group Policy (bagian 1.8) dan pendelegasian wewenang [S2]. OU adalah wadah terendah tempat aturan Group Policy bisa ditautkan [S15]. Dengan pendelegasian, pengelola bisa menyerahkan kendali penuh atau terbatas atas objek di sebuah OU kepada user atau group tertentu [S2], misalnya tim helpdesk Bandung boleh mereset password hanya untuk akun di OU Bandung.

**Analogi:** forest adalah kawasan perkantoran berisi beberapa gedung yang berbagi aturan dasar dan satu buku direktori bersama. OU adalah pembagian lantai atau sayap di dalam satu gedung, supaya peraturan dan petugas bisa diatur per lantai. Batasnya: gedung-gedung dalam satu kawasan digital otomatis saling percaya, sesuatu yang jarang terjadi di kawasan nyata. Dan menaruh seseorang di "lantai admin" tidak memberinya kunci apa pun; hak datang dari group (bagian 1.4), bukan dari letak OU.

**Cara kerja:** struktur OU PT JAB yang kamu lihat di konsol, diringkas:

```
corp.jab.example                      (domain; forest dengan satu domain)
 +-- Domain Controllers                (OU bawaan: JKT-DC01, JKT-DC02)
 +-- Users                             (container bawaan: Domain Admins, Domain Users, ...)
 +-- JAB
      +-- Jakarta
      |    +-- Karyawan                (OU per divisi: Keuangan, NOC, SOC, Teknologi, ...)
      |    +-- Komputer
      |         +-- Laptop             (JKT-WS-0815, JKT-WS-1072, ...)
      |         +-- Server             (JKT-FS01, JKT-BKP01, JKT-JUMP01, ...)
      +-- Bandung                      (Karyawan, Komputer)
      +-- Admin                        (akun adm.*: adm.agung, adm.fajar, ...)
      +-- Akun-Layanan                 (svc-backup, svc-scan, gmsa-* ...)
```

Lokasi sebuah objek ditulis sebagai distinguished name (DN), misalnya `CN=svc-backup,OU=Akun-Layanan,OU=JAB,DC=corp,DC=jab,DC=example`. Bentuk ini sering muncul di log, termasuk di alert `SOC-2027-0838`.

**Contoh di PT JAB:** aturan "kunci layar setelah 10 menit" ditautkan ke OU `Laptop`, jadi otomatis berlaku untuk semua laptop di dalamnya, sementara server di OU `Server` mendapat aturan yang berbeda. Tim helpdesk Bandung diberi wewenang reset password hanya di OU `Bandung\Karyawan`.

**Beda OU dengan group:** OU menjawab "objek ini disimpan dan diatur di mana" (untuk GPO dan pendelegasian). Group menjawab "akun ini boleh apa" (untuk izin dan hak). Satu akun hanya berada di satu OU, tetapi bisa menjadi anggota banyak group.

### 1.3 Akun: user, computer, dan service account

Pertanyaan ketiga Sari menyangkut tiga jenis akun yang terlihat berdampingan di konsol: `gilang.ramadhan`, `JKT-WS-1072`, dan `svc-backup`. Ketiganya bisa login ke domain, tetapi pemilik dan risikonya berbeda.

**Apa itu:** di AD, setiap pihak yang bisa diautentikasi disebut security principal: user, komputer, atau layanan [S10]. Ada tiga jenis akun yang perlu kamu kenali.

- **User account** adalah akun milik satu orang. Di PT JAB nama loginnya berbentuk `<nama>@jab.example`, disebut UPN (user principal name), dan karyawan yang butuh hak admin diberi akun kedua terpisah berawalan `adm.`.
- **Computer account** adalah akun milik satu komputer yang sudah tergabung (joined) ke domain. Setiap perangkat di domain punya akun dan password sendiri, dan secara bawaan komputer anggota domain mengajukan penggantian password akunnya setiap 30 hari [S7]. Di log, nama akun komputer diakhiri tanda `$`, misalnya `JKT-WS-1072$` [S18]. Semua workstation dan server yang tergabung otomatis menjadi anggota grup `Domain Computers` [S4].
- **Service account** adalah akun yang dipakai aplikasi atau layanan untuk berjalan dan mengakses sumber daya lain, misalnya software backup yang perlu membaca file di banyak server. Akun ini tidak dipakai orang untuk login sehari-hari, tetapi sering punya hak luas dan password yang jarang diganti.

Untuk akun layanan, Windows punya jenis khusus bernama managed service account. Group Managed Service Account (gMSA) adalah akun layanan yang password-nya dikelola sistem operasi, bukan admin: kuncinya berganti berkala dan diambil server anggota dari DC, sehingga tidak ada manusia yang perlu mengetik atau menyimpan password-nya [S6].

Setiap akun dan group punya SID (security identifier), nomor unik yang diterbitkan DC dan tidak pernah dipakai ulang untuk akun atau group lain, walaupun akun lamanya sudah dihapus [S18]. Nama akun bisa diganti; SID tetap.

**Analogi:** user account adalah kartu identitas penghuni. Computer account adalah kartu registrasi perangkat milik gedung: hanya perangkat terdaftar yang boleh tersambung ke jaringan gedung. Service account adalah kartu akses untuk mesin otomatis, misalnya robot pengantar dokumen yang berkeliling semua lantai malam hari. Batasnya: kartu mesin sering membuka lebih banyak pintu daripada kartu penghuni biasa, tidak ada wajah yang bisa dicocokkan, dan jarang diganti, sehingga pencurian kartu ini lama tidak ketahuan.

**Cara kerja:** tabel berikut merangkum perbedaan ketiganya; perhatikan kolom Risiko khas, karena di situlah kebanyakan temuan SOC berasal.

| Jenis | Pemilik | Contoh di PT JAB | Password diganti oleh | Risiko khas |
|---|---|---|---|---|
| User | Satu orang | `gilang.ramadhan`, `adm.fajar` | Pemilik akun | Phishing, password dipakai ulang, akun admin dipakai untuk browsing |
| Computer | Satu komputer | `JKT-WS-1072$`, `JKT-FS01$` | Komputer itu sendiri, bawaan 30 hari [S7] | Komputer yang dikuasai penyerang bisa bertindak atas nama akunnya |
| Service (biasa) | Aplikasi | `svc-backup`, `svc-scan` | Admin, sering tidak pernah | Hak berlebihan, password lemah dan lama, target Kerberoasting |
| gMSA | Aplikasi | `gmsa-sqlrpt$` | Windows, otomatis [S6] | Lebih kecil, selama hak aksesnya tetap dibatasi |

**Contoh di PT JAB:** `svc-backup` adalah akun layanan software backup di `JKT-BKP01`. Akun ini dibuat tahun 2019 sebagai akun user biasa, password-nya diketik admin saat itu dan belum pernah diganti. Setelah `INC-2026-023`, ketika password akun layanan lain berhasil ditebak penyerang, Agung memasukkan semua akun `svc-*` ke daftar migrasi ke gMSA; `svc-backup` belum termasuk yang selesai.

**Beda service account dengan akun admin:** akun admin dipakai manusia untuk tugas administrasi dan seharusnya hanya aktif saat dipakai. Akun layanan dipakai terus-menerus oleh mesin. Akun layanan tidak seharusnya punya hak admin domain; aplikasinya cukup diberi hak yang dibutuhkan saja (least privilege, Day 01 bagian 1.7).

**Salah paham umum:**
- "Akun komputer bukan akun sungguhan, jadi tidak perlu dipantau." Akun komputer bisa login ke domain dan memegang hak. Komputer yang sudah dikuasai penyerang bisa memakai akun komputernya untuk bertindak di jaringan.

### 1.4 Group: security group dan distribution group

Pertanyaan keempat Sari ("kenapa hak tidak diberikan langsung ke orang") terkait langsung dengan alert yang sedang menunggu: yang berubah di `SOC-2027-0838` bukan akun, melainkan isi sebuah group.

**Apa itu:** group adalah kumpulan akun (dan group lain) yang dikelola sebagai satu kesatuan. AD punya dua jenis group [S3]:

- **Security group** dipakai untuk memberi hak (user rights, yaitu kemampuan di tingkat sistem seperti boleh login ke server) dan izin (permissions, yaitu akses ke sumber daya seperti folder bersama) [S3]. Microsoft menyarankan izin ke sumber daya diberikan ke security group, bukan ke user satu per satu: izin cukup diatur sekali di group, dan setiap akun yang ditambahkan ke group langsung mendapat hak dan izin group itu [S3].
- **Distribution group** hanya untuk daftar email dan tidak punya fungsi keamanan, sehingga tidak bisa dipakai untuk memberi izin [S3].

Group juga punya cakupan (scope) yang menentukan anggota dari mana yang boleh masuk dan di mana group itu bisa dipakai: domain local, global, dan universal [S3]. Untuk analyst, cukup diingat bahwa `Domain Admins` adalah global security group, sedangkan `Enterprise Admins` dan `Schema Admins` adalah universal security group [S4]. Perbedaan ini menentukan Event ID yang muncul saat anggotanya berubah (bagian 2.1).

**Analogi:** daftar akses per kelompok. Satpam ruang arsip tidak menghafal 40 nama staf Keuangan; ia cukup memegang aturan "semua yang ada di daftar Keuangan boleh masuk". Batasnya: menambah satu nama ke daftar langsung memberi akses ke semua pintu yang memakai daftar itu, dan satu daftar bisa berisi daftar lain, sehingga satu perubahan kecil bisa memberi akses jauh lebih luas dari yang terlihat.

**Cara kerja:**

```
 izin folder \\JKT-FS01\SOC   -->  diberikan ke group GG-SOC (bukan ke orang)
 group GG-SOC                 -->  berisi: sari.kusuma, gilang.ramadhan, dwi.cahyono, ...
 karyawan baru masuk SOC      -->  admin cukup menambah akunnya ke GG-SOC
 karyawan pindah divisi       -->  admin cukup mengeluarkannya dari GG-SOC
```

Saat user login, DC memasukkan daftar group-nya ke dalam bukti login (bagian 1.6). Akibatnya, perubahan anggota group biasanya baru berlaku penuh setelah user login ulang atau tiketnya diperbarui.

**Contoh di PT JAB:** folder bersama milik divisi Keuangan di `JKT-FS01`, yang dulu terenkripsi pada insiden ransomware `INC-2026-017`, kini hanya bisa dibuka anggota group `GG-Keuangan-Share`. Saat audit, Nina Kartika (Manajer Risiko dan Kepatuhan TI) cukup meminta daftar anggota group itu, bukan memeriksa izin folder satu per satu.

**Beda group dengan role:** di banyak sistem modern, hak dikemas dalam role (peran) yang berisi kumpulan izin, lalu role diberikan ke orang; konsep ini (RBAC) dibahas di Day 06. Di AD, security group sering dipakai untuk menjalankan gagasan yang sama.

**Salah paham umum:**
- "Group yang namanya tidak berbau admin pasti tidak berbahaya." Group seperti `Backup Operators` bisa melewati batasan keamanan file untuk keperluan backup, dan `Group Policy Creator Owners` bisa membuat dan mengubah GPO [S4]. Bahaya ditentukan oleh hak yang dipegang group, bukan namanya.

### 1.5 LDAP: cara aplikasi membaca dan mengubah AD

Pertanyaan kelima Sari menyangkut VPN. Saat karyawan login ke `jkt-vpn01`, perangkat VPN perlu tahu apakah orang itu anggota group `GG-VPN-Users`. Perangkat itu bukan komputer Windows, jadi ia bertanya ke AD dengan bahasa standar: LDAP.

**Apa itu:** LDAP (Lightweight Directory Access Protocol) adalah protokol standar untuk mengakses layanan directory, yang dirumuskan di RFC 4511 [S8]. Lewat LDAP, aplikasi bisa mencari objek ("siapa saja anggota GG-VPN-Users?"), membaca atributnya, dan bila punya hak, mengubahnya. Di DC Windows, LDAP berjalan di port 389, LDAP dengan TLS (LDAPS) di port 636, dan global catalog di port 3268 [S9]. (Port adalah nomor layanan di sebuah perangkat; lihat Day 02 bagian 1.6. TLS, lapisan enkripsi, dibahas di Day 05.)

**Analogi:** loket informasi direktori gedung. Siapa pun yang memegang kartu penghuni bisa bertanya ke loket "siapa saja penghuni lantai 5" atau "apakah Gilang anggota tim SOC". Batasnya: secara bawaan, user biasa di domain AD bisa membaca sebagian besar isi directory walaupun hanya bisa mengubah sedikit [S4]. Penyusup yang berhasil memegang satu akun karyawan mana pun bisa memakai loket ini untuk memetakan seluruh gedung: siapa admin, akun layanan apa saja yang ada, dan server mana yang penting.

**Cara kerja:**

```
 karyawan --login VPN--> jkt-vpn01 --LDAP 636: "apakah X anggota GG-VPN-Users?"--> JKT-DC01
                                   <--------- "ya" / "tidak" ----------------------
           <--izinkan/tolak--
```

Aplikasi yang memakai LDAP biasanya login ke AD dengan akun layanannya sendiri sebelum bertanya. Karena itu satu perangkat jaringan bisa ikut menyimpan password akun layanan domain.

**Contoh di PT JAB:** `jkt-vpn01`, server RADIUS `jkt-radius01`, dan beberapa aplikasi internal membaca keanggotaan group lewat LDAP. Setelah `INC-2026-024`, Agung mewajibkan semua aplikasi memakai LDAPS di port 636, supaya pertanyaan dan jawaban LDAP tidak melintas jaringan tanpa enkripsi.

**Beda LDAP dengan AD:** AD adalah basis datanya; LDAP adalah salah satu bahasa untuk berbicara dengannya. Sistem directory lain di luar Microsoft juga memakai LDAP.

### 1.6 Kerberos: TGT dan service ticket

Pertanyaan keenam Sari ("apa yang terjadi saat Gilang login tadi pagi") adalah pertanyaan paling sering keluar di interview tentang AD, dan dasarnya dipakai untuk membaca hampir semua log login Windows.

**Apa itu:** Kerberos adalah protokol autentikasi untuk memverifikasi identitas user atau host, dan Windows memakai Kerberos versi 5 sebagai metode bawaan di domain [S10]. Kerberos melibatkan tiga pihak: klien yang bertindak atas nama user, layanan yang ingin diakses, dan Key Distribution Center (KDC) yang dipercaya keduanya; di Windows, KDC berjalan di setiap DC dan memakai basis data AD sebagai daftar akunnya [S10]. Spesifikasi standarnya, RFC 4120, menyebut Kerberos sebagai pihak ketiga tepercaya yang memakai kunci rahasia bersama, dan dirancang dengan anggapan bahwa penyerang bisa membaca, mengubah, dan menyisipkan paket di jaringan [S11].

Ada dua jenis tiket:

- **TGT (ticket-granting ticket)** diterbitkan KDC saat user login. TGT adalah kredensial yang membuat klien bisa meminta akses ke layanan tanpa mengirim password lagi; klien menyimpannya dan memakainya ulang sampai kedaluwarsa [S10]. Di domain Windows, umur maksimum TGT bawaan adalah 10 jam [S12].
- **Service ticket** diminta klien dengan menunjukkan TGT ke KDC, untuk satu layanan tertentu. Klien lalu menunjukkan service ticket langsung ke layanan tujuan. Karena tiket sudah berisi informasi untuk memverifikasi klien, layanan bisa mengautentikasi klien tanpa menghubungi DC untuk setiap koneksi [S10].

Service ticket disegel dengan kunci milik layanan tujuan, sehingga hanya layanan itu yang bisa membukanya [S11]. Layanan dikenali lewat SPN (service principal name), nama unik sebuah instance layanan yang selalu memuat nama host tempat layanan berjalan [S19]. Kerberos juga mendukung mutual authentication: klien bisa memastikan server di ujung sana memang server yang ia tuju [S10].

**Analogi:** gelang masuk gedung. Pagi hari kamu menunjukkan identitas di kantor administrasi (KDC) dan mendapat gelang (TGT) yang berlaku sampai sore. Setiap kali ingin masuk ruangan, kamu menunjukkan gelang di loket, dan loket memberimu tiket khusus ruangan itu (service ticket). Penjaga ruangan cukup memeriksa tiket yang dicap dengan stempel ruangannya, tanpa menelepon kantor administrasi. Batasnya ada tiga, dan ketiganya penting untuk security:

1. Gelang dan tiket tetap berlaku sampai kedaluwarsa walaupun pemiliknya sudah dipecat. Microsoft mencatat bahwa akun yang sudah dinonaktifkan bisa tetap mengakses layanan dengan tiket yang terbit sebelum akun dinonaktifkan [S12].
2. Loket menerbitkan tiket ruangan untuk siapa pun yang memakai gelang sah; boleh tidaknya masuk diputuskan penjaga ruangan, bukan loket. Celah ini yang dipakai Kerberoasting (bagian 1.10).
3. Semua gelang dicap dengan satu stempel rahasia kantor administrasi, yaitu kunci akun `krbtgt`. Siapa pun yang mencuri stempel itu bisa membuat gelang palsu untuk siapa saja (golden ticket, bagian 1.10).

**Cara kerja:** urutan yang terjadi saat Gilang login di laptop `JKT-WS-1072` lalu membuka folder bersama di `JKT-FS01`, disederhanakan dari RFC 4120 [S11] dan dokumentasi Microsoft [S10]:

```
 [laptop JKT-WS-1072]                [KDC di JKT-DC01]                [JKT-FS01]
        |                                    |                              |
 1. Gilang mengetik password                 |                              |
    laptop membuat bukti: cap waktu          |                              |
    dienkripsi kunci turunan password -----> | AS exchange                  |
        |                                    | cek bukti, cek akun aktif    |
        | <---------------- TGT -------------| (Event 4768 di DC)           |
 2. laptop minta tiket untuk dirinya         |                              |
    sendiri (JKT-WS-1072$) --- TGT --------> | TGS exchange                 |
        | <------- service ticket -----------| (Event 4769 di DC)           |
    Windows membuka sesi Gilang (Event 4624 Logon Type 2 di laptop)          |
        |                                    |                              |
 3. Gilang membuka \\JKT-FS01\SOC            |                              |
    laptop --- TGT, minta tiket JKT-FS01 --> | (Event 4769 di DC)           |
        | <------- service ticket -----------|                              |
 4. laptop --- service ticket ------------------------------------------>  |
        |                                    |   server membuka tiket dengan |
        |                                    |   kuncinya sendiri, tanpa     |
        |                                    |   bertanya ke DC              |
        |                                    |   (Event 4624 Logon Type 3)  |
```

Beberapa hal yang perlu diingat dari gambar itu:

- Password tidak dikirim mentah. Yang dikirim adalah bukti yang dienkripsi dengan kunci turunan password; jenis bukti standar ini tercatat sebagai pre-authentication type 2 di log [S18]. Kunci rahasia sebuah akun memang bisa diturunkan dari password-nya [S11], jadi password yang lemah tetap menghasilkan kunci yang lemah.
- Jam semua komputer harus kurang lebih sama. RFC 4120 menyebut jam host cukup "longgar" sinkron, biasanya dalam selisih sekitar 5 menit [S11]; bila selisihnya terlalu besar, DC menolak dengan kode kesalahan clock skew [S18].
- Event 4768 dan 4769 hanya tercatat di domain controller [S18][S19], sedangkan 4624 tercatat di komputer yang diakses, tempat sesi login dibuat [S16]. Satu login lengkap meninggalkan jejak di minimal dua tempat.
- Bila laptop sama sekali tidak bisa menghubungi DC (misalnya dibawa pulang tanpa VPN), Windows bisa memakai kredensial yang tersimpan di laptop dari login sebelumnya. Login seperti ini tercatat sebagai Logon Type 11 (CachedInteractive): DC tidak dihubungi untuk memverifikasi kredensial [S16].

**Contoh di PT JAB:** jejak lengkap login Gilang pagi ini, termasuk satu salah ketik password, dibedah di bagian 2.2.

**Beda TGT dengan service ticket:** TGT menjawab "orang ini sudah membuktikan identitasnya ke DC hari ini" dan hanya dipakai untuk berbicara dengan KDC. Service ticket menjawab "orang ini boleh dikenalkan ke layanan X" dan hanya bisa dibuka layanan X. Keduanya bukan izin akses: setelah tiket diterima, layanan tetap memeriksa izin (authorization, Day 01 bagian 1.2) berdasarkan akun dan group yang tercantum di tiket.

**Salah paham umum:**
- "Kerberos berarti tidak ada lagi yang bisa dicuri dari jaringan." Kerberos menghilangkan pengiriman password, tetapi tiket itu sendiri adalah benda berharga. Tiket yang dicuri dari memori komputer, atau tiket yang dienkripsi dengan password lemah, tetap bisa disalahgunakan.

### 1.7 NTLM: cara lama yang masih hidup

Pertanyaan ketujuh Sari muncul karena di log hari ini masih ada login dengan keterangan `NTLM`, padahal Kerberos sudah menjadi bawaan sejak lama.

**Apa itu:** NTLM adalah keluarga protokol autentikasi lama yang mencakup LAN Manager versi 1 dan 2 serta NTLM versi 1 dan 2 [S13]. NTLM memakai mekanisme tantangan dan jawaban (challenge-response) yang membuktikan ke server atau DC bahwa user tahu password akunnya [S13]. Bila akunnya akun domain, server yang dituju harus menghubungi DC untuk memverifikasi setiap kali butuh bukti akses baru; bila akunnya akun lokal, server memeriksa basis data akun lokalnya sendiri [S13].

Hash password di sini adalah sidik jari password: nilai tetap hasil perhitungan satu arah yang dibahas di Day 05. Jawaban NTLM dihitung dari hash itu, bukan dari password aslinya. Akibatnya, siapa pun yang memegang hash bisa menghitung jawaban yang benar tanpa pernah tahu password-nya; sifat ini menjadi dasar teknik pass-the-hash (bagian 1.10).

NTLM masih dipakai karena beberapa keadaan belum bisa memakai Kerberos: komputer yang menjadi anggota workgroup (tidak tergabung ke domain), login lokal di komputer yang bukan DC, dan aplikasi buatan Microsoft maupun pihak lain yang masih memakai NTLM [S13]. Di Windows, mekanisme Negotiate memilih Kerberos dan hanya memakai NTLM bila Kerberos tidak bisa dipakai oleh salah satu sistem yang terlibat atau bila aplikasi tidak memberi informasi yang cukup untuk Kerberos [S16]. Microsoft sudah menyatakan semua versi NTLM deprecated (tidak lagi dikembangkan) sejak Juni 2024 dan menghapus NTLMv1 mulai Windows 11 versi 24H2 dan Windows Server 2025 (bagian 5) [S14].

**Analogi:** penjaga ruangan yang menelepon kantor pusat setiap kali ada tamu. Tamu menyebut namanya, penjaga memberi soal acak, tamu menjawab dengan hitungan dari sidik jari password-nya, lalu penjaga menelepon kantor administrasi untuk bertanya apakah jawaban itu benar. Batasnya: yang dibuktikan hanyalah kepemilikan sidik jari, jadi pencuri sidik jari bisa lolos; dan tamu tidak bisa memastikan penjaga itu asli, karena NTLM tidak memungkinkan klien memverifikasi identitas server [S10].

**Cara kerja:**

```
 [klien]                       [server JKT-FS01]                  [DC]
    | -- "saya svc-scan" ---------> |                               |
    | <-- tantangan acak ---------- |                               |
    | -- jawaban (dihitung          |                               |
    |    dari hash password) -----> | -- teruskan untuk dicek ----> |  Event 4776 di DC
    |                               | <-- "benar" / "salah" ------- |
    |                               |  Event 4624 di server:         |
    |                               |  Authentication Package = NTLM |
```

Bandingkan dengan Kerberos di bagian 1.6: pada Kerberos, server membuka tiket sendiri tanpa bertanya ke DC; pada NTLM, server bertanya ke DC untuk setiap autentikasi baru [S10][S13].

Untuk akun domain, setiap validasi kredensial NTLM tercatat sebagai Event 4776 di DC, dan event ini hanya mencatat nama komputer asal, bukan server tujuan [S20]. Di Event 4624 milik server tujuan, field Authentication Package menunjukkan `NTLM`, `Kerberos`, atau `Negotiate`, dan field Package Name menunjukkan versi NTLM (`NTLM V1`, `NTLM V2`, atau `LM`) [S16].

**Contoh di PT JAB:** mesin pemindai dokumen multifungsi di lantai 3 menyimpan hasil scan ke folder di `JKT-FS01` memakai akun `svc-scan`. Firmware mesin itu hanya mendukung NTLMv2, jadi setiap kali ada yang memindai, DC mencatat Event 4776. Kasus ini dibahas sebagai alert `SOC-2027-0839` di bagian 2.3.

**Beda NTLMv1 dengan NTLMv2:** keduanya berbasis tantangan dan jawaban, tetapi NTLMv1 jauh lebih lemah dan sudah dihapus dari Windows versi terbaru [S14]. Di PT JAB, `NTLM V1` di field Package Name selalu dinaikkan ke L2 karena berarti ada perangkat atau konfigurasi sangat lama.

**Salah paham umum:**
- "Kalau domain sudah memakai Kerberos, NTLM pasti sudah mati." Selama ada perangkat lama, aplikasi lama, atau login dengan akun lokal, NTLM tetap muncul di log [S13]. Langkah realistisnya adalah menginventaris pemakai NTLM, membatasinya, lalu menggantinya sedikit demi sedikit.

### 1.8 Group Policy dan GPO

Pertanyaan kedelapan Sari ("aturan kunci layar 10 menit datang dari mana") membawa kamu ke fitur yang membuat ribuan laptop bisa diatur dari satu tempat.

**Apa itu:** Group Policy adalah fitur Windows untuk pengelolaan dan konfigurasi terpusat atas sistem operasi, aplikasi, dan pengaturan user [S15]. Bila dipakai bersama AD, kumpulan pengaturan disimpan dalam Group Policy Object (GPO), yaitu satu paket berisi pengaturan, izin keamanan, dan cakupan penerapan yang diterapkan ke user dan komputer [S15]. GPO tersimpan di AD dan di folder SYSVOL pada setiap DC, lalu direplikasi antar DC [S15]. Pengaturannya terbagi dua: Computer Configuration yang berlaku untuk seluruh komputer (misalnya aturan firewall) dan User Configuration yang hanya berlaku untuk user yang sedang login [S15].

GPO ditautkan (linked) ke site, domain, atau OU, dan tautan itu menentukan siapa yang terkena [S15]. Pengaturan diterapkan saat komputer menyala dan saat user login, lalu diperbarui berkala di latar belakang [S15]. Urutan penerapannya: kebijakan lokal, site, domain, lalu OU; pengaturan yang diterapkan belakangan menimpa yang lebih awal [S12]. GPO yang ditautkan ke OU yang lebih tinggi secara bawaan diwarisi OU di bawahnya [S15]. Kebijakan password biasanya diatur di tingkat domain [S15].

**Analogi:** peraturan gedung yang otomatis berlaku di semua lantai. Kantor administrasi cukup menempel satu peraturan ("pintu ruang kerja terkunci otomatis bila ditinggal 10 menit") di papan lantai, dan semua ruangan di lantai itu mengikutinya. Batasnya: peraturan baru tidak berlaku seketika, melainkan saat komputer dinyalakan, user login, atau pembaruan berkala berikutnya. Dan siapa pun yang bisa mengubah papan peraturan bisa mengubah perilaku semua komputer di bawahnya sekaligus, termasuk menyuruh semuanya menjalankan program tertentu. Karena itu hak mengubah GPO setara dengan hak admin atas komputer-komputer itu.

**Cara kerja:**

```
 Default Domain Policy        --ditautkan ke--> corp.jab.example  (password minimal, kebijakan Kerberos)
 GPO-Laptop-Baseline          --ditautkan ke--> OU Laptop         (kunci layar 10 menit, firewall aktif,
                                                                   blokir USB storage)
 GPO-Server-Baseline          --ditautkan ke--> OU Server         (audit login, larang login user biasa)
 GPO-DC-Audit                 --ditautkan ke--> OU Domain Controllers (audit perubahan group, Kerberos)

 laptop JKT-WS-1072 menyala -> cek GPO untuk site, domain, OU Jakarta, OU Komputer, OU Laptop
                            -> terapkan berurutan; yang terakhir menang bila bertabrakan
```

**Contoh di PT JAB:** aturan kunci layar 10 menit berasal dari `GPO-Laptop-Baseline` di OU `Laptop`. Aturan audit yang membuat DC mencatat penambahan anggota group (sumber alert `SOC-2027-0838`) berasal dari `GPO-DC-Audit`. Microsoft menyarankan audit perubahan security group diaktifkan untuk melihat pembuatan group, perubahan dan penghapusan group penting, serta penambahan dan pengeluaran anggota [S21]. Bila GPO audit itu dimatikan, alert ini tidak akan pernah muncul; karena itu SOC PT JAB juga memantau perubahan GPO di OU `Domain Controllers`.

**Beda GPO dengan group:** GPO mengatur konfigurasi komputer dan user ("apa yang terpasang dan bagaimana perilakunya"). Group mengatur hak dan izin ("boleh membuka apa"). GPO ditautkan ke OU, sedangkan izin diberikan ke group. Keduanya sering dipakai bersama, tetapi menjawab pertanyaan berbeda.

**Salah paham umum:**
- "Mengubah GPO langsung berlaku di semua komputer detik itu juga." Komputer menerapkan GPO saat menyala, saat user login, dan saat pembaruan berkala [S15]. Saat insiden, jeda ini berarti komputer yang tidak menyala belum menerima aturan darurat yang baru dibuat.

### 1.9 Privileged group: Domain Admins dan kawan-kawan

Pertanyaan kesembilan Sari adalah alasan alert `SOC-2027-0838` langsung berstatus P1. Jawabannya ada pada apa yang bisa dilakukan anggota `Domain Admins`.

**Apa itu:** AD punya banyak group bawaan dengan hak tinggi. Tiga di antaranya adalah group dengan hak tertinggi di directory: Enterprise Admins, Domain Admins, dan Administrators bawaan; ditambah Schema Admins yang haknya sempit tetapi bisa merusak seluruh forest bila disalahgunakan [S4]. Tabel berikut merangkum keempatnya; cari kolom Jangkauan untuk melihat kenapa perubahan anggotanya selalu serius.

| Group | Jenis | Jangkauan | Catatan |
|---|---|---|---|
| Domain Admins | Global security group | Admin penuh satu domain; anggota grup Administrators lokal di setiap komputer yang tergabung ke domain [S4] | Seharusnya hanya dipakai untuk keadaan darurat (break glass) [S4] |
| Enterprise Admins | Universal security group, hanya di domain root forest | Perubahan di seluruh forest: menambah domain, membuat trust [S4] | Tidak punya hak bawaan di workstation dan member server [S4] |
| Administrators (bawaan) | Domain local security group | Hak langsung di directory dan di DC [S4] | Berisi Domain Admins dan Enterprise Admins secara bawaan [S4] |
| Schema Admins | Universal security group | Hanya schema forest [S4] | Jarang dibutuhkan; perubahan anggotanya tetap dipantau |

Microsoft menegaskan bahwa anggota salah satu dari tiga group teratas bisa memanipulasi directory untuk masuk ke dua group lainnya, sehingga ketiganya harus dianggap setara dari sisi potensi hak [S4]. Microsoft juga menyarankan menghapus keanggotaan permanen di group berhak tinggi dan memberi keanggotaan sementara hanya saat dibutuhkan, tidak memakai akun berhak tinggi untuk pekerjaan sehari-hari, serta mengelola sistem penting hanya dari komputer administrasi yang aman dengan MFA (autentikasi lebih dari satu faktor, Day 06) [S5]. Pengelolaan akun berhak tinggi seperti ini disebut PAM dan juga dibahas di Day 06.

**Analogi:** Domain Admins adalah pemegang kunci master yang bisa membuka setiap pintu di gedung, termasuk kantor administrasi. Batasnya: kunci master digital bisa digandakan tanpa jejak fisik dan dipakai dari jauh, dan kunci master bukan satu-satunya jalan menuju kekuasaan penuh. Ada pemegang kunci lain (Enterprise Admins, Administrators), ada petugas yang bisa mengubah peraturan gedung (pemegang hak GPO), dan ada "tukang pembuat kunci", yaitu akun `krbtgt` dan server sertifikat, yang bila dikuasai bisa menerbitkan kunci baru.

**Cara kerja:** penambahan anggota ke group keamanan domain tercatat di log Security DC dengan Event ID yang bergantung pada jenis group-nya [S21]:

| Event ID | Arti | Contoh group |
|---|---|---|
| 4728 | Anggota ditambahkan ke security-enabled global group | Domain Admins |
| 4729 | Anggota dikeluarkan dari security-enabled global group | Domain Admins |
| 4732 | Anggota ditambahkan ke security-enabled local group | Administrators bawaan |
| 4756 | Anggota ditambahkan ke security-enabled universal group | Enterprise Admins, Schema Admins |

Tabel di atas dipakai untuk memilih Event ID yang harus dipantau; rule yang hanya memantau 4728 akan melewatkan penambahan ke Enterprise Admins (4756) dan Administrators (4732). Kategori audit ini bervolume rendah [S21], jadi hampir setiap kemunculannya layak dilihat manusia.

**Contoh di PT JAB:** target PT JAB adalah `Domain Admins` kosong di luar keadaan darurat. Kenyataannya per Agustus 2027 masih ada dua anggota permanen, `adm.agung` dan `adm.fajar` (Fajar Nugroho, admin Windows di tim Agung), yang hanya boleh dipakai dari `JKT-JUMP01`. Rule SIEM untuk Event 4728, 4732, dan 4756 pada group berhak tinggi otomatis membuat alert P1 bila tidak ada nomor change request yang cocok. Itulah sebabnya `SOC-2027-0838` langsung P1.

**Beda privileged group dengan akun admin:** akun admin seperti `adm.fajar` hanyalah akun; kekuatannya datang dari group tempat ia menjadi anggota. Mengeluarkan akun dari `Domain Admins` mencabut kekuatan itu, tetapi tiket Kerberos yang sudah terbit masih membawa daftar group lama sampai diperbarui (bagian 1.6).

**Salah paham umum:**
- "Perubahan oleh admin yang sah pasti aman." Admin sah bisa salah langkah, dan akun admin sah bisa sedang dipakai penyerang. Karena itu verifikasi dilakukan lewat jalur terpisah dan lewat jejak teknis, bukan hanya dengan melihat nama akun di log (bagian 2.1).

### 1.10 Kenapa AD jadi target utama

Pertanyaan terakhir Sari merangkum semua bagian sebelumnya. Penyerang yang masuk lewat satu laptop jarang berhenti di laptop itu; tujuan berikutnya hampir selalu AD.

**Apa itu:** AD menyediakan autentikasi dan otorisasi untuk banyak jaringan perusahaan, sehingga menjadi target bernilai tinggi; bila AD dikuasai, penyerang bisa mendapat akses istimewa ke setiap sistem dan user yang dikelolanya [S25]. Badan siber Australia (ASD ACSC) bersama CISA, NSA, dan badan siber Kanada, Inggris, dan Selandia Baru menerbitkan panduan bersama yang membahas 17 teknik paling umum untuk menguasai AD [S26], termasuk Kerberoasting, DCSync, golden ticket, dan Shadow Credentials [S25]. Microsoft mencatat bahwa pencuri kredensial biasanya mengincar akun yang sudah punya hak tinggi, akun VIP, akun yang terkait hak AD, domain controller, dan layanan infrastruktur seperti server PKI (sertifikat) [S5].

Alasannya bisa diringkas menjadi empat:

1. **Satu pusat untuk semua kunci.** DC menyimpan kredensial semua akun domain, dan satu DC memegang salinan lengkap [S1][S2].
2. **Hak yang bertingkat dan saling terkait.** Domain Admins adalah admin di setiap komputer domain [S4], dan anggota satu group tertinggi bisa naik ke group tertinggi lainnya [S4].
3. **Mudah dipetakan dari dalam.** User biasa bisa membaca sebagian besar isi directory [S4], jadi satu akun karyawan yang dicuri sudah cukup untuk melihat peta gedung.
4. **Bukti login yang bisa dicuri dan dipakai ulang.** Hash password dan tiket Kerberos bisa dipakai tanpa mengetahui password aslinya.

Tiga teknik berikut cukup kamu kenali di tingkat konsep. Nama dan nomornya diambil dari MITRE ATT&CK, katalog teknik serangan yang dibahas di Day 14.

- **Kerberoasting (T1558.003).** Setiap user domain yang punya TGT sah bisa meminta service ticket untuk layanan mana pun yang punya SPN. Bagian tiket itu sering dienkripsi dengan kunci turunan password akun layanan, sehingga penyerang bisa membawa tiket keluar lalu menebak password-nya sendiri tanpa menyentuh jaringan lagi [S22]. Bila akun layanan memakai password pendek dan lama seperti `svc-backup`, tebakan bisa berhasil. Tanda yang dipantau: Event 4769 dengan enkripsi RC4 (`0x17`) dan satu akun yang meminta banyak service ticket dalam waktu singkat; pencegahannya password akun layanan yang panjang (MITRE menyebut idealnya 25 karakter atau lebih), gMSA, enkripsi AES, dan hak minimum [S22]. Pola ini yang terjadi pada `INC-2026-023`.
- **Pass-the-hash (T1550.002).** Penyerang memakai hash password yang dicuri untuk login sebagai user tanpa mengetahui password aslinya, melewati langkah autentikasi yang biasanya meminta password [S23]. Teknik ini memanfaatkan sifat NTLM di bagian 1.7 dan sering dipakai untuk berpindah dari satu komputer ke komputer lain; pergerakan seperti itu (lateral movement) dibahas di Day 15.
- **Golden ticket (T1558.001).** Penyerang yang berhasil mendapat hash password akun `krbtgt`, biasanya setelah punya akses istimewa ke DC, bisa membuat TGT palsu untuk akun apa pun di AD [S24]. Akun `krbtgt` adalah akun layanan KDC yang punya akses ke kredensial semua akun di AD [S4]. MITRE mencatat tiket palsu ini tetap bisa dipakai sampai password `krbtgt` direset dua kali [S24]; mereset password user biasa tidak cukup.

Selain ketiganya, server sertifikat yang terhubung ke AD (AD CS) juga bisa menjadi jalan pintas ke hak tertinggi bila template sertifikatnya salah konfigurasi, seperti pada `INC-2026-024`. Panduan bersama ASD dan mitranya memuat kompromi AD CS sebagai salah satu teknik utama [S26].

**Analogi:** penyusup yang masuk gedung lewat jendela toilet tidak tertarik pada isi toilet. Ia ingin ke kantor administrasi, karena di sana ada data semua penghuni, stempel pembuat gelang, dan lemari kunci master. Batasnya: di gedung nyata, penyusup harus berjalan melewati lorong yang dijaga; di AD, setelah memegang satu akun sah, sebagian besar "lorong" menuju kantor administrasi adalah permintaan yang tampak normal (membaca directory, meminta tiket), sehingga jauh lebih sulit dibedakan dari aktivitas karyawan biasa.

**Cara kerja:** pola umum serangan yang berujung pada penguasaan domain:

```
 1. Masuk     : phishing, layanan terbuka ke internet, atau server tanpa EDR
 2. Pijakan   : satu laptop dan satu akun karyawan biasa
 3. Memetakan : membaca directory lewat LDAP (siapa admin, akun layanan apa, server mana)
 4. Naik hak  : Kerberoasting akun layanan, mencuri hash/tiket dari memori, salah konfigurasi AD CS/GPO
 5. Menguasai : masuk Domain Admins atau setara; bisa menjalankan apa pun di semua komputer domain
 6. Bertahan  : golden ticket, akun admin tersembunyi, perubahan GPO
 7. Dampak    : ransomware ke banyak server sekaligus, pencurian data
```

**Contoh di PT JAB:** dua insiden lama PT JAB menyentuh langkah 4 dan 5: `INC-2026-023` (Kerberoasting akun layanan) dan `INC-2026-024` (domain dikuasai lewat template sertifikat). Alert `SOC-2027-0840` di bagian 2.4 memperlihatkan pola langkah 4 terdeteksi lebih awal.

**Beda menguasai satu komputer dengan menguasai domain:** penyerang yang menguasai satu laptop bisa merusak satu laptop. Penyerang yang menguasai domain bisa mendorong program ke semua komputer, membuat akun baru yang tampak sah, dan membaca semua data yang diizinkan AD. Karena itu tanda-tanda langkah 3 dan 4 diprioritaskan tinggi walaupun belum ada kerusakan yang terlihat.

## 2. Contoh nyata

Semua contoh di bagian ini adalah keluaran ilustrasi dari organisasi fiktif PT JAB, bukan hasil eksekusi nyata. Nama host, akun, alamat IP, waktu, dan angka dibuat untuk latihan. Format log diringkas dari field Event ID Windows yang didokumentasikan Microsoft; tampilan di SIEM-mu bisa berbeda.

### 2.1 Membedah alert `SOC-2027-0838`: `svc-backup` masuk Domain Admins

Alert berikut muncul saat orientasi Selasa pagi. Ringkasannya di SIEM PT JAB seperti ini:

```
Alert     : SOC-2027-0838
Prioritas : P1
Waktu     : 2027-08-10 10:46:12 WIB
Rule      : Perubahan anggota group berhak tinggi tanpa change request
Sumber    : JKT-DC02.corp.jab.example, log Security

EventCode : 4728  A member was added to a security-enabled global group.
Subject   : Account Name  adm.fajar
            Account Domain CORP
            Logon ID      0x3A7F21C
Member    : Account Name  CN=svc-backup,OU=Akun-Layanan,OU=JAB,DC=corp,DC=jab,DC=example
            Security ID   CORP\svc-backup
Group     : Group Name    Domain Admins
            Group Domain  CORP
Change    : tidak ada nomor change request yang cocok
```

Cara membacanya: field Subject adalah akun yang melakukan perubahan (`adm.fajar`), field Member adalah akun yang ditambahkan (`svc-backup`, ditulis sebagai distinguished name), dan field Group adalah group tujuannya. Satu event ini memuat dua akun sekaligus; jangan tertukar antara pelaku dan yang ditambahkan. Field Logon ID adalah nomor sesi login pelaku di DC itu, dipakai untuk mencari event lain dari sesi yang sama.

Sari lalu mengajak memeriksa tiga hal, berurutan. Tabel berikut merangkum langkahnya; perhatikan kolom Kenapa, karena setiap langkah menjawab satu keraguan berbeda.

| Langkah | Yang dicek | Hasil | Kenapa |
|---|---|---|---|
| 1 | Event 4624 di `JKT-DC02` dengan Logon ID `0x3A7F21C` | Login `adm.fajar` pukul 10:44:58, Logon Type 3, Authentication Package Kerberos, dari `10.20.10.50` (`JKT-JUMP01`) | Memastikan sesi pelaku berasal dari jump host yang memang diwajibkan untuk akun admin |
| 2 | Event 4624 di `JKT-JUMP01` untuk `adm.fajar` | Login Logon Type 10 (Remote Desktop) pukul 10:31:07 dari `10.10.37.77` (`JKT-WS-1077`, laptop Fajar) | Menelusuri satu langkah lagi ke belakang: dari laptop siapa sesi itu dimulai |
| 3 | Menelepon Fajar di nomor ekstensi dari direktori karyawan, bukan membalas chat | Fajar mengakui: job backup `JKT-BKP01` gagal "access denied" sejak 02:00, ia menambahkan `svc-backup` ke Domain Admins "sementara" supaya backup malam ini jalan | Konfirmasi lewat jalur terpisah; bila akun `adm.fajar` dikuasai penyerang, chat dari akun itu juga bisa palsu |

Logon Type 3 berarti login dari jaringan, dan Logon Type 10 berarti login lewat Remote Desktop [S16]. Keduanya wajar untuk admin yang bekerja dari jump host.

Kesimpulan Sari: pelakunya orang yang sah, dari komputer yang sah, tetapi tindakannya tidak sah. Akun layanan dengan password lama kini memegang kunci master, sehingga satu tiket Kerberos untuk `svc-backup` yang berhasil ditebak (Kerberoasting, bagian 1.10) akan langsung memberi penyerang hak Domain Admins. Tindakan yang diambil:

1. Pukul 11:32:40, `adm.agung` mengeluarkan `svc-backup` dari Domain Admins (tercatat sebagai Event 4729). Durasi keanggotaan: 10:46:12 sampai 11:32:40, yaitu 46 menit 28 detik.
2. SOC memeriksa semua aktivitas `svc-backup` dalam rentang itu: hanya ada login dari `JKT-BKP01` (Event 4624 Logon Type 5, Service), tidak ada login dari komputer lain dan tidak ada perubahan group lain.
3. Password `svc-backup` tetap direset, dan migrasinya ke gMSA dinaikkan prioritasnya.
4. Masalah backup diselesaikan dengan memberi `svc-backup` hak backup hanya di server yang memang di-backup, lewat change request resmi.
5. Alert ditutup sebagai aktivitas sah yang melanggar kebijakan; klasifikasi alert seperti ini dibahas di Day 11. Tidak ada nomor insiden, tetapi Agung membuka tiket perbaikan proses: penambahan ke group berhak tinggi wajib lewat change request dan persetujuan orang kedua (separation of duties, Day 01 bagian 1.7).

### 2.2 Jejak login Gilang pagi hari

Untuk menjawab pertanyaan keenam Sari dengan data, kalian membuka log login Gilang Ramadhan (analyst L1) di laptop `JKT-WS-1072` (`10.10.37.72`) pagi itu. Event berikut diurutkan menurut waktu dari tiga sumber: laptop, DC, dan file server.

```
Waktu      Komputer      EventCode  Ringkasan
07:57:41   JKT-WS-1072   4625       Account gilang.ramadhan, Logon Type 2,
                                    Status 0xC000006D, Sub Status 0xC000006A (password salah)
07:57:41   JKT-DC01      4771       Kerberos pre-authentication failed, gilang.ramadhan,
                                    Failure Code 0x18, Client 10.10.37.72
07:58:03   JKT-DC01      4768       TGT requested, Account gilang.ramadhan, Service krbtgt,
                                    Result 0x0, Ticket Encryption 0x12, Pre-Auth Type 2,
                                    Client 10.10.37.72
07:58:03   JKT-DC01      4769       Service ticket requested, gilang.ramadhan@CORP.JAB.EXAMPLE,
                                    Service JKT-WS-1072$, Ticket Encryption 0x12, Failure 0x0
07:58:04   JKT-WS-1072   4624       Account gilang.ramadhan, Logon Type 2,
                                    Authentication Package Negotiate
08:15:40   JKT-DC01      4769       Service ticket requested, gilang.ramadhan@CORP.JAB.EXAMPLE,
                                    Service JKT-FS01$, Ticket Encryption 0x12, Failure 0x0
08:15:40   JKT-FS01      4624       Account gilang.ramadhan, Logon Type 3,
                                    Authentication Package Kerberos, Source 10.10.37.72
```

Cara membacanya, baris demi baris:

- **07:57:41.** Gilang salah mengetik password. Laptop mencatat Event 4625 (login gagal), yang tercatat di komputer tempat login dicoba [S17]. Sub Status `0xC000006A` berarti password salah [S20]. Di DC, kegagalan pre-authentication Kerberos karena password salah tidak dicatat sebagai 4768, melainkan sebagai Event 4771 dengan kode `0x18` [S18].
- **07:58:03.** Percobaan kedua berhasil. DC mencatat Event 4768: TGT diterbitkan, dengan Service Name `krbtgt` yang memang selalu muncul untuk permintaan TGT [S18]. Ticket Encryption `0x12` berarti AES256, jenis yang diharapkan di Windows modern [S18]. Pre-Auth Type 2 adalah autentikasi password standar [S18].
- **07:58:03.** Laptop langsung meminta service ticket untuk dirinya sendiri (`JKT-WS-1072$`), supaya Windows di laptop bisa menerima Gilang. Service Name di Event 4769 adalah nama akun atau komputer yang tiketnya diminta [S19].
- **07:58:04.** Laptop membuka sesi Gilang: Event 4624 dengan Logon Type 2 (Interactive, login langsung di depan komputer) [S16]. Authentication Package `Negotiate` berarti Windows memilih protokol sendiri, dan di sini Kerberos yang dipilih [S16].
- **08:15:40.** Gilang membuka folder `\\JKT-FS01\SOC`. Laptop memakai TGT yang sama untuk meminta service ticket `JKT-FS01$` (Event 4769 di DC), lalu menunjukkan tiket itu ke `JKT-FS01`. File server mencatat Event 4624 dengan Logon Type 3 (Network) dan Authentication Package `Kerberos` [S16]. Tidak ada event 4776, karena tidak ada NTLM yang terlibat.

Beberapa angka yang bisa dihitung dari log ini: jeda antara login gagal dan berhasil adalah 22 detik (07:57:41 sampai 07:58:03). TGT terbit pukul 07:58:03; dengan umur maksimum bawaan 10 jam [S12], tiket itu harus diperbarui paling lambat pukul 17:58:03. Login ke file server pukul 08:15:40 terjadi 17 menit 37 detik setelah TGT terbit dan tetap memakai TGT yang sama, tanpa Gilang mengetik password lagi.

Pola ini adalah gambaran normal yang kamu pakai sebagai pembanding. Bila suatu hari kamu melihat Event 4624 Logon Type 3 dengan Authentication Package `NTLM` untuk akun Gilang dari komputer yang bukan laptopnya, atau Event 4769 dengan enkripsi `0x17` (RC4) padahal biasanya `0x12`, itu tanda ada yang berbeda dan perlu dicek. Microsoft menyarankan memantau jenis enkripsi tiket selain `0x11` dan `0x12` (keluarga AES) [S19].

### 2.3 Alert `SOC-2027-0839`: NTLM dari mesin pemindai

Pukul 09:20, sebelum alert P1 muncul, antrean SOC juga memuat alert berprioritas rendah yang menjawab pertanyaan ketujuh Sari. Rule ini memantau pemakaian NTLM dari perangkat yang belum ada di daftar inventaris NTLM PT JAB.

```
Alert     : SOC-2027-0839
Prioritas : P4
Waktu     : 2027-08-10 09:12:30 WIB
Rule      : NTLM dari sumber yang belum terdaftar di inventaris NTLM

JKT-DC01  EventCode 4776  Logon Account svc-scan, Source Workstation JKT-MFP-L3-07,
                          Error Code 0x0
JKT-FS01  EventCode 4624  Account svc-scan, Logon Type 3, Authentication Package NTLM,
                          Package Name NTLM V2, Key Length 128, Source 10.10.37.150

Ringkasan 24 jam: 41 validasi NTLM berhasil untuk svc-scan, semuanya dari 10.10.37.150,
                  semuanya ke JKT-FS01, 0 gagal
```

Cara membacanya: Event 4776 di DC hanya menyebut komputer asal (`JKT-MFP-L3-07`), tidak menyebut server tujuan [S20]; server tujuan baru terlihat dari Event 4624 di `JKT-FS01`. `NTLM V2` dan Key Length 128 adalah nilai yang diharapkan untuk NTLM modern; Microsoft menyarankan memantau Key Length yang bukan 128 dan versi NTLM yang tidak sesuai standar organisasi [S16].

Sari dan kamu mengecek tiga hal: alamat `10.10.37.150` memang mesin pemindai multifungsi baru di lantai 3 yang dipasang Senin; akun `svc-scan` hanya punya izin tulis ke satu folder hasil scan; dan semua 41 login menuju satu server yang sama. Kesimpulan: pemakaian NTLM yang sah dari perangkat yang belum mendukung Kerberos. Tindakan: perangkat dimasukkan ke inventaris NTLM, Agung diminta mengecek apakah firmware baru mesin itu mendukung Kerberos, dan rule diberi pengecualian khusus untuk pasangan `svc-scan` dan `10.10.37.150` saja, bukan untuk semua NTLM.

Seandainya Package Name menunjukkan `NTLM V1`, atau `svc-scan` tiba-tiba login ke server lain, alert ini akan dinaikkan ke L2: yang pertama berarti protokol yang sudah dihapus dari Windows terbaru [S14], yang kedua berarti akun layanan dipakai di luar kebiasaannya.

### 2.4 Alert `SOC-2027-0840`: pola Kerberoasting

Siang harinya, setelah `SOC-2027-0838` ditutup, muncul alert dari rule yang dibuat PT JAB setelah `INC-2026-023`. Alert ini memperlihatkan langkah "naik hak" di bagian 1.10 tertangkap sebelum berhasil.

```
Alert     : SOC-2027-0840
Prioritas : P2
Waktu     : 2027-08-10 14:05:10 sampai 14:07:52 WIB
Rule      : Satu akun meminta banyak service ticket untuk layanan berbeda dalam waktu singkat
Sumber    : JKT-DC01 dan JKT-DC02, EventCode 4769

Akun      : rina.wulandari@CORP.JAB.EXAMPLE  (staf administrasi Penjualan)
Client    : 10.10.37.74 (JKT-WS-1074)
Jumlah    : 37 permintaan service ticket untuk 37 SPN berbeda
Enkripsi  : 34 tiket 0x17 (RC4), 3 tiket 0x12 (AES256)
Baseline  : akun ini rata-rata 3 sampai 8 permintaan service ticket per jam,
            selalu ke JKT-FS01, server email lokal, dan printer
```

Cara membacanya: 37 permintaan dalam 2 menit 42 detik (14:05:10 sampai 14:07:52) berarti lebih dari 13 permintaan per menit, sedangkan akun ini biasanya maksimal 8 per jam. 34 dari 37 tiket (sekitar 92%) memakai RC4, padahal lingkungan PT JAB biasanya memakai AES. MITRE menyebut dua tanda ini, banyak permintaan service ticket dalam waktu singkat dan permintaan dengan enkripsi RC4 `0x17`, sebagai petunjuk Kerberoasting [S22]. Tidak ada satu pun permintaan yang gagal, karena memang setiap user domain berhak meminta tiket (batas analogi kedua di bagian 1.6).

Kamu menaikkan alert ini ke Sari dalam lima menit. Sari mengonfirmasi lewat EDR (agen pengawas di laptop) bahwa di `JKT-WS-1074` ada program tidak dikenal yang dijalankan dari folder unduhan pukul 14:04, lalu mengisolasi laptop itu dari jaringan dan membuka insiden `INC-2027-086`. Langkah berikutnya diambil alih tim L2 dan Agung: mereset password semua akun layanan yang tiketnya diminta (karena tiket sudah keluar dari jaringan dan bisa ditebak tanpa batas waktu), mendahulukan akun layanan yang punya hak tinggi, dan mempercepat migrasi ke gMSA. Penanganan insiden secara utuh dibahas di Day 19.

Perhatikan kaitannya dengan `SOC-2027-0838`: seandainya Kerberoasting ini terjadi pagi tadi, saat `svc-backup` masih anggota Domain Admins, tiket `svc-backup` termasuk yang diminta, dan password-nya yang berumur delapan tahun berhasil ditebak, penyerang akan langsung memegang kunci master.

## 3. Perbandingan istilah yang sering tertukar

### 3.1 Kerberos vs NTLM

Dua protokol ini sama-sama menjawab "kamu siapa" di jaringan Windows, tetapi caranya sangat berbeda. Tabel berikut membandingkannya dari sisi yang paling sering ditanyakan; cari kolom Yang perlu dipantau SOC saat membaca log.

| Aspek | Kerberos | NTLM |
|---|---|---|
| Status | Bawaan dan yang diutamakan di domain AD [S13] | Deprecated sejak Juni 2024; NTLMv1 dihapus dari Windows 11 24H2 dan Server 2025 [S14] |
| Bukti yang dibawa klien | Tiket (TGT, lalu service ticket) | Jawaban atas tantangan, dihitung dari hash password |
| Peran DC | Menerbitkan tiket; server tujuan tidak perlu bertanya ke DC setiap koneksi [S10] | Server bertanya ke DC untuk setiap autentikasi akun domain [S13] |
| Server diverifikasi klien? | Ya, mutual authentication [S10] | Tidak [S10] |
| Butuh jam sinkron | Ya, selisih sekitar 5 menit [S11] | Tidak |
| Event di DC | 4768 (TGT), 4769 (service ticket), 4771 (pre-auth gagal) | 4776 (validasi kredensial) |
| Event di server tujuan | 4624 dengan Authentication Package Kerberos | 4624 dengan Authentication Package NTLM dan Package Name |
| Serangan terkenal | Kerberoasting, golden ticket | Pass-the-hash |
| Yang perlu dipantau SOC | Enkripsi RC4, lonjakan 4769 per akun, 4768 dari IP di luar rentang internal | Sumber NTLM baru, `NTLM V1`, akun admin yang memakai NTLM |

### 3.2 Domain, forest, OU, dan group

Empat istilah ini semuanya "mengelompokkan", sehingga sering tertukar. Tabel berikut membedakannya dengan pertanyaan yang dijawab masing-masing.

| Istilah | Pertanyaan yang dijawab | Contoh PT JAB | Analogi |
|---|---|---|---|
| Forest | Domain mana saja yang berbagi struktur dan saling percaya? | Forest dengan satu domain `corp.jab.example` | Kawasan perkantoran |
| Domain | Wilayah pengelolaan akun dan autentikasi yang mana? | `corp.jab.example` | Satu gedung |
| OU | Objek ini disimpan di mana, dan GPO atau petugas mana yang mengaturnya? | OU `Laptop`, OU `Akun-Layanan` | Lantai atau sayap gedung |
| Group | Akun ini boleh membuka apa? | `GG-SOC`, `Domain Admins` | Daftar akses per kelompok |

### 3.3 TGT, service ticket, hash, dan password

Empat benda ini adalah "bukti identitas" dalam bentuk berbeda. Tabel berikut menunjukkan siapa yang menerbitkan, di mana ia hidup, dan apa akibatnya bila dicuri; kolom terakhir menjelaskan kenapa semuanya diperlakukan seperti password.

| Benda | Dibuat oleh | Berlaku untuk | Bila dicuri |
|---|---|---|---|
| Password | User | Semua yang memakai akun itu | Penyerang menjadi user itu sampai password diganti |
| Hash password | Sistem, dari password | Autentikasi NTLM | Bisa dipakai login lewat NTLM tanpa tahu password (pass-the-hash) [S23] |
| TGT | KDC di DC | Meminta service ticket, sampai kedaluwarsa (bawaan maksimal 10 jam [S12]) | Penyerang bisa meminta tiket layanan atas nama user selama TGT berlaku |
| Service ticket | KDC di DC | Satu layanan | Bisa dipakai ke layanan itu; bila terenkripsi password lemah, password akun layanan bisa ditebak (Kerberoasting) [S22] |

### 3.4 User account, computer account, service account, dan akun admin

Empat jenis akun ini muncul berdampingan di log. Tabel berikut membantu menebak jenis akun dari namanya dan menentukan perilaku yang dianggap normal.

| Jenis | Ciri di log PT JAB | Perilaku normal | Perilaku yang mencurigakan |
|---|---|---|---|
| User | `nama.belakang` | Login interaktif di laptopnya, akses file dan email | Login ke banyak server, login tengah malam dari IP asing |
| Computer | Diakhiri `$` [S18] | Autentikasi dari komputernya sendiri | Akun komputer dipakai dari IP komputer lain |
| Service | `svc-*` atau `gmsa-*` | Login Logon Type 5 (Service) dari server aplikasinya [S16] | Login interaktif atau Remote Desktop, login dari laptop karyawan |
| Admin | `adm.*` | Login dari `JKT-JUMP01` saja | Login dari laptop biasa, browsing internet, perubahan group tanpa change request |

## 4. Salah paham umum

Butir berikut adalah salah paham yang melintasi beberapa istilah sekaligus. Salah paham yang khusus satu istilah sudah ditulis di subbagiannya.

- **Anggapan:** AD hanyalah buku telepon karyawan. **Kenyataannya:** AD adalah pusat autentikasi, otorisasi, dan konfigurasi untuk semua komputer yang tergabung [S1][S2]. Menguasai AD berarti menguasai hampir semua komputer dan akun yang dikelolanya [S25].
- **Anggapan:** menonaktifkan akun langsung memutus semua aksesnya. **Kenyataannya:** tiket Kerberos yang sudah terbit tetap bisa dipakai sampai kedaluwarsa [S12]. Saat akun dicurigai dikuasai penyerang, menonaktifkan akun perlu disertai langkah lain, misalnya mengisolasi komputer yang dipakai, dan dicatat sebagai titik waktu, bukan sebagai akhir masalah (bagian 1.6).
- **Anggapan:** memindahkan akun ke OU `Admin` membuatnya menjadi admin. **Kenyataannya:** OU hanya menentukan tempat penyimpanan, GPO, dan pendelegasian; hak admin datang dari keanggotaan group (bagian 1.2 dan 1.4).
- **Anggapan:** serangan ke AD selalu butuh akun admin. **Kenyataannya:** Kerberoasting cukup memakai TGT dari akun domain biasa [S22], dan membaca isi directory cukup dengan akun user biasa [S4]. Satu akun karyawan yang tertipu phishing sudah menjadi pijakan untuk menyerang AD.
- **Anggapan:** mereset password semua user memulihkan domain yang sudah dikuasai. **Kenyataannya:** golden ticket dibuat dari kunci `krbtgt`, bukan dari password user, dan tetap berlaku sampai password `krbtgt` direset dua kali [S24]. Domain yang dikuasai penuh butuh pemulihan yang direncanakan bersama tim IR; reset massal saja tidak cukup.
- **Anggapan:** perubahan anggota group berhak tinggi oleh admin yang dikenal tidak perlu diperiksa. **Kenyataannya:** pelaku yang sah bisa salah langkah, seperti pada `SOC-2027-0838`, dan akun admin yang sah bisa dikuasai penyerang. Verifikasi dilakukan lewat jejak teknis dan jalur komunikasi terpisah (bagian 2.1).
- **Anggapan:** Kerberos aman, NTLM tidak aman, jadi cukup matikan NTLM. **Kenyataannya:** Kerberos juga punya teknik serangannya sendiri (Kerberoasting, golden ticket), dan mematikan NTLM tanpa inventaris bisa memutus perangkat sah seperti mesin pemindai di bagian 2.3. Yang perlu dipantau adalah keduanya.

## 5. Catatan terkini

Bagian ini mencatat perubahan dokumentasi, versi Windows, dan panduan yang perlu diketahui saat membaca sumber lain.

- **NTLM deprecated (Juni 2024).** Microsoft menyatakan semua versi NTLM, termasuk LANMAN, NTLMv1, dan NTLMv2, tidak lagi dikembangkan dan berstatus deprecated; NTLM masih berfungsi di rilis Windows Server dan Windows berikutnya, dan pemanggilan NTLM disarankan diganti dengan Negotiate. Pembaruan November 2024 menambahkan bahwa NTLMv1 dihapus mulai Windows 11 versi 24H2 dan Windows Server 2025 [S14]. Status ini dicek di halaman deprecated features bertanggal 2026-09-23; cek ulang halaman itu sebelum mengutip tanggal penghapusan berikutnya.
- **Event 4768 dan 4769 versi baru.** Windows Server 2016 dan yang lebih baru menampilkan versi baru kedua event ini setelah pembaruan keamanan kumulatif 14 Januari 2025 atau sesudahnya, dengan field tambahan seperti jenis enkripsi yang didukung akun, layanan, dan DC [S18][S19]. Rule SIEM yang ditulis untuk format lama perlu dicek ulang di lingkunganmu.
- **Halaman event audit Windows berstatus arsip.** Dokumentasi Event ID 4624, 4625, 4768, 4769, dan 4776 di Microsoft Learn kini berada di bagian "previous versions" untuk Windows 10, tetapi isinya masih dipakai dan diperbarui (termasuk catatan Januari 2025 di atas) [S16][S18].
- **Windows Server 2025 dan jenis enkripsi Kerberos.** Mulai Windows Server 2025, Kerberos tidak lagi membaca kunci registry lama `SupportedEncryptionTypes`; Microsoft menyarankan memakai Group Policy untuk mengatur jenis enkripsi yang diizinkan [S10].
- **Panduan bersama tentang kompromi AD.** Panduan "Detecting and Mitigating Active Directory Compromises" pertama kali terbit September 2024 dari ASD ACSC bersama CISA, NSA, dan badan siber Kanada, Inggris, dan Selandia Baru; halaman CISA mencantumkan revisi 15 September 2026 [S25][S26].
- **Versi teknik MITRE ATT&CK** yang dirujuk Day ini: T1558.003 Kerberoasting versi 1.3 (diubah 24 Oktober 2025), T1558.001 Golden Ticket versi 1.2 (diubah 24 Oktober 2025), dan T1550.002 Pass the Hash versi 2.0 (diubah 12 Mei 2026) [S22][S23][S24].
- **Nama produk identitas cloud.** Microsoft Entra ID adalah nama baru Azure Active Directory (Azure AD), dan Microsoft Entra Connect adalah alat sinkronisasi dari AD ke Entra ID. Dokumen lama masih memakai nama Azure AD; walaupun namanya mirip, Entra ID bukan AD yang dipindah ke cloud dan memakai protokol yang berbeda. Bahasannya di Day 06 dan Day 08.

## 6. Cheat sheet

```
Active Directory (AD DS) : directory service Microsoft; pusat akun, login, group, dan aturan konfigurasi
Domain                   : wilayah pengelolaan akun dan autentikasi (corp.jab.example)
Domain controller (DC)   : server yang menyimpan salinan lengkap data domain dan menjalankan KDC
Replikasi                : penyalinan perubahan antar DC; semua DC setara
Forest                   : kumpulan domain berbagi schema, konfigurasi, global catalog; saling percaya
OU                       : wadah di domain untuk GPO dan pendelegasian; BUKAN pemberi hak
User / computer / service: akun orang / akun komputer (diakhiri $) / akun aplikasi
gMSA                     : akun layanan yang password-nya dikelola Windows otomatis
SID                      : nomor unik permanen akun dan group; tidak pernah dipakai ulang
SPN                      : nama unik layanan untuk Kerberos
Security group           : pemberi hak dan izin; distribution group hanya untuk email
LDAP                     : protokol baca/ubah directory; 389, LDAPS 636, global catalog 3268
Kerberos                 : autentikasi berbasis tiket, bawaan AD, KDC di DC, port 88
TGT                      : tiket awal setelah login (bawaan maks 10 jam), untuk minta tiket lain
Service ticket           : tiket satu layanan, disegel kunci layanan itu
krbtgt                   : akun yang kuncinya mengamankan semua TGT; dicuri = golden ticket
NTLM                     : challenge-response dari hash password; server tanya DC tiap kali
Negotiate                : pilih Kerberos, jatuh ke NTLM bila perlu
GPO                      : paket aturan konfigurasi; ditautkan ke site/domain/OU; urutan L-S-D-OU
Domain Admins            : admin penuh domain; admin lokal di semua komputer domain
Event 4624 / 4625        : login berhasil / gagal (di komputer tujuan)
Event 4768 / 4769 / 4771 : TGT / service ticket / pre-auth Kerberos gagal (di DC)
Event 4776               : validasi kredensial NTLM (di DC untuk akun domain)
Event 4728 / 4732 / 4756 : anggota ditambah ke global / local / universal security group
Kerberoasting T1558.003  : minta service ticket akun layanan, tebak password offline
Pass-the-hash T1550.002  : login memakai hash tanpa tahu password
Golden ticket T1558.001  : TGT palsu dari kunci krbtgt; reset krbtgt dua kali
```

## 7. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Akun seorang karyawan yang resign dinonaktifkan pukul 13:00, jadi mustahil akun itu masih bisa membuka file server pukul 15:00." Benarkah?

<details><summary>Jawaban</summary>

Tidak selalu. Tiket Kerberos yang terbit sebelum akun dinonaktifkan tetap bisa dipakai sampai kedaluwarsa, dan umur maksimum TGT bawaan di domain Windows adalah 10 jam. Microsoft sendiri mencatat akun yang dinonaktifkan bisa tetap mengakses layanan dengan tiket yang sudah terbit. Karena itu menonaktifkan akun adalah satu langkah, bukan jaminan akses langsung terputus; untuk akun yang dicurigai dipakai penyerang, langkah lain seperti mengisolasi komputernya tetap dibutuhkan. Lihat bagian 1.6 dan 4.

</details>

**2. Skenario keputusan.** Alert P1 muncul: `adm.agung` menambahkan sebuah akun ke `Domain Admins` pukul 23:10, tanpa change request. Agung adalah Lead Infrastruktur yang memang berwenang. Apa langkah pertama yang paling tepat?

- A. Tutup alert, karena pelakunya admin yang berwenang.
- B. Telusuri sesi pelaku (Logon ID di Event 4728, lalu Event 4624 asalnya), pastikan berasal dari `JKT-JUMP01`, lalu konfirmasi ke Agung lewat jalur terpisah seperti telepon ke nomor di direktori, dan naikkan ke L2 bila ada yang tidak cocok.
- C. Langsung nonaktifkan akun `adm.agung` dan semua akun admin lain tanpa memeriksa apa pun.

<details><summary>Jawaban</summary>

B. Nama akun di log hanya menunjukkan akun yang dipakai, bukan orang yang duduk di depan keyboard; akun admin yang sah bisa sedang dikuasai penyerang, dan admin yang sah juga bisa salah langkah seperti pada `SOC-2027-0838`. A keliru karena tidak memverifikasi apa pun untuk perubahan yang memberi kunci master. C keliru karena memutus semua admin tanpa dasar bisa melumpuhkan operasi dan menghapus kesempatan memahami apa yang terjadi; tindakan sekeras itu diputuskan setelah ada bukti, bersama L2. Lihat bagian 1.9 dan 2.1.

</details>

**3. Pertanyaan jebakan.** "Akun `svc-backup` hanya akun layanan, bukan akun orang, jadi kalaupun masuk Domain Admins risikonya kecil." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Kekuatan akun datang dari group-nya, bukan dari siapa pemiliknya; akun layanan di Domain Admins adalah admin di semua komputer domain. Akun layanan justru lebih berisiko: password-nya sering lama dan tidak pernah diganti, dan siapa pun dengan akun domain biasa bisa meminta service ticket untuknya lalu menebak password-nya secara offline (Kerberoasting). Itulah sebabnya `svc-backup` dikeluarkan dari Domain Admins dan password-nya direset walaupun tidak ada tanda penyalahgunaan. Lihat bagian 1.3, 1.10, dan 2.1.

</details>

**4. Skenario keputusan.** Kamu melihat Event 4769 dari satu laptop staf: 37 service ticket untuk 37 layanan berbeda dalam tiga menit, sebagian besar dengan enkripsi `0x17`. Semua permintaan berhasil. Apa penilaian yang paling tepat?

- A. Normal, karena semua permintaan berhasil dan tidak ada login gagal.
- B. Pola yang cocok dengan Kerberoasting; naikkan segera ke L2, karena tiket yang sudah keluar bisa ditebak offline dan permintaan tiket memang selalu berhasil untuk user domain.
- C. Abaikan sampai ada akun yang terkunci.

<details><summary>Jawaban</summary>

B. Pada Kerberoasting, semua permintaan memang berhasil, karena setiap user domain berhak meminta service ticket; yang membuatnya mencurigakan adalah jumlah, jumlah layanan berbeda, dan enkripsi RC4 dibanding kebiasaan akun itu. A keliru karena keberhasilan tiket bukan tanda aman. C keliru karena penebakan password dilakukan di komputer penyerang, tidak pernah memicu penguncian akun di AD. Lihat bagian 1.10 dan 2.4.

</details>

**5. Jelaskan ulang.** Jelaskan kepada anggota keluargamu yang bukan orang IT, dalam tiga kalimat, kenapa penyerang yang masuk ke satu laptop kantor biasanya langsung mengincar Active Directory.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Di kantorku, ada satu sistem pusat yang seperti kantor administrasi gedung: ia menyimpan data semua karyawan, memeriksa password mereka, dan menerbitkan kartu akses ke semua ruangan. Penyusup yang masuk lewat satu laptop hanya bisa membuka satu ruangan, tetapi kalau ia berhasil menguasai kantor administrasi itu, ia bisa membuat kartu akses sendiri untuk semua ruangan. Jadi pekerjaanku termasuk mengawasi tanda-tanda orang mencoba mendekati kantor administrasi itu, misalnya nama baru yang tiba-tiba masuk daftar pemegang kunci master."

Kesalahan yang sering muncul:
- Memakai istilah teknis tanpa penjelasan (domain controller, Kerberos, Domain Admins) kepada orang yang bukan orang IT.
- Menjelaskan seolah-olah penyerang langsung masuk ke sistem pusat, padahal biasanya ia masuk lewat satu laptop atau satu akun karyawan dulu.
- Lupa menyebut kenapa itu berbahaya: satu sistem pusat memegang akses ke hampir semua komputer.

</details>

**6. Pertanyaan jebakan.** "Kalau sebuah server mencatat login dengan Authentication Package NTLM, itu pasti serangan pass-the-hash." Benarkah?

<details><summary>Jawaban</summary>

Tidak. NTLM masih dipakai secara sah oleh perangkat dan aplikasi yang tidak mendukung Kerberos, oleh komputer di luar domain, dan untuk login dengan akun lokal; Windows juga jatuh ke NTLM bila Kerberos tidak bisa dipakai. Contohnya mesin pemindai di `SOC-2027-0839`. Yang membuat NTLM mencurigakan adalah konteksnya: sumber yang tidak dikenal, akun admin yang biasanya memakai Kerberos tiba-tiba memakai NTLM, akun yang login ke banyak komputer dalam waktu singkat, atau versi `NTLM V1`. Lihat bagian 1.7 dan 2.3.

</details>

**7. Interview question (English).** "Walk me through what happens with Kerberos when a domain user logs on and opens a file share, and explain how it differs from NTLM. Why do attackers care?"

<details><summary>Sample answer</summary>

"When the user types their password, the workstation doesn't send it. It sends a pre-authentication timestamp encrypted with a key derived from the password to the KDC, which runs on every domain controller. If that checks out, the KDC issues a ticket-granting ticket, logged as event 4768 on the DC, which by default is valid for up to ten hours. When the user opens a file share, the client presents the TGT to the KDC and asks for a service ticket for that server's SPN, logged as 4769. The client then hands that ticket to the file server, which decrypts it with its own key and creates a network logon, a 4624 with logon type 3 and Kerberos as the package, without calling the DC. With NTLM it's a challenge-response computed from the password hash, and the server has to pass every authentication to the DC, which logs 4776; there's also no mutual authentication. Attackers care because both produce reusable credential material. A stolen NTLM hash can be used directly in pass-the-hash. With Kerberos, any domain user can request service tickets and try to crack weak service account passwords offline, which is Kerberoasting, and anyone who gets the krbtgt key can forge TGTs for any account, a golden ticket. So in a SOC I watch for RC4 service tickets and spikes in 4769 per account, unexpected NTLM from admin accounts, and any change to privileged groups like Domain Admins, which shows up as 4728."

What makes this answer strong: it follows the real order of events and names the log generated at each step and where it is generated, contrasts the two protocols on the points interviewers probe (DC involvement, mutual authentication, what is reusable), and ends with concrete detection ideas instead of only naming attacks.

</details>

## 8. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Microsoft Learn: Active Directory Domain Services overview | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview | primer (dokumentasi vendor) | ms.date 2025-03-10; diakses 2026-10-21 | Tinggi. Definisi directory dan AD DS, schema, global catalog, replikasi semua DC |
| S2 | Microsoft Learn: Understanding the Active Directory Logical Model | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/understanding-the-active-directory-logical-model | primer (dokumentasi vendor) | ms.date 2025-05-12; diakses 2026-10-21 | Tinggi. Forest, domain, OU, trust dua arah, fungsi DC |
| S3 | Microsoft Learn: Active Directory Security Groups | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups | primer (dokumentasi vendor) | ms.date 2025-07-02; diakses 2026-10-21 | Tinggi. Security vs distribution group, user rights vs permissions, scope group |
| S4 | Microsoft Learn: Active Directory Privileged Accounts and Groups Guide | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory | primer (dokumentasi vendor) | ms.date 2025-07-04; diakses 2026-10-21 | Tinggi. Hak Domain Admins, Enterprise Admins, Administrators, Schema Admins; krbtgt; user biasa bisa membaca sebagian besar directory |
| S5 | Microsoft Learn: Best practices for securing Active Directory | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory | primer (dokumentasi vendor) | ms.date 2025-05-21; diakses 2026-10-21 | Tinggi. Target pencurian kredensial, keamanan DC, hapus keanggotaan permanen, host administrasi aman |
| S6 | Microsoft Learn: Group Managed Service Accounts overview | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/group-managed-service-accounts-overview | primer (dokumentasi vendor) | ms.date 2025-07-01; diakses 2026-10-21 | Tinggi. Password gMSA dikelola Windows |
| S7 | Microsoft Learn: Domain member: Maximum machine account password age | https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/domain-member-maximum-machine-account-password-age | primer (dokumentasi vendor) | ms.date 2020-05-29; diakses 2026-10-21 | Tinggi. Setiap perangkat punya akun dan password; bawaan ganti setiap 30 hari. URL dialihkan ke bagian previous versions |
| S8 | RFC 4511: Lightweight Directory Access Protocol (LDAP): The Protocol | https://www.rfc-editor.org/rfc/rfc4511.html | primer (standar IETF) | Juni 2006; diakses 2026-10-21 | Tinggi. Definisi LDAP |
| S9 | Microsoft Learn: Service overview and network port requirements for Windows | https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements | primer (dokumentasi vendor) | ms.date 2026-02-12; diakses 2026-10-21 | Tinggi. Port Kerberos 88, LDAP 389, LDAP SSL 636, global catalog 3268 |
| S10 | Microsoft Learn: Kerberos authentication overview in Windows Server | https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview | primer (dokumentasi vendor) | ms.date 2026-09-14; diakses 2026-10-21 | Tinggi. KDC di setiap DC, TGT, service ticket, mutual authentication, NTLM tanpa verifikasi server, perubahan Server 2025 |
| S11 | RFC 4120: The Kerberos Network Authentication Service (V5) | https://www.rfc-editor.org/rfc/rfc4120.html | primer (standar IETF) | Juli 2005; diakses 2026-10-21 | Tinggi. Pihak ketiga tepercaya, AS dan TGS, tiket disegel kunci server, jam sinkron sekitar 5 menit, kunci dari password |
| S12 | Microsoft Learn: Maximum lifetime for user ticket | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/maximum-lifetime-for-user-ticket | primer (dokumentasi vendor) | ms.date 2017-04-19; diakses 2026-10-21 | Tinggi. TGT bawaan 10 jam, akun nonaktif masih bisa memakai tiket lama, urutan penerapan GPO |
| S13 | Microsoft Learn: NTLM overview in Windows Server | https://learn.microsoft.com/en-us/windows-server/security/kerberos/ntlm-overview | primer (dokumentasi vendor) | ms.date 2025-04-17; diakses 2026-10-21 | Tinggi. Keluarga NTLM, challenge-response, server menghubungi DC, kapan NTLM masih dipakai |
| S14 | Microsoft Learn: Deprecated features in the Windows client (entri NTLM) | https://learn.microsoft.com/en-us/windows/whats-new/deprecated-features | primer (dokumentasi vendor) | ms.date 2026-09-23; diakses 2026-10-21 | Tinggi. NTLM deprecated Juni 2024; NTLMv1 dihapus mulai Windows 11 24H2 dan Server 2025 |
| S15 | Microsoft Learn: Group Policy overview for Windows Server | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-overview | primer (dokumentasi vendor) | ms.date 2025-06-10; diakses 2026-10-21 | Tinggi. GPO, SYSVOL, tautan ke site/domain/OU, penerapan saat startup dan login, pewarisan OU |
| S16 | Microsoft Learn: 4624(S) An account was successfully logged on | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624 | primer (dokumentasi vendor) | ms.date 2021-09-07; diakses 2026-10-21 | Tinggi. Logon Type 2, 3, 5, 10, 11; Authentication Package dan Negotiate; Package Name NTLM |
| S17 | Microsoft Learn: 4625(F) An account failed to log on | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625 | primer (dokumentasi vendor) | ms.date 2026-03-29; diakses 2026-10-21 | Tinggi. Tercatat di komputer tempat login dicoba |
| S18 | Microsoft Learn: 4768(S, F) A Kerberos authentication ticket (TGT) was requested | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768 | primer (dokumentasi vendor) | ms.date 2021-10-20, pembaruan Januari 2025; diakses 2026-10-21 | Tinggi. Hanya di DC, kode 0x18 ke 4771, jenis enkripsi, pre-auth type, akun komputer berakhiran $, SID |
| S19 | Microsoft Learn: 4769(S, F) A Kerberos service ticket was requested | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769 | primer (dokumentasi vendor) | ms.date 2021-09-07, pembaruan Januari 2025; diakses 2026-10-21 | Tinggi. Hanya di DC, Service Name, definisi SPN, pantau enkripsi selain 0x11 dan 0x12 |
| S20 | Microsoft Learn: 4776(S, F) The computer attempted to validate the credentials for an account | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4776 | primer (dokumentasi vendor) | ms.date 2021-09-13; diakses 2026-10-21 | Tinggi. Validasi NTLM, DC otoritatif untuk akun domain, hanya mencatat komputer asal, kode 0xC000006A |
| S21 | Microsoft Learn: Audit Security Group Management | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management | primer (dokumentasi vendor) | ms.date 2021-09-06; diakses 2026-10-21 | Tinggi. Event 4728, 4729, 4732, 4756; volume rendah; rekomendasi audit Success |
| S22 | MITRE ATT&CK T1558.003: Steal or Forge Kerberos Tickets: Kerberoasting | https://attack.mitre.org/techniques/T1558/003/ | primer (basis pengetahuan MITRE) | versi 1.3, diubah 2025-10-24; diakses 2026-10-21 | Tinggi. Mekanisme konsep, tanda 4769 dan RC4, mitigasi password panjang, gMSA, AES |
| S23 | MITRE ATT&CK T1550.002: Use Alternate Authentication Material: Pass the Hash | https://attack.mitre.org/techniques/T1550/002/ | primer (basis pengetahuan MITRE) | versi 2.0, diubah 2026-05-12; diakses 2026-10-21 | Tinggi. Definisi konsep |
| S24 | MITRE ATT&CK T1558.001: Steal or Forge Kerberos Tickets: Golden Ticket | https://attack.mitre.org/techniques/T1558/001/ | primer (basis pengetahuan MITRE) | versi 1.2, diubah 2025-10-24; diakses 2026-10-21 | Tinggi. TGT palsu dari hash krbtgt; reset krbtgt dua kali |
| S25 | Canadian Centre for Cyber Security: Joint guidance on detecting and mitigating Active Directory compromises | https://www.cyber.gc.ca/en/news-events/joint-guidance-detecting-and-mitigating-active-directory-compromises | primer (badan pemerintah) | dimodifikasi 2026-09-15; diakses 2026-10-21 | Tinggi. AD sebagai target bernilai tinggi; contoh teknik Kerberoasting, DCSync, golden ticket, Shadow Credentials |
| S26 | CISA: Detecting and Mitigating Active Directory Compromises | https://www.cisa.gov/resources-tools/resources/detecting-and-mitigating-active-directory-compromises | primer (badan pemerintah) | revisi 2026-09-15; diakses 2026-10-21 | Tinggi. 17 teknik umum, badan penyusun. Isi PDF lengkap tidak diperiksa langsung; daftar bab AD CS dan golden ticket dikutip dari daftar isi |

**Catatan sumber:** isi PDF panduan bersama ASD dan mitranya tidak dibaca langsung; klaim bahwa panduan itu memuat kompromi AD CS diambil dari daftar isinya, sedangkan contoh teknik lain diambil dari halaman badan siber Kanada [S25] dan CISA [S26]. Field Event 4728 di bagian 2.1 mengikuti struktur event 4732 yang dirujuk halaman audit [S21] dan disederhanakan untuk ilustrasi. Klaim bahwa laptop meminta service ticket untuk akun komputernya sendiri saat login, dan bahwa komputer menemukan DC lewat DNS, adalah pengetahuan umum tentang domain Windows yang konsisten dengan contoh event di [S19] tetapi tidak dikutip dari satu halaman khusus. Istilah "tree" untuk domain bersambung tidak muncul di halaman logical model yang diperiksa [S2]; istilah ini disebut singkat karena masih sering muncul di materi lain. Seluruh isi PT JAB (struktur OU, nama GPO, akun, alert `SOC-2027-0838` sampai `SOC-2027-0840`, insiden `INC-2027-086`, waktu, dan angka) adalah contoh fiktif.
