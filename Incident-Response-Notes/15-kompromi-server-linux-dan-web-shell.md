---
day: 15
title: 'Respons kompromi server Linux dan web shell: titik masuk, access log, auditd, persistence, DMZ, dan pemulihan aplikasi'
researched_on: 2026-10-15
versions_checked: 'MITRE ATT&CK v20 (T1505.003, T1190, T1053.003, T1098.004, T1543.002, T1574.006; halaman dimodifikasi 2025-10-24 sampai 2026-05-12); CISA Eviction Strategies Tool CM0106 Eliminate Web Shells dan CM0027 Rebuild Compromised Host (versi 1.0, Maret 2025); NSA Cybersecurity, repositori Mitigating-Web-Shells di GitHub; OWASP File Upload Cheat Sheet; auditctl(8) man-pages; crontab(1) Debian bookworm; Elastic Security prebuilt rule Suspicious Child Execution via Web Server (rule version 118, dokumentasi Elastic Security 8.19); Sigma rule Webshell Remote Command Execution (status test)'
---

# Day 15: Respons kompromi server Linux dan web shell (titik masuk, access log, auditd, persistence, DMZ, dan pemulihan aplikasi)

Cakupan: menemukan titik masuk aplikasi yang dipakai menaruh web shell, membaca access log untuk memisahkan penyerang dari scanner, merekonstruksi perintah yang dijalankan lewat web shell di server Linux tanpa EDR, mencari persistence khas Linux, menilai lateral movement dari DMZ dan akses ke database, lalu membersihkan dan memulihkan aplikasi web tanpa membawa celah dan file penyerang ikut kembali.

## Ide inti

Web shell bukan malware yang masuk sendiri; ia adalah file yang ditaruh lewat celah aplikasi, lalu dipanggil dengan request HTTP biasa. Akibatnya ada dua hal yang sering terlewat. Pertama, web shell hanya pintu pertama: dalam beberapa menit penyerang biasanya sudah menjalankan perintah sebagai user web server, membaca kredensial di konfigurasi aplikasi, dan memasang jalan masuk kedua yang tidak bergantung pada web shell maupun alamat IP-nya. Kedua, bukti terbaik justru ada di luar web shell: access log menunjukkan bagaimana file itu masuk, log audit proses menunjukkan apa yang dijalankan, dan log firewall menunjukkan ke mana server itu berbicara. Respons yang baik membaca ketiganya, mencari semua pintu yang ditinggalkan, menutup celah aplikasinya, lalu memulihkan server dari sumber yang diketahui bersih.

Kamu sudah mengenal pola ini dari NOC. Bayangkan router edge yang web management-nya terbuka ke internet dan punya celah di fitur unggah file. Penyerang menaruh skrip lewat fitur itu, lalu memerintah router lewat HTTP. Engineer yang hanya memblok IP penyerang di ACL merasa aman, padahal dari router itu penyerang sudah membuka tunnel keluar ke servernya sendiri dan menyimpan salinan skrip di folder lain. Engineer yang berpengalaman membandingkan running-config dengan golden config, mencari tunnel dan akun yang tidak dikenal, menutup akses web management dari internet, lalu memuat ulang router dari konfigurasi standar. Bedanya di server Linux: jumlah tempat persistence jauh lebih banyak, dan aplikasi web yang berjalan di atasnya juga harus diperbaiki, bukan hanya sistem operasinya.

```
celah aplikasi (unggah file)
  |
  v
web shell ditaruh di direktori web --> request POST memerintah shell
  |                                     (access log: siapa, kapan, berapa byte)
  v
perintah sebagai user web server       (auditd execve: apa yang dijalankan)
  |
  +-- baca kredensial di konfigurasi --> database (log koneksi DB)
  +-- unduh alat, buka tunnel keluar  --> firewall (koneksi keluar dari DMZ)
  +-- pasang persistence              --> cron, shell kedua, systemd, key SSH
  +-- coba bergerak dari DMZ          --> firewall internal (deny)
  |
  v
blok IP penyerang saja = gejala; tunnel dan shell kedua tetap hidup
  |
  v
bukti -> containment serentak -> rebuild dari sumber bersih + perbaiki aplikasi
```

Situasi yang dipakai sepanjang Day ini adalah `INC-2026-012` di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif. Sabtu 12 September 2026 pukul 01:40, alert `SOC-2026-0127` menandai file PHP baru di direktori upload server portal pelanggan `jkt-portal01`, diikuti request POST ke file itu dari `198.51.100.23`. Insiden dinyatakan SEV-2 pukul 02:55 dan IP penyerang diblok di firewall perimeter pukul 04:31 setelah tertunda karena masalah wewenang (sisi proses dan eskalasi malam itu dibahas di Day 02). `jkt-portal01` belum memakai EDR; log server dikirim ke Splunk, dan live response dilakukan lewat SSH dari `jkt-bastion01`. Handover pukul 07:00 diterima technical lead Sari Kusuma, dan pukul 09:04 peran IC diserahkan dari Dimas Prasetyo ke Yoga Pratama. Pukul 08:20 Sari menemukan koneksi keluar dari `jkt-portal01` yang masih aktif walaupun IP penyerang sudah diblok. Pukul 09:15, Yoga menulis di kanal `#inc-2026-012`:

> "Sar, saya sudah baca handover dan temuanmu jam 08:20. Sebelum update ke Pak Hendra jam 10:50, saya perlu jawaban untuk ini. Bagaimana caranya dia bisa menaruh file PHP di server kita, dan apakah celahnya masih terbuka? Access log semalam isinya ribuan request, mana yang benar-benar dia? Tanpa EDR, bagaimana kita tahu apa saja yang dia jalankan? IP-nya sudah diblok jam 04:31, kenapa masih ada koneksi keluar, dan apa lagi yang dia tinggalkan? Apakah dia bisa pindah dari portal ke server lain atau ke database pelanggan? Retainer datang jam 10:00; cukup hapus shell.php lalu patch, atau harus bangun ulang? Lalu bagaimana memastikan portal yang nanti online lagi tidak bisa dibobol dengan cara yang sama?"

Pesan itu memuat tujuh pertanyaan:

1. Bagaimana file PHP bisa ditaruh, dan apakah celahnya masih terbuka?
2. Mana request penyerang di antara ribuan request semalam?
3. Bagaimana tahu perintah yang dijalankan tanpa EDR?
4. Kenapa masih ada koneksi keluar setelah IP diblok, dan apa lagi yang ditinggalkan?
5. Apakah penyerang bisa pindah dari portal ke server lain atau ke database?
6. Cukup hapus web shell, atau bangun ulang?
7. Bagaimana memastikan portal tidak dibobol dengan cara yang sama?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, pertanyaan 6 di bagian 1.6, dan pertanyaan 7 di bagian 1.7. Bagian 2 berisi query, perintah, dan dokumen yang dipakai Sari dan retainer hari itu.

**Kapan relevan:** setiap kali server yang menghadap internet menjalankan file atau proses yang tidak dikenal, terutama server aplikasi web Linux tanpa EDR; juga saat menyiapkan logging, aturan auditd, dan segmentasi DMZ sebelum insiden.
**Kapan bukan jawaban:** Day ini tidak mengulang dasar pengambilan bukti Linux, containment, dan rebuild yang sudah dibahas di Day 04, Day 05, dan Day 06; yang dibahas di sini adalah bagian yang khas web shell dan server Linux. Day ini juga bukan panduan menulis web shell atau mengeksploitasi aplikasi; semua contoh menjelaskan jejak, bukan cara menyerang.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (severity, IC, technical lead, scoping, live response, AVML, chain of custody, containment, egress allowlist, rebuild, gold image, akar masalah, rotasi rahasia) tidak diulang. Tabel berikut memuat istilah baru Day ini. Kolom padanan memakai analogi NOC dan SOC yang sama di semua Day IR.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Web shell | Skrip yang ditaruh di server web yang bisa diakses publik, dipakai penyerang untuk menjalankan perintah lewat HTTP | Skrip yang ditanam di router lewat celah web management, lalu diperintah dari luar |
| Exploit public-facing application | Masuk lewat kelemahan aplikasi atau layanan yang menghadap internet (T1190) | Masuk lewat celah di web management perangkat edge |
| Access log | Log server web yang mencatat setiap request: IP, waktu, metode, path, status, ukuran respons, user agent | Syslog perangkat yang mencatat setiap akses ke antarmuka manajemen |
| Scanner internet | Klien otomatis yang mengirim ribuan request ke banyak path untuk mencari celah umum; kebanyakan berakhir 404 | Trafik scanning port dan SNMP dari internet yang terus menghantam perangkat edge |
| URI langka | Path yang diminta oleh sangat sedikit IP dalam satu periode; web shell biasanya termasuk di sini | Prefix yang hanya muncul dari satu peer di tabel routing |
| Known-good comparison | Membandingkan isi direktori web di server dengan salinan bersih dari repositori aplikasi | Membandingkan running-config dengan golden config |
| Proses anak web server | Proses yang dijalankan oleh proses web server atau PHP-FPM; pada aplikasi web biasa hampir tidak pernah ada | Router yang tiba-tiba menjalankan skrip dari antarmuka web management |
| Aturan auditd execve | Aturan audit kernel Linux yang mencatat setiap program yang dijalankan, bisa dibatasi per user | Accounting TACACS untuk setiap perintah yang diketik di perangkat |
| Jalan masuk kedua | Akses cadangan yang dipasang penyerang supaya tidak bergantung pada web shell pertama atau IP-nya | Tunnel GRE tersembunyi yang dibuat penyusup di router selain akses web management |
| Persistence Linux | Cara bertahan di server Linux: cron, unit systemd, `authorized_keys`, akun baru, `LD_PRELOAD`, modul web server, file tambahan di direktori web | Konfigurasi tambahan yang membuat perubahan penyusup aktif lagi setelah reboot |
| DMZ | Segmen jaringan untuk server yang menghadap internet, dipisah firewall dari jaringan internal | DMZ di edge yang memisahkan server publik dari jaringan manajemen |
| Egress dari DMZ | Koneksi keluar yang dibuka server DMZ sendiri; idealnya hampir tidak ada | Trafik yang berasal dari router sendiri, bukan trafik pelanggan yang lewat |

### 1.1 Titik masuk: file itu masuk lewat fitur apa, dan apakah pintunya masih terbuka

Pertanyaan pertama Yoga adalah pertanyaan yang paling sering dilewati, karena tim terburu-buru menghapus web shell. Padahal web shell hanyalah hasil; selama pintu yang dipakai untuk menaruhnya masih terbuka, siapa pun bisa menaruh file baru setelah file lama dihapus.

ATT&CK memasukkan cara masuk ini ke T1190, Exploit Public-Facing Application: penyerang memanfaatkan bug, salah konfigurasi, atau kelemahan di sistem yang menghadap internet untuk mendapat akses awal [S5]. Web shell sendiri masuk ke T1505.003, dan strategi deteksinya di Linux dimulai dari file skrip yang tidak sah muncul di direktori web, lalu web server menjalankan program yang tidak wajar [S4]. Untuk menemukan titik masuk, tiga sumber dicocokkan:

1. **Waktu file dibuat.** Waktu modifikasi dan perubahan metadata file web shell memberi patokan detik. Waktu itu bisa diubah penyerang, jadi dicocokkan dengan sumber lain, tidak dipercaya sendirian.
2. **Access log di sekitar waktu itu.** Request yang berakhir tepat sebelum file muncul, biasanya `POST` ke endpoint yang menerima file, adalah kandidat titik masuk.
3. **Kode aplikasi.** Endpoint kandidat dibaca di repositori aplikasi bersama pemiliknya untuk memastikan kelemahannya, tanpa mencobanya ulang di server produksi.

Di `INC-2026-012`, `shell.php` muncul di `/var/www/portal/uploads/` pukul 01:38:02. Access log mencatat satu `POST /api/upload-bukti` dari `198.51.100.23` pada detik yang sama, tanpa request login sebelumnya. Tim aplikasi portal membaca endpoint itu bersama Sari dan menemukan tiga kelemahan yang bertumpuk: endpoint unggah bukti transfer tidak memeriksa sesi login, ekstensi file hanya dicek di sisi browser, dan file disimpan dengan nama aslinya di direktori yang berada di bawah webroot dan ikut diproses PHP-FPM. Satu kelemahan saja belum cukup untuk menaruh web shell yang bisa dipanggil; ketiganya bersama-sama cukup.

OWASP File Upload Cheat Sheet memberi daftar kontrol yang berlapis karena tidak ada satu kontrol yang cukup: allowlist ekstensi yang dicek di server setelah nama file di-decode, tidak memercayai header `Content-Type`, nama file dibuat ulang oleh server, file disimpan di luar webroot atau di host terpisah, izin direktori yang mencegah file unggahan dieksekusi, dan unggahan hanya untuk pengguna yang terautentikasi dan berwenang [S10]. Ketiga kelemahan portal PT JAB melanggar empat kontrol itu sekaligus.

Jawaban untuk Yoga: pada pukul 09:15 pintunya masih terbuka. Siapa pun bisa mengunggah file `.php` baru ke endpoint yang sama. Karena itu penutupan sementara endpoint dan larangan eksekusi PHP di direktori unggahan masuk rencana jam H (bagian 2.6), bersama tindakan lain, mengikuti prinsip containment serentak di Day 05 bagian 1.7.

### 1.2 Memisahkan penyerang dari scanner di access log

Pertanyaan kedua Yoga ("access log isinya ribuan request") wajar: server yang menghadap internet menerima scanning terus-menerus, dan malam itu `jkt-portal01` mencatat 18.412 request antara 00:00 dan 08:00. Mencari penyerang dengan membaca baris satu per satu tidak mungkin.

Repositori mitigasi web shell NSA memakai dua pendekatan yang saling melengkapi [S1]:

- **Known-good comparison:** bandingkan file di server produksi dengan salinan bersih aplikasi untuk menemukan file baru atau berubah. Hasilnya tetap perlu ditinjau manual karena perubahan yang sah juga muncul.
- **Anomali trafik web:** cari URI yang jarang diminta, dengan melihat user agent, IP klien, dan referrer. Web shell biasanya hanya dipanggil oleh satu atau dua IP, sedangkan halaman sah dipanggil banyak klien. Repositori itu mengingatkan bahwa cara ini menghasilkan false positive dan hanya satu lapis pertahanan.

Dari dua pendekatan itu, Sari memakai urutan berikut:

1. **Pivot dari file yang sudah diketahui.** Semua IP yang meminta `shell.php`, lalu semua request dari IP itu, termasuk sebelum dan sesudah web shell dipakai.
2. **URI langka dengan status sukses.** Path yang diminta kurang dari tiga IP, berakhir `.php`, dan mendapat status 200. Scanner menghasilkan banyak path langka juga, tetapi hampir semuanya 404.
3. **Lihat pola, bukan IP.** Scanner mengirim ribuan request ke path acak dalam waktu singkat. Penyerang mengirim sedikit request ke path yang sama, sering `POST`, dengan ukuran respons yang berubah-ubah karena isi respons tergantung perintah.

Hasil di `INC-2026-012` (rinciannya di bagian 2.1): dua IP scanner menyumbang 15.984 request dengan mayoritas 404, sedangkan `198.51.100.23` hanya mengirim 14 request. Langkah kedua menemukan sesuatu yang terlewat semalam: file PHP kedua, `/assets/fonts/fontawesome-webfont.php`, yang dipanggil `198.51.100.23` sekali pukul 03:49 dan oleh IP lain, `198.51.100.226`, pukul 05:12 dan 06:30. Pengecekan malam itu ("tidak ada request ke `shell.php` setelah 04:31") benar, tetapi hanya memeriksa satu file, sehingga request ke file kedua setelah blokir tidak terlihat.

Perhatian: access log hanya mencatat request yang dilayani web server ini. Web shell yang dikendalikan lewat cookie atau header, atau request yang tidak sampai ke log karena konfigurasi, tidak terlihat di path. Karena itu access log dipakai bersama log proses (bagian 1.3), bukan sendirian.

### 1.3 Mengetahui perintah yang dijalankan tanpa EDR

Pertanyaan ketiga Yoga punya jawaban yang bergantung pada persiapan sebelum insiden. Tanpa EDR, yang menentukan adalah apakah kernel diminta mencatat program yang dijalankan.

Aplikasi web biasa hampir tidak pernah menjalankan program lain. Karena itu aturan deteksi web shell di Linux berpusat pada satu pola: proses web server atau PHP-FPM yang memulai program lain. Rule Elastic "Suspicious Child Execution via Web Server" menganggap `nginx`, `apache2`, dan `php-fpm*` sebagai induk, lalu menandai anak yang dijalankan dari path seperti `/tmp`, `/var/tmp`, `/dev/shm`, atau `/var/www`, nama yang diawali titik, dan alat pengintai atau jaringan seperti `whoami`, `ss`, `cat`, `curl`, dan `base64`; panduan triage-nya meminta pemeriksaan pohon proses, koneksi, file yang dijatuhkan, dan persistence seperti cron [S13]. Rule komunitas Sigma "Webshell Remote Command Execution" lebih sederhana: setiap `execve` atau `execveat` dengan `euid` 33, yaitu `www-data` di Debian dan Ubuntu, dan rule itu hanya bekerja bila aturan auditd untuk `execve` dengan filter user web server sudah dipasang [S14].

Aturan auditd ditulis dengan bentuk syscall: `-a always,exit -F arch=b64 -S execve` ditambah filter seperti `-F euid=33` dan kunci pencarian `-k`. Halaman manual `auditctl` menyebut `-F arch` harus ditulis sebelum `-S` supaya tabel syscall yang benar dipakai, dan menyarankan dua aturan, satu untuk `b32` dan satu untuk `b64`, karena aturan syscall tanpa arsitektur berlaku untuk keduanya [S11]. Aturan yang hanya ditambahkan lewat `auditctl` di shell hilang saat reboot; aturan permanen ditulis di file aturan audit (halaman manual menyebut `/etc/audit/audit.rules`; cek lokasi direktori aturan di distribusimu) [S11].

PT JAB punya aturan itu di baseline server web sejak temuan audit internal tahun lalu, dan log `linux_audit` dikirim ke Splunk. Malam itu auditd mencatat 37 eksekusi oleh `euid` 33 antara 01:41 dan 04:02. Rule SOC untuk eksekusi oleh user web server menghasilkan alert `SOC-2026-0128` pukul 01:42, tetapi alert itu berprioritas P3 dan baru dibaca pagi hari, karena malam itu semua perhatian ada di alert `SOC-2026-0127` dan urusan eskalasi. Ringkasan temuannya, dalam bahasa temuan dan bukan perintah:

- 01:41: program pengenal sistem dan user (`id`, `uname`, `ps`), daftar isi direktori unggahan, dan pencarian file konfigurasi.
- 01:52: pembacaan file konfigurasi database aplikasi `/var/www/portal/config/database.php`.
- 02:16: klien PostgreSQL dijalankan oleh `www-data` (argumen tidak disalin ke catatan karena memuat kredensial).
- 02:22: program pemindai koneksi dijalankan, cocok dengan deny di firewall internal (bagian 1.5).
- 03:47 sampai 03:55: file baru ditulis ke `/var/tmp/.sess/`, izin eksekusi diberikan, program `kthreadd2` dijalankan dari sana, lalu `crontab` dijalankan oleh `www-data`.
- Setelah 04:02 tidak ada eksekusi baru oleh `euid` 33 kecuali yang dijalankan cron tiap 10 menit.

Batas yang harus disebut saat melapor: auditd mencatat program yang dijalankan, bukan apa yang dilakukan PHP di dalam prosesnya sendiri. File yang dibaca langsung oleh kode PHP web shell tanpa menjalankan program lain tidak muncul di aturan `execve`. Jadi "tidak ada di auditd" berarti "tidak ada program yang dijalankan", bukan "tidak ada yang dibaca". Bila aturan ini tidak ada, sumber yang tersisa adalah memori (diambil retainer dengan AVML, Day 04 bagian 1.4), waktu file di disk, dan log jaringan.

### 1.4 Kenapa masih ada koneksi keluar: jalan masuk kedua dan persistence

Pertanyaan keempat Yoga menyentuh pola paling umum pada web shell: blokir IP penyerang hanya memutus satu kanal. Pada pukul 04:31, saat `198.51.100.23` diblok, penyerang sudah 40 menit punya kanal lain.

Temuan Sari pukul 08:20 dan pemeriksaan lanjutan menunjukkan tiga hal yang dipasang sebelum blokir:

1. **Proses `kthreadd2`** dari `/var/tmp/.sess/`, berjalan sebagai `www-data` sejak 03:52, memegang koneksi keluar ke `203.0.113.225:443`. Namanya meniru thread kernel, tetapi thread kernel asli tidak punya file eksekusi di `/var/tmp`.
2. **Entri cron milik `www-data`** yang dibuat 03:55 dan menjalankan ulang program itu setiap 10 menit bila mati. Crontab user di Debian disimpan per user di `/var/spool/cron/crontabs`, dan untuk sistem Debian standar semua user boleh memakai `crontab` kecuali dibatasi `cron.allow` atau `cron.deny` [S12].
3. **File PHP kedua** di direktori `assets/fonts`, yang diakses dari IP lain setelah blokir (bagian 1.2).

Karena satu jalan masuk hampir selalu disertai jalan lain, pemeriksaan persistence di server Linux dilakukan dengan daftar, bukan berdasarkan temuan pertama. Tabel berikut adalah daftar PT JAB; kolom kanan menunjukkan apa yang ditemukan di `jkt-portal01`, termasuk yang dicek dan tidak ditemukan.

| Tempat | Kenapa diperiksa | Di `jkt-portal01` |
|---|---|---|
| Cron user dan sistem | Penyerang menjadwalkan program supaya hidup lagi; ATT&CK menyarankan memantau crontab yang dibuat user non-root atau dari proses induk tak wajar [S6] | Ditemukan: crontab `www-data` 03:55 |
| Unit systemd sistem dan user | Unit `.service` bisa menjalankan program saat boot; unit user tidak butuh root, dan `ExecStart` yang menunjuk `/tmp` atau `/dev/shm` patut diprioritaskan [S8] | Tidak ditemukan unit baru atau berubah |
| `authorized_keys` semua akun | Kunci publik penyerang memberi login SSH yang tidak bergantung pada web shell [S7] | Tidak ditemukan perubahan; `www-data` tidak punya direktori `.ssh` |
| Akun dan grup baru | Akun lokal baru, terutama dengan UID 0 atau grup sudo | Tidak ditemukan |
| `LD_PRELOAD` dan `/etc/ld.so.preload` | Library yang dimuat lebih dulu bisa menyembunyikan file dan proses dari `ls` atau `ps` [S9] | `/etc/ld.so.preload` tidak ada; variabel `LD_PRELOAD` tidak ditemukan di environment proses |
| Konfigurasi dan modul web server | Modul atau direktif yang memuat kode penyerang di setiap request | Konfigurasi `nginx` dan pool PHP-FPM sama dengan repositori konfigurasi |
| File di direktori web yang tidak ada di repositori | Web shell kedua dan seterusnya | Ditemukan: file PHP di `assets/fonts` dan `shell.php` |
| Proses dan koneksi aktif | Program yang sedang berjalan dari lokasi aneh | Ditemukan: `kthreadd2` ke `203.0.113.225:443` |

Satu catatan untuk tabel itu: semua yang ditemukan berjalan sebagai `www-data`, dan tempat yang butuh root tidak berubah. Itu konsisten dengan penyerang yang tidak berhasil menaikkan hak, tetapi belum membuktikannya. Library preload yang disembunyikan dengan baik atau celah kernel bisa membuat pemeriksaan dari dalam server memberi jawaban yang salah; itulah salah satu alasan keputusan di bagian 1.6.

### 1.5 Bergerak dari DMZ: server lain dan database

Pertanyaan kelima Yoga dijawab dengan log di luar server, karena server yang terkompromi tidak bisa dipercaya untuk melaporkan dirinya sendiri.

`jkt-portal01` (`10.20.8.11`) berada di segmen DMZ `10.20.8.0/24`. Aturan firewall internal saat itu hanya mengizinkan dua arah dari DMZ ke dalam: ke `jkt-billingdb01` (`10.20.5.30`) port 5432 untuk akun database `portal_ro`, dan dari `jkt-bastion01` untuk SSH. ATT&CK menyebut segmentasi server yang menghadap internet sebagai salah satu mitigasi T1190 [S5]. Dua temuan:

- **Server lain.** Pukul 02:22 sampai 02:23 firewall internal mencatat 214 deny dari `10.20.8.11` ke 61 alamat di `10.20.0.0/16` pada port 22, 445, dan 3389. Rule korelasi menghasilkan alert `SOC-2026-0129` pukul 02:23, yang masuk antrean P3 dan baru dibaca pagi hari. Tidak ada koneksi yang diizinkan selain ke database. Segmentasi bekerja; deteksinya tidak diprioritaskan.
- **Database.** Log PostgreSQL saat itu hanya mencatat koneksi, bukan query. Koneksi aplikasi portal berasal dari pool yang dibuka saat layanan mulai dan bertahan, sehingga koneksi baru di tengah malam menonjol. Log mencatat satu koneksi `portal_ro` dari `10.20.8.11` pukul 02:16:31 sampai 02:19:48, cocok dengan klien PostgreSQL di auditd (bagian 1.3). Log firewall internal untuk sesi itu mencatat 41.296 byte dari database ke portal.

Akun `portal_ro` hanya boleh membaca view `v_tagihan_portal` (nomor pelanggan, nama, periode, nominal, status bayar), bukan tabel pelanggan dengan NIK dan alamat. 41.296 byte cukup untuk ratusan baris dari view itu, sehingga kesimpulan Sari: data pribadi pelanggan dalam jumlah terbatas kemungkinan dibaca, dengan keyakinan sedang. Direktori unggahan juga berisi 1.214 file bukti transfer pelanggan; auditd mencatat daftar isi direktori itu, tidak ada program pengarsip atau penyalin yang dijalankan, dan total trafik keluar ke `203.0.113.225` sampai 08:20 adalah 1,9 MB. Pembacaan sebagian file oleh kode PHP tidak bisa disingkirkan (batas auditd di bagian 1.3).

Penilaian ini diteruskan ke DPO Agus Setiawan dan Legal Ratna Sari, yang sudah diberi tahu pukul 06:50. Severity tetap SEV-2: kompromi terkonfirmasi tetapi terbatas, dengan data pribadi dalam jumlah terbatas. Kewajiban pemberitahuan atas data yang mungkin dibaca diputuskan DPO dan dibahas di Day 18.

### 1.6 Hapus web shell atau bangun ulang

Pertanyaan keenam Yoga ("cukup hapus `shell.php` lalu patch?") punya jawaban yang sama dengan Day 06 bagian 1.2: yang menentukan adalah apa yang tidak kamu ketahui. Di sini yang tidak diketahui cukup banyak: apakah penyerang menaikkan hak, apa yang dibaca PHP di luar catatan auditd, dan apakah ada file ketiga yang belum ditemukan.

Countermeasure CISA CM0106 untuk menghapus web shell berisi tujuh langkah: isolasi server web untuk mengurangi kemungkinan lateral movement; amankan artefak disk dan memori serta log OS, aplikasi web, access, error, WAF, reverse proxy, CDN, firewall DMZ, dan database; hapus web shell; ganti password admin web, user database, akun hosting, dan akses jarak jauh; investigasi kerentanan atau penyebab pembobolan; pulihkan dari backup bersih; lalu patch dan perkuat aplikasi atau server web [S2]. CM0106 juga menyebut web shell sering dipakai bersama alat lain sehingga countermeasure tambahan mungkin dibutuhkan, dan penghapusan bisa butuh downtime yang harus disiapkan [S2]. CM0027 untuk rebuild host meminta sumber image, software, dan backup diverifikasi bersih, sistem dihapus aman, OS dan aplikasi dipasang ulang dari image bersih, lalu patch diterapkan, setelah cakupan kompromi ditentukan [S3].

Untuk `jkt-portal01`, Sari dan retainer merekomendasikan rebuild dengan tiga perbedaan dibanding rebuild server biasa:

- **Aplikasi dari repositori, bukan dari server.** Kode portal diambil dari tag rilis di repositori dan diperbaiki dulu (bagian 1.7), bukan disalin dari server lama, karena salinan dari server lama membawa file penyerang.
- **Data unggahan dipulihkan sebagai data.** 1.214 bukti transfer dibutuhkan untuk proses billing, jadi tidak dibuang. File dipindah ke penyimpanan baru di luar webroot hanya bila tipe isinya cocok dengan gambar atau PDF; file lain, termasuk semua yang berakhiran skrip, dikarantina sebagai bukti.
- **Rahasia yang bisa dibaca `www-data` dirotasi.** Password `portal_ro`, secret sesi aplikasi, dan kunci API yang tersimpan di konfigurasi aplikasi. Kunci privat TLS dimiliki root dengan izin 600 dan tidak terbaca `www-data`; tidak dirotasi, dan alasannya dicatat sesuai prinsip inventaris rahasia di Day 06 bagian 1.4.

Penghapusan `shell.php` dan file kedua tetap dilakukan, tetapi sebagai bagian dari containment setelah bukti diambil, bukan sebagai pengganti rebuild.

### 1.7 Supaya portal tidak dibobol dengan cara yang sama

Pertanyaan terakhir Yoga adalah inti eradication untuk insiden aplikasi web: rebuild menghapus penyerang dari server, tetapi tidak menutup pintunya. Day 06 bagian 1.3 menyebut rebuild tanpa menutup jalan masuk mengundang penyerang kembali.

Perbaikan dibagi tiga lapis, dan setiap lapis punya pemilik:

1. **Aplikasi (Tim Aplikasi Portal).** Endpoint unggah wajib sesi login dan hanya untuk pemilik akun; allowlist ekstensi dan pemeriksaan tipe isi di server; nama file dibuat server; file disimpan di luar webroot dan disajikan lewat handler aplikasi [S10]. Perbaikan diuji oleh pihak di luar tim pembuat sebelum portal online.
2. **Server web (Infrastruktur).** `nginx` menolak menjalankan atau meneruskan file skrip apa pun di direktori unggahan ke PHP-FPM, sebagai lapis kedua bila validasi aplikasi gagal [S10]; isi webroot dibandingkan dengan hash rilis setiap hari (known-good comparison, [S1]); aturan auditd `execve` untuk `www-data` dipertahankan.
3. **Jaringan dan deteksi (NOC dan SOC).** Egress dari DMZ ditutup kecuali tujuan yang disebut (Splunk forwarder, NTP, repositori paket lewat proxy); alert eksekusi oleh `www-data` dan deny dari DMZ ke dalam dinaikkan dari P3 ke P1 untuk server DMZ, karena malam itu dua alert yang benar (`SOC-2026-0128` dan `SOC-2026-0129`) menunggu di antrean berjam-jam.

Perbaikan proses dari insiden ini juga melahirkan playbook `JAB-PB-04` Kompromi aplikasi web dan web shell, yang dibahas di post-incident review 22 September (Day 02).

## 2. Contoh artefak dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Access log `nginx` `jkt-portal01` dikirim ke Splunk index `linux` dengan sourcetype `nginx_access`, dan log auditd dengan sourcetype `linux_audit`; nama sourcetype dan field (`clientip`, `method`, `uri_path`, `status`, `bytes` untuk access log; `syscall`, `euid`, `exe` untuk auditd) bergantung pada add-on yang kamu pakai, jadi cocokkan dulu. Perintah di server dijalankan lewat SSH dari `jkt-bastion01` dengan toolkit tepercaya, mengikuti Day 04 bagian 1.4.

### 2.1 Access log: siapa saja yang berbicara dengan portal malam itu

Query ini menjawab pertanyaan kedua Yoga: dari 18.412 request, mana yang penyerang.

**Tujuan:** meringkas semua request ke `jkt-portal01` per IP klien, lalu memisahkan scanner (banyak path, hampir semua 404) dari klien yang sedikit request tetapi sukses ke file skrip.

```
index=linux sourcetype=nginx_access host=jkt-portal01
earliest="09/12/2026:00:00:00" latest="09/12/2026:08:00:00"
| eval sukses=if(status>=200 AND status<300, 1, 0)
| eval php=if(match(uri_path, "\.php$"), 1, 0)
| stats count as req dc(uri_path) as uri_unik sum(sukses) as s2xx sum(php) as req_php
        min(_time) as first max(_time) as last by clientip
| where req>1000 OR req_php>0
| sort - req
| convert ctime(first) ctime(last)
```

Penjelasan tiap bagian:

- `sukses` dan `php` adalah penanda 0 atau 1 per request, sehingga `sum()` menghitung request sukses dan request ke file berakhiran `.php` per IP.
- `dc(uri_path)` menghitung path unik. Scanner meminta ribuan path berbeda; web shell dipanggil di path yang sama berulang kali.
- `where req>1000 OR req_php>0` menampilkan dua kelompok yang ingin dibandingkan: penyumbang trafik terbesar dan siapa pun yang meminta file `.php`. Portal PT JAB tidak menyajikan halaman `.php` langsung ke pelanggan (semua lewat router aplikasi di `/`), jadi request ke path `.php` di luar itu patut dicurigai.

Keluaran ilustrasi:

```
clientip         req    uri_unik  s2xx  req_php  first                last
203.0.113.221    9870   9611        41      388  09/12/2026 00:12:40  09/12/2026 03:05:18
203.0.113.229    6114   5902        37      251  09/12/2026 05:40:02  09/12/2026 07:58:31
198.51.100.23      14      3        14       13  09/12/2026 01:38:02  09/12/2026 04:29:40
198.51.100.226      2      1         2        2  09/12/2026 05:12:03  09/12/2026 06:30:41
```

Cara membaca hasil:

- Dua baris teratas adalah scanner: 9.870 dan 6.114 request (total 15.984), hampir sebanyak itu path unik, dan sebagian besar gagal (9.829 dan 6.077 request tidak 2xx). Request `.php` mereka adalah tebakan nama file umum, hampir semuanya 404.
- `198.51.100.23` hanya 14 request ke 3 path, semuanya sukses: satu `POST /api/upload-bukti` pukul 01:38:02, dua belas `POST /uploads/shell.php` antara 01:41:05 dan 04:29:40, dan satu request ke `/assets/fonts/fontawesome-webfont.php` pukul 03:49:10. Polanya kebalikan scanner: sedikit, terarah, dan sukses.
- `198.51.100.226` adalah temuan baru: dua request sukses ke `fontawesome-webfont.php` pukul 05:12:03 dan 06:30:41, setelah `198.51.100.23` diblok 04:31. IP baru, file yang sama, jadi ini penyerang yang sama atau rekannya.
- Sisa 2.412 request malam itu berasal dari klien pelanggan biasa yang tidak meminta file `.php` dan tidak lolos filter `where`.

**Variasi:** ganti `by clientip` dengan `by uri_path` dan tambahkan `dc(clientip) as ip_unik`, lalu saring `ip_unik<3 AND s2xx>0`. Ini pendekatan URI langka dari bagian 1.2, yang menemukan file web shell tanpa perlu tahu IP penyerang lebih dulu [S1].

**Kapan gagal:** web shell dipanggil lewat path halaman sah dengan parameter, cookie, atau header khusus, sehingga `uri_path` tidak menonjol; atau log tidak memuat body `POST`, yang memang tidak dicatat `nginx` secara default. Dalam kedua kasus, log proses (bagian 2.3) yang menjadi sumber utama.

### 2.2 Known-good comparison: file mana yang bukan milik aplikasi

Langkah ini menjawab bagian kedua pertanyaan keempat Yoga ("apa lagi yang dia tinggalkan?") untuk isi direktori web.

**Tujuan:** menemukan file skrip di webroot yang tidak ada di rilis aplikasi atau isinya berbeda.

```bash
# di jkt-bastion01: daftar hash rilis dari repositori (tag yang terpasang di produksi)
git -C /srv/repo/portal archive v3.8.2 | tar -x -C /tmp/portal-v3.8.2
cd /tmp/portal-v3.8.2 && find . -type f -name '*.php' -exec sha256sum {} + | sort -k2 > /tmp/rilis.sha256

# di jkt-portal01 lewat SSH, dengan sha256sum dari toolkit
cd /var/www/portal && /mnt/irkit/bin/find . -type f -name '*.php' \
  -exec /mnt/irkit/bin/sha256sum {} + | sort -k2 > /mnt/irout/server.sha256

# kembali di bastion (folder output insiden yang sama di-mount di /mnt/irout): bandingkan
diff /tmp/rilis.sha256 /mnt/irout/server.sha256
```

Penjelasan tiap bagian:

- Daftar acuan dibuat dari tag rilis di repositori, bukan dari server lain, karena server lain bisa saja ikut terkompromi.
- `find` dan `sha256sum` dijalankan dari toolkit tepercaya di NFS bukti (Day 04 bagian 1.4), dan keluarannya ditulis ke folder insiden, bukan ke disk server.
- `diff` menampilkan file yang hanya ada di salah satu sisi atau hash-nya berbeda. Repositori NSA memakai `diff` untuk perbandingan yang sama di Linux dan mengingatkan bahwa setiap hasil harus ditinjau manual karena perubahan yang sah juga muncul [S1].

Keluaran ilustrasi (diringkas, hash dipotong):

```
> 5e0c...  ./assets/fonts/fontawesome-webfont.php
> 91ab...  ./storage/cache/routes.php
> d47f...  ./uploads/shell.php
```

Cara membaca hasil:

- Tanda `>` berarti file hanya ada di server. Tidak ada baris `<` atau pasangan hash berbeda, sehingga file aplikasi asli tidak diubah.
- `storage/cache/routes.php` dibuat aplikasi sendiri saat cache dibangun ulang. Tim aplikasi mengonfirmasi namanya, dan waktunya (Kamis 10 September 14:05) jauh sebelum insiden. Dicatat sebagai sudah dijelaskan.
- Dua file lain adalah web shell yang sudah diketahui. Tidak ada file ketiga di webroot.

**Variasi:** jalankan perbandingan yang sama untuk direktori konfigurasi `nginx` dan pool PHP-FPM terhadap repositori konfigurasi, yang menghasilkan baris "sama dengan repositori" di tabel bagian 1.4.

**Kapan gagal:** aplikasi tidak punya rilis yang bisa direproduksi, atau tim mengedit file langsung di server. Tanpa acuan, perbandingan berubah menjadi tebakan; perbaikannya adalah proses rilis, bukan alat.

### 2.3 Auditd: program apa yang dijalankan user web server

Query ini menjawab pertanyaan ketiga Yoga dengan data dari aturan `execve` yang dibahas di bagian 1.3.

**Tujuan:** meringkas semua program yang dijalankan dengan `euid` 33 (`www-data`) di `jkt-portal01` malam itu.

```
index=linux sourcetype=linux_audit host=jkt-portal01 type=SYSCALL euid=33
(syscall=59 OR syscall=execve)
earliest="09/12/2026:01:00:00" latest="09/12/2026:04:04:59"
| stats count min(_time) as first max(_time) as last by exe
| sort first
| convert timeformat="%H:%M:%S" ctime(first) ctime(last)
```

Penjelasan tiap bagian:

- `syscall=59` adalah nomor `execve` di x86_64; sebagian add-on menerjemahkannya menjadi nama, jadi keduanya ditulis.
- `euid=33` membatasi ke proses yang berjalan sebagai user web server, sesuai rule Sigma yang sama [S14].
- Rentang diakhiri 04:04:59, sebelum putaran cron pertama milik penyerang pukul 04:05, supaya ringkasan ini hanya berisi aktivitas interaktif. Eksekusi oleh cron dihitung terpisah di variasi.

Keluaran ilustrasi:

```
exe                          count  first     last
/usr/bin/dash                    8  01:41:05  03:51:58
/usr/bin/id                      1  01:41:06  01:41:06
/usr/bin/uname                   1  01:41:06  01:41:06
/usr/bin/ps                      2  01:41:07  02:21:42
/usr/bin/ls                      6  01:41:08  03:47:41
/usr/bin/find                    3  01:41:09  01:41:40
/usr/bin/cat                     4  01:52:04  03:58:14
/usr/bin/psql                    1  02:16:29  02:16:29
/usr/bin/bash                    1  02:21:47  02:21:47
/usr/bin/hostname                1  02:24:06  02:24:06
/usr/bin/chmod                   1  03:47:40  03:47:40
/var/tmp/.sess/kthreadd2         1  03:52:02  03:52:02
/usr/bin/crontab                 2  03:55:01  03:55:20
/usr/bin/ss                      2  03:56:30  03:58:02
/usr/bin/head                    3  03:59:40  04:02:11
```

Cara membaca hasil:

- Totalnya 37 eksekusi, sama dengan angka di bagian 1.3. Argumen tidak ditampilkan di ringkasan ini; untuk `psql` dan `bash`, argumen di event aslinya memuat kredensial dan daftar alamat, dan disimpan di folder bukti, tidak disalin ke catatan.
- Delapan `dash` adalah shell yang dibuka PHP-FPM, satu untuk setiap request web shell sampai 03:51:58. Waktunya cocok dengan delapan dari dua belas `POST` ke `shell.php` di access log (bagian 2.1).
- Empat `POST` sesudahnya (04:10 sampai 04:29) tidak menghasilkan satu pun eksekusi. Artinya request itu dikerjakan oleh kode PHP di dalam prosesnya sendiri, misalnya membaca file, yang tidak terlihat oleh aturan `execve` (batas di bagian 1.3).
- `crontab`, `ss`, satu `cat`, dan `head` setelah 03:52 tidak punya request web yang cocok. Proses induknya, dilihat dari `ppid` di event yang sama, adalah `kthreadd2`. Penyerang sudah memerintah lewat kanal kedua sebelum IP pertamanya diblok.

**Variasi:** perpanjang `latest` sampai 08:20 untuk menghitung putaran cron penyerang (setiap 10 menit sejak 04:05), lalu ganti `by exe` dengan `by exe, ppid` untuk memetakan pohon proses.

**Kapan gagal:** aturan `execve` untuk user web server tidak terpasang, hanya dipasang untuk satu arsitektur, atau log audit tidak dikirim keluar server sehingga bisa dihapus penyerang yang naik ke root.

### 2.4 Pemeriksaan persistence dengan daftar

Langkah ini mengisi kolom kanan tabel bagian 1.4 dan menjawab "apa lagi yang dia tinggalkan?" untuk sisi sistem operasi. Semua perintah hanya membaca, dijalankan dari toolkit, dan keluarannya disimpan ke folder insiden.

**Tujuan:** memeriksa setiap tempat persistence di daftar PT JAB, bukan berhenti di temuan pertama.

```bash
K=/mnt/irkit/bin
# cron: crontab per user dan direktori cron sistem, diurutkan dari yang terbaru
sudo $K/ls -la --time-style=full-iso /var/spool/cron/crontabs/ /etc/cron.d/
sudo $K/cat /var/spool/cron/crontabs/www-data
# systemd: unit yang berubah setelah rilis terakhir, di lokasi sistem dan user
sudo $K/find /etc/systemd /lib/systemd /usr/lib/systemd /home /root /var/www \
  -name '*.service' -newer /var/www/portal/VERSION -printf '%TY-%Tm-%Td %TT %p\n'
# kunci SSH dan akun
sudo $K/find / -xdev -name authorized_keys -printf '%TY-%Tm-%Td %TT %u %p\n'
$K/awk -F: '$3==0 || $3>=1000 {print $1, $3, $7}' /etc/passwd
# library preload
$K/ls -la /etc/ld.so.preload
sudo $K/grep -l LD_PRELOAD /proc/[0-9]*/environ
# proses dan koneksi
sudo $K/ss -tnp state established
sudo $K/ls -l /proc/[0-9]*/exe 2>/dev/null | $K/grep -E '/tmp/|/var/tmp/|/dev/shm/'
```

Penjelasan tiap bagian:

- Isi crontab dibaca dengan `cat` dari spool, bukan diubah. Halaman manual `crontab` Debian menyebut crontab per user disimpan di `/var/spool/cron/crontabs` dan tidak dimaksudkan untuk diedit langsung [S12].
- `-newer /var/www/portal/VERSION` memakai file penanda rilis terakhir sebagai patokan waktu, sehingga unit yang dibuat setelah rilis muncul. Waktu file bisa dipalsukan, jadi daftar ini melengkapi, bukan menggantikan, perbandingan isi.
- `/proc/<PID>/exe` menunjuk ke file eksekusi proses yang sedang berjalan; proses yang berjalan dari `/tmp`, `/var/tmp`, atau `/dev/shm` patut diprioritaskan, sesuai daftar lokasi di rule Elastic [S13].

Keluaran ilustrasi (diringkas):

```
-rw------- 1 www-data crontab 2026-09-12 03:55:20 /var/spool/cron/crontabs/www-data
*/10 * * * *  [perintah memeriksa dan menjalankan ulang /var/tmp/.sess/kthreadd2; disalin ke bukti]

ESTAB  10.20.8.11:48802  203.0.113.225:443  users:(("kthreadd2",pid=4410,fd=3))
lrwxrwxrwx 1 www-data www-data /proc/4410/exe -> /var/tmp/.sess/kthreadd2
ls: cannot access '/etc/ld.so.preload': No such file or directory
```

Cara membaca hasil:

- Crontab `www-data` diubah pukul 03:55:20, cocok dengan dua eksekusi `crontab` di auditd (bagian 2.3). Isi baris lengkapnya disimpan di bukti, tidak disalin ke catatan.
- Satu koneksi keluar ke `203.0.113.225:443` dipegang `kthreadd2` (PID 4410) yang berjalan dari `/var/tmp/.sess/`. Ini temuan Sari pukul 08:20.
- `find` untuk unit systemd dan `authorized_keys` tidak mengembalikan baris baru, dan tidak ada akun UID 0 selain `root`. Hasil kosong ini dicatat sebagai "sudah diperiksa, tidak ditemukan" di scope statement.

**Kapan gagal:** penyerang sudah root dan memasang rootkit yang menyembunyikan file dan proses dari perintah di server itu. Toolkit tepercaya mengurangi risiko dari biner yang diganti, tetapi tidak dari kernel yang dimanipulasi; pembanding dari luar (analisis memori retainer, log firewall) tetap diperlukan.

### 2.5 Log firewall: ke mana `jkt-portal01` berbicara

Query ini menjawab pertanyaan kelima Yoga dari sisi jaringan, dengan sumber yang tidak bisa diubah dari dalam server.

**Tujuan:** meringkas semua koneksi dari `jkt-portal01` (`10.20.8.11`) malam itu, dengan deny ke jaringan internal dikelompokkan menjadi satu baris.

```
index=firewall src_ip=10.20.8.11
earliest="09/12/2026:00:00:00" latest="09/12/2026:08:20:00"
| eval tujuan=if(action="blocked" AND cidrmatch("10.20.0.0/16", dest_ip), "internal_ditolak", dest_ip)
| stats count dc(dest_ip) as dest_unik values(dest_port) as port sum(bytes) as bytes
        min(_time) as first max(_time) as last by tujuan, action
| search NOT tujuan IN ("10.20.1.50", "10.20.1.60")
| sort first
| convert timeformat="%H:%M:%S" ctime(first) ctime(last)
```

Penjelasan tiap bagian:

- `tujuan` menyatukan semua deny ke `10.20.0.0/16` menjadi satu baris supaya pola pemindaian terbaca sekaligus; koneksi lain tetap per IP tujuan.
- Baris terakhir menyembunyikan tujuan sah yang sudah dikenal (indexer Splunk dan server NTP di contoh ini) supaya keluaran pendek; di investigasi sungguhan, tujuan sah tetap dilihat sekali.

Keluaran ilustrasi:

```
tujuan             action   count  dest_unik  port           bytes    first     last
10.20.5.30         allowed      1          1  5432           41296    02:16:31  02:19:48
internal_ditolak   blocked    214         61  22 445 3389        0    02:22:03  02:23:10
203.0.113.225      allowed      3          1  443          1902340    03:52:05  08:20:00
```

Cara membaca hasil:

- Satu sesi ke database billing pukul 02:16:31 sampai 02:19:48 dengan 41.296 byte, cocok dengan `psql` di auditd dan log koneksi PostgreSQL (bagian 1.5).
- 214 deny ke 61 alamat internal dalam satu menit lebih sedikit: pemindaian dari DMZ yang ditolak segmentasi. Tidak ada baris `allowed` ke alamat internal selain database.
- Tiga sesi ke `203.0.113.225:443` sejak 03:52:05 dengan total 1.902.340 byte (sekitar 1,9 MB) sampai 08:20. Egress dari DMZ saat itu belum dibatasi, sehingga koneksi ini diizinkan; itulah kenapa blokir `198.51.100.23` tidak memutusnya.

**Kapan gagal:** firewall hanya mencatat sesi saat ditutup, sehingga sesi panjang yang masih terbuka belum muncul atau `bytes`-nya belum lengkap. Cek apakah firewall-mu mengirim log interim untuk sesi panjang.

### 2.6 Keputusan pukul 10:50 dan rencana jam H

Dokumen ini menjawab pertanyaan keenam dan ketujuh Yoga sekaligus, dan menjadi isi update ke Hendra. Mematikan portal adalah tindakan berdampak layanan pelanggan, sehingga A-nya Hendra sesuai RACI di Day 02 bagian 2.2.

```
INC-2026-012 | Update dan permintaan keputusan | Sabtu 2026-09-12 10:50 WIB
Untuk: Hendra Wijaya | Dari: Yoga Pratama (IC), Sari Kusuma (TL)
Severity: SEV-2 sejak 02:55

TEMUAN SEJAK 07:00
- Titik masuk: endpoint unggah bukti transfer tanpa cek login; file PHP bisa diunggah
  dan dijalankan. Celah MASIH TERBUKA.
- Jalan masuk kedua sejak 03:52 (proses kthreadd2 + cron), koneksi keluar ke
  203.0.113.225 masih aktif; web shell kedua dipakai IP 198.51.100.226 setelah blokir.
- Database: satu sesi akun portal_ro 02:16-02:19 (sekitar 41 KB, view tagihan, tanpa NIK).
- Server lain: 214 percobaan ke jaringan internal, semua ditolak.
- Bukti: memori diambil retainer 10:20-10:42 (AVML); image disk setelah server dimatikan.

PERMINTAAN KEPUTUSAN
- Portal dialihkan ke halaman pemeliharaan mulai 12:00 sampai server pengganti lolos
  validasi, perkiraan Minggu 13 September malam. Alternatif (portal tetap jalan dengan
  endpoint unggah ditutup) tidak direkomendasikan: server tidak bisa dipercaya.

KEPUTUSAN (Hendra Wijaya, 11:05): disetujui. Corporate Communication menyiapkan
pengumuman pemeliharaan portal; pembayaran lewat kanal lain tetap jalan.
```

Rencana jam H berikut mengikuti pola Day 05 bagian 2.2. Kolom Verifikasi menunjukkan bukti bahwa tindakan berjalan, bukan hanya diperintahkan.

| Menit | Tindakan | R (pelaksana) | A | Verifikasi |
|---|---|---|---|---|
| H-30 (11:30) | Go/no-go di bridge: NOC, Infrastruktur, Tim Aplikasi Portal, retainer | Semua | IC | Setiap pelaksana menjawab "siap" |
| H+0 | Firewall perimeter: trafik portal dialihkan ke halaman pemeliharaan statis di `jkt-static01` (`10.20.8.20`) | NOC | Hendra | Portal menampilkan halaman pemeliharaan dari luar |
| H+0 | Egress `jkt-portal01` ditutup kecuali indexer Splunk; blok `203.0.113.225` dan `198.51.100.226` di perimeter dengan logging | NOC | IC | Deny tercatat; sesi ke `203.0.113.225` hilang dari `ss` |
| H+5 | Rotasi password `portal_ro`, secret sesi aplikasi, dan kunci API di konfigurasi portal | Tim Aplikasi Portal | IC | Login lama ditolak database dan penyedia API |
| H+10 | `jkt-portal01` dimatikan; image disk oleh retainer | Retainer | IC | Hash image tercatat di evidence log |
| H+15 | Validasi: tidak ada koneksi baru dari `10.20.8.11`, tidak ada request ke path web shell di perimeter | Sari | IC | Query bagian 2.1 dan 2.5 dengan rentang sejak jam H |

Setelah jam H, rebuild mengikuti bagian 1.6 dan 1.7: server pengganti `jkt-portal02` (`10.20.8.12`) dibangun dari image bersih, kode dari tag rilis yang sudah diperbaiki, data unggahan dipulihkan sebagai data, `nginx` melarang eksekusi skrip di direktori unggahan, aturan auditd dan egress allowlist DMZ aktif sejak hari pertama. Perbaikan endpoint diuji retainer sebelum portal online kembali Minggu 13 September 21:40.

Cara membaca elemennya:

- **Celah ditulis "masih terbuka"** dengan huruf besar karena itulah alasan utama portal tidak dibiarkan jalan: menutup satu endpoint di server yang tidak bisa dipercaya tidak menutup apa yang sudah dipasang di dalamnya.
- **Alternatif yang ditolak tetap ditulis**, sama seperti memo Day 05 bagian 2.1, supaya keputusan bisa dipertanggungjawabkan.
- **Server lama dimatikan setelah memori diambil**, mengikuti urutan bukti sebelum containment di Day 04.

**Kapan gagal:** egress ditutup lebih dulu tanpa koordinasi, padahal proses penyerang memakai kanal itu untuk perintah; penyerang yang kehilangan kanal kedua bisa kembali lewat web shell yang belum diblok bila halaman pemeliharaan belum aktif. Karena itu dua tindakan H+0 dijalankan dalam menit yang sama.

## 3. Lab praktik (di VM lab terisolasi)

Lab ini memakai VM Linux lab dengan `nginx` dan PHP-FPM, Splunk lab, dan satu VM klien. Tidak ada web shell sungguhan: "web shell" di lab adalah file PHP jinak yang hanya mencetak teks tetap dan tidak menerima input apa pun, dan "persistence" adalah entri cron jinak yang menulis waktu ke file. Semua langkah di VM dengan snapshot, dan jangan memakai data atau nama dari pekerjaan nyata.

1. **Logging lebih dulu.** Pasang aturan auditd `execve` untuk user web server, dua arsitektur, dengan kunci pencarian, mengikuti bagian 1.3. Kirim access log `nginx` dan log audit ke Splunk. Catat UID user web server di distribusimu (33 di Debian dan Ubuntu).
2. **Buat jejak.** Taruh `uploads/catatan.php` berisi satu baris yang mencetak teks tetap. Dari VM klien, panggil file itu lima kali. Dari host yang sama, jalankan juga satu perintah sederhana sebagai user web server dengan `sudo -u` untuk menghasilkan event `execve` (misalnya `id`), dan tambahkan entri cron jinak untuk user itu yang menulis waktu ke `/tmp/lab-cron.txt` setiap 10 menit.
3. **Buat kebisingan.** Dari VM klien, kirim beberapa ratus request ke path acak yang tidak ada, sehingga access log berisi pola scanner.
4. **Investigasi.** Jalankan query bagian 2.1 dan variasi URI langka. Pastikan `catatan.php` muncul dan scanner terpisah. Jalankan query bagian 2.3 dan cocokkan waktu `execve` dengan request di access log.
5. **Known-good comparison.** Simpan salinan bersih webroot sebelum langkah 2 sebagai "rilis". Jalankan perbandingan bagian 2.2 dan pastikan `catatan.php` muncul sebagai file yang hanya ada di server.
6. **Daftar persistence.** Jalankan perintah bagian 2.4 dan isi tabel seperti bagian 1.4, termasuk baris "tidak ditemukan".
7. **Tutup pintunya.** Ubah konfigurasi `nginx` supaya file `.php` di direktori `uploads` tidak diteruskan ke PHP-FPM. Panggil ulang `catatan.php` dan pastikan statusnya 403 atau 404, dan tidak ada event `execve` baru.
8. **Dokumen.** Tulis update dan permintaan keputusan dengan format bagian 2.6 untuk skenario lab-mu, termasuk satu alternatif yang ditolak.

**Hasil yang sebaiknya tersimpan:**

- Aturan auditd dan konfigurasi pengiriman log yang dipakai.
- Hasil query bagian 2.1 dan 2.3, dengan catatan request mana yang cocok dengan eksekusi mana.
- Hasil perbandingan bagian 2.2 dan tabel persistence dari langkah 6.
- Potongan konfigurasi `nginx` dari langkah 7 dan bukti status penolakan.
- `latihan/day15-update.md` berisi update dan permintaan keputusan.

**Variasi tantangan:** matikan aturan auditd sebelum langkah 2, lalu coba jawab "program apa saja yang dijalankan user web server?" hanya dari access log dan waktu file. Catat pertanyaan mana yang tidak bisa dijawab tanpa log proses.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat menangani web shell di server Linux. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Koneksi keluar tetap ada setelah IP penyerang diblok | Jalan masuk kedua dengan tujuan lain; egress DMZ terbuka | `ss` dan log firewall dari server; tutup egress DMZ kecuali tujuan yang disebut |
| Request ke web shell tidak terlihat di access log | Perintah lewat cookie, header, atau body yang tidak dicatat | Pakai log proses dan log jaringan; jangan menyimpulkan dari path saja |
| Auditd tidak mencatat apa pun dari user web server | Aturan tidak ada, salah UID, atau hanya satu arsitektur | Cek aturan aktif dengan `auditctl -l`; aturan `b32` dan `b64` [S11] |
| Ada request web shell tetapi tidak ada `execve` | Kode PHP bekerja di dalam prosesnya sendiri | Catat sebagai batas visibilitas; bandingkan dengan waktu akses file dan trafik keluar |
| Perbandingan file menghasilkan ratusan perbedaan | Acuan bukan rilis yang terpasang, atau ada file cache dan unggahan | Pakai tag rilis yang tepat; pisahkan direktori unggahan dan cache, lalu tinjau sisanya [S1] |
| Web shell muncul lagi setelah dihapus | Celah aplikasi belum ditutup atau persistence belum dibersihkan | Tutup endpoint dan larang eksekusi skrip di direktori unggahan; jalankan daftar persistence [S2][S10] |
| Alert eksekusi oleh user web server menunggu berjam-jam | Prioritas alert untuk server DMZ terlalu rendah | Naikkan prioritas untuk server yang menghadap internet |

## 5. Kesalahan umum dan jebakan

- Menghapus web shell sebelum mengambil bukti dan sebelum tahu titik masuknya. File baru bisa ditaruh lagi, dan bukti waktu file hilang [S2].
- Menganggap blokir IP penyerang sama dengan containment. Penyerang biasanya sudah punya kanal kedua.
- Mencari hanya file yang sudah diketahui. Di `INC-2026-012`, pengecekan "tidak ada request ke `shell.php`" melewatkan web shell kedua.
- Membaca "tidak ada di auditd" sebagai "tidak ada yang dibaca". Aturan `execve` tidak melihat kerja kode PHP di dalam prosesnya.
- Menyalin kode aplikasi dari server lama ke server baru. File penyerang ikut terbawa; ambil dari repositori.
- Rebuild tanpa memperbaiki endpoint. Server baru dengan celah yang sama akan dibobol dengan cara yang sama.
- Hanya merotasi password database, padahal rahasia lain yang bisa dibaca user web server (secret sesi, kunci API) juga terpapar.
- Membiarkan egress DMZ terbuka "karena selama ini tidak ada masalah". Server yang menghadap internet hampir tidak pernah perlu memulai koneksi ke sembarang tujuan.

## 6. Catatan terkini

Bagian ini menampung detail versi sumber yang bisa berubah. Berguna saat membuka sumbernya lagi, tetapi tidak mengubah langkah investigasi di atas.

- **MITRE ATT&CK v20**: halaman teknik yang dipakai (T1505.003, T1190, T1053.003, T1098.004, T1543.002, T1574.006) dimodifikasi antara Oktober 2025 dan Mei 2026. Panduan deteksi di ATT&CK sekarang dikelompokkan sebagai detection strategy per teknik; nama dan nomornya bisa berubah antar versi [S4][S5][S6][S7][S8][S9].
- **CISA Eviction Strategies Tool**: CM0106 Eliminate Web Shells dan CM0027 Rebuild Compromised Host versi 1.0, dibuat Maret 2025 [S2][S3].
- **Repositori NSA Mitigating-Web-Shells** berisi panduan bersama NSA dan ASD yang terbit 2020, beserta skrip dan query contoh. Contoh query di repositori itu belum tentu cocok dengan nama field add-on Splunk terbaru [S1].
- **Rule Elastic** yang dikutip adalah versi 118 di dokumentasi Elastic Security 8.19; daftar induk dan path di rule ini bertambah dari versi ke versi [S13]. **Rule Sigma** berstatus test [S14].

## 7. Cheat sheet

```
WEB SHELL = hasil; TITIK MASUK = masalahnya
  cocokkan: waktu file + access log (POST sebelum file muncul) + kode aplikasi
  OWASP upload: allowlist ekstensi di server, nama dibuat server, simpan di luar webroot,
                larang eksekusi di direktori unggahan, hanya user terautentikasi

ACCESS LOG: scanner = banyak path, banyak 404 | penyerang = sedikit path, sukses, POST
  pivot dari file yang diketahui -> semua IP -> semua request IP itu
  URI langka (<3 IP, .php, 2xx) | batas: body/cookie/header tidak tercatat

TANPA EDR: auditd execve euid=<UID web server>, b32 + b64, kirim ke SIEM
  induk php-fpm/nginx/apache menjalankan program = hampir selalu salah
  batas: kerja PHP di dalam proses tidak tercatat

PERSISTENCE (daftar, bukan temuan pertama): cron user + sistem | systemd sistem + user
  | authorized_keys | akun UID 0 / baru | ld.so.preload + LD_PRELOAD | konfigurasi web server
  | file di webroot vs rilis | proses dari /tmp /var/tmp /dev/shm + koneksi

DMZ: deny ke internal = segmentasi bekerja; alert harus dibaca | egress DMZ ditutup
  DB: log koneksi + byte firewall + izin akun DB = batas atas data yang terbaca

ERADICATION: bukti -> containment serentak (alih portal + tutup egress) -> rebuild
  kode dari repositori | data unggahan sebagai data | rotasi rahasia yang terbaca user web
  perbaikan aplikasi diuji pihak lain sebelum online
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "IP penyerang sudah diblok pukul 04:31 dan tidak ada request ke `shell.php` setelah itu, jadi penyerang sudah tidak punya akses ke `jkt-portal01`." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Sejak 03:52 penyerang punya proses `kthreadd2` yang memegang koneksi keluar ke `203.0.113.225:443` dan dijalankan ulang oleh cron setiap 10 menit, dan web shell kedua di `assets/fonts` dipakai IP lain pukul 05:12 dan 06:30. Pengecekan malam itu hanya melihat satu file dan satu IP. Lihat bagian 1.2, 1.4, dan 2.4.

</details>

**2. Skenario keputusan.** Pukul 09:20 tim aplikasi menawarkan, "Kami hapus `shell.php` sekarang dan tambah validasi ekstensi di endpoint unggah, portal tidak perlu berhenti." Respons mana yang tepat?

- A. Setuju, karena celah ditutup dan web shell hilang.
- B. Tunda penghapusan sampai bukti diambil; ajukan ke Hendra pengalihan portal ke halaman pemeliharaan dan rebuild dari repositori yang sudah diperbaiki, dengan tindakan jam H yang serentak.
- C. Setuju menghapus web shell sekarang, lalu putuskan rebuild setelah retainer datang.

<details><summary>Jawaban</summary>

B. Server tidak bisa dipercaya: ada jalan masuk kedua, akses ke database, dan bagian yang tidak terlihat oleh auditd, sehingga rebuild lebih aman daripada membersihkan di tempat; mematikan portal adalah keputusan Hendra. A keliru karena hanya menutup satu pintu dan satu file, sementara `kthreadd2` dan web shell kedua tetap ada. C keliru karena menghapus sebelum bukti diambil menghilangkan waktu file dan memberi tanda ke penyerang sebelum tindakan lain siap. Lihat bagian 1.1, 1.6, dan 2.6.

</details>

**3. Pertanyaan jebakan.** "Auditd tidak mencatat eksekusi apa pun untuk empat request terakhir ke `shell.php` (04:10 sampai 04:29), jadi request itu tidak melakukan apa-apa." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Aturan `execve` hanya mencatat program yang dijalankan. Kode PHP web shell bisa membaca file atau mengirim data dari dalam prosesnya sendiri tanpa menjalankan program lain, dan itu tidak tercatat. Yang benar adalah "tidak ada program yang dijalankan", dan pembacaan file oleh PHP tetap tidak bisa disingkirkan. Lihat bagian 1.3 dan 2.3.

</details>

**4. Skenario keputusan.** Saat memeriksa persistence, Yoga menemukan crontab `www-data` milik penyerang. Ia mengusulkan berhenti di situ karena "persistence-nya sudah ketemu". Respons mana yang tepat?

- A. Setuju, satu persistence biasanya cukup bagi penyerang.
- B. Lanjutkan seluruh daftar persistence PT JAB, catat juga yang tidak ditemukan, dan bandingkan isi webroot dengan rilis.
- C. Hapus crontab itu sekarang supaya proses tidak hidup lagi, lalu lanjutkan pemeriksaan.

<details><summary>Jawaban</summary>

B. Penyerang yang sudah memasang satu jalan masuk hampir selalu memasang yang lain; di `INC-2026-012` ada tiga (proses, cron, web shell kedua). Daftar memastikan setiap tempat diperiksa, dan baris "tidak ditemukan" memberi arti pada scope statement. A keliru karena berhenti di temuan pertama. C keliru karena mengubah server sebelum bukti dan containment serentak memberi tanda ke penyerang dan menghapus artefak. Lihat bagian 1.4 dan 2.4.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Hendra Wijaya, dalam tiga kalimat, kenapa portal harus dialihkan ke halaman pemeliharaan dan servernya dibangun ulang, padahal web shell bisa dihapus dalam lima menit.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "File yang kita temukan hanya pintu pertama; sebelum IP-nya kita blok, penyerang sudah memasang program lain yang tetap terhubung keluar dan menaruh pintu kedua, dan ada bagian aktivitasnya yang tidak tercatat di log kita. Karena kita tidak bisa memastikan semua yang ditinggalkan sudah ketemu, server ini tidak bisa dipercaya lagi, jadi lebih aman membangun server baru dari kode yang sudah diperbaiki daripada membersihkan yang lama. Portal kita alihkan ke halaman pemeliharaan sampai server baru lolos uji, perkiraan Minggu malam, dan pembayaran lewat kanal lain tetap jalan."

Kesalahan yang sering muncul:
- Memakai istilah seperti "persistence", "auditd", atau "egress" tanpa menjelaskannya.
- Tidak menyebut perkiraan waktu dan dampak ke pelanggan, padahal itu yang diputuskan Hendra.
- Menjanjikan bahwa server baru "pasti aman", padahal yang bisa dijanjikan adalah celah yang diketahui sudah ditutup dan diuji.

</details>

**6. Pertanyaan jebakan.** "Log firewall mencatat 214 deny dari `jkt-portal01` ke jaringan internal, jadi segmentasi DMZ sudah cukup dan tidak ada yang perlu diperbaiki di sisi jaringan." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Segmentasi ke dalam memang bekerja, tetapi dua hal lain gagal: egress dari DMZ ke internet terbuka sehingga `kthreadd2` bisa terhubung ke `203.0.113.225`, dan alert pemindaian (`SOC-2026-0129`) menunggu di antrean P3 sampai pagi. Perbaikannya menutup egress DMZ kecuali tujuan yang disebut dan menaikkan prioritas alert untuk server yang menghadap internet. Lihat bagian 1.5, 1.7, dan 2.5.

</details>

**7. Interview question (English).** "You find a web shell on a Linux web server. Walk me through your response."

<details><summary>Sample answer</summary>

"First I treat the web shell as a symptom and assume there's more. I preserve evidence before touching anything: memory, the web root, access and error logs, audit logs, and firewall logs. Then I work out the entry point by lining up the file's timestamps with the access log, usually a POST to an upload or vulnerable endpoint just before the file appeared, and I confirm the weakness in the code with the app team. I separate the attacker from scanners by looking for rare URIs with successful responses, then pivot on every IP that touched them. Without EDR, I rely on auditd execve logging for the web server user to see what was run, keeping in mind it won't show what the PHP did internally. I check every persistence location on a list, cron, systemd, SSH keys, accounts, preload, web server config, files that differ from the release, and outbound connections, and I check firewall logs for lateral movement and database access. Containment is coordinated: take the site to a maintenance page and close DMZ egress at the same time, then rotate every secret the web user could read. For eradication I rebuild from a clean image with code from the repository, fix and independently test the upload flaw, block script execution in upload directories, and keep audit logging and egress restrictions in place."

What makes this answer strong: it puts evidence before deletion, finds the entry point instead of just the file, explains how to work without EDR and its limits, uses a checklist for persistence, coordinates containment, and ends with fixing the root cause rather than only rebuilding.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | NSA Cybersecurity: Mitigating-Web-Shells (repositori GitHub) | https://github.com/nsacyber/Mitigating-Web-Shells | primer | panduan NSA dan ASD 2020; diakses 2026-10-15 | Tinggi. Known-good comparison dengan `diff`, anomali request (URI langka, user agent, referrer, IP), peringatan false positive |
| S2 | CISA Eviction Strategies Tool: CM0106 Eliminate Web Shells | https://www.cisa.gov/eviction-strategies-tool/info-countermeasures/CM0106 | primer | versi 1.0, Maret 2025; diakses 2026-10-15 | Tinggi. Tujuh langkah, catatan downtime, countermeasure tambahan |
| S3 | CISA Eviction Strategies Tool: CM0027 Rebuild Compromised Host | https://www.cisa.gov/eviction-strategies-tool/info-countermeasures/CM0027 | primer | versi 1.0, Maret 2025; diakses 2026-10-15 | Tinggi. Rebuild dari image dan sumber yang diverifikasi bersih |
| S4 | MITRE ATT&CK: Server Software Component: Web Shell (T1505.003) | https://attack.mitre.org/techniques/T1505/003/ | primer | ATT&CK v20; diakses 2026-10-15 | Tinggi. Definisi dan arah deteksi web shell di Linux |
| S5 | MITRE ATT&CK: Exploit Public-Facing Application (T1190) | https://attack.mitre.org/techniques/T1190/ | primer | ATT&CK v20; diakses 2026-10-15 | Tinggi. Definisi akses awal dan mitigasi segmentasi |
| S6 | MITRE ATT&CK: Scheduled Task/Job: Cron (T1053.003) | https://attack.mitre.org/techniques/T1053/003/ | primer | ATT&CK v20; diakses 2026-10-15 | Tinggi. Pemantauan crontab oleh user non-root |
| S7 | MITRE ATT&CK: Account Manipulation: SSH Authorized Keys (T1098.004) | https://attack.mitre.org/techniques/T1098/004/ | primer | ATT&CK v20; diakses 2026-10-15 | Tinggi. Kunci SSH sebagai persistence |
| S8 | MITRE ATT&CK: Create or Modify System Process: Systemd Service (T1543.002) | https://attack.mitre.org/techniques/T1543/002/ | primer | ATT&CK v20; diakses 2026-10-15 | Tinggi. Unit sistem dan user, lokasi `ExecStart` mencurigakan |
| S9 | MITRE ATT&CK: Hijack Execution Flow: Dynamic Linker Hijacking (T1574.006) | https://attack.mitre.org/techniques/T1574/006/ | primer | ATT&CK v20; diakses 2026-10-15 | Tinggi. `LD_PRELOAD` dan `/etc/ld.so.preload` |
| S10 | OWASP Cheat Sheet Series: File Upload Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html | primer (standar komunitas keamanan aplikasi) | tanpa nomor versi; diakses 2026-10-15 | Tinggi. Kontrol unggahan berlapis |
| S11 | auditctl(8), Linux manual page | https://man7.org/linux/man-pages/man8/auditctl.8.html | primer | diakses 2026-10-15 | Tinggi. `-F arch` sebelum `-S`, aturan `b32` dan `b64`, file aturan |
| S12 | crontab(1), Debian bookworm manpages | https://manpages.debian.org/bookworm/cron/crontab.1.en.html | primer | Debian bookworm; diakses 2026-10-15 | Tinggi. Lokasi spool, `cron.allow` dan `cron.deny`, default Debian |
| S13 | Elastic Security: prebuilt rule Suspicious Child Execution via Web Server | https://www.elastic.co/guide/en/security/current/suspicious-child-execution-via-web-server.html | sekunder (dokumentasi vendor) | rule version 118, Elastic 8.19; diakses 2026-10-15 | Sedang sampai tinggi. Induk, path, dan nama program yang dianggap mencurigakan; panduan triage |
| S14 | SigmaHQ: Webshell Remote Command Execution (lnx_auditd_web_rce) | https://github.com/SigmaHQ/sigma/blob/master/rules/linux/auditd/syscall/lnx_auditd_web_rce.yml | komunitas | status test; diakses 2026-10-15 | Sedang. `execve`/`execveat` dengan `euid` 33 dan kebutuhan aturan auditd |

**Catatan sumber:** urutan tiga sumber untuk menemukan titik masuk di bagian 1.1, urutan pemisahan scanner di bagian 1.2, daftar persistence PT JAB di bagian 1.4, dan tiga lapis perbaikan di bagian 1.7 adalah susunan catatan ini dari sumber yang disebut, bukan daftar resmi. Bahwa aturan `execve` tidak melihat kerja kode PHP di dalam prosesnya ditulis dari cara kerja audit syscall, bukan dari kalimat sumber tertentu. Rule Sigma [S14] adalah konten komunitas yang konsisten dengan arah deteksi di ATT&CK [S4] dan rule Elastic [S13]. Nama sourcetype dan field Splunk di bagian 2 bergantung pada add-on dan perlu dicek di lingkunganmu. Semua isi PT JAB, termasuk jumlah request, waktu, alamat IP, dan nama proses, adalah contoh fiktif.
