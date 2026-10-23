---
day: 23
title: 'Triage Linux dan macOS: peta artefak, persistensi, koleksi dengan UAC, autentikasi dan sesi, riwayat perintah, auditd, journal, unified log, dan jebakan berulang'
researched_on: 2026-10-22
versions_checked: 'UAC 3.4.0 (rilis 2026-09-09, membawa AVML v0.20.0; dokumentasi uac-docs); systemd journalctl(1) dan journald.conf(5) (man7.org); auditd(8) dan ausearch(8) (man7.org); utmp(5); mount(8) relatime; ld.so(8); Debian 12 release notes 5.1.7 (rsyslog tidak terpasang bawaan); Ubuntu 22.04 LTS (jkt-billing01, keluaran ilustrasi); The Sleuth Kit 4.15.0; Apple unified logging (Apple Developer, tingkat log dan persistensi), log CLI macOS; Apple SIP (Support 102149) dan payload Privacy Preferences Policy Control; mac_apt v1.36.2 (2026-10-10)'
---

# Day 23: Triage Linux dan macOS

Cakupan: peta artefak Linux dan macOS, persistensi yang diperiksa lebih dulu, koleksi yang konsisten dengan UAC, cara membaca autentikasi, sesi, riwayat perintah, auditd, journal, dan unified log, serta jebakan yang berulang, dipraktikkan dengan memverifikasi ulang kesimpulan retainer atas server billing Linux PT JAB dan menyusun prosedur koleksi untuk server Linux dan MacBook.

## Ide inti

Linux dan macOS tidak punya registry, Prefetch, Amcache, atau SRUM. Informasi yang di Windows terkumpul di beberapa basis data terpusat tersebar di sini ke berkas konfigurasi teks, berkas properti (plist), basis data SQLite, log teks, log biner (journal di Linux, unified log di macOS), dan metadata file system. Akibatnya ada dua hal. Pertama, triage di sistem Unix bergantung pada koleksi yang menyeluruh dan konsisten, bukan pada lima artefak kunci: yang tidak tersalin saat koleksi biasanya tidak bisa dicari lagi, terutama isi tmpfs dan keadaan yang hidup. Kedua, pertanyaan "program apa yang dijalankan" hampir tidak punya jawaban bawaan. Tanpa auditd dengan aturan `execve`, tanpa EDR, dan tanpa riwayat shell yang utuh, kamu hanya punya jejak tidak langsung: log autentikasi, log cron dan sudo, waktu file, dan isi memori bila sempat diambil. Jadi kerja forensik Linux berpusat pada tiga hal: keadaan saat koleksi, persistensi, dan siapa masuk dari mana, lalu setiap kesimpulan tentang eksekusi ditulis bersama sumber dan batasnya.

Kamu sudah mengenal situasi ini dari NOC. Router dari vendor berbeda menyimpan log di tempat dan format berbeda: ada yang menulis syslog teks ke server, ada yang menyimpan buffer biner internal yang hanya dibaca dengan perintah vendornya, ada yang mencatat perintah lewat accounting TACACS, ada yang tidak sama sekali. Engineer yang pernah menangani gangguan lintas vendor tahu bahwa yang menyelamatkan adalah skrip capture standar yang sama untuk semua perangkat, dijalankan sebelum reload, dengan output yang disimpan di luar perangkat. Dan ia tahu bahwa perangkat tanpa accounting perintah tidak bisa ditanya "siapa mengetik apa", sebagus apa pun alat analisisnya. Batasnya: di server Linux, skrip koleksi berjalan di atas sistem yang mungkin sudah dikuasai penyerang, memakai biner host itu sendiri, dan setiap perintahnya mengubah sedikit keadaan host.

```
pertanyaan                      Linux                                   macOS
--------------------------------------------------------------------------------------------------
siapa masuk, dari mana          auth.log/secure + journal + wtmp/btmp    unified log (sshd, loginwindow)
                                + auditd (event PAM)                     + /var/log lama, wtmp terbatas
apa yang bertahan (persistensi) cron, systemd unit/timer, authorized_keys launchd plist (3 lokasi),
                                rc/profile, ld.so.preload, akun UID 0    login/background items,
                                                                         PrivilegedHelperTools, profil
apa yang dijalankan             auditd execve (bila ADA aturannya)       unified log (sebagian),
                                riwayat shell (rapuh), log cron/sudo,    riwayat zsh, KnowledgeC/Biome,
                                atime (relatime), memori                 quarantine xattr
apa yang ada SEKARANG           /proc, ss, ps, tmpfs (/dev/shm, /run)    ps, lsof, launchctl
                                -> hilang saat reboot                    -> hilang saat reboot
koleksi                         UAC (shell, tanpa instalasi)             UAC + log collect
                                tulis ke NFS/media lain                  butuh Full Disk Access
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan dan data pribadi sekitar 400 ribu pelanggan broadband di sistem billing. Kasus acuannya `INC-2026-019` (Oktober 2026, sudah ditutup). Lampiran phishing dijalankan di laptop staf penagihan `JKT-WS-0388` (`andi.pratama`, `10.10.23.88`), password akun service `svc_billing` dibaca penyerang dari skrip sah `export-tagihan.ps1` di laptop itu, lalu Selasa 2026-10-13 pukul 02:14 WIB dipakai untuk SSH dari `10.10.23.88` ke server billing Linux `jkt-billing01` (`10.20.5.21`, tanpa EDR). `svc_billing` adalah akun lokal Linux di server itu, bukan akun AD; pemakaian sahnya adalah login publickey dari server job ekspor `10.20.1.15` setiap 5 menit dan login password dari workstation penagihan saat staf menjalankan skrip ekspor. Aturan sudo `svc_billing` hanya mengizinkan restart layanan billing. Pukul 02:20 server mulai beacon ke `203.0.113.77` dari proses `/dev/shm/.cache/kworkerd` (PID 23817) yang dijalankan cron milik `svc_billing`. Selasa siang Yoga Pratama (analyst L2, pemegang bukti) mengambil live response lewat SSH dari `jkt-bastion01` (E04, output teks), memori dengan AVML 13:20 sampai 13:41 (E05), salinan biner `kworkerd` dari `/proc/23817/exe` (E06), dan arsip `/var/log` serta ekspor journal (E07). Retainer PT Forensik Digital Contoh menganalisis memori dan menemukan dari riwayat perintah implant: salinan kedua biner `/var/tmp/.font-unix/kworkerd` pukul 02:31 yang tidak berjalan, pembacaan `/opt/billing/conf/app.env` (kredensial database `billing_app`) pukul 02:44, query `SELECT nama, nik, alamat, telepon FROM pelanggan LIMIT 5000` pukul 03:06 ke `jkt-billingdb01` (`10.20.5.30:5432`), arsip `/dev/shm/.cache/p.gz` sekitar 1,4 MB pukul 03:10 yang dihapus pukul 03:12, dan sesi psql kedua pukul 03:15. Server pengganti `jkt-billing02` (`10.20.5.22`) dibangun dari gold image `JAB-LNX-GOLD-2026.09` dengan Defender for Endpoint untuk Linux, `jkt-billing01` dimatikan setelah cutover Kamis malam, dan image disknya (E17) diambil retainer Jumat 2026-10-16 pukul 00:30 setelah snapshot volatil singkat. Saat itu forensik Linux tercatat sebagai kemampuan retainer, dan rencana kapabilitas 2027 menaruh "triage Linux internal" sebagai nomor 10 dengan pemilik kamu sendiri (Day 20 bagian 1.13).

Selasa 2027-02-16 pukul 09:00, Dimas Prasetyo (SOC lead) menulis kepadamu:

> "Kita mulai rencana nomor 10 sekarang, jangan tunggu Juni. Latihan pertama: verifikasi sendiri kesimpulan retainer soal `jkt-billing01` dari E17 dan E04 sampai E07. Yoga sudah buat salinan kerja E17-W1 kemarin sore. Saya mau tahu kesimpulan mana yang bisa kita buktikan sendiri dari disk dan log, mana yang cuma bersandar pada analisis memori mereka. Login penyerang bisa dibedakan dari login job ekspor dan staf yang pakai akun yang sama? Benar cron satu-satunya persistensi? Apa yang bisa kita buktikan soal perintah yang dijalankan, padahal server itu tidak punya EDR dan auditd-nya tidak mencatat eksekusi? Setelah itu, susun prosedur koleksi standar pakai UAC untuk `jkt-billing02`, `jkt-portal02`, dan `jkt-radius01`, dijalankan lewat SSH dari bastion. Satu lagi: Bu Maya baru pakai MacBook untuk tim Corporate Communication dan kita belum punya prosedur apa pun untuk Mac. Tulis prosedurnya dan apa saja yang mesti diambil. Catat juga jebakan yang bikin verifikasi kita bisa salah. Memo verifikasi Kamis sore, prosedur Rabu depan."

Pesan itu memuat tujuh pertanyaan:

1. Kesimpulan retainer mana yang bisa dibuktikan sendiri dari disk E17 dan E04-E07, dan mana yang hanya bersandar pada memori E05?
2. Bagaimana menentukan siapa masuk, kapan, dari mana, dan membedakan login penyerang dari login sah dengan akun yang sama?
3. Apakah cron benar satu-satunya persistensi, dan lokasi apa saja yang harus diperiksa untuk menyatakannya?
4. Apa yang bisa dibuktikan tentang perintah yang dijalankan tanpa EDR dan tanpa aturan auditd `execve`?
5. Seperti apa prosedur koleksi standar dengan UAC untuk tiga server Linux, dijalankan lewat SSH dari `jkt-bastion01`?
6. Untuk MacBook Corporate Communication: artefak apa yang diambil, dengan alat apa, dan syarat apa yang harus disiapkan sebelum insiden?
7. Jebakan apa yang berulang dan bisa membuat verifikasi salah?

Pertanyaan 1 dijawab di bagian 1.1 dan 1.2, pertanyaan 2 di bagian 1.3, pertanyaan 3 di bagian 1.4, pertanyaan 4 di bagian 1.5, pertanyaan 5 di bagian 1.6, pertanyaan 6 di bagian 1.7 dan 1.8, dan pertanyaan 7 di bagian 1.9. Bagian 2 berisi perintah atas E17-W1, memo verifikasi untuk Dimas, dan dua prosedur yang kamu serahkan.

**Kapan relevan:** saat host yang diperiksa adalah server Linux, appliance berbasis Unix, atau laptop macOS, baik untuk koleksi cepat sebelum host dimatikan atau dibangun ulang, analisis offline atas image dan koleksi, maupun menyusun prosedur dan telemetri sebelum insiden berikutnya.
**Kapan bukan jawaban:** Day ini bukan analisis memori Linux atau macOS (butuh symbol table kernel yang persis dan dibahas sebagai batas, bukan langkah), bukan reverse engineering implant seperti `kworkerd`, bukan forensik kontainer dan Kubernetes, dan bukan forensik disk macOS yang terenkripsi FileVault secara mendalam (status enkripsi dan kunci dibahas di Day 22).

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (live response, triage collection, image, salinan kerja, hash bukti, chain of custody, order of volatility, jejak responder, persistence, super-timeline, MACB, last access update, normalisasi zona waktu, AVML, symbol table) tidak diulang. Tabel berikut memuat istilah baru Day ini; kolom padanan memakai analogi NOC dan SOC yang sama di semua Day.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| UAC (Unix-like Artifacts Collector) | Skrip shell pengumpul artefak untuk Linux, macOS, dan Unix lain, tanpa instalasi, dengan profil dan artefak YAML | Skrip capture `show tech` yang sama untuk router semua vendor, dengan satu format output |
| Profil UAC | Daftar artefak yang dikumpulkan dalam satu kali jalan (`ir_triage`, `full`, atau buatan sendiri) | Daftar perintah `show` yang disetujui untuk satu jenis gangguan |
| journald dan journal | Layanan log systemd yang menyimpan log dalam berkas biner terindeks, dibaca dengan `journalctl` | Buffer log internal perangkat yang hanya dibaca dengan perintah vendornya |
| Syslog teks (rsyslog) | Daemon yang menulis log ke berkas teks seperti `/var/log/auth.log` atau `/var/log/secure` | Syslog yang dikirim perangkat ke server log teks |
| utmp, wtmp, btmp, lastlog | Berkas biner sesi: sesi berjalan, riwayat login dan logout, login gagal, login terakhir per akun | Tabel sesi aktif dan accounting start/stop RADIUS lokal |
| auditd | Daemon audit kernel Linux; mencatat event PAM bawaan dan, bila diberi aturan, syscall seperti `execve` | Accounting TACACS: hanya mencatat yang dikonfigurasi untuk dicatat |
| Crontab user | Jadwal per akun di spool cron (`/var/spool/cron/crontabs/<user>` di Debian dan Ubuntu) | Scheduler kron atau EEM applet di router yang dipasang per operator |
| tmpfs | File system di RAM (`/dev/shm`, `/run`, sering `/tmp`) yang hilang saat reboot | File di RAM-disk router yang hilang saat reload |
| Bodyfile | Daftar metadata file (path, inode, ukuran, MACB) dalam format teks pipa, bahan timeline | Inventaris CMDB yang diekspor dengan kolom waktu |
| atime dan relatime | Waktu akses terakhir file; dengan `relatime` hanya diperbarui pada kondisi tertentu | Counter "last used" yang hanya diperbarui sekali sehari |
| Unified log | Sistem log biner macOS untuk seluruh tingkat sistem; sebagian tingkat hanya di memori | Buffer log bertingkat: debug di RAM, severity tinggi ke flash |
| `.logarchive` | Bundel unified log yang dibekukan dengan `log collect` untuk dianalisis di tempat lain | Arsip `show logging` yang disalin ke server sebelum reload |
| LaunchAgent dan LaunchDaemon | plist launchd yang menjalankan program otomatis, per pengguna (agent) atau sistem (daemon) | Startup-config yang menjalankan service saat perangkat boot |
| `com.apple.quarantine` | Extended attribute yang ditempel macOS pada file yang diunduh aplikasi tertentu | Tag asal pada file yang diunggah lewat portal resmi |
| TCC dan Full Disk Access | Kontrol privasi macOS per aplikasi; Full Disk Access membuka data terlindung, termasuk untuk root | ACL per aplikasi di NMS yang tidak bisa dilewati hanya dengan akun admin |
| SIP (System Integrity Protection) | Proteksi macOS yang membatasi root mengubah lokasi sistem seperti `/System` dan `/usr` | Bagian firmware yang terkunci dan tidak bisa diubah walau dengan enable |
| PPPC (Privacy Preferences Policy Control) | Payload MDM untuk memberi izin TCC, termasuk `SystemPolicyAllFiles`, ke aplikasi tertentu | Perubahan ACL lewat change ticket terpusat, bukan di perangkat |
| mac_apt | Alat pengurai artefak macOS dari image atau koleksi menjadi keluaran terstruktur | Parser bundel `show tech` menjadi tabel |

### 1.1 Model artefak Unix: keadaan, persistensi, dan siapa masuk

Pertanyaan pertama Dimas sebenarnya menanyakan model artefaknya. Kesimpulan retainer tentang `jkt-billing01` datang dari dua jenis sumber: memori proses implant (E05) dan disk serta log (E04, E06, E07, E17). Sebelum memeriksa satu per satu, kamu perlu tahu jenis pertanyaan apa yang bisa dijawab disk Linux dan jenis apa yang tidak.

Perbedaan dengan Windows bisa diringkas dalam tiga baris. Tabel berikut menunjukkan kenapa daftar artefak Windows dari Day 07-10 tidak bisa dipindahkan begitu saja; cari baris "jejak eksekusi" karena di situlah celah terbesarnya.

| Aspek | Windows | Linux dan macOS |
|---|---|---|
| Konfigurasi terpusat | Registry | Tersebar di berkas konfigurasi, plist, dan SQLite |
| Jejak eksekusi | Prefetch, Shimcache, Amcache, BAM, SRUM | Sangat terbatas; bergantung pada log, shell history, dan audit |
| Log sistem | EVTX terstruktur | journald biner atau syslog teks di Linux; unified log biner di macOS |

Poin kedua yang paling terasa. Di Linux tidak ada artefak yang setara Prefetch, sehingga pertanyaan "program apa yang pernah dijalankan" sering tidak punya jawaban pasti kecuali auditd dengan aturan `execve` aktif atau ada EDR. Karena itu triage Linux berpusat pada tiga jenis pertanyaan yang memang punya artefak:

1. **Keadaan saat koleksi:** proses, koneksi, file terbuka, isi tmpfs. Hanya ada di sistem hidup, dan hanya sekali. Di `jkt-billing01` ini adalah E04 (output perintah) dan E05 (memori).
2. **Persistensi:** apa yang membuat penyerang kembali setelah reboot atau setelah prosesnya dibunuh. Persistensi Linux hampir selalu berupa file teks di lokasi yang diketahui, jadi bisa diperiksa di image (E17) dan dibandingkan dengan output live response.
3. **Siapa masuk, kapan, dari mana:** log autentikasi teks, journal, berkas sesi biner, dan event PAM di auditd. Sumbernya banyak dan saling menguatkan, karena setiap login melewati PAM, sshd, dan pencatat sesi.

Pertanyaan keempat, "apa yang dikerjakan setelah masuk", adalah wilayah memori. Retainer bisa menyebut urutan 02:31, 02:44, 03:06, 03:10, 03:12, dan 03:15 karena implant menyimpan riwayat perintahnya di memori proses, bukan karena ada log di disk. Jadi jawaban jujur untuk Dimas sudah bisa diduga sebelum membuka E17: kesimpulan tentang masuk dan persistensi bisa diverifikasi internal dengan beberapa sumber independen, sedangkan kesimpulan tentang tindakan di dalam implant sebagian besar hanya bisa dikuatkan secara tidak langsung (waktu file, log cron, volume firewall) dan sisanya tetap bersandar pada E05.

Satu konsekuensi praktis lagi: verifikasi ini tidak mengulang analisis memori E05. Volatility 3 bisa membaca memori Linux, tetapi butuh symbol table untuk kernel yang persis sama dengan `jkt-billing01` (dibuat dari debug symbol kernel itu), dan PT JAB belum pernah menyiapkannya. Itu dicatat sebagai batas, bukan dikerjakan setengah jalan.

### 1.2 Peta artefak Linux dan dua dunia log

Sebelum mencari, kamu perlu tahu di mana tiap jenis jejak disimpan dan apa yang membuatnya hilang. Tabel berikut adalah peta kerja untuk server Debian dan Ubuntu seperti `jkt-billing01` (Ubuntu 22.04 LTS) dan keluarga RHEL; perhatikan kolom catatan, karena nama berkas berbeda antar distribusi dan beberapa artefak hanya ada bila diaktifkan sebelum insiden.

| Pertanyaan | Artefak | Catatan |
|---|---|---|
| Siapa masuk, kapan, dari mana | `/var/log/auth.log` (Debian, Ubuntu) atau `/var/log/secure` (RHEL); journal | Nama berkas berbeda antar distribusi; berkas teks hanya ada bila rsyslog terpasang |
| Sesi yang pernah dan sedang berjalan | `/var/run/utmp`, `/var/log/wtmp`, `/var/log/btmp`, `/var/log/lastlog` | Format biner; `utmp` sesi berjalan, `wtmp` riwayat, `btmp` upaya gagal [S17] |
| Perintah yang pernah diketik | `~/.bash_history`, `~/.zsh_history`, `~/.psql_history` | Ditulis saat shell keluar, mudah dihapus, tanpa timestamp kecuali `HISTTIMEFORMAT` diatur [S18] |
| Layanan dan tugas terjadwal | unit systemd, crontab user, `/etc/crontab`, `/etc/cron.*`, timer systemd | Tempat persistensi utama; jejak jalannya ada di log cron dan journal, bukan di berkas jadwal |
| Akses jarak jauh | `~/.ssh/authorized_keys`, `/etc/ssh/sshd_config` dan `sshd_config.d/` | Kunci tambahan adalah persistensi klasik |
| Hak istimewa | `/etc/sudoers`, `/etc/sudoers.d/`, log sudo di auth.log | Pemakaian sudo tercatat per perintah di log autentikasi |
| Paket yang dipasang | `dpkg.log`, `apt/history.log`, log `dnf` atau `yum` | Garis waktu perubahan sistem yang sah |
| Audit terperinci | auditd, `/var/log/audit/audit.log*` | Event PAM tercatat bawaan; syscall hanya bila ada aturannya [S4][S11] |
| Keadaan saat ini | `/proc`, tmpfs (`/dev/shm`, `/run`, sering `/tmp`) | Hanya pada sistem hidup |
| Metadata file | inode ext4 (atime, mtime, ctime, crtime) | Diambil dari image atau bodyfile; atime bergantung opsi mount [S20] |

Soal log sistem, bedakan dua dunia. Distribusi modern memakai journald dengan berkas journal biner yang dibaca `journalctl`, sedangkan sebagian sistem masih menulis syslog teks, dan banyak yang menjalankan keduanya: journald menerima pesan, rsyslog menyalinnya ke berkas teks. Kalau kamu hanya menyalin `/var/log/*.log`, kamu bisa kehilangan seluruh journal; kalau hanya membaca journal, kamu bisa kehilangan berkas rotasi teks yang lebih tua dari jendela journal. Periksa keduanya.

Tiga detail yang mengubah cara kerja:

- **Persistensi journal.** `journald.conf` punya opsi `Storage=`: `volatile` menyimpan hanya di `/run/log/journal` (hilang saat reboot), `persistent` di `/var/log/journal`, `auto` bertindak persistent hanya bila `/var/log/journal` ada, dan `none` tidak menyimpan apa pun. Dokumentasi systemd versi terbaru menyebut default `persistent`; versi dan distribusi lama memakai `auto`, jadi selalu cek berkas konfigurasi dan keberadaan direktori di host yang kamu periksa [S10].
- **Ukuran, bukan umur.** Journal dibatasi ukuran: `SystemMaxUse=` default 10 persen ukuran file system dengan batas atas 4G, dan `MaxRetentionSec=` default 0 (tidak ada penghapusan berbasis waktu) [S10]. Jendela waktunya tergantung seberapa ramai host. Server yang menerima login job setiap 5 menit mengisi journal lebih cepat daripada server yang sepi.
- **Rsyslog tidak selalu ada.** Sejak Debian 12, rsyslog tidak lagi terpasang pada instalasi bawaan; log dibaca dengan `journalctl` dari berkas biner di `/var/log/journal`, dan sistem hasil upgrade bisa saja tidak menyimpan journal secara persisten [S19]. Di server Debian 12 tanpa rsyslog, `/var/log/auth.log` tidak ada, dan itu bukan tanda log dihapus.

Untuk `jkt-billing01`, E17 berisi keduanya: rsyslog menulis `auth.log` dan `syslog` (rotasi mingguan, empat generasi lama, yang tertua terkompresi), dan journal persisten di `/var/log/journal/<machine-id>/`. Server diatur ke zona `Asia/Jakarta`, sehingga berkas teks memakai waktu lokal tanpa zona dan tanpa tahun, sedangkan journal, wtmp, dan audit.log menyimpan waktu absolut (epoch UTC). Inilah sumber jebakan pertama di bagian 1.9.

### 1.3 Autentikasi dan sesi: siapa masuk, dan membedakan penyerang dari pemakai sah

Pertanyaan kedua Dimas muncul karena `svc_billing` dipakai tiga pihak sekaligus: server job ekspor `10.20.1.15` (publickey, setiap 5 menit, sekitar 288 login per hari), staf penagihan yang menjalankan `export-tagihan.ps1` (password, dari `10.10.23.88` dan `10.10.23.41`), dan penyerang (password, dari `10.10.23.88`, laptop Andi). Penyerang memakai akun, metode, dan IP yang sama dengan pemakaian sah. Pembeda tidak ada di satu baris log; ia ada di pola dan di artefak pendamping.

Setiap login SSH meninggalkan jejak di beberapa tempat yang ditulis komponen berbeda. Tabel berikut memetakan komponen ke artefaknya; yang perlu kamu cari adalah kolom "kapan tidak ada", karena di situ letak salah tafsir.

| Komponen | Artefak | Isi yang berguna | Kapan tidak ada |
|---|---|---|---|
| sshd | auth.log atau secure, journal (`_COMM=sshd`) | Metode (`password`, `publickey`), akun, IP dan port sumber, PID sshd | Bila rsyslog tidak terpasang (berkas teks) atau journal volatile dan host sudah reboot |
| PAM dan systemd-logind | auth.log, journal | `session opened/closed`, nomor sesi logind | Sama seperti di atas |
| Pencatat sesi | wtmp (riwayat), utmp (berjalan), lastlog | Terminal (`pts/N`), IP, mulai dan selesai sesi | Untuk sesi tanpa terminal (perintah jarak jauh dari skrip) biasanya tidak ada baris; buktikan perilaku ini di lab |
| auditd | audit.log, tipe `USER_AUTH`, `USER_LOGIN`, `USER_START`, `USER_END`, `USER_CMD` | Waktu epoch, `auid`, `ses`, `addr`, `terminal`, `res=success/failed` | Bila auditd tidak terpasang; event PAM tercatat walau tanpa aturan syscall |
| sudo | auth.log, journal, `USER_CMD` di audit | Siapa menjalankan apa sebagai root, dari terminal mana | Bila sudo tidak dipakai |

Dengan peta itu, pembeda login penyerang dari login sah di `jkt-billing01` menjadi empat pemeriksaan:

1. **Metode dan sumber.** Login job selalu `publickey` dari `10.20.1.15`. Login password dari workstation penagihan sah, tetapi selama lima minggu jendela auth.log hanya terjadi di jam kerja hari kerja.
2. **Waktu.** Login password pukul 02:14 dini hari tidak cocok dengan pola staf mana pun.
3. **Jenis sesi.** Skrip ekspor menjalankan perintah jarak jauh tanpa terminal. Sesi penyerang mendapat terminal (`pts/2`), muncul di wtmp dengan durasi, dan memicu `sudo -l` dari terminal itu.
4. **Pendamping di sisi sumber.** Di laptop Andi, Sysmon mencatat `ssh.exe svc_billing@10.20.5.21` berinduk PowerShell dari task penyerang pukul 02:14:31 (Day 05 bagian 2.5). Dua host yang sepakat pada menit yang sama adalah korelasi terkuat.

Login yang gagal juga penting. `btmp` dan baris `Failed password` memperlihatkan percobaan yang tidak berhasil; di jendela E17 ada satu, Rabu 2026-10-14 08:35 dari `10.10.23.41`, yaitu staf penagihan Yudi Hermawan yang menjalankan skrip lama setelah password `svc_billing` dirotasi. Ini contoh baik bahwa kegagalan setelah rotasi bisa sepenuhnya sah.

Satu batas yang harus ditulis: semua artefak ini ada di host yang dikuasai penyerang dengan hak `svc_billing`. Akun itu tidak bisa menulis auth.log, wtmp, journal sistem, atau audit.log (semuanya milik root), dan tidak ada tanda eskalasi ke root, sehingga log ini layak dipercaya untuk jendela kompromi. Kalimat itu bergantung pada kesimpulan "tidak ada eskalasi", yang sendiri hanya berkeyakinan sedang (bagian 1.5).

### 1.4 Persistensi Linux: lokasi yang diperiksa dan cara menyatakan "hanya satu"

Pertanyaan ketiga Dimas menguji kalimat retainer "satu-satunya persistensi adalah crontab `svc_billing`". Kalimat seperti itu hanya bisa dipertanggungjawabkan bila disertai daftar lokasi yang diperiksa, karena "tidak ditemukan" selalu berarti "tidak ditemukan di tempat yang dilihat".

Urutan ini disusun dari mekanisme yang paling sering dipakai:

1. **Unit systemd.** Unit di direktori sistem (`/etc/systemd/system`, `/usr/lib/systemd/system`, `/lib/systemd/system`) dan di direktori milik pengguna (`~/.config/systemd/user`); perhatikan unit yang namanya meniru unit sah dan unit yang baru dibuat. Unit yang aktif ditautkan dari direktori `*.wants`.
2. **Timer systemd dan cron.** Keduanya menjalankan sesuatu secara berkala. Cron punya beberapa lokasi sekaligus: crontab user di spool (`/var/spool/cron/crontabs/` di Debian dan Ubuntu, `/var/spool/cron/` di RHEL), `/etc/crontab`, `/etc/cron.d/`, dan `/etc/cron.hourly` sampai `cron.monthly`. `/etc/cron.d` sering terlewat.
3. **Kunci SSH.** Entri tambahan di `authorized_keys` adalah cara masuk yang bertahan melewati perubahan password. Untuk `svc_billing`, ini pertanyaan penting: rotasi password Selasa tidak berarti apa-apa bila penyerang menanam kunci.
4. **Berkas inisialisasi shell.** `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `/etc/profile`, `/etc/profile.d/`, dan berkas serupa untuk shell lain.
5. **Pemuatan pustaka.** Berkas dan variabel yang memengaruhi pemuat dinamis, termasuk `/etc/ld.so.preload`; berkas itu memuat pustaka bersama ke setiap program yang dijalankan [S6], jadi keberadaannya saja sudah layak diperiksa karena jarang dipakai secara sah.
6. **Akun dan hak.** Akun baru, akun dengan UID 0 selain root, perubahan pada `/etc/sudoers` dan `/etc/sudoers.d/`, serta grup `sudo` atau `wheel`.

Di setiap lokasi, ada dua jenis bukti yang saling melengkapi: isi berkas (apa yang dijadwalkan) dan log jalannya (kapan benar-benar dijalankan). Untuk cron di Ubuntu, setiap eksekusi dicatat daemon cron ke syslog dalam bentuk baris `CRON[PID]: (user) CMD (perintah)`, dan program `crontab` sendiri mencatat ketika crontab user dipasang, dibaca, atau dihapus. Format persis baris-baris itu berbeda antar implementasi cron dan distribusi, jadi cocokkan di lab dengan versi yang sama.

Kasus `jkt-billing01` punya satu komplikasi yang khas: jejak responder. Selasa sore saat containment, Yoga menghapus crontab `svc_billing` dengan `crontab -r -u svc_billing` (pukul 16:04:12, tercatat di case notes) setelah isinya disalin ke E04 pukul 13:5x. Akibatnya, berkas `/var/spool/cron/crontabs/svc_billing` sudah tidak ada di E17. Isi jadwal hanya ada di E04; waktu pemasangan dan penghapusan ada di log; dan inode berkas yang dihapus mungkin masih terbaca dari image. Bila kamu mencari crontab di E17 tanpa tahu riwayat ini, kesimpulanmu bisa terbalik: "tidak ada cron di E17" bukan bantahan terhadap retainer, melainkan akibat containment.

Kalimat yang bisa kamu tulis untuk Dimas setelah semua lokasi diperiksa adalah kalimat dengan dua bagian: mekanisme yang ditemukan beserta bukti jalannya, lalu daftar lokasi yang diperiksa dengan hasil negatif dan batasnya. Batas utamanya: E17 diambil tiga hari setelah kompromi dan setelah containment, sehingga persistensi yang ditanam lalu dihapus sendiri oleh penyerang sebelum Selasa siang hanya terlihat bila meninggalkan log.

### 1.5 Jejak eksekusi tanpa EDR: riwayat shell, auditd, atime, dan memori

Pertanyaan keempat Dimas adalah inti latihan ini. `jkt-billing01` tidak punya EDR. auditd terpasang dari paket distribusi, tetapi aturan auditnya hanya aturan bawaan tanpa aturan syscall, sehingga ia mencatat event PAM (login, sudo, autentikasi) dan tidak mencatat satu pun `execve`. Pemeriksaan `ausearch -m EXECVE` atas audit.log E17 mengembalikan nol event, dan itu bukan tanda penghapusan; aturan itu memang tidak pernah ada. Ini berbeda dengan `jkt-portal02`, yang sejak dibangun ulang punya aturan `execve` untuk akun web server. Satu nama alat yang sama, auditd, memberi visibilitas yang sangat berbeda tergantung aturannya.

Tanpa `execve`, eksekusi hanya bisa didekati dari empat sumber tidak langsung. Tabel berikut merangkum apa yang dibuktikan masing-masing; baca kolom terakhir sebelum menulis kalimat apa pun ke memo.

| Sumber | Yang dibuktikan | Yang tidak dibuktikan |
|---|---|---|
| Riwayat shell (`.bash_history`) | Perintah yang diketik di shell interaktif yang keluar dengan normal | Urutan waktu (tanpa `HISTTIMEFORMAT`), perintah dari shell yang dibunuh, perintah yang dijalankan program lain (implant, cron) |
| Log cron dan sudo | Waktu dan isi perintah yang dijalankan lewat cron atau sudo | Apa yang dikerjakan program itu setelah berjalan |
| atime dengan `relatime` | Ada akses ke file setelah titik tertentu, bila kondisi pembaruan terpenuhi | Siapa yang mengakses, dan akses berikutnya dalam 24 jam |
| Memori (E05) | Perintah dan data di dalam proses yang hidup saat diambil | Apa pun yang sudah hilang dari memori; dan butuh analisis memori Linux |

Riwayat shell punya sifat yang perlu dihafal. Bash memuat berkas riwayat saat mulai dan menuliskan riwayat sesi ke berkas saat shell berakhir. Dengan `HISTTIMEFORMAT`, setiap perintah didahului baris `#` berisi epoch; tanpa itu tidak ada waktu sama sekali [S18]. Akibatnya: shell yang dibunuh tidak menulis riwayat, `history -c` atau `unset HISTFILE` membuatnya kosong, dan perintah yang dijalankan implant tidak pernah masuk riwayat shell siapa pun. Di `jkt-billing01`, `.bash_history` milik `svc_billing` berisi sembilan baris tanpa waktu, dan mtime berkasnya sama dengan waktu logout sesi penyerang di wtmp. Kedua fakta itu memberi jangkar: semua sembilan perintah terjadi di antara login 02:14:33 dan logout 02:21:44. Urutan di dalamnya hanya bisa ditambatkan ke log lain (sudo, cron, firewall).

atime butuh penjelasan lebih panjang karena ia satu-satunya jejak "dibaca" di disk Linux. Dengan opsi mount `relatime`, yang menjadi perilaku default kernel sejak Linux 2.6.30 kecuali `noatime` dipasang, atime hanya diperbarui bila atime sebelumnya lebih awal atau sama dengan mtime atau ctime, atau bila atime sudah lebih tua dari satu hari [S20]. Dua akibatnya:

- File yang baru ditulis punya atime sama dengan mtime. Akses pertama setelah itu pasti memperbarui atime. Jadi bila atime salinan kedua `/var/tmp/.font-unix/kworkerd` masih sama dengan waktu pembuatannya, berkas itu tidak dibaca dan tidak dijalankan sejak ditulis (dengan syarat file system tidak di-mount `noatime`). Ini mendukung kalimat retainer "tidak berjalan".
- File lama yang jarang dibuka akan menyimpan waktu akses pertama dalam satu jendela 24 jam. Akses kedua dan seterusnya di hari yang sama tidak terlihat. Jadi atime binary klien PostgreSQL `psql` bisa menunjuk pemakaian pertama dini hari itu, tetapi tidak bisa menghitung berapa kali, dan tidak bisa menyebut akunnya.

Kondisi "file ditulis ulang" menghapus jejak ini. `/opt/billing/conf/app.env` dibaca implant pukul 02:44 menurut retainer, tetapi Selasa sore sekitar 16:05 tim aplikasi menulis ulang berkas itu untuk rotasi kredensial `billing_app` (layanan pembayaran berhenti 16:02 sampai 16:11), lalu aplikasi billing membacanya saat restart. Di E17, mtime dan atime `app.env` menunjuk Selasa sore, bukan 02:44. Pembacaan 02:44 tidak bisa diverifikasi dari disk, dan penyebabnya adalah tindakan pemulihan yang sah. Ini perlu ditulis eksplisit, karena pembaca memo bisa salah menyimpulkan "disk membantah retainer".

Eskalasi ke root mengikuti logika yang sama. Dari disk kamu bisa memeriksa: tidak ada `sudo` oleh `svc_billing` selain `sudo -l` (melihat daftar hak) pukul 02:15:02, tidak ada `su`, berkas `/etc/passwd`, `/etc/shadow`, dan `/etc/sudoers` tidak berubah sejak Agustus, tidak ada file SUID baru di bodyfile. Yang tidak bisa disingkirkan: eskalasi lewat celah kernel yang tidak menulis ke disk. Kesimpulan "tidak terlihat eskalasi ke root" tetap berkeyakinan sedang, sama seperti kesimpulan retainer dari memori.

### 1.6 Koleksi standar dengan UAC lewat bastion

Pertanyaan kelima Dimas meminta prosedur, bukan sekali jalan. Live response `jkt-billing01` di Oktober memakai daftar perintah yang disusun Yoga saat itu juga (E04): efektif, tetapi bentuknya bergantung pada orang dan hari. Prosedur standar harus menghasilkan koleksi yang bentuknya sama di `jkt-billing02` (Ubuntu 24.04 LTS dari gold image, dengan Defender for Endpoint untuk Linux), `jkt-portal02` (Debian 12, tanpa EDR, dengan aturan auditd `execve` untuk akun web server), dan `jkt-radius01` (Rocky Linux 9, tanpa EDR), supaya koleksi bulan depan bisa dibandingkan dengan koleksi bulan ini.

UAC adalah pengumpul artefak untuk sistem mirip Unix yang tidak butuh instalasi maupun dependensi, berlisensi Apache 2.0 [S1]. Ia mendukung AIX, ESXi, FreeBSD, Linux, macOS, NetBSD, NetScaler, OpenBSD, dan Solaris, serta berjalan di perangkat NAS, perangkat jaringan, dan perangkat IoT selama ada shell [S1]. Yang dikumpulkannya mencakup proses yang berjalan termasuk yang binernya tidak ada di disk, hash proses dan berkas yang bisa dieksekusi, status berkas dan direktori untuk membuat bodyfile, data sistem dan per pengguna, berkas konfigurasi, log, serta memori volatil di Linux [S1]. Pengumpulannya mengikuti urutan volatilitas, dan profil serta artefaknya bisa disesuaikan lewat YAML [S1]. Versi terbaru saat Day ini ditulis adalah 3.4.0 (rilis 9 September 2026), yang antara lain memperbarui AVML di dalam paketnya ke v0.20.0 [S8].

Opsi yang dipakai di prosedur PT JAB dipilih supaya hasil bisa dipertanggungjawabkan. Tabel berikut merangkum opsi dari dokumentasi UAC [S9]; cari kolom "kenapa dipakai" untuk tahu alasan tiap baris masuk prosedur.

| Opsi | Arti | Kenapa dipakai di PT JAB |
|---|---|---|
| `-p ir_triage` | Profil koleksi cepat | Default prosedur; profil `full` hanya atas keputusan technical lead |
| `-a <artefak>` | Tambah atau kecualikan artefak (`!` di depan), boleh wildcard | Menambah memori (`artifacts/memory_dump/avml.yaml`) bila diputuskan |
| `-o <nama>` | Nama dasar berkas output tanpa ekstensi | Nama memuat nomor kasus, nomor bukti, dan hostname |
| `-f tar` atau `zip` | Format output (default `tar`) | `tar` default; `zip` bila perlu sandi dengan `-P` |
| `-H` | Hash semua berkas yang dikumpulkan | Daftar hash per berkas; butuh sekitar dua kali ruang dan waktu lebih lama |
| `--case-number`, `--evidence-number`, `--examiner` | Metadata kasus di log UAC | Mengikat koleksi ke evidence log |
| `--start-date`, `--end-date` | Hanya berkas yang berubah, diakses, atau dibuat di rentang itu | Tidak dipakai di triage awal; berisiko melewatkan berkas lama yang relevan |
| `--temp-dir` | Lokasi direktori kerja sementara (default di dalam tujuan) | Dibiarkan default supaya tidak ada yang ditulis ke disk host |
| `-u` | Lewati pemeriksaan root | Tidak dipakai; koleksi tanpa root kehilangan banyak artefak |

Keputusan desain prosedur PT JAB:

1. **Jalur akses.** SSH dari `jkt-bastion01` (`10.20.1.20`) dengan akun admin per analyst (`adm.<nama>`), sama seperti live response Oktober. Tidak ada login dengan akun aplikasi. Sebelum mulai, sepakati batas waktu dan pemicu containment segera dengan IC, karena sesi responder terlihat di `w` dan bisa diperhatikan penyerang.
2. **Alat dan output tidak menyentuh disk host.** UAC dijalankan dari export NFS toolkit `jkt-evid01:/export/irkit` yang di-mount read-only, dan tujuan output adalah export `jkt-evid01:/export/irout/<kasus>` yang di-mount read-write. Karena direktori sementara UAC default berada di dalam tujuan [S9], tidak ada data koleksi yang ditulis ke disk server.
3. **Volatil dulu, dengan perintah toolkit.** Sebelum UAC, jalankan blok pendek yang sama seperti E04: jam (`date -u; date` dan status NTP), `ss -tanp`, `ps` dengan forest dan waktu mulai, `w`, dan status lockdown kernel. UAC juga mengumpulkan proses, tetapi beberapa menit kemudian, dan dengan biner host.
4. **Memori sebagai keputusan, bukan default.** Memori diambil dengan AVML dari toolkit bila kernel lockdown tidak aktif dan technical lead memutuskan perlu. Untuk server dengan RAM besar, perhitungkan waktu dan ruang di export.
5. **Hash di dua titik.** UAC dengan `-H` memberi hash per berkas; arsipnya di-hash lagi di `jkt-evid01` dan dicatat di evidence log.
6. **Uji sebelum dipakai.** Prosedur diuji di VM lab, lalu sekali di `jkt-billing02` dalam jendela pemeliharaan dengan persetujuan pemilik aplikasi.

Batas yang ditulis di prosedur: UAC adalah skrip shell yang memakai perintah yang tersedia di host (`find`, `stat`, `ps`, dan lainnya). Di host yang mungkin sudah dimodifikasi penyerang, perintah itu bisa berbohong. Toolkit statis untuk blok volatil dan perbandingan dengan image mengurangi risiko itu, tetapi tidak menghapusnya. Koleksi juga meninggalkan jejak responder: login `adm.<nama>`, sudo, mount NFS, dan perubahan atime pada berkas yang dibaca. Semua itu dicatat di case notes dengan waktunya.

Satu catatan tentang `jkt-billing02`: Defender for Endpoint untuk Linux memberi telemetri proses dan jaringan yang tidak dimiliki `jkt-billing01`. Prosedur UAC tetap dipakai di host itu, karena telemetri EDR menjawab "apa yang terjadi" selama retensinya, sedangkan koleksi UAC membekukan berkas, log lokal, dan konfigurasi yang dibutuhkan untuk analisis disk dan perbandingan.

### 1.7 macOS: peta artefak dan persistensi

Pertanyaan keenam Dimas berangkat dari hal yang belum pernah terjadi: enam MacBook di tim Corporate Communication (`JKT-MB-01` sampai `JKT-MB-06`, Apple silicon) yang dikelola lewat Microsoft Intune, terdaftar lewat Automated Device Enrollment sehingga berstatus supervised, dengan FileVault aktif dan recovery key tersimpan di Intune. MacBook ini belum di-onboard ke Defender for Endpoint, sehingga saat insiden yang tersedia hanya artefak di laptop itu sendiri. Kepala timnya, Maya Lestari, juga pemegang komunikasi satu pintu saat insiden; laptopnya menyimpan draf pernyataan publik dan kontak media, jadi kompromi di sana bukan hal kecil.

Tabel berikut adalah peta artefak macOS untuk triage; perhatikan kolom catatan, karena hampir setiap baris punya syarat izin (bagian 1.8) atau bergantung versi macOS.

| Pertanyaan | Artefak | Catatan |
|---|---|---|
| Apa yang terjadi di sistem | Unified log | Biner; dibaca lewat alat `log` di macOS, bisa dibekukan sebagai `.logarchive` |
| Apa yang dijalankan otomatis | `LaunchAgents` dan `LaunchDaemons` di `/Library`, `~/Library`, dan `/System/Library` | Tempat persistensi utama; lokasi `/System` dilindungi SIP |
| Helper berhak tinggi | `/Library/PrivilegedHelperTools` | Bisa dipakai untuk persistensi; dikumpulkan artefak baru di UAC 3.4.0 [S8] |
| Berkas dari mana | Extended attribute `com.apple.quarantine` | Menyimpan asal unduhan; hilang bila atribut dihapus |
| Izin privasi yang diberikan | Basis data TCC sistem dan per pengguna | Menunjukkan aplikasi yang diberi akses disk penuh, kamera, mikrofon, layar |
| Aktivitas berkas | FSEvents | Catatan perubahan per direktori dengan granularitas terbatas |
| Aktivitas pengguna | KnowledgeC, Biome, dan artefak aplikasi | Pemakaian aplikasi; lokasi dan format berubah antar versi |
| Konfigurasi aplikasi | plist (XML atau biner) | Perlu dikonversi bila biner |
| Metadata berkas | Spotlight | Kadang menyimpan jejak berkas yang sudah dihapus |
| Riwayat perintah | `~/.zsh_history` | zsh adalah shell bawaan macOS modern; sifatnya rapuh seperti riwayat bash |

Unified log adalah pusatnya, dan sifatnya perlu dipahami sebelum menjanjikan jendela waktu. Apple menjelaskan bahwa unified logging menyimpan data log secara terpusat di memori dan di disk, bukan di berkas teks [S3]. Semua pesan disimpan di memori lebih dulu, lalu hanya tingkat yang lebih berat yang ditulis ke disk: `debug` tidak disimpan ke disk, `info` hanya bila dikumpulkan dengan alat `log`, sedangkan `default` (notice), `error`, dan `fault` disimpan ke disk sampai batas penyimpanan, dan pesan lama dihapus saat penyimpanan melebihi ukuran yang ditetapkan [S13]. Nilai dinamis berupa string dan objek kompleks juga disensor secara bawaan kecuali pengembang menandainya publik [S13]. Akibatnya untuk forensik: jendela unified log ditentukan volume, bukan hari; pesan `info` dan `debug` dari saat kejadian umumnya sudah tidak ada; dan nama file atau URL di dalam pesan bisa tampil sebagai teks tersensor.

Persistensi macOS diperiksa dengan urutan berikut:

1. **launchd.** Berkas properti di `/Library/LaunchDaemons`, `/Library/LaunchAgents`, dan `~/Library/LaunchAgents`. Perhatikan kunci yang membuat program dijalankan ulang terus-menerus (`RunAtLoad`, `KeepAlive`) dan program yang lokasinya tidak lazim.
2. **Login items dan background items.** Item yang dijalankan saat login, termasuk yang didaftarkan aplikasi; macOS modern menampilkannya di pengaturan sistem, dan lokasi penyimpanannya berbeda antar versi.
3. **PrivilegedHelperTools.** Helper yang dipasang aplikasi untuk tugas berhak tinggi.
4. **Profil konfigurasi.** Profil yang dipasang bisa menetapkan kebijakan dan membuka akses; di MacBook PT JAB semua profil sah datang dari Intune, jadi profil yang tidak tercantum di Intune adalah temuan.
5. **Ekstensi kernel dan sistem.** Lebih jarang sekarang, tetapi tetap perlu dicek keberadaannya.
6. **Pekerjaan terjadwal lama.** `cron` dan `at` masih ada walaupun tidak lazim dipakai, dan justru karena itu menarik bila ada isinya.

### 1.8 Koleksi macOS: Full Disk Access, SIP, dan peran MDM

Di Linux, root membaca hampir semua berkas. Di macOS tidak. TCC membatasi akses ke data terlindung per aplikasi, dan izin Full Disk Access harus diberikan ke aplikasi yang menjalankan koleksi, misalnya Terminal atau sesi SSH jarak jauh. Dokumentasi UAC menyebut Full Disk Access sebagai fitur privasi sejak macOS Mojave (10.14) dan menyarankan memberikannya ke Terminal atau ke pengguna SSH jarak jauh sebelum menjalankan UAC [S9]. Tanpa itu, UAC tetap berjalan dengan `sudo`, tetapi basis data TCC, sebagian isi `~/Library`, dan data aplikasi terlindung tidak terbaca, dan kamu baru tahu dari log galat UAC.

SIP adalah lapisan kedua. Ia membatasi tindakan root pada lokasi terlindung seperti `/System`, `/usr`, `/bin`, `/sbin`, `/var`, dan aplikasi bawaan, sedangkan `/Applications`, `/Library`, dan `/usr/local` tetap bisa ditulis perangkat lunak pihak ketiga [S15]. Untuk koleksi, SIP berarti dua hal: mematikannya bukan langkah triage (butuh reboot ke recovery, yang menghapus keadaan hidup dan mengubah host), dan persistensi penyerang hampir selalu berada di lokasi yang tidak dilindungi SIP, sehingga tetap terbaca.

Karena MacBook PT JAB supervised dan dikelola Intune, izin Full Disk Access tidak perlu diberikan dengan tangan pengguna. Payload Privacy Preferences Policy Control (PPPC) memberi izin TCC ke aplikasi tertentu lewat layanan manajemen perangkat; payload itu khusus macOS, butuh supervisi bila dipasang lewat layanan manajemen, dan menetapkan aplikasi lewat identifier (bundle ID atau path), tipe identifier, dan code requirement hasil `codesign -dr -` [S16]. Layanan `SystemPolicyAllFiles` di payload itu membuka data seperti Mail, Messages, Safari, dan cadangan Time Machine untuk aplikasi yang ditunjuk [S16]. Keputusan prosedur PT JAB:

1. **Profil siap pakai, tidak terpasang.** Tim IT menyiapkan profil PPPC `JAB-IR-FDA-Terminal` yang memberi `SystemPolicyAllFiles` ke Terminal, ditargetkan ke grup perangkat `IR-Triage-Mac` yang kosong. Saat insiden, perangkat yang diperiksa dimasukkan ke grup itu, lalu dikeluarkan setelah koleksi. Pemberian izin permanen ke Terminal di semua Mac ditolak karena membuka data privat ke apa pun yang berjalan di Terminal.
2. **Konsol, bukan jarak jauh.** Remote Login tidak aktif di MacBook PT JAB dan tidak diaktifkan saat insiden. Koleksi dilakukan responder di depan laptop dengan akun admin lokal khusus IR yang dibuat Intune.
3. **Laptop tetap menyala.** FileVault aktif; mematikan laptop berarti image disk berikutnya butuh kunci, dan keadaan hidup hilang. Status enkripsi dan kunci dibahas di Day 22.
4. **Tanpa memori.** Akuisisi memori macOS di Apple silicon tidak masuk prosedur; Volatility 3 versi terbaru juga sudah memberi peringatan deprecation untuk analisis macOS (Day 02 bagian 6). Ini batas yang ditulis, bukan diam-diam dilewati.
5. **Dua koleksi.** `log collect` untuk membekukan unified log, lalu UAC dengan profil `ir_triage` untuk berkas, konfigurasi, persistensi, dan bodyfile. Keduanya ke media responder, bukan ke disk laptop.
6. **Analisis.** Alat `log` hanya ada di macOS, jadi `.logarchive` dibaca di Mac analisis, yang belum dimiliki PT JAB; untuk sementara, artefak lain diurai dengan mac_apt di `jkt-dfir02`. mac_apt adalah alat pengurai artefak macOS dari image atau berkas hasil koleksi, dipakai untuk tahap analisis, bukan koleksi [S5]; versi terbaru v1.36.2 (10 Oktober 2026) menambah beberapa plugin baru [S12]. Format input yang didukung (termasuk apakah keluaran UAC bisa dibaca langsung) dicek di versi yang dipasang.

### 1.9 Jebakan berulang dan batas verifikasi

Pertanyaan ketujuh Dimas mengumpulkan hal-hal yang membuat verifikasi salah tanpa terasa salah. Daftar ini disusun dari kasus `jkt-billing01` dan berlaku untuk host Unix lain.

**Zona waktu.** Ini penyebab kesalahan nomor satu. Log Linux teks sering ditulis dalam waktu lokal tanpa zona dan tanpa tahun, sedangkan journald, wtmp, audit.log, dan unified log menyimpan waktu absolut. Di `jkt-billing01`, auth.log tertulis `Oct 13 02:14:33` (WIB, karena zona server `Asia/Jakarta`), audit.log menulis epoch `1791832473` (19:14:33 UTC tanggal 12), dan perintah `last` di workstation analisis menampilkan waktu sesuai zona workstation itu, bukan zona server. Tetapkan zona host dari image (`/etc/timezone`, tautan `/etc/localtime`), catat di case notes, dan konversikan semuanya ke satu zona sebelum menggabungkan (Day 13).

**tmpfs hilang saat reboot.** Bila sistem Linux dimatikan sebelum dikumpulkan, isi `/run`, `/dev/shm`, dan sebagian `/tmp` ikut hilang. Biner `kworkerd` asli dan `p.gz` berada di `/dev/shm`, sehingga keduanya tidak pernah ada di E17. Biner hanya selamat karena E06 menyalin `/proc/23817/exe`; `p.gz` hanya terlihat di memori karena sudah dihapus sebelum live response.

**Riwayat shell bukan log.** `~/.bash_history` ditulis saat shell keluar dan mudah dikosongkan. Ketiadaannya bukan bukti penghapusan, dan keberadaannya tidak membuktikan urutan waktu kecuali timestamp diaktifkan.

**Jejak responder dan pemulihan.** Containment dan pemulihan mengubah disk: crontab dihapus Yoga, `app.env` ditulis ulang saat rotasi, `tar` atas `/var/log` mengubah atime berkas log, login `adm.yoga` mengisi auth.log dan wtmp. Pisahkan dengan case notes, jangan dengan tebakan.

**"Tidak ada" yang sebenarnya "tidak dicatat".** auditd tanpa aturan `execve` menghasilkan nol event eksekusi; journal volatile di host yang sudah reboot menghasilkan nol baris; Debian 12 tanpa rsyslog tidak punya auth.log. Mulai setiap "tidak ada" dari konfigurasi pencatatnya.

**Batas verifikasi internal.** Tindakan yang dikerjakan implant di dalam prosesnya sendiri (membaca berkas, mengirim query, mengompres, menghapus) tidak meninggalkan jejak di log host tanpa audit yang sesuai. Untuk tindakan seperti itu, verifikasi internal hanya bisa menyebut "konsisten dengan" (waktu file, volume firewall) atau "tidak bisa diverifikasi dari disk". Kalimat retainer tetap berdiri dengan keyakinan yang ditulis retainer, dan memo internal menyebut sumbernya.

## 2. Contoh dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Analisis E17-W1 dijalankan di workstation analisis forensik `jkt-dfir02` (Ubuntu LTS) atas salinan kerja yang di-mount read-only; bukti asli E04-E07 dibaca dari `/mnt/evidence` (share bukti read-only) dan hasil kerja ditulis ke `/mnt/cases/INC-2026-019/analysis/E17-W1/latihan-2027-02/`. Narasi memakai WIB (UTC+7). Server `jkt-billing01` diatur ke zona `Asia/Jakarta`, jadi berkas log teks di E17 sudah dalam WIB tanpa label zona; journal, wtmp, dan audit.log menyimpan waktu absolut yang ditampilkan sesuai zona yang kamu minta, sehingga setiap perintah di bawah menyebut zonanya. Cocokkan format baris log, nama unit, dan opsi alat dengan distribusi dan versi di lab-mu sebelum memakai contoh ini.

Nomor bukti yang dipakai di Day ini mengikuti evidence log `INC-2026-019`: E04 output live response teks (Selasa 2026-10-13 13:12 sampai 13:58, file `E04_00_waktu.txt` sampai `E04_10_svc_billing.txt`), E05 memori AVML 13:20 sampai 13:41, E06 salinan biner `E06_kworkerd_pid23817.bin`, E07 arsip `E07_var_log.tar.gz` dan ekspor `E07_journal.txt`, dan E17 image disk dari retainer. Retainer menyerahkan salinan master E17 (EWF, empat segmen) beserta lampiran analisis disk dua halaman ke `jkt-evid01` pada 2026-10-22; master ada di `/evidence/INC-2026-019/E17/` dengan SHA-256 `5a90...`. Yoga membuat salinan kerja `E17-W1` Senin 2027-02-15 pukul 16:00 di `/cases/INC-2026-019/work/E17-W1/`.

### 2.1 Menyiapkan E17-W1 dan bukti live response

Langkah ini memastikan semua bacaan berikutnya berasal dari salinan yang identik dengan master, dan bahwa mount tidak menulis apa pun. Dikerjakan Selasa 2027-02-16 pukul 09:20 sampai 09:48 setelah pesan Dimas.

```bash
# salin salinan kerja ke disk lokal jkt-dfir02, lalu verifikasi terhadap hash master
mkdir -p /data/INC-2026-019/E17-W1 && cp /mnt/cases/INC-2026-019/work/E17-W1/* /data/INC-2026-019/E17-W1/
cd /data/INC-2026-019/E17-W1 && sha256sum -c /mnt/evidence/INC-2026-019/E17/E17.sha256
chmod 444 /data/INC-2026-019/E17-W1/*

# buka EWF sebagai raw read-only, lihat partisi, mount partisi root read-only tanpa replay journal
sudo mkdir -p /mnt/e17raw /mnt/e17
sudo ewfmount /data/INC-2026-019/E17-W1/E17_jkt-billing01.E01 /mnt/e17raw
mmls /mnt/e17raw/ewf1
sudo mount -o ro,noload,noexec,nodev,offset=$((1050624*512)) /mnt/e17raw/ewf1 /mnt/e17
```

- `sha256sum -c` membaca daftar hash per segmen dari folder master dan membandingkannya dengan salinan lokal; empat baris `OK` berarti salinan identik.
- `ewfmount` menyajikan isi EWF sebagai berkas raw `ewf1` tanpa mengubah segmen.
- `mmls` menampilkan tabel partisi; partisi root ext4 dimulai di sektor 1050624, sehingga offset byte-nya 537.919.488.
- `ro,noload`: mount read-only dan tanpa memuat journal ext4. Dokumentasi `mount` mengingatkan bahwa ext3 dan ext4 tetap memutar ulang journal bila file system kotor walaupun di-mount `ro`, dan menyarankan `ro,noload` untuk mencegah akses tulis [S20]. `noexec` dan `nodev` mencegah biner di image ikut dijalankan secara tidak sengaja.

Keluaran ilustrasi `mmls`:

```
GUID Partition Table (EFI)
      Slot      Start        End          Length       Description
004:  000       0000002048   0001050623   0001048576   EFI System Partition
005:  001       0001050624   0419428351   0418377728   Linux filesystem
```

**Cara membaca hasil:** partisi kedua adalah root (`/`) server. Setelah mount, cek identitas host dan zona waktunya dari image, bukan dari ingatan: `cat /mnt/e17/etc/hostname` memberi `jkt-billing01`, `cat /mnt/e17/etc/os-release` memberi Ubuntu 22.04 LTS, `cat /mnt/e17/etc/timezone` memberi `Asia/Jakarta`, dan opsi mount root di `/mnt/e17/etc/fstab` adalah `defaults` (tanpa `noatime`, jadi kernel memakai `relatime`) [S20]. Catat ketiganya di case notes karena seluruh penafsiran waktu bergantung pada itu.

Bukti live response tidak perlu di-mount. Berkas teks E04 dibaca langsung dari `/mnt/evidence/INC-2026-019/E04/`, dan arsip E07 diekstrak ke folder kerja:

```bash
mkdir -p /data/INC-2026-019/E07-W1 && tar -xzf /mnt/evidence/INC-2026-019/E07/E07_var_log.tar.gz -C /data/INC-2026-019/E07-W1
```

**Variasi:** bila image berisi LVM, partisi root tidak bisa di-mount langsung dengan offset; volume group harus diaktifkan dari loop device read-only. Bila nama volume group di image sama dengan nama di workstation analisis (umum pada instalasi Ubuntu bawaan), aktivasi bisa bentrok; tangani di salinan kerja kedua dan catat langkahnya. `jkt-billing01` dipasang tanpa LVM, jadi masalah ini tidak muncul di E17.

**Kapan gagal:** mount `ro` tanpa `noload` pada image dari server yang dimatikan tidak bersih bisa memutar ulang journal ext4 dan mengubah salinan kerja; hash sesudah analisis tidak lagi cocok. Juga, bila `ewfmount` tidak terpasang, jangan mengonversi E01 ke raw di folder bukti; lakukan di folder kerja dan hash hasil konversinya.

### 2.2 Autentikasi: auth.log dan journal

Langkah ini menjawab pertanyaan kedua Dimas dari dua pencatat yang berbeda: rsyslog (berkas teks) dan journald (berkas biner). Mulai dari ringkasan semua login `svc_billing` di jendela auth.log, supaya login penyerang terlihat di tengah pemakaian sahnya.

```bash
cd /mnt/e17/var/log
zgrep -h "svc_billing from" auth.log auth.log.1 auth.log.*.gz \
  | grep -oE "(Accepted|Failed) (password|publickey) for svc_billing from [0-9.]+" \
  | sort | uniq -c | sort -rn
```

- `zgrep -h` membaca berkas teks dan berkas rotasi terkompresi sekaligus, tanpa nama berkas di depan baris.
- `grep -oE` mengambil hanya bagian baris berisi metode, akun, dan IP sumber, sehingga baris bisa dihitung.
- `sort | uniq -c | sort -rn` menghitung tiap kombinasi dan mengurutkannya dari yang terbanyak.

Keluaran ilustrasi (jendela auth.log E17: Minggu 2026-09-13 00:00 WIB sampai Kamis 2026-10-15 23:48 WIB, lima generasi berkas):

```
   9492 Accepted publickey for svc_billing from 10.20.1.15
      9 Accepted password for svc_billing from 10.10.23.88
      5 Accepted password for svc_billing from 10.10.23.41
      1 Failed password for svc_billing from 10.10.23.41
```

**Cara membaca hasil:** 9.492 login publickey adalah job ekspor setiap 5 menit selama 32 hari ditambah 23 jam (32 x 288 + 23 x 12), sampai cutover Kamis 23:00. Login password dari `10.10.23.88` (laptop Andi) ada sembilan, dari `10.10.23.41` (laptop Yudi) lima, dan satu kegagalan Rabu 08:35 setelah rotasi password. Angka ini belum memisahkan penyerang, karena penyerang memakai IP Andi. Langkah berikutnya menampilkan sembilan baris itu dengan waktunya:

```bash
zgrep -h "Accepted password for svc_billing from 10.10.23.88" auth.log auth.log.1 auth.log.*.gz | sort -M -k1,2 -k3
```

Keluaran ilustrasi (waktu lokal server, WIB, tanpa tahun):

```
Sep 15 14:07:52 jkt-billing01 sshd[1904211]: Accepted password for svc_billing from 10.10.23.88 port 61240 ssh2
Sep 22 13:58:10 jkt-billing01 sshd[2011876]: Accepted password for svc_billing from 10.10.23.88 port 55318 ssh2
Sep 24 15:21:47 jkt-billing01 sshd[2049102]: Accepted password for svc_billing from 10.10.23.88 port 57014 ssh2
Sep 29 14:02:33 jkt-billing01 sshd[2116522]: Accepted password for svc_billing from 10.10.23.88 port 50877 ssh2
Oct  1 16:10:05 jkt-billing01 sshd[2152290]: Accepted password for svc_billing from 10.10.23.88 port 62091 ssh2
Oct  6 14:05:19 jkt-billing01 sshd[2231708]: Accepted password for svc_billing from 10.10.23.88 port 51662 ssh2
Oct  8 15:44:02 jkt-billing01 sshd[2270415]: Accepted password for svc_billing from 10.10.23.88 port 58830 ssh2
Oct 12 14:02:14 jkt-billing01 sshd[2341987]: Accepted password for svc_billing from 10.10.23.88 port 49718 ssh2
Oct 13 02:14:33 jkt-billing01 sshd[22904]: Accepted password for svc_billing from 10.10.23.88 port 50122 ssh2
```

**Cara membaca hasil:** delapan baris pertama terjadi di jam kerja hari kerja, termasuk Senin 2026-10-12 14:02:14 yang cocok dengan eksekusi `export-tagihan.ps1` oleh Andi pada 14:02:11 di laptopnya (Day 05). Baris terakhir, Selasa 02:14:33, berbeda waktu dua detik dari `ssh.exe` di laptop Andi (02:14:31), selisih yang wajar antara jam laptop dan jam server. Untuk konteks sesi, ambil semua baris dari PID sshd yang sama dan baris di sekitarnya:

```bash
zgrep -h -E "sshd\[22904\]|sudo: +svc_billing|systemd-logind.*svc_billing" auth.log.1 | grep "^Oct 13 0[2-3]"
```

Keluaran ilustrasi (WIB):

```
Oct 13 02:14:33 jkt-billing01 sshd[22904]: Accepted password for svc_billing from 10.10.23.88 port 50122 ssh2
Oct 13 02:14:33 jkt-billing01 sshd[22904]: pam_unix(sshd:session): session opened for user svc_billing(uid=1001) by (uid=0)
Oct 13 02:14:33 jkt-billing01 systemd-logind[812]: New session 4417 of user svc_billing.
Oct 13 02:15:02 jkt-billing01 sudo: svc_billing : TTY=pts/2 ; PWD=/home/svc_billing ; USER=root ; COMMAND=list
Oct 13 02:21:44 jkt-billing01 sshd[22904]: pam_unix(sshd:session): session closed for user svc_billing
Oct 13 02:21:44 jkt-billing01 systemd-logind[812]: Session 4417 logged out. Waiting for processes to exit.
```

**Cara membaca hasil:** sesi penyerang berlangsung 02:14:33 sampai 02:21:44 (7 menit 11 detik) dengan terminal `pts/2`. Baris `sudo ... COMMAND=list` adalah `sudo -l`: penyerang memeriksa hak sudo akun itu dan tidak menjalankan perintah lain lewat sudo. Logind nomor sesi 4417 dipakai untuk menautkan ke audit.log (bagian 2.3). Tidak ada baris `sudo` lain oleh `svc_billing` di seluruh jendela kecuali restart layanan billing oleh job, yang sesuai aturannya.

Journal dibaca untuk memastikan berkas teks tidak berbeda dengan pencatat biner, dan untuk jendela yang lebih panjang:

```bash
JD=/mnt/e17/var/log/journal/$(ls /mnt/e17/var/log/journal/)
journalctl -D "$JD" --list-boots
TZ=Asia/Jakarta journalctl -D "$JD" _COMM=sshd -o short-iso-precise \
  --since "2026-10-13 02:10:00" --until "2026-10-13 02:25:00" | grep -v publickey
```

- `-D` (`--directory`) membaca berkas journal dari direktori di image, bukan journal workstation analisis [S2].
- `--list-boots` menampilkan daftar boot beserta waktu pesan pertama dan terakhir; ini cara cepat mengetahui jendela journal [S2].
- `_COMM=sshd` memilih pesan dari proses `sshd`. Filter nama unit (`_SYSTEMD_UNIT=`) juga bisa dipakai, tetapi nama unit SSH berbeda antar distribusi (`ssh.service` di keluarga Debian dan Ubuntu, `sshd.service` di keluarga RHEL), jadi cek nama unitnya di image sebelum memakainya.
- `TZ=Asia/Jakarta` membuat `--since`, `--until`, dan tampilan memakai WIB; tanpa itu, journalctl memakai zona workstation analisis. `-o short-iso-precise` menampilkan offset zona dan mikrodetik, sehingga waktu bisa digabung dengan sumber lain tanpa menebak zona [S2].

Keluaran ilustrasi:

```
IDX BOOT ID                          FIRST ENTRY                  LAST ENTRY
 -1 8b2d47e0c3a94f6d8e15a7c9b0d2e638 Sun 2026-08-09 04:12:55 WIB  Thu 2026-08-27 22:08:41 WIB
  0 3f6c0a9e51d24b7e9a1d6c2b8e0f4471 Thu 2026-08-27 22:10:05 WIB  Thu 2026-10-15 23:48:09 WIB

2026-10-13T02:14:33.204118+07:00 jkt-billing01 sshd[22904]: Accepted password for svc_billing from 10.10.23.88 port 50122 ssh2
2026-10-13T02:14:33.209671+07:00 jkt-billing01 sshd[22904]: pam_unix(sshd:session): session opened for user svc_billing(uid=1001) by (uid=0)
2026-10-13T02:21:44.871502+07:00 jkt-billing01 sshd[22904]: pam_unix(sshd:session): session closed for user svc_billing
```

**Cara membaca hasil:** journal menyimpan dua boot: boot sebelumnya mulai 2026-08-09 (pesan paling tua yang belum terhapus karena batas ukuran) sampai reboot setelah pembaruan paket 2026-08-27, lalu boot terakhir sampai server dimatikan Kamis 23:48. Jendela journal jadi lebih tua dari jendela auth.log teks, yang mulai 2026-09-13. Isinya untuk sesi penyerang sama dengan auth.log, dengan presisi mikrodetik dan offset `+07:00`. Dua pencatat yang ditulis proses berbeda dan sepakat menaikkan keyakinan. Bila `--list-boots` hanya menampilkan satu ID padahal wtmp mencatat reboot, cek apakah berkas boot lama sudah terhapus karena batas ukuran.

**Variasi:** di server Debian 12 tanpa rsyslog (`jkt-portal02`), langkah ini hanya memakai journal. Di keluarga RHEL (`jkt-radius01`), berkas teksnya `/var/log/secure`.

**Kapan gagal:** journal volatile di host yang sudah reboot memberi nol baris tanpa galat; berkas journal yang rusak sebagian (server mati tidak bersih) bisa memotong hasil, dan `journalctl --header` membantu melihat keadaan berkas [S2]. `sort -M` pada auth.log tanpa tahun salah urut bila jendela melewati pergantian tahun.

### 2.3 Sesi dan event PAM: wtmp, btmp, dan auditd

Langkah ini menambahkan dua pencatat lagi untuk login yang sama: berkas sesi biner dan auditd. Tujuannya membuktikan jenis sesi (terminal atau bukan) dan menautkan login ke nomor sesi audit.

```bash
TZ=Asia/Jakarta last -F -w -f /mnt/e17/var/log/wtmp
TZ=Asia/Jakarta lastb -F -w -f /mnt/e17/var/log/btmp
```

- `-f` membaca berkas dari image, bukan wtmp workstation analisis.
- `-F` menampilkan tanggal dan jam lengkap, `-w` nama pengguna dan domain lengkap.
- `TZ=Asia/Jakarta` diperlukan karena wtmp menyimpan waktu absolut dan `last` menampilkannya sesuai zona proses yang menjalankannya.

Keluaran ilustrasi `last` (WIB, dipersingkat):

```
adm.yoga     pts/1   10.20.1.20    Thu Oct 15 23:05:12 2026 - Thu Oct 15 23:47:30 2026  (00:42)
adm.yoga     pts/1   10.20.1.20    Tue Oct 13 16:01:08 2026 - Tue Oct 13 16:12:40 2026  (00:11)
adm.yoga     pts/1   10.20.1.20    Tue Oct 13 13:11:52 2026 - Tue Oct 13 13:58:30 2026  (00:46)
svc_billing  pts/2   10.10.23.88   Tue Oct 13 02:14:33 2026 - Tue Oct 13 02:21:44 2026  (00:07)
reboot   system boot 5.15.0-122-ge Thu Aug 27 22:10:05 2026 - Thu Oct 15 23:48:10 2026 (49+01:38)

wtmp begins Thu Aug 27 22:10:05 2026
```

**Cara membaca hasil:** di jendela wtmp, `svc_billing` hanya punya satu sesi terminal: sesi penyerang. Ribuan login job dan login skrip staf tidak muncul karena keduanya menjalankan perintah jarak jauh tanpa terminal; perilaku ini perlu dibuktikan di lab dengan versi OpenSSH yang sama sebelum dipakai sebagai argumen di laporan. Sesi `adm.yoga` adalah jejak responder (live response Selasa siang, containment Selasa sore, cutover Kamis malam), cocok dengan case notes. Baris `reboot` menunjukkan server berjalan tanpa reboot dari 27 Agustus sampai dimatikan Kamis 23:48:10, jadi tidak ada journal atau tmpfs yang hilang karena reboot di jendela kompromi. `lastb` memberi satu baris yang relevan, `svc_billing` dari `10.10.23.41` Rabu 08:35, sama dengan auth.log.

auditd di E17 diperiksa dengan dua langkah: aturan yang terpasang, lalu event.

```bash
cat /mnt/e17/etc/audit/rules.d/audit.rules /mnt/e17/etc/audit/audit.rules
TZ=Asia/Jakarta ausearch -if /mnt/e17/var/log/audit/ -i -m USER_LOGIN -ts 10/13/2026 02:00:00 -te 10/13/2026 03:00:00
TZ=Asia/Jakarta ausearch -if /mnt/e17/var/log/audit/ -i -m EXECVE
TZ=Asia/Jakarta ausearch -if /mnt/e17/var/log/audit/ -i -m USER_CMD -ts 10/13/2026 16:00:00 -te 10/13/2026 16:10:00
```

- `-if` membaca berkas atau direktori log dari image, bukan log workstation [S11].
- `-i` menerjemahkan angka (UID, waktu) menjadi teks [S11].
- `-m` memilih tipe pesan; `-ts` dan `-te` membatasi waktu. Format tanggal untuk `-ts` dan `-te` mengikuti locale workstation (cek dengan `date '+%x'`), dan jamnya ditafsirkan dalam zona proses `ausearch` [S11].

Keluaran ilustrasi (dipersingkat):

```
## First rule - delete all
-D
## Increase the buffers to survive stress events.
-b 8192
--backlog_wait_time 60000
-f 1

----
type=USER_LOGIN msg=audit(10/13/2026 02:14:33.512:88231) : pid=22904 uid=root auid=svc_billing ses=4417
  msg='op=login id=svc_billing exe=/usr/sbin/sshd hostname=? addr=10.10.23.88 terminal=/dev/pts/2 res=success'

<no matches>

----
type=USER_CMD msg=audit(10/13/2026 16:04:12.307:151904) : pid=31877 uid=adm.yoga auid=adm.yoga ses=4602
  msg='cwd=/home/adm.yoga cmd=crontab -r -u svc_billing exe=/usr/bin/sudo terminal=pts/1 res=success'
```

**Cara membaca hasil:** berkas aturan hanya berisi pengaturan buffer dan mode kegagalan, tanpa satu pun aturan `-a ... -S execve` atau `-w`. Karena itu pencarian `EXECVE` mengembalikan `<no matches>`: tidak ada yang dihapus, aturan itu memang tidak pernah ada. Event PAM tetap tercatat karena PAM dan sudo mengirimnya ke subsistem audit tanpa perlu aturan. `USER_LOGIN` pukul 02:14:33 dengan `ses=4417` dan `addr=10.10.23.88` adalah pencatat keempat untuk login yang sama; waktu mentahnya epoch `1791832473`, yang sama dengan 2026-10-12 19:14:33 UTC. `USER_CMD` pukul 16:04:12 adalah perintah responder yang menghapus crontab, lengkap dengan akun, terminal, dan nomor sesi Yoga. Jendela audit.log di E17 dimulai Jumat 2026-10-02 04:51 WIB karena rotasi berdasarkan ukuran; cek `max_log_file` dan `num_logs` di `/mnt/e17/etc/audit/auditd.conf` untuk menjelaskan jendela itu.

**Variasi:** di `jkt-portal02`, pencarian yang sama dengan `-k` (kunci aturan) dan `-ui 33` mengembalikan eksekusi oleh akun web server, karena aturannya ada. Untuk analisis massal, `--format csv` memberi keluaran yang bisa diimpor ke spreadsheet atau timeline [S11].

**Kapan gagal:** `-ts` dengan format tanggal yang tidak sesuai locale menghasilkan galat atau, lebih buruk, rentang yang salah tanpa galat. Berkas audit dari image dibaca `ausearch` dengan nama UID dari `/etc/passwd` workstation analisis saat `-i` dipakai; bila UID berbeda antar host, nama yang tampil bisa salah. Bandingkan dengan `/mnt/e17/etc/passwd`.

### 2.4 Persistensi: cron, unit systemd, kunci SSH, pemuat pustaka, dan akun

Langkah ini menjawab pertanyaan ketiga Dimas. Mulai dari jejak cron, karena itulah mekanisme yang diklaim retainer, lalu periksa lokasi lain satu per satu.

Isi crontab hanya ada di E04, karena berkas spool sudah dihapus saat containment:

```bash
cat /mnt/evidence/INC-2026-019/E04/E04_09_cron.txt
```

Keluaran ilustrasi (diringkas; baris perintah ditulis sebagai deskripsi):

```
# crontab -l -u svc_billing   (Selasa 2026-10-13 13:53 WIB)
*/5 * * * *   <jalankan /dev/shm/.cache/kworkerd bila proses bernama kworkerd tidak ada; output dibuang>

# ls -la /var/spool/cron/crontabs
-rw------- 1 svc_billing crontab  86 Oct 13 02:19 svc_billing
```

Jejak pemasangan, jalannya, dan penghapusan ada di syslog:

```bash
zgrep -h "svc_billing" /mnt/e17/var/log/syslog /mnt/e17/var/log/syslog.1 \
  | grep -E "crontab\[|CRON\[" | awk '{print $5, $6, $7, $8}' | sed 's/\[[0-9]*\]//' | sort | uniq -c
```

- `grep -E "crontab\[|CRON\["` memilih baris dari program `crontab` (pemasangan, pembacaan, penghapusan) dan dari daemon cron (eksekusi).
- `awk` dan `sed` membuang waktu dan PID supaya baris yang sama jenisnya bisa dihitung.

Keluaran ilustrasi:

```
    165 CRON: (svc_billing) CMD
      1 crontab: (svc_billing) REPLACE (svc_billing)
      1 crontab: (svc_billing) LIST (svc_billing)
      1 crontab: (root) LIST (svc_billing)
      1 crontab: (root) DELETE (svc_billing)
```

**Cara membaca hasil:** `REPLACE` pukul 02:19:40 adalah pemasangan crontab oleh `svc_billing` di dalam sesi penyerang; `LIST` oleh `svc_billing` pukul 02:19:52 adalah penyerang memeriksa hasilnya. Eksekusi pertama `CMD` pukul 02:20:01, sama dengan waktu mulai PID 23817 di `E04_04_proses.txt` (`Tue Oct 13 02:20:01 2026`), dan eksekusi terakhir 16:00:01; 165 eksekusi sama dengan setiap 5 menit dari 02:20 sampai 16:00. `LIST` oleh root pukul 13:53 adalah Yoga saat mengambil E04, dan `DELETE` oleh root pukul 16:04:12 adalah containment yang sama dengan `USER_CMD` di bagian 2.3. Sebelum 02:19:40, tidak ada satu baris cron pun untuk `svc_billing` di seluruh jendela syslog. Format persis baris `crontab` dan apakah ada baris `RELOAD` saat daemon membaca ulang spool berbeda antar implementasi cron; cek di lab dengan paket yang sama.

Keadaan spool di E17 mengonfirmasi penghapusan:

```bash
ls -la --time-style=full-iso /mnt/e17/var/spool/cron/crontabs/
fls -r -d -o 1050624 /mnt/e17raw/ewf1 | grep "spool/cron"
```

Keluaran ilustrasi:

```
drwx-wx--T 2 root crontab 4096 2026-10-13 16:04:12.418806533 +0700 .
drwxr-xr-x 3 root root    4096 2025-11-04 10:12:40.000000000 +0700 ..

r/r * 1311022(realloc):	var/spool/cron/crontabs/svc_billing
```

**Cara membaca hasil:** direktori kosong dengan mtime 16:04:12, waktu penghapusan. `fls -d` menampilkan nama berkas yang dihapus, tetapi inode-nya sudah dipakai ulang (`realloc`), sehingga isinya tidak bisa dipulihkan dari E17. Satu-satunya salinan isi jadwal adalah E04. Ini alasan prosedur live response mengambil isi persistensi sebelum containment menghapusnya.

Lokasi persistensi lain diperiksa dengan perintah dari daftar bagian 1.4. Perintah `systemctl` hanya bermakna di sistem hidup, jadi di image yang dibaca adalah direktori unit dan tautan `*.wants` langsung:

```bash
find /mnt/e17/etc/systemd /mnt/e17/usr/lib/systemd /mnt/e17/lib/systemd \
     /mnt/e17/home/*/.config/systemd /mnt/e17/root/.config/systemd \
     \( -name '*.service' -o -name '*.timer' \) -newermt '2026-09-01' -ls 2>/dev/null
find /mnt/e17/etc/cron* /mnt/e17/var/spool/cron -type f -ls
cat /mnt/e17/home/svc_billing/.ssh/authorized_keys; stat /mnt/e17/home/svc_billing/.ssh/authorized_keys
ls -la /mnt/e17/etc/ld.so.preload 2>/dev/null; grep -r . /mnt/e17/etc/ld.so.conf.d/
awk -F: '$3 == 0 {print}' /mnt/e17/etc/passwd
ls -la --time-style=full-iso /mnt/e17/etc/passwd /mnt/e17/etc/shadow /mnt/e17/etc/sudoers /mnt/e17/etc/sudoers.d/
ls -la --time-style=full-iso /mnt/e17/home/svc_billing/.bashrc /mnt/e17/home/svc_billing/.profile /mnt/e17/etc/profile.d/
```

Hasil ringkas (keluaran ilustrasi) disusun sebagai tabel supaya setiap lokasi punya baris; yang perlu kamu cari adalah kolom "batas", karena di situlah kalimat negatif bisa berlebihan.

| Lokasi | Hasil di E17 | Batas |
|---|---|---|
| Unit dan timer systemd (sistem dan per pengguna) | Tiga unit berubah sejak 2026-09-01, semuanya dari pembaruan paket 2026-09-24 (cocok `dpkg.log`); tidak ada direktori `~/.config/systemd` untuk `svc_billing` | Unit yang dibuat lalu dihapus sebelum E17 hanya terlihat bila ada di journal |
| Cron sistem (`/etc/crontab`, `/etc/cron.d`, `cron.daily` dan seterusnya) | Hanya berkas paket, waktu cocok dengan instalasi | Sama |
| Crontab user | Kosong (dihapus responder 16:04:12); isi di E04 | Inode dipakai ulang |
| `authorized_keys` `svc_billing` | Satu kunci (komentar job ekspor), mtime 2026-03-18 10:02 WIB | Kunci di akun lain diperiksa sama; tidak ada akun lain yang login dari luar bastion |
| `/etc/ld.so.preload` | Tidak ada | |
| Akun UID 0 | Hanya `root` | |
| `/etc/passwd`, `shadow`, `sudoers`, `sudoers.d/` | Tidak berubah sejak Agustus 2026; aturan `svc_billing` hanya restart layanan billing | Perubahan yang dikembalikan ke isi semula tidak terlihat dari mtime saja |
| Berkas inisialisasi shell `svc_billing` dan `/etc/profile.d` | Tidak berubah sejak akun dibuat (2026-03-18) atau sejak paket dipasang | |
| `/var/tmp/.font-unix/kworkerd` | Ada, tidak dirujuk oleh jadwal atau unit mana pun | Bagian 2.5 |

**Cara membaca hasil:** satu mekanisme ditemukan (crontab user) dengan bukti pemasangan, 165 eksekusi, dan penghapusan; delapan lokasi lain negatif. Kalimat untuk memo: "crontab `svc_billing` adalah satu-satunya mekanisme persistensi yang ditemukan di lokasi yang diperiksa (daftar terlampir); E17 diambil setelah containment, sehingga mekanisme yang dihapus sebelum Selasa 13:12 hanya akan terlihat bila meninggalkan log, dan log yang tersedia tidak menunjukkan mekanisme lain."

**Kapan gagal:** `-newermt` memakai mtime, yang bisa dipalsukan oleh pemilik berkas; untuk unit yang mencurigakan, cek juga ctime dan crtime dengan `istat` (bagian 2.5). Di keluarga RHEL, crontab user ada di `/var/spool/cron/` tanpa subdirektori `crontabs`.

### 2.5 Waktu file dan bodyfile: salinan kedua, `app.env`, dan `psql`

Langkah ini menjawab pertanyaan keempat Dimas untuk tiga klaim retainer yang menyangkut berkas di disk. Bodyfile dari seluruh partisi dibuat sekali, lalu berkas tertentu diperiksa lebih teliti dengan `istat`.

```bash
fls -r -m / -o 1050624 /mnt/e17raw/ewf1 > /mnt/cases/INC-2026-019/analysis/E17-W1/latihan-2027-02/E17-W1.body
mactime -b E17-W1.body -d -z Asia/Jakarta 2026-10-12..2026-10-14 > E17-W1_mactime_12-14okt.csv
ifind -o 1050624 -n /var/tmp/.font-unix/kworkerd /mnt/e17raw/ewf1
istat -o 1050624 -z Asia/Jakarta /mnt/e17raw/ewf1 1309745
```

- `fls -r -m /` menelusuri seluruh partisi dan menulis bodyfile dengan awalan path `/`; `-o 1050624` adalah offset partisi dalam sektor.
- `mactime -b ... -d -z Asia/Jakarta` menyusun timeline CSV dalam WIB untuk rentang tanggal di argumen terakhir.
- `ifind -n` mencari nomor inode dari path; `istat` menampilkan seluruh atribut inode termasuk empat waktu ext4 dengan presisi nanodetik.

Keluaran ilustrasi `istat` untuk inode 1309745:

```
inode: 1309745
Allocated
uid / gid: 1001 / 1001
mode: rrwxr-xr-x
size: 2318336
Inode Times:
Accessed:       2026-10-13 02:31:07.418230116 (WIB)
File Modified:  2026-10-13 02:31:07.552917004 (WIB)
Inode Modified: 2026-10-13 02:31:07.553040871 (WIB)
File Created:   2026-10-13 02:31:07.418230116 (WIB)
```

**Cara membaca hasil:** berkas dibuat pukul 02:31:07 oleh UID 1001 (`svc_billing`), cocok dengan waktu retainer. Hash isinya (`icat -o 1050624 /mnt/e17raw/ewf1 1309745 | sha256sum`) sama dengan E06 (`c1d8...`) dan ukurannya sama, 2.318.336 byte, jadi ini salinan biner yang sama dengan yang berjalan sebagai PID 23817. Accessed sama dengan Created dan lebih awal dari Modified. Dengan `relatime`, akses berikutnya ke berkas itu akan memperbarui atime karena atime lebih awal dari mtime [S20]; atime yang tidak berubah sampai E17 mendukung bahwa berkas itu tidak pernah dibaca atau dijalankan setelah ditulis. Keyakinannya sedang, bukan tinggi: kesimpulan ini bergantung pada opsi mount yang tercatat di `fstab` dan pada tidak adanya akses lewat cara yang tidak memperbarui atime.

Dua berkas lain diperiksa dengan cara yang sama. Ringkasannya ada di tabel berikut; cari kolom "arti" untuk melihat mengapa waktu yang sama-sama "terlihat" bisa bermakna sangat berbeda.

| Berkas | Waktu di E17 (WIB) | Arti |
|---|---|---|
| `/opt/billing/conf/app.env` | Modified dan Inode Modified Selasa 16:05:40; Accessed Selasa 16:06:02; Created 2025-11-04 | Berkas ditulis ulang saat rotasi kredensial `billing_app` dan dibaca aplikasi saat restart. Pembacaan 02:44 menurut retainer tertimpa; tidak bisa diverifikasi dari disk |
| `/usr/lib/postgresql/14/bin/psql` | Accessed Selasa 03:02:11; Modified 2026-08-27 (pembaruan paket) | Ada akses pertama ke klien `psql` dalam jendela 24 jam pada 03:02:11, cocok dengan "psql ke `jkt-billingdb01`: daftar tabel" pukul 03:02. Pemakaian 03:06 dan 03:15 tidak bisa terlihat karena atime tidak diperbarui lagi dalam 24 jam; akun pemakai tidak tercatat |
| `/home/svc_billing/.psql_history` | Tidak ada | `psql` yang dijalankan tanpa mode interaktif tidak menulis riwayat; ketiadaannya tidak membantah retainer |
| `/home/svc_billing/.bash_history` | Modified Selasa 02:21:44 | Sama dengan logout sesi penyerang di wtmp; isi di bagian 2.6 |

Timeline `mactime` untuk 12-14 Oktober memberi gambaran sekitar kejadian. Baris yang relevan (keluaran ilustrasi, diringkas dari CSV):

```
Date (WIB)                  Size     MACB  Mode         UID   File
2026-10-13 02:14:33        4096     .a..  drwxr-x---   1001  /home/svc_billing
2026-10-13 02:19:40          86     macb  -rw-------   1001  /var/spool/cron/crontabs/svc_billing (deleted-realloc)
2026-10-13 02:21:44         512     m.c.  -rw-------   1001  /home/svc_billing/.bash_history
2026-10-13 02:31:06        4096     m.cb  drwxr-xr-x   1001  /var/tmp/.font-unix
2026-10-13 02:31:07     2318336     .a.b  -rwxr-xr-x   1001  /var/tmp/.font-unix/kworkerd
2026-10-13 02:31:07     2318336     m.c.  -rwxr-xr-x   1001  /var/tmp/.font-unix/kworkerd
2026-10-13 03:02:11     3954496     .a..  -rwxr-xr-x   0     /usr/lib/postgresql/14/bin/psql
2026-10-13 16:04:12        4096     m.c.  drwx-wx--T   0     /var/spool/cron/crontabs
2026-10-13 16:05:40         611     m.c.  -rw-r-----   1001  /opt/billing/conf/app.env
2026-10-13 16:06:02         611     .a..  -rw-r-----   1001  /opt/billing/conf/app.env
```

**Cara membaca hasil:** waktu berkas crontab yang terhapus di baris kedua berasal dari entri nama yang tersisa dan menunjuk inode yang kini dipakai berkas lain; jangan dipakai sebagai bukti mandiri, cukup sebagai petunjuk yang sudah dikonfirmasi syslog. Tidak ada berkas di bawah `/dev/shm` karena tmpfs tidak ada di image. Tidak ada baris yang menunjuk pukul 03:10 atau 03:12 (`p.gz`), karena berkas itu berada di tmpfs.

**Variasi:** UAC dengan profil `ir_triage` menghasilkan bodyfile dari sistem hidup, termasuk tmpfs. Bila prosedur bagian 2.8 sudah ada Oktober lalu, bodyfile `/dev/shm` pukul 13:xx akan tersedia sebagai pembanding E04_08.

**Kapan gagal:** `mactime` tanpa `-z` menampilkan waktu dalam zona workstation analisis. Server yang di-mount `noatime` atau `lazytime` dengan kondisi tertentu membuat atime tidak bisa dipakai; cek `fstab` dan opsi mount di E04 (`mount` atau `/proc/mounts` bila diambil) sebelum memakai atime.

### 2.6 Riwayat perintah `svc_billing`

Langkah ini membaca satu-satunya catatan perintah yang diketik penyerang. Berkas yang sama ada di dua tempat: E04 (dibaca Yoga Selasa 13:5x) dan E17.

```bash
for f in /mnt/e17/home/*/.bash_history /mnt/e17/root/.bash_history; do
  echo "=== $f"; cat "$f"
done
diff <(sed -n '/bash_history/,$p' /mnt/evidence/INC-2026-019/E04/E04_10_svc_billing.txt | tail -n +2) /mnt/e17/home/svc_billing/.bash_history
grep -rn "HISTFILE\|HISTSIZE\|HISTTIMEFORMAT\|histappend" /mnt/e17/home/svc_billing/.bashrc /mnt/e17/etc/bash.bashrc /mnt/e17/etc/profile.d/
```

Isi `.bash_history` `svc_billing` (sembilan baris, tanpa timestamp) disajikan sebagai tabel dengan jangkar waktu dari sumber lain. Isi perintah unduhan dipotong; yang perlu dicatat adalah perilakunya.

| Baris | Perintah (diringkas) | Jangkar waktu dari sumber lain |
|---|---|---|
| 1 | `id` | Setelah login 02:14:33 |
| 2 | `sudo -l` | auth.log 02:15:02 |
| 3 | `cd /dev/shm` | |
| 4 | `mkdir .cache && cd .cache` | |
| 5 | `curl` mengunduh berkas `kworkerd` dari `cdn-sync.example.net` | Firewall (E12): `10.20.5.21` ke `203.0.113.77:443` 02:17:49 sampai 02:17:52; mtime `/dev/shm/.cache/kworkerd` di `E04_08_tmpfs.txt` 02:17:52 |
| 6 | `chmod +x kworkerd` | |
| 7 | `crontab -` (memasang satu baris jadwal) | syslog `REPLACE` 02:19:40 |
| 8 | `crontab -l` | syslog `LIST` 02:19:52 |
| 9 | `exit` | wtmp logout 02:21:44; mtime berkas 02:21:44 |

**Cara membaca hasil:** riwayat di E04 dan E17 identik, dan konfigurasi shell tidak mengatur `HISTTIMEFORMAT`, sehingga urutan perintah berasal dari urutan baris dan jangkar waktu berasal dari log lain [S18]. Riwayat memberi dua fakta yang tidak ada di memo memori retainer: penyerang memeriksa hak sudo sebelum memasang persistensi, dan biner diunduh dari server C2 lewat `curl` di dalam sesi SSH (bukan disalin dari laptop Andi, yang konsisten dengan tidak adanya `scp.exe` di laptop itu). Riwayat tidak memuat apa pun setelah 02:21:44, karena semua tindakan berikutnya (02:31 sampai 03:15) dikerjakan implant, bukan shell. Riwayat `root` dan `adm.yoga` hanya berisi perintah administrasi dan responder.

**Kapan gagal:** riwayat dari shell yang dibunuh atau dari sesi dengan `HISTFILE` dikosongkan tidak tertulis; riwayat dengan `histappend` mati bisa tertimpa sesi lain yang keluar belakangan. Ketiadaan riwayat bukan bukti tidak ada perintah [S18].

### 2.7 Memo verifikasi untuk Dimas

Memo ini adalah jawaban pertanyaan pertama Dimas. Dikirim Kamis 2027-02-18 pukul 15:30 dan disimpan di `\\jkt-evid01\cases\INC-2026-019\notes\verifikasi-internal-E17-2027-02-18.md`. Skala keyakinan memakai skala template laporan PT JAB (Tinggi, Sedang, Rendah, Tidak dapat ditentukan).

Tabel berikut adalah inti memo. Yang harus dibaca Dimas adalah kolom "status": terverifikasi internal, konsisten (didukung tidak langsung), atau bersandar pada E05.

| No | Kesimpulan retainer | Bukti internal (sumber) | Status | Keyakinan internal |
|---|---|---|---|---|
| 1 | SSH `svc_billing` dengan password dari `10.10.23.88` Selasa 02:14 | auth.log, journal, wtmp, audit `USER_LOGIN` (E17); Sysmon `JKT-WS-0388` 02:14:31 | Terverifikasi | Tinggi |
| 2 | Beacon mulai 02:20 dari `/dev/shm/.cache/kworkerd` lewat cron `svc_billing` | syslog `CRON CMD` 02:20:01 dan 165 eksekusi; waktu mulai PID 23817 (E04_04); koneksi ke `203.0.113.77:443` (E04_01); isi crontab (E04_09) | Terverifikasi | Tinggi |
| 3 | Crontab satu-satunya persistensi | Delapan lokasi lain negatif (bagian 2.4) | Terverifikasi untuk lokasi yang diperiksa | Sedang |
| 4 | Salinan kedua `/var/tmp/.font-unix/kworkerd` 02:31, tidak berjalan | Created 02:31:07, hash sama E06; atime tidak berubah dengan `relatime` | Terverifikasi (keberadaan dan waktu); konsisten (tidak berjalan) | Tinggi untuk keberadaan; Sedang untuk tidak berjalan |
| 5 | Membaca `app.env` 02:44 | Waktu berkas tertimpa rotasi kredensial 16:05 | Bersandar pada E05 | Tidak dapat ditentukan dari disk |
| 6 | `psql` 03:02, query 5.000 baris 03:06, sesi kedua 03:15 | atime `psql` 03:02:11 | Konsisten untuk 03:02; isi query dan 03:06 serta 03:15 bersandar pada E05 | Sedang untuk pemakaian `psql` dini hari; isi query tidak dapat ditentukan dari disk |
| 7 | `p.gz` dibuat 03:10, dihapus 03:12 | Berkas di tmpfs, tidak ada di E17; tidak ada di `E04_08` (13:5x); kenaikan volume ke C2 di firewall | Bersandar pada E05 dan firewall | Tidak dapat ditentukan dari disk |
| 8 | Tidak terlihat eskalasi ke root | Hanya `sudo -l`; berkas identitas dan sudoers tidak berubah; tidak ada SUID baru | Konsisten | Sedang |

Selain tabel, memo memuat empat paragraf pendek:

1. **Temuan tambahan.** Riwayat shell menunjukkan penyerang memeriksa hak sudo (02:15:02) dan mengunduh implant dengan `curl` dari `cdn-sync.example.net` di dalam sesi SSH (02:17:49 sampai 02:17:52). Tidak mengubah kesimpulan dampak.
2. **Jejak responder dan pemulihan.** Penghapusan crontab (16:04:12), rotasi `app.env` (16:05:40), sesi `adm.yoga`, dan `tar` atas `/var/log` (mengubah atime berkas log) adalah tindakan PT JAB, tercatat di case notes dan audit.
3. **Yang tidak diverifikasi.** Analisis memori E05 tidak diulang karena PT JAB belum punya symbol table untuk kernel `5.15.0-122-generic`. Kesimpulan retainer tentang isi query dan volume data tetap berdiri dengan keyakinan "sedang-tinggi" yang ditulis retainer; verifikasi internal tidak menaikkan atau menurunkannya.
4. **Pelajaran untuk prosedur.** Bila auditd di `jkt-billing01` punya aturan `execve` untuk `svc_billing`, eksekusi `psql`, `gzip`, dan `rm` oleh implant akan tercatat dengan waktu dan argumennya, dan butir 5 sampai 7 bisa diverifikasi internal. Usulan aturan masuk ke prosedur bagian 2.8.

**Kapan gagal:** memo yang hanya berisi kolom "status" tanpa sumber akan dibaca sebagai "kita membantah retainer" di butir 5 dan 7. Kolom sumber dan paragraf jejak pemulihan mencegah salah baca itu.

### 2.8 Prosedur koleksi Linux dengan UAC: `JAB-DFIR-PRO-LNX-01`

Prosedur ini menjawab pertanyaan kelima Dimas. Draf diuji di VM lab, lalu sekali di `jkt-billing02` pada Senin 2027-02-22 pukul 21:00 sampai 21:16 dalam jendela pemeliharaan yang disetujui Lead Aplikasi Billing Wahyu Nugroho, dengan pemberitahuan ke L1 shift supaya alert yang muncul tidak dieskalasi sebagai insiden. Versi 1.0 diserahkan Selasa 2027-02-23 pukul 17:00 dan disimpan di repositori `jab-ir-tools` path `docs/forensik/JAB-DFIR-PRO-LNX-01.md`; paket UAC 3.4.0 beserta SHA-256 arsip rilisnya dicatat di inventaris toolkit `jkt-evid01:/export/irkit/uac-3.4.0/`.

Perbedaan antar host yang harus diketahui pelaksana dirangkum di tabel berikut; baca kolom "yang berubah di prosedur" sebelum menjalankan di host tertentu.

| Host | Sistem | Log autentikasi | auditd | Telemetri lain | Yang berubah di prosedur |
|---|---|---|---|---|---|
| `jkt-billing02` (`10.20.5.22`) | Ubuntu 24.04 LTS dari `JAB-LNX-GOLD-2026.09` | auth.log dan journal | Aturan baseline gold image | Defender for Endpoint untuk Linux | Ekspor timeline perangkat dari portal Defender sebagai bukti terpisah |
| `jkt-portal02` | Debian 12, instalasi baru | Journal saja (rsyslog tidak terpasang) | Aturan `execve` untuk akun web server | Access log web server | Pastikan journal persisten sebelum insiden; tambahkan log web server ke profil |
| `jkt-radius01` | Rocky Linux 9 | `/var/log/secure` dan journal | Bawaan | Log aplikasi AAA | Crontab user di `/var/spool/cron/`; layanan pelanggan sensitif terhadap beban CPU |

Langkah prosedur (semua dari `jkt-bastion01`; `$H` host target, `$C` nomor kasus, `$E` nomor bukti, `$K` folder biner statis toolkit):

```bash
# 0. jam dan identitas, sebelum apa pun
ssh adm.<nama>@$H "date -u; date; timedatectl; hostname; cat /etc/os-release" > ${E}_00_waktu.txt

# 1. mount toolkit read-only dan export output (dicatat di case notes)
ssh -t adm.<nama>@$H "sudo mkdir -p /mnt/irkit /mnt/irout && \
  sudo mount -o ro,nolock jkt-evid01:/export/irkit /mnt/irkit && \
  sudo mount -o rw,nolock jkt-evid01:/export/irout/$C /mnt/irout"

# 2. blok volatil dengan biner toolkit, output ditangkap di bastion
ssh -t adm.<nama>@$H "sudo $K/ss -tanp; sudo $K/ps -eo pid,ppid,user,lstart,args --forest; $K/w; cat /sys/kernel/security/lockdown" > ${E}_01_volatil.txt

# 3. memori (hanya atas keputusan technical lead; lockdown harus [none])
ssh -t adm.<nama>@$H "sudo /mnt/irkit/avml --compress /mnt/irout/${E}_${H}_mem.lime.snappy"

# 4. koleksi UAC
ssh -t adm.<nama>@$H "cd /mnt/irkit/uac-3.4.0 && sudo ./uac -p ir_triage -H \
  --case-number $C --evidence-number $E --examiner '<nama>' \
  -o ${E}_${H}_uac /mnt/irout"

# 5. lepas mount, lalu hash di jkt-evid01
ssh -t adm.<nama>@$H "sudo umount /mnt/irout /mnt/irkit"
sha256sum /export/irout/$C/${E}_${H}_* > /export/irout/$C/${E}_${H}.sha256
```

Penjelasan bagian yang menentukan:

- Langkah 0 dan 2 mengulang pola E04: jam dan keadaan volatil diambil sebelum koleksi yang lebih lama, dengan biner dari toolkit untuk perintah yang paling sering dipalsukan.
- `-p ir_triage` memilih profil koleksi cepat; `-H` meng-hash semua berkas yang dikumpulkan; `--case-number`, `--evidence-number`, dan `--examiner` menulis metadata kasus ke log UAC; `-o` memberi nama dasar output tanpa ekstensi; argumen terakhir adalah tujuan output [S9]. Format default `tar` dipakai.
- Tujuan `/mnt/irout` adalah export NFS. Direktori sementara UAC default berada di dalam tujuan, jadi tidak ada data yang ditulis ke disk host [S9]. Prosedur mensyaratkan uji lab bahwa UAC berjalan dari direktori read-only; bila versi yang dipakai menolak, salin folder UAC ke `/mnt/irout/$C/uac-run/`, bukan ke disk host.
- Profil `full` atau tambahan artefak dengan `-a` hanya atas keputusan technical lead. Contoh: memori lewat artefak UAC `./uac -a ./artifacts/memory_dump/avml.yaml -p full <tujuan>` [S1], atau mengecualikan bodyfile dengan `-a \!artifacts/bodyfile/bodyfile.yaml` bila waktu sangat terbatas. Untuk mengulang hanya artefak proses dari profil penuh, polanya `./uac -p full -a './artifacts/live_response/process/*' <tujuan>`.

Keluaran ilustrasi uji di `jkt-billing02` (ringkas dari `uac.log` dan catatan uji):

```
Case number: UJI-2027-02   Evidence number: UJI01   Examiner: <nama>
Profile: ir_triage         Hash collected: yes
Start: 2027-02-22 21:03:40 WIB   End: 2027-02-22 21:15:20 WIB   (11 menit 40 detik)
Output: UJI01_jkt-billing02_uac.tar (412 MB) + daftar hash per berkas
Artefak gagal: 3 (perintah tidak tersedia di gold image), tercatat di uac.log
Beban: CPU naik ke sekitar 35 persen selama pembuatan bodyfile dan hash; layanan billing normal
Defender for Endpoint: 1 alert prioritas rendah untuk pola enumerasi sistem, ditutup L1 dengan rujukan uji
```

**Cara membaca hasil:** durasi dan ukuran menjadi angka perencanaan untuk insiden nyata (kapan koleksi bisa selesai sebelum keputusan containment). Tiga artefak yang gagal didaftar di prosedur sebagai celah yang diketahui untuk host dari gold image itu, dan pemilik gold image diminta menilai apakah paket yang dibutuhkan perlu ditambahkan. Alert Defender adalah pengingat bahwa koleksi forensik terlihat seperti aktivitas penyerang bagi EDR; prosedur mewajibkan pemberitahuan ke SOC sebelum menjalankannya.

Prosedur juga memuat usulan telemetri untuk server tanpa EDR, karena pelajaran memo bagian 2.7: aturan auditd `execve` dua arsitektur untuk akun aplikasi (`svc_billing`, akun web server, akun layanan RADIUS) dengan kunci pencarian (bebannya kecil karena akun aplikasi jarang menjalankan program lain, sehingga volume event rendah), journal persisten dengan ukuran yang cukup untuk minimal 30 hari, `HISTTIMEFORMAT` untuk akun interaktif, dan pengiriman `linux_secure` dan `linux_audit` ke Splunk. Pemilik usulan: tim Infrastruktur.

**Kapan gagal:** export NFS tidak bisa di-mount karena firewall data center atau paket klien NFS tidak terpasang di gold image; uji mount ini setiap kuartal. UAC berjalan lama di server dengan jutaan berkas kecil (bodyfile dan hash); untuk host seperti itu, tetapkan batas waktu dan pertimbangkan mengecualikan bodyfile lalu mengambil image. Menjalankan UAC tanpa root (`-u`) memberi koleksi yang tampak lengkap tetapi kehilangan log dan berkas milik akun lain [S9].

### 2.9 Prosedur triage macOS: `JAB-DFIR-PRO-MAC-01`

Prosedur ini menjawab pertanyaan keenam Dimas. Tidak ada kasus nyata; prosedur disusun dari peta artefak bagian 1.7 dan syarat izin bagian 1.8, lalu diuji di MacBook cadangan tim IT yang terdaftar di Intune. Diserahkan bersama prosedur Linux Selasa 2027-02-23 dan disimpan di `jab-ir-tools` path `docs/forensik/JAB-DFIR-PRO-MAC-01.md`.

Persiapan sebelum insiden (pemilik: tim IT bersama pembaca):

1. Profil PPPC `JAB-IR-FDA-Terminal` (`SystemPolicyAllFiles` untuk Terminal, dengan code requirement Terminal) dibuat di Intune dan ditargetkan ke grup perangkat `IR-Triage-Mac` yang kosong [S16].
2. Akun admin lokal khusus IR di setiap MacBook, dibuat dan dirotasi lewat Intune.
3. Media responder `JAB-IR-MAC` (SSD eksternal, exFAT supaya terbaca di `jkt-dfir02` dan `JKT-DFIR01`) berisi `uac-3.4.0/` dan daftar SHA-256 alat.
4. Mac analisis untuk membaca `.logarchive` (belum ada; diusulkan, karena alat `log` hanya tersedia di macOS).

Langkah saat insiden (responder di depan laptop; `$C`, `$E`, dan nama host diisi):

```bash
# 0. jam dan identitas
date -u; date; sw_vers; hostname

# 1. setelah perangkat masuk grup IR-Triage-Mac dan profil terpasang (dicek di Intune)
sudo log collect --output /Volumes/JAB-IR-MAC/$C/${E}_JKT-MB-0X.logarchive --last 7d

# 2. koleksi UAC
cd /Volumes/JAB-IR-MAC/uac-3.4.0 && sudo ./uac -p ir_triage -H \
  --case-number $C --evidence-number $E --examiner '<nama>' -o ${E}_JKT-MB-0X_uac /Volumes/JAB-IR-MAC/$C

# 3. persistensi dan asal berkas yang mencurigakan (dicatat ke berkas di media)
ls -la /Library/LaunchDaemons /Library/LaunchAgents /Users/*/Library/LaunchAgents /Library/PrivilegedHelperTools
xattr -l "<path berkas mencurigakan>"

# 4. hash di media, lalu keluarkan perangkat dari grup
shasum -a 256 /Volumes/JAB-IR-MAC/$C/${E}_JKT-MB-0X_* > /Volumes/JAB-IR-MAC/$C/${E}_JKT-MB-0X.sha256
```

- `log collect` membekukan unified log ke berkas arsip yang bisa dibawa dan dianalisis di tempat lain, dan arsip itu yang dijadikan bukti, bukan laptopnya. Sintaksnya `log collect [--output path] [--start ...] [--size ...] [--last num[m|h|d]]`; tanpa `--output`, arsip ditulis ke direktori kerja [S14].
- Langkah 2 sama dengan Linux; UAC mendeteksi macOS sendiri, atau dipaksa dengan `-s macos` [S9].
- Laptop dibiarkan menyala; FileVault aktif, jadi mematikannya mengunci disk (Day 22).

Analisis di Mac analisis memakai `log show` atas arsip:

```bash
log show --archive E0X_JKT-MB-0X.logarchive \
         --predicate 'process == "sshd" OR eventMessage CONTAINS "launchd"' \
         --style ndjson --start '2027-02-01 00:00:00' --timezone local
```

- `--style ndjson` memberi satu objek JSON per baris, yang memudahkan penggabungan ke timeline (Day 13); `--info` dan `--debug` mati secara default, jadi tanpa opsi itu hanya pesan tingkat default dan di atasnya yang tampil [S14].
- Sebelum menganalisis, cek rentang waktu nyata di arsip: rentang yang diminta dengan `--last 7d` bisa lebih panjang daripada isi penyimpanan, karena pesan lama dihapus saat penyimpanan melebihi batas [S13].
- Opsi persisnya bisa berbeda antar versi macOS; cocokkan dengan `man log` di Mac analisis.

Contoh membaca persistensi diambil dari lab (bukan dari MacBook PT JAB). Bila ditemukan LaunchDaemon yang tidak dikenal, plist biner dikonversi dulu:

```bash
plutil -convert xml1 -o - "/Library/LaunchDaemons/com.vendor.updater.plist"
xattr -p com.apple.quarantine "/Users/<pengguna>/Downloads/installer.pkg"
```

Keluaran ilustrasi plist setelah dikonversi:

```xml
<key>Label</key>        <string>com.vendor.updater</string>
<key>ProgramArguments</key>
<array>
  <string>/Users/Shared/.cache/updater</string>
</array>
<key>RunAtLoad</key>    <true/>
<key>KeepAlive</key>    <true/>
```

**Cara membaca hasil:** program di `/Users/Shared/.cache` dengan nama direktori berawalan titik adalah lokasi yang tidak lazim untuk daemon sah. `RunAtLoad` dan `KeepAlive` bersama berarti program dijalankan saat dimuat dan dijalankan ulang bila berhenti, yaitu perilaku yang diinginkan untuk persistensi. Atribut `com.apple.quarantine` menyimpan jejak asal unduhan berkas; ketiadaannya pada berkas yang seharusnya diunduh bisa berarti atributnya dihapus, atau berkas datang lewat jalur yang tidak menandai, misalnya disalin dari media lepasan atau dibuat di sistem itu.

**Variasi:** bila Mac analisis belum ada, artefak berkas (plist, basis data SQLite, FSEvents) bisa diurai dengan mac_apt di `jkt-dfir02`; cek modul dan format input yang didukung versi yang dipasang [S5][S12]. Atribut extended tidak selalu ikut tersalin ke media exFAT dalam bentuk yang sama, jadi pemeriksaan `xattr` untuk berkas penting dilakukan di laptop dan hasilnya dicatat.

**Kapan gagal:** profil PPPC belum terpasang saat koleksi dimulai, sehingga log UAC penuh galat izin untuk TCC dan `~/Library`; cek status profil di Intune sebelum langkah 1. Rentang `log collect` yang diminta melebihi retensi yang ada. Responder mematikan laptop "supaya aman" dan kehilangan akses ke disk tanpa recovery key.

### 2.10 Menggabungkan ke satu timeline

Bodyfile dari koleksi UAC atau dari `fls`, ekspor journal (`journalctl -o json`), audit.log, dan keluaran `ndjson` dari unified log bisa digabungkan ke super-timeline yang sama seperti di Day 13. Kunci keberhasilannya satu: semua dikonversi ke UTC lebih dulu, dan zona waktu asal dicatat per sumber. Untuk `jkt-billing01`, catatan zonanya: auth.log dan syslog dalam WIB tanpa zona dan tanpa tahun, journal dan wtmp dan audit.log dalam waktu absolut, bodyfile dalam epoch, dan log firewall dalam zona yang dicatat Splunk. Garis waktu kurasi memo bagian 2.7 disusun dengan kolom UTC dan WIB berdampingan.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** VM baru `LAB-LNX01` (`172.16.50.50`, Ubuntu Server 22.04 LTS, rsyslog dan journal persisten, auditd terpasang dengan aturan bawaan, OpenSSH server, snapshot `bersih-lnx-2027-02`), `LAB-DFIR01` (`172.16.50.20`) sebagai sumber SSH dan tempat menyimpan hasil, dan bila ada VM timeline `LAB-TL01` (`172.16.50.40`, Ubuntu LTS) dari lab Day 13 untuk menjalankan `journalctl`, `ausearch`, dan The Sleuth Kit atas koleksi. Semua di jaringan host-only `172.16.50.0/24`. Akun lab: `lab-svc23` (akun "service" yang dipakai penyerang tiruan, password dan satu kunci SSH) dan `lab-ir23` (admin responder dengan sudo). Disk virtual kedua `LAB-IR23` (ext4) berisi folder `uac-3.4.0/` yang SHA-256 arsip rilisnya dicatat, dan menjadi tujuan output. Folder kasus `CASE-2026-LAB-023` di `LAB-DFIR01` dengan `evidence\`, `work\`, `analysis\`, `notes\`. Semua aktivitas "penyerang" jinak: program tiruan adalah skrip yang menulis timestamp ke berkas di `/dev/shm`, bukan sampel. Tanpa macOS, kerjakan bagian Linux saja dan catat bagian macOS sebagai celah.

1. **Kebenaran dasar.** Tulis `kebenaran-dasar.md` di `LAB-DFIR01` sebelum mulai: setiap langkah berikut beserta jam WIB-nya. Catat zona waktu `LAB-LNX01` (atur ke `Asia/Jakarta`) dan zona `LAB-TL01` (biarkan UTC) supaya jebakan zona waktu muncul sendiri.
2. **Pemakaian sah.** Dari `LAB-DFIR01`, jalankan perintah jarak jauh tanpa terminal ke `lab-svc23` dengan kunci SSH setiap beberapa menit selama satu jam (pengganti job ekspor), dan dua kali dengan password.
3. **Sesi "penyerang".** Login interaktif dengan password ke `lab-svc23`, jalankan `id` dan `sudo -l`, buat `/dev/shm/.lab23/`, salin skrip tiruan ke sana, pasang crontab tiap 5 menit yang menjalankannya bila belum berjalan, lalu `crontab -l` dan `exit`. Lima belas menit kemudian, dari proses yang dijalankan cron, tulis salinan kedua skrip ke `/var/tmp/.lab23/`.
4. **Koleksi live.** Sebagai `lab-ir23`, jalankan blok volatil (jam, `ss -tanp`, `ps` forest, `w`, status lockdown), lalu UAC `-p ir_triage -H` dengan `--case-number CASE-2026-LAB-023` ke disk `LAB-IR23`. Catat durasi, ukuran output, dan artefak yang gagal di `uac.log`. Uji juga apakah UAC berjalan dari folder yang di-mount read-only.
5. **Containment tiruan.** Hapus crontab `lab-svc23` dengan `sudo crontab -r -u lab-svc23`, hentikan proses tiruan, lalu matikan VM dengan bersih. Ambil image disk VM (salinan berkas disk virtual) dan hash-nya.
6. **Autentikasi.** Dari koleksi dan image, hitung login per metode dan IP dari auth.log, cari sesi yang sama di journal (`-D`, `_COMM=sshd`), wtmp (`last -f`), dan audit (`ausearch -if ... -m USER_LOGIN`). Pastikan login skrip tanpa terminal tidak muncul di wtmp, atau catat bila muncul (bagian 2.2 dan 2.3).
7. **Persistensi dari koleksi offline.** Temukan crontab dari output UAC dan dari syslog (`REPLACE`, `CMD`, `DELETE`), periksa delapan lokasi lain dari bagian 2.4 di image, dan buktikan bahwa berkas spool tidak bisa dipulihkan setelah dihapus.
8. **Waktu file.** Dengan `istat`, periksa salinan kedua di `/var/tmp/.lab23/`: catat empat waktunya, lalu baca berkas itu sekali di VM (setelah mengembalikan snapshot sebelum langkah 5) dan ulangi untuk melihat atime berubah. Ulangi dengan mount `noatime` untuk melihat atime tidak berubah.
9. **auditd execve.** Kembalikan snapshot, tambahkan aturan `execve` dua arsitektur untuk UID `lab-svc23` dengan kunci `lab23`, ulangi langkah 3, lalu bandingkan hasil `ausearch -k lab23` dengan hasil tanpa aturan.
10. **Riwayat shell.** Ulangi sesi penyerang dengan `HISTTIMEFORMAT` diatur, lalu sekali lagi dengan sesi yang dibunuh dari luar (`kill -9` pada shell). Bandingkan isi `.bash_history` ketiga percobaan.
11. **Journal volatile.** Ubah `Storage=volatile`, reboot, ulangi login, matikan, lalu cari login itu di image. Kembalikan snapshot sesudahnya.
12. **macOS (bila ada Mac lab atau VM macOS).** Jalankan `log collect --last 7d`, periksa rentang nyata di arsip dengan `log show`, bandingkan dengan rentang yang diminta. Buat LaunchAgent jinak dengan `RunAtLoad` dan `KeepAlive`, temukan dari koleksi UAC, lalu periksa atribut quarantine pada satu berkas yang diunduh browser dan satu yang disalin dari media lepasan. Jalankan UAC sekali tanpa Full Disk Access untuk Terminal dan sekali dengan, lalu bandingkan galat di `uac.log`.
13. **Timeline dan memo.** Gabungkan bodyfile, ekspor journal JSON, dan audit ke satu timeline UTC (Day 13), lalu tulis memo verifikasi satu halaman dengan format bagian 2.7 terhadap `kebenaran-dasar.md`: butir mana yang terverifikasi, konsisten, atau tidak dapat ditentukan dari disk.

**Hasil yang sebaiknya tersimpan:**

- `kebenaran-dasar.md` dan catatan zona waktu kedua VM.
- Output UAC beserta durasi, ukuran, daftar artefak gagal, dan hasil uji direktori read-only.
- Tabel login per metode dan IP, dengan satu sesi yang ditemukan di empat pencatat.
- Bukti persistensi cron dari koleksi offline, termasuk jejak penghapusan oleh responder.
- Tabel atime salinan kedua sebelum dan sesudah dibaca, dengan `relatime` dan `noatime`.
- Perbandingan audit tanpa dan dengan aturan `execve`.
- Kesimpulan tentang keandalan riwayat shell dari tiga percobaan.
- Rentang waktu nyata `.logarchive` dibanding yang diminta, isi plist LaunchAgent, dan hasil pemeriksaan quarantine (bila ada Mac).
- Timeline gabungan dan memo verifikasi.

**Variasi tantangan:** ulangi langkah 3-7 di VM Debian 12 bawaan (tanpa rsyslog) dan di VM keluarga RHEL. Catat setiap baris prosedur yang harus diubah, lalu tulis ulang tabel perbedaan host seperti di bagian 2.8 untuk lab-mu.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat triage dan analisis Linux dan macOS. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| `journalctl` tidak menemukan apa pun | Journal tidak persisten, hanya di memori; atau membaca journal workstation, bukan image | Cek `Storage=` dan keberadaan `/var/log/journal`; pakai `-D` ke direktori di image; cari syslog teks |
| Tidak ada `/var/log/auth.log` | Distribusi tanpa rsyslog (Debian 12 instalasi baru) atau keluarga RHEL (`secure`) | Baca journal; cek `/var/log/secure` |
| `last` menampilkan hasil kosong atau jam aneh | `wtmp` dirotasi atau dikosongkan; zona workstation berbeda | Periksa berkas rotasi (`wtmp.1`); jalankan dengan `TZ=` zona host; bandingkan dengan log autentikasi |
| `ausearch -m EXECVE` kosong | Tidak ada aturan syscall di auditd | Baca `audit.rules` di image; catat sebagai celah visibilitas, bukan penghapusan |
| `ausearch -ts` galat atau rentang salah | Format tanggal mengikuti locale; jam ditafsirkan dalam zona workstation | Cek `date '+%x'`; jalankan dengan `TZ=` zona host |
| Tidak ada jejak eksekusi sama sekali | Tidak ada auditd `execve` dan tidak ada EDR | Catat sebagai celah visibilitas; fokus ke keadaan, persistensi, log cron dan sudo, atime |
| Waktu antar sumber tidak cocok | Sebagian log dalam waktu lokal tanpa zona dan tanpa tahun | Tetapkan zona host dari image, konversi semua ke UTC (Day 13) |
| Berkas di `/run` atau `/dev/shm` tidak ada di image | tmpfs hilang saat dimatikan | Cari di output live response dan memori; jangan simpulkan tidak pernah ada |
| Crontab tidak ada di image padahal live response menemukannya | Dihapus saat containment | Cek case notes, syslog `DELETE`, audit `USER_CMD` |
| Hash salinan kerja berubah setelah mount | ext4 memutar ulang journal pada mount `ro` | Mount dengan `ro,noload`; buat ulang salinan kerja dari master |
| atime tidak bisa dipakai | Mount `noatime`, atau berkas diakses ulang dalam 24 jam | Cek `fstab` dan opsi mount saat live; tulis atime sebagai pendukung, bukan bukti tunggal |
| Koleksi UAC gagal atau tidak lengkap di sistem minim | Beberapa artefak butuh perintah yang tidak ada | Pakai profil yang lebih kecil; catat artefak yang gagal dari `uac.log` |
| UAC di macOS penuh galat izin | Terminal belum punya Full Disk Access | Pastikan profil PPPC terpasang; jalankan ulang |
| `log show` memberi lebih sedikit dari yang diminta | Retensi unified log lebih pendek dari rentang permintaan; `info` dan `debug` tidak disimpan | Periksa rentang nyata di arsip sebelum menganalisis |
| plist tidak terbaca | Formatnya biner | Konversi dengan `plutil -convert xml1` |
| Tidak ada atribut quarantine pada berkas unduhan | Atribut dihapus, atau berkas tidak datang lewat jalur yang menandai | Jangan simpulkan satu arah; cari jalur masuk lain |

## 5. Kesalahan umum dan jebakan

- **Menulis hasil koleksi ke disk yang sedang diperiksa.** Tujuan output selalu NFS atau media lain, dan direktori sementara UAC ikut berada di tujuan itu.
- **Menyalin hanya `/var/log/*.log`** dan kehilangan seluruh journal biner, atau sebaliknya membaca journal saja dan melewatkan berkas rotasi teks yang lebih tua.
- **Mematikan sistem Linux sebelum mengumpulkan** isi tmpfs, daftar proses, dan koneksi. Biner `kworkerd` di `/dev/shm` hanya selamat karena disalin dari `/proc/23817/exe`.
- **Memperlakukan `~/.bash_history` sebagai catatan waktu yang andal.** Tanpa `HISTTIMEFORMAT` tidak ada waktu; perintah implant dan cron tidak pernah masuk riwayat.
- **Menyimpulkan tidak ada eksekusi mencurigakan** padahal memang tidak ada mekanisme yang mencatatnya. "auditd aktif" tidak sama dengan "eksekusi tercatat".
- **Membaca jejak responder dan pemulihan sebagai bantahan.** Crontab yang dihapus saat containment dan `app.env` yang ditulis ulang saat rotasi membuat disk tampak tidak sejalan dengan retainer.
- **Menulis atime sebagai bukti kuat.** Dengan `relatime`, atime hanya memberi akses pertama dalam jendela tertentu, tanpa akun.
- **Membedakan penyerang dari pemakai sah hanya dengan IP.** Di kasus ini IP-nya sama; pembedanya waktu, jenis sesi, perintah, dan korelasi dengan host sumber.
- **Menggabungkan log dari beberapa sumber tanpa menyeragamkan zona waktu**, termasuk lupa bahwa `last`, `journalctl`, `ausearch`, dan `mactime` menampilkan waktu sesuai zona workstation analisis.
- **Memeriksa hanya satu dari tiga lokasi LaunchAgent dan LaunchDaemon** di macOS, atau lupa `PrivilegedHelperTools`.
- **Menyimpulkan asal berkas hanya dari ada atau tidaknya atribut quarantine.**
- **Mematikan SIP atau MacBook ber-FileVault "supaya bisa dikoleksi".** Keduanya menghapus keadaan hidup, dan yang kedua bisa membuat disk tidak terjangkau.
- **Mengandalkan alat Windows** untuk memeriksa artefak yang formatnya khas Unix.

## 6. Catatan terkini

Bagian ini menampung detail versi, perubahan perilaku distribusi, dan catatan sumber yang bisa berubah; alur analisis di atas tidak bergantung padanya kecuali disebut.

- **UAC 3.4.0** (rilis 9 September 2026) menambah artefak untuk berbagai alat pengembangan berbasis AI, artefak macOS untuk `PrivilegedHelperTools` (bisa dipakai untuk persistensi), memperluas artefak Docker ke macOS, memasukkan macOS ke set perintah `ps`, dan memperbarui AVML di dalam paket ke v0.20.0 [S8]. Rilis sebelumnya 3.3.0 (April 2026). README tidak mencantumkan nomor versi; versi dicatat dari halaman rilis saat menyiapkan toolkit [S1][S8].
- **Opsi UAC** yang dipakai prosedur PT JAB (`-p`, `-a`, `-o`, `-f`, `-H`, `-u`, `--case-number`, `--start-date`, `--temp-dir`) diambil dari dokumentasi proyek; nama berkas output default `uac-%hostname%-%os%-%timestamp%` [S9]. UAC berjalan tanpa instalasi dan tanpa dependensi, hanya butuh shell [S1]. Untuk tim kecil, ini berarti satu prosedur koleksi bisa dipakai di hampir semua sistem non-Windows yang akan kamu temui.
- **UAC mengumpulkan proses yang berjalan termasuk yang binernya tidak ada di disk** [S1]. Itu kategori temuan yang berharga, karena proses tanpa berkas di disk adalah pola yang sering muncul pada malware Linux.
- **journald:** dokumentasi systemd terbaru menyebut `Storage=persistent` sebagai default namespace bawaan dan `SystemMaxUse=` 10 persen file system dengan batas 4G [S10]. Distribusi dan versi systemd lama memakai `auto`; jangan menganggap default tanpa membaca konfigurasi host.
- **Debian 12** tidak lagi memasang rsyslog secara bawaan; sistem hasil upgrade bisa tidak menyimpan journal secara persisten [S19].
- **mac_apt v1.36.2** (10 Oktober 2026) menambah plugin baru dan perbaikan parsing; rilis sebelumnya v1.33.2 (Juli 2026) menambah plugin Biome dan Trash serta dukungan DMG terkompresi [S12]. Halaman rilis tidak memuat daftar versi macOS yang didukung; cek per versi.
- **Unified log macOS** bersifat terpadu untuk seluruh tingkat sistem [S3], dan aturan persistensinya per tingkat log kini terdokumentasi Apple: `debug` tidak disimpan ke disk, `info` hanya bila dikumpulkan dengan alat `log`, tingkat lain disimpan sampai batas penyimpanan [S13]. Selalu periksa rentang yang benar-benar tersedia sebelum menjanjikan jendela analisis kepada siapa pun.
- **Volatility 3** versi terbaru memberi peringatan deprecation untuk analisis macOS (Day 02 bagian 6); analisis memori Linux tetap didukung tetapi butuh symbol table kernel yang persis.
- **The Sleuth Kit 4.15.0** adalah rilis terbaru di halaman rilis proyek (15 April; tahun tidak tercantum di halaman); dukungan ext4 inline data ditambahkan sejak 4.10.2. Versi paket di repositori Ubuntu `jkt-dfir02` bisa lebih lama; catat versinya di inventaris.
- **Ketiadaan artefak setara Prefetch di Linux adalah batas struktural, bukan kekurangan alat.** Rekomendasi pasca kasus yang paling berguna untuk Linux biasanya bukan alat forensik, melainkan mengaktifkan auditd dengan aturan yang terarah dan mengirim lognya keluar host.

## 7. Cheat sheet

```
BEDA DARI WINDOWS   tidak ada registry (konfigurasi tersebar) | jejak eksekusi SANGAT terbatas
                    log: journald biner / syslog teks (Linux), unified log biner (macOS)
                    -> triage berpusat pada KEADAAN + PERSISTENSI + SIAPA MASUK, bukan riwayat

KOLEKSI   uac -p ir_triage <tujuan>     |  uac -p full -a '<artefak>' <tujuan>
          -H hash semua | -o nama | -f tar|zip | --case-number --evidence-number --examiner
          '!' di depan artefak = kecualikan | -u = tanpa root (koleksi terbatas)
          TULIS KE NFS / MEDIA LAIN; temp dir default di dalam tujuan
          PT JAB: ssh dari jkt-bastion01 -> blok volatil (toolkit) -> [AVML] -> UAC -> umount -> sha256 di jkt-evid01
          UAC: AIX/ESXi/FreeBSD/Linux/macOS/NetBSD/NetScaler/OpenBSD/Solaris; cuma butuh shell

IMAGE     ewfmount x.E01 /mnt/raw ; mmls ; mount -o ro,noload,noexec,nodev,offset=$((sektor*512))
          cek /etc/hostname, os-release, timezone, fstab (relatime/noatime) SEBELUM menafsir waktu

LINUX     auth: /var/log/auth.log | secure | journald (Debian 12: sering journal saja)
          zgrep "svc from" auth.log* | uniq -c   -> metode x IP; lalu lihat waktu + PID sshd
          journalctl -D <dir> --list-boots | TZ=<zona> journalctl -D <dir> _COMM=sshd -o short-iso-precise
          sesi: utmp (berjalan) wtmp (riwayat) btmp (gagal) lastlog   -> TZ=<zona> last -F -f <berkas>
          auditd: rules dulu! ausearch -if <dir> -i -m USER_LOGIN|USER_CMD|EXECVE (-ts format locale)
          PERSISTENSI urut: unit systemd -> timer+cron (/etc/cron.d sering lewat; spool user) -> authorized_keys
                            -> rc/bashrc/profile.d -> /etc/ld.so.preload -> akun UID 0 / sudoers
          cron: isi = spool (atau E04) | jalan = syslog CRON CMD | pasang/hapus = crontab REPLACE/DELETE
          awk -F: '$3 == 0 {print}' /etc/passwd     (cari akun setara root)
          waktu file: fls -r -m / | mactime -d -z <zona> | istat (crtime, ns)
          atime + relatime: update bila atime<=mtime/ctime atau >1 hari -> akses PERTAMA saja, tanpa akun
          tmpfs (/run /dev/shm) HILANG saat reboot -> kumpulkan saat hidup

MACOS     log collect --output x.logarchive --last 7d  |  log show --archive x --predicate '...' --style ndjson
          debug: tidak ke disk | info: hanya via log collect | default/error/fault: sampai batas ukuran
          launchd: /Library/LaunchDaemons | /Library/LaunchAgents | ~/Library/LaunchAgents | PrivilegedHelperTools
          RunAtLoad + KeepAlive = pola persistensi
          plutil -convert xml1 -o -  (plist biner)
          xattr -p com.apple.quarantine  (asal unduhan; ketiadaan != bukti dihapus)
          lain: TCC (izin privasi) | FSEvents (per direktori) | KnowledgeC/Biome | Spotlight | zsh_history
          izin: Full Disk Access untuk Terminal via PPPC (SystemPolicyAllFiles), JANGAN matikan SIP
          FileVault: jangan matikan laptop | log show hanya di macOS | parse lain: mac_apt

JEBAKAN   zona waktu: log teks sering lokal tanpa zona/tahun; last/journalctl/ausearch/mactime pakai zona workstation
          bash_history: ditulis saat shell keluar, mudah dikosongkan, biasanya tanpa timestamp
          jejak responder/pemulihan (crontab -r, rotasi rahasia, tar /var/log) != bantahan
          "tidak ada" -> cek dulu apakah pencatatnya dikonfigurasi

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "`ausearch -m EXECVE` atas audit.log E17 mengembalikan `<no matches>`, padahal auditd jelas aktif karena login tercatat. Berarti penyerang menghapus event eksekusi dari audit.log." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Event login, sudo, dan autentikasi dikirim PAM dan sudo ke subsistem audit tanpa perlu aturan, sehingga tercatat walau auditd hanya memakai aturan bawaan. Event `EXECVE` hanya muncul bila ada aturan syscall `execve`, dan berkas `audit.rules` di E17 tidak memuat aturan seperti itu. Hasil kosong adalah celah visibilitas yang sudah ada sebelum insiden, bukan penghapusan; lagi pula `svc_billing` tidak punya hak menulis audit.log. Langkah pertama untuk setiap "tidak ada" adalah membaca konfigurasi pencatatnya. Lihat bagian 1.5 dan 2.3.

</details>

**2. Skenario keputusan.** Retainer menulis implant membaca `/opt/billing/conf/app.env` pukul 02:44. Di E17, atime berkas itu Selasa 16:06:02 dan mtime 16:05:40. Apa yang kamu tulis di memo?

- A. "Disk membantah retainer: berkas tidak dibaca pukul 02:44."
- B. "Waktu berkas tertimpa rotasi kredensial `billing_app` sekitar 16:05 dan restart aplikasi; pembacaan 02:44 tidak dapat ditentukan dari disk dan bersandar pada analisis memori E05."
- C. "Pakai mtime 16:05:40 sebagai waktu pembacaan oleh penyerang."

<details><summary>Jawaban</summary>

B. Tim aplikasi menulis ulang `app.env` saat rotasi dan aplikasi membacanya saat restart, sehingga atime dan mtime kini menunjuk tindakan pemulihan yang sah. Dengan `relatime`, atime hanya menyimpan satu akses dalam kondisi tertentu, jadi akses 02:44 yang lebih tua sudah tertimpa. A keliru karena ketiadaan jejak di disk bukan bukti tidak terjadi; penyebabnya jelas tercatat. C keliru karena mtime adalah waktu penulisan oleh tim aplikasi, bukan pembacaan oleh siapa pun. Lihat bagian 1.5 dan 2.5.

</details>

**3. Pertanyaan jebakan.** "Di E17, `/var/spool/cron/crontabs/` kosong. Jadi klaim retainer bahwa persistensinya crontab `svc_billing` tidak terbukti." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Crontab itu dihapus Yoga saat containment Selasa 16:04:12, setelah isinya disalin ke E04 pukul 13:53. Penghapusan tercatat di syslog (`DELETE` oleh root), di audit `USER_CMD` dengan akun dan terminal Yoga, dan di case notes; mtime direktori spool juga 16:04:12. Pemasangannya tercatat sebagai `REPLACE` pukul 02:19:40 dan 165 eksekusi `CMD` dari 02:20:01 sampai 16:00:01. Isi jadwal hanya ada di E04 karena inode berkasnya sudah dipakai ulang. Lihat bagian 1.4 dan 2.4.

</details>

**4. Skenario keputusan.** Saat menjalankan UAC di MacBook `JKT-MB-03`, `uac.log` penuh galat izin untuk basis data TCC dan sebagian `~/Library`, padahal UAC dijalankan dengan `sudo`. Apa langkah yang tepat?

- A. Reboot ke recovery dan matikan SIP supaya root bisa membaca semuanya.
- B. Hentikan, pastikan perangkat sudah dimasukkan ke grup `IR-Triage-Mac` dan profil PPPC Full Disk Access untuk Terminal terpasang menurut Intune, lalu jalankan ulang dan catat kedua percobaan.
- C. Jalankan ulang dengan opsi `-u` supaya UAC tidak memeriksa root.

<details><summary>Jawaban</summary>

B. Di macOS, akses ke data terlindung TCC diberikan per aplikasi lewat Full Disk Access, bukan lewat root; PT JAB memberikannya ke Terminal lewat profil PPPC hanya selama koleksi. A keliru karena SIP tidak mengatur TCC, dan reboot ke recovery menghapus keadaan hidup, mengubah host, serta mengunci disk FileVault. C keliru karena `-u` justru melewati pemeriksaan root dan membuat koleksi lebih terbatas. Lihat bagian 1.8 dan 2.9.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Wahyu Nugroho (Lead Aplikasi Billing), dalam tiga kalimat, kenapa prosedur baru meminta aturan auditd `execve` untuk akun `svc_billing` di `jkt-billing02`, padahal server itu sudah punya Defender for Endpoint.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Di insiden Oktober, kita bisa membuktikan sendiri siapa masuk dan bagaimana penyerang bertahan, tetapi tidak bisa membuktikan dari server apakah `psql` dipakai untuk mengambil data pelanggan, karena auditd di `jkt-billing01` tidak mencatat program yang dijalankan dan kita harus bergantung pada analisis memori retainer. Aturan `execve` untuk akun aplikasi mencatat setiap program yang dijalankan akun itu beserta argumen dan waktunya, langsung di server dan di Splunk, dengan beban yang kecil karena akun itu jarang menjalankan program lain. Defender tetap kita pakai, tetapi data mentahnya punya umur dan hanya ada selama sensornya sehat, jadi audit lokal menjadi lapis kedua yang tetap ada saat kita butuh memverifikasi."

Kesalahan yang sering muncul:
- Menjelaskan auditd dengan istilah syscall tanpa menyebut pertanyaan bisnis yang tidak bisa dijawab Oktober lalu.
- Mengusulkan aturan `execve` untuk semua akun tanpa membahas beban dan volume log.
- Menyiratkan bahwa Defender tidak berguna.

</details>

**6. Pertanyaan jebakan.** "Atime `/var/tmp/.font-unix/kworkerd` di E17 sama persis dengan waktu pembuatannya, jadi terbukti dengan keyakinan tinggi bahwa salinan kedua itu tidak pernah dijalankan." Benarkah?

<details><summary>Jawaban</summary>

Tidak sepenuhnya. Dengan `relatime`, akses pertama ke berkas yang atime-nya tidak lebih baru dari mtime atau ctime pasti memperbarui atime, sehingga atime yang tidak berubah memang mendukung bahwa berkas itu tidak dibaca atau dijalankan setelah ditulis. Tetapi kesimpulan itu bergantung pada opsi mount (berlaku untuk `relatime`, tidak untuk `noatime`) dan pada tidak adanya akses lewat jalur yang tidak memperbarui atime, sehingga keyakinan internalnya sedang. Yang berkeyakinan tinggi adalah keberadaan berkas, waktunya, dan kesamaan hash dengan E06. Lihat bagian 1.5 dan 2.5.

</details>

**7. Interview question (English).** "You get SSH access to a compromised Linux server that has no EDR and cannot be shut down yet. What do you collect, in what order, and how do you avoid destroying evidence?"

<details><summary>Sample answer</summary>

"I connect from a bastion with a named admin account and agree a time box and containment triggers with the incident commander first, because the attacker may see my session. I record the system clock and NTP offset, then capture volatile state with trusted static binaries from a read-only share: network connections with owning processes, the process tree with start times, logged-in users, and the kernel lockdown state. If memory matters and lockdown allows it, I take memory with AVML straight to an NFS export, never to the local disk. Then I run a standard collector such as UAC with a triage profile and file hashing, writing its output and temp directory to the same export, so the result is consistent across servers. Before anyone contains the host, I make sure persistence like crontabs and unit files is captured, because containment often deletes it. Afterwards I hash everything on the evidence server and log every command I ran, since my own logins, sudo calls, and reads change logs and access times."

What makes this answer strong: it follows order of volatility, keeps tools and output off the suspect disk, uses a repeatable collector, anticipates that containment destroys persistence evidence, and treats the responder's own footprint as something to document rather than ignore.

</details>

## 9. Sumber

| # | Judul | URL | Tipe | Tanggal / diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | UAC (Unix-like Artifacts Collector), README repo resmi | https://github.com/tclahr/uac | primer | dilihat 2026-10-09; diakses ulang 2026-10-22 | Tinggi. Sistem yang didukung, opsi `-p` dan `-a`, contoh `avml.yaml` dan pengecualian `!`, isi koleksi (proses tanpa biner di disk, hash, bodyfile, memori Linux), urutan volatilitas, profil YAML, lisensi Apache 2.0; nomor versi tidak tercantum di README |
| S2 | journalctl(1), manual systemd | https://man7.org/linux/man-pages/man1/journalctl.1.html | primer | dirujuk 2026-10-09; diakses ulang 2026-10-22 | Tinggi untuk `--file`, `-D/--directory`, `--root`, `--image`, `--utc`, `--list-boots`, `--header`, format `short-iso-precise` dan `json` |
| S3 | Apple Developer: Logging (unified logging system) | https://developer.apple.com/documentation/os/logging | primer | dirujuk 2026-10-09; diakses ulang 2026-10-22 | Sedang-tinggi. Penyimpanan terpusat di memori dan disk, pengganti ASL dan syslog, dibaca dengan Console dan alat `log`; tidak merinci opsi baris perintah |
| S4 | auditd(8), manual | https://man7.org/linux/man-pages/man8/auditd.8.html | primer | dirujuk 2026-10-09 | Tinggi untuk peran auditd dan keberadaannya yang bergantung konfigurasi |
| S5 | mac_apt (macOS Artifact Parsing Tool) | https://github.com/ydkhatri/mac_apt | primer | dirujuk 2026-10-09 | Sedang-tinggi. Alat pengurai artefak macOS; modul dan format input perlu dicek per versi |
| S6 | ld.so(8) dan crontab (manual) | https://man7.org/linux/man-pages/man8/ld.so.8.html | primer | dirujuk 2026-10-09 | Tinggi untuk perilaku pemuat dinamis, termasuk berkas preload |
| S7 | Endpoint-Forensics-note Day 02, 05, 13, 20, 22 | (lokal) | rujukan internal | 2026-10-22 | Keterkaitan antar Day |
| S8 | GitHub: tclahr/uac Releases | https://github.com/tclahr/uac/releases | primer (repo resmi) | uac-3.4.0 2026-09-09, uac-3.3.0 April 2026; diakses 2026-10-22 | Tinggi. Isi rilis 3.4.0: artefak alat pengembangan AI, `PrivilegedHelperTools` macOS, Docker macOS, `ps` macOS, AVML v0.20.0 |
| S9 | UAC Documentation (uac-docs) | https://tclahr.github.io/uac-docs/ | primer (dokumentasi proyek) | diakses 2026-10-22 | Tinggi. Opsi `-p`, `-a`, `-o`, `-f`, `-P`, `-c`, `-m`, `-s`, `-H`, `-u`, `--temp-dir`, `--start-date`, `--case-number` dan lainnya; nama output default; catatan Full Disk Access sejak macOS 10.14. Halaman profil tidak mendaftar isi profil bawaan |
| S10 | journald.conf(5), manual systemd | https://man7.org/linux/man-pages/man5/journald.conf.5.html | primer | diakses 2026-10-22 | Tinggi. Nilai `Storage=` dan default `persistent` di versi yang dibaca, `SystemMaxUse=` 10 persen batas 4G, `MaxRetentionSec=` 0, `ForwardToSyslog=` mati bawaan. Default distribusi bisa berbeda |
| S11 | ausearch(8), manual | https://man7.org/linux/man-pages/man8/ausearch.8.html | primer | diakses 2026-10-22 | Tinggi. `-if`, `-i`, `-m`, `-ts/-te` (format mengikuti locale), `-k`, `-ui/-ua`, `-x`, `-sc`, `--format csv` |
| S12 | GitHub: ydkhatri/mac_apt Releases | https://github.com/ydkhatri/mac_apt/releases | primer (repo resmi) | v1.36.2 2026-10-10; diakses 2026-10-22 | Tinggi untuk versi dan isi rilis; tidak memuat daftar versi macOS yang didukung |
| S13 | Apple Developer: Generating log messages from your code | https://developer.apple.com/documentation/os/generating-log-messages-from-your-code | primer | diakses 2026-10-22 | Tinggi. Tabel persistensi per tingkat (debug tidak, info hanya lewat alat `log`, default/error/fault sampai batas penyimpanan), penghapusan saat melebihi ukuran, sensor nilai dinamis |
| S14 | SS64: log (macOS) | https://ss64.com/mac/log.html | sekunder (referensi komunitas) | diakses 2026-10-22 | Sedang. Sintaks `log collect`, `log show` (`--archive`, `--predicate`, `--style ndjson`, `--info`, `--debug`, `--timezone`), `log stats`, `log config`; bukan halaman Apple, cocokkan dengan `man log` |
| S15 | Apple Support: About System Integrity Protection on your Mac | https://support.apple.com/en-us/102149 | primer | diakses 2026-10-22 | Tinggi. Lokasi yang dilindungi (`/System`, `/usr`, `/bin`, `/sbin`, `/var`, aplikasi bawaan), lokasi yang tetap bisa ditulis, pembatasan root |
| S16 | Apple Platform Deployment: Privacy Preferences Policy Control payload settings | https://support.apple.com/guide/deployment/privacy-preferences-policy-control-payload-dep38df53c2a/web | primer | diakses 2026-10-22 | Tinggi. Khusus macOS, butuh supervisi bila lewat layanan manajemen, identifier dan tipe, code requirement dari `codesign -dr -`, layanan `SystemPolicyAllFiles`. Halaman tidak memakai istilah "Full Disk Access" |
| S17 | utmp(5), manual | https://man7.org/linux/man-pages/man5/utmp.5.html | primer | diakses 2026-10-22 | Tinggi. `utmp` sesi berjalan, `wtmp` riwayat login, logout, shutdown, reboot, dan perubahan jam; wtmp tidak dibuat ulang otomatis bila dihapus; field `ut_type`, `ut_line`, `ut_host`, `ut_tv`, `ut_addr_v6`. btmp tidak dibahas di halaman ini |
| S18 | SANS ISC Diary: Improving Bash Forensics Capabilities (Xavier Mertens) | https://isc.sans.edu/diary/Improving+Bash+Forensics+Capabilities/20887/ | komunitas (SANS ISC) | 2016-03-28; diakses 2026-10-22 | Sedang-tinggi. Riwayat ditulis saat shell berakhir, `HISTTIMEFORMAT` menambah baris epoch berawalan `#`, `histappend`, dukungan syslog sejak Bash 4.1 yang umumnya tidak aktif. Sumber lama tetapi perilakunya stabil |
| S19 | Debian 12 (bookworm) Release Notes, bagian 5.1.7 Changes to system logging | https://www.debian.org/releases/oldstable/amd64/release-notes/ch-information.en.html | primer | diakses 2026-10-22 | Tinggi. rsyslog tidak lagi terpasang bawaan; journal mungkin tidak persisten pada sistem hasil upgrade |
| S20 | mount(8), manual | https://man7.org/linux/man-pages/man8/mount.8.html | primer | diakses 2026-10-22 | Tinggi. Semantik `relatime` (default sejak Linux 2.6.30), `noatime`, `strictatime`; peringatan replay journal ext3/ext4 pada mount `ro` dan saran `ro,noload` |

**Catatan sumber:** opsi baris perintah `log collect` dan `log show` di bagian 2.9 berasal dari referensi komunitas [S14], bukan dari halaman Apple yang merincinya, karena halaman Apple yang dibuka [S3][S13] tidak memuat manual alat `log`; cocokkan dengan `man log` di versi macOS yang kamu periksa. Perilaku persistensi per tingkat log yang dulu dicatat sebagai pengetahuan komunitas kini dikonfirmasi dokumentasi Apple [S13]. Format baris log cron (`CMD`, `REPLACE`, `LIST`, `DELETE`), baris sudo `COMMAND=list`, tidak tercatatnya sesi SSH tanpa terminal di wtmp, nama unit SSH per distribusi, dan isi berkas aturan audit bawaan Ubuntu ditulis dari praktik umum dan tidak dikutip dari halaman resmi; buktikan di lab dengan paket yang sama sebelum dipakai sebagai argumen di laporan. Nama berkas log autentikasi Linux berbeda antar distribusi, dan daftar di bagian 1.2 adalah yang paling umum, bukan daftar lengkap. Lokasi dan nama artefak macOS seperti TCC, FSEvents, KnowledgeC, Biome, dan login items berubah antar versi sistem, jadi verifikasi di versi yang kamu hadapi. Semua isi PT JAB, termasuk waktu, PID, nomor inode, hash, jumlah baris log, hasil uji di `jkt-billing02`, nama profil Intune, dan nama prosedur, adalah contoh fiktif yang disusun agar konsisten dengan fakta insiden, bukan kejadian nyata.
