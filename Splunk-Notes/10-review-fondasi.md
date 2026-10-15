---
day: 10
title: 'Review fondasi: Day 01-09, tiga benang, glosarium, dan lab gabungan satu shift malam'
researched_on: 2026-10-15
versions_checked: 'Merangkum Day 01-09; Splunk Enterprise 10.6 (rilis 2026-09-30); Enterprise Security 8.7.0; CIM 6.4 sebagai acuan catatan dan app CIM 8.7.0 di Splunkbase; Splunk Add-on for Microsoft Windows 11.0.3; Splunk Add-on for Sysmon 5.0.1; BOTS v1'
---

# Day 10: Review fondasi analyst, dari index sampai alert yang dirawat

Cakupan: ringkasan Day 01-09 (cara Splunk menyimpan dan mencari data, SPL inti, log Windows, Sysmon dan PowerShell, jaringan, Linux dan identitas cloud, alur triage L1, chart dan timechart, report dan alert), peta konsep berupa tiga benang yang ditelusuri lewat tiket SOC-2026-0217, glosarium, dan lab gabungan yang mengerjakan ulang satu alert dari data mentah sampai alert pengganti yang dirawat.

## Ide inti

Day 01-09 membangun tiga lapis yang dipakai setiap shift. Lapis pertama adalah cara mencari: index, sourcetype, rentang waktu, search mode, lalu pipeline SPL yang mengubah event menjadi angka (Day 01-02). Lapis kedua adalah arti log: siapa, di mana, lewat cara apa, dan hasilnya apa, di Windows, Sysmon dan PowerShell, perangkat jaringan, Linux, dan tenant cloud (Day 03-06). Lapis ketiga adalah apa yang dilakukan dengan hasilnya: disposisi dan eskalasi, grafik yang jujur, dan pemeriksaan berulang yang dijadikan report atau alert (Day 07-09). Fondasinya sudah kokoh bila dari satu alert kamu bisa menjawab tiga pertanyaan tanpa menebak: apakah datanya ada dan lengkap, akun dan host mana yang sebenarnya terlibat, dan angka mana yang bisa diulang orang lain dengan hasil yang sama. Tiga pertanyaan itu muncul di setiap Day dengan bentuk berbeda, dan review ini menyebutnya tiga benang.

Analoginya tetap malam pertama memegang NOC sendirian. Sebelum menyimpulkan link pelanggan mati, kamu memastikan polling-nya masih jalan, karena grafik yang rata bisa berarti polling berhenti, bukan trafik tenang. Kamu membaca log di folder perangkat yang benar dengan template parsing yang cocok, dan kamu ingat bahwa jam di baris log bisa berbeda dari jam baris itu sampai di kolektor. Kamu menyusun rekap dengan pipe di shell, menutup tiket dengan kode penyelesaian yang benar, lalu memasang alarm dengan dampening supaya satu perangkat flapping tidak membanjiri layar. Batas analoginya ada dua, dan keduanya dibahas di Day asalnya: di SOC ketidakpastian adalah alasan eskalasi yang sah (Day 07), dan alert Splunk tidak menahan apa pun secara otomatis sehingga throttle harus dipasang sendiri (Day 09).

```
LAPIS 1  cara mencari       Day 01 index, sourcetype, _time/_indextime, time modifier, mode, job
                            Day 02 pipeline, search vs where, stats, batas bawaan, fillnull
LAPIS 2  arti log           Day 03 Windows Security   Day 04 Sysmon + PowerShell
                            Day 05 firewall, proxy, DNS, VPN   Day 06 Linux, Entra ID, M365
LAPIS 3  apa yang dilakukan Day 07 triage, disposisi, eskalasi, note, handover
                            Day 08 chart, timechart, span, batas 10 seri, single value
                            Day 09 report, alert, throttle, alert action, permission, dashboard
Tiga benang yang lewat di semua lapis: DATA (ada dan lengkap?) | IDENTITAS (akun mana?) | ANGKA (bisa diulang?)
```

Situasi yang dipakai di Day ini: mulai minggu depan kamu memegang shift malam L1 di PT Jaringan Anak Bangsa (PT JAB, ISP menengah fiktif) tanpa pendamping. Sebelum itu, SOC lead meninggalkan pesan di channel SOC:

> "Ambil SOC-2026-0217, brute force VPN dari 203.0.113.45 minggu lalu, dan kerjakan ulang dari nol seolah alert-nya baru masuk jam dua pagi. Buktikan datanya lengkap, tulis angka yang bisa saya ulang, tentukan disposisi dan eskalasinya, cek apa yang dilakukan akun itu setelah masuk, lalu buat alert penggantinya yang tidak membanjiri shift. Kalau ada titik yang kamu ragu, tulis. Lebih baik ketahuan sekarang daripada jam dua pagi."

Pesan itu bisa dipecah menjadi enam pertanyaan, mengikuti urutan Day:

1. Apakah data yang dibutuhkan ada, dan kenapa hasil nol belum berarti kejadiannya tidak ada? (Day 01)
2. Bagaimana meringkas event menjadi angka tanpa ada yang terpotong diam-diam? (Day 02)
3. Setelah login VPN sukses, akun dan host mana yang benar-benar terlibat, dan log mana yang menjawabnya? (Day 03-06)
4. Disposisi apa, kapan eskalasi, dan apa yang ditulis di note serta handover? (Day 07)
5. Bagaimana menunjukkan bentuk kejadian di rapat pagi tanpa salah angka? (Day 08)
6. Bagaimana pemeriksaan ini dijadikan alert yang jalan sendiri, tidak membanjiri shift, dan tidak mati saat pembuatnya pindah? (Day 09)

Ringkasan per Day ada di bagian 1.1 sampai 1.9. Bagian 1.10 menelusuri keenam pertanyaan itu sebagai tiga benang dengan artefak PT JAB dari Day 01-09, dan bagian 1.11 berisi glosarium. Lab di bagian 2-4 memintamu mengerjakan ulang SOC-2026-0217 dan satu latihan di dataset BOTS v1.

Day 11-14 berikutnya memperdalam SPL: `rex` dan `eval`, `foreach` dan `lookup`, `transaction`, lalu search yang efisien. Semuanya mengandaikan tiga benang di sini sudah menjadi kebiasaan.

**Kapan relevan:** sebelum memegang antrean alert sendirian, sebelum masuk SPL lanjutan dan knowledge object, dan sebelum interview untuk posisi SOC L1.
**Kapan bukan jawaban:** review ini tidak menambah perilaku produk atau field baru. Bila ada yang terasa baru atau kabur, kembali ke Day asal yang disebut di setiap butir.

## 1. Ringkasan, peta konsep, dan glosarium

### 1.1 Day 01: cara Splunk menyimpan dan mencari data

- Yang disimpan untuk setiap event adalah `_raw` ditambah label dari ingest; hampir semua field lain dihitung saat search jalan. Hasil search ditentukan empat keputusan: index, sourcetype, rentang waktu, dan search mode (Day 01 bagian 1.1).
- Index adalah tempat simpan sekaligus batas hak akses dan retensi. Event yang dirutekan ke index yang belum dibuat dibuang indexer, dan search tanpa `index=` mengikuti daftar index default role, sehingga dua analyst bisa mendapat jumlah berbeda [S5].
- Sourcetype menentukan pemecahan event, pembacaan timestamp, dan field. Source adalah nama file, stream, atau input asal event, bukan formatnya (Day 01 bagian 1.3).
- `_time` adalah waktu kejadian menurut isi event, `_indextime` waktu event selesai disimpan, dan `_indextime` tersembunyi sampai dipakai di `eval`. Rentang search menyaring menurut `_time`, jadi event yang belum tersimpan tidak muncul walau `_time`-nya sudah lewat. Tiket SOC-2026-0198 adalah contohnya: kejadian 23.40.12, masuk Splunk 00.12.40, lag 1.948 detik (Day 01 bagian 1.4 dan 2.3).
- `earliest` dan `latest` di dalam search menimpa time picker. Format absolutnya `%m/%d/%Y:%H:%M:%S`, snap-to selalu membulatkan ke belakang, dan kemarin penuh ditulis `-1d@d` sampai `@d` [S1]. Rentang berbasis kalender seperti `@d` mengikuti zona waktu user (Day 01 bagian 1.4).
- Dataset statis seperti BOTS v1 (dibuat 2016, index `botsv1`) wajib memakai rentang absolut yang ditentukan lebih dulu, misalnya lewat `earliest=0` [S6].
- Mode Fast mematikan field discovery (Day 01 bagian 1.6). Interesting Fields hanya memuat field yang muncul di minimal 20% event hasil search, dan nama field peka huruf besar-kecil sedangkan nilainya tidak [S2].
- Job hidup 10 menit secara default dan bisa diubah ke 7 hari [S3]. Membagikan tautan job memperpanjangnya menjadi 7 hari dan mengubah read permission menjadi Everyone, dan hasil job memakai kuota `srchDiskQuota` per role dengan bawaan 100MB [S4].

### 1.2 Day 02: SPL inti untuk triage

- SPL adalah pipeline. Begitu hasil melewati command transforming seperti `stats`, yang mengalir adalah baris tabel tanpa `_raw`. Saring dulu, ringkas kemudian, dan taruh `rename` serta `table` di akhir (Day 02 bagian 1.1).
- `where` mengevaluasi eval expression yang peka huruf besar-kecil; string berkutip dianggap nilai, string tanpa kutip dianggap nama field [S8]. Nilai di command `search` tidak peka huruf besar-kecil, dan operator `IN` di sana boleh memakai wildcard [S7].
- Fungsi `in()` di `eval` dan `where` tidak menerima wildcard, dan di `eval` harus dibungkus `if`, `case`, atau `validate` [S12].
- `NOT field=*` mengembalikan event yang field-nya null atau tidak ada, sedangkan `field!=*` tidak pernah mengembalikan apa pun; `!=` juga membuang event yang tidak punya field itu [S7].
- `count` menjawab berapa kejadian, `dc` menjawab berapa nilai unik. `values()` mengembalikan nilai distinct terurut leksikografis, sedangkan `list()` mengikuti urutan event dan hanya mengembalikan 100 nilai pertama [S11]. Hitung bersyarat ditulis `count(eval(<kondisi>))` (Day 02 bagian 1.3).
- Batas bawaan yang diam-diam memotong hasil: `sort` tanpa angka berhenti di 10000 hasil [S9], `top` dan `rare` mengembalikan 10 baris, dan `useother=true` pada `top` menambahkan baris `OTHER` untuk sisanya [S10]. `head` tanpa angka juga mengembalikan 10 (Day 02 bagian 1.5).
- `fillnull` tanpa daftar field mengisi semua field dengan `0`, dan Splunk tidak bisa membedakan field null dari field yang tidak ada di kumpulan hasil [S13]. "Tidak ada data" dan "nol kejadian" adalah dua hal berbeda (Day 02 bagian 1.7).
- Urutan baku sembilan langkah: saring, saring lagi, normalkan, ringkas, golongkan, isi lubang, urutkan, potong, sajikan (Day 02 bagian 1.8).

### 1.3 Day 03: log Windows Security

- Add-on Windows modern memakai sourcetype generik `XmlWinEventLog` atau `WinEventLog` dan memindahkan nama channel ke `source`, misalnya `source=XmlWinEventLog:Security` [S14]. BOTS v1 dibuat dengan add-on lama dan menyimpan event Security sebagai `sourcetype=WinEventLog:Security` [S6].
- Event yang tidak diaudit tidak pernah ada. 4688 butuh Audit Process Creation, dan field command line baru terisi setelah setelan Include command line in process creation events aktif [S19].
- 4624 dengan logon type: 2 interaktif, 3 jaringan, 4 batch, 5 service, 7 unlock, 8 cleartext, 9 NewCredentials, 10 RDP, 11 cached [S16]. Pada 4625, `Status` sering berisi kode umum `0xC000006D`, dan detailnya ada di `SubStatus`, misalnya `0xC000006A` password salah dan `0xC0000064` username tidak ada [S17].
- Banyak event memuat dua akun: Subject (yang meminta atau melaporkan) dan target. Di format klasik keduanya menjadi satu field multivalue `Account_Name`, sehingga perlu dipecah dengan `mvcount` dan `mvindex` (Day 03 bagian 1.5 dan 2.3).
- Logon ID menjahit satu sesi: `TargetLogonId` di 4624 sama dengan `SubjectLogonId` di 4672 dan 4688 (Day 03 bagian 1.6).
- Di 4728, 4732, dan 4756, pelaku ada di `SubjectUserName`, anggota di `MemberName` atau `MemberSid`, dan `TargetUserName` berisi nama grup. Untuk grup lokal `MemberName` biasanya `-`, jadi pakai `MemberSid` [S18].
- 4698 (task baru), 7045 (service baru, di log System), dan 1102 (Security log dihapus, diselidiki setiap kemunculannya) melengkapi gambaran persistence dan jejak (Day 03 bagian 1.8).

### 1.4 Day 04: Sysmon dan PowerShell

- Sysmon adalah service dan driver tambahan yang isinya ditentukan file konfigurasi. Event 3 mati secara default, event 10 bisa sangat besar volumenya sehingga dinyalakan dengan filter, dan event 22 tidak ada di Windows 7 dan sebelumnya [S20].
- Event Sysmon masuk sebagai `sourcetype=XmlWinEventLog` dengan `source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`; dataset dan artikel lama memakai nama sourcetype gaya lama (Day 04 bagian 1.2).
- `ProcessGuid` unik per proses dan tidak dipakai ulang, sedangkan PID dipakai ulang Windows [S20]. Process tree disusun dengan mencocokkan `ParentProcessGuid` ke `ProcessGuid`, dan `LogonId` di event 1 menjembatani ke sesi 4624 (Day 04 bagian 1.3).
- Event 3 adalah catatan "koneksi dibuat" tanpa byte dan durasi; `DestinationHostname` berasal dari reverse lookup, sedangkan nama yang benar-benar diminta ada di event 22 bersama proses peminta (Day 04 bagian 1.4 dan 1.7).
- `GrantedAccess` di event 10 adalah bitmask. Detection akses LSASS memeriksa bit `0x10` dan `0x1000`, sehingga `0x1010` dan `0x1410` sama-sama tertangkap [S21].
- 4104 menyimpan isi script block. Script panjang dipecah menjadi beberapa event yang diikat `ScriptBlockId`, dan sebagian script yang mirip pola berbahaya tetap dicatat walau script block logging mati [S22]. PowerShell 7 menulis ke channel `PowerShellCore/Operational` (Day 04 bagian 1.8).

### 1.5 Day 05: log jaringan

- Empat sumber menjawab empat pertanyaan: firewall (alamat, port, keputusan, byte), proxy (halaman dan user), DNS (nama yang dicari), VPN (identitas di balik alamat internal). Kuncinya alamat IP dan waktu (Day 05 Ide inti dan bagian 1.7).
- `action` punya nilai baku berbeda per data model: Network Traffic memakai `allowed`, `blocked`, `teardown` [S24], Authentication memakai `success` dan `failure` [S26]. Jalankan `stats count BY action` sebelum menulis kondisi.
- Arah `direction` relatif terhadap perangkat pencatat, dan untuk pertanyaan exfiltration angka yang dilihat adalah `bytes_out`, bukan `bytes` [S24]. Di lingkungan CGNAT satu alamat publik bisa mewakili ratusan pelanggan (Day 05 bagian 1.2).
- Trafik HTTPS lewat proxy hanya meninggalkan `CONNECT host:port` dan metadata; path dan parameter URL tidak terlihat (Day 05 bagian 1.3).
- DNS di CIM memisahkan `Query` dan `Response` lewat `message_type`, dan `reply_code` menerima nilai bergaya kalimat maupun singkatan vendor seperti `NXDomain` [S25]. Query log BIND tidak memuat kode jawaban, dan index yang disampling butuh rasio, bukan ambang absolut (Day 05 bagian 1.4 dan 1.5).
- Alamat di pool VPN dipinjamkan per sesi, sehingga pemetaan alamat ke akun selalu dibatasi rentang waktu (Day 05 bagian 1.6).
- Koneksi keluar tanpa query DNS sebelumnya punya tiga penjelasan: alamat ditulis langsung, nama ada di cache, atau klien memakai resolver lain (Day 05 bagian 1.7).

### 1.6 Day 06: log Linux dan identitas cloud

- Tiga jalur ingest berbeda: `linux_secure` dari file di host, sign-in Entra sebagai `azure:monitor:aad` lewat diagnostic settings dan event hub, audit M365 sebagai `o365:management:activity` lewat Management Activity API. Sign-in tidak ada di sourcetype M365 (Day 06 bagian 1.1).
- `linux_secure` ditulis banyak program (sshd, sudo, su, useradd); pisahkan dengan field `process`, dan ingat satu percobaan SSH bisa menulis beberapa baris (Day 06 bagian 1.2).
- `sudo` mencatat perintah yang diminta, dan secara bawaan mencatat yang diizinkan maupun yang ditolak [S29]. Setelah `sudo /bin/bash`, aktivitas di dalam shell root tidak menulis baris `sudo` lagi (Day 06 bagian 1.3).
- Di auditd, `uid` adalah identitas efektif dan bernilai 0 setelah `sudo`, sedangkan `auid` menyimpan akun yang login; contoh `ADD_USER` resmi memuat `uid` 0 bersama `AUID="ubuntu"` [S28].
- Di sign-in Entra, `ResultType` 0 berarti berhasil, dan `ConditionalAccessStatus` bernilai `success`, `failure`, atau `notApplied` [S30]. `notApplied` berarti tidak ada kebijakan yang dievaluasi, bukan diizinkan kebijakan (Day 06 bagian 1.6).
- `50140` dan `50158` adalah interupsi normal dalam alur sign-in, bukan tanda user gagal [S31]. Menghitung semua kode selain 0 sebagai kegagalan menggelembungkan angka (Day 06 bagian 2.6).
- Di M365, parameter inbox rule datang sebagai dua field multivalue sejajar yang dibaca dengan `mvfind` lalu `mvindex`; pada pemberian role, penerima ada di `ObjectId` dan pelaku di `Actor{}.ID` (Day 06 bagian 1.7). Data cloud datang dalam batch, sehingga detection resmi memeriksa `-70m` sampai `-10m` (Day 06 bagian 1.1).

### 1.7 Day 07: alur triage alert L1

- Triage adalah keputusan cepat berbasis bukti. Hasilnya tiga hal yang dipakai orang lain: disposisi, keputusan eskalasi, dan note yang bisa dibaca tanpa bertanya (Day 07 Ide inti).
- Lima pertanyaan pertama: siapa, apa, di mana, kapan, apakah wajar. Konfirmasi ke pengguna lewat kanal kedua, bukan lewat akun yang sedang diselidiki (Day 07 bagian 1.2).
- Enrichment memakai `lookup` (`OUTPUT` menimpa, `OUTPUTNEW` tidak) dan `iplocation`, yang tidak memberi lokasi untuk alamat privat (Day 07 bagian 1.3).
- Empat disposisi dasar: true positive, benign positive, false positive, undetermined. ES 8.7 menyediakan tujuh label, Undetermined adalah default, dan mengisi disposition tidak mengubah status finding [S32].
- Urgency di ES dihitung dari severity detection dan priority aset atau identitas, sehingga identitas yang tidak terdaftar bisa membuat finding penting tampil rendah [S33].
- Eskalasi punya tiga alasan: dampak, wewenang, dan ketidakpastian (Day 07 bagian 1.7).
- Note berisi yang dilihat, yang dicek dengan query dan rentang waktunya, kesimpulan dan keyakinan, langkah berikut, dan keterbatasan. Handover hanya merangkum kasus yang masih terbuka (Day 07 bagian 1.8).

### 1.8 Day 08: chart, timechart, dan visualisasi

- Visualisasi digambar di atas tabel hasil, jadi bentuk tabel hasil menentukan pilihan grafik (Day 08 bagian 1.1).
- `chart count OVER a BY b` memilih sumbu baris dan kolom, dengan satu klausa `BY` [S34]. `timechart` selalu memakai `_time` sebagai sumbu baris sehingga hanya menerima satu field pemecah [S35].
- Tanpa `span`, preset Last 7 days memakai bin satu hari dan Last 24 hours memakai 30 menit [S35]; lonjakan 14 menit hilang di bin harian.
- `chart` dan `timechart` menampilkan sepuluh seri secara default dan menyapu sisanya ke OTHER; event tanpa field pemecah menjadi NULL. `useother=f` tidak menaikkan batas, dan `WHERE max in top5` memilih seri menurut puncak, bukan total [S34].
- Single value dari `timechart` memperlihatkan hasil paling baru dengan sparkline dan trend indicator, sedangkan dari `stats` memperlihatkan total sepanjang rentang [S36].
- Grafik dipakai untuk menemukan jam yang tidak wajar; angka untuk tiket diambil dengan `stats` pada rentang absolut, karena batas bin bisa membelah satu burst (Day 08 bagian 1.7). Tiga dimensi termasuk waktu dikerjakan dengan `bin` lalu `stats` (Day 08 bagian 1.4).

### 1.9 Day 09: report, alert, throttle, dan dashboard

- Aksi report terjadwal berjalan setiap kali report jalan; aksi alert berjalan hanya bila kondisi trigger terpenuhi [S38].
- Pada `Run on Cron Schedule`, `Earliest` dan `Latest` menimpa rentang di dalam search [S37]. Jendela yang lebih panjang dari interval mengevaluasi event yang sama lebih dari sekali; jendela yang lebih pendek membuat ada event yang tidak pernah dievaluasi; beri delay minimal satu menit [S38].
- Trigger bisa sekali per jalan atau sekali per hasil. Custom condition berjalan sebagai search kedua, dan field yang tersedia untuk notifikasi berasal dari base search (Day 09 bagian 1.3).
- Throttle memakai field suppress dan periode, dan menyunting alert atau setelan throttle-nya membatalkan throttle yang sedang berjalan [S39].
- Webhook mengirim HTTP POST yang hanya memuat baris hasil pertama, ke URL yang harus ada di allow list [S40]. Log event action membuat riwayat alert bisa di-search; di PT JAB index-nya `soc_alerts` (Day 09 bagian 1.5 dan 2.5).
- Objek baru hanya terlihat oleh pembuatnya, dan objek milik user yang dihapus menjadi yatim sehingga report dan alert-nya berhenti jalan [S41]. Scheduled report berjalan sebagai pemiliknya (Day 09 bagian 1.6).
- Dashboard Studio memakai JSON dan visual editor, Classic memakai Simple XML; base search dan chain search membuat bagian berat search hanya jalan sekali, dan token waktu hanya bekerja di base search (Day 09 bagian 1.7 dan 1.8).

### 1.10 Peta konsep: tiga benang dan jejak SOC-2026-0217

Peta berikut menggabungkan sembilan Day dalam satu gambar. Pakai sebagai satu-satunya bantuan saat uji lisan di Bagian D lab.

```
                      ALERT MASUK  (scheduled alert / finding / laporan)
                                  |
 BENANG DATA        apakah datanya ada dan lengkap?
   cara mencari     index + role | sourcetype vs source | _time vs _indextime (lag)       Day 01
                    rentang absolut | search mode | Interesting Fields 20%                 Day 01
   cakupan sumber   audit policy (4688) | konfigurasi Sysmon | aturan auditd               Day 03-04, 06
                    kategori Entra yang dikirim | sampling DNS | logging per rule firewall  Day 05-06
                                  |
 BENANG IDENTITAS   akun dan host mana yang sebenarnya?
                    Subject vs target | Logon ID | ProcessGuid vs PID                     Day 03-04
                    pool VPN + waktu | CGNAT | user di proxy                               Day 05
                    uid vs auid | UPN vs nama pendek | ObjectId vs Actor{}.ID               Day 06
                                  |
 BENANG ANGKA       angka mana yang bisa diulang?
                    search vs where | count vs dc | top/sort/list/head memotong            Day 02
                    span + batas 10 seri + OTHER/NULL | single value                       Day 08
                    rentang absolut di dalam search, bukan time picker                     Day 01
                                  |
 KEPUTUSAN          5 pertanyaan -> enrichment -> disposisi -> eskalasi -> note -> handover Day 07
                                  |
 PERAWATAN          report / alert: jendela = interval + delay, trigger, throttle,          Day 09
                    alert action (log event), owner fungsional, permission app
                    dashboard: base search + chain search
                                  |
            alert baru membawa pertanyaan data, identitas, dan angka yang baru
```

Setiap benang punya satu kalimat kerja yang berulang di Day asalnya. Benang data: nol hasil adalah pernyataan tentang filter-mu, bukan tentang dunia (Day 01 bagian 5), dan event yang tidak diaudit, tidak dikonfigurasi, atau tidak dikirim tidak bisa ditemukan search apa pun (Day 03 bagian 1.2, Day 04 bagian 1.1, Day 06 bagian 1.4). Benang identitas: kolom akun pertama yang terlihat belum tentu pelakunya. Benang angka: angka yang masuk tiket berasal dari hasil penuh pada rentang absolut, dan pemotongan disebut terus terang (Day 02 bagian 2.7, Day 08 bagian 1.7).

Tabel berikut menjawab pesan SOC lead di Ide inti dengan artefak yang sudah ada di Day 07-09. Baca per baris; kolom terakhir menunjuk tempat langkah itu dikerjakan sungguhan.

| Pertanyaan | Bukti untuk SOC-2026-0217 | Benang | Day asal |
|---|---|---|---|
| Datanya lengkap? | Jalur `jkt-vpn01` pernah mencatat lag maksimum 2.051 detik, jadi pemeriksaan memakai rentang absolut 01:30 sampai 02:30, bukan 15 menit terakhir | Data | Day 01 bagian 2.2, Day 07 bagian 2.1 |
| Apa yang terjadi? | 181 percobaan dari 203.0.113.45 ke 25 akun: 180 gagal (lima akun 8 kali, dua puluh akun 7 kali) dan 1 sukses `rina.wulandari` pukul 02:04:13 | Angka | Day 07 bagian 2.1, Day 08 bagian 2.6 |
| Apakah wajar? | Dalam 30 hari Rina login dari dua IP Indonesia; 203.0.113.45 pertama terlihat 02:04:13 | Identitas | Day 07 bagian 2.2 |
| Konteks apa? | IP ada di feed internal sebagai bruteforce; pemilik akun juga memegang `adm.rina` | Identitas | Day 07 bagian 2.3 |
| Apa yang dilakukan setelah masuk? | Dari 10.10.250.17: logon type 3 ke `JKT-FS01` dua kali, lalu `adm.rina` logon type 10 ke `JKT-JUMP01` pukul 02:11:02 | Identitas | Day 07 bagian 2.4, arti logon type di Day 03 bagian 1.3 |
| Keputusan? | True Positive, keyakinan tinggi, eskalasi ke L2 on-call pukul 02:42 | Keputusan | Day 07 bagian 2.6 |
| Bentuk untuk rapat? | Bin 01:00 bernilai 104 dan bin 02:00 bernilai 84; dari 203.0.113.45 masing-masing 98 dan 82 | Angka | Day 08 bagian 2.1 dan 2.2 |
| Perawatan? | Alert dibuat ulang: `-20m@m` sampai `-5m@m`, cron `*/5 * * * *`, throttle pada `src` 60 menit, log event ke `soc_alerts` | Perawatan | Day 09 bagian 2.2 sampai 2.5 |

Dua hal terlihat dari tabel itu. Pertama, angka 104 dari grafik dan angka 180 di tiket sama-sama benar, tetapi hanya 180 yang mengukur serangan, karena serangan 01:52 sampai 02:06 menyeberangi batas jam. Kedua, rantainya punya satu titik yang belum tersambung, dan note Day 07 menuliskannya sendiri sebagai keterbatasan: aktivitas di `JKT-JUMP01` setelah 02:11 belum dicek. Cara menutupnya ada di Day 03 dan Day 04: ikuti Logon ID sesi `adm.rina` ke 4672 dan 4688, lalu ke process tree Sysmon lewat `LogonId`, setelah memastikan `JKT-JUMP01` memang mengirim event Sysmon yang dibutuhkan. Bagian A lab mengerjakan langkah itu.

Kasus lain di Day 01-09 menonjolkan benang yang berbeda. Tabel ini membantu memilih kasus mana yang dibaca ulang bila satu benang terasa lemah.

| Kasus | Day | Benang yang paling menonjol | Pelajarannya |
|---|---|---|---|
| SOC-2026-0198, event VPN 23.40 yang "tidak ada di Splunk" | Day 01 bagian 2.3 | Data | Lag 1.948 detik; event ada, hanya belum tersimpan saat dicari |
| Rekap shift malam: blok firewall, domain baru, kronologi unduhan `andi.pratama` | Day 02 bagian 2.3 sampai 2.7 | Angka | `dc` untuk jumlah host, `top` tanpa `useother` menyembunyikan sisa, `fillnull` hanya pada kolom yang disebut |
| Sesi `adm.rina` di `JKT-JUMP01`: `net group` ke Domain Admins, PowerShell terenkode, akses LSASS | Day 03 bagian 2.5 sampai 2.7, Day 04 bagian 2.9 | Identitas | Subject vs target, Logon ID, `ProcessGuid`, `GrantedAccess` dibaca per bit |
| Tiga laporan NOC: IP pelanggan "diblokir", lonjakan resolver, domain baru di `JKT-WS-0412` | Day 05 bagian 2.2 sampai 2.7 | Identitas dan angka | Bukti per `rule`, CGNAT, `CONNECT`, rasio pada index yang disampling, kronologi tiga sumber |
| SOC-2026-0244, `svc_radius` di `jkt-bastion01` dan BEC terhadap `fitri.handayani` | Day 06 bagian 2.9 | Identitas | `auid`, `notApplied`, IMAP4, `Actor{}.ID`, dua insiden terpisah walau datang bersamaan |
| SOC-2026-0219, uji failover RADIUS dengan change CHG-0912 | Day 07 bagian 2.7 | Keputusan | Benign Positive ditutup dengan nomor change sebagai bukti |

### 1.11 Glosarium

Definisi di bawah ditulis dengan kata sendiri untuk keperluan belajar, bukan definisi resmi. Kolom terakhir adalah pasangan yang paling sering membuat jawaban triage atau interview keliru.

| Istilah | Penjelasan singkat | Sering tertukar dengan |
|---|---|---|
| `_time` | Waktu kejadian menurut isi event, disimpan dalam UTC | `_indextime` |
| `_indextime` | Waktu event selesai disimpan; tersembunyi sampai dipakai di `eval` | `_time` |
| Index | Tempat simpan, batas hak akses, dan batas retensi | Sourcetype |
| Sourcetype | Format data yang menentukan pemecahan event, timestamp, dan field | Source |
| Source | Nama file, stream, atau input asal; di add-on Windows modern membawa nama channel | Sourcetype |
| Time modifier | `earliest` dan `latest` di dalam search, menimpa time picker | Time picker |
| Snap-to | Pembulatan rentang ke belakang ke batas satuan, misalnya `@d` | Rentang relatif "24 jam terakhir" |
| Interesting Fields | Field yang muncul di minimal 20% event hasil search | Semua field yang ada |
| Job lifetime | Masa simpan hasil search, bawaan 10 menit | Hasil search yang permanen |
| `where` | Penyaring eval expression, peka huruf, bisa membandingkan dua field | `search` |
| `NOT field=x` | Membuang yang cocok, tetap menyimpan event tanpa field itu | `field!=x` |
| `dc()` | Jumlah nilai unik | `count` |
| `list()` | Nilai mengikuti urutan event, maksimal 100 | `values()` |
| `top` | Nilai terbanyak, bawaan 10 baris | `stats` lalu `head` |
| Subject | Akun yang meminta atau melaporkan aksi | Akun target |
| Logon ID | Nomor sesi yang menjahit 4624, 4672, dan 4688 | `ProcessGuid` |
| `ProcessGuid` | Identitas proses yang unik dan tidak dipakai ulang | `ProcessId` |
| `GrantedAccess` | Bitmask hak akses antar proses | Satu nilai yang dicocokkan utuh |
| Script block (4104) | Isi script PowerShell, bisa terpecah menjadi beberapa event | Command line proses |
| `auid` | Akun yang login di sesi audit, tetap walau sudah `sudo` | `uid` |
| `notApplied` | Tidak ada kebijakan Conditional Access yang dievaluasi | Diizinkan kebijakan |
| `action` CIM | Network Traffic: `allowed`/`blocked`; Authentication: `success`/`failure` | Satu set nilai untuk semua data model |
| Benign Positive | Detection benar, aktivitas nyata tetapi sah dan diharapkan | False Positive |
| Disposition | Hasil penilaian finding | Status |
| Urgency | Prioritas finding dari severity dan priority aset atau identitas | Risk score entity |
| Seri OTHER | Nama seri buatan command untuk nilai di luar batas | Nilai field yang bisa di-drilldown |
| `span` | Lebar satu bin waktu | Interval perekaman data |
| Report | Search tersimpan yang aksinya jalan setiap kali jalan | Alert |
| Throttle | Penahan aksi alert per field suppress selama periode | Kondisi trigger |
| Objek yatim | Objek milik user yang dihapus; jadwalnya berhenti | Objek yang dinonaktifkan |

Untuk interview dan pekerjaan harian, parafrase di tabel ini sudah cukup. Perubahan nama produk dan istilah yang membuat dokumentasi lama memakai kata lain dicatat di bagian 6.

## 2-4. Lab gabungan dan troubleshooting

Lab ini memakai beberapa Day sekaligus. Bagian A mengerjakan ulang SOC-2026-0217 di data PT JAB sebagai latihan tertulis dengan keluaran ilustrasi dari Day 07-09; bila kamu memakai lab sendiri, ganti index, host, dan rentang waktunya dengan data lab-mu. Bagian B memakai dataset BOTS v1 dengan rentang waktu absolut. Bagian C berisi latihan skenario singkat, dan Bagian D uji lisan. Semua search dijalankan di instance Splunk lab terisolasi, bukan di mesin kerja.

### Bagian A: SOC-2026-0217 dari data mentah sampai alert pengganti

Asumsi PT JAB sama dengan Day 07 dan Day 09: log VPN di `index=vpn` dengan field gaya CIM Authentication (`user`, `src`, `action`), log Windows Security format XML di `index=wineventlog`, Sysmon di `index=sysmon`, pool VPN karyawan `10.10.250.0/24`, zona waktu akun WIB.

1. **Benang data: ukur lag sebelum percaya hasil nol (Day 01).** Jalankan pola Day 01 bagian 2.2 dengan rentang absolut malam kejadian:

   ```
   index=vpn earliest="10/14/2026:00:00:00" latest="10/14/2026:06:00:00"
   | eval lag_detik = _indextime - _time
   | stats count max(lag_detik) AS lag_maks perc95(lag_detik) AS lag_p95 BY sourcetype host
   | sort - lag_maks
   ```

   Catat `lag_maks` per host. Angka ini dipakai dua kali: untuk menentukan seberapa lebar rentang pemeriksaan di langkah 2, dan untuk menentukan delay alert di langkah 8. Bila ada lag negatif, curigai zona waktu saat ingest (Day 01 bagian 2.2).

2. **Benang angka: ringkas dengan rentang absolut (Day 02, 07, 08).** Jalankan versi `chart` dari Day 08 bagian 2.6:

   ```
   index=vpn src="203.0.113.45" earliest="10/14/2026:01:30:00" latest="10/14/2026:02:30:00"
   | chart count OVER user BY action usenull=f
   | addtotals fieldname=total
   | sort - total - success
   ```

   Sebelum membaca hasilnya, tulis dulu angka yang kamu harapkan dari tiket: 25 baris, kolom `failure` berjumlah 180 (lima akun 8 kali dan dua puluh akun 7 kali), kolom `success` berisi satu angka 1. Lalu jalankan `stats count BY action` sekali untuk memastikan nilai `action` memang `failure` dan `success`, bukan nilai mentah vendor (Day 05 bagian 1.1).

3. **Benang angka: bentuk tujuh hari tanpa salah baca (Day 08).** Jalankan dua search berikut dengan rentang absolut tujuh hari penuh:

   ```
   index=vpn action=failure earliest="10/08/2026:00:00:00" latest="10/15/2026:00:00:00"
   | timechart span=1h count AS gagal
   ```

   ```
   index=vpn action=failure earliest="10/08/2026:00:00:00" latest="10/15/2026:00:00:00"
   | timechart span=1h count BY src WHERE max in top5 usenull=f
   ```

   Pastikan kamu bisa menjelaskan kenapa tidak ada bin bernilai 180, kenapa kolom OTHER tetap dibiarkan, dan apa yang terjadi bila `WHERE max in top5` diganti `limit=5` (Day 08 bagian 2.1 dan 2.2). Lalu ulangi search pertama tanpa `span` dan catat lebar bin yang dipilih Splunk.

4. **Benang identitas: konteks dan baseline (Day 07).** Jalankan pola baseline 30 hari dan enrichment dari Day 07 bagian 2.2 dan 2.3. Tulis satu kalimat tentang fakta mana yang mengubah urgensi kasus, dan rujuk baris matriks eskalasi Day 07 bagian 1.7 yang berlaku.

5. **Benang identitas: dari alamat VPN ke sesi Windows (Day 03, 05, 07).** Pertama, pastikan alamat 10.10.250.17 memang dipegang sesi Rina pada jam itu dengan pola pemetaan pool VPN berbatas waktu (Day 05 bagian 2.7), karena alamat pool bisa berganti pemilik. Lalu cari logon Windows dari pool itu dengan field format XML:

   ```
   index=wineventlog source="XmlWinEventLog:Security" EventCode=4624 IpAddress="10.10.250.*"
       earliest="10/14/2026:02:04:00" latest="10/14/2026:02:40:00"
   | stats count min(_time) AS pertama values(LogonType) AS logon_type values(TargetLogonId) AS logon_id
           BY TargetUserName IpAddress host
   | eval pertama=strftime(pertama, "%F %T")
   ```

   Catat `TargetLogonId` untuk logon `adm.rina` ke `JKT-JUMP01`. `values(TargetLogonId)` bisa berisi lebih dari satu nilai bila akun admin membuat sesi berpasangan (Day 03 bagian 1.3). Lalu jalankan pola Day 03 bagian 2.5 untuk Logon ID itu, dengan host `JKT-JUMP01` dan rentang mulai 02:11, supaya 4672 dan 4688 dari sesi yang sama terkumpul dalam satu baris.

6. **Benang data lalu identitas: Sysmon di jump host (Day 04).** Jalankan inventaris Day 04 bagian 2.1 untuk `host=JKT-JUMP01` dan catat event ID mana yang ada. Bila event 1 ada, jalankan pola Day 04 bagian 2.3 dengan variasi filter `LogonId` untuk sesi dari langkah 5, setelah memeriksa format penulisan `LogonId` di data-mu. Bila event yang kamu butuhkan tidak ada, tulis itu sebagai keterbatasan, bukan sebagai "tidak ada aktivitas".

7. **Keputusan: disposisi, note, handover (Day 07).** Tulis note dengan lima bagian template Day 07 bagian 1.8. Setiap baris "yang dicek" harus memuat query, rentang absolut, dan angka dari langkah 1 sampai 6. Pilih disposisi beserta alasan satu kalimat, lalu tulis entri handover pukul 07:00 maksimal lima baris.

8. **Perawatan: alert pengganti (Day 09).** Simpan search Day 09 bagian 2.2 sebagai alert dengan `Earliest` `-20m@m`, `Latest` `-5m@m`, cron `*/5 * * * *`, trigger `For each result`, throttle pada `src` selama 60 menit, dan log event ke `soc_alerts`. Bandingkan delay 5 menit itu dengan `lag_maks` dari langkah 1, lalu tulis keputusanmu: delay cukup, atau jendelanya perlu digeser. Terakhir, hitung secara manual jalan alert mana saja yang jendelanya menyentuh serangan 01:52 sampai 02:06 tanpa throttle. Jendela setiap jalan pada waktu T adalah T-20 menit sampai T-5 menit, jadi jawabannya enam jalan, pukul 02:00 sampai 02:25. Dengan throttle pada `src`, notifikasi untuk 203.0.113.45 hanya terkirim sekali dalam 60 menit.

9. **Perawatan: serah terima objek (Day 09).** Pindahkan alert ke app SOC, atur `Display for` ke app itu, beri Read untuk L1 dan Write untuk detection engineer serta SOC lead, pindahkan kepemilikan ke akun fungsional tim, dan pastikan akun itu punya akses ke `index=vpn` (Day 09 bagian 2.7).

### Bagian B: latihan BOTS v1 dengan rentang absolut

BOTS v1 adalah dataset statis dari 2016 [S6], dan event Security-nya memakai format klasik dengan `sourcetype=WinEventLog:Security` (Day 03 bagian 1.1). Bagian ini menggabungkan Day 01, 02, 03, dan 08 pada data nyata.

1. **Tentukan rentang (Day 01).** Jalankan `| tstats min(_time) AS awal max(_time) AS akhir where index=botsv1 sourcetype="WinEventLog:Security" | eval awal=strftime(awal, "%F %T"), akhir=strftime(akhir, "%F %T")`. Day 03 menyebut datanya dari Agustus 2016 dan memakai contoh `earliest="08/01/2016:00:00:00" latest="09/01/2016:00:00:00"`; pakai rentang itu hanya setelah hasil `tstats` di lab-mu mengonfirmasinya, lalu tulis rentang yang terverifikasi di semua langkah berikut. Buktikan juga bahwa `earliest=-7d` mengembalikan nol hasil.
2. **Inventaris (Day 01, 03).** `index=botsv1 sourcetype="WinEventLog:Security" earliest=<awal> latest=<akhir> | stats count BY EventCode | sort - count`. Catat lima event ID terbanyak.
3. **Akun yang benar (Day 03, 02).** Pada 4625, pecah `Account_Name` dengan pola Day 03 bagian 2.3, lalu bandingkan `stats count BY Account_Name` dengan `stats count BY akun_target`. Tulis selisihnya dan akun mesin (`HOST$`) yang ikut terhitung di versi pertama.
4. **Bentuk lalu angka (Day 08).** Jalankan `timechart span=1h count BY akun_target WHERE max in top5` pada rentang terverifikasi, pilih satu jam yang menonjol, lalu ambil angka pastinya dengan `stats count BY akun_target` pada rentang absolut satu jam itu. Bila ternyata tidak ada 4625 dengan dua nilai `Account_Name`, catat itu sebagai temuan tentang dataset, bukan sebagai kegagalan lab.
5. **Serahkan hasil (Day 01, 09).** Simpan search langkah 4 sebagai report dengan rentang absolut di dalam SPL, lalu bagikan sebagai teks SPL, bukan tautan job, dan atur permission-nya ke app (Day 01 bagian 2.7, Day 09 bagian 1.6).

### Bagian C: latihan skenario singkat

Jawab dulu sebelum membaca pembahasan. Setiap skenario memakai lebih dari satu Day.

**Skenario A.** Shift sebelumnya menulis di tiket bahwa koneksi VPN pukul 23.40 "tidak ada di Splunk"; pagi ini event itu ada.
Pembahasan: benang data. Ukur lag dengan `_indextime - _time` dan cari event dengan rentang absolut yang lebih lebar. Di SOC-2026-0198 penyebabnya lag 1.948 detik (Day 01 bagian 2.3). Untuk alert di index yang sama, lag ini menentukan delay di jendela jadwal (Day 09 bagian 1.2).

**Skenario B.** Alert lama menghitung `stats count BY Account_Name` dan melaporkan `JKT-WS-0412$` sebagai salah satu akun yang paling sering gagal login.
Pembahasan: benang identitas. Di format klasik, Subject dan target sama-sama masuk `Account_Name`; akun mesin itu Subject yang melaporkan, bukan akun yang gagal (Day 03 bagian 2.3). Perbaiki dengan `mvindex`, atau pindah ke format XML dan `TargetUserName`. Bila alert itu disimpan ulang, perbaiki juga deskripsi dan pemiliknya (Day 09 bagian 2.7).

**Skenario C.** Alert "login Entra gagal" yang memfilter kode selain 0 membawa ribuan hasil setiap hari, dan rekan menyarankan menaikkan ambang.
Pembahasan: benang angka. Sebagian besar hasilnya bisa berupa `50140` dan `50158`, interupsi normal alur sign-in (Day 06 bagian 2.6). Yang diperbaiki adalah kode yang dihitung, bukan ambangnya. Bila alert itu tetap berisik setelah diperbaiki, disposisi yang tepat untuk logika yang salah adalah False Positive - Incorrect Analytic Logic dengan tiket tuning (Day 07 bagian 1.6).

**Skenario D.** Layar SOC menampilkan panel "Login gagal VPN 24 jam" bernilai 9 pada pagi setelah serangan.
Pembahasan: single value dari `timechart` memperlihatkan bin terbaru, bukan total (Day 08 bagian 2.5). Samakan judul dengan search-nya. Bila panel itu dibangun dari base search yang sudah diagregasi, ingat bahwa panel tren waktu butuh data source sendiri (Day 09 bagian 2.6).

**Skenario E.** Alert brute force VPN yang dulu rajin menyala tiba-tiba tidak pernah menyala lagi sejak pembuatnya pindah tim, padahal log VPN masih masuk.
Pembahasan: objek milik user yang dihapus menjadi yatim dan jadwalnya berhenti (Day 09 bagian 1.6). Pastikan juga ini bukan masalah data: jalankan inventaris index dan sourcetype (Day 01 bagian 2.1) dan cek nilai `action` (Day 05 bagian 1.1). Alert "tidak ada data" dengan `| stats count` dan kondisi `count=0` (Day 09 bagian 2.3) menjaga sisi data, bukan sisi kepemilikan.

**Skenario F.** Rekap handover menulis "hanya 10 host internal kena blok firewall malam ini" dari `| top src`.
Pembahasan: `top` mengembalikan 10 baris secara bawaan. Jumlah host diambil dengan `dc(src)`, sebaran dengan `stats count BY src`, dan tabel yang dipotong disebut terus terang (Day 02 bagian 2.4 dan 2.7).

### Bagian D: uji lisan lima menit

Rekam dirimu menjelaskan alur satu alert dari masuk sampai alert penggantinya dirawat, dalam lima menit, dengan peta konsep bagian 1.10 sebagai satu-satunya bantuan. Lalu jawab tiga pertanyaan tanpa catatan:

- "Kenapa hasil nol belum membuktikan apa pun?" (Day 01 bagian 1.4, Day 03 bagian 1.2, Day 04 bagian 1.1)
- "Di log mana kamu mencari siapa sebenarnya yang menjalankan aksi, dan field apa?" (Day 03 bagian 1.5, Day 06 bagian 1.4)
- "Kenapa angka di grafik tidak kamu salin ke tiket?" (Day 08 bagian 1.7)

Catat bagian yang membuatmu ragu; itu daftar yang perlu diulang sebelum masuk Day 11.

**Hasil yang sebaiknya tersimpan:**

- Tabel lag per host dari Bagian A langkah 1, dan keputusan delay alert yang memakainya.
- Tabel per akun SOC-2026-0217 yang jumlahnya cocok dengan hitungan manual (180 gagal, 1 sukses, 25 akun).
- Dua grafik tujuh hari (satu seri, dan per sumber dengan `WHERE max in top5`) beserta satu kalimat kenapa tidak ada bin bernilai 180.
- Note tiket lima bagian dan entri handover, dengan keterbatasan yang tertulis eksplisit.
- Hasil penelusuran Logon ID dan process tree `JKT-JUMP01`, atau catatan bahwa event yang dibutuhkan tidak tersedia.
- Setelan alert pengganti (jendela, cron, trigger, throttle, alert action, pemilik, permission) dan hitungan enam jalan yang menyentuh serangan.
- Rentang absolut BOTS v1 yang terverifikasi dan perbandingan `Account_Name` sebelum dan sesudah dipecah.
- Jawaban tertulis untuk skenario A sampai F, lalu catatan Day mana yang jawabanmu paling banyak meleset.

### Troubleshooting lintas Day

Tabel ini memetakan gejala yang sering muncul di lab ke Day yang perlu diulang. Mulai dari gejala yang paling mirip dengan kesulitanmu.

| Gejala | Day yang perlu diulang | Pemeriksaan |
|---|---|---|
| Search nol hasil padahal kejadiannya pasti ada | 01 | Rentang dibanding lag, `index=` disebut, role boleh mencari index itu, sourcetype dan nama field cocok |
| Search Windows dari contoh lama selalu kosong | 01, 03 | Sourcetype generik dan nama channel di `source`; BOTS v1 memakai `WinEventLog:Security` |
| Field ada di `_raw` tetapi tidak di sidebar | 01 | Mode Fast, atau field di bawah ambang 20%; buktikan dengan `fieldsummary` atau `stats` |
| Angka di tabel lebih kecil dari total yang kamu tahu | 02, 08 | `top`, `head`, `sort`, `list()`, dan batas sepuluh seri |
| `where` tidak menemukan nilai yang jelas ada | 02 | Huruf besar-kecil, kutip pada nilai literal |
| Jumlah akun unik dua kali lipat | 02, 03 | Field multivalue (`Account_Name`, `Actor{}.ID`); pecah dulu |
| Process tree terputus | 04 | Rentang terlalu sempit, Sysmon dipasang belakangan, kelompokkan dengan `ProcessGuid` |
| Event Sysmon atau auditd tertentu tidak pernah ada | 04, 06 | Konfigurasi Sysmon dan aturan auditd di host itu |
| Pemetaan alamat ke orang menghasilkan dua akun | 05 | Pool VPN dipakai ulang; persempit rentang waktunya |
| Sign-in Entra tidak ditemukan | 06 | Cari di `azure:monitor:aad`, cek kategori yang dikirim tenant |
| Disposisi berbeda antar analyst untuk kasus serupa | 07 | Dua pertanyaan dasar: detection bekerja benar, aktivitas berbahaya |
| Single value tidak sesuai judul panel | 08 | `timechart` memberi bin terbaru, `stats` memberi total |
| Satu serangan menghasilkan belasan notifikasi | 09 | Jendela lebih panjang dari interval tanpa throttle |
| Alert jalan tetapi tidak pernah menyala | 09, 01 | Rentang jadwal menimpa SPL; nilai field berbeda; pemilik tanpa akses index |

## 5. Kesalahan umum dan jebakan (review)

- Menyimpulkan "tidak terjadi" dari hasil nol tanpa memeriksa rentang dibanding lag, index, sourcetype, audit policy, atau konfigurasi sensor.
- Mengandalkan time picker untuk search yang dibagikan, atau rentang relatif untuk dataset statis. Rentang ditulis di dalam search dan absolut bila hasilnya harus bisa diulang [S1].
- Menulis angka dari tabel atau grafik yang dipotong (`top`, `head`, `sort`, batas sepuluh seri) tanpa menyebut pemotongannya [S9][S10][S34].
- Menyalin nilai satu bin grafik ke tiket sebagai ukuran satu burst.
- Membaca kolom akun pertama sebagai pelaku: Subject di 4625, `TargetUserName` di event grup, `uid` setelah `sudo`, elemen pertama `Actor{}.ID`, atau alamat pool VPN tanpa batas waktu.
- Memakai `values()` untuk menyusun ulang script 4104 atau kronologi, padahal `values()` mengurutkan dan membuang duplikat [S11].
- Mencatat Benign Positive sebagai False Positive, atau menutup finding dengan Undetermined [S32].
- Menerima konfirmasi pengguna lewat akun yang sedang diselidiki sebagai bukti tunggal.
- Menyimpan alert tanpa throttle, tanpa log event, dengan `earliest`/`latest` ganda di SPL dan jadwal, atau dimiliki akun pribadi [S37][S39][S41].
- Membagikan tautan job berisi hasil index sensitif; berbagi tautan mengubah read permission menjadi Everyone [S4].

## 6. Catatan terkini

Bagian ini menampung versi acuan yang dipakai di Day 01-09 dan perubahan istilah yang membuat dokumentasi lama memakai nama lain. Isinya tidak mengubah alur review, tetapi perlu disebut saat menulis search produksi atau menjawab interview.

- Splunk Enterprise 10.6 dirilis 30 September 2026, dan sejak rilis itu Splunk memakai format versi empat segmen; field filter di 10.6 sudah generally available dan aktif secara default [S42]. Panel atau alert yang tiba-tiba kosong pada field tertentu perlu dicek terhadap field filter (Day 09 bagian 6).
- Add-on yang dipakai di Day 03 dan Day 04: Splunk Add-on for Microsoft Windows 11.0.3, dirilis 1 Oktober 2026 [S15], dan Splunk Add-on for Sysmon 5.0.1, dirilis 6 Juli 2026 [S23]. Versi dan status add-on jaringan, Linux, dan cloud dicatat di Day 05 bagian 6 dan Day 06 bagian 6, termasuk add-on proxy dan DNS yang berstatus arsip.
- Catatan ini memakai CIM 6.4 sebagai acuan, sedangkan app CIM di Splunkbase sudah versi 8.7.0 (2 September 2026) [S27], dan add-on yang dipakai mencantumkan kompatibilitas CIM yang berbeda-beda. Day 05 membaca halaman data model di dokumentasi CIM 8.7; cek matriks kompatibilitas add-on sebelum mengandalkan sebuah field (Day 05 bagian 6, Day 06 bagian 6).
- Di ES 8, notable event menjadi finding dan Incident Review menjadi analyst queue di Mission Control; artikel Lantern tentang alur kerja insiden masih memakai istilah ES 7 (Day 07 bagian 6). Panel konfigurasi disposition di dokumentasi ES 8.7 menampilkan lima label, sedangkan drop-down menyebut tujuh [S32].
- Azure AD sudah berganti nama menjadi Microsoft Entra ID, tetapi sourcetype dan judul detection masih memakai nama lama, misalnya `azure:monitor:aad` (Day 06 bagian 6).
- Dokumentasi Splunk kini dibaca di help.splunk.com, dan sebagian halaman Search Manual yang dipakai Day 01 masih terbit sebagai versi 10.4, 10.2, 10.0, dan 9.4 (Day 01 bagian 6).
- BOTS v1 dibuat dengan Splunk Enterprise 6.5.2 dan Splunk Add-on for Microsoft Windows 4.8.3, sehingga nama sourcetype-nya berbeda dari add-on modern [S6]. BOTS v2 dan v3 punya catatan serupa di Day 06 bagian 6 dan Day 04 bagian 6.

## 7. Cheat sheet fondasi

```
EMPAT KEPUTUSAN  index | sourcetype | rentang waktu | search mode               (Day 01)
DATA             lag = _indextime - _time ; rentang absolut "%m/%d/%Y:%H:%M:%S"
                 kemarin penuh -1d@d..@d ; dataset statis: cari rentang dulu, lalu absolut
                 Fast = tanpa field discovery ; Interesting Fields >= 20% ; job 10 menit / 7 hari
SPL              saring -> where -> eval -> stats -> eval -> fillnull -> sort -> head -> rename -> table
                 search: nilai tidak peka huruf, IN boleh wildcard | where: peka huruf, in() tanpa wildcard
                 NOT f=* = event tanpa f | f!=* = selalu kosong | count vs dc | values vs list(100)
                 batas: sort 10000 | top/rare/head 10 | fillnull tanpa daftar = semua field
WINDOWS          source=XmlWinEventLog:Security ; BOTS v1 sourcetype="WinEventLog:Security"
                 4624 type 2/3/4/5/7/8/9/10/11 ; 4625 Status umum -> SubStatus
                 Subject vs target ; TargetLogonId(4624) = SubjectLogonId(4672, 4688)
                 grup: pelaku Subject, anggota MemberName/MemberSid, grup TargetUserName
SYSMON + PS      ProcessGuid bukan PID ; LogonId -> 4624 ; EID 3 mati default ; 22 tanpa Win7
                 GrantedAccess bitmask 0x10 + 0x1000 ; 4104 gabung per ScriptBlockId, list() setelah sort
JARINGAN         Traffic action allowed|blocked|teardown ; Auth action success|failure
                 bytes_out untuk exfil ; HTTPS proxy = CONNECT host:port ; BIND query log tanpa reply_code
                 sampling -> rasio ; pool VPN -> selalu batasi waktu ; CGNAT 1 IP = banyak pelanggan
LINUX + CLOUD    sudo /bin/bash = jejak berhenti ; auid = orangnya, uid = efektif
                 sign-in Entra di azure:monitor:aad ; errorCode 0 sukses ; 50140/50158 bukan gagal
                 notApplied = tidak ada kebijakan dievaluasi ; M365 Parameters{} -> mvfind + mvindex
TRIAGE           siapa | apa | di mana | kapan | wajar? -> enrichment -> disposisi -> eskalasi
                 TP | Benign | FP-Logic | FP-Data | Undetermined (jangan ditutup)
                 eskalasi: dampak | wewenang | ketidakpastian ; disposition != status
                 note: dilihat | dicek (query + rentang + angka) | kesimpulan | langkah | keterbatasan
CHART            chart OVER a BY b ; timechart span=1h BY b (satu BY) ; bin + stats untuk 3 dimensi
                 10 seri + OTHER ; useother=f tidak menaikkan batas ; WHERE max in top5
                 single value: timechart = bin terbaru, stats = total ; grafik untuk bentuk, stats untuk angka
ALERT            report = aksi tiap jalan ; alert = aksi saat trigger
                 Earliest/Latest jadwal menimpa SPL ; jendela == interval atau throttle ; delay >= 1 menit
                 Once | For each result ; throttle field + periode ; menyunting = throttle batal
                 log event -> soc_alerts ; webhook = baris pertama + allow list
                 owner fungsional ; Display for app ; objek yatim berhenti jalan
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci. Soal di bawah mencampur materi Day 01-09; kunci juga menunjuk Day asal bila perlu diulang.

**1. Pertanyaan jebakan.** Tiga analyst melapor pada malam yang sama. Analyst A: search VPN 15 menit terakhir pukul 23.45 nol hasil, jadi log VPN tidak masuk. Analyst B: `CommandLine` di 4688 dari beberapa host kosong, jadi tidak ada perintah yang dijalankan. Analyst C: tidak ada Sysmon event 3 dari `JKT-DC01` selama seminggu, jadi DC itu tidak membuat koneksi keluar. Apa kesalahan yang sama dari ketiganya?

<details><summary>Jawaban</summary>

Ketiganya membaca ketiadaan data sebagai ketiadaan kejadian, padahal penyebabnya ada di benang data. Untuk A, rentang search menyaring menurut `_time`, sedangkan event baru bisa dicari setelah tersimpan; di SOC-2026-0198 selisihnya 1.948 detik. Untuk B, field command line baru terisi setelah setelan Include command line in process creation events aktif, terpisah dari audit Process Creation yang membuat 4688 ditulis. Untuk C, event 3 mati secara default di Sysmon dan hanya ada bila `NetworkConnect` dinyalakan di konfigurasi host itu. Kesimpulan yang benar adalah "pada sumber dan konfigurasi ini, data itu tidak tersedia", lalu buktikan dengan lag, audit policy, atau hasil `sysmon64 -c`. Lihat bagian 1.10, atau Day 01 bagian 1.4, Day 03 bagian 1.2, dan Day 04 bagian 1.1.

</details>

**2. Skenario keputusan.** Untuk note SOC-2026-0217, angka mana yang kamu tulis sebagai jumlah login gagal dari 203.0.113.45?

- A. 104, karena itu puncak di grafik `timechart span=1h` pada bin 01:00.
- B. Lima angka teratas dari `top limit=5 user`, karena itu yang terlihat di layar.
- C. 180, dari `stats` atau `chart` dengan `src="203.0.113.45"` pada rentang absolut 01:30 sampai 02:30, ditulis bersama query dan rentangnya.

<details><summary>Jawaban</summary>

C. Serangan berlangsung 01:52 sampai 02:06 dan menyeberangi batas jam, sehingga grafik membelahnya menjadi dua bin; 104 juga memuat kegagalan dari sumber lain, dan sumbangan 203.0.113.45 di dua bin itu 98 dan 82. Angka yang mengukur serangan diambil dengan agregasi pada rentang absolut yang menutupi seluruh rangkaian, dan bisa diulang orang lain dengan hasil yang sama. A keliru karena nilai bin bukan ukuran burst. B keliru karena `top` memotong di batas yang kamu pilih dan membuang sisanya tanpa pesan; di kasus ini 25 akun terlibat. Lihat bagian 1.10, atau Day 08 bagian 2.1 dan 2.6.

</details>

**3. Pertanyaan jebakan.** "Di setiap log, kolom akun yang pertama terlihat adalah pelakunya." Berikan tiga contoh dari Day 03-06 yang membantah kalimat itu.

<details><summary>Jawaban</summary>

Pertama, di 4625 format klasik `Account_Name` berisi dua nilai, dan nilai pertama biasanya Subject, misalnya akun mesin `JKT-JUMP01$` yang mewakili SYSTEM, bukan akun yang gagal. Kedua, di 4728 dan 4732 `TargetUserName` berisi nama grup; pelaku ada di `SubjectUserName` dan akun yang ditambahkan di `MemberName` atau `MemberSid`. Ketiga, di auditd `uid` bernilai 0 setelah `sudo` untuk siapa pun, dan orang yang login ada di `auid`. Contoh lain yang sah: elemen pertama `Actor{}.ID` di event role M365 bisa berupa GUID, dan alamat pool VPN bisa dipegang dua akun dalam rentang yang lebar. Lihat bagian 1.3, 1.5, dan 1.6, atau Day 03 bagian 1.5 dan 1.7 dan Day 06 bagian 1.4.

</details>

**4. Skenario keputusan.** Pukul 02.50, search Day 06 menemukan tiga kegagalan SSH lalu satu login sukses dengan password untuk akun `svc_radius` di `jkt-bastion01` dari 192.0.2.118, IP publik yang belum pernah terlihat. Apa langkah L1 yang paling tepat?

- A. Tutup sebagai Benign Positive, karena server yang terbuka ke internet memang selalu menerima pemindaian.
- B. Eskalasi segera ke L2 on-call dengan note lengkap, disposisi sementara Undetermined atau True Positive bila bukti sudah jelas, dan rekomendasi tindakan.
- C. Nonaktifkan `svc_radius` sendiri dan blokir 192.0.2.118, lalu tutup tiket.

<details><summary>Jawaban</summary>

B. Dua kondisi di matriks eskalasi PT JAB terpenuhi sekaligus: login sukses setelah rangkaian gagal dari sumber tak dikenal, dan akun service terlibat. Polanya juga menumpuk tiga anomali di satu baris: akun service login interaktif, memakai password padahal admin memakai publickey, dan datang dari IP publik. A keliru karena profil pemindaian adalah ramai, lama, tidak selektif, dan tanpa keberhasilan, sedangkan kasus ini justru berhasil. C keliru karena menonaktifkan akun dan memblokir IP berada di luar wewenang L1, dan menutup tiket menghentikan scoping yang belum dilakukan. Lihat bagian 1.6 dan 1.7, atau Day 06 bagian 2.3 dan Day 07 bagian 1.7.

</details>

**5. Jelaskan ulang.** Jelaskan kepada analyst L1 yang baru masuk, dalam tiga kalimat, apa yang harus sudah kamu periksa sebelum menulis satu angka di note tiket.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Pertama, pastikan datanya ada dan lengkap: index dan sourcetype yang benar, rentang yang lebih lebar dari lag ingest, dan sumber yang memang mencatat event itu. Kedua, pastikan angkanya berasal dari hasil penuh: `stats` dengan `dc` atau `count` yang sesuai pertanyaan, tanpa `top`, `head`, atau batas sepuluh seri yang diam-diam memotong, dan bukan dari nilai satu bin grafik. Ketiga, tulis query beserta rentang absolutnya di samping angka itu, supaya orang lain yang menjalankannya besok mendapat hasil yang sama."

Kesalahan yang sering muncul:
- Menyebut grafik atau screenshot sebagai bukti angka.
- Lupa rentang waktu absolut, sehingga angka berubah saat search dibuka hari lain.
- Memakai `count` untuk pertanyaan "berapa host" atau "berapa akun".

</details>

**6. Pertanyaan jebakan.** "Alert brute force VPN sudah dibuat ulang, jalan setiap 5 menit, dan tidak pernah error. Jadi deteksinya sudah aman." Apa yang belum terbukti dari kalimat itu?

<details><summary>Jawaban</summary>

Banyak hal yang tidak terlihat dari status "jalan tanpa error". Rentang `Earliest` dan `Latest` di jadwal menimpa rentang di SPL, jadi jendela yang benar-benar dipakai harus dicek di form alert. Jendela yang lebih pendek dari interval membuat ada event yang tidak pernah dievaluasi, dan delay yang lebih kecil dari lag ingest jalur VPN membuat event terlambat terlewat. Jendela yang lebih panjang dari interval tanpa throttle membanjiri shift, dan menyunting alert membatalkan throttle yang sedang berjalan. Alert yang dimiliki akun pribadi berhenti jalan bila akun itu dihapus, dan scheduled search berjalan sebagai pemiliknya, sehingga pemilik tanpa akses `index=vpn` menghasilkan nol tanpa pesan. Lihat bagian 1.9 dan Bagian A langkah 8, atau Day 09 bagian 1.2, 1.4, dan 1.6 serta Day 01 bagian 2.2.

</details>

**7. Interview question (English).** "What are the most common ways a Splunk search gives an analyst a misleading answer, and how do you guard against them?"

<details><summary>Sample answer</summary>

"I group them into three threads. The first is data: a zero result often means my filter is wrong, not that nothing happened. I check the index and whether my role can search it, the source type and the exact field names, whether my time range is wider than the ingest lag, and whether the event was ever written, because audit policy, the Sysmon config, auditd rules, or the cloud log categories decide that before Splunk ever sees anything. The second is identity: the first account column is often not the actor. In Windows it can be the Subject rather than the target, after sudo the Linux uid is zero for everyone and the real person is in the audit login ID, and a VPN pool address only maps to a person inside a specific time window. The third is numbers: commands like top, head and sort, the ten-series limit in chart and timechart, and list truncate quietly, and a chart bucket can split one burst into two values. So I use charts to find where to look, then take the figure for the ticket from a stats search over an absolute time range and write the query next to it. When I turn that into an alert, I align the schedule window with the interval, leave a delay, throttle on the field that defines the same incident, log the alert to an index, and give it a team owner so it doesn't silently stop."

What makes this answer strong: it organises many small pitfalls into three reusable checks, gives a concrete example for each, and ends by showing the same discipline carried into an alert that someone else will maintain.

</details>

## 9. Sumber

Setiap baris di bawah disalin dari tabel Sumber Day asal dan diberi nomor baru; kolom terakhir menyebut asal barisnya.

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Splunk Enterprise 10.4 Search Manual: Specify time modifiers in your search | https://help.splunk.com/en/splunk-enterprise/search/search-manual/10.4/specify-time-ranges/specify-time-modifiers-in-your-search | primer | diperbarui 2026-05-16; diakses 2026-10-14 | Tinggi. Sintaks `earliest`/`latest`, format absolut, snap-to, menimpa time picker. Asal: Day 01 S2 |
| S2 | Splunk Enterprise 10.6 Search Tutorial: Use fields to search | https://help.splunk.com/en/splunk-enterprise/get-started/search-tutorial/10.6/part-4-searching-the-tutorial-data/use-fields-to-search | primer | diperbarui 2026-08-25; diakses 2026-10-14 | Tinggi. Ambang 20% Interesting Fields, nama field peka huruf. Asal: Day 01 S5 |
| S3 | Splunk Enterprise 10.0 Search Manual: Extending job lifetimes | https://help.splunk.com/en/splunk-enterprise/search/search-manual/10.0/manage-jobs/extending-job-lifetimes | primer | diperbarui 2025-07-18; diakses 2026-10-14 | Tinggi. Bawaan 10 menit, pilihan 7 hari. Asal: Day 01 S9 |
| S4 | Splunk Enterprise 10.4 Search Manual: About jobs and job management | https://help.splunk.com/en/splunk-enterprise/search/search-manual/10.4/manage-jobs/about-jobs-and-job-management | primer | diperbarui 2026-05-16; diakses 2026-10-14 | Tinggi. Berbagi job, masa simpan, `srchDiskQuota` 100MB. Asal: Day 01 S7 |
| S5 | Splunk Enterprise 10.0: Create custom indexes | https://help.splunk.com/en/data-management/manage-splunk-enterprise-indexers/10.0/manage-indexes/create-custom-indexes | primer | diperbarui 2025-07-18; diakses 2026-10-14 | Tinggi. Alasan memisahkan index, event dibuang bila index tidak ada, index default per role. Asal: Day 01 S11 |
| S6 | GitHub splunk/botsv1 | https://github.com/splunk/botsv1 | primer | dataset 2016; diakses 2026-10-14 | Tinggi. Index `botsv1`, contoh `earliest=0`, versi Splunk dan add-on pembuat dataset. Asal: Day 01 S12, Day 03 S15 |
| S7 | Splunk Enterprise 10.6 SPL Search Reference: search | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/search | primer | diperbarui 2026-09-09; diakses 2026-10-14 | Tinggi. Operator `IN` dengan wildcard, `NOT` vs `!=`, nilai tidak peka huruf. Asal: Day 02 S1, Day 01 S14 |
| S8 | Splunk Enterprise 10.6 SPL Search Reference: where | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/where | primer | diperbarui 2026-09-09; diakses 2026-10-14 | Tinggi. Eval expression peka huruf, string berkutip sebagai literal. Asal: Day 02 S2 |
| S9 | Splunk Enterprise 10.6 SPL Search Reference: sort | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/sort | primer | diperbarui 2026-09-09; diakses 2026-10-14 | Tinggi. Batas bawaan 10000, `sort 0`. Asal: Day 02 S5 |
| S10 | Splunk Enterprise 10.6 SPL Search Reference: top | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/top | primer | diperbarui 2026-09-09; diakses 2026-10-14 | Tinggi. Bawaan 10, `limit=0`, `useother`, `otherstr`. Asal: Day 02 S6 |
| S11 | Splunk Enterprise 10.6 SPL Search Reference: Multivalue stats and chart functions | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/statistical-and-charting-functions/multivalue-stats-and-chart-functions | primer | diperbarui 2026-09-09; diakses 2026-10-14 | Tinggi. `values()` distinct dan leksikografis, `list()` dibatasi 100 nilai. Asal: Day 02 S4 |
| S12 | Splunk Enterprise 10.6 SPL Search Reference: Comparison and Conditional functions | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/evaluation-functions/comparison-and-conditional-functions | primer | diperbarui 2026-09-09; diakses 2026-10-14 | Tinggi. `in()` tanpa wildcard dan harus dibungkus. Asal: Day 02 S14 |
| S13 | Splunk Enterprise 10.6 SPL Search Reference: fillnull | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/fillnull | primer | diperbarui 2026-09-09; diakses 2026-10-14 | Tinggi. Bawaan `0`, berlaku ke semua field bila daftar tidak disebut. Asal: Day 02 S12 |
| S14 | Splunk Security Content: Data Source Windows Event Log Security 4624 | https://research.splunk.com/sources/08682968-0366-4882-9559-fe4fe018a846/ | primer (Splunk) | 2026-05-13; diakses 2026-10-14 | Tinggi. Source, sourcetype, daftar field add-on 11.0.3. Asal: Day 03 S5 |
| S15 | Splunkbase: Splunk Add-on for Microsoft Windows | https://splunkbase.splunk.com/app/742 | primer | versi 11.0.3, 2026-10-01; diakses 2026-10-14 | Tinggi untuk versi dan kompatibilitas. Asal: Day 03 S7 |
| S16 | Microsoft Learn: 4624(S) An account was successfully logged on | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624 | primer | diperbarui 2026-04-27; diakses 2026-10-14 | Tinggi. Logon type dan rekomendasi pemantauan. Asal: Day 03 S1 |
| S17 | Microsoft Learn: 4625(F) An account failed to log on | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625 | primer | 2026-03-29, diperbarui 2026-05-01; diakses 2026-10-14 | Tinggi. Kode Status/Sub Status. Asal: Day 03 S2 |
| S18 | Microsoft Learn: 4732(S) A member was added to a security-enabled local group | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4732 | primer | diperbarui 2026-04-27; diakses 2026-10-14 | Tinggi. `MemberName`, `MemberSid`, `TargetUserName` sebagai grup. Asal: Day 03 S9 |
| S19 | Microsoft Learn: Command line process auditing | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing | primer | 2025-05-12, diperbarui 2025-09-23; diakses 2026-10-14 | Tinggi. Dua setelan untuk 4688. Asal: Day 03 S16 |
| S20 | Microsoft Learn: Sysmon (Sysinternals) | https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon | primer | terbit 2026-09-10; diakses 2026-10-14 | Tinggi. Daftar event, default, `ProcessGuid`. Asal: Day 04 S1 |
| S21 | Splunk Security Content: Detection Detect Credential Dumping through LSASS access | https://research.splunk.com/endpoint/2c365e57-4414-4540-8dc0-73ab10729996 | primer (Splunk) | versi 16, 2026-09-08; diakses 2026-10-14 | Tinggi. Logika bitmask `GrantedAccess`. Asal: Day 04 S11 |
| S22 | Microsoft DevBlogs: PowerShell the Blue Team | https://devblogs.microsoft.com/powershell/powershell-the-blue-team/ | primer | diakses 2026-10-14 | Sedang-tinggi. Script block dipecah; pencatatan otomatis script mencurigakan. Asal: Day 04 S14 |
| S23 | Splunkbase: Splunk Add-on for Sysmon | https://splunkbase.splunk.com/app/5709 | primer | versi 5.0.1, 2026-07-06; diakses 2026-10-14 | Tinggi untuk versi dan kompatibilitas. Asal: Day 04 S10 |
| S24 | Splunk CIM 8.7: Network Traffic | https://help.splunk.com/en/data-management/common-information-model/8.7/data-models/network-traffic | primer | CIM 8.7; diakses 2026-10-14 | Tinggi. Nilai baku `action`, field byte, `direction`. Asal: Day 05 S4 |
| S25 | Splunk CIM 8.7: Network Resolution (DNS) | https://help.splunk.com/en/data-management/common-information-model/8.7/data-models/network-resolution-dns | primer | CIM 8.7; diakses 2026-10-14 | Tinggi. `message_type`, `reply_code`, `reply_code_id`. Asal: Day 05 S6 |
| S26 | Splunk CIM 8.7: Authentication | https://help.splunk.com/en/data-management/common-information-model/8.7/data-models/authentication | primer | CIM 8.7; diakses 2026-10-14 | Tinggi. Nilai baku `action`. Asal: Day 05 S7 |
| S27 | Splunkbase: Splunk Common Information Model (CIM) | https://splunkbase.splunk.com/app/1621 | primer | versi 8.7.0, 2026-09-02; diakses 2026-10-14 | Tinggi untuk versi CIM terbaru. Asal: Day 05 S8 |
| S28 | Splunk Security Content: Data Source Linux Auditd Add User | https://research.splunk.com/sources/30f79353-e1d2-4585-8735-1e0359559f3f/ | primer (Splunk) | 2026-05-13, versi 3; diakses 2026-10-14 | Tinggi. Field auditd, contoh `ADD_USER` dengan `uid` 0 dan `AUID`. Asal: Day 06 S4 |
| S29 | Sudoers Manual (sudoers.man) | https://www.sudo.ws/docs/man/sudoers.man/ | primer | diakses 2026-10-14 | Tinggi. Urutan field log, `log_allowed`, `log_denied`. Asal: Day 06 S6 |
| S30 | Microsoft Learn: Azure Monitor Logs reference, tabel SigninLogs | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs | primer | 2026-08-27; diakses 2026-10-14 | Tinggi. Arti `ResultType` dan `ConditionalAccessStatus`. Asal: Day 06 S10 |
| S31 | Microsoft Learn: Microsoft Entra authentication and authorization error codes | https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes | primer | diperbarui 2026-06-15; diakses 2026-10-14 | Tinggi. Deskripsi kode AADSTS. Asal: Day 06 S11 |
| S32 | ES 8.7: Configure dispositions for findings in Splunk Enterprise Security | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/investigations/configure-dispositions-for-findings-in-splunk-enterprise-security | primer | diakses 2026-10-14 | Tinggi. Tujuh disposition, default Undetermined, disposition tidak mengubah status. Asal: Day 07 S1 |
| S33 | ES 8.7: Configure the urgency for findings in Splunk Enterprise Security | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/findings/configure-the-urgency-for-findings-in-splunk-enterprise-security | primer | diakses 2026-10-14 | Tinggi untuk prinsip perhitungan urgency. Asal: Day 07 S4 |
| S34 | Splunk Enterprise 10.6 Search Reference: chart | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/chart | primer | diakses 2026-10-14 | Tinggi. `OVER`/`BY`, batas sepuluh kolom, `useother`, `usenull`, klausa `where`. Asal: Day 08 S1 |
| S35 | Splunk Enterprise 10.6 Search Reference: timechart | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/timechart | primer | diakses 2026-10-14 | Tinggi. Span default per preset, satu klausa `BY`. Asal: Day 08 S2 |
| S36 | Splunk Enterprise 10.6: Generate a single value | https://help.splunk.com/en/splunk-enterprise/create-dashboards-and-reports/simple-xml-dashboards/10.6/single-value/generate-a-single-value | primer | diakses 2026-10-14 | Tinggi. Beda single value dari `timechart` dan `stats`. Asal: Day 08 S6 |
| S37 | Splunk Enterprise 10.6 Alerting Manual: Create scheduled alerts | https://help.splunk.com/en/splunk-enterprise/alert-and-respond/alerting-manual/10.6/create-alerts/create-scheduled-alerts | primer | diakses 2026-10-14 | Tinggi. Run on Cron Schedule, rentang menimpa search. Asal: Day 09 S1 |
| S38 | Splunk Enterprise 10.6 Alerting Manual: Alert scheduling tips | https://help.splunk.com/en/splunk-enterprise/alert-and-respond/alerting-manual/10.6/create-alerts/alert-scheduling-tips | primer | diperbarui 2026-08-25; diakses 2026-10-14 | Tinggi. Selaras jadwal dan rentang, delay, report vs alert. Asal: Day 09 S2 |
| S39 | Splunk Enterprise 10.6 Alerting Manual: Throttle alerts | https://help.splunk.com/en/splunk-enterprise/alert-and-respond/alerting-manual/10.6/manage-alert-trigger-conditions-and-throttling/throttle-alerts | primer | diakses 2026-10-14 | Tinggi. Field suppress, periode, penyuntingan membatalkan throttle. Asal: Day 09 S5 |
| S40 | Splunk Enterprise 10.6 Alerting Manual: Use a webhook alert action | https://help.splunk.com/en/splunk-enterprise/alert-and-respond/alerting-manual/10.6/configure-alert-actions/use-a-webhook-alert-action | primer | diperbarui 2026-08-25; diakses 2026-10-14 | Tinggi. Payload memuat baris hasil pertama, allow list. Asal: Day 09 S9 |
| S41 | Splunk Enterprise 10.6 Knowledge Manager Manual: Manage knowledge object permissions | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/get-started-with-knowledge-objects/manage-knowledge-object-permissions | primer | diperbarui 2026-09-09; diakses 2026-10-14 | Tinggi. Private sebagai default, objek yatim. Asal: Day 09 S12 |
| S42 | Splunk Enterprise 10.6 release notes: Welcome to Splunk Enterprise 10.6 | https://help.splunk.com/en/splunk-enterprise/release-notes-and-updates/release-notes/10.6/whats-new/welcome-to-splunk-enterprise-10.6 | primer | diperbarui 2026-09-30; diakses 2026-10-14 | Tinggi. Tanggal rilis, format versi empat segmen, field filter GA. Asal: Day 09 S20 |

**Catatan sumber:** Day ini tidak memakai sumber baru; semua klaim produk berasal dari Day 01-09, dan klaim yang masih lemah di Day asal tetap lemah di sini. Yang paling perlu diingat: nama field format klasik Windows dan urutan nilai multivalue `Account_Name` belum dikonfirmasi sumber primer (Day 03 bagian 9), nama sourcetype `squid:access` dan `isc:bind:query` serta field alamat tunnel VPN `private_ip` perlu dicocokkan dengan add-on versi-mu (Day 05 bagian 9), dan pengkodean heksadesimal `proctitle` di auditd perlu dicek di lab (Day 06 bagian 9). Rentang tanggal BOTS v1 tidak tercantum di README dataset [S6], sehingga rentang di Bagian B wajib diverifikasi dengan `tstats` sebelum dipakai. Matriks eskalasi, template note, kriteria disposisi, tabel pemilihan visualisasi, dan ambang alert PT JAB adalah praktik kerja yang disusun untuk catatan ini, bukan aturan produk (Day 07 bagian 9, Day 08 bagian 9, Day 09 bagian 9). Hitungan enam jalan alert di Bagian A langkah 8 diturunkan dari setelan jadwal Day 09 bagian 2.2 dan rentang serangan di Day 07 bagian 2.1.
