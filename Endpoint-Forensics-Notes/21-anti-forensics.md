---
day: 21
title: 'Anti-forensics dan deteksinya: pembersihan event log, penghapusan USN journal, wiping, shadow copy, telemetri yang dimatikan, dan timestomping lanjutan'
researched_on: 2026-10-23
versions_checked: 'Windows 11 23H2 (build 22631); fsutil usn (Microsoft Learn, diperbarui 2026-02-16; USN_JOURNAL_DATA_V0 ms.date 2018-12-05; Creating, Modifying, and Deleting a Change Journal ms.date 2018-05-31); SDelete (Sysinternals, terbit 2026-03-05, default 1 pass); Sysmon v15.x (Microsoft Learn 2026-09-10, EID 2/4/16/23/26/28); vssadmin delete shadows dan cipher (Microsoft Learn); event 1102, 104, 4719 (Microsoft Learn ms.date 2021-09-07); EZ Tools 2026.5.0; MITRE ATT&CK v20 (T1070 Indicator Removal versi 3.0, taktik Stealth TA0005; T1070.006 Timestomp; T1070.001 direvoke menjadi T1685.005; T1562.002 menjadi T1685.001; T1685 Disable or Modify Tools versi 1.0, taktik Defense Impairment TA0112; T1490 Inhibit System Recovery)'
---

# Day 21: Anti-forensics dan deteksinya

Cakupan: empat keluarga teknik penghilangan jejak di Windows (menghapus bukti, mengubah bukti, mencegah perekaman, menghancurkan data), jejak yang justru ditinggalkan masing-masing, sumber di luar host yang tidak ikut terhapus, dan cara menulis kalimat jujur tentang periode yang hilang.

## Ide inti

Anti-forensik jarang berhasil sempurna. Yang biasanya terjadi adalah penyerang menghapus satu lapis bukti dan meninggalkan lapis lain, karena Windows mencatat hal yang sama di beberapa tempat dengan mekanisme berbeda, dan karena satu-satunya cara menghapus data di volume yang hidup adalah menulis ke volume itu. Penghapusan adalah penulisan, dan penulisan itu sendiri meninggalkan jejak: event pembersihan, identitas journal baru, pola nama khas alat wiping, perintah di event log, dan telemetri yang sudah terlanjur diteruskan keluar host sebelum yang lokal dihapus. Tugas pemeriksa bukan membuktikan bahwa tidak ada yang dihapus, melainkan menemukan bekas penghapusannya, memperkirakan apa yang hilang, dan menuliskan batasnya tanpa melebih-lebihkan. Satu tanda bukan kesimpulan; dan "tidak bisa dipulihkan dari host ini" tidak sama dengan "hilang selamanya", karena salinan di SIEM dan di layanan cloud sering menjawab seluruh pertanyaan.

Kamu sudah mengenal pola ini dari NOC. Orang yang mengutak-atik sebuah router lalu menghapus baris aneh di running-config dan menjalankan `clear logging` tidak benar-benar bersih: `clear logging` sendiri tercatat, `archive log config` menyimpan perubahan konfigurasi, accounting TACACS ada di server AAA yang terpisah, dan NetFlow serta syslog sudah mengalir ke collector sebelum ia sempat menyentuhnya. Yang hilang permanen hanyalah data yang benar-benar ditimpa di perangkat itu; sisanya pindah tempat, bukan lenyap. Di host Windows, archive log config dan collector syslog itu bernama USN journal, event log yang diteruskan ke Splunk, telemetri EDR di cloud, dan log autentikasi di domain controller.

```
penyerang mencoba menghapus jejak di satu host
  |
  v
tiap tindakan penghapusan = PENULISAN -> meninggalkan jejaknya sendiri
  |
  +-- bersihkan event log   -> 1102 (Security) / 104 (System) + EventRecordID restart
  +-- hapus USN journal      -> UsnJournalID baru + LowestValidUsn diskontinu + $J jadi pendek + fsutil di Prefetch
  +-- wiping (SDelete)        -> pola nama A..Z, Prefetch/Amcache, Sysmon FileDelete + perintah (diteruskan)
  +-- hapus shadow copy       -> vssadmin di Prefetch/4688 (efek bisa nol bila tak ada shadow copy)
  +-- matikan telemetri       -> CARI PERUBAHANNYA: 7036/EID 4 Sysmon berhenti, EnablePrefetcher=0 + waktu tulis
  +-- timestomp               -> SI<FN, urutan EntryNumber MFT, Prefetch/Shimcache/Amcache tak ikut diubah
  |
  v
sumber DI LUAR host yang tidak ikut terhapus: Splunk (diteruskan sebelum dihapus), Defender cloud, JKT-DC01
  |
  v
kalimat jujur: sebut jendela yang hilang lokal, sumber yang menutupinya, dan apa yang benar-benar tak bisa dipulihkan
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan dan data pribadi sekitar 400 ribu pelanggan broadband. Kasusnya `INC-2027-011` (SEV-2, Februari 2027), kompromi dengan upaya anti-forensik di workstation staf IT Infrastruktur Jakarta `JKT-WS-0528` (`10.10.52.28`, Windows 11 23H2 build 22631, di OU `Workstations-EDR` yang menerima Microsoft Defender for Endpoint, Sysmon, dan GPO audit `JAB-WS-Audit`). Pemilik akun `rizal.fadillah` (staf IT Infrastruktur, juga punya akun admin `adm.rizal`). Akun `rizal.fadillah` dikuasai penyerang lewat phishing kredensial, dan dari sesi interaktif yang dibajak itu penyerang mengangkat diri memakai `adm.rizal`, lalu mencoba membersihkan jejak sebelum meninggalkan host: membersihkan log Security, menghapus USN journal, menghancurkan satu folder staging dengan alat wiping, memalsukan waktu satu berkas, menjalankan `vssadmin`, dan menghapus Sysmon beserta mematikan prefetch. Tidak semuanya berhasil. Rangkaian alert `SOC-2027-0110` sampai `SOC-2027-0119` menyala Senin 2027-02-01 dari Defender, dan Rudi Hartanto (analyst L2, primary on-call sejak 1 Februari 2027) yang pertama menerimanya; host diisolasi lewat EDR, lalu Yoga Pratama meng-image disk (`INC-2027-011-E01`) Senin malam. Selasa 2027-02-02 pagi, Sari Kusuma (technical lead) menulis kepadamu (analyst L2 forensik) di kanal `#inc-2027-011`:

> "Pagi. E01 sudah siap, hash cocok, salinan kerja E01-W1 di-mount. Ini kasus pertama kita yang pelakunya jelas-jelas mencoba menghapus jejak, jadi aku mau hati-hati soal kalimatnya. Yang aku butuh: apa saja yang dia hapus atau matikan di laptop ini? Untuk tiap satu, apa yang masih bisa kita buktikan justru dari bekas penghapusannya sendiri? Log Security kelihatan pendek sekali, benarkah dibersihkan, dan kalau iya periode mana yang hilang? USN journal juga aneh, tolong cek. Berkas apa yang dia hancurkan, dan masih bisa tidak kita tahu namanya? Sumber di luar laptop ini yang mana yang masih utuh, Splunk atau Defender atau DC? Dan terakhir, kalimat apa yang aman aku tulis di laporan soal periode yang hilang, supaya tidak kelihatan seperti kita bilang 'tidak terjadi apa-apa' padahal cuma 'tidak tercatat lagi di sini'. Draf sebelum jam 15:00 ya."

Pesan itu memuat enam pertanyaan:

1. Apa saja yang dihapus atau dimatikan di `JKT-WS-0528`, dan bagaimana mengelompokkannya supaya tahu ke mana mencari?
2. Benarkah log Security dibersihkan, periode mana yang hilang secara lokal, dan apa yang membuktikannya?
3. Apakah USN journal dihapus atau dibuat ulang, dan apa jejaknya?
4. Berkas apa yang dihancurkan alat wiping, dan masih bisakah namanya diketahui?
5. Telemetri apa yang dimatikan (Sysmon, prefetch, shadow copy), dan bagaimana membuktikannya tanpa bergantung pada ketiadaan data?
6. Sumber di luar host mana yang masih utuh, dan kalimat apa yang aman ditulis tentang periode yang hilang?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, dan pertanyaan 6 di bagian 1.6 dan 1.7; timestomping lanjutan dibahas tersendiri di bagian 1.6. Bagian 2 berisi perintah, hasil ilustrasi, dan jawaban tertulis yang kamu kirim ke Sari.

**Kapan relevan:** saat triage atau image menemukan tanda penghilangan jejak (log pendek, journal yang baru, alat wiping di artefak eksekusi, telemetri yang tiba-tiba berhenti), untuk menentukan apa yang hilang, apa yang masih bisa dibuktikan, dan sumber mana di luar host yang menutup celahnya.
**Kapan bukan jawaban:** Day ini bukan panduan membangun teknik anti-forensik (semua dibahas dari sisi jejak dan deteksi), bukan pengganti arsitektur log forwarding dan EDR yang justru membuat anti-forensik lokal tidak ada gunanya, dan bukan tempat menilai niat; ketiadaan data yang tidak disertai bekas penghapusan lebih sering masalah operasional daripada anti-forensik.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (event 1102, 104, 4719, `EventRecordID`, audit policy, Logon ID, `$MFT`, `$J`, SI dan FN, MACB, timestomping, Prefetch, Amcache, Shimcache, Sysmon, shadow copy, salinan kerja, jejak responder, super-timeline) tidak diulang. Tabel ini hanya memuat istilah baru Day ini; kolom padanan memakai analogi NOC dan SOC yang sama di semua Day.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Anti-forensik | Tindakan menghilangkan, mengubah, atau mencegah terbentuknya bukti di host | Menghapus baris konfigurasi dan menjalankan `clear logging` setelah mengutak-atik perangkat |
| Penghapusan adalah penulisan | Prinsip bahwa menghapus data di volume hidup tetap menulis ke volume itu dan tercatat | `no` sebuah baris konfigurasi tetap muncul di `archive log config` |
| `fsutil usn deletejournal` | Perintah yang menonaktifkan atau menghapus USN journal aktif pada sebuah volume | `clear` buffer log perubahan di perangkat, lalu buffer dimulai ulang |
| `UsnJournalID` | Identitas journal; journal diberi ID baru saat dibuat dan bisa dicap ID baru selama hidupnya | Nomor seri modul baru setelah RMA; ID lama tidak kembali |
| `LowestValidUsn` | USN pertama yang ditulis untuk instance journal ini; nilai lebih rendah menandakan journal dicap ulang | Penanda "log dimulai dari sini"; entri lebih tua berarti buffer sudah di-reset |
| Secure delete (SDelete) | Alat yang menimpa isi berkas lalu mengganti namanya berulang agar nama lama tak terbaca | Menimpa isi dan label modul sebelum dibuang, bukan sekadar melepasnya dari rak |
| FileBlockShredding (Sysmon EID 28) | Event Sysmon yang mendeteksi dan memblokir shredding berkas oleh alat seperti SDelete | Fitur perangkat yang menolak perintah `erase` dan mencatat percobaannya |
| Log forwarding ke SIEM | Pengiriman event log keluar host secara terus-menerus ke Splunk sebelum sempat dihapus lokal | Syslog dan NetFlow yang sudah mengalir ke collector sebelum engineer menyentuh perangkat |
| Indicator Removal (ATT&CK) | Keluarga teknik penghapusan jejak; sebagian pindah ke Disable or Modify Tools di ATT&CK v19 ke atas | Taksonomi gangguan yang nomor dan namanya berubah antar rilis dokumentasi |

### 1.1 Empat keluarga teknik dan prinsip penghapusan adalah penulisan

Pertanyaan pertama Sari ("apa saja yang dihapus atau dimatikan, dan ke mana mencari") paling mudah dijawab bila teknik anti-forensik dikelompokkan dulu, karena kelompok menentukan ke mana kamu mencari.

Tabel berikut mengelompokkan teknik menjadi empat keluarga; baca kolom "Yang biasanya tertinggal", karena di situlah pemeriksaan dimulai.

| Keluarga | Contoh | Yang hilang | Yang biasanya tertinggal |
|---|---|---|---|
| Menghapus bukti | Bersihkan event log, hapus USN journal, hapus shadow copy | Isi log, riwayat perubahan berkas, versi lama berkas | Event pembersihan (1102, 104), `UsnJournalID` baru dan `LowestValidUsn` diskontinu, perintah di artefak eksekusi |
| Mengubah bukti | Timestomping, memalsukan nama atau waktu | Keandalan urutan waktu | Ketidakcocokan antar sumber timestamp, urutan nomor entry MFT |
| Mencegah perekaman | Matikan Sysmon, ubah audit policy, matikan prefetch | Telemetri sejak saat itu | Event perubahan konfigurasinya (7036, EID 4, 4719), waktu tulis kunci registry, kekosongan yang dimulai pada satu titik |
| Menghancurkan data | Wiping berkas, wiping ruang kosong | Isi berkas yang bisa dipulihkan | Pola nama khas alat wiping di MFT dan journal, Prefetch dan Amcache alatnya |

Pembedaan ini berguna karena menentukan jenis pertanyaan. Untuk keluarga pertama dan keempat, carilah peristiwanya dan pola khasnya. Untuk keluarga kedua, carilah ketidakcocokan antar sumber. Untuk keluarga ketiga, carilah perubahan konfigurasinya, bukan ketiadaan datanya, karena ketiadaan data bisa berarti banyak hal.

Di belakang keempatnya ada satu prinsip. Satu-satunya cara menghapus data di volume yang hidup adalah menulis ke volume itu, dan penulisan tercatat di USN journal, di `$LogFile`, dan sering di MFT sebagai entry baru atau entry yang dipakai ulang. Konsekuensi praktisnya ada dua. Pertama, urutan pemeriksaan: periksa artefak yang paling mahal dibersihkan lebih dulu, karena penyerang paling sering berhenti di situ. Kedua, dan ini yang menentukan di lingkungan ber-EDR seperti `JKT-WS-0528`, penghapusan lokal tidak menyentuh salinan yang sudah terkirim keluar host. Log Security yang diteruskan ke Splunk, telemetri Sysmon sebelum service-nya dihapus, kejadian yang sudah sampai ke cloud Defender, dan autentikasi yang tercatat di domain controller semuanya berada di luar jangkauan perintah penghapusan di host. Itulah kenapa, di host yang dikonfigurasi dengan benar, anti-forensik lokal hampir tidak ada gunanya, dan kenapa jawaban paling kuat untuk Sari sering datang dari luar laptop.

### 1.2 Pembersihan event log dan batasnya

Pertanyaan kedua Sari ("benarkah Security dibersihkan, periode mana yang hilang") dijawab dari dua lapis: cari peristiwa pembersihannya, lalu periksa kesinambungan nomor rekaman, lalu bandingkan dengan salinan di luar host.

Membersihkan log Security menghasilkan event 1102 di log yang baru saja dibersihkan; event itu ditulis oleh provider `Microsoft-Windows-Eventlog` dan memuat SID, nama akun, domain, dan Logon ID yang membersihkannya [S3]. Membersihkan log lain seperti System menghasilkan event 104 di System [S4]. Keduanya adalah hal yang sama anehnya: catatan tentang penghapusan catatan. Microsoft menyatakan 1102 adalah event yang biasanya tidak perlu terlihat, karena hampir tidak ada alasan membersihkan log Security secara manual, dan menyarankan memantau serta menyelidiki kemunculannya [S3].

Penyerang yang tahu hal ini punya pilihan, dan keduanya bisa dideteksi:

- **Membersihkan satu kali.** Log yang baru dibersihkan mulai dari `EventRecordID` kecil, dan 1102 muncul sebagai salah satu rekaman pertama, karena catatan pembersihan ditulis ke log yang sudah kosong. Pembersihan satu kali justru meninggalkan buktinya sendiri secara utuh.
- **Membersihkan dua kali atau menghapus rekaman tertentu.** Pembersihan kedua ikut menghapus 1102 yang pertama, tetapi menyisakan log yang isinya mencurigakan pendek dengan `EventRecordID` yang dimulai dari angka kecil di mesin yang sudah lama berjalan. Penghapusan rekaman tertentu dengan alat khusus meninggalkan diskontinuitas `EventRecordID` di dalam satu berkas EVTX.

Karena itu pemeriksaan event log selalu dua lapis: cari peristiwa pembersihannya (1102 di Security, 104 di System, dan 4719 untuk perubahan audit policy), lalu periksa kesinambungan `EventRecordID`. Satu fakta membuat lapis pertama lebih tajam: hak membersihkan log Security adalah `SeSecurityPrivilege`, salah satu hak sensitif yang memicu 4672 saat diberikan ke sesi (Day 05 bagian 1.6). Sesi pengguna biasa tanpa 4672 tidak memegang hak itu, jadi pembersihan Security selalu menunjuk ke sesi yang terangkat.

Lapis ketiga, yang mengubah seluruh perhitungan, adalah sumber di luar host. Kalau host meneruskan log ke SIEM, bandingkan rentang waktu dan jumlah event per periode di berkas lokal dengan yang ada di SIEM; selisihnya adalah perkiraan apa yang hilang secara lokal, dan isi periode yang hilang justru masih bisa dibaca di SIEM. Di `JKT-WS-0528` yang ber-EDR dan meneruskan `wineventlog` ke Splunk, pembersihan lokal tidak menghapus apa pun yang sudah terkirim. Event 4719 ditulis setiap kali audit policy sistem berubah, terlepas dari setting subkategori Audit Policy Change, dan memuat akun serta subkategori yang diubah [S5]; kemunculannya bersama kekosongan event adalah sinyal audit policy sengaja diubah.

Satu catatan taksonomi untuk laporan yang dibaca tim deteksi: di ATT&CK v19 ke atas, membersihkan Windows event log tidak lagi berada di bawah Indicator Removal. Teknik Clear Windows Event Logs yang dulu bernomor T1070.001 direvoke dan menjadi sub-teknik T1685.005 di bawah Disable or Modify Tools (T1685), pada taktik baru Defense Impairment (TA0112); menonaktifkan Windows event logging yang dulu T1562.002 menjadi T1685.001 [S6][S7]. Dokumentasi dan rule lama masih memakai nomor lama, jadi kenali keduanya saat memetakan temuan ke rule.

### 1.3 Penghapusan dan pembuatan ulang USN journal

Pertanyaan ketiga Sari ("USN journal aneh, cek") adalah pertanyaan tentang keluarga pertama, dan artefak ini mahal dibersihkan, jadi sering menjadi titik berhenti penyerang.

`fsutil usn deletejournal` menghapus atau menonaktifkan USN journal aktif. Opsi `/d` menonaktifkan journal dan mengembalikan kendali I/O selama proses berlangsung, sedangkan `/n` baru mengembalikan kendali setelah selesai [S1]. Dokumentasi Microsoft menegaskan bahwa menghapus atau menonaktifkan journal aktif sangat memakan waktu, karena sistem harus mengakses seluruh rekaman di master file table (MFT) dan menyetel atribut last USN setiap berkas menjadi nol; prosesnya bisa memakan beberapa menit dan berlanjut setelah sistem dinyalakan ulang bila perlu, dan selama itu journal tidak dianggap aktif maupun dinonaktifkan sehingga setiap operasi journal mengembalikan galat [S1][S8]. Dokumentasi struktur journal menambahkan bahwa journal diberi identitas baru saat dibuat dan bisa dicap identitas baru selama hidupnya, dan identitas ini dipakai NTFS untuk pemeriksaan integritas [S9].

Dari fakta itu lahir tiga pemeriksaan yang berguna bagi pemeriksa, dan yang ketiga adalah sinyal yang paling tepat:

- **Journal bukan tindakan senyap.** Penghapusan menulis ke seluruh MFT (menyetel last USN ke nol), yaitu tulisan masif yang mengubah waktu modifikasi `$MFT` itu sendiri dan memakan waktu yang terlihat di artefak lain.
- **`UsnJournalID` baru.** Journal yang dibuat ulang punya identitas yang berbeda dari identitas sebelumnya. Bila kamu punya nilai journal lama dari koleksi atau image sebelumnya, identitas yang berubah membuktikan journal diganti.
- **`LowestValidUsn` dan diskontinuitas.** Dokumentasi mendefinisikan `LowestValidUsn` sebagai rekaman pertama yang ditulis untuk instance journal ini; bila enumerasi berkas mengembalikan USN yang lebih rendah dari nilai ini, journal telah dicap identitas baru sejak USN terakhir ditulis, dan ini menandakan diskontinuitas: perubahan pada sebagian atau seluruh berkas bisa terjadi tanpa tercatat di journal [S9]. Di lapangan, tandanya sederhana: `First Usn` yang mendekati nol dengan `Next Usn` yang kecil pada sistem yang sudah berjalan berminggu-minggu, ditambah rekaman tertua `$J` yang baru beberapa jam atau hari, padahal host dipakai jauh lebih lama.

`fsutil usn queryjournal` menampilkan nilai-nilai ini pada host hidup [S1]; pada image, bacanya dari rekaman tertua `$J` dan dari struktur journal yang diparse. Perintah penghapusannya sendiri (`fsutil.exe deletejournal`) muncul sebagai eksekusi di Prefetch dan Amcache (Day 07) dan, bila diteruskan sebelum telemetri dimatikan, sebagai 4688 atau Sysmon 1 di Splunk. Yang hilang bukan sekadar daftar perubahan: jendela `$J` untuk periode sebelum penghapusan lenyap dari host, sehingga pertanyaan "berkas apa yang berubah sebelum itu" harus dijawab dari SIEM dan EDR, bukan dari journal. Perhatian satu hal: pada volume yang journal-nya memang tidak pernah aktif, tidak ada yang bisa disimpulkan; periksa dulu apakah journal seharusnya ada.

### 1.4 Penghancuran data: SDelete, cipher, dan shadow copy

Pertanyaan keempat Sari ("berkas apa yang dihancurkan, masih bisakah namanya diketahui") menyentuh keluarga keempat, dan di sinilah pola nama khas alat wiping menjadi sidik jari yang sangat spesifik.

SDelete adalah alat secure delete dari Sysinternals yang menimpa isi berkas memakai standar DOD 5220.22-M [S2]. Dua perilakunya penting bagi pemeriksa. Pertama, untuk menimpa nama berkas yang dihapus, SDelete mengganti nama berkas 26 kali, tiap kali mengganti setiap karakter nama dengan huruf alfabet berurutan, sehingga penggantian pertama atas `foo.txt` menjadi `AAA.AAA` [S2]. Rantai penggantian nama dari A sampai Z pada berkas yang sama adalah tanda yang sangat khas. Kedua, saat membersihkan ruang kosong di NTFS, SDelete juga mengisi rekaman MFT yang kosong dengan berkas kecil sampai tidak bisa membuat berkas baru lagi, meninggalkan ledakan pembuatan dan penghapusan berkas kecil [S2].

Dokumentasinya juga menyebut hal yang sering disalahpahami, dan penting untuk ditulis benar di laporan:

- **Default satu pass, bukan tiga.** Opsi `-p` menentukan jumlah pass, dan bawaannya satu [S2]. Menuliskan "tiga pass" tanpa dasar adalah kesalahan.
- **Nama berkas di ruang kosong tidak dihapus aman.** SDelete menghapus isi berkas secara aman, tetapi bukan nama berkas yang berada di ruang kosong disk; menghapusnya butuh manipulasi langsung struktur direktori yang tidak ia lakukan [S2]. Jadi nama berkas lama kadang masih terbaca di slack direktori meski isinya hilang.
- **Berkas terkompresi, terenkripsi, dan sparse** ditangani lewat API defragmentasi untuk menemukan cluster yang benar lalu ditimpa lewat akses raw [S2].

Di mana jejaknya masih terbaca sangat bergantung pada apakah USN journal masih utuh. Bila `$J` masih ada, rantai penggantian nama A sampai Z terbaca langsung di journal, dan nama asli berkas ada di baris `RenameOldName` pertama. Bila `$J` sudah dihapus (seperti di kasus ini), yang tersisa di host adalah rekaman MFT bebas (`InUse` false) dengan nama berpola huruf berulang, Prefetch `SDELETE64.EXE` dengan waktu run, dan SHA-1 di Amcache. Nama asli berkas yang dihancurkan kemudian hanya bisa dipulihkan dari telemetri yang diteruskan sebelum Sysmon dimatikan: Sysmon mencatat penghapusan berkas lewat EID 23 (FileDelete archived, yang juga menyimpan salinan berkas di `ArchiveDirectory`) dan EID 26 (FileDeleteDetected, mencatat tanpa menyimpan), dan rantai penggantian namanya lewat EID 11 dan EID 2 [S10]. Ada satu fitur Sysmon yang justru bisa menggagalkan wiping: EID 28 (FileBlockShredding) mendeteksi dan memblokir shredding berkas dari alat seperti SDelete [S10]; bila konfigurasi Sysmon host mengaktifkannya, wiping gagal dan percobaannya tercatat. Konfigurasi Sysmon PT JAB tidak mengaktifkan FileBlockShredding (celah yang layak masuk rekomendasi), sehingga wiping berhasil, tetapi EID 26 dan EID 2 tetap tercatat dan diteruskan ke Splunk sebelum Sysmon dihapus.

Dua teknik penghancuran lain yang perlu dikenali:

- **`cipher /w`** menimpa ruang kosong pada volume; ia tidak menghapus berkas yang masih ada, hanya data yang sudah tidak teralokasi [S11]. Keberadaannya menunjukkan niat menghilangkan data yang sudah dihapus sebelumnya, bukan menghapus berkas aktif.
- **`vssadmin delete shadows`** menghapus shadow copy, dipetakan ke T1490 Inhibit System Recovery, dan lebih sering muncul pada ransomware daripada pada operasi yang berhati-hati [S12][S13]. Penting: bila host memang tidak punya shadow copy (System Protection sering mati di workstation), perintah ini berjalan tetapi tidak menghapus apa pun. Eksekusinya tetap jejak waktu, tetapi efeknya nol, dan kamu tidak boleh menyimpulkan ada shadow copy yang dihancurkan hanya dari perintahnya.

### 1.5 Mencegah perekaman: Sysmon, prefetch, dan audit policy

Pertanyaan kelima Sari ("telemetri apa yang dimatikan, buktikan tanpa bergantung pada ketiadaan data") adalah keluarga ketiga, dan aturannya satu: cari perubahannya, bukan ketiadaannya.

Lebih efisien bagi penyerang mencegah bukti terbentuk daripada menghapusnya. Tempat yang biasa disentuh dan jejak perubahannya:

- **Sysmon dihapus atau dihentikan.** Sysmon berjalan sebagai protected process sehingga tidak bisa diutak-atik dari user mode biasa, tetapi admin bisa menghapusnya dengan `sysmon64 -u` [S10]. Penghentian atau penghapusan service meninggalkan jejak di beberapa tempat: Sysmon sendiri menulis EID 4 (Sysmon service state changed, started atau stopped) yang tidak bisa difilter, sehingga event terakhir di channel Sysmon adalah catatan bahwa service berhenti [S10]; System log mencatat 7036 (service masuk keadaan stopped) dan, bila dipasang ulang kelak, 7045; driver `SysmonDrv` ikut dilepas. EID 16 mencatat perubahan konfigurasi Sysmon, juga tidak bisa difilter [S10]. Semua event Sysmon sampai detik penghapusan sudah diteruskan ke Splunk.
- **Prefetch dimatikan.** Nilai registry `EnablePrefetcher` di `SYSTEM\...\Memory Management\PrefetchParameters` yang disetel 0 mematikan prefetch. Yang diperiksa bukan ketiadaan `.pf`, melainkan waktu tulis kunci registry itu dibandingkan dengan waktu `.pf` terakhir yang ada: bila prefetch berhenti tepat setelah kunci itu ditulis, hubungannya kuat (Day 09 untuk membaca waktu tulis registry).
- **Audit policy diubah.** Perubahan audit policy menulis 4719 dengan akun dan subkategori yang diubah, terlepas dari setting Audit Policy Change [S5]. Bandingkan waktu 4719 dengan jenis event yang tiba-tiba berhenti muncul.

Pemeriksaannya bukan mencari ketiadaan, melainkan mencari perubahannya, karena ketiadaan data bisa berarti telemetri memang tidak pernah aktif, host sedang tidur, atau pengiriman tertunda. Perubahan konfigurasi punya waktu dan pelaku; bandingkan waktu perubahan itu dengan garis waktu aktivitas lain. Konfigurasi telemetri yang berubah tepat sebelum kekosongan data adalah temuan; kekosongan tanpa perubahan konfigurasi biasanya masalah operasional (Day 05 bagian 1.5 untuk membaca audit policy dari konfigurasi, bukan dari ketiadaan event).

### 1.6 Timestomping di luar perbandingan SI dan FN

Pertanyaan tentang satu berkas yang waktunya dipalsukan adalah keluarga kedua. Day 08 bagian 1.3 sudah membahas perbandingan SI dan FN serta batasnya; di sini ditambahkan lapis yang berguna ketika heuristik itu tidak memberi jawaban, dipetakan ke T1070.006 Timestomp yang masih berada di bawah Indicator Removal (T1070) pada taktik Stealth di ATT&CK v20 [S6].

Tiga lapis tambahan di luar perbandingan SI dan FN:

- **Urutan nomor rekaman MFT.** Nomor entry dialokasikan kurang lebih berurutan. Berkas yang menurut timestamp dibuat bertahun lalu tetapi menempati nomor entry di antara berkas-berkas yang baru dibuat adalah anomali yang tidak bisa diperbaiki dengan mengubah timestamp, karena nomor entry bukan timestamp dan tidak ikut dipalsukan saat SI diubah.
- **Artefak lain yang menyebut berkas yang sama.** Prefetch, Shimcache, dan Amcache menyimpan waktu sendiri (Day 07). Timestomping biasanya hanya menyentuh timestamp di file system, sehingga waktu di artefak eksekusi untuk berkas yang sama sering tidak ikut berubah dan bertentangan dengan SI palsu.
- **USN journal.** Journal mencatat kapan berkas benar-benar dibuat dan diubah lewat `FileCreate` dan `BasicInfoChange`, terlepas dari isi timestamp (Day 08 bagian 1.4). Record `BasicInfoChange` yang muncul setelah `FileCreate` pada berkas yang timestamp-nya mencurigakan adalah penanda pemalsuan. Di host ini journal sudah dihapus, jadi lapis ini pindah ke Splunk (Sysmon EID 2, A process changed a file creation time, yang justru dirancang menangkap timestomping) [S10].

Aturan laporan yang berlaku untuk seluruh Day ini: satu tanda bukan kesimpulan. Sebutkan heuristik yang dipakai, sebutkan batasnya, dan nyatakan tingkat keyakinan (Day 19 bagian 1.4). Perbandingan SI dan FN bisa gagal bila penyerang memindah atau me-rename berkas setelah memalsukan SI, karena FN ikut tersalin palsu (Day 08 bagian 1.3); di situlah nomor entry MFT dan artefak eksekusi menjadi bukti independen.

### 1.7 Keyakinan, sumber di luar host, dan kalimat tentang periode yang hilang

Pertanyaan terakhir Sari ("sumber mana yang utuh, kalimat apa yang aman") adalah bagian yang menentukan apakah laporan anti-forensik bisa dipakai tanpa melebih-lebihkan.

Di host ber-EDR yang meneruskan log, sumber di luar host hampir selalu menutup sebagian besar yang dihapus lokal. Tabel berikut memetakan tiap teknik ke sumber luar yang menutupnya; baca kolom "Sumber luar yang utuh", karena itulah yang kamu minta dan kutip di laporan.

| Dihapus atau dimatikan di host | Jejak lokal yang tersisa | Sumber luar yang utuh |
|---|---|---|
| Log Security dibersihkan | 1102 di Security baru, `EventRecordID` restart | Splunk index `wineventlog` (diteruskan sebelum clear), log autentikasi di `JKT-DC01` |
| USN journal dihapus | `UsnJournalID` baru, `LowestValidUsn` diskontinu, `$J` pendek, fsutil di Prefetch | Perubahan berkas sebelum penghapusan: Splunk index `sysmon` (EID 11), Defender cloud |
| Berkas di-wipe (SDelete) | Pola nama A..Z di MFT, Prefetch dan Amcache SDelete | Nama asli berkas: Splunk index `sysmon` (EID 26, EID 2), Defender `DeviceFileEvents` |
| Sysmon dihapus | EID 4 stop (event terakhir), 7036 di System, driver dilepas | Seluruh event Sysmon sebelum penghapusan di Splunk index `sysmon` |
| Prefetch dimatikan | `EnablePrefetcher`=0 dan waktu tulis kunci | Eksekusi tetap terlihat di Splunk dan Defender bila sensor masih hidup |
| Perintah anti-forensik | Prefetch dan Amcache alatnya | 4688 dan Sysmon 1 di Splunk, `DeviceProcessEvents` Defender |

Tiga aturan menulis kalimatnya:

- **Pisahkan "tidak bisa dipulihkan dari host ini" dari "tidak terjadi".** Kalimat yang aman menyebut jendela yang hilang secara lokal dan sumber yang menutupnya: "Log Security lokal untuk periode sebelum pembersihan pukul X tidak lagi ada di host, tetapi event untuk periode itu tersedia di Splunk index `wineventlog` sampai batas retensi." Hindari "tidak ada logon sebelum X", karena itu mengklaim sesuatu yang justru dibantah oleh salinan di SIEM.
- **Sebut yang benar-benar tidak bisa dipulihkan.** Isi berkas yang di-wipe SDelete tidak bisa dipulihkan dari mana pun; yang tersisa hanya namanya (dari MFT atau telemetri yang diteruskan). Aktivitas lokal pada celah antara checkpoint pengiriman terakhir dan saat telemetri dimatikan juga tidak bisa dipulihkan bila forwarder sempat tertinggal; sebut celah itu, jangan diabaikan.
- **Pembersihan adalah temuan tersendiri.** Pembersihan log dan penghapusan journal dicatat sebagai tindakan dengan waktu, akun, dan cara, bukan dilewati. Keyakinan untuk "upaya anti-forensik dilakukan" tinggi (buktinya ada di bekas penghapusan dan di telemetri yang diteruskan); keyakinan untuk "apa persisnya yang hilang" sering sedang, dan ditulis sebagai rentang dengan alasannya (Day 19 bagian 1.4).

## 2. Contoh dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi yang disusun untuk kasus ini, bukan hasil eksekusi. Perintah EZ Tools dan `fsutil` dijalankan di workstation analisis forensik internal `JKT-DFIR01` atas salinan kerja `E01-W1` yang di-mount read-only, bukan atas sistem produksi; kueri Splunk dijalankan di search head SOC dan kueri advanced hunting di portal Defender, keduanya dengan akun analyst. Perintah anti-forensik ditampilkan hanya sebagai jejak yang dibaca, bukan untuk dijalankan di sistem bukti. Nama kolom CSV, event ID, dan nama field bisa berbeda antar versi alat dan build Windows; cocokkan dengan versi di lab-mu. Narasi memakai WIB (UTC+7); setiap keluaran alat diberi label zona waktunya, karena EvtxECmd, RECmd, MFTECmd, dan PECmd menulis waktu dalam UTC (UTC = WIB dikurangi 7 jam), Splunk menampilkan waktu sesuai zona akun (di sini WIB), dan advanced hunting memakai UTC.

Nomor bukti di Day ini (ditetapkan untuk `INC-2027-011`): `INC-2027-011-E01` image disk `JKT-WS-0528` (EWF, diambil Yoga Senin 2027-02-01 setelah isolasi EDR, SHA-256 `d7f2...`); salinan kerja internal `E01-W1` dibuat Yoga Selasa 2027-02-02 09:10 setelah verifikasi hash master. Rangkaian anti-forensik terjadi Minggu 2027-01-31 malam WIB.

### 2.1 Menyiapkan E01-W1 dan mendaftar sumber di luar host

Langkah ini menyiapkan salinan kerja dan, yang khas untuk kasus anti-forensik, mendaftar sumber di luar host lebih dulu, karena di situlah banyak jawaban berada.

```
Get-FileHash -Path E01-W1.E01 -Algorithm SHA256
# mount read-only (huruf drive contoh G:), lalu parse dari drive itu
```

| Langkah | Tujuan |
|---|---|
| Verifikasi hash E01-W1 terhadap master | Memastikan salinan kerja identik dengan master sebelum analisis |
| Mount read-only `G:` | Mencegah perubahan pada salinan kerja; hash tetap pembuktinya |
| Daftar sumber luar | Catat index Splunk yang menerima host ini (`wineventlog`, `sysmon`, `powershell`), ketersediaan data Defender, dan log `JKT-DC01` sebelum menyimpulkan apa pun hilang |

**Cara membaca hasil:** hash cocok (`d7f2...`) berarti salinan kerja siap. `JKT-WS-0528` di OU `Workstations-EDR` meneruskan event log ke Splunk lewat universal forwarder dan onboard ke Microsoft Defender for Endpoint, jadi tiga sumber luar tersedia sebelum analisis host dimulai: Splunk (retensi `wineventlog` 180 hari, `sysmon` dan `powershell` lebih pendek), advanced hunting Defender (data mentah sampai 30 hari), dan log autentikasi domain di `JKT-DC01`.

**Kapan gagal:** `Mount-DiskImage` di Windows me-mount read-write secara bawaan. Pastikan opsi read-only dipakai atau mount di VM analisis dengan lapisan read-only; hash sebelum dan sesudah membuktikan tidak ada perubahan (Day 02).

### 2.2 Pembersihan Security log: 1102 lokal dan periode yang hilang

Langkah ini menjawab pertanyaan kedua Sari. Mulai dengan profil cakupan semua channel, lalu cari event pembersihan, lalu bandingkan dengan Splunk.

```powershell
$e = Import-Csv 'G:\...\analysis\E01-W1\EZ-2026.5.0\EventLogs\E01-W1_evtx.csv'
$e | Group-Object Channel | ForEach-Object {
    $t = $_.Group.TimeCreated | Sort-Object
    [pscustomobject]@{ Channel = $_.Name; Jumlah = $_.Count; Pertama = $t[0]; Terakhir = $t[-1] }
} | Sort-Object Jumlah -Descending | Select-Object -First 5 | Format-Table -AutoSize
```

Keluaran ilustrasi (waktu UTC):

```
Channel                                    Jumlah Pertama                     Terakhir
-------                                    ------ -------                     --------
Microsoft-Windows-Sysmon/Operational        38104 2027-01-19 02:10:44.1180331 2027-01-31 14:55:40.6020110
System                                       6213  2026-11-02 01:12:07.5512807 2027-02-01 03:41:52.0098116
Security                                     642   2027-01-31 15:05:14.4402176 2027-02-01 03:40:11.7719052
Microsoft-Windows-TaskScheduler/Operational  2991  2027-01-08 23:51:07.3310482 2027-02-01 03:36:03.0127755
Microsoft-Windows-PowerShell/Operational     1788  2026-12-30 01:44:19.9061223 2027-02-01 03:35:04.2290148
```

**Cara membaca hasil:**

- Security hanya memuat 642 event, dan event paling awalnya 2027-01-31 15:05:14 UTC (Minggu 22:05:14 WIB), padahal channel lain mencakup berminggu-minggu ke belakang. Ini ciri log yang baru dibersihkan.
- Channel Sysmon berhenti 2027-01-31 14:55:40 UTC (21:55:40 WIB), lebih awal daripada channel lain yang berlanjut sampai isolasi Senin, yaitu tanda Sysmon dimatikan pada waktu itu (bagian 2.5).
- System tetap panjang (sejak 2026-11-02), jadi System tidak dibersihkan.

Cari event pembersihan dan periksa kesinambungan nomor rekaman:

```powershell
$e | Where-Object { ($_.Channel -eq 'Security' -and $_.EventId -in '1102','4719') -or
                    ($_.Channel -eq 'System' -and $_.EventId -eq '104') } |
    Select-Object TimeCreated, Channel, EventId, UserName, RecordNumber | Format-Table -AutoSize
```

Keluaran ilustrasi (waktu UTC):

```
TimeCreated                 Channel   EventId  UserName         RecordNumber
2027-01-31 15:05:14.440     Security  1102     JAB\adm.rizal    1
2027-01-31 15:06:02.118     Security  4719     JAB\adm.rizal    5
```

**Cara membaca hasil:** 1102 ada di Security sebagai `RecordNumber` 1, dibuat `JAB\adm.rizal` Minggu 2027-01-31 22:05:14 WIB. Record bernilai 1 pada mesin yang sudah berjalan berbulan-bulan adalah tanda kuat log dibersihkan satu kali, bukan dua kali, karena 1102-nya justru selamat. Event 4719 sesudahnya menunjukkan audit policy juga disentuh pada menit yang sama. Tidak ada 104 di System, jadi System tidak dibersihkan. Hak membersihkan Security butuh `SeSecurityPrivilege`, jadi tindakan ini menunjuk sesi `adm.rizal` yang terangkat, bukan sesi pengguna biasa.

Lalu bandingkan dengan Splunk untuk mengukur yang hilang dan memulihkan isinya:

```
index=wineventlog host=JKT-WS-0528 source="WinEventLog:Security"
earliest="01/05/2027:00:00:00" latest="01/31/2027:22:05:14"
| stats count min(_time) as awal max(_time) as akhir
```

Keluaran ilustrasi (waktu WIB):

```
count  awal                 akhir
58122  2027-01-05 08:00:11  2027-01-31 22:05:10
```

**Cara membaca hasil:** Splunk memegang 58.122 event Security untuk periode 5 sampai 31 Januari yang di host lokal sudah hilang (hanya 642 yang tersisa, semuanya setelah pembersihan). Event terakhir yang diteruskan pukul 22:05:10 WIB, empat detik sebelum pembersihan 22:05:14, jadi celah lokal yang benar-benar tidak tertutup hanya sekitar empat detik. Isi periode yang hilang secara lokal bisa dibaca penuh di Splunk sampai batas retensi 180 hari.

**Kalimat untuk Sari:** "Log Security di `JKT-WS-0528` dibersihkan satu kali oleh `JAB\adm.rizal` Minggu 2027-01-31 pukul 22:05:14 WIB; event 1102 dan 4719 membuktikannya, dan System tidak ikut dibersihkan. Event Security lokal sebelum pukul 22:05 tidak lagi ada di host, tetapi 58.122 event untuk periode 5 sampai 31 Januari tersedia di Splunk index `wineventlog` sampai batas retensi, dengan celah tak tertutup hanya sekitar empat detik sebelum pembersihan."

**Kapan gagal:** hanya mencari 1102 di Security, padahal host yang Sysmon atau PowerShell-nya dibersihkan meninggalkan 104 di System, bukan 1102. Dan log yang memang baru dirotasi juga mulai dari nomor kecil; periksa ukuran maksimum channel dan apakah ada 1102 sebelum menyimpulkan.

### 2.3 USN journal: queryjournal, diskontinuitas, dan jendela yang hilang

Langkah ini menjawab pertanyaan ketiga. Baca nilai journal dari salinan kerja, lalu bandingkan dengan umur sistem.

```
fsutil usn queryjournal G:
```

Keluaran ilustrasi:

```
Usn Journal ID   : 0x01dd9f3a2c4b1e07
First Usn        : 0x0000000000000000
Next Usn         : 0x0000000000041a80
Lowest Valid Usn : 0x0000000000000000
Max Usn          : 0x07ffffffffff0000
Maximum Size     : 0x0000000002000000
Allocation Delta : 0x0000000000400000
```

**Cara membaca hasil:** `First Usn` nol dan `Next Usn` yang kecil (sekitar 270 KB terpakai) pada sistem yang sudah dipakai berminggu-minggu menandakan journal baru dibuat. Nilai `Usn Journal ID` adalah identitas journal saat ini; journal diberi identitas baru saat dibuat dan dicap identitas baru saat dibuat ulang, dan identitas ini dipakai NTFS untuk pemeriksaan integritas, sehingga identitas yang tidak cocok dengan koleksi sebelumnya membuktikan journal diganti [S1][S9]. Lihat juga jendela `$J` yang sebenarnya:

```
MFTECmd.exe -f "G:\$Extend\$UsnJrnl:$J" --csv C:\DFIR\out\INC-2027-011 --csvf E01-W1_J.csv
```

Keluaran ilustrasi (waktu UTC, dua baris ekstrem):

```
UpdateTimestamp              Name                 UpdateReasons
2027-01-31 15:10:02.330      <rekaman tertua>     FileCreate|Close
2027-02-01 03:41:48.117      <rekaman termuda>    DataExtend|Close
```

**Cara membaca hasil:** rekaman `$J` tertua hanya 2027-01-31 15:10:02 UTC (Minggu 22:10:02 WIB), sekitar lima menit setelah pembersihan log, padahal laptop dipakai sejak jauh sebelumnya. Jendela journal hanya mencakup kira-kira satu setengah hari, dari Minggu malam sampai image Senin. Diskontinuitas ini konsisten dengan `fsutil usn deletejournal` yang dijalankan Minggu malam: perintah itu mengakses seluruh rekaman MFT dan menyetel last USN tiap berkas ke nol, memakan waktu, lalu journal dibuat ulang dengan identitas baru [S1][S8]. Eksekusi `fsutil.exe` sendiri terlihat di Prefetch dan Amcache (bagian 2.4), dan perintah `deletejournal` terlihat di Splunk index `sysmon` sebagai Sysmon 1 yang diteruskan sebelum Sysmon dimatikan:

```
index=sysmon host=JKT-WS-0528 EventCode=1 Image="*\\fsutil.exe"
| table _time, User, CommandLine, ParentImage
```

Keluaran ilustrasi (waktu WIB):

```
_time                User           CommandLine                        ParentImage
2027-01-31 21:44:31  JAB\adm.rizal  fsutil usn deletejournal /d C:     C:\Windows\System32\cmd.exe
```

**Cara membaca hasil:** perintah penghapusan journal terekam di Splunk pukul 21:44:31 WIB oleh `adm.rizal`, lebih dari dua puluh menit sebelum pembersihan log, menautkan penghapusan journal ke sesi dan waktu yang sama. Perubahan berkas sebelum 21:44 yang hilang dari `$J` lokal harus dicari di Sysmon EID 11 di Splunk dan di Defender `DeviceFileEvents`, bukan dari journal.

**Kapan gagal:** pada volume yang journal-nya memang tidak pernah aktif, tidak ada yang bisa disimpulkan; periksa dulu apakah journal seharusnya ada. Bentuk keluaran `queryjournal` dan nama kolom MFTECmd berbeda antar versi; cocokkan dengan versi lab-mu.

### 2.4 Jejak SDelete di MFT, Prefetch, Amcache, dan telemetri yang diteruskan

Langkah ini menjawab pertanyaan keempat. Karena `$J` sudah dihapus, rantai nama A sampai Z tidak terbaca lagi dari journal lokal, jadi pemeriksaan bertumpu pada MFT, artefak eksekusi, dan telemetri yang diteruskan.

Mulai dari artefak eksekusi untuk memastikan alatnya dijalankan:

```
PECmd.exe -d "G:\Windows\Prefetch" --csv C:\DFIR\out\INC-2027-011 --csvf E01-W1_pf.csv
```

Keluaran ilustrasi (waktu UTC):

```
ExecutableName     RunCount  LastRun                  Hash      SourceFilename
SDELETE64.EXE      1         2027-01-31 14:42:11      3F2A9C1D  ...\AppData\Local\Temp\svc\SDELETE64.EXE
FSUTIL.EXE         3         2027-01-31 14:44:31      A14C7E59  C:\Windows\System32\FSUTIL.EXE
```

**Cara membaca hasil:** `SDELETE64.EXE` dijalankan Minggu 21:42:11 WIB dari folder Temp profil `rizal.fadillah`, dan `FSUTIL.EXE` 21:44:31 WIB, cocok dengan urutan di Splunk. Amcache mengonfirmasi identitasnya:

```
AmcacheParser.exe -f "G:\Windows\appcompat\Programs\Amcache.hve" --csv C:\DFIR\out\INC-2027-011
```

SHA-1 `SDELETE64.EXE` di Amcache (`e5a1...`) bisa dicocokkan dengan sampel SDelete resmi untuk memastikan itu memang SDelete, bukan berkas lain dengan nama sama [S2]. Di MFT, cari rekaman bebas dengan pola nama huruf berulang:

```
MFTECmd.exe -f "G:\$MFT" --csv C:\DFIR\out\INC-2027-011 --csvf E01-W1_mft.csv
# lalu saring InUse=false dan FileName berpola huruf berulang
```

Keluaran ilustrasi (waktu UTC):

```
EntryNumber  InUse  FileName    Created0x10            ParentPath
312540       False  ZZZ.ZZZ     2027-01-31 14:42:10    \Users\rizal.fadillah\AppData\Local\Temp\svc\stage
312541       False  ZZZ.ZZZ     2027-01-31 14:42:10    \Users\rizal.fadillah\AppData\Local\Temp\svc\stage
312542       False  ZZZ.ZZZ     2027-01-31 14:42:11    \Users\rizal.fadillah\AppData\Local\Temp\svc\stage
```

**Cara membaca hasil:** tiga rekaman MFT bebas dengan nama `ZZZ.ZZZ` di folder `stage` adalah sisa penggantian nama SDelete: nama berkas diganti 26 kali sampai huruf terakhir sebelum dihapus, sehingga nama terakhir yang tertinggal berpola satu huruf berulang [S2]. MFT menunjukkan ada tiga berkas yang dihancurkan di folder itu, tetapi tidak nama aslinya, karena nama asli hanya ada di rantai `RenameOldName` pertama yang kini hilang bersama `$J`. Nama asli dipulihkan dari telemetri yang diteruskan sebelum Sysmon dimatikan:

```
index=sysmon host=JKT-WS-0528 EventCode IN (26,11,2)
TargetFilename="*\\Temp\\svc\\stage\\*" earliest="01/31/2027:21:42:00" latest="01/31/2027:21:42:30"
| table _time, EventCode, TargetFilename
```

Keluaran ilustrasi (waktu WIB, disaring):

```
_time                EventCode  TargetFilename
2027-01-31 21:42:10  11         ...\stage\data-portal-ekspor.csv
2027-01-31 21:42:10  11         ...\stage\AAA.AAA
2027-01-31 21:42:10  26         ...\stage\ZZZ.ZZZ
2027-01-31 21:42:11  26         ...\stage\data-radius-dump.txt
2027-01-31 21:42:11  26         ...\stage\daftar-host.txt
```

**Cara membaca hasil:** Sysmon yang diteruskan menyimpan nama asli ketiga berkas yang dihancurkan (`data-portal-ekspor.csv`, `data-radius-dump.txt`, `daftar-host.txt`) beserta rantai penggantian nama dari `AAA.AAA` ke `ZZZ.ZZZ`, karena event itu sudah sampai ke Splunk sebelum Sysmon dihapus 21:55:40. Isi berkas tetap tidak bisa dipulihkan (SDelete menimpanya), tetapi namanya cukup untuk menunjukkan folder staging berisi dump data pelanggan dan daftar host. Konfigurasi Sysmon PT JAB tidak mengaktifkan FileBlockShredding (EID 28), sehingga wiping tidak diblokir; mengaktifkannya adalah rekomendasi yang layak ditulis [S10].

**Kapan gagal:** bila Sysmon tidak terpasang atau tidak meneruskan ke SIEM, nama asli berkas yang dihancurkan hilang total dan hanya pola `ZZZ.ZZZ` yang tersisa. Alat wiping lain yang tidak memakai pola rename A sampai Z tidak meninggalkan tanda ini; cari pola lain seperti ledakan pembuatan dan penghapusan berkas kecil.

### 2.5 Sysmon dan prefetch dimatikan: cari perubahannya

Langkah ini menjawab pertanyaan kelima. Jangan simpulkan dari ketiadaan data; cari peristiwa perubahannya.

Untuk Sysmon, event terakhir di channel-nya dan jejak di System:

```
# event terakhir channel Sysmon sudah terlihat di bagian 2.2 (berhenti 21:55:40 WIB)
EvtxECmd.exe -f "G:\...\System.evtx" --csv C:\DFIR\out\INC-2027-011 --csvf E01-W1_System.csv --maps ...\Maps
# saring 7036 untuk service Sysmon64
```

Keluaran ilustrasi (waktu UTC):

```
TimeCreated (UTC)     Channel  EventId  MapDescription                    Payload
2027-01-31 14:55:40   Sysmon   4        Sysmon service state changed       State: Stopped
2027-01-31 14:55:41   System   7036     Service entered the stopped state  Sysmon64
```

**Cara membaca hasil:** Sysmon menulis EID 4 (service state changed, Stopped) Minggu 21:55:40 WIB sebagai event terakhir di channel-nya, dan System mencatat 7036 service `Sysmon64` berhenti satu detik kemudian; EID 4 dan EID 16 tidak bisa difilter konfigurasi, jadi selalu tertulis [S10]. Karena System tidak dibersihkan, jejak ini selamat. Perintah penghapusannya terekam di Splunk sebelum Sysmon mati:

```
index=sysmon host=JKT-WS-0528 EventCode=1 (CommandLine="*sysmon*-u*")
| table _time, User, CommandLine
```

Keluaran ilustrasi (waktu WIB):

```
_time                User           CommandLine
2027-01-31 21:55:38  JAB\adm.rizal  sysmon64 -u force
```

Untuk prefetch, baca nilai registry dan waktu tulisnya dari salinan kerja:

```
RECmd.exe -f "G:\Windows\System32\config\SYSTEM" ^
  --kn "ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters"
```

Keluaran ilustrasi (last write UTC):

```
ValueName         ValueData   LastWriteTimestamp
EnablePrefetcher  0           2027-01-31 14:56:20
```

**Cara membaca hasil:** `EnablePrefetcher` bernilai 0 dengan waktu tulis kunci Minggu 21:56:20 WIB berarti prefetch dimatikan pada waktu itu. Buktinya bukan ketiadaan `.pf` baru, melainkan nilai dan waktu tulis kunci yang jatuh tepat setelah rangkaian anti-forensik lain. Prefetch `SDELETE64.EXE` dan `FSUTIL.EXE` tetap ada karena dibuat sebelum prefetch dimatikan (bagian 2.4).

**Kalimat untuk Sari:** "Sysmon dihapus dengan `sysmon64 -u force` pukul 21:55:38 WIB (Sysmon EID 4 Stopped dan System 7036 membuktikannya; System tidak dibersihkan sehingga jejak selamat), dan prefetch dimatikan lewat `EnablePrefetcher`=0 pukul 21:56:20 WIB. Telemetri Sysmon sampai pukul 21:55:40 sudah diteruskan ke Splunk; kekosongan Sysmon setelah itu adalah akibat penghapusan, bukan tidak ada aktivitas."

**Kapan gagal:** kekosongan data Sysmon tanpa 7036, EID 4, atau perubahan konfigurasi biasanya masalah operasional (service crash, disk penuh, antrean pengiriman), bukan anti-forensik; periksa dulu sebelum menyimpulkan. Prefetch yang memang mati bawaan di sebagian edisi server juga bukan temuan.

### 2.6 Timestomping `drvsync.exe`: SI vs FN dan nomor entry MFT

Langkah ini memeriksa satu berkas yang waktunya dipalsukan, memakai tiga sumber yang saling menguatkan.

```
# dari E01-W1_mft.csv: urutkan EntryNumber, bandingkan Created0x10 dan Created0x30
```

Keluaran ilustrasi (waktu UTC):

```
EntryNumber  FileName       Created0x10 (SI)       Created0x30 (FN)       SI<FN
312601       setup.etl      2027-01-29 02:13:40    2027-01-29 02:13:40
312604       drvsync.exe    2021-06-12 01:00:00    2027-01-29 02:14:05    YES
312607       update.log     2027-01-29 02:14:22    2027-01-29 02:14:22
```

**Cara membaca hasil:** entry 312604 (`C:\ProgramData\Intel\drvsync.exe`) mengaku dibuat 2021 di SI, tetapi FN-nya 2027-01-29 dan nomor entry-nya duduk di antara berkas yang dibuat pada menit yang sama di 2027. Tiga lapis sepakat berkas ini di-timestomp: SI jauh lebih tua dari FN, nomor entry MFT tidak bisa dipalsukan dengan mengubah timestamp dan menempatkannya di 2027, dan artefak eksekusi untuk berkas yang sama tidak ikut diubah. Karena `$J` lokal sudah dihapus, konfirmasi record `FileCreate` dan `BasicInfoChange` pindah ke Sysmon EID 2 (A process changed a file creation time) di Splunk, yang justru dirancang menangkap perubahan waktu pembuatan [S10]. Prefetch dan Shimcache untuk `drvsync.exe` menyimpan waktu 2027, bertentangan dengan SI palsu 2021 (Day 07).

**Kapan gagal:** bila penyerang memindah atau me-rename berkas setelah memalsukan SI, FN bisa ikut tersalin palsu dan perbandingan SI vs FN tidak menemukan apa pun (Day 08 bagian 1.3); di situ nomor entry MFT dan artefak eksekusi menjadi bukti independen. Nama kolom FN berbeda antar versi MFTECmd; cocokkan dengan versi lab.

### 2.7 Shadow copy dan `vssadmin`: eksekusi tanpa efek

Langkah ini memeriksa penghapusan shadow copy, dan menunjukkan kenapa eksekusi perintah tidak otomatis berarti ada yang dihancurkan.

```
index=sysmon host=JKT-WS-0528 EventCode=1 Image="*\\vssadmin.exe"
| table _time, User, CommandLine
```

Keluaran ilustrasi (waktu WIB):

```
_time                User           CommandLine
2027-01-31 21:58:50  JAB\adm.rizal  vssadmin delete shadows /all /quiet
```

**Cara membaca hasil:** `vssadmin delete shadows /all /quiet` dijalankan 21:58:50 WIB, dipetakan ke T1490 Inhibit System Recovery [S12][S13]. Tetapi System Protection sering mati di workstation, sehingga perlu diperiksa apakah ada shadow copy untuk dihapus. Keluaran console yang diteruskan (dan status di Defender) menunjukkan perintah mengembalikan pesan bahwa tidak ada item yang memenuhi kueri, artinya tidak ada shadow copy yang dihancurkan karena memang tidak ada. Eksekusinya tetap jejak waktu dan niat, tetapi kamu tidak boleh menulis "shadow copy dihapus"; yang benar adalah "perintah penghapusan shadow copy dijalankan, tetapi host tidak punya shadow copy, sehingga tidak ada versi lama berkas yang hilang karena perintah ini". Konfirmasi di image bahwa area penyimpanan shadow copy memang kosong.

**Kapan gagal:** menyimpulkan ada shadow copy yang dihancurkan hanya dari perintahnya; atau sebaliknya, mengira ketiadaan shadow copy berarti dihapus, padahal memang tidak pernah diaktifkan. Periksa konfigurasi dan isi area VSS di image sebelum menyimpulkan.

### 2.8 Garis waktu kurasi dan jawaban untuk Sari

Langkah ini menyatukan temuan menjadi garis waktu dan jawaban yang bisa dipakai di laporan dan PIR.

Garis waktu kurasi (WIB; sumber diberi label; jejak responder dipisahkan):

| Waktu (WIB) | Kejadian | Sumber | Keyakinan |
|---|---|---|---|
| Min 2027-01-31 21:40:02 | `adm.rizal` elevasi di sesi `rizal.fadillah` (4624 + 4672) | Splunk `wineventlog`, `JKT-DC01` | Tinggi |
| 21:42:10-21:42:11 | SDelete menghancurkan 3 berkas di folder `stage` | Prefetch, MFT, Splunk `sysmon` (EID 26/11) | Tinggi |
| 21:44:31 | `fsutil usn deletejournal /d C:` | Splunk `sysmon`, Prefetch, `$J` diskontinu | Tinggi |
| 21:52:xx | `drvsync.exe` di-timestomp ke 2021 | MFT (SI vs FN, EntryNumber), Splunk `sysmon` EID 2 | Tinggi |
| 21:55:38-21:55:41 | Sysmon dihapus (`sysmon64 -u force`) | Splunk `sysmon` (EID 4), System 7036 | Tinggi |
| 21:56:20 | Prefetch dimatikan (`EnablePrefetcher`=0) | RECmd SYSTEM (waktu tulis kunci) | Tinggi |
| 21:58:50 | `vssadmin delete shadows` dijalankan, tidak ada efek | Splunk `sysmon`, konfirmasi VSS kosong di image | Tinggi (eksekusi); efek nol |
| 22:05:14 | Log Security dibersihkan | 1102 lokal, Splunk `wineventlog` (periode hilang pulih) | Tinggi |
| Sen 2027-02-01 10:40 | Host diisolasi lewat EDR (responder) | Case notes, portal Defender | Tinggi |
| Sen 2027-02-01 sore | Image `INC-2027-011-E01` diambil Yoga (responder) | Case notes, chain of custody | Tinggi |

Jawaban tertulis untuk Sari (disimpan `\\jkt-evid01\cases\INC-2027-011\notes\anti-forensik-JKT-WS-0528-2027-02-02.md`):

- **Yang dihapus atau dimatikan:** log Security dibersihkan; USN journal dihapus dan dibuat ulang; tiga berkas staging dihancurkan dengan SDelete; satu berkas (`drvsync.exe`) di-timestomp; Sysmon dihapus dan prefetch dimatikan; `vssadmin delete shadows` dijalankan tanpa efek. Semua oleh `adm.rizal` Minggu 2027-01-31 antara 21:40 dan 22:05 WIB.
- **Yang dibuktikan dari bekas penghapusannya sendiri:** pembersihan log dari 1102 dan `EventRecordID` yang restart; penghapusan journal dari identitas journal baru, `LowestValidUsn` diskontinu, dan jendela `$J` yang hanya satu setengah hari; wiping dari pola nama `ZZZ.ZZZ` di MFT dan Prefetch SDelete; timestomping dari SI vs FN dan nomor entry MFT; Sysmon dimatikan dari EID 4 dan System 7036; prefetch dari nilai dan waktu tulis registry.
- **Sumber di luar host yang masih utuh:** Splunk index `wineventlog` (58.122 event Security periode yang hilang lokal), index `sysmon` (perintah anti-forensik, nama asli berkas yang dihancurkan, perubahan waktu berkas, sampai 21:55:40), index `powershell`, advanced hunting Defender sampai 30 hari, dan log autentikasi `JKT-DC01`.
- **Kalimat aman tentang periode yang hilang:** periode sebelum pembersihan tidak lagi ada di host tetapi tersedia di Splunk sampai retensi, dengan celah tak tertutup sekitar empat detik; perubahan berkas sebelum penghapusan journal dibaca dari Sysmon EID 11 di Splunk; yang benar-benar tidak bisa dipulihkan adalah isi tiga berkas yang di-wipe (hanya namanya yang selamat, dari telemetri yang diteruskan).
- **Keyakinan:** tinggi bahwa upaya anti-forensik dilakukan dan untuk tiap teknik yang didaftar; sedang untuk "apa persisnya yang ada di tiga berkas staging" karena hanya nama dan konteks yang tersedia, bukan isi.

## 3. Lab praktik (di VM lab terisolasi)

Prasyarat: VM Windows lab dengan Sysmon dan audit lengkap, satu VM analisis forensik, dan bila memungkinkan satu kolektor yang menerima event log (misalnya Splunk atau pengumpul syslog di VM analisis) supaya kamu bisa membuktikan sendiri bahwa telemetri yang diteruskan selamat dari pembersihan lokal. Semua aktivitas lab jinak dan dijalankan atas snapshot yang boleh dirusak. Folder kasus lab `CASE-2026-LAB-021`, host `LAB-WS01` (`172.16.50.10`), `LAB-DFIR01` (`172.16.50.20`), jaringan host-only `172.16.50.0/24`. Ambil snapshot bersih sebelum tiap langkah uji.

1. **Keadaan awal.** Ambil snapshot `bersih-anti-forensik`. Buat sepuluh berkas uji dengan nama yang mudah dikenali di satu folder `stage`, lalu catat `fsutil usn queryjournal C:` (identitas journal, First Usn, Next Usn) dan rentang event log sebagai keadaan awal. Bila ada kolektor, pastikan event log `LAB-WS01` sudah mengalir ke sana.
2. **Pembersihan event log.** Bersihkan log Security dengan akun admin lab, lalu segera ambil salinan EVTX. Periksa 1102 dan `EventRecordID`. Ulangi pembersihan kedua dan amati apa yang terjadi pada 1102 yang pertama. Bila ada kolektor, bandingkan jumlah event sebelum pembersihan di kolektor dengan yang tersisa lokal, dan hitung berapa yang hilang lokal tetapi selamat di kolektor.
3. **Penghapusan USN journal.** Jalankan `fsutil usn deletejournal /d C:` pada volume uji. Catat berapa lama prosesnya, apakah berlanjut setelah restart, dan bandingkan `queryjournal` sebelum dan sesudah: identitas journal baru, `First Usn` rendah, dan rekaman tertua `$J` yang bergeser.
4. **Wiping dengan SDelete.** Hancurkan tiga berkas uji di `stage` dengan SDelete. Bila `$J` masih ada (lakukan sebelum langkah 3 pada snapshot terpisah), temukan rantai penggantian nama A sampai Z dan tuliskan nama asli hanya dari journal. Pada snapshot tempat journal sudah dihapus, buktikan kamu hanya bisa menemukan pola `ZZZ.ZZZ` di MFT dan nama asli dari telemetri kolektor.
5. **Uji FileBlockShredding.** Aktifkan EID 28 (FileBlockShredding) di konfigurasi Sysmon lab, lalu coba SDelete lagi dan amati bahwa percobaan shredding diblokir dan tercatat. Tulis kalimat untuk laporan yang membedakan "wiping berhasil, nama dipulihkan dari telemetri" dari "wiping diblokir".
6. **Mematikan telemetri.** Hapus Sysmon dengan `sysmon64 -u force`, lalu buktikan dari EID 4 dan System 7036 kapan persisnya berhenti. Setel `EnablePrefetcher`=0 dan buktikan dari waktu tulis kunci registry, bukan dari ketiadaan `.pf`.
7. **Timestomping tiga lapis.** Palsukan SI satu berkas uji ke tahun lampau, lalu buktikan dengan tiga cara terpisah: perbandingan SI dan FN, posisi nomor entry MFT, dan artefak eksekusi. Lalu pindahkan berkas itu dan amati apakah FN ikut tersalin palsu, sehingga perbandingan SI vs FN gagal dan hanya nomor entry serta artefak eksekusi yang bertahan.
8. **Shadow copy.** Pada satu snapshot aktifkan System Protection dan buat satu restore point, pada snapshot lain biarkan mati. Jalankan `vssadmin delete shadows /all /quiet` di keduanya dan bandingkan keluarannya, supaya kamu bisa membedakan "ada yang dihapus" dari "perintah jalan tanpa efek".
9. **Laporan.** Susun garis waktu kurasi lintas artefak dan tulis setengah halaman temuan dengan tingkat keyakinan per klaim, sebutkan secara eksplisit apa yang tidak bisa kamu simpulkan dan sumber luar mana yang menutup celahnya.

**Hasil yang sebaiknya tersimpan:**

- Keadaan `queryjournal` sebelum dan sesudah penghapusan journal beserta durasi prosesnya.
- Salinan EVTX sesudah pembersihan pertama dan kedua dengan catatan `EventRecordID`, dan perbandingan dengan kolektor.
- Daftar nama asli berkas yang dihancurkan, dipulihkan dari journal (bila ada) dan dari telemetri kolektor.
- Bukti EID 28 memblokir shredding pada snapshot yang mengaktifkannya.
- Bukti waktu Sysmon berhenti dan prefetch dimatikan, dari event dan waktu tulis registry.
- Bukti tiga lapis untuk satu berkas yang di-timestomp, dan demonstrasi perbandingan SI vs FN gagal setelah berkas dipindah.
- Perbandingan keluaran `vssadmin` pada host dengan dan tanpa shadow copy.
- Setengah halaman temuan dengan tingkat keyakinan dan batasnya.

**Variasi tantangan:** bersihkan log Security dua kali lalu buktikan dari kolektor periode mana yang hilang, meski 1102 sudah ikut terhapus di host. Tulis kalimat laporan yang membedakan "tidak ada logon sebelum pukul X" (klaim yang salah) dari "log lokal sebelum pukul X hilang, tersedia di kolektor sampai retensi" (klaim yang benar).

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat memeriksa anti-forensik. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Tidak ada 1102 padahal log Security pendek | Log dibersihkan dua kali, atau memang baru dirotasi | Periksa `EventRecordID`, ukuran maksimum channel, dan bandingkan dengan salinan di SIEM |
| `$J` kosong atau sangat pendek | Journal dihapus dan dibuat ulang, atau sudah berputar | Bandingkan identitas journal dan `First Usn` dengan umur sistem; cari `fsutil` di Prefetch dan di SIEM |
| Rantai nama A sampai Z tidak ditemukan | Journal sudah dihapus, atau alat wiping lain | Cari pola `ZZZ.ZZZ` di MFT, Prefetch SDelete, dan nama asli di Sysmon yang diteruskan |
| Perbandingan SI dan FN tidak memberi tanda | Timestomping yang juga menyentuh FN, atau berkas disalin | Pakai nomor entry MFT dan artefak eksekusi (bagian 2.6) |
| Kekosongan Sysmon tanpa 7036 atau EID 4 | Masalah operasional, bukan penghapusan | Periksa log service, ruang disk, dan antrean pengiriman forwarder |
| `vssadmin` dijalankan tetapi tidak ada shadow copy yang hilang | System Protection memang mati di host | Periksa keluaran perintah dan area VSS di image sebelum menyebut penghapusan |
| Prefetch kosong padahal `EnablePrefetcher` bukan 0 | Prefetch mati bawaan di sebagian edisi server | Periksa nilai registry dan edisi sistem sebelum menyimpulkan |
| Nama field atau kolom tidak cocok | Beda versi EvtxECmd, MFTECmd, atau add-on Splunk | Cocokkan dengan versi alat dan map di lab |

## 5. Kesalahan umum dan jebakan

- Menyimpulkan anti-forensik dari satu tanda tunggal, tanpa korelasi antar sumber.
- Menganggap ketiadaan data sebagai bukti penghapusan, padahal bisa berarti telemetri tidak pernah aktif, host tidur, atau pengiriman tertunda.
- Menulis "tidak ada logon sebelum pukul X" alih-alih "log lokal sebelum pukul X hilang, tersedia di SIEM sampai retensi".
- Melewatkan pembanding di luar host, padahal salinan di Splunk, Defender, dan `JKT-DC01` sering menjawab seluruh pertanyaan.
- Mengira SDelete memakai tiga pass secara bawaan, padahal bawaannya satu [S2].
- Mengira pembersihan ruang kosong juga menghancurkan nama berkas di ruang kosong, padahal tidak [S2].
- Memeriksa event log lebih dulu dan artefak file system belakangan, padahal urutan itu terbalik dari tingkat kesulitan pembersihannya.
- Menyebut "shadow copy dihapus" hanya karena `vssadmin` dijalankan, tanpa memastikan ada shadow copy untuk dihapus.
- Memakai nomor teknik ATT&CK lama (T1070.001, T1562.002) tanpa menyadari sebagian pindah ke T1685 pada taktik Defense Impairment di v19 ke atas [S6][S7].
- Menjalankan perintah anti-forensik di sistem bukti alih-alih di salinan lab.
- Menulis "penyerang melakukan anti-forensik" tanpa menyebut teknik, batas, dan tingkat keyakinan per klaim.

## 6. Catatan terkini

Bagian ini menampung detail versi dan taksonomi yang bisa berubah; tidak mengubah alur analisis di atas.

- **ATT&CK v19 (April 2026) membelah taktik Defense Evasion** menjadi Stealth (tetap TA0005) dan Defense Impairment (TA0112) [S6][S7]. Indicator Removal (T1070) kini berada di taktik Stealth, dengan Timestomp (T1070.006) tetap sebagai sub-teknik. Clear Windows Event Logs yang dulu T1070.001 direvoke menjadi T1685.005, dan Disable Windows Event Logging yang dulu T1562.002 menjadi T1685.001; keduanya kini di bawah Disable or Modify Tools (T1685) pada taktik Defense Impairment [S7]. Dokumentasi, rule Sigma, dan laporan vendor lama masih memakai nomor lama, jadi kenali keduanya.
- **SDelete** versi 5 Maret 2026 memakai satu pass secara bawaan, mengganti nama berkas 26 kali dengan pola huruf berurutan, dan tidak menghapus aman nama berkas di ruang kosong [S2]. Pola nama itu indikator paling spesifik di Day ini; masukkan ke daftar periksa triage.
- **Sysmon** publikasi 10 September 2026 menambah dan menegaskan beberapa event yang relevan untuk anti-forensik: EID 2 (perubahan waktu pembuatan berkas, menangkap timestomping), EID 4 dan EID 16 (perubahan keadaan dan konfigurasi Sysmon, tidak bisa difilter), EID 23 dan EID 26 (penghapusan berkas, dengan dan tanpa menyimpan salinan), dan EID 28 (FileBlockShredding, memblokir shredding dari alat seperti SDelete) [S10]. EID 28 yang diaktifkan bisa menggagalkan wiping sejak awal.
- **`fsutil usn deletejournal`** menyetel last USN seluruh rekaman MFT ke nol, memakan beberapa menit, dan bisa berlanjut setelah restart; selama proses, operasi journal mengembalikan galat [S1][S8]. Journal yang dibuat ulang punya `UsnJournalID` baru dan `LowestValidUsn` yang menandai diskontinuitas [S9].
- **Log forwarding ke SIEM mengubah seluruh perhitungan anti-forensik.** Pembersihan lokal tidak menghapus salinan yang sudah terkirim. Ini argumen operasional yang layak dibawa ke diskusi arsitektur: host yang meneruskan log, onboard EDR, dan terikat audit policy membuat anti-forensik lokal hampir sia-sia, dan celah yang tersisa (FileBlockShredding mati, Sysmon bisa dihapus admin) adalah bahan rekomendasi.

## 7. Cheat sheet

```
PRINSIP   menghapus = MENULIS -> penghapusan meninggalkan jejaknya sendiri
URUTAN    periksa yang paling sulit dibersihkan dulu: USN journal -> $LogFile -> MFT -> event log
          lalu SELALU cek sumber luar: Splunk (diteruskan sblm dihapus) | Defender cloud | JKT-DC01

LOG       Security dibersihkan -> 1102 (di log baru) ; System -> 104 ; audit diubah -> 4719
          bersih 2x? -> 1102 ikut hilang, tapi EventRecordID mulai kecil
          bandingkan jumlah event lokal vs SIEM = perkiraan yang hilang (isinya pulih dari SIEM)
          clear Security butuh SeSecurityPrivilege -> sesi ber-4672

USN       fsutil usn queryjournal C:  -> UsnJournalID baru + First Usn kecil + $J pendek = journal dibuat ulang
          LowestValidUsn = diskontinuitas ; deletejournal set last USN=0 di SELURUH MFT, makan menit
          perintah fsutil -> Prefetch/Amcache + 4688/Sysmon 1 (diteruskan)

SDELETE   default 1 pass (BUKAN 3) | -c free space | nama di free space TIDAK dihapus aman
          JEJAK: rename 26x foo.txt -> AAA.AAA -> ... -> ZZZ.ZZZ ; di $J bila ada, di MFT sbg nama ZZZ.ZZZ
          nama ASLI dari Sysmon diteruskan (EID 26/11/2) bila $J sudah dihapus
          Sysmon EID 28 FileBlockShredding bisa MEMBLOKIR SDelete

TELEMETRI cari PERUBAHANNYA, bukan ketiadaannya:
          Sysmon dihapus -> EID 4 Stopped + System 7036 (+ sysmon64 -u di SIEM) | prefetch -> EnablePrefetcher=0 + waktu tulis
          vssadmin delete shadows (T1490) -> eksekusi != ada yang dihapus (cek apakah ada shadow copy)

TIMESTOMP di luar SI vs FN (Day 08): urutan EntryNumber MFT | Prefetch/Shimcache/Amcache | Sysmon EID 2
          SI vs FN GAGAL bila berkas dipindah setelah dipalsukan -> andalkan EntryNumber + artefak eksekusi

ATT&CK    T1070 Indicator Removal (Stealth TA0005) ; T1070.006 Timestomp
          T1070.001 -> T1685.005 ; T1562.002 -> T1685.001 (Disable or Modify Tools, Defense Impairment TA0112)

LAPORAN   "hilang dari host" != "tidak terjadi" ; sebut jendela hilang + sumber penutup + yang benar2 tak terpulihkan
          satu tanda bukan kesimpulan; keyakinan per klaim (Day 19)
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Log Security di `JKT-WS-0528` hanya memuat 642 event sejak 22:05 Minggu, jadi laptop ini baru aktif sejak saat itu dan tidak ada aktivitas sebelumnya." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Log yang pendek dan dimulai dari `EventRecordID` 1 pada mesin yang sudah berjalan berbulan-bulan adalah ciri log yang baru dibersihkan, bukan host yang baru aktif. Event 1102 pukul 22:05:14 oleh `adm.rizal` membuktikan pembersihan, dan Splunk index `wineventlog` memegang 58.122 event Security untuk periode 5 sampai 31 Januari yang hilang secara lokal. Kalimat yang benar menyebut periode yang hilang lokal dan sumber yang menutupnya, bukan "tidak ada aktivitas sebelumnya". Lihat bagian 1.2 dan 2.2.

</details>

**2. Skenario keputusan.** `$J` di `JKT-WS-0528` hanya memuat sekitar satu setengah hari, padahal laptop dipakai berminggu-minggu. Langkah mana yang paling tepat untuk memastikan ini penghapusan journal, bukan rotasi biasa?

- A. Simpulkan rotasi biasa, karena `$J` memang punya ukuran terbatas dan berputar.
- B. Baca `fsutil usn queryjournal` (identitas journal dan `First Usn`), bandingkan dengan umur sistem, lalu cari `fsutil.exe` di Prefetch dan perintah `deletejournal` di Splunk index `sysmon`.
- C. Simpulkan penghapusan journal hanya dari `$J` yang pendek, tanpa pemeriksaan lain.

<details><summary>Jawaban</summary>

B. Identitas journal yang baru, `First Usn` yang rendah, dan rekaman tertua `$J` yang baru beberapa jam pada sistem lama menandakan journal dibuat ulang; `fsutil.exe` di Prefetch dan perintah `deletejournal` yang diteruskan ke Splunk menautkannya ke waktu dan akun. A keliru karena rotasi tidak mengubah identitas journal atau menyetel `First Usn` ke nol. C keliru karena satu tanda bukan kesimpulan. Lihat bagian 1.3 dan 2.3.

</details>

**3. Pertanyaan jebakan.** "SDelete sudah menghancurkan tiga berkas staging, jadi kita tidak akan pernah tahu berkas apa yang ada di sana." Benarkah?

<details><summary>Jawaban</summary>

Tidak sepenuhnya. Isi ketiga berkas memang tidak bisa dipulihkan, karena SDelete menimpanya. Tetapi namanya masih bisa diketahui: MFT menyimpan rekaman bebas berpola `ZZZ.ZZZ` yang menunjukkan jumlah berkas, dan Sysmon yang diteruskan ke Splunk sebelum service-nya dihapus menyimpan nama asli (`data-portal-ekspor.csv`, `data-radius-dump.txt`, `daftar-host.txt`) beserta rantai penggantian nama. Jadi nama dan konteks diketahui, isi tidak. Lihat bagian 1.4 dan 2.4.

</details>

**4. Skenario keputusan.** Kamu melihat `vssadmin delete shadows /all /quiet` dijalankan `adm.rizal` pukul 21:58:50. Apa yang paling tepat ditulis di laporan?

- A. "Shadow copy dihapus untuk menghalangi pemulihan."
- B. Periksa dulu apakah host punya shadow copy; bila tidak ada, tulis "perintah penghapusan shadow copy dijalankan, tetapi host tidak punya shadow copy sehingga tidak ada versi lama berkas yang hilang karena perintah ini".
- C. Abaikan, karena perintah yang tidak berefek tidak perlu dilaporkan.

<details><summary>Jawaban</summary>

B. Eksekusi perintah tidak otomatis berarti ada yang dihancurkan; System Protection sering mati di workstation. Periksa keluaran perintah dan area VSS di image. A keliru karena mengklaim efek tanpa bukti. C keliru karena eksekusinya tetap jejak waktu dan niat yang layak dicatat, hanya efeknya yang nol. Lihat bagian 1.4 dan 2.7.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Sari, dalam tiga kalimat, kenapa host `JKT-WS-0528` yang ber-EDR dan meneruskan log membuat upaya anti-forensik penyerang hampir sia-sia, dan apa satu-satunya hal yang benar-benar hilang.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Karena laptop ini meneruskan event log ke Splunk dan onboard ke Defender, semua yang dihapus lokal (log Security, telemetri Sysmon, perubahan berkas) sudah terlanjur tersalin keluar host sebelum penyerang menyentuhnya, jadi isinya masih bisa kita baca di Splunk sampai retensi dan di Defender sampai 30 hari. Penghapusan journal dan pembersihan log justru meninggalkan buktinya sendiri, yaitu identitas journal baru dan event 1102. Satu-satunya yang benar-benar hilang adalah isi tiga berkas yang di-wipe SDelete; namanya kita pulihkan dari telemetri yang diteruskan, tetapi isinya tidak bisa dikembalikan dari mana pun."

Kesalahan yang sering muncul:
- Menulis "semua bukti hilang" padahal sebagian besar pindah ke SIEM dan cloud.
- Lupa menyebut bahwa isi berkas yang di-wipe benar-benar tidak terpulihkan.
- Menganggap pembersihan lokal menghapus salinan di SIEM.

</details>

**6. Pertanyaan jebakan.** "Berkas `drvsync.exe` dibuat 2021 menurut Explorer, jadi ia sudah lama ada dan bukan bagian dari insiden ini." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Waktu yang dilihat Explorer berasal dari SI yang bisa dipalsukan dari user mode. Di `drvsync.exe`, SI mengaku 2021 tetapi FN menunjukkan 2027-01-29, dan nomor entry MFT-nya (312604) duduk di antara berkas yang dibuat pada menit yang sama di 2027, yang tidak bisa dipalsukan dengan mengubah timestamp. Prefetch dan Shimcache untuk berkas itu juga menyimpan waktu 2027. Ini timestomping, dan berkas itu bagian dari insiden. Lihat bagian 1.6 dan 2.6.

</details>

**7. Interview question (English).** "A workstation looks like it was wiped by the attacker: the Security log is almost empty and the USN journal only covers a day. How do you investigate without overstating what was lost?"

<details><summary>Sample answer</summary>

"I start from the principle that deletion is a write, so each anti-forensic action leaves its own trace, and I look for those first. A short Security log with a 1102 event and a record number restarting at one tells me it was cleared, by which account and when; a USN journal with a new journal ID and a very low first USN on an old machine tells me it was deleted and recreated. Then I pivot off the host entirely, because an EDR-onboarded workstation forwards its logs to the SIEM before the attacker can touch them, so the cleared Security period is still readable in the SIEM up to retention, Sysmon in the SIEM holds the wiped file names and the anti-forensic commands, and the domain controller holds the authentication. In the report I separate 'not recoverable from this host' from 'did not happen', I name the exact lost window and the source that covers it, and the only thing I call truly unrecoverable is the content of the securely wiped files, whose names I still recovered from forwarded telemetry."

What makes this answer strong: it leads with the governing principle, ties each technique to a verifiable trace, uses off-host sources instead of treating the host as the only evidence, and ends by drawing the honest line between what is lost locally and what is gone for good.

</details>

## 9. Sumber

Tabel ini adalah rujukan verifikasi, bukan bacaan wajib; isi yang dibutuhkan sudah ditulis di badan Day.

| # | Judul | URL | Tipe | Tanggal / diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Microsoft Learn: fsutil usn | https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn | primer | diperbarui 2026-02-16; diakses 2026-10-23 | Tinggi. Sintaks `deletejournal /d` dan `/n`, `queryjournal`, `createjournal`; peringatan proses mengakses seluruh MFT, menyetel last USN ke nol, memakan menit, bisa berlanjut setelah restart, journal mengembalikan galat selama proses |
| S2 | Sysinternals: SDelete | https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete | primer | terbit 2026-03-05; diakses 2026-10-23 | Tinggi. Default 1 pass (`-p`), `-c` dan `-z` free space, penggantian nama 26 kali dengan contoh `foo.txt` menjadi `AAA.AAA`, pengisian rekaman MFT kosong, dan keterangan nama berkas di free space tidak dihapus aman |
| S3 | Microsoft Learn: 1102(S) The audit log was cleared | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102 | primer | ms.date 2021-09-07; diakses 2026-10-23 | Tinggi. Provider `Microsoft-Windows-Eventlog`, field Subject (SID, Account Name, Domain, Logon ID), saran memantau dan menyelidiki |
| S4 | Microsoft Learn: 104 dan EvtxECmd Maps (104, 7036) | https://github.com/EricZimmerman/evtx/tree/master/evtx/Maps | primer (repo resmi) | diakses 2026-10-23 | Tinggi untuk isi kolom per map pada tanggal akses; 104 (System, log dibersihkan) dan 7036 (service state) dipakai di Day ini; map bisa berubah antar versi |
| S5 | Microsoft Learn: 4719(S) System audit policy was changed | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4719 | primer | ms.date 2021-09-07; diakses 2026-10-23 | Tinggi. Ditulis setiap audit policy berubah terlepas dari setting Audit Policy Change; field Subject, Category, Subcategory, Changes |
| S6 | MITRE ATT&CK: Indicator Removal (T1070) | https://attack.mitre.org/techniques/T1070/ | primer | ATT&CK v20, versi 3.0, dimodifikasi 2026-05-12; diakses 2026-10-23 | Tinggi. T1070 di taktik Stealth (TA0005); sub-teknik termasuk T1070.006 Timestomp dan T1070.004 File Deletion |
| S7 | MITRE ATT&CK: Disable or Modify Tools (T1685) dan Updates April 2026 | https://attack.mitre.org/techniques/T1685/ | primer | ATT&CK v19/v20, T1685 versi 1.0 dimodifikasi 2026-09-11; diakses 2026-10-23 | Tinggi. T1685 di taktik Defense Impairment (TA0112); T1070.001 direvoke menjadi T1685.005, T1562.002 menjadi T1685.001 (Updates April 2026) |
| S8 | Microsoft Learn: Creating, Modifying, and Deleting a Change Journal | https://learn.microsoft.com/en-us/windows/win32/fileio/creating-modifying-and-deleting-a-change-journal | primer | ms.date 2018-05-31; diakses 2026-10-23 | Tinggi. `FSCTL_DELETE_USN_JOURNAL` menyusuri seluruh berkas dan menyetel USN ke nol, persisten melintasi restart, `ERROR_JOURNAL_DELETE_IN_PROGRESS`; journal tidak selalu dibuat saat startup |
| S9 | Microsoft Learn: USN_JOURNAL_DATA_V0 | https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_journal_data_v0 | primer | ms.date 2018-12-05; diakses 2026-10-23 | Tinggi. `UsnJournalID` (identitas baru saat dibuat atau dicap ulang), `FirstUsn`, `NextUsn`, `LowestValidUsn` (diskontinuitas), `MaxUsn` |
| S10 | Sysinternals: Sysmon | https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon | primer | publikasi 2026-09-10; diakses 2026-10-23 | Tinggi. EID 2 (perubahan waktu pembuatan berkas), EID 4 dan 16 (state dan config Sysmon, tidak bisa difilter), EID 23 dan 26 (file delete), EID 28 (FileBlockShredding memblokir SDelete) |
| S11 | Microsoft Learn: cipher | https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cipher | primer | diakses 2026-10-23 | Tinggi untuk opsi `/w` yang menimpa ruang kosong tanpa menghapus berkas aktif |
| S12 | Microsoft Learn: vssadmin delete shadows | https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/vssadmin-delete-shadows | primer | diakses 2026-10-23 | Tinggi untuk sintaks dan efek; perintah bisa berjalan tanpa efek bila tidak ada shadow copy |
| S13 | MITRE ATT&CK: Inhibit System Recovery (T1490) | https://attack.mitre.org/techniques/T1490/ | primer | ATT&CK v20; dirujuk 2026-10-23 | Tinggi untuk ID dan pemetaan penghapusan shadow copy; lebih sering pada ransomware |
| S14 | Elastic Security: Delete Volume USN Journal with Fsutil | https://www.elastic.co/guide/en/security/current/delete-volume-usn-journal-with-fsutil.html | sekunder (vendor) | versi rule 317; diakses 2026-10-23 | Sedang-tinggi. Logika deteksi `fsutil.exe` dengan argumen `deletejournal` dan `usn`, saran investigasi rantai proses dan akun; pemetaan ATT&CK pada rule masih memakai label taktik lama |
| S15 | Endpoint-Forensics-Notes Day 05, 07, 08, 09, 13, 19 | (lokal) | rujukan internal | 2026-10-23 | Keterkaitan antar Day: audit policy dan pembersihan log (05), artefak eksekusi (07), MFT, SI vs FN, `$J` (08), waktu tulis registry (09), super-timeline (13), bahasa keyakinan (19) |

**Catatan sumber:** nilai persis keluaran `fsutil usn queryjournal` di bagian 2.3 adalah ilustrasi dengan nama field yang umum muncul; angka `First Usn`, `Next Usn`, dan identitas journal perlu kamu amati sendiri di lab, tetapi perilakunya (identitas baru dan `LowestValidUsn` yang menandai diskontinuitas) sesuai dokumentasi struktur journal [S9]. Klaim bahwa `EventRecordID` yang dimulai dari angka kecil menandakan pembersihan berulang adalah penalaran dari perilaku penulisan EVTX, bukan pernyataan dokumentasi, jadi uji di lab sebelum memakainya sebagai argumen di laporan. Pemetaan event 104 dan 7036 memakai map EvtxECmd yang isinya benar pada tanggal akses dan bisa berubah antar versi [S4]. Pemetaan ATT&CK ke T1685 berasal dari halaman teknik dan catatan rilis April 2026 [S6][S7]; rule dan laporan lama masih memakai nomor lama, jadi keduanya perlu dikenali. Nama kolom keluaran MFTECmd, EvtxECmd, PECmd, dan RECmd berbeda antar versi dan harus dicocokkan dengan versi yang terpasang. Semua isi PT JAB, termasuk waktu, akun `rizal.fadillah` dan `adm.rizal`, host `JKT-WS-0528`, nomor bukti `INC-2027-011-E01`, nama berkas yang dihancurkan, dan hasil parse, adalah contoh fiktif yang disusun agar konsisten dengan fakta insiden, bukan kejadian nyata.
