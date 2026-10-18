---
day: 16
title: 'Capstone: tiga hunt terdokumentasi dari hipotesis sampai deteksi, evaluasi akhir Q1, dan portofolio pribadi dengan write-up publik dan rubrik'
researched_on: 2026-10-18
versions_checked: 'Splunk Enterprise 10.6 (rilis 2026-09-30) dan 10.6.1 (2026-10-16); Velociraptor 0.77.3 (2026-10-05; artifact Windows.Search.FileFinder, Windows.System.DLLs, Windows.Sysinternals.Autoruns, plugin glob); Wazuh 4.14.9 (2026-10-14; PT JAB di 4.14); MITRE ATT&CK v20.0 (2026-10-13): T1574.001 v3.0 (2026-09-11), T1105 v2.6 (2026-09-11), T1071.001 v1.5 (2026-09-11), T1059.003 v1.5 (2026-05-12); Sigma specification 2.1.0 (2025-08-02); ATT&CK Navigator 5.3.2 (2026-04-21), layer format 4.5 (sejak 4.9.0); Atomic Red Team T1574.001 (7 test) dan T1105 (8 test Linux); HijackLibs; Microsoft Learn event 4688 (diperbarui 2026-04-27); LOLBAS Certutil; rujukan Threat-Hunting Day 01-15'
---

# Day 16: Capstone: tiga hunt dari hipotesis sampai deteksi, evaluasi Q1, dan portofolio

Cakupan: menjalankan tiga hunt terakhir kuartal pertama Program hunt PT JAB dengan tiga platform berbeda (Velociraptor, Wazuh, Splunk) sampai laporan final dan usulan deteksi, memperbarui metrik program sampai 31 Maret, menulis satu halaman evaluasi Q1 beserta rekomendasi Q2, lalu mereplikasi ketiga hunt di lab pribadi sebagai portofolio dengan templat write-up publik, aturan sanitasi, struktur repo, layer ATT&CK Navigator, dan rubrik penilaian diri.

## Ide inti

Capstone hunting bukan ujian menemukan penyerang. Ia membuktikan bahwa siklus hunt yang dipelajari Day 01 sampai 15 bisa dijalankan sampai ujung tanpa bantuan: pelajaran dari pekerjaan sebelumnya dipilih menjadi hipotesis yang bisa dibantah, Evidence-nya diperiksa sebelum query ditulis, query dibuktikan sanggup menangkap contoh positif, setiap baris hasil diberi label dengan bukti di luar query, dan laporannya meninggalkan sesuatu yang permanen (baseline, usulan deteksi, celah yang tercatat dengan pemiliknya, hipotesis baru). Hasil "tidak ditemukan" yang cakupannya tertulis dan querynya teruji adalah temuan yang sah, bukan kegagalan; capstone yang ketiga hunt-nya negatif tetap capstone yang lengkap bila ketiganya bisa dihitung ulang orang lain. Capstone juga punya dua jalur yang tidak boleh tercampur. Jalur kerja menghasilkan laporan dan angka untuk organisasi. Jalur belajar mereplikasi hunt yang sama di lab pribadi dengan data milikmu sendiri, sehingga hasilnya boleh dipublikasikan sebagai portofolio tanpa membawa satu baris pun dari pekerjaan.

Kamu sudah mengenal pola ini dari NOC. Akhir kuartal, patroli preventif terakhir dijalankan penuh dengan formulir baku: segmen mana yang dicek, titik mana yang diukur, mana yang normal, mana yang tidak bisa diukur karena perangkatnya belum mengirim data, dan temuan mana yang diteruskan ke tim lapangan atau dijadikan alarm permanen di NMS. Laporan patroli "segmen X dicek, normal" bersama daftar titiknya tetap masuk laporan kuartal, karena itulah bukti area yang sudah diperiksa. Engineer yang ingin membangun reputasi di luar kantor tidak membawa konfigurasi pelanggan ke presentasi komunitas; ia membangun ulang topologinya di lab rumah lalu memamerkan cara kerjanya. Batas analoginya: degradasi fiber tidak berusaha bersembunyi, sedangkan penyerang sengaja bergerak di bawah ambang. Karena itu "normal" dalam hunting hanya berlaku untuk pertanyaan, data, dan rentang yang tertulis, dan baru kuat bila query-nya pernah terbukti menangkap contoh positif.

```
 pelajaran program (INC-2027-040, register celah G01-G16, backlog)
          |
          v
 3 abstract ABLE (Selasa 23 Mar) ---> cek Evidence + cakupan per host
          |
   +------+--------------------+---------------------------+
   v                           v                           v
 HUNT-2027-026               HUNT-2027-028               HUNT-2027-027
 Velociraptor (disk+modul)   Wazuh archives + firewall   Splunk 4688 regional
 Sel 23 - Sel 30 (expiry)    Kam 25                      Sel 30 (setelah GPO 22 Mar)
   |                           |                           |
   +-------> uji positif (data nyata lama / VM lab) <------+
                               |
                               v
 label tiap item -> laporan final (Kategori hasil + blok Metrik) -> handover
                               |
          +--------------------+---------------------+
          v                                          v
 metrik program per 31 Mar + register        jalur portofolio (lab pribadi)
 satu halaman evaluasi Q1 + rekomendasi Q2   HUNT-CAP-001..003, write-up publik,
 (Rabu 31 Mar, Hendra dan Dimas)             repo, layer Navigator, rubrik
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan, kantor pusat dan data center di Jakarta, serta POP regional di Bandung, Surabaya, dan Medan. SOC PT JAB memakai Splunk Enterprise 10.6 dengan Enterprise Security (ES) 8.x; hunting berjalan di search head `jkt-splunk-sh01` dengan role `jab_hunter`. Sysmon terpasang di 214 host (61 server Windows dan 153 workstation Jakarta di OU `Workstations-EDR`), dan GPO audit `JAB-WS-Audit` (4688 dengan command line dan 4698) selama ini hanya ditautkan ke OU itu. Server Velociraptor `jkt-velo02` menjangkau host Windows sejak akhir Februari, dan Wazuh 4.14 di `jkt-wazuh01` menjadi HIDS untuk empat server Linux tanpa EDR, dengan archives aktif dan rule auditd `jab_exec` hanya di `jkt-bastion01` dan `jkt-billing02`. Program hunt PT JAB adalah percobaan dua kuartal (Februari sampai Juli 2027) yang disetujui Direktur Teknologi Hendra Wijaya; kamu (analyst L2) memegangnya setiap Selasa dan Kamis, dengan SOC lead Dimas Prasetyo sebagai sponsor. Kamis lalu (Day 15) lembar metrik dan register celah disusun; Jumat register dikirim ke para pemilik dengan permintaan status sampai Kamis 2027-03-25. Senin malam 2027-03-22 pukul 20:00, di jendela change Infrastruktur, tim Agung Prabowo menautkan GPO `JAB-WS-Audit` ke OU Bandung dan OU POP (Surabaya dan Medan) dan memulihkan Sysmon di `JKT-WS-0532`. Selasa 2027-03-23 pukul 08:15, Dimas menulis:

> "Pagi. Sisa kuartal tinggal tiga hari hunting: hari ini, Kamis, dan Selasa depan. Pak Hendra dan aku minta tiga hunt terakhir Q1 dijalankan lengkap dari hipotesis sampai deteksi, jangan setengah jalan, lalu Rabu 31 Maret kita presentasi evaluasi akhir Q1, satu halaman. Hunt mana yang paling layak, dan kenapa? Aku masih kepikiran INC-2027-040: apa pola laptop Surabaya itu ada di laptop lain, walaupun bentuknya bukan scheduled task? Semalam Agung menautkan GPO audit ke Bandung dan POP; itu artinya apa untuk hunt, baseline, dan detection yang sudah jalan? Lutfi juga pernah tanya, server Linux kita ada yang bicara ke internet di luar fungsinya atau tidak. Kalau ketiganya tidak menemukan apa-apa, apa yang aku bawa ke Pak Hendra? Tolong angka program sampai 31 Maret dan satu halamannya, plus rekomendasi untuk Q2, tapi rencana Q2 lengkapnya nanti saja. Satu lagi: kamu pernah bilang mau bikin portofolio. Boleh, asal tidak ada data kita di situ, termasuk nama PT JAB."

Pesan itu memuat tujuh pertanyaan:

1. Tiga hunt mana yang paling layak menutup Q1, dan kenapa?
2. Apakah pola `INC-2027-040` (executable bertanda tangan dengan DLL palsu di profil pengguna laptop yang jarang di kantor) ada di host lain, apa pun mekanisme persistence-nya?
3. Apa arti perubahan GPO 22 Maret untuk hunt, baseline, dan detection yang sudah aktif?
4. Apakah ada server Linux yang berkomunikasi ke internet di luar fungsinya?
5. Bila ketiganya tidak menemukan apa-apa, apa yang dibawa ke evaluasi?
6. Berapa angka program sampai 31 Maret, seperti apa satu halaman evaluasinya, dan apa rekomendasi untuk Q2?
7. Bagaimana hunt yang sama dipakai untuk portofolio pribadi tanpa membawa data PT JAB?

Pertanyaan 1 dijawab di bagian 1.2 dan Bagian A, pertanyaan 2 di bagian 1.3 dan Bagian B, pertanyaan 3 di bagian 1.4 dan Bagian D, pertanyaan 4 di bagian 1.3 dan Bagian C, pertanyaan 5 di bagian 1.5 dan Bagian E, pertanyaan 6 di Bagian F, G, dan H, dan pertanyaan 7 di bagian 1.6 dan Bagian I sampai L. Bagian 1.1 merangkum titik awal program per 18 Maret.

**Kapan relevan:** saat menutup satu periode program hunt dengan hunt yang benar-benar selesai sampai handover; saat menyiapkan evaluasi ke manajemen dengan angka yang bisa ditelusuri; saat membangun portofolio hunting untuk interview; dan saat ingin membuktikan ke diri sendiri bahwa setiap langkah siklus bisa dijalankan tanpa panduan.
**Kapan bukan jawaban:** saat ada insiden aktif (hunt berhenti, temuan diserahkan ke IR, Day 09 bagian 2.8); saat yang dibutuhkan adalah rencana kuartal berikutnya secara penuh (kalender, model tim, dan target program dibahas Day 19); dan saat ingin "memamerkan" pekerjaan kantor, karena write-up publik dari data kerja, bahkan yang disamarkan, tetap pelanggaran.

## 1. Ringkasan, rancangan capstone, dan glosarium

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (ABLE, kartu kesiapan, stacking, first-seen, uji positif, Kategori hasil, blok Metrik, register celah, `origin_hunt`, layer Navigator) tidak diulang. Tabel ini hanya memuat istilah yang baru dipakai di Day ini.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Capstone | Satu rangkaian hunt yang dijalankan penuh dari hipotesis sampai handover untuk membuktikan siklusnya utuh | Patroli preventif penutup kuartal dengan formulir lengkap |
| DLL side-loading | Executable sah yang memuat DLL dari foldernya sendiri, sehingga DLL palsu bernama sama ikut berjalan di bawah proses bertanda tangan (bagian dari T1574.001) | Modem resmi yang memuat firmware tidak resmi dari slot yang sama |
| DLL bernama DLL sistem | DLL yang namanya sama dengan pustaka bawaan Windows (`version.dll`, `winhttp.dll`) tetapi berada di luar `System32` atau `SysWOW64` | Perangkat dengan hostname perangkat inti tetapi berada di segmen akses |
| Baseline ulang | Membangun baseline baru setelah sumber atau populasi telemetri berubah, alih-alih memakai baseline lama | Profil trafik baru untuk POP yang baru masuk NMS |
| Populasi telemetri | Kumpulan host yang benar-benar mengirim satu jenis event, diukur per host, bukan dari konfigurasi | Daftar router yang benar-benar mengirim NetFlow, bukan yang dikonfigurasi |
| Pergeseran cakupan detection | Detection yang sama tiba-tiba melihat host baru karena sumber datanya bertambah, tanpa rule diubah | Alarm NMS yang ikut memantau POP baru begitu perangkatnya masuk inventaris |
| Positive control | Contoh positif yang sudah diketahui (dari kasus lama atau lab) untuk membuktikan query tidak buta | Loop test pada link sebelum menyimpulkan "link sehat" |
| Jalur portofolio | Replikasi hunt di lab pribadi dengan nomor `HUNT-CAP-NNN` dan data milik sendiri | Lab rumah untuk mempraktikkan konfigurasi sebelum dibagikan ke komunitas |
| Write-up publik | Laporan hunt untuk pembaca umum: metode, hasil jujur, deteksi yang lahir, tanpa data kerja | Presentasi studi kasus di forum NOG dari lab sendiri |
| Sanitasi | Aturan membuang semua jejak pekerjaan dan identitas organisasi dari artefak publik | Membersihkan konfigurasi dari IP pelanggan dan kredensial sebelum dibagikan |
| Rubrik penilaian diri | Daftar kriteria berskor untuk menilai artefak hunt sendiri sebelum ditunjukkan | Checklist acceptance test sebelum serah terima link |

### 1.1 Titik awal: program per 18 Maret

Pertanyaan kelima Dimas hanya bisa dijawab bila titik awalnya jelas. Day 15 bagian 2.4 menyusun lembar metrik per Kamis 2027-03-18; tabel berikut merangkum baris yang akan berubah karena capstone. Cari kolom kanan: itulah hal yang ingin diperbaiki tiga hunt terakhir.

| Metrik per 18 Mar | Nilai | Yang ingin diperbaiki capstone |
|---|---|---|
| Hunt selesai | 22 (endpoint Windows 15, jaringan dan DNS 4, Linux 2, identitas 1, cloud 0) | Linux baru dua hunt, keduanya di Februari |
| Kategori hasil | ditemukan 1, ditemukan-bukan-insiden 1, tidak-ditemukan 20 | Bukan jumlah temuan, tetapi kekuatan hasil negatif |
| Tidak-ditemukan dengan uji positif | 2 dari 20 (10%) | Setiap hunt capstone wajib punya uji positif |
| Detection aktif lahir dari hunt | 12 dari 9 hunt | Detection yang ada harus diperiksa ulang bila sumber datanya berubah |
| Celah data | 16 dilaporkan, 3 ditutup, 4 tanpa status, 1 tanpa pemilik (G15) | Status diminta ke pemilik sampai 25 Maret |
| Miskonfigurasi | 17 dilaporkan, 2 diperbaiki, 14 tanpa status | Sama |
| Teknik diburu | 32 unik (ATT&CK v20) | Teknik yang muncul di insiden tetapi belum diburu |
| Hunt endpoint terbatas Sysmon | 9 dari 15 (60%) | Memakai sumber baru (Velociraptor, 4688 regional) |

Tiga pelajaran dari kuartal ini menjadi bahan baku hipotesis. Pertama, satu-satunya kompromi nyata (`INC-2027-040`) ditemukan dari keadaan disk lewat Velociraptor, bukan dari log, di laptop POP yang tidak terlihat di proxy karena split tunnel. Kedua, hampir setiap kesimpulan endpoint dibatasi celah telemetri (G01, G03), dan setiap perubahan telemetri menggeser makna baseline dan detection yang sudah ada. Ketiga, server Linux tanpa EDR hanya diburu dua kali, keduanya di server ber-auditd.

### 1.2 Memilih tiga hunt dari pelajaran program

Pertanyaan pertama Dimas dijawab dengan aturan sederhana: setiap hunt capstone harus menindaklanjuti satu pelajaran program yang tercatat, memakai platform yang paling dekat dengan Evidence-nya, dan menghasilkan sesuatu yang permanen walaupun hasilnya negatif. Tiga hunt dengan tiga platform berbeda juga menunjukkan keluasan, sama seperti tujuan capstone versi awal catatan ini (trigger, tipe, dan tool berbeda). Tabel berikut adalah keputusannya; baca kolom "Kenapa platform ini", karena di situlah alasan memilih alat dari Evidence, bukan dari kebiasaan.

| Hunt | Pelajaran yang ditindaklanjuti | Tipe (PEAK) | Platform | Kenapa platform ini | Teknik (v20) |
|---|---|---|---|---|---|
| `HUNT-2027-026` | `INC-2027-040` dan backlog Day 09: DLL bernama DLL sistem di samping executable bertanda tangan di folder pengguna, terutama laptop yang jarang di kantor | Hypothesis-driven | Velociraptor | Pola ada di disk dan di modul proses; 229 workstation tanpa Sysmon, dan Sysmon tidak mengumpulkan image load di host mana pun | T1574.001 (persistence dicek lewat T1547.001 dan T1053.005) |
| `HUNT-2027-027` | Perubahan telemetri G03 (GPO 22 Maret) di register Day 15: populasi baru tanpa baseline | Baseline, lalu hypothesis-driven | Splunk | 4688 masuk `wineventlog` dan data model `Endpoint.Processes`; baseline, detection, dan laporan terjadwal semuanya di Splunk | TA0002: T1204.002, T1059.001, T1059.003, T1059.005 (plus cek T1053.005) |
| `HUNT-2027-028` | Pertanyaan Lutfi dan pelajaran `INC-2026-012` (server Linux tanpa EDR); backlog Day 08: stacking argumen tool jaringan di server ber-auditd | Hypothesis-driven | Wazuh (archives), dengan pivot firewall di Splunk | Argumen perintah lengkap hanya ada di archives Wazuh untuk dua server ber-auditd; firewall satu-satunya sumber koneksi untuk 37 server | T1071.001, T1105 |

Urutan pengerjaan mengikuti sifat platform. `HUNT-2027-026` dimulai paling awal, Selasa 23 Maret, karena hunt Velociraptor kedaluwarsa setelah satu minggu dan laptop yang jarang tersambung butuh waktu itu (Day 09 bagian 1.4). `HUNT-2027-028` dikerjakan Kamis 25 Maret. `HUNT-2027-027` sengaja terakhir, Selasa 30 Maret, supaya data 4688 dari populasi baru mencapai tujuh hari penuh.

Yang tidak dipilih juga dicatat. Hunt identitas dan cloud lebih mendesak menurut sebaran area (cloud masih nol), tetapi butuh persiapan data yang tidak muat dalam tiga hari dan menjadi rekomendasi Q2 (Bagian H). `HUNT-2027-008` (4698 diikuti 4699 dalam waktu singkat) tetap kandidat; ia baru bermakna di populasi regional setelah baseline 4688 dan 4698 regional ada, sehingga `HUNT-2027-027` justru menjadi prasyaratnya.

### 1.3 Tiga teknik yang diburu

Pertanyaan kedua dan keempat Dimas butuh pemahaman teknik yang cukup untuk membaca hasil. Ringkasan berikut memakai ATT&CK v20.

- **T1574.001 Hijack Execution Flow: DLL.** Di v20 sub-teknik ini bernama "DLL" (versi 3.0, diubah 11 September 2026) di taktik Stealth dan Execution, dan mencakup DLL side-loading, search order hijacking, redirection, phantom DLL, dan substitusi [S9]. Side-loading berarti DLL berbahaya ditanam di samping aplikasi sah yang memuatnya, sehingga kode berjalan di bawah proses tepercaya; search order hijacking berarti DLL palsu diletakkan di folder yang dicari Windows lebih dulu daripada folder pustaka asli [S9]. Strategi deteksinya mencari pemuatan DLL dari folder tidak standar dan penggantian DLL, dengan mengorelasikan telemetri file, registry, dan pemuatan modul [S9]. Pola `INC-2027-040` masuk di sini: `pdfupdater.exe` bertanda tangan vendor di `AppData\Local\PDFSuite\` ditemani `version.dll` yang hash-nya berbeda dari IOC kasus lama (Day 09 bagian 2.7).
- **T1105 Ingress Tool Transfer.** Penyerang menyalin tool atau file dari luar ke host korban, sering lewat kanal C2 [S2]. Di Windows, binary bawaan seperti `certutil.exe` bisa mengunduh file dari URL sehingga tidak butuh tool tambahan [S8]; di Linux, halaman v20 (versi 2.6) menyebut `curl`, `wget`, `scp`, `sftp`, dan `rsync` sebagai alat yang lazim dipakai [S2]. Jejaknya di server ber-auditd adalah eksekusi tool itu dengan argumen tujuan eksternal.
- **T1071.001 Application Layer Protocol: Web Protocols.** C2 disembunyikan di HTTP, HTTPS, atau WebSocket supaya tercampur dengan trafik web biasa; v20 (versi 1.5) mencantumkan Linux di platformnya [S4]. Untuk server, yang bisa diburu tanpa sensor jaringan khusus adalah tujuan internet baru per server di log firewall, dibanding fungsi server itu.

Untuk persistence di `HUNT-2027-026`, dua teknik yang sudah dikenal dipakai sebagai pemeriksaan lanjutan: T1547.001 (program didaftarkan di Run key atau folder Startup agar berjalan saat logon [S3]) dan T1053.005 (scheduled task). `HUNT-2027-027` memakai teknik Execution yang sudah dipetakan sejak Day 10; satu-satunya yang baru diburu adalah T1059.003 Windows Command Shell, penyalahgunaan `cmd.exe` dan file batch untuk menjalankan perintah (versi 1.5, diubah 12 Mei 2026) [S20].

### 1.4 Perubahan telemetri menggeser baseline dan detection

Pertanyaan ketiga Dimas sering dijawab "bagus, datanya bertambah", padahal perubahan telemetri punya tiga akibat yang harus diperiksa sebelum data baru dipercaya.

- **Baseline lama tidak berlaku untuk populasi baru.** Baseline parent-child PT JAB (`jab_hunt_baseline_parentchild.csv`) dibangun dari Sysmon di 153 workstation Jakarta. Workstation Bandung dan POP punya software regional, skrip logon IT lokal, dan pola kerja sales yang tidak pernah ada di Jakarta. Membandingkan mereka dengan baseline Jakarta membuat semua kebiasaan regional tampak "baru". Analogi NOC-nya: profil trafik POP baru tidak dibandingkan dengan profil Jakarta; ia dibangun sendiri dulu.
- **Sumber baru tidak setara dengan sumber lama.** Event 4688 versi 2 (Windows 10) membawa `NewProcessName`, `ParentProcessName` (Creator Process Name), `CommandLine` bila setting command line aktif, `TokenElevationType`, dan `MandatoryLabel` [S19]. Ia tidak membawa hash, `OriginalFileName`, `ProcessGuid`, atau command line induk seperti Sysmon EID 1. Pola yang bergantung pada field itu, misalnya rename binary lewat `OriginalFileName` (Day 13 bagian 1.5), tetap buta di populasi baru.
- **Cakupan detection bergeser tanpa rule diubah.** Detection yang membaca `wineventlog` 4698 dan 4702 tiba-tiba melihat 81 workstation tambahan; detection yang dikonversi dengan pipeline `index=sysmon` tidak melihat satu pun. Kedua arah harus diketahui pemilik detection: yang pertama bisa menaikkan volume dan FP, yang kedua menciptakan kesan palsu bahwa populasi baru ikut terlindungi.

Prinsip yang sama sudah muncul di Day 06 bagian 1.2: data model `Endpoint.Processes` menerima Sysmon EID 1 dan juga 4688, sehingga setiap query harus menyebut sumbernya. Capstone menerapkannya pada perubahan yang terjadi semalam sebelum hunt.

### 1.5 Hasil negatif adalah temuan valid

Pertanyaan kelima Dimas punya jawaban yang sudah disiapkan Day 15 bagian 1.7, dan capstone menegakkannya dengan tiga syarat untuk setiap hunt. Hasil "tidak ditemukan" sah bila:

1. **Cakupannya tertulis per host.** Berapa host yang benar-benar menjawab atau mengirim data, bukan berapa yang direncanakan, dan host mana yang tidak (Day 09 bagian 1.4 untuk hunt yang kedaluwarsa).
2. **Querynya terbukti tidak buta.** Ada positive control: contoh nyata dari kasus lama (seperti `HUNT-2027-015` memakai koleksi `HUNT-2027-013`) atau aktivitas uji jinak di VM lab dengan telemetri yang sama (seperti `HUNT-2027-023`). Bila uji positif menemukan celah, query diperbaiki dan dijalankan ulang sebelum hasil ditulis.
3. **Item yang mirip pola diberi label dengan bukti di luar query.** Tiket, pemilik, konfirmasi pengguna, atau artefak lain. Label "jinak" tanpa bukti sama dengan tebakan.

Hunt negatif yang memenuhi tiga syarat itu memberi tahu Hendra persis area mana yang sudah diperiksa dan area mana yang belum bisa diperiksa, dan hampir selalu meninggalkan sesuatu: baseline, usulan detection, celah yang kini punya pemilik, atau hipotesis berikutnya. Yang tidak boleh adalah kebalikannya: menulis "tidak ditemukan" sebagai bukti bersih tanpa cakupan, atau mengubah hasil negatif menjadi "ditemukan" dengan menaikkan temuan jinak menjadi drama supaya presentasi terlihat berisi.

### 1.6 Dua jalur: PT JAB dan portofolio

Pertanyaan ketujuh Dimas punya batas yang tegas. Jalur kerja dan jalur portofolio memakai hipotesis dan metode yang sama, tetapi tidak berbagi data, nama, nomor, atau gambar. Tabel ini menjadi pegangan; baca kolom kanan sebelum menyalin apa pun ke repo pribadi.

| Aspek | Jalur kerja (PT JAB) | Jalur portofolio (lab pribadi) |
|---|---|---|
| Nomor hunt | `HUNT-2027-026` sampai `-028` | `HUNT-CAP-001` sampai `-003` |
| Data | Splunk, Velociraptor, Wazuh produksi PT JAB | VM lab milikmu: Splunk, Velociraptor, Wazuh, VM Windows dengan Sysmon, VM Linux, Atomic Red Team |
| Nama host, akun, IP | Host dan akun PT JAB | Nama lab buatan sendiri, IP privat lab atau rentang dokumentasi |
| Uji positif | Data kasus lama dan VM lab SOC (`jab-lab-win11`) | Test Atomic Red Team yang dicatat GUID-nya |
| Keluaran | Laporan di `jab-hunt`, usulan ke Sari, register, satu halaman evaluasi | Repo portofolio, write-up publik, layer Navigator, skor rubrik |
| Boleh dipublikasikan | Tidak | Ya, setelah sanitasi (Bagian J) |

Aturan sanitasi berlaku juga untuk organisasi fiktif: nama PT JAB, nomor insiden, dan host fiktifnya tidak dipakai di write-up publik, karena pembaca tidak bisa membedakan fiktif dari nyata dan karena nama itu mengikatmu ke catatan kerja. Write-up boleh ditulis dalam bahasa Inggris supaya bisa dibaca pewawancara di mana pun; penjelasan di catatan ini tetap bahasa Indonesia.

### 1.7 Peta konsep capstone

Peta ini menghubungkan Day 01 sampai 15 dengan langkah capstone; baca dari atas ke bawah sebagai satu siklus.

```
 Day 01-03  pemicu -> hipotesis ABLE -> abstract (backlog, nomor HUNT)
 Day 04     kartu kesiapan: sumber ada? field terisi? host mana yang mengirim? retensi?
 Day 05-06  teknik: stacking, first-seen, normalisasi, tstats + uji kesetaraan
 Day 08     Wazuh: archives, Query DSL, multi_terms, rule kustom
 Day 09     Velociraptor: hunt, canary, expiry, notebook, koleksi terarah
 Day 10-13  pola per taktik: persistence, credential, C2, LOLBin; uji positif di lab
 Day 14     temuan -> usulan deteksi (Sigma, ES, Wazuh), uji +/-, origin_hunt, tanggal aktif
 Day 15     Kategori hasil + blok Metrik -> register -> lembar metrik -> satu halaman
 Day 16     tiga hunt penuh + metrik 31 Mar + evaluasi Q1  ||  replikasi lab -> portofolio publik
```

## 2-4. Lab capstone dan troubleshooting

Bagian A sampai H adalah jalur kerja PT JAB, Selasa 2027-03-23 sampai Rabu 2027-03-31. Semua angka, nama, dan hasil di bagian ini fiktif dan merupakan keluaran ilustrasi; query ditulis untuk lingkungan PT JAB yang dijelaskan di Ide inti. Bagian I sampai L adalah jalur portofolio di lab pribadimu, dan hanya bagian itu yang dikerjakan di VM lab terisolasi milikmu.

### Bagian A: tiga abstract, Selasa 2027-03-23 pagi

Jawaban praktis untuk pertanyaan pertama Dimas adalah tiga abstract yang ditulis Selasa pukul 08:40 sampai 09:30, sebelum satu query pun dijalankan. Formatnya templat final Day 07 bagian 1.9; setiap baris "Kesiapan data" sudah diisi dari pemeriksaan singkat, bukan asumsi.

```
ID             : HUNT-2027-026
Dibuat         : Selasa 2027-03-23 08:40, pemilik: <kamu>, reviewer: Dimas Prasetyo
Asal usulan    : backlog Day 09 (dua kandidat turunan INC-2027-040)
Trigger        : Insiden - INC-2027-040: pdfupdater.exe bertanda tangan + version.dll di AppData
                 SBY-WS-0107, lolos IOC INC-2026-026 dan tidak terlihat di proxy (split tunnel)
Tipe (PEAK)    : Hypothesis-driven, analisis dengan stacking lintas fleet
Hipotesis      : Ada host Windows PT JAB yang menyimpan DLL bernama DLL sistem di folder yang bisa
                 ditulis pengguna (AppData, ProgramData, Users\Public) dan dimuat executable di folder
                 yang sama, tanpa alasan sah, apa pun mekanisme persistence-nya.
ABLE           : Actor tidak spesifik (pola kampanye installer PDF palsu dan variannya)
                 | Behavior DLL side-loading, T1574.001
                 | Location semua host Windows; prioritas laptop POP dan Bandung tanpa Sysmon
                 | Evidence file DLL di disk (path, ukuran, waktu, SHA1) dan modul yang dimuat proses
                   berjalan (path modul, sertifikat)
ATT&CK         : T1574.001 (Stealth, Execution; v20); persistence dicek lewat T1547.001 dan T1053.005
Data           : jkt-velo02 (Velociraptor 0.77.3): Windows.Search.FileFinder + Windows.System.DLLs,
                 semua client Windows; hasil dibekukan saat hunt kedaluwarsa Selasa 2027-03-30 09:40
Kesiapan data  : SIAP SEBAGIAN. 437 dari 443 host Windows terdaftar. Pemuatan image (Sysmon EID 7)
                 tidak dikumpulkan di host mana pun, jadi modul hanya terlihat dari proses yang sedang
                 berjalan saat collection
Di luar cakupan: host yang tidak tersambung sampai expiry; DLL dengan nama di luar daftar; DLL yang
                 sudah dihapus setelah dimuat; side-loading dari Program Files
Teknik analisis: stacking path ternormalisasi (folder + nama DLL) per host, pivot ke modul, hash, autostart
Kriteria sukses: semua pasangan (folder, nama DLL) dengan hosts <= 2 diberi label; positive control
                 SBY-WS-0107 tertandai; satu test T1574.001 di VM lab tertangkap
FP yang diduga : aplikasi per-user yang membawa pustaka sendiri, tool IT di ProgramData\JAB-IT,
                 sisa installer di Temp
Time-box       : satu minggu (expiry hunt); peninjauan Selasa 23 dan Selasa 30 Maret
Batas sumber   : timeout 1.200 s, max_rows 5.000, tanpa upload isi file; canary label velo-canary dulu
Handover       : IR (Dimas) bila ditemukan; Agung (celah image load); IT (software di luar katalog);
                 Sari (usulan); backlog
Status         : berjalan (Selasa 2027-03-23 09:00)
```

```
ID             : HUNT-2027-028
Dibuat         : Selasa 2027-03-23 09:10, dijalankan Kamis 2027-03-25; pemilik: <kamu>
Asal usulan    : pertanyaan Lutfi Hakim (Lead DevOps) lewat Dimas; backlog Day 08 (argumen curl/wget)
Trigger        : Keahlian domain + celah visibilitas: server Linux tanpa EDR (pelajaran INC-2026-012)
Tipe (PEAK)    : Hypothesis-driven
Hipotesis      : Ada server Linux PT JAB yang menghubungi tujuan internet di luar fungsi bisnisnya,
                 atau menjalankan tool jaringan (curl, wget, nc, socat, scp, sftp, rsync, whois)
                 ke tujuan eksternal yang tidak dikenal pemilik server.
ABLE           : Actor tidak spesifik | Behavior C2 lewat web (T1071.001), unduhan tool (T1105)
                 | Location 37 server Linux; argumen perintah hanya di jkt-bastion01 dan jkt-billing02
                 | Evidence (1) Wazuh archives key jab_exec: exe, a0-a7, auid, cwd;
                   (2) firewall pan:traffic akhir sesi dari IP server ke tujuan non-privat
ATT&CK         : T1071.001, T1105 (Command and Control; v20)
Data           : (1) wazuh-archives-* Kamis 2027-03-18 00:00 - Kamis 2027-03-25 00:00 WIB;
                 (2) index=firewall: baseline 2027-01-28 00:00 - 2027-02-25 00:00,
                     jendela 2027-02-25 00:00 - 2027-03-25 00:00 WIB
Kesiapan data  : SIAP SEBAGIAN. auditd execve hanya di 2 dari 4 server ber-Wazuh (G08) dan 6 dari 37
                 server Linux; daftar IP server Linux tidak ada di Splunk (disusun dari CMDB
                 Infrastruktur menjadi jab_hunt_linux_srv.csv); event firewall tertua 2026-12-23,
                 jadi baseline 28 hari tersedia
Di luar cakupan: koneksi dari dalam proses tanpa execve baru (misalnya kode di proses web); tujuan
                 privat; isi sesi; server Linux yang tidak tercatat di CMDB
Teknik analisis: stacking (server, exe, auid) dan argumen; first-seen tujuan per server di firewall
Kriteria sukses: semua eksekusi tool jaringan dengan tujuan eksternal diberi label; semua pasangan
                 (server, tujuan, port, app) yang baru muncul di jendela diberi label
FP yang diduga : cron billing ke payment gateway, rilis CI, mirror paket OS, NOC atau Infrastruktur
                 yang menguji layanan pelanggan dari bastion
Time-box       : satu hari
Handover       : IR (Dimas); Lutfi dan Agung (pemilik server); Sari (usulan); backlog
Status         : siap dijalankan
```

```
ID             : HUNT-2027-027
Dibuat         : Selasa 2027-03-23 09:30, dijalankan Selasa 2027-03-30; pemilik: <kamu>
Trigger        : Perubahan telemetri: G03 sebagian ditutup Senin 2027-03-22 20:00 (GPO JAB-WS-Audit
                 ditautkan ke OU Bandung dan OU POP); 81 workstation tanpa baseline proses
Tipe (PEAK)    : Baseline (populasi baru), lalu hypothesis-driven atas long tail-nya
Hipotesis      : Di workstation Bandung dan POP yang baru mengirim 4688, ada rantai proses yang tidak
                 ada di baseline Jakarta dan menjalankan program dari folder yang bisa ditulis pengguna,
                 atau Office dan script host yang memunculkan shell, tanpa alasan sah.
ABLE           : Actor tidak spesifik | Behavior eksekusi oleh pengguna dan interpreter (TA0002)
                 | Location 81 workstation (Bandung 58, Surabaya 13, Medan 10), laptop sales prioritas
                 | Evidence 4688 (NewProcessName, ParentProcessName, CommandLine) di wineventlog dan
                   Endpoint.Processes; 4698/4702 untuk task baru
ATT&CK         : T1204.002, T1059.001, T1059.003, T1059.005 (Execution); cek T1053.005
Data           : index=wineventlog EventCode 4688, 4698, 4702; host BDG-WS-*, SBY-WS-*, MDN-WS-*;
                 Selasa 2027-03-23 00:00 - Selasa 2027-03-30 00:00 WIB
Kesiapan data  : diukur di langkah pertama (host yang benar-benar mengirim, bukan yang ditautkan GPO)
Di luar cakupan: hash, OriginalFileName, koneksi jaringan, DNS (tidak ada di 4688); host yang belum
                 menerapkan GPO; 148 workstation Jakarta di luar OU Workstations-EDR
Teknik analisis: baseline per sumber dan populasi; stacking pasangan ternormalisasi terhadap baseline
                 Jakarta; filter perilaku; ukur dampak ke detection yang aktif
Kriteria sukses: cakupan per host tercatat; semua pasangan baru yang lolos filter perilaku diberi
                 label; baseline regional tersimpan; dampak ke 12 detection aktif tertulis
FP yang diduga : skrip logon IT lokal Bandung, aplikasi sales, driver printer, aplikasi yang sudah
                 dilaporkan (calsync), template bermakro
Time-box       : satu hari
Handover       : Sari (dampak detection); Agung (host yang belum menerapkan GPO, OU Jakarta); IT;
                 IR bila ditemukan
Status         : menunggu data tujuh hari
```

Cara membaca ketiganya:

- **Setiap hunt menyebut pelajaran asalnya.** "Asal usulan" dan "Trigger" menunjuk insiden, backlog, atau register, sehingga Hendra bisa melihat bahwa program belajar dari kuartalnya sendiri.
- **Kesiapan data ditulis SIAP SEBAGIAN, bukan SIAP.** Ketiganya punya batas yang sudah diketahui sebelum mulai (image load, auditd hanya dua server, populasi yang belum mengirim). Menulisnya di depan membuat hasil negatif nanti tidak terdengar seperti alasan.
- **Kriteria sukses memuat positive control.** Ini target Q2 dari Day 15 yang dimajukan ke capstone: tidak ada hunt capstone yang ditutup tanpa bukti bahwa query-nya menangkap contoh positif.
- **Time-box `HUNT-2027-026` satu minggu** karena sifat hunt Velociraptor, bukan karena hunt-nya dikerjakan seminggu penuh. Pekerjaan hunter-nya dua sesi: Selasa 23 dan Selasa 30.

**Kapan gagal:** abstract ditulis setelah hasil keluar, sehingga kriteria sukses menyesuaikan hasil; atau "Di luar cakupan" dikosongkan supaya hunt terlihat lengkap, lalu laporan negatif dibaca sebagai jaminan untuk host yang tidak pernah diperiksa.

### Bagian B: `HUNT-2027-026`, DLL bernama DLL sistem di folder pengguna (Velociraptor)

Hunt ini menjawab pertanyaan kedua Dimas. Pola `INC-2027-040` ditemukan lewat scheduled task, tetapi inti tekniknya side-loading: executable bertanda tangan vendor yang memuat `version.dll` palsu dari folder yang sama. Penyerang yang memakai pola sama bisa memilih Run key, folder Startup, atau sekadar menunggu pengguna menjalankan "updater" itu. Karena itu hunt ini mencari DLL-nya, bukan mekanisme persistence.

**Langkah 1, daftar nama DLL.** Daftar diambil dari HijackLibs, proyek komunitas yang memetakan DLL kandidat hijacking ke executable yang rentan, dengan metadata, aturan Sigma, dan ekspor CSV dan JSON [S15]. Entri `version.dll` di sana bertipe DLL side-loading, lokasi wajarnya `%SYSTEM32%` dan `%SYSWOW64%`, dan mencatat 42 executable rentan, termasuk aplikasi pihak ketiga yang berjalan dari `AppData` [S15]. Entri `winhttp.dll` mencatat 21 executable [S15]. Entri `dbghelp.dll` justru punya banyak lokasi wajar di luar `System32` (folder debugger Windows Kits, folder Office, folder Cisco Jabber) [S15], sehingga nama itu pasti menghasilkan FP di folder aplikasi; ia tetap dipakai karena hunt ini hanya melihat folder yang bisa ditulis pengguna. HijackLibs sendiri menyebut aturan Sigma-nya untuk `version.dll` kemungkinan besar menghasilkan false positive [S15], dan itu alasan pola ini dijalankan sebagai hunt dengan stacking, bukan langsung sebagai alert. Dua belas nama dipakai di awal: `version`, `winhttp`, `dbghelp`, `wtsapi32`, `userenv`, `cryptbase`, `dwmapi`, `uxtheme`, `winmm`, `secur32`, `iphlpapi`, `netapi32`.

**Langkah 2, konfigurasi hunt.** Dua artifact dijalankan dalam satu hunt, supaya disk dan memori dibaca pada kunjungan yang sama.

| Artifact | Parameter | Nilai | Alasan |
|---|---|---|---|
| `Windows.Search.FileFinder` | `SearchFilesGlobTable` | tiga baris glob (di bawah) | Satu hunt untuk tiga lokasi yang bisa ditulis pengguna [S13] |
| | `Calculate_Hash` | `Y` | SHA1 untuk dibandingkan antar host dan dengan IOC lama [S13] |
| | `Upload_File` | `N` | Hanya metadata; isi file tidak dikirim (default PT JAB, Day 09) |
| `Windows.System.DLLs` | `DllRegex` | regex nama DLL di folder pengguna (di bawah) | Hanya modul yang relevan; default `.` mengembalikan semua modul [S12] |
| | `CertificateInfo` | `Y` | Penanda tangan modul, untuk dibandingkan dengan penanda tangan executable [S12] |
| | `Calculate_Hash` | `Y` | Hash modul yang sedang dimuat [S12] |

Glob di `SearchFilesGlobTable`:

```
Glob
C:\Users\*\AppData\**10\{version,winhttp,dbghelp,wtsapi32,userenv,cryptbase,dwmapi,uxtheme,winmm,secur32,iphlpapi,netapi32}.dll
C:\ProgramData\**10\{version,winhttp,dbghelp,wtsapi32,userenv,cryptbase,dwmapi,uxtheme,winmm,secur32,iphlpapi,netapi32}.dll
C:\Users\Public\**10\{version,winhttp,dbghelp,wtsapi32,userenv,cryptbase,dwmapi,uxtheme,winmm,secur32,iphlpapi,netapi32}.dll
```

`DllRegex` untuk `Windows.System.DLLs`:

```
(?i)\\(users|programdata)\\.+\\(version|winhttp|dbghelp|wtsapi32|userenv|cryptbase|dwmapi|uxtheme|winmm|secur32|iphlpapi|netapi32)\.dll$
```

| Bagian | Fungsi |
|---|---|
| `{a,b,...}` | Alternatif dalam glob Velociraptor, dipisah koma [S14] |
| `**10` | Rekursif sampai 10 tingkat; tanpa angka, `**` hanya 3 tingkat [S14], terlalu dangkal untuk `AppData\Local\Programs\<vendor>\<versi>\` |
| Pencocokan glob | Tidak peka huruf besar/kecil; `/` dan `\` sama-sama diterima sebagai pemisah [S14] |
| `FileFinder` membaca `Glob` atau `SearchFilesGlobTable` | Keduanya diteruskan ke plugin `glob()`; hash dihitung untuk setiap file bukan folder bila `Calculate_Hash` aktif [S13] |
| `Windows.System.DLLs` | Mengambil proses lewat `pslist()`, lalu modul tiap proses lewat `modules()`, dan menyimpan baris yang `ModulePath`-nya cocok dengan `DllRegex` [S12] |

Kolom keluaran `FileFinder` adalah `OSPath`, `Size`, `MTime`, `ATime`, `CTime`, `BTime`, `IsDir`, `Hash`, dan beberapa lainnya [S13]; kolom `Windows.System.DLLs` adalah `Pid`, `Name`, `_Exe`, `_CommandLine`, `ModuleName`, `ModulePath`, `Hash`, dan `Certinfo` [S12]. Bentuk isi `Hash` dan `Certinfo` (nama sub-field) perlu dicek di satu baris hasil canary sebelum query notebook ditulis.

**Langkah 3, canary dan cakupan.** Hunt dijalankan ke label `velo-canary` (25 client) pukul 09:00 dan selesai 09:31: durasi median 3 menit 10 detik, maksimum 9 menit 40 detik di satu server file, tanpa keluhan pengguna. Glob rekursif 10 tingkat di `AppData` lebih berat daripada artifact Day 09, sehingga timeout dinaikkan ke 1.200 detik sebelum hunt seluruh fleet dimulai pukul 09:40 (mengecualikan label canary). Cakupan dibekukan saat hunt kedaluwarsa Selasa 2027-03-30 09:40, dan tabel berikut adalah angka yang masuk laporan; baca baris "tidak menjawab", karena di sanalah batas kesimpulannya.

| Kelompok | Inventaris AD | Terdaftar | Menjawab sampai expiry | Tidak menjawab |
|---|---|---|---|---|
| Server Windows | 61 | 61 | 61 | 0 |
| Workstation Jakarta | 301 | 301 | 299 | 2 (terdaftar, offline sepanjang minggu) |
| Workstation Bandung | 58 | 58 | 56 | 2 (terdaftar, offline) |
| Workstation Surabaya | 13 | 10 | 7 | 6 (3 offline, 3 belum terdaftar) |
| Workstation Medan | 10 | 7 | 5 | 5 (2 offline, 3 belum terdaftar) |
| Total | 443 | 437 | 428 | 15 |

Dua laptop Bandung sempat dibatalkan timeout dan dijadwalkan ulang dengan 1.800 detik; keduanya selesai. Workstation POP yang tercakup hanya 12 dari 23, dan `SBY-WS-0107` (host `INC-2027-040`) termasuk yang tidak tersambung minggu itu. Kalimat ini masuk laporan apa adanya: kesimpulan untuk POP lebih lemah daripada untuk Jakarta.

**Langkah 4, stacking di notebook.**

**Tujuan:** menghitung berapa host memiliki setiap pasangan folder dan nama DLL, setelah nama pengguna, folder sementara, dan nomor versi dinormalisasi, lalu melihat pasangan yang hanya ada di satu atau dua host.

```
LET names = '''\\(version|winhttp|dbghelp|wtsapi32|userenv|cryptbase|dwmapi|uxtheme|winmm|secur32|iphlpapi|netapi32|amsi)\.dll$'''

LET raw = SELECT ClientId, lowcase(string=format(format="%v", args=OSPath)) AS P, Hash.SHA1 AS SHA1
FROM source(artifact="Windows.Search.FileFinder")
WHERE NOT IsDir

LET norm = SELECT ClientId, SHA1,
       regex_replace(
         source=regex_replace(
           source=regex_replace(source=P, re='''\\users\\[^\\]+\\''', replace='''\users\<user>\'''),
           re='''\\temp\\[^\\]+\\''', replace='''\temp\<rnd>\'''),
         re='''\\[a-z_-]*\d+(\.\d+)+\\''', replace='''\<ver>\''') AS PathN
FROM raw
WHERE P =~ names

LET per_host = SELECT PathN, ClientId, format(format="%v|%v", args=[PathN, ClientId]) AS Key
FROM norm
GROUP BY Key

LET stack = SELECT PathN, count() AS hosts, enumerate(items=ClientId) AS clients
FROM per_host
GROUP BY PathN

SELECT * FROM stack WHERE hosts <= 2 ORDER BY hosts
```

| Bagian | Fungsi |
|---|---|
| `names` | Regex nama DLL di akhir path; `amsi` ditambahkan setelah uji lab (langkah 6) |
| `lowcase(string=format(format="%v", args=OSPath))` | `OSPath` diubah ke string huruf kecil supaya normalisasi dan pencocokan konsisten |
| Tiga `regex_replace` bersarang | `\users\<user>\`, `\temp\<rnd>\`, dan segmen bernomor versi menjadi `\<ver>\`, padanan macro `jab_norm_parentchild` di SPL (Day 05 bagian 2.3) |
| `GROUP BY Key` lalu `GROUP BY PathN` | Dua tahap: satu baris per pasangan dan host, lalu jumlah host per pasangan; VQL tidak punya distinct count (Day 09 bagian 1.6) |
| `WHERE hosts <= 2` di luar `GROUP BY` | Filter atas hasil agregat |

Nama fungsi `lowcase()`, `regex_replace()`, `enumerate()`, cara mengubah `OSPath` menjadi string, dan akses `Hash.SHA1` perlu diuji di notebook lab versi 0.77.x sebelum dipakai.

Keluaran ilustrasi (statistik):

```
Client yang menjawab                    : 428 (61 server + 367 workstation)
Baris FileFinder (file DLL cocok glob)  : 3.874 dari 402 host
PathN unik (folder + nama)              : 71
  hosts >= 3                            : 59  (aplikasi per-user resmi yang membawa pustaka sendiri)
  hosts <= 2                            : 12  (8 dengan hosts = 1, 4 dengan hosts = 2)
SHA1 sama dengan IOC INC-2026-026 (3f9c2b7e...) atau varian SBY-WS-0107 (9b1e47d2...): 0
Baris Windows.System.DLLs               : 1.206 dari 296 host
  pasangan (proses, modul) hosts <= 2   : 9
```

**Cara membaca hasil:** 3.874 file terdengar banyak, tetapi 59 dari 71 pasangan ada di tiga host atau lebih, dan semuanya folder aplikasi per-user yang dikenal (klien rapat, add-in, viewer). Pemeriksaan hash terhadap dua IOC lama ikut dijalankan karena murah, tetapi bukan inti hunt: `INC-2027-040` sendiri lolos IOC karena hash-nya berbeda. Dua belas pasangan langka ditinjau di langkah 7.

**Langkah 5, pivot ke modul dan autostart.**

**Tujuan:** mengetahui apakah DLL langka benar-benar dimuat proses, oleh executable apa, dan apakah penanda tangan modul sama dengan penanda tangan executable.

```
LET mods = SELECT ClientId, lowcase(string=Name) AS Proc, lowcase(string=_Exe) AS ExeP,
       lowcase(string=ModulePath) AS M, Certinfo
FROM source(artifact="Windows.System.DLLs")

LET norm = SELECT ClientId, Proc, ExeP, Certinfo,
       regex_replace(
         source=regex_replace(source=M, re='''\\users\\[^\\]+\\''', replace='''\users\<user>\'''),
         re='''\\[a-z_-]*\d+(\.\d+)+\\''', replace='''\<ver>\''') AS ModN
FROM mods

LET per_host = SELECT Proc, ModN, ClientId,
       format(format="%v|%v", args=[Proc, ModN]) AS Pair,
       format(format="%v|%v|%v", args=[Proc, ModN, ClientId]) AS Key
FROM norm
GROUP BY Key

SELECT Proc, ModN, count() AS hosts, enumerate(items=ClientId) AS clients
FROM per_host
GROUP BY Pair
ORDER BY hosts
```

Keluaran ilustrasi: 9 pasangan dengan hosts maksimal 2. Lima berasal dari folder kandidat disk (viewer vendor Network Planning, launcher pribadi, tiga tool IT). Empat adalah klien rapat versi lama di laptop yang belum restart setelah pembaruan, sehingga proses lama masih memuat DLL dari folder versi sebelumnya. Untuk pasangan viewer, `Certinfo` modul `version.dll` dan executable `fpviewer.exe` menyebut penanda tangan vendor yang sama.

Pemeriksaan autostart memakai dua sumber yang sudah ada, bukan hunt baru: baseline autoruns `HUNT-2027-012` (Day 09 bagian 2.3) dan hasil hunt Velociraptor mingguan TaskScheduler terakhir (Senin 2027-03-29). `Windows.Sysinternals.Autoruns` menjalankan `autorunsc` di host dan mem-parse keluarannya [S7], jadi untuk dua host yang tidak tercakup baseline Februari, koleksi terarah artifact itu dijalankan Selasa 30 Maret pukul 10:30. Hasilnya dipakai di langkah 7.

**Variasi:** stacking per SHA1 alih-alih path, untuk menemukan DLL yang sama persis di folder berbeda (pola penyerang yang meniru nama folder vendor di beberapa host); atau membandingkan `BTime` file DLL dengan `BTime` executable di folder yang sama, karena DLL yang ditanam belakangan lebih baru daripada aplikasinya.

**Kapan gagal:** proses yang memuat DLL palsu tidak sedang berjalan saat collection, sehingga `Windows.System.DLLs` kosong dan hanya disk yang tersisa; DLL palsu memakai nama di luar daftar; atau normalisasi versi terlalu agresif sehingga folder penyerang yang meniru pola `app-1.2.3` tergabung dengan folder vendor asli.

**Langkah 6, positive control dan uji lab.** Dua uji dijalankan sebelum hasil ditulis.

- **Data nyata lama.** Query langkah 4 dijalankan atas koleksi terarah `HUNT-2027-013` di `SBY-WS-0107` (Kamis 2027-02-25, client `C.4e1a9b07d2c3f815`, artifact `Windows.Search.FileFinder`) dengan `source()` yang diarahkan ke client dan flow koleksi itu. Hasilnya satu baris: `c:\users\<user>\appdata\local\pdfsuite\version.dll`, hosts 1, SHA1 `9b1e47d2...`. Query sanggup menandai pola yang memicu hunt ini.
- **VM lab `jab-lab-win11`** (jaringan lab SOC terisolasi, bukan host PT JAB), Selasa 2027-03-23 13:00 sampai 13:40. Test Atomic Red Team T1574.001 nomor 1 (`8549ad4b-b5df-4a2d-a3d7-2aee9e7052a3`) menyalin `amsi.dll` milik sistem dan salinan PowerShell yang diganti nama menjadi `updater.exe` ke `%APPDATA%`, lalu menjalankannya; test ini butuh hak admin dan cleanup-nya menghapus kedua file [S10]. Hasil pertama: tidak tertangkap, karena `amsi.dll` tidak ada di daftar dua belas nama. Daftar diperluas dengan `amsi`, test dijalankan ulang, dan kedua artifact menandainya.

Karena daftar berubah setelah hunt utama berjalan, Selasa pukul 14:00 dibuat hunt susulan di bawah nomor yang sama, hanya `FileFinder` dengan glob `amsi.dll` di tiga lokasi yang sama, expiry juga Selasa 30 Maret 09:40. Hasilnya: 0 baris dari 426 client yang menjawab. Pola perbaikannya sama dengan `HUNT-2027-023` yang menemukan celah `about:` lewat uji lab (Day 13 bagian 2.4): uji positif menemukan kebutaan sebelum kesimpulan ditulis, bukan sesudahnya.

**Langkah 7, label.** Tabel ini adalah hasil peninjauan dua belas pasangan; baca kolom "Bukti", karena label tanpa bukti di luar query tidak diterima.

| Kelompok | Pasangan | Contoh path ternormalisasi | Host | Bukti |
|---|---|---|---|---|
| Tool IT di `ProgramData\JAB-IT` | 5 (3 dengan 1 host, 2 dengan 2 host) | `c:\programdata\jab-it\tools\<ver>\dbghelp.dll` | 7 workstation Jakarta | Tiket IT; dipasang helpdesk; executable dan DLL ditandatangani vendor tool |
| Sisa installer di Temp | 2 | `c:\users\<user>\appdata\local\temp\<rnd>\winmm.dll` | 2 | Installer driver printer, folder tidak dipakai lagi; IT membersihkan |
| Viewer vendor Network Planning | 1 | `c:\users\<user>\appdata\local\programs\fiberplan-viewer\version.dll` | `JKT-WS-0611`, `JKT-WS-0614` | Executable dan DLL bertanda tangan vendor yang sama; hash DLL identik di kedua host; tiket pemasangan IT |
| Launcher pribadi | 1 | `c:\users\<user>\appdata\roaming\retrolauncher\winmm.dll` | `JKT-WS-0648`, `JKT-WS-0655` | Launcher game bertanda tangan penerbitnya; Run key HKCU (T1547.001) dari koleksi autoruns terarah; dipasang pengguna Senin 2027-03-08; software di luar katalog, tiket ke IT |
| Regional | 3 | `c:\users\public\remoteassist\wtsapi32.dll`; `c:\programdata\printvendor\tools\dbghelp.dll`; `c:\programdata\modemdash\iphlpapi.dll` | `BDG-WS-0229`, `SBY-WS-0112`, `MDN-WS-0014` | Sisa tool remote support IT lokal Bandung tanpa executable (dibersihkan); helper driver printer yang sudah dikenal sejak `HUNT-2027-015`; dashboard modem USB laptop sales Medan (pola `HUNT-2027-012`) |

Jumlahnya cocok: 5 + 2 + 1 + 1 + 3 = 12 pasangan, dan pasangan dengan dua host ada 2 + 1 + 1 = 4. Pasangan yang paling mirip pola `INC-2027-040` adalah viewer vendor: executable bertanda tangan di `AppData` dengan `version.dll` di sampingnya. Yang membedakannya dari `pdfupdater.exe` adalah bukti di luar query: penanda tangan DLL sama dengan penanda tangan aplikasinya, hash identik di dua host yang dipasang lewat tiket, dan tidak ada persistence yang tidak dikenal. Nama dan lokasi saja tidak cukup untuk menyebut jinak atau jahat.

**Hasil:** tidak ditemukan (tidak terbukti) di 428 host yang menjawab, untuk tiga belas nama DLL dan tiga lokasi yang bisa ditulis pengguna. Satu software di luar katalog dilaporkan ke IT. Laporan finalnya di Bagian E.

### Bagian C: `HUNT-2027-028`, server Linux bicara ke internet (Wazuh dan firewall)

Hunt ini menjawab pertanyaan keempat Dimas, pertanyaan Lutfi. Ia dikerjakan Kamis 2027-03-25 dan punya dua sisi yang saling melengkapi: argumen perintah lengkap (hanya ada di archives untuk dua server ber-auditd) dan koneksi keluar (firewall, satu-satunya sumber untuk 37 server). Bentuk query-nya mengikuti Day 08 bagian 2.5 dan 2.6 (Wazuh) serta Day 12 bagian 2.3 (firewall).

**Langkah 1, tool jaringan di dua server ber-auditd.**

**Tujuan:** mengambil setiap eksekusi tool pemindah atau pengunduh file yang argumennya memuat tujuan eksternal.

```
GET wazuh-archives-*/_search
{
  "size": 200,
  "_source": ["timestamp", "agent.name", "data.audit.exe", "data.audit.execve.a0",
              "data.audit.execve.a1", "data.audit.execve.a2", "data.audit.execve.a3",
              "data.audit.auid", "data.audit.cwd"],
  "sort": [ { "timestamp": "asc" } ],
  "query": { "bool": {
    "filter": [
      { "term":  { "data.audit.key": "jab_exec" } },
      { "range": { "timestamp": { "gte": "2027-03-18T00:00:00+07:00", "lt": "2027-03-25T00:00:00+07:00" } } },
      { "terms": { "data.audit.exe": [
          "/usr/bin/curl", "/usr/bin/wget", "/usr/bin/scp", "/usr/bin/sftp",
          "/usr/bin/rsync", "/usr/bin/nc", "/bin/nc", "/usr/bin/ncat",
          "/usr/bin/socat", "/usr/bin/whois", "/usr/bin/ssh" ] } }
    ]
  } }
}
```

| Bagian | Fungsi |
|---|---|
| `terms` atas `data.audit.exe` | Daftar tool jaringan dengan path absolut; `data.audit.exe` adalah path biner yang dijalankan [S16] |
| `_source` `a0` sampai `a3` | Empat argumen pertama; auditd hanya mengekstrak sampai `a7` dan tidak lebih [S16] |
| `range` tujuh hari absolut WIB | Satu minggu, selaras jendela archives |

Keluaran ilustrasi: 142 eksekusi, 2 server. Setelah membuang argumen yang jelas lokal (`127.0.0.1`, `10.`, host internal `*.corp.jab.example`) dengan membaca `a1` sampai `a3`, tersisa 11 eksekusi dengan tujuan yang bukan privat:

```
timestamp                  agent          exe            a1..a3 (tujuan, dipendekkan)                     auid
2027-03-19T22:06:11+07:00  jkt-billing02  /usr/bin/curl  -fsS https://repo.debian.org/...               1501
2027-03-19T22:06:14+07:00  jkt-billing02  /usr/bin/curl  -s https://pay-gw.bankpartner.example/health  1501
2027-03-20T03:00:02+07:00  jkt-billing02  /usr/bin/rsync -az /var/backups billing@vault... (203.0.113.200) 1403
2027-03-23T10:41:55+07:00  jkt-bastion01  /usr/bin/ssh   netops@cpe-98.51.100.* (pelanggan)             1012
...
```

**Cara membaca hasil:** 11 eksekusi, semua dari kedua server yang memang punya fungsi keluar: `jkt-billing02` (cron billing ke payment gateway `pay-gw.bankpartner.example`, mirror paket OS, backup ke vault vendor) dan `jkt-bastion01` (engineer NOC SSH ke CPE pelanggan untuk troubleshooting). Semua `auid` memetakan ke akun layanan atau engineer yang dikenal, dan tujuannya cocok dengan fungsi server. Konfirmasi ke Lutfi dan Bambang: tidak ada yang di luar kebiasaan. Label: jinak.

**Kapan gagal:** tool dijalankan lewat path non-standar atau nama lain (`/usr/local/bin/curl`, biner statis yang dibawa penyerang), sehingga `terms` atas path tidak cocok; argumen tujuan ada di luar `a3` (misalnya setelah banyak flag); atau koneksi dibuat dari dalam proses yang sudah berjalan (library HTTP aplikasi), yang tidak menghasilkan execve baru dan hanya terlihat di firewall (langkah 2).

**Langkah 2, tujuan internet baru per server (firewall).** Karena execve hanya ada di dua server, koneksi 35 server lain hanya terlihat di firewall. Pendekatannya first-seen: tujuan eksternal yang baru muncul di jendela dibanding baseline 28 hari.

**Tujuan:** menemukan pasangan (server, tujuan, port, aplikasi) yang pertama kali muncul di jendela hunt, untuk server Linux saja.

```
index=firewall sourcetype=pan:traffic eventtype=pan_traffic_end
    earliest="01/28/2027:00:00:00" latest="03/25/2027:00:00:00"
| lookup jab_hunt_linux_srv.csv ip AS src OUTPUT role
| where isnotnull(role)
| where NOT (cidrmatch("10.0.0.0/8", dest) OR cidrmatch("172.16.0.0/12", dest)
             OR cidrmatch("192.168.0.0/16", dest))
| eval win=if(_time>=relative_time(strptime("02/25/2027:00:00:00","%m/%d/%Y:%H:%M:%S"),"+0s"), "hunt", "base")
| stats min(_time) AS first_seen values(win) AS wins count BY src role dest dest_port app
| where first_seen>=strptime("02/25/2027:00:00:00","%m/%d/%Y:%H:%M:%S")
| sort first_seen
```

| Bagian | Fungsi |
|---|---|
| `lookup jab_hunt_linux_srv.csv ip AS src OUTPUT role` | Hanya trafik dari IP server Linux (daftar dari CMDB Infrastruktur, karena Splunk tidak punya peta ini) |
| `where NOT (cidrmatch ...)` | Buang tujuan privat; di `eval`/`where` dipakai `cidrmatch`, bukan CIDR di `search` (Day 12 bagian 1.x) |
| `eval win=if(_time>= ... )` | Tandai tiap event baseline atau jendela hunt |
| `stats min(_time) ... BY src role dest dest_port app` | Satu baris per tujuan unik per server, dengan waktu pertama |
| `where first_seen>= ...` | Hanya tujuan yang first-seen-nya di dalam jendela hunt (tidak ada di baseline) |

Keluaran ilustrasi: 6 pasangan baru.

```
src          role          dest            dport app          first_seen            wins  count
10.20.1.60   portal        203.0.113.188   443   ssl          2027-03-04 02:15      hunt  31
10.20.7.12   app           203.0.113.201   443   ssl          2027-03-12 14:08      hunt  4
10.20.2.25   mailgw        198.51.100.95   25    smtp         2027-03-02 09:41      hunt  212
10.20.1.33   radius        198.51.100.120  443   ssl          2027-03-19 11:20      hunt  2
10.20.8.37   pdu           203.0.113.61    8883  mqtt         2027-03-01 00:03      base  ...
10.20.9.10   netops        203.0.113.221   443   ssl          2027-03-17 02:00      hunt  9
```

**Cara membaca hasil:** lima pasangan baru plus satu (`jkt-pdu07`) yang ternyata sudah ada di baseline dan tersaring keluar. Semua lima ditinjau dengan pemilik server: `jkt-portal02` ke mirror CDN baru vendor aplikasi portal (change Lutfi 2027-03-04), `jkt-app03` ke endpoint lisensi vendor baru, mail gateway ke relay SMTP partner yang memang baru ditambah (tiket NOC), `jkt-radius01` dua koneksi ke NAT Jakarta (uji konektivitas oleh adm.agung, tiket), dan `jkt-netops01` ke endpoint telemetri perangkat (change Infrastruktur). Label semuanya: jinak. Catatan ke Agung: `jkt-netops01` belum dipasang agent Wazuh (fakta tetap), jadi hanya firewall yang melihatnya, dan `jkt-radius01` termasuk server tanpa rule auditd `jab_exec` (G08), jadi execve-nya tidak ikut langkah 1.

**Hasil `HUNT-2027-028`:** tidak ditemukan komunikasi di luar fungsi, di dua server ber-auditd (argumen perintah) dan 35 server lain (first-seen tujuan firewall). Dua celah lama ditegaskan: G08 (auditd belum di `jkt-portal02` dan `jkt-radius01`) dan tidak adanya agent di `jkt-netops01`. Usulan detection di Bagian E.

### Bagian D: dampak perubahan GPO ke hunt, baseline, dan detection

Pertanyaan ketiga Dimas dijawab dengan tiga pemeriksaan, dijalankan Selasa 2027-03-30 pagi sebelum `HUNT-2027-027`. Jawabannya bukan "sekarang semua workstation tercakup", melainkan daftar yang bergeser dan yang belum.

**Pemeriksaan 1, populasi telemetri nyata.** Menautkan GPO tidak sama dengan workstation benar-benar mengirim 4688; GPO harus diterapkan (gpupdate atau reboot) dan event harus sampai ke Splunk. Query ini mengukur siapa yang benar-benar mengirim, bukan siapa yang ditautkan.

```
index=wineventlog sourcetype=XmlWinEventLog EventCode=4688
    (host=BDG-WS-* OR host=SBY-WS-* OR host=MDN-WS-*)
    earliest="03/23/2027:00:00:00" latest="03/30/2027:00:00:00"
| stats count AS ev dc(host) AS hosts_sending BY host
| stats count AS hosts_sending sum(ev) AS events
```

```
hosts_sending  events
63             1.804.219
```

**Cara membaca:** dari 81 workstation yang GPO-nya ditautkan, 63 benar-benar mengirim 4688 dalam tujuh hari; 18 belum (offline sepanjang minggu, atau GPO belum diterapkan karena belum reboot). Baseline regional dibangun atas 63 host yang mengirim, bukan 81, dan laporan menulis itu.

**Pemeriksaan 2, baseline mana yang berlaku.** Baseline parent-child Jakarta (`jab_hunt_baseline_parentchild.csv`) tidak dipakai sebagai pembanding untuk host regional, karena kebiasaan regional akan tampak "baru". Baseline regional dibangun terpisah sebagai `jab_hunt_baseline_parentchild_regional.csv` di langkah `HUNT-2027-027` (Bagian E), dan hunt hanya menandai pasangan yang baru terhadap gabungan kedua baseline, dengan catatan sumbernya 4688, bukan Sysmon.

**Pemeriksaan 3, detection yang bergeser cakupannya.** Dua belas detection aktif diperiksa dampaknya; tabel ini dikirim ke Sari. Baca kolom "Aksi", karena perubahan sumber data menuntut keputusan, bukan sekadar pemberitahuan.

| Detection (origin_hunt) | Sumber | Dampak GPO 22 Mar | Aksi |
|---|---|---|---|
| Scheduled task AppData (`-015`) | `wineventlog` 4698/4702 | Kini melihat 63 workstation baru; volume dan FP bisa naik | Pantau volume 1 minggu; siapkan pengecualian untuk aplikasi regional |
| Logon admin ke ws selain JKT-JUMP01 (`-019`) | `wineventlog` 4624 (sudah 443 host) | Tidak berubah (4624 sudah dari semua host) | Tidak ada |
| Office signed proxy binary (`-023`) | `index=sysmon` via pipeline | Tidak melihat host regional (4688 tidak masuk pipeline sysmon) | Catat: populasi baru TIDAK terlindungi; kandidat backtest ulang setelah Sysmon |
| Proxy binary scriptlet (`-023`), script host (`-025`) | `index=sysmon` | Sama dengan di atas | Sama |
| certutil/bitsadmin (`-002`) | `index=sysmon` | Sama | Sama |
| Beacon, unggahan, FBD (`-020`, `-022`) | proxy, firewall | Workstation POP keluar lewat firewall POP tanpa proxy (fakta tetap); tidak berubah | Tidak ada |
| Wazuh 100200, 100201 (`-010`) | archives Linux | Tidak terkait | Tidak ada |

**Cara membaca:** satu detection (`-015`) kini melihat lebih banyak host dan butuh pemantauan FP; lima detection berbasis Sysmon tetap buta di populasi baru walaupun GPO berubah, karena 4688 tidak masuk pipeline konversi mereka. Inilah inti pertanyaan ketiga Dimas: perubahan telemetri menutup satu celah (proses di workstation regional kini terlihat untuk hunting dan untuk `-015`) tetapi tidak membuat detection Sysmon ikut melindungi mereka. Kesan "sekarang aman" adalah jebakan; yang benar adalah "sekarang terlihat untuk hunting dan satu detection, belum untuk lima lainnya".

**Kapan gagal:** menyimpulkan cakupan dari jumlah GPO yang ditautkan, bukan dari host yang mengirim event; atau mengira detection berbasis Sysmon ikut melihat 4688 karena keduanya "sama-sama proses", padahal pipeline konversinya mengunci `index=sysmon sourcetype=XmlWinEventLog` (Day 14 bagian 2.3).

### Bagian E: `HUNT-2027-027`, baseline dan hunt populasi regional (Splunk)

Hunt ini dikerjakan Selasa 2027-03-30, setelah data 4688 regional mencapai tujuh hari. Ia menindaklanjuti pemeriksaan Bagian D: membangun baseline regional dulu, lalu berburu di long tail-nya. Field 4688 berbeda dari Sysmon, jadi hunt ini sengaja hanya memakai yang ada di 4688.

**Langkah 1, baseline regional.**

**Tujuan:** menyimpan pasangan parent-child ternormalisasi dari 63 workstation regional yang mengirim 4688, sebagai baseline terpisah.

```
index=wineventlog sourcetype=XmlWinEventLog EventCode=4688
    (host=BDG-WS-* OR host=SBY-WS-* OR host=MDN-WS-*)
    earliest="03/23/2027:00:00:00" latest="03/30/2027:00:00:00"
| eval ParentImage=coalesce(ParentProcessName, parent_process_name),
       Image=coalesce(NewProcessName, process_name)
| `jab_norm_parentchild`
| stats count AS executions dc(host) AS hosts min(_time) AS first_seen BY parent_n child_n
| outputlookup jab_hunt_baseline_parentchild_regional.csv
```

| Bagian | Fungsi |
|---|---|
| `coalesce(ParentProcessName, ...)` dan `coalesce(NewProcessName, ...)` | 4688 memakai `ParentProcessName` (Creator Process Name) dan `NewProcessName` [S19]; macro `jab_norm_parentchild` membaca `ParentImage` dan `Image`, jadi keduanya diselaraskan dulu |
| `` `jab_norm_parentchild` `` | Macro normalisasi yang sama dengan baseline Jakarta (Day 05 bagian 2.3), supaya kedua baseline sebanding |
| `outputlookup` | Simpan sebagai baseline regional terpisah |

**Langkah 2, hunt long tail terhadap dua baseline.**

**Tujuan:** menemukan pasangan parent-child di workstation regional yang tidak ada di baseline Jakarta maupun regional, dan menjalankan program dari folder yang bisa ditulis pengguna atau memunculkan shell dari Office atau script host.

```
index=wineventlog sourcetype=XmlWinEventLog EventCode=4688
    (host=BDG-WS-* OR host=SBY-WS-* OR host=MDN-WS-*)
    earliest="03/23/2027:00:00:00" latest="03/30/2027:00:00:00"
| eval ParentImage=coalesce(ParentProcessName, parent_process_name),
       Image=coalesce(NewProcessName, process_name), CommandLine=coalesce(CommandLine, process)
| `jab_norm_parentchild`
| where match(child_n, "c:/users/|c:/programdata/|/temp/|/appdata/")
     OR (match(parent_n, "winword|excel|powerpnt|outlook|mshta|wscript|cscript")
         AND match(child_n, "cmd\.exe|powershell|regsvr32|rundll32|mshta"))
| stats count AS executions dc(host) AS hosts values(host) AS host_list min(_time) AS first_seen
    BY parent_n child_n
| lookup jab_hunt_baseline_parentchild.csv parent_n child_n OUTPUT first_seen AS seen_jkt
| lookup jab_hunt_baseline_parentchild_regional.csv parent_n child_n OUTPUT first_seen AS seen_reg
| where isnull(seen_jkt)
| sort hosts
```

| Bagian | Fungsi |
|---|---|
| `where match(child_n, ...) OR (match(parent_n ...) AND match(child_n ...))` | Dua pola berbahaya: anak dari folder user-writable, atau Office/script host memunculkan shell |
| dua `lookup ... OUTPUT first_seen` | Bandingkan dengan kedua baseline |
| `where isnull(seen_jkt)` | Buang yang sudah dikenal di Jakarta; baseline regional dipakai untuk memberi konteks "baru di regional juga" di tinjauan, bukan sebagai filter keras di sini |

Keluaran ilustrasi: 1.804.219 event, 1.206 pasangan ternormalisasi, 38 lolos filter perilaku, 9 tidak ada di baseline Jakarta. Setelah menandai mana yang juga tidak ada di baseline regional (`seen_reg` null), 4 pasangan benar-benar baru di kedua baseline. Semua 9 ditinjau; tabel ringkasnya:

| Pasangan | Host | Label dan bukti |
|---|---|---|
| `gpscript.exe` ke `cmd.exe` (net use) | 11 Bandung | Skrip logon IT lokal Bandung; `\\bdg-fs01\logon\mapdrive.bat`; dikonfirmasi IT Bandung |
| `winword.exe` ke `cmd.exe` | 2 Bandung | Template bermakro Corporate Communication (pola M02 dari `HUNT-2027-007`); kini terlihat di Bandung juga |
| `excel.exe` ke `cmd.exe` (copy ke share) | `MDN-WS-0009` | Makro rekonsiliasi Keuangan POP; pola sama dengan `nur.aini` di Day 01 |
| `salesapp.exe` ke `powershell.exe` | 4 sales Bandung dan Surabaya | Aplikasi CRM sales regional; `-File C:\ProgramData\SalesApp\sync.ps1`; software katalog IT |
| sisanya (5) | berbagai | Updater per-user resmi, installer, tool IT lokal; ternormalisasi belum sempurna untuk aplikasi regional |

**Cara membaca hasil:** tidak ada pasangan yang mencurigakan setelah ditinjau; yang baru adalah kebiasaan regional yang memang tidak pernah ada di baseline Jakarta, persis yang diperingatkan Bagian D. Pasangan `winword.exe` ke `cmd.exe` adalah pola yang sudah memicu usulan "JAB - Office atau WMI memunculkan shell" (risk, `-001`); kini terlihat di Bandung, menguatkan usulan itu dan menambah entitas yang akan muncul bila risk itu aktif. Baseline regional disimpan supaya hunt bulan depan tidak mengulang peninjauan ini.

**Langkah 3, positive control.** VM lab `jab-lab-win11` dengan hanya 4688 aktif (Sysmon dimatikan untuk uji ini), Selasa 2027-03-30 11:00. Test Atomic T1204.002 nomor 3 (`0330a5d2-a45a-4272-a9ee-e364411c4b18`, makro Word memunculkan `cmd.exe`, Day 13) dijalankan; query langkah 2 menandai `winword.exe` ke `cmd.exe`. Query terbukti menangkap pola target walau sumbernya 4688, bukan Sysmon. Celah yang tetap: tanpa `OriginalFileName` di 4688, rename binary tidak tertangkap, dan itu ditulis di cakupan.

**Hasil `HUNT-2027-027`:** tidak ditemukan di 63 workstation regional yang mengirim 4688 selama 23 sampai 30 Maret; baseline regional dibuat; 18 workstation yang ditautkan GPO belum mengirim; populasi ini tidak mencakup field hash, OriginalFileName, dan jaringan.

### Bagian F: tiga laporan final dan usulan deteksi

Pertanyaan pertama Dimas ("jangan setengah jalan") ditutup di sini: setiap hunt punya laporan final dengan Kategori hasil dan blok Metrik (Day 15 bagian 2.1), dan usulan deteksi yang lahir darinya. Ketiganya dikirim ke Sari bersama satu paket Selasa 2027-03-30 sore.

```
ID            : HUNT-2027-026                          Selesai: Selasa 2027-03-30 (expiry 09:40)
Hasil         : Tidak ditemukan (tidak terbukti)
Kategori hasil: tidak-ditemukan
Ringkasan     : Tidak ada DLL bernama DLL sistem di folder yang bisa ditulis pengguna yang dimuat
                tanpa alasan sah, di 428 host Windows yang menjawab. Query terbukti menandai pola
                INC-2027-040 pada koleksi lama dan satu test Atomic di VM lab.
Cakupan nyata : 428 dari 443 host Windows menjawab sampai expiry; 13 nama DLL; 3 lokasi user-writable
Di luar cakupan: 15 host tidak menjawab (termasuk SBY-WS-0107); DLL dengan nama di luar daftar;
                DLL yang sudah dihapus; side-loading dari Program Files; image load tidak dikumpulkan
Kelengkapan   : Sysmon EID 7 (image load) tidak ada di host mana pun; modul hanya dari proses berjalan
Ambang/asumsi : hosts <= 2 ditinjau; normalisasi user/temp/versi sama dengan macro Jakarta
Temuan        : 12 pasangan langka, semua jinak terkonfirmasi (5 tool IT, 2 sisa installer, 1 viewer
                vendor, 1 launcher pribadi, 3 regional); 0 cocok hash IOC lama
Eskalasi      : tidak ada
Celah data    : image load tidak dikumpulkan (G17, baru); 229 ws tanpa Sysmon (G01); POP terbatas (G18, baru)
Deteksi       : "JAB - DLL bernama DLL sistem dimuat dari folder user-writable" -> Sari (hunting/laporan)
Rekomendasi   : software di luar katalog (launcher pribadi) -> IT
Artefak       : queries/filefinder.vql, dlls.vql, notebook-stack.vql; koleksi positive control
Hipotesis baru: side-loading dari Program Files aplikasi pihak ketiga (T1574.001) -> backlog
Pelajaran     : daftar nama DLL harus mencakup amsi.dll; uji lab menemukannya sebelum hasil ditulis

Metrik (diisi 2027-03-30)
Teknik diburu : T1574.001 (plus cek T1547.001, T1053.005)
Uji positif   : ya (koleksi HUNT-2027-013 SBY-WS-0107; VM lab jab-lab-win11 Atomic T1574.001 test 1)
Detection     : 1 diusulkan (laporan hunter mingguan, bukan alert); 0 aktif per 30 Mar
Det. diperbarui: 0
Celah         : baru G17 (image load), G18 (POP Velociraptor terbatas); berulang G01
Miskonfigurasi: baru - (launcher pribadi sebagai tiket software, bukan Mnn)
Eskalasi      : tidak ada
Baseline      : koleksi autoruns terarah 2 host; tidak ada baseline baru tersimpan
Waktu         : Selasa 2027-03-23 08:40 (abstract) sampai Selasa 2027-03-30 (peninjauan)
```

```
ID            : HUNT-2027-028                          Selesai: Kamis 2027-03-25 16:40
Hasil         : Tidak ditemukan (tidak terbukti)
Kategori hasil: tidak-ditemukan
Ringkasan     : Tidak ada server Linux yang menghubungi internet di luar fungsinya. 11 eksekusi tool
                jaringan di 2 server ber-auditd dan 5 tujuan internet baru di firewall, semua jinak.
Cakupan nyata : argumen perintah: jkt-bastion01 dan jkt-billing02 (2 server ber-auditd), 18-25 Mar;
                koneksi: 37 server Linux di firewall, baseline 28 hari, jendela 28 hari
Di luar cakupan: koneksi dari proses tanpa execve baru (35 server); isi sesi; server tak terdaftar CMDB;
                jkt-portal02 dan jkt-radius01 tanpa auditd; jkt-netops01 tanpa agent Wazuh
Kelengkapan   : auditd execve hanya 2 dari 4 server ber-Wazuh; firewall event tertua 2026-12-23
Ambang/asumsi : tujuan non-privat; first-seen terhadap baseline 28 hari
Temuan        : 11 eksekusi tool (cron billing, mirror OS, backup vault, SSH CPE pelanggan) jinak;
                5 tujuan firewall baru (CDN portal, lisensi app, relay SMTP, uji konektivitas, telemetri) jinak
Eskalasi      : tidak ada
Celah data    : G08 (auditd belum di portal02, radius01); jkt-netops01 tanpa agent Wazuh (G19, baru)
Deteksi       : "JAB - Tool jaringan menghubungi tujuan eksternal di server" (Wazuh) -> Sari dan Agung;
                laporan mingguan first-seen tujuan firewall server -> laporan hunter
Rekomendasi   : auditd jab_exec di portal02 dan radius01 (G08) -> Lutfi; agent Wazuh jkt-netops01 -> Agung
Artefak       : queries/wazuh-nettools.json, firewall-firstseen.spl; jab_hunt_linux_srv.csv
Hipotesis baru: koneksi keluar dari proses layanan (tanpa execve) di 35 server -> butuh EDR/Sysmon Linux
Pelajaran     : tanpa auditd di semua server, argumen hanya terlihat di 2 server; firewall menutup
                koneksi tetapi bukan argumen

Metrik (diisi 2027-03-25)
Teknik diburu : T1071.001, T1105
Uji positif   : ya (lab Linux pribadi: curl ke web server lab, cocok filter; firewall lab first-seen)
Detection     : 1 Wazuh diusulkan; 0 aktif per 25 Mar (menunggu review Sari dan jendela change)
Det. diperbarui: 0
Celah         : baru G19 (netops01 tanpa agent); berulang G08
Miskonfigurasi: baru -
Eskalasi      : tidak ada
Baseline      : jab_hunt_linux_srv.csv (daftar IP server Linux)
Waktu         : Kamis 2027-03-25 09:00-16:40
```

```
ID            : HUNT-2027-027                          Selesai: Selasa 2027-03-30 16:20
Hasil         : Tidak ditemukan (tidak terbukti)
Kategori hasil: tidak-ditemukan
Ringkasan     : Tidak ada rantai proses mencurigakan di 63 workstation regional yang baru mengirim
                4688. 9 pasangan baru terhadap baseline Jakarta, semua kebiasaan regional yang sah.
Cakupan nyata : 63 workstation regional yang mengirim 4688 (dari 81 ditautkan GPO), 23-30 Mar
Di luar cakupan: 18 ws ditautkan GPO tetapi belum mengirim; 148 ws Jakarta non-OU; hash,
                OriginalFileName, koneksi, DNS (tidak ada di 4688)
Kelengkapan   : 4688 field lebih sedikit dari Sysmon EID 1; baseline regional baru, belum matang
Ambang/asumsi : filter perilaku (user-writable atau Office/script host ke shell); baseline Jakarta + regional
Temuan        : 9 pasangan baru, semua jinak (skrip logon IT Bandung, template makro, makro Keuangan,
                CRM sales regional, updater); winword->cmd kini terlihat di Bandung (menguatkan risk -001)
Eskalasi      : tidak ada
Celah data    : populasi baru tanpa hash/OriginalFileName/jaringan (G20, baru); 18 ws belum mengirim
Deteksi       : tidak ada usulan baru; catatan ke Sari: perluas pengecualian "-015" untuk aplikasi
                regional; backtest "-023/-025" setelah Sysmon regional
Rekomendasi   : GPO ke 148 ws Jakarta non-OU; dorong reboot 18 ws -> Agung
Artefak       : queries/baseline-regional.spl, hunt-longtail.spl; jab_hunt_baseline_parentchild_regional.csv
Hipotesis baru: 4698/4702 regional (task baru) kini mungkin; HUNT-2027-008 bisa dijalankan di regional
Pelajaran     : baseline lama tidak berlaku untuk populasi baru; bangun baseline terpisah dulu

Metrik (diisi 2027-03-30)
Teknik diburu : T1204.002, T1059.001, T1059.003, T1059.005 (plus cek T1053.005)
Uji positif   : ya (VM lab jab-lab-win11 hanya 4688, Atomic T1204.002 test 3, cocok)
Detection     : 0 diusulkan baru; catatan dampak ke 12 detection (Bagian D) ke Sari
Det. diperbarui: 0 (pengecualian "-015" diusulkan, belum diterapkan)
Celah         : baru G20 (populasi 4688 tanpa field Sysmon); berulang G03 (sebagian ditutup)
Miskonfigurasi: baru - (M02 template makro kini terlihat di Bandung, berulang)
Eskalasi      : tidak ada
Baseline      : jab_hunt_baseline_parentchild_regional.csv (1.206 pasangan dari 63 host)
Waktu         : Selasa 2027-03-30 08:30-16:20
```

Tiga usulan deteksi, dalam format abstract deteksi Day 14 bagian 2.2 (diringkas):

| Usulan | Asal | Jenis | Logika kasar | Volume dari hunt | Catatan |
|---|---|---|---|---|---|
| JAB - DLL bernama DLL sistem dimuat dari folder user-writable | `-026` | Laporan hunter Velociraptor mingguan (bukan alert ES) | `Windows.System.DLLs` + `FileFinder`: DLL dengan nama pustaka sistem di `\Users\`, `\ProgramData\`, `\Users\Public\`, modul tidak bertanda tangan Microsoft atau tanda tangan beda dari executable | 12 pasangan langka, 0 jahat | FP tinggi (HijackLibs menandai version.dll rawan FP [S15]); cocok sebagai hunt terjadwal, bukan alert |
| JAB - Tool jaringan menghubungi tujuan eksternal di server | `-028` | Rule Wazuh lokal (100203) | execve `curl/wget/scp/sftp/rsync/nc/socat/whois` dengan argumen tujuan non-privat, key `jab_exec`, kecuali daftar tujuan sah | 11/minggu, semua jinak | Perlu allowlist tujuan sah dulu (repo OS, payment gateway, vault); tanpa itu membanjiri |
| TH - first-seen tujuan internet server Linux (firewall) | `-028` | Laporan hunter mingguan | first-seen (server, dest, port, app) terhadap baseline 28 hari, server Linux saja | 5/bulan, semua jinak | Laporan ke hunter, bukan alert; menutup 35 server tanpa auditd |

Ketiganya diproses Sari seperti usulan lain (triase Day 14): yang pertama dan ketiga menjadi laporan hunter terjadwal (role `jab_hunter`), yang kedua menunggu allowlist tujuan sah sebelum dipasang sebagai rule Wazuh. Tidak ada yang menjadi alert ES langsung, karena ketiganya ber-FP tinggi tanpa penyempurnaan; keputusan ini jujur dan masuk metrik sebagai "diusulkan", bukan "aktif".

### Bagian G: metrik program sampai 31 Maret

Pertanyaan keenam Dimas butuh angka yang dihitung ulang dari register dan laporan, bukan dari ingatan (Day 15 bagian 1.1). Lembar Day 15 (per 18 Maret) ditambah tiga hunt capstone dan status celah yang masuk sampai 25 Maret, lalu dihitung ulang per Rabu 2027-03-31 12:00. Tabel berikut hanya menampilkan baris yang berubah; baca kolom "Arah", karena beberapa angka sengaja turun dan itu jujur.

| Metrik | 18 Mar | 31 Mar | Arah dan alasan |
|---|---|---|---|
| Nomor hunt dibagikan | 25 | 28 | +3 (`-026`, `-027`, `-028`); = 25 selesai + 2 di nomor lain + 1 kandidat (`-008`) |
| Hunt selesai | 22 | 25 | endpoint Windows 17, jaringan dan DNS 4, Linux 3, identitas 1, cloud 0 |
| Hari hunting dialokasikan | 14 | 17 | +3 (Sel 23, Kam 25, Sel 30 Mar); 31 Mar presentasi, bukan hunting |
| Hari menjalankan hunt | 11 | 14 | +3 |
| Kategori hasil | 1 / 1 / 20 | 1 / 1 / 23 | ditemukan 1, ditemukan-bukan-insiden 1, tidak-ditemukan 23 |
| Tidak-ditemukan dengan uji positif | 2 dari 20 (10%) | 5 dari 23 (21,7%) | naik; ketiga hunt capstone punya positive control (target Q2 dimajukan) |
| Detection aktif lahir dari hunt | 12 | 12 | tetap; 3 usulan capstone ber-FP tinggi, jadi laporan hunter atau menunggu allowlist, bukan alert |
| Detection diusulkan belum aktif | 3 tunda | 4 | +1 (Wazuh tool jaringan, menunggu allowlist); dua usulan capstone lain masuk laporan hunter, bukan baris ini |
| Hunt yang melahirkan detection aktif | 9 dari 22 | 9 dari 25 | tetap 9; rasio turun karena penyebut naik |
| Laporan hunter terjadwal | 4 + VR mingguan | 6 + VR mingguan | +2 (DLL side-load mingguan, first-seen tujuan server Linux) |
| Teknik ATT&CK diburu (unik, v20) | 32 | 34 | +2 baru diburu: T1574.001, T1059.003 |
| Teknik dengan detection dari hunt | 15 | 15 | tetap; usulan capstone belum aktif |
| ID ber-detection di layer | 94 menjadi 100 | 100 | tetap; tidak ada detection aktif baru |
| Celah data dilaporkan | 16 | 20 | +4 (G17 image load, G18 POP Velo terbatas, G19 netops01 tanpa agent, G20 4688 tanpa field Sysmon) |
| Celah ditutup | 3 | 3 penuh + G03 sebagian | GPO 22 Mar menutup sebagian G03 (regional terlihat di 4688; Sysmon belum) |
| Celah dengan status diketahui | 11 dari 16 | 17 dari 20 | status pemilik masuk 25 Mar; 3 masih tanpa status, 1 tanpa pemilik (G15) |
| Miskonfigurasi diperbaiki | 2 dari 17 | 4 dari 17 | +2 setelah respons pemilik (M01 CMSTP diganti, M13 hdk-shell dihapus); M02 kini berulang di Bandung |
| Software di luar katalog | 5 tiket | 6 tiket | +1 (launcher pribadi dari `-026`) |
| Host tercakup | 9 Sysmon, 5 VR, 1 MDE | + Velociraptor 428 host (`-026`), 63 ws regional via 4688 (`-027`), 37 server Linux (`-028`) | cakupan melebar ke regional, Linux, dan keadaan disk |
| Hari laporan ke aktif | median 8 (n=12) | median 8 (n=12) | tetap; usulan capstone belum aktif, jadi tidak masuk hitungan ini |

Perhitungan yang paling mungkin ditanya ulang Hendra, dihitung dari baris di atas:

| Metrik | Rumus | 31 Mar | Cara membaca |
|---|---|---|---|
| Rasio hunt ke detection | hunt ber-detection aktif / hunt selesai | 9 / 25 = 36,0% | Turun dari 40,9%; tiga hunt terakhir menambah penyebut tanpa detection aktif, dan itu jujur: ketiganya ber-FP tinggi atau negatif bersih |
| Porsi tidak-ditemukan | tidak-ditemukan / selesai | 23 / 25 = 92,0% | Konteks; dibaca bersama baris berikut |
| Tidak-ditemukan dengan uji positif | negatif teruji / negatif | 5 / 23 = 21,7% | Dua kali lipat dari 18 Mar; kekuatan hasil negatif naik, target utama Q2 |
| Teknik diburu ber-detection dari hunt | teknik ber-detection / teknik diburu | 15 / 34 = 44,1% | Turun dari 46,9%; dua teknik baru diburu (T1574.001, T1059.003) belum ber-detection aktif |
| Penutupan celah | ditutup / dilaporkan | 3 / 20 = 15,0% | Turun karena 4 celah baru dilaporkan; yang bisa diperbaiki program adalah status, bukan penutupan |
| Celah berstatus | berstatus / dilaporkan | 17 / 20 = 85,0% | Naik dari 68,8%; respons pemilik 25 Mar menutup celah informasi |

Dua angka yang sengaja turun (rasio hunt ke detection, teknik ber-detection) adalah inti jawaban untuk pertanyaan kelima Dimas. Program yang mengejar angka akan berhenti menjalankan hunt yang tidak menghasilkan detection; program yang jujur menjalankan hunt yang benar sesuai pelajaran, lalu menjelaskan kenapa tiga hunt terakhir meninggalkan baseline, celah, dan usulan ber-FP tinggi alih-alih alert. Yang naik justru yang paling penting untuk kematangan: hasil negatif yang teruji dan celah yang kini punya status.

Penilaian HMM per 31 Maret: perilaku HMM2 terpenuhi dengan bukti (kalender Selasa dan Kamis sepanjang kuartal, 25 laporan, prosedur publik dijalankan terjadwal), bukti awal HMM3 menguat (tiga hunt capstone adalah prosedur yang dirancang sendiri dengan positive control, bukan menjalankan playbook orang lain), HMM4 belum (12 detection aktif dari 25 hunt, laporan hunter masih ditinjau manusia).

**Kapan gagal:** menyembunyikan rasio yang turun dengan hanya menampilkan "25 hunt selesai"; atau mengklaim 4 celah baru sebagai prestasi ("kami menemukan lebih banyak celah") padahal celah baru berarti ada lebih banyak yang belum tertutup.

### Bagian H: satu halaman evaluasi Q1 dan rekomendasi Q2

Pertanyaan keenam Dimas butuh bentuk, bukan hanya angka. Satu halaman ini dibawa ke evaluasi Rabu 2027-03-31, ditulis untuk Hendra dan bisa diteruskan ke direksi, dengan urutan Day 15 bagian 1.8: keluaran permanen dulu, angka aktivitas paling bawah. Rencana Q2 hanya disebut sebagai arah; kalender, model tim, dan targetnya disusun terpisah (Day 19).

```
PROGRAM HUNT PT JAB: EVALUASI AKHIR KUARTAL 1 (1 Februari - 31 Maret 2027)
Untuk: Direktur Teknologi. Disusun SOC PT JAB. Setiap angka dapat ditelusuri ke
jab-hunt/docs/hunt-metrics-2027-Q1.md (dihitung 31 Maret 12:00). Status celah per 31 Maret.

YANG DITINGGALKAN PROGRAM SECARA PERMANEN
- 12 detection baru aktif, lahir dari 9 hunt, menutup 11 cara serangan yang sebelumnya lolos.
  10 aktif sejak 17 Maret, 2 sejak 25 Februari; belum ada yang memicu insiden (wajar, baru aktif).
- 1 kompromi nyata ditemukan dan ditangani IR: laptop sales Surabaya dengan program tersembunyi
  sekitar 82 hari, yang lolos daftar indikator insiden Desember 2026 (INC-2027-040; dampak di laporan IR).
- 1 pelanggaran kebijakan akses admin dihentikan (0 kejadian sejak 5 Maret).
- Kemampuan baru: keadaan 428 dari 443 komputer Windows kini bisa diperiksa langsung lewat koleksi
  endpoint; server Linux dan workstation regional kini masuk cakupan hunting.
- 9 baseline, 2 aturan normalisasi, dan daftar aset yang dipakai ulang setiap hunt berikutnya.

APA ARTI "TIDAK DITEMUKAN" (23 DARI 25 HUNT)
- Untuk area, data, dan rentang di setiap laporan, tidak ada aktivitas berbahaya. Delapan hunt negatif
  tetap melahirkan detection, dan tiga hunt terakhir meninggalkan baseline baru dan 4 celah telemetri.
- Batasnya, dinyatakan jujur: kesimpulan di komputer pengguna sebagian besar hanya berlaku untuk
  workstation yang punya telemetri lengkap, dan baru 5 dari 23 hasil negatif yang dibuktikan dengan
  uji positif. Angka itu naik dua kali lipat sejak pertengahan Maret dan menjadi fokus kuartal depan.

RISIKO TERBUKA DAN KEPUTUSAN YANG DIBUTUHKAN
- 229 workstation (sekitar 60%) tanpa Sysmon. GPO audit kini menjangkau Bandung dan POP, sehingga
  prosesnya terlihat untuk hunting, tetapi lima detection berbasis Sysmon belum melindungi mereka.
  Usulan tetap: rollout Sysmon dua tahap. Butuh keputusan anggaran.
- 20 celah telemetri dilaporkan ke pemilik, 3 ditutup dan 1 ditutup sebagian; 17 dari 20 kini berstatus.
  17 temuan konfigurasi, 4 diperbaiki.
- Laptop yang bekerja dari luar kantor (split tunnel) tetap tidak terlihat di proxy dan DNS, dan belum
  ada pemilik untuk celah ini.
- Belum ada hunt di data cloud (AWS, Azure) dan baru satu hunt identitas; dua insiden termahal 2026
  justru di wilayah itu.

ARAH KUARTAL 2 (rencana rinci menyusul)
- Prioritas: hunt identitas dan cloud, menutup celah area yang paling mahal di 2026.
- Kualitas: uji positif untuk setiap hunt yang hasilnya negatif (dari 5 dari 23 menuju seluruhnya).
- Perluasan: memanfaatkan telemetri regional yang baru untuk baseline dan detection yang mencakup
  lebih dari sekitar 40% workstation.
- Ukuran di evaluasi Juli: detection aktif dari hunt dan insiden yang dipicunya, celah yang ditutup,
  hasil negatif yang teruji, dan kematangan dari HMM2 ke awal HMM3.

KONTEKS: 25 hunt selesai dalam 14 hari hunting (Selasa dan Kamis), satu analyst L2.
```

Cara membaca halaman ini:

- **Keluaran permanen dulu, termasuk yang dari hunt negatif.** Baseline, kemampuan koleksi, dan cakupan baru disebut sebagai hasil, bukan hanya detection. Inilah jawaban untuk "kalau ketiganya tidak menemukan apa-apa, apa yang aku bawa".
- **"Tidak ditemukan" ditulis dengan batasnya di halaman yang sama.** Kalimat "5 dari 23" dan "60% tanpa Sysmon" membuat angka lain dipercaya dan langsung mengarah ke keputusan anggaran.
- **Rekomendasi Q2 adalah arah, bukan rencana.** Empat baris prioritas tanpa kalender, tanpa target angka, tanpa model tim, karena itu bahan evaluasi tersendiri di akhir percobaan (Day 19). Menyodorkan rencana penuh sekarang akan mendahului keputusan Hendra apakah percobaan dilanjutkan.
- **Jumlah hunt di baris terakhir, berlabel konteks.** Hendra mungkin bertanya; jawabannya tersedia tanpa menjadi judul.

Ringkasan jawaban yang dikirim ke Dimas Selasa 2027-03-30 sore, sebelum presentasi:

| Pertanyaan Dimas | Jawaban singkat | Dasar |
|---|---|---|
| Tiga hunt mana dan kenapa | `-026` (side-load, tindak lanjut INC-2027-040), `-028` (Linux keluar), `-027` (populasi regional baru); tiga platform, tiga pelajaran | Bagian 1.2, A |
| Pola INC-2027-040 di host lain | Tidak ditemukan di 428 host; 12 pasangan langka semua jinak; SBY-WS-0107 tidak tersambung minggu itu (ditulis) | Bagian B, E |
| Arti perubahan GPO | Regional kini terlihat untuk hunting dan 1 detection; 5 detection Sysmon tetap buta; baseline regional dibangun terpisah | Bagian D |
| Server Linux keluar di luar fungsi | Tidak ditemukan; 11 eksekusi tool dan 5 tujuan baru semua jinak; G08 dan netops01 ditegaskan | Bagian C |
| Kalau ketiganya negatif | Baseline regional, 4 celah baru berpemilik, 3 usulan, cakupan melebar, 5 dari 23 kini teruji | Bagian F, G |
| Angka dan satu halaman | 25 hunt, 23 negatif, rasio detection 36% (turun, jujur), uji positif 21,7% (naik), 20 celah | Bagian G, H |
| Portofolio tanpa data kita | Replikasi di lab pribadi, nomor HUNT-CAP, sanitasi penuh termasuk nama PT JAB | Bagian I-L |

**Kapan gagal:** satu halaman dibuka dengan "25 hunt, miliaran event dipindai"; Hendra membaca aktivitas, bukan hasil. Atau rasio detection yang turun disembunyikan, lalu Nina menelusurinya dan menemukan penyebut berubah tanpa catatan.

### Bagian I: mereplikasi tiga hunt di lab pribadi (HUNT-CAP-001 sampai -003)

Mulai bagian ini, semua dikerjakan di VM lab terisolasi milikmu, bukan di PT JAB. Jalur portofolio mereplikasi hipotesis dan metode yang sama dengan data yang boleh kamu publikasikan. Lab minimal: Splunk, Velociraptor, Wazuh, satu VM Windows dengan Sysmon dan GPO audit 4688, satu VM Linux dengan auditd, dan Atomic Red Team. Semua VM punya snapshot, dan tidak ada koneksi ke jaringan kerja.

Sebelum hunt, kamu menjadi purple team untuk dirimu sendiri: jalankan beberapa test Atomic yang jinak pada hari tertentu dan catat GUID serta waktunya di file terpisah yang tidak kamu buka sampai hunt selesai. Catatan itu menjadi kunci jawaban (positive control terencana). Baca isi test di katalog sebelum menjalankannya.

| Hunt lab | Replikasi dari | Platform | Test Atomic (positive control) | Catatan test |
|---|---|---|---|---|
| `HUNT-CAP-001` | `-026` DLL side-load | Velociraptor | T1574.001 test 4 (`65526037-7079-44a9-bda1-2cb624838040`): side-load lewat GUP.exe Notepad++ yang membuka calculator; atau test 7 (`e96b8105-d7f7-484e-8d81-2d0c7086971b`): ntprint.exe bertanda tangan memuat ntprint.dll kustom | Test 4 membuka `calc.exe` sebagai payload jinak; cleanup menutup calculator [S10]. DLL diunduh dari GitHub saat prasyarat, jadi lab butuh akses terbatas ke GitHub atau file disiapkan lebih dulu |
| `HUNT-CAP-002` | `-028` tool jaringan Linux | Wazuh (archives) + lab firewall atau Sysmon Linux | T1105 Linux test 27 (`bdc373c5-e9cf-4563-8a7b-a9ba720a90f3`): `curl -sO` mengunduh skrip lalu mencoba menjalankannya; atau test 1 rsync push (`0fc6e977-cb12-44f6-b263-2824ba917409`) | Arahkan URL ke web server lab, bukan GitHub, dan host file teks jinak sendiri. Test 27 mengunduh `atomic.sh` dari repo Atomic secara default; ganti `remote_url` ke lab [S10] |
| `HUNT-CAP-003` | `-027` baseline populasi dan Office memunculkan shell | Splunk (4688) | T1204.002 test 3 (`0330a5d2-a45a-4272-a9ee-e364411c4b18`): makro Word memunculkan `cmd.exe choice`; T1059.003 batch sederhana | Matikan Sysmon di VM untuk uji ini supaya hanya 4688 yang terlihat, menirukan populasi regional PT JAB |

Setiap hunt dijalankan dengan siklus penuh: abstract ABLE, kartu kesiapan, query (dari Bagian B, C, E dengan nama host lab), peninjauan dan label, lalu laporan dengan Kategori hasil dan blok Metrik. Setelah ketiganya selesai, buka catatan kunci dan isi tabel pencocokan:

| Aktivitas uji | Hunt | Tertangkap? | Kenapa |
|---|---|---|---|
| T1574.001 test 4 (GUP.exe side-load calc) | `HUNT-CAP-001` | Ya | `winhttp.dll` atau `libcurl.dll` di folder GUP.exe terbaca FileFinder dan modul |
| T1574.001 test 7 (ntprint side-load) | `HUNT-CAP-001` | Ya atau Tidak | Bila `ntprint.dll` tidak ada di daftar nama DLL, lolos; tambahkan dan jalankan ulang (pelajaran amsi dari Bagian B) |
| T1105 Linux test 27 (curl download) | `HUNT-CAP-002` | Ya | `curl` dengan argumen URL eksternal tertangkap filter tool jaringan |
| T1204.002 test 3 (Word ke cmd) | `HUNT-CAP-003` | Ya | `winword.exe` ke `cmd.exe` lolos filter Office ke shell |

Baris kedua adalah pelajaran berharga yang sama dengan Bagian B: bila test lolos, perbaiki daftar atau query dulu, lalu jalankan ulang, baru tulis hasil. Hunt yang gagal menangkap positive control-nya bukan hunt "tidak ditemukan"; ia hunt yang buta, dan menuliskannya sebagai negatif adalah kesalahan.

**Hasil yang mungkin:** ketiga hunt lab boleh berakhir "tidak ditemukan" untuk aktivitas berbahaya di luar test terencana, dan itu hasil yang sah. Yang membuktikan kemampuanmu bukan temuan, melainkan siklus lengkap dengan positive control yang terdokumentasi.

### Bagian J: aturan sanitasi dan templat write-up publik

Pertanyaan ketujuh Dimas punya syarat yang tidak bisa ditawar: tidak ada data kerja di artefak publik. Aturan sanitasi:

- **Tidak ada data PT JAB apa pun**, termasuk nama organisasi fiktif PT JAB, nomor insiden (`INC-*`), nomor alert (`SOC-*`), nama host (`JKT-WS-*`, `SBY-WS-*`), nama orang, IP, nama detection (`JAB - ...`), dan angka hasil kerja. Pembaca tidak bisa membedakan fiktif dari nyata, dan nama itu mengikatmu ke catatan kerja.
- **Hanya data lab pribadi atau dataset publik.** Nama host lab buatan sendiri, IP privat lab atau rentang dokumentasi (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), domain `*.example`.
- **GUID test aman dicatat**, screenshot disamarkan (buramkan nama mesin dan path pengguna), dan tidak ada hash atau indikator dari pekerjaan.
- **Metode boleh dibagikan, konteks kerja tidak.** Query, logika stacking, dan pelajaran umum (seperti "daftar nama DLL harus mencakup amsi") adalah pengetahuan publik; angka "428 dari 443 host" adalah data kerja.

Templat write-up publik, `writeups/hunting-dll-sideloading-home-lab.md` (contoh untuk `HUNT-CAP-001`, dalam bahasa Inggris karena ditujukan ke pembaca umum):

```markdown
# Hunt write-up: DLL side-loading in a home lab

## Summary
I hypothesized that a legitimate, signed executable in a user-writable folder could
load a planted DLL named after a system library (version.dll, winhttp.dll, ...),
and hunted for it across my lab hosts using Velociraptor disk and module artifacts.

## Hypothesis (ABLE)
Behavior: DLL side-loading, T1574.001. Location: Windows lab hosts. Evidence:
DLL files on disk (path, size, SHA1) and modules loaded by running processes.

## Data and scope
All lab Windows hosts, Velociraptor Windows.Search.FileFinder and Windows.System.DLLs.
Image-load events (Sysmon EID 7) were not collected, so modules were only visible
for processes running at collection time. Hosts that were offline at expiry were out of scope.

## Technique
Glob user-writable folders for a list of system DLL names, stack by normalized
(folder, DLL name) across hosts, then pivot to the loading process and its signature.

## Positive control
Atomic Red Team T1574.001 test 4 (GUP.exe side-load, opens calculator). The first run
missed it because the loaded DLL name was not on my list; I added it and re-ran, and
both artifacts flagged it. A hunt that cannot catch its own positive control is blind,
not negative.

## Result
No malicious side-loading found across the hosts that responded. All rare (folder, DLL)
pairs were benign, confirmed by signer and known installation. A negative result with a
stated scope and a working positive control is a valid finding.

## Detection idea
A weekly Velociraptor hunt for system-named DLLs in user-writable folders whose module
signature differs from the executable's. False positives are likely (see HijackLibs),
so this fits a scheduled hunt, not an automated alert.

## Lessons
Keep the DLL name list driven by HijackLibs and expand it when a positive control slips through.

## Note
All data is from a personal, isolated lab. Hosts, users, and IPs are fictional and
unrelated to any organization.
```

Write-up menekankan metode, hasil jujur (termasuk negatif), positive control, dan deteksi yang lahir, semuanya dari lab. Catatan penutup menegaskan sanitasi.

### Bagian K: struktur repo portofolio dan layer ATT&CK Navigator

Repo portofolio disusun supaya tiap klaim bisa ditelusuri, sama seperti `jab-hunt` di tempat kerja, tetapi dengan data lab saja.

```
threat-hunting-portfolio/
  README.md                    tujuan, daftar hunt, ringkasan metrik lab
  hunts/
    BACKLOG.md
    HUNT-CAP-001/
      abstract.md
      report.md                Kategori hasil + blok Metrik
      queries/                 .vql, .spl, query Wazuh berkomentar
      lab-tests.md             GUID test, waktu, hasil query (positive control)
    HUNT-CAP-002/ ...
    HUNT-CAP-003/ ...
  detections/                  rule Sigma + fixture uji positif dan negatif + hasil
  baseline/                    baseline lab tersimpan (parent-child, autoruns)
  writeups/                    write-up publik per hunt (bahasa Inggris)
  coverage/
    layer-before.json          layer Navigator sebelum capstone lab
    layer-after.json           layer sesudah
    layer-hunted.json          teknik yang diburu
  docs/
    data-inventory.md          sumber lab dan cakupannya
    hunt-metrics-cap.md        metrik lab (outcome, bukan aktivitas)
```

Layer Navigator memakai format layer 4.5 (wajib `name`, `domain`, dan bila `versions` ditulis maka `navigator` minimal 4.9.0 dan `layer` harus `4.5`); `attack` opsional dan bila ditulis dipakai supaya layer bisa dibandingkan lintas versi ATT&CK. Potongan `layer-after.json`:

```json
{
  "name": "Home lab hunt coverage - after capstone",
  "versions": { "attack": "20", "navigator": "5.3.2", "layer": "4.5" },
  "domain": "enterprise-attack",
  "description": "Score = jumlah detection/hunt terjadwal per teknik di lab. Data lab saja.",
  "gradient": { "colors": ["#ffffff", "#9ecae1", "#08519c"], "minValue": 0, "maxValue": 3 },
  "techniques": [
    { "techniqueID": "T1574.001", "score": 1,
      "comment": "origin=hunt HUNT-CAP-001; hunt terjadwal DLL side-load; uji positif Atomic test 4; FP tinggi" },
    { "techniqueID": "T1105", "score": 1,
      "comment": "origin=hunt HUNT-CAP-002; tool jaringan ke tujuan eksternal; uji positif Atomic Linux test 27" },
    { "techniqueID": "T1204.002", "score": 1,
      "comment": "origin=hunt HUNT-CAP-003; Office memunculkan shell; uji positif Atomic test 3" }
  ]
}
```

Komentar menulis `origin_hunt`, prosedur, dan uji, bukan sekadar "covered", karena satu detection untuk satu prosedur bukan cakupan penuh teknik. Layer selisih dibuat di Navigator lewat "Create Layer from other layers" dengan dua layer diberi variabel `a` dan `b`, lalu score expression `b - a` (jumlah yang bertambah) dan `b > 0 and a < 1` (teknik yang sebelumnya tanpa apa pun); pewarisan komentar hanya berlaku bila kedua layer satu domain dan satu versi. Ekspor SVG untuk write-up, JSON untuk repo.

### Bagian L: rubrik penilaian diri

Nilai tiap kriteria 0 sampai 2 untuk satu hunt portofolio. Total maksimal 24; 20 ke atas berarti siap ditunjukkan. Rubrik ini menilai artefak hunt, bukan apakah kamu menemukan penyerang.

| Kriteria | 0 | 1 | 2 |
|---|---|---|---|
| Hipotesis | Topik, bukan hipotesis | Bisa diuji, ABLE tidak lengkap | ABLE lengkap, bisa dibantah |
| Kesiapan data | Tidak dicek | Dicek tanpa angka | Kartu kesiapan dengan host yang mengirim, field, retensi |
| Query | Tidak tersimpan | Tersimpan tanpa komentar | Berkomentar, menyebut asumsi sumber, field, dan versi |
| Peninjauan | Hasil tidak dilabeli | Sebagian dilabeli | Semua item dilabeli dengan bukti di luar query |
| Cakupan nyata | Tidak ditulis | Sama dengan rencana | Dari host yang benar-benar menjawab, menyebut yang tidak |
| Hasil negatif | Disembunyikan | Ditulis tanpa batas | Ditulis dengan cakupan dan uji positif |
| Positive control | Tidak ada | Uji tanpa pencocokan | Tabel tertangkap/lolos; query diperbaiki bila lolos |
| Deteksi | Tidak ada | Rule IOC | Perilaku, FP dinilai jujur, origin_hunt, uji +/- atau alasan hanya laporan |
| Handover dan backlog | Tidak ada | Disebut tanpa penerima | Penerima jelas, celah berpemilik, hipotesis baru |
| Write-up | Tidak ada | Memuat detail yang tidak perlu | Jujur, ringkas, metode dibagikan |
| Sanitasi | Ada jejak kerja | Ragu-ragu | Tidak ada data, nama, atau organisasi kerja sama sekali |
| Metrik | Aktivitas (jumlah query) | Campur | Outcome (detection, celah, cakupan, uji positif) |

**Variasi tantangan:** jalankan satu kampanye jinak yang merangkai tiga taktik (eksekusi, persistence, side-load) di satu host lab dalam satu hari, lalu buru tanpa membuka catatan uji. Dokumentasikan sebagai satu kampanye hunt dan tunjukkan bagaimana temuan di satu taktik memicu hunt di taktik berikutnya (menutup loop, Day 02). Tambahan: ambil satu hunt lab yang "tidak ditemukan" dan tulis satu paragraf kenapa hasil itu tetap bernilai, lengkap dengan cakupan dan uji positifnya.

**Hasil yang sebaiknya tersimpan:**

- Tiga hunt kerja (`-026`, `-027`, `-028`) dengan abstract, laporan final (Kategori hasil dan blok Metrik), dan usulan deteksi.
- Tiga hunt lab (`HUNT-CAP-001` sampai `-003`) dengan tabel pencocokan positive control dan penyebab untuk yang lolos.
- Lembar metrik program sampai 31 Maret dengan dua angka yang turun dijelaskan, dan satu halaman evaluasi Q1.
- Baseline regional dan daftar aset yang dibuat, serta register celah yang bertambah empat baris berpemilik.
- Repo portofolio dengan write-up publik tersanitasi, rule Sigma dengan fixture, dan tiga layer Navigator (sebelum, sesudah, diburu) beserta SVG.
- Skor rubrik untuk setiap hunt lab dengan catatan perbaikan untuk kriteria yang belum 2.

### Troubleshooting ringkas

Tabel ini memuat masalah yang muncul saat menjalankan capstone dan membangun portofolio. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Hunt Velociraptor "tidak ditemukan" tetapi banyak host diam | Cakupan diambil dari host terdaftar, bukan yang menjawab sampai expiry | Bekukan cakupan pada satu jam; tulis host yang tidak menjawab (Bagian B) |
| Positive control tidak tertangkap | Daftar nama/pola terlalu sempit | Perbaiki daftar (amsi.dll, ntprint.dll), jalankan ulang sebelum menulis hasil (Bagian B, I) |
| Baseline regional memunculkan ratusan "pasangan baru" | Dibandingkan dengan baseline Jakarta | Bangun baseline populasi baru terpisah dulu (Bagian D, E) |
| Detection terlihat melindungi populasi baru padahal tidak | Sumber 4688 tidak masuk pipeline Sysmon detection | Periksa pipeline konversi tiap detection; catat yang tetap buta (Bagian D) |
| `Windows.System.DLLs` kosong untuk host yang jelas kena | Proses pemuat tidak berjalan saat collection | Lengkapi dengan disk (FileFinder) dan autostart; catat image load tidak dikumpulkan (Bagian B) |
| Argumen tool Linux tidak terlihat | auditd execve tidak ada di server itu | Pakai firewall untuk koneksi; tulis G08 dan server tanpa auditd (Bagian C) |
| Rasio hunt ke detection turun di akhir kuartal | Hunt bertambah, detection aktif tidak | Jelaskan sebagai jujur; sorot uji positif dan celah yang naik (Bagian G) |
| Write-up publik memuat istilah yang mengikat ke kerja | Sanitasi tidak menyeluruh | Buang nama organisasi (termasuk fiktif), host, IP, angka hasil kerja (Bagian J) |
| Layer selisih ditolak Navigator | `versions.layer` bukan 4.5 atau versi ATT&CK berbeda | Samakan versi; format 4.5 sejak Navigator 4.9.0 (Bagian K) |
| Capstone terasa seperti tiga hunt acak | Tidak ada benang pelajaran program | Setiap hunt menindaklanjuti insiden, backlog, atau celah tertentu (Bagian 1.2, A) |

## 5. Kesalahan umum dan jebakan

- **Menilai capstone dari temuan.** Capstone yang ketiga hunt-nya negatif tetap lengkap bila ketiganya bisa dihitung ulang dan punya positive control. Yang dinilai adalah siklus, bukan tangkapan (bagian 1.5).
- **Menulis "tidak ditemukan" tanpa positive control.** Query yang tidak pernah dibuktikan menangkap contoh positif bisa buta; hasil negatifnya tidak bisa dibedakan dari "query salah" (Bagian B langkah 6).
- **Menyimpulkan cakupan dari rencana, bukan dari host yang menjawab.** Hunt Velociraptor kedaluwarsa, bukan selesai; GPO ditautkan bukan berarti event terkirim (Bagian B, D).
- **Mengira perubahan telemetri otomatis melindungi.** GPO baru membuat proses terlihat untuk hunting dan satu detection, tetapi lima detection Sysmon tetap buta di populasi baru (Bagian D).
- **Memakai baseline lama untuk populasi baru.** Kebiasaan regional akan tampak "baru" dan menenggelamkan yang penting; bangun baseline terpisah dulu (Bagian E).
- **Memaksa hunt negatif menjadi detection aktif.** Usulan ber-FP tinggi (side-load, tool jaringan) lebih jujur sebagai laporan hunter atau menunggu allowlist daripada alert yang membanjiri (Bagian F).
- **Menyembunyikan angka yang turun.** Rasio hunt ke detection turun di akhir kuartal karena hunt bertambah tanpa detection aktif; menjelaskannya lebih kuat daripada menyembunyikannya (Bagian G).
- **Menyodorkan rencana Q2 penuh di evaluasi Q1.** Rekomendasi adalah arah; kalender dan target adalah bahan evaluasi tersendiri (Bagian H, Day 19).
- **Melabeli item dengan nama dan lokasi saja.** Executable bertanda tangan dengan DLL bernama sistem di `AppData` bisa jinak atau jahat; pembedanya bukti di luar query (Bagian B langkah 7).
- **Membawa data kerja ke portofolio.** Nama organisasi (termasuk fiktif), host, IP, dan angka hasil kerja tidak boleh ada di write-up publik (Bagian J).
- **Mengukur portofolio dari jumlah hunt.** Rubrik menilai kelengkapan siklus, bukan banyaknya hunt atau temuan (Bagian L).

## 6. Catatan terkini

Bagian ini menampung versi alat dan rujukan yang dipakai di Day ini; detailnya tidak mengubah cara kerja capstone di atas.

- Capstone menyatukan seluruh siklus Day 01-15: ABLE dan kartu kesiapan, stacking dan first-seen, hunting di Splunk, Wazuh, dan Velociraptor, pola per taktik dengan positive control, usulan deteksi, serta Kategori hasil dan blok Metrik untuk angka program [S22].
- **MITRE ATT&CK v20.0** dirilis 13 Oktober 2026, menggantikan v19.2 (28 April sampai 12 Oktober 2026) [S1]. Teknik yang dipakai: T1574.001 versi 3.0 (diubah 2026-09-11, taktik Stealth dan Execution) [S9]; T1105 versi 2.6 (2026-09-11), menyebut curl, wget, scp, sftp, dan rsync di Linux [S2]; T1071.001 versi 1.5 (2026-09-11), mencantumkan Linux di platform [S4]; T1059.003 versi 1.5 (2026-05-12) [S20]; T1547.001 untuk pemeriksaan autostart [S3].
- **Velociraptor 0.77.3** (5 Oktober 2026) adalah rilis terbaru, sebuah rilis perbaikan yang menutup beberapa CVE; artifact `Windows.Search.FileFinder`, `Windows.System.DLLs`, dan `Windows.Sysinternals.Autoruns` dipakai di `HUNT-2027-026` [S17][S12][S13][S7]. Glob Velociraptor mendukung `{a,b}`, `?`, dan `**` dengan kedalaman default 3 yang bisa diubah (`**10`), tidak peka huruf besar/kecil [S14].
- **Wazuh 4.14.9** (14 Oktober 2026) adalah rilis terbaru seri 4.14; PT JAB masih di 4.14 dengan rule auditd `jab_exec` hanya di dua server [S18][S16].
- **Splunk Enterprise 10.6** dirilis 30 September 2026, dengan rilis pemeliharaan 10.6.1 pada 16 Oktober 2026 [S21]. Event 4688 versi 2 (Windows 10) membawa `NewProcessName`, `ParentProcessName`, `CommandLine` (bila setting command line aktif), `TokenElevationType`, dan `MandatoryLabel`, tanpa hash atau `OriginalFileName` [S19].
- **HijackLibs** adalah proyek komunitas yang memetakan DLL kandidat hijacking ke executable rentan, dengan aturan Sigma, CSV, dan JSON; entri `version.dll` mencatat 42 executable dan memperingatkan bahwa aturannya rawan false positive, sehingga cocok untuk hunting, bukan blokir otomatis [S15].
- **ATT&CK Navigator 5.3.2** (21 April 2026) adalah rilis terbaru; format layer 4.5 diperkenalkan di Navigator 4.9.0 (31 Oktober 2023) dan dipakai di layer coverage [S6][S11].
- **Atomic Red Team** menyediakan test per teknik dengan GUID; test T1574.001 memakai `calc.exe` atau salinan DLL sistem sebagai payload jinak, dan test T1105 Linux memakai curl, rsync, scp, sftp [S10]. Nomor urut test bisa bergeser, jadi cocokkan GUID.
- **Sigma specification 2.1.0** (2 Agustus 2025) hanya mewajibkan `title`, `logsource`, dan `detection` dengan `condition`; field kustom seperti `origin_hunt` diperbolehkan [S5].

## 7. Cheat sheet

```
3 HUNT      -026 Velociraptor (DLL side-load, T1574.001) | -028 Wazuh+firewall (Linux keluar, T1071.001/T1105)
            | -027 Splunk 4688 (populasi regional, TA0002) ; tiga platform, tiga pelajaran program
TIAP HUNT   abstract ABLE + kartu kesiapan -> query -> label (bukti di luar query) -> positive control
            -> laporan (Kategori hasil + blok Metrik) -> usulan deteksi + handover
NEGATIF OK  cakupan per host (yang menjawab, bukan yang direncanakan) + uji positif + label berbukti
TELEMETRI   GPO ditautkan != event terkirim ; baseline lama != populasi baru ; 4688 != Sysmon (no hash/OFN/net)
            detection Sysmon tetap buta di 4688 walau GPO berubah -> periksa pipeline tiap detection
METRIK 31/3 25 hunt, 23 negatif ; hunt->detection 9/25=36% (TURUN, jujur) ; uji positif 5/23=21,7% (NAIK)
            20 celah (4 baru) ; detection aktif tetap 12 ; usulan capstone FP tinggi -> laporan hunter
SATU HLM    permanen (termasuk dari hunt negatif) -> arti "tidak ditemukan" + batas -> risiko & keputusan
            -> ARAH Q2 (bukan rencana penuh) ; jumlah hunt paling bawah
PORTOFOLIO  HUNT-CAP-001..003 lab ; Atomic GUID dicatat ; SANITASI (buang nama org fiktif, host, IP, angka kerja)
            repo + write-up English + layer Navigator 4.5 (before/after/hunted) + rubrik 12 x 0-2 (>=20 siap)
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Ketiga hunt capstone berakhir 'tidak ditemukan', jadi capstone-nya gagal dan tidak ada yang bisa dibawa ke evaluasi." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Capstone menilai kelengkapan siklus, bukan temuan. Ketiga hunt punya positive control yang terbukti (query menangkap pola target), cakupan per host yang tertulis, dan label berbukti untuk setiap item mirip pola. Ketiganya meninggalkan keluaran permanen: baseline regional, 4 celah telemetri baru yang kini berpemilik, 3 usulan deteksi, dan cakupan yang melebar ke server Linux, workstation regional, dan keadaan disk. Yang dibawa ke evaluasi justru itu, ditambah kenaikan hasil negatif teruji dari 10% menjadi 21,7%. Lihat bagian 1.5 dan Bagian F, G.

</details>

**2. Skenario keputusan.** Hunt Velociraptor `HUNT-2027-026` menemukan `version.dll` di samping `fpviewer.exe` bertanda tangan di `AppData\Local` dua workstation. Apa langkah yang paling tepat?

- A. Tulis "ditemukan side-loading" dan eskalasi ke IR, karena polanya persis `INC-2027-040`.
- B. Labeli jinak tanpa pemeriksaan lebih lanjut, karena `fpviewer.exe` bertanda tangan.
- C. Periksa bukti di luar query: penanda tangan DLL dibanding executable, hash DLL di kedua host, tiket pemasangan; baru beri label.

<details><summary>Jawaban</summary>

C. Nama dan lokasi saja tidak cukup; `INC-2027-040` sendiri memakai executable bertanda tangan dengan DLL palsu. Pemeriksaan menemukan penanda tangan DLL sama dengan executable-nya, hash DLL identik di dua host, dan tiket pemasangan IT, sehingga label jinak punya dasar. A keliru karena mengangkat kemiripan permukaan menjadi insiden tanpa bukti, membuang waktu IR. B keliru karena tanda tangan executable tidak menjamin DLL di sampingnya; justru itu inti side-loading. Lihat Bagian B langkah 7.

</details>

**3. Pertanyaan jebakan.** "Setelah GPO audit ditautkan ke Bandung dan POP pada 22 Maret, semua detection endpoint kini melindungi workstation regional." Benarkah?

<details><summary>Jawaban</summary>

Tidak. GPO membuat 4688 terkirim dari 63 workstation regional, sehingga prosesnya terlihat untuk hunting dan untuk satu detection yang membaca `wineventlog` (scheduled task AppData, `-015`). Lima detection berbasis Sysmon tetap buta, karena pipeline konversinya mengunci `index=sysmon sourcetype=XmlWinEventLog` dan 4688 tidak masuk ke sana. Selain itu 4688 tidak membawa hash, `OriginalFileName`, atau data jaringan, sehingga pola yang bergantung field itu tetap tidak tertangkap. Yang benar: regional kini terlihat untuk hunting dan satu detection, belum untuk lima lainnya. Lihat bagian 1.4 dan Bagian D.

</details>

**4. Skenario keputusan.** Rasio hunt ke detection turun dari 40,9% (18 Maret) ke 36,0% (31 Maret). Bagaimana membawanya ke evaluasi?

- A. Jangan tampilkan rasio itu; cukup "25 hunt selesai".
- B. Tampilkan apa adanya dan jelaskan: tiga hunt terakhir menambah penyebut tanpa detection aktif karena ketiganya ber-FP tinggi atau negatif bersih, sambil menyorot uji positif yang naik dan celah yang kini berstatus.
- C. Naikkan satu usulan capstone menjadi "aktif" supaya rasionya tidak turun.

<details><summary>Jawaban</summary>

B. Angka yang turun menceritakan keputusan yang benar: menjalankan hunt sesuai pelajaran program walau tidak menghasilkan detection, lalu meninggalkan baseline dan celah. A menyembunyikan, dan begitu Nina menelusuri register ia menemukan penyebut berubah tanpa catatan. C memalsukan: usulan ber-FP tinggi yang dipaksa aktif akan membanjiri antrean L1 dan merusak kepercayaan pada program. Yang disorot justru angka yang naik: hasil negatif teruji (10% ke 21,7%) dan celah berstatus (68,8% ke 85%). Lihat Bagian G.

</details>

**5. Jelaskan ulang.** Jelaskan kepada seorang analyst L1 yang baru ikut program, dalam tiga kalimat, kenapa setiap hunt capstone wajib punya positive control dan apa yang dilakukan bila positive control-nya lolos.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Positive control adalah contoh positif yang sudah kita ketahui, dari kasus lama atau test jinak di lab, yang dijalankan atas query hunt untuk membuktikan query itu benar-benar bisa menangkap pola yang kita cari. Tanpa itu, hasil 'tidak ditemukan' bisa berarti dua hal yang sangat berbeda: memang bersih, atau query-nya buta. Kalau positive control lolos, seperti saat daftar nama DLL kita belum memuat amsi.dll, kita perbaiki query atau daftarnya dulu lalu jalankan ulang, baru menulis hasil, bukan menuliskan 'tidak ditemukan' atas query yang terbukti buta."

Kesalahan yang sering muncul:
- Menyebut positive control sebagai "mencari penyerang", padahal ia menguji query, bukan lingkungan.
- Menjalankan positive control setelah hasil ditulis, sehingga tidak sempat memperbaiki query.
- Menganggap hunt yang gagal menangkap positive control-nya sebagai "tidak ditemukan".

</details>

**6. Pertanyaan jebakan.** "Portofolio hunting-ku pakai kasus PT JAB yang sudah disamarkan nama host dan IP-nya, jadi aman dipublikasikan." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Sanitasi bukan sekadar mengganti nama host dan IP; artefak publik tidak boleh memuat data kerja apa pun, termasuk nama organisasi (bahkan yang fiktif seperti PT JAB), nomor insiden, nama detection, dan angka hasil kerja seperti "428 dari 443 host". Pembaca tidak bisa membedakan fiktif dari nyata, dan nama itu mengikatmu ke catatan kerja. Portofolio dibangun dari replikasi di lab pribadi (`HUNT-CAP-001` sampai `-003`) dengan data milikmu sendiri, bukan dari kasus kerja yang disamarkan. Lihat bagian 1.6 dan Bagian J.

</details>

**7. Interview question (English).** "Walk me through a hunt you ran end to end, including how you knew your query actually worked."

<details><summary>Sample answer</summary>

"I hunted for DLL side-loading, where a signed executable in a user-writable folder loads a planted DLL named after a system library like version.dll. I wrote an ABLE hypothesis, checked data readiness, and ran two Velociraptor artifacts across the fleet: one to find those DLL files on disk, one to see which running processes loaded them. I froze coverage at expiry and wrote down the hosts that did not answer, because a hunt that expires is not a hunt that finished. Before writing the result I ran a positive control: a known-benign Atomic Red Team side-loading test in my lab. The first run missed it because the DLL name was not on my list, so I added it and re-ran until it caught the test, because a query that cannot catch its own positive control is blind, not negative. The result was negative with a stated scope, and I turned the pattern into a scheduled hunt rather than an alert, since this technique has a high false-positive rate. I keep every query, the test GUIDs, and the metrics in a repo so anyone can recount the numbers."

What makes this answer strong: it shows the full cycle, treats scope and expiry honestly, makes the positive control the centerpiece, and chooses a scheduled hunt over a noisy alert based on false-positive risk.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | MITRE ATT&CK: Versions of ATT&CK | https://attack.mitre.org/resources/versions/ | primer | diakses 2026-10-18 | Tinggi. v20.0 dirilis 2026-10-13; v19.2 2026-04-28 sampai 2026-10-12 |
| S2 | MITRE ATT&CK: T1105 Ingress Tool Transfer | https://attack.mitre.org/techniques/T1105/ | primer | v2.6 (2026-09-11); diakses 2026-10-18 | Tinggi. Menyebut curl, wget, scp, sftp, rsync di Linux; platform termasuk Linux |
| S3 | MITRE ATT&CK: T1547.001 Registry Run Keys / Startup Folder | https://attack.mitre.org/techniques/T1547/001/ | primer | diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi. Autostart lewat Run key dan folder Startup |
| S4 | MITRE ATT&CK: T1071.001 Application Layer Protocol: Web Protocols | https://attack.mitre.org/techniques/T1071/001/ | primer | v1.5 (2026-09-11); diakses 2026-10-18 | Tinggi. C2 di HTTP/S dan WebSocket; platform termasuk Linux |
| S5 | SigmaHQ: Sigma Rules Specification 2.1.0 | https://github.com/SigmaHQ/sigma-specification | primer | versi 2.1.0 (2025-08-02); diakses 2026-10-18 | Tinggi. Field wajib title/logsource/detection+condition; field kustom diperbolehkan; status stable/test/experimental/deprecated/unsupported |
| S6 | MITRE ATT&CK Navigator (repo dan USAGE.md) | https://github.com/mitre-attack/attack-navigator | primer | diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi. Layer, skor, komentar; Create Layer from other layers (variabel a/b, operator 1/0), pewarisan hanya domain dan versi sama, ekspor SVG/JSON |
| S7 | Velociraptor: Windows.Sysinternals.Autoruns | https://docs.velociraptor.app/artifact_references/pages/windows.sysinternals.autoruns/ | primer | diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi untuk cara kerja artifact; menjalankan autorunsc dan mem-parse keluarannya; kolom tidak dirinci |
| S8 | LOLBAS: Certutil | https://lolbas-project.github.io/lolbas/Binaries/Certutil/ | sekunder (katalog komunitas) | diakses 2026-10-10 | Tinggi untuk fungsi unduh certutil |
| S9 | MITRE ATT&CK: T1574.001 Hijack Execution Flow: DLL | https://attack.mitre.org/techniques/T1574/001/ | primer | v3.0 (2026-09-11); diakses 2026-10-18 | Tinggi. Side-loading, search order hijacking, phantom DLL, substitusi; taktik Stealth dan Execution; strategi deteksi DET0201 |
| S10 | Atomic Red Team: T1574.001 dan T1105 | https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1574.001 ; https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1105 | primer (katalog test) | diakses 2026-10-18 | Tinggi. T1574.001 test 1 (amsi, GUID 8549ad4b...), 4 (GUP.exe calc, 65526037...), 7 (ntprint, e96b8105...); T1105 Linux test 27 curl (bdc373c5...), rsync push (0fc6e977...). Nomor bisa bergeser, GUID tetap |
| S11 | MITRE ATT&CK Navigator: Layer File Format v4.5 dan CHANGELOG | https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md ; https://raw.githubusercontent.com/mitre-attack/attack-navigator/master/CHANGELOG.md | primer | diakses 2026-10-18 | Tinggi. Field wajib name/domain; versions.navigator minimal 4.9.0, versions.layer "4.5"; 5.3.2 (2026-04-21) terbaru; 4.5 sejak 4.9.0 (2023-10-31) |
| S12 | Velociraptor: Windows.System.DLLs | https://docs.velociraptor.app/artifact_references/pages/windows.system.dlls/ | primer | diakses 2026-10-18 | Tinggi. Parameter ProcessRegex/DllRegex/Calculate_Hash/CertificateInfo; kolom Pid, Name, ModuleName, ModulePath, Hash, Certinfo; memakai pslist() lalu modules() |
| S13 | Velociraptor: Windows.Search.FileFinder | https://docs.velociraptor.app/artifact_references/pages/windows.search.filefinder/ | primer | diakses 2026-10-18 | Tinggi. Parameter Glob/SearchFilesGlobTable/Calculate_Hash/Upload_File; kolom OSPath, Size, MTime, Hash; rate limit 20-50 ops/detik untuk pencarian isi |
| S14 | Velociraptor: glob (VQL reference) | https://docs.velociraptor.app/vql_reference/popular/glob/ | primer | diakses 2026-10-18 | Tinggi. `*`, `?`, `{a,b}`, `**` kedalaman default 3 (`**10` untuk ubah), tidak peka huruf, `/` dan `\` sama |
| S15 | HijackLibs (proyek dan entri version.dll) | https://hijacklibs.net/ ; https://hijacklibs.net/entries/microsoft/built-in/version.html | sekunder (katalog komunitas) | diakses 2026-10-18 | Sedang-tinggi. Pemetaan DLL ke executable rentan, aturan Sigma, CSV/JSON; version.dll 42 executable, lokasi wajar System32/SysWOW64; peringatan FP tinggi |
| S16 | Wazuh ruleset v4.14.0: 0040-auditd_decoders.xml | https://raw.githubusercontent.com/wazuh/wazuh/v4.14.0/ruleset/decoders/0040-auditd_decoders.xml | primer (kode sumber) | tag v4.14.0; diakses 2026-10-18 | Tinggi. Field data.audit.* termasuk exe, execve.a0-a7, auid, cwd; argumen tidak diekstrak di atas a7 |
| S17 | Velociraptor releases (0.77.3) | https://github.com/Velocidex/velociraptor/releases | primer | 0.77.3, 2026-10-05; diakses 2026-10-18 | Tinggi. Versi terbaru, rilis perbaikan CVE; tidak ada rilis lebih baru |
| S18 | Wazuh documentation: Release notes | https://documentation.wazuh.com/current/release-notes/index.html | primer | 4.14.9 (2026-10-14); diakses 2026-10-18 | Tinggi. Versi terbaru 4.14.9; belum ada 5.0 |
| S19 | Microsoft Learn: 4688(S) A new process has been created | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688 | primer | diperbarui 2026-04-27; diakses 2026-10-18 | Tinggi. Field NewProcessName, ParentProcessName (Creator Process Name, versi 2), CommandLine (versi 1+, default kosong), TokenElevationType, MandatoryLabel |
| S20 | MITRE ATT&CK: T1059.003 Windows Command Shell | https://attack.mitre.org/techniques/T1059/003/ | primer | v1.5 (2026-05-12); diakses 2026-10-18 | Tinggi. Penyalahgunaan cmd.exe dan file batch; taktik Execution |
| S21 | Splunk Enterprise 10.6 release notes | https://help.splunk.com/en/splunk-enterprise/release-notes-and-updates/release-notes/10.6 | primer | 10.6 (2026-09-30), 10.6.1 (2026-10-16); diakses 2026-10-18 | Tinggi untuk tanggal rilis |
| S22 | Threat-Hunting Day 01-15 (metode siklus, templat, register, metrik) | (lokal) | rujukan internal | 2026-10-18 | Sumber metode dan semua angka PT JAB di capstone; ABLE, kartu kesiapan, stacking, hunting per platform, usulan deteksi, lembar metrik |

**Catatan sumber:** nama kolom keluaran `Windows.Sysinternals.Autoruns`, `Windows.System.DLLs`, dan `Windows.Search.FileFinder` mengikuti dokumentasi artifact dan sebagian tidak dirinci (bentuk `Hash` dan `Certinfo`); cek satu baris hasil di lab versi 0.77.x sebelum menulis query notebook. Daftar executable rentan di HijackLibs [S15] adalah data komunitas yang diperbarui otomatis; angka 42 untuk version.dll per akses 2026-10-18. Seluruh angka, nama, host, akun, dan hasil PT JAB di Day ini (`HUNT-2027-026` sampai `-028`, metrik 31 Maret, register celah, satu halaman evaluasi) adalah penerapan catatan ini pada organisasi fiktif, bukan hasil eksekusi nyata; seluruh keluaran query adalah ilustrasi. Jalur portofolio (`HUNT-CAP-001` sampai `-003`) dikerjakan di lab pribadi pembaca dengan data miliknya sendiri.
