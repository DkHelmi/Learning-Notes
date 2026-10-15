---
day: 14
title: 'Respons ransomware end-to-end: sinyal sebelum enkripsi, containment, backup, dan pelaporan'
researched_on: 2026-10-15
versions_checked: 'CISA #StopRansomware Guide (edisi September 2023); NCSC UK Mitigating malware and ransomware attacks (v3.0, direview 9 September 2021, dimodifikasi 28 Juli 2026); MITRE ATT&CK v20 (T1486 Data Encrypted for Impact, T1490 Inhibit System Recovery); Microsoft Incident Response ransomware approach (ms.date 2024-10-16); Microsoft Defender XDR, Find ransomware with advanced hunting (ms.date 2026-07-02); NIST IR 8374 Rev. 1 (Juni 2026); Sophos State of Ransomware 2025; The DFIR Report, Quantum Ransomware (April 2022)'
---

# Day 14: Respons ransomware end-to-end (sinyal sebelum enkripsi, containment, backup, dan pelaporan)

Cakupan: memahami ransomware yang dijalankan manusia sebagai insiden yang sudah berjalan berhari-hari sebelum enkripsi, mengenali sinyal sebelum enkripsi, menahan penyebaran yang sedang berjalan cepat, merekonstruksi jalan masuk dan luas kompromi, memulihkan dari backup yang tepercaya, menimbang keputusan membayar tebusan, dan menangani sisi pencurian data dan pelaporan.

## Ide inti

Ransomware modern bukan virus yang kebetulan menyebar, melainkan tahap terakhir dari operasi manusia yang sudah masuk berhari-hari sebelumnya: mendapat akses awal, mencuri kredensial, bergerak lateral, mematikan alat keamanan, menghapus backup, sering menyalin data keluar, lalu baru mengenkripsi. Saat enkripsi mulai dan alert berbunyi, yang kamu lihat adalah ujung dari rantai itu. Karena itu respons ransomware punya dua sisi yang harus dikerjakan bersamaan. Sisi pertama adalah balapan: kerusakan sedang berjalan, jadi host yang sedang mengenkripsi ditahan dulu, bahkan sebelum scope lengkap. Sisi kedua adalah investigasi mundur: dari enkripsi, telusuri kembali sampai jalan masuk, karena membersihkan host yang terenkripsi tanpa menutup jalan masuk hanya mengundang gelombang kedua. Setelah itu baru pemulihan dari backup yang benar-benar bersih, dan penanganan data yang mungkin sudah dicuri.

Kamu sudah mengenal pola ini dari NOC. Saat gangguan berantai mulai menjatuhkan POP satu per satu, engineer tidak menunggu laporan lengkap sebelum bertindak: ia memasang isolasi darurat untuk menghentikan perambatan, lalu baru mencari akar (kartu yang flapping, loop, konfigurasi salah) sambil memulihkan layanan dari konfigurasi standar yang diketahui baik. Ransomware memakai pola yang sama dengan dua perbedaan. Pertama, perambatannya disengaja oleh manusia yang bisa mempercepat begitu sadar dipergoki. Kedua, backup yang biasa jadi jaring pengaman justru diincar lebih dulu, jadi jaring itu belum tentu ada saat dibutuhkan.

```
akses awal (hari H-beberapa)   exploit, kredensial, RDP          <- sering tidak teralert
  |
  v
eskalasi + lateral             dump kredensial, PsExec, RDP
  |
  v
persiapan enkripsi             matikan AV, hapus shadow copy,
  (sinyal sebelum enkripsi)    hapus/henti backup, (sering) exfil   <- jendela deteksi terakhir
  |
  v
ENKRIPSI + catatan tebusan     alert berbunyi                      <- kebanyakan org sadar di sini
  |
  +-- tahan host yang mengenkripsi SEKARANG (kerusakan berjalan)
  +-- telusuri mundur ke jalan masuk (jangan rebuild lalu kena lagi)
  +-- pulihkan dari backup yang terbukti bersih dan terpisah
  +-- tangani data yang mungkin dicuri (pelaporan, Day 18)
```

Situasi yang dipakai sepanjang Day ini melanjutkan `INC-2026-017` dari Day 01, di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif. Ringkasnya: Jumat 2026-10-09 pukul 21:32, alert `SOC-2026-0187` sampai `-0191` menunjukkan file di share `Keuangan` pada `JKT-FS01` berganti ekstensi `.lck` dan muncul `BACA-INI.txt`. Insiden dinyatakan SEV-1 pukul 22:03 oleh IC Dimas Prasetyo atas usul L2 on-call Yoga Pratama. Sumber enkripsi `JKT-WS-0457` (akun `budi.santoso`) diisolasi 23:18 dan akunnya dinonaktifkan 23:24; `JKT-FS01` diisolasi lewat EDR pukul 22:17. Sabtu 2026-10-10 pukul 08:30, setelah tim bekerja semalaman, Direktur Teknologi Hendra Wijaya menulis di kanal `#inc-2026-017`:

> "Dim, semalam saya ikuti. Sekarang saya harus bisa menjawab beberapa hal sebelum Senin. Ini masuk lewat mana, dan sejak kapan mereka di dalam? Kenapa baru ketahuan jam 21:32, bukan lebih awal? Data pelanggan ada yang dicuri tidak, atau cuma dikunci? Kita bisa pulih dari backup tidak, atau harus bayar? Kalau bayar, siapa yang boleh memutuskan? Lalu kapan layanan keuangan bisa jalan lagi, dan apa kewajiban lapor kita?"

Pesan itu memuat tujuh pertanyaan:

1. Masuk lewat mana, dan sejak kapan penyerang di dalam?
2. Kenapa baru ketahuan saat enkripsi, bukan lebih awal?
3. Data dicuri atau hanya dikunci?
4. Bagaimana menahan dan membersihkan tanpa mengundang gelombang kedua?
5. Bisa pulih dari backup, atau harus bayar?
6. Kalau mempertimbangkan bayar, siapa yang memutuskan?
7. Kapan layanan pulih, dan apa kewajiban pelaporan?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, pertanyaan 6 di bagian 1.6, dan pertanyaan 7 di bagian 1.7. Bagian 2 berisi query perburuan, rencana pemulihan, memo keputusan tebusan, dan garis waktu pelaporan PT JAB.

**Kapan relevan:** saat ada tanda enkripsi massal, catatan tebusan, atau sinyal persiapan ransomware (AV dimatikan, shadow copy dihapus, backup diutak-atik); dan saat merancang kesiapan backup dan playbook ransomware sebelum insiden.
**Kapan bukan jawaban:** Day ini bukan tentang kompromi domain menyeluruh; bila penyerang menguasai domain dan menyebar ransomware lewat GPO atau PsExec dari DC, penanganan AD mengikuti Day 12 (bagian 1.7). Rincian kewajiban pelaporan ke regulator dan subjek data dibahas di Day 18; di sini hanya sejauh menentukan apa yang harus dicatat sejak awal.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (insiden, severity, IC, executive sponsor, containment, eradication, recovery, scoping, scope statement, bukti, IOC, blast radius, jam H) tidak diulang. Tabel berikut memuat istilah baru Day ini. Kolom padanan memakai analogi NOC dan SOC yang sama di semua Day IR.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Human-operated ransomware | Ransomware yang dijalankan operator manusia yang masuk dan bergerak dulu, bukan menyebar otomatis | Gangguan yang dipicu tindakan manusia, bukan kegagalan perangkat |
| Sinyal sebelum enkripsi | Aktivitas persiapan (matikan AV, hapus shadow copy, henti backup) sebelum file dikunci | Lonjakan error dan drop sesi sebelum link benar-benar putus |
| Time-to-ransom (TTR) | Rentang dari akses awal sampai enkripsi dijalankan | Rentang dari gejala pertama sampai gangguan massal |
| Double extortion | Data disalin keluar lalu dipakai mengancam publikasi, selain dikunci | Pelaku tidak hanya memutus layanan, tetapi juga menyandera data pelanggan |
| Shadow copy | Salinan snapshot volume Windows yang bisa dipakai memulihkan file | Snapshot konfigurasi perangkat sebelum perubahan |
| Inhibit system recovery | Menghapus atau mematikan mekanisme pemulihan bawaan sebelum enkripsi | Menghapus konfigurasi cadangan dan boot image di perangkat |
| Backup offline atau immutable | Salinan cadangan yang terpisah dari jaringan atau tidak bisa diubah atau dihapus | Konfigurasi standar yang disimpan di repositori terpisah dan tidak bisa ditimpa |
| Gerbang validasi recovery | Uji keamanan sebelum sistem pulih dikembalikan ke produksi | Uji layanan sebelum tiket gangguan ditutup |
| Decryptor | Alat pemulih file untuk varian ransomware tertentu | Patch pemulih dari vendor untuk bug tertentu |
| Minimum viable operations (MVO) | Layanan paling penting yang dipulihkan lebih dulu | Layanan prioritas yang dinaikkan duluan saat gangguan besar |

### 1.1 Jalan masuk dan sejak kapan: alert enkripsi adalah ujung, bukan awal

Hendra bertanya "masuk lewat mana, sejak kapan". Pertanyaan ini wajib dijawab lebih dulu, karena menentukan apa yang harus dibersihkan dan apa yang harus ditutup. Microsoft Incident Response menyebut menentukan bagaimana penyerang mendapat akses sebagai hal krusial untuk menemukan celah, memitigasi, dan mencegah serangan berikutnya, dan mengingatkan penyerang sering menutupi jejak sehingga rantai lengkapnya belum tentu terlihat [S5].

Ransomware yang dijalankan manusia bukan masalah perangkat lunak berbahaya semata, melainkan masalah pelaku manusia yang berperilaku seperti aktor tingkat lanjut: ia mematikan atau menghapus antivirus sebelum mengenkripsi, mematikan layanan keamanan dan logging agar tidak terdeteksi, serta menemukan dan merusak atau menghapus backup sebelum mengirim permintaan tebusan [S5]. Karena itu rentang antara akses awal dan enkripsi (time-to-ransom) bisa panjang atau sangat pendek. The DFIR Report mendokumentasikan satu kasus Quantum dengan TTR hanya 3 jam 44 menit, dari IcedID yang dikirim lewat email sampai ransomware dijalankan dengan WMI dan PsExec [S9]. Di banyak kasus lain, operator berada di dalam berhari-hari lebih dulu.

Untuk `INC-2026-017`, investigasi mundur Sabtu dini hari menyusun rantai berikut (semuanya fiktif, keluaran ilustrasi):

- **Rabu 2026-10-07, sekitar 03:10:** akses awal lewat kerentanan pada server aplikasi lama yang menghadap internet, `jkt-dmz-app01` (`10.20.9.20`). Kerentanan yang dieksploitasi sesuai temuan umum: Sophos State of Ransomware 2025 menyebut kerentanan yang dieksploitasi sebagai akar teknis terbanyak, 32 persen kasus [S8]. Dari situ terpasang beacon ke `sync-win.example.net` (`203.0.113.205:443`).
- **Rabu sampai Kamis:** dump kredensial di `jkt-dmz-app01`, penemuan jaringan, dan pemakaian ulang kredensial local admin ke host internal lewat RDP dan SMB.
- **Kamis 2026-10-08:** lateral ke workstation keuangan `JKT-WS-0441` (`siti.rahayu`, `10.10.44.41`) lalu `JKT-WS-0457` (`budi.santoso`, `10.10.45.57`), keduanya punya akses tulis ke share `Keuangan` di `JKT-FS01`.
- **Jumat 2026-10-09:** persiapan enkripsi dan (diduga) pencurian data, lalu enkripsi pukul 21:32.

Alert pertama (21:32) bukan awal insiden. Day 03 bagian 1.4 sudah menegaskan prinsip ini untuk insiden lain; di ransomware ia lebih tajam, karena titik masuk sering jauh di hulu dan di host yang paling sedikit dipantau.

### 1.2 Kenapa baru ketahuan saat enkripsi: sinyal yang terlewat

Hendra bertanya "kenapa baru jam 21:32". Jawabannya: ada sinyal sebelum enkripsi, tetapi sebagiannya lewat karena prioritas rendah atau cakupan deteksi yang bolong. Mengenali sinyal ini adalah inti deteksi ransomware, karena di situlah jendela untuk menghentikan serangan sebelum data hilang [S6].

Microsoft mengelompokkan aktivitas persiapan yang halus tetapi umum [S6]:

- **Menghentikan proses dan layanan** dengan `taskkill.exe`, `net stop`, dan `sc.exe`, supaya file tidak terkunci aplikasi dan supaya software keamanan serta backup tidak mengganggu enkripsi.
- **Menghapus shadow copy dan mematikan pemulihan** dengan `vssadmin.exe`, `wmic shadowcopy delete`, `wbadmin delete catalog`, dan `bcdedit` (mematikan recovery otomatis). MITRE menamai ini Inhibit System Recovery (T1490) [S4].
- **Menghapus log dan bukti** dengan `wevtutil cl`, `cipher.exe /w`, dan `fsutil usn deletejournal`.

Enkripsi itu sendiri adalah Data Encrypted for Impact (T1486) [S3]: ledakan penulisan file dengan ekstensi tak biasa (`.lck` di sini), diikuti catatan tebusan di banyak folder.

Di `INC-2026-017`, dua sinyal ada tetapi tidak dieskalasi: alert `SOC-2026-0192` (tamper terhadap antivirus di `JKT-WS-0457`, pukul 20:52, masuk antrean dengan prioritas P3) dan `SOC-2026-0193` (penghapusan shadow copy di `JKT-WS-0441`, pukul 21:05). Keduanya adalah jendela deteksi terakhir yang terlewat. CISA meminta tim memeriksa sistem deteksi dan log yang ada untuk aktivitas tahap awal dan malware pendahulu, karena peristiwa ransomware bisa menjadi bukti kompromi jaringan sebelumnya yang belum ditangani [S1]. Pelajaran ini dicatat untuk post-incident review (Day 18 dan review minggu), bukan untuk menyalahkan analyst yang menerima alert P3 tengah malam.

### 1.3 Dicuri atau dikunci: double extortion dan kenapa itu mengubah kewajiban

Hendra bertanya "data dicuri atau cuma dikunci". Jawabannya menentukan kewajiban, bukan hanya teknis: bila data pribadi disalin keluar, kewajiban pelaporan muncul walaupun file bisa dipulihkan dari backup. NCSC mengingatkan penyerang bisa mengancam mempublikasikan data yang dicuri bahkan ketika file korban bisa dipulihkan, dan menyarankan organisasi mengenali kewajiban pelaporannya [S2].

Tanda pencurian data dicari di log keluar: transfer keluar yang tidak wajar di port mana pun, alat tunneling, dan alat transfer data seperti rclone, Rsync, FTP/SFTP, atau penyimpanan berbasis web [S1]. Di `INC-2026-017`, log proxy dan firewall menunjukkan transfer keluar sekitar 6 GB dari `JKT-WS-0457` ke `198.51.100.205` antara 18:40 dan 20:10 Jumat, sebelum enkripsi. Catatan tebusan `BACA-INI.txt` mengklaim data sudah dicuri. Klaim catatan tebusan sendiri bukan bukti (The DFIR Report mencatat catatan tebusan yang mengklaim pencurian tanpa eksfiltrasi yang teramati [S9]), tetapi di sini klaim itu didukung bukti transfer keluar, sehingga PT JAB menilai data kemungkinan besar dicuri dengan keyakinan sedang sampai tinggi, dan share `Keuangan` memuat data tagihan pelanggan.

Konsekuensinya: severity tetap SEV-1, DPO Agus Setiawan dan Legal Ratna Sari ikut sejak awal, dan isi share yang dicuri harus diidentifikasi untuk menilai kewajiban pelaporan. Day 01 sudah menegaskan: bila ada tanda data disalin keluar sebelum enkripsi, severity tetap SEV-1 dan DPO ikut sejak awal.

### 1.4 Menahan dan membersihkan tanpa mengundang gelombang kedua

Hendra bertanya "bagaimana menahan tanpa kena lagi". Di ransomware, urutannya berbeda dari insiden yang sunyi (Day 03 bagian Ide inti): karena kerusakan berjalan cepat, host yang sedang mengenkripsi ditahan lebih dulu, lalu scoping dan bukti menyusul. Day 01 sudah menerapkan ini: `JKT-FS01` diisolasi lewat EDR tanpa dimatikan, supaya memori tetap ada.

CISA menempatkan isolasi segera sebagai langkah pertama: tentukan sistem terdampak dan isolasi; bila banyak sistem terdampak, putus jaringan di tingkat switch; bila tidak, cabut atau lepaskan dari Wi-Fi. Mematikan perangkat adalah jalan terakhir, hanya bila tidak mungkin memutus jaringan, karena mematikan menghapus bukti volatil di memori [S1]. Microsoft menambahkan: isolasi sistem terkompromi dari jaringan tetapi jangan dimatikan, nonaktifkan akun privileged kecuali sedikit yang dipakai memulihkan AD, dan isolasikan minimal satu (idealnya dua) domain controller yang diketahui baik di tiap domain [S5].

Setelah penyebaran berhenti, barulah pembersihan dan penutupan jalan masuk. CISA mengurutkan: ambil image dan memori sampel host bila mitigasi belum mungkin, identifikasi sistem dan akun pada breach awal termasuk akun email, kontain sistem yang bisa memberi akses lanjutan (VPN, remote access, SSO, aset yang menghadap internet), lalu rebuild sistem menurut urutan prioritas layanan dan baru reset password setelah lingkungan dibersihkan [S1]. Di `INC-2026-017`, selain `JKT-FS01` dan `JKT-WS-0457` (sudah ditahan Jumat malam), Sabtu pagi ditambahkan: isolasi `jkt-dmz-app01` dan `JKT-WS-0441`, blok `203.0.113.205` dan `198.51.100.205` di firewall dengan logging dan sinkhole `sync-win.example.net`, lalu rotasi kredensial yang terpapar (local admin yang dipakai ulang, `svc_backup` karena infrastruktur backup tersentuh, dan `budi.santoso` yang sudah dinonaktifkan). Karena tidak ada bukti penyerang mencapai domain controller atau akun domain admin, reset krbtgt tidak diperlukan; pola keputusan dan pemicunya mengikuti Day 06 bagian 1.4 dan Day 11 bagian 1.6.

Satu catatan tentang domain: bila penyerang sudah menguasai domain, ia bisa menyebarkan ransomware ke seluruh jaringan sekaligus lewat GPO atau PsExec dari DC. Di titik itu, ransomware menjadi bagian dari kompromi domain dan pemulihannya mengikuti Day 12 (bagian 1.7), bukan hanya reimage beberapa host. Di `INC-2026-017` penyebaran masih manual ke segelintir host, jadi penanganannya tetap di tingkat host dan file server.

### 1.5 Pulih dari backup, atau bayar: kenapa backup lebih dulu diperiksa

Hendra bertanya "bisa pulih dari backup, atau harus bayar". Jawabannya bergantung pada apakah ada backup yang benar-benar bersih dan terpisah, karena backup justru yang pertama diincar. NCSC menekankan backup offline: dalam insiden nyata, backup online ikut terenkripsi dan disandera bersama data lain, sehingga penting selalu punya backup offline terbaru dari data terpenting [S2]. Sophos mencatat pemulihan lewat backup berada di titik terendah dalam enam tahun [S8], yang sejalan dengan backup yang makin sering dirusak lebih dulu.

Prinsip backup yang tahan ransomware [S2][S3][S4]:

- Simpan minimal satu salinan offline atau immutable, terpisah dari jaringan, idealnya di luar lokasi.
- Jangan biarkan perangkat backup terus tersambung ke jaringan, dan lindungi akun backup (akses privileged terbatas, MFA yang tidak di perangkat yang sama).
- Pilih layanan cloud yang menyimpan versi sebelumnya; aktifkan object versioning (M1053).
- Uji restore secara berkala; backup yang tidak pernah diuji belum tentu bisa dipulihkan.
- Sambungkan backup hanya ke perangkat yang diketahui bersih, dan pindai backup dari malware sebelum restore, karena ransomware bisa menyebar ke backup sebelum ketahuan [S2].

Di `INC-2026-017`, penyerang mencapai server backup lama `jkt-bkp-nas01` (`10.20.3.10`) dan menghapus snapshot online untuk `JKT-FS01`, tetapi salinan mingguan offline (tape yang dirotasi ke luar lokasi, terakhir Kamis 2026-10-08 dini hari) selamat. Artinya pemulihan `Keuangan` kehilangan sekitar satu setengah hari perubahan file, tetapi tidak perlu bergantung pada penyerang. Fakta ini menjadi dasar keputusan di bagian 1.6: karena ada jalan pulih yang tepercaya, membayar tidak diperlukan untuk memulihkan data.

Soal membayar secara umum: NCSC menyatakan penegak hukum tidak mendorong atau membenarkan pembayaran; membayar tidak menjamin data kembali, perangkat tetap terinfeksi, dan pembayaran mendanai kelompok kriminal serta bisa membuat organisasi jadi sasaran lagi; sebagian "ransomware" sebenarnya wiper yang tidak memulihkan data walau dibayar [S2]. CISA menyarankan berkonsultasi dengan penegak hukum tentang kemungkinan decryptor yang tersedia untuk varian tertentu sebelum menyimpulkan tidak ada jalan selain bayar [S1].

### 1.6 Siapa yang memutuskan: keputusan bisnis, bukan keputusan teknis

Hendra bertanya "kalau bayar, siapa yang memutuskan". Membayar atau tidak adalah keputusan bisnis dan hukum berdampak besar, jadi pemiliknya executive sponsor bersama Legal, bukan IC atau technical lead. Di RACI PT JAB (Day 02 bagian 2.2), keputusan yang berdampak bisnis besar (mematikan layanan pelanggan, membayar pihak ketiga, pengumuman publik) ada di executive sponsor Hendra.

Keputusan itu dibuat dengan informasi dari tim: apakah ada backup yang bisa dipulihkan dan berapa lama (dari technical lead), apakah ada decryptor publik atau dari penegak hukum [S1], risiko hukum membayar (sanksi, aliran dana ke pihak yang dilarang; dinilai Legal), dan apakah pembayaran benar-benar mengurangi dampak pencurian data (sering tidak, karena data sudah di tangan penyerang). Di `INC-2026-017`, karena backup offline bisa dipulihkan dan data sudah terlanjur dicuri, Hendra bersama Legal dan DPO memutuskan tidak membayar; keputusan dan alasannya dicatat (bagian 2.3).

### 1.7 Kapan layanan pulih, dan apa yang harus dicatat untuk pelaporan

Hendra bertanya "kapan pulih, apa kewajiban lapor". Pemulihan mengikuti pola Day 06: pulihkan dari sumber tepercaya menurut urutan prioritas layanan (MVO), lewati gerbang validasi sebelum produksi, lalu pantau. CISA: sambungkan kembali dan restore dari backup offline terenkripsi menurut prioritas layanan, dan jangan menulari ulang sistem bersih, misalnya hanya menambahkan sistem bersih ke VLAN pemulihan [S1].

Untuk `INC-2026-017`, urutannya: rebuild `JKT-WS-0457`, `JKT-WS-0441`, dan `jkt-dmz-app01` dari image bersih; restore share `Keuangan` dari tape offline ke file server yang sudah dibersihkan; lewati gerbang validasi (bagian 2.2); lalu kembalikan akses bertahap sambil memantau ketat. Otoritas IT atau keamanan yang ditunjuk menyatakan insiden selesai berdasarkan kriteria yang sudah ditetapkan [S1].

Sisi pelaporan harus disiapkan sejak sekarang, bukan di akhir. Karena data pribadi pelanggan kemungkinan dicuri, PT JAB sebagai pengendali data pribadi punya kewajiban pemberitahuan menurut UU 27/2022 tentang Pelindungan Data Pribadi; titik mulai dan rinciannya dibahas di Day 18, dan titik mulai hitungan 3 x 24 jam Pasal 46 masih perlu dipastikan ke penjelasan resmi. Yang penting untuk Day ini: waktu, bukti transfer keluar, dan isi data yang terdampak dicatat rapi sejak awal, karena itu yang nanti menentukan apakah kewajiban terpenuhi. NIST IR 8374 Rev. 1 (Juni 2026), profil CSF 2.0 untuk ransomware, menempatkan respons dan pemulihan ransomware dalam kerangka yang sama dan bisa dipakai menyusun playbook ransomware organisasi [S7].

## 2. Contoh artefak dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Query KQL memakai skema advanced hunting Defender for Endpoint; query Splunk memakai index PT JAB dengan field mengikuti CIM. Cocokkan nama field dengan add-on yang kamu pakai.

### 2.1 Perburuan sinyal sebelum enkripsi di Defender for Endpoint

Query ini menjawab pertanyaan kedua Hendra: sinyal apa yang sebenarnya ada sebelum 21:32, dan di host mana saja. Pendekatannya menimbang beberapa sinyal sekaligus, karena satu sinyal saja (misalnya `vssadmin`) bisa sah [S6].

**Tujuan:** menemukan host yang menunjukkan lebih dari satu jenis aktivitas persiapan ransomware dalam rentang waktu insiden.

```kusto
let win = (ago(3d));
let recovery = DeviceProcessEvents
| where Timestamp > win
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has_any("delete shadows","resize shadowstorage"))
    or (FileName =~ "wmic.exe" and ProcessCommandLine has "shadowcopy" and ProcessCommandLine has "delete")
    or (FileName =~ "wbadmin.exe" and ProcessCommandLine has "delete")
    or (FileName =~ "bcdedit.exe" and ProcessCommandLine has_any("recoveryenabled no","bootstatuspolicy ignoreallfailures"))
| extend Sinyal = "inhibit_recovery";
let stopsvc = DeviceProcessEvents
| where Timestamp > win
| where (FileName =~ "net.exe" and ProcessCommandLine has "stop")
    or (FileName =~ "sc.exe" and ProcessCommandLine has "config" and ProcessCommandLine has "disabled")
    or (FileName =~ "taskkill.exe")
| extend Sinyal = "stop_proses_layanan";
let clearlog = DeviceProcessEvents
| where Timestamp > win
| where ProcessCommandLine has "wevtutil" and ProcessCommandLine has "cl"
| extend Sinyal = "hapus_log";
union recovery, stopsvc, clearlog
| summarize JenisSinyal = make_set(Sinyal), Perintah = make_set(ProcessCommandLine), Mulai = min(Timestamp) by DeviceName
| extend JumlahJenis = array_length(JenisSinyal)
| where JumlahJenis >= 2
| sort by Mulai asc
```

Penjelasan tiap bagian:

- Tiga blok memeriksa tiga kelompok sinyal: mematikan pemulihan, menghentikan proses dan layanan, dan menghapus log [S4][S6].
- `JumlahJenis >= 2` hanya menampilkan host dengan lebih dari satu jenis sinyal, supaya satu `vssadmin` yang sah (misalnya oleh software backup) tidak ikut. Turunkan ke 1 saat scoping agresif, naikkan untuk mengurangi kebisingan [S6].
- `Mulai` membantu menyusun urutan waktu: host yang sinyalnya paling awal sering lebih dekat ke titik masuk.

Keluaran ilustrasi (diringkas):

```
DeviceName     Mulai                 JumlahJenis  JenisSinyal
JKT-WS-0441    2026-10-09 21:05:12   2            [inhibit_recovery, stop_proses_layanan]
JKT-WS-0457    2026-10-09 20:49:38   3            [inhibit_recovery, stop_proses_layanan, hapus_log]
```

Cara membaca hasil: `JKT-WS-0457` menunjukkan tiga jenis sinyal mulai 20:49, sekitar 40 menit sebelum alert enkripsi 21:32. Ini membuktikan ada jendela deteksi yang terlewat, dan sekaligus menegaskan `JKT-WS-0457` sebagai host yang paling dalam terlibat. `JKT-WS-0441` menyusul, menandai host kedua yang harus masuk scope.

**Variasi:** tambahkan `DeviceNetworkEvents` untuk host yang sama guna melihat koneksi ke `203.0.113.205` atau `198.51.100.205`, menghubungkan sinyal persiapan dengan C2 dan exfil.

**Kapan gagal:** host sumber tidak memakai EDR (seperti `jkt-dmz-app01` yang server lama), sehingga sinyalnya tidak muncul di sini dan harus dicari di Sysmon atau log OS. Cakupan EDR yang bolong adalah salah satu pelajaran insiden ini.

### 2.2 Siapa yang menulis file terenkripsi, dan gerbang validasi restore

Query ini menjawab bagian dari pertanyaan pertama dan keempat: dari mana koneksi SMB yang menulis file `.lck` berasal, sehingga sumber enkripsi dipastikan sebelum containment. Day 01 menyebut temuan ini pukul 23:10; query di bawah adalah cara mendapatkannya.

**Tujuan:** menemukan host sumber yang menulis file dengan ekstensi `.lck` ke share `Keuangan` di `JKT-FS01`.

```
index=wineventlog host=JKT-FS01 EventCode=5145 Relative_Target_Name="*\\Keuangan\\*"
Accesses="*WriteData*"
earliest="10/09/2026:21:00:00" latest="10/09/2026:22:30:00"
| rex field=Relative_Target_Name "(?<ext>\.[^.\\\\]+)$"
| stats count values(ext) as ekstensi dc(Relative_Target_Name) as berkas
    min(_time) as mulai max(_time) as akhir by Source_Address, Account_Name
| sort - berkas
| convert ctime(mulai) ctime(akhir)
```

Penjelasan tiap bagian:

- Event 5145 (A network share object was checked) mencatat akses share beserta `Source_Address` dan `Account_Name`, sehingga sumber koneksi SMB terlihat.
- `rex` mengambil ekstensi tiap berkas untuk memisahkan penulisan `.lck` dari aktivitas normal.
- `dc(Relative_Target_Name)` menghitung jumlah berkas unik, yang untuk enkripsi massal akan sangat besar dibanding aktivitas normal.

Keluaran ilustrasi:

```
Source_Address  Account_Name   berkas  ekstensi   mulai                 akhir
10.10.45.57     budi.santoso    5231   [.lck]     10/09/2026 21:31:58   10/09/2026 22:17:04
10.10.44.41     siti.rahayu       12   [.xlsx]    10/09/2026 21:03:11   10/09/2026 21:19:22
```

Cara membaca hasil: `10.10.45.57` (`JKT-WS-0457`, `budi.santoso`) menulis 5.231 berkas `.lck` mulai 21:31:58 sampai 22:17:04, lalu berhenti tepat saat `JKT-FS01` diisolasi. Ini sumber enkripsi. Baris `siti.rahayu` dengan 12 berkas `.xlsx` adalah aktivitas kerja normal sebelum enkripsi, bukan penyerang; tetap diperiksa untuk memastikan.

**Gerbang validasi restore.** Sebelum share `Keuangan` yang dipulihkan dikembalikan ke produksi, jalankan gerbang validasi seperti Day 06 bagian 2.4: pastikan file yang dipulihkan dari tape tidak membawa berkas terenkripsi atau catatan tebusan, scan backup dari malware sebelum restore [S2], konfirmasi tidak ada `.lck` atau `BACA-INI.txt` tersisa, dan pastikan file server yang menerima restore adalah sistem yang sudah dibangun ulang bersih, bukan `JKT-FS01` lama. Query di atas dijalankan ulang pada file server bersih setelah restore; hasilnya harus nol berkas `.lck`.

**Kapan gagal:** audit object access (event 5145) tidak aktif di file server, sehingga sumber koneksi SMB tidak tercatat. Aktifkan audit share dan file system sebelum insiden; tanpa itu, sumber enkripsi hanya bisa ditebak dari EDR di host sumber.

### 2.3 Memo keputusan tebusan dan pemulihan

Memo ini menjawab pertanyaan 5 dan 6 Hendra. Disiapkan Dimas dan Sari Sabtu pukul 11:00, diputuskan Hendra bersama Legal dan DPO pukul 11:40. Perhatikan bahwa pilihan membayar tetap ditulis beserta alasan penolakannya, supaya keputusan bisa dipertanggungjawabkan.

```
INC-2026-017 | Memo keputusan tebusan dan pemulihan | Sabtu 2026-10-10 11:00 WIB
Untuk: Hendra Wijaya (executive sponsor) | Dari: Dimas Prasetyo (IC), Sari Kusuma (TL)
Dikonsultasikan: Ratna Sari (Legal), Agus Setiawan (DPO), Bambang Hartono (NOC),
                 PT Forensik Digital Contoh (retainer, siaga)
Severity: SEV-1

SITUASI
- Share Keuangan di JKT-FS01 terenkripsi (ekstensi .lck), 5.231 berkas.
- Data kemungkinan besar dicuri sebelum enkripsi: transfer ~6 GB ke 198.51.100.205
  Jumat 18:40-20:10 (keyakinan sedang-tinggi). Catatan tebusan mengklaim pencurian.
- Backup online JKT-FS01 di jkt-bkp-nas01 dihapus penyerang.
- Backup offline mingguan (tape, luar lokasi) terakhir Kamis 2026-10-08 selamat.

PILIHAN
A. Pulihkan dari tape offline (rekomendasi IC)
   + Tidak bergantung pada penyerang; tidak mendanai kriminal
   - Kehilangan perubahan file Keuangan sejak Kamis dini hari (~1,5 hari)
   - Perlu rebuild host dan file server dulu; perkiraan layanan keuangan 2-3 hari
B. Bayar tebusan untuk decryptor
   - Tidak menjamin data kembali; perangkat tetap perlu dibersihkan [S2]
   - Tidak menghentikan ancaman publikasi data yang sudah dicuri
   - Risiko hukum pembayaran (dinilai Legal); mendanai kelompok kriminal
   Ditolak: ada jalan pulih dari backup; data sudah terlanjur dicuri
C. Minta decryptor publik atau dari penegak hukum sebelum menyimpulkan
   + Murah dicek; CISA menyarankan konsultasi penegak hukum soal decryptor [S1]
   Dijalankan paralel dengan A, tidak menunda pemulihan

KEPUTUSAN (Hendra Wijaya, Legal, DPO, 11:40)
- Pilihan A, tidak membayar. Pulihkan dari tape offline ke file server bersih.
- Cek decryptor publik dan lapor ke penegak hukum (paralel).
- DPO dan Legal menyiapkan penilaian kewajiban pemberitahuan (lihat Day 18).
- Corporate Communication menyiapkan pesan internal; pengumuman publik ditahan
  sampai scope data yang dicuri jelas.
```

Cara membaca elemennya:

- **Pilihan B ditulis lengkap dengan alasan penolakan.** Bila nanti direksi atau regulator bertanya kenapa tidak membayar (atau kenapa tidak dipertimbangkan), jawabannya tercatat.
- **Keputusan dipegang bersama Legal dan DPO**, bukan IC sendiri, karena ini keputusan bisnis dan hukum (bagian 1.6).
- **Kewajiban data dipisah dari pemulihan teknis.** Memulihkan file tidak menghapus kewajiban atas data yang dicuri.

**Kapan gagal:** memo hanya menulis "tidak bayar, pulihkan dari backup" tanpa memastikan backup offline benar-benar ada dan bisa dipulihkan. Bila kemudian tape ternyata rusak atau ikut terenkripsi, keputusan harus diulang dalam tekanan waktu.

### 2.4 Garis waktu pelaporan dan hal yang dicatat sejak awal

Artefak ini menjawab pertanyaan ketujuh: apa yang harus dicatat sejak sekarang supaya kewajiban pelaporan bisa dipenuhi. Isinya ringkas; prosedur dan batas waktu lengkap ada di Day 18.

```
INC-2026-017 | Catatan untuk pelaporan | disusun bertahap sejak Sabtu 2026-10-10
DICATAT (fakta, bukan dugaan):
- Waktu kejadian kunci: akses awal ~Rabu 07/10 03:10; exfil Jumat 18:40-20:10;
  enkripsi Jumat 21:32; declare 22:03; containment selesai bertahap.
- Bukti transfer keluar: log proxy dan firewall ke 198.51.100.205, hash berkas
  arsip bila ditemukan, ukuran ~6 GB.
- Data terdampak: share Keuangan (berisi data tagihan pelanggan korporat);
  identifikasi isi persisnya sedang berjalan (basis penilaian kewajiban).
- Keyakinan pencurian: sedang-tinggi (bukti transfer + klaim tebusan).
MENUNGGU:
- Isi persis data yang dicuri (menentukan subjek data yang perlu diberi tahu).
- Penilaian Legal/DPO atas kewajiban dan titik mulai hitungan waktu (Day 18).
PRINSIP: titik mulai 3 x 24 jam UU PDP Pasal 46 dipastikan ke penjelasan resmi,
jangan diasumsikan; catat waktu validasi kejadian dengan teliti.
```

Cara membaca elemennya:

- **Fakta dipisah dari dugaan**, sama seperti catatan declare Day 01 bagian 2.1. Laporan ke regulator berdiri di atas fakta bertanggal.
- **Keyakinan ditulis eksplisit** ("sedang-tinggi"), karena pelaporan sering harus dilakukan sebelum semua pasti.
- **Titik mulai hitungan waktu tidak diasumsikan.** Salah titik mulai berarti terlambat lapor; ini dipastikan ke sumber resmi di Day 18.

## 3. Lab praktik (di VM lab terisolasi)

Lab ini memakai VM Windows dengan Sysmon dan EDR lab (atau log ke Splunk), satu VM yang berperan file server, dan Atomic Red Team yang sudah ada di lab pribadi. Jangan memakai sampel ransomware sungguhan; enkripsi disimulasikan dengan skrip yang menyalin lalu mengganti ekstensi file dummy buatan sendiri di folder uji. Semua di VM lab dengan snapshot, terputus dari jaringan produksi. Jangan memakai data, nama, atau kejadian dari pekerjaan nyata.

1. **Buat sinyal sebelum enkripsi.** Di VM Windows, jalankan tes Atomic Red Team untuk T1490 (penghapusan shadow copy, `bcdedit`) dan penghentian layanan, yang semuanya hanya menyentuh VM lab. Catat event apa yang muncul di EDR atau Sysmon dan di index Splunk.
2. **Perburuan multi-sinyal.** Sesuaikan query bagian 2.1 dengan field lab-mu. Pastikan VM uji muncul karena menunjukkan lebih dari satu jenis sinyal. Ubah ambang `JumlahJenis` dan amati bedanya.
3. **Simulasi enkripsi share.** Buat folder share `Keuangan-lab` berisi file dummy. Jalankan skrip buatan sendiri yang menyalin tiap file lalu mengganti ekstensi menjadi `.lck` dan menaruh `BACA-INI.txt`, dijalankan dari VM kedua lewat SMB. Aktifkan audit object access, lalu jalankan query bagian 2.2 untuk menemukan VM sumber. Pastikan `Source_Address` benar.
4. **Backup dan restore.** Buat dua backup folder itu: satu "online" yang bisa dicapai VM sumber, satu "offline" yang kamu putus sebelum simulasi. Jalankan simulasi, lalu pulihkan hanya dari salinan offline ke folder bersih. Catat berapa banyak perubahan yang hilang dan buktikan tidak ada `.lck` tersisa.
5. **Gerbang validasi.** Tulis daftar periksa gerbang validasi dengan format Day 06 bagian 2.4 untuk restore folder itu, termasuk pemindaian malware dan pengecekan sisa `.lck` dan catatan tebusan.
6. **Memo dan pelaporan.** Tulis memo keputusan tebusan (format bagian 2.3) dan catatan pelaporan (format bagian 2.4) untuk skenario lab, dengan minimal satu alasan penolakan membayar.

**Hasil yang sebaiknya tersimpan:**

- `latihan/day14-hunt.md` berisi query multi-sinyal yang sudah disesuaikan dan hasilnya pada VM uji.
- Cuplikan hasil query sumber enkripsi yang menunjukkan `Source_Address` benar.
- Catatan berapa perubahan hilang saat restore dari salinan offline, dan bukti folder bersih.
- `latihan/day14-memo.md` berisi memo keputusan tebusan dan catatan pelaporan.

**Variasi tantangan:** matikan EDR di VM sumber dan ulangi; bagaimana kamu masih bisa menemukan sinyal sebelum enkripsi tanpa EDR (Sysmon, log OS, log share)? Ini meniru `jkt-dmz-app01` yang tanpa EDR.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat merespons ransomware. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Enkripsi berlanjut walau host diisolasi dari jaringan | Proses enkripsi berjalan lokal di host | Isolasi menahan penyebaran, bukan proses lokal; hentikan proses setelah bukti, atau matikan sebagai jalan terakhir [S1] |
| Backup online ikut terenkripsi atau terhapus | Backup tersambung terus ke jaringan dan dicapai penyerang | Pulihkan dari salinan offline atau immutable; jadikan backup offline standar [S2] |
| Restore memunculkan kembali infeksi | Backup sudah tertular sebelum ketahuan, atau direstore ke host belum bersih | Scan backup sebelum restore; restore hanya ke sistem yang sudah dibangun ulang bersih [S1][S2] |
| Host sumber tidak muncul di perburuan EDR | Host tanpa EDR (server lama, DMZ) | Cari di Sysmon, log OS, dan log share; tutup celah cakupan EDR |
| Sumber koneksi SMB penulis file tidak diketahui | Audit object access (event 5145) tidak aktif di file server | Aktifkan audit share dan file system; sementara pakai EDR di host sumber |
| Penyerang muncul lagi beberapa hari setelah pulih | Jalan masuk awal tidak ditutup | Telusuri mundur ke akses awal sebelum menyatakan selesai; tutup kerentanan dan rotasi kredensial [S1][S5] |
| Tim ingin cepat menyalakan semua layanan | Tekanan bisnis mengalahkan urutan pemulihan | Pulihkan menurut prioritas layanan lewat gerbang validasi; jangan tambah sistem belum tervalidasi ke VLAN pemulihan [S1] |
| Catatan tebusan mengklaim data dicuri, belum tahu benar atau tidak | Klaim belum tentu benar | Cari bukti transfer keluar di log; nilai dengan tingkat keyakinan, jangan menyangkal atau memastikan tanpa bukti [S9] |

## 5. Kesalahan umum dan jebakan

- Menganggap alert enkripsi sebagai awal insiden. Operator sering sudah di dalam berhari-hari; telusuri mundur ke akses awal [S5][S9].
- Mematikan host yang terenkripsi sebagai refleks pertama. Itu menghapus memori dan bukti; isolasi jaringan lebih dulu, matikan hanya bila tak ada cara lain [S1].
- Rebuild host lalu menyatakan selesai tanpa menutup jalan masuk. Mengundang gelombang kedua [S1][S5].
- Mengandalkan backup online yang tersambung terus ke jaringan. Backup itu yang pertama diincar; butuh salinan offline atau immutable [S2][S8].
- Restore langsung ke produksi tanpa memindai backup dan tanpa host bersih. Bisa menulari ulang [S1][S2].
- Menganggap data hanya dikunci, bukan dicuri, tanpa memeriksa log keluar. Melewatkan double extortion dan kewajiban pelaporan [S1][S2].
- Membiarkan IC atau technical lead memutuskan membayar. Itu keputusan executive sponsor bersama Legal [S1].
- Menyimpulkan harus membayar tanpa mengecek decryptor publik atau dari penegak hukum [S1].
- Mengabaikan sinyal sebelum enkripsi yang berprioritas rendah (AV tamper, `vssadmin delete`). Itu jendela deteksi terakhir [S6].
- Menunda pencatatan untuk pelaporan sampai akhir. Fakta bertanggal dan bukti harus dikumpulkan sejak awal [S2].

## 6. Catatan terkini

Bagian ini menampung detail yang bisa berubah dan tidak mengubah cara merespons.

- **CISA #StopRansomware Guide** yang dipakai adalah edisi September 2023, produk bersama CISA, FBI, NSA, dan MS-ISAC. Part 2 berisi checklist respons ransomware dan pemerasan data, termasuk daftar perburuan ancaman [S1]. Cek halaman CISA untuk edisi terbaru.
- **NCSC UK Mitigating malware and ransomware attacks** terbit 13 Februari 2020, direview versi 3.0 pada 9 September 2021, dimodifikasi 28 Juli 2026 [S2]. NCSC juga punya panduan terpisah Recovering from a highly disruptive cyber attack.
- **MITRE ATT&CK** yang dipakai v20: T1486 Data Encrypted for Impact dan T1490 Inhibit System Recovery, keduanya dimodifikasi 12 Mei 2026 [S3][S4]. Nomor teknik stabil; detail analitik deteksi bisa bertambah.
- **Microsoft Incident Response ransomware approach** (ms.date 2024-10-16) menyarankan, untuk kasus kompromi domain, reset krbtgt dua kali dengan proses yang dapat diulang; ini relevan hanya bila domain dikuasai (Day 12), bukan untuk ransomware yang terbatas di beberapa host [S5].
- **Microsoft Defender XDR, Find ransomware with advanced hunting** (ms.date 2026-07-02) memuat query konsolidasi yang menimbang banyak sinyal; query di bagian 2.1 adalah versi ringkas yang diadaptasi, bukan salinan [S6].
- **NIST IR 8374** sudah Rev. 1 (Juni 2026), profil CSF 2.0 untuk ransomware; versi lama (Februari 2022) memakai CSF 1.1 dan sudah ditarik [S7].
- **Statistik** Sophos State of Ransomware 2025 (survei 3.400 organisasi) dan kasus The DFIR Report adalah pembanding, bukan dasar keputusan; angka berubah tiap tahun [S8][S9].

## 7. Cheat sheet

```
RANSOMWARE = tahap akhir operasi manusia (akses awal -> lateral -> persiapan -> enkripsi)
  alert enkripsi = UJUNG, bukan awal; telusuri MUNDUR ke jalan masuk

SINYAL SEBELUM ENKRIPSI (jendela deteksi terakhir):
  matikan AV/layanan: taskkill, net stop, sc config disabled
  hapus pemulihan (T1490): vssadmin delete shadows, wmic shadowcopy delete,
    wbadmin delete catalog, bcdedit recoveryenabled no
  hapus bukti: wevtutil cl, cipher /w, fsutil usn deletejournal
  (sering) exfil sebelum enkripsi -> double extortion
  enkripsi (T1486): ledakan tulis ekstensi aneh + catatan tebusan

URUTAN (kerusakan berjalan -> beda dari insiden sunyi):
  1 tahan host yang mengenkripsi SEKARANG (isolasi jaringan, JANGAN matikan dulu)
  2 scoping + bukti menyusul; telusuri ke akses awal
  3 tutup jalan masuk + rotasi kredensial yang terpapar (krbtgt hanya bila domain, Day 12)
  4 pulihkan dari backup OFFLINE/IMMUTABLE yang sudah dipindai, ke host bersih
  5 gerbang validasi -> produksi -> pantau

BACKUP: offline/immutable, terpisah, diuji restore, versioning, lindungi akun backup
  online saja = diincar duluan (NCSC, Sophos)

BAYAR atau TIDAK: keputusan executive sponsor + Legal, BUKAN IC
  cek decryptor publik / penegak hukum dulu (CISA); bayar tak jamin data kembali,
  tak hentikan ancaman publikasi data yang sudah dicuri (NCSC)

DATA DICURI? cek log keluar (transfer besar, rclone/FTP/web storage) -> pelaporan (Day 18)
  klaim catatan tebusan != bukti; nilai dengan tingkat keyakinan

DOMAIN DIKUASAI + sebar lewat GPO/PsExec dari DC -> ini kompromi domain (Day 12)
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Alert enkripsi di `JKT-FS01` baru berbunyi 21:32, jadi penyerang baru masuk malam itu." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Ransomware yang dijalankan manusia biasanya sudah berjalan berhari-hari sebelum enkripsi: akses awal, pencurian kredensial, gerakan lateral, lalu persiapan enkripsi. Di `INC-2026-017`, investigasi mundur menemukan akses awal Rabu 2026-10-07 lewat `jkt-dmz-app01`. Alert enkripsi adalah ujung rantai, bukan awal; membersihkan host terenkripsi tanpa menutup jalan masuk mengundang gelombang kedua. Lihat bagian 1.1 dan 1.2.

</details>

**2. Skenario keputusan.** `JKT-FS01` sedang mengenkripsi file dengan cepat. Tindakan pertama yang paling tepat?

- A. Matikan `JKT-FS01` secepatnya supaya enkripsi berhenti.
- B. Isolasi `JKT-FS01` dari jaringan lewat EDR tanpa mematikannya, lalu segera cari dan tahan host sumber yang menulis lewat SMB.
- C. Tunggu scoping lengkap dulu supaya tidak salah menahan host yang keliru.

<details><summary>Jawaban</summary>

B. Kerusakan sedang berjalan, jadi penyebaran dihentikan dulu, tetapi isolasi jaringan lebih baik daripada mematikan karena mematikan menghapus memori dan bukti volatil. CISA menempatkan mematikan sebagai jalan terakhir. A membuang bukti memori. C keliru karena menunggu scope lengkap berarti membiarkan enkripsi berlanjut; di ransomware, containment mendahului scoping lengkap. Lihat bagian 1.4 dan 2.2.

</details>

**3. Pertanyaan jebakan.** "Kita punya backup harian ke `jkt-bkp-nas01`, jadi ransomware tidak masalah; tinggal restore." Benarkah?

<details><summary>Jawaban</summary>

Tidak selalu. Backup yang tersambung terus ke jaringan justru yang pertama diincar; di `INC-2026-017` penyerang menghapus backup online `JKT-FS01` di `jkt-bkp-nas01`. Yang menyelamatkan adalah salinan mingguan offline yang terpisah. NCSC menekankan backup offline karena backup online ikut terenkripsi di insiden nyata, dan Sophos mencatat pemulihan lewat backup di titik terendah enam tahun. Backup juga harus dipindai dan direstore ke host bersih. Lihat bagian 1.5 dan 2.2.

</details>

**4. Skenario keputusan.** Catatan tebusan mengklaim data dicuri. Backup offline bisa dipulihkan. Apa langkah yang tepat soal "membayar"?

- A. Tidak perlu memikirkan bayar sama sekali karena backup ada.
- B. Executive sponsor bersama Legal dan DPO memutuskan, dengan informasi backup, decryptor publik atau penegak hukum, risiko hukum, dan fakta bahwa membayar tidak menghentikan ancaman publikasi data yang sudah dicuri; keputusan dan alasannya dicatat.
- C. IC memutuskan membayar supaya data pelanggan tidak dipublikasi.

<details><summary>Jawaban</summary>

B. Membayar atau tidak adalah keputusan bisnis dan hukum, jadi pemiliknya executive sponsor bersama Legal, bukan IC. Walau backup ada, pilihan bayar tetap ditulis dengan alasan penolakannya supaya bisa dipertanggungjawabkan, dan decryptor publik atau dari penegak hukum dicek. A terlalu menyederhanakan karena ada sisi pencurian data. C salah pemilik keputusan, dan membayar tidak menghentikan ancaman publikasi karena data sudah di tangan penyerang. Lihat bagian 1.5, 1.6, dan 2.3.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Bambang Hartono (Manajer NOC), dalam tiga kalimat, kenapa menutup jalan masuk awal sama pentingnya dengan memulihkan file dari backup.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Penyerang yang mengenkripsi file sudah masuk lewat satu celah berhari-hari sebelumnya, biasanya lewat server lama yang menghadap internet, dan sering menyisakan kredensial curian serta akses cadangan. Kalau kita hanya memulihkan file dari backup tanpa menutup celah itu dan mengganti kredensial yang bocor, mereka bisa masuk lagi dan mengenkripsi ulang dalam beberapa hari. Jadi pemulihan file dan penutupan jalan masuk harus jalan bersama; file yang pulih di jaringan yang masih terbuka hanya menunggu gelombang kedua."

Kesalahan yang sering muncul:
- Memakai istilah seperti "lateral movement" atau "C2" yang tidak dibutuhkan Manajer NOC.
- Menggambarkan ransomware seperti virus yang menyebar sendiri, bukan operasi manusia.
- Tidak mengaitkan ke tindakan konkret (tutup celah, ganti kredensial) yang NOC bantu kerjakan.

</details>

**6. Pertanyaan jebakan.** "Semua file sudah dipulihkan dari backup dan layanan keuangan jalan lagi, jadi `INC-2026-017` selesai." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Pemulihan file bukan akhir insiden. Jalan masuk awal harus sudah ditutup dan kredensial yang terpapar dirotasi, pemulihan harus lewat gerbang validasi dan dipantau, dan sisi pencurian data pelanggan masih menimbulkan kewajiban pelaporan yang dinilai Legal dan DPO terlepas dari apakah file pulih. Insiden dinyatakan selesai berdasarkan kriteria yang ditetapkan, bukan karena layanan menyala. Lihat bagian 1.7, 2.2, dan 2.4.

</details>

**7. Interview question (English).** "Walk me through how you'd respond to a ransomware incident where a file server is being encrypted right now."

<details><summary>Sample answer</summary>

"First I treat the encryption alert as the end of the chain, not the start. Because damage is ongoing, I contain immediately: isolate the file server from the network through EDR without powering it off, so I keep memory and evidence, and I find the source host writing the files over SMB and isolate that too. Then I work backwards to the initial access, because ransomware operators are usually inside for days, and if I rebuild hosts without closing the entry point and rotating exposed credentials, they come back. For recovery I rely on offline or immutable backups, scanned and restored to clean rebuilt systems through a validation gate, in order of business priority, not straight to production. I check outbound logs for data theft, because if personal data was exfiltrated we have reporting obligations even if files are recoverable, and the decision to pay, which I'd advise against, belongs to the executive sponsor and legal, not to me. Finally I don't declare it over until the entry point is closed, recovery is validated and monitored, and the data-exposure question is answered."

What makes this answer strong: it contains the spread first because damage is live, works backwards to initial access, insists on offline backups and clean restore, separates the data-theft and reporting angle from file recovery, and puts the pay decision with the business rather than the responder.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | CISA: #StopRansomware Guide (ransomware guide) | https://www.cisa.gov/stopransomware/ransomware-guide | primer | Edisi September 2023; diakses 2026-10-15 | Tinggi. Part 2 checklist respons: isolasi, mematikan sebagai jalan terakhir, prioritas restore, periksa log tahap awal, konsultasi penegak hukum soal decryptor, daftar perburuan ancaman |
| S2 | NCSC UK: Mitigating malware and ransomware attacks | https://www.ncsc.gov.uk/guidance/mitigating-malware-and-ransomware-attacks | primer | Terbit 13 Feb 2020, direview v3.0 9 Sep 2021, dimodifikasi 28 Jul 2026; diakses 2026-10-15 | Tinggi. Backup offline, lindungi akun backup, scan sebelum restore, pembayaran tebusan, double extortion |
| S3 | MITRE ATT&CK: Data Encrypted for Impact (T1486) | https://attack.mitre.org/techniques/T1486/ | primer | ATT&CK v20, dimodifikasi 12 Mei 2026; diakses 2026-10-15 | Tinggi. Enkripsi untuk dampak; mitigasi M1053 Data Backup (off-system, versioning) |
| S4 | MITRE ATT&CK: Inhibit System Recovery (T1490) | https://attack.mitre.org/techniques/T1490/ | primer | ATT&CK v20, dimodifikasi 12 Mei 2026; diakses 2026-10-15 | Tinggi. vssadmin, wmic shadowcopy, wbadmin, bcdedit; mitigasi backup dan pembatasan utilitas |
| S5 | Microsoft Learn: Microsoft Incident Response ransomware approach and best practices | https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-dart-ransomware-approach | primer (dokumentasi vendor) | ms.date 2024-10-16; diakses 2026-10-15 | Tinggi. Operator mematikan AV dan menghapus backup; pertanyaan investigasi; containment (isolasi tanpa matikan, isolasi DC, krbtgt bila kompromi) |
| S6 | Microsoft Learn: Find ransomware with advanced hunting (Microsoft Defender XDR) | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-find-ransomware | primer (dokumentasi vendor) | ms.date 2026-07-02; diakses 2026-10-15 | Tinggi. Tabel sinyal persiapan dan query konsolidasi multi-sinyal; query bagian 2.1 adaptasi ringkas |
| S7 | NIST IR 8374 Rev. 1: Ransomware Risk Management, A Cybersecurity Framework 2.0 Community Profile | https://csrc.nist.gov/pubs/ir/8374/r1/final | primer | Juni 2026 (final 11 Jun 2026); diakses 2026-10-15 | Tinggi. Profil CSF 2.0 untuk ransomware; respons dan pemulihan; dasar playbook. Rev. lama (Feb 2022, CSF 1.1) ditarik |
| S8 | Sophos: The State of Ransomware 2025 | https://www.sophos.com/en-us/blog/the-state-of-ransomware-2025 | sekunder | 2025 (survei 3.400 organisasi); diakses 2026-10-15 | Sedang. Akar teknis terbanyak kerentanan dieksploitasi 32 persen; pemulihan backup titik terendah enam tahun; 49 persen membayar |
| S9 | The DFIR Report: Quantum Ransomware | https://thedfirreport.com/2022/04/25/quantum-ransomware/ | komunitas | April 2022; diakses 2026-10-15 | Sedang. TTR 3 jam 44 menit, akses awal IcedID lewat ISO, deploy via WMI dan PsExec, klaim pencurian tanpa eksfiltrasi teramati. Studi kasus, bukan statistik agregat |

**Catatan sumber:** rantai serangan `INC-2026-017` (waktu akses awal, exfil, host, akun, server backup) adalah contoh fiktif yang disusun agar konsisten dengan fakta Day 01, bukan kejadian nyata. Angka Sophos [S8] adalah hasil survei satu vendor dan dipakai sebagai pembanding, bukan dasar keputusan. Pembagian tujuh pertanyaan, urutan containment, dan daftar kriteria di catatan ini adalah susunan dari sumber yang disebut, bukan daftar resmi tunggal. Titik mulai hitungan 3 x 24 jam UU PDP Pasal 46 belum dipastikan dan dibahas di Day 18. Nama field event 5145 dan field KQL bergantung pada versi dan add-on; cek di lingkunganmu.
