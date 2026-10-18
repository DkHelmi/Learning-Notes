---
day: 04
title: 'Data untuk hunting: kebutuhan data dari hipotesis, inventaris, kualitas dan kesiapan, pemetaan ke ATT&CK, OSSEM dan DeTT&CT'
researched_on: 2026-10-18
versions_checked: 'MITRE ATT&CK v20.0 (13 Okt 2026; Data Components, Detection Strategies, Analytics sejak v18); Sysmon v15.22 (halaman Microsoft Learn 2026-09-10) dan Sysmon bawaan Windows 11 (Insider, Feb 2026); DeTT&CT v2.2.0 (dukungan model data ATT&CK v18; wiki data quality 0-5, visibility 0-4); OSSEM (OTRF, DD/CDM/DM); Splunk Enterprise 10.6 (SPL: tstats, metadata, _indextime, TZ di props.conf; dokumentasi 10.2/10.4); Wazuh 4.14 (alerts vs archives); Microsoft Defender XDR advanced hunting (30 hari, UTC); audit 4688 command line (Microsoft Learn); SANS 2026 (data hambatan utama)'
---

# Day 04: Data untuk hunting (inventaris, kualitas, peta ATT&CK, dan kesiapan data)

Cakupan: cara menurunkan kebutuhan data dari hipotesis, menginventaris sumber log, menilai kualitasnya (depth, scope, konfigurasi, waktu), memetakannya ke ATT&CK Data Components dengan bantuan OSSEM dan DeTT&CT, lalu memutuskan apakah sebuah hunt siap dijalankan dan celah data mana yang diperbaiki lebih dulu.

## Ide inti

Hunt hanya sebaik data yang diperiksanya. Sebuah sumber yang "ada" di SIEM belum tentu siap dipakai: bisa jadi hanya terpasang di sebagian host (scope), hanya mencatat sebagian jenis event (depth), field pentingnya kosong karena konfigurasi, timestamp-nya bergeser beberapa jam, atau datanya sudah terhapus sebelum rentang yang dibutuhkan hipotesis. Karena itu setiap hunt melewati satu gerbang sebelum dijalankan: kebutuhan data diturunkan dari hipotesis, dicocokkan dengan inventaris sumber, diukur kualitasnya, lalu diputuskan dalam satu kartu kesiapan (siap, siap sebagian dengan cakupan yang ditulis, atau tidak siap). Hasil gerbang yang "tidak siap" bukan kegagalan; itu celah visibilitas yang punya pemilik dan bisa diprioritaskan.

Kamu sudah mengenal ini dari NOC. Sebelum menyimpulkan "tidak ada trafik anomali di POP Medan" dari NetFlow, engineer yang teliti mengecek dulu apakah semua router di POP itu benar-benar mengirim NetFlow, apakah sampling rate-nya sama, dan apakah jam router sinkron dengan NTP. Grafik yang datar bisa berarti link sepi, bisa juga berarti collector berhenti menerima. Batas analoginya: di NOC, router yang berhenti mengirim biasanya memicu alarm dari sisi lain (SNMP, BGP, ping), sedangkan di SIEM sumber yang berhenti tidak menghasilkan error apa pun, hanya nol event. Selain itu, sumber yang ada belum tentu field-nya lengkap atau waktunya akurat, jadi keberadaan saja tidak pernah cukup.

```
 hipotesis (ABLE: Evidence)
          |
          v
 kebutuhan data: sumber, field, host, rentang, tanda behavior
          |
          v
 inventaris sumber  --->  cek kualitas:
 (index, sourcetype,       - depth (jenis event, field terisi?)
  host, retensi, pemilik)  - scope (berapa host dari seharusnya?)
                           - konfigurasi (filter, audit policy)
                           - waktu (retensi, latency, zona waktu)
          |
          v
 peta ATT&CK (sumber -> Data Component -> teknik)
          |
          v
 kartu kesiapan per hunt
   |              |                         |
  SIAP     SIAP SEBAGIAN               TIDAK SIAP
   |       (cakupan ditulis)           (celah visibilitas)
   v              v                         v
  hunt       hunt + "di luar cakupan"   perbaikan telemetri,
                                        prioritas, pemilik
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan. SOC PT JAB memakai Splunk Enterprise di search head `jkt-splunk-sh01`, dan sejak Senin 2027-02-01 menjalankan "Program hunt PT JAB" setiap Selasa dan Kamis, dipegang olehmu sebagai analyst L2. Hunt pertama, `HUNT-2027-001` (baseline parent-child dari Sysmon Event ID 1), selesai Kamis 2027-02-04 dengan hasil tidak ditemukan, dan laporannya menyebut celah besar: sekitar 60% workstation tidak punya Sysmon, sehingga berada di luar cakupan. Celah itu diserahkan ke tim Infrastruktur. Selasa 2027-02-09 pukul 09:00, Lead Infrastruktur Agung Prabowo membalas:

> "Laporan celah Sysmon dari HUNT-2027-001 sudah saya baca. Terus terang anggaran kuartal ini terbatas; saya cuma bisa memperluas satu hal, dan saya harus mempertanggungjawabkannya ke Pak Hendra. Sebelum saya ajukan, tolong jelaskan: sebenarnya data apa yang dibutuhkan hunt kalian? Apa saja yang sudah kita punya, dan mana yang sudah cukup sehingga tidak perlu diutak-atik? Bagaimana saya tahu sebuah sumber itu sehat: lengkap, konfigurasinya benar, jamnya benar, dan datanya cukup lama? Saya juga dengar retensi DNS dan proxy cuma 30 hari. Kalau hanya bisa satu, mana yang harus didahulukan: Sysmon ke workstation lain, atau retensi? Saya butuh alasan yang bisa diaudit, bukan daftar keinginan."

Pesan itu memuat tujuh pertanyaan:

1. Data apa yang dibutuhkan sebuah hunt, dan bagaimana menurunkannya dari hipotesis?
2. Sumber apa saja yang dimiliki PT JAB sekarang, dan bagaimana mencatatnya supaya bisa dipantau?
3. Bagaimana tahu sebuah sumber lengkap, baik dari jenis event maupun jumlah host?
4. Bagaimana tahu konfigurasinya benar?
5. Bagaimana tahu waktunya benar dan datanya tersimpan cukup lama?
6. Mana yang sudah cukup dan mana yang bolong, dilihat dari teknik serangan yang bisa diburu?
7. Bila hanya bisa memperbaiki satu hal, apa yang didahulukan dan kenapa?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, pertanyaan 6 di bagian 1.6 dan 1.7, dan pertanyaan 7 di bagian 1.8. Bagian 2 berisi pemeriksaan nyata atas data PT JAB: inventaris, feed yang diam, kelengkapan field, sebaran host, latency dan zona waktu, peta ATT&CK, kartu kesiapan untuk `HUNT-2027-001` sampai `HUNT-2027-004`, dan rekomendasi untuk Agung.

**Kapan relevan:** sebelum menjadwalkan hunt (cek Evidence dan cakupannya), saat menulis bagian "di luar cakupan" di laporan hunt, saat ada pihak yang harus memilih investasi telemetri, dan secara berkala (misalnya bulanan) untuk menangkap feed yang berhenti diam-diam.
**Kapan bukan jawaban:** saat insiden aktif dan pertanyaannya "data apa yang ada sekarang untuk host ini" (itu scoping IR, cukup cek langsung); saat sumbernya sudah kamu kenal betul dan baru diverifikasi minggu ini untuk hunt cepat; dan saat yang dibutuhkan sebenarnya rule baru atas data yang sudah lengkap (itu celah deteksi, bukan celah data).

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (threat hunting, hipotesis, abstract, stacking, PEAK, TaHiTI, HMM, handover, ABLE) tidak diulang. Kolom padanan memakai analogi NOC dan SOC yang sama dengan Day lain.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Data readiness (kesiapan data) | Keadaan di mana data yang dibutuhkan hipotesis ada, lengkap, benar konfigurasinya, tepat waktunya, dan masih tersimpan | Cek NetFlow/syslog benar-benar dikirim dari semua router sebelum menyimpulkan |
| Inventaris sumber data | Daftar sumber log dengan lokasi di SIEM, volume, host, retensi, pemilik, dan tanggal verifikasi | Inventaris perangkat yang mengirim syslog dan NetFlow ke collector |
| Depth | Berapa banyak jenis event dan field yang dihasilkan sebuah sumber | Router mengirim NetFlow saja, atau juga syslog, SNMP trap, dan BGP log |
| Scope | Berapa banyak aset dan user yang tercakup sebuah sumber | NetFlow aktif di 3 dari 20 router POP |
| Feed mati | Sumber yang berhenti mengirim tanpa error, sehingga terlihat seperti "tidak ada aktivitas" | Grafik MRTG datar nol karena poller berhenti, bukan karena link kosong |
| Latency (indexing lag) | Jeda antara waktu event terjadi (`_time`) dan waktu event masuk index (`_indextime`) | Jeda antara gangguan terjadi dan trap diterima NMS |
| Retensi | Berapa lama data tersimpan dan masih bisa dicari | Berapa lama data NetFlow disimpan collector |
| Celah visibilitas | Data yang dibutuhkan tidak ada, sehingga perilaku mustahil terlihat | Segmen tanpa NetFlow: tidak ada yang bisa dibaca |
| Celah deteksi | Data ada, tetapi belum ada rule yang memakainya | Counter tersedia, tetapi threshold alarm belum dibuat |
| Data Component | Objek ATT&CK yang menyebut properti atau nilai yang dibutuhkan untuk mendeteksi teknik, beserta log source konkretnya | Jenis counter yang dibutuhkan untuk mendiagnosis satu jenis gangguan |
| Detection Strategy / Analytic | Objek ATT&CK (sejak v18): pendekatan deteksi per teknik dan implementasinya per platform | Prosedur diagnosis per jenis gangguan, lalu versi per vendor perangkat |
| Mutable element | Bagian analytic ATT&CK yang memang harus disetel per lingkungan (ambang, jendela waktu, daftar proses) | Threshold yang disesuaikan per kapasitas link |
| OSSEM | Proyek komunitas OTRF untuk mendokumentasikan dan menstandarkan log keamanan (DD, CDM, DM) | Kamus format syslog per vendor dan skema normalisasinya |
| DeTT&CT | Alat Rabobank CDC untuk menilai kualitas data source (0-5) dan visibilitas per teknik (0-4), lalu membuat layer ATT&CK Navigator | Lembar penilaian kesehatan monitoring per POP |
| Kartu kesiapan data | Ringkasan satu halaman per hunt: data yang dibutuhkan, yang ada, kualitasnya, dan putusan | Checklist pra-maintenance: semua titik ukur sudah terpasang? |
| Tier sumber | Pengelompokan sumber menurut seberapa banyak teknik yang dibukanya dan seberapa mendesak bila hilang | Prioritas monitoring: core dulu, akses belakangan |

### 1.1 Dari Evidence ke kebutuhan data

Pertanyaan pertama Agung ("data apa yang sebenarnya dibutuhkan") tidak bisa dijawab dengan daftar sumber umum. Jawabannya selalu diturunkan dari hipotesis yang sedang dikerjakan.

Hipotesis di program ini ditulis dengan kerangka ABLE dari PEAK (Day 03 bagian 1.4): Actor (opsional), Behavior, Location, dan Evidence. Elemen Evidence menyatakan sumber data dan seperti apa aktivitasnya di sana. Survei SANS 2026 menempatkan data sebagai hambatan hunting nomor satu, di atas staf terampil [S6], dan kemampuan hunting sebuah tim sangat bergantung pada seberapa banyak log yang dikumpulkan dan seberapa bisa dipakai data itu [S1]. Jadi Evidence tidak boleh berhenti di nama sumber; ia diterjemahkan menjadi kebutuhan konkret.

Tabel berikut adalah lima pertanyaan penerjemah itu, diisi untuk `HUNT-2027-002` (unduhan lewat LOLBin, T1105). Baca kolom kanan sebagai daftar yang harus dibuktikan ada, bukan diasumsikan.

| Pertanyaan | Isi untuk `HUNT-2027-002` (LOLBin download, T1105) |
|---|---|
| Sumber apa? | Sysmon EID 1 (process creation) dan EID 3 (network connection) |
| Field apa yang wajib ada? | `Image`, `CommandLine`, `ParentImage`, `ProcessGuid` (EID 1); `DestinationIp`, `DestinationPort`, `ProcessGuid` (EID 3) |
| Host mana yang tercakup? | Workstation dan server Windows yang mengirim kedua event itu |
| Rentang berapa? | Minimal 14 sampai 30 hari supaya pemakaian rutin terlihat (Day 03) |
| Apa yang menandakan behavior? | Argumen URL http/https di command line LOLBin, lalu koneksi ke IP eksternal dari `ProcessGuid` yang sama |

Bila salah satu baris tidak terpenuhi, misalnya `CommandLine` tidak dicatat, hunt itu belum layak; perbaiki data dulu atau persempit cakupannya dan tulis yang tidak tercakup.

Dua hal sering terlewat di tahap ini:

- **Field korelasi.** Hipotesis yang menggabungkan dua event (proses lalu koneksi) butuh field penghubung. Di Sysmon itu `ProcessGuid`, yang dibuat unik per proses supaya korelasi tetap benar walaupun Windows memakai ulang Process ID [S7]. Tanpa field ini, korelasi berbasis `ProcessId` dan waktu bisa salah pasang.
- **Data pembanding.** Hampir setiap hunt butuh tahu "normal" seperti apa. Rentang 14 sampai 30 hari tadi bukan untuk mencari serangan selama 30 hari, tetapi supaya pemakaian sah (updater, skrip IT) terlihat berulang dan bisa dipisahkan dari yang langka.

Detection engineering juga menilai data, tetapi dari sudut yang lebih sempit: engineer memastikan satu rule tertentu punya field dan event yang dibutuhkannya. Hunter menilai kesiapan data secara luas, karena pertanyaan hunt berikutnya belum tentu diketahui hari ini. Karena itu Day ini membahas inventaris dan kualitas sumber secara umum dulu, lalu menurunkannya ke tiap hipotesis lewat kartu kesiapan (bagian 2.7).

### 1.2 Inventaris sumber data

Pertanyaan kedua Agung ("apa saja yang sudah kita punya") terdengar sederhana, tetapi di PT JAB belum ada satu dokumen yang menjawabnya. Daftar index di Splunk hanya menyebut nama; ia tidak menyebut host mana yang mengirim, siapa pemiliknya, atau kapan terakhir dicek.

Untuk setiap sumber, catat kolom berikut [S1][S5]. Baca kolom kanan untuk alasan tiap kolom ada.

| Kolom | Isi | Kenapa perlu |
|---|---|---|
| Sumber | Nama (Sysmon, Security, auditd, Zeek, DNS, firewall) | Identitas |
| Lokasi di SIEM | Index/sourcetype (Splunk), index pattern (OpenSearch) | Query yang benar |
| Volume harian | Perkiraan event per hari | Mendeteksi feed yang diam |
| Host | Jumlah host pengirim dibanding yang seharusnya | Scope (bagian 1.3) |
| Retensi | Berapa lama data tersimpan dan bisa dicari | Rentang hunt maksimal |
| Pemilik | Siapa yang mengelola sumber dan agennya | Tujuan handover celah data |
| Tanggal verifikasi terakhir | Kapan terakhir dipastikan sumber benar-benar mengirim | Kepercayaan pada hasil negatif |

Kolom tanggal verifikasi dan volume harian paling penting. Feed yang diam-diam berhenti (agent mati, pipeline putus) tidak menghasilkan error, hanya nol event, dan hunt di atasnya akan "tidak menemukan apa-apa" secara menyesatkan [S5].

Inventaris PT JAB yang disusun Selasa pagi itu memuat tiga kelompok sumber, dan pembagian ini penting untuk Agung karena tiap kelompok punya cara akses dan retensi berbeda:

- **Di Splunk** (bisa dikorelasikan dalam satu query): `wineventlog`, `sysmon`, `powershell`, `firewall`, `proxy`, `dns`, `vpn`, `linux` (`linux_secure`, `linux_audit`), `o365`, `netops`, `aws`, `azure`. Retensi `proxy` dan `dns` 30 hari; `o365` (termasuk log sign-in Entra) 1 tahun.
- **Di luar Splunk, bisa dicari:** Microsoft Defender for Endpoint (MDE) Plan 2 di server Windows dan workstation Jakarta serta Bandung, dengan pengecualian; data mentahnya dicari lewat advanced hunting di portal Defender dengan batas 30 hari [S22]. Wazuh 4.14 di `jkt-wazuh01` sebagai HIDS untuk empat server Linux tanpa EDR (`jkt-portal02`, `jkt-radius01`, `jkt-bastion01`, `jkt-billing02`), terpisah dari Splunk.
- **Tidak ada:** server Velociraptor permanen untuk mengumpulkan artefak host sesuai kebutuhan (server sementara yang dulu dibuat untuk satu kasus sudah dimatikan); EDR di server Linux selain `jkt-billing02`; Sysmon maupun EDR di enam laptop Bandung (termasuk `BDG-WS-0142`) dan di 23 workstation POP Surabaya dan Medan, karena MDE hanya di-onboard untuk workstation Jakarta dan Bandung.

Pembagian itu langsung menjawab sebagian pertanyaan Agung: hunt yang butuh korelasi lintas sumber paling murah dikerjakan di Splunk, MDE mengisi sebagian celah workstation tetapi hanya 30 hari dan di konsol terpisah, dan Wazuh hanya membantu untuk empat server. Inventaris lengkap dengan angka ada di bagian 2.1.

### 1.3 Kelengkapan: depth dan scope

Pertanyaan ketiga Agung ("bagaimana tahu sumber itu lengkap") punya dua sumbu, dan PT JAB lemah di sumbu yang berbeda untuk sumber yang berbeda.

Sebuah sumber dinilai pada dua sumbu [S4]:

- **Depth:** berapa banyak jenis event berbeda yang dihasilkan sumber. Sysmon dengan konfigurasi penuh (proses, network, registry, DNS) lebih dalam daripada Sysmon yang hanya mencatat proses.
- **Scope:** berapa banyak aset dan user yang tercakup. Sysmon di 2 dari 50 host punya scope rendah, betapapun dalamnya.

Sumber bisa "ada" tetapi lemah di salah satu sumbu. Hunt yang mengandalkan sumber dengan scope rendah menghasilkan kesimpulan yang hanya berlaku untuk sebagian kecil lingkungan; nyatakan cakupan nyata di laporan (Day 01 bagian 1.6).

Angka PT JAB memperlihatkan keduanya sekaligus. Sysmon dikirim dari sekitar 214 host: 61 server Windows dan 153 workstation di OU `Workstations-EDR` (di bawah OU Jakarta). Dari 382 workstation Windows aktif di Active Directory, itu sekitar 40%; seluruh workstation Bandung, Surabaya, dan Medan berada di luar OU itu. Itu masalah scope. Di dalam 214 host itu pun depth-nya tidak seragam: Event ID 1, 11, dan 13 datang dari 214 host, tetapi EID 3 (`NetworkConnect`) hanya dari 198 dan EID 22 (`DnsQuery`) hanya dari 186. Selisihnya adalah host dengan file konfigurasi yang tidak memuat tag itu. Jadi "Sysmon terpasang di 214 host" tidak sama dengan "hunt yang butuh EID 3 mencakup 214 host".

Dua kebiasaan yang membuat penilaian ini jujur:

- **Ukur scope terhadap inventaris aset, bukan terhadap log lain.** Membandingkan jumlah host Sysmon dengan jumlah host di log Windows hanya mengukur cakupan relatif terhadap sumber yang juga bisa bolong. Pembanding yang benar adalah daftar aset (Active Directory, CMDB) [S4].
- **Ukur depth di level field, bukan event.** Event ID 1 yang ada tetapi `CommandLine`-nya kosong tidak menolong hunt LOLBin. Kelengkapan field diukur dengan query di bagian 2.3.

### 1.4 Kualitas: ketepatan konfigurasi

Pertanyaan keempat Agung ("konfigurasinya benar?") paling sering diabaikan, karena sumber yang salah konfigurasi tetap terlihat sehat: event masuk, volume normal, tidak ada error.

Sumber yang ada belum tentu mencatat yang kamu butuhkan. Contoh klasik: log Security Windows adalah sumber hunting yang kuat, tetapi audit policy default membuat banyak event tidak tercatat dengan detail yang cukup, sehingga perlu dikonfigurasi ulang [S4]. Tiga contoh konkret yang paling sering menjatuhkan hunt ada di tabel berikut; baca kolom kanan, karena di situlah hunt gagal tanpa terlihat gagal.

| Sumber | Yang harus dikonfigurasi | Akibat bila tidak |
|---|---|---|
| Security 4688 (process creation) | Dua setting GPO: `Audit Process Creation` di `Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Detailed Tracking`, dan `Include command line in process creation events` di `Administrative Templates > System > Audit Process Creation` [S8] | Tanpa yang pertama, 4688 tidak muncul sama sekali. Tanpa yang kedua, 4688 muncul tetapi field `Process Command Line` kosong, sehingga hunt LOLBin tidak bisa membedakan pemakaian wajar dan unduhan |
| Sysmon | File konfigurasi XML dengan filter `include`/`exclude` per event; EID 3 (NetworkConnect) nonaktif secara default, EID 7 (ImageLoad) juga harus dinyalakan eksplisit [S7] | Konfigurasi komunitas yang populer sering meng-exclude proses yang dianggap bising; bila proses yang kamu buru masuk daftar exclude, event-nya tidak pernah tercatat. Aturan `exclude` menang atas `include` [S7] |
| auditd (Linux) | Rule audit, misalnya rule syscall `execve` untuk mencatat setiap eksekusi beserta argumennya, dan rule watch (`-w`) untuk file sensitif | Tanpa rule `execve`, auditd hanya mencatat event bawaan (login, perubahan konfigurasi audit) dan eksekusi proses tidak terlihat |

Perhatian: setting command line di 4688 membuat argumen proses tersimpan dalam teks biasa, termasuk password yang kebetulan diketik di command line. Batasi siapa yang bisa membaca log Security [S8].

Di PT JAB, empat temuan konfigurasi langsung relevan untuk empat hunt yang sudah berjalan:

- **GPO audit hanya di satu OU.** GPO `JAB-WS-Audit` (audit process creation dengan command line, dan subkategori `Audit Other Object Access Events` yang menghasilkan 4698 saat scheduled task dibuat [S26]) hanya ditautkan ke OU `Workstations-EDR`. Pemeriksaan laporan GPO bersama tim Infrastruktur Selasa pagi memastikan kedua subkategori itu aktif di sana. Workstation di luar OU itu memakai audit bawaan, sehingga 4688 dengan command line dan 4698 tidak ada dari host tersebut. Server Windows memakai baseline audit server sendiri yang juga menghasilkan 4688 dan 4698. Sejak Windows 10 versi 1903, event 4698 juga membawa `ClientProcessId` dan `ParentProcessId` [S26]; field itu hanya angka PID, jadi untuk tahu nama proses pembuat task tetap dibutuhkan Sysmon EID 1 atau 4688 dari host yang sama.
- **Tiga profil Sysmon.** Workstation memakai profil lengkap. Enam belas server (domain controller, file server, dan server database) memakai profil ringan tanpa `NetworkConnect` dan `DnsQuery` karena volumenya dulu dianggap terlalu besar. Dua belas server lain masih memakai profil lama yang dibuat sebelum `DnsQuery` ditambahkan. Itulah asal angka 198 dan 186 di bagian 1.3 (214 dikurangi 16, lalu dikurangi 12 lagi).
- **Wazuh hanya menyimpan alerts.** Wazuh membedakan alerts (event yang cocok dengan rule) dan archives (semua event yang diterima server, cocok atau tidak dengan rule). Archives nonaktif secara default karena menyimpan log tanpa batas dan memakan disk besar; untuk bisa dicari di dashboard, archives harus diaktifkan dalam format JSON (`logall_json`) dan dikirim ke index `wazuh-archives-*` [S24]. Di `jkt-wazuh01` archives belum aktif, jadi hunting atas event mentah empat server Linux itu belum mungkin; yang bisa dicari hanya event yang sudah memicu rule.
- **Log DNS hanya mencatat pertanyaan.** Index `dns` berisi query log BIND dari resolver `jkt-res01`, `jkt-res02`, `bdg-res01`, dan `sby-res01`. Pengukuran di bagian 2.3 menunjukkan field kode jawaban kosong di semua event, sehingga analisis rasio NXDOMAIN tidak bisa dijalankan dari sourcetype ini.

Cek konfigurasi terhadap kebutuhan hunt, bukan hanya keberadaan sumber. Pertanyaannya: "Apakah field yang dibutuhkan hipotesis benar-benar terisi di event nyata?" Jawab dengan melihat event mentah dan mengukur persentasenya, bukan mengasumsikan dari dokumen konfigurasi. Untuk Sysmon, konfigurasi yang benar-benar berjalan di sebuah host bisa ditampilkan dengan `sysmon -c` tanpa argumen [S7], dan setiap perubahan konfigurasi tercatat sebagai Event ID 16 [S7].

### 1.5 Kualitas: waktu (retensi, latency, dan zona waktu)

Pertanyaan kelima Agung punya dua bagian: "jamnya benar?" dan "datanya cukup lama?". Keduanya urusan waktu, dan keduanya bisa membuat hunt salah tanpa terlihat salah.

Hunting historis membutuhkan data yang cukup lama tersimpan; hunting mendekati real-time membutuhkan data yang cepat masuk. Tiga hal yang dipantau:

- **Retensi:** apakah rentang yang dibutuhkan hipotesis (misalnya 30 hari) masih ada dan bisa dicari. Data yang sudah di-archive atau roll off tidak bisa diburu. Di PT JAB, `proxy` dan `dns` 30 hari, advanced hunting MDE juga 30 hari untuk data Defender [S22], sedangkan `o365` 1 tahun. Artinya baseline "domain yang pertama kali terlihat" atau hunt retro atas indikator lama hanya bisa mundur 30 hari di dua sumber jaringan terpenting. Retensi juga diverifikasi, bukan dibaca dari konfigurasi: pada Kamis 2027-02-04, event tertua di index `dns` bertanggal 2027-01-05 02:14, cocok dengan 30 hari.
- **Latency:** seberapa cepat event muncul di SIEM setelah terjadi. Sumber cloud sering terlambat beberapa menit sampai jam. Akibatnya, query yang mencari "15 menit terakhir" bisa melewatkan event yang sudah terjadi tetapi belum masuk; event itu juga tidak tertangkap oleh jalannya query berikutnya karena waktunya sudah di luar jendela. Untuk hunt yang dijadwalkan berulang, geser jendela ke belakang sebesar latency yang diukur (misalnya `earliest=-75m latest=-15m`) dan buat jendela saling tumpang tindih bila perlu. Ukur latency dengan membandingkan `_indextime` dan `_time` di Splunk. Field `_time` memuat timestamp event dalam UNIX time dan disimpan dalam UTC; `_indextime` memuat waktu event di-index, dan field itu tersembunyi di hasil search kecuali dipakai di `eval` atau di-rename [S20].
- **Zona waktu dan jam sumber:** timestamp bisa bergeser bila sumber menulis jam lokal tanpa zona waktu. Splunk menentukan zona waktu dengan urutan prioritas: zona waktu di data mentah (misalnya `-0800`), lalu atribut `TZ` di `props.conf` untuk host, source, atau sourcetype itu, lalu zona waktu yang dikirim forwarder, terakhir zona waktu sistem operasi indexer [S21]. Perangkat yang menulis jam WIB tanpa offset, diindex oleh indexer ber-zona UTC, akan tercatat tujuh jam lebih lambat dari kenyataan. Di Windows, Sysmon menulis field `UtcTime` dalam UTC [S7], dan advanced hunting MDE memakai UTC untuk semua data sehingga query harus ditulis dalam UTC [S22]. Selisih tujuh jam saat membandingkan `UtcTime` dengan tampilan Splunk ber-zona WIB adalah normal, bukan kesalahan.

Sumber hunting yang dipakai di catatan ini tidak menetapkan ambang latency baku untuk hunting [S1]; praktik yang konkret adalah mencatat tanggal verifikasi terakhir dan volume harian per sumber untuk menangkap feed yang berhenti [S5], ditambah pengukuran latency berkala seperti di bagian 2.5.

Kenapa ini penting untuk Agung: retensi adalah keputusan biaya penyimpanan, sedangkan latency dan zona waktu biasanya keputusan konfigurasi yang murah. Memisahkan keduanya mencegah perbaikan murah ikut menunggu anggaran.

### 1.6 Memetakan sumber ke ATT&CK: Data Component, Detection Strategy, Analytic

Pertanyaan keenam Agung ("mana yang sudah cukup dan mana yang bolong") butuh bahasa yang sama antara SOC dan Infrastruktur. Bahasa itu adalah peta sumber ke teknik ATT&CK: untuk melihat apa yang bisa dan tidak bisa kamu buru, petakan tiap sumber ke teknik atau taktik yang didukungnya, lalu visualisasikan sebagai heat map [S2][S3].

**Model deteksi ATT&CK sejak v18.** Rilis Oktober 2025 (v18) men-deprecate objek Data Source di ketiga domain (38 di Enterprise), merevisi Data Components ke versi 2.0, dan mengganti bagian deteksi di halaman teknik dengan objek baru Detection Strategy dan Analytic [S13]. Versi yang berlaku per Oktober 2026 adalah ATT&CK v20.0, dirilis 13 Oktober 2026 [S12]. Model deteksinya kini berlapis [S9]; tabel berikut merangkum lapisannya, dan kolom contoh perlu dibaca dari bawah ke atas untuk hunting.

| Lapisan | Arti | Contoh |
|---|---|---|
| Detection Strategy (`DET####`) | Pendekatan tingkat tinggi untuk mendeteksi satu teknik; wadah bagi beberapa analytic | `DET0400` Behavioral Detection of DNS Tunneling and Application Layer Abuse, untuk T1071.004 [S14] |
| Analytic (`AN####`) | Implementasi per platform (Windows, Linux, macOS, cloud) dari strategi itu | `AN1121` untuk Windows: query DNS frekuensi tinggi atau anomali dari proses non-browser dan non-sistem [S14] |
| Data Component (`DC####`) | Properti atau nilai yang dibutuhkan untuk mendeteksi teknik | `DC0032 Process Creation`, `DC0064 Command Execution`, `DC0082 Network Connection Creation` |
| Log source (nama dan channel) | Log konkret yang menyediakan Data Component itu | `WinEventLog:Sysmon` channel `EventCode=1`; `WinEventLog:Security` channel `EventCode=4688`; `auditd:SYSCALL` |

Untuk hunting, baca tabel ini dari bawah ke atas: mulai dari log yang kamu punya, cari Data Component yang dipenuhinya, lalu teknik yang analytic-nya membutuhkan Data Component itu. Halaman setiap Data Component mendaftar log source yang dianggap memenuhinya; misalnya `Process Creation` mencantumkan Sysmon EID 1, Security 4688, `auditd:EXECVE`, dan sumber EDR atau osquery [S9], termasuk `m365:defender` untuk data Defender [S9]. Dokumentasi lama (sebelum v18) masih menyebut "Data Source: Process" dengan komponen di bawahnya; kenali bentuk itu bila membaca laporan lama, tetapi pakai Data Component untuk pemetaan baru.

**Contoh lengkap satu analytic.** `AN1121` (Windows) di bawah `DET0400` membutuhkan dua Data Component: `Network Connection Creation` (DC0082) dari `WinEventLog:Sysmon` channel `EventCode=3, 22`, dan `Network Traffic Content` (DC0085) dari `NSM:Flow` channel `dns.log` [S14]. Analytic itu juga punya mutable elements, yaitu bagian yang memang harus disetel per lingkungan: `QueryLengthThreshold` (panjang subdomain yang dianggap mencurigakan), `ProcessImageFilter` (proses yang tidak lazim melakukan query DNS), dan `TimeWindow` (jendela hitung laju query per proses) [S14]. Untuk PT JAB, artinya analytic ini hanya bisa dijalankan penuh di 186 host yang mengirim EID 22, dan tiga angka itu harus ditentukan dari baseline PT JAB sendiri, bukan disalin.

**Dua jebakan pemetaan DNS.** Pertama, Sysmon EID 22 tidak tercantum di Data Component `Active DNS` (DC0103); komponen itu mengacu ke data resolusi DNS dari sisi server atau jaringan, bukan query per proses, dan di v20.0 log source yang dicantumkannya hanya "Domain Name" [S9]. EID 22 masuk lewat DC0082 bersama EID 3 [S16]. Kedua, log query resolver (seperti index `dns` PT JAB) dan `dns.log` Zeek dicantumkan di bawah `Network Traffic Content` (DC0085), misalnya dengan nama `NSM:DNS` dan `dns:querylog` [S9]. Log proxy juga tercantum di DC0082 lewat `NSM:Firewall` [S16].

**Celah visibilitas dan celah deteksi.** Baris peta tanpa sumber adalah blind spot: teknik relevan yang tidak bisa dilihat. Catat sebagai celah visibilitas (data tidak ada sehingga behavior mustahil terlihat), bukan celah deteksi (data ada tetapi belum ada rule). Perbaikannya berbeda: celah visibilitas butuh telemetri baru dan biasanya anggaran, celah deteksi cukup rule baru dan biasanya cukup waktu analyst. Yang dibawa ke Agung hanya celah visibilitas.

### 1.7 OSSEM dan DeTT&CT: kamus field dan skor yang bisa dibandingkan

Pemetaan di bagian 1.6 masih menyisakan dua pertanyaan Agung: "field apa yang dimaksud?" dan "seberapa baik, dalam angka?". Dua alat komunitas menjawabnya.

**OSSEM (Open Source Security Events Metadata).** Proyek komunitas OTRF untuk mendokumentasikan, menstandarkan, dan memodelkan log keamanan, mencakup Windows, Linux, macOS, Azure, dan AWS [S2][S10]. Tiga bagiannya:

- **Data Dictionaries (DD):** satu dokumen per jenis event, dikelompokkan per OS dan penyedia data, berisi nama field dan artinya. Berguna sebagai wiki data internal: saat kamu ragu apa isi `ParentCommandLine` atau field mana yang memuat user di 4688, kamus inilah tempat jawabannya dicatat.
- **Common Data Model (CDM):** skema standar untuk menormalisasi log dari banyak sumber ke nama field yang sama (misalnya `process_command_line` untuk Sysmon EID 1 dan 4688), sehingga satu query bisa mencakup keduanya. Perannya mirip CIM di Splunk atau ECS di Elastic.
- **Detection Model (DM):** memetakan hubungan antar event dalam bentuk "objek, relasi, objek", misalnya "process created process" atau "process connected to ip". Relasi ini membantu menjawab: behavior yang ingin kuburu terdiri dari relasi apa, dan event mana yang mencatat relasi itu.

Untuk PT JAB, nilai OSSEM ada di DD dan DM. DM membantu menjelaskan ke Agung kenapa hunt LOLBin butuh dua event ("process created process" dan "process connected to ip"), bukan satu. Repo OSSEM tidak menyatakan status pemeliharaannya secara eksplisit [S10], jadi pakai sebagai rujukan struktur, bukan sebagai skema yang dijamin mengikuti ATT&CK terbaru.

**DeTT&CT (Detect Tactics, Techniques & Combat Threats).** Alat dari Rabobank CDC yang memakai file YAML administrasi untuk mencatat data source, kualitasnya, lalu visibilitas dan deteksi per teknik, dan menghasilkan layer untuk ATT&CK Navigator [S2][S11]. Versi 2.2.0 menambahkan dukungan model data ATT&CK v18: karena data component kini terhubung ke teknik lewat analytic dan detection strategy, DeTT&CT memetakan data component ke teknik melalui jalur itu supaya skor visibilitas per teknik tetap bisa dihitung [S17]. Kualitas tiap data source dinilai 0-5 pada lima dimensi [S11]; tabel berikut meringkas skalanya, dan kolom kanan dipakai saat mengisi inventaris.

| Dimensi | Pertanyaan | Skor 1 / 3 / 5 (ringkas) |
|---|---|---|
| Device completeness | Apakah data ada dari semua perangkat yang perlu dicakup? | 1-25% / 51-75% / 100% perangkat |
| Data field completeness | Apakah field yang dibutuhkan ada dan terisi? | 1-25% / 51-75% / 100% field |
| Timeliness | Seberapa cepat data tersedia dan seakurat apa timestamp-nya? | jeda lama / jeda kecil / langsung dan akurat |
| Consistency | Seberapa standar nama dan tipe field sehingga bisa dikorelasikan? | 1-50% / 51-99% / 100% field terstandar |
| Retention | Berapa lama data disimpan dibanding periode yang diinginkan? | 1-25% / 51-75% / 100% periode |

Skor 0 berarti tidak diketahui, tidak terdokumentasi, atau tidak berlaku. Untuk device completeness, field completeness, dan retention, skor 2 dan 4 mengisi rentang di antaranya (26-50% dan 76-99%); untuk timeliness dan consistency, wiki tidak mendefinisikan skor 2 dan 4, jadi pilih yang paling dekat dan tulis alasannya [S11]. Visibilitas per teknik dinilai terpisah 0-4: 0 tidak ada, 1 minimal (satu aspek prosedur terlihat), 2 sedang (beberapa aspek), 3 baik (hampir semua aspek yang diketahui), 4 sangat baik (semua aspek) [S11].

Lima dimensi ini memetakan langsung ke bagian 1.3 sampai 1.5: device completeness adalah scope, data field completeness adalah depth dan ketepatan konfigurasi, timeliness dan retention adalah dimensi waktu. Dengan memakai skala DeTT&CT di inventaris manual pun, penilaianmu bisa dibandingkan antar waktu. Contoh PT JAB: Sysmon untuk workstation mendapat device completeness 2 (153 dari 382, sekitar 40%), sedangkan retensi `dns` mendapat skor 2 bila periode yang diinginkan 90 hari (30 dari 90 hari, sekitar 33%). Angka seperti ini yang bisa diaudit Hendra, karena perubahan setelah investasi bisa diukur ulang dengan skala yang sama.

### 1.8 Tier sumber dan cara memilih satu perbaikan

Pertanyaan terakhir Agung paling sulit: bila hanya satu yang bisa diperbaiki, mana? Tanpa kerangka, jawabannya mudah menjadi selera.

Salah satu metode menilai sumber berdasarkan jumlah teknik ATT&CK yang dicakup dibagi perkiraan biaya ingestion bulanan [S3]. Metode yang sama menyarankan memeriksa sekumpulan sumber tier satu lebih dulu, dan menjadikan sumber tier satu yang hilang prioritas perbaikan tanpa memandang biaya [S3]. Untuk lab Splunk + Wazuh + Sysmon, prioritas realistisnya ada di tabel berikut; kolom kanan adalah alasan tier-nya.

| Tier | Sumber | Teknik yang dibuka |
|---|---|---|
| 1 | Sysmon (proses, network, registry, DNS, image load), Security (logon, akun, task, service) | Mayoritas teknik endpoint Windows |
| 1 | auditd / Sysmon for Linux | Eksekusi dan perubahan file Linux |
| 2 | PowerShell 4104, DNS resolver, Zeek (jaringan) | Script, tunneling, C2 |
| 3 | Proxy/web, cloud identity, email | Exfiltration, phishing (sering tidak ada di lab) |

Sumber tier 1 yang tidak ada adalah prioritas perbaikan tanpa memandang biaya [S3]. Sumber tier 3 yang tidak ada di lab dicatat sebagai batas lingkup lab (banyak hipotesis cloud/email tidak bisa diuji di lab, Day 03). Di organisasi seperti PT JAB, proxy, DNS, dan identitas cloud sudah ada; tier-nya bergeser karena proxy dan DNS adalah sumber utama untuk C2, sehingga yang menjadi pertanyaan bukan "ada atau tidak", tetapi retensinya.

Untuk memilih satu perbaikan, pakai empat pertanyaan berurutan. Urutan ini disusun dari bagian 1.1 sampai 1.7, bukan standar resmi:

1. **Tier berapa celahnya?** Celah tier 1 didahulukan.
2. **Berapa hunt di backlog yang berubah putusannya?** Perbaikan yang mengubah banyak kartu dari "siap sebagian" menjadi "siap" lebih bernilai daripada yang mengubah satu.
3. **Berapa skor DeTT&CT naik?** Naik dari 2 ke 4 atau 5 di device completeness lebih terukur daripada janji "visibilitas lebih baik".
4. **Apakah ada jalan murah yang setara?** Perubahan konfigurasi (menautkan GPO, memperbaiki `TZ`, memisahkan subset data ke index lain) tidak perlu menunggu anggaran dan tidak boleh menghabiskan jatah "satu hal".

Penerapan empat pertanyaan itu ke pilihan Agung (Sysmon ke workstation lain atau retensi DNS dan proxy) ada di bagian 2.8.

## 2. Contoh dan langkah praktis: kesiapan data PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Query menilai keberadaan dan kualitas data, bukan memburu ancaman. Query ditulis untuk Splunk PT JAB (`jkt-splunk-sh01`, role `jab_hunter`) dengan zona waktu tampilan WIB; untuk latihan, jalankan versi yang disesuaikan di lab pribadi (bagian 3). Rentang standar bagian ini adalah tujuh hari, Senin 2027-02-01 00:00 sampai Senin 2027-02-08 00:00 WIB, dikerjakan Selasa 2027-02-09.

### 2.1 Inventaris otomatis di Splunk

Query ini menjawab pertanyaan kedua Agung dengan angka: semua index dan sourcetype, volume, jumlah host, dan kapan event terakhir masuk.

**Tujuan:** mendapat inventaris sumber per sourcetype untuk satu minggu, lengkap dengan volume harian dan kesegaran.

**Asumsi data:** role `jab_hunter` bisa membaca semua index non-internal. `index`, `sourcetype`, `host`, dan `_time` adalah field yang di-index, sehingga bisa dipakai `tstats` tanpa data model (klausa WHERE `tstats` hanya boleh memuat field yang di-index [S19]).

```
| tstats count AS events dc(host) AS hosts max(_time) AS last_event
    WHERE index=* earliest="02/01/2027:00:00:00" latest="02/08/2027:00:00:00"
    BY index sourcetype
| eval per_day=round(events/7,0)
| eval end=strptime("02/08/2027:00:00:00", "%m/%d/%Y:%H:%M:%S")
| eval silent_h=round((end-last_event)/3600,1)
| eval last_event=strftime(last_event, "%Y-%m-%d %H:%M")
| fields index sourcetype events per_day hosts last_event silent_h
| sort index sourcetype
```

Tabel berikut menjelaskan tiap baris query.

| Baris | Fungsi |
|---|---|
| `tstats count ... dc(host) ... max(_time)` | Menghitung event, host unik, dan event terakhir langsung dari index (tsidx), jauh lebih cepat daripada `stats` atas raw event |
| `WHERE index=* earliest=... latest=...` | Semua index non-internal, rentang absolut tujuh hari supaya inventaris bisa diulang dan dibandingkan minggu depan |
| `BY index sourcetype` | Satu baris per sumber |
| `eval per_day=round(events/7,0)` | Volume harian rata-rata, untuk dibandingkan dengan inventaris minggu lalu |
| `eval end=strptime(...)` lalu `silent_h` | Berapa jam sumber diam sebelum akhir rentang. Dihitung terhadap akhir rentang, bukan `now()`, supaya hasil tidak berubah saat query diulang |
| `strftime(last_event, ...)` | Mengubah epoch menjadi tanggal yang bisa dibaca, dalam zona waktu user (WIB) |

Keluaran ilustrasi:

```
index       sourcetype                 events         per_day      hosts  last_event        silent_h
aws         aws:cloudtrail             2.118.442      302.635      1      2027-02-07 23:52  0.1
dns         isc:bind:query             109.618.441    15.659.777   4      2027-02-07 23:59  0.0
firewall    pan:traffic                412.775.903    58.967.986   6      2027-02-07 23:59  0.0
linux       linux_audit                22.640.177     3.234.311    6      2027-02-07 23:59  0.0
linux       linux_secure               9.881.205      1.411.601    37     2027-02-07 23:59  0.0
netops      cisco:ios                  5.336.104      762.301      412    2027-02-07 23:59  0.0
o365        azure:monitor:aad          1.083.127      154.732      1      2027-02-07 23:41  0.3
o365        o365:management:activity   14.372.660     2.053.237    1      2027-02-07 23:22  0.6
powershell  XmlWinEventLog             3.106.540      443.791      214    2027-02-07 23:59  0.0
proxy       squid:access               63.845.411     9.120.773    3      2027-02-07 23:59  0.0
sysmon      XmlWinEventLog             61.874.112     8.839.159    214    2027-02-07 23:59  0.0
vpn         pan:globalprotect          1.204.388      172.055      2      2027-02-07 23:58  0.0
wineventlog XmlWinEventLog             88.402.517     12.628.931   443    2027-02-07 23:59  0.0
```

**Cara membaca hasil:**

- Tidak ada sourcetype yang diam. Itu belum berarti semua host sehat: satu host yang berhenti tidak menggeser `last_event` sebuah sourcetype yang dikirim ratusan host. Pengecekan per host ada di bagian 2.2.
- Kolom `hosts` sudah memperlihatkan scope: `sysmon` dan `powershell` dari 214 host, `wineventlog` dari 443 host (382 workstation dan 61 server). Selisih 229 adalah workstation tanpa Sysmon. `linux_audit` hanya dari 6 host, sedangkan `linux_secure` dari 37: hanya enam server Linux yang punya rule auditd untuk eksekusi.
- `dns` sekitar 15,7 juta event per hari dari empat resolver. Resolver PT JAB juga melayani pelanggan broadband, sehingga query dari jaringan kantor (`10.10.0.0/16`, `10.20.0.0/16`, `10.30.0.0/16`) hanya sebagian kecil (sekitar seperlima pada sampel bagian 2.3 dan 2.5). Fakta ini penting untuk opsi retensi di bagian 2.8.
- Untuk input cloud seperti `o365` dan `aws`, kolom `hosts` berisi collector, bukan jumlah tenant atau user, jadi jangan dibaca sebagai scope.
- Event terakhir `o365` 38 menit sebelum akhir rentang bukan feed mati; sumber cloud memang terlambat masuk (bagian 2.5).

**Variasi:** `metadata` memberi ringkasan per host tanpa memindai event, berguna untuk cek cepat harian:

```
| metadata type=hosts index=sysmon
| eval silent_h=round((now()-lastTime)/3600,1)
| eval index_lag_s=recentTime-lastTime
| where silent_h > 24
| sort - silent_h
```

`metadata` menghasilkan `firstTime`, `lastTime`, `recentTime` (waktu index terakhir), dan `totalCount` per nilai [S18]. Rentang waktunya diatur lewat Time Range Picker karena `earliest` dan `latest` tidak bisa ditulis di string search, dan hasilnya tidak presisi untuk rentang selain All Time: metadata disimpan per bucket, jadi bucket yang melintasi batas rentang ikut dihitung penuh [S18]. Di lingkungan dengan sangat banyak nilai, hasilnya juga bisa tidak lengkap secara sengaja [S18]. Karena itu `metadata` cocok untuk "siapa yang diam hari ini" (memakai `now()` memang disengaja), sedangkan `tstats` dengan rentang absolut dipakai untuk inventaris yang dilaporkan.

**Kapan gagal:** role yang menjalankan query tidak punya akses ke semua index, sehingga sebuah sumber terlihat "tidak ada" padahal hanya tersembunyi dari role itu; sebuah sourcetype yang nol event dalam rentang tidak muncul sebagai baris sama sekali, jadi sumber yang hilang hanya terlihat bila dibandingkan dengan inventaris minggu sebelumnya; dan `strptime` memakai zona waktu user, sehingga `silent_h` bergeser bila profil user tidak di WIB.

### 2.2 Feed mati atau host mati: cek per host

Langkah ini melanjutkan bagian 2.1 ke level host. Untuk laporan cakupan, yang dibutuhkan Agung dan Dimas adalah daftar host yang Sysmon-nya berhenti, bukan kesimpulan umum "Sysmon sehat".

**Tujuan:** menemukan host yang berhenti mengirim Sysmon lebih dari 24 jam, lalu membedakan "host mati atau offline" dari "Sysmon mati di host yang hidup".

**Asumsi data:** nama `host` sama di `sysmon` dan `wineventlog` karena keduanya dikirim forwarder yang sama.

```
| tstats max(_time) AS last_seen
    WHERE index IN (sysmon, wineventlog) earliest="02/01/2027:00:00:00" latest="02/08/2027:00:00:00"
    BY host index
| eval src=if(index="sysmon", "last_sysmon", "last_winevt")
| xyseries host src last_seen
| where isnotnull(last_sysmon)
| eval end=strptime("02/08/2027:00:00:00", "%m/%d/%Y:%H:%M:%S")
| eval sysmon_silent_h=round((end-last_sysmon)/3600,1)
| eval winevt_silent_h=round((end-last_winevt)/3600,1)
| where sysmon_silent_h > 24
| eval status=case(isnull(last_winevt), "tidak ada log Windows",
                   winevt_silent_h > 24, "host diam",
                   true(), "Sysmon diam, host aktif")
| eval last_sysmon=strftime(last_sysmon, "%Y-%m-%d %H:%M"), last_winevt=strftime(last_winevt, "%Y-%m-%d %H:%M")
| table host last_sysmon last_winevt sysmon_silent_h winevt_silent_h status
| sort - sysmon_silent_h
```

Tabel berikut menjelaskan bagian query yang paling menentukan hasil.

| Bagian | Fungsi |
|---|---|
| `index IN (sysmon, wineventlog)` | Dua index dalam satu `tstats`; operator `IN` dipakai di klausa WHERE `tstats` |
| `xyseries host src last_seen` | Mengubah dua baris per host menjadi satu baris dengan kolom `last_sysmon` dan `last_winevt` |
| `where isnotnull(last_sysmon)` | Hanya host yang pernah mengirim Sysmon dalam rentang; host tanpa Sysmon sama sekali adalah urusan scope (bagian 2.4) |
| `case(isnull(last_winevt), ...)` | Ditaruh pertama supaya host tanpa log Windows tidak salah dilabel "host aktif" |
| `winevt_silent_h > 24` | Bila log Windows juga diam, kemungkinan besar host mati, dibawa pulang, atau cuti |

Keluaran ilustrasi:

```
host         last_sysmon       last_winevt       sysmon_silent_h  winevt_silent_h  status
JKT-WS-0538  2027-02-01 17:02  2027-02-01 17:05  151.0            150.9            host diam
JKT-WS-0532  2027-02-02 10:14  2027-02-07 23:58  133.8            0.0              Sysmon diam, host aktif
JKT-WS-0448  2027-02-05 18:12  2027-02-05 18:13  53.8             53.8             host diam
```

**Cara membaca hasil:**

- `JKT-WS-0538` dan `JKT-WS-0448` diam di kedua sumber pada waktu yang hampir sama. Pola ini cocok dengan laptop yang dimatikan (cuti, dinas luar); cukup dicatat, tidak perlu tiket.
- `JKT-WS-0532` berbeda: log Windows masih masuk sampai Minggu malam, tetapi Sysmon berhenti Selasa 2027-02-02 pukul 10:14. Ini feed mati yang sesungguhnya. Pivot pertama adalah Event ID 4 Sysmon (perubahan status layanan) di host itu [S7]; bila layanan berhenti dengan normal, event "stopped" biasanya tercatat sebelum diam. Pengecekan bersama tim Infrastruktur menemukan layanan Sysmon tidak berjalan lagi setelah pembaruan Windows pagi itu.
- Dampaknya ke laporan hunt: setiap hunt di backlog yang rentangnya mencakup waktu setelah Selasa 2027-02-02 10:14 harus menulis `JKT-WS-0532` di luar cakupan untuk periode itu. `HUNT-2027-001` (25 Januari sampai 1 Februari) tidak terdampak.

**Variasi:** ganti `sysmon` dengan `linux` dan `wineventlog` dengan sumber detak lain dari host yang sama untuk server Linux, atau jalankan versi `metadata` di bagian 2.1 sebagai scheduled search harian yang mengirim daftar host diam ke tim Infrastruktur.

**Kapan gagal:** nama host berbeda format antar sumber (FQDN di satu index, nama pendek di index lain), sehingga `xyseries` menghasilkan dua baris yang tidak bertemu; host yang baru dipasang di tengah rentang terlihat normal walaupun separuh minggu tanpa data; dan host yang diam sepanjang rentang tidak muncul sama sekali karena `max(_time)` hanya ada untuk host yang pernah mengirim. Untuk yang terakhir, bandingkan dengan daftar aset (bagian 2.4).

### 2.3 Kelengkapan field (depth)

Query ini mengukur bagian "field terisi?" dari pertanyaan keempat Agung untuk sumber terpenting hunt proses, lalu untuk DNS.

**Tujuan:** mengukur berapa persen event Sysmon EID 1 yang punya `CommandLine`, `ParentImage`, dan `ProcessGuid`.

```
index=sysmon sourcetype=XmlWinEventLog EventCode=1
    earliest="02/01/2027:00:00:00" latest="02/08/2027:00:00:00"
| eval has_cmdline=if(isnotnull(CommandLine) AND CommandLine!="", 1, 0)
| eval has_parent=if(isnotnull(ParentImage) AND ParentImage!="", 1, 0)
| eval has_guid=if(isnotnull(ProcessGuid) AND ProcessGuid!="", 1, 0)
| stats count AS total sum(has_cmdline) AS with_cmdline sum(has_parent) AS with_parent sum(has_guid) AS with_guid
| eval pct_cmdline=round(with_cmdline/total*100,2)
| eval pct_parent=round(with_parent/total*100,2)
| eval pct_guid=round(with_guid/total*100,2)
```

Tabel berikut menjelaskan bagian query yang paling menentukan hasil.

| Bagian | Fungsi |
|---|---|
| `if(isnotnull(X) AND X!="", 1, 0)` | Field dianggap terisi hanya bila ada dan tidak kosong; field yang ada tetapi string kosong sama tidak bergunanya |
| `sum(has_...)` | Jumlah event yang terisi |
| `round(.../total*100,2)` | Persentase dua desimal, supaya selisih kecil tetap terlihat |

Keluaran ilustrasi:

```
total      with_cmdline  with_parent  with_guid  pct_cmdline  pct_parent  pct_guid
6.904.218  6.904.218     6.902.115    6.904.218  100          99.97       100
```

**Cara membaca hasil:** `CommandLine` dan `ProcessGuid` lengkap. `ParentImage` kosong di 2.103 event (6.904.218 dikurangi 6.902.115), sekitar 0,03%. Pivot ke beberapa event itu menunjukkan proses yang induknya sudah keluar sebelum event dicatat, pola yang wajar dan terlalu kecil untuk mengubah putusan. Field yang sering kosong (misalnya di bawah 95%) berarti konfigurasi Sysmon atau add-on Splunk perlu diperbaiki sebelum hunt yang mengandalkannya [S4]. Nama field di sini mengikuti event mentah Sysmon; bila add-on menormalisasi ke nama lain (misalnya `process_guid`), cek nama yang benar di lingkunganmu.

**Variasi untuk DNS:** pertanyaan yang sama untuk index `dns`, dibatasi ke query dari jaringan kantor dan satu jam saja karena volumenya:

```
index=dns sourcetype=isc:bind:query earliest="02/08/2027:08:00:00" latest="02/08/2027:09:00:00"
    (src="10.10.*" OR src="10.20.*" OR src="10.30.*")
| eval has_query=if(isnotnull(query) AND query!="", 1, 0)
| eval has_reply=if(isnotnull(reply_code) AND reply_code!="", 1, 0)
| stats count AS total sum(has_query) AS with_query sum(has_reply) AS with_reply
```

Keluaran ilustrasi:

```
total    with_query  with_reply
186.402  186.402     0
```

`reply_code` kosong di semua event: log ini mencatat pertanyaan klien, tidak mencatat jawaban resolver. Akibatnya hunt DNS tunneling di PT JAB bisa memakai panjang subdomain, jumlah subdomain unik per domain, dan frekuensi, tetapi tidak bisa memakai rasio NXDOMAIN dari sumber ini. Itu harus tertulis di kartu kesiapan `HUNT-2027-003` (bagian 2.7). Nama field `query` dan `reply_code` bergantung pada add-on; cek di event mentah.

**Variasi cepat lain:** `| fieldsummary maxvals=0` setelah `| head 100000` memberi jumlah event per field untuk sampel, berguna untuk melihat field mana yang jarang terisi tanpa menulis `eval` satu per satu. Untuk Sysmon EID 3, cara ini memperlihatkan `DestinationHostname` hanya terisi di sekitar 61% event; Sysmon mengisinya lewat reverse DNS lookup (opsi `DnsLookup`, default aktif [S7]), yang sering gagal untuk IP eksternal. Hunt sebaiknya bertumpu pada `DestinationIp`.

**Kapan gagal:** field diekstrak dengan nama berbeda per sourcetype sehingga `isnotnull` selalu bernilai salah; sampel `head` hanya mengambil event terbaru dari beberapa host bising, sehingga persentase tidak mewakili seluruh host.

### 2.4 Scope: sebaran host terhadap inventaris aset

Query ini menjawab bagian "berapa host dari seharusnya" dari pertanyaan ketiga Agung, dengan pembanding yang benar: daftar aset, bukan log lain.

**Tujuan:** menghitung cakupan Sysmon per kota terhadap daftar workstation di Active Directory.

**Asumsi data:** lookup `jab_assets.csv` diekspor setiap malam dari Active Directory, dengan field `nt_host`, `category` (`workstation` atau `server`), `city`, dan `ou`.

```
| tstats count WHERE index=sysmon earliest="02/01/2027:00:00:00" latest="02/08/2027:00:00:00" BY host
| eval nt_host=upper(host), has_sysmon=1
| fields nt_host has_sysmon
| append
    [| inputlookup jab_assets.csv where category="workstation"
     | eval nt_host=upper(nt_host)
     | fields nt_host city ou]
| stats max(has_sysmon) AS has_sysmon values(city) AS city BY nt_host
| where isnotnull(city)
| fillnull value=0 has_sysmon
| stats count AS workstations sum(has_sysmon) AS with_sysmon BY city
| eval coverage_pct=round(with_sysmon/workstations*100,1)
```

Tabel berikut menjelaskan bagian query yang paling menentukan hasil.

| Bagian | Fungsi |
|---|---|
| `tstats ... BY host` lalu `has_sysmon=1` | Daftar host yang mengirim Sysmon dalam rentang |
| `append [ inputlookup ... ]` | Menambahkan daftar workstation dari AD sebagai baris terpisah |
| `upper(...)` | Menyamakan huruf nama host dari dua sumber |
| `stats max(has_sysmon) ... BY nt_host` | Menggabungkan dua baris per host; host di AD tanpa Sysmon mendapat nilai kosong |
| `where isnotnull(city)` | Membuang host Sysmon yang bukan workstation (server tidak ada di subset lookup ini) |
| `fillnull value=0 has_sysmon` | Workstation tanpa Sysmon dihitung nol |

Keluaran ilustrasi:

```
city      workstations  with_sysmon  coverage_pct
Bandung   58            0            0.0
Jakarta   301           153          50.8
Medan     10            0            0.0
Surabaya  13            0            0.0
```

**Cara membaca hasil:** 153 dari 382 workstation (sekitar 40%) mengirim Sysmon, semuanya di Jakarta. Bandung, Surabaya, dan Medan nol. Di Jakarta pun hanya separuh, karena 148 workstation Jakarta belum dipindah ke OU `Workstations-EDR`. Total workstation tanpa Sysmon 229 (58 + 148 + 10 + 13).

**Variasi: scope per jenis event.** Scope yang sama dihitung per Event ID, karena hunt berbeda butuh event berbeda:

```
index=sysmon EventCode IN (1, 3, 11, 13, 22)
    earliest="02/01/2027:00:00:00" latest="02/08/2027:00:00:00"
| stats dc(host) AS hosts BY EventCode
```

Keluaran ilustrasi:

```
EventCode  hosts
1          214
3          198
11         214
13         214
22         186
```

`EventCode` diekstrak saat search, bukan di-index, sehingga query ini memakai search biasa, bukan `tstats` [S19]. Ia memindai sekitar 62 juta event, jadi jalankan di luar jam sibuk. Angka 198 dan 186 cocok dengan tiga profil Sysmon di bagian 1.4.

**Jebakan event jarang:** menjalankan query serupa untuk `index=wineventlog EventCode IN (4688, 4698)` menghasilkan 4688 dari 214 host tetapi 4698 hanya dari 171 host. Itu bukan berarti 43 host tidak diaudit; scheduled task memang tidak dibuat di setiap host setiap minggu. Scope untuk event yang jarang diukur dari konfigurasi (GPO yang berlaku, profil Sysmon), bukan dari jumlah host yang kebetulan menghasilkan event.

**Kapan gagal:** lookup aset basi atau memuat komputer yang sudah tidak aktif, sehingga cakupan terlihat lebih rendah dari kenyataan; nama host di Splunk berbentuk FQDN sedangkan di lookup nama pendek.

### 2.5 Latency dan zona waktu

Pemeriksaan ini menjawab "jamnya benar?" dari pertanyaan kelima Agung. Satu jam data cukup untuk melihat pola.

**Tujuan:** mengukur jeda antara waktu event dan waktu index per sourcetype, sekaligus menangkap timestamp yang bergeser.

```
index IN (sysmon, wineventlog, firewall, proxy, dns, o365, netops)
    earliest="02/08/2027:08:00:00" latest="02/08/2027:09:00:00"
| eval lag_s=_indextime-_time
| stats count median(lag_s) AS p50_s perc95(lag_s) AS p95_s min(lag_s) AS min_s BY index sourcetype
| sort - p95_s
```

Tabel berikut menjelaskan bagian query yang paling menentukan hasil.

| Bagian | Fungsi |
|---|---|
| `eval lag_s=_indextime-_time` | Jeda dalam detik. `_indextime` tersembunyi di hasil search, tetapi bisa dipakai di `eval` [S20] |
| `median` dan `perc95` | Jeda tipikal dan jeda terburuk yang masih umum; rata-rata mudah menipu karena beberapa event sangat terlambat |
| `min(lag_s)` | Nilai negatif berarti `_time` lebih lambat dari waktu index, tanda timestamp bergeser ke masa depan |

Keluaran ilustrasi:

```
index        sourcetype                 count       p50_s   p95_s   min_s
o365         o365:management:activity   98.210      1.140   3.960   212
o365         azure:monitor:aad          6.874       420     1.020   95
proxy        squid:access               702.551     31      62      2
wineventlog  XmlWinEventLog             744.118     5       41      0
sysmon       XmlWinEventLog             512.304     4       38      0
netops       cisco:ios                  18.442      3       9       -25.204
dns          isc:bind:query             912.776     2       6       0
firewall     pan:traffic                3.104.877   1       5       0
```

**Cara membaca hasil:**

- `o365:management:activity` punya median 19 menit dan p95 66 menit. Hunt atau scheduled search atas data ini yang memakai jendela "satu jam terakhir" akan melewatkan banyak event. Geser jendela ke belakang minimal sebesar p95, atau cari berdasarkan waktu index (variasi di bawah).
- Sumber endpoint dan jaringan di bawah satu menit pada p95; cukup untuk hunting.
- `netops` terlihat sehat dari median dan p95, tetapi `min_s` -25.204 detik, kira-kira minus tujuh jam. Sebagian event tercatat tujuh jam di masa depan. Ini hanya terlihat karena kolom `min_s` ikut dihitung.

Drill-down ke host:

```
index=netops sourcetype=cisco:ios earliest="02/08/2027:08:00:00" latest="02/08/2027:09:00:00"
| eval lag_s=_indextime-_time
| where lag_s < -60
| stats count min(lag_s) AS min_s max(lag_s) AS max_s BY host
```

Keluaran ilustrasi (ringkas):

```
host          count  min_s    max_s
mdn-rtr01     212    -25.204  -25.196
mdn-rtr02     198    -25.203  -25.197
mdn-sw03      41     -25.201  -25.198
... (11 host lain, semuanya di POP Medan)
```

Empat belas perangkat POP Medan menulis jam WIB tanpa offset zona waktu, dan karena tidak ada `TZ` untuk host itu, Splunk memakai zona waktu yang lebih rendah prioritasnya (bagian 1.5). Perbaikannya murah: atribut `TZ = Asia/Jakarta` di `props.conf` untuk stanza host tersebut [S21], dikerjakan bersama NOC (Bambang Hartono) sebagai pemilik `netops`. Perbaikan hanya berlaku untuk data baru; data yang sudah terindex tetap bergeser, jadi query atas periode sebelum perbaikan perlu mengoreksi `_time` tujuh jam untuk host-host itu dan menuliskannya di laporan.

**Variasi:** cari berdasarkan waktu index dengan modifier `_index_earliest` dan `_index_latest`, sehingga event yang terlambat masuk tetap tertangkap oleh jalannya query berikutnya. Untuk MDE advanced hunting, ingat bahwa query ditulis dalam UTC [S22], tujuh jam di belakang WIB.

**Kapan gagal:** satu jam sampel jatuh di jam sepi sehingga p95 terlihat bagus; sumber yang mengirim batch harian tampak memiliki latency puluhan ribu detik padahal itu memang desainnya, jadi baca bersama cara pengirimannya; dan perangkat dengan jam yang melenceng karena NTP tidak berjalan menghasilkan pergeseran yang tidak bulat tujuh jam.

### 2.6 Peta cakupan ATT&CK PT JAB

Tabel ini adalah jawaban pertanyaan keenam Agung dalam satu halaman: sumber ke Data Component ke teknik, dengan scope nyata di PT JAB. Kolom scope dari bagian 2.1 sampai 2.4; pemetaan Data Component mengikuti halaman ATT&CK v20.0 [S9]. Baca kolom terakhir untuk menemukan bagian yang bolong.

| Sumber PT JAB | Data Component (ATT&CK v20.0) | Contoh teknik yang didukung | Scope nyata |
|---|---|---|---|
| Sysmon EID 1 / Security 4688 dengan command line | DC0032 Process Creation, DC0064 Command Execution | T1059, T1105, T1047, T1053.005 | 214 host (61 server, 153 workstation); 229 workstation tanpa keduanya |
| Sysmon EID 3 dan 22 | DC0082 Network Connection Creation (ATT&CK mencantumkan channel `EventCode=3, 22`) [S16] | T1071, T1571, T1071.004 | EID 3: 198 host; EID 22: 186 host |
| Index `dns` (query log BIND) | DC0085 Network Traffic Content | T1071.004, T1048 | Semua klien yang memakai resolver internal; tanpa nama proses, tanpa kode jawaban; 30 hari |
| Index `proxy`, `firewall` | DC0082 (proxy lewat `NSM:Firewall`) [S16] | T1071.001, T1105, T1048 | Semua lalu lintas web karyawan lewat Squid; tanpa nama proses; `proxy` 30 hari |
| Security 4698 | DC0001 Scheduled Job Creation (4698, 4699; juga TaskScheduler 106) [S15] | T1053.005 | 214 host; tidak ada di 229 workstation di luar OU |
| Sysmon EID 11 dan 13 | Komponen file dan registry (DC0039 File Creation, DC0063 Windows Registry Key Modification) | T1053.005 (jejak file dan registry task), T1547 | 214 host |
| PowerShell 4104 | DC0029 Script Execution (ATT&CK mencantumkan 4103 sampai 4106) | T1059.001 | 214 host |
| `linux_audit` (auditd `execve`) | DC0032 Process Creation (`auditd:EXECVE`, `auditd:SYSCALL`) | T1059.004 | 6 dari 37 server Linux |
| MDE advanced hunting (portal) | DC0032 (`m365:defender`) dan lainnya | Teknik endpoint Windows | Workstation Jakarta dan Bandung kecuali pengecualian; 30 hari; terpisah dari Splunk |
| Wazuh `jkt-wazuh01` | Alerts saja, bukan event mentah | Hanya pola yang sudah punya rule | 4 server Linux |

Blind spot yang muncul dari peta ini, semuanya celah visibilitas:

- Eksekusi proses di enam laptop Bandung tanpa EDR dan tanpa Sysmon (termasuk `BDG-WS-0142`) dan di 23 workstation POP Surabaya dan Medan: tidak ada sumber proses sama sekali.
- Eksekusi proses di 31 server Linux tanpa rule `execve` dan tanpa EDR.
- Query DNS per proses di 28 server Windows (profil Sysmon ringan dan lama).
- Workstation di luar OU `Workstations-EDR` untuk apa pun yang lebih tua dari 30 hari, karena satu-satunya sumber prosesnya (MDE) hanya menyimpan 30 hari.
- Keadaan host saat ini (autostart, file di disk) secara massal, karena tidak ada server Velociraptor permanen (dibahas di Day 09).
- Event mentah empat server Linux ber-Wazuh, karena archives belum aktif.

Yang tidak ada di daftar ini sama pentingnya: identitas cloud (sign-in Entra di `o365` 1 tahun) dan lalu lintas web karyawan (Squid) sudah tercakup, sehingga hipotesis di area itu dibatasi retensi, bukan ketiadaan data.

### 2.7 Kartu kesiapan untuk `HUNT-2027-001` sampai `HUNT-2027-004`

Kartu ini menerapkan gerbang dari Ide inti ke empat hunt yang sudah ada di program. Ia menilai data, bukan hasil hunt, sehingga berlaku apa pun status pengerjaan tiap hunt. Bagi Agung, kartu inilah bukti bahwa celah data mengubah apa yang bisa dikatakan SOC.

```
HUNT-2027-001  Baseline parent-child proses (Execution, TA0002)
Evidence butuh : Sysmon EID 1 (ParentImage, Image, CommandLine, User)
Ada?           : ya; CommandLine 100%, ParentImage 99,97% (bagian 2.3)
Scope          : 153 dari 382 workstation (40%); di luar: 229 workstation
Waktu          : retensi sysmon cukup untuk 7 hari; latency p95 38 detik
Jalur lain     : MDE advanced hunting untuk workstation Jakarta/Bandung tanpa Sysmon (30 hari, UTC)
Putusan        : SIAP SEBAGIAN. Hasil berlaku untuk workstation ber-Sysmon saja
Celah/pemilik  : scope Sysmon workstation -> Infrastruktur (Agung)

HUNT-2027-002  Unduhan lewat LOLBin (T1105)
Evidence butuh : Sysmon EID 1 (Image, CommandLine, ProcessGuid) + EID 3 (DestinationIp, ProcessGuid)
Ada?           : EID 1 di 214 host; EID 3 di 198 host
Scope          : workstation ber-Sysmon lengkap (153); 16 server tanpa EID 3
Waktu          : rentang 18 Jan sampai 1 Feb tidak terdampak JKT-WS-0532 (Sysmon diam sejak 2027-02-02 10:14);
                 pengulangan setelah tanggal itu wajib mengecualikannya
Jalur lain     : proxy (URL per IP sumber, tanpa nama proses), 30 hari
Putusan        : SIAP SEBAGIAN. Server profil ringan dan 229 workstation di luar cakupan
Celah/pemilik  : profil Sysmon server ringan -> Infrastruktur; scope workstation -> Infrastruktur

HUNT-2027-003  DNS tunneling (T1071.004, T1048)
Evidence butuh : log DNS (query, panjang subdomain, frekuensi, tipe record) + atribusi proses
Ada?           : index dns ya (query saja, reply_code 0%); Sysmon EID 22 di 186 host
Scope          : dns: semua klien resolver internal; EID 22: 186 host
Waktu          : dns 30 hari (event tertua 2027-01-05 02:14 saat dicek 4 Feb); rentang 28 hari
                 7 Jan sampai 4 Feb masih muat, baseline domain langka maksimal 30 hari
Jalur lain     : firewall untuk DNS keluar langsung yang tidak lewat resolver internal
Batas          : tanpa rasio NXDOMAIN; host tanpa EID 22 hanya terlihat sebagai IP; DoH tidak terlihat
Putusan        : SIAP SEBAGIAN. Deteksi pola bisa; atribusi proses hanya di 186 host
Celah/pemilik  : retensi dns, profil Sysmon server -> Infrastruktur; log jawaban resolver -> NOC

HUNT-2027-004  Scheduled task oleh parent atau user tidak lazim (T1053.005)
Evidence butuh : 4698 (isi task, akun) dan/atau Sysmon EID 1 (schtasks.exe), 11, 13 (file dan registry task)
Ada?           : 4698 dan Sysmon di 214 host (OU Workstations-EDR dan server); subkategori
                 Audit Other Object Access Events terverifikasi aktif di JAB-WS-Audit (9 Feb)
Field          : 4698 memuat TaskName, TaskContent, ParentProcessId (PID saja);
                 nama parent dari Sysmon EID 1 / 4688 di host yang sama
Scope          : 229 workstation di luar OU tanpa 4698 dan tanpa Sysmon (GPO JAB-WS-Audit hanya di OU itu)
Jalur lain     : MDE advanced hunting untuk workstation Jakarta dan Bandung di antara 229 itu;
                 6 laptop Bandung dan 23 workstation POP tanpa sumber apa pun
Putusan        : SIAP SEBAGIAN. Hasil Splunk berlaku untuk 214 host
Celah/pemilik  : tautan GPO audit dan scope Sysmon -> Infrastruktur; 29 workstation tanpa EDR -> Infrastruktur dan SOC lead
```

Cara membaca kartu:

- **Putusan tiga nilai.** "SIAP SEBAGIAN" bukan kompromi; ia memaksa baris "di luar cakupan" yang sama persis masuk ke laporan hunt (Day 01 bagian 1.6). Hunt berstatus TIDAK SIAP tidak dijadwalkan; ia menjadi masukan perbaikan telemetri.
- **Jalur lain** menyelamatkan sebagian cakupan tanpa menunggu investasi, tetapi dengan harga: konsol terpisah, 30 hari, dan korelasi manual dengan Splunk.
- **Pola berulang.** Keempat kartu menyebut scope workstation di luar OU `Workstations-EDR`. Pola inilah yang menjadi dasar rekomendasi di bagian 2.8.

**Kapan gagal:** kartu diisi dari dokumen konfigurasi, bukan dari pengukuran di bagian 2.2 sampai 2.5; atau kartu ditulis sekali dan tidak diperbarui, padahal feed seperti Sysmon `JKT-WS-0532` bisa berhenti kapan saja.

### 2.8 Rekomendasi untuk Agung

Bagian ini adalah jawaban pertanyaan ketujuh: satu prioritas, dengan alasan yang bisa diaudit. Empat pertanyaan di bagian 1.8 diterapkan ke empat opsi yang realistis. Tabel berikut membandingkannya; baca kolom "Kartu berubah" dan "Skor DeTT&CT", karena dua kolom itulah yang bisa diukur ulang setelah perbaikan.

| Opsi | Tier celah | Kartu berubah | Skor DeTT&CT | Biaya dan risiko |
|---|---|---|---|---|
| A. Sysmon profil workstation lengkap (termasuk `NetworkConnect` dan `DnsQuery`) ke 229 workstation lain | 1 | -001, -002, -004 menjadi SIAP untuk workstation; -003 mendapat atribusi proses | Device completeness workstation dari 2 ke 4 atau 5 | Ingest sekitar 4,8 GB per hari (rata-rata 21 MB per workstation per hari dari pemakaian lisensi Januari); rollout bertahap |
| B. Retensi `dns` dan `proxy` dari 30 ke 90 hari | 2 | -003 lebih kuat (baseline lebih panjang); hunt beaconing dan first-seen di backlog | Retention dari 2 ke 5 | Penyimpanan tiga kali lipat untuk `dns` (sekitar 15,7 juta event per hari, mayoritas query pelanggan); tidak menambah host yang terlihat |
| C. Server Velociraptor permanen | 1 untuk keadaan host | Tidak mengubah kartu yang ada; membuka hunt keadaan host | Tidak ada di skala data source | Server, agent, dan pemeliharaan; dibahas di Day 09 |
| D. Aktifkan archives Wazuh | 1 untuk 4 server Linux | Tidak mengubah kartu yang ada | Field completeness Wazuh naik untuk 4 server | Disk `jkt-wazuh01`; hanya 4 server |

Rekomendasi yang dikirim Selasa sore:

1. **Satu hal yang memakai anggaran kuartal ini: opsi A.** Alasannya: celah tier 1, satu-satunya opsi yang mengubah keempat kartu, dan menutup lokasi insiden yang nyata (laptop Bandung pada `INC-2026-026` menghubungi server C2 73 kali tanpa alert). Rollout dua tahap supaya volume dan kestabilan diukur per tahap, dimulai dari host yang hari ini paling buta: tahap pertama Bandung, Surabaya, dan Medan (81 workstation, termasuk 29 yang hari ini tanpa sumber proses apa pun), tahap kedua sisa Jakarta (148, yang sementara masih punya MDE). Setiap tahap diukur ulang dengan query bagian 2.2 dan 2.4.
2. **Perubahan konfigurasi tanpa anggaran besar, diajukan sebagai change biasa:** menautkan GPO audit `JAB-WS-Audit` ke OU workstation lain bersamaan dengan rollout Sysmon (4688 dengan command line dan 4698 untuk 229 workstation); menyamakan profil Sysmon server agar `NetworkConnect` dan `DnsQuery` aktif dengan filter exclude yang sempit; memperbaiki `TZ` 14 perangkat POP Medan (bersama NOC); dan memulihkan Sysmon di `JKT-WS-0532`.
3. **Kandidat kuartal berikutnya: opsi B, dalam bentuk yang lebih murah.** Volume `dns` didominasi query pelanggan broadband. Query dari jaringan kantor (`10.10.0.0/16`, `10.20.0.0/16`, `10.30.0.0/16`) bisa diarahkan ke index terpisah dengan retensi lebih panjang, sehingga baseline hunt mendapat 90 hari tanpa menyimpan seluruh trafik pelanggan. Desain ini perlu dicek bersama NOC dan pemilik Splunk, terutama dampaknya ke search yang sudah memakai index `dns`.
4. **Bukan prioritas sekarang:** C dan D. Keduanya bernilai, tetapi cakupannya lebih sempit atau tidak mengubah hunt yang sudah ada di backlog.

Ringkasan untuk Agung dan Hendra dalam satu kalimat: memperluas Sysmon menaikkan cakupan workstation dari sekitar 40% ke target di atas 90% dan mengubah empat hunt dari "siap sebagian" menjadi "siap", sedangkan memperpanjang retensi hanya memperdalam pandangan atas host yang sudah terlihat.

**Kapan gagal:** rekomendasi menjanjikan cakupan 100% (laptop yang jarang tersambung akan selalu tertinggal; targetkan skor 4, bukan 5); biaya ingest dihitung dari rata-rata server, bukan workstation; atau tahap rollout tidak diukur, sehingga konfigurasi yang terlalu bising baru ketahuan saat lisensi terlampaui.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** Splunk dan Wazuh lab dengan Sysmon, Security, dan auditd; hipotesis ABLE dari Day 03. Gunakan data lab sendiri; PT JAB hanya contoh fiktif. Sesuaikan rentang absolut di setiap query dengan tanggal data lab-mu.

1. **Inventaris.** Jalankan query bagian 2.1 di Splunk. Buat `docs/data-inventory.md` dengan kolom bagian 1.2 untuk setiap sumber, termasuk volume, jumlah host, retensi, dan tanggal verifikasi.
2. **Feed mati.** Hentikan layanan Sysmon di satu VM Windows lab (snapshot dulu), biarkan beberapa jam, lalu jalankan query bagian 2.2. Pastikan VM itu muncul dengan status "Sysmon diam, host aktif", dan catat Event ID 4 Sysmon yang mendahuluinya. Nyalakan kembali dan ukur berapa lama sampai VM hilang dari daftar.
3. **Kelengkapan.** Jalankan bagian 2.3 untuk Sysmon EID 1. Catat persentase field kunci. Bila `CommandLine` di bawah 95%, periksa konfigurasi Sysmon: dump konfigurasi aktif (`sysmon -c` tanpa argumen menampilkan konfigurasi yang berjalan [S7]), cari blok `ProcessCreate onmatch="exclude"` yang terlalu luas, dan pastikan add-on di Splunk mengekstrak field dari format XML. Untuk 4688, cek dua setting GPO di bagian 1.4.
4. **Scope.** Buat lookup kecil berisi semua VM lab (termasuk yang sengaja tanpa Sysmon), lalu jalankan versi bagian 2.4. Catat cakupan Sysmon terhadap host Windows.
5. **Latency dan zona waktu.** Jalankan bagian 2.5. Lalu kirim syslog dari VM Linux dengan jam lokal tanpa offset ke Splunk yang zona waktunya berbeda, ukur `min_s`, perbaiki dengan `TZ` di `props.conf`, dan ukur ulang untuk event baru.
6. **Peta ATT&CK.** Isi tabel seperti bagian 2.6 untuk sumber lab-mu, memakai halaman Data Component ATT&CK versi terbaru. Tandai minimal tiga blind spot (teknik relevan tanpa sumber). Di lab, identitas cloud biasanya salah satunya (T1078.004).
7. **Kartu kesiapan.** Untuk tiga hipotesis Day 03, isi kartu dengan format bagian 2.7. Tandai mana yang SIAP, SIAP SEBAGIAN, dan TIDAK SIAP.
8. **Rekomendasi.** Tulis `docs/data-gaps.md`: untuk tiap celah, sumber yang perlu ditambahkan, teknik yang akan dibuka, kartu yang berubah, skor DeTT&CT sebelum dan sesudah, dan prioritasnya (tier 1 dulu), dengan format tabel bagian 2.8.

**Hasil yang sebaiknya tersimpan:**

- Inventaris sumber lengkap dengan volume, host, retensi, dan tanggal verifikasi.
- Bukti satu feed mati yang tertangkap query per host, dengan waktu deteksinya.
- Persentase kelengkapan field Sysmon EID 1 tercatat.
- Cakupan scope Sysmon terhadap daftar host lab tercatat.
- Latency per sourcetype dan satu contoh pergeseran zona waktu sebelum dan sesudah perbaikan.
- Peta sumber ke ATT&CK dengan minimal tiga blind spot.
- Kartu kesiapan untuk tiga hipotesis, dengan putusan tiga nilai.
- Rekomendasi telemetri berprioritas tertulis.

**Variasi tantangan:** pasang DeTT&CT (oleh kamu sendiri di mesin lab; versi 2.2.0 ke atas untuk model data ATT&CK v18 dan sesudahnya) dan isi file administrasi data source untuk lab-mu dengan skor lima dimensi bagian 1.7. Bangkitkan layer visibilitas, lalu bandingkan dengan peta manual langkah 6. Catat teknik yang kamu lewatkan di peta manual tetapi tertangkap DeTT&CT, dan sebaliknya.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat menilai kesiapan data. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Hunt "tidak menemukan apa-apa" mencurigakan | Feed sumber diam-diam berhenti | Cek `silent_h` per sourcetype dan per host (bagian 2.1, 2.2) [S5] |
| Satu host hilang tetapi sourcetype terlihat sehat | Agregasi per sourcetype menutupi host yang mati | Cek per host, bedakan host diam dan Sysmon diam (bagian 2.2) |
| Field kunci sering kosong | Konfigurasi Sysmon/audit policy | Cek filter exclude Sysmon dan dua setting GPO 4688 (bagian 1.4); ukur ulang (bagian 2.3) [S4] |
| Kesimpulan hunt terlalu luas | Scope sumber rendah | Ukur terhadap daftar aset (bagian 2.4); nyatakan cakupan nyata; perluas agent |
| Jumlah host per Event ID terlihat rendah | Event memang jarang (misalnya 4698) | Ukur scope dari konfigurasi, bukan dari event yang kebetulan muncul (bagian 2.4) |
| Event muncul di jam yang aneh atau `min_s` negatif | Sumber menulis jam lokal tanpa offset | Drill-down per host, set `TZ` di `props.conf` [S21] (bagian 2.5) |
| Scheduled search atas data cloud melewatkan event | Latency sumber cloud lebih besar dari jendela | Geser jendela sebesar p95 atau pakai `_index_earliest`/`_index_latest` (bagian 2.5) |
| Hasil `metadata` berbeda dari `tstats` | `metadata` bekerja per bucket dan bisa tidak lengkap | Pakai `tstats` dengan rentang absolut untuk laporan [S18] |
| Rentang data kurang | Retensi pendek | Perpanjang retensi untuk sumber hunting utama, atau pisahkan subset yang penting ke index berretensi panjang |
| Peta ATT&CK terasa menebak | Tidak memakai Data Component | Pakai ATT&CK Data Components atau OSSEM [S2] |
| Query MDE dan Splunk tidak cocok waktunya | MDE advanced hunting memakai UTC | Tulis query MDE dalam UTC, tampilan Splunk WIB [S22] |
| Banyak hipotesis tidak bisa diuji | Sumber tier 3 tidak ada | Normal untuk lab; catat sebagai batas lingkup |

## 5. Kesalahan umum dan jebakan

- **Menjalankan hunt sebelum memastikan Evidence ada.** Kartu kesiapan (bagian 2.7) adalah gerbang.
- **Menyamakan "sumber ada" dengan "sumber siap".** Periksa depth, scope, konfigurasi, dan waktu [S4].
- **Mengira nol hasil berarti bersih.** Bisa jadi feed mati [S5], atau host yang dicari tidak pernah mengirim sumber itu.
- **Mengukur scope terhadap log lain**, bukan terhadap daftar aset. Hasilnya cakupan relatif terhadap sumber yang juga bisa bolong.
- **Membaca latency hanya dari rata-rata atau median.** Pergeseran zona waktu di sebagian host hanya terlihat di nilai minimum (bagian 2.5).
- **Menulis rule untuk data yang tidak ada** alih-alih memperbaiki telemetri dulu. Rule seperti itu tidak pernah memicu dan memberi rasa aman palsu di peta cakupan.
- **Heat map cakupan tanpa Data Component**, sehingga pemetaan sumber ke teknik hanya tebakan [S2].
- **Memetakan Sysmon EID 22 ke `Active DNS`.** Di ATT&CK, EID 22 masuk lewat `Network Connection Creation` (DC0082) [S16]; `Active DNS` mengacu ke data resolusi dari sisi server atau jaringan [S9].
- **Menyalin mutable elements analytic ATT&CK apa adanya.** Ambang dan jendela waktu di analytic sengaja dibiarkan untuk disetel per lingkungan [S14].
- **Menghabiskan jatah anggaran untuk perbaikan yang sebenarnya hanya konfigurasi**, seperti menautkan GPO atau memperbaiki `TZ`.
- `[komunitas, belum terkonfirmasi]` Praktisi menyarankan memeriksa sekumpulan sumber tier satu lebih dulu dan menjadikan sumber tier satu yang hilang prioritas segera tanpa memandang biaya [S3]. Ini praktik yang masuk akal; sesuaikan daftar tier dengan ancaman dan teknologi lingkunganmu.

## 6. Catatan terkini

Bagian ini menampung detail versi, tanggal rilis, dan perubahan alat yang berguna saat membuka sumbernya, tetapi tidak mengubah alur kerja di atas.

- SANS 2026: data (kualitas dan kuantitas) menjadi hambatan hunting nomor satu, pertama kali melampaui staf [S6].
- **ATT&CK:** v18 (Oktober 2025) men-deprecate Data Sources dan memperkenalkan Detection Strategies dan Analytics, dengan Data Components yang direvisi ke versi 2.0; saat rilis itu Enterprise memuat 106 Data Component, 691 Detection Strategy, dan 1.739 Analytic [S13]. v19.2 berlaku 28 April sampai 12 Oktober 2026, dan v20.0 dirilis 13 Oktober 2026 [S12]. Halaman Data Components di v20.0 mendaftar 120 Data Component [S9]. Catatan rilis v20 menyebut enam Detection Strategy baru dan 12 Analytic baru di Enterprise, serta kenaikan versi beberapa Data Component seperti Process Creation dan Command Execution [S12]. Pemetaan sumber ke teknik kini lewat Data Component dan log source yang dicantumkannya; cek ulang pemetaan di bagian 2.6 setiap rilis April dan Oktober.
- **DeTT&CT** 2.2.0 menambahkan dukungan model data ATT&CK v18 (data component dipetakan ke teknik lewat analytic dan detection strategy) [S17]. Halaman rilisnya belum menyebut v19 atau v20, jadi cek dukungan versi ATT&CK terbaru di repo sebelum membuat layer Navigator. OSSEM tidak menyatakan status pemeliharaan secara eksplisit [S10].
- **Sysmon:** dokumentasi Microsoft Learn (diperbarui 2026-09-10) mencantumkan event sampai EID 29 (FileExecutableDetected) [S7]; konfigurasi lama mungkin belum memakai event baru ini. Versi terbaru yang tercatat di situs unduhan pihak ketiga adalah v15.22 bertanggal 10 September 2026 [S25]. Microsoft juga mulai menguji Sysmon bawaan Windows 11 di build Insider (Februari 2026): fitur opsional yang nonaktif secara default, diaktifkan lewat Settings atau DISM lalu `sysmon -i`, dan versi Sysinternals yang terpasang harus dicopot dulu [S23]. Untuk rollout seperti opsi A di bagian 2.8, cek status ketersediaan umum fitur ini di catatan rilis Windows sebelum memilih antara Sysmon Sysinternals dan versi bawaan.
- **Wazuh 4.14:** archives tetap nonaktif secara default; `logall_json` dan pengaktifan archives di Filebeat diperlukan agar event mentah bisa dicari di dashboard [S24].
- **MDE advanced hunting:** data Defender bisa dicari sampai 30 hari; untuk retensi lebih panjang Microsoft menyarankan workspace Microsoft Sentinel atau streaming API [S22].

## 7. Cheat sheet

```
EVIDENCE   dari ABLE: sumber apa, field wajib, field korelasi (ProcessGuid), host mana, rentang berapa, tanda behavior
INVENTARIS sumber | lokasi SIEM | volume harian | host | retensi | pemilik | tanggal verifikasi
KUALITAS   depth (jenis event, field terisi?) + scope (host vs daftar aset) + konfigurasi (filter, audit policy)
           + waktu (retensi, latency, zona waktu)
FEED MATI  nol event != bersih ; cek per sourcetype lalu per host ; host diam vs Sysmon diam
SPL        | tstats count dc(host) max(_time) WHERE index=* earliest="MM/DD/YYYY:HH:MM:SS" latest="..." BY index sourcetype
           | metadata type=hosts index=X   (cepat, per bucket, tidak presisi untuk laporan)
           eval lag_s=_indextime-_time | stats median perc95 min BY sourcetype   (min negatif = zona waktu)
ATT&CK     v18+: Detection Strategy (DET) > Analytic (AN, per platform, mutable elements) > Data Component (DC) > log source
           baca dari bawah: log yang ada -> DC -> teknik ; EID 22 = DC0082, bukan Active DNS
ALAT       OSSEM (DD kamus field, CDM normalisasi, DM relasi) ; DeTT&CT (kualitas 0-5 x 5 dimensi, visibilitas 0-4)
CELAH      visibilitas (data tidak ada -> telemetri) vs deteksi (data ada -> rule)
PRIORITAS  tier 1 dulu ; kartu yang berubah ; skor DeTT&CT naik ; konfigurasi murah jangan pakai jatah anggaran
GERBANG    kartu kesiapan: SIAP | SIAP SEBAGIAN (cakupan ditulis) | TIDAK SIAP (perbaiki data / pilih lain)
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Sysmon terpasang dan mengirim dari 214 host, jadi hunt unduhan LOLBin yang menggabungkan EID 1 dan EID 3 mencakup 214 host." Benarkah?

<details><summary>Jawaban</summary>

Tidak. EID 1 memang datang dari 214 host, tetapi EID 3 (`NetworkConnect`) hanya dari 198 host karena 16 server memakai profil Sysmon ringan tanpa tag itu. Hunt yang butuh kedua event hanya mencakup host yang mengirim keduanya, sehingga 16 server itu harus ditulis di luar cakupan. Ini contoh sumber yang "ada" tetapi depth-nya tidak seragam. Lihat bagian 1.3 dan 1.4.

</details>

**2. Skenario keputusan.** Agung hanya bisa mendanai satu perbaikan kuartal ini. Pilihan mana yang paling bisa dipertanggungjawabkan?

- A. Memperpanjang retensi `dns` dan `proxy` dari 30 ke 90 hari, karena 30 hari terdengar pendek.
- B. Memperluas Sysmon dengan profil workstation lengkap (termasuk `NetworkConnect` dan `DnsQuery`) ke 229 workstation di luar OU `Workstations-EDR`, bertahap mulai dari Bandung.
- C. Mengaktifkan archives Wazuh di `jkt-wazuh01`.

<details><summary>Jawaban</summary>

B. Celahnya tier 1, ia satu-satunya opsi yang mengubah keempat kartu kesiapan (`HUNT-2027-001` sampai `-004`), menaikkan device completeness workstation dari skor 2 ke 4 atau 5, dan menutup lokasi insiden nyata di Bandung. A keliru sebagai prioritas pertama karena hanya memperdalam pandangan atas host yang sudah terlihat, mahal untuk `dns` yang didominasi query pelanggan, dan punya alternatif lebih murah (memisahkan query kantor ke index berretensi panjang). C keliru karena hanya menyentuh empat server Linux dan tidak mengubah hunt yang ada di backlog. Lihat bagian 1.8 dan 2.8.

</details>

**3. Pertanyaan jebakan.** "Latency `netops` sehat: median 3 detik dan p95 9 detik. Timestamp sumber ini bisa dipercaya untuk korelasi." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Nilai minimum lag -25.204 detik (sekitar minus tujuh jam) menunjukkan sebagian event tercatat di masa depan. Drill-down per host menemukan 14 perangkat POP Medan yang menulis jam WIB tanpa offset, sehingga Splunk memakai zona waktu dengan prioritas lebih rendah. Median dan p95 menyembunyikan masalah yang hanya menimpa sebagian host. Perbaikannya `TZ` di `props.conf`, dan data lama tetap perlu dikoreksi di query. Lihat bagian 1.5 dan 2.5.

</details>

**4. Skenario keputusan.** Query per host menunjukkan `JKT-WS-0532` berhenti mengirim Sysmon sejak Selasa 2027-02-02 10:14, tetapi log Windows-nya masih masuk sampai Minggu malam. Apa langkah yang tepat?

- A. Anggap laptop itu dimatikan pemiliknya; tidak perlu tindakan.
- B. Laporkan ke tim Infrastruktur sebagai Sysmon mati di host yang hidup, cek Event ID 4 Sysmon di host itu, dan tulis host itu di luar cakupan untuk setiap hunt yang rentangnya mencakup setelah 2 Februari 10:14.
- C. Abaikan karena hanya satu dari 214 host.

<details><summary>Jawaban</summary>

B. Log Windows yang tetap masuk membuktikan host hidup, jadi yang mati adalah Sysmon-nya; ini feed mati yang sesungguhnya, dan cakupan hunt harus jujur tentang itu. A keliru karena pola host dimatikan adalah kedua sumber diam bersamaan, seperti `JKT-WS-0538`. C keliru karena satu host yang tidak tercatat bisa justru host yang dicari, dan hasil "tidak ditemukan" tanpa menyebutnya melebih-lebihkan cakupan. Lihat bagian 2.2.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Agung Prabowo, dalam tiga kalimat, beda celah visibilitas dan celah deteksi, dan kenapa hanya yang pertama yang dibawa ke dia.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Celah visibilitas berarti datanya tidak ada sama sekali, misalnya 229 workstation tanpa Sysmon, sehingga perilaku penyerang di sana mustahil terlihat oleh query apa pun. Celah deteksi berarti datanya sudah ada di Splunk tetapi belum ada rule yang memakainya, dan itu cukup diselesaikan SOC dengan menulis rule baru. Yang saya bawa ke Pak Agung hanya celah visibilitas, karena hanya itu yang butuh telemetri baru, agen, atau penyimpanan dari tim Infrastruktur."

Kesalahan yang sering muncul:
- Menyebut semua celah sebagai "kurang data", sehingga Infrastruktur diminta mengerjakan hal yang sebenarnya pekerjaan rule.
- Tidak memberi contoh konkret dari lingkungan sendiri.
- Lupa bahwa celah visibilitas punya pemilik dan biaya, sedangkan celah deteksi dibayar dengan waktu analyst.

</details>

**6. Pertanyaan jebakan.** "Untuk memetakan Sysmon EID 22 ke ATT&CK, pakai Data Component `Active DNS`, karena isinya query DNS." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Di ATT&CK v20.0, `Active DNS` (DC0103) mengacu ke data resolusi DNS dari sisi server atau jaringan dan hanya mencantumkan log source "Domain Name". Sysmon EID 22 dicantumkan bersama EID 3 di bawah `Network Connection Creation` (DC0082), dan dipakai misalnya oleh analytic `AN1121` untuk DNS tunneling di Windows. Log query resolver seperti index `dns` PT JAB masuk lewat `Network Traffic Content` (DC0085). Lihat bagian 1.6.

</details>

**7. Interview question (English).** "Before you start a hunt, how do you know the data is good enough?"

<details><summary>Sample answer</summary>

"I derive the data requirements from the hypothesis first: which events, which fields including correlation keys like ProcessGuid, which hosts, and how many days. Then I check four things against measurements, not documentation. Completeness: field fill rates, and host coverage against the asset inventory rather than against another log. Configuration: audit policy, Sysmon include and exclude rules, and whether the field I need is actually populated in raw events. Timeliness: retention covers my window, indexing lag per sourcetype, and negative lag that points to time zone problems. Finally, per-host silence, because a dead feed looks exactly like no activity. I summarise this in a readiness card: ready, partially ready with an explicit out-of-scope list, or not ready, which becomes a visibility gap with an owner. I map sources to ATT&CK data components so I can show which techniques we cannot see, and I keep visibility gaps separate from detection gaps when I ask for investment."

What makes this answer strong: it starts from the hypothesis instead of a generic data list, insists on measuring rather than assuming, covers the silent-feed and time zone traps that most candidates miss, and ends with a decision format that management can act on.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Practical Threat Intelligence (O'Reilly): Working with Data | https://www.oreilly.com/library/view/practical-threat-intelligence/9781838556372/B13376_05_Final_SK_ePub.xhtml | sekunder (buku) | diakses 2026-10-08 | Sedang-tinggi. Kualitas data menentukan kemampuan hunting; OSSEM/CAR |
| S2 | Practical Threat Intelligence (O'Reilly): Assessing Data Quality (OSSEM Power-up, DeTT&CT) | https://www.oreilly.com/library/view/practical-threat-intelligence/9781838556372/B13376_11_Final_SK_ePub.xhtml | sekunder (buku) | diakses 2026-10-08 | Sedang-tinggi. OSSEM dan DeTT&CT untuk menilai data |
| S3 | Decryption Digest: Log source onboarding dan prioritization | https://www.decryptiondigest.com/blog/log-source-onboarding-siem-prioritization | sekunder (praktisi) | diakses 2026-10-08 | Sedang. Prioritas sumber per teknik/biaya; tier satu |
| S4 | Dataversity: How to plan a threat hunt using log analytics | https://www.dataversity.net/articles/how-to-plan-a-threat-hunt-using-log-analytics-to-manage-data-in-depth/ | sekunder | diakses 2026-10-08 | Sedang. Depth vs scope; default audit policy |
| S5 | Decryption Digest (artikel yang sama dengan S3), bagian inventaris sumber | https://www.decryptiondigest.com/blog/log-source-onboarding-siem-prioritization | sekunder | diakses 2026-10-08 | Sedang. Tanggal verifikasi, volume harian; feed diam terdeteksi lewat volume |
| S6 | SANS 2026 Threat Hunting Survey (rilis pers) | https://www.sans.org/press/announcements/threat-hunters-call-data-their-biggest-barrier-overtaking-staffing-first-time-survey-finds | sekunder | 2026-09-23; diakses 2026-10-07 | Sedang-tinggi. Data hambatan nomor satu |
| S7 | Microsoft Learn: Sysmon (Sysinternals) | https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon | primer | halaman diperbarui 2026-09-10; diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi. Daftar event sampai EID 29, EID 3 dan 7 nonaktif default, aturan include/exclude, `sysmon -c`, `ProcessGuid`, `UtcTime` dalam UTC, EID 4 dan 16, opsi `DnsLookup`. Halaman tidak mencantumkan nomor versi biner |
| S8 | Microsoft Learn: Command line process auditing | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing | primer | diperbarui 2025; diakses 2026-10-10 | Tinggi. Dua setting GPO untuk command line di 4688 |
| S9 | MITRE ATT&CK: Data Components (indeks dan halaman komponen DC0032, DC0029, DC0085, DC0103) | https://attack.mitre.org/datacomponents/ | primer | konten v20.0; diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi. 120 Data Component; log source per komponen (Process Creation termasuk `m365:defender`; Script Execution 4103-4106; Active DNS hanya "Domain Name"; Network Traffic Content memuat `NSM:DNS`, `dns:querylog`, `dns.log`) |
| S10 | OTRF: OSSEM (GitHub) | https://github.com/OTRF/OSSEM | primer (repo proyek) | diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi untuk struktur DD, CDM, DM; status pemeliharaan tidak dinyatakan eksplisit |
| S11 | Rabobank CDC: DeTT&CT wiki (Data quality scoring, Visibility scoring) | https://github.com/rabobank-cdc/DeTTECT/wiki/Data-quality-scoring | primer (dokumentasi alat) | diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi. Lima dimensi kualitas 0-5 (skor 2 dan 4 tidak didefinisikan untuk timeliness dan consistency), visibilitas 0-4 (halaman Visibility-scoring di wiki yang sama) |
| S12 | MITRE ATT&CK: Version History dan Updates October 2026 (v20) | https://attack.mitre.org/resources/versions/ | primer | v20.0 dirilis 2026-10-13; diakses 2026-10-18 | Tinggi. Tanggal v17.1, v18.1, v19.2, v20.0; ringkasan perubahan v20 dari https://attack.mitre.org/resources/updates/ |
| S13 | MITRE ATT&CK: Updates October 2025 (v18) | https://attack.mitre.org/resources/updates/updates-october-2025/ | primer | 2025-10; diakses 2026-10-18 | Tinggi. Deprecation Data Sources, Data Components v2.0, Detection Strategies dan Analytics baru beserta jumlahnya |
| S14 | MITRE ATT&CK: Detection Strategy DET0400 (DNS tunneling) | https://attack.mitre.org/detectionstrategies/DET0400/ | primer | dibuat 2025-10-21, diubah 2026-05-12; diakses 2026-10-18 | Tinggi. Analytic AN1121 sampai AN1125, Data Component dan log source AN1121, mutable elements |
| S15 | MITRE ATT&CK: Data Component DC0001 Scheduled Job Creation | https://attack.mitre.org/datacomponents/DC0001/ | primer | versi 3.0, diubah 2026-10-13; diakses 2026-10-18 | Tinggi. Log source Windows 4698, 4699, TaskScheduler 106; Sysmon tidak dicantumkan |
| S16 | MITRE ATT&CK: Data Component DC0082 Network Connection Creation | https://attack.mitre.org/datacomponents/DC0082/ | primer | konten v20.0; diakses 2026-10-18 | Tinggi. `WinEventLog:Sysmon` channel `EventCode=3, 22`; `NSM:Firewall` untuk log proxy; Security 5156/5157 |
| S17 | Rabobank CDC: DeTT&CT release v2.2.0 | https://github.com/rabobank-cdc/DeTTECT/releases/tag/v2.2.0 | primer (catatan rilis) | rilis 21 Januari (tahun tidak tampil di halaman); diakses 2026-10-18 | Tinggi untuk isi rilis. Dukungan model data ATT&CK v18 |
| S18 | Splunk: SPL Search Reference 10.2, metadata | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.2/search-commands/metadata | primer | dokumentasi 10.2; diakses 2026-10-18 | Tinggi. Field keluaran, rentang waktu per bucket, hasil bisa tidak lengkap, batas 10.000 baris |
| S19 | Splunk: SPL Search Reference 10.2, tstats | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.2/search-commands/tstats | primer | dokumentasi 10.2; diakses 2026-10-18 | Tinggi. Klausa WHERE hanya field yang di-index; modifier waktu di WHERE |
| S20 | Splunk: Knowledge Manager Manual 10.4, Use default fields | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.4/fields-and-field-extractions/use-default-fields | primer | dokumentasi 10.4; diakses 2026-10-18 | Tinggi. `_time` (UTC, UNIX time) dan `_indextime` (tersembunyi kecuali di-eval/rename) |
| S21 | Splunk: Getting Data In 10.4, Specify time zones for timestamps | https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/10.4/configure-timestamps/specify-time-zones-for-timestamps | primer | dokumentasi 10.4; diakses 2026-10-18 | Tinggi. Urutan prioritas zona waktu, `TZ` di `props.conf` |
| S22 | Microsoft Learn: Advanced hunting overview in Microsoft Defender XDR | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview | primer | halaman 2026-08-07; diakses 2026-10-18 | Tinggi. 30 hari data Defender, UTC untuk query, perpanjangan lewat Sentinel atau streaming API |
| S23 | BleepingComputer: Microsoft rolls out native Windows 11 Sysmon security monitoring | https://bleepingcomputer.com/news/microsoft/microsoft-rolls-out-native-windows-11-sysmon-security-monitoring | sekunder (media) | 2026-02-04; diakses 2026-10-18 | Sedang-tinggi. Build Insider, nonaktif default, cara mengaktifkan, versi Sysinternals harus dicopot |
| S24 | Wazuh 4.14 documentation: Event logging (archives) | https://documentation.wazuh.com/4.14/user-manual/manager/event-logging.html | primer | dokumentasi 4.14; diakses 2026-10-18 | Tinggi. Archives menyimpan semua event, nonaktif default, `logall` vs `logall_json`, index `wazuh-archives-*` |
| S25 | Mado no Mori (forest.watch.impress.co.jp, Impress): halaman perangkat lunak Sysmon | https://forest.watch.impress.co.jp/library/software/sysmon/ | sekunder (situs unduhan) | diakses 2026-10-18 | Sedang. Versi terbaru tercatat v15.22 (26/09/10); pengumuman Sysmon bawaan Windows 11 dan Server 2025 tanggal 2025-11-20 |
| S26 | Microsoft Learn: 4698(S) A scheduled task was created | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698 | primer (dokumentasi arsip Windows 10) | halaman 2021-09-07, diperbarui 2026-04-27; diakses 2026-10-18 | Tinggi. Subkategori Audit Other Object Access Events; field TaskName, TaskContent; ClientProcessId dan ParentProcessId sejak Windows 10 1903 |

**Catatan sumber:** isi buku O'Reilly [S1][S2] dan artikel praktisi [S3][S4][S5] dipakai dari ringkasan bab, bukan teks lengkap; klaim yang hanya bersandar padanya (prioritas per biaya ingestion, tier satu) adalah praktik praktisi, bukan standar. Dimensi kualitas depth, scope, konfigurasi, dan waktu konsisten antar sumber sekunder dan sejalan dengan lima dimensi DeTT&CT [S11], tetapi tidak berasal dari satu standar resmi. Pemetaan Data Component di bagian 2.6 mengikuti daftar log source ATT&CK v20.0 dan bisa berubah di rilis berikutnya; pemetaan Sysmon EID 11 dan 13 ke DC0039 dan DC0063 mengikuti nama komponennya dan perlu dicek di daftar log source halaman masing-masing. Nomor versi Sysmon v15.22 berasal dari situs unduhan pihak ketiga [S25] karena halaman Microsoft Learn tidak mencantumkan nomor versi; cocokkan dengan properti file `Sysmon64.exe` hasil unduhan resmi. Tahun rilis DeTT&CT 2.2.0 tidak tampil di halaman rilis [S17]; urutannya setelah ATT&CK v18 (Oktober 2025). Status ketersediaan umum Sysmon bawaan Windows 11 belum dikonfirmasi sumber primer Microsoft [S23]. Nama field `ProcessGuid`, `query`, dan `reply_code` perlu dicek setelah normalisasi add-on di lab-mu. Seluruh angka PT JAB (host, volume, latency, profil Sysmon, lookup aset, biaya ingest) dan isi kartu kesiapan adalah penerapan catatan ini pada organisasi fiktif, bukan hasil eksekusi nyata.
