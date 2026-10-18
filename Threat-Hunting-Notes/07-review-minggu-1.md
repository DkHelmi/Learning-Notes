---
day: 07
title: 'Review minggu 1: tujuh hunt pertama, peta konsep, templat hunt dan usulan hipotesis, glosarium, dan lab gabungan scheduled task'
researched_on: 2026-10-18
versions_checked: 'Merangkum Day 01-06; MITRE ATT&CK v20.0 (13 Okt 2026), T1053.005 versi 1.8 (diubah 2026-05-12), DET0441 versi 1.0 (dibuat 2025-10-21, diubah 2026-05-12); Microsoft Learn 4698, 4699, dan Audit Other Object Access Events (arsip Windows 10, ms.date 2021-09, diperbarui 2026-04-27); Atomic Red Team T1053.005 (14 test, dicek 2026-10-18); Splunk Enterprise 10.6 (SPL) dan Search Manual 10.0 About subsearches; PEAK (Splunk, 2023); TaHiTI whitepaper (di-host 2026-03); Hunting Maturity Model (Sqrrl Hunt Evil); SANS 2026 Threat Hunting Survey (rilis pers 23 Sep 2026)'
---

# Day 07: Review minggu 1 (fondasi hunting, templat, dan hunt scheduled task)

Cakupan: ringkasan Day 01-06 beserta tujuh hunt pertama PT JAB, peta konsep satu siklus hunt, pelajaran tentang data, templat dokumentasi hunt dan templat usulan hipotesis untuk L1, glosarium, lalu satu lab gabungan yang menjalankan `HUNT-2027-004` (scheduled task, T1053.005) dari abstract sampai handover, ditambah latihan di VM lab dan skenario keputusan.

## Ide inti

Enam Day pertama bukan enam topik terpisah, tetapi satu siklus yang setiap langkahnya menghasilkan dokumen: pemicu menjadi abstract di backlog, hipotesis ditulis dengan ABLE, Evidence-nya diuji dulu lewat kartu kesiapan data, teknik analisis memperkecil data menjadi daftar yang bisa ditinjau, Splunk menjalankannya tanpa membebani platform bersama, dan laporan menutupnya dengan satu dari empat hasil, cakupan nyata, celah data, serta handover ke penerima yang bisa bertindak. Siklus itu sudah benar-benar berjalan bila orang lain bisa ikut masuk di titik mana pun. Analyst L1 yang menyumbang usulan cukup mengisi pemicu, perilaku, lokasi, dan data yang menurutnya menjawab; hunter yang menerimanya tahu persis apa yang harus dicek sebelum usulan itu diberi nomor hunt; dan pembaca laporan tahu apa yang sudah diperiksa dan apa yang belum, tanpa harus bertanya. Hasil "tidak ditemukan" yang lengkap dengan batasnya adalah keluaran yang sah, dan sering justru yang paling berguna karena menunjukkan celah yang belum terlihat orang lain.

Kamu sudah mengenal pola ini dari NOC. Setiap minggu ada laporan patroli preventif: segmen mana yang dicek, titik mana yang diukur, mana yang normal, dan mana yang tidak bisa diukur karena perangkatnya tidak mengirim data. Teknisi junior tidak menunggu ditugasi; mereka mengisi formulir tiket preventive maintenance bila melihat gejala aneh, dengan kolom yang sama untuk semua orang (gejala, lokasi, data ukur), lalu engineer senior memeriksa apakah datanya tersedia sebelum tiket itu masuk antrean. Batas analoginya ada dua. Degradasi fiber tidak berusaha bersembunyi, sedangkan penyerang sengaja bergerak di bawah ambang, sehingga laporan "normal" hanya berlaku untuk pertanyaan, data, dan rentang yang tertulis. Dan usulan dari L1 adalah dugaan, bukan hipotesis final: ia baru menjadi hunt setelah Evidence-nya terbukti ada.

```
 usulan L1 / intel / insiden / baseline / celah deteksi
            |
            v
 templat usulan (pemicu, perilaku, lokasi, data)  --- hunter: cek Evidence
            |                                               |
            v                                     tidak ada --> celah data (pemilik, backlog)
 abstract + ABLE + kartu kesiapan (backlog, nomor HUNT)     |
            | SIAP / SIAP SEBAGIAN                          |
            v                                               |
 teknik (stacking, first-seen, frekuensi, searching) di Splunk (tstats dulu, raw bertarget)
            |
            v
 label tiap item: jinak | perlu investigasi | inkonklusif | data tidak cukup
            |                    \
            |                     +--> berbahaya: eskalasi ke IR SEKARANG
            v
 laporan: hasil + cakupan nyata + di luar cakupan + celah + deteksi + hipotesis baru
            |
            v
 handover: IR | Sari (detection) | Infrastruktur/NOC (telemetri) | pemilik sistem | backlog
```

Situasi Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan, kantor pusat dan data center di Jakarta, serta POP regional di Bandung, Surabaya, dan Medan. SOC PT JAB memakai Splunk Enterprise dengan Enterprise Security (ES); Sysmon terpasang di 61 server Windows dan 153 workstation OU `Workstations-EDR` (semuanya di Jakarta), dan GPO audit `JAB-WS-Audit` hanya ditautkan ke OU itu. Sejak Senin 2027-02-01 kamu, analyst L2, memegang "Program hunt PT JAB" setiap Selasa dan Kamis, dengan SOC lead Dimas Prasetyo sebagai sponsor. Tiga minggu berjalan, tujuh hunt sudah punya nomor (`HUNT-2027-001` sampai `-007`), dan satu di antaranya, `HUNT-2027-004` (scheduled task dari brief forum intel ISP regional), masih menunggu sejak Day 03 karena kesiapan datanya baru dicek di Day 04. Kamis 2027-02-18 pukul 08:10, Dimas menulis:

> "Pagi. Besok di rapat mingguan SOC aku mau kasih ringkasan tiga minggu pertama program hunt, dan mulai minggu depan Gilang sama Dwi aku minta ikut menyumbang hipotesis ke backlog. Tolong siapkan bahannya hari ini. Apa saja yang sudah kita kerjakan dan hasilnya apa? Apa yang kita pelajari soal data kita sendiri? Kalau anak L1 mau usul hipotesis, mereka isi templat yang mana, dan laporanmu sendiri formatnya apa? Istilah apa yang wajib mereka paham supaya tidak bingung baca laporanmu? Aku juga mau satu contoh utuh dari awal sampai laporan; pakai saja hunt scheduled task dari brief forum itu, yang katanya tinggal tunggu data. Terakhir, apa yang belum bisa kita kerjakan, supaya aku tidak menjanjikan yang tidak bisa ke Pak Hendra."

Pesan itu memuat enam pertanyaan:

1. Apa yang sudah dikerjakan tiga minggu ini, dan hasilnya apa?
2. Apa yang dipelajari tentang data PT JAB?
3. Templat apa yang dipakai L1 untuk mengusulkan hipotesis, dan templat apa yang dipakai hunter untuk abstract dan laporan?
4. Istilah apa yang wajib dipahami L1?
5. Bagaimana sebuah hunt dijalankan dari awal sampai laporan, dengan satu contoh utuh?
6. Apa yang belum bisa dikerjakan?

Pertanyaan 1 dijawab di bagian 1.1 sampai 1.7, pertanyaan 2 di bagian 1.8, pertanyaan 3 di bagian 1.9 dan 1.10, pertanyaan 4 di bagian 1.11, pertanyaan 5 di lab gabungan (Bagian A sampai F), dan pertanyaan 6 di bagian 1.8 serta Bagian F. Bagian 1.12 merangkum semuanya sebagai bahan rapat Jumat.

**Kapan relevan:** sebelum masuk hunting per alat dan per teknik (Day 08 dan seterusnya), saat orang baru (L1, pemilik detection, admin platform) mulai ikut dalam program, saat menyiapkan laporan berkala ke manajemen, dan sebelum interview yang meminta kamu menceritakan satu hunt dari awal sampai akhir.
**Kapan bukan jawaban:** review ini tidak menambah metode baru; bila ada yang terasa baru, kembali ke Day asalnya. Review ini juga tidak membahas Wazuh, Velociraptor, atau teknik ATT&CK lain secara mendalam; lab gabungannya hanya satu teknik, T1053.005, dan hanya pada host yang punya audit.

## 1. Ringkasan, peta konsep, dan glosarium

### 1.1 Day 01: definisi, posisi, dan kematangan

- Threat hunting adalah pencarian proaktif, dipimpin manusia, dan iteratif atas aktivitas berbahaya yang lolos dari pertahanan yang ada. TaHiTI menambahkan dua hal: hunting mengandaikan security monitoring sudah berjalan, dan tujuan utamanya memperpendek breach detection gap atau dwell time [S2].
- Pembedanya dengan pekerjaan harian ada di pemicu dan kapan selesai. Detection dimulai dari alert dan selesai saat alert ditutup; IR dimulai dari insiden dan dipegang IC; hunting dimulai dari pertanyaan dan selesai saat hipotesis terjawab. Scoping saat insiden (misalnya mencari laptop lain pada `INC-2026-026`) adalah IR, walaupun query-nya mirip hunt.
- Alasan PT JAB butuh hunting ada di kasusnya sendiri: sekitar 66 jam antara akses awal dan alert enkripsi di `INC-2026-017`, dan `BDG-WS-0163` yang beacon 73 kali selama akhir pekan tanpa alert di `INC-2026-026`.
- Hunting Maturity Model: HMM0 Initial (hanya alert), HMM1 Minimal (pencarian IOC), HMM2 Procedural (menjalankan prosedur buatan pihak lain secara terjadwal), HMM3 Innovative (membuat prosedur sendiri), HMM4 Leading (mengotomasi prosedur yang berhasil) [S3]. Level ditentukan oleh pertanyaan tertinggi yang bisa dijawab "ya" dengan bukti. PT JAB per 1 Februari 2027 ada di HMM1; target Juli adalah perilaku HMM2 yang konsisten dan awal HMM3.
- Empat hasil sebuah hunt: ditemukan, tidak ditemukan (dengan cakupan), inkonklusif, dan data tidak cukup [S2]. "Tidak ditemukan" tanpa cakupan adalah pernyataan kosong.
- Rekrutmen threat hunter khusus belum perlu, karena hambatan utama hunting kini data, bukan orang; evaluasi ulang di akhir percobaan.

### 1.2 Day 02: siklus hunt, empat hasil, dan handover

- Hunting loop Sqrrl punya empat tahap: buat hipotesis, investigasi dengan alat dan teknik, ungkap pola dan TTP, lalu perkaya analitik otomatis. Loop berputar karena setiap deteksi baru memunculkan pertanyaan tentang apa yang masih lolos [S3].
- PEAK (Splunk, 2023) mengoperasionalkan loop menjadi Prepare, Execute, dan Act, dengan Knowledge di semua fase, dan membedakan tiga tipe hunt: hypothesis-driven, baseline (exploratory data analysis), dan model-assisted (M-ATH) [S1]. Langkah Escalate Critical Findings ada di fase Execute: temuan berbahaya diserahkan ke IR saat itu juga, tidak menunggu laporan.
- TaHiTI memecah hunt menjadi Initiate (pemicu ditulis sebagai abstract dan masuk backlog), Hunt (define/refine dan execute, bolak-balik sampai hipotesis tervalidasi), dan Finalize (dokumentasi dan handover) [S2].
- PT JAB memakai PEAK untuk memilih tipe hunt dan alur kerja, dan TaHiTI untuk format abstract, backlog, dan handover.
- Kriteria sukses dan time-box ditulis sebelum Execute. Bila time-box habis, yang belum ditinjau ditulis sebagai di luar cakupan, bukan "tidak ditemukan".
- Celah deteksi (data ada, rule belum) diserahkan ke Sari Kusuma sebagai abstract deteksi lengkap dengan volume dari data hunt, false positive yang terlihat, dan level di Hierarchy of Detection Outputs. Celah visibilitas (data tidak ada) diserahkan ke tim Infrastruktur (Agung Prabowo) atau NOC.
- Aktivitas yang cocok dengan pola tetapi sah dicatat sebagai "ditemukan, jinak terkonfirmasi"; hipotesis tetap tidak terbukti. Contohnya `certutil -urlcache` oleh `adm.hari` di `jkt-mgmt01` pada `HUNT-2027-002`.

### 1.3 Day 03: hipotesis dan ABLE

- Topik ("data exfiltration") bukan hipotesis. Hipotesis harus bisa dibuktikan atau dibantah dengan data tertentu, dan penajamannya berjalan dari kategori besar ke satu metode, lalu ke satu konteks [S1].
- ABLE: Actor (opsional), Behavior (satu atau dua TTP, bukan seluruh kill chain), Location (di mana behavior kemungkinan muncul), dan Evidence (sumber data dan seperti apa jejaknya) [S1]. Hipotesis siap dijalankan bila Behavior, Location, dan Evidence terisi dan Evidence terbukti ada lewat satu query cepat.
- Daftar IOC dari brief adalah pencarian indikator (HMM1), dikerjakan L1 dan dibatasi retensi 30 hari di `proxy` dan `dns`. Hunt mengambil perilakunya. Brief forum intel ISP regional (Kamis 2027-02-04) menghasilkan dua hunt terpisah: `HUNT-2027-003` (DNS tunneling) dan `HUNT-2027-004` (scheduled task).
- Urutan pengerjaan memakai kriteria yang bisa diulang: relevansi, dampak, Evidence siap, data hilang bila ditunda, dan celah deteksi. `-003` didahulukan karena data `dns` menyusut setiap hari.
- Anti-pola: terlalu luas, tidak bisa dibantah, hanya IOC, tanpa Evidence, menebak tanpa Knowledge, seluruh kill chain, dan hipotesis tentang niat. Niat tidak terlihat di log; tulis perbuatannya.
- PEAK menyarankan batas durasi, misalnya tiga hari, dan rentang data biasanya setidaknya sekitar 30 hari [S1].

### 1.4 Day 04: kesiapan data

- Evidence di ABLE diterjemahkan menjadi lima kebutuhan: sumber, field wajib (termasuk field korelasi seperti `ProcessGuid`), host yang tercakup, rentang, dan tanda behavior.
- Inventaris sumber mencatat lokasi di SIEM, volume harian, jumlah host, retensi, pemilik, dan tanggal verifikasi. Volume dan tanggal verifikasi penting karena feed yang berhenti tidak menghasilkan error, hanya nol event.
- Kualitas dinilai pada empat sumbu: depth (jenis event dan field terisi), scope (host tercakup dibanding daftar aset, bukan dibanding log lain), ketepatan konfigurasi (filter Sysmon, audit policy), dan waktu (retensi, latency, zona waktu).
- Pemetaan ke ATT&CK sejak v18 memakai Data Component, Detection Strategy, dan Analytic; OSSEM memberi kamus field dan relasi, DeTT&CT memberi skor kualitas 0-5 dan visibilitas 0-4.
- Keluarannya kartu kesiapan per hunt dengan tiga putusan: SIAP, SIAP SEBAGIAN (cakupan ditulis), atau TIDAK SIAP (celah visibilitas dengan pemilik). Keempat hunt pertama mendapat SIAP SEBAGIAN.
- Untuk `HUNT-2027-004`, Day 04 menutup pertanyaan yang ditinggalkan Day 03: subkategori Audit Other Object Access Events terverifikasi aktif di `JAB-WS-Audit`, server punya baseline audit sendiri yang juga menghasilkan 4698, dan 229 workstation di luar OU tidak menghasilkan 4698 maupun Sysmon.

### 1.5 Day 05: baselining, stacking, dan beacon

- Empat teknik saling melengkapi: searching (hipotesis spesifik), stacking (hitung lalu periksa yang langka), grouping (apa yang muncul bersama pada data yang sudah dicurigai), dan clustering (kemiripan agregat atas seluruh data) [S5]. Analisis frekuensi adalah stacking yang ditambah dimensi waktu.
- Baseline ditulis per kelompok host, dari periode yang alasan "bersih"-nya ditulis, dengan aturan normalisasi yang disimpan sebagai macro (`jab_norm_parentchild`). Baseline disimpan sebagai lookup (`jab_hunt_baseline_parentchild.csv`, dengan kolom `first_seen`), bukan dihitung ulang tiap hunt.
- Yang langka layak dicurigai karena penyerang biasanya di ekor distribusi, tetapi langka hanya sinyal. Syarat yang lebih tajam: jarang dieksekusi dan hanya di sedikit host. Ambang diambil dari distribusi, bukan ditebak.
- Beacon diukur dengan interval antar-koneksi dan coefficient of variation (CV). Ambang yang dipakai sejak Day 05: CV maksimal 0,2 setelah membuang jeda lebih dari tiga kali median. Agent sah juga teratur; yang membedakan adalah prevalence, pemilik, proses pemanggil, umur tujuan, dan pola harian.
- Semua teknik memperkecil ruang pencarian; vonis tetap di tangan manusia yang meninjau dan melabeli tiap item.

### 1.6 Day 06: hunting di Splunk

- Pola dua tahap: persempit dengan `tstats` atas data model terakselerasi (`Endpoint.Processes`, summary range 90 hari, `jkt-splunk-sh01` sebagai reader ringkasan `jkt-splunk-es01`, sehingga `summariesonly=true`), lalu perdalam dengan raw search bertarget pada irisan kecil.
- Optimasi tidak boleh mengubah pertanyaan. Uji kesetaraan `HUNT-2027-007` baru lulus (389 sama dengan 389) setelah `index=sysmon` ditambahkan (karena 4688 ikut masuk dataset) dan baris ber-parent `unknown` dibuang.
- Search raw yang membaca terlalu banyak event membebani indexer bersama dan bisa membuat correlation search ES terlewat (tujuh run dari tiga correlation search pada Kamis 2027-02-11). Rem yang diusulkan untuk role `jab_hunter` adalah workload rule, bukan `srchTimeWin`.
- Hunt eksploratif tetap interaktif; yang dijadwalkan hanya pemeliharaan baseline dan laporan first-seen. Baseline diperbarui inkremental dengan `override_if_empty=false`.
- Job Inspector: lihat `runDuration`, `scanCount`, `eventCount`, `resultCount`, dan komponen termahal. Scan rate sekitar 40.000 event per detik berarti indexer membaca cepat; masalahnya volume.
- Query disimpan sebagai file `.spl` berkomentar di `jab-hunt/hunts/HUNT-2027-NNN/queries/`, dengan rentang absolut dan angka Job Inspector.

### 1.7 Peta konsep dan tujuh hunt pertama

Peta berikut menggabungkan diagram Day 01-06 dalam satu gambar. Setiap kotak adalah gerbang: hunt yang melompatinya biasanya berakhir inkonklusif tanpa disadari, karena "tidak ada hasil" bisa berarti tidak ada aktivitas, tidak ada telemetri, atau query yang buta.

```
 PEMICU  intel | ATT&CK | insiden 2026 | baseline | keahlian domain | celah deteksi | usulan L1
    |
    v
 ABSTRACT (TaHiTI Initiate, PEAK Prepare) -> backlog/BACKLOG.md
    hipotesis bisa dibantah + ABLE (Actor? Behavior Location Evidence) + kriteria sukses + time-box
    |
    v
 KARTU KESIAPAN (Day 04)  depth | scope vs daftar aset | konfigurasi | retensi, latency, zona waktu
    |  SIAP / SIAP SEBAGIAN                        TIDAK SIAP --> celah visibilitas -> pemilik telemetri
    v
 TEKNIK (Day 05)  searching | stacking | first-seen vs baseline | grouping | frekuensi (CV)
    |
    v
 SPLUNK (Day 06)  tstats mempersempit -> uji kesetaraan -> raw bertarget ; simpan .spl + Job Inspector
    |
    v
 LABEL per item   jinak (bukti di luar query) | perlu investigasi | inkonklusif | data tidak cukup
    |        \
    |         +--> berbahaya: Escalate Critical Findings ke IR (Dimas), jangan tunggu laporan
    v
 HASIL (TaHiTI validasi)  ditemukan | tidak ditemukan + cakupan | inkonklusif | data tidak cukup
    |
    v
 HANDOVER (TaHiTI Finalize, PEAK Act)
    IR | Sari: abstract deteksi (volume, FP, level) | Agung/NOC: celah | pemilik sistem | backlog
    |
    +--> hipotesis baru, baseline diperbarui ---------------------------------> kembali ke PEMICU
```

Tabel berikut adalah jawaban pertanyaan pertama Dimas: tujuh hunt yang sudah bernomor sampai pagi ini. Angkanya sama persis dengan laporan masing-masing di Day asalnya. Baca kolom "Tindak lanjut", karena di situlah nilai hunt yang hasilnya "tidak ditemukan".

| Hunt | Day | Tipe dan teknik | Data dan rentang | Hasil | Angka kunci | Tindak lanjut |
|---|---|---|---|---|---|---|
| `HUNT-2027-001` | 01 | Baseline parent-child, Execution (TA0002) | Sysmon EID 1, workstation OU `Workstations-EDR`, 25 Jan-1 Feb | Tidak ditemukan | 4.812.330 event, 3.214 pasangan, 1.146 pasangan `<= 3`; dipersempit ke parent berisiko: 3 pasangan, semua jinak | Usulan rule "JAB - Office atau WMI memunculkan shell" (setelah uji lab); 2 kandidat backlog; celah Sysmon ke Agung |
| `HUNT-2027-002` | 02 | Hypothesis-driven, T1105 lewat LOLBin | Sysmon EID 1 dan 3, 214 host, 18 Jan-1 Feb | Tidak terbukti | 65 eksekusi bertanda unduhan, 2 dengan koneksi keluar (certutil di `jkt-mgmt01`, jinak dengan tiket change) | Abstract deteksi "JAB - certutil atau bitsadmin mengunduh dari URL eksternal"; 16 host tanpa EID 3 ke Agung; 2 kandidat backlog |
| `HUNT-2027-003` | 03 | Hypothesis-driven, T1071.004 (T1048 bila kanal exfil terpisah) | `dns` 4 resolver + Sysmon EID 22 (186 host), 7 Jan-4 Feb | Siap dijalankan; belum dijalankan penuh | Sampel 3 Feb: 61.402 domain induk, 1 lolos ambang (`avcloud.example`, engine antivirus `jkt-proxy01`, jinak, masuk allowlist); agregat 28 hari 4.318 domain induk disimpan | Data mentah 7-18 Januari sudah lewat retensi; yang tersisa agregat `jab_hunt_baseline_dns_parent.csv` |
| `HUNT-2027-004` | 03, 07 | Hypothesis-driven, T1053.005 | 4698 + Sysmon EID 1; abstract Day 03, dijalankan hari ini | Lihat lab gabungan | Lihat Bagian F | Lihat Bagian F |
| `HUNT-2027-005` | 05 | Analisis frekuensi, T1071.001 | `proxy` Jakarta dan Bandung, 1-7 Feb | Tidak ditemukan C2; 1 inkonklusif | 58.912.407 event, 118.477 pasangan, 2.947 kandidat tahap A, 751 pasangan di 6 tujuan teratur | `BDG-WS-0196` ke `api.statuspulse.example` tiap 1.800 detik masih terbuka di backlog; laporan mingguan "TH - kandidat beacon proxy" diusulkan ke Sari |
| `HUNT-2027-006` | 05 | Baseline first-seen parent-child | Sysmon EID 1 workstation; baseline 1-31 Jan, jendela 1-10 Feb | Tidak ditemukan | Baseline 20.164.882 event menjadi 2.611 pasangan dinormalisasi; jendela 1.722 pasangan, 5 baru (412 tanpa normalisasi), semua jinak | Lookup baseline dan macro normalisasi; laporan first-seen harian diusulkan ke Sari |
| `HUNT-2027-007` | 06 | Baseline + hypothesis-driven, binary proxy (T1218.003/.004/.009, T1127.001) | `Endpoint.Processes` dari `index=sysmon`, 153 workstation, 17 Jan-16 Feb | Tidak ditemukan | 4 pasangan first-seen, semua jinak; stacking 30 hari raw 1.659 detik menjadi 19 detik dengan `tstats` | Baseline 2.611 menjadi 2.620 baris; catatan ke Sari soal makro template; 2 kandidat backlog |

Tiga hal terbaca dari tabel ini untuk rapat besok. Pertama, belum ada satu pun temuan berbahaya, dan itu hasil yang sah selama cakupannya tertulis. Kedua, setiap hunt menghasilkan sesuatu yang bisa dipakai pihak lain: dua usulan rule, dua usulan laporan terjadwal, tiga lookup, dan daftar celah data yang sama berulang kali. Ketiga, `HUNT-2027-003` menunjukkan biaya menunda hunt di atas data berretensi pendek: rentang abstract-nya hanya bisa diulang dari agregat yang disimpan pada hari abstract ditulis.

### 1.8 Yang dipelajari tentang data PT JAB

Pertanyaan kedua Dimas jawabannya hampir sama di setiap laporan: data PT JAB kuat di sebagian host dan buta di sebagian lain. Tabel berikut merangkum pelajaran data dari tujuh hunt dan pemeriksaan Day 04; baca kolom "Akibat untuk hunt", karena itulah kalimat yang harus muncul di setiap laporan.

| Pelajaran | Angka | Akibat untuk hunt |
|---|---|---|
| Sysmon hanya di server Windows dan workstation OU `Workstations-EDR` | 214 host = 61 server + 153 workstation; 153 dari 382 workstation aktif (40,1%), semuanya Jakarta | Setiap hunt endpoint menulis 229 workstation di luar cakupan (Jakarta 148, Bandung 58, POP Surabaya dan Medan 23) |
| GPO audit `JAB-WS-Audit` hanya di OU yang sama | 4688 dengan command line dan 4698 hanya dari 214 host | Workstation tanpa Sysmon juga tanpa 4688 dan 4698; satu-satunya sumber proses di sana adalah MDE (30 hari, konsol terpisah), dan 29 workstation tanpa sumber apa pun |
| Profil Sysmon server tidak seragam | EID 3 dari 198 host, EID 22 dari 186 host | Hunt koneksi atau DNS per proses menulis 16 dan 28 host di luar cakupan |
| Feed bisa mati diam-diam | Sysmon `JKT-WS-0532` diam sejak Selasa 2027-02-02 10:14 (host aktif); `JKT-WS-0538` dan `JKT-WS-0448` offline | Hunt setelah 2 Februari mengecualikan `JKT-WS-0532` untuk data Sysmon |
| Retensi `proxy` dan `dns` 30 hari | Event tertua `dns` 2027-01-05 02:14 saat dicek 4 Februari | Hunt di atas dua sumber itu harus dijalankan atau diagregasi segera |
| Log DNS hanya mencatat pertanyaan | `reply_code` terisi 0% | Rasio NXDOMAIN tidak bisa dipakai dari sumber ini |
| Waktu tidak selalu benar | 14 perangkat POP Medan tercatat tujuh jam di masa depan; o365 p95 latency 3.960 detik | Perbaiki `TZ` di `props.conf`; geser jendela search data cloud |
| Data model bisa dipakai, dengan syarat | `Endpoint` 90 hari; `Network_Traffic` dan `Web` 30 hari; 4688 ikut masuk `Endpoint.Processes` | Filter `index=sysmon` dan uji kesetaraan sebelum memakai `tstats` |

Yang sudah dikerjakan atas pelajaran itu: rekomendasi ke Agung Selasa 2027-02-09 (Sysmon profil lengkap ke 229 workstation dalam dua tahap, Bandung dan POP lebih dulu; menautkan GPO audit; menyamakan profil Sysmon server; memperbaiki `TZ` Medan; memulihkan Sysmon `JKT-WS-0532`), dan usulan scheduled search harian untuk host Sysmon yang diam.

Yang belum bisa dikerjakan, untuk pertanyaan keenam Dimas:

- Apa pun yang butuh proses, task, atau command line di 229 workstation di luar OU, kecuali lewat MDE untuk workstation Jakarta dan Bandung yang ber-EDR, dengan batas 30 hari dan konsol terpisah.
- Keadaan host saat ini secara massal (autostart, file di disk, task yang tidak pernah tercatat di log), karena tidak ada server koleksi endpoint permanen. Rekomendasi Day 04 menempatkannya sebagai "bukan sekarang"; lab gabungan hari ini memberi alasan konkret untuk membuka lagi keputusan itu (Bagian F, `HUNT-2027-009`).
- Event mentah empat server Linux ber-Wazuh, karena archives belum aktif; dan eksekusi proses di 31 server Linux tanpa rule `execve`.
- Baseline jaringan lebih dari 30 hari ke belakang.

### 1.9 Templat dokumentasi hunt: abstract dan laporan

Satu hunt menghasilkan dua dokumen di `jab-hunt/hunts/HUNT-2027-NNN/`: `abstract.md` sebelum Execute dan `report.md` setelahnya, ditambah folder `queries/`. Templat berikut adalah versi final setelah tujuh hunt; setiap baris sudah terbukti dibutuhkan di salah satu hunt.

Abstract (TaHiTI Initiate, PEAK Prepare):

```
ID             : HUNT-2027-NNN
Dibuat         : YYYY-MM-DD (hari), pemilik: <hunter>, reviewer: Dimas Prasetyo
Asal usulan    : <bila dari usulan L1: nama pengusul dan tanggal usulan>
Trigger        : <intel | ATT&CK | insiden | baseline | keahlian domain | celah deteksi | usulan L1> + asal
Tipe (PEAK)    : hypothesis-driven | baseline | M-ATH
Hipotesis      : <pernyataan yang bisa dibuktikan ATAU dibantah oleh data tertentu>
ABLE           : Actor <opsional> | Behavior <1-2 TTP + ID ATT&CK> | Location <host/segmen + prioritas>
                 | Evidence <index/event, field, seperti apa jejaknya>
ATT&CK         : <ID teknik (taktik), versi ATT&CK>
Data           : <index, sourcetype, EventCode>, <jumlah host>, rentang absolut WIB
Kesiapan data  : SIAP | SIAP SEBAGIAN | TIDAK SIAP + alasan (depth, scope, retensi, feed diam)
Di luar cakupan: <host tanpa sumber (jumlah), periode, jalur teknik yang tidak terlihat>
Teknik analisis: <searching | stacking | first-seen | grouping | frekuensi> + baseline yang dipakai
Kriteria sukses: <"semua X ditinjau dan dilabeli" yang bisa dicek orang lain>
FP yang diduga : <software, tim, atau proses sah yang mirip pola>
Time-box       : <mis. satu hari hunting>
Hasil mungkin  : ditemukan | tidak ditemukan | inkonklusif | data tidak cukup
Handover       : IR (Dimas) | Sari (detection) | Agung/NOC (telemetri) | pemilik sistem | backlog
Status         : kandidat | siap dijalankan | menunggu kesiapan data | berjalan | selesai
```

Laporan (TaHiTI Finalize, PEAK Act):

```
ID            : HUNT-2027-NNN                        Selesai: YYYY-MM-DD HH:MM
Hasil         : ditemukan | tidak ditemukan | inkonklusif | data tidak cukup
Ringkasan     : <2-3 kalimat: apa yang diperiksa dan apa jawabannya>
Cakupan nyata : <host yang BENAR-BENAR tercakup, sumber, rentang absolut, angka event>
Di luar cakupan: <host, periode, jalur teknik, item yang tidak sempat ditinjau>
Kelengkapan   : <feed diam, ringkasan data model, uji kesetaraan raw vs tstats>
Ambang/asumsi : <ambang dan alasannya dari distribusi; aturan normalisasi dan versinya>
Temuan        : <item yang ditinjau + label + bukti di luar query (tiket, pemilik, konfirmasi)>
Eskalasi      : <IR: kapan dan apa yang diserahkan, atau "tidak ada">
Celah data    : <celah visibilitas -> pemilik>
Deteksi       : <abstract deteksi ke Sari: logika kasar, level, volume, FP, pengecualian>
Rekomendasi   : <salah konfigurasi atau risiko -> pemilik sistem>
Artefak       : <lookup, macro, file .spl, angka Job Inspector>
Hipotesis baru: <-> backlog, dengan nomor bila ABLE sudah lengkap>
Pelajaran     : <apa yang akan dilakukan berbeda>
```

Dua baris yang paling sering diisi asal-asalan adalah "Cakupan nyata" dan "Ambang/asumsi". Cakupan nyata berbeda dari cakupan rencana: bila abstract menyebut 214 host tetapi Sysmon satu host diam sejak 2 Februari, laporan menulis itu. Ambang tanpa alasan (misalnya `count <= 3` tanpa distribusi) membuat hunt tidak bisa diulang secara konsisten. Baris "Eskalasi" sengaja ada walaupun sering berisi "tidak ada", supaya pembaca tahu pertanyaan itu memang ditanyakan.

### 1.10 Templat usulan hipotesis untuk L1

Gilang Ramadhan dan Dwi Cahyono melihat pola yang tidak terlihat hunter: alert yang sering ditutup jinak, host yang selalu muncul, keluhan pengguna yang berulang. Templat ini sengaja lebih pendek dari abstract. L1 mengisi bagian atas; hunter mengisi bagian bawah saat meninjau usulan setiap Selasa pagi, lalu memutuskan apakah usulan itu menjadi abstract bernomor, kandidat backlog, atau celah data.

```
=== DIISI PENGUSUL (L1) ===
Pengusul / tanggal : <nama>, YYYY-MM-DD
Pemicu             : alert berulang | insiden lama | laporan intel | keluhan pengguna | pengalaman | lainnya
                     + rujukan (nomor alert, insiden, atau judul laporan)
Pertanyaan         : <satu kalimat: "Apakah ada ... di ... tanpa alert?">
Perilaku yang dicari: <apa yang TERLIHAT di log bila dugaan benar; bukan niat, bukan nama malware>
Di mana            : <host, segmen, kelompok pengguna, aplikasi>
Data yang menurutku menjawab: <index/sourcetype/event yang kamu tahu, boleh "tidak tahu">
Apa yang membuat dugaan ini SALAH: <hasil data seperti apa yang membantahnya>
Kenapa sekarang    : <data akan hilang (retensi), intel baru, kejadian baru>
Dugaan jinak       : <software, tim, atau jadwal yang mungkin menjelaskan>

=== DIISI HUNTER ===
Diterima           : YYYY-MM-DD, oleh <hunter>
Topik atau hipotesis: topik (perlu ditajamkan) | hipotesis bisa diuji
ABLE               : Actor | Behavior (ID ATT&CK) | Location | Evidence
Cek Evidence       : <query cepat + hasil: sumber ada? field terisi? host tercakup? retensi?>
Kesiapan           : SIAP | SIAP SEBAGIAN | TIDAK SIAP (celah -> pemilik)
Keputusan          : abstract HUNT-2027-NNN | kandidat backlog | celah data | ditolak + alasan
Umpan balik ke pengusul: <satu-dua kalimat>
```

Contoh terisi berikut berasal dari kandidat backlog yang sudah ada sejak Day 03 (alert P3 perlindungan endpoint yang berkumpul di satu host, pelajaran `INC-2026-017`), ditulis ulang seolah diusulkan Gilang. Contoh ini sengaja memperlihatkan bagian hunter yang belum lengkap.

```
=== DIISI PENGUSUL (L1) ===
Pengusul / tanggal : Gilang Ramadhan, 2027-02-23
Pemicu             : alert berulang + insiden lama (INC-2026-017: alert tamper AV P3 tidak dieskalasi)
Pertanyaan         : Apakah ada host yang mengumpulkan beberapa alert P3 perlindungan endpoint dalam
                     90 hari, yang masing-masing ditutup jinak tanpa ada yang melihat polanya?
Perilaku yang dicari: dua atau lebih alert P3 jenis "perlindungan dimatikan/diubah" di host yang sama
Di mana            : semua host yang punya MDE
Data yang menurutku menjawab: alert di ES (tidak tahu index-nya)
Apa yang membuat dugaan ini SALAH: tidak ada host dengan lebih dari satu alert jenis itu, atau semua
                     host yang berulang punya penjelasan tertulis (tiket, pengecualian)
Kenapa sekarang    : belum ada rule yang melihat alert per host lintas minggu
Dugaan jinak       : laptop IT yang sering diuji, pembaruan agent

=== DIISI HUNTER ===
Diterima           : 2027-02-23, oleh <hunter>
Topik atau hipotesis: hipotesis bisa diuji (perilaku, lokasi, dan bukti bantahan sudah ada)
ABLE               : Actor tidak spesifik | Behavior pelemahan pertahanan endpoint berulang (cek ID teknik
                     di ATT&CK v20 sebelum ditulis) | Location host ber-MDE | Evidence data alert ES
Cek Evidence       : perlu dicek nama index alert di ES 8.x (jkt-splunk-es01) dan retensinya;
                     90 hari hanya bisa bila retensi alert minimal 90 hari
Kesiapan           : belum dinilai
Keputusan          : kandidat backlog sampai cek Evidence selesai
Umpan balik ke pengusul: usulan bagus karena kalimat "apa yang membuatnya salah" sudah jelas.
                     Langkah berikutnya: cari bersama Sari di mana alert disimpan dan berapa lama.
```

Kesalahan usulan yang paling sering, dan cara menjawabnya ke pengusul:

- **Topik, bukan pertanyaan** ("cek ransomware"). Minta satu perilaku yang terlihat di log (Day 03 bagian 2.8).
- **Daftar IOC** ("cari 40 domain ini"). Itu pencarian indikator; kerjakan langsung lewat threat intelligence ES, lalu tanyakan perilakunya (Day 03 bagian 1.1).
- **Niat** ("aktor ingin mencuri data pelanggan"). Minta perbuatan yang teramati.
- **Tanpa bukti bantahan.** Bila tidak ada hasil data yang bisa membuktikan dugaan itu salah, usulan belum bisa dijadikan hunt.
- **Data yang tidak ada.** Usulan tetap dicatat; keputusannya "celah data", dan pemiliknya ditulis. Usulan seperti itu tetap bernilai.

### 1.11 Glosarium

Glosarium ini menjawab pertanyaan keempat Dimas: istilah yang muncul di laporan hunt PT JAB. Definisi ditulis dengan kata sendiri untuk keperluan belajar. Kolom terakhir adalah pasangan yang paling sering membuat pembaca laporan salah paham.

| Istilah | Arti singkat | Sering tertukar dengan |
|---|---|---|
| Threat hunting | Pencarian proaktif, dipimpin manusia, iteratif, atas aktivitas yang lolos dari pertahanan | Triage alert, scoping saat insiden |
| Detection | Logika otomatis yang menghasilkan alert untuk pola yang sudah dirumuskan | Hunt yang dijalankan ulang manual |
| Hipotesis | Dugaan yang bisa dibuktikan atau dibantah oleh data tertentu | Topik ("data exfiltration") |
| Pencarian indikator | Mencocokkan daftar IOC ke data historis; ciri HMM1 | Hunting TTP |
| Pyramid of Pain | Urutan jenis indikator dari yang mudah diganti penyerang (hash, IP) sampai yang sulit (TTP) | Tingkat keparahan |
| Hunting loop | Model Sqrrl: hipotesis, investigasi, ungkap TTP, perkaya analitik, berulang | Checklist sekali jalan |
| PEAK | Prepare, Execute, Act with Knowledge; tiga tipe hunt (Splunk, 2023) | TaHiTI |
| TaHiTI | Initiate, Hunt (define/refine dan execute), Finalize; menekankan abstract, backlog, handover | PEAK |
| HMM | Hunting Maturity Model, HMM0 sampai HMM4; level dari bukti, bukan klaim | Skor kualitas data |
| Hunt abstract | Rencana satu halaman: pemicu, hipotesis, data, cakupan, kriteria, handover | Laporan hunt |
| Backlog | Daftar abstract dan kandidat yang menunggu, diprioritaskan menurut intel, insiden, dan celah | Antrean tiket menurut umur |
| ABLE | Actor (opsional), Behavior, Location, Evidence | Formulir yang wajib diisi lengkap termasuk Actor |
| Kriteria sukses | Kondisi tertulis yang menandai hunt boleh ditutup | "Sampai tidak ada yang mencurigakan" |
| Time-box | Batas durasi hunt yang ditetapkan saat Prepare | Tenggat laporan |
| Empat hasil | Ditemukan, tidak ditemukan (dengan cakupan), inkonklusif, data tidak cukup | "Berhasil" dan "gagal" |
| Jinak terkonfirmasi | Cocok dengan pola tetapi sah, dengan bukti di luar query (tiket, pemilik) | "Jinak karena akunnya admin" |
| Handover | Penyerahan keluaran ke penerima yang bisa bertindak | Mengirim query mentah |
| Abstract deteksi | Usulan rule dari hunt: logika kasar, volume, FP, level, pengecualian | Rule jadi |
| Celah deteksi | Data ada, rule belum | Celah visibilitas |
| Celah visibilitas | Data tidak dikumpulkan, perilaku mustahil terlihat | Celah deteksi |
| Kartu kesiapan | Gerbang per hunt: SIAP, SIAP SEBAGIAN, TIDAK SIAP | Inventaris sumber |
| Depth dan scope | Ragam event dan field dari satu sumber; jumlah aset tercakup | Volume event |
| Feed mati | Sumber berhenti tanpa error, terlihat sebagai nol event | Host mati |
| Baseline | Gambaran normal per kelompok host dan periode, disimpan sebagai pembanding | Rata-rata seluruh lingkungan |
| Normalisasi | Menyeragamkan path, versi, folder acak, GUID, SID sebelum dihitung | Membuang data |
| Stacking dan long tail | Menghitung kombinasi nilai, lalu melihat yang paling jarang | Vonis bahwa yang langka jahat |
| First-seen | Kombinasi yang tidak ada di baseline | Kombinasi yang pertama kali ada di lingkungan |
| Prevalence | Berapa banyak host yang punya perilaku sama | Jumlah event |
| Beacon dan CV | Koneksi berulang dengan interval relatif tetap; CV mengukur keteraturan | C2 (agent sah juga beacon) |
| `tstats` dan data model | Statistik dari ringkasan terakselerasi; cepat tetapi hanya field standar | Raw search yang sama lengkapnya tanpa uji |
| Uji kesetaraan | Menjalankan raw dan `tstats` sekali di rentang sama; `resultCount` harus sama | Membandingkan `runDuration` saja |
| Job Inspector | Rincian biaya satu search job (`scanCount`, `runDuration`, komponen) | Log scheduler |
| Scheduled task | Program yang dijalankan Task Scheduler Windows pada jadwal atau pemicu | Service |
| 4698 dan 4699 | Event Security saat scheduled task dibuat dan dihapus, dari subkategori Audit Other Object Access Events [S7][S10] | Event TaskScheduler/Operational |
| `TaskName` dan root | Path task dari Task Scheduler Library; task di root bernama seperti `\NAMA` [S7] | Nama file executable |
| `TaskContent` | Isi XML definisi task: trigger, principal, dan `Command` [S7] | Command line proses pembuat |
| `ClientProcessId` | PID proses yang meminta pembuatan task, di 4698 versi 1 (Windows 10 1903 ke atas) [S7] | `ProcessGuid` Sysmon |

### 1.12 Bahan rapat Jumat untuk Dimas

Tabel berikut adalah ringkasan yang kamu kirim ke Dimas Kamis pukul 16:30, setelah lab gabungan selesai. Setiap baris merujuk bagian di atas supaya Dimas bisa membaca alasannya bila Hendra bertanya.

| Pertanyaan Dimas | Jawaban singkat | Dasar |
|---|---|---|
| Apa yang sudah dikerjakan | Tujuh hunt bernomor, kalender Selasa dan Kamis berjalan, empat hunt selesai tidak ditemukan dengan cakupan tertulis, satu inkonklusif masih terbuka, satu siap dijalankan dari agregat, `HUNT-2027-004` selesai hari ini | Bagian 1.7, Bagian F |
| Hasilnya | Belum ada temuan berbahaya; dua usulan rule, dua usulan laporan terjadwal, tiga lookup, dan daftar celah data ke Infrastruktur | Bagian 1.7 |
| Apa yang dipelajari soal data | Kuat di 214 host ber-Sysmon dan ber-audit, buta di 229 workstation; feed bisa mati diam-diam; retensi `proxy` dan `dns` 30 hari | Bagian 1.8 |
| Templat L1 | Templat usulan dengan bagian pengusul dan bagian hunter; ditinjau setiap Selasa pagi | Bagian 1.10 |
| Templat hunter | Abstract dan laporan final di `jab-hunt` | Bagian 1.9 |
| Istilah wajib | Glosarium satu halaman | Bagian 1.11 |
| Contoh utuh | `HUNT-2027-004` dari abstract sampai handover dan dua abstract baru | Bagian A sampai F di lab gabungan |
| Yang belum bisa | Apa pun di 229 workstation tanpa audit kecuali lewat MDE terbatas; keadaan host secara massal; event mentah Linux; baseline jaringan lebih dari 30 hari | Bagian 1.8, Bagian F |

Satu kalimat untuk Hendra: program sudah berjalan sesuai kalender dan setiap hunt menghasilkan keluaran yang bisa diaudit, tetapi kesimpulan "tidak ditemukan" sejauh ini hanya berlaku untuk sekitar 40% workstation, dan menutup celah itu adalah keputusan telemetri, bukan keputusan hunting. Penilaian ulang level HMM dilakukan di evaluasi Q1 Rabu 2027-03-31, bukan di rapat besok.

## 2-4. Lab gabungan dan troubleshooting

Lab gabungan ini menjawab pertanyaan kelima Dimas dengan satu hunt nyata di PT JAB, `HUNT-2027-004`, dikerjakan Kamis 2027-02-18 dari pukul 08:40 sampai 15:30. Semua isi Bagian A sampai F fiktif dan merupakan keluaran ilustrasi; query ditulis untuk Splunk PT JAB (`jkt-splunk-sh01`, role `jab_hunter`, tampilan WIB). Bagian G adalah latihan di VM lab pribadimu, dan Bagian H berisi skenario keputusan.

**Asumsi data untuk semua query:** log Security Windows masuk `index=wineventlog` dengan `sourcetype=XmlWinEventLog`, dan field `EventData` terekstrak dengan nama aslinya (`SubjectUserName`, `TaskName`, `TaskContent`, `ClientProcessId`). Sysmon masuk `index=sysmon` dengan field `Image`, `ParentImage`, `User`, `ProcessId`; PowerShell 4104 masuk `index=powershell` dengan field `ScriptBlockText`. Nama `host` sama di ketiga index karena dikirim forwarder yang sama. Isi `TaskContent` bisa tampil sebagai XML biasa atau ter-escape (`&lt;Command&gt;`), bergantung add-on; cek satu event mentah sebelum menjalankan query.

### Teknik yang diburu: T1053.005 Scheduled Task

Scheduled task adalah fitur Windows untuk menjalankan program pada jadwal atau pemicu tertentu (saat boot, saat logon, setiap N menit). Di ATT&CK v20, T1053.005 tercatat di tiga taktik: Execution, Persistence, dan Privilege Escalation [S6]. Task bisa dibuat lewat `schtasks`, GUI Task Scheduler, wrapper .NET, library netapi32, WMI (termasuk cmdlet `Invoke-CimMethod` dengan kelas `PS_ScheduledTask`), dan COM [S6]. Jalur pembuatan menentukan jejak yang terlihat. Tabel berikut adalah alasan hunt ini memakai lebih dari satu sumber; baca kolom 4698, karena itulah satu-satunya kolom yang terisi untuk semua jalur.

| Jalur pembuatan | Jejak di Sysmon EID 1 | Jejak di Security 4698 | Jejak lain |
|---|---|---|---|
| `schtasks.exe /create` | Proses `schtasks.exe` dengan `/create`, beserta parent-nya | Ada | TaskScheduler/Operational 106 bila channel itu dikumpulkan |
| PowerShell `Register-ScheduledTask` di proses baru | `powershell.exe` (cmdlet terlihat di command line hanya bila ditulis inline); tidak ada `schtasks.exe` | Ada | PowerShell 4104 memuat cmdlet |
| PowerShell remoting | Tidak ada proses baru; perintah berjalan di dalam `wsmprovhost.exe` | Ada, `ClientProcessId` menunjuk `wsmprovhost.exe` | 4104 di host tujuan, 4624 tipe 3 sebelumnya |
| GUI, installer, WMI/CIM, atau COM langsung dari program | Tidak ada `schtasks.exe`; yang terlihat hanya proses pembuatnya bila PID-nya dikorelasikan | Ada | Bergantung program pembuatnya |
| Manipulasi registry langsung (task tersembunyi) | Tidak ada pembuatan lewat Task Scheduler | Tidak ada | Perubahan registry (Sysmon EID 13) |

Pelajarannya sama dengan Day 03: hunt yang hanya mencari `schtasks.exe` buta terhadap sebagian besar jalur. Event 4698 ditulis layanan Task Scheduler apa pun jalur API-nya, sehingga paling lengkap untuk pertanyaan "task apa yang dibuat", dengan dua syarat. Pertama, subkategori Audit Other Object Access Events harus aktif; Microsoft merekomendasikan audit Success subkategori ini untuk domain controller, member server, dan workstation, terutama karena event scheduled task [S9]. Di PT JAB itu berarti 214 host. Kedua, ATT&CK mencatat task yang disembunyikan lewat registry (misalnya menghapus nilai Security Descriptor, yang butuh hak SYSTEM) [S6], dan katalog Atomic Red Team memuat satu test yang menambahkan task lewat manipulasi registry tanpa event 4698 [S8]. Jalur itu berada di luar cakupan hunt ini.

Isi event 4698 yang relevan untuk hunt [S7]:

| Field | Isi | Kegunaan |
|---|---|---|
| `SubjectUserName`, `SubjectDomainName` | Akun yang meminta pembuatan task; task yang dibuat proses SYSTEM tercatat atas nama akun komputer (`HOST$`) | Stacking per pembuat |
| `SubjectLogonId` | Logon ID sesi pembuat | Korelasi ke 4624 untuk tahu asal logon |
| `TaskName` | Path task di Task Scheduler Library, misalnya `\Microsoft\Windows\...` atau `\NamaTask` | Task di root lebih sering dibuat manual atau oleh malware |
| `TaskContent` | XML definisi task: trigger, principal (termasuk `LogonType`), dan `Command` | Apa yang dijalankan dan dengan akun apa |
| `ClientProcessId`, `ParentProcessId`, `ClientProcessStartKey` | Tambahan di event versi 1, Windows 10 versi 1903 ke atas | Korelasi ke Sysmon EID 1 di host yang sama |

Microsoft memberi tiga rekomendasi monitoring untuk 4698: pantau semua pembuatan task terutama di host kritis, pantau task baru di root Task Scheduler Library, dan beri alert bila `TaskContent` memuat `LogonType` bernilai `Password`, karena password akun yang menjalankan task tersimpan di Credential Manager dan bisa diambil dengan hak administrator [S7]. Event 4699 punya field yang sama untuk task yang dihapus; Microsoft menyebut penghapusan jarang terjadi dan penghapusan task di root bisa menandakan aktivitas berbahaya [S10].

Event 4698 tidak memuat nama proses pembuat, hanya PID-nya. Untuk mengetahui proses mana yang membuat task, korelasikan `ClientProcessId` dengan `ProcessId` di Sysmon EID 1 pada host yang sama. PID bisa dipakai ulang Windows, dan `ClientProcessStartKey` tidak dicatat Sysmon, jadi korelasi ini pendekatan: ambil proses dengan PID sama yang paling akhir dimulai sebelum task dibuat, lalu cek ulang setiap baris yang akan diberi label (Bagian D).

### Bagian A: abstract final `HUNT-2027-004`

Abstract Day 03 berstatus "menunggu kesiapan data". Kartu kesiapan Day 04 memberinya putusan SIAP SEBAGIAN untuk 214 host. Pagi ini abstract-nya diperbarui (define/refine TaHiTI) dengan rentang absolut, ambang, dan time-box.

```
ID             : HUNT-2027-004
Dibuat         : 2027-02-04 (Kamis); diperbarui 2027-02-18 08:40; pemilik: <kamu>, reviewer: Dimas Prasetyo
Trigger        : Intel - brief forum berbagi intel ISP regional (2027-02-04): persistence lewat scheduled task;
                 celah deteksi - belum ada rule untuk task yang dibuat parent/user tidak lazim
Tipe (PEAK)    : Hypothesis-driven, dengan stacking task dan stacking pembuat
Hipotesis      : Ada scheduled task yang dibuat di host Windows PT JAB oleh parent process atau user
                 yang tidak lazim untuk membuat task, tanpa memicu alert.
ABLE           : Actor kampanye di brief, tidak dinamai | Behavior T1053.005 | Location server Windows dan
                 workstation OU Workstations-EDR, prioritas server data center | Evidence 4698 (TaskName,
                 TaskContent, ClientProcessId), Sysmon EID 1 (schtasks.exe, proses pembuat), 4104
ATT&CK         : T1053.005 (Execution, Persistence, Privilege Escalation), ATT&CK v20
Data           : index=wineventlog EventCode=4698, 214 host ber-audit (61 server, 153 workstation),
                 Senin 2027-02-01 00:00 sampai Kamis 2027-02-18 00:00 WIB (17 hari);
                 index=sysmon EventCode=1 untuk korelasi pembuat, proses dimulai sejak 2027-01-01 00:00;
                 index=powershell EventCode=4104 untuk jalur PowerShell
Kesiapan data  : SIAP SEBAGIAN (kartu Day 04): 229 workstation tanpa 4698 dan tanpa Sysmon;
                 JKT-WS-0532 tanpa Sysmon sejak 2027-02-02 10:14
Perubahan      : rentang 28 hari di abstract Day 03 dipersempit ke 17 hari Februari karena time-box
                 satu hari; rentang ini sudah memuat Patch Tuesday 2027-02-09 dan rollout JAB AssetScan
                 2027-02-12, sehingga pembuatan task sah yang ramai ikut terlihat. 4698 sebelum 1 Februari
                 ditulis di luar cakupan
Di luar cakupan: 229 workstation di luar OU (Jakarta 148, Bandung 58, POP 23); 4698 sebelum 1 Februari;
                 task tersembunyi lewat registry (tanpa 4698); perubahan task (4702); penghapusan task (4699)
Teknik analisis: stacking task (nama dinormalisasi, root, command, akun) + stacking pembuat lewat
                 ClientProcessId; searching schtasks.exe dan Register-ScheduledTask
Kriteria sukses: semua kombinasi pembuat dengan hosts <= 5 ditinjau dan dilabeli; setiap nama task di root
                 ditinjau; setiap task dengan LogonType Password ditinjau; event tanpa korelasi pembuat
                 dijelaskan
FP yang diduga : Windows Update dan Office, updater browser, OneDrive per pengguna, installer software IT,
                 admin Infrastruktur dengan tiket change, helpdesk
Time-box       : satu hari hunting (Kamis 2027-02-18)
Handover       : IR (Dimas) bila ditemukan; Sari Kusuma untuk usulan detection; Agung Prabowo untuk celah
                 audit dan risiko konfigurasi; backlog untuk pertanyaan baru
Status         : berjalan
```

Ambang `hosts <= 5` dipilih dari distribusi pembuat (Bagian D): kombinasi pembuat yang sah karena rollout atau update tersebar di puluhan sampai ratusan host, sedangkan yang dibuat tangan atau oleh satu aplikasi lokal muncul di satu sampai beberapa host.

### Bagian B: cek cakupan 4698 terhadap daftar aset

Langkah pertama adalah kartu kesiapan dalam bentuk angka: berapa host yang semestinya menghasilkan 4698, dan berapa yang benar-benar menghasilkannya dalam rentang hunt. Pembandingnya daftar aset, bukan log lain (Day 04 bagian 1.3).

**Tujuan:** menghitung host dengan 4698 per kelompok (server, workstation OU `Workstations-EDR`, workstation lain) terhadap `jab_assets.csv`.

```
index=wineventlog sourcetype=XmlWinEventLog EventCode=4698
    earliest="02/01/2027:00:00:00" latest="02/18/2027:00:00:00"
| stats count AS ev4698 BY host
| eval nt_host=upper(host)
| fields nt_host ev4698
| append
    [| inputlookup jab_assets.csv
     | eval nt_host=upper(nt_host)
     | fields nt_host category ou]
| stats sum(ev4698) AS ev4698 values(category) AS category values(ou) AS ou BY nt_host
| where isnotnull(category)
| fillnull value=0 ev4698
| eval kelompok=case(category="server", "server",
                     match(ou, "Workstations-EDR"), "workstation OU Workstations-EDR",
                     true(), "workstation lain")
| stats count AS hosts_ad count(eval(ev4698>0)) AS hosts_4698 sum(ev4698) AS events BY kelompok
```

Tabel berikut menjelaskan bagian yang menentukan hasil.

| Bagian | Fungsi |
|---|---|
| `EventCode=4698` di base search | Term `4698` jarang muncul di event lain, sehingga base search selektif dan raw search cukup murah |
| `append [ inputlookup jab_assets.csv ]` | Menambahkan semua host dari Active Directory sebagai pembanding |
| `stats ... BY nt_host` lalu `fillnull value=0` | Host di AD yang tidak punya 4698 mendapat nol, bukan hilang dari hasil |
| `case(...)` | Tiga kelompok yang berbeda konfigurasi auditnya |
| `count(eval(ev4698>0))` | Jumlah host yang benar-benar menghasilkan 4698 |

Keluaran ilustrasi:

```
kelompok                          hosts_ad  hosts_4698  events
server                            61        55          612
workstation OU Workstations-EDR   153       151         1.624
workstation lain                  229       0           0
```

**Cara membaca hasil:** 2.236 event 4698 dari 206 host. Enam server dan dua workstation tanpa 4698 dalam 17 hari tidak berarti audit-nya mati; task memang tidak dibuat di setiap host (jebakan event jarang, Day 04 bagian 2.4). Sebaliknya, nol dari 229 workstation selama 17 hari yang mencakup Patch Tuesday konsisten dengan konfigurasi: GPO audit tidak berlaku di sana. Di kelompok inilah celah datanya, dan scheduled task di 229 workstation itu tidak terlihat sama sekali oleh hunt ini.

**Variasi:** cek versi event untuk tahu host mana yang punya `ClientProcessId`: `index=wineventlog EventCode=4698 earliest=... latest=... | eval has_cpid=if(isnotnull(ClientProcessId), "ya", "tidak") | stats dc(host) AS hosts count BY has_cpid`. Di PT JAB hasilnya 4 server tanpa field itu; keempatnya Windows Server 2019, yang buildnya lebih tua dari Windows 10 versi 1903.

**Kapan gagal:** lookup aset basi sehingga host yang sudah pensiun terhitung "tanpa 4698"; nama `ou` di lookup berbeda format (DN lengkap atau nama pendek), sehingga `match` tidak menemukan apa pun dan semua workstation masuk "workstation lain".

### Bagian C: stacking task baru

Langkah ini menjawab "task apa yang dibuat": stacking nama task yang dinormalisasi, letaknya (root atau subfolder), command yang dijalankan, dan akun pembuatnya.

**Tujuan:** memperkecil 2.236 event menjadi daftar nama task yang bisa ditinjau, dengan yang paling sedikit host di atas.

```
index=wineventlog sourcetype=XmlWinEventLog EventCode=4698
    earliest="02/01/2027:00:00:00" latest="02/18/2027:00:00:00"
| eval task_n=lower(replace(TaskName, "\\\\", "/"))
| eval task_n=replace(task_n, "[{][0-9a-f-]{36}[}]", "{<guid>}")
| eval task_n=replace(task_n, "s-1-5-21-[0-9-]+", "<sid>")
| eval is_root=if(match(task_n, "^/[^/]+$"), "root", "subfolder")
| rex field=TaskContent "(?:<|&lt;)Command(?:>|&gt;)(?<task_cmd>[^<&]+)"
| eval cmd_n=lower(replace(task_cmd, "\\\\", "/"))
| eval cmd_n=replace(cmd_n, "^c:/users/[^/]+/", "c:/users/<user>/")
| eval creator_acct=if(match(SubjectUserName, "[$]$"), "<komputer>$", lower(SubjectUserName))
| stats count AS events dc(host) AS hosts dc(creator_acct) AS n_creators values(creator_acct) AS creators
        values(cmd_n) AS commands BY task_n is_root
| sort hosts
```

Tabel berikut menjelaskan baris yang paling menentukan hasil.

| Baris | Fungsi |
|---|---|
| `replace(TaskName, "\\\\", "/")` | Backslash menjadi `/`. Di string SPL, `\\\\` menjadi regex `\\` yang cocok dengan satu backslash |
| `replace(task_n, "[{][0-9a-f-]{36}[}]", "{<guid>}")` | GUID di nama task updater (berbeda per host) diseragamkan; kurung kurawal ditulis sebagai kelas karakter supaya tidak bergantung aturan escape |
| `replace(task_n, "s-1-5-21-[0-9-]+", "<sid>")` | SID pengguna di nama task per pengguna diseragamkan |
| `match(task_n, "^/[^/]+$")` | Task di root Task Scheduler Library: tepat satu segmen setelah `/` [S7] |
| `rex ... "(?:<\|&lt;)Command(?:>\|&gt;)..."` | Mengambil isi `Command` dari XML, baik ter-escape maupun tidak |
| `replace(cmd_n, "^c:/users/[^/]+/", ...)` | Folder profil pengguna diseragamkan, seperti macro `jab_norm_parentchild` |
| `creator_acct` | Akun komputer (`HOST$`, artinya proses SYSTEM) digabung menjadi satu nilai; akun manusia tetap per nama |

Keluaran ilustrasi (82 baris; ditampilkan yang paling sedikit host dan semua nama di root):

```
Event 4698 dalam rentang      : 2.236 dari 206 host
Nama task unik (dinormalisasi): 82   (tanpa normalisasi GUID dan SID: 376)
Nama task di root             : 6 nama, 334 event

task_n                                          is_root    events hosts creators          commands
/jab/infra/nic-fw-check                         subfolder  2      1     adm.hari          c:/tools/nicutil-4.2/nicutil.exe
/netcapture-rotate                              root       1      1     arif.kurniawan    c:/users/<user>/tools/capture-rotate.bat
/jab/helpdesk/clearteamscache                   subfolder  1      1     adm.taufik        c:/windows/system32/windowspowershell/v1.0/powershell.exe
/jab/arsip-template-mingguan                    subfolder  1      1     adm.agung         c:/windows/system32/robocopy.exe
/jab payroll/slipsync                           subfolder  4      4     <komputer>$       c:/program files/jab payroll client/slipsync.exe
(9 nama /microsoft/windows/..., 1-5 host, semua <komputer>$, semua command di c:/windows/system32/)
/googleupdatetaskmachinecore{<guid>}            root       11     9     <komputer>$       c:/program files (x86)/google/update/googleupdate.exe
/googleupdatetaskmachineua{<guid>}              root       11     9     <komputer>$       c:/program files (x86)/google/update/googleupdate.exe
/onedrive standalone update task-<sid>          root       97     58    (58 akun pengguna) c:/users/<user>/appdata/local/microsoft/onedrive/onedrivestandaloneupdater.exe
/microsoftedgeupdatetaskmachinecore{<guid>}     root       107    107   <komputer>$       c:/program files (x86)/microsoft/edgeupdate/microsoftedgeupdate.exe
/microsoftedgeupdatetaskmachineua{<guid>}       root       107    107   <komputer>$       c:/program files (x86)/microsoft/edgeupdate/microsoftedgeupdate.exe
/jab/assetscan collect                          subfolder  149    149   <komputer>$       c:/program files/jab assetscan/assetscan.exe
(62 nama /microsoft/... lain, 6-206 host, total 1.745 event bersama 9 nama di atas)
```

**Cara membaca hasil:** normalisasi mengubah 376 nama menjadi 82. Tanpa itu, setiap updater Edge di setiap host terlihat sebagai task "unik" dan memenuhi daftar. Enam nama di root terdiri dari lima updater vendor (Google, OneDrive, Edge) dan satu task buatan tangan, `/netcapture-rotate`, yang menjalankan file `.bat` dari folder profil pengguna. Kombinasi "task di root yang menjalankan command dari folder pengguna" persis pola yang disebut rekomendasi Microsoft dan pola persistence yang lazim, jadi baris itu wajib diperdalam (Bagian F). OneDrive juga menjalankan command dari folder pengguna, tetapi polanya identik di 58 host dan berasal dari updater bertanda tangan.

**Variasi:** rekomendasi Microsoft untuk `LogonType` Password [S7]:

```
index=wineventlog sourcetype=XmlWinEventLog EventCode=4698
    earliest="02/01/2027:00:00:00" latest="02/18/2027:00:00:00"
| where match(TaskContent, "LogonType(>|&gt;)Password")
| table _time host SubjectUserName TaskName
```

Keluaran ilustrasi: satu baris, `jkt-filesrv01`, `adm.agung`, `\JAB\Arsip-Template-Mingguan`, Rabu 2027-02-10 19:40.

**Kapan gagal:** add-on tidak mengekstrak `TaskContent` sehingga `cmd_n` kosong untuk semua baris; nama task vendor memakai pola GUID lain (tanpa kurung kurawal) sehingga normalisasi tidak berlaku; atau task penyerang meniru nama updater vendor, sehingga hanya terlihat dari command atau pembuatnya yang berbeda. Untuk kasus terakhir, kolom `commands` dan `n_creators` di baris vendor harus berisi satu nilai yang wajar; dua nilai atau lebih di baris updater adalah alasan memecah baris itu.

### Bagian D: siapa pembuatnya, lewat `ClientProcessId`

Langkah ini menjawab inti hipotesis: parent atau proses apa yang membuat task. Polanya adalah persempit lalu perdalam (Day 06 bagian 2.1): ambil dulu pasangan host dan PID dari 4698 yang jumlahnya kecil, lalu tarik Sysmon EID 1 hanya untuk pasangan itu.

**Tujuan:** menempelkan nama proses pembuat, parent-nya, dan user-nya ke setiap event 4698, lalu stacking per kombinasi pembuat.

```
(index=wineventlog sourcetype=XmlWinEventLog EventCode=4698)
OR (index=sysmon sourcetype=XmlWinEventLog EventCode=1
    [ search index=wineventlog sourcetype=XmlWinEventLog EventCode=4698
          earliest="02/01/2027:00:00:00" latest="02/18/2027:00:00:00"
      | dedup host ClientProcessId
      | rename ClientProcessId AS ProcessId
      | fields host ProcessId ])
earliest="01/01/2027:00:00:00" latest="02/18/2027:00:00:00"
| eval pid=if(EventCode=4698, ClientProcessId, ProcessId)
| eval p_image=if(EventCode=1, Image, null()), p_parent=if(EventCode=1, ParentImage, null()),
       p_user=if(EventCode=1, User, null()), p_start=if(EventCode=1, _time, null())
| sort 0 host pid _time
| streamstats last(p_image) AS creator_image last(p_parent) AS creator_parent
              last(p_user) AS creator_user last(p_start) AS creator_start BY host pid
| where EventCode=4698 AND _time >= strptime("02/01/2027:00:00:00", "%m/%d/%Y:%H:%M:%S")
| eval creator_image=if(isnull(creator_start), "tidak terkorelasi", lower(creator_image))
| eval creator_parent=if(isnull(creator_start), "-", lower(creator_parent))
| eval acct=case(match(SubjectUserName, "[$]$"), "sistem",
                 match(SubjectUserName, "^adm[.]"), "admin",
                 true(), "pengguna")
| stats count AS events dc(host) AS hosts values(SubjectUserName) AS subjects
        BY creator_image creator_parent acct
| sort hosts
```

Tabel berikut menjelaskan bagian query; perhatikan baris subsearch dan `streamstats`, karena di dua baris itulah biaya dan ketepatannya ditentukan.

| Bagian | Fungsi |
|---|---|
| Subsearch `[ search ... EventCode=4698 ... ]` | Berjalan lebih dulu sebagai job sendiri, lalu hasilnya menjadi kriteria untuk search utama [S13]. Di sini ia membatasi Sysmon EID 1 ke pasangan `host` dan `ProcessId` milik pembuat task, sehingga yang ditarik hanya beberapa ribu event, bukan belasan juta |
| `dedup host ClientProcessId` | Satu baris per pasangan; event 4698 tanpa `ClientProcessId` (event versi 0) ikut terbuang dari subsearch |
| `earliest="01/01/2027..."` di search utama | Proses pembuat bisa dimulai jauh sebelum task dibuat (misalnya `svchost.exe` sejak boot), jadi rentang proses dibuka sampai 1 Januari |
| `eval pid=...` dan `p_*` | Menyamakan nama field PID dari dua sumber, dan menyiapkan nilai Sysmon yang kosong di event 4698 |
| `sort 0 host pid _time` | Urut naik per host dan PID; `0` berarti tanpa batas jumlah baris |
| `streamstats last(...) BY host pid` | Untuk setiap event, nilai terakhir yang terisi sebelumnya; untuk 4698 itu proses ber-PID sama yang paling akhir dimulai sebelum task dibuat |
| `where EventCode=4698 AND _time >= ...` | Hanya 4698 Februari yang dilaporkan |
| `acct=case(...)` | Akun komputer berarti proses SYSTEM; akun `adm.` adalah akun admin PT JAB |

Subsearch secara default mengembalikan paling banyak 10.000 hasil dan berjalan paling lama 60 detik, lalu hasilnya difinalisasi [S13]. Dengan 2.236 event 4698, jumlah pasangan host dan PID jauh di bawah batas itu. Untuk rentang lebih panjang atau jumlah host lebih besar, cek pesan peringatan subsearch di hasil search, dan lihat kriteria yang dihasilkan subsearch di komponen `remoteSearch` Job Inspector [S13].

Keluaran ilustrasi:

```
creator_image                                              creator_parent                         acct      events hosts
c:/windows/system32/schtasks.exe                           c:/windows/system32/cmd.exe            admin     2      1
c:/windows/system32/schtasks.exe                           c:/windows/system32/cmd.exe            pengguna  1      1
c:/windows/system32/wsmprovhost.exe                        c:/windows/system32/svchost.exe        admin     1      1
c:/windows/system32/mmc.exe                                c:/windows/explorer.exe                admin     1      1
tidak terkorelasi                                          -                                      sistem    31     5
c:/program files (x86)/google/update/googleupdate.exe      c:/windows/system32/services.exe       sistem    22     9
c:/program files/common files/microsoft shared/clicktorun/officeclicktorun.exe
                                                           c:/windows/system32/services.exe       sistem    51     51
c:/users/<user>/appdata/local/microsoft/onedrive/<ver>/onedrivesetup.exe
                                                           c:/users/<user>/appdata/local/microsoft/onedrive/onedrive.exe
                                                                                                  pengguna  97     58
c:/program files (x86)/microsoft/edgeupdate/microsoftedgeupdate.exe
                                                           c:/windows/system32/services.exe       sistem    214    107
c:/windows/system32/msiexec.exe                            c:/windows/system32/services.exe       sistem    152    148
c:/windows/system32/mousocoreworker.exe                    c:/windows/system32/svchost.exe        sistem    262    201
c:/windows/system32/svchost.exe                            c:/windows/system32/services.exe       sistem    1.402  201

Event 4698 dengan pembuat terkorelasi : 2.205 dari 2.236 (98,6%)
```

**Cara membaca hasil:**

- Kombinasi pembuat yang tersebar luas cocok dengan pembuatan task sah: layanan Windows dan Windows Update (`svchost.exe`, `mousocoreworker.exe`) di 201 host setelah Patch Tuesday 2027-02-09, `msiexec.exe` sebagai SYSTEM di 148 host (installer JAB AssetScan Jumat 2027-02-12 pagi, ditambah installer aplikasi payroll HR Senin 2027-02-08 di 4 host yang juga menerima AssetScan), updater Office, Edge, Google, dan OneDrive.
- Empat kombinasi berada di bawah ambang `hosts <= 5`: `schtasks.exe` dari `cmd.exe` oleh admin (1 host), `schtasks.exe` dari `cmd.exe` oleh pengguna biasa (1 host), `wsmprovhost.exe` oleh admin (1 host), dan `mmc.exe` oleh admin (1 host). Empat kombinasi itu, lima event, ditinjau satu per satu di Bagian F.
- Tidak ada pembuat dari kelompok yang paling dicari hipotesis: aplikasi Office, browser, pembaca PDF, `wscript.exe`, `cscript.exe`, `mshta.exe`, atau proses dari folder `Temp` dan `Downloads`. Tidak ada akun pengguna biasa yang membuat task di server.
- 31 event "tidak terkorelasi" di 5 host punya dua penyebab yang bisa dijelaskan: 9 event di `JKT-WS-0532` (Sysmon diam sejak 2 Februari, `ClientProcessId` ada tetapi tidak ada proses untuk dicocokkan), dan 22 event di 4 server Windows Server 2019 yang 4698-nya versi 0 tanpa `ClientProcessId` (Bagian B). Keduanya ditinjau dengan cara lain di Bagian F.

**Variasi:** tambahkan `eval same_user=if(lower(mvindex(split(creator_user, "\\"), -1))=lower(SubjectUserName), "ya", "tidak")` sebelum `stats`, lalu cari baris `tidak` untuk akun manusia. Akun Sysmon dan akun 4698 yang berbeda untuk task buatan manusia berarti korelasi PID kemungkinan salah pasang.

**Kapan gagal:** PID dipakai ulang di antara proses pembuat dan proses lain yang dimulai belakangan tetapi sebelum task dibuat, sehingga proses yang salah ditempelkan (cek ulang per baris yang akan dilabel); proses pembuat dimulai sebelum 1 Januari sehingga tidak terkorelasi; format `ClientProcessId` di add-on-mu heksadesimal sementara `ProcessId` Sysmon desimal (contoh XML Microsoft memakai desimal [S7]; cek di event mentah); atau subsearch melewati batas hasil dan dipotong diam-diam.

### Bagian E: jalur `schtasks.exe` dan PowerShell

Langkah ini memeriksa dua jalur yang disebut di Evidence ABLE dari sisi proses dan skrip, sekaligus menjadi pembanding untuk Bagian D: jumlah `schtasks /create` di Sysmon harus cocok dengan jumlah 4698 yang pembuatnya `schtasks.exe`.

**Tujuan:** stacking eksekusi `schtasks.exe` per parent dan aksi, lalu mencari cmdlet pembuat task di command line dan di script block.

```
index=sysmon sourcetype=XmlWinEventLog EventCode=1 schtasks.exe Image="*\\schtasks.exe"
    earliest="02/01/2027:00:00:00" latest="02/18/2027:00:00:00"
| eval cl=lower(CommandLine)
| eval action=case(match(cl, "[/-]create"), "create", match(cl, "[/-]delete"), "delete",
                   match(cl, "[/-]change"), "change", true(), "lain")
| stats count AS runs dc(host) AS hosts values(host) AS host_list values(User) AS users
        BY ParentImage action
| sort action runs
```

| Bagian | Fungsi |
|---|---|
| Term literal `schtasks.exe` sebelum filter `Image="*\\..."` | Wildcard di depan mahal; term literal membuat base search selektif (Day 06 bagian 1.3) |
| `match(cl, "[/-]create")` | `schtasks` menerima awalan `/` maupun `-` untuk switch-nya |
| `stats ... BY ParentImage action` | Siapa yang memanggil `schtasks.exe`, untuk apa |

Keluaran ilustrasi:

```
ParentImage                      action  runs  hosts  host_list                 users
C:\Windows\System32\cmd.exe      create  3     2      JKT-WS-0552, jkt-mgmt01   JAB\arif.kurniawan, JAB\adm.hari
C:\Windows\System32\cmd.exe      delete  1     1      jkt-mgmt01                JAB\adm.hari
C:\Windows\System32\cmd.exe      lain    38    11     (11 host)                 (skrip helpdesk dan admin, /query)
```

Tiga `/create` cocok dengan tiga event 4698 yang pembuatnya `schtasks.exe` di Bagian D (dua di `jkt-mgmt01`, satu di `JKT-WS-0552`). Kecocokan ini adalah uji silang yang murah: bila Sysmon mencatat `/create` tanpa 4698 pasangannya di host ber-audit, ada masalah audit di host itu.

Jalur PowerShell di command line proses dan di script block:

```
index=sysmon sourcetype=XmlWinEventLog EventCode=1 earliest="02/01/2027:00:00:00" latest="02/18/2027:00:00:00"
    (CommandLine="*Register-ScheduledTask*" OR CommandLine="*New-ScheduledTask*")
| stats count BY host User ParentImage
```

```
index=powershell EventCode=4104 earliest="02/01/2027:00:00:00" latest="02/18/2027:00:00:00"
    (Register-ScheduledTask OR New-ScheduledTaskAction)
| stats count min(_time) AS first BY host UserID
| convert ctime(first)
```

Keluaran ilustrasi: nol baris di Sysmon EID 1; satu host di 4104, `JKT-WS-0611`, Senin 2027-02-15 10:32, dengan `UserID` milik `adm.taufik`. Nol baris di EID 1 bukan berarti tidak ada task lewat PowerShell: task itu dibuat lewat PowerShell remoting, sehingga perintah berjalan di dalam `wsmprovhost.exe` dan tidak pernah muncul sebagai command line proses baru. Itulah sebabnya Bagian D menemukan `wsmprovhost.exe` sebagai pembuat. Nama field user di 4104 bisa berbeda (`UserID` berisi SID di XML); cek di event mentah.

**Kapan gagal:** filter `CommandLine` dengan wildcard di kedua sisi atas seluruh EID 1 tujuh belas hari mahal; jalankan di luar jam puncak atau persempit ke `Image="*\\powershell.exe"` dulu. Penyerang juga bisa memakai alias atau memecah nama cmdlet, sehingga pencarian string di 4104 tidak lengkap; 4698 tetap pembanding utamanya.

### Bagian F: label, laporan, handover, dan dua abstract baru

Setiap baris yang memenuhi kriteria sukses diberi label dengan bukti di luar query, seperti di Day 02 bagian 2.5.

- **`\JAB\Infra\nic-fw-check` di `jkt-mgmt01` oleh `adm.hari`: jinak terkonfirmasi.** Rabu 2027-02-10 14:21 `schtasks /create` dari `cmd.exe` membuat task harian 06:00 sebagai SYSTEM yang menjalankan `C:\Tools\nicutil-4.2\nicutil.exe --check`, utilitas NIC yang diunduh lewat `certutil` pada 21 Januari (`HUNT-2027-002`). Task dihapus 14:23 karena jam salah, lalu dibuat ulang 14:24. Sesuai tiket change lanjutan pembaruan firmware NIC yang disetujui Agung. Catatan: pola "buat, hapus, buat lagi" dalam tiga menit ini sah, dan akan muncul di hunt penghapusan task (`HUNT-2027-008`).
- **`\NetCapture-Rotate` di `JKT-WS-0552` oleh `arif.kurniawan`: jinak terkonfirmasi.** Senin 2027-02-15 16:05, task di root yang menjalankan `C:\Users\arif.kurniawan\Tools\capture-rotate.bat` setiap jam, dibuat lewat `schtasks.exe` dari `cmd.exe` oleh akun pengguna biasa. Sysmon EID 11 mencatat file `.bat` dibuat `notepad.exe` tiga menit sebelumnya. Isinya merotasi file capture Wireshark yang dipasang Arif pada 9 Februari (`HUNT-2027-006`). Dikonfirmasi ke Arif dan Bambang Hartono. Catatan: dari semua baris, inilah yang paling mirip persistence penyerang (root, folder pengguna, akun biasa), dan ia akan menjadi satu-satunya false positive usulan rule di bawah. Rekomendasi ke Bambang: skrip alat NOC ditaruh di lokasi yang dikelola, bukan di profil pengguna.
- **`\JAB\Helpdesk\ClearTeamsCache` di `JKT-WS-0611` oleh `adm.taufik`: jinak terkonfirmasi.** Senin 2027-02-15 10:32 lewat PowerShell remoting; 4104 memuat `Register-ScheduledTask` untuk task saat logon yang menjalankan `C:\ProgramData\JAB\Helpdesk\clear-teams-cache.ps1`. Event 4624 tipe 3 dari `JKT-WS-0583` (workstation helpdesk Taufik) satu menit sebelumnya. Sesuai tiket helpdesk gangguan Teams. Catatan: remoting dari workstation helpdesk, bukan dari `JKT-JUMP01`, relevan untuk kandidat backlog "eksekusi jarak jauh dari host selain `JKT-JUMP01`" dan dicatat di kandidat itu.
- **`\JAB\Arsip-Template-Mingguan` di `jkt-filesrv01` oleh `adm.agung`: jinak terkonfirmasi, dengan risiko konfigurasi.** Rabu 2027-02-10 19:40 lewat GUI Task Scheduler (`mmc.exe`); task mingguan menjalankan `robocopy.exe` dari share template ke share arsip sebagai akun layanan `svc_filesync` dengan `LogonType` Password. Sesuai tiket change. Risiko: password akun itu tersimpan di Credential Manager server dan bisa diambil siapa pun yang punya hak administrator di `jkt-filesrv01` [S7]. Rekomendasi ke Agung: ganti dengan akun yang tidak menyimpan password (misalnya group Managed Service Account), cek dukungannya untuk task ini.
- **`\JAB Payroll\SlipSync` di 4 workstation HR: jinak terkonfirmasi.** Dibuat `msiexec.exe` sebagai SYSTEM saat aplikasi payroll dipasang Senin 2027-02-08, sesuai tiket instalasi yang sudah dikonfirmasi di `HUNT-2027-006`; command di `C:\Program Files\`.
- **Updater di root (Edge, Google, OneDrive): jinak sebagai kelompok.** Pembuatnya updater vendor dengan parent yang wajar (Bagian D), command di path standar vendor, satu nilai command dan satu kelompok pembuat per nama, dan pola tersebar sesuai pemasangan software.
- **9 nama `\Microsoft\Windows\...` dengan 1-5 host: jinak.** Dibuat `svchost.exe` atau `mousocoreworker.exe` sebagai SYSTEM, command di `C:\Windows\System32\`, di server dengan peran tertentu.
- **31 event tidak terkorelasi: jinak berdasarkan kesamaan isi, pembuat tidak terverifikasi.** Di `JKT-WS-0532`, 9 event berupa task AssetScan dan 8 task Windows Update; nama task, command, dan argumennya sama persis dengan host lain. Di 4 server Windows Server 2019, 22 event berupa task Windows yang sama persis dengan server lain berperan sama. Label ini lebih lemah dari yang lain dan ditulis apa adanya di laporan.

Validasi hipotesis: tidak terbukti. Tidak ada task yang dibuat oleh parent atau user yang tidak lazim tanpa penjelasan, di host ber-audit, selama 17 hari. Tidak ada eskalasi ke IR.

```
ID            : HUNT-2027-004                         Selesai: Kamis 2027-02-18 15:30
Hasil         : Tidak ditemukan aktivitas berbahaya (hipotesis tidak terbukti)
Ringkasan     : Semua pembuatan scheduled task di 214 host ber-audit selama 1-17 Februari berasal dari
                layanan Windows, updater vendor, installer IT, dan empat pembuatan manual dengan tiket.
                Tidak ada task yang dibuat Office, browser, script host, atau proses dari folder sementara.
                Scheduled task di 229 workstation tanpa audit tidak terlihat sama sekali.
Cakupan nyata : 4698 dari 206 dari 214 host ber-audit (55 dari 61 server, 151 dari 153 workstation OU
                Workstations-EDR), Senin 2027-02-01 00:00 sampai Kamis 2027-02-18 00:00 WIB, 2.236 event;
                pembuat terkorelasi lewat Sysmon EID 1 untuk 2.205 event (98,6%); 4104 di 214 host
Di luar cakupan: 229 workstation tanpa 4698 dan tanpa Sysmon (Jakarta 148, Bandung 58, POP 23);
                4698 sebelum 1 Februari; task tersembunyi lewat registry (tanpa 4698); 4702 dan 4699;
                pembuat untuk 9 event JKT-WS-0532 (Sysmon diam) dan 22 event di 4 server Windows Server 2019
                (4698 versi 0); JKT-WS-0538 dan JKT-WS-0448 offline sebagian besar rentang
Ambang/asumsi : Kombinasi pembuat hosts <= 5 (sah tersebar 9-201 host); normalisasi GUID, SID, profil
                pengguna di nama task dan command; korelasi PID terakhir sebelum 4698, rentang proses sejak
                1 Januari
Temuan        : 4 kombinasi pembuat langka (5 event) jinak dengan tiket atau konfirmasi; 6 nama di root
                (5 updater vendor, 1 task NOC) jinak; 1 task LogonType Password (risiko konfigurasi);
                31 event tanpa korelasi pembuat, jinak berdasarkan kesamaan isi
Eskalasi      : Tidak ada
Celah data    : 229 workstation tanpa audit 4698 dan tanpa Sysmon -> Agung (sama dengan rekomendasi Day 04);
                4 server Windows Server 2019 tanpa ClientProcessId; Sysmon JKT-WS-0532 masih diam -> Agung
Deteksi       : (1) "JAB - Scheduled task di root menjalankan command dari folder pengguna";
                (2) "JAB - Scheduled task dibuat dengan LogonType Password" -> Sari Kusuma
Rekomendasi   : svc_filesync tanpa password tersimpan -> Agung; skrip alat NOC di lokasi terkelola -> Bambang
Artefak       : queries/01-coverage.spl, 02-task-stack.spl, 03-creator-cpid.spl, 04-schtasks-ps.spl;
                Job Inspector 03-creator-cpid: runDuration 61,3 s, resultCount 12
Hipotesis baru: HUNT-2027-008 (task dibuat lalu dihapus cepat); HUNT-2027-009 (task di host tanpa audit)
Pelajaran     : 4698 lebih lengkap dari schtasks.exe; PowerShell remoting tidak terlihat di EID 1;
                "tidak ditemukan" untuk task hanya berlaku di 214 host
```

Abstract deteksi untuk Sari mengikuti format Day 02 bagian 2.7, diringkas:

```
Usulan deteksi : (1) JAB - Scheduled task di root menjalankan command dari folder pengguna
Asal           : HUNT-2027-004 (tidak terbukti), selesai 2027-02-18
ATT&CK         : T1053.005 (Persistence)
Data dan field : index=wineventlog EventCode=4698: host, SubjectUserName, TaskName, TaskContent (Command)
Logika kasar   : TaskName di root (satu segmen) DAN Command di bawah C:\Users\
                 KECUALI TaskName "OneDrive Standalone Update Task-<SID>" DAN Command persis
                 C:\Users\<user>\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe
Level (PEAK)   : Signatures & rules; urgensi sedang
Volume dari hunt: 98 dalam 17 hari tanpa pengecualian (97 OneDrive); 1 dengan pengecualian (JKT-WS-0552)
Contoh positif : JKT-WS-0552 2027-02-15 16:05 (jinak); uji lab Atomic T1053.005 test 2 sebelum aktif
Triage         : cek pembuat (ClientProcessId ke Sysmon EID 1), isi file yang dijalankan, konfirmasi pengguna
Celah          : hanya 214 host ber-audit; task di subfolder dan command di ProgramData tidak tertangkap

Usulan deteksi : (2) JAB - Scheduled task dibuat dengan LogonType Password
Logika kasar   : EventCode=4698 DAN TaskContent memuat LogonType Password [rekomendasi Microsoft]
Level (PEAK)   : Signatures & rules; urgensi rendah, penerima pemilik server
Volume dari hunt: 1 dalam 17 hari (jkt-filesrv01, tiket change)
```

Dua abstract baru masuk `jab-hunt/backlog/BACKLOG.md` hari ini. Keduanya hanya abstract; belum dijalankan.

```
ID             : HUNT-2027-008
Dibuat         : 2027-02-18 (Kamis), pemilik: <kamu>
Trigger        : Lanjutan HUNT-2027-004: 4699 di luar cakupan; pola buat-hapus terlihat sah di jkt-mgmt01;
                 analytic ATT&CK DET0441 mencakup pembuatan, perubahan, dan penghapusan task
Tipe (PEAK)    : Hypothesis-driven
Hipotesis      : Ada scheduled task yang dibuat lalu dihapus dalam waktu singkat (4698 diikuti 4699 untuk
                 TaskName yang sama di host yang sama) untuk menjalankan perintah sekali tanpa
                 meninggalkan task, di luar pola admin yang tercatat di tiket.
ATT&CK         : T1053.005 (Execution)
Data           : index=wineventlog EventCode IN (4698, 4699), 214 host ber-audit; rentang absolut ditetapkan
                 saat eksekusi; Sysmon EID 1 untuk pembuat
Teknik analisis: pasangkan 4698 dan 4699 per host + TaskName; jarak waktu; stacking pembuat dan command
Di luar cakupan: 229 workstation tanpa audit; task yang dihapus tanpa pernah tercatat dibuat
FP yang diduga : admin memperbaiki task (jkt-mgmt01 2027-02-10, tiga menit), installer dan uninstaller,
                 cleanup uji lab
Kesiapan data  : SIAP SEBAGIAN (sama dengan HUNT-2027-004)
Status         : kandidat; ambang jarak waktu ditetapkan dari distribusi saat eksekusi

ID             : HUNT-2027-009
Dibuat         : 2027-02-18 (Kamis), pemilik: <kamu>
Trigger        : Celah data HUNT-2027-004: scheduled task di 229 workstation di luar OU Workstations-EDR
                 tidak menghasilkan 4698 dan tidak punya Sysmon, sehingga tidak terlihat
Tipe (PEAK)    : Hypothesis-driven, butuh koleksi endpoint
Hipotesis      : Ada scheduled task persistence di workstation tanpa audit yang menjalankan command dari
                 folder yang bisa ditulis pengguna, yang tidak pernah terlihat di SIEM.
ATT&CK         : T1053.005 (Persistence)
Location       : 229 workstation; prioritas 81 workstation Bandung dan POP Surabaya-Medan, termasuk
                 29 tanpa sumber apa pun
Evidence       : keadaan task saat ini di host (file XML di C:\Windows\System32\Tasks\ dan kunci registry
                 TaskCache), diambil lewat alat koleksi endpoint; jalur sebagian lewat MDE advanced hunting
                 untuk workstation Jakarta dan Bandung ber-EDR (30 hari, konsol terpisah, UTC)
Kesiapan data  : TIDAK SIAP: tidak ada server koleksi endpoint permanen per 18 Februari
Handover       : Dimas untuk keputusan koleksi endpoint; Agung untuk rollout audit dan Sysmon
Status         : menunggu keputusan alat
```

`HUNT-2027-009` membawa celah ini ke rapat besok dengan bentuk yang bisa diputuskan: bukan "kita buta di 60% workstation", tetapi "pertanyaan ini, untuk 229 host ini, butuh alat ini".

**Kapan gagal:** laporan menulis "tidak ada persistence scheduled task di PT JAB"; baris "Di luar cakupan" menghilangkan 229 workstation karena terlihat seperti kelemahan; atau event tanpa korelasi pembuat diberi label jinak tanpa menulis dasar yang lebih lemah.

### Bagian G: lab pribadi T1053.005 di VM lab

Bagian ini dikerjakan di lab pribadimu, bukan di data PT JAB. Semua aktivitas uji jinak dijalankan di VM lab terisolasi dengan snapshot; perintah teknik dirujuk ke katalog Atomic Red Team lewat nomor test dan GUID, bukan ditulis sebagai resep.

**Prasyarat:** Splunk lab dengan Security log dan Sysmon dari minimal satu VM Windows 10/11 versi 1903 ke atas (snapshot bersih), script block logging aktif, Invoke-AtomicRedTeam terpasang di VM, dan `hunts/BACKLOG.md` di repo portofolio pribadimu. Jangan memakai data, nama, atau kejadian dari pekerjaan nyata; PT JAB hanya contoh fiktif. Sesuaikan rentang absolut di setiap query dengan tanggal data lab-mu.

Katalog Atomic Red Team untuk T1053.005 memuat 14 test [S8]. Tabel berikut memuat test yang relevan untuk lab ini; kolom GUID dipakai untuk mencocokkan, karena nomor urut bisa bergeser bila katalog diperbarui.

| Test | Nama | GUID | Yang terjadi | Elevasi |
|---|---|---|---|---|
| 2 | Scheduled task Local | `42f53695-ad4a-4546-abb6-7d837f644a71` | `schtasks` membuat task sekali jalan bernama `spawn` yang menjalankan `cmd.exe` | Tidak |
| 4 | Powershell Cmdlet Scheduled Task | `af9fd58f-c4ac-4bf2-a9ba-224b71ff25fd` | Cmdlet PowerShell mendaftarkan `AtomicTask` saat logon yang menjalankan `calc.exe` | Tidak |
| 6 | WMI Invoke-CimMethod Scheduled Task | `e16b3b75-dc9e-4cde-a23d-dfa2d0507b3b` | Task didaftarkan dari XML lewat kelas WMI `PS_ScheduledTask`, menjalankan `notepad.exe` setelah logon | Ya |
| 9 | PowerShell Modify A Scheduled Task | `dda6fc7b-c9a6-4c18-b98d-95ec6542af6d` | Task `AtomicTaskModifed` dibuat lalu action-nya diubah | Tidak |

Semua test di atas punya perintah cleanup. Test 10 (task lewat manipulasi registry tanpa 4698) memakai alat pihak ketiga yang harus diunduh; jangan dijalankan untuk lab ini, cukup catat sebagai batas hunt.

1. **Abstract dan kesiapan.** Tulis abstract hunt scheduled task untuk lab-mu dengan templat bagian 1.9, termasuk "Di luar cakupan". Di VM, cek status subkategori audit dengan `auditpol /get /subcategory:"Other Object Access Events"`. Bila belum aktif, catat sebagai celah, aktifkan Success, lalu buat satu task jinak manual untuk membuktikan 4698 muncul.
2. **Baseline lab.** Jalankan query Bagian B dan C atas data lab beberapa hari sebelum uji. Catat jumlah 4698, nama task unik sebelum dan sesudah normalisasi, dan nama di root. Di lab yang sepi, hampir semua task berasal dari Windows dan updater; catat itu sebagai pelajaran.
3. **Uji positif.** Catat jam (WIB), lalu jalankan test 2 dan test 4 dengan GUID di atas. Bila VM-mu mengizinkan, jalankan juga test 6 dan test 9.
4. **Ulangi hunt.** Jalankan query Bagian C, D, dan E untuk rentang yang mencakup uji. Yang harus terlihat: dua atau lebih 4698 baru; test 2 menghasilkan EID 1 `schtasks.exe` dengan `/create` dan `ClientProcessId` yang terkorelasi ke `schtasks.exe`; test 4 tidak menghasilkan `schtasks.exe`, tetapi 4104 memuat cmdlet-nya dan `ClientProcessId` terkorelasi ke `powershell.exe` (cek apakah command line proses itu memuat cmdlet, bergantung cara executor menjalankannya); test 6 terkorelasi ke proses WMI, bukan PowerShell; test 9 menghasilkan 4702 setelah 4698.
5. **Cleanup dan 4699.** Jalankan cleanup tiap test, lalu cari 4699 untuk nama task yang sama. Catat jarak waktu 4698 ke 4699: inilah data lab untuk ambang `HUNT-2027-008`. Kembalikan snapshot.
6. **Label dan laporan.** Beri label setiap baris (jinak, perlu investigasi, data tidak cukup). Task uji dikenali sebagai uji, bukan temuan; kemunculannya adalah bukti query sanggup menangkap pola. Isi laporan dengan templat bagian 1.9.
7. **Usulan dari sudut L1.** Isi satu templat usulan bagian 1.10 seolah kamu analyst L1 yang melihat task uji itu di alert, lalu isi bagian hunter-nya sendiri.

**Hasil yang sebaiknya tersimpan:**

- Abstract dan laporan hunt lab dengan cakupan nyata dan "Di luar cakupan".
- Status subkategori audit sebelum dan sesudah, dan bukti 4698 dari task jinak manual.
- GUID test yang dijalankan, jamnya, dan event yang muncul per test (4698, 4699, 4702, EID 1, 4104).
- Hasil korelasi `ClientProcessId` per test, termasuk satu contoh yang gagal dikorelasikan bila ada, dan alasannya.
- Jarak waktu 4698 ke 4699 dari cleanup.
- Satu templat usulan L1 yang sudah diisi kedua bagiannya.

**Variasi tantangan:** buat ulang test 2 dengan nama task meniru updater vendor (misalnya diawali `MicrosoftEdgeUpdate`), lalu lihat apakah stacking Bagian C masih menonjolkannya lewat kolom `commands` dan `n_creators`. Ubah juga query Bagian D supaya memakai `tstats` atas `Endpoint.Processes` untuk sisi Sysmon (`Processes.process_id`), lalu jalankan uji kesetaraan dengan versi raw seperti Day 06 bagian 2.5.

### Bagian H: latihan skenario dengan pembahasan

Jawab setiap skenario dalam tiga sampai lima kalimat sebelum membuka pembahasannya.

**Skenario 1.** Kamu menulis hipotesis "ada DNS tunneling dari departemen finance". Saat cek data, ternyata Sysmon EID 22 hanya aktif di 3 dari 40 workstation finance, dan resolver internal tidak mencatat query.

<details><summary>Pembahasan</summary>

Kartu kesiapan: TIDAK SIAP untuk cakupan finance, karena scope Evidence hanya 7,5% (3 dari 40). Ada dua pilihan sah. Pertama, jalankan hunt di 3 host itu dan tulis cakupan nyata dengan jujur; kesimpulan "tidak terbukti" hanya berlaku untuk 3 host. Kedua, nyatakan hunt gagal karena data, lalu serahkan rekomendasi telemetri (logging resolver atau Sysmon EID 22 di seluruh finance) ke pemilik sistem. Yang salah adalah menjalankan hunt di 3 host lalu menulis "tidak ada DNS tunneling di finance".

</details>

**Skenario 2.** Stacking parent-child 30 hari menghasilkan 640 baris dengan `executions <= 5`. Batas durasi hunt dua hari.

<details><summary>Pembahasan</summary>

640 baris tidak bisa ditinjau dengan layak dalam dua hari. Langkah pertama adalah melihat distribusi, bukan menebak ambang baru: bila p25 jumlah eksekusi sudah 5, ambang itu memang mengambil seperempat data. Persempit dengan syarat tambahan yang punya alasan: `hosts <= 2` (pasangan yang tersebar luas biasanya software sah), kecualikan parent yang sudah diverifikasi jinak dengan alasan tertulis, atau fokus ke parent berisiko (Office, browser, `wmiprvse.exe`). Catat semua pengecualian di baris "Ambang/asumsi" agar hunt bisa diulang, dan tulis sisanya sebagai di luar cakupan.

</details>

**Skenario 3.** Di hari pertama hunt, kamu menemukan `rundll32.exe` di satu host yang memuat DLL dari `C:\Users\Public\` dan membuat koneksi keluar ke IP yang tidak dikenal setiap lima menit.

<details><summary>Pembahasan</summary>

Ini memenuhi ambang "dicurigai kuat": eksekusi dari lokasi yang bisa ditulis siapa pun, proxy execution lewat `rundll32` (T1218.011), dan pola koneksi teratur yang mirip beacon. Hunt berhenti menjadi hunt untuk host ini; serahkan ke IR sekarang, bukan di akhir hunt (Escalate Critical Findings). Serahkan host, waktu, `ProcessGuid`, command line, IP tujuan, dan hipotesis. Setelah itu kamu boleh melanjutkan hunt di host lain untuk mencari pola yang sama, karena pertanyaan "apakah ada host lain" justru pekerjaan hunting, tetapi koordinasikan dengan IC karena sekarang ada insiden. Jangan menyentuh host yang sedang ditangani IR tanpa koordinasi.

</details>

**Skenario 4.** Hipotesis menyebut `mshta.exe` dengan argumen URL. Query `index=sysmon EventCode=1 Image=*\\mshta.exe` di 30 hari mengembalikan nol baris.

<details><summary>Pembahasan</summary>

Nol baris punya tiga kemungkinan: memang tidak ada eksekusi, data tidak ada, atau query salah. Sebelum menulis "tidak terbukti", buktikan dua yang terakhir tidak terjadi. Cek apakah EID 1 masuk dari host yang dimaksud selama 30 hari itu (volume harian per host, termasuk feed yang diam). Cek apakah nama field dan path cocok, misalnya `Image` vs `process_path` setelah normalisasi. Lalu jalankan `mshta.exe` jinak di VM lab (misalnya membuka file `.hta` lokal yang hanya menampilkan teks) dan pastikan muncul. Hanya setelah ketiga cek itu kamu boleh menulis "tidak terbukti".

</details>

**Skenario 5.** Dwi Cahyono mengirim usulan: "Cari scheduled task mencurigakan di semua laptop Bandung." Apa yang kamu tulis di bagian hunter templat usulannya?

<details><summary>Pembahasan</summary>

Usulan itu topik, bukan hipotesis: "mencurigakan" belum menyebut perilaku yang terlihat di log. Tajamkan bersama Dwi, misalnya "task di root yang menjalankan command dari folder pengguna". Lalu cek Evidence: laptop Bandung tidak punya 4698 maupun Sysmon (di luar OU `Workstations-EDR`), dan enam di antaranya juga tanpa EDR, sehingga kesiapannya TIDAK SIAP. Keputusannya bukan menolak, tetapi menautkan usulan itu ke `HUNT-2027-009` yang menunggu keputusan koleksi endpoint, dan memberi umpan balik bahwa usulannya justru menunjukkan celah yang nyata.

</details>

### Troubleshooting ringkas

Tabel ini menggabungkan masalah yang paling sering muncul dari Day 01-06 dan dari lab gabungan. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Perbaikan |
|---|---|---|
| Hunt tidak selesai | Tidak ada kriteria sukses atau time-box | Tetapkan di abstract (Day 02 bagian 1.5) |
| Evidence tidak ada saat Execute | ABLE dan kartu kesiapan tidak dicek | Kartu kesiapan sebelum mulai (Day 04 bagian 2.7) |
| 4698 tidak pernah muncul di host aktif | Audit Other Object Access Events tidak aktif | Aktifkan Success lewat audit policy, uji dengan satu task jinak [S9] |
| 4698 nol di kelompok host tertentu | GPO audit tidak ditautkan ke OU itu | Bandingkan dengan daftar aset per OU (Bagian B); celah ke pemilik GPO |
| `task_cmd` kosong | XML ter-escape atau field berbeda nama | Lihat event mentah; regex Bagian C menangani `&lt;` dan `<` |
| `ClientProcessId` kosong | Event 4698 versi 0 (OS lebih tua dari Windows 10 1903) | Korelasi lewat `SubjectLogonId` dan waktu; tulis sebagai batas |
| Pembuat "tidak terkorelasi" banyak | Sysmon diam, proses dimulai sebelum rentang, subsearch terpotong | Cek feed per host (Day 04 bagian 2.2); buka rentang proses; cek pesan subsearch [S13] |
| Task PowerShell tidak terlihat di EID 1 | Remoting berjalan di `wsmprovhost.exe`, atau cmdlet di dalam file skrip | Pakai 4104 dan 4698 |
| Nama updater memenuhi daftar | GUID dan SID di nama task | Normalisasi seperti Bagian C |
| Hasil stacking ratusan baris | Lab sepi atau ambang longgar | Ambang dari distribusi, dua syarat (jarang dan sedikit host) (Day 05 bagian 1.4) |
| Hunt lambat dan ES terlewat | Raw di rentang panjang | `tstats` dulu, atau subsearch yang mempersempit (Day 06 bagian 2.1) |
| Temuan tidak diserahkan | Handover tidak direncanakan | Tentukan penerima di abstract |
| Usulan L1 menumpuk tanpa jawaban | Tidak ada jadwal tinjauan | Tinjau setiap Selasa pagi; isi bagian hunter dan beri umpan balik |

## 5. Kesalahan umum dan jebakan

- Menyebut pencarian IOC sebagai hunting; naik ke TTP (Day 01).
- Melewati fase Act dan handover, sehingga hunt hilang nilainya (Day 02).
- Menunda handover ke IR sampai hunt selesai padahal temuan sudah memenuhi ambang dicurigai kuat (Day 02).
- Hipotesis terlalu luas, tentang niat, atau tidak bisa dibantah (Day 03).
- Menjalankan hunt sebelum memastikan Evidence ada, atau mengira nol hasil berarti bersih (Day 04).
- Mengira daftar hasil teknik adalah jawaban; manusia tetap meninjau dan melabeli (Day 05).
- Menarik rentang panjang sebagai raw, atau memakai `tstats` tanpa uji kesetaraan (Day 06).
- Hanya mencari `schtasks.exe` untuk persistence scheduled task, padahal task bisa dibuat lewat PowerShell, remoting, GUI, installer, WMI, atau COM tanpa proses itu.
- Menganggap 4698 mencakup semua host. Di PT JAB ia hanya ada di 214 host; 229 workstation buta untuk pertanyaan ini.
- Memperlakukan korelasi `ClientProcessId` seperti `ProcessGuid`. PID bisa dipakai ulang; cek ulang setiap baris yang akan dilabel.
- Membuang task di root karena "itu updater vendor" tanpa melihat command dan pembuatnya. Penyerang bisa meniru nama updater.
- Memberi label jinak pada event tanpa korelasi pembuat dengan dasar yang sama kuatnya dengan yang terkonfirmasi. Tulis dasar yang lebih lemah apa adanya.
- Menolak usulan L1 karena datanya tidak ada. Usulan seperti itu menunjukkan celah dan tetap dicatat dengan pemiliknya.

## 6. Catatan terkini

Bagian ini menampung versi, tanggal, dan detail sumber untuk teknik dan event yang dipakai di lab gabungan. Berguna saat membuka sumbernya, tetapi tidak mengubah alur kerja di atas.

- **ATT&CK v20.0** dirilis 13 Oktober 2026, menggantikan v19.2 yang berlaku 28 April sampai 12 Oktober 2026 [S12]. T1053.005 di v20 berada di versi 1.8 (dibuat 27 November 2019, diubah 12 Mei 2026), dengan tiga taktik: Execution, Persistence, Privilege Escalation [S6]. Halaman teknik kini juga menyebut cara menyembunyikan task dengan mengubah metadata seperti nilai `Index` di kunci registry terkait, selain menghapus Security Descriptor [S6].
- **DET0441** (Detection of Suspicious Scheduled Task Creation and Execution on Windows), versi 1.0, dibuat 21 Oktober 2025 dan diubah 12 Mei 2026, berisi satu analytic Windows, AN1221 [S11]. Data Component dan log source yang dicantumkannya: Scheduled Job Creation (4698), Scheduled Job Modification (4702), Process Creation (Sysmon EID 1), File Creation (Sysmon EID 11), dan Windows Registry Key Modification (Sysmon EID 13 dan 14). Mutable element-nya: `TimeWindow`, `UserContext`, `TaskNamePattern`, dan `CommandLineEntropyThreshold` [S11]. Analytic itu tidak mencantumkan channel TaskScheduler/Operational; Data Component Scheduled Job Creation di Day 04 bagian 2.6 mencantumkan 4698, 4699, dan TaskScheduler 106.
- **Microsoft Learn** untuk 4698, 4699, dan Audit Other Object Access Events adalah halaman arsip Windows 10 (ms.date September 2021, diperbarui 27 April 2026) [S7][S9][S10]. Field tambahan versi 1 (`ClientProcessStartKey`, `ClientProcessId`, `ParentProcessId`, `RpcCallClientLocality`, `FQDN`) disebut untuk Windows 10 versi 1903 ke atas; untuk Windows Server, cek versi event di event mentah. Subkategori ini juga memuat 4700 (task diaktifkan), 4701 (task dinonaktifkan), dan 4702 (task diperbarui) [S9].
- **Atomic Red Team T1053.005** memuat 14 test per 18 Oktober 2026 [S8]. Hanya satu test yang memakai `Invoke-CimMethod` (test 6); test lain memakai `schtasks`, cmdlet PowerShell, makro VBA, impor XML, dan manipulasi registry. Cleanup test 8 di katalog menghapus nama task yang berbeda dengan task yang dibuatnya; cek manual setelah menjalankannya.
- **SANS 2026:** data menjadi hambatan utama hunting (50%), metodologi formal hanya 37%, dan hanya 40% organisasi mengukur efektivitas hunting secara formal [S4]. Program yang punya kalender, templat, dan laporan dengan cakupan tertulis sudah berada di atas kebiasaan rata-rata responden.
- Versi acuan Day 01-06: PEAK (2023), TaHiTI (di-host 2026-03), HMM (era Sqrrl), Splunk Enterprise 10.6 dengan ES 8.x, ATT&CK v20.

## 7. Cheat sheet

```
DEFINISI  proaktif + dipimpin manusia + iteratif + asumsi deteksi punya celah ; "tidak ditemukan" sah DENGAN cakupan
SIKLUS    hipotesis -> investigasi -> uncover TTP -> inform/enrich ; PEAK Prepare/Execute/Act ; TaHiTI Initiate/Hunt/Finalize
          temuan berbahaya -> IR SEKARANG (Escalate Critical Findings)
HIPOTESIS bisa dibuktikan ATAU dibantah ; ABLE (Actor? Behavior Location Evidence) ; 1-2 behavior ; bukan niat, bukan IOC
DATA      kartu SIAP | SIAP SEBAGIAN | TIDAK SIAP ; depth, scope vs daftar aset, konfigurasi, waktu ; nol hasil != bersih
PT JAB    214 host Sysmon+audit (61 server, 153 ws) | 229 ws buta (JKT 148, BDG 58, POP 23) | proxy/dns 30 hari
TEKNIK    searching | stacking | first-seen vs baseline | grouping | frekuensi (CV <= 0,2 setelah buang jeda > 3x median)
SPLUNK    tstats persempit -> uji kesetaraan -> raw bertarget ; subsearch maks 10.000 hasil / 60 s default
TEMPLAT   abstract (ID, trigger, ABLE, data+rentang absolut, kesiapan, di luar cakupan, kriteria, time-box, handover)
          laporan (hasil, cakupan nyata, di luar cakupan, ambang, temuan+bukti, eskalasi, celah, deteksi, backlog)
          usulan L1 (pemicu, pertanyaan, perilaku, di mana, data, apa yang membuatnya SALAH | bagian hunter)
T1053.005 4698 (semua jalur API, butuh Audit Other Object Access Events) + EID 1 schtasks.exe (jalur CLI)
          + 4104 (PowerShell, termasuk remoting di wsmprovhost.exe) ; 4699 hapus, 4702 ubah ; registry: tanpa 4698
4698      SubjectUserName (HOST$ = SYSTEM) | TaskName (root \NAMA) | TaskContent <Command>, LogonType Password
          | ClientProcessId (versi 1, Win10 1903+) -> Sysmon ProcessId, PID terakhir sebelum task, cek ulang
NORMAL    {GUID} -> {<guid>} | S-1-5-21-... -> <sid> | c:/users/<nama>/ -> c:/users/<user>/
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "`HUNT-2027-004` hasilnya tidak ditemukan, jadi di PT JAB tidak ada persistence lewat scheduled task." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Hasil itu hanya berlaku untuk 214 host ber-audit (dan 4698 hanya muncul dari 206 di antaranya), untuk 1-17 Februari, dan untuk task yang dibuat lewat Task Scheduler. Sebanyak 229 workstation di luar OU `Workstations-EDR` tidak menghasilkan 4698 dan tidak punya Sysmon, sehingga task di sana tidak terlihat sama sekali; task tersembunyi lewat registry juga tidak menghasilkan 4698. Karena itu celahnya dijadikan `HUNT-2027-009`, bukan disembunyikan. Lihat bagian 1.8 dan Bagian F di lab gabungan.

</details>

**2. Skenario keputusan.** Gilang mengirim tiga usulan lewat templat L1. Mana yang paling siap menjadi hunt?

- A. "Cek apakah aktor dari brief forum ingin mencuri data pelanggan kita."
- B. "Apakah ada host yang mengumpulkan beberapa alert P3 perlindungan endpoint dalam 90 hari? Dugaan ini salah bila tidak ada host dengan lebih dari satu alert jenis itu, atau semua punya penjelasan tertulis."
- C. "Cari 25 hash dari laporan vendor di semua endpoint."

<details><summary>Jawaban</summary>

B. Usulan itu menyebut perilaku yang terlihat di data, lokasinya, dan hasil data yang akan membantahnya, sehingga hunter tinggal mengecek Evidence (index alert di ES dan retensinya). A keliru karena menyatakan niat, dan niat tidak terlihat di log. C keliru karena itu pencarian indikator (HMM1) yang dikerjakan langsung lewat threat intelligence ES, bukan hunt. Lihat bagian 1.3 dan 1.10.

</details>

**3. Pertanyaan jebakan.** "Untuk task yang dibuat lewat PowerShell, cukup cari `Register-ScheduledTask` di command line Sysmon EID 1; kalau nol, tidak ada task PowerShell." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Cmdlet hanya terlihat di command line bila ditulis inline saat proses dimulai. Di `HUNT-2027-004`, EID 1 mengembalikan nol baris, padahal ada satu task yang dibuat lewat PowerShell remoting di `JKT-WS-0611`: perintahnya berjalan di dalam `wsmprovhost.exe`, sehingga yang menemukannya adalah 4104 dan korelasi `ClientProcessId` di 4698. Lihat Bagian D dan E di lab gabungan.

</details>

**4. Skenario keputusan.** Di tengah `HUNT-2027-004`, stacking pembuat menunjukkan satu task di root yang dibuat `WINWORD.EXE` di workstation Customer Service, menjalankan file dari `AppData` pengguna, tanpa tiket apa pun. Apa langkah yang tepat?

- A. Selesaikan dulu seluruh stacking, tulis laporan, lalu serahkan ke IR di fase Act.
- B. Hubungi Dimas sekarang dengan host, akun, waktu, `TaskName`, isi `TaskContent`, dan proses pembuatnya, lalu lanjutkan hunt di host lain dengan koordinasi.
- C. Hapus task itu dari host supaya tidak dijalankan, lalu catat di laporan.

<details><summary>Jawaban</summary>

B. Office yang membuat task di root yang menjalankan file dari folder pengguna tanpa penjelasan memenuhi ambang dicurigai kuat, dan PEAK menempatkan Escalate Critical Findings di fase Execute: diserahkan saat itu juga. A keliru karena menunda IR sampai laporan selesai. C keliru karena menghapus task adalah tindakan containment dan eradication yang menjadi keputusan IR, dan menghapusnya merusak bukti. Lihat bagian 1.2.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Dwi Cahyono (analyst L1), dalam tiga kalimat, kenapa templat usulan hipotesis punya baris "Apa yang membuat dugaan ini SALAH".

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Hunt hanya bisa selesai kalau ada hasil data yang bisa membuktikan dugaanmu salah; tanpa itu kita akan terus mencari tanpa tahu kapan berhenti. Baris itu memaksa kamu menulis seperti apa data yang 'normal', misalnya 'tidak ada host dengan lebih dari satu alert jenis itu', dan itulah yang nanti menjadi kriteria sukses di abstract. Kalau kamu tidak bisa mengisinya, itu tanda usulanmu masih topik atau niat, dan kita tajamkan bersama dulu."

Kesalahan yang sering muncul:
- Mengatakan baris itu untuk membuktikan usulan L1 keliru, padahal tujuannya membuat dugaan bisa diuji.
- Tidak mengaitkannya dengan kriteria sukses dan kapan hunt selesai.
- Lupa bahwa usulan yang belum bisa mengisinya tetap diterima dan ditajamkan, bukan ditolak.

</details>

**6. Pertanyaan jebakan.** "Korelasi `ClientProcessId` di 4698 ke `ProcessId` Sysmon EID 1 sama tepatnya dengan pivot lewat `ProcessGuid`, jadi hasil Bagian D bisa langsung dipakai sebagai label." Benarkah?

<details><summary>Jawaban</summary>

Tidak. `ProcessGuid` unik per proses, sedangkan PID bisa dipakai ulang Windows, dan `ClientProcessStartKey` yang ada di 4698 tidak dicatat Sysmon. Query Bagian D mengambil proses ber-PID sama yang paling akhir dimulai sebelum task dibuat, sehingga hasilnya pendekatan yang harus dicek ulang per baris sebelum diberi label, misalnya dengan mencocokkan akun Sysmon dengan `SubjectUserName`. Event tanpa `ClientProcessId` (versi 0) atau dari host yang Sysmon-nya diam tidak bisa dikorelasikan sama sekali dan labelnya ditulis dengan dasar yang lebih lemah. Lihat Bagian D dan F di lab gabungan.

</details>

**7. Interview question (English).** "Tell me about a threat hunt you ran end to end where you found nothing malicious. What did you deliver?"

<details><summary>Sample answer</summary>

"I hunted for scheduled task persistence created by an unusual parent process or user, triggered by an intel brief about a campaign against telecom providers. Before running anything I checked data readiness: task creation events were only audited on 214 of our hosts, so 229 workstations were written out of scope in the abstract, not discovered later. I stacked task creation events by normalised task name, root location, command and creating account, then correlated the requesting process ID to Sysmon process creation to see which process actually created each task. That surfaced four rare creators, each confirmed with a change or helpdesk ticket, and showed that one task created over PowerShell remoting never appeared as a new process. The result was 'not found' for the hosts and dates covered, and I delivered two detection proposals with measured volumes, a configuration risk for a task storing a service account password, the audit gap to the infrastructure lead, and two new hypotheses for the backlog, including one that needs endpoint collection for the unaudited workstations."

What makes this answer strong: it treats data readiness and scope as part of the method, explains the technique behind the result, separates confirmed benign from weaker conclusions, and shows that a negative hunt still produced detections, a risk finding and a telemetry decision.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Splunk: Introducing the PEAK Threat Hunting Framework; PEAK hypothesis-driven hunting | https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html ; https://www.splunk.com/en_us/blog/security/peak-hypothesis-driven-threat-hunting.html | sekunder (blog penulis kerangka) | 2023; diakses 2026-10-10 | Tinggi untuk PEAK dan ABLE |
| S2 | TaHiTI: a threat hunting methodology (whitepaper) | https://www.betaalvereniging.nl/wp-content/uploads/2026/03/TaHiTI-Threat-Hunting-Methodology-whitepaper.pdf | primer (pemilik metodologi) | di-host 2026-03; diakses 2026-10-10 | Tinggi |
| S3 | Sqrrl: Hunt Evil: Your Practical Guide to Threat Hunting | https://www.threathunting.net/files/hunt-evil-practical-guide-threat-hunting.pdf | primer (panduan Sqrrl, memuat HMM dan hunting loop) | tanpa tahun; diakses 2026-10-10 | Tinggi untuk HMM dan loop |
| S4 | SANS: Threat hunters call data their biggest barrier (2026 survey) | https://www.sans.org/press/announcements/threat-hunters-call-data-their-biggest-barrier-overtaking-staffing-first-time-survey-finds | sekunder (rilis pers survei) | 2026-09-23; diakses 2026-10-07 | Sedang-tinggi; angka dari rilis pers |
| S5 | Intel471: Threat hunting tactics and techniques | https://www.intel471.com/blog/threat-hunting-tactics-techniques | sekunder (vendor) | diakses 2026-10-08 | Sedang-tinggi untuk taksonomi teknik |
| S6 | MITRE ATT&CK: T1053.005 Scheduled Task/Job: Scheduled Task | https://attack.mitre.org/techniques/T1053/005/ | primer | versi 1.8, dibuat 2019-11-27, diubah 2026-05-12; konten ATT&CK v20; diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi. Taktik, jalur pembuatan, task tersembunyi (Security Descriptor, nilai `Index`), DET0441 |
| S7 | Microsoft Learn: 4698(S) A scheduled task was created | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698 | primer (dokumentasi vendor, arsip) | ms.date 2021-09-07, diperbarui 2026-04-27; diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi untuk field, field versi 1 (Windows 10 1903+), task di root, alert `LogonType` Password |
| S8 | Atomic Red Team: T1053.005 | https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md | primer (katalog test) | diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi; 14 test, nama, GUID, elevasi, cleanup. Jumlah dan isi test bisa berubah |
| S9 | Microsoft Learn: Audit Other Object Access Events | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-other-object-access-events | primer (dokumentasi vendor, arsip) | ms.date 2021-09-06, diperbarui 2026-04-27; diakses 2026-10-18 | Tinggi. Rekomendasi Success untuk DC, member server, workstation; daftar event 4698 sampai 4702 |
| S10 | Microsoft Learn: 4699(S) A scheduled task was deleted | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4699 | primer (dokumentasi vendor, arsip) | ms.date 2021-09-07, diperbarui 2026-04-27; diakses 2026-10-18 | Tinggi. Field sama dengan 4698, penghapusan jarang, task di root |
| S11 | MITRE ATT&CK: DET0441 Detection of Suspicious Scheduled Task Creation and Execution on Windows | https://attack.mitre.org/detectionstrategies/DET0441/ | primer | versi 1.0, dibuat 2025-10-21, diubah 2026-05-12; diakses 2026-10-18 | Tinggi. AN1221: Data Component, log source, mutable elements |
| S12 | MITRE ATT&CK: Versions of ATT&CK | https://attack.mitre.org/resources/versions/ | primer | diakses 2026-10-18 | Tinggi. v20.0 sejak 2026-10-13; v19.2 2026-04-28 sampai 2026-10-12 |
| S13 | Splunk Enterprise Search Manual 10.0: About subsearches | https://help.splunk.com/en/splunk-enterprise/search/search-manual/10.0/subsearches | primer (dokumentasi vendor) | diakses 2026-10-18 | Tinggi untuk 10.0: batas default 10.000 hasil (`maxout`) dan 60 detik (`maxtime`), `remoteSearch`. Nilai di 10.6 perlu dicek di `limits.conf` |

**Catatan sumber:** nama field 4698 dan 4104 di Splunk bergantung format ingest (XML atau klasik) dan add-on yang dipakai; cek satu event mentah di lab-mu, termasuk apakah `ClientProcessId` ditulis desimal. Halaman Microsoft [S7] tidak menyebut status bawaan subkategori audit; status di VM lab-mu dicek dengan `auditpol` (Bagian G). Perilaku PowerShell remoting yang menjalankan perintah di dalam `wsmprovhost.exe` dan pemetaan test Atomic ke proses pembuat (Bagian G langkah 4) adalah perilaku yang lazim dan perlu dikonfirmasi di lab. Batas subsearch [S13] dibaca dari Search Manual 10.0. Rekomendasi akun layanan tanpa password tersimpan untuk task adalah saran praktik umum; cek dukungannya di dokumentasi Microsoft sebelum dipakai. Ringkasan Day 01-06 di bagian 1.1 sampai 1.8 memakai fakta dan angka dari Day asalnya, dengan sumber yang dirujuk di sana. Seluruh isi PT JAB (tujuh hunt, angka, host, akun, task, laporan, dan abstract `HUNT-2027-008` dan `-009`) adalah penerapan catatan ini pada organisasi fiktif, bukan hasil eksekusi nyata.
