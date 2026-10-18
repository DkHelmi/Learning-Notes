---
day: 15
title: 'Dokumentasi dan metrik hunt: laporan yang bisa dihitung ulang, lima metrik PEAK, impact/coverage/operational, vanity metrics, "tidak ditemukan" sebagai hasil, cakupan ATT&CK, dan satu halaman untuk direksi'
researched_on: 2026-10-18
versions_checked: 'PEAK Measuring Hunting Success (Splunk blog, David Bianco, 2023-08-02, dicek ulang 2026-10-18); MITRE ATT&CK v20.0 (2026-10-13); ATT&CK Navigator 5.3.2 (2026-04-21), layer file format 4.5 (sejak Navigator 4.9.0); Splunk Enterprise Security 8.7 (istilah finding dan intermediate finding) dan ES 7.3 (anotasi correlation search); SANS 2026 Threat Hunting Survey (rilis pers 2026-09-23); Intel 471 (2026-02-10); Dropzone AI (tanpa tanggal); AttackIQ (2026-03-10); Splunk Enterprise 10.6 (SPL)'
---

# Day 15: Dokumentasi dan metrik hunt (dari 22 laporan ke satu halaman untuk direksi)

Cakupan: menulis laporan hunt yang angkanya bisa dihitung ulang orang lain, lalu menyusun metrik program dari laporan itu: lima metrik kunci PEAK, pengelompokan impact, coverage, dan operational, menghindari vanity metrics, melaporkan "tidak ditemukan" sebagai hasil, menunjukkan nilai insiden yang ditemukan hunt tanpa melebih-lebihkan, mengukur cakupan ATT&CK dengan layer Navigator, dan meringkas semuanya dalam satu halaman untuk manajemen.

## Ide inti

Metrik program hunting hanya sejujur dokumen tempat ia dihitung. Bila setiap laporan hunt menulis kategori hasil dengan kosakata yang sama, cakupan nyata, detection yang lahir beserta tanggal laporannya, dan celah yang diserahkan beserta pemiliknya, angka program cukup dijumlahkan dan siapa pun bisa menghitungnya ulang. Bila tidak, angka program direkonstruksi dari ingatan, dan angka dari ingatan hampir selalu lebih bagus daripada kenyataan. Setelah angkanya bisa dihitung, pertanyaan berikutnya adalah angka mana yang layak dibawa ke atasan. Ukuran yang jujur adalah keluaran yang mengubah postur keamanan: detection yang aktif, insiden yang ditemukan, celah yang benar-benar ditutup, dan teknik yang kini punya pengawasan. Jumlah hunt, query, atau jam kerja hanya mengukur seberapa keras tim bekerja; boleh dicatat sebagai konteks, tidak pernah sebagai bukti nilai. Hasil "tidak ditemukan" yang cakupannya tertulis termasuk keluaran, karena ia memberi tahu persis area mana yang sudah diperiksa dan area mana yang belum bisa diperiksa.

Kamu sudah mengenal pola ini dari NOC. Laporan bulanan NOC ke manajemen yang dipercaya tidak berisi jumlah ping yang dikirim atau jumlah tiket yang ditutup per shift, tetapi availability per link, MTTR, jumlah link yang kini terpantau dibanding awal bulan, dan daftar temuan audit yang belum diperbaiki pemiliknya. Laporan patroli preventif juga ditulis "segmen X dicek, normal" bersama daftar titik yang diukur, sehingga patroli yang tidak menemukan gangguan tetap tercatat sebagai pekerjaan yang bisa diaudit. Batas analoginya: hunting tidak punya angka alami seperti uptime. Sebagian besar nilai hunt baru terbukti kelak, saat detection yang lahir darinya memicu, dan "nol temuan" bisa berarti bersih atau bisa berarti query-nya buta. Karena itu metrik hunting selalu dibaca bersama cakupan dan bukti bahwa query sanggup menangkap pola yang dicari.

```
 report.md per hunt (kategori hasil terkontrol + blok Metrik)
        |            \
        |             +--> register celah & miskonfigurasi (pemilik, status, tanggal)
        |             +--> docs detection: origin_hunt, tanggal laporan, tanggal aktif
        v
 lembar metrik kuartal (dihitung, bukan diingat)
        |
        +--> IMPACT       detection aktif dari hunt | insiden saat hunt vs dari detection hunt
        |                 celah ditutup / dilaporkan | miskonfigurasi diperbaiki / dilaporkan
        +--> COVERAGE     teknik diburu | teknik ber-detection dari hunt (layer awal vs akhir)
        |                 host yang benar-benar tercakup
        +--> OPERATIONAL  waktu laporan -> aktif (median) | waktu eskalasi | umur backlog
        +--> KONTEKS      jumlah hunt, hari hunting (dicatat, bukan dijual)
        |
        v
 satu halaman manajemen: keluaran permanen, arti "tidak ditemukan", risiko terbuka, keputusan
        |
        +--> Act with Knowledge: celah yang berulang dan teknik yang belum diburu memilih hunt berikutnya
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan. SOC PT JAB memakai Splunk Enterprise 10.6 dengan Enterprise Security (ES) 8.x di search head terpisah `jkt-splunk-es01`; hunting berjalan di search head `jkt-splunk-sh01`. Sysmon terpasang di 214 host (61 server Windows dan 153 workstation Jakarta di OU `Workstations-EDR`), sehingga 229 dari 382 workstation tidak punya Sysmon; sejak 22 sampai 24 Februari 2027 ada server Velociraptor permanen `jkt-velo02` untuk menjangkau host itu. Program hunt PT JAB adalah percobaan dua kuartal (Februari sampai Juli 2027) yang disetujui Direktur Teknologi Hendra Wijaya; kamu (analyst L2) memegangnya setiap Selasa dan Kamis dengan SOC lead Dimas Prasetyo sebagai sponsor. Enam minggu berjalan, program sudah membagikan 25 nomor hunt, menemukan satu kompromi nyata (`INC-2027-040`, scheduled task `\PDFSuite Updater` di laptop sales Surabaya `SBY-WS-0107`, ditemukan Kamis 2027-02-25), dan kemarin, Rabu 2027-03-17 pukul 09:00, Sari Kusuma mengaktifkan sepuluh detection ES yang lahir dari hunt. Kamis 2027-03-18 pukul 08:30, Dimas menulis:

> "Pagi. Pak Hendra minta aku membawa angka program hunt ke evaluasi akhir Q1, Rabu 31 Maret, dan beliau mau satu halaman yang bisa diteruskan ke direksi. Aku tidak mau datang dengan angka yang kelihatan bagus tapi tidak bisa dipertanggungjawabkan; Bu Nina biasanya minta setiap angka bisa ditelusuri ke dokumen. Tolong bantu. Angkanya kita ambil dari mana, dan apakah laporan-laporanmu cukup untuk itu? Metrik apa yang jujur? Mana yang cuma terlihat bagus, misalnya 'lebih dari dua puluh hunt dalam enam minggu'? Sebagian besar hunt kita hasilnya 'tidak ditemukan'; bagaimana melaporkannya tanpa terlihat seperti kita tidak menghasilkan apa-apa? Bagaimana menunjukkan nilai INC-2027-040 tanpa melebih-lebihkan? Pak Hendra juga pasti tanya cakupan ATT&CK kita bertambah berapa; yang benar-benar bertambah apa? Terakhir, satu halaman untuk direksi itu sebaiknya seperti apa."

Pesan itu memuat tujuh pertanyaan:

1. Dari mana angka program diambil, dan apakah dokumentasi hunt yang ada cukup untuk menghitungnya?
2. Metrik apa yang jujur untuk menunjukkan hasil program?
3. Metrik mana yang hanya terlihat bagus?
4. Bagaimana melaporkan bahwa sebagian besar hunt berakhir "tidak ditemukan"?
5. Bagaimana menunjukkan nilai `INC-2027-040` tanpa melebih-lebihkan?
6. Cakupan ATT&CK apa yang benar-benar bertambah?
7. Seperti apa satu halaman untuk direksi?

Pertanyaan 1 dijawab di bagian 1.1, 1.2, 2.1, dan 2.3, pertanyaan 2 di bagian 1.3, 1.4, 2.4, dan 2.5, pertanyaan 3 di bagian 1.6, pertanyaan 4 di bagian 1.7, pertanyaan 5 di bagian 1.5 dan 2.6, pertanyaan 6 di bagian 1.5 dan 2.8, dan pertanyaan 7 di bagian 1.8 dan 2.9. Bagian 2.7 menyusun register celah dan miskonfigurasi yang menjadi dasar angka "ditutup", dan bagian 2.10 merangkum jawaban untuk Dimas.

**Kapan relevan:** setiap kali laporan hunt ditulis (blok metrik dan kategori hasil diisi saat itu juga, bukan direkonstruksi); setiap akhir periode (bulan, kuartal, akhir percobaan) saat program harus membuktikan nilainya; saat manajemen bertanya "apa yang kita dapat dari hunting"; dan saat memilih hunt berikutnya dari celah yang berulang dan teknik yang belum diburu.
**Kapan bukan jawaban:** saat ada insiden aktif (angka dampak dan waktu penanganan milik laporan IR, bukan lembar metrik hunt); untuk menilai kinerja satu hunter secara individu (jumlah hunt per orang merusak program, bagian 1.6); dan untuk membandingkan PT JAB dengan organisasi lain, karena definisi "hunt", "actionable", dan "cakupan" berbeda di setiap program.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (empat hasil hunt, handover, HMM, PEAK, celah deteksi dan celah visibilitas, `origin_hunt`, metrik jembatan, finding dan intermediate finding) tidak diulang. Tabel ini hanya memuat istilah baru yang dipakai di Day ini.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Metrik outcome | Ukuran keluaran yang mengubah postur keamanan: detection aktif, insiden, celah ditutup, teknik yang kini diawasi | Availability dan MTTR per link di laporan bulanan |
| Vanity metric | Angka yang terlihat produktif tetapi hanya mengukur aktivitas (jumlah hunt, query, jam, laporan) | Jumlah ping atau tiket yang ditutup per shift |
| Lima metrik kunci PEAK | Detection dibuat atau diperbarui; insiden; celah ditemukan dan ditutup; kerentanan dan miskonfigurasi ditemukan dan ditutup; teknik yang diburu | Indikator baku laporan kinerja NOC |
| Impact, coverage, operational | Tiga kelompok penyajian metrik: apa yang dihasilkan, apakah yang diburu tepat, bagaimana proses berjalan | Kualitas layanan, cakupan monitoring, efisiensi tim |
| Kategori hasil terkontrol | Satu field di laporan dengan kosakata tetap (`ditemukan`, `tidak-ditemukan`, dst.) supaya bisa dihitung mesin | Kode penyebab gangguan baku di tiket |
| Blok Metrik | Bagian akhir laporan hunt berisi angka yang langsung dijumlahkan ke lembar program | Kolom KPI yang wajib diisi saat tiket ditutup |
| Register celah | Daftar celah data dan miskonfigurasi yang dilaporkan hunt, dengan pemilik, tanggal, dan status | Daftar temuan audit jaringan beserta status per pemilik |
| Rasio hunt ke detection | Hunt yang melahirkan minimal satu detection aktif, dibagi hunt yang selesai | Persentase temuan patroli yang menjadi alarm permanen |
| Insiden saat hunt vs dari detection hunt | Insiden yang ditemukan hunter saat mencari, dibanding insiden yang kelak dipicu detection hasil hunt | Gangguan yang ditemukan saat patroli vs yang ditangkap alarm baru minggu berikutnya |
| Layer ATT&CK Navigator | Berkas JSON yang memberi skor, warna, dan komentar per teknik ATT&CK untuk ditampilkan di matriks | Peta coverage monitoring per POP yang diwarnai |
| Score expression | Rumus di Navigator yang membuat layer baru dari layer lain, misalnya `b - a` | Overlay peta coverage sebelum dan sesudah upgrade |
| Delta cakupan | Selisih jumlah teknik yang punya detection di awal dan di akhir periode, dihitung per daftar yang jelas | Jumlah link yang kini punya alarm dibanding awal kuartal |

### 1.1 Kenapa dokumentasi menentukan

Pertanyaan pertama Dimas sebenarnya pertanyaan Nina Kartika, Manajer Risiko dan Kepatuhan TI: angka ini berasal dari dokumen mana? Hunt tanpa dokumentasi tidak bisa diulang, diukur, atau ditunjukkan (Day 01 bagian 1.6). Dokumentasi yang baik menjawab, berbulan-bulan kemudian:

- Apa hipotesisnya dan dari mana datangnya?
- Data apa yang dicakup, dan apa yang tidak?
- Apa hasilnya, termasuk "tidak ditemukan"?
- Apa yang diserahkan, ke siapa?
- Apa yang berubah karena hunt ini (deteksi, telemetri, intel)?

Ini juga yang ditunjukkan ke pewawancara: bukan "saya bisa pakai Splunk", melainkan "ini hunt yang saya jalankan, dengan hipotesis, hasil, dan deteksi yang lahir darinya".

Dokumentasi juga bahan baku metrik. Semua angka di bagian 2.4 dan 2.5 dihitung dari laporan per hunt, dari dokumen detection di repo `jab-detections`, dan dari register celah. Bila laporan tidak mencatat kategori hasil dengan kata yang sama, tanggal laporan, atau celah yang diserahkan, metrik program harus direkonstruksi dari ingatan, dan angka dari ingatan selalu lebih bagus daripada kenyataan. PT JAB mengalaminya sendiri: 22 laporan sudah ada di `jab-hunt`, tetapi baris "Hasil"-nya ditulis dengan 16 rumusan berbeda dan satu dokumen melaporkan tiga hunt sekaligus, sehingga hitungan otomatis meleset sebelum dirapikan (bagian 2.3). Status celah juga hanya tercatat di laporan tempat celah itu pertama kali muncul; tidak ada satu tempat yang menyebut mana yang sudah ditutup (bagian 2.7).

Survei SANS 2026 menyebut hanya 40% program threat hunting yang mengukur hasil hunting secara formal, turun dari 64% pada 2024; rilis pers survei itu mengaitkannya langsung dengan sulitnya program mempertahankan anggaran [S4]. Percobaan PT JAB dievaluasi akhir Juli, jadi dokumentasi yang bisa dihitung adalah syarat bertahan, bukan kerapian administrasi.

### 1.2 Dua dokumen per hunt, ditambah blok Metrik

Jawaban kedua untuk pertanyaan pertama Dimas: dokumennya sudah ada, tinggal dilengkapi. Day 07 bagian 1.9 menetapkan dua dokumen per hunt di `jab-hunt/hunts/HUNT-2027-NNN/`: `abstract.md` sebelum Execute dan `report.md` sesudahnya, ditambah folder `queries/`. Ringkasnya:

- **Abstract:** ID, asal usulan, trigger, tipe, hipotesis, ABLE, ATT&CK, data dan rentang absolut, kesiapan data, di luar cakupan, teknik analisis, kriteria sukses, FP yang diduga, time-box, handover, status.
- **Laporan:** hasil, ringkasan, cakupan nyata, di luar cakupan, kelengkapan, ambang dan asumsi, temuan berlabel, eskalasi, celah data, deteksi, rekomendasi, artefak, hipotesis baru, pelajaran.

Day ini menambahkan dua hal ke laporan, keduanya untuk keperluan menghitung:

- **Baris `Kategori hasil`** dengan kosakata tetap: `ditemukan`, `ditemukan-bukan-insiden`, `tidak-ditemukan`, `inkonklusif`, `data-tidak-cukup`. Baris `Hasil` tetap boleh ditulis bebas untuk manusia; baris kategori untuk mesin.
- **Blok `Metrik`** di akhir laporan: teknik yang diburu, uji positif, detection diusulkan dan aktif (dengan tanggal), detection lama yang diperbarui, ID celah dan miskonfigurasi di register, eskalasi beserta jamnya, dan hipotesis baru. Angka, bukan kalimat, supaya bisa dijumlahkan tanpa ditafsirkan ulang.

Blok metrik diisi saat laporan ditulis, lalu diperbarui saat statusnya berubah (detection yang aktif belakangan, celah yang ditutup). Templat lengkapnya di bagian 2.1, dan contoh terisi di bagian 2.2.

### 1.3 Lima metrik kunci PEAK

Pertanyaan kedua Dimas ("metrik apa yang jujur") dijawab oleh kerangka yang sudah dipakai program sejak hari pertama. PEAK berangkat dari satu prinsip: tujuan hunting bukan bekerja keras, melainkan memperbaiki postur keamanan, jadi yang diukur adalah dampak hunt pada program keamanan [S1]. Artikel metrik PEAK (David Bianco, Agustus 2023) menyebut lima metrik kunci [S1]. Tabel berikut meringkasnya; kolom kanan adalah hal yang paling sering terlewat saat menerapkannya.

| Metrik PEAK | Isi | Catatan penting |
|---|---|---|
| Deteksi dibuat atau diperbarui | Deteksi baru dari hunt, dan deteksi lama yang diperbaiki (FP berkurang, kasus tepi tertutup) | Perbaikan deteksi lama dihitung sama berharganya |
| Insiden yang dibuka selama atau akibat hunt | Insiden saat hunt, dan insiden yang kemudian muncul dari deteksi buatan hunt | Insiden sesudah hunt lebih bermakna, karena hunter tidak mengendalikan kapan penyerang aktif |
| Celah ditemukan dan ditutup | Sumber log yang hilang, sistem yang tidak logging dengan benar, dokumentasi baseline yang tidak ada | Hitung dua angka: dilaporkan dan ditutup; tim hunt sering tidak menutupnya sendiri |
| Kerentanan dan miskonfigurasi ditemukan dan ditutup | Miskonfigurasi, software usang, kerentanan lain yang dilaporkan | Juga dua angka: dilaporkan dan diperbaiki |
| Teknik yang diburu | Jumlah teknik unik, dipetakan ke ATT&CK, Kill Chain, atau Pyramid of Pain | Menunjukkan cakupan hunting |

Di luar lima itu, PEAK memakai Hunting Maturity Model (HMM0 sampai HMM4) untuk mengukur kematangan program secara keseluruhan, bukan dampak per hunt [S1]. Artikel itu menyarankan sebagian besar organisasi setidaknya berada di HMM2, banyak yang membidik HMM3, dan idealnya bergerak ke HMM4 dengan mengubah sebagian besar hunt menjadi deteksi otomatis [S1]. Untuk PT JAB, penilaian Day 01 bagian 1.5 (HMM1 per 1 Februari, target Juli perilaku HMM2 konsisten dan awal HMM3) dinilai ulang di lembar metrik dengan bukti yang sama ketatnya.

PEAK juga menganjurkan satu kebiasaan yang membuat metrik pertama dan kedua bisa dihitung: catat detection mana berasal dari hunt mana, sehingga insiden yang kelak dipicu detection itu bisa ditautkan kembali ke hunt asalnya [S1]. Di PT JAB kebiasaan itu sudah dimulai di Day 14 dengan `origin_hunt`, tanggal laporan, dan tanggal aktif.

### 1.4 Mengelompokkan: impact, coverage, operational

Lima metrik PEAK lebih mudah disajikan bila dikelompokkan. Pengelompokan detection, coverage, dan operational dipakai beberapa penulis vendor [S3]; PEAK sendiri menyajikannya sebagai daftar lima metrik. Catatan ini memakai tiga kelompok berikut sebagai alat bantu penyajian; baca kolom "Pertanyaan", karena itulah urutan yang dipakai di satu halaman manajemen.

| Kelompok | Pertanyaan | Metrik |
|---|---|---|
| Impact | Apa yang dihasilkan hunt? | Deteksi dibuat/diperbarui; insiden saat hunt dan dari deteksi buatan hunt; celah ditutup; kerentanan/miskonfigurasi ditutup [S1] |
| Coverage | Apakah kita memburu hal yang tepat? | Teknik ATT&CK yang diburu [S1]; teknik yang kini punya deteksi dari hunt; host yang benar-benar tercakup; sumber data dipakai dibanding dibutuhkan [S3] |
| Operational | Bagaimana jalannya proses? | Waktu laporan ke deteksi aktif, waktu eskalasi temuan, umur abstract di backlog, ritme hunt [S3] |

Metrik impact yang paling bernilai, karena menunjukkan hunting menambah kemampuan permanen. Metrik coverage menunjukkan apakah hunt diarahkan ke celah yang benar. Metrik operational berguna untuk mengelola program (di mana jembatan macet, berapa lama temuan berbahaya menunggu), tetapi tidak boleh disajikan sebagai bukti nilai.

Intel 471 menambahkan dua ukuran yang cocok untuk kelompok impact: dwell time dan waktu containment untuk insiden yang ditemukan secara proaktif, dan deteksi baru untuk ancaman yang tidak tertangkap cara lain [S2]. Ukuran pertama dipakai untuk `INC-2027-040` di bagian 1.5, dengan angka containment yang diambil dari laporan IR, bukan dari lembar hunt.

### 1.5 Metrik impact dan coverage secara rinci

Pertanyaan kelima dan keenam Dimas ada di sini: nilai `INC-2027-040`, dan cakupan ATT&CK yang benar-benar bertambah.

Metrik impact butuh pelacakan: deteksi mana berasal dari hunt mana (bagian 2.6). Untuk insiden, PEAK membedakan dua jenis [S1]:

- **Insiden saat hunt.** Ditemukan hunter ketika mencari. Nilainya nyata, tetapi bergantung keberuntungan: penyerang kebetulan aktif atau tidak di area dan rentang yang diperiksa.
- **Insiden dari deteksi buatan hunt.** Dibuka setelah hunt, karena detection yang dibuat atau diperbaiki hunt memicu. PEAK menyebut melacak jenis ini sebagai pendekatan yang lebih baik, karena itu bukti detection tersebut bekerja di dunia nyata [S1].

`INC-2027-040` termasuk jenis pertama. Cara menunjukkan nilainya tanpa melebih-lebihkan adalah menyebut fakta yang bisa ditelusuri ke laporan `HUNT-2027-013` dan laporan IR, lalu berhenti di situ:

- **Apa yang ditemukan:** persistence `\PDFSuite Updater` di `SBY-WS-0107`, terdaftar sejak 2026-12-05, aktif sekitar 82 hari sampai terlihat Kamis 2027-02-25 11:05.
- **Kenapa cara lain tidak menemukannya:** daftar IOC `INC-2026-026` menunjuk domain C2 lain, installer dijalankan dari rumah lewat split tunnel sehingga tidak terlihat di proxy, dan host itu tanpa MDE, Sysmon, dan audit 4698. Yang menemukannya adalah pola perilaku di disk, lewat Velociraptor.
- **Seberapa cepat diserahkan:** pesan ke Dimas 11:12, insiden SEV-3 dinyatakan 11:40, handover ke IR 11:45. Dari terlihat sampai dinyatakan insiden: 35 menit.
- **Apa yang tidak diklaim:** kerugian yang dicegah, serangan lanjutan yang digagalkan, atau angka dampak apa pun. Angka containment dan dampak ada di laporan IR (TL Rudi Hartanto); lembar metrik hunt merujuknya, tidak menghitung ulang.

Satu catatan jujur ikut ditulis: detection "JAB - Scheduled task menjalankan biner dari folder AppData pengguna" yang lahir dari pola ini hanya mencakup 214 host ber-audit, sehingga tidak akan menangkap laptop seperti `SBY-WS-0107`. Kontrol untuk tipe host itu adalah hunt Velociraptor mingguan dari `HUNT-2027-013`, bukan detection ES. Insiden dari detection buatan hunt per 18 Maret: nol, dan itu bukan angka yang bisa dinilai setelah satu hari detection aktif.

Untuk coverage, ada tiga sudut:

- **Teknik yang diburu:** dipetakan ke ATT&CK dari baris ATT&CK di abstract. Ini menunjukkan ke mana hunting diarahkan, termasuk area yang belum disentuh sama sekali.
- **Teknik yang kini punya deteksi dari hunt:** dihitung dari dua layer ATT&CK Navigator, awal dan akhir periode, dengan skor jumlah detection aktif per teknik. Selisihnya adalah delta cakupan. Hitung terhadap daftar yang jelas (misalnya teknik yang diburu, atau teknik di layer awal), bukan terhadap seluruh matriks ATT&CK; persentase atas seluruh matriks membuat kenaikan tampak tidak berarti dan mendorong orang mengejar teknik yang tidak relevan.
- **Host yang benar-benar tercakup:** satu ID teknik "tercakup" tidak berarti semua host terawasi. Di PT JAB sebagian besar detection endpoint hanya berlaku di 214 host ber-Sysmon dan ber-audit.

Coverage per ID teknik juga mudah melebih-lebihkan. AttackIQ (Maret 2026) mengingatkan bahwa cakupan adalah spektrum, bukan biner: satu detection untuk satu prosedur tidak sama dengan cakupan seluruh teknik, dan klaim cakupan seharusnya menyebut platform, prosedur yang diuji, arti "tercakup" (alert, log, blok), dan tanggal terakhir diuji [S11]. Day 14 bagian 1.9 menyebut hal yang sama dari sisi PT JAB: cakupan dihitung per prosedur, bukan per ID teknik. Karena itu komentar di layer akhir menulis prosedur, cakupan host, dan `origin_hunt` untuk setiap teknik yang bertambah (bagian 2.8).

### 1.6 Vanity metrics: yang harus dihindari

Pertanyaan ketiga Dimas sudah memberi contohnya sendiri: "lebih dari dua puluh hunt dalam enam minggu". Metrik yang terlihat produktif tetapi tidak menunjukkan nilai:

- **Jumlah hunt yang dijalankan.** PEAK menyebut angka ini pada dasarnya hanya mengukur seberapa keras tim bekerja, sementara tujuan hunting bukan bekerja keras [S1]. Tetapi PEAK tetap menganjurkan mencatatnya, sebagai konteks [S1]. Intel 471 juga memasukkan jumlah sesi hunting yang selesai per periode sebagai ukuran aktivitas tingkat tim [S2].
- **Jumlah query, laporan, jam kerja, atau hipotesis yang dibuat.** Menciptakan rasa produktif yang palsu; tim yang menjalankan banyak hunt dangkal belum tentu lebih efektif daripada tim dengan sedikit hunt mendalam [S3]. Dropzone memberi contoh klaim "500 hipotesis diselidiki kuartal ini" yang tidak berarti apa-apa tanpa konteks apa yang ditemukan atau diperbaiki [S3]. Intel 471 menggolongkan jumlah laporan yang dibuat sebagai pengalih perhatian, karena tidak mencerminkan isi yang disampaikan ke pemangku kepentingan [S2].
- **Jumlah hunt per hunter.** Intel 471 menggolongkannya sebagai metrik yang merusak program, karena mendorong burnout dan membuat talenta keluar [S2]. Di PT JAB pelaksananya satu orang, sehingga "hunt per hunter" sama dengan jumlah hunt, dan menjadikannya target sama dengan meminta hunt yang lebih dangkal.
- **Persentase hijau di heatmap ATT&CK.** Warna per ID teknik menyembunyikan prosedur dan host yang belum tercakup [S11]. Angka ini terlihat bagus justru karena kasar.
- **Nol alert dari detection baru.** Detection yang diam sehari setelah aktif belum membuktikan apa-apa; ia bisa diam karena lingkungan bersih atau karena buta. Yang membuktikan adalah uji positif dan waktu (Day 14 bagian 1.8).

Aturan praktis: ukur hasil (outcome), bukan aktivitas. Jumlah hunt boleh muncul di laporan, tetapi diberi label konteks, diletakkan di bawah angka outcome, dan tidak pernah menjadi target.

### 1.7 "Tidak ditemukan" sebagai hasil, bukan kegagalan

Pertanyaan keempat Dimas adalah yang paling menentukan bagi percobaan ini: 20 dari 22 hunt yang selesai berkategori `tidak-ditemukan`.

PEAK menegaskan bahwa bila aktivitas yang diburu memang tidak terjadi, itu tidak berarti hunt gagal atau tidak berguna [S1]. Penulis lain menambahkan bahwa hunt yang mengonfirmasi perilaku normal di sistem kritis menghasilkan baseline cakupan yang tervalidasi [S3]; Dropzone bahkan menghitung hunt seperti itu sebagai temuan dalam rasio hasilnya, dan tidak menyarankan menilai hunt hanya dari ancaman yang ditemukan [S3]. Hunt "tidak ditemukan" juga sering menghasilkan metrik impact lain: celah log ditemukan, baseline terdokumentasi, atau deteksi baru yang ditulis untuk berjaga bila perilaku itu muncul kelak. Di PT JAB, delapan dari sembilan hunt yang melahirkan detection aktif berkategori `tidak-ditemukan` (bagian 2.3).

Rasio temuan yang rendah bukan kegagalan, tetapi tetap sinyal yang perlu dibaca: mungkin celah data, hipotesis yang kurang tajam, pemilihan hipotesis yang tidak mengikuti ancaman relevan, atau query yang tidak pernah dibuktikan sanggup menangkap pola yang dicari. Sinyal terakhir itu bisa diukur. Dari 20 hunt `tidak-ditemukan` di PT JAB, hanya dua yang punya uji positif: `HUNT-2027-015` (query TaskScheduler menandai `\PDFSuite Updater` pada koleksi `HUNT-2027-013`) dan `HUNT-2027-023` (lima test Atomic Red Team di VM lab, yang sekaligus menemukan dan menutup celah pola `about:`). Untuk 18 hunt lain, "tidak ditemukan" berarti tidak ada kecocokan dengan query yang belum dibuktikan menangkap contoh positif. Angka itu masuk lembar metrik sebagai keterbatasan, bukan disembunyikan.

Karena itu laporan "tidak ditemukan" harus menyatakan cakupan dengan jelas (Day 01 bagian 1.6), sehingga ia terbaca sebagai bukti cakupan, bukan waktu yang terbuang. Kalimat "tidak ditemukan regsvr32 dari Office" tanpa cakupan tidak berarti apa-apa; "tidak ditemukan pada 214 host ber-Sysmon, Sysmon EID 1, 1-28 Februari 2027; 229 workstation tanpa Sysmon dan `JKT-WS-0532` setelah 2 Februari tidak tercakup; query terbukti menangkap uji positif di lab" adalah bukti yang bisa diaudit.

Hasil yang bukan insiden tetapi berupa daftar pekerjaan juga sah, dan sering bernilai tinggi. `HUNT-2027-025` menghasilkan inventaris VBScript yang masih dipakai untuk tim IT sebelum fase berikut deprecation VBScript; `HUNT-2027-024` menemukan salinan `cmd.exe` yang diganti nama dan launcher payroll yang membawa `regsvr32.exe` lama; `HUNT-2027-019` menemukan pelanggaran kebijakan admin yang kini berhenti. Hunt inventaris dan konfigurasi seperti ini dicatat di kelompok impact sebagai miskonfigurasi atau celah yang dilaporkan, dan statusnya dilacak sampai ditutup (bagian 2.7).

### 1.8 Menyajikan ke manajemen

Pertanyaan ketujuh Dimas butuh bentuk, bukan hanya angka. Satu halaman untuk manajemen per periode berisi empat bagian, dengan urutan yang disengaja:

- **Yang ditinggalkan program secara permanen:** detection aktif dan prosedur yang ditutupnya, insiden yang ditemukan, pelanggaran yang dihentikan, kemampuan baru (misalnya koleksi endpoint), celah yang ditutup.
- **Arti "tidak ditemukan":** satu kalimat tentang apa yang sudah diperiksa, dan satu kalimat tentang batasnya (host yang tidak tercakup).
- **Risiko yang masih terbuka dan keputusan yang dibutuhkan:** celah visibilitas yang perlu investasi atau perubahan konfigurasi, dengan pemilik.
- **Rencana periode berikutnya:** area yang belum diburu, dan ukuran yang akan dilaporkan di evaluasi berikutnya.

Hindari tabel vanity (jumlah query, jumlah event yang dipindai). Bila atasan meminta angka aktivitas, berikan, tetapi letakkan di bawah angka outcome dan beri konteksnya. Intel 471 menyebut tujuan metrik di depan manajemen adalah menerjemahkan pekerjaan menjadi keluaran yang berarti bagi pemimpin di bidang keamanan, keuangan, dan risiko, sekaligus dasar keputusan investasi pada orang, proses, dan platform [S2]. Untuk PT JAB, keputusan yang paling jelas adalah anggaran rollout Sysmon ke 229 workstation (Day 04 bagian 2.8), karena hampir setiap kesimpulan "tidak ditemukan" di endpoint dibatasi oleh celah itu.

Metrik juga harus dipakai ke dalam. Di PEAK, fase Act with Knowledge berarti hasil hunt dan metriknya menjadi bahan memilih hunt berikutnya [S5]. Celah visibilitas yang muncul berulang di beberapa laporan adalah alasan untuk menunda hunt di area itu sampai datanya ada, atau memakai jalur lain (Velociraptor) secara sengaja. Teknik dan area yang belum disentuh sama sekali, di PT JAB data cloud `aws` dan `azure` serta sebagian besar identitas, menjadi kandidat pertama kuartal berikutnya.

## 2. Contoh dan langkah praktis: lembar metrik Q1 Program hunt PT JAB

Bagian ini mengerjakan permintaan Dimas hari Kamis itu: merapikan laporan supaya bisa dihitung, menyusun register, menghitung lembar metrik periode Senin 2027-02-01 sampai Kamis 2027-03-18, mengukur cakupan ATT&CK, lalu menulis satu halaman untuk direksi. Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Perintah `grep` dijalankan di salinan lokal repo GitLab `jab-hunt` dan `jab-detections`; query Splunk ditulis untuk ES PT JAB. Versi untuk portofolio pribadi ada di bagian 3.

### 2.1 Templat laporan final dengan kategori dan blok Metrik

Templat ini adalah laporan Day 07 bagian 1.9 dengan dua tambahan Day ini, dan menjawab bagian kedua pertanyaan pertama Dimas: laporannya cukup, setelah dua baris ini ada di semua laporan.

```
ID            : HUNT-2027-NNN                        Selesai: YYYY-MM-DD HH:MM
Hasil         : <kalimat bebas untuk manusia>
Kategori hasil: ditemukan | ditemukan-bukan-insiden | tidak-ditemukan | inkonklusif | data-tidak-cukup
Ringkasan     : <2-3 kalimat: apa yang diperiksa dan apa jawabannya>
Cakupan nyata : <host yang BENAR-BENAR tercakup, sumber, rentang absolut, angka event>
Di luar cakupan: <host, periode, jalur teknik, item yang tidak sempat ditinjau>
Kelengkapan   : <feed diam, ringkasan data model, uji kesetaraan raw vs tstats>
Ambang/asumsi : <ambang dan alasannya dari distribusi; aturan normalisasi dan versinya>
Temuan        : <item yang ditinjau + label + bukti di luar query (tiket, pemilik, konfirmasi)>
Eskalasi      : <IR: kapan dan apa yang diserahkan, atau "tidak ada">
Celah data    : <celah visibilitas -> pemilik; ID register Gnn>
Deteksi       : <abstract deteksi ke Sari: logika kasar, level, volume, FP, pengecualian>
Rekomendasi   : <salah konfigurasi atau risiko -> pemilik sistem; ID register Mnn>
Artefak       : <lookup, macro, file .spl, angka Job Inspector>
Hipotesis baru: <-> backlog, dengan nomor bila ABLE sudah lengkap>
Pelajaran     : <apa yang akan dilakukan berbeda>

Metrik (diisi saat laporan, diperbarui saat status berubah)
Teknik diburu : <ID ATT&CK dari baris ATT&CK abstract; tanpa pemetaan bersyarat>
Uji positif   : ya (<cara, tanggal>) | tidak
Detection     : <n> diusulkan; <n> aktif (<nama>, <tanggal aktif>); <n> ditunda/ditolak
Det. diperbarui: <n> detection lama yang diubah karena hunt ini (<nama>)
Celah         : baru <Gnn, ...>; berulang <Gnn, ...>
Miskonfigurasi: baru <Mnn, ...>
Eskalasi      : <jam terlihat> -> <jam pesan IR> -> <jam insiden dinyatakan> | tidak ada
Baseline      : <lookup/baseline yang dibuat atau diperbarui>
Waktu         : <hari, jam mulai-selesai; hunt lain yang dikerjakan bersamaan>
```

Cara membaca tambahan ini:

- **`Kategori hasil`** memisahkan kalimat untuk manusia dari kategori untuk dihitung. Kategori `ditemukan-bukan-insiden` dibutuhkan PT JAB sejak `HUNT-2027-019`: pelanggaran kebijakan bukan insiden, tetapi juga bukan "tidak ditemukan". Temuan jinak yang dikonfirmasi tetap masuk `tidak-ditemukan`, karena hipotesisnya tentang aktivitas berbahaya.
- **`Teknik diburu`** hanya memuat ID yang memang diuji. Pemetaan bersyarat di abstract, misalnya "T1048 bila DNS kanal exfil terpisah" di `HUNT-2027-003` atau "T1176.001 bila pemanggilnya ekstensi browser" di `HUNT-2027-020`, tidak dihitung, karena hunt itu tidak menguji teknik tersebut secara terpisah.
- **ID register `Gnn` dan `Mnn`** menunjuk satu baris di register celah dan miskonfigurasi (bagian 2.7). Laporan tidak menyimpan status; status ada di register, supaya satu celah yang muncul di lima laporan tidak dihitung lima kali dan penutupannya cukup dicatat sekali.
- **`Eskalasi` dengan tiga jam** memberi metrik operational yang paling penting untuk temuan berbahaya: berapa lama temuan menunggu sebelum masuk IR.

**Kapan gagal:** blok metrik diisi sekali lalu tidak pernah diperbarui, sehingga detection yang aktif tiga minggu setelah laporan tetap tercatat "diusulkan"; atau kategori ditulis dengan variasi ("tidak-terbukti", "tidak ditemukan") sehingga hitungan otomatis kembali meleset.

### 2.2 Contoh laporan terisi: `HUNT-2027-023`

Contoh ini dipilih karena menjawab dua pertanyaan Dimas sekaligus: ia berkategori `tidak-ditemukan`, tetapi melahirkan dua detection aktif dan punya uji positif. Isinya diambil dari laporan Kamis 2027-03-11 (Day 13 bagian 2.8) dan handover Day 14, dengan baris kategori dan blok metrik ditambahkan Kamis 2027-03-18.

```
ID            : HUNT-2027-023                          Selesai: Kamis 2027-03-11 13:00
Hasil         : Tidak ditemukan (tidak terbukti)
Kategori hasil: tidak-ditemukan
Ringkasan     : Tidak ada aplikasi Office yang memunculkan regsvr32, rundll32, atau mshta untuk
                menjalankan kode, dan tidak ada proxy binary dengan scriptlet atau skrip inline, di
                214 host ber-Sysmon selama Februari 2027. Query terbukti menangkap uji positif di lab.
Cakupan nyata : 214 host ber-Sysmon, Sysmon EID 1, 2027-02-01 00:00 - 2027-03-01 00:00 WIB
Di luar cakupan: 229 workstation tanpa Sysmon; JKT-WS-0532 setelah 2027-02-02 10:14;
                argumen terobfuscate yang tidak cocok pola teks; rantai dengan lebih dari satu perantara
Kelengkapan   : Sysmon JKT-WS-0532 diam sejak 2027-02-02 10:14 (host aktif)
Ambang/asumsi : Tanpa ambang frekuensi; setiap eksekusi tahap A dan tahap B ditinjau
Temuan        : Tahap A: 76 eksekusi Outlook -> rundll32 di 42 host (71 url.dll,FileProtocolHandler
                https di 39 host; 5 OpenAs_RunDLL lampiran .dwg dari Content.Outlook di 5 host);
                Tahap B (semua parent): 140 eksekusi di 4 kelompok, semua jinak terkonfirmasi:
                rundll32 FileProtocolHandler 118/52 host (Outlook 71, aplikasi chat 47),
                rundll32 OpenAs dari folder user 5/5, regsvr32 add-in VidMeet 14/6, mshta HTA
                installer printer 3/3; scriptlet/inline 0
Eskalasi      : tidak ada
Celah data    : 229 workstation tanpa Sysmon (G01, berulang); JKT-WS-0532 (G04, berulang)
Deteksi       : "JAB - Office meluncurkan signed proxy binary" dan "JAB - Proxy binary dengan
                scriptlet atau skrip inline" -> Sari (diproses Selasa 2027-03-16)
Rekomendasi   : tidak ada yang baru
Artefak       : queries/01-tahap-a.spl, 02-tahap-b.spl, 03-tahap-b-about.spl; GUID test Atomic di
                lab-tests.md
Hipotesis baru: (dari handover detection 2027-03-16) Office -> perantara -> proxy binary;
                proxy binary lain dari Office (msiexec, cmstp, installutil, regasm);
                rundll32 dengan lebih dari satu "dll," di command line
Pelajaran     : Uji positif menemukan celah pola mshta "about:" (T1218.005 test 10) sebelum hasil
                ditulis; data Februari dijalankan ulang dengan pola perbaikan, tetap 140

Metrik (diperbarui Kamis 2027-03-18)
Teknik diburu : T1218.010, T1218.011, T1218.005, T1204.002 (ATT&CK v20)
Uji positif   : ya (VM lab jab-lab-win11, Kamis 2027-03-11 10:30-11:45, 5 test Atomic Red Team)
Detection     : 2 diusulkan; 2 aktif Rabu 2027-03-17 09:00 (6 hari dari laporan):
                JAB - Office meluncurkan signed proxy binary (alert ES, level high)
                JAB - Proxy binary dengan scriptlet atau skrip inline (alert ES)
Det. diperbarui: 0
Celah         : baru -; berulang G01, G04
Miskonfigurasi: baru -
Eskalasi      : tidak ada
Baseline      : -
Waktu         : Kamis 2027-03-11 08:40-13:00, bersamaan dengan HUNT-2027-024 dan -025
```

Cara membaca laporan ini dan kenapa bentuknya begitu:

- **Cakupan menyebut host yang tidak tercakup.** Bila suatu hari terbukti salah satu dari 229 workstation tanpa Sysmon menjalankan pola ini di Februari, laporan ini tetap benar, karena ia tidak pernah mengklaim host itu bersih.
- **Temuan jinak tetap dicatat beserta alasannya.** Pola Outlook dengan `FileProtocolHandler` dan `OpenAs_RunDLL` menjadi pengecualian sempit di rule (Day 14 bagian 2.2), dan mencegah hunter berikutnya memeriksa ulang hal yang sama.
- **Angka di Temuan harus menjumlah.** 118 + 5 + 14 + 3 = 140, dan 71 + 5 = 76. Pembaca yang menghitung ulang dan mendapat angka berbeda akan meragukan seluruh laporan.
- **Blok metrik berisi angka dan ID, bukan kalimat.** Dua detection, enam hari, ID celah yang berulang. Celah G01 tidak dihitung baru di sini, karena sudah dilaporkan sejak `HUNT-2027-001`.
- **Teknik diburu memuat keempat ID dari baris ATT&CK abstract**, termasuk T1218.011 dan T1218.005 yang tidak menghasilkan temuan, karena hipotesisnya memang menguji ketiga binary itu dan prasyarat T1204.002.

**Kapan gagal:** blok metrik menulis "detection: 2" tanpa nama dan tanggal aktif; enam bulan kemudian tidak ada yang tahu apakah dua detection itu masih aktif, sudah digabung, atau pernah dimatikan.

### 2.3 Register hunt: 25 nomor, 22 laporan

Register ini adalah fondasi semua angka, dan jawaban paling langsung untuk pertanyaan pertama Dimas. Langkah pertamanya menghitung kategori hasil dari laporan yang ada.

**Tujuan:** menghitung kategori hasil dari semua laporan di `jab-hunt` tanpa membaca satu per satu.

**Sintaks (sebelum dirapikan):**

```bash
grep -h "^Hasil" jab-hunt/hunts/HUNT-2027-*/report.md | sort | uniq -c | sort -rn
```

| Bagian | Fungsi |
|---|---|
| `grep -h "^Hasil"` | Ambil baris yang diawali `Hasil` dari setiap `report.md`, tanpa nama file (`-h`) |
| `HUNT-2027-*/report.md` | Semua folder hunt; folder tanpa `report.md` tidak ikut |
| `sort \| uniq -c` | Kelompokkan baris yang persis sama dan hitung |
| `sort -rn` | Yang paling banyak di atas |

Keluaran ilustrasi:

```
      4 Hasil         : Tidak ditemukan aktivitas berbahaya
      2 Hasil         : Tidak ditemukan (tidak terbukti)
      1 Hasil         : Tidak terbukti
      1 Hasil         : Tidak ditemukan aktivitas berbahaya (hipotesis tidak terbukti)
      1 Hasil         : Tidak ditemukan C2; 1 item inkonklusif ke backlog
      1 Hasil         : Tidak ditemukan
      1 Hasil         : Tidak ditemukan (kategori autostart terpilih, tanpa scheduled task)
      1 Hasil         : DITEMUKAN - handover ke IR 11:45, INC-2027-040 SEV-3 (TL Rudi Hartanto)
      1 Hasil         : Tidak ditemukan aktivitas berbahaya (selain SBY-WS-0107, sudah di INC-2027-040)
      1 Hasil         : Tidak ditemukan akses LSASS tidak lazim
      1 Hasil         : Tidak ditemukan password spray
      1 Hasil         : DITEMUKAN pelanggaran kebijakan (bukan insiden)
      1 Hasil         : Tidak ditemukan C2; BDG-WS-0196 ditutup jinak terkonfirmasi
      1 Hasil         : Tidak ditemukan DNS tunneling
      1 Hasil         : Tidak ditemukan exfiltration
      1 Hasil         : Tidak ditemukan (tidak terbukti); ditemukan-jinak 1 rename, 1 salinan di lokasi salah
```

**Cara membaca hasil:** 16 rumusan untuk lima kategori, dan totalnya 20 baris, bukan 22. Dua masalah terlihat sekaligus. Pertama, kalimat bebas tidak bisa dijumlahkan mesin; "Tidak terbukti" dan "Tidak ditemukan" berarti sama, tetapi `uniq` memisahkannya. Kedua, laporan Selasa 2027-03-02 melaporkan `HUNT-2027-014`, `-015`, dan `-016` dalam satu dokumen di folder `-014` (Day 10 bagian 2.8), sehingga folder `-015` dan `-016` tidak punya `report.md`. Perbaikannya: tambahkan baris `Kategori hasil` ke 20 laporan, dan buat `report.md` pendek di folder `-015` dan `-016` yang berisi ID, kategori, metrik masing-masing, dan rujukan ke laporan gabungan.

**Sintaks (setelah dirapikan):**

```bash
grep -h "^Kategori hasil" jab-hunt/hunts/HUNT-2027-*/report.md | sort | uniq -c
grep -L "^Kategori hasil" jab-hunt/hunts/HUNT-2027-*/report.md
```

Keluaran ilustrasi:

```
      1 Kategori hasil: ditemukan
      1 Kategori hasil: ditemukan-bukan-insiden
     20 Kategori hasil: tidak-ditemukan
```

Perintah kedua (`-L`, file yang tidak memuat pola) tidak mengembalikan apa pun, artinya semua laporan sudah punya kategori. Total 22.

Tabel berikut adalah register yang disimpan di `jab-hunt/docs/hunt-register-2027-Q1.md`. Setiap nomor yang pernah dibagikan muncul, termasuk yang tidak punya laporan sendiri; baca kolom "Keluaran permanen", karena di situlah terlihat bahwa hunt `tidak-ditemukan` juga meninggalkan sesuatu.

| Hunt | Selesai | Area dan cakupan | Kategori hasil | Keluaran permanen |
|---|---|---|---|---|
| `-001` | Kam 4 Feb | Endpoint, 153 ws ber-Sysmon | tidak-ditemukan | Risk ES "Office memunculkan shell"; G01 |
| `-002` | Sel 2 Feb | Endpoint, 214 host | tidak-ditemukan (jinak: certutil `jkt-mgmt01`) | Alert ES certutil/bitsadmin; G02 |
| `-003` | (abstract Kam 4 Feb) | DNS | dijalankan sebagai `-021` | Baseline `jab_hunt_baseline_dns_parent.csv`, allowlist DNS |
| `-004` | Kam 18 Feb | Endpoint, 214 host | tidak-ditemukan | Usulan digabung ke detection `-015`; satu usulan tunda; abstract `-008`, `-009`; M03, M04 |
| `-005` | Kam 11 Feb | Jaringan, proxy | tidak-ditemukan (1 item inkonklusif, ditutup 9 Mar) | Laporan hunter beacon; `jab_hunt_baseline_beacon.csv`; G10, G11 |
| `-006` | Kam 11 Feb | Endpoint, 153 ws | tidak-ditemukan | Laporan hunter first-seen; baseline parent-child dan macro |
| `-007` | Sel 16 Feb | Endpoint, 153 ws | tidak-ditemukan | Baseline diperbarui; M01, M02 |
| `-008` | belum | Endpoint | kandidat, belum dijalankan | (abstract sejak 18 Feb) |
| `-009` | (TIDAK SIAP 18 Feb) | Endpoint, 229 ws | dijalankan sebagai `-013` | Memicu keputusan koleksi endpoint permanen (G06) |
| `-010` | Sel 23 Feb | Linux, 2 server | tidak-ditemukan | Wazuh 100200, 100201; G07 ditutup; G08, G09; M05 |
| `-011` | Sel 23 Feb | Linux, `jkt-bastion01` | tidak-ditemukan | Laporan hunter first-seen SSH |
| `-012` | Kam 25 Feb | Endpoint, VR 375 host | tidak-ditemukan | Baseline autoruns; M06; 1 tiket software |
| `-013` | Kam 25 Feb | Endpoint, VR 379 host | ditemukan | `INC-2027-040`; hunt VR mingguan; G03, G15; 2 tiket software |
| `-014` | Sel 2 Mar | Endpoint, 213 host + VR 431 | tidak-ditemukan | `jab_hunt_baseline_runkeys.csv` dan macro |
| `-015` | Sel 2 Mar | Endpoint, 214 host + VR 431 | tidak-ditemukan | Alert ES scheduled task AppData; 1 tiket software |
| `-016` | Sel 2 Mar | Endpoint, 214 host + VR 218 | tidak-ditemukan | G12; M07 |
| `-017` | Kam 4 Mar | Endpoint, 214 host | tidak-ditemukan | Kandidat detection LSASS kembali ke backlog |
| `-018` | Kam 4 Mar | Identitas, DC + Entra | tidak-ditemukan | Laporan hunter spray; G13 ditutup; M09, M10 |
| `-019` | Kam 4 Mar | Endpoint 214 host + 4624 | ditemukan-bukan-insiden | Alert ES logon admin; M08 |
| `-020` | Sel 9 Mar | Jaringan, proxy + firewall | tidak-ditemukan | Risk ES beacon; `jab_hunt_egress_infra.csv`; M11, M17 |
| `-021` | Sel 9 Mar | DNS, 4 resolver | tidak-ditemukan | 7 baris allowlist DNS; M12 |
| `-022` | Sel 9 Mar | Jaringan, proxy + firewall | tidak-ditemukan | Risk ES unggahan; `jab_hunt_baseline_dest.csv`; G15 |
| `-023` | Kam 11 Mar | Endpoint, 214 host | tidak-ditemukan | 2 alert ES |
| `-024` | Kam 11 Mar | Endpoint, 214 host + MDE | tidak-ditemukan (jinak: 1 rename, 1 salinan) | `jab_hunt_sysbin_ofn.csv`; usulan tunda; M13, M14, M16 |
| `-025` | Kam 11 Mar | Endpoint, 214 host | tidak-ditemukan | Alert ES script host; inventaris VBScript; M15 |

Tiga hal terbaca dari register ini. Pertama, 25 nomor tidak sama dengan 25 hunt: 22 selesai dengan laporan, 2 dijalankan di bawah nomor lain (`-003` sebagai `-021`, `-009` sebagai `-013`), dan 1 masih kandidat (`-008`). Menghitung nomor sebagai hunt akan menggelembungkan angka aktivitas dan, lebih buruk, membuat `-003` dan `-021` tampak sebagai dua hunt DNS. Kedua, sebaran area tidak seimbang: 15 hunt endpoint Windows, 4 jaringan dan DNS, 2 Linux, 1 identitas, dan 0 cloud. Ketiga, delapan dari sembilan hunt yang melahirkan detection aktif berkategori `tidak-ditemukan` (semua kecuali `-019`), sedangkan satu-satunya hunt yang menemukan kompromi (`-013`) tidak melahirkan detection ES, karena datanya tidak ada di SIEM; kontrolnya hunt Velociraptor mingguan. Mengukur nilai hunt dari "berapa yang menemukan sesuatu" akan membuang delapan sumber detection itu.

**Variasi:** `grep -l "ditemukan-bukan-insiden" jab-hunt/hunts/*/report.md` untuk daftar hunt yang menghasilkan pekerjaan bagi pemilik sistem; atau `grep -h "^Teknik diburu" jab-hunt/hunts/*/report.md | grep -oE "T[0-9]{4}(\.[0-9]{3})?" | sort -u | wc -l` untuk jumlah teknik unik (bagian 2.5).

**Kapan gagal:** satu dokumen melaporkan beberapa hunt tanpa stub di folder masing-masing; atau kategori diganti di laporan tanpa memperbarui register, sehingga dua sumber memberi angka berbeda saat Nina menelusurinya.

### 2.4 Lembar metrik Q1 (per Kamis 2027-03-18)

Lembar ini adalah jawaban pertanyaan kedua Dimas dalam bentuk yang bisa ditelusuri Nina: setiap baris menyebut sumbernya, dan setiap angka bisa dihitung ulang dari register, laporan, dan dokumen detection. Disimpan di `jab-hunt/docs/hunt-metrics-2027-Q1.md`; angka untuk Selasa 2027-03-23 sampai Rabu 2027-03-31 ditambahkan saat evaluasi.

```
Periode            : Senin 2027-02-01 sampai Kamis 2027-03-18 (dihitung Kamis 2027-03-18 12:00 WIB)
Sumber angka       : hunts/*/report.md (Kategori hasil, Metrik), docs/hunt-register-2027-Q1.md,
                     docs/gaps.md, jab-detections/docs/*.md, coverage/coverage-2027-Q1-*.json

KONTEKS (dicatat, bukan ukuran nilai)
Hari hunting dialokasikan    : 14 (Selasa dan Kamis); 11 menjalankan hunt, 3 untuk kesiapan data
                               (9 Feb), hunt ke deteksi (16 Mar), dan metrik (18 Mar)
Nomor hunt dibagikan         : 25 = 22 selesai + 2 dijalankan di nomor lain + 1 kandidat
Hunt selesai                 : 22 (endpoint Windows 15, jaringan dan DNS 4, Linux 2, identitas 1, cloud 0)
Kategori hasil               : ditemukan 1 | ditemukan-bukan-insiden 1 | tidak-ditemukan 20
                               | inkonklusif 0 | data-tidak-cukup 0
  dari 20 tidak-ditemukan    : 2 dengan temuan jinak di baris Hasil (-002, -024); 1 dengan item
                               inkonklusif yang ditutup jinak 2027-03-09 (-005); 2 dengan uji positif

IMPACT
Detection lahir dari hunt, aktif     : 12 (ES 10: alert 6, risk 3, finding-based 1; Wazuh 2)
Hunt yang melahirkan detection aktif : 9 dari 22
Detection lama diperbarui karena hunt: 0
Laporan hunter terjadwal             : 4, plus 1 hunt Velociraptor mingguan (mulai 2027-03-22)
Usulan ditunda / ditolak / ke backlog: 3 / 1 / 1
Insiden saat hunt                    : 1 (INC-2027-040, SEV-3, dinyatakan 2027-02-25 11:40)
Insiden dari detection buatan hunt   : 0 (Wazuh aktif sejak 2027-02-25, ES sejak 2027-03-17 09:00)
Pelanggaran kebijakan dihentikan     : 1 (HUNT-2027-019; 0 kejadian sejak 2027-03-05)
Celah data                           : 16 dilaporkan; 3 ditutup; 7 terbuka terkonfirmasi;
                                       1 dijadwalkan kuartal berikut; 4 tanpa status; 1 tanpa pemilik
Miskonfigurasi dan praktik berisiko  : 17 dilaporkan; 2 diperbaiki; 1 disepakati; 14 tanpa status
Software di luar katalog ke IT       : 5 tiket
Baseline dan referensi               : 9 lookup, 2 macro normalisasi, 1 baseline autoruns (notebook)

COVERAGE
Teknik ATT&CK diburu (unik, v20)     : 32 (dari 20 hunt; 2 hunt baseline tanpa ID teknik)
Teknik dengan detection dari hunt    : 15 (6 di antaranya sebelumnya tanpa detection aktif)
ID ber-detection di layer            : 94 (awal) menjadi 100 (akhir)
Prosedur baru tertutup               : 11 (12 detection dikurangi 1 pengumpul finding-based)
Area belum diburu                    : data cloud (aws, azure); taktik Discovery, Collection, Impact
Host tercakup, 15 hunt endpoint      : 9 hanya host ber-Sysmon/audit (maksimal 214 dari 443 host Windows);
                                       5 dengan Velociraptor (218 sampai 431 host); 1 dengan MDE

OPERATIONAL
Hari dari laporan ke detection aktif : 2, 2, 6, 6, 6, 8, 8, 8, 13, 15, 41, 43 (per detection, n = 12)
Eskalasi temuan berbahaya (-013)     : terlihat 11:05, pesan ke IR 11:12, insiden dinyatakan 11:40
Selesai dalam time-box               : 22 dari 22
Umur abstract sebelum dijalankan     : -003 33 hari (sebagai -021), -004 14, -009 7 (sebagai -013),
                                       -010 7, -011 7; -008 menunggu 28 hari per 18 Mar
Usulan hipotesis dari L1             : 1 tercatat (2027-02-23), status kandidat backlog

KEMATANGAN (HMM)
1 Feb 2027 HMM1. 18 Mar 2027: perilaku HMM2 terpenuhi dengan bukti (kalender Selasa dan Kamis,
22 laporan, prosedur publik dijalankan terjadwal); bukti awal HMM3 (prosedur sendiri, misalnya
-013, -020, -022); HMM4 belum (12 detection dari 22 hunt, laporan hunter masih ditinjau manusia).
```

Cara membaca lembar ini:

- **Konteks di atas, tetapi berlabel.** Jumlah hunt dan hari hunting dicatat karena PEAK menganjurkannya sebagai konteks [S1], dan karena tanpa angka itu rasio di bagian 2.5 tidak bisa dihitung. Labelnya mencegah angka itu dikutip sebagai prestasi.
- **Dua angka untuk setiap celah dan miskonfigurasi.** "16 dilaporkan, 3 ditutup" lebih jujur daripada "16 celah ditemukan", dan baris "4 tanpa status" menunjukkan pekerjaan yang belum selesai di sisi program sendiri: status itu belum ditanyakan ke pemiliknya (bagian 2.7).
- **Insiden dipisah dua.** `INC-2027-040` adalah insiden saat hunt; insiden dari detection buatan hunt masih nol, dan itu wajar setelah satu hari (bagian 1.5).
- **Data operational disimpan mentah.** Daftar 12 angka hari, bukan hanya rata-rata, supaya bisa dihitung ulang dengan cara lain dan nilai ekstremnya terlihat.
- **Uji positif dicatat di bawah kategori hasil.** "2 dengan uji positif" adalah ukuran seberapa kuat 20 kesimpulan "tidak ditemukan" (bagian 1.7).

**Kapan gagal:** lembar diisi dari ingatan di hari evaluasi, bukan dari register dan laporan; atau angka program diambil dari lembar kuartal lalu tanpa mencatat tanggal hitung, sehingga dua versi beredar dengan angka berbeda.

### 2.5 Menghitung metrik dari lembar di atas

Perhitungan berikut memakai angka bagian 2.4, dan ini bagian yang paling mungkin ditanya ulang Hendra. Tabel menuliskan rumus supaya siapa pun mendapat hasil yang sama; baca kolom "Cara membaca", karena angka tanpa tafsiran yang benar justru menyesatkan.

| Metrik | Rumus | Hasil | Cara membaca |
|---|---|---|---|
| Rasio hunt ke detection | hunt yang melahirkan detection aktif / hunt selesai | 9 / 22 = 40,9% | Dua dari lima hunt meninggalkan detection permanen; delapan di antaranya berkategori tidak-ditemukan |
| Detection per hunt yang melahirkan | detection aktif / hunt yang melahirkan | 12 / 9 = 1,33 | Hunt yang menghasilkan detection rata-rata menutup lebih dari satu prosedur |
| Porsi tidak-ditemukan | hunt tidak-ditemukan / hunt selesai | 20 / 22 = 90,9% | Konteks, bukan ukuran gagal; dibaca bersama baris berikut |
| Tidak-ditemukan dengan uji positif | hunt tidak-ditemukan dengan uji positif / hunt tidak-ditemukan | 2 / 20 = 10% | Hanya dua kesimpulan negatif yang terbukti tidak buta; target perbaikan Q2 |
| Teknik diburu yang kini ber-detection dari hunt | teknik dengan detection dari hunt / teknik diburu | 15 / 32 = 46,9% | Hampir separuh teknik yang diperiksa kini dijaga terus |
| Delta cakupan | ID ber-detection akhir - awal | 100 - 94 = 6 ID (6 / 94 = 6,4% dari layer awal) | Enam teknik yang sebelumnya tanpa detection aktif; dihitung terhadap layer awal, bukan seluruh matriks |
| Penutupan celah data | celah ditutup / celah dilaporkan | 3 / 16 = 18,8% | Penutupan ada di tangan pemilik; yang bisa diperbaiki program adalah status yang tidak diketahui |
| Celah dengan status diketahui | (ditutup + terbuka terkonfirmasi + terjadwal) / dilaporkan | (3 + 7 + 1) / 16 = 68,8% | Lima celah belum punya status atau pemilik |
| Miskonfigurasi diperbaiki | diperbaiki / dilaporkan | 2 / 17 = 11,8% | Satu lagi disepakati; 14 belum ditanyakan statusnya |
| Median hari laporan ke aktif | median dari 12 nilai | 8 hari (rentang 2 sampai 43) | Rata-ratanya 158 / 12 = 13,2, ditarik dua nilai ekstrem (41, 43) |
| Waktu eskalasi | jam pesan IR - jam terlihat; jam insiden - jam terlihat | 7 menit; 35 menit | Temuan berbahaya tidak menunggu laporan selesai |
| Hunt endpoint terbatas Sysmon | hunt endpoint hanya host ber-Sysmon/audit / hunt endpoint | 9 / 15 = 60% | Kesimpulan endpoint sebagian besar berlaku untuk sekitar 40% workstation |

Beberapa catatan perhitungan:

- **Median dan rata-rata waktu ke produksi berbeda jauh** (8 dan 13,2 hari) karena dua nilai ekstrem: usulan `HUNT-2027-002` (43 hari) dan `HUNT-2027-001` (41 hari) menunggu sejak awal Februari sebelum repo `jab-detections` dan pipeline konversi ada. Laporkan median, lalu sebut nilai ekstremnya dan sebabnya. Usulan yang dilaporkan di Maret aktif dalam 6 sampai 15 hari, dan rule Wazuh dalam 2 hari karena dipasang lewat jendela change Infrastruktur.
- **Per detection atau per hunt harus disebut.** Per hunt (9 nilai: 2, 6, 6, 8, 8, 13, 15, 41, 43) median-nya juga 8 hari, tetapi rata-ratanya 142 / 9 = 15,8. Dua hunt dengan dua detection yang aktif bersamaan (`-010`, `-023`) dihitung sekali.
- **Delta cakupan dihitung terhadap daftar yang ditulis.** Enam ID dari 94 terdengar kecil, dan memang kecil. Yang lebih bermakna untuk manajemen adalah 11 prosedur baru yang tertutup, ditambah catatan bahwa sebagian besar hanya berlaku di 214 host (bagian 2.8).
- **Rasio 40,9% tidak bisa dibandingkan antar organisasi.** Definisi "hunt" dan "detection aktif" berbeda di setiap program. Bandingkan dengan kuartal berikutnya milik PT JAB sendiri.
- **Hunt yang menemukan kompromi tidak melahirkan detection ES.** `HUNT-2027-013` menemukan `INC-2027-040` dari data disk Velociraptor; rasio hunt ke detection tidak menangkap nilainya, dan itu alasan metrik insiden dipisah.

**Kapan gagal:** satu rasio dipilih karena angkanya paling bagus (misalnya 46,9% teknik ber-detection) lalu disajikan tanpa penyebut dan tanpa catatan cakupan host; atau persentase dihitung terhadap seluruh matriks ATT&CK sehingga orang mulai mengejar teknik yang tidak relevan untuk ISP.

### 2.6 Melacak detection yang lahir dari hunt dan alert-nya

Bagian ini menyediakan angka impact di lembar metrik dan menjawab sisi teknis pertanyaan kelima Dimas: dari mana tahu detection hasil hunt aktif, kapan aktif, dan apakah sudah menghasilkan alert atau insiden. Day 14 menetapkan setiap detection yang diterima mencatat `origin_hunt`, tanggal laporan hunt, dan tanggal aktif. Di `jab-detections`, ketiganya ditulis di baris awal `docs/<rule>.md` sebagai `origin_hunt:`, `hunt_report_date:`, dan `active_date:`; untuk rule Wazuh 100200 dan 100201, dokumen yang sama ditambahkan ke `jab-detections/docs/` Kamis pagi ini supaya semua detection hasil hunt ada di satu tempat. Usulan yang ditunda ada di `docs/pending.md`, yang juga memuat `origin_hunt:` tetapi tanpa `active_date:`.

**Tujuan:** menghitung detection aktif per hunt asal dan jarak laporan ke aktif, tanpa ikut menghitung usulan tunda.

**Sintaks:**

```bash
grep -L "^active_date:" jab-detections/docs/*.md
grep -l "^active_date:" jab-detections/docs/*.md | xargs grep -h "^origin_hunt:" | sort | uniq -c
for f in $(grep -l "^active_date:" jab-detections/docs/*.md); do
  r=$(grep -h "^hunt_report_date:" "$f" | awk '{print $2}')
  a=$(grep -h "^active_date:" "$f" | awk '{print $2}')
  echo "$(( ( $(date -d "$a" +%s) - $(date -d "$r" +%s) ) / 86400 )) $(basename "$f" .md)"
done | sort -n
```

| Bagian | Fungsi |
|---|---|
| `grep -L "^active_date:"` | Dokumen tanpa tanggal aktif: yang harus muncul hanya `pending.md` dan dokumen non-rule (misalnya `README.md`) |
| `grep -l ... \| xargs grep -h "^origin_hunt:"` | Ambil `origin_hunt` hanya dari dokumen yang punya tanggal aktif, lalu hitung per nilai |
| `date -d "$a" +%s` | Ubah tanggal `YYYY-MM-DD` ke detik sejak epoch; selisih dibagi 86.400 menjadi hari |
| `sort -n` | Urutkan dari yang paling cepat aktif |

Keluaran ilustrasi (dua perintah terakhir):

```
      1 origin_hunt: HUNT-2027-001
      1 origin_hunt: HUNT-2027-002
      2 origin_hunt: HUNT-2027-010
      1 origin_hunt: HUNT-2027-015
      1 origin_hunt: HUNT-2027-019
      1 origin_hunt: HUNT-2027-020
      1 origin_hunt: HUNT-2027-020, HUNT-2027-022
      1 origin_hunt: HUNT-2027-022
      2 origin_hunt: HUNT-2027-023
      1 origin_hunt: HUNT-2027-025

2 wazuh-100200-exec-from-temp
2 wazuh-100201-script-from-temp
6 office-signed-proxy-binary
6 proxy-binary-scriptlet-inline
6 script-host-from-user-folder
8 beacon-new-domain-risk
8 large-upload-new-dest-risk
8 two-risk-signals-7d
13 admin-logon-not-jump01
15 schtask-appdata-binary
41 office-shell-risk
43 certutil-bitsadmin-url
```

**Cara membaca hasil:** 12 dokumen aktif dari 9 hunt asal, dan 12 angka hari yang sama dengan lembar metrik. Baris `HUNT-2027-020, HUNT-2027-022` adalah pengumpul finding-based yang lahir dari dua hunt; saat menghitung "hunt yang melahirkan detection", hunt di baris itu sudah terhitung dari baris masing-masing, jadi tidak menambah jumlah hunt. Nama file adalah nama dokumen di repo, bukan nama detection di ES.

**Variasi:** ganti `^origin_hunt:` dengan `^updated_by_hunt:` untuk menghitung detection lama yang diperbaiki karena hunt. Di PT JAB perintah itu belum mengembalikan apa pun, dan baris "Detection lama diperbarui: 0" di lembar metrik berasal dari situ; kebiasaannya tetap ditetapkan sekarang, karena PEAK menghitung perbaikan detection lama sama berharganya dengan detection baru [S1].

**Kapan gagal:** `pending.md` ikut dihitung karena grep langsung ke `docs/*.md`, sehingga tiga usulan tunda tampak sebagai detection aktif; tanggal ditulis dengan format berbeda (`17/03/2027`) sehingga `date -d` salah membaca; atau detection dimatikan di ES tanpa dokumennya diubah.

Langkah berikutnya menghitung alert dari detection itu sejak aktif, karena metrik "insiden dari detection buatan hunt" dimulai dari alert. Kalimat pengantarnya sederhana: lookup kecil `jab_hunt_detections.csv` di `jkt-splunk-es01` (kolom `search_name`, `origin_hunt`, `active_time`) disusun Sari dari dokumen di atas, dan query ini dijalankan Sari karena role `jab_hunter` hanya ada di `jkt-splunk-sh01`.

**Tujuan:** menghitung finding per detection ES hasil hunt sejak aktif, termasuk detection yang belum menghasilkan apa pun.

**Sintaks:**

```
index=notable earliest="03/17/2027:09:00:00" latest="03/18/2027:08:00:00"
| stats count AS findings BY search_name
| append [| inputlookup jab_hunt_detections.csv | fields search_name origin_hunt]
| stats sum(findings) AS findings values(origin_hunt) AS origin_hunt BY search_name
| where isnotnull(origin_hunt)
| fillnull value=0 findings
| sort - findings
```

| Bagian | Fungsi |
|---|---|
| `index=notable ... earliest=... latest=...` | Finding sejak aktivasi Rabu 09:00 sampai Kamis 08:00, rentang absolut supaya bisa diulang |
| `stats count AS findings BY search_name` | Jumlah finding per detection |
| `append [\| inputlookup ...]` | Tambahkan semua detection hasil hunt sebagai baris, termasuk yang tidak punya finding |
| `stats sum(findings) ... BY search_name` | Gabungkan dua sumber per nama detection |
| `where isnotnull(origin_hunt)` | Buang detection lain di ES yang bukan hasil hunt |
| `fillnull value=0 findings` | Detection tanpa finding tampil dengan 0, bukan hilang |

Keluaran ilustrasi:

```
search_name                                                                        origin_hunt                    findings
JAB - certutil atau bitsadmin mengunduh dari URL eksternal - Rule                  HUNT-2027-002                  0
JAB - Scheduled task menjalankan biner dari folder AppData pengguna - Rule         HUNT-2027-015                  0
JAB - Logon akun admin ke workstation dari host selain JKT-JUMP01 - Rule           HUNT-2027-019                  0
JAB - Office meluncurkan signed proxy binary - Rule                                HUNT-2027-023                  0
JAB - Proxy binary dengan scriptlet atau skrip inline - Rule                       HUNT-2027-023                  0
JAB - Script host menjalankan skrip dari Downloads, Temp, atau ekstraksi arsip - Rule HUNT-2027-025               0
JAB - Dua sinyal risk berbeda pada satu entitas dalam 7 hari - Rule                HUNT-2027-020, HUNT-2027-022   0
```

**Cara membaca hasil:** tujuh detection yang menghasilkan finding (enam alert dan satu pengumpul), semuanya nol setelah 23 jam. Angka nol ini tidak masuk satu halaman manajemen sebagai "nol false positive"; dengan perkiraan volume sekitar 3 alert per minggu (Day 14 bagian 2.1), 23 jam belum cukup untuk menilai apa pun. Tiga detection risk tidak muncul di sini karena keluarannya intermediate finding, bukan finding; hitung dengan cara yang sama dari index penyimpan intermediate finding. Untuk Wazuh, hitungan setara di Dashboard dengan filter `rule.id:100200 or rule.id:100201` di `wazuh-alerts-*` sejak Kamis 2027-02-25 malam juga nol, sesuai perkiraan 0 alert per minggu saat rule diusulkan.

**Variasi:** tambahkan `status` dan `disposition` dari finding (lewat lookup status ES atau field yang tersedia di versi-mu) untuk memisahkan finding yang ditutup jinak dari yang dieskalasi; yang dieskalasi menjadi insiden adalah angka "insiden dari detection buatan hunt".

**Kapan gagal:** nama di lookup tidak sama persis dengan `search_name` di ES (ES menambahkan akhiran seperti ` - Rule`), sehingga `where isnotnull(origin_hunt)` membuang semua baris; atau nama index penyimpan berbeda. Dokumentasi findings ES 8.7 menegaskan istilah finding menggantikan notable event dan intermediate finding menggantikan risk event, dan contoh finding di sana memuat field `search_name`, tetapi tidak menyebut nama index penyimpannya [S12]. Index `notable` dan `risk` di atas adalah nama di ES 7 dan di lingkungan PT JAB; cek di ES 8.x-mu sebelum memakai query ini.

### 2.7 Register celah dan miskonfigurasi

Register ini menjawab bagian pertanyaan kedua Dimas yang paling mudah dibesar-besarkan: berapa celah yang benar-benar ditutup. Laporan hunt menulis celah dan rekomendasi saat ditemukan, tetapi status sesudahnya tidak pernah kembali ke laporan. Kamis pagi itu setiap baris "Celah data" dan "Rekomendasi" dari 22 laporan, kartu kesiapan Day 04, dan handover Day 14 dipindah ke `jab-hunt/docs/gaps.md`, satu baris per celah, dengan status terakhir yang bisa dibuktikan dari dokumen yang ada. Baca kolom "Status per 18 Mar" dan "Bukti", karena status tanpa bukti ditulis "tanpa status", bukan ditebak.

| ID | Celah data | Asal | Pemilik | Status per 18 Mar | Bukti |
|---|---|---|---|---|---|
| G01 | Sysmon hanya 214 host; 229 workstation tanpa Sysmon | `-001` (dan 9 laporan lain) | Agung | Terbuka | Rekomendasi rollout dua tahap 9 Feb; Velociraptor sebagai jalur sementara |
| G02 | Profil Sysmon server tidak seragam (16 tanpa EID 3, 12 tanpa EID 22) | `-002`, Day 04 | Agung | Terbuka | `HUNT-2027-020` 9 Mar: EID 3 masih dari 45 server |
| G03 | GPO `JAB-WS-Audit` hanya di OU `Workstations-EDR` (4688, 4698) | Day 04, `-013`, `-015` | Agung | Terbuka | Laporan 2 Mar: 4698 hanya 214 host |
| G04 | Sysmon `JKT-WS-0532` diam sejak 2027-02-02 10:14 | Day 04 | Agung | Terbuka | Laporan 11 Mar: masih di luar cakupan |
| G05 | 14 perangkat POP Medan tanpa `TZ` (`_time` +7 jam) | Day 04 | Bambang (NOC) | Tanpa status | Tidak ada catatan setelah 9 Feb |
| G06 | Tidak ada koleksi endpoint permanen | Day 04, `-009` | Dimas, Agung | Ditutup 2027-02-24 | `jkt-velo02`; 431 dari 443 host menjawab 2 Mar |
| G07 | Archives Wazuh tidak aktif | Day 04, `-010` | Agung | Ditutup 2027-02-24 | Keputusan Agung, policy ISM 30 hari |
| G08 | Rule auditd `jab_exec` belum di `jkt-portal02`, `jkt-radius01` | `-010` | Lutfi | Tanpa status | Tidak ada catatan setelah 23 Feb |
| G09 | Log aplikasi RADIUS tanpa decoder Wazuh | `-010` | Agung, Lutfi | Tanpa status | Tidak ada catatan setelah 23 Feb |
| G10 | Inventaris ekstensi browser tidak dikumpulkan | `-005`, `-020` | Infrastruktur; kebijakan: Dimas, Nina | Terbuka | Koleksi per host lewat Velociraptor terbukti 9 Mar; lintas fleet masih kandidat backlog |
| G11 | Agent dan tool NOC tidak tercatat di inventaris aset SOC | `-005`, `-015` | Bambang | Terbuka | Laporan 2 Mar: `probecheck.exe` masih belum tercatat |
| G12 | Log PowerShellCore/Operational tidak dikumpulkan | `-016` | Agung | Tanpa status | Tidak ada catatan setelah 2 Mar |
| G13 | Bug parsing akun komputer (`$` hilang) di satu sumber 4625 | `-018` | Infrastruktur | Ditutup 2027-03-04 | Laporan `-018`: diperbaiki bersama Infrastruktur |
| G14 | Tidak ada pemetaan IP ke host harian | Day 14 | Agung | Terbuka | Diserahkan 16 Mar |
| G15 | Laptop di luar kantor (split tunnel) tidak terlihat di `proxy` dan `dns` | `-013`, `-022` | Belum ada | Tanpa pemilik | Hanya dicatat di "Di luar cakupan" |
| G16 | Retensi `proxy` dan `dns` 30 hari | Day 04 | Agung, NOC | Dijadwalkan kuartal berikut | Rekomendasi 9 Feb nomor 3 (index DNS kantor 90 hari) |

Miskonfigurasi dan praktik berisiko dicatat terpisah, karena PEAK menghitungnya sebagai metrik sendiri [S1] dan pemiliknya sering bukan tim telemetri. Tabel kedua ini memakai aturan status yang sama.

| ID | Miskonfigurasi atau praktik berisiko | Asal | Pemilik | Status per 18 Mar |
|---|---|---|---|---|
| M01 | Distribusi profil koneksi vendor lewat CMSTP | `-007` | Agung | Tanpa status |
| M02 | Template surat bermakro di `\\jkt-filesrv01\template$` | `-007` | Corporate Communication (lewat Sari) | Tanpa status |
| M03 | Task `\JAB\Arsip-Template-Mingguan` dengan password `svc_filesync` tersimpan | `-004` | Agung | Tanpa status (detection LogonType Password ditunda menunggu ini) |
| M04 | Skrip alat NOC dijalankan dari folder pengguna (`capture-rotate.bat`) | `-004` | Bambang | Tanpa status |
| M05 | Rilis billing diekstrak dan dijalankan dari `/tmp` | `-010` | Lutfi | Disepakati: rilis berikutnya ke `/opt/jab-release/` |
| M06 | Service sisa uninstall VPN lama | `-012` | IT | Tanpa status (tiket) |
| M07 | Pemasangan tool dengan `irm ... \| iex` dari internet | `-016` | Dimas (edukasi) | Tanpa status |
| M08 | Akun admin helpdesk dipakai dari workstation sendiri | `-019` | Dimas, Hadi Santoso | Diperbaiki (0 kejadian 5 sampai 15 Mar) |
| M09 | Tiga akun service pemantauan dengan kredensial kedaluwarsa di `jkt-mon01` | `-018` | Infrastruktur | Diperbaiki (laporan `-018`) |
| M10 | Skrip kontraktor lama mencoba login ke 3 akun Entra | `-018` | IAM | Tanpa status |
| M11 | PDU data center dengan akses internet langsung | `-020` | Agung | Tanpa status |
| M12 | Sembilan perangkat dengan resolver DNS tertanam (diblokir firewall) | `-021` | Bambang | Tanpa status |
| M13 | `hdk-shell.exe` (salinan `cmd.exe` diganti nama) di toolkit IT | `-024` | IT | Tanpa status |
| M14 | Launcher PayrollClient membawa `regsvr32.exe` lama | `-024` | IT, vendor | Tanpa status |
| M15 | `logon_old.vbs` dan Run key di 6 host | `-025` | IT | Tanpa status |
| M16 | Status ASR rule "Office child processes" dan "copied or impersonated system tools" tidak diketahui | `-024` | Dimas | Tanpa status |
| M17 | Tidak ada kebijakan ekstensi browser | `-020` | Dimas, Nina | Tanpa status (menunggu inventaris G10) |

**Cara membaca hasil:** dari 16 celah, hanya 3 yang bisa diklaim ditutup, dan dua di antaranya (G06, G07) ditutup oleh keputusan yang dipicu program sendiri. Dari 17 miskonfigurasi, 2 diperbaiki dan 1 disepakati. Angka "tanpa status" bukan kegagalan pemilik; ia berarti program belum pernah menanyakan statusnya. Jumat 2027-03-19 daftar ini dikirim ke Agung, Bambang, Lutfi, Hadi, dan tim IT dengan permintaan status sampai Kamis 2027-03-25, supaya satu halaman yang dibawa ke evaluasi memakai status terbaru, bukan status 18 Maret.

**Kapan gagal:** satu celah yang muncul di sepuluh laporan dihitung sepuluh kali (G01), sehingga "celah dilaporkan" menggelembung; status "ditutup" ditulis dari janji di rapat tanpa bukti di data (misalnya profil Sysmon dianggap sudah seragam padahal EID 3 masih dari 45 server); atau celah tanpa pemilik (G15) tidak dihitung sama sekali karena tidak ada yang bisa ditanya.

### 2.8 Layer ATT&CK Navigator: awal, akhir, dan selisih

Bagian ini menjawab pertanyaan keenam Dimas dengan angka yang bisa diperlihatkan sebagai gambar. Layer Navigator adalah berkas JSON yang menyimpan skor, warna, dan komentar per teknik untuk ditampilkan di matriks ATT&CK [S6]. Langkahnya: ekspor detection aktif beserta anotasi ATT&CK dari ES, pisahkan detection lama dari detection hasil hunt, tulis dua layer, lalu buat layer selisih di Navigator.

**Tujuan:** menghitung, per ID teknik, jumlah detection ES aktif yang lama dan yang lahir dari hunt.

**Asumsi data:** correlation search atau event-based detection disimpan sebagai saved search di `jkt-splunk-es01`, dan anotasi ATT&CK-nya tersimpan sebagai JSON di `action.correlationsearch.annotations` dengan key `mitre_attack`. Dokumentasi yang menyebut lokasi ini adalah ES 7.3 [S13]; cek nama key di ES 8.x-mu. Query dijalankan Sari di `jkt-splunk-es01`.

```
| rest /servicesNS/-/-/saved/searches splunk_server=local count=0
| search action.correlationsearch.enabled=1 disabled=0
| rename action.correlationsearch.annotations AS annotations
| spath input=annotations path=mitre_attack{} output=technique
| mvexpand technique
| lookup jab_hunt_detections.csv search_name AS title OUTPUT origin_hunt
| eval asal=if(isnull(origin_hunt), "lama", "hunt")
| stats dc(eval(if(asal="lama", title, null()))) AS det_lama
        dc(eval(if(asal="hunt", title, null()))) AS det_hunt
        values(origin_hunt) AS origin_hunt BY technique
| sort technique
```

| Bagian | Fungsi |
|---|---|
| `\| rest /servicesNS/-/-/saved/searches splunk_server=local count=0` | Semua saved search dari semua app di search head ES ini, tanpa batas jumlah |
| `search action.correlationsearch.enabled=1 disabled=0` | Hanya detection ES yang aktif |
| `spath input=annotations path=mitre_attack{}` | Ambil daftar ID ATT&CK dari JSON anotasi |
| `mvexpand technique` | Satu baris per pasangan detection dan teknik |
| `lookup jab_hunt_detections.csv` | Tandai detection yang lahir dari hunt |
| `dc(eval(if(...)))` | Hitung detection unik per teknik, dipisah lama dan hunt |

Keluaran ilustrasi (ringkas; hanya baris dengan `det_hunt` lebih dari 0):

```
technique   det_lama  det_hunt  origin_hunt
T1021.002   2         1         HUNT-2027-019
T1021.006   0         1         HUNT-2027-019
T1041       0         1         HUNT-2027-022
T1047       1         1         HUNT-2027-019
T1053.005   3         1         HUNT-2027-015
T1059.005   1         1         HUNT-2027-025
T1059.007   0         1         HUNT-2027-025
T1071.001   1         1         HUNT-2027-020
T1105       2         1         HUNT-2027-002
T1204.002   1         3         HUNT-2027-001, HUNT-2027-023, HUNT-2027-025
T1218.005   0         2         HUNT-2027-023
T1218.010   1         2         HUNT-2027-023
T1218.011   2         2         HUNT-2027-023
T1567       0         1         HUNT-2027-022

Total baris: 99 | det_lama > 0: 94 | det_hunt > 0: 14 | det_hunt > 0 dan det_lama = 0: 5
Detection ES aktif: 222 (212 lama + 10 hunt); beranotasi ATT&CK: 180 (171 lama + 9 hunt)
```

**Cara membaca hasil:** 14 ID mendapat detection dari hunt di ES, dan 5 di antaranya sebelumnya tidak punya detection aktif sama sekali. Rule Wazuh tidak ada di REST ES, sehingga ditambahkan manual dari dokumennya: 100200 (T1105) dan 100201 (T1059.004). Setelah itu totalnya 15 ID dengan detection dari hunt dan 6 ID baru (T1021.006, T1041, T1059.004, T1059.007, T1218.005, T1567); layer awal 94 ID menjadi 100 di layer akhir. Pengumpul finding-based tidak punya anotasi teknik, jadi 10 detection ES hasil hunt menyumbang 9 baris anotasi. Baris yang paling menarik untuk dibaca jujur justru yang `det_lama`-nya tidak nol: T1053.005 sudah punya tiga detection sebelum program, dan tidak satu pun menangkap `\PDFSuite Updater`; T1071.001 sudah "tercakup" oleh rule kampanye `INC-2026-026` yang berbasis indikator, yang tidak menangkap varian domain baru. Per ID teknik, keduanya tampak hijau sejak awal.

**Variasi:** ganti `stats ... BY technique` dengan `stats values(technique) BY title` untuk daftar teknik per detection, berguna saat meninjau anotasi yang keliru; atau tambahkan `action.correlationsearch.label` bila nama tampilan detection berbeda dari `title`.

**Kapan gagal:** anotasi kosong atau salah di sebagian detection lama (171 dari 212 beranotasi, jadi 41 detection lama tidak muncul di layer sama sekali); key JSON berbeda di versi ES-mu; atau detection lama ikut diubah orang lain selama periode, sehingga layer "awal" yang direkonstruksi dari kondisi hari ini tidak sama dengan kondisi 1 Februari. Untuk yang terakhir, cek riwayat perubahan konten ES selama periode sebelum menyebut angka 94 sebagai kondisi awal.

Hasil query diekspor sebagai CSV, lalu dua layer ditulis dengan skor jumlah detection aktif per teknik: `coverage/coverage-2027-Q1-awal.json` dengan skor `det_lama`, dan `coverage/coverage-2027-Q1-akhir.json` dengan skor `det_lama + det_hunt`. Potongan layer akhir di bawah memakai format layer 4.5, yang wajib memuat `name`, `domain`, serta `versions.navigator` dan `versions.layer` bila `versions` ditulis [S9]:

```json
{
  "name": "PT JAB - detection aktif 2027-Q1 akhir (18 Mar)",
  "versions": { "attack": "20", "navigator": "5.3.2", "layer": "4.5" },
  "domain": "enterprise-attack",
  "description": "Skor = jumlah detection aktif (ES + Wazuh kustom) per teknik. Sumber: rest saved/searches jkt-splunk-es01 2027-03-18 dan jab-detections/docs.",
  "gradient": { "colors": ["#ffffff", "#9ecae1", "#08519c"], "minValue": 0, "maxValue": 4 },
  "legendItems": [ { "label": "Ada detection dari hunt (lihat comment)", "color": "#fdae6b" } ],
  "techniques": [
    { "techniqueID": "T1053.005", "score": 4,
      "comment": "origin=hunt HUNT-2027-015; prosedur: 4698/4702 command di AppData pengguna; hanya 214 host ber-audit; tidak mencakup tipe SBY-WS-0107 (kontrol: hunt VR mingguan)" },
    { "techniqueID": "T1059.004", "score": 1,
      "comment": "origin=hunt HUNT-2027-010; Wazuh 100201; hanya jkt-bastion01 dan jkt-billing02 (auditd execve)" },
    { "techniqueID": "T1218.005", "score": 2,
      "comment": "origin=hunt HUNT-2027-023; mshta dari Office dan mshta selain HTA lokal; 214 host ber-Sysmon; uji positif lab 2027-03-11 dan 2027-03-16" }
  ]
}
```

Bagian yang perlu diperhatikan di layer ini:

- **`versions`.** Bila objek ini ditulis, `navigator` (minimal 4.9.0) dan `layer` (harus `4.5`) wajib ada; `attack` opsional dan kosongnya berarti versi terbaru [S9]. Menulis `"attack": "20"` membuat layer bisa dibandingkan dengan layer kuartal depan walaupun ATT&CK sudah naik versi.
- **`comment` menulis prosedur, cakupan host, dan uji.** Ini menerapkan saran agar setiap klaim cakupan menyebut platform, prosedur yang diuji, dan tanggal uji [S11]. Satu kata "covered" di heatmap tidak cukup.
- **`tactic` tidak ditulis.** Tanpa field itu, anotasi berlaku di semua taktik tempat teknik itu berada [S9], sehingga T1053.005 tampil sama di Execution, Persistence, dan Privilege Escalation.
- **`gradient`.** `maxValue` 4 karena skor tertinggi di layer ini 4 (T1053.005, T1105, T1204.002, T1218.011); warna diatur supaya teknik tanpa detection tetap putih.

Layer selisih dibuat di Navigator lewat "Create Layer from other layers": kedua layer dibuka, diberi variabel `a` (awal) dan `b` (akhir), lalu score expression diisi. Ekspresi dihitung per teknik; operator perbandingan menghasilkan 1 atau 0 dan bisa digabung dengan `and` atau `or` [S6]. Dua ekspresi yang dipakai PT JAB:

```
b - a              -> jumlah detection yang bertambah per teknik (15 teknik bernilai > 0)
b > 0 and a < 1    -> 1 untuk teknik yang sebelumnya tanpa detection aktif (6 teknik)
```

Layer selisih bisa mewarisi komentar dari layer akhir, karena keduanya satu domain dan satu versi; Navigator hanya mengizinkan pewarisan properti dari layer dengan domain dan versi yang sama [S6]. Hasilnya diekspor sebagai SVG untuk gambar di satu halaman, dan sebagai JSON untuk disimpan di `jab-hunt/coverage/`. Layer ketiga, `coverage-2027-Q1-diburu.json`, memberi skor 1 untuk 32 teknik yang diburu; menumpuknya dengan layer akhir lewat `c > 0 and b < 1` memperlihatkan teknik yang sudah diburu tetapi belum punya detection apa pun.

**Kapan gagal:** layer awal dan akhir memakai versi ATT&CK berbeda, sehingga pewarisan ditolak dan ID yang dipindah antar versi dihitung dua kali; layer dibuat di Navigator versi lama yang memakai format layer sebelum 4.5; atau gambar heatmap dibawa ke direksi tanpa komentar dan tanpa catatan "214 host", sehingga hijau dibaca sebagai "semua host terlindungi".

### 2.9 Satu halaman untuk direksi

Halaman ini menjawab pertanyaan ketujuh Dimas. Ditulis untuk Hendra dan bisa diteruskan ke direksi tanpa penjelasan lisan, dengan urutan bagian 1.8: keluaran permanen dulu, angka aktivitas paling bawah.

```
PROGRAM HUNT PT JAB: RINGKASAN Q1 (1 Februari sampai 18 Maret 2027)
Untuk: Direktur Teknologi. Disusun SOC PT JAB. Setiap angka dapat ditelusuri ke
jab-hunt/docs/hunt-metrics-2027-Q1.md. Status celah per 18 Maret; diperbarui 29 Maret.

YANG DITINGGALKAN PROGRAM SECARA PERMANEN
- 12 detection baru aktif, lahir dari 9 hunt, menutup 11 cara serangan yang sebelumnya lolos
  (contoh: kode dijalankan lewat dokumen Office, scheduled task dari folder pengguna, laptop
  yang menghubungi domain baru secara teratur). 10 aktif sejak 17 Maret, 2 sejak 25 Februari.
- 1 kompromi nyata ditemukan: laptop sales Surabaya dengan program tersembunyi sekitar 82 hari,
  yang tidak tertangkap daftar indikator insiden Desember 2026. Dinyatakan insiden 35 menit
  setelah terlihat dan ditangani IR (INC-2027-040; dampak dan penanganan di laporan IR).
- 1 pelanggaran kebijakan akses admin dihentikan (0 kejadian sejak 5 Maret).
- Koleksi endpoint permanen menjangkau 431 dari 443 komputer Windows, termasuk 229 workstation
  yang tidak punya telemetri proses di SIEM.

APA ARTI "TIDAK DITEMUKAN" (20 DARI 22 HUNT)
- Untuk area, data, dan rentang yang tertulis di setiap laporan, tidak ada aktivitas berbahaya.
  Delapan hunt di antaranya tetap melahirkan detection, sehingga pola yang sama kini dijaga terus.
- Batasnya: sebagian besar kesimpulan di komputer pengguna hanya berlaku untuk sekitar 40%
  workstation yang punya Sysmon, dan baru 2 dari 20 hasil negatif yang dibuktikan dengan uji positif.

RISIKO TERBUKA DAN KEPUTUSAN YANG DIBUTUHKAN
- 229 workstation (sekitar 60%) tanpa Sysmon. Usulan: rollout dua tahap, Bandung dan POP dulu;
  tambahan ingest sekitar 4,8 GB per hari. Butuh keputusan anggaran.
- 16 celah data dilaporkan ke pemilik, 3 sudah ditutup; 17 temuan konfigurasi, 2 sudah diperbaiki.
  Status sisanya sedang dikonfirmasi ke pemilik sampai 25 Maret.
- Laptop yang bekerja dari luar kantor (split tunnel) tidak terlihat di proxy dan DNS; belum ada
  pemilik untuk celah ini.
- Belum ada hunt di data cloud (AWS, Azure) dan baru satu hunt identitas.

RENCANA Q2 DAN UKURAN DI EVALUASI JULI
- Hunt identitas dan cloud; uji positif untuk setiap hunt yang hasilnya negatif.
- Ukuran: detection aktif dari hunt dan alert-nya, insiden yang dipicu detection itu, celah dan
  temuan konfigurasi yang ditutup, hari dari laporan sampai detection aktif (kini median 8 hari).
- Kematangan: dari HMM1 (1 Februari) ke perilaku HMM2 yang terbukti; target Juli awal HMM3.

KONTEKS: 22 hunt selesai dalam 14 hari hunting (Selasa dan Kamis), satu analyst L2.
```

Cara membaca halaman ini dan kenapa bentuknya begitu:

- **Tidak ada istilah yang butuh glosarium.** "Signed proxy binary" ditulis "kode dijalankan lewat dokumen Office"; "beacon" ditulis "menghubungi domain baru secara teratur". Direksi tidak perlu tahu nama teknik untuk memutuskan anggaran.
- **Klaim `INC-2027-040` berhenti di fakta.** Tidak ada "mencegah ransomware" atau "menghemat sekian rupiah"; dampak dirujuk ke laporan IR.
- **Keterbatasan ditulis di halaman yang sama dengan prestasi.** Kalimat "40% workstation" dan "2 dari 20" membuat angka lain dipercaya, dan langsung mengarah ke keputusan anggaran di bagian berikutnya.
- **Jumlah hunt ada, di baris paling bawah, berlabel konteks.** Hendra mungkin bertanya; jawabannya tersedia tanpa menjadi judul.
- **Tanggal status ditulis.** "Status celah per 18 Maret; diperbarui 29 Maret" mencegah halaman ini beredar dengan angka yang sudah basi.

**Kapan gagal:** halaman dibuka dengan "kami menjalankan 22 hunt dan memindai miliaran event"; direksi membaca aktivitas, bukan hasil, dan pertanyaan pertama yang muncul adalah "lalu apa yang kita dapat", yang jawabannya justru ada di bawah.

### 2.10 Jawaban untuk Dimas

Ringkasan berikut kamu kirim ke Dimas Kamis pukul 17:00, bersama lembar metrik, register, dua layer Navigator, dan draf satu halaman. Setiap baris merujuk subbagian di atas.

| Pertanyaan Dimas | Jawaban singkat | Dasar |
|---|---|---|
| Angka dari mana, laporan cukup? | Dari 22 laporan, register hunt, register celah, dan dokumen detection; laporan cukup setelah ditambah baris `Kategori hasil` dan blok Metrik, dan setelah laporan gabungan diberi stub per hunt | Bagian 1.1, 1.2, 2.1, 2.3 |
| Metrik yang jujur | Lima metrik PEAK dalam tiga kelompok: 12 detection aktif dari 9 hunt, 1 insiden saat hunt, 0 insiden dari detection hunt, 3 dari 16 celah ditutup, 2 dari 17 miskonfigurasi diperbaiki, 32 teknik diburu, median 8 hari laporan ke aktif | Bagian 1.3, 1.4, 2.4, 2.5 |
| Yang cuma terlihat bagus | Jumlah hunt dan nomor hunt, jumlah query dan event, hunt per hunter, persentase hijau heatmap, nol alert dari detection baru | Bagian 1.6 |
| Melaporkan "tidak ditemukan" | Sebut cakupan, jinak terkonfirmasi, dan apa yang lahir darinya (delapan hunt negatif melahirkan detection); laporkan juga bahwa baru 2 dari 20 yang punya uji positif | Bagian 1.7, 2.5 |
| Nilai `INC-2027-040` | Fakta yang bisa ditelusuri: sekitar 82 hari, lolos IOC dan proxy, 35 menit ke insiden; dampak dari laporan IR; tidak ada klaim kerugian dicegah | Bagian 1.5, 2.6 |
| Cakupan ATT&CK yang bertambah | 15 teknik mendapat detection dari hunt, 6 di antaranya baru (94 menjadi 100 ID); yang lebih penting 11 prosedur, sebagian besar hanya di 214 host; cloud belum diburu | Bagian 1.5, 2.8 |
| Satu halaman untuk direksi | Keluaran permanen, arti "tidak ditemukan", risiko dan keputusan, rencana Q2; jumlah hunt di baris terakhir | Bagian 1.8, 2.9 |

**Kapan gagal:** jawaban dikirim tanpa register celah, sehingga Dimas membawa "16 celah ditemukan" ke rapat tanpa tahu bahwa hanya 3 yang ditutup dan 4 belum pernah ditanyakan statusnya; pertanyaan pertama Nina akan langsung mengarah ke situ.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** repo portofolio pribadi (misalnya `hunt-portfolio/`) berisi minimal tiga hunt dari lab-mu dengan abstract dan laporan, repo atau folder rule Sigma dari latihan detection, Splunk lab bila ingin menjalankan query bagian 2.6 dan 2.8, dan ATT&CK Navigator (versi web resmi atau instance lokal). Jangan memakai data, nama, atau kejadian dari pekerjaan nyata; PT JAB hanya contoh fiktif.

1. **Kategori hasil terkontrol.** Tambahkan baris `Kategori hasil:` dengan lima nilai bagian 2.1 ke setiap laporan di `hunts/*/report.md`. Jalankan dua perintah bagian 2.3 (sebelum dan sesudah) dan catat berapa rumusan bebas yang ada sebelum dirapikan. Bila satu dokumen melaporkan beberapa hunt, buat stub per hunt.
2. **Blok Metrik.** Isi blok Metrik bagian 2.1 di setiap laporan: teknik diburu (tanpa pemetaan bersyarat), uji positif, detection diusulkan dan aktif dengan tanggal, ID celah dan miskonfigurasi. Pakai contoh bagian 2.2 sebagai acuan tingkat detail, termasuk memastikan angka di Temuan menjumlah.
3. **Register.** Buat `docs/gaps.md` dengan dua tabel seperti bagian 2.7. Untuk lab, "pemilik" boleh dirimu sendiri; yang dilatih adalah status berbukti. Tulis "tanpa status" untuk yang belum dicek, bukan tebakan.
4. **Tautkan detection.** Untuk setiap rule dari hunt, tulis `origin_hunt:`, `hunt_report_date:`, dan `active_date:` di dokumen rule-nya; usulan tunda di `pending.md` tanpa `active_date:`. Jalankan tiga perintah bagian 2.6 dan pastikan `pending.md` tidak terhitung.
5. **Lembar metrik dan rumus.** Isi lembar bagian 2.4 dari repo-mu, lalu tabel rumus bagian 2.5. Hitung median dan rata-rata hari laporan ke aktif, dan tulis satu kalimat bila keduanya berbeda jauh. Simpan data operational dalam bentuk mentah.
6. **Teknik dari rule.** Kumpulkan ID teknik dari tag Sigma dengan `grep -rhoE "attack\.t[0-9]{4}(\.[0-9]{3})?" rules/ | sort | uniq -c`, lalu ubah ke huruf besar untuk ID Navigator. Bila Splunk lab-mu punya ES, jalankan query REST bagian 2.8; bila tidak, cukup dari tag Sigma.
7. **Dua layer dan selisihnya.** Tulis `coverage-awal.json` dan `coverage-akhir.json` dengan format layer 4.5 (bagian 2.8), skor jumlah detection per teknik, dan komentar berisi prosedur, cakupan host lab, dan tanggal uji. Buka keduanya di Navigator, buat layer dari ekspresi `b - a` dan `b > 0 and a < 1`, lalu ekspor SVG. Catat versi Navigator yang dipakai (menu informasi di Navigator) dan versi ATT&CK yang dimuat.
8. **Cek vanity.** Tandai setiap baris lembar metrikmu: outcome, coverage, operational, atau konteks. Pastikan tidak ada baris konteks yang naik ke bagian atas satu halaman.
9. **Satu halaman.** Tulis satu halaman bagian 2.9 untuk lab-mu, termasuk kalimat "tidak ditemukan" beserta batasnya dan jumlah hasil negatif yang punya uji positif.

**Hasil yang sebaiknya tersimpan:**

- Semua laporan lab punya `Kategori hasil` dan blok Metrik, dan hitungan `grep` sama dengan jumlah hunt.
- `docs/gaps.md` dengan status berbukti untuk setiap celah dan miskonfigurasi.
- Dokumen rule dengan `origin_hunt`, tanggal laporan, dan tanggal aktif; daftar hari laporan ke aktif.
- Lembar metrik dan tabel rumus dengan cara membacanya.
- Dua layer Navigator format 4.5, layer selisih, dan gambar SVG-nya, beserta versi Navigator dan ATT&CK.
- Satu halaman ringkasan yang menyajikan outcome, termasuk "tidak ditemukan" sebagai cakupan.

**Variasi tantangan:** ambil satu metrik vanity yang mungkin diminta atasan ("berapa hunt bulan ini") dan tulis satu paragraf yang menjelaskan kenapa itu menyesatkan, lalu usulkan metrik outcome pengganti yang menjawab maksud sebenarnya (ingin tahu apakah tim produktif dan menambah nilai). Tambahan: untuk satu hunt "tidak ditemukan" di lab-mu, rancang dan jalankan uji positif di VM lab, lalu catat apakah kesimpulannya bertahan; ubah baris "tidak-ditemukan dengan uji positif" di lembarmu.

## 4. Troubleshooting

Tabel ini memuat masalah yang muncul saat menyusun metrik dari dokumen hunt. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Hitungan kategori tidak sama dengan jumlah hunt | Laporan gabungan, folder tanpa `report.md`, atau rumusan bebas | `grep -L "^Kategori hasil"`; buat stub per hunt (bagian 2.3) |
| Metrik impact nol padahal banyak usulan | Detection tidak ditautkan ke hunt, atau tanggal aktif tidak dicatat | Isi `origin_hunt` dan `active_date` di dokumen rule (bagian 2.6) |
| Detection aktif terhitung lebih banyak dari kenyataan | `pending.md` ikut di-grep | Hitung hanya dokumen ber-`active_date` (bagian 2.6) |
| Perbaikan detection lama tidak terhitung | Hanya rule baru yang ditandai | Tambahkan `updated_by_hunt:` [S1] |
| Celah "dilaporkan" menggelembung | Celah yang sama dihitung per laporan | Satu baris per celah di register; laporan hanya menyebut ID (bagian 2.7) |
| Angka "ditutup" tidak bisa dibuktikan | Status dari janji rapat, bukan data | Kolom Bukti di register; tulis "tanpa status" bila tidak ada |
| Query finding mengembalikan nol baris | Nama di lookup berbeda dari `search_name`, atau index berbeda | Bandingkan dengan `\| stats count BY search_name` tanpa filter; cek nama index di ES 8.x-mu [S12] |
| Detection tanpa finding hilang dari tabel | `stats` tidak menghasilkan baris untuk nol | `append` lookup lalu `fillnull` (bagian 2.6) |
| REST tidak memuat anotasi | Key anotasi berbeda di versi ES, atau detection tanpa anotasi | Cek satu saved search mentah; hitung yang tanpa anotasi secara terpisah [S13] |
| Layer ditolak Navigator | `versions.layer` bukan `4.5` atau `navigator` di bawah 4.9.0 | Perbaiki `versions` (bagian 2.8) [S9] |
| Pewarisan komentar gagal saat membuat layer selisih | Domain atau versi ATT&CK layer berbeda | Samakan versi; upgrade layer lama lewat alur upgrade Navigator [S6] |
| Delta cakupan tampak sangat kecil | Dihitung atas seluruh matriks, atau satu-satunya angka yang disajikan | Hitung atas layer awal; sajikan prosedur dan host bersama ID (bagian 2.5) |
| Waktu ke produksi rata-ratanya menyesatkan | Nilai ekstrem | Laporkan median dan sebut nilai ekstremnya |
| Metrik tidak memengaruhi rencana | Metrik hanya dilaporkan | Pakai celah berulang dan teknik yang belum diburu untuk memilih hunt berikutnya (bagian 1.8) |

## 5. Kesalahan umum dan jebakan

- **Mengukur aktivitas, bukan outcome.** Jumlah hunt dan query mengukur kerja keras, bukan dampak [S1][S3].
- **Menghitung nomor hunt sebagai hunt.** 25 nomor di PT JAB berarti 22 hunt selesai; nomor yang dijalankan di bawah nomor lain dihitung sekali (bagian 2.3).
- **Menjadikan jumlah hunt per hunter target individu**, yang mendorong hunt dangkal dan burnout [S2].
- **Tidak menautkan deteksi ke hunt**, sehingga metrik impact tak bisa dihitung.
- **Hanya menghitung deteksi baru**, padahal PEAK menghitung deteksi yang diperbaiki dengan bobot yang sama [S1].
- **Mencampur insiden saat hunt dengan insiden dari detection hunt.** `INC-2027-040` ditemukan saat hunt; detection yang lahir dari pola itu belum menghasilkan insiden apa pun dan tidak mencakup host seperti `SBY-WS-0107` (bagian 1.5).
- **Mengklaim dampak insiden dari lembar hunt.** Dampak dan waktu containment milik laporan IR; lembar metrik hunt merujuknya.
- **Menyajikan "tidak ditemukan" sebagai kegagalan** alih-alih baseline cakupan tervalidasi [S1][S3], atau sebaliknya menyajikannya sebagai bukti bersih tanpa cakupan dan tanpa uji positif.
- **Menyebut "celah ditemukan" tanpa angka "ditutup"**, atau menulis "ditutup" tanpa bukti di data.
- **Membaca heatmap per ID teknik sebagai perlindungan.** Satu detection untuk satu prosedur di 214 host bukan cakupan teknik itu di seluruh lingkungan [S11].
- **Menyajikan nol alert dari detection yang baru aktif sebagai prestasi.** Itu belum data.
- **Mengklaim tiga kategori impact/coverage/operational sebagai istilah resmi PEAK.** PEAK memakai lima metrik kunci plus HMM [S1]; pengelompokan tiga kategori adalah alat bantu penyajian.

## 6. Catatan terkini

Bagian ini menampung detail versi, tanggal terbit, dan perubahan istilah yang memengaruhi cara membaca sumber, tetapi tidak mengubah cara menghitung di atas.

- Artikel metrik PEAK (David Bianco, 2 Agustus 2023) menetapkan lima metrik kunci: deteksi dibuat atau diperbarui, insiden, celah, kerentanan dan miskonfigurasi, serta teknik yang diburu, ditambah HMM untuk kematangan program; artikel itu tidak menetapkan alat pencatatan tertentu [S1].
- **SANS 2026 Threat Hunting Survey (rilis pers 23 September 2026):** 40% program mengukur hasil hunting secara formal, turun dari 64% pada 2024; metodologi formal 37% (2025: 46%, 2024: 51%); pendekatan ad hoc naik ke 39% [S4]. Angka berasal dari rilis pers survei, bukan laporan lengkap.
- **MITRE ATT&CK v20.0** dirilis 13 Oktober 2026, menggantikan v19.2 (28 April sampai 12 Oktober 2026) [S10]. Layer yang dibuat dengan versi lama perlu di-upgrade lewat alur upgrade Navigator sebelum dibandingkan [S6].
- **ATT&CK Navigator 5.3.2** (21 April 2026) adalah rilis terbaru di halaman rilis per 18 Oktober 2026; perubahan 5.x tidak mengubah format layer, yang terakhir naik ke 4.5 di Navigator 4.9.0 [S8]. Sejak 5.1.0 spesifikasi format layer disimpan di subfolder berversi `layers/spec/` [S8].
- **Splunk ES 8.x:** finding menggantikan istilah notable event dan intermediate finding menggantikan risk event; teks ini sama di dokumentasi 8.0 sampai 8.7 [S12]. Lokasi anotasi `action.correlationsearch.annotations` dirujuk dari dokumentasi ES 7.3 [S13].
- Peringatan vanity metrics konsisten di beberapa sumber vendor: ukur outcome, perlakukan "tidak ditemukan" sebagai cakupan [S2][S3]. Tulisan AttackIQ (10 Maret 2026) menambahkan sudut cakupan ATT&CK: spektrum, bukan biner, dan setiap klaim butuh konteks [S11].
- Day 16 (capstone) memakai lembar ini sebagai titik awal dan menambahkan tiga hunt terakhir kuartal; Day 19 menambahkan metrik tingkat program untuk rencana Q2.

## 7. Cheat sheet

```
DOKUMEN    abstract (sebelum) + report.md (sesudah) per hunt; laporan gabungan -> stub per hunt
           Kategori hasil: ditemukan | ditemukan-bukan-insiden | tidak-ditemukan | inkonklusif | data-tidak-cukup
           blok Metrik: teknik diburu, uji positif, detection (+tanggal aktif), det. diperbarui, Gnn/Mnn, eskalasi (3 jam)
PEAK (5)   deteksi dibuat/diperbarui | insiden (saat hunt vs dari detection hunt: yang kedua lebih bermakna)
           | celah dilaporkan/ditutup | kerentanan & miskonfigurasi dilaporkan/diperbaiki | teknik diburu ; + HMM
KELOMPOK   impact | coverage | operational | konteks (alat bantu penyajian, bukan istilah PEAK)
RUMUS      hunt->detection = hunt ber-detection aktif / hunt selesai ; uji positif = negatif teruji / negatif
           delta cakupan = ID akhir - ID awal (atas layer awal, bukan seluruh matriks) ; waktu ke produksi: MEDIAN + ekstrem
VANITY     jumlah hunt/nomor, query, event, jam, laporan, hunt per hunter (merusak), % hijau heatmap, 0 alert hari pertama
NIHIL      "tidak ditemukan" = cakupan tervalidasi bila cakupan + jinak + (idealnya) uji positif ditulis
REGISTER   docs/gaps.md: satu baris per celah, pemilik, status per tanggal, BUKTI ; "tanpa status" bukan tebakan
LACAK      grep -l "^active_date:" docs/*.md | xargs grep -h "^origin_hunt:" | sort | uniq -c
           index=notable ... | stats count BY search_name | append [| inputlookup ...] | stats sum() | fillnull
NAVIGATOR  layer 4.5: name, domain, versions{attack,navigator>=4.9.0,layer="4.5"}, techniques[{techniqueID,score,comment}]
           create layer from other layers: b - a ; b > 0 and a < 1 ; pewarisan hanya domain+versi sama
MANAJEMEN  permanen -> arti "tidak ditemukan" + batas -> risiko & keputusan -> rencana ; jumlah hunt paling bawah
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "20 dari 22 hunt PT JAB berakhir 'tidak ditemukan', jadi program ini menghasilkan nilai hanya dari dua hunt." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Delapan dari sembilan hunt yang melahirkan detection aktif justru berkategori tidak-ditemukan, dan hunt negatif juga menghasilkan baseline, celah yang dilaporkan, dan cakupan yang tertulis. Sebaliknya, satu-satunya hunt yang menemukan kompromi (`HUNT-2027-013`) tidak melahirkan detection ES karena datanya tidak ada di SIEM. Yang benar dari pernyataan itu hanya satu hal: kekuatan 20 hasil negatif terbatas, karena baru dua yang punya uji positif dan sebagian besar hanya mencakup host ber-Sysmon. Lihat bagian 1.7 dan 2.5.

</details>

**2. Skenario keputusan.** Hendra bertanya di evaluasi, "Cakupan ATT&CK kita sekarang berapa persen?" Jawaban mana yang paling tepat?

- A. "Kami menghitung terhadap seluruh matriks Enterprise ATT&CK: 100 ID ber-detection, jadi sekitar sekian persen dari semua teknik dan sub-teknik."
- B. "Program memburu 32 teknik; 15 di antaranya kini punya detection dari hunt, 6 sebelumnya tanpa detection sama sekali, sehingga layer kita naik dari 94 ke 100 ID. Yang lebih penting, 11 cara serangan baru kini terdeteksi, tetapi sebagian besar hanya di 214 host yang punya Sysmon, dan data cloud belum diburu."
- C. Menunjukkan heatmap Navigator layer akhir tanpa komentar, karena hijaunya sudah bicara sendiri.

<details><summary>Jawaban</summary>

B. Jawaban itu menyebut penyebut yang jelas (teknik yang diburu dan layer awal), memisahkan teknik dari prosedur, dan menyebut batas host serta area yang belum disentuh. A keliru karena persentase atas seluruh matriks membuat kenaikan tampak tidak berarti dan mendorong mengejar teknik yang tidak relevan, sekaligus mengklaim cakupan per ID yang menyembunyikan prosedur. C keliru karena hijau per ID teknik dibaca sebagai "terlindungi", padahal T1053.005 sudah hijau sejak awal dan tetap tidak menangkap `\PDFSuite Updater`. Lihat bagian 1.5 dan 2.8.

</details>

**3. Pertanyaan jebakan.** "`INC-2027-040` adalah bukti terbaik bahwa detection hasil hunt bekerja, karena itu insiden yang ditemukan program." Benarkah?

<details><summary>Jawaban</summary>

Tidak. `INC-2027-040` adalah insiden saat hunt: ditemukan hunter lewat Velociraptor ketika menjalankan `HUNT-2027-013`, bukan dipicu detection. PEAK menilai insiden dari detection buatan hunt sebagai bukti yang lebih kuat, dan per 18 Maret jumlahnya nol, karena detection ES baru aktif sehari. Detection scheduled task AppData yang lahir dari pola ini juga hanya mencakup 214 host ber-audit, sehingga tidak akan menangkap laptop seperti `SBY-WS-0107`; kontrolnya hunt Velociraptor mingguan. Lihat bagian 1.5.

</details>

**4. Skenario keputusan.** Untuk baris "waktu dari laporan ke detection aktif" di satu halaman, angka mana yang dipakai?

- A. Rata-rata 13,2 hari, karena memakai semua data.
- B. "6 hari", karena itu angka usulan minggu lalu dan menunjukkan perbaikan.
- C. Median 8 hari dengan rentang 2 sampai 43, dan catatan bahwa dua usulan Februari menunggu 41 dan 43 hari sebelum repo dan pipeline detection ada.

<details><summary>Jawaban</summary>

C. Median tidak ditarik dua nilai ekstrem, dan menyebut ekstremnya beserta sebabnya menunjukkan di mana jembatan sempat macet dan apa yang memperbaikinya. A keliru karena rata-rata ditarik naik oleh 41 dan 43 hari sehingga tidak menggambarkan kebanyakan detection. B keliru karena memilih subset yang paling bagus tanpa menyebut sisanya; begitu Nina menelusuri lembar metrik, angka itu tidak bisa dipertahankan. Lihat bagian 2.5.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Nina Kartika (Manajer Risiko dan Kepatuhan TI), dalam tiga kalimat, kenapa angka "3 dari 16 celah ditutup" ditulis apa adanya dan apa yang dilakukan program terhadapnya.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Program hunt melaporkan 16 celah data ke pemiliknya, dan hanya 3 yang punya bukti ditutup, misalnya server Velociraptor yang sekarang menjangkau 431 dari 443 komputer Windows. Sisanya bukan berarti diabaikan pemilik: tujuh terkonfirmasi masih terbuka, satu dijadwalkan kuartal depan, empat belum pernah kami tanyakan statusnya, dan satu belum punya pemilik. Daftar lengkapnya dengan bukti per baris sudah dikirim ke pemilik untuk konfirmasi sampai 25 Maret, sehingga angka di evaluasi nanti memakai status terbaru, bukan status yang kami tebak."

Kesalahan yang sering muncul:
- Menyebut "16 celah ditemukan" sebagai prestasi tanpa angka "ditutup".
- Menulis "ditutup" untuk celah yang hanya dijanjikan di rapat.
- Menyalahkan pemilik, padahal status "tanpa status" berarti program belum bertanya.

</details>

**6. Pertanyaan jebakan.** "`grep -h "^Hasil" hunts/HUNT-2027-*/report.md | wc -l` menghasilkan 20, jadi program menyelesaikan 20 hunt." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Laporan Selasa 2027-03-02 melaporkan `HUNT-2027-014`, `-015`, dan `-016` dalam satu dokumen, sehingga dua hunt tidak punya `report.md` sendiri; hunt yang selesai berjumlah 22. Baris `Hasil` juga ditulis dengan 16 rumusan berbeda, sehingga tidak bisa dipakai untuk menghitung kategori. Perbaikannya baris `Kategori hasil` dengan kosakata tetap dan stub per hunt untuk laporan gabungan, lalu `grep -L` untuk memastikan tidak ada laporan yang terlewat. Lihat bagian 2.3.

</details>

**7. Interview question (English).** "How do you measure the value of a threat hunting program, especially when most hunts find nothing?"

<details><summary>Sample answer</summary>

"I measure outcomes, not activity. I start from the five PEAK metrics: detections created or improved, incidents found during hunts and later by hunt-born detections, data gaps reported and actually closed, misconfigurations reported and fixed, and techniques hunted. Every hunt report has a fixed result category and a metrics block, and every detection carries its origin hunt, report date and go-live date, so the numbers can be recounted by anyone. In my last quarter most hunts were negative, but most of the detections that went live came from those negative hunts, and each negative result had a written scope. I also report how many negative results were backed by a positive test, because a query that was never proven to catch the behavior can be blind. For ATT&CK coverage I compare a start and end Navigator layer, but I present procedures and host coverage alongside technique IDs. Hunt counts go at the bottom, labelled as context."

What makes this answer strong: it uses a named framework, shows how the numbers are made auditable, treats negative results as valuable but states their limits, and avoids the heatmap and hunt-count traps.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Splunk: Measuring Hunting Success with PEAK (David Bianco) | https://www.splunk.com/en_us/blog/security/peak-threat-hunting-metrics.html | sekunder (blog vendor, penulis kerangka) | 2023-08-02; diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi. Lima metrik kunci, insiden setelah hunt lebih bermakna, celah dan miskonfigurasi dilaporkan dan ditutup, HMM (minimal HMM2, ideal HMM4), jumlah hunt sebagai ukuran kerja keras, "tidak ditemukan" bukan kegagalan, lacak detection per hunt |
| S2 | Intel 471: How threat hunting and good metrics help the business | https://www.intel471.com/blog/how-threat-hunting-and-good-metrics-help-the-business | sekunder (blog vendor) | 2026-02-10; diakses 2026-10-10, dicek ulang 2026-10-18 | Sedang. Metrik baik (insiden proaktif, dwell dan containment, deteksi baru, sesi hunting per periode), pengalih (jumlah laporan), merusak (hunt per hunter), penyajian ke pemimpin |
| S3 | Dropzone AI: Threat Hunting Metrics That Actually Measure Success in Your SOC (Tyson Supasatit) | https://www.dropzone.ai/blog/blog-threat-hunting-metrics | sekunder (blog vendor) | tanggal tidak tercantum; diakses 2026-10-10, dicek ulang 2026-10-18 | Sedang. Kelompok detection/coverage/operational, metrik aktivitas sebagai effort, contoh "500 hipotesis", baseline cakupan tervalidasi dihitung sebagai temuan |
| S4 | SANS: rilis pers SANS 2026 Threat Hunting Survey | https://www.sans.org/press/announcements/threat-hunters-call-data-their-biggest-barrier-overtaking-staffing-first-time-survey-finds | sekunder (rilis pers penyelenggara survei) | 2026-09-23; diakses 2026-10-10, dicek ulang 2026-10-18 | Sedang-tinggi. 40% mengukur formal pada 2026, 64% pada 2024; metodologi formal 37/46/51%; ad hoc 39% |
| S5 | Splunk: Introducing the PEAK Threat Hunting Framework | https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html | sekunder (blog vendor, penulis kerangka) | 2023; diakses 2026-10-10 | Tinggi untuk fase Act with Knowledge |
| S6 | MITRE ATT&CK Navigator (repo dan USAGE.md) | https://github.com/mitre-attack/attack-navigator | primer | diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi. Layer, skor, komentar; Create Layer from other layers (variabel a, b, operator perbandingan 1/0, and/or), pewarisan hanya domain dan versi sama, ekspor JSON/Excel/SVG, alur upgrade layer (https://github.com/mitre-attack/attack-navigator/blob/master/USAGE.md) |
| S7 | Threat-Hunting Day 01-14 (laporan hunt, kartu kesiapan, triase dan tanggal aktif detection) | (lokal) | rujukan internal | 2026-10-18 | Sumber semua angka PT JAB di lembar metrik, register, dan tanggal aktif |
| S8 | MITRE ATT&CK Navigator: CHANGELOG | https://raw.githubusercontent.com/mitre-attack/attack-navigator/master/CHANGELOG.md | primer | diakses 2026-10-18 | Tinggi. 5.3.2 (2026-04-21) terbaru; format layer 4.5 sejak 4.9.0; subfolder `layers/spec/` sejak 5.1.0 |
| S9 | MITRE ATT&CK Navigator: Layer File Format v4.5 | https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md | primer | diakses 2026-10-18 | Tinggi. Field wajib `name`, `domain`; `versions.navigator` minimal 4.9.0, `versions.layer` "4.5", `attack` opsional; objek technique (`techniqueID` wajib, `score`, `comment`, `tactic`), `gradient`, `legendItems` |
| S10 | MITRE ATT&CK: Versions of ATT&CK | https://attack.mitre.org/resources/versions/ | primer | diakses 2026-10-18 | Tinggi. v20.0 dirilis 2026-10-13; v19.2 2026-04-28 sampai 2026-10-12 |
| S11 | AttackIQ: What Does MITRE ATT&CK Coverage Really Mean? (Jon Baker, William Booth) | https://www.attackiq.com/2026/03/10/what-does-mitre-attack-coverage-really-mean/ | sekunder (blog vendor) | 2026-03-10; diakses 2026-10-18 | Sedang. Cakupan sebagai spektrum, 100% sebagai target yang salah, klaim cakupan butuh platform, prosedur, arti "tercakup", dan tanggal uji. Penulis vendor validasi keamanan |
| S12 | Splunk ES 8.7: Monitor your security operations center with findings | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/findings | primer | ES 8.7; diakses 2026-10-18 | Tinggi untuk istilah finding/intermediate finding dan contoh field `search_name`. Tidak menyebut nama index penyimpan |
| S13 | Splunk ES 7.3: How risk annotations provide additional context in Splunk Enterprise Security | https://help.splunk.com/en/splunk-enterprise-security-7/risk-based-alerting/7.3/identify-threat/how-risk-annotations-provide-additional-context-in-splunk-enterprise-security | primer | ES 7.3; diakses 2026-10-18 | Tinggi untuk ES 7.3: anotasi di `savedsearches.conf` sebagai JSON `action.correlationsearch.annotations`, definisi ATT&CK di `security_framework_annotations.csv`. Perlu dicek untuk ES 8.x |

**Catatan sumber:** pengelompokan impact, coverage, dan operational adalah alat bantu penyajian di catatan ini yang meminjam pola dari tulisan vendor [S3], bukan istilah PEAK. Sumber vanity metrics dan cakupan [S2][S3][S11] adalah tulisan vendor yang menjual layanan hunting, otomasi, atau validasi; pesannya konsisten dengan PEAK, tetapi klaim efektivitas produk di dalamnya tidak dipakai. Angka 40% dan 64% berasal dari rilis pers survei, bukan dari laporan lengkap; metodologi dan jumlah responden perlu dicek di laporan SANS bila angka ini akan dikutip di dokumen resmi. Lokasi anotasi ATT&CK detection ES berasal dari dokumentasi ES 7.3 [S13], dan nama index penyimpan finding di ES 8 tidak disebut di dokumentasi findings 8.7 [S12]; query bagian 2.6 dan 2.8 perlu dicek di ES 8.x sebelum dipakai. Seluruh angka PT JAB (register, lembar metrik, jumlah detection ES lama, layer awal 94 ID, status celah) adalah penerapan catatan ini pada organisasi fiktif, bukan hasil eksekusi nyata.
