---
day: 14
title: 'Hunt ke deteksi: memilah usulan, Pyramid of Pain, handover, Sigma dan konversi, alert vs sinyal risk, menguji, dan menutup loop'
researched_on: 2026-10-18
versions_checked: 'Sigma specification 2.1.0 (2025-08-02); SigmaHQ rule convention; sigma-cli 3.1.0 (PyPI 2026-07-07, butuh pySigma >=1.3,<2); pySigma 1.5.1 (2026-09-21) dan 2.0.1 (2026-10-11); pySigma-backend-splunk 2.1.0 (PyPI 2026-03-22, pipeline splunk_windows, splunk_sysmon_acceleration, splunk_cim; format default, savedsearches, data_model); pySigma-pipeline-sysmon; Splunk Enterprise Security 8.7 (event-based dan finding-based detection, risk modifier); Splunk Security Content "Windows Office Product Spawned Uncommon Process" v9 (2026-05-13); MITRE ATT&CK v20 (T1218.010 versi 3.0 dan T1204.002 versi 1.6, keduanya diubah 2026-05-12); Wazuh 4.x rule XML; Palantir ADS framework; PEAK (fase Act with Knowledge); Splunk Enterprise 10.6 (SPL)'
---

# Day 14: Hunt ke deteksi (memilah usulan, menulis rule yang teruji, dan menutup loop)

Cakupan: mengubah temuan hunt menjadi detection yang tahan lama dan teruji, mulai dari memilah usulan dan memilih bentuk keluaran (alert langsung, sinyal risk, laporan, ditunda), menulis rule Sigma dan mengonversinya ke SPL, menguji dengan contoh positif dan data sendiri, menyerahkan dengan format yang jelas, sampai menutup loop ke backlog dan mencatat metrik jembatan.

## Ide inti

Query hunt yang berhasil belum menjadi detection. Query hunt dibuat untuk dijalankan sekali atas rentang panjang, hasilnya ditinjau manusia satu per satu, dan semua yang jinak diberi label oleh hunter. Detection berjalan sendiri setiap beberapa menit, tidak ada hunter yang menilai hasilnya, dan setiap kecocokan mendarat di antrean L1. Jadi pekerjaan di jembatan ini adalah mengubah pengetahuan hunter menjadi sesuatu yang bisa berjalan tanpa hunter: memilih perilaku yang sulit diganti penyerang (bukan IOC yang ditemukan), menuliskan pengecualian sempit untuk false positive yang sudah dikonfirmasi saat hunt, menentukan bentuk keluaran dari volume nyata, membuktikan rule menangkap contoh positif dan diam di data sendiri, lalu menyerahkannya dengan pemilik, tanggal aktif, dan tanggal review. Tidak semua temuan harus menjadi alert. Pola yang hampir selalu jinak tetapi bermakna bila berkumpul lebih tepat menjadi sinyal risk, dan pola yang butuh penilaian manusia tetap menjadi laporan hunter. Setiap detection baru juga membuka pertanyaan baru, yaitu prosedur yang belum ia tutup, dan pertanyaan itu kembali ke backlog.

Kamu sudah mengenal pola ini dari NOC. Engineer yang menemukan degradasi optik saat patroli tidak langsung memasang alarm "error counter naik" di NMS. Ia melihat data beberapa minggu untuk menentukan ambang, mengecualikan port yang memang selalu bising dengan nama port yang jelas, menguji alarm dengan mengganggu link uji, menentukan siapa yang menerima alarm, dan menulis kapan alarm itu direview. Gejala yang sendirian tidak berarti apa-apa, misalnya satu interface flapping sekali, dijadikan alarm minor yang baru dieskalasi bila beberapa terkumpul di satu node. Batas analoginya: query hunt jarang langsung layak jadi rule karena masih butuh ambang, pengecualian, dan uji; dan untuk alarm minor yang dikumpulkan, skor dan daftar tujuan yang dikenal harus terus dirawat, karena bila tidak, skor menumpuk di agent sah dan alarm kumpulan itu menjadi bising seperti alarm biasa.

```
  usulan dari hunt (abstract deteksi: volume, FP, cakupan, uji)
        |
        v
  TRIASE --+--> alert langsung (finding)        volume rendah setelah pengecualian sempit
           +--> sinyal risk (intermediate)      sering jinak, bermakna bila berkumpul
           +--> laporan hunter (bukan antrean L1)  butuh penilaian manusia
           +--> tunda (menunggu perbaikan sistem/data)
           +--> kembali ke backlog (abstract belum cukup)
        |
        v
  Sigma (logika portabel) --> sigma-cli + pipeline --> SPL --> sesuaikan rentang, jeda, ambang
        |
        v
  UJI: positif (lab) | negatif (data PT JAB) | goodlog | replay jadwal
        |
        v
  handover + aktif di ES (status test) --> review --> stable
        |
        +--> blind spot dan prosedur lain --> backlog hunt (loop)
        +--> metrik jembatan: detection lahir dari hunt, waktu ke produksi, celah ditutup
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan. SOC PT JAB memakai Splunk Enterprise 10.6 dengan Enterprise Security (ES) 8.x di search head terpisah `jkt-splunk-es01`; search head umum untuk hunting adalah `jkt-splunk-sh01`. Sysmon terpasang di 214 host (61 server Windows dan 153 workstation OU `Workstations-EDR`); 229 workstation lain belum punya Sysmon. Sejak 1 Februari 2027, kamu (analyst L2) memegang Program hunt PT JAB setiap Selasa dan Kamis, dengan Dimas Prasetyo (SOC lead) sebagai sponsor. Setiap laporan hunt selama enam minggu itu berakhir dengan usulan untuk Sari Kusuma, analyst L2 pemilik konten detection `JAB - ...` di ES, tetapi selain tiga rule Wazuh untuk server Linux, belum ada satu pun yang menjadi detection di ES. Selasa 2027-03-16 pukul 08:20, Sari menulis di chat SOC:

> "Pagi. Aku sekarang pegang tumpukan usulan dari program hunt sejak awal Februari, dan Kamis lalu kamu tambah lagi dari LOLBin. Aku mau mulai memasang, tapi aku tidak mau antrean L1 banjir dan aku tidak mau rule yang basi dalam sebulan. Tolong bantu aku dulu. Dari semua usulan itu, mana yang benar-benar layak jadi detection dan mana yang tidak? Bagaimana memastikan logikanya tidak cepat basi, misalnya seperti daftar IOC `INC-2026-026` yang tidak menemukan laptop Surabaya? Apa yang harus ada di setiap usulan supaya aku tidak perlu mengulang hunt-mu? Query hunt-mu membaca sebulan data, sedangkan detection jalan tiap 15 menit, jadi bagaimana mengubahnya? Kamu menyebut Sigma: perlu tidak, dan bagaimana dari Sigma ke SPL di ES kita? Kapan alert langsung, kapan cukup risk? Terakhir, bagaimana mengujinya sebelum aktif, dan bagaimana kita tahu nanti bahwa program hunt benar-benar menambah detection?"

Pesan itu memuat tujuh pertanyaan:

1. Dari tumpukan usulan sejak Februari, mana yang layak menjadi detection dan mana yang tidak?
2. Bagaimana memilih logika yang tidak cepat basi?
3. Apa yang harus diserahkan hunter supaya Sari bisa memproses usulan tanpa mengulang hunt?
4. Bagaimana query hunt diubah menjadi rule terjadwal, termasuk rentang, jeda, dan ambang?
5. Perlukah Sigma, dan bagaimana mengubahnya menjadi SPL untuk ES PT JAB?
6. Kapan alert langsung, kapan cukup sinyal risk?
7. Bagaimana menguji sebelum aktif, dan bagaimana melacak hasilnya setelah aktif?

Pertanyaan 1 dijawab di bagian 1.1 dan 2.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3 dan 2.6, pertanyaan 4 di bagian 1.4 dan 2.5, pertanyaan 5 di bagian 1.5, 1.6, 2.2, dan 2.3, pertanyaan 6 di bagian 1.7 dan 2.5, dan pertanyaan 7 di bagian 1.8, 1.9, 2.4, dan 2.7. Bagian 2 mengerjakan dua contoh utama hari itu: dari `HUNT-2027-023` ke detection "JAB - Office meluncurkan signed proxy binary" lengkap dengan Sigma, konversi, dan uji; dan dari `HUNT-2027-020` ke sinyal risk "JAB - Beacon ke domain baru (risk)".

**Kapan relevan:** setiap kali hunt menemukan pola yang bisa dinyatakan sebagai logika dan perlu dijaga terus, termasuk hunt yang hasilnya "tidak ditemukan" tetapi sudah membuktikan bentuk jejaknya; saat menerima atau mereview usulan detection dari hunter; dan saat harus menjelaskan ke manajemen apa yang ditinggalkan program hunt secara permanen.
**Kapan bukan jawaban:** saat temuannya indikator satu kampanye (IP, hash, domain) yang cukup dipasang sementara di threat intelligence; saat pola hanya bisa dinilai manusia per kasus, sehingga tempatnya laporan hunter; saat datanya belum ada atau tidak stabil di host yang ingin ditutup (perbaiki telemetri dulu); dan saat ada insiden aktif, karena prioritasnya IR, bukan menulis rule.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (handover, Hierarchy of Detection Outputs, abstract deteksi, Sigma secara umum, risk event, uji positif) tidak diulang. Tabel ini memuat istilah baru yang dipakai di Day ini.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Detection-as-code | Rule disimpan di repo git, diubah lewat merge request yang direview, diuji otomatis, lalu dipasang dari repo | Konfigurasi router disimpan di repo dan dipasang lewat change yang direview, bukan diketik langsung di perangkat |
| `logsource` | Blok Sigma yang menyebut jenis log (`category`, `product`, `service`) | Jenis feed yang dibaca alarm: syslog, SNMP trap, NetFlow |
| Selection, filter, `condition` | Blok pencocokan di bagian `detection` Sigma dan ekspresi yang merangkainya | Kondisi alarm dan daftar port yang dikecualikan |
| Modifier | Akhiran nama field di Sigma yang mengubah cara cocok (`endswith`, `contains`, `all`) | Operator pencocokan di filter NMS |
| Status dan level rule | Kematangan rule (`experimental`, `test`, `stable`) dan tingkat keparahan (`informational` sampai `critical`) | Alarm uji coba lawan alarm produksi, dan kelas minor/major/critical |
| pySigma, sigma-cli | Pustaka Python untuk membaca dan mengonversi rule Sigma, dan antarmuka baris perintahnya | Template konfigurasi lintas vendor dan alat yang merendernya ke sintaks tiap perangkat |
| Backend | Plugin pySigma yang menghasilkan query untuk satu SIEM (misalnya Splunk) | Renderer untuk satu vendor perangkat |
| Processing pipeline | Aturan konversi yang memetakan field dan menambah kondisi sesuai cara data di-onboard | Pemetaan nama interface generik ke nama interface di tiap model perangkat |
| ADS (Alerting and Detection Strategy) | Kerangka dokumentasi detection dari Palantir | Runbook alarm: apa yang dipantau, kenapa, dan apa yang dilakukan saat berbunyi |
| Event-based detection | Detection ES 8 yang mencari event mentah lalu menghasilkan finding atau intermediate finding | Alarm yang dibangkitkan langsung dari satu jenis event |
| Finding-based detection | Detection ES 8 yang mengelompokkan finding dan intermediate finding per entitas dan memunculkan finding group | Korelasi alarm per node: eskalasi bila beberapa alarm minor menunjuk node yang sama |
| Finding dan intermediate finding | Hasil detection yang masuk antrean analyst (finding) dan yang hanya tersimpan di index risk (intermediate finding) | Alarm yang masuk tiket dan alarm minor yang hanya tercatat |
| Risk modifier | Pengaturan di detection ES 8: entitas, tipe entitas, skor, pesan, dan jenis keluaran | Bobot alarm per jenis gangguan |
| Threat object | Nilai yang mengaitkan perilaku lintas entitas (command line, domain, hash) | Signature gangguan yang sama di beberapa node |
| Jendela berjeda | Rentang search terjadwal yang berakhir beberapa menit sebelum waktu jalan, untuk memberi waktu event terlambat masuk index | Polling yang menunggu counter stabil sebelum dihitung |
| Throttling (suppression) | Menahan hasil berulang untuk kombinasi field yang sama selama jangka tertentu | Menahan alarm yang sama agar tidak terbit ulang tiap polling |
| Backtest dan replay | Menjalankan logika detection atas data lampau; replay mengulang jadwal hari per hari | Menguji ambang alarm baru dengan data trafik bulan lalu |
| Goodlog | Log dari host bersih dengan aktivitas normal, dipakai untuk memastikan rule diam | Trafik baseline dari segmen sehat |
| Fixture | Event contoh yang disimpan di repo sebagai input uji otomatis | Capture paket contoh untuk menguji filter |
| Metrik jembatan | Ukuran nilai hunt yang diwujudkan sebagai detection: jumlah detection, waktu ke produksi, celah yang ditutup | Jumlah alarm permanen yang lahir dari patroli |

### 1.1 Kapan temuan layak jadi deteksi

Pertanyaan pertama Sari muncul karena tumpukannya tidak seragam. Ada usulan rule dengan volume dua kejadian per dua minggu, ada laporan mingguan untuk hunter, ada sinyal risk, dan ada pola yang sendiri tidak yakin pantas diusulkan. Memasang semuanya sebagai alert akan membanjiri L1; menolak semuanya berarti enam minggu hunt hilang.

Tidak semua temuan hunt layak jadi rule. Tabel berikut adalah kriteria kelayakannya; baca per kolom, karena setiap kolom adalah tempat yang berbeda untuk temuan.

| Layak jadi deteksi | Lebih cocok tetap hunt berkala | Lebih cocok IOC sementara |
|---|---|---|
| Pola berulang dan bisa dinyatakan sebagai logika | FP tinggi yang butuh penilaian manusia tiap kali | Indikator spesifik satu kampanye (IP, hash) |
| FP bisa dikelola dengan filter | Butuh baseline yang sering berubah | Berumur pendek |
| Data tersedia dan stabil | Eksploratif, pertanyaan berubah tiap kali | Dari laporan intel satu peristiwa |

Temuan yang FP-nya hanya bisa dinilai manusia (misalnya "koneksi ke domain muda") lebih baik tetap sebagai hunt berkala atau sinyal risk (bagian 1.7), bukan alert langsung. Memaksakannya jadi alert menghasilkan alert fatigue: analyst menerima begitu banyak alert jinak sehingga mulai menutupnya tanpa membaca, dan alert yang benar ikut tertutup.

Untuk memilah tumpukan PT JAB, kriteria di atas diterjemahkan menjadi lima keputusan yang mungkin untuk setiap usulan:

- **Terima sebagai alert langsung.** Volume setelah pengecualian sempit rendah (nol sampai beberapa kejadian per bulan), setiap kecocokan layak diperiksa, dan data tersedia di host yang ingin ditutup. Ini level 4 di Hierarchy of Detection Outputs PEAK (Day 02 bagian 1.6).
- **Terima sebagai sinyal risk.** Pola sering jinak sendirian, tetapi bermakna bila menumpuk dengan sinyal lain di entitas yang sama.
- **Laporan hunter.** Pola butuh penilaian manusia setiap kali; dijadwalkan sebagai laporan untuk hunter di `jkt-splunk-sh01` (level 1), bukan masuk antrean L1.
- **Tunda.** Pola layak, tetapi volume baru bisa diterima setelah ada perbaikan di sistem atau data (misalnya IT membersihkan tool yang memicu FP).
- **Kembali ke backlog.** Usulan belum punya abstract deteksi yang cukup (tanpa volume, tanpa uji, atau tumpang tindih dengan kontrol lain yang belum dicek).

Satu batasan lagi yang menentukan semuanya: anggaran antrean. Sari tidak perlu angka absolut untuk ini; cukup bahwa setiap usulan menyebut volume per minggu dari data PT JAB sendiri, sehingga total tambahan antrean bisa dijumlahkan sebelum apa pun dipasang. Triase lengkapnya ada di bagian 2.1.

### 1.2 Pyramid of Pain: pilih logika yang tahan lama

Pertanyaan kedua Sari datang dari pelajaran yang masih baru. Daftar IOC `INC-2026-026` (domain, IP, hash installer PDF palsu) dicari ulang di seluruh data, tetapi laptop `SBY-WS-0107` yang terinfeksi varian lain baru ditemukan oleh hunt pola persistence `HUNT-2027-013`, karena varian itu memakai domain C2 lain (`cdn.pdfsuite-cloud.example.net`, `198.51.100.39`) yang tidak ada di daftar. Detection yang hanya berisi indikator itu akan basi persis seperti pencarian IOC itu.

Pyramid of Pain dari David Bianco menyusun jenis indikator berdasarkan seberapa sakit bagi penyerang bila indikator itu kamu blokir atau deteksi [S4]. Saat mengubah hunt jadi deteksi, pilih tingkat yang tahan lama (Day 01 bagian 1.4). Tabel ini dipakai untuk menilai setiap usulan; cari baris tempat logika usulan itu berada.

| Tingkat | Contoh | Ketahanan |
|---|---|---|
| Hash, IP, domain | IOC spesifik | Rapuh; penyerang mudah mengganti |
| Artefak host/jaringan | Nama file, path, user-agent | Sedang |
| Tools | Nama tool, pola command line khas | Sedang-tinggi |
| TTP (perilaku) | Parent-child, urutan, teknik | Paling tahan; penyerang sulit mengubah |

Deteksi yang lahir dari hunt sebaiknya menargetkan TTP (perilaku), bukan IOC yang ditemukan. Contoh: hunt yang menemukan `mshta` mengunduh dari satu IP sebaiknya menjadi deteksi "mshta dengan argumen URL" (perilaku), bukan "koneksi ke IP itu" (IOC yang akan basi).

Di PT JAB, ini berarti indikator dari `INC-2027-040` tetap dipasang di threat intelligence ES dengan masa berlaku, sedangkan yang dijadikan detection adalah perilakunya: scheduled task yang menjalankan biner dari folder AppData pengguna (usulan Day 10). Analogi dari NOC: memblokir satu MAC modem nakal berbeda dengan mengenali pola gangguan seri modem itu. Batasnya juga sama: indikator di puncak piramida lebih tahan, tetapi lebih mahal dirumuskan dan lebih banyak menghasilkan false positive. Itulah sebabnya rule perilaku selalu datang bersama pengecualian yang sudah dikonfirmasi saat hunt.

### 1.3 Apa yang hunter serahkan ke deteksi

Pertanyaan ketiga Sari adalah inti kekhawatirannya: usulan yang hanya berisi query mentah memaksanya mengukur ulang volume, mencari ulang FP, dan menebak cakupan.

Handover ke detection engineer bukan rule jadi, melainkan usulan deteksi yang bisa diproses. Strukturnya mengambil bagian penting dari Alerting and Detection Strategy (ADS), kerangka dokumentasi deteksi yang dipublikasikan Palantir [S3]. ADS meminta setiap deteksi punya goal, kategorisasi ATT&CK, strategy abstract (ringkasan cara kerja), technical context, blind spots and assumptions, false positives, validation (cara membuktikan rule bekerja), priority, dan response (apa yang dilakukan analyst saat alert muncul). Hunter tidak perlu mengisi semuanya, tetapi bagian yang hanya diketahui hunter wajib ada. Tabel berikut memetakan isi abstract deteksi PT JAB (format Day 02 bagian 2.7) ke bagian ADS; kolom kanan menunjukkan bagian ADS yang terisi.

| Bagian | Isi | Padanan di ADS |
|---|---|---|
| Hipotesis/tujuan | Perilaku apa yang dideteksi dan kenapa penting | Goal |
| Teknik ATT&CK | ID teknik (dan prosedur spesifik) | Categorization |
| Sumber data | Log/field yang dibutuhkan (dari Evidence hunt) | Technical Context |
| Logika kandidat | Query hunt yang berhasil, sebagai titik awal rule | Strategy Abstract |
| Sampel | Event TP dari hunt (dan FP kandidat yang ditemui) | Validation |
| False positive diketahui | Yang kamu temui saat hunt dan cara membedakannya | False Positives |
| Blind spot | Prosedur yang tidak tertangkap logika ini | Blind Spots and Assumptions |
| Saran output | Alert langsung atau sinyal risk, berdasarkan FP | Priority |

Query hunt yang berhasil adalah hadiah terbesar: ia sudah terbukti menemukan pola di data nyata. Bagian FP diketahui adalah yang kedua, karena hunter sudah memeriksa kasusnya satu per satu, sesuatu yang tidak bisa dilakukan detection engineer yang menulis rule dari laporan intel.

Dua hal ditambahkan di PT JAB karena pelajaran enam minggu terakhir. Pertama, baris cakupan: rule berbasis Sysmon hanya hidup di 214 host, dan rule berbasis 4698 tidak menyentuh laptop seperti `SBY-WS-0107`; menuliskannya mencegah rasa aman palsu (Day 10 bagian 2.8). Kedua, volume dari data sendiri, dihitung mentah dan setelah pengecualian sempit. Setelah detection diterima, handover akhir (bagian 2.6) menambahkan yang hanya diketahui pemilik konten: nama di ES, jadwal, entitas dan skor, tanggal aktif, dan tanggal review.

### 1.4 Dari query hunt ke rule

Pertanyaan keempat Sari tepat sasaran: query `HUNT-2027-023` membaca seluruh Februari, menghitung dengan `stats`, dan semua hasilnya diberi label oleh hunter. Detection membaca 15 menit, menghasilkan satu kecocokan per event, dan tidak punya hunter di belakangnya.

Query hunt dan rule deteksi berbeda tujuan, jadi perlu disesuaikan. Tabel ini merangkum bedanya; baca baris "Tuning", karena di situ pekerjaan terbesar jembatan ini.

| Aspek | Query hunt | Rule deteksi |
|---|---|---|
| Rentang | Panjang (30 hari eksplorasi) | Jendela pendek yang dijalankan berkala, dengan jeda untuk keterlambatan log |
| Ambang | Longgar (ingin melihat banyak) | Ketat, diambil dari distribusi data nyata |
| Output | Daftar untuk ditinjau manusia | Alert atau risk event |
| Tuning | Minimal (hunter menilai) | Filter dan allowlist yang terdokumentasi |
| Baseline | Interaktif | Tersimpan dan terjadwal |

Dua istilah di tabel itu perlu dijelaskan. Jendela berjeda berarti rule yang dijadwalkan tiap jam tidak memeriksa "60 menit terakhir sampai sekarang", melainkan misalnya "dari 70 sampai 10 menit lalu", supaya event yang terlambat masuk index tidak terlewat. Konten resmi Splunk memakai pola persis itu: detection Office dari Splunk Security Content dijadwalkan setiap jam (`0 * * * *`) dengan `earliest=-70m@m` dan `latest=-10m@m` [S26]. Ambang dari distribusi berarti kamu melihat sebaran nilai normal (misalnya persentil 99 jumlah koneksi per host per jam selama 30 hari) lalu menaruh ambang di atasnya, bukan memakai angka bulat yang terasa wajar.

Jeda dipilih dari latency nyata. Di PT JAB, latency indexing Sysmon p50 4 detik dan p95 38 detik (Day 04), sehingga jeda 10 menit sudah longgar untuk host yang online. Yang tidak tertolong jeda adalah host yang offline lalu mengirim tumpukan event saat tersambung lagi; untuk itu ada variasi berbasis waktu index di bagian 2.3.

Ambang juga harus diskalakan ulang bila rentangnya berubah. Hunt beacon `HUNT-2027-020` mensyaratkan minimal 20 koneksi dalam 28 hari; detection yang membaca 7 hari tidak bisa memakai angka yang sama tanpa membutakan beacon jarang (hitungannya di bagian 2.5).

Mengubah query hunt jadi rule berarti: persempit rentang, tetapkan ambang dari distribusi, tambahkan filter untuk FP yang ditemui, tulis dalam format rule yang bisa dibawa lintas SIEM, lalu uji dengan sampel dan emulasi.

### 1.5 Sigma: format rule yang portabel

Pertanyaan kelima Sari dimulai dengan "perlu tidak". Untuk PT JAB jawabannya ya, dengan alasan praktis: konten detection hidup di dua tempat (ES untuk Windows dan jaringan, Wazuh untuk server Linux), dan rule yang ditulis langsung dalam SPL tidak bisa direview, diuji, atau dipindah tanpa menulis ulang.

**Sigma** adalah format rule deteksi generik berbasis YAML yang tidak terikat SIEM tertentu [S1]. Satu rule Sigma punya metadata (`title`, `id`, `status`, `description`, `tags`, `level`, `falsepositives`), blok `logsource` yang menyatakan jenis log (misalnya `category: process_creation`, `product: windows`), dan blok `detection` berisi satu atau lebih selection plus `condition` yang merangkainya. Field bisa diberi modifier, misalnya `Image|endswith` atau `CommandLine|contains`. Pencocokan nilai di Sigma tidak peka huruf besar kecil secara default [S1]. Daftar di dalam satu field dibaca sebagai OR, sedangkan beberapa field di dalam satu selection dibaca sebagai AND.

Spesifikasi versi 2.1.0 (2025-08-02) merinci aturan yang dipakai di Day ini [S1]:

- **`id`** adalah UUID versi 4 yang dibuat acak sekali dan tidak pernah diganti, supaya rule bisa dilacak walaupun judulnya berubah.
- **`status`**: `experimental` (bisa bising, tetapi bisa menemukan hal menarik), `test` (sebagian besar stabil, mungkin butuh penyesuaian per lingkungan), `stable` (andal untuk produksi), `deprecated` (diganti rule lain lewat `related`), dan `unsupported` (tidak bisa dipakai apa adanya).
- **`level`**: `informational` (pengayaan, tidak membuat alert), `low`, `medium` (review manual rutin), `high` (memicu alert internal dan review), dan `critical` (hanya bila kemungkinannya mendekati pasti).
- **`related`** menautkan rule ke rule lain dengan tipe `derived`, `obsolete`, `merged`, `renamed`, atau `similar`. Tipe `merged` berguna bila dua usulan hunt digabung menjadi satu rule.
- **`date`** dan **`modified`** memakai format `YYYY-MM-DD`.
- **`condition`** mengenal `and`, `or`, `not`, tanda kurung, dan bentuk `1 of <pola>` atau `all of <pola>` dengan wildcard pada nama selection; `all of them` tidak dianjurkan.
- **Daftar dan map**: item dalam daftar di-OR-kan, pasangan dalam satu map di-AND-kan, dan beberapa map dalam satu daftar di-OR-kan. Itulah cara Sigma menyatakan "field A cocok ATAU field B cocok".
- **Nilai** dicocokkan tanpa peka huruf, tetapi regular expression (`re`) peka huruf secara default.

Konvensi SigmaHQ, yang berlaku untuk repo publik SigmaHQ dan bukan bagian dari spesifikasi, menambahkan kebiasaan yang layak ditiru di repo internal [S14]: rule baru selalu mulai sebagai `experimental`; `falsepositives` ditulis sejelas mungkin (atau `Unknown` bila belum diuji, `Unlikely` bila penulis tidak memperkirakan FP), tanpa kata seperti "Pentest"; filter pengecualian dinamai `filter_main_*` untuk yang selalu ada di instalasi bawaan dan `filter_optional_*` untuk software yang tidak selalu ada; dan bentuk `1 of selection_*` diutamakan. Konvensi itu juga meminta judul bergaya Title Case berbahasa Inggris dan deskripsi diawali "Detects"; di repo internal PT JAB, `title` sengaja disamakan dengan nama detection di ES (`JAB - ...`) supaya pencarian lintas sistem mudah.

Tag ATT&CK ditulis dengan namespace `attack`: tag teknik `attack.t1218.010` dan tag taktik huruf kecil bertanda hubung [S15]. Rule SigmaHQ terbaru sudah memakai `attack.stealth` untuk TA0005, nama taktik di ATT&CK v20 [S16]; daftar contoh taktik di lampiran tag spesifikasi masih memuat nama lama seperti `defense-evasion` [S15]. Repo PT JAB memakai `attack.stealth` agar selaras dengan ATT&CK v20 dan Day 13.

Rule SigmaHQ yang paling dekat dengan usulan `HUNT-2027-023` adalah "Suspicious Microsoft Office Child Process" (status `test`, level `high`), yang mencocokkan sekitar sepuluh parent Office dan puluhan child, termasuk `cmd.exe`, `powershell.exe`, dan child dari folder seperti `\AppData\` [S16]. Rule itu tidak memasukkan `OUTLOOK.EXE` sebagai parent. Dipasang apa adanya di PT JAB, rule itu akan menyala untuk makro rekonsiliasi Keuangan (`EXCEL.EXE` ke `cmd.exe`, Day 01) dan makro template Marketing (`WINWORD.EXE` ke `cmd.exe`, Day 06), tetapi tidak melihat Outlook. Rule publik adalah titik awal yang baik; volume dan pengecualiannya tetap harus diukur di data sendiri.

### 1.6 Konversi dan detection-as-code secukupnya

Bagian kedua pertanyaan kelima Sari: dari Sigma ke SPL yang benar-benar jalan di ES PT JAB. Di sinilah rule yang sintaksnya sempurna bisa diam selamanya.

**Konversi** dilakukan dengan pySigma, pustaka Python yang membaca rule Sigma lalu menerjemahkannya lewat backend (misalnya backend Splunk) dan processing pipeline yang memetakan nama field Sigma ke nama field di datamu [S2]. Antarmuka baris perintahnya `sigma-cli`, dengan pola `sigma convert -t <backend> -p <pipeline> <rule>` [S2]. Pipeline penting: rule yang sama menghasilkan query yang salah bila pemetaan field-nya tidak cocok dengan cara data di-onboard. Untuk Wazuh, jalur yang aman adalah menulis rule XML sendiri dengan logika yang sama, karena backend Sigma untuk Wazuh tidak menjadi bagian dari pySigma inti; cek status alat konversi pihak ketiga sebelum memakainya.

Komponen yang dipakai untuk Splunk, dan apa yang dilakukan masing-masing:

- **Backend `splunk`** (pySigma-backend-splunk 2.1.0) punya tiga format keluaran: `default` (query SPL biasa), `savedsearches` (isi `savedsearches.conf`), dan `data_model` (query `tstats` atas data model, dengan opsi seperti `summariesonly`) [S19][S20].
- **Pipeline `sysmon`** (paket pySigma-pipeline-sysmon) menambahkan kondisi EventID per kategori log, misalnya `process_creation` menjadi EventID 1 dan `network_connection` menjadi EventID 3, lalu mengubah logsource menjadi `service: sysmon` [S21].
- **Pipeline `splunk_windows`** menambahkan kondisi `source` berbentuk `WinEventLog:<channel>` untuk log Windows dan mengganti nama `EventID` menjadi `EventCode` [S20].
- **Pipeline `splunk_cim`** memetakan field ke data model CIM (misalnya `Endpoint.Processes`), dan `splunk_sysmon_acceleration` menambah kata kunci untuk mempercepat search Sysmon [S20].
- **`sigma check`** memvalidasi rule: error parsing, error condition, dan isu dari validator pySigma yang terpasang; secara default perintah gagal bila ada error, tetapi tidak gagal bila hanya ada isu, kecuali diberi `--fail-on-issues` [S22].

Jebakan PT JAB ada di pipeline `splunk_windows`. Sysmon PT JAB masuk dengan `source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` dan `sourcetype=XmlWinEventLog`, sedangkan pipeline itu membangun `source` dengan awalan `WinEventLog:`. Query hasil konversi tetap valid, tetapi tidak pernah cocok dengan satu event pun. Tanpa `splunk_windows`, masalahnya berbalik: pipeline `sysmon` menulis `EventID=1`, padahal field di PT JAB bernama `EventCode`. Jalan keluarnya adalah pipeline YAML kecil milik PT JAB yang memetakan `EventID` ke `EventCode` dan menambahkan `index=sysmon sourcetype=XmlWinEventLog` (bagian 2.3). Format pipeline YAML pySigma memuat `name`, `priority`, dan daftar `transformations`, masing-masing dengan `id`, `type` (misalnya `field_name_mapping`), parameter, dan `rule_conditions` yang membatasi transformasi ke logsource tertentu [S23]. Pipeline `sysmon` punya prioritas 5, sehingga dijalankan sebelum pipeline berprioritas lebih tinggi [S21].

**Detection-as-code** berarti rule disimpan di repo git seperti kode: setiap perubahan lewat pull request, ditinjau orang lain, diuji otomatis (validasi sintaks Sigma, konversi berhasil, sampel TP memicu, sampel jinak tidak memicu), lalu di-deploy dari repo. Manfaatnya untuk hunter: usulan dari hunt punya tempat masuk yang jelas, dan metadata seperti asal hunt bisa dilacak (Day 15).

Versi secukupnya untuk PT JAB, yang bisa dikerjakan satu pemilik konten tanpa platform baru:

- Repo `jab-detections` di GitLab internal, dipegang Sari, dengan review satu orang (Dimas atau hunter) seperti `jab-hunt`.
- Setiap rule Sigma membawa field kustom `origin_hunt` berisi nomor hunt asal, supaya detection yang lahir dari hunt bisa dihitung dari repo.
- Pipeline GitLab menjalankan `sigma check` dan `sigma convert` untuk setiap merge request; hasil konversi disimpan sebagai artefak.
- Sari memasang hasil konversi sebagai event-based detection di ES lewat Content management, lalu mencatat nama detection dan commit asalnya di handover. Pemasangan otomatis ke ES tidak dikejar sekarang.

Alat Splunk sendiri untuk alur ini sedang bergeser: `contentctl`, alat tim riset Splunk untuk mengelola repo Security Content, tidak lagi menerima pull request baru karena investasi dipindah ke Detection Studio di ES [S28][S29]. Karena itu PT JAB tidak membangun alur di atas `contentctl`.

### 1.7 Alert langsung atau sinyal risk

Pertanyaan keenam Sari adalah tempat banjir antrean dicegah atau dibiarkan. Usulan "JAB - Beacon ke domain baru (risk)" dari Day 12 sudah menjawab sebagian: pola beacon ke tujuan baru hampir selalu jinak (aplikasi baru yang sah), tetapi menjadi sangat menarik bila host yang sama juga mengunggah data besar ke tujuan baru.

Ada dua bentuk output deteksi:

- **Alert langsung.** Rule yang cocok langsung membuat alert untuk ditriase analyst. Cocok untuk perilaku yang jarang sah, sehingga hampir setiap kecocokan layak diperiksa.
- **Sinyal risk.** Rule yang cocok tidak membuat alert, melainkan menambahkan skor risk ke entitas (user atau host) dan mencatat objek ancamannya (command line, IP, nama file). Alert baru muncul ketika skor total entitas dalam suatu jendela melewati ambang, atau ketika beberapa teknik berbeda menumpuk di entitas yang sama [S6]. Pendekatan ini dikenal sebagai risk-based alerting (RBA) di Splunk Enterprise Security; skor bisa dinaikkan untuk entitas penting seperti admin atau server yang menghadap internet [S6].

RBA membuat sinyal ber-FP tinggi tetap berguna: satu sinyal tidak cukup untuk alert, tetapi tiga sinyal berbeda di host yang sama dalam satu hari sudah layak diperiksa. Di Splunk ES 8, alert disebut finding (menggantikan notable event di ES 7); cek nama tampilan risk event di versi-mu. Wazuh tidak punya mesin skor risk per entitas yang setara, jadi di Wazuh pola serupa biasanya ditiru dengan rule korelasi (`if_matched_sid` dengan `frequency` dan `timeframe`) atau dengan memindahkan korelasinya ke SIEM lain; cek kebutuhanmu sebelum memilih.

Di ES 8 kedua bentuk itu diatur di objek yang sama. Event-based detection punya risk modifier: nama field entitas (misalnya `dest` atau `src`), tipe entitas (user, system, atau other), skor (bilangan bulat; skor 0 hanya menyimpan event sebagai konteks di index risk), pesan risk yang bisa memuat field seperti `$dest$`, dan keluaran berupa Finding atau Intermediate Findings. Dokumentasi ES 8.7 menganjurkan Finding untuk entitas utama dan Intermediate Findings untuk entitas tambahan; threat object (misalnya command line atau hash) ditambahkan di bagian yang sama [S24]. Menu pembuatannya di ES 8.7 berada di Security content > Content management, lalu tombol konten baru (ditulis `+Content` di satu halaman dan Create new content di halaman lain) > Detection, yang menawarkan pilihan event-based atau finding-based [S24][S25]. Jadi "alert langsung" berarti minimal satu entitas berkeluaran Finding, dan "sinyal risk" berarti semua entitasnya berkeluaran Intermediate Findings.

Pengumpulnya adalah finding-based detection. Detection jenis ini mengelompokkan finding dan intermediate finding yang berbagi entitas menjadi finding group (maksimal 100 finding per group), dan skor agregat sebuah aset atau identitas adalah jumlah skor risk-nya di index risk pada periode tertentu [S25]. ES 8.7 mengaktifkan dua bawaan: "Risk - 24 Hour Risk Threshold Exceeded - Rule" (skor melewati ambang dalam 24 jam; nilai ambangnya tidak disebut di halaman itu, jadi cek di instance-mu) dan "Risk - 7 Day ATT&CK Tactic Threshold Exceeded - Rule" (minimal tiga taktik ATT&CK berbeda dan lebih dari empat detection berbeda) [S25]. Untuk PT JAB yang baru punya beberapa sumber risk, syarat tiga taktik dan lebih dari empat detection hampir tidak pernah tercapai, sehingga dibutuhkan finding-based detection sendiri yang lebih sederhana (bagian 2.5).

Konten resmi Splunk memberi contoh campuran keduanya: detection "Windows Office Product Spawned Uncommon Process" membuat Finding pada `user` dan Intermediate Finding pada `dest`, keduanya skor 50, dijalankan setiap jam [S26]. Detection itu juga contoh konsolidasi: detection per binary seperti "Office Application Spawn rundll32 process" dihapus di versi 5.2.0 karena dinilai tidak lagi efektif, dan diarahkan ke detection generik tersebut [S27].

Satu jebakan entitas yang khas PT JAB: sinyal dari proxy hanya punya IP sumber (`src`), sedangkan sinyal dari Sysmon punya nama host (`dest`). Bila entitasnya tidak dinormalisasi, dua sinyal dari laptop yang sama tidak pernah bertemu di satu entitas, dan finding-based detection diam walaupun logikanya benar. Batas ini ditulis di handover risk (bagian 2.5).

### 1.8 Menguji deteksi yang lahir dari hunt

Pertanyaan ketujuh Sari dimulai dengan uji. Untungnya, deteksi dari hunt datang dengan bahan uji yang tidak dimiliki rule yang ditulis dari laporan intel.

Deteksi baru diuji dari tiga arah:

- **Sampel TP dari hunt.** Event yang kamu temukan harus memicu rule. Simpan event mentahnya (dianonimkan) di repo sebagai fixture uji.
- **Sampel FP dan data jinak.** Event FP yang kamu temui saat hunt tidak boleh memicu. Tambahkan juga log dari host bersih yang menjalankan aktivitas normal (sering disebut goodlog) untuk memastikan rule tidak menyala pada aktivitas harian.
- **Emulasi.** Jalankan tes emulasi di lab, misalnya dari Atomic Red Team (Day 13 bagian 1.8), untuk membuktikan rule menangkap teknik itu di luar satu sampel yang kamu punya. Emulasi mengukur recall: berapa variasi prosedur yang tertangkap.

Keuntungan deteksi dari hunt: kamu sudah punya sampel TP dan FP nyata dari proses hunting, sehingga pengujian lebih kuat daripada rule yang ditulis spekulatif. Perhatikan juga bahwa tes emulasi tidak selalu meniru prosedur yang kamu temukan. Contohnya ada di bagian 2.4.

Dua uji tambahan berlaku untuk rule terjadwal di PT JAB:

- **Backtest atas data sendiri dengan logika final.** Hunt sudah menghitung volume, tetapi dengan query hunt. Rule hasil konversi harus dijalankan ulang atas rentang yang sama, karena pipeline, filter, dan perbedaan huruf bisa membuat angkanya berbeda. Tambahkan juga data setelah hunt selesai: pola jinak baru sering muncul dalam beberapa hari.
- **Replay jadwal.** Untuk rule yang membaca jendela bergeser (misalnya 7 hari, dijalankan harian), jalankan logikanya untuk setiap tanggal jadwal di masa lalu. Replay menunjukkan hal yang tidak terlihat di backtest satu kali: hasil yang sama berulang setiap hari, dan efek awal baseline ketika semua tujuan terlihat "baru".

Status Sigma mengikuti hasil uji: rule ditulis sebagai `experimental`, naik ke `test` setelah lulus uji positif, uji negatif, dan goodlog, lalu naik ke `stable` setelah berjalan di produksi tanpa FP yang tidak tertangani sampai tanggal review.

### 1.9 Menutup loop dan metrik jembatan

Bagian akhir pertanyaan ketujuh Sari ("bagaimana kita tahu program hunt benar-benar menambah detection") juga pertanyaan Hendra untuk evaluasi akhir kuartal Rabu 2027-03-31.

Hunting loop (Day 02 bagian 1.1) adalah siklus: deteksi baru memunculkan hipotesis baru. Saat sebuah perilaku menjadi deteksi, pertanyaan berikutnya muncul:

- Prosedur lain dari teknik yang sama yang belum tertutup. Cakupan dihitung per prosedur, bukan per ID teknik: rule regsvr32 dari Office tidak menutup regsvr32 dari `wmiprvse.exe`.
- Cara penyerang menghindari deteksi baru ini (binary yang di-rename, parent yang berbeda).
- Perilaku terkait yang sering muncul bersama.

Masukkan pertanyaan ini ke backlog (Day 02 bagian 2.7) sebagai hipotesis baru.

Dua metrik menunjukkan nilai jembatan hunt ke deteksi (Day 15 memperdalam metrik):

- **Deteksi yang lahir dari hunt:** berapa rule baru atau rule yang diperbaiki berasal dari hunt. Ini bukti hunting menambah cakupan permanen.
- **Celah yang ditutup:** teknik atau prosedur yang sebelumnya tidak terdeteksi, kini terdeteksi. Cara praktis mencatatnya adalah layer ATT&CK Navigator, berkas JSON yang memberi skor dan komentar per teknik di matriks ATT&CK [S10]. Teknik yang deteksinya lahir dari hunt diberi komentar asal hunt-nya.

Agar metrik itu bisa dihitung tanpa mengandalkan ingatan, setiap detection yang diterima mencatat tiga hal sejak hari pertama: `origin_hunt` di rule Sigma, tanggal laporan hunt asal, dan tanggal aktif di produksi. Selisih dua tanggal terakhir adalah waktu ke produksi, metrik yang langsung menunjukkan apakah jembatan ini macet. Di PT JAB jembatan itu memang macet: usulan pertama (`HUNT-2027-002`, 2 Februari) menunggu enam minggu, dan itulah yang diperbaiki hari ini (bagian 2.7).

## 2. Contoh dan langkah praktis: dari tumpukan usulan ke detection aktif di ES PT JAB

Bagian ini mengerjakan permintaan Sari hari Selasa itu: memilah semua usulan, mengerjakan dua contoh utama dari awal sampai handover, lalu mencatat detection yang aktif dan menutup loop. Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi; query ditulis untuk Splunk PT JAB, dan versi untuk lab pribadi ada di bagian 3.

Asumsi data: Sysmon di `index=sysmon`, `sourcetype=XmlWinEventLog`, `source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, dengan field asli Sysmon (`Image`, `ParentImage`, `OriginalFileName`, `CommandLine`, `User`, `ProcessGuid`, `Hashes`) dan `EventCode`; proxy di `index=proxy sourcetype=squid:access` dengan `src`, `dest`, `duration` (milidetik), dan `bytes_out` dari `%>st` (Day 12); lookup `jab_hunt_baseline_beacon.csv` (`dest`, `owner`) dan `jab_hunt_baseline_dest.csv` (`dest`, `first_seen`, `last_seen`, `hosts`, diperbarui harian 02:30). Cek nama index, sourcetype, dan field di lingkunganmu sebelum menjalankan.

### 2.1 Triase tumpukan usulan sejak Februari

Langkah pertama adalah daftar lengkap yang menjawab pertanyaan pertama Sari. Setiap baris diambil dari laporan hunt yang sudah ada di `jab-hunt`; tidak ada usulan baru yang ditambahkan hari ini. Pertanyaan PEAK dari Day 02 bagian 1.6 diajukan untuk setiap baris: apakah kita tahu cara menemukan aktivitas ini, dan apakah kita yakin menaruh hasilnya di depan L1.

Tabel berikut adalah hasil triase Selasa pagi bersama Sari. Baca kolom "Volume dari data", karena hanya angka itu yang boleh dipakai untuk memutuskan; volume Februari 2027 dihitung ulang hari ini dengan logika usulan bila Day asal memakai rentang lain.

| Usulan | Asal | Volume dari data | Keputusan | Alasan |
|---|---|---|---|---|
| JAB - certutil atau bitsadmin mengunduh dari URL eksternal | `HUNT-2027-002` (Day 02) | 2 dalam 14 hari Januari; Februari 1 (`jkt-mgmt01`, `adm.hari`, Rabu 2027-02-10 14:05, unduhan `nicutil-4.2`, tiket change) | Alert | Volume rendah, verifikasi lewat tiket change murah; pengecualian per host sengaja tidak dibuat (Day 02 bagian 2.7) |
| JAB - Office atau WMI memunculkan shell | `HUNT-2027-001` (Day 01), catatan Day 06 | Office ke `cmd`/`powershell` Februari: 14 mentah (add-in tanda tangan Outlook 9 di 2 host, makro Keuangan 4, template Word Marketing 1); 1 setelah pengecualian persis | Bagian Office: risk (skor 20). Bagian WMI: digabung ke usulan logon admin | Makro dan add-in bisnis belum diinventaris dan pengecualian per command line mudah patah saat makro diubah; WMI dari `JKT-JUMP01` sah 512 kali per bulan dan sumbernya tidak ada di event Sysmon |
| TH - kandidat beacon proxy (mingguan) | `HUNT-2027-005` (Day 05) | Laporan, bukan alert | Laporan hunter | Butuh penilaian per tujuan; dijadwalkan di `jkt-splunk-sh01` role `jab_hunter` |
| Laporan first-seen parent-child (harian 01:00, baseline 01:30) | `HUNT-2027-006`, `-007` (Day 05, 06) | Laporan, bukan alert | Laporan hunter, versi `tstats` | Pasangan baru hampir selalu rollout software sah |
| JAB - Scheduled task di root menjalankan command dari folder pengguna | `HUNT-2027-004` (Day 07) | 98 dalam 17 hari, 1 setelah pengecualian OneDrive | Digabung (`related: merged`) ke usulan AppData Day 10 | Dua usulan menangkap perilaku yang hampir sama; dua rule untuk satu perilaku menggandakan alert |
| JAB - Scheduled task dibuat dengan LogonType Password | `HUNT-2027-004` (Day 07) | 1 dalam 17 hari (`jkt-filesrv01`, `svc_filesync`, tiket change) | Tunda | Satu-satunya kecocokan adalah task sah yang direkomendasikan pindah ke gMSA (Agung); aktifkan setelah itu agar setiap kecocokan berarti |
| Rule Wazuh 100200, 100201, 100202 | `HUNT-2027-010` (Day 08) | 0 alert per minggu yang diharapkan | Sudah aktif sejak Kamis 2027-02-25 malam | Dipasang Agung di jendela change setelah review Sari; review pengecualian 100202 tetap 2027-03-31 |
| Laporan first-seen login SSH `jkt-bastion01` (mingguan) | `HUNT-2027-011` (Day 08) | Laporan, bukan alert | Laporan hunter | Pasangan akun-IP baru biasanya runner atau admin baru |
| Hunt TaskScheduler mingguan di Velociraptor | `HUNT-2027-013` (Day 09) | Hunt terjadwal | Di luar ES | Kontrol pengganti untuk host tanpa audit; bukan konten ES |
| JAB - Scheduled task menjalankan biner dari folder AppData pengguna | `HUNT-2027-015` (Day 10) | Februari 412 cocok, 8 setelah pengecualian (sekitar 2 per minggu) | Alert | Perilaku `INC-2027-040`; cakupan 214 host ditulis terang |
| JAB - Logon akun admin ke workstation dari host selain `JKT-JUMP01` | `HUNT-2027-019` (Day 11) | Februari 31 event, semua `adm.ilham` dari `JKT-WS-0671` sebelum ditindaklanjuti; Jumat 2027-03-05 sampai Senin 2027-03-15: 0 | Alert | Data 4624 ada di 443 host Windows, termasuk 229 workstation tanpa Sysmon; setiap kecocokan adalah pelanggaran kebijakan atau lateral movement |
| JAB - WmiPrvSE memunculkan shell di workstation dari sumber selain `JKT-JUMP01` | `HUNT-2027-019` (Day 11) | Tidak bisa diukur sebagai satu event | Tolak (digantikan logon admin) | Sumber WMI tidak ada di event Sysmon EID 1, sehingga butuh korelasi dengan 4624; logon admin menangkap prasyarat yang sama dengan cakupan lebih luas |
| TH - kandidat spray per sumber (mingguan) | `HUNT-2027-018` (Day 11) | Laporan, bukan alert | Laporan hunter | Ambang spray lambat butuh penilaian per sumber |
| Akses LSASS dari image tidak lazim | `HUNT-2027-017` (Day 11) | Februari 0 di luar 5 SourceImage Microsoft | Kembali ke backlog | Belum ada abstract deteksi (GrantedAccess, CallTrace, uji lab) dan belum dicek tumpang tindih dengan alert bawaan MDE |
| JAB - Beacon ke domain baru (risk) | `HUNT-2027-020` (Day 12) | Day 12: 2 risk event dalam 28 hari (`push.kanbanapp.example`); replay hari ini di bagian 2.5 | Risk (skor 30) | Hampir selalu aplikasi baru yang sah; bermakna bila berkumpul |
| JAB - Unggahan besar ke tujuan baru (risk) | `HUNT-2027-022` (Day 12) | 5 transfer di 2-9 Maret, semua jinak | Risk (skor 30) | Sama; pasangan sinyal untuk beacon |
| JAB - Office meluncurkan signed proxy binary | `HUNT-2027-023` (Day 13) | Februari 76 mentah, 0 setelah pengecualian | Alert | Contoh utama, bagian 2.2 sampai 2.4 |
| JAB - Proxy binary dengan scriptlet atau skrip inline | `HUNT-2027-023` (Day 13) | Februari 0 (termasuk `mshta.exe` selain HTA lokal) | Alert | Setiap kecocokan layak ditanya; pola sudah diperbaiki dengan `about:` |
| JAB - Script host menjalankan skrip dari Downloads, Temp, atau ekstraksi arsip | `HUNT-2027-025` (Day 13) | Februari 2 (vendor OLT, NOC) | Alert | Pola `INC-2026-019`; triage cukup bertanya ke pengguna |
| `OriginalFileName` tidak cocok atau lokasi di luar daftar resmi | `HUNT-2027-024` (Day 13) | 297 mentah; 85 sebelum IT membersihkan toolkit dan launcher | Tunda (laporan mingguan dulu) | Diaktifkan sebagai alert setelah dua minggu berturut-turut 0 |
| `wscript`/`cscript` dari AppData | `HUNT-2027-025` (Day 13) | 112 (`logon_old.vbs`, 6 host) | Tunda | Ukur ulang setelah IT membersihkan skrip lama |
| `rundll32 url.dll,FileProtocolHandler https://...` | `HUNT-2027-002`, `-023` | 118 per bulan | Tetap tidak diusulkan | Tidak ada pembeda |

**Cara membaca hasil:**

- **Enam alert, tiga sinyal risk, satu pengumpul.** Ditambah finding-based detection yang dibutuhkan sinyal risk (bagian 2.5), ada sepuluh detection ES yang diterima hari ini. Tabel lengkapnya, dengan tanggal aktif, ada di bagian 2.7.
- **Anggaran antrean L1.** Dari volume Februari dan awal Maret, enam alert itu menambah sekitar 3 alert per minggu: scheduled task AppData sekitar 2, script host dari Downloads/Temp sekitar 0,5, certutil/bitsadmin sekitar 0,25, sisanya nol. Sinyal risk tidak menambah antrean kecuali pengumpulnya menyala.
- **"Tolak" dan "tunda" punya alasan tertulis.** Usulan yang ditolak di sini tidak hilang: WMI digantikan rule yang lebih luas, dan dua usulan tunda punya syarat aktivasi yang bisa dicek.
- **Laporan hunter bukan konten ES.** Lima laporan dan satu hunt terjadwal dipindah dari tumpukan Sari ke tanggung jawab hunter, dijadwalkan di bawah role `jab_hunter` mulai Senin 2027-03-22.

**Kapan gagal:** triase dilakukan tanpa angka volume, sehingga keputusan "alert" diambil dari kesan; atau usulan yang tumpang tindih (dua rule scheduled task) diterima dua-duanya, sehingga satu kejadian menghasilkan dua alert dan L1 belajar mengabaikan salah satunya.

### 2.2 Dari `HUNT-2027-023` ke draf Sigma

Contoh utama pertama menjawab pertanyaan kelima Sari dengan rule nyata. Bahannya laporan `HUNT-2027-023` (Day 13 bagian 2.8): hasil tidak ditemukan di 214 host ber-Sysmon selama Februari, 76 eksekusi Outlook ke `rundll32.exe` yang semuanya jinak dalam dua pola, dan uji positif di VM lab yang membuktikan query menangkap Word ke `regsvr32.exe`.

Teknik yang terlibat: T1218.010 (System Binary Proxy Execution: Regsvr32) adalah pemakaian `regsvr32.exe` yang bertanda tangan Microsoft untuk memuat kode, termasuk scriptlet COM lewat `scrobj.dll`, sehingga eksekusi tampak berasal dari binary sah [S7]. Di ATT&CK v20 teknik ini berada di taktik Stealth (TA0005), versi 3.0, dengan detection strategy DET0282; halaman itu menyebut regsvr32 bisa memuat COM scriptlet untuk menjalankan DLL dengan hak pengguna, termasuk dari URL, tanpa perubahan registry karena objek COM tidak pernah didaftarkan [S7]. T1204.002 (User Execution: Malicious File) adalah eksekusi yang dipicu pengguna membuka berkas, misalnya dokumen Office bermakro [S8]; di v20 teknik ini berada di taktik Execution, versi 1.6, detection strategy DET0294 [S8]. Gabungan keduanya terlihat di telemetri sebagai aplikasi Office yang menjadi parent dari binary proxy. Sub-teknik rundll32 (.011) dan mshta (.005) dipetakan di Day 13 bagian 1.3.

Usulan deteksi dari laporan hunt, ditulis ulang dalam format abstract deteksi:

```
Usulan deteksi : JAB - Office meluncurkan signed proxy binary
Asal           : HUNT-2027-023 (tidak terbukti), selesai Kamis 2027-03-11 13:00
Tujuan         : Alert saat aplikasi Office langsung memunculkan regsvr32, rundll32, atau mshta
                 (termasuk salinan yang diganti nama), pola dokumen atau lampiran yang menjalankan kode
ATT&CK (v20)   : T1218.010, T1218.011, T1218.005 (Stealth); T1204.002 (Execution)
Data dan field : index=sysmon EID 1: host, User, ParentImage, Image, OriginalFileName, CommandLine,
                 ProcessGuid, Hashes
Logika kasar   : ParentImage berakhiran salah satu dari 8 aplikasi Office (daftar tahap A)
                 DAN (Image berakhiran regsvr32/rundll32/mshta ATAU OriginalFileName salah satunya)
                 KECUALI Outlook + url.dll,FileProtocolHandler https://...
                 KECUALI Outlook + shell32.dll,OpenAs_RunDLL + \INetCache\Content.Outlook\
Level (PEAK)   : Signatures & rules; urgensi tinggi
Volume dari hunt: Februari 76 mentah (71 FileProtocolHandler https di 39 host, 5 OpenAs_RunDLL di 5 host),
                 0 setelah pengecualian
Contoh positif : VM lab jab-lab-win11 Kamis 2027-03-11: Word -> regsvr32 scriptlet (tertangkap tahap A)
FP diketahui   : dua pola di atas; regsvr32 add-in VidMeet bukan dari Office (parent vidmeetupdate.exe)
Celah          : 229 workstation tanpa Sysmon; JKT-WS-0532 (Sysmon diam sejak 2027-02-02 10:14);
                 rantai dengan perantara (Office -> cmd -> regsvr32); proxy binary lain (msiexec, cmstp)
Triage         : lihat bagian 2.6
```

Draf rule Sigma dari usulan di atas, disimpan di `jab-detections/rules/windows/process_creation/jab_office_signed_proxy_binary.yml`:

```yaml
title: JAB - Office meluncurkan signed proxy binary
id: 3b7d9e42-6c1a-4f8e-9d25-7a0c4e1b58f3
status: experimental
description: |
    Mendeteksi aplikasi Office yang langsung memunculkan regsvr32, rundll32, atau mshta,
    termasuk salinan yang diganti nama (dicocokkan lewat OriginalFileName).
    Pola dokumen atau lampiran yang menjalankan kode lewat binary bertanda tangan Microsoft.
references:
    - jab-hunt/hunts/HUNT-2027-023/report.md
author: Program hunt PT JAB
date: 2027-03-16
tags:
    - attack.execution
    - attack.stealth
    - attack.t1204.002
    - attack.t1218.005
    - attack.t1218.010
    - attack.t1218.011
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith:
            - '\WINWORD.EXE'
            - '\EXCEL.EXE'
            - '\POWERPNT.EXE'
            - '\OUTLOOK.EXE'
            - '\ONENOTE.EXE'
            - '\MSACCESS.EXE'
            - '\MSPUB.EXE'
            - '\VISIO.EXE'
    selection_child_img:
        Image|endswith:
            - '\regsvr32.exe'
            - '\rundll32.exe'
            - '\mshta.exe'
    selection_child_ofn:
        OriginalFileName:
            - 'REGSVR32.EXE'
            - 'RUNDLL32.EXE'
            - 'MSHTA.EXE'
    filter_main_outlook_fph:
        ParentImage|endswith: '\OUTLOOK.EXE'
        CommandLine|contains: '\url.dll,FileProtocolHandler https://'
    filter_main_outlook_openas:
        ParentImage|endswith: '\OUTLOOK.EXE'
        CommandLine|contains|all:
            - 'shell32.dll,OpenAs_RunDLL'
            - '\INetCache\Content.Outlook\'
    condition: selection_parent and 1 of selection_child_* and not 1 of filter_main_*
falsepositives:
    - Outlook membuka tautan web di browser lewat url.dll FileProtocolHandler (dikecualikan filter_main_outlook_fph)
    - Dialog Open With untuk lampiran berekstensi tidak dikenal dari folder sementara Outlook (dikecualikan filter_main_outlook_openas)
level: high
origin_hunt: HUNT-2027-023
```

Cara membacanya:

- `selection_parent` adalah satu field dengan daftar nilai, jadi dibaca "ParentImage berakhiran WINWORD ATAU EXCEL ATAU ... VISIO". Daftar delapan aplikasi sama dengan daftar tahap A `HUNT-2027-023`, sehingga cakupan rule sama dengan cakupan yang sudah diukur. Outlook sengaja masuk, berbeda dengan rule SigmaHQ (bagian 1.5), karena di PT JAB Outlook adalah satu-satunya parent Office yang benar-benar memunculkan proxy binary.
- `selection_child_img` dan `selection_child_ofn` dipecah menjadi dua selection lalu dirangkai dengan `1 of selection_child_*`. Hasilnya "Image cocok ATAU OriginalFileName cocok", cara Sigma menyatakan OR antar field. `OriginalFileName` ikut dipakai karena field itu diambil dari metadata PE, sehingga binary yang di-rename (misalnya `regsvr32.exe` disalin menjadi `update.exe`) tetap tertangkap (Day 13 bagian 1.5).
- Dua `filter_main_*` adalah pengecualian dari hunt, masing-masing kombinasi parent, fungsi, dan bentuk argumen, bukan host atau pengguna. Nama `filter_main_` dipakai karena keduanya perilaku bawaan Outlook dan Windows [S14].
- `condition` merangkai ketiganya: parent Office, salah satu child, dan bukan salah satu filter.
- `id` adalah UUID versi 4 yang dibuat sekali dan tidak pernah diganti, supaya rule bisa dilacak walaupun judulnya berubah. UUID di contoh ini fiktif.
- `status: experimental` karena rule belum diuji dalam bentuk akhirnya. Status naik setelah bagian 2.4.
- `origin_hunt` adalah field kustom di tingkat atas yang dipakai untuk metrik jembatan. Cek apakah validator `sigma check` di versi-mu memberi peringatan untuk field kustom; peringatan seperti itu tidak menggagalkan check secara default [S22].
- Nilai Sigma tidak peka huruf, jadi `'\WINWORD.EXE'` juga cocok dengan `winword.exe` [S1].

**Kapan gagal:** filter ditulis dengan `contains` atas string yang bisa disisipkan penyerang. Command line yang memuat `\url.dll,FileProtocolHandler https://` di bagian mana pun lolos filter pertama, termasuk command line yang memanggil DLL lain lebih dulu lalu menempelkan string itu sebagai argumen. Celah ini ditulis di blind spot handover dan masuk backlog (bagian 2.7); rule kedua (scriptlet dan skrip inline) tetap menangkap varian yang membawa `scrobj`, `javascript:`, `vbscript:`, atau `about:`.

### 2.3 Konversi ke SPL dengan sigma-cli

Langkah ini adalah bagian kedua jawaban pertanyaan kelima Sari. Konversi dijalankan oleh pipeline GitLab `jab-detections` dan juga bisa diulang di laptop analyst; yang dibahas di sini adalah dua kali konversi, yang pertama salah dengan cara yang tidak terlihat.

**Tujuan:** menghasilkan SPL yang cocok dengan cara Sysmon di-onboard di PT JAB, lalu membandingkannya dengan query hunt.

Persiapan sekali (di lingkungan Python tersendiri, misalnya virtualenv di laptop analyst atau runner CI):

```
python -m pip install sigma-cli
sigma plugin install splunk
sigma plugin install sysmon
sigma list pipelines
sigma check rules/
```

- `sigma plugin install` memasang backend dan pipeline sebagai plugin [S2]. `sigma list pipelines` memastikan `sysmon`, `splunk_windows`, `splunk_sysmon_acceleration`, dan `splunk_cim` tersedia [S20].
- `sigma check` gagal bila ada error parsing atau condition, dan hanya mencetak isu validator kecuali diberi `--fail-on-issues`; opsi `--junitxml` menulis hasil untuk laporan CI [S22].

**Konversi pertama, memakai pipeline bawaan:**

```
sigma convert -t splunk -p sysmon -p splunk_windows \
    rules/windows/process_creation/jab_office_signed_proxy_binary.yml
```

Keluaran ilustrasi (dirapikan menjadi beberapa baris):

```
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
ParentImage IN ("*\\WINWORD.EXE", "*\\EXCEL.EXE", "*\\POWERPNT.EXE", "*\\OUTLOOK.EXE",
                "*\\ONENOTE.EXE", "*\\MSACCESS.EXE", "*\\MSPUB.EXE", "*\\VISIO.EXE")
(Image IN ("*\\regsvr32.exe", "*\\rundll32.exe", "*\\mshta.exe")
 OR OriginalFileName IN ("REGSVR32.EXE", "RUNDLL32.EXE", "MSHTA.EXE"))
NOT ((ParentImage="*\\OUTLOOK.EXE" CommandLine="*\\url.dll,FileProtocolHandler https://*")
     OR (ParentImage="*\\OUTLOOK.EXE" CommandLine="*shell32.dll,OpenAs_RunDLL*"
         CommandLine="*\\INetCache\\Content.Outlook\\*"))
```

**Cara membaca hasil:** sintaksnya benar, dan `EventCode=1` sudah benar karena `splunk_windows` mengganti `EventID` menjadi `EventCode` [S20]. Yang salah adalah baris pertama: pipeline membangun `source` dengan awalan `WinEventLog:` [S20], sedangkan Sysmon PT JAB ber-`source` `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`. Dijalankan atas Februari di `jkt-splunk-sh01`, query ini mengembalikan 0 event, termasuk 0 untuk 76 eksekusi Outlook yang seharusnya terlihat sebelum filter. Nol yang ini bukan bukti rule bagus; itu bukti rule buta. Cek ini sengaja dijalankan dengan filter dihapus dulu: query tanpa blok `NOT` harus mengembalikan 76.

**Konversi kedua, memakai pipeline PT JAB.** Berkas `jab-detections/pipelines/jab_splunk_sysmon.yml`:

```yaml
name: JAB Splunk Sysmon
priority: 100
transformations:
  - id: jab_eventcode
    type: field_name_mapping
    mapping:
      EventID: EventCode
    rule_conditions:
      - type: logsource
        service: sysmon
  - id: jab_index_sysmon
    type: add_condition
    conditions:
      index: sysmon
      sourcetype: XmlWinEventLog
    rule_conditions:
      - type: logsource
        service: sysmon
```

| Bagian | Fungsi |
|---|---|
| `priority: 100` | Dijalankan setelah pipeline `sysmon` (prioritas 5), yang lebih dulu mengubah logsource menjadi `service: sysmon` dan menambah `EventID=1` [S21] |
| `field_name_mapping` `EventID: EventCode` | Nama field event ID di Splunk PT JAB [S23] |
| `add_condition` | Menambah `index=sysmon sourcetype=XmlWinEventLog` ke setiap rule Sysmon, menggantikan kondisi `source` dari `splunk_windows`. Nama parameter `conditions` perlu dicek di dokumentasi `AddConditionTransformation` versi pySigma-mu |
| `rule_conditions` `service: sysmon` | Transformasi hanya berlaku untuk rule yang logsource-nya sudah menjadi Sysmon [S23] |

```
sigma convert -t splunk -p sysmon -p pipelines/jab_splunk_sysmon.yml \
    rules/windows/process_creation/jab_office_signed_proxy_binary.yml
```

Keluaran ilustrasi:

```
index="sysmon" sourcetype="XmlWinEventLog" EventCode=1
ParentImage IN ("*\\WINWORD.EXE", "*\\EXCEL.EXE", "*\\POWERPNT.EXE", "*\\OUTLOOK.EXE",
                "*\\ONENOTE.EXE", "*\\MSACCESS.EXE", "*\\MSPUB.EXE", "*\\VISIO.EXE")
(Image IN ("*\\regsvr32.exe", "*\\rundll32.exe", "*\\mshta.exe")
 OR OriginalFileName IN ("REGSVR32.EXE", "RUNDLL32.EXE", "MSHTA.EXE"))
NOT ((ParentImage="*\\OUTLOOK.EXE" CommandLine="*\\url.dll,FileProtocolHandler https://*")
     OR (ParentImage="*\\OUTLOOK.EXE" CommandLine="*shell32.dll,OpenAs_RunDLL*"
         CommandLine="*\\INetCache\\Content.Outlook\\*"))
```

Dijalankan atas Februari tanpa blok `NOT`: 76 event, sama dengan tahap A hunt. Kesetaraan itu yang membuktikan konversi benar, bukan tidak adanya error.

**Membandingkan dengan query hunt.** Tabel ini membandingkan hasil konversi dengan query tahap A Day 13 bagian 2.2; baris "Hasil" adalah alasan keduanya boleh berbeda bentuk.

| Aspek | Query hunt tahap A | SPL hasil konversi |
|---|---|---|
| Parent | `where match(parent, ...)` atas `lower(ParentImage)` | `ParentImage IN ("*\\WINWORD.EXE", ...)` di search, tanpa peka huruf |
| Child | `Image` atau `OriginalFileName` di base search | Sama, dari dua selection |
| Pengecualian | Tidak ada; hunter melabeli 71 + 5 | Dua kombinasi di blok `NOT` |
| Hasil | `stats` per pasangan parent dan child | Satu baris per event |
| Rentang | Februari penuh, absolut | Ditambahkan di ES sebagai jendela berjeda |

**Menjadi detection ES.** Hasil konversi ditempel ke event-based detection "JAB - Office meluncurkan signed proxy binary" di `jkt-splunk-es01`, dengan tambahan baris untuk L1:

```
<SPL hasil konversi kedua>
| eval pname=mvindex(split(ParentImage, "\\"), -1), cname=mvindex(split(Image, "\\"), -1)
| rename host AS dest, User AS user
| table _time dest user pname cname OriginalFileName CommandLine ParentCommandLine ProcessGuid Hashes
```

Jadwal: cron `*/15 * * * *`, earliest `-25m@m`, latest `-10m@m`. Run pukul 09:15 membaca 08:50 sampai 09:05, run 09:30 membaca 09:05 sampai 09:20: jendela 15 menit yang bersambung tanpa celah dan tanpa tumpang tindih, berjeda 10 menit. Satu run atas jendela 15 menit selesai sekitar 1,9 detik (keluaran ilustrasi Job Inspector), sehingga tidak menambah beban berarti di search head yang pernah mengalami skipped search (Day 06 bagian 2.7).

**Variasi:**

- **Waktu index untuk host yang terlambat mengirim.** Laptop yang offline lalu tersambung mengirim event dengan `_time` lama, yang sudah lewat jendela. Bentuk `earliest=-24h latest=now _index_earliest=-25m@m _index_latest=-10m@m` memilih event berdasarkan kapan event itu masuk index, sambil tetap membatasi `_time` ke 24 jam. Biayanya scan yang lebih lebar; pakai untuk detection yang sumbernya banyak laptop.
- **Format `data_model`.** `sigma convert -t splunk -p splunk_cim -f data_model rule.yml` menghasilkan `tstats` atas `Endpoint.Processes` [S20]. Berguna bila data model Endpoint terakselerasi di ES, tetapi cek pemetaan `OriginalFileName` dan `ParentImage` ke field CIM di keluaran sebelum dipakai.
- **Format `savedsearches`.** `-f savedsearches -o savedsearches.conf` menghasilkan stanza saved search [S2]; berguna untuk lab tanpa ES.
- **Padanan Wazuh (untuk lab-mu).** Di PT JAB, Wazuh hanya memantau server Linux, jadi rule ini tidak dipasang di sana. Untuk lab yang mengirim Sysmon ke Wazuh, padanannya ditulis manual di `local_rules.xml` [S9]:

```xml
<group name="sysmon,hunt_origin,">
  <rule id="100210" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.parentImage" type="pcre2">(?i)\\(winword|excel|powerpnt)\.exe$</field>
    <field name="win.eventdata.image" type="pcre2">(?i)\\(regsvr32|rundll32|mshta)\.exe$</field>
    <description>Office meluncurkan signed proxy binary: $(win.eventdata.image)</description>
    <mitre>
      <id>T1218.010</id>
      <id>T1204.002</id>
    </mitre>
  </rule>
</group>
```

- `if_group` membuat rule ini hanya dievaluasi untuk event yang sudah diklasifikasi sebagai Sysmon event 1 oleh ruleset bawaan; cek nama group itu di ruleset versi-mu.
- Dua elemen `field` dibaca AND. `(?i)` membuat regex tidak peka huruf besar kecil, menyamai perilaku Sigma.
- Versi ini belum memakai `originalFileName`. Tambahkan rule kedua dengan `win.eventdata.originalFileName` agar binary yang di-rename juga tertangkap; satu rule Wazuh tidak bisa menyatakan "field A cocok ATAU field B cocok" dengan dua elemen `field`.
- ID rule kustom Wazuh memakai rentang 100000 sampai 120000 supaya tidak bentrok dengan ruleset bawaan [S9].

**Kapan gagal:** pipeline tidak cocok dengan onboarding (konversi pertama di atas); hasil konversi tidak memuat `index=` sehingga search membaca index default role; bentuk keluaran berubah antar versi backend; atau SPL hasil konversi diedit langsung di ES, sehingga rule di repo dan rule yang berjalan tidak lagi sama. Perubahan selalu masuk lewat Sigma, lalu dikonversi ulang.

### 2.4 Menguji dengan contoh positif lab dan data Februari PT JAB

Langkah ini menjawab pertanyaan ketujuh Sari untuk contoh pertama. Rencananya diturunkan dari bagian 1.8; tabel berikut menunjukkan setiap uji dan hasil yang diharapkan, dan baris emulasi parent shell adalah jebakan yang sering membuat orang mengira rule rusak.

| Uji | Input | Hasil yang diharapkan |
|---|---|---|
| TP dari uji lab Day 13 | Event Sysmon EID 1 regsvr32 dari WINWORD dengan scrobj (`jab-lab-win11`, Kamis 2027-03-11) | Rule memicu |
| Positif baru: rundll32 | Harness makro yang sama, perintah diganti perintah T1218.011 test 2 (VBScript tanpa unduhan) | Rule memicu |
| Positif baru: rename | Harness makro yang sama, memanggil salinan `regsvr32.exe` yang diganti nama `C:\Users\Public\svchelper.exe` dengan scriptlet lokal | Rule memicu lewat `OriginalFileName` |
| FP dari hunt | Outlook lab membuka tautan `https://` dari email | Tidak memicu (filter) |
| Emulasi regsvr32 dari shell | Atomic Red Team T1218.010 test 1 (scriptlet COM lokal), dijalankan dari shell | Tidak memicu, karena parent-nya bukan Office |
| Goodlog | Satu hari log VM lab yang dipakai normal (Office dibuka, dokumen diedit) | Nol kecocokan |
| Negatif PT JAB | Februari 2027 penuh, 214 host | 0 setelah pengecualian dari 76 mentah |
| Data setelah hunt | 1 sampai 15 Maret 2027 | 0 atau pola jinak baru yang harus dijelaskan |

Baris emulasi dari shell perlu dijelaskan. Tes Atomic untuk T1218.010 menjalankan regsvr32 dari Command Prompt, memuat scriptlet `.sct` lewat `scrobj.dll`, lalu memunculkan `calc.exe` [S11]. Di Sysmon EID 1 kamu akan melihat `Image` berakhiran `regsvr32.exe`, `ParentImage` berupa shell (`cmd.exe`, atau PowerShell yang menjalankan test itu, seperti urutan 3 di Day 13 bagian 2.4), dan `CommandLine` memuat `scrobj.dll` serta jalur `.sct`. Karena parent-nya bukan Office, rule ini memang tidak boleh memicu. Hasil itu justru membuktikan dua hal: rule-mu spesifik ke prosedur parent Office, dan prosedur "regsvr32 dengan scrobj dari parent apa pun" harus ditutup rule lain. Di PT JAB rule lain itu sudah ada di tumpukan: "JAB - Proxy binary dengan scriptlet atau skrip inline", yang memang menangkap urutan 3 dan 4 di uji lab Day 13.

**Tujuan uji positif:** menjalankan SPL hasil konversi atas data lab (dua test lama dan tiga test baru) dan memastikan tiga yang semestinya tertangkap muncul.

Test baru dijalankan Selasa 2027-03-16 pukul 10:00 sampai 10:40 di VM `jab-lab-win11` (jaringan lab SOC terisolasi, snapshot bersih, konfigurasi Sysmon sama dengan profil `Workstations-EDR`), mengirim ke Splunk lab `jab-lab-splunk01`. Data uji Kamis masih ada di index lab. Tidak ada test yang dijalankan di host PT JAB.

```
index=sysmon sourcetype=XmlWinEventLog EventCode=1 host=jab-lab-win11
    earliest="03/11/2027:10:00:00" latest="03/16/2027:11:00:00"
    <kondisi hasil konversi kedua, tanpa index dan sourcetype>
| eval pname=mvindex(split(ParentImage, "\\"), -1), cname=mvindex(split(Image, "\\"), -1)
| table _time host pname cname OriginalFileName CommandLine
| sort _time
```

- Base search sama dengan detection, ditambah `host=jab-lab-win11` dan rentang absolut yang mencakup kedua sesi uji.
- `split(ParentImage, "\\")` memecah path di setiap backslash; di string SPL `"\\"` adalah satu backslash. `mvindex(..., -1)` mengambil nama file.

Keluaran ilustrasi (kolom keterangan ditambahkan dari catatan uji, bukan dari Splunk):

```
_time                host           pname        cname          OriginalFileName  keterangan
2027-03-11 10:41:07  jab-lab-win11  WINWORD.EXE  regsvr32.exe   REGSVR32.EXE      urutan 2 uji Day 13
2027-03-16 10:12:44  jab-lab-win11  WINWORD.EXE  rundll32.exe   RUNDLL32.EXE      positif baru: rundll32
2027-03-16 10:24:19  jab-lab-win11  WINWORD.EXE  svchelper.exe  REGSVR32.EXE      positif baru: rename
```

**Cara membaca hasil:** tiga dari tiga uji positif tertangkap, termasuk salinan yang diganti nama, yang hanya tertangkap lewat `selection_child_ofn`. Yang tidak muncul juga sesuai rencana: Word ke `cmd.exe` (urutan 1 Day 13; ditangani sinyal risk Office ke shell), regsvr32 dan mshta dari PowerShell (urutan 3 sampai 5; ditangani rule scriptlet/inline), dan Outlook membuka tautan `https://` (filter). Goodlog Senin 2027-03-15 08:00 sampai 17:00 di VM yang sama: 0.

**Tujuan uji negatif:** menghitung, atas data PT JAB, berapa event yang cocok sebelum filter, berapa yang dikecualikan tiap filter, dan berapa yang akan menjadi alert.

```
index=sysmon sourcetype=XmlWinEventLog EventCode=1
    earliest="02/01/2027:00:00:00" latest="03/01/2027:00:00:00"
    (ParentImage="*\\WINWORD.EXE" OR ParentImage="*\\EXCEL.EXE" OR ParentImage="*\\POWERPNT.EXE"
     OR ParentImage="*\\OUTLOOK.EXE" OR ParentImage="*\\ONENOTE.EXE" OR ParentImage="*\\MSACCESS.EXE"
     OR ParentImage="*\\MSPUB.EXE" OR ParentImage="*\\VISIO.EXE")
    (Image="*\\regsvr32.exe" OR Image="*\\rundll32.exe" OR Image="*\\mshta.exe"
     OR OriginalFileName IN ("REGSVR32.EXE", "RUNDLL32.EXE", "MSHTA.EXE"))
| eval p=lower(ParentImage), cmd=lower(CommandLine)
| eval hasil=case(like(p, "%\\outlook.exe") AND like(cmd, "%\\url.dll,fileprotocolhandler https://%"),
                  "filter_main_outlook_fph",
                  like(p, "%\\outlook.exe") AND like(cmd, "%shell32.dll,openas_rundll%")
                      AND like(cmd, "%\\inetcache\\content.outlook\\%"),
                  "filter_main_outlook_openas",
                  true(), "ALERT")
| stats count AS events dc(host) AS hosts BY hasil
```

| Bagian | Fungsi |
|---|---|
| Base search tanpa blok `NOT` | Semua yang cocok selection, supaya angka sebelum filter terlihat (76 menurut hunt) |
| `eval p=lower(...), cmd=lower(...)` | `like()` peka huruf, tidak seperti pencocokan nilai di `search` dan di Sigma |
| `like(cmd, "%\\url.dll,...%")` | Meniru `contains` Sigma. Di string SPL `\\` adalah satu backslash; di `like()` hanya `%` dan `_` yang istimewa, jadi garis bawah di `openas_rundll` cocok dengan karakter apa pun, termasuk garis bawah itu sendiri |
| `case(..., true(), "ALERT")` | Label per event: filter mana yang mengecualikannya, atau ALERT bila tidak ada |
| `stats ... BY hasil` | Satu baris per label |

Keluaran ilustrasi, Februari:

```
hasil                        events  hosts
filter_main_outlook_fph          71     39
filter_main_outlook_openas        5      5
```

Tidak ada baris ALERT karena `stats` tidak menampilkan kelompok yang kosong: Februari menghasilkan 0 alert, sama dengan angka setelah pengecualian di laporan hunt. Query yang sama dijalankan untuk Senin 2027-03-01 00:00 sampai Selasa 2027-03-16 00:00 (`earliest="03/01/2027:00:00:00" latest="03/16/2027:00:00:00"`):

```
hasil                        events  hosts
filter_main_outlook_fph          38     27
ALERT                             2      2
```

Dua baris ALERT adalah `OUTLOOK.EXE` ke `rundll32.exe url.dll,FileProtocolHandler http://...` di `JKT-WS-0403` (`yuni.astuti`) dan `JKT-WS-0466` (`lestari.putri`), Customer Service, Selasa 2027-03-09: tautan `http://` di newsletter vendor yang dibuka ke browser. Fungsinya sama dengan 71 kejadian `https://` (membuka browser), hanya skemanya yang berbeda. Penyesuaiannya:

- Filter diperluas menjadi dua nilai, `\url.dll,FileProtocolHandler https://` dan `\url.dll,FileProtocolHandler http://`, karena alasannya fungsi, bukan host atau pengguna.
- Logika tidak diubah lebih jauh. Pengecualian per host Customer Service akan membutakan rule tepat di host yang paling sering membuka lampiran.

Setelah penyesuaian, Februari tetap 0 dan 1 sampai 15 Maret menjadi 0. Volume yang diharapkan: kurang dari satu alert per bulan. Rule dikonversi ulang, `modified: 2027-03-16` ditambahkan, dan `status` naik dari `experimental` ke `test`.

Event lab (tiga positif, satu FP lab) dan dua event `http://` dari PT JAB yang dianonimkan disimpan sebagai fixture di `jab-detections/tests/jab_office_signed_proxy_binary/`, supaya setiap perubahan rule berikutnya diuji ulang otomatis.

**Variasi:** ulangi uji positif dengan `mshta.exe` sebagai child langsung dari Word, untuk menutup cabang ketiga `selection_child_img`; dan ulangi uji negatif atas rentang 90 hari bila data model Endpoint terakselerasi (summary range `Endpoint` 90 hari, Day 06), dengan format `data_model`.

**Kapan gagal:** uji negatif hanya dijalankan atas rentang yang sama dengan hunt, sehingga pola jinak baru (seperti `http://` di Maret) baru ditemukan L1 setelah rule aktif; uji positif dijalankan di VM dengan konfigurasi Sysmon berbeda dari produksi; atau angka 0 diterima tanpa memastikan query tanpa filter mengembalikan angka mentah yang benar.

### 2.5 Dari `HUNT-2027-020` ke sinyal risk

Contoh utama kedua menjawab pertanyaan keenam Sari. Usulan "JAB - Beacon ke domain baru (risk)" dari Day 12 bagian 2.7 sudah menyebut logika, skor, jadwal, dan ambang alert; hari ini usulan itu diubah menjadi dua detection ES dan diuji dengan replay.

Kenapa bukan alert langsung, dalam satu kalimat dari data: dalam 28 hari hunt, satu-satunya pasangan yang memenuhi logika ini adalah aplikasi papan proyek sah yang baru dipasang di dua workstation Marketing. Sebagai alert, pola ini hampir selalu menghasilkan tiket jinak; sebagai sinyal risk, ia diam sampai ada sinyal kedua di entitas yang sama. Teknik yang dicakup tetap T1071 (Application Layer Protocol), yang mencakup C2 lewat protokol aplikasi umum seperti HTTP, HTTPS, atau DNS supaya menyatu dengan trafik normal [S12]; karena itu satu koneksi teratur tidak cukup sebagai bukti.

**Tujuan:** search harian yang menghasilkan risk event untuk pasangan `src` dan `dest` berpola beacon ke tujuan yang baru terlihat, dengan ambang yang diskalakan dari hunt 28 hari ke jendela 7 hari.

**Menyesuaikan ambang dari hunt ke detection.** Hunt `HUNT-2027-020` memakai `conns >= 20 AND hours_seen >= 12` atas 28 hari. Beacon tiap 4 jam di workstation yang menyala sekitar 9 jam per hari kerja menghasilkan 2 sampai 3 koneksi per hari, atau 10 sampai 15 dalam lima hari kerja (Day 12 bagian 1.4). Ambang 20 dalam 7 hari akan membutakan beacon itu, sehingga detection memakai `conns >= 10 AND hours_seen >= 6`. Syarat tambahan `intervals >= 6` (jumlah interval setelah jeda dibuang) mencegah CV dihitung dari dua atau tiga interval saja. Ambang keteraturan tidak berubah: CV maksimal 0,2 setelah jeda lebih dari tiga kali median dibuang, interval median 30 detik sampai 4 jam, `dest_hosts` maksimal 10.

Search detection "JAB - Beacon ke domain baru (risk)", dijadwalkan harian 02:00 di `jkt-splunk-es01`:

```
index=proxy sourcetype=squid:access earliest=-7d@d latest=@d
    (src=10.10.0.0/16 OR src=10.30.0.0/16)
| lookup jab_hunt_baseline_beacon.csv dest OUTPUT owner
| where isnull(owner)
| lookup jab_hunt_baseline_dest.csv dest OUTPUT first_seen AS dest_first_seen
| where isnull(dest_first_seen) OR dest_first_seen >= relative_time(now(), "-14d@d")
| eventstats dc(src) AS dest_hosts BY dest
| where dest_hosts <= 10
| eval start=_time-(duration/1000)
| bin span=1h start AS hour
| eventstats count AS conns dc(hour) AS hours_seen BY src dest
| where conns >= 10 AND hours_seen >= 6
| sort 0 src dest start
| streamstats current=f last(start) AS prev_start BY src dest
| eval delta=start-prev_start
| where isnotnull(delta)
| eventstats median(delta) AS med_int BY src dest
| where delta <= 3*med_int
| stats count AS intervals avg(delta) AS avg_int stdev(delta) AS sd_int max(med_int) AS med_int
        max(conns) AS conns max(hours_seen) AS hours_seen max(dest_hosts) AS dest_hosts
        max(dest_first_seen) AS dest_first_seen BY src dest
| eval cv=round(sd_int/avg_int, 3)
| where intervals >= 6 AND med_int >= 30 AND med_int <= 14400 AND cv <= 0.2
| eval dest_first_seen=strftime(dest_first_seen, "%Y-%m-%d")
| eval risk_message="Beacon teratur ke tujuan baru ".dest." dari ".src." (interval ".med_int." s, CV ".cv.")"
```

| Bagian | Fungsi |
|---|---|
| `earliest=-7d@d latest=@d` | Rentang relatif yang benar untuk search terjadwal atas data live: tujuh hari penuh sampai tengah malam. Untuk backtest, diganti rentang absolut (di bawah) |
| `lookup jab_hunt_baseline_beacon.csv ... where isnull(owner)` | Tujuan polling yang sudah dikonfirmasi pemiliknya tidak pernah diberi skor |
| `where isnull(dest_first_seen) OR dest_first_seen >= ...` | Hanya tujuan yang pertama terlihat dalam 14 hari. Cabang `isnull` penting: baseline tujuan baru diperbarui 02:30, setelah search ini jalan, sehingga tujuan yang pertama muncul kemarin belum ada di lookup. Tanpa cabang itu, tujuan paling baru justru terbuang |
| `eventstats dc(src) AS dest_hosts BY dest` | Prevalence tujuan dalam jendela; tujuan yang dihubungi lebih dari 10 sumber dibuang |
| `bin span=1h start AS hour` lalu `eventstats ... BY src dest` | Jumlah koneksi dan jam berbeda dihitung sebelum jeda dibuang, sehingga ambang 10 dan 6 mengukur aktivitas, bukan sisa interval |
| `streamstats` sampai `where delta <= 3*med_int` | Interval antar koneksi dengan jeda malam dan akhir pekan dibuang, sama dengan Day 05 bagian 2.2 |
| `where intervals >= 6 AND ... cv <= 0.2` | Ambang program untuk keteraturan, ditambah jumlah interval minimal |
| `risk_message` | Teks yang tampil di risk event; memuat tujuan, sumber, interval, dan CV untuk triage |

Pengaturan detection di ES (event-based detection, bagian 1.7):

```
Nama          : JAB - Beacon ke domain baru (risk)
Jadwal        : cron 0 2 * * *  (harian 02:00), membaca 7 hari penuh sebelum hari ini
Risk modifier : entitas src, tipe system, skor 30, keluaran Intermediate Findings
Threat object : dest (tipe domain)
ATT&CK        : T1071.001
Throttling    : per src, dest selama 14 hari
Asal          : HUNT-2027-020 (Day 12)
```

Throttling 14 hari per `src` dan `dest` perlu karena search membaca 7 hari dan jalan setiap hari: tanpa throttling, pasangan yang sama memberi skor setiap pagi selama tujuannya masih "baru", dan satu aplikasi sah bisa menumpuk skor 30 berkali-kali. Angka 14 sama dengan jendela "tujuan baru", sehingga satu pasangan diberi skor sekali selama tujuannya masih baru. Cek nama opsi throttling atau suppression di editor detection ES 8.x-mu.

Sinyal kedua, "JAB - Unggahan besar ke tujuan baru (risk)", dibangun dari logika Day 12 bagian 2.5 dengan bentuk yang sama: harian 02:00, membaca kemarin (`earliest=-1d@d latest=@d`), `sum(bytes_out)` per `src` dan `dest` lebih dari 10.485.760 byte ke tujuan yang `first_seen`-nya dalam 14 hari atau belum ada di lookup, entitas `src` tipe system, skor 30, Intermediate Findings, T1567 dan T1041, throttling 14 hari per `src` dan `dest`.

**Pengumpul: finding-based detection.** Ambang alert dari Day 12 ("minimal dua sinyal berbeda pada host yang sama dalam 7 hari") ditulis sebagai finding-based detection "JAB - Dua sinyal risk berbeda pada satu entitas dalam 7 hari". Logika setaranya dalam SPL, untuk memahami dan menguji:

```
| tstats summariesonly=false sum(All_Risk.calculated_risk_score) AS risk_score
        dc(source) AS sources values(source) AS source_list
    FROM datamodel=Risk.All_Risk
    WHERE earliest=-7d@h latest=now
    BY All_Risk.risk_object All_Risk.risk_object_type
| `drop_dm_object_name("All_Risk")`
| where sources >= 2
```

- `dc(source)` menghitung detection berbeda yang memberi skor, bukan jumlah skor. Dengan begitu satu detection yang menyala berkali-kali tidak bisa memicu pengumpul sendirian.
- `risk_score` tetap ditampilkan untuk konteks triage dan untuk ambang 24 jam bawaan ES.
- Nama field data model Risk dan macro `drop_dm_object_name` perlu dicek di ES-mu; di ES 8 pengumpul dibuat lewat editor finding-based detection, dan editor itulah yang menentukan apakah intermediate finding ikut dibaca [S25].

Skor 30 per sinyal dipilih supaya satu sinyal tidak pernah melewati ambang 24 jam bawaan sendirian; nilai ambang bawaan itu tidak disebut di dokumentasi yang diperiksa, jadi cek di instance PT JAB sebelum skor dipakai. Keluaran pengumpul berupa finding group untuk L1, severity medium.

**Backtest dengan replay.** Proxy disimpan 30 hari, sehingga pada 16 Maret data tersedia sejak sekitar 14 Februari. Baseline tujuan dibuat 9 Maret dari data sejak 9 Februari, sehingga setiap tujuan lama tercatat dengan `first_seen` 9 Februari dan tampak "baru" sampai 23 Februari. Replay karena itu dimulai dari run Rabu 2027-02-24 02:00 sampai run Selasa 2027-03-16 02:00: 21 run. Satu run replay ditulis dengan rentang absolut dan tanggal acuan tetap, misalnya run 24 Februari:

```
index=proxy sourcetype=squid:access
    earliest="02/17/2027:00:00:00" latest="02/24/2027:00:00:00"
    (src=10.10.0.0/16 OR src=10.30.0.0/16)
| lookup jab_hunt_baseline_beacon.csv dest OUTPUT owner
| where isnull(owner)
| lookup jab_hunt_baseline_dest.csv dest OUTPUT first_seen AS dest_first_seen
| where isnull(dest_first_seen) OR dest_first_seen >= strptime("2027-02-10", "%Y-%m-%d")
| ... (sisa search sama dengan detection)
```

- `relative_time(now(), "-14d@d")` diganti `strptime("2027-02-10", ...)`, yaitu 14 hari sebelum tanggal run. Tanpa penggantian itu, replay memakai "hari ini" sebagai acuan dan hasilnya salah.
- Replay memakai lookup per hari ini. Akibatnya `push.kanbanapp.example`, yang masuk `jab_hunt_baseline_beacon.csv` setelah ditutup 9 Maret, tidak lagi diberi skor; angka uji Day 12 (2 risk event dari pasangan itu) dihitung sebelum tujuan itu dikonfirmasi.

Keluaran ilustrasi replay (setelah throttling), digabung dari kedua sinyal:

```
run (02:00)  detection                                 src           dest                          skor
2027-02-27   JAB - Unggahan besar ke tujuan baru (risk)  10.10.22.71   efiling.taxportal.example       30
2027-03-04   JAB - Unggahan besar ke tujuan baru (risk)  10.30.14.22   eproc.clientportal.example      30
2027-03-05   JAB - Unggahan besar ke tujuan baru (risk)  10.10.48.33   support.routervendor.example    30
2027-03-06   JAB - Unggahan besar ke tujuan baru (risk)  10.10.51.18   transfer.agencyshare.example    30
2027-03-09   JAB - Unggahan besar ke tujuan baru (risk)  10.10.61.11   files.fiberplan.example         30
2027-03-09   JAB - Unggahan besar ke tujuan baru (risk)  10.10.61.14   files.fiberplan.example         30
2027-03-11   JAB - Beacon ke domain baru (risk)          10.10.36.64   api.weatherwidget.example       30
```

**Cara membaca hasil:**

- **Tujuh risk event dalam 21 run, nol finding untuk L1.** Enam unggahan adalah transfer yang sudah dijelaskan di Day 12 (pajak Keuangan, tender sales Bandung, tech-support NOC, agensi iklan Marketing, file vendor Network Planning). Tidak ada entitas dengan dua detection berbeda dalam 7 hari, jadi pengumpul diam sepanjang replay.
- **Satu beacon baru setelah hunt.** `10.10.36.64` ke `api.weatherwidget.example` tiap 1.800 detik, pertama terlihat Rabu 2027-03-10 09:05. IP itu dipetakan lewat MDE ke `JKT-WS-0664`, dan prosesnya widget cuaca desktop yang dipasang pengguna sendiri, bertanda tangan vendornya. Jinak; dicatat sebagai shadow IT ke IT dan tujuannya masuk `jab_hunt_baseline_beacon.csv`.
- **Hampir terjadi satu korelasi.** `10.10.51.18` (`JKT-WS-0388`) dengan daftar lookup lama akan memberi beacon `push.kanbanapp.example` pada run 24 Februari dan unggahan pada run 6 Maret. Jaraknya 10 hari, di luar 7 hari, sehingga tetap tidak menjadi finding. Contoh ini dipakai untuk menjelaskan ke L1 kenapa jendela pengumpul harus ditetapkan, bukan dibiarkan terbuka.
- **Volume yang diharapkan.** Sekitar 2 sampai 3 risk event per minggu dari kedua sinyal, dan finding pengumpul jarang. Risk event ditinjau hunter setiap Selasa sebagai bagian laporan mingguan, bukan oleh L1.

**Variasi:** tambahkan sinyal "JAB - Office memunculkan shell (risk)" (skor 20) ke pengumpul. Sinyal itu memakai entitas `dest` (nama host dari Sysmon), sedangkan dua sinyal proxy memakai `src` (IP). Tanpa pemetaan IP ke host, ketiganya tidak pernah bertemu di satu entitas; pemetaan itu masuk backlog telemetri (bagian 2.7).

**Kapan gagal:** throttling tidak dipasang sehingga satu aplikasi sah memberi skor setiap hari; baseline tujuan diperbarui sebelum risk search sehingga tujuan baru kemarin dianggap lama; IP sumber berganti karena DHCP di tengah jendela 7 hari, sehingga dua sinyal dari laptop yang sama jatuh ke dua entitas; pengumpul diberi ambang satu sinyal, sehingga risk event berubah menjadi alert biasa dengan nama lain; atau daftar tujuan dikenal tidak dirawat sehingga skor menumpuk di agent sah.

### 2.6 Format handover dan entri di ES

Artefak ini adalah jawaban akhir pertanyaan ketiga Sari: bentuk yang ia simpan untuk setiap detection yang diterima. Bedanya dengan abstract deteksi (bagian 2.2) adalah isi yang hanya diketahui setelah rule ditulis dan diuji: nama di ES, jadwal, entitas, hasil uji, tanggal aktif, dan tanggal review.

```
Nama ES        : JAB - Office meluncurkan signed proxy binary
Sigma          : jab-detections/rules/windows/process_creation/jab_office_signed_proxy_binary.yml
                 id 3b7d9e42-6c1a-4f8e-9d25-7a0c4e1b58f3, status test (sejak 2027-03-16), level high
origin_hunt    : HUNT-2027-023 (tidak terbukti), laporan Kamis 2027-03-11 13:00
Tujuan         : Office langsung memunculkan regsvr32/rundll32/mshta, termasuk salinan diganti nama
ATT&CK (v20)   : T1218.010, T1218.011, T1218.005 (Stealth); T1204.002 (Execution)
Data           : index=sysmon EID 1; pipeline konversi: sysmon + pipelines/jab_splunk_sysmon.yml
Cakupan        : 214 host ber-Sysmon. TIDAK mencakup 229 workstation tanpa Sysmon, JKT-WS-0532
                 selama Sysmon-nya diam, dan rantai dengan perantara (Office -> cmd -> regsvr32)
Pengecualian   : filter_main_outlook_fph (http:// dan https://, diperluas 2027-03-16);
                 filter_main_outlook_openas (folder sementara Outlook)
Volume         : Februari 0 dari 76 mentah; 1-15 Maret 2 sebelum penyesuaian, 0 setelahnya
Uji            : positif 3/3 (jab-lab-win11, 2027-03-11 dan 2027-03-16); FP lab tidak memicu;
                 emulasi T1218.010 dari shell tidak memicu (sesuai rancangan); goodlog 0; fixture di tests/
Jadwal ES      : cron */15 * * * *, earliest -25m@m, latest -10m@m
Output ES      : Finding pada dest (system) skor 60; Intermediate Findings pada user skor 60;
                 threat object CommandLine
Triage L1      : (1) buka dokumen induk dari ParentCommandLine dan asalnya (email, unduhan);
                 (2) lihat proses anak berikutnya dan koneksi keluar (EID 3, MDE);
                 (3) tanya pengguna apakah ia membuka lampiran itu; (4) eskalasi ke L2 bila tidak ada
                 penjelasan bisnis atau bila ada proses anak/koneksi keluar
Blind spot     : string pengecualian bisa disisipkan ke command line; proxy binary lain (msiexec,
                 cmstp, installutil) dari Office; COM tanpa proses anak
Pemilik        : Sari Kusuma (konten), <kamu> (hunter asal); review merge request: Dimas Prasetyo
Aktif di ES    : Rabu 2027-03-17 09:00 WIB
Review         : Rabu 2027-03-31: naik ke stable bila tidak ada FP yang belum tertangani dan tidak
                 ada run yang skipped
```

Cara membaca elemennya dari sisi Sari:

- **Cakupan** menulis tiga hal yang tidak ditangkap, supaya L1 dan Dimas tidak mengira semua workstation tertutup. Kalimat yang sama muncul di deskripsi detection di ES.
- **Volume** memuat angka setelah penyesuaian dan tanggalnya. Bila nanti volume naik, perbandingannya jelas.
- **Uji** menyebut emulasi yang sengaja tidak memicu. Tanpa baris itu, orang yang menjalankan test Atomic berikutnya akan mengira rule rusak.
- **Aktif di ES** dan **Review** adalah dua tanggal yang dipakai metrik jembatan (bagian 1.9).

Usulan dan handover disimpan di dua repo, dengan rujukan silang:

```
jab-hunt/handover/2027-03-16-office-signed-proxy-binary.md   (abstract deteksi, bagian 2.2)
jab-hunt/handover/2027-03-16-beacon-risk.md                  (abstract sinyal risk, bagian 2.5)
jab-detections/rules/windows/process_creation/jab_office_signed_proxy_binary.yml
jab-detections/pipelines/jab_splunk_sysmon.yml
jab-detections/tests/jab_office_signed_proxy_binary/          (fixture positif dan negatif)
jab-detections/docs/jab_office_signed_proxy_binary.md         (handover akhir di atas)
```

Setiap file usulan memakai struktur bagian 1.3. Di repo deteksi, usulan ini menjadi rule baru dengan dokumentasi ADS lengkap dan field `origin_hunt` (Day 15).

Handover untuk sinyal risk berbentuk sama, dengan tiga baris yang berbeda: Output ES (entitas `src`, skor 30, Intermediate Findings saja), Throttling (14 hari per `src` dan `dest`), dan Cakupan (proxy Jakarta dan Bandung saja; laptop di luar kantor lewat split tunnel dan POP tanpa proxy tidak terlihat, Day 12 bagian 1.8; pemetaan IP ke host belum ada).

**Kapan gagal:** handover ditulis setelah detection aktif, dari ingatan, sehingga baris Uji dan Volume berisi perkiraan; atau baris Review kosong, sehingga rule `test` tidak pernah naik ke `stable` dan tidak pernah ditinjau ulang.

### 2.7 Detection yang diterima, tanggal aktif, dan menutup loop ke backlog

Bagian ini menjawab bagian akhir pertanyaan ketujuh Sari: apa yang aktif, kapan, dan apa yang kembali ke hunter. Dimas mereview merge request `jab-detections` Rabu 2027-03-17 pukul 08:30 dan menyetujui semuanya; Sari mengaktifkan sepuluh detection ES pukul 09:00 dengan status `test` untuk yang berbasis Sigma. Volume setiap detection di bawah berasal dari bagian 2.1, 2.4, dan 2.5; yang di luar dua contoh utama diuji dengan cara yang sama tetapi lebih ringkas (backtest Februari dengan logika final dan satu uji positif di `jab-lab-win11`, misalnya Atomic T1105 test 7 sampai 9 untuk certutil dan bitsadmin seperti direncanakan Day 02).

Tabel ini adalah catatan untuk metrik jembatan. Baca kolom "Hari dari laporan", yaitu jarak antara laporan hunt asal dan aktif di produksi.

| Detection | Jenis | `origin_hunt` | Laporan hunt | Aktif | Hari dari laporan |
|---|---|---|---|---|---|
| JAB - Eksekusi biner dari folder temp (Wazuh 100200) | Alert Wazuh, level 10 | `HUNT-2027-010` | Selasa 2027-02-23 | Kamis 2027-02-25 malam | 2 |
| JAB - Script dari folder temp dijalankan interpreter (Wazuh 100201) | Alert Wazuh, level 10 | `HUNT-2027-010` | Selasa 2027-02-23 | Kamis 2027-02-25 malam | 2 |
| JAB - certutil atau bitsadmin mengunduh dari URL eksternal | Alert ES | `HUNT-2027-002` | Selasa 2027-02-02 | Rabu 2027-03-17 09:00 | 43 |
| JAB - Scheduled task menjalankan biner dari folder AppData pengguna | Alert ES (`related: merged` dengan usulan `HUNT-2027-004`) | `HUNT-2027-015` | Selasa 2027-03-02 | Rabu 2027-03-17 09:00 | 15 |
| JAB - Logon akun admin ke workstation dari host selain `JKT-JUMP01` | Alert ES | `HUNT-2027-019` | Kamis 2027-03-04 | Rabu 2027-03-17 09:00 | 13 |
| JAB - Office meluncurkan signed proxy binary | Alert ES | `HUNT-2027-023` | Kamis 2027-03-11 | Rabu 2027-03-17 09:00 | 6 |
| JAB - Proxy binary dengan scriptlet atau skrip inline | Alert ES | `HUNT-2027-023` | Kamis 2027-03-11 | Rabu 2027-03-17 09:00 | 6 |
| JAB - Script host menjalankan skrip dari Downloads, Temp, atau ekstraksi arsip | Alert ES | `HUNT-2027-025` | Kamis 2027-03-11 | Rabu 2027-03-17 09:00 | 6 |
| JAB - Office memunculkan shell (risk) | Risk ES, skor 20, entitas `dest` | `HUNT-2027-001` | Kamis 2027-02-04 | Rabu 2027-03-17 09:00 | 41 |
| JAB - Beacon ke domain baru (risk) | Risk ES, skor 30, entitas `src` | `HUNT-2027-020` | Selasa 2027-03-09 | Rabu 2027-03-17 09:00 | 8 |
| JAB - Unggahan besar ke tujuan baru (risk) | Risk ES, skor 30, entitas `src` | `HUNT-2027-022` | Selasa 2027-03-09 | Rabu 2027-03-17 09:00 | 8 |
| JAB - Dua sinyal risk berbeda pada satu entitas dalam 7 hari | Finding-based ES (pengumpul) | `HUNT-2027-020`, `-022` | Selasa 2027-03-09 | Rabu 2027-03-17 09:00 | 8 |

Rule Wazuh 100202 tidak dihitung sebagai detection karena isinya pengecualian (level 0). Dua usulan tunda punya syarat aktivasi yang dicatat di `jab-detections/docs/pending.md`: "JAB - Scheduled task dibuat dengan LogonType Password" setelah `svc_filesync` pindah ke gMSA, dan alert `OriginalFileName` atau lokasi salah setelah dua minggu berturut-turut 0 di laporan mingguan.

**Cara membaca hasil:** angka "Hari dari laporan" menunjukkan jembatan yang macet untuk usulan awal (41 dan 43 hari) dan lancar untuk usulan minggu ini (6 sampai 8 hari) setelah ada repo, pipeline konversi, dan format handover. Angka ini bahan Day 15; yang penting di sini adalah tanggalnya tercatat hari ini, bukan direkonstruksi minggu depan. Untuk layer ATT&CK Navigator kuartal ini, teknik yang kini punya detection karena hunt diberi komentar `origin=hunt HUNT-2027-NNN` [S10].

Menutup loop: hipotesis turunan dari detection hari ini masuk `jab-hunt/backlog/BACKLOG.md`, belum diberi nomor hunt karena belum dijadwalkan:

```
Masuk backlog (dari Day 14, Selasa 2027-03-16)
(a) Office -> perantara (cmd, powershell) -> proxy binary dalam beberapa detik
    Asal: blind spot "JAB - Office meluncurkan signed proxy binary"; T1218, T1204.002
    Data: Sysmon EID 1, korelasi ParentProcessGuid dua tingkat
(b) Proxy binary lain dari Office (msiexec, cmstp, installutil, regasm) yang ada di rule SigmaHQ
    tetapi tidak di rule PT JAB; ukur volume dulu
(c) Command line rundll32 dengan lebih dari satu "dll," (string pengecualian disisipkan)
    Asal: blind spot filter_main_outlook_fph
(d) Beacon ke tujuan berprevalence tinggi (dest_hosts > 10) yang ditumpangi penyerang
    Asal: di luar cakupan HUNT-2027-020 dan detection risk
(e) Abstract deteksi akses LSASS dari image tidak lazim (GrantedAccess, CallTrace, uji lab,
    cek tumpang tindih dengan alert MDE) -> dikembalikan dari triase Sari
```

Dua hal diserahkan ke luar backlog hunt: ke Agung Prabowo, permintaan pemetaan IP ke host harian (lookup dari sumber DHCP atau inventaris jaringan endpoint) supaya sinyal risk berbasis proxy dan berbasis Sysmon bisa bertemu di satu entitas; dan ke Sari sendiri, pengingat bahwa setiap perluasan Sysmon (rollout ke 229 workstation) mengubah volume semua detection berbasis Sysmon, sehingga backtest diulang setelah rollout.

Loop berlanjut: deteksi baru menutup satu prosedur, hipotesis baru mengejar prosedur dan celah berikutnya.

**Kapan gagal:** detection diaktifkan tanpa tanggal tercatat, sehingga waktu ke produksi tidak bisa dihitung; atau blind spot di handover tidak pernah dipindah ke backlog, sehingga hunter berikutnya mengulang pertanyaan yang sudah dijawab dan prosedur yang belum tertutup tetap terbuka.

### 2.8 Jawaban untuk Sari

Ringkasan berikut kamu kirim ke Sari Selasa pukul 17:00, bersama merge request `jab-detections` untuk direview Dimas. Setiap baris merujuk subbagian di atas.

| Pertanyaan Sari | Jawaban singkat | Dasar |
|---|---|---|
| Mana yang layak jadi detection | Enam alert, tiga sinyal risk, satu pengumpul; lima laporan dipindah ke hunter; dua tunda dengan syarat; satu ditolak; satu kembali ke backlog. Tambahan antrean L1 sekitar 3 per minggu | Bagian 1.1, 2.1 |
| Logika yang tidak cepat basi | Perilaku (TTP), bukan IOC; IOC `INC-2027-040` tetap di threat intelligence dengan masa berlaku | Bagian 1.2 |
| Isi usulan supaya tidak mengulang hunt | Abstract deteksi: volume mentah dan setelah pengecualian, FP terkonfirmasi, cakupan jujur, uji; setelah diterima, handover akhir dengan nama, jadwal, entitas, tanggal aktif, dan review | Bagian 1.3, 2.6 |
| Dari query sebulan ke rule 15 menit | Jendela berjeda 15 menit (`-25m@m` sampai `-10m@m`), pengecualian sempit dari hunt, ambang diskalakan ulang bila rentang berubah | Bagian 1.4, 2.3, 2.5 |
| Sigma dan konversi ke SPL | Ya: Sigma sebagai sumber, sigma-cli dengan pipeline `sysmon` plus pipeline PT JAB, karena `splunk_windows` menghasilkan `source` yang tidak cocok dengan onboarding kita | Bagian 1.5, 1.6, 2.2, 2.3 |
| Alert atau risk | Alert bila hampir setiap kecocokan layak diperiksa; risk bila sering jinak dan bermakna saat berkumpul, dengan pengumpul dua sinyal berbeda dalam 7 hari | Bagian 1.7, 2.5 |
| Uji dan pelacakan | Uji positif lab, uji negatif data sendiri (termasuk data setelah hunt), goodlog, replay untuk rule harian; `origin_hunt`, tanggal laporan, tanggal aktif, dan tanggal review dicatat sejak hari pertama | Bagian 1.8, 1.9, 2.4, 2.7 |

**Kapan gagal:** jawaban dikirim tanpa daftar yang ditolak dan ditunda. Sari lalu harus menebak apakah usulan yang tidak disebut terlupa atau sengaja tidak dipasang, dan tumpukan berikutnya dimulai dari kebingungan yang sama.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** satu temuan hunt dari lab-mu sendiri (dari Day 10 sampai 13); repo git lokal untuk rule dan untuk usulan (`handover/`); VM atau container Python di lab untuk `sigma-cli` (jangan dipasang di mesin kerja); Splunk lab dengan Sysmon dari VM Windows lab ber-snapshot dan Microsoft Office; opsional Wazuh lab. Jangan memakai data, nama, atau kejadian dari pekerjaan nyata; PT JAB hanya contoh fiktif.

1. **Pilih temuan.** Ambil satu temuan dari hunt Day 10-13 yang menemukan pola berulang (bukan IOC satu peristiwa).
2. **Nilai kelayakan.** Tentukan apakah layak jadi alert, sinyal risk, laporan hunter, tunda, atau kembali ke backlog (bagian 1.1). Tulis alasannya dengan angka volume dari data lab.
3. **Pilih tingkat Pyramid.** Pastikan logika menargetkan TTP/perilaku, bukan IOC yang ditemukan (bagian 1.2). Bila temuanmu berbasis IOC, naikkan ke perilaku.
4. **Tulis usulan deteksi.** Isi struktur bagian 1.3 di `handover/`. Sertakan query hunt yang berhasil, sampel TP dan FP, cakupan, dan saran output.
5. **Tulis draf Sigma.** Ikuti pola bagian 2.2, termasuk `filter_main_*` untuk FP yang sudah dikonfirmasi dan field `origin_hunt`. Buat UUID versi 4 sendiri. Jalankan `sigma check`.
6. **Konversi dua kali.** Konversi dengan `-p sysmon -p splunk_windows`, lalu bandingkan `source`, `sourcetype`, dan nama field event ID dengan event mentah di Splunk lab-mu. Bila tidak cocok, tulis pipeline YAML seperti bagian 2.3 dan konversi ulang. Catat versi `sigma-cli`, pySigma, dan backend yang terpasang (`pip list`).
7. **Buktikan konversi benar.** Jalankan hasil konversi tanpa blok filter atas rentang hunt-mu; jumlahnya harus sama dengan angka mentah di laporan hunt.
8. **Tulis padanan Wazuh** bila lab-mu memakai Wazuh, lalu uji dengan `wazuh-logtest` memakai event fixture.
9. **Uji.** Jalankan rencana uji bagian 2.4: minimal dua uji positif (satu lewat `OriginalFileName` dengan salinan binary yang diganti nama, di VM lab), satu FP dari hunt, satu emulasi yang memakai parent lain, goodlog satu hari, dan uji negatif dengan label per filter. Catat hasil tiap baris, termasuk yang tidak memicu dan alasannya.
10. **Jadwalkan.** Simpan hasil konversi sebagai saved search lab dengan jendela berjeda (misalnya `*/15`, `-25m@m` sampai `-10m@m`). Matikan forwarder VM 30 menit, jalankan satu uji positif, nyalakan lagi, dan lihat apakah event itu tertangkap. Ulangi dengan variasi `_index_earliest` dari bagian 2.3.
11. **Tutup loop.** Tambahkan minimal dua hipotesis turunan ke backlog (bagian 2.7), salah satunya dari blind spot yang terlihat saat emulasi.
12. **Catat metrik.** Tulis tanggal laporan hunt, tanggal rule aktif di lab, dan selisihnya (bagian 1.9).

**Hasil yang sebaiknya tersimpan:**

- Satu temuan dinilai kelayakannya dengan alasan dan angka volume.
- Logika deteksi menargetkan perilaku, bukan IOC yang ditemukan.
- Usulan deteksi lengkap di `handover/` dengan sampel, FP, dan cakupan.
- Rule Sigma yang lolos `sigma check`, dua hasil konversi, pipeline YAML (bila perlu), dan catatan perbedaan field serta versi alat.
- Bukti kesetaraan: jumlah mentah hasil konversi sama dengan angka hunt.
- Tabel hasil uji (TP, rename, FP, emulasi, goodlog, negatif) dengan penjelasan untuk tiap hasil yang tidak sesuai harapan, dan fixture-nya.
- Catatan uji jendela berjeda: apakah event dari forwarder yang terlambat tertangkap.
- Minimal dua hipotesis turunan masuk backlog.
- Tanggal laporan, tanggal aktif, dan selisihnya.

**Variasi tantangan:** ambil satu temuan hunt yang FP-nya tinggi (misalnya beacon). Rancang dua jalur: (a) sebagai alert dengan filter ketat, (b) sebagai sinyal risk yang hanya beralert saat digabung sinyal lain. Hitung dari data 30 hari berapa alert per hari yang dihasilkan jalur (a), dan berapa host yang melewati ambang skor di jalur (b). Splunk lab tanpa ES bisa meniru jalur (b) dengan menulis hasil detection ke summary index lab (`| collect index=lab_risk`) lalu menjalankan search pengumpul `dc(source)` per entitas atas index itu. Jalankan replay hari per hari dengan rentang absolut dan tanggal acuan tetap seperti bagian 2.5, sekali tanpa throttling dan sekali dengan, lalu bandingkan jumlah risk event. Putuskan mana yang kamu rekomendasikan, dengan alasan.

## 4. Troubleshooting

Tabel ini memuat masalah yang muncul saat mengubah hunt menjadi detection. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Rule baru banjir FP | Query hunt dipakai apa adanya (ambang longgar) | Tetapkan ambang dari distribusi; tambah filter sempit (bagian 2.4, 2.5) |
| Rule cepat basi | Logika berbasis IOC yang ditemukan | Naikkan ke perilaku/TTP (bagian 1.2) |
| Detection engineer tidak bisa memproses usulan | Handover kurang lengkap | Isi semua bagian 1.3, termasuk sampel, FP, volume, dan cakupan |
| Hasil konversi Sigma tidak menemukan apa pun | Pipeline tidak cocok dengan nama field, `source`, atau `EventID`/`EventCode` | Jalankan tanpa blok filter dan bandingkan dengan angka mentah hunt; bandingkan field hasil konversi dengan event mentah (bagian 2.3) |
| `pip install` memasang pySigma versi lama walaupun 2.0 sudah rilis | `sigma-cli` 3.1.0 dan backend Splunk 2.1.0 mensyaratkan pySigma di bawah 2.0 | Biarkan resolver memilih 1.x; jangan memaksa pySigma 2.0 sebelum plugin mendukungnya (bagian 6) |
| `sigma check` lulus padahal ada peringatan | Isu validator tidak menggagalkan check secara default | Tambah `--fail-on-issues` di CI bila isu harus memblok merge [S22] |
| Rule Wazuh tidak pernah memicu | `if_group` salah atau nama field `win.eventdata.*` berbeda | Jalankan `wazuh-logtest` dengan event mentah dan lihat fase decoding |
| Rule lulus sampel hunt tapi gagal emulasi | Emulasi memakai prosedur lain (parent berbeda) | Baca isi tes; bila prosedurnya memang berbeda, catat sebagai blind spot atau pastikan rule lain menutupnya (bagian 2.4) |
| Event dari laptop yang baru online tidak pernah memicu | Jendela berbasis `_time` sudah lewat saat event masuk index | Variasi `_index_earliest`/`_index_latest` (bagian 2.3) |
| Satu aplikasi sah memberi skor risk setiap hari | Tidak ada throttling untuk search harian yang membaca 7 hari | Throttling per `src`, `dest` selama jendela "baru" (bagian 2.5) |
| Pengumpul risk tidak pernah menyala walaupun dua sinyal jelas dari host yang sama | Entitas berbeda bentuk (IP di satu sinyal, nama host di sinyal lain) | Normalisasi entitas atau pemetaan IP ke host; tulis batasnya di handover (bagian 1.7, 2.7) |
| Tujuan yang paling baru tidak pernah diberi skor | Baseline tujuan diperbarui setelah search, dan `where` membuang nilai null | Tambah cabang `isnull(dest_first_seen) OR ...` (bagian 2.5) |
| Replay menandai hampir semua tujuan sebagai baru | Replay dimulai sebelum 14 hari setelah baseline dibuat | Mulai replay setelah jendela "baru" pertama lewat (bagian 2.5) |
| Temuan dipaksakan jadi alert | FP tinggi, butuh konteks | Jadikan sinyal risk (bagian 1.7) |
| Loop tidak berlanjut | Tidak ada hipotesis turunan | Tambah ke backlog tiap kali deteksi dibuat (bagian 2.7) |

## 5. Kesalahan umum dan jebakan

- **Mengubah IOC temuan jadi deteksi.** IP dan hash cepat basi; deteksi dari hunt harus menargetkan perilaku.
- **Memakai query hunt apa adanya sebagai rule.** Rentang dan ambang hunt terlalu longgar; sesuaikan.
- **Memaksakan semua temuan jadi alert.** FP tinggi lebih cocok sinyal risk atau laporan hunter.
- **Handover tanpa sampel dan FP.** Detection engineer kehilangan bukti nyata yang dikumpulkan hunt.
- **Percaya hasil konversi tanpa membandingkan dengan data.** Pipeline yang salah menghasilkan query yang sintaksnya benar tetapi tidak pernah cocok. Nol hasil hanya berarti sesuatu bila query tanpa filter mengembalikan angka mentah yang benar.
- **Mengedit SPL di ES tanpa mengubah Sigma.** Rule di repo dan rule yang berjalan berpisah, uji otomatis menguji sesuatu yang tidak berjalan, dan perubahan berikutnya menimpa perbaikan.
- **Pengecualian per host atau per pengguna.** Pengecualian `JKT-WS-0403` untuk FP Outlook akan membutakan rule di host Customer Service yang paling sering membuka lampiran. Pengecualian ditulis per kombinasi parent, fungsi, dan bentuk argumen.
- **Menyalin ambang hunt ke rentang yang berbeda.** Ambang 20 koneksi dalam 28 hari tidak sama dengan 20 koneksi dalam 7 hari.
- **Menyimpulkan rule rusak karena tes emulasi tidak memicu**, padahal tesnya meniru prosedur lain.
- **Sinyal risk tanpa throttling dan tanpa pengumpul berbasis jumlah detection.** Satu detection yang menyala setiap hari memicu ambang skor sendirian, dan RBA berubah menjadi alert biasa.
- **Mengimpor rule publik tanpa backtest.** Rule SigmaHQ untuk child Office yang memuat `cmd.exe` akan menyala untuk makro bisnis sah di PT JAB, dan tidak melihat Outlook.
- **Lupa menutup loop.** Tanpa hipotesis turunan, hunting berputar di tempat, bukan tumbuh.
- **Tidak mencatat tanggal aktif.** Waktu ke produksi dan jumlah detection dari hunt lalu direkonstruksi dari ingatan, dan angkanya selalu terlihat lebih baik dari kenyataan.
- `[komunitas, belum terkonfirmasi]` Praktisi menilai "jumlah deteksi yang lahir dari hunt" sebagai metrik nilai hunting yang paling meyakinkan manajemen, karena menunjukkan penambahan cakupan permanen. PEAK juga menaruh jumlah deteksi yang dibuat atau diperbaiki sebagai metrik pertamanya (Day 15); cocokkan dengan kerangka metrik yang kamu pilih.

## 6. Catatan terkini

Bagian ini menampung detail versi alat, perubahan spesifikasi, dan perubahan konten vendor. Berguna saat memasang alat atau membaca rule lama, tetapi tidak mengubah alur kerja di atas.

- Tahap "inform and enrich analytics" (hunting loop) dan fase Act with Knowledge (PEAK) adalah dasar jembatan hunt ke deteksi [S5].
- **Sigma specification 2.1.0** (2025-08-02) [S1]: tidak ada perubahan yang merusak rule dari 2.0; ada modifier baru, tag baru, kategori jaringan generik di taksonomi, dan operator Metric di correlation rule. Sigma specification sudah di versi 2, dan alat konversi resminya adalah pySigma dengan antarmuka `sigma-cli`; backend dan pipeline dipasang sebagai plugin terpisah [S1][S2]. Contoh lama yang memakai `sigmac` berasal dari generasi alat sebelumnya.
- **Versi alat per 2026-10-18:** `sigma-cli` 3.1.0 (2026-07-07, Python 3.10 ke atas) mensyaratkan pySigma minimal 1.3.0 dan di bawah 2.0.0 [S17]; pySigma-backend-splunk 2.1.0 (2026-03-22) mensyaratkan pySigma 1.x [S19]; pySigma sendiri sudah merilis 2.0.0 (2026-10-04) dan 2.0.1 (2026-10-11), dengan 1.5.1 (2026-09-21) sebagai rilis 1.x terakhir [S18]. Instalasi biasa akan memakai pySigma 1.x sampai plugin diperbarui. Backend 2.1.0 memperbaiki backend SPL2, menambah dukungan data model DNS, dan membatasi nama capture group `rex` sampai 32 karakter [S20].
- **Tag taktik di Sigma:** rule SigmaHQ sudah memakai `attack.stealth` [S16], sedangkan daftar contoh taktik di lampiran tag spesifikasi masih memuat nama sebelum ATT&CK v20, seperti `defense-evasion` [S15]. Rule lama dan rule pihak ketiga akan memakai keduanya.
- **ATT&CK v20:** T1218.010 versi 3.0 dan T1204.002 versi 1.6, keduanya diubah 2026-05-12; detection strategy DET0282 dan DET0294 [S7][S8].
- **Splunk ES 8.7:** event-based detection dengan risk modifier (entitas, tipe, skor, pesan, Finding atau Intermediate Findings, threat object) dan finding-based detection dengan dua bawaan aktif (24 jam dan 7 hari ATT&CK) [S24][S25]. Keputusan alert atau risk mengikuti kemampuan SIEM-mu: Splunk ES punya RBA bawaan [S6], sedangkan di Wazuh korelasi perlu dirancang sendiri dengan rule berfrekuensi.
- **Splunk Security Content:** "Windows Office Product Spawned Uncommon Process" versi 9 (2026-05-13) menggantikan detection per binary Office yang dihapus di versi 5.2.0, dan dipetakan ke T1566.001, bukan T1218 [S26][S27]. Pemetaan teknik antar sumber bisa berbeda untuk perilaku yang sama; yang dipakai PT JAB adalah pemetaan Day 13.
- **Alat detection-as-code Splunk:** `contentctl` tidak lagi menerima pull request atau permintaan fitur baru karena investasi beralih ke Detection Studio [S28]. Detection Studio diumumkan GA untuk ES Essentials dan ES Premier pada 22 April 2026 [S29]; cek ketersediaannya untuk ES on-premises di catatan rilis versi-mu sebelum merencanakan alur di atasnya.
- Day 15 memperdalam metrik dan dokumentasi; Day 16 menggabungkan semua dalam capstone.

## 7. Cheat sheet

```
KELAYAKAN   alert: volume rendah setelah pengecualian sempit | risk: sering jinak, bermakna bila berkumpul
            laporan hunter: butuh penilaian manusia | tunda: tunggu perbaikan sistem/data
            backlog: abstract belum cukup | IOC sementara: spesifik 1 kampanye (threat intel, masa berlaku)
PYRAMID     deteksi dari hunt targetkan TTP/perilaku, BUKAN IP/hash yang ditemukan (tahan lama)
HANDOVER    tujuan | teknik ATT&CK | sumber data | logika kandidat | volume mentah + setelah pengecualian
            | FP diketahui | cakupan + blind spot | saran output | uji  (subset ADS)
            + setelah diterima: nama ES, jadwal, entitas/skor, aktif, review, origin_hunt
HUNT->RULE  jendela berjeda (*/15, -25m@m s/d -10m@m) | ambang diskalakan ulang per rentang
            | filter FP per parent+fungsi+argumen | Sigma + konversi | uji
SIGMA       id UUIDv4 | status experimental -> test -> stable | level informational..critical
            list nilai = OR ; map = AND ; list of maps = OR ; 1 of selection_* ; not 1 of filter_main_*
            tag: attack.t1218.010, attack.stealth ; nilai tidak peka huruf, re peka huruf
KONVERSI    sigma plugin install splunk ; sigma check rules/ [--fail-on-issues]
            sigma convert -t splunk -p sysmon -p <pipeline PT JAB>.yml rule.yml
            splunk_windows -> source="WinEventLog:..." (PT JAB: XmlWinEventLog) ; EventID -> EventCode
            -f savedsearches | -f data_model (+ -p splunk_cim)
            bukti benar: tanpa filter = angka mentah hunt
UJI         positif lab (termasuk rename) | FP hunt tidak memicu | goodlog nol | negatif data sendiri
            + data setelah hunt | emulasi: baca dulu prosedur tesnya (parent bisa beda) | replay untuk rule harian
ES 8        event-based: risk modifier (entitas, tipe, skor, Finding | Intermediate Findings, threat object)
            finding-based: kumpulkan per entitas; PT JAB: dc(detection) >= 2 dalam 7 hari
            throttling per src,dest = panjang jendela "baru"
LOOP        deteksi baru -> hipotesis turunan ke backlog (prosedur lain, evasi, blind spot dari emulasi)
METRIK      detection lahir dari hunt (origin_hunt) | hari dari laporan ke aktif | celah ditutup (layer Navigator)
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Query tahap A `HUNT-2027-023` sudah terbukti menangkap Word ke `regsvr32.exe` di uji lab, jadi Sari cukup menjadwalkannya apa adanya setiap 15 menit." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Query hunt membaca rentang panjang, menghitung dengan `stats`, dan tidak punya pengecualian karena hunter melabeli setiap hasil; dijadwalkan apa adanya, 71 eksekusi FileProtocolHandler dan 5 OpenAs_RunDLL per bulan akan masuk antrean L1. Rule membutuhkan jendela berjeda, satu hasil per event, pengecualian sempit untuk FP yang sudah dikonfirmasi, dan uji ulang dengan logika final, termasuk data setelah hunt, yang di PT JAB memunculkan pola `http://` baru. Lihat bagian 1.4 dan 2.4.

</details>

**2. Skenario keputusan.** Usulan "JAB - Beacon ke domain baru (risk)" dalam 28 hari hanya cocok dengan aplikasi papan proyek sah yang baru dipasang. Bentuk mana yang paling tepat?

- A. Alert langsung dengan severity rendah, supaya L1 tetap melihat setiap beacon baru.
- B. Event-based detection berkeluaran Intermediate Findings dengan skor 30 dan throttling per pasangan, ditambah finding-based detection yang memunculkan finding bila minimal dua detection berbeda menunjuk entitas yang sama dalam 7 hari.
- C. Laporan mingguan untuk hunter saja, tanpa skor risk.

<details><summary>Jawaban</summary>

B. Pola ini hampir selalu jinak sendirian tetapi bermakna bila bertemu sinyal lain, terutama unggahan besar ke tujuan baru; risk event menyimpan konteksnya tanpa menambah antrean, dan pengumpul berbasis jumlah detection berbeda mencegah satu sinyal memicu alert sendirian. A keliru karena hampir setiap tiket akan jinak dan L1 belajar mengabaikannya. C keliru karena kehilangan korelasi otomatis dengan sinyal kedua; laporan hunter cocok untuk pola yang butuh penilaian per kasus, bukan untuk pola yang nilainya ada di kombinasi. Lihat bagian 1.7 dan 2.5.

</details>

**3. Pertanyaan jebakan.** "`sigma convert -t splunk -p sysmon -p splunk_windows` berjalan tanpa error dan menghasilkan query yang menulis `EventCode=1`, jadi rule itu siap dipakai di ES PT JAB." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Pipeline `splunk_windows` membangun kondisi `source` berawalan `WinEventLog:`, sedangkan Sysmon PT JAB ber-`source` `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, sehingga query itu tidak pernah cocok dengan satu event pun walaupun sintaksnya benar. Konversi baru terbukti benar bila hasilnya, tanpa blok filter, mengembalikan angka mentah yang sama dengan hunt (76 untuk Februari). PT JAB memakai pipeline YAML sendiri yang memetakan `EventID` ke `EventCode` dan menambah `index=sysmon sourcetype=XmlWinEventLog`. Lihat bagian 1.6 dan 2.3.

</details>

**4. Skenario keputusan.** Rekan menjalankan Atomic Red Team T1218.010 test 1 (scriptlet COM lokal) di VM lab, dan "JAB - Office meluncurkan signed proxy binary" tidak memicu. Apa kesimpulan yang tepat?

- A. Rule rusak; hapus syarat parent Office supaya semua regsvr32 dengan scriptlet tertangkap.
- B. Sesuai rancangan: parent test itu shell, bukan Office, sehingga rule ini memang tidak boleh memicu; pastikan prosedur itu ditangkap "JAB - Proxy binary dengan scriptlet atau skrip inline", dan catat di baris Uji handover.
- C. Ganti test dengan test lain sampai rule memicu, lalu tulis uji emulasi lulus.

<details><summary>Jawaban</summary>

B. Rule ini spesifik ke prosedur parent Office; test yang memakai parent shell menguji prosedur lain, dan prosedur itu memang ditutup rule scriptlet/inline, yang menangkap urutan 3 dan 4 di uji lab Day 13. A keliru karena mengubah rule menjadi duplikat rule lain dan membuang pembeda parent yang sudah diukur volumenya. C keliru karena memilih test sampai hasilnya cocok menyembunyikan informasi tentang cakupan. Lihat bagian 2.4.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Gilang Ramadhan (analyst L1), dalam tiga kalimat, kenapa "JAB - Beacon ke domain baru (risk)" tidak pernah muncul di antreannya, dan kapan ia akan melihat sesuatu darinya.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Detection itu hanya memberi skor 30 ke IP yang berkomunikasi teratur ke domain yang baru terlihat, karena dalam sebulan terakhir pola itu hampir selalu aplikasi baru yang sah, jadi kalau dijadikan alert kamu akan menutup tiket jinak terus. Skor itu disimpan di index risk dan ditinjau hunter setiap Selasa. Kamu baru akan melihat finding kalau IP yang sama juga kena detection lain dalam 7 hari, misalnya unggahan besar ke tujuan baru, dan finding itu memuat kedua sinyal supaya triage-mu langsung punya konteks."

Kesalahan yang sering muncul:
- Mengatakan detection itu "tidak aktif" atau "hanya uji coba", padahal ia berjalan setiap hari dan menyimpan skor.
- Lupa menyebut syarat dua detection berbeda dalam 7 hari, sehingga Gilang mengira skor tinggi dari satu sinyal saja akan muncul.
- Tidak menjelaskan kenapa bukan alert (volume jinak dari data sendiri).

</details>

**6. Pertanyaan jebakan.** "Setelah `INC-2027-040`, detection terbaik untuk kasus seperti `SBY-WS-0107` adalah alert ES untuk `cdn.pdfsuite-cloud.example.net` dan `198.51.100.39`." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Domain dan IP berada di dasar Pyramid of Pain dan mudah diganti penyerang; varian di `SBY-WS-0107` sendiri lolos dari pencarian IOC `INC-2026-026` karena memakai domain C2 yang berbeda, dan yang menemukannya adalah pola persistence. Indikator itu tempatnya threat intelligence dengan masa berlaku, sedangkan detection-nya perilaku: scheduled task yang menjalankan biner dari folder AppData pengguna, dengan cakupan yang ditulis jujur karena laptop seperti itu tidak menghasilkan 4698. Lihat bagian 1.2 dan 2.1.

</details>

**7. Interview question (English).** "Walk me through how you turn a threat hunt finding into a production detection."

<details><summary>Sample answer</summary>

"I start by deciding whether it should be a detection at all, using numbers from our own data: raw volume, volume after narrow exclusions for false positives I already confirmed during the hunt, and which hosts actually have the telemetry. If almost every match deserves a look, it becomes an alert; if it is usually benign but meaningful in combination, it becomes a risk signal feeding a correlation that needs two different detections on the same entity; if it needs human judgment every time, it stays a hunter report. I target behavior rather than the indicators I found, write the logic in Sigma with exclusions scoped to parent, function and argument shape, never to a host, and convert it with a processing pipeline that matches how our data is onboarded. I prove the conversion by checking that the query without filters returns the same raw count as the hunt, then test with positive cases in an isolated lab, including a renamed binary, benign data, a goodlog day and data from after the hunt ended. The handover records coverage gaps, triage steps, the go-live date and a review date, and every blind spot goes back into the hunt backlog. I also track the hunt-to-production time, because that tells me whether the bridge between hunting and detection is working."

What makes this answer strong: it grounds every decision in measured volume, separates alert, risk and report outputs, shows awareness that a clean conversion can still be blind, includes regression-style testing, and closes the loop with backlog items and a metric.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | SigmaHQ: Sigma specification (Sigma Rules Specification 2.1.0) | https://github.com/SigmaHQ/sigma-specification | primer | diakses 2026-10-10, dicek ulang 2026-10-18 (versi 2.1.0, 2025-08-02) | Tinggi. Struktur rule, modifier, condition, perilaku pencocokan, status, level, UUIDv4, `related`, perubahan 2.0 ke 2.1 (`other/version-2.0-2.1.md`) |
| S2 | SigmaHQ: sigma-cli dan pySigma-backend-splunk | https://github.com/SigmaHQ/sigma-cli | primer | diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi. Perintah `sigma convert -t splunk -p sysmon`, opsi `-f`, `-o`, `-O`, `sigma plugin`, `sigma list`, format keluaran `savedsearches`; detail backend di https://github.com/SigmaHQ/pySigma-backend-splunk |
| S3 | Palantir: Alerting and Detection Strategy Framework | https://github.com/palantir/alerting-detection-strategy-framework | primer (pemilik kerangka) | diakses 2026-10-10 | Tinggi. Bagian-bagian dokumen ADS |
| S4 | David Bianco: The Pyramid of Pain | https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html | primer (penulis konsep) | 2013; diakses 2026-10-10 | Tinggi untuk definisi tingkat indikator |
| S5 | Splunk: Introducing the PEAK Threat Hunting Framework | https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html | sekunder (blog vendor, penulis kerangka) | 2023; diakses 2026-10-10 | Tinggi untuk fase Act with Knowledge |
| S6 | Splunk: Risk-Based Alerting, the new frontier for SIEM | https://www.splunk.com/en_us/blog/security/risk-based-alerting-the-new-frontier-for-siem.html | sekunder (blog vendor) | 2022-04-04; diakses 2026-10-10 | Sedang-tinggi. Konsep risk object, skor, ambang; angka penurunan alert adalah klaim pengalaman penulis |
| S7 | MITRE ATT&CK: T1218.010 Regsvr32 | https://attack.mitre.org/techniques/T1218/010/ | primer | ATT&CK v19 diakses 2026-10-10; dicek ulang 2026-10-18 (v20, versi 3.0, diubah 2026-05-12) | Tinggi. Taktik Stealth (TA0005), DET0282, COM scriptlet tanpa perubahan registry |
| S8 | MITRE ATT&CK: T1204.002 Malicious File | https://attack.mitre.org/techniques/T1204/002/ | primer | ATT&CK v19 diakses 2026-10-10; dicek ulang 2026-10-18 (v20, versi 1.6, diubah 2026-05-12) | Tinggi. Taktik Execution, DET0294 |
| S9 | Wazuh documentation: Rules syntax | https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html | primer | Wazuh 4.x; diakses 2026-10-10 | Tinggi untuk elemen `if_group`, `field`, `mitre`, rentang ID kustom |
| S10 | MITRE ATT&CK Navigator | https://github.com/mitre-attack/attack-navigator | primer | diakses 2026-10-10 | Tinggi untuk konsep layer, skor, dan komentar per teknik |
| S11 | Atomic Red Team: T1218.010 | https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.010/T1218.010.md | primer (repo tes) | diakses 2026-10-10 | Tinggi untuk isi tes (scriptlet lokal/remote, DLL) dan executor Command Prompt |
| S12 | MITRE ATT&CK: T1071 Application Layer Protocol | https://attack.mitre.org/techniques/T1071/ | primer | ATT&CK v19; diakses 2026-10-10 | Tinggi |
| S13 | Threat-Hunting Day 01-13 (laporan hunt, usulan, uji lab Day 13) | (lokal) | rujukan internal | 2026-10-18 | Sumber semua usulan di bagian 2.1, angka volume, dan test uji lab |
| S14 | SigmaHQ: SigmaHQ Rule Convention | https://github.com/SigmaHQ/sigma-specification/blob/main/sigmahq/sigmahq-rule-convention.md | primer (konvensi repo SigmaHQ, bukan spesifikasi) | diakses 2026-10-18 | Tinggi. Urutan field, rule baru `experimental`, `falsepositives`, `filter_main_*`/`filter_optional_*`, `1 of selection_*` |
| S15 | SigmaHQ: Sigma Tags appendix | https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-appendix-tags.md | primer | diakses 2026-10-18 | Tinggi untuk namespace `attack`, `car`, `cve`, `detection`, `tlp`. Daftar contoh taktik belum memuat Stealth |
| S16 | SigmaHQ rule: Suspicious Microsoft Office Child Process (`proc_creation_win_office_susp_child_processes.yml`) | https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_office_susp_child_processes.yml | primer (repo rule) | 2018-04-06, diubah 2023-04-24; diakses 2026-10-18 | Tinggi. Status test, level high, tag `attack.stealth`, daftar parent tanpa Outlook, child termasuk cmd dan powershell |
| S17 | PyPI: sigma-cli | https://pypi.org/project/sigma-cli/ | primer (registry paket) | 3.1.0, 2026-07-07; diakses 2026-10-18 | Tinggi. Versi, Python 3.10 ke atas, syarat pySigma >=1.3.0,<2.0.0 (dari metadata JSON) |
| S18 | PyPI: pySigma | https://pypi.org/project/pySigma/ | primer (registry paket) | 2.0.1 (2026-10-11), 2.0.0 (2026-10-04), 1.5.1 (2026-09-21); diakses 2026-10-18 | Tinggi untuk nomor dan tanggal rilis |
| S19 | PyPI: pySigma-backend-splunk | https://pypi.org/project/pySigma-backend-splunk/ | primer (registry paket) | 2.1.0, 2026-03-22; diakses 2026-10-18 | Tinggi. Syarat pySigma 1.x (dari metadata JSON) |
| S20 | SigmaHQ: pySigma-backend-splunk (README, `sigma/pipelines/splunk/splunk.py`, rilis) | https://github.com/SigmaHQ/pySigma-backend-splunk | primer | diakses 2026-10-18 | Tinggi. Pipeline `splunk_windows` (`source` berawalan `WinEventLog:`, `EventID` ke `EventCode`), `splunk_sysmon_acceleration`, `splunk_cim`; format `default`, `savedsearches`, `data_model`; isi rilis 2.1.0 |
| S21 | SigmaHQ: pySigma-pipeline-sysmon | https://github.com/SigmaHQ/pySigma-pipeline-sysmon | primer | diakses 2026-10-18 | Tinggi. EventID per kategori, logsource menjadi `service: sysmon`, prioritas 5 |
| S22 | SigmaHQ: sigma-cli `check.py` | https://github.com/SigmaHQ/sigma-cli/blob/main/sigma/cli/check.py | primer (kode sumber) | diakses 2026-10-18 | Tinggi. Opsi `--validation-config`, `--exclude`, `--fail-on-error`, `--fail-on-issues`, `--junitxml` |
| S23 | pySigma documentation: Processing Pipelines (v1.5.0) | https://sigmahq-pysigma.readthedocs.io/en/v1.5.0/_sources/Processing_Pipelines.rst.txt | primer | diakses 2026-10-18 | Tinggi untuk format YAML pipeline (`name`, `priority`, `transformations`, `rule_conditions`) dan identifier `field_name_mapping`, `add_condition`. Parameter `add_condition` tidak dicontohkan |
| S24 | Splunk ES 8.7: Assign risk using risk modifiers | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/risk-based-alerting/assign-risk-using-risk-modifiers-in-splunk-enterprise-security | primer | ES 8.7; diakses 2026-10-18 | Tinggi. Entitas, tipe, skor (0 hanya konteks), pesan, Finding vs Intermediate Findings, threat object, jalur menu |
| S25 | Splunk ES 8.7: Create finding-based detections | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/detections/create-finding-based-detections-in-splunk-enterprise-security | primer | ES 8.7; diakses 2026-10-18 | Tinggi. Finding group (maksimal 100), skor agregat, detection bawaan 24 jam dan 7 hari ATT&CK. Nilai ambang 24 jam tidak disebut |
| S26 | Splunk Security Content: Windows Office Product Spawned Uncommon Process | https://research.splunk.com/endpoint/55d8741c-fa32-4692-8109-410304961eb8/ | primer (konten vendor) | versi 9, 2026-05-13; diakses 2026-10-18 | Tinggi. Jadwal `0 * * * *`, `-70m@m` sampai `-10m@m`, Finding pada user dan Intermediate Finding pada dest skor 50, T1566.001 |
| S27 | Splunk Security Content: Office Application Spawn rundll32 process (removed) | https://research.splunk.com/removed/958751e4-9c5f-11eb-b103-acde48001122/ | primer (konten vendor) | dihapus di 5.2.0; diakses 2026-10-18 | Tinggi. Alasan penghapusan dan penggantinya |
| S28 | Splunk: contentctl (GitHub) | https://github.com/splunk/contentctl | primer | diakses 2026-10-18 | Tinggi. Fungsi alat; tidak lagi menerima pull request baru, investasi ke Detection Studio |
| S29 | Splunk blog: From Data to Defense: Mastering the Detection Lifecycle with Detection Studio | https://www.splunk.com/en_us/blog/security/mastering-the-detection-lifecycle-with-detection-studio.html | sekunder (blog vendor) | 2026-04-22; diakses 2026-10-18 | Sedang-tinggi. GA untuk ES Essentials dan Premier; tidak menyebut ketersediaan on-premises |

**Catatan sumber:** keluaran konversi SPL di bagian 2.3 adalah ilustrasi dan bentuk persisnya bergantung versi backend serta pipeline; jalankan konversi di lab dan bandingkan. Nilai `source` persis yang dibangun `splunk_windows` untuk Sysmon disimpulkan dari awalan `WinEventLog:` di kode pipeline [S20] dan nama channel Sysmon; fungsi pembantunya tidak terlihat di halaman yang diperiksa, jadi cocokkan dengan keluaran konversi di versi-mu. Nama parameter `conditions` untuk transformasi `add_condition` di pipeline YAML tidak dicontohkan di dokumentasi yang diperiksa [S23]; cek di dokumentasi `AddConditionTransformation` sebelum dipakai, dan apakah `-p` di `sigma-cli` versi-mu menerima path berkas YAML (`sigma convert --help`). Nama group `sysmon_event1` dan nama field `win.eventdata.*` di rule Wazuh mengikuti ruleset dan decoder bawaan Wazuh 4.x untuk Sysmon; cocokkan dengan keluaran `wazuh-logtest` di versi-mu. Status alat konversi Sigma ke Wazuh berasal dari komunitas dan berubah cepat, jadi cek sebelum dipakai. Nama opsi throttling di editor detection ES 8, nama field data model Risk, dan nilai ambang bawaan "Risk - 24 Hour Risk Threshold Exceeded" tidak dikonfirmasi dari dokumentasi yang diperiksa [S24][S25]. Angka skor risk (20, 30, 60) adalah keputusan organisasi fiktif, bukan rekomendasi. Situasi Sari, triase usulan, rule Sigma dan UUID-nya, pipeline PT JAB, hasil uji lab di `jab-lab-win11`, angka backtest Februari dan Maret, replay risk, dan tanggal aktif detection adalah penerapan catatan ini pada organisasi fiktif, bukan hasil eksekusi nyata.
