---
day: 05
title: 'Baselining dan stacking: empat teknik analisis hunting, membangun baseline, dan analisis frekuensi untuk beacon'
researched_on: 2026-10-18
versions_checked: 'Splunk Enterprise 10.6 SPL Search Reference (streamstats, eventstats, outputlookup, inputlookup, statistical functions; halaman diperbarui 2026-09-09); Splunk blog Baseline Hunting with the PEAK Framework (Jul 2023); Sqrrl Hunt Evil dan Hunting Loop (2015); Intel 471 Threat Hunting Tactics and Techniques (Jan 2021); RITA v5.1.2 (7 Mei 2026); Squid wiki LogFormat; MITRE ATT&CK v20'
---

# Day 05: Baselining dan stacking (empat teknik analisis, baseline tersimpan, dan analisis frekuensi untuk beacon)

Cakupan: empat teknik analisis hunting (searching, stacking, grouping, clustering), cara membangun, menormalisasi, dan menyimpan baseline, kenapa long tail menarik dan kapan tidak, analisis frekuensi untuk menemukan beacon beserta cara membedakannya dari agent sah, serta batas semua teknik itu.

## Ide inti

Kata "anomali" baru punya arti setelah kamu menulis apa yang dianggap normal, untuk kelompok host mana, dari periode kapan, dan dengan aturan normalisasi apa. Baseline adalah tulisan itu, disimpan supaya hunt berikutnya cukup membandingkan, bukan menghitung ulang dari nol. Di atas baseline, empat teknik analisis (searching, stacking, grouping, clustering) dan analisis frekuensi bekerja dengan satu tujuan yang sama: memperkecil jutaan event menjadi daftar yang cukup pendek untuk ditinjau manusia. Tidak ada satu pun dari teknik itu yang memberi vonis. Langka belum tentu jahat, teratur belum tentu beacon, dan "baru" belum tentu berbahaya; yang membuat sebuah item layak dicurigai adalah gabungan sinyal itu dengan konteks: siapa pemiliknya, berapa host yang melakukannya, dan apakah ada penjelasan yang bisa dikonfirmasi.

Kamu sudah melakukan ini di NOC. Profil trafik normal per POP per jam adalah baseline: tanpa profil itu, lonjakan pukul 02:00 tidak bisa disebut aneh. Mencari perangkat dengan konfigurasi paling langka di inventaris adalah stacking. Dan setiap engineer NOC pernah curiga pada polling SNMP terjadwal dari sumber yang tidak dikenal, lalu ternyata itu NMS milik tim lain. Batas analoginya ada dua. Baseline trafik jaringan jarang sengaja dicemari, sedangkan baseline keamanan bisa dibangun saat penyerang sudah di dalam, sehingga perilakunya ikut tercatat sebagai normal; karena itu periode baseline harus dipilih dan isinya yang langka ditinjau dulu. Lalu agent sah juga beacon, dan penyerang sengaja menambahkan jitter supaya intervalnya tidak rapi; keteraturan saja tidak cukup untuk membedakan keduanya.

```
 data mentah (Sysmon, proxy)            periode bersih + kelompok host
          |                                         |
          v                                         v
   normalisasi field  ------------------->  BASELINE tersimpan (lookup CSV,
          |                                  summary index, CDB list)
          |                                         |
          +------------+--------------+-------------+
                       |              |             |
                   stacking      first-seen    analisis frekuensi
                 (yang langka)  (yang baru)   (yang teratur: beacon)
                       |              |             |
                       +------> daftar pendek <-----+
                                      |
                       grouping / pivot per item (apa yang muncul bersama?)
                                      |
                 label: jinak | perlu investigasi | inkonklusif | data tidak cukup
                                      |
                laporan hunt + baseline diperbarui + backlog + usulan deteksi
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan. SOC PT JAB memakai Splunk Enterprise dengan Enterprise Security (ES); Sysmon terpasang di server Windows dan sekitar 40% workstation (OU `Workstations-EDR`), dan trafik web karyawan lewat proxy Squid yang log-nya masuk `index=proxy` dengan retensi 30 hari. Sejak 1 Februari 2027, kamu (analyst L2) memegang Program hunt PT JAB setiap Selasa dan Kamis. Hunt pertama, `HUNT-2027-001`, menghitung pasangan parent-child proses selama 25 Januari sampai 1 Februari 2027 dan meninggalkan pelajaran: dari 3.214 pasangan unik, 1.146 muncul tiga kali atau kurang, terlalu banyak untuk ditinjau, sebagian besar karena path berversi dan folder acak installer. Kamis 2027-02-11 pukul 07:55, Bambang Hartono, Manajer NOC, menulis di kanal SOC:

> "Mas, anak NOC tadi malam lihat di grafik request per klien proxy Jakarta, ada satu PC kantor, `JKT-WS-0541`, yang ngobrol ke internet teratur banget, tiap menit pas, kayak polling SNMP. Ini tanda C2 bukan? Kalau iya, kenapa SOC tidak dapat alert?"

Pukul 08:20, SOC lead Dimas Prasetyo menambahkan:

> "Sekalian. Laporan `HUNT-2027-001` bilang long tail mentah terlalu panjang dan perlu normalisasi path plus baseline. Aku mau paham dulu: 'normal' itu kita definisikan bagaimana, dan disimpan di mana supaya tidak dihitung ulang tiap hunt? Kenapa yang langka layak dicurigai, padahal kemarin yang langka ternyata jinak semua? Untuk kasus Pak Bambang, bagaimana bedanya beacon malware dengan agent yang memang polling? Tolong jelaskan juga teknik mana dipakai untuk pertanyaan mana dan apa batasnya, supaya anak-anak L1 tidak menganggap hasil stacking itu vonis."

Dua pesan itu memuat tujuh pertanyaan:

1. Teknik analisis mana yang dipakai untuk pertanyaan mana?
2. Apa itu "normal", dan bagaimana baseline dibangun?
3. Di mana baseline disimpan, dan bagaimana diperbarui tanpa merusaknya?
4. Kenapa yang langka menarik, dan kapan kelangkaan tidak berarti apa-apa?
5. Bagaimana mengukur keteraturan koneksi, dan bagaimana jitter mengacaukannya?
6. Bagaimana membedakan beacon malware dari agent sah yang polling?
7. Apa batas teknik-teknik ini, dan apakah PC milik Pak Bambang itu C2?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, pertanyaan 6 di bagian 1.6, dan pertanyaan 7 di bagian 1.7 serta hasil `HUNT-2027-005` di bagian 2.1 sampai 2.3. Bagian 2.4 sampai 2.6 membangun baseline parent-child dan menjalankan `HUNT-2027-006`, dan bagian 2.7 berisi laporan kedua hunt plus jawaban untuk Bambang dan Dimas.

**Kapan relevan:** saat hunt bertipe baseline (exploratory) dan pada tahap investigasi hampir semua hunt, yaitu setiap kali data terlalu besar untuk dibaca dan perlu diperkecil; saat ada pertanyaan "apakah ini normal" dari NOC, pemilik sistem, atau L1; dan saat menyiapkan deteksi first-seen atau laporan beacon berkala.
**Kapan bukan jawaban:** saat hipotesis sudah sangat spesifik (searching langsung lebih cepat daripada membangun baseline); saat lingkungan terlalu kecil atau sepi sehingga hampir semuanya langka; saat datanya belum siap (field kosong, waktu tidak akurat, retensi terlalu pendek, Day 04); dan saat ada insiden aktif, karena membangun baseline di tengah insiden berarti memasukkan perilaku penyerang ke "normal".

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (threat hunting, hipotesis, stacking, long tail, PEAK, TaHiTI, handover) tidak diulang. Tabel ini hanya memuat istilah baru di Day ini; kolom kanan memetakannya ke pengalaman NOC dan SOC.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Searching | Query bertarget untuk menguji hipotesis yang sudah spesifik | Cek satu dugaan penyebab gangguan langsung di perangkatnya |
| Grouping | Melihat karakteristik yang muncul bersama pada himpunan yang sudah dicurigai | Melihat semua alarm satu node dalam jendela waktu yang sama |
| Clustering | Mengelompokkan seluruh data berdasarkan kemiripan agregat untuk menemukan outlier, biasanya dengan statistik atau ML | Mengelompokkan modem pelanggan berdasarkan pola trafik lalu mencari yang menyendiri |
| Baseline | Gambaran perilaku normal, dari periode dan kelompok host tertentu, yang disimpan sebagai pembanding | Profil trafik normal per POP per jam |
| Normalisasi | Menyeragamkan nilai field (huruf, path berversi, folder acak) sebelum dihitung atau dibandingkan | Menyeragamkan nama interface (`Gi0/1` dan `GigabitEthernet0/1`) sebelum membandingkan konfigurasi |
| First-seen | Kombinasi nilai yang belum pernah ada di baseline | Alarm "MAC baru terlihat di port" |
| Prevalence | Berapa banyak host yang memiliki perilaku atau tujuan yang sama | Berapa banyak pelanggan yang memakai profil yang sama |
| Beacon (beaconing) | Koneksi berulang dari satu sumber ke satu tujuan pada interval yang relatif tetap | Polling SNMP terjadwal dari sumber yang tidak dikenal |
| Interval (delta) | Selisih waktu antara dua koneksi berurutan pada pasangan sumber-tujuan yang sama | Jarak antar-poll di log NMS |
| Jitter | Variasi acak yang sengaja ditambahkan ke interval beacon | Variasi delay paket pada link |
| Coefficient of variation (CV) | Deviasi standar interval dibagi rata-ratanya; makin kecil, makin teratur | Persentase fluktuasi latensi terhadap rata-ratanya |
| Analisis frekuensi | Melihat seberapa sering dan dengan pola apa sesuatu terjadi | Membaca pola polling di grafik |
| Analisis volumetrik | Melihat seberapa banyak (byte, koneksi) sesuatu terjadi | Membaca utilisasi bandwidth |

### 1.1 Empat teknik analisis dan memilih yang tepat

Dimas meminta penjelasan "teknik mana untuk pertanyaan mana" karena L1 cenderung memakai satu cara untuk semua hal: `stats count` lalu `sort`. Padahal pertanyaan Bambang ("PC ini polling teratur, C2 atau bukan?") dan pertanyaan Dimas tentang long tail membutuhkan teknik yang berbeda.

Literatur hunting membedakan empat teknik yang saling melengkapi [S1][S2]. Tabel berikut membandingkannya; baca kolom "Kapan dipakai", karena itulah yang menentukan pilihan.

| Teknik | Cara kerja | Kapan dipakai | Keluaran |
|---|---|---|---|
| Searching | Query bertarget untuk menguji hipotesis spesifik | Hipotesis sudah jelas (Day 03) | Cocok atau tidak cocok |
| Stacking (stack counting) | Hitung frekuensi tiap nilai, periksa yang langka | Ingin menemukan outlier di satu atau dua field | Daftar nilai langka |
| Grouping | Kelompokkan sekumpulan karakteristik spesifik atas data yang sudah dicurigai | Sudah punya himpunan menarik, ingin melihat yang muncul bersama | Kelompok item terkait |
| Clustering | Kelompokkan data berdasarkan kemiripan agregat, sering dibantu statistik | Data besar, pola belum jelas | Cluster dan outlier |

Perbedaan grouping dan clustering sering membingungkan [S2]:

- **Clustering** bekerja atas seluruh dataset, mengelompokkan berdasarkan karakteristik bersama untuk menemukan outlier, misalnya jumlah kemunculan yang tidak lazim dari perilaku yang umum. Biasanya butuh alat statistik atau ML.
- **Grouping** bekerja atas himpunan yang sudah dicurigai (hasil langkah sebelumnya), memakai beberapa karakteristik eksplisit, untuk melihat item mana yang muncul bersama. Intel 471 memberi contoh grouping atas sumber koneksi keluar untuk menemukan host yang melewati filter web, dan atas server DNS yang dipakai untuk menemukan resolver tidak standar [S2].

Sqrrl, dalam model hunting loop-nya (2015), menyebut stack counting dan clustering sebagai teknik "row-oriented" yang melengkapi analisis data bertaut dan visualisasi [S8]. Panduan Hunt Evil menyebut stacking sebagai teknik yang dipakai di banyak jenis hunt, dari lateral movement sampai C2 [S1]. Kelebihannya: sederhana, bisa dimulai bahkan dengan command line dan spreadsheet [S1][S2]. Kekurangannya: hanya bekerja baik pada field berkardinalitas rendah sampai sedang. Panduan yang sama mengingatkan bahwa efektivitas stacking bergantung pada input yang tersaring dengan baik: terlalu sedikit data tidak mengungkap apa pun, terlalu banyak membanjiri peninjau. Bila hasil terlalu besar, persempit input (misalnya satu subnet) atau ganti field yang di-stack (dari hostname ke kombinasi EventID dan username, atau dari IP tujuan ke port tujuan) [S1].

Analisis frekuensi (bagian 1.5) bukan teknik kelima yang terpisah; ia adalah stacking yang ditambah dimensi waktu: bukan hanya "berapa kali", tetapi "dengan jarak berapa". Model-Assisted hunting (M-ATH), tipe hunt ketiga PEAK yang memakai machine learning, berada di ujung clustering; Day ini tidak membahasnya lebih jauh karena stacking dan analisis frekuensi sudah memberi nilai besar tanpa infrastruktur ML.

Tabel berikut menerapkan pilihan teknik ke pertanyaan nyata hari ini. Baca dari kiri: bentuk pertanyaan menentukan teknik.

| Pertanyaan | Teknik |
|---|---|
| "Apakah host X menjalankan certutil dengan URL?" | Searching (hipotesis spesifik) |
| "Proses apa yang paling langka di lingkungan?" | Stacking |
| "Pasangan parent-child apa yang belum pernah ada bulan lalu?" | Stacking terhadap baseline (first-seen) |
| "Host ini mencurigakan; apa lagi yang terjadi bersamaan?" | Grouping |
| "Koneksi keluar mana yang berpola tidak wajar di seluruh data?" | Clustering / analisis frekuensi |
| "PC `JKT-WS-0541` polling teratur, C2 atau bukan?" | Analisis frekuensi untuk semua pasangan, lalu grouping dan pivot untuk kandidat |

Untuk pertanyaan Bambang, perhatikan baris terakhir. Memeriksa hanya `JKT-WS-0541` adalah searching, dan hasilnya hanya menjawab satu PC. Pertanyaan yang lebih berguna untuk SOC: "pasangan mana saja di seluruh proxy yang berperilaku seperti itu?" Itulah `HUNT-2027-005`.

### 1.2 Baselining: apa itu normal

Pertanyaan pertama Dimas ("normal itu didefinisikan bagaimana") adalah inti dari pelajaran `HUNT-2027-001`. Long tail 1.146 pasangan tidak bisa dinilai karena tidak ada pembanding: tidak ada yang tahu apakah pasangan itu muncul juga bulan lalu.

Baseline adalah gambaran perilaku normal yang menjadi pembanding. Tanpa baseline, kata "anomali" tidak punya arti. Tabel berikut membedakan dua bentuknya; baca kolom "Contoh" untuk menentukan bentuk mana yang dibutuhkan pertanyaanmu.

| Jenis | Isi | Contoh |
|---|---|---|
| Statis (daftar yang pernah terlihat) | Kombinasi nilai yang sudah pernah muncul di periode bersih | Pasangan parent-child, proses yang membuat koneksi keluar, user per host, tujuan yang dikenal polling teratur |
| Dinamis (distribusi/statistik) | Rata-rata, median, persentil, deviasi standar per entitas | Jumlah koneksi per jam per host, panjang query DNS, jumlah eksekusi per pasangan |

Splunk merumuskan baseline hunt (disebut juga Exploratory Data Analysis, salah satu dari tiga tipe hunt PEAK) sebagai langkah-langkah berikut [S7]:

- **Prepare:** pilih sumber data yang paling relevan, pelajari dokumentasinya dan arti field-nya, catat deteksi yang sudah ada dan tim pemilik sistemnya. Kelompokkan sistem yang mirip (misalnya "workstation pengguna" dan "server aplikasi") dan buat baseline terpisah per kelompok. Untuk kebanyakan sumber, 30 sampai 90 hari data biasanya cukup.
- **Execute:** kumpulkan data, buat data dictionary (nama field, tipe data, arti nilainya), lihat distribusi (rata-rata atau median untuk nilai numerik, nilai teratas untuk nilai kategorikal, dan kardinalitas), lalu cari outlier dengan stack counting (least frequency of occurrence) atau z-score (nilai yang berjarak sekitar dua sampai tiga deviasi standar dari rata-rata). Setiap outlier diselidiki untuk memutuskan apakah ia masalah keamanan atau keanehan jinak. Catat juga celah data dan hubungan antar-field, misalnya jumlah login per jam.
- **Act:** simpan data, query, dan hasil; dokumentasikan baseline (data dictionary, statistik, hubungan antar-field, dan daftar outlier yang sudah dikonfirmasi jinak); jadikan deteksi bila sebuah ambang atau hubungan layak menjadi alert, dan sisanya laporan atau dashboard; komunikasikan ke pemilik sistem, SOC, IR, dan detection engineer.

Panduan yang sama mengingatkan bahwa abnormal tidak sama dengan berbahaya, dan alert untuk semua perilaku abnormal hampir pasti membanjiri antrean dengan alert berkualitas rendah [S7].

Tiga keputusan praktis untuk PT JAB:

- **Kelompok host.** Baseline parent-child untuk workstation dan server dipisah. Server punya pola yang jauh lebih sempit, sehingga pasangan baru di server lebih bermakna. Day ini membangun baseline workstation ber-Sysmon saja.
- **Periode.** 1 sampai 31 Januari 2027 (31 hari, di dalam saran 30 sampai 90 hari). Periode harus berakhir sebelum jendela hunt dimulai.
- **Alasan menganggapnya bersih ditulis.** Baseline harus dibangun dari periode yang diyakini bersih dan diperbarui secara berkala, karena lingkungan berubah: software baru dipasang, user pindah peran, server dimigrasi. Baseline yang dibangun saat penyerang sudah ada akan menganggap perilaku penyerang normal. Untuk Januari 2027, alasannya: satu-satunya insiden di bulan itu, `INC-2027-001` (Senin 2027-01-11), adalah kompromi sesi akun di layanan cloud yang menurut laporan IR tidak melibatkan eksekusi proses di workstation; `HUNT-2027-001` tidak menemukan aktivitas berbahaya pada minggu terakhir Januari; dan isi baseline yang langka ditinjau dulu sebelum baseline dibekukan (bagian 2.4). Tinjau ulang isi baseline juga saat ada perubahan besar seperti rollout software atau migrasi.

Sebelum dihitung, nilai harus dinormalisasi. Di Windows, path tidak peka huruf besar/kecil, aplikasi menyimpan versi di nama folder (`...\Edge\Application\121.0.2277.128\msedge.exe`), installer membuat folder acak di `Temp`, dan setiap pengguna punya folder profil sendiri. Tanpa normalisasi, satu program bisa terpecah menjadi puluhan "pasangan langka", persis yang terjadi di `HUNT-2027-001`. Aturan normalisasinya sendiri menjadi bagian dari baseline: hunt yang membandingkan harus memakai aturan yang sama persis.

### 1.3 Menyimpan baseline

Pertanyaan kedua Dimas ("disimpan di mana supaya tidak dihitung ulang") muncul karena menghitung baseline 31 hari Sysmon dari raw event setiap Selasa dan Kamis memakan waktu dan membuat hasil antar-hunt tidak bisa dibandingkan.

Agar hunt berikutnya bisa membandingkan, baseline disimpan, bukan dihitung ulang dari nol tiap kali:

- **Lookup CSV (Splunk):** daftar kombinasi yang pernah terlihat. `outputlookup` menulis hasil search ke file lookup, dan `inputlookup append=true` menambahkan isi lookup lama ke hasil search yang sedang berjalan, sehingga baseline bisa digabung lalu ditulis ulang tanpa kehilangan isi lama [S4][S6]. Cocok untuk baseline statis. Di PT JAB nama file-nya mengikuti pola `jab_hunt_baseline_<topik>.csv`, misalnya `jab_hunt_baseline_parentchild.csv`.
- **Summary index atau saved search terjadwal:** untuk baseline dinamis yang dihitung berkala. Saved search harian menghitung statistik (misalnya rata-rata dan p95 koneksi per host) lalu menulis hasilnya ke index ringkasan, sehingga hunt berikutnya cukup membaca ringkasan, bukan data mentah berbulan-bulan.
- **CDB list (Wazuh):** file daftar key (dan nilai opsional) di manager Wazuh yang bisa dicocokkan oleh rule, misalnya daftar proses atau IP yang dianggap normal. Isinya dikelola manual atau lewat skrip, dan perubahan perlu restart manager agar terbaca.

Beberapa perilaku `outputlookup` di Splunk 10.6 yang menentukan apakah baseline-mu aman [S4]:

- Secara default (`append=false`) file lookup yang sudah ada ditimpa. File ditulis ke folder `lookups` milik app tempat search dijalankan, kecuali `createinapp=false` atau `create_context` diubah.
- `override_if_empty` default-nya true: bila search menghasilkan nol baris, file lama dihapus. Untuk build pertama baseline, `override_if_empty=false` mencegah baseline lenyap karena satu search gagal (misalnya Sysmon sedang tidak masuk).
- Dengan `append=true` pada file CSV, hanya field yang sudah ada di CSV yang ditulis; field baru hilang. Bila kolom baru ditambahkan ke baseline, tulis ulang file sekali tanpa `append`.
- Pembatasan siapa yang boleh menulis lookup diatur di `transforms.conf` dan `limits.conf`, dan default-nya semua user bisa menulis. Untuk lookup baseline, batasi penulisan ke role hunting (di PT JAB `jab_hunter`).

`inputlookup` adalah generating command, jadi biasanya ditulis paling depan dengan pipe di awal (`| inputlookup ...`). Dengan `append=true`, isi lookup ditambahkan ke hasil yang sedang berjalan, bukan menggantikannya, dan pola itulah yang dipakai untuk menggabungkan baseline lama dengan data baru [S6].

Secara default, pencocokan lookup CSV di Splunk peka huruf besar/kecil (setelan `case_sensitive_match` di definisi lookup; cek di versi-mu). Karena itu normalisasi ke huruf kecil dilakukan baik saat membangun baseline maupun saat membandingkan.

Baseline yang disimpan juga menjadi basis deteksi first-seen: "kombinasi yang tidak ada di baseline" adalah anomali. Pola ini sering dipakai detection engineer untuk perilaku yang jarang berubah, misalnya parent-child proses di server atau akun admin yang login ke host tertentu.

Pembaruan baseline punya jebakan sendiri. Bila baseline diperbarui otomatis setiap malam dengan data kemarin, pasangan baru yang berbahaya ikut menjadi "normal" keesokan harinya, kecuali ada yang meninjaunya lebih dulu. Dua cara mengatasinya: simpan kolom `first_seen` di lookup sehingga "apa yang baru dalam 7 hari terakhir" tetap bisa ditanyakan dari lookup itu sendiri, dan pastikan laporan first-seen ditinjau sebelum isinya dianggap normal. Kolom `first_seen` juga hanya sejauh retensi data saat baseline pertama dibangun; ia berarti "pertama terlihat sejak baseline dimulai", bukan "pertama kali ada di lingkungan".

### 1.4 Long tail: kenapa yang langka menarik, dan kapan tidak

Pertanyaan ketiga Dimas tajam: kalau di `HUNT-2027-001` yang langka ternyata jinak semua, kenapa yang langka masih layak dicurigai?

Di banyak dataset keamanan, sebagian kecil nilai muncul sangat sering (normal) dan ekor panjang nilai muncul jarang. Perilaku penyerang sering berada di ekor: proses yang hanya ada di satu host, domain yang hanya dikunjungi sekali, parent-child yang tak lazim [S1]. Penyerang yang masuk ke satu workstation menjalankan alatnya di satu host itu, bukan di 160 host sekaligus. Stacking dengan `where count <= N` mengambil ekor ini, dan PEAK menyebut teknik ini least frequency of occurrence [S7].

Tetapi kelangkaan hanya sinyal, dan ada empat situasi di mana sinyal itu lemah:

- **Lingkungan sepi atau data sedikit.** Di lab yang sepi, hampir semuanya langka, sehingga long tail tidak bermakna. Baseline butuh volume dan keberagaman aktivitas normal agar yang langka benar-benar menonjol.
- **Belum dinormalisasi.** Path berversi dan folder acak membuat program yang sama terlihat langka. Ini penyebab utama 1.146 pasangan di `HUNT-2027-001`.
- **Langka karena peran.** Satu-satunya engineer NOC yang memakai alat capture paket akan selalu langka. Itu sebabnya stacking yang baik memakai dua syarat: jarang dieksekusi dan hanya di sedikit host. Pasangan langka yang tersebar di banyak host biasanya software sah.
- **Penyerang yang meniru yang umum.** Jahat belum tentu langka. Penyerang yang memakai `powershell.exe` dari `explorer.exe` bersembunyi di kepala distribusi, bukan di ekor. Stacking tidak akan menemukannya; itu tugas searching dengan hipotesis spesifik.

Ambang "langka" juga tidak ditebak. Hitung dulu distribusi jumlah eksekusi per pasangan (persentil p5, p25, median, maksimum), lalu pilih ambang dengan alasan yang ditulis di laporan (bagian 2.4).

Jawaban untuk Dimas: yang langka layak dicurigai karena di situ penyerang biasanya berada, tetapi long tail adalah daftar periksa, bukan daftar tersangka. Jinaknya tiga pasangan di `HUNT-2027-001` bukan bukti bahwa teknik ini gagal; itu hasil sah yang sudah dijelaskan di laporan Day 01 bagian 2.4.

### 1.5 Analisis frekuensi: mengukur keteraturan dan pengaruh jitter

Grafik yang dilihat NOC adalah analisis frekuensi versi visual. Untuk menjawab Bambang secara sistematis, keteraturan perlu diukur dengan angka untuk semua pasangan, bukan dilihat satu per satu.

Intel 471 membedakan dua hal yang terkait [S2]:

- **Volumetrik:** seberapa banyak sesuatu (jumlah byte, jumlah koneksi). Berguna untuk exfiltration besar dan untuk menemukan yang paling sering atau paling jarang terlihat.
- **Frekuensi:** seberapa sering sesuatu terjadi, dan dengan pola apa. Berguna untuk menemukan pola yang sering ditemukan pada beacon malware yang menghubungi C2 pada interval teratur [S2]. Keduanya sering dipakai bersama.

Panduan Hunt Evil memuat contoh hunt di mana analisis frekuensi memperlihatkan beacon yang konsisten setiap dua jam dari trafik HTTP PUT yang otomatis [S1].

Beacon C2 memiliki ciri: koneksi berulang ke tujuan yang sama pada interval relatif tetap (dengan atau tanpa jitter). Hunting beacon mencari pasangan sumber-tujuan dengan banyak koneksi dan interval yang konsisten. Ini memakai kombinasi stacking (hitung per pasangan) dan analisis frekuensi (keteraturan interval).

Cara mengukurnya: urutkan koneksi per pasangan berdasarkan waktu, hitung selisih antar-koneksi (delta), lalu ringkas deltanya. Ukuran yang dipakai:

- **Rata-rata (mean)** dan **median** interval: berapa detik jarak tipikal antar-koneksi.
- **Deviasi standar (stdev):** seberapa jauh delta menyebar dari rata-rata. Di Splunk, `stdev()` menghitung deviasi standar sampel dan `stdevp()` deviasi standar populasi [S6].
- **Coefficient of variation (CV):** stdev dibagi rata-rata. CV membuat pasangan dengan interval 60 detik dan 1.800 detik bisa dibandingkan dengan satu ambang. CV 0,02 berarti delta bergeser sekitar 2% dari rata-ratanya.

Jitter adalah variasi acak yang sengaja ditambahkan framework C2 ke interval tidur beacon. Dalam profil Cobalt Strike, misalnya, jitter ditulis sebagai persentase waktu tidur acak yang ditambahkan ke komunikasi C2 [S11]. Dampaknya terhadap angka bisa dihitung. Tabel berikut memakai tiga deret contoh berisi 10 interval (dalam detik) yang dihitung ulang; baca kolom CV dan bandingkan dengan ambang yang biasa dipakai.

| Deret | Isi 10 interval | Rata-rata | Median | Stdev (sampel) | CV |
|---|---|---|---|---|---|
| A, agent sah 300 detik | 300, 301, 299, 300, 302, 298, 300, 301, 299, 300 | 300,0 | 300 | 1,15 | 0,004 |
| B, beacon 300 detik dengan jitter sekitar 20% | 312, 251, 347, 289, 266, 358, 301, 244, 333, 279 | 298,0 | 295 | 39,47 | 0,132 |
| C, deret A dengan interval ke-10 berupa jeda malam 14 jam | 300, 301, 299, 300, 302, 298, 300, 301, 299, 50.400 | 5.310,0 | 300 | 15.843,01 | 2,984 |

Tiga pelajaran dari tabel itu:

- **Ambang 10% terlalu ketat untuk beacon berjitter.** Syarat `sd_interval < avg_interval*0.1` (CV di bawah 0,1) meloloskan deret A tetapi membuang deret B, padahal B adalah beacon. Ambang CV sekitar 0,2 menangkap B. Melonggarkan ambang menangkap beacon berjitter, tetapi menambah false positive dari polling sah yang kurang rapi.
- **Satu jeda merusak rata-rata dan stdev.** Workstation kantor dimatikan atau tidur di malam hari. Satu jeda 14 jam membuat deret C, yang sebenarnya sama rapinya dengan A, terlihat sangat tidak teratur (CV 2,984). Median tetap 300 karena median tahan terhadap nilai ekstrem.
- **Buang jeda dengan median, lalu ukur ulang.** Bila delta yang lebih besar dari tiga kali median dibuang, deret C tinggal 9 interval dengan rata-rata 300,0, stdev 1,22, dan CV 0,004, sama dengan A. Di Splunk, median per pasangan dihitung dengan `eventstats` sebelum filter (bagian 2.2).

Ada pembatas lain yang bersifat data, bukan statistik. Di log Squid format native, kolom waktu dicatat saat transaksi selesai, bukan saat dimulai, dan kolom durasi berisi lama transaksi dalam milidetik; waktu mulai diperkirakan dengan mengurangkan durasi dari waktu catat [S12]. Bila beacon kadang lambat dilayani, interval yang dihitung dari waktu catat ikut bergeser. Untuk trafik HTTPS tanpa inspeksi TLS, proxy hanya melihat permintaan CONNECT ke host dan port, satu baris per tunnel; beacon yang memakai ulang satu koneksi panjang menghasilkan sedikit baris, sehingga tidak terlihat teratur di proxy. Cek perilaku logging CONNECT di konfigurasi Squid-mu.

### 1.6 Beacon atau agent sah: sinyal yang membedakan

Pertanyaan keempat Dimas adalah inti dari kasus Bambang. Dalam satu minggu di proxy PT JAB, ratusan workstation "ngobrol teratur" ke luar: antivirus, Teams, aplikasi internal `JAB DocSync` yang memeriksa update. Bila keteraturan saja yang dipakai, semua itu adalah kandidat C2.

Keteraturan hanya satu dari beberapa sinyal. RITA (Real Intelligence Threat Analytics), alat open source dari Active Countermeasures untuk menganalisis log Zeek dan mencari C2, memberi contoh bagaimana alat yang matang menggabungkan sinyal. Di versi 5 (rilis terbaru v5.1.2, 7 Mei 2026), skor beacon terdiri dari empat subskor dengan bobot default masing-masing 0,25: keteraturan timestamp, keteraturan ukuran data, durasi (seberapa banyak jam dalam sehari pasangan itu terlihat), dan histogram pola koneksi per jam [S9][S10]. Pasangan dengan kurang dari 4 koneksi unik tidak dianalisis, subskor durasi baru dihitung setelah pasangan terlihat lebih dari 6 jam, dan skor dinaikkan 15% bila prevalence-nya paling banyak 2% serta diturunkan 15% bila prevalence-nya minimal 50% [S10]. Konfigurasinya juga mengingatkan bahwa bila proxy berada di jaringan internal, IP proxy harus dimasukkan ke daftar yang selalu disertakan, karena semua trafik keluar terlihat berasal dari proxy [S10].

Dari sana, sinyal yang dipakai di PT JAB disusun seperti tabel berikut. Baca kolom kanan: tidak ada satu sinyal pun yang cukup sendirian.

| Sinyal | Mengarah ke beacon berbahaya bila | Mengarah ke agent sah bila | Catatan |
|---|---|---|---|
| Keteraturan interval (CV) | Rendah, dengan atau tanpa jitter | Sama-sama rendah | Paling lemah sebagai pembeda, kuat sebagai penyaring awal |
| Prevalence tujuan | Hanya satu atau segelintir host | Ratusan host dengan pola yang sama | Penyerang bisa juga menyebar; prevalence tinggi diverifikasi per tujuan, bukan diabaikan |
| Pemilik dan inventaris | Tidak ada tim yang mengakui | Ada pemilik, tiket, atau paket distribusi | Konfirmasi ke pemilik adalah bukti terkuat untuk label jinak |
| Ukuran data | Kecil dan seragam, sesekali melonjak (perintah atau upload) | Sesuai fungsi (update kecil, sinkronisasi besar) | Butuh field byte yang akurat |
| Proses pemanggil | Proses tak lazim, di folder yang bisa ditulis user | Biner bertanda tangan di `Program Files` | Butuh Sysmon EID 3 atau EDR; proxy saja tidak tahu proses |
| Umur dan reputasi tujuan | Domain muda, belum terkategori, baru pertama terlihat | Domain vendor yang dikenal | Reputasi bersih bukan bukti aman |
| Pola harian | Terus berjalan saat pengguna tidak aktif | Mengikuti jam kerja atau jadwal layanan | Laptop yang dibiarkan menyala membuat keduanya mirip |

Dua batas penting. Pertama, keteraturan bisa disamarkan: penyerang yang memakai jitter besar atau interval sangat panjang tidak akan lolos ambang CV atau ambang jumlah koneksi. Sebaliknya, trafik sah yang tidak teratur juga bisa membawa C2. Kedua, tujuan dengan prevalence tinggi tidak otomatis aman; penyerang yang menyusup lewat software yang didistribusikan ke semua host akan terlihat "umum". Karena itu tujuan berprevalence tinggi diverifikasi per tujuan (siapa pemiliknya, apakah domainnya benar milik vendor), bukan dibuang dari daftar.

### 1.7 Memperkecil ruang, bukan memberi jawaban

Pertanyaan terakhir Dimas ("supaya L1 tidak menganggap hasil stacking itu vonis") dan pertanyaan Bambang ("ini C2 bukan?") dijawab dengan prinsip yang sama.

Semua teknik di Day ini memperkecil data besar menjadi daftar kecil; mereka tidak memberi verdict. Setiap item di daftar hasil tetap perlu ditinjau manusia dan diberi label (jinak, perlu investigasi, inkonklusif, atau data tidak cukup), seperti di Day 01. Stacking yang menghasilkan 500 baris "langka" belum menyelesaikan apa pun; stacking yang baik menghasilkan daftar yang cukup kecil untuk ditinjau dalam waktu hunt.

Batas yang harus ditulis di setiap laporan yang memakai teknik ini:

- **Batas data.** Hunt beacon dari proxy hanya melihat trafik yang lewat proxy. Koneksi langsung lewat firewall, DNS, dan trafik dari host tanpa proxy berada di luar cakupan. Hunt first-seen dari Sysmon hanya melihat sekitar 40% workstation.
- **Batas ambang.** Beacon dengan interval di atas satu jam, dengan jitter besar, atau yang hanya aktif sebentar tidak lolos ambang jumlah koneksi dan CV. Ambang ditulis di laporan supaya pembaca tahu apa yang tidak tertangkap.
- **Batas baseline.** First-seen hanya sebaik baseline-nya. Bila baseline mencakup periode yang tercemar, atau normalisasinya terlalu agresif sehingga dua program berbeda menjadi satu, yang baru tidak akan terlihat baru.
- **Batas retensi.** Dengan retensi proxy 30 hari, "domain ini pertama terlihat 19 Januari" berarti "pertama terlihat dalam 30 hari terakhir".

Untuk Bambang, artinya: grafik NOC adalah pemicu yang bagus (TaHiTI menyebut keahlian domain sebagai salah satu sumber pemicu hunt), tetapi grafik itu sendiri belum menjawab "C2 atau bukan". Jawabannya datang dari konteks per kandidat (bagian 2.3), dan alasan tidak ada alert adalah karena keteraturan saja memang tidak dijadikan rule di ES: rule seperti itu akan memunculkan ratusan alert per hari dari agent sah.

## 2. Contoh dan langkah praktis: dua hunt hari Kamis

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Query ditulis untuk Splunk PT JAB; untuk latihan, jalankan versi yang disesuaikan di lab pribadi (bagian 3). Semua domain eksternal disamarkan dengan akhiran `.example` atau `.example.net`; di log nyata, layanan seperti Microsoft Defender dan Teams muncul dengan domain resmi vendornya.

**Asumsi data proxy:** log Squid kantor Jakarta dan Bandung masuk `index=proxy` dengan `sourcetype=squid:access`, dan add-on mengekstrak `src` (IP klien), `dest` (host tujuan; untuk CONNECT, host tanpa port), `bytes`, `duration` (milidetik), `http_method`, `user`, dan `http_user_agent`. Format native Squid tidak memuat user agent, jadi PT JAB memakai `logformat` kustom yang menambahkannya. Cek nama dan satuan field ini di add-on dan `squid.conf` versi-mu sebelum menjalankan.

**Asumsi data Sysmon:** sama dengan Day 01: `index=sysmon`, `sourcetype=XmlWinEventLog`, field `ParentImage`, `Image`, `host`, `User` terekstrak.

### 2.1 `HUNT-2027-005`: abstract dan tahap A (stacking pasangan)

Pesan Bambang adalah pemicu. Daripada memeriksa satu PC, kamu membuka hunt untuk seluruh proxy, karena pertanyaan yang berguna bagi SOC adalah "pasangan mana saja yang berperilaku seperti ini".

```
ID             : HUNT-2027-005
Dibuat         : 2027-02-11 (Kamis) 08:40, pemilik: <kamu>, reviewer: Dimas Prasetyo
Trigger        : Keahlian domain (NOC) - Bambang Hartono melihat JKT-WS-0541 polling teratur
                 ke internet di grafik request per klien proxy Jakarta; sekaligus kandidat
                 backlog dari pelajaran INC-2026-026 (beacon berkala ke domain baru, Day 03)
Tipe (PEAK)    : Baseline (analisis frekuensi), dilanjutkan hypothesis-driven per kandidat
Hipotesis      : Ada workstation PT JAB yang berkomunikasi lewat proxy ke tujuan eksternal dengan
                 interval teratur (beacon), dan tujuan itu tidak dimiliki layanan atau agent
                 yang dikenal; pola ini menandakan C2 lewat protokol web.
ATT&CK         : T1071.001 Application Layer Protocol: Web Protocols (Command and Control, TA0011)
Data           : index=proxy sourcetype=squid:access, src 10.10.0.0/16 (Jakarta) dan
                 10.30.0.0/16 (Bandung), Senin 2027-02-01 00:00 sampai Senin 2027-02-08 00:00 WIB
Di luar cakupan: trafik yang tidak lewat proxy (langsung via firewall, DNS), server data center,
                 POP selain Jakarta dan Bandung, beacon dengan interval di atas 1 jam atau
                 aktif kurang dari 24 jam dalam seminggu, beacon yang memakai satu tunnel panjang
Kriteria sukses: Semua pasangan yang lolos tahap B dengan dest_hosts <= 10 ditinjau per pasangan;
                 tujuan dengan dest_hosts > 10 diverifikasi per tujuan (pemilik dan domain);
                 tiap item berlabel jinak / perlu investigasi / inkonklusif / data tidak cukup
FP diketahui   : Agent antivirus/EDR, aplikasi kolaborasi, updater aplikasi, agent monitoring
Handover       : IR (Dimas) bila ditemukan; Sari Kusuma untuk usulan laporan berkala;
                 Bambang untuk jawaban dan inventaris agent NOC
Target selesai : Kamis 2027-02-11
```

Tahap A menjawab pertanyaan kasar dulu: pasangan mana yang cukup sering dan cukup lama aktif untuk layak diukur keteraturannya.

**Tujuan:** mengurangi semua pasangan `src` dan `dest` selama 7 hari menjadi kandidat yang punya cukup koneksi untuk dihitung intervalnya, sambil mencatat prevalence tiap tujuan.

```
index=proxy sourcetype=squid:access
    earliest="02/01/2027:00:00:00" latest="02/08/2027:00:00:00"
    (src=10.10.0.0/16 OR src=10.30.0.0/16)
| bin span=1h _time AS hour
| stats count AS conns dc(hour) AS hours_seen BY src dest
| eventstats dc(src) AS dest_hosts BY dest
| where conns >= 100 AND hours_seen >= 24
| outputlookup override_if_empty=false jab_hunt_005_candidates.csv
```

Tabel berikut menjelaskan tiap baris; perhatikan urutan `eventstats` dan `where`.

| Baris | Fungsi |
|---|---|
| `src=10.10.0.0/16 OR src=10.30.0.0/16` | Hanya klien kantor Jakarta dan Bandung; command `search` mendukung pencocokan CIDR |
| `bin span=1h _time AS hour` | Membulatkan waktu ke jam, disimpan di field baru `hour` tanpa mengubah `_time` |
| `stats count AS conns dc(hour) AS hours_seen BY src dest` | Stacking per pasangan: jumlah koneksi dan berapa jam berbeda pasangan itu aktif |
| `eventstats dc(src) AS dest_hosts BY dest` | Prevalence: berapa host yang menghubungi tujuan itu. `eventstats` menambahkan hasil agregasi ke setiap baris tanpa menghapus baris [S6] |
| `where conns >= 100 AND hours_seen >= 24` | Kandidat: minimal 100 koneksi dan aktif minimal 24 jam berbeda. Dipasang setelah `eventstats` supaya prevalence dihitung dari semua pasangan, bukan hanya kandidat |
| `outputlookup override_if_empty=false ...` | Menyimpan kandidat untuk tahap B; file lama tidak dihapus bila hasil kosong [S4] |

Karena `eventstats` di sini berjalan setelah `stats`, ia hanya mengolah sekitar seratus ribu baris ringkasan, bukan jutaan event mentah. Itu pola yang sama-sama benar dan jauh lebih ringan daripada menjalankan `eventstats` atas raw event.

Keluaran ilustrasi (ringkas):

```
Event proxy dari 10.10.0.0/16 dan 10.30.0.0/16       : 58.912.407
Host sumber unik (IP)                                 : 351
Pasangan src-dest unik                                : 118.477
Pasangan dengan conns >= 100 dan hours_seen >= 24      : 2.947  (ditulis ke jab_hunt_005_candidates.csv)
```

**Cara membaca hasil:** 2.947 pasangan masih terlalu banyak untuk ditinjau, tetapi cukup kecil untuk dihitung intervalnya. Ambang 100 koneksi dan 24 jam ditulis di abstract sebagai batas: beacon tiap 2 jam yang aktif 40 jam hanya menghasilkan sekitar 20 koneksi dan tidak masuk.

**Variasi:** stacking `dest` saja dengan `dc(src)` untuk melihat tujuan yang hanya dihubungi satu host selama seminggu; atau stacking `http_user_agent` per `dest`, karena user agent yang tidak lazim adalah salah satu field stacking yang disebut Intel 471 [S2].

**Kapan gagal:** `dest` berisi IP, bukan nama host, untuk sebagian baris (misalnya CONNECT langsung ke IP), sehingga satu layanan terpecah; `src` adalah IP yang berganti karena DHCP, sehingga satu workstation terlihat sebagai dua sumber dalam seminggu. Untuk kasus kedua, petakan IP ke host dengan log DHCP pada rentang yang sama sebelum menyimpulkan.

### 2.2 `HUNT-2027-005` tahap B: interval, jitter, dan CV

Tahap B mengukur keteraturan untuk 2.947 kandidat, memakai pelajaran deret C di bagian 1.5: jeda malam harus dibuang dulu.

**Tujuan:** menghitung median, rata-rata, stdev, dan CV interval per pasangan kandidat, setelah membuang jeda yang lebih panjang dari tiga kali median.

```
index=proxy sourcetype=squid:access
    earliest="02/01/2027:00:00:00" latest="02/08/2027:00:00:00"
    [| inputlookup jab_hunt_005_candidates.csv | fields src dest]
| eval start=_time-(duration/1000)
| sort 0 src dest start
| streamstats current=f last(start) AS prev_start BY src dest
| eval delta=round(start-prev_start, 1)
| where isnotnull(delta)
| eventstats median(delta) AS med_int BY src dest
| where delta <= 3*med_int
| stats count AS intervals avg(delta) AS avg_int stdev(delta) AS sd_int
        avg(bytes) AS avg_bytes stdev(bytes) AS sd_bytes max(med_int) AS med_int BY src dest
| eval cv=round(sd_int/avg_int, 3), cv_bytes=round(sd_bytes/avg_bytes, 2)
| where med_int >= 30 AND cv <= 0.2
| lookup jab_hunt_005_candidates.csv src dest OUTPUT conns hours_seen dest_hosts
| sort dest_hosts cv
```

Tabel berikut menjelaskan bagian yang paling sering salah.

| Bagian | Fungsi |
|---|---|
| `[\| inputlookup jab_hunt_005_candidates.csv \| fields src dest]` | Subsearch yang mengubah 2.947 baris kandidat menjadi filter `(src=... AND dest=...) OR ...`, sehingga hanya event kandidat yang dibaca. Batas default subsearch umumnya 10.000 hasil (cek `maxout` di `limits.conf`), jadi 2.947 masih aman |
| `eval start=_time-(duration/1000)` | Squid mencatat waktu selesai; waktu mulai diperkirakan dengan mengurangi durasi (milidetik) [S12] |
| `sort 0 src dest start` | Mengurutkan semua event (angka 0 berarti tanpa batas jumlah) per pasangan lalu per waktu, menaik |
| `streamstats current=f last(start) AS prev_start BY src dest` | `current=f` membuat event saat ini tidak ikut dihitung, sehingga `last(start)` adalah waktu mulai koneksi sebelumnya pada pasangan yang sama [S4] |
| `eventstats median(delta) AS med_int BY src dest` | Median interval per pasangan ditempel ke setiap event, supaya bisa dipakai sebagai filter di baris berikutnya [S6] |
| `where delta <= 3*med_int` | Membuang jeda malam, tidur, dan laptop dibawa pulang |
| `stdev(delta)` | Deviasi standar sampel interval [S6] |
| `cv`, `cv_bytes` | Keteraturan interval dan keseragaman ukuran |
| `where med_int >= 30 AND cv <= 0.2` | Interval minimal 30 detik (membuang sesi interaktif yang rapat) dan CV maksimal 0,2 (menangkap jitter sekitar 20%, deret B) |

Dokumentasi `streamstats` menyebut batas default 10.000 event dari setelan `max_stream_window` di `limits.conf` bila `window` dan `time_window` tidak diisi [S4]. Karena event sudah diurutkan per pasangan, koneksi sebelumnya selalu bersebelahan dengan koneksi saat ini, sehingga `last()` tidak bergantung pada jendela yang panjang; cek perilakunya di versi-mu bila hasilnya terlihat janggal. `sort 0` dan `eventstats` atas jutaan event juga memakan memori search head; `eventstats` dibatasi `max_mem_usage_mb` dan berhenti menambahkan field bila batasnya tercapai [S6]. Itu alasan tahap A dipisah: tahap B hanya membaca event dari kandidat.

Keluaran ilustrasi, diringkas per tujuan dengan `| stats count AS pairs_regular max(dest_hosts) AS dest_hosts median(med_int) AS med_int median(cv) AS med_cv BY dest`:

```
dest                              pairs_regular  dest_hosts  med_int  med_cv
wdcp.mde-cloud.example.net                  289         336      300   0.030
presence.teams-svc.example.net              271         330       60   0.050
docsync-update.jab.example                  181         196      900   0.020
probe.netmon.example.net                      6           6       60   0.015
cloudprint.printvendor.example                3           3      600   0.040
api.statuspulse.example                       1           1     1800   0.080
```

Total 751 pasangan lolos tahap B (289 + 271 + 181 + 6 + 3 + 1), terkumpul di enam tujuan. Sepuluh pasangan berada di tujuan dengan `dest_hosts` paling banyak 10, dan itulah yang ditinjau per pasangan. Tiga baris yang mewakili tiga tujuan itu:

```
src           dest                            conns  hours_seen  med_int  avg_int  sd_int  cv     avg_bytes  cv_bytes  dest_hosts
10.10.42.87   probe.netmon.example.net        10080         168       60     60.0     0.9  0.015      14812      0.01           6
10.10.31.24   cloudprint.printvendor.example    313          52      600    601.2    24.0  0.040       3410      0.05           3
10.30.12.54   api.statuspulse.example           243         121     1800   1796.4   143.7  0.080       5912      0.03           1
```

(Lima pasangan probe lain dan dua pasangan cloudprint lain berpola hampir sama dan tidak ditampilkan.)

**Cara membaca hasil:**

- Angka-angkanya konsisten dengan fungsinya. `10.10.42.87` (`JKT-WS-0541`) membuat koneksi setiap 60 detik selama 168 jam, yaitu 604.800 detik dibagi 60, sama dengan 10.080 koneksi: PC itu menyala terus sepanjang minggu. Pasangan Bandung membuat 243 koneksi dengan median 1.800 detik selama 121 jam berbeda, kira-kira dua koneksi per jam aktif.
- CV semua baris jauh di bawah 0,2, jadi keteraturan tidak membedakan apa pun di sini. Yang membedakan adalah prevalence: tiga tujuan teratas dihubungi ratusan host, tiga terbawah hanya 6, 3, dan 1 host. Dengan 351 IP sumber, prevalence `probe.netmon.example.net` sekitar 1,7% dan `api.statuspulse.example` sekitar 0,28%; dalam logika RITA, keduanya akan dinaikkan skornya, sedangkan Defender (336 dari 351, sekitar 96%) akan diturunkan [S10].
- Tujuan berprevalence tinggi diverifikasi per tujuan: `wdcp.mde-cloud.example.net` dan `presence.teams-svc.example.net` adalah endpoint layanan Microsoft yang dipakai Defender dan Teams (dicocokkan dengan daftar endpoint resmi vendor oleh tim Infrastruktur), dan `docsync-update.jab.example` adalah server update `JAB DocSync` milik PT JAB sendiri, yang memeriksa versi baru setiap 15 menit. Ketiganya jinak.

**Variasi:** ganti CV dengan rasio median absolute deviation terhadap median (MAD dibagi median), yang lebih tahan terhadap sisa jeda yang tidak terbuang; atau tambahkan `dc(date_hour)` untuk melihat apakah pasangan aktif di luar jam kerja. Untuk data tanpa durasi (misalnya Sysmon EID 3), pakai `_time` langsung.

**Kapan gagal:** beacon dengan jitter di atas sekitar 20% (CV melewati 0,2); beacon yang memakai satu tunnel HTTPS panjang sehingga proxy hanya mencatat sedikit baris; beacon tiap beberapa jam yang tidak lolos tahap A; field `duration` kosong atau bersatuan detik, sehingga `start` salah; dan IP sumber yang berganti di tengah minggu.

### 2.3 Grouping dan pivot untuk kandidat

Sepuluh pasangan berprevalence rendah sekarang ditinjau. Langkah ini adalah grouping (apa lagi yang terjadi di host itu pada saat yang sama) dan pivot (proses mana yang membuat koneksi), karena proxy tidak tahu proses.

**Kandidat 1, `JKT-WS-0541` (pertanyaan Bambang).** Host ini termasuk OU `Workstations-EDR`, jadi Sysmon EID 3 (koneksi jaringan) tersedia.

```
index=sysmon sourcetype=XmlWinEventLog EventCode=3 host=JKT-WS-0541
    earliest="02/04/2027:10:00:00" latest="02/04/2027:10:10:00"
| stats count values(DestinationIp) AS dst_ip values(DestinationPort) AS dst_port BY Image User
```

Keluaran ilustrasi:

```
Image                                              User                  count  dst_ip       dst_port
C:\Program Files\NetProbe Agent\probeagent.exe     NT AUTHORITY\SYSTEM      10  10.20.3.60   3128
```

**Cara membaca hasil:** tujuan di Sysmon adalah `10.20.3.60:3128`, yaitu `jkt-proxy01`, bukan host internet. Di jaringan dengan proxy eksplisit, Sysmon hanya melihat koneksi ke proxy; tujuan akhir dicocokkan lewat waktu dengan log proxy. Sepuluh koneksi dalam 10 menit cocok dengan interval 60 detik. `probeagent.exe` berada di `Program Files`, berjalan sebagai service, dan bertanda tangan vendor (dicek di halaman file MDE). Konfirmasi ke pemiliknya menyelesaikan kasus: tim Service Assurance di bawah NOC memasang agent synthetic monitoring di 6 PC kantor pada November 2026 untuk mengukur latensi HTTPS dari kantor ke layanan pemantauan vendor. Tim transport NOC yang melihat grafik tidak tahu tentang pemasangan itu. Label: jinak.

**Kandidat 2, tiga pasangan `cloudprint.printvendor.example`.** Tiga workstation Keuangan menjalankan agent driver printer multifungsi baru yang melapor status ke cloud vendor setiap 10 menit, sesuai tiket pemasangan printer tim IT bulan Januari. Label: jinak.

**Kandidat 3, `10.30.12.54` (`BDG-WS-0196`) ke `api.statuspulse.example`.** Laptop ini milik `rizal.siregar` (sales korporat Bandung). Ia berada di luar OU `Workstations-EDR` (tanpa Sysmon), tetapi punya Microsoft Defender for Endpoint. Grouping di proxy memperlihatkan apa yang muncul bersama beacon:

```
index=proxy sourcetype=squid:access src=10.30.12.54
    earliest="02/03/2027:08:00:00" latest="02/04/2027:08:00:00"
| bin span=30m _time
| stats dc(dest) AS n_dest values(dest) AS dests count BY _time
| eval only_pulse=if(n_dest=1 AND dests="api.statuspulse.example", "ya", "tidak")
| stats count AS windows sum(eval(if(only_pulse="ya",1,0))) AS windows_only_pulse
```

Keluaran ilustrasi: dari 48 jendela 30 menit pada Rabu 08:00 sampai Kamis 08:00, laptop aktif di 31 jendela; 19 di antaranya (jam kerja) berisi banyak tujuan (browsing, M365, CRM), sedangkan 12 jendela (malam, laptop dibiarkan menyala) hanya berisi `api.statuspulse.example`.

Pivot berikutnya memberi tiga fakta:

- **Proses.** Advanced hunting MDE (`DeviceNetworkEvents`, retensi 30 hari) menunjukkan koneksi ke `api.statuspulse.example` dibuat oleh `msedge.exe`. Browser berbasis Chromium menjalankan permintaan jaringan dari proses layanan jaringannya sendiri, sehingga dari data jaringan tidak terlihat tab atau ekstensi mana yang memanggil.
- **Tujuan.** Di `index=dns`, domain itu me-resolve ke `198.51.100.77`. Pencarian `index=proxy dest=api.statuspulse.example` sejak awal retensi (sekitar 12 Januari) menunjukkan kemunculan pertama Selasa 2027-01-19 09:12, hanya dari laptop ini. Domain belum terkategori di proxy dan tidak ada di feed threat intelligence ES. Ukuran tiap koneksi seragam (rata-rata 5.912 byte, CV 0,03), tanpa lonjakan upload.
- **Konfirmasi.** `rizal.siregar` sedang cuti sampai Senin 2027-02-15 dan laptopnya tidak tersambung sejak Jumat sore. Tidak ada inspeksi TLS, jadi isi permintaan tidak terlihat. Inventaris ekstensi browser tidak dikumpulkan PT JAB saat ini.

Label: inkonklusif. Polanya cocok dengan ekstensi browser atau tab status yang polling (bisa sah, bisa juga ekstensi yang disalahgunakan sebagai C2, T1176.001 Software Extensions: Browser Extensions), tetapi datanya belum cukup untuk memutuskan, dan tidak ada indikasi aktivitas lanjutan (tidak ada upload, tidak ada host lain, tidak ada proses baru yang terlihat MDE). Ini bukan insiden. Item masuk backlog dengan tiga langkah: konfirmasi ke pengguna pada 15 Februari, cek ketersediaan inventaris ekstensi browser di lisensi MDE PT JAB, dan cari host lain yang me-resolve domain atau menghubungi IP yang sama di `index=dns` dan `index=firewall`. Pola beacon lewat browser ini dibahas lagi di Day 12. Dimas diberi tahu lewat laporan, tanpa eskalasi IR.

**Kapan gagal:** grouping dijalankan di jendela yang terlalu lebar sehingga semua host terlihat "ramai"; atau pivot berhenti di proxy padahal host punya Sysmon atau EDR yang bisa menunjukkan proses.

### 2.4 Normalisasi path dan ambang dari distribusi

Bagian ini menjawab pelajaran `HUNT-2027-001` secara langsung: sebelum baseline parent-child disimpan, path dinormalisasi dan ambang "langka" ditetapkan dari distribusi.

**Tujuan:** menyeragamkan `ParentImage` dan `Image` menjadi `parent_n` dan `child_n`, lalu mengukur distribusi jumlah eksekusi per pasangan di Januari 2027.

Normalisasi disimpan sebagai search macro `jab_norm_parentchild` (`Settings > Advanced search > Search macros`) di app hunting, supaya baseline dan hunt memakai aturan yang sama persis. Isi macro:

```
eval parent_n=replace(lower(ParentImage), "\\\\", "/"), child_n=replace(lower(Image), "\\\\", "/")
| eval parent_n=replace(parent_n, "^c:/users/[^/]+/", "c:/users/<user>/"),
       child_n=replace(child_n, "^c:/users/[^/]+/", "c:/users/<user>/")
| eval parent_n=replace(parent_n, "/[a-z_-]*\d+(\.\d+)+/", "/<ver>/"),
       child_n=replace(child_n, "/[a-z_-]*\d+(\.\d+)+/", "/<ver>/")
| eval parent_n=replace(parent_n, "/temp/[^/]+/", "/temp/<rnd>/"),
       child_n=replace(child_n, "/temp/[^/]+/", "/temp/<rnd>/")
| eval parent_n=replace(parent_n, "\{?[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\}?", "<guid>"),
       child_n=replace(child_n, "\{?[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\}?", "<guid>")
```

Tabel berikut menjelaskan tiap aturan; baca kolom kanan untuk tahu apa yang hilang karena aturan itu.

| Aturan | Fungsi | Yang ikut hilang |
|---|---|---|
| `lower(...)` lalu `replace(..., "\\\\", "/")` | Huruf kecil dan backslash menjadi `/`. Di string SPL, `\\\\` menjadi regex `\\` yang cocok dengan satu backslash; setelah ini regex berikutnya tidak perlu escape backslash | Tidak ada; path Windows memang tidak peka huruf |
| `^c:/users/[^/]+/` | Folder profil pengguna menjadi `<user>` | Siapa penggunanya (tetap ada di field `User`) |
| `/[a-z_-]*\d+(\.\d+)+/` | Segmen folder berversi (`121.0.2277.128`, `app-1.6.00.4472`, `4.2.0`) menjadi `<ver>` | Versi; juga `v1.0` di path PowerShell ikut menjadi `<ver>`, dan itu diterima karena konsisten di kedua sisi |
| `/temp/[^/]+/` | Folder acak installer di dalam `Temp` menjadi `<rnd>` | Nama folder sementara |
| `\{?...\}?` (pola GUID) | Folder GUID (misalnya di `Package Cache`) menjadi `<guid>` | GUID paket |

Regex diuji dengan kasus positif dan negatif sebelum dipakai. Tabel ini memperlihatkan hasil normalisasi atas contoh path; baris terakhir adalah kasus negatif yang memang tidak boleh berubah.

| Path asli | Hasil normalisasi |
|---|---|
| `C:\Users\rizal.siregar\AppData\Local\Temp\is-4QK2N.tmp\setup.tmp` | `c:/users/<user>/appdata/local/temp/<rnd>/setup.tmp` |
| `C:\Program Files (x86)\Microsoft\Edge\Application\121.0.2277.128\msedge.exe` | `c:/program files (x86)/microsoft/edge/application/<ver>/msedge.exe` |
| `C:\Program Files\JAB DocSync\4.2.0\jabdocsync-migrate.exe` | `c:/program files/jab docsync/<ver>/jabdocsync-migrate.exe` |
| `C:\ProgramData\Package Cache\{3B4F2C1A-9D8E-4F7B-A1C2-5E6D7F8A9B0C}\vc_redist.x64.exe` | `c:/programdata/package cache/<guid>/vc_redist.x64.exe` |
| `C:\Windows\Temp\abc.exe` (file langsung di `Temp`, bukan folder) | `c:/windows/temp/abc.exe` |

Query distribusi atas Januari 2027:

```
index=sysmon sourcetype=XmlWinEventLog EventCode=1
    earliest="01/01/2027:00:00:00" latest="02/01/2027:00:00:00"
| `jab_norm_parentchild`
| stats count AS executions dc(host) AS hosts BY parent_n child_n
| stats count AS pairs p5(executions) AS p5 p25(executions) AS p25 median(executions) AS p50
        max(executions) AS max count(eval(executions<=3)) AS rare3
```

`p5()` dan `p25()` adalah penulisan singkat fungsi persentil (`perc5()`, `perc25()`) yang juga diterima Splunk; cek di versi-mu. Bila butuh angka persis, `exactperc` tersedia, dengan biaya sumber daya besar untuk field berkardinalitas tinggi [S6].

Tabel berikut membandingkan hasil dengan dan tanpa normalisasi (keluaran ilustrasi, 20.164.882 event EID 1 di Januari). Baca baris "Pasangan dengan executions <= 3", karena itulah ukuran long tail.

| Ukuran | Path mentah | Path dinormalisasi |
|---|---|---|
| Pasangan unik | 8.946 | 2.611 |
| p5 / p25 / median eksekusi | 1 / 1 / 6 | 1 / 3 / 41 |
| Pasangan dengan executions <= 3 | 4.170 (46,6%) | 702 (26,9%) |
| Maksimum eksekusi satu pasangan | 1.204.388 | 1.204.388 |

**Cara membaca hasil:** normalisasi memangkas pasangan unik sekitar 71% dan long tail dari 4.170 menjadi 702. p25 = 3 berarti seperempat pasangan muncul tiga kali atau kurang; ambang `executions <= 3` mengambil sedikit di atas seperempat data. 702 masih terlalu banyak untuk ditinjau sekali duduk, sehingga syarat kedua dibutuhkan: pasangan hanya di satu host dan child berada di folder yang bisa ditulis pengguna. Tulis angka distribusi ini di laporan hunt sebagai alasan ambang.

```
| inputlookup jab_hunt_baseline_parentchild.csv
| where executions <= 3 AND hosts = 1
    AND match(child_n, "^c:/(users/<user>|programdata|windows/temp)/")
| sort first_seen
```

Query ini dijalankan setelah baseline disimpan (bagian 2.5) dan sebelum baseline dinyatakan berlaku. Hasilnya 38 pasangan, dan semuanya ditinjau dengan pivot ke `CommandLine` dan `User` di raw event: 21 installer dari daftar software resmi yang dijalankan dari `Downloads` atau `Temp`, 9 tool portabel admin IT, 6 updater aplikasi per-user, dan 2 skrip makro Keuangan yang sudah dikenal dari `HUNT-2027-001`. Semuanya jinak, dan daftar 38 itu disimpan di dokumentasi baseline sebagai outlier jinak yang sudah dikonfirmasi, seperti yang disarankan langkah Act PEAK [S7]. Inilah tindak lanjut backlog "long tail di luar daftar parent dengan path dinormalisasi" dari `HUNT-2027-001`: bagian long tail yang paling berisiko ditinjau, dan sisanya diterima sebagai normal dengan alasan tertulis.

**Variasi:** least-frequency pada satu field, untuk menemukan biner yang baru muncul atau hanya ada di satu tempat:

```
index=sysmon sourcetype=XmlWinEventLog EventCode=1
    earliest="01/01/2027:00:00:00" latest="02/01/2027:00:00:00"
| `jab_norm_parentchild`
| stats count dc(host) AS hosts BY child_n
| sort count
| head 20
```

Ganti `child_n` dengan `CommandLine` (lebih berisik, kardinalitas tinggi), `DestinationIp`, atau `QueryName` untuk field lain.

**Kapan gagal:** macro diubah setelah baseline dibangun, sehingga baseline dan hunt memakai aturan berbeda dan semua pasangan terlihat baru; regex versi terlalu agresif sehingga dua program berbeda di folder bernomor menjadi satu; `ParentImage` atau `Image` kosong di sebagian event (Day 04).

### 2.5 Menyimpan baseline sebagai lookup

Dengan normalisasi siap, baseline Januari ditulis ke lookup. Ini jawaban konkret pertanyaan Dimas "disimpan di mana".

**Tujuan:** membangun `jab_hunt_baseline_parentchild.csv` dari Sysmon EID 1 workstation ber-Sysmon selama 1 sampai 31 Januari 2027, lengkap dengan kolom `first_seen`.

```
index=sysmon sourcetype=XmlWinEventLog EventCode=1
    earliest="01/01/2027:00:00:00" latest="02/01/2027:00:00:00"
| `jab_norm_parentchild`
| stats count AS executions dc(host) AS hosts min(_time) AS first_seen max(_time) AS last_seen
        BY parent_n child_n
| outputlookup override_if_empty=false jab_hunt_baseline_parentchild.csv
```

| Bagian | Fungsi |
|---|---|
| Rentang absolut Januari | Baseline bisa diulang dengan hasil sama dan berakhir sebelum jendela hunt (1 Februari) |
| `min(_time) AS first_seen`, `max(_time) AS last_seen` | Kapan pasangan pertama dan terakhir terlihat di periode baseline |
| `dc(host) AS hosts` | Sebaran, untuk syarat "hanya satu host" |
| `override_if_empty=false` | Bila search gagal dan hasilnya kosong, file lama tidak dihapus [S4] |

Keluaran ilustrasi: 2.611 baris tertulis ke `jab_hunt_baseline_parentchild.csv` di app hunting `jkt-splunk-sh01`, dengan izin tulis hanya untuk role `jab_hunter`. Metadata baseline dicatat di `jab-hunt/hunts/HUNT-2027-006/abstract.md`: periode, kelompok host, versi macro normalisasi, alasan menganggap periode bersih (bagian 1.2), dan 38 outlier jinak (bagian 2.4).

Untuk pembaruan, pola yang menggabungkan baseline lama dengan data baru adalah `inputlookup append=true` di tengah search, lalu agregasi ulang:

```
index=sysmon sourcetype=XmlWinEventLog EventCode=1 earliest=-1d@d latest=@d
| `jab_norm_parentchild`
| stats count AS executions dc(host) AS hosts min(_time) AS first_seen max(_time) AS last_seen
        BY parent_n child_n
| inputlookup append=true jab_hunt_baseline_parentchild.csv
| stats sum(executions) AS executions max(hosts) AS hosts min(first_seen) AS first_seen
        max(last_seen) AS last_seen BY parent_n child_n
| outputlookup jab_hunt_baseline_parentchild.csv
```

- `inputlookup append=true` menggabungkan baseline lama agar tidak hilang saat data bergeser; tanpa itu, kombinasi yang terakhir muncul 31 hari lalu akan hilang dari baseline dan muncul lagi sebagai "baru".
- `min(first_seen)` mempertahankan tanggal pertama terlihat paling awal, dan `max(hosts)` adalah pendekatan: jumlah host unik dari dua periode tidak bisa dijumlahkan tanpa daftar host-nya.
- Rentang relatif (`-1d@d` sampai `@d`) di sini benar karena ini saved search terjadwal atas data live, bukan hunt yang harus bisa diulang.

Usulan untuk Sari: saved search ini dijadwalkan setiap hari pukul 01:30 setelah `HUNT-2027-006` selesai, dan laporan first-seen harian (bagian 2.6) dijalankan pukul 01:00, sebelum pembaruan, supaya pasangan baru selalu muncul di laporan dulu sebelum menjadi bagian baseline.

**Kapan gagal:** saved search pembaruan berjalan sebelum laporan first-seen, sehingga pasangan baru tidak pernah tampil; lookup diedit manual di luar Splunk dengan nama kolom berbeda, sehingga `append=true` membuang kolom yang tidak dikenal [S4]; atau dua orang menulis lookup yang sama di saat bersamaan.

### 2.6 `HUNT-2027-006`: first-seen 1 sampai 10 Februari

Dengan baseline beku per 31 Januari, pertanyaan "apa yang baru" bisa dijawab untuk sepuluh hari pertama Februari. Ini cara kedua menindaklanjuti long tail `HUNT-2027-001`: bukan meninjau semua yang langka, tetapi meninjau yang belum pernah ada.

```
ID             : HUNT-2027-006
Dibuat         : 2027-02-11 (Kamis) 09:30, pemilik: <kamu>, reviewer: Dimas Prasetyo
Trigger        : Backlog HUNT-2027-001 (long tail dengan path dinormalisasi) + pelajaran
                 "perlu baseline"
Tipe (PEAK)    : Baseline (first-seen terhadap baseline tersimpan)
Hipotesis      : Di workstation ber-Sysmon ada pasangan parent-child (path dinormalisasi) yang
                 belum pernah terlihat selama Januari 2027 dan menandakan eksekusi baru yang
                 tidak lazim
ATT&CK         : Execution (TA0002) - teknik spesifik ditentukan setelah temuan
Data           : Sysmon EID 1, workstation OU Workstations-EDR; baseline 1-31 Jan 2027
                 (jab_hunt_baseline_parentchild.csv); jendela hunt Senin 2027-02-01 00:00
                 sampai Kamis 2027-02-11 00:00 WIB
Di luar cakupan: sekitar 60% workstation tanpa Sysmon, server, Linux; pasangan yang sudah ada
                 di Januari walaupun dipakai penyerang (first-seen tidak melihatnya)
Kriteria sukses: Semua pasangan baru ditinjau dan berlabel
Handover       : IR bila ditemukan; Sari untuk laporan first-seen harian
Target selesai : Kamis 2027-02-11
```

**Tujuan:** menampilkan pasangan parent-child di jendela hunt yang tidak ada di baseline.

```
index=sysmon sourcetype=XmlWinEventLog EventCode=1
    earliest="02/01/2027:00:00:00" latest="02/11/2027:00:00:00"
| `jab_norm_parentchild`
| stats count AS executions dc(host) AS hosts values(host) AS host_list values(User) AS users
        min(_time) AS first_time BY parent_n child_n
| lookup jab_hunt_baseline_parentchild.csv parent_n child_n OUTPUT first_seen AS baseline_first
| where isnull(baseline_first)
| eval first_time=strftime(first_time, "%Y-%m-%d %H:%M")
| sort - hosts
```

| Bagian | Fungsi |
|---|---|
| Macro yang sama dengan baseline | Tanpa itu, perbedaan normalisasi akan muncul sebagai "baru" |
| `lookup ... parent_n child_n OUTPUT first_seen AS baseline_first` | Mencocokkan pasangan ke baseline; pasangan yang tidak ditemukan mendapat `baseline_first` kosong |
| `where isnull(baseline_first)` | Hanya yang belum pernah terlihat di Januari |
| `sort - hosts` | Yang tersebar luas di atas: biasanya rollout software, cepat dikonfirmasi ke tim IT |

Keluaran ilustrasi:

```
Event EID 1 dalam jendela hunt        : 6.903.115
Pasangan (dinormalisasi) unik          : 1.722
Pasangan yang tidak ada di baseline    : 5
(uji banding dengan path mentah        : 412 pasangan "baru")
```

```
parent_n                                          child_n                                                   executions hosts first_time        host_list / users
c:/program files/jab docsync/jabdocsync.exe       c:/program files/jab docsync/<ver>/jabdocsync-migrate.exe        149   149 2027-02-03 19:02  149 host
c:/program files/jab docsync/jabdocsync.exe       c:/windows/system32/icacls.exe                                   149   149 2027-02-03 19:02  149 host
c:/program files/jab payroll client/payrollclient.exe  c:/windows/system32/cmd.exe                                  37     4 2027-02-08 10:14  4 host HR Jakarta
c:/windows/explorer.exe                           c:/users/<user>/downloads/wireshark-x64-setup.exe                  1     1 2027-02-09 14:20  JKT-WS-0552 / JAB\arif.kurniawan
c:/users/<user>/downloads/wireshark-x64-setup.exe c:/users/<user>/appdata/local/temp/<rnd>/npcap-setup.exe           1     1 2027-02-09 14:22  JKT-WS-0552 / JAB\arif.kurniawan
```

Kelima pasangan ditinjau:

- **Dua pasangan `jabdocsync.exe`:** rollout `JAB DocSync` 4.2 oleh tim IT pada Rabu 2027-02-03 malam, sesuai tiket perubahan. Komponen migrasi berjalan sekali per host, lalu `icacls.exe` mengatur izin folder cache baru. `icacls.exe` dari aplikasi bisa terlihat mencurigakan, tetapi `CommandLine`-nya hanya menyentuh folder `C:\ProgramData\JAB DocSync\cache` dan polanya identik di 149 host. Label: jinak.
- **`payrollclient.exe` ke `cmd.exe`:** aplikasi payroll baru untuk HR, dipasang Senin 2027-02-08 di 4 workstation HR Jakarta. `CommandLine` menunjukkan `cmd.exe /c net use` untuk memetakan printer slip gaji. Dikonfirmasi ke tim IT dan HR. Label: jinak. Catatan: pola aplikasi memunculkan `cmd.exe` sama dengan pola yang dicari usulan rule "JAB - Office atau WMI memunculkan shell" dari `HUNT-2027-001`; bila rule itu diperluas ke aplikasi lain, pengecualiannya harus sempit (path aplikasi dan command line).
- **Installer Wireshark dan Npcap di `JKT-WS-0552`:** engineer NOC `arif.kurniawan` memasang Wireshark dari folder `Downloads` pada Selasa 2027-02-09, dan installer itu menjalankan installer Npcap dari folder sementara. Wireshark ada di daftar software yang disetujui untuk NOC, tanda tangan digital installer valid menurut halaman file MDE, dan pemasangan dikonfirmasi oleh pengguna dan Bambang. Label: jinak.

**Cara membaca hasil:** lima pasangan, semua jinak, sehingga hasil hunt adalah "tidak ditemukan" untuk cakupan yang ditulis. Perbandingan 5 dan 412 adalah bukti nilai normalisasi: tanpa normalisasi, update Edge, Teams, dan installer dengan folder acak akan memenuhi daftar. Nama file installer yang memuat nomor versi tidak dinormalisasi oleh macro ini, karena aturan versi hanya berlaku untuk segmen folder; installer berikutnya dengan versi berbeda akan muncul lagi sebagai pasangan baru. Itu diterima, karena pemasangan software baru memang layak dilihat.

**Variasi:** setelah baseline diperbarui otomatis, "apa yang baru dalam 7 hari terakhir" bisa ditanyakan dari lookup saja:

```
| inputlookup jab_hunt_baseline_parentchild.csv
| where first_seen >= relative_time(now(), "-7d@d")
| sort - hosts
```

Ganti `child_n` dengan kombinasi `child_n` dan `User` untuk baseline "siapa menjalankan apa", atau bangun baseline terpisah untuk server Windows dengan pola yang sama.

**Kapan gagal:** baseline mencakup jendela hunt sehingga semuanya tampak lama (pastikan rentang baseline berakhir sebelum jendela hunt); penyerang memakai pasangan yang sudah umum (misalnya `explorer.exe` ke `powershell.exe`), yang memang tidak pernah "baru"; atau penyerang menamai ulang biner, karena `Image` mencatat path file, bukan nama asli program (`OriginalFileName` Sysmon dibahas di Day 13).

### 2.7 Laporan kedua hunt dan jawaban untuk Bambang dan Dimas

Dua laporan berikut adalah langkah Finalize TaHiTI dan fase Act PEAK untuk hari Kamis ini.

```
ID            : HUNT-2027-005                        Selesai: Kamis 2027-02-11 15:30
Hasil         : Tidak ditemukan C2; 1 item inkonklusif ke backlog
Cakupan nyata : Proxy Squid Jakarta dan Bandung, 1-7 Feb 2027 (Senin 00:00 sampai Senin 00:00),
                351 IP sumber, 118.477 pasangan
Ambang        : Tahap A conns >= 100 dan hours_seen >= 24 (2.947 kandidat);
                tahap B med_int >= 30 detik, CV <= 0.2 setelah jeda > 3x median dibuang (751 pasangan)
Di luar cakupan: trafik non-proxy, server, POP lain, beacon > 1 jam atau jitter > ~20%, tunnel panjang
Jinak terkonfirmasi: Defender, Teams (verifikasi per tujuan), JAB DocSync update 15 menit,
                agent synthetic monitoring Service Assurance NOC (6 PC, termasuk JKT-WS-0541),
                agent printer Keuangan (3 PC)
Inkonklusif   : BDG-WS-0196 (rizal.siregar) ke api.statuspulse.example tiap 30 menit dari msedge.exe,
                pertama terlihat 2027-01-19; pengguna cuti sampai 15 Feb -> backlog
Artefak       : jab_hunt_baseline_beacon.csv (tujuan polling teratur yang dikenal: tujuan, pemilik,
                interval, tanggal review); jab_hunt_005_candidates.csv dihapus setelah laporan
Deteksi       : Usulan laporan mingguan "TH - kandidat beacon proxy" untuk hunter (bukan alert L1),
                mengecualikan tujuan di jab_hunt_baseline_beacon.csv -> ke Sari Kusuma
Celah data    : Inventaris ekstensi browser tidak dikumpulkan; agent NOC tidak tercatat di inventaris
                aset SOC -> ke tim Infrastruktur dan Bambang
```

```
ID            : HUNT-2027-006                        Selesai: Kamis 2027-02-11 16:30
Hasil         : Tidak ditemukan aktivitas berbahaya
Cakupan nyata : Sysmon EID 1, workstation OU Workstations-EDR, 1-10 Feb 2027, dibanding baseline
                1-31 Jan 2027 (2.611 pasangan dinormalisasi)
Temuan        : 5 pasangan baru, semua jinak (rollout DocSync 4.2 x2, payroll HR, installer
                Wireshark/Npcap di JKT-WS-0552)
Artefak       : jab_hunt_baseline_parentchild.csv + macro jab_norm_parentchild + 38 outlier jinak
Deteksi       : Usulan laporan first-seen harian 01:00 dan pembaruan baseline 01:30 -> ke Sari
Di luar cakupan: sekitar 60% workstation tanpa Sysmon, server, Linux, pasangan yang sudah umum
Pelajaran     : Normalisasi mengubah 412 pasangan "baru" menjadi 5
```

Tabel berikut adalah jawaban yang dikirim ke Bambang dan Dimas Kamis sore. Setiap baris merujuk subbagian di atas, supaya alasannya bisa dibaca ulang.

| Pertanyaan | Jawaban singkat | Dasar |
|---|---|---|
| (Bambang) `JKT-WS-0541` itu C2? | Bukan. Itu agent synthetic monitoring milik tim Service Assurance NOC, polling tiap 60 detik; sudah dikonfirmasi pemiliknya dan dicatat di daftar tujuan polling yang dikenal | Bagian 2.2, 2.3 |
| (Bambang) Kenapa tidak ada alert? | Keteraturan saja tidak dijadikan rule karena ratusan agent sah juga teratur; hunt mingguan memakai prevalence dan konteks untuk memilah | Bagian 1.6, 1.7 |
| Teknik mana untuk apa | Searching untuk hipotesis spesifik, stacking untuk yang langka, grouping untuk yang muncul bersama, clustering dan analisis frekuensi untuk pola di seluruh data | Bagian 1.1 |
| Apa itu normal | Baseline per kelompok host, dari periode yang alasannya ditulis, dengan normalisasi yang disimpan sebagai macro | Bagian 1.2, 2.4 |
| Disimpan di mana | Lookup `jab_hunt_baseline_parentchild.csv` dengan `first_seen`, diperbarui harian setelah laporan first-seen | Bagian 1.3, 2.5 |
| Kenapa yang langka menarik | Penyerang biasanya di ekor distribusi, tetapi langka hanya sinyal; ambang dari distribusi, dua syarat (jarang dan sedikit host) | Bagian 1.4 |
| Beacon atau agent sah | Keteraturan menyaring; yang membedakan prevalence, pemilik, proses, umur tujuan, dan pola harian | Bagian 1.5, 1.6 |
| Batasnya | Hasil adalah daftar periksa, bukan vonis; cakupan, ambang, baseline, dan retensi ditulis di laporan | Bagian 1.7 |

**Kapan gagal:** jawaban ke Bambang hanya "bukan C2" tanpa menyebut pemilik dan bukti. NOC akan bertanya lagi minggu depan untuk PC lain, dan SOC tidak punya daftar tujuan yang dikenal untuk menjawabnya cepat.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** Splunk lab dengan Sysmon EID 1, 3, dan 11 dari beberapa hari, sebaiknya dari minimal dua VM Windows supaya prevalence bermakna; hipotesis dari Day 03; VM dengan snapshot. Opsional: satu VM Squid sebagai proxy eksplisit untuk VM klien. Jangan memakai data, nama, atau kejadian dari pekerjaan nyata; PT JAB hanya contoh fiktif. Sesuaikan index, sourcetype, dan rentang absolut dengan data lab-mu.

1. **Tabel teknik.** Buat `docs/hunt-techniques.md` dengan empat teknik dan kapan memakainya (bagian 1.1), ditambah satu contoh pertanyaan dari lab-mu sendiri untuk tiap teknik.
2. **Normalisasi.** Buat macro normalisasi seperti bagian 2.4 di lab-mu. Uji dengan minimal lima path positif (folder berversi, profil pengguna, folder `Temp` acak, GUID) dan dua path negatif yang tidak boleh berubah. Catat hasilnya dalam tabel seperti bagian 2.4.
3. **Distribusi dan ambang.** Jalankan query distribusi bagian 2.4 dengan dan tanpa macro. Catat pasangan unik, p5, p25, median, maksimum, dan jumlah pasangan `executions <= 3`. Tetapkan ambang stacking dengan alasan, bukan tebakan.
4. **Baseline tersimpan.** Bangun `baseline_parent_child.csv` di lab dengan query bagian 2.5 (rentang absolut yang berakhir sebelum hari terakhir datamu). Jalankan query pembaruan dua kali (dua hari) untuk melihat baseline bertambah lewat `append=true`, dan pastikan `first_seen` pasangan lama tidak berubah.
5. **Baseline yang tercemar (uji sengaja).** Sebelum membangun ulang baseline, jalankan satu aktivitas jinak yang tidak biasa di VM (misalnya `cmd.exe` dari dokumen Office lewat test Atomic Red Team T1204.002 yang hanya menjalankan perintah tidak berbahaya; catat GUID test-nya). Bangun baseline yang mencakup hari itu, lalu ulangi aktivitas yang sama keesokan harinya dan jalankan query first-seen bagian 2.6. Catat bahwa aktivitas itu tidak muncul sebagai baru, lalu jalankan query tinjauan outlier bagian 2.4 dan pastikan aktivitas itu terlihat di sana.
6. **Hunt first-seen.** Jalankan query bagian 2.6 untuk satu hari setelah periode baseline. Beri label setiap pasangan baru.
7. **Beacon jinak.** Di VM lab dengan snapshot, buat beacon jinak: skrip yang memanggil satu URL lab tiap 60 detik selama minimal 70 menit (tulis sendiri; jangan pakai tool C2). Durasi ini perlu agar jumlah koneksi melewati ambang; 70 menit menghasilkan sekitar 70 koneksi. Sesuaikan ambang tahap A untuk lab (misalnya `conns >= 50` dan `hours_seen >= 1`), lalu jalankan tahap B bagian 2.2 (atau versinya untuk Sysmon EID 3 dengan `_time` langsung). Pastikan pasangan beacon muncul dengan median mendekati 60 dan CV kecil.
8. **Beacon berjitter.** Ubah skrip agar menunggu acak antara 48 dan 72 detik (sekitar 20% jitter) dan jalankan lagi 70 menit. Hitung CV-nya, lalu bandingkan dengan dua ambang: CV di bawah 0,1 dan CV maksimal 0,2. Hentikan skrip dan kembalikan snapshot.
9. **Jeda.** Biarkan skrip beacon pertama berjalan, matikan VM klien selama 30 menit, lalu hidupkan lagi. Bandingkan CV dengan dan tanpa baris `where delta <= 3*med_int`.
10. **Proxy (opsional).** Bila lab punya Squid, bandingkan `_time` di log Squid dengan `_time` Sysmon EID 3 untuk koneksi yang sama, lalu hitung selisihnya dan bandingkan dengan kolom durasi.
11. **Grouping.** Ambil host beacon, jalankan grouping per 10 menit atau 30 menit (bagian 2.3), dan tulis apa yang muncul bersama.
12. **Laporan.** Isi laporan hunt (template Day 01 bagian 2.4 atau bagian 2.7): hasil, cakupan, ambang yang dipakai, dan label tiap item yang ditinjau.

**Hasil yang sebaiknya tersimpan:**

- Tabel empat teknik dengan contoh dari lab sendiri.
- Macro normalisasi dengan tabel uji positif dan negatif.
- Angka distribusi dengan dan tanpa normalisasi, plus ambang yang dipilih beserta alasannya.
- Baseline lookup yang terbukti bertambah lewat `append=true` dengan `first_seen` yang bertahan.
- Catatan uji baseline tercemar: GUID test, tanggal, dan bukti bahwa first-seen buta terhadapnya.
- Angka CV beacon tanpa jitter, dengan jitter, dan dengan jeda, sebelum dan sesudah filter median.
- Laporan hunt dengan ambang, cakupan, dan label.

**Variasi tantangan:** jalankan analisis frekuensi beacon dengan dua definisi keteraturan: deviasi standar relatif terhadap rata-rata (CV) dan MAD dibagi median, lalu bandingkan mana yang lebih tahan terhadap jitter dan jeda di lab-mu. Tulis satu paragraf tentang trade-off antara menangkap beacon berjitter dan menambah false positive dari polling sah.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat membangun baseline dan menjalankan stacking atau analisis frekuensi. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Stacking menghasilkan ratusan baris langka | Lab terlalu sepi, path belum dinormalisasi, atau ambang terlalu longgar | Normalisasi dulu (bagian 2.4); tetapkan ambang dari distribusi; tambah syarat host |
| First-seen menandai semua kombinasi | Baseline kosong, macro berbeda, atau lookup peka huruf | Bangun baseline dulu; pakai macro yang sama; normalisasi ke huruf kecil |
| First-seen tidak menandai apa pun | Rentang baseline tumpang tindih dengan jendela hunt, atau pembaruan harian berjalan sebelum laporan | Pisahkan rentang (bagian 2.5); jadwalkan laporan sebelum pembaruan |
| Baseline tiba-tiba kosong | Search pembaruan menghasilkan nol baris dengan `override_if_empty` default | Pakai `override_if_empty=false`; pulihkan dari cadangan lookup |
| Kolom baru tidak muncul di lookup | `append=true` hanya menulis field yang sudah ada di CSV [S4] | Tulis ulang sekali tanpa `append` |
| Beacon tidak terdeteksi | Jitter besar; CV di atas ambang; jeda malam belum dibuang | Buang jeda dengan median (bagian 2.2); longgarkan CV ke sekitar 0,2 |
| Terlalu banyak false positive beacon | Polling sah (update, telemetri, kolaborasi) | Daftar tujuan dikenal dengan pemilik; verifikasi per tujuan untuk prevalence tinggi |
| `streamstats` salah hitung interval | Data tidak terurut per pasangan | `sort 0 src dest start` sebelum `streamstats` |
| Interval proxy bergeser acak | `_time` Squid adalah waktu selesai | Hitung waktu mulai dari durasi (bagian 1.5) |
| Subsearch kandidat terpotong | Kandidat lebih dari 10.000 baris | Perketat tahap A atau pecah per subnet |
| `eventstats` tidak menambahkan field di sebagian hasil | Batas memori `max_mem_usage_mb` tercapai [S6] | Kurangi event sebelum `eventstats` (tahap A) |
| Stacking `CommandLine` lambat atau berisik | Kardinalitas sangat tinggi | Normalkan dulu (buang argumen variabel) atau stacking field lain |

## 5. Kesalahan umum dan jebakan

- **Stacking pada field kardinalitas tinggi** (`CommandLine` mentah) menghasilkan hampir semua unik; normalkan atau pilih field lain.
- **Ambang yang ditebak.** Hitung distribusi dulu (bagian 2.4) dan tulis angkanya di laporan.
- **Baseline dari periode tidak bersih**, sehingga perilaku penyerang dianggap normal. Tulis alasan periode dianggap bersih dan tinjau outlier di dalam baseline sebelum membekukannya.
- **Baseline yang diperbarui otomatis tanpa ada yang meninjau**, sehingga pasangan baru yang berbahaya menjadi normal keesokan harinya.
- **Normalisasi berbeda antara baseline dan hunt.** Simpan aturannya sebagai macro dan catat versinya di metadata baseline.
- **Mengira daftar hasil adalah jawaban.** Teknik memperkecil ruang; manusia tetap meninjau dan melabeli [S1][S7].
- **Menganggap teratur berarti jahat.** Defender, Teams, dan updater sama teraturnya dengan beacon; keteraturan adalah penyaring, bukan pembeda.
- **Membuang tujuan berprevalence tinggi tanpa verifikasi.** Penyerang yang menumpang software yang tersebar luas juga berprevalence tinggi.
- **Ambang CV 0,1 untuk beacon berjitter.** Jitter sekitar 20% menghasilkan CV di atas 0,1 (deret B di bagian 1.5).
- **Lupa bahwa proxy tidak tahu proses.** Pivot ke Sysmon EID 3 atau EDR, dan ingat bahwa dengan proxy eksplisit, Sysmon hanya melihat koneksi ke proxy.
- **Menyamakan grouping dan clustering.** Grouping atas data yang sudah dicurigai; clustering atas seluruh data [S2].
- **Hanya mengandalkan stacking.** Stacking dipakai di banyak jenis hunt [S1], tetapi beacon dan pola temporal lebih cocok dengan analisis frekuensi, dan penyerang yang meniru perilaku umum hanya tertangkap searching dengan hipotesis spesifik.

## 6. Catatan terkini

Bagian ini menampung detail versi, tanggal terbit, dan sejarah istilah yang tidak mengubah langkah kerja di atas.

- Taksonomi empat teknik (searching, stacking, grouping, clustering) berasal dari literatur hunting era Sqrrl dan masih dipakai luas [S1][S2][S8]; terminologi "frequency vs volumetric" bervariasi antar sumber [S2].
- Stacking tetap teknik yang paling sering muncul di prosedur hunt publik [S1]. PEAK menyebutnya juga least frequency of occurrence dan menambahkan z-score sebagai cara statistik sederhana menemukan outlier [S7].
- Pendekatan baseline (EDA) adalah salah satu dari tiga tipe hunt PEAK (Day 02 bagian 1.4); baselining dan stacking adalah mesin utamanya. Tulisan Splunk tentang baseline hunting terbit 11 Juli 2023 [S7].
- Alat ML untuk clustering (M-ATH, Day 02) di luar lingkup lab ini; stacking dan analisis frekuensi memberi nilai besar tanpa infrastruktur ML.
- RITA versi 5 memakai Docker dan membaca log Zeek (TSV atau JSON); rilis terbaru di GitHub adalah v5.1.2 (7 Mei 2026), sebelumnya v5.1.1 (21 Januari 2026) dan v5.1.0 (22 September 2025) [S9]. Skor beacon versi 5 memakai empat subskor berbobot sama dan modifier prevalence [S10]. Vendor yang sama menjual produk komersial yang kini bernama AC-Hunter (dulu AI-Hunter); detail produknya tidak diverifikasi di sini, jadi cek di situs Active Countermeasures bila perlu.
- Uji lab The DFIR Report (Januari 2022) melaporkan RITA menangkap beacon Cobalt Strike dari sekitar satu jam data, apa pun profil dan jitter yang dipakai [S11]. Itu hasil satu lab dengan log Zeek, bukan jaminan untuk data proxy.
- Preprint arXiv September 2026 (satu penulis, belum melalui peer review) melaporkan bahwa trafik agent AI berbasis Model Context Protocol menyerupai beacon secara struktur, tetapi interval antar-permintaannya yang tidak teratur membuat RITA memberi skor beacon 0,0 di testbed penulis [S14]. Implikasinya untuk hunting: trafik otomatis yang tidak teratur tidak tertangkap analisis keteraturan, sehingga makin banyak agent otomatis di endpoint berarti makin penting sinyal non-interval (prevalence, pemilik, umur tujuan).
- Di ATT&CK v20, T1176 bernama Software Extensions dengan sub-teknik T1176.001 Browser Extensions dan T1176.002 IDE Extensions (dimodifikasi 24 Oktober 2025); dokumentasi lama menyebut T1176 sebagai Browser Extensions tanpa sub-teknik [S13]. T1071.001 Web Protocols tetap di bawah taktik Command and Control [S13].
- Halaman SPL Search Reference Splunk Enterprise 10.6 untuk `streamstats`, `eventstats`, `outputlookup`, `inputlookup`, dan fungsi statistik diperbarui 9 September 2026 [S4][S6]. Versi Day ini sebelumnya merujuk dokumentasi 10.0.

## 7. Cheat sheet

```
TEKNIK     searching (hipotesis spesifik) | stacking (hitung, ambil langka) | grouping (atas data dicurigai) | clustering (seluruh data, statistik)
BASELINE   statis (daftar pernah-terlihat, lookup) | dinamis (median/p95/stdev, summary) ; per kelompok host ; 30-90 hari
           periode BERSIH + alasan ditulis ; tinjau outlier di dalam baseline sebelum dibekukan ; diperbarui
NORMALISASI lower + "\\\\"->"/" | users/<user> | <ver> | temp/<rnd> | <guid> ; simpan sebagai MACRO, sama di baseline & hunt
SIMPAN     outputlookup override_if_empty=false <file>.csv | inputlookup append=true (gabung lama + baru) | CDB list (Wazuh) | summary index
           append=true hanya menulis field yang sudah ada di CSV ; lookup CSV peka huruf secara default
STACKING   stats count dc(host) BY <field(s)> | where count <= N AND hosts <= M | sort count ; N dari p25/distribusi
FIRST-SEEN lookup baseline ... OUTPUT first_seen | where isnull(...) ; baseline berakhir SEBELUM jendela hunt
           laporan first-seen jalan SEBELUM pembaruan baseline
BEACON A   bin span=1h _time AS hour | stats count dc(hour) BY src dest | eventstats dc(src) AS dest_hosts BY dest | where ...
BEACON B   eval start=_time-(duration/1000) | sort 0 src dest start | streamstats current=f last(start) AS prev BY src dest
           | eval delta=start-prev | eventstats median(delta) AS med BY src dest | where delta <= 3*med
           | stats avg(delta) stdev(delta) BY src dest | eval cv=sd/avg | where cv <= 0.2
CV         A agent 0.004 | B jitter ~20% 0.132 | C dengan jeda 14 jam 2.984 (median tetap 300)
PEMBEDA    prevalence | pemilik | proses | umur tujuan | ukuran data | pola harian ; keteraturan = penyaring saja
INGAT      teknik memperkecil ruang, bukan memvonis ; tiap item ditinjau & dilabeli ; lab sepi -> long tail tak bermakna
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Pasangan dengan CV interval paling kecil adalah kandidat C2 paling kuat, jadi daftar hasil tahap B cukup diurutkan berdasarkan CV." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Di `HUNT-2027-005`, CV paling kecil justru milik agent sah: agent synthetic monitoring NOC (0,015), `JAB DocSync` (0,02), dan Defender (0,03). Agent sah sering lebih teratur daripada beacon berjitter. Keteraturan adalah penyaring; yang membedakan adalah prevalence, pemilik, proses pemanggil, umur tujuan, ukuran data, dan pola harian. Karena itu hasil diurutkan berdasarkan `dest_hosts` dulu, dan tujuan berprevalence tinggi diverifikasi per tujuan. Lihat bagian 1.6 dan 2.2.

</details>

**2. Skenario keputusan.** Kamu akan membangun baseline parent-child untuk hunt first-seen 1 sampai 10 Februari. Pilihan mana yang paling tepat?

- A. Pakai data 1 Januari sampai 10 Februari supaya baseline selengkap mungkin.
- B. Pakai data 1 sampai 31 Januari dengan path dinormalisasi, tulis alasan periode itu dianggap bersih, tinjau outlier langka di folder yang bisa ditulis pengguna, lalu bekukan sebelum dibandingkan.
- C. Pakai data 7 hari terakhir supaya baseline mencerminkan kondisi terbaru.

<details><summary>Jawaban</summary>

B. Periode baseline harus berakhir sebelum jendela hunt, alasan kebersihannya ditulis, dan isi yang langka ditinjau dulu karena baseline yang tercemar membuat perilaku penyerang menjadi normal. A keliru karena baseline mencakup jendela hunt, sehingga semua pasangan Februari sudah ada di baseline dan first-seen tidak menemukan apa pun. C keliru karena 7 hari terakhir juga tumpang tindih dengan jendela hunt dan terlalu pendek dibanding saran 30 sampai 90 hari. Lihat bagian 1.2, 2.4, dan 2.5.

</details>

**3. Pertanyaan jebakan.** "Syarat `sd_interval < avg_interval*0.1` sudah cukup longgar untuk menangkap beacon yang memakai jitter." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Deret B di bagian 1.5, beacon 300 detik dengan jitter sekitar 20%, punya rata-rata 298,0 detik, stdev 39,47, dan CV 0,132. Syarat CV di bawah 0,1 membuangnya, padahal deret agent sah dengan CV 0,004 lolos. Ambang sekitar 0,2 menangkap deret B, dengan konsekuensi lebih banyak polling sah yang ikut masuk. Lihat bagian 1.5.

</details>

**4. Skenario keputusan.** Pasangan `JAB DocSync` di satu workstation terlihat sangat tidak teratur di tahap B (CV hampir 3), padahal update check-nya berjalan tiap 15 menit. Apa langkah yang tepat?

- A. Naikkan ambang CV ke 3 supaya pasangan seperti ini ikut masuk.
- B. Hitung median interval per pasangan dengan `eventstats`, buang delta yang lebih dari tiga kali median (jeda malam atau laptop mati), lalu hitung ulang rata-rata, stdev, dan CV.
- C. Buang pasangan itu dari analisis karena jelas aplikasi internal.

<details><summary>Jawaban</summary>

B. Satu jeda panjang merusak rata-rata dan stdev, sedangkan median tetap mencerminkan interval tipikal; setelah jeda dibuang, deret seperti deret C kembali ke CV sekitar 0,004. A keliru karena ambang CV 3 meloloskan hampir semua trafik, termasuk sesi interaktif yang sama sekali tidak teratur. C keliru karena label jinak diberikan setelah verifikasi, dan membuang pasangan sebelum diukur dengan benar juga menyembunyikan masalah pengukuran yang sama di pasangan lain. Lihat bagian 1.5 dan 2.2.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Bambang Hartono, dalam tiga kalimat, kenapa `JKT-WS-0541` bukan C2 dan kenapa SOC tidak mendapat alert untuk pola itu.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "PC itu menjalankan agent synthetic monitoring milik tim Service Assurance NOC, yang sejak November mengukur latensi HTTPS ke layanan vendor tiap 60 detik; prosesnya terlihat di Sysmon, bertanda tangan vendor, dan sudah dikonfirmasi pemiliknya. Kami tidak membuat alert untuk koneksi yang sekadar teratur, karena dalam seminggu ada lebih dari 700 pasangan teratur dari Defender, Teams, dan updater, dan hampir semuanya sah. Yang kami lakukan adalah hunt mingguan yang memilah pasangan teratur berdasarkan berapa host yang melakukannya dan siapa pemiliknya, dan agent tim Bapak sekarang masuk daftar tujuan yang dikenal supaya tidak ditanyakan ulang."

Kesalahan yang sering muncul:
- Menjawab "bukan C2" tanpa bukti pemilik dan proses, sehingga NOC tidak bisa menilai jawabannya.
- Mengatakan SOC "tidak bisa" mendeteksi beacon, padahal yang benar adalah keteraturan saja tidak layak menjadi alert.
- Lupa menutup celah inventaris: agent NOC perlu tercatat supaya pertanyaan yang sama tidak berulang.

</details>

**6. Pertanyaan jebakan.** "Laporan first-seen harian kosong selama seminggu, jadi tidak ada eksekusi baru di workstation." Benarkah?

<details><summary>Jawaban</summary>

Tidak otomatis. Laporan bisa kosong karena pembaruan baseline berjalan sebelum laporan sehingga pasangan baru sudah dianggap normal, karena macro normalisasi diubah atau terlalu agresif, karena Sysmon tidak masuk, atau karena penyerang memakai pasangan yang sudah umum. Laporan first-seen juga hanya mencakup workstation ber-Sysmon, sekitar 40% workstation. Cek urutan jadwal, versi macro, volume event, dan `first_seen` di lookup sebelum menyimpulkan. Lihat bagian 1.3, 1.7, 2.5, dan 2.6.

</details>

**7. Interview question (English).** "How would you hunt for C2 beaconing in proxy logs, and how do you tell it apart from legitimate software that also calls home on a schedule?"

<details><summary>Sample answer</summary>

"I'd work in two passes so the search stays affordable. First, I stack source and destination pairs over a fixed week, keeping pairs with enough connections and enough distinct active hours, and I record how many hosts talk to each destination. Second, for those candidates only, I sort by pair and time, compute the gap between consecutive connections, drop gaps much longer than the median so overnight shutdowns don't wreck the statistics, and measure regularity with the coefficient of variation, using a threshold loose enough for roughly twenty percent jitter. With proxy logs I also correct for the timestamp being written at the end of the transaction. Regularity only filters; legitimate agents are often more regular than malware. What separates them is prevalence, a known owner, the calling process from Sysmon or EDR, the age and category of the destination, payload size, and whether it runs when the user is away. High-prevalence destinations get verified per destination rather than ignored, and anything I can't explain with the data I have goes in the report as inconclusive with next steps, not as an incident."

What makes this answer strong: it shows a scalable two-stage method, handles the real statistical pitfalls (gaps and jitter), knows a data-source quirk, and treats regularity as a filter rather than a verdict while keeping the result honest.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Sqrrl: Hunt Evil: Your Practical Guide to Threat Hunting (berkas huntpedia.pdf di threathunting.net) | https://www.threathunting.net/files/huntpedia.pdf | primer (panduan komunitas era Sqrrl) | diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi untuk stacking (dipakai di banyak jenis hunt, input harus tersaring, persempit subnet atau ganti field) dan contoh analisis frekuensi beacon tiap dua jam; dokumen lama, tanpa tahun |
| S2 | Intel 471: Threat Hunting Tactics and Techniques | https://www.intel471.com/blog/threat-hunting-tactics-techniques | sekunder (vendor) | 2021-01-05; diakses 2026-10-08, dicek ulang 2026-10-18 | Sedang-tinggi. Clustering, grouping, stacking, frequency vs volumetric; tidak menamai searching sebagai teknik |
| S3 | SANS Institute: brosur acara (abstrak sesi tentang prosedur hunt yang bergantung pada stacking), tanpa tahun | tautan asli tidak lagi tersedia | sekunder | dirujuk 2026-10-08 | Rendah. Klaim yang sama kini didukung S1 |
| S4 | Splunk: SPL Search Reference 10.6, streamstats dan outputlookup | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/streamstats ; https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/outputlookup | primer (dokumentasi vendor) | diperbarui 2026-09-09; diakses 2026-10-10 (versi 10.0), dicek ulang 2026-10-18 (versi 10.6) | Tinggi untuk sintaks dan default (`current`, `max_stream_window`, `append`, `override_if_empty`, lokasi file) |
| S5 | Day 01-04 Threat-Hunting-note | (lokal) | rujukan internal | 2026-10-08 | Loop, hipotesis, data, Pyramid of Pain |
| S6 | Splunk: SPL Search Reference 10.6, eventstats, inputlookup, dan statistical and charting functions | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/eventstats ; https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/inputlookup ; https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/statistical-and-charting-functions/statistical-and-charting-functions | primer (dokumentasi vendor) | diperbarui 2026-09-09; diakses 2026-10-18 | Tinggi untuk `eventstats` (agregasi ditempel ke setiap event, batas memori), `inputlookup append=true`, `stdev` sampel vs `stdevp`, `perc`, `exactperc` |
| S7 | Splunk: Baseline Hunting with the PEAK Framework (David Bianco) | https://www.splunk.com/en_us/blog/security/peak-baseline-hunting.html | sekunder (blog vendor, penulis kerangka) | 2023-07-11; diakses 2026-10-18 | Tinggi untuk langkah baseline hunt, 30-90 hari, kelompok sistem, stack counting/LFO, z-score, dokumentasi baseline |
| S8 | Sqrrl: The Threat Hunting Reference Model Part 2: The Hunting Loop (salinan di threathunting.net) | https://threathunting.net/files/The%20Threat%20Hunting%20Reference%20Model%20Part%202_%20The%20Hunting%20Loop%20_%20Sqrrl.pdf | sekunder (blog vendor, diarsipkan) | 2015-10-28; diakses 2026-10-18 | Sedang. Menyebut stack counting dan clustering sebagai teknik row-oriented |
| S9 | Active Countermeasures: RITA (repositori GitHub, README dan daftar rilis) | https://github.com/activecm/rita ; https://github.com/activecm/rita/releases | primer (proyek open source) | v5.1.2 2026-05-07; diakses 2026-10-18 | Tinggi untuk fungsi (beacon, long connection, DNS tunneling, threat intel), input Zeek TSV/JSON, dan tanggal rilis |
| S10 | RITA: default_config.hjson | https://raw.githubusercontent.com/activecm/rita/main/default_config.hjson | primer (konfigurasi default proyek) | diakses 2026-10-18 | Tinggi untuk bobot subskor, ambang koneksi unik 4, modifier prevalence 2%/50%, catatan IP proxy internal |
| S11 | The DFIR Report: Cobalt Strike, a Defender's Guide - Part 2 | https://thedfirreport.com/2022/01/24/cobalt-strike-a-defenders-guide-part-2/ | sekunder (riset praktisi) | 2022-01-24; diakses 2026-10-18 | Sedang-tinggi. Definisi sleeptime (milidetik) dan jitter (persentase) di profil, uji RITA di lab penulis |
| S12 | Squid wiki: Feature: Customizable Log Formats (LogFormat) | https://wiki.squid-cache.org/Features/LogFormat | primer (dokumentasi proyek) | diakses 2026-10-18 | Tinggi untuk kolom native access.log, waktu dicatat di akhir transaksi, durasi dalam milidetik; tidak membahas CONNECT |
| S13 | MITRE ATT&CK: T1071.001 Web Protocols dan T1176 Software Extensions | https://attack.mitre.org/techniques/T1071/001/ ; https://attack.mitre.org/techniques/T1176/ | primer | ATT&CK v20; diakses 2026-10-18 | Tinggi untuk nama dan ID teknik |
| S14 | Sohail: When Agents Look Like Beacons: NIDS Evasion by Model Context Protocol Traffic (arXiv:2609.19091) | https://arxiv.org/abs/2609.19091 | sekunder (preprint) | 2026-09-16; diakses 2026-10-18 | Rendah-sedang. Satu penulis, belum peer review, hasil terbatas pada testbed penulis |

**Catatan sumber:** taksonomi empat teknik muncul di panduan komunitas dan vendor, tetapi atribusinya ke satu penulis tertentu belum jelas; anggap sebagai kosakata umum, bukan definisi baku. S1 dan S8 mendukung stacking dan clustering, S2 mendukung clustering, grouping, dan stacking, dan tidak satu pun yang diperiksa menamai searching secara eksplisit sebagai teknik keempat. Terminologi frequency vs volumetric berbeda antar sumber. Ambang beacon (100 koneksi, 24 jam, CV 0,2, tiga kali median) dan ambang stacking adalah ilustrasi, bukan nilai baku. Arti persis subskor durasi dan histogram RITA disimpulkan dari nama dan komentar konfigurasi [S10], bukan dari dokumentasi algoritma; cek kode sumber RITA bila angka itu dipakai untuk argumen formal. Perilaku logging CONNECT Squid tidak dibahas S12 dan perlu dicek di konfigurasi Squid-mu. Nama field add-on Squid dan nama index Sysmon perlu dicek di lab-mu. Seluruh isi `HUNT-2027-005` dan `HUNT-2027-006` (host, angka, label) adalah penerapan catatan ini pada organisasi fiktif, bukan hasil eksekusi nyata.
