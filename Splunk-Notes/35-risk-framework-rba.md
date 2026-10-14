---
day: 35
title: Risk framework dan Risk-Based Alerting (RBA) di ES
researched_on: 2026-10-10
versions_checked: Splunk ES 8.7 (Risk scoring / risk-based alerting); Splunk blog "The New & Improved Splunk Guide to Risk-Based Alerting" (Haylee Mills, 29 Agu 2024); komunitas RBA (github.com/splunk/rba, splunk.github.io/rba); ES 8.7 glosarium
---

# Day 35: Risk framework dan Risk-Based Alerting (RBA)

Cakupan: dasar risk framework Enterprise Security dan cara kerja Risk-Based Alerting, dari risk rule sampai finding group.

## Ide inti

Sampai Day 34, semua pekerjaan di ES berangkat dari satu finding: ada detection yang menyala, ada antrean, ada investigasi, ada disposisi. Model itu menyimpan satu asumsi yang jarang diucapkan, yaitu bahwa setiap detection cukup yakin untuk layak ditriage satu per satu. Kenyataannya sebagian besar perilaku yang menarik tidak pernah cukup yakin bila berdiri sendiri. PowerShell dengan argumen terenkode di satu workstation bisa jadi admin yang sedang bekerja. Perintah discovery beruntun bisa jadi skrip inventaris. Akses ke share administratif bisa jadi proses backup. Detection semacam itu biasanya berakhir dimatikan karena berisik, padahal yang menggambarkan serangan justru kombinasinya pada satu akun dan satu host dalam rentang waktu yang sempit. Risk-Based Alerting membalik urutannya. Detection yang lemah tidak lagi membuat alert, melainkan menempelkan skor pada entity yang terlibat, yaitu akun atau host, lalu menyimpannya sebagai intermediate finding di risk index. Alert baru lahir dari lapisan kedua, ketika akumulasi atau keragaman sinyal pada satu entity melewati ambang yang kamu tetapkan sendiri.

Dua hal perlu disadari sejak awal karena keduanya menentukan apakah RBA memperbaiki antrean atau hanya memindahkan masalahnya. Pertama, seluruh angka di sistem ini buatan sendiri: skor per rule, pengali konteks, ambang, dan lebar jendela waktu semuanya keputusanmu, jadi skor tinggi adalah hipotesis yang perlu diperiksa, bukan bukti. Kedua, bobot konteks bergantung pada kualitas daftar aset dan identitas. Pengali yang menaikkan skor untuk akun admin atau server kritis hanya bekerja pada entity yang memang terdaftar, sehingga aset yang belum masuk daftar diam-diam diperlakukan sebagai aset biasa.

Cara berpikirnya sudah kamu pakai di NOC. Satu modem pelanggan yang sekali flap tidak membangunkan siapa pun, tetapi perangkat yang flap beberapa kali, disertai CRC error dan redaman yang naik, masuk daftar periksa teknisi walaupun tidak ada satu pun alarm yang sendirian melewati threshold. Angka yang kamu kumpulkan per perangkat itulah padanan risk score, dan daftar yang dihasilkannya adalah padanan finding group. Batas analogi: bobot setiap sinyal di daftar NOC itu kamu sendiri yang menetapkan, dan hal yang sama berlaku di ES. Entity dengan skor 280 tidak otomatis lebih berbahaya daripada entity dengan skor 90 bila yang menaikkannya hanya satu rule yang berisik, jadi skor tinggi belum tentu insiden.

```
MODEL LAMA   satu detection menyala  ->  satu finding  ->  satu item di antrean L1
             10 detection lemah x 18 kali per shift  =  180 item untuk ditriage
             jalan keluar yang biasa dipakai: matikan detection yang paling berisik

MODEL RBA    satu detection menyala  ->  skor menempel ke entity (akun atau host)
             akumulasi dan keragaman per entity dinilai di lapisan kedua
             alert hanya dibuat untuk entity yang melewati ambang
```

Situasi yang dipakai sepanjang Day ini: di PT Jaringan Anak Bangsa (PT JAB, ISP menengah fiktif dengan SOC internal enam analyst L1 dalam tiga shift, dua analyst L2, satu detection engineer, dan satu SOC lead), tiket SOC-2026-0263 baru selesai. Isinya scheduled task persistence di workstation `JKT-WS-0523`: task `\EdgeUpdateCheck` dibuat oleh proses `vendorbackup.exe`. Saat ditinjau ulang, ternyata dalam setengah hari sebelum task itu dibuat, host yang sama dan akun yang sama (`rina.wulandari`) sudah muncul di empat alert kecil dari rule yang berbeda, sebagian dari Sysmon dan sebagian dari Windows Security. Keempatnya ditutup terpisah oleh tiga analyst di tiga shift sebagai benign. Antrean L1 memang sekitar 180 item per shift dan hampir sembilan dari sepuluh ditutup tanpa tindakan. Asset & Identity di ES juga belum lengkap karena aset POP dan perangkat pelanggan belum masuk. SOC lead menulis ke kamu:

> "Tiga shift menutup empat alert kecil untuk host dan akun yang sama, dan tidak ada yang melihat gabungannya sampai 0263 dibuka. Aku tidak mau mematikan detection itu karena isinya kadang benar. Jelaskan apakah risk based alerting menjawab ini, bagaimana skornya ditentukan dan siapa yang menentukannya, lalu apa yang terjadi pada bobot risiko kalau daftar aset dan identitas kita masih setengah jalan."

Pesan itu memuat enam pertanyaan:

1. Kenapa RBA ada, dan apa yang sebenarnya berubah dibanding model satu detection satu alert?
2. Objek apa saja yang membentuk risk framework ES, di mana skornya disimpan, dan apa bedanya entity dengan threat object?
3. Bagaimana sebuah detection lemah diubah menjadi risk rule: entity mana yang diberi skor, berapa, dan apa yang perlu ikut dicatat?
4. Kapan alert benar-benar dibuat, dan pola ambang mana yang menangkap kasus seperti 0263?
5. Kalau satu rule berisik mendominasi skor, bagaimana menyetelnya, dan apa pengaruh Asset & Identity yang belum lengkap?
6. Apakah risk score ini sama dengan risiko yang dibahas manajemen dan auditor?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, dan pertanyaan 6 di bagian 1.6. Bagian 2 menjalankan query yang dipakai untuk memeriksa dan menyetel semuanya di data PT JAB.

**Kapan relevan:** saat antrean penuh alert berkualitas rendah dan kamu tidak mau kehilangan sinyalnya, saat merancang detection yang berguna tetapi tidak cukup yakin untuk dialertkan sendiri, saat menyetel detection berisik yang sudah ada, dan saat membaca atau mengkalibrasi finding group di ES.
**Kapan bukan jawaban:** RBA tidak memperbaiki detection yang logikanya salah, tidak menggantikan detection berfidelitas tinggi yang memang harus langsung dilihat analyst, dan tidak memberi bukti apa pun dengan sendirinya. Skor juga bukan penilaian risiko organisasi, dan tanpa daftar aset dan identitas yang terawat, bobot kontekstualnya hanya berlaku untuk sebagian entity (bagian 1.5 dan Day 26).

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah Splunk dan ES dari Day sebelumnya (index, detection, finding, annotation, analyst queue, Asset & Identity) tidak diulang di sini. Tabel ini memuat istilah risk framework yang dipakai Day ini; cari kolom padanan bila sebuah istilah terasa jauh dari pekerjaan harian.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Alert fatigue | Antrean yang terlalu penuh oleh alert berkualitas rendah, sehingga alert yang benar ikut terlewat | Alarm flapping di NMS yang akhirnya diabaikan operator |
| Risk-Based Alerting (RBA) | Pola kerja saat detection lemah memberi skor ke entity dan alert dibuat dari akumulasinya | Skor reputasi per host atau user yang naik setiap kali ada sinyal kecil |
| Risk score | Metrik tunggal yang menunjukkan risiko relatif sebuah entity dari waktu ke waktu | Angka kumulatif per perangkat di daftar pengawasan |
| Entity | Aset, identitas, user, atau perangkat yang diberi skor; tipenya `system` atau `user` | Objek yang dipantau di NMS, yaitu perangkat atau pelanggan |
| Intermediate finding (risk event) | Satu catatan skor yang dibuat tiap kali detection cocok, lalu diindeks di risk index | Satu baris di log pengawasan perangkat, bukan tiket |
| Risk index | Index ES tempat intermediate finding disimpan | Rekap sinyal kecil yang belum menjadi tiket |
| Risk rule | Detection event-based yang pengaturan risikonya diisi, sehingga outputnya skor | Threshold kecil yang menambah poin tanpa membangunkan siapa pun |
| Threat object (ES 8: observable) | Artefak ancaman yang menyertai skor: hash, domain, IP eksternal, command line | Serial atau firmware modem yang dicatat sebagai penyebab, bukan pelanggannya |
| Risk factor | Pengali kontekstual yang menyesuaikan skor menurut atribut entity | Bobot prioritas pelanggan korporat dibanding pelanggan rumah |
| Finding-based detection (risk incident rule) | Detection yang membaca intermediate finding dan membuat alert saat ambang terlewati | Aturan lapisan kedua: perangkat masuk daftar periksa setelah beberapa sinyal |
| Finding group (risk notable) | Alert hasil finding-based detection yang masuk antrean triage | Tiket yang akhirnya dibuat untuk satu perangkat |
| Score stacking | Satu rule berisik mencapai ambang sendirian karena skornya menumpuk | Satu interface flapping yang mendominasi laporan gangguan mingguan |
| Ad-Hoc Risk Entry | Form di dashboard Risk analysis untuk menambah atau mengurangi skor secara manual | Catatan manual operator di daftar perangkat yang diawasi |
| Risk badge | Penanda warna di antrean yang menunjukkan rentang skor sebuah entity | Warna status perangkat di layar NOC |

### 1.1 Kenapa RBA ada dan apa yang berubah

Keluhan SOC lead PT JAB adalah gejala dari desain, bukan dari kelalaian analyst. Pada model alert tradisional, setiap detection langsung menjadi notable. Akibatnya detection yang lemah tetapi berguna, misalnya PowerShell dengan argumen tertentu atau akses ke share yang tidak biasa, dimatikan karena berisik, dan analyst tenggelam oleh sisanya.

RBA membalik pendekatan itu:

- Detection lemah tidak langsung menjadi alert. Ia memberi skor risiko pada sebuah entity, yaitu user atau sistem.
- Alert, yang di ES 8 berbentuk finding group, baru muncul ketika akumulasi atau pola risiko pada satu entity cukup kuat.

Splunk menggambarkan RBA sebagai cara mengurangi jumlah alert sambil menaikkan fidelitasnya [S2]. FAQ RBA di komunitas Splunk menyebut pelanggan melihat penurunan volume alert 50-90% [S7]. Perlakukan angka itu sebagai klaim vendor dengan rentang lebar: materi Splunk lain pernah memakai rentang berbeda, dan hasil di organisasimu bergantung pada berapa banyak detection berisik yang dipindah ke risk. Ukur sendiri volume finding sebelum dan sesudah.

Yang berubah untuk analyst L1 PT JAB bukan hanya jumlah item di antrean, tetapi juga bentuk pekerjaannya. Satu finding group datang sebagai kumpulan sinyal dengan urutan waktu dan label taktik, sehingga pertanyaan pertama bukan lagi "apakah alert ini penting" melainkan "apakah rangkaian ini masuk akal untuk akun dan host ini".

### 1.2 Komponen dan alur (ES 8.7)

Untuk kasus 0263, empat alert kecil yang ditutup terpisah itu seharusnya menjadi empat skor pada entity yang sama. Alur di bawah menunjukkan di mana setiap objek berada, mulai dari detection sampai antrean.

```
Risk rule (event-based detection + risk analysis)
   |  setiap match -> INTERMEDIATE FINDING (risk event) di index=risk
   |                  { entity, entity type (system|user), risk score, risk message, threat object(s), annotations }
   v
Risk factors (pengali kontekstual, mis. user_category, prioritas aset)
   v
Risk incident rule (finding-based detection): ambang skor dalam jendela waktu, keragaman taktik/sumber
   v
FINDING GROUP ("risk notable") di analyst queue  -> investigation -> disposition
```

Definisi dari dokumentasi ES 8.7 [S1]:

- **Risk score:** metrik tunggal yang menunjukkan risiko relatif sebuah entity dari waktu ke waktu.
- **Entity:** aset, identitas, user, atau perangkat. Tipenya `system` (dicocokkan dengan lookup aset) atau `user` (lookup identitas).
- **Intermediate finding:** dibuat saat detection menemukan event mencurigakan, berisi entity, tipe entity, risk score, dan risk message, lalu diindeks di risk index.
- **Risk modifier atau pengaturan risiko di detection:** pengaturan yang memberi skor ke entity saat detection cocok, yaitu field entity, tipe entity, skor, threat object, dan pesan.
- Risk factor (lewat Risk Factor Editor): menyesuaikan skor intermediate finding berdasarkan atribut konteks, misalnya mengalikan skor untuk `user_category` tertentu atau prioritas aset.
- **Finding-based detection:** mengagregasi intermediate finding dengan ambang. Contoh default yang disebut dokumentasi: skor risiko melewati ambang dalam 24 jam, atau terwakilinya beberapa taktik ATT&CK. Saat ambang terlewati, finding dibuat untuk diinvestigasi [S1].
- **Risk analysis dashboard:** Analytics > Dashboards > Risk analysis. Menampilkan skor per entity dan annotation, timeline, serta Ad-Hoc Risk Entry untuk penyesuaian skor manual [S1].
- Risk badge di analyst queue: kuning 0-25, oranye 25-50, merah muda 50-75, merah tua 75+, untuk entity dengan event risiko dalam 7 hari terakhir [S1].

**Catatan field:** dokumentasi ES 8.7 memakai istilah entity dan entity type. Nama field klasik di risk index adalah `risk_object` dan `risk_object_type` (Day 31), cek nama field fisik di ES 8.7 sebelum menulis SPL produksi.

Satu pembedaan yang menentukan apakah deduplikasi dan korelasi lintas entity bisa bekerja:

- Entity adalah korban atau pelaku internal yang diberi skor, yaitu user dan host.
- Threat object, yang di ES 8 disebut observable, adalah artefak ancaman yang menyertai: hash, domain, IP eksternal, atau command line [S5].

Pada 0263, entity-nya `rina.wulandari` dan `JKT-WS-0523`, sedangkan threat object-nya nama task `\EdgeUpdateCheck` dan hash `vendorbackup.exe`. Bedanya terasa saat satu artefak muncul di banyak tempat: satu domain berbahaya di sepuluh host adalah satu threat object dengan sepuluh entity, dan itulah yang dipakai untuk mengenali kampanye, bukan untuk menaikkan skor sepuluh kali pada satu host.

### 1.3 Merancang risk rule

Detection "PowerShell terenkode" di PT JAB sudah ada dan sudah dimatikan sekali karena berisik. Mengubahnya menjadi risk rule berarti mengambil lima keputusan berikut per rule.

1. **Entity yang tepat:** `user`, `dest` (host), atau keduanya. Banyak detection memberi risiko ke dua entity, yaitu user dan sistem.
2. **Skor:** proporsional dengan kepercayaan (confidence) dan dampak (impact). ESCU menyediakan annotation Confidence dan Impact (Day 45). Detection lemah diberi skor kecil.
3. **Threat object:** artefak yang bisa dipakai untuk pivot dan deduplikasi, misalnya hash proses, domain, atau parent process.
4. **Risk message:** kalimat yang menjelaskan apa yang terjadi, dengan field dinamis. Analyst membacanya di timeline.
5. **Annotation ATT&CK:** wajib agar incident rule berbasis taktik bekerja (Day 29/30).

Panduan RBA menyarankan membangun RBA paralel dengan alerting yang ada, memperkuat threat object untuk tuning, menambah keragaman rule dari sisi sumber dan skor, memasukkan sumber berbasis signature seperti IDS, DLP, dan EDR sebagai risiko, serta mengubah konten berisik menjadi risk scoring [S2]. Saran "paralel" itu penting untuk PT JAB, karena sebagian pekerjaan L1 masih berjalan di app Search & Reporting dan alert terjadwal lama tidak bisa dimatikan dalam satu malam.

### 1.4 Merancang risk incident rule

Pertanyaan SOC lead tentang kasus 0263 sebenarnya pertanyaan tentang lapisan kedua: pola seperti apa yang akan menangkap empat sinyal kecil dari sumber berbeda pada satu akun dalam setengah hari. Tabel ini membandingkan lima pola yang umum dipakai; cari kolom Risiko untuk melihat cara masing-masing pola gagal.

| Pola | Logika | Kekuatan | Risiko |
|---|---|---|---|
| Ambang skor | `sum(risk_score) > N` per entity dalam 24 jam | Sederhana | Score stacking: satu rule berisik bisa mencapai ambang sendirian |
| Keragaman taktik | `dc(taktik ATT&CK) >= k` | Menangkap progresi serangan | Bergantung annotation yang benar |
| Keragaman sumber | `dc(source) >= k` (detection berbeda) | Mencegah stacking dari satu rule | Bisa melewatkan serangan yang hanya memicu satu jenis detection |
| Kombinasi | skor tinggi dan minimal dua taktik atau sumber | Fidelitas tinggi | Butuh kalibrasi |
| Jendela panjang | ambang lebih rendah dalam 7 hari | Menangkap low-and-slow | Lebih banyak data dan noise |

Komunitas RBA menyediakan contoh search "score stacking limitations", deduplikasi, dan prevalensi threat object [S3][S4] `[komunitas]`. Konsepnya dikonfirmasi oleh dokumentasi ES yang memakai ambang skor dan multi-taktik [S1].

### 1.5 Menyetel RBA

Satu rule PowerShell di PT JAB menyala ribuan kali per bulan, sedangkan rule scheduled task menyala puluhan kali. Tanpa penyetelan, rule pertama yang menentukan isi antrean, bukan rule yang paling bermakna.

- **Score stacking:** deduplikasi kontribusi per kombinasi entity, source, dan threat object dalam jendela waktu, sebelum dijumlahkan (bagian 2.3).
- **Risk factors:** naikkan skor untuk entity sensitif seperti admin, eksekutif, dan server kritis, lalu turunkan untuk entity yang memang diharapkan berisik seperti jump host dan scanner [S1].
- Allowlist sempit pada risk rule bila benign positive berulang (Day 34).
- Panel Executive summary "jenis event risiko yang tidak menghasilkan risk notable" (Day 32) menunjukkan rule yang tidak pernah berkontribusi. Kandidatnya dihapus, atau skornya terlalu rendah.
- **Ad-Hoc Risk Entry:** analyst bisa menambah atau mengurangi risiko secara manual saat investigasi [S1]. Gunakan dengan catatan alasan.

Di PT JAB ada satu batas yang perlu dinyatakan terang-terangan sebelum risk factor dipakai sebagai argumen. Risk factor bekerja atas atribut konteks seperti `user_category` dan prioritas aset [S1], dan atribut itu berasal dari daftar aset dan identitas. Karena aset POP dan perangkat pelanggan belum masuk daftar, entity dari segmen itu tidak terkena pengali apa pun dan diperlakukan seperti aset biasa. Akibatnya urutan antrean memihak bagian estate yang datanya sudah rapi. Ukur dulu berapa banyak entity yang tidak dikenal daftar aset (Day 26), lalu baru putuskan besar pengalinya.

### 1.6 Risk di RBA bukan risk management organisasi

Pertanyaan terakhir SOC lead muncul karena kata "risk" dipakai di dua rapat yang berbeda. Risk di RBA adalah akumulasi sinyal perilaku per entity untuk prioritas alert. Itu bukan penilaian risiko organisasi, yang menimbang likelihood dan impact atas aset bisnis dan berakhir pada keputusan manajemen (Day 29). Dua angka itu tidak bisa dijumlahkan, dibandingkan, atau dipakai saling menggantikan di laporan.

**Tanpa ES:** RBA dan risk framework adalah fitur ES. Di Splunk Enterprise biasa, konsepnya bisa ditiru: detection menulis ke sebuah index risk di lab lewat `collect` atau alert action, lalu saved search terjadwal mengagregasi per entity (bagian 2.5). Yang tidak kamu dapat adalah Asset & Identity, risk factor, annotation terkelola, risk badge, dan finding group, jadi pengali konteks dan pengelompokan alert harus ditulis sendiri sebagai lookup dan SPL. Di PT JAB keduanya hidup berdampingan, karena ES baru dipasang di search head terpisah sementara sebagian alert L1 masih berjalan dari app Search & Reporting.

## 2. Contoh SPL dan langkah di ES

> Semua keluaran di bagian ini adalah keluaran ilustrasi, bukan hasil eksekusi. Asumsi: ES 8.7 di search head terpisah dengan risk index aktif, dan field klasik `risk_object`, `risk_object_type`, `risk_score`, `risk_message`, `threat_object`, serta `source`; cek nama field fisiknya di ES 8.7 karena dokumentasinya memakai istilah entity. Untuk lab tanpa ES, lihat bagian 2.5.

Empat search pertama mengikuti urutan yang dipakai saat meninjau kasus 0263: melihat riwayat satu entity, mencoba pola incident rule, memperbaikinya supaya tahan score stacking, lalu mencari rule yang hanya menambah volume.

### 2.1 Timeline risiko satu entity

**Tujuan:** melihat apa yang sebenarnya terjadi pada `rina.wulandari` di hari sebelum task `\EdgeUpdateCheck` dibuat, dalam satu tabel yang bisa disalin ke note tiket.

```
index=risk earliest=-7d risk_object="rina.wulandari"
| eval tactic=mvjoin('annotations.mitre_attack.mitre_tactic', ",")
| table _time source risk_score risk_message threat_object tactic
| sort _time
```

- `annotations.mitre_attack.mitre_tactic` berpotensi multivalue karena satu detection boleh dipetakan ke beberapa taktik, jadi `mvjoin()` dipakai supaya nilainya terbaca sebagai satu kolom.
- `source` di risk index berisi nama detection yang menulis event risiko itu, sehingga kolom ini sekaligus menjawab "rule mana yang menyumbang".

Keluaran ilustrasi, dengan kolom `risk_message` dipendekkan supaya tabelnya terbaca:

```
_time                 source                                  risk_score  risk_message                       threat_object        tactic
2026-10-12 09:14:07   JAB - Discovery beruntun                        15  whoami lalu net group              -                    Discovery
2026-10-12 09:38:11   JAB - PowerShell terenkode                      25  PowerShell -enc di JKT-WS-0523     sha256:9f2c4a...     Execution
2026-10-12 09:39:02   JAB - PowerShell terenkode                      25  PowerShell -enc di JKT-WS-0523     sha256:9f2c4a...     Execution
2026-10-12 09:41:55   JAB - PowerShell terenkode                      25  PowerShell -enc di JKT-WS-0523     sha256:9f2c4a...     Execution
2026-10-12 10:02:40   JAB - Scheduled task dari script host           40  Task dibuat oleh vendorbackup.exe  \EdgeUpdateCheck     Persistence
2026-10-12 10:17:23   JAB - PowerShell terenkode                      25  PowerShell -enc di JKT-WS-0523     sha256:9f2c4a...     Execution
2026-10-12 10:48:09   JAB - Akses share administratif                 25  Akses backup$ di JKT-FS01          \\JKT-FS01\backup$   Lateral Movement
2026-10-12 10:49:31   JAB - Akses share administratif                 25  Akses backup$ di JKT-FS01          \\JKT-FS01\backup$   Lateral Movement
2026-10-12 11:03:18   JAB - Akses share administratif                 25  Akses backup$ di JKT-FS01          \\JKT-FS01\backup$   Lateral Movement
2026-10-12 11:26:44   JAB - PowerShell terenkode                      25  PowerShell -enc di JKT-WS-0523     sha256:9f2c4a...     Execution
2026-10-12 13:52:06   JAB - PowerShell terenkode                      25  PowerShell -enc di JKT-WS-0523     sha256:9f2c4a...     Execution
```

**Cara membaca hasil:** ada dua pola di tabel yang sama, dan keduanya perlu dibaca terpisah. Pola pertama adalah progresi taktik: Discovery pada 09:14, Execution pada 09:38, Persistence pada 10:02, lalu Lateral Movement pada 10:48, seluruhnya dalam satu setengah jam pada satu akun. Itulah sinyal yang hilang ketika empat alert ditutup oleh tiga analyst berbeda. Pola kedua adalah pengulangan: enam dari sebelas baris datang dari satu source dengan threat object yang sama, yaitu hash yang sama persis. Jumlah skor naif di tabel ini 280, dan 150 di antaranya berasal dari enam event PowerShell yang sebenarnya satu perilaku berulang. Angka yang dibaca analyst harus selalu disertai pertanyaan "dari berapa rule dan berapa artefak".
**Variasi:** ganti `risk_object` dengan `"JKT-WS-0523"` untuk melihat sudut pandang host, atau tutup pipeline dengan `| stats sum(risk_score) AS total count BY source` untuk langsung melihat penyumbang terbesar tanpa membaca sebelas baris.
**Kapan gagal:** bila entity tidak ternormalisasi, riwayat yang sama terpecah antara `rina.wulandari` dan `JAB\rina.wulandari` sehingga timeline terlihat pendek (bagian 4). Kolom `tactic` kosong bila detection dibuat tanpa annotation, dan dalam keadaan itu pola progresi taktik tidak bisa dipakai sama sekali.

### 2.2 Risk incident rule: skor dan keragaman

**Tujuan:** mencoba pola lapisan kedua pada data 24 jam PT JAB, untuk melihat entity mana yang akan muncul di antrean bila ambang itu dipakai.

```
index=risk earliest=-24h
| stats sum(risk_score) AS total_risk dc(source) AS sources
        dc(annotations.mitre_attack.mitre_tactic) AS tactics values(source) AS rules
        BY risk_object risk_object_type
| where total_risk >= 100 AND (sources >= 3 OR tactics >= 2)
| sort - total_risk
```

- Gabungan ambang skor dan keragaman mengurangi stacking.
- Ambang ilustratif. Kalibrasi dengan data 30 hari (bagian 3).
- `values(source)` menghasilkan field multivalue, jadi satu baris hasil bisa menampilkan beberapa nama rule bertumpuk.

Keluaran ilustrasi:

```
risk_object      risk_object_type  total_risk  sources  tactics  rules
rina.wulandari   user                     280        4        4  JAB - Akses share administratif
                                                                 JAB - Discovery beruntun
                                                                 JAB - PowerShell terenkode
                                                                 JAB - Scheduled task dari script host
JKT-WS-0523      system                   125        3        3  JAB - Discovery beruntun
                                                                 JAB - PowerShell terenkode
                                                                 JAB - Scheduled task dari script host
svc_backup       user                     115        3        3  JAB - Akses share administratif
                                                                 JAB - Discovery beruntun
                                                                 JAB - PowerShell terenkode
```

**Cara membaca hasil:** dua baris teratas adalah dua sisi dari satu kejadian, yaitu akun dan workstation yang dipakainya, jadi keduanya harus ditangani sebagai satu kasus walaupun mesin menyajikannya sebagai dua entity. Skor host lebih kecil karena rule yang sama diatur memberi bobot lebih besar ke user daripada ke sistem. Baris ketiga adalah pengingat bahwa akun layanan seperti `svc_backup` memang mengumpulkan skor dari aktivitas terjadwal yang wajar, dan itulah kandidat pertama untuk allowlist sempit atau risk factor yang menurunkan bobot. Yang tidak muncul juga informatif: `JKT-FS01` mengumpulkan 45 dari satu source saja, sehingga ia gagal di dua syarat sekaligus dan tidak membebani antrean.
**Variasi:** turunkan ambang menjadi 60 dengan jendela `earliest=-7d` untuk mencari pola low-and-slow, atau tambahkan `values(threat_object) AS artefak` supaya analyst langsung melihat artefak yang perlu dipivot.
**Kapan gagal:** bila annotation tidak diisi, `tactics` menjadi 0 untuk semua baris dan syarat keragaman taktik mati tanpa pesan apa pun, sehingga seluruh beban jatuh ke `sources`. Nama field entity juga perlu dicek di ES 8.7 sebelum search ini dipakai di produksi.

### 2.3 Deduplikasi sebelum menjumlah (anti score stacking)

**Tujuan:** menjawab keberatan utama atas bagian 2.2, yaitu bahwa 280 pada baris pertama belum tentu berarti empat kali lebih berbahaya daripada 70.

```
index=risk earliest=-24h
| eval tobj=coalesce(threat_object, "none")
| stats max(risk_score) AS risk_score values(annotations.mitre_attack.mitre_tactic) AS tactic
        BY risk_object risk_object_type source tobj
| stats sum(risk_score) AS total_risk dc(source) AS sources BY risk_object risk_object_type
| where total_risk >= 100
```

- Stats pertama menyisakan satu kontribusi per kombinasi entity, source, dan threat object, dengan skor maksimum. Pengulangan dari rule yang sama atas artefak yang sama tidak lagi menumpuk.
- Stats kedua menjumlahkan per entity.
- Pola ini sejalan dengan diskusi deduplikasi di komunitas RBA [S3][S4] `[komunitas]`.

Keluaran ilustrasi:

```
risk_object      risk_object_type  total_risk  sources
rina.wulandari   user                     105        4
```

**Cara membaca hasil:** skor `rina.wulandari` turun dari 280 menjadi 105 karena enam event PowerShell dengan hash yang sama kini dihitung satu kali, begitu pula tiga akses ke share yang sama. Dua entity lain jatuh di bawah ambang (`JKT-WS-0523` menjadi 50 dan `svc_backup` menjadi 65), sehingga yang perlu ditriage turun dari tiga menjadi satu, dan yang tersisa adalah entity yang memang perlu dilihat. Konsekuensinya harus diterima dengan sadar: ambang yang dikalibrasi untuk jumlah naif menjadi terlalu tinggi setelah deduplikasi, dan host `JKT-WS-0523` tidak lagi muncul sendiri. Pilihannya menurunkan ambang, mengkalibrasi ambang terpisah untuk entity bertipe `system`, atau menyandarkan pengelompokan host dan akun pada tahap investigasi.
**Variasi:** tambahkan `bin _time span=1h` sebelum stats pertama dan masukkan `_time` ke kunci agregasi, supaya perilaku yang berulang di jam berbeda tetap menyumbang sekali per jam, bukan sekali per hari. Ganti `max()` dengan `latest()` bila skor sebuah rule memang berubah menurut konteks.
**Kapan gagal:** bila sebagian besar rule tidak mengisi threat object, `coalesce()` mengisi `none` untuk semuanya dan kunci deduplikasi runtuh menjadi entity dan source saja, sehingga pengulangan atas artefak berbeda ikut hilang. `threat_object` juga berpotensi multivalue karena satu event bisa membawa beberapa observable; dalam keadaan itu kunci dedup perlu dinormalisasi dulu, misalnya dengan `mvjoin()` atau `mvexpand`, dan pilihannya harus dicatat karena mengubah angka hasil.

### 2.4 Rule yang tidak pernah berkontribusi ke risk notable

**Tujuan:** memberi detection engineer daftar prioritas penyetelan, yaitu rule yang paling banyak menambah volume risiko di 30 hari terakhir.

```
index=risk earliest=-30d
| stats count dc(risk_object) AS entities avg(risk_score) AS avg_score BY source
| sort - count
```

Keluaran ilustrasi:

```
source                                  count  entities  avg_score
JAB - PowerShell terenkode               4120       612      25.0
JAB - Discovery beruntun                 1870       441      15.0
JAB - Akses share administratif            903       128      25.0
JAB - Scheduled task dari script host       47        31      40.0
JAB - Login RADIUS dari ASN tak lazim       12         9      20.0
```

**Cara membaca hasil:** dari 6.952 event risiko dalam 30 hari, 4.120 atau sekitar 59 persen berasal dari satu rule, dan rule itu menyentuh 612 entity berbeda. Kalau `count` dikalikan `avg_score`, sumbangan skornya sekitar 103.000 dari total sekitar 155.700, atau sekitar dua pertiga seluruh risiko di deployment ini. Rule dengan volume besar dan skor seragam seperti itu adalah penyebab utama score stacking. Lawan bacanya di baris terakhir: `JAB - Login RADIUS dari ASN tak lazim` hanya menyala 12 kali, dan rule selangka itu perlu diperiksa dari arah berlawanan, apakah memang jarang terjadi atau sumber datanya sedang tidak masuk.
**Variasi:** tambahkan `| eval kontribusi=count*avg_score | sort - kontribusi` supaya urutannya mengikuti sumbangan skor, bukan jumlah event. Bandingkan daftar ini dengan finding group 30 hari: rule bervolume besar yang tidak pernah berada di finding group ber-disposisi true positive adalah kandidat penurunan skor atau perbaikan logika.
**Kapan gagal:** `source` berisi nama saved search, jadi detection yang pernah diganti nama akan tampil sebagai dua baris dan riwayatnya terlihat pendek. Penyesuaian manual lewat Ad-Hoc Risk Entry juga muncul di sini dengan source tersendiri, dan itu bukan rule yang perlu disetel.

### 2.5 Lab tanpa ES: RBA mini

**Tujuan:** membuktikan sendiri mekanisme dua lapisan di search head tanpa ES, tempat sebagian alert PT JAB masih berjalan.

Langkah 1, tiga risk rule lab menulis ke index `lab_risk`. Contoh satu rule:

```
index=sysmon EventCode=1 Image="*\\powershell.exe" CommandLine="*-enc*"
| eval risk_object=host, risk_object_type="system", risk_score=20,
       risk_message="Encoded PowerShell on ".host, source="lab_ps_encoded", tactic="Execution"
| table _time risk_object risk_object_type risk_score risk_message source tactic CommandLine
| collect index=lab_risk
```

- `collect` menulis hasil ke index lain. Cek izin, index tujuan, dan efek `collect` pada lisensi di versi-mu.

Langkah 2, risk incident rule terjadwal:

```
index=lab_risk earliest=-24h
| stats sum(risk_score) AS total dc(source) AS sources dc(tactic) AS tactics values(risk_message) AS msgs BY risk_object
| where total>=50 AND sources>=2
```

Keluaran ilustrasi setelah rangkaian jinak di bagian 3 dijalankan sekali:

```
risk_object    total  sources  tactics  msgs
JKT-WS-0523       65        3        3  Discovery commands on JKT-WS-0523
                                        Encoded PowerShell on JKT-WS-0523
                                        Scheduled task created on JKT-WS-0523
```

**Cara membaca hasil:** 65 adalah jumlah dari tiga rule lab, yaitu 15 untuk discovery, 20 untuk PowerShell terenkode, dan 30 untuk scheduled task, dan tidak ada satu pun yang mencapai ambang 50 sendirian. Itulah seluruh gagasan RBA dalam satu baris. `msgs` multivalue, sehingga baris itu juga menjadi ringkasan kejadian yang bisa disalin ke note.
**Variasi:** jalankan PowerShell terenkode berulang dan bandingkan hasilnya dengan versi deduplikasi di bagian 2.3 untuk melihat efek stacking dengan angka sendiri.
**Kapan gagal:** index `lab_risk` tidak ada atau role-mu tidak berhak menulis ke sana, sehingga `collect` gagal tanpa mengubah hasil search yang terlihat di layar. Periksa `index=lab_risk` secara terpisah sebelum menjadwalkan rule-nya.

### 2.6 Langkah di ES (generik)

Urutan ini yang kamu kerjakan di search head ES PT JAB setelah pola di atas disetujui SOC lead.

1. Configure > Content management, pilih detection, lalu atur bagian risiko: field entity, tipe entity, skor, threat object, dan pesan [S1]. Cek nama bagian ini di editor 8.7.
2. Risk Factor Editor untuk faktor kontekstual [S1], cek letak menunya.
3. Aktifkan atau sesuaikan finding-based detection default, yaitu ambang 24 jam dan multi-taktik [S1].
4. Pantau Analytics > Dashboards > Risk analysis [S1].

## 3. Lab praktik

1. Bangun RBA mini (bagian 2.5) dengan tiga risk rule lab:
   - PowerShell terenkode (Execution);
   - schtasks dari script host (Persistence, Day 30);
   - `whoami` dan `net user` beruntun (Discovery).

   Beri skor 10-30 dan tulis ke `lab_risk`.
2. Di VM Windows lab (snapshot), jalankan rangkaian jinak: `whoami /all`, `net user`, PowerShell terenkode `Get-Date`, lalu buat scheduled task uji dan hapus setelahnya.
3. Jalankan incident rule bagian 2.5 langkah 2. Hasil yang diharapkan: host lab muncul dengan minimal 2 sumber dan 2 taktik.
4. Tambah noise: jalankan PowerShell terenkode 20 kali. Bandingkan hasil versi tanpa deduplikasi dengan versi bagian 2.3, lalu amati efek score stacking pada angkanya.
5. Kalibrasi: jalankan bagian 2.4 atas `lab_risk` setelah beberapa hari dan tetapkan ambang yang masuk akal untuk data lab-mu, bukan ambang 100 yang dipakai sebagai ilustrasi.
6. **Dengan ES:** lakukan hal yang sama dengan detection ESCU yang setara, lalu buka Risk analysis dan finding group di analyst queue.

**Hasil yang sebaiknya tersimpan:**

- Tiga risk rule yang terbukti menulis event risiko.
- Incident rule yang menghasilkan risk notable untuk host lab, beserta angka totalnya.
- Bukti stacking tanpa dedup dan hasilnya setelah dedup, dalam dua tabel yang bisa dibandingkan.
- Penjelasan entity dibanding threat object pada contohmu sendiri.
- Ambang hasil kalibrasi beserta alasan angkanya.

**Variasi tantangan:** tambahkan risk factor lab, yaitu lookup `lab_assets.csv` (Day 26) dengan `priority=critical`, lalu kalikan skor 1,5 sebelum dijumlahkan. Bandingkan urutan entity sebelum dan sesudah, lalu catat apa yang terjadi pada host yang tidak ada di lookup itu.

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Perbaikan |
|---|---|---|
| Risk notable terlalu banyak | Ambang rendah; stacking dari satu rule | Dedup per source dan threat object; tambah syarat keragaman [S3] |
| Tidak pernah ada risk notable | Ambang tinggi; skor terlalu kecil; annotation taktik kosong | Kalibrasi dari data 30 hari; isi annotation |
| Entity terpecah (`rina.wulandari` dan `JAB\rina.wulandari`) | Identitas tidak ternormalisasi | Konvensi identitas di Asset & Identity (Day 26) |
| Skor tidak sesuai harapan | Risk factor memodifikasi diam-diam | Tinjau Risk Factor Editor [S1] |
| Risk factor tidak pernah berlaku | Entity tidak ada di daftar aset atau identitas, sehingga atribut konteksnya kosong | Ukur cakupan A&I lebih dulu (Day 26), lalu lengkapi daftarnya |
| Rule tidak muncul di risk index | Pengaturan risiko di detection belum diisi | Isi field entity dan skor di detection editor |

## 5. Kesalahan umum dan jebakan

- Menjadikan setiap rule RBA sebagai notable juga. Itu menghapus manfaat RBA.
- Menyamakan threat object dengan entity (bagian 1.2).
- Hanya memakai ambang skor, sehingga rentan stacking [S3].
- Annotation ATT&CK kosong, sehingga incident rule multi-taktik tidak bisa bekerja.
- Membaca skor sebagai bukti. Skor adalah hipotesis yang dibuat dari bobot buatan sendiri.
- Menyamakan RBA risk dengan risk management organisasi (bagian 1.6).
- `[komunitas]` Komunitas RBA di GitHub, Slack, dan office hours aktif dan banyak dipakai praktisi [S2][S3]. Search dari komunitas perlu diuji di lab sebelum dipakai di produksi.

## 6. Catatan terkini

Bagian ini menampung detail versi dan perubahan istilah yang membuat dokumentasi lama dan baru terbaca berbeda.

- ES 8.x memakai istilah intermediate finding, finding-based detection, finding group, dan entity untuk konsep RBA lama, yaitu risk event, risk incident rule, risk notable, dan risk object [S1][Day 45].
- ES 8.7 mendokumentasikan risk badge berwarna di analyst queue dan Ad-Hoc Risk Entry di Risk analysis [S1].
- Panduan RBA Splunk diperbarui Agustus 2024, setelah pertama dirilis 2022, dengan langkah kematangan paralel [S2].
- Sebagian tulisan menyamakan threat object dengan teknik ATT&CK. Itu keliru menurut glosarium ES 8: threat object adalah observable, sedangkan teknik ATT&CK masuk lewat annotation [S5].

## 7. Cheat sheet

```
RBA = sinyal lemah -> skor per ENTITY -> alert hanya saat akumulasi/pola kuat (volume turun, fidelitas naik)
RISK RULE (event-based detection + risk settings): entity field | entity type (system|user) | score | threat object | message | annotation
INTERMEDIATE FINDING (risk event) -> index=risk  [field klasik: risk_object, risk_object_type, risk_score, risk_message, threat_object, source]
RISK FACTOR (Risk Factor Editor): pengali kontekstual (user_category, prioritas aset) ; hanya berlaku bila entity ada di A&I
FINDING-BASED DETECTION (risk incident rule): default skor > ambang/24 jam ; multi taktik ATT&CK
FINDING GROUP (risk notable) -> analyst queue
DASHBOARD Analytics > Dashboards > Risk analysis (timeline, Ad-Hoc Risk Entry) ; badge 0-25/25-50/50-75/75+
TUNING   dedup (entity, source, threat object) -> sum ; syarat keragaman sumber/taktik ; risk factor ; allowlist sempit
ENTITY (yang diskor) vs THREAT OBJECT/observable (artefak: hash, domain, IP eksternal)
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Dua entity muncul di antrean pagi ini: satu akun dengan total risk 280 dari empat rule, dan satu akun dengan total risk 150 dari satu rule. Rekanmu mengambil yang 280 lebih dulu karena skornya hampir dua kali lipat. Apa yang salah dari alasan itu, walaupun keputusannya bisa jadi benar?

<details><summary>Jawaban</summary>

Alasannya salah karena membandingkan dua angka yang tidak sebanding. Skor adalah jumlah dari bobot yang kamu tetapkan sendiri, jadi 150 dari satu rule berarti satu perilaku yang berulang tiga puluh kali atau enam kali, tergantung bobotnya, sedangkan 280 dari empat rule berarti empat perilaku berbeda pada satu akun. Yang membuat entity pertama lebih layak didahulukan adalah keragaman sumber dan taktiknya, bukan besar angkanya, dan itu juga yang menjelaskan kenapa pola ambang murni rentan terhadap score stacking. Urutan yang benar adalah melihat berapa rule dan berapa threat object yang menyusun skor, lalu baru membaca totalnya. Lihat bagian 1.4 dan 2.1.

</details>

**2. Skenario keputusan.** Detection "PowerShell terenkode" di PT JAB menyala 4.120 kali dalam 30 hari pada 612 entity dan belum pernah ada di finding group yang ditutup true positive. Apa langkah yang paling tepat?

- A. Matikan detection itu, karena volumenya besar dan belum pernah membuktikan diri.
- B. Turunkan skornya dan pastikan threat object terisi, lalu periksa apakah ia masih sanggup berkontribusi ketika digabung dengan rule lain.
- C. Naikkan ambang finding-based detection sampai entity dengan rule itu saja tidak lagi lolos.

<details><summary>Jawaban</summary>

B. Rule bervolume besar dengan skor seragam adalah penyebab utama score stacking, dan perbaikannya ada di dua tempat sekaligus: bobot yang lebih kecil supaya ia tidak mencapai ambang sendirian, dan threat object yang terisi supaya pengulangan atas artefak yang sama bisa dideduplikasi. A mengulangi kesalahan yang justru melahirkan RBA, yaitu membuang sinyal yang bermakna dalam kombinasi; rule inilah yang menjadi salah satu dari empat sinyal pada kasus 0263. C menyembuhkan gejala di satu rule tetapi menaikkan ambang untuk semua entity, sehingga rangkaian sinyal lemah yang sah ikut tenggelam. Lihat bagian 1.5, 2.3, dan 2.4.

</details>

**3. Pertanyaan jebakan.** Satu domain berbahaya terlihat di sepuluh host dalam satu jam. Rekanmu mengusulkan menaikkan skor sepuluh kali pada entity domain itu supaya cepat naik ke antrean. Kenapa itu tidak jalan?

<details><summary>Jawaban</summary>

Karena domain bukan entity, melainkan threat object atau observable. Entity adalah user atau sistem yang diberi skor, yaitu pihak internal yang bisa dimiliki, diprioritaskan, dan diinvestigasi, sedangkan threat object adalah artefak ancaman yang menyertai skor supaya bisa dipivot dan dideduplikasi. Kemunculan satu domain di sepuluh host berarti sepuluh entity menerima skor masing-masing dengan satu threat object yang sama, dan nilai temuan itu ada pada prevalensinya, yaitu petunjuk kampanye yang sama menyentuh sepuluh mesin. Menjadikannya entity juga akan merusak deduplikasi, karena kunci dedup memang mengandalkan pasangan entity dan threat object yang berbeda. Lihat bagian 1.2 dan 2.3.

</details>

**4. Skenario keputusan.** Kamu membangun finding-based detection dengan syarat `total_risk >= 100 AND tactics >= 2`, dan selama dua minggu tidak ada satu pun finding group yang muncul, padahal risk index terisi ribuan event per hari. Apa yang kamu cek pertama?

- A. Apakah ambang 100 terlalu tinggi untuk deployment ini.
- B. Apakah field annotation taktik benar-benar terisi di event risiko.
- C. Apakah data model Authentication sudah terakselerasi.

<details><summary>Jawaban</summary>

B. Syarat `tactics >= 2` dihitung dari annotation ATT&CK yang dibawa setiap intermediate finding, dan bila risk rule dibuat tanpa mengisi annotation, nilai `dc()` itu menjadi 0 untuk semua entity. Syaratnya lalu tidak mungkin terpenuhi berapa pun skornya, dan tidak ada pesan error karena search tetap valid. A masuk akal sebagai langkah kedua, tetapi ambang yang terlalu tinggi biasanya masih meloloskan satu atau dua entity dalam dua minggu, bukan nol. C tidak relevan karena search ini membaca risk index, bukan data model. Lihat bagian 1.3, 1.4, dan 2.2.

</details>

**5. Jelaskan ulang.** Jelaskan ke analyst L1 yang baru masuk, dalam tiga kalimat, apa yang berubah di pekerjaannya ketika sepuluh detection berisik dipindahkan ke RBA.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh jawaban: "Sepuluh detection itu tidak lagi membuat item di antreanmu, melainkan menambah skor pada akun atau host yang terlibat, dan catatannya disimpan di risk index. Antrean baru menerima satu item ketika skor atau keragaman sinyal pada satu akun atau host melewati ambang, jadi yang kamu buka bukan satu alert kecil, melainkan rangkaian beberapa sinyal dengan urutan waktu dan label taktiknya. Pertanyaan pertamamu ikut berubah: bukan lagi apakah alert ini penting, melainkan apakah rangkaian ini masuk akal untuk akun dan host ini, dan skornya sendiri bukan bukti karena angkanya berasal dari bobot yang kami tetapkan."

Kesalahan yang sering muncul: mengatakan alert menjadi lebih sedikit tanpa menyebut bahwa sinyalnya tetap tersimpan; menyebut skor tinggi sebagai tanda insiden; dan lupa bahwa satu kejadian bisa muncul sebagai dua entity, yaitu akun dan host, sehingga keduanya perlu dihubungkan saat investigasi. Lihat bagian 1.1 dan 2.2.

</details>

**6. Pertanyaan jebakan.** SOC lead meminta risk factor yang mengalikan skor untuk aset kritis, supaya POP regional naik prioritas. Daftar aset ES PT JAB belum memuat aset POP dan perangkat pelanggan. Apa yang sebenarnya terjadi bila risk factor itu tetap dipasang?

<details><summary>Jawaban</summary>

Pengali itu hanya berlaku untuk entity yang punya atribut konteks, dan atribut itu datang dari daftar aset dan identitas. Aset POP yang belum terdaftar tidak punya prioritas, jadi ia tidak terkena pengali apa pun dan diperlakukan seperti aset biasa, sementara aset yang datanya sudah rapi naik. Hasilnya bukan prioritas yang lebih baik, melainkan antrean yang memihak bagian estate yang administrasinya paling tertib, dan efek itu tidak terlihat sebagai error. Langkah yang benar adalah mengukur dulu berapa banyak entity yang tidak dikenal daftar aset, lalu melengkapi daftarnya sebelum menyetel besar pengalinya. Lihat bagian 1.5 dan bagian 4.

</details>

**7. Interview question (English).** "Your SOC queue is full of low-value alerts, and management asks you to implement risk-based alerting. How do you approach it, and how do you know it worked?"

<details><summary>Sample answer</summary>

"I start by separating detections by confidence rather than by volume. High-confidence detections that need an immediate response stay as alerts. Low-confidence detections that are still meaningful get converted into risk rules: instead of creating an alert, each match writes a risk event against an entity, a user or a host, with a score, a message, a threat object and an ATT&CK annotation. A second layer then aggregates those risk events per entity and only raises an alert when the accumulated score and the diversity of sources or tactics cross a threshold I calibrated from historical data. The two things I watch most closely are score stacking and context quality. Score stacking is when one noisy rule reaches the threshold on its own, so I deduplicate contributions per entity, source and threat object before summing, and I require diversity rather than score alone. Context quality matters because risk factors that boost admins or critical servers only apply to entities that exist in the asset and identity lists, so an incomplete inventory silently biases the queue toward the well-documented part of the estate. For measuring success I avoid the vendor headline numbers and use my own baseline: alert volume per shift before and after, the share of closures with no action taken, how many of the new grouped alerts end up dispositioned as true positive, and whether detections I previously had to disable are now contributing to real cases. I also run RBA in parallel with existing alerting during the transition, because the goal is fewer items to triage without losing signal, and you only know you have not lost signal by comparing the two paths on the same days."

What makes this answer strong: it describes the mechanism in the right order, from per-detection risk settings to the aggregation layer, names the two failure modes that decide whether RBA actually helps, treats the published reduction figures as vendor claims rather than evidence, and defines success with measurements the candidate would own rather than with a number from marketing material.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | ES 8.7: Risk scoring in Splunk Enterprise Security (risk-based alerting) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/risk-based-alerting | primer | diakses 2026-10-07 | Tinggi |
| S2 | Splunk blog: The New & Improved Splunk Guide to Risk-Based Alerting | https://www.splunk.com/en_us/blog/security/the-new-improved-splunk-guide-to-risk-based-alerting.html | primer (vendor) | 2024-08-29; diakses 2026-10-07 | Tinggi untuk konsep dan lima building block |
| S3 | GitHub splunk/rba (komunitas RBA) | https://github.com/splunk/rba | komunitas (repo di org Splunk) | diakses 2026-10-07 | Sedang-tinggi |
| S4 | splunk.github.io/rba: Splunk RBA community site | https://splunk.github.io/rba/ | komunitas | diakses 2026-10-07 | Sedang |
| S5 | ES 8.7 Glossary (entity, observable, intermediate finding; lihat Day 45) | https://help.splunk.com/en/splunk-enterprise-security-8/release-notes-and-resources/8.7/where-to-find-help/glossary | primer | diakses 2026-10-07 | Tinggi |
| S6 | ES 8.7 Executive summary dashboard (panel risk; lihat Day 32) | https://help.splunk.com/en/splunk-enterprise-security-8/user-guide/8.7/analytics/executive-summary-dashboard | primer | diakses 2026-10-07 | Tinggi |
| S7 | Splunk Community: Risk-Based Alerting FAQs | https://community.splunk.com/t5/Splunk-Enterprise-Security/Risk-Based-Alerting-FAQs/td-p/668170 | komunitas (dikelola Splunk) | diakses 2026-10-10 | Sedang; angka reduksi adalah klaim vendor |

**Catatan sumber:** angka penurunan volume alert 50-90% adalah klaim vendor [S7], bukan hasil riset independen; cocokkan dengan teks FAQ sebelum mengutipnya. Nama field fisik risk index di ES 8.7, yaitu apakah masih `risk_object` dan `risk_object_type`, perlu dicek di instance. Search komunitas RBA [S3][S4] perlu diuji di lab sebelum dipakai di produksi. Semua angka di keluaran ilustrasi disusun agar bisa dijumlahkan ulang dan konsisten antar bagian (280 naif menjadi 105 setelah deduplikasi), tetapi bukan hasil eksekusi.
