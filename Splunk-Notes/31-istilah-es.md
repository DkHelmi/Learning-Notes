---
day: 31
title: 'Istilah dan objek ES: finding, finding group, entity, observable, adaptive response, dan pemetaan istilah ES 7 ke ES 8'
researched_on: 2026-10-10
versions_checked: Splunk ES 8.7 (glosarium; adaptive response actions); ES 8.0 (findings and finding groups); ES 8.6 (dispositions); Splunk Enterprise 10.6
---

# Day 31: Istilah dan objek ES

Cakupan: istilah dan objek inti Enterprise Security beserta alur hubungannya, dan pemetaan istilah ES 7 ke ES 8 yang masih beredar di dokumentasi dan runbook lama.

## Ide inti

Enterprise Security menambahkan beberapa objek bernama resmi di atas Splunk, dan objek-objek itu saling menyambung: detection menghasilkan finding atau intermediate finding, intermediate finding menumpuk menjadi risiko pada sebuah entity, akumulasi itu menghasilkan finding group, dan pekerjaan manusia atasnya dicatat sebagai investigation dengan disposition. Yang perlu kamu kuasai bukan hafalan definisinya, tetapi satu pertanyaan untuk setiap objek: apakah ada orang yang harus menanggapinya sekarang, atau objek itu hanya bahan hitungan. Salah menjawab pertanyaan itu membuat analyst menutup kasus yang sebenarnya sedang menumpuk, atau sebaliknya membuka ratusan tiket untuk satu rangkaian kejadian.

Masalah kedua adalah namanya ada dua generasi. ES 8 mengganti hampir semua istilah ES 7, sedangkan dokumentasi lama, blog, materi pelatihan, dan runbook internal masih memakai nama lama. Keadaan ini sudah kamu alami di NOC: vendor mengganti nama kategori alarm di NMS versi baru, dan selama setahun berikutnya separuh tim menyebut alarm itu dengan nama lama sementara layarnya menampilkan nama baru. Selama dua nama dipakai bergantian dalam satu tiket, tidak ada yang bisa memastikan apakah sebuah kejadian sudah ditangani atau belum. Bedanya dengan penggantian nama alarm biasa, pemetaan ES 7 ke ES 8 tidak seluruhnya satu ke satu, jadi menerjemahkannya butuh sedikit lebih dari daftar sinonim.

```
Dua nama untuk benda yang sama (kiri: runbook lama, kanan: layar ES 8)

correlation search  -> detection (event-based)  : Content management            (bagian 1.2)
notable event       -> finding                  : analyst queue                 (bagian 1.1, 1.3)
risk event          -> intermediate finding     : risk index, tanpa antrean     (bagian 1.1, 1.5)
risk incident rule  -> finding-based detection  : Content management            (bagian 1.2)
risk notable        -> finding group            : analyst queue                 (bagian 1.1, 1.3)
Incident Review     -> analyst queue            : Mission Control               (bagian 1.2)
risk object         -> entity                   : risk index, Asset & Identity  (bagian 1.5)
threat object       -> observable               : finding dan threat list       (bagian 1.6)
```

Situasi yang dipakai sepanjang Day ini: Enterprise Security baru dinyalakan di search head terpisah milik PT Jaringan Anak Bangsa (PT JAB, ISP fiktif), sementara sebagian pekerjaan L1 masih berjalan di app Search & Reporting. SOC lead menulis di channel SOC:

> "ES-nya sudah hidup di search head baru, dan dua hal bikin kacau minggu ini. Pertama, runbook VPN kita masih menulis 'kalau notable brute force muncul di Incident Review, assign ke diri sendiri lalu naikkan ke L2', padahal di layar ES 8 tidak ada menu bernama itu. Kedua, tiket `SOC-2026-0231` ditutup dengan catatan 'ada banyak risk event tapi tidak ada notable, berarti aman'. Aku perlu satu halaman: istilah apa saja yang dipakai ES sekarang, apa padanannya dengan istilah di runbook lama kita, objek mana yang memang menuntut orang menanggapinya detik itu, mana yang cuma bahan hitungan, dan kalau analyst mau menjalankan nslookup langsung dari layar ES itu masuk kategori apa. Sekalian: kalau mau aku periksa sendiri lewat SPL, field apa yang harus aku baca?"

Pesan itu memuat enam pertanyaan:

1. Istilah apa saja yang menjadi kosakata harian ES, dan apa definisi persis masing-masing?
2. Apa padanan ES 8 untuk tiap istilah ES 7 di runbook lama, termasuk pemetaan yang tidak satu ke satu?
3. Objek mana yang menuntut tanggapan manusia sekarang, dan mana yang hanya bahan akumulasi?
4. Dari mana sebuah finding group muncul, dan apa hubungannya dengan investigation serta disposition?
5. Menjalankan nslookup dari layar ES masuk kategori apa, dan apa saja aksi bawaannya?
6. Field apa yang dibaca kalau ingin memeriksa sendiri isi risk index lewat SPL?

Pertanyaan 1 dijawab di bagian 1.0 dan 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3 dan 1.6, pertanyaan 4 di bagian 1.3, pertanyaan 5 di bagian 1.4, dan pertanyaan 6 di bagian 1.5. Bagian 2 menjalankan semuanya sebagai search dan langkah di UI, dan bagian 2.6 merangkai seluruh istilah lewat satu rangkaian kejadian.

**Kapan relevan:** membaca atau menulis ulang runbook dan note tiket di lingkungan yang memakai ES, menerjemahkan dokumentasi dan tulisan lama ke istilah produk sekarang, menjelaskan alur kerja ES ke analyst baru, dan menjawab pertanyaan interview tentang alur dari detection sampai disposition.
**Kapan bukan jawaban:** saat yang dibutuhkan cara membaca panel dan memilih dashboard ES (Day 32), saat pertanyaannya cara menyetel ambang dan bobot risiko (Day 35), saat yang dicari logika detection beserta tuningnya (Day 36), dan saat lingkunganmu belum memakai ES sama sekali, karena padanannya di Splunk Enterprise hanya alert dan alert action (Day 09).

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah Splunk dari Day sebelumnya (index, sourcetype, data model, `tstats`, alert, lookup) tidak diulang. Tabel ini memuat istilah Enterprise Security yang dipakai di Day ini, dengan kolom padanan dari pekerjaan NOC dan SOC yang sudah kamu kerjakan; definisi panjang enam istilah inti ada di bagian 1.1 supaya tidak ditulis dua kali.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Enterprise Security (ES) | App premium Splunk berisi detection, antrean kerja analyst, kerangka risiko, dan konteks aset dan identitas | Modul manajemen gangguan di atas NMS, bukan NMS-nya sendiri |
| Detection (dulu correlation search) | Search terjadwal yang mencari kondisi tertentu dan menghasilkan finding atau intermediate finding | Detection rule terjadwal di SIEM |
| Event-based detection | Detection yang mengevaluasi raw event | Alarm yang dipicu langsung oleh counter perangkat |
| Finding-based detection (dulu risk incident rule) | Detection yang mengevaluasi finding dan intermediate finding di risk index, bukan raw event | Aturan yang membaca riwayat alarm, bukan counter mentah |
| Finding (dulu notable event) | Event yang dibuat detection untuk ditinjau analyst, lengkap dengan status, pemilik, urgensi, dan disposition | Alert yang masuk antrean triage |
| Intermediate finding (dulu risk event atau contributing event) | Event risiko yang tersimpan di risk index sebagai bahan akumulasi dan tidak masuk antrean | Hitungan error di interface yang terus menumpuk tanpa memicu alarm |
| Finding group (dulu risk notable) | Kumpulan finding dan intermediate finding yang dikelompokkan finding-based detection karena ambang atau pola | Satu tiket gangguan yang menggabungkan banyak keluhan dari POP yang sama |
| Entity (dulu risk object) | Pihak internal yang diberi skor risiko: user atau sistem | Perangkat atau pelanggan yang menjadi subjek tiket |
| Observable (dulu threat object) | Artefak yang menyertai kejadian: hash, domain, IP eksternal, command line | Serial number atau tipe perangkat yang muncul di keluhan |
| Analyst queue (dulu Incident Review) | Daftar finding dan investigation yang menunggu triage, berada di Mission Control | Antrean tiket SOC |
| Investigation | Wadah kerja kolaboratif atas satu kasus: catatan, response plan, dan disposition | Tiket gangguan besar dengan catatan kerja dan langkah penanganan |
| Disposition | Kesimpulan akhir atas sebuah finding, misalnya true positive atau false positive | Kode penyelesaian tiket di NOC: benar, salah alarm, sesuai ekspektasi |
| Risk score | Angka kontribusi risiko sebuah kejadian terhadap satu entity, yang menumpuk sepanjang waktu | Skor reputasi per host atau pelanggan yang naik setiap ada sinyal kecil |
| Urgency | Prioritas satu finding, dihitung dari severity detection dan prioritas aset | Prioritas satu tiket dari gabungan dampak dan kelas pelanggan |
| Adaptive response action | Tindakan yang dijalankan detection secara otomatis atau analyst secara ad hoc dari sebuah finding | Tombol aksi di konsol: blokir, isolasi, kirim ke sandbox |
| Risk index | Index ES tempat intermediate finding beserta entity dan skornya disimpan | Tabel riwayat alarm yang dipakai untuk rekap, bukan untuk ditatap |
| Note | Catatan analyst pada finding atau investigation | Kolom catatan penanganan di tiket |
| Threat list | Daftar indikator intel yang dicocokkan dengan data yang masuk | Daftar recall vendor yang dicocokkan dengan serial perangkat |
| Annotation | Label konteks pada detection, misalnya ID teknik ATT&CK atau analytic story | Kode kategori gangguan yang ditempel di tiket |

### 1.1 Enam istilah inti

Enam istilah ini yang muncul di runbook lama PT JAB dan di hampir semua tulisan tentang ES. Tabel memuat definisinya, padanan ES 8, dan tempat istilah itu benar-benar dipakai saat bekerja.

| Istilah ES 7 | Padanan ES 8 [S1] | Definisi | Penggunaan |
|---|---|---|---|
| SPL | SPL | Search Processing Language, bahasa query Splunk. Semua detection, dashboard, dan investigasi ES berbasis SPL | Menulis dan menyetel detection (Day 36), pivot investigasi (Day 24), hunting (Day 38-39) |
| Notable event | Finding | Event yang dibuat detection untuk ditinjau analyst, dengan metadata (urgensi, pemilik, status, disposition, risiko, ATT&CK) [S1][S2] | Unit kerja triage di analyst queue (dulu Incident Review) |
| Risk notable | Finding menurut glosarium; dalam praktik berupa finding group dari finding-based detection (dulu *risk incident rule*) | Notable atau finding yang dibuat karena akumulasi risiko pada sebuah entity melewati ambang atau pola tertentu, bukan karena satu event [S2] | Inti RBA: analyst meninjau satu kasus "entity berisiko tinggi" alih-alih puluhan alert kecil (Day 35) |
| Adaptive response action | Adaptive response action | Tindakan yang dijalankan otomatis oleh detection atau ad hoc oleh analyst dari finding: membuat finding, mengirim email, menjalankan skrip, Stream capture, ping, nslookup, nbtstat, menambah threat intel, dan lain-lain [S3] | Respons dan enrichment cepat (Day 41) |
| Risk object | Entity | Objek yang diberi skor risiko: user, sistem atau aset, dan sejenisnya (`risk_object` ditambah `risk_object_type`) [S1] | Agregasi skor per user dan host di RBA |
| Contributing events | Intermediate finding (glosarium); juga event pendukung sebuah finding | Event yang berkontribusi pada terbentuknya finding. Dalam RBA, ini event risiko individual yang terkumpul menjadi risk notable atau finding group. Intermediate finding tidak tampil di analyst queue [S1][S2] | Bukti dan konteks saat menyelidiki finding group |

**Catatan glosarium ES 8.7:**
- Glosarium memetakan contributing events ke intermediate finding, dan risk notable ke finding (bukan finding group). Dokumentasi findings menjelaskan bahwa event-based detection menghasilkan finding tunggal, sedangkan finding-based detection menghasilkan finding group. Jadi dalam praktik, "risk notable" ES 7 paling dekat dengan finding group yang dihasilkan finding-based detection. Kalau ditanya padanan resmi menurut glosarium, jawabannya finding.
- Kontribusi ke satu finding group dibatasi maksimal 50 event, terpisah dari batas 100 finding per investigation [S2].

Catatan kedua itu yang menjawab tiket `SOC-2026-0231` di situasi pembuka: "banyak risk event tapi tidak ada notable" bukan kabar baik, melainkan keadaan normal untuk intermediate finding. Yang perlu diperiksa adalah apakah ada finding-based detection yang memang menjumlahkannya, bukan apakah antreannya sepi.

### 1.2 Pemetaan istilah ES 7.x ke ES 8.x

Tabel ini yang dipakai saat membaca runbook lama, dokumentasi ES 7, blog, atau materi pelatihan yang masih beredar. Cari istilah yang tertulis di dokumen lama di kolom pertama, lalu pakai kolom kedua saat menulis atau berbicara sekarang; kolom ketiga menandai pemetaan yang tidak cukup dibaca sebagai sinonim. Sumbernya glosarium ES 8.7 [S1] dan ringkasan rilis ES 8.0 [S6].

| Istilah ES 7.x | Istilah ES 8.x | Catatan singkat |
|---|---|---|
| Correlation search (juga risk rule, threat match search) | Detection (event-based) | Search terjadwal yang menghasilkan finding |
| Risk incident rule | Finding-based detection | Mengevaluasi finding dan intermediate finding -> finding group [S6] |
| Notable event | Finding | Muncul di analyst queue |
| Risk notable | Finding (menurut glosarium); dalam praktik berupa finding group yang dibuat finding-based detection | Glosarium 8.7 memetakan risk notable ke "finding", sedangkan dokumentasi findings menyebut output finding-based detection sebagai finding group. Pahami keduanya |
| Risk event / contributing events | Intermediate finding | Tidak tampil di analyst queue |
| Incident Review | Analyst queue | Daftar finding dan investigation untuk triage |
| Incident (Mission Control) / ES investigation | Investigation | Kasus kolaboratif |
| Risk object / asset / identity | Entity | Memiliki risk score |
| Threat object / indicator | Observable | Hostname, IP, URL, hash |
| Comment / risk message | Note | |
| Correlation search editor | Detection editor | |
| Intelligence workflow | Threat list | |

**Cara memakai tabel ini:** saat membaca dokumentasi atau tulisan lama, terjemahkan ke istilah ES 8 di kepala. Saat berbicara di pekerjaan atau interview, pakai istilah baru dan sebut istilah lama sebagai jembatan bila lawan bicaramu masih memakainya. Untuk runbook VPN PT JAB, kalimat "kalau notable brute force muncul di Incident Review" cukup diubah menjadi "kalau finding brute force muncul di analyst queue", dan baris yang menyebut risk notable diubah menjadi finding group dengan nama finding-based detection yang menghasilkannya, supaya orang berikutnya tahu objek mana yang dimaksud.

### 1.3 Alur objek di ES 8

```
raw events --(event-based detection)--> finding  (tampil di analyst queue)
                     \
                      +--> intermediate finding (risk event) di risk index, dengan entity + risk score + annotations
                                     |
                         (finding-based detection: ambang/pola per entity)
                                     v
                              finding group  (= "risk notable")  -> analyst queue
                                     |
                              investigation (kasus kolaboratif, response plan) -> disposition
```

Finding group dapat dikelompokkan berdasarkan: entity yang sama, threat object atau observable yang sama, ambang risiko kumulatif entity, fase Kill Chain, taktik ATT&CK, atau aturan kustom [S2].

### 1.4 Adaptive response action bawaan (ES 8.7)

Pertanyaan kelima SOC lead, yaitu nslookup dari layar ES, jatuh di kategori ini. Daftar bawaan menurut dokumentasi [S3]:

1. Send email
2. Log an event (ke index tertentu)
3. Stream Capture (packet capture lewat Splunk Stream)
4. Nbtstat
5. Nslookup
6. Create Splunk messages
7. Output results to telemetry endpoint
8. Ping
9. Run a script (dari `$SPLUNK_HOME/bin/scripts`)
10. Send to UBA
11. Send to Splunk Mobile
12. Add Threat Intelligence
13. Finding (membuat finding dengan metadata dan drilldown)

Dua cara memicu [S3]:
- **Otomatis:** dikonfigurasi di detection editor.
- **Ad hoc:** analyst menjalankannya dari finding di Mission Control.

Risk scoring (membuat event risiko untuk entity) di ES 7 disebut aksi "Risk Analysis". Halaman adaptive response ES 8.7 tidak mencantumkannya sebagai aksi terpisah [S3], cek di mana konfigurasi risiko berada di detection editor ES 8.7 (Day 35). Integrasi SOAR (Day 42) menambah aksi lewat app SOAR.

### 1.5 Field kunci di risk index

Pertanyaan keenam adalah apa yang dibaca kalau SOC lead ingin memeriksa sendiri lewat SPL. Nama field klasik di risk index (ES 7.x, kemungkinan masih dipakai di ES 8), perlu dicek
- `risk_object`: nilai entity (misalnya `svc_backup`, `JKT-FS01`);
- `risk_object_type`: jenis (misalnya `user`, `system`);
- `risk_score`: skor kontribusi event ini;
- `risk_message`: pesan yang bisa dibaca manusia;
- `threat_object`, `threat_object_type`: observable (misalnya hash, domain);
- `source`: nama detection yang menghasilkan;
- `annotations.*`: framework yang dipetakan ke detection, misalnya ID teknik ATT&CK (Day 29 dan 30 untuk frameworknya, Day 33 untuk pengaturannya di ES).

### 1.6 Pasangan istilah yang paling sering tertukar

Sebagian besar kebingungan di ES bukan karena istilahnya sulit, tetapi karena dua istilah yang berdekatan dipakai bergantian. Tabel ini merangkum lima pasangan yang paling sering salah di diskusi tim dan di tiket; kolom terakhir adalah pertanyaan yang bisa kamu ucapkan sendiri untuk memilih istilah yang benar.

| Pasangan | Bedanya | Pertanyaan penguji |
|---|---|---|
| Finding vs intermediate finding | Finding masuk analyst queue dan menuntut keputusan manusia. Intermediate finding hanya tersimpan di risk index sebagai bahan akumulasi [S1] | "Apakah ada orang yang harus menanggapi event ini sekarang?" |
| Entity vs observable (threat object) | Entity adalah pihak internal yang diberi skor (user, host). Observable adalah artefak yang menyertai (hash, domain, IP eksternal, command line) [S1] | "Apakah ini sesuatu milik organisasi yang bisa terdampak, atau jejak penyerang?" |
| Finding group vs investigation | Finding group adalah hasil otomatis finding-based detection. Investigation adalah wadah kerja kolaboratif yang dibuat analyst atau aturan, tempat catatan, response plan, dan disposition berada [S2] | "Apakah ini dibuat mesin karena ambang, atau dibuat manusia untuk bekerja?" |
| Detection vs adaptive response | Detection menemukan. Adaptive response bertindak atas hasil detection, otomatis atau ad hoc [S3] | "Apakah langkah ini mencari, atau melakukan sesuatu?" |
| Risk score vs urgency | Risk score adalah akumulasi per entity dari banyak event. Urgency adalah prioritas satu finding, dihitung dari severity detection dan prioritas aset (Day 26, Day 32) | "Apakah angka ini milik entity sepanjang waktu, atau milik satu finding?" |

Dua kebiasaan yang membantu di PT JAB, yang timnya masih campuran: selalu sebut padanan ES 7 dalam kurung saat menulis untuk tim campuran (misalnya "finding group (risk notable)"), dan jangan pernah menulis "alert" di laporan ES tanpa menjelaskan apakah yang dimaksud finding, intermediate finding, atau alert Splunk biasa.

**Tanpa ES:** semua istilah di Day ini khusus ES, kecuali SPL. Di Splunk Enterprise biasa, padanan kasarnya adalah alert (triggered alert) dan alert action, misalnya email, webhook, dan skrip (Day 09). Tidak ada risk object, finding group, atau analyst queue, dan karena itu tidak ada tempat baku untuk status, pemilik, dan disposition: semuanya hidup di sistem tiket di luar Splunk. Di PT JAB keadaan itu masih berjalan berdampingan, karena ES ada di search head terpisah sementara sebagian alert L1 tetap dibuat sebagai scheduled alert di search head biasa, sehingga satu kejadian bisa muncul sebagai finding di satu layar dan sebagai email alert di layar lain. Bagian 3 memberi cara meniru alur risiko di instance tanpa ES, dengan catatan bahwa yang ditiru hanya bentuk datanya, bukan antrean kerja beserta metriknya.

## 2. Contoh SPL dan langkah di ES

> Keluaran berlabel ilustrasi. Nama index, macro, dan field ES 8, perlu dicek. ES 7 memakai `` `notable` `` dan `index=risk`.

### 2.1 Finding hari ini per detection dan urgensi (ES 7 pola)

Pertanyaan pertama SOC lead setiap pagi: apa yang menumpuk di antrean dan dari detection mana.

```
`notable` earliest=-24h
| stats count BY rule_name urgency status_label
| sort - count
```

### 2.2 Contributing events (event risiko) untuk satu entity

Ini query yang dipakai untuk memeriksa klaim "banyak risk event tapi tidak ada notable" di tiket `SOC-2026-0231`.

```
index=risk earliest=-7d risk_object="svc_backup"
| table _time source risk_score risk_message threat_object annotations.mitre_attack.mitre_technique_id
| sort _time
```

- Hasilnya adalah "cerita" di balik sebuah risk notable atau finding group, yaitu event-event kecil yang menumpuk.
- **Cara membaca hasil:** urutan teknik (misalnya Discovery, lalu Credential Access, lalu Lateral Movement) lebih meyakinkan daripada satu event bernilai tinggi.

### 2.3 Entity dengan risiko tertinggi (bahan risk notable)

```
index=risk earliest=-24h
| stats sum(risk_score) AS total_risk dc(source) AS detections dc(annotations.mitre_attack.mitre_tactic) AS tactics
        BY risk_object risk_object_type
| where total_risk >= 100 OR tactics >= 3
| sort - total_risk
```

- Ambang 100 dan 3 taktik adalah ilustrasi. Logika RBA bawaan ES punya ambang dan aturannya sendiri (Day 35).

### 2.4 Menjalankan adaptive response secara ad hoc (UI)

1. Buka finding di Mission Control (analyst queue).
2. Pilih aksi, misalnya Nslookup pada domain, Ping pada host, atau Add Threat Intelligence untuk hash [S3].
3. Hasil aksi tercatat dan dapat ditinjau sebagai bagian investigasi, cek lokasi hasil di ES 8.7.

### 2.5 Konfigurasi otomatis di detection editor (UI)

1. Configure > Content management, pilih detection, buka Adaptive response actions, lalu tambahkan Finding (dengan urgensi atau severity, deskripsi, dan drilldown) dan aksi lain [S3].
2. Konfigurasi risiko (entity dan skor) untuk menghasilkan intermediate finding (Day 35), cek nama bagian di ES 8.7.

### 2.6 Satu serangan fiktif, enam istilah

Skenario fiktif berikut dipakai untuk mengikat semua istilah, dan menjadi tiket `SOC-2026-0274` di PT JAB. Akun `rina.wulandari` di workstation `JKT-WS-0744` menerima lampiran berbahaya, menjalankan PowerShell terenkode, lalu menjalankan beberapa command discovery, dan akhirnya login ke file server `JKT-FS01`.

Event risiko yang terbentuk dalam tiga jam (keluaran ilustrasi dari query bagian 2.2, dijalankan untuk entity di kasus ini):

```
_time     source                                   risk_object       risk_score  threat_object              tactic
09:12:04  Endpoint - Office Spawning PowerShell    JKT-WS-0744       40          winword.exe                Execution
09:12:04  Endpoint - Office Spawning PowerShell    rina.wulandari    40          winword.exe                Execution
09:13:30  Endpoint - Encoded PowerShell            JKT-WS-0744       25          powershell.exe -enc ...    Execution
09:20:11  Endpoint - Discovery Commands Burst      JKT-WS-0744       15          whoami.exe,nltest.exe      Discovery
11:47:52  Access - First Time Logon To Server      rina.wulandari    30          JKT-FS01                   Lateral Movement
```

Cara membaca istilahnya dari tabel itu:

- **SPL** dipakai di setiap langkah: detection yang menulis baris-baris ini, query yang menampilkannya, dan finding-based detection yang menjumlahkannya.
- **Contributing events atau intermediate finding:** kelima baris di atas. Tidak ada satu pun yang muncul di analyst queue, karena masing-masing terlalu lemah untuk ditangani sendiri.
- **Risk object atau entity:** `JKT-WS-0744` (tipe system, total 80) dan `rina.wulandari` (tipe user, total 70). Satu kejadian bisa memberi skor ke dua entity sekaligus.
- **Threat object atau observable:** `winword.exe`, command line PowerShell, nama tool discovery, dan `JKT-FS01` sebagai tujuan. Observable inilah yang dipakai untuk mencari host lain dengan jejak sama.
- **Risk notable atau finding group:** bila finding-based detection memakai aturan "total skor minimal 75 dalam 24 jam" atau "minimal tiga taktik ATT&CK", `JKT-WS-0744` memenuhi aturan skor (80 poin). Aturan tiga taktik tidak terpenuhi untuk host itu saja (hanya Execution dan Discovery), tetapi terpenuhi bila host dan user-nya dilihat bersama, karena login ke `JKT-FS01` menambah Lateral Movement. Karena itu ES menyediakan pengelompokan finding group berdasarkan entity maupun observable yang sama [S2]. Hasilnya satu finding group di analyst queue dengan kejadian-kejadian di atas sebagai event pendukung.
- **Adaptive response action:** analyst menjalankan Nslookup ad hoc pada domain yang dihubungi PowerShell, dan detection Office Spawning PowerShell sudah otomatis menjalankan aksi Finding untuk dirinya sendiri bila dikonfigurasi dengan output finding.

Pelajaran dari skenario ini: kalau semua detection di atas diset untuk menghasilkan finding langsung, analyst akan menerima lima tiket terpisah dengan konteks parsial. Dengan alur risk, analyst menerima satu kasus yang sudah bercerita urutan kejadiannya. Itu alasan istilah-istilah ini perlu dipahami sebagai satu rantai, bukan daftar hafalan.

## 3. Lab praktik

**Tanpa ES:**
1. Buat alert Splunk dengan dua alert action: kirim email (atau webhook ke Shuffle atau TheHive) dan Log an event ke index `lab_alerts`. Ini analog "notable".
2. Buat "event risiko" buatan: saved search yang menulis `risk_object`, `risk_score`, `risk_message` ke index `lab_risk` (lewat `collect`, cek penggunaan `collect` dan hak akses). Lalu jalankan versi bagian 2.3 di `lab_risk`.

**Dengan ES:**
1. Aktifkan satu detection ESCU yang relevan dengan data lab. Pastikan ia membuat finding dan intermediate finding.
2. Picu dari VM lab, lalu temukan finding di analyst queue dan event risiko dengan bagian 2.2.
3. Jalankan satu aksi ad hoc (Nslookup atau Ping).

**Hasil yang sebaiknya tersimpan:**
- Kartu definisi enam istilah inti beserta padanan ES 8.
- Kartu pemetaan lengkap istilah ES 7 ke ES 8 (bagian 1.2).
- Satu "notable" dan beberapa "event risiko" (ES atau analog lab).
- Satu adaptive response atau alert action yang sudah dijalankan.
- Satu paragraf runbook lama yang sudah ditulis ulang dengan istilah ES 8.

**Variasi tantangan:** gambarkan alur bagian 1.3 dengan contoh konkret dari lab-mu: nama detection, entity, skor, dan finding group yang terbentuk.

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Perbaikan |
|---|---|---|
| Detection jalan, tidak ada finding | Aksi Finding tidak dikonfigurasi | Tambahkan aksi Finding [S3] |
| Ada event risiko, tidak ada finding group | Ambang finding-based detection belum terlampaui atau detection belum aktif | Cek konfigurasi finding-based detection (Day 35) |
| Aksi ad hoc gagal | Izin atau role, konektivitas, relay (untuk aksi jarak jauh) | Cek capability; dokumentasi relay adaptive response, perlu dicek |
| Field `risk_object` kosong | Konfigurasi entity di detection salah | Tetapkan field entity dan tipenya |

## 5. Kesalahan umum dan jebakan

- Menyamakan notable dengan event risiko. Event risiko (intermediate finding) tidak muncul di antrean analyst [S1].
- Menyimpulkan bahwa antrean yang sepi berarti tidak ada aktivitas, padahal risk index sedang menumpuk tanpa finding-based detection yang menjumlahkannya.
- Menganggap risk notable sama dengan satu event berskor tinggi. Risk notable atau finding group lahir dari akumulasi atau pola [S2].
- Menganggap adaptive response hanya otomatis. Ada mode ad hoc dari finding [S3].
- Mencampur istilah ES 7 dan 8 dalam satu jawaban atau satu runbook tanpa penjelasan.
- `[komunitas]` Tidak ada sumber komunitas. Definisi dari dokumentasi ES 8.

## 6. Catatan terkini

- ES 8.x memperkenalkan istilah finding, intermediate finding, finding group, entity, dan observable [S1].
- Halaman findings ES 8.0 menandai sebagian fitur sebagai preview saat itu [S2], cek status di 8.7.
- Menurut ringkasan praktisi, penggantian istilah ES 8 diselaraskan dengan Open Cybersecurity Schema Framework (OCSF) [S6], cek klaim OCSF di dokumentasi resmi.
- Release notes ES 8.7 menyebut AI SOC Analyst yang dapat menjalankan tindakan respons yang diizinkan. Hubungannya dengan adaptive response (apakah memakai aksi yang sama dan tercatat di tempat yang sama) perlu dicek di instance.

## 7. Cheat sheet

```
SPL                -> bahasa semua detection/dashboard/investigasi
Notable event      -> FINDING (analyst queue, Mission Control)
Risk notable       -> FINDING GROUP (finding-based detection; akumulasi/pola risiko per entity)
Contributing events-> INTERMEDIATE FINDING / event pendukung (tidak di antrean)
Risk object        -> ENTITY (risk_object + risk_object_type: user/system)
Threat object      -> OBSERVABLE (hash, domain, IP, URL, command line)
Correlation search -> DETECTION (event-based) | Risk incident rule -> FINDING-BASED DETECTION
Incident Review    -> ANALYST QUEUE | Comment/risk message -> NOTE | Intelligence workflow -> THREAT LIST
Adaptive response  -> aksi otomatis (detection editor) atau ad hoc (dari finding)
   bawaan 8.7: Send email | Log an event | Stream Capture | Nbtstat | Nslookup | Create Splunk messages
               | Output to telemetry endpoint | Ping | Run a script | Send to UBA | Send to Splunk Mobile
               | Add Threat Intelligence | Finding
RISK INDEX         risk_object risk_object_type risk_score risk_message threat_object source annotations.*
ALUR               raw -> event-based detection -> finding + intermediate finding -> finding-based detection -> finding group -> investigation
BATAS              50 event per finding group | 100 finding per investigation
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Analyst shift malam PT JAB menutup tiket `SOC-2026-0231` dengan catatan "ada banyak risk event untuk `svc_backup` tapi tidak ada notable sama sekali, berarti aman". Apa yang keliru?

<details><summary>Jawaban</summary>

Kesimpulannya dibalik. Intermediate finding (dulu risk event atau contributing event) memang tidak pernah tampil di analyst queue, karena tempatnya di risk index sebagai bahan akumulasi. Jadi "tidak ada notable" adalah keadaan normal untuk objek jenis itu, bukan bukti bahwa tidak ada apa-apa. Yang seharusnya diperiksa: berapa total skor entity itu dan berapa taktik yang terlibat, lalu apakah ada finding-based detection yang aktif dan menjumlahkannya. Kalau tidak ada, akumulasi itu tidak akan pernah menjadi finding group dan tidak akan pernah masuk antrean siapa pun. Lihat bagian 1.1, 1.3, dan 1.6.

</details>

**2. Skenario keputusan.** Runbook VPN PT JAB menulis: "bila risk notable brute force muncul di Incident Review, assign ke diri sendiri lalu naikkan ke L2". Kamu diminta menulis ulang satu baris itu untuk ES 8. Mana yang kamu tulis?

- A. "Bila finding brute force muncul di analyst queue, assign ke diri sendiri lalu naikkan ke L2", karena notable dan risk notable dua-duanya menjadi finding menurut glosarium.
- B. "Bila finding group brute force dari finding-based detection `JAB - Login berhasil setelah rangkaian gagal` muncul di analyst queue, assign ke diri sendiri lalu naikkan ke L2", dan tambahkan keterangan bahwa istilah lamanya risk notable.
- C. Biarkan istilah lamanya, cukup tambahkan catatan "Incident Review sekarang bernama analyst queue", karena mengubah seluruh istilah berisiko membuat tim bingung.

<details><summary>Jawaban</summary>

B. Kata "risk notable" di runbook lama menunjuk hasil akumulasi risiko, dan dalam praktik ES 8 itu adalah finding group yang dibuat finding-based detection; menyebut nama detection-nya membuat orang berikutnya tahu objek mana yang dimaksud dan di mana ambangnya diatur. A tidak salah menurut glosarium, yang memang memetakan risk notable ke finding, tetapi di layar objeknya tampil sebagai finding group, sehingga runbook itu akan menyuruh analyst mencari sesuatu dengan nama yang tidak ada. C membiarkan dua generasi istilah hidup di dokumen yang sama, dan itu justru sumber kekacauan yang sedang diperbaiki. Lihat bagian 1.1 dan 1.2.

</details>

**3. Pertanyaan jebakan.** Seorang rekan mengusulkan: "IP penyerang dari luar sebaiknya kita daftarkan sebagai entity juga, supaya skor risikonya ikut naik dan kelihatan di Risk analysis." Apa yang perlu dikoreksi?

<details><summary>Jawaban</summary>

Entity adalah pihak internal yang bisa terdampak dan diberi skor, yaitu user atau sistem milik organisasi. IP penyerang adalah observable (dulu threat object), yaitu artefak yang menyertai kejadian bersama hash, domain, dan command line. Memberi skor pada observable membuat angka risiko kehilangan artinya, karena skor seharusnya menjawab "siapa di dalam organisasi yang paling perlu diperiksa", bukan "artefak apa yang paling sering muncul". Observable tetap sangat berguna, tetapi untuk pekerjaan lain: mencari host lain dengan jejak sama, dan mengelompokkan finding group berdasarkan observable yang sama. Lihat bagian 1.5 dan 1.6.

</details>

**4. Skenario keputusan.** Sebuah finding di analyst queue menyebut domain yang dihubungi PowerShell di `JKT-WS-0744`. Kamu ingin tahu domain itu resolve ke mana sekarang, dan tidak ingin keluar dari layar ES. Apa yang kamu lakukan?

- A. Buka terminal di server Splunk dan jalankan nslookup di sana, karena hasilnya sama saja.
- B. Jalankan adaptive response action Nslookup secara ad hoc dari finding itu di Mission Control, lalu catat hasilnya sebagai bagian investigasi.
- C. Ubah detection yang menghasilkan finding itu supaya menjalankan Nslookup otomatis, lalu tunggu finding berikutnya.

<details><summary>Jawaban</summary>

B. Adaptive response action punya dua cara pemicu: otomatis dari detection editor, dan ad hoc oleh analyst dari finding di Mission Control; Nslookup adalah salah satu aksi bawaan ES 8.7. A memang menghasilkan jawaban teknis yang sama, tetapi hasilnya tidak tercatat pada kasus, sehingga hilang dari jejak kerja dan dari investigation. C menyelesaikan masalah untuk kejadian yang akan datang, bukan untuk finding yang sedang kamu kerjakan, dan menambah aksi otomatis ke detection tanpa alasan membuat setiap pemicu menghasilkan trafik keluar. Lihat bagian 1.4 dan 2.4.

</details>

**5. Pertanyaan jebakan.** Dalam rapat, seseorang berkata: "investigation itu kan hasil otomatis kalau skor risiko entity sudah melewati ambang." Apa yang perlu dikoreksi?

<details><summary>Jawaban</summary>

Yang lahir otomatis dari ambang atau pola per entity adalah finding group, hasil finding-based detection. Investigation adalah wadah kerja kolaboratif atas satu kasus, tempat catatan, response plan, dan disposition berada, dan dibuat analyst atau aturan, bukan dihasilkan ambang risiko. Pertanyaan penguji yang memisahkan keduanya: apakah objek ini dibuat mesin karena ambang, atau dibuat manusia untuk bekerja. Beda ini juga terlihat dari batasnya: satu finding group dibatasi maksimal 50 event yang berkontribusi, sedangkan satu investigation dibatasi 100 finding. Lihat bagian 1.1, 1.3, dan 1.6.

</details>

**6. Jelaskan ulang.** Jelaskan kepada analyst L1 baru di PT JAB, dalam tiga kalimat, apa yang terjadi antara sebuah event mentah di `wineventlog` sampai munculnya satu kasus di antrean kerja, memakai istilah ES 8.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Event mentah dibaca oleh event-based detection, dan hasilnya bisa dua macam: finding yang langsung masuk analyst queue karena memang perlu ditanggapi, atau intermediate finding yang hanya tersimpan di risk index sebagai skor untuk entity-nya, yaitu user atau host yang terlibat. Kalau skor atau pola pada satu entity melewati aturan yang kita tetapkan, finding-based detection menggabungkan kejadian-kejadian kecil itu menjadi satu finding group, dan itulah yang muncul di antrean sebagai satu kasus dengan ceritanya, bukan lima tiket terpisah. Pekerjaan kita di atasnya dicatat di investigation: catatan, langkah respons, lalu disposition sebagai kesimpulan akhir."

Kesalahan yang sering muncul:

- Menyebut intermediate finding sebagai "finding kecil yang ada di antrean"; objek itu tidak pernah tampil di analyst queue.
- Melewatkan entity, sehingga alur risiko terdengar seperti penjumlahan alert, padahal skornya selalu menempel pada user atau sistem tertentu.
- Memakai kata "alert" untuk semuanya, sehingga pendengar tidak tahu apakah yang dimaksud finding, intermediate finding, atau alert Splunk biasa.

</details>

**7. Interview question (English).** "Your team is moving from ES 7 to ES 8. How would you explain the object model to a new analyst, and what do you do with the old runbooks?"

<details><summary>Sample answer</summary>

"I explain it as one chain with one question attached to every object. A detection runs on a schedule; an event-based detection reads raw events and can produce a finding, which is what ES 7 called a notable event and is the thing sitting in the analyst queue waiting for a human, or an intermediate finding, which is what we used to call a risk event and which only lives in the risk index as score attached to an entity, a user or a system. When the score or the pattern on that entity crosses a rule, a finding-based detection, formerly the risk incident rule, groups those events into a finding group, which is the closest thing to the old risk notable, and that is the case the analyst actually works, with the small events as supporting evidence and the artefacts, hashes, domains and command lines, as observables rather than entities. The work itself is recorded in an investigation with notes and a disposition. For the old runbooks I do not just append a glossary: I rewrite each line to name the object on the screen, so notable becomes finding, Incident Review becomes analyst queue, and risk notable becomes the finding group from a named finding-based detection, and I keep the old term in brackets for a few months because half the team and most of the documentation still speak ES 7."

What makes this answer strong: it presents the terms as a chain rather than a glossary, attaches the decision question (does a human need to act now) to each object, is precise about risk notable mapping to finding in the glossary but to a finding group in practice, and treats the old runbooks as something to rewrite rather than annotate.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | ES 8.7: Glossary | https://help.splunk.com/en/splunk-enterprise-security-8/release-notes-and-resources/8.7/where-to-find-help/glossary | primer | diakses 2026-10-07 | Tinggi. Definisi dan pemetaan istilah |
| S2 | ES 8.0: Findings and finding groups in Splunk Enterprise Security | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.0/investigations/findings-and-finding-groups-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi; ditandai preview saat itu |
| S3 | ES 8.7: Configure adaptive response actions for detections | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/detections/configure-adaptive-response-actions-for-detections-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi |
| S4 | ES 8.6: Configure dispositions (lihat Day 34) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.6/investigations/configure-dispositions-for-findings-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi |
| S5 | ES 8.4: Configure adaptive response action relays | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.4/detections/configure-adaptive-response-action-relays-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Sedang-tinggi; versi 8.4 |
| S6 | Somerford Associates: What's new for Splunk Enterprise Security v8 | https://somerfordassociates.com/blog/whats-new-for-splunk-enterprise-security-v8 | sekunder (partner) | tanggal tidak tercatat | Sedang. Klaim OCSF dan risk incident rule perlu dicek |

**Catatan sumber:** nama field fisik di risk index ES 8.7 dan nama bagian pengaturan risiko di detection editor 8.7 perlu dicek di instance. Pemetaan glosarium (risk notable ke finding, contributing events ke intermediate finding) dan batas 50 event per finding group berasal dari dokumentasi resmi [S1][S2]. Baris risk incident rule menjadi finding-based detection dan klaim OCSF hanya berasal dari ringkasan partner [S6], jadi cocokkan dengan dokumentasi resmi. Contoh di bagian 2.6 sepenuhnya fiktif.
