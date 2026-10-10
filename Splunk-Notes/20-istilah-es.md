---
day: 20
title: 'Istilah ES: SPL, notable event, risk notable, adaptive response action, risk object, contributing events (dan padanan ES 8)'
researched_on: 2026-10-10
versions_checked: Splunk ES 8.7 (glosarium; adaptive response actions); ES 8.0 (findings and finding groups); ES 8.6 (dispositions); Splunk Enterprise 10.6
---

# Day 20: Istilah ES

Cakupan: mendefinisikan istilah dan aspek Splunk Enterprise Security beserta penggunaannya: SPL, Notable Event, Risk Notable, Adaptive Response Action, Risk Object, Contributing Events.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- mendefinisikan enam istilah inti ES versi lama dan menyebut padanan ES 8-nya.
- menjelaskan alur data dari detection, event risiko atau finding, finding group, sampai investigation.
- menyebut adaptive response action bawaan, serta bedanya eksekusi otomatis vs ad hoc.
- mencari setiap objek ini dengan SPL atau menemukannya di UI.

## 2. Konteks singkat

Istilah ini adalah kosakata harian ES. Dokumentasi dan tulisan lama memakai istilah ES 7 (*notable*, *risk notable*), sedangkan produk ES 8 memakai istilah yang diselaraskan (*finding*, *finding group*, *intermediate finding*, *entity*). Day 06 sudah memberi tabel pemetaan. Hari ini setiap istilah diperdalam beserta penggunaannya.

## 3. Konsep inti

### 3.1 Enam istilah inti

| Istilah ES 7 | Padanan ES 8 [S1] | Definisi | Penggunaan |
|---|---|---|---|
| SPL | SPL | Search Processing Language, bahasa query Splunk. Semua detection, dashboard, dan investigasi ES berbasis SPL | Menulis/menyetel detection (Day 23), pivot investigasi (Day 11), hunting (Day 24-25) |
| Notable event | Finding | Event yang dibuat detection untuk ditinjau analyst, dengan metadata (urgensi, pemilik, status, disposition, risiko, ATT&CK) [S1][S2] | Unit kerja triage di analyst queue (dulu Incident Review) |
| Risk notable | Finding menurut glosarium; dalam praktik berupa finding group dari finding-based detection (dulu *risk incident rule*) | Notable/finding yang dibuat karena akumulasi risiko pada sebuah entity melewati ambang atau pola tertentu, bukan karena satu event [S2] | Inti RBA: analyst meninjau satu kasus "entity berisiko tinggi" alih-alih puluhan alert kecil (Day 22) |
| Adaptive response action | Adaptive response action | Tindakan yang dijalankan otomatis oleh detection atau ad hoc oleh analyst dari finding: membuat finding, mengirim email, menjalankan skrip, Stream capture, ping/nslookup/nbtstat, menambah threat intel, dll. [S3] | Respons dan enrichment cepat (Day 26) |
| Risk object | Entity | Objek yang diberi skor risiko: user, sistem/aset, dll. (*risk_object* + *risk_object_type*) [S1] | Agregasi skor per user/host di RBA |
| Contributing events | Intermediate finding (glosarium); juga event pendukung sebuah finding | Event yang berkontribusi pada terbentuknya finding. Dalam RBA, ini event risiko individual yang terkumpul menjadi risk notable/finding group. Intermediate finding tidak tampil di analyst queue [S1][S2] | Bukti dan konteks saat menyelidiki finding group |

**Catatan glosarium ES 8.7:**
- Glosarium memetakan contributing events ke intermediate finding, dan risk notable ke finding (bukan finding group). Dokumentasi findings menjelaskan bahwa event-based detection menghasilkan finding tunggal, sedangkan finding-based detection menghasilkan finding group. Jadi dalam praktik, "risk notable" ES 7 paling dekat dengan finding group yang dihasilkan finding-based detection. Kalau ditanya padanan resmi menurut glosarium, jawabannya finding.
- Kontribusi ke satu finding group dibatasi maksimal 50 event, terpisah dari batas 100 finding per investigation [S2].

### 3.2 Alur objek di ES 8

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

Finding group dapat dikelompokkan berdasarkan: entity yang sama, threat object/observable yang sama, ambang risiko kumulatif entity, fase Kill Chain, taktik ATT&CK, atau aturan kustom [S2].

### 3.3 Adaptive response action bawaan (ES 8.7)

Daftar bawaan menurut dokumentasi [S3]:
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

Risk scoring (membuat event risiko untuk entity) di ES 7 disebut aksi "Risk Analysis". Halaman adaptive response ES 8.7 tidak mencantumkannya sebagai aksi terpisah [S3], cek di mana konfigurasi risiko berada di detection editor ES 8.7 (Day 22). Integrasi SOAR (Day 27) menambah aksi lewat app SOAR.

### 3.4 Field kunci di risk index

Nama field klasik di risk index (ES 7.x, kemungkinan masih dipakai di ES 8), perlu dicek
- `risk_object`: nilai entity (mis. `alice`, `WIN-LAB01`);
- `risk_object_type`: jenis (mis. `user`, `system`);
- `risk_score`: skor kontribusi event ini;
- `risk_message`: pesan yang bisa dibaca manusia;
- `threat_object`, `threat_object_type`: observable (mis. hash, domain);
- `source`: nama detection yang menghasilkan;
- `annotations.*`: framework (Day 14/16).

### 3.5 Pasangan istilah yang paling sering tertukar

Sebagian besar kebingungan di ES bukan karena istilahnya sulit, tetapi karena dua istilah yang berdekatan dipakai bergantian. Tabel ini merangkum lima pasangan yang paling sering salah di diskusi tim dan di tiket.

| Pasangan | Bedanya | Pertanyaan penguji |
|---|---|---|
| Finding vs intermediate finding | Finding masuk analyst queue dan menuntut keputusan manusia. Intermediate finding hanya tersimpan di risk index sebagai bahan akumulasi [S1] | "Apakah ada orang yang harus menanggapi event ini sekarang?" |
| Entity vs observable (threat object) | Entity adalah pihak internal yang diberi skor (user, host). Observable adalah artefak yang menyertai (hash, domain, IP eksternal, command line) [S1] | "Apakah ini sesuatu milik organisasi yang bisa terdampak, atau jejak penyerang?" |
| Finding group vs investigation | Finding group adalah hasil otomatis finding-based detection. Investigation adalah wadah kerja kolaboratif yang dibuat analyst atau aturan, tempat catatan, response plan, dan disposition berada [S2] | "Apakah ini dibuat mesin karena ambang, atau dibuat manusia untuk bekerja?" |
| Detection vs adaptive response | Detection menemukan. Adaptive response bertindak atas hasil detection, otomatis atau ad hoc [S3] | "Apakah langkah ini mencari, atau melakukan sesuatu?" |
| Risk score vs urgency | Risk score adalah akumulasi per entity dari banyak event. Urgency adalah prioritas satu finding, dihitung dari severity detection dan prioritas aset (Day 10, Day 21) | "Apakah angka ini milik entity sepanjang waktu, atau milik satu finding?" |

Dua kebiasaan yang membantu: selalu sebut padanan ES 7 dalam kurung saat menulis untuk tim campuran (misalnya "finding group (risk notable)"), dan jangan pernah menulis "alert" di laporan ES tanpa menjelaskan apakah yang dimaksud finding, intermediate finding, atau alert Splunk biasa.

### 3.6 Enterprise vs ES

Semua istilah ini khusus ES, kecuali SPL. Di Splunk Enterprise biasa, padanan kasarnya adalah alert (triggered alert) dan alert action (email, webhook, skrip). Tidak ada risk object, finding group, atau analyst queue.

## 4. Contoh SPL dan langkah di ES

> Keluaran berlabel ilustrasi. Nama index/macro/field ES 8, perlu dicek. ES 7 memakai `` `notable` `` dan `index=risk`.

### 4.1 Notable/finding hari ini per detection dan urgensi (ES 7 pola)

```
`notable` earliest=-24h
| stats count BY rule_name urgency status_label
| sort - count
```

### 4.2 Contributing events (event risiko) untuk satu entity

```
index=risk earliest=-7d risk_object="alice"
| table _time source risk_score risk_message threat_object annotations.mitre_attack.mitre_technique_id
| sort _time
```

- Hasilnya adalah "cerita" di balik sebuah risk notable/finding group, yaitu event-event kecil yang menumpuk.
- **Cara membaca hasil:** urutan teknik (mis. Discovery, lalu Credential Access, lalu Lateral Movement) lebih meyakinkan daripada satu event bernilai tinggi.

### 4.3 Entity dengan risiko tertinggi (bahan risk notable)

```
index=risk earliest=-24h
| stats sum(risk_score) AS total_risk dc(source) AS detections dc(annotations.mitre_attack.mitre_tactic) AS tactics
        BY risk_object risk_object_type
| where total_risk >= 100 OR tactics >= 3
| sort - total_risk
```

- Ambang 100 dan 3 taktik adalah ilustrasi. Logika RBA bawaan ES punya ambang dan aturannya sendiri (Day 22).

### 4.4 Menjalankan adaptive response secara ad hoc (UI)

1. Buka finding di Mission Control (analyst queue).
2. Pilih aksi (mis. Nslookup pada domain, Ping pada host, Add Threat Intelligence untuk hash) [S3].
3. Hasil aksi tercatat dan dapat ditinjau sebagai bagian investigasi, cek lokasi hasil di ES 8.7.

### 4.5 Konfigurasi otomatis di detection editor (UI)

1. Configure > Content management, pilih detection, buka Adaptive response actions, lalu tambahkan Finding (dengan urgensi/severity, deskripsi, drilldown) dan aksi lain [S3].
2. Konfigurasi risiko (entity dan skor) untuk menghasilkan intermediate finding (Day 22), cek nama bagian di ES 8.7.

### 4.6 Satu serangan fiktif, enam istilah

Skenario fiktif berikut dipakai untuk mengikat semua istilah. Akun `rina.k` di workstation `WS-FIN-07` menerima lampiran berbahaya, menjalankan PowerShell terenkode, lalu menjalankan beberapa command discovery, dan akhirnya login ke file server `FS-01`.

Event risiko yang terbentuk dalam tiga jam (keluaran ilustrasi dari query bagian 4.2):

```
_time     source                                   risk_object  risk_score  threat_object              tactic
09:12:04  Endpoint - Office Spawning PowerShell    WS-FIN-07    40          winword.exe                Execution
09:12:04  Endpoint - Office Spawning PowerShell    rina.k       40          winword.exe                Execution
09:13:30  Endpoint - Encoded PowerShell            WS-FIN-07    25          powershell.exe -enc ...     Execution
09:20:11  Endpoint - Discovery Commands Burst      WS-FIN-07    15          whoami.exe,nltest.exe      Discovery
11:47:52  Access - First Time Logon To Server      rina.k       30          FS-01                      Lateral Movement
```

Cara membaca istilahnya dari tabel itu:

- **SPL** dipakai di setiap langkah: detection yang menulis baris-baris ini, query yang menampilkannya, dan finding-based detection yang menjumlahkannya.
- **Contributing events / intermediate finding:** kelima baris di atas. Tidak ada satu pun yang muncul di analyst queue, karena masing-masing terlalu lemah untuk ditangani sendiri.
- **Risk object / entity:** `WS-FIN-07` (tipe system, total 80) dan `rina.k` (tipe user, total 70). Satu kejadian bisa memberi skor ke dua entity sekaligus.
- **Threat object / observable:** `winword.exe`, command line PowerShell, nama tool discovery, dan `FS-01` sebagai tujuan. Observable ini yang dipakai untuk mencari host lain dengan jejak sama.
- **Risk notable / finding group:** bila finding-based detection memakai aturan "total skor minimal 75 dalam 24 jam" atau "minimal tiga taktik ATT&CK", `WS-FIN-07` memenuhi aturan skor (80 poin). Aturan tiga taktik tidak terpenuhi untuk host itu saja (hanya Execution dan Discovery), tetapi terpenuhi bila host dan user-nya dilihat bersama, karena login ke `FS-01` menambah Lateral Movement. Karena itu ES menyediakan pengelompokan finding group berdasarkan entity maupun observable yang sama [S2]. Hasilnya satu finding group di analyst queue dengan kejadian-kejadian di atas sebagai event pendukung.
- **Adaptive response action:** analyst menjalankan Nslookup ad hoc pada domain yang dihubungi PowerShell, dan detection Office Spawning PowerShell sudah otomatis menjalankan aksi Finding untuk dirinya sendiri bila dikonfigurasi dengan output finding.

Pelajaran dari skenario ini: kalau semua detection di atas diset untuk menghasilkan finding langsung, analyst akan menerima lima tiket terpisah dengan konteks parsial. Dengan alur risk, analyst menerima satu kasus yang sudah bercerita urutan kejadiannya. Itulah alasan istilah-istilah ini perlu dipahami sebagai satu rantai, bukan daftar hafalan.

## 5. Lab praktik

**Tanpa ES:**
1. Buat alert Splunk dengan dua alert action: kirim email (atau webhook ke Shuffle/TheHive) dan Log an event ke index `lab_alerts`. Ini analog "notable".
2. Buat "event risiko" buatan: saved search yang menulis `risk_object`, `risk_score`, `risk_message` ke index `lab_risk` (lewat `collect`, cek penggunaan `collect` dan hak akses). Lalu jalankan versi bagian 4.3 di `lab_risk`.

**Dengan ES:**
1. Aktifkan satu detection ESCU yang relevan dengan data lab. Pastikan ia membuat finding dan intermediate finding.
2. Picu dari VM lab, lalu temukan finding di analyst queue dan event risiko dengan bagian 4.2.
3. Jalankan satu aksi ad hoc (Nslookup/Ping).

**Hasil yang sebaiknya tersimpan:**
- Kartu definisi 6 istilah + padanan ES 8.
- Satu "notable" dan beberapa "event risiko" (ES atau analog lab).
- Satu adaptive response/alert action dijalankan.

**Variasi tantangan:** gambarkan alur bagian 3.2 dengan contoh konkret dari lab-mu: nama detection, entity, skor, dan finding group yang terbentuk.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Perbaikan |
|---|---|---|
| Detection jalan, tidak ada finding | Aksi Finding tidak dikonfigurasi | Tambahkan aksi Finding [S3] |
| Ada event risiko, tidak ada finding group | Ambang finding-based detection belum terlampaui atau detection belum aktif | Cek konfigurasi finding-based detection (Day 22) |
| Aksi ad hoc gagal | Izin/role, konektivitas, relay (untuk aksi jarak jauh) | Cek capability; dokumentasi relay adaptive response, perlu dicek |
| Field `risk_object` kosong | Konfigurasi entity di detection salah | Tetapkan field entity dan tipenya |

## 7. Kesalahan umum dan jebakan

- Menyamakan notable dengan event risiko. Event risiko (intermediate finding) tidak muncul di antrean analyst [S1].
- Menganggap risk notable = satu event berskor tinggi. Risk notable/finding group lahir dari akumulasi atau pola [S2].
- Menganggap adaptive response hanya otomatis. Ada mode ad hoc dari finding [S3].
- Mencampur istilah ES 7 dan 8 dalam satu jawaban tanpa penjelasan.
- `[komunitas]` Tidak ada sumber komunitas. Definisi dari dokumentasi ES 8.

## 8. Catatan terkini

- ES 8.x memperkenalkan istilah finding, intermediate finding, finding group, entity, dan observable (Day 06) [S1].
- Halaman findings ES 8.0 menandai sebagian fitur sebagai preview saat itu [S2], cek status di 8.7.
- Release notes ES 8.7 menyebut AI SOC Analyst yang dapat menjalankan tindakan respons yang diizinkan. Hubungannya dengan adaptive response (apakah memakai aksi yang sama dan tercatat di tempat yang sama) perlu dicek di instance.

## 9. Cheat sheet

```
SPL                -> bahasa semua detection/dashboard/investigasi
Notable event      -> FINDING (analyst queue, Mission Control)
Risk notable       -> FINDING GROUP (finding-based detection; akumulasi/pola risiko per entity)
Contributing events-> INTERMEDIATE FINDING / event pendukung (tidak di antrean)
Risk object        -> ENTITY (risk_object + risk_object_type: user/system)
Adaptive response  -> aksi otomatis (detection editor) atau ad hoc (dari finding)
   bawaan 8.7: Send email | Log an event | Stream Capture | Nbtstat | Nslookup | Create Splunk messages
               | Output to telemetry endpoint | Ping | Run a script | Send to UBA | Send to Splunk Mobile
               | Add Threat Intelligence | Finding
RISK INDEX         risk_object risk_object_type risk_score risk_message threat_object source annotations.*
ALUR               raw -> event-based detection -> finding + intermediate finding -> finding-based detection -> finding group -> investigation
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | ES 8.7: Glossary (lihat Day 06) | https://help.splunk.com/en/splunk-enterprise-security-8/release-notes-and-resources/8.7/where-to-find-help/glossary | primer | diakses 2026-10-07 | Tinggi |
| S2 | ES 8.0: Findings and finding groups in Splunk Enterprise Security | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.0/investigations/findings-and-finding-groups-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi; ditandai preview saat itu |
| S3 | ES 8.7: Configure adaptive response actions for detections | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/detections/configure-adaptive-response-actions-for-detections-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi |
| S4 | ES 8.6: Configure dispositions (lihat Day 19) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.6/investigations/configure-dispositions-for-findings-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi |
| S5 | ES 8.4: Configure adaptive response action relays | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.4/detections/configure-adaptive-response-action-relays-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Sedang-tinggi; versi 8.4 |

**Catatan sumber:** nama field fisik di risk index ES 8.7 dan nama bagian pengaturan risiko di detection editor 8.7 perlu dicek di instance. Pemetaan glosarium (risk notable ke finding, contributing events ke intermediate finding) dan batas 50 event per finding group berasal dari dokumentasi resmi [S1][S2]. Contoh di bagian 4.6 sepenuhnya fiktif.
