---
day: 37
title: 'Review data, konteks, dan ES: dari sumber log dan CIM sampai finding, RBA, detection, dan metrik'
researched_on: 2026-10-15
versions_checked: 'Merangkum Day 21-36; Splunk Enterprise 10.6; Splunk ES 8.7.0 (2 Sep 2026); CIM 6.4; SSE 3.8; MITRE ATT&CK v19.2; NIST CSF 2.0; CIS Controls v8.1'
---

# Day 37: Review data, konteks, dan ES

Cakupan: ringkasan Day 21-36 (data model dan normalisasi, konteks ancaman dan SOC, serta Enterprise Security), peta konsep yang menyambungkan ketiganya, jejak lima kasus PT JAB dari log mentah sampai angka di rapat, glosarium istilah ES 8, dan lab gabungan beserta latihan skenario.

## Ide inti

Day 21-36 membahas tiga kelompok materi secara terpisah: bagaimana data masuk dan menjadi terbaca (sumber data, data model, CIM, `tstats`, akselerasi, onboarding), konteks apa yang membuat data itu bermakna (aset dan identitas, peran SOC, framework, ATT&CK, threat intelligence), dan apa yang dilakukan Enterprise Security di atas keduanya (finding, risk, detection, investigation, metrik). Di pekerjaan nyata ketiganya adalah satu rantai. Sebuah finding hanya sebaik detection yang membuatnya, detection hanya sebaik data model yang dibacanya, data model hanya sebaik tag dan field di setiap sumber, dan angka di rapat kuartalan hanya sebaik disposisi dan jejak waktu yang ditulis analyst. Fondasi ini sudah kokoh bila kamu bisa mengambil satu kasus dan menunjuk mata rantai mana yang menentukan hasilnya, termasuk mata rantai yang putus tanpa pesan error.

Analoginya post-mortem gangguan di NOC. Setelah satu gangguan besar selesai, kamu tidak berhenti di "link sudah naik lagi", tetapi menelusuri ke belakang: apakah segmen itu punya titik monitoring, apakah parser-nya membaca counter dengan benar, kenapa alarm terlambat, siapa yang memegang tiket, dan kode penyelesaian apa yang dipakai sehingga gangguan itu muncul di laporan bulanan. Review ini melakukan hal yang sama pada kasus SOC. Batas analoginya ada di cara rantai itu putus. Di NOC, segmen tanpa monitoring biasanya ketahuan karena pelanggan menelepon. Di SIEM, rantai yang putus hampir selalu terlihat seperti keadaan tenang: panel kosong, `tstats` nol baris, antrean sepi, atau skor cakupan yang tetap terlihat wajar. Karena itu setiap kesimpulan "tidak ada aktivitas" perlu diuji ke belakang, sama seperti grafik yang rata perlu dicurigai sebagai polling yang berhenti.

```
SUMBER DATA (Day 21, 28)        log masuk, segar, terparse benar (sourcetype, TZ, line break)
   |
NORMALISASI (Day 22, 23, 24)    event type -> tag -> field CIM -> nilai yang diharapkan
   |
KECEPATAN (Day 25, 26, 27)      akselerasi + tstats ; cakupan dinilai SSE / Detection Studio
   |
KONTEKS (Day 26, 29, 30, 33)    aset dan identitas | ATT&CK + annotation | threat list
   |
OBJEK ES (Day 31, 35, 36)       detection -> finding / intermediate finding -> finding group
   |
PEKERJAAN (Day 32, 33, 34)      analyst queue -> investigation -> response plan -> disposition
   |
METRIK (Day 34)                 MTTR, dwell time, FP rate -> tuning detection dan perbaikan data
   |
   +------> kembali ke sumber data, normalisasi, dan detection
```

Situasi yang dipakai di Day ini: Enterprise Security di PT Jaringan Anak Bangsa (PT JAB, ISP menengah fiktif) sudah berjalan sebulan di search head terpisah, sementara sebagian pekerjaan L1 masih di app Search & Reporting. Sebelum review pasca-implementasi, SOC lead menulis:

> "Ambil lima kasus yang paling banyak mengajari kita bulan ini: 0258, 0231, 0263, 0276, dan 0217. Telusuri masing-masing dari log mentah sampai angka yang akan aku bawa ke rapat. Di setiap kasus, tandai mata rantai mana yang putus dan siapa pemilik perbaikannya. Aku tidak mau dengar 'datanya sudah masuk' kalau ternyata tidak ada detection yang bisa membacanya."

Pesan itu bisa dipecah menjadi enam pertanyaan yang diajukan ke setiap kasus:

1. Apakah datanya masuk, segar, dan terparse benar? (Day 21 dan Day 28)
2. Apakah data itu terbaca data model dengan nilai yang benar, dan cukup cepat dibaca? (Day 22 sampai Day 27)
3. Konteks apa yang menempel: aset dan identitas, framework dan ATT&CK, atau intel? (Day 26, Day 29, Day 30, dan Day 33)
4. Objek ES apa yang lahir dari kasus itu, dan apakah ada orang yang memang harus menanggapinya? (Day 31, Day 32, dan Day 35)
5. Apakah detection-nya dijadwalkan dan disetel supaya tidak terlambat, berisik, atau diam? (Day 35 dan Day 36)
6. Bagaimana kasus itu dibawa sampai tuntas, dan angka apa yang jujur untuk dilaporkan? (Day 33 dan Day 34)

Ringkasan per Day ada di bagian 1.1 sampai 1.16. Bagian 1.17 menelusuri kelima kasus dengan keenam pertanyaan itu, dan bagian 1.18 memuat glosarium. Lab di bagian 2-4 memintamu melakukan hal yang sama untuk detection dan data di lab-mu sendiri.

Day 38 sampai Day 40 berikutnya masuk ke hunting, yang mengandaikan rantai ini sudah lancar: hunting yang berjalan di atas data model kosong atau tanpa konteks aset hanya menghasilkan kesimpulan kosong yang terlihat meyakinkan.

**Kapan relevan:** sebelum masuk ke hunting dan otomasi respons, sebelum interview untuk posisi yang menyebut Splunk ES, dan saat menyiapkan review pasca-implementasi ES atau laporan kuartalan SOC.
**Kapan bukan jawaban:** review ini tidak menambah fakta atau fitur baru. Bila sebuah ringkasan terasa asing atau kabur, kembali ke Day asalnya; rincian query, angka, dan sumbernya ada di sana.

## 1. Ringkasan, peta konsep, dan glosarium

Ringkasan di bawah dikelompokkan menurut tiga bagian materi: data model dan normalisasi (Day 21-28), konteks ancaman dan SOC (Day 29-30), dan Enterprise Security (Day 31-36). Setiap butir adalah hal yang paling sering dipakai atau paling sering salah, bukan isi lengkap Day itu.

### 1.1 Day 21: sistem pertahanan dan sumber data

- Sistem pertahanan dikelompokkan per lapisan (perimeter, web dan email, DNS, endpoint, identitas, cloud, data, kerentanan). SIEM bernilai karena mengorelasikan jejak banyak lapisan atas kejadian yang sama.
- Sumber data dipilih dari pertanyaan analisis, bukan dari daftar produk: siapa login ke mana (Authentication), proses apa berjalan (Endpoint), host berbicara dengan siapa (Network_Traffic), domain apa di-resolve (Network_Resolution), URL apa diakses (Web).
- Panduan logging ASD ACSC, CISA, dan mitra (Agustus 2024) memprioritaskan sistem kritis, layanan yang menghadap internet, identitas, EDR, cloud, OT, dan infrastruktur jaringan, dengan format terstruktur dan timestamp UTC yang tersinkron [S18].
- Sysmon hanya mencatat yang dinyalakan di konfigurasinya; EID 3 nonaktif secara default, jadi profil event per host diperiksa sebelum detection dijanjikan.
- Sejak ATT&CK v18 (Oktober 2025), Data Sources diganti Detection Strategies dan Analytics per teknik.
- Sumber yang diam adalah temuan visibilitas, dan diperlakukan sebagai temuan keamanan, karena salah satu penyebabnya agent yang dimatikan penyerang.

### 1.2 Day 22: membuat data model dan memakai Pivot

- Data model adalah skema untuk orang lain: knowledge manager menuangkan pemahaman tentang data sekali, lalu pengguna Pivot bertanya sendiri tanpa SPL. Di PT JAB contohnya model `jab_billing_portal` untuk portal pelanggan dan billing (SOC-2026-0251).
- Empat jenis dataset: root event, root search, root transaction, dan child. Root transaction beserta turunannya tidak bisa di-accelerate, root search hanya bila seluruhnya streaming, dan model private tidak bisa di-accelerate [S17].
- Lima jenis attribute: auto-extracted (hanya di root), eval expression, regular expression, lookup, dan geo IP. Urutan diproses dari atas ke bawah, Extracted sebelum Calculated.
- Flag Required menyaring event yang tidak punya field itu, jadi ia mengubah isi, bukan tampilan. Hidden dipakai untuk field perantara.
- Pivot editor punya empat kategori elemen (Filters, Split Rows, Split Columns, Column Values), filter match hanya mendukung AND, dan Group Others bisa menyapu kategori ke kolom OTHER.
- `| datamodel <model> <dataset> search` secara default hanya mengembalikan field default dan field di constraint; field lookup dan calculated baru muncul dengan `strict_fields=false`.

### 1.3 Day 23: CIM, CIM Add-on, dan praktik terbaik SIEM

- CIM adalah skema saat search. Add-on `Splunk_SA_CIM` membawa kamusnya (data model, dokumentasi, alat validasi, model aksi), bukan datanya; yang menormalisasi adalah TA vendor atau konfigurasimu sendiri. Navigasi referensi CIM 6.4 memuat 26 entri, dua di antaranya deprecated.
- Sebuah event terhitung di data model bila empat mata rantai terpenuhi: event type cocok, event type diberi tag sesuai constraint, field bernama sesuai CIM, dan nilai field sesuai yang diharapkan. Tag yang hilang membuat event tidak ada di model; nilai yang salah membuat event ada di model tetapi tidak ditemukan filter detection.
- Model dipilih dari tujuan event, bukan dari nama field yang tersedia.
- Akselerasi data model CIM nonaktif secara default, Indexes allowlist adalah kunci performa, dan bila ES terpasang pengaturan akselerasi dipaksakan oleh ES lewat Data Model Acceleration Enforcement [S15].
- SOC-2026-0258: log RADIUS pelanggan (`jab:radius:auth`, 38.602 event dalam sehari) tidak masuk Authentication sama sekali. Mini TA berisi event type `jab_radius_auth`, tag `authentication`, field alias, dan `EVAL-action` membuat alert brute force yang sudah ada ikut menghitung akun pelanggan tanpa satu baris pun diubah.

### 1.4 Day 24: field CIM untuk investigasi

- Field poros pivot: `src`, `dest`, `user`, `action`, `app`, `dvc`, `vendor_product`. Nilai `action` berbeda per model, misalnya `success`, `failure`, `pending`, `error` di Authentication dan `allowed`, `blocked`, `teardown` di Network Traffic.
- Arti `src` dan `dest` bergeser: di Endpoint, `dest` adalah host tempat proses berjalan; di Authentication, `src` asal login dan `dest` sistem yang dimasuki.
- Nama dataset root berbeda dari nama model (`All_Traffic`, `Processes`, `DNS`, `IDS_Attacks`), dan salah menyebutnya menghasilkan nol baris tanpa error.
- Field enrichment berakhiran `_priority`, `_category`, `_bunit` diisi korelasi aset dan identitas saat search, bukan oleh add-on.
- Pivot gagal paling sering karena format nilai: `JAB\andi.pratama` dibanding `andi.pratama@jab.example`, IP dibanding hostname, atau `user` yang multivalue karena event Windows klasik memuat akun Subject dan target (Day 03 bagian 1.5).

### 1.5 Day 25: tstats

- `tstats` membaca file tsidx, bukan raw event. Tanpa data model ia hanya melihat field indexed (`index`, `sourcetype`, `source`, `host`, `_time`); dengan data model yang di-accelerate, field CIM ikut tertulis di summary.
- `summariesonly` default `false`, sedangkan konten ES dan Security Content menyetelnya `true` lewat macro `security_content_summariesonly`, sehingga SPL yang sama bisa berarti cakupan berbeda di instance berbeda [S16].
- `fillnull_value` tidak punya default, jadi baris dengan null di field BY dibuang diam-diam. `count(eval(...))` tidak didukung. `prestats=true` dipakai sebelum `timechart`.
- Hasil kosong dari `tstats` bukan bukti tidak ada aktivitas; konfirmasi dengan `summariesonly=false` atau search raw yang sempit.

### 1.6 Day 26: acceleration dan Asset & Identity

- Akselerasi adalah sistem yang berjalan terus: summarization setiap lima menit, satu jalannya dibatasi sekitar satu jam, tiga search summarization bersamaan secara default, dan summary range kosong berarti All Time. Status "100 persen" dihitung terhadap rentang yang diminta, bukan seluruh isi index [S17].
- Asset & Identity mengambil data dari Exposure Analytics entity discovery, CSV, LDAP/AD, dan penyedia cloud, lalu identity manager menggabungkannya menjadi `asset_lookup_by_str`, `asset_lookup_by_cidr`, dan `identity_lookup_expanded`.
- Korelasi mencocokkan `src`, `dest`, `dvc` ke aset dan `user`, `src_user` ke identitas, dan tidak lagi otomatis terhadap `host` atau `orig_host` [S9]. Syslog POP di index `netops` yang hanya membawa `host` tidak akan diperkaya seberapa pun lengkap daftar asetnya.
- Konteks itu dipakai untuk urgency finding, risk factor di RBA, konteks investigasi, dan sinyal sendiri seperti login oleh identitas yang `endDate`-nya sudah lewat.
- Ukuran cakupan dilaporkan sebagai dua angka berpasangan. Pada ilustrasi PT JAB, 612 dari 759 host di data autentikasi (sekitar 81 persen) tidak dikenal daftar aset dan menyumbang sekitar 25 persen event.
- Korelasi yang baru dinyalakan tidak mengisi summary yang dibangun sebelumnya.

### 1.7 Day 27: SSE dan ES menilai sumber data

- Sebuah content baru bekerja bila tiga hal terpenuhi bersamaan: jenis event yang tepat ada di data, field-nya ternormalisasi ke CIM, dan ada content yang memakainya.
- SSE Data Inventory mendaftarkan product beserta sourcetype, volume, dan CIM compliance lewat Automated Introspection di search head yang bisa melihat data produksi [S19]. Data source category menjadi bahasa penghubung antara event dan content.
- Analytics Advisor mewarnai matriks ATT&CK sebagai Total, Active, Available, atau Needs data. Available berarti kategori event terlihat ada, belum berarti field dan macro-nya benar.
- Detection Studio di ES 8.7 menampilkan cakupan teknik ATT&CK untuk detection aktif sekaligus kesehatannya lewat KPI Performance, Compatibility, Impact, dan Confidence [S3].
- Sourcetype adalah label add-on yang bisa berganti (`ms:o365:management` menjadi `o365:management:activity`), jadi detection sebaiknya ditulis di atas data model CIM.

### 1.8 Day 28: onboarding data dan konfigurasi index-time

- Pipeline: input, parsing, indexing, search. Universal forwarder tidak melakukan parsing untuk data umum, kecuali `INDEXED_EXTRACTIONS` untuk CSV, TSV, dan JSON.
- Delapan setting berurutan: `sourcetype`, `LINE_BREAKER`, `SHOULD_LINEMERGE=false`, `TIME_PREFIX`, `TIME_FORMAT`, `MAX_TIMESTAMP_LOOKAHEAD`, `TZ`, dan `TRUNCATE` (default 10.000 byte).
- Kesalahan index-time permanen untuk data yang sudah masuk, jadi apa pun yang bisa dikerjakan saat search sebaiknya dikerjakan saat search, dan setiap perubahan diuji dengan oneshot ke index uji.
- `SEDCMD` bukan kontrol akses, dan membuang event ke `nullQueue` adalah keputusan keamanan karena event itu tidak bisa menjadi bukti.
- Ingest lag adalah `_indextime` dikurangi `_time`. Lag menentukan jeda jendela detection di Day 36, dan `TZ` yang salah pada syslog router dan switch POP menggeser timeline investigasi beberapa jam.

### 1.9 Day 29: SOC, peran, framework, dan risiko

- SOC terdiri dari people, process (dimulai dari threat modeling), dan technology. Tier memisahkan kedalaman dan wewenang; analyst mengurus kejadian, engineer mengurus sistem dan konten, architect mengurus desain.
- SOC-2026-0231: password spraying berakhir dengan login berhasil ke `svc_backup` di `JKT-FS01`, dan findingnya muncul 25 menit setelah aktivitas dimulai karena detection brute force di-skip 46 kali dalam 24 jam akibat batas konkurensi. Analyst menutup kejadian, engineer memperbaiki jadwal dan filter, architect memperbaiki kapasitas.
- Kontrol adalah mekanisme, standar adalah persyaratan yang bisa diaudit, framework adalah struktur. NIST CSF 2.0 punya enam fungsi termasuk Govern [S6], CIS Controls v8.1 tetap 18 kontrol [S4], dan kontrol ISO/IEC 27001:2022 yang paling dekat dengan SOC adalah 8.15 Logging dan 8.16 Monitoring activities.
- Annotation ES 8.7 membawa label ATT&CK, CIS, NIST CSF, Kill Chain, dan PCI DSS 4.0 dari detection sampai finding dan `index=risk`, dengan pola field `annotations.<framework>.<field>`.
- CIA mengikuti FIPS 199 dengan dampak low, moderate, atau high. Risiko dalam arti manajemen adalah fungsi likelihood dan impact dengan treatment mitigate, transfer, avoid, atau accept, dan itu bukan risk score RBA.

### 1.10 Day 30: serangan, ATT&CK, TTP, dan tingkatan threat intelligence

- Attack vector adalah jalan masuk, attack type adalah jenis atau tujuan serangan, dan satu insiden biasanya punya satu vector awal dengan beberapa tahap.
- TTP: tactic adalah tujuan, technique adalah cara, procedure adalah implementasi spesifik. T1053.005 Scheduled Task melayani tiga taktik (Execution, Persistence, Privilege Escalation).
- ATT&CK v19 punya 15 taktik karena Defense Evasion dipecah menjadi Stealth (TA0005) dan Defense Impairment (TA0112) [S2]. Selalu sebut versi saat menulis pemetaan.
- Pyramid of Pain mengurutkan hash, IP, domain, artifact, tools, sampai TTP menurut biaya penggantian bagi penyerang.
- Detection biasanya menangkap satu procedure, bukan seluruh teknik, jadi cakupan dilaporkan per procedure dan teknik prioritas ditopang minimal dua procedure atau dua sumber data, misalnya `schtasks.exe` lewat Sysmon EID 1 dan event 4698 yang butuh audit policy.
- Model empat tingkatan intel (strategic, operational, tactical, technical) dipakai untuk memilah satu laporan ke konsumennya. Laporan di SOC-2026-0263 dipilah menjadi tren untuk direksi, perilaku untuk detection, dan 40 IP, 12 domain, serta 6 hash untuk daftar indikator bermasa berlaku.

### 1.11 Day 31: istilah dan objek ES

- Alur objek ES 8: event-based detection menghasilkan finding atau intermediate finding; intermediate finding menumpuk sebagai skor pada entity di risk index; finding-based detection mengubah akumulasi itu menjadi finding group; pekerjaan manusia dicatat sebagai investigation dengan disposition.
- Pemetaan lengkap istilah ES 7 ke ES 8, termasuk catatan pemetaan yang tidak satu ke satu, ada di Day 31 bagian 1.2 dan tidak disalin ulang di sini. Satu yang paling sering salah: glosarium ES 8.7 memetakan risk notable ke finding, sedangkan di layar objeknya tampil sebagai finding group [S5].
- Intermediate finding tidak pernah tampil di analyst queue, jadi "banyak risk event tapi tidak ada notable" di tiket SOC-2026-0231 bukan bukti aman.
- Satu finding group menampung maksimal 50 event yang berkontribusi, terpisah dari batas 100 finding per investigation [S8].
- Entity adalah user atau sistem internal yang diberi skor; observable adalah artefak penyerta seperti hash, domain, IP eksternal, dan command line. Risk score milik entity sepanjang waktu, urgency milik satu finding.
- ES 8.7 punya 13 adaptive response action bawaan, misalnya Nslookup, Ping, Add Threat Intelligence, dan Finding, yang bisa dipicu otomatis dari detection editor atau ad hoc dari finding.
- SOC-2026-0274 merangkai semuanya: lima intermediate finding untuk `JKT-WS-0744` (total 80) dan `rina.wulandari` (total 70) menjadi satu finding group, bukan lima tiket.

### 1.12 Day 32: dashboard bawaan ES

- Setiap dashboard punya satu audiens: Security posture untuk triage 24 jam, Executive summary untuk manajemen, SOC operations untuk alur kerja dan disposisi, Risk analysis untuk entity berisiko, dashboard domain untuk analyst, dan Audit untuk engineer. Antrean kerja ada di Mission Control, bukan di Analytics.
- Urgency menggabungkan severity detection dan prioritas aset, sehingga daftar aset yang kosong membuat urgency menumpuk di satu nilai.
- Setiap sub-dashboard domain membaca data model tertentu. Panel kosong diuji dengan `tstats summariesonly=false`, lalu `summariesonly=true`; nol di keduanya berarti masalah onboarding atau tag CIM.
- Panel disposisi di SOC operations memisahkan pekerjaan: detection yang dominan di "incorrect logic" untuk detection engineer, yang dominan di "inaccurate data" untuk data engineer. Close rate per analyst bukan ukuran kualitas.

### 1.13 Day 33: Mission Control, investigation, threat intelligence, dan annotations

- Finding adalah pemicu, investigation adalah pekerjaan. Satu insiden satu investigation; tiga investigation untuk satu insiden memecah metrik dan pekerjaan.
- Alur: assign, investigation, note hipotesis, response plan, action atau playbook, intel, note penilaian, disposition, tutup. Note yang berguna memuat hipotesis, bukti beserta query dan rentangnya, penilaian dengan keyakinan, keterbatasan, dan tindakan beserta pemiliknya.
- Response plan tersusun dari phase dan task, baru bisa dipasang setelah Published, hanya bisa diimpor dari JSON, dan search di dalam task berjalan untuk 24 jam terakhir secara default.
- Threat intelligence di ES 8 punya dua jalur: native (koleksi KV store dan threat match) dan Threat Intelligence Management (Cloud). Tab Intelligence di investigation hanya menampilkan data TIM, jadi indikator native dibuktikan dengan `| inputlookup` ke koleksinya [S14].
- Setiap indikator butuh masa berlaku dan confidence, karena IP di hosting murah cepat berganti penyewa.
- Annotation adalah label konteks, bukan logika. Detection `JAB - ` tanpa annotation tetap berjalan tetapi hilang dari laporan cakupan dan analisis risiko per taktik.
- SOC-2026-0276: threat match domain `update-cdn.example` di `JKT-WS-0417` (finding group FG-0276) dari indikator berumur sembilan bulan, dengan dugaan benign positive yang menuntut baris allowlist berkedaluwarsa dan penurunan confidence indikator.

### 1.14 Day 34: investigasi lima tahap dan metrik

- Continuous monitoring adalah proses koleksi, analisis, pelaporan, respons, dan peninjauan, bukan sebuah layar yang menyala terus.
- Lima tahap alur kerja insiden menurut Lantern: Review events, Assessment, Determine risk, Mitigate, Re-assess, masing-masing dengan hasil yang wajib tertinggal di tiket [S11]. Triage dan disposisi (tahap 1-2) dibahas utuh di Day 07, termasuk tujuh disposition bawaan ES 8.7 di Day 07 bagian 1.5; Day 34 memakai disposisi sebagai kolom data metrik.
- Pada SOC-2026-0217, Determine risk menghasilkan tiga hal, yaitu `rina.wulandari` di VPN, `adm.rina` di `JKT-JUMP01`, dan `JKT-FS01`, sehingga mereset satu password hanya menyelesaikan satu dari tiga.
- ES 8 menyediakan delapan template response plan, termasuk Account Compromise dan NIST 800-61. NIST SP 800-61r3 (April 2025) memetakan respons insiden ke enam fungsi CSF 2.0.
- Metrik dari blog SOC Metrics Splunk: MTTD, MTTA&A, MTTI, MTTR, MTRS, FP rate, FN rate [S12]. Dwell time dihitung per insiden dari T0 (kompromi) sampai T1 (deteksi), dan T0 baru diketahui lewat investigasi.
- Laporkan median dan p90, pasangkan kecepatan dengan kualitas, dan tulis definisi setiap metrik. Pada ilustrasi tiga kasus, rata-rata dwell time 128,47 jam dan median 0,4 jam berasal dari data yang sama, karena SOC-2026-0263 sendiri mencapai 384,9 jam.

### 1.15 Day 35: risk framework dan RBA

- Detection lemah tidak membuat alert, melainkan menulis intermediate finding berisi entity, tipe entity, skor, pesan, threat object, dan annotation ke risk index. Alert berupa finding group baru lahir dari finding-based detection, misalnya skor melewati ambang dalam 24 jam atau beberapa taktik ATT&CK terwakili [S10].
- Pola lapisan kedua: ambang skor (rentan score stacking), keragaman taktik (bergantung annotation), keragaman sumber, kombinasi, dan jendela panjang untuk pola low-and-slow.
- SOC-2026-0263: empat alert kecil untuk `JKT-WS-0523` dan `rina.wulandari` ditutup terpisah oleh tiga analyst di tiga shift. Di risk index, skor naif `rina.wulandari` 280, dan setelah deduplikasi per entity, source, dan threat object menjadi 105.
- Risk factor hanya berlaku untuk entity yang ada di daftar aset dan identitas, jadi daftar yang setengah jalan membuat antrean memihak bagian estate yang datanya rapi.
- Risk badge di analyst queue: 0-25, 25-50, 50-75, dan 75 ke atas.
- Skor adalah hipotesis dari bobot buatan sendiri, bukan bukti, dan bukan risiko organisasi.

### 1.16 Day 36: membuat dan menyetel detection

- Detection dibuat lewat Security content > Content management > + Content > Detection > Event-based detection, dengan output finding, intermediate finding, atau keduanya.
- Real-time schedule bisa di-skip dan jendela yang terlewat tidak dipindai ulang; continuous schedule tidak pernah di-skip. Jadwal di-stagger, jendela dibuat berjeda dan dibulatkan seperti `earliest=-20m@m latest=-5m@m`, dan Index Time dipertimbangkan untuk data yang sering terlambat [S13].
- Pilihan output mengikuti fidelitas: tinggi menjadi finding, sedang atau rendah menjadi intermediate finding saja, dan yang hanya untuk hunting cukup saved search biasa.
- Throttling menahan duplikat, tuning logika mengubah apa yang dianggap mencurigakan (untuk ESCU lewat filter macro `_filter`), dan mengubah output memindahkan detection berisik ke RBA.
- Ambang dikalibrasi dari p95 dan p99 data 30 hari, logika diuji dengan `makeresults`, dan setiap detection punya kartu ringkas berdasarkan Alerting and Detection Strategy (Palantir, 2017).
- Search manual yang menemukan SOC-2026-0217 diubah menjadi detection yang berjalan sendiri setiap 15 menit. Contoh lengkapnya, `Lab - Auth - Brute Force Followed By Success`, memakai continuous schedule, throttling satu jam per `src` dan `user`, serta output finding dan intermediate finding.

### 1.17 Peta konsep dan jejak lima kasus PT JAB

Peta berikut menggabungkan diagram Day 21-36 dalam satu gambar. Pakai sebagai satu-satunya bantuan saat uji lisan di Lab D bagian 2-4.

```
 PERTANYAAN ANALISIS (Day 21)
        |
 SUMBER DATA -> onboarding (Day 28: sourcetype, TZ, LINE_BREAKER, TRUNCATE, lag)
        |                                   freshness: sumber diam = temuan
        v
 CIM (Day 23): event type -> tag -> field -> nilai     data model sendiri bila tak ada padanan (Day 22)
        |                       field poros src/dest/user/action (Day 24)
        v
 AKSELERASI (Day 26) -> tstats summariesonly (Day 25)  cakupan: SSE + Detection Studio (Day 27)
        |
        +--- A&I (Day 26): src/dest/dvc, user/src_user -> _priority _category _bunit -> urgency, risk factor
        +--- FRAMEWORK (Day 29) + ATT&CK v19 / TTP / intel tiers (Day 30) -> annotation, threat list (Day 33)
        v
 DETECTION (Day 36): jadwal, jendela berjeda, throttling, output
        |                         \
        v                          v
 FINDING                  INTERMEDIATE FINDING (risk index: entity, score, observable, annotation)
        |                          |
        |                  FINDING-BASED DETECTION (Day 35): ambang, keragaman, dedup
        |                          v
        +-------------> ANALYST QUEUE (Mission Control) <---- FINDING GROUP
                               |
             INVESTIGATION (Day 33): note, response plan, intel, adaptive response
                               |
             LIMA TAHAP (Day 34): Review -> Assessment -> Determine risk -> Mitigate -> Re-assess
                               |
             DISPOSITION + T0..T4 -> METRIK (MTTR median/p90, dwell time, FP rate) + DASHBOARD (Day 32)
                               |
             kembali ke: tuning detection (Day 36), skor RBA (Day 35), normalisasi (Day 23), onboarding (Day 28)
```

Tabel berikut menjawab permintaan SOC lead di bagian Ide inti dengan artefak fiktif PT JAB dari Day 23 sampai Day 36. Baca per baris; kolom terakhir adalah mata rantai yang putus beserta pemilik perbaikannya, dan setiap sel menunjuk artefak yang sudah kamu lihat di Day asalnya.

| Kasus | Data dan normalisasi | Konteks | Objek ES dan detection | Investigasi dan metrik | Mata rantai yang putus |
|---|---|---|---|---|---|
| SOC-2026-0258, credential stuffing RADIUS (Day 23) | 38.602 event `jab:radius:auth` per hari, 0 di Authentication | Akun pelanggan seperti `pelanggan.0192`, sebagian dengan realm `@jab.example` | Alert brute force yang sudah ada tidak melihat sumber ini | Percobaan ke akun pelanggan lolos tanpa finding | Normalisasi. Mini TA (event type, tag, alias, `EVAL-action`) oleh engineer; detection tidak diubah |
| SOC-2026-0231, spraying lalu `svc_backup` di `JKT-FS01` (Day 29, 31, 34) | Data autentikasi lengkap | T1110 dan kontrol logging dan monitoring yang ditanyakan auditor | Detection brute force skipped 46 kali karena batas konkurensi; banyak risk event tanpa notable | Finding telat 25 menit; dwell time 0,4 jam; tiket sempat ditutup "aman" | Jadwal dan kapasitas (engineer dan architect), lalu pemahaman intermediate finding di sisi analyst |
| SOC-2026-0263, scheduled task `\EdgeUpdateCheck` di `JKT-WS-0523` (Day 30, 34, 35) | Sysmon baru di sekitar 40 persen workstation; 4698 lebih merata asal audit policy aktif | T1053.005; laporan forum dengan 40 IP, 12 domain, 6 hash | Empat alert kecil ditutup terpisah; di RBA skor `rina.wulandari` 280 naif, 105 setelah dedup | T0 ditemukan lewat hunting; dwell time 384,9 jam, TTR 30,6 jam | Cara alert lemah dikelola. Detection lemah dipindah ke risk rule dengan annotation, ditambah finding-based detection |
| SOC-2026-0276, threat match `update-cdn.example` di `JKT-WS-0417` (Day 33) | 36 request proxy dari satu host dalam tujuh hari | Indikator forum `forum_isp_2026_10` berumur sembilan bulan tanpa tanggal terakhir terlihat | Finding group FG-0276; detection `JAB - ` tanpa annotation hilang dari laporan cakupan | Tiga investigation untuk satu insiden, satu note "sudah dicek, aman"; dugaan benign positive | Disiplin investigasi dan kualitas intel. Satu investigation, note lengkap, `expires` dan confidence, annotation |
| SOC-2026-0217, brute force VPN (Day 07, 34, 36) | 180 percobaan ke 25 akun lewat `jkt-vpn01`, satu sukses `rina.wulandari` | `dest_priority` gateway VPN bernilai `unknown` karena belum terdaftar di A&I | Ditemukan lewat search manual, lalu dibangun menjadi detection 15 menit dengan jendela berjeda | Determine risk menemukan `adm.rina` di `JKT-JUMP01` dan `JKT-FS01`; dwell time 0,1 jam, TTR 9,3 jam | Konteks aset (gateway belum terdaftar) dan scoping yang tidak boleh berhenti di satu akun |

Kelima kasus menyentuh mata rantai yang berbeda, dan tidak satu pun gagal karena SPL yang salah tulis. Itu pola yang perlu diingat: di lingkungan ES, kegagalan paling mahal terjadi di normalisasi, jadwal, konteks, dan disiplin penutupan kasus, dan semuanya terlihat normal di layar sampai ada insiden yang ditelusuri ke belakang.

**Tanpa ES:** sebagian besar rantai di atas tetap ada di Splunk Enterprise biasa. Add-on CIM gratis dan bisa dipakai tanpa ES lengkap dengan data model dan akselerasinya, `tstats` dan akselerasi adalah fitur platform, SSE adalah app gratis, dan detection berbentuk saved search atau alert dengan jadwal, throttle, dan alert action. Yang hanya ada di ES: korelasi Asset & Identity beserta field seperti `src_priority`, enforcement akselerasi CIM, Detection Studio, annotation terkelola, finding dan intermediate finding, RBA dengan risk factor, analyst queue, investigation dengan response plan, dan dashboard ES. Di PT JAB keduanya hidup berdampingan, sehingga kasus seperti SOC-2026-0217 bisa muncul sebagai finding di satu search head dan sebagai tiket dari alert terjadwal di search head lain; kosakata disposisinya harus sama supaya metrik dua jalur bisa digabung.

### 1.18 Glosarium

Definisi di bawah ditulis dengan kata sendiri untuk keperluan belajar. Istilah ES ditulis dengan nama ES 8; nama ES 7 dicantumkan di kolom terakhir sebagai jembatan, dan pemetaan lengkapnya ada di Day 31 bagian 1.2. Kolom "Sering tertukar dengan" adalah pasangan yang paling sering membuat jawaban interview keliru.

| Istilah | Penjelasan singkat | Sering tertukar dengan | Day dan nama ES 7 |
|---|---|---|---|
| Data model | Skema berjenjang atas data, dipakai Pivot, `tstats`, dashboard, dan detection | Salinan data atau alat mempercepat search | Day 22, 23 |
| Root transaction dataset | Dataset yang mengelompokkan event berurutan; tidak bisa di-accelerate | Root search dataset | Day 22 |
| Constraint | Bagian filter yang menentukan event mana yang masuk dataset; di CIM umumnya tag | Filter di Pivot | Day 22, 23 |
| CIM | Kamus field, tag, dan nilai bersama yang bekerja saat search | Add-on yang menormalisasi data | Day 23 |
| Technology Add-on (TA) | Add-on vendor yang memetakan sebuah sumber ke nama dan nilai CIM | Add-on CIM | Day 23 |
| Data model acceleration | Summary tsidx yang dibangun terjadwal di indexer untuk field data model | Ad hoc acceleration di Pivot | Day 25, 26 |
| `summariesonly` | Argumen `tstats`: `true` hanya membaca summary, default `false` | Bukti lengkap atau tidaknya data | Day 25 |
| Summary range | Rentang ke belakang yang dicakup summary; kosong berarti All Time | Retensi index | Day 26 |
| Asset & Identity (A&I) | Daftar aset dan identitas yang dikorelasikan ke event saat search | CMDB itu sendiri | Day 26 |
| Field berprefiks (`dest_priority`, `user_bunit`) | Hasil korelasi A&I, dinamai menurut field asal yang cocok | Field yang diisi add-on | Day 24, 26 |
| Data source category | Jenis event spesifik yang dibutuhkan sebuah content di SSE | Sourcetype | Day 27 |
| Detection Studio | Halaman ES 8 untuk cakupan ATT&CK dan kesehatan detection aktif | Matriks ATT&CK di SSE | Day 27 |
| Index-time dan search-time | Keputusan saat data disimpan (permanen) dan saat data dibaca (bisa diubah) | Dua cara yang sama-sama bisa diperbaiki | Day 28 |
| Ingest lag | Selisih `_indextime` dan `_time` per event | Kesalahan zona waktu | Day 28, 36 |
| Analyst, engineer, architect | Peran yang mengurus kejadian, sistem dan konten, serta desain | Tingkat senioritas | Day 29 |
| Kontrol, standar, framework | Mekanisme, persyaratan yang bisa diaudit, dan struktur organisasi praktik | Tiga nama untuk hal yang sama | Day 29 |
| Risiko (manajemen) | Fungsi likelihood dan impact atas sebuah skenario, dinilai terhadap risk appetite | Risk score RBA | Day 29, 35 |
| TTP | Perilaku aktor: tactic (tujuan), technique (cara), procedure (implementasi) | Daftar IOC | Day 30 |
| Pyramid of Pain | Urutan indikator menurut biaya penggantian bagi penyerang | Urutan keyakinan atau prioritas investigasi | Day 30 |
| Tingkatan intel | Strategic, operational, tactical, technical menurut konsumen dan horizon | Model tiga tipe vendor yang arti labelnya berbeda | Day 30 |
| Detection (event-based) | Search terjadwal atas event yang menghasilkan finding, intermediate finding, atau keduanya | Alert Splunk biasa | Day 31, 36; ES 7: correlation search |
| Finding-based detection | Detection yang membaca finding dan intermediate finding lalu membuat finding group | Event-based detection | Day 31, 35; ES 7: risk incident rule |
| Finding | Hasil detection yang masuk analyst queue dan menuntut keputusan manusia | Intermediate finding | Day 31, 33; ES 7: notable event |
| Intermediate finding | Event risiko di risk index, bahan akumulasi, tidak tampil di antrean | Finding kecil di antrean | Day 31, 35; ES 7: risk event, contributing events |
| Finding group | Kumpulan finding dan intermediate finding per entity atau observable, hasil finding-based detection | Investigation | Day 31, 35; ES 7: risk notable (glosarium 8.7: finding) |
| Entity | User atau sistem internal yang diberi risk score | Observable | Day 31, 35; ES 7: risk object |
| Observable | Artefak penyerta: hash, domain, IP eksternal, command line | Entity | Day 31, 33; ES 7: threat object |
| Analyst queue | Daftar finding dan finding group di Mission Control | Dashboard Security posture | Day 31, 32; ES 7: Incident Review |
| Investigation | Wadah kerja satu kasus: note, response plan, disposition | Finding group | Day 31, 33 |
| Response plan | Template phase dan task untuk satu jenis kasus | Prosedur kebijakan yang tidak bisa diverifikasi | Day 33, 34 |
| Disposition | Kesimpulan akhir atas finding, sumber data metrik kualitas | Status | Day 07, 33, 34 |
| Urgency | Prioritas satu finding dari severity detection dan prioritas aset | Severity atau risk score | Day 26, 32 |
| Risk score | Akumulasi kontribusi risiko per entity sepanjang waktu | Risiko organisasi | Day 31, 35 |
| Risk factor | Pengali skor menurut atribut entity dari A&I | Ambang finding-based detection | Day 35 |
| Annotation | Label framework pada detection yang terbawa ke finding dan risk index | Logika deteksi | Day 29, 33 |
| Threat list | Daftar indikator yang dicocokkan dengan data | Generic intelligence | Day 33; ES 7: intelligence workflow |
| Throttling | Penahan finding duplikat per kombinasi field dalam jendela waktu | Tuning logika | Day 36 |
| Dwell time | Jarak kompromi awal sampai penyerang ditemukan, dihitung per insiden | MTTD | Day 34 |
| MTTR | Rata-rata waktu dari deteksi sampai kasus selesai, menurut definisi yang dipakai di catatan ini | Mean time to respond, repair, atau recover | Day 34 |

Parafrase di tabel ini cukup untuk interview dan pekerjaan harian. Definisi resmi istilah ES ada di glosarium ES 8.7 [S5].

## 2-4. Lab gabungan dan troubleshooting

Lab ini merapikan latihan Day 21-36 menjadi satu jejak yang bisa diuji dari ujung ke ujung, lalu menguji pemahamanmu dengan latihan skenario. Semua langkah dijalankan di VM lab terisolasi dengan snapshot; aktivitas serangan yang dipakai adalah rangkaian jinak dengan akun uji. Bila latihan Day sebelumnya belum lengkap, kerjakan dulu bagian yang kosong.

### Lab A: matriks keterlacakan untuk detection milikmu

Pilih tiga detection di lab-mu (atau tiga alert terjadwal bila tanpa ES). Untuk setiap detection, isi satu baris:

```
Detection | Sumber dan sourcetype | Lag p95 | Data model dan dataset | Event type dan tag | Nilai field yang difilter
| Akselerasi dan summary range | Konteks A&I yang dipakai | Annotation ATT&CK (versi) | Output (finding/risk) | Jadwal dan jendela
| Throttling | Disposition 30 hari | Pemilik
```

Lalu pilih satu kasus yang pernah kamu picu di lab dan telusuri dengan enam pertanyaan di Ide inti, dengan format yang sama seperti tabel lima kasus di bagian 1.17.

Setiap kolom seharusnya terisi. Kolom yang kosong menunjukkan mata rantai yang putus, dan itu temuanmu sendiri: tulis apa yang kosong, akibatnya pada detection atau investigasi, dan siapa pemilik perbaikannya.

### Lab B: akun lab dikompromikan, lalu bergerak ke server

Skenario lab: satu akun uji dikompromikan lewat brute force, lalu dipakai untuk discovery, persistence, dan login ke VM "server".

1. **Data (Day 23, 24, 26, dan 27):** pastikan Authentication dan Endpoint.Processes terisi untuk VM Windows, dan catat celahnya di Data Inventory SSE.
2. **Konteks aset dan identitas (Day 26):** daftarkan VM sebagai aset (workstation `medium`, "server" lab `high`) dan akun uji sebagai identitas.
3. **Ancaman (Day 30):** rencanakan rangkaian jinak yang mewakili taktik ATT&CK v19:
   - Credential Access: brute force lalu sukses;
   - Discovery: `whoami`, `net user`;
   - Persistence: scheduled task;
   - Lateral Movement: login RDP atau SMB ke VM "server" dengan akun uji.
4. **Detection (Day 35 dan 36):**
   - detection brute force dengan output finding dan intermediate finding;
   - dua detection lain (discovery dan schtasks) dengan output intermediate finding saja;
   - beri annotation ATT&CK pada ketiganya (Day 30).
5. **RBA (Day 35):** pastikan finding group muncul untuk akun uji, atau jalankan versi lab tanpa ES di Day 35 bagian 2.5.
6. **Investigasi (Day 33 dan 34):** jalani lima tahap dan terapkan response plan Account Compromise (ES) atau checklist di TheHive.
7. **Respons (Day 41 dan 42):** jalankan satu adaptive response ad hoc (Nslookup atau Ping) dan satu playbook (Shuffle atau SOAR) dengan approval.
8. **Disposition dan metrik (Day 34):** tutup dengan disposition yang tepat, catat T0, T1, dan T4, lalu hitung dwell time dan TTR.
9. **Dashboard (Day 32):** temukan kasus ini di Security posture dan Risk analysis, atau di dashboard lab.

Tabel berikut adalah bukti yang seharusnya terlihat bila lab berjalan baik; isi kolom kanannya dengan angka dari lab-mu.

| Langkah | Bukti yang harus terlihat |
|---|---|
| 1 Data | `tstats count` dari Authentication dan Endpoint.Processes untuk host lab tidak nol |
| 2 Aset dan identitas | Finding dari VM "server" berurgency lebih tinggi daripada finding serupa dari workstation |
| 4 Detection | Satu finding brute force di antrean; event risiko dari discovery dan schtasks di risk index, tanpa finding sendiri |
| 5 RBA | Satu finding group untuk akun uji atau host lab, berisi minimal tiga event pendukung dari dua taktik |
| 6 Investigasi | Satu investigation dengan note per tahap dan response plan yang task-nya terisi |
| 8 Metrik | T0 (aksi pertama di lab), T1 (finding pertama), dan T4 (penutupan) tercatat, dengan disposition True Positive - Suspicious Activity, atau Testing bila itu kebijakan lab-mu |

**Troubleshooting langkah 5:** bila finding group tidak muncul, periksa berurutan apakah data model terisi, apakah field entity terisi, apakah annotation taktik ada, dan apakah ambangnya terlalu tinggi (Day 35 bagian 4).

### Lab C: latihan skenario dengan pembahasan

Coba jawab setiap skenario sebelum membaca pembahasannya. Semua skenario fiktif.

**Skenario 1: panel urgency yang tidak informatif.** Security posture menunjukkan hampir semua finding berurgency medium, termasuk finding malware di server database utama. Apa penyebab paling mungkin, dan di mana memperbaikinya?

Pembahasan: urgency dihitung dari severity detection dan prioritas aset (Day 26 dan Day 32). Bila semua jatuh di medium, kemungkinan besar daftar aset kosong atau tidak cocok dengan nilai `dest` di finding, sehingga prioritas aset dianggap unknown. Perbaikannya di Asset & Identity: pastikan server database terdaftar dengan `priority=critical` dan kolom `ip`, `dns`, serta `nt_host` cocok dengan nilai yang muncul di data. Mengubah severity detection bukan perbaikan, karena masalahnya di konteks, bukan di detection.

**Skenario 2: risk rule yang tidak pernah menghasilkan finding group.** Tiga risk rule baru aktif seminggu dan menulis event risiko, tetapi finding-based detection multi-taktik tidak pernah terpicu, padahal `JKT-WS-0523` jelas menjalankan discovery dan persistence. Apa yang dicek?

Pembahasan: urutan cek dari Day 35 bagian 4. Pertama, apakah annotation ATT&CK terisi pada ketiga rule; aturan multi-taktik menghitung `dc` taktik dari annotation, jadi annotation kosong berarti nol taktik. Kedua, apakah ketiga rule memberi skor ke entity yang sama, karena nama host bisa tertulis `JKT-WS-0523` di satu rule dan `jkt-ws-0523.corp.jab.example` di rule lain. Ketiga, apakah ambang dan jendela waktunya cocok dengan rentang aktivitasnya.

**Skenario 3: metrik yang menyesatkan.** Manajer melaporkan MTTR turun dari 9 jam ke 2 jam dalam satu kuartal, tetapi jumlah insiden yang dibuka ulang naik tiga kali lipat. Bagaimana kamu menjelaskannya?

Pembahasan: MTTR yang turun bersamaan dengan reopen rate yang naik adalah tanda penutupan prematur (Day 34). Metrik kecepatan harus dibaca bersama metrik kualitas. Usulan konkret: laporkan median dan p90 TTR, reopen rate, dan proporsi disposition Undetermined. Bila Undetermined tinggi, wajibkan disposition sebelum menutup finding.

**Skenario 4: memilih data model untuk pertanyaan.** Tim ingin tahu apakah ada akun yang login ke lebih dari lima server berbeda dalam satu jam. Data model mana yang dipakai, field apa, dan apa jebakannya?

Pembahasan: data model Authentication (Day 23 dan Day 24) dengan `user`, `dest`, `action`, dan `_time`; hitung `dc(dest)` per `user` dalam `span=1h`. Jebakannya: log Windows klasik bisa memuat dua akun dalam satu event (Subject dan target), sehingga `user` bisa multivalue atau berisi akun mesin (`HOST$`). Saring akun mesin dan pastikan TA memetakan akun target ke `user` (Day 03 bagian 1.5).

**Skenario 5: istilah dalam laporan.** Draf laporan berbunyi "Risk notable dibuat dari 12 notable kecil pada risk object `rina.wulandari`." Tulis ulang dengan istilah ES 8 yang benar.

Pembahasan: "Finding group dibuat oleh finding-based detection dari 12 intermediate finding pada entity `rina.wulandari`." Dua koreksi penting: event pendukung bukan notable karena mereka tidak masuk antrean, dan risk object di ES 8 disebut entity. Untuk pembaca yang terbiasa ES 7, tambahkan padanan lama dalam kurung.

**Skenario 6: tab Intelligence kosong.** PT JAB mengunggah 40 IP dan 12 domain lewat jalur native, threat match sudah menghasilkan finding, tetapi tab Intelligence di investigation kosong. Seorang analyst mengusulkan mengunggah ulang semua indikator.

Pembahasan: tidak ada yang perlu diunggah ulang. Tab Intelligence hanya menampilkan data Threat Intelligence Management (Cloud), bukan koleksi KV store native (Day 33). Pembuktiannya `| inputlookup` ke koleksi sesuai jenis IOC dan threat match di data model Threat_Activity. Yang justru perlu ditambahkan adalah kolom masa berlaku dan confidence pada setiap indikator.

### Lab D: uji lisan sepuluh menit

Rekam dirimu menjelaskan rantai di bagian 1.17 dari sumber data sampai metrik dalam sepuluh menit, dengan peta konsep sebagai satu-satunya bantuan. Lalu jawab tiga pertanyaan interview tanpa catatan:

- "Kenapa sebuah sumber log bisa sudah masuk Splunk dengan volume besar dan tetap tidak terlihat oleh satu pun detection?" (Day 23 bagian 1.2)
- "Apa beda finding, intermediate finding, dan finding group?" (Day 31 bagian 1.3 dan 1.6)
- "Kenapa rata-rata dwell time bisa menyesatkan?" (Day 34 bagian 1.6 dan 2.7)

Catat bagian yang membuatmu ragu; itu daftar yang perlu diulang sebelum masuk Day 38, sekaligus bahan tabel rencana di Day 47.

### Troubleshooting lintas Day

Tabel ini memetakan gejala yang sering muncul ke Day yang perlu diulang. Mulai dari gejala yang paling mirip dengan kesulitanmu di lab.

| Gejala | Day yang perlu diulang | Pemeriksaan |
|---|---|---|
| Sumber ada di index tetapi data model kosong | 23, 24 | `stats count BY tag eventtype` pada sourcetype itu; nilai `action` dengan `tstats ... by action` |
| `tstats` mengembalikan lebih sedikit daripada search raw | 25, 26 | `fillnull_value`, `summariesonly`, summary range, status akselerasi |
| Timeline investigasi bergeser beberapa jam | 28 | `TZ` di stanza sourcetype; `_time` dibanding `_indextime` |
| Field `src_priority` atau `dest_priority` kosong | 24, 26 | Event punya `src` atau `dest`, bukan hanya `host`; daftar aset memuat nama yang sama |
| Content Available di SSE tetapi tidak pernah menghasilkan apa pun | 27, 23 | CIM coverage di Data Inventory dan macro input content |
| Laporan cakupan ATT&CK tampak bolong | 30, 33 | Annotation pada detection kustom; versi ATT&CK; cakupan per procedure |
| Antrean penuh alert lemah, atau antrean sepi padahal risk index penuh | 31, 35 | Pilihan output detection; finding-based detection aktif atau tidak |
| Panel dashboard ES kosong | 32, 26 | Data model di balik sub-dashboard; `summariesonly=false` lalu `true` |
| Tiga analyst menangani kasus serupa dengan cara berbeda | 33, 34 | Response plan Published dan terikat investigation type |
| Detection telat atau melewatkan event yang datang terlambat | 36, 28, 29 | Scheduler log untuk skipped; jendela berjeda; ingest lag |
| Metrik terlihat membaik tetapi insiden berulang | 34 | Median dan p90, reopen rate, proporsi Undetermined |

**Hasil yang sebaiknya tersimpan:**

- Matriks keterlacakan tiga detection dari Lab A tanpa kolom kosong, atau dengan kolom kosong yang sudah ditulis sebagai temuan beserta pemiliknya.
- Satu jejak kasus lab dengan format tabel lima kasus di bagian 1.17.
- Tabel bukti Lab B yang sudah diisi angka, plus satu paragraf tentang langkah yang paling lama dan kenapa.
- Jawaban tertulis untuk skenario 1 sampai 6 di Lab C, lalu catatan Day mana yang jawabanmu paling banyak meleset dari pembahasan.
- Daftar topik yang masih lemah dari uji lisan Lab D, untuk tabel rencana di Day 47.

## 5. Kesalahan umum dan jebakan

- Membaca keadaan tenang sebagai bukti: panel kosong, `tstats` nol baris, atau antrean sepi diartikan "tidak ada aktivitas" tanpa menguji data model, summary, dan risk index (Day 23, 25, 31, 32).
- Mengira memasang add-on CIM berarti data sudah ternormalisasi, atau memilih data model berdasarkan nama field, bukan tujuan event (Day 23).
- Menyalakan akselerasi semua data model tanpa Indexes allowlist, lalu mengubahnya berulang kali di CIM Setup padahal ES memaksakan pengaturannya (Day 23, 26).
- Mengharapkan korelasi Asset & Identity berjalan lewat field `host` di ES 8 (Day 26).
- Menghardcode sourcetype di detection, padahal sourcetype adalah label add-on yang bisa berganti (Day 27).
- Memperbaiki masalah index-time dengan `rex` di setiap search (Day 28).
- Menyamakan risk score RBA dengan risk management organisasi (Day 29 dan Day 35).
- Memakai daftar taktik ATT&CK lama tanpa menyebut versinya, atau mengklaim satu teknik tertutup dari satu procedure (Day 30).
- Memakai label tingkatan intel tanpa menjelaskan isinya (Day 30).
- Menganggap annotation mengubah logika deteksi (Day 30 dan Day 33).
- Mencampur istilah ES 7 dan ES 8 dalam satu runbook tanpa padanan (Day 31).
- Membuat satu investigation per finding untuk insiden yang sama, atau menutup finding tanpa disposition (Day 33).
- Mencampur Benign Positive dengan False Positive (Day 07 dan Day 33).
- Melompat dari Assessment ke Mitigate tanpa Determine risk, dan melaporkan rata-rata dwell time sebagai angka organisasi (Day 34).
- Memakai ambang skor saja di finding-based detection, sehingga satu rule berisik mencapai ambang sendirian (Day 35).
- Memakai `count(eval())` di `tstats` (Day 25 dan Day 36).
- Jendela waktu detection tanpa jeda dan real-time schedule untuk detection yang tidak boleh kehilangan apa pun (Day 36).

## 6. Catatan terkini

Bagian ini menampung status versi dan perubahan istilah yang memengaruhi cara membaca dokumentasi. Isinya tidak mengubah review di atas.

- ES 8.7.0 (2 September 2026) masih rilis ES terbaru per 2026-10-07 [S1]. Cek halaman release notes bila membaca catatan ini jauh setelah tanggal itu.
- ATT&CK v19 (April 2026) memecah Defense Evasion menjadi Stealth dan Defense Impairment, dan v19.2 (Agustus 2026) adalah rilis Agile pertama [S2].
- CIM 6.4.0 (Februari 2026) menambah field unit bisnis di Data Access untuk aset dan identitas, plus beberapa field di Network Sessions, Network Traffic, dan Endpoint [S7].
- SSE 3.8 dan Detection Studio di ES 8.x adalah dua alat penilai cakupan yang dipakai di Day 27 [S3][S19].
- NIST CSF 2.0 menambah fungsi Govern [S6], dan CIS Controls v8.1 diselaraskan dengan CSF 2.0 [S4].
- Dokumentasi ES 8.7 masih memakai istilah ES 7 (notable, risk notable, correlation search) di beberapa halaman dashboard, jadi menu dan dokumentasi tidak selalu konsisten (Day 32).
- Nama field fisik di risk index dan pada finding ES 8.7 (misalnya `risk_object`, field waktu, dan bentuk nilai `disposition`) masih perlu dicek di instance, sehingga query yang ditulis dengan nama field ES 7 di Day 29 sampai Day 35 perlu diuji dulu sebelum dipakai di ES 8.

## 7. Cheat sheet

```
DATA     pertanyaan -> sumber (Day 21) ; freshness: | tstats count latest(_time) where index=* by index sourcetype
         onboarding: sourcetype > LINE_BREAKER > SHOULD_LINEMERGE=false > TIME_* > TZ > TRUNCATE ; lag = _indextime - _time
DM       root event | root search (streaming) | root transaction (TIDAK accelerate) | child ; Required = saring ; Hidden = perantara
CIM      event type -> tag -> field -> NILAI ; tag hilang = tidak di model ; nilai salah = filter detection buta
         pilih model dari TUJUAN event ; accel CIM default off ; ES enforce ; Indexes allowlist
FIELD    src/dest/user/action ; Endpoint dest = host ; Auth src = asal login ; dataset root All_Traffic Processes DNS IDS_Attacks
TSTATS   summariesonly default false (ES macro = true) ; fillnull_value tanpa default ; no count(eval()) ; prestats -> timechart
A&I      src/dest/dvc -> aset ; user/src_user -> identitas ; BUKAN host ; _priority _category _bunit ; risk factor butuh A&I
CAKUPAN  SSE: Data Inventory, Available/Needs data ; ES: Detection Studio (coverage + health)
SOC      analyst = kejadian | engineer = sistem/konten | architect = desain ; kontrol | standar | framework ; risk != risk score
ATT&CK   v19.2, 15 taktik (Stealth TA0005 + Defense Impairment TA0112) ; detection = procedure ; Pyramid hash < ... < TTP
ES 8     detection -> finding (antrean) / intermediate finding (risk index) -> finding-based detection -> finding group
         -> investigation -> disposition ; pemetaan ES 7 lengkap: Day 31 bagian 1.2
INVES    assign -> note hipotesis -> response plan (Published, JSON) -> intel (native vs TIM) -> disposition
         5 tahap: Review > Assessment > Determine risk > Mitigate > Re-assess
METRIK   MTTD MTTA&A MTTI MTTR MTRS FP/FN ; dwell = T0->T1 per insiden ; median + p90 ; tulis definisi
RBA      skor per entity ; dedup (entity, source, threat object) ; keragaman taktik/sumber ; badge 0-25/25-50/50-75/75+
DETEKSI  continuous vs real-time ; stagger ; earliest=-20m@m latest=-5m@m ; throttling | _filter macro | ubah ke risk
```

## 8. Uji diri

Soal di bawah mencampur materi Day 21-36. Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci; kunci juga menunjuk Day asal bila perlu diulang lebih dalam.

**1. Pertanyaan jebakan.** Analyst PT JAB membuka sub-dashboard Intrusion Center dan panelnya kosong, lalu menjalankan `| tstats summariesonly=true count from datamodel=Intrusion_Detection.IDS_Attacks` untuk 24 jam terakhir dan hasilnya nol baris. Ia menulis di tiket "tidak ada aktivitas IDS". Kenapa kesimpulan itu belum sah?

<details><summary>Jawaban</summary>

Keduanya membaca data model, dan dua bukti kosong dari sumber yang sama tidak membuktikan apa pun tentang aktivitas. `summariesonly=true` hanya membaca summary akselerasi, jadi rentang yang belum ter-summarize atau berada di luar summary range memberi nol baris walau datanya ada; langkah berikutnya adalah mengulang dengan `summariesonly=false`. Bila hasilnya tetap nol, masalahnya di rantai keanggotaan CIM, yaitu event type, tag, nama field, atau nilai, atau di onboarding, bukan di dashboard. Baru setelah sumber IDS terbukti masuk model, kesimpulan "tidak ada aktivitas" boleh ditulis. Lihat bagian 1.3, 1.5, dan 1.12, atau Day 32 bagian 1.6.

</details>

**2. Skenario keputusan.** Review SOC-2026-0263 menunjukkan empat alert kecil untuk `JKT-WS-0523` dan `rina.wulandari` ditutup terpisah oleh tiga analyst di tiga shift, sebelum scheduled task `\EdgeUpdateCheck` dibuat. SOC lead tidak mau kasus seperti ini terulang. Langkah mana yang paling tepat?

- A. Matikan keempat detection itu, karena masing-masing sudah terbukti berisik dan ditutup sebagai benign.
- B. Ubah detection yang lemah menjadi risk rule yang menulis intermediate finding beserta threat object dan annotation ATT&CK, lalu aktifkan finding-based detection yang memakai deduplikasi dan syarat keragaman sumber atau taktik.
- C. Ubah keempatnya menjadi finding berseverity high, supaya tidak ada lagi yang ditutup tanpa diperhatikan.

<details><summary>Jawaban</summary>

B. Yang hilang di kasus ini adalah gabungan sinyal pada satu entity, dan itu persis yang dikerjakan RBA: detection lemah menambah skor pada entity, lalu finding group lahir ketika akumulasi atau keragamannya melewati ambang. Annotation wajib karena syarat keragaman taktik dihitung darinya, dan deduplikasi per entity, source, dan threat object mencegah satu rule berisik mencapai ambang sendirian, seperti skor `rina.wulandari` yang turun dari 280 naif menjadi 105. A membuang sinyal yang justru bermakna dalam kombinasi. C menambah beban antrean tanpa memberi analyst gabungan konteksnya, sehingga keempat alert tetap dibaca terpisah. Lihat bagian 1.15 dan 1.17, atau Day 35 bagian 1.4 dan 2.3.

</details>

**3. Pertanyaan jebakan.** Draf laporan cakupan PT JAB berbunyi: "Kami menutupi 9 dari 14 taktik ATT&CK, termasuk Defense Evasion, dan T1053.005 sudah covered karena ada alert `schtasks /create`." Apa saja yang perlu dikoreksi?

<details><summary>Jawaban</summary>

Tiga hal. Sejak ATT&CK v19 jumlah taktiknya 15, karena Defense Evasion dipecah menjadi Stealth (TA0005) dan Defense Impairment (TA0112), jadi laporan itu memakai pemetaan lama dan harus menyebut versi ATT&CK yang dipakai. Satu alert `schtasks /create` menangkap satu procedure, bukan seluruh teknik, sehingga cakupan T1053.005 perlu dilaporkan per procedure dan ditopang sumber kedua seperti event 4698 di host yang audit policy-nya aktif. Terakhir, laporan cakupan hanya menghitung detection yang punya annotation, jadi detection kustom tanpa annotation bisa membuat cakupan tampak lebih buruk atau berbeda dari kenyataan. Lihat bagian 1.10 dan 1.13, atau Day 30 bagian 1.5 dan 1.8.

</details>

**4. Skenario keputusan.** Log RADIUS pelanggan sudah masuk index `linux` dengan volume besar, tetapi alert brute force PT JAB tidak pernah menangkap percobaan ke akun pelanggan. Apa yang kamu kerjakan?

- A. Tulis detection kedua khusus RADIUS dengan logika yang sama, membaca langsung `sourcetype=jab:radius:auth`.
- B. Normalkan sumber itu ke data model Authentication: event type, tag `authentication`, field alias ke `user`, `src`, `dest`, dan `EVAL-action` yang menghasilkan `success` atau `failure`, lalu validasi dengan `tstats` dan jalankan alert lama tanpa mengubahnya.
- C. Masukkan sumber itu ke Network Traffic, karena isinya banyak alamat IP.

<details><summary>Jawaban</summary>

B. Alert yang ada membaca data model, dan sebuah event baru terhitung di model bila event type, tag, nama field, dan nilai field semuanya sesuai. Begitu keempatnya terpenuhi, alert brute force yang sudah ada ikut menghitung akun pelanggan tanpa satu baris pun diubah, dan itu inti nilai CIM. A menggandakan logika yang harus dirawat di dua tempat dan menghardcode sourcetype yang bisa berganti. C memilih model dari nama field, bukan dari tujuan event, sehingga kosakata nilai `action` tidak cocok dan Authentication tetap kosong. Lihat bagian 1.3 dan 1.7, atau Day 23 bagian 1.2 dan 2.4.

</details>

**5. Pertanyaan jebakan.** Sebuah detection PT JAB berjalan setiap 15 menit dengan `earliest=-15m latest=now` dan real-time schedule. Log scheduler tidak menunjukkan error, tetapi beberapa kejadian yang eventnya jelas ada di index tidak pernah memunculkan finding. Rekanmu menyimpulkan logikanya salah. Apa dugaan yang lebih kuat?

<details><summary>Jawaban</summary>

Dua penyebab yang tidak menyentuh logika sama sekali. Pertama, ingest lag: event yang masuk index setelah search untuk jendelanya sudah berjalan tidak pernah dibaca, karena jendela yang menempel ke `now` justru berisi menit yang paling sering belum lengkap. Perbaikannya jendela berjeda dan dibulatkan seperti `earliest=-20m@m latest=-5m@m`, dengan besar jeda diukur dari lag sumber itu sendiri, atau Index Time untuk sumber yang sering terlambat. Kedua, real-time schedule di-skip ketika search head sibuk dan jendela yang terlewat tidak dipindai ulang, jadi detection yang tidak boleh kehilangan apa pun dipindah ke continuous schedule dan jadwalnya di-stagger. Lihat bagian 1.8 dan 1.16, atau Day 36 bagian 1.2.

</details>

**6. Jelaskan ulang.** Jelaskan kepada analyst L1 baru di PT JAB, dalam tiga kalimat, perjalanan satu event login gagal di `wineventlog` sampai menjadi angka di laporan kuartalan, memakai istilah ES 8.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Event itu baru berguna setelah add-on memberinya event type, tag `authentication`, nama field CIM, dan nilai `action=failure`, karena detection membaca data model Authentication lewat `tstats`, bukan membaca index, dan konteks prioritas akun atau host-nya ditempelkan dari daftar aset dan identitas. Detection yang terjadwal lalu menghasilkan finding di analyst queue bila polanya cukup yakin, atau intermediate finding yang menambah skor pada entity bila sinyalnya lemah, dan akumulasi skor itu bisa menjadi finding group lewat finding-based detection. Analyst membawanya ke investigation, menjalani lima tahap sampai ditutup dengan disposition, dan dari disposition serta jejak waktu itulah FP rate per detection, MTTR, dan dwell time dihitung untuk rapat."

Kesalahan yang sering muncul:
- Melompat dari event langsung ke finding, seolah detection membaca log mentah tanpa normalisasi.
- Menyebut intermediate finding sebagai item di antrean.
- Berhenti di "kasus ditutup", padahal disposition yang benar adalah bahan metrik dan tuning.

</details>

**7. Interview question (English).** "Pick an incident you worked and trace it end to end: from the raw log to the number you reported to management."

<details><summary>Sample answer</summary>

"Take a scheduled task persistence case on a workstation. It starts with data: process creation with command lines from Sysmon, which in that environment only covered part of the fleet, so I also relied on the Windows task creation event, which depends on the audit policy being enabled. Those events had to be normalised into the CIM Endpoint data model with the right tags and values, otherwise the detections reading the accelerated model through tstats would simply see nothing, and an empty result there is not evidence of absence. The context came next: asset and identity data for priority, and an ATT&CK annotation, T1053.005 under version 19, so the case could be counted in coverage and in risk by tactic. What went wrong was not the search logic: four weak alerts on the same user and host were closed separately by three analysts, so the pattern only became visible later. The fix was to turn those weak detections into risk rules and let a finding-based detection raise one finding group, with deduplication by entity, source and threat object so one noisy rule cannot reach the threshold alone. The investigation then went through review, assessment, scoping, mitigation and re-assessment, and closed with a disposition. For management I reported median and p90 time to resolution, and dwell time for that case separately, because one long persistence case can turn an average into a number that describes nobody."

What makes this answer strong: it walks the chain in order instead of jumping to the SPL, names the data and normalisation dependencies that fail silently, places the real failure in how weak signals were handled, shows the RBA fix with its main safeguard, and ends with honest metric reporting.

</details>

## 9. Sumber

Sumber untuk setiap klaim rinci ada di tabel Sumber Day asalnya. Tabel di bawah hanya memuat sumber untuk klaim yang ditulis ulang dengan rujukan `[S#]` di Day ini, beserta Day asal yang memakainya.

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Release notes ES 8.7 | https://help.splunk.com/en/splunk-enterprise-security-8/release-notes-and-resources/8.7 | primer | 2026-09-02; dilihat 2026-10-07 | Tinggi. Versi ES 8.7.0 |
| S2 | MITRE ATT&CK: Enterprise tactics v19 (Day 30) | https://attack.mitre.org/tactics/enterprise/ | primer | diakses 2026-10-07 | Tinggi. Daftar 15 taktik |
| S3 | ES 8.7: Monitor detection coverage and health using Detection Studio (Day 27) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/detections/identify-optimal-detections-for-your-security-environment-using-detection-studio-in-splunk-enterprise-security/monitor-detection-coverage-and-health-using-detection-studio-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi |
| S4 | CIS: CIS Critical Security Controls v8.1 (Day 29) | https://www.cisecurity.org/insights/white-papers/cis-critical-security-controls-v8-1 | primer | 2024-06; dilihat 2026-10-07 | Tinggi |
| S5 | ES 8.7: Glossary (Day 31) | https://help.splunk.com/en/splunk-enterprise-security-8/release-notes-and-resources/8.7/where-to-find-help/glossary | primer | diakses 2026-10-07 | Tinggi. Definisi dan pemetaan istilah ES 7 ke ES 8 |
| S6 | NIST: The NIST Cybersecurity Framework (CSF) 2.0 (Day 29) | https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf | primer | 2024-02-26; diakses 2026-10-10 | Tinggi. Enam fungsi |
| S7 | CIM 6.4: Release notes (Day 23) | https://help.splunk.com/en/data-management/common-information-model/6.4/introduction/release-notes-for-the-splunk-common-information-model-add-on | primer | 2026-02-04 | Tinggi |
| S8 | ES 8.0: Findings and finding groups in Splunk Enterprise Security (Day 31) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.0/investigations/findings-and-finding-groups-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi. Batas 50 event per finding group dan 100 finding per investigation |
| S9 | ES 8.7: Configure asset and identity correlation (Day 26) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/asset-and-identity-validation/configure-asset-and-identity-correlation-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi. Field korelasi; `host` tidak dikorelasikan |
| S10 | ES 8.7: Risk scoring in Splunk Enterprise Security (Day 35) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/risk-based-alerting | primer | diakses 2026-10-07 | Tinggi |
| S11 | Splunk Lantern: Creating an incident workflow in Splunk Enterprise Security (Day 34) | https://lantern.splunk.com/Security_Use_Cases/Advanced_Threat_Detection/Creating_an_incident_workflow_in_Splunk_Enterprise_Security | primer | diakses 2026-10-07 | Tinggi untuk lima tahap |
| S12 | Splunk blog: SOC Metrics: Security Metrics & KPIs for Measuring SOC Success (Day 34) | https://www.splunk.com/en_us/blog/learn/security-operations-metrics.html | primer (vendor) | 2023-05-18; diakses 2026-10-07 | Tinggi untuk definisi metrik; bukan standar industri |
| S13 | ES 8.7: Specify the time to run detections in Splunk Enterprise Security (Day 36) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/detections/specify-the-time-to-run-detections-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi |
| S14 | ES 8.7: Configure threat lists in Splunk Enterprise Security (Day 33) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/threat-intelligence/configure-threat-lists-in-splunk-enterprise-security | primer | dilihat 2026-10-09 | Tinggi. Tab Intelligence hanya menampilkan TIM (Cloud) |
| S15 | Set up the Splunk Common Information Model Add-on (dok 6.2; Day 23) | https://help.splunk.com/en/data-management/common-information-model/6.2/introduction/set-up-the-splunk-common-information-model-add-on | primer | diakses 2026-10-07 | Tinggi. Allowlist, akselerasi default nonaktif, enforcement ES |
| S16 | SPL Search Reference: tstats (Splunk Enterprise 10.2; Day 25) | https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.2/search-commands/tstats | primer | diakses 2026-10-07 | Tinggi. Default dan batasan argumen |
| S17 | Splunk Enterprise 10.6 Knowledge Manager Manual: Accelerate data models (Day 22 dan Day 26) | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/use-data-summaries-to-accelerate-searches/accelerate-data-models | primer | diakses 2026-10-14 | Tinggi. Syarat akselerasi dan angka operasional |
| S18 | CISA: Best Practices for Event Logging and Threat Detection (Day 21) | https://cisa.gov/resources-tools/resources/best-practices-event-logging-and-threat-detection | primer | 2024-08-21; diakses 2026-10-07 | Tinggi. Ringkasan halaman sumber daya |
| S19 | SSE 3.8: Configure the products you have in your environment with the Data Inventory dashboard (Day 27) | https://help.splunk.com/en/splunk-enterprise-security-8/security-essentials/use-splunk-security-essentials/3.8/use-data-in-splunk-security-essentials | primer | diakses 2026-10-07 | Tinggi |

**Catatan sumber:** Day review ini tidak menambah klaim teknis baru; semua fakta dan angka diambil dari Day 21-36, dan hal yang di sana masih perlu dicek tetap berlaku, terutama nama field finding dan risk index di ES 8.7, menu ES 8.7 yang berasal dari dokumentasi versi lebih lama, dan angka survei atau laporan yang berasal dari liputan. Status ES 8.7.0 sebagai rilis terbaru dicatat per 2026-10-07 dari release notes [S1]. Kasus SOC-2026-0217, 0231, 0251, 0258, 0263, 0274, dan 0276 beserta seluruh angkanya adalah artefak fiktif PT JAB dari Day asalnya; skenario di Lab C fiktif.
