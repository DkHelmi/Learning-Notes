---
day: 04
title: 'Framework CTI: Cyber Kill Chain, Diamond Model, ATT&CK, dan Pyramid of Pain'
researched_on: 2026-10-10
versions_checked: 'MITRE ATT&CK Enterprise v19.2 (Agustus 2026; 15 tactic); Hutchins, Cloppert, Amin (2011); Diamond Model (Caltagirone, Pendergast, Betz, 2013); Pyramid of Pain (Bianco, 2013, revisi 2014); Unified Kill Chain (Pols)'
---

# Day 04: Framework CTI

Cakupan: empat kerangka untuk menstrukturkan analisis ancaman (Cyber Kill Chain dengan course of action matrix, Diamond Model dengan pivot dan activity thread, ATT&CK v19, dan Pyramid of Pain) diterapkan bersama pada satu kampanye fiktif.

## Ide inti

Analisis ancaman tanpa kerangka cenderung berantakan: daftar IOC tanpa struktur, atau cerita panjang yang sulit dibandingkan dengan kasus lain. Framework memberi bahasa bersama sehingga analis bisa membandingkan kampanye, berbicara dengan detection engineer dan IR, dan memprioritaskan tindakan. Tidak ada satu framework yang terbaik, karena masing-masing menjawab pertanyaan yang berbeda tentang kasus yang sama.

Kill Chain memberi urutan tahap serangan dan tempat memutusnya. Diamond menstrukturkan satu event dan hubungan antar event. ATT&CK mengatalogkan perilaku dengan ID yang dipakai seluruh industri, termasuk di rule deteksi dan hipotesis hunting. Pyramid of Pain memprioritaskan indikator menurut biaya yang ditimbulkan bagi penyerang.

Kamu sudah memakai keempat sudut pandang ini secara tidak resmi saat menulis laporan insiden. Timeline per tahap dan pertanyaan "kontrol mana yang gagal di tahap ini" adalah Kill Chain. Pivot di SIEM dari satu IP ke host lain yang menghubunginya adalah Diamond. Tag T-ID di detection rule dan coverage matrix adalah ATT&CK. Keputusan mana yang masuk blocklist hari ini dan mana yang dijadikan rule perilaku adalah Pyramid of Pain. Day ini memberi nama dan aturan pada kebiasaan itu, supaya hasilnya bisa dibandingkan lintas kasus dan lintas organisasi.

```
Satu kasus (LOGI-FICTA)
  -> Kill Chain     : di tahap mana bisa diputus?          -> tahap tanpa lapisan kedua  -> backlog kontrol
  -> Diamond        : event mana terhubung, pivot ke mana?  -> host dan korban lain      -> scoping, kandidat cluster
  -> ATT&CK         : perilaku apa, terdeteksi atau tidak?  -> T-ID dengan dasar bukti   -> coverage deteksi
  -> Pyramid of Pain: indikator mana yang tahan lama?       -> blokir hari ini vs rule   -> investasi deteksi
Keempatnya melayani keputusan; pemetaan bukan hasil akhir.
```

Situasi yang dipakai sepanjang Day ini: PT Logistik Contoh (PT LC, perusahaan logistik fiktif dengan gudang di Jakarta, Surabaya, dan Medan) baru selesai menangani intrusi yang diberi nama kampanye "LOGI-FICTA". Seorang staf pengadaan membuka lampiran bermacro, host-nya beaconing ke domain luar, dan sekitar 1,2 GB dokumen kontrak keluar. Setelah containment, Lead SOC menulis ke tim CTI:

> "Untuk post-incident review minggu ini, tolong susun analisis LOGI-FICTA yang bisa dipakai semua tim:
> 1. Di tahap mana serangan ini seharusnya bisa kita putus, dan tahap mana yang tidak punya lapisan kontrol kedua?
> 2. Apakah ada host atau korban lain yang terhubung dengan kasus ini?
> 3. Teknik apa yang dipakai, dalam bahasa yang dipakai detection engineer, dan seberapa kuat buktinya?
> 4. Indikator mana yang diblokir hari ini, dan apa yang dibangun detection engineer untuk jangka panjang?
> 5. ISAC menyebut pola mirip di perusahaan logistik lain. Apakah pelakunya sama?"

Butir 1 dijawab Kill Chain dan course of action matrix (bagian 1.1 dan 2.2). Butir 2 dijawab Diamond Model dan pivot (bagian 1.2, 1.3, dan 2.3). Butir 3 dijawab ATT&CK (bagian 1.4 dan 2.4). Butir 4 dijawab Pyramid of Pain (bagian 1.5 dan 2.5). Butir 5 menuntut gabungan framework dan bahasa keyakinan (bagian 1.6 sampai 1.8 dan pivot ketiga di bagian 2.3).

**Kapan relevan:** menulis analisis insiden atau kampanye, memetakan laporan publik ke kemampuan deteksi sendiri, berkomunikasi lintas tim, dan memprioritaskan backlog deteksi.
**Kapan bukan jawaban:** framework adalah alat bantu. Memaksa data ke kategori yang tidak cocok menghasilkan kepastian palsu.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Tabel ini memuat istilah framework yang muncul di Day ini. Kolom padanan memakai analogi SOC yang sama di semua Day CTI. Istilah dari Day sebelumnya (CTI, IOC, TTP, PIR, bahasa keyakinan) tidak diulang.

| Istilah | Arti singkat | Padanan di SOC |
|---|---|---|
| Cyber Kill Chain | Tujuh tahap intrusi terarah dari reconnaissance sampai actions on objectives | Timeline laporan insiden yang dibagi per tahap serangan |
| Course of action matrix | Matriks tahap Kill Chain terhadap enam aksi: detect, deny, disrupt, degrade, deceive, destroy | Coverage kontrol per tahap: tahap mana yang punya pencegahan dan deteksi |
| Indikator atomic, computed, behavioral | Indikator yang tidak bisa dipecah (IP, email), diturunkan dari data (hash, regex), dan gabungan yang menggambarkan perilaku | Isi blocklist, signature, dan correlation rule perilaku |
| Unified Kill Chain | Gabungan Kill Chain dan ATT&CK menjadi 18 fase dalam tiga siklus | Timeline yang memberi ruang untuk aktivitas di dalam jaringan |
| Diamond Model | Struktur satu intrusion event: adversary, capability, infrastructure, victim | Ringkasan satu event di case: siapa, pakai apa, lewat mana, ke siapa |
| Meta-feature | Atribut tambahan event: timestamp, phase, result, direction, methodology, resources | Field tambahan di event: waktu, arah koneksi, hasil |
| Infrastructure Type 1 dan Type 2 | Infrastruktur milik penyerang vs milik perantara yang dibobol atau disalahgunakan | Server C2 milik penyerang vs akun atau host pihak ketiga yang diambil alih sebagai relay |
| Pivot | Dari satu feature yang diketahui, cari event lain yang berbagi feature itu | Pivot di SIEM dari satu IP atau hash ke event lain |
| Activity thread | Event berurutan untuk pasangan adversary dan victim yang sama, diurutkan menurut phase | Timeline satu case |
| Activity group | Gabungan thread yang berbagi ciri; dasar clustering aktor | Mengelompokkan beberapa case yang mirip menjadi satu kampanye |
| Tactic | Tujuan taktis sebuah aksi, "kenapa" | Kolom di matriks ATT&CK |
| Technique dan sub-technique | Cara mencapai tactic, dengan ID `Txxxx` dan `Txxxx.yyy` | Tag T-ID di detection rule |
| Procedure | Implementasi konkret oleh aktor atau malware tertentu | Command line spesifik yang terlihat di satu kasus |
| Pyramid of Pain | Urutan jenis indikator menurut seberapa menyakitkan bagi penyerang bila ditolak | Umur pakai isi blocklist dibanding rule perilaku |

### 1.1 Cyber Kill Chain dan course of action matrix

Butir pertama Lead SOC menanyakan di mana LOGI-FICTA seharusnya bisa diputus. Pertanyaan itu mengandaikan serangan punya urutan tahap, dan itulah gagasan Kill Chain.

Model ini berasal dari paper Hutchins, Cloppert, dan Amin dari Lockheed Martin (2011). Gagasannya: intrusi terarah adalah rangkaian tahap, dan penyerang harus berhasil di setiap tahap, sedangkan pembela cukup memutus satu tahap [S1]. Tabel berikut memuat ketujuh tahap; perhatikan kolom terakhir, karena itu yang menentukan di mana kamu bisa melihat sebuah tahap di log sendiri.

| Tahap | Isi menurut paper | Contoh yang terlihat oleh pembela |
|---|---|---|
| Reconnaissance | Riset dan pemilihan target: alamat email, relasi sosial, teknologi yang dipakai | Kunjungan crawler ke halaman karier; jarang terlihat |
| Weaponization | Menggabungkan malware dengan exploit atau dokumen menjadi muatan yang siap kirim | Tidak terlihat langsung; dipelajari dari sampel |
| Delivery | Pengiriman: email, situs, media USB | Log email gateway, proxy |
| Exploitation | Kode penyerang berjalan: celah aplikasi, fitur OS, atau pengguna yang membuka file | Process creation dari aplikasi Office |
| Installation | Akses bertahan dipasang di host | Run key, service, scheduled task baru |
| Command and Control | Kanal kendali dari luar | Beaconing DNS atau HTTP berkala |
| Actions on Objectives | Tujuan dicapai: mencuri data, merusak, atau pindah ke target lain | Volume upload besar, akses file massal |

Paper ini juga memperkenalkan dua alat yang sering dilupakan. Pertama, tiga jenis indikator: atomic (tidak bisa dipecah lagi, misalnya IP atau email), computed (diturunkan dari data, misalnya hash atau regex), dan behavioral (gabungan keduanya yang menggambarkan perilaku) [S1]. Kedua, course of action matrix yang memasangkan setiap tahap dengan enam aksi dari doktrin operasi informasi: detect, deny, disrupt, degrade, deceive, destroy. Contohnya: NIDS bisa detect pada tahap delivery, patch bisa deny exploitation, dan DEP bisa disrupt exploitation [S1]. Matriks ini berguna untuk menilai lapisan kontrol: tahap mana yang punya lebih dari satu aksi, dan tahap mana yang kosong. Matriks LOGI-FICTA ada di bagian 2.2.

Keterbatasannya nyata. Model ini linear dan berpusat pada malware yang masuk lewat perimeter. Serangan berbasis identitas (login dengan kredensial curian ke layanan cloud) melewati weaponization, exploitation, dan installation dalam arti klasik. Aktivitas setelah masuk, seperti lateral movement dan eskalasi hak, terjepit di antara installation dan actions. Unified Kill Chain dari Paul Pols mencoba menutup celah ini dengan menggabungkan Kill Chain dan ATT&CK menjadi 18 fase dalam tiga siklus: masuk (In), bergerak di dalam jaringan (Through), dan mengambil hasil (Out) [S5].

### 1.2 Diamond Model: struktur satu event

Untuk menjawab butir kedua (apakah ada host atau korban lain), kamu perlu mencatat setiap event LOGI-FICTA dengan bagian-bagian yang bisa dicari ulang: siapa pelakunya, alat apa yang dipakai, lewat infrastruktur apa, dan siapa korbannya.

Diamond Model (Caltagirone, Pendergast, Betz, 2013) dimulai dari satu aksioma: setiap intrusion event terdiri atas adversary yang memakai capability melalui infrastructure terhadap victim untuk menghasilkan suatu result [S2]. Tabel berikut merinci keempat core feature; perhatikan kolom catatan, karena pembedaan di sana (operator dan customer, Type 1 dan Type 2, persona dan asset) yang sering menentukan tindakan.

| Core feature | Arti | Catatan dari paper |
|---|---|---|
| Adversary | Pelaku | Dibedakan antara operator (yang melakukan intrusi) dan customer (yang mendapat manfaat); bisa orang yang sama atau berbeda |
| Capability | Alat dan teknik | Termasuk malware, exploit, dan teknik manual; C2 diperlakukan sebagai bagian capability |
| Infrastructure | Struktur komunikasi untuk mengirim capability, mengendalikan, dan mengambil hasil | Type 1 milik penyerang; Type 2 milik perantara (host yang dibobol, domain staging, akun email curian) yang menyamarkan asal; service provider seperti ISP dan registrar |
| Victim | Target | Dibedakan antara victim persona (orang, organisasi) dan victim asset (host, akun, email) |

Event juga punya meta-feature: timestamp mulai dan selesai, phase, result, direction, methodology, dan resources [S2]. Direction berguna untuk menentukan tempat deteksi; nilainya antara lain victim-to-infrastructure, infrastructure-to-victim, dan bidirectional. Setiap feature punya nilai keyakinan sendiri, sehingga kamu bisa menulis "infrastructure: diketahui, keyakinan tinggi; adversary: cluster TA-FICTA, keyakinan rendah". Model ini juga menambah dua sumbu: social-political (hubungan dan kebutuhan antara adversary dan victim, yang menjelaskan motif) dan technology (hubungan antara capability dan infrastructure).

### 1.3 Diamond Model: pivot, activity thread, dan activity group

Setelah event LOGI-FICTA tercatat, pertanyaan berikutnya adalah ke mana mencari. Di SIEM kamu biasa pivot dari satu IP ke host lain; Diamond memberi pola yang sama dengan nama yang jelas.

Kekuatan utama Diamond adalah pivot. Dari satu feature yang diketahui, cari event lain yang berbagi feature itu. Paper menyebut beberapa pendekatan yang berpusat pada satu feature: victim-centered (mulai dari korban, cari capability dan infrastructure yang menyentuhnya), capability-centered (mulai dari sampel malware, cari korban lain dan infrastrukturnya), infrastructure-centered (mulai dari domain atau IP), dan adversary-centered [S2].

Event yang berurutan untuk pasangan adversary dan victim yang sama disusun menjadi activity thread, diurutkan menurut phase. Thread yang berbagi ciri digabung menjadi activity group, yaitu dasar clustering aktor yang dibahas di Day 03 [S2]. Butir kelima Lead SOC (pelaku sama dengan kasus di perusahaan lain?) adalah pertanyaan activity group. Contoh tiga event, satu thread, dan tiga pivot ada di bagian 2.3.

### 1.4 MITRE ATT&CK

Butir ketiga Lead SOC meminta teknik LOGI-FICTA dalam bahasa detection engineer. Bahasa itu adalah ATT&CK, karena ID-nya yang dipakai di rule, coverage matrix, dan laporan vendor.

ATT&CK adalah basis pengetahuan perilaku adversary yang dibangun dari observasi nyata [S3]. Strukturnya bertingkat:

- **Tactic:** tujuan taktis, "kenapa" sebuah aksi dilakukan.
- **Technique:** cara mencapai tactic, "bagaimana". ID berbentuk `T1566`.
- **Sub-technique:** varian lebih spesifik, misalnya `T1566.001` Spearphishing Attachment.
- **Procedure:** implementasi konkret oleh aktor atau malware tertentu, dicatat sebagai contoh di halaman technique.

Satu technique bisa berada di beberapa tactic. Contohnya `T1078` Valid Accounts muncul di Initial Access, Persistence, Privilege Escalation, dan Stealth, karena akun sah bisa dipakai untuk semua tujuan itu [S3].

Versi ATT&CK menentukan nama dan ID tactic yang kamu tulis, jadi sebut versinya di setiap pemetaan. Tabel berikut memuat tactic Enterprise di ATT&CK v19.2; cari terutama dua baris yang menggantikan Defense Evasion.

| ID | Tactic | ID | Tactic |
|---|---|---|---|
| TA0043 | Reconnaissance | TA0006 | Credential Access |
| TA0042 | Resource Development | TA0007 | Discovery |
| TA0001 | Initial Access | TA0008 | Lateral Movement |
| TA0002 | Execution | TA0009 | Collection |
| TA0003 | Persistence | TA0011 | Command and Control |
| TA0004 | Privilege Escalation | TA0010 | Exfiltration |
| TA0005 | Stealth | TA0040 | Impact |
| TA0112 | Defense Impairment | | |

Perubahan penting di v19 (April 2026): tactic Defense Evasion dipecah. ID `TA0005` kini bernama Stealth (menghindari terlihat, misalnya proxy execution lewat binary sistem seperti `T1218.005` Mshta), dan tactic baru `TA0112` Defense Impairment menampung teknik yang melemahkan pertahanan [S3]. Dokumen, rule, dan laporan sebelum April 2026 masih memakai nama Defense Evasion, jadi kenali keduanya dan remap pemetaan lama.

Selain matriks, ATT&CK punya halaman Groups (aktor yang dilacak, dengan nama alias dari berbagai vendor), Software (malware dan tool), dan Campaigns (rangkaian aktivitas dengan rentang waktu). Di CTI, ATT&CK dipakai untuk mendeskripsikan perilaku aktor dengan kosakata standar, memetakan deteksi yang dimiliki, membandingkan kelompok, dan menyusun prioritas deteksi berbasis aktor yang relevan. Pemetaan LOGI-FICTA ada di bagian 2.4.

### 1.5 Pyramid of Pain

Butir keempat Lead SOC membedakan dua hal: yang diblokir hari ini dan yang dibangun untuk jangka panjang. Pyramid of Pain memberi alasan kenapa keduanya berbeda.

Pyramid of Pain (David Bianco, 2013) mengurutkan jenis indikator menurut seberapa menyakitkan bagi penyerang bila indikator itu ditolak [S4]. Tabel berikut dibaca dari bawah ke atas; perhatikan kolom "Kenapa", karena itu yang menjelaskan biaya penyerang untuk mengganti indikator.

| Tingkat (bawah ke atas) | Contoh | Label Bianco | Kenapa |
|---|---|---|---|
| Hash values | SHA256 file | Trivial | Ubah satu byte, hash berubah total |
| IP addresses | 203.0.113[.]50 | Easy | Ganti server atau lewat proxy |
| Domain names | bad-logistics[.]example | Simple | Perlu registrasi, tetapi murah dan cepat |
| Network/host artifacts | Pola URI, User-Agent khas, nama service, registry key | Annoying | Penyerang harus mengubah konfigurasi atau mengompilasi ulang alat |
| Tools | Backdoor, credential dumper, builder dokumen | Challenging | Harus mencari atau membuat alat baru dan belajar memakainya |
| TTPs | Cara kerja: misalnya mencuri kredensial dari memori lalu bergerak dengan RDP | Tough | Harus mengubah cara beroperasi |

Pelajarannya bukan "jangan pakai hash". Hash dan IP tetap berguna untuk scoping insiden dan blokir cepat, dan sangat akurat. Masalahnya umurnya pendek. Investasi deteksi jangka panjang sebaiknya diarahkan ke tingkat atas, dan di situlah ATT&CK berguna sebagai kosakata. Keputusan untuk indikator LOGI-FICTA ada di bagian 2.5.

### 1.6 Kapan memakai yang mana

Lima butir pesan Lead SOC ternyata lima pertanyaan berbeda, dan tiap pertanyaan punya framework yang paling cocok. Tabel berikut adalah alat pilih cepat; cari baris yang paling mirip dengan pertanyaan yang sedang kamu hadapi.

| Pertanyaan | Framework |
|---|---|
| Di tahap mana serangan ini bisa diputus, dan kontrol apa yang kosong? | Kill Chain dan course of action matrix |
| Bagaimana event ini terhubung dengan event lain, dan ke mana pivot berikutnya? | Diamond |
| Perilaku apa yang dipakai aktor, dan apakah kita bisa mendeteksinya? | ATT&CK |
| Indikator mana yang layak dijadikan deteksi jangka panjang? | Pyramid of Pain |
| Apakah dua insiden kemungkinan pelaku yang sama? | Diamond activity group ditambah pola TTP ATT&CK |

### 1.7 Memadukan framework

Analisis LOGI-FICTA untuk post-incident review tidak memilih satu framework; keempatnya dipakai pada data yang sama.

Framework saling melengkapi. Setiap event Diamond punya meta-feature phase yang bisa diisi tahap Kill Chain. Capability di event dipetakan ke technique ATT&CK. Indikator yang terkumpul diurutkan dengan Pyramid of Pain. Hasilnya analisis berlapis: urutan tahap, struktur dan pivot, perilaku terstandar, dan prioritas tindakan. Pola TTP yang konsisten lintas kampanye juga menjadi dasar clustering yang lebih tahan false flag daripada IOC atomik. Karena itu, untuk butir kelima, kemiripan domain saja belum cukup; yang dicari adalah pola TTP dan capability yang sama.

### 1.8 Framework sebagai alat, bukan tujuan

Godaan setelah analisis LOGI-FICTA selesai adalah menyerahkan tabel pemetaan ke Lead SOC dan menganggap pekerjaan selesai.

Bahaya umum adalah memperlakukan pemetaan sebagai hasil akhir: "kita sudah petakan ke ATT&CK, selesai." Pemetaan melayani PIR dan keputusan (Day 02). Tanya selalu: pemetaan ini mengubah keputusan apa? Bahaya kedua adalah memaksa data ambigu ke ID yang terlalu spesifik. Bila bukti hanya menunjukkan "ada eksekusi dari lampiran", petakan ke tactic Execution dan technique `T1204` dulu; sub-technique dipilih setelah ada bukti jenis file atau tautannya. Nyatakan ketidakpastiannya seperti di Day 03.

## 2. Contoh artefak intelijen

Semua isi bagian ini fiktif dan berlabel ilustrasi: kampanye "LOGI-FICTA" dan korbannya, PT Logistik Contoh, dibuat untuk latihan, IOC di-defang, dan teknik dirujuk ke ATT&CK v19.2. Artefak di bawah adalah bahan jawaban untuk pesan Lead SOC di bagian Ide inti.

### 2.1 Kronologi singkat kasus

Kronologi ini adalah fakta kasus yang dipakai oleh semua artefak berikutnya.

Dua minggu sebelum insiden, beberapa staf pengadaan menerima pesan LinkedIn dari "rekruter". Pada 2026-10-06, staf pengadaan menerima email berlampiran `Penawaran_Tarif_Q4.docm`. Satu staf membuka dan mengaktifkan macro. Host-nya kemudian membuat Run key baru dan mulai menghubungi `bad-logistics[.]example` (203.0.113[.]50) setiap 60 detik lewat HTTPS. Dua hari kemudian, sekitar 1,2 GB dokumen kontrak dikirim keluar lewat kanal yang sama.

### 2.2 Kill Chain dan course of action matrix

Matriks ini menjawab butir pertama Lead SOC: tiap tahap LOGI-FICTA dipasangkan dengan kontrol detect, deny, dan disrupt yang ada atau bisa dipasang. Cari baris yang kolomnya banyak berisi tanda "-".

| Tahap | Aktivitas LOGI-FICTA | Detect | Deny | Disrupt |
|---|---|---|---|---|
| Reconnaissance | Profil staf pengadaan di media sosial | Kesadaran staf, laporan pesan mencurigakan | Batasi detail jabatan di profil publik | - |
| Weaponization | Dokumen dengan macro | Analisis sampel (pasca kejadian) | - | - |
| Delivery | Email berlampiran `.docm` | Rule email gateway untuk lampiran bermacro dari luar | Blokir `.docm` dari pengirim eksternal | - |
| Exploitation | Pengguna mengaktifkan macro | EDR: Office membuat proses anak | Kebijakan blokir macro dari internet | ASR rule |
| Installation | Run key baru | Rule registry Run key | Hak pengguna terbatas | - |
| C2 | Beaconing HTTPS 60 detik | Analitik beaconing di proxy | Kategori domain baru diblokir | Sinkhole DNS |
| Actions | Exfiltration 1,2 GB | Alert volume upload | DLP | Batasi bandwidth keluar per host |

**Cara membaca hasil:** tahap delivery dan exploitation punya kontrol deny yang murah (blokir lampiran bermacro). Tahap C2 dan actions hanya punya detect yang bergantung pada analitik, jadi bila deteksi di sana gagal, tidak ada lapisan lain. Itu temuan untuk backlog.

### 2.3 Diamond: tiga event dan satu activity thread

Catatan event ini menjawab butir kedua dan menjadi bahan pivot. Perhatikan nilai keyakinan per feature dan label Type 1 atau Type 2 pada infrastructure.

```
Event 1  phase=Delivery  ts=2026-10-06 08:12  direction=Infrastructure-to-Victim
  Adversary      : tidak diketahui (keyakinan -)
  Capability     : dokumen .docm bermacro
  Infrastructure : pengirim tarif@mail-logistik[.]example (Type 2, kemungkinan akun dibobol)
  Victim         : persona=staf pengadaan; asset=mailbox
  Result         : sukses (email terkirim, dibuka)

Event 2  phase=C2  ts=2026-10-06 08:20 s.d. 10-08  direction=Victim-to-Infrastructure
  Capability     : implant beaconing HTTPS 60 detik
  Infrastructure : bad-logistics[.]example -> 203.0.113[.]50 (Type 1, keyakinan sedang)
  Victim         : asset=WS-PROC-07

Event 3  phase=Actions on Objectives  ts=2026-10-08 01:10  direction=Victim-to-Infrastructure
  Capability     : exfiltration lewat kanal C2
  Infrastructure : 203.0.113[.]50
  Result         : 1,2 GB keluar
Activity thread: E1 -> E2 -> E3 (adversary-victim sama, diurutkan phase)
```

**Pivot yang dilakukan (infrastructure-centered):** cari host lain yang me-resolve `bad-logistics[.]example` atau menghubungi 203.0.113[.]50. Hasil ilustrasi: satu host lagi di divisi keuangan, belum ada exfiltration. Pivot kedua (capability-centered): cari lampiran `.docm` lain dari pengirim yang sama; ditemukan tiga email ke staf pengadaan lain yang tidak dibuka. Pivot ketiga ke luar: riwayat registrasi domain menunjukkan domain didaftarkan sembilan hari sebelum Event 1, pola yang juga dilaporkan ISAC untuk satu perusahaan logistik lain. Itu kandidat activity group, dengan keyakinan rendah sampai ada bukti capability yang sama.

### 2.4 Pemetaan ATT&CK

Tabel ini menjawab butir ketiga. Kolom terakhir sengaja ada supaya detection engineer bisa membedakan pemetaan yang didukung log dari pemetaan yang masih dugaan.

| Perilaku | Tactic | Technique | Dasar bukti |
|---|---|---|---|
| Profil staf dikumpulkan dari media sosial | Reconnaissance | T1593.001 Search Open Websites/Domains: Social Media | Pesan "rekruter" (lemah, keyakinan rendah) |
| Domain didaftarkan sebelum serangan | Resource Development | T1583.001 Acquire Infrastructure: Domains | Data registrasi |
| Email berlampiran `.docm` | Initial Access | T1566.001 Phishing: Spearphishing Attachment | Log email gateway |
| Pengguna mengaktifkan macro | Execution | T1204.002 User Execution: Malicious File | EDR process tree |
| Run key baru | Persistence | T1547.001 Registry Run Keys / Startup Folder | EDR registry event |
| Beaconing HTTPS | Command and Control | T1071.001 Application Layer Protocol: Web Protocols | Log proxy |
| Data keluar lewat kanal C2 | Exfiltration | T1041 Exfiltration Over C2 Channel | Volume proxy ke IP yang sama |

Kolom "dasar bukti" sengaja ditulis. Tanpa kolom ini, pemetaan T1593.001 terlihat sama kuat dengan T1566.001, padahal yang pertama hanya dugaan.

### 2.5 Pyramid of Pain dan keputusan

Tabel ini menjawab butir keempat: setiap indikator LOGI-FICTA diberi tingkat, tindakan, dan umur pakai. Bandingkan kolom umur pakai dari baris teratas ke terbawah.

| Indikator | Tingkat | Tindakan | Umur pakai |
|---|---|---|---|
| Hash `Penawaran_Tarif_Q4.docm` | Hash | Blokir dan cari di mail store | Hari |
| 203.0.113[.]50 | IP | Blokir, lookup SIEM 30 hari | Minggu |
| bad-logistics[.]example | Domain | Blokir, pantau domain serupa | Minggu |
| Interval beacon 60 detik ke domain berumur kurang dari 30 hari | Network artifact | Analitik proxy | Bulan |
| Office membuat proses anak lalu menulis Run key | TTP | Rule EDR berbasis perilaku | Tahun |

**Keputusan:** blokir IOC atomik hari ini untuk containment, tetapi investasi detection engineering diarahkan ke dua baris terbawah karena keduanya tetap berlaku walau domain dan dokumen berganti.

## 3. Lab praktik

Lab memakai editor teks dan akses baca ke situs ATT&CK. Kampanye fiktif; jangan pakai data kerja; jangan menjalankan sampel atau tool apa pun.

1. **Kampanye sendiri.** Tulis kronologi fiktif berbasis identitas: login ke layanan email cloud dengan kredensial curian (T1078.004 Valid Accounts: Cloud Accounts), membuat aturan forward kotak masuk, lalu mengirim email penipuan pembayaran ke pelanggan.
2. **Kill Chain.** Petakan kronologi itu ke tujuh tahap. Catat tahap yang kosong atau dipaksakan, lalu bandingkan dengan tiga siklus Unified Kill Chain.
3. **Course of action matrix.** Isi kolom detect, deny, disrupt untuk setiap tahap. Tandai tahap yang hanya punya satu kontrol.
4. **Diamond.** Tulis minimal tiga event dengan meta-feature phase, direction, dan result, lalu susun activity thread-nya. Tulis dua pivot dan sebut pendekatan pivotnya.
5. **ATT&CK.** Petakan setiap perilaku ke tactic dan technique v19.2 dengan kolom dasar bukti. Untuk perilaku yang buktinya lemah, berhenti di tactic.
6. **Pyramid of Pain.** Daftar semua indikator, urutkan, dan tulis umur pakai serta tindakan untuk masing-masing.
7. **Satu paragraf keputusan.** Tulis rekomendasi untuk detection engineer yang memakai keempat framework.

**Hasil yang sebaiknya tersimpan:**

- Kronologi kampanye fiktif berbasis identitas.
- Tabel Kill Chain dengan course of action matrix dan catatan tahap yang tidak cocok.
- Tiga event Diamond, activity thread, dan dua pivot.
- Tabel ATT&CK v19.2 dengan kolom dasar bukti.
- Tabel Pyramid of Pain dengan tindakan dan umur pakai.
- Satu paragraf rekomendasi.

**Variasi tantangan:** ambil satu laporan kampanye publik yang menyebut lebih dari sepuluh technique ATT&CK. Tandai mana yang didukung bukti di laporan itu dan mana yang hanya disebut. Laporan sering mencantumkan ID tanpa bukti per teknik.

## 4. Troubleshooting

Tabel ini memuat gejala yang paling sering muncul saat memakai keempat framework; cari gejala yang mirip dengan yang kamu alami di lab.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Kampanye tidak muat Kill Chain | Ancaman berbasis identitas atau cloud | Pakai ATT&CK dan Diamond; catat tahap yang kosong |
| Pemetaan ATT&CK terasa menebak | Bukti kurang untuk sub-technique | Petakan ke tactic atau technique induk dulu |
| Pivot Diamond buntu | Satu feature minim data | Pivot dari feature lain; isi meta-feature direction dan timestamp |
| Dua tim berbeda ID untuk perilaku sama | Satu technique di beberapa tactic | Sepakati tactic berdasarkan tujuan aksi di kasus itu |
| Rule lama merujuk Defense Evasion | Dibuat sebelum v19 | Remap ke Stealth (TA0005) atau Defense Impairment (TA0112) |
| Fokus hanya IOC atomik | Pyramid of Pain dilupakan | Tambah baris artifact dan TTP pada setiap analisis |

## 5. Kesalahan umum dan jebakan

- Memaksa semua serangan ke Kill Chain. Model linear kurang cocok untuk serangan identitas dan cloud.
- Menebak sub-technique tanpa bukti. Lebih baik technique induk yang benar daripada sub-technique yang salah.
- Mengira Type 2 infrastructure milik penyerang. Server yang dibobol dan akun email curian milik korban lain; memblokir atau melaporkannya butuh kehati-hatian.
- Berhenti di IOC atomik. Pyramid of Pain menunjukkan nilai jangka panjang ada di TTP.
- Pemetaan sebagai hasil akhir. Framework melayani keputusan.
- Mengabaikan versi ATT&CK. Nama dan ID tactic berubah di v19; sebut versi di setiap pemetaan.

## 6. Catatan terkini

Bagian ini menampung versi dan perkembangan framework. Berguna saat membaca dokumen lama dan menyebut versi di pemetaan.

- ATT&CK v19 (April 2026) memecah Defense Evasion menjadi Stealth (TA0005) dan Defense Impairment (TA0112), sehingga Enterprise kini punya 15 tactic. Versi yang berlaku saat catatan ini ditulis adalah v19.2 (Agustus 2026), yang memperbarui Groups dan Software [S3].
- Pyramid of Pain pertama kali diterbitkan Bianco pada 2013 dan direvisi pada 2014. Label tingkat di bagian 1.5 mengikuti gambar revisi 2014 [S4].
- Kill Chain tetap dipakai untuk menjelaskan tahap ke manajemen dan untuk course of action matrix, tetapi pemetaan perilaku di industri bersandar pada ATT&CK.
- Unified Kill Chain menggabungkan keduanya dan berguna untuk serangan yang banyak bergerak di dalam jaringan [S5].

## 7. Cheat sheet

```
KILL CHAIN  Recon -> Weaponize -> Deliver -> Exploit -> Install -> C2 -> Actions
            CoA matrix: detect | deny | disrupt | degrade | deceive | destroy per tahap
            indikator: atomic | computed | behavioral ; batas: linear, malware-sentris
UKC         18 fase dalam 3 siklus: In | Through | Out
DIAMOND     adversary(operator/customer) - capability - infrastructure(Type1/Type2/provider) - victim(persona/asset)
            meta: timestamp, phase, result, direction, methodology, resources ; confidence per feature
            sumbu: social-political, technology ; event -> activity thread -> activity group
            pivot: victim-, capability-, infrastructure-, adversary-centered
ATT&CK      tactic (kenapa) > technique Txxxx > sub Txxxx.yyy > procedure ; v19.2 = 15 tactic
            TA0005 Stealth + TA0112 Defense Impairment (dulu Defense Evasion)
PYRAMID     hash(trivial) < IP(easy) < domain(simple) < artifact(annoying) < tools(challenging) < TTP(tough)
PILIH       putus tahap=Kill Chain | pivot=Diamond | perilaku+deteksi=ATT&CK | prioritas indikator=Pyramid
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Seorang analyst menyerahkan tabel ATT&CK LOGI-FICTA ke Lead SOC dan berkata, "Semua perilaku sudah dipetakan, jadi analisisnya selesai." Benarkah?

<details><summary>Jawaban</summary>

Belum. Pemetaan melayani PIR dan keputusan, bukan hasil akhir; pertanyaan yang harus dijawab adalah pemetaan ini mengubah keputusan apa, misalnya rule mana yang dibangun atau kontrol mana yang ditambah. Tabel juga harus punya kolom dasar bukti. Tanpa kolom itu, T1593.001 (hanya didukung pesan "rekruter", keyakinan rendah) terlihat sama kuat dengan T1566.001 yang didukung log email gateway. Lihat bagian 1.8 dan 2.4.

</details>

**2. Skenario keputusan.** Di kasus lain, satu-satunya bukti adalah "ada eksekusi dari lampiran email"; jenis file dan tautannya belum diketahui. Bagaimana kamu memetakannya ke ATT&CK?

- A. Langsung ke `T1204.002` User Execution: Malicious File, karena itu sub-technique yang paling sering muncul untuk lampiran.
- B. Ke tactic Execution dan technique `T1204` dulu, lalu pilih sub-technique setelah ada bukti jenis file atau tautannya.
- C. Jangan dipetakan sama sekali sampai semua bukti lengkap.

<details><summary>Jawaban</summary>

B. Technique induk yang benar lebih baik daripada sub-technique yang salah, dan ketidakpastiannya dinyatakan dengan bahasa keyakinan. A keliru karena memaksa data ambigu ke ID yang terlalu spesifik, sehingga menghasilkan kepastian palsu. C keliru karena pemetaan ke tactic atau technique induk tetap berguna untuk coverage dan komunikasi; yang dihindari adalah spesifisitas tanpa bukti, bukan pemetaan itu sendiri. Lihat bagian 1.8, 4, dan 5.

</details>

**3. Pertanyaan jebakan.** Di Event 1 LOGI-FICTA, pengirim `tarif@mail-logistik[.]example` dicatat sebagai infrastructure. Seorang rekan mengusulkan, "Laporkan domain itu ke ISAC sebagai infrastruktur milik aktor LOGI-FICTA." Tepatkah?

<details><summary>Jawaban</summary>

Tidak tepat. Pengirim itu dicatat sebagai Type 2, yaitu infrastruktur perantara yang kemungkinan akun dibobol, bukan Type 1 milik penyerang. Type 2 menyamarkan asal penyerang, dan pemiliknya bisa jadi korban lain. Memblokir atau melaporkannya butuh kehati-hatian dan harus menyebut statusnya sebagai kemungkinan akun dibobol. Lihat bagian 1.2, 2.3, dan 5.

</details>

**4. Skenario keputusan.** Kamu menganalisis kampanye berbasis identitas: login ke layanan email cloud dengan kredensial curian, membuat aturan forward kotak masuk, lalu mengirim email penipuan pembayaran ke pelanggan. Framework apa yang memimpin analisis?

- A. Kill Chain untuk seluruh analisis, karena tujuh tahapnya mencakup semua jenis intrusi.
- B. ATT&CK dan Diamond sebagai tulang punggung, dengan catatan tahap Kill Chain mana yang kosong atau dipaksakan.
- C. Pyramid of Pain saja, karena yang penting adalah indikator mana yang diblokir.

<details><summary>Jawaban</summary>

B. Serangan berbasis identitas melewati weaponization, exploitation, dan installation dalam arti klasik, jadi Kill Chain yang linear dan malware-sentris akan menyisakan tahap kosong. ATT&CK menangkap perilakunya (misalnya T1078.004) dan Diamond menstrukturkan event serta pivotnya. A keliru karena memaksa semua serangan ke Kill Chain adalah kesalahan umum; Unified Kill Chain dibuat untuk mencoba menutup celah itu. C keliru karena Pyramid of Pain hanya memprioritaskan indikator dan tidak menjelaskan urutan, hubungan event, atau perilaku. Lihat bagian 1.1, 1.6, 4, dan 5.

</details>

**5. Jelaskan ulang.** Direktur operasional PT LC bertanya kenapa tim memblokir IP dan domain LOGI-FICTA hari ini, tetapi anggaran detection engineering justru diminta untuk rule perilaku. Jelaskan dalam tiga kalimat memakai Pyramid of Pain.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "IP, domain, dan hash dokumen LOGI-FICTA kami blokir hari ini karena akurat dan cepat untuk containment, tetapi penyerang bisa menggantinya dalam hitungan hari atau minggu dengan biaya murah. Perilaku seperti Office yang membuat proses anak lalu menulis Run key jauh lebih mahal untuk diubah penyerang, karena mereka harus mengubah cara beroperasi. Jadi blokir indikator adalah tindakan hari ini, sedangkan rule perilaku adalah investasi yang tetap berlaku walau domain dan dokumennya berganti."

Kesalahan yang sering muncul:
- Menyimpulkan bahwa hash dan IP tidak berguna. Keduanya tetap berguna untuk scoping dan blokir cepat; masalahnya umur pakainya pendek.
- Membalik urutan piramida, misalnya menyebut domain lebih sulit diganti daripada tools.
- Menjelaskan dengan label Bianco saja (trivial, tough) tanpa menyebut biaya bagi penyerang.

</details>

**6. Pertanyaan jebakan.** ISAC melaporkan bahwa domain di kasus perusahaan logistik lain juga didaftarkan sekitar sembilan hari sebelum serangan. Lead SOC menyimpulkan, "Berarti pelakunya sama dengan LOGI-FICTA." Benarkah?

<details><summary>Jawaban</summary>

Belum bisa disimpulkan. Kesamaan pola registrasi domain menjadikan kedua kasus kandidat activity group, dengan keyakinan rendah sampai ada bukti capability yang sama. Clustering yang lebih tahan false flag bersandar pada pola TTP yang konsisten lintas kampanye, bukan pada IOC atomik atau satu kemiripan infrastruktur. Jawaban yang tepat untuk butir kelima pesan Lead SOC adalah penilaian dengan bahasa keyakinan, bukan atribusi pasti. Lihat bagian 1.3, 1.7, dan 2.3.

</details>

**7. Interview question (English).** "How would you use frameworks like the Kill Chain, the Diamond Model, and ATT&CK when analysing an intrusion?"

<details><summary>Sample answer</summary>

"I use them together because each answers a different question. The Kill Chain, with a course of action matrix, shows where we could have broken the intrusion and which stages have no second layer of control. The Diamond Model structures each event into adversary, capability, infrastructure, and victim, which tells me where to pivot to find other affected hosts or related activity. ATT&CK gives me standard technique IDs so detection engineers can check coverage, and I always add an evidence column and stop at the parent technique when the evidence is weak. Finally, I use the Pyramid of Pain to separate quick blocks on hashes and domains from longer-term behavioural detections. I also state the ATT&CK version, because v19 split Defense Evasion into Stealth and Defense Impairment."

What makes this answer strong: it matches each framework to a specific question, shows discipline about evidence and specificity in mapping, links the analysis to concrete decisions, and shows awareness of version changes.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Hutchins, Cloppert, Amin: Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains (Lockheed Martin) | https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/documents/cyber/LM-White-Paper-Intel-Driven-Defense.pdf | primer | 2011; diakses 2026-10-10 | Tinggi. Tahap, jenis indikator, course of action matrix |
| S2 | Caltagirone, Pendergast, Betz: The Diamond Model of Intrusion Analysis | https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf | primer | 2013; diakses 2026-10-10 | Tinggi. Aksioma, feature, meta-feature, pivot, activity thread dan group |
| S3 | MITRE ATT&CK: Enterprise Tactics dan halaman Updates | https://attack.mitre.org/tactics/enterprise/ | primer | v19.2, Agustus 2026; diakses 2026-10-10 | Tinggi. Daftar 15 tactic dan ID; catatan rilis v19 ada di https://attack.mitre.org/resources/updates/ |
| S4 | David Bianco: The Pyramid of Pain | https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html | primer | 2013, revisi 2014-01; diakses 2026-10-10 | Tinggi |
| S5 | Paul Pols: The Unified Kill Chain | https://www.unifiedkillchain.com/ | primer (whitepaper penulis) | diakses 2026-10-10 | Sedang-tinggi. Jumlah fase dan pembagian tiga siklus |

**Catatan sumber:** contoh tactic untuk technique tertentu (misalnya T1218.005 di Stealth) diambil dari halaman technique ATT&CK v19.2 dan bisa berubah di rilis berikutnya. Label Bianco untuk tiap tingkat diambil dari gambar piramida revisi 2014.
