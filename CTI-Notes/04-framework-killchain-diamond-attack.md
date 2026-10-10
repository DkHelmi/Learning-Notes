---
day: 04
title: 'Framework CTI: Cyber Kill Chain, Diamond Model, ATT&CK, dan Pyramid of Pain'
researched_on: 2026-10-10
versions_checked: 'MITRE ATT&CK Enterprise v19.2 (Agustus 2026; 15 tactic); Hutchins, Cloppert, Amin (2011); Diamond Model (Caltagirone, Pendergast, Betz, 2013); Pyramid of Pain (Bianco, 2013, revisi 2014); Unified Kill Chain (Pols)'
---

# Day 04: Framework CTI

Cakupan: empat kerangka untuk menstrukturkan analisis ancaman (Cyber Kill Chain dengan course of action matrix, Diamond Model dengan pivot dan activity thread, ATT&CK v19, dan Pyramid of Pain) diterapkan bersama pada satu kampanye fiktif.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan tujuh tahap Cyber Kill Chain, course of action matrix, dan keterbatasan model ini untuk ancaman modern.
- memakai Diamond Model untuk menstrukturkan satu event, mengisi meta-feature, menyusun activity thread, dan melakukan pivot.
- menjelaskan struktur ATT&CK (tactic, technique, sub-technique, procedure), daftar 15 tactic Enterprise v19, dan perubahan Defense Evasion.
- mengurutkan indikator dengan Pyramid of Pain dan menjelaskan kenapa deteksi berbasis perilaku lebih tahan lama.
- memilih framework yang cocok untuk pertanyaan tertentu dan memadukan keempatnya dalam satu analisis kampanye.

## 2. Konteks singkat

Analisis ancaman tanpa kerangka cenderung berantakan: daftar IOC tanpa struktur, atau cerita panjang yang sulit dibandingkan dengan kasus lain. Framework memberi bahasa bersama sehingga analis bisa membandingkan kampanye, berbicara dengan detection engineer dan IR, dan memprioritaskan tindakan. Tidak ada satu framework yang terbaik; masing-masing menjawab pertanyaan berbeda.

Kill Chain memberi urutan tahap serangan dan tempat memutusnya. Diamond menstrukturkan satu event dan hubungan antar event. ATT&CK mengatalogkan perilaku dengan ID yang dipakai seluruh industri, termasuk di rule deteksi dan hipotesis hunting. Pyramid of Pain memprioritaskan indikator menurut biaya yang ditimbulkan bagi penyerang.

**Kapan dipakai:** menulis analisis insiden atau kampanye, memetakan laporan publik ke kemampuan deteksi sendiri, berkomunikasi lintas tim, dan memprioritaskan backlog deteksi.

**Kapan terbatas:** framework adalah alat bantu. Memaksa data ke kategori yang tidak cocok menghasilkan kepastian palsu.

## 3. Konsep inti

### 3.1 Cyber Kill Chain

Model ini berasal dari paper Hutchins, Cloppert, dan Amin dari Lockheed Martin (2011). Gagasannya: intrusi terarah adalah rangkaian tahap, dan penyerang harus berhasil di setiap tahap, sedangkan pembela cukup memutus satu tahap [S1].

| Tahap | Isi menurut paper | Contoh yang terlihat oleh pembela |
|---|---|---|
| Reconnaissance | Riset dan pemilihan target: alamat email, relasi sosial, teknologi yang dipakai | Kunjungan crawler ke halaman karier; jarang terlihat |
| Weaponization | Menggabungkan malware dengan exploit atau dokumen menjadi muatan yang siap kirim | Tidak terlihat langsung; dipelajari dari sampel |
| Delivery | Pengiriman: email, situs, media USB | Log email gateway, proxy |
| Exploitation | Kode penyerang berjalan: celah aplikasi, fitur OS, atau pengguna yang membuka file | Process creation dari aplikasi Office |
| Installation | Akses bertahan dipasang di host | Run key, service, scheduled task baru |
| Command and Control | Kanal kendali dari luar | Beaconing DNS atau HTTP berkala |
| Actions on Objectives | Tujuan dicapai: mencuri data, merusak, atau pindah ke target lain | Volume upload besar, akses file massal |

Paper ini juga memperkenalkan dua alat yang sering dilupakan. Pertama, tiga jenis indikator: atomic (tidak bisa dipecah lagi, misalnya IP atau email), computed (diturunkan dari data, misalnya hash atau regex), dan behavioral (gabungan keduanya yang menggambarkan perilaku) [S1]. Kedua, course of action matrix yang memasangkan setiap tahap dengan enam aksi dari doktrin operasi informasi: detect, deny, disrupt, degrade, deceive, destroy. Contohnya: NIDS bisa detect pada tahap delivery, patch bisa deny exploitation, dan DEP bisa disrupt exploitation [S1]. Matriks ini berguna untuk menilai lapisan kontrol: tahap mana yang punya lebih dari satu aksi, dan tahap mana yang kosong.

Keterbatasannya nyata. Model ini linear dan berpusat pada malware yang masuk lewat perimeter. Serangan berbasis identitas (login dengan kredensial curian ke layanan cloud) melewati weaponization, exploitation, dan installation dalam arti klasik. Aktivitas setelah masuk, seperti lateral movement dan eskalasi hak, terjepit di antara installation dan actions. Unified Kill Chain dari Paul Pols mencoba menutup celah ini dengan menggabungkan Kill Chain dan ATT&CK menjadi 18 fase dalam tiga siklus: masuk (In), bergerak di dalam jaringan (Through), dan mengambil hasil (Out) [S5].

### 3.2 Diamond Model

Diamond Model (Caltagirone, Pendergast, Betz, 2013) dimulai dari satu aksioma: setiap intrusion event terdiri atas adversary yang memakai capability melalui infrastructure terhadap victim untuk menghasilkan suatu result [S2].

| Core feature | Arti | Catatan dari paper |
|---|---|---|
| Adversary | Pelaku | Dibedakan antara operator (yang melakukan intrusi) dan customer (yang mendapat manfaat); bisa orang yang sama atau berbeda |
| Capability | Alat dan teknik | Termasuk malware, exploit, dan teknik manual; C2 diperlakukan sebagai bagian capability |
| Infrastructure | Struktur komunikasi untuk mengirim capability, mengendalikan, dan mengambil hasil | Type 1 milik penyerang; Type 2 milik perantara (host yang dibobol, domain staging, akun email curian) yang menyamarkan asal; service provider seperti ISP dan registrar |
| Victim | Target | Dibedakan antara victim persona (orang, organisasi) dan victim asset (host, akun, email) |

Event juga punya meta-feature: timestamp mulai dan selesai, phase, result, direction, methodology, dan resources [S2]. Direction berguna untuk menentukan tempat deteksi; nilainya antara lain victim-to-infrastructure, infrastructure-to-victim, dan bidirectional. Setiap feature punya nilai keyakinan sendiri, sehingga kamu bisa menulis "infrastructure: diketahui, keyakinan tinggi; adversary: cluster TA-FICTA, keyakinan rendah". Model ini juga menambah dua sumbu: social-political (hubungan dan kebutuhan antara adversary dan victim, yang menjelaskan motif) dan technology (hubungan antara capability dan infrastructure).

Kekuatan utama Diamond adalah pivot. Dari satu feature yang diketahui, cari event lain yang berbagi feature itu. Paper menyebut beberapa pendekatan yang berpusat pada satu feature: victim-centered (mulai dari korban, cari capability dan infrastructure yang menyentuhnya), capability-centered (mulai dari sampel malware, cari korban lain dan infrastrukturnya), infrastructure-centered (mulai dari domain atau IP), dan adversary-centered [S2].

Event yang berurutan untuk pasangan adversary dan victim yang sama disusun menjadi activity thread, diurutkan menurut phase. Thread yang berbagi ciri digabung menjadi activity group, yaitu dasar clustering aktor yang dibahas di Day 03 [S2].

### 3.3 MITRE ATT&CK

ATT&CK adalah basis pengetahuan perilaku adversary yang dibangun dari observasi nyata [S3].

- **Tactic:** tujuan taktis, "kenapa" sebuah aksi dilakukan.
- **Technique:** cara mencapai tactic, "bagaimana". ID berbentuk `T1566`.
- **Sub-technique:** varian lebih spesifik, misalnya `T1566.001` Spearphishing Attachment.
- **Procedure:** implementasi konkret oleh aktor atau malware tertentu, dicatat sebagai contoh di halaman technique.

Satu technique bisa berada di beberapa tactic. Contohnya `T1078` Valid Accounts muncul di Initial Access, Persistence, Privilege Escalation, dan Stealth, karena akun sah bisa dipakai untuk semua tujuan itu [S3].

Tactic Enterprise di ATT&CK v19.2:

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

Selain matriks, ATT&CK punya halaman Groups (aktor yang dilacak, dengan nama alias dari berbagai vendor), Software (malware dan tool), dan Campaigns (rangkaian aktivitas dengan rentang waktu). Di CTI, ATT&CK dipakai untuk mendeskripsikan perilaku aktor dengan kosakata standar, memetakan deteksi yang dimiliki, membandingkan kelompok, dan menyusun prioritas deteksi berbasis aktor yang relevan.

### 3.4 Pyramid of Pain

Pyramid of Pain (David Bianco, 2013, direvisi 2014) mengurutkan jenis indikator menurut seberapa menyakitkan bagi penyerang bila indikator itu ditolak [S4].

| Tingkat (bawah ke atas) | Contoh | Label Bianco | Kenapa |
|---|---|---|---|
| Hash values | SHA256 file | Trivial | Ubah satu byte, hash berubah total |
| IP addresses | 203.0.113[.]50 | Easy | Ganti server atau lewat proxy |
| Domain names | bad-logistics[.]example | Simple | Perlu registrasi, tetapi murah dan cepat |
| Network/host artifacts | Pola URI, User-Agent khas, nama service, registry key | Annoying | Penyerang harus mengubah konfigurasi atau mengompilasi ulang alat |
| Tools | Backdoor, credential dumper, builder dokumen | Challenging | Harus mencari atau membuat alat baru dan belajar memakainya |
| TTPs | Cara kerja: misalnya mencuri kredensial dari memori lalu bergerak dengan RDP | Tough | Harus mengubah cara beroperasi |

Pelajarannya bukan "jangan pakai hash". Hash dan IP tetap berguna untuk scoping insiden dan blokir cepat, dan sangat akurat. Masalahnya umurnya pendek. Investasi deteksi jangka panjang sebaiknya diarahkan ke tingkat atas, dan di situlah ATT&CK berguna sebagai kosakata.

### 3.5 Kapan memakai yang mana

| Pertanyaan | Framework |
|---|---|
| Di tahap mana serangan ini bisa diputus, dan kontrol apa yang kosong? | Kill Chain dan course of action matrix |
| Bagaimana event ini terhubung dengan event lain, dan ke mana pivot berikutnya? | Diamond |
| Perilaku apa yang dipakai aktor, dan apakah kita bisa mendeteksinya? | ATT&CK |
| Indikator mana yang layak dijadikan deteksi jangka panjang? | Pyramid of Pain |
| Apakah dua insiden kemungkinan pelaku yang sama? | Diamond activity group ditambah pola TTP ATT&CK |

### 3.6 Memadukan framework

Framework saling melengkapi. Setiap event Diamond punya meta-feature phase yang bisa diisi tahap Kill Chain. Capability di event dipetakan ke technique ATT&CK. Indikator yang terkumpul diurutkan dengan Pyramid of Pain. Hasilnya analisis berlapis: urutan tahap, struktur dan pivot, perilaku terstandar, dan prioritas tindakan. Pola TTP yang konsisten lintas kampanye juga menjadi dasar clustering yang lebih tahan false flag daripada IOC atomik.

### 3.7 Framework sebagai alat, bukan tujuan

Bahaya umum adalah memperlakukan pemetaan sebagai hasil akhir: "kita sudah petakan ke ATT&CK, selesai." Pemetaan melayani PIR dan keputusan (Day 02). Tanya selalu: pemetaan ini mengubah keputusan apa? Bahaya kedua adalah memaksa data ambigu ke ID yang terlalu spesifik. Bila bukti hanya menunjukkan "ada eksekusi dari lampiran", petakan ke tactic Execution dan technique `T1204` dulu; sub-technique dipilih setelah ada bukti jenis file atau tautannya. Nyatakan ketidakpastiannya seperti di Day 03.

## 4. Contoh artefak intelijen

Kampanye fiktif "LOGI-FICTA" berlabel ilustrasi. Korbannya PT Logistik Contoh. IOC di-defang. Teknik dirujuk ke ATT&CK v19.2.

### 4.1 Kronologi singkat kasus

Dua minggu sebelum insiden, beberapa staf pengadaan menerima pesan LinkedIn dari "rekruter". Pada 2026-10-06, staf pengadaan menerima email berlampiran `Penawaran_Tarif_Q4.docm`. Satu staf membuka dan mengaktifkan macro. Host-nya kemudian membuat Run key baru dan mulai menghubungi `bad-logistics[.]example` (203.0.113[.]50) setiap 60 detik lewat HTTPS. Dua hari kemudian, sekitar 1,2 GB dokumen kontrak dikirim keluar lewat kanal yang sama.

### 4.2 Kill Chain dan course of action matrix

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

### 4.3 Diamond: tiga event dan satu activity thread

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

### 4.4 Pemetaan ATT&CK

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

### 4.5 Pyramid of Pain dan keputusan

| Indikator | Tingkat | Tindakan | Umur pakai |
|---|---|---|---|
| Hash `Penawaran_Tarif_Q4.docm` | Hash | Blokir dan cari di mail store | Hari |
| 203.0.113[.]50 | IP | Blokir, lookup SIEM 30 hari | Minggu |
| bad-logistics[.]example | Domain | Blokir, pantau domain serupa | Minggu |
| Interval beacon 60 detik ke domain berumur kurang dari 30 hari | Network artifact | Analitik proxy | Bulan |
| Office membuat proses anak lalu menulis Run key | TTP | Rule EDR berbasis perilaku | Tahun |

**Keputusan:** blokir IOC atomik hari ini untuk containment, tetapi investasi detection engineering diarahkan ke dua baris terbawah karena keduanya tetap berlaku walau domain dan dokumen berganti.

## 5. Lab praktik

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

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Kampanye tidak muat Kill Chain | Ancaman berbasis identitas atau cloud | Pakai ATT&CK dan Diamond; catat tahap yang kosong |
| Pemetaan ATT&CK terasa menebak | Bukti kurang untuk sub-technique | Petakan ke tactic atau technique induk dulu |
| Pivot Diamond buntu | Satu feature minim data | Pivot dari feature lain; isi meta-feature direction dan timestamp |
| Dua tim berbeda ID untuk perilaku sama | Satu technique di beberapa tactic | Sepakati tactic berdasarkan tujuan aksi di kasus itu |
| Rule lama merujuk Defense Evasion | Dibuat sebelum v19 | Remap ke Stealth (TA0005) atau Defense Impairment (TA0112) |
| Fokus hanya IOC atomik | Pyramid of Pain dilupakan | Tambah baris artifact dan TTP pada setiap analisis |

## 7. Kesalahan umum dan jebakan

- Memaksa semua serangan ke Kill Chain. Model linear kurang cocok untuk serangan identitas dan cloud.
- Menebak sub-technique tanpa bukti. Lebih baik technique induk yang benar daripada sub-technique yang salah.
- Mengira Type 2 infrastructure milik penyerang. Server yang dibobol dan akun email curian milik korban lain; memblokir atau melaporkannya butuh kehati-hatian.
- Berhenti di IOC atomik. Pyramid of Pain menunjukkan nilai jangka panjang ada di TTP.
- Pemetaan sebagai hasil akhir. Framework melayani keputusan.
- Mengabaikan versi ATT&CK. Nama dan ID tactic berubah di v19; sebut versi di setiap pemetaan.

## 8. Catatan terkini

- ATT&CK v19 (April 2026) memecah Defense Evasion menjadi Stealth (TA0005) dan Defense Impairment (TA0112), sehingga Enterprise kini punya 15 tactic. Versi yang berlaku saat catatan ini ditulis adalah v19.2 (Agustus 2026), yang memperbarui Groups dan Software [S3].
- Kill Chain tetap dipakai untuk menjelaskan tahap ke manajemen dan untuk course of action matrix, tetapi pemetaan perilaku di industri bersandar pada ATT&CK.
- Unified Kill Chain menggabungkan keduanya dan berguna untuk serangan yang banyak bergerak di dalam jaringan [S5].
- Day 05 masuk ke sumber pengumpulan dan batas etika serta legalnya.

## 9. Cheat sheet

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

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Hutchins, Cloppert, Amin: Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains (Lockheed Martin) | https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/documents/cyber/LM-White-Paper-Intel-Driven-Defense.pdf | primer | 2011; diakses 2026-10-10 | Tinggi. Tahap, jenis indikator, course of action matrix |
| S2 | Caltagirone, Pendergast, Betz: The Diamond Model of Intrusion Analysis | https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf | primer | 2013; diakses 2026-10-10 | Tinggi. Aksioma, feature, meta-feature, pivot, activity thread dan group |
| S3 | MITRE ATT&CK: Enterprise Tactics dan halaman Updates | https://attack.mitre.org/tactics/enterprise/ | primer | v19.2, Agustus 2026; diakses 2026-10-10 | Tinggi. Daftar 15 tactic dan ID; catatan rilis v19 ada di https://attack.mitre.org/resources/updates/ |
| S4 | David Bianco: The Pyramid of Pain | https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html | primer | 2013, revisi 2014-01; diakses 2026-10-10 | Tinggi |
| S5 | Paul Pols: The Unified Kill Chain | https://www.unifiedkillchain.com/ | primer (whitepaper penulis) | diakses 2026-10-10 | Sedang-tinggi. Jumlah fase dan pembagian tiga siklus |

**Catatan sumber:** contoh tactic untuk technique tertentu (misalnya T1218.005 di Stealth) diambil dari halaman technique ATT&CK v19.2 dan bisa berubah di rilis berikutnya. Label Bianco untuk tiap tingkat diambil dari gambar piramida revisi 2014.
