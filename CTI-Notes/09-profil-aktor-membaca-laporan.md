---
day: 09
title: 'Profil aktor dan membaca laporan intelijen: penamaan, atribusi berhati-hati, dan ekstraksi yang bisa dipakai'
researched_on: 2026-10-10
versions_checked: 'MITRE ATT&CK Groups (v19); kolaborasi pemetaan nama aktor CrowdStrike-Microsoft (diumumkan 2 Juni 2025); rujukan Day 02-04, 07-08'
---

# Day 09: Profil aktor dan membaca laporan

Cakupan: cara membaca skema penamaan aktor antar vendor, membedakan threat actor, intrusion set, cluster sementara, dan campaign, menyusun profil aktor yang melayani keputusan, membaca laporan intelijen secara kritis, mengekstrak perilaku ke ATT&CK sampai tingkat procedure, dan menulis pernyataan atribusi yang jujur tentang keyakinannya.

## Ide inti

Profil aktor hanya berguna bila mengubah sesuatu di pertahanan: rule baru, hunt, prioritas patching, atau keputusan bahwa aktor itu tidak perlu diikuti. Bahan bakunya adalah laporan vendor, advisori pemerintah, dan blog peneliti, yang kualitasnya sangat beragam. Satu entitas bisa punya sepuluh nama, sebagian laporan juga berfungsi sebagai materi pemasaran, dan kesimpulan sering ditulis seperti fakta. Karena itu analis tidak menelan laporan mentah. Ia membaca seperti menilai sumber (Day 03 dan 05), memisahkan observasi dari penilaian, mencocokkan nama dengan hati-hati, lalu mengekstrak perilaku sampai tingkat yang bisa dicari di log. Hasil akhirnya profil yang menjawab PIR, bukan ensiklopedia aktor.

Kamu sudah melakukan versi kecil pekerjaan ini di SOC dan DFIR. Saat satu sampel diunggah ke layanan multi-scanner, tiap engine antivirus memberi nama family yang berbeda, dan kamu tidak menyimpulkan apa pun hanya karena satu engine memakai nama yang terdengar menakutkan. Saat EDR memberi label "Critical", kamu tetap membuka process tree dan membaca apa yang benar-benar terjadi, lalu menulis catatan kasus berisi temuan, dugaan beserta confidence-nya, dan tindakan berikutnya. Membaca laporan aktor adalah pekerjaan yang sama: nama vendor adalah label, isi laporan adalah telemetri orang lain, dan profil adalah catatan kasusmu.

```
Laporan vendor A, vendor B, advisori
  -> baca kritis       : penerbit, fakta vs penilaian, keyakinan, metodologi
  -> rekonsiliasi nama : satu nama utama + alias bersumber ("tumpang tindih sebagian")
  -> profil (Diamond)  : adversary | capability | infrastructure | victim
  -> ekstraksi         : tactic -> technique -> procedure -> telemetri -> cakupan deteksi
  -> keputusan         : rule baru | hunt | patch | "tidak relevan"
Atribusi: penilaian berkeyakinan, jarang dibutuhkan untuk langkah di atas.
```

Situasi yang dipakai sepanjang Day ini: dalam satu minggu Oktober 2026, tim CTI PT Logistik Contoh (PT LC) menerima dua laporan vendor (fiktif) tentang ransomware yang menyasar perusahaan logistik. Vendor A menyebut pelakunya "FICTA SPIDER", vendor B menyebut "Storm-0000". Keduanya relevan untuk PIR-2026-003 (Day 02) tentang kelompok ransomware yang menyasar logistik Asia Tenggara. CISO meneruskan kedua laporan dengan pesan:

> "Dua laporan, dua nama. Tolong jawab sebelum Jumat: (1) ini kelompok yang sama atau bukan? (2) Laporan vendor A bilang kelompok ini 'jelas didukung negara'. Perlu saya bawa ke direksi? (3) Buatkan satu profil yang bisa dipakai tim, jangan ensiklopedia."

Detection engineer menambahkan di thread yang sama:

> "(4) Tolong jangan cuma kasih nama technique. Saya perlu tahu apa yang dicari di log. (5) Ujungnya, apa yang harus kita ubah?"

Pertanyaan 1 dijawab di bagian 1.1, 1.2, dan 2.3. Pertanyaan 2 menyangkut membaca kritis dan atribusi (bagian 1.5, 1.7, dan 2.2). Pertanyaan 3 adalah anatomi profil (bagian 1.3, 1.4, dan 2.1). Pertanyaan 4 adalah ekstraksi procedure (bagian 1.6 dan 2.4). Pertanyaan 5 adalah penutup setiap profil (bagian 1.8).

**Kapan relevan:** menjawab PIR tentang ancaman yang relevan, menyiapkan deteksi dan hunt berbasis TTP aktor, dan memberi konteks pada insiden yang sedang ditangani.
**Kapan bukan jawaban:** saat yang dicari adalah kepastian siapa pelakunya. Atribusi jarang pasti, aktor berevolusi, dan laporan bisa usang atau bias. Untuk banyak keputusan defensif, memahami TTP sudah cukup tanpa tahu siapa di baliknya.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Tabel ini memuat istilah CTI yang muncul di Day ini. Kolom padanan memakai analogi SOC yang sama di semua Day CTI. Istilah dari Day sebelumnya (PIR, Diamond Model, Pyramid of Pain, kode Admiralty, circular reporting, STIX) tidak diulang.

| Istilah | Arti singkat | Padanan di SOC |
|---|---|---|
| Alias | Nama berbeda dari vendor berbeda untuk aktivitas yang dinilai berasal dari pihak yang sama | Nama family berbeda dari tiap engine antivirus untuk sampel yang sama |
| Threat actor | Individu atau organisasi nyata di balik aktivitas | Pelaku nyata di balik insiden, yang di IR jarang bisa dipastikan |
| Intrusion set | Kumpulan aktivitas dan sumber daya bersama yang dinilai berasal dari satu pihak | Satu case yang menggabungkan banyak alert karena dinilai berasal dari satu pelaku |
| Cluster sementara | Pengelompokan aktivitas yang belum cukup bukti untuk digabung ke intrusion set yang dikenal | Alert yang dikelompokkan sementara sebelum jelas termasuk case mana |
| Campaign | Rangkaian aktivitas dengan tujuan tertentu dalam rentang waktu tertentu | Satu gelombang phishing dengan tema dan periode yang sama |
| Profil aktor | Ringkasan terstruktur tentang aktor atau cluster yang melayani keputusan | Catatan kasus: temuan, dugaan beserta confidence, tindakan berikutnya |
| Procedure | Cara spesifik satu aktor menjalankan sebuah technique | Logika rule yang menyebut field dan nilai, bukan hanya nama kategori use case |
| Atribusi | Penilaian tentang siapa di balik aktivitas | Menyimpulkan siapa pelaku dari artefak insiden |
| False flag | Artefak yang sengaja ditanam untuk menyesatkan atribusi | Artefak palsu yang mengecoh analis, seperti timestamp yang dimanipulasi |
| Celah intelijen | Hal yang belum diketahui tentang aktor | Celah visibilitas: pertanyaan yang belum bisa dijawab karena datanya belum ada |
| Bahasa keyakinan | Cara menyatakan seberapa yakin sebuah penilaian | Confidence pada alert |

### 1.1 Skema penamaan antar vendor

Pertanyaan pertama CISO ("dua laporan, dua nama") muncul karena setiap vendor intelijen besar menamai aktor dengan skema sendiri, sehingga satu entitas bisa punya banyak nama [S1]. Mengenali skemanya membantu kamu menebak jenis dan asal yang diklaim vendor dari namanya saja.

Tabel berikut merangkum skema vendor besar. Baca kolom "Arti pola" untuk mengetahui apa yang sebenarnya diklaim vendor lewat sebuah nama.

| Pemberi nama | Pola | Arti pola |
|---|---|---|
| MITRE ATT&CK | `G####` untuk group, `C####` untuk campaign, `S####` untuk software | ID netral; halaman group mencantumkan "associated groups" dari vendor lain |
| Microsoft | Nama cuaca: Typhoon, Blizzard, Sandstorm, Sleet, Tempest; `Storm-####` | Typhoon dikaitkan dengan Tiongkok, Blizzard dengan Rusia, Sandstorm dengan Iran, Sleet dengan Korea Utara, Tempest untuk motif finansial; `Storm-####` untuk cluster yang masih berkembang |
| CrowdStrike | Nama hewan: PANDA, BEAR, KITTEN, CHOLLIMA, SPIDER | Hewan menandai negara asal yang dinilai (PANDA Tiongkok, BEAR Rusia, KITTEN Iran, CHOLLIMA Korea Utara); SPIDER untuk kriminal |
| Mandiant (Google) | `APT##`, `FIN##`, `UNC####` | APT untuk aktor negara, FIN untuk finansial, UNC untuk cluster yang belum dikategorikan |
| Proofpoint | `TA###` | Penomoran aktor yang dilacak, terutama dari sisi email |

Tabel ini menjelaskan skema, bukan klaim atribusi. Nama seperti "X Bear" hanya berarti vendor itu menilai asalnya Rusia; penilaian itu bisa berbeda dengan vendor lain. Di situasi PT LC, nama fiktif "FICTA SPIDER" mengikuti pola nama kriminal, dan "Storm-0000" mengikuti pola cluster yang masih berkembang. Kedua nama itu sendiri belum menjawab apakah entitasnya sama.

Cara menangani alias:

- Pakai satu nama utama di catatan tim, dan tulis alias beserta sumbernya. Banyak tim memakai nama ATT&CK sebagai titik acuan karena netral dan mencantumkan alias.
- Sumber pemetaan yang bisa dipakai: halaman group ATT&CK (bagian "associated groups"), galaxy threat actor di MISP yang memuat sinonim (Day 08), dan pemetaan bersama CrowdStrike-Microsoft [S6]. Tanggal pengumuman dan cakupannya ada di bagian 6.
- Alias jarang setara satu banding satu. Vendor A bisa menggabungkan aktivitas yang oleh vendor B dipecah menjadi dua cluster. Tulis "tumpang tindih sebagian" bila itu yang terjadi.

### 1.2 Threat actor, intrusion set, cluster, dan campaign

Saat CISO bertanya "kelompok yang sama atau bukan", ia sebenarnya bertanya tentang tingkat entitas: apakah yang dilacak vendor A dan B adalah pihak nyata yang sama, kumpulan aktivitas yang sama, atau dua pengelompokan sementara yang kebetulan mirip. Istilah berikut mengikuti STIX (Day 07) dan dipakai luas [S4].

Tabel ini membedakan empat tingkat entitas. Perhatikan kolom "Contoh pernyataan" untuk melihat seberapa kuat klaim yang dibuat tiap tingkat.

| Istilah | Arti | Contoh pernyataan |
|---|---|---|
| Threat actor | Individu atau organisasi nyata di balik aktivitas | "Unit X dari organisasi Y" (jarang bisa dibuktikan publik) |
| Intrusion set | Kumpulan aktivitas dan sumber daya bersama yang dinilai berasal dari satu pihak | "ISET-FICTA" |
| Cluster sementara | Pengelompokan aktivitas yang belum cukup bukti untuk digabung ke intrusion set yang dikenal | `UNC####`, `Storm-####`, `TA###` |
| Campaign | Rangkaian aktivitas dengan tujuan tertentu dalam rentang waktu tertentu | "Kampanye phishing logistik Oktober 2026" |

Kebanyakan profil di pekerjaan sebenarnya adalah profil intrusion set atau cluster, bukan profil aktor nyata. Mengakui itu adalah bentuk kejujuran analitis: "aktivitas cluster X" lebih tepat daripada menyebut negara tanpa bukti cukup. Profil yang disusun tim PT LC di bagian 2.1 juga profil intrusion set, dengan nama internal ISET-FICTA.

Cluster bisa bergabung (merge) ke intrusion set lain ketika bukti terkumpul, atau dipecah ketika ternyata berisi dua operator. Profil yang kamu tulis harus mencatat nama lama agar riwayatnya bisa dilacak.

### 1.3 Diamond Model sebagai kerangka profil

Permintaan CISO "jangan ensiklopedia" adalah peringatan terhadap profil yang hanya berisi daftar malware dan IOC. Diamond Model (Day 04) memberi empat sudut yang membuat profil seimbang [S3]:

- **Adversary:** siapa (atau cluster apa), motivasi yang dinilai.
- **Capability:** malware, alat, dan teknik.
- **Infrastructure:** domain, IP, hosting, pola registrasi.
- **Victim:** sektor, geografi, ukuran, teknologi yang ditargetkan.

Profil yang hanya punya sudut capability dan infrastructure tidak membantu menilai relevansi. Sudut victim yang menjawab "apakah organisasi seperti kita ada di dalam pola sasarannya". Untuk PT LC, sudut victim inilah yang menentukan apakah ISET-FICTA layak diprofilkan sama sekali.

### 1.4 Anatomi profil aktor

Setelah keempat sudut terisi, profil perlu bentuk tetap supaya setiap analis di tim menulis hal yang sama dengan cara yang sama. Tabel berikut adalah template yang dipakai di bagian 2.1. Perhatikan kolom "Catatan kualitas": di sanalah bedanya profil yang dipakai dan profil yang hanya disimpan.

| Bagian | Isi | Catatan kualitas |
|---|---|---|
| Identitas | Nama utama, alias per vendor, ID ATT&CK bila ada | Sebut sumber tiap alias |
| Ringkasan | Tiga kalimat: siapa, apa yang dilakukan, kenapa penting bagi kita | Tulis terakhir |
| Motivasi | Finansial, spionase, hacktivism, sabotase | Selalu penilaian, beri keyakinan |
| Target | Sektor, geografi, jenis organisasi, teknologi | Pisahkan korban teramati dari target yang dinilai |
| TTP | Perilaku per tactic, dipetakan ke ATT&CK | Bagian paling tahan lama |
| Tooling | Malware dan alat, termasuk alat sah yang disalahgunakan | Bedakan milik sendiri vs umum |
| Infrastruktur | Pola, bukan hanya daftar nilai | Paling cepat usang |
| Linimasa | Kapan pertama dan terakhir teramati, perubahan penting | Menunjukkan apakah aktor masih aktif |
| Keyakinan dan sumber | Keyakinan per klaim, daftar sumber dengan Admiralty | Day 03 |
| Relevansi dan tindakan | Kenapa penting, apa yang harus berubah | Menjawab PIR |
| Celah intelijen | Apa yang belum diketahui | Menjadi kebutuhan collection berikutnya |

Profil yang baik menekankan TTP di atas IOC, sesuai Pyramid of Pain (Day 04). Infrastruktur sebaiknya ditulis sebagai pola ("domain bertema logistik, didaftarkan kurang dari seminggu sebelum dipakai, hosting VPS"), karena pola bertahan lebih lama daripada nilainya.

### 1.5 Membaca laporan secara kritis

Klaim "jelas didukung negara" di laporan vendor A adalah alasan untuk membaca laporan itu dengan daftar periksa, bukan alasan untuk langsung meneruskannya ke direksi. Pakai daftar periksa yang sama untuk setiap laporan agar penilaianmu konsisten.

Tabel berikut berisi delapan pertanyaan yang dipakai di bagian 2.2 dan Lab. Untuk setiap baris, cari tanda di kolom kanan lebih dulu, karena tanda waspada lebih cepat terlihat daripada tanda baik.

| Pertanyaan | Tanda baik | Tanda waspada |
|---|---|---|
| Siapa penerbitnya dan apa kepentingannya? | Lembaga pemerintah, vendor dengan rekam jejak, peneliti independen | Laporan yang berujung ajakan membeli produk |
| Apakah fakta dan penilaian dipisah? | Kalimat "kami mengamati" terpisah dari "kami menilai" | Kesimpulan ditulis seperti fakta |
| Apakah keyakinan dinyatakan? | Bahasa estimatif dengan tingkat keyakinan | Kata "jelas", "pasti", "paling canggih" |
| Apakah bukti atribusi dijelaskan? | Menyebut jenis bukti (overlap infrastruktur, kode, TTP) | Atribusi tanpa dasar |
| Kapan datanya dikumpulkan? | Rentang waktu jelas | Hanya tanggal terbit |
| Sumbernya independen? | Data telemetri atau investigasi sendiri | Mengutip laporan lain tanpa data baru (circular reporting, Day 05) |
| Seberapa luas pengamatannya? | Menyebut jumlah kasus atau sumber telemetri | Generalisasi dari satu insiden |
| Bisa ditindaklanjuti? | Perilaku rinci, procedure, IOC dengan konteks | Hanya narasi umum |

Bagian metodologi dan keterbatasan sering diletakkan di akhir atau di catatan kaki. Baca bagian itu lebih dulu, karena di situlah penulis mengatakan seberapa jauh kesimpulannya bisa dipercaya.

Laporan yang mengandung pemasaran tetap bisa berguna. Yang perlu kamu lakukan adalah memisahkan bumbunya dan mengambil observasinya. Laporan vendor A di bagian 2.2 adalah contohnya: satu kalimat pemasaran dan satu penilaian tanpa dasar, tetapi observasi procedure-nya tetap bernilai.

### 1.6 Mengekstrak ke ATT&CK pada tingkat procedure

Permintaan detection engineer ("jangan cuma kasih nama technique") adalah permintaan untuk procedure. Ekstraksi yang baik bekerja di tiga tingkat:

- **Tactic:** tujuan (misalnya Persistence).
- **Technique atau sub-technique:** cara umum (misalnya T1053.005 Scheduled Task).
- **Procedure:** cara spesifik aktor ini, misalnya "membuat scheduled task bernama mirip layanan pembaruan yang menjalankan skrip dari folder ProgramData setiap 30 menit".

Procedure adalah tingkat yang paling berguna untuk deteksi dan hunt. Mengetahui bahwa aktor memakai T1053.005 hanya mempersempit ruang pencarian; procedure memberi tahu field mana dan nilai apa yang dicari.

Langkah ekstraksi:

1. Tandai setiap kalimat yang menjelaskan perilaku.
2. Tulis perilakunya dengan kata-katamu sebagai procedure.
3. Petakan ke technique ATT&CK. Bila ragu antara dua technique, tulis keduanya dan alasannya.
4. Catat telemetri yang dibutuhkan untuk melihatnya (log proses, log autentikasi, DNS, proxy, email).
5. Bandingkan dengan deteksi yang sudah ada: tercakup, sebagian, atau tidak.

Kesalahan umum di langkah 3 adalah memetakan berdasarkan kata kunci. Kalimat "aktor memakai PowerShell" belum tentu T1059.001 sebagai teknik utama; bisa saja PowerShell hanya dipakai untuk mengunduh berkas, yang lebih tepat dipetakan ke Ingress Tool Transfer (T1105). Petakan berdasarkan tujuan perilakunya. Hasil kelima langkah ini untuk ISET-FICTA ada di bagian 2.4.

### 1.7 Atribusi berhati-hati

Pertanyaan kedua CISO pada dasarnya bertanya: seberapa kuat klaim "didukung negara" itu? Menerapkan Day 03 pada aktor:

- Atribusi adalah penilaian berkeyakinan, bukan fakta. Nyatakan keyakinan dan jenis buktinya.
- Bukti punya bobot berbeda. Overlap infrastruktur bisa kebetulan (hosting murah dipakai banyak pihak). Kode yang sama bisa berarti alat yang dijual atau bocor. Pola TTP yang konsisten lintas banyak kampanye lebih kuat, dan kombinasi beberapa jenis bukti independen lebih kuat lagi.
- False flag mungkin terjadi: string bahasa tertentu, zona waktu kompilasi, atau alat milik aktor lain bisa sengaja ditanam.
- Bedakan "aktivitas ini mirip aktor X" (observasi kemiripan) dari "aktor X melakukan ini" (klaim atribusi).

Untuk pertahanan, atribusi negara jarang dibutuhkan. Yang dibutuhkan adalah TTP dan relevansi. Atribusi penuh adalah ranah dengan taruhan tinggi dan bukti yang jarang lengkap di sumber publik. Bagi CISO PT LC, jawaban yang jujur adalah menjelaskan dasar klaim itu dan bobotnya, bukan meneruskan klaimnya.

### 1.8 Dari profil ke keputusan

Pertanyaan terakhir detection engineer ("apa yang harus kita ubah?") adalah pertanyaan penutup setiap profil. Profil aktor melayani keputusan (PIR, Day 02), jadi profil selesai ketika jawabannya tertulis.

Jawabannya bisa berupa deteksi baru untuk TTP tertentu, prioritas patching teknologi yang ditargetkan, hunt untuk jejak aktor, atau keputusan bahwa aktor ini tidak relevan sehingga tidak perlu diikuti. Keputusan terakhir itu juga bernilai, karena membebaskan waktu tim.

## 2. Contoh artefak intelijen

Semua contoh di bagian ini fiktif dan berupa keluaran ilustrasi; skema penamaan nyata hanya disebut sebagai pola, dan IOC di-defang. Keempat artefak di bawah adalah jawaban tim CTI PT LC untuk pesan CISO dan detection engineer di bagian Ide inti.

### 2.1 Profil aktor (fiktif)

Ini jawaban untuk pertanyaan ketiga CISO: satu profil yang mengikuti template bagian 1.4, dengan keyakinan per klaim dan tindakan di akhir.

```
Profil: ISET-FICTA (intrusion set, fiktif)        TLP:AMBER     Versi: 2026-10-10
Alias  : "FICTA SPIDER" (vendor A, fiktif) ; Storm-0000 (vendor B, fiktif, tumpang tindih sebagian)
         ATT&CK Group: tidak ada
Ringkasan: Cluster kriminal yang menjalankan ransomware ransomware-lab terhadap perusahaan
  logistik di Asia Tenggara sejak Juli 2026. Akses awal lewat lampiran email bertema faktur.
  Relevan karena sektor dan wilayah kita cocok dengan pola korban.
Motivasi : finansial [penilaian, keyakinan tinggi: catatan tebusan, data leak site]
Target   : teramati 6 korban logistik (ID, MY, TH) ; dinilai menargetkan logistik regional
           [keyakinan sedang]
TTP (procedure -> ATT&CK):
  lampiran .js dalam zip bertema faktur            -> T1566.001
  wscript menjalankan .js dari folder Downloads    -> T1204.002, T1059.007
  scheduled task "UpdateSvcCheck" tiap 30 menit    -> T1053.005
  HTTPS ke domain baru dengan interval tetap       -> T1071.001
  arsip data diunggah ke layanan cloud storage     -> T1567.002
  enkripsi berkas di share jaringan                -> T1486
Tooling  : ransomware-lab (milik sendiri, keyakinan sedang) ; rclone (alat sah disalahgunakan)
Infrastruktur (pola): domain bertema logistik/faktur, didaftarkan < 7 hari sebelum dipakai,
  VPS di ASN hosting murah, sertifikat self-signed [keyakinan sedang]
Linimasa : pertama teramati 2026-07 ; terakhir 2026-10-07 ; aktif
Sumber   : laporan vendor A (B2), laporan vendor B (B3), advisori CERT fiktif (A2)
Celah    : vektor akses awal selain email belum diketahui ; hubungan dengan Storm-0000 belum jelas
Tindakan : deteksi T1053.005 dengan nama task mirip layanan ; hunt T1567.002 ; blok .js dalam zip
```

**Cara membaca hasil:** motivasi diberi keyakinan tinggi karena didukung dua jenis bukti (catatan tebusan dan data leak site), sedangkan target yang dinilai hanya keyakinan sedang karena berasal dari enam korban. Baris Celah langsung menjadi kebutuhan collection berikutnya.

### 2.2 Laporan dibaca kritis (anotasi)

Ini jawaban untuk pertanyaan kedua CISO. Kutipan di bawah berasal dari laporan vendor A (fiktif), dianotasi dengan daftar periksa bagian 1.5.

```
Kutipan laporan fiktif                                   Anotasi
"Aktor paling canggih yang pernah kami lihat..."         [PEMASARAN] abaikan
"Kami mengamati 6 korban antara Juli dan Oktober 2026"   [FAKTA] cakupan jelas, sampel kecil
"Email membawa zip berisi berkas .js bertema faktur"     [FAKTA] procedure, bisa diekstrak
"Kami menilai dengan keyakinan sedang aktor ini          [PENILAIAN] dasar disebut: overlap
  berkaitan dengan Storm-0000 berdasarkan overlap          infrastruktur saja -> bobot lemah;
  infrastruktur"                                           catat sebagai kemungkinan
"Kelompok ini jelas didukung negara"                     [PENILAIAN tanpa dasar] bertentangan
                                                           dengan bukti tebusan; tolak
"IOC: bad-logistics[.]example, 203.0.113[.]50"           [IOC] beri konteks + expiry (Day 07)
Terbit 2026-10-08, data sampai 2026-10-05                [kemutakhiran] baik
Mengutip blog vendor C untuk data korban                 [cek circular reporting]
Bagian metodologi: telemetri EDR 6 pelanggan             [independensi] data sendiri, baik
```

**Cara membaca hasil:** klaim "jelas didukung negara" ditolak karena tidak disertai bukti dan bertentangan dengan bukti motif finansial di laporan yang sama. Jawaban untuk CISO: klaim itu tidak dibawa ke direksi, tetapi observasi procedure di laporan yang sama tetap dipakai.

### 2.3 Rekonsiliasi dua laporan

Ini jawaban untuk pertanyaan pertama CISO. Kedua laporan dibandingkan per sudut, lalu keputusannya ditulis dengan keyakinan.

```
Laporan A (vendor A): "FICTA SPIDER", ransomware-lab, logistik, akses via phishing .js
Laporan B (vendor B): "Storm-0000", ransomware-lab dan satu ransomware lain, logistik dan
                      ritel, akses via phishing .js dan kredensial VPN
Analisis:
  Sama   : ransomware-lab, procedure phishing .js, sektor logistik
  Beda   : B juga melihat ritel, akses VPN, dan ransomware kedua
  Penilaian: kemungkinan B melacak himpunan aktivitas lebih luas yang mencakup A,
             misalnya karena beberapa afiliasi memakai ransomware-lab [keyakinan rendah]
  Keputusan: profil pakai nama ISET-FICTA ; catat Storm-0000 sebagai "tumpang tindih
             sebagian" ; TTP akses VPN masuk profil dengan label "dari laporan B saja"
```

**Cara membaca hasil:** jawaban untuk "kelompok yang sama atau bukan" adalah "tumpang tindih sebagian, keyakinan rendah", bukan ya atau tidak. TTP akses VPN tetap relevan untuk PT LC yang banyak vendornya masuk lewat VPN, sehingga dicatat walaupun hanya dari satu laporan.

### 2.4 Ekstraksi ke tindakan

Ini jawaban untuk pertanyaan keempat dan kelima: setiap procedure dari profil dipasangkan dengan telemetri dan cakupan deteksi PT LC saat ini.

```
Procedure                           Telemetri           Deteksi saat ini   Tindakan
lampiran .js dalam zip               gateway email       sebagian (zip lolos) blokir .js dalam arsip
wscript dari Downloads               log proses          tidak ada          rule baru
scheduled task nama mirip layanan    log task/proses     ada (generik)      tuning: nama + jadwal
HTTPS interval tetap ke domain baru  proxy, DNS          tidak ada          hunt beaconing
unggah arsip ke cloud storage        proxy               tidak ada          hunt volume keluar
Keputusan (PIR-2026-003): dua rule baru dan dua hunt dalam 30 hari.
```

**Cara membaca hasil:** baris dengan deteksi "tidak ada" tetapi telemetri tersedia adalah kandidat rule atau hunt paling cepat. Keputusan di baris terakhir adalah jawaban untuk "apa yang harus kita ubah".

## 3. Lab praktik

**Prasyarat:** editor teks dan akses baca ke satu laporan CTI publik yang sah, misalnya advisori lembaga pemerintah atau blog riset vendor yang memuat rincian perilaku [S2]. Jangan mengarang fakta tentang aktor nyata. Skenario tambahan dibuat fiktif.

1. **Template.** Buat template profil dari tabel bagian 1.4.
2. **Daftar periksa.** Nilai laporan yang kamu pilih dengan delapan pertanyaan di bagian 1.5. Beri nilai baik, cukup, atau lemah untuk masing-masing.
3. **Anotasi.** Ambil minimal sepuluh kalimat dari laporan dan beri label fakta, penilaian, pemasaran, atau IOC seperti bagian 2.2.
4. **Penamaan.** Catat nama aktor di laporan, cari aliasnya di halaman group ATT&CK atau galaxy MISP, lalu tulis nama utama yang kamu pakai beserta sumber setiap alias.
5. **Ekstraksi procedure.** Ekstrak minimal lima procedure, petakan ke technique ATT&CK, catat telemetri yang dibutuhkan, dan nilai cakupan deteksi lab-mu.
6. **Atribusi.** Tulis satu paragraf pernyataan atribusi atau clustering: jenis bukti, bobotnya, kemungkinan false flag, dan tingkat keyakinan.
7. **Keputusan.** Tulis satu keputusan pertahanan yang dihasilkan profil untuk PIR fiktif.

**Hasil yang sebaiknya tersimpan:**

- Template profil yang bisa dipakai ulang.
- Penilaian laporan dengan delapan pertanyaan.
- Anotasi sepuluh kalimat.
- Tabel alias dengan sumber.
- Tabel ekstraksi procedure ke ATT&CK beserta telemetri dan cakupan.
- Pernyataan atribusi dengan keyakinan.
- Satu keputusan pertahanan.

**Variasi tantangan:** tulis dua laporan fiktif pendek tentang aktivitas serupa dengan nama dan atribusi berbeda, lalu rekonsiliasi seperti bagian 2.3. Tentukan apakah entitasnya sama, berbeda, atau tidak bisa dipastikan, dan dengan keyakinan apa.

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Nama aktor simpang siur | Skema vendor berbeda | Satu nama utama, alias dengan sumber, ID ATT&CK sebagai acuan |
| Dua nama dianggap sama padahal cakupannya beda | Alias diperlakukan satu banding satu | Tulis "tumpang tindih sebagian" dan perbedaannya |
| Profil cepat usang | Berpusat pada IOC dan nilai infrastruktur | Tekankan TTP dan pola infrastruktur |
| Pemetaan ATT&CK diperdebatkan | Dipetakan dari kata kunci | Petakan dari tujuan perilaku; tulis alasan |
| Deteksi dari profil tidak bisa dibuat | Ekstraksi berhenti di tingkat technique | Turunkan ke procedure dan telemetri |
| Atribusi terasa dipaksakan | Satu jenis bukti, satu sumber | Clustering, keyakinan rendah, sebut alternatif |
| Profil tidak dipakai | Tidak terikat keputusan | Tambah bagian relevansi dan tindakan |

## 5. Kesalahan umum dan jebakan

- **Menelan laporan mentah.** Pisahkan fakta, penilaian, dan pemasaran; baca metodologi lebih dulu.
- **Menyamakan alias tanpa dasar.** Cakupan cluster antar vendor jarang identik.
- **Profil berpusat IOC.** IOC rapuh; tekankan TTP dan pola.
- **Ekstraksi berhenti di nama technique.** Deteksi butuh procedure.
- **Atribusi dari satu jenis bukti.** Overlap infrastruktur atau kode saja tidak cukup kuat.
- **Profil tanpa relevansi.** Profil melayani PIR; akhiri dengan tindakan atau keputusan untuk tidak mengikuti aktor itu.

## 6. Catatan terkini

Bagian ini menampung tanggal dan perkembangan penamaan aktor. Berguna saat mengutip sumber, tetapi tidak mengubah cara menyusun profil.

- Penamaan aktor tetap tidak seragam. CrowdStrike dan Microsoft mengumumkan pemetaan nama bersama pada 2 Juni 2025 yang memetakan alias tanpa memaksakan satu standar penamaan, dan membuka kontribusi vendor lain. Saat diumumkan, pemetaan itu sudah menyelaraskan lebih dari 80 alias [S6]. Apakah vendor lain sudah bergabung perlu dicek.
- ATT&CK Groups (v19) memberi titik acuan untuk sebagian aktor dan mencantumkan alias, tetapi tidak semua cluster tercakup [S1].
- Penamaan cluster sementara (`UNC`, `Storm-`, `TA`) sebelum atribusi penuh makin umum, dan profil perlu mencatat riwayat merge atau rename.

## 7. Cheat sheet

```
SKEMA       ATT&CK G####/C####/S#### | MS cuaca: Typhoon CN, Blizzard RU, Sandstorm IR, Sleet KP, Tempest $, Storm-#### |
            CS hewan: PANDA CN, BEAR RU, KITTEN IR, CHOLLIMA KP, SPIDER kriminal | Mandiant APT/FIN/UNC | Proofpoint TA###
ALIAS       satu nama utama + alias bersumber ; "tumpang tindih sebagian" bila cakupan beda
ISTILAH     threat actor (pihak nyata) | intrusion set (aktivitas satu pihak) | cluster sementara | campaign (tujuan+waktu)
DIAMOND     adversary | capability | infrastructure | victim (victim = relevansi)
PROFIL      identitas | ringkasan | motivasi | target | TTP | tooling | infra (POLA) | linimasa | keyakinan+sumber | tindakan | celah
BACA        penerbit+kepentingan | fakta vs penilaian | keyakinan | dasar atribusi | waktu data | independensi | luas sampel | actionable
EKSTRAK     tactic -> technique -> PROCEDURE -> telemetri -> cakupan deteksi ; petakan dari TUJUAN, bukan kata kunci
ATRIBUSI    penilaian, bukan fakta ; bobot: TTP konsisten + bukti independen > overlap infra/kode ; false flag
KEPUTUSAN   apa yang berubah? deteksi | patch | hunt | atau "tidak relevan"
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Seorang rekan berkata, "FICTA SPIDER dan Storm-0000 cuma dua nama untuk kelompok yang sama. Vendor memang suka memberi nama sendiri, jadi gabungkan saja semua isinya ke satu profil." Benarkah?

<details><summary>Jawaban</summary>

Tidak sepenuhnya. Vendor memang memakai skema nama sendiri, tetapi alias jarang setara satu banding satu: satu vendor bisa menggabungkan aktivitas yang oleh vendor lain dipecah atau diperluas. Rekonsiliasi kedua laporan menunjukkan vendor B juga melihat ritel, akses VPN, dan ransomware kedua, sehingga penilaiannya "tumpang tindih sebagian" dengan keyakinan rendah. Profil memakai satu nama utama (ISET-FICTA), mencatat Storm-0000 sebagai tumpang tindih sebagian, dan memberi label pada TTP yang hanya berasal dari laporan B. Lihat bagian 1.1 dan 2.3.

</details>

**2. Skenario keputusan.** Sebuah laporan menulis: "Aktor memakai PowerShell untuk mengunduh berkas tahap kedua." Bagaimana kamu memetakannya ke ATT&CK?

- A. T1059.001 (PowerShell) sebagai teknik utama, karena kalimatnya menyebut PowerShell.
- B. Ingress Tool Transfer (T1105) sebagai teknik utama, karena tujuan perilakunya mengunduh berkas; bila ragu, tulis kedua technique beserta alasannya.
- C. Cukup tulis tactic-nya saja, karena technique sering diperdebatkan.

<details><summary>Jawaban</summary>

B. Pemetaan dilakukan berdasarkan tujuan perilaku, bukan kata kunci. Di kalimat ini PowerShell hanya alat untuk mengunduh berkas, sehingga Ingress Tool Transfer lebih tepat sebagai teknik utama, dan bila ragu kedua technique ditulis dengan alasannya. A keliru karena memetakan dari kata kunci, kesalahan paling umum di langkah pemetaan. C keliru karena tactic hanya menyebut tujuan umum; deteksi butuh technique dan, lebih baik lagi, procedure yang menyebut field dan nilai yang dicari. Lihat bagian 1.6.

</details>

**3. Pertanyaan jebakan.** Laporan vendor A memakai telemetri EDR dari enam pelanggannya sendiri. Karena datanya independen, kalimat "kelompok ini jelas didukung negara" di laporan itu cukup kuat untuk dibawa ke direksi. Benarkah?

<details><summary>Jawaban</summary>

Tidak. Data sendiri membuat observasi vendor A (enam korban, procedure phishing .js) layak dipakai, tetapi tidak otomatis menguatkan setiap penilaian di laporan yang sama. Kalimat itu adalah penilaian tanpa dasar: tidak menyebut jenis bukti, memakai kata "jelas" yang menjadi tanda waspada, dan bertentangan dengan bukti motif finansial (catatan tebusan, data leak site). Atribusi adalah penilaian berkeyakinan yang harus menyebut jenis buktinya, dan untuk pertahanan atribusi negara jarang dibutuhkan. Lihat bagian 1.5, 1.7, dan 2.2.

</details>

**4. Jelaskan ulang.** Jelaskan kepada CISO PT LC dalam tiga kalimat kenapa profil tim disebut "intrusion set ISET-FICTA" dan bukan "kelompok dari negara X".

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Yang bisa kita amati dari laporan vendor adalah kumpulan aktivitas dan sumber daya bersama, seperti ransomware yang sama, cara phishing yang sama, dan pola infrastruktur yang mirip, yang kita nilai berasal dari satu pihak; itu yang disebut intrusion set. Siapa individu atau organisasi nyata di baliknya hampir tidak pernah bisa dibuktikan dari sumber publik, dan klaim negara di salah satu laporan tidak disertai bukti. Untuk keputusan kita, yang penting adalah perilaku dan apakah kita masuk pola sasarannya, jadi nama intrusion set sudah cukup dan lebih jujur."

Kesalahan yang sering muncul:
- Menyamakan intrusion set dengan threat actor, seolah nama intrusion set sudah menunjuk pihak nyata.
- Menganggap nama vendor seperti "SPIDER" atau "BEAR" sebagai bukti atribusi, padahal nama itu hanya mencerminkan penilaian vendor tersebut.
- Lupa menyebut bahwa cluster bisa digabung atau dipecah, sehingga profil perlu mencatat riwayat nama.

</details>

**5. Skenario keputusan.** Detection engineer PT LC hanya punya waktu untuk satu masukan dari profil ISET-FICTA minggu ini. Mana yang paling berguna?

- A. Daftar lengkap domain dan IP dari kedua laporan.
- B. Procedure "scheduled task bernama mirip layanan pembaruan, berjalan tiap 30 menit", lengkap dengan telemetri yang dibutuhkan dan cakupan deteksi saat ini.
- C. Paragraf analisis atribusi negara dari laporan vendor A.

<details><summary>Jawaban</summary>

B. Procedure memberi tahu field dan nilai apa yang dicari, dan pasangan telemetri serta cakupan deteksi langsung menunjukkan apakah perlu rule baru atau tuning. A keliru karena IOC dan nilai infrastruktur paling cepat usang; profil yang baik menekankan TTP dan pola. C keliru karena atribusi negara jarang dibutuhkan untuk pertahanan, dan klaim di laporan vendor A sendiri tidak berdasar. Lihat bagian 1.4, 1.6, 1.7, dan 2.4.

</details>

**6. Pertanyaan jebakan.** Setelah menyusun profil sebuah aktor, analis menyimpulkan aktor itu tidak menyasar sektor atau teknologi PT LC dan merekomendasikan untuk tidak mengikutinya. Apakah profil itu gagal karena tidak menghasilkan rule atau hunt?

<details><summary>Jawaban</summary>

Tidak. Profil melayani keputusan, dan keputusan bahwa aktor tidak relevan sehingga tidak perlu diikuti juga bernilai karena membebaskan waktu tim. Yang membuat keputusan itu sah adalah sudut victim di Diamond Model: profil menjawab apakah organisasi seperti PT LC ada di dalam pola sasarannya. Profil yang gagal adalah profil yang tidak terikat keputusan sama sekali. Lihat bagian 1.3 dan 1.8.

</details>

**7. Interview question (English).** "You receive a vendor report about a threat actor targeting your sector. How do you turn it into something your team can use?"

<details><summary>Sample answer</summary>

"First I read it critically: who published it and why, whether observations are separated from assessments, whether confidence is stated, and when the data was collected. I read the methodology section early, and I set aside marketing language and attribution claims that come without evidence. Then I reconcile the actor's name with what we already track, keeping one primary name and listing aliases with sources, and I write 'partial overlap' when two vendors clearly track different scopes. The most valuable part is the behaviour, so I extract it down to procedure level, map it to ATT&CK by the purpose of the behaviour rather than keywords, note the telemetry needed, and compare it against our current detection coverage. The output is a profile that ends with a decision, such as new rules, a hunt, or a conclusion that the actor isn't relevant to us."

What makes this answer strong: it shows a repeatable reading method, treats attribution as an assessment rather than fact, prioritises procedures over indicators, and ends with a concrete defensive decision.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | MITRE ATT&CK Groups | https://attack.mitre.org/groups/ | primer | diakses 2026-10-09 | Tinggi. ID group, associated groups, technique per group |
| S2 | CISA Cybersecurity Advisories | https://www.cisa.gov/news-events/cybersecurity-advisories | primer | diakses 2026-10-09 | Tinggi. Contoh laporan aktor dengan pemetaan ATT&CK |
| S3 | Caltagirone, Pendergast, Betz: The Diamond Model of Intrusion Analysis (2013) | https://www.activeresponse.org/the-diamond-model/ | primer | diakses 2026-10-09 | Tinggi. Empat sudut peristiwa intrusi |
| S4 | OASIS STIX Version 2.1 (definisi threat actor, intrusion set, campaign) | https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html | primer | diakses 2026-10-10 | Tinggi. Definisi istilah |
| S5 | CTI-note Day 02-04, 07-08 | (lokal) | rujukan internal | 2026-10-09 | PIR, tradecraft, framework, IOC, TIP |
| S6 | CrowdStrike: CrowdStrike and Microsoft Collaborate to Harmonize Cyber Threat Attribution (Business Wire, 2 Juni 2025) | https://www.businesswire.com/news/home/20250602497894/en/CrowdStrike-Microsoft-Collaborate-Harmonize-Cyber-Threat-Attribution | sekunder (siaran pers vendor) | diakses 2026-10-10 | Sedang-tinggi. Pemetaan alias bersama, lebih dari 80 alias saat diumumkan |

**Catatan sumber:** arti pola nama vendor di bagian 1.1 berasal dari publikasi masing-masing vendor dan bisa berubah; cocokkan dengan halaman taksonomi vendor terbaru sebelum mengutipnya di produk. Status keanggotaan vendor lain di pemetaan nama bersama belum terkonfirmasi. Seluruh profil, laporan, dan nama di bagian 2 fiktif; ID technique ATT&CK di contoh dipakai untuk latihan pemetaan dan harus dicek ulang terhadap ATT&CK versi yang kamu pakai.
