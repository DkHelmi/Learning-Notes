---
day: 09
title: 'Profil aktor dan membaca laporan intelijen: penamaan, atribusi berhati-hati, dan ekstraksi yang bisa dipakai'
researched_on: 2026-10-10
versions_checked: 'MITRE ATT&CK Groups (v19); kolaborasi pemetaan nama aktor CrowdStrike-Microsoft (diumumkan 2 Juni 2025); rujukan Day 02-04, 07-08'
---

# Day 09: Profil aktor dan membaca laporan

Cakupan: cara membaca skema penamaan aktor antar vendor, menyusun profil aktor yang melayani keputusan, membaca laporan intelijen secara kritis, dan mengekstrak TTP serta IOC yang bisa langsung dipakai.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- mengenali skema penamaan aktor dari vendor besar dan memetakan alias tanpa menyamakan entitas secara gegabah.
- membedakan threat actor, intrusion set, cluster sementara, dan campaign.
- menyusun profil aktor yang berguna: motivasi, target, TTP, tooling, infrastruktur, keyakinan, dan relevansi.
- membaca laporan intelijen secara kritis dengan daftar periksa yang konsisten.
- mengekstrak perilaku dari laporan ke ATT&CK pada tingkat procedure, beserta IOC berkonteks.
- menulis pernyataan atribusi yang jujur tentang keyakinan dan dasar buktinya.

## 2. Konteks singkat

Intelijen operasional (Day 01) sering berpusat pada aktor: siapa yang menargetkan organisasi seperti kita, bagaimana cara kerja mereka, dan apa artinya bagi pertahanan. Sumber utamanya adalah laporan vendor, advisori pemerintah, dan blog peneliti. Masalahnya, kualitas laporan sangat beragam, satu entitas bisa punya sepuluh nama, dan sebagian laporan juga berfungsi sebagai materi pemasaran.

Analis yang baik tidak menelan laporan mentah. Ia membaca seperti menilai sumber (Day 03 dan 05), memisahkan observasi dari penilaian, lalu mengekstrak bagian yang bisa ditindaklanjuti. Hasil akhirnya adalah profil yang mengubah sesuatu di pertahanan, bukan ensiklopedia aktor.

**Kapan dipakai:** menjawab PIR tentang ancaman yang relevan, menyiapkan deteksi dan hunt berbasis TTP aktor, memberi konteks pada insiden yang sedang ditangani.

**Kapan terbatas:** atribusi jarang pasti, aktor berevolusi, dan laporan bisa usang atau bias. Untuk banyak keputusan defensif, memahami TTP sudah cukup tanpa tahu siapa di baliknya.

## 3. Konsep inti

### 3.1 Skema penamaan antar vendor

Setiap vendor intelijen besar menamai aktor dengan skema sendiri, sehingga satu entitas bisa punya banyak nama [S1]. Mengenali skemanya membantu kamu menebak jenis dan asal yang diklaim vendor dari namanya saja.

| Pemberi nama | Pola | Arti pola |
|---|---|---|
| MITRE ATT&CK | `G####` untuk group, `C####` untuk campaign, `S####` untuk software | ID netral; halaman group mencantumkan "associated groups" dari vendor lain |
| Microsoft | Nama cuaca: Typhoon, Blizzard, Sandstorm, Sleet, Tempest; `Storm-####` | Typhoon dikaitkan dengan Tiongkok, Blizzard dengan Rusia, Sandstorm dengan Iran, Sleet dengan Korea Utara, Tempest untuk motif finansial; `Storm-####` untuk cluster yang masih berkembang |
| CrowdStrike | Nama hewan: PANDA, BEAR, KITTEN, CHOLLIMA, SPIDER | Hewan menandai negara asal yang dinilai (PANDA Tiongkok, BEAR Rusia, KITTEN Iran, CHOLLIMA Korea Utara); SPIDER untuk kriminal |
| Mandiant (Google) | `APT##`, `FIN##`, `UNC####` | APT untuk aktor negara, FIN untuk finansial, UNC untuk cluster yang belum dikategorikan |
| Proofpoint | `TA###` | Penomoran aktor yang dilacak, terutama dari sisi email |

Tabel ini menjelaskan skema, bukan klaim atribusi. Nama seperti "X Bear" hanya berarti vendor itu menilai asalnya Rusia; penilaian itu bisa berbeda dengan vendor lain.

Cara menangani alias:

- Pakai satu nama utama di catatan tim, dan tulis alias beserta sumbernya. Banyak tim memakai nama ATT&CK sebagai titik acuan karena netral dan mencantumkan alias.
- Sumber pemetaan yang bisa dipakai: halaman group ATT&CK (bagian "associated groups"), galaxy threat actor di MISP yang memuat sinonim (Day 08), dan pemetaan bersama CrowdStrike-Microsoft yang diumumkan Juni 2025 dan saat diumumkan sudah menyelaraskan lebih dari 80 alias [S6].
- Alias jarang setara satu banding satu. Vendor A bisa menggabungkan aktivitas yang oleh vendor B dipecah menjadi dua cluster. Tulis "tumpang tindih sebagian" bila itu yang terjadi.

### 3.2 Threat actor, intrusion set, cluster, dan campaign

Istilah ini mengikuti STIX (Day 07) dan dipakai luas:

| Istilah | Arti | Contoh pernyataan |
|---|---|---|
| Threat actor | Individu atau organisasi nyata di balik aktivitas | "Unit X dari organisasi Y" (jarang bisa dibuktikan publik) |
| Intrusion set | Kumpulan aktivitas dan sumber daya bersama yang dinilai berasal dari satu pihak | "ISET-FICTA" |
| Cluster sementara | Pengelompokan aktivitas yang belum cukup bukti untuk digabung ke intrusion set yang dikenal | `UNC####`, `Storm-####`, `TA###` |
| Campaign | Rangkaian aktivitas dengan tujuan tertentu dalam rentang waktu tertentu | "Kampanye phishing logistik Oktober 2026" |

Kebanyakan profil di pekerjaan sebenarnya adalah profil intrusion set atau cluster, bukan profil aktor nyata. Mengakui itu adalah bentuk kejujuran analitis: "aktivitas cluster X" lebih tepat daripada menyebut negara tanpa bukti cukup.

Cluster bisa bergabung (merge) ke intrusion set lain ketika bukti terkumpul, atau dipecah ketika ternyata berisi dua operator. Profil yang kamu tulis harus mencatat nama lama agar riwayatnya bisa dilacak.

### 3.3 Diamond Model sebagai kerangka profil

Diamond Model (Day 04) memberi empat sudut yang membuat profil seimbang [S3]:

- **Adversary:** siapa (atau cluster apa), motivasi yang dinilai.
- **Capability:** malware, alat, dan teknik.
- **Infrastructure:** domain, IP, hosting, pola registrasi.
- **Victim:** sektor, geografi, ukuran, teknologi yang ditargetkan.

Profil yang hanya punya sudut capability dan infrastructure (daftar malware dan IOC) tidak membantu menilai relevansi. Sudut victim yang menjawab "apakah organisasi seperti kita ada di dalam pola sasarannya".

### 3.4 Anatomi profil aktor

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

### 3.5 Membaca laporan secara kritis

Pakai daftar periksa yang sama untuk setiap laporan agar penilaianmu konsisten:

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

Laporan yang mengandung pemasaran tetap bisa berguna. Yang perlu kamu lakukan adalah memisahkan bumbunya dan mengambil observasinya.

### 3.6 Mengekstrak ke ATT&CK pada tingkat procedure

Ekstraksi yang baik bekerja di tiga tingkat:

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

Kesalahan umum di langkah 3 adalah memetakan berdasarkan kata kunci. Kalimat "aktor memakai PowerShell" belum tentu T1059.001 sebagai teknik utama; bisa saja PowerShell hanya dipakai untuk mengunduh berkas, yang lebih tepat dipetakan ke Ingress Tool Transfer (T1105). Petakan berdasarkan tujuan perilakunya.

### 3.7 Atribusi berhati-hati

Menerapkan Day 03 pada aktor:

- Atribusi adalah penilaian berkeyakinan, bukan fakta. Nyatakan keyakinan dan jenis buktinya.
- Bukti punya bobot berbeda. Overlap infrastruktur bisa kebetulan (hosting murah dipakai banyak pihak). Kode yang sama bisa berarti alat yang dijual atau bocor. Pola TTP yang konsisten lintas banyak kampanye lebih kuat, dan kombinasi beberapa jenis bukti independen lebih kuat lagi.
- False flag mungkin terjadi: string bahasa tertentu, zona waktu kompilasi, atau alat milik aktor lain bisa sengaja ditanam.
- Bedakan "aktivitas ini mirip aktor X" (observasi kemiripan) dari "aktor X melakukan ini" (klaim atribusi).

Untuk pertahanan, atribusi negara jarang dibutuhkan. Yang dibutuhkan adalah TTP dan relevansi. Atribusi penuh adalah ranah dengan taruhan tinggi dan bukti yang jarang lengkap di sumber publik.

### 3.8 Dari profil ke keputusan

Profil aktor melayani keputusan (PIR, Day 02). Pertanyaan penutupnya selalu: apa yang berubah dari pertahanan kita karena profil ini? Jawabannya bisa berupa deteksi baru untuk TTP tertentu, prioritas patching teknologi yang ditargetkan, hunt untuk jejak aktor, atau keputusan bahwa aktor ini tidak relevan sehingga tidak perlu diikuti. Keputusan terakhir itu juga bernilai, karena membebaskan waktu tim.

## 4. Contoh artefak intelijen

Semua contoh di bagian ini fiktif dan berupa keluaran ilustrasi. Skema penamaan nyata hanya disebut sebagai pola. IOC di-defang.

### 4.1 Profil aktor (fiktif)

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

### 4.2 Laporan dibaca kritis (anotasi)

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

### 4.3 Rekonsiliasi dua laporan

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

### 4.4 Ekstraksi ke tindakan

```
Procedure                           Telemetri           Deteksi saat ini   Tindakan
lampiran .js dalam zip               gateway email       sebagian (zip lolos) blokir .js dalam arsip
wscript dari Downloads               log proses          tidak ada          rule baru
scheduled task nama mirip layanan    log task/proses     ada (generik)      tuning: nama + jadwal
HTTPS interval tetap ke domain baru  proxy, DNS          tidak ada          hunt beaconing
unggah arsip ke cloud storage        proxy               tidak ada          hunt volume keluar
Keputusan (PIR-02): dua rule baru dan dua hunt dalam 30 hari.
```

## 5. Lab praktik

**Prasyarat:** editor teks dan akses baca ke satu laporan CTI publik yang sah, misalnya advisori lembaga pemerintah atau blog riset vendor yang memuat rincian perilaku. Jangan mengarang fakta tentang aktor nyata. Skenario tambahan dibuat fiktif.

1. **Template.** Buat template profil dari tabel bagian 3.4.
2. **Daftar periksa.** Nilai laporan yang kamu pilih dengan delapan pertanyaan di bagian 3.5. Beri nilai baik, cukup, atau lemah untuk masing-masing.
3. **Anotasi.** Ambil minimal sepuluh kalimat dari laporan dan beri label fakta, penilaian, pemasaran, atau IOC seperti bagian 4.2.
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

**Variasi tantangan:** tulis dua laporan fiktif pendek tentang aktivitas serupa dengan nama dan atribusi berbeda, lalu rekonsiliasi seperti bagian 4.3. Tentukan apakah entitasnya sama, berbeda, atau tidak bisa dipastikan, dan dengan keyakinan apa.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Nama aktor simpang siur | Skema vendor berbeda | Satu nama utama, alias dengan sumber, ID ATT&CK sebagai acuan |
| Dua nama dianggap sama padahal cakupannya beda | Alias diperlakukan satu banding satu | Tulis "tumpang tindih sebagian" dan perbedaannya |
| Profil cepat usang | Berpusat pada IOC dan nilai infrastruktur | Tekankan TTP dan pola infrastruktur |
| Pemetaan ATT&CK diperdebatkan | Dipetakan dari kata kunci | Petakan dari tujuan perilaku; tulis alasan |
| Deteksi dari profil tidak bisa dibuat | Ekstraksi berhenti di tingkat technique | Turunkan ke procedure dan telemetri |
| Atribusi terasa dipaksakan | Satu jenis bukti, satu sumber | Clustering, keyakinan rendah, sebut alternatif |
| Profil tidak dipakai | Tidak terikat keputusan | Tambah bagian relevansi dan tindakan |

## 7. Kesalahan umum dan jebakan

- **Menelan laporan mentah.** Pisahkan fakta, penilaian, dan pemasaran; baca metodologi lebih dulu.
- **Menyamakan alias tanpa dasar.** Cakupan cluster antar vendor jarang identik.
- **Profil berpusat IOC.** IOC rapuh; tekankan TTP dan pola.
- **Ekstraksi berhenti di nama technique.** Deteksi butuh procedure.
- **Atribusi dari satu jenis bukti.** Overlap infrastruktur atau kode saja tidak cukup kuat.
- **Profil tanpa relevansi.** Profil melayani PIR; akhiri dengan tindakan atau keputusan untuk tidak mengikuti aktor itu.

## 8. Catatan terkini

- Penamaan aktor tetap tidak seragam. CrowdStrike dan Microsoft mengumumkan pemetaan nama bersama pada 2 Juni 2025 yang memetakan alias tanpa memaksakan satu standar penamaan, dan membuka kontribusi vendor lain [S6]. Apakah vendor lain sudah bergabung perlu dicek.
- ATT&CK Groups (v19) memberi titik acuan untuk sebagian aktor dan mencantumkan alias, tetapi tidak semua cluster tercakup [S1].
- Penamaan cluster sementara (`UNC`, `Storm-`, `TA`) sebelum atribusi penuh makin umum, dan profil perlu mencatat riwayat merge atau rename.

## 9. Cheat sheet

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

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | MITRE ATT&CK Groups | https://attack.mitre.org/groups/ | primer | diakses 2026-10-09 | Tinggi. ID group, associated groups, technique per group |
| S2 | CISA Cybersecurity Advisories | https://www.cisa.gov/news-events/cybersecurity-advisories | primer | diakses 2026-10-09 | Tinggi. Contoh laporan aktor dengan pemetaan ATT&CK |
| S3 | Caltagirone, Pendergast, Betz: The Diamond Model of Intrusion Analysis (2013) | https://www.activeresponse.org/the-diamond-model/ | primer | diakses 2026-10-09 | Tinggi. Empat sudut peristiwa intrusi |
| S4 | OASIS STIX Version 2.1 (definisi threat actor, intrusion set, campaign) | https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html | primer | diakses 2026-10-10 | Tinggi. Definisi istilah |
| S5 | CTI-note Day 02-04, 07-08 | (lokal) | rujukan internal | 2026-10-09 | PIR, tradecraft, framework, IOC, TIP |
| S6 | CrowdStrike: CrowdStrike and Microsoft Collaborate to Harmonize Cyber Threat Attribution (Business Wire, 2 Juni 2025) | https://www.businesswire.com/news/home/20250602497894/en/CrowdStrike-Microsoft-Collaborate-Harmonize-Cyber-Threat-Attribution | sekunder (siaran pers vendor) | diakses 2026-10-10 | Sedang-tinggi. Pemetaan alias bersama, lebih dari 80 alias saat diumumkan |

**Catatan sumber:** arti pola nama vendor di bagian 3.1 berasal dari publikasi masing-masing vendor dan bisa berubah; cocokkan dengan halaman taksonomi vendor terbaru sebelum mengutipnya di produk. Status keanggotaan vendor lain di pemetaan nama bersama belum terkonfirmasi. Seluruh profil, laporan, dan nama di bagian 4 fiktif; ID technique ATT&CK di contoh dipakai untuk latihan pemetaan dan harus dicek ulang terhadap ATT&CK versi yang kamu pakai.
