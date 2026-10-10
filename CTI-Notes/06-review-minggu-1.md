---
day: 06
title: 'Review Minggu 1: konsolidasi definisi CTI, siklus, tradecraft, framework, dan sumber'
researched_on: 2026-10-10
versions_checked: 'Merangkum Day 01-05; ATT&CK Enterprise v19.2; FIRST TLP 2.0; ICD 203'
---

# Day 06: Review Minggu 1

Cakupan: konsolidasi Day 01-05 dalam satu alur kerja, dari konsumen dan PIR sampai penilaian berkeyakinan yang distrukturkan dengan framework, lengkap dengan peta konsep, glosarium, lab gabungan, dan latihan skenario beserta pembahasannya.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan hubungan antara tingkat intelijen, siklus intelijen, tradecraft, framework, dan sumber sebagai satu alur kerja.
- menjalankan satu skenario fiktif dari wawancara pemangku kepentingan sampai brief dengan rekomendasi.
- memakai istilah inti Day 01-05 dengan tepat, termasuk istilah yang maknanya berbeda antar sumber.
- menjawab skenario singkat yang menguji penilaian, bukan hafalan.
- mengenali bagian mana dari Day 01-05 yang masih lemah dan perlu diulang.

## 2. Konteks singkat

Day 01-05 membahas fondasi CTI secara terpisah: apa CTI dan siapa konsumennya, bagaimana kebutuhan diubah menjadi pertanyaan, bagaimana menilai informasi dan menulis penilaian, bagaimana menstrukturkan analisis teknis, dan dari mana bahan intelijen boleh diambil. Di pekerjaan nyata, kelima hal itu terjadi dalam satu alur dan sering dalam satu hari. Day ini mengikatnya, lalu mengujinya dengan satu lab gabungan dan beberapa skenario pendek.

Day 07 dan seterusnya masuk ke sisi operasional: IOC dan STIX/TAXII, platform MISP dan OpenCTI, profil aktor, operasionalisasi ke deteksi, dan penulisan produk. Semua itu mengandaikan fondasi di sini sudah lancar.

## 3. Ringkasan, peta konsep, dan glosarium

### 3.1 Day 01: CTI, tingkat intelijen, dan konsumen

CTI adalah informasi ancaman yang sudah dianalisis untuk mendukung sebuah keputusan: mencegah serangan, mempercepat penemuannya, atau memahami risiko. Feed IOC hanya lapisan paling bawah. Model MWR/CPNI membagi intelijen menurut konsumen dan umur:

| Tipe | Isi | Konsumen | Umur |
|---|---|---|---|
| Strategic | Tren, motif, dampak bisnis | Direksi, CISO | Panjang |
| Operational | Serangan spesifik yang akan datang | Kepala IR, security manager | Pendek, jarang tersedia bagi swasta |
| Tactical | TTP | Arsitek, detection engineer | Panjang |
| Technical | IOC | SOC, sistem otomatis | Pendek |

Jebakan utamanya: vendor lain memakai "tactical" untuk IOC dan "operational" untuk TTP. Saat berbicara dengan tim, sebut isinya, bukan hanya labelnya. Hubungan CTI dengan hunting dan IR berjalan dua arah: intel memicu dan mengarahkan hunt, sedangkan hunt dan insiden menghasilkan intel paling relevan.

### 3.2 Day 02: siklus intelijen dan PIR

Siklus berjalan dari direction, collection, processing, analysis, dissemination, lalu feedback, dan berulang. Tahap boleh tumpang tindih. Dua titik gagal paling umum adalah direction (tidak ada PIR yang disetujui) dan dissemination (produk salah format atau terlambat).

PIR adalah pertanyaan prioritas yang terikat keputusan, spesifik, dapat dikumpulkan, terikat waktu, dan berisi satu pertanyaan. Ia diturunkan menjadi SIR (pertanyaan yang bisa dijawab satu analisis) dan EEI (fakta yang dicari kolektor). RFI adalah permintaan ad hoc; RFI yang berulang menandakan PIR yang belum ditulis. Uji PIR yang paling berguna: keputusan apa yang berubah bila jawabannya ya, dan bila jawabannya tidak?

### 3.3 Day 03: analytic tradecraft

Skala Admiralty menilai keandalan sumber (A sampai F) terpisah dari kredibilitas informasi (1 sampai 6). F dan 6 berarti belum bisa dinilai. Kesimpulan tidak diberi kode Admiralty; kesimpulan memakai istilah probabilitas dari skala yang disepakati (ICD 203 atau PHIA) dan tingkat keyakinan yang ditulis di kalimat terpisah.

Bias tidak hilang hanya karena disadari, jadi dipakai structured analytic techniques: Key Assumptions Check, Quality of Information Check, Indicators of Change, dan ACH. Di ACH yang dihitung adalah inkonsistensi, bukti yang konsisten dengan semua hipotesis dibuang, dan kesimpulan diuji dengan analisis sensitivitas. Atribusi dibedakan menjadi clustering, kelompok yang dilacak, dan entitas nyata.

### 3.4 Day 04: framework

Kill Chain memberi tujuh tahap dan course of action matrix (detect, deny, disrupt, degrade, deceive, destroy), tetapi linear dan berpusat pada malware. Diamond menstrukturkan satu event menjadi adversary, capability, infrastructure, dan victim, ditambah meta-feature seperti phase dan direction; event disusun menjadi activity thread dan activity group, dan analis pivot antar feature. ATT&CK v19.2 punya 15 tactic Enterprise; Defense Evasion dipecah menjadi Stealth (TA0005) dan Defense Impairment (TA0112). Pyramid of Pain mengurutkan indikator dari hash (trivial) sampai TTP (tough). Keempatnya dipakai bersama, dan pemetaan selalu disertai dasar bukti.

### 3.5 Day 05: sumber, etika, dan legal

Sumber internal paling relevan; sumber eksternal memberi konteks di luar visibilitas. Setiap sumber dinilai dengan matriks yang sama (relevansi, keandalan, waktu, kelengkapan, independensi, format, biaya, batas legal). Feed diukur dengan hit rate, false positive rate, tumpang tindih, dan umur indikator. Circular reporting dilacak sampai sumber dengan akses langsung. Pengumpulan pasif diutamakan; unggahan ke layanan publik dan kunjungan ke infrastruktur aktor adalah risiko OPSEC. Garisnya tegas: tidak ada dark web, interaksi pelaku, pembelian data bocoran, atau akses sistem tanpa izin. TLP 2.0 punya lima label, dan label menempel pada informasi.

### 3.6 Peta konsep

```
 Konsumen + keputusan (Day 01)
        |
        v
 Direction: PIR -> SIR -> EEI (Day 02)  <------------------------------+
        |                                                             |
        v                                                             |
 Collection: matriks sumber, TLP, garis legal (Day 05)                |
        |                                                             |
        v                                                             |
 Processing: normalisasi, asal + tanggal, kode Admiralty (Day 02-03)  |
        |                                                             |
        v                                                             |
 Analysis: ACH, keyakinan (Day 03) + Kill Chain/Diamond/ATT&CK/       |
           Pyramid (Day 04)                                           |
        |                                                             |
        v                                                             |
 Dissemination: produk per tingkat intelijen (Day 01)                 |
        |                                                             |
        v                                                             |
 Feedback: tindakan tercatat, PIR direvisi --------------------------+
```

Cara membaca peta: setiap kotak punya artefak yang bisa diperiksa. Bila sebuah produk gagal, telusuri ke atas sampai menemukan kotak yang artefaknya hilang atau lemah.

### 3.7 Glosarium

| Istilah | Arti singkat | Day |
|---|---|---|
| CTI | Informasi ancaman yang dianalisis untuk mendukung keputusan | 01 |
| Strategic, operational, tactical, technical | Tipe intelijen menurut konsumen dan umur (model MWR) | 01 |
| Intelligence cycle | Direction, collection, processing, analysis, dissemination, feedback | 02 |
| PIR | Priority Intelligence Requirement; pertanyaan prioritas terikat keputusan | 02 |
| SIR, EEI | Turunan PIR: pertanyaan spesifik dan fakta yang dicari | 02 |
| RFI | Request for Information; permintaan ad hoc | 02 |
| Collection plan | Peta requirement ke sumber, pengumpul, frekuensi, status, dan gap | 02 |
| Admiralty code | Keandalan sumber A-F dan kredibilitas informasi 1-6 | 03 |
| Estimative language | Istilah probabilitas berentang angka (ICD 203, PHIA) | 03 |
| Confidence | Kekuatan dasar sebuah penilaian: high, moderate, low | 03 |
| Key Assumptions Check | Mendaftar dan menguji asumsi yang menopang kesimpulan | 03 |
| ACH | Analysis of Competing Hypotheses; uji hipotesis dengan menghitung inkonsistensi | 03 |
| Clustering | Mengelompokkan aktivitas serupa tanpa menyebut entitas nyata | 03 |
| Cyber Kill Chain | Tujuh tahap intrusi terarah | 04 |
| Course of action matrix | Tahap Kill Chain dikali aksi detect, deny, disrupt, degrade, deceive, destroy | 04 |
| Diamond Model | Adversary, capability, infrastructure, victim, plus meta-feature | 04 |
| Activity thread, activity group | Rangkaian event untuk satu pasangan adversary-victim; kelompok thread yang mirip | 04 |
| ATT&CK | Basis pengetahuan perilaku: tactic, technique, sub-technique, procedure | 04 |
| Stealth, Defense Impairment | Dua tactic pengganti Defense Evasion sejak v19 | 04 |
| Pyramid of Pain | Urutan indikator menurut biaya bagi penyerang | 04 |
| OSINT | Informasi dari sumber terbuka | 05 |
| ISAC | Wadah berbagi informasi antar organisasi satu sektor | 05 |
| Circular reporting | Banyak sumber yang berakar pada satu sumber asal | 05 |
| Pengumpulan pasif dan aktif | Membaca data yang ada vs menyentuh infrastruktur aktor | 05 |
| TLP 2.0 | RED, AMBER+STRICT, AMBER, GREEN, CLEAR | 05 |

## 4-6. Lab gabungan dan troubleshooting

### Skenario lab gabungan

Organisasi fiktif: "PT Klinik Sehat Contoh", jaringan 40 klinik dengan aplikasi rekam medis terpusat dan portal janji temu daring. Lab ini memakai editor teks saja; jangan pakai data kerja dan jangan mengakses sumber terlarang.

Bahan yang tersedia (semua fiktif):

- Wawancara direktur operasional: "Tahun depan kami memutuskan apakah rekam medis pindah ke cloud. Yang paling saya takutkan adalah klinik berhenti melayani karena sistem terkunci."
- Advisori CERT nasional (TLP:CLEAR): kelompok ransomware menyasar fasilitas kesehatan regional lewat VPN tanpa MFA dan portal web yang belum di-patch.
- Laporan ISAC kesehatan (TLP:AMBER+STRICT): satu rumah sakit anggota diserang lewat akun vendor IT; dilampirkan IP 198.51.100[.]77.
- Tiga artikel media yang menyebut "kelompok X" menyerang rumah sakit, semuanya mengutip blog satu vendor.
- Log internal: login VPN gagal berulang dari 198.51.100[.]77 ke akun `vendor.lab02` minggu lalu, tanpa login berhasil.

Langkah:

1. **Konsumen dan tingkat.** Tentukan konsumen dan tipe intelijen untuk setiap pihak yang terlibat.
2. **PIR.** Tulis satu PIR dengan SIR dan EEI, terikat keputusan direktur.
3. **Sumber.** Beri kode Admiralty pada setiap butir bahan, tandai circular reporting, dan tulis batas TLP untuk setiap butir.
4. **Analisis.** Jalankan ACH ringkas untuk pertanyaan "apakah login gagal dari 198.51.100[.]77 adalah upaya awal kelompok yang sama dengan insiden di rumah sakit anggota ISAC?" dengan minimal tiga hipotesis.
5. **Framework.** Petakan perilaku yang diketahui ke ATT&CK v19.2 dan Kill Chain, lalu urutkan indikatornya dengan Pyramid of Pain.
6. **Produk.** Tulis brief setengah halaman untuk direktur dan daftar tindakan untuk SOC. Perhatikan apa yang boleh masuk ke masing-masing menurut TLP.
7. **Feedback.** Tulis umpan balik fiktif dan revisi PIR putaran kedua.

### Pembahasan contoh jawaban

Pembahasan ini satu contoh yang baik, bukan satu-satunya jawaban benar.

**Konsumen.** Direktur operasional membutuhkan intelijen strategic (risiko ransomware terhadap keputusan migrasi). Detection engineer membutuhkan tactical (akses lewat VPN dan akun vendor). SOC membutuhkan technical (IP). Tidak ada operational dalam arti MWR, karena tidak ada informasi tentang serangan spesifik yang direncanakan terhadap klinik ini; login gagal adalah observasi, bukan peringatan rencana.

**PIR.**

```
PIR-K-001: Dalam 12 bulan terakhir, lewat jalur akses apa kelompok ransomware
  yang menyasar fasilitas kesehatan regional masuk, dan apakah jalur itu
  terbuka di lingkungan kita, sehingga syarat keamanan migrasi rekam medis
  ke cloud perlu ditetapkan sebelum keputusan migrasi (Q2)?
SIR-1 Jalur akses awal apa yang dilaporkan untuk sektor kesehatan regional?
  EEI: teknik ATT&CK (T1133, T1078, T1190), jumlah kasus, sumber
SIR-2 Apakah jalur itu terbuka di lingkungan kita?
  EEI: akun VPN tanpa MFA, akun vendor aktif, versi portal web, log percobaan login
SIR-3 Kontrol apa yang perlu menjadi syarat migrasi?
  EEI: kontrol per jalur, biaya relatif
```

**Kode sumber dan TLP.**

| Butir | Kode | TLP dan batas |
|---|---|---|
| Wawancara direktur | A1 | Internal |
| Advisori CERT | B2 | CLEAR |
| Laporan ISAC | B2 | AMBER+STRICT: hanya tim keamanan internal |
| Tiga artikel media | Dinilai sebagai satu sumber: blog vendor, B3 | CLEAR |
| Log VPN internal | A1 | Internal |

Tiga artikel media adalah circular reporting; dihitung satu. Klaim "kelompok X" hanya punya satu sumber asal, sehingga atribusi tetap rendah keyakinannya.

**ACH ringkas.**

| Bukti | H1 kelompok sama dengan kasus ISAC | H2 aktor lain memakai infrastruktur sama | H3 pemindaian oportunistik umum |
|---|---|---|---|
| E1 IP sama dengan lampiran ISAC (B2) | C | C | C |
| E2 Akun yang dicoba adalah akun vendor yang sah (A1) | C | C | I |
| E3 Tidak ada percobaan ke akun lain (A1) | C | C | I |
| E4 IP terdaftar di layanan VPN komersial (A2) | N | C | C |
| Jumlah I | 0 | 0 | 2 |

E1 konsisten dengan semua hipotesis sehingga tidak diagnostik, walaupun terasa paling "menarik". H3 melemah karena pemindaian umum jarang menebak nama akun vendor yang benar. H1 dan H2 tidak bisa dibedakan dengan bukti yang ada. Penilaian yang jujur: "Kemungkinan besar (likely) percobaan login ini terarah ke klinik kita, bukan pemindaian umum. Keyakinan sedang. Kami belum dapat menilai apakah pelakunya sama dengan insiden di sektor; IP yang sama berasal dari layanan VPN komersial yang dipakai banyak pihak." Pertanyaan pembeda berikutnya: dari mana penyerang tahu nama akun `vendor.lab02`?

**Framework.** Perilaku: percobaan login ke akun vendor lewat VPN (Initial Access dan Credential Access; T1133 External Remote Services, T1110 Brute Force, dengan sub-technique dipilih setelah polanya jelas), dan pada kasus ISAC penggunaan akun sah (T1078). Di Kill Chain, aktivitas ini ada di tahap delivery atau exploitation versi identitas, contoh di mana model klasik terasa dipaksakan. Pyramid of Pain: IP (easy) diblokir hari ini; pola "login ke akun vendor dari VPN komersial di luar jam kerja" adalah artifact dan TTP yang layak dijadikan deteksi.

**Produk dan TLP.** Brief direktur hanya memakai advisori CERT dan data internal, karena laporan ISAC berlabel AMBER+STRICT dan direktur operasional di luar tim keamanan. Isi brief: risiko jalur akses vendor dan VPN terhadap rencana migrasi, penilaian dengan keyakinan, dan rekomendasi MFA untuk semua akses vendor sebagai syarat migrasi. Daftar SOC boleh memuat IP dari laporan ISAC karena SOC bagian dari tim keamanan internal.

**Feedback.** Contoh umpan balik: "Saya butuh tahu apakah penyedia cloud yang kami pertimbangkan mendukung MFA untuk akses vendor." PIR putaran kedua menambah SIR tentang kontrol di sisi penyedia cloud.

### Latihan skenario singkat

Jawab dulu sebelum membaca pembahasan.

**Skenario A.** Manajer SOC meminta "laporan intelijen mingguan tentang semua ancaman terbaru".
Pembahasan: ini bukan PIR. Tanyakan keputusan apa yang ia buat tiap minggu (misalnya prioritas tuning rule atau shift staf), lalu tulis PIR yang terikat ke keputusan itu. Bila tidak ada keputusan, laporan mingguan akan menjadi rangkuman berita yang tidak dibaca.

**Skenario B.** Empat feed menandai satu domain sebagai berbahaya, jadi rekan menulis "keyakinan tinggi, domain milik kelompok Y".
Pembahasan: cek apakah keempat feed mengambil dari sumber asal yang sama. Domain berbahaya dan domain milik kelompok Y adalah dua klaim berbeda: yang pertama bisa terkonfirmasi, yang kedua atribusi yang butuh dasar sendiri.

**Skenario C.** Laporan vendor tahun 2024 memetakan sebuah teknik ke Defense Evasion, dan kamu ingin mencocokkannya dengan rule di SIEM yang sudah di-tag dengan ATT&CK v19.2.
Pembahasan: Defense Evasion tidak lagi ada sebagai nama tactic di v19. Cek halaman technique tersebut di v19.2 untuk melihat apakah kini berada di Stealth (TA0005) atau Defense Impairment (TA0112), lalu remap.

**Skenario D.** Rekan menyarankan membuka URL phishing yang dilaporkan pegawai dari laptop kerja "supaya cepat tahu isinya".
Pembahasan: itu pengumpulan aktif dari jaringan kantor. Risikonya memberi tahu penyerang dan terkena exploit browser. Mulai dari sumber pasif (reputasi URL, riwayat domain), dan bila isi halaman tetap diperlukan, ikuti kebijakan tim tentang lingkungan analisis terpisah.

**Skenario E.** Laporan ISAC berlabel TLP:AMBER memuat IOC yang ingin kamu bagikan ke MSSP yang memantau SIEM-mu.
Pembahasan: TLP:AMBER mengizinkan berbagi ke organisasi penerima dan kliennya atas dasar need-to-know. MSSP adalah penyedia layananmu, bukan klienmu, jadi tanya ISAC atau pengirim laporan sebelum berbagi. Bila labelnya AMBER+STRICT, jawabannya jelas tidak tanpa izin pengirim.

### Troubleshooting lintas Day

| Gejala | Day yang perlu diulang | Pemeriksaan |
|---|---|---|
| Brief bagus tetapi tidak menghasilkan tindakan | 01, 02 | Apakah ada keputusan dan rekomendasi? Apakah konsumen dan tipe intelijennya cocok? |
| Tidak tahu harus mengumpulkan apa | 02 | Apakah PIR sudah diturunkan ke SIR dan EEI? |
| Penilaian sering dikoreksi rekan | 03 | Apakah fakta dan penilaian dipisah? Apakah alternatif diuji? |
| Pemetaan ATT&CK berbeda antar analis | 04 | Apakah ada kolom dasar bukti dan versi ATT&CK? |
| Keyakinan terlalu tinggi | 03, 05 | Apakah ada circular reporting? Apakah kesimpulan bertumpu pada satu butir lemah? |
| Ragu boleh berbagi | 05 | Label TLP apa yang menempel pada informasi yang dikutip? |

**Hasil yang sebaiknya tersimpan:**

- PIR, SIR, dan EEI untuk skenario klinik.
- Tabel kode sumber dan TLP, dengan catatan circular reporting.
- Matriks ACH ringkas dan penilaian dengan probabilitas serta keyakinan.
- Pemetaan ATT&CK, Kill Chain, dan Pyramid of Pain dengan dasar bukti.
- Brief setengah halaman untuk direktur dan daftar tindakan SOC yang patuh TLP.
- Jawaban tertulis untuk skenario A sampai E, lalu catatan Day mana yang jawabanmu paling banyak meleset dari pembahasan.

## 7. Kesalahan umum dan jebakan

- Membawa label "operational" dari laporan vendor ke brief internal tanpa menjelaskan isinya.
- Menulis PIR tanpa SIR internal, sehingga jawaban berhenti di deskripsi ancaman.
- Memberi kode Admiralty pada kesimpulan, atau mencampur probabilitas dan keyakinan dalam satu frasa.
- Menganggap bukti yang paling menarik sebagai bukti paling diagnostik, seperti E1 di ACH klinik.
- Memaksa serangan berbasis identitas ke tujuh tahap Kill Chain.
- Mengutip informasi AMBER+STRICT di produk untuk pihak di luar organisasi.

## 8. Catatan terkini

- ATT&CK Enterprise v19.2 (Agustus 2026) adalah versi acuan untuk semua pemetaan di Day 01-05; perubahan Defense Evasion terjadi di v19 (April 2026).
- TLP 2.0 tetap versi yang berlaku; dokumen lama masih memakai TLP:WHITE.
- Istilah probabilitas di catatan ini mengikuti ICD 203; PHIA dipakai sebagai pembanding.

## 9. Cheat sheet

```
ALUR      konsumen+keputusan -> PIR/SIR/EEI -> sumber sah (matriks, TLP) -> processing (asal+tanggal, Admiralty)
          -> analisis (ACH, keyakinan, framework) -> produk per tipe intel -> feedback -> revisi PIR
TIPE      strategic | operational (langka) | tactical (TTP) | technical (IOC) ; sebut isi, bukan label
PIR       terikat keputusan, spesifik, dapat dikumpulkan, terikat waktu, satu pertanyaan
NILAI     Admiralty A-F + 1-6 untuk BUTIR ; kesimpulan = probabilitas + keyakinan (kalimat terpisah)
ACH       hitung I ; buang non-diagnostik ; sensitivitas ; lapor semua hipotesis
FRAMEWORK Kill Chain (tahap, CoA) | Diamond (event, pivot) | ATT&CK v19.2 (perilaku) | Pyramid (prioritas)
SUMBER    independensi > jumlah ; pasif dulu ; garis legal ; TLP menempel pada informasi
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | MWR InfoSecurity, CPNI, CERT-UK: Threat Intelligence: Collecting, Analysing, Evaluating (salinan PDF) | https://www.ismsforum.es/ficheros/descargas/threat-intelligence--collecting-analysing.pdf | primer | 2015; diakses 2026-10-10 | Tinggi. Tipe intelijen menurut konsumen |
| S2 | MITRE ATT&CK: Enterprise Tactics | https://attack.mitre.org/tactics/enterprise/ | primer | v19.2, Agustus 2026; diakses 2026-10-10 | Tinggi. Daftar tactic dan ID |
| S3 | FIRST: Traffic Light Protocol version 2.0 | https://www.first.org/tlp/ | primer | 2022-08; diakses 2026-10-10 | Tinggi. Definisi label |
| S4 | Richards J. Heuer Jr.: Psychology of Intelligence Analysis | https://www.cia.gov/resources/csi/books-monographs/psychology-of-intelligence-analysis-2/ | primer | 1999; diakses 2026-10-10 | Tinggi. ACH |
| S5 | Office of the Director of National Intelligence: ICD 203, Analytic Standards | https://www.dni.gov/files/documents/ICD/ICD-203.pdf | primer | 2015, amandemen 2022 | Tinggi. Istilah probabilitas; situs menolak akses otomatis |

**Catatan sumber:** Day ini merangkum Day 01-05; klaim rinci dan catatan kelemahannya ada di bagian 10 Day asal. Skenario klinik dan pembahasannya fiktif dan disusun untuk latihan.
