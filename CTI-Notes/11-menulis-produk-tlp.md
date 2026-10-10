---
day: 11
title: 'Menulis produk CTI: struktur brief, BLUF, bahasa keyakinan, dan Traffic Light Protocol 2.0'
researched_on: 2026-10-10
versions_checked: 'FIRST TLP 2.0 (berlaku sejak Agustus 2022); ICD 203 (bahasa estimatif); rujukan Day 01-03, 07, 10'
---

# Day 11: Menulis produk CTI dan TLP

Cakupan: cara menulis produk intelijen yang dibaca dan dipakai, mulai dari memilih jenis produk dan menyusun BLUF sampai menyatakan kemungkinan dan keyakinan dengan benar, lalu menandai batas berbaginya dengan TLP 2.0.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- memilih jenis produk yang cocok untuk konsumen dan kebutuhan (flash alert, ringkasan, assessment, jawaban RFI).
- menulis BLUF yang memuat temuan, dampak, dan tindakan dalam beberapa kalimat.
- memakai bahasa estimatif yang terdefinisi dan membedakan kemungkinan (likelihood) dari keyakinan (confidence).
- memisahkan fakta dari penilaian di dalam teks dan menyertakan keandalan sumber.
- menerapkan TLP 2.0 dengan benar, termasuk aturan penulisan, pewarisan label, dan perbedaannya dengan PAP.
- merevisi draf sampai ringkas, jujur tentang ketidakpastian, dan bisa ditindaklanjuti.

## 2. Konteks singkat

Produk tertulis adalah wajah CTI. Betapapun bagus analisisnya, produk yang membingungkan, terlalu panjang, atau salah sasaran tidak menghasilkan tindakan. Itu kegagalan dissemination (Day 02), dan sering terjadi justru pada analis yang teknisnya kuat.

Menulis produk yang baik punya aturan yang bisa dipelajari: sesuaikan dengan konsumen, mulai dari kesimpulan, nyatakan ketidakpastian dengan kosakata yang disepakati, dan akhiri dengan tindakan. TLP menandai sampai mana produk boleh dibagikan, sehingga sumber terlindungi dan mitra tetap mau berbagi.

**Kapan dipakai:** setiap produk CTI tertulis, termasuk pesan singkat di chat insiden, dan setiap kali berbagi dengan pihak luar.

**Kapan terbatas:** format akhir mengikuti kebijakan organisasi. TLP adalah kesepakatan berbagi, bukan skema klasifikasi hukum, dan tidak menggantikan NDA atau kewajiban regulasi.

## 3. Konsep inti

### 3.1 Jenis produk dan konsumennya

| Jenis produk | Konsumen | Pemicu | Panjang | Isi kunci |
|---|---|---|---|---|
| Flash alert | SOC, IR, admin sistem | Ancaman aktif atau kerentanan dieksploitasi | Setengah sampai satu halaman | Apa yang terjadi, siapa terdampak, tindakan dalam jam ini, IOC/TTP |
| Ringkasan berkala (mingguan) | Manajer keamanan, SOC lead | Jadwal | Satu sampai dua halaman | Tiga sampai lima item relevan dengan "so what" masing-masing |
| Threat assessment | CISO, manajemen risiko | PIR atau permintaan | Dua sampai lima halaman | Penilaian ancaman, kemungkinan, dampak, rekomendasi |
| Jawaban RFI | Peminta spesifik | Request for information | Sependek mungkin | Jawaban langsung atas pertanyaan, keyakinan, celah |
| Profil aktor atau kampanye | Analis, detection engineer, hunter | PIR | Beberapa halaman plus lampiran | TTP, procedure, IOC, deteksi dan hunt |
| Brief strategis | Pimpinan, board | Tren atau peristiwa besar | Satu halaman | Risiko bisnis, keputusan yang diminta |

Kesalahan yang paling sering adalah mengirim satu dokumen ke semua orang. Pimpinan tidak membaca daftar IOC, dan SOC tidak bisa bertindak dari paragraf tentang tren geopolitik. Bila satu analisis harus melayani dua konsumen, tulis dua produk: brief singkat untuk pengambil keputusan dan lampiran teknis untuk pelaksana.

### 3.2 BLUF (Bottom Line Up Front)

BLUF berarti kesimpulan dan tindakan ditulis di awal, lalu didukung oleh detail. Pembaca sibuk harus mendapat inti dalam dua sampai empat kalimat pertama, karena banyak yang tidak membaca lebih jauh.

BLUF yang baik menjawab empat hal:

1. **Apa** temuan utamanya.
2. **Jadi apa** dampaknya bagi organisasi ini, bukan bagi dunia secara umum.
3. **Seberapa yakin** kita.
4. **Lalu apa** yang harus dilakukan, oleh siapa, dan kapan.

Contoh BLUF yang lemah: "Laporan ini membahas kampanye ransomware terbaru yang menargetkan berbagai sektor di Asia Tenggara dan teknik-teknik yang digunakan."

Versi yang kuat: "Kami menilai kemungkinan besar (keyakinan sedang) perusahaan logistik di Indonesia, termasuk kita, menjadi sasaran kampanye ransomware LOGI-FICTA dalam tiga bulan ke depan. Akses awalnya lewat lampiran .js dalam zip, yang saat ini lolos gateway email kita. Kami merekomendasikan tim email memblokir lampiran skrip dalam arsip minggu ini dan SOC menambah dua rule deteksi yang sudah kami siapkan."

Versi kedua bisa dihentikan setelah tiga kalimat dan pembaca tetap tahu apa yang harus dilakukan.

### 3.3 Bahasa estimatif: kemungkinan dan keyakinan

Kata seperti "mungkin" atau "bisa jadi" ditafsirkan sangat berbeda oleh pembaca yang berbeda. Satu orang membacanya 20 persen, orang lain 60 persen. Karena itu tim CTI memakai kosakata terdefinisi. Skala yang banyak dirujuk berasal dari ICD 203 [S4]:

| Istilah (Inggris) | Padanan yang bisa dipakai | Rentang kemungkinan |
|---|---|---|
| almost no chance / remote | hampir tidak mungkin | 1-5% |
| very unlikely / highly improbable | sangat kecil kemungkinannya | 5-20% |
| unlikely / improbable | kecil kemungkinannya | 20-45% |
| roughly even chance | kurang lebih sama besar | 45-55% |
| likely / probable | kemungkinan besar | 55-80% |
| very likely / highly probable | sangat mungkin | 80-95% |
| almost certain / nearly certain | hampir pasti | 95-99% |

Pilih satu set istilah Indonesia, tetapkan rentangnya di kebijakan tim, dan pakai secara konsisten. Lampirkan tabelnya di akhir produk untuk pembaca baru.

Kemungkinan dan keyakinan adalah dua hal berbeda:

- **Kemungkinan** menjawab "seberapa besar peluang peristiwa ini terjadi atau benar".
- **Keyakinan** (rendah, sedang, tinggi) menjawab "seberapa kuat dasar penilaian kita": kualitas dan jumlah sumber, konsistensi bukti, dan seberapa banyak asumsi yang dipakai.

Keduanya bisa tidak sejalan. "Sangat mungkin (keyakinan rendah)" berarti indikasinya mengarah kuat tetapi berbasis satu sumber yang belum terkonfirmasi. ICD 203 juga meminta agar kemungkinan dan keyakinan tidak digabung dalam satu kalimat yang membingungkan; nyatakan keduanya dengan jelas.

Definisi kerja tingkat keyakinan yang bisa kamu pakai:

- **Tinggi:** beberapa sumber andal dan independen, bukti konsisten, sedikit asumsi.
- **Sedang:** sumber andal tetapi terbatas atau belum terkonfirmasi silang, atau ada celah informasi yang berarti.
- **Rendah:** sumber tunggal atau keandalan diragukan, bukti terfragmentasi, banyak asumsi.

### 3.4 Memisahkan fakta, penilaian, dan sumber

Pembaca harus bisa membedakan apa yang diamati dari apa yang disimpulkan. Pola kalimat yang membantu:

- Fakta: "Pada 7 Oktober, gateway email mencatat 42 email dengan lampiran zip berisi berkas .js ke 11 penerima di divisi keuangan."
- Penilaian: "Kami menilai kemungkinan besar (keyakinan sedang) email ini bagian dari kampanye LOGI-FICTA, karena pola lampiran dan domain pengirimnya cocok dengan laporan vendor A."

Sertakan keandalan sumber dengan skala Admiralty (Day 03), misalnya "laporan vendor A (B2)". Pembaca teknis memakai kode ini untuk menimbang sendiri, dan kode itu juga menjaga kejujuranmu ketika semua bukti berasal dari satu tempat.

Bila ada pandangan alternatif yang masuk akal, tuliskan. Kalimat seperti "kemungkinan lain adalah aktor berbeda yang memakai builder yang sama; kami menilainya kecil kemungkinannya karena..." menunjukkan bahwa analisis mempertimbangkan hipotesis lain (ACH, Day 03).

### 3.5 Struktur produk

Struktur umum yang bisa disesuaikan dengan kebijakan organisasi:

| Bagian | Isi | Catatan |
|---|---|---|
| Header | Label TLP, judul, nomor produk, tanggal, analis, PIR yang dijawab | Label TLP di baris paling atas |
| BLUF | Temuan, dampak, keyakinan, tindakan | Maksimal satu paragraf |
| Penilaian | Analisis dengan bahasa estimatif | Satu paragraf per penilaian utama |
| Bukti | Fakta pendukung dengan sumber dan Admiralty | Bisa berupa tabel |
| Alternatif dan keterbatasan | Hipotesis lain, celah informasi, apa yang bisa mengubah penilaian | Menambah kredibilitas |
| Rekomendasi | Tindakan, pemilik, tenggat | Bernomor, bisa dicentang tim penerima |
| Lampiran teknis | TTP ke ATT&CK, IOC berkonteks dan ter-defang, rule atau hipotesis hunt | Bisa diberi TLP lebih ketat |
| Umpan balik | Cara memberi masukan atau melaporkan sighting | Satu baris |
| Footer | Label TLP lagi | Wajib di setiap halaman |

Bagian "apa yang bisa mengubah penilaian" sering terlupa padahal sangat berguna: misalnya "penilaian ini akan naik bila kami melihat procedure yang sama di jaringan kita; turun bila vendor B mengonfirmasi kampanye berhenti". Ini memberi pembaca indikator untuk dipantau.

### 3.6 Traffic Light Protocol 2.0

TLP dari FIRST menandai batas berbagi informasi. TLP 2.0 berlaku sejak Agustus 2022 dan memakai lima label [S2]:

| Label | Siapa boleh menerima dari penerima pertama |
|---|---|
| TLP:RED | Tidak diteruskan sama sekali; hanya untuk individu penerima, umumnya disampaikan langsung dalam rapat atau percakapan |
| TLP:AMBER+STRICT | Hanya anggota organisasi penerima, atas dasar perlu tahu |
| TLP:AMBER | Anggota organisasi penerima dan klien-kliennya, atas dasar perlu tahu untuk melindungi diri atau mencegah kerugian |
| TLP:GREEN | Komunitas penerima (rekan dan mitra), tetapi tidak lewat kanal yang bisa diakses publik |
| TLP:CLEAR | Tanpa batas; boleh dipublikasikan, dengan tetap mengikuti aturan hak cipta |

Perubahan dari TLP 1.0: TLP:WHITE berganti nama menjadi TLP:CLEAR, dan TLP:AMBER+STRICT ditambahkan untuk kasus yang dulu sering ditulis sebagai "TLP:AMBER, hanya internal" [S2][S3]. Bila komunitas untuk TLP:GREEN tidak didefinisikan, standar mengasumsikan komunitas keamanan siber dan pertahanan.

Aturan penulisan:

- Label ditulis huruf kapital tanpa spasi: `TLP:AMBER`, `TLP:AMBER+STRICT`.
- Di email, label ditaruh di baris subjek dan sebelum isi pesan.
- Di dokumen, label ditaruh di header dan footer setiap halaman, rata kanan menurut spesifikasi.
- Label berwarna memakai warna yang ditentukan standar di atas latar hitam (misalnya teks kuning-oranye untuk AMBER), agar tetap terbaca di layar dan cetak.
- Bila sebagian isi punya label berbeda, tandai per bagian.

### 3.7 Menghormati TLP sumber dan PAP

TLP hanya bekerja bila dihormati:

- **Jangan melonggarkan label.** Informasi TLP:AMBER dari mitra tidak boleh kamu tulis ulang sebagai TLP:GREEN.
- **Minta izin untuk berbagi lebih luas.** Hanya pemberi informasi yang bisa melonggarkan label.
- **Warisi label paling ketat.** Produk yang menggabungkan beberapa sumber memakai label paling ketat dari sumber itu, atau pisahkan bagian yang ketat ke lampiran tersendiri.
- **Ingat sistem yang ikut membaca.** Mengunggah produk TLP:AMBER+STRICT ke platform yang bisa diakses vendor, MSSP, atau kontraktor bisa berarti penyebaran di luar organisasi.

PAP (Permissible Actions Protocol) melengkapi TLP. TLP mengatur siapa boleh menerima informasi; PAP mengatur tindakan apa yang boleh dilakukan terhadap indikator. Contohnya, PAP:RED berarti hanya tindakan pasif yang tidak terdeteksi oleh penyerang (misalnya mencari di log sendiri), PAP:AMBER mengizinkan tindakan pasif yang mungkin terlihat (misalnya query ke layanan reputasi online), PAP:GREEN mengizinkan tindakan aktif seperti blokir, dan PAP:CLEAR tanpa batasan. Label ini sering dipakai di platform seperti MISP (Day 08). Cek definisi PAP yang dipakai komunitasmu, karena PAP tidak dikelola FIRST seperti TLP.

### 3.8 Revisi

Draf pertama jarang cukup. Revisi dengan urutan ini:

1. **Uji BLUF.** Bacakan hanya paragraf pertama ke rekan. Bila ia tidak bisa menyebut tindakan yang diminta, tulis ulang.
2. **Buang yang tidak melayani konsumen.** Riwayat aktor lima tahun ke belakang jarang dibutuhkan pimpinan.
3. **Periksa setiap kata kemungkinan.** Apakah memakai istilah dari tabel tim? Apakah keyakinan dinyatakan?
4. **Periksa fakta dan sumber.** Setiap klaim fakta punya sumber; setiap penilaian punya dasar.
5. **Periksa rekomendasi.** Setiap butir punya pemilik dan tenggat.
6. **Periksa TLP.** Label di subjek, header, footer; label sesuai sumber paling ketat.
7. **Periksa IOC.** Semua ter-defang di teks.

Ukuran akhirnya adalah apakah konsumen bisa bertindak setelah membaca, dan apakah kamu mendapat umpan balik bahwa produk itu dipakai.

## 4. Contoh artefak intelijen

Semua contoh di bagian ini fiktif dan berupa ilustrasi. IOC di-defang.

### 4.1 Brief strategis untuk pimpinan

```
TLP:AMBER
CTI-2026-041 | 2026-10-10 | Analis: tim CTI | Menjawab PIR-02 (ancaman ransomware terhadap operasi)
Judul: Kampanye ransomware LOGI-FICTA berisiko mengganggu operasi gudang

BLUF
Kami menilai kemungkinan besar (keyakinan sedang) perusahaan kita menjadi sasaran
kampanye ransomware LOGI-FICTA dalam tiga bulan ke depan. Kampanye ini sudah
melumpuhkan sistem gudang enam perusahaan logistik di kawasan sejak Juli. Celah
utama kita ada di penyaringan lampiran email, yang bisa ditutup minggu ini tanpa
biaya tambahan. Kami meminta persetujuan untuk perubahan kebijakan email tersebut.

Kenapa penting
- Korban teramati semuanya logistik, tiga di antaranya di Indonesia [fakta, sumber B2].
- Rata-rata gangguan operasional korban yang dilaporkan lebih dari satu minggu [fakta, sumber B3].
- Profil kita (sektor, wilayah, sistem gudang) cocok dengan pola korban [penilaian].

Yang diminta
1. Persetujuan memblokir lampiran skrip dalam arsip di email (Kepala TI, minggu ini).
2. Prioritas dua rule deteksi dan satu hunt yang sudah disiapkan (SOC Lead, 14 hari).

Keterbatasan
Penilaian bersandar pada dua laporan vendor; belum ada indikasi aktivitas ini di jaringan kita.
Penilaian naik bila kami menemukan email kampanye ini lolos ke pengguna.
TLP:AMBER
```

### 4.2 Lampiran teknis untuk SOC

```
TLP:AMBER+STRICT
CTI-2026-041-L1 | Lampiran teknis

TTP (procedure -> ATT&CK)
  lampiran .js dalam zip bertema faktur      T1566.001
  wscript menjalankan .js dari Downloads     T1204.002, T1059.007
  scheduled task dari ProgramData            T1053.005
  HTTPS interval seragam ke domain baru      T1071.001
  unggah arsip ke cloud storage              T1567.002

IOC (keyakinan sedang, expiry 2027-01-08, PAP:GREEN)
  domain  bad-logistics[.]example   sumber vendor A (B2)
  ip      203.0.113[.]50            sumber vendor A (B2), hosting VPS, bisa berpindah

Tindakan SOC
  1. Muat IOC ke watchlist dan jalankan pencarian retroaktif 90 hari.
  2. Pasang rule Sigma CTI-ISET-FICTA-01 (scheduled task dari ProgramData).
  3. Jalankan hunt H-2026-07 (beaconing dan unggahan besar).
Umpan balik: laporkan hit dan false positive ke kanal tim CTI.
TLP:AMBER+STRICT
```

Lampiran diberi TLP lebih ketat karena memuat IOC dari mitra yang hanya boleh dipakai internal, sedangkan brief strategis boleh dibagikan ke anak perusahaan sebagai klien yang perlu tahu.

### 4.3 Menulis ulang paragraf yang buruk

```
SEBELUM
"Kelompok hacker berbahaya ini sangat canggih dan mungkin akan menyerang kita.
 Mereka menggunakan berbagai teknik termasuk phishing dan malware. Sebaiknya kita
 meningkatkan keamanan."

MASALAH
- "sangat canggih": tidak didukung bukti, bernada pemasaran
- "mungkin": tidak terdefinisi ; keyakinan tidak disebut
- "berbagai teknik": tidak actionable
- "meningkatkan keamanan": tanpa pemilik, tanpa tindakan spesifik

SESUDAH
"Kami menilai kemungkinan besar (keyakinan sedang) kelompok ini akan menargetkan kita
 lewat email berlampiran .js dalam zip, karena seluruh korbannya perusahaan logistik
 di kawasan. Tim email perlu memblokir lampiran skrip dalam arsip minggu ini."
```

### 4.4 Keputusan TLP saat menggabungkan sumber

```
Sumber 1: laporan vendor A       TLP:CLEAR
Sumber 2: email ISAC             TLP:GREEN
Sumber 3: briefing mitra         TLP:AMBER+STRICT (berisi IOC dari insiden mitra)
Produk   : brief pimpinan tanpa IOC mitra -> TLP:AMBER (isi dari sumber 1-2, plus penilaian internal)
           lampiran berisi IOC mitra       -> TLP:AMBER+STRICT (warisi sumber 3)
Bila ingin membagikan IOC mitra ke ISAC: minta izin mitra lebih dulu.
```

## 5. Lab praktik

**Prasyarat:** editor teks dan skenario fiktif (bisa memakai profil ISET-FICTA dari Day 09 dan artefak Day 10). Jangan menyebarkan produk fiktif seolah nyata.

1. **Kebijakan istilah.** Tulis tabel bahasa estimatif tim fiktifmu (istilah Indonesia dan rentangnya) dan definisi tiga tingkat keyakinan.
2. **Dua produk.** Untuk skenario yang sama, tulis brief strategis satu halaman dan lampiran teknis untuk SOC.
3. **BLUF.** Pastikan BLUF tiap produk menjawab apa, jadi apa, seberapa yakin, lalu apa. Uji dengan membacakannya ke orang lain.
4. **Fakta dan penilaian.** Tandai setiap kalimat di brief sebagai fakta atau penilaian, dan pastikan setiap fakta punya sumber dengan kode Admiralty.
5. **Alternatif.** Tambahkan satu hipotesis alternatif dan indikator yang bisa mengubah penilaian.
6. **TLP.** Gabungkan tiga sumber fiktif dengan label berbeda dan tentukan label tiap produk, seperti bagian 4.4.
7. **Revisi.** Ambil satu paragraf buruk (tulis sendiri atau dari draf lama) dan revisi seperti bagian 4.3, lengkap dengan daftar masalahnya.
8. **Flash alert.** Tulis flash alert setengah halaman untuk kerentanan fiktif yang sedang dieksploitasi pada produk yang dipakai organisasi fiktifmu.

**Hasil yang sebaiknya tersimpan:**

- Tabel bahasa estimatif dan definisi keyakinan.
- Brief strategis dan lampiran teknis untuk skenario yang sama.
- Catatan uji BLUF.
- Brief beranotasi fakta dan penilaian.
- Keputusan TLP untuk sumber gabungan.
- Contoh revisi paragraf dengan daftar masalah.
- Satu flash alert.

**Variasi tantangan:** ambil lampiran teknis yang kamu tulis dan ubah menjadi brief tiga kalimat untuk direktur operasional yang tidak berlatar teknis. Catat apa yang kamu buang, apa yang kamu angkat, dan pastikan keyakinan tetap jujur.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Pimpinan tidak membaca | Terlalu teknis atau panjang | Satu halaman, BLUF, keputusan yang diminta |
| Pesan utama hilang | Kesimpulan di akhir | Pindahkan ke BLUF |
| Pembaca salah menangkap tingkat kepastian | Istilah kemungkinan tidak terdefinisi | Pakai tabel istilah tim; nyatakan keyakinan terpisah |
| Produk dianggap menakut-nakuti | Bahasa pemasaran, tanpa bukti | Hapus superlatif; tunjukkan fakta dan sumber |
| Tidak ada tindakan setelah produk terbit | Rekomendasi tanpa pemilik dan tenggat | Tulis pemilik dan tenggat per butir |
| Produk tersebar tidak semestinya | Label salah atau tidak diwariskan | Label paling ketat; pisahkan lampiran |
| Mitra berhenti berbagi | TLP sumber dilonggarkan | Minta izin sebelum memperluas penyebaran |

## 7. Kesalahan umum dan jebakan

- **Satu produk untuk semua konsumen.** Pisahkan brief dan lampiran teknis.
- **Kesimpulan di akhir.** Pakai BLUF.
- **Mencampur kemungkinan dan keyakinan.** "Kemungkinan besar" dan "keyakinan sedang" menjawab pertanyaan berbeda.
- **Superlatif tanpa bukti.** "Paling canggih" atau "sangat berbahaya" merusak kredibilitas.
- **Menyembunyikan keterbatasan.** Keterbatasan yang jujur membuat penilaian lebih dipercaya.
- **Menyamakan TLP dengan PAP.** TLP mengatur siapa menerima, PAP mengatur tindakan terhadap indikator.
- **Memakai TLP:WHITE.** Sudah diganti TLP:CLEAR di TLP 2.0.

## 8. Catatan terkini

- TLP 2.0 dari FIRST tetap versi yang berlaku. Perubahan utamanya dari 1.0 adalah TLP:CLEAR menggantikan TLP:WHITE dan penambahan TLP:AMBER+STRICT [S2][S3].
- Penulisan BLUF dan bahasa estimatif terdefinisi makin umum di tim CTI swasta, dipengaruhi standar analitik pemerintah seperti ICD 203 [S4].
- Produk makin sering dilengkapi pemetaan ATT&CK, IOC dalam STIX (Day 07), dan rule siap pakai (Day 10) agar bisa langsung dioperasionalkan.

## 9. Cheat sheet

```
PRODUK     flash alert (SOC, segera) | ringkasan berkala | assessment (CISO) | jawaban RFI | profil | brief strategis (board)
BLUF       apa | jadi apa (bagi KITA) | seberapa yakin | lalu apa (siapa, kapan) ; 2-4 kalimat
ESTIMATIF  hampir tidak mungkin 1-5 | sangat kecil 5-20 | kecil 20-45 | sama besar 45-55 |
           kemungkinan besar 55-80 | sangat mungkin 80-95 | hampir pasti 95-99 (%)
KEYAKINAN  tinggi (banyak sumber andal, konsisten) | sedang (andal tapi terbatas) | rendah (tunggal/diragukan)
           kemungkinan != keyakinan ; nyatakan keduanya
KALIMAT    fakta: "kami mengamati ..." + sumber (Admiralty) | penilaian: "kami menilai ..." + dasar
STRUKTUR   TLP+header | BLUF | penilaian | bukti | alternatif+keterbatasan | rekomendasi (pemilik, tenggat) | lampiran | umpan balik | TLP
TLP 2.0    RED (individu) | AMBER+STRICT (org saja) | AMBER (org + klien, perlu tahu) | GREEN (komunitas, non-publik) | CLEAR (publik)
TULIS      KAPITAL tanpa spasi ; email: subjek + awal isi ; dokumen: header + footer tiap halaman
HORMATI    jangan longgarkan ; minta izin ; warisi paling ketat ; ingat sistem pihak ketiga
PAP        RED pasif tak terlihat | AMBER pasif mungkin terlihat | GREEN aktif (blokir) | CLEAR bebas
REVISI     uji BLUF -> buang -> istilah -> fakta/sumber -> pemilik+tenggat -> TLP -> defang
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | CTI-note Day 01-03, 07, 10 | (lokal) | rujukan internal | 2026-10-09 | Konsumen, siklus, Admiralty, ACH, IOC, operasionalisasi |
| S2 | FIRST: Traffic Light Protocol (TLP) 2.0 | https://www.first.org/tlp/ | primer | diakses 2026-10-09 | Tinggi. Definisi label, aturan penulisan, warna |
| S3 | CERT-EU: TLP version 2 | https://www.cert.europa.eu/ | sekunder | diakses 2026-10-09 | Sedang-tinggi. Ringkasan perubahan TLP 1.0 ke 2.0 |
| S4 | ODNI: Intelligence Community Directive 203, Analytic Standards | https://www.dni.gov/files/documents/ICD/ICD-203.pdf | primer | diakses 2026-10-09 | Tinggi. Skala bahasa estimatif dan pemisahan kemungkinan dari keyakinan |
| S5 | MITRE ATT&CK | https://attack.mitre.org/ | primer | diakses 2026-10-09 | Tinggi. Pemetaan TTP di lampiran teknis |

**Catatan sumber:** definisi kerja tiga tingkat keyakinan di bagian 3.3 dan struktur produk di bagian 3.5 adalah praktik umum yang perlu disesuaikan dengan kebijakan organisasi, bukan isi baku dari satu standar. Definisi PAP di bagian 3.7 mengikuti penggunaan yang lazim di komunitas MISP; PAP tidak diterbitkan FIRST, jadi cocokkan dengan definisi yang dipakai komunitas berbagimu. CERT-EU dirujuk di tingkat situs; halaman spesifik tentang TLP 2.0 perlu dicari di situs itu bila dibutuhkan.
