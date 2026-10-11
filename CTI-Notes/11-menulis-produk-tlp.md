---
day: 11
title: 'Menulis produk CTI: struktur brief, BLUF, bahasa keyakinan, dan Traffic Light Protocol 2.0'
researched_on: 2026-10-10
versions_checked: 'FIRST TLP 2.0 (berlaku sejak Agustus 2022); ICD 203 (bahasa estimatif); rujukan Day 01-03, 07, 10'
---

# Day 11: Menulis produk CTI dan TLP

Cakupan: cara menulis produk intelijen yang dibaca dan dipakai, mulai dari memilih jenis produk dan menyusun BLUF sampai menyatakan kemungkinan dan keyakinan dengan benar, lalu menandai batas berbaginya dengan TLP 2.0.

## Ide inti

Produk tertulis adalah wajah CTI. Betapapun bagus analisisnya, produk yang membingungkan, terlalu panjang, atau salah sasaran tidak menghasilkan tindakan. Itu kegagalan dissemination (Day 02), dan sering terjadi justru pada analis yang teknisnya kuat. Menulis produk yang baik punya aturan yang bisa dipelajari: sesuaikan dengan konsumen, mulai dari kesimpulan, nyatakan ketidakpastian dengan kosakata yang disepakati, dan akhiri dengan tindakan yang punya pemilik dan tenggat. TLP menandai sampai mana produk boleh dibagikan, sehingga sumber terlindungi dan mitra tetap mau berbagi.

Kamu sudah menulis versi kecil produk ini setiap kali mengeskalasi insiden. Pesan eskalasi ke on-call manager tidak dibuka dengan kronologi log; isinya apa yang terjadi, host mana yang terdampak, seberapa yakin kamu bahwa ini true positive, dan keputusan apa yang dibutuhkan. Laporan insiden lengkap menyusul, dengan ringkasan di halaman pertama untuk manajemen dan lampiran timeline serta IOC untuk tim teknis, dan tiketnya punya klasifikasi kerahasiaan yang menentukan siapa boleh membacanya. Produk CTI memakai pola yang sama: BLUF adalah pesan eskalasi itu, lampiran teknis adalah timeline-nya, bahasa estimatif dan keyakinan adalah confidence pada alert yang dinyatakan dengan kosakata yang disepakati, dan TLP adalah klasifikasi tiket yang tetap berlaku setelah dokumen keluar dari organisasi. Bedanya, pembaca produk CTI sering bukan orang teknis, dan TLP mengikat penerima yang tidak kamu kendalikan, sehingga label harus dihormati di setiap langkah penerusan.

```
Analisis selesai (profil, penilaian, IOC)
  -> konsumen siapa, keputusan apa?  -> jenis produk: brief, lampiran teknis, flash alert, jawaban RFI
  -> BLUF                            : apa | jadi apa bagi kita | seberapa yakin | lalu apa
  -> isi                             : penilaian (kemungkinan + keyakinan) | bukti (sumber + Admiralty) | alternatif
  -> rekomendasi                     : tindakan, pemilik, tenggat
  -> label TLP                       : warisi label sumber paling ketat; pisahkan lampiran bila perlu
  -> revisi -> kirim -> umpan balik konsumen
```

Situasi yang dipakai sepanjang Day ini: profil ISET-FICTA beserta kampanye LOGI-FICTA sudah terbit di PT Logistik Contoh (PT LC, perusahaan logistik fiktif dengan gudang di Jakarta, Surabaya, dan Medan) sebagai produk internal CTI-2026-041 dan sudah dioperasionalkan SOC (Day 10). CISO ingin membawanya ke rapat direksi, tetapi Direktur Operasional mengembalikan dokumen itu. CISO lalu menulis ke tim CTI:

> "Direktur Operasional mengembalikan CTI-2026-041. Katanya terlalu panjang, penuh nama teknik, dan ia tidak tahu apa yang diminta darinya. Tolong siapkan ulang sebelum rapat direksi Senin:
> 1. Siapa menerima apa? Direksi tidak butuh daftar domain, dan SOC tidak butuh paragraf soal tren.
> 2. Apa yang harus terbaca di tiga kalimat pertama, kalau direksi berhenti membaca di situ?
> 3. Draf kalian menulis 'mungkin akan menyerang kita'. Mungkin itu seberapa besar, dan seberapa yakin kalian?
> 4. Mana yang benar-benar kita amati, mana yang dugaan kalian?
> 5. Saya mau meneruskan brief-nya ke anak perusahaan dan sebagian ke ISAC, padahal ada bahan dari briefing mitra. Label apa yang dipasang, dan apa yang boleh dibagikan?"

Pertanyaan 1 dijawab oleh jenis produk dan struktur produk (bagian 1.1, 1.6, 2.1, dan 2.2). Pertanyaan 2 adalah BLUF (bagian 1.2 dan 2.1). Pertanyaan 3 adalah bahasa estimatif dan keyakinan (bagian 1.3, 1.4, dan 2.3). Pertanyaan 4 adalah pemisahan fakta dan penilaian (bagian 1.5). Pertanyaan 5 adalah TLP, pewarisan label, dan PAP (bagian 1.7 sampai 1.9 dan 2.4). Sebelum dikirim, semua jawaban diuji ulang dengan urutan revisi di bagian 1.10.

**Kapan relevan:** setiap produk CTI tertulis, termasuk pesan singkat di chat insiden, dan setiap kali berbagi dengan pihak luar.
**Kapan bukan jawaban:** format akhir mengikuti kebijakan organisasi, jadi struktur di Day ini perlu disesuaikan. TLP adalah kesepakatan berbagi, bukan skema klasifikasi hukum, dan tidak menggantikan NDA atau kewajiban regulasi.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Tabel ini memuat istilah yang muncul di Day ini. Kolom padanan memakai analogi SOC yang sama di semua Day CTI. Istilah dari Day sebelumnya (dissemination, RFI, PIR, kode Admiralty, ACH, keyakinan, fakta dan penilaian, ICD 203, TLP 2.0, PAP, defang) tidak diulang.

| Istilah | Arti singkat | Padanan di SOC |
|---|---|---|
| Produk intelijen | Hasil analisis CTI dalam bentuk yang dikirim ke konsumen tertentu | Laporan atau notifikasi yang dikirim SOC ke stakeholder |
| Flash alert | Produk singkat untuk ancaman aktif atau kerentanan yang sedang dieksploitasi | Notifikasi insiden kritis yang dikirim sebelum investigasi selesai |
| Threat assessment | Penilaian ancaman, kemungkinan, dampak, dan rekomendasi untuk CISO atau manajemen risiko | Penilaian dampak insiden untuk manajemen |
| Brief strategis | Produk satu halaman untuk pimpinan tentang risiko bisnis dan keputusan yang diminta | Ringkasan tren insiden kuartalan untuk direksi |
| Lampiran teknis | Bagian terpisah berisi TTP, IOC, rule, dan hunt untuk pelaksana | Lampiran timeline dan IOC di laporan insiden |
| BLUF (Bottom Line Up Front) | Kesimpulan dan tindakan ditulis di awal, detail menyusul | Pesan eskalasi ke on-call manager: apa yang terjadi, dampaknya, keputusan yang dibutuhkan |
| Bahasa estimatif | Kosakata kemungkinan dengan rentang angka yang disepakati tim | Kamus severity yang disepakati tim |
| Kemungkinan (likelihood) | Seberapa besar peluang sebuah peristiwa terjadi atau benar | Peluang sebuah alert adalah true positive |
| Pewarisan label | Produk gabungan memakai label TLP paling ketat dari sumbernya | Tiket gabungan mengikuti klasifikasi tiket paling rahasia yang dirujuknya |
| Indikator perubahan penilaian | Kondisi yang akan menaikkan atau menurunkan penilaian | Kondisi eskalasi di catatan tiket: naikkan severity bila host lain menunjukkan pola yang sama |

### 1.1 Jenis produk dan konsumennya

CTI-2026-041 dikembalikan karena dokumen yang ditulis untuk tim teknis dikirim utuh ke direksi. Masalahnya bukan kualitas analisis, melainkan jenis produknya: satu analisis butuh bentuk yang berbeda untuk konsumen yang berbeda.

Tabel berikut memasangkan jenis produk dengan konsumen dan pemicunya. Cari baris yang konsumennya cocok dengan penerimamu, lalu perhatikan kolom panjang, karena itu batas yang masih akan dibaca.

| Jenis produk | Konsumen | Pemicu | Panjang | Isi kunci |
|---|---|---|---|---|
| Flash alert | SOC, IR, admin sistem | Ancaman aktif atau kerentanan dieksploitasi | Setengah sampai satu halaman | Apa yang terjadi, siapa terdampak, tindakan dalam jam ini, IOC/TTP |
| Ringkasan berkala (mingguan) | Manajer keamanan, SOC lead | Jadwal | Satu sampai dua halaman | Tiga sampai lima item relevan dengan "so what" masing-masing |
| Threat assessment | CISO, manajemen risiko | PIR atau permintaan | Dua sampai lima halaman | Penilaian ancaman, kemungkinan, dampak, rekomendasi |
| Jawaban RFI | Peminta spesifik | Request for information | Sependek mungkin | Jawaban langsung atas pertanyaan, keyakinan, celah |
| Profil aktor atau kampanye | Analis, detection engineer, hunter | PIR | Beberapa halaman plus lampiran | TTP, procedure, IOC, deteksi dan hunt |
| Brief strategis | Pimpinan, board | Tren atau peristiwa besar | Satu halaman | Risiko bisnis, keputusan yang diminta |

Kesalahan yang paling sering adalah mengirim satu dokumen ke semua orang. Pimpinan tidak membaca daftar IOC, dan SOC tidak bisa bertindak dari paragraf tentang tren geopolitik. Bila satu analisis harus melayani dua konsumen, tulis dua produk: brief singkat untuk pengambil keputusan dan lampiran teknis untuk pelaksana. Untuk CTI-2026-041, artinya brief strategis untuk direksi (bagian 2.1) dan lampiran teknis untuk SOC (bagian 2.2).

### 1.2 BLUF (Bottom Line Up Front)

CISO menduga direksi berhenti membaca setelah beberapa kalimat. Karena itu kalimat-kalimat pertama brief harus memuat semua yang perlu diputuskan.

BLUF berarti kesimpulan dan tindakan ditulis di awal, lalu didukung oleh detail. Pembaca sibuk harus mendapat inti dalam dua sampai empat kalimat pertama, karena banyak yang tidak membaca lebih jauh.

BLUF yang baik menjawab empat hal:

1. **Apa:** temuan utamanya.
2. **Jadi apa:** dampaknya bagi organisasi ini, bukan bagi dunia secara umum.
3. **Seberapa yakin:** tingkat keyakinan kita.
4. **Lalu apa:** apa yang harus dilakukan, oleh siapa, dan kapan.

Contoh BLUF yang lemah: "Laporan ini membahas kampanye ransomware terbaru yang menargetkan berbagai sektor di Asia Tenggara dan teknik-teknik yang digunakan."

Versi yang kuat: "Kami menilai kemungkinan besar (keyakinan sedang) perusahaan logistik di Indonesia, termasuk kita, menjadi sasaran kampanye ransomware LOGI-FICTA dalam tiga bulan ke depan. Akses awalnya lewat lampiran .js dalam zip, yang saat ini lolos gateway email kita. Kami merekomendasikan tim email memblokir lampiran skrip dalam arsip minggu ini dan SOC menambah dua rule deteksi yang sudah kami siapkan."

Versi kedua bisa dihentikan setelah tiga kalimat dan pembaca tetap tahu apa yang harus dilakukan. Versi pertama hanya memberi tahu topik dokumen.

### 1.3 Bahasa estimatif: kosakata kemungkinan

Draf lama CTI-2026-041 menulis "mungkin akan menyerang kita", dan CISO langsung bertanya: mungkin itu seberapa besar?

Kata seperti "mungkin" atau "bisa jadi" ditafsirkan sangat berbeda oleh pembaca yang berbeda. Satu orang membacanya 20 persen, orang lain 60 persen. Karena itu tim CTI memakai kosakata terdefinisi. Skala yang banyak dirujuk berasal dari ICD 203 [S4]. Tabel berikut memasangkan istilah Inggrisnya dengan padanan Indonesia yang bisa dipakai; perhatikan kolom rentang, karena angka itulah yang disepakati tim.

| Istilah (Inggris) | Padanan yang bisa dipakai | Rentang kemungkinan |
|---|---|---|
| almost no chance / remote | hampir tidak mungkin | 1-5% |
| very unlikely / highly improbable | sangat kecil kemungkinannya | 5-20% |
| unlikely / improbable | kecil kemungkinannya | 20-45% |
| roughly even chance | kurang lebih sama besar | 45-55% |
| likely / probable | kemungkinan besar | 55-80% |
| very likely / highly probable | sangat mungkin | 80-95% |
| almost certain / nearly certain | hampir pasti | 95-99% |

Pilih satu set istilah Indonesia, tetapkan rentangnya di kebijakan tim, dan pakai secara konsisten. Lampirkan tabelnya di akhir produk untuk pembaca baru. Di brief CTI-2026-041, "mungkin" diganti "kemungkinan besar", yang berarti 55-80% menurut tabel tim.

### 1.4 Kemungkinan dan keyakinan

Pertanyaan CISO punya dua bagian: "seberapa besar" dan "seberapa yakin". Keduanya terdengar mirip, tetapi menjawab hal yang berbeda, sama seperti severity dan confidence pada alert.

Kemungkinan dan keyakinan adalah dua hal berbeda:

- **Kemungkinan** menjawab "seberapa besar peluang peristiwa ini terjadi atau benar".
- **Keyakinan** (rendah, sedang, tinggi) menjawab "seberapa kuat dasar penilaian kita": kualitas dan jumlah sumber, konsistensi bukti, dan seberapa banyak asumsi yang dipakai.

Keduanya bisa tidak sejalan. "Sangat mungkin (keyakinan rendah)" berarti indikasinya mengarah kuat tetapi berbasis satu sumber yang belum terkonfirmasi. ICD 203 juga meminta agar kemungkinan dan keyakinan tidak digabung dalam satu kalimat yang membingungkan; nyatakan keduanya dengan jelas.

Definisi kerja tingkat keyakinan yang bisa kamu pakai:

- **Tinggi:** beberapa sumber andal dan independen, bukti konsisten, sedikit asumsi.
- **Sedang:** sumber andal tetapi terbatas atau belum terkonfirmasi silang, atau ada celah informasi yang berarti.
- **Rendah:** sumber tunggal atau keandalan diragukan, bukti terfragmentasi, banyak asumsi.

Brief CTI-2026-041 bersandar pada dua laporan vendor dan aktivitas yang sudah teramati di jaringan PT LC, tetapi kaitan aktivitas itu dengan LOGI-FICTA baru berdasar kemiripan pola, sehingga keyakinannya sedang (bagian 2.1).

### 1.5 Memisahkan fakta, penilaian, dan sumber

Pertanyaan keempat CISO ("mana yang kita amati, mana dugaan") adalah pertanyaan yang sama dengan yang diajukan reviewer laporan forensik: mana artefak, mana interpretasi.

Pembaca harus bisa membedakan apa yang diamati dari apa yang disimpulkan. Pola kalimat yang membantu, dengan contoh dari bahan CTI-2026-041:

- Fakta: "Pada 7 Oktober, gateway email mencatat 42 email dengan lampiran zip berisi berkas .js ke 11 penerima di divisi keuangan."
- Penilaian: "Kami menilai kemungkinan besar (keyakinan sedang) email ini bagian dari kampanye LOGI-FICTA, karena pola lampiran dan domain pengirimnya cocok dengan laporan vendor A."

Sertakan keandalan sumber dengan skala Admiralty (Day 03), misalnya "laporan vendor A (B2)". Pembaca teknis memakai kode ini untuk menimbang sendiri, dan kode itu juga menjaga kejujuranmu ketika semua bukti berasal dari satu tempat. Di brief bagian 2.1, setiap butir "Kenapa penting" diberi label `[fakta, sumber B2]` atau `[penilaian]`.

Bila ada pandangan alternatif yang masuk akal, tuliskan. Kalimat seperti "kemungkinan lain adalah aktor berbeda yang memakai builder yang sama; kami menilainya kecil kemungkinannya karena..." menunjukkan bahwa analisis mempertimbangkan hipotesis lain (ACH, Day 03).

### 1.6 Struktur produk

Brief dan lampiran CTI-2026-041 ditulis orang yang berbeda di tim CTI, tetapi harus terbaca sebagai satu produk. Kerangka yang sama membuat konsumen tahu di mana mencari BLUF, bukti, dan rekomendasi.

Tabel berikut adalah struktur umum yang bisa disesuaikan dengan kebijakan organisasi. Perhatikan kolom catatan: di sana letak aturan yang paling sering dilanggar, seperti label TLP di setiap halaman dan rekomendasi yang punya pemilik.

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

Bagian "apa yang bisa mengubah penilaian" sering terlupa padahal sangat berguna: misalnya "penilaian ini akan naik bila kami melihat procedure yang sama di jaringan kita; turun bila vendor B mengonfirmasi kampanye berhenti". Ini memberi pembaca indikator untuk dipantau, seperti kondisi eskalasi di catatan tiket.

### 1.7 Traffic Light Protocol 2.0

CISO ingin meneruskan brief ke anak perusahaan dan sebagian ke ISAC. Sebelum dikirim, setiap produk butuh label yang menyatakan sampai mana ia boleh diteruskan.

TLP dari FIRST menandai batas berbagi informasi. TLP 2.0 memakai lima label [S2]. Tabel berikut adalah definisi kelima label itu; baca kolom kedua sebagai jawaban atas pertanyaan "dari penerima pertama, siapa saja yang boleh menerima berikutnya?".

| Label | Siapa boleh menerima dari penerima pertama |
|---|---|
| TLP:RED | Tidak diteruskan sama sekali; hanya untuk individu penerima, umumnya disampaikan langsung dalam rapat atau percakapan |
| TLP:AMBER+STRICT | Hanya anggota organisasi penerima, atas dasar perlu tahu |
| TLP:AMBER | Anggota organisasi penerima dan klien-kliennya, atas dasar perlu tahu untuk melindungi diri atau mencegah kerugian |
| TLP:GREEN | Komunitas penerima (rekan dan mitra), tetapi tidak lewat kanal yang bisa diakses publik |
| TLP:CLEAR | Tanpa batas; boleh dipublikasikan, dengan tetap mengikuti aturan hak cipta |

Dua hal dari versi sebelumnya memengaruhi cara menulis label hari ini: TLP:WHITE berganti nama menjadi TLP:CLEAR, dan TLP:AMBER+STRICT ditambahkan untuk kasus yang dulu sering ditulis sebagai "TLP:AMBER, hanya internal" [S2][S3]. Bila komunitas untuk TLP:GREEN tidak didefinisikan, standar mengasumsikan komunitas keamanan siber dan pertahanan.

Aturan penulisan:

- Label ditulis huruf kapital tanpa spasi: `TLP:AMBER`, `TLP:AMBER+STRICT`.
- Di email, label ditaruh di baris subjek dan sebelum isi pesan.
- Di dokumen, label ditaruh di header dan footer setiap halaman, rata kanan menurut spesifikasi.
- Label berwarna memakai warna yang ditentukan standar di atas latar hitam (misalnya teks kuning-oranye untuk AMBER), agar tetap terbaca di layar dan cetak.
- Bila sebagian isi punya label berbeda, tandai per bagian.

### 1.8 Menghormati TLP sumber

Bahan CTI-2026-041 berasal dari tiga sumber dengan label berbeda, termasuk briefing mitra berlabel TLP:AMBER+STRICT yang berisi IOC dari insiden mitra. Label produk tidak bisa dipilih bebas; ia ditentukan oleh label bahannya.

TLP hanya bekerja bila dihormati:

- **Jangan melonggarkan label.** Informasi TLP:AMBER dari mitra tidak boleh kamu tulis ulang sebagai TLP:GREEN.
- **Minta izin untuk berbagi lebih luas.** Hanya pemberi informasi yang bisa melonggarkan label.
- **Warisi label paling ketat.** Produk yang menggabungkan beberapa sumber memakai label paling ketat dari sumber itu, atau pisahkan bagian yang ketat ke lampiran tersendiri.
- **Ingat sistem yang ikut membaca.** Mengunggah produk TLP:AMBER+STRICT ke platform yang bisa diakses vendor, MSSP, atau kontraktor bisa berarti penyebaran di luar organisasi.

Keputusan label untuk tiga sumber CTI-2026-041 ada di bagian 2.4.

### 1.9 PAP: tindakan yang boleh dilakukan terhadap indikator

Lampiran untuk SOC memuat IOC, dan SOC tidak hanya bertanya siapa boleh membacanya. Mereka juga bertanya apa yang boleh dilakukan terhadapnya: dicari di log sendiri, dicek ke layanan reputasi, atau langsung diblokir.

PAP (Permissible Actions Protocol) melengkapi TLP. TLP mengatur siapa boleh menerima informasi; PAP mengatur tindakan apa yang boleh dilakukan terhadap indikator. Contohnya, PAP:RED berarti hanya tindakan pasif yang tidak terdeteksi oleh penyerang (misalnya mencari di log sendiri), PAP:AMBER mengizinkan tindakan pasif yang mungkin terlihat (misalnya query ke layanan reputasi online), PAP:GREEN mengizinkan tindakan aktif seperti blokir, dan PAP:CLEAR tanpa batasan. Label ini sering dipakai di platform seperti MISP (Day 08). Cek definisi PAP yang dipakai komunitasmu, karena PAP tidak dikelola FIRST seperti TLP.

Lampiran teknis di bagian 2.2 memberi IOC-nya PAP:GREEN, sehingga SOC boleh memblokirnya, walaupun lampiran itu sendiri berlabel TLP:AMBER+STRICT dan tidak boleh keluar organisasi.

### 1.10 Revisi

Sebelum dikirim ulang ke Direktur Operasional, draf baru CTI-2026-041 melewati satu putaran revisi. Draf pertama jarang cukup, dan urutan di bawah mengecek kelima pertanyaan CISO sekaligus.

Revisi dengan urutan ini:

1. **Uji BLUF.** Bacakan hanya paragraf pertama ke rekan. Bila ia tidak bisa menyebut tindakan yang diminta, tulis ulang.
2. **Buang yang tidak melayani konsumen.** Riwayat aktor lima tahun ke belakang jarang dibutuhkan pimpinan.
3. **Periksa setiap kata kemungkinan.** Apakah memakai istilah dari tabel tim? Apakah keyakinan dinyatakan?
4. **Periksa fakta dan sumber.** Setiap klaim fakta punya sumber; setiap penilaian punya dasar.
5. **Periksa rekomendasi.** Setiap butir punya pemilik dan tenggat.
6. **Periksa TLP.** Label di subjek, header, footer; label sesuai sumber paling ketat.
7. **Periksa IOC.** Semua ter-defang di teks.

Ukuran akhirnya adalah apakah konsumen bisa bertindak setelah membaca, dan apakah kamu mendapat umpan balik bahwa produk itu dipakai.

## 2. Contoh artefak intelijen

Semua contoh di bagian ini fiktif dan berupa ilustrasi; kampanye LOGI-FICTA, nomor produk, rule, dan hunt dibuat untuk latihan, dan IOC di-defang. Keempat artefak di bawah adalah jawaban tim CTI PT LC untuk pesan CISO di bagian Ide inti.

### 2.1 Brief strategis untuk pimpinan

Ini versi CTI-2026-041 yang dibawa ke rapat direksi: satu halaman, BLUF di atas, dan keputusan yang diminta tertulis jelas (pertanyaan 1 dan 2 CISO).

```
TLP:AMBER
CTI-2026-041 | 2026-10-10 | Analis: tim CTI | Menjawab PIR-02 (ancaman ransomware terhadap operasi)
Judul: Kampanye ransomware LOGI-FICTA berisiko mengganggu operasi gudang

BLUF
Kami menilai kemungkinan besar (keyakinan sedang) perusahaan kita menjadi sasaran
gelombang berikutnya kampanye ransomware LOGI-FICTA dalam tiga bulan ke depan. Kampanye ini sudah
melumpuhkan sistem gudang enam perusahaan logistik di kawasan sejak Juli. Celah
utama kita ada di penyaringan lampiran email, yang bisa ditutup minggu ini tanpa
biaya tambahan. Kami meminta persetujuan untuk perubahan kebijakan email tersebut.

Kenapa penting
- Korban teramati semuanya logistik, tiga di antaranya di Indonesia [fakta, sumber B2].
- Rata-rata gangguan operasional korban yang dilaporkan lebih dari satu minggu [fakta, sumber B3].
- Profil kita (sektor, wilayah, sistem gudang) cocok dengan pola korban [penilaian].

Yang diminta
1. Persetujuan memblokir lampiran skrip dalam arsip di email (Kepala TI, minggu ini).
2. Prioritas dua rule deteksi dan dua hunt yang sudah disiapkan (SOC Lead, 30 hari).

Keterbatasan
Penilaian bersandar pada dua laporan vendor dan aktivitas di jaringan kita: intrusi
6-8 Oktober sudah ditangani, dan 42 email bertema faktur masuk ke divisi keuangan
pada 7 Oktober. Kaitannya dengan LOGI-FICTA baru berdasar kemiripan pola.
Penilaian naik bila hunt menemukan aktivitas lanjutan di host lain.
TLP:AMBER
```

### 2.2 Lampiran teknis untuk SOC

Ini bagian CTI-2026-041 yang dipisahkan dari brief supaya direksi tidak menerima daftar teknik, sementara SOC tetap mendapat semua yang bisa dikerjakan (pertanyaan 1 CISO).

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

### 2.3 Menulis ulang paragraf yang buruk

Paragraf "sebelum" di bawah adalah jenis kalimat yang membuat Direktur Operasional mengembalikan draf lama, termasuk kata "mungkin" yang ditanyakan CISO (pertanyaan 3).

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

### 2.4 Keputusan TLP saat menggabungkan sumber

Ini jawaban untuk pertanyaan 5 CISO: label tiap produk ditentukan dari label ketiga sumbernya, dan IOC mitra hanya bisa sampai ke ISAC lewat izin mitra.

```
Sumber 1: laporan vendor A       TLP:CLEAR
Sumber 2: email ISAC             TLP:GREEN
Sumber 3: briefing mitra         TLP:AMBER+STRICT (berisi IOC dari insiden mitra)
Produk   : brief pimpinan tanpa IOC mitra -> TLP:AMBER (isi dari sumber 1-2, plus penilaian internal)
           lampiran berisi IOC mitra       -> TLP:AMBER+STRICT (warisi sumber 3)
Bila ingin membagikan IOC mitra ke ISAC: minta izin mitra lebih dulu.
```

## 3. Lab praktik

**Prasyarat:** editor teks dan skenario fiktif (bisa memakai profil ISET-FICTA dari Day 09 dan artefak Day 10). Jangan menyebarkan produk fiktif seolah nyata.

1. **Kebijakan istilah.** Tulis tabel bahasa estimatif tim fiktifmu (istilah Indonesia dan rentangnya) dan definisi tiga tingkat keyakinan.
2. **Dua produk.** Untuk skenario yang sama, tulis brief strategis satu halaman dan lampiran teknis untuk SOC.
3. **BLUF.** Pastikan BLUF tiap produk menjawab apa, jadi apa, seberapa yakin, lalu apa. Uji dengan membacakannya ke orang lain.
4. **Fakta dan penilaian.** Tandai setiap kalimat di brief sebagai fakta atau penilaian, dan pastikan setiap fakta punya sumber dengan kode Admiralty.
5. **Alternatif.** Tambahkan satu hipotesis alternatif dan indikator yang bisa mengubah penilaian.
6. **TLP.** Gabungkan tiga sumber fiktif dengan label berbeda dan tentukan label tiap produk, seperti bagian 2.4.
7. **Revisi.** Ambil satu paragraf buruk (tulis sendiri atau dari draf lama) dan revisi seperti bagian 2.3, lengkap dengan daftar masalahnya.
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

## 4. Troubleshooting

Tabel ini dipakai saat produk sudah terkirim tetapi hasilnya tidak sesuai harapan; mulai dari kolom gejala.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Pimpinan tidak membaca | Terlalu teknis atau panjang | Satu halaman, BLUF, keputusan yang diminta |
| Pesan utama hilang | Kesimpulan di akhir | Pindahkan ke BLUF |
| Pembaca salah menangkap tingkat kepastian | Istilah kemungkinan tidak terdefinisi | Pakai tabel istilah tim; nyatakan keyakinan terpisah |
| Produk dianggap menakut-nakuti | Bahasa pemasaran, tanpa bukti | Hapus superlatif; tunjukkan fakta dan sumber |
| Tidak ada tindakan setelah produk terbit | Rekomendasi tanpa pemilik dan tenggat | Tulis pemilik dan tenggat per butir |
| Produk tersebar tidak semestinya | Label salah atau tidak diwariskan | Label paling ketat; pisahkan lampiran |
| Mitra berhenti berbagi | TLP sumber dilonggarkan | Minta izin sebelum memperluas penyebaran |

## 5. Kesalahan umum dan jebakan

- **Satu produk untuk semua konsumen.** Pisahkan brief dan lampiran teknis.
- **Kesimpulan di akhir.** Pakai BLUF.
- **Mencampur kemungkinan dan keyakinan.** "Kemungkinan besar" dan "keyakinan sedang" menjawab pertanyaan berbeda.
- **Superlatif tanpa bukti.** "Paling canggih" atau "sangat berbahaya" merusak kredibilitas.
- **Menyembunyikan keterbatasan.** Keterbatasan yang jujur membuat penilaian lebih dipercaya.
- **Menyamakan TLP dengan PAP.** TLP mengatur siapa menerima, PAP mengatur tindakan terhadap indikator.
- **Memakai TLP:WHITE.** Sudah diganti TLP:CLEAR di TLP 2.0.

## 6. Catatan terkini

Bagian ini menampung status versi TLP dan perkembangan kebiasaan menulis produk. Berguna saat mengutip standar, tetapi tidak mengubah aturan di bagian 1.

- TLP 2.0 dari FIRST berlaku sejak Agustus 2022 dan tetap versi yang berlaku. Perubahan utamanya dari 1.0 adalah TLP:CLEAR menggantikan TLP:WHITE dan penambahan TLP:AMBER+STRICT [S2][S3].
- Penulisan BLUF dan bahasa estimatif terdefinisi makin umum di tim CTI swasta, dipengaruhi standar analitik pemerintah seperti ICD 203 [S4].
- Produk makin sering dilengkapi pemetaan ATT&CK, IOC dalam STIX (Day 07), dan rule siap pakai (Day 10) agar bisa langsung dioperasionalkan.

## 7. Cheat sheet

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

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Mitra mengirim laporan berlabel TLP:AMBER ke PT LC. Seorang analyst menulis ulang isinya dengan kata-katanya sendiri, lalu memberi label TLP:GREEN supaya bisa dikirim ke ISAC. Karena kalimatnya sudah baru, apakah itu boleh?

<details><summary>Jawaban</summary>

Tidak. Menulis ulang tidak mengubah asal informasinya, jadi label sumber tetap berlaku. Informasi TLP:AMBER dari mitra tidak boleh ditulis ulang sebagai TLP:GREEN, dan hanya pemberi informasi yang bisa melonggarkan label. Langkah yang benar adalah meminta izin mitra lebih dulu. Melonggarkan label tanpa izin juga salah satu penyebab mitra berhenti berbagi. Lihat bagian 1.8, 2.4, dan 4.

</details>

**2. Skenario keputusan.** Brief CTI-2026-041 dibangun dari laporan vendor A (TLP:CLEAR), email ISAC (TLP:GREEN), dan briefing mitra (TLP:AMBER+STRICT) yang berisi IOC dari insiden mitra. CISO ingin brief-nya bisa diteruskan ke anak perusahaan. Pilihan mana yang paling tepat?

- A. Beri seluruh produk label TLP:CLEAR, karena sebagian besar bahannya berasal dari laporan publik.
- B. Jadikan brief dan semua IOC satu dokumen berlabel TLP:AMBER+STRICT.
- C. Tulis brief tanpa IOC mitra dengan label TLP:AMBER, dan taruh IOC mitra di lampiran berlabel TLP:AMBER+STRICT.

<details><summary>Jawaban</summary>

C. Produk gabungan mewarisi label paling ketat dari sumbernya, atau bagian yang ketat dipisahkan ke lampiran tersendiri. Dengan memisahkan IOC mitra, brief cukup berlabel TLP:AMBER sehingga boleh sampai ke anak perusahaan sebagai klien yang perlu tahu, sedangkan lampiran tetap hanya di dalam organisasi. A keliru karena melonggarkan label sumber 2 dan 3, padahal hanya pemberi informasi yang boleh melakukannya. B memang patuh aturan pewarisan, tetapi seluruh dokumen menjadi hanya untuk internal, sehingga brief tidak bisa diteruskan ke anak perusahaan seperti yang diminta. Lihat bagian 1.7, 1.8, 2.2, dan 2.4.

</details>

**3. Pertanyaan jebakan.** Sebuah penilaian ditulis "sangat mungkin (keyakinan rendah)". Rekanmu bilang kalimat itu bertentangan dengan dirinya sendiri dan harus diperbaiki. Benarkah?

<details><summary>Jawaban</summary>

Tidak. Kemungkinan dan keyakinan menjawab dua pertanyaan berbeda. Kemungkinan menjawab seberapa besar peluang peristiwa itu terjadi atau benar; keyakinan menjawab seberapa kuat dasar penilaiannya. "Sangat mungkin (keyakinan rendah)" berarti indikasinya mengarah kuat, tetapi berbasis satu sumber yang belum terkonfirmasi. Yang perlu dihindari justru mencampur keduanya dalam satu kalimat yang membingungkan; ICD 203 meminta keduanya dinyatakan dengan jelas. Lihat bagian 1.4.

</details>

**4. Jelaskan ulang.** Jelaskan kepada analyst baru di tim CTI PT LC dalam tiga kalimat apa itu BLUF dan kenapa Direktur Operasional mengembalikan CTI-2026-041.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "BLUF berarti kesimpulan dan tindakan ditulis di awal, lalu detailnya menyusul, karena banyak pembaca sibuk berhenti setelah dua sampai empat kalimat. BLUF yang baik menjawab apa temuannya, apa dampaknya bagi PT LC, seberapa yakin kita, dan apa yang harus dilakukan, oleh siapa, kapan. Draf lama dikembalikan karena dokumen untuk tim teknis dikirim utuh ke direksi tanpa BLUF dan tanpa keputusan yang diminta, jadi kita memecahnya menjadi brief satu halaman untuk direksi dan lampiran teknis untuk SOC."

Kesalahan yang sering muncul:
- Menyamakan BLUF dengan ringkasan topik ("laporan ini membahas ..."), padahal BLUF memuat kesimpulan dan tindakan.
- Lupa menyebut tingkat keyakinan di BLUF.
- Menulis dampak bagi dunia secara umum, bukan bagi organisasi ini.
- Menulis tindakan tanpa pemilik dan tenggat.

</details>

**5. Skenario keputusan.** Pagi ini diketahui sebuah kerentanan (fiktif) pada produk yang dipakai PT LC sedang dieksploitasi aktif. SOC, IR, dan admin sistem perlu bertindak hari ini. Produk apa yang ditulis?

- A. Threat assessment dua sampai lima halaman untuk CISO.
- B. Flash alert setengah sampai satu halaman untuk SOC, IR, dan admin sistem.
- C. Butir di ringkasan mingguan berikutnya.

<details><summary>Jawaban</summary>

B. Flash alert dipicu ancaman aktif atau kerentanan yang dieksploitasi, ditujukan ke SOC, IR, dan admin sistem, dan berisi apa yang terjadi, siapa terdampak, tindakan dalam jam ini, serta IOC atau TTP. A keliru karena threat assessment ditujukan ke CISO dan manajemen risiko dengan pemicu PIR atau permintaan; panjangnya memperlambat tindakan yang dibutuhkan hari ini. C keliru karena ringkasan berkala terikat jadwal, sehingga informasinya terlambat. Lihat bagian 1.1.

</details>

**6. Pertanyaan jebakan.** Event dari ISAC berlabel TLP:GREEN. Analyst SOC PT LC menyimpulkan, "Karena boleh dibagikan ke komunitas, indikatornya juga boleh langsung dicek ke layanan reputasi online dan diblokir di firewall." Benarkah?

<details><summary>Jawaban</summary>

Belum tentu. TLP hanya mengatur siapa boleh menerima informasi; tindakan terhadap indikator diatur PAP. Bila indikatornya berlabel PAP:RED, hanya tindakan pasif yang tidak terdeteksi penyerang yang boleh dilakukan, misalnya mencari di log sendiri. Query ke layanan reputasi online baru boleh pada PAP:AMBER, dan blokir pada PAP:GREEN. Karena PAP tidak dikelola FIRST, cek juga definisi PAP yang dipakai komunitas ISAC itu. Lihat bagian 1.9 dan 5.

</details>

**7. Interview question (English).** "How do you make sure an intelligence report actually leads to action?"

<details><summary>Sample answer</summary>

"I start with who will act on it and what decision they need to make, and I write separate products for separate consumers: a one-page brief for leadership and a technical annex for the SOC, instead of one document for everyone. Each product opens with a bottom line up front: what we found, what it means for us specifically, how confident we are, and what should be done, by whom and by when. I use a defined set of estimative terms, so 'likely' means the same range to every reader, and I state confidence separately, because likelihood and confidence answer different questions. I mark facts and assessments clearly, cite sources with reliability codes, include alternatives and what would change the assessment, and every recommendation has an owner and a deadline. Before sending, I apply the strictest TLP label from the sources, split partner-restricted material into an annex if needed, and ask for feedback so I know the product was used."

What makes this answer strong: it ties writing to consumers and decisions, shows command of BLUF and estimative language, separates likelihood from confidence, and treats TLP handling and feedback as part of making intelligence actionable.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | CTI-note Day 01-03, 07, 10 | (lokal) | rujukan internal | 2026-10-09 | Konsumen, siklus, Admiralty, ACH, IOC, operasionalisasi |
| S2 | FIRST: Traffic Light Protocol (TLP) 2.0 | https://www.first.org/tlp/ | primer | diakses 2026-10-09 | Tinggi. Definisi label, aturan penulisan, warna |
| S3 | CERT-EU: TLP version 2 | https://www.cert.europa.eu/ | sekunder | diakses 2026-10-09 | Sedang-tinggi. Ringkasan perubahan TLP 1.0 ke 2.0 |
| S4 | ODNI: Intelligence Community Directive 203, Analytic Standards | https://www.dni.gov/files/documents/ICD/ICD-203.pdf | primer | diakses 2026-10-09 | Tinggi. Skala bahasa estimatif dan pemisahan kemungkinan dari keyakinan |
| S5 | MITRE ATT&CK | https://attack.mitre.org/ | primer | diakses 2026-10-09 | Tinggi. Pemetaan TTP di lampiran teknis |

**Catatan sumber:** definisi kerja tiga tingkat keyakinan di bagian 1.4 dan struktur produk di bagian 1.6 adalah praktik umum yang perlu disesuaikan dengan kebijakan organisasi, bukan isi baku dari satu standar. Definisi PAP di bagian 1.9 mengikuti penggunaan yang lazim di komunitas MISP; PAP tidak diterbitkan FIRST, jadi cocokkan dengan definisi yang dipakai komunitas berbagimu. CERT-EU dirujuk di tingkat situs; halaman spesifik tentang TLP 2.0 perlu dicari di situs itu bila dibutuhkan.
