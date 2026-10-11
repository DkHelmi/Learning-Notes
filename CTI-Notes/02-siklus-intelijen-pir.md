---
day: 02
title: 'Siklus intelijen dan PIR: dari kebutuhan pemangku kepentingan ke intelijen yang dipakai'
researched_on: 2026-10-10
versions_checked: 'Konsep stabil (intelligence cycle, PIR/RFI); JP 2-0 dirujuk lewat ringkasan CRS IF10574 (Januari 2026); MWR/CPNI 2015'
---

# Day 02: Siklus intelijen dan PIR

Cakupan: siklus intelijen sebagai proses berulang, cara menggali kebutuhan pemangku kepentingan menjadi PIR yang bisa dijawab, menurunkannya ke sub-pertanyaan dan collection plan, serta menutup siklus dengan dissemination dan umpan balik.

## Ide inti

Program CTI bekerja dari pertanyaan, bukan dari data. Siklus intelijen adalah disiplin yang menjaga urutan itu: tetapkan dulu keputusan apa yang perlu didukung, tulis sebagai PIR (Priority Intelligence Requirement), kumpulkan hanya yang menjawab PIR, analisis sampai ada penilaian dan rekomendasi, kirim ke konsumen sebelum keputusannya dibuat, lalu minta umpan balik untuk memperbaiki putaran berikutnya. Tanpa proses ini, tim CTI cenderung mengumpulkan IOC tanpa arah dan menulis laporan yang tidak dipakai siapa pun. PIR yang buruk membuat seluruh siklus sia-sia, sebaik apa pun alat dan feed-nya.

Kamu sudah mengenal pola ini dari detection engineering. Rule yang baik tidak lahir dari "nyalakan semua rule bawaan", tetapi dari use case request: pertanyaan yang ingin dijawab sebelum rule ditulis. Dari situ kamu menentukan log source apa yang dibutuhkan, field apa yang harus ada, lalu rule ditulis, diuji, dan di-tuning setelah review false positive atau miss. PIR adalah use case request untuk intelijen, collection plan adalah peta log source-nya, dan umpan balik konsumen adalah tuning-nya. Bedanya, PIR terikat keputusan pengambil keputusan, bukan hanya ide deteksi. PIR juga menjadi bahan baku hipotesis threat hunting: pertanyaan "apakah teknik X dipakai aktor yang menyasar sektor kita" mudah diubah menjadi "apakah teknik X sudah terjadi di lingkungan kita".

```
Keputusan pemangku kepentingan (anggaran Q1: MFA vendor vs EDR server gudang)
  -> Direction    : PIR disetujui CISO -> SIR -> EEI
  -> Collection   : collection plan (sumber internal + eksternal, gap tertulis)
  -> Processing   : normalisasi, deduplikasi, asal dan tanggal di setiap data
  -> Analysis     : penilaian + rekomendasi + keyakinan
  -> Dissemination: produk per konsumen, tiba sebelum tanggal keputusan
  -> Feedback     : apa yang dipakai, apa yang kurang -> PIR putaran berikutnya
RFI (mendesak, sekali jalan) masuk dari samping: ditriase, dikaitkan ke PIR bila temanya sama
```

Situasi yang dipakai sepanjang Day ini: awal Oktober 2026, setelah diwawancarai tim CTI, CISO PT Logistik Contoh (PT LC, perusahaan logistik fiktif dengan gudang di Jakarta, Surabaya, dan Medan, WMS on-premise, portal pelanggan, dan banyak vendor yang masuk lewat VPN) mengirim pesan ke tim CTI:

> "Saya tidak mau lagi menerima kiriman berita ancaman tanpa arah. Desember nanti saya harus memilih anggaran Q1: MFA untuk akses vendor atau EDR untuk server gudang. Apa yang perlu kalian cari supaya pilihan saya bukan tebakan, dan kapan jawabannya siap? Satu lagi: jangan sampai permintaan mendadak dari IR menghabiskan waktu kalian."

Pesan itu memuat lima pertanyaan:

1. Bagaimana kerja tim CTI diatur supaya tidak berhenti di kumpulkan sekali, lapor sekali?
2. Apa beda kebutuhan program yang berkelanjutan dengan permintaan mendadak dari IR?
3. Bagaimana keputusan anggaran CISO diubah menjadi pertanyaan yang bisa dijawab?
4. Dari mana jawabannya dikumpulkan, dan bagian mana yang belum bisa dijawab?
5. Bagaimana jawabannya sampai ke CISO tepat waktu, dan bagaimana tim tahu jawabannya berguna?

Pertanyaan 1 dijawab di bagian 1.1 dan 1.2, pertanyaan 2 di bagian 1.3 dan 2.4, pertanyaan 3 di bagian 1.4 sampai 1.6 beserta 2.1 dan 2.2, pertanyaan 4 di bagian 1.7, 1.8, dan 2.3, dan pertanyaan 5 di bagian 1.9 dan 2.5.

**Kapan relevan:** saat menyiapkan atau merapikan program CTI, menentukan apa yang dikumpulkan, menilai apakah laporan menjawab kebutuhan, dan menolak permintaan yang tidak terikat keputusan.
**Kapan bukan jawaban:** sebagai urutan kerja yang kaku. Tim satu atau dua orang sering memadatkan tahap, dan itu wajar asalkan PIR dan umpan balik tetap ada. Model ini berasal dari doktrin militer, sehingga istilah dan hierarkinya perlu disesuaikan untuk perusahaan. Permintaan mendadak yang sekali jalan juga tidak perlu dijadikan PIR baru; jalurnya RFI.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Tabel ini memuat istilah yang muncul di Day ini. Kolom padanan memakai analogi SOC yang sama di semua Day CTI. Istilah dari Day 01 (CTI, feed IOC, requirements, konsumen, TTP, threat hunting, bahasa keyakinan) tidak diulang.

| Istilah | Arti singkat | Padanan di SOC |
|---|---|---|
| Siklus intelijen | Proses berulang dari kebutuhan sampai umpan balik | Siklus hidup use case deteksi: request, onboarding data, rule, tuning, review |
| Direction (planning) | Tahap menetapkan kebutuhan: PIR dan prioritasnya | Memilih use case mana yang dikerjakan dulu |
| Collection | Tahap mengumpulkan data dari sumber sesuai collection plan | Onboarding log source |
| Processing | Tahap mengubah data mentah menjadi bentuk yang bisa dianalisis | Parsing, field extraction, normalisasi, deduplikasi |
| Analysis (production) | Tahap memberi makna: menilai, mengorelasi, menyimpulkan dengan keyakinan | Investigasi: dari event ke kesimpulan |
| Dissemination | Tahap menyampaikan produk ke konsumen dalam bentuk dan waktu yang berguna | Mengirim laporan atau notifikasi SOC ke stakeholder yang tepat |
| Feedback | Konsumen menilai manfaat, lalu PIR diperbarui | Tuning setelah review false positive atau miss |
| Intelligence Requirement (IR) | Kebutuhan informasi umum organisasi | Daftar use case yang ingin ditutup |
| PIR | IR yang diprioritaskan karena terikat keputusan penting dan disetujui pimpinan | Use case request yang disetujui dan diprioritaskan |
| RFI (Request for Information) | Permintaan ad hoc yang spesifik dan sering mendesak | Tiket ad hoc dari IR: "cek domain ini" |
| SIR | Sub-pertanyaan PIR yang bisa dijawab satu jenis analisis | Satu use case turunan dari requirement besar |
| EEI | Fakta konkret yang dicari kolektor | Field yang harus ada di log supaya rule bisa jalan |
| Collection plan | Peta setiap sub-pertanyaan ke sumber, pengumpul, dan statusnya | Peta log source per use case, termasuk yang belum tersedia |
| Gap | Sub-pertanyaan yang belum punya sumber | Use case tanpa log source |

### 1.1 Siklus intelijen

CISO PT LC bertanya apa yang perlu dicari supaya pilihan anggarannya bukan tebakan. Sebelum menjawab, tim CTI butuh urutan kerja yang menjamin pertanyaan itu yang dijawab, bukan apa pun yang kebetulan muncul di feed.

Model yang paling sering dipakai di CTI punya lima tahap, ditambah umpan balik. Sebagian sumber memisahkan processing dan exploitation atau menjadikan feedback tahap sendiri, sehingga jumlahnya enam [S1][S2]. Tabel berikut menjadi daftar periksa: kolom terakhir adalah pertanyaan yang bisa kamu ajukan untuk tahu apakah sebuah tahap sudah dikerjakan dengan benar.

| Tahap | Isi | Pertanyaan kontrol |
|---|---|---|
| Direction (planning) | Tetapkan kebutuhan: PIR dan prioritasnya | Keputusan siapa yang didukung? |
| Collection | Kumpulkan data dari sumber sesuai collection plan | Apakah sumber ini menjawab sub-pertanyaan tertentu? |
| Processing | Ubah data mentah menjadi bentuk yang bisa dianalisis | Apakah data sudah dinormalisasi, dideduplikasi, diberi sumber dan tanggal? |
| Analysis (production) | Beri makna: nilai, korelasi, simpulkan dengan keyakinan | Apakah ada penilaian dan rekomendasi, bukan hanya ringkasan? |
| Dissemination | Sampaikan ke konsumen dalam bentuk dan waktu yang berguna | Apakah konsumen menerima sebelum keputusannya dibuat? |
| Feedback | Konsumen menilai manfaat; PIR diperbarui | Apa yang berubah untuk putaran berikutnya? |

Doktrin intelijen militer Amerika Serikat (Joint Publication 2-0) menyebut proses intelijen gabungan sebagai enam kategori operasi yang saling terkait: planning and direction, collection, processing and exploitation, analysis and production, dissemination and integration, serta evaluation and feedback [S2]. Kata "integration" di sana berguna untuk CTI: produk belum selesai sampai ia terintegrasi ke proses konsumen (masuk ke backlog detection, ke rapat risiko, atau ke playbook IR). Untuk CISO PT LC, artinya jawaban baru selesai ketika masuk ke rapat anggaran, bukan ketika laporannya terkirim.

### 1.2 Kenapa berulang, bukan garis lurus

Jawaban pertama untuk CISO PT LC hampir pasti memunculkan pertanyaan baru, misalnya soal biaya kontrol atau seberapa yakin tim pada nama kelompok yang disebut. Karena itu siklus digambar sebagai lingkaran.

Hasil satu putaran mengubah kebutuhan berikutnya. Temuan analisis memunculkan pertanyaan baru, umpan balik konsumen mempertajam PIR, dan gap pengumpulan mengarahkan koleksi berikutnya. Memperlakukan siklus sebagai garis lurus (kumpulkan sekali, lapor sekali) kehilangan nilai utamanya, yaitu penyempurnaan terus-menerus.

Dalam praktik, banyak putaran kecil berjalan paralel untuk PIR yang berbeda, dan tahap bisa tumpang tindih. Analis sering sudah menganalisis data awal sambil collection berjalan, dan bisa melompat kembali ke direction ketika ternyata PIR ambigu. Doktrin sendiri menyebut operasi intelijen tidak harus berurutan ketat [S2]. Gambar lingkaran rapi di slide adalah alat bantu pengajaran, bukan urutan kerja yang wajib.

### 1.3 Requirement, PIR, dan RFI

Pesan CISO memuat dua jenis permintaan: pertanyaan anggaran yang dijawab dalam hitungan minggu, dan permintaan mendadak dari IR yang harus dijawab hari itu juga. Keduanya dilayani tim yang sama, tetapi dikelola berbeda.

Tabel berikut membedakan tiga jenis kebutuhan. Perhatikan kolom "Siapa menetapkan" dan "Umur", karena dua kolom itu yang menentukan apakah sebuah permintaan masuk antrean PIR atau ditangani sebagai RFI. Di catatan ini, singkatan IR di kolom pertama berarti Intelligence Requirement, sedangkan "IR lead" di bagian lain berarti pemimpin incident response.

| Istilah | Arti | Siapa menetapkan | Umur |
|---|---|---|---|
| Intelligence Requirement (IR) | Kebutuhan informasi umum organisasi | Tim CTI bersama pemangku kepentingan | Berkelanjutan |
| Priority Intelligence Requirement (PIR) | IR yang diprioritaskan karena terikat keputusan penting | Pemangku kepentingan senior (CISO, kepala SOC, manajemen risiko) | Biasanya ditinjau tiap kuartal atau semester |
| Request for Information (RFI) | Permintaan ad hoc spesifik, sering mendesak | Konsumen mana pun | Sekali jalan, ditutup setelah dijawab |

PIR mengarahkan program secara berkelanjutan; RFI adalah permintaan sekali jalan. Keduanya dilacak dengan ID agar tim tahu apa yang sedang dijawab dan berapa lama. Hubungan keduanya penting: bila RFI dengan tema yang sama muncul berulang (misalnya tiga RFI dalam sebulan tentang kebocoran kredensial VPN), itu tanda ada PIR yang belum ditulis.

### 1.4 Hierarki PIR, sub-pertanyaan, dan elemen informasi

Pertanyaan anggaran CISO PT LC terlalu besar untuk diserahkan langsung ke analis yang membaca laporan vendor, apalagi ke rule otomatis di platform. Ia perlu dipecah sampai setiap orang tahu persis apa yang dicarinya.

Satu PIR biasanya terlalu besar untuk langsung dikumpulkan. Banyak tim memecahnya menjadi tiga lapis. Penamaan lapis ini berbeda antar organisasi; yang umum di CTI adalah PIR, lalu SIR (specific intelligence requirement), lalu EEI (essential element of information) [komunitas, penamaan bervariasi]. Tabel berikut menunjukkan bentuk tiap lapis; perhatikan bahwa makin ke bawah, isinya makin berupa fakta yang bisa dicari, bukan pertanyaan yang perlu dianalisis.

| Lapis | Bentuk | Contoh singkat (fiktif) |
|---|---|---|
| PIR | Pertanyaan terikat keputusan | Teknik akses awal apa dari kelompok ransomware penyasar logistik yang belum kita deteksi? |
| SIR | Pertanyaan yang bisa dijawab satu jenis analisis | Kelompok mana yang menyasar logistik Asia Tenggara dalam enam bulan terakhir? |
| EEI | Fakta konkret yang dicari kolektor | Nama kelompok, tanggal insiden, sektor korban, teknik akses awal yang dilaporkan, ID ATT&CK |

Manfaat hierarki ini praktis: kolektor (atau feed, atau rule otomatis di platform) bekerja di level EEI, sedangkan analis menyusun jawaban di level SIR dan PIR. Bila EEI tidak terdefinisi, kolektor mengumpulkan apa saja yang "terlihat terkait". Di SOC, ini sama dengan menulis rule tanpa tahu field apa yang dibutuhkan: rule-nya ada, tetapi tidak pernah bisa jalan dengan benar.

### 1.5 Anatomi PIR yang baik

Sebelum CISO PT LC menyetujui sebuah PIR, tim CTI perlu yakin drafnya bisa dijawab dan jawabannya akan dipakai. Lima kriteria berikut adalah alat uji drafnya.

Kriteria yang dipakai di catatan ini adalah sintesis praktik komunitas CTI dan doktrin [S1][komunitas]:

- **Terikat keputusan:** jawaban mengubah tindakan nyata (prioritas patching, investasi kontrol, backlog detection).
- **Spesifik:** menyebut ancaman, aset, atau aktivitas konkret.
- **Dapat dikumpulkan:** ada sumber yang sah dan realistis untuk menjawabnya.
- **Terikat waktu:** ada horizon pengamatan (enam bulan terakhir) dan tenggat keputusan (sebelum perencanaan anggaran Q1).
- **Satu pertanyaan:** PIR yang memuat tiga pertanyaan sekaligus sulit dinilai "terjawab atau belum".

Contoh berikut menunjukkan jalan dari pertanyaan kabur ke PIR yang bentuknya mirip PIR-2026-003 di bagian 2.2, langkah demi langkah:

1. Awal: "Apa ancaman siber terbaru?" Tidak ada keputusan, tidak spesifik, tidak ada horizon.
2. Tanya pemangku kepentingan keputusan apa yang dia buat: "Saya harus memutuskan tambahan kontrol untuk akses remote vendor tahun depan."
3. Persempit ke aset dan ancaman: akses remote vendor, ancaman yang memakai akses itu.
4. Tambah horizon dan sektor: "Dalam 12 bulan terakhir, apakah aktor yang menyasar perusahaan logistik di Asia Tenggara masuk lewat akses remote pihak ketiga (VPN, RMM, akun vendor), dan teknik apa yang mereka pakai, sehingga kita perlu menambah kontrol pada akses vendor sebelum anggaran Q1 dikunci?"
5. Uji: bila jawabannya "ya, dua dari lima insiden lewat akun vendor tanpa MFA", keputusan berubah (MFA wajib untuk vendor). Bila jawabannya "tidak ada bukti", keputusan juga berubah (anggaran dialihkan). PIR lolos uji.

### 1.6 Menggali kebutuhan dari pemangku kepentingan

Pilihan "MFA vendor atau EDR server gudang" tidak muncul dari pertanyaan "ancaman apa yang kamu khawatirkan?". Ia muncul dari wawancara yang menggali keputusan CISO PT LC (catatannya di bagian 2.1).

PIR jarang datang siap pakai. Kebanyakan pimpinan akan menjawab "beri tahu saya ancaman yang relevan". Tugas analis adalah mewawancarai mereka sampai keputusan yang sebenarnya muncul. Pertanyaan yang biasanya berhasil:

- Keputusan apa yang kamu buat dalam enam bulan ke depan yang bergantung pada keamanan?
- Kejadian apa yang paling kamu takutkan menimpa organisasi ini? (biasanya menyebut aset kritis atau "crown jewels")
- Kapan terakhir kali kamu terkejut oleh sebuah insiden atau berita, dan informasi apa yang seharusnya kamu dapat lebih awal?
- Dalam format apa dan seberapa sering kamu mau menerima informasi?
- Siapa lagi yang harus kami tanya?

Catat jawaban per pemangku kepentingan, kelompokkan tema yang berulang, lalu ajukan kembali draf PIR untuk disetujui. Persetujuan ini penting: PIR yang disetujui CISO memberi tim CTI dasar untuk menolak pekerjaan yang tidak terkait. Untuk tim yang baru mulai, tiga sampai tujuh PIR aktif sudah cukup; lebih dari itu biasanya tidak bisa dijawab dengan kapasitas yang ada.

### 1.7 Dari PIR ke collection plan

Setelah PIR-2026-003 dipecah, tim CTI PT LC harus menentukan siapa mencari apa, dari mana, dan seberapa sering. Sebagian jawaban ada di luar (laporan vendor, ISAC), sebagian lagi hanya ada di dalam (rule SIEM, laporan insiden sendiri).

Collection plan memetakan setiap SIR dan EEI ke sumber yang akan menjawabnya. Fungsinya ada tiga: mencegah pengumpulan tanpa arah, memperlihatkan gap (sub-pertanyaan tanpa sumber), dan menjadi dasar menilai sumber (sumber yang tidak pernah menjawab apa pun layak dihentikan). Elemen minimalnya: ID requirement, sub-pertanyaan, sumber yang direncanakan, siapa yang mengumpulkan, frekuensi, prioritas, dan status.

Dua kebiasaan yang membuat collection plan berguna. Pertama, sumber internal ditulis sejajar dengan sumber eksternal, karena telemetri dan laporan insiden sendiri sering menjawab sub-pertanyaan paling penting ("apakah ini sudah terjadi pada kita"). Kedua, gap ditulis eksplisit beserta keputusan atasnya: diterima sebagai risiko, dicari sumber pengganti, atau PIR dipersempit.

### 1.8 Processing yang sering diabaikan

Bahan untuk menjawab PIR-2026-003 datang dalam bentuk yang berbeda-beda: laporan vendor dalam PDF, feed dalam CSV dengan kolom berbeda, posting dalam bahasa lain. Sebelum analis bisa membandingkan semuanya, bahan itu harus dirapikan.

Processing mencakup normalisasi format, deduplikasi, penerjemahan, pemberian timestamp dan sumber, defang IOC, dan pengayaan awal. Data mentah jarang bisa langsung dianalisis. Tanpa processing yang rapi, analisis menjadi lambat dan rawan salah, misalnya domain yang sama tercatat dua kali dengan huruf besar dan kecil sehingga dianggap dua indikator. Di SOC, kesalahan yang sama terjadi bila field extraction tidak konsisten antar log source.

Satu aturan processing yang berdampak besar: setiap butir data harus membawa asal dan tanggalnya. Tanpa itu, kamu tidak bisa menilai keandalan sumber (Day 03) atau mendeteksi circular reporting (Day 05). Platform seperti MISP dan OpenCTI (Day 08) mengotomasi sebagian processing, tetapi keputusan apa yang disimpan dan bagaimana dinormalisasi tetap keputusan analis.

### 1.9 Dissemination, umpan balik, dan titik gagal

Brief untuk CISO PT LC tidak berguna bila tiba setelah rapat anggaran. CISO juga bertanya bagaimana tim tahu jawabannya berguna; jawabannya ada di umpan balik dan beberapa angka sederhana.

Dua tahap paling sering gagal:

- **Direction:** tanpa PIR yang jelas dan disetujui, tim mengumpulkan apa saja. Akar masalahnya biasanya kurangnya keterlibatan pimpinan, bukan kurangnya feed.
- **Dissemination:** intelijen bagus yang dikirim dalam format salah, ke orang yang salah, atau setelah keputusan dibuat, tidak berdampak. Produk harus sesuai konsumen (tingkat intelijen di Day 01) dan tenggatnya diikat ke kalender keputusan, bukan ke kapan analisis selesai.

Umpan balik sebaiknya diminta secara terstruktur, misalnya tiga pertanyaan singkat di akhir setiap produk: apakah ini menjawab pertanyaanmu, tindakan apa yang kamu ambil, apa yang kurang. Dari sana tim bisa mengukur program dengan angka sederhana: persentase PIR yang terjawab per kuartal, waktu rata-rata menjawab RFI, jumlah produk yang menghasilkan tindakan tercatat (rule baru, kontrol diubah, risiko diterima). Angka ini lebih jujur daripada jumlah IOC yang dikumpulkan.

## 2. Contoh artefak intelijen

Semua contoh di bagian ini fiktif dan berlabel ilustrasi; kelimanya mengikuti PIR-2026-003 PT LC dari wawancara CISO sampai umpan balik putaran pertama.

### 2.1 Catatan wawancara pemangku kepentingan

Ini catatan wawancara yang melahirkan pilihan anggaran di pesan CISO, ditulis dengan lima pertanyaan di bagian 1.6.

```
Wawancara: CISO PT Logistik Contoh (fiktif), 2026-10-01
Keputusan 6 bulan ke depan:
  - Anggaran Q1: MFA untuk akses vendor vs EDR untuk server gudang
  - Apakah portal pelanggan perlu WAF terkelola
Ketakutan terbesar: ransomware menghentikan sistem gudang (WMS) saat musim puncak
Terkejut terakhir: insiden di kompetitor lewat akun vendor; tahu dari berita
Format: brief 1 halaman bulanan + peringatan ad hoc via chat
Rujukan lain: kepala operasi gudang, manajer TI vendor
```

**Cara membaca hasil:** dua keputusan anggaran dan satu ketakutan sudah cukup untuk dua PIR. Kalimat "tahu dari berita" adalah kebutuhan dissemination: CISO ingin peringatan lebih cepat daripada media.

### 2.2 PIR lengkap dengan turunannya

Dari catatan wawancara itu, tim menulis PIR untuk keputusan anggaran Q1 dan memecahnya ke SIR dan EEI seperti di bagian 1.4.

```
PIR-2026-003  (disetujui CISO, 2026-10-03; tinjau ulang 2027-01-15)
Pernyataan: Dalam 12 bulan terakhir, apakah kelompok ransomware yang
  menyasar perusahaan logistik di Asia Tenggara masuk lewat akses remote
  pihak ketiga, dan teknik akses awal apa yang belum kita deteksi?
Keputusan terkait: prioritas anggaran Q1 (MFA vendor vs EDR gudang).
Tenggat jawaban: 2026-11-30 (rapat anggaran 2026-12-05).
SIR-003.1 Kelompok mana yang menyasar logistik Asia Tenggara 12 bulan terakhir?
  EEI: nama/cluster, tanggal, negara dan sektor korban, sumber
SIR-003.2 Teknik akses awal apa yang dipakai kelompok tersebut?
  EEI: ID ATT&CK (mis. T1133 External Remote Services, T1078 Valid Accounts,
       T1190 Exploit Public-Facing Application, T1566 Phishing), bukti per teknik
SIR-003.3 Teknik mana yang tidak kita deteksi atau cegah saat ini?
  EEI: daftar rule aktif per teknik, log source yang tersedia, hasil uji
Status: aktif
```

**Cara membaca hasil:** setiap SIR bisa dijawab oleh orang atau sumber yang berbeda. SIR-003.3 sepenuhnya internal; tanpa itu PIR hanya menghasilkan cerita tentang ancaman di luar, tidak sampai ke keputusan.

### 2.3 Collection plan

Tabel ini menjawab pertanyaan keempat CISO: dari mana jawaban PIR-2026-003 dikumpulkan, oleh siapa, dan apa yang belum punya sumber. Baca kolom Sumber dan Pengumpul bersamaan untuk melihat bahwa sumber internal duduk sejajar dengan sumber eksternal.

| Req | Sumber | Pengumpul | Frekuensi | Prioritas | Status |
|---|---|---|---|---|---|
| SIR-003.1 | Laporan vendor publik, advisori CERT nasional, ISAC sektor | Analis CTI | Mingguan | Tinggi | Berjalan |
| SIR-003.1 | Situs kebocoran ransomware (hanya lewat ringkasan vendor yang memantaunya) | Analis CTI | Mingguan | Sedang | Berjalan |
| SIR-003.2 | ATT&CK Groups dan Campaigns, laporan teknis kampanye | Analis CTI | Per kelompok baru | Tinggi | Berjalan |
| SIR-003.3 | Inventaris rule SIEM, peta log source | Detection engineer | Sekali, lalu saat ada perubahan | Tinggi | Antre |
| SIR-003.3 | Laporan insiden internal 24 bulan | IR lead | Sekali | Sedang | Belum mulai |

Gap: belum ada sumber tentang insiden yang tidak dipublikasikan di logistik lokal. Keputusan: ajukan keanggotaan ISAC sektor; sementara itu nyatakan keterbatasan di produk. Situs kebocoran tidak diakses langsung (alasan etika dan keamanan dibahas di Day 05).

### 2.4 RFI dan cara menilainya

Ini contoh permintaan mendadak dari IR yang dikhawatirkan CISO, beserta cara menanganinya tanpa mengganggu kerja PIR.

```
RFI-2026-017  (prioritas: mendesak)
Peminta: IR lead
Pertanyaan: Domain bad-logistics[.]example muncul di alert proxy hari ini.
  Apakah ada laporan publik yang mengaitkannya ke aktor atau kampanye,
  dan indikator lain apa yang perlu dicari?
Keputusan terkait: isolasi host atau tidak
Dibutuhkan sebelum: 2026-10-08 17:00
Terkait PIR: PIR-2026-003 (tema ransomware logistik)
Jawaban: <ringkasan + sumber dengan kode keandalan + keyakinan + IOC ter-defang>
Ditutup: <tanggal, siapa, tindakan yang diambil>
```

Saat RFI masuk, analis memeriksa empat hal sebelum mulai bekerja: apa keputusannya, kapan dibutuhkan, apakah sudah pernah dijawab (cek arsip RFI), dan apakah ia terkait PIR aktif. RFI yang tidak punya keputusan sebaiknya diklarifikasi dulu ("hasilnya akan dipakai untuk apa?"). RFI yang terkait PIR memperkaya jawaban PIR; RFI yang berulang menjadi kandidat PIR baru.

### 2.5 Produk, dissemination, dan umpan balik

Rencana ini menjawab pertanyaan terakhir CISO: kapan jawabannya siap, untuk siapa saja, dan apa yang terjadi setelah CISO membacanya.

```
Rencana dissemination PIR-2026-003
  CISO           : brief 1 halaman, 2026-11-28, rekomendasi anggaran + keyakinan
  Detection eng. : daftar teknik tanpa deteksi + ID ATT&CK, 2026-11-20
  SOC            : IOC ter-defang via lookup SIEM, berkala
Umpan balik CISO (2026-12-02):
  "Berguna. Butuh perkiraan biaya relatif dan keyakinan atribusi kelompok."
Tindakan: PIR-2026-003 putaran 2 menambah SIR-003.4 (biaya dan efektivitas
  kontrol) dan meminta kode keyakinan pada setiap atribusi.
```

**Cara membaca hasil:** produk untuk detection engineer dikirim lebih awal dari brief CISO karena mereka butuh waktu memperkirakan biaya rule baru, dan angka itu masuk ke brief. Umpan balik CISO menghasilkan SIR baru, bukti siklus benar-benar berputar.

## 3. Lab praktik

Lab ini tidak memerlukan alat selain editor teks. Pakai organisasi fiktif; jangan pakai data kerja.

1. **Gambar siklus.** Dari ingatan, gambar siklus intelijen dan tulis satu kalimat per tahap tentang apa yang bisa salah di sana.
2. **Wawancara simulasi.** Pilih satu peran (CISO, kepala operasi, kepala SOC) di organisasi fiktif. Jawab sendiri lima pertanyaan di bagian 1.6 dari sudut pandang peran itu, lalu catat dalam format bagian 2.1.
3. **Tulis dua PIR.** Turunkan dua PIR dari catatan wawancara. Setiap PIR memenuhi lima kriteria di bagian 1.5 dan punya tenggat yang terikat kalender keputusan.
4. **Pecah ke SIR dan EEI.** Untuk satu PIR, tulis tiga SIR dan EEI-nya, dengan minimal satu SIR yang hanya bisa dijawab data internal.
5. **Collection plan.** Buat tabel seperti bagian 2.3, termasuk minimal satu gap dan keputusan atas gap itu.
6. **RFI.** Tulis dua RFI fiktif: satu yang jelas keputusannya, satu yang kabur. Tulis pertanyaan klarifikasi untuk yang kabur.
7. **Satu putaran penuh.** Tulis umpan balik fiktif dari konsumen dan perubahan PIR untuk putaran kedua.

**Hasil yang sebaiknya tersimpan:**

- Catatan wawancara satu pemangku kepentingan dengan keputusan dan tenggatnya.
- Dua PIR yang lolos uji "keputusan apa yang berubah".
- Satu PIR yang dipecah menjadi SIR dan EEI.
- Collection plan dengan sumber internal, sumber eksternal, gap, dan keputusan atas gap.
- Dua RFI dengan catatan triase.
- Umpan balik dan revisi PIR putaran kedua.

**Variasi tantangan:** ambil satu laporan ancaman publik yang kamu baca minggu ini dan kerjakan terbalik: PIR apa yang akan dijawab laporan itu untuk organisasimu, dan SIR mana yang tetap tidak terjawab. Latihan ini membiasakan membaca laporan dari sudut kebutuhan, bukan dari sudut isi.

## 4. Troubleshooting

Tabel ini dibaca dari kolom Gejala: cari keluhan yang mirip dengan yang kamu alami, lalu periksa penyebab yang paling sering.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Laporan tidak dipakai | PIR tidak terikat keputusan | Tanya keputusan apa yang berubah; tulis ulang PIR |
| Pengumpulan tanpa arah | Tidak ada collection plan atau EEI | Petakan SIR ke sumber; definisikan EEI |
| PIR terlalu luas | "Apa ancaman kami" | Persempit ke aset, ancaman, dan horizon |
| PIR tidak pernah "selesai" | Tidak ada tenggat atau kriteria terjawab | Tambah tenggat dan tanggal tinjau ulang |
| RFI menenggelamkan kerja PIR | Tidak ada triase RFI | Wajibkan keputusan dan tenggat di setiap RFI; gabungkan RFI berulang menjadi PIR |
| Analisis lambat | Processing diabaikan | Normalisasi, deduplikasi, dan beri sumber serta tanggal pada setiap data |
| Intelijen terlambat | Tenggat tidak diikat ke kalender keputusan | Mulai dari tanggal keputusan, hitung mundur |
| Siklus mandek | Tidak ada umpan balik | Tambahkan tiga pertanyaan umpan balik di setiap produk |

## 5. Kesalahan umum dan jebakan

- Mulai dari data, bukan kebutuhan. Mengumpulkan IOC tanpa PIR menghasilkan laporan yang tidak terpakai.
- PIR tanpa keputusan. Bila jawaban tidak mengubah tindakan, itu rasa ingin tahu, bukan PIR.
- PIR yang ditulis tim CTI sendiri tanpa persetujuan pemangku kepentingan. Tanpa persetujuan, tim tidak punya dasar untuk menolak pekerjaan lain.
- Terlalu banyak PIR. Dua puluh PIR aktif untuk tim dua orang sama dengan tidak punya prioritas.
- Lupa sisi internal. PIR tentang ancaman luar tanpa SIR "apakah kita siap" berhenti di deskripsi ancaman.
- Mengabaikan processing. Data tanpa asal dan tanggal tidak bisa dinilai keandalannya.
- Dissemination seragam. Satu format untuk semua konsumen gagal; sesuaikan ke tingkat intelijen (Day 01).
- Melupakan umpan balik. Tanpa menutup siklus, kualitas tidak membaik dan program sulit dipertahankan saat anggaran ditinjau.

## 6. Catatan terkini

Bagian ini menampung asal-usul model, kritik terhadapnya, dan kondisi industri saat ini. Berguna sebagai konteks, tetapi tidak mengubah cara menulis PIR.

- Model siklus intelijen berasal dari doktrin militer dan diadaptasi ke CTI. Ringkasan Congressional Research Service (diperbarui Januari 2026) masih menggambarkan proses intelijen gabungan dalam enam kategori seperti di bagian 1.1 [S2].
- Sebagian praktisi menilai model siklus terlalu kaku dan lebih menekankan iterasi cepat berbasis pertanyaan. Kritik ini tidak membatalkan siklus; ia mengingatkan bahwa tahap bisa paralel.
- Survei industri CTI 2026 yang dibahas di Day 01 menunjukkan banyak program belum punya umpan balik efektivitas yang sistematis, sehingga bagian 1.9 masih menjadi kelemahan umum.
- Platform modern (MISP, OpenCTI; Day 08) mengotomasi sebagian collection dan processing, tetapi direction dan dissemination tetap pekerjaan manusia.
- Day 03 masuk ke analytic tradecraft yang mengisi tahap analysis.

## 7. Cheat sheet

```
SIKLUS     Direction(PIR) -> Collection -> Processing -> Analysis -> Dissemination -> Feedback -> ulang
           berulang dan boleh tumpang tindih; JP 2-0: 6 kategori (+ integration, evaluation)
IR/PIR/RFI IR=kebutuhan umum | PIR=prioritas, terikat keputusan, disetujui pimpinan | RFI=ad hoc, sekali jalan
HIERARKI   PIR -> SIR (bisa dijawab satu analisis) -> EEI (fakta yang dicari kolektor)
PIR BAIK   terikat keputusan + spesifik + dapat dikumpulkan + terikat waktu + satu pertanyaan
UJI PIR    "keputusan apa yang berubah bila jawabannya ya / tidak?"
WAWANCARA  keputusan 6 bulan | ketakutan terbesar | terakhir terkejut | format | siapa lagi
COLL PLAN  req -> sumber -> pengumpul -> frekuensi -> prioritas -> status ; tulis GAP + keputusan atas gap
RFI TRIASE keputusan? tenggat? sudah pernah dijawab? terkait PIR? ; RFI berulang = kandidat PIR
GAGAL      paling sering di DIRECTION dan DISSEMINATION
METRIK     % PIR terjawab | waktu jawab RFI | produk yang menghasilkan tindakan tercatat
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Saat diwawancarai, seorang direktur PT LC menjawab, "Beri tahu saya ancaman yang relevan." Tim CTI langsung mencatatnya sebagai PIR. Tepatkah?

<details><summary>Jawaban</summary>

Tidak. Kalimat itu tidak menyebut keputusan, tidak spesifik, dan tidak punya horizon, sehingga gagal di tiga dari lima kriteria PIR yang baik. Jawaban seperti ini justru umum di awal wawancara; tugas analis adalah terus bertanya (keputusan apa dalam enam bulan ke depan, kejadian apa yang paling ditakutkan, kapan terakhir terkejut) sampai keputusan yang sebenarnya muncul, lalu mengajukan draf PIR untuk disetujui. Uji akhirnya: keputusan apa yang berubah bila jawabannya ya atau tidak? Lihat bagian 1.5 dan 1.6.

</details>

**2. Skenario keputusan.** Pada 2026-10-08, IR lead mengirim RFI-2026-017 tentang domain `bad-logistics[.]example` di alert proxy, dibutuhkan sebelum 17.00 hari itu. Tim CTI sedang mengerjakan PIR-2026-003. Apa yang sebaiknya dilakukan?

- A. Tolak, karena tim sudah punya PIR yang disetujui CISO dan RFI bukan bagian dari PIR.
- B. Periksa empat hal (keputusannya, tenggatnya, apakah sudah pernah dijawab, apakah terkait PIR aktif), lalu jawab sebelum tenggat dan kaitkan temuannya ke PIR-2026-003.
- C. Hentikan semua kerja PIR dan langsung kumpulkan semua informasi tentang domain itu tanpa memeriksa apa pun.

<details><summary>Jawaban</summary>

B. RFI ini punya keputusan yang jelas (isolasi host atau tidak) dan tenggat yang jelas, jadi layak dikerjakan. Temanya sama dengan PIR-2026-003, sehingga jawabannya juga memperkaya PIR. A keliru karena RFI memang jalur resmi untuk permintaan ad hoc dan mendesak; PIR memberi dasar menolak pekerjaan yang tidak terkait keputusan, bukan menolak semua permintaan. C keliru karena tanpa triase tim bisa mengulang pekerjaan yang sudah pernah dijawab dan RFI menenggelamkan kerja PIR. Bila RFI dengan tema yang sama terus berulang, itu tanda ada PIR yang belum ditulis. Lihat bagian 1.3 dan 2.4.

</details>

**3. Pertanyaan jebakan.** "Siklus intelijen harus dijalankan berurutan: collection tidak boleh dimulai sebelum direction selesai, dan analysis tidak boleh dimulai sebelum collection selesai." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Dalam praktik banyak putaran kecil berjalan paralel untuk PIR yang berbeda, dan tahap bisa tumpang tindih. Analis sering sudah menganalisis data awal sambil collection berjalan, dan bisa kembali ke direction ketika PIR ternyata ambigu. Ringkasan doktrin JP 2-0 juga menyebut operasi intelijen tidak harus berurutan ketat. Lingkaran rapi di slide adalah alat bantu pengajaran, bukan urutan kerja yang wajib. Yang tidak boleh hilang adalah PIR dan umpan balik. Lihat bagian 1.2.

</details>

**4. Jelaskan ulang.** Jelaskan kepada CISO PT LC dalam tiga kalimat beda PIR, SIR, dan EEI, memakai PIR-2026-003 sebagai contoh.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "PIR adalah pertanyaan besar yang Bapak setujui karena terikat keputusan anggaran Q1: apakah kelompok ransomware penyasar logistik Asia Tenggara masuk lewat akses pihak ketiga, dan teknik apa yang belum kita deteksi. SIR memecahnya menjadi pertanyaan yang bisa dijawab satu jenis analisis, misalnya kelompok mana yang aktif, teknik akses awal apa yang mereka pakai, dan teknik mana yang belum kita deteksi. EEI adalah fakta konkret yang dicari pengumpul untuk tiap SIR, seperti nama kelompok, tanggal insiden, ID ATT&CK seperti T1133 atau T1078, dan daftar rule aktif per teknik."

Kesalahan yang sering muncul:
- Menganggap EEI sama dengan IOC. EEI adalah fakta apa pun yang dibutuhkan SIR, termasuk data internal seperti daftar rule.
- Lupa bahwa satu SIR (SIR-003.3) sepenuhnya internal; tanpa itu PIR berhenti di cerita tentang ancaman luar.
- Menganggap nama lapis PIR, SIR, dan EEI baku di semua organisasi. Penamaannya bervariasi.

</details>

**5. Skenario keputusan.** Collection plan PIR-2026-003 tidak punya sumber tentang insiden di perusahaan logistik lokal yang tidak dipublikasikan. Apa langkah yang paling tepat?

- A. Tulis gap itu secara eksplisit beserta keputusannya: ajukan keanggotaan ISAC sektor, dan sementara itu nyatakan keterbatasannya di produk.
- B. Abaikan gap itu dan sampaikan jawaban seolah-olah gambaran ancamannya sudah lengkap.
- C. Akses langsung situs kebocoran ransomware supaya gap tertutup.

<details><summary>Jawaban</summary>

A. Salah satu fungsi collection plan adalah memperlihatkan gap, dan gap ditulis beserta keputusan atasnya: diterima sebagai risiko, dicari sumber pengganti, atau PIR dipersempit. B keliru karena konsumen akan mengambil keputusan anggaran dengan anggapan gambaran sudah lengkap, padahal belum. C keliru karena collection plan PT LC sengaja memakai situs kebocoran hanya lewat ringkasan vendor yang memantaunya; akses langsung tidak dilakukan karena alasan etika dan keamanan. Lihat bagian 1.7 dan 2.3.

</details>

**6. Pertanyaan jebakan.** "Program CTI kita berhasil kuartal ini: kita mengumpulkan puluhan ribu IOC baru." Apakah itu ukuran keberhasilan yang baik?

<details><summary>Jawaban</summary>

Bukan. Jumlah IOC mengukur aktivitas collection, bukan apakah intelijen dipakai. Angka yang lebih jujur adalah persentase PIR yang terjawab per kuartal, waktu rata-rata menjawab RFI, dan jumlah produk yang menghasilkan tindakan tercatat (rule baru, kontrol diubah, risiko diterima). Angka itu hanya bisa dihitung bila umpan balik diminta secara terstruktur di setiap produk. Lihat bagian 1.9.

</details>

**7. Interview question (English).** "How would you set up intelligence requirements for a new CTI program?"

<details><summary>Sample answer</summary>

"I'd start by interviewing the key stakeholders, such as the CISO and the heads of the SOC and operations, and asking what decisions they need to make in the next six months, what they fear most, and when they were last surprised. From that I'd draft a small set of priority intelligence requirements, maybe three to seven for a new team, each tied to a decision, specific, collectable, and time-bound, and get them approved so we have a basis for saying no to unrelated work. I'd break each PIR into sub-questions and the concrete facts we need, then build a collection plan that puts internal sources like our own detections and incident reports alongside external ones and shows the gaps. Ad hoc requests go through a separate RFI process, and if the same RFI theme keeps coming back, that tells me a PIR is missing. Finally, I'd tie delivery dates to the decision calendar and ask for feedback on every product, so we can measure how many PIRs we actually answered and what actions came out of them."

What makes this answer strong: it starts from decisions rather than data sources, gives concrete criteria and a realistic number of PIRs, includes internal sources and gaps, separates RFIs from PIRs, and closes the loop with feedback and outcome-based metrics.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | MWR InfoSecurity, CPNI, CERT-UK: Threat Intelligence: Collecting, Analysing, Evaluating (salinan PDF) | https://www.ismsforum.es/ficheros/descargas/threat-intelligence--collecting-analysing.pdf | primer (dokumen bersama lembaga pemerintah UK) | 2015; diakses 2026-10-10 | Tinggi untuk prinsip "mulai dari requirement" |
| S2 | Congressional Research Service: Defense Primer: Intelligence Support to Military Operations (IF10574) | https://www.everycrsreport.com/files/2026-01-23_IF10574_bdac509fff989a3adb3336c4ee922cbec9177a90.pdf | sekunder (ringkasan resmi atas JP 2-0) | diperbarui 2026-01-23; diakses 2026-10-10 | Tinggi untuk kategori proses intelijen JP 2-0 |
| S3 | Joint Chiefs of Staff: Joint Publication 2-0, Joint Intelligence | (tautan resmi tidak dapat diakses otomatis) | primer (doktrin) | 2013, revisi 2022 | Tinggi. Doktrin asal siklus; isi yang dipakai di catatan ini sudah tercakup lewat S2 |

**Catatan sumber:** hierarki PIR, SIR, dan EEI serta kriteria PIR yang baik adalah praktik komunitas CTI; penamaan lapisnya berbeda antar organisasi, jadi sesuaikan dengan istilah di tim-mu. Jumlah PIR aktif yang disarankan (tiga sampai tujuh) adalah pedoman praktis, bukan angka dari standar. Urutan enam kategori JP 2-0 diambil dari ringkasan CRS; cocokkan dengan teks JP 2-0 bila tersedia.
