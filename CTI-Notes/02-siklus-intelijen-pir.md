---
day: 02
title: 'Siklus intelijen dan PIR: dari kebutuhan pemangku kepentingan ke intelijen yang dipakai'
researched_on: 2026-10-10
versions_checked: 'Konsep stabil (intelligence cycle, PIR/RFI); JP 2-0 dirujuk lewat ringkasan CRS IF10574 (Januari 2026); MWR/CPNI 2015'
---

# Day 02: Siklus intelijen dan PIR

Cakupan: siklus intelijen sebagai proses berulang, cara menggali kebutuhan pemangku kepentingan menjadi PIR yang bisa dijawab, menurunkannya ke sub-pertanyaan dan collection plan, serta menutup siklus dengan dissemination dan umpan balik.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan tahap siklus intelijen dan kenapa ia berjalan berulang, bukan sekali jalan.
- membedakan intelligence requirement, PIR, dan RFI, serta siapa yang menetapkan dan siapa yang menjawabnya.
- mewawancarai pemangku kepentingan untuk menemukan keputusan yang perlu didukung intelijen.
- menyusun PIR yang terikat keputusan, spesifik, dapat dikumpulkan, dan terikat waktu, lalu menurunkannya ke sub-pertanyaan dan elemen informasi.
- membuat collection plan yang memetakan setiap sub-pertanyaan ke sumber dan memperlihatkan gap.
- menerima, menilai, dan menjawab RFI tanpa mengganggu kerja PIR.
- menjelaskan kenapa tahap direction dan dissemination paling sering gagal, dan bagaimana mengukurnya.

## 2. Konteks singkat

Day 01 mendefinisikan CTI sebagai informasi yang bisa ditindaklanjuti untuk sebuah keputusan. Day ini membahas proses yang mengubah kebutuhan menjadi intelijen itu. Tanpa proses, tim CTI cenderung mengumpulkan IOC tanpa arah dan menulis laporan yang tidak dipakai siapa pun. Siklus memberi disiplin: mulai dari kebutuhan pemangku kepentingan, bukan dari data yang kebetulan tersedia.

Inti praktisnya adalah PIR (Priority Intelligence Requirement), yaitu pertanyaan prioritas yang mengarahkan seluruh pengumpulan dan analisis. PIR yang buruk membuat seluruh siklus sia-sia, sebaik apa pun alat dan feed-nya. PIR juga menjadi bahan baku hipotesis threat hunting: pertanyaan "apakah teknik X dipakai aktor yang menyasar sektor kita" mudah diubah menjadi "apakah teknik X sudah terjadi di lingkungan kita".

**Kapan dipakai:** menyiapkan atau merapikan program CTI, menentukan apa yang dikumpulkan, menilai apakah laporan menjawab kebutuhan, dan menolak permintaan yang tidak terikat keputusan.

**Kapan terbatas:** tim satu atau dua orang sering memadatkan tahap; itu wajar asalkan PIR dan umpan balik tetap ada. Model ini berasal dari doktrin militer sehingga istilah dan hierarkinya perlu disesuaikan untuk perusahaan.

## 3. Konsep inti

### 3.1 Siklus intelijen

Model yang paling sering dipakai di CTI punya lima tahap, ditambah umpan balik. Sebagian sumber memisahkan processing dan exploitation atau menjadikan feedback tahap sendiri, sehingga jumlahnya enam [S1][S2].

| Tahap | Isi | Pertanyaan kontrol |
|---|---|---|
| Direction (planning) | Tetapkan kebutuhan: PIR dan prioritasnya | Keputusan siapa yang didukung? |
| Collection | Kumpulkan data dari sumber sesuai collection plan | Apakah sumber ini menjawab sub-pertanyaan tertentu? |
| Processing | Ubah data mentah menjadi bentuk yang bisa dianalisis | Apakah data sudah dinormalisasi, dideduplikasi, diberi sumber dan tanggal? |
| Analysis (production) | Beri makna: nilai, korelasi, simpulkan dengan keyakinan | Apakah ada penilaian dan rekomendasi, bukan hanya ringkasan? |
| Dissemination | Sampaikan ke konsumen dalam bentuk dan waktu yang berguna | Apakah konsumen menerima sebelum keputusannya dibuat? |
| Feedback | Konsumen menilai manfaat; PIR diperbarui | Apa yang berubah untuk putaran berikutnya? |

Doktrin intelijen militer Amerika Serikat (Joint Publication 2-0) menyebut proses intelijen gabungan sebagai enam kategori operasi yang saling terkait: planning and direction, collection, processing and exploitation, analysis and production, dissemination and integration, serta evaluation and feedback [S2]. Kata "integration" di sana berguna untuk CTI: produk belum selesai sampai ia terintegrasi ke proses konsumen (masuk ke backlog detection, ke rapat risiko, atau ke playbook IR).

### 3.2 Kenapa berulang, bukan garis lurus

Hasil satu putaran mengubah kebutuhan berikutnya. Temuan analisis memunculkan pertanyaan baru, umpan balik konsumen mempertajam PIR, dan gap pengumpulan mengarahkan koleksi berikutnya. Memperlakukan siklus sebagai garis lurus (kumpulkan sekali, lapor sekali) kehilangan nilai utamanya, yaitu penyempurnaan terus-menerus.

Dalam praktik, banyak putaran kecil berjalan paralel untuk PIR yang berbeda, dan tahap bisa tumpang tindih. Analis sering sudah menganalisis data awal sambil collection berjalan, dan bisa melompat kembali ke direction ketika ternyata PIR ambigu. Doktrin sendiri menyebut operasi intelijen tidak harus berurutan ketat [S2]. Gambar lingkaran rapi di slide adalah alat bantu pengajaran, bukan urutan kerja yang wajib.

### 3.3 Requirement, PIR, dan RFI

| Istilah | Arti | Siapa menetapkan | Umur |
|---|---|---|---|
| Intelligence Requirement (IR) | Kebutuhan informasi umum organisasi | Tim CTI bersama pemangku kepentingan | Berkelanjutan |
| Priority Intelligence Requirement (PIR) | IR yang diprioritaskan karena terikat keputusan penting | Pemangku kepentingan senior (CISO, kepala SOC, manajemen risiko) | Biasanya ditinjau tiap kuartal atau semester |
| Request for Information (RFI) | Permintaan ad hoc spesifik, sering mendesak | Konsumen mana pun | Sekali jalan, ditutup setelah dijawab |

PIR mengarahkan program secara berkelanjutan; RFI adalah permintaan sekali jalan. Keduanya dilacak dengan ID agar tim tahu apa yang sedang dijawab dan berapa lama. Hubungan keduanya penting: bila RFI dengan tema yang sama muncul berulang (misalnya tiga RFI dalam sebulan tentang kebocoran kredensial VPN), itu tanda ada PIR yang belum ditulis.

### 3.4 Hierarki PIR, sub-pertanyaan, dan elemen informasi

Satu PIR biasanya terlalu besar untuk langsung dikumpulkan. Banyak tim memecahnya menjadi tiga lapis. Penamaan lapis ini berbeda antar organisasi; yang umum di CTI adalah PIR, lalu SIR (specific intelligence requirement), lalu EEI (essential element of information) [komunitas, penamaan bervariasi].

| Lapis | Bentuk | Contoh singkat (fiktif) |
|---|---|---|
| PIR | Pertanyaan terikat keputusan | Teknik akses awal apa dari kelompok ransomware penyasar logistik yang belum kita deteksi? |
| SIR | Pertanyaan yang bisa dijawab satu jenis analisis | Kelompok mana yang menyasar logistik Asia Tenggara dalam enam bulan terakhir? |
| EEI | Fakta konkret yang dicari kolektor | Nama kelompok, tanggal insiden, sektor korban, teknik akses awal yang dilaporkan, ID ATT&CK |

Manfaat hierarki ini praktis: kolektor (atau feed, atau rule otomatis di platform) bekerja di level EEI, sedangkan analis menyusun jawaban di level SIR dan PIR. Bila EEI tidak terdefinisi, kolektor mengumpulkan apa saja yang "terlihat terkait".

### 3.5 Anatomi PIR yang baik

Kriteria yang dipakai di catatan ini adalah sintesis praktik komunitas CTI dan doktrin [S1][komunitas]:

- **Terikat keputusan:** jawaban mengubah tindakan nyata (prioritas patching, investasi kontrol, backlog detection).
- **Spesifik:** menyebut ancaman, aset, atau aktivitas konkret.
- **Dapat dikumpulkan:** ada sumber yang sah dan realistis untuk menjawabnya.
- **Terikat waktu:** ada horizon pengamatan (enam bulan terakhir) dan tenggat keputusan (sebelum perencanaan anggaran Q1).
- **Satu pertanyaan:** PIR yang memuat tiga pertanyaan sekaligus sulit dinilai "terjawab atau belum".

Contoh menulis ulang PIR buruk, langkah demi langkah:

1. Awal: "Apa ancaman siber terbaru?" Tidak ada keputusan, tidak spesifik, tidak ada horizon.
2. Tanya pemangku kepentingan keputusan apa yang dia buat: "Saya harus memutuskan tambahan kontrol untuk akses remote vendor tahun depan."
3. Persempit ke aset dan ancaman: akses remote vendor, ancaman yang memakai akses itu.
4. Tambah horizon dan sektor: "Dalam 12 bulan terakhir, apakah aktor yang menyasar perusahaan logistik di Asia Tenggara masuk lewat akses remote pihak ketiga (VPN, RMM, akun vendor), dan teknik apa yang mereka pakai, sehingga kita perlu menambah kontrol pada akses vendor sebelum anggaran Q1 dikunci?"
5. Uji: bila jawabannya "ya, dua dari lima insiden lewat akun vendor tanpa MFA", keputusan berubah (MFA wajib untuk vendor). Bila jawabannya "tidak ada bukti", keputusan juga berubah (anggaran dialihkan). PIR lolos uji.

### 3.6 Menggali kebutuhan dari pemangku kepentingan

PIR jarang datang siap pakai. Kebanyakan pimpinan akan menjawab "beri tahu saya ancaman yang relevan". Tugas analis adalah mewawancarai mereka sampai keputusan yang sebenarnya muncul. Pertanyaan yang biasanya berhasil:

- Keputusan apa yang kamu buat dalam enam bulan ke depan yang bergantung pada keamanan?
- Kejadian apa yang paling kamu takutkan menimpa organisasi ini? (biasanya menyebut aset kritis atau "crown jewels")
- Kapan terakhir kali kamu terkejut oleh sebuah insiden atau berita, dan informasi apa yang seharusnya kamu dapat lebih awal?
- Dalam format apa dan seberapa sering kamu mau menerima informasi?
- Siapa lagi yang harus kami tanya?

Catat jawaban per pemangku kepentingan, kelompokkan tema yang berulang, lalu ajukan kembali draf PIR untuk disetujui. Persetujuan ini penting: PIR yang disetujui CISO memberi tim CTI dasar untuk menolak pekerjaan yang tidak terkait. Untuk tim yang baru mulai, tiga sampai tujuh PIR aktif sudah cukup; lebih dari itu biasanya tidak bisa dijawab dengan kapasitas yang ada.

### 3.7 Dari PIR ke collection plan

Collection plan memetakan setiap SIR dan EEI ke sumber yang akan menjawabnya. Fungsinya ada tiga: mencegah pengumpulan tanpa arah, memperlihatkan gap (sub-pertanyaan tanpa sumber), dan menjadi dasar menilai sumber (sumber yang tidak pernah menjawab apa pun layak dihentikan). Elemen minimalnya: ID requirement, sub-pertanyaan, sumber yang direncanakan, siapa yang mengumpulkan, frekuensi, prioritas, dan status.

Dua kebiasaan yang membuat collection plan berguna. Pertama, sumber internal ditulis sejajar dengan sumber eksternal, karena telemetri dan laporan insiden sendiri sering menjawab sub-pertanyaan paling penting ("apakah ini sudah terjadi pada kita"). Kedua, gap ditulis eksplisit beserta keputusan atasnya: diterima sebagai risiko, dicari sumber pengganti, atau PIR dipersempit.

### 3.8 Processing yang sering diabaikan

Processing mencakup normalisasi format, deduplikasi, penerjemahan, pemberian timestamp dan sumber, defang IOC, dan pengayaan awal. Data mentah jarang bisa langsung dianalisis: laporan vendor dalam PDF, feed dalam CSV dengan kolom berbeda, posting dalam bahasa lain. Tanpa processing yang rapi, analisis menjadi lambat dan rawan salah, misalnya domain yang sama tercatat dua kali dengan huruf besar dan kecil sehingga dianggap dua indikator.

Satu aturan processing yang berdampak besar: setiap butir data harus membawa asal dan tanggalnya. Tanpa itu, kamu tidak bisa menilai keandalan sumber (Day 03) atau mendeteksi circular reporting (Day 05). Platform seperti MISP dan OpenCTI (Day 08) mengotomasi sebagian processing, tetapi keputusan apa yang disimpan dan bagaimana dinormalisasi tetap keputusan analis.

### 3.9 Dissemination, umpan balik, dan titik gagal

Dua tahap paling sering gagal:

- **Direction:** tanpa PIR yang jelas dan disetujui, tim mengumpulkan apa saja. Akar masalahnya biasanya kurangnya keterlibatan pimpinan, bukan kurangnya feed.
- **Dissemination:** intelijen bagus yang dikirim dalam format salah, ke orang yang salah, atau setelah keputusan dibuat, tidak berdampak. Produk harus sesuai konsumen (tingkat intelijen di Day 01) dan tenggatnya diikat ke kalender keputusan, bukan ke kapan analisis selesai.

Umpan balik sebaiknya diminta secara terstruktur, misalnya tiga pertanyaan singkat di akhir setiap produk: apakah ini menjawab pertanyaanmu, tindakan apa yang kamu ambil, apa yang kurang. Dari sana tim bisa mengukur program dengan angka sederhana: persentase PIR yang terjawab per kuartal, waktu rata-rata menjawab RFI, jumlah produk yang menghasilkan tindakan tercatat (rule baru, kontrol diubah, risiko diterima). Angka ini lebih jujur daripada jumlah IOC yang dikumpulkan.

## 4. Contoh artefak intelijen

Semua contoh di bagian ini fiktif dan berlabel ilustrasi. Organisasinya adalah "PT Logistik Contoh", perusahaan logistik fiktif dengan gudang di tiga kota, portal pelanggan, dan banyak vendor yang mengakses sistem lewat VPN.

### 4.1 Catatan wawancara pemangku kepentingan

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

### 4.2 PIR lengkap dengan turunannya

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

### 4.3 Collection plan

| Req | Sumber | Pengumpul | Frekuensi | Prioritas | Status |
|---|---|---|---|---|---|
| SIR-003.1 | Laporan vendor publik, advisori CERT nasional, ISAC sektor | Analis CTI | Mingguan | Tinggi | Berjalan |
| SIR-003.1 | Situs kebocoran ransomware (hanya lewat ringkasan vendor yang memantaunya) | Analis CTI | Mingguan | Sedang | Berjalan |
| SIR-003.2 | ATT&CK Groups dan Campaigns, laporan teknis kampanye | Analis CTI | Per kelompok baru | Tinggi | Berjalan |
| SIR-003.3 | Inventaris rule SIEM, peta log source | Detection engineer | Sekali, lalu saat ada perubahan | Tinggi | Antre |
| SIR-003.3 | Laporan insiden internal 24 bulan | IR lead | Sekali | Sedang | Belum mulai |

Gap: belum ada sumber tentang insiden yang tidak dipublikasikan di logistik lokal. Keputusan: ajukan keanggotaan ISAC sektor; sementara itu nyatakan keterbatasan di produk. Situs kebocoran tidak diakses langsung (alasan etika dan keamanan dibahas di Day 05).

### 4.4 RFI dan cara menilainya

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

### 4.5 Produk, dissemination, dan umpan balik

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

## 5. Lab praktik

Lab ini tidak memerlukan alat selain editor teks. Pakai organisasi fiktif; jangan pakai data kerja.

1. **Gambar siklus.** Dari ingatan, gambar siklus intelijen dan tulis satu kalimat per tahap tentang apa yang bisa salah di sana.
2. **Wawancara simulasi.** Pilih satu peran (CISO, kepala operasi, kepala SOC) di organisasi fiktif. Jawab sendiri lima pertanyaan di bagian 3.6 dari sudut pandang peran itu, lalu catat dalam format bagian 4.1.
3. **Tulis dua PIR.** Turunkan dua PIR dari catatan wawancara. Setiap PIR memenuhi lima kriteria di bagian 3.5 dan punya tenggat yang terikat kalender keputusan.
4. **Pecah ke SIR dan EEI.** Untuk satu PIR, tulis tiga SIR dan EEI-nya, dengan minimal satu SIR yang hanya bisa dijawab data internal.
5. **Collection plan.** Buat tabel seperti bagian 4.3, termasuk minimal satu gap dan keputusan atas gap itu.
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

## 6. Troubleshooting

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

## 7. Kesalahan umum dan jebakan

- Mulai dari data, bukan kebutuhan. Mengumpulkan IOC tanpa PIR menghasilkan laporan yang tidak terpakai.
- PIR tanpa keputusan. Bila jawaban tidak mengubah tindakan, itu rasa ingin tahu, bukan PIR.
- PIR yang ditulis tim CTI sendiri tanpa persetujuan pemangku kepentingan. Tanpa persetujuan, tim tidak punya dasar untuk menolak pekerjaan lain.
- Terlalu banyak PIR. Dua puluh PIR aktif untuk tim dua orang sama dengan tidak punya prioritas.
- Lupa sisi internal. PIR tentang ancaman luar tanpa SIR "apakah kita siap" berhenti di deskripsi ancaman.
- Mengabaikan processing. Data tanpa asal dan tanggal tidak bisa dinilai keandalannya.
- Dissemination seragam. Satu format untuk semua konsumen gagal; sesuaikan ke tingkat intelijen (Day 01).
- Melupakan umpan balik. Tanpa menutup siklus, kualitas tidak membaik dan program sulit dipertahankan saat anggaran ditinjau.

## 8. Catatan terkini

- Model siklus intelijen berasal dari doktrin militer dan diadaptasi ke CTI. Ringkasan Congressional Research Service (diperbarui Januari 2026) masih menggambarkan proses intelijen gabungan dalam enam kategori seperti di bagian 3.1 [S2].
- Sebagian praktisi menilai model siklus terlalu kaku dan lebih menekankan iterasi cepat berbasis pertanyaan. Kritik ini tidak membatalkan siklus; ia mengingatkan bahwa tahap bisa paralel.
- Survei industri CTI 2026 yang dibahas di Day 01 menunjukkan banyak program belum punya umpan balik efektivitas yang sistematis, sehingga bagian 3.9 masih menjadi kelemahan umum.
- Platform modern (MISP, OpenCTI; Day 08) mengotomasi sebagian collection dan processing, tetapi direction dan dissemination tetap pekerjaan manusia.
- Day 03 masuk ke analytic tradecraft yang mengisi tahap analysis.

## 9. Cheat sheet

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

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | MWR InfoSecurity, CPNI, CERT-UK: Threat Intelligence: Collecting, Analysing, Evaluating (salinan PDF) | https://www.ismsforum.es/ficheros/descargas/threat-intelligence--collecting-analysing.pdf | primer (dokumen bersama lembaga pemerintah UK) | 2015; diakses 2026-10-10 | Tinggi untuk prinsip "mulai dari requirement" |
| S2 | Congressional Research Service: Defense Primer: Intelligence Support to Military Operations (IF10574) | https://www.everycrsreport.com/files/2026-01-23_IF10574_bdac509fff989a3adb3336c4ee922cbec9177a90.pdf | sekunder (ringkasan resmi atas JP 2-0) | diperbarui 2026-01-23; diakses 2026-10-10 | Tinggi untuk kategori proses intelijen JP 2-0 |
| S3 | Joint Chiefs of Staff: Joint Publication 2-0, Joint Intelligence | (tautan resmi tidak dapat diakses otomatis) | primer (doktrin) | 2013, revisi 2022 | Tinggi. Doktrin asal siklus; isi yang dipakai di catatan ini sudah tercakup lewat S2 |

**Catatan sumber:** hierarki PIR, SIR, dan EEI serta kriteria PIR yang baik adalah praktik komunitas CTI; penamaan lapisnya berbeda antar organisasi, jadi sesuaikan dengan istilah di tim-mu. Jumlah PIR aktif yang disarankan (tiga sampai tujuh) adalah pedoman praktis, bukan angka dari standar. Urutan enam kategori JP 2-0 diambil dari ringkasan CRS; cocokkan dengan teks JP 2-0 bila tersedia.
