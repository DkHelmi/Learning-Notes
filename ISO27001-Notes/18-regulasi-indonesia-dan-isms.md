---
day: 18
title: 'Regulasi Indonesia dan ISMS: memetakan kewajiban ke kontrol, menjalankan satu sistem'
researched_on: 2026-10-10
versions_checked: 'UU No. 27 Tahun 2022 (PDP), ditetapkan dan diundangkan 17 Oktober 2022, masa penyesuaian 2 tahun berakhir 17 Oktober 2024; PP No. 71 Tahun 2019 (PSTE), berlaku 10 Oktober 2019, tanpa perubahan tercatat di BPK; Peraturan BSSN No. 8 Tahun 2020 (sistem pengamanan PSE), diundangkan 23 November 2020; Peraturan BSSN No. 1 Tahun 2024 (pengelolaan insiden siber), berlaku 18 Januari 2024; Perpres No. 82 Tahun 2022 (pelindungan IIV), 24 Mei 2022; POJK No. 11/POJK.03/2022 (TI bank umum), diundangkan 7 Juli 2022; PP No. 33 Tahun 2026 dan pembentukan lembaga PDP belum ditemukan di sumber resmi per 2026-10-10'
---

# Day 18: Regulasi Indonesia dan ISMS

Cakupan: kewajiban utama regulasi Indonesia yang bersinggungan dengan keamanan informasi (UU PDP, PP 71/2019, Peraturan BSSN, Perpres IIV, contoh sektor bank), tenggat pelaporan insiden yang berjalan bersamaan, dan cara memasukkan semuanya ke ISMS sehingga satu sistem melayani beberapa kewajiban sekaligus, termasuk cara menulis status kepatuhan yang belum pasti.

## Ide inti

Regulasi tidak membutuhkan sistem kedua. Setiap kewajiban hukum diperlakukan sebagai persyaratan tambahan bagi ISMS yang sudah ada: dicatat di klausul 4.2, dijaga mutakhir lewat kontrol 5.31, dipetakan ke klausul dan kontrol yang memenuhinya, lalu masuk ke risk register, program audit, dan management review yang sama (Day 03 membahas daftar pihak berkepentingan; Day ini mengisi daftar itu untuk Indonesia). Pekerjaan sesungguhnya ada di titik-titik tempat regulasi menuntut lebih dari standar: tenggat dalam jam, penerima laporan yang ditentukan, lokasi data, dan hak subjek data. Untuk titik itu, persyaratannya ditambahkan ke proses yang ada beserta bukti pemenuhannya, bukan dibuatkan proses paralel.

Kamu sudah mengenal pola ini dari onboarding klien baru di SOC atau MSSP. Klien membawa lingkungannya sendiri dan tuntutan SLA serta pelaporannya sendiri. Tuntutan itu dicatat, lalu dimasukkan ke playbook, eskalasi, dan laporan yang sudah berjalan; tidak ada yang membangun SOC kedua untuk setiap klien. Regulator diperlakukan dengan cara yang sama: pihak berkepentingan dengan tenggat, format, dan penerima laporan yang ditetapkan. Batas analoginya lebih tajam di sini daripada di Day 03: tuntutan regulator tidak bisa dinegosiasikan seperti SLA, pelanggarannya berujung sanksi, dan sebagian kewajiban (hak subjek data, DPIA) tidak punya padanan kontrol sama sekali.

```
UU, PP, Perpres, peraturan lembaga, peraturan sektor, kontrak
  -> register kewajiban (4.2 + kontrol 5.31): dasar hukum, kenapa berlaku, pemilik
  -> petakan ke klausul dan kontrol yang sudah ada
       ada padanan        -> tambahkan persyaratan dan bukti ke proses yang ada
       melampaui standar  -> tenggat jam, penerima laporan, lokasi data, hak subjek
       tanpa padanan      -> proses baru di bawah tata kelola privasi (Day 19)
  -> satu risk register, satu program audit, satu jalur korektif, satu management review
  -> status jujur: terpenuhi | terpenuhi sebagian | belum | belum pasti
```

Bagi SOC dan tim IR, regulasi paling terasa pada tenggat pelaporan. Kebocoran data pribadi di sebuah bank bisa memicu beberapa jam yang berjalan bersamaan: pemberitahuan UU PDP, notifikasi awal ke OJK, dan laporan insiden siber bila sistemnya IIV. Masalah yang hendak dicegah adalah sistem paralel, ketika tiap regulasi menjadi proyek sendiri dengan daftar kontrol dan jadwal audit sendiri.

Situasi yang dipakai sepanjang Day ini: Januari 2027, PT Awan Nusantara (PT AN, penyedia hosting fiktif di Jakarta) sedang memperbarui register kewajiban kepatuhannya. Legal baru saja mengirim memo bahwa media memberitakan terbitnya peraturan pelaksana UU PDP, dan klien bank meminta tambahan klausul kontrak tentang notifikasi insiden supaya bank bisa memenuhi tenggat ke OJK. Direktur Operasional meneruskan keduanya ke ISMS Manager dan Lead SOC:

> "Legal menyebut UU PDP, PP 71/2019, dua peraturan BSSN, dan Perpres IIV. Klien bank membawa POJK lewat kontrak. Saya tidak mau lima proyek kepatuhan dengan lima daftar kontrol. Sebelum review semester depan, jawab:
> 1. Aturan mana yang mengikat kita, dan lewat jalur apa?
> 2. Kalau besok ransomware mengenai data pelanggan, laporan apa yang harus keluar, ke siapa, dan sejak kapan jamnya dihitung?
> 3. Mana yang sudah ditutup ISMS kita, dan mana yang tidak punya padanan?
> 4. Bagaimana semuanya dijalankan dalam satu sistem?
> 5. Apa yang belum bisa kita pastikan?"

Pertanyaan 1 dijawab oleh lapisan kewajiban dan ringkasan tiap regulasi (bagian 1.1 sampai 1.5), pertanyaan 2 oleh peta pemberitahuan dan pelaporan (bagian 1.6), pertanyaan 3 oleh pemetaan ke klausul dan kontrol (bagian 1.7), serta pertanyaan 4 dan 5 oleh register tunggal dan status yang jujur (bagian 1.8).

**Kapan relevan:** saat menyusun atau meninjau daftar persyaratan 4.2, menulis prosedur pelaporan insiden, menjawab klien teregulasi (bank, kesehatan), memetakan lokasi data, dan saat aturan pelaksana baru diberitakan.
**Kapan bukan jawaban:** Day ini bukan nasihat hukum. Ringkasan pasal ditulis dengan kata sendiri dari teks resmi pada tanggal riset; untuk keputusan yang mengikat, baca teks resmi terbaru dan libatkan penasihat hukum organisasimu. Day ini juga tidak membangun tata kelola privasi untuk kewajiban yang tidak punya padanan di ISMS; itu bahasan Day 19.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Tabel ini memuat istilah regulasi yang muncul di Day ini. Kolom padanan memakai bahasa SOC supaya istilah hukum punya pegangan. Klausul 4.2, kontrol 5.31, dan pihak berkepentingan sudah dijelaskan di Day 03, sedangkan proses manajemen insiden di Day 10; istilah itu tidak diulang.

| Istilah | Arti singkat | Padanan di SOC |
|---|---|---|
| Lapisan kewajiban | Sumber kewajiban dari UU sampai kontrak, masing-masing dengan pihak yang dikenai | Sumber requirement deteksi: kebijakan internal, permintaan klien, regulasi |
| PSE lingkup publik / privat | Penyelenggara sistem elektronik dari instansi negara / dari orang, badan usaha, atau masyarakat (PP 71/2019) | Klasifikasi tenant yang menentukan paket aturan yang berlaku |
| Kategori sistem elektronik | Strategis, tinggi, atau rendah menurut penilaian mandiri (Peraturan BSSN 8/2020) | Tier kritikalitas aset yang menentukan baseline kontrol |
| IIV (infrastruktur informasi vital) | Sistem yang gangguannya berdampak serius dan ditetapkan oleh K/L sektornya (Perpres 82/2022) | Crown jewels tingkat nasional |
| TTIS | Tim Tanggap Insiden Siber di tingkat nasional, sektoral, dan organisasi (Peraturan BSSN 1/2024) | CSIRT dengan jalur eskalasi ke luar organisasi |
| Pengendali dan prosesor | Pihak yang menentukan tujuan pemrosesan data pribadi dan pihak yang memproses atas perintahnya | Klien pemilik data dan MSSP yang memprosesnya atas perintah klien |
| Subjek data | Orang yang datanya diproses | Orang yang namanya muncul di log dan tiket |
| Kegagalan pelindungan data pribadi | Gangguan kerahasiaan, keutuhan, atau ketersediaan data pribadi, disengaja maupun tidak | Insiden yang menyentuh data pribadi, termasuk ransomware |
| PPDP | Pejabat atau petugas pelindungan data pribadi | Titik kontak privasi, sering disebut DPO |
| DPIA | Penilaian dampak pelindungan data pribadi untuk pemrosesan berisiko tinggi | Threat model khusus privasi sebelum sistem baru jalan |
| Register kewajiban kepatuhan | Daftar kewajiban yang setiap barisnya menunjuk dasar hukum, proses pemenuhan, kontrol, bukti, dan pemilik | Daftar requirement deteksi yang setiap barisnya menunjuk rule yang memenuhinya |
| Status belum pasti | Kewajiban yang belum jelas karena aturan pelaksana atau lembaga penerimanya belum ada | Rule yang menunggu log source yang belum tersedia |

### 1.1 Lapisan kewajiban

Pertanyaan pertama Direktur Operasional, aturan mana yang mengikat PT AN, tidak bisa dijawab dengan membaca satu undang-undang. Kewajiban datang berlapis, dan lapisan paling bawah sering paling rinci.

Tabel ini memetakan lapisan kewajiban dari yang paling umum ke yang paling khusus. Cari di kolom ketiga apakah organisasimu termasuk pihak yang dikenai.

| Lapisan | Contoh | Berlaku bagi |
|---|---|---|
| Undang-undang | UU No. 27 Tahun 2022 tentang Pelindungan Data Pribadi [S1] | Pengendali dan prosesor data pribadi |
| Peraturan pemerintah | PP No. 71 Tahun 2019 tentang Penyelenggaraan Sistem dan Transaksi Elektronik [S2] | Penyelenggara sistem elektronik (PSE) |
| Peraturan presiden | Perpres No. 82 Tahun 2022 tentang Pelindungan Infrastruktur Informasi Vital [S7] | Penyelenggara IIV |
| Peraturan lembaga | Peraturan BSSN No. 8 Tahun 2020 dan No. 1 Tahun 2024 [S6][S3] | PSE, penyelenggara IIV |
| Peraturan sektor | POJK No. 11/POJK.03/2022 untuk bank umum [S8] | Sektornya saja |
| Kontrak | Perjanjian dengan pelanggan dan pemasok | Para pihak |

Dua kesalahan yang berulang: hanya memperhatikan undang-undang lalu terkejut oleh ketentuan sektor yang lebih rinci, dan melupakan kontrak yang sering lebih ketat daripada regulasi. Seluruh lapisan masuk ke klausul 4.2 dan menjadi masukan penilaian risiko di 6.1 (Day 03 dan Day 04).

### 1.2 UU PDP: kewajiban yang menyentuh ISMS

PT AN memproses data pribadi karyawannya dan data pengguna portal pelanggan, jadi UU PDP adalah lapisan pertama yang diperiksa. Masa penyesuaian 2 tahun (Pasal 74) sudah berakhir 17 Oktober 2024 [S1]; tanggal berlakunya ada di bagian 6.

Tabel ini hanya memuat pasal yang menyentuh ISMS, bukan seluruh UU. Cari pasal yang menghasilkan proses atau bukti: rekaman pemrosesan, DPIA, pemberitahuan, pengawasan prosesor, dan transfer.

| Pasal | Inti kewajiban (kata sendiri) |
|---|---|
| 35 | Melindungi dan memastikan keamanan data pribadi lewat langkah teknis operasional, dengan tingkat keamanan sesuai sifat dan risiko data |
| 36-39 | Menjaga kerahasiaan, mengawasi pihak yang terlibat dalam pemrosesan, mencegah pemrosesan dan akses tidak sah |
| 31 | Merekam seluruh kegiatan pemrosesan |
| 34 | DPIA bila pemrosesan berisiko tinggi: keputusan otomatis berdampak hukum, data spesifik, skala besar, pemantauan sistematis, penggabungan data, teknologi baru |
| 46 | Pemberitahuan kegagalan pelindungan data pribadi (bagian 1.6) |
| 51-52 | Prosesor bekerja atas perintah pengendali; subprosesor perlu persetujuan tertulis; Pasal 35-39 juga berlaku bagi prosesor |
| 53-54 | Pejabat atau petugas pelindungan data pribadi (PPDP) wajib bila pemrosesan untuk pelayanan publik, ada pemantauan sistematis berskala besar, atau data spesifik berskala besar; tugasnya memberi saran, memantau kepatuhan, memberi saran atas DPIA, dan menjadi narahubung |
| 56 | Transfer ke luar Indonesia, berurutan: negara penerima setara atau lebih tinggi; bila tidak, pelindungan yang memadai dan mengikat; bila tidak ada, persetujuan subjek data |
| 57 | Sanksi administratif: peringatan tertulis, penghentian sementara pemrosesan, penghapusan data, denda paling tinggi 2% pendapatan tahunan |
| 58-61 | Penyelenggaraan PDP oleh lembaga yang bertanggung jawab kepada Presiden, dibentuk lewat Perpres |

Pasal 53 ayat (1) huruf b, salah satu syarat wajib PPDP, menjadi objek Putusan MK yang dicatat di bagian 6; baca putusannya sebelum menyimpulkan kewajiban menunjuk PPDP.

Pidana diatur di Pasal 67-70, hak subjek data di Pasal 5-13. Tenggat hak subjek yang perlu diketahui tim operasional: pembetulan (Pasal 30), akses (Pasal 32), penghentian pemrosesan setelah persetujuan ditarik (Pasal 40), dan pembatasan (Pasal 41) masing-masing paling lambat 3 x 24 jam sejak permintaan diterima [S1]. Tenggat sependek itu mustahil tanpa inventaris yang menyebut di sistem mana data seseorang tersimpan.

### 1.3 PP 71/2019: kewajiban penyelenggara sistem elektronik

PT AN menjalankan layanan hosting dan portal pelanggan yang dipakai pengguna, sehingga perlu tahu posisinya sebagai PSE. Jawabannya menentukan kewajiban pendaftaran dan aturan lokasi data.

PSE Lingkup Publik adalah instansi penyelenggara negara atau institusi yang ditunjuknya; PSE Lingkup Privat adalah orang, badan usaha, atau masyarakat (Pasal 1 angka 5-6) [S2]. Lingkup privat mencakup PSE yang diawasi kementerian atau lembaga dan aplikasi untuk perdagangan, transaksi keuangan, konten berbayar, komunikasi, mesin pencari, serta pemrosesan data pribadi (Pasal 2 ayat (5)).

Tabel ini merangkum kewajiban PSE yang paling sering bertemu ISMS. Perhatikan baris 20 dan 21: lingkup publik dan privat diperlakukan berbeda soal lokasi data.

| Pasal | Inti |
|---|---|
| 6 | Mendaftar sebelum sistem dipakai pengguna, lewat OSS |
| 3-4 | Menyelenggarakan sistem secara andal dan aman, termasuk melindungi ketersediaan, keutuhan, keotentikan, kerahasiaan, dan keteraksesan |
| 14 ayat (5) | Memberi tahu pemilik data secara tertulis bila pelindungan data pribadi gagal |
| 20 | Lingkup Publik: wajib punya rencana keberlangsungan, dan data serta sistem dikelola di Indonesia kecuali teknologinya tidak tersedia di dalam negeri |
| 21 | Lingkup Privat: boleh di luar Indonesia, asal efektivitas pengawasan dan akses penegakan hukum dijamin; sektor keuangan diatur regulatornya |
| 22 | Menyediakan audit trail seluruh kegiatan |
| 24 | Punya prosedur dan sarana pengamanan; gangguan serius akibat perbuatan pihak lain dilaporkan segera pada kesempatan pertama ke aparat penegak hukum dan K/L terkait |
| 100 | Sanksi administratif, dari teguran tertulis sampai dikeluarkan dari daftar |

Pasal 24 ayat (4) mendelegasikan rincian pengamanan ke BSSN, dan dari situlah lahir Peraturan BSSN No. 8 Tahun 2020.

### 1.4 Lapisan BSSN dan infrastruktur informasi vital

Lapisan ini paling dekat dengan pekerjaan SOC: regulasi menyebut SNI ISO/IEC 27001 secara eksplisit, mewajibkan tim tanggap insiden, dan menetapkan tenggat laporan insiden siber.

**Peraturan BSSN No. 8 Tahun 2020.** Peraturan ini adalah titik tempat regulasi menyebut ISO 27001 secara eksplisit [S6]. PSE mengategorikan sistemnya lewat penilaian mandiri menjadi strategis (berdampak serius pada kepentingan umum, pelayanan publik, penyelenggaraan negara, atau pertahanan), tinggi (berdampak terbatas pada sektor atau daerah tertentu), atau rendah, lalu melaporkan hasilnya ke BSSN untuk diverifikasi (Pasal 6-7). Sistem strategis wajib menerapkan SNI ISO/IEC 27001 ditambah standar BSSN dan standar kementerian atau lembaga; sistem tinggi SNI ISO/IEC 27001 dan/atau standar BSSN; sistem rendah salah satunya (Pasal 9). Aturan sertifikasinya dibahas di Day 17.

**Perpres No. 82 Tahun 2022.** Sektor IIV meliputi administrasi pemerintahan, energi dan sumber daya mineral, transportasi, keuangan, kesehatan, TIK, pangan, pertahanan, dan sektor lain yang ditetapkan Presiden (Pasal 4) [S7]. PSE di sektor itu mengidentifikasi IIV minimal sekali setahun dan melapor ke K/L sektornya, yang menetapkan IIV dan penyelenggaranya (Pasal 6). Penyelenggara IIV wajib menerapkan standar keamanan yang ditetapkan (Pasal 9), manajemen risiko keamanan siber yang efektif (Pasal 10), dan melapor insiden siber paling lambat 1 x 24 jam setelah ditemukan (Pasal 13).

**Peraturan BSSN No. 1 Tahun 2024.** Peraturan ini melaksanakan Perpres 82/2022 [S3][S4]. Tim Tanggap Insiden Siber (TTIS) ada di tingkat nasional, sektoral, dan organisasi; penyelenggara IIV dan juga PSE di luar IIV wajib membentuk TTIS organisasi (Pasal 4-8). Insiden dengan tingkat risiko minimal tinggi dilaporkan ke TTIS sektoral dengan tembusan ke TTIS nasional, berisi kontak, deskripsi, kronologi, dan dampak (Pasal 15). Untuk IIV tenggatnya 1 x 24 jam; untuk PSE non-IIV teksnya tidak menyebut jam. Simulasi kesiapan dilakukan minimal sekali dalam 2 tahun (Pasal 26).

### 1.5 Contoh lapisan sektor: POJK 11/2022 untuk bank umum

Klien bank PT AN terikat POJK 11/2022. Ketentuan itu sampai ke PT AN lewat kontrak, seperti permintaan notifikasi di situasi Day ini (bagian 2.1, KW-05).

Ketentuan POJK No. 11/POJK.03/2022 yang paling sering bertemu ISMS [S8]:

- **Notifikasi insiden TI** yang berpotensi atau telah menimbulkan kerugian signifikan atau mengganggu operasional: notifikasi awal paling lama 24 jam setelah diketahui, laporan paling lama 5 hari kerja (Pasal 60).
- **Pusat data dan pusat pemulihan bencana** di Indonesia; di luar negeri hanya dengan izin OJK (Pasal 35-36).
- **Ketahanan siber:** penilaian mandiri maturitas tahunan (Pasal 22), pengujian berbasis skenario minimal setahun sekali (Pasal 23-25), dan DRP diuji minimal setahun sekali (Pasal 18).

Sektor lain punya ketentuannya sendiri. Cara membacanya sama: cari tenggat pelaporan, ketentuan lokasi data, dan kewajiban pengujian.

### 1.6 Pemberitahuan dan pelaporan: kewajiban yang berbeda

Pertanyaan kedua Direktur Operasional, laporan apa yang keluar bila ransomware mengenai data pelanggan, adalah tempat regulasi paling terasa bagi SOC. Satu insiden bisa memicu beberapa kewajiban dengan penerima dan tenggat berbeda.

Pasal 46 UU PDP mewajibkan pengendali memberi pemberitahuan tertulis paling lambat 3 x 24 jam kepada subjek data dan lembaga bila terjadi kegagalan pelindungan data pribadi [S1]. Isi minimalnya: data yang terungkap, kapan dan bagaimana terungkap, serta upaya penanganan dan pemulihan. Dalam hal tertentu, misalnya kegagalan yang mengganggu pelayanan publik, masyarakat juga harus diberi tahu. Penjelasan pasalnya mengartikan kegagalan sebagai gangguan kerahasiaan, keutuhan, atau ketersediaan, disengaja maupun tidak, sehingga ransomware yang membuat data tidak tersedia juga termasuk.

Teks UU tidak menyebut kapan hitungan 3 x 24 jam dimulai. Prosedur internal harus menetapkannya; pilihan yang aman adalah sejak kegagalan tervalidasi, bukan sejak investigasi selesai.

Tabel ini memisahkan kewajiban yang sering tercampur saat insiden. Baca per baris: dasar, penerima, dan tenggatnya berbeda, jadi satu insiden bisa memicu beberapa baris sekaligus.

| Kewajiban | Dasar | Kepada | Tenggat |
|---|---|---|---|
| Pemberitahuan kegagalan PDP | UU PDP Pasal 46 | Subjek data dan lembaga; masyarakat dalam hal tertentu | 3 x 24 jam |
| Pemberitahuan oleh PSE | PP 71/2019 Pasal 14 ayat (5) | Pemilik data | Tidak disebut |
| Laporan insiden siber IIV | Perpres 82/2022 Pasal 13; Peraturan BSSN 1/2024 Pasal 15 | TTIS sektoral, tembusan TTIS nasional | 1 x 24 jam setelah ditemukan |
| Gangguan serius akibat pihak lain | PP 71/2019 Pasal 24 ayat (3) | Aparat penegak hukum dan K/L terkait | Segera, kesempatan pertama |
| Insiden TI bank | POJK 11/2022 Pasal 60 | OJK | 24 jam notifikasi awal; 5 hari kerja laporan |

### 1.7 Di mana kewajiban bertemu kontrol

Pertanyaan ketiga meminta peta: kewajiban mana yang sudah dipenuhi oleh klausul dan kontrol ISMS, dan mana yang tidak. Peta ini juga yang membuat satu sistem mungkin, karena setiap kewajiban menunjuk proses yang sudah ada.

Tabel ini menunjukkan klausul atau kontrol ISO/IEC 27001:2022 tempat setiap jenis kewajiban dipenuhi. Cari baris terakhir: kewajiban yang tidak punya padanan di standar.

| Jenis kewajiban | Klausul dan kontrol ISO/IEC 27001:2022 |
|---|---|
| Identifikasi kewajiban hukum | 4.2; 5.31 persyaratan hukum, regulasi, dan kontrak |
| Inventaris dan rekam pemrosesan (UU PDP Pasal 31) | 5.9 inventaris; 5.12 klasifikasi; 5.34 privasi dan pelindungan PII |
| Keamanan pemrosesan (UU PDP Pasal 35-39) | 6.1.2, 6.1.3; kontrol hasil penilaian risiko, misalnya 5.15, 8.5, 8.24 |
| Prosesor dan subprosesor (Pasal 51) | 5.19-5.22 hubungan pemasok; 5.23 layanan cloud |
| Pemberitahuan dan pelaporan (bagian 1.6) | 5.24-5.28 manajemen insiden; 5.5 kontak dengan otoritas |
| Lokasi data (PP 71 Pasal 20-21; POJK Pasal 35) | 5.23; 8.13 backup; 5.19-5.22 |
| Audit trail (PP 71 Pasal 22) | 8.15 logging; 5.28 pengumpulan bukti |
| Rencana keberlangsungan (PP 71 Pasal 20; POJK Pasal 18) | 5.29 keamanan saat gangguan; 5.30 kesiapan ICT |
| SNI ISO/IEC 27001 (Peraturan BSSN 8/2020) | Seluruh ISMS; lingkup (4.3) harus mencakup sistem yang dikategorikan |
| DPIA, dasar pemrosesan, hak subjek data | Tidak ada padanan langsung; perlu tata kelola privasi (Day 19) |

Regulasi melampaui standar di empat titik: tenggat dalam jam, penerima laporan yang ditentukan, lokasi data, serta hak subjek data dan sanksi. Untuk tiap titik, tambahkan persyaratannya ke ISMS dengan bukti pemenuhan, bukan proses kedua.

### 1.8 Satu sistem, status yang jujur

Pertanyaan keempat ("bagaimana semuanya dijalankan dalam satu sistem") dan kelima ("apa yang belum bisa kita pastikan") dijawab bersama: kewajiban masuk ke mesin ISMS yang sama, dan statusnya ditulis apa adanya, termasuk bila kewajibannya sendiri belum jelas.

Kewajiban regulasi diperlakukan sebagai persyaratan tambahan ISMS: satu register kewajiban yang merujuk ke klausul atau kontrol, satu register risiko, satu program audit dengan frekuensi lebih tinggi untuk area teregulasi (Day 15), satu jalur tindakan korektif, dan satu management review (Day 16). Yang tetap terpisah hanya bukti khusus regulator dan dokumen yang formatnya ditetapkan regulator, misalnya penilaian mandiri BSSN atau laporan insiden OJK.

Status kepatuhan ditulis dengan empat kategori:

```
TERPENUHI          : ada kewajiban, ada proses, ada bukti pelaksanaan
TERPENUHI SEBAGIAN : ada proses tetapi belum lengkap atau belum ada bukti
BELUM              : belum ada proses
BELUM PASTI        : kewajibannya sendiri belum jelas karena aturan pelaksana
                     atau lembaga penerima belum ada
```

Status keempat nyata di Indonesia saat ini. Pasal 46 menyebut pemberitahuan kepada lembaga, tetapi pembentukan lembaga PDP belum terkonfirmasi di sumber resmi, dan teks resmi PP pelaksana UU PDP yang diberitakan media juga belum ditemukan (bagian 6). Status yang jujur adalah belum pasti, dengan catatan apa yang ditunggu dan apa yang sudah disiapkan.

## 2. Contoh dokumen / artefak (organisasi fiktif)

Organisasi fiktif: PT Awan Nusantara (PT AN), penyedia hosting di Jakarta (PSE lingkup privat) yang melayani klien bank dan klien sektor kesehatan. Semua nomor dokumen, nama, dan angka di bawah adalah ilustrasi, bukan nasihat hukum. Kelima artefak ini adalah bahan jawaban ISMS Manager dan Lead SOC untuk lima pertanyaan Direktur Operasional di bagian Ide inti.

### 2.1 Register kewajiban kepatuhan

Register ini menjawab pertanyaan 1 dan 4: aturan mana yang berlaku, kenapa, dan proses mana yang memenuhinya. Perhatikan kolom "dipenuhi oleh" dan "kontrol".

```
REGISTER KEWAJIBAN KEPATUHAN                 PT AN      versi 2.0, ditinjau 2027-01-15
Disusun bersama: Legal, pejabat pelindungan data pribadi (PPDP), pemilik risiko

KW-01
  kewajiban      : memberitahukan kegagalan pelindungan data pribadi
  dasar hukum    : UU 27/2022 Pasal 46 ayat (1)-(3); PP 71/2019 Pasal 14 ayat (5)
  berlaku karena : kami pengendali data pribadi karyawan dan pengguna portal pelanggan
  tenggat        : 3 x 24 jam; titik mulai internal = saat kegagalan tervalidasi (IR-01 9.2)
  dipenuhi oleh  : IR-01 pasal 9; templat pemberitahuan lampiran 4; pohon keputusan lampiran 3
  kontrol        : 5.24-5.28, 5.5, 5.34
  bukti          : catatan uji tabletop 2026-11; daftar kontak eskalasi
  pemilik        : PPDP
  status         : terpenuhi sebagian (templat ada, kanal ke lembaga belum pasti)
  tinjau         : 2027-07-15

KW-02
  kewajiban      : pendaftaran PSE lingkup privat sebelum sistem dipakai pengguna
  dasar hukum    : PP 71/2019 Pasal 2 ayat (5), Pasal 6
  dipenuhi oleh  : pendaftaran lewat OSS; pemantauan perubahan data pendaftaran
  bukti          : tanda daftar; catatan pembaruan terakhir
  pemilik        : Sekretaris Perusahaan
  status         : terpenuhi
  tinjau         : 2027-10-01

KW-03
  kewajiban      : kategorisasi sistem elektronik dan penerapan SNI ISO/IEC 27001
  dasar hukum    : Peraturan BSSN 8/2020 Pasal 6, 7, 9
  dipenuhi oleh  : penilaian mandiri dilaporkan ke BSSN; ISMS tersertifikasi
                   (lingkup: layanan managed VM AN-Hosting, DC Jakarta-1)
  bukti          : hasil verifikasi kategori dari BSSN (tinggi); sertifikat
  pemilik        : CISO
  status         : terpenuhi
  tinjau         : saat ada sistem baru atau perubahan besar

KW-04
  kewajiban      : TTIS organisasi dan pelaporan insiden siber berisiko minimal tinggi
  dasar hukum    : Peraturan BSSN 1/2024 Pasal 8, 15
  dipenuhi oleh  : IR-01 pasal 10; pendaftaran TTIS; pohon keputusan lampiran 3
  bukti          : tanda registrasi TTIS; catatan simulasi 2026
  pemilik        : Manajer Operasi Keamanan
  status         : terpenuhi sebagian (simulasi berikutnya paling lambat 2028)
  tinjau         : 2027-04-01

KW-05
  kewajiban      : mendukung klien bank memenuhi notifikasi 24 jam ke OJK
  dasar hukum    : kontrak dengan klien bank (turunan POJK 11/2022 Pasal 60)
  dipenuhi oleh  : notifikasi ke klien bank maksimal 4 jam setelah insiden diketahui (kontrak)
  status         : terpenuhi
  pemilik        : Account Manager + Manajer Operasi Keamanan

KW-06
  kewajiban      : ketentuan teknis peraturan pelaksana UU PDP
  dasar hukum    : PP pelaksana UU PDP (dilaporkan media sebagai PP 33/2026)
  status         : BELUM PASTI (teks resmi belum ditemukan di peraturan.bpk.go.id)
  catatan        : pantau JDIH Setneg dan BPK setiap bulan; lakukan gap analysis begitu teks resmi ada
  pemilik        : Legal
```

Kolom "dipenuhi oleh" dan "kontrol" menyatukan register ini dengan ISMS: setiap baris menunjuk prosedur yang sudah ada, bukan proyek baru.

### 2.2 Matriks kewajiban ke kontrol dan celah

Matriks ini menjawab pertanyaan 3. Baca kolom Celah, terutama baris yang klausul dan kontrolnya bertuliskan "tidak ada padanan" atau "sebagian".

| Kewajiban | Klausul | Kontrol | Celah |
|---|---|---|---|
| KW-01 pemberitahuan kegagalan PDP | 4.2, 10.2 | 5.24-5.28, 5.5, 5.34 | Kanal ke lembaga belum ada |
| KW-03 kategorisasi dan SNI ISO/IEC 27001 | 4.3 | seluruh Annex A sesuai SoA | Sistem baru belum masuk lingkup |
| KW-04 pelaporan insiden siber | 10.2 | 5.24, 5.26 | Simulasi belum dijadwalkan |
| Hak subjek data, 3 x 24 jam (UU PDP Pasal 30, 32, 40, 41) | tidak ada padanan | tidak ada padanan | Proses baru diperlukan |
| DPIA (UU PDP Pasal 34) | 6.1.2 sebagian | 5.34 sebagian | Metode DPIA belum ada |
| Transfer ke luar negeri (UU PDP Pasal 56) | 6.1, 8.1 | 5.19-5.23 | Lokasi data per layanan belum dipetakan |

Tiga baris terakhir menunjukkan ke manajemen bahwa ISMS saja tidak cukup.

### 2.3 Pemetaan lokasi data

Pemetaan ini menindaklanjuti baris terakhir matriks bagian 2.2 dan menyentuh langsung klien bank. Cari baris yang lokasi penyimpanannya berbeda dari lokasi pemrosesan.

| Layanan | Jenis data | Lokasi pemrosesan | Lokasi penyimpanan | Pemasok | Dasar transfer (UU PDP Pasal 56) |
|---|---|---|---|---|---|
| Email korporat | data pribadi karyawan | luar negeri | luar negeri | Pemasok A | <negara penerima setara? klausul kontrak? diisi Legal> |
| Managed VM pelanggan (AN-Hosting) | data pelanggan di dalam VM, termasuk klien bank | dalam negeri (DC Jakarta-1) | dalam negeri (DC Jakarta-1) | sendiri | tidak berpindah |
| Backup VM pelanggan | salinan VM pelanggan | dalam negeri | luar negeri | Pemasok B | <diisi Legal>; cek juga kontrak klien bank |
| Analitik portal pelanggan | data perilaku pengguna portal | luar negeri | luar negeri | Pemasok C | <diisi Legal> |

Baris backup adalah temuan yang sangat sering: data utamanya di dalam negeri, salinannya tidak. Bagi PT AN baris itu juga menyentuh kontrak klien bank, yang terikat ketentuan lokasi pusat data POJK 11/2022.

### 2.4 Tenggat regulasi di prosedur insiden

Pasal prosedur dan lampiran ini menjawab pertanyaan 2: laporan apa yang keluar, ke siapa, dan sejak kapan jam dihitung. Perhatikan pasal 9.2 dan catatan perancangannya.

```
IR-01 pasal 9  PEMBERITAHUAN KEPADA PIHAK LUAR

9.1  Begitu insiden divalidasi, Koordinator Insiden menjalankan pohon keputusan pelaporan
     (lampiran 3) dan mencatat WAKTU VALIDASI di tiket.
9.2  Untuk kegagalan pelindungan data pribadi, hitungan 3 x 24 jam (UU PDP Pasal 46)
     dimulai sejak waktu validasi, BUKAN sejak insiden selesai ditangani.
9.3  Untuk klien bank, notifikasi dikirim maksimal 4 jam setelah insiden diketahui (KW-05),
     agar klien bisa memenuhi 24 jam ke OJK.
9.4  Pemberitahuan awal dikirim walaupun informasi belum lengkap, menyebut apa yang belum
     diketahui dan kapan pembaruan dikirim. Isi minimum Pasal 46 ayat (2) wajib ada.
9.5  Bila tenggat tidak dapat dipenuhi, alasannya dicatat dan dilaporkan ke management review.

CATATAN PERANCANGAN
  UU tidak menyebut titik mulai 3 x 24 jam. Pasal 9.2 memilih titik paling awal yang bisa
  dipertanggungjawabkan. Tinjau ulang bila peraturan pelaksana menetapkan lain.
```

```
LAMPIRAN 3  POHON KEPUTUSAN PELAPORAN (fiktif, PT AN)

Q1  Insiden sudah divalidasi?          tidak -> lanjut investigasi, ulangi tiap pembaruan
                                       ya    -> catat WAKTU VALIDASI; jalankan Q2, Q4, Q5, Q6
Q2  Data pribadi terdampak (terungkap, diubah, hilang, tidak tersedia)?
                                       tidak/belum diketahui -> catat alasan, tinjau ulang
                                       ya    -> Q3
Q3  UU PDP Pasal 46: libatkan PPDP dan Legal SEKARANG; pemberitahuan ke subjek data dan
    lembaga dalam 3 x 24 jam sejak waktu validasi; nilai perlu tidaknya pemberitahuan publik.
Q4  Insiden siber berisiko minimal tinggi?  ya -> lapor TTIS sektoral, tembusan TTIS nasional
                                            (Peraturan BSSN 1/2024 Pasal 15); bila sistem IIV,
                                            paling lambat 1 x 24 jam
Q5  Gangguan berdampak serius akibat perbuatan pihak lain?
                                       ya -> lapor aparat penegak hukum dan K/L terkait
                                             pada kesempatan pertama (PP 71/2019 Pasal 24)
Q6  Klien bank terdampak?              ya -> notifikasi maksimal 4 jam (kontrak, KW-05)

Setiap jawaban, termasuk "tidak", dicatat di tiket beserta waktu dan nama pengambil keputusan.
```

Keputusan "tidak perlu melapor" yang tercatat beserta alasannya adalah bukti bahwa kewajiban dipertimbangkan.

### 2.5 Satu halaman status kepatuhan untuk management review

Halaman ini menjawab pertanyaan 5 dalam bentuk yang dibawa ke management review. Perhatikan bagian "Yang tidak bisa kami pastikan".

```
STATUS KEPATUHAN                              Semester 1 2027

RINGKASAN
  terpenuhi            : 6 dari 11 kewajiban
  terpenuhi sebagian   : 3
  belum                : 0
  belum pasti          : 2   (teks resmi PP pelaksana UU PDP; lembaga PDP)

YANG PERLU KEPUTUSAN
  1. Backup VM pelanggan tersimpan di luar negeri (bagian 2.3).
     Pilihan: (i) pindahkan, (ii) lengkapi dasar transfer Pasal 56, (iii) terima risiko sementara
  2. Hak subjek data dengan tenggat 3 x 24 jam belum punya proses.
     Pilihan: (i) bangun proses sendiri, (ii) sistem manajemen informasi privasi (Day 19)

YANG TIDAK BISA KAMI PASTIKAN
  Kanal pemberitahuan ke lembaga PDP belum ada. Kami menyiapkan templat dan memantau
  pembentukannya. Risiko ini tercatat sebagai R-0xx.
```

## 3. Lab praktik

**Prasyarat:** hasil Day 03, Day 04, dan Day 10. Seluruh lab memakai ringkasan pasal di bagian 1 dan organisasi fiktif. Simpan hasilnya di `latihan/day18-<nama-org-fiktif>.md`.

1. Untuk tiga profil fiktif, (a) PT AN, (b) rumah sakit swasta dengan aplikasi pendaftaran pasien, (c) dinas pemerintah daerah dengan portal layanan, tentukan: PSE publik atau privat, kemungkinan sektor IIV, dan kewajiban menunjuk PPDP.
2. Untuk profil (c), tulis konsekuensi PP 71/2019 Pasal 20 terhadap rencana memakai SaaS email yang datanya disimpan di luar negeri.
3. Isi kriteria penilaian mandiri Peraturan BSSN 8/2020 untuk PT AN dengan angka fiktif: nilai investasi sistem (lebih dari Rp30 miliar, Rp3-30 miliar, kurang dari Rp3 miliar), anggaran operasional tahunan (lebih dari Rp10 miliar, Rp1-10 miliar, kurang dari Rp1 miliar), dan kewajiban kepatuhan. Tulis kategori yang kamu perkirakan dan standar wajibnya menurut Pasal 9.
4. Susun register bagian 2.1 untuk profil (b): minimal delapan kewajiban dari empat lapisan, lengkap dengan pasal dan kontrol, lalu isi matriks bagian 2.2 dan tandai yang tanpa padanan.
5. Tabletop: ransomware di PT AN ditemukan Senin 09.00, divalidasi Senin 14.00, dan mengenkripsi basis data portal pelanggan serta beberapa VM klien bank. Hitung jam batas setiap baris tabel bagian 1.6 yang berlaku, termasuk notifikasi ke klien bank, dan tulis pengirimnya.
6. Ubah prosedur insiden Day 10 memakai bentuk bagian 2.4, termasuk catatan perancangan titik mulai 3 x 24 jam.
7. Susun pemetaan lokasi data bagian 2.3 untuk lima layanan, termasuk backup dan email, dengan dasar transfer Pasal 56 yang paling mungkin.
8. Rancang proses permintaan akses subjek data yang selesai dalam 3 x 24 jam: penerima, verifikasi identitas, sistem sumber, dan bukti pemenuhan.
9. Periksa status PP pelaksana UU PDP dan lembaga PDP di peraturan.bpk.go.id dan JDIH Setneg pada tanggal pengerjaan, perbarui baris KW-06, lalu susun satu halaman status bagian 2.5.

**Hasil yang sebaiknya tersimpan:**
- Tabel penerapan regulasi tiga profil dan analisis Pasal 20 untuk profil (c).
- Penilaian mandiri kategori sistem PT AN.
- Register dan matriks kewajiban profil (b) dengan celah ditandai.
- Timeline tabletop dengan jam batas tiap kewajiban.
- Prosedur insiden dengan tenggat dan titik mulai.
- Pemetaan lokasi data lima layanan.
- Rancangan proses permintaan akses subjek data.
- Catatan status PP pelaksana dan lembaga PDP, serta halaman status kepatuhan.

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Kewajiban sektor baru ketahuan saat audit | Hanya memperhatikan UU dan PP | Tambahkan lapisan sektor dan kontrak ke register (bagian 1.1) |
| Beberapa daftar kontrol untuk regulasi berbeda | Tiap regulasi diperlakukan sebagai proyek sendiri | Satukan ke register kewajiban (bagian 1.8) |
| Pemberitahuan selalu terlambat pada latihan | Jam dihitung dari selesainya penanganan | Tetapkan titik mulai di prosedur (bagian 2.4) |
| Tim bingung laporan mana yang dikirim | Kewajiban berbeda dicampur | Pakai tabel bagian 1.6 dan lampiran 3 |
| Permintaan akses subjek data lewat 3 x 24 jam | Tidak tahu data tersimpan di sistem mana | Lengkapi inventaris dan rekam pemrosesan (UU PDP Pasal 31; kontrol 5.9) |
| Salinan backup ternyata di luar negeri | Backup tidak masuk pemetaan | Masukkan backup sebagai layanan tersendiri (bagian 2.3) |
| Tenggat berbeda antar sumber | Mengutip ringkasan pihak ketiga | Cocokkan ke teks resmi sebelum masuk prosedur |

## 5. Kesalahan umum dan jebakan

- Menganggap sertifikasi ISO 27001 otomatis memenuhi UU PDP atau PP 71/2019 (bagian 1.7).
- Membangun sistem terpisah untuk tiap regulasi, atau melupakan lapisan sektor dan kontrak (bagian 1.1 dan 1.8).
- Menghitung 3 x 24 jam dari selesainya penanganan insiden.
- Mencampur pemberitahuan kegagalan PDP dengan laporan insiden siber ke TTIS.
- Menunda pemberitahuan awal sampai informasi lengkap.
- Membiarkan hak subjek data tanpa pemilik karena tidak ada padanannya di ISMS.
- Menulis kewajiban yang aturannya belum lengkap sebagai sudah terpenuhi.

## 6. Catatan terkini

Bagian ini menampung tanggal berlaku regulasi dan status aturan yang belum terverifikasi. Tanggal berlaku berguna saat membaca dokumen lama; status PP pelaksana, lembaga PDP, dan putusan MK perlu dicek ulang sebelum mengubah prosedur.

- UU No. 27 Tahun 2022 berlaku sejak diundangkan 17 Oktober 2022 (Pasal 76), dengan masa penyesuaian 2 tahun (Pasal 74) yang berakhir 17 Oktober 2024 [S1].
- PP No. 71 Tahun 2019 berlaku sejak 10 Oktober 2019 [S2].
- POJK No. 11/POJK.03/2022 diundangkan 7 Juli 2022 dan berlaku 3 bulan kemudian (Pasal 73) [S8].
- Beberapa media dan kantor hukum melaporkan bahwa peraturan pelaksana UU PDP terbit sebagai PP No. 33 Tahun 2026, ditetapkan 16 Juli 2026 dan berlaku 16 Januari 2027, dengan ketentuan antara lain tentang data anak, DPIA, PPDP, transfer lintas negara, dan variabel denda [S5]. Per 2026-10-10, pencarian PP tahun 2026 dengan kata kunci "data pribadi" di peraturan.bpk.go.id tidak menghasilkan apa pun [S9]. Cek teks resminya di JDIH Setneg atau BPK sebelum mengubah prosedur, terutama apakah PP ini menetapkan titik mulai 3 x 24 jam.
- Pembentukan lembaga penyelenggara PDP (UU PDP Pasal 58) belum terkonfirmasi lewat Perpres yang bisa ditemukan di sumber resmi per 2026-10-10. Selama itu, kanal pemberitahuan kepada lembaga berstatus belum pasti.
- Laman BPK untuk UU PDP mencatat Putusan MK No. 151/PUU-XXII/2024 atas Pasal 53 ayat (1) huruf b (kata "dan" dimaknai "dan/atau") [S1]. Baca putusannya sebelum menyimpulkan kewajiban menunjuk PPDP.

## 7. Cheat sheet

```
BUKAN nasihat hukum. Cocokkan pasal dengan teks resmi terbaru.

LAPISAN  UU PDP | PP 71/2019 | Perpres 82/2022 | Peraturan BSSN 8/2020, 1/2024 | sektor (POJK 11/2022) | KONTRAK
         semuanya masuk klausul 4.2 + kontrol 5.31, lalu ke penilaian risiko 6.1

UU PDP (27/2022; berlaku 17 Okt 2022; penyesuaian berakhir 17 Okt 2024)
  Ps 35-39 keamanan pemrosesan | Ps 31 rekam pemrosesan | Ps 34 DPIA
  Ps 46 kegagalan PDP: tertulis, 3 x 24 jam, ke subjek + lembaga (+ publik dalam hal tertentu)
        isi: data terungkap, kapan & bagaimana, penanganan; TITIK MULAI TIDAK DISEBUT UU
  Ps 51-52 prosesor | Ps 53-54 PPDP | Ps 56 transfer: setara -> memadai & mengikat -> persetujuan
  Ps 57 sanksi admin, denda maks 2% pendapatan tahunan | hak subjek: 3 x 24 jam (Ps 30, 32, 40, 41)

PP 71/2019  publik vs privat (Ps 1-2) | daftar sebelum dipakai (Ps 6) | andal & aman (Ps 3-4)
  beri tahu pemilik data bila gagal (Ps 14(5)) | publik: data di Indonesia (Ps 20)
  privat: boleh di luar, akses pengawasan dijamin (Ps 21) | audit trail (Ps 22) | lapor segera (Ps 24)

BSSN 8/2020  kategori strategis/tinggi/rendah lewat penilaian mandiri, lapor BSSN
  strategis WAJIB SNI ISO/IEC 27001 + standar BSSN + standar K/L (Ps 9)
BSSN 1/2024 + Perpres 82/2022  TTIS organisasi (juga PSE non-IIV) | lapor risiko >= tinggi
  IIV: 1 x 24 jam setelah ditemukan | simulasi min 2 tahun sekali
POJK 11/2022  notifikasi awal 24 jam, laporan 5 hari kerja (Ps 60) | DC & DRC di Indonesia (Ps 35)

TANPA PADANAN DI ISMS  hak subjek data | DPIA | dasar pemrosesan -> sistem privasi (Day 19)

STATUS  terpenuhi | sebagian | belum | BELUM PASTI (PP pelaksana belum terverifikasi, lembaga PDP)
LOKASI DATA  jangan lupa BACKUP dan EMAIL; temuan khas: data di dalam negeri, salinannya tidak
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** ISMS PT AN tersertifikasi ISO 27001, dan kategori sistemnya sudah diverifikasi BSSN. Seorang manajer menyimpulkan bahwa kewajiban UU PDP otomatis sudah terpenuhi. Benarkah?

<details><summary>Jawaban</summary>

Tidak. Di register PT AN, sertifikat menjadi bukti untuk baris penerapan SNI ISO/IEC 27001 dari Peraturan BSSN 8/2020 (KW-03), dan banyak kewajiban UU PDP punya padanan di ISMS (keamanan pemrosesan, inventaris, manajemen insiden). Tetapi regulasi melampaui standar di empat titik: tenggat dalam jam, penerima laporan yang ditentukan, lokasi data, serta hak subjek data dan sanksi. DPIA, dasar pemrosesan, dan hak subjek data dengan tenggat 3 x 24 jam tidak punya padanan langsung di standar, sehingga di matriks PT AN barisnya tercatat sebagai celah. Lihat bagian 1.7 dan 2.2.

</details>

**2. Pertanyaan jebakan.** Ransomware mengenkripsi basis data portal pelanggan PT AN. Forensik menunjukkan tidak ada data yang keluar dari jaringan. Lead SOC berpendapat Pasal 46 UU PDP tidak relevan karena tidak ada kebocoran. Tepatkah?

<details><summary>Jawaban</summary>

Tidak. Penjelasan Pasal 46 mengartikan kegagalan pelindungan data pribadi sebagai gangguan kerahasiaan, keutuhan, atau ketersediaan, disengaja maupun tidak. Ransomware yang membuat data tidak tersedia termasuk di dalamnya, walaupun tidak ada data yang dicuri. Pohon keputusan PT AN juga menanyakan apakah data pribadi terungkap, diubah, hilang, atau tidak tersedia, bukan hanya apakah data bocor. Lihat bagian 1.6 dan 2.4.

</details>

**3. Skenario keputusan.** Ransomware di PT AN ditemukan Senin 09.00, divalidasi Senin 14.00, dan investigasi selesai Rabu 16.00. Data pribadi pengguna portal tidak tersedia. Bagaimana prosedur PT AN menetapkan batas pemberitahuan menurut Pasal 46?

- A. Hitung 3 x 24 jam sejak investigasi selesai, supaya isi pemberitahuan lengkap; batasnya Sabtu 16.00.
- B. Hitung 3 x 24 jam sejak waktu validasi; batasnya Kamis 14.00, dan pemberitahuan awal dikirim walaupun informasi belum lengkap.
- C. Tunda penetapan titik mulai sampai teks resmi PP pelaksana UU PDP terverifikasi.

<details><summary>Jawaban</summary>

B. Teks UU tidak menyebut kapan hitungan dimulai, jadi prosedur internal harus menetapkannya. PT AN memilih waktu validasi sebagai titik paling awal yang bisa dipertanggungjawabkan (IR-01 9.2), sehingga Senin 14.00 ditambah 72 jam menjadi Kamis 14.00. Pemberitahuan awal tetap memuat isi minimum Pasal 46 ayat (2) dan menyebut apa yang belum diketahui. A keliru karena menghitung dari selesainya penanganan adalah penyebab umum pemberitahuan terlambat, dan menunggu informasi lengkap juga termasuk kesalahan umum. C keliru karena kewajiban Pasal 46 sudah ada di UU; yang belum pasti adalah kemungkinan PP pelaksana menetapkan lain, dan catatan perancangan prosedur sudah menyebut kapan harus ditinjau ulang. Lihat bagian 1.6, 2.4, dan 5.

</details>

**4. Skenario keputusan.** Klien bank meminta PT AN ikut memastikan bank bisa memenuhi notifikasi 24 jam ke OJK. Bagaimana kewajiban ini sebaiknya masuk ke ISMS PT AN?

- A. PT AN melaporkan insiden langsung ke OJK dalam 24 jam, karena POJK 11/2022 berlaku untuk semua pemasok bank.
- B. PT AN mencatatnya sebagai kewajiban kontrak di register: notifikasi ke klien bank maksimal 4 jam setelah insiden diketahui, dipenuhi lewat prosedur insiden yang sudah ada.
- C. PT AN mengabaikannya, karena POJK hanya mengatur bank.

<details><summary>Jawaban</summary>

B. Peraturan sektor berlaku bagi sektornya saja, tetapi kontrak adalah lapisan kewajiban tersendiri dan sering lebih ketat daripada regulasi. Di register PT AN, KW-05 berdasar kontrak dengan klien bank sebagai turunan POJK 11/2022 Pasal 60, dan pasal 9.3 prosedur insiden serta Q6 pohon keputusan mengirim notifikasi dalam 4 jam supaya bank bisa memenuhi 24 jam ke OJK. A keliru karena tabel lapisan menempatkan POJK sebagai peraturan yang berlaku bagi sektornya; register PT AN tidak mencatat kewajiban lapor langsung ke OJK. C keliru karena melupakan lapisan kontrak adalah salah satu dari dua kesalahan yang paling sering berulang. Lihat bagian 1.1, 1.5, dan 2.1.

</details>

**5. Skenario keputusan.** Memo Legal menyebut media memberitakan PP No. 33 Tahun 2026 sebagai peraturan pelaksana UU PDP. Bagaimana baris KW-06 sebaiknya ditulis?

- A. Terpenuhi, karena prosedur insiden PT AN sudah mencakup Pasal 46.
- B. Belum, lalu ubah prosedur sekarang mengikuti isi PP menurut pemberitaan media.
- C. Belum pasti, dengan catatan teks resmi belum ditemukan di peraturan.bpk.go.id, pantauan berkala ke JDIH Setneg dan BPK, dan gap analysis begitu teks resmi tersedia.

<details><summary>Jawaban</summary>

C. Status belum pasti dipakai bila kewajibannya sendiri belum jelas karena aturan pelaksana atau lembaga penerima belum ada. Per tanggal riset, PP itu hanya didukung media dan kantor hukum, sedangkan pencarian di basis data BPK tidak menemukannya. Status yang jujur menyebut apa yang ditunggu dan apa yang sudah disiapkan. A keliru karena menulis kewajiban yang aturannya belum lengkap sebagai terpenuhi adalah kesalahan umum. B keliru karena tenggat dan ketentuan harus dicocokkan ke teks resmi sebelum masuk prosedur. Lihat bagian 1.8, 2.1, dan 6.

</details>

**6. Jelaskan ulang.** Jelaskan kepada Direktur Operasional dalam tiga kalimat kenapa PT AN tidak perlu lima proyek kepatuhan terpisah, tanpa memakai kata "klausul" atau "Annex".

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Setiap aturan kita catat di satu register yang menyebut dasar hukumnya, kenapa berlaku bagi kita, dan prosedur mana yang sudah memenuhinya, lalu semuanya diaudit dan dibahas di rapat tinjauan yang sama. Pekerjaan tambahannya hanya di titik tempat aturan menuntut lebih dari yang sudah kita jalankan, misalnya tenggat laporan dalam hitungan jam, penerima laporan tertentu, lokasi data, dan permintaan dari pemilik data. Yang tetap dibuat terpisah hanya dokumen yang formatnya ditentukan regulator, seperti penilaian mandiri BSSN atau laporan insiden untuk OJK."

Kesalahan yang sering muncul:
- Mengklaim sistem keamanan yang ada sudah menutup semua kewajiban. Hak subjek data dan DPIA tidak punya padanan dan butuh proses baru.
- Lupa menyebut kontrak sebagai sumber kewajiban, padahal tuntutan klien bank datang lewat kontrak.
- Menyatukan semuanya sampai dokumen berformat regulator ikut dilebur, padahal format itu ditetapkan regulator.

Lihat bagian 1.7 dan 1.8.

</details>

**7. Interview question (English).** "An incident at a company in Indonesia affects personal data and a bank client. How would you handle the overlapping notification requirements within an ISO 27001 ISMS?"

<details><summary>Sample answer</summary>

"I wouldn't build a separate process per regulation. The obligations sit in one compliance register, mapped to our incident management controls, 5.24 to 5.28 and 5.5 contact with authorities, and the incident procedure has a reporting decision tree. As soon as the incident is validated, we record the validation time and run the tree. For personal data, the PDP Law, Article 46, requires written notice to data subjects and the authority within 3 x 24 hours; the law doesn't say when the clock starts, so our procedure defines it as the validation time and we send an initial notice even if details are incomplete. If it's a high-risk cyber incident, it goes to the sectoral incident response team with a copy to the national one, within 1 x 24 hours for vital information infrastructure. For the bank client, our contract requires notification within four hours so they can meet OJK's 24-hour initial notification. Every decision, including 'no need to report', is logged with time and owner. And I'd be honest about gaps: the authority under the PDP Law hasn't been confirmed in official sources yet, so that channel is marked as uncertain, with a template ready."

What makes this answer strong: it keeps one system, separates each obligation by recipient and deadline, explains how the undefined start of the clock is handled, and states openly what is still uncertain instead of claiming full compliance.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Undang-Undang Nomor 27 Tahun 2022 tentang Pelindungan Data Pribadi | https://peraturan.bpk.go.id/Details/229798/uu-no-27-tahun-2022 | primer | 17 Oktober 2022; diakses 2026-10-10 | Tinggi. Teks resmi (LN 2022/196) untuk Pasal 5-13, 30-41, 46, 50-61, 67-70, 74, 76; metadata putusan MK dari laman yang sama |
| S2 | Peraturan Pemerintah Nomor 71 Tahun 2019 tentang Penyelenggaraan Sistem dan Transaksi Elektronik | https://peraturan.bpk.go.id/Details/122030/pp-no-71-tahun-2019 | primer | berlaku 10 Oktober 2019; diakses 2026-10-10 | Tinggi. Teks resmi (LN 2019/185) untuk Pasal 1-6, 14, 20-24, 100 |
| S3 | Peraturan BSSN Nomor 1 Tahun 2024 tentang Pengelolaan Insiden Siber | https://peraturan.bpk.go.id/Details/291240/peraturan-bssn-no-1-tahun-2024 | primer | berlaku 18 Januari 2024; diakses 2026-10-10 | Tinggi. Teks resmi (BN 2024/43) untuk Pasal 2-28 |
| S4 | JDIH BSSN | https://jdih.bssn.go.id/ | primer | dirujuk 2026-10-09 | Tinggi sebagai tempat memverifikasi peraturan BSSN |
| S5 | Katadata, PP Pelindungan Data Pribadi Berlaku Januari 2027 | https://katadata.co.id/finansial/makro/6a9979b7c5745/pp-pelindungan-data-pribadi-berlaku-januari-2027-ini-aturan-baru-data-anak | sekunder (media) | 3 September 2026; diakses 2026-10-10 | Sedang. Nomor, tanggal, dan sebagian isi PP 33/2026 menurut media; belum dicocokkan dengan teks resmi |
| S6 | Peraturan BSSN Nomor 8 Tahun 2020 tentang Sistem Pengamanan dalam Penyelenggaraan Sistem Elektronik | https://peraturan.go.id/files/bn1375-2020.pdf | primer | diundangkan 23 November 2020; diakses 2026-10-10 | Tinggi. Teks resmi (BN 2020/1375) untuk Pasal 6-9, 26-34 dan lampiran; status berlaku di https://peraturan.bpk.go.id/Details/174285/peraturan-bssn-no-8-tahun-2020 |
| S7 | Peraturan Presiden Nomor 82 Tahun 2022 tentang Pelindungan Infrastruktur Informasi Vital | https://peraturan.go.id/files/ps82-2022.pdf | primer | 24 Mei 2022; diakses 2026-10-10 | Tinggi. Teks resmi (LN 2022/129) untuk Pasal 4, 6, 9, 10, 13 |
| S8 | POJK Nomor 11/POJK.03/2022 tentang Penyelenggaraan Teknologi Informasi oleh Bank Umum | https://ojk.go.id/id/regulasi/Pages/Penyelenggaraan-Teknologi-Informasi-oleh-Bank-Umum.aspx | primer | diundangkan 7 Juli 2022; diakses 2026-10-10 | Tinggi. Teks resmi tertaut di laman untuk Pasal 18, 22-26, 35-36, 60, 72-73 |
| S9 | Pencarian basis data peraturan BPK: PP tahun 2026, kata kunci "data pribadi" | https://peraturan.bpk.go.id/Search?keywords=data+pribadi&tahun=2026&jenis=10 | primer (basis data resmi) | diakses 2026-10-10 | Tinggi untuk fakta bahwa PP pelaksana UU PDP belum tercatat di basis data BPK pada tanggal itu |

**Catatan sumber:** PP No. 33 Tahun 2026 hanya didukung media dan kantor hukum [S5] dan belum ada di basis data BPK [S9]; status lembaga PDP juga belum terkonfirmasi di sumber resmi. Putusan MK No. 151/PUU-XXII/2024 hanya diketahui dari metadata laman BPK. Pemetaan ke kontrol (bagian 1.7, 2.2) dan pohon keputusan (bagian 2.4) adalah susunan sendiri. Seluruh nomor dokumen, nama, dan angka di bagian 2 adalah fiktif.
