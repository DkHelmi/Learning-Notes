---
day: 18
title: 'Komunikasi dan pelaporan insiden: stakeholder, ritme update, out-of-band, dan kewajiban pelaporan di Indonesia'
researched_on: 2026-10-15
versions_checked: 'UU 27/2022 tentang Pelindungan Data Pribadi (diundangkan 17 Oktober 2022; teks pasal dan penjelasan dari salinan BPK); PP 71/2019 tentang Penyelenggaraan Sistem dan Transaksi Elektronik (salinan JDIH Kemenkeu); Peraturan BSSN 1/2024 tentang Pengelolaan Insiden Siber (ditetapkan 10 Januari 2024); PP 33/2026 pelaksanaan UU PDP (dilaporkan ditetapkan 16 Juli 2026 dan berlaku 16 Januari 2027; naskah resmi belum diperiksa); NIST SP 800-61 Rev. 3 (April 2025); NIST SP 800-61 Rev. 2 (Agustus 2012, digantikan Rev. 3); CISA Cybersecurity Incident and Vulnerability Response Playbooks (November 2021); NCSC UK, Plan your cyber incident response processes (review 19 September 2019); PagerDuty External Communication Guidelines (diakses 2026-10-15)'
---

# Day 18: Komunikasi dan pelaporan insiden (stakeholder, ritme update, out-of-band, dan kewajiban pelaporan di Indonesia)

Cakupan: membedakan empat jenis komunikasi insiden beserta pemiliknya, menyusun ritme dan isi update, memakai kanal out-of-band, membaca kewajiban pemberitahuan UU PDP dan kewajiban pelaporan lain yang relevan bagi penyelenggara sistem elektronik di Indonesia, menulis pemberitahuan ke subjek data, lembaga, pelanggan, dan media, serta mencatat semua komunikasi supaya bisa dipertanggungjawabkan.

## Ide inti

Komunikasi adalah bagian dari respons, bukan pekerjaan setelah respons selesai. Insiden yang ditangani rapi secara teknis tetap bisa gagal bila pimpinan mendengar kabar dari media, pelanggan diberi tahu terlambat, regulator menerima laporan yang isinya berbeda dengan pernyataan publik, atau penyerang membaca rencana containment di email yang ia kuasai. Karena itu setiap pesan insiden menjawab empat hal yang sama: untuk siapa, siapa yang berhak mengirim, lewat kanal apa, dan berdasarkan fakta apa. Kewajiban hukum menambah satu hal lagi: waktu. Untuk itu waktu, dasar keputusan, dan isi setiap pemberitahuan dicatat sejak awal.

Kamu sudah mengenal pola ini dari NOC. Saat gangguan massal, engineer di bridge tidak menelepon pelanggan sendiri; update ke pelanggan korporat dikirim berkala oleh account manager dengan isi yang disepakati, status page diperbarui satu pintu, dan laporan gangguan ke regulator telekomunikasi dikirim oleh bagian regulasi dengan batas waktu yang dihitung dari titik yang ditetapkan aturan. Bila jaringan produksi bermasalah, engineer memakai jalur manajemen out-of-band. IR memakai pola yang sama dengan dua perbedaan. Pertama, kanal internal sendiri bisa sedang dibaca penyerang. Kedua, yang dilaporkan bukan hanya layanan yang turun, tetapi data pribadi orang lain, dan kewajiban atas data itu tetap ada walaupun layanan berjalan normal.

```
insiden dinyatakan
  |
  +-- koordinasi (internal + pihak dengan peran)   IC, kanal insiden / OOB
  |     ritme update sesuai severity
  |
  +-- notifikasi (formal, wajib)                   DPO + Legal, A: executive sponsor
  |     subjek data, lembaga, aparat, BSSN, sektor, kontrak
  |
  +-- komunikasi publik                            Corporate Communication, satu pintu
  |     holding statement, media, CS
  |
  +-- berbagi informasi (sukarela)                 SOC, lewat jalur yang disepakati
        IOC dan TTP ke komunitas atau mitra

semua pesan: fakta terverifikasi | yang belum diketahui | langkah berikutnya | update berikutnya
semua pesan dicatat: waktu, pengirim, penerima, isi, dasar keputusan
```

Situasi yang dipakai sepanjang Day ini melanjutkan `INC-2026-019` di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif yang menjadi pengendali data pribadi sekitar 400 ribu pelanggan broadband. Ringkasnya: lampiran email dijalankan di tiga laptop staf penagihan, kredensial akun service `svc_billing` dibaca dari skrip, dan penyerang memakai server billing `jkt-billing01` untuk terhubung ke database pelanggan. DPO Agus Setiawan dan Legal Ratna Sari diberi tahu Selasa 2026-10-13 pukul 12:20, severity naik ke SEV-1 pukul 13:35, dan containment serentak dijalankan pukul 16:00. Rabu 2026-10-14 pukul 10:00, retainer PT Forensik Digital Contoh menyimpulkan bahwa 5.000 baris data pelanggan (nama, NIK, alamat, telepon) kemungkinan besar diambil, dengan keyakinan sedang-tinggi; IC Dimas Prasetyo meneruskannya ke Agus dan Ratna pukul 10:20. Pukul 10:35, Direktur Teknologi Hendra Wijaya menulis di grup Signal "JAB-CSIRT-OOB":

> "Saya sudah baca kesimpulan retainer. Sebelum rapat jam 11:00 saya mau jelas dulu. Siapa saja yang harus kita beri tahu, dan siapa yang bicara atas nama perusahaan? Update ke saya dan direksi sebaiknya seberapa sering, isinya apa? Kenapa kita masih di Signal, apa Teams dan email sudah aman? Agus bilang UU PDP 3 x 24 jam: dihitung dari kapan, ke siapa saja, dan isinya apa? Selain UU PDP, ada kewajiban lapor lain, ke polisi, BSSN, Komdigi? Maya tanya apa yang harus dia jawab kalau wartawan atau pelanggan menelepon. Terakhir, bagaimana kita membuktikan nanti bahwa semua kewajiban ini kita penuhi tepat waktu?"

Pesan itu memuat tujuh pertanyaan:

1. Siapa saja yang perlu diberi tahu, dan siapa yang berbicara atas nama perusahaan?
2. Seberapa sering update dikirim, dan apa isinya?
3. Kapan kanal out-of-band dipakai, dan kapan boleh kembali ke kanal biasa?
4. Apa yang diwajibkan UU PDP Pasal 46, ke siapa, dan kapan hitungan 3 x 24 jam dimulai?
5. Kewajiban pelaporan apa lagi yang mungkin berlaku?
6. Apa yang dikatakan ke subjek data, pelanggan, dan media?
7. Bagaimana membuktikan bahwa kewajiban itu dipenuhi?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, pertanyaan 6 di bagian 1.6, dan pertanyaan 7 di bagian 1.7. Bagian 2 berisi dokumen yang dipakai PT JAB hari itu dan keesokan harinya.

**Kapan relevan:** sejak insiden dinyatakan, setiap kali ada pihak yang harus tahu, berhak tahu, atau wajib diberi tahu; dan sebelum insiden, saat menyusun peta stakeholder, template, kanal cadangan, serta prosedur pelaporan bersama Legal dan DPO.
**Kapan bukan jawaban:** Day ini bukan nasihat hukum. Regulasi dijelaskan secara umum dari teks resmi; penerapannya pada satu kasus, termasuk titik mulai hitungan dan instansi yang dituju, diputuskan Legal dan DPO. Day ini juga bukan tentang laporan insiden akhir dan post-incident review, yang dibahas di Day 19.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (severity, IC, executive sponsor, scope statement, kanal insiden, containment, retainer) tidak diulang. Tabel berikut memuat istilah baru Day ini. Kolom padanan memakai analogi NOC dan SOC yang sama di semua Day IR.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Koordinasi insiden | Komunikasi tentang aktivitas respons di antara pihak yang punya peran | Diskusi di bridge gangguan massal |
| Notifikasi insiden | Pemberitahuan formal ke pihak terdampak atau berwenang, sering diwajibkan aturan atau kontrak | Laporan gangguan ke regulator telekomunikasi |
| Komunikasi publik | Pernyataan tentang status insiden ke publik, termasuk jawaban ke media | Pengumuman gangguan di status page dan media sosial |
| Berbagi informasi | Membagikan IOC dan TTP ke organisasi lain, biasanya sukarela | Berbagi info serangan DDoS dengan ISP lain lewat forum operator |
| Satu pintu | Hanya orang yang ditunjuk yang berbicara ke pihak luar | Hanya account manager atau call center yang bicara ke pelanggan |
| Holding statement | Pernyataan singkat yang sudah disetujui, dipakai sebelum fakta lengkap tersedia | Pesan "gangguan sedang ditangani" di status page |
| Kanal out-of-band (OOB) | Jalur komunikasi di luar email dan chat korporat yang mungkin dipantau penyerang | Jalur manajemen out-of-band saat jaringan produksi bermasalah |
| Kegagalan Pelindungan Data Pribadi | Kegagalan melindungi kerahasiaan, integritas, atau ketersediaan data pribadi, termasuk akses tidak sah (UU PDP) | Tidak ada padanan langsung; yang dihitung adalah data orang, bukan layanan |
| Pengendali Data Pribadi | Pihak yang menentukan tujuan dan mengendalikan pemrosesan data pribadi; di sini PT JAB | Pemilik jaringan yang bertanggung jawab atas data pelanggannya |
| Subjek Data Pribadi | Orang yang datanya diproses; di sini pelanggan PT JAB | Pelanggan yang terdampak gangguan |
| Lembaga | Lembaga penyelenggara pelindungan data pribadi menurut UU PDP | Regulator sektor |
| TTIS | Tim Tanggap Insiden Siber; organisasi, sektoral, dan nasional menurut Peraturan BSSN 1/2024 | CSIRT perusahaan, CSIRT sektor, dan CSIRT nasional |
| Log komunikasi | Catatan setiap pesan keluar dan masuk: waktu, pengirim, penerima, isi, dasar | Log tiket gangguan berisi semua kontak dengan pelanggan |

### 1.1 Empat jenis komunikasi, empat pemilik

Pertanyaan pertama Hendra ("siapa saja, dan siapa yang bicara?") paling mudah dijawab bila komunikasi dipisah per jenis, karena tiap jenis punya penerima, aturan, dan pemilik yang berbeda.

NIST SP 800-61 Rev. 3 membagi aktivitas pelaporan dan komunikasi insiden (kategori RS.CO) menjadi empat: koordinasi insiden di antara pihak internal dan eksternal yang punya peran; notifikasi insiden, yaitu pemberitahuan formal ke pelanggan, karyawan, mitra, regulator, atau pihak lain tentang kebocoran data atau insiden lain; komunikasi publik, misalnya menjawab media; dan berbagi informasi ancaman, biasanya sukarela [S4]. Rev. 3 juga meminta mekanisme koordinasi disiapkan sebelum dibutuhkan, prosedur yang menyebut apa dilaporkan ke siapa dan kapan, notifikasi sesuai hukum yang berlaku untuk sektor dan lokasi organisasi, notifikasi ke pihak ketiga sesuai kewajiban regulasi, hukum, dan kontrak, serta notifikasi ke penegak hukum dan regulator berdasarkan kriteria di IR plan dan persetujuan manajemen, oleh orang yang ditunjuk (RS.CO-02) [S4].

Rev. 2 menambahkan daftar pihak yang biasanya dilibatkan, antara lain public affairs untuk insiden yang bisa menarik perhatian publik, departemen legal untuk insiden dengan konsekuensi hukum, dan penegak hukum bila sesuai; dan meminta semua kontak dengan pihak luar didokumentasikan untuk keperluan tanggung jawab dan pembuktian [S5]. Untuk media, Rev. 2 menyarankan satu narahubung dan minimal satu cadangan, yang dibriefing tentang hal sensitif sebelum berbicara [S5].

Di PT JAB, pembagian itu sudah tertulis di IR plan dan RACI (Day 02 bagian 2.1 dan 2.2):

- **Koordinasi:** IC, lewat kanal insiden atau OOB. Ritme update ke executive sponsor mengikuti severity.
- **Notifikasi ke regulator dan subjek data:** DPO sebagai R, Direktur Teknologi sebagai A, Legal dan IC sebagai C.
- **Komunikasi publik dan media:** Corporate Communication sebagai R, Direktur Teknologi sebagai A, Legal dan DPO sebagai C.
- **Berbagi informasi:** SOC, setelah Legal menyetujui apa yang boleh dibagi.

Prinsip yang mengikat semuanya adalah satu pintu per jenis. Teknisi tidak menjawab wartawan, CS tidak menjelaskan detail serangan, dan analyst tidak mengirim IOC ke grup komunitas tanpa persetujuan. Bukan karena informasinya rahasia semua, tetapi karena pesan yang berbeda dari dua orang akan dibaca sebagai ketidakjujuran.

### 1.2 Ritme dan isi update: fakta, yang belum diketahui, dan update berikutnya

Pertanyaan kedua Hendra menyangkut dua hal: frekuensi dan isi. Keduanya sudah ada aturannya sebelum hari itu.

PT JAB menetapkan ritme berdasarkan severity: SEV-1 setiap 1 jam, SEV-2 setiap 4 jam, SEV-3 harian (Day 01 bagian 1.7). Rev. 3 menyebut prosedur koordinasi harus memuat notifikasi awal dan update status berkala [S4]. Panduan komunikasi eksternal PagerDuty memberi pola yang berguna untuk isi: pesan awal yang sepenuhnya memakai template, pesan scoping yang menyebut dampak, lalu update berkala yang memuat perubahan dampak atau cakupan, apakah pemulihan sudah dimulai, dan kapan update berikutnya; PagerDuty juga memperingatkan bahwa update tanpa isi membuat penerima lelah dan berhenti membaca [S8].

Dari sumber itu, setiap update PT JAB punya lima bagian tetap:

1. Status dan severity, dengan waktu sejak kapan.
2. Fakta terverifikasi sejak update terakhir, dengan sumber.
3. Yang belum diketahui, ditulis terang.
4. Keputusan yang dibutuhkan dari penerima, bila ada.
5. Waktu update berikutnya.

Bagian 3 dan 5 yang paling sering hilang. Tanpa bagian 3, pimpinan menganggap tidak ada lagi yang belum diketahui. Tanpa bagian 5, setiap jeda dibaca sebagai masalah, dan pimpinan mulai menelepon analyst langsung, sehingga satu pintu runtuh.

Ritme ke pihak luar berbeda dengan ritme internal. Update ke direksi bisa tiap jam; pemberitahuan ke pelanggan dikirim saat ada sesuatu yang perlu mereka ketahui atau lakukan, dan pernyataan publik hanya bila diputuskan. Mengirim ke luar dengan ritme internal menghasilkan pesan tanpa isi yang justru memancing pertanyaan.

### 1.3 Kanal out-of-band: kapan dipakai, kapan boleh kembali

Pertanyaan ketiga Hendra ("kenapa kita masih di Signal?") punya jawaban yang bergantung pada satu pertanyaan: apakah penyerang mungkin bisa membaca kanal biasa.

Playbook CISA memasukkan kanal komunikasi dan metode koordinasi out-of-band ke tahap persiapan, dan untuk keamanan operasi menyarankan memberi tahu pengguna sistem yang terkompromi lewat telepon, bukan email [S6]. NCSC UK menyarankan mempertimbangkan komunikasi aman atau alternatif untuk insiden sensitif atau saat jaringan, email, atau telepon terganggu, menyiapkan minimal satu nomor conference yang selalu tersedia untuk panggilan darurat, dan mencatat minimal dua cara kontak serta dua orang untuk setiap kontak penting [S7]. Rev. 2 juga menyebut metode out-of-band seperti tatap muka dan kertas sebagai bagian dari pilihan metode komunikasi [S5].

PT JAB punya dua kanal OOB yang sudah disiapkan: grup Signal "JAB-CSIRT-OOB" dan conference bridge NOC (Day 02 bagian 2.1). Di `INC-2026-019`, Dimas memindahkan diskusi keputusan ke OOB sejak Selasa siang, karena tiga akun karyawan terkompromi, akun-akun itu tersinkron ke Microsoft 365, dan selama scoping belum bisa dipastikan apakah penyerang memegang sesi email atau chat. Rabu pagi, alasan itu sebagian sudah hilang: akun ditahan dan sesi dicabut sejak jam H, dan tidak ada tanda akses ke mailbox. Sebagian lain masih ada: laptop pengganti baru dibagikan siang itu, dan bahan yang sedang dibahas (data pelanggan dan rencana pelaporan) sensitif.

Kriteria kembali ke kanal biasa ditulis seperti kriteria lain:

- Akun dan perangkat yang terkompromi sudah ditahan, sesi dicabut, dan diverifikasi.
- Tidak ada tanda akses penyerang ke email, chat, atau penyimpanan dokumen.
- Bahan yang dibahas tidak memberi keuntungan bagi penyerang bila terbaca (rencana containment belum dijalankan termasuk yang tidak boleh).

Untuk `INC-2026-019`, Dimas menetapkan: koordinasi teknis kembali ke `#inc-2026-019` mulai Rabu 13:00 setelah laptop pengganti dibagikan, sedangkan rencana yang belum dijalankan dan bahan pelaporan tetap di OOB sampai containment dinyatakan berhasil.

Batas OOB juga perlu diingat: grup chat di ponsel pribadi tetap kanal yang bisa bocor (ponsel hilang, anggota grup yang sudah tidak relevan, tangkapan layar). Isi pesan OOB dibatasi pada keputusan dan koordinasi, tanpa data pribadi pelanggan, dan setiap keputusan yang dibuat di OOB disalin scribe ke tiket insiden.

### 1.4 UU PDP Pasal 46: apa yang wajib, ke siapa, dan kapan jam mulai berjalan

Pertanyaan keempat Hendra adalah pertanyaan yang paling sering dijawab dari ingatan, padahal jawabannya harus dibaca dari teks resmi.

**Isi pasal.** UU 27/2022 tentang Pelindungan Data Pribadi Pasal 46 mengatur tiga hal [S1]:

1. Ayat (1): bila terjadi kegagalan Pelindungan Data Pribadi, Pengendali Data Pribadi wajib menyampaikan pemberitahuan tertulis paling lambat 3 x 24 jam kepada Subjek Data Pribadi dan lembaga.
2. Ayat (2): pemberitahuan itu minimal memuat data pribadi yang terungkap, kapan dan bagaimana data itu terungkap, serta upaya penanganan dan pemulihan oleh pengendali.
3. Ayat (3): dalam hal tertentu, pengendali wajib memberitahukan kepada masyarakat.

**Penjelasan pasal.** Penjelasan resmi Pasal 46 mendefinisikan kegagalan Pelindungan Data Pribadi sebagai kegagalan melindungi data pribadi dalam hal kerahasiaan, integritas, dan ketersediaan, termasuk pelanggaran keamanan yang disengaja maupun tidak, yang mengarah pada perusakan, kehilangan, perubahan, pengungkapan, atau akses tidak sah terhadap data yang dikirim, disimpan, atau diproses [S1]. "Dalam hal tertentu" di ayat (3) dijelaskan antara lain bila kegagalan itu mengganggu pelayanan publik dan/atau berdampak serius terhadap kepentingan masyarakat [S1]. Ayat (2) dijelaskan "cukup jelas".

Dua hal penting dari definisi itu. Pertama, akses tidak sah sudah termasuk; pengendali tidak perlu menunggu data muncul di forum kebocoran. Kedua, kegagalan integritas dan ketersediaan juga termasuk, sehingga ransomware yang hanya mengenkripsi data pribadi tanpa menyalinnya pun bisa masuk definisi.

**Titik mulai 3 x 24 jam.** Teks Pasal 46 dan penjelasannya tidak menyebut kapan hitungan 3 x 24 jam dimulai: sejak kegagalan terjadi, sejak diketahui, atau sejak dipastikan [S1]. Peraturan pelaksana UU PDP, PP 33/2026, dilaporkan ditetapkan 16 Juli 2026 dan mulai berlaku 16 Januari 2027, dan sumber sekunder menyebut kewajiban pemberitahuan diatur di Pasal 114 dan pengumuman ke publik di Pasal 115 [S9][S13]. Satu analisis firma hukum menyebut PP itu menghitung tenggat sejak kegagalan diketahui [S12], tetapi naskah resmi PP 33/2026 belum diperiksa untuk catatan ini dan sumber lain tidak menyebut pemicunya [S13]. Karena itu, untuk insiden sebelum 16 Januari 2027, dasar yang pasti hanya Pasal 46 UU PDP, dan titik mulainya adalah tafsir yang diputuskan Legal dan DPO. Cek naskah resmi PP 33/2026 di JDIH sebelum memakai rumusan PP itu.

Dari ketidakpastian itu, PT JAB menulis aturan internal yang bisa dibela tanpa bergantung pada tafsir paling longgar:

- **Pakai titik paling awal yang masuk akal**, yaitu saat PT JAB punya dasar yang wajar bahwa akses tidak sah ke data pribadi terjadi, bukan saat kepastian forensik lengkap.
- **Tulis titik mulai, alasannya, dan tafsir alternatifnya** di catatan keputusan DPO, beserta tenggat untuk masing-masing.
- **Jangan menunggu laporan forensik lengkap** untuk mengirim pemberitahuan pertama; isi yang belum pasti ditulis sebagai belum pasti dan dilengkapi dengan pemberitahuan lanjutan.

**Kepada siapa.** Ayat (1) menyebut dua penerima: subjek data dan lembaga. Pasal 58 menyebut penyelenggaraan pelindungan data pribadi dilaksanakan oleh lembaga yang ditetapkan dan bertanggung jawab kepada Presiden, dengan ketentuan lebih lanjut diatur Peraturan Presiden [S1]. Per pertengahan September 2026, lembaga itu dilaporkan belum terbentuk sepenuhnya [S11], rancangan Peraturan Presidennya sudah diajukan ke Presiden, dan Komdigi menyatakan fungsi pelindungan data pribadi untuk sementara tetap dijalankan lewat Direktorat Jenderal Pengawasan Ruang Digital [S10]. Status ini bisa berubah kapan saja; cek status lembaga dan kanal pelaporannya setiap kali prosedur ini dipakai, dan biarkan Legal yang menetapkan alamat pemberitahuan.

**Ke masyarakat.** Untuk `INC-2026-019`, Legal menilai ayat (3) belum terpenuhi: layanan publik tidak terganggu (portal pembayaran hanya berhenti sembilan menit saat rotasi kredensial), dan data yang terdampak sekitar 5.000 dari 400 ribu pelanggan. Penilaian itu ditulis beserta alasannya, dan holding statement tetap disiapkan untuk berjaga-jaga (bagian 2.6).

### 1.5 Kewajiban lain: PP 71/2019, Peraturan BSSN 1/2024, sektor, dan kontrak

Pertanyaan kelima Hendra ("polisi, BSSN, Komdigi?") menunjukkan bahwa satu insiden bisa memicu beberapa kewajiban sekaligus, masing-masing dengan penerima dan batas waktu sendiri. Tabel di bagian 2.3 merangkumnya; di sini isi tiap aturan.

**PP 71/2019 tentang Penyelenggaraan Sistem dan Transaksi Elektronik.** Dua pasal relevan untuk penyelenggara sistem elektronik (PSE) [S2]:

- Pasal 14 ayat (5): bila terjadi kegagalan pelindungan data pribadi yang dikelolanya, PSE wajib memberitahukan secara tertulis kepada pemilik data pribadi tersebut.
- Pasal 24 ayat (3): bila terjadi kegagalan atau gangguan sistem yang berdampak serius akibat perbuatan pihak lain, PSE wajib mengamankan informasi dan dokumen elektronik dan segera melaporkan pada kesempatan pertama kepada aparat penegak hukum dan kementerian atau lembaga terkait.

Pasal 24 ayat (3) tidak memakai jam, tetapi "kesempatan pertama". Kewajiban mengamankan informasi juga sejalan dengan pengamanan bukti di Day 04.

**Peraturan BSSN 1/2024 tentang Pengelolaan Insiden Siber.** Peraturan ini membedakan Penyelenggara Infrastruktur Informasi Vital (IIV) dan PSE selain IIV [S3]:

- PSE selain IIV juga membentuk Tim Tanggap Insiden Siber (TTIS) organisasi (Pasal 8), dan TTIS organisasi wajib registrasi ke TTIS nasional (Pasal 9).
- Setiap insiden siber yang minimal berisiko tinggi wajib dilaporkan TTIS organisasi kepada TTIS sektoral dengan tembusan ke TTIS nasional; laporan paling sedikit memuat informasi kontak pelapor, deskripsi, kronologi, dan dampak serangan (Pasal 15 ayat (1) sampai (4)).
- Batas paling lambat 1 x 24 jam setelah insiden ditemukan ditulis untuk insiden pada IIV (Pasal 15 ayat (5)); bila TTIS sektoral belum terbentuk, laporan insiden IIV disampaikan ke kementerian atau lembaga sesuai sektornya dengan tembusan ke TTIS nasional (Pasal 15 ayat (6)).

Untuk PT JAB, dua hal harus sudah dijawab Legal sebelum insiden: apakah sistem PT JAB ditetapkan sebagai IIV (yang mengubah batas waktu menjadi 1 x 24 jam), dan ke mana laporan dikirim bila TTIS sektoral belum ada, karena ayat (6) hanya ditulis untuk IIV. Catatan Legal PT JAB per Oktober 2026: belum ada penetapan IIV untuk PT JAB, CSIRT virtual PT JAB sudah diregistrasi sebagai TTIS organisasi, dan laporan dikirim ke TTIS nasional sambil menanyakan TTIS sektoral yang berwenang. Itu keputusan fiktif untuk contoh; statusnya di organisasimu harus dicek.

**Sektor telekomunikasi dan kontrak.** Sebagai penyelenggara jasa telekomunikasi, PT JAB juga punya kewajiban ke Komdigi berdasarkan izin dan peraturan sektor, terutama untuk gangguan layanan. Kewajiban itu tidak dibahas di sini karena sumber resminya belum diperiksa untuk catatan ini; Legal yang memegang daftarnya. Kontrak pelanggan korporat dan perjanjian dengan pihak ketiga (misalnya penyedia payment gateway) bisa memuat kewajiban pemberitahuan dengan batas waktu sendiri, dan Rev. 3 menyebut notifikasi ke pihak ketiga sesuai kewajiban kontrak sebagai bagian dari RS.CO-02 [S4].

Pelajaran praktisnya: daftar kewajiban pelaporan disusun dan dicek sebelum insiden, berisi dasar aturan, pemicu, penerima, batas waktu, isi minimal, dan pemiliknya. Saat insiden, tim tidak membaca peraturan dari awal; tim mencocokkan fakta ke daftar.

### 1.6 Pesan ke subjek data, pelanggan, dan media

Pertanyaan keenam Hendra (yang dititipkan Maya) menyangkut pesan yang dibaca orang di luar tim, sehingga gaya dan isinya berbeda dengan update internal.

**Ke subjek data.** Isi minimal mengikuti Pasal 46 ayat (2): data apa yang terungkap, kapan dan bagaimana, dan apa yang sudah dan sedang dilakukan [S1]. Supaya pemberitahuan berguna bagi penerima, PT JAB menambahkan tiga hal: apa yang sebaiknya dilakukan penerima (misalnya waspada terhadap telepon atau pesan yang mengaku dari PT JAB dan meminta OTP atau pembayaran), kanal resmi untuk bertanya, dan bahwa PT JAB tidak akan meminta password atau OTP. Bahasa sederhana, tanpa istilah teknis, tanpa menyalahkan siapa pun, dan tanpa janji yang belum pasti seperti "data Anda aman".

**Ke pelanggan secara umum dan CS.** Pelanggan yang tidak terdampak juga akan bertanya begitu ada kabar. CS diberi FAQ yang disetujui, dengan jawaban untuk "apakah data saya termasuk?" yang mengarah ke kanal pemeriksaan, bukan tebakan.

**Ke media.** Rev. 2 menyarankan narahubung media yang ditunjuk, briefing sebelum berbicara, pernyataan status yang selalu diperbarui supaya jawaban konsisten, dan tidak membuka detail teknis yang bisa membantu penyerang lain [S5]. Rev. 2 juga memberi contoh pertanyaan wartawan yang perlu dilatih, termasuk siapa pelakunya, apakah ini terjadi karena praktik keamanan yang buruk, seberapa luas, dan apakah data pribadi terdampak [S5]. Holding statement disiapkan sebelum ditanya: singkat, faktual, menyebut langkah yang diambil, dan menunjuk kanal resmi. Spekulasi tentang pelaku tidak dimasukkan.

Konsistensi antar pesan lebih penting daripada kelengkapan. Angka, tanggal, dan jenis data di pemberitahuan ke subjek data, laporan ke lembaga, FAQ CS, dan holding statement harus sama. Karena itu keempatnya disusun dari satu lembar fakta yang disetujui IC dan DPO.

### 1.7 Mencatat dan berbagi: membuktikan kewajiban terpenuhi

Pertanyaan terakhir Hendra ("bagaimana membuktikan?") dijawab dengan catatan yang dibuat saat itu juga, bukan disusun ulang setelahnya.

NCSC UK menekankan pelacakan dan dokumentasi semua temuan, tugas, dan komunikasi, terutama untuk kasus yang nanti bisa ditinjau regulator atau pengadilan, termasuk keputusan yang diambil dan data yang dikumpulkan atau tidak tersedia [S7]. Rev. 2 meminta semua kontak dengan pihak luar didokumentasikan untuk keperluan tanggung jawab dan pembuktian [S5]. NCSC juga menyarankan formulir pelaporan regulator disiapkan sebelumnya [S7].

Log komunikasi PT JAB mencatat untuk setiap pesan keluar: waktu kirim, pengirim, penerima, kanal, versi isi (disimpan utuh), dasar keputusan, dan bukti terkirim. Catatan keputusan DPO tentang titik mulai dan tenggat (bagian 2.3) disimpan di tiket yang sama. Dengan itu, pertanyaan "kapan kalian memberi tahu, dan kenapa baru saat itu?" bisa dijawab dengan dokumen, bukan ingatan.

**Berbagi informasi** berbeda dengan notifikasi: sukarela dan bertujuan membantu organisasi lain. Rev. 3 menyebut berbagi TTP dengan komunitas sektoral sering saling menguntungkan dan meminta informasi dibagi secara aman sesuai rencana respons dan perjanjian berbagi informasi (RS.CO-03) [S4]. Di `INC-2026-019`, SOC membagikan IOC jaringan dan perilaku loader (tanpa data pelanggan dan tanpa nama PT JAB di indikator) setelah disetujui Legal, sesudah containment berhasil supaya tidak memberi tanda ke penyerang.

## 2. Contoh artefak dan langkah praktis di PT JAB

Semua isi bagian ini fiktif. Dokumen hukum di bawah adalah contoh latihan, bukan template yang sudah dinilai penasihat hukum; nama instansi, alamat pelaporan, dan kanal resmi ditetapkan Legal di organisasimu.

### 2.1 Peta stakeholder `INC-2026-019`

Peta ini menjawab pertanyaan pertama Hendra dan dipakai sebagai daftar periksa di rapat 11:00. Baca kolom "Pemilik" dan "Kanal": setiap baris punya satu pengirim dan satu jalur.

| Penerima | Jenis | Apa yang mereka butuhkan | Pemilik (R) | Persetujuan (A) | Kanal | Ritme atau waktu |
|---|---|---|---|---|---|---|
| Hendra Wijaya dan direksi | Koordinasi | Status, dampak, keputusan yang dibutuhkan | Dimas (IC) | - | Bridge NOC, Signal OOB, lalu `#inc-2026-019` | Tiap 1 jam (SEV-1), tiap 4 jam setelah turun SEV-2 |
| Tim teknis dan pemilik aplikasi | Koordinasi | Tugas, urutan, perubahan scope | Sari (TL) | Dimas | `#inc-2026-019`, bridge | Saat ada perubahan |
| Karyawan yang akunnya terdampak | Koordinasi | Apa yang terjadi pada akun dan laptop mereka, apa yang harus dilakukan | Atasan langsung bersama SOC | Dimas | Telepon dan tatap muka | Sekali, lalu saat laptop pengganti siap |
| 5.000 pelanggan terdampak | Notifikasi | Data apa, kapan, apa yang dilakukan, apa yang sebaiknya mereka lakukan | Agus (DPO) | Hendra | Email dan SMS dari kanal resmi, surat bila tidak ada email | Satu kali dalam tenggat, lanjutan bila ada fakta baru |
| Lembaga PDP (fungsi saat ini di Komdigi) | Notifikasi | Isi Pasal 46 ayat (2), kontak, langkah | Agus (DPO) | Hendra | Kanal yang ditetapkan Legal | Dalam tenggat |
| Aparat penegak hukum dan kementerian terkait | Notifikasi (PP 71/2019) | Laporan kejadian dan bukti awal | Ratna (Legal) | Hendra | Laporan resmi oleh Legal | Kesempatan pertama |
| TTIS nasional (dan sektoral bila ada) | Notifikasi (BSSN 1/2024) | Kontak, deskripsi, kronologi, dampak | Dimas | Hendra | Kanal pelaporan TTIS | Sesuai prosedur Legal |
| Penyedia payment gateway | Notifikasi kontrak | Kunci API dirotasi, waktu pemakaian kunci lama | Wahyu (Lead Aplikasi Billing) | Dimas | Kontak resmi di kontrak | Sebelum rotasi, sesuai kontrak |
| Pelanggan umum dan CS | Komunikasi publik | Jawaban konsisten bila bertanya | Maya (Corp Comm) | Hendra | FAQ internal CS | Siap sebelum pemberitahuan dikirim |
| Media | Komunikasi publik | Pernyataan resmi | Maya | Hendra | Satu narahubung | Hanya bila ditanya atau diputuskan |
| Komunitas keamanan | Berbagi informasi | IOC dan TTP tanpa data pelanggan | SOC | Ratna | Jalur berbagi yang disepakati | Setelah containment berhasil |

Cara membaca elemennya:

- **Kolom A selalu Hendra untuk pesan keluar**, sesuai RACI di Day 02 bagian 2.2: yang melapor dan berbicara adalah perusahaan, bukan individu.
- **Karyawan terdampak dihubungi lewat telepon atau tatap muka**, bukan email, mengikuti saran playbook CISA [S6].
- **CS disiapkan sebelum pemberitahuan dikirim**, karena begitu 5.000 email terkirim, telepon ke call center naik dalam hitungan menit.

**Kapan gagal:** peta dibuat saat insiden, dari nol. Baris yang paling sering terlupa adalah pihak ketiga dengan kewajiban kontrak dan karyawan yang akunnya dipakai penyerang.

### 2.2 Update internal SEV-1 pukul 11:00

Update ini menjawab pertanyaan kedua Hendra dengan contoh nyata. Perhatikan bagian "Belum diketahui" dan "Keputusan yang dibutuhkan".

```
INC-2026-019 | Update 11:00 | SEV-1 sejak Selasa 13:35 | kanal: bridge NOC + Signal OOB
Untuk: Hendra Wijaya, direksi | Dari: Dimas Prasetyo (IC)

FAKTA BARU SEJAK 10:00
- Retainer: 5.000 baris data pelanggan (nama, NIK, alamat, telepon) kemungkinan besar
  diambil Selasa 03:06-03:12. Keyakinan sedang-tinggi (perintah terlihat di memori,
  isi trafik keluar terenkripsi).
- Tidak ada bukti kompromi akun domain berhak tinggi. Keyakinan sedang.
- Containment: belum ada tanda baru sejak 17:20 kemarin; kriteria 24 jam terpenuhi 17:20 hari ini.

BELUM DIKETAHUI
- Daftar pasti 5.000 pelanggan (sedang direkonstruksi Tim Aplikasi Billing, target 15:00).
- Apakah data sudah dipublikasikan atau dijual (pemantauan sumber terbuka oleh retainer).

KEPUTUSAN YANG DIBUTUHKAN (rapat 11:00)
1. Titik mulai hitungan UU PDP Pasal 46 dan tenggat (usulan DPO dan Legal).
2. Persetujuan draf pemberitahuan ke pelanggan dan lembaga (target draf 16:00).
3. Persetujuan laporan ke aparat dan TTIS nasional oleh Legal hari ini.

UPDATE BERIKUTNYA: 12:00
```

Cara membaca elemennya:

- **Keyakinan ditulis per fakta**, mengikuti pola scope statement di Day 03, karena DPO memutuskan berdasarkan keyakinan itu.
- **Keputusan ditulis bernomor**, sehingga rapat selesai dengan jawaban untuk setiap nomor, bukan diskusi umum.
- **Kanal ditulis di kepala update**, supaya penerima tahu ini bukan email biasa yang bisa diteruskan.

**Kapan gagal:** update hanya menyalin log teknis. Direksi tidak bisa membedakan yang penting dari yang rinci, dan bagian "keputusan yang dibutuhkan" tenggelam.

### 2.3 Pohon keputusan pelaporan dan catatan keputusan titik mulai

Pohon ini menjawab pertanyaan keempat dan kelima Hendra. Isinya ringkasan bagian 1.4 dan 1.5 dalam bentuk yang bisa dijalankan saat rapat. Setiap cabang "ya" membuka satu kewajiban dengan pemilik sendiri; cabang-cabang itu berjalan paralel, bukan berurutan.

```
Apakah ada akses tidak sah, pengungkapan, perubahan, kehilangan, atau
gangguan ketersediaan terhadap data pribadi? (Penjelasan Pasal 46 ayat (1))
  |
  +-- ya --> UU PDP Pasal 46: tertulis ke subjek data + lembaga, maks 3 x 24 jam
  |            titik mulai: tafsir Legal/DPO, tulis di catatan keputusan
  |            mengganggu layanan publik / dampak serius ke masyarakat?
  |              +-- ya --> juga ke masyarakat (ayat (3))
  |          PP 71/2019 Pasal 14 ayat (5): tertulis ke pemilik data
  |
Apakah ada kegagalan/gangguan sistem berdampak serius akibat perbuatan pihak lain?
  +-- ya --> PP 71/2019 Pasal 24 ayat (3): amankan + lapor kesempatan pertama
  |            ke aparat penegak hukum dan kementerian/lembaga terkait
  |
Apakah insiden siber minimal berisiko tinggi?
  +-- ya --> Peraturan BSSN 1/2024 Pasal 15: TTIS organisasi lapor ke TTIS sektoral,
  |            tembusan TTIS nasional; IIV: maks 1 x 24 jam
  |
Ada kewajiban sektor telekomunikasi (gangguan layanan) atau kontrak pihak ketiga?
  +-- ya --> daftar kewajiban Legal; batas waktu sesuai izin/kontrak
```

Catatan keputusan DPO berikut disimpan di tiket insiden. Perhatikan bahwa tafsir alternatif dan tenggatnya tetap ditulis.

```
INC-2026-019 | Catatan keputusan pemberitahuan data pribadi | Rabu 2026-10-14 11:40 WIB
Disusun: Agus Setiawan (DPO), Ratna Sari (Legal) | Disetujui: Hendra Wijaya

FAKTA
- Selasa 13:15 proses penyerang terlihat memegang koneksi ke database pelanggan;
  13:35 SEV-1 karena akses ke data pelanggan tidak bisa disingkirkan.
- Rabu 10:00 retainer: 5.000 baris (nama, NIK, alamat, telepon) kemungkinan besar diambil.

PENILAIAN
- Termasuk kegagalan Pelindungan Data Pribadi menurut Penjelasan Pasal 46 ayat (1)
  (akses tidak sah dan kemungkinan pengungkapan).
- Pasal 46 dan penjelasannya tidak menyebut titik mulai 3 x 24 jam.
  Tafsir yang dipakai: titik paling awal yang wajar, Selasa 13:35.
  Tenggat: Jumat 2026-10-16 13:35.
  Tafsir alternatif: sejak kesimpulan retainer Rabu 10:00, tenggat Sabtu 10:00. Tidak dipakai.
- Ayat (3) ke masyarakat: tidak terpenuhi saat ini (layanan publik tidak terganggu,
  sekitar 5.000 dari 400 ribu pelanggan). Dinilai ulang bila data muncul di publik.
- PP 71/2019 Pasal 24 ayat (3): terpenuhi (gangguan berdampak serius akibat pihak lain).
- Peraturan BSSN 1/2024 Pasal 15: insiden berisiko tinggi; PT JAB bukan IIV menurut
  catatan Legal; laporan ke TTIS nasional.

RENCANA
- Laporan aparat penegak hukum dan kementerian terkait: Legal, Rabu sebelum 17:00.
- Laporan TTIS nasional: Dimas, Rabu sebelum 17:00.
- Pemberitahuan ke lembaga: Kamis 14:00. Ke 5.000 pelanggan: Kamis 16:00 (CS siap 15:30).
- Daftar pelanggan: query penyerang tanpa ORDER BY, sehingga baris yang terambil tidak
  bisa dipastikan dari ulangan query. Rekonstruksi dari salinan database Selasa dini
  hari; batas ini ditulis di pemberitahuan ke lembaga.
```

Cara membaca elemennya:

- **Tafsir alternatif ditulis bersama tenggatnya.** Bila nanti ada yang berpendapat titik mulainya lain, catatan ini menunjukkan bahwa pilihan PT JAB adalah yang lebih ketat, dan pemberitahuan dikirim sebelum kedua tenggat.
- **Daftar pelanggan punya batas yang ditulis.** Dokumentasi PostgreSQL menyebut `LIMIT` tanpa `ORDER BY` menghasilkan subset baris yang tidak bisa diprediksi [S14], sehingga menjalankan ulang query yang sama tidak menjamin hasil yang sama. Keterbatasan seperti ini lebih baik ditulis daripada disembunyikan.
- **Kewajiban berjalan paralel.** Laporan ke aparat dan TTIS tidak menunggu pemberitahuan ke pelanggan, dan sebaliknya.

**Kapan gagal:** titik mulai baru dibahas di hari ketiga, atau tidak ditulis sama sekali. Saat ditanya, tim hanya bisa menjawab dari ingatan, dan setiap jawaban yang berbeda melemahkan posisi perusahaan.

### 2.4 Pemberitahuan tertulis ke subjek data

Pemberitahuan ini menjawab bagian pertama pertanyaan keenam. Isinya mengikuti tiga isi minimal Pasal 46 ayat (2) [S1], ditambah apa yang sebaiknya dilakukan pelanggan.

```
Subjek: Pemberitahuan insiden keamanan yang melibatkan data Anda

Yth. [Nama Pelanggan], nomor pelanggan [xxxx]

Kami memberi tahu Anda tentang insiden keamanan di sistem tagihan PT Jaringan Anak Bangsa.

Data yang terdampak: nama, NIK, alamat, dan nomor telepon Anda. Data rekening bank,
kartu pembayaran, dan password akun tidak termasuk.

Kapan dan bagaimana: pada Selasa, 13 Oktober 2026 dini hari, pihak yang tidak berwenang
masuk ke sistem tagihan kami memakai kredensial yang dicuri, dan kemungkinan besar
menyalin data di atas. Kami mendeteksi kejadian ini pada hari yang sama.

Yang sudah kami lakukan: memutus akses pihak tersebut, mengganti seluruh kredensial
terkait, melaporkan kejadian ini kepada instansi berwenang, dan memperketat pemantauan.
Server yang terdampak sedang dibangun ulang dari sumber yang bersih.

Yang sebaiknya Anda lakukan: waspadai telepon, SMS, atau pesan yang mengaku dari PT JAB
dan meminta kode OTP, password, atau pembayaran ke rekening yang tidak biasa. PT JAB
tidak pernah meminta OTP atau password.

Pertanyaan: hubungi [nomor layanan khusus] atau [alamat email resmi], atau kunjungi
[halaman resmi]. Pejabat pelindungan data pribadi PT JAB: [kontak].

PT Jaringan Anak Bangsa
```

Cara membaca elemennya:

- **Tiga isi minimal ayat (2) muncul sebagai judul paragraf** (data, kapan dan bagaimana, upaya penanganan), sehingga mudah dicek Legal.
- **Data yang tidak terdampak juga disebut**, karena itu pertanyaan pertama pelanggan.
- **Tidak ada tautan untuk "cek data Anda" di email**, karena penipu akan meniru email ini; pelanggan diarahkan ke kanal resmi yang sudah mereka kenal.

**Kapan gagal:** email dikirim dari domain atau alamat yang tidak biasa dipakai PT JAB, sehingga pelanggan mengira itu phishing, atau sebaliknya penipu dengan mudah menirunya. Kanal pengiriman disepakati dengan tim email dan diumumkan di halaman resmi.

### 2.5 Pemberitahuan ke lembaga dan laporan insiden siber

Dokumen ini menjawab bagian kedua pertanyaan kelima. Dua laporan punya isi yang sebagian sama, tetapi dasar aturan, penerima, dan isi minimalnya berbeda, sehingga disusun dari lembar fakta yang sama dan dikirim terpisah.

| Bagian | Ke lembaga PDP (Pasal 46) | Ke TTIS (Peraturan BSSN 1/2024 Pasal 15) |
|---|---|---|
| Identitas pelapor | PT JAB sebagai Pengendali Data Pribadi; kontak DPO | TTIS organisasi PT JAB; kontak IC |
| Isi wajib | Data pribadi yang terungkap; kapan dan bagaimana; upaya penanganan dan pemulihan [S1] | Kontak pelapor; deskripsi; kronologi; dampak serangan [S3] |
| Fokus | Data dan subjek data: jenis data, perkiraan jumlah, langkah untuk subjek data | Serangan: vektor, sistem terdampak, IOC, dampak layanan |
| Isi tambahan PT JAB | Titik mulai yang dipakai dan alasannya; batas rekonstruksi daftar pelanggan; rencana pemberitahuan ke subjek data | Status containment dan eradication; IOC yang boleh dibagikan |
| Pengirim | DPO, atas persetujuan Hendra | IC, atas persetujuan Hendra |

Cara membaca elemennya:

- **Satu lembar fakta, dua laporan.** Angka dan waktu harus sama; perbedaannya hanya pada fokus.
- **Batas pengetahuan ditulis di laporan ke lembaga**, termasuk rekonstruksi daftar pelanggan, sehingga pemberitahuan lanjutan tidak terlihat seperti koreksi atas laporan yang keliru.

**Kapan gagal:** laporan ke TTIS menyebut "data pelanggan tidak terdampak" karena disusun dari scope statement lama, sementara laporan ke lembaga menyebut 5.000 baris. Dua instansi kemudian membandingkan dan PT JAB harus menjelaskan.

### 2.6 Holding statement dan FAQ layanan pelanggan

Dokumen ini menjawab pertanyaan Maya: apa yang dikatakan bila wartawan atau pelanggan menelepon sebelum dan sesudah pemberitahuan dikirim.

```
HOLDING STATEMENT (disetujui Hendra 14:30, berlaku sampai diganti)
"PT Jaringan Anak Bangsa mendeteksi insiden keamanan pada sistem tagihan pada 13 Oktober
2026 dan segera menanganinya bersama pihak forensik independen. Akses pihak tidak berwenang
sudah diputus dan sistem sudah diamankan. Kami sedang memberi tahu pelanggan yang datanya
terdampak secara langsung, dan sudah melaporkan kejadian ini kepada instansi berwenang.
Layanan internet dan pembayaran berjalan normal. Pelanggan dapat menghubungi [kanal resmi]."

FAQ CS (ringkas)
T: Apakah data saya termasuk?
J: Pelanggan yang terdampak menerima pemberitahuan langsung dari kami lewat email/SMS
   resmi. Bila ragu, kami bisa memeriksanya setelah verifikasi identitas lewat kanal resmi.
T: Data apa saja?
J: Nama, NIK, alamat, dan nomor telepon. Bukan data rekening, kartu, atau password.
T: Siapa pelakunya?
J: Masih diinvestigasi dan sudah dilaporkan ke instansi berwenang. Kami tidak bisa
   berspekulasi.
T: Apa yang harus saya lakukan?
J: Waspadai pihak yang mengaku dari PT JAB dan meminta OTP, password, atau pembayaran.
   Kami tidak pernah memintanya.
ESKALASI: wartawan diarahkan ke Corporate Communication (Maya Lestari). Pertanyaan hukum
ke Legal. Jangan menjawab detail teknis.
```

Cara membaca elemennya:

- **Holding statement tidak menyebut jumlah pelanggan** sampai daftar selesai direkonstruksi; angka yang kemudian berubah lebih merusak daripada angka yang belum disebut.
- **Tidak ada spekulasi pelaku**, sesuai saran Rev. 2 agar narahubung media dibriefing tentang hal sensitif [S5].
- **FAQ dan holding statement memakai fakta yang sama** dengan pemberitahuan ke pelanggan (bagian 2.4).

**Kapan gagal:** CS menjawab dari pengetahuan sendiri sebelum FAQ dibagikan, atau teknisi menjawab pertanyaan wartawan di media sosial. Satu pintu harus diumumkan ke internal, bukan hanya ditulis di plan.

### 2.7 Kartu kanal out-of-band

Kartu ini menjawab pertanyaan ketiga Hendra dalam bentuk yang bisa dibawa: dicetak dan disimpan anggota CSIRT, dan diuji bersama uji kontak mingguan (Day 02 bagian 2.4).

```
JAB-CSIRT KANAL OOB (versi Oktober 2026, rahasia internal)
PAKAI OOB BILA: akun karyawan/admin terkompromi dan sesi belum dipastikan dicabut;
                email/chat korporat diduga dibaca penyerang; jaringan kantor terganggu.
KANAL 1: grup Signal "JAB-CSIRT-OOB" (anggota ditinjau tiap bulan; admin: SOC lead)
KANAL 2: conference bridge NOC [nomor], PIN di kartu fisik; cadangan: telepon langsung
KONTAK: minimal 2 cara per orang, 2 orang per peran (IC, TL, DPO, Legal, Comm, NOC)
ATURAN ISI: keputusan dan koordinasi saja; tanpa data pelanggan, password, atau IOC lengkap
            yang belum dibagi; scribe menyalin keputusan ke tiket insiden
KEMBALI KE KANAL BIASA BILA: akun/perangkat terkompromi ditahan dan diverifikasi,
            tidak ada tanda akses ke email/chat, dan IC menyatakannya di OOB
```

Cara membaca elemennya:

- **Dua cara kontak dan dua orang per peran** mengikuti saran NCSC UK [S7].
- **Aturan isi** membatasi apa yang boleh ditulis di ponsel pribadi, karena kanal OOB sendiri bisa bocor.
- **Pernyataan kembali ke kanal biasa** dibuat eksplisit oleh IC, sehingga tidak ada anggota yang masih memakai OOB atau sudah kembali ke email sendiri-sendiri.

## 3. Lab praktik

Lab ini berupa latihan dokumen untuk organisasi fiktif atau lab-mu sendiri, tanpa menjalankan alat apa pun. Jangan memakai data, nama, atau kejadian dari pekerjaan nyata, dan jangan menganggap hasil latihan sebagai pendapat hukum.

1. **Daftar kewajiban.** Buat tabel kewajiban pelaporan untuk organisasimu dengan kolom dasar aturan, pemicu, penerima, batas waktu, isi minimal, dan pemilik. Isi minimal baris UU PDP Pasal 46, PP 71/2019 Pasal 14 ayat (5) dan Pasal 24 ayat (3), dan Peraturan BSSN 1/2024 Pasal 15, dari teks resmi. Tandai baris yang masih harus dicek bersama Legal (status IIV, regulator sektor, kontrak).
2. **Status hari ini.** Cari status terbaru lembaga pelindungan data pribadi dan PP 33/2026 dari sumber resmi. Catat tanggal pengecekan dan apa yang berubah dibanding catatan ini.
3. **Peta stakeholder.** Buat peta dengan format bagian 2.1 untuk skenario `INC-2026-025` (data tiket 38.400 pelanggan berisi nomor pelanggan, nama, telepon, dan alamat pemasangan, tanpa NIK, terunduh dari penyimpanan cloud). Bandingkan barisnya dengan `INC-2026-019`.
4. **Catatan keputusan titik mulai.** Untuk skenario yang sama, tulis catatan keputusan dengan format bagian 2.3: fakta dengan waktu, titik mulai yang dipilih, tafsir alternatif dan tenggatnya, dan penilaian ayat (3).
5. **Tiga pesan dari satu lembar fakta.** Tulis lembar fakta satu halaman, lalu dari situ susun pemberitahuan ke subjek data, holding statement, dan FAQ CS. Minta orang lain mencari angka atau istilah yang tidak konsisten di antara ketiganya.
6. **Uji kanal OOB.** Tanpa memberi tahu sebelumnya, minta tiga anggota tim bergabung ke kanal OOB dalam 10 menit. Catat siapa yang tidak bisa dan kenapa (nomor berubah, aplikasi belum terpasang, PIN bridge hilang).

**Hasil yang sebaiknya tersimpan:**

- `latihan/day18-kewajiban.md` berisi tabel kewajiban dan status pengecekan dengan tanggal.
- `latihan/day18-inc025.md` berisi peta stakeholder dan catatan keputusan titik mulai.
- Lembar fakta dan tiga pesan turunannya, dengan daftar inkonsistensi yang ditemukan.
- Hasil uji kanal OOB beserta perbaikannya.

**Variasi tantangan:** ubah skenario langkah 3 menjadi BEC seperti `INC-2026-021`, di mana salinan KTP PIC pelanggan korporat terbaca dan pelanggan sudah mentransfer dana ke rekening penipu. Kewajiban mana yang bertambah, dan siapa saja yang harus dihubungi dalam satu jam pertama?

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul dalam komunikasi dan pelaporan insiden. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Pimpinan menelepon analyst langsung | Update tidak teratur atau tidak menyebut update berikutnya | Ritme tetap per severity dan bagian "update berikutnya" di setiap pesan |
| Dua pesan keluar berisi angka berbeda | Tiap pesan disusun dari sumber berbeda | Satu lembar fakta yang disetujui IC dan DPO untuk semua pesan |
| Tidak ada yang tahu kapan tenggat pelaporan | Titik mulai tidak diputuskan dan tidak ditulis | Catatan keputusan titik mulai di hari pertama, dengan tafsir alternatif [S1] |
| Rencana containment bocor ke penyerang | Dibahas di email atau chat yang dipantau | Kanal OOB yang sudah diuji [S6][S7] |
| Anggota tim tidak bisa masuk kanal OOB | Kanal tidak pernah diuji | Uji bersama uji kontak mingguan; dua cara kontak per orang [S7] |
| Pelanggan mengira pemberitahuan resmi adalah phishing | Pengirim atau format tidak biasa, ada tautan | Kirim dari kanal resmi, tanpa tautan login, umumkan di halaman resmi |
| Laporan ke instansi berbeda isinya | Disusun dari scope statement versi berbeda | Tandai versi lembar fakta di setiap laporan |
| Tidak jelas laporan dikirim ke instansi mana | Lembaga belum terbentuk atau TTIS sektoral belum ada | Legal menetapkan kanal sebelum insiden dan mengecek ulang statusnya berkala [S3][S10] |

## 5. Kesalahan umum dan jebakan

- Menunggu laporan forensik lengkap sebelum memulai proses pemberitahuan. Tenggat bisa lewat sebelum kepastian datang.
- Menghitung 3 x 24 jam dari titik yang paling menguntungkan tanpa menulis alasannya. Teks Pasal 46 tidak menyebut titik mulai, sehingga pilihan itu harus bisa dipertanggungjawabkan [S1].
- Menganggap kewajiban hanya muncul bila data terbukti dijual atau dipublikasikan. Penjelasan Pasal 46 sudah memasukkan akses tidak sah [S1].
- Menganggap pemulihan dari backup menghapus kewajiban. Kegagalan kerahasiaan tetap terjadi walaupun ketersediaan pulih.
- Menyebut hanya satu kewajiban (UU PDP) dan melupakan PP 71/2019, Peraturan BSSN 1/2024, sektor, dan kontrak [S2][S3].
- Membiarkan banyak orang berbicara ke luar. Media dan pelanggan menerima versi berbeda.
- Mengirim update tanpa isi hanya untuk memenuhi ritme, atau tidak mengirim update karena belum ada kemajuan [S8].
- Menulis "data pelanggan aman" di pernyataan awal sebelum scope selesai.
- Membahas data pelanggan di kanal OOB di ponsel pribadi.
- Menyusun ulang kronologi komunikasi setelah insiden dari ingatan, bukan dari log yang dibuat saat itu [S5][S7].

## 6. Catatan terkini

Bagian ini menampung status regulasi dan sumber yang bisa berubah. Cek ulang setiap kali prosedur pelaporan dipakai, karena status kelembagaan di bawah sedang bergerak.

- **UU 27/2022** diundangkan 17 Oktober 2022. Pasal 74 memberi pengendali dan prosesor waktu paling lama dua tahun sejak diundangkan untuk menyesuaikan pemrosesan data pribadi [S1]. Halaman BPK mencatat Putusan MK Nomor 151/PUU-XXII/2024 yang menyangkut Pasal 53, bukan Pasal 46.
- **PP 33/2026** sebagai peraturan pelaksana UU PDP dilaporkan ditetapkan dan diundangkan 16 Juli 2026 dan berlaku 16 Januari 2027; pada akhir Agustus 2026 Kompas melaporkan salinannya beredar sebelum disebarluaskan resmi [S9][S13]. Naskah resminya belum diperiksa untuk catatan ini, termasuk rumusan titik mulai tenggat pemberitahuan [S12].
- **Lembaga pelindungan data pribadi**: pada 27 Juli 2026 Komdigi menyatakan rancangan Peraturan Presiden pembentukannya sudah diajukan ke Presiden, UU PDP tidak menetapkan batas waktu pembentukannya, dan fungsinya untuk sementara dijalankan Ditjen Pengawasan Ruang Digital [S10]. Per 16 September 2026 lembaga itu dilaporkan belum terbentuk sepenuhnya [S11].
- **Peraturan BSSN 1/2024** ditetapkan 10 Januari 2024 [S3].
- **NIST SP 800-61 Rev. 3** (April 2025) memindahkan pembahasan komunikasi ke kategori RS.CO di profil CSF 2.0; Rev. 2 (Agustus 2012) masih berguna untuk rincian komunikasi dengan media dan pihak luar [S4][S5].

## 7. Cheat sheet

```
EMPAT JENIS (NIST r3 RS.CO): koordinasi | notifikasi | komunikasi publik | berbagi informasi
  satu pintu per jenis; A pesan keluar = executive sponsor; R: IC / DPO / Corp Comm / SOC

UPDATE: status+sejak | fakta baru (sumber) | BELUM DIKETAHUI | keputusan dibutuhkan | UPDATE BERIKUTNYA
  PT JAB: SEV-1 1 jam | SEV-2 4 jam | SEV-3 harian | ke luar: hanya saat ada yang perlu diketahui

OOB: akun/perangkat terkompromi, email/chat mungkin dibaca -> Signal JAB-CSIRT-OOB + bridge NOC
  2 cara kontak, 2 orang per peran | isi: keputusan saja | kembali ke kanal biasa: dinyatakan IC

UU PDP Ps 46: tertulis maks 3x24 jam ke subjek data + lembaga
  isi: data terungkap | kapan & bagaimana | penanganan & pemulihan
  ke masyarakat "dalam hal tertentu" = ganggu layanan publik / dampak serius ke masyarakat
  kegagalan = kerahasiaan/integritas/ketersediaan, TERMASUK akses tidak sah
  titik mulai: TIDAK disebut UU -> Legal/DPO putuskan, tulis + tafsir alternatif
  PP 33/2026 berlaku 16 Jan 2027 (cek naskah resmi) | lembaga: cek status, saat ini via Komdigi

PP 71/2019: Ps 14(5) tertulis ke pemilik data | Ps 24(3) amankan + lapor kesempatan pertama
  ke aparat penegak hukum + kementerian/lembaga terkait
BSSN 1/2024: TTIS organisasi (juga non-IIV) | Ps 15: insiden >= risiko tinggi ke TTIS sektoral,
  tembusan nasional | isi: kontak, deskripsi, kronologi, dampak | IIV: 1x24 jam
+ sektor telekomunikasi (Legal) + kontrak pihak ketiga

BUKTI: log komunikasi (waktu, pengirim, penerima, kanal, isi utuh, dasar, bukti kirim)
  catatan keputusan titik mulai | satu lembar fakta untuk semua pesan
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Datanya belum muncul di forum kebocoran mana pun, jadi menurut UU PDP belum ada kegagalan pelindungan data pribadi dan belum ada yang perlu diberitahukan." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Penjelasan Pasal 46 ayat (1) mendefinisikan kegagalan Pelindungan Data Pribadi termasuk pelanggaran keamanan yang mengarah pada pengungkapan atau akses tidak sah terhadap data pribadi. Akses tidak sah ke database pelanggan sudah cukup; munculnya data di forum bukan syarat. Lihat bagian 1.4.

</details>

**2. Skenario keputusan.** Rabu 11:40, Legal dan DPO harus menetapkan titik mulai hitungan 3 x 24 jam untuk `INC-2026-019`. Pilihan mana yang paling tepat?

- A. Sejak kesimpulan retainer Rabu 10:00, karena baru saat itu ada keyakinan sedang-tinggi, tanpa perlu menulis alternatif.
- B. Sejak titik paling awal yang wajar (Selasa 13:35), dengan alasan dan tafsir alternatif beserta tenggatnya ditulis di catatan keputusan, dan pemberitahuan dikirim sebelum kedua tenggat.
- C. Sejak laporan lengkap retainer Jumat, karena pemberitahuan harus berisi fakta yang pasti.

<details><summary>Jawaban</summary>

B. Teks Pasal 46 dan penjelasannya tidak menyebut titik mulai, sehingga yang bisa dibela adalah pilihan yang ketat dan terdokumentasi, dengan pemberitahuan yang memenuhi tafsir mana pun. A bukan pilihan yang salah dengan sendirinya, tetapi tidak menulis alternatif membuat keputusan sulit dipertanggungjawabkan bila dipersoalkan. C keliru karena menunggu kepastian forensik bisa melewati tenggat, dan hal yang belum pasti bisa ditulis sebagai belum pasti lalu dilengkapi pemberitahuan lanjutan. Lihat bagian 1.4 dan 2.3.

</details>

**3. Pertanyaan jebakan.** "Kalau UU PDP sudah dipenuhi dengan memberi tahu pelanggan dan lembaga, tidak ada kewajiban pelaporan lain untuk `INC-2026-019`." Benarkah?

<details><summary>Jawaban</summary>

Tidak. PP 71/2019 Pasal 24 ayat (3) mewajibkan PSE mengamankan informasi dan segera melapor pada kesempatan pertama kepada aparat penegak hukum dan kementerian atau lembaga terkait bila ada gangguan berdampak serius akibat perbuatan pihak lain. Peraturan BSSN 1/2024 Pasal 15 mewajibkan insiden siber minimal berisiko tinggi dilaporkan TTIS organisasi ke TTIS sektoral dengan tembusan ke TTIS nasional. Kewajiban sektor telekomunikasi dan kontrak pihak ketiga juga dicek Legal. Lihat bagian 1.5 dan 2.3.

</details>

**4. Skenario keputusan.** Rabu pagi, Yoga mengusulkan memindahkan semua diskusi kembali ke `#inc-2026-019` karena "Signal ribet". Respons mana yang tepat?

- A. Setuju sepenuhnya, karena akun yang terkompromi sudah ditahan sejak kemarin.
- B. Kembalikan koordinasi teknis setelah kriteria terpenuhi dan dinyatakan IC, tetapi rencana yang belum dijalankan dan bahan pelaporan tetap di OOB sampai containment dinyatakan berhasil.
- C. Tetap di Signal untuk semua hal sampai insiden ditutup, termasuk membagikan daftar pelanggan terdampak di sana.

<details><summary>Jawaban</summary>

B. Kembali ke kanal biasa adalah keputusan dengan kriteria (akun dan perangkat ditahan dan diverifikasi, tidak ada tanda akses ke email atau chat, bahan tidak menguntungkan penyerang), dan bisa bertahap. A mengabaikan bahwa laptop pengganti belum dibagikan dan bahan pelaporan masih sensitif. C keliru karena OOB di ponsel pribadi juga bisa bocor; data pelanggan tidak boleh ada di sana. Lihat bagian 1.3 dan 2.7.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Maya Lestari (Corporate Communication), dalam tiga kalimat, kenapa holding statement belum menyebut jumlah pelanggan terdampak.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Angka 5.000 itu perkiraan dari cara penyerang mengambil data, dan daftar persis pelanggannya masih direkonstruksi tim aplikasi, jadi angkanya bisa berubah. Kalau kita sudah menyebut angka ke publik lalu harus mengoreksinya, kesannya kita tidak jujur atau tidak menguasai masalah, dan itu lebih merusak daripada belum menyebut angka. Begitu daftar final dan pelanggan yang terdampak sudah kita beri tahu langsung, angka itu bisa masuk pernyataan berikutnya dengan versi yang sama di semua pesan."

Kesalahan yang sering muncul:
- Memakai istilah teknis seperti "LIMIT tanpa ORDER BY" yang tidak dibutuhkan tim komunikasi.
- Terdengar seperti menyembunyikan informasi, tanpa menjelaskan kapan angka akan disampaikan.
- Tidak menyebut bahwa semua pesan harus memakai angka yang sama.

</details>

**6. Pertanyaan jebakan.** "Kegagalan Pelindungan Data Pribadi hanya soal kebocoran. Ransomware yang mengenkripsi share berisi data pelanggan tanpa menyalinnya tidak termasuk." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Penjelasan Pasal 46 ayat (1) mencakup kegagalan kerahasiaan, integritas, dan ketersediaan, termasuk yang mengarah pada perusakan atau kehilangan data pribadi. Enkripsi oleh ransomware bisa masuk definisi itu walaupun data tidak disalin keluar; penilaiannya tetap oleh DPO dan Legal. Lihat bagian 1.4.

</details>

**7. Interview question (English).** "During a breach involving customer personal data, how do you manage communications and regulatory reporting?"

<details><summary>Sample answer</summary>

"I separate four streams, because they have different owners and rules: internal coordination run by the incident commander, formal notifications owned by the DPO and legal with executive approval, public communication through a single spokesperson, and voluntary threat-intel sharing after legal sign-off. Internally I keep a fixed cadence by severity, and every update says what's confirmed, what's still unknown, what decisions we need, and when the next update is. If accounts or devices are compromised, we move sensitive coordination to a pre-tested out-of-band channel. For reporting, I work from a pre-built obligations register: in Indonesia that means the PDP Law's three-times-24-hour written notice to data subjects and the authority, the electronic systems regulation's duty to report serious disruptions to law enforcement and the relevant ministry, BSSN's incident reporting rules, plus sector and contract obligations. Where the law doesn't define when the clock starts, legal and the DPO pick the earliest defensible point, write down the reasoning and the alternative, and we notify before either deadline. All external messages come from one approved fact sheet, and every message is logged with time, recipient, content and basis, so we can prove compliance later."

What makes this answer strong: it shows structure (four streams with owners), discipline in updates, awareness of compromised channels, specific local obligations without overstating them, a defensible approach to legal ambiguity, and evidence through logging.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | BPK JDIH: UU Nomor 27 Tahun 2022 tentang Pelindungan Data Pribadi (halaman dan salinan PDF) | https://peraturan.bpk.go.id/Details/229798/uu-no-27-tahun-2022 | primer | diundangkan 17 Oktober 2022; diakses 2026-10-15 | Tinggi. Pasal 46 dan Penjelasan Pasal 46, Pasal 58, Pasal 74; status berlaku |
| S2 | JDIH Kemenkeu: PP Nomor 71 Tahun 2019 tentang Penyelenggaraan Sistem dan Transaksi Elektronik (PDF) | https://jdih.kemenkeu.go.id/FullText/2019/71TAHUN2019PP.pdf | primer | 2019; diakses 2026-10-15 | Tinggi. Pasal 14 ayat (5) dan Pasal 24 ayat (3) |
| S3 | Peraturan.go.id: Peraturan BSSN Nomor 1 Tahun 2024 tentang Pengelolaan Insiden Siber (PDF) | https://www.peraturan.go.id/files/peraturan-bssn-no-1-tahun-2024.pdf | primer | ditetapkan 10 Januari 2024; diakses 2026-10-15 | Tinggi. Definisi Penyelenggara IIV dan PSE, Pasal 8, 9, 15 |
| S4 | NIST SP 800-61 Rev. 3 (PDF) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf | primer | April 2025; diakses 2026-10-15 | Tinggi. Kategori RS.CO, RS.CO-02, RS.CO-03 |
| S5 | NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide (PDF) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf | primer | Agustus 2012 (lebih dari 3 tahun, digantikan Rev. 3); diakses 2026-10-15 | Tinggi untuk bagian 2.3.4 (pihak luar, media, dokumentasi kontak) dan 3.2.7 (pihak yang diberi tahu, metode out-of-band) |
| S6 | CISA: Cybersecurity Incident and Vulnerability Response Playbooks (PDF) | https://www.cisa.gov/sites/default/files/publications/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf | primer | November 2021; diakses 2026-10-15 | Tinggi. Kanal dan koordinasi out-of-band, memberi tahu pengguna lewat telepon |
| S7 | NCSC UK: Incident management collection, halaman Processes for Cyber Incident Response | https://www.ncsc.gov.uk/collection/incident-management/cyber-incident-response-processes | primer | review 19 September 2019; diakses 2026-10-15 | Tinggi. Komunikasi alternatif, nomor conference, dua cara kontak, dokumentasi untuk regulator, formulir pelaporan |
| S8 | PagerDuty Incident Response Documentation: External Communication Guidelines | https://response.pagerduty.com/during/external_communication_guidelines/ | sekunder (vendor) | diakses 2026-10-15 | Sedang sampai tinggi. Pesan awal, scoping, update, template; konteks layanan SaaS |
| S9 | Kompas.id: Peraturan pelaksana UU PDP akhirnya terbit, lembaga pengawas masih dinanti | https://www.kompas.id/artikel/peraturan-pelaksana-uu-pdp-akhirnya-terbit-lembaga-pengawas-masih-dinanti | sekunder (media) | 29 Agustus 2026; diakses 2026-10-15 | Sedang. PP 33/2026 ditetapkan dan diundangkan 16 Juli 2026 menurut sumber yang tidak disebut namanya; lembaga belum dibentuk |
| S10 | Kompas.com: Komdigi ungkap Perpres pembentukan Badan Perlindungan Data Pribadi sedang disusun | https://nasional.kompas.com/read/2026/07/27/15423511/komdigi-ungkap-perpres-pembentukan-badan-perlindungan-data-pribadi-sedang | sekunder (media) | 27 Juli 2026; diakses 2026-10-15 | Sedang. Pernyataan Komdigi di sidang MK: rancangan Perpres diajukan, tanpa batas waktu di UU, fungsi sementara di Ditjen Pengawasan Ruang Digital |
| S11 | CNBC Indonesia: Lembaga perlindungan data belum ada, begini nasib data warga RI | https://www.cnbcindonesia.com/tech/20260916120242-37-768329/lembaga-perlindungan-data-belum-ada-begini-nasib-data-warga-ri | sekunder (media) | 16 September 2026; diakses 2026-10-15 | Sedang. Lembaga belum terbentuk sepenuhnya |
| S12 | DDS Law: PP 33 Tahun 2026 tentang Pelindungan Data Pribadi dan kewajiban penting perusahaan | https://ddslaw.id/pp-33-tahun-2026-pelindungan-data-pribadi/ | komunitas (analisis firma hukum) | 2026; diakses 2026-10-15 | Rendah sampai sedang. Menyebut tenggat dihitung sejak kegagalan diketahui; belum dicocokkan dengan naskah resmi |
| S13 | KRES.ID: Hitung mundur 16 Januari 2027, PP 33/2026 terbit | https://www.kres.id/pp-33-2026-aturan-pelaksana-uu-pdp | sekunder (analisis konsultan) | 2026; diakses 2026-10-15 | Sedang. Pasal 114 (pemberitahuan 3 x 24 jam), Pasal 115 (pengumuman publik), berlaku enam bulan sejak diundangkan; tidak menyebut titik mulai |
| S14 | PostgreSQL 18 Documentation: LIMIT and OFFSET | https://www.postgresql.org/docs/current/queries-limit.html | primer (dokumentasi vendor) | versi 18; diakses 2026-10-15 | Tinggi. `LIMIT` tanpa `ORDER BY` menghasilkan subset baris yang tidak bisa diprediksi |

**Catatan sumber:** teks Pasal 46 dan Penjelasannya, PP 71/2019, dan Peraturan BSSN 1/2024 dibaca dari salinan resmi [S1][S2][S3]. Semua keterangan tentang PP 33/2026 (tanggal, nomor pasal, dan rumusan titik mulai) berasal dari media dan analisis konsultan, bukan dari naskah resmi, dan rumusan titik mulainya hanya dari satu analisis firma hukum [S12], sehingga diperlakukan sebagai belum terkonfirmasi. Status lembaga pelindungan data pribadi berasal dari pemberitaan Juli sampai September 2026 [S10][S11] dan bisa sudah berubah. Kewajiban sektor telekomunikasi ke Komdigi tidak diuraikan karena sumber resminya belum diperiksa. Empat jenis komunikasi diambil dari Rev. 3 [S4]; lima bagian tetap update, aturan titik mulai paling awal yang wajar, kartu OOB, dan pemisahan dua laporan di bagian 2.5 adalah susunan catatan ini, bukan aturan resmi. Semua isi PT JAB, termasuk catatan Legal tentang status IIV, tenggat, isi pemberitahuan, dan holding statement, adalah contoh fiktif dan bukan pendapat hukum.
