---
day: 10
title: 'Kontrol insiden dan pelaporan event: 5.24-5.28, 6.8, seri ISO/IEC 27035, dan pemetaan ke playbook IR'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 27001:2022 + Amd 1:2024; ISO/IEC 27035-1:2023 (edisi 2), 27035-2:2023, 27035-3:2020, 27035-4:2024 (edisi 1, Des 2024); ISO/IEC 27037:2012; NIST SP 800-61 Rev. 3 (Apr 2025); UU No. 27 Tahun 2022 (PDP)'
---

# Day 10: Kontrol insiden, pelaporan event, dan seri ISO/IEC 27035

> Catatan pribadi, bukan materi resmi ISO, dan bukan nasihat hukum atau audit. Regulasi disebut secara umum; cek teks resmi sebelum dipakai untuk keputusan nyata.

Cakupan: kontrol Annex A 5.24-5.28 dan 6.8 (serta 5.5, 5.6, 5.29 yang terkait), seri ISO/IEC 27035, ISO/IEC 27037 untuk bukti digital, perbandingan dengan NIST SP 800-61 Rev. 3, kewajiban pemberitahuan di UU PDP, dan pemetaan ke playbook IR serta laporan forensik.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- membedakan event, insiden, dan kelemahan, lalu menjelaskan kenapa keputusan klasifikasi (5.25) harus terdokumentasi.
- memetakan lima fase 27035-1 ke kontrol 5.24-5.28 dan 6.8, serta ke fungsi CSF 2.0 di NIST SP 800-61 Rev. 3.
- menyebut keempat bagian seri 27035 beserta fungsinya.
- menjelaskan prinsip penanganan bukti digital menurut ISO/IEC 27037 dan menyusun formulir chain of custody.
- menghitung tenggat pemberitahuan kegagalan pelindungan data pribadi dan memasukkannya ke playbook.

## 2. Konteks singkat

Saat audit, proses insiden adalah area yang paling mudah diuji lewat sampling. Auditor meminta daftar insiden, memilih beberapa tiket, lalu mencocokkannya dengan prosedur. Ia memeriksa apakah klasifikasi sesuai kriteria, apakah eskalasi tepat waktu, apakah ada pelajaran yang ditindaklanjuti, dan apakah bukti dikumpulkan dengan benar.

Bagi analyst SOC dan DFIR, Day ini adalah titik temu bahasa teknis dan bahasa ISMS. Playbook yang sudah kamu tulis bisa langsung menjadi bukti 5.26. Laporan forensik bisa menjadi bukti 5.28. Post-incident review bisa menjadi bukti 5.27 sekaligus input 10.2 dan 8.2.

Kapan dipakai: menulis atau meninjau rencana IR, persiapan audit, latihan tabletop, dan setelah insiden besar.
Kapan tidak cukup: kontrol Annex A dan 27035 tidak memberi detail teknis forensik seperti cara mengakuisisi image disk atau menganalisis artefak. Yang diatur adalah prosesnya: siapa, kapan, dengan prosedur apa, dan rekaman apa yang tersisa.

## 3. Konsep inti

### 3.1 Event, insiden, dan kelemahan

Ketiga istilah ini perlu dibedakan dengan jelas (dengan kata sendiri):

- **Event keamanan informasi:** kejadian yang menunjukkan kemungkinan pelanggaran keamanan atau kegagalan kontrol. Contohnya satu alert login gagal beruntun.
- **Insiden keamanan informasi:** satu atau beberapa event yang kemungkinan besar merusak operasi bisnis atau mengancam keamanan informasi. Contohnya login berhasil dari IP mencurigakan setelah brute force.
- **Kelemahan (weakness):** kondisi yang bisa dimanfaatkan, tetapi belum terjadi apa-apa. Contohnya akun default yang masih aktif.

Sebagian besar event bukan insiden. Itu sebabnya kontrol 5.25 (assessment and decision) penting: organisasi harus punya kriteria untuk memutuskan event mana yang naik menjadi insiden, dan keputusan itu harus tercatat. Bagi SOC, triage alert adalah pelaksanaan 5.25.

### 3.2 Seri ISO/IEC 27035

| Bagian | Judul singkat | Edisi | Fungsi |
|---|---|---|---|
| 27035-1 | Principles and process | Edisi 2, 13 Feb 2023 [S1] | Konsep, prinsip, dan proses inti |
| 27035-2 | Guidelines to plan and prepare for incident response | 2023 [S6] | Kebijakan, rencana, tim, pelatihan, pengujian |
| 27035-3 | Guidelines for ICT incident response operations | 2020 [S6] | Operasi respons insiden TIK |
| 27035-4 | Coordination | Edisi 1, 2 Des 2024 [S2] | Koordinasi lintas organisasi |

27035-1 mencakup persiapan, deteksi, pelaporan, penilaian, respons, dan penerapan pelajaran. Panduan ini berlaku untuk organisasi yang menangani insidennya sendiri maupun penyedia layanan manajemen insiden eksternal [S1]. Seri ini umumnya diringkas menjadi lima fase [S5][S6]:

1. **Plan and prepare:** kebijakan, rencana, tim, alat, pelatihan;
2. **Detect and report:** mendeteksi event dan melaporkannya;
3. **Assess and decide:** menilai apakah event adalah insiden dan menentukan prioritas;
4. **Respond:** containment, investigasi, eradikasi, pemulihan;
5. **Learn lessons:** memperbaiki proses dan kontrol berdasarkan temuan, termasuk dari near miss.

27035-4 relevan untuk penyedia layanan dan organisasi dalam rantai pasok. Bagian ini membahas bagaimana beberapa organisasi menangani insiden bersama, dan bagaimana kerja sama eksternal memengaruhi proses internal masing-masing [S2]. Contohnya, PT AN sebagai penyedia hosting harus berkoordinasi dengan klien saat VM klien diserang.

### 3.3 Kontrol Annex A dan fase 27035

| Fase 27035 | Kontrol Annex A | Bukti yang biasa diminta |
|---|---|---|
| Plan and prepare | 5.24 Incident management planning and preparation; 5.5 Contact with authorities; 5.6 Contact with special interest groups | Rencana IR, peran, daftar kontak, catatan latihan |
| Detect and report | 6.8 Information security event reporting; 8.15, 8.16 | Kanal lapor karyawan, rule deteksi, tiket dari laporan |
| Assess and decide | 5.25 Assessment and decision on information security events | Kriteria klasifikasi, tiket dengan alasan keputusan |
| Respond | 5.26 Response to information security incidents; 5.28 Collection of evidence; 5.29 Information security during disruption | Timeline, tindakan containment, formulir bukti |
| Learn lessons | 5.27 Learning from information security incidents | Post-incident review, tindakan perbaikan yang selesai |

Dua catatan untuk kontrol ini:

- **6.8 ada di tema People** karena kewajibannya ada pada orang: setiap karyawan harus tahu cara dan ke mana melaporkan event. Bukti yang kuat adalah tiket yang benar-benar berasal dari laporan karyawan, bukan hanya poster kampanye.
- **5.28 Collection of evidence** meminta prosedur untuk identifikasi, pengumpulan, akuisisi, dan preservasi bukti, supaya bukti tetap utuh dan bisa dipakai bila ada tindakan disipliner atau hukum. Cakupannya log sistem, tangkapan jaringan, image disk, dump memori, dan rekaman email [S8].

### 3.4 NIST SP 800-61 Rev. 3

NIST menerbitkan SP 800-61 Rev. 3 pada April 2025 dengan judul yang menekankan manajemen risiko keamanan siber dan bentuk "CSF 2.0 Community Profile". Dokumen ini menggantikan Rev. 2 (Agustus 2012) [S3]. Perubahan besarnya, respons insiden tidak lagi dipandang sebagai kegiatan tim terpisah. Rekomendasinya disusun mengikuti fungsi CSF 2.0 [S3].

| 27035-1 | NIST 800-61 Rev. 2 (siklus lama) | NIST 800-61 Rev. 3 (fungsi CSF 2.0) |
|---|---|---|
| Plan and prepare | Preparation | Govern, Identify, Protect |
| Detect and report | Detection and analysis | Detect |
| Assess and decide | Detection and analysis | Detect |
| Respond | Containment, eradication, recovery | Respond, Recover |
| Learn lessons | Post-incident activity | Perbaikan di seluruh fungsi (Identify, improvement) |

Rev. 3 sendiri menggambarkan pergeseran ini: persiapan tersebar ke Govern, Identify, dan Protect; deteksi dan respons ke Detect, Respond, dan Recover; sedangkan pelajaran dari insiden masuk ke kategori Improvement di Identify dan berlaku untuk semua fungsi. Kolom 27035 di tabel adalah penyejajaran yang dibuat catatan ini, bukan pemetaan resmi dari ISO atau NIST. Yang perlu diingat: ISO 27035 dan NIST 800-61 tidak saling bertentangan. Organisasi yang memakai ISO 27001 boleh menulis playbook dengan struktur NIST, asalkan kontrol 5.24-5.28 terpenuhi dan bisa dibuktikan.

### 3.5 Bukti digital dan ISO/IEC 27037

ISO/IEC 27037:2012 membahas tahap awal penanganan bukti digital: identifikasi, pengumpulan, akuisisi, dan preservasi, dengan menjaga integritas dan chain of custody [S4]. Standar ini membedakan dua peran:

- **Digital Evidence First Responder (DEFR):** orang pertama yang menangani bukti;
- **Digital Evidence Specialist (DES):** spesialis yang memproses bukti lebih lanjut.

Standar terkait [S4]:

- 27041 untuk jaminan metode investigasi;
- 27042 untuk analisis dan interpretasi;
- 27043 untuk prinsip dan proses investigasi;
- seri 27050 untuk electronic discovery.

Status: edisi 2012 masih berlaku. ISO27k mencatat edisi itu dikonfirmasi tanpa perubahan pada 2018 [S4]. Satu sumber lain menyebut proyek revisi dibuka 2024 tetapi belum terbit. Cek status revisi 27037 di katalog ISO.

Untuk analyst SOC, arti praktisnya: bila sebuah insiden mungkin berujung pada tindakan disipliner, klaim asuransi, atau proses hukum, bukti harus dikumpulkan dengan cara yang bisa dipertanggungjawabkan. Caranya: catat siapa, kapan, apa, dan bagaimana; hitung hash; simpan salinan kerja terpisah dari salinan asli; dan batasi akses. Prinsip dasarnya: kumpulkan dari yang paling mudah hilang lebih dulu (memori dan koneksi aktif sebelum disk), jangan menganalisis bukti asli, dan catat setiap alat beserta versinya. Penanganan bukti di catatan ini berlaku untuk konteks organisasi swasta dan bukan nasihat hukum.

### 3.6 Kewajiban pemberitahuan: UU PDP

UU No. 27 Tahun 2022 tentang Pelindungan Data Pribadi, Pasal 46, mewajibkan pengendali data pribadi memberi pemberitahuan tertulis paling lambat 3 x 24 jam bila terjadi kegagalan pelindungan data pribadi. Pemberitahuan ditujukan kepada subjek data dan lembaga, dan minimal memuat data yang terungkap, kapan dan bagaimana data terungkap, serta upaya penanganan dan pemulihan. Dalam hal tertentu, masyarakat juga harus diberi tahu [S7].

Konsekuensi untuk ISMS dan SOC:

- persyaratan ini masuk register pihak berkepentingan (4.2) dan kontrol 5.31 serta 5.34;
- playbook insiden yang menyangkut data pribadi harus punya langkah "nilai apakah ini kegagalan pelindungan data pribadi" dan jam mulai tenggat;
- tim SOC perlu tahu kapan harus melibatkan DPO dan Legal.

Cek tiga hal di teks resmi UU dan aturan turunannya (JDIH): titik mulai perhitungan 3 x 24 jam (saat kejadian atau saat diketahui), status lembaga pengawas PDP, dan kewajiban sektor lain yang mungkin lebih ketat.

### 3.7 Apa yang dicari auditor di proses insiden

Daftar periksa yang bisa kamu pakai sebelum audit:

- rencana IR punya tanggal tinjau dan pernah diuji (tabletop atau simulasi) dalam 12 bulan terakhir;
- kriteria klasifikasi tertulis dan dipakai secara konsisten di tiket;
- sampel tiket menunjukkan timeline, keputusan, dan penanggung jawab;
- insiden besar punya post-incident review, dan tindakannya selesai atau terlacak;
- formulir chain of custody terisi untuk insiden yang butuh bukti;
- kontak otoritas dan kelompok khusus (5.5, 5.6) mutakhir.

## 4. Contoh dokumen / artefak (organisasi fiktif)

Organisasi fiktif: PT Awan Nusantara (PT AN). Semua isi adalah ilustrasi.

### 4.1 Kriteria klasifikasi event (5.25)

| Prioritas | Kriteria (salah satu terpenuhi) | Waktu respons awal | Eskalasi |
|---|---|---|---|
| P1 Kritis | Data pribadi pelanggan terindikasi terungkap; ransomware aktif; layanan banyak pelanggan terganggu | 15 menit | Incident manager, Direktur Ops, DPO |
| P2 Tinggi | Akses tidak sah terkonfirmasi pada satu sistem; malware aktif tanpa penyebaran | 30 menit | Incident manager, Lead SOC |
| P3 Sedang | Aktivitas mencurigakan belum terkonfirmasi; percobaan eksploitasi gagal pada aset penting | 4 jam | Lead SOC |
| P4 Rendah | Event yang tidak memengaruhi CIA; false positive yang perlu tuning | 1 hari kerja | Tidak ada |

Kriteria P1 sengaja menyebut "data pribadi pelanggan terindikasi terungkap". Kategori ini memicu langkah penilaian UU PDP dan pelibatan DPO sejak awal, bukan di akhir investigasi.

### 4.2 Kerangka playbook ransomware VM pelanggan

| Langkah | Kegiatan | Fase 27035 | Kontrol | Rekaman |
|---|---|---|---|---|
| 1 | Alert enkripsi massal diterima, tiket P1 dibuka | Detect and report | 8.16, 6.8 | Tiket, waktu alert |
| 2 | Konfirmasi dan klasifikasi; nilai keterlibatan data pribadi | Assess and decide | 5.25 | Alasan klasifikasi di tiket |
| 3 | Isolasi VM dan segmen jaringan; hentikan akun yang disalahgunakan | Respond | 5.26 | Timeline tindakan |
| 4 | Ambil snapshot VM dan memori, hitung hash, isi formulir chain of custody | Respond | 5.28 | Formulir bukti, hash |
| 5 | Notifikasi klien sesuai kontrak; bila ada kegagalan pelindungan data pribadi, siapkan pemberitahuan 3 x 24 jam | Respond | 5.24, 5.5, 5.31 | Salinan pemberitahuan, waktu kirim |
| 6 | Eradikasi dan pemulihan dari backup yang bersih | Respond | 5.26, 8.13, 5.29 | Catatan pemulihan |
| 7 | Post-incident review dalam 10 hari kerja | Learn lessons | 5.27 | Laporan PIR |
| 8 | Tindakan perbaikan masuk register NC/CA dan risk register | Learn lessons | 10.2, 8.2 | ID CA dan ID risiko |

Langkah 4 sengaja diletakkan sebelum eradikasi. Bila VM dibersihkan dulu, bukti hilang.

### 4.3 Formulir chain of custody (kolom minimum)

```
ID bukti        : EV-2026-031-02
Insiden         : INC-2026-031
Deskripsi       : Snapshot disk VM cust-vm-118 (format qcow2), 40 GB
Sumber          : Hypervisor hv-jkt1-07, diambil oleh hypervisor admin atas permintaan IR
Waktu akuisisi  : 2026-09-01 15:42 WIB
Diakuisisi oleh : Analyst L2 (DEFR), disaksikan Lead SOC
Hash (SHA-256)  : <dicatat saat akuisisi>
Lokasi simpan   : Evidence store terenkripsi, folder INC-2026-031, akses: tim IR saja
Riwayat serah terima:
  2026-09-01 16:10  Analyst L2 -> Evidence store      tujuan: penyimpanan
  2026-09-02 09:00  Evidence store -> DFIR specialist tujuan: analisis salinan kerja
```

Kolom hash dibiarkan sebagai tempat isi, karena nilai hash hanya bermakna bila dihitung dari bukti nyata. Panah di blok ini hanya notasi arah serah terima.

### 4.4 Menghitung tenggat pemberitahuan

Skenario fiktif: analisis pada 2026-09-02 10:00 WIB menyimpulkan data pribadi 1.200 pelanggan terungkap. Kegagalan itu sendiri terjadi pada 2026-09-01 sekitar 14:30 WIB.

- Bila tenggat dihitung dari saat kejadian: 2026-09-01 14:30 + 72 jam = 2026-09-04 14:30 WIB.
- Bila tenggat dihitung dari saat diketahui: 2026-09-02 10:00 + 72 jam = 2026-09-05 10:00 WIB.

Selisihnya hampir satu hari. Selama titik mulainya belum dipastikan dari teks resmi, playbook PT AN memakai perhitungan yang lebih ketat (dari saat kejadian sejauh bisa diperkirakan) dan mencatat dasar keputusannya di tiket. Cek titik mulai di teks UU dan aturan turunannya.

## 5. Lab praktik (di VM lab terisolasi)

Latihan dokumen untuk organisasi fiktifmu, ditambah satu simulasi kecil di lab. Simpan di `ISO27001-note/latihan/day10-<nama-org-fiktif>.md`.

1. Tulis kriteria klasifikasi 4 tingkat seperti bagian 4.1. Minimal satu kriteria memicu penilaian UU PDP.
2. Tulis playbook untuk satu skenario (ransomware, akun cloud dibobol, atau kebocoran data lewat email). Setiap langkah dipetakan ke fase 27035, kontrol Annex A, dan rekaman yang dihasilkan.
3. Buat formulir chain of custody dengan kolom minimum seperti bagian 4.3.
4. Tulis template post-incident review: ringkasan, timeline, akar masalah, apa yang berjalan baik, apa yang perlu diperbaiki, tindakan beserta pemilik dan tenggat, serta tautan ke register NC dan risiko.
5. Tulis skenario tabletop 60 menit dengan 4 "inject" (misalnya: alert awal, bukti data pribadi terlibat, klien menelepon, wartawan bertanya). Untuk setiap inject tulis keputusan yang diharapkan dan kontrol yang diuji.
6. Simulasi kecil di lab terisolasi: picu event jinak yang sudah kamu kenal di Splunk atau Wazuh lab, misalnya beberapa login SSH gagal ke VM lab sendiri. Jalankan playbook-mu sampai langkah klasifikasi dan pencatatan bukti: catat waktu alert, waktu triage, keputusan klasifikasi, dan hash file ekspor alert. Semua dilakukan di VM lab dengan snapshot, bukan di sistem kerja.
7. Hitung dua versi tenggat pemberitahuan untuk skenario fiktifmu seperti bagian 4.4.

**Hasil yang seharusnya teramati:** kriteria, playbook, formulir, dan template PIR yang saling merujuk, serta satu catatan simulasi dengan waktu nyata dari lab-mu.

**Hasil yang sebaiknya tersimpan:**
- Setiap langkah playbook punya kontrol dan rekaman.
- Pengumpulan bukti terjadi sebelum eradikasi.
- Formulir chain of custody mencatat siapa, kapan, apa, di mana, dan riwayat serah terima.
- Template PIR menautkan tindakan ke register NC/CA dan risk register.
- Tabletop menguji minimal 5.24, 5.25, 5.26, dan komunikasi (7.4).
- Hitungan tenggat dicek ulang.

**Variasi tantangan:** PT AN memakai MSSP untuk monitoring malam. Tulis bagian playbook yang mengatur serah terima dari MSSP ke tim internal, dengan memakai gagasan koordinasi 27035-4: siapa memutuskan klasifikasi, siapa memegang bukti, dan siapa berbicara ke klien.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Klasifikasi tiket tidak konsisten antar shift | Kriteria tidak tertulis atau terlalu umum | Tulis kriteria dengan contoh; audit sampel tiket per bulan |
| Bukti hilang karena VM sudah dipulihkan | Urutan playbook salah | Pindahkan pengumpulan bukti sebelum eradikasi; buat pengecualian tertulis bila bisnis harus pulih lebih dulu |
| PIR ditulis tetapi tindakannya tidak pernah selesai | Tidak ada tautan ke register CA | Wajibkan ID tindakan dan pemilik di setiap PIR |
| Karyawan tidak tahu ke mana melaporkan | 6.8 hanya berupa kebijakan | Satu kanal sederhana; uji dengan simulasi phishing yang menghitung laporan |
| Tim ragu kapan memberi tahu regulator | Kewajiban hukum tidak masuk playbook | Tambahkan langkah penilaian PDP dan kontak DPO/Legal di P1 |

## 7. Kesalahan umum dan jebakan

- Menyamakan setiap alert dengan insiden. Ini membuat metrik dan pelaporan kacau; 5.25 justru meminta keputusan.
- Rencana IR yang tidak pernah diuji. Bukti latihan sama pentingnya dengan dokumennya.
- Melewatkan near miss di post-incident review. 27035 menekankan pembelajaran dari insiden kecil dan nyaris terjadi [S5].
- Menganggap NIST 800-61 dan ISO 27035 harus dipilih salah satu. Keduanya bisa dipakai bersama.
- Mengumpulkan bukti tanpa catatan siapa dan kapan. Bukti yang tidak bisa dipertanggungjawabkan kehilangan nilainya.
- Menghitung tenggat pemberitahuan dari akhir investigasi. Tenggat UU PDP pendek, jadi penilaian harus dimulai sejak awal.

## 8. Catatan terkini

- ISO/IEC 27035-4:2024 (Coordination) terbit 2 Desember 2024 [S2].
- NIST SP 800-61 Rev. 3 (April 2025) menggantikan Rev. 2 dan menyusun respons insiden sebagai profil komunitas CSF 2.0 [S3].
- ISO/IEC 27037:2012 masih edisi berlaku. Informasi tentang proyek revisi berbeda antar sumber [S4]; cek statusnya di katalog ISO.
- UU PDP diundangkan 17 Oktober 2022 dengan masa penyesuaian dua tahun, sehingga berlaku penuh sejak Oktober 2024. Pembentukan lembaga pengawas PDP dan aturan pelaksananya perlu dicek di sumber resmi per tanggal kamu membaca catatan ini.

## 9. Cheat sheet

```
Event (mungkin masalah) -> Insiden (kemungkinan besar merusak) ; Kelemahan (belum terjadi)
27035-1:2023 prinsip & proses | -2:2023 rencana & persiapan | -3:2020 operasi IR TIK | -4:2024 koordinasi
Fase: plan & prepare | detect & report | assess & decide | respond | learn lessons
Kontrol: 5.24 rencana | 6.8 lapor event (People) | 5.25 nilai & putuskan | 5.26 respons
         5.27 belajar | 5.28 bukti | 5.5 otoritas | 5.6 kelompok khusus | 5.29 saat gangguan
NIST 800-61r3 (Apr 2025) = profil CSF 2.0, ganti r2 (2012)
27037:2012 = identifikasi, pengumpulan, akuisisi, preservasi | DEFR & DES | 27041/27042/27043 | 27050 e-discovery
Bukti: siapa, kapan, apa, bagaimana, hash, salinan kerja, akses terbatas, riwayat serah terima
UU PDP Ps. 46: tertulis maks 3x24 jam ke subjek data + lembaga; isi: data apa, kapan/bagaimana, upaya penanganan
Auditor: rencana diuji, kriteria dipakai, timeline tiket, PIR + tindakan, formulir bukti, kontak mutakhir
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | ISO committee: ISO/IEC 27035-1:2023 | https://committee.iso.org/standard/78973.html | primer (katalog ISO) | 2023-02-13; diakses 2026-10-08 | Tinggi untuk judul, edisi, tanggal, abstrak |
| S2 | ISO committee: ISO/IEC 27035-4:2024 | https://committee.iso.org/standard/80973.html | primer (katalog ISO) | 2024-12-02; diakses 2026-10-08 | Tinggi |
| S3 | NIST CSRC: SP 800-61 Rev. 3 | https://csrc.nist.gov/pubs/sp/800/61/r3/final | primer (NIST) | April 2025; diakses 2026-10-08 | Tinggi untuk judul, status, dan dokumen yang digantikan. Penyejajaran fase lama ke fungsi CSF di bagian 3.4 perlu dicocokkan dengan gambar di dokumen r3 |
| S4 | ISO27k: ISO/IEC 27037 | https://www.iso27001security.com/html/27037 | sekunder (komentar praktisi) | diperbarui 2026-08-19; diakses 2026-10-08 | Sedang. Ruang lingkup, peran DEFR/DES, standar terkait |
| S5 | ISO27k: ISO/IEC 27035 | https://www.iso27001security.com/html/27035 | sekunder (komentar praktisi) | diperbarui 2026-08-19; diakses 2026-10-08 | Sedang. Lima tahap dan penekanan pada near miss |
| S6 | ANSI Blog: ISO/IEC 27035-1:2023 information security incident management | https://blog.ansi.org/ansi/iso-iec-27035-1-2023-information-security-management/ | sekunder (lembaga standar nasional) | diakses 2026-10-08 | Sedang. Nama lima fase dan edisi 27035-2/-3 |
| S7 | pasal.id: UU No. 27 Tahun 2022 Pasal 46 | https://pasal.id/peraturan/uu/uu-no-27-tahun-2022/pasal-46 | sekunder (agregator peraturan) | diakses 2026-10-08 | Sedang. Isi konsisten dengan ringkasan hukum lain; cocokkan dengan teks resmi di JDIH |
| S8 | UpGuard: ISO 27001 control 5.28 collection of evidence | https://www.upguard.com/compliance/iso-27001/5-28/ | sekunder (vendor) | diakses 2026-10-08 | Sedang. Cakupan jenis bukti |

**Catatan sumber:** isi 27035, 27037, dan kontrol 5.24-5.28 disusun dari halaman katalog dan ringkasan sekunder, bukan dari teks standar. Teks UU PDP Pasal 46 berasal dari agregator peraturan; cocokkan dengan salinan resmi di JDIH, terutama titik mulai hitungan 3 x 24 jam. Penyejajaran fase 27035 dengan siklus NIST lama dan fungsi CSF 2.0 adalah interpretasi yang perlu dicocokkan dengan dokumen SP 800-61r3.
