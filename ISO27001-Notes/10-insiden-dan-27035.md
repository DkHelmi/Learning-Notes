---
day: 10
title: 'Kontrol insiden dan pelaporan event: 5.24-5.28, 6.8, seri ISO/IEC 27035, dan pemetaan ke playbook IR'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 27001:2022 + Amd 1:2024; ISO/IEC 27035-1:2023 (edisi 2), 27035-2:2023 (edisi 2), 27035-3:2020 (edisi 1, tinjauan sistematis 2025), 27035-4:2024 (edisi 1); ISO/IEC 27037:2012 (dikonfirmasi 2018); NIST SP 800-61 Rev. 3 (3 April 2025); UU No. 27 Tahun 2022 (PDP); PP No. 33 Tahun 2026 menurut ringkasan firma profesional (berlaku 16 Januari 2027; teks resmi belum ditemukan di peraturan.bpk.go.id per 2026-10-10)'
---

# Day 10: Kontrol insiden, pelaporan event, dan seri ISO/IEC 27035

Cakupan: kontrol Annex A 5.24-5.28 dan 6.8 beserta kontrol terkait, seri ISO/IEC 27035, ISO/IEC 27037 untuk bukti digital, perbandingan dengan NIST SP 800-61 Rev. 3, kewajiban pemberitahuan di UU PDP, dan pemetaannya ke playbook IR serta laporan forensik.

> Catatan pribadi, bukan materi resmi ISO, dan bukan nasihat hukum atau audit. Regulasi disebut secara umum; cek teks resmi sebelum dipakai untuk keputusan nyata.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- membedakan event, insiden, dan kelemahan, lalu menjelaskan kenapa keputusan klasifikasi (5.25) harus terdokumentasi.
- memetakan lima fase 27035-1 ke kontrol 5.24-5.28 dan 6.8, serta ke fungsi CSF 2.0 di NIST SP 800-61 Rev. 3.
- menyebut keempat bagian seri 27035 beserta edisi dan fungsinya.
- menjelaskan prinsip penanganan bukti digital menurut ISO/IEC 27037 dan menyusun formulir chain of custody.
- menghitung tenggat pemberitahuan kegagalan pelindungan data pribadi dan memasukkannya ke playbook.

## 2. Konteks singkat

Saat audit, proses insiden paling mudah diuji lewat sampling. Auditor memilih beberapa tiket lalu mencocokkannya dengan prosedur: klasifikasi sesuai kriteria, eskalasi tepat waktu, post-incident review dengan tindakan yang terlacak, formulir bukti terisi, rencana IR pernah diuji dalam 12 bulan, dan kontak otoritas (5.5, 5.6) mutakhir.

Bagi SOC dan DFIR, playbook menjadi bukti 5.26, laporan forensik bukti 5.28, dan post-incident review bukti 5.27 sekaligus input 10.2 dan 8.2.

Kapan dipakai: menulis atau meninjau rencana IR, persiapan audit, tabletop, dan setelah insiden besar.
Kapan tidak cukup: Annex A dan 27035 tidak memberi detail teknis forensik; yang diatur adalah prosesnya: siapa, kapan, prosedur apa, dan rekaman apa yang tersisa.

## 3. Konsep inti

### 3.1 Event, insiden, dan kelemahan

27035-1:2023 memakai definisi dari ISO/IEC 27000 untuk istilah dasar [S9]. Dengan kata sendiri:

- **Event keamanan informasi:** keadaan sistem, layanan, atau jaringan yang menunjukkan kemungkinan pelanggaran kebijakan keamanan atau kegagalan kontrol. Contohnya satu alert login gagal beruntun.
- **Insiden keamanan informasi:** satu atau serangkaian event yang tidak diinginkan dan berpeluang besar mengganggu operasi bisnis atau mengancam keamanan informasi. Contohnya login berhasil dari IP mencurigakan setelah brute force.
- **Kelemahan (weakness):** kondisi yang bisa dimanfaatkan, tetapi belum terjadi apa-apa. Contohnya akun default yang masih aktif. Kontrol 6.8 meminta personel melaporkan event yang diamati maupun dicurigai, termasuk kelemahan seperti ini.

Sebagian besar event bukan insiden, sehingga 5.25 meminta kriteria untuk memutuskan event mana yang naik menjadi insiden, dengan keputusan yang tercatat. Triage alert di SOC adalah pelaksanaan 5.25.

### 3.2 Seri ISO/IEC 27035

| Bagian | Judul singkat | Edisi dan terbit | Fungsi |
|---|---|---|---|
| 27035-1 | Principles and process | Edisi 2, 13 Feb 2023 [S1] | Konsep, prinsip, dan proses inti |
| 27035-2 | Guidelines to plan and prepare for incident response | Edisi 2, 13 Feb 2023 [S6] | Rinci untuk fase plan and prepare dan learn lessons |
| 27035-3 | Guidelines for ICT incident response operations | Edisi 1, 16 Sep 2020 [S10] | Operasi IR TIK: deteksi, triage, analisis, containment, eradikasi, pemulihan |
| 27035-4 | Coordination | Edisi 1, 2 Des 2024 [S2] | Koordinasi lintas organisasi |

27035-1 berlaku untuk organisasi yang menangani insidennya sendiri maupun penyedia layanan manajemen insiden eksternal [S1]. Prosesnya terdiri dari lima fase, yang menjadi judul subbagian klausul 5 standar itu [S9]:

1. **Plan and prepare:** kebijakan, rencana, tim, alat, pelatihan;
2. **Detect and report:** mendeteksi event dan melaporkannya;
3. **Assess and decide:** menilai apakah event adalah insiden dan menentukan prioritas;
4. **Respond:** containment, investigasi, eradikasi, pemulihan;
5. **Learn lessons:** memperbaiki proses dan kontrol, termasuk dari near miss.

27035-1 juga memuat lampiran rujuk silang ke 27001 [S9]. 27035-2 merinci persiapan (kebijakan dengan dukungan pimpinan, rencana tertulis, tim, hubungan internal dan eksternal, dukungan teknis, pelatihan) dan learn lessons (identifikasi dan pelaksanaan perbaikan, evaluasi tim) [S6]. 27035-4 membahas penanganan insiden bersama oleh beberapa organisasi [S2], misalnya PT AN sebagai penyedia hosting yang berkoordinasi dengan klien saat VM klien diserang.

### 3.3 Kontrol Annex A dan fase 27035

| Fase 27035 | Kontrol Annex A | Bukti yang biasa diminta |
|---|---|---|
| Plan and prepare | 5.24 Information security incident management planning and preparation; 5.5 Contact with authorities; 5.6 Contact with special interest groups | Rencana IR, peran, daftar kontak, catatan latihan |
| Detect and report | 6.8 Information security event reporting; 8.15, 8.16 | Kanal lapor karyawan, rule deteksi, tiket dari laporan |
| Assess and decide | 5.25 Assessment and decision on information security events | Kriteria klasifikasi, tiket dengan alasan keputusan |
| Respond | 5.26 Response to information security incidents; 5.28 Collection of evidence; 5.29 Information security during disruption | Timeline, tindakan containment, formulir bukti |
| Learn lessons | 5.27 Learning from information security incidents | Post-incident review, tindakan perbaikan yang selesai |

Dua catatan:

- **6.8 ada di tema People** karena kewajibannya pada orang: setiap karyawan tahu cara dan ke mana melapor. Bukti kuatnya adalah tiket dari laporan karyawan, bukan poster kampanye.
- **5.28** meminta prosedur identifikasi, pengumpulan, akuisisi, dan preservasi bukti, supaya bukti tetap utuh untuk tindakan disipliner atau hukum. Cakupannya log sistem, tangkapan jaringan, image disk, dump memori, dan rekaman email [S8].

### 3.4 NIST SP 800-61 Rev. 3

NIST menerbitkan SP 800-61 Rev. 3 pada 3 April 2025 dengan judul Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile. Dokumen ini menggantikan Rev. 2 (6 Agustus 2012). Alasannya, insiden kini sering dan pemulihannya bisa berbulan-bulan, sehingga IR tidak lagi cocok diperlakukan sebagai siklus terpisah, dan pelajaran perlu dibagikan segera [S3].

Rev. 3 memuat tabel resmi yang memetakan fase lama ke fungsi CSF 2.0 [S3]:

| Fase Rev. 2 | Fungsi CSF 2.0 (Rev. 3) | Fase 27035 yang sejajar |
|---|---|---|
| Preparation | Govern, Identify (semua kategori), Protect | Plan and prepare |
| Detection and Analysis | Detect, Identify (Improvement) | Detect and report; Assess and decide |
| Containment, Eradication and Recovery | Respond, Recover, Identify (Improvement) | Respond |
| Post-Incident Activity | Identify (Improvement) | Learn lessons |

Kolom 27035 adalah penyejajaran catatan ini, bukan pemetaan resmi. Dalam model baru, Govern, Identify, dan Protect adalah lapisan persiapan yang lebih luas dari IR; IR sendiri adalah Detect, Respond, dan Recover; dan kategori Improvement (ID.IM) menerima pelajaran dari semua fungsi [S3]. Keputusan "event menjadi insiden" di Rev. 3 ada di DE.AE-08 (insiden dinyatakan bila event memenuhi kriteria), lalu RS.MA-02 (triage dan validasi laporan) dan RS.MA-03 (kategorisasi dan prioritas) [S3]. Itu padanan 5.25.

Organisasi ISO 27001 boleh menulis playbook dengan struktur NIST, asalkan 5.24-5.28 terpenuhi dan bisa dibuktikan.

### 3.5 Bukti digital dan ISO/IEC 27037

ISO/IEC 27037:2012 membahas tahap awal penanganan bukti digital: identifikasi, pengumpulan, akuisisi, dan preservasi, dengan menjaga integritas dan chain of custody. Panduannya mencakup media penyimpanan komputer, ponsel, kamera termasuk CCTV, dan sistem berjaringan [S11]. Standar ini membedakan dua peran [S4]:

- **Digital Evidence First Responder (DEFR):** orang pertama yang menangani bukti;
- **Digital Evidence Specialist (DES):** spesialis yang memproses bukti lebih lanjut.

Standar terkait: 27041 (jaminan metode investigasi), 27042 (analisis dan interpretasi), 27043 (prinsip dan proses investigasi), dan seri 27050 (electronic discovery) [S4].

Bila insiden mungkin berujung pada tindakan disipliner, klaim asuransi, atau proses hukum: catat siapa, kapan, apa, dan bagaimana; hitung hash; analisis salinan kerja, bukan bukti asli; batasi akses; kumpulkan yang paling mudah hilang lebih dulu (memori dan koneksi aktif sebelum disk); dan catat setiap alat beserta versinya.

### 3.6 Kewajiban pemberitahuan: UU PDP

UU No. 27 Tahun 2022 tentang Pelindungan Data Pribadi (diundangkan 17 Oktober 2022, LN 2022 No. 196) [S12], Pasal 46, berisi tiga ayat [S7]:

1. Bila terjadi kegagalan pelindungan data pribadi, pengendali wajib memberi pemberitahuan tertulis paling lambat 3 x 24 jam kepada subjek data dan kepada lembaga.
2. Pemberitahuan minimal memuat data pribadi yang terungkap, kapan dan bagaimana data terungkap, serta upaya penanganan dan pemulihan.
3. Dalam hal tertentu, pengendali juga wajib memberi tahu masyarakat.

Penjelasan pasal itu mengartikan kegagalan pelindungan data pribadi secara luas: kegagalan menjaga kerahasiaan, integritas, dan ketersediaan data pribadi, termasuk pelanggaran keamanan yang disengaja maupun tidak, yang berujung pada perusakan, kehilangan, perubahan, pengungkapan, atau akses tidak sah. "Dalam hal tertentu" dicontohkan antara lain kegagalan yang mengganggu pelayanan publik atau berdampak serius pada kepentingan masyarakat [S13]. UU dan penjelasannya tidak menyebut kapan hitungan 3 x 24 jam dimulai.

Konsekuensi untuk ISMS dan SOC:

- persyaratan ini masuk register pihak berkepentingan (4.2) dan kontrol 5.31 serta 5.34;
- playbook insiden yang menyangkut data pribadi butuh langkah "nilai apakah ini kegagalan pelindungan data pribadi" dan jam mulai tenggat yang dicatat;
- SOC perlu tahu kapan melibatkan DPO dan Legal, dan prosesor (MSSP, penyedia cloud) perlu kewajiban kontrak untuk segera melapor ke pengendali.

## 4. Contoh dokumen / artefak (organisasi fiktif)

Organisasi fiktif: PT Awan Nusantara (PT AN). Semua isi adalah ilustrasi.

### 4.1 Kriteria klasifikasi event (5.25)

| Prioritas | Kriteria (salah satu terpenuhi) | Waktu respons awal | Eskalasi |
|---|---|---|---|
| P1 Kritis | Data pribadi pelanggan terindikasi terungkap; ransomware aktif; layanan banyak pelanggan terganggu | 15 menit | Incident manager, Direktur Ops, DPO |
| P2 Tinggi | Akses tidak sah terkonfirmasi pada satu sistem; malware aktif tanpa penyebaran | 30 menit | Incident manager, Lead SOC |
| P3 Sedang | Aktivitas mencurigakan belum terkonfirmasi; percobaan eksploitasi gagal pada aset penting | 4 jam | Lead SOC |
| P4 Rendah | Event yang tidak memengaruhi CIA; false positive yang perlu tuning | 1 hari kerja | Tidak ada |

Kriteria P1 sengaja memicu penilaian UU PDP dan pelibatan DPO sejak awal, bukan di akhir investigasi.

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

Kolom hash dibiarkan kosong karena hanya bermakna bila dihitung dari bukti nyata.

### 4.4 Menghitung tenggat pemberitahuan

Skenario fiktif: analisis pada 2026-09-02 10:00 WIB menyimpulkan data pribadi 1.200 pelanggan terungkap. Kegagalan itu sendiri terjadi pada 2026-09-01 sekitar 14:30 WIB.

- Dihitung dari saat kejadian: 2026-09-01 14:30 + 72 jam = 2026-09-04 14:30 WIB.
- Dihitung dari saat diketahui: 2026-09-02 10:00 + 72 jam = 2026-09-05 10:00 WIB.

Selisihnya 19 jam 30 menit. Karena UU tidak menyebut titik mulainya, playbook PT AN memakai perhitungan yang lebih ketat (dari saat kejadian sejauh bisa diperkirakan) dan mencatat dasar keputusannya di tiket.

## 5. Lab praktik (di VM lab terisolasi)

Simpan di `latihan/day10-<nama-org-fiktif>.md`.

1. Tulis kriteria klasifikasi 4 tingkat seperti bagian 4.1. Minimal satu kriteria memicu penilaian UU PDP.
2. Tulis playbook untuk satu skenario (ransomware, akun cloud dibobol, atau kebocoran data lewat email). Setiap langkah dipetakan ke fase 27035, kontrol Annex A, dan rekaman.
3. Buat formulir chain of custody dengan kolom minimum seperti bagian 4.3.
4. Tulis template post-incident review: timeline, akar masalah, yang berjalan baik dan yang perlu diperbaiki, tindakan dengan pemilik dan tenggat, serta tautan ke register NC dan risiko.
5. Tulis tabletop 60 menit dengan 4 inject (alert awal, data pribadi terlibat, klien menelepon, wartawan bertanya), masing-masing dengan keputusan yang diharapkan dan kontrol yang diuji.
6. Di Splunk atau Wazuh lab, picu event jinak (beberapa login SSH gagal ke VM lab sendiri). Jalankan playbook sampai klasifikasi dan pencatatan bukti: waktu alert, waktu triage, keputusan, dan hash file ekspor alert.
7. Hitung dua versi tenggat pemberitahuan untuk skenario fiktifmu seperti bagian 4.4.

**Hasil yang sebaiknya tersimpan:**
- Kriteria, playbook, formulir, dan template PIR yang saling merujuk; setiap langkah playbook punya kontrol dan rekaman, dan bukti dikumpulkan sebelum eradikasi.
- Template PIR menautkan tindakan ke register NC/CA dan risk register.
- Tabletop menguji minimal 5.24, 5.25, 5.26, dan komunikasi (7.4).
- Satu catatan simulasi dengan waktu nyata dari lab-mu, serta hitungan tenggat yang sudah dicek ulang.

**Variasi tantangan:** PT AN memakai MSSP untuk monitoring malam. Tulis bagian playbook yang mengatur serah terima dari MSSP ke tim internal dengan gagasan koordinasi 27035-4: siapa memutuskan klasifikasi, siapa memegang bukti, dan siapa berbicara ke klien.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Klasifikasi tiket tidak konsisten antar shift | Kriteria tidak tertulis atau terlalu umum | Tulis kriteria dengan contoh; audit sampel tiket per bulan |
| Bukti hilang karena VM sudah dipulihkan | Urutan playbook salah | Kumpulkan bukti sebelum eradikasi; pengecualian tertulis bila bisnis harus pulih dulu |
| PIR ditulis tetapi tindakannya tidak selesai | Tidak ada tautan ke register CA | Wajibkan ID tindakan dan pemilik di setiap PIR |
| Karyawan tidak tahu ke mana melapor | 6.8 hanya berupa kebijakan | Satu kanal sederhana; uji lewat simulasi phishing |
| Tim ragu kapan memberi tahu regulator | Kewajiban hukum tidak masuk playbook | Tambahkan penilaian PDP dan kontak DPO/Legal di P1 |

## 7. Kesalahan umum dan jebakan

- Menyamakan setiap alert dengan insiden, padahal 5.25 meminta keputusan.
- Rencana IR yang tidak pernah diuji. Bukti latihan sama pentingnya dengan dokumennya.
- Melewatkan near miss di post-incident review. 27035 menekankan pembelajaran dari insiden kecil dan nyaris terjadi [S5].
- Menghitung tenggat pemberitahuan dari akhir investigasi. Tenggat UU PDP pendek, jadi penilaian dimulai sejak awal.

## 8. Catatan terkini

- ISO/IEC 27035-3:2020 sedang melalui tinjauan sistematis (dimulai Juli 2025, ditutup Desember 2025); katalog belum menunjukkan hasilnya [S10]. Cek apakah bagian ini dikonfirmasi atau direvisi.
- ISO/IEC 27037:2012 masih edisi berlaku; katalog ISO menyebut terakhir dikonfirmasi 2018 dan tidak mencantumkan proyek pengganti [S11].
- NIST SP 800-61 Rev. 3 (April 2025) menggantikan Rev. 2 [S3].
- UU PDP berlaku penuh sejak Oktober 2024. Menurut ringkasan firma profesional, peraturan pelaksananya terbit sebagai PP No. 33 Tahun 2026 (ditetapkan 16 Juli 2026, berlaku 16 Januari 2027) dan mengatur di Pasal 114-118 pemberitahuan 3 x 24 jam, pemberitahuan publik, dokumentasi insiden, prosedur internal termasuk post-incident review, dan kewajiban prosesor melapor ke pengendali [S14]. Nomor, tanggal, dan pasal itu belum dicocokkan dengan teks resmi; per 2026-10-10 PP ini belum muncul di peraturan.bpk.go.id. Saat teks resminya tersedia, cek apakah titik mulai hitungan diatur, dan cek status lembaga PDP, yang per Oktober 2026 dilaporkan belum terbentuk.

## 9. Cheat sheet

```
Event (mungkin masalah) -> Insiden (berpeluang besar merusak) ; Kelemahan (belum terjadi) -- definisi dari ISO/IEC 27000
27035-1:2023 ed.2 prinsip & proses | -2:2023 ed.2 rencana & persiapan | -3:2020 ed.1 operasi IR TIK | -4:2024 ed.1 koordinasi
Fase: plan & prepare | detect & report | assess & decide | respond | learn lessons
Kontrol: 5.24 rencana | 6.8 lapor event (People) | 5.25 nilai & putuskan | 5.26 respons
         5.27 belajar | 5.28 bukti | 5.5 otoritas | 5.6 kelompok khusus | 5.29 saat gangguan
NIST 800-61r3 (3 Apr 2025) = profil CSF 2.0, ganti r2 (Agu 2012)
  Preparation=GV+ID+PR | Detection&Analysis=DE | Contain/Eradicate/Recover=RS+RC | Post-incident=ID.IM
  deklarasi insiden: DE.AE-08 ; triage RS.MA-02 ; kategori & prioritas RS.MA-03
27037:2012 = identifikasi, pengumpulan, akuisisi, preservasi | DEFR & DES | 27041/27042/27043 | 27050 e-discovery
Bukti: siapa, kapan, apa, bagaimana, hash, salinan kerja, akses terbatas, riwayat serah terima
UU PDP Ps. 46: tertulis maks 3x24 jam ke subjek data + lembaga; isi: data apa, kapan/bagaimana, penanganan; publik "dalam hal tertentu"
PP 33/2026 (menurut ringkasan firma; cek teks resmi): Ps. 114-118 notifikasi, publik, dokumentasi, prosedur, prosesor ke pengendali
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | ISO committee: ISO/IEC 27035-1:2023 | https://committee.iso.org/standard/78973.html | primer (katalog ISO) | 2023-02-13; diakses 2026-10-10 | Tinggi untuk judul, edisi, tanggal, abstrak |
| S2 | ISO committee: ISO/IEC 27035-4:2024 | https://committee.iso.org/standard/80973.html | primer (katalog ISO) | 2024-12-02; diakses 2026-10-10 | Tinggi |
| S3 | NIST CSRC: SP 800-61 Rev. 3 | https://csrc.nist.gov/pubs/sp/800/61/r3/final | primer (NIST) | 2025-04-03; diakses 2026-10-10 | Tinggi. Tabel 1, DE.AE-08, RS.MA |
| S4 | ISO27k: ISO/IEC 27037 | https://www.iso27001security.com/html/27037 | sekunder (komentar praktisi) | diperbarui 2026-08-19; diakses 2026-10-08 | Sedang. Peran DEFR/DES, standar terkait |
| S5 | ISO27k: ISO/IEC 27035 | https://www.iso27001security.com/html/27035 | sekunder (komentar praktisi) | diperbarui 2026-08-19; diakses 2026-10-08 | Sedang. Penekanan pada near miss |
| S6 | ISO committee: ISO/IEC 27035-2:2023 | https://committee.iso.org/standard/78974.html | primer (katalog ISO) | 2023-02-13; diakses 2026-10-10 | Tinggi. Edisi dan abstrak |
| S7 | pasal.id: UU No. 27 Tahun 2022 Pasal 46 | https://pasal.id/peraturan/uu/uu-no-27-tahun-2022/pasal-46 | sekunder (agregator peraturan) | diakses 2026-10-10 | Sedang. Teks batang tubuh; cocok dengan ringkasan hukum lain |
| S8 | UpGuard: ISO 27001 control 5.28 collection of evidence | https://www.upguard.com/compliance/iso-27001/5-28/ | sekunder (vendor) | diakses 2026-10-08 | Sedang. Cakupan jenis bukti |
| S9 | VDE Verlag: pratinjau ISO/IEC 27035-1:2023 (daftar isi dan klausul 3) | https://assets.vde-verlag.de/iec-normen/preview-pdf/info_isoiec27035-1%7Bed2.0%7Den.pdf | primer (pratinjau resmi standar) | 2023; diakses 2026-10-10 | Tinggi. Lima fase di klausul 5, rujukan istilah ke 27000 |
| S10 | ISO committee: ISO/IEC 27035-3:2020 | https://committee.iso.org/standard/74033.html | primer (katalog ISO) | 2020-09-16; diakses 2026-10-10 | Tinggi. Edisi dan status tinjauan sistematis |
| S11 | ISO committee: ISO/IEC 27037:2012 | https://committee.iso.org/standard/44381.html | primer (katalog ISO) | 2012-10-15; diakses 2026-10-10 | Tinggi. Edisi, cakupan, status konfirmasi 2018 |
| S12 | JDIH BPK: UU No. 27 Tahun 2022 | https://peraturan.bpk.go.id/Details/229798/uu-no-27-tahun-2022 | primer (basis data peraturan resmi) | 2022-10-17; diakses 2026-10-10 | Tinggi untuk nomor, tanggal, dan status |
| S13 | Wikisource: UU No. 27 Tahun 2022, halaman penjelasan Pasal 46 | https://id.wikisource.org/wiki/Halaman:UU_Nomor_27_Tahun_2022_Tentang_Perlindungan_Data_Pribadi.pdf/46 | sekunder (transkripsi naskah resmi) | diakses 2026-10-10 | Sedang. Penjelasan ayat (1) dan (3) |
| S14 | RSM Indonesia: Client Alert PP 33/2026, six implementation priorities before 16 January 2027 | https://www.rsm.global/indonesia/sites/default/files/media/publications/Client%20Alert/2026/RSM%20Indonesia%20Client%20Alert%20-%20PP%20332026%20Six%20Implementation%20Priorities%20before%2016%20January%202027.pdf | sekunder (firma profesional) | 2026; diakses 2026-10-10 | Sedang. Tanggal penetapan dan berlaku, Pasal 114-118 |

**Catatan sumber:** isi 5.24-5.28 dan 27037 disusun dari katalog, pratinjau, dan ringkasan sekunder. Teks Pasal 46 dan penjelasannya berasal dari agregator dan transkripsi, karena salinan di JDIH BPK berupa hasil pindai. Isi PP 33/2026 berasal dari ringkasan firma dan belum dicocokkan dengan teks resmi.
