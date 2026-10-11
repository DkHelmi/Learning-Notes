---
day: 10
title: 'Kontrol insiden dan pelaporan event: 5.24-5.28, 6.8, seri ISO/IEC 27035, dan pemetaan ke playbook IR'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 27001:2022 + Amd 1:2024; ISO/IEC 27035-1:2023 (edisi 2), 27035-2:2023 (edisi 2), 27035-3:2020 (edisi 1, tinjauan sistematis 2025), 27035-4:2024 (edisi 1); ISO/IEC 27037:2012 (dikonfirmasi 2018); NIST SP 800-61 Rev. 3 (3 April 2025); UU No. 27 Tahun 2022 (PDP); PP No. 33 Tahun 2026 menurut ringkasan firma profesional (berlaku 16 Januari 2027; teks resmi belum ditemukan di peraturan.bpk.go.id per 2026-10-10)'
---

# Day 10: Kontrol insiden, pelaporan event, dan seri ISO/IEC 27035

Cakupan: kontrol Annex A 5.24-5.28 dan 6.8 beserta kontrol terkait, seri ISO/IEC 27035, ISO/IEC 27037 untuk bukti digital, perbandingan dengan NIST SP 800-61 Rev. 3, kewajiban pemberitahuan di UU PDP, dan pemetaannya ke playbook IR serta laporan forensik.

## Ide inti

Kontrol insiden di Annex A dan seri ISO/IEC 27035 tidak mengajarkan teknik forensik atau cara menulis detection. Yang diatur adalah prosesnya: siapa memutuskan, kapan, dengan prosedur apa, dan rekaman apa yang tersisa setelah semuanya selesai. Satu insiden harus bisa ditelusuri dari alert pertama, keputusan bahwa alert itu memang insiden, tindakan respons, bukti yang dijaga, pemberitahuan kepada pihak yang berhak tahu, sampai pelajaran yang mengubah kontrol.

Kamu sudah menjalankan siklus ini setiap kali menangani case: triage alert, eskalasi, containment, pengumpulan artefak, lalu post-incident review. Sejak Day 01, audit dipadankan dengan QA tiket (ambil sampel, cocokkan dengan prosedur) dan bukti dengan artefak yang bisa ditunjukkan. Proses insiden adalah area tempat kedua analogi itu paling harfiah: auditor memilih beberapa tiket lalu mencocokkannya dengan prosedur. Bagi SOC dan DFIR, playbook menjadi bukti 5.26, laporan forensik bukti 5.28, dan post-incident review bukti 5.27 sekaligus input 10.2 dan 8.2.

```
event (alert SIEM, laporan karyawan 6.8)
  -> 5.25 nilai dan putuskan: event biasa atau insiden? (kriteria tertulis, alasan di tiket)
  -> 5.26 respons: containment, eradikasi, pemulihan
       + 5.28 bukti dikumpulkan sebelum eradikasi (27037: hash, chain of custody)
       + pemberitahuan: klien sesuai kontrak; UU PDP 3 x 24 jam bila data pribadi terlibat
  -> 5.27 belajar: post-incident review -> 10.2 (corrective action) dan 8.2 (risk register)
5.24 rencana, peran, latihan, serta 5.5 dan 5.6 (kontak) menopang semua langkah
```

Situasi yang dipakai sepanjang Day ini: program audit internal PT Awan Nusantara (PT AN, penyedia hosting fiktif) di Day 06 menjadwalkan audit proses SOC (kontrol 5.24-5.28) pada Q1 2027, dengan auditor dari tim GRC yang tidak boleh berasal dari SOC. Auditor mengirim pesan ke Lead SOC:

> "Saya akan mengambil sampel tiket insiden, termasuk INC-2026-031 (akses tidak sah lewat akun default). Tolong siapkan:
> 1. Kriteria yang dipakai analyst untuk memutuskan sebuah alert menjadi insiden, dan di mana alasan keputusannya tercatat.
> 2. Rencana IR, bukti latihan dalam 12 bulan terakhir, dan penjelasan kenapa playbook kalian memakai struktur NIST padahal yang diaudit ISO.
> 3. Formulir chain of custody untuk bukti INC-2026-031.
> 4. Cara playbook menentukan tenggat pemberitahuan bila data pribadi pelanggan terlibat.
> 5. Post-incident review INC-2026-031 dan tindakan yang dihasilkannya."

Butir 1 adalah kontrol 5.25 (bagian 1.1 dan 2.1). Butir 2 menyentuh 5.24, seri 27035, dan NIST SP 800-61 Rev. 3 (bagian 1.2 sampai 1.4, contoh playbook di bagian 2.2). Butir 3 adalah 5.28 dan ISO/IEC 27037 (bagian 1.5 dan 2.3). Butir 4 adalah UU PDP (bagian 1.6 dan 2.4). Butir 5 adalah 5.27, yang di PT AN berujung pada corrective action CA-2026-014 (Day 06). Auditor juga biasanya memeriksa apakah daftar kontak otoritas (5.5, 5.6) masih mutakhir.

**Kapan relevan:** menulis atau meninjau rencana IR, persiapan audit, tabletop, dan setelah insiden besar.
**Kapan bukan jawaban:** Annex A dan 27035 tidak memberi detail teknis forensik. Yang diatur adalah prosesnya: siapa, kapan, prosedur apa, dan rekaman apa yang tersisa.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Tabel ini memuat istilah yang muncul di Day ini. Kolom padanan memakai analogi SOC yang sama di semua Day. Beda insiden dan nonconformity sudah dibahas di Day 06, dan struktur Annex A serta NIST CSF 2.0 di Day 08; istilah itu tidak diulang.

| Istilah | Arti singkat | Padanan di SOC |
|---|---|---|
| Event keamanan informasi | Keadaan yang menunjukkan kemungkinan pelanggaran kebijakan atau kegagalan kontrol | Alert |
| Insiden keamanan informasi | Satu atau serangkaian event yang berpeluang besar mengganggu bisnis atau mengancam keamanan informasi | Case yang dinaikkan setelah triage |
| Kelemahan (weakness) | Kondisi yang bisa dimanfaatkan, tetapi belum terjadi apa-apa | Temuan hardening atau kerentanan tanpa aktivitas |
| Seri ISO/IEC 27035 | Empat bagian panduan manajemen insiden: prinsip, persiapan, operasi, koordinasi | Kerangka IR yang menjadi acuan playbook |
| Lima fase 27035 | Plan and prepare, detect and report, assess and decide, respond, learn lessons | Siklus IR SOC: persiapan, deteksi, triage, respons, PIR |
| NIST SP 800-61 Rev. 3 | Panduan IR NIST yang disusun sebagai profil CSF 2.0 | Kerangka IR yang sering dipakai tim SOC |
| ISO/IEC 27037 | Panduan identifikasi, pengumpulan, akuisisi, dan preservasi bukti digital | Prosedur akuisisi forensik |
| DEFR dan DES | Penanganan bukti pertama vs spesialis yang memproses bukti lebih lanjut | Analyst on-call vs analyst DFIR |
| Chain of custody | Catatan siapa memegang bukti, kapan, dan untuk apa, sejak akuisisi | Riwayat serah terima artefak forensik |
| Post-incident review (PIR) | Tinjauan setelah insiden untuk menarik pelajaran dan tindakan perbaikan | Post-mortem atau lessons learned |
| Kegagalan pelindungan data pribadi | Istilah UU PDP untuk gagalnya menjaga kerahasiaan, integritas, dan ketersediaan data pribadi | Breach yang melibatkan data pribadi |
| Pengendali dan prosesor | Pihak yang wajib memberi pemberitahuan menurut UU PDP vs pihak yang memproses data untuknya | Pemilik data vs MSSP atau penyedia cloud |

### 1.1 Event, insiden, dan kelemahan

Butir pertama auditor menyangkut keputusan paling sering di SOC: alert ini insiden atau bukan? Di INC-2026-031, akun default yang masih aktif, login gagal beruntun, dan login berhasil setelah brute force adalah tiga hal yang berbeda kategori.

27035-1:2023 memakai definisi dari ISO/IEC 27000 untuk istilah dasar [S9]. Dengan kata sendiri:

- **Event keamanan informasi:** keadaan sistem, layanan, atau jaringan yang menunjukkan kemungkinan pelanggaran kebijakan keamanan atau kegagalan kontrol. Contohnya satu alert login gagal beruntun.
- **Insiden keamanan informasi:** satu atau serangkaian event yang tidak diinginkan dan berpeluang besar mengganggu operasi bisnis atau mengancam keamanan informasi. Contohnya login berhasil dari IP mencurigakan setelah brute force.
- **Kelemahan (weakness):** kondisi yang bisa dimanfaatkan, tetapi belum terjadi apa-apa. Contohnya akun default yang masih aktif. Kontrol 6.8 meminta personel melaporkan event yang diamati maupun dicurigai, termasuk kelemahan seperti ini.

Sebagian besar event bukan insiden, sehingga 5.25 meminta kriteria untuk memutuskan event mana yang naik menjadi insiden, dengan keputusan yang tercatat. Triage alert di SOC adalah pelaksanaan 5.25. Contoh kriteria ada di bagian 2.1.

### 1.2 Seri ISO/IEC 27035

Butir kedua auditor meminta rencana IR beserta acuannya. Di keluarga ISO, acuan itu adalah seri 27035, yang terdiri dari empat bagian dengan fungsi berbeda. Tabel berikut membantu kamu memilih bagian mana yang dibuka untuk kebutuhan tertentu; edisi dan tanggal terbitnya ada di bagian 6.

| Bagian | Judul singkat | Fungsi |
|---|---|---|
| 27035-1 | Principles and process | Konsep, prinsip, dan proses inti [S1] |
| 27035-2 | Guidelines to plan and prepare for incident response | Rinci untuk fase plan and prepare dan learn lessons [S6] |
| 27035-3 | Guidelines for ICT incident response operations | Operasi IR TIK: deteksi, triage, analisis, containment, eradikasi, pemulihan [S10] |
| 27035-4 | Coordination | Koordinasi lintas organisasi [S2] |

27035-1 berlaku untuk organisasi yang menangani insidennya sendiri maupun penyedia layanan manajemen insiden eksternal [S1]. Prosesnya terdiri dari lima fase, yang menjadi judul subbagian klausul 5 standar itu [S9]:

1. **Plan and prepare:** kebijakan, rencana, tim, alat, pelatihan;
2. **Detect and report:** mendeteksi event dan melaporkannya;
3. **Assess and decide:** menilai apakah event adalah insiden dan menentukan prioritas;
4. **Respond:** containment, investigasi, eradikasi, pemulihan;
5. **Learn lessons:** memperbaiki proses dan kontrol, termasuk dari near miss.

27035-1 juga memuat lampiran rujuk silang ke 27001 [S9]. 27035-2 merinci persiapan (kebijakan dengan dukungan pimpinan, rencana tertulis, tim, hubungan internal dan eksternal, dukungan teknis, pelatihan) dan learn lessons (identifikasi dan pelaksanaan perbaikan, evaluasi tim) [S6]. 27035-4 membahas penanganan insiden bersama oleh beberapa organisasi [S2], misalnya PT AN sebagai penyedia hosting yang berkoordinasi dengan klien saat VM klien diserang.

### 1.3 Kontrol Annex A dan fase 27035

Auditor tidak mengaudit 27035, karena 27035 adalah panduan. Yang diaudit adalah kontrol Annex A yang dipilih di SoA. Supaya bukti yang disiapkan Lead SOC tepat sasaran, setiap fase perlu dipasangkan dengan kontrolnya. Tabel berikut menunjukkan pasangan itu; kolom terakhir adalah yang akan diminta auditor dalam sampling.

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

Untuk butir 5 auditor, fase learn lessons di INC-2026-031 dibuktikan dengan post-incident review yang tindakannya masuk register corrective action (CA-2026-014 di Day 06).

### 1.4 NIST SP 800-61 Rev. 3

Butir kedua auditor juga menanyakan kenapa playbook PT AN memakai struktur NIST. Jawabannya ada di cara NIST menyusun ulang IR dan di posisi kontrol ISO sebagai yang diaudit.

NIST SP 800-61 Rev. 3 berjudul Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile, dan menggantikan Rev. 2 (tanggal keduanya di bagian 6). Alasannya, insiden kini sering dan pemulihannya bisa berbulan-bulan, sehingga IR tidak lagi cocok diperlakukan sebagai siklus terpisah, dan pelajaran perlu dibagikan segera [S3].

Rev. 3 memuat tabel resmi yang memetakan fase lama ke fungsi CSF 2.0 [S3]. Kolom terakhir ditambahkan di catatan ini supaya kamu bisa melihat fase 27035 mana yang sejajar.

| Fase Rev. 2 | Fungsi CSF 2.0 (Rev. 3) | Fase 27035 yang sejajar |
|---|---|---|
| Preparation | Govern, Identify (semua kategori), Protect | Plan and prepare |
| Detection and Analysis | Detect, Identify (Improvement) | Detect and report; Assess and decide |
| Containment, Eradication and Recovery | Respond, Recover, Identify (Improvement) | Respond |
| Post-Incident Activity | Identify (Improvement) | Learn lessons |

Kolom 27035 adalah penyejajaran catatan ini, bukan pemetaan resmi. Dalam model baru, Govern, Identify, dan Protect adalah lapisan persiapan yang lebih luas dari IR; IR sendiri adalah Detect, Respond, dan Recover; dan kategori Improvement (ID.IM) menerima pelajaran dari semua fungsi [S3]. Keputusan "event menjadi insiden" di Rev. 3 ada di DE.AE-08 (insiden dinyatakan bila event memenuhi kriteria), lalu RS.MA-02 (triage dan validasi laporan) dan RS.MA-03 (kategorisasi dan prioritas) [S3]. Itu padanan 5.25.

Organisasi ISO 27001 boleh menulis playbook dengan struktur NIST, asalkan 5.24-5.28 terpenuhi dan bisa dibuktikan.

### 1.5 Bukti digital dan ISO/IEC 27037

Butir ketiga auditor, formulir chain of custody, menguji apakah bukti INC-2026-031 masih bisa dipakai bila kasusnya berlanjut ke tindakan disipliner atau hukum. Acuannya ISO/IEC 27037.

ISO/IEC 27037:2012 membahas tahap awal penanganan bukti digital: identifikasi, pengumpulan, akuisisi, dan preservasi, dengan menjaga integritas dan chain of custody. Panduannya mencakup media penyimpanan komputer, ponsel, kamera termasuk CCTV, dan sistem berjaringan [S11]. Standar ini membedakan dua peran [S4]:

- **Digital Evidence First Responder (DEFR):** orang pertama yang menangani bukti;
- **Digital Evidence Specialist (DES):** spesialis yang memproses bukti lebih lanjut.

Standar terkait: 27041 (jaminan metode investigasi), 27042 (analisis dan interpretasi), 27043 (prinsip dan proses investigasi), dan seri 27050 (electronic discovery) [S4].

Bila insiden mungkin berujung pada tindakan disipliner, klaim asuransi, atau proses hukum: catat siapa, kapan, apa, dan bagaimana; hitung hash; analisis salinan kerja, bukan bukti asli; batasi akses; kumpulkan yang paling mudah hilang lebih dulu (memori dan koneksi aktif sebelum disk); dan catat setiap alat beserta versinya. Formulir di bagian 2.3 menampung catatan itu.

### 1.6 Kewajiban pemberitahuan: UU PDP

Butir keempat auditor menyangkut kewajiban hukum, bukan hanya kontrak dengan klien. Bila insiden menyentuh data pribadi pelanggan, ada tenggat yang berjalan sejak awal, sehingga playbook harus tahu kapan jam mulai dihitung.

UU No. 27 Tahun 2022 tentang Pelindungan Data Pribadi (diundangkan 17 Oktober 2022, LN 2022 No. 196) [S12], Pasal 46, berisi tiga ayat [S7]:

1. Bila terjadi kegagalan pelindungan data pribadi, pengendali wajib memberi pemberitahuan tertulis paling lambat 3 x 24 jam kepada subjek data dan kepada lembaga.
2. Pemberitahuan minimal memuat data pribadi yang terungkap, kapan dan bagaimana data terungkap, serta upaya penanganan dan pemulihan.
3. Dalam hal tertentu, pengendali juga wajib memberi tahu masyarakat.

Penjelasan pasal itu mengartikan kegagalan pelindungan data pribadi secara luas: kegagalan menjaga kerahasiaan, integritas, dan ketersediaan data pribadi, termasuk pelanggaran keamanan yang disengaja maupun tidak, yang berujung pada perusakan, kehilangan, perubahan, pengungkapan, atau akses tidak sah. "Dalam hal tertentu" dicontohkan antara lain kegagalan yang mengganggu pelayanan publik atau berdampak serius pada kepentingan masyarakat [S13]. UU dan penjelasannya tidak menyebut kapan hitungan 3 x 24 jam dimulai.

Konsekuensi untuk ISMS dan SOC:

- persyaratan ini masuk register pihak berkepentingan (4.2) dan kontrol 5.31 serta 5.34;
- playbook insiden yang menyangkut data pribadi butuh langkah "nilai apakah ini kegagalan pelindungan data pribadi" dan jam mulai tenggat yang dicatat;
- SOC perlu tahu kapan melibatkan DPO dan Legal, dan prosesor (MSSP, penyedia cloud) perlu kewajiban kontrak untuk segera melapor ke pengendali.

Peraturan pelaksana UU PDP dan status lembaga PDP masih bergerak; rinciannya di bagian 6. Contoh perhitungan tenggat ada di bagian 2.4.

## 2. Contoh dokumen / artefak (organisasi fiktif)

Organisasi fiktif: PT Awan Nusantara (PT AN). Semua isi adalah ilustrasi. Keempat artefak ini adalah yang disiapkan Lead SOC untuk audit internal Q1 2027 di bagian Ide inti.

### 2.1 Kriteria klasifikasi event (5.25)

Jawaban untuk butir 1 auditor. Cari kolom kriteria P1: di sana kriteria klasifikasi bertemu dengan kewajiban UU PDP.

| Prioritas | Kriteria (salah satu terpenuhi) | Waktu respons awal | Eskalasi |
|---|---|---|---|
| P1 Kritis | Data pribadi pelanggan terindikasi terungkap; ransomware aktif; layanan banyak pelanggan terganggu | 15 menit | Incident manager, Direktur Ops, DPO |
| P2 Tinggi | Akses tidak sah terkonfirmasi pada satu sistem; malware aktif tanpa penyebaran | 30 menit | Incident manager, Lead SOC |
| P3 Sedang | Aktivitas mencurigakan belum terkonfirmasi; percobaan eksploitasi gagal pada aset penting | 4 jam | Lead SOC |
| P4 Rendah | Event yang tidak memengaruhi CIA; false positive yang perlu tuning | 1 hari kerja | Tidak ada |

Kriteria P1 sengaja memicu penilaian UU PDP dan pelibatan DPO sejak awal, bukan di akhir investigasi. Alasan klasifikasi setiap tiket dicatat di tiket itu sendiri, sehingga auditor bisa mencocokkan keputusan dengan tabel ini.

### 2.2 Kerangka playbook ransomware VM pelanggan

Salah satu playbook dalam rencana IR yang diminta di butir 2 auditor. Setiap langkah membawa label fase 27035 dan kontrol Annex A, sehingga playbook berstruktur apa pun bisa ditelusuri ke kontrol yang diaudit. Perhatikan urutan langkah 4 dan 6.

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

### 2.3 Formulir chain of custody (kolom minimum)

Jawaban untuk butir 3 auditor: formulir untuk salah satu bukti INC-2026-031. Baca bagian riwayat serah terima, karena di sanalah chain of custody biasanya putus.

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

### 2.4 Menghitung tenggat pemberitahuan

Jawaban untuk butir 4 auditor, ditunjukkan dengan skenario latihan, bukan dengan INC-2026-031. Bandingkan kedua hasil hitungan dan perhatikan alasan PT AN memilih salah satunya.

Skenario fiktif: analisis pada 2026-09-02 10:00 WIB menyimpulkan data pribadi 1.200 pelanggan terungkap. Kegagalan itu sendiri terjadi pada 2026-09-01 sekitar 14:30 WIB.

- Dihitung dari saat kejadian: 2026-09-01 14:30 + 72 jam = 2026-09-04 14:30 WIB.
- Dihitung dari saat tervalidasi (organisasi mengetahui kegagalan itu): 2026-09-02 10:00 + 72 jam = 2026-09-05 10:00 WIB.

Selisihnya 19 jam 30 menit. Karena UU tidak menyebut titik mulainya, playbook PT AN menetapkannya sendiri: hitungan dimulai saat kegagalan tervalidasi, bukan saat investigasi selesai. Alasannya, waktu validasi tercatat pasti di tiket, sedangkan waktu kejadian sering baru bisa diperkirakan dan masih bisa bergeser setelah analisis forensik. Dasar keputusan dan perkiraan waktu kejadian tetap dicatat di tiket. Aturan yang sama dipakai di prosedur insiden PT AN pada Day 18.

## 3. Lab praktik (di VM lab terisolasi)

Simpan di `latihan/day10-<nama-org-fiktif>.md`.

1. Tulis kriteria klasifikasi 4 tingkat seperti bagian 2.1. Minimal satu kriteria memicu penilaian UU PDP.
2. Tulis playbook untuk satu skenario (ransomware, akun cloud dibobol, atau kebocoran data lewat email). Setiap langkah dipetakan ke fase 27035, kontrol Annex A, dan rekaman.
3. Buat formulir chain of custody dengan kolom minimum seperti bagian 2.3.
4. Tulis template post-incident review: timeline, akar masalah, yang berjalan baik dan yang perlu diperbaiki, tindakan dengan pemilik dan tenggat, serta tautan ke register NC dan risiko.
5. Tulis tabletop 60 menit dengan 4 inject (alert awal, data pribadi terlibat, klien menelepon, wartawan bertanya), masing-masing dengan keputusan yang diharapkan dan kontrol yang diuji.
6. Di Splunk atau Wazuh lab, picu event jinak (beberapa login SSH gagal ke VM lab sendiri). Jalankan playbook sampai klasifikasi dan pencatatan bukti: waktu alert, waktu triage, keputusan, dan hash file ekspor alert.
7. Hitung dua versi tenggat pemberitahuan untuk skenario fiktifmu seperti bagian 2.4.

**Hasil yang sebaiknya tersimpan:**
- Kriteria, playbook, formulir, dan template PIR yang saling merujuk; setiap langkah playbook punya kontrol dan rekaman, dan bukti dikumpulkan sebelum eradikasi.
- Template PIR menautkan tindakan ke register NC/CA dan risk register.
- Tabletop menguji minimal 5.24, 5.25, 5.26, dan komunikasi (7.4).
- Satu catatan simulasi dengan waktu nyata dari lab-mu, serta hitungan tenggat yang sudah dicek ulang.

**Variasi tantangan:** PT AN memakai MSSP untuk monitoring malam. Tulis bagian playbook yang mengatur serah terima dari MSSP ke tim internal dengan gagasan koordinasi 27035-4: siapa memutuskan klasifikasi, siapa memegang bukti, dan siapa berbicara ke klien.

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Klasifikasi tiket tidak konsisten antar shift | Kriteria tidak tertulis atau terlalu umum | Tulis kriteria dengan contoh; audit sampel tiket per bulan |
| Bukti hilang karena VM sudah dipulihkan | Urutan playbook salah | Kumpulkan bukti sebelum eradikasi; pengecualian tertulis bila bisnis harus pulih dulu |
| PIR ditulis tetapi tindakannya tidak selesai | Tidak ada tautan ke register CA | Wajibkan ID tindakan dan pemilik di setiap PIR |
| Karyawan tidak tahu ke mana melapor | 6.8 hanya berupa kebijakan | Satu kanal sederhana; uji lewat simulasi phishing |
| Tim ragu kapan memberi tahu regulator | Kewajiban hukum tidak masuk playbook | Tambahkan penilaian PDP dan kontak DPO/Legal di P1 |

## 5. Kesalahan umum dan jebakan

- Menyamakan setiap alert dengan insiden, padahal 5.25 meminta keputusan.
- Rencana IR yang tidak pernah diuji. Bukti latihan sama pentingnya dengan dokumennya.
- Melewatkan near miss di post-incident review. 27035 menekankan pembelajaran dari insiden kecil dan nyaris terjadi [S5].
- Menghitung tenggat pemberitahuan dari akhir investigasi. Tenggat UU PDP pendek, jadi penilaian dimulai sejak awal.

## 6. Catatan terkini

Bagian ini menampung edisi dan status standar, tanggal terbit panduan NIST, serta perkembangan peraturan pelaksana UU PDP. Berguna saat memilih edisi yang dikutip di rencana IR atau memperbarui playbook.

- Edisi seri 27035 yang berlaku: 27035-1 edisi 2, terbit 13 Februari 2023 [S1]; 27035-2 edisi 2, terbit 13 Februari 2023 [S6]; 27035-3 edisi 1, terbit 16 September 2020 [S10]; 27035-4 edisi 1, terbit 2 Desember 2024 [S2].
- ISO/IEC 27035-3:2020 sedang melalui tinjauan sistematis (dimulai Juli 2025, ditutup Desember 2025); katalog belum menunjukkan hasilnya [S10]. Cek apakah bagian ini dikonfirmasi atau direvisi.
- ISO/IEC 27037:2012 masih edisi berlaku; katalog ISO menyebut terakhir dikonfirmasi 2018 dan tidak mencantumkan proyek pengganti [S11].
- NIST menerbitkan SP 800-61 Rev. 3 pada 3 April 2025, menggantikan Rev. 2 (6 Agustus 2012) [S3].
- UU PDP berlaku penuh sejak Oktober 2024. Menurut ringkasan firma profesional, peraturan pelaksananya terbit sebagai PP No. 33 Tahun 2026 (ditetapkan 16 Juli 2026, berlaku 16 Januari 2027) dan mengatur di Pasal 114-118 pemberitahuan 3 x 24 jam, pemberitahuan publik, dokumentasi insiden, prosedur internal termasuk post-incident review, dan kewajiban prosesor melapor ke pengendali [S14]. Nomor, tanggal, dan pasal itu belum dicocokkan dengan teks resmi; per 2026-10-10 PP ini belum muncul di peraturan.bpk.go.id. Saat teks resminya tersedia, cek apakah titik mulai hitungan diatur, dan cek status lembaga PDP, yang per Oktober 2026 dilaporkan belum terbentuk.

## 7. Cheat sheet

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

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Supaya aman saat audit, Lead SOC mengusulkan setiap alert yang masuk SIEM PT AN otomatis dibuka sebagai tiket insiden. Apakah itu memenuhi 5.25 dengan lebih baik?

<details><summary>Jawaban</summary>

Tidak. Sebagian besar event bukan insiden, dan 5.25 justru meminta kriteria untuk memutuskan event mana yang naik menjadi insiden, dengan keputusan yang tercatat. Menyamakan setiap alert dengan insiden menghapus keputusan itu, sehingga auditor tidak bisa mencocokkan klasifikasi dengan kriteria. Yang dicari auditor adalah kriteria tertulis (seperti tabel P1-P4) dan alasan klasifikasi di setiap tiket. Lihat bagian 1.1, 2.1, dan 5.

</details>

**2. Skenario keputusan.** Alert enkripsi massal muncul di VM pelanggan dan tiket P1 dibuka. Head of Platform ingin layanan klien kembali secepatnya. Urutan mana yang paling tepat setelah klasifikasi?

- A. Pulihkan VM dari backup yang bersih dulu, lalu kumpulkan log yang tersisa untuk analisis.
- B. Isolasi VM dan segmen jaringan, ambil snapshot VM dan memori, hitung hash, isi formulir chain of custody, baru eradikasi dan pemulihan.
- C. Biarkan VM tetap berjalan tanpa isolasi sampai analisis forensik lengkap selesai, supaya tidak ada artefak yang berubah.

<details><summary>Jawaban</summary>

B. Di playbook PT AN, isolasi (containment) datang lebih dulu, lalu bukti dikumpulkan sebelum eradikasi, karena bila VM dibersihkan dulu, bukti hilang. Memori diambil bersama snapshot karena yang paling mudah hilang dikumpulkan lebih dulu. A menghapus bukti yang dibutuhkan 5.28; bila bisnis memang harus pulih dulu, pengecualiannya harus tertulis. C menunda containment, padahal di playbook isolasi adalah langkah respons pertama, sebelum pengumpulan bukti. Lihat bagian 1.5, 2.2, dan 4.

</details>

**3. Pertanyaan jebakan.** Playbook IR PT AN disusun mengikuti NIST SP 800-61 Rev. 3, bukan fase 27035. Seorang konsultan berkata auditor ISO pasti akan menganggapnya tidak sesuai. Benarkah?

<details><summary>Jawaban</summary>

Tidak. 27035 adalah panduan, sedangkan yang diaudit adalah kontrol Annex A yang dipilih. Organisasi ISO 27001 boleh menulis playbook dengan struktur NIST, asalkan 5.24-5.28 terpenuhi dan bisa dibuktikan. Cara praktisnya adalah memberi label kontrol dan rekaman di setiap langkah, seperti kolom Kontrol dan Rekaman di playbook PT AN. Penyejajaran fase NIST ke fase 27035 di catatan ini membantu, tetapi bukan pemetaan resmi. Lihat bagian 1.3, 1.4, dan 2.2.

</details>

**4. Skenario keputusan.** Dalam latihan tabletop, kegagalan pelindungan data pribadi terjadi pada 2026-09-01 sekitar 14:30 WIB dan analisis pada 2026-09-02 10:00 WIB menyimpulkan data pribadi 1.200 pelanggan terungkap. Tenggat mana yang sebaiknya dipakai playbook?

- A. 2026-09-05 10:00 WIB, dihitung dari saat kegagalan tervalidasi, dengan dasar keputusan dan perkiraan waktu kejadian dicatat di tiket.
- B. 2026-09-04 14:30 WIB, dihitung dari perkiraan waktu kejadian.
- C. 72 jam setelah investigasi selesai dan laporan forensik final ditandatangani.

<details><summary>Jawaban</summary>

A. UU PDP dan penjelasannya tidak menyebut kapan hitungan 3 x 24 jam dimulai, sehingga playbook PT AN menetapkan titik mulainya sendiri: saat kegagalan tervalidasi, karena waktunya tercatat pasti di tiket. B tidak bertentangan dengan teks UU dan lebih konservatif, tetapi waktu kejadian di sini hanya perkiraan dan bisa bergeser setelah analisis forensik, sehingga tenggatnya ikut bergeser; organisasi yang memilih cara ini tetap butuh dasar tertulis. C adalah kesalahan umum: tenggatnya pendek, jadi penilaian dimulai sejak awal, bukan di akhir investigasi. Titik mulai hitungan perlu dicek lagi saat teks resmi peraturan pelaksana tersedia. Lihat bagian 1.6, 2.4, 5, dan 6.

</details>

**5. Pertanyaan jebakan.** ISMS Manager memasang poster "laporkan hal mencurigakan" di setiap lantai kantor PT AN, lalu menandai kontrol 6.8 sebagai diterapkan di SoA. Bukti apa yang lebih kuat untuk auditor?

<details><summary>Jawaban</summary>

Tiket yang benar-benar berasal dari laporan karyawan. 6.8 ada di tema People karena kewajibannya pada orang: setiap karyawan tahu cara dan ke mana melapor, termasuk melaporkan kelemahan seperti akun default yang masih aktif. Poster hanya menunjukkan kampanye, bukan bahwa kanalnya dipakai. Bila karyawan tidak tahu ke mana melapor, sediakan satu kanal sederhana dan uji lewat simulasi phishing. Lihat bagian 1.1, 1.3, dan 4.

</details>

**6. Jelaskan ulang.** Jelaskan kepada Head of Platform beda event, insiden, dan kelemahan dengan memakai kasus akun default di VM pelanggan, tanpa memakai nomor kontrol.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Akun default yang masih aktif di VM adalah kelemahan: celahnya ada, tetapi belum ada yang terjadi, dan siapa pun yang melihatnya sebaiknya melapor. Saat SIEM mencatat login gagal beruntun ke akun itu, itu event: tanda kemungkinan ada masalah, yang harus dinilai dulu. Begitu ada login berhasil dari IP mencurigakan setelah brute force, itu insiden, karena keamanan VM pelanggan benar-benar terancam, dan keputusan menaikkannya dicatat di tiket berdasarkan kriteria tertulis."

Kesalahan yang sering muncul:
- Menyebut akun default aktif sebagai insiden, padahal belum terjadi apa-apa.
- Menganggap setiap event otomatis insiden, sehingga langkah penilaian dan pencatatan keputusan hilang.
- Lupa bahwa kelemahan juga wajib dilaporkan, bukan hanya event yang sudah terjadi.

</details>

**7. Interview question (English).** "How does a SOC's incident response process map to ISO 27001?"

<details><summary>Sample answer</summary>

"Mainly through Annex A controls 5.24 to 5.28 and 6.8, and ISO/IEC 27035 gives the process behind them in five phases. Plan and prepare is 5.24: the IR plan, roles, contacts with authorities, and exercises. Detect and report covers our detection and 6.8, so every employee knows how to report events and weaknesses. Assess and decide is 5.25: written triage criteria, with the reason for each classification recorded in the ticket. Respond is 5.26, and 5.28 for evidence, so we isolate first, acquire and hash evidence with a chain of custody form before eradication. Learn lessons is 5.27: a post-incident review whose actions go into the corrective action register and the risk register. Our playbooks can follow NIST SP 800-61 Rev. 3 as long as each step is traceable to those controls. And if personal data is involved, the Indonesian PDP law requires written notification within 3 x 24 hours, so that assessment starts at triage, not at the end."

What makes this answer strong: it maps each phase to a control and to the evidence an auditor would sample, shows that NIST and ISO can coexist, and includes the legal notification deadline that is easy to forget.

</details>

## 9. Sumber

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
