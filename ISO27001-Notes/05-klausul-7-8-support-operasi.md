---
day: 05
title: 'Klausul 7-8: sumber daya, kompetensi, awareness, komunikasi, informasi terdokumentasi, dan operasi'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 27001:2022 + Amd 1:2024 (tanpa revisi di katalog ISO per Okt 2026); ISO 10013:2021 (panduan documented information, acuan pembanding); Harmonized Structure Annex SL 2021'
---

# Day 05: Klausul 7-8, support dan operasi

Cakupan: klausul 7.1-7.5 dan 8.1-8.3 ISO/IEC 27001:2022 sebagai syarat agar rencana bisa dijalankan dan dibuktikan berjalan, dengan contoh penerapan di SOC. Kontrol Annex A terkait (6.3, 5.33, 5.37, 8.32, kelompok supplier) hanya disinggung karena detailnya di Day 08.

## Ide inti

Rencana dari klausul 6 tidak berjalan sendiri. Klausul 7 memastikan organisasi mampu menjalankannya: orangnya cukup, kompeten, sadar akan perannya, tahu harus berbicara kepada siapa, dan memakai dokumen yang benar. Klausul 8 memastikan rencana itu benar-benar dijalankan: proses berjalan sesuai kriteria, perubahan dikendalikan, pihak luar diawasi, dan risiko dinilai ulang saat keadaan berubah. Di audit, keduanya diuji lewat wawancara dan sampling, bukan lewat dokumen kebijakan.

Kamu mengenal ini sebagai kesiapan operasional SOC. Roster shift yang cukup, analyst yang lulus QA, runbook yang satu versi resmi di repo, jalur eskalasi yang jelas, monitoring kesehatan pipeline log, dan MSSP yang dievaluasi. SOC dengan detection rule bagus tetapi runbook hanya di kepala analyst senior akan goyah begitu analyst itu resign. Auditor mencari celah yang sama.

```
Rencana (klausul 6)
  -> 7 Dukungan: orang cukup (7.1), kompeten (7.2), sadar (7.3),
                 tahu jalur komunikasi (7.4), dokumen terkendali (7.5)
  -> 8 Operasi:  proses sesuai kriteria, perubahan dan pihak luar dikendalikan (8.1),
                 risk assessment dijalankan (8.2), treatment dijalankan (8.3)
  -> bukti:      rekaman kompetensi, runbook berversi, tiket, hasil RA dan RT
```

Situasi yang dipakai sepanjang Day ini: pada hari audit, auditor menghabiskan satu jam di ruang SOC PT Awan Nusantara (PT AN, penyedia hosting fiktif) dan mewawancarai analyst L1 shift malam. Pertanyaannya:

> 1. "Apa kaitan kebijakan keamanan perusahaan dengan pekerjaanmu, dan apa akibatnya kalau tidak dipatuhi?"
> 2. "Pelatihan apa yang kamu ikuti tahun ini, dan bagaimana perusahaan tahu pelatihan itu berhasil?"
> 3. "Tunjukkan runbook yang kamu pakai untuk alert brute force SSH. Versi berapa, siapa yang menyetujui, dan apakah ini satu-satunya salinan?"
> 4. "Kalau insiden memengaruhi klien, siapa yang memberi tahu klien, dan siapa yang boleh menjawab wartawan?"
> 5. "Bulan lalu tiga parser gagal selama sembilan jam setelah update agent. Bagaimana kalian tahu, dan apa yang berubah sesudahnya?"
> 6. "Monitoring malam rencananya dialihkan ke MSSP. Bagaimana kalian akan mengawasi kinerja mereka?"

Setiap pertanyaan menunjuk satu subklausul: 7.3, 7.2, 7.5, 7.4, 8.1 (perubahan tidak direncanakan), dan 8.1 (pihak eksternal). Banyak temuan audit di area ini lahir dari kebiasaan sehari-hari, misalnya runbook yang hanya ada di kepala analyst senior, wiki tanpa riwayat persetujuan, atau MSSP yang tidak pernah dievaluasi.

**Kapan relevan:** setiap kali SOC menulis prosedur, merekrut atau melatih analyst, mengganti alat, memakai pihak ketiga, atau bersiap menghadapi wawancara audit.
**Kapan bukan jawaban:** klausul 7-8 tidak menentukan isi teknis prosedur. Isi teknis datang dari kontrol yang dipilih (Day 08-12).

## 1. Konsep inti

### 1.0 Istilah di Day ini

Tabel ini memuat istilah yang muncul di Day ini. Kolom padanan memakai analogi SOC yang sama di semua Day. Istilah dari Day 01-04 (misalnya informasi terdokumentasi, dokumen dan rekaman, risk assessment) tidak diulang.

| Istilah | Arti singkat | Padanan di SOC |
|---|---|---|
| Sumber daya (7.1) | Orang, waktu, alat, dan anggaran untuk ISMS | Roster shift, lisensi, storage |
| Kompetensi (7.2) | Kemampuan menerapkan pengetahuan dan keterampilan untuk pekerjaan yang memengaruhi keamanan | Skill matrix analyst dengan skor QA |
| Efektivitas tindakan | Bukti bahwa pelatihan atau tindakan lain benar-benar mengubah kemampuan | Analyst yang dilatih hunting menghasilkan laporan hunt |
| Awareness (7.3) | Kesadaran akan kebijakan, kontribusi diri, dan akibat tidak patuh | Program security awareness untuk semua karyawan |
| Matriks komunikasi (7.4) | Tabel apa, kapan, kepada siapa, dan bagaimana berkomunikasi | Jalur pemberitahuan insiden ke klien, regulator, media |
| Pengendalian dokumen (7.5.2-7.5.3) | Identitas, format, persetujuan, akses, perubahan, retensi, pemusnahan | Repo git runbook dengan pull request |
| Dokumen dari luar | Dokumen pihak lain yang dipakai ISMS: panduan vendor, teks regulasi | Dokumentasi SIEM versi yang terpasang |
| Kriteria proses (8.1) | Ukuran kapan sebuah proses dianggap berjalan benar | Definisi "triage selesai" dan SLA-nya |
| Perubahan tidak direncanakan | Perubahan yang terjadi tanpa direncanakan dan harus ditinjau akibatnya | Parser rusak setelah update agent |
| Proses, produk, layanan pihak eksternal | Semua yang disediakan pihak luar dan relevan dengan ISMS | MSSP, SIEM SaaS, platform cloud |

### 1.1 Klausul 7.1: sumber daya

Sebelum auditor bertanya apa pun, ada pertanyaan yang lebih dasar: apakah SOC 24x7 PT AN punya cukup orang untuk benar-benar 24x7?

Organisasi menentukan dan menyediakan sumber daya untuk membangun, menjalankan, memelihara, dan meningkatkan ISMS. Sumber daya mencakup orang, waktu, alat, dan anggaran, dan pengelolaannya berlangsung terus, bukan sekali beli [S1]. Bukti yang wajar: persetujuan anggaran, rencana kapasitas, dan catatan pengadaan alat [S2].

Contoh hitungan kasar untuk SOC 24x7: satu kursi analyst yang selalu terisi membutuhkan 168 jam per minggu. Bila satu orang bekerja 40 jam per minggu, dibutuhkan 168 / 40 = 4,2 orang per kursi, belum termasuk cuti, sakit, dan pelatihan. Angka seperti ini membantu menunjukkan ke pimpinan (dan auditor) bahwa sumber daya dihitung, bukan ditebak.

### 1.2 Klausul 7.2: kompetensi

Pertanyaan 2 auditor ("bagaimana perusahaan tahu pelatihan itu berhasil?") menyasar sisi 7.2 yang paling sering terlewat.

Organisasi harus [S1]:

- a. menentukan kompetensi yang dibutuhkan orang yang bekerja di bawah kendali organisasi dan pekerjaannya memengaruhi kinerja keamanan informasi;
- b. memastikan orang itu kompeten berdasarkan pendidikan, pelatihan, atau pengalaman;
- c. bila perlu, mengambil tindakan untuk memenuhi kompetensi dan menilai efektivitas tindakan itu. Catatan standar menyebut contoh tindakan: pelatihan, mentoring, rotasi tugas, merekrut, atau mengontrak orang yang kompeten;
- d. menyimpan bukti kompetensi sebagai informasi terdokumentasi.

Butir d adalah salah satu rekaman wajib (Day 02 bagian 1.6). Auditor mencari sertifikat, CV, catatan pelatihan, atau penilaian kinerja, bukan pernyataan "tim kami berpengalaman" [S1][S2]. Karena rumusannya "di bawah kendali organisasi", kontraktor dan staf MSSP yang bekerja untuk ISMS ikut tercakup [S1].

Bagian yang sering terlewat adalah menilai efektivitas. Mengirim analyst ke pelatihan threat hunting belum membuktikan apa pun. Buktinya adalah perubahan yang terukur, misalnya analyst itu menjalankan dua hunt terdokumentasi dalam tiga bulan berikutnya, atau lulus penilaian praktik internal. Di SOC, ini sama dengan tidak menganggap analyst siap hanya karena sudah membaca runbook; yang dilihat adalah skor QA tiketnya.

### 1.3 Klausul 7.3: awareness

Pertanyaan 1 auditor tidak meminta analyst menghafal kebijakan. Yang diuji adalah apakah ia paham kaitannya.

Semua orang yang bekerja di bawah kendali organisasi harus sadar akan tiga hal [S1]: (a) kebijakan keamanan informasi; (b) kontribusinya pada efektivitas ISMS, termasuk manfaat bila kinerja keamanan membaik; (c) akibat bila tidak mematuhi persyaratan ISMS.

Awareness membuat orang paham relevansi dan konsekuensi; pelatihan membangun keterampilan [S2]. Karyawan tidak perlu hafal kalimat kebijakan, tetapi harus bisa menjelaskan tanggung jawabnya, dan auditor mengujinya lewat wawancara [S1]. 7.3 tidak mewajibkan informasi terdokumentasi, jadi format buktinya bebas: sertifikat, daftar hadir, atau hasil kuis [S5].

Kontrol Annex A 6.3 (Information security awareness, education and training) adalah pasangan operasional 7.3: program awareness dan pelatihan yang terencana dan diperbarui.

### 1.4 Klausul 7.4: komunikasi

Pertanyaan 4 auditor menyangkut komunikasi yang paling sensitif bagi SOC: komunikasi insiden.

Organisasi menentukan kebutuhan komunikasi internal dan eksternal yang relevan dengan ISMS, mencakup (a) apa yang dikomunikasikan, (b) kapan, (c) kepada siapa, dan (d) bagaimana [S8]. Bentuk yang praktis adalah matriks komunikasi per audiens [S2]. Kolom "pengirim" di matriks komunikasi tetap praktik baik walau tidak disebut eksplisit di edisi 2022.

Untuk SOC, komunikasi yang paling sensitif adalah komunikasi insiden: kapan klien diberi tahu, siapa yang boleh berbicara ke media, dan jalur ke regulator. Itu semua harus konsisten dengan prosedur insiden (kontrol 5.24-5.26) dan kewajiban kontrak di register pihak berkepentingan (Day 03).

### 1.5 Klausul 7.5: informasi terdokumentasi

Pertanyaan 3 auditor ("versi berapa, siapa yang menyetujui, apakah ini satu-satunya salinan?") adalah ujian 7.5. Padanannya repo git runbook: branch main sebagai satu-satunya versi resmi, pull request sebagai bukti persetujuan, dan riwayat commit sebagai jejak perubahan.

Tabel berikut merangkum tiga subklausul 7.5. Kolom kanan menunjukkan wujudnya di SOC.

| Subklausul | Isi (kata sendiri) | Contoh di SOC |
|---|---|---|
| 7.5.1 Umum | ISMS memuat (a) informasi yang diwajibkan standar dan (b) informasi yang dianggap perlu oleh organisasi. Luasnya boleh berbeda menurut ukuran dan jenis organisasi, kompleksitas proses, dan kompetensi orang | Runbook triage dianggap perlu karena turnover analyst tinggi |
| 7.5.2 Membuat dan memperbarui | (a) identitas dan deskripsi (judul, tanggal, penulis, nomor rujukan); (b) format (bahasa, versi perangkat lunak, grafik) dan media (kertas, elektronik); (c) tinjauan dan persetujuan atas kesesuaian dan kecukupan | Header runbook berisi ID, versi, pemilik, dan penyetuju |
| 7.5.3 Pengendalian | (a) tersedia dan layak dipakai saat dibutuhkan; (b) terlindungi dari bocor, salah pakai, dan kehilangan integritas. Yang diatur: (c) distribusi, akses, pengambilan, dan pemakaian; (d) penyimpanan dan preservasi, termasuk tetap terbaca; (e) pengendalian perubahan; (f) retensi dan pemusnahan. Dokumen dari luar yang diperlukan juga diidentifikasi dan dikendalikan | Wiki dengan hak akses per role (baca saja atau baca-ubah), riwayat versi, dan jadwal tinjau; panduan vendor SIEM disimpan sesuai versi yang dipakai |

Standar tidak mewajibkan bentuk tertentu. Panduan ISO 10013:2021 untuk sistem manajemen mutu menegaskan bahwa media elektronik boleh dipakai dengan berbagai cara dan manual dokumen tidak lagi wajib [S6]. Bagi SOC, repositori git dengan pull request dan review adalah bentuk pengendalian perubahan yang sah, asalkan persetujuan dan riwayatnya bisa ditunjukkan. Batas analoginya: 7.5.3 juga mengatur akses, retensi, pemusnahan, dan dokumen dari luar, hal yang tidak otomatis diurus oleh git.

Temuan audit yang sering muncul di 7.5.3 [S3]:

- salinan kebijakan tidak terkendali di drive lokal, atau versi berbeda di intranet dan materi pelatihan;
- tanggal tinjau kosong atau kedaluwarsa, atau komentar draf tertinggal di versi terbit;
- hak akses berlebihan untuk karyawan yang sudah keluar;
- tidak ada bukti pemusnahan aman walaupun kebijakan retensinya ada.

Kontrol Annex A terkait: 5.33 Protection of records (rekaman dilindungi dari hilang, rusak, dan akses tidak sah) dan 5.37 Documented operating procedures (prosedur operasional tersedia bagi yang membutuhkan).

Log di SIEM juga bisa menjadi rekaman ISMS bila dipakai sebagai bukti, misalnya bukti monitoring (9.1) atau bukti insiden. Akibatnya, retensi dan proteksi integritas log ikut menjadi urusan 7.5.3, bukan hanya urusan kapasitas storage.

### 1.6 Klausul 8.1: perencanaan dan pengendalian operasional

Pertanyaan 5 dan 6 auditor sama-sama menyangkut 8.1: yang satu tentang perubahan yang tidak direncanakan, yang lain tentang pihak luar.

8.1 meminta organisasi merencanakan, menjalankan, dan mengendalikan proses yang dibutuhkan untuk memenuhi persyaratan keamanan dan menjalankan tindakan dari klausul 6 (termasuk rencana sasaran 6.2). Caranya [S4]:

- menetapkan kriteria untuk proses itu, lalu mengendalikan proses sesuai kriterianya;
- menyediakan informasi terdokumentasi secukupnya untuk yakin proses berjalan sesuai rencana;
- mengendalikan perubahan yang direncanakan, meninjau akibat perubahan yang tidak direncanakan, dan memitigasi dampak buruknya bila perlu;
- memastikan proses, produk, atau layanan dari pihak eksternal yang relevan dengan ISMS ikut dikendalikan.

**Perubahan tidak direncanakan.** Butir ini sangat relevan untuk SOC: update otomatis agent mengubah format log, parser gagal, dan alert berhenti muncul. Monitoring kesehatan pipeline log adalah cara SOC menyadari kejadian seperti ini, meninjau akibatnya, dan bertindak. Batas analoginya: butir ini berlaku untuk semua proses ISMS, bukan hanya pipeline teknis.

**Pihak eksternal.** Cakupannya luas: platform cloud, SaaS, MSSP, dan kontraktor [S7]. Kontrol Annex A yang menjadi alat pelaksananya adalah 5.19-5.23 (pemasok dan cloud). URM menyarankan pengendalian pemasok lewat seleksi, evaluasi ulang berkala, dan pemantauan kinerja, menanam pengendalian di alat kerja yang sudah ada (ticketing, ERP) alih-alih proses paralel, serta mempertimbangkan 6.3 (perubahan ISMS) dan kontrol 8.32 (perubahan teknis) bersama [S4]. Akuntabilitas tetap di organisasi; kontrak tanpa evaluasi tidak cukup.

### 1.7 Klausul 8.2 dan 8.3: menjalankan risk assessment dan treatment

Kejadian parser gagal dan rencana MSSP sama-sama mengubah keadaan. Pertanyaan berikutnya: apakah risk register ikut diperbarui, atau menunggu jadwal tahunan?

8.2 meminta risk assessment dijalankan pada interval terencana, serta saat perubahan signifikan diusulkan atau terjadi, dengan memakai kriteria dari 6.1.2 a. Hasilnya wajib disimpan. 8.3 meminta risk treatment plan dijalankan dan hasil treatment disimpan [S4].

Pemicu di luar jadwal yang wajar untuk SOC:

- insiden besar yang menunjukkan skenario baru;
- perubahan arsitektur, misalnya migrasi SIEM atau pindah ke cloud;
- regulasi atau kontrak baru;
- temuan audit yang menunjukkan kontrol tidak efektif.

Bukti 8.2 yang lemah biasanya berupa risk register dengan tanggal tinjau terakhir dua tahun lalu, padahal ada migrasi besar tahun ini.

## 2. Contoh dokumen / artefak (organisasi fiktif)

Organisasi fiktif: PT Awan Nusantara (PT AN). Semua isi adalah ilustrasi. Keempat artefak ini adalah yang ditunjukkan SOC PT AN saat menjawab pertanyaan auditor di bagian Ide inti.

### 2.1 Matriks kompetensi SOC (7.2)

Jawaban untuk pertanyaan 2 auditor. Perhatikan kolom terakhir: setiap kompetensi punya cara menilai efektivitas.

| Kompetensi | L1 | L2 | L3/Lead | Bukti | Cara menilai efektivitas |
|---|---|---|---|---|---|
| Triage alert sesuai runbook | Wajib | Wajib | Wajib | Catatan onboarding, QA sampling tiket | Skor QA sampling minimal 90% |
| Query SIEM (SPL dan Wazuh) | Dasar | Mahir | Mahir | Pelatihan internal, tugas praktik | Lulus tugas praktik 5 query |
| Penanganan bukti dan chain of custody | Paham | Wajib | Wajib | Pelatihan DFIR internal | Audit sampel formulir chain of custody |
| Threat hunting berbasis hipotesis | - | Dasar | Mahir | Sertifikat atau laporan hunt | 2 laporan hunt per kuartal |
| Komunikasi insiden ke klien | - | Paham | Wajib | Simulasi tabletop | Hasil evaluasi tabletop |

Status per orang dicatat terpisah, misalnya "Analyst A: L1, lulus QA 93%, belum pelatihan chain of custody, target selesai Q3". Matriks menunjukkan apa yang dibutuhkan; catatan per orang menunjukkan siapa yang sudah memenuhi. Keduanya dibutuhkan untuk 7.2.

### 2.2 Matriks komunikasi (7.4)

Jawaban untuk pertanyaan 4 auditor. Baris klien dan media adalah yang ditanyakan.

| Apa | Kapan | Kepada siapa | Bagaimana | Pengirim |
|---|---|---|---|---|
| Ringkasan metrik SOC | Bulanan | Manajemen, ISMS Manager | Laporan + rapat | Lead SOC |
| Insiden yang memengaruhi layanan klien | Sesuai tenggat kontrak | Kontak keamanan klien | Email terenkripsi + telepon | Incident manager |
| Pemberitahuan kegagalan pelindungan data pribadi | Tertulis, paling lambat 3 x 24 jam (UU PDP Pasal 46, Day 10 bagian 1.6); UU dan penjelasannya tidak menyebut titik mulai, prosedur PT AN memakai saat kegagalan tervalidasi (Day 10 bagian 2.4) | Lembaga PDP, subjek data | Kanal resmi | DPO dan Legal |
| Perubahan kebijakan keamanan | Saat terbit | Semua karyawan in-scope | Email + pengakuan baca | ISMS Manager |
| Peringatan phishing aktif | Saat terdeteksi | Semua karyawan | Pesan singkat internal | Analyst on-duty |
| Pertanyaan media soal insiden | Saat ada | Media | Hanya lewat juru bicara | Corporate communication |

Baris terakhir sering terlupa. Bila tidak ada aturan, analyst bisa saja menjawab pertanyaan wartawan lewat media sosial pribadi.

### 2.3 Header pengendalian dokumen untuk runbook (7.5.2 dan 7.5.3)

Jawaban untuk pertanyaan 3 auditor: header ini menunjukkan versi, penyetuju, dan lokasi resmi.

```
ID          : RB-SOC-007
Judul       : Triage alert brute force SSH pada VM pelanggan
Versi       : 1.3
Pemilik     : Lead SOC
Penyetuju   : ISMS Manager
Disetujui   : 2026-08-20
Tinjau ulang: 2027-02-20 (6 bulan) atau saat ada perubahan rule/alat
Klasifikasi : Internal
Lokasi resmi: repo git soc-runbooks, branch main (salinan lain tidak terkendali)
Riwayat     : 1.2 -> 1.3 menambah langkah cek akun default (CA-2026-014)
```

Cara membaca:

- "Lokasi resmi" menjawab masalah salinan tidak terkendali.
- "Tinjau ulang" punya dua pemicu, yaitu tanggal dan perubahan.
- "Riwayat" menunjuk ke corrective action (10.2), sehingga auditor bisa menelusuri kenapa runbook berubah.
- Bila runbook disimpan di git, persetujuan bisa dibuktikan dengan pull request yang di-review oleh penyetuju.

### 2.4 Pengendalian pihak eksternal dan perubahan tidak direncanakan (8.1)

Jawaban untuk pertanyaan 5 dan 6 auditor.

| Pihak atau kejadian | Pengendalian | Bukti |
|---|---|---|
| MSSP untuk monitoring malam (opsi masa depan) | Klausul keamanan di kontrak, SLA triage, laporan bulanan, evaluasi tahunan | Kontrak, laporan SLA, notulen evaluasi |
| Penyedia SIEM cloud | Penilaian keamanan sebelum kontrak, tinjau laporan audit pihak ketiga tiap tahun | Kuesioner, laporan audit pemasok |
| Kejadian: update agent mengubah format log, 3 parser gagal selama 9 jam | Alert kesehatan pipeline, tinjauan pasca-kejadian, rollback, uji parser sebelum update berikutnya | Tiket, laporan tinjauan, perubahan prosedur update |

Kejadian di baris ketiga adalah contoh perubahan tidak direncanakan menurut 8.1. Bila terulang atau berdampak besar, kejadian itu juga menjadi nonconformity yang ditangani di 10.2.

## 3. Lab praktik

Latihan untuk organisasi fiktifmu. Simpan di `latihan/day05-<nama-org-fiktif>.md`.

1. Hitung kebutuhan orang untuk SOC fiktifmu: jumlah kursi yang harus terisi, jam operasi per minggu, dan asumsi jam kerja per orang. Tulis hasil hitungannya dan cek ulang.
2. Buat matriks kompetensi seperti bagian 2.1 untuk minimal 5 kompetensi. Setiap kompetensi punya kolom bukti dan cara menilai efektivitas.
3. Tulis rencana awareness untuk tiga audiens: semua karyawan, engineer, dan pimpinan. Untuk masing-masing tulis pesan inti, format, frekuensi, dan cara mengujinya.
4. Buat matriks komunikasi minimal 6 baris, termasuk satu baris media dan satu baris regulator.
5. Pilih satu runbook dari lab-mu (atau tulis runbook pendek untuk satu alert Wazuh atau Splunk). Tambahkan header pengendalian dokumen seperti bagian 2.3.
6. Daftar 5 proses operasional SOC (misalnya triage, eskalasi, tuning rule, onboarding sumber log, penanganan bukti). Untuk tiap proses tulis kriterianya, artinya "proses ini dianggap berjalan benar bila ...", dan rekaman yang membuktikannya.
7. Hubungkan ke lab: periksa apakah konfigurasi penting di lab-mu (misalnya `ossec.conf` dan rule kustom Wazuh, atau saved search Splunk) punya riwayat perubahan. Bila tidak, tulis usulan cara mengendalikannya (git, backup bertanggal, atau catatan perubahan). Cukup amati dan tulis usulan; jangan mengubah konfigurasi saat latihan ini.
8. Tulis satu skenario perubahan tidak direncanakan di lab-mu dan langkah 8.1 untuk menanganinya.

**Hasil yang sebaiknya tersimpan:**
- Hitungan kebutuhan orang lengkap dengan asumsinya.
- Matriks kompetensi yang setiap barisnya punya cara menilai efektivitas, bukan hanya "ikut pelatihan".
- Rencana awareness yang membedakan awareness dari pelatihan.
- Matriks komunikasi dengan baris media dan regulator.
- Header runbook yang menyebut lokasi resmi, penyetuju, dan pemicu tinjau.
- Daftar proses operasional dengan kriteria dan rekamannya, plus satu skenario perubahan tidak direncanakan.
- Tidak ada kalimat yang disalin dari teks standar.

**Variasi tantangan:** tulis lima pertanyaan wawancara yang akan diajukan auditor kepada analyst L1 untuk menguji 7.3, beserta jawaban yang menurutmu memadai.

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Bukti kompetensi hanya berupa sertifikat kehadiran | Efektivitas tidak dinilai | Tambahkan penilaian praktik atau indikator kinerja setelah pelatihan |
| Analyst tidak bisa menjelaskan kebijakan saat ditanya | Awareness hanya berupa email sekali setahun | Ringkas kebijakan menjadi 5 poin; uji lewat kuis dan diskusi tim |
| Runbook di wiki berbeda dengan versi di git | Dua lokasi tanpa satu sumber resmi | Tetapkan satu lokasi resmi; lokasi lain hanya tautan |
| MSSP tidak pernah dievaluasi | Pengendalian pihak eksternal hanya di kontrak | Jadwalkan evaluasi berkala dan minta laporan kinerja |
| Risk register tidak diperbarui setelah migrasi besar | Risk assessment hanya tahunan | Tambahkan pemicu "perubahan signifikan" di metodologi risiko |

## 5. Kesalahan umum dan jebakan

- Menganggap 7.5 mewajibkan "prosedur kontrol dokumen" tertulis. Yang diwajibkan adalah pengendaliannya; bentuknya bebas, termasuk alat elektronik [S6].
- Menyamakan awareness dengan pelatihan teknis [S2].
- Mengabaikan dokumen dari luar, misalnya panduan vendor atau teks regulasi yang dipakai tanpa catatan versi.
- Hanya mengendalikan perubahan yang direncanakan, lalu tidak punya mekanisme untuk mendeteksi perubahan yang tidak direncanakan.
- `[komunitas, belum terkonfirmasi]` Di forum Advisera, konsultan menyatakan format bukti awareness bebas [S5]. Klaim bahwa daftar hadir awareness "tidak wajib tetapi disarankan" beredar di artikel konsultan, tetapi belum dikonfirmasi sumber lain.

## 6. Catatan terkini

Bagian ini menampung detail edisi dan perubahan dari edisi 2013. Berguna saat memperbarui prosedur yang disusun untuk edisi lama.

- Per Oktober 2026, ISO/IEC 27001:2022 dengan Amd 1:2024 masih edisi berlaku, tanpa tahap revisi di katalog ISO [S9]. Amd 1:2024 (perubahan terkait iklim) hanya menyentuh klausul 4.1 dan 4.2, jadi klausul 7 dan 8 tetap seperti teks 2022.
- Di 7.4, edisi 2013 punya dua butir terakhir yang berbeda, yaitu siapa yang berkomunikasi dan proses komunikasinya; edisi 2022 menggabungkan keduanya menjadi butir "bagaimana" [S8]. Matriks komunikasi lama yang punya kolom "pengirim" tidak perlu dibuang.
- Di 8.1, butir kriteria proses baru eksplisit di 2022 [S8]. Butir pihak eksternal berasal dari Annex SL 2021, yang mengganti istilah "outsourced processes" dengan semua proses, produk, dan layanan dari pihak eksternal [S7]. Prosedur lama yang hanya membahas "outsourcing" perlu diperluas ke cloud, SaaS, dan kontraktor.
- ISO 10013:2021 menggantikan ISO/TR 10013:2001 sebagai panduan documented information di sistem manajemen mutu dan mengakui digitalisasi serta proteksi rekaman elektronik [S6]. Standar ini milik keluarga mutu, tetapi relevan karena struktur klausul 7.5 sama di semua standar berbasis Harmonized Structure.

## 7. Cheat sheet

```
7.1 Sumber daya  : orang, waktu, alat, anggaran (berkelanjutan). 24x7 = 168 jam/minggu per kursi
7.2 Kompetensi   : tentukan -> pastikan -> tindakan + NILAI EFEKTIVITAS -> simpan bukti (rekaman wajib)
                   berlaku juga untuk kontraktor/MSSP
7.3 Awareness    : kebijakan | kontribusi + manfaat | akibat tidak patuh   (!= pelatihan; Annex A 6.3)
                   diuji lewat wawancara; tidak perlu hafal kalimat kebijakan
7.4 Komunikasi   : apa | kapan | kepada siapa | bagaimana (2013: siapa + proses, kini digabung)
7.5.1 wajib + yang dianggap perlu (jumlah boleh beda per organisasi)
7.5.2 identitas (judul, tanggal, penulis, nomor) | format & media | tinjau & setujui
7.5.3 tersedia + terlindungi | distribusi, akses, pengambilan, pemakaian | simpan + tetap terbaca
      | pengendalian perubahan | retensi + pemusnahan | dokumen dari luar
      Annex A 5.33 records | 5.37 operating procedures
8.1 kriteria proses + kendalikan sesuai kriteria | info terdokumentasi secukupnya
    | perubahan terencana + TIDAK terencana | proses/produk/layanan pihak eksternal (5.19-5.23)
8.2 RA berkala + saat perubahan signifikan, pakai kriteria 6.1.2 a, simpan hasil
8.3 jalankan RTP, simpan hasil
6.3 perubahan ISMS  vs  8.32 perubahan teknis  -> pertimbangkan bersama
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** PT AN mengirim dua analyst L2 ke pelatihan threat hunting dan menyimpan sertifikat kehadiran mereka di folder HR. Apakah 7.2 untuk kompetensi hunting sudah terpenuhi?

<details><summary>Jawaban</summary>

Belum sepenuhnya. Sertifikat kehadiran memenuhi sebagian bukti, tetapi 7.2 c juga meminta organisasi menilai efektivitas tindakan yang diambil. Pelatihan baru terbukti efektif bila ada perubahan terukur, misalnya analyst itu menjalankan dua hunt terdokumentasi dalam tiga bulan berikutnya atau lulus penilaian praktik internal. Matriks kompetensi di bagian 2.1 punya kolom "Cara menilai efektivitas" untuk alasan ini. Lihat bagian 1.2 dan 2.1.

</details>

**2. Jelaskan ulang.** Manajer HR bertanya, "Kita sudah punya pelatihan teknis untuk SOC. Kenapa masih perlu program awareness?" Jelaskan dalam tiga kalimat, dengan satu contoh dari SOC.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Pelatihan teknis membangun keterampilan, misalnya cara menulis query atau menangani bukti, dan itu urusan kompetensi. Awareness memastikan setiap orang paham kebijakan keamanan, apa kontribusinya, dan apa akibatnya kalau tidak patuh, dan itu berlaku untuk semua karyawan, bukan hanya SOC. Analyst yang mahir query tetap perlu tahu bahwa ia tidak boleh menjawab pertanyaan wartawan soal insiden, dan itu pesan awareness, bukan materi pelatihan teknis."

Kesalahan yang sering muncul:
- Menganggap awareness berarti menghafal kalimat kebijakan. Yang diuji adalah pemahaman tanggung jawab, lewat wawancara.
- Menganggap awareness wajib berbentuk daftar hadir. 7.3 tidak mewajibkan informasi terdokumentasi; format buktinya bebas.
- Melupakan butir "akibat bila tidak patuh".

</details>

**3. Skenario keputusan.** Saat auditor meminta runbook brute force SSH, analyst menemukan dua versi: di wiki (v1.2) dan di repo git (v1.3). Apa langkah yang paling tepat setelah audit?

- A. Biarkan keduanya; analyst cukup memakai versi dengan nomor tertinggi.
- B. Tetapkan repo git sebagai satu-satunya lokasi resmi, ganti halaman wiki dengan tautan ke repo, dan catat lokasi resmi di header runbook.
- C. Hapus repo git karena wiki lebih mudah diakses analyst baru.

<details><summary>Jawaban</summary>

B. 7.5.3 meminta dokumen tersedia dalam versi yang layak dipakai dan perubahannya dikendalikan. Dua lokasi tanpa satu sumber resmi adalah temuan klasik (salinan tidak terkendali). Header runbook di bagian 2.3 punya baris "Lokasi resmi" untuk alasan ini. A keliru karena analyst bisa memakai versi lama tanpa sadar, dan tidak ada yang menjamin nomor tertinggi adalah versi yang disetujui. C keliru karena memindahkan masalah tanpa menyelesaikannya; repo git dengan pull request justru menyediakan bukti persetujuan dan riwayat. Lihat bagian 1.5, 2.3, dan 4.

</details>

**4. Skenario keputusan.** Update otomatis agent mengubah format log, dan tiga parser gagal selama sembilan jam tanpa ada yang sadar. Bagaimana kejadian ini dilihat dari sisi ISO 27001?

- A. Tidak relevan dengan ISO, karena bukan perubahan yang direncanakan dan tidak ada change request.
- B. Perubahan tidak direncanakan menurut 8.1: akibatnya ditinjau, dampaknya dimitigasi (rollback, uji parser sebelum update berikutnya), dan bila terulang atau berdampak besar menjadi nonconformity di 10.2.
- C. Cukup restart parser; selama log kembali masuk, tidak perlu catatan apa pun.

<details><summary>Jawaban</summary>

B. 8.1 tidak hanya meminta perubahan terencana dikendalikan, tetapi juga meminta akibat perubahan yang tidak direncanakan ditinjau dan dampak buruknya dimitigasi bila perlu. Monitoring kesehatan pipeline adalah cara SOC menyadari kejadian seperti ini. A keliru karena justru perubahan yang tidak direncanakan disebut eksplisit di 8.1. C keliru karena tidak ada tinjauan akibat (log sembilan jam yang hilang mungkin menyembunyikan insiden) dan tidak ada perubahan yang mencegah kejadian serupa. Lihat bagian 1.6 dan 2.4.

</details>

**5. Pertanyaan jebakan.** Kontrak PT AN dengan calon MSSP sudah memuat klausul keamanan dan SLA triage. Apakah itu cukup untuk memenuhi pengendalian pihak eksternal di 8.1?

<details><summary>Jawaban</summary>

Belum. Kontrak adalah awal pengendalian, tetapi 8.1 meminta layanan pihak eksternal yang relevan dengan ISMS ikut dikendalikan selama berjalan. Pengendalian yang wajar mencakup laporan kinerja bulanan dan evaluasi berkala, dan akuntabilitas tetap di PT AN. Selain itu, staf MSSP yang bekerja untuk ISMS ikut tercakup persyaratan kompetensi 7.2 karena bekerja di bawah kendali organisasi. Lihat bagian 1.2, 1.6, dan 2.4.

</details>

**6. Skenario keputusan.** Metodologi risiko PT AN menjadwalkan risk assessment setiap Januari. Migrasi sebagian log ke Wazuh selesai bulan Juni. Kapan risiko terkait migrasi seharusnya dinilai?

- A. Januari berikutnya, sesuai jadwal.
- B. Saat migrasi diusulkan, karena 8.2 meminta risk assessment juga dijalankan saat perubahan signifikan diusulkan atau terjadi, lalu hasilnya disimpan.
- C. Tidak perlu dinilai bila migrasi berjalan lancar.

<details><summary>Jawaban</summary>

B. 8.2 meminta risk assessment pada interval terencana dan juga saat perubahan signifikan diusulkan atau terjadi, memakai kriteria dari 6.1.2 a. Migrasi SIEM adalah contoh perubahan arsitektur yang menjadi pemicu di luar jadwal. A keliru karena risiko selama migrasi (misalnya celah logging saat cutover) sudah lewat sebelum Januari. C keliru karena penilaian dibutuhkan untuk merencanakan migrasi dengan aman, bukan setelah hasilnya diketahui. Lihat bagian 1.7.

</details>

**7. Interview question (English).** "An auditor asks you, a SOC analyst, to prove that the runbook you use is the current approved version. What do you show?"

<details><summary>Sample answer</summary>

"I'd open the runbook from its official location, which for us is the main branch of the runbook repository, and show the header: document ID, version, owner, approver, approval date, and next review date. Then I'd show the pull request where the approver reviewed and merged the latest change, and the change history that links the update to a corrective action. If anyone keeps copies elsewhere, the header states that those are uncontrolled, so the auditor can see we have a single source of truth."

What makes this answer strong: it covers identification, approval, change history, and the single official location, which is what clause 7.5.2 and 7.5.3 ask for, without claiming that a specific tool is required.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | DQS: Resources, competence, awareness, communication, ISO 27001 clauses 7.1-7.4 | https://www.dqsglobal.com/en/explore/blog/iso27001-resources-competence-awareness-communication-clauses-7-1-to-7-4 | sekunder (lembaga sertifikasi) | 2025-03-19; diakses 2026-10-08 | Sedang-tinggi. Isi 7.1-7.4 dan bukti yang dicari auditor |
| S2 | Advisera: ISO 27001 clause 7 support | https://advisera.com/iso27001/clause-7-support/ | sekunder (konsultan) | tanpa tanggal; diakses 2026-10-08 | Sedang. Bukti per subklausul, beda awareness dan pelatihan |
| S3 | HighTable: ISO 27001 clause 7.5.3 control of documented information | https://hightable.io/iso-27001-clause-7-5-3-control-of-documented-information-essential-guide | sekunder (konsultan) | diperbarui 2026-09-14; diakses 2026-10-08 | Sedang. Temuan audit umum |
| S4 | URM Consulting: ISO 27001 clause 8.1 effective ISMS operational planning and control | https://www.urmconsulting.com/blog/iso-27001-clause-8-1-effective-isms-operational-planning-and-control | sekunder (praktisi) | 2026-07-03; diakses 2026-10-08 | Sedang. Isi 8.1 dan 8.2, pengendalian pemasok dan perubahan |
| S5 | Advisera Expert Advice Community: Evidence of InfoSec awareness training | https://community.advisera.com/topic/evidence-of-infosec-awareness-training/ | komunitas (forum tanya-jawab) | 2022-08-09; diakses 2026-10-08 | Rendah-sedang. Opini satu konsultan |
| S6 | ISO/TC 176: Release of ISO 10013:2021, guidance for documented information | https://committee.iso.org/sites/tc176/home/news/content-left-area/news-and-updates/release-of-iso-100132021-quality.html | primer (situs komite ISO) | 2021-02-17; diakses 2026-10-08 | Tinggi untuk fakta rilis; standar keluarga mutu, dipakai sebagai pembanding |
| S7 | IAF news: New 2021 edition of Annex SL | https://iaf.news/2021/07/02/new-2021-edition-of-annex-sl-for-management-system-standards/ | sekunder (situs berita IAF) | 2021-07-02; diakses 2026-10-08 | Sedang-tinggi. Asal perubahan 8.1 |
| S8 | Cloud Security Alliance (A-LIGN): ISO 27001:2013 vs 2022 | https://cloudsecurityalliance.org/articles/what-s-the-difference-between-iso-27001-2013-and-iso-27001-2022 | sekunder | 2023-02-10; diakses 2026-10-10 | Sedang. Penggabungan butir d dan e di 7.4; kriteria proses di 8.1 |
| S9 | ISO committee: ISO/IEC 27001:2022 | https://committee.iso.org/standard/82875.html | primer (katalog ISO) | 2022-10-25; diakses 2026-10-10 | Tinggi untuk edisi, Amd 1:2024, dan status tanpa revisi |

**Catatan sumber:** butir 7.1-8.3 diparafrasekan dari struktur klausul yang stabil dan dicocokkan dengan ringkasan [S1][S2][S4][S8]. Klaim tentang format bukti awareness [S5] adalah opini satu konsultan. ISO 10013:2021 [S6] adalah panduan keluarga mutu, dipakai hanya sebagai pembanding.
