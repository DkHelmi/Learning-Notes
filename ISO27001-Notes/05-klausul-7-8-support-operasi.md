---
day: 05
title: 'Klausul 7-8: sumber daya, kompetensi, awareness, komunikasi, informasi terdokumentasi, dan operasi'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 27001:2022 + Amd 1:2024 (tanpa revisi di katalog ISO per Okt 2026); ISO 10013:2021 (panduan documented information, acuan pembanding); Harmonized Structure Annex SL 2021'
---

# Day 05: Klausul 7-8, support dan operasi

Cakupan: klausul 7.1-7.5 dan 8.1-8.3 ISO/IEC 27001:2022 dengan contoh penerapan di SOC, sementara kontrol Annex A terkait (6.3, 5.33, 5.37, 8.32, kelompok supplier) hanya disinggung karena detailnya di Day 08.

> Catatan pribadi, bukan materi resmi ISO, dan bukan nasihat hukum atau audit. Catatan ini hanya menyebut nomor dan judul singkat klausul dan kontrol, lalu menjelaskannya dengan kata-kata sendiri.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan apa yang diminta 7.1-7.4 dan bukti yang wajar untuk setiap subklausul di konteks SOC.
- membedakan awareness (7.3) dari kompetensi (7.2), serta menyusun matriks kompetensi analyst beserta cara menilai efektivitas pelatihan.
- menerapkan kontrol informasi terdokumentasi (7.5.2 dan 7.5.3) pada runbook, rule deteksi, dan laporan SOC.
- menjelaskan isi 8.1, termasuk kriteria proses, perubahan yang tidak direncanakan, dan pengendalian layanan pihak eksternal.
- membedakan 8.2/8.3 dari 6.1.2/6.1.3 dan menyebut pemicu risk assessment di luar jadwal.

## 2. Konteks singkat

Klausul 4-6 menghasilkan rencana. Klausul 7 menyediakan bahan bakarnya (orang, kompetensi, komunikasi, dokumen), dan klausul 8 membuktikan rencana itu dijalankan. Di audit, keduanya diuji lewat wawancara dan sampling: auditor bertanya ke analyst soal kebijakan, membuka satu runbook untuk melihat versi dan persetujuannya, lalu mencocokkan satu tiket insiden dengan langkah di runbook.

Kenapa SOC perlu peduli: banyak temuan audit di area ini lahir dari kebiasaan sehari-hari, misalnya runbook yang hanya ada di kepala analyst senior, wiki tanpa riwayat persetujuan, atau MSSP yang tidak pernah dievaluasi.

Kapan dipakai: setiap kali SOC menulis prosedur, merekrut atau melatih analyst, mengganti alat, atau memakai pihak ketiga.
Kapan tidak cukup: klausul 7-8 tidak menentukan isi teknis prosedur. Isi teknis datang dari kontrol yang dipilih (Day 08-12).

## 3. Konsep inti

### 3.1 Klausul 7.1: sumber daya

Organisasi menentukan dan menyediakan sumber daya untuk membangun, menjalankan, memelihara, dan meningkatkan ISMS. Sumber daya mencakup orang, waktu, alat, dan anggaran, dan pengelolaannya berlangsung terus, bukan sekali beli [S1]. Bukti yang wajar: persetujuan anggaran, rencana kapasitas, dan catatan pengadaan alat [S2].

Contoh hitungan kasar untuk SOC 24x7: satu kursi analyst yang selalu terisi membutuhkan 168 jam per minggu. Bila satu orang bekerja 40 jam per minggu, dibutuhkan 168 / 40 = 4,2 orang per kursi, belum termasuk cuti, sakit, dan pelatihan. Angka seperti ini membantu menunjukkan ke pimpinan (dan auditor) bahwa sumber daya dihitung, bukan ditebak.

### 3.2 Klausul 7.2: kompetensi

Organisasi harus [S1]:

- a. menentukan kompetensi yang dibutuhkan orang yang bekerja di bawah kendali organisasi dan pekerjaannya memengaruhi kinerja keamanan informasi;
- b. memastikan orang itu kompeten berdasarkan pendidikan, pelatihan, atau pengalaman;
- c. bila perlu, mengambil tindakan untuk memenuhi kompetensi dan menilai efektivitas tindakan itu. Catatan standar menyebut contoh tindakan: pelatihan, mentoring, rotasi tugas, merekrut, atau mengontrak orang yang kompeten;
- d. menyimpan bukti kompetensi sebagai informasi terdokumentasi.

Butir d adalah salah satu rekaman wajib (Day 02 bagian 3.5). Auditor mencari sertifikat, CV, catatan pelatihan, atau penilaian kinerja, bukan pernyataan "tim kami berpengalaman" [S1][S2]. Karena rumusannya "di bawah kendali organisasi", kontraktor dan staf MSSP yang bekerja untuk ISMS ikut tercakup [S1].

Bagian yang sering terlewat adalah menilai efektivitas. Mengirim analyst ke pelatihan threat hunting belum membuktikan apa pun. Buktinya adalah perubahan yang terukur, misalnya analyst itu menjalankan dua hunt terdokumentasi dalam tiga bulan berikutnya, atau lulus penilaian praktik internal.

### 3.3 Klausul 7.3: awareness

Semua orang yang bekerja di bawah kendali organisasi harus sadar akan tiga hal [S1]: (a) kebijakan keamanan informasi; (b) kontribusinya pada efektivitas ISMS, termasuk manfaat bila kinerja keamanan membaik; (c) akibat bila tidak mematuhi persyaratan ISMS.

Awareness membuat orang paham relevansi dan konsekuensi; pelatihan membangun keterampilan [S2]. Karyawan tidak perlu hafal kalimat kebijakan, tetapi harus bisa menjelaskan tanggung jawabnya, dan auditor mengujinya lewat wawancara [S1]. 7.3 tidak mewajibkan informasi terdokumentasi, jadi format buktinya bebas: sertifikat, daftar hadir, atau hasil kuis [S5].

Kontrol Annex A 6.3 (Information security awareness, education and training) adalah pasangan operasional 7.3: program awareness dan pelatihan yang terencana dan diperbarui.

### 3.4 Klausul 7.4: komunikasi

Organisasi menentukan kebutuhan komunikasi internal dan eksternal yang relevan dengan ISMS, mencakup (a) apa yang dikomunikasikan, (b) kapan, (c) kepada siapa, dan (d) bagaimana. Edisi 2013 punya dua butir terakhir yang berbeda, yaitu siapa yang berkomunikasi dan proses komunikasinya; edisi 2022 menggabungkan keduanya menjadi butir "bagaimana" [S8]. Kolom "pengirim" di matriks komunikasi tetap praktik baik walau tidak lagi disebut eksplisit. Bentuk yang praktis adalah matriks komunikasi per audiens [S2].

Untuk SOC, komunikasi yang paling sensitif adalah komunikasi insiden: kapan klien diberi tahu, siapa yang boleh berbicara ke media, dan jalur ke regulator. Itu semua harus konsisten dengan prosedur insiden (kontrol 5.24-5.26) dan kewajiban kontrak di register pihak berkepentingan (Day 03).

### 3.5 Klausul 7.5: informasi terdokumentasi

Klausul ini terdiri dari tiga subklausul:

| Subklausul | Isi (kata sendiri) | Contoh di SOC |
|---|---|---|
| 7.5.1 Umum | ISMS memuat (a) informasi yang diwajibkan standar dan (b) informasi yang dianggap perlu oleh organisasi. Luasnya boleh berbeda menurut ukuran dan jenis organisasi, kompleksitas proses, dan kompetensi orang | Runbook triage dianggap perlu karena turnover analyst tinggi |
| 7.5.2 Membuat dan memperbarui | (a) identitas dan deskripsi (judul, tanggal, penulis, nomor rujukan); (b) format (bahasa, versi perangkat lunak, grafik) dan media (kertas, elektronik); (c) tinjauan dan persetujuan atas kesesuaian dan kecukupan | Header runbook berisi ID, versi, pemilik, dan penyetuju |
| 7.5.3 Pengendalian | (a) tersedia dan layak dipakai saat dibutuhkan; (b) terlindungi dari bocor, salah pakai, dan kehilangan integritas. Yang diatur: (c) distribusi, akses, pengambilan, dan pemakaian; (d) penyimpanan dan preservasi, termasuk tetap terbaca; (e) pengendalian perubahan; (f) retensi dan pemusnahan. Dokumen dari luar yang diperlukan juga diidentifikasi dan dikendalikan | Wiki dengan hak akses per role (baca saja atau baca-ubah), riwayat versi, dan jadwal tinjau; panduan vendor SIEM disimpan sesuai versi yang dipakai |

Standar tidak mewajibkan bentuk tertentu. Panduan ISO 10013:2021 untuk sistem manajemen mutu menegaskan bahwa media elektronik boleh dipakai dengan berbagai cara dan manual dokumen tidak lagi wajib [S6]. Bagi SOC, repositori git dengan pull request dan review adalah bentuk pengendalian perubahan yang sah, asalkan persetujuan dan riwayatnya bisa ditunjukkan.

Temuan audit yang sering muncul di 7.5.3 [S3]:

- salinan kebijakan tidak terkendali di drive lokal, atau versi berbeda di intranet dan materi pelatihan;
- tanggal tinjau kosong atau kedaluwarsa, atau komentar draf tertinggal di versi terbit;
- hak akses berlebihan untuk karyawan yang sudah keluar;
- tidak ada bukti pemusnahan aman walaupun kebijakan retensinya ada.

Kontrol Annex A terkait: 5.33 Protection of records (rekaman dilindungi dari hilang, rusak, dan akses tidak sah) dan 5.37 Documented operating procedures (prosedur operasional tersedia bagi yang membutuhkan).

Log di SIEM juga bisa menjadi rekaman ISMS bila dipakai sebagai bukti, misalnya bukti monitoring (9.1) atau bukti insiden. Akibatnya, retensi dan proteksi integritas log ikut menjadi urusan 7.5.3, bukan hanya urusan kapasitas storage.

### 3.6 Klausul 8.1: perencanaan dan pengendalian operasional

8.1 meminta organisasi merencanakan, menjalankan, dan mengendalikan proses yang dibutuhkan untuk memenuhi persyaratan keamanan dan menjalankan tindakan dari klausul 6 (termasuk rencana sasaran 6.2). Caranya [S4]:

- menetapkan kriteria untuk proses itu, lalu mengendalikan proses sesuai kriterianya;
- menyediakan informasi terdokumentasi secukupnya untuk yakin proses berjalan sesuai rencana;
- mengendalikan perubahan yang direncanakan, meninjau akibat perubahan yang tidak direncanakan, dan memitigasi dampak buruknya bila perlu;
- memastikan proses, produk, atau layanan dari pihak eksternal yang relevan dengan ISMS ikut dikendalikan.

Butir kriteria proses baru eksplisit di 2022 [S8]. Butir pihak eksternal berasal dari Annex SL 2021, yang mengganti istilah "outsourced processes" dengan semua proses, produk, dan layanan dari pihak eksternal [S7]. Cakupannya lebih luas: platform cloud, SaaS, MSSP, dan kontraktor. Kontrol Annex A yang menjadi alat pelaksananya adalah 5.19-5.23 (pemasok dan cloud). URM menyarankan pengendalian pemasok lewat seleksi, evaluasi ulang berkala, dan pemantauan kinerja, menanam pengendalian di alat kerja yang sudah ada (ticketing, ERP) alih-alih proses paralel, serta mempertimbangkan 6.3 (perubahan ISMS) dan kontrol 8.32 (perubahan teknis) bersama [S4].

"Perubahan yang tidak direncanakan" sangat relevan untuk SOC: update otomatis agent mengubah format log, parser gagal, dan alert berhenti muncul. Monitoring kesehatan pipeline log adalah cara SOC menyadari kejadian seperti ini, meninjau akibatnya, dan bertindak.

### 3.7 Klausul 8.2 dan 8.3: menjalankan risk assessment dan treatment

8.2 meminta risk assessment dijalankan pada interval terencana, serta saat perubahan signifikan diusulkan atau terjadi, dengan memakai kriteria dari 6.1.2 a. Hasilnya wajib disimpan. 8.3 meminta risk treatment plan dijalankan dan hasil treatment disimpan [S4].

Pemicu di luar jadwal yang wajar untuk SOC:

- insiden besar yang menunjukkan skenario baru;
- perubahan arsitektur, misalnya migrasi SIEM atau pindah ke cloud;
- regulasi atau kontrak baru;
- temuan audit yang menunjukkan kontrol tidak efektif.

Bukti 8.2 yang lemah biasanya berupa risk register dengan tanggal tinjau terakhir dua tahun lalu, padahal ada migrasi besar tahun ini.

## 4. Contoh dokumen / artefak (organisasi fiktif)

Organisasi fiktif: PT Awan Nusantara (PT AN). Semua isi adalah ilustrasi.

### 4.1 Matriks kompetensi SOC (7.2)

| Kompetensi | L1 | L2 | L3/Lead | Bukti | Cara menilai efektivitas |
|---|---|---|---|---|---|
| Triage alert sesuai runbook | Wajib | Wajib | Wajib | Catatan onboarding, QA sampling tiket | Skor QA sampling minimal 90% |
| Query SIEM (SPL dan Wazuh) | Dasar | Mahir | Mahir | Pelatihan internal, tugas praktik | Lulus tugas praktik 5 query |
| Penanganan bukti dan chain of custody | Paham | Wajib | Wajib | Pelatihan DFIR internal | Audit sampel formulir chain of custody |
| Threat hunting berbasis hipotesis | - | Dasar | Mahir | Sertifikat atau laporan hunt | 2 laporan hunt per kuartal |
| Komunikasi insiden ke klien | - | Paham | Wajib | Simulasi tabletop | Hasil evaluasi tabletop |

Status per orang dicatat terpisah, misalnya "Analyst A: L1, lulus QA 93%, belum pelatihan chain of custody, target selesai Q3". Matriks menunjukkan apa yang dibutuhkan; catatan per orang menunjukkan siapa yang sudah memenuhi. Keduanya dibutuhkan untuk 7.2.

### 4.2 Matriks komunikasi (7.4)

| Apa | Kapan | Kepada siapa | Bagaimana | Pengirim |
|---|---|---|---|---|
| Ringkasan metrik SOC | Bulanan | Manajemen, ISMS Manager | Laporan + rapat | Lead SOC |
| Insiden yang memengaruhi layanan klien | Sesuai tenggat kontrak | Kontak keamanan klien | Email terenkripsi + telepon | Incident manager |
| Pemberitahuan kegagalan pelindungan data pribadi | Tertulis, paling lambat 3 x 24 jam (UU PDP Pasal 46, Day 10 bagian 3.6); titik mulai hitungan perlu dicek di teks resmi UU di JDIH | Lembaga PDP, subjek data | Kanal resmi | DPO dan Legal |
| Perubahan kebijakan keamanan | Saat terbit | Semua karyawan in-scope | Email + pengakuan baca | ISMS Manager |
| Peringatan phishing aktif | Saat terdeteksi | Semua karyawan | Pesan singkat internal | Analyst on-duty |
| Pertanyaan media soal insiden | Saat ada | Media | Hanya lewat juru bicara | Corporate communication |

Baris terakhir sering terlupa. Bila tidak ada aturan, analyst bisa saja menjawab pertanyaan wartawan lewat media sosial pribadi.

### 4.3 Header pengendalian dokumen untuk runbook (7.5.2 dan 7.5.3)

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

### 4.4 Pengendalian pihak eksternal dan perubahan tidak direncanakan (8.1)

| Pihak atau kejadian | Pengendalian | Bukti |
|---|---|---|
| MSSP untuk monitoring malam (opsi masa depan) | Klausul keamanan di kontrak, SLA triage, laporan bulanan, evaluasi tahunan | Kontrak, laporan SLA, notulen evaluasi |
| Penyedia SIEM cloud | Penilaian keamanan sebelum kontrak, tinjau laporan audit pihak ketiga tiap tahun | Kuesioner, laporan audit pemasok |
| Kejadian: update agent mengubah format log, 3 parser gagal selama 9 jam | Alert kesehatan pipeline, tinjauan pasca-kejadian, rollback, uji parser sebelum update berikutnya | Tiket, laporan tinjauan, perubahan prosedur update |

Kejadian di baris ketiga adalah contoh perubahan tidak direncanakan menurut 8.1. Bila terulang atau berdampak besar, kejadian itu juga menjadi nonconformity yang ditangani di 10.2.

## 5. Lab praktik

Latihan untuk organisasi fiktifmu. Simpan di `latihan/day05-<nama-org-fiktif>.md`.

1. Hitung kebutuhan orang untuk SOC fiktifmu: jumlah kursi yang harus terisi, jam operasi per minggu, dan asumsi jam kerja per orang. Tulis hasil hitungannya dan cek ulang.
2. Buat matriks kompetensi seperti bagian 4.1 untuk minimal 5 kompetensi. Setiap kompetensi punya kolom bukti dan cara menilai efektivitas.
3. Tulis rencana awareness untuk tiga audiens: semua karyawan, engineer, dan pimpinan. Untuk masing-masing tulis pesan inti, format, frekuensi, dan cara mengujinya.
4. Buat matriks komunikasi minimal 6 baris, termasuk satu baris media dan satu baris regulator.
5. Pilih satu runbook dari lab-mu (atau tulis runbook pendek untuk satu alert Wazuh atau Splunk). Tambahkan header pengendalian dokumen seperti bagian 4.3.
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

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Bukti kompetensi hanya berupa sertifikat kehadiran | Efektivitas tidak dinilai | Tambahkan penilaian praktik atau indikator kinerja setelah pelatihan |
| Analyst tidak bisa menjelaskan kebijakan saat ditanya | Awareness hanya berupa email sekali setahun | Ringkas kebijakan menjadi 5 poin; uji lewat kuis dan diskusi tim |
| Runbook di wiki berbeda dengan versi di git | Dua lokasi tanpa satu sumber resmi | Tetapkan satu lokasi resmi; lokasi lain hanya tautan |
| MSSP tidak pernah dievaluasi | Pengendalian pihak eksternal hanya di kontrak | Jadwalkan evaluasi berkala dan minta laporan kinerja |
| Risk register tidak diperbarui setelah migrasi besar | Risk assessment hanya tahunan | Tambahkan pemicu "perubahan signifikan" di metodologi risiko |

## 7. Kesalahan umum dan jebakan

- Menganggap 7.5 mewajibkan "prosedur kontrol dokumen" tertulis. Yang diwajibkan adalah pengendaliannya; bentuknya bebas, termasuk alat elektronik [S6].
- Menyamakan awareness dengan pelatihan teknis [S2].
- Mengabaikan dokumen dari luar, misalnya panduan vendor atau teks regulasi yang dipakai tanpa catatan versi.
- Hanya mengendalikan perubahan yang direncanakan, lalu tidak punya mekanisme untuk mendeteksi perubahan yang tidak direncanakan.
- `[komunitas, belum terkonfirmasi]` Di forum Advisera, konsultan menyatakan format bukti awareness bebas [S5]. Klaim bahwa daftar hadir awareness "tidak wajib tetapi disarankan" beredar di artikel konsultan, tetapi belum dikonfirmasi sumber lain.

## 8. Catatan terkini

- Per Oktober 2026, ISO/IEC 27001:2022 dengan Amd 1:2024 masih edisi berlaku, tanpa tahap revisi di katalog ISO [S9]. Amd 1:2024 (perubahan terkait iklim) hanya menyentuh klausul 4.1 dan 4.2, jadi klausul 7 dan 8 tetap seperti teks 2022.
- ISO 10013:2021 menggantikan ISO/TR 10013:2001 sebagai panduan documented information di sistem manajemen mutu dan mengakui digitalisasi serta proteksi rekaman elektronik [S6]. Standar ini milik keluarga mutu, tetapi relevan karena struktur klausul 7.5 sama di semua standar berbasis Harmonized Structure.

## 9. Cheat sheet

```
7.1 Sumber daya  : orang, waktu, alat, anggaran (berkelanjutan). 24x7 = 168 jam/minggu per kursi
7.2 Kompetensi   : tentukan -> pastikan -> tindakan + NILAI EFEKTIVITAS -> simpan bukti (rekaman wajib)
                   berlaku juga untuk kontraktor/MSSP
7.3 Awareness    : kebijakan | kontribusi + manfaat | akibat tidak patuh   (!= pelatihan; Annex A 6.3)
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

## 10. Sumber

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
