---
day: 15
title: 'Menjalankan audit internal: dari program sampai laporan, dari sisi auditor'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 27001:2022 + Amd 1:2024 klausul 9.2; ISO 19011:2026 (edisi 4, 27 Mei 2026; edisi 2018 withdrawn); ISO/IEC 27007:2020 (90.92, akan direvisi); ISO/IEC DIS 27007 (edisi 4, stage 40.60 per 2026-09-23); ISO/IEC 17021-1:2015'
---

# Day 15: Menjalankan audit internal

Cakupan: menyiapkan dan menjalankan audit internal dari kursi auditor, mulai dari persyaratan 9.2 dan program audit sampai laporan yang bisa ditindaklanjuti. Audit sertifikasi eksternal dan grading temuan oleh CB dibahas di Day 13; menutup temuan dibahas di Day 16.

## Ide inti

Audit internal yang berguna menghasilkan bukti, bukan kesan. Klausul 9.2 meminta program audit yang frekuensinya punya dasar, kriteria dan lingkup yang jelas untuk tiap audit, auditor yang objektif, dan laporan yang sampai ke manajemen yang bisa bertindak. Day 06 membahas 9.2 sebagai persyaratan dan Day 13 membahas rasanya diaudit. Day ini melihat dari kursi sebaliknya: kamu yang menjadi auditor internal.

Posisi ini sering jatuh ke orang teknis di organisasi kecil karena ia memahami sistemnya. Tanpa disiplin audit, hasilnya dua kegagalan khas: audit berubah menjadi sesi perbaikan teknis sehingga temuan tidak tercatat, atau menjadi pemeriksaan dokumen sehingga keadaan sebenarnya tidak tersentuh. Persyaratannya datang dari klausul 9.2 ISO/IEC 27001:2022 [S3][S4]. Cara mengauditnya mengikuti panduan ISO 19011 [S1] dan, khusus ISMS, ISO/IEC 27007 [S2][S5]. Kedua panduan itu tidak disertifikasi; yang diperiksa CB adalah apakah audit internalmu memenuhi 9.2.

Kamu sudah mengenal bentuk kecilnya: QA tiket di SOC. Jadwal QA bergilir oleh tim lain yang diprioritaskan berdasarkan risiko adalah program audit. Mengambil sampel tiket lalu mencocokkannya dengan runbook adalah pelaksanaan audit, dan selisih antara runbook dan tiket adalah finding. Cara auditor bekerja di lapangan juga mirip pivot investigasi: ambil satu kejadian nyata, lalu telusuri jejaknya sampai ceritanya utuh. Batasnya ada dua. Auditor tidak memperbaiki apa pun yang ditemukannya dan tidak menulis rekomendasi di temuannya. Auditor juga memakai sampel, sehingga satu benang yang putus menjadi temuan, bukan bukti bahwa seluruh ISMS gagal.

```
program audit (9.2.2: frekuensi dari risiko + hasil audit sebelumnya, alasan per baris)
  -> rencana satu audit (kriteria, lingkup, auditor objektif, aturan sampel)
  -> daftar periksa 3 lapis (ada aturannya? dijalankan? efektif?)
  -> wawancara + sampling + penelusuran satu kejadian nyata = bukti di kertas kerja
  -> temuan: pernyataan | bukti | kriteria (tanpa rekomendasi)
  -> laporan ke manajemen terkait (termasuk blok "tidak diperiksa")
  -> tindakan korektif oleh pemilik area (Day 16) -> masuk program berikutnya
```

Situasi yang dipakai sepanjang Day ini: program audit internal PT Awan Nusantara (PT AN, penyedia hosting fiktif) 2026-2027 menjadwalkan audit proses SOC pada Q1 2027 (Day 06 bagian 2.2). Kamu auditor internal dari tim GRC yang memegang audit itu, dimulai dari logging dan pemantauan. Awal Januari 2027, ISMS Manager mengirim pesan:

> "Ada empat hal sebelum kamu mulai audit logging bulan Februari. Pertama, auditor surveillance pasti bertanya kenapa program kita menaruh area ini di Q1; alasannya harus tertulis. Kedua, Lead SOC menawarkan diri ikut menilai karena paling paham platformnya. Ketiga, saya tidak mau laporan yang isinya hanya 'prosedur ada dan dijalankan'; saya perlu tahu apakah pemantauannya benar-benar efektif. Keempat, tim SOC pasti membantah kalau temuannya tidak jelas sampelnya dari mana. Laporannya saya bawa ke management review berikutnya."

Hal pertama dijawab isi 9.2 dan program audit (bagian 1.1 dan 1.2), hal kedua menyangkut prinsip audit dan objektivitas (bagian 1.3 dan 1.4), hal ketiga diuji dengan tiga pertanyaan berurutan dari kriteria (bagian 1.5), dan hal keempat bergantung pada wawancara, sampling, penulisan temuan, dan kertas kerja (bagian 1.6 sampai 1.9). Dokumen yang dihasilkan ada di bagian 2.

**Kapan relevan:** saat kamu ditunjuk menjadi auditor internal, menyusun program audit tahunan, atau menilai mutu audit internal sebelum surveillance.
**Kapan bukan jawaban:** Day ini tidak membahas cara menghadapi audit eksternal atau grading temuan oleh CB (Day 13), dan tidak membahas cara menutup temuan (Day 16).

## 1. Konsep inti

### 1.0 Istilah di Day ini

Tabel ini memuat istilah yang muncul di Day ini. Kolom padanan memakai analogi SOC yang sama di semua Day. Program audit, objektivitas dan imparsialitas, serta badan sertifikasi (CB) sudah dijelaskan di Day 01 dan Day 06; Day ini memakainya dari kursi auditor.

| Istilah | Arti singkat | Padanan di SOC |
|---|---|---|
| Kriteria audit | Persyaratan yang dipakai sebagai acuan pembanding: klausul, dokumen internal, kewajiban eksternal | Runbook yang dipakai untuk menilai tiket di QA |
| Lingkup audit | Batas apa yang termasuk dan tidak termasuk dalam satu audit | Daftar host dan log source yang masuk satu hunt |
| Rencana audit | Dokumen satu audit: kriteria, lingkup, auditor, jadwal, aturan sampel | Rencana hunt sebelum mulai |
| Daftar periksa tiga lapis | Pertanyaan per kriteria: ada aturannya, dijalankan, efektif | Rule ada di repo, rule aktif, rule terbukti menangkap serangan saat diuji |
| Prinsip audit | Tujuh prinsip ISO 19011 yang menjadi dasar sikap auditor | Kode etik analyst saat investigasi |
| Sampling acak, terarah, menyeluruh | Tiga cara memilih item yang diperiksa dari sebuah populasi | Sampel tiket QA acak, tiket P1 saja, atau semua tiket |
| Temuan | Pernyataan ketidaksesuaian yang ditopang bukti dan menunjuk kriteria | Finding QA |
| Observasi | Catatan di luar temuan: hal yang perlu diperhatikan atau hal positif | Catatan QA yang bukan pelanggaran SOP |
| Kertas kerja | Catatan auditor untuk menelusuri bagaimana kesimpulan diambil | Catatan kasus analyst: timeline, query, tangkapan layar |

### 1.1 Apa yang dituntut klausul 9.2

Hal pertama dari ISMS Manager, alasan program yang tertulis, berawal dari isi 9.2 itu sendiri. Sebelum menyusun apa pun, pahami dulu apa yang sebenarnya dituntut.

Klausul 9.2.1 meminta audit internal dijalankan pada interval terencana untuk memberi informasi apakah ISMS sesuai dengan persyaratan organisasi sendiri dan persyaratan standar, serta apakah ISMS diterapkan dan dipelihara secara efektif [S4].

Klausul 9.2.2 mengatur programnya. Tabel ini memecah 9.2.2 menjadi unsur yang bisa dicek satu per satu; kolom tengah menunjukkan wujud tiap unsur di dokumenmu, dan kolom kanan menunjuk bagian Day ini yang membahasnya [S4].

| Unsur 9.2.2 | Artinya dalam praktik | Dibahas di |
|---|---|---|
| Program audit dengan frekuensi, metode, tanggung jawab, persyaratan perencanaan, dan pelaporan | Satu dokumen program, bukan hanya kalender | 1.2, 2.1 |
| Program mempertimbangkan pentingnya proses dan hasil audit sebelumnya | Frekuensi punya dasar risiko dan riwayat temuan | 1.2 |
| Kriteria dan lingkup ditetapkan untuk tiap audit | Setiap audit punya rencana tertulis | 1.5, 2.2 |
| Auditor dipilih dan audit dijalankan sehingga objektif dan imparsial | Auditor tidak mengaudit pekerjaannya sendiri | 1.3, 1.4 |
| Hasil dilaporkan kepada manajemen terkait | Laporan sampai ke pemilik area dan manajemen yang bisa bertindak | 2.6 |
| Informasi terdokumentasi disimpan sebagai bukti program dan hasil audit | Program, rencana, kertas kerja, dan laporan diarsipkan | 1.9 |

Tiga hal sering salah dibaca. "Interval terencana" tidak berarti tiap klausul tiap tahun; program boleh bergulir asalkan seluruh lingkup tercakup dalam siklus. Persyaratan organisasi sendiri ikut menjadi kriteria. Dan 9.2 tidak mewajibkan auditor bersertifikat; yang dituntut objektivitas, imparsialitas, dan kompetensi yang bisa ditunjukkan (7.2).

### 1.2 Program audit, bukan daftar audit

Auditor surveillance akan bertanya kenapa audit logging PT AN ditaruh di Q1 2027, bukan di Q3. Jawabannya ada di program audit, bukan di kalender.

Program audit adalah rencana beberapa periode, biasanya satu siklus sertifikasi, yang memastikan seluruh lingkup tersentuh dengan frekuensi sesuai risikonya. Faktor di bawah adalah dasar frekuensi yang bisa dipertanggungjawabkan, turunan dari frasa "pentingnya proses dan hasil audit sebelumnya" di 9.2.2. Pakai tabel ini sebagai daftar alasan yang bisa ditulis di sebelah tiap baris program.

| Faktor | Pengaruh pada frekuensi |
|---|---|
| Risiko area terhadap sasaran ISMS | Risiko tinggi diaudit lebih sering |
| Hasil audit sebelumnya | Area dengan temuan sebelumnya diaudit lebih cepat |
| Perubahan besar | Sistem baru, pemasok baru, atau reorganisasi memicu audit tambahan |
| Insiden | Area yang terlibat insiden masuk ke jadwal berikutnya |
| Kewajiban eksternal | Area yang disorot regulator atau pelanggan |

Membagi klausul merata ke dua belas bulan tanpa alasan akan ditanyakan auditor eksternal. Catat satu kalimat alasan di sebelah tiap baris program. Di PT AN, audit proses SOC ditaruh di Q1 2027 karena tiga faktor sekaligus: risiko tinggi, insiden besar Q3 2026, dan sumber log baru yang belum pernah diaudit (bagian 2.1).

### 1.3 Prinsip audit menurut ISO 19011

Tawaran Lead SOC untuk ikut menilai menyentuh prinsip audit, bukan hanya aturan 9.2. Prinsip ini juga menjadi dasar cara bertanya, mengambil sampel, dan menulis laporan di subbagian berikutnya.

ISO 19011:2018 merumuskan tujuh prinsip audit [S7]:

1. **Integritas:** jujur, cermat, dan tidak mengubah temuan karena tekanan.
2. **Penyajian yang adil (fair presentation):** laporan mencerminkan keadaan sebenarnya, termasuk hambatan dan perbedaan pendapat yang belum selesai.
3. **Kecermatan profesional (due professional care):** memakai pertimbangan dan skeptisisme yang sepadan dengan pentingnya audit.
4. **Kerahasiaan:** informasi yang diperoleh selama audit dilindungi.
5. **Independensi:** bebas dari bias dan konflik kepentingan; sejauh praktis, auditor terpisah dari kegiatan yang diaudit.
6. **Pendekatan berbasis bukti:** kesimpulan bertumpu pada bukti yang bisa diverifikasi dari proses sampling yang sistematis.
7. **Pendekatan berbasis risiko:** perencanaan dan pelaksanaan audit difokuskan pada hal yang paling berpengaruh.

Daftar ini berasal dari edisi 2018; status rumusannya di edisi 2026 ada di bagian 6. Prinsip 5 dan 6 adalah dasar praktik di bagian 1.4, 1.6, dan 1.7. Prinsip 2 adalah alasan laporan memuat blok "tidak diperiksa" (bagian 2.6).

### 1.4 Objektivitas dalam organisasi kecil, dan batas peran badan sertifikasi

Lead SOC memang paling paham platform logging, tetapi ia juga yang mengelolanya. Di organisasi kecil, situasi ini selalu muncul: orang yang paham sistem adalah yang membangunnya.

Auditor tidak mengaudit pekerjaannya sendiri. Tiga jalan keluar yang biasa dipakai:

- **Pertukaran antar fungsi.** Orang infrastruktur mengaudit area aplikasi dan sebaliknya, dengan pendamping yang paham areanya.
- **Auditor dari luar yang bukan badan sertifikasi.** Konsultan atau auditor independen boleh menjalankan audit internal.
- **Audit berpasangan.** Satu orang memahami area dan satu menjaga disiplin audit, dengan pembagian peran tertulis.

Yang tidak boleh adalah badan sertifikasi (CB) yang menyertifikasimu menjalankan audit internalmu. ISO/IEC 17021-1:2015 klausul 5.2.6 melarang CB menawarkan audit internal kepada klien yang disertifikasinya; konsensus badan akreditasi Eropa menambahkan bahwa CB boleh mengaudit internal organisasi lain, tetapi perlu jeda sekitar dua tahun sebelum menyertifikasinya [S6]. Alasannya imparsialitas: CB akan menilai hasil kerjanya sendiri saat audit sertifikasi. Klausul 5.2 yang sama juga melarang CB memberi konsultasi sistem manajemen.

Apa pun pengaturannya, tuliskan di rencana audit beserta siapa yang menyetujuinya. Itu bukti langsung untuk tuntutan objektivitas dan imparsialitas di 9.2.2. Di PT AN, jawabannya untuk Lead SOC tertulis di baris Independensi rencana audit (bagian 2.2): auditor dari tim GRC yang menilai, dan orang yang paham area hanya mendampingi.

### 1.5 Dari kriteria ke pertanyaan

Hal ketiga ISMS Manager, laporan yang tidak berhenti di "prosedur ada dan dijalankan", dijawab dengan cara menurunkan kriteria menjadi pertanyaan.

9.2.2 meminta kriteria dan lingkup ditetapkan untuk tiap audit. Kriteria audit internal ISMS biasanya tiga lapis:

1. Persyaratan standar, yaitu klausul yang berlaku.
2. Dokumen internal organisasi, yaitu kebijakan dan prosedur yang kamu tetapkan sendiri.
3. Kewajiban eksternal yang relevan, misalnya kontrak dan regulasi.

Lapis kedua sering menghasilkan temuan paling banyak, karena organisasi menuliskan prosedur yang lebih ketat daripada yang dijalankan. Karena 9.2.1 menyebut persyaratan organisasi sendiri, ketidaksesuaian terhadap prosedur internal tetap nonconformity.

Untuk setiap kriteria, tanyakan tiga hal berurutan. Urutan ini mengikuti dua tuntutan 9.2.1: sesuai persyaratan, lalu diterapkan dan dipelihara secara efektif.

```
1. Apakah ada aturannya?        -> periksa dokumen
2. Apakah dijalankan?           -> minta bukti pelaksanaan
3. Apakah berjalan efektif?     -> periksa hasilnya, bukan hanya pelaksanaannya
```

Polanya sama dengan menilai satu detection rule: apakah rule-nya ada di repo, apakah rule itu aktif di SIEM, dan apakah rule itu benar-benar menangkap serangan saat diuji. Rule yang aktif tetapi tidak pernah memicu alert saat simulasi serangan bukan bukti deteksi bekerja. Batas analogi ini: lapis ketiga audit tidak selalu bisa diuji dengan simulasi, sehingga auditor sering menilai efektivitas dari hasil nyata, misalnya rekaman pencabutan hak atau log tertua yang benar-benar tersimpan.

Pertanyaan ketiga yang membedakan auditor yang baik. Tinjauan hak akses yang rutin dijalankan tetapi tidak pernah menghasilkan pencabutan hak adalah bukti yang perlu dipertanyakan, bukan yang menenangkan.

### 1.6 Wawancara yang menghasilkan bukti

Analyst SOC PT AN yang diwawancarai kemungkinan akan menjawab "ya, kami meninjau alert setiap hari". Jawaban itu belum bukti.

Prinsip pendekatan berbasis bukti berarti jawaban lisan belum menjadi bukti sampai ditunjukkan rekamannya. Kesalahan paling umum adalah bertanya dengan cara yang jawabannya ya atau tidak. Tabel ini mengganti pertanyaan ya atau tidak dengan permintaan yang memaksa bukti muncul; perhatikan kata kerja di kolom kanan.

| Alih-alih | Tanyakan |
|---|---|
| Apakah kalian meninjau hak akses? | Tunjukkan tinjauan hak akses terakhir dan hasilnya |
| Apakah log dipantau? | Siapa yang memeriksa alert kemarin pagi, dan apa yang dilakukannya |
| Apakah ada prosedur insiden? | Ceritakan insiden terakhir dan tunjukkan jejaknya |
| Apakah backup diuji? | Kapan terakhir pemulihan diuji dan apa hasilnya |

Teknik paling produktif: minta satu kejadian nyata yang baru, lalu telusuri jejaknya dari awal sampai akhir. Penelusuran satu kasus mengungkap lebih banyak daripada memeriksa sepuluh dokumen. Ini pivot investigasi yang sama dengan yang kamu lakukan dari satu alert ke proxy, EDR, dan AD.

Tiga aturan sikap: catat apa yang dikatakan dan oleh siapa; jangan memperbaiki apa pun selama audit karena itu mengubah bukti; dan jangan berdebat, karena tugasmu mengumpulkan bukti, bukan meyakinkan.

### 1.7 Sampling yang bisa dijelaskan

Hal keempat, "sampelnya dari mana", adalah bantahan paling umum terhadap temuan. Bantahan itu hanya bisa dijawab bila cara memilih sampel tercatat sebelum hasilnya diketahui.

Day 13 bagian 1.3 menjelaskan dua pendekatan sampling di ISO 19011: berbasis pertimbangan dan statistik. Dari kursi auditor internal, yang penting metodenya bisa dijelaskan dan diulang. Tabel ini membandingkan tiga cara yang dipakai dalam praktik; kolom Kelemahan menunjukkan batas kesimpulan yang boleh kamu tarik dari masing-masing.

| Cara | Kapan dipakai | Kelemahan |
|---|---|---|
| Acak (statistik) | Ingin memperkirakan keadaan populasi | Bisa melewatkan kasus penting |
| Terarah (berbasis pertimbangan) | Ingin memeriksa kasus berisiko tinggi | Tidak bisa dipakai menyimpulkan populasi |
| Menyeluruh | Populasi kecil | Mahal pada populasi besar |

Yang harus kamu tulis di kertas kerja: ukuran populasi, jumlah sampel, cara pemilihan, dan alasan. Tanpa keempatnya, temuanmu bisa dibantah dengan mengatakan sampelnya kebetulan buruk.

Tidak ada angka sampel baku untuk audit internal di 27001 maupun 19011. Tetapkan aturanmu secara tertulis, pakai konsisten, dan sebutkan bahwa itu aturan internal.

### 1.8 Menulis temuan

Temuan audit logging akan dibaca Lead SOC, yang paham platformnya lebih baik daripada auditor. Temuan itu harus bisa diterima tanpa debat soal apa yang sebenarnya dilihat auditor.

Temuan yang baik memisahkan tiga hal. "Pernyataan" di sini sama dengan "kondisi" di Day 13.

```
PERNYATAAN : apa yang tidak sesuai, dalam satu kalimat
BUKTI      : apa yang kamu lihat, dengan identitas dan tanggal
KRITERIA   : klausul atau dokumen internal yang dilanggar
```

Yang sering salah adalah mencampurkan rekomendasi ke dalam temuan. Tugas auditor menyatakan apa yang tidak sesuai; menentukan cara memperbaikinya adalah tugas pemilik area, dan auditor yang menentukan perbaikan kehilangan independensinya untuk memeriksa perbaikan itu nanti.

Catat juga hal yang baik; observasi positif membuat laporan lebih jujur dan lebih mau dibaca.

### 1.9 Kertas kerja

Bila tim SOC membantah temuan sebulan setelah audit, yang menjawab adalah kertas kerja, bukan ingatan auditor.

Kertas kerja memungkinkan orang lain menelusuri bagaimana kamu sampai pada kesimpulan. Isinya: siapa yang diwawancarai dan kapan, dokumen apa yang diperiksa dengan versinya, sampel apa yang diambil dan bagaimana dipilih, apa yang dilihat, dan kesimpulan per kriteria.

Simpan terpisah dari laporan. Laporan untuk pembaca, kertas kerja untuk penelusuran. Di SOC, bedanya seperti catatan kasus analyst (timeline, query, tangkapan layar) dan laporan insiden untuk manajemen. Bersama program, rencana, dan laporan, kertas kerja adalah informasi terdokumentasi yang diminta 9.2.2 sebagai bukti program dan hasil audit, dan auditor eksternal kadang memintanya untuk menilai mutu audit internalmu.

## 2. Contoh dokumen / artefak (organisasi fiktif)

Organisasi fiktif: PT Awan Nusantara (PT AN). Angka, nama, nomor prosedur, dan aturan sampel di bawah adalah aturan internal fiktif, bukan persyaratan standar. Artefak ini adalah program yang menaungi audit logging Q1 2027 dan dokumen yang dihasilkan auditor GRC selama audit itu.

### 2.1 Program audit internal dengan alasan

Jawaban untuk hal pertama ISMS Manager: program yang alasannya tertulis per baris. Program ini memperluas cuplikan di Day 06 bagian 2.2 dengan kolom kriteria dan metode, serta audit tambahan yang tidak tampak di cuplikan itu.

Kolom program memuat unsur 9.2.2: frekuensi, metode, tanggung jawab, dan dasar pemilihan. Aturan perencanaan dan pelaporan ditulis di pengantar program: tiap audit punya rencana tertulis (bentuk bagian 2.2), dan laporannya dikirim ke pemilik area serta ISMS Manager dalam 10 hari kerja.

| Periode | Area | Kriteria utama | Metode | Auditor | Alasan pemilihan |
|---|---|---|---|---|---|
| 2026 Q4 | Klausul 4-6, SoA, risk register | Klausul 4 sampai 6; SoA | Tinjauan dokumen, wawancara pimpinan | Konsultan eksternal | Persiapan surveillance; risk register berubah setelah migrasi |
| 2026 Q4 | Manajemen akses | 5.15, 5.18, prosedur AKS-01 | Sampling tiket akses, wawancara | Tim GRC | Dua temuan minor pada audit sebelumnya belum terverifikasi efektif |
| 2027 Q1 | Proses SOC: logging, pemantauan, respons insiden | 9.1; 5.24 sampai 5.28; 8.15 sampai 8.17; prosedur LOG-02 | Penelusuran alert dan satu insiden, cek konfigurasi | Tim GRC (bukan Lead SOC atau analyst SOC) | Risiko R-04 dan R-09 tinggi; insiden besar Q3 2026; sumber log baru ditambahkan pada Q3 2026 dan belum pernah diaudit |
| 2027 Q2 | Klausul 7, kontrol people dan physical | Klausul 7; tema People dan Physical | Tinjauan rekaman, wawancara | Tim GRC (bukan HR untuk kontrol people) | Tidak diaudit tahun lalu |
| 2027 Q3 | Klausul 8 | Klausul 8 | Tinjauan dokumen, wawancara | Tim GRC | Seluruh klausul harus tercakup dalam siklus; persiapan surveillance |
| 2027 Q3 | Klausul 9-10, termasuk 9.2 (proses audit internal itu sendiri); kontrol pemasok | 9.1 sampai 10.2; 5.19 sampai 5.23 | Tinjauan program dan laporan audit, tinjauan kontrak, wawancara | Konsultan eksternal | Rencana MSSP dan dua pemasok baru dengan akses jaringan; temuan management review; tim GRC tidak boleh mengaudit pekerjaannya sendiri |
| 2027 Q4 | Kelangsungan dan pemulihan | 5.29, 5.30 | Observasi uji pemulihan | Fungsi infrastruktur | Belum pernah diuji sejak sistem dipindahkan ke cloud |

Kolom alasan yang membuat program ini bisa dipertahankan; tanpanya tabel di atas hanya jadwal. Baris audit atas klausul 9.2 sering terlupa: proses audit internal juga harus diaudit, dan pelakunya tidak boleh tim yang menjalankannya.

### 2.2 Rencana audit satu area

Rencana untuk audit logging Februari 2027, satu bagian dari baris proses SOC Q1 2027 di program. Baris Independensi menjawab tawaran Lead SOC, dan blok aturan sampel menyiapkan jawaban untuk hal keempat.

```
RENCANA AUDIT INTERNAL                     Nomor: AI-2027-01
Area        : Logging dan pemantauan
Tanggal     : 11 sampai 12 Februari 2027
Auditor     : <nama>, tim GRC, tidak terlibat dalam pengelolaan platform logging
Pendamping  : <nama>, memahami area tetapi tidak menilai
Independensi: auditor berasal dari tim GRC; Lead SOC dan analyst SOC tidak ikut menilai;
              pengaturan ini disetujui oleh <jabatan>
Pelaporan   : laporan ke Lead SOC dan ISMS Manager paling lambat 10 hari kerja setelah rapat penutup

KRITERIA
  ISO/IEC 27001:2022 klausul 9.1; Annex A 8.15 dan 8.16
  Prosedur internal LOG-02 versi 3.1
  Kontrak pelanggan X pasal retensi log

LINGKUP
  Termasuk : platform SIEM, sumber log produksi, proses peninjauan alert harian
  Tidak termasuk : sistem pengembangan, log aplikasi pihak ketiga yang tidak terintegrasi

JADWAL
  Hari 1 pagi  : pembukaan, tinjauan dokumen
  Hari 1 siang : wawancara pengelola platform, pengambilan sampel
  Hari 2 pagi  : wawancara analyst, penelusuran satu alert nyata
  Hari 2 siang : verifikasi bukti, rapat penutup

ATURAN SAMPEL (internal)
  alert : 10 dari populasi 30 hari terakhir, acak, ditambah 3 terarah pada alert berprioritas tinggi
  sumber log : seluruh sumber yang ditambahkan setelah 1 Juli 2026
```

### 2.3 Daftar periksa yang berlapis tiga

Daftar periksa ini menurunkan kriteria di rencana bagian 2.2 menjadi tiga lapis pertanyaan dari bagian 1.5. Kolom ketiga adalah jawaban untuk hal ketiga ISMS Manager; cari di sana apa yang membedakan "dijalankan" dari "efektif".

| Kriteria | 1. Ada aturannya? | 2. Dijalankan? | 3. Efektif? |
|---|---|---|---|
| Sumber log yang wajib dikumpulkan ditetapkan | LOG-02 pasal 4 | Daftar sumber aktual vs daftar wajib | Ada sumber wajib yang tidak mengirim sejak kapan |
| Alert ditinjau setiap hari kerja | LOG-02 pasal 7 | Catatan peninjauan 30 hari terakhir | Berapa alert yang ditutup tanpa catatan alasan |
| Jam sistem diselaraskan | LOG-02 pasal 5 | Konfigurasi sumber waktu | Selisih waktu antar sumber pada satu kejadian nyata |
| Retensi sesuai kontrak | Kontrak pelanggan X | Konfigurasi retensi | Log tertua yang benar-benar ada |

Kolom ketiga yang membedakan audit ini dari pemeriksaan dokumen. Dua baris terakhir memakai teknik Day 11: memeriksa keadaan nyata, bukan konfigurasi yang diklaim.

### 2.4 Catatan wawancara

Catatan wawancara dengan analyst SOC di hari kedua, memakai pola permintaan bukti dari bagian 1.6.

```
WAWANCARA                                   AI-2027-01 / W-03
Tanggal   : 12 Februari 2027, 09:10 sampai 09:55
Narasumber: <nama>, analyst SOC
Auditor   : <nama>

PERTANYAAN DAN JAWABAN (ringkas, bukan transkrip)
  Q: Tunjukkan alert yang kamu tangani kemarin pagi dan ceritakan langkahnya.
  A: Menunjukkan tiket #4412. Alert login tidak lazim. Diperiksa, ditutup sebagai false positive.
  Catatan auditor: tiket tidak memuat alasan penutupan; hanya status.

  Q: Kalau alert ini benar, apa langkah berikutnya?
  A: Eskalasi ke lead, lalu ikuti IR-01.
  Catatan auditor: jawaban sesuai prosedur; tidak diverifikasi karena tidak ada kasus nyata.

BUKTI YANG DIAMBIL
  tangkapan layar tiket #4412 (disimpan di kertas kerja, bukan di laporan)
  daftar 10 tiket sampel dengan kolom alasan penutupan
```

Catatan auditor dipisahkan dari jawaban narasumber, dan satu jawaban ditandai tidak terverifikasi, bukan diterima begitu saja. Kejujuran semacam itu yang membuat kertas kerja bernilai.

### 2.5 Temuan dengan tiga bagian terpisah

Temuan ini lahir dari sampel acak di rencana bagian 2.2 dan wawancara di bagian 2.4. Bukti yang menyebut periode, jumlah, dan nomor tiket membuat bantahan "sampelnya kebetulan buruk" sulit dipertahankan.

```
TEMUAN AI-2027-01 / T-01                            Klasifikasi: minor

PERNYATAAN
  Penutupan alert tidak selalu disertai alasan, sehingga peninjauan ulang tidak dimungkinkan.

BUKTI
  Dari 10 tiket sampel acak periode 13 Januari sampai 11 Februari 2027, 6 ditutup tanpa
  catatan alasan (tiket #4380, #4391, #4402, #4412, #4418, #4425).
  Diperiksa pada 12 Februari 2027 bersama <nama>.

KRITERIA
  Prosedur internal LOG-02 versi 3.1 pasal 7.3 mewajibkan alasan penutupan dicatat.

ALASAN KLASIFIKASI
  Alert tetap ditinjau dan ditangani; yang hilang adalah rekaman alasannya. Kemampuan ISMS
  mencapai hasilnya belum terganggu, sehingga minor. Bila pola yang sama ditemukan di area lain,
  pertimbangkan major karena menunjukkan kegagalan sistemik (Day 13 bagian 1.4).

CATATAN
  Tidak ada rekomendasi perbaikan di sini; penentuan tindakan adalah tanggung jawab pemilik area
  dan akan dicatat di lembar tindakan korektif (Day 16).
```

Baris catatan terakhir melindungi independensimu saat memverifikasi perbaikannya nanti.

### 2.6 Ringkasan laporan audit

Laporan ini yang dibawa ISMS Manager ke management review berikutnya. Blok terakhirnya menerapkan prinsip penyajian yang adil.

```
LAPORAN AUDIT INTERNAL                      AI-2027-01
Area, tanggal, auditor, kriteria, lingkup   : (lihat rencana)
Dikirim kepada                              : Lead SOC, ISMS Manager (9.2.2: manajemen terkait)

KESIMPULAN
  ISMS pada area ini secara umum berjalan sesuai kriteria, dengan 1 temuan minor
  dan 2 observasi. Tidak ditemukan major nonconformity.

TEMUAN
  T-01 minor : penutupan alert tanpa alasan tercatat

OBSERVASI
  O-01 : dua sumber log yang ditambahkan Juli 2026 belum masuk daftar sumber wajib di LOG-02,
         walaupun sudah dikumpulkan; dokumen tertinggal dari praktik
  O-02 : peninjauan harian dilakukan konsisten termasuk pada hari libur nasional (positif)

CAKUPAN SAMPEL
  alert   : 13 dari sekitar 240 (10 acak, 3 terarah)
  sumber  : 4 dari 4 sumber baru (menyeluruh)

TIDAK DIPERIKSA
  log aplikasi pihak ketiga yang tidak terintegrasi (di luar lingkup; dicatat untuk program berikutnya)
```

Blok terakhir sering dihilangkan. Menyatakan apa yang tidak diperiksa (prinsip penyajian yang adil) mencegah laporan dibaca sebagai jaminan menyeluruh.

## 3. Lab praktik

**Prasyarat:** dokumen fiktif dari Day sebelumnya, terutama hasil Day 06, Day 09, dan Day 11. Seluruh lab bersifat menulis dan melatih wawancara dengan rekan.

1. Susun program audit internal satu siklus untuk PT AN memakai bentuk bagian 2.1. Cocokkan dengan tabel 9.2.2 di bagian 1.1: apakah frekuensi, metode, tanggung jawab, perencanaan, dan pelaporan semuanya tertulis, dan apakah seluruh klausul 4-10 serta kontrol di SoA tercakup dalam siklus?
2. Tulis pengaturan objektivitas untuk organisasi dengan delapan orang di tim TI, termasuk siapa yang mengaudit proses audit internal itu sendiri, lalu minta rekan menilai apakah pengaturan itu akan diterima auditor eksternal.
3. Susun rencana audit satu area memakai bentuk bagian 2.2, lengkap dengan aturan sampel internal dan alasannya.
4. Buat daftar periksa berlapis tiga bagian 2.3 untuk area yang sama, minimal delapan baris, dan pastikan kolom ketiga benar-benar menguji efektivitas, bukan pelaksanaan.
5. Latih wawancara dengan rekan yang berperan sebagai pemilik area. Pakai pola pertanyaan bagian 1.6, dan catat hasilnya dalam bentuk bagian 2.4.
6. Tinjau catatan wawancaramu: tandai mana yang bukti dan mana yang pernyataan lisan tanpa bukti. Hitung perbandingannya.
7. Ambil sampel dari populasi fiktif memakai ketiga cara di bagian 1.7, lalu tulis bagaimana kesimpulan yang bisa kamu tarik berbeda untuk masing-masing.
8. Tulis tiga temuan memakai bentuk bagian 2.5, lalu periksa apakah ada rekomendasi yang tercampur ke dalamnya dan buang bila ada.
9. Susun laporan ringkas bagian 2.6, termasuk blok tidak diperiksa.
10. Minta rekan membaca laporanmu dan menandai kalimat yang bisa dibantah karena buktinya tidak cukup. Perbaiki kalimat itu.

**Hasil yang sebaiknya tersimpan:**
- Program audit satu siklus dengan alasan per baris dan cek kelengkapan unsur 9.2.2.
- Pengaturan objektivitas beserta penilaian rekan.
- Rencana audit, daftar periksa tiga lapis, dan catatan wawancara untuk satu area.
- Rasio bukti terhadap pernyataan lisan, dan perbandingan kesimpulan dari tiga cara sampling.
- Tiga temuan tanpa rekomendasi dan laporan ringkas dengan blok tidak diperiksa.
- Daftar kalimat yang diperbaiki setelah ditinjau rekan.

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Semua jawaban ya tetapi tidak ada bukti | Pertanyaan berbentuk ya atau tidak | Pakai pola bagian 1.6; minta tunjukkan, bukan jelaskan |
| Temuan dibantah dengan alasan sampel buruk | Metode sampling tidak tercatat | Tulis populasi, jumlah, cara, dan alasan di kertas kerja |
| Objektivitas dipertanyakan | Auditor mengaudit areanya sendiri | Pakai salah satu pengaturan di bagian 1.4 dan tuliskan |
| CB menawarkan audit internal sekaligus sertifikasi | Tidak paham batas imparsialitas | Tolak; pakai auditor internal atau konsultan yang bukan bagian CB (bagian 1.4) |
| Dokumen tertinggal dari praktik tidak terdeteksi | Hanya memeriksa dokumen, bukan keadaan nyata | Bandingkan daftar di dokumen dengan keadaan sistem |

## 5. Kesalahan umum dan jebakan

- Membagi klausul merata ke dalam setahun tanpa dasar risiko atau alasan tertulis.
- Mengaudit area yang kamu kelola sendiri, atau tidak pernah mengaudit proses audit internal itu sendiri.
- Meminta badan sertifikasi yang sama menjalankan audit internal.
- Menerima penjelasan lisan sebagai bukti, atau memperbaiki masalah selama audit berlangsung.
- Mencampurkan rekomendasi ke dalam pernyataan temuan.
- Hanya menguji keberadaan aturan dan pelaksanaannya, tanpa menguji efektivitasnya. Audit internal yang tidak pernah menemukan apa pun biasanya tanda lapis ini terlewat, dan auditor eksternal mengenali pola itu.
- Laporan tidak sampai ke manajemen yang bisa bertindak, sehingga tuntutan pelaporan 9.2.2 tidak terpenuhi.

## 6. Catatan terkini

Bagian ini menampung status edisi panduan audit dan standar yang mengatur badan sertifikasi. Berguna saat memilih rujukan atau meninjau templat dan materi pelatihan lama.

- Daftar tujuh prinsip di bagian 1.3 berasal dari ISO 19011:2018 [S7]. Edisi 2026 tetap memuat bagian prinsip audit [S1]. Ringkasan pihak ketiga menyebut fondasi prinsipnya pada dasarnya tidak berubah dan penekanan pada risiko diperkuat [S8]. Rumusan persis tiap prinsip di edisi 2026, termasuk kalimat tentang independensi auditor internal, perlu dicek di teks standarnya.
- ISO 19011:2026 (edisi 4) terbit 27 Mei 2026 dan edisi 2018 berstatus withdrawn [S1]. Tidak ada masa transisi karena 19011 adalah panduan, tetapi templat dan materi pelatihan yang masih merujuk edisi 2018 sebaiknya ditinjau.
- ISO/IEC 27007:2020 berada di stage 90.92 (diputuskan untuk direvisi) setelah systematic review 2025 [S2]. Penggantinya, ISO/IEC DIS 27007 (edisi 4), menutup pemungutan suara DIS pada 23 September 2026 (stage 40.60) [S5]. Pantau terbitnya; isinya kemungkinan menyesuaikan 19011:2026.
- ISO/IEC 17021-1:2015, sumber larangan audit internal oleh CB, sedang dalam systematic review (Day 13 bagian 6).

## 7. Cheat sheet

```
9.2.1  interval terencana; sesuai persyaratan SENDIRI + standar; diterapkan dan dipelihara efektif
9.2.2  program: frekuensi | metode | tanggung jawab | perencanaan | pelaporan
       pertimbangkan pentingnya proses + hasil audit sebelumnya
       tiap audit: kriteria + lingkup | auditor objektif dan imparsial | lapor ke manajemen terkait
       simpan bukti program dan hasil
19011:2018 prinsip: integritas | penyajian adil | kecermatan profesional | kerahasiaan
                    independensi | berbasis bukti | berbasis risiko

PROGRAM AUDIT (lebih dari jadwal)
  dasar frekuensi: RISIKO area | hasil audit sebelumnya | perubahan besar | insiden | kewajiban eksternal
  TULIS ALASAN di sebelah tiap baris; tanpa itu, auditor eksternal akan mempertanyakannya
  membagi klausul merata tanpa alasan = memenuhi di atas kertas saja

INDEPENDENSI (organisasi kecil)
  pertukaran antar fungsi | auditor luar yang BUKAN badan sertifikasimu | audit berpasangan
  CB dilarang audit internal klien yang disertifikasinya (17021-1 5.2.6; jeda 2 tahun)
  proses audit internal juga diaudit, oleh pihak lain
  TULISKAN pengaturannya di rencana audit; jawaban lisan tidak cukup

KRITERIA 3 LAPIS  persyaratan standar | DOKUMEN INTERNAL SENDIRI | kewajiban eksternal
  lapis kedua sering paling banyak menghasilkan temuan (prosedur lebih ketat dari praktik)

TIGA PERTANYAAN BERURUTAN
  1 ada aturannya?  -> dokumen
  2 dijalankan?     -> bukti pelaksanaan
  3 EFEKTIF?        -> hasilnya, bukan pelaksanaannya
  audit yang selalu bersih = lapis 3 tidak diuji

WAWANCARA  jangan tanya ya/tidak; minta "TUNJUKKAN", bukan "jelaskan"
  teknik terbaik: ambil SATU kejadian nyata yang baru, telusuri dari awal sampai akhir
  catat siapa yang bicara | JANGAN memperbaiki selama audit | jangan berdebat

SAMPLING  acak (perkirakan populasi) | terarah (kasus berisiko) | menyeluruh (populasi kecil)
  WAJIB dicatat: ukuran populasi, jumlah sampel, cara pemilihan, ALASAN
  tidak ada angka baku yang berlaku umum; tetapkan aturan internal dan konsisten

TEMUAN  pisahkan: PERNYATAAN | BUKTI (identitas + tanggal) | KRITERIA
  JANGAN masukkan rekomendasi; itu tugas pemilik area, dan mencampurnya merusak independensimu
  catat juga observasi POSITIF

LAPORAN  selalu sertakan blok APA YANG TIDAK DIPERIKSA
         kertas kerja DIPISAH dari laporan; auditor eksternal kadang memintanya
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Program audit internal sebuah organisasi membagi klausul 4-10 dan tema Annex A merata ke dua belas bulan, satu area per bulan, sehingga seluruh lingkup tercakup dalam setahun. Apakah program itu sudah memenuhi 9.2.2?

<details><summary>Jawaban</summary>

Belum tentu. Cakupan penuh memang dibutuhkan, tetapi 9.2.2 juga meminta program mempertimbangkan pentingnya proses dan hasil audit sebelumnya. Pembagian merata tanpa alasan akan ditanyakan auditor eksternal. Dasar frekuensi yang bisa dipertanggungjawabkan adalah risiko area, hasil audit sebelumnya, perubahan besar, insiden, dan kewajiban eksternal, dan alasannya ditulis satu kalimat di sebelah tiap baris program. "Interval terencana" juga tidak berarti tiap klausul tiap tahun; program boleh bergulir asalkan seluruh lingkup tercakup dalam siklus. Lihat bagian 1.1, 1.2, dan 2.1.

</details>

**2. Skenario keputusan.** Lead SOC PT AN menawarkan diri menilai di audit logging karena paling paham platformnya. Apa tanggapan yang tepat?

- A. Terima, karena kompetensi teknis adalah syarat utama auditor.
- B. Tolak sebagai penilai. Auditor dari tim GRC yang menilai, orang yang paham area boleh mendampingi tanpa menilai, dan pengaturannya ditulis di rencana audit beserta penyetujunya.
- C. Terima, asalkan auditor GRC ikut menandatangani laporan.

<details><summary>Jawaban</summary>

B. Lead SOC mengelola platform logging, dan auditor tidak mengaudit pekerjaannya sendiri. Rencana AI-2027-01 menulis pengaturan ini di baris Independensi, yang menjadi bukti langsung untuk tuntutan objektivitas dan imparsialitas di 9.2.2. A keliru karena 9.2 menuntut objektivitas dan imparsialitas, bukan hanya kompetensi; 9.2 bahkan tidak mewajibkan auditor bersertifikat. C keliru karena tanda tangan auditor GRC tidak mengubah fakta bahwa penilaiannya dibuat oleh pengelola area itu sendiri. Lihat bagian 1.4 dan 2.2.

</details>

**3. Pertanyaan jebakan.** Di audit manajemen akses, auditor menemukan tinjauan hak akses dijalankan setiap kuartal sesuai prosedur dan semua rekamannya lengkap. Tinjauan itu tidak pernah menghasilkan satu pun pencabutan hak. Auditor menulis kesimpulan "kontrol efektif". Tepatkah?

<details><summary>Jawaban</summary>

Belum. Rekaman yang lengkap baru menjawab dua pertanyaan pertama: aturannya ada dan dijalankan. Pertanyaan ketiga memeriksa hasilnya, bukan pelaksanaannya. Tinjauan yang rutin tetapi tidak pernah menghasilkan pencabutan hak adalah bukti yang perlu dipertanyakan, bukan yang menenangkan. Audit internal yang tidak pernah menemukan apa pun biasanya tanda lapis ketiga ini terlewat, dan auditor eksternal mengenali pola itu. Lihat bagian 1.5 dan 5.

</details>

**4. Skenario keputusan.** Untuk menguji penutupan alert di SOC PT AN, auditor menghadapi populasi alert 30 hari terakhir. Cara mana yang paling bisa dipertahankan?

- A. Pilih 10 tiket yang judulnya paling mencurigakan. Bila 6 di antaranya tanpa alasan penutupan, tulis bahwa 60% penutupan alert di SOC bermasalah.
- B. Ambil 10 tiket secara acak ditambah 3 terarah pada alert berprioritas tinggi, lalu catat ukuran populasi, jumlah sampel, cara pemilihan, dan alasannya di kertas kerja.
- C. Pakai angka sampel baku dari ISO 19011 supaya temuan tidak bisa dibantah.

<details><summary>Jawaban</summary>

B. Ini aturan sampel di rencana AI-2027-01, dan keempat unsur yang dicatat membuat temuan tidak bisa dibantah dengan "sampelnya kebetulan buruk". A keliru karena sampel terarah tidak bisa dipakai menyimpulkan keadaan populasi, dan cara pemilihannya tidak tercatat. Perkiraan tentang populasi hanya bisa ditarik dari sampel acak; itu sebabnya bukti di temuan T-01 menyebut "6 dari 10 tiket sampel acak". C keliru karena tidak ada angka sampel baku untuk audit internal di 27001 maupun 19011; aturan ditetapkan tertulis, dipakai konsisten, dan disebut sebagai aturan internal. Lihat bagian 1.7, 2.2, dan 2.5.

</details>

**5. Pertanyaan jebakan.** Draf temuan seorang auditor berbunyi: "Alert ditutup tanpa alasan. SOC harus menjadikan field alasan penutupan wajib diisi di sistem tiket." Apakah ini temuan yang baik?

<details><summary>Jawaban</summary>

Tidak. Pertama, rekomendasi tercampur ke dalam temuan. Menentukan cara memperbaiki adalah tugas pemilik area, dan auditor yang menentukan perbaikan kehilangan independensinya untuk memeriksa perbaikan itu nanti. Kedua, tidak ada bukti dengan identitas dan tanggal, misalnya nomor tiket, periode, dan jumlah sampel. Ketiga, tidak ada kriteria, yaitu klausul atau dokumen internal yang dilanggar. Bandingkan dengan temuan T-01, yang memisahkan pernyataan, bukti, dan kriteria (LOG-02 versi 3.1 pasal 7.3) dan menyerahkan tindakan ke lembar tindakan korektif. Lihat bagian 1.8 dan 2.5.

</details>

**6. Jelaskan ulang.** Lead SOC keberatan dengan draf laporan: "Kenapa ada blok 'tidak diperiksa'? Audit jadi terlihat tidak lengkap. Dan kenapa tangkapan layar serta catatan wawancaranya tidak dilampirkan di laporan?" Jelaskan dalam tiga kalimat.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Blok 'tidak diperiksa' menerapkan prinsip penyajian yang adil: tanpa blok itu, laporan bisa dibaca sebagai jaminan bahwa seluruh area sudah bersih, padahal log aplikasi pihak ketiga memang di luar lingkup. Tangkapan layar dan catatan wawancara disimpan di kertas kerja, karena laporan ditulis untuk pembaca yang perlu bertindak, sedangkan kertas kerja untuk siapa pun yang perlu menelusuri bagaimana kesimpulan diambil. Kertas kerja itu tetap diarsipkan bersama program, rencana, dan laporan sebagai bukti 9.2.2, dan auditor eksternal kadang memintanya."

Kesalahan yang sering muncul:
- Menganggap blok "tidak diperiksa" sebagai kelemahan audit yang sebaiknya disembunyikan.
- Menjawab bahwa kertas kerja rahasia dan tidak perlu disimpan, padahal kertas kerja termasuk informasi terdokumentasi yang diminta 9.2.2.
- Melampirkan semua bukti mentah ke laporan sehingga kesimpulannya tenggelam.

</details>

**7. Interview question (English).** "You've been asked to run an internal audit of the SOC's logging and monitoring. How would you approach it?"

<details><summary>Sample answer</summary>

"First I check that the audit sits in a risk-based programme, so the timing has a written reason, and that I'm not auditing my own work; if someone from the SOC knows the platform best, they can accompany me but they don't judge. Then I write a plan with criteria in three layers: the 27001 clauses and Annex A controls such as 8.15 and 8.16, our internal logging procedure, and contractual retention requirements. For each criterion I ask three questions: is there a rule, is it followed, and is it effective. For example, I compare the required log sources against what is actually sending, and check the oldest log we really hold. In interviews I ask people to show me records instead of explaining, and I trace one recent real alert end to end. I record the population, sample size, selection method and reason, so the findings hold up. Each finding separates statement, evidence and criteria, with no recommendations, and the report goes to the area owner and management with a clear section on what was not examined."

What makes this answer strong: it covers independence, risk-based planning, three-layer criteria, testing effectiveness rather than existence, evidence-based interviewing, defensible sampling, and a report that is honest about its limits.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | ISO committee: ISO 19011:2026 Guidelines for auditing management systems | https://committee.iso.org/standard/88984.html | primer (katalog ISO) | 2026-05-27; diakses 2026-10-10 | Tinggi untuk edisi dan status; edisi 2018 withdrawn |
| S2 | ISO committee: ISO/IEC 27007:2020 Guidelines for ISMS auditing | https://committee.iso.org/standard/77802.html | primer (katalog ISO) | 2020-01-21; diakses 2026-10-10 | Tinggi. Stage 90.92 sejak 2025-06-10 |
| S3 | ISO committee: ISO/IEC 27001:2022 | https://committee.iso.org/standard/82875.html | primer (katalog ISO) | Oktober 2022; diakses 2026-10-10 | Tinggi untuk edisi dan status |
| S4 | Hicomply: ISO 27001 clause 9.2 internal audit (2022) | https://hicomply.com/hub/iso-27001-clause-9-2-internal-audit-2022 | sekunder (vendor) | 2026-07-15; diakses 2026-10-10 | Sedang. Ringkasan isi 9.2.1 dan 9.2.2, konsisten dengan Day 06 |
| S5 | ISO committee: ISO/IEC DIS 27007 | https://committee.iso.org/standard/92416.html | primer (katalog ISO) | stage 40.60 pada 2026-09-23; diakses 2026-10-10 | Tinggi untuk status draf |
| S6 | European Accreditation FAQ: Question CW2017 3 (ISO/IEC 17021-1:2015 klausul 5.2.6) | https://european-accreditation.org/?p=43180 | primer (konsensus badan akreditasi) | jawaban Maret 2018; diakses 2026-10-10 | Tinggi. Larangan audit internal oleh CB, jeda 2 tahun |
| S7 | Open Exam Prep: ISO 19011 audit principles and framework | https://open-exam-prep.com/study-guides/iso-27001-lead-auditor/fundamental-audit-concepts-and-principles/iso-19011-audit-principles-and-framework | sekunder (materi studi) | diakses 2026-10-10 | Sedang. Tujuh prinsip ISO 19011:2018 |
| S8 | TRECCERT: ISO 19011:2026 is here | https://treccert.com/iso-19011-2026-is-here-what-the-new-standard-means-for-management-system-auditing/ | sekunder (lembaga sertifikasi) | 2026-05-28; diakses 2026-10-10 | Rendah-sedang. Ringkasan perubahan; tidak merinci prinsip |

**Catatan sumber:** isi 9.2.1 dan 9.2.2 diparafrasekan dari ringkasan sekunder [S4] yang cocok dengan Day 06, bukan dari teks standar. Daftar tujuh prinsip berasal dari edisi 2018 [S7]; rumusan prinsip di edisi 2026 belum dicocokkan dengan teks standar. Larangan konsultasi oleh CB (17021-1 klausul 5.2) belum punya sumber terbuka terpisah. Praktik wawancara, daftar periksa tiga lapis, dan format kertas kerja adalah praktik audit umum yang disusun sendiri. Seluruh nomor prosedur, tiket, temuan, dan aturan sampel di bagian 2 adalah fiktif.
