---
day: 03
title: 'Klausul 4-5: konteks, scope, pihak berkepentingan, kepemimpinan, kebijakan, dan peran'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 27001:2022 + Amd 1:2024 (Climate action changes, terbit 23 Feb 2024); SNI ISO/IEC 27001:2022/Amd.1:2024 (BSN, 2024); IAF-ISO Joint Communique 22 Feb 2024 dan IAF TC Final Decision; UU No. 27 Tahun 2022'
---

# Day 03: Klausul 4-5, konteks organisasi dan kepemimpinan

Cakupan: klausul 4.1-4.4 dan 5.1-5.3 ISO/IEC 27001:2022 termasuk Amd 1:2024 sebagai fondasi ISMS (kondisi, tuntutan, batas, dan kendali), cara auditor menilai keputusan perubahan iklim, serta hubungannya dengan kontrol organisasi di Annex A (5.1-5.4, 5.31).

## Ide inti

Sebelum menilai risiko atau memilih kontrol, organisasi harus menjawab empat pertanyaan dasar: dalam kondisi apa ISMS ini berjalan, siapa yang punya tuntutan terhadapnya, sampai mana batasnya, dan siapa yang memegang kendali. Klausul 4 menjawab tiga pertanyaan pertama (konteks, pihak berkepentingan, scope). Klausul 5 menjawab yang keempat (komitmen pimpinan, kebijakan, peran). Kalau fondasi ini salah, risiko yang dinilai tidak relevan, kontrol tidak menjawab kebutuhan klien, dan sertifikat tidak mencakup layanan yang dibeli orang.

Kamu sudah mengenal pola ini dari onboarding klien baru di SOC atau MSSP. Sebelum menulis satu detection pun, kalian menyepakati lingkungan dan ancaman klien, apa yang mereka tuntut (SLA, format dan tenggat laporan), aset dan log source mana yang dimonitor, dan siapa kontak eskalasi yang berwenang memutuskan saat insiden. SOC yang melompati onboarding akan memonitor hal yang salah dan tidak tahu harus menghubungi siapa jam dua pagi.

Peta klausul di Day ini:

```
4.1 isu internal dan eksternal ----+
                                   +--> 4.3 scope (+ interface, dependency) --> risiko (klausul 6)
4.2 pihak berkepentingan       ----+
    dan persyaratannya
4.4 ISMS sebagai kumpulan proses yang saling terhubung

5.1 komitmen pimpinan | 5.2 kebijakan | 5.3 peran dan wewenang  --> memayungi semuanya
```

Situasi yang dipakai sepanjang Day ini: bank yang di Day 01 meminta sertifikat ISO 27001 kini masuk tahap due diligence dan mengirim kuesioner keamanan ke PT Awan Nusantara (PT AN, penyedia hosting fiktif). Empat pertanyaan di kuesioner itu menyentuh SOC:

> 1. Isu apa yang kalian anggap memengaruhi keamanan layanan, termasuk regulasi data pribadi dan risiko iklim terhadap data center?
> 2. Bagaimana kewajiban pelaporan insiden kepada kami dan kepada otoritas ditangani?
> 3. Apakah layanan managed VM, data center, dan SOC termasuk scope ISMS? Pihak ketiga apa yang kalian andalkan?
> 4. Lampirkan kebijakan keamanan informasi kalian. Siapa yang berwenang menyatakan insiden mayor?

Lead SOC memintamu menyiapkan draf jawaban. Setiap pertanyaan ternyata menunjuk satu klausul: pertanyaan 1 ke 4.1, pertanyaan 2 ke 4.2, pertanyaan 3 ke 4.3, dan pertanyaan 4 ke 5.2 dan 5.3.

**Kapan relevan:** organisasi memulai ISMS, scope diperluas, ada regulasi atau kontrak baru, setiap management review, dan saat menjawab kuesioner keamanan klien.
**Kapan bukan jawaban:** klausul 4-5 tidak menentukan kontrol apa yang dipilih. Pilihan kontrol adalah hasil risk assessment (Day 04).

## 1. Konsep inti

### 1.0 Istilah di Day ini

Tabel ini memuat istilah yang muncul di Day ini. Kolom padanan memakai analogi SOC yang sama di semua Day. Istilah dari Day 01-02 tidak diulang, kecuali pihak berkepentingan karena menjadi pokok Day ini.

| Istilah | Arti singkat | Padanan di SOC |
|---|---|---|
| Konteks organisasi | Kondisi internal dan eksternal yang memengaruhi kemampuan ISMS mencapai hasilnya | Lingkungan dan ancaman klien yang dicatat saat onboarding |
| Isu internal dan eksternal | Hal di dalam organisasi (SDM, perubahan sistem) dan di luar (hukum, ancaman, lingkungan) yang relevan dengan ISMS | Faktor yang memengaruhi prioritas monitoring |
| PESTLE dan SWOT | Alat bantu menyusun isu: politik, ekonomi, sosial, teknologi, legal, lingkungan; serta kekuatan, kelemahan, peluang, ancaman | Template kuesioner onboarding |
| Pihak berkepentingan | Pihak yang punya kebutuhan atau harapan terhadap ISMS: klien, regulator, pemasok, karyawan, investor | Stakeholder yang menuntut laporan dari SOC |
| Persyaratan pihak berkepentingan | Tuntutan pihak itu, termasuk persyaratan hukum, regulasi, dan kontrak | SLA dan kewajiban pelaporan di kontrak klien |
| Interface | Titik pertemuan antara yang di dalam dan di luar scope | Titik tempat traffic atau log menyeberang batas monitoring |
| Dependency | Hal di luar scope yang tetap dibutuhkan ISMS | Layanan luar yang dibutuhkan SOC: SIEM SaaS, colocation |
| Top management | Orang atau kelompok yang mengarahkan dan mengendalikan organisasi di level tertinggi | Sponsor eksekutif SOC |
| Kebijakan keamanan informasi (5.2) | Kebijakan tingkat atas: arah, kerangka sasaran, dan komitmen | Piagam SOC |
| Kebijakan topik khusus (kontrol 5.1) | Kebijakan per topik: logging, insiden, kontrol akses | SOP dan standar teknis SOC |
| RACI | Alat bantu pembagian peran: responsible, accountable, consulted, informed | Matriks eskalasi SOC |
| Segregation of duties | Pemisahan tugas yang bertentangan supaya satu orang tidak bisa melakukan dan menyetujui sendiri | Four-eyes untuk menonaktifkan rule |
| Amd 1:2024 (Climate action changes) | Amandemen 27001:2022 yang menambah pertimbangan perubahan iklim di 4.1 dan 4.2 | Patch kecil pada SOP, tanpa perlu menulis ulang |
| Catatan (Note) | Teks informatif di standar; mengingatkan, tetapi bukan persyaratan tambahan | Komentar di rule: menjelaskan, tidak mengubah logika |

### 1.1 Klausul 4.1: isu internal dan eksternal

Pertanyaan 1 di kuesioner bank meminta daftar isu. Bank ingin tahu apakah PT AN sadar akan kondisi yang bisa memengaruhi layanan, bukan hanya punya firewall.

Persyaratannya: organisasi menentukan isu internal dan eksternal yang relevan dengan tujuannya dan memengaruhi kemampuan ISMS mencapai hasil yang diinginkan. Formatnya bebas; banyak organisasi memakai PESTLE untuk isu eksternal dan SWOT untuk internal [S7], tetapi keduanya alat bantu, bukan persyaratan.

Tabel berikut berisi contoh isu untuk perusahaan hosting. Perhatikan kolom terakhir: isu baru berguna kalau jelas pengaruhnya ke ISMS.

| Jenis | Contoh | Kenapa relevan untuk ISMS |
|---|---|---|
| Eksternal, legal | UU No. 27 Tahun 2022 tentang Pelindungan Data Pribadi, berlaku 17 Oktober 2022 [S9] | Pengendali data wajib memberi tahu subjek data dan lembaga secara tertulis paling lambat 3 x 24 jam bila terjadi kegagalan pelindungan data pribadi (Pasal 46 ayat 1; detail di Day 10 bagian 1.6) |
| Eksternal, teknologi | Serangan ransomware ke penyedia hosting meningkat | Memengaruhi prioritas risiko dan kebutuhan deteksi |
| Eksternal, lingkungan | Banjir musiman di Jakarta | Memengaruhi ketersediaan data center |
| Internal | Turnover analyst SOC tinggi | Memengaruhi kompetensi (7.2) dan konsistensi triage |
| Internal | Migrasi sebagian log dari Splunk ke Wazuh karena biaya lisensi | Perubahan ISMS yang harus direncanakan (6.3) |

Sejak Amd 1:2024, di akhir 4.1 ada satu kalimat persyaratan tambahan tentang perubahan iklim. Isinya dan cara auditor menilainya dibahas di bagian 1.3.

### 1.2 Klausul 4.2: pihak berkepentingan dan persyaratannya

Pertanyaan 2 di kuesioner menyangkut dua pihak sekaligus: bank sebagai klien (tenggat laporan insiden di kontrak) dan otoritas pelindungan data (kewajiban UU PDP). Keduanya pihak berkepentingan, dan tuntutan mereka adalah persyaratan yang harus dicatat.

4.2 meminta organisasi menentukan tiga hal:

1. pihak berkepentingan yang relevan dengan ISMS;
2. persyaratan relevan dari pihak-pihak itu (bisa berupa persyaratan hukum, regulasi, dan kontrak);
3. persyaratan mana yang akan ditangani lewat ISMS. Butir ketiga ini baru di edisi 2022 [S4], diturunkan dari Annex SL 2021 [S3].

Butir ketiga mengakui bahwa tidak semua persyaratan pihak berkepentingan urusan ISMS. Klien mungkin menuntut harga murah atau SLA uptime 99,9%; uptime terkait availability, tetapi target bisnisnya diatur di luar ISMS. Register yang baik menuliskan keputusan itu supaya auditor tidak menganggapnya terlewat. Mirip dokumen onboarding SOC yang mencatat "permintaan monitoring kinerja aplikasi: di luar layanan SOC", supaya tidak ada yang menganggapnya lupa.

### 1.3 Perubahan iklim: keputusan yang harus bisa ditunjukkan

Pertanyaan 1 di kuesioner juga menyebut risiko iklim terhadap data center. Bank menanyakannya karena sejak 2024 ISO 27001 secara eksplisit meminta organisasi mempertimbangkan perubahan iklim.

**Apa yang ditambahkan Amd 1:2024.** Ada dua tambahan [S1][S10]:

- Di akhir 4.1 ditambahkan satu kalimat persyaratan: organisasi menentukan apakah perubahan iklim merupakan isu yang relevan. Kata kuncinya "menentukan apakah". Organisasi boleh menyimpulkan perubahan iklim tidak relevan, tetapi keputusan itu harus diambil dengan sadar dan bisa ditunjukkan.
- Di akhir 4.2 ditambahkan catatan baru (Note 2, di SNI "Catatan 2") yang menyebut pihak berkepentingan yang relevan bisa punya persyaratan terkait perubahan iklim [S1]. Catatan di standar ISO bersifat informatif, bukan persyaratan tambahan; fungsinya mengingatkan agar persyaratan semacam itu ikut dipertimbangkan.

**Cara auditor menilainya.** IAF dan ISO menerbitkan komunike bersama, disertai keputusan Technical Committee IAF yang menjelaskan dampaknya bagi organisasi, lembaga sertifikasi (CB), dan badan akreditasi [S2]. Isinya:

- Maksud persyaratan 4.1 dan 4.2 tidak berubah, karena isu internal dan eksternal sejak awal sudah harus dipertimbangkan. Amandemen diperlakukan sebagai klarifikasi, sehingga tidak ada program transisi penuh.
- Organisasi tersertifikasi menentukan apakah perubahan iklim relevan, dan bila relevan memasukkannya ke evaluasi risiko di dalam scope tiap sistem manajemen yang dimiliki.
- CB memastikan perubahan iklim sudah dipertimbangkan. Bila relevan, CB memastikan isu itu masuk ke sasaran dan tindakan mitigasi bila diperlukan. Bila organisasi menyimpulkan tidak relevan, CB menilai efektivitas proses pengambilan keputusan itu.
- Badan akreditasi memastikan CB memeriksa hal ini dalam siklus akreditasi rutin.
- Sejak amandemen terbit, CB memasukkan teks baru ke audit konteks, dan bila organisasi tidak bisa menunjukkan pertimbangan itu, auditor menerbitkan temuan yang sesuai.
- Sertifikat tidak perlu diterbitkan ulang, karena tahun terbit standar dan scope sertifikasi tidak berubah.

Konflik sumber: satu artikel konsultan menulis bahwa tidak mencantumkan perubahan iklim "otomatis" menjadi minor nonconformity [S7]. Dokumen IAF hanya menyebut temuan yang sesuai, tanpa menetapkan tingkatnya [S2]. Catatan ini mengikuti sumber primer: tingkat temuan bergantung pada penilaian auditor.

**Relevansinya untuk SOC.** Perubahan iklim relevan bila memengaruhi ketersediaan data center (banjir, panas ekstrem yang membebani pendingin) atau bila klien menanyakannya dalam kuesioner keamanan, seperti bank di situasi Day ini. Dampaknya biasanya masuk ke risiko availability dan kontrol kontinuitas, bukan ke deteksi.

### 1.4 Klausul 4.3: scope ISMS

Pertanyaan 3 di kuesioner adalah pertanyaan scope: apakah managed VM, data center, dan SOC termasuk, dan pihak ketiga apa yang diandalkan. Padanannya di SOC adalah daftar aset dan log source yang masuk monitoring, tetapi scope ISMS ditetapkan formal dan tercantum di sertifikat.

Saat menentukan scope, organisasi mempertimbangkan isu dari 4.1, persyaratan dari 4.2, serta interface dan dependency antara aktivitas yang dijalankan sendiri dan yang dijalankan pihak lain [S5]. Scope wajib tersedia sebagai informasi terdokumentasi.

Dua istilah itu sering tertukar:

- **Interface:** titik pertemuan antara yang di dalam dan di luar scope. Contoh: koneksi VPN dari kantor cabang (di luar scope) ke jaringan manajemen (di dalam scope). Di SOC, ini titik tempat traffic atau log menyeberang batas monitoring.
- **Dependency:** hal di luar scope yang tetap dibutuhkan ISMS. Contoh: penyedia colocation yang mengurus listrik dan pendingin, atau penyedia SIEM berbasis cloud.

Scope yang baik biasanya menyebut batas organisasi (unit, tim), batas fisik (lokasi), batas teknologi (jaringan, platform), layanan atau proses yang dicakup, dan pengecualian beserta alasannya [S5]. Scope sebaiknya dikelola sebagai dokumen hidup dengan versi dan persetujuan, bukan dibuat ulang setiap menjelang audit [S5].

Untuk SOC: bila SOC di luar scope, bukti kontrol logging dan monitoring harus datang dari pihak yang tidak diaudit. Lebih mudah memasukkan SOC ke scope, atau memperlakukannya sebagai dependency dengan perjanjian layanan yang jelas.

### 1.5 Klausul 4.4: ISMS sebagai kumpulan proses

Scope menjawab "sampai mana". 4.4 menjawab "apa isinya": organisasi membangun, menerapkan, memelihara, dan terus meningkatkan ISMS, dan sejak 2022 secara eksplisit termasuk proses yang dibutuhkan beserta interaksinya [S4]. Bukti yang wajar adalah peta proses (Day 02 bagian 1.3): proses yang ada, pemiliknya, serta input dan output masing-masing.

### 1.6 Klausul 5.1: kepemimpinan dan komitmen

Kuesioner bank tidak bertanya langsung soal komitmen pimpinan, tetapi auditor pasti menanyakannya. Padanannya di SOC adalah sponsor eksekutif: orang yang menyetujui anggaran, headcount, dan retensi log. Bedanya, di ISMS komitmen itu harus terlihat lewat bukti, bukan hanya tanda tangan.

Top management harus menunjukkan kepemimpinan, bukan hanya menandatangani kebijakan. Butir a sampai h di 5.1 [S6]:

- memastikan kebijakan dan sasaran keamanan ditetapkan dan selaras dengan arah strategis;
- mengintegrasikan persyaratan ISMS ke proses bisnis;
- menyediakan sumber daya;
- mengomunikasikan pentingnya manajemen keamanan informasi yang efektif dan kepatuhan pada persyaratan ISMS;
- memastikan ISMS mencapai hasil yang diinginkan;
- mengarahkan dan mendukung orang yang berkontribusi;
- mendorong perbaikan berkelanjutan;
- mendukung manajer lain menjalankan kepemimpinan di area masing-masing.

Auditor mencari bukti nyata: keputusan anggaran, komunikasi pimpinan ke karyawan, kehadiran di management review, dan keterlibatan saat insiden besar [S6]. Bagi SOC, persetujuan anggaran untuk lisensi SIEM, penambahan headcount, atau retensi log yang lebih panjang adalah bukti 5.1 yang sering terlupakan.

### 1.7 Klausul 5.2: kebijakan keamanan informasi

Pertanyaan 4 meminta kebijakan keamanan informasi. Draf pertama yang ditemukan Lead SOC di share drive ternyata dokumen sepuluh halaman berisi retensi log, panjang password, dan jadwal patch. Itu bukan yang diminta 5.2.

Kebijakan tingkat atas yang diminta 5.2 harus [S6]:

- sesuai dengan tujuan organisasi;
- memuat sasaran keamanan atau kerangka untuk menetapkannya;
- memuat komitmen memenuhi persyaratan yang berlaku;
- memuat komitmen perbaikan berkelanjutan;
- tersedia sebagai informasi terdokumentasi, dikomunikasikan di dalam organisasi, dan tersedia bagi pihak berkepentingan bila sesuai.

Kebijakan 5.2 berbeda dengan kontrol Annex A 5.1 (Policies for information security). Kontrol 5.1 mencakup kebijakan tingkat atas ditambah kebijakan topik khusus, misalnya kebijakan logging, kebijakan manajemen insiden, dan kebijakan kontrol akses. Kebijakan topik khusus itu harus disetujui, dikomunikasikan, dan ditinjau. URM melaporkan temuan audit 2026 berupa kebijakan yang belum diakui atau dibaca oleh pihak yang relevan [S8].

Hubungannya seperti piagam SOC dan SOP. Piagam menyatakan arah dan komitmen dalam satu-dua halaman; SOP dan standar teknis memuat detailnya. Kebijakan yang baik untuk 5.2 justru pendek, sekitar satu sampai dua halaman. Detail teknis seperti "log disimpan 365 hari" ditaruh di kebijakan topik khusus atau standar teknis, bukan di kebijakan tingkat atas.

### 1.8 Klausul 5.3: peran, tanggung jawab, dan wewenang

Bagian kedua pertanyaan 4, "siapa yang berwenang menyatakan insiden mayor", adalah pertanyaan 5.3. Di SOC jawabannya ada di matriks eskalasi; di ISMS, peran dan wewenang seperti itu harus ditetapkan dan dikomunikasikan.

Top management memastikan tanggung jawab dan wewenang untuk peran yang relevan ditetapkan dan dikomunikasikan di dalam organisasi. Ada dua tanggung jawab yang wajib ditugaskan secara eksplisit [S6]:

1. memastikan ISMS sesuai dengan persyaratan standar;
2. melaporkan kinerja ISMS kepada top management.

Standar tidak mewajibkan jabatan CISO atau ISMS Manager; yang wajib, kedua tanggung jawab itu dimiliki seseorang dan diketahui organisasi.

Kontrol Annex A terkait:

- 5.2 Information security roles and responsibilities (peran di level kontrol);
- 5.3 Segregation of duties (pemisahan tugas yang bertentangan);
- 5.4 Management responsibilities (manajer memastikan stafnya menjalankan kebijakan).

Contoh di SOC: penulis rule deteksi tidak sendirian menyetujui penonaktifan rule itu, dan admin SIEM tidak bisa menghapus log audit aksinya sendiri tanpa jejak.

## 2. Contoh dokumen / artefak (organisasi fiktif)

Organisasi fiktif: PT Awan Nusantara (PT AN), penyedia hosting di Jakarta, 120 karyawan. Semua isi di bawah adalah ilustrasi. Keempat artefak ini adalah bahan draf jawaban untuk kuesioner bank di bagian Ide inti.

### 2.1 Cuplikan register konteks (4.1)

Sumber jawaban pertanyaan 1 kuesioner. Perhatikan kolom "Tindak lanjut".

```
ID    Jenis      Isu                                           Dampak ke ISMS                     Tindak lanjut
K-03  Eksternal  UU PDP berlaku; klien minta bukti pelaporan    Risiko kepatuhan dan reputasi       Risiko R-11; prosedur IR v2
K-07  Eksternal  Perubahan iklim: banjir musiman, beban         Ketersediaan DC Jakarta-1           Relevan. Risiko R-15;
                 pendingin saat panas ekstrem                                                       uji BCP tahunan
K-09  Internal   Rencana migrasi 40% sumber log ke Wazuh        Potensi celah logging saat cutover  Rencana perubahan CH-02 (6.3)
K-12  Internal   Turnover analyst L1 sekitar 30%/tahun          Kualitas triage tidak konsisten      Program onboarding (7.2)
```

Cara membaca: kolom "Tindak lanjut" menunjukkan isu tidak berhenti di register. Setiap isu yang relevan mengalir ke risiko (6.1), perubahan (6.3), atau kompetensi (7.2). Baris K-07 adalah bukti bahwa perubahan iklim sudah ditentukan relevan, lengkap dengan alasannya. Bila PT AN menyimpulkan tidak relevan, baris itu tetap ada, berisi alasan kenapa tidak relevan.

### 2.2 Cuplikan register pihak berkepentingan (4.2)

Sumber jawaban pertanyaan 2 kuesioner. Baris bank dan lembaga PDP menunjukkan bahwa kewajiban pelaporan sudah dicatat dan masuk prosedur IR.

| Pihak | Persyaratan relevan | Ditangani lewat ISMS? | Catatan |
|---|---|---|---|
| Klien perbankan | Laporan insiden keamanan yang memengaruhi layanan dalam tenggat kontrak | Ya | Masuk prosedur IR dan SLA SOC |
| Klien perbankan | Harga tetap selama kontrak | Tidak | Urusan komersial |
| Lembaga PDP dan subjek data | Pemberitahuan kegagalan pelindungan maks 3 x 24 jam | Ya | Masuk prosedur IR |
| Penyedia colocation | Akses fisik teknisi sesuai jadwal | Ya (sebagian) | Interface fisik; kontrol 7.2 Physical entry |
| Karyawan SOC | Jadwal shift yang adil | Tidak | Urusan HR, di luar ISMS |
| Investor | Tidak ada kebocoran data yang berdampak reputasi | Ya | Masuk sasaran keamanan 6.2 |

Kolom "Ditangani lewat ISMS?" menjawab butir 4.2 c [S4]. Baris "Tidak" sama pentingnya dengan "Ya": ia menunjukkan persyaratan sudah dipertimbangkan dan sengaja diletakkan di luar ISMS.

### 2.3 Pernyataan scope v1.0 (4.3)

Sumber jawaban pertanyaan 3 kuesioner. Ini versi resmi dari draf scope di Day 01.

```
Scope ISMS PT Awan Nusantara, v1.0, disetujui Direktur Operasional 2026-01-15

Mencakup: penyediaan, operasi, dan dukungan layanan AN-Hosting (managed VM), termasuk
  - SOC 24x7 (lantai 5, kantor pusat Jakarta) dan platform SIEM-nya
  - data center Jakarta-1 (ruang server sewa di fasilitas colocation)
  - tim Platform Engineering dan Service Desk L1
Tidak mencakup: divisi pemasaran dan kantor cabang Surabaya
  Alasan: tidak memproses data pelanggan AN-Hosting; akses ke platform hanya lewat VPN terkontrol
Interface: VPN cabang Surabaya ke jaringan manajemen; portal pelanggan; API billing (dikelola divisi Keuangan)
Dependency: penyedia colocation (listrik, pendingin, akses fisik); penyedia layanan email cloud
Acuan: ISO/IEC 27001:2022 + Amd 1:2024; SoA v1.1
```

Tabel berikut menjelaskan kenapa setiap elemen scope ditulis seperti itu; cari elemen yang belum ada di scope organisasimu.

| Elemen | Kenapa ditulis begitu |
|---|---|
| Versi dan persetujuan | Scope adalah dokumen yang dikendalikan (7.5) |
| SOC disebut eksplisit | Bukti logging, monitoring, dan insiden berasal dari SOC |
| Alasan pengecualian | Pengecualian tanpa alasan akan dipertanyakan auditor |
| Interface dan dependency dipisah | Interface butuh kontrol di titik temu; dependency butuh pengelolaan pemasok (kontrol 5.19-5.22) |
| Rujukan ke SoA | Scope dan SoA dibaca bersama oleh auditor |

### 2.4 Matriks peran ISMS untuk SOC (5.3)

Sumber jawaban bagian kedua pertanyaan 4: baris "Menyatakan insiden mayor" menunjukkan siapa yang berwenang.

| Aktivitas | Direktur Ops | ISMS Manager | Lead SOC | Analyst SOC | Internal auditor |
|---|---|---|---|---|---|
| Memastikan ISMS sesuai standar (5.3 a) | A | R | C | I | C |
| Melaporkan kinerja ISMS ke pimpinan (5.3 b) | I | R | C | - | - |
| Menyetujui kebijakan logging | A | R | C | I | - |
| Menyatakan insiden mayor | A | C | R | C | - |
| Menonaktifkan rule deteksi | - | I | A | R | - |
| Mengaudit proses SOC | I | C | C | C | R |

R = responsible, A = accountable, C = consulted, I = informed. RACI alat bantu, bukan bentuk wajib. Di baris "Menonaktifkan rule deteksi", pengusul (R) berbeda dengan penyetuju (A): contoh kecil kontrol 5.3 Segregation of duties.

## 3. Lab praktik

Latihan dokumen untuk organisasi fiktifmu dari Day 01-02.

1. Tulis register konteks minimal 8 isu (4 eksternal dengan PESTLE, 4 internal dengan SWOT), masing-masing dengan tindak lanjut.
2. Tambahkan satu baris keputusan perubahan iklim, relevan atau tidak, beserta alasannya.
3. Susun register pihak berkepentingan minimal 6 pihak dan 8 persyaratan; minimal dua diputuskan "Tidak ditangani lewat ISMS" dengan alasan.
4. Tulis ulang scope Day 01 menjadi v1.0 dengan format bagian 2.3, minimal dua interface dan dua dependency.
5. Tulis kerangka kebijakan tingkat atas (5.2) maksimal satu halaman yang memuat keempat unsur di bagian 1.7.
6. Buat matriks RACI minimal 6 aktivitas SOC dan tandai satu baris pemisahan tugas.
7. Hubungkan ke lab: di Splunk atau Wazuh lab-mu, catat siapa yang punya hak admin dan apakah satu orang bisa membuat rule, menonaktifkannya, dan menghapus jejaknya sendiri. Bila bisa, tulis sebagai temuan kontrol 5.3 beserta usulan perbaikan. Cukup amati konfigurasi peran di UI.

**Hasil yang sebaiknya tersimpan:**
- Empat dokumen pendek di `latihan/day03-<nama-org-fiktif>.md` yang saling merujuk: isu konteks mengarah ke risiko atau perubahan, persyaratan pihak berkepentingan muncul di scope atau kebijakan, dan peran di RACI cocok dengan pemilik di peta ISMS Day 02.
- Keputusan perubahan iklim yang eksplisit beserta alasannya, dan kolom "ditangani lewat ISMS" di register pihak berkepentingan.
- Scope dengan pengecualian beralasan, interface, dan dependency.
- Dua tanggung jawab wajib 5.3 dengan pemilik bernama (jabatan fiktif).
- Tidak ada kalimat yang disalin dari teks standar.

**Variasi tantangan:** organisasimu memutuskan memakai MSSP untuk monitoring malam hari. Tulis ulang scope dan RACI-nya. Apakah MSSP menjadi interface, dependency, atau keduanya? Kontrol Annex A mana yang mulai relevan (petunjuk: kelompok supplier 5.19-5.22)?

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Register konteks tanpa tindak lanjut | Dibuat untuk formalitas | Tambahkan kolom tindak lanjut; isu tanpa tindakan ditandai "dipantau" dengan alasan |
| Bingung interface atau dependency | Definisi tercampur | Interface titik temu; dependency ketergantungan pada pihak luar |
| Scope terlalu luas sehingga ISMS tidak terkelola | Ingin "seluruh perusahaan" sejak awal | Mulai dari layanan yang diminta klien; perluas bertahap |
| Kebijakan 5.2 sepuluh halaman berisi detail teknis | Kebijakan tingkat atas tercampur kebijakan topik khusus | Pisahkan ke kebijakan topik (kontrol 5.1) atau standar teknis |
| Tidak jelas siapa pemegang 5.3 a dan b | Peran tidak ditetapkan tertulis | Tulis di dokumen penetapan peran yang disetujui pimpinan dan komunikasikan |

## 5. Kesalahan umum dan jebakan

- Menganggap perubahan iklim wajib dinyatakan relevan. Yang wajib adalah menentukan apakah relevan dan bisa menunjukkan keputusan beserta alasannya [S1][S2].
- Scope yang mengecualikan SOC, lalu kesulitan menunjukkan bukti logging dan insiden.
- Register pihak berkepentingan tanpa keputusan "ditangani lewat ISMS" (butir 4.2 c, baru di 2022) [S4]. Pasangannya di management review, input 9.3.2 c, juga dilaporkan sering terlewat [S8].
- Kebijakan ditandatangani tetapi tidak pernah dikomunikasikan atau dibaca. Temuan ini dilaporkan untuk kontrol 5.1 [S8].

## 6. Catatan terkini

Bagian ini menampung tanggal dan latar belakang amandemen. Berguna saat membaca dokumen lama atau menjelaskan asal tambahan iklim, tetapi tidak mengubah apa yang harus disiapkan.

- Amd 1:2024 (Climate action changes) terbit 23 Februari 2024 [S10]. Komunike bersama IAF-ISO bertanggal 22 Februari 2024 [S2]. Amandemen serupa diterapkan ke sejumlah standar sistem manajemen lain (misalnya ISO 9001 dan 14001) sebagai tindak lanjut London Declaration on Climate Action [S2].
- BSN menetapkan SNI ISO/IEC 27001:2022/Amd.1:2024 secara identik dengan metode terjemahan dua bahasa. Rapat konsensus berlangsung 21 Juni 2024 dan jajak pendapat 18 Juli sampai 1 Agustus 2024 [S1].
- Dokumen IAF menyebut kedua pernyataan iklim akan dimasukkan ke semua standar sistem manajemen yang baru atau sedang direvisi [S2], sehingga edisi 27001 berikutnya akan memuatnya langsung di teks.

## 7. Cheat sheet

```
4.1 Isu internal/eksternal (PESTLE/SWOT boleh, tidak wajib)
    + Amd1:2024: tentukan APAKAH perubahan iklim relevan (keputusan + alasan, boleh "tidak relevan")
4.2 (a) pihak berkepentingan (b) persyaratannya (c) mana yang ditangani lewat ISMS [baru 2022]
    + Note 2 Amd1: pihak bisa punya persyaratan iklim (informatif)
4.3 Scope = pertimbangkan 4.1 + 4.2 + interface & dependency; WAJIB terdokumentasi
    interface = titik temu dalam/luar scope   dependency = ketergantungan pada pihak luar
4.4 ISMS + proses dan interaksinya [eksplisit 2022]
5.1 Pimpinan: arah strategis, integrasi, sumber daya, komunikasi, dukung manajer lain
5.2 Kebijakan: sesuai tujuan | sasaran/kerangka | komitmen persyaratan | komitmen perbaikan
    terdokumentasi, dikomunikasikan, tersedia bagi pihak berkepentingan bila sesuai
    pendek (1-2 halaman); detail teknis ke kebijakan topik khusus (kontrol 5.1)
5.3 Dua tanggung jawab wajib: (a) kesesuaian ISMS dengan standar (b) lapor kinerja ke pimpinan
    jabatan CISO tidak wajib; yang wajib pemiliknya jelas dan diketahui
Annex A terkait: 5.1 kebijakan | 5.2 peran | 5.3 segregation of duties | 5.4 tanggung jawab manajemen
                 5.19-5.22 pemasok | 5.31 persyaratan legal/kontrak
IAF-ISO Feb 2024: tanpa transisi penuh; CB menilai sejak terbit; temuan "yang sesuai" bila tidak dipertimbangkan
                  (tingkat temuan tidak otomatis minor)
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** ISMS Manager PT AN berkata kepada auditor CB: "Kami sudah membahas perubahan iklim di rapat dan sepakat tidak relevan, jadi tidak kami tulis di register konteks." Apakah persyaratan Amd 1:2024 terpenuhi?

<details><summary>Jawaban</summary>

Belum. Organisasi memang boleh menyimpulkan perubahan iklim tidak relevan, tetapi keputusan itu harus bisa ditunjukkan. Bila organisasi menyimpulkan tidak relevan, CB menilai efektivitas proses pengambilan keputusan itu, dan kesepakatan lisan tanpa jejak sulit dinilai. Bila pertimbangannya tidak bisa ditunjukkan, auditor menerbitkan temuan yang sesuai; tingkatnya bergantung pada penilaian auditor, tidak otomatis minor. Perbaikannya: tambahkan baris di register konteks berisi keputusan "tidak relevan" beserta alasannya. Lihat bagian 1.3 dan 2.1.

</details>

**2. Pertanyaan jebakan.** Supaya register pihak berkepentingan terlihat rapi, seorang staf menghapus semua persyaratan yang tidak ditangani lewat ISMS, misalnya "harga tetap selama kontrak". Apakah itu langkah yang benar?

<details><summary>Jawaban</summary>

Tidak. Butir 4.2 c meminta organisasi menentukan persyaratan mana yang ditangani lewat ISMS, sehingga keputusan "tidak" juga merupakan hasil yang perlu terlihat. Baris "Tidak" menunjukkan persyaratan sudah dipertimbangkan dan sengaja diletakkan di luar ISMS. Kalau dihapus, auditor tidak bisa membedakan persyaratan yang sengaja dikeluarkan dari persyaratan yang terlewat. Lihat bagian 1.2 dan 2.2.

</details>

**3. Skenario keputusan.** PT AN memindahkan SIEM-nya ke layanan SIEM berbasis cloud milik pihak ketiga. Bagaimana penyedia itu dicatat di pernyataan scope?

- A. Sebagai interface, karena log dikirim ke sana.
- B. Sebagai dependency, karena penyedia itu berada di luar scope tetapi dibutuhkan ISMS, lalu dikelola lewat kontrol pemasok.
- C. Tidak perlu dicatat, karena penyedia itu berada di luar scope.

<details><summary>Jawaban</summary>

B. Dependency adalah hal di luar scope yang tetap dibutuhkan ISMS, dan penyedia SIEM berbasis cloud adalah contoh langsungnya. Dependency dikelola lewat kontrol pemasok (5.19-5.22). A kurang tepat sebagai jawaban utama: titik koneksi pengiriman log bisa dicatat sebagai interface, tetapi penyedianya sendiri adalah ketergantungan, bukan titik temu. C keliru karena 4.3 meminta interface dan dependency dipertimbangkan saat menetapkan scope; justru hal di luar scope yang dibutuhkan ISMS harus disebut. Lihat bagian 1.4 dan 2.3.

</details>

**4. Skenario keputusan.** Untuk menjawab pertanyaan 4 kuesioner bank, Lead SOC menemukan "Kebijakan Keamanan Informasi" sepuluh halaman berisi retensi log 365 hari, aturan password, dan jadwal patch. Apa yang sebaiknya dilakukan?

- A. Kirim apa adanya. Semakin detail kebijakan, semakin baik untuk auditor dan klien.
- B. Pisahkan: kebijakan tingkat atas (5.2) dibuat pendek dan memuat unsur wajibnya, sedangkan detail teknis dipindah ke kebijakan topik khusus atau standar teknis (kontrol 5.1).
- C. Hapus semua detail teknis karena ISO 27001 tidak membahas retensi log atau password.

<details><summary>Jawaban</summary>

B. Kebijakan 5.2 harus sesuai tujuan organisasi, memuat sasaran atau kerangkanya, memuat komitmen memenuhi persyaratan dan komitmen perbaikan berkelanjutan, serta dikomunikasikan. Kebijakan yang baik untuk 5.2 pendek, sekitar satu sampai dua halaman. A keliru karena detail teknis mencampur kebijakan tingkat atas dengan kebijakan topik khusus, sehingga sulit dikelola dan dikomunikasikan. C keliru karena detail itu tetap dibutuhkan, hanya tempatnya di kebijakan topik khusus yang juga harus disetujui, dikomunikasikan, dan ditinjau. Lihat bagian 1.7.

</details>

**5. Pertanyaan jebakan.** PT AN tidak punya jabatan CISO maupun ISMS Manager. Apakah otomatis tidak memenuhi 5.3?

<details><summary>Jawaban</summary>

Tidak. Standar tidak mewajibkan jabatan tertentu. Yang wajib adalah dua tanggung jawab ditugaskan secara eksplisit, yaitu memastikan ISMS sesuai dengan persyaratan standar dan melaporkan kinerja ISMS kepada top management, lalu diketahui organisasi. Tanggung jawab itu boleh dipegang jabatan lain, selama penetapannya tertulis dan dikomunikasikan. Lihat bagian 1.8.

</details>

**6. Jelaskan ulang.** Manajer SOC bertanya, "Kenapa repot memasukkan SOC ke scope ISMS? Kita kan bukan layanan yang dijual." Jawab dalam tiga kalimat.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Bukti bahwa logging, monitoring, dan penanganan insiden benar-benar berjalan datangnya dari SOC. Kalau SOC di luar scope, bukti itu harus diambil dari tim yang tidak ikut diaudit, dan auditor akan sulit menerimanya. Jadi lebih mudah memasukkan SOC ke scope, atau kalau tidak, memperlakukannya sebagai dependency dengan perjanjian layanan yang jelas."

Kesalahan yang sering muncul:
- Menjawab "karena ISO mewajibkan SOC". Standar tidak mewajibkan SOC; yang dibutuhkan adalah bukti kontrol yang biasanya dihasilkan SOC.
- Menganggap masuk scope berarti auditor menilai alat SOC. Yang dicari adalah bukti bahwa kontrol logging, monitoring, dan insiden berjalan.
- Lupa pilihan kedua (dependency dengan perjanjian layanan) bila SOC memang dijalankan pihak lain.

</details>

**7. Interview question (English).** "Our ISO 27001 certificate scope doesn't mention the SOC. As a SOC analyst, why should you care?"

<details><summary>Sample answer</summary>

"The scope defines what the auditors actually examine and what the certificate covers. Most evidence for logging, monitoring, and incident handling comes from the SOC, so if the SOC is outside the scope, that evidence has to come from teams that aren't audited, which makes it weak. I'd check whether the SOC is listed as a dependency with a clear service agreement, because then it still has to be managed through supplier controls. And when a client asks whether our monitoring is covered by the certificate, I need to know the honest answer."

What makes this answer strong: it links scope to evidence instead of prestige, mentions the dependency option, and connects the question to real client conversations.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | BSN: RSNI3 ISO/IEC 27001:2022/Amd.1:2024 | https://bsn.go.id/uploads/attachment/rsni_iso_iec_27001-2022-amd1_1.pdf | primer | 2024; diakses 2026-10-10 | Tinggi. Teks perubahan 4.1 dan 4.2 (dua bahasa), prakata, komite |
| S2 | IAF: IAF-ISO Joint Communique on Addition of Climate Change Considerations to MSS (memuat IAF TC Final Decision) | https://iaf.nu/wp-content/uploads/2024/02/IAF-ISO-Joint-Communique-_2024F.pdf | primer (IAF) | 2024-02-23; diakses 2026-10-10 | Tinggi. Ekspektasi untuk organisasi, CB, badan akreditasi, waktu berlaku, dan sertifikat |
| S3 | IAF news: New 2021 edition of Annex SL | https://iaf.news/2021/07/02/new-2021-edition-of-annex-sl-for-management-system-standards/ | sekunder (situs berita IAF) | 2021-07-02; diakses 2026-10-10 | Sedang-tinggi. Asal butir 4.2 c |
| S4 | Cloud Security Alliance (A-LIGN): ISO 27001:2013 vs 2022 | https://cloudsecurityalliance.org/articles/what-s-the-difference-between-iso-27001-2013-and-iso-27001-2022 | sekunder | 2023-02-10; diakses 2026-10-08 | Sedang. Perubahan 4.2, 4.4, 5.3 |
| S5 | Hicomply: ISO 27001 clause 4.3 determining the scope of the ISMS | https://www.hicomply.com/hub/iso-27001-clause-4-3-determining-the-scope-of-the-information-security-management-system | sekunder (vendor) | 2026-07-15; diakses 2026-10-08 | Sedang. Input scope, interface, dependency |
| S6 | Advisera: ISO 27001 clause 5 leadership | https://advisera.com/iso27001/clause-5-leadership/ | sekunder (konsultan) | diakses 2026-10-08 | Sedang. Isi 5.1-5.3 dan bukti yang dicari auditor |
| S7 | HighTable: ISO 27001 external issues | https://hightable.io/iso-27001-2022/external-issues/ | sekunder (konsultan) | diperbarui 2026-10-06; diakses 2026-10-08 | Sedang. PESTLE/SWOT; klaim "otomatis minor NC" bertentangan dengan S2 |
| S8 | URM Consulting: Common issues identified during audits of ISO 27001:2022 | https://urmconsulting.com/blog/common-issues-identified-during-audits-of-iso-27001-2022 | sekunder (praktisi audit) | 2026-04-09; diakses 2026-10-08 | Sedang. Pengalaman satu konsultan |
| S9 | BPK: UU No. 27 Tahun 2022 tentang Pelindungan Data Pribadi | https://peraturan.bpk.go.id/Details/229798/uu-no-27-tahun-2022 | primer (database peraturan) | ditetapkan dan berlaku 2022-10-17; diakses 2026-10-10 | Tinggi. Judul, nomor, dan tanggal berlaku |
| S10 | ISO committee: ISO/IEC 27001:2022/Amd 1:2024 Climate action changes | https://committee.iso.org/standard/88435.html | primer (katalog ISO) | terbit 2024-02-23; diakses 2026-10-10 | Tinggi untuk judul dan tanggal terbit |

**Catatan sumber:** butir 5.1-5.3 disusun dari ringkasan sekunder yang saling cocok; urutan butir 5.1 bisa sedikit berbeda dari teks ISO/IEC 27001:2022. Pasal 46 UU PDP tidak menyebut secara eksplisit sejak kapan 3 x 24 jam dihitung; cek penjelasan pasal dan peraturan pelaksananya di peraturan.bpk.go.id sebelum dipakai untuk prosedur IR.
