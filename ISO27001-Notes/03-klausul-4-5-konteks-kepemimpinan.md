---
day: 03
title: 'Klausul 4-5: konteks, scope, pihak berkepentingan, kepemimpinan, kebijakan, dan peran'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 27001:2022 + Amd 1:2024 (Climate action changes, Feb 2024); SNI ISO/IEC 27001:2022/Amd.1:2024 (BSN, 2024); IAF-ISO Joint Communique 22 Feb 2024'
---

# Day 03: Klausul 4-5, konteks organisasi dan kepemimpinan

> Catatan pribadi, bukan materi resmi ISO, dan bukan nasihat hukum atau audit. Catatan ini hanya menyebut nomor dan judul singkat klausul, lalu menjelaskannya dengan kata-kata sendiri.

Cakupan: klausul 4.1-4.4 dan 5.1-5.3 ISO/IEC 27001:2022 termasuk Amd 1:2024, serta hubungannya dengan kontrol organisasi di Annex A (5.1-5.4, 5.31). Risk assessment di klausul 6 dibahas di Day 04.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan apa yang diminta 4.1 dan 4.2, termasuk tambahan perubahan iklim dari Amd 1:2024 dan cara auditor menilainya.
- menyusun register pihak berkepentingan yang memisahkan persyaratan yang ditangani lewat ISMS dari yang tidak.
- menulis pernyataan scope yang menyebut batas, pengecualian, interface, dan dependency.
- membedakan kewajiban top management di 5.1, isi kebijakan di 5.2, dan dua tanggung jawab wajib di 5.3.
- menunjukkan posisi SOC di dalam konteks, scope, dan struktur peran ISMS.

## 2. Konteks singkat

Klausul 4 dan 5 adalah fondasi. Jika konteks dan scope salah, semua yang dibangun di atasnya ikut miring: risiko yang dinilai bukan risiko yang relevan, kontrol yang dipilih tidak menjawab kebutuhan klien, dan sertifikat tidak mencakup layanan yang sebenarnya dibeli orang.

Bagi analyst SOC, dua klausul ini terasa jauh dari pekerjaan harian. Padahal keduanya menentukan tiga hal yang langsung memengaruhi SOC:

- apakah SOC dan sistem yang dipantaunya masuk scope;
- persyaratan klien atau regulator mana yang harus dipenuhi SOC, misalnya tenggat pelaporan insiden;
- siapa yang berwenang memutuskan saat insiden besar terjadi.

Kapan dipakai: saat organisasi memulai ISMS, saat scope diperluas (misalnya layanan baru), saat ada regulasi atau kontrak baru, dan setiap management review.
Kapan tidak cukup: klausul 4-5 tidak memberi tahu kontrol apa yang dipilih. Itu hasil risk assessment (Day 04).

## 3. Konsep inti

### 3.1 Klausul 4.1: isu internal dan eksternal

Organisasi harus memahami isu internal dan eksternal yang relevan dengan tujuannya dan memengaruhi kemampuan ISMS mencapai hasil yang diinginkan. Standar tidak menentukan formatnya. Banyak organisasi memakai PESTLE (politik, ekonomi, sosial, teknologi, legal, lingkungan) untuk isu eksternal dan SWOT untuk isu internal [S7]. Keduanya alat bantu, bukan persyaratan.

Contoh isu yang relevan untuk perusahaan hosting:

| Jenis | Contoh | Kenapa relevan untuk ISMS |
|---|---|---|
| Eksternal, legal | UU No. 27 Tahun 2022 tentang Pelindungan Data Pribadi | Mewajibkan pelindungan data pribadi dan pemberitahuan tertulis paling lambat 3 x 24 jam bila terjadi kegagalan pelindungan (Pasal 46, lihat Day 10 bagian 3.6). Titik mulai hitungan tenggat perlu dicek di teks resmi UU PDP |
| Eksternal, teknologi | Serangan ransomware ke penyedia hosting meningkat | Memengaruhi prioritas risiko dan kebutuhan deteksi |
| Eksternal, lingkungan | Banjir musiman di Jakarta | Memengaruhi ketersediaan data center |
| Internal | Turnover analyst SOC tinggi | Memengaruhi kompetensi (7.2) dan konsistensi triage |
| Internal | Migrasi sebagian log dari Splunk ke Wazuh karena biaya lisensi | Perubahan ISMS yang harus direncanakan (6.3) |

**Tambahan Amd 1:2024:** di akhir 4.1 ditambahkan satu kalimat yang mewajibkan organisasi menentukan apakah perubahan iklim merupakan isu yang relevan [S1]. Perhatikan kata "menentukan apakah". Organisasi boleh menyimpulkan bahwa perubahan iklim tidak relevan, tetapi keputusan itu harus diambil dengan sadar dan bisa ditunjukkan.

### 3.2 Klausul 4.2: pihak berkepentingan dan persyaratannya

4.2 meminta organisasi menentukan tiga hal:

1. pihak berkepentingan yang relevan dengan ISMS;
2. persyaratan relevan dari pihak-pihak itu (bisa berupa persyaratan hukum, regulasi, dan kontrak);
3. persyaratan mana yang akan ditangani lewat ISMS. Butir ketiga ini baru di edisi 2022 [S4], diturunkan dari Annex SL 2021 [S3].

Butir ketiga mengakui kenyataan bahwa tidak semua persyaratan pihak berkepentingan adalah urusan ISMS. Klien mungkin menuntut harga murah atau SLA uptime 99,9%. Uptime ada hubungannya dengan availability, tetapi target bisnisnya diatur di luar ISMS. Register yang baik menuliskan keputusan itu secara eksplisit, supaya auditor tidak menganggapnya terlewat.

**Tambahan Amd 1:2024:** catatan baru (Note 2) di 4.2 menyebut bahwa pihak berkepentingan yang relevan bisa punya persyaratan terkait perubahan iklim [S1]. Catatan di standar ISO bersifat informatif, bukan persyaratan tambahan. Fungsinya mengingatkan agar persyaratan semacam itu ikut dipertimbangkan.

### 3.3 Cara auditor menilai tambahan perubahan iklim

Komunike bersama IAF dan ISO (22 Februari 2024) menjelaskan maksud amandemen ini [S2]:

- Inti persyaratan 4.1 dan 4.2 tidak berubah. Amandemen dianggap klarifikasi, sehingga tidak ada program transisi penuh dan sertifikat tidak perlu diterbitkan ulang.
- Organisasi tersertifikasi diharapkan sudah mempertimbangkan aspek dan risiko perubahan iklim. Bila relevan, isu itu masuk evaluasi risiko di dalam scope.
- Lembaga sertifikasi (CB) diharapkan memastikan perubahan iklim sudah dipertimbangkan. Bila organisasi menyimpulkan tidak relevan, CB menilai apakah proses pengambilan keputusannya efektif.
- Sejak amandemen terbit (dijadwalkan 23 Februari 2024), CB memasukkan teks baru ke audit konteks. Bila organisasi tidak bisa menunjukkan pertimbangan itu, auditor menerbitkan temuan yang sesuai.

Konflik sumber: satu artikel konsultan menulis bahwa tidak mencantumkan perubahan iklim "otomatis" menjadi minor nonconformity [S7]. Komunike IAF hanya menyebut "temuan yang sesuai", tanpa menetapkan tingkatnya [S2]. Catatan ini mengikuti sumber primer: tingkat temuan bergantung pada penilaian auditor.

Contoh untuk SOC: perubahan iklim relevan bila memengaruhi ketersediaan data center (banjir, panas ekstrem yang membebani pendingin) atau bila klien menanyakannya dalam kuesioner keamanan. Dampaknya biasanya masuk ke risiko availability dan kontrol kontinuitas, bukan ke deteksi.

### 3.4 Klausul 4.3: scope ISMS

Saat menentukan scope, organisasi mempertimbangkan isu dari 4.1, persyaratan dari 4.2, serta interface dan dependency antara aktivitas yang dijalankan sendiri dan yang dijalankan pihak lain [S5]. Scope wajib tersedia sebagai informasi terdokumentasi.

Dua istilah itu sering tertukar:

- **Interface:** titik pertemuan antara yang di dalam dan di luar scope. Contoh: koneksi VPN dari kantor cabang (di luar scope) ke jaringan manajemen (di dalam scope).
- **Dependency:** hal di luar scope yang tetap dibutuhkan ISMS. Contoh: penyedia colocation yang mengurus listrik dan pendingin, atau penyedia SIEM berbasis cloud.

Scope yang baik biasanya menyebut batas organisasi (unit, tim), batas fisik (lokasi), batas teknologi (jaringan, platform), layanan atau proses yang dicakup, dan pengecualian beserta alasannya [S5]. Scope sebaiknya dikelola sebagai dokumen hidup dengan versi dan persetujuan, bukan dibuat ulang setiap menjelang audit [S5].

Kenapa ini penting untuk SOC: bila SOC berada di luar scope, kontrol logging dan monitoring di dalam scope tetap butuh bukti. Bukti itu akhirnya harus datang dari pihak yang tidak diaudit. Biasanya lebih mudah memasukkan SOC ke scope, atau memperlakukannya sebagai dependency dengan perjanjian layanan yang jelas.

### 3.5 Klausul 4.4: ISMS dan proses-prosesnya

4.4 meminta organisasi membangun, menerapkan, memelihara, dan terus meningkatkan ISMS. Sejak 2022, ISMS secara eksplisit mencakup proses yang dibutuhkan beserta interaksinya [S4]. Bukti yang wajar adalah peta proses seperti diagram di Day 02 bagian 3.3: proses apa saja yang ada (risk assessment, manajemen insiden, audit internal, kontrol dokumen), siapa pemiliknya, serta input dan output masing-masing.

### 3.6 Klausul 5.1: kepemimpinan dan komitmen

Top management harus menunjukkan kepemimpinan, bukan hanya menandatangani kebijakan. Isi 5.1 kira-kira mencakup:

- memastikan kebijakan dan sasaran keamanan selaras dengan arah strategis;
- mengintegrasikan persyaratan ISMS ke proses bisnis;
- menyediakan sumber daya;
- mengomunikasikan pentingnya keamanan informasi dan kesesuaian dengan ISMS;
- memastikan ISMS mencapai hasil yang diinginkan;
- mengarahkan dan mendukung orang yang berkontribusi;
- mendorong perbaikan berkelanjutan;
- mendukung manajer lain menjalankan kepemimpinan di area masing-masing.

Auditor mencari bukti nyata: keputusan anggaran, komunikasi pimpinan ke karyawan, kehadiran di management review, dan keterlibatan saat insiden besar [S6]. Bagi SOC, persetujuan anggaran untuk lisensi SIEM, penambahan headcount, atau retensi log yang lebih panjang adalah bukti 5.1 yang sering terlupakan.

### 3.7 Klausul 5.2: kebijakan keamanan informasi

Kebijakan tingkat atas yang diminta 5.2 harus [S6]:

- sesuai dengan tujuan organisasi;
- memuat sasaran keamanan atau kerangka untuk menetapkannya;
- memuat komitmen memenuhi persyaratan yang berlaku;
- memuat komitmen perbaikan berkelanjutan;
- tersedia sebagai informasi terdokumentasi, dikomunikasikan di dalam organisasi, dan tersedia bagi pihak berkepentingan bila sesuai.

Kebijakan 5.2 berbeda dengan kontrol Annex A 5.1 (Policies for information security). Kontrol 5.1 mencakup kebijakan tingkat atas ditambah kebijakan topik khusus, misalnya kebijakan logging, kebijakan manajemen insiden, dan kebijakan kontrol akses. Kebijakan topik khusus itu harus disetujui, dikomunikasikan, dan ditinjau. URM melaporkan temuan audit 2026 berupa kebijakan yang belum diakui atau dibaca oleh pihak yang relevan [S8].

Kebijakan yang baik untuk 5.2 justru pendek, sekitar satu sampai dua halaman. Detail teknis seperti "log disimpan 365 hari" ditaruh di kebijakan topik khusus atau standar teknis, bukan di kebijakan tingkat atas.

### 3.8 Klausul 5.3: peran, tanggung jawab, dan wewenang

Top management memastikan tanggung jawab dan wewenang untuk peran yang relevan ditetapkan dan dikomunikasikan di dalam organisasi. Ada dua tanggung jawab yang wajib ditugaskan secara eksplisit [S6]:

1. memastikan ISMS sesuai dengan persyaratan standar;
2. melaporkan kinerja ISMS kepada top management.

Standar tidak mewajibkan jabatan bernama CISO atau ISMS Manager. Yang diwajibkan adalah kedua tanggung jawab itu dimiliki seseorang dan semua orang tahu siapa orangnya.

Kontrol Annex A terkait:

- 5.2 Information security roles and responsibilities (peran di level kontrol);
- 5.3 Segregation of duties (pemisahan tugas yang bertentangan);
- 5.4 Management responsibilities (manajer memastikan stafnya menjalankan kebijakan).

Untuk SOC, pemisahan tugas punya contoh nyata. Analyst yang menulis rule deteksi sebaiknya tidak sendirian menyetujui penonaktifan rule itu, dan admin SIEM sebaiknya tidak bisa menghapus log audit aksinya sendiri tanpa jejak.

## 4. Contoh dokumen / artefak (organisasi fiktif)

Organisasi fiktif: PT Awan Nusantara (PT AN), penyedia hosting di Jakarta, 120 karyawan. Semua isi di bawah adalah ilustrasi.

### 4.1 Cuplikan register konteks (4.1)

```
ID    Jenis      Isu                                           Dampak ke ISMS                     Tindak lanjut
K-03  Eksternal  UU PDP berlaku; klien minta bukti pelaporan    Risiko kepatuhan dan reputasi       Risiko R-11; prosedur IR v2
K-07  Eksternal  Perubahan iklim: banjir musiman, beban         Ketersediaan DC Jakarta-1           Relevan. Risiko R-15;
                 pendingin saat panas ekstrem                                                       uji BCP tahunan
K-09  Internal   Rencana migrasi 40% sumber log ke Wazuh        Potensi celah logging saat cutover  Rencana perubahan CH-02 (6.3)
K-12  Internal   Turnover analyst L1 sekitar 30%/tahun          Kualitas triage tidak konsisten      Program onboarding (7.2)
```

Cara membaca: kolom "Tindak lanjut" menunjukkan isu tidak berhenti di register. Setiap isu yang relevan mengalir ke risiko (6.1), perubahan (6.3), atau kompetensi (7.2). Baris K-07 adalah bukti bahwa perubahan iklim sudah ditentukan relevan, lengkap dengan alasannya. Bila PT AN menyimpulkan tidak relevan, baris itu tetap ada, berisi alasan kenapa tidak relevan.

### 4.2 Cuplikan register pihak berkepentingan (4.2)

| Pihak | Persyaratan relevan | Ditangani lewat ISMS? | Catatan |
|---|---|---|---|
| Klien perbankan | Laporan insiden keamanan yang memengaruhi layanan dalam tenggat kontrak | Ya | Masuk prosedur IR dan SLA SOC |
| Klien perbankan | Harga tetap selama kontrak | Tidak | Urusan komersial |
| Regulator (PDP) | Pelindungan data pribadi dan pemberitahuan kegagalan pelindungan maks 3 x 24 jam | Ya | Detail di Day 10 bagian 3.6 |
| Penyedia colocation | Akses fisik teknisi sesuai jadwal | Ya (sebagian) | Interface fisik; kontrol 7.2 Physical entry |
| Karyawan SOC | Jadwal shift yang adil | Tidak | Urusan HR, di luar ISMS |
| Investor | Tidak ada kebocoran data yang berdampak reputasi | Ya | Masuk sasaran keamanan 6.2 |

Kenapa kolom "Ditangani lewat ISMS?" ada: butir ketiga 4.2 meminta keputusan ini [S4]. Baris "Tidak" sama pentingnya dengan baris "Ya", karena menunjukkan persyaratan itu sudah dipertimbangkan dan sengaja diletakkan di luar ISMS.

### 4.3 Pernyataan scope v1.0 (4.3)

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

| Elemen | Kenapa ditulis begitu |
|---|---|
| Versi dan persetujuan | Scope adalah dokumen yang dikendalikan (7.5) |
| SOC disebut eksplisit | Bukti logging, monitoring, dan insiden berasal dari SOC |
| Alasan pengecualian | Pengecualian tanpa alasan akan dipertanyakan auditor |
| Interface dan dependency dipisah | Interface butuh kontrol di titik temu; dependency butuh pengelolaan pemasok (kontrol 5.19-5.22) |
| Rujukan ke SoA | Scope dan SoA dibaca bersama oleh auditor |

### 4.4 Matriks peran ISMS untuk SOC (5.3)

| Aktivitas | Direktur Ops | ISMS Manager | Lead SOC | Analyst SOC | Internal auditor |
|---|---|---|---|---|---|
| Memastikan ISMS sesuai standar (5.3 a) | A | R | C | I | C |
| Melaporkan kinerja ISMS ke pimpinan (5.3 b) | I | R | C | - | - |
| Menyetujui kebijakan logging | A | R | C | I | - |
| Menyatakan insiden mayor | A | C | R | C | - |
| Menonaktifkan rule deteksi | - | I | A | R | - |
| Mengaudit proses SOC | I | C | C | C | R |

R = responsible, A = accountable, C = consulted, I = informed. RACI adalah alat bantu, bukan bentuk yang diwajibkan standar. Perhatikan baris "Menonaktifkan rule deteksi": yang mengusulkan (R) berbeda dengan yang menyetujui (A). Pemisahan ini adalah contoh kecil kontrol 5.3 Segregation of duties.

## 5. Lab praktik

Latihan berupa dokumen untuk organisasi fiktifmu dari Day 01-02. Simpan di `ISO27001-note/latihan/day03-<nama-org-fiktif>.md`.

1. Tulis register konteks berisi minimal 8 isu: 4 eksternal (pakai PESTLE) dan 4 internal (pakai SWOT). Setiap isu wajib punya kolom tindak lanjut.
2. Tambahkan satu baris keputusan perubahan iklim, relevan atau tidak, dengan alasan dua sampai tiga kalimat.
3. Susun register pihak berkepentingan berisi minimal 6 pihak dan 8 persyaratan. Minimal dua persyaratan diputuskan "Tidak ditangani lewat ISMS" beserta alasannya.
4. Tulis ulang scope dari Day 01 menjadi v1.0 dengan format bagian 4.3. Pisahkan interface dan dependency, dan sebutkan minimal dua dari masing-masing.
5. Tulis kerangka kebijakan keamanan informasi tingkat atas (5.2), maksimal satu halaman, dengan kata-katamu sendiri. Pastikan keempat unsur di bagian 3.7 ada.
6. Buat matriks RACI untuk minimal 6 aktivitas SOC. Tandai satu baris yang menunjukkan pemisahan tugas.
7. Hubungkan ke lab: di Splunk atau Wazuh lab-mu, catat siapa saja yang punya hak admin. Tulis apakah satu orang bisa membuat rule, menonaktifkannya, dan menghapus jejaknya sendiri. Bila bisa, tulis sebagai temuan untuk kontrol 5.3 dan usulan perbaikannya. Cukup amati konfigurasi peran di UI; jangan mengubah apa pun dulu.

**Hasil yang seharusnya teramati:** empat dokumen pendek yang saling merujuk. Isu di register konteks mengarah ke risiko atau perubahan, persyaratan di register pihak berkepentingan muncul di scope atau kebijakan, dan peran di RACI cocok dengan pemilik di peta ISMS Day 02.

**Hasil yang sebaiknya tersimpan:**
- Ada keputusan perubahan iklim yang eksplisit beserta alasannya.
- Register pihak berkepentingan punya kolom "ditangani lewat ISMS".
- Scope menyebut pengecualian beralasan, interface, dan dependency.
- Kebijakan memuat sasaran atau kerangkanya, komitmen persyaratan, dan komitmen perbaikan.
- Dua tanggung jawab wajib 5.3 punya pemilik bernama (jabatan fiktif).
- Tidak ada kalimat yang disalin dari teks standar.

**Variasi tantangan:** organisasimu memutuskan memakai MSSP untuk monitoring malam hari. Tulis ulang scope dan RACI-nya. Apakah MSSP menjadi interface, dependency, atau keduanya? Kontrol Annex A mana yang mulai relevan (petunjuk: kelompok supplier 5.19-5.22)?

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Register konteks berisi daftar panjang tanpa tindak lanjut | Dibuat untuk memenuhi formalitas | Tambahkan kolom tindak lanjut; isu tanpa tindak lanjut ditandai "dipantau" beserta alasannya |
| Bingung apakah sesuatu interface atau dependency | Definisi tercampur | Interface adalah titik temu; dependency adalah ketergantungan pada pihak atau layanan di luar |
| Scope terlalu luas sehingga ISMS tidak terkelola | Ingin "seluruh perusahaan" sejak awal | Mulai dari layanan yang diminta klien; perluas bertahap |
| Kebijakan 5.2 sepuluh halaman berisi detail teknis | Kebijakan tingkat atas tercampur kebijakan topik khusus | Pisahkan ke kebijakan topik (kontrol 5.1) atau standar teknis |
| Tidak jelas siapa pemegang 5.3 a dan b | Peran tidak ditetapkan tertulis | Tulis di dokumen penetapan peran yang disetujui pimpinan dan komunikasikan |

## 7. Kesalahan umum dan jebakan

- Menganggap perubahan iklim wajib dinyatakan relevan. Yang wajib adalah menentukan apakah relevan, lalu bisa menunjukkan keputusan dan alasannya [S1][S2].
- Menganggap catatan (Note) di standar sebagai persyaratan. Note 2 di 4.2 bersifat informatif.
- Scope yang mengecualikan SOC, lalu kesulitan menunjukkan bukti logging dan insiden.
- Register pihak berkepentingan tanpa keputusan "ditangani lewat ISMS", padahal butir ini baru di 2022 [S4]. Sejalan dengan itu, URM melaporkan input 9.3.2 c (perubahan kebutuhan pihak berkepentingan) sering terlewat di management review [S8].
- Kebijakan ditandatangani tetapi tidak pernah dikomunikasikan atau dibaca. Temuan ini dilaporkan untuk kontrol 5.1 [S8].
- Mengira 5.3 mewajibkan jabatan CISO. Yang wajib adalah dua tanggung jawab itu dimiliki seseorang dan diketahui organisasi.

## 8. Catatan terkini

- Amd 1:2024 (Climate action changes) terbit Februari 2024. Isinya satu kalimat di akhir 4.1 dan satu catatan (Note 2) di akhir 4.2 [S1]. Amandemen serupa diterapkan ke sejumlah standar sistem manajemen lain (misalnya ISO 9001 dan 14001) sebagai tindak lanjut London Declaration ISO [S2].
- IAF dan ISO menyatakan tidak ada program transisi penuh dan sertifikat tidak perlu diterbitkan ulang. CB menilai pertimbangan perubahan iklim mulai saat amandemen terbit [S2].
- BSN menetapkan SNI ISO/IEC 27001:2022/Amd.1:2024 secara identik dengan metode terjemahan dua bahasa. Rapat konsensus berlangsung 21 Juni 2024 dan jajak pendapat 18 Juli sampai 1 Agustus 2024 [S1].
- Komunike IAF menyebut teks perubahan iklim juga akan dimasukkan ke semua standar sistem manajemen yang baru atau sedang direvisi [S2]. Jadi edisi 27001 berikutnya akan memuatnya langsung di teks. Pantau status revisi 27001 di katalog ISO.

## 9. Cheat sheet

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
5.3 Dua tanggung jawab wajib: (a) kesesuaian ISMS dengan standar (b) lapor kinerja ke pimpinan
Annex A terkait: 5.1 kebijakan | 5.2 peran | 5.3 segregation of duties | 5.4 tanggung jawab manajemen
                 5.19-5.22 pemasok | 5.31 persyaratan legal/kontrak
IAF-ISO Feb 2024: tanpa transisi penuh; CB menilai sejak terbit; temuan "yang sesuai" bila tidak dipertimbangkan
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | BSN: RSNI3 ISO/IEC 27001:2022/Amd.1:2024 | https://bsn.go.id/uploads/attachment/rsni_iso_iec_27001-2022-amd1_1.pdf | primer | 2024; diakses 2026-10-08 | Tinggi. Teks perubahan 4.1 dan 4.2 (dua bahasa), prakata, susunan komite |
| S2 | IAF-ISO Joint Communique on Addition of Climate Change Considerations to MSS | https://iaf.nu/wp-content/uploads/2024/02/IAF-ISO-Joint-Communique-_2024F.pdf | primer (IAF) | 2024-02-22; diakses 2026-10-08 | Tinggi. Ekspektasi untuk organisasi, CB, AB, dan waktu berlaku |
| S3 | IAF news: New 2021 edition of Annex SL | https://iaf.news/2021/07/02/new-2021-edition-of-annex-sl-for-management-system-standards/ | sekunder (situs berita IAF) | 2021-07-02; diakses 2026-10-08 | Sedang-tinggi. Asal butir "persyaratan yang ditangani lewat sistem manajemen" |
| S4 | Cloud Security Alliance (penulis A-LIGN): ISO 27001:2013 vs 2022 | https://cloudsecurityalliance.org/articles/what-s-the-difference-between-iso-27001-2013-and-iso-27001-2022 | sekunder | 2023-02-10; diakses 2026-10-08 | Sedang. Perubahan 4.2, 4.4, 5.3 |
| S5 | Hicomply: ISO 27001 clause 4.3 determining the scope of the ISMS | https://www.hicomply.com/hub/iso-27001-clause-4-3-determining-the-scope-of-the-information-security-management-system | sekunder (vendor) | 2026-07-15; diakses 2026-10-08 | Sedang. Input scope, interface dan dependency |
| S6 | Advisera: ISO 27001 clause 5 leadership | https://advisera.com/iso27001/clause-5-leadership/ | sekunder (konsultan) | tanpa tanggal; diakses 2026-10-08 | Sedang. Isi 5.1-5.3 dan bukti yang dicari auditor |
| S7 | HighTable: ISO 27001 external issues | https://hightable.io/iso-27001-2022/external-issues/ | sekunder (konsultan) | diperbarui 2026-10-06; diakses 2026-10-08 | Sedang. PESTLE/SWOT. Klaim "otomatis minor NC" bertentangan dengan S2 |
| S8 | URM Consulting: Common issues identified during audits of ISO 27001:2022 | https://urmconsulting.com/blog/common-issues-identified-during-audits-of-iso-27001-2022 | sekunder (praktisi audit) | 2026-04-09; diakses 2026-10-08 | Sedang. Pengalaman satu konsultan |

**Catatan sumber:** isi 5.1-5.3 di bagian 3.6-3.8 disusun dari ringkasan sekunder yang saling cocok, bukan dari teks standar; urutan dan pengelompokan butirnya bisa sedikit berbeda dari teks ISO/IEC 27001:2022. Teks amandemen iklim (S1) dan ekspektasi IAF-ISO (S2) berasal dari sumber primer. Kewajiban UU PDP di tabel bagian 3.1 dan 4.2 hanya dirangkum; tenggat 3 x 24 jam (Pasal 46) cukup pasti, sedangkan titik mulai hitungannya perlu dicek di teks resmi UU No. 27 Tahun 2022.
