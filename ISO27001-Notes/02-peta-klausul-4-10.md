---
day: 02
title: 'Peta klausul 4-10: gambaran satu halaman dan hubungan antar klausul'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 27001:2022 + Amd 1:2024 (masih edisi berlaku); SNI ISO/IEC 27001:2022/Amd.1:2024 (BSN); Harmonized Structure di ISO/IEC Directives Part 1 Consolidated ISO Supplement, Annex SL edisi 2021'
---

# Day 02: Peta klausul 4-10 dan hubungan antar klausul

> Catatan pribadi, bukan materi resmi ISO, dan bukan nasihat hukum atau audit. Catatan ini hanya menyebut nomor dan judul singkat klausul, lalu menjelaskannya dengan kata-kata sendiri.

Cakupan: struktur klausul 4-10 ISO/IEC 27001:2022, alur input dan output antar klausul, daftar informasi terdokumentasi wajib, dan perubahan klausul dari edisi 2013. Detail tiap klausul dibahas di Day 03-06.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menyebut ketujuh klausul wajib (4-10) beserta subklausulnya dan pertanyaan yang dijawab masing-masing.
- menggambar alur input dan output antar klausul, dari konteks sampai perbaikan, lalu kembali lagi ke konteks.
- membedakan klausul yang menetapkan proses (6.1.2, 6.1.3) dari klausul yang menjalankannya (8.2, 8.3).
- menyusun register informasi terdokumentasi wajib dan membedakan "dokumen" dari "rekaman".
- menelusuri satu insiden SOC melalui klausul 8, 9, dan 10 sampai kembali ke risk assessment di klausul 6.

## 2. Konteks singkat

Saat audit, auditor tidak membaca ISMS dari halaman pertama sampai terakhir. Ia mengambil satu benang, misalnya satu insiden, satu risiko, atau satu sasaran, lalu menariknya melewati beberapa klausul untuk melihat apakah semuanya tersambung. Analyst SOC biasanya hanya melihat satu titik di benang itu: alert dan tiket. Peta klausul membantumu melihat dari mana titik itu datang (risiko di klausul 6, proses di klausul 8) dan ke mana ia pergi (metrik di 9.1, management review di 9.3, tindakan korektif di 10.2).

Kapan peta ini berguna: saat menyiapkan bukti audit, saat menulis prosedur SOC yang harus "nyambung" ke ISMS, dan saat interview ketika ditanya "bagaimana SOC mendukung ISO 27001".

Kapan tidak cukup: peta ini tidak menjelaskan kontrol Annex A (Day 08) dan tidak memberi metodologi risiko (Day 04 dan 09). Peta hanya menunjukkan kerangka tempat semua itu menempel.

## 3. Konsep inti

### 3.1 Kenapa urutan klausulnya sama dengan ISO 9001 dan 14001

ISO mewajibkan semua standar sistem manajemen baru atau yang direvisi memakai kerangka bersama yang disebut Harmonized Structure. Kerangka ini ada di Annex SL dalam ISO/IEC Directives. Dulu namanya High Level Structure; edisi Annex SL 2021 mengganti istilahnya [S3]. Isinya adalah urutan klausul, teks inti yang identik, serta istilah dan definisi inti.

Beberapa perubahan di Annex SL 2021 kemudian muncul di 27001:2022 [S3]:

- organisasi harus menentukan persyaratan pihak berkepentingan mana yang ditangani lewat sistem manajemen (menjadi 4.2 c di 27001:2022);
- subklausul baru 6.3 tentang perencanaan perubahan;
- istilah outsourcing diganti dengan kewajiban mengendalikan proses, produk, atau layanan dari pihak eksternal (masuk ke 8.1);
- urutan klausul 10 diubah supaya continual improvement berada di depan.

Bagian klausul 4-10 yang khas keamanan informasi ada di 6.1.2 dan 6.1.3 (risk assessment, risk treatment, dan SoA), serta di 8.2 dan 8.3 yang menjalankannya. Sisanya hampir sama dengan standar sistem manajemen lain, sehingga organisasi yang sudah punya ISO 9001 bisa menggabungkan management review, internal audit, dan kontrol dokumen ke satu sistem terintegrasi.

### 3.2 Peta subklausul 27001:2022

Klausul 0-3 bersifat pengantar dan tidak diaudit. Klausul 4-10 wajib dipenuhi seluruhnya [S8].

| Klausul | Subklausul (judul singkat) | Pertanyaan yang dijawab |
|---|---|---|
| 4 Context | 4.1 organisasi dan konteksnya; 4.2 pihak berkepentingan; 4.3 scope ISMS; 4.4 ISMS | Kita siapa, siapa yang peduli, dan di mana batas ISMS? |
| 5 Leadership | 5.1 kepemimpinan dan komitmen; 5.2 kebijakan; 5.3 peran, tanggung jawab, wewenang | Siapa yang bertanggung jawab dan apa arah kebijakannya? |
| 6 Planning | 6.1.1 umum; 6.1.2 risk assessment; 6.1.3 risk treatment; 6.2 sasaran dan rencana pencapaiannya; 6.3 perencanaan perubahan | Risiko apa, bagaimana ditangani, ke mana arahnya? |
| 7 Support | 7.1 sumber daya; 7.2 kompetensi; 7.3 awareness; 7.4 komunikasi; 7.5 informasi terdokumentasi (7.5.1-7.5.3) | Apa yang dibutuhkan agar sistem bisa berjalan? |
| 8 Operation | 8.1 perencanaan dan pengendalian operasional; 8.2 menjalankan risk assessment; 8.3 menjalankan risk treatment | Apakah rencana benar-benar dijalankan? |
| 9 Performance evaluation | 9.1 monitoring, pengukuran, analisis, evaluasi; 9.2 internal audit (9.2.1 umum, 9.2.2 program audit); 9.3 management review (9.3.1 umum, 9.3.2 input, 9.3.3 hasil) | Apakah berjalan efektif, dan bagaimana kita tahu? |
| 10 Improvement | 10.1 continual improvement; 10.2 nonconformity dan corrective action | Apa yang diperbaiki dan bagaimana mencegah terulang? |

Kalau membaca versi SNI, "clause" diterjemahkan "pasal" dan "subclause" menjadi "subpasal". Misalnya, BSN menulis perubahan Amd.1:2024 sebagai perubahan "Subpasal 4.1" dan "Subpasal 4.2" [S7].

### 3.3 Alur input dan output antar klausul

Klausul tidak berdiri sendiri. Output satu klausul menjadi input klausul lain. Diagram berikut adalah interpretasi alur yang umum dipakai, bukan gambar dari standar:

```
 4.1 isu internal/eksternal  ---+
 4.2 pihak berkepentingan    ---+--> 4.3 scope --> 6.1 risiko & peluang
                                                    |
           5.1-5.3 pimpinan, kebijakan, peran       |  6.1.2 proses risk assessment
           (memayungi semua klausul)                |  6.1.3 proses treatment + SoA
                                                    |  6.2 sasaran   6.3 perubahan
           7.1-7.5 sumber daya, kompetensi,         v
           awareness, komunikasi, dokumen  --> 8.1-8.3 operasi (jalankan rencana,
           (memampukan klausul 8)                  risk assessment berkala, treatment)
                                                    |
                                                    v
                                     9.1 metrik --> 9.2 internal audit --> 9.3 management review
                                                                               |
                                                    +--------------------------+
                                                    v
                                     10.2 nonconformity & corrective action
                                     10.1 continual improvement
                                                    |
                         kembali ke 4.1/4.2 (konteks berubah?) dan 6.1 (risiko berubah?)
```

Ada empat rantai yang perlu kamu hafal karena sering dipakai auditor:

1. **Rantai konteks:** isu di 4.1 dan persyaratan di 4.2 menjadi bahan untuk scope di 4.3 dan untuk risiko serta peluang di 6.1.1. Kalau 4.1 menyebut "klien perbankan menuntut laporan insiden dalam waktu tertentu", auditor akan mencari jejak persyaratan itu di risiko, kontrol, dan prosedur IR.
2. **Rantai risiko:** proses risk assessment di 6.1.2 menghasilkan daftar risiko, lalu 6.1.3 memilih kontrol dan menuangkannya ke SoA dan risk treatment plan. Klausul 8.2 dan 8.3 membuktikan bahwa proses itu benar-benar dijalankan.
3. **Rantai bukti:** operasi di klausul 8 menghasilkan data, lalu 9.1 mengubahnya menjadi metrik. Internal audit di 9.2 menguji kesesuaian, dan management review di 9.3 mengambil keputusan.
4. **Rantai perbaikan:** keputusan dan temuan masuk ke 10.2 (perbaiki dan cari akar masalah) dan 10.1 (tingkatkan). Perubahan yang dihasilkan direncanakan lewat 6.3, lalu konteks dan risiko dievaluasi ulang.

Input management review di 9.3.2 memperlihatkan rantai ini dengan jelas. Inputnya antara lain status tindakan dari review sebelumnya, perubahan isu internal dan eksternal, perubahan kebutuhan pihak berkepentingan, tren nonconformity, hasil monitoring dan audit, pencapaian sasaran, hasil risk assessment dan status risk treatment plan, serta peluang perbaikan [S5]. Hampir setiap klausul lain menyumbang satu input ke rapat ini.

### 3.4 Klausul 6 merencanakan, klausul 8 menjalankan

Pola ini sering membingungkan pembaca pertama:

| Topik | Klausul 6 (Planning) | Klausul 8 (Operation) |
|---|---|---|
| Risk assessment | 6.1.2: tetapkan prosesnya, termasuk kriteria risiko, cara identifikasi, analisis, dan evaluasi | 8.2: jalankan risk assessment pada interval terencana dan saat ada perubahan signifikan; simpan hasilnya |
| Risk treatment | 6.1.3: tetapkan proses treatment, pilih kontrol, buat SoA dan risk treatment plan | 8.3: jalankan risk treatment plan; simpan hasilnya |
| Sasaran | 6.2: tetapkan sasaran yang terukur (bila praktis) dan rencana pencapaiannya | 8.1: rencanakan dan kendalikan proses supaya sasaran tercapai |

Konsekuensinya untuk audit: punya metodologi risiko yang bagus (6.1.2) tetapi tidak ada bukti risk assessment dijalankan tahun ini (8.2) tetap menjadi temuan. Sebaliknya, punya risk register tanpa metodologi tertulis membuat hasilnya sulit dibandingkan dari tahun ke tahun.

### 3.5 Informasi terdokumentasi wajib

Sejak 2013, standar tidak lagi memakai istilah "documents" dan "records" secara terpisah. Keduanya disebut documented information. Bahasa standar sistem manajemen ISO tetap membedakannya lewat kata kerja: "maintain" berarti informasi yang dijaga tetap mutakhir (pada praktiknya dokumen, seperti kebijakan dan scope), sedangkan "retain" berarti informasi yang disimpan sebagai bukti (pada praktiknya rekaman, seperti hasil audit).

Ringkasan konsultan menyebut sekitar 14 tempat di klausul 4-10 yang secara eksplisit mewajibkan informasi terdokumentasi [S4]:

| Klausul | Informasi terdokumentasi | Jenis |
|---|---|---|
| 4.3 | Scope ISMS | Dokumen |
| 5.2 | Kebijakan keamanan informasi | Dokumen |
| 6.1.2 | Informasi tentang proses risk assessment | Dokumen (metodologi) |
| 6.1.3 | Informasi tentang proses risk treatment | Dokumen |
| 6.1.3 d | Statement of Applicability | Dokumen |
| 6.2 | Sasaran keamanan informasi | Dokumen |
| 7.2 | Bukti kompetensi | Rekaman |
| 8.1 | Informasi secukupnya untuk yakin proses berjalan sesuai rencana | Rekaman |
| 8.2 | Hasil risk assessment | Rekaman |
| 8.3 | Hasil risk treatment | Rekaman |
| 9.1 | Bukti hasil monitoring dan pengukuran | Rekaman |
| 9.2.2 | Bukti pelaksanaan program audit dan hasil audit | Rekaman |
| 9.3.3 | Bukti hasil management review | Rekaman |
| 10.2 | Sifat nonconformity, tindakan yang diambil, dan hasil corrective action | Rekaman |

Daftar ini batas bawah. Klausul 7.5.1 juga mewajibkan informasi lain yang dianggap perlu oleh organisasi, dan kontrol Annex A yang dipilih membawa kebutuhan dokumen sendiri, misalnya prosedur operasional (kontrol 5.37). Itu dibahas di Day 08.

Perhatian: huruf sub-butir (misalnya 6.1.3 d untuk SoA) berasal dari ringkasan sekunder. Cocokkan dengan teks standar atau SNI resmi sebelum dikutip di dokumen audit.

### 3.6 Perubahan klausul dari 2013 ke 2022

Perubahan di klausul 4-10 kecil dan sebagian besar berupa penyelarasan dengan Harmonized Structure [S1][S2][S3]:

| Klausul | Perubahan 2022 | Dampak praktis |
|---|---|---|
| 4.2 | Tambahan: tentukan persyaratan pihak berkepentingan mana yang ditangani lewat ISMS | Register pihak berkepentingan butuh kolom "ditangani lewat ISMS? ya/tidak" |
| 4.4 | Eksplisit: ISMS mencakup proses yang dibutuhkan dan interaksinya | Peta proses atau diagram seperti bagian 3.3 berguna sebagai bukti |
| 5.3 | Klarifikasi: peran dikomunikasikan di dalam organisasi | Struktur peran harus diketahui, bukan hanya tertulis |
| 6.2 | Sasaran harus dipantau dan tersedia sebagai informasi terdokumentasi | Sasaran perlu pemilik, metrik, dan jadwal tinjau |
| 6.3 | Baru: perubahan pada ISMS direncanakan | Migrasi SIEM atau reorganisasi SOC perlu rencana tertulis |
| 7.4 | Butir tentang proses komunikasi disederhanakan | Kecil |
| 8.1 | Tetapkan kriteria proses dan kendalikan sesuai kriteria; kendalikan proses, produk, dan layanan dari pihak eksternal | Layanan MSSP atau SOC outsourcing masuk pengendalian operasional |
| 9.2 | Dipecah menjadi 9.2.1 dan 9.2.2 | Isi hampir sama |
| 9.3 | Dipecah menjadi 9.3.1-9.3.3; input baru: perubahan kebutuhan pihak berkepentingan | Notulen management review perlu agenda khusus untuk butir ini |
| 10 | Urutan dibalik: 10.1 continual improvement, 10.2 nonconformity | Hanya penomoran |

Soal 9.2, sumber sekunder tidak seragam: satu artikel menulis 9.2 "digabung" [S1], sedangkan yang lain menulis 9.2 dipecah [S2]. Faktanya, edisi 2013 hanya punya satu subklausul 9.2, sedangkan edisi 2022 memecahnya menjadi 9.2.1 (umum: kapan audit dijalankan dan apa yang diperiksa) dan 9.2.2 (program audit: frekuensi, metode, tanggung jawab, kriteria, scope, pemilihan auditor yang objektif, pelaporan ke manajemen) [S2][S5]. Isi persyaratannya hampir sama; yang berubah hanya pengelompokan.

### 3.7 Klausul 4-10 dan Annex A

Klausul 4-10 tidak boleh dikecualikan, sedangkan kontrol Annex A boleh dikecualikan bila alasannya sah dan tercatat di SoA. Auditor sertifikasi biasanya memastikan dulu bahwa sistem manajemennya hidup, baru menilai apakah pilihan kontrol konsisten dengan risk assessment dan SoA [S8]. Untuk SOC, artinya rule deteksi yang bagus tidak menyelamatkan audit bila rekaman management review atau internal audit tidak ada. Sebaliknya, dokumen lengkap tanpa bukti operasi (log tidak ditinjau, insiden tidak dicatat) akan gagal di klausul 8 dan 9.

## 4. Contoh dokumen / artefak (organisasi fiktif)

Organisasi fiktif yang sama dengan Day 01: PT Awan Nusantara (PT AN), penyedia hosting di Jakarta dengan 120 karyawan, SOC 24x7 di dalam scope. Semua nama, angka, dan tanggal di bawah adalah ilustrasi.

### 4.1 Peta ISMS satu halaman PT AN

| Klausul | Artefak utama PT AN | Pemilik | Frekuensi tinjau |
|---|---|---|---|
| 4.1-4.2 | Register konteks dan pihak berkepentingan (termasuk keputusan soal perubahan iklim) | ISMS Manager | Tahunan dan saat ada perubahan besar |
| 4.3-4.4 | Scope ISMS v1.0; peta proses ISMS | ISMS Manager | Tahunan |
| 5.1-5.3 | Kebijakan keamanan informasi; matriks RACI peran ISMS | Direktur Operasional | Tahunan |
| 6.1.2-6.1.3 | Metodologi risiko; risk register; SoA; risk treatment plan | ISMS Manager, risk owner | Risk register ditinjau per kuartal |
| 6.2-6.3 | Daftar sasaran beserta metriknya; formulir perencanaan perubahan ISMS | ISMS Manager | Kuartalan |
| 7.1-7.5 | Rencana pelatihan analyst; materi awareness; prosedur kontrol dokumen | HR dan Lead SOC | Tahunan |
| 8.1-8.3 | Prosedur operasional SOC; laporan risk assessment tahunan; status treatment | Lead SOC, risk owner | Sesuai jadwal |
| 9.1 | Laporan metrik bulanan (cakupan log, MTTD, MTTR) | Lead SOC | Bulanan |
| 9.2 | Program audit internal tahunan; laporan audit | Internal auditor (independen dari SOC) | Tahunan |
| 9.3 | Notulen management review | Direksi | Minimal tahunan |
| 10.1-10.2 | Register nonconformity dan corrective action | ISMS Manager | Bulanan |

**Kenapa kolom pemilik penting:** auditor menanyakan "siapa yang bertanggung jawab atas ini" untuk hampir setiap artefak, dan jawabannya harus cocok dengan peran di 5.3.

**Kenapa internal auditor dipisah dari SOC:** auditor tidak boleh mengaudit pekerjaannya sendiri. Prinsip objektivitas dan imparsialitas tercantum di 9.2.2 [S5].

### 4.2 Menelusuri satu insiden melalui klausul

Skenario fiktif: Wazuh di lab PT AN memunculkan alert brute force SSH terhadap VM pelanggan. Investigasi menemukan login berhasil memakai akun default yang lupa dinonaktifkan saat provisioning.

| Langkah | Apa yang terjadi | Klausul atau kontrol yang tersentuh | Bukti |
|---|---|---|---|
| 1 | Alert ditriage, insiden dibuka, VM diisolasi | 8.1 (prosedur operasional); kontrol 5.25 dan 5.26 | Tiket insiden, timeline |
| 2 | Log dan snapshot disimpan untuk analisis | Kontrol 5.28 pengumpulan bukti; 8.15 logging | Catatan chain of custody, hash |
| 3 | Insiden masuk laporan metrik bulanan | 9.1 | Laporan MTTD/MTTR |
| 4 | Akar masalah: checklist provisioning tidak punya langkah nonaktifkan akun default | 10.2 (nonconformity terhadap prosedur internal) | Register NC, analisis akar masalah |
| 5 | Corrective action: checklist diubah, image VM diperbaiki | 10.2; 6.3 bila perubahannya menyentuh proses ISMS | Rencana perubahan, versi checklist baru |
| 6 | Risiko "akun default pada image VM" dinilai ulang | 8.2 dan 6.1.2 | Entri risk register diperbarui |
| 7 | Ringkasan dibahas di management review | 9.3.2 (tren NC, hasil monitoring) | Notulen |
| 8 | Engineer provisioning dilatih ulang | 7.2 dan 7.3 | Rekaman pelatihan |

Satu alert menyentuh lima klausul dan beberapa kontrol. Karena itu auditor senang memilih insiden sebagai benang audit: dari satu tiket ia bisa menguji apakah rantai bukti dan rantai perbaikan benar-benar tersambung.

### 4.3 Cuplikan register informasi terdokumentasi

```
ID      Judul                         Klausul  Jenis     Pemilik        Versi  Disetujui    Retensi
DOC-01  Scope ISMS                    4.3      maintain  ISMS Manager   1.0    2026-01-15   sampai diganti
DOC-02  Kebijakan Keamanan Informasi  5.2      maintain  Dir. Ops       1.2    2026-01-15   sampai diganti
DOC-05  Statement of Applicability    6.1.3d   maintain  ISMS Manager   1.1    2026-03-02   sampai diganti
REC-03  Laporan metrik SOC bulanan    9.1      retain    Lead SOC       -      -            3 tahun
REC-07  Notulen management review     9.3.3    retain    Sekretaris     -      -            3 tahun
REC-09  Register NC dan CA            10.2     retain    ISMS Manager   -      -            3 tahun
```

Cara membaca: baris DOC punya versi dan tanggal persetujuan karena isinya berubah dan harus dikendalikan (7.5.2, 7.5.3). Baris REC tidak punya versi karena rekaman tidak boleh diubah setelah dibuat; yang diatur adalah retensi dan aksesnya. Angka retensi tiga tahun adalah pilihan fiktif PT AN, bukan ketentuan standar. Retensi nyata bergantung pada siklus sertifikasi, kontrak, dan regulasi.

## 5. Lab praktik

Latihan berupa dokumen untuk organisasi fiktifmu dari Day 01. Simpan di `ISO27001-note/latihan/day02-<nama-org-fiktif>.md`.

1. Buat peta ISMS satu halaman seperti bagian 4.1 untuk organisasimu. Setiap baris wajib berisi pemilik dan frekuensi tinjau.
2. Gambar ulang diagram bagian 3.3 dengan tanganmu sendiri, lalu tambahkan nama artefak organisasimu di setiap kotak.
3. Susun register informasi terdokumentasi berisi minimal 10 baris. Tandai setiap baris sebagai `maintain` atau `retain`, dan tulis retensi yang kamu pilih beserta alasannya.
4. Telusuri dua skenario dengan format tabel bagian 4.2:
   - skenario A: satu insiden dari lab Splunk atau Wazuh-mu (cukup alert fiktif seperti brute force atau malware terdeteksi);
   - skenario B: satu perubahan, yaitu SOC memindahkan sebagian sumber log dari Splunk ke Wazuh. Tunjukkan di mana 6.3 dan 8.1 berperan, dan risiko apa yang harus dinilai sebelum migrasi (misalnya celah logging selama cutover).
5. Untuk setiap klausul 4-10, tulis satu pertanyaan yang menurutmu akan diajukan auditor kepada Lead SOC.
6. Hubungkan ke lab: tentukan dua laporan atau dashboard dari Splunk atau Wazuh lab yang bisa menjadi bukti 9.1. Tulis nama laporan, metrik yang ditampilkan, dan frekuensinya. Tidak perlu menjalankan apa pun dulu; cukup rancangannya.

**Hasil yang seharusnya teramati:** dokumen 2-3 halaman yang menunjukkan setiap klausul punya artefak dan pemilik, serta dua jejak skenario yang kembali ke klausul 6.

**Hasil yang sebaiknya tersimpan:**
- Ketujuh klausul (4-10) muncul di peta, tanpa ada yang kosong.
- Register dokumen memuat semua item di tabel bagian 3.5.
- Skenario A berakhir di 9.3 dan 10.2, bukan berhenti di "tiket ditutup".
- Skenario B menyebut 6.3 dan menilai risiko sebelum perubahan dijalankan.
- Tidak ada kalimat yang disalin dari teks standar.

**Variasi tantangan:** buat versi PDCA dari peta yang sama (Plan 4-6, Do 7-8, Check 9, Act 10). Lalu tulis satu paragraf tentang klausul yang sulit dimasukkan ke satu fase (misalnya 5 Leadership yang memayungi semuanya) dan alasannya.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Bingung kenapa risk assessment muncul di 6 dan 8 | Belum membedakan "menetapkan proses" dan "menjalankan proses" | Pakai tabel bagian 3.4; tanyakan "ini metodologi atau hasil?" |
| Register dokumen membengkak menjadi ratusan baris | Semua file dianggap documented information wajib | Pisahkan wajib (bagian 3.5), wajib karena kontrol, dan pilihan organisasi |
| Jejak insiden berhenti di tiket ditutup | Tidak menghubungkan operasi dengan evaluasi dan perbaikan | Tambahkan langkah 9.1, 9.3, dan 10.2; tanya "pelajaran apa yang masuk ke risiko?" |
| Tidak yakin apakah perubahan butuh 6.3 | 6.3 hanya untuk perubahan pada ISMS | Perubahan teknis biasa diatur kontrol 8.32 change management; perubahan proses, scope, atau peran ISMS masuk 6.3 |

## 7. Kesalahan umum dan jebakan

- Menganggap Annex A adalah "isi utama" ISO 27001. Klausul 4-10 yang wajib seluruhnya; Annex A dipilih berdasarkan risiko [S8].
- Mengira management review cukup berupa rapat tanpa notulen. 9.3.3 meminta bukti hasilnya, dan hasilnya harus berisi keputusan.
- Melupakan input 9.3.2 c tentang perubahan kebutuhan pihak berkepentingan. Konsultan URM melaporkan butir ini sering terlewat dalam audit 27001:2022 [S6].
- Program audit internal yang tidak menunjukkan cakupan seluruh klausul dan kontrol dalam satu siklus. Ini juga temuan yang sering dilaporkan [S6].
- Menyamakan 6.3 dengan change management teknis. Kontrol 8.32 mengatur perubahan pada fasilitas dan sistem pemrosesan informasi; 6.3 mengatur perubahan pada sistem manajemennya.

## 8. Catatan terkini

- ISO/IEC 27001:2022 dengan Amd 1:2024 masih edisi berlaku per 2026-10-08. Amd 1 menambah satu kalimat di 4.1 (organisasi menentukan apakah perubahan iklim relevan) dan satu catatan di 4.2 [S7]. Detail di Day 03.
- SNI ISO/IEC 27001:2022/Amd.1:2024 sudah ditetapkan BSN pada 2024. Sekretariat komite teknisnya (Komtek 35-04) berada di BSSN [S7].
- ISO/IEC 27000:2026 terbit Juli 2026 (lihat Day 01). Per Oktober 2026 belum ada pengumuman edisi baru 27001; pantau status standar di katalog ISO.
- Artikel URM (April 2026) merangkum temuan audit 27001:2022 yang sering muncul, termasuk program audit internal yang tidak memakai hasil risk assessment untuk menentukan prioritas, dan input 9.3.2 c yang terlewat [S6].

## 9. Cheat sheet

```
KLAUSUL 4-10 (semua wajib, tidak bisa dikecualikan)
4 Context      4.1 isu | 4.2 pihak berkepentingan (+ c: mana yang ditangani ISMS) | 4.3 scope | 4.4 ISMS + proses
5 Leadership   5.1 komitmen | 5.2 kebijakan | 5.3 peran, tanggung jawab, wewenang
6 Planning     6.1.1 umum | 6.1.2 proses RA | 6.1.3 proses RT + SoA + RTP | 6.2 sasaran | 6.3 perubahan (baru 2022)
7 Support      7.1 sumber daya | 7.2 kompetensi | 7.3 awareness | 7.4 komunikasi | 7.5 informasi terdokumentasi
8 Operation    8.1 kendali operasional | 8.2 jalankan RA | 8.3 jalankan RT
9 Evaluation   9.1 metrik | 9.2.1-9.2.2 audit internal | 9.3.1-9.3.3 management review
10 Improvement 10.1 continual improvement | 10.2 NC + corrective action  (urutan dibalik di 2022)

RANTAI: konteks -> scope -> risiko -> kontrol/SoA -> operasi -> metrik -> audit -> review -> NC/CA -> (ulang)
6 = menetapkan proses   8 = menjalankan proses dan menyimpan hasilnya
maintain = dokumen hidup (versi, persetujuan)   retain = rekaman bukti (tidak diubah, ada retensi)
Wajib dokumen: 4.3 5.2 6.1.2 6.1.3 SoA 6.2 | rekaman: 7.2 8.1 8.2 8.3 9.1 9.2.2 9.3.3 10.2
SNI: clause = pasal, subclause = subpasal
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Cloud Security Alliance (penulis A-LIGN): What's the difference between ISO 27001:2013 and ISO 27001:2022 | https://cloudsecurityalliance.org/articles/what-s-the-difference-between-iso-27001-2013-and-iso-27001-2022 | sekunder | 2023-02-10; diakses 2026-10-08 | Sedang. Deskripsi perubahan 9.2 tidak cocok dengan S2 (lihat bagian 3.6) |
| S2 | HighTable: ISO 27001 2013 vs 2022 explained | https://hightable.io/iso-27001-2013-vs-2022/ | sekunder (konsultan) | diperbarui 2026-09-14; diakses 2026-10-08 | Sedang. Rincian pemecahan 9.2 dan 9.3, pertukaran 10.1/10.2 |
| S3 | IAF news: New 2021 edition of Annex SL for management system standards | https://iaf.news/2021/07/02/new-2021-edition-of-annex-sl-for-management-system-standards/ | sekunder (situs berita IAF) | 2021-07-02 (lebih dari 3 tahun, tetapi topiknya stabil); diakses 2026-10-08 | Sedang-tinggi. Menjelaskan perubahan Annex SL yang diturunkan ke 27001:2022 |
| S4 | TCSA: ISO/IEC 27001:2022 mandatory documents | https://www.tcsa.in/frameworks/iso-27001/mandatory-documents | sekunder (konsultan) | tanpa tanggal; diakses 2026-10-08 | Sedang. Daftar sekitar 14 item; konsisten dengan ringkasan konsultan lain |
| S5 | Hicomply: ISO 27001:2022 clause 9.3 management review | https://hicomply.com/hub/iso-27001-clause-9-3-management-review-2022 | sekunder (vendor) | diakses 2026-10-08 | Sedang. Ringkasan isi 9.2.2 dan 9.3.2; cocokkan butirnya dengan teks standar |
| S6 | URM Consulting: Common issues identified during audits of ISO 27001:2022 | https://urmconsulting.com/blog/common-issues-identified-during-audits-of-iso-27001-2022 | sekunder (praktisi audit) | 2026-04-09; diakses 2026-10-08 | Sedang. Pengalaman satu konsultan, bukan statistik |
| S7 | BSN: RSNI3 ISO/IEC 27001:2022/Amd.1:2024 | https://bsn.go.id/uploads/attachment/rsni_iso_iec_27001-2022-amd1_1.pdf | primer | 2024; diakses 2026-10-08 | Tinggi. Prakata, isi amandemen dua bahasa, susunan komite |
| S8 | Elevate Consult: ISO 27001 Annex A vs clauses 4-10 | https://elevateconsult.com/insights/iso-27001-annex-a-vs-clauses-4-10-understanding-the-key-differences-for-non-technical-teams/ | sekunder (konsultan) | diakses 2026-10-08 | Sedang. Klaim "klausul 4-10 tidak bisa dikecualikan" adalah fakta stabil yang juga dibahas di Day 01 |

**Catatan sumber:** struktur subklausul dan daftar informasi terdokumentasi wajib disusun dari beberapa ringkasan sekunder yang saling cocok, bukan dari teks standar. Huruf sub-butir (6.1.3 d, 9.3.2 c) dan daftar input management review perlu dicocokkan dengan teks ISO/IEC 27001:2022 atau SNI resmi sebelum dikutip di dokumen audit. Klaim tentang temuan audit yang sering muncul [S6] adalah pengalaman satu konsultan, bukan statistik.
