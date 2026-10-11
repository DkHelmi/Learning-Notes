---
day: 02
title: 'Peta klausul 4-10: gambaran satu halaman dan hubungan antar klausul'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 27001:2022 edisi 3 + Amd 1:2024; SNI ISO/IEC 27001:2022/Amd.1:2024; Annex SL edisi 2021 (Harmonized Structure)'
---

# Day 02: Peta klausul 4-10 dan hubungan antar klausul

Cakupan: klausul 4-10 ISO/IEC 27001:2022 sebagai satu rantai input dan output, cara auditor menelusuri satu benang lewat beberapa klausul, beda klausul yang menetapkan dan menjalankan proses, daftar informasi terdokumentasi wajib, dan perubahan klausul dari edisi 2013.

## Ide inti

Klausul 4-10 bukan tujuh bab yang berdiri sendiri. Hasil satu klausul menjadi bahan klausul berikutnya: konteks organisasi menentukan risiko, risiko menentukan rencana, rencana dijalankan, hasilnya diukur dan ditinjau pimpinan, temuan diperbaiki, lalu konteks dan risiko dinilai ulang. Auditor menguji ISMS dengan mengambil satu benang (satu insiden, satu risiko, atau satu sasaran) lalu menariknya melewati beberapa klausul untuk melihat apakah ada yang putus.

Kamu sudah melakukan hal yang sama saat investigasi. Dari satu alert, kamu pivot ke proxy log, EDR, dan log AD sampai ceritanya utuh. Kalau satu log source hilang, cerita putus di situ. Auditor melakukannya dengan artefak ISMS: dari tiket insiden ke laporan metrik bulanan, ke notulen rapat tinjauan pimpinan, ke catatan perbaikan, sampai ke daftar risiko. Analyst SOC biasanya hanya melihat satu titik di benang itu, yaitu alert dan tiket. Day ini menunjukkan dari mana titik itu datang dan ke mana ia pergi.

Peta kasarnya:

```
4 Konteks: siapa kita, siapa yang peduli, apa batas ISMS
  -> 6 Rencana: risiko apa, kontrol apa, sasaran apa
  -> 8 Operasi: rencana dijalankan               <- di sini SOC bekerja
  -> 9 Evaluasi: diukur, diaudit internal, ditinjau pimpinan
  -> 10 Perbaikan: temuan diperbaiki
  -> kembali ke 4 (konteks berubah?) dan 6 (risiko berubah?)

5 Kepemimpinan dan 7 Dukungan menopang seluruh rantai
```

Situasi yang dipakai sepanjang Day ini: dua minggu sebelum audit internal, auditor internal PT Awan Nusantara (PT AN, penyedia hosting fiktif dari Day 01) mengirim pesan ke Lead SOC:

> "Saya akan mengambil insiden brute force SSH akhir Agustus sebagai sampel. Tolong siapkan jejaknya, dari tiket sampai keputusan di management review."

Lead SOC lalu bertanya padamu: "Selain tiket, apa lagi yang akan dia minta, dan di mana kita menyimpannya?"

Untuk menjawabnya, kamu perlu tahu klausul mana yang disentuh insiden itu, artefak apa yang dihasilkan di tiap klausul, dan artefak mana yang wajib ada menurut standar.

**Kapan relevan:** menyiapkan bukti audit, menulis prosedur SOC yang tersambung ke ISMS, atau menjawab "bagaimana SOC mendukung ISO 27001" di interview.
**Kapan bukan jawaban:** peta ini tidak merinci isi tiap klausul, kontrol Annex A, atau metodologi risiko. Isi klausul dibahas di Day 03-06, kontrol di Day 08, dan risiko di Day 04 dan 09.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Tabel ini memuat istilah ISO yang muncul di Day ini. Kolom padanan memakai analogi SOC yang sama di semua Day; istilah dari Day 01 (ISMS, risiko, kontrol, Annex A, SoA, scope, audit, nonconformity) tidak diulang di sini.

| Istilah | Arti singkat | Padanan di SOC |
|---|---|---|
| Klausul dan subklausul (SNI: pasal dan subpasal) | Bab dan sub-bab persyaratan di 27001, misalnya klausul 9 dan subklausul 9.2 | Bab dan sub-bab SOP SOC |
| Harmonized Structure (dulu Annex SL atau High Level Structure) | Kerangka klausul dan teks inti yang sama untuk semua standar sistem manajemen ISO | Skema data bersama seperti CIM |
| Pihak berkepentingan (interested parties) | Pihak yang punya kebutuhan atau harapan terhadap ISMS: klien, regulator, pemilik, karyawan | Stakeholder yang meminta laporan dari SOC |
| Risk assessment | Proses mengidentifikasi, menganalisis, dan mengevaluasi risiko | Menyusun dan memperbarui threat model |
| Risk treatment | Proses memilih cara menangani risiko dan kontrolnya | Memutuskan detection, hardening, atau prosedur apa yang dibuat |
| Risk treatment plan (RTP) | Rencana pelaksanaan treatment: kontrol apa, siapa pemiliknya, kapan selesai | Backlog detection engineering dengan pemilik dan tenggat |
| Sasaran keamanan informasi (objectives) | Target terukur yang ingin dicapai ISMS | Target MTTD, MTTR, atau cakupan log |
| Informasi terdokumentasi (documented information) | Informasi yang wajib dikendalikan dan disimpan organisasi | Isi repo SOC, tiket, dan laporan |
| Maintain vs retain | Dijaga tetap mutakhir (dokumen) vs disimpan sebagai bukti (rekaman) | Rule di repo vs log dan tiket |
| Internal audit | Audit oleh organisasi sendiri untuk menguji apakah ISMS sesuai dan efektif | QA tiket oleh tim di luar shift yang diperiksa |
| Management review | Tinjauan berkala oleh pimpinan atas kinerja dan arah ISMS | Rapat review operasi SOC bulanan bersama pimpinan |
| Corrective action | Tindakan menghilangkan akar masalah supaya nonconformity tidak terulang | Perbaikan root cause setelah post-incident review |
| Perencanaan perubahan (6.3) | Perubahan pada ISMS itu sendiri harus direncanakan | Rencana migrasi SIEM atau perubahan proses triage |

### 1.1 Tujuh klausul, tujuh pertanyaan

Saat menyiapkan jejak insiden akhir Agustus itu, hal pertama yang dibutuhkan Lead SOC adalah tahu artefak mana masuk klausul mana. Untuk itu cukup diingat bahwa setiap klausul menjawab satu pertanyaan.

Klausul 0-3 bersifat pengantar; klausul 4-10 wajib dipenuhi seluruhnya [S8][S9]. Tabel berikut adalah peta subklausulnya. Baca kolom terakhir dulu, lalu kolom subklausul saat butuh nomor yang tepat.

| Klausul | Subklausul (judul singkat) | Pertanyaan yang dijawab |
|---|---|---|
| 4 Context | 4.1 organisasi dan konteksnya; 4.2 pihak berkepentingan; 4.3 scope ISMS; 4.4 ISMS | Kita siapa, siapa yang peduli, dan di mana batas ISMS? |
| 5 Leadership | 5.1 kepemimpinan dan komitmen; 5.2 kebijakan; 5.3 peran, tanggung jawab, wewenang | Siapa yang bertanggung jawab dan apa arah kebijakannya? |
| 6 Planning | 6.1.1 umum; 6.1.2 risk assessment; 6.1.3 risk treatment; 6.2 sasaran dan rencana pencapaiannya; 6.3 perencanaan perubahan | Risiko apa, bagaimana ditangani, ke mana arahnya? |
| 7 Support | 7.1 sumber daya; 7.2 kompetensi; 7.3 awareness; 7.4 komunikasi; 7.5 informasi terdokumentasi (7.5.1-7.5.3) | Apa yang dibutuhkan agar sistem bisa berjalan? |
| 8 Operation | 8.1 perencanaan dan pengendalian operasional; 8.2 menjalankan risk assessment; 8.3 menjalankan risk treatment | Apakah rencana benar-benar dijalankan? |
| 9 Performance evaluation | 9.1 monitoring, pengukuran, analisis, evaluasi; 9.2 internal audit (9.2.1 umum, 9.2.2 program audit); 9.3 management review (9.3.1 umum, 9.3.2 input, 9.3.3 hasil) | Apakah berjalan efektif, dan bagaimana kita tahu? |
| 10 Improvement | 10.1 continual improvement; 10.2 nonconformity dan corrective action | Apa yang diperbaiki dan bagaimana mencegah terulang? |

Di versi SNI, "clause" menjadi "pasal" dan "subclause" menjadi "subpasal", misalnya "Subpasal 4.1" di Amd.1:2024 [S7]. Kalau dokumen ISMS organisasimu memakai SNI, istilah itu yang akan kamu temui.

### 1.2 Kenapa urutannya sama dengan ISO 9001

Direktur PT AN pernah bertanya: "Kita sudah punya ISO 9001. Apa management review dan audit internal harus dibuat ulang untuk ISO 27001?" Jawabannya tidak, dan alasannya ada di cara ISO menyusun standar.

ISO mewajibkan standar sistem manajemen baru atau yang direvisi memakai kerangka bersama di Annex SL (bagian dari ISO/IEC Directives). Edisi 2021 menyebut kerangka itu Harmonized Structure; materi lama menyebutnya High Level Structure. Isinya urutan klausul, teks inti yang identik, serta istilah dan definisi inti [S3].

Hubungannya mirip CIM di Splunk. Karena semua data memakai nama field yang sama, satu dashboard bisa membaca log dari banyak vendor. Karena semua standar sistem manajemen memakai kerangka yang sama, satu proses management review, audit internal, dan kontrol dokumen bisa melayani ISO 9001 dan ISO 27001 sekaligus dalam satu sistem terintegrasi.

Batas analoginya: yang seragam hanya kerangka dan teks inti. Bagian yang khas keamanan informasi ada di 6.1.2, 6.1.3, 8.2, dan 8.3. Sisanya hampir sama dengan standar sistem manajemen lain.

### 1.3 Alur input dan output antar klausul

Kembali ke pesan auditor. Ia tidak meminta "dokumen klausul 9". Ia meminta jejak, karena yang ingin dilihat adalah apakah output satu klausul benar-benar menjadi input klausul lain. Diagram berikut memperlihatkan aliran itu; statusnya interpretasi umum, bukan gambar dari standar:

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

Auditor biasanya menarik salah satu dari empat rantai berikut. Insiden akhir Agustus PT AN melewati rantai bukti dan rantai perbaikan.

1. **Rantai konteks:** isu 4.1 dan persyaratan 4.2 menjadi bahan scope 4.3 dan risiko 6.1.1. Bila 4.1 menyebut "klien perbankan menuntut laporan insiden dalam tenggat tertentu", auditor mencari jejaknya di risiko, kontrol, dan prosedur IR.
2. **Rantai risiko:** 6.1.2 menghasilkan daftar risiko, 6.1.3 memilih kontrol ke SoA dan risk treatment plan, dan 8.2 serta 8.3 membuktikan keduanya dijalankan.
3. **Rantai bukti:** operasi klausul 8 menghasilkan data, 9.1 menjadikannya metrik, 9.2 menguji kesesuaian, dan 9.3 mengambil keputusan.
4. **Rantai perbaikan:** keputusan dan temuan masuk ke 10.2 dan 10.1, perubahan pada ISMS direncanakan lewat 6.3, lalu konteks dan risiko dievaluasi ulang.

Di rantai bukti, audit internal sendiri harus terencana. Subklausul 9.2.2 meminta program audit yang menetapkan frekuensi, metode, tanggung jawab, persyaratan perencanaan, dan pelaporan, ditambah kriteria dan scope tiap audit, pemilihan auditor yang objektif, dan pelaporan hasil ke manajemen terkait [S5]. Karena itu auditor internal PT AN berasal dari luar SOC.

### 1.4 Management review: tempat semua rantai bertemu

Ujung permintaan auditor adalah "keputusan di management review". Rapat ini mirip review operasi SOC bulanan bersama pimpinan, tetapi yang dibahas seluruh ISMS dan bahan rapatnya ditetapkan standar.

Subklausul 9.3.2 menetapkan tujuh input [S5][S10]. Tabel berikut menambahkan kolom asal setiap input (interpretasi, bukan teks standar), supaya terlihat bahwa ketujuh input itu adalah ujung dari rantai di bagian 1.3.

| Butir | Input management review | Datang dari |
|---|---|---|
| a | Status tindakan dari management review sebelumnya | 9.3 periode lalu |
| b | Perubahan isu internal dan eksternal yang relevan dengan ISMS | 4.1 |
| c | Perubahan kebutuhan dan harapan pihak berkepentingan yang relevan dengan ISMS | 4.2 |
| d | Umpan balik kinerja keamanan informasi: tren nonconformity dan corrective action, hasil monitoring dan pengukuran, hasil audit, pencapaian sasaran | 10.2, 9.1, 9.2, 6.2 |
| e | Umpan balik dari pihak berkepentingan | 4.2 |
| f | Hasil risk assessment dan status risk treatment plan | 8.2, 8.3 |
| g | Peluang perbaikan berkelanjutan | 10.1 |

Insiden akhir Agustus PT AN masuk lewat butir d (hasil monitoring dan tren nonconformity). Butir c baru ada di edisi 2022 dan sering terlewat di agenda rapat (bagian 5).

### 1.5 Klausul 6 menetapkan, klausul 8 menjalankan

Auditor PT AN bisa mengajukan dua permintaan yang terdengar mirip: "tunjukkan metodologi risiko kalian" dan "tunjukkan risk assessment tahun ini". Yang pertama ditanyakan ke klausul 6, yang kedua ke klausul 8.

Analoginya playbook dan tiket. Menulis playbook dan kriteria severity adalah pekerjaan menetapkan proses. Menjalankan playbook saat alert datang dan menyimpan tiketnya adalah pekerjaan menjalankan proses. Tabel berikut memisahkan keduanya untuk tiga topik; cari kata "tetapkan" di kolom tengah dan "jalankan" di kolom kanan.

| Topik | Klausul 6 (Planning) | Klausul 8 (Operation) |
|---|---|---|
| Risk assessment | 6.1.2: tetapkan prosesnya, termasuk kriteria risiko, cara identifikasi, analisis, dan evaluasi | 8.2: jalankan risk assessment pada interval terencana dan saat ada perubahan signifikan; simpan hasilnya |
| Risk treatment | 6.1.3: tetapkan proses treatment, pilih kontrol, buat SoA (butir d) dan risk treatment plan (butir e) | 8.3: jalankan risk treatment plan; simpan hasilnya |
| Sasaran | 6.2: tetapkan sasaran yang terukur (bila praktis) dan rencana pencapaiannya | 8.1: rencanakan dan kendalikan proses supaya persyaratan dan rencana klausul 6 terpenuhi |

Keduanya diaudit terpisah. Metodologi yang bagus (6.1.2) tanpa bukti risk assessment dijalankan tahun ini (8.2) tetap menjadi temuan. Sebaliknya, risk register tanpa metodologi tertulis membuat hasil sulit dibandingkan antar tahun.

### 1.6 Informasi terdokumentasi: dokumen dan rekaman

Pertanyaan kedua Lead SOC adalah "di mana kita menyimpannya". Untuk itu perlu dibedakan dua jenis informasi yang diperlakukan sangat berbeda.

Analoginya repo rule dan log. Rule deteksi di repo terus diperbarui, berversi, dan perubahan harus di-review. Log dan tiket tidak boleh diubah setelah tercatat; yang diatur adalah berapa lama disimpan dan siapa yang boleh mengakses.

Sejak 2013, standar tidak lagi memisahkan "documents" dan "records"; keduanya disebut documented information. Di lapangan pembagiannya tetap dipakai: informasi yang dijaga tetap mutakhir ("maintain") diperlakukan sebagai dokumen, sedangkan informasi yang disimpan sebagai bukti ("retain") diperlakukan sebagai rekaman. Edisi 2022 banyak memakai rumusan "tersedia sebagai informasi terdokumentasi", jadi kolom "Jenis" di bawah adalah klasifikasi praktis.

Tabel berikut memuat tempat di klausul 4-10 yang secara eksplisit meminta informasi terdokumentasi [S4][S9]. Pakai tabel ini sebagai daftar periksa minimum saat menyusun register dokumen.

| Klausul | Informasi terdokumentasi | Jenis |
|---|---|---|
| 4.3 | Scope ISMS | Dokumen |
| 5.2 | Kebijakan keamanan informasi | Dokumen |
| 6.1.2 | Informasi tentang proses risk assessment (metodologi, kriteria) | Dokumen |
| 6.1.3 | Informasi tentang proses risk treatment | Dokumen |
| 6.1.3 d | Statement of Applicability | Dokumen |
| 6.2 | Sasaran keamanan informasi | Dokumen |
| 7.2 | Bukti kompetensi | Rekaman |
| 7.5.1 b | Informasi lain yang dinilai organisasi perlu untuk efektivitas ISMS | Keduanya |
| 8.1 | Informasi secukupnya untuk yakin proses berjalan sesuai rencana | Rekaman |
| 8.2 | Hasil risk assessment | Rekaman |
| 8.3 | Hasil risk treatment | Rekaman |
| 9.1 | Bukti hasil monitoring dan pengukuran | Rekaman |
| 9.2.2 | Bukti pelaksanaan program audit dan hasil audit | Rekaman |
| 9.3.3 | Bukti hasil management review | Rekaman |
| 10.2 | Sifat nonconformity, tindakan yang diambil, dan hasil corrective action | Rekaman |

Risk treatment plan dirumuskan di 6.1.3 e dan hasilnya disimpan di 8.3, jadi di praktik selalu terdokumentasi [S4]. Daftar ini batas bawah: butir 7.5.1 b membuka ruang untuk dokumen tambahan, dan kontrol Annex A yang dipilih membawa kebutuhan dokumen sendiri, misalnya prosedur operasional terdokumentasi (kontrol 5.37, dibahas di Day 08).

### 1.7 Klausul tidak bisa dikecualikan, kontrol bisa

Day 01 sudah membedakan klausul yang wajib semua dari kontrol Annex A yang dipilih berdasarkan risiko. Akibatnya untuk peta ini: klausul 4-10 tidak boleh dikecualikan, sedangkan kontrol Annex A boleh dikecualikan bila alasannya sah dan tercatat di SoA [S8].

Dua hal mengikuti dari aturan itu. Rule deteksi yang bagus tidak menyelamatkan audit bila rekaman management review atau internal audit tidak ada. Sebaliknya, dokumen lengkap tanpa bukti operasi (log tidak ditinjau, insiden tidak dicatat) gagal di klausul 8 dan 9.

## 2. Contoh dokumen / artefak (organisasi fiktif)

Organisasi fiktif dari Day 01: PT Awan Nusantara (PT AN), penyedia hosting di Jakarta, SOC 24x7 di dalam scope. Semua isi di bawah ilustrasi.

### 2.1 Peta ISMS satu halaman PT AN

Peta ini adalah jawaban untuk "di mana kita menyimpannya": satu baris per klausul, dengan artefak, pemilik, dan frekuensi tinjau.

| Klausul | Artefak utama PT AN | Pemilik | Frekuensi tinjau |
|---|---|---|---|
| 4.1-4.2 | Register konteks (termasuk keputusan iklim) dan pihak berkepentingan | ISMS Manager | Tahunan dan saat ada perubahan besar |
| 4.3-4.4 | Scope ISMS v1.0; peta proses ISMS | ISMS Manager | Tahunan |
| 5.1-5.3 | Kebijakan keamanan informasi; matriks RACI peran ISMS | Direktur Operasional | Tahunan |
| 6.1.2-6.1.3 | Metodologi risiko; risk register; SoA; risk treatment plan | ISMS Manager, risk owner | Register per kuartal |
| 6.2-6.3 | Sasaran dan metriknya; formulir perencanaan perubahan | ISMS Manager | Kuartalan |
| 7.1-7.5 | Rencana pelatihan analyst; materi awareness; prosedur kontrol dokumen | HR dan Lead SOC | Tahunan |
| 8.1-8.3 | Prosedur operasional SOC; laporan risk assessment; status treatment | Lead SOC, risk owner | Sesuai jadwal |
| 9.1 | Laporan metrik bulanan (cakupan log, MTTD, MTTR) | Lead SOC | Bulanan |
| 9.2 | Program audit internal; laporan audit | Internal auditor (di luar SOC) | Tahunan |
| 9.3 | Notulen management review | Direksi | Minimal tahunan |
| 10.1-10.2 | Register nonconformity dan corrective action | ISMS Manager | Bulanan |

Pemilik artefak harus cocok dengan peran di 5.3. Internal auditor dipisah dari SOC karena 9.2.2 meminta audit yang objektif dan imparsial [S5].

### 2.2 Menelusuri insiden akhir Agustus melalui klausul

Ini jejak yang diminta auditor di bagian Ide inti. Wazuh PT AN memunculkan alert brute force SSH ke VM pelanggan. Investigasi menemukan login berhasil memakai akun default yang lupa dinonaktifkan saat provisioning.

| Langkah | Apa yang terjadi | Klausul atau kontrol yang tersentuh | Bukti |
|---|---|---|---|
| 1 | Alert ditriage, insiden dibuka, VM diisolasi | 8.1 (prosedur operasional); kontrol 5.25 dan 5.26 | Tiket insiden, timeline |
| 2 | Log dan snapshot disimpan untuk analisis | Kontrol 5.28 pengumpulan bukti; 8.15 logging | Catatan chain of custody, hash |
| 3 | Insiden masuk laporan metrik bulanan | 9.1 | Laporan MTTD/MTTR |
| 4 | Akar masalah: checklist provisioning tanpa langkah nonaktifkan akun default | 10.2 (nonconformity prosedur internal) | Register NC, analisis akar masalah |
| 5 | Corrective action: checklist diubah, image VM diperbaiki | 10.2; 6.3 bila perubahannya menyentuh proses ISMS | Rencana perubahan, versi checklist baru |
| 6 | Risiko "akun default pada image VM" dinilai ulang | 8.2 dan 6.1.2 | Entri risk register diperbarui |
| 7 | Ringkasan dibahas di management review | 9.3.2 d (tren NC, hasil monitoring) | Notulen |
| 8 | Engineer provisioning dilatih ulang | 7.2 dan 7.3 | Rekaman pelatihan |

Satu alert menyentuh lima klausul dan beberapa kontrol, sehingga auditor senang memilih insiden sebagai benang audit. Jawaban untuk Lead SOC: selain tiket, siapkan catatan chain of custody, laporan metrik Juli, entri register NC, versi checklist baru, entri risk register, notulen management review, dan rekaman pelatihan ulang.

### 2.3 Cuplikan register informasi terdokumentasi

Register ini menerapkan pembedaan dokumen dan rekaman di bagian 1.6. Perhatikan kolom versi dan retensi.

```
ID      Judul                         Klausul  Jenis     Pemilik        Versi  Disetujui    Retensi
DOC-01  Scope ISMS                    4.3      maintain  ISMS Manager   1.0    2026-01-15   sampai diganti
DOC-02  Kebijakan Keamanan Informasi  5.2      maintain  Dir. Ops       1.2    2026-01-15   sampai diganti
DOC-05  Statement of Applicability    6.1.3d   maintain  ISMS Manager   1.1    2026-03-02   sampai diganti
REC-03  Laporan metrik SOC bulanan    9.1      retain    Lead SOC       -      -            3 tahun
REC-07  Notulen management review     9.3.3    retain    Sekretaris     -      -            3 tahun
REC-09  Register NC dan CA            10.2     retain    ISMS Manager   -      -            3 tahun
```

Baris DOC punya versi dan persetujuan karena isinya berubah dan harus dikendalikan (7.5.2, 7.5.3). Baris REC tidak punya versi karena rekaman tidak diubah; yang diatur retensi dan aksesnya. Retensi tiga tahun adalah pilihan fiktif PT AN, bukan ketentuan standar.

## 3. Lab praktik

Latihan dokumen untuk organisasi fiktifmu dari Day 01.

1. Buat peta ISMS satu halaman seperti bagian 2.1. Setiap baris wajib berisi pemilik dan frekuensi tinjau.
2. Gambar ulang diagram bagian 1.3 dan isi setiap kotak dengan nama artefak organisasimu.
3. Susun register informasi terdokumentasi minimal 10 baris, bertanda `maintain` atau `retain`, dengan retensi dan alasannya.
4. Telusuri dua skenario dengan format tabel bagian 2.2:
   - skenario A: satu insiden dari lab Splunk atau Wazuh-mu (cukup alert fiktif seperti brute force atau malware terdeteksi);
   - skenario B: SOC memindahkan sebagian sumber log dari Splunk ke Wazuh. Tunjukkan peran 6.3 dan 8.1 serta risiko yang dinilai sebelum migrasi (misalnya celah logging saat cutover).
5. Untuk setiap klausul 4-10, tulis satu pertanyaan auditor kepada Lead SOC.
6. Hubungkan ke lab: rancang dua laporan atau dashboard Splunk atau Wazuh yang bisa menjadi bukti 9.1. Tulis nama laporan, metrik, dan frekuensinya.

**Hasil yang sebaiknya tersimpan:**
- Dokumen 2-3 halaman di `latihan/day02-<nama-org-fiktif>.md`.
- Ketujuh klausul (4-10) muncul di peta, masing-masing dengan artefak dan pemilik.
- Register dokumen memuat semua item di tabel bagian 1.6.
- Skenario A berakhir di 9.3 dan 10.2 lalu kembali ke risk assessment, bukan berhenti di "tiket ditutup".
- Skenario B menyebut 6.3 dan menilai risiko sebelum perubahan dijalankan.
- Tidak ada kalimat yang disalin dari teks standar.

**Variasi tantangan:** buat versi PDCA dari peta yang sama (Plan 4-6, Do 7-8, Check 9, Act 10) dan jelaskan klausul yang sulit dimasukkan ke satu fase, misalnya 5 Leadership.

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Bingung kenapa risk assessment muncul di 6 dan 8 | Belum membedakan "menetapkan proses" dan "menjalankan proses" | Pakai tabel bagian 1.5; tanyakan "ini metodologi atau hasil?" |
| Register dokumen membengkak | Semua file dianggap wajib | Pisahkan wajib (bagian 1.6), wajib karena kontrol, dan pilihan organisasi |
| Jejak insiden berhenti di tiket ditutup | Operasi tidak dihubungkan dengan evaluasi dan perbaikan | Tambahkan langkah 9.1, 9.3, dan 10.2; tanya "pelajaran apa yang masuk ke risiko?" |
| Ragu apakah perubahan butuh 6.3 | 6.3 hanya untuk perubahan ISMS | Perubahan teknis: kontrol 8.32; perubahan proses, scope, atau peran ISMS: 6.3 |

## 5. Kesalahan umum dan jebakan

- Mengira management review cukup berupa rapat tanpa notulen. 9.3.3 meminta bukti hasil yang memuat keputusan tentang peluang perbaikan dan kebutuhan perubahan ISMS.
- Melupakan input 9.3.2 c, atau menyusun program audit internal tanpa memakai hasil risk assessment. Keduanya dilaporkan sering muncul dalam audit 27001:2022 [S6].
- Menyamakan 6.3 dengan kontrol 8.32 Change management. 8.32 mengatur perubahan sistem pemrosesan informasi; 6.3 mengatur perubahan sistem manajemennya.

## 6. Catatan terkini

Bagian ini menampung detail edisi dan sejarah perubahan. Detail ini berguna saat membaca dokumen ISMS lama atau ringkasan daring yang masih memakai edisi 2013, tetapi tidak perlu dihafal untuk memahami peta klausul.

**Edisi yang berlaku:**

- ISO/IEC 27001:2022 (edisi 3) dengan Amd 1:2024 masih edisi berlaku per 2026-10-10 [S9]. Amd 1 menambah satu kalimat di 4.1 (organisasi menentukan apakah perubahan iklim relevan) dan satu catatan di 4.2 [S7]. Detail di Day 03.
- SNI ISO/IEC 27001:2022/Amd.1:2024 ditetapkan BSN pada 2024; sekretariat Komtek 35-04 berada di BSSN [S7].

**Perubahan Annex SL 2021 yang muncul di 27001:2022** [S3]: persyaratan pihak berkepentingan yang ditangani lewat sistem manajemen (4.2 c), subklausul baru 6.3, outsourcing diganti pengendalian proses, produk, atau layanan pihak eksternal (8.1), penyederhanaan persyaratan informasi terdokumentasi, dan continual improvement dipindah ke depan klausul 10.

**Perubahan klausul dari 2013 ke 2022.** Perubahan di klausul 4-10 kecil dan sebagian besar berupa penyelarasan dengan Harmonized Structure [S1][S2][S3][S10]. Tabel berikut berguna saat memperbarui dokumen ISMS yang disusun untuk edisi 2013; kolom terakhir menunjukkan apa yang harus diubah.

| Klausul | Perubahan 2022 | Dampak praktis |
|---|---|---|
| 4.2 | Butir c baru: persyaratan mana yang ditangani lewat ISMS | Register butuh kolom "ditangani lewat ISMS?" |
| 4.4 | Eksplisit: ISMS mencakup proses dan interaksinya | Peta proses menjadi bukti |
| 5.3 | Peran dikomunikasikan di dalam organisasi | Peran harus diketahui, bukan hanya tertulis |
| 6.1.3 | Annex A disebut daftar kontrol yang mungkin, tidak lengkap; istilah control objectives hilang | Kontrol dari kerangka lain sah |
| 6.2 | Butir baru d (dipantau) dan g (tersedia sebagai informasi terdokumentasi) | Sasaran perlu pemilik dan metrik |
| 6.3 | Baru: perubahan ISMS terencana | Migrasi SIEM perlu rencana |
| 7.4 | "Siapa" dan "proses" komunikasi diganti "bagaimana" berkomunikasi | Kecil |
| 8.1 | Kriteria proses; pengendalian proses, produk, dan layanan dari pihak eksternal | MSSP masuk pengendalian operasional |
| 9.1 | Syarat hasil bisa dibandingkan dan diulang pindah dari catatan ke butir b | Definisi metrik harus stabil |
| 9.2 | Dipecah menjadi 9.2.1 (umum) dan 9.2.2 (program audit) | Hanya pengelompokan |
| 9.3 | Dipecah menjadi 9.3.1-9.3.3; input baru 9.3.2 c | Agenda review perlu butir ini |
| 10 | Urutan dibalik: 10.1 continual improvement, 10.2 nonconformity | Hanya penomoran |

Sebagian ringkasan sekunder menulis bahwa 9.2 "digabung" di edisi 2022 [S1]. Yang benar, 9.2 dan 9.3 dipecah menjadi subklausul.

## 7. Cheat sheet

```
KLAUSUL 4-10 (semua wajib, tidak bisa dikecualikan)
4 Context      4.1 isu | 4.2 pihak berkepentingan (+ c: mana yang ditangani ISMS) | 4.3 scope | 4.4 ISMS + proses
5 Leadership   5.1 komitmen | 5.2 kebijakan | 5.3 peran, tanggung jawab, wewenang
6 Planning     6.1.1 umum | 6.1.2 proses RA | 6.1.3 proses RT + SoA (d) + RTP (e) | 6.2 sasaran | 6.3 perubahan (baru 2022)
7 Support      7.1 sumber daya | 7.2 kompetensi | 7.3 awareness | 7.4 komunikasi | 7.5 informasi terdokumentasi
8 Operation    8.1 pengendalian operasional | 8.2 jalankan RA | 8.3 jalankan RT
9 Evaluation   9.1 metrik | 9.2.1-9.2.2 audit internal | 9.3.1-9.3.3 management review (input a-g)
10 Improvement 10.1 continual improvement | 10.2 NC + corrective action  (urutan dibalik di 2022)

RANTAI: konteks -> scope -> risiko -> kontrol/SoA -> operasi -> metrik -> audit -> review -> NC/CA -> (ulang)
Benang audit = pivot investigasi: satu insiden ditarik lewat 8 -> 9.1 -> 9.3 -> 10.2 -> 8.2/6.1.2
6 = menetapkan proses (playbook)   8 = menjalankan proses dan menyimpan hasilnya (tiket)
maintain = dokumen hidup (versi, persetujuan)   retain = rekaman bukti (tidak diubah, ada retensi)
Wajib dokumen: 4.3 5.2 6.1.2 6.1.3 SoA(6.1.3d) 6.2 | rekaman: 7.2 8.1 8.2 8.3 9.1 9.2.2 9.3.3 10.2 | + 7.5.1b
9.3.2 input: a tindakan lalu | b isu | c pihak berkepentingan | d kinerja | e umpan balik | f risiko/RTP | g peluang
Baru 2022: 4.2c 4.4 6.2(d,g) 6.3 7.4 8.1 9.2/9.3 dipecah 9.3.2c 10.1<->10.2
6.3 = perubahan ISMS   kontrol 8.32 = perubahan sistem pemrosesan informasi
SNI: clause = pasal, subclause = subpasal
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Risk register PT AN lengkap dan diperbarui tiap kuartal, tetapi tidak ada dokumen metodologi risiko. Karena risk assessment terbukti dijalankan, apakah persyaratan 6.1.2 terpenuhi?

<details><summary>Jawaban</summary>

Tidak. Risk register adalah hasil menjalankan proses (8.2). Subklausul 6.1.2 meminta prosesnya sendiri ditetapkan, termasuk kriteria risiko serta cara identifikasi, analisis, dan evaluasi, dan informasi tentang proses itu wajib terdokumentasi. Tanpa metodologi tertulis, hasil tiap kuartal sulit dibandingkan karena tidak jelas kriteria apa yang dipakai. Lihat bagian 1.5 dan 1.6.

</details>

**2. Pertanyaan jebakan.** Management review PT AN benar-benar berlangsung: undangan kalender ada, semua direksi hadir, dan Lead SOC mempresentasikan metrik. Hanya notulennya yang tidak dibuat. Apakah 9.3 terpenuhi?

<details><summary>Jawaban</summary>

Tidak. 9.3.3 meminta bukti hasil management review sebagai informasi terdokumentasi, dan hasil itu harus memuat keputusan tentang peluang perbaikan dan kebutuhan perubahan ISMS. Undangan kalender hanya membuktikan rapat dijadwalkan, bukan apa yang diputuskan. Tanpa notulen, auditor juga tidak bisa menelusuri butir 9.3.2 a (status tindakan dari review sebelumnya) di rapat berikutnya. Lihat bagian 1.4, 1.6, dan 5.

</details>

**3. Jelaskan ulang.** Jelaskan kepada analyst SOC yang baru bergabung kenapa satu tiket insiden bisa menjadi bahan audit untuk banyak bagian ISO 27001, dalam tiga atau empat kalimat, tanpa menyebut nomor klausul.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Tiket insiden bukan akhir cerita. Insiden itu masuk laporan metrik bulanan, akar masalahnya dicatat sebagai temuan yang harus diperbaiki, risikonya dinilai ulang, dan ringkasannya dibahas pimpinan dalam rapat tinjauan. Auditor suka mengambil satu insiden lalu menelusuri semua jejak itu, seperti kita pivot dari satu alert ke log lain sampai ceritanya utuh. Kalau salah satu jejak tidak ada, itulah yang menjadi temuan audit."

Kesalahan yang sering muncul:
- Berhenti di "tiket ditutup dan dicatat rapi", seolah auditor hanya memeriksa kualitas tiket.
- Menyebut bahwa yang diaudit adalah alatnya (SIEM, EDR), bukan jejak keputusan dan perbaikannya.
- Menganggap pelatihan ulang atau perubahan prosedur sebagai urusan HR yang terpisah dari insiden.

</details>

**4. Skenario keputusan.** SOC PT AN berencana memindahkan sebagian log source dari Splunk ke Wazuh bulan depan. Apa yang paling tepat?

- A. Cukup ajukan change request teknis lewat proses kontrol 8.32, karena ini perubahan sistem.
- B. Rencanakan sebagai perubahan ISMS lewat 6.3 karena proses monitoring dalam ISMS berubah, nilai risikonya sebelum dijalankan (misalnya celah logging saat cutover), dan jalankan perubahan teknisnya lewat 8.32.
- C. Tidak perlu langkah khusus. Selama log tetap terkumpul setelah migrasi, kontrol logging tetap terpenuhi.

<details><summary>Jawaban</summary>

B. Migrasi ini mengubah cara ISMS menjalankan monitoring, jadi termasuk perubahan ISMS yang harus direncanakan lewat 6.3. Perubahan signifikan juga memicu risk assessment (8.2 meminta risk assessment dijalankan saat ada perubahan signifikan), sehingga risiko seperti celah logging saat cutover dinilai sebelum migrasi. A keliru karena 8.32 hanya mengatur perubahan sistem pemrosesan informasi, bukan perubahan sistem manajemennya; keduanya berjalan bersamaan. C keliru karena yang dinilai bukan hanya kondisi setelah migrasi, tetapi juga risiko selama perubahan. Lihat bagian 1.5, 4, dan 5.

</details>

**5. Skenario keputusan.** PT AN harus menunjuk auditor internal untuk proses SOC. Pilihan mana yang tepat?

- A. Lead SOC, karena paling memahami proses SOC.
- B. Auditor dari luar SOC yang dipilih supaya audit objektif dan imparsial.
- C. Tidak perlu audit internal, karena lembaga sertifikasi sudah mengaudit setiap tahun.

<details><summary>Jawaban</summary>

B. Subklausul 9.2.2 meminta pemilihan auditor dan pelaksanaan audit yang objektif dan imparsial, sehingga orang yang menjalankan proses tidak mengaudit pekerjaannya sendiri. A keliru karena Lead SOC akan mengaudit prosesnya sendiri. C keliru karena 9.2 adalah bagian dari klausul 4-10 yang tidak bisa dikecualikan; audit eksternal tidak menggantikan audit internal. Lihat bagian 1.3, 1.7, dan 2.1.

</details>

**6. Pertanyaan jebakan.** Saat angka Agustus keluar, seorang analyst ingin membuka laporan metrik SOC bulan Juli, memperbarui angkanya, lalu menaikkan nomor versinya menjadi 1.1. Apakah itu cara yang benar mengelola laporan metrik?

<details><summary>Jawaban</summary>

Tidak. Laporan metrik bulanan adalah rekaman (bukti hasil monitoring di 9.1), bukan dokumen hidup. Rekaman tidak diubah setelah dibuat; yang diatur adalah retensi dan aksesnya. Angka Agustus masuk laporan Agustus yang baru. Versi dan persetujuan berlaku untuk dokumen seperti scope, kebijakan, atau SoA. Lihat bagian 1.6 dan 2.3.

</details>

**7. Interview question (English).** "How does a SOC support an ISO 27001 ISMS, beyond running the SIEM?"

<details><summary>Sample answer</summary>

"The SOC sits in the operation part of the ISMS, but its output feeds the whole improvement loop. An incident ticket is evidence for clause 8. The same incident shows up in the monthly metrics for clause 9.1, the root cause goes into the nonconformity and corrective action register under 10.2, the related risk gets reassessed, and a summary reaches the management review under 9.3. Auditors like to pick one incident and trace it through all of those records, so I make sure each step leaves documented evidence, not just a closed ticket."

What makes this answer strong: it describes the SOC as part of a chain of clauses instead of a tool owner, and it names the records an auditor would actually ask for.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Cloud Security Alliance (A-LIGN): ISO 27001:2013 vs 2022 | https://cloudsecurityalliance.org/articles/what-s-the-difference-between-iso-27001-2013-and-iso-27001-2022 | sekunder | 2023-02-10; diakses 2026-10-08 | Sedang. Menulis 9.2 "digabung"; yang benar dipecah |
| S2 | HighTable: ISO 27001 2013 vs 2022 explained | https://hightable.io/iso-27001-2013-vs-2022/ | sekunder (konsultan) | diperbarui 2026-09-14; diakses 2026-10-10 | Sedang. Rincian perubahan per klausul |
| S3 | IAF news: New 2021 edition of Annex SL for management system standards | https://iaf.news/2021/07/02/new-2021-edition-of-annex-sl-for-management-system-standards/ | sekunder (situs berita IAF) | 2021-07-02; diakses 2026-10-10 | Sedang-tinggi. Perubahan Annex SL 2021 |
| S4 | Advisera: List of mandatory documents required by ISO 27001 (2022 revision) | https://advisera.com/27001academy/knowledgebase/list-of-mandatory-documents-required-by-iso-27001/ | sekunder (konsultan) | diperbarui 2022-11-28; diakses 2026-10-10 | Sedang. Dokumen dan rekaman wajib per klausul |
| S5 | Hicomply: ISO 27001:2022 clause 9.3 management review | https://hicomply.com/hub/iso-27001-clause-9-3-management-review-2022 | sekunder (vendor) | diakses 2026-10-08 | Sedang. Ringkasan isi 9.2.2 dan 9.3.2 |
| S6 | URM Consulting: Common issues identified during audits of ISO 27001:2022 | https://urmconsulting.com/blog/common-issues-identified-during-audits-of-iso-27001-2022 | sekunder (praktisi audit) | 2026-04-09; diakses 2026-10-08 | Sedang. Pengalaman satu konsultan, bukan statistik |
| S7 | BSN: RSNI3 ISO/IEC 27001:2022/Amd.1:2024 | https://bsn.go.id/uploads/attachment/rsni_iso_iec_27001-2022-amd1_1.pdf | primer | 2024; diakses 2026-10-10 | Tinggi. Prakata, teks amandemen, komite |
| S8 | Elevate Consult: ISO 27001 Annex A vs clauses 4-10 | https://elevateconsult.com/insights/iso-27001-annex-a-vs-clauses-4-10-understanding-the-key-differences-for-non-technical-teams/ | sekunder (konsultan) | diakses 2026-10-08 | Sedang. Posisi klausul wajib dan Annex A |
| S9 | ISO committee: ISO/IEC 27001:2022 | https://committee.iso.org/standard/82875.html | primer (katalog ISO) | terbit 2022-10-25; diakses 2026-10-10 | Tinggi untuk edisi dan status |
| S10 | Protiviti: ISO 27001:2022 key changes and approaches to transition | https://www.protiviti.com/us-en/whitepaper/iso-27001-2022-key-changes-and-approaches-transition | sekunder (konsultan) | diakses 2026-10-10 | Sedang. 6.3, pemecahan 9.2/9.3, input 9.3.2 c |

**Catatan sumber:** daftar informasi terdokumentasi wajib dan perubahan 2013 ke 2022 disusun dari beberapa ringkasan sekunder yang saling cocok. Kata kerja persis tiap persyaratan (maintain, retain, atau available) bisa dicocokkan dengan teks ISO/IEC 27001:2022 atau SNI resmi bila dibutuhkan untuk dokumen audit. Kolom "Datang dari" di bagian 1.4 adalah pemetaan interpretatif, bukan bagian teks standar.
