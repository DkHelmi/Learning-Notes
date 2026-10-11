---
day: 16
title: 'Menutup temuan dengan benar: koreksi, tindakan korektif, dan management review'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 27001:2022 + Amd 1:2024 klausul 9.3 dan 10.2; ISO 9000:2026 (edisi 5, 27 Mei 2026, menggantikan ISO 9000:2015); ISO 19011:2026 (edisi 4)'
---

# Day 16: Menutup temuan dengan benar

Cakupan: memenuhi klausul 10.2 dan 9.3 dalam praktik, yaitu membedakan koreksi dari tindakan korektif, menemukan akar penyebab, memilih tindakan yang bertahan, memverifikasi efektivitas, memantau tindakan sampai ditutup, dan menjalankan management review yang menghasilkan keputusan.

## Ide inti

Temuan baru selesai bila penyebabnya hilang dan ada bukti bahwa ia tidak muncul lagi. Klausul 10.2 meminta urutan yang jelas: bereaksi atas kasus yang ditemukan, mencari penyebab, memeriksa apakah masalah serupa ada di tempat lain, menjalankan tindakan, lalu meninjau efektivitasnya. Klausul 9.3 adalah tempat top management melihat apakah proses perbaikan itu bekerja dan memutuskan hal yang tidak bisa diputuskan tim operasional. Day 06 membahas keduanya sebagai persyaratan, dan Day 15 membahas cara menghasilkan temuan. Day ini mengerjakan apa yang terjadi sesudahnya, dan di situlah banyak sistem manajemen gagal diam-diam.

Polanya mudah dikenali: temuan muncul, seseorang memperbaiki gejalanya, tiket ditutup, dan temuan yang sama muncul lagi tahun berikutnya. Siklus itu memenuhi persyaratan di atas kertas tetapi tidak memperbaiki apa pun, dan menghabiskan kepercayaan manajemen terhadap ISMS. Bagi SOC, ini relevan langsung: banyak nonconformity berasal dari insiden dan post-incident review, dan tindakan korektifnya sering berupa perubahan rule, runbook, atau konfigurasi.

Kamu sudah mengenal bedanya dari post-incident review. Menutup tiket dan memblokir IOC adalah koreksi (correction); memperbaiki celah yang membuat serangan berhasil adalah tindakan korektif (corrective action). Rule yang sudah di-tuning juga baru dianggap beres setelah diuji ulang dan tidak miss lagi. Batas analoginya: tindakan korektif harus sepadan dengan dampak dan ditinjau efektivitasnya sebelum ditutup. Management review mirip rapat review operasi SOC bersama pimpinan, dengan batas bahwa inputnya ditetapkan standar dan hasilnya wajib berupa keputusan yang terdokumentasi.

```
temuan (audit, insiden yang merupakan NC, keluhan)
  -> 10.2 a koreksi + tangani konsekuensi (kasus yang ditemukan)
  -> 10.2 b akar penyebab (uji berhenti) + cek NC serupa di tempat lain
  -> 10.2 c tindakan korektif (tingkat kekuatan setinggi yang masuk akal, sepadan dampak)
  -> 10.2 d verifikasi efektivitas (apa, kapan, ambang, bila gagal; oleh orang lain)
  -> 10.2 e ubah ISMS bila perlu -> ditutup, atau dibuka kembali bila verifikasi gagal
  -> daftar pantau + 4 angka kesehatan -> 9.3 management review (keputusan, pemilik, tenggat)
```

Situasi yang dipakai sepanjang Day ini: akhir Juni 2027, ISMS Manager PT Awan Nusantara (PT AN, penyedia hosting fiktif) menyiapkan management review semester 1 yang dijadwalkan 1 Juli 2027. Temuan T-01 dari audit logging Februari (Day 15) sudah menjadi lembar tindakan korektif CA-2027-004. Direktur Operasional, yang memimpin management review 20 November 2026 (Day 06), mengirim pesan:

> "Sebelum rapat 1 Juli, saya mau empat jawaban. Pertama, temuan audit logging Februari: benar-benar beres, atau hanya enam tiketnya yang dilengkapi? Kedua, temuan manajemen akses berulang lagi dalam tiga siklus; kenapa perbaikan kita tidak bertahan? Ketiga, ada tindakan yang lewat tenggat berbulan-bulan dan saya baru mendengarnya sekarang. Keempat, saya mau rapatnya menghasilkan keputusan seperti November lalu, bukan dua jam presentasi."

Pertanyaan pertama dijawab langkah 10.2, beda koreksi dan tindakan korektif, serta verifikasi efektivitas (bagian 1.1, 1.2, dan 1.5). Pertanyaan kedua menyangkut akar penyebab, jenis penyebab, dan kekuatan tindakan (bagian 1.3 dan 1.4). Pertanyaan ketiga adalah salah satu pola kegagalan yang berulang (bagian 1.6) dan dijawab dengan daftar pantau. Pertanyaan keempat adalah 9.3 (bagian 1.7). Dokumen yang dibawa ISMS Manager ada di bagian 2.

**Kapan relevan:** setiap kali temuan audit, insiden yang merupakan nonconformity, atau keluhan perlu ditutup, dan saat menyiapkan management review.
**Kapan bukan jawaban:** insiden yang terjadi walaupun semua kontrol berjalan sesuai rencana bukan nonconformity, sehingga tidak butuh lembar tindakan korektif; pelajarannya masuk ke risk assessment dan continual improvement (Day 06). Cara menghasilkan temuan ada di Day 15.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Tabel ini memuat istilah yang muncul di Day ini. Kolom padanan memakai analogi SOC yang sama di semua Day. Correction, corrective action, analisis akar masalah, dan efektivitas corrective action sudah diperkenalkan di Day 06; Day ini menyebutnya koreksi, tindakan korektif, dan analisis akar penyebab, lalu merinci cara mengerjakannya.

| Istilah | Arti singkat | Padanan di SOC |
|---|---|---|
| Konsekuensi (10.2 a) | Akibat dari nonconformity yang perlu ditangani, di luar memperbaiki kasusnya | Memeriksa ulang alert yang ditutup tanpa alasan, kalau-kalau ada insiden yang terlewat |
| Uji berhenti | Pertanyaan untuk memastikan analisis akar penyebab berhenti di tempat yang benar | Bertanya "kalau celah ini ditutup, apakah serangan yang sama masih bisa berhasil?" |
| Jenis penyebab | Sistemik, teknis, atau manusia | Prosedur triage tidak jelas, SIEM mengizinkan, atau analyst belum dilatih |
| Kekuatan tindakan | Urutan tindakan dari yang membuat kesalahan tidak mungkin sampai yang mengandalkan orang | Blokir atau hardening, detection rule otomatis, hunting berkala, berharap analyst ingat |
| Verifikasi efektivitas | Bukti terukur, dengan waktu dan ambang yang ditetapkan di muka, bahwa tindakan berhasil | Rule yang sudah di-tuning diuji ulang dan tidak miss lagi |
| Daftar pantau tindakan korektif | Register semua tindakan dengan pemilik, tenggat, status, dan jadwal verifikasi | Backlog perbaikan pasca-insiden dengan kolom retest |
| Blok keputusan dan blok informasi | Pemisahan agenda management review antara hal yang perlu diputuskan dan lampiran yang cukup dibaca | Rapat review: keputusan headcount dibahas, metrik rutin dikirim sebagai laporan |
| Risalah | Catatan hasil management review yang memuat keputusan, pemilik, dan tenggat | Notulen rapat review dengan action item |
| Ukuran kesehatan proses perbaikan | Empat angka tren untuk menilai apakah proses perbaikan bekerja (bukan persyaratan ISO) | Metrik insiden berulang dan waktu penutupan action item |

### 1.1 Apa yang dituntut klausul 10.2

Pertanyaan pertama Direktur Operasional ("benar-benar beres, atau hanya tiketnya yang dilengkapi?") dijawab dengan menunjukkan bahwa setiap langkah 10.2 terisi, bukan hanya langkah pertama.

Saat nonconformity terjadi, termasuk yang berasal dari audit, insiden, atau keluhan, klausul 10.2 menuntut urutan berikut. Tabel ini memetakan tiap tuntutan ke blok pada lembar tindakan korektif di bagian 2.1; pakai kolom kanan untuk mengecek apakah lembarmu punya tempat untuk setiap langkah [S4].

| Tuntutan 10.2 (parafrase) | Di lembar CA-2027-004 |
|---|---|
| a) Bereaksi: bila relevan, mengendalikan dan mengoreksi nonconformity, serta menangani konsekuensinya | Blok KOREKSI dan KONSEKUENSI |
| b) Mengevaluasi perlunya tindakan untuk menghilangkan penyebab agar tidak terulang atau terjadi di tempat lain, dengan: meninjau nonconformity, menentukan penyebabnya, dan menentukan apakah nonconformity serupa ada atau bisa terjadi | Blok ANALISIS AKAR PENYEBAB dan tindakan CA-c |
| c) Menerapkan tindakan yang dibutuhkan | CA-a, CA-b, CA-c dengan pemilik dan tenggat |
| d) Meninjau efektivitas tindakan korektif | Blok VERIFIKASI EFEKTIVITAS |
| e) Mengubah ISMS bila perlu | Blok PERUBAHAN ISMS |

Dua tuntutan lain sering terlupa. Tindakan korektif harus sepadan dengan dampak nonconformity-nya: kesalahan kecil tidak butuh proyek besar, dan nonconformity yang membuka risiko serius tidak cukup ditangani dengan pengingat. Lalu informasi terdokumentasi harus disimpan sebagai bukti sifat nonconformity, tindakan yang diambil, dan hasil tindakan korektif [S4]. Lembar di bagian 2.1 dan daftar pantau di bagian 2.3 adalah bukti itu.

### 1.2 Koreksi dan tindakan korektif

Melengkapi enam tiket yang kosong adalah jawaban yang paling mudah untuk temuan T-01, dan justru jawaban yang akan ditanya auditor. Di Day 06 polanya sama: menonaktifkan akun default di 14 VM adalah koreksi, sedangkan mengubah image VM dan prosedur perubahan template di CA-2026-014 adalah tindakan korektif.

Kosakata sistem manajemen di ISO 9000 memisahkan dua hal yang sering disamakan; status edisinya ada di bagian 6. Tabel ini menaruh kedua istilah berdampingan dengan langkah 10.2-nya; kolom kanan menunjukkan bedanya pada satu temuan yang sama.

| Istilah | Yang dilakukan | Langkah 10.2 | Contoh pada temuan di Day 15 |
|---|---|---|---|
| Koreksi (correction) | Menghilangkan ketidaksesuaian yang terdeteksi | a) | Mengisi alasan penutupan pada enam tiket yang kosong |
| Tindakan korektif (corrective action) | Menghilangkan penyebab ketidaksesuaian agar tidak terulang | b) sampai d) | Membuat kolom alasan menjadi wajib di sistem tiket |

Keduanya diperlukan. Mengisi enam tiket menyelesaikan masalah hari ini; membuat kolom itu wajib mencegah masalah besok. Kesalahan yang paling sering adalah melaporkan koreksi sebagai tindakan korektif. Auditor mengenalinya dengan satu pertanyaan: apa yang mencegah hal ini terjadi lagi?

Uji sendiri: bila tindakanmu hanya menyentuh kasus yang ditemukan auditor dan tidak menyentuh kasus yang belum ditemukan, itu koreksi.

### 1.3 Mencari akar penyebab tanpa berhenti terlalu cepat

Temuan manajemen akses yang berulang dalam tiga siklus, pertanyaan kedua Direktur Operasional, biasanya tanda bahwa analisis akar penyebab sebelumnya berhenti di tempat yang salah.

Analisis akar penyebab adalah cara memenuhi langkah "menentukan penyebab" di 10.2 b). Ia gagal karena dua hal berlawanan: berhenti terlalu cepat, sehingga akarnya ternyata hanya gejala lain; atau berjalan terlalu jauh, sehingga berakhir pada hal yang tidak bisa kamu ubah.

Tanda berhenti terlalu cepat: akar penyebabnya berupa kesalahan satu orang. Hampir selalu ada lapis di bawahnya, yaitu kenapa sistemnya mengizinkan kesalahan itu, atau kenapa kesalahan itu tidak terdeteksi. Kerangka RCA2 dari Institute for Healthcare Improvement menegaskan hal yang sama: kinerja individu diperlakukan sebagai gejala masalah sistem, bukan sasaran analisis [S6].

Tanda berjalan terlalu jauh: akar penyebabnya berupa kekurangan anggaran atau budaya organisasi. Keduanya mungkin benar, tetapi tidak bisa ditindaklanjuti oleh tim yang menerima temuan; bawa ke management review bila memang itu akarnya.

Berhenti yang benar ada di antara keduanya, yaitu pada hal yang bisa kamu ubah dan yang bila diubah akan mencegah terulangnya. Uji berhenti: bayangkan akar penyebab itu dihilangkan, lalu tanyakan apakah temuan ini masih mungkin terjadi. Di SOC, pertanyaannya mirip saat post-incident review: kalau celah ini ditutup, apakah serangan yang sama masih bisa berhasil?

Standar tidak mewajibkan metode tertentu. 5 whys cocok untuk penyebab tunggal; diagram sebab akibat (fishbone) lebih cocok bila penyebabnya beberapa dan saling menguatkan. Yang penting adalah alasan di tiap langkah tercatat.

### 1.4 Jenis penyebab dan kekuatan tindakan

Setelah akar ditemukan, pertanyaan berikutnya adalah tindakan seperti apa yang bertahan. Perbaikan yang hanya berupa pengingat cenderung meluruh, dan itu salah satu penjelasan yang mungkin untuk temuan manajemen akses yang terus kembali.

Tabel ini mencocokkan jenis penyebab dengan jenis tindakan; cari baris yang sesuai dengan akar yang kamu temukan sebelum memilih tindakan.

| Jenis | Ciri | Tindakan yang sesuai |
|---|---|---|
| Penyebab sistemik | Prosedur tidak ada, tidak jelas, atau tidak mungkin dijalankan | Ubah prosedur atau alur prosesnya |
| Penyebab teknis | Sistem mengizinkan keadaan yang tidak diinginkan | Ubah konfigurasi atau tambahkan kontrol teknis |
| Penyebab manusia | Orang tidak tahu, tidak mampu, atau tidak terdorong | Pelatihan, kejelasan peran, atau ubah insentif |

Penyebab manusia hampir tidak pernah berdiri sendiri. Bila kesimpulanmu "orang kurang teliti", tanyakan kenapa sistemnya bergantung pada ketelitian.

Urutan kekuatan tindakan, dari yang paling kuat: membuat kesalahan tidak mungkin terjadi, membuat kesalahan terdeteksi otomatis, membuat kesalahan terdeteksi lewat tinjauan berkala, lalu mengandalkan orang untuk tidak salah. Gagasan ini dipinjam dari action hierarchy di dunia keselamatan pasien, yang dibuat untuk memilih tindakan dengan efek paling kuat dan bertahan [S6]. Di SOC urutannya mirip: mencegah lewat blokir atau hardening, lalu detection rule yang memicu alert otomatis, lalu hunting atau review berkala, dan terakhir berharap analyst ingat. Naikkan tindakanmu ke tingkat setinggi yang masuk akal, sambil ingat tuntutan 10.2 agar tindakan sepadan dengan dampaknya.

### 1.5 Merancang verifikasi efektivitas

Jawaban "sudah beres" untuk temuan logging baru boleh diberikan setelah verifikasi CA-2027-004 dijalankan, bukan saat tindakannya selesai dikerjakan.

Langkah 10.2 d) paling sering kosong di lembar tindakan korektif, dan paling sering ditanyakan auditor. Verifikasi efektivitas menjawab satu pertanyaan: dari mana kita tahu ini berhasil. Jawabannya harus berupa bukti yang bisa diperiksa, dengan waktu yang ditentukan di muka. Di SOC, bedanya seperti "rule sudah diubah" dan "rule diuji ulang dengan skenario yang sama dan tidak miss lagi".

Tabel ini membandingkan bunyi verifikasi yang lemah dan yang kuat; perhatikan bahwa kolom kanan selalu menyebut ukuran, waktu, dan ambang.

| Lemah | Kuat |
|---|---|
| Sudah dilatih seluruh tim | Pengambilan 20 tiket tiga bulan setelah perubahan, nol yang tanpa alasan |
| Prosedur sudah diperbarui | Audit ulang area itu pada siklus berikutnya, tanpa temuan serupa |
| Sudah diingatkan di rapat | Laporan otomatis bulanan menunjukkan nol kasus selama tiga bulan |

Tiga unsur wajib: apa yang diukur, kapan diukur, dan ambang yang dianggap berhasil. Tanpa ambang, verifikasi menjadi penilaian subjektif yang selalu lolos. Tetapkan juga apa yang terjadi bila verifikasi gagal: temuan dibuka kembali, bukan ditutup dengan catatan.

### 1.6 Pola kegagalan yang berulang

Tindakan yang lewat tenggat berbulan-bulan tanpa ada yang tahu, keluhan ketiga Direktur Operasional, adalah gejala dari pola yang membuat temuan muncul berulang. Kelima pola di bawah adalah yang paling sering:

- **Koreksi dilaporkan sebagai tindakan korektif.** Dibahas di bagian 1.2.
- **Akar penyebab berupa nama orang.** Orangnya berganti, masalahnya tetap.
- **Tindakan bergantung pada kedisiplinan.** Berhasil tiga bulan pertama, lalu meluruh.
- **Tidak ada verifikasi efektivitas.** Tidak ada yang tahu apakah berhasil.
- **Tidak ada pemilik tunggal.** Tindakan dimiliki sebuah tim, dan karena itu tidak dimiliki siapa pun.

Bila kamu memegang daftar temuan beberapa tahun, hitung berapa yang berulang. Angka itu adalah ukuran kesehatan proses perbaikanmu, dan ia masuk ke input "tren nonconformity dan tindakan korektif" di management review. Daftar pantau di bagian 2.3 dan empat angka di bagian 2.6 membuat pola ini terlihat sebelum Direktur Operasional menanyakannya.

### 1.7 Management review: persyaratan 9.3

Permintaan keempat, rapat yang menghasilkan keputusan seperti November lalu, adalah inti 9.3. Agenda 20 November 2026 di Day 06 sudah memetakan tiap butir ke input 9.3.2; Day ini menambahkan cara memisahkan yang perlu diputuskan dari yang cukup dibaca.

Klausul 9.3.1 meminta top management meninjau ISMS pada interval terencana untuk memastikan ISMS tetap sesuai (suitable), memadai (adequate), dan efektif [S5]. Klausul 9.3.2 menyebut hal yang harus dipertimbangkan. Tabel ini memberi huruf pada tiap input supaya bisa dipakai sebagai kolom penelusuran di agenda (bagian 2.4); perhatikan butir d yang punya empat sub-butir [S5].

| Huruf | Input 9.3.2 (parafrase) |
|---|---|
| a | Status tindakan dari management review sebelumnya |
| b | Perubahan isu eksternal dan internal yang relevan dengan ISMS |
| c | Perubahan kebutuhan dan harapan pihak berkepentingan yang relevan dengan ISMS |
| d | Umpan balik kinerja keamanan informasi, termasuk tren: 1) nonconformity dan tindakan korektif, 2) hasil monitoring dan pengukuran, 3) hasil audit, 4) pencapaian sasaran keamanan informasi |
| e | Umpan balik dari pihak berkepentingan |
| f | Hasil risk assessment dan status risk treatment plan |
| g | Peluang perbaikan berkelanjutan |

Klausul 9.3.3 meminta hasil review memuat keputusan tentang peluang perbaikan berkelanjutan dan kebutuhan perubahan ISMS, dan bukti hasil itu disimpan sebagai informasi terdokumentasi [S5]. Auditor akan mencari dua hal di risalah: jejak bahwa ketujuh input dipertimbangkan, dan keputusan yang jelas.

Tanda management review yang tidak berguna: isinya presentasi status, tidak ada keputusan yang dicatat, dan tidak ada yang berubah sesudahnya. Tiga hal yang mengubahnya:

1. **Bawa keputusan, bukan laporan.** Bahan yang tidak membutuhkan keputusan dikirim sebagai lampiran tertulis sebelum rapat. Lampiran itu tetap dicatat di risalah sebagai sudah ditinjau, karena 9.3.2 menuntut setiap input dipertimbangkan.
2. **Bawa yang buruk, bukan hanya yang baik.** Temuan berulang, tindakan lewat tenggat, dan risiko yang naik adalah isi yang paling bernilai.
3. **Catat keputusan dengan pemilik dan tenggat.** Risalah tanpa pemilik dan tenggat hanyalah catatan percakapan.

Management review juga tempat yang tepat untuk mengeskalasi hal yang tidak bisa diselesaikan tim operasional: sumber daya, konflik prioritas antar unit, atau risiko yang perlu diterima secara formal.

## 2. Contoh dokumen / artefak (organisasi fiktif)

Organisasi fiktif: PT Awan Nusantara (PT AN). Nomor, nama, tenggat, dan ambang di bawah adalah aturan internal fiktif, bukan persyaratan standar. Keenam artefak ini adalah bahan yang disiapkan ISMS Manager untuk menjawab Direktur Operasional sebelum management review 1 Juli 2027.

### 2.1 Lembar tindakan korektif

Jawaban untuk pertanyaan pertama: lembar tindakan korektif untuk temuan T-01 dari audit logging (Day 15 bagian 2.5). Nomornya mengikuti register tindakan korektif PT AN yang sama dengan CA-2026-014 di Day 06.

```
TINDAKAN KOREKTIF                                   Nomor: CA-2027-004
Asal temuan   : AI-2027-01 / T-01 (audit internal, minor)
Pemilik       : <nama>, Manajer Operasi Keamanan        <- satu orang, bukan tim
Dibuka        : 2027-02-15          Tenggat tindakan : 2027-03-31

PERNYATAAN TEMUAN
  Penutupan alert tidak selalu disertai alasan, sehingga peninjauan ulang tidak dimungkinkan.

KOREKSI (menyelesaikan kasus yang ditemukan)
  Enam tiket yang kosong dilengkapi alasannya berdasarkan ingatan analyst dan data pendukung.
  Dicatat bahwa tiga di antaranya diisi dengan keterangan "alasan tidak dapat direkonstruksi".
  Selesai: 2027-02-18

KONSEKUENSI (10.2 a)
  Tiga alert yang alasannya tidak bisa direkonstruksi ditinjau ulang oleh analyst lain
  untuk memastikan tidak ada yang sebenarnya insiden. Hasil: ketiganya false positive.
  Selesai: 2027-02-19

ANALISIS AKAR PENYEBAB
  Kenapa alasan tidak tercatat?        kolom alasan opsional di sistem tiket
  Kenapa opsional?                     saat sistem dipasang, kolom itu dianggap tambahan
  Kenapa tidak diubah setelah LOG-02 mewajibkannya?
                                       perubahan prosedur tidak memicu peninjauan konfigurasi sistem
  AKAR: tidak ada mekanisme yang menautkan perubahan prosedur ke perubahan sistem pendukung

  Uji berhenti: bila akar ini dihilangkan, apakah temuan masih mungkin? Tidak, karena setiap
  perubahan prosedur akan memicu pemeriksaan sistem pendukungnya.

TINDAKAN KOREKTIF (menghilangkan penyebab)
  CA-a  Kolom alasan dijadikan wajib di sistem tiket           pemilik <nama>  tenggat 2027-03-10
  CA-b  Daftar periksa perubahan prosedur ditambahi langkah
        "periksa sistem pendukung yang terdampak"              pemilik <nama>  tenggat 2027-03-31
  CA-c  Ditinjau apakah prosedur lain punya masalah serupa
        (10.2 b: nonconformity serupa ada atau bisa terjadi)   pemilik <nama>  tenggat 2027-03-31

JENIS PENYEBAB   sistemik (utama) dan teknis (pendukung)
KEKUATAN TINDAKAN  CA-a membuat kesalahan tidak mungkin terjadi; CA-b dan CA-c sistemik

VERIFIKASI EFEKTIVITAS
  apa yang diukur : proporsi tiket yang ditutup tanpa alasan
  cara mengukur   : pengambilan 20 tiket acak
  kapan           : 2027-06-30 (tiga bulan setelah tenggat seluruh tindakan)
  ambang berhasil : nol dari 20
  bila gagal      : temuan dibuka kembali; akar penyebab ditinjau ulang
  pelaksana       : auditor internal, bukan pemilik tindakan

PERUBAHAN ISMS (10.2 e)
  LOG-02 versi 3.2: pasal 7.3 merujuk kolom wajib; prosedur pengendalian dokumen ditambah
  langkah pemeriksaan sistem pendukung

STATUS   tindakan selesai
         (alur status: dibuka, tindakan selesai, diverifikasi efektif, ditutup)
```

Lembar ini memuat semua langkah 10.2 (bagian 1.1). Koreksi dicatat jujur, termasuk bagian yang tidak bisa direkonstruksi, dan konsekuensinya ditangani dengan memeriksa ulang alert yang meragukan. Verifikasi dijalankan oleh orang yang berbeda dari pemilik tindakan. Statusnya masih "tindakan selesai", sehingga jawaban jujur untuk pertanyaan pertama sebelum 30 Juni adalah "tindakan sudah dikerjakan, efektivitasnya belum terbukti".

### 2.2 Menguji kekuatan tindakan

Latihan singkat yang layak dijalankan untuk setiap tindakan sebelum disetujui. Tabel ini menilai beberapa tindakan untuk masalah tiket tanpa alasan; pola yang sama berlaku untuk temuan manajemen akses yang berulang, karena tindakan di tingkat "mengandalkan orang" cenderung meluruh.

| Tindakan yang diusulkan | Tingkat kekuatan | Penilaian |
|---|---|---|
| Mengingatkan tim di rapat mingguan | mengandalkan orang | Terlalu lemah; tidak akan bertahan |
| Menambahkan langkah di prosedur | mengandalkan orang | Lemah bila tidak ada pemeriksaan |
| Tinjauan bulanan atas tiket yang kosong | deteksi berkala | Cukup, bila tinjauannya benar-benar berjalan |
| Laporan otomatis bila ada tiket kosong | deteksi otomatis | Kuat |
| Kolom wajib di sistem | kesalahan tidak mungkin | Paling kuat |

Tindakan paling kuat tidak selalu paling tepat: kolom wajib bisa mendorong orang mengisi asal-asalan. Tindakan di tingkat mana pun tetap butuh verifikasi efektivitas.

### 2.3 Daftar pantau tindakan korektif

Jawaban untuk pertanyaan ketiga. Posisi per 2027-06-25, disiapkan untuk management review semester 1; kolom verifikasi adalah bagian yang perlu kamu perhatikan.

| Nomor | Asal | Pemilik | Tenggat tindakan | Status | Verifikasi | Catatan |
|---|---|---|---|---|---|---|
| CA-2026-011 | Audit eksternal 2026 | <nama> | 2026-09-30 | diverifikasi efektif | 2027-01-15, lulus | ditutup |
| CA-2026-017 | Insiden INC-2026-008 | <nama> | 2026-11-30 | tindakan selesai | belum dijadwalkan | dijadwalkan saat penyusunan daftar ini |
| CA-2027-002 | Audit internal AI-2026-04 | <nama> | 2027-01-31 | lewat tenggat | belum dijadwalkan | dieskalasi ke management review |
| CA-2027-004 | Audit internal AI-2027-01 | <nama> | 2027-03-31 | tindakan selesai | dijadwalkan 2027-06-30 | |

Kolom verifikasi yang membedakan daftar ini dari daftar tugas biasa. Baris kedua, tindakan selesai tetapi verifikasi belum dijadwalkan tujuh bulan kemudian, adalah pola yang paling sering terlupakan dan paling sering ditanyakan auditor eksternal.

Baris ketiga memperlihatkan jalur eskalasi yang benar: tindakan lewat tenggat dibawa ke tingkat yang bisa memutuskan, bukan diam-diam diperpanjang.

### 2.4 Agenda management review yang menghasilkan keputusan

Jawaban untuk pertanyaan keempat: agenda rapat 1 Juli 2027 yang memisahkan keputusan dari informasi.

```
MANAGEMENT REVIEW                            Periode: semester 1 2027
Tanggal, peserta, ketua                      : 2027-07-01; (diisi)

A. KEPUTUSAN YANG DIMINTA  (dibahas; inti rapat)                       input 9.3.2
  A1. CA-2027-002 lewat tenggat hampir 5 bulan. Pilihan:                d1
      (i) tambah sumber daya, (ii) turunkan lingkup, (iii) terima risiko secara formal
      Rekomendasi penyusun: (i) dengan alasan <...>
  A2. Dua temuan berulang pada area manajemen akses dalam tiga siklus.  d1, d3
      Pilihan: (i) ubah proses, (ii) ganti alat, (iii) terima dan pantau
  A3. Permintaan menerima risiko R-14 secara formal sampai 2028         f

B. INFORMASI  (lampiran dikirim 5 hari kerja sebelumnya; tidak dipresentasikan)
  B1. Status tindakan dari review sebelumnya                            a
  B2. Perubahan isu internal dan eksternal                              b
  B3. Perubahan kebutuhan pihak berkepentingan (kontrak baru, UU PDP)   c
  B4. Daftar pantau tindakan korektif dan 4 angka kesehatan (2.3, 2.6)  d1
  B5. Metrik SOC dan ISMS terhadap sasaran                              d2, d4
  B6. Hasil audit internal dan eksternal periode ini                    d3
  B7. Umpan balik pihak berkepentingan (keluhan, kuesioner klien)       e
  B8. Hasil risk assessment dan status risk treatment plan              f
  B9. Peluang perbaikan yang tidak memerlukan keputusan                 g

C. KELUARAN  (dicatat saat rapat)
  Setiap keputusan: apa yang diputuskan, siapa pemiliknya, kapan tenggatnya,
  dan bagaimana pelaksanaannya akan diperiksa
```

Pemisahan blok A dan B yang membuat rapat ini berbeda: waktu rapat dipakai untuk hal yang memang membutuhkan orang-orang itu berada di satu ruangan. Kolom kanan memastikan ketujuh input 9.3.2 (a sampai g, termasuk empat sub-butir d) tercakup, sehingga auditor bisa menelusuri tiap input ke agenda dan risalah.

### 2.5 Risalah yang berisi keputusan

Risalah rapat 1 Juli 2027. Keputusan K-01 sampai K-03 menjawab ketiga butir blok A di agenda.

```
RISALAH MANAGEMENT REVIEW                    Semester 1 2027

KEPUTUSAN
  K-01  Menambah satu posisi analyst untuk menutup CA-2027-002.
        Pemilik: <nama>   Tenggat: perekrutan dimulai 2027-07-15
        Pemeriksaan: status dilaporkan pada management review berikutnya

  K-02  Mengganti proses tinjauan hak akses dari manual menjadi berbasis laporan otomatis.
        Pemilik: <nama>   Tenggat: 2027-09-30
        Pemeriksaan: audit internal area akses dijadwalkan ulang ke 2027 Q4

  K-03  Risiko R-14 diterima secara formal sampai 2028-06-30 dengan syarat pemantauan bulanan.
        Pemilik: <nama>   Tenggat tinjau ulang: 2028-03-31
        Pemeriksaan: laporan pemantauan bulanan dilampirkan ke review berikutnya

INPUT YANG DITINJAU
  Lampiran B1-B9 dinyatakan sudah ditinjau peserta; tidak ada keberatan atas isinya.

TIDAK DIPUTUSKAN
  Usulan perubahan lingkup sertifikasi ditunda; menunggu kepastian rencana bisnis kuartal depan.
  Akan dibawa kembali pada review berikutnya.
```

K-01 sampai K-03 adalah keputusan 9.3.3 (perbaikan dan perubahan ISMS). Blok input yang ditinjau menjadi jejak bahwa 9.3.2 dipertimbangkan, dan blok tidak diputuskan mencegah usulan hilang tanpa jejak. K-02 juga menaikkan tingkat kekuatan tindakan untuk manajemen akses, dari tinjauan manual ke deteksi otomatis.

### 2.6 Ukuran kesehatan proses perbaikan

Empat angka ini masuk lampiran B4 dan menjawab pertanyaan kedua dari sisi tren: seberapa sering perbaikan tidak bertahan.

```
1. proporsi temuan yang berulang dalam tiga siklus terakhir
2. median waktu dari temuan dibuka sampai tindakan selesai
3. proporsi tindakan yang diverifikasi efektif pada percobaan pertama
4. jumlah tindakan yang lewat tenggat, dan berapa lama
```

Angka ketiga paling jarang dilaporkan dan paling informatif: proporsi yang rendah berarti analisis akar penyebab belum bekerja, masalah yang berbeda dari kurangnya sumber daya. Keempat angka ini mengisi input d1 (tren nonconformity dan tindakan korektif).

## 3. Lab praktik

**Prasyarat:** temuan dari Day 15, daftar risiko dari Day 09, dan catatan insiden dari Day 10.

1. Ambil tiga temuan dari Day 15, lalu untuk masing-masing isi kelima langkah 10.2 (bagian 1.1), termasuk konsekuensi dan cek nonconformity serupa. Periksa apakah ada tindakan korektif yang sebenarnya hanya koreksi.
2. Untuk satu temuan, jalankan analisis akar penyebab sampai berhenti, lalu terapkan uji berhenti di bagian 1.3. Bila gagal uji, lanjutkan satu lapis lagi.
3. Ulangi langkah 2 dengan sengaja berhenti terlalu cepat dan sengaja berjalan terlalu jauh, lalu bandingkan tindakan yang dihasilkan ketiganya.
4. Kelompokkan penyebab dari ketiga temuan ke dalam tiga jenis di bagian 1.4, lalu periksa apakah ada yang kamu beri label penyebab manusia padahal ada lapis sistemik di bawahnya.
5. Untuk setiap tindakan yang kamu usulkan, tentukan tingkat kekuatannya memakai tabel bagian 2.2, lalu naikkan satu tingkat bila memungkinkan dan catat konsekuensinya.
6. Tulis verifikasi efektivitas untuk ketiga tindakan, lengkap dengan apa yang diukur, kapan, ambang, dan apa yang terjadi bila gagal.
7. Susun daftar pantau bagian 2.3 untuk seluruh tindakan fiktifmu, dan sengaja masukkan satu yang lewat tenggat.
8. Susun agenda management review bagian 2.4 dengan pemisahan blok keputusan dan blok informasi, lalu pastikan setiap input 9.3.2 (a sampai g, termasuk d1-d4) punya baris.
9. Jalankan simulasi rapat dengan rekan sebagai manajemen, lalu tulis risalahnya dalam bentuk bagian 2.5 termasuk blok tidak diputuskan.
10. Hitung keempat angka di bagian 2.6 dari data fiktifmu, lalu tulis satu paragraf tentang apa yang angka itu katakan tentang proses perbaikanmu.

**Hasil yang sebaiknya tersimpan:**
- Tiga lembar tindakan korektif yang memuat kelima langkah 10.2, dengan verifikasi efektivitas lengkap.
- Analisis akar penyebab yang lulus uji berhenti, dibandingkan dengan dua titik berhenti yang salah.
- Pengelompokan penyebab dan penilaian kekuatan tindakan, beserta koreksi label bila ada.
- Daftar pantau tindakan termasuk satu yang lewat tenggat.
- Agenda management review dengan dua blok terpisah dan pemetaan ke input 9.3.2.
- Risalah berisi keputusan dengan pemilik dan tenggat, plus blok tidak diputuskan.
- Empat angka kesehatan proses perbaikan beserta tafsirannya.

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Temuan yang sama muncul lagi | Yang dilakukan hanya koreksi | Periksa apakah tindakan menyentuh kasus yang belum ditemukan (bagian 1.2) |
| Akar penyebab berupa nama orang | Berhenti terlalu cepat | Tanyakan kenapa sistem mengizinkan dan kenapa tidak terdeteksi |
| Tindakan berhasil tiga bulan lalu meluruh | Bergantung pada kedisiplinan | Naikkan tingkat kekuatan tindakan (bagian 2.2) |
| Auditor menanyakan bukti efektivitas | Verifikasi tidak dirancang di muka | Tambahkan apa, kapan, ambang, dan konsekuensi gagal |
| Verifikasi selalu lulus | Tidak ada ambang, atau diverifikasi pemilik tindakan | Tetapkan ambang; serahkan verifikasi ke pihak lain |
| Tindakan lewat tenggat diperpanjang diam-diam | Tidak ada jalur eskalasi | Bawa ke management review sebagai keputusan |
| Management review tidak mengubah apa pun | Isinya presentasi status | Pisahkan blok keputusan dari blok informasi (bagian 2.4) |
| Auditor bertanya apakah input c atau e dipertimbangkan | Agenda tidak dipetakan ke 9.3.2 | Tambah kolom huruf input di agenda dan blok input yang ditinjau di risalah |

## 5. Kesalahan umum dan jebakan

- Melaporkan koreksi sebagai tindakan korektif, atau melewatkan penanganan konsekuensi (10.2 a).
- Tidak memeriksa apakah nonconformity serupa ada di tempat lain (10.2 b).
- Menghentikan analisis akar penyebab pada kesalahan satu orang, atau melanjutkannya sampai ke hal yang tidak bisa diubah tim.
- Memilih pelatihan sebagai tindakan untuk masalah yang sebenarnya teknis atau sistemik.
- Menutup tindakan tanpa verifikasi efektivitas, tanpa ambang, atau dengan verifikasi oleh pemilik tindakan sendiri.
- Menetapkan pemilik tindakan berupa tim, bukan orang.
- Memperpanjang tenggat tanpa membawanya ke tingkat yang bisa memutuskan.
- Management review yang melewatkan satu input 9.3.2 (yang sering terlewat adalah c, perubahan kebutuhan pihak berkepentingan), atau tidak menghasilkan keputusan 9.3.3.

## 6. Catatan terkini

Bagian ini menampung status edisi standar kosakata, panduan audit, dan perubahan persyaratan yang memengaruhi isi management review. Berguna saat mengutip definisi di prosedur atau meninjau templat lama.

- ISO 9000:2026 (edisi 5) terbit 27 Mei 2026 dan menggantikan ISO 9000:2015 [S2]. Definisi correction dan corrective action yang dikutip materi pelatihan biasanya masih nomor istilah edisi 2015; cocokkan nomornya di edisi 2026 bila kamu mengutipnya di prosedur.
- ISO/IEC 27000:2026 (edisi 6) memangkas daftar definisinya (Day 07), jadi definisi resmi istilah perbaikan untuk ISMS perlu dicari di standar masing-masing atau di ISO 9000.
- ISO 19011:2026 (edisi 4) terbit 27 Mei 2026 [S3]. Bagian tindak lanjut audit, tempat panduan verifikasi tindakan korektif oleh auditor, sudah ada sejak edisi 2018; tinjau templat tindak lanjutmu terhadap edisi baru.
- Input 9.3.2 c (perubahan kebutuhan dan harapan pihak berkepentingan) baru ada di edisi 2022.
- ISO/IEC 27001:2022 dengan Amd 1:2024 masih edisi berlaku [S1]. Amandemen 2024 menambah pertimbangan perubahan iklim di 4.1 dan 4.2, sehingga isu iklim bisa muncul sebagai input b dan c di management review.

## 7. Cheat sheet

```
10.2  a bereaksi: tahan dan koreksi, tangani konsekuensi
      b evaluasi perlu tindakan: tinjau NC | tentukan penyebab | NC serupa ada / bisa terjadi?
      c terapkan | d tinjau efektivitas | e ubah ISMS bila perlu
      tindakan SEPADAN dampak; simpan: sifat NC, tindakan, hasil CA

KOREKSI vs TINDAKAN KOREKTIF
  koreksi          : menghilangkan ketidaksesuaian YANG DITEMUKAN (kasus ini)
  tindakan korektif: menghilangkan PENYEBAB agar TIDAK TERULANG
  uji sendiri: kalau tindakanmu hanya menyentuh kasus yang ditemukan auditor = itu KOREKSI
  keduanya diperlukan; yang salah adalah MELAPORKAN koreksi sebagai tindakan korektif

AKAR PENYEBAB  jangan berhenti terlalu cepat, jangan berjalan terlalu jauh
  terlalu cepat : akarnya "kesalahan satu orang"  -> tanya kenapa sistem MENGIZINKAN + kenapa TIDAK TERDETEKSI
  terlalu jauh  : akarnya "anggaran" atau "budaya" -> tidak bisa ditindaklanjuti tim
  UJI BERHENTI  : bayangkan akar ini hilang; apakah temuan masih mungkin? kalau ya, lanjut satu lapis

JENIS PENYEBAB  sistemik (prosedur) | teknis (sistem mengizinkan) | manusia (tahu/mampu/terdorong)
  "penyebab manusia" hampir tak pernah berdiri sendiri
  -> kalau kesimpulannya "kurang teliti", tanya kenapa sistem BERGANTUNG pada ketelitian

KEKUATAN TINDAKAN (naikkan setinggi yang masuk akal)
  1 kesalahan TIDAK MUNGKIN terjadi      <- paling kuat
  2 terdeteksi OTOMATIS
  3 terdeteksi lewat TINJAUAN BERKALA
  4 mengandalkan ORANG untuk tidak salah <- paling lemah, akan meluruh
  catatan: yang paling kuat tidak selalu paling tepat (kolom wajib -> diisi asal-asalan)

VERIFIKASI EFEKTIVITAS (wajib, dirancang DI MUKA)
  APA yang diukur | KAPAN diukur | AMBANG berhasil | apa yang terjadi BILA GAGAL
  dijalankan oleh ORANG LAIN, bukan pemilik tindakan
  gagal = temuan DIBUKA KEMBALI, bukan ditutup dengan catatan

POLA GAGAL  koreksi dilaporkan sebagai korektif | akar berupa nama orang
            tindakan bergantung kedisiplinan | tanpa verifikasi | pemilik berupa TIM (= tak ada pemilik)

MANAGEMENT REVIEW 9.3  top management, interval terencana: sesuai | memadai | efektif
  input 9.3.2: a status tindakan lalu | b isu int/eks | c kebutuhan pihak berkepentingan
               d kinerja: d1 NC+CA, d2 monitoring, d3 audit, d4 sasaran
               e umpan balik pihak berkepentingan | f risk assessment + RTP | g peluang perbaikan
  output 9.3.3: keputusan peluang perbaikan + kebutuhan perubahan ISMS; simpan buktinya
  bawa KEPUTUSAN, bukan laporan
  blok A (dibahas): pilihan yang perlu diputuskan, dengan rekomendasi penyusun
  blok B (lampiran, TIDAK dipresentasikan, tetapi dicatat sudah ditinjau): input a-g
  bawa yang BURUK: temuan berulang, tindakan lewat tenggat, risiko yang naik
  risalah tanpa PEMILIK + TENGGAT = bukan keputusan
  catat juga INPUT YANG DITINJAU dan APA YANG TIDAK DIPUTUSKAN beserta kapan dibahas lagi
  tempat yang tepat untuk eskalasi: sumber daya, konflik prioritas, penerimaan risiko formal

4 ANGKA KESEHATAN  temuan berulang | median waktu tutup | LULUS VERIFIKASI PERCOBAAN PERTAMA
                   | tindakan lewat tenggat
  angka ketiga paling jarang dilaporkan dan paling informatif
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Untuk temuan T-01, tim SOC PT AN melengkapi alasan penutupan di enam tiket yang kosong, lalu melaporkan "tindakan korektif selesai". Benarkah?

<details><summary>Jawaban</summary>

Tidak. Melengkapi enam tiket adalah koreksi: tindakan itu hanya menyentuh kasus yang ditemukan auditor dan tidak menyentuh kasus yang belum ditemukan. Tindakan korektif menghilangkan penyebabnya, seperti di CA-2027-004: kolom alasan dijadikan wajib (CA-a), daftar periksa perubahan prosedur ditambahi langkah pemeriksaan sistem pendukung (CA-b), dan prosedur lain ditinjau untuk masalah serupa (CA-c). Langkah 10.2 a juga meminta konsekuensi ditangani, yaitu tiga alert yang alasannya tidak bisa direkonstruksi ditinjau ulang oleh analyst lain. Lihat bagian 1.1, 1.2, dan 2.1.

</details>

**2. Skenario keputusan.** Analisis akar penyebab untuk temuan manajemen akses yang berulang menghasilkan tiga kandidat titik berhenti. Mana yang paling tepat?

- A. "Admin lupa mencabut hak akses karyawan yang pindah divisi."
- B. "Anggaran tim TI kurang dan budaya disiplin organisasi lemah."
- C. "Proses mutasi karyawan tidak memicu permintaan pencabutan hak di sistem akses."

<details><summary>Jawaban</summary>

C. Titik ini bisa diubah oleh organisasi, dan lolos uji berhenti: bila mutasi otomatis memicu permintaan pencabutan, temuan yang sama sulit terjadi lagi. A berhenti terlalu cepat karena akarnya kesalahan satu orang; pertanyaan berikutnya adalah kenapa sistem mengizinkan kesalahan itu dan kenapa tidak terdeteksi. B berjalan terlalu jauh: anggaran dan budaya mungkin benar, tetapi tidak bisa ditindaklanjuti tim yang menerima temuan, dan bila memang itu akarnya, bawa ke management review. Lihat bagian 1.3.

</details>

**3. Pertanyaan jebakan.** Kolom alasan penutupan sudah dijadikan wajib di sistem tiket, tingkat tindakan yang paling kuat. Apakah CA-2027-004 boleh langsung ditutup?

<details><summary>Jawaban</summary>

Tidak. Tindakan di tingkat mana pun tetap butuh verifikasi efektivitas, dan tindakan paling kuat tidak selalu paling tepat: kolom wajib bisa mendorong orang mengisi asal-asalan. Lembar CA-2027-004 sudah menetapkan verifikasinya di muka: 20 tiket acak pada 2027-06-30, ambang nol tiket tanpa alasan, dijalankan auditor internal, dan temuan dibuka kembali bila gagal. Sampai verifikasi itu lulus, statusnya "tindakan selesai", bukan ditutup. Lihat bagian 1.4, 1.5, 2.1, dan 2.2.

</details>

**4. Skenario keputusan.** Pemilik sebuah tindakan korektif mengusulkan rencana verifikasi. Mana yang bisa diterima auditor?

- A. "Seluruh tim sudah dilatih. Verifikasi dilakukan pemilik tindakan."
- B. "Pengambilan 20 tiket acak tiga bulan setelah perubahan, ambang nol tiket tanpa alasan, dijalankan auditor internal; bila gagal, temuan dibuka kembali."
- C. "Laporan otomatis dipantau. Verifikasi dianggap selesai bila tidak ada keluhan."

<details><summary>Jawaban</summary>

B. Rencana ini memuat ketiga unsur wajib (apa yang diukur, kapan, ambang), menetapkan apa yang terjadi bila gagal, dan dijalankan orang lain. A keliru karena "sudah dilatih" adalah bunyi verifikasi yang lemah, dan verifikasi oleh pemilik tindakan cenderung selalu lulus. C keliru karena tidak ada waktu dan ambang; "tidak ada keluhan" adalah penilaian subjektif, berbeda dengan laporan otomatis yang menunjukkan nol kasus selama tiga bulan. Lihat bagian 1.5 dan 2.1.

</details>

**5. Pertanyaan jebakan.** Di daftar pantau PT AN, CA-2026-017 berstatus "tindakan selesai" sebelum tenggat 2026-11-30. Pemiliknya berpendapat tidak ada masalah karena tenggatnya terpenuhi. Benarkah?

<details><summary>Jawaban</summary>

Tidak. Tindakan selesai belum berarti efektif. Tujuh bulan kemudian verifikasinya belum dijadwalkan, dan itu pola yang paling sering terlupakan dan paling sering ditanyakan auditor eksternal. Kolom verifikasi yang membedakan daftar pantau dari daftar tugas biasa. Bandingkan dengan CA-2027-002 yang lewat tenggat: jalur yang benar adalah eskalasi ke management review, bukan perpanjangan diam-diam. Lihat bagian 1.5, 1.6, dan 2.3.

</details>

**6. Jelaskan ulang.** Direktur Operasional bertanya: "Kenapa lampiran B1 sampai B9 tidak dipresentasikan di rapat, tetapi tetap dicatat di risalah sebagai sudah ditinjau?" Jelaskan dalam tiga kalimat.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Waktu rapat dipakai untuk hal yang memang butuh keputusan Bapak dan peserta lain, seperti tindakan yang lewat tenggat, temuan berulang, dan penerimaan risiko; bahan yang tidak membutuhkan keputusan dikirim lima hari kerja sebelumnya. Walaupun tidak dipresentasikan, 9.3.2 meminta setiap input dipertimbangkan, jadi risalah mencatat bahwa lampiran itu sudah ditinjau. Dengan begitu auditor bisa menelusuri ketujuh input ke agenda dan risalah, dan rapat tetap menghasilkan keputusan 9.3.3 dengan pemilik dan tenggat."

Kesalahan yang sering muncul:
- Menghapus input yang tidak butuh keputusan dari agenda dan risalah sama sekali, sehingga jejak 9.3.2 hilang.
- Menganggap tanda tangan peserta cukup sebagai bukti bahwa input dipertimbangkan.
- Lupa bahwa input c, perubahan kebutuhan pihak berkepentingan, yang paling sering terlewat.

</details>

**7. Interview question (English).** "An auditor asks you to show how you closed a nonconformity. What would you show them?"

<details><summary>Sample answer</summary>

"I'd show the corrective action record, which follows clause 10.2 step by step. First the correction and how we handled the consequences, for example filling in the missing ticket reasons and having another analyst re-review the alerts we couldn't reconstruct. Then the root cause analysis, stopped at something we can actually change rather than at one person's mistake, plus a check for similar problems in other procedures. Then the actions, each with a single owner and a deadline, ideally at the strongest reasonable level, like making a field mandatory rather than reminding people. Most importantly, the effectiveness check that we defined in advance: what we measure, when, the pass threshold, and who checks it, someone other than the action owner. The record is only closed once that check passes; if it fails, we reopen it. Overdue or recurring items go to management review as decisions."

What makes this answer strong: it separates correction from corrective action, avoids blaming individuals, considers the strength of the action, and closes on pre-defined evidence of effectiveness verified independently.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | ISO committee: ISO/IEC 27001:2022 | https://committee.iso.org/standard/82875.html | primer (katalog ISO) | Oktober 2022; diakses 2026-10-10 | Tinggi. Edisi 3, Amd 1:2024 |
| S2 | ISO committee: ISO 9000:2026 Quality management, fundamentals and vocabulary | https://committee.iso.org/standard/88465.html | primer (katalog ISO) | 2026-05-27; diakses 2026-10-10 | Tinggi untuk edisi dan status; ISO 9000:2015 withdrawn |
| S3 | ISO committee: ISO 19011:2026 Guidelines for auditing management systems | https://committee.iso.org/standard/88984.html | primer (katalog ISO) | 2026-05-27; diakses 2026-10-10 | Tinggi untuk edisi dan status |
| S4 | HighTable: ISO 27001 clause 10.2 nonconformity and corrective action | https://hightable.io/iso-27001-clause-10-1-nonconformity-and-corrective-action-essential-guide/ | sekunder (konsultan) | diperbarui 2026-10-10; diakses 2026-10-10 | Sedang. Urutan langkah 10.2 dan informasi terdokumentasi; konsisten dengan Day 06 |
| S5 | Hicomply: ISO 27001 clause 9.3 management review (2022) | https://hicomply.com/hub/iso-27001-clause-9-3-management-review-2022 | sekunder (vendor) | diakses 2026-10-10 | Sedang. Isi 9.3.1-9.3.3; pengelompokan butir d di halaman itu kurang rapi, urutan a-g mengikuti Day 06 |
| S6 | Institute for Healthcare Improvement: RCA2, improving root cause analyses and actions to prevent harm | https://www.ihi.org/library/tools/rca2-improving-root-cause-analyses-and-actions-prevent-harm | sekunder (lembaga keselamatan pasien) | RCA2 2015, Action Hierarchy 2019; diakses 2026-10-10 | Sedang-tinggi untuk fokus sistem dan tujuan action hierarchy; bukan standar ISO |

**Catatan sumber:** isi 10.2 dan 9.3 diparafrasekan dari ringkasan sekunder [S4][S5] yang cocok dengan Day 06, bukan dari teks standar. Pemisahan correction dan corrective action di ISO 9000:2015 adalah kosakata baku, tetapi tidak ada sumber terbuka di tabel ini yang memuat teks definisinya. Urutan kekuatan tindakan di bagian 1.4 dan 2.2 diadaptasi dari gagasan action hierarchy [S6]; rincian tingkatnya di Day ini susunan sendiri. Empat ukuran kesehatan di bagian 2.6 bukan persyaratan ISO. Seluruh nomor dokumen, nama, tenggat, ambang, dan angka di bagian 2 adalah fiktif.
