---
day: 19
title: 'Pelaporan forensik: struktur laporan, menulis untuk audiens berbeda, keyakinan dan keterbatasan, dan defensibility'
researched_on: 2026-10-22
versions_checked: 'NIST SP 800-86 bagian 3.4 Reporting (Agustus 2006, final, halaman CSRC tanpa catatan revisi per 2026-10-22); NIST SP 800-61r3 (April 2025, menggantikan r2); ODNI ICD 203 Analytic Standards (2 Januari 2015, amandemen teknis 2022 dan 2023); ISO/IEC 27042:2015 edisi 1.0 (hanya abstrak penerbit); Lenny Zeltser IR writing guidelines 1.5.1 (2026-05-26); versi alat di lampiran mengikuti pembekuan kasus di Day 17 dan 18 (EZ Tools 2026.5.0, Volatility 3 2.28.2); rujukan Day 01, 12, 13, 17, 18'
---

# Day 19: Pelaporan forensik

Cakupan: menyusun laporan forensik yang bisa dibaca manajemen, dipakai tim teknis, dan dipertahankan bila dipersoalkan, dengan keyakinan dan keterbatasan yang dinyatakan untuk setiap temuan, lewat satu template baku yang diuji pada dua kasus: dugaan pencurian data oleh orang dalam dan infeksi installer palsu.

## Ide inti

Laporan adalah produk akhir forensik, dan pembacanya hampir tidak pernah melihat artefak. Mereka menilai seberapa kuat sebuah kesimpulan dari kata yang kamu pilih, dari urutan bagian, dan dari apa yang kamu tulis sebagai batas. Karena itu laporan forensik bukan ringkasan pekerjaan teknis, tetapi dokumen keputusan: setiap kalimat harus bisa ditunjuk ke artefak, setiap kesimpulan membawa tingkat keyakinan dari satu skala yang sama, fakta dipisahkan dari tafsiran dan pendapat, dan yang tidak bisa dijawab ditulis sejelas yang bisa dijawab. Satu laporan yang sama dibaca beberapa pihak sekaligus, jadi strukturnya disusun dari umum ke rinci supaya direksi bisa berhenti di halaman pertama, sedangkan analyst lain yang ingin mengulang pekerjaanmu langsung ke metodologi dan lampiran. Laporan yang baik tidak berusaha terdengar yakin; ia berusaha tepat, dan ketepatan itu yang membuatnya bertahan saat dipersoalkan.

Kamu sudah mengenal pola ini dari NOC. Setelah gangguan besar yang mengenai pelanggan korporat, kamu menulis RFO (reason for outage). Paragraf pertamanya dibaca direksi dan account manager: apa yang terjadi, berapa lama, pelanggan mana yang terdampak, dan apa yang sudah dilakukan. Kronologinya dibaca engineer lain dan vendor, dengan setiap baris menunjuk log perangkat. Lampirannya dibaca pelanggan yang menuntut kompensasi SLA, dan di situlah setiap kata dipersoalkan: "root cause confirmed" berbeda dengan "suspected", dan "tidak ada indikasi gangguan sebelumnya" ditanya balik "log mana yang kamu periksa". Engineer senior menulis RFO dengan satu template, menyebut status root cause dengan istilah yang sama di semua RFO, dan menerbitkan revisi bila TAC vendor memberi temuan baru, bukan menimpa versi lama. Batasnya: RFO jarang menyangkut orang. Laporan forensik bisa dipakai untuk keputusan hubungan kerja dan proses hukum, sehingga satu kata yang berlebihan bisa merugikan orang yang tidak bersalah atau membuat seluruh laporan ditolak.

```
artefak, case notes, temuan per pertanyaan (Day 17, Day 18)
        |
        v
TEMPLATE BAKU (dari umum ke rinci)
  inti + keputusan        -> direksi (berhenti di sini)
  ringkasan eksekutif     -> direksi, HR, Legal, DPO
  lingkup + metodologi    -> Legal, analyst lain
  temuan: FAKTA | TAFSIRAN | PENDAPAT (ditandai) + KEYAKINAN + BATAS + hipotesis alternatif
  garis waktu kurasi, IOC, data pribadi, yang belum diketahui
  rekomendasi: apa | kenapa | pemilik | tenggat
  lampiran: CoC + hash, alat + versi, keluaran pendukung, riwayat versi, glosarium
        |
        v
REVIEW sebelum kirim (teknis + non-teknis + Legal untuk kasus berpotensi litigasi)
        |
        v
draf 0.x -> final 1.0 -> revisi 1.1 bila ada data baru (tercatat, tidak menimpa diam-diam)
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan, layanan broadband rumah untuk sekitar 400 ribu pelanggan dan dedicated internet untuk pelanggan korporat. Kamu adalah analyst L2 yang memegang forensik endpoint. Dua kasus sudah kamu kerjakan dan menjadi bahan Day ini.

Kasus pertama, `INC-2027-010` (SEV-3, dugaan pencurian data oleh orang dalam). Arif Wicaksono (`arif.wicaksono`), account manager pelanggan korporat di Divisi Enterprise Sales Jakarta, mengundurkan diri dengan hari kerja terakhir Jumat 2027-01-08. Senin 2027-01-11, PIC PT Samudra Logistik Contoh melapor ditawari ISP pesaing dengan harga yang sama dengan harga kontrak PT JAB. Atas izin tertulis Legal, kamu memeriksa image laptop kantornya `JKT-WS-0516` (`INC-2027-010-E01`), log akses share `JKT-FS01`, proxy, dan Defender, lalu Rabu 2027-01-13 pukul 17:10 mengirim ringkasan forensik ke Dimas Prasetyo (SOC lead, incident commander) sebagai bahan rapat HR, Legal, dan DPO Kamis 2027-01-14 (Day 17 bagian 2.9). Ringkasan itu adalah jawaban sementara, bukan laporan.

Kasus kedua, `INC-2026-026` (SEV-2, Desember 2026). Installer PDF palsu dari iklan pencarian menjatuhkan `pdfupdater.exe` bertanda tangan vendor dan `version.dll` tak bertanda tangan di laptop `BDG-WS-0163` (`bima.ardiansyah`, Sales Bandung), yang berjalan tiga hari tanpa alert sampai hunting menemukannya Senin 2026-12-07. Selasa 2026-12-08 kamu membedah host itu dan pukul 15:30 mengirim jawaban tertulis ke Rudi Hartanto (technical lead) (Day 18 bagian 2.10). Jawaban itu hanya terbit sebagai memo kerja, tidak pernah sebagai laporan forensik.

Senin 2027-01-18 pukul 09:00, Dimas menulis kepadamu di kanal `#inc-2027-010`:

> "Pagi. Ringkasan forensik `INC-2027-010` yang kamu kirim Rabu lalu sudah dipakai di rapat Kamis, terima kasih. Sekarang Bu Ratna (Legal) dan Bu Larasati (HR) minta laporan forensik final yang bisa dipakai untuk keputusan HR dan, kalau perlu, langkah hukum. Pak Agus (DPO) minta satu bagian khusus yang menjawab: apakah data pribadi PIC pelanggan korporat keluar dari PT JAB atau tidak. Pak Hendra cuma akan baca satu halaman, jadi halaman pertama harus berdiri sendiri. Sekalian, kita belum punya template laporan forensik baku. Tolong susun satu, kasih nomor dokumen, lalu uji dengan menulis ulang `INC-2026-026` versi forensik host `BDG-WS-0163` yang Desember lalu cuma jadi memo. Draf keduanya Rabu 20 Januari; Sari review teknis, Bu Ratna review bahasa, baru kita finalkan. Satu lagi: jangan sampai laporan final bertentangan dengan ringkasan Rabu lalu, karena ringkasan itu sudah dibaca banyak orang."

Pesan itu memuat tujuh pertanyaan:

1. Struktur baku apa yang dipakai untuk semua laporan forensik PT JAB, dan bagian mana untuk pembaca mana?
2. Bagaimana menulis halaman pertama yang berdiri sendiri untuk Pak Hendra, netral, dan tidak lebih kuat dari bukti?
3. Bagaimana menyatakan keyakinan per temuan dan memisahkan fakta, tafsiran, dan pendapat supaya laporan bisa dipakai untuk keputusan HR dan langkah hukum?
4. Bagaimana menjawab pertanyaan DPO, "apakah data pribadi PIC keluar dari PT JAB", dengan jujur?
5. Garis waktu, IOC, dan rekomendasi seperti apa yang layak masuk laporan?
6. Apa yang membuat laporan bisa dipertahankan bila dipersoalkan, dan bagaimana memeriksanya sebelum dikirim?
7. Bagaimana laporan final berhubungan dengan ringkasan sementara yang sudah beredar, dan apa yang dilakukan bila ada temuan yang berubah?

Pertanyaan 1 dijawab di bagian 1.1 dan 2.1, pertanyaan 2 di bagian 1.2, 2.2, dan 2.4, pertanyaan 3 di bagian 1.3, 1.4, dan 1.5 dengan contoh di 2.5 dan 2.6, pertanyaan 4 di bagian 1.9 dan 2.3, pertanyaan 5 di bagian 1.6, 1.7, 2.7, dan 2.8, pertanyaan 6 di bagian 1.8, 2.9, dan 2.10, dan pertanyaan 7 di bagian 1.10 dan 2.11. Isi Day ini adalah praktik kerja pelaporan, bukan nasihat hukum; untuk kasus yang berpotensi litigasi, struktur, bahasa, penandaan, dan distribusi laporan dibahas dengan Legal sebelum laporan final diterbitkan.

**Kapan relevan:** akhir setiap investigasi forensik; laporan interim selama kasus berjalan; laporan yang dibaca HR, Legal, DPO, auditor, asuransi siber, atau pihak luar; menulis ulang memo kerja menjadi laporan yang bisa disimpan dan dirujuk.
**Kapan bukan jawaban:** insiden kecil yang selesai dalam sehari cukup dengan memo dua halaman yang memakai skala keyakinan yang sama; penilaian kewajiban notifikasi atau langkah hukum adalah wewenang DPO dan Legal, bukan isi laporan forensik; laporan post-incident review yang menilai proses respons secara keseluruhan memakai bahan dari laporan ini tetapi bukan laporan ini; dan review akhir seluruh rangkaian ada di Day 20.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (chain of custody, case notes, hash bukti, salinan kerja, garis waktu kurasi, lembar batas bukti, hipotesis tandingan, tangga bukti, lingkup izin, IOC atomik, IOC perilaku, jejak responder, pembekuan versi per kasus) tidak diulang. Tabel ini hanya memuat istilah baru Day ini; kolom padanan memakai analogi NOC dan SOC yang sama di semua Day.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Laporan forensik | Dokumen akhir yang menjawab pertanyaan investigasi dengan temuan, keyakinan, batas, dan lampiran yang bisa ditelusuri | RFO gangguan besar untuk pelanggan korporat dengan klaim SLA |
| Executive summary (ringkasan eksekutif) | Bagian depan yang berdiri sendiri: apa yang terjadi, seberapa parah, status, dan keputusan yang dibutuhkan | Paragraf pertama RFO yang dibaca direksi dan account manager |
| Finding (temuan) | Satu jawaban atas satu pertanyaan, dengan bukti, tafsiran, keyakinan, batas, dan hipotesis alternatif | Satu baris root cause di RFO beserta log pendukungnya |
| Skala keyakinan | Satu set istilah tetap untuk menyatakan seberapa kuat bukti mendukung sebuah pernyataan | Status root cause "confirmed", "probable", "suspected" yang dipakai sama di semua RFO |
| Fakta, tafsiran, pendapat | Tiga lapis pernyataan: yang tercatat, arti menurut pengetahuan forensik, dan penilaian yang melampaui artefak | Log interface down, kesimpulan fiber putus, dugaan penyebabnya pekerjaan galian pihak lain |
| Defensibility | Sifat laporan yang penalarannya bisa diikuti dan hasilnya bisa diulang orang lain dari bukti yang sama | RFO yang bertahan saat pelanggan menuntut kompensasi SLA dan meminta log mentahnya |
| Laporan interim | Update tertulis selama kasus berjalan, dengan status keyakinan dan perubahan sejak update sebelumnya | Update berkala di bridge dan status page selama gangguan berlangsung |
| Riwayat versi laporan | Catatan draf, final, dan revisi: tanggal, apa yang berubah, dan kenapa | Revisi RFO setelah TAC vendor memberi temuan baru, dengan nomor revisi |

### 1.1 Struktur laporan dan template baku: satu urutan untuk banyak pembaca

Pertanyaan pertama Dimas meminta struktur yang dipakai semua laporan, bukan format sekali pakai untuk `INC-2027-010`. Template baku punya dua keuntungan. Pembaca yang sama (Legal, DPO, direksi) belajar di mana jawaban mereka berada, dan penulis tidak lupa bagian yang mudah terlewat seperti "yang tidak diketahui" atau riwayat versi.

Laporan forensik dibaca beberapa pihak sekaligus, dan setiap pihak punya pertanyaan yang berbeda. Manajemen memakainya untuk keputusan bisnis: mengisolasi sistem, memberi tahu pelanggan, melapor ke regulator. Tim teknis memakainya untuk remediasi. HR dan Legal memakainya bila kasus melibatkan karyawan atau pihak ketiga. Kadang auditor atau asuransi siber juga membacanya. Laporan yang baik menjawab semuanya tanpa memaksa satu pembaca membaca bagian yang ditujukan ke pembaca lain. Panduan penulisan laporan IR dari praktisi merumuskan kebutuhan ini dengan cara yang sama: eksekutif butuh dampak, eksposur regulasi, dan keputusan; pembaca teknis butuh root cause dan indikator; pembaca hukum butuh cakupan data, tenggat, dan status bukti; asuransi butuh garis waktu, containment, dan rincian biaya [S6].

Tabel berikut adalah urutan bagian di template PT JAB; baca kolom "Pembaca utama" untuk memastikan setiap pembaca di pesan Dimas punya bagian yang bisa ia baca tanpa membaca yang lain.

| Bagian | Isi | Pembaca utama |
|---|---|---|
| Inti dan keputusan | Tiga sampai lima kalimat: apa yang terjadi, dampak, status; keputusan yang diminta, disebut eksplisit | Direksi |
| Executive summary | Apa yang terjadi, dampak, status, keputusan yang dibutuhkan, keyakinan per temuan, tanpa istilah teknis | Manajemen, HR, Legal, DPO |
| Scope dan pertanyaan | Sistem yang diperiksa, pertanyaan yang dijawab, lingkup izin, apa yang di luar cakupan | Semua |
| Metodologi | Cara bukti dikumpulkan dan dianalisis, alat dan versi, zona waktu, skala keyakinan, asumsi | Teknis, Legal |
| Findings | Temuan berurutan, masing-masing dengan bukti, tafsiran, keyakinan, keterbatasan, hipotesis alternatif | Teknis, manajemen |
| Timeline | Kejadian signifikan berurutan dengan sumber per baris | Semua |
| Data pribadi dan dampak | Data apa, berapa, sampai anak tangga bukti mana, apa yang tidak dapat ditentukan | DPO, Legal |
| IOC | Indikator dengan jenis dan daya tahan | Teknis |
| Yang belum diketahui | Pertanyaan terbuka, sumber yang bisa menjawabnya, dan siapa yang memutuskan | Legal, IC |
| Recommendations | Containment, remediasi, pencarian lintas lingkungan, deteksi, perbaikan visibilitas; dengan pemilik dan tenggat | Manajemen, teknis |
| Appendices | Chain of custody, hash bukti, daftar alat, keluaran pendukung, riwayat versi, glosarium | Teknis, Legal |

Urutannya sengaja dari umum ke rinci. Manajer berhenti setelah executive summary dan rekomendasi; analyst yang mengulang pekerjaanmu langsung ke metodologi dan lampiran. Tiga bagian di tabel itu tidak ada di banyak template lama dan sengaja ditambahkan. "Data pribadi dan dampak" ada karena PT JAB adalah pengendali data pribadi dan DPO butuh jawaban yang bisa ia nilai sendiri. "Yang belum diketahui" ada karena di kasus orang dalam, bagian inilah yang menentukan langkah Legal berikutnya; praktisi menyebutnya investigative leads, yaitu sumber atau perangkat di luar cakupan yang bisa menjawab pertanyaan sisa [S8]. Glosarium di lampiran ada karena pembaca non-teknis akan menemui istilah seperti VSN atau Recycle Bin [S8].

Template tidak berarti semua bagian wajib terisi panjang. Bagian IOC di kasus orang dalam biasanya kosong dan ditulis "tidak relevan untuk kasus ini"; bagian data pribadi di kasus malware tanpa akses data cukup satu kalimat. Yang penting, bagian itu ada dan dinyatakan kosong dengan alasan, sehingga pembaca tahu ia tidak terlewat.

### 1.2 Executive summary: bagian yang paling banyak dibaca

Pertanyaan kedua Dimas menyangkut satu halaman yang akan dibaca Hendra Wijaya, Direktur Teknologi. Executive summary adalah bagian yang paling banyak dibaca dan sering satu-satunya yang dibaca. Empat hal yang harus dijawab, dalam urutan ini: apa yang terjadi, seberapa parah, apa statusnya sekarang, dan keputusan apa yang dibutuhkan dari pembaca.

Prinsipnya:

- **Bahasa dampak, bukan nama artefak.** "Malware mendapat kendali atas satu workstation" lebih berguna daripada "region RWX ditemukan di proses updater". Istilah teknis yang tidak bisa dihindari dijelaskan saat pertama muncul [S6].
- **Satu halaman atau kurang.** Di atasnya, tiga sampai lima kalimat inti yang bisa dibaca dalam setengah menit. Panduan praktisi menyarankan inti seperti ini di bawah sekitar 150 kata, dibuka dengan bahasa biasa (bukan nomor kasus), dengan angka konkret dan permintaan keputusan yang disebut eksplisit [S6].
- **Angka konkret bila ada:** berapa host, berapa lama, berapa berkas, data apa. "Beberapa berkas" diganti "19 berkas" [S6].
- **Kepastian dinyatakan jujur** dengan bahasa keyakinan di bagian 1.4, per temuan, bukan satu label untuk seluruh kasus.
- **Tidak ada informasi baru yang tidak muncul di findings.** Executive summary meringkas, bukan menambah. Karena itu ia ditulis terakhir, setelah temuan selesai, walaupun letaknya paling depan [S8].
- **Berdiri sendiri.** Pembaca yang tidak membuka halaman lain harus tetap tahu batasnya: apa yang tidak diperiksa dan apa yang tidak bisa ditentukan. Ringkasan untuk pembaca non-teknis cukup sebagai satu-satunya dokumen bila klien atau pengacara hanya butuh ringkasan, jadi ia tidak boleh bergantung pada bagian lain untuk batasnya [S7].

Untuk kasus orang dalam ada satu syarat tambahan: halaman pertama menyebut eksplisit bahwa laporan menjelaskan aktivitas akun dan perangkat, bukan niat atau kesalahan seseorang. Kalimat itu sudah ada di ringkasan Rabu (Day 17 bagian 2.9) dan harus tetap ada di laporan final, karena halaman pertama itulah yang paling mungkin dikutip lepas dari konteksnya.

**Kapan gagal:** executive summary disusun dari ingatan rapat, bukan dari findings, sehingga memuat kalimat yang lebih kuat dari temuan. Tandanya: ada kalimat di halaman pertama yang tidak bisa kamu tunjuk ke satu finding.

### 1.3 Tiga faktor dari NIST SP 800-86 dan apa yang ditambahkan SP 800-61r3

Pertanyaan ketiga Dimas ("bisa dipakai untuk keputusan HR dan langkah hukum") punya dasar di panduan publik. NIST SP 800-86 membagi proses forensik menjadi empat tahap: collection, examination, analysis, dan reporting [S1]. Investigasi terbaik pun tidak berguna bila temuannya tidak tersampaikan dengan jelas, atau bila satu kalimat yang berlebihan membuat seluruh laporan diragukan.

SP 800-86 mendefinisikan reporting sebagai proses menyiapkan dan menyajikan informasi hasil tahap analisis, dan menyebut beberapa faktor yang memengaruhinya [S1]. Tiga yang paling berguna untuk pekerjaan sehari-hari:

- **Penjelasan alternatif.** Bila informasi tidak lengkap, bisa ada lebih dari satu penjelasan yang masuk akal. Setiap penjelasan harus dipertimbangkan dan diuji secara metodis, lalu dilaporkan mana yang didukung dan mana yang disingkirkan [S1]. Ini yang dilakukan di Day 17 dengan hipotesis H1 sampai H4 dan di Day 18 dengan H1 sampai H3. Di laporan, hasil pengujian itu menjadi tabel hipotesis alternatif, bukan catatan kaki.
- **Pertimbangan audiens.** Kasus yang melibatkan penegak hukum butuh laporan sangat rinci beserta salinan bukti; administrator sistem butuh detail teknis; manajemen senior butuh gambaran tingkat tinggi tentang apa yang terjadi dan apa yang harus dicegah [S1]. Template di bagian 1.1 menjawab faktor ini dengan urutan bagian, bukan dengan menulis tiga laporan berbeda.
- **Informasi yang bisa ditindaklanjuti.** Laporan juga mengidentifikasi informasi yang membuka sumber data baru atau mencegah kejadian berikutnya, misalnya backdoor yang masih terpasang atau kerentanan yang bisa dieksploitasi lagi [S1]. Di `INC-2026-026`, domain kampanye baru dari alert `SOC-2026-0272` adalah informasi semacam ini; di `INC-2027-010`, message trace Microsoft 365 dan flashdisk itu sendiri adalah sumber data baru yang hanya bisa dibuka atas keputusan Legal.

SP 800-86 juga menyarankan agar proses pelaporan mencatat masalah yang perlu diperbaiki, seperti kekurangan kebijakan, kesalahan prosedur, atau logging yang tidak cukup, termasuk bagaimana kontrol seperti audit dan logging bisa diubah agar mencatat data yang berguna untuk investigasi berikutnya [S1]. Di laporan swasta, ini menjadi kelompok "perbaikan visibilitas" di rekomendasi: Audit Removable Storage yang tidak ada di GPO `JAB-WS-Audit` (Day 17), dan laptop Bandung yang tidak menerima GPO audit Jakarta (Day 18).

Dua hal lain dari SP 800-86 relevan untuk kasus yang mungkin dipakai di proses disipliner atau hukum. Di tahap analisis, pendekatan metodis bisa berujung pada kesimpulan, atau pada pernyataan bahwa belum ada kesimpulan yang bisa diambil; keduanya hasil yang sah [S1]. Dan bila bukti mungkin dibutuhkan untuk tindakan hukum atau disipliner internal, analyst mendokumentasikan temuan dan setiap langkah dengan cermat [S1].

SP 800-61r3 (April 2025) menyusun rekomendasi respons insiden mengikuti fungsi NIST CSF 2.0, dan beberapa butirnya langsung menyentuh laporan forensik [S2]:

- tindakan selama investigasi dicatat, dan integritas serta asal-usul catatan itu dijaga; catatan respons insiden bisa memuat informasi sensitif, termasuk pengguna yang mungkin melakukan tindakan tidak semestinya, sehingga aksesnya dibatasi (RS.AN-06);
- data dan metadata insiden tetap diperlakukan sebagai bukti walaupun sebagian besar insiden tidak berujung penuntutan (RS.AN-07);
- urutan kejadian, aset yang terlibat, dan akar masalah ditetapkan (RS.AN-03);
- prosedur koordinasi menyebut apa yang dilaporkan ke siapa dan kapan, termasuk notifikasi awal dan update status berkala, dan HR diberi tahu bila ada aktivitas orang dalam yang merugikan (RS.CO-02, RS.CO-03);
- perbaikan sering ditemukan saat menyusun laporan tindak lanjut atau rapat lessons learned (ID.IM-03).

Butir terakhir menjelaskan kenapa laporan forensik dan post-incident review saling mengisi tetapi berbeda: laporan forensik menetapkan apa yang terjadi dan seberapa yakin, review menilai bagaimana organisasi merespons.

### 1.4 Bahasa keyakinan: satu skala untuk seluruh laporan

Pertanyaan ketiga Dimas juga menyangkut kata. Pembaca tidak bisa melihat artefak; mereka menilai kepastian dari kata yang kamu pilih. Kata yang dipakai bergantian tanpa aturan membuat laporan terasa tidak konsisten, dan di rapat dengan Legal, perbedaan antara "menunjukkan" dan "mendukung" akan ditanyakan. Tetapkan satu skala dan pakai di seluruh laporan.

Tabel berikut adalah skala di template PT JAB; ia menyatukan syarat yang sudah dipakai di Day 17 dan Day 18 dengan frasa baku untuk tiap tingkat. Cari kolom "Frasa": hanya frasa di kolom itu yang dipakai untuk menyatakan kesimpulan.

| Tingkat | Kapan dipakai | Frasa |
|---|---|---|
| Tinggi | Beberapa artefak independen sepakat (minimal dua sumber yang sifatnya berbeda), tidak ada bukti yang bertentangan | "Bukti menunjukkan", "terkonfirmasi" |
| Sedang | Bukti konsisten tetapi ada celah atau satu sumber saja; rantai lengkap tetapi tidak langsung | "Bukti mendukung", "kemungkinan besar" |
| Rendah | Indikasi tunggal atau tidak langsung, atau inferensi dari ketiadaan | "Ada indikasi", "tidak dapat dipastikan" |
| Tidak dapat ditentukan | Data yang dibutuhkan tidak tersedia | "Tidak dapat ditentukan dari data yang tersedia" |

Cantumkan tabel ini di bagian metodologi supaya pembaca tahu maknanya. Hindari "jelas", "pasti", dan "tidak ada" kecuali benar-benar terbukti. "Tidak ditemukan bukti X" berbeda dari "X tidak terjadi": kalimat pertama melaporkan pemeriksaan, kalimat kedua mengklaim sesuatu yang biasanya tidak bisa dibuktikan. Praktisi juga menyarankan menghindari kata sifat dan keterangan penguat seperti "jelas" atau "mutlak", karena kata itu mengubah pendapat ahli menjadi pendapat pribadi [S8].

Standar analisis komunitas intelijen AS (ICD 203) bukan standar forensik, tetapi tiga aturannya berguna untuk skala ini [S4]:

- **Konsistensi istilah.** Keberhasilan menyatakan ketidakpastian bergantung pada istilah yang dipakai konsisten beserta alasan yang mendukungnya. Jangan mencampur dua set istilah dalam satu dokumen tanpa penjelasan.
- **Keyakinan dan kemungkinan dipisah.** ICD 203 membedakan derajat kemungkinan sebuah kejadian (dari "remote" sampai "nearly certain") dari tingkat keyakinan analyst atas penilaiannya, dan meminta keduanya tidak digabung dalam satu kalimat. Dalam praktik PT JAB, skala di atas adalah satu skala keyakinan yang diikat ke bukti; jangan menulis kalimat seperti "keyakinan tinggi bahwa kemungkinan besar ...", karena pembaca tidak tahu kata mana yang menentukan.
- **Sebut penyebab ketidakpastian dan indikator yang akan mengubahnya.** Setiap keyakinan sedang atau rendah disertai alasan (data tidak lengkap, satu sumber, jendela log) dan apa yang bisa menaikkannya. Di laporan PT JAB, ini menjadi bagian "Yang dapat menaikkan kepastian", seperti di ringkasan Day 17.

Keyakinan ditulis per temuan, bahkan per bagian temuan bila perlu. Temuan penyalinan di `INC-2027-010` adalah contohnya: tinggi untuk salinan lokal, sedang untuk dua berkas di flashdisk, rendah untuk 17 berkas lain di flashdisk, dan tidak dapat ditentukan untuk isi flashdisk. Satu label "sedang" untuk seluruh temuan akan menurunkan bagian yang kuat dan menaikkan bagian yang lemah sekaligus. Bila sumber memberi rentang, seperti "rendah sampai sedang" untuk "tidak terlihat unggahan dari laptop di kantor" (Day 17 bagian 2.7), rentang itu boleh dipertahankan asal alasannya ditulis di kalimat yang sama.

Panduan praktisi menambahkan satu hal untuk laporan yang terbit lebih dari sekali: tandai apakah keyakinan itu preliminary atau final, lalu sebut bukti yang masih ditunggu dan apa yang akan mengubahnya [S6]. Ini menghubungkan skala dengan laporan interim di bagian 1.10.

### 1.5 Fakta, interpretasi, pendapat

Lapisan kedua pertanyaan ketiga Dimas adalah bagaimana sebuah kalimat bertahan saat disanggah. Satu temuan biasanya mengandung tiga lapis yang harus bisa dibedakan pembaca:

- **Fakta:** apa yang tercatat. "Event 4688 pukul 19:33:46 WIB mencatat `EXCEL.EXE` PID 7344 dijalankan dengan path `E:\JAB\Kontrak-Ref\HK-2026-SMLC.xlsx`."
- **Interpretasi:** arti fakta menurut pengetahuan forensik. "Berkas itu dibuka dari volume removable yang tersambung pada sesi profil `arif.wicaksono`."
- **Pendapat:** penilaian yang melampaui artefak. "Penyalinan seluruh folder kemungkinan dilakukan sekaligus lewat Explorer."

Fakta ditulis di bagian Bukti, interpretasi di Analisis, dan pendapat, bila memang perlu, ditandai sebagai pendapat analis. Bila pembaca tidak bisa membedakan ketiganya, sanggahan terhadap satu pendapat bisa meruntuhkan kepercayaan pada fakta yang sebenarnya kuat.

ICD 203 memakai pembagian yang mirip: produk analisis harus membedakan informasi yang mendasari dari asumsi dan penilaian analyst, menyebut asumsi secara eksplisit bila ia menjadi tumpuan argumen atau menjembatani celah informasi, dan menjelaskan akibatnya bila asumsi itu ternyata salah [S4]. Di laporan forensik, asumsi yang paling sering tersembunyi adalah asumsi tentang alat dan perilaku sistem: "waktu pembuatan di FAT adalah waktu penyalinan" atau "satu LNK berakhiran `(2)` berarti pembukaan kedua". Keduanya ditulis di Day 17 sebagai hal yang perlu diamati di lab. Di laporan, asumsi seperti itu dicantumkan di metodologi beserta dampaknya: bila perilaku waktu penyalinan berbeda, keyakinan "dua berkas disalin sekitar 19:31" turun, tetapi fakta bahwa dua berkas dibuka dari flashdisk tidak berubah.

Pendapat tidak dilarang. Analyst yang berpengalaman boleh menulis penilaian yang membantu pembaca, asal ditandai, diberi alasan, dan tidak menyangkut niat seseorang. Pendapat tentang niat, kesalahan, atau motif tidak pernah ditulis di laporan forensik (bagian 1.9).

### 1.6 Timeline untuk laporan

Pertanyaan kelima Dimas dimulai dari garis waktu. Timeline di laporan berbeda dari super-timeline mentah (Day 13). Ia dikurasi:

- Hanya kejadian yang mendukung temuan, biasanya 10 sampai 30 baris.
- Zona waktu dinyatakan di judul kolom. Untuk pembaca lokal, tampilkan waktu lokal dan UTC.
- Setiap baris menyebut sumber, sehingga pembaca bisa menelusuri ke lampiran.
- Kejadian yang disimpulkan (bukan tercatat langsung) ditandai.

Tiga aturan tambahan dari pengalaman `INC-2026-019` dan dua kasus Day ini. Pertama, waktu kejadian dipisah dari waktu ditemukan: infeksi `BDG-WS-0163` mulai Jumat 2026-12-04, ditemukan Senin 2026-12-07, dan jarak itu (dwell time) adalah informasi untuk manajemen [S6]. Kedua, aktivitas penyerang atau subjek dipisah dari aktivitas responder dengan kolom pelaku, seperti baris `adm.yoga` di garis waktu Day 17 bagian 2.9; panduan praktisi juga menyarankan memisahkan aktivitas penyerang dari aktivitas respons di insiden bertahap [S6]. Ketiga, celah diakui di garis waktu itu sendiri, bukan hanya di keterbatasan: baris "laptop tidak tersambung ke jaringan sampai shutdown" di kasus Arif adalah celah yang menjelaskan kenapa Defender tidak punya data malam itu.

Garis waktu kurasi wajib disertai tiga daftar yang sudah dipakai di Day 13 bagian 1.7 dan Day 17 bagian 2.9: tidak ditemukan (dengan cakupan), tidak bisa dijawab dari sumber yang ada, dan bisa dijawab dengan sumber tambahan. Tanpa tiga daftar itu, pembaca menganggap yang tidak ada di garis waktu berarti tidak terjadi.

### 1.7 IOC dan rekomendasi

Bagian akhir pertanyaan kelima Dimas adalah apa yang harus dikerjakan orang setelah membaca laporan. IOC disajikan dengan jenis, nilai dalam bentuk defang, sumber, dan daya tahan (Day 18 bagian 2.8). Defang (`198.51.100[.]37`, `cdn.pdfsuite-update[.]example[.]net`) mencegah nilai berubah menjadi tautan aktif di email atau dokumen dan mencegah orang membukanya tanpa sengaja; nilai mentah tetap ada di lampiran CSV untuk tim deteksi. Hash biner sah tidak pernah masuk daftar. Di `INC-2026-026`, itu berarti hash `version.dll` JAB DocSync (`8a41d0c3...`) ditulis sebagai known-good untuk pengecualian, bukan sebagai IOC.

Rekomendasi yang baik punya pemilik dan bisa diperiksa selesai atau belum. Bandingkan:

- Lemah: "Tingkatkan keamanan endpoint."
- Kuat: "Blokir domain `cdn.pdfsuite-update[.]example[.]net` dan IP `198.51.100[.]37` di proxy dan DNS internal (NOC, hari ini)."

Kelompokkan rekomendasi menjadi containment (sekarang), remediasi (sebelum host kembali dipakai), pencarian lintas lingkungan (apakah host lain terkena), deteksi baru (agar pola yang sama terlihat lebih cepat), dan perbaikan visibilitas (log yang kurang selama investigasi). Panduan praktisi memakai tabel Apa, Kenapa, Kapan, dan Siapa, diurutkan menurut prioritas, dan menyarankan pemilik ditulis sebagai fungsi (tim atau jabatan), bukan hanya nama orang, supaya rekomendasi tetap bermakna bila orangnya berganti [S6]. Template PT JAB menulis keduanya: fungsi sebagai pemilik, nama sebagai kontak. Panduan yang sama menyarankan mencatat juga kontrol dan tindakan yang berhasil, supaya laporan tidak hanya berisi celah [S6]. Di `INC-2027-010`, contohnya laptop yang ditahan IT tanpa dinyalakan sejak dikembalikan; itu yang membuat jejak responder di image hampir nol.

Rekomendasi di kasus orang dalam berbeda bentuknya. Containment teknis biasanya sudah selesai (akun dinonaktifkan, laptop ditahan), dan yang tersisa adalah keputusan Legal dan HR tentang sumber tambahan, penilaian DPO, dan perbaikan kontrol (izin share per portofolio, audit media lepasan). Rekomendasi tidak pernah menyarankan sanksi; itu wewenang HR.

### 1.8 Defensibility: laporan yang bisa diikuti dan diulang orang lain

Pertanyaan keenam Dimas ("bisa dipertahankan bila dipersoalkan") adalah inti dari kata defensible. Laporan defensible berarti orang lain bisa mengikuti penalaranmu dan, idealnya, mendapatkan hasil yang sama dari bukti yang sama. Elemennya:

- **Chain of custody dan hash bukti** di lampiran (Day 01 bagian 1.5 dan 2.4).
- **Metodologi dengan versi alat.** Keluaran parser bisa berubah antar versi; tanpa versi, hasil tidak bisa diulang. SP 800-86 meminta log rinci setiap langkah termasuk informasi tentang alat yang dipakai, supaya analyst lain bisa mengulang proses, dan mencatat nama serta nomor versi alat akuisisi [S1].
- **Rujukan bukti per temuan.** Setiap klaim menunjuk artefak spesifik, bukan "berdasarkan analisis".
- **Objektivitas.** Sertakan bukti yang bertentangan dan hipotesis yang disingkirkan, bukan hanya yang mendukung kesimpulan.
- **Riwayat versi laporan.** Draft, revisi, final, dengan tanggal dan apa yang berubah. Bila temuan direvisi karena data baru, revisinya tercatat, bukan diam-diam ditimpa.

ISO/IEC 27042:2015 (pedoman analisis dan interpretasi bukti digital) menyebut empat sifat yang dituju analisis: continuity, validity, reproducibility, dan repeatability; ia juga meminta catatan yang cukup supaya proses analisis bisa diperiksa pihak independen bila diperlukan, dan meminta metode baru dibuktikan sesuai tujuan [S5]. Isi rinci standar itu berbayar dan tidak dibahas di sini; empat sifat di abstraknya cukup sebagai daftar periksa: apakah rantai bukti tidak terputus, apakah metode tepat untuk pertanyaannya, apakah orang lain dengan alat yang sama mendapat hasil yang sama, dan apakah kamu sendiri mendapat hasil yang sama bila mengulang.

Dua hal yang sering membuat laporan swasta tidak defensible walaupun analisisnya benar:

- **Lampiran berisi semua yang dikumpulkan.** Lampiran yang memuat seluruh ekspor alat tanpa kaitan ke temuan menyulitkan pembaca dan memperluas paparan data pribadi; lampiran hanya memuat yang menopang temuan [S8]. SANS menyebut kebiasaan mendaftar semua alat dan ekspor tanpa menjelaskan relevansinya sebagai link dumping, dan menyarankan bukti disusun menjadi cerita yang runtut, misalnya garis waktu [S7].
- **Laporan lengkap tidak disimpan.** Bila klien atau manajemen hanya meminta ringkasan, laporan lengkap tetap ditulis dan disimpan untuk dokumentasi internal, karena setiap kasus bisa berakhir di proses hukum; retensinya dibahas dengan Legal [S7].

### 1.9 Nada dan data pribadi, terutama di kasus orang dalam

Pertanyaan keempat Dimas (pertanyaan DPO) dan nada seluruh laporan `INC-2027-010` diatur oleh prinsip yang sama. Laporan objektif dan faktual. Fokus pada aksi yang tercatat, bukan pada orang. "Akun `arif.wicaksono` membuka berkas X dari volume lepasan" bisa dipertahankan; "Arif mencuri data" tidak, karena forensik endpoint tidak bisa membuktikan niat dan tidak bisa membuktikan siapa yang duduk di depan keyboard. Bila kata sandi akun bisa diketahui orang lain, sebutkan itu sebagai keterbatasan atribusi. Penilaian niat dan pelanggaran kebijakan diserahkan ke HR dan Legal. Praktisi merumuskan hal yang sama: investigator menyajikan fakta, tidak menyatakan siapa bersalah, dan menulis seolah laporan akan diuji di pengadilan [S8]. Panduan penulisan laporan IR menambahkan sisi organisasi: kritik ditujukan ke proses dan sistem, bukan orang, dan kasus orang dalam membutuhkan koordinasi dengan HR dan Legal [S6].

Di laporan, prinsip itu menjadi aturan penulisan yang bisa diperiksa:

- Kalimat temuan teknis memakai akun, sesi, dan perangkat ("sesi profil `arif.wicaksono`"), bukan nama orang.
- Nama orang muncul hanya di tempat yang perlu: latar kasus, keterangan yang diterima (dengan nama pemberi keterangan dan waktu), dan daftar distribusi.
- Kata "mencuri", "menyalahgunakan", "sengaja", "menutupi", "menghilangkan bukti", dan dugaan motif tidak dipakai. Daftar kalimat dilarang kasus ini ada di Day 17 bagian 2.9, mengikuti pola lembar batas bukti di Day 12 bagian 1.11: kalimat yang paling mungkin muncul di rapat ditulis eksplisit sebagai yang tidak boleh dipakai.
- Keterangan orang ditulis sebagai keterangan, terpisah dari temuan artefak.

Data pribadi juga dua arah di laporan, seperti di analisisnya (Day 17 bagian 1.2). Laporan memuat data pribadi subjek (jam kerja, jaringan, aplikasi), jadi lampiran hanya memuat baris yang relevan dan distribusinya dibatasi. SP 800-61r3 menyebut catatan respons insiden bisa memuat informasi sensitif tentang pengguna yang mungkin melakukan tindakan tidak semestinya, sehingga aksesnya dibatasi dan pengamanannya menjadi tanggung jawab pemimpin insiden [S2]. Di sisi lain, data pribadi pihak ketiga (PIC pelanggan korporat di daftar PIC) adalah pokok pertanyaan DPO.

Untuk pertanyaan DPO, jawaban jujurnya hampir selalu berbentuk tangga, bukan ya atau tidak. Panduan praktisi menyarankan laporan memisahkan data yang diakses dari data yang dieksfiltrasi, menyebut jenis data secara spesifik, dan menghitung cakupannya [S6]. Di `INC-2027-010`, itu berarti menulis anak tangga mana yang dicapai bukti untuk berkas daftar PIC: diakses (tinggi), disalin ke laptop (tinggi), berada di flashdisk pribadi (sedang), keluar dari kendali PT JAB dan diterima pihak lain (tidak dapat ditentukan). Kategori dan jumlah data pribadi dihitung bersama DPO dari berkas asli di share, bukan dibaca analyst dari salinan bukti, supaya minimisasi tetap terjaga. Penilaian apakah keadaan itu menimbulkan kewajiban notifikasi adalah wewenang DPO dan Legal, dan laporan menyatakannya eksplisit [S6].

### 1.10 Laporan interim, jawaban sementara, dan riwayat versi

Pertanyaan ketujuh Dimas menyangkut ringkasan Rabu yang sudah beredar. Insiden yang berjalan beberapa hari butuh update berkala, biasanya harian. Format interim yang berguna: apa yang diketahui sekarang dengan tingkat keyakinan, apa yang berubah sejak update terakhir, apa yang sedang dikerjakan, dan keputusan yang dibutuhkan. Tulis bahwa temuan interim bisa berubah. Setiap update yang dikirim adalah dokumen yang bisa dibaca kembali, jadi berlaku disiplin bahasa yang sama dengan laporan final.

SP 800-61r3 memberi isi minimal status yang dilacak per insiden: ringkasan insiden, IOC terkait, status dan perkiraan waktu setiap tindakan yang ditugaskan, dan langkah berikutnya [S2]. Interim forensik mengikuti isi itu dari sisi bukti.

Hubungan interim dengan final diatur oleh satu aturan ICD 203 yang berguna di sini: produk analisis menyatakan apakah penilaian utamanya konsisten dengan produk sebelumnya atau berubah, dan bila berubah, informasi atau penalaran baru apa yang menyebabkannya; produk berkala cukup menyebut perubahan [S4]. Untuk PT JAB, aturannya:

- Laporan final memuat tabel riwayat versi yang menyebut jawaban sementara dan interim sebelumnya, termasuk ringkasan Rabu 2027-01-13.
- Bila keyakinan sebuah temuan berubah, bagian "Perubahan sejak versi sebelumnya" menyebut temuan mana, dari tingkat apa ke tingkat apa, dan bukti apa yang menyebabkannya.
- Bila hanya kata yang berubah supaya sesuai skala (keyakinan tetap), itu juga ditulis, supaya pembaca yang membandingkan dua dokumen tidak mengira ada temuan baru.
- Bila data baru masuk setelah final (misalnya flashdisk diserahkan), terbit versi 1.1 dengan riwayat perubahan; versi 1.0 tidak ditimpa.

**Kapan gagal:** interim ditulis santai di chat ("kayaknya dia copy semua ke USB"), lalu chat itu dikutip di rapat. Disiplin bahasa berlaku sejak pesan pertama.

## 2. Contoh dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi yang disusun untuk dua kasus di atas; angka, jam, nomor bukti, dan keyakinan diambil dari Day 17 (`INC-2027-010`) dan Day 18 (`INC-2026-026`). Narasi dan laporan memakai WIB (UTC+7); kolom UTC ditulis bila sumber aslinya UTC (EZ Tools, Volatility, advanced hunting). Perintah PowerShell dijalankan di `JKT-DFIR01` dan perintah Linux di `jkt-dfir02`, keduanya atas folder kerja kasus di `\\jkt-evid01\cases\` (di `jkt-dfir02` di-mount sebagai `/mnt/cases`). Laporan disusun dalam Markdown, diekspor ke PDF untuk distribusi, dan disimpan di folder `report\` area kerja kasus. Nilai hash ditulis disingkat di contoh supaya hemat tempat; di laporan sungguhan, tulis hash lengkap.

Urutan kerja Senin sampai Rabu: template disusun Senin pagi, laporan `INC-2027-010` Senin siang sampai Selasa, laporan `INC-2026-026` Selasa sore, review sendiri dan pengiriman draf ke Sari dan Ratna Rabu 2027-01-20 pukul 14:00.

### 2.1 Template `JAB-DFIR-TPL-01`

Template ini menjawab pertanyaan pertama Dimas. Ia disimpan sebagai `\\jkt-evid01\cases\_template\JAB-DFIR-TPL-01_v1.0.md`, dan setiap laporan dimulai dari salinan template itu, bukan dari laporan kasus sebelumnya, supaya isi kasus lama tidak terbawa.

```
# Laporan Forensik: <judul netral, tanpa nama orang>
No. dokumen  : <INC-NNNN-NNN>-LAP-<nn>        Template: JAB-DFIR-TPL-01 v1.0
Versi        : 0.x (draf) | 1.0 (final) | 1.x (revisi)      Tanggal: <YYYY-MM-DD>
Klasifikasi  : <ditetapkan Legal untuk kasus berpotensi litigasi>
Distribusi   : <daftar nama dan jabatan; tidak diteruskan tanpa izin IC dan Legal>
Penyusun     : <nama, peran>         Peninjau teknis: <nama>     Peninjau bahasa/Legal: <nama>
Zona waktu   : WIB (UTC+7) kecuali disebut lain

## 0. Inti dan keputusan yang dibutuhkan            (3-5 kalimat; dibaca lebih dulu)
## 1. Ringkasan eksekutif                           (maks. 1 halaman; ditulis terakhir)
   Apa yang terjadi | Dampak | Status | Temuan dan keyakinan | Batas | Keputusan
## 2. Latar, permintaan, dan lingkup
   2.1 Latar dan pemicu   2.2 Pertanyaan investigasi (bernomor)
   2.3 Lingkup izin (dokumen, tanggal)   2.4 Di luar lingkup (dan alasannya)
## 3. Bukti dan metodologi
   3.1 Daftar bukti (ID, deskripsi, cara dan waktu pengambilan, SHA-256)  -> rinci di Lampiran A
   3.2 Analisis: salinan kerja, alat dan versi                           -> rinci di Lampiran B
   3.3 Zona waktu dan koreksi jam   3.4 Skala keyakinan (tabel baku)
   3.5 Asumsi dan dampaknya bila salah   3.6 Jejak responder dan cara memisahkannya
## 4. Temuan                                         (satu per pertanyaan)
   ### Temuan n: <judul>
   Pertanyaan | Bukti (FAKTA, rujukan Lampiran C.n) | Analisis (TAFSIRAN)
   Keyakinan (per bagian bila perlu) | Keterbatasan | Hipotesis alternatif
   Pendapat analis (opsional, DITANDAI) | Teknik ATT&CK dan IOC (kasus malware)
## 5. Hipotesis alternatif: tabel hasil pengujian
## 6. Garis waktu kurasi (WIB | UTC | kejadian | pelaku | sumber | keyakinan)
   + Tidak ditemukan (dengan cakupan) | Tidak bisa dijawab | Bisa dijawab dengan sumber tambahan
## 7. Data pribadi dan dampak                       (untuk DPO; "tidak relevan" bila tidak ada)
## 8. Indicators of Compromise                       (defang; "tidak relevan" bila tidak ada)
## 9. Yang belum diketahui dan cara menjawabnya      (sumber, siapa yang memutuskan)
## 10. Rekomendasi: kelompok | apa | kenapa | pemilik (fungsi, kontak) | tenggat | status
## 11. Yang berjalan baik dan celah visibilitas
## Lampiran
   A. Chain of custody dan hash bukti
   B. Alat dan versi (dibekukan per kasus)
   C. Keluaran pendukung per temuan (hanya yang relevan)
   D. Riwayat versi dan catatan review
   E. Glosarium
```

Cara membaca elemennya:

- **Judul netral.** "Laporan Forensik: Aktivitas Berkas dan Media Lepasan pada Laptop JKT-WS-0516", bukan "Investigasi Pencurian Data oleh Arif". Judul adalah kalimat yang paling sering dikutip.
- **Bagian 0 dan 1 terpisah.** Bagian 0 untuk pembaca yang hanya membaca setengah menit; bagian 1 untuk yang membaca satu halaman. Keduanya ditulis terakhir.
- **Bagian 3.5 dan 3.6.** Asumsi (bagian 1.5) dan jejak responder ditulis di metodologi, bukan disisipkan di temuan, supaya Legal bisa membaca seluruh dasar laporan di satu tempat.
- **Bagian 7, 8, 9 selalu ada.** Bila kosong, tulis "tidak relevan untuk kasus ini" beserta alasannya.
- **Kolom status di rekomendasi.** Untuk laporan yang ditulis setelah tindakan berjalan (seperti `INC-2026-026`), status diambil dari tiket IC, bukan dari ingatan.

**Variasi:** untuk insiden kecil, pakai versi memo dua halaman: bagian 0, 1, 4 (temuan ringkas dengan keyakinan), 9, 10, dan lampiran A. Skala keyakinan tetap sama, supaya memo dan laporan bisa dibandingkan.

**Kapan gagal:** template diisi dengan menyalin laporan kasus lain lalu mengganti nama, sehingga kalimat, nomor bukti, atau nama dari kasus lama tertinggal. Mulai selalu dari template kosong.

### 2.2 Executive summary `INC-2027-010`

Halaman ini menjawab pertanyaan kedua Dimas untuk kasus Arif dan adalah satu-satunya halaman yang dibaca Hendra Wijaya. Semua angka, jam, dan keyakinannya sama dengan temuan Day 17; yang berubah dari ringkasan Rabu hanyalah susunan dan bahasa keyakinan (bagian 2.10).

```
INC-2027-010-LAP-01 | Laporan Forensik: Aktivitas Berkas dan Media Lepasan pada Laptop JKT-WS-0516
Versi 0.9 (draf) | Rabu 2027-01-20 | Distribusi terbatas: Direktur Teknologi, Legal, HR, DPO, IC
Semua waktu WIB (UTC+7)

0. INTI DAN KEPUTUSAN
Pada 4 sampai 7 Januari 2027, akun arif.wicaksono mengakses berkas harga kontrak milik portofolio
account manager lain, menyalin 19 berkas (termasuk daftar PIC pelanggan korporat) dari file server ke
laptop kantor, dan dua di antaranya tercatat berada di flashdisk pribadi yang tidak terdaftar sebagai
media kerja. Isi flashdisk dan keberadaan data di luar PT JAB tidak dapat ditentukan dari bukti yang
ada. Laporan ini menjelaskan aktivitas akun dan perangkat, bukan niat atau kesalahan seseorang.
Keputusan yang dibutuhkan: (1) Legal: permintaan message trace dan audit Microsoft 365 untuk akun ini
4-8 Januari; (2) Legal dan HR: langkah memperoleh flashdisk secara sah; (3) DPO: penilaian atas daftar
PIC (bagian 7).

1. RINGKASAN EKSEKUTIF
Latar. Senin 11 Januari, satu pelanggan korporat melaporkan ditawari ISP pesaing dengan harga yang sama
dengan harga kontrak PT JAB. Atas izin tertulis Legal (memo 11 Januari 14:30), tim forensik memeriksa
laptop kantor JKT-WS-0516 milik account manager yang hari kerja terakhirnya Jumat 8 Januari, log akses
file server, log proxy, dan data Defender. Akun dan perangkat pribadi tidak termasuk pemeriksaan.

Temuan dan keyakinan
1. Senin 4 Januari 16:42-17:06, akun tersebut membuka folder harga kontrak dan menyentuh 14 berkas
   milik portofolio account manager lain; enam dibuka di Excel. Selama 91 hari sebelumnya akun ini
   tidak pernah mengakses berkas portofolio lain.                                   Keyakinan: Tinggi
2. Rabu 6 Januari 15:12, 19 berkas (11 harga portofolio sendiri, 7 harga portofolio lain, daftar PIC)
   disalin dari file server ke folder di laptop; isinya identik dengan berkas asli. Keyakinan: Tinggi
3. Satu flashdisk pribadi Kingston (serial 0019E06B4A21C5F0A7) tersambung dua kali di sesi akun
   tersebut: Senin 4 Januari 16:58-17:01 dan Kamis 7 Januari 19:26-19:52, saat laptop tidak
   tersambung ke jaringan mana pun.                                                  Keyakinan: Tinggi
4. Dua berkas (harga kontrak PT Samudra Logistik Contoh dan daftar PIC) tercatat dibuat di flashdisk
   Kamis 19:31 dan dibuka dari sana 19:33 dan 19:36.                                Keyakinan: Sedang
   Ada indikasi seluruh 19 berkas ikut disalin, tetapi 17 berkas lainnya tidak meninggalkan catatan
   di laptop dan tidak dapat dipastikan.                                             Keyakinan: Rendah
   Isi flashdisk saat ini dan ke mana flashdisk dibawa: tidak dapat ditentukan dari data yang tersedia.
5. Folder salinan di laptop dipindah ke Recycle Bin Kamis 19:55 dan isinya masih utuh; tidak ditemukan
   pembersihan log atau alat penghapus.                                              Keyakinan: Tinggi
6. Dari laptop dan proxy kantor tidak terlihat unggahan ke layanan penyimpanan online 4-8 Januari; ada
   tiga sesi webmail pribadi Rabu sore yang isinya tidak terlihat.        Keyakinan: Rendah sampai sedang
   (proxy hanya melihat trafik dari kantor; jaringan rumah dan ponsel di luar pemeriksaan)

Penjelasan lain yang diuji. Pekerjaan serah terima yang sah menjelaskan 11 berkas portofolio sendiri;
tidak menjelaskan 7 berkas portofolio lain, daftar PIC lengkap, dan flashdisk, menurut keterangan
atasan dan penerima serah terima. Flashdisk tidak terdaftar sebagai media kerja (keterangan IT).
Kemungkinan orang lain memakai sesi akun tidak dapat disingkirkan oleh artefak.

Batas. Artefak menunjukkan akun, sesi, dan perangkat, bukan orang yang mengoperasikannya, dan tidak
menunjukkan tujuan atau niat. Laporan ini tidak menyatakan bahwa data diberikan kepada pihak mana pun.

Status. Laptop ditahan dan diamankan sebagai bukti; image dan salinan kerja tersimpan di server bukti.
Akses akun berakhir bersama hari kerja terakhir (dikonfirmasi IT).
```

Cara membaca elemennya:

- **Bagian 0 bisa dibaca sendiri.** Lima kalimat: apa yang terjadi, apa yang tidak dapat ditentukan, kalimat batas niat, dan tiga keputusan yang disebut dengan pemiliknya.
- **Keyakinan per butir di kolom kanan.** Butir 4 punya tiga tingkat dalam satu butir karena memang tiga pernyataan berbeda (bagian 1.4). Frasa di kalimatnya mengikuti skala: "tercatat" untuk fakta, "ada indikasi ... tidak dapat dipastikan" untuk rendah, "tidak dapat ditentukan" untuk yang datanya tidak ada.
- **Nama pelanggan disebut sekali,** karena berkas itulah yang menghubungkan laporan pelanggan dengan temuan. Nama Arif tidak dipakai di kalimat temuan; "akun tersebut" dan "sesi akun tersebut" dipakai konsisten.
- **"Akses akun berakhir bersama hari kerja terakhir (dikonfirmasi IT)"** adalah keterangan, ditulis dengan sumbernya. Bila IT belum mengonfirmasi saat laporan disusun, kalimat itu ditulis sebagai yang perlu dicek, bukan ditebak.

**Kapan gagal:** butir 4 diringkas menjadi "19 berkas disalin ke flashdisk" karena halaman terasa terlalu penuh. Itu kalimat dilarang di Day 17 bagian 2.9; memendekkan halaman tidak boleh menaikkan keyakinan.

### 2.3 Bagian data pribadi untuk DPO (`INC-2027-010`)

Bagian ini menjawab pertanyaan keempat Dimas, yaitu pertanyaan Agus Setiawan. Jumlah baris dan kategori data dihitung Agus bersama Surya Atmaja (Kepala Divisi Enterprise Sales, pemilik data) dari berkas asli di share Jumat 2027-01-15, bukan dibaca analyst dari salinan bukti (bagian 1.9).

```
7. DATA PRIBADI DAN DAMPAK

7.1 Data pribadi yang terlibat
Berkas  : \\JKT-FS01\Enterprise-Sales\Kontak-PIC\Daftar-PIC-Korporat-2026.xlsx (1.187.840 byte)
Isi     : 287 baris PIC untuk 64 pelanggan korporat; kolom nama, jabatan, nomor ponsel, email kantor
          (dihitung DPO dan pemilik data dari berkas asli, Jumat 2027-01-15)
Berkas lain: 18 berkas harga kontrak (HK-2026-*.xlsx). Apakah memuat data pribadi dinilai DPO
          bersama pemilik data; tim forensik tidak membuka isinya.

7.2 Sampai mana bukti membawa (daftar PIC)
Anak tangga                               Keyakinan                Dasar
Diakses dari akun ini                     Tinggi                   5145 JKT-FS01 Rabu 15:12:39; baseline 5 event
Disalin ke laptop kantor                  Tinggi                   $J, Defender, 5145; hash identik dengan asli
Berada di flashdisk pribadi               Sedang                   LNK + Jump List + rantai USB; dibuat 19:31:14,
                                                                   dibuka 19:36:03; isi tidak dapat dibandingkan
Keluar dari kendali PT JAB                Tidak dapat ditentukan   flashdisk tidak tersedia; laptop dikembalikan
Diterima atau dipakai pihak lain          Tidak dapat ditentukan   tidak ada sumber di lingkup pemeriksaan

7.3 Jalur lain yang diperiksa
Webmail pribadi Rabu 15:20-15:41 dari kantor: total kirim 182.336 byte, isi tidak terlihat. Volume itu
lebih kecil dari ukuran daftar PIC (1.187.840 byte), tetapi juga cocok dengan aktivitas email biasa;
tidak membuktikan apa pun ke arah mana pun. Unggahan ke layanan penyimpanan online dari kantor: tidak
terlihat (proxy 4-8 Januari, riwayat Edge). Jaringan rumah, ponsel, dan akun pribadi: di luar pemeriksaan.

7.4 Batas
Laporan forensik menyediakan fakta dan batasnya. Penilaian apakah keadaan ini menimbulkan kewajiban
pemberitahuan menurut peraturan pelindungan data pribadi berada di DPO dan Legal, bukan di laporan ini.
```

Cara membaca elemennya:

- **Jawaban atas "keluar atau tidak" ada di dua baris terbawah tabel 7.2:** tidak dapat ditentukan. Itu jawaban jujur, dan baris di atasnya menunjukkan seberapa dekat bukti sampai ke sana.
- **Angka 182.336 dan 1.187.840 diletakkan berdampingan** tanpa ditarik kesimpulan. Membandingkannya membantu DPO memahami kenapa sesi webmail tidak diabaikan dan tidak juga dijadikan bukti.
- **Kalimat 7.4** menempatkan keputusan pada pemiliknya. Panduan praktisi menyarankan sikap notifikasi diserahkan ke legal atau kepatuhan [S6].

**Variasi:** bila Legal kelak memperoleh flashdisk dan image-nya memuat berkas daftar PIC dengan hash yang sama dengan asli, baris "Berada di flashdisk pribadi" naik ke tinggi lewat revisi 1.1, dan baris "Keluar dari kendali" tetap dinilai dari keterangan tentang flashdisk, bukan dari hash.

**Kapan gagal:** analyst membuka salinan daftar PIC dari `$R` di salinan kerja untuk menghitung baris. Hasilnya benar, tetapi ia membaca data pribadi pihak ketiga di luar kebutuhan pertanyaan forensik, padahal berkas aslinya ada di share dan bisa dihitung pemilik data.

### 2.4 Executive summary `INC-2026-026`

Halaman ini adalah bagian pertama uji template yang diminta Dimas: memo kerja Selasa 2026-12-08 ditulis ulang menjadi halaman pertama laporan forensik host. Isi temuannya sama dengan memo (Day 18); yang ditambahkan adalah bahasa dampak, keyakinan per temuan, batas, dan keputusan.

```
INC-2026-026-LAP-01 | Laporan Forensik Host: Infeksi Installer Aplikasi PDF Palsu pada Laptop BDG-WS-0163
Versi 0.9 (draf) | Rabu 2027-01-20 (penulisan ulang memo 2026-12-08 15:30) | Semua waktu WIB (UTC+7)

0. INTI DAN KEPUTUSAN
Jumat 4 Desember 2026, laptop staf Sales Bandung BDG-WS-0163 terinfeksi setelah pengguna menjalankan
installer aplikasi PDF palsu yang diunduh dari iklan hasil pencarian. Program jahat berjalan tiga hari
tanpa alert, berkomunikasi dengan server di internet sekitar tiap lima menit, bertahan setelah restart,
dan Senin 7 Desember dipakai operator untuk memetakan akun administrator domain. Tidak ditemukan tanda
pencurian kata sandi atau perpindahan ke komputer lain sebelum laptop diisolasi Senin 12:30.
Keputusan yang dibutuhkan: menetapkan aturan deteksi berbasis perilaku yang mengecualikan aplikasi
internal JAB DocSync sebagai deteksi tetap (pemilik: tim deteksi SOC), dan menutup celah audit pada
laptop kantor Bandung (pemilik: tim endpoint).

1. RINGKASAN EKSEKUTIF
Apa yang terjadi. Installer palsu menaruh program updater bertanda tangan sebuah vendor dan satu
komponen DLL tanpa tanda tangan di folder profil pengguna. Program updater memuat komponen itu,
menjalankan kode tahap kedua di memorinya sendiri, membuat jadwal tugas agar berjalan setiap pengguna
login, dan menghubungi server penyerang. Senin pagi, operator mengetik perintah pengintaian domain lewat
program itu selama sekitar tiga menit (08:10-08:12).

Temuan dan keyakinan
1. Titik masuk: installer dijalankan Jumat 15:04:50; program jahat pertama berjalan 15:05:10.
                                                                                    Keyakinan: Tinggi
2. Tidak ada kode yang disuntikkan ke proses lain; ada tahap kedua yang hidup di memori program
   updater.                                     Keyakinan: Tinggi (memuat DLL palsu), Sedang (tahap kedua)
3. Bertahan lewat satu jadwal tugas saat logon, dibuat Jumat 15:05:12.               Keyakinan: Tinggi
4. Komunikasi ke cdn.pdfsuite-update[.]example[.]net (198.51.100[.]37) sejak Jumat 15:06, 73 koneksi
   sampai Senin 11:34; masih aktif saat memori diambil Senin 11:22.                 Keyakinan: Tinggi
5. Pengintaian domain Senin 08:10-08:12; tidak ditemukan pencurian kredensial atau perpindahan ke host
   lain dari host ini.                                                              Keyakinan: Sedang
   (pemakaian kredensial pengguna dari tempat lain hanya bisa dijawab log DC dan EDR)
6. Indikator yang bisa dipakai untuk mencari di seluruh perangkat tanpa menandai 214 perangkat yang
   memakai komponen bernama sama secara sah: diserahkan ke tim hunting dan deteksi (bagian 8, 10).

Dampak dan cakupan. Minimal tiga laptop tersentuh kampanye ini, satu dengan aktivitas operator
(BDG-WS-0163). Isi komunikasi dengan server penyerang terenkripsi; apakah ada data yang diambil dari
laptop ini bukan pertanyaan pemeriksaan Desember dan tidak dapat ditentukan dari bukti host.

Status. Host diisolasi Senin 7 Desember 12:30; bukti memori, paket investigasi, dan image disk
diamankan sebelum host dipulihkan. Status pelaksanaan rekomendasi per 18 Januari di bagian 10.
```

Cara membaca elemennya:

- **Bandingkan dengan executive summary `INC-2027-010`.** Kasus malware menekankan keputusan cepat dan cakupan; kasus orang dalam menekankan batas kesimpulan dan pemisahan antara aksi dan niat. Keduanya memakai skala yang sama.
- **Nilai IOC di halaman pertama sudah di-defang** (bagian 1.7), karena halaman ini paling mungkin diteruskan lewat email.
- **"Bukan pertanyaan pemeriksaan Desember"** adalah kalimat yang menutup celah yang paling mungkin ditanyakan Hendra ("ada data yang diambil?") tanpa menebak jawabannya.
- **Keputusan di bagian 0** adalah dua hal yang masih terbuka di Januari. Tindakan containment Desember tidak diminta ulang, tetapi statusnya dilaporkan di rekomendasi.

**Kapan gagal:** memo Desember disalin ke template tanpa diubah, sehingga halaman pertama berisi `dlllist`, `malfind`, dan PID. Memo ditulis untuk Rudi; halaman pertama laporan ditulis untuk orang yang tidak pernah membuka Volatility.

### 2.5 Finding lengkap `INC-2027-010`: penyalinan ke flashdisk

Temuan ini adalah contoh pertanyaan ketiga Dimas dalam bentuk paling sulit: satu temuan dengan tiga tingkat keyakinan, fakta yang kuat, dan kesimpulan yang tidak boleh melampauinya. Isinya dari Day 17 bagian 2.6.

```
### Temuan 4: Salinan berkas di laptop dan di flashdisk

Pertanyaan
Apakah ada bukti berkas harga kontrak dan daftar PIC disalin ke perangkat lepasan? (pertanyaan 4)

Bukti (fakta; waktu WIB, sumber UTC di Lampiran C.4)
- $J volume C: (MFTECmd 2026.5.0): folder C:\Users\arif.wicaksono\Documents\Kontrak-Ref dibuat
  Rabu 2027-01-06 15:12:05; 19 berkas FileCreate 15:12:31-15:12:40.                      (C.4.1)
- Defender DeviceFileEvents: 19 baris FileCreated di Kontrak-Ref, 15:12:31-15:12:40,
  proses explorer.exe.                                                                     (C.4.2)
- 5145 JKT-FS01: pembacaan berkas yang sama pada detik yang sama.                          (C.1.3)
- Recycle Bin: $IQ7M2KD / $RQ7M2KD, folder Kontrak-Ref, DeletedOn Kamis 19:55:40, 2.209.792 byte;
  SHA-256 ke-19 berkas di $RQ7M2KD sama dengan 19 berkas asli di share (19 dari 19).        (C.4.3)
- LNK HK-2026-SMLC (2).xlsx.lnk dan Daftar-PIC-Korporat-2026 (2).xlsx.lnk: LocalPath
  E:\JAB\Kontrak-Ref\, DriveType removable, VSN 5A1C0E37, label KINGSTON, TargetCreated
  19:31:12 dan 19:31:14, ukuran 68.096 dan 1.187.840 byte.                                (C.2.2)
- Jump List Excel: kedua path di E: (MRU 0 dan 1, 19:36:03 dan 19:33:48).                  (C.2.3)
- 4688 dan Sysmon 1, 19:33:46: EXCEL.EXE PID 7344 dengan path E:\JAB\Kontrak-Ref\HK-2026-SMLC.xlsx.
                                                                                           (C.2.4)
- ShellBags: Documents\Kontrak-Ref 19:29:58, E:\JAB 19:31:05, E:\JAB\Kontrak-Ref 19:33:40.   (C.2.1)
- Rantai VSN 5A1C-0E37 ke flashdisk serial 0019E06B4A21C5F0A7: Temuan 3.

Analisis (tafsiran)
Salinan lokal lahir dari share Rabu sore lewat Explorer: tiga sumber independen ($J, Defender,
5145) sepakat pada detik yang sama, dan isi salinan identik dengan asli. Dua berkas bernama dan
berukuran sama dengan berkas di folder lokal berada di volume flashdisk tersebut, tercatat dibuat
di sana empat menit setelah flashdisk dicolok saat folder lokal masih ada, lalu dibuka dari sana
di sesi profil arif.wicaksono. Nama folder tujuan sama dengan folder lokal. Penyalinan dari C: ke
E: tidak menulis apa pun ke C:, sehingga USN laptop tidak bisa membuktikan penyalinan ke flashdisk.

Keyakinan
- Salinan 19 berkas di laptop, isi identik dengan asli: Tinggi.
- Dua berkas (SMLC, daftar PIC) berada di flashdisk dan dibuka dari sana: Sedang
  (rantai lengkap tetapi tidak langsung; isi tidak dapat dibandingkan tanpa flashdisk).
- 17 berkas lain di flashdisk: Rendah (tidak ada artefak di laptop yang menunjuk berkas itu di E:).
- Isi flashdisk saat ini: Tidak dapat ditentukan.

Keterbatasan
Flashdisk tidak tersedia. Laptop tidak tersambung jaringan sejak Kamis 17:38:47, sehingga Defender
tidak punya data sesi malam itu; ketiadaan baris Defender untuk E: bukan hasil negatif. Audit
Removable Storage tidak aktif di GPO JAB-WS-Audit; konfigurasi Sysmon tidak mencatat dokumen Office
di media lepasan.

Asumsi (lihat metodologi 3.5)
TargetCreated di volume FAT adalah waktu berkas dibuat di volume itu, yang pada penyalinan lewat
Explorer sama dengan waktu penyalinan. Bila asumsi ini salah, waktu "sekitar 19:31" turun keyakinannya;
fakta bahwa dua berkas dibuka dari flashdisk 19:33 dan 19:36 tidak berubah.

Hipotesis alternatif
H2 (serah terima) menjelaskan 11 berkas portofolio sendiri, tidak menjelaskan 7 berkas portofolio
lain, daftar PIC, dan flashdisk. H3 (media kerja resmi) tidak didukung: serial tidak terdaftar.
H4 (orang lain memakai sesi) tidak dapat disingkirkan; kunci layar dibuka dengan kredensial akun ini
(4624 type 7, 19:24:15) di laptop yang tidak tersambung jaringan.

Pendapat analis (ditandai)
Urutan ShellBags dan nama folder yang sama konsisten dengan penyalinan seluruh folder Kontrak-Ref ke
E:\JAB\ sekitar 19:31 dalam satu tindakan. Pendapat ini tidak menaikkan keyakinan untuk 17 berkas lain.
```

Cara membaca elemennya:

- **Setiap butir Bukti punya rujukan lampiran.** Pembaca Legal yang meragukan satu butir bisa membuka C.4.3 dan melihat 19 baris hash, tanpa bertanya ke penulis.
- **Analisis tidak mengulang angka,** tetapi menjelaskan kenapa sumber-sumber itu sepakat dan apa yang tidak bisa dicatat sumber mana pun.
- **Asumsi ditulis dengan akibatnya** (bagian 1.5). Ini yang membedakan asumsi dari keterbatasan: keterbatasan adalah data yang tidak ada; asumsi adalah dasar tafsir yang bisa salah.
- **Pendapat analis dipisah dan diberi batas.** Ia membantu pembaca memahami pola, tetapi kalimat terakhirnya mencegah pendapat dipakai sebagai bukti untuk 17 berkas lain.

**Kapan gagal:** keterbatasan "laptop tidak tersambung" ditulis tanpa jam. Pembaca akan bertanya "sejak kapan", dan jawabannya (17:38:47) justru yang menjelaskan kenapa sesi 19:26 tidak ada di Defender.

### 2.6 Finding lengkap `INC-2026-026`: persistence

Temuan ini adalah contoh kasus malware dengan baris tambahan Teknik ATT&CK dan IOC (Day 18 bagian 1.2). Isinya dari Day 18 bagian 2.4, ditulis ulang ke format template.

```
### Temuan 3: Persistence lewat scheduled task \PDFSuite Updater

Pertanyaan
Bagaimana kode bertahan setelah restart? (pertanyaan 3)

Bukti (fakta)
- File XML C:\Windows\System32\Tasks\PDFSuite Updater (E06-W1): RegistrationInfo Date
  2026-12-04T15:05:12 (lokal, WIB); Author JAB\bima.ardiansyah; Action pdfupdater.exe di
  C:\Users\bima.ardiansyah\AppData\Local\PDFSuite\; LogonTrigger; Principal InteractiveToken.  (C.3.1)
- TaskCache (RECmd DFIRBatch, E06-W1): Tree\PDFSuite Updater last write 2026-12-04 08:05:12 UTC
  (15:05:12 WIB), nilai SD ada; Tasks\{b7e2c940-...} last write 2026-12-07 00:58:06 UTC.        (C.3.2)
- $MFT: waktu FN file task 15:05:12 WIB.                                                      (C.3.3)
- Paket investigasi E04 (Senin 11:12): CSV scheduled tasks memuat \PDFSuite Updater dengan action
  yang sama.                                                                                  (C.3.4)
- Memori E05: pdfupdater.exe PID 5216 berinduk svchost.exe PID 1344 (layanan Schedule),
  CreateTime Senin 00:58:04 UTC (07:58:04 WIB).                                               (C.2.1)

Analisis (tafsiran)
Empat sumber disk dan EDR sepakat pada waktu pendaftaran Jumat 15:05:12, dua detik setelah
pdfupdater.exe pertama berjalan. Task dibuat di root, berjalan di konteks pengguna tanpa hak admin,
dan tidak disembunyikan (nilai SD ada). Proses pdfupdater.exe yang masih hidup Senin berinduk layanan
Task Scheduler, bukti bahwa persistence bekerja setelah logon Senin. Last write Tasks\{GUID} Senin
00:58:06 UTC adalah data runtime yang diperbarui Windows, bukan waktu pembuatan.

Teknik ATT&CK: T1053.005 Scheduled Task (task XML, TaskCache, induk svchost Schedule).
IOC: scheduled task \PDFSuite Updater saat logon dengan action di AppData\Local (artefak host,
daya tahan sedang: nama bisa diganti).

Keyakinan: Tinggi.

Keterbatasan
Laptop Bandung tidak menerima GPO audit Jakarta: tanpa 4698, tanpa 4688, channel
TaskScheduler/Operational mati. Proses pembuat task tidak bisa ditautkan dari disk; menurut process
timeline EDR, task dibuat oleh schtasks.exe yang dipanggil pdfupdater.exe (waktu: lihat catatan
review D.2). Mekanisme lain yang diperiksa dan tidak ditemukan: Run key, service, Startup folder,
WMI subscription (registry dan OBJECTS.DATA).

Hipotesis alternatif
Task dipasang aplikasi sah (H2): disingkirkan; pemuat bukan JAB DocSync, DLL tanpa tanda tangan,
dan task menunjuk folder profil pengguna. Uji red team (H3): disingkirkan; tidak ada jadwal uji
dan C2 menuju infrastruktur eksternal yang tidak dikenal.
```

Cara membaca elemennya:

- **Baris Teknik ATT&CK dan IOC** ada karena pembaca kedua laporan ini adalah tim deteksi dan hunting. Di kasus orang dalam, dua baris itu dihapus dari temuan.
- **"Mekanisme lain yang diperiksa dan tidak ditemukan"** adalah hasil negatif dengan cakupan, bukan "tidak ada persistence lain".
- **"Waktu: lihat catatan review D.2"** menunjuk temuan review di bagian 2.10: memo Desember menulis waktu pemanggilan `schtasks.exe` yang lebih lambat dari waktu pendaftaran task, dan selisih itu sedang dicek ulang di timeline EDR sebelum laporan final.

**Kapan gagal:** last write `Tasks\{GUID}` ditulis sebagai waktu pembuatan task karena itu waktu paling "baru" di registry. Pembaca teknis lain akan menemukan bahwa angka itu Senin, sedangkan XML dan TaskCache Tree menunjuk Jumat, dan seluruh temuan dipertanyakan.

### 2.7 Garis waktu dan IOC versi laporan (`INC-2026-026`)

Bagian ini menjawab pertanyaan kelima Dimas untuk kasus malware. Garis waktu di memo Desember (Day 18 bagian 2.9) dipindah ke format laporan dengan kolom pelaku dan keyakinan, dan baris yang disimpulkan ditandai. Tabel ini memuat baris yang menopang temuan; baca kolom "Pelaku", karena di situlah aktivitas penyerang dipisah dari aktivitas tim PT JAB.

| WIB | UTC | Kejadian | Pelaku | Sumber | Keyakinan |
|---|---|---|---|---|---|
| Jum 2026-12-04 15:02:31 | 08:02:31 | Unduh `PDFSuite_Setup_4.2.zip` dari `pdf-suite-download[.]example[.]net` | sesi `bima.ardiansyah` | log proxy, `DeviceFileEvents` | Tinggi |
| Jum 15:04:50 | 08:04:50 | `PDFSuite_Setup_4.2.exe` dijalankan | sesi `bima.ardiansyah` | Prefetch, PCA | Tinggi |
| Jum 15:05:10 | 08:05:10 | `pdfupdater.exe` berjalan, memuat `version.dll` dari `AppData` | penyerang (kode) | Prefetch, Amcache, dlllist | Tinggi |
| Jum 15:05:12 | 08:05:12 | Task `\PDFSuite Updater` didaftarkan | penyerang (kode) | XML, TaskCache, `$MFT` FN | Tinggi |
| Jum 15:06:02 | 08:06:02 | Beacon pertama ke `198.51.100[.]37:443` | penyerang (kode) | netscan, SRUM, log firewall | Tinggi |
| Jum 15:06 sampai 17:26 | 08:06 sampai 10:26 | 29 koneksi C2 (laptop menyala) | penyerang (kode) | netscan, log firewall | Tinggi |
| Sen 2026-12-07 07:58:04 | 00:58:04 | Logon; task menjalankan `pdfupdater.exe` lagi | sistem (task) | Prefetch, pstree, dlllist | Tinggi |
| Sen 07:59:40 | 00:59:40 | Beacon Senin dimulai | penyerang (kode) | netscan, log firewall | Tinggi |
| Sen 08:10:05 | 01:10:05 | `pdfupdater.exe` membuka `cmd.exe` | operator lewat C2 | BAM, EDR timeline | Tinggi |
| Sen 08:10 sampai 08:12 | 01:10 sampai 01:12 | Discovery domain (`whoami`, `nltest`, `net group`, `net view`, `ipconfig`) | operator lewat C2 | Prefetch, BAM, EDR timeline (argumen) | Tinggi |
| Sen 07:59 sampai 11:34 | 00:59 sampai 04:34 | 44 koneksi C2 | penyerang (kode) | netscan, log firewall | Tinggi |
| Sen 11:12 sampai 11:18 | 04:12 sampai 04:18 | Paket investigasi E04 diambil | responder (Yoga) | case notes, Action center | Tinggi |
| Sen 11:22 sampai 11:32 | 04:22 sampai 04:32 | Memori E05 diambil (koneksi C2 `ESTABLISHED` masih terlihat) | responder (Yoga) | case notes, netscan | Tinggi |
| Sen 12:30 | 05:30 | Host diisolasi lewat EDR | responder | Action center | Tinggi |
| Sen 16:10 sampai 17:40 | 09:10 sampai 10:40 | Image disk E06 diambil | responder (Fajar) | CoC | Tinggi |

Di bawah garis waktu, tiga daftar dari bagian 1.6:

- **Tidak ditemukan (dengan cakupan):** injeksi ke proses lain dan hollowing (memori E05, satu titik waktu); handle ke `lsass.exe` dari `pdfupdater.exe`; MRU RDP keluar baru, `PsExec`, atau `wmic` di Prefetch; 4648 ke host lain; persistence selain task (Run key, service, Startup, WMI).
- **Tidak bisa dijawab dari host ini:** isi komunikasi C2; isi tahap kedua dan `update.dat` (diserahkan ke tim sampel); pemakaian kredensial `bima.ardiansyah` dari tempat lain; koneksi C2 antara 11:34 dan isolasi 12:30 di luar yang tertangkap memori.
- **Bisa dijawab dengan sumber lain:** log DC dan EDR untuk logon akun di host lain; hunting lintas fleet dan log proxy serta DNS untuk host tanpa sensor; analisis tim sampel.

Bagian IOC laporan mengambil tabel Day 18 bagian 2.8 dengan dua perubahan: nilai jaringan di-defang, dan known-good ditulis di baris terpisah supaya tidak tertukar dengan IOC.

```
8. INDICATORS OF COMPROMISE (nilai mentah: Lampiran C.8, iocs-INC-2026-026.csv)
Jenis       Nilai                                         Sumber             Daya tahan
SHA-1       3f9c2b7e... (version.dll, tanpa tanda tangan) Amcache E06        Rendah
SHA-1       d0a71e5c... (pdfupdater.exe)                  Amcache E06        Rendah
IP          198.51.100[.]37                               netscan E05, E04   Rendah
Domain      cdn.pdfsuite-update[.]example[.]net           DnsCache E04       Sedang (kampanye sudah
                                                                             berganti domain, SOC-2026-0272)
Domain      pdf-suite-download[.]example[.]net            log proxy          Sedang
Host        task \PDFSuite Updater saat logon             XML, TaskCache     Sedang
Host        folder AppData\Local\PDFSuite\                $MFT, Amcache      Sedang
Perilaku    version.dll tanpa tanda tangan atau signer bukan PT JAB, dimuat dari folder yang bisa
            ditulis pengguna oleh executable selain jabdocsync.exe di C:\Program Files\JAB\DocSync\,
            lalu koneksi keluar berkala                    dlllist, netscan   Tinggi

KNOWN-GOOD (bukan IOC; dipakai untuk pengecualian)
version.dll JAB DocSync, signer PT Jaringan Anak Bangsa, SHA-1 8a41d0c3..., di 214 perangkat
```

**Kapan gagal:** baris responder (E04, E05, isolasi) dihapus supaya garis waktu "fokus ke penyerang". Pembaca yang membandingkan netscan dengan log firewall akan menemukan aktivitas pukul 11:22 yang tidak dijelaskan.

### 2.8 Rekomendasi dengan pemilik dan tenggat

Bagian ini menutup pertanyaan kelima Dimas. Kedua tabel memakai format Apa, Kenapa, Pemilik, Tenggat dari template; pemilik ditulis sebagai fungsi dengan nama kontak (bagian 1.7).

Rekomendasi `INC-2027-010`. Tidak ada containment teknis yang tersisa; yang tersisa keputusan, penilaian, dan perbaikan kontrol. Baca kolom "Kenapa": setiap baris menunjuk temuan atau batas yang mendasarinya.

| Kelompok | Apa | Kenapa | Pemilik (kontak) | Tenggat |
|---|---|---|---|---|
| Keputusan | Putuskan permintaan message trace dan audit Microsoft 365 akun `arif.wicaksono` 4 sampai 8 Januari | Temuan 6: jalur email korporat belum diperiksa; butuh izin terpisah | Legal (Ratna Sari) | Jumat 2027-01-22 |
| Keputusan | Putuskan langkah memperoleh flashdisk serial `0019E06B4A21C5F0A7` secara sah | Temuan 4: satu-satunya cara menaikkan keyakinan isi flashdisk | Legal dan HR (Ratna Sari, Larasati Wibisono) | Jumat 2027-01-22 |
| Penilaian | Nilai dampak daftar PIC (287 baris, 64 pelanggan) dan kewajiban yang mungkin timbul | Bagian 7: berada di flashdisk pribadi dengan keyakinan sedang | DPO (Agus Setiawan) | ditetapkan DPO |
| Perbaikan kontrol | Tinjau izin folder `Harga-Kontrak` agar akses mengikuti portofolio, dengan pengecualian yang disetujui | Temuan 1: akun bisa membuka 64 berkas walau memegang 11 | Divisi Enterprise Sales dan IT (Surya Atmaja, admin file server) | 2027-02-26 |
| Visibilitas | Uji Audit Removable Storage di `JAB-WS-Audit` pada kelompok pilot, ukur volume log, lalu putuskan perluasan | Temuan 4: penulisan ke media lepasan tidak tercatat di mana pun | Tim endpoint (admin GPO) | pilot selesai 2027-02-26 |
| Visibilitas | Tinjau daftar media kerja terdaftar dan opsi kontrol media lepasan yang tersedia di lisensi PT JAB | Temuan 3: flashdisk pribadi bisa di-mount tanpa hambatan | Tim endpoint dan SOC (Dimas Prasetyo) | 2027-03-31 |
| Pertahankan | Tulis di prosedur offboarding: laptop karyawan yang keluar dengan kasus terbuka ditahan tanpa dinyalakan | Yang berjalan baik: image nyaris tanpa jejak responder | HR dan IT Helpdesk (Larasati Wibisono, Teguh Wibowo) | 2027-02-26 |

Rekomendasi `INC-2026-026`. Laporan ditulis setelah tindakan Desember berjalan, jadi kolom status diambil dari tiket IC per 2027-01-18. Tabel ini diringkas; baca kolom "Kelompok" untuk melihat urutan dari yang paling mendesak.

| Kelompok | Apa | Pemilik (kontak) | Tenggat awal | Status per 2027-01-18 |
|---|---|---|---|---|
| Containment | Blokir `cdn.pdfsuite-update[.]example[.]net`, `pdf-suite-download[.]example[.]net`, dan `198.51.100[.]37` di proxy, firewall, dan DNS | NOC (Bambang Hartono) | 2026-12-08 | dari tiket IC |
| Containment | Blok hash `version.dll` dan `pdfupdater.exe` di Defender; hapus installer dari host yang hanya mengunduh | Tim endpoint | 2026-12-08 | dari tiket IC |
| Remediasi | Reset kredensial `bima.ardiansyah`; reimage `BDG-WS-0163` setelah bukti diamankan | IT dan SOC (Rudi Hartanto) | sebelum host dipakai lagi | dari tiket IC |
| Pencarian | Hunting perilaku dan atomik sejak 2026-12-01 di semua endpoint; log proxy dan DNS untuk host tanpa sensor | Tim hunting SOC | 48 jam | dari tiket IC |
| Deteksi | Aturan perilaku `version.dll` berpengecualian JAB DocSync sebagai deteksi tetap; aturan task saat logon dengan action di `AppData\Local` | Tim deteksi SOC | 2027-02-12 | keputusan diminta (bagian 0) |
| Visibilitas | Pindahkan laptop kantor Bandung ke OU yang menerima GPO audit dan Sysmon | Tim endpoint (admin GPO) | 2027-02-26 | keputusan diminta (bagian 0) |

Cara membaca hasil:

- **"Dari tiket IC"** bukan isi yang dibiarkan kosong. Di laporan sungguhan, kolom itu diisi dari tiket sebelum draf dikirim; di sini dibiarkan sebagai penanda karena status pelaksanaan Desember tidak termasuk bahan Day ini.
- **Tidak ada rekomendasi sanksi** di tabel `INC-2027-010`. Keputusan kepegawaian bukan isi laporan forensik.
- **Baris "Pertahankan"** mengikuti saran mencatat yang berjalan baik [S6]; ia juga memberi HR alasan untuk menjadikan praktik itu prosedur, bukan kebetulan.

**Kapan gagal:** rekomendasi ditulis untuk "tim IT" tanpa nama kontak dan tanpa tenggat. Tiga bulan kemudian tidak ada yang tahu apakah audit media lepasan pernah diuji.

### 2.9 Lampiran chain of custody dan alat

Lampiran ini menjawab sebagian pertanyaan keenam Dimas: orang lain bisa memeriksa bahwa bukti yang dianalisis sama dengan yang diambil, dan alat apa versi berapa yang menghasilkan setiap angka. Sebelum menulis lampiran, verifikasi ulang hash master dan salinan kerja, supaya angka di lampiran adalah hasil pemeriksaan hari itu, bukan salinan dari catatan lama.

**Tujuan:** memastikan image `INC-2027-010-E01` di server bukti masih cocok dengan hash saat akuisisi, lalu mencatat hasilnya di Lampiran A.

```bash
cd /mnt/evidence/INC-2027-010/E01
sha256sum -c INC-2027-010-E01.sha256 | tee -a /mnt/cases/INC-2027-010/report/verifikasi-hash-2027-01-19.txt
```

- `cd /mnt/evidence/...`: masuk ke folder master bukti lewat share `\\jkt-evid01\evidence` yang di-mount read-only di `jkt-dfir02` (Day 02 bagian 2.8); master tidak pernah dibuka lewat jalur yang bisa ditulis.
- `sha256sum -c`: membaca berkas `.sha256` yang dibuat saat akuisisi dan menghitung ulang setiap segmen.
- `tee -a`: menyimpan hasil ke folder laporan, supaya Lampiran A bisa menunjuk berkas verifikasi bertanggal.

Keluaran ilustrasi (sembilan segmen EWF):

```
INC-2027-010-E01.E01: OK
INC-2027-010-E01.E02: OK
...
INC-2027-010-E01.E09: OK
```

**Cara membaca hasil:** sembilan `OK` berarti master tidak berubah sejak Senin 2027-01-11. Tanggal verifikasi (Selasa 2027-01-19) ditulis di Lampiran A bersama hash akuisisi.

**Variasi:** di `JKT-DFIR01`, pakai `Get-FileHash -Algorithm SHA256` atas salinan kerja dan bandingkan dengan manifest seperti di Day 17 bagian 2.1. Untuk `INC-2026-026-E05`, verifikasi dua hash: berkas terkompresi hasil akuisisi dan raw hasil dekompresi.

**Kapan gagal:** hanya salinan kerja yang diverifikasi. Lampiran harus menyatakan master cocok, karena master yang dijadikan rujukan bila laporan dipersoalkan.

Lampiran A untuk `INC-2027-010` menggabungkan formulir chain of custody perangkat fisik (pola Day 01 bagian 2.4) dengan daftar bukti digital:

```
LAMPIRAN A. CHAIN OF CUSTODY DAN HASH BUKTI (INC-2027-010)
Item    Deskripsi                         SHA-256    Dari                 Ke                    Waktu (WIB)         Catatan
E01-D   Laptop JKT-WS-0516                belum ada  Arif Wicaksono       Teguh Wibowo (IT)     Jum 2027-01-08 16:20  diterima mati, tidak dinyalakan
E01-D   idem                              belum ada  Teguh Wibowo         Lemari IT             Jum 16:40           ditahan atas permintaan HR
E01-D   idem, kantong bukti No. 0107      belum ada  Lemari IT            Yoga Pratama          Sen 2027-01-11 15:10  segel dan foto
E01     Image disk (EWF, 9 segmen)        7f3e...    Yoga Pratama         jkt-evid01 master     Sen 15:40-18:25     hash akuisisi = verifikasi
E01-W1  Salinan kerja                     7f3e...    jkt-evid01 master    work\E01-W1           Sen 19:20           hash 9 segmen cocok Sel 09:15
-       Verifikasi ulang master           7f3e...    -                    -                     Sel 2027-01-19      9 segmen OK (berkas verifikasi)
Data pendukung: ekspor kueri 5145, proxy, dan Defender beserta hash 19 berkas asli (hash-19-asli.csv,
dihitung adm.yoga Selasa 2027-01-12 13:20-13:24) di analysis\, SHA-256 per berkas di manifest.
Konsistensi artefak dengan CoC: event terakhir di image adalah System 6006 Kamis 2027-01-07 21:47:30;
tidak ada boot setelahnya, sesuai keterangan bahwa laptop tidak dinyalakan sejak dikembalikan.
```

Lampiran B untuk `INC-2027-010` dan ringkasan Lampiran A dan B untuk `INC-2026-026`:

```
LAMPIRAN B. ALAT DAN VERSI (INC-2027-010; dibekukan saat kasus dibuka)
KAPE (KapeFiles sinkron terakhir sebelum kasus; versi di inventaris alat) | EZ Tools 2026.5.0 .NET 9:
LECmd, JLECmd, SBECmd, RECmd (DFIRBatch), MFTECmd, EvtxECmd, RBCmd, PECmd | PowerShell 7 (Get-FileHash,
Compare-Object, [Convert]::FromHexString) | Splunk search head SOC (kueri tersimpan di Lampiran C) |
Microsoft Defender for Endpoint advanced hunting (kueri UTC tersimpan di Lampiran C) | alat akuisisi dan
alat mount image: nama dan versi dari evidence log E01

LAMPIRAN A dan B (INC-2026-026, ringkas)
E04  Paket investigasi Defender BDG-WS-0163   c7a2...          Yoga, Sen 2026-12-07 11:12-11:18, portal
E05  Memori, image terkompresi (~2,6 GB)      41d9...          Yoga, Sen 11:22:10-11:31:48, live response
     Memori, raw hasil dekompresi (~9,9 GiB)  e83f...          dicatat saat E05-W1 dibuat
E06  Image disk                               b56e...          Fajar Nugraha, Sen 16:10-17:40, POP Bandung
Alat: Volatility 3 2.28.2 (symbol pack offline) | EZ Tools 2026.5.0 (PECmd, AmcacheParser,
AppCompatCacheParser, RECmd DFIRBatch, SrumECmd) | KAPE | Defender live response, paket investigasi,
advanced hunting | skrip akuisisi WinPmem dari library live response (versi di inventaris toolkit)
```

Cara membaca elemennya:

- **Tiga baris pertama `INC-2027-010` tanpa hash** bukan kekurangan: hash baru ada setelah image dibuat. Integritas selama laptop di IT dibuktikan oleh catatan serah terima, segel, dan keterangan IT, lalu dikuatkan oleh artefak (tidak ada boot setelah Kamis 21:47).
- **Baris "Konsistensi artefak dengan CoC"** adalah cara sederhana membuat CoC defensible: dokumen dan artefak saling menguatkan.
- **E05 punya dua hash.** Yang dianalisis Volatility adalah raw hasil dekompresi; hash berkas terkompresi membuktikan apa yang ditarik dari host, hash raw membuktikan apa yang dianalisis. Keduanya perlu supaya rantai dari akuisisi ke analisis tidak terputus.
- **Alat yang versinya tidak diketahui ditulis begitu,** dengan rujukan ke tempat versinya tercatat, bukan ditebak.

**Kapan gagal:** lampiran alat ditulis dari versi terbaru yang terpasang hari ini, bukan dari versi yang dipakai saat analisis. Bila alat diperbarui setelah kasus dibuka (Day 02 bagian 1.3), angka di laporan bisa tidak bisa diulang dengan versi yang tercatat.

### 2.10 Review sebelum kirim dan riwayat versi

Bagian ini menjawab sisa pertanyaan keenam dan sebagian pertanyaan ketujuh Dimas. Bacakan laporan dengan pertanyaan berikut, idealnya oleh rekan yang tidak ikut menganalisis:

- Apakah setiap kalimat di executive summary punya finding pendukung?
- Apakah setiap finding menyebut keyakinan dan keterbatasan?
- Apakah ada kata "pasti", "jelas", atau "tidak ada" yang tidak didukung bukti?
- Apakah zona waktu konsisten di seluruh laporan?
- Apakah ada hash biner sah atau IOC yang tidak di-defang?
- Apakah setiap rekomendasi punya pemilik?
- Apakah nama orang muncul hanya di tempat yang perlu, dan tanpa tuduhan niat?
- Apakah versi alat dan hash bukti tercantum?
- Apakah angka dan jam sama di semua bagian (halaman pertama, temuan, garis waktu, lampiran) [S6]?
- Apakah perubahan dari versi atau ringkasan sebelumnya dijelaskan (bagian 1.10)?
- Apakah laporan sudah dibaca satu pembaca teknis (untuk kesalahan) dan satu pembaca non-teknis (untuk kejelasan) [S8]?
- Untuk kasus berpotensi litigasi: apakah Legal sudah meninjau bahasa, penandaan, dan daftar distribusi?

Satu langkah mekanis membantu sebelum review manusia: cari kata yang sering melampaui bukti.

**Tujuan:** menandai kalimat di draf yang memakai kata penguat atau kata yang dilarang, untuk diperiksa satu per satu.

```powershell
$r = '\\jkt-evid01\cases\INC-2027-010\report\INC-2027-010-LAP-01_v0.9.md'
Select-String -Path $r -Pattern '\b(pasti|jelas|mutlak|tidak ada|mencuri|sengaja|menutupi|menghapus jejak|terbukti)\b' |
  Select-Object LineNumber, Line
```

- `Select-String -Pattern`: mencari pola regex di berkas; `\b` membatasi pencarian pada kata utuh. Pencarian default tidak membedakan huruf besar dan kecil.
- Daftar kata: penguat ("pasti", "jelas", "mutlak"), kata absolut ("tidak ada", "terbukti"), dan kata yang menyangkut niat ("mencuri", "sengaja", "menutupi", "menghapus jejak").
- `Select-Object LineNumber, Line`: menampilkan nomor baris dan isinya supaya mudah dibuka di editor.

Keluaran ilustrasi:

```
LineNumber Line
---------- ----
        87 ... Isi flashdisk dan 17 berkas lainnya tidak ada catatan di laptop ...
       142 - 17 berkas lain di flashdisk: Rendah (tidak ada artefak di laptop yang menunjuk berkas itu di E:).
       201 ... tidak ditemukan pembersihan log; tidak ada boot setelah Kamis 21:47 ...
```

**Cara membaca hasil:** setiap baris diperiksa, bukan otomatis diganti. Ketiga baris di atas sah, karena "tidak ada" di sana melaporkan pemeriksaan atas sumber yang disebut (catatan di laptop, artefak di laptop, boot di image), bukan klaim bahwa sesuatu tidak terjadi. Baris yang tidak lolos adalah yang memakai "tidak ada" tanpa sumber, misalnya "tidak ada data yang keluar".

**Variasi:** tambahkan pola untuk nama subjek (`\bArif\b`) dan periksa bahwa nama itu hanya muncul di latar, keterangan, dan distribusi.

**Kapan gagal:** hasil pencarian kosong dianggap laporan aman. Alat ini hanya menemukan kata; kalimat yang terlalu kuat tanpa kata-kata itu ("berkas harga sampai ke pesaing lewat flashdisk") hanya tertangkap pembaca manusia.

Hasil review Rabu sampai Jumat dicatat di Lampiran D. Tabel berikut adalah catatan review kedua laporan; baca kolom "Penyelesaian", karena di situ terlihat mana yang mengubah isi dan mana yang hanya mengubah kata.

| No. | Laporan | Peninjau | Catatan | Penyelesaian |
|---|---|---|---|---|
| D.1 | 010 | Sari Kusuma (teknis) | Ringkasan Rabu 13 Januari menulis "kemungkinan seluruh 19 berkas disalin", sedangkan skala template memakai "kemungkinan besar" untuk sedang | Kalimat diganti "ada indikasi ... tidak dapat dipastikan" sesuai tingkat rendah yang sudah ditetapkan di temuan; keyakinan tidak berubah, perubahan kata dicatat di riwayat versi |
| D.2 | 026 | Sari Kusuma (teknis) | Memo Desember menulis `schtasks.exe` dipanggil pukul 15:05:20, delapan detik setelah waktu pendaftaran task 15:05:12 di XML, TaskCache, dan `$MFT` | Waktu pemanggilan dicek ulang ke process timeline EDR sebelum final; sementara temuan tidak menyebut jam pemanggilan, dan keyakinan waktu pendaftaran tetap tinggi karena tiga sumber disk sepakat |
| D.3 | 010 | Ratna Sari (Legal) | Judul draf awal memuat kata "Dugaan Pencurian" | Judul diganti netral (bagian 2.1); nomor kasus tetap |
| D.4 | 010 | Ratna Sari (Legal) | Penandaan dokumen dan daftar distribusi | Ditetapkan Legal; laporan tidak diteruskan tanpa izin IC dan Legal |
| D.5 | 010 | Larasati Wibisono (HR, pembaca non-teknis) | "VSN" dan "Recycle Bin" tidak dipahami | Ditambahkan ke glosarium Lampiran E; tidak dipakai di halaman pertama |

Riwayat versi `INC-2027-010-LAP-01` di Lampiran D:

```
Versi  Tanggal      Status                     Perubahan
0.1    2027-01-13   Ringkasan sementara        Ringkasan forensik untuk rapat HR/Legal/DPO 14 Januari
                    (bukan laporan)            (notes\ringkasan-forensik-2027-01-13.md)
0.9    2027-01-20   Draf untuk review          Struktur JAB-DFIR-TPL-01; keyakinan per temuan; bagian data
                                               pribadi (287 baris, dihitung DPO 15 Januari); lampiran A-E
1.0    2027-01-21   Final                      Setelah catatan D.1-D.5 diselesaikan
Perubahan terhadap ringkasan 13 Januari: tidak ada temuan yang berubah keyakinannya. Perubahan kata
pada butir 17 berkas lain (D.1) menyesuaikan skala; tingkat keyakinan tetap rendah.
```

**Kapan gagal:** catatan Legal tentang bahasa diterapkan dengan mengubah isi temuan, misalnya menghapus keterbatasan agar laporan "lebih tegas". Legal boleh mengubah format, penandaan, dan kata; fakta, keyakinan, dan batas hanya berubah bila buktinya berubah, dan setiap perubahan dicatat.

### 2.11 Contoh laporan interim

Contoh ini menutup pertanyaan ketujuh Dimas dari sisi lain: seperti apa update di tengah kasus yang kelak harus konsisten dengan laporan final. Selasa 2026-12-08, saat membedah `BDG-WS-0163` dengan tenggat 16:00, kamu mengirim satu update tertulis ke Rudi pukul 12:00, karena insiden SEV-2 membutuhkan update berkala dan tim containment menunggu konfirmasi sebelum reimage.

```
INC-2026-026 | Update forensik host #1 BDG-WS-0163 | Selasa 2026-12-08 12:00 WIB | ke: Rudi Hartanto
Status: PRELIMINARY. Temuan bisa berubah; final dijadwalkan 16:00.

DIKETAHUI SEKARANG (keyakinan)
- Titik masuk: PDFSuite_Setup_4.2.exe dijalankan Jumat 15:04:50; pdfupdater.exe berjalan 15:05:10 dan
  memuat version.dll dari AppData\Local\PDFSuite\ (Tinggi: Prefetch, Amcache, PCA, $MFT).
- version.dll tanpa tanda tangan, SHA-1 3f9c2b7e..., berbeda dari version.dll JAB DocSync 8a41d0c3...
  (Tinggi: Amcache).
- Persistence: task \PDFSuite Updater saat logon, didaftarkan Jumat 15:05:12 (Tinggi: XML, TaskCache,
  $MFT FN).
- Tool discovery berjalan Senin 08:10-08:12 di bawah SID bima.ardiansyah (Tinggi: Prefetch, BAM);
  argumen dari EDR timeline, sama dengan hasil hunting kemarin.

BERUBAH SEJAK HUNTING SENIN
- Tidak ada temuan hunting yang direvisi. Disk mengonfirmasi waktu dan akun untuk eksekusi dan
  discovery; persistence kini dibuktikan dari tiga sumber disk selain EDR.

SEDANG DIKERJAKAN (perkiraan selesai)
- Memori E05: tahap kedua, injeksi, pemilik koneksi C2 (14:00).
- IOC perilaku yang mengecualikan 214 perangkat JAB DocSync (15:30).

BELUM BISA DIJAWAB
- Pencurian kredensial dan lateral movement dari host ini: menunggu analisis memori.

KEPUTUSAN YANG DIBUTUHKAN
- Tunda reimage BDG-WS-0163 sampai jawaban final 16:00 (image E06 sudah aman, tetapi host masih
  dibutuhkan bila perlu pengambilan ulang).
```

Cara membaca elemennya:

- **"PRELIMINARY" di baris status** adalah label yang disarankan praktisi untuk keyakinan yang belum final [S6], dan isinya mengikuti isi status minimal SP 800-61r3: ringkasan, IOC, status tindakan dengan perkiraan waktu, dan langkah berikutnya [S2].
- **"Berubah sejak hunting Senin"** diisi walaupun jawabannya "tidak ada yang direvisi". Itu penerapan aturan ICD 203 tentang menjelaskan konsistensi atau perubahan penilaian [S4].
- **Bandingkan dengan laporan final (bagian 2.4).** Final menambah Temuan 2 (tahap kedua, keyakinan sedang), Temuan 4 (C2, 73 koneksi), dan Temuan 5 (tanpa tanda pencurian kredensial, keyakinan sedang). Tidak ada kalimat interim yang ditarik. Itu hasil dari disiplin interim: yang belum diperiksa ditulis "belum bisa dijawab", bukan "tidak ada".

**Variasi:** di kasus orang dalam, interim jarang dikirim ke banyak orang. Ringkasan Rabu 13 Januari (Day 17 bagian 2.9) adalah bentuk interim untuk rapat; versi itu tercatat sebagai 0.1 di riwayat versi laporan final (bagian 2.10).

**Kapan gagal:** interim menulis "tidak ada lateral movement" sebelum memori diperiksa. Bila analisis memori kemudian menemukan sesuatu, laporan final harus menarik kalimat itu, dan pembaca akan bertanya kalimat lain mana yang juga ditulis sebelum diperiksa.

## 3. Lab praktik (di VM lab terisolasi)

Lab ini melatih menulis laporan, bukan menjalankan alat. Bahannya adalah hasil kerja lab-mu sendiri di Day 13 sampai 18 (`CASE-2026-LAB-013` sampai `CASE-2026-LAB-018`): temuan, garis waktu, IOC, case notes, hash, dan catatan kebenaran dasar. Folder kasus lab `CASE-2026-LAB-019` di `LAB-DFIR01` (`172.16.50.20`). Bila perlu mengulang satu pemeriksaan, pakai `LAB-WS01` (`172.16.50.10`) atau `LAB-WS02` (`172.16.50.11`) dari snapshot di jaringan host-only `172.16.50.0/24`. Semua isi laporan adalah data lab-mu; jangan memakai data atau nama dari pekerjaan nyata.

**Prasyarat:** minimal satu kasus lab lengkap dari Day 17 (`CASE-2026-LAB-017`, pola orang dalam) atau Day 18 (`CASE-2026-LAB-018`, pola side-loading), lebih baik keduanya; salinan kosong template bagian 2.1 di `CASE-2026-LAB-019\template\`.

1. **Pilih kasus dan tetapkan pembaca.** Tulis di case notes siapa pembaca tiap bagian (misalnya "direksi fiktif", "Legal fiktif", "tim deteksi"). Beri nomor dokumen `CASE-2026-LAB-019-LAP-01`.
2. **Isi kerangka** bagian 2.1 sampai lengkap, termasuk skala keyakinan di metodologi, asumsi beserta dampaknya bila salah, dan jejak responder lab-mu (akun `lab.ir`, disk `LAB-USB`, snapshot).
3. **Temuan.** Tulis minimal tiga finding dengan format bagian 2.5 atau 2.6. Di draf pertama, tandai fakta, tafsiran, dan pendapat dengan warna berbeda untuk memeriksa pemisahannya, lalu hapus warnanya.
4. **Executive summary.** Tulis terakhir, maksimal satu halaman, dengan bagian 0 tiga sampai lima kalimat. Uji dengan meminta orang non-teknis membacanya, lalu minta ia menyebutkan apa yang terjadi, apa yang tidak diketahui, dan keputusan apa yang diminta.
5. **Garis waktu, IOC, data pribadi, yang belum diketahui.** Kurasi garis waktu dengan kolom pelaku dan tiga daftar di bawahnya (bagian 1.6). Isi IOC dengan defang dan daya tahan bila kasusnya malware; isi bagian data pribadi dengan tangga bukti bila kasusnya menyangkut berkas `daftar-tiruan.xlsx`.
6. **Rekomendasi.** Tulis dengan format Apa, Kenapa, Pemilik, Tenggat; setiap baris menunjuk temuan.
7. **Lampiran.** Verifikasi ulang hash image lab dengan `sha256sum -c` atau `Get-FileHash` (bagian 2.9), lalu tulis chain of custody lab (snapshot, image, salinan kerja), alat dan versi yang benar-benar kamu pakai, dan keluaran pendukung per finding saja.
8. **Review.** Jalankan pencarian kata bagian 2.10 atas draf-mu, lalu daftar pertanyaan review. Catat setiap temuan review dan penyelesaiannya dalam tabel seperti Lampiran D.
9. **Dua versi keyakinan.** Tulis ulang executive summary untuk situasi di mana image memori tidak tersedia (kasus Day 18) atau log file server tidak tersedia (kasus Day 17). Bandingkan kalimat mana yang turun tingkat keyakinannya dan kenapa.
10. **Bandingkan dengan kebenaran dasar.** Baca catatan kebenaran dasar dari lab Day 17 atau 18 dan tandai kalimat laporan yang lebih kuat atau lebih lemah dari kenyataan skenario.

**Variasi:**

- Tulis laporan interim hari pertama untuk kasus lab Day 18, saat hanya alert EDR atau Sysmon dan triage yang tersedia, lalu laporan final. Catat temuan interim mana yang berubah, dan tulis bagian "Perubahan sejak versi sebelumnya".
- Tulis memo dua halaman untuk kasus yang sama dan bandingkan apa yang harus dibuang dan apa yang tidak boleh dibuang (skala keyakinan, batas).
- Minta rekan memainkan peran pihak yang menyanggah laporan kasus lab Day 17. Catat pertanyaan yang sulit dijawab, perbaiki laporannya, dan terbitkan versi 1.1 dengan riwayat perubahan.
- Tulis bagian 0 dalam bahasa Inggris untuk pembaca retainer atau auditor luar, lalu periksa apakah tingkat keyakinan tetap sama setelah diterjemahkan.

**Hasil yang sebaiknya tersimpan:**

- Template `JAB-DFIR-TPL-01` versi lab-mu, bila kamu mengubahnya, beserta alasan perubahan.
- Laporan lengkap dengan semua bagian, lampiran A sampai E, dan riwayat versi.
- Executive summary yang lolos uji pembaca non-teknis, beserta catatan apa yang tidak dipahami pembaca.
- Minimal tiga finding dengan bukti, tafsiran, keyakinan, keterbatasan, asumsi, dan hipotesis alternatif.
- Rekomendasi dengan pemilik dan tenggat.
- Hasil pencarian kata dan catatan review beserta penyelesaiannya.
- Dua versi executive summary dengan tingkat keyakinan berbeda, dan selisih laporan terhadap kebenaran dasar.

## 4. Troubleshooting

Tabel ini memuat masalah yang paling sering muncul saat menyusun dan mengirim laporan forensik. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Manajemen tidak paham laporan | Executive summary memakai istilah artefak | Tulis ulang dengan bahasa dampak dan keputusan; pindahkan istilah ke glosarium |
| Temuan terkesan dugaan | Tidak ada rujukan artefak | Tautkan setiap klaim ke lampiran |
| Laporan dianggap berlebihan | Keterbatasan tidak dinyatakan | Tambahkan keterbatasan dan hipotesis alternatif per finding |
| Hasil tidak bisa diulang | Versi alat tidak dicatat | Catat versi di metodologi dan lampiran |
| Timeline membanjiri pembaca | Super-timeline mentah dimasukkan | Kurasi ke kejadian yang mendukung finding |
| Rekomendasi tidak dikerjakan | Tidak ada pemilik dan tenggat | Tambahkan pemilik dan tenggat per butir |
| Temuan berubah setelah laporan dikirim | Data baru masuk | Terbitkan versi baru dengan riwayat perubahan |
| Laporan final terdengar berbeda dari ringkasan sementara | Kata berubah tanpa penjelasan | Tulis bagian "Perubahan sejak versi sebelumnya", termasuk perubahan kata yang tidak mengubah keyakinan |
| Angka di halaman pertama berbeda dari temuan atau garis waktu | Ringkasan ditulis dari ingatan atau dari draf lama | Bandingkan setiap angka halaman pertama dengan temuan dan lampiran sebelum kirim |
| DPO meminta jawaban "ya atau tidak" | Pertanyaan menyangkut anak tangga yang tidak dicapai bukti | Jawab dengan tangga bukti per anak tangga; tulis "tidak dapat ditentukan" dan sumber yang bisa menjawab |
| Legal meminta kesimpulan lebih tegas | Tekanan untuk keputusan cepat | Format, kata, dan penandaan boleh diubah; fakta, keyakinan, dan batas hanya berubah bila bukti berubah |
| Template terasa terlalu panjang untuk insiden kecil | Semua bagian diisi penuh | Pakai versi memo dua halaman dengan skala keyakinan yang sama |

## 5. Kesalahan umum dan jebakan

- **Executive summary yang teknis.** Manajemen butuh dampak dan keputusan.
- **Bahasa keyakinan yang berubah-ubah.** Tetapkan skala dan pakai konsisten, termasuk di interim.
- **"Tidak ada" padahal maksudnya "tidak ditemukan".** Yang kamu laporkan adalah hasil pemeriksaan, bukan kepastian bahwa sesuatu tidak terjadi.
- **Mencampur fakta, interpretasi, dan pendapat.** Satu pendapat yang disanggah bisa menyeret fakta yang kuat.
- **Asumsi yang tersembunyi.** Asumsi tentang perilaku alat atau sistem ditulis di metodologi beserta dampaknya bila salah.
- **Satu label keyakinan untuk satu temuan yang berisi beberapa pernyataan.** Pecah keyakinan per pernyataan.
- **Menuduh niat.** Laporkan aksi pada akun dan perangkat.
- **Menjawab pertanyaan DPO dengan ya atau tidak.** Jawab dengan tangga bukti dan serahkan penilaian kewajiban ke DPO dan Legal.
- **IOC tanpa defang atau berisi hash biner sah.**
- **Mengubah laporan final tanpa riwayat versi.**
- **Lampiran berisi semua ekspor alat.** Lampiran hanya memuat yang menopang temuan, dan data pribadi diminimalkan.
- **Menghapus baris responder dari garis waktu.** Pembaca yang membandingkan sumber akan menemukan aktivitas yang tidak dijelaskan.
- **Menyalin laporan kasus lama sebagai template.** Kalimat dan nama dari kasus lama ikut terbawa.

## 6. Catatan terkini

Bagian ini menampung detail edisi, status dokumen, dan versi alat yang bisa berubah; isinya tidak mengubah cara menyusun laporan di atas.

- **NIST SP 800-86** (Agustus 2006) masih menjadi rujukan publik paling sering dipakai untuk tahapan proses forensik, termasuk reporting [S1]. Halaman CSRC per 2026-10-22 menandainya final tanpa catatan revisi atau publikasi pengganti.
- **NIST SP 800-61r3** terbit April 2025 dan menggantikan r2 (2012). Rekomendasinya disusun mengikuti fungsi dan kategori NIST CSF 2.0, sehingga butir yang relevan untuk laporan forensik tersebar di Respond (RS.AN, RS.CO, RS.MA) dan Identify (ID.IM), bukan di satu bab pelaporan [S2].
- **ICD 203** ditandatangani 2 Januari 2015 dengan amandemen teknis 2022 dan 2023; ia mengatur produk analisis komunitas intelijen AS, bukan laporan forensik, dan dipakai di Day ini hanya sebagai rujukan untuk bahasa ketidakpastian dan pemisahan informasi dari penilaian [S4].
- **ISO/IEC 27042:2015** edisi 1.0 terbit 2015-06-19 menurut halaman penerbit IEC [S5]; status peninjauan berkalanya dicek di halaman ISO sebelum standar ini dirujuk di laporan. Isi standar berbayar; Day ini hanya memakai abstraknya.
- **Panduan penulisan laporan IR Lenny Zeltser** versi 1.5.1 (2026-05-26) memakai SP 800-61r3 sebagai jangkar fase respons dan memuat aturan praktis untuk ringkasan, keyakinan preliminary atau final, pemisahan data diakses dan dieksfiltrasi, dan tabel tindakan dengan pemilik [S6]. Panduan ini ditulis untuk laporan IR umum, bukan khusus forensik host.
- **Versi alat di lampiran contoh** mengikuti pembekuan kasus: EZ Tools 2026.5.0 dan Volatility 3 2.28.2, keduanya masih versi terbaru di halaman resmi saat Day 17 dan 18 diperiksa 2026-10-22. Plaso 20260720 yang tercantum di lampiran contoh versi lama Day ini tidak dipakai di kedua kasus, sehingga tidak dicantumkan.
- Laporan DFIR swasta makin sering dibaca pihak di luar organisasi, seperti asuransi siber dan regulator. Ini menambah alasan untuk memisahkan fakta dari pendapat dan mencatat riwayat versi.
- Day 20 adalah review akhir seluruh rangkaian Day.

## 7. Cheat sheet

```
TEMPLATE    JAB-DFIR-TPL-01: 0 inti+keputusan | 1 exec summary | 2 lingkup | 3 metodologi (alat+versi+zona
            +skala+asumsi+jejak responder) | 4 temuan | 5 hipotesis | 6 timeline | 7 data pribadi | 8 IOC
            | 9 belum diketahui | 10 rekomendasi | 11 berjalan baik | Lampiran A CoC B alat C bukti D versi E glosarium
EXEC        apa terjadi -> seberapa parah -> status -> keputusan ; inti 3-5 kalimat + maks 1 halaman ;
            ditulis TERAKHIR ; tanpa nama artefak ; berdiri sendiri (batas ikut tertulis)
NIST 800-86 penjelasan alternatif | audiens | informasi yang bisa ditindaklanjuti | catat celah kebijakan/logging
800-61r3    RS.AN-06 catat tindakan + jaga integritas catatan | RS.AN-07 data = bukti | RS.MA status: ringkasan,
            IOC, status+perkiraan waktu, langkah berikut | RS.CO-03 HR untuk kasus orang dalam | ID.IM-03
KEYAKINAN   tinggi "bukti menunjukkan" | sedang "bukti mendukung" | rendah "ada indikasi" | "tidak dapat ditentukan"
            per pernyataan, bukan per kasus ; jangan gabung keyakinan + kemungkinan dalam satu kalimat
LAPIS       fakta (Bukti) | interpretasi (Analisis) | pendapat (ditandai) | asumsi (metodologi + dampak bila salah)
"tidak ditemukan" != "tidak terjadi"
TIMELINE    WIB + UTC | sumber | pelaku (penyerang/subjek/responder) | disimpulkan ditandai | celah diakui
            + tidak ditemukan | tidak bisa dijawab | bisa dijawab dengan sumber tambahan
DPO         tangga: diakses | disalin | di media | keluar | diterima ; jumlah data dihitung DPO dari ASLI
IOC         defang ; jenis + sumber + daya tahan ; known-good di baris terpisah, bukan IOC
REKOMENDASI containment | remediasi | pencarian | deteksi | visibilitas ; apa + kenapa + pemilik (fungsi, kontak) + tenggat
DEFENSIBLE  CoC + hash master diverifikasi ulang + versi alat + rujukan per klaim + hipotesis disingkirkan
            + riwayat versi ; 27042: continuity, validity, reproducibility, repeatability
NADA        aksi pada akun/perangkat, bukan niat orang ; nama orang hanya di latar, keterangan, distribusi
INTERIM     PRELIMINARY ; diketahui (keyakinan) | berubah | dikerjakan (perkiraan) | belum bisa dijawab | keputusan
REVIEW      angka sama di semua bagian ; kata penguat ; pembaca teknis + non-teknis ; Legal untuk litigasi
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Proxy kantor dan riwayat Edge tidak menunjukkan unggahan ke layanan penyimpanan online, jadi bagian data pribadi bisa menulis bahwa daftar PIC tidak keluar dari PT JAB." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Hasil itu hanya berlaku untuk trafik dari kantor yang lewat proxy dan untuk riwayat browser di laptop; jaringan rumah, ponsel, akun pribadi, dan flashdisk berada di luar pemeriksaan. Daftar PIC berada di flashdisk pribadi dengan keyakinan sedang, dan anak tangga "keluar dari kendali PT JAB" serta "diterima pihak lain" tidak dapat ditentukan dari data yang tersedia. Bagian data pribadi menulis tangga bukti per anak tangga dan menyerahkan penilaian kewajiban ke DPO dan Legal. Lihat bagian 1.9 dan 2.3.

</details>

**2. Skenario keputusan.** Kamu harus memilih satu kalimat tentang flashdisk untuk halaman pertama yang dibaca Hendra. Mana yang paling tepat?

- A. "Arif menyalin 19 berkas harga dan daftar PIC ke flashdisk pribadinya."
- B. "Dua berkas tercatat dibuat dan dibuka di flashdisk pribadi yang tersambung di sesi akun tersebut (keyakinan sedang); ada indikasi 17 berkas lainnya ikut disalin, tetapi tidak dapat dipastikan, dan isi flashdisk tidak dapat ditentukan."
- C. "Penyalinan ke flashdisk tidak dapat dibuktikan karena flashdisk tidak tersedia."

<details><summary>Jawaban</summary>

B. Kalimat itu memakai frasa skala yang sesuai untuk tiap pernyataan: fakta yang tercatat, keyakinan sedang untuk dua berkas, "ada indikasi ... tidak dapat dipastikan" untuk 17 berkas lain, dan "tidak dapat ditentukan" untuk isi. A keliru karena menyebut orang, bukan akun dan sesi, dan memperluas bukti dua berkas ke 19 berkas. C keliru karena artefak laptop tetap memberi bukti tidak langsung yang kuat untuk dua berkas; ketiadaan flashdisk hanya membatasi verifikasi isi. Lihat bagian 1.4, 2.2, dan 2.5.

</details>

**3. Pertanyaan jebakan.** "Legal meminta bagian keterbatasan dipersingkat supaya laporan terdengar lebih tegas. Laporan yang lebih tegas lebih kuat di proses hukum." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Laporan defensible bukan laporan yang terdengar yakin, tetapi laporan yang penalarannya bisa diikuti dan diulang orang lain. Keterbatasan, asumsi, dan hipotesis yang disingkirkan adalah bagian dari objektivitas; laporan yang menyembunyikannya mudah dipatahkan saat pihak lain menemukan celah sendiri. Legal boleh mengubah format, kata, penandaan, dan distribusi, tetapi fakta, keyakinan, dan batas hanya berubah bila buktinya berubah, dan setiap perubahan dicatat di riwayat versi. Lihat bagian 1.8 dan 2.10.

</details>

**4. Skenario keputusan.** Saat menyusun laporan final, kamu sadar ringkasan Rabu menulis "kemungkinan seluruh 19 berkas disalin", sedangkan skala template memakai "kemungkinan besar" untuk keyakinan sedang. Keyakinan untuk 17 berkas itu tetap rendah. Apa yang kamu lakukan?

- A. Ganti kalimatnya diam-diam supaya sesuai skala; toh keyakinannya tidak berubah.
- B. Ganti kalimatnya sesuai skala, lalu catat di riwayat versi bahwa kata berubah tetapi keyakinan tetap rendah.
- C. Pertahankan kalimat ringkasan Rabu di laporan final supaya tidak terlihat berbeda.

<details><summary>Jawaban</summary>

B. Pembaca yang membandingkan dua dokumen harus tahu bahwa perbedaan kata tidak berarti temuan baru; aturan ICD 203 meminta produk menyatakan apakah penilaiannya konsisten atau berubah dan kenapa. A keliru karena perubahan tanpa catatan membuat pembaca menebak, dan di kasus yang bisa dipersoalkan, perubahan diam-diam bisa dibaca sebagai upaya menyesuaikan kesimpulan. C keliru karena laporan final lalu memakai kata yang tidak sesuai skalanya sendiri, sehingga pembaca bisa membacanya sebagai keyakinan sedang. Lihat bagian 1.10 dan 2.10.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Agus Setiawan (DPO), dalam tiga kalimat, kenapa laporan forensik tidak bisa menjawab "ya" atau "tidak" untuk pertanyaan apakah data PIC keluar dari PT JAB, dan apa yang diberikannya sebagai gantinya.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Bukti dari laptop dan log server membawa kita sampai berkas daftar PIC disalin ke laptop (keyakinan tinggi) dan berada di flashdisk pribadi yang tersambung di sesi akun itu (keyakinan sedang), tetapi flashdisk tidak ada di tangan kita dan tidak ada sumber yang mencatat ke mana ia dibawa. Karena itu laporan menulis 'tidak dapat ditentukan' untuk anak tangga keluar dari kendali PT JAB dan diterima pihak lain, bukan 'tidak keluar' dan bukan 'keluar'. Sebagai gantinya laporan memberi tangga bukti per anak tangga, jumlah dan kategori data yang Bapak hitung dari berkas asli, dan sumber yang bisa menaikkan kepastian, sehingga penilaian kewajiban tetap ada di Bapak dan Legal."

Kesalahan yang sering muncul:
- Menjawab "kemungkinan besar keluar" tanpa dasar artefak, hanya karena urutannya mencurigakan.
- Menjadikan volume webmail 182.336 byte sebagai bukti bahwa daftar PIC tidak terkirim.
- Ikut menilai apakah kewajiban notifikasi timbul.

</details>

**6. Pertanyaan jebakan.** "Halaman pertama `INC-2026-026` untuk Hendra cukup menulis 'tingkatkan keamanan endpoint', karena beliau bukan orang teknis dan rincian ada di bagian rekomendasi." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Halaman pertama harus menyebut keputusan yang dibutuhkan secara eksplisit, dengan pemiliknya, karena halaman itulah yang dibaca direksi; "tingkatkan keamanan endpoint" tidak bisa diputuskan dan tidak bisa diperiksa selesai atau belum. Di laporan `INC-2026-026`, keputusannya adalah menetapkan aturan deteksi perilaku yang mengecualikan JAB DocSync (tim deteksi) dan menutup celah audit laptop Bandung (tim endpoint). Rekomendasi di bagian 10 tetap memakai format apa, kenapa, pemilik, dan tenggat. Lihat bagian 1.2, 1.7, 2.4, dan 2.8.

</details>

**7. Interview question (English).** "You've finished a forensic investigation into an employee suspected of taking confidential data. HR and Legal want a report they can use for an employment decision and possibly litigation. How do you write it?"

<details><summary>Sample answer</summary>

"I use a fixed structure that goes from general to detailed: a few lines of bottom line with the decisions we need, a one-page executive summary written last, then scope and legal authorization, methodology with tool versions, time zone, a defined confidence scale and stated assumptions, findings, the alternative hypotheses I tested, a curated timeline, a personal-data section for the DPO, open questions, and recommendations with owners and dates, with chain of custody, hashes, tool versions and version history in the appendices. In every finding I separate what the artifact recorded from my interpretation, and I mark any opinion as an opinion. I assign confidence per statement, not per case, so I might say the local copy is high confidence, two files on the USB drive are moderate, the other seventeen are low, and the drive's current contents cannot be determined. I write about accounts, sessions and devices, never intent or guilt, and I keep negative results with their scope, like 'no upload seen from the office proxy', instead of 'no data left the company'. Before release a technical peer and a non-technical reader review it, Legal reviews language, marking and distribution, and if new evidence arrives later I issue a revised version rather than overwriting the final."

What makes this answer strong: it shows a repeatable structure built for multiple audiences, uses a consistent confidence scale applied per statement, separates fact from interpretation and opinion, avoids intent, handles negative results honestly, and treats defensibility as chain of custody, reproducibility, review, and version control rather than confident wording.

</details>

## 9. Sumber

Tabel ini adalah rujukan verifikasi; semua isi yang dibutuhkan untuk memahami Day ini sudah ditulis di atas.

| # | Judul | URL | Tipe | Tanggal / diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response, bagian 3.4 Reporting | https://csrc.nist.gov/pubs/sp/800/86/final | primer | Agustus 2006; dibaca 2026-10-10, diakses ulang 2026-10-22 | Tinggi. Empat tahap proses; reporting sebagai penyajian hasil analisis; faktor pelaporan (penjelasan alternatif, audiens, informasi yang bisa ditindaklanjuti); pencatatan masalah kebijakan, prosedur, dan logging (bagian 3.4); analisis bisa berakhir tanpa kesimpulan; dokumentasi temuan dan langkah untuk tindakan hukum atau disipliner (bagian 3.3); log rinci tiap langkah dan alat agar bisa diulang (bagian 3.1.2); nama dan versi alat akuisisi (bagian 4.2.1). Halaman CSRC: final, tanpa catatan revisi |
| S2 | NIST SP 800-61r3: Incident Response Recommendations and Considerations for Cybersecurity Risk Management | https://csrc.nist.gov/pubs/sp/800/61/r3/final | primer | April 2025; dirujuk 2026-10-10, dibaca 2026-10-22 | Tinggi. Menggantikan r2; disusun mengikuti CSF 2.0. Dipakai: RS.MA (isi status per insiden), RS.AN-03, RS.AN-06 (catatan tindakan, integritas, akses terbatas, informasi sensitif tentang pengguna), RS.AN-07 (data insiden sebagai bukti), RS.CO-02 dan RS.CO-03 (apa dilaporkan ke siapa dan kapan; HR untuk aktivitas orang dalam), ID.IM-03 (perbaikan dari laporan tindak lanjut dan lessons learned) |
| S3 | Endpoint-Forensics-Notes Day 01, 02, 12, 13, 17, 18 | (lokal) | rujukan internal | 2026-10-22 | Chain of custody dan case notes (Day 01), pembekuan versi dan mount (Day 02), lembar batas bukti (Day 12), garis waktu kurasi (Day 13), bahan kasus `INC-2027-010` (Day 17) dan `INC-2026-026` (Day 18) |
| S4 | ODNI: Intelligence Community Directive 203, Analytic Standards | https://www.dni.gov/files/documents/ICD/ICD-203.pdf | primer (lembaga pemerintah) | 2 Januari 2015, amandemen teknis 2022 dan 2023; diakses 2026-10-22 (diarahkan ke archive.dni.gov) | Tinggi untuk isi standar; bukan standar forensik. Dipakai: konsistensi istilah ketidakpastian, keyakinan dan kemungkinan tidak digabung dalam satu kalimat, membedakan informasi dari asumsi dan penilaian, analisis alternatif, pesan utama di depan, menjelaskan perubahan atau konsistensi penilaian terhadap produk sebelumnya |
| S5 | IEC Webstore: ISO/IEC 27042:2015 Guidelines for the analysis and interpretation of digital evidence | https://webstore.iec.ch/publication/22757 | primer (abstrak penerbit) | terbit 2015-06-19, edisi 1.0; diakses 2026-10-22 | Sedang untuk Day ini: hanya abstrak yang dibaca (continuity, validity, reproducibility, repeatability; catatan untuk pemeriksaan independen; metode baru sesuai tujuan; kompetensi tim). Isi standar berbayar tidak dibuka; status peninjauan berkala dicek di halaman ISO |
| S6 | Lenny Zeltser: IR writing guidelines (incident response report writing) | https://zeltser.com/media/docs/ir-writing-guidelines.yaml | sekunder (praktisi) | versi 1.5.1, 2026-05-26; diakses 2026-10-22 | Sedang-tinggi. Ringkasan singkat dengan angka dan permintaan keputusan; keyakinan preliminary atau final dengan bukti yang ditunggu; waktu kejadian dan waktu ditemukan dipisah; data diakses dan dieksfiltrasi dipisah; kritik proses bukan orang; tabel tindakan Apa, Kenapa, Kapan, Siapa dengan pemilik berupa fungsi; catat yang berjalan baik; kebutuhan per audiens; sikap notifikasi diserahkan ke legal; angka konsisten antar bagian |
| S7 | SANS: Report Writing for Digital Forensics, Part II | https://www.sans.org/blog/report-writing-for-digital-forensics-part-ii | sekunder | 2013-02-26 (lebih dari 24 bulan); diakses 2026-10-22 | Sedang. Ringkasan kasus untuk pembaca non-teknis dan bisa berdiri sendiri; proses akuisisi dijelaskan dengan bahasa awam; hindari link dumping; susun bukti menjadi cerita runtut; laporan lengkap tetap disimpan dan retensi dibahas dengan legal. Penulis tidak tercantum di halaman |
| S8 | Champlain College Leahy Center: Enfuse 2017 Reflection, Forensic Report Writing | https://leahycenterblog.champlain.edu/2017/09/26/enfuse-2017-reflection-jonathan-castro-forensic-report-writing/ | komunitas | 2017-09-26 (lebih dari 24 bulan); diakses 2026-10-22 | Sedang-rendah. Ringkasan mahasiswa atas sesi konferensi (pembicara Joseph Greenfield dan Pierson Clair): hindari kata sifat dan keterangan penguat, tidak menyatakan bersalah, executive summary ditulis terakhir, investigative leads, lampiran hanya yang relevan, glosarium, review oleh pembaca teknis dan non-teknis |

**Catatan sumber:** skala bahasa keyakinan, struktur laporan, template `JAB-DFIR-TPL-01`, dan daftar review di Day ini adalah praktik kerja yang disusun dari sumber di atas dan dari praktik umum DFIR swasta, bukan format baku dari satu standar. Sesuaikan dengan template organisasi atau klien bila ada. ICD 203 [S4] adalah standar analisis intelijen, bukan forensik, dan dipakai sebagai pembanding untuk bahasa ketidakpastian. ISO/IEC 27042 [S5] hanya dirujuk lewat abstrak penerbit; isi standarnya tidak dibuka. Sumber praktisi dan komunitas [S7][S8] berumur lebih dari 24 bulan dan dipakai untuk prinsip penulisan yang tidak bergantung versi; [S8] adalah ringkasan pihak ketiga atas sebuah presentasi, bukan materi pembicara. Untuk kasus yang mungkin dibawa ke proses hukum, persyaratan format, isi, penandaan, dan retensi laporan ditentukan bersama Legal. Semua isi PT JAB di Day ini, termasuk nomor dokumen, jumlah baris daftar PIC, hash bukti `INC-2026-026` yang disingkat, tenggat rekomendasi, dan catatan review, adalah contoh fiktif yang disusun agar konsisten dengan Day 17 dan 18.
