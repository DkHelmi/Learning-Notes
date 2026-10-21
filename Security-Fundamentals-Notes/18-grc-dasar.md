---
day: 18
title: 'GRC dasar: governance, risk, compliance, kebijakan, framework, UU PDP, audit, BCP, DRP, RTO, RPO, dan backup'
researched_on: 2026-10-21
versions_checked: 'UU No. 27 Tahun 2022 tentang Pelindungan Data Pribadi (diundangkan 17 Okt 2022); PP No. 33 Tahun 2026 (ditetapkan 16 Jul 2026, berlaku 16 Jan 2027, menurut pemberitaan); NIST CSF 2.0 (CSWP 29, 26 Feb 2024); ISO/IEC 27001:2022 edisi 3 dan Amd 1:2024; NIST SP 800-34 Rev. 1 (Nov 2010); NIST SP 800-12 Rev. 1 (Jun 2017); CISA #StopRansomware Guide (Sep 2023); US-CERT Data Backup Options (2012)'
---

# Day 18: GRC dasar (governance, risk, compliance, kebijakan, framework, UU PDP, audit, BCP, DRP, dan backup)

Cakupan: istilah yang dipakai saat keamanan dibicarakan sebagai urusan organisasi, yaitu governance, risk management (risk register, risk treatment, risk appetite), compliance, jenjang dokumen (policy, standard, procedure, guideline), framework NIST CSF 2.0 dan ISO/IEC 27001, regulasi UU Pelindungan Data Pribadi, audit internal dan eksternal, BCP dan DRP, RTO, RPO, MTD, serta backup 3-2-1, immutable, dan offline.

## Ide inti

Alat keamanan menjawab pertanyaan "bagaimana", tetapi selalu ada pertanyaan yang lebih dulu: siapa yang memutuskan apa yang harus dilindungi, seberapa besar risiko yang masih boleh diterima, aturan mana yang wajib diikuti, bagaimana membuktikan bahwa aturan itu benar-benar dijalankan, dan apa yang terjadi bila semua pengaman tetap gagal. Kelompok istilah GRC (governance, risk, compliance) dan pasangannya, continuity (BCP, DRP, backup), adalah bahasa untuk menjawab pertanyaan-pertanyaan itu. Bahasa ini dipakai direksi, manajer risiko, auditor, DPO, dan regulator, dan analyst SOC yang paham bahasanya bisa menjelaskan kenapa sebuah alert kecil, misalnya backup gagal dua malam, ternyata menyangkut janji perusahaan kepada auditor dan kepada pelanggan.

Bayangkan sebuah rumah tangga. Kepala keluarga menetapkan aturan rumah dan membagi tugas (governance). Keluarga memutuskan mana yang perlu dikhawatirkan: maling, banjir, atau kebakaran, dan mana yang cukup diasuransikan (risk). Ada aturan yang wajib dari luar, misalnya peraturan RT dan syarat asuransi, dan ada aturan buatan sendiri, misalnya "rumah dikunci saat kosong" (compliance). Sesekali pengurus RT atau petugas asuransi datang memeriksa apakah aturan itu dijalankan (audit). Keluarga juga punya rencana bila rumah kebanjiran: mengungsi ke rumah saudara supaya tetap bisa sekolah dan bekerja (BCP), lalu memperbaiki rumah setelah air surut (DRP), dan dokumen penting sudah difotokopi dan sebagian dititipkan di rumah saudara (backup). Batas analogi ini: organisasi punya ribuan aset dan ratusan orang, keputusan dan buktinya harus tertulis supaya bisa diperiksa pihak luar, dan kewajiban hukumnya punya sanksi nyata, bukan sekadar teguran tetangga.

```
              GOVERNANCE  (arah, peran, kebijakan; diputuskan pimpinan)
                    |
        +-----------+-----------+
        |                       |
      RISK                 COMPLIANCE
  (pilih prioritas:      (penuhi kewajiban: UU PDP,
   register, treatment,   kontrak, kebijakan sendiri;
   appetite)              framework sebagai panduan)
        |                       |
        +-----------+-----------+
                    |
                  AUDIT  (periksa: tertulis = dijalankan = efektif?)
                    |
   bila pengaman tetap gagal:  BCP (bisnis tetap jalan)  +  DRP (sistem dipulihkan)
                               diukur dengan MTD, RTO, RPO; bertumpu pada backup 3-2-1
```

Kamu adalah analyst L1 di SOC (Security Operations Center) PT Jaringan Anak Bangsa (PT JAB), ISP fiktif dengan sekitar 1.200 karyawan dan sekitar 400 ribu pelanggan internet rumah, dan ini minggu keempat masa orientasimu. Kamis 2027-08-26 pukul 08:15, dua alert dari semalam ada di antreanmu: `SOC-2027-0895` (job backup file server `JKT-FS01` di server backup `JKT-BKP01` gagal dua malam berturut-turut) dan `SOC-2027-0896` (percobaan menghapus restore point di repository backup ditolak sistem). Pukul 09:00 Nina Kartika, Manajer Risiko dan Kepatuhan TI, mampir ke meja SOC bersama Agus Setiawan, DPO (petugas pelindungan data pribadi) PT JAB:

> "Pas sekali dua alert ini muncul sekarang. Tiga minggu lagi auditor lembaga sertifikasi datang untuk audit surveillance ISO 27001, dan sebelumnya kita harus menjalankan uji DRP tahunan. Bantu saya menyiapkan bukti dari sisi SOC, tetapi pahami dulu bahasanya. Kenapa urusan backup sampai ke meja saya, dan siapa yang memutuskan aturannya? Risiko 'backup tidak bisa dipakai saat ransomware' dicatat di mana dan diputuskan bagaimana? Kita wajib patuh pada apa saja, dan apa beda framework dengan undang-undang? Alert semalam melanggar kebijakan, standar, atau prosedur? Kenapa di rapat komite kita bicara NIST CSF tetapi disertifikasi ISO 27001? Pak Agus akan menjelaskan kapan insiden wajib dilaporkan menurut UU PDP. Lalu: apa yang dicari auditor dan apa bedanya dengan audit internal, apa beda BCP dan DRP, apakah RPO file server sudah terlewati, dan kenapa penghapusan restore point semalam ditolak padahal yang mencoba admin kita sendiri?"

Pesan itu memuat sepuluh pertanyaan:

1. Kenapa urusan backup naik ke manajemen, dan siapa yang memutuskan aturannya?
2. Di mana risiko dicatat, dan bagaimana memutuskan penanganannya?
3. Organisasi wajib patuh pada apa, dan apa beda framework dengan undang-undang?
4. Alert semalam melanggar kebijakan, standar, atau prosedur?
5. Apa beda NIST CSF dan ISO 27001, dan kenapa PT JAB memakai keduanya?
6. Kapan insiden wajib dilaporkan menurut UU PDP, kepada siapa, dan dalam berapa lama?
7. Apa yang dicari auditor eksternal, dan apa bedanya dengan audit internal?
8. Apa beda BCP dan DRP?
9. Apakah target RPO file server sudah terlewati?
10. Kenapa penghapusan restore point ditolak?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, pertanyaan 6 di bagian 1.6, pertanyaan 7 di bagian 1.7, pertanyaan 8 di bagian 1.8, pertanyaan 9 di bagian 1.9, dan pertanyaan 10 di bagian 1.10. Bagian 2 membedah kedua alert, risk register, tenggat pemberitahuan data pribadi, dan persiapan audit serta uji DRP.

**Kapan relevan:** saat sebuah temuan teknis harus dijelaskan ke manajemen atau auditor, saat menentukan apakah insiden menyentuh kewajiban hukum, saat menyiapkan bukti audit, saat menilai apakah kegagalan backup atau gangguan layanan melanggar target pemulihan, dan saat interview untuk posisi yang bersinggungan dengan risiko dan kepatuhan.
**Kapan bukan jawaban:** GRC tidak menggantikan respons teknis saat serangan berlangsung, dan dokumen kebijakan tidak menghentikan ransomware. Day ini juga bukan nasihat hukum: keputusan apakah dan bagaimana sebuah insiden dilaporkan ke regulator ada di tangan DPO dan penasihat hukum organisasi, bukan analyst SOC. Tugas SOC adalah menyediakan fakta yang cepat dan akurat untuk keputusan itu.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (CIA, risk, likelihood, impact, control, residual risk, separation of duties) tidak diulang di tabel ini; definisinya diulang satu kalimat di tempat pemakaiannya. Tabel berikut memuat istilah baru Day ini; pakai kolom padanan sehari-hari untuk mengingat posisi setiap istilah dalam cerita rumah tangga.

| Istilah | Arti singkat | Padanan sehari-hari |
|---|---|---|
| Governance | Cara pimpinan menetapkan arah, peran, kebijakan, dan pengawasan keamanan | Aturan rumah tangga yang ditetapkan kepala keluarga |
| Risk register | Catatan pusat semua risiko beserta pemilik, nilai, keputusan, dan statusnya | Buku catatan keluarga berisi daftar kekhawatiran dan rencananya |
| Risk treatment | Keputusan atas satu risiko: mitigate, transfer, avoid, atau accept | Memasang teralis, membeli asuransi, pindah rumah, atau pasrah dengan sadar |
| Risk appetite | Jumlah dan jenis risiko yang secara umum mau diterima organisasi | Seberapa berani keluarga menanggung kemungkinan rugi |
| Compliance | Keadaan memenuhi kewajiban dari luar dan dari dalam, beserta buktinya | Mematuhi aturan RT, syarat asuransi, dan aturan rumah sendiri |
| Policy | Pernyataan tingkat tinggi tentang apa yang wajib dan kenapa | "Rumah harus dikunci saat kosong" |
| Standard | Aturan rinci yang wajib dan seragam untuk memenuhi policy | Jenis kunci yang wajib dipakai |
| Procedure | Langkah demi langkah untuk menjalankan tugas | Urutan cara mengunci pintu dan jendela |
| Guideline | Saran yang dianjurkan, boleh dijalankan dengan cara lain | "Sebaiknya titipkan kunci cadangan ke tetangga" |
| NIST CSF 2.0 | Framework NIST dengan enam fungsi: Govern, Identify, Protect, Detect, Respond, Recover | Daftar periksa umum rumah aman yang boleh dipakai siapa saja |
| ISO/IEC 27001 | Standar internasional berisi persyaratan sistem manajemen keamanan informasi (ISMS) yang bisa disertifikasi | Sertifikat "rumah aman" dari lembaga penilai |
| UU PDP | Undang-Undang No. 27 Tahun 2022 tentang Pelindungan Data Pribadi | Undang-undang tentang menjaga rahasia orang lain yang dititipkan kepadamu |
| Pengendali data pribadi | Pihak yang menentukan tujuan dan mengendalikan pemrosesan data pribadi | Orang yang memutuskan untuk apa titipan dipakai |
| DPO | Pejabat atau petugas pelindungan data pribadi (PPDP) | Anggota keluarga yang ditugasi menjaga titipan orang lain |
| Kegagalan pelindungan data pribadi | Kegagalan menjaga kerahasiaan, keutuhan, atau ketersediaan data pribadi | Titipan orang hilang, rusak, atau dibuka orang lain |
| Audit | Pemeriksaan independen atas catatan dan kegiatan untuk menilai kecukupan control dan kepatuhan | Pemeriksaan oleh pengurus RT atau petugas asuransi |
| BCP | Business continuity plan: rencana supaya proses bisnis tetap berjalan selama dan setelah gangguan besar | Rencana keluarga tetap bisa hidup saat rumah kebanjiran (mengungsi) |
| DRP | Disaster recovery plan: rencana memulihkan sistem TI setelah gangguan besar, biasanya di lokasi lain | Rencana memperbaiki rumah setelah banjir |
| BIA | Business impact analysis: analisis proses mana yang paling penting dan berapa lama boleh terhenti | Menentukan barang dan kegiatan apa yang harus diselamatkan lebih dulu |
| MTD | Maximum tolerable downtime: lama maksimal proses bisnis boleh terhenti sebelum kerugian serius | Batas paling lama keluarga bisa bertahan di pengungsian |
| RTO | Recovery time objective: lama maksimal sebuah sistem boleh mati sebelum dampaknya tidak bisa diterima | Berapa lama keluarga boleh mengungsi |
| RPO | Recovery point objective: titik waktu terakhir yang datanya harus bisa dikembalikan | Berapa banyak catatan keuangan boleh hilang sejak terakhir difotokopi |
| Backup | Salinan data yang disimpan terpisah untuk pemulihan | Fotokopi dokumen penting |
| Aturan 3-2-1 | Tiga salinan, dua jenis media, satu di luar lokasi | Tiga salinan dokumen, dua jenis tempat, satu di rumah saudara |
| Immutable backup | Backup yang tidak bisa diubah atau dihapus sampai masa kuncinya habis | Fotokopi yang disimpan di kotak bertimer, tidak bisa dibuka sebelum waktunya |

### 1.1 Governance dan GRC

Pertanyaan pertama Nina terdengar seperti urusan birokrasi, tetapi jawabannya menjelaskan kenapa alert `SOC-2027-0895` tidak berhenti di tim Infrastruktur. Backup bukan sekadar tugas teknis; ia adalah cara perusahaan memenuhi janji yang diputuskan pimpinan: data penting harus bisa dipulihkan dalam waktu tertentu.

**Apa itu:** governance (tata kelola) keamanan adalah cara pimpinan organisasi menetapkan strategi, harapan, dan kebijakan keamanan, mengomunikasikannya, lalu mengawasi pelaksanaannya. NIST CSF 2.0 merumuskan fungsi Govern persis seperti itu: strategi, ekspektasi, dan kebijakan manajemen risiko keamanan siber ditetapkan, dikomunikasikan, dan dipantau [S8]. Govern mencakup pemahaman konteks organisasi (misi, pemangku kepentingan, kewajiban hukum dan kontrak), strategi manajemen risiko, peran dan wewenang, kebijakan, pengawasan, dan risiko rantai pasok [S8]. NIST juga menekankan bahwa governance memasukkan keamanan siber ke manajemen risiko perusahaan secara keseluruhan (enterprise risk management), sejajar dengan risiko keuangan dan reputasi [S8].

GRC adalah singkatan yang mengikat tiga kegiatan: governance (siapa memutuskan dan ke mana arahnya), risk management (risiko mana yang ditangani lebih dulu dan bagaimana), dan compliance (kewajiban apa yang harus dipenuhi dan bagaimana membuktikannya). Ketiganya dipisah di nama, tetapi dikerjakan bersama: kebijakan dibuat berdasarkan risiko dan kewajiban, dan kepatuhan pada kebijakan itu diperiksa lewat audit.

**Analogi:** aturan rumah tangga yang ditetapkan kepala keluarga. Kepala keluarga memutuskan bahwa rumah harus aman, menunjuk siapa yang memegang kunci, siapa yang membayar asuransi, dan sesekali memeriksa apakah anak-anak benar-benar mengunci pintu. Ia tidak memasang kunci sendiri, tetapi ia yang menentukan bahwa kunci harus ada dan siapa yang bertanggung jawab. Batasnya: di organisasi, "kepala keluarga" adalah direksi dan komite, keputusannya harus tertulis dan bisa ditelusuri, dan pimpinan ikut bertanggung jawab secara hukum bila kewajiban dilanggar.

**Cara kerja:** governance berjalan sebagai lingkaran: pimpinan menetapkan arah, peran dan wewenang dibagi, kebijakan ditulis, tim menjalankan control, pelaksanaan dipantau, lalu hasil dan audit dilaporkan kembali ke pimpinan. Auditor biasanya memeriksa empat hal: kebijakan yang disetujui pimpinan, peran yang jelas (pemilik risiko, pemilik sistem, pelaksana control), sumber daya yang sepadan dengan risiko, dan pengawasan berkala atas hasil manajemen risiko [S8].

**Contoh di PT JAB:** struktur governance keamanan PT JAB per Agustus 2027 bisa dibaca di tabel berikut; cari kolom Peran saat kamu ragu ke siapa sebuah keputusan harus dibawa.

| Pihak | Peran dalam GRC |
|---|---|
| Direksi | Menyetujui Kebijakan Keamanan Informasi dan pernyataan risk appetite |
| Komite Keamanan Informasi (diketuai Hendra Wijaya, Direktur Teknologi) | Rapat bulanan; meninjau risk register, menyetujui penerimaan risiko tingkat Tinggi |
| Nina Kartika, Manajer Risiko dan Kepatuhan TI | Menjaga risk register, menyusun kebijakan dan standar, mengoordinasi audit |
| Agus Setiawan, DPO | Menilai dan memutuskan kewajiban pelindungan data pribadi, termasuk pemberitahuan |
| Tim Infrastruktur (Agung Prabowo, Fajar Nugroho) | Pemilik dan pelaksana control teknis seperti backup |
| SOC (Dimas Prasetyo, Sari Kusuma, kamu) | Memantau control, mendeteksi kegagalan, menyediakan bukti |
| Audit Internal (melapor ke Komite Audit) | Memeriksa secara independen bahwa semua di atas berjalan |

Backup sampai ke meja Nina karena Kebijakan Backup dan Pemulihan disetujui direksi, targetnya berasal dari analisis dampak bisnis, dan control backup (ISO/IEC 27001 Annex A 8.13) masuk cakupan sertifikasi. Dua malam backup gagal tanpa diketahui pemiliknya adalah pertanyaan governance: siapa yang seharusnya melihat peringatan kapasitas, dan kenapa peringatan itu tidak sampai (bagian 2.1).

**Beda governance dengan management:** governance memutuskan arah dan mengawasi ("data penting harus bisa dipulihkan dalam 24 jam; laporkan tiap bulan"). Management menjalankan dan mengatur sehari-hari ("job backup jalan pukul 22:00, kapasitas ditambah bila penuh"). Governance tanpa management menghasilkan dokumen tanpa pelaksanaan; management tanpa governance menghasilkan pekerjaan teknis tanpa prioritas yang jelas.

**Salah paham umum:**
- "GRC adalah urusan tim kepatuhan, bukan SOC." Kenyataannya, SOC adalah salah satu penghasil bukti terbesar untuk GRC: alert, tiket, dan laporan bulanan SOC menunjukkan bahwa control detective benar-benar berjalan.

### 1.2 Risk management: risk register, risk treatment, risk appetite

Pertanyaan kedua Nina menyangkut tempat dan cara risiko diputuskan. Di Day 01 bagian 1.4, risk didefinisikan sebagai gabungan likelihood (seberapa mungkin terjadi) dan impact (seberapa besar kerugiannya), dan Nina menilai tiga risiko portal R1 sampai R3 dengan tabel 3x3 (Day 01 bagian 2.2). Day ini melanjutkan ceritanya: setelah dinilai, risiko itu dicatat di mana, siapa yang memutuskan, dan bagaimana keputusannya diikuti.

**Apa itu:**
- **Risk register** adalah tempat penyimpanan informasi risiko, termasuk perkembangan pemahaman tentang risiko itu dari waktu ke waktu [S15]. NIST juga menyebutnya catatan pusat risiko yang ada saat ini untuk satu lingkup atau organisasi, termasuk risiko yang diterima dan risiko yang sedang dimitigasi [S15]. Kolom yang umum: ID, deskripsi risiko, aset, pemilik risiko, likelihood, impact, tingkat risiko, keputusan, rencana tindakan, tenggat, risiko sisa (residual risk), dan tanggal tinjau berikutnya.
- **Risk treatment** (NIST menyebutnya risk response) adalah keputusan sadar atas risiko yang sudah dikenali: menerima (accept), menghindari (avoid), menurunkan (mitigate), atau membagi dan memindahkan ke pihak lain (share atau transfer) [S15].
- **Risk appetite** adalah jenis dan jumlah risiko yang secara umum mau diterima organisasi dalam mengejar tujuannya [S15]. **Risk tolerance** lebih sempit: tingkat risiko atau ketidakpastian yang masih bisa diterima untuk satu tujuan atau satu keadaan tertentu [S15]. NIST CSF 2.0 meminta pernyataan risk appetite dan risk tolerance ditetapkan, dikomunikasikan, dan dirawat sebagai bagian dari Govern [S8].

**Analogi:** buku catatan keluarga berisi daftar kekhawatiran. Untuk banjir, keluarga memutuskan meninggikan lantai (mitigate). Untuk kebakaran, keluarga membeli asuransi (transfer). Untuk kompor minyak tanah tua yang sering bocor, keluarga berhenti memakainya (avoid). Untuk genteng yang sesekali bocor sedikit, keluarga memutuskan menunggu renovasi tahun depan (accept). Risk appetite adalah watak keluarga itu: keluarga yang punya bayi tidak mau menanggung risiko kebakaran sekecil apa pun, tetapi mau menerima genteng bocor sedikit. Batasnya: di organisasi, setiap keputusan harus diambil orang yang berwenang, dicatat dengan alasannya, dan ditinjau ulang; "pasrah" tanpa catatan bukan accept, melainkan kelalaian.

**Cara kerja:** risiko dikenali (dari alert, audit, insiden, atau perubahan sistem), dinilai dengan tabel likelihood dan impact yang disepakati, lalu dibandingkan dengan risk appetite. Bila masih dalam batas, risiko boleh diterima; bila tidak, dipilih treatment. Keputusan, pemilik, tenggat, dan residual risk dicatat di risk register, lalu ditinjau berkala atau saat keadaan berubah.

Empat pilihan treatment dibedakan seperti ini; cari kolom Contoh PT JAB untuk melihat bahwa keempatnya dipakai sungguhan.

| Treatment | Artinya | Contoh PT JAB |
|---|---|---|
| Mitigate | Menambah atau memperkuat control supaya likelihood atau impact turun | R1: OTP wajib untuk perubahan paket dan data pribadi |
| Transfer (share) | Memindahkan sebagian akibat finansial ke pihak lain lewat kontrak atau asuransi | Polis asuransi siber 2027 menanggung biaya forensik dan pemberitahuan pelanggan |
| Avoid | Menghentikan kegiatan yang menimbulkan risiko | R6: fitur unggah foto KTP di portal dihentikan; verifikasi dilakukan di gerai |
| Accept | Sengaja tidak menambah control, dengan persetujuan tertulis dan tanggal tinjau | R3: portal satu server, diterima sampai server kedua masuk anggaran 2028 |

Transfer hanya memindahkan akibat finansial, bukan tanggung jawab hukum: asuransi bisa membayar biaya pemberitahuan, tetapi kewajiban memberi tahu tetap di PT JAB. Setelah treatment selalu ada residual risk (risiko sisa), dan residual itulah yang dibandingkan lagi dengan risk appetite.

**Contoh di PT JAB:** pernyataan risk appetite PT JAB yang disetujui direksi pada Januari 2027 berbunyi ringkas: appetite rendah untuk risiko terhadap data pribadi pelanggan dan kepatuhan hukum; appetite sedang untuk gangguan sistem internal yang tidak langsung dirasakan pelanggan; risiko tingkat Tinggi di area appetite rendah wajib dimitigasi, dan penerimaannya hanya boleh disetujui Komite Keamanan Informasi. Risk tolerance turunannya untuk backup: file server boleh kehilangan data maksimal 24 jam (ini menjadi RPO di bagian 1.9). Alert `SOC-2027-0895` memicu risiko baru R4 di risk register, yang dibahas di bagian 2.2.

**Beda risk appetite dengan risk tolerance:** appetite adalah sikap umum ("kami tidak suka risiko terhadap data pelanggan"), tolerance adalah angka atau batas untuk satu hal ("data file server boleh hilang maksimal 24 jam"). Appetite ditetapkan direksi; tolerance diturunkan pemilik proses agar appetite bisa diukur.

**Salah paham umum:**
- "Accept berarti tidak melakukan apa-apa." Accept yang sah tetap punya pemilik, alasan, persetujuan, dan tanggal tinjau. Risiko yang tidak pernah dibahas tidak "diterima"; risiko itu hanya tidak diketahui.

### 1.3 Compliance, framework, dan regulasi

Pertanyaan ketiga Nina ("kita wajib patuh pada apa saja") membedakan dua jenis aturan yang sering disebut bersamaan di rapat: aturan yang wajib karena hukum, dan aturan yang dipilih sendiri karena berguna.

**Apa itu:** compliance (kepatuhan) adalah keadaan ketika organisasi memenuhi kewajiban yang berlaku baginya dan bisa membuktikannya. Kewajiban itu datang dari tiga sumber: hukum dan peraturan (misalnya UU PDP), kontrak dan perjanjian (misalnya syarat dari pelanggan korporat atau mitra pembayaran), serta aturan internal organisasi sendiri (kebijakan dan standar). NIST CSF 2.0 memasukkan pemahaman dan pengelolaan kewajiban hukum, regulasi, dan kontrak, termasuk kewajiban privasi, ke fungsi Govern [S8].

Dua istilah yang harus dipisahkan:
- **Regulasi** adalah aturan hukum yang mengikat dan punya sanksi. Organisasi tidak memilih untuk mematuhinya; ia wajib. Contoh: UU No. 27 Tahun 2022 tentang Pelindungan Data Pribadi (bagian 1.6).
- **Control framework** adalah kerangka panduan yang disusun lembaga standar atau pemerintah untuk membantu organisasi menyusun program keamanan. Framework umumnya sukarela. NIST CSF 2.0 bahkan menyatakan dirinya tidak menetapkan bagaimana hasil (outcome) harus dicapai; ia memberi daftar hasil dan menautkan ke panduan lain [S8]. ISO/IEC 27001 adalah standar persyaratan yang bisa disertifikasi; standar ini sukarela, tetapi bisa menjadi wajib secara tidak langsung bila diminta kontrak atau pelanggan (bagian 1.5).

**Analogi:** peraturan RT dan syarat asuransi wajib dipatuhi; bila dilanggar, ada teguran atau klaim ditolak. Buku panduan rumah aman dari dinas pemadam kebakaran tidak wajib, tetapi sangat membantu memenuhi peraturan dan syarat itu. Batasnya: di dunia nyata, sebuah framework bisa menjadi wajib karena dirujuk kontrak atau peraturan sektor, jadi status "sukarela" harus dicek per organisasi.

**Cara kerja:** kepatuhan dikelola dengan memetakan setiap kewajiban ke control dan buktinya. Contoh: kewajiban UU PDP Pasal 46 (beri tahu dalam 3 x 24 jam) dipenuhi lewat prosedur pemberitahuan insiden data pribadi, dibuktikan dengan tiket dan catatan waktu, lalu diperiksa audit internal, auditor eksternal, atau regulator. Satu control yang baik sering memenuhi beberapa kewajiban sekaligus. Backup yang terenkripsi dan teruji menopang kewajiban keamanan UU PDP, persyaratan ISO/IEC 27001, dan hasil PR.DS-11 di NIST CSF ("backup dibuat, dilindungi, dirawat, dan diuji") [S8].

**Contoh di PT JAB:** daftar kewajiban (compliance register) yang dijaga Nina memuat, antara lain: UU PDP dan peraturan pelaksananya; persyaratan ISO/IEC 27001 untuk lingkup yang disertifikasi; kontrak dengan pelanggan korporat yang mewajibkan pemberitahuan insiden dalam waktu tertentu; dan Kebijakan Keamanan Informasi PT JAB sendiri. NIST CSF 2.0 tidak ada di daftar itu sebagai kewajiban; CSF dipakai sebagai bahasa laporan ke Komite (bagian 1.5).

**Beda compliance dengan security:** compliance menjawab "apakah kewajiban terpenuhi dan terbukti", security menjawab "apakah kita benar-benar terlindungi dari ancaman yang nyata". Organisasi bisa patuh di atas kertas tetapi tetap mudah dibobol, misalnya punya prosedur backup yang rapi tetapi backup-nya tidak pernah diuji. Sebaliknya, keamanan yang baik tanpa bukti tertulis tetap dinilai tidak patuh oleh auditor.

### 1.4 Policy, standard, procedure, guideline

Pertanyaan keempat Nina menguji apakah kamu bisa menunjuk dokumen yang dilanggar. Ini penting karena tindak lanjutnya berbeda: pelanggaran policy dibawa ke pimpinan, pelanggaran procedure cukup diperbaiki di tim.

**Apa itu:** NIST menjelaskan bahwa kebijakan keamanan informasi adalah kumpulan arahan, aturan, dan praktik yang menentukan bagaimana organisasi mengelola, melindungi, dan membagikan informasinya [S12]. Karena policy ditulis di tingkat umum, organisasi menurunkannya ke dokumen yang lebih rinci [S12]:
- **Policy** menyatakan apa yang wajib dan kenapa, di tingkat tinggi, dan disetujui pimpinan. Policy jarang berubah.
- **Standard** (standar organisasi, bukan standar nasional atau internasional) menetapkan pemakaian teknologi, parameter, atau prosedur tertentu secara seragam; standar biasanya wajib di dalam organisasi [S12].
- **Procedure** adalah langkah yang lebih rinci untuk menyelesaikan tugas keamanan tertentu [S12].
- **Guideline** membantu pengguna dan staf mengamankan sistem, dengan kesadaran bahwa sistem berbeda-beda dan standar tidak selalu bisa dipaksakan; guideline bisa dijalankan dengan benar lewat lebih dari satu cara [S12].

**Analogi:** rumah tangga yang sama. Policy: "rumah harus dikunci saat kosong." Standard: "kunci yang dipakai wajib kunci dua putaran merek tertentu, dan jendela wajib bergrendel." Procedure: "sebelum pergi, tutup jendela belakang, pasang grendel, kunci pintu samping, kunci pintu depan dua putaran, lalu coba tarik gagangnya." Guideline: "sebaiknya titipkan kunci cadangan ke tetangga yang dipercaya." Batasnya: di organisasi, setiap dokumen punya pemilik, nomor versi, tanggal tinjau, dan pihak yang menyetujui; dokumen tanpa pemilik cepat usang.

**Cara kerja:** dokumen tersusun seperti piramida; semakin ke bawah semakin rinci, semakin sering berubah, dan semakin dekat ke pelaksana.

```
          POLICY          wajib, umum, disetujui direksi        "apa dan kenapa"
        STANDARD          wajib, rinci, seragam                 "dengan apa, berapa"
      PROCEDURE           wajib diikuti pelaksana               "langkah-langkahnya"
    GUIDELINE             anjuran, fleksibel                    "saran cara baik"
```

**Contoh di PT JAB:** dokumen backup PT JAB tersusun seperti tabel berikut; cari kolom Contoh isi untuk melihat bedanya tingkat kerincian.

| Jenis | Dokumen PT JAB | Contoh isi | Pemilik |
|---|---|---|---|
| Policy | Kebijakan Backup dan Pemulihan (bagian dari Kebijakan Keamanan Informasi) | Data dan sistem penting wajib di-backup dan bisa dipulihkan sesuai target hasil BIA | Direksi, dirawat Nina |
| Standard | STD-BKP-01 Standar Backup | Aturan 3-2-1 dengan satu salinan immutable dan satu offline; retensi dan masa kunci immutable 30 hari; dua kegagalan beruntun memicu alert ke SOC | Agung Prabowo |
| Procedure | PRO-BKP-03 Penanganan job backup gagal | Cek penyebab, perbaiki, jalankan ulang manual, catat di tiket; penghapusan restore point hanya lewat change request dengan persetujuan orang kedua | Agung Prabowo |
| Guideline | Panduan penyimpanan file kerja | Simpan dokumen kerja di share `JKT-FS01`, bukan di desktop laptop, supaya ikut ter-backup | Nina |

Jawaban untuk Nina: `SOC-2027-0895` menunjukkan target di standard STD-BKP-01 tidak tercapai (backup gagal dua malam, RPO terlewati), dan `SOC-2027-0896` adalah pelanggaran procedure PRO-BKP-03 (penghapusan restore point tanpa change request). Policy-nya sendiri tidak salah; yang gagal adalah pelaksanaannya.

**Beda standard organisasi dengan standar internasional:** kata "standard" dipakai untuk dua hal. STD-BKP-01 adalah standar internal PT JAB. ISO/IEC 27001 adalah standar internasional yang diterbitkan ISO dan IEC. NIST secara khusus mengingatkan agar keduanya tidak tertukar [S12].

### 1.5 Framework: NIST CSF 2.0 dan ISO/IEC 27001

Pertanyaan kelima Nina ("kenapa kita bicara NIST CSF di rapat komite tetapi disertifikasi ISO 27001") bisa dijawab dengan melihat fungsi keduanya: yang satu peta untuk berdiskusi, yang lain persyaratan untuk diperiksa.

**Apa itu:**
- **NIST Cybersecurity Framework (CSF) 2.0** adalah panduan dari NIST, lembaga standar Amerika Serikat, yang memberi taksonomi hasil keamanan siber tingkat tinggi yang bisa dipakai organisasi apa pun, apa pun ukuran, sektor, dan kematangannya [S8]. CSF tidak menetapkan cara mencapai hasil itu [S8]. Intinya (Core) disusun dalam enam fungsi: Govern, Identify, Protect, Detect, Respond, Recover, lalu dipecah menjadi Category dan Subcategory [S8]. CSF juga punya Profile (Current Profile untuk keadaan sekarang, Target Profile untuk keadaan yang diinginkan) dan empat Tier (Partial, Risk Informed, Repeatable, Adaptive) untuk menggambarkan kematangan cara organisasi mengelola risiko [S8].
- **ISO/IEC 27001:2022** adalah standar internasional berisi persyaratan untuk membangun, menjalankan, merawat, dan terus memperbaiki ISMS (information security management system), yaitu sistem manajemen yang memakai proses manajemen risiko untuk menjaga confidentiality, integrity, dan availability informasi [S9]. Persyaratan wajibnya ada di klausul 4 sampai 10 (konteks, kepemimpinan, perencanaan, dukungan, operasi, evaluasi kinerja, perbaikan). Annex A memuat 93 control acuan dalam empat tema: organizational (37), people (8), physical (14), dan technological (34) [S10]. Organisasi memilih control berdasarkan penilaian risikonya dan mencatat pilihan serta alasannya di Statement of Applicability (SoA) [S10]. Organisasi bisa disertifikasi oleh lembaga sertifikasi yang terakreditasi.

**Analogi:** CSF seperti buku panduan rumah aman dari dinas pemadam kebakaran: semua keluarga boleh memakainya, isinya daftar hal yang sebaiknya tercapai (rumah punya alat pemadam, jalur evakuasi jelas), tanpa mengatur merek alatnya. ISO/IEC 27001 seperti sertifikat "rumah aman" dari lembaga penilai: ada syarat yang harus dipenuhi, ada pemeriksa yang datang, dan ada sertifikat yang bisa ditunjukkan ke pihak lain. Batasnya: sertifikat ISO tidak berarti rumah tidak bisa kemalingan; ia berarti ada sistem yang rutin menilai risiko, memasang pengaman, memeriksa, dan memperbaiki.

**Cara kerja:** enam fungsi CSF 2.0 membentuk siklus, dengan Govern di tengah. Tabel berikut meringkas pertanyaan setiap fungsi; cari kolom Contoh PT JAB untuk melihat di mana pekerjaan SOC berada.

| Fungsi CSF 2.0 | Hasil yang dituju [S8] | Contoh PT JAB |
|---|---|---|
| Govern (GV) | Strategi, ekspektasi, dan kebijakan risiko ditetapkan, dikomunikasikan, dipantau | Kebijakan, risk appetite, Komite Keamanan Informasi |
| Identify (ID) | Risiko keamanan siber saat ini dipahami | Inventaris aset, risk register R1 sampai R6 |
| Protect (PR) | Pengaman untuk mengelola risiko dipakai | MFA, patch, backup (PR.DS-11) |
| Detect (DE) | Kemungkinan serangan dan kompromi ditemukan dan dianalisis | SOC, SIEM, alert `SOC-2027-0895` dan `0896` |
| Respond (RS) | Tindakan atas insiden yang terdeteksi diambil | Penanganan insiden (dibahas di Day 19) |
| Recover (RC) | Aset dan operasi yang terdampak dipulihkan | DRP, restore dari backup; integritas backup dicek sebelum dipakai (RC.RP-03) |

ISO/IEC 27001 bekerja sebagai siklus manajemen: tetapkan konteks dan lingkup, nilai risiko, pilih control (Annex A dan SoA), jalankan, ukur, audit internal, tinjau oleh manajemen, lalu perbaiki. Control Annex A yang relevan untuk Day ini dipetakan ke bukti audit di bagian 2.4 [S10].

**Contoh di PT JAB:** PT JAB disertifikasi ISO/IEC 27001 sejak September 2025 untuk lingkup operasi data center Jakarta, NOC, dan SOC. Sertifikat itulah yang diminta pelanggan korporat dan mitra. Di rapat Komite Keamanan Informasi, Nina melaporkan kemajuan dengan enam fungsi CSF karena lebih mudah dipahami direksi: "Detect kita sudah di Tier 3, Recover masih Tier 2 karena uji DRP tahun lalu gagal memenuhi RTO portal." Satu organisasi memakai keduanya: ISO untuk sertifikasi dan sistem manajemen, CSF untuk bahasa komunikasi dan peta kematangan.

**Beda framework dengan standar sertifikasi:** CSF tidak punya skema sertifikasi resmi dan tidak memberi tahu cara mencapainya; ISO/IEC 27001 punya persyaratan yang dinilai pihak ketiga. Keduanya tetap sukarela, berbeda dengan UU PDP yang wajib.

**Salah paham umum:**
- "Organisasi bersertifikat ISO 27001 harus memasang semua 93 control Annex A." Control dipilih berdasarkan risiko; control yang tidak dipakai boleh dikecualikan asalkan alasannya tercatat di SoA [S10].
- "CSF 2.0 hanya untuk infrastruktur kritis di Amerika." Versi 2.0 ditujukan untuk organisasi di semua sektor dan ukuran [S8].

### 1.6 Regulasi: UU Pelindungan Data Pribadi

Pertanyaan keenam dijawab Agus, dengan peringatan: "Saya jelaskan dasarnya supaya kalian tahu kapan memanggil saya. Keputusannya tetap di saya dan tim hukum."

**Apa itu:** UU No. 27 Tahun 2022 tentang Pelindungan Data Pribadi (UU PDP) ditetapkan, diundangkan, dan berlaku pada 17 Oktober 2022 (LN 2022 No. 196) [S1]. Undang-undang ini mengatur, antara lain, jenis data pribadi, hak subjek data, kewajiban pengendali dan prosesor, transfer data ke luar negeri, sanksi administratif, kelembagaan, dan ketentuan pidana [S1]. Istilah kuncinya:
- **Data pribadi** adalah data tentang orang perseorangan yang teridentifikasi atau dapat diidentifikasi, sendiri atau digabung dengan informasi lain, langsung atau tidak langsung [S1][S2].
- **Pengendali data pribadi** adalah pihak yang, sendiri atau bersama-sama, menentukan tujuan dan melakukan kendali pemrosesan data pribadi [S2]. Untuk data pelanggan, PT JAB adalah pengendali.
- **Prosesor data pribadi** adalah pihak yang memproses data atas nama pengendali, misalnya penyedia cloud atau vendor pengiriman SMS.
- **Subjek data pribadi** adalah orang yang datanya diproses, misalnya pelanggan.
- **Lembaga** adalah otoritas penyelenggara pelindungan data pribadi yang ditetapkan Presiden. Statusnya dibahas di bawah.

**Analogi:** kamu dititipi barang berharga oleh tetangga. Kamu wajib menjaganya, hanya memakainya untuk keperluan yang disepakati, dan bila barang itu hilang, rusak, atau dibuka orang lain, kamu wajib segera memberi tahu pemiliknya dan pengurus lingkungan, lengkap dengan apa yang hilang, kapan, dan apa yang sudah kamu lakukan. Batasnya: di UU PDP ada batas waktu tertulis, isi pemberitahuan yang ditentukan, sanksi administratif dan pidana, dan "barang titipan" itu bisa berjumlah ratusan ribu orang sekaligus.

**Cara kerja:** bagian yang paling sering bersentuhan dengan SOC adalah kewajiban saat terjadi kegagalan pelindungan.

1. **Apa yang dihitung sebagai kegagalan.** Penjelasan Pasal 46 ayat (1) mengartikan kegagalan pelindungan data pribadi sebagai kegagalan melindungi data pribadi dalam hal kerahasiaan, integritas, dan ketersediaan, termasuk pelanggaran keamanan yang disengaja maupun tidak yang menyebabkan perusakan, kehilangan, perubahan, pengungkapan, atau akses tanpa izin [S3]. Jadi bukan hanya kebocoran (confidentiality); data pribadi yang terkunci ransomware tanpa backup yang bisa dipakai (availability) juga termasuk.
2. **Tenggat dan penerima.** Pengendali wajib menyampaikan pemberitahuan tertulis paling lambat 3 x 24 jam kepada subjek data pribadi dan kepada Lembaga [S2].
3. **Isi minimal.** Data pribadi yang terungkap; kapan dan bagaimana data itu terungkap; serta upaya penanganan dan pemulihannya [S2].
4. **Pemberitahuan ke masyarakat.** Dalam hal tertentu, pengendali juga wajib memberi tahu masyarakat [S2]; penjelasannya menyebut contoh kegagalan yang mengganggu pelayanan publik atau berdampak serius terhadap kepentingan masyarakat [S3].
5. **Kapan jam mulai dihitung.** Teks Pasal 46 tidak menyebut titik awal hitungan. PP No. 33 Tahun 2026, menurut ulasan atas teksnya, menghitung 3 x 24 jam sejak kegagalan diketahui secara pasti, patut, dan wajar, serta menambahkan informasi narahubung atau PPDP ke isi pemberitahuan [S6]. Karena itu kecepatan SOC memastikan fakta (data apa, berapa orang, kapan) langsung menentukan sisa waktu DPO.

Kewajiban lain yang perlu dikenal analyst:
- **DPO (PPDP).** Pengendali dan prosesor wajib menunjuk pejabat atau petugas pelindungan data pribadi antara lain bila kegiatan intinya memantau data pribadi secara teratur dan sistematis dalam skala besar, atau memproses data pribadi spesifik dalam skala besar; petugasnya boleh dari dalam atau luar organisasi [S2]. PT JAB, dengan 400 ribu pelanggan, menunjuk Agus.
- **Masa penyesuaian.** Pengendali, prosesor, dan pihak lain diberi waktu paling lama dua tahun sejak UU diundangkan untuk menyesuaikan diri [S2], sehingga masa transisi berakhir 17 Oktober 2024.
- **Sanksi administratif.** Berupa peringatan tertulis, penghentian sementara pemrosesan, penghapusan atau pemusnahan data pribadi, dan/atau denda administratif paling tinggi 2 persen dari pendapatan atau penerimaan tahunan terhadap variabel pelanggaran [S2].
- **Sanksi pidana.** Misalnya, memperoleh atau mengumpulkan data pribadi milik orang lain secara melawan hukum untuk menguntungkan diri sendiri diancam pidana penjara paling lama 5 tahun dan/atau denda paling banyak Rp5 miliar; bila pelakunya korporasi, pidananya berupa denda sampai 10 kali maksimal denda yang diancamkan, ditambah kemungkinan pidana tambahan seperti pembekuan usaha [S2].

**Status peraturan pelaksana dan Lembaga (per 21 Oktober 2026):** PP No. 33 Tahun 2026 sebagai peraturan pelaksana UU PDP ditetapkan 16 Juli 2026 dan berlaku 16 Januari 2027, menurut pemberitaan; PP ini mengatur antara lain pemberitahuan kegagalan pelindungan, PPDP, dan sanksi administratif sampai 2 persen pendapatan tahunan [S4][S5][S6]. Lembaga pengawas PDP belum terbentuk; selama itu fungsi pengawasan dijalankan Direktorat Jenderal Pengawasan Ruang Digital Kementerian Komunikasi dan Digital [S7]. Rincian dan hal yang perlu dicek ada di bagian 5.

**Contoh di PT JAB:** Agus memakai dua insiden bulan ini sebagai contoh. Pada `INC-2027-080` (Day 01 bagian 2.1), tiga akun pelanggan portal diambil alih lewat password bocor, sehingga data tiga orang mungkin sudah dilihat pihak lain. Pada `INC-2027-087` (Day 08 bagian 2.2), data 1.250 peserta kampanye (nama, nomor HP, paket langganan) terbuka publik di bucket cloud selama hampir 20 jam. Keduanya memenuhi arti kegagalan pelindungan karena kerahasiaan data pribadi tidak terjaga. Perhitungan tenggat `INC-2027-087` ada di bagian 2.3.

Untuk alert hari ini, Agus menjawab: "Backup yang gagal belum tentu kegagalan pelindungan data pribadi, karena datanya masih ada di file server. Tetapi kalau malam ini `JKT-FS01` kena ransomware dan data pelanggan di dalamnya tidak bisa dipulihkan, itu kegagalan dari sisi ketersediaan, dan jam 3 x 24 saya mulai berjalan. Jadi backup yang sehat juga control kepatuhan."

**Beda pengendali dengan prosesor:** pengendali memutuskan untuk apa dan bagaimana data dipakai, dan memikul kewajiban pemberitahuan kepada subjek data. Prosesor bekerja atas perintah pengendali; menurut ulasan atas PP 33/2026, prosesor wajib memberi tahu pengendali pada kesempatan pertama bila terjadi kegagalan [S6]. Bila vendor cloud PT JAB bocor, PT JAB tetap yang memberi tahu pelanggannya.

**Salah paham umum:**
- "Selama lembaganya belum ada, UU PDP belum berlaku." UU PDP berlaku sejak 17 Oktober 2022 dan masa penyesuaiannya sudah berakhir 17 Oktober 2024 [S1][S2]. Yang belum lengkap adalah lembaga pengawasnya, bukan kewajibannya.

### 1.7 Audit: internal dan external

Pertanyaan ketujuh Nina menyangkut auditor yang akan datang tiga minggu lagi. Untuk analyst, audit sering terasa seperti ujian mendadak; sebenarnya audit hanya meminta satu hal yang seharusnya selalu ada: bukti.

**Apa itu:** audit sistem adalah tinjauan dan pemeriksaan independen atas catatan dan kegiatan untuk menilai kecukupan control dan memastikan kepatuhan pada kebijakan dan prosedur yang ditetapkan [S12]. Auditor bertugas memeriksa apakah sistem memenuhi persyaratan keamanan dan kebijakan organisasi, dan apakah control-nya memadai [S12]. NIST memisahkan audit dari monitoring: memeriksa log setiap hari untuk mencari akses tanpa izin adalah monitoring, sedangkan menelusuri catatan beberapa bulan ke belakang adalah audit [S12].

- **Internal audit** dilakukan oleh fungsi di dalam organisasi yang independen dari yang diaudit, misalnya unit Audit Internal yang melapor ke Komite Audit. Tujuannya menemukan masalah lebih dulu dan memberi masukan perbaikan. ISO/IEC 27001 mewajibkan audit internal ISMS secara terencana.
- **External audit** dilakukan pihak di luar organisasi. Untuk ISO/IEC 27001, auditornya berasal dari lembaga sertifikasi (certification body) yang terakreditasi. Sertifikasinya memakai siklus tiga tahun yang wajib tercantum di sertifikat [S11]. Di antara sertifikasi dan sertifikasi ulang, lembaga sertifikasi melakukan **surveillance audit** sekali setiap tahun kalender, kecuali di tahun sertifikasi ulang [S11]. Audit oleh regulator atau pelanggan korporat juga termasuk external audit.

Hasil audit berupa temuan. **Nonconformity** adalah temuan bahwa sebuah persyaratan tidak terpenuhi; auditor ISO membaginya menjadi major (kegagalan sistemik) dan minor (kekurangan terbatas).

**Analogi:** pemeriksaan oleh pengurus RT atau petugas asuransi. Pengurus RT datang memeriksa apakah setiap rumah punya alat pemadam sesuai kesepakatan warga; petugas asuransi memeriksa apakah syarat polis dipenuhi sebelum polis diperpanjang. Anggota keluarga yang memeriksa rumah sendiri sebelum petugas datang adalah audit internal. Batasnya: auditor tidak memeriksa semua hal; ia mengambil sampel, dan ia menilai bukti, bukan janji. "Kami selalu mengunci pintu" tanpa catatan tidak dihitung.

**Cara kerja:** auditor membandingkan tiga lapis untuk setiap control yang diperiksa.

```
TERTULIS?      ada policy, standard, procedure yang berlaku dan disetujui?
   |
DIJALANKAN?    ada bukti pelaksanaan (log, tiket, laporan) sesuai dokumen?
   |
EFEKTIF?       hasilnya mencapai tujuan (backup benar-benar bisa dipulihkan)?
```

Satu temuan biasanya ditulis dengan tiga unsur: kondisi (apa yang ditemukan), kriteria (persyaratan mana yang dilanggar), dan bukti (dokumen atau catatan yang dilihat).

**Contoh di PT JAB:** sertifikasi ISO/IEC 27001 PT JAB diterbitkan September 2025, surveillance pertama September 2026, surveillance kedua dijadwalkan Selasa-Rabu 2027-09-14 sampai 2027-09-15, dan sertifikasi ulang pada 2028. Surveillance 2026 meninggalkan satu minor nonconformity: uji DRP September 2026 gagal memenuhi RTO portal, dan tindak lanjutnya belum ditutup saat audit. Audit Internal PT JAB memeriksa proses backup pada Juli 2027 dan mencatat bahwa peringatan kapasitas penyimpanan dikirim ke kotak surat milik karyawan yang sudah keluar; tindak lanjutnya belum selesai ketika `SOC-2027-0895` muncul. Bukti apa yang disiapkan SOC ada di bagian 2.4.

**Beda internal audit dengan external audit:** tabel berikut merangkumnya; cari kolom Siapa yang membaca hasil untuk memahami kenapa sikap terhadap keduanya berbeda.

| Aspek | Internal audit | External audit (surveillance ISO) |
|---|---|---|
| Pelaksana | Unit di dalam organisasi, independen dari yang diaudit | Auditor lembaga sertifikasi |
| Tujuan | Menemukan dan memperbaiki lebih dulu | Memutuskan apakah sertifikat dipertahankan |
| Jadwal | Sesuai program audit internal | Sekali setiap tahun kalender [S11] |
| Siapa yang membaca hasil | Manajemen dan Komite Audit | Lembaga sertifikasi; sertifikat dilihat pelanggan dan mitra |
| Akibat temuan | Rencana perbaikan internal | Temuan major yang tidak ditutup bisa membuat sertifikat dibekukan atau dicabut |

**Salah paham umum:**
- "Saat audit, sembunyikan masalah supaya tidak jadi temuan." Masalah yang sudah diketahui, tercatat di risk register, dan punya rencana perbaikan biasanya dinilai jauh lebih baik daripada masalah yang ditemukan sendiri oleh auditor. Menyembunyikan bukti merusak kepercayaan dan bisa mengubah temuan minor menjadi major.

### 1.8 BCP dan DRP

Pertanyaan kedelapan Nina menyangkut uji yang akan dijalankan sebelum audit. Kedua istilah ini sering dipakai bergantian, padahal yang satu bicara tentang bisnis dan yang lain tentang sistem.

**Apa itu:**
- **BCP (business continuity plan)** adalah sekumpulan instruksi atau prosedur yang sudah ditetapkan sebelumnya, yang menjelaskan bagaimana proses bisnis organisasi tetap berjalan selama dan setelah gangguan besar [S14]. BCP berfokus pada proses bisnis, misalnya proses penggajian atau layanan pelanggan, dan bisa mencakup satu unit atau seluruh organisasi [S13].
- **DRP (disaster recovery plan)** menurut NIST adalah rencana tertulis untuk memulihkan satu atau lebih sistem informasi di fasilitas alternatif setelah kerusakan besar perangkat keras atau perangkat lunak atau hancurnya fasilitas [S14]. DRP berfokus pada sistem TI dan, dalam pengertian NIST, khusus untuk gangguan yang memaksa pemindahan ke lokasi lain; DRP mendukung BCP dengan memulihkan sistem yang dibutuhkan proses bisnis [S13]. Di banyak organisasi, istilah DRP dipakai lebih longgar untuk semua rencana pemulihan TI, termasuk pemulihan di lokasi yang sama.
- **BIA (business impact analysis)** adalah dasar keduanya. NIST menjabarkannya dalam tiga langkah: tentukan proses bisnis dan seberapa kritis pemulihannya, kenali sumber daya yang dibutuhkan, lalu tetapkan prioritas pemulihan sistem [S13]. Dari BIA lahir angka MTD, RTO, dan RPO (bagian 1.9).

**Analogi:** keluarga yang rumahnya kebanjiran. BCP adalah rencana supaya keluarga tetap bisa hidup: mengungsi ke rumah saudara, anak tetap berangkat sekolah dari sana, orang tua tetap bekerja, tagihan tetap dibayar lewat HP. DRP adalah rencana memperbaiki rumah setelah air surut: memanggil tukang, mengganti instalasi listrik, mengembalikan perabot dari fotokopi daftar barang. Batasnya: di organisasi, BCP dan DRP berjalan bersamaan sejak awal gangguan, ditulis lengkap dengan nama penanggung jawab dan nomor kontak, dan harus diuji; rencana yang tidak pernah diuji biasanya gagal di langkah pertama.

**Cara kerja:** saat gangguan besar (banjir data center, ransomware massal, kebakaran), BCP menjalankan proses bisnis dengan cara alternatif, misalnya layanan pelanggan pindah lokasi dan pembayaran tetap lewat bank, sementara DRP memulihkan sistem sesuai urutan prioritas hasil BIA (autentikasi pelanggan dulu, lalu portal, lalu file server) dari backup, image sistem, dan lokasi alternatif. Rencana lain yang berdekatan: incident response plan menangani serangan atau insiden keamanan (siklusnya dibahas di Day 19), sedangkan BCP dan DRP menangani akibat gangguan besar, apa pun penyebabnya. Saat ransomware, ketiganya bisa aktif bersamaan.

**Contoh di PT JAB:** BCP PT JAB mengatur, antara lain, call center pindah ke POP Bandung bila gedung Jakarta tidak bisa dipakai, dan pelanggan diarahkan membayar lewat kanal bank bila portal mati (alasan R3 di Day 01 bagian 2.2 dinilai impact sedang). DRP-nya memulihkan sistem internal ke lingkungan cadangan di Azure subscription `JAB-Azure-Prod`, yang memang sudah dipakai untuk server cadangan beberapa aplikasi internal. Uji DRP tahunan dijadwalkan Sabtu 2027-09-11: tim Infrastruktur memulihkan portal (dari image dan backup database) dan file server `JKT-FS01` ke lingkungan cadangan, lalu mengukur lamanya dibandingkan dengan RTO.

**Beda BCP dengan DRP:** BCP bertanya "bagaimana bisnis tetap berjalan", DRP bertanya "bagaimana sistem kembali hidup". BCP dimiliki unit bisnis bersama manajemen; DRP dimiliki tim TI. DRP yang berhasil tetapi tidak ada BCP berarti sistem pulih, tetapi pelanggan sudah berhari-hari tidak dilayani.

**Salah paham umum:**
- "Punya backup berarti punya DRP." Backup adalah bahan, DRP adalah rencana: urutan pemulihan, siapa mengerjakan apa, di mana, dengan target waktu berapa. Backup tanpa rencana dan tanpa uji sering baru ketahuan tidak lengkap saat dibutuhkan.

### 1.9 RTO, RPO, dan MTD

Pertanyaan kesembilan Nina adalah pertanyaan hitungan: backup file server gagal dua malam, jadi berapa banyak data yang tidak terlindungi, dan apakah itu melanggar target?

**Apa itu:**
- **MTD (maximum tolerable downtime)** adalah lamanya proses bisnis boleh terganggu tanpa menimbulkan kerugian serius bagi misi organisasi [S14]. MTD menggambarkan total waktu gangguan yang mau diterima pemilik proses, dengan mempertimbangkan semua dampak [S13].
- **RTO (recovery time objective)** adalah lama maksimal komponen sistem boleh berada dalam fase pemulihan sebelum berdampak buruk pada misi atau proses bisnis [S14]. Karena RTO harus menjamin MTD tidak terlampaui, RTO biasanya lebih pendek daripada MTD; waktu tambahan untuk memproses ulang data setelah sistem hidup juga harus masuk hitungan [S13].
- **RPO (recovery point objective)** adalah titik waktu yang datanya harus bisa dipulihkan setelah gangguan [S14]. RPO tidak termasuk hitungan MTD; ia menggambarkan berapa banyak kehilangan data yang masih bisa diterima proses bisnis [S13]. Dalam praktik, RPO menentukan seberapa sering backup harus dibuat.

**Analogi:** keluarga yang kebanjiran lagi. MTD adalah batas paling lama keluarga bisa bertahan hidup di pengungsian sebelum pekerjaan hilang dan anak tertinggal pelajaran. RTO adalah berapa lama keluarga boleh mengungsi sebelum rumah harus kembali bisa ditinggali, dan harus lebih pendek dari MTD karena setelah pulang masih perlu waktu membereskan rumah. RPO adalah berapa banyak catatan keuangan boleh hilang sejak terakhir difotokopi: bila fotokopi dibuat setiap Minggu dan banjir datang Sabtu, catatan enam hari hilang. Batasnya: di TI, angka ini ditetapkan per sistem lewat BIA dan harus didukung teknologi dan anggaran; RTO satu jam tanpa server cadangan hanyalah harapan.

**Cara kerja:**

```
                 backup terakhir         GANGGUAN          sistem hidup    proses normal
                       |                    |                    |               |
  waktu  -------------[B]------------------[X]------------------[R]-------------[N]------>
                       <------ RPO -------->  <------ RTO ------->
                       data yang hilang      sistem mati            <- proses ulang ->
                                             <------------------ MTD ------------------>
```

Cara membaca diagram: RPO diukur ke belakang dari saat gangguan (berapa data yang hilang), RTO dan MTD diukur ke depan (berapa lama mati). Semakin pendek RTO dan RPO, semakin mahal solusinya [S13]: RPO 15 menit butuh replikasi atau backup log yang terus-menerus, sedangkan RPO 24 jam cukup dengan backup harian.

**Contoh di PT JAB:** hasil BIA 2027 untuk empat layanan tercatat di tabel berikut; perhatikan bahwa RTO selalu lebih pendek dari MTD, dan bahwa RPO berbeda jauh antar layanan.

| Layanan | Proses bisnis | MTD | RTO | RPO | Cara backup |
|---|---|---|---|---|---|
| Autentikasi pelanggan (RADIUS `jkt-radius01`) | Pelanggan bisa online | 4 jam | 2 jam | 15 menit | Server kedua aktif, replikasi database |
| Portal pelanggan `jkt-portal01` | Lihat tagihan, bayar, ganti paket | 24 jam | 8 jam | 1 jam | Backup log database tiap 15 menit, image server harian |
| File server `JKT-FS01` | Dokumen kerja, share Keuangan | 72 jam | 24 jam | 24 jam | Backup harian pukul 22:00 |
| Email Microsoft 365 | Komunikasi | Tidak ditetapkan PT JAB | Bergantung Microsoft | Bergantung Microsoft dan backup pihak ketiga | Layanan SaaS; ketersediaan dijamin penyedia sesuai kontrak |

Untuk `JKT-FS01`, RPO 24 jam berarti setiap saat harus ada restore point yang umurnya kurang dari 24 jam. Dengan backup terakhir yang berhasil pada Senin 2027-08-23 pukul 22:00, RPO sudah terlewati sejak Selasa 2027-08-24 pukul 22:00, saat backup berikutnya seharusnya ada. Hitungan lengkapnya di bagian 2.1.

**Beda RTO dengan RPO:** RTO tentang waktu ("berapa lama boleh mati"), RPO tentang data ("berapa banyak boleh hilang"). Sistem bisa memenuhi satu dan gagal di yang lain: file server yang pulih dalam 3 jam (RTO terpenuhi) dari backup berumur 3 hari (RPO gagal) tetap merugikan, karena pekerjaan tiga hari hilang.

**Salah paham umum:**
- "RTO dihitung sejak tim TI mulai bekerja." RTO dihitung dari saat sistem tidak tersedia. Waktu untuk menyadari gangguan, memanggil orang, dan memutuskan memulai DRP ikut termakan dari RTO.

### 1.10 Backup 3-2-1, immutable, dan offline

Pertanyaan terakhir Nina menyangkut `SOC-2027-0896`: Fajar Nugroho, admin infrastruktur, mencoba menghapus restore point lama untuk memberi ruang, dan sistem menolaknya. Jawabannya ada di cara backup PT JAB disusun.

**Apa itu:**
- **Backup** adalah salinan data yang disimpan terpisah supaya data bisa dipulihkan bila hilang atau rusak. Satu salinan pada satu titik waktu disebut **restore point**. **Retensi** adalah berapa lama restore point disimpan sebelum dihapus otomatis.
- **Aturan 3-2-1** dari US-CERT (sekarang bagian dari CISA): simpan 3 salinan setiap file penting (1 data utama dan 2 backup), di 2 jenis media yang berbeda untuk melindungi dari jenis bahaya yang berbeda, dan simpan 1 salinan di luar lokasi, misalnya di luar rumah atau gedung kantor [S16].
- **Offline backup** adalah backup yang tidak tersambung ke jaringan saat tidak dipakai, misalnya tape yang disimpan di lemari. CISA menganjurkan menyimpan backup data penting secara offline dan terenkripsi, serta menguji ketersediaan dan keutuhannya secara rutin, karena banyak varian ransomware sengaja mencari lalu menghapus atau mengenkripsi backup yang bisa dijangkau [S17].
- **Immutable backup** adalah backup yang disimpan dengan model write once, read many (WORM): setelah ditulis, ia tidak bisa diubah atau dihapus sampai masa kuncinya habis [S18]. Penyimpanan cloud menyediakan fitur serupa, misalnya object lock atau perlindungan penghapusan, yang juga dianjurkan CISA [S17]. CISA juga mengingatkan agar penyimpanan immutable dipakai dengan hati-hati, karena belum tentu memenuhi semua kriteria kepatuhan dan salah konfigurasi bisa mahal [S17].
- Varian modern sering ditulis **3-2-1-1-0**: tambahan satu salinan immutable atau terputus dari jaringan (air-gapped), dan nol galat saat uji pemulihan [S18].

**Analogi:** dokumen penting keluarga (sertifikat rumah, akta, ijazah). Tiga salinan: aslinya di lemari, satu fotokopi di map, satu hasil pindai di flashdisk (tiga salinan). Dua jenis tempat: kertas dan digital (dua media), karena air merusak kertas dan flashdisk bisa rusak dengan cara lain. Satu salinan dititipkan di rumah saudara di kota lain (satu di luar lokasi), supaya banjir di rumah tidak menghabiskan semuanya. Salinan offline adalah map di rumah saudara itu: maling yang masuk rumahmu tidak bisa menjangkaunya. Salinan immutable seperti fotokopi di kotak bertimer yang tidak bisa dibuka siapa pun, termasuk pemiliknya, sebelum waktunya. Batasnya: backup digital bisa diam-diam gagal dibuat, bisa ikut terenkripsi bila tersambung, dan bisa tidak bisa dipulihkan karena formatnya rusak; karena itu backup harus dipantau dan diuji, bukan hanya disimpan.

**Cara kerja:** susunan backup `JKT-FS01` sesuai STD-BKP-01:

```
SALINAN 1 (data utama)   JKT-FS01                       data center Jakarta
        |
        | job harian 22:00, dikendalikan server backup JKT-BKP01 (akun svc-backup)
        v
SALINAN 2                jkt-bkprepo01                  disk, data center Jakarta
                         repository Linux, retensi dan immutable 30 hari
        |
        | salin ulang pukul 02:00
        v
SALINAN 3                penyimpanan objek Azure        cloud, luar lokasi
                         (JAB-Azure-Prod), immutable 30 hari
        +
SALINAN BULANAN          tape LTO full backup           offline, disimpan di POP Bandung
```

Susunan ini memenuhi 3-2-1 (tiga salinan, disk dan cloud, salinan Azure di luar lokasi), ditambah satu lapis immutable dan satu salinan offline (tape). Uji pemulihan dijalankan setiap bulan pada satu folder acak, dan uji penuh saat uji DRP tahunan.

**Contoh di PT JAB:** pukul 23:37 Rabu 2027-08-25, Fajar mencoba menghapus 14 restore point lama di `jkt-bkprepo01` supaya ruang kosong cukup untuk backup malam itu. Sistem menolak karena restore point itu masih dalam masa kunci immutable. Penolakan itu memicu `SOC-2027-0896`. Dari sisi keamanan, perilaku sistem ini benar: penyerang yang sudah menguasai akun admin, seperti pada ransomware `INC-2026-017` Oktober 2026, akan melakukan hal yang persis sama sebelum mengenkripsi server. Immutable tidak bertanya siapa yang meminta, dan itulah gunanya. Penyelesaian masalah kapasitas yang benar adalah menambah kapasitas, bukan menghapus backup (bagian 2.1).

**Beda backup dengan replikasi dan redundansi:** replikasi menyalin perubahan ke tempat lain hampir seketika, sehingga file yang terhapus atau terenkripsi ransomware ikut tersalin dalam hitungan detik. Redundansi (dua server, dua jalur listrik) menjaga availability dari kerusakan perangkat. Hanya backup dengan beberapa titik waktu yang bisa mengembalikan data ke keadaan sebelum kerusakan. Organisasi butuh ketiganya untuk tujuan yang berbeda.

**Salah paham umum:**
- "Backup yang sukses berarti data bisa dipulihkan." Status sukses hanya berarti salinan berhasil ditulis. CISA menganjurkan menguji prosedur backup secara rutin [S17], dan NIST CSF 2.0 meminta integritas backup diverifikasi sebelum dipakai untuk pemulihan [S8].

## 2. Contoh nyata

Semua contoh di bagian ini adalah keluaran ilustrasi dari organisasi fiktif PT JAB, bukan hasil eksekusi nyata. Nama host, nomor, waktu, dan angka dibuat untuk latihan.

### 2.1 Membaca `SOC-2027-0895` dan `SOC-2027-0896` dengan kacamata RPO dan 3-2-1

Dua alert pagi ini adalah bahan pertama Nina. Ringkasan keduanya di Splunk:

```
Alert     : SOC-2027-0895
Dibuat    : 2027-08-25 22:52 WIB
Prioritas : P3
Judul     : Job backup gagal dua kali berturut-turut
Host      : JKT-BKP01 (server backup)
Job       : FS01-harian  (sumber JKT-FS01, tujuan jkt-bkprepo01)
Riwayat   : 2027-08-23 22:00  Success   selesai 23:12
            2027-08-24 22:00  Failed    22:47  "repository free space below required threshold"
            2027-08-25 22:00  Failed    22:51  "repository free space below required threshold"
Catatan   : 2 job lain ke repository yang sama juga gagal pada 2027-08-24 dan 2027-08-25

Alert     : SOC-2027-0896
Dibuat    : 2027-08-25 23:37 WIB
Prioritas : P2
Judul     : Percobaan menghapus restore point immutable ditolak
Akun      : CORP\adm.fajar  dari JKT-JUMP01 (10.20.10.50)
Target    : jkt-bkprepo01, job FS01-harian, 14 restore point (2027-07-27 s.d. 2027-08-09)
Hasil     : Denied  "restore point is immutable until retention lock expires"
```

**Cara membaca `SOC-2027-0895`:** penyebabnya kapasitas, bukan serangan. Restore point terakhir yang berhasil adalah Senin 2027-08-23 pukul 22:00 (waktu mulai backup, karena data diambil sejak saat itu). Bila `JKT-FS01` rusak pada Kamis 2027-08-26 pukul 09:00, data yang hilang adalah semua perubahan sejak Senin 22:00, yaitu 59 jam (Senin 22:00 sampai Rabu 22:00 adalah 48 jam, ditambah 11 jam sampai Kamis 09:00). RPO `JKT-FS01` adalah 24 jam, jadi saat ini paparan sudah 35 jam melewati batas. Paparan itu berlaku juga untuk salinan Azure, karena salinan Azure hanya menyalin ulang isi repository.

**Cara membaca `SOC-2027-0896`:** pelakunya admin yang sah dari jump host yang memang diwajibkan untuk akun admin, sehingga mirip pola Day 07 bagian 2.1: orang sah, tindakan tidak sah. Prioritas P2 karena menghapus backup adalah langkah khas sebelum ransomware. Yoga Pratama (analyst L2 shift malam) menelepon Fajar lewat nomor ekstensi dari direktori karyawan pukul 23:45, bukan lewat chat, dan Fajar mengakui ia mencoba memberi ruang supaya backup malam itu jalan. Alert ditutup sebagai aktivitas sah yang melanggar prosedur PRO-BKP-03 (penghapusan restore point wajib lewat change request dengan persetujuan orang kedua).

Tabel berikut memetakan kedua alert ke istilah Day ini; pakai kolom kanan sebagai pola saat menulis catatan tiket yang akan dibaca tim risiko dan auditor.

| Istilah | Di dua alert ini |
|---|---|
| Governance | Peringatan kapasitas repository dikirim ke kotak surat karyawan yang sudah keluar; tidak ada pemilik yang menerima |
| Standard yang tidak tercapai | STD-BKP-01: backup harian, RPO 24 jam |
| Procedure yang dilanggar | PRO-BKP-03: penghapusan restore point tanpa change request |
| RPO | 24 jam; paparan 59 jam per Kamis 09:00 |
| 3-2-1 | Ketiga salinan terhenti di titik yang sama; tape bulanan terakhir 2027-08-01 |
| Immutable | Bekerja sesuai rancangan: menolak penghapusan, termasuk oleh admin sah |

Tindak lanjut hari itu: Agung menambah kapasitas repository pukul 11:00, job `FS01-harian` dijalankan ulang manual pukul 13:00 dan selesai pukul 14:20, dan salinan ke Azure selesai pukul 14:55. Restore point baru bertanggal Kamis 2027-08-26 13:00 menutup paparan. Peringatan kapasitas dialihkan ke alamat tim Infrastruktur dan dikirim juga ke Splunk, sehingga SOC mendapat alert bila pemakaian repository melewati 85 persen.

### 2.2 Risk register PT JAB setelah alert backup

Pertanyaan kedua Nina dijawab dengan melihat register yang ia bawa ke Komite Keamanan Informasi berikutnya. R1 sampai R3 adalah risiko portal dari Day 01 bagian 2.2 dengan status per Agustus 2027; R4 sampai R6 adalah risiko baru. Penilaian memakai tabel 3x3 yang sama dengan Day 01. Baca kolom Treatment bersama kolom Residual: keputusan yang baik menurunkan risiko ke tingkat yang sesuai risk appetite.

| ID | Risiko | Pemilik | L | I | Tingkat | Treatment | Tindakan dan status | Residual | Tinjau |
|---|---|---|---|---|---|---|---|---|---|
| R1 | Akun pelanggan diambil alih lewat password bocor | Kepala Layanan Digital | Tinggi | Sedang | Tinggi | Mitigate | OTP wajib untuk perubahan paket dan data pribadi; target 2027-09-30, berjalan | Sedang | 2027-10 |
| R2 | Database pelanggan dicuri lewat komponen web yang belum di-patch | Agung Prabowo | Sedang | Tinggi | Tinggi | Mitigate dan transfer sebagian | Patch selesai 2027-08-12; asuransi siber menanggung biaya forensik dan pemberitahuan | Sedang (L rendah, I tinggi) | 2027-11 |
| R3 | Portal mati karena satu-satunya server rusak | Kepala Layanan Digital | Rendah | Sedang | Rendah | Accept | Disetujui Hendra Wijaya; server kedua di anggaran 2028 | Rendah | 2028-01 |
| R4 | Backup tidak bisa dipakai saat dibutuhkan (gagal tanpa diketahui, atau dihapus penyerang) | Agung Prabowo | Sedang | Tinggi | Tinggi | Mitigate | Immutable dan salinan Azure sudah ada; tambah: alert kapasitas ke SOC, pemilik peringatan diperbaiki, uji restore bulanan dicatat; target 2027-09-10 | Sedang | 2027-10 |
| R5 | Kewajiban pemberitahuan UU PDP terlambat karena fakta insiden lambat sampai ke DPO | Agus Setiawan | Sedang | Tinggi | Tinggi | Mitigate | Prosedur SOC: insiden yang menyentuh data pribadi dilaporkan ke DPO dalam 2 jam sejak dibuka; latihan bersama per kuartal | Sedang | 2027-12 |
| R6 | Foto KTP pelanggan bocor lewat fitur unggah lama di portal | Kepala Layanan Digital | Sedang | Tinggi | Tinggi | Avoid | Fitur unggah dihentikan 2027-08-20; verifikasi identitas di gerai; file lama dimusnahkan sesuai retensi | Rendah | 2027-12 |

Cara membacanya:

- R2, R4, R5, dan R6 berada di area appetite rendah (data pelanggan dan kepatuhan), jadi tidak boleh sekadar diterima.
- Residual R2 Sedang: patch menurunkan likelihood ke Rendah, tetapi impact pencurian database tetap Tinggi, dan menurut tabel 3x3 kombinasi itu menjadi Sedang. Asuransi tidak menurunkan likelihood atau impact terhadap pelanggan; ia hanya memindahkan sebagian biaya.
- R3 boleh diterima karena tingkatnya Rendah dan berada di area appetite sedang (ada kanal pembayaran lain), dan penerimaannya punya pemilik, persetujuan, dan tanggal tinjau.
- R6 contoh avoid: kegiatannya dihentikan, sehingga residual turun ke Rendah. Avoid hanya mungkin bila kegiatan itu tidak benar-benar dibutuhkan bisnis.
- Setiap baris punya pemilik yang berwenang memutuskan, bukan nama tim. SOC tidak memiliki risiko-risiko ini; SOC memberi bukti bahwa control-nya bekerja atau gagal.

### 2.3 Menghitung tenggat pemberitahuan untuk `INC-2027-087`

Pertanyaan keenam dijawab Agus dengan insiden bucket cloud dua minggu lalu (Day 08 bagian 2.2). Catatan waktunya dari tiket:

```
INC-2027-087  Data peserta kampanye terbuka publik di bucket S3

Selasa 2027-08-10 14:03:40 WIB  bucket policy publik terpasang
Rabu   2027-08-11 08:40:00 WIB  CSPM melaporkan (SOC-2027-0843)
Rabu   2027-08-11 09:52:10 WIB  bucket ditutup kembali
Rabu   2027-08-11 10:20 WIB     isi 3 file CSV dipastikan: 1.250 baris (nama, nomor HP, paket)
Rabu   2027-08-11 10:35 WIB     Sari melapor ke Agus (DPO) lewat telepon dan tiket
Rabu   2027-08-11 11:00 WIB     Agus menetapkan: kegagalan pelindungan diketahui secara pasti
Jumat  2027-08-13 16:00 WIB     pemberitahuan tertulis ke 1.250 subjek data (email dan SMS)
Jumat  2027-08-13 16:30 WIB     pemberitahuan tertulis ke otoritas pengawas PDP
```

**Cara membaca:**

- Titik awal yang dipakai Agus adalah saat kegagalan diketahui secara pasti (Rabu 11:00), sesuai PP 33/2026 yang berlaku sejak Januari 2027 [S6]. Tenggat 3 x 24 jam jatuh pada Sabtu 2027-08-14 pukul 11:00. Hitungan memakai jam, bukan hari kerja.
- Pemberitahuan ke subjek data dikirim Jumat 16:00, yaitu 53 jam setelah titik awal (48 jam sampai Jumat 11:00, ditambah 5 jam), sehingga masih 19 jam sebelum tenggat. Pemberitahuan ke otoritas dikirim 30 menit kemudian.
- Isi pemberitahuan memenuhi unsur Pasal 46 ayat (2) [S2]: data yang terungkap (nama, nomor HP, paket langganan), kapan dan bagaimana (bucket penyimpanan terbuka publik 19 jam 48 menit 30 detik karena salah konfigurasi), upaya penanganan dan pemulihan (bucket ditutup, izin diperketat, deteksi baru di Splunk), ditambah narahubung DPO sesuai PP 33/2026 [S6].
- Waktu dari CSPM melapor (08:40) sampai DPO menerima fakta lengkap (10:35) adalah 1 jam 55 menit. Inilah yang ingin dijaga R5: setiap menit yang dipakai SOC untuk memastikan fakta adalah menit yang tidak bisa dipakai DPO.
- Penerima di sisi otoritas ditulis umum karena kelembagaan pengawas PDP masih berproses per Oktober 2026 (bagian 1.6).

Perhatian: hitungan ini menggambarkan cara berpikir, bukan tafsir hukum yang mengikat. Kapan sebuah kegagalan dianggap "diketahui secara pasti" adalah keputusan DPO dan penasihat hukum, dan catatan waktunya harus tersimpan di tiket supaya bisa dipertanggungjawabkan.

### 2.4 Persiapan audit surveillance dan uji DRP

Pertanyaan ketujuh dan kedelapan Nina berujung pada dua daftar kerja. Daftar pertama adalah bukti yang diminta auditor untuk control yang menyentuh SOC; cari kolom Lapis (tertulis, dijalankan, efektif) untuk melihat bahwa auditor tidak berhenti di dokumen.

| Control Annex A | Bukti yang disiapkan | Lapis |
|---|---|---|
| 5.1 Kebijakan keamanan informasi | Kebijakan Keamanan Informasi versi terbaru dengan persetujuan direksi | Tertulis |
| 8.13 Backup informasi | STD-BKP-01, PRO-BKP-03; laporan job backup Agustus; tiket `SOC-2027-0895` dan tindak lanjutnya; catatan uji restore bulanan | Tertulis, dijalankan, efektif |
| 5.29 dan 5.30 Gangguan dan kesiapan TIK | BCP, DRP, hasil BIA 2027, laporan uji DRP 2027-09-11 | Tertulis, efektif |
| 5.31 dan 5.34 Kewajiban hukum dan data pribadi | Compliance register; tiket `INC-2027-087` dengan catatan waktu pemberitahuan | Tertulis, dijalankan |
| 5.36 Kepatuhan pada kebijakan | Tiket `SOC-2027-0896` (pelanggaran prosedur terdeteksi dan ditindaklanjuti) | Dijalankan |
| Tindak lanjut temuan 2026 | Laporan penutupan minor nonconformity uji DRP portal | Efektif |

Daftar kedua adalah rencana uji DRP Sabtu 2027-09-11 beserta hasil tahun lalu; baca kolom Hasil 2026 untuk memahami kenapa portal menjadi fokus.

| Sistem | RTO | RPO | Hasil 2026 | Perbaikan sejak 2026 | Yang diukur 2027 |
|---|---|---|---|---|---|
| Portal `jkt-portal01` | 8 jam | 1 jam | Pulih 9 jam 10 menit (gagal RTO); data sampai 40 menit sebelum gangguan (lolos RPO) | Image server disiapkan di Azure; restore database diuji per bulan | Waktu sampai portal bisa login dan menampilkan tagihan |
| File server `JKT-FS01` | 24 jam | 24 jam | Pulih 14 jam (lolos) | Tidak ada | Waktu pulih; keutuhan file acak dibandingkan hash sebelum backup |
| Autentikasi pelanggan | 2 jam | 15 menit | Tidak diuji (server kedua aktif) | Tidak ada | Uji alih ke server kedua selama 30 menit pada malam hari |

Cara membaca: portal gagal RTO tahun lalu dengan selisih 1 jam 10 menit (9 jam 10 menit dikurangi 8 jam), dan inilah minor nonconformity surveillance 2026. Bila uji 2027 berhasil, laporan uji itu menjadi bukti penutupan temuan. Bila gagal lagi, Nina harus menunjukkan analisis penyebab dan rencana baru; temuan minor yang berulang tanpa perbaikan berisiko dinaikkan menjadi major.

Peran SOC selama uji DRP: memastikan log sistem yang dipulihkan tetap masuk ke Splunk, memantau login admin ke lingkungan cadangan, dan mencatat waktu setiap tahap (mulai, sistem hidup, layanan bisa dipakai) sebagai bukti RTO yang tidak bisa diperdebatkan.

## 3. Perbandingan istilah yang sering tertukar

### 3.1 Framework, standar sertifikasi, dan regulasi

Tiga jenis acuan ini sering disebut sejajar padahal kekuatan mengikatnya berbeda. Tabel berikut membandingkan tiga acuan utama Day ini; cari kolom Wajib? dan Bila tidak dipenuhi.

| Acuan | Jenis | Wajib? | Bisa disertifikasi? | Bila tidak dipenuhi |
|---|---|---|---|---|
| NIST CSF 2.0 | Framework (panduan hasil) | Sukarela | Tidak ada skema sertifikasi resmi | Tidak ada sanksi; kehilangan panduan |
| ISO/IEC 27001:2022 | Standar persyaratan sistem manajemen | Sukarela, bisa diwajibkan kontrak | Ya, oleh lembaga sertifikasi terakreditasi | Temuan audit; sertifikat bisa dibekukan atau dicabut |
| UU No. 27 Tahun 2022 (PDP) | Regulasi | Wajib | Tidak | Sanksi administratif (sampai 2 persen pendapatan tahunan) dan pidana |

### 3.2 BCP, DRP, incident response plan, dan backup

Empat hal ini sering dianggap satu paket "kalau ada masalah". Tabel berikut membedakan fokusnya; cari kolom Pemicu untuk menentukan rencana mana yang aktif.

| Hal | Fokus | Pemicu | Pemilik | Contoh PT JAB |
|---|---|---|---|---|
| BCP | Proses bisnis tetap berjalan | Gangguan besar apa pun | Unit bisnis dan manajemen | Call center pindah ke Bandung |
| DRP | Sistem TI dipulihkan, sering di lokasi lain | Gangguan besar yang mematikan sistem | Tim TI | Portal dan `JKT-FS01` dipulihkan ke Azure |
| Incident response plan | Insiden keamanan ditangani | Serangan atau dugaan serangan | SOC dan tim IR | Penanganan ransomware (Day 19) |
| Backup | Salinan data untuk pemulihan | Dipakai oleh DRP dan IR | Tim Infrastruktur | 3-2-1 dengan immutable dan tape offline |

## 4. Salah paham umum

- **Anggapan:** bersertifikat ISO/IEC 27001 berarti otomatis patuh UU PDP. **Kenyataannya:** sertifikasi menilai sistem manajemen keamanan untuk lingkup tertentu (di PT JAB: data center, NOC, dan SOC), sedangkan UU PDP mengatur hak subjek data, dasar pemrosesan, DPO, transfer ke luar negeri, dan pemberitahuan dalam 3 x 24 jam [S2]. Sertifikat membantu menunjukkan keseriusan, tetapi kewajiban hukum diperiksa tersendiri.
- **Anggapan:** tiga salinan backup sudah cukup, di mana pun letaknya. **Kenyataannya:** aturan 3-2-1 menuntut dua jenis media dan satu salinan di luar lokasi [S16]; tiga salinan di satu ruang server yang sama bisa habis oleh satu banjir atau satu akun admin yang dikuasai penyerang. Karena itu CISA menekankan backup offline dan terenkripsi [S17].
- **Anggapan:** RTO dan RPO bisa dipilih bebas oleh tim TI. **Kenyataannya:** keduanya diturunkan dari BIA bersama pemilik proses bisnis [S13], dan harus dibayar dengan teknologi: semakin pendek targetnya, semakin mahal solusinya [S13]. Target yang tidak didukung anggaran hanya akan gagal saat uji DRP.
- **Anggapan:** immutable backup membuat backup kebal dari semua masalah. **Kenyataannya:** immutable mencegah penghapusan dan perubahan, tetapi tidak mencegah backup gagal dibuat (kapasitas penuh pada `SOC-2027-0895`), tidak menjamin isi backup bersih dari malware, dan bila salah dikonfigurasi bisa mahal atau tidak sesuai kebutuhan kepatuhan [S17]. Pemantauan dan uji restore tetap wajib.

## 5. Catatan terkini

Bagian ini mencatat versi dokumen acuan, tanggal, dan perubahan kelembagaan yang perlu diketahui saat membaca sumber lain.

- **UU PDP.** UU No. 27 Tahun 2022 ditetapkan dan diundangkan 17 Oktober 2022 [S1]; masa penyesuaian dua tahun berakhir 17 Oktober 2024 [S2]. Database peraturan BPK mencatat Putusan Mahkamah Konstitusi No. 151/PUU-XXII/2024 yang memaknai kata "dan" di Pasal 53 ayat (1) huruf b (syarat penunjukan DPO) menjadi "dan/atau" [S1].
- **PP No. 33 Tahun 2026.** Ditetapkan 16 Juli 2026 dan berlaku 16 Januari 2027 menurut pemberitaan; satu laporan menyebut 12 bab dan 224 pasal [S4][S5][S6]. Akhir Juli 2026 kementerian masih menyebut PP dan Perpres belum ditetapkan [S7], sedangkan salinan PP baru beredar akhir Agustus 2026 [S4]; pastikan teks resminya di JDIH Sekretariat Negara sebelum dikutip.
- **Lembaga pengawas PDP.** Belum terbentuk per 21 Oktober 2026. Rancangan Perpres diajukan ke Presiden pada Mei 2026, pengawasan sementara dijalankan Ditjen Pengawasan Ruang Digital Komdigi, dan uji materi di Mahkamah Konstitusi tentang pembentukan lembaga ini masih berjalan pada Juli 2026 [S7].
- **NIST CSF 2.0** terbit 26 Februari 2024 sebagai CSWP 29, menambah fungsi Govern dan memperluas sasaran ke semua organisasi [S8].
- **ISO/IEC 27001:2022** adalah edisi 3 (terbit 25 Oktober 2022) dan masih edisi berlaku; satu amandemen, ISO/IEC 27001:2022/Amd 1:2024 "Climate action changes", terbit 23 Februari 2024 [S9]. Amandemen itu menambah pertimbangan perubahan iklim di bagian konteks organisasi, tanpa mengubah daftar control Annex A. Edisi 2022 merombak Annex A edisi 2013 (114 control dalam 14 domain) menjadi 93 control dalam empat tema, termasuk 11 control baru seperti threat intelligence dan kesiapan TIK untuk kelangsungan bisnis [S10].
- **NIST SP 800-34 Rev. 1** (Contingency Planning Guide for Federal Information Systems) terbit Mei 2010 dengan pembaruan 11 November 2010, dan masih berstatus final tanpa revisi baru di halaman publikasinya [S13]. Istilah DRP di dokumen ini lebih sempit daripada pemakaian sehari-hari (bagian 1.8).
- **CISA #StopRansomware Guide** yang dirujuk adalah versi September 2023, pembaruan dari versi September 2020 [S17]. Aturan 3-2-1 berasal dari makalah US-CERT "Data Backup Options" (2012), bukan dari panduan ransomware itu [S16].

## 6. Cheat sheet

```
Governance          : pimpinan menetapkan arah, peran, kebijakan, dan mengawasi (CSF: Govern)
GRC                 : governance + risk + compliance; diperiksa lewat audit
Risk register       : catatan pusat risiko: pemilik, L, I, tingkat, treatment, status, residual, tinjau
Risk treatment      : mitigate | transfer (share) | avoid | accept (tertulis, ada pemilik)
Risk appetite       : sikap umum: risiko apa dan seberapa banyak mau diterima
Compliance          : memenuhi kewajiban (hukum, kontrak, kebijakan sendiri) dan bisa membuktikannya
Control framework   : panduan sukarela (NIST CSF 2.0); ISO 27001 = standar yang bisa disertifikasi
Policy              : wajib, umum, disetujui pimpinan: "apa dan kenapa"
Standard            : wajib, rinci, seragam: "dengan apa, berapa"
Procedure           : langkah demi langkah untuk pelaksana
Guideline           : anjuran, boleh cara lain
NIST CSF 2.0        : 6 fungsi GV ID PR DE RS RC; Profile (Current/Target); Tier 1-4; Feb 2024
ISO/IEC 27001:2022  : ISMS, klausul 4-10 wajib; Annex A 93 control, 4 tema (37/8/14/34); SoA; Amd 1:2024
UU PDP              : UU 27/2022, berlaku 17 Okt 2022, transisi s.d. 17 Okt 2024
Pasal 46 UU PDP     : kegagalan pelindungan -> tertulis maks 3 x 24 jam ke subjek data dan Lembaga
Sanksi UU PDP       : administratif s.d. 2% pendapatan tahunan; pidana (mis. 5 th / Rp5 M); korporasi denda s.d. 10x
PP 33/2026          : pelaksana UU PDP, berlaku 16 Jan 2027 (menurut pemberitaan)
Lembaga PDP         : belum terbentuk per Okt 2026; sementara Ditjen Pengawasan Ruang Digital Komdigi
Audit               : pemeriksaan independen; tertulis? dijalankan? efektif?
Surveillance audit  : sekali tiap tahun kalender dalam siklus sertifikasi 3 tahun
BCP                 : bisnis tetap jalan selama dan setelah gangguan besar
DRP                 : sistem TI dipulihkan (NIST: di fasilitas alternatif)
BIA                 : proses kritis, sumber daya, prioritas pemulihan -> MTD, RTO, RPO
MTD                 : lama maksimal proses bisnis boleh terganggu
RTO                 : lama maksimal sistem boleh mati; RTO < MTD
RPO                 : titik waktu data yang harus bisa dipulihkan; menentukan frekuensi backup
3-2-1               : 3 salinan, 2 jenis media, 1 di luar lokasi; varian 3-2-1-1-0
Immutable backup    : WORM, tidak bisa diubah/dihapus sampai masa kunci habis
```

## 7. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "PT JAB sudah bersertifikat ISO/IEC 27001, jadi otomatis sudah patuh UU PDP dan tidak perlu DPO menilai insiden." Benarkah?

<details><summary>Jawaban</summary>

Tidak. ISO/IEC 27001 adalah standar sukarela yang menilai sistem manajemen keamanan untuk lingkup tertentu, di PT JAB hanya data center, NOC, dan SOC. UU PDP adalah regulasi wajib dengan kewajiban sendiri, misalnya menunjuk DPO dan memberi tahu subjek data dan Lembaga paling lambat 3 x 24 jam setelah kegagalan pelindungan. Sertifikat membantu, tetapi tidak menggantikan penilaian DPO atas setiap insiden yang menyentuh data pribadi. Lihat bagian 1.3, 1.5, dan 1.6.

</details>

**2. Skenario keputusan.** Kamis pagi kamu melihat job backup `JKT-FS01` gagal dua malam karena repository penuh. RPO file server 24 jam. Apa langkah yang paling tepat?

- A. Tunggu job malam ini; kalau berhasil, masalah selesai dengan sendirinya.
- B. Eskalasi ke pemilik control sekarang karena RPO sudah terlewati, minta kapasitas ditambah dan backup dijalankan ulang manual, lalu catat paparannya di tiket.
- C. Minta admin menghapus restore point lama supaya ada ruang kosong untuk backup malam ini.

<details><summary>Jawaban</summary>

B. Backup terakhir berumur lebih dari 24 jam, jadi target RPO sudah dilanggar dan setiap jam menunggu menambah data yang tidak terlindungi; per Kamis 09:00 paparannya 59 jam. A keliru karena membiarkan pelanggaran berlanjut hampir satu hari lagi dan tidak menyelesaikan penyebabnya. C keliru karena restore point dalam masa kunci immutable memang tidak bisa dihapus, penghapusan tanpa change request melanggar prosedur, dan langkah itu sama persis dengan yang dilakukan penyerang ransomware sebelum mengenkripsi. Lihat bagian 1.9, 1.10, dan 2.1.

</details>

**3. Pertanyaan jebakan.** "RTO portal 8 jam, jadi data portal yang boleh hilang maksimal 8 jam." Benarkah?

<details><summary>Jawaban</summary>

Tidak. RTO mengukur berapa lama sistem boleh mati, dihitung ke depan dari saat gangguan. Data yang boleh hilang diatur RPO, dihitung ke belakang dari saat gangguan; RPO portal PT JAB 1 jam. Sistem bisa memenuhi RTO tetapi gagal RPO, misalnya pulih cepat dari backup yang terlalu lama. Lihat bagian 1.9.

</details>

**4. Skenario keputusan.** DPO menetapkan sebuah kegagalan pelindungan data pribadi diketahui secara pasti pada Jumat pukul 16:00. Kapan batas akhir pemberitahuan tertulis ke subjek data dan Lembaga menurut Pasal 46 UU PDP?

- A. Rabu pukul 16:00, karena dihitung tiga hari kerja.
- B. Senin pukul 16:00, karena dihitung 3 x 24 jam (72 jam).
- C. Tidak ada batas selama investigasi forensik belum selesai.

<details><summary>Jawaban</summary>

B. Pasal 46 menyebut paling lambat 3 x 24 jam, jadi hitungannya jam, termasuk Sabtu dan Minggu: Jumat 16:00 ditambah 72 jam adalah Senin 16:00. A keliru karena undang-undang tidak menyebut hari kerja. C keliru karena tenggat tidak menunggu investigasi selesai; pemberitahuan memuat apa yang sudah diketahui dan upaya penanganannya. Titik awal "diketahui secara pasti" diatur di PP 33/2026 dan tetap keputusan DPO dan penasihat hukum. Lihat bagian 1.6 dan 2.3.

</details>

**5. Jelaskan ulang.** Jelaskan kepada anggota keluargamu yang bukan orang IT, dalam tiga kalimat, beda BCP dan DRP.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Bayangkan rumah kita kebanjiran. BCP adalah rencana supaya kita tetap bisa hidup normal selama banjir, misalnya mengungsi ke rumah tante sehingga tetap bisa sekolah dan bekerja. DRP adalah rencana memperbaiki rumah setelah air surut sampai bisa ditinggali lagi, dan di kantorku DRP berarti menghidupkan kembali komputer dan data perusahaan."

Kesalahan yang sering muncul:
- Menganggap keduanya sama, atau menganggap backup sudah merupakan DRP.
- Memakai singkatan dan istilah teknis (RTO, failover) kepada orang yang bukan orang IT.

</details>

**6. Pertanyaan jebakan.** "Tiga salinan backup `JKT-FS01` disimpan di tiga server berbeda di ruang data center Jakarta yang sama, semuanya bisa diakses akun admin domain. Ini sudah memenuhi aturan 3-2-1." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Aturan 3-2-1 menuntut tiga salinan, di dua jenis media yang berbeda, dengan satu salinan di luar lokasi. Tiga server di ruang yang sama hanya memenuhi angka 3; satu banjir, kebakaran, atau satu akun admin yang dikuasai penyerang bisa menghabiskan ketiganya. CISA juga menganjurkan salinan offline dan terenkripsi karena ransomware sengaja mencari backup yang bisa dijangkau. Lihat bagian 1.10 dan 4.

</details>

**7. Interview question (English).** "What is the difference between RTO and RPO, and how would you use them as a SOC analyst?"

<details><summary>Sample answer</summary>

"RTO, the recovery time objective, is how long a system can be down before the impact becomes unacceptable, measured forward from the moment of the outage. RPO, the recovery point objective, is how much data the business can afford to lose, measured backward from the outage, so it drives backup frequency. Both come out of the business impact analysis, and the RTO has to sit inside the maximum tolerable downtime for the business process. As a SOC analyst, I use them to judge urgency: if a nightly backup for a file server with a 24-hour RPO fails twice, the RPO is already breached, so I escalate to the control owner the same morning instead of waiting for the next run. During disaster recovery tests, I record the timestamps of each stage so the measured recovery time can be compared with the RTO and used as audit evidence."

What makes this answer strong: it defines both terms by direction on the timeline, links them to the business impact analysis and maximum tolerable downtime, and shows concrete SOC behaviour: escalating a breached RPO and producing evidence for audits.

</details>

## 8. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Database Peraturan BPK: Undang-undang (UU) Nomor 27 Tahun 2022 tentang Pelindungan Data Pribadi | https://peraturan.bpk.go.id/Details/229798 | primer (database peraturan resmi) | 2022-10-17; diakses 2026-10-21 | Tinggi untuk tanggal, nomor LN, ruang lingkup, definisi, dan Putusan MK 151/PUU-XXII/2024 |
| S2 | Pasal.id: UU No. 27 Tahun 2022 Pasal 46, 53, 57, 67, 70, 74 | https://pasal.id/peraturan/uu/uu-no-27-tahun-2022/pasal-46<br>https://pasal.id/peraturan/uu/uu-no-27-tahun-2022/pasal-53<br>https://pasal.id/peraturan/uu/uu-no-27-tahun-2022/pasal-57<br>https://pasal.id/peraturan/uu/uu-no-27-tahun-2022/pasal-67<br>https://pasal.id/peraturan/uu/uu-no-27-tahun-2022/pasal-70<br>https://pasal.id/peraturan/uu/uu-no-27-tahun-2022/pasal-74 | sekunder (transkripsi teks UU) | diakses 2026-10-21 | Sedang sampai tinggi. Teks pasal sesuai UU; tetap cocokkan dengan teks resmi untuk dokumen formal |
| S3 | Wikisource: UU Nomor 27 Tahun 2022, halaman penjelasan Pasal 46 | https://id.wikisource.org/wiki/Halaman:UU_Nomor_27_Tahun_2022_Tentang_Perlindungan_Data_Pribadi.pdf/46 | sekunder (transkripsi teks UU) | diakses 2026-10-21 | Sedang sampai tinggi. Penjelasan ayat (1) (arti kegagalan pelindungan) dan ayat (3) (dalam hal tertentu) |
| S4 | Kompas.id: Beredar Peraturan Pelaksana UU Perlindungan Data Pribadi | https://www.kompas.id/artikel/peraturan-pelaksana-uu-pdp-akhirnya-terbit-lembaga-pengawas-masih-dinanti | sekunder (berita) | 2026-08-29; diakses 2026-10-21 | Sedang. Berdasarkan salinan tidak resmi; menyebut PP 33/2026 bertanggal 16 Juli 2026 dan lembaga pengawas belum ditetapkan |
| S5 | Katadata: PP Pelindungan Data Pribadi Berlaku Januari 2027, Ini Aturan Baru Data Anak | https://katadata.co.id/finansial/makro/6a9979b7c5745/pp-pelindungan-data-pribadi-berlaku-januari-2027-ini-aturan-baru-data-anak | sekunder (berita) | 2026-09-03; diakses 2026-10-21 | Sedang. Tanggal tanda tangan 16 Juli 2026 dan berlaku 16 Januari 2027 |
| S6 | Veritask: Pengaturan Teknis Pelindungan Data Pribadi dan Kewajiban Pengendali serta Prosesor Akhirnya Terbit Lewat PP 33/2026 | https://veritask.ai/id/artikel/pengaturan-teknis-pelindungan-data-pribadi-dan-kewajiban-pengendali-serta-prosesor-akhirnya-terbit-lewat-pp-33-2026 | sekunder (ulasan hukum) | 2026-09-03; diakses 2026-10-21 | Sedang. Ringkasan isi PP 33/2026; belum dicocokkan dengan teks resmi |
| S7 | Kompas.com: Komdigi Ungkap Perpres Pembentukan Badan Perlindungan Data Pribadi Sedang Disusun | https://nasional.kompas.com/read/2026/07/27/15423511/komdigi-ungkap-perpres-pembentukan-badan-perlindungan-data-pribadi-sedang | sekunder (berita, keterangan pemerintah di sidang MK) | 2026-07-27; diakses 2026-10-21 | Sedang sampai tinggi. Status rancangan Perpres dan pengawasan sementara oleh Ditjen Pengawasan Ruang Digital Komdigi |
| S8 | NIST CSWP 29: The NIST Cybersecurity Framework (CSF) 2.0; NIST News: NIST Releases Version 2.0 of Landmark Cybersecurity Framework | https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf<br>https://www.nist.gov/news-events/news/2024/02/nist-releases-version-20-landmark-cybersecurity-framework | primer | 2024-02-26; diakses 2026-10-21 | Tinggi. Enam fungsi, kategori Govern (GV.OC, GV.RM, GV.RR, GV.PO, GV.OV, GV.SC), risk appetite dan tolerance (GV.RM-02), PR.DS-11, RC.RP-03, Profile dan Tier |
| S9 | ISO committee: ISO/IEC 27001:2022 dan ISO/IEC 27001:2022/Amd 1:2024 | https://committee.iso.org/standard/82875.html<br>https://committee.iso.org/standard/88435.html | primer (katalog ISO) | 2022-10-25 dan 2024-02-23; diakses 2026-10-21 | Tinggi untuk judul, edisi, status, dan tanggal terbit. Halaman tidak memuat isi amandemen |
| S10 | Scrut: ISO 27001:2022 Annex A Controls; Modulos: ISO 27001 Annex A | https://www.scrut.io/hub/iso-27001/iso-27001-controls<br>https://docs.modulos.ai/frameworks/iso-27001/annex-a | sekunder (vendor kepatuhan) | diperbarui 2025-11-07; diakses 2026-10-21 | Sedang. Jumlah control per tema, 11 control baru, SoA, nama kelompok control 5.29 sampai 5.36 dan 8.13. Teks standar tidak diperiksa |
| S11 | European Accreditation FAQ: ISO/IEC 17021-1 klausul 9.1.3 dan 8.2.2 | https://european-accreditation.org/?p=43034<br>https://european-accreditation.org/?p=48729 | primer (badan akreditasi) | 2019 dan 2026-03; diakses 2026-10-21 | Tinggi. Surveillance sekali setiap tahun kalender; siklus sertifikasi tiga tahun wajib tertulis di sertifikat |
| S12 | NIST SP 800-12 Rev. 1: An Introduction to Information Security | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-12r1.pdf | primer | 2017-06; diakses 2026-10-21 | Tinggi. Policy, standards, guidelines, procedures (bab 5 dan 5.1); peran auditor; audit vs monitoring (bagian 7.3) |
| S13 | NIST SP 800-34 Rev. 1: Contingency Planning Guide for Federal Information Systems | https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-34r1.pdf<br>https://csrc.nist.gov/pubs/sp/800/34/r1/upd1/final | primer | 2010-05, diperbarui 2010-11-11; diakses 2026-10-21 | Tinggi. BCP (2.2.1), DRP (2.2.6), BIA tiga langkah, MTD/RTO/RPO dan hubungannya (3.2), biaya RTO pendek |
| S14 | NIST CSRC Glossary: recovery time objective, recovery point objective, maximum tolerable downtime, business continuity plan, disaster recovery plan | https://csrc.nist.gov/glossary/term/recovery_time_objective<br>https://csrc.nist.gov/glossary/term/recovery_point_objective<br>https://csrc.nist.gov/glossary/term/maximum_tolerable_downtime<br>https://csrc.nist.gov/glossary/term/business_continuity_plan<br>https://csrc.nist.gov/glossary/term/disaster_recovery_plan | primer (glosarium NIST) | diakses 2026-10-21 | Tinggi. Definisi dari SP 800-34 Rev. 1 dan CNSSI 4009-2022 |
| S15 | NIST CSRC Glossary: risk register, risk response, risk appetite, risk tolerance | https://csrc.nist.gov/glossary/term/risk_register<br>https://csrc.nist.gov/glossary/term/risk_response<br>https://csrc.nist.gov/glossary/term/risk_appetite<br>https://csrc.nist.gov/glossary/term/risk_tolerance | primer (glosarium NIST) | diakses 2026-10-21 | Tinggi. Pilihan accept, avoid, mitigate, share, transfer dari SP 800-39 |
| S16 | US-CERT (CISA): Data Backup Options | https://www.cisa.gov/uscert/sites/default/files/publications/data_backup_options.pdf | primer (publikasi pemerintah AS) | 2012; diakses 2026-10-21 | Tinggi. Rumusan aturan 3-2-1 |
| S17 | CISA, MS-ISAC dan mitra: #StopRansomware Guide | https://www.cisa.gov/stopransomware/ransomware-guide | primer | 2023-09; diakses 2026-10-21 | Tinggi. Backup offline dan terenkripsi, uji rutin, peringatan pemakaian immutable storage, object lock dan delete protection |
| S18 | NAKIVO: 3-2-1 Backup Rule | https://www.nakivo.com/blog/3-2-1-backup-rule/ | sekunder (blog vendor backup) | diakses 2026-10-21 | Sedang. Dipakai untuk varian 3-2-1-1-0 dan arti WORM/immutable |

**Catatan sumber:** isi pasal UU PDP diambil dari transkripsi teks undang-undang (S2, S3) karena PDF di database BPK berupa pindaian yang tidak bisa dibaca sebagai teks; tanggal dan status diambil dari BPK (S1). Isi PP No. 33 Tahun 2026, termasuk titik awal 3 x 24 jam sejak kegagalan diketahui, hanya bersumber dari pemberitaan dan ulasan hukum (S4 sampai S6) yang belum dicocokkan dengan teks resmi di JDIH Sekretariat Negara; cek teks itu sebelum dipakai. Status lembaga pengawas ditulis per 21 Oktober 2026 berdasarkan pemberitaan Juli sampai Agustus 2026 (S4, S7); tidak ditemukan berita penetapan Perpres sampai tanggal riset. Isi Amd 1:2024 (pertimbangan perubahan iklim di konteks organisasi) tidak tercantum di halaman katalog ISO (S9) dan ditulis dari ringkasan umum amandemen itu. Nama dan nomor control Annex A berasal dari sumber sekunder (S10), bukan dari teks standar. Pembagian nonconformity major dan minor serta struktur temuan (kondisi, kriteria, bukti) adalah praktik umum audit sertifikasi tanpa sumber khusus di tabel ini. Seluruh isi PT JAB (alert `SOC-2027-0895` dan `0896`, struktur governance, dokumen STD-BKP-01 dan PRO-BKP-03, risk register R4 sampai R6, angka BIA, jadwal audit dan uji DRP, host `jkt-bkprepo01`, dan catatan waktu `INC-2027-087` setelah pukul 09:52) adalah contoh fiktif.
