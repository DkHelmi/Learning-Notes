---
day: 03
title: 'Analytic tradecraft: keandalan sumber (Admiralty), bahasa keyakinan, bias kognitif, dan ACH'
researched_on: 2026-10-10
versions_checked: 'ICD 203 (2015, amandemen teknis 2022); PHIA Probability Yardstick (gov.uk, Maret 2025); Tradecraft Primer (US Government, 2009); Heuer, Psychology of Intelligence Analysis (1999); skala Admiralty dari FM 2-22.3'
---

# Day 03: Analytic tradecraft

Cakupan: cara berpikir analis intelijen, yaitu menilai sumber dan informasi dengan skala Admiralty, menyatakan probabilitas dan keyakinan dengan istilah terdefinisi, mengenali bias, dan memakai structured analytic techniques seperti Key Assumptions Check dan ACH dengan contoh kerja.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menilai keandalan sumber dan kredibilitas informasi secara terpisah dengan skala Admiralty, termasuk untuk sumber siber seperti vendor, feed, dan telemetri sendiri.
- memakai istilah probabilitas dari ICD 203 atau PHIA secara konsisten, dan memisahkannya dari tingkat keyakinan.
- membedakan fakta, penilaian, dan spekulasi di tingkat kalimat.
- mengenali bias kognitif yang umum di CTI dan memilih teknik untuk menguranginya.
- menjalankan Key Assumptions Check, Quality of Information Check, dan ACH pada kasus fiktif, termasuk analisis sensitivitas.
- menulis pernyataan atribusi yang jujur tentang keyakinan dan alternatifnya.

## 2. Konteks singkat

Tahap analysis dalam siklus (Day 02) adalah tempat data menjadi intelijen, dan di sinilah tradecraft menentukan kualitas. Dua analis dengan data yang sama bisa sampai ke kesimpulan berbeda. Yang membedakan analis yang bisa dipercaya adalah disiplinnya: menilai sumber, menyatakan keyakinan dengan jujur, menyadari bias, dan menguji alternatif. Tanpa itu, CTI berubah menjadi tebakan yang terdengar yakin karena dibungkus bahasa teknis.

Bagi analis forensik dan SOC, prinsipnya sudah akrab (rantai bukti, artefak berbeda dari interpretasi); yang baru adalah kosakata dan teknik terstruktur agar penalaran bisa ditulis dan diperiksa rekan.

**Kapan dipakai:** setiap penilaian intelijen, atribusi, jawaban RFI, dan produk tertulis.

**Kapan terbatas:** teknik formal seperti ACH memakan waktu dan tidak cocok untuk RFI yang harus dijawab dalam satu jam. Untuk kasus seperti itu, pakai versi ringkas: kode sumber, satu kalimat keyakinan, dan satu alternatif yang dipertimbangkan.

## 3. Konsep inti

### 3.1 Keandalan sumber dan kredibilitas informasi

Dua hal ini berbeda dan sering dicampur [S1]:

- **Keandalan sumber (reliability):** seberapa bisa dipercaya sumbernya, dinilai dari rekam jejak dan kemampuannya mengetahui hal yang dilaporkan. Skala huruf A sampai F.
- **Kredibilitas informasi (credibility):** seberapa masuk akal informasi itu sendiri, dinilai dari konsistensi logis dan konfirmasi oleh sumber lain. Skala angka 1 sampai 6.

Keduanya dinilai terpisah agar reputasi sumber tidak memengaruhi penilaian isi. Hasilnya kode dua karakter seperti B2. Pemisahan ini mencegah dua kesalahan klasik: percaya informasi lemah karena sumbernya bagus, atau membuang informasi kuat karena sumbernya baru.

### 3.2 Skala Admiralty

| Kode | Keandalan sumber | Makna ringkas |
|---|---|---|
| A | Completely reliable | Tidak ada keraguan; rekam jejak selalu valid |
| B | Usually reliable | Sedikit keraguan; sebagian besar laporan masa lalu valid |
| C | Fairly reliable | Ada keraguan, tetapi pernah memberi informasi valid |
| D | Not usually reliable | Keraguan signifikan, sesekali valid |
| E | Unreliable | Rekam jejak informasi tidak valid |
| F | Reliability cannot be judged | Tidak ada dasar menilai (sumber baru) |

| Kode | Kredibilitas informasi | Makna ringkas |
|---|---|---|
| 1 | Confirmed by other sources | Dikonfirmasi sumber independen lain, logis, konsisten |
| 2 | Probably true | Belum dikonfirmasi, logis, konsisten dengan informasi lain |
| 3 | Possibly true | Belum dikonfirmasi, cukup logis, cocok dengan sebagian informasi lain |
| 4 | Doubtful | Belum dikonfirmasi, mungkin tetapi tidak logis, tidak ada informasi pendukung |
| 5 | Improbable | Tidak logis dan bertentangan dengan informasi lain |
| 6 | Truth cannot be judged | Tidak ada dasar menilai |

Dua hal yang sering terlewat. Pertama, F dan 6 bukan nilai buruk; artinya "belum bisa dinilai". Sumber baru selalu mulai dari F, dan naik atau turun seiring rekam jejaknya. Kedua, kesimpulan analis tidak diberi kode Admiralty; kode menempel pada butir informasi, sedangkan kesimpulan memakai bahasa probabilitas dan keyakinan (bagian 3.3) [S1].

Untuk sumber siber, terjemahkan "rekam jejak" menjadi pertanyaan yang bisa dijawab:

| Sumber | Pertanyaan penilaian keandalan | Kode awal yang wajar |
|---|---|---|
| Telemetri sendiri (EDR, proxy) | Apakah sensor terkonfigurasi benar dan waktu tersinkron? | A untuk keandalan, kredibilitas tetap dinilai per data |
| Laporan vendor dengan bukti teknis | Apakah klaim lama vendor ini pernah dikoreksi? Apakah mereka menunjukkan bukti? | B |
| Advisori pemerintah | Apakah advisori menyebut dasar klaimnya? | B, bisa A untuk klaim teknis yang dapat diuji |
| Blog peneliti independen | Apakah penulis punya rekam jejak dan metode terbuka? | C sampai F |
| Akun media sosial anonim | Ada riwayat yang bisa diperiksa? | F atau E |

Angka kredibilitas menyangkut isi, jadi laporan vendor B bisa membawa informasi 2 (teknik yang dijelaskan dengan sampel), 3 (atribusi tanpa bukti yang ditunjukkan), atau 6 (klaim tentang niat aktor).

### 3.3 Bahasa probabilitas dan keyakinan

Kata seperti "mungkin" atau "kemungkinan besar" ditafsirkan sangat berbeda oleh pembaca. Survei yang dikutip pemerintah Inggris menunjukkan frasa seperti "realistic possibility" dibaca dari sekitar 10% sampai hampir pasti oleh orang yang berbeda [S3]. Karena itu standar analitik menetapkan istilah dengan rentang angka.

| ICD 203 (istilah utama) | Padanan ICD 203 | Rentang | PHIA Probability Yardstick (UK) | Rentang PHIA |
|---|---|---|---|---|
| almost no chance | remote | 1-5% | remote chance | >0 sampai sekitar 5% |
| very unlikely | highly improbable | 5-20% | highly unlikely | sekitar 10-20% |
| unlikely | improbable | 20-45% | unlikely | sekitar 25-35% |
| roughly even chance | roughly even odds | 45-55% | realistic possibility | sekitar 40 sampai <50% |
| likely | probable | 55-80% | likely atau probable | sekitar 55-75% |
| very likely | highly probable | 80-95% | highly likely | sekitar 80-90% |
| almost certain | nearly certain | 95-99% | almost certain | sekitar 95 sampai <100% |

Sumber: ICD 203 [S2], PHIA [S3]. Skala PHIA sengaja punya celah antar rentang agar tidak memberi kesan presisi palsu [S3]. Pilih satu skala untuk tim-mu, tulis di template produk, dan jangan mencampur istilah dari dua skala dalam satu dokumen.

Keyakinan (confidence) adalah hal lain. Probabilitas menjawab "seberapa mungkin hal ini benar atau terjadi"; keyakinan menjawab "seberapa kuat dasar penilaian kita". ICD 203 meminta analis menyatakan keduanya secara eksplisit dan menjelaskan dasar ketidakpastiannya [S2]. Pedoman praktis tingkat keyakinan yang umum dipakai tim CTI:

| Keyakinan | Dasar yang biasanya dibutuhkan |
|---|---|
| High | Beberapa sumber independen berkualitas tinggi, sedikit gap, alternatif sudah diuji dan lemah |
| Moderate | Sumber kredibel tetapi belum terkonfirmasi silang, atau ada gap penting |
| Low | Sumber terbatas atau kualitasnya dipertanyakan, banyak asumsi |

Contoh kalimat yang benar: "Kami menilai kemungkinan besar (likely) aktor masuk lewat akun VPN vendor. Keyakinan sedang: bukti log kuat, tetapi kami belum bisa memeriksa perangkat vendor." Probabilitas dan keyakinan ditulis di kalimat terpisah agar tidak dibaca sebagai satu angka.

### 3.4 Fakta, penilaian, spekulasi

| Jenis | Arti | Contoh (fiktif) |
|---|---|---|
| Fakta | Observasi yang bisa diverifikasi | "Domain X di-resolve oleh host Y pada 2026-10-08 02:14 UTC menurut log DNS." |
| Penilaian | Kesimpulan dari bukti, dengan probabilitas dan keyakinan | "Kemungkinan besar domain X bagian dari kampanye Z (keyakinan sedang)." |
| Spekulasi | Dugaan tanpa dasar bukti kuat, ditandai jelas | "Bila pola ini berlanjut, aktor bisa saja beralih ke sektor lain." |

Teknik sederhana agar pembaca tahu jenis kalimat: fakta memakai kata kerja observasi ("tercatat di log"), penilaian diawali "kami menilai", dan spekulasi diberi label atau dihindari di produk eksekutif.

### 3.5 Bias kognitif dan penangkalnya

Heuer menunjukkan bahwa bias kognitif tidak hilang hanya karena analis menyadarinya; yang membantu adalah prosedur yang memaksa penalaran keluar dari jalur kebiasaan [S4].

| Bias | Bentuknya di CTI | Penangkal |
|---|---|---|
| Confirmation bias | Hanya mencari log yang mendukung dugaan awal | ACH; tulis bukti yang akan membantah sebelum mencari |
| Anchoring | Penilaian pertama di tiket dipertahankan walau bukti berubah | Penilaian ulang terjadwal; rekan menilai tanpa melihat kesimpulan awal |
| Mirror imaging | Mengira aktor akan memilih cara yang menurut kita masuk akal | Red Team Analysis: tulis rencana dari sudut aktor |
| Availability | Ancaman yang sedang ramai di berita dianggap paling mungkin | Bandingkan dengan data insiden sektor, bukan berita |
| Attribution bias | Teknik mirip langsung dianggap aktor yang sama | Pisahkan clustering dari atribusi; ACH dengan hipotesis "aktor lain memakai alat sama" |

### 3.6 Structured analytic techniques

Tradecraft Primer pemerintah Amerika Serikat (2009) mengelompokkan teknik terstruktur menjadi tiga jenis [S5]:

| Kelompok | Teknik | Kapan berguna di CTI |
|---|---|---|
| Diagnostic | Key Assumptions Check, Quality of Information Check, Indicators or Signposts of Change, ACH | Menilai atribusi, menguji kesimpulan insiden, menentukan indikator yang dipantau |
| Contrarian | Devil's Advocacy, Team A/Team B, High-Impact/Low-Probability Analysis, "What If?" Analysis | Menantang konsensus tim, menyiapkan skenario jarang tetapi berdampak besar |
| Imaginative thinking | Brainstorming, Outside-In Thinking, Red Team Analysis, Alternative Futures Analysis | Threat modeling, memperkirakan langkah aktor berikutnya |

Tiga teknik paling sering dipakai di CTI harian:

- **Key Assumptions Check:** daftar asumsi yang mendasari kesimpulan, lalu untuk setiap asumsi tanya: kenapa kita yakin ini benar, dalam kondisi apa ia salah, dan apa dampaknya pada kesimpulan bila salah. Asumsi yang lemah tetapi menopang kesimpulan adalah titik yang harus diselidiki dulu.
- **Quality of Information Check:** periksa sumber yang paling menentukan kesimpulan. Apakah ada konfirmasi independen? Apakah ada laporan yang sudah ditarik atau dikoreksi? Apakah informasi ambigu sudah diberi catatan? [S5]
- **Indicators or Signposts of Change:** daftar observasi yang, bila muncul, menandakan penilaian perlu diubah. Di CTI ini sering menjadi daftar pemantauan atau bahkan rule deteksi.

### 3.7 Analysis of Competing Hypotheses

ACH dikembangkan Richards Heuer untuk melawan confirmation bias dengan menguji beberapa hipotesis sekaligus terhadap seluruh bukti [S4]. Delapan langkahnya:

1. Identifikasi semua hipotesis yang masuk akal, sebaiknya lewat diskusi kelompok; termasuk yang tidak disukai.
2. Daftar bukti dan argumen yang signifikan, termasuk asumsi dan ketiadaan bukti yang seharusnya ada.
3. Susun matriks bukti terhadap hipotesis; tandai setiap sel konsisten (C), tidak konsisten (I), atau tidak relevan/netral (N).
4. Perbaiki matriks: hapus bukti yang tidak diagnostik (konsisten dengan semua hipotesis), gabungkan atau pecah hipotesis bila perlu.
5. Tarik kesimpulan sementara dengan mencoba membantah setiap hipotesis; yang paling sedikit inkonsistensinya paling kuat.
6. Analisis sensitivitas: bukti mana yang paling menentukan, dan bagaimana kesimpulan berubah bila bukti itu salah atau hasil penipuan.
7. Laporkan kesimpulan dengan membahas kemungkinan relatif semua hipotesis, bukan hanya pemenangnya.
8. Tetapkan milestone: observasi masa depan yang akan menandakan kesimpulan perlu diubah.

Inti ACH adalah logika pembantahan. Seratus bukti yang konsisten tidak membuktikan hipotesis bila bukti itu juga konsisten dengan hipotesis lain, sedangkan satu bukti kuat yang tidak konsisten bisa menggugurkannya. Karena itu menghitung C tidak berguna; yang dihitung adalah I, dan bobot I bergantung pada kualitas buktinya. Contoh kerja lengkap ada di bagian 4.3.

### 3.8 Atribusi dan kerendahan hati analitis

Atribusi (menisbahkan aktivitas ke aktor) adalah penilaian tersulit dan paling rawan bias.

- Atribusi adalah penilaian berprobabilitas dan berkeyakinan, bukan fakta.
- Bedakan tiga tingkat: clustering aktivitas ("cluster A dan B berbagi infrastruktur dan tooling"), atribusi ke kelompok yang dilacak ("cluster ini kemungkinan besar kelompok X"), dan atribusi ke entitas nyata (negara, organisasi, orang). Kebanyakan tim enterprise cukup sampai tingkat pertama atau kedua, karena keputusan defensif jarang bergantung pada tingkat ketiga.
- Indikator teknis bisa dipalsukan atau dibagi bersama: infrastruktur sewaan, malware yang dijual bebas, dan alat red team yang bocor dipakai banyak pihak.
- Jangan menyimpulkan dari satu jenis bukti. Atribusi yang kuat biasanya menggabungkan infrastruktur, tooling, TTP, korban, dan waktu operasi.

Menyatakan batas dan ketidakpastian adalah tanda tradecraft matang. Produk yang jujur tentang keyakinannya lebih dipercaya, dan ketika ternyata salah, kerusakannya lebih kecil karena pembaca sudah tahu batasnya.

## 4. Contoh artefak intelijen

Semua contoh fiktif dan berlabel ilustrasi. Kasusnya: Sabtu 2026-10-03, sekitar 600 file di file server keuangan PT Logistik Contoh berubah ekstensi menjadi `.lck` dan muncul file catatan tebusan di setiap folder.

### 4.1 Kode Admiralty untuk butir informasi kasus

| Butir | Sumber | Kode | Alasan |
|---|---|---|---|
| E1: login VPN akun `vendor.it01` dari 198.51.100[.]23 pukul 01:40 | Log VPN sendiri | A1 | Sensor sendiri, waktu tersinkron, terlihat juga di log firewall |
| E2: `vssadmin delete shadows` dijalankan di file server pukul 02:05 | EDR | A1 | Tercatat di EDR dan event log server |
| E3: 198.51.100[.]23 pernah dipakai afiliasi ransomware | Laporan vendor publik | B3 | Vendor umumnya andal, tetapi laporan tidak menunjukkan bukti teknis untuk IP ini |
| E4: Seorang staf keuangan menerima surat pemutusan kontrak Jumat | HR | A1 | Fakta administratif |
| E5: Tidak ada pengujian red team atau proyek enkripsi di change calendar | Change management | B2 | Kalender kadang tidak lengkap |
| E6: Posting anonim di media sosial mengklaim "orang dalam" pelakunya | Akun anonim | F6 | Tidak ada dasar menilai |

### 4.2 Key Assumptions Check untuk dugaan awal

Dugaan awal tim pada Sabtu pagi: "Ini ransomware oleh afiliasi kriminal dari luar."

| Asumsi | Kenapa dianggap benar | Kapan bisa salah | Dampak bila salah |
|---|---|---|---|
| Akun `vendor.it01` dipakai pihak luar | Login dari IP asing di luar jam kerja vendor | Vendor memang bekerja malam dari luar negeri | Tinggi: hipotesis orang dalam atau kelalaian vendor naik |
| IP 198.51.100[.]23 milik afiliasi ransomware | Laporan vendor (B3) | IP adalah VPN komersial yang dipakai banyak orang | Sedang: tidak menggugurkan, tetapi melemahkan kaitan |
| Penghapusan shadow copy bagian dari serangan | Pola umum ransomware | Admin menghapusnya untuk alasan ruang disk | Rendah: waktunya 25 menit sebelum enkripsi |

**Cara membaca hasil:** asumsi pertama paling menentukan dan paling murah dicek: telepon kontak vendor dan minta log sisi mereka. Itu tindakan pertama, sebelum menulis atribusi apa pun.

### 4.3 Matriks ACH

Hipotesis:

- H1: serangan ransomware oleh pihak luar lewat akun vendor yang dicuri.
- H2: sabotase orang dalam (staf yang kontraknya diputus) yang meniru ransomware.
- H3: kesalahan operasional, misalnya alat enkripsi atau backup yang salah konfigurasi.
- H4: pengujian red team yang tidak terkoordinasi.

| Bukti | Kode | H1 | H2 | H3 | H4 |
|---|---|---|---|---|---|
| E0: file berubah ekstensi dan ada catatan tebusan | A1 | C | C | I | C |
| E1: login VPN `vendor.it01` dari IP asing 01:40 | A1 | C | N | I | C |
| E2: penghapusan shadow copy 02:05 | A1 | C | C | I | I |
| E3: IP pernah dipakai afiliasi ransomware | B3 | C | I | I | I |
| E4: staf keuangan diputus kontraknya | A1 | N | C | N | N |
| E5: tidak ada pengujian atau proyek terjadwal | B2 | N | N | I | I |
| E6: klaim anonim "orang dalam" | F6 | N | C | N | N |
| Jumlah I | | 0 | 1 | 5 | 3 |

Catatan pengisian: E2 ditandai I untuk H4 karena aturan keterlibatan red team biasanya melarang aksi destruktif di sistem produksi. E4 dan E6 konsisten dengan H2 tetapi netral untuk yang lain, jadi keduanya mendukung H2 tanpa membantah H1. Di sini letak jebakan anchoring: E4 terasa kuat secara emosional, padahal ia tidak membedakan H1 dari H2.

**Kesimpulan sementara:** H3 dan H4 gugur (lima dan tiga inkonsistensi, termasuk bukti A1). H1 tidak punya inkonsistensi. H2 hanya punya satu, dan inkonsistensi itu berasal dari E3 yang berkode B3.

**Analisis sensitivitas:** bila E3 salah (IP itu ternyata VPN komersial biasa), H2 tidak lagi punya inkonsistensi dan bersaing ketat dengan H1. Jadi kesimpulan bertumpu pada butir paling lemah di matriks. Pembeda yang dibutuhkan adalah bukti yang hanya konsisten dengan salah satu hipotesis: apakah staf yang diputus pernah punya akses ke kredensial `vendor.it01`, dan apakah vendor mengonfirmasi akun itu tidak dipakai mereka.

**Laporan (ringkas):**

```
Penilaian (fiktif, 2026-10-03 14:00):
Kami menilai kemungkinan besar (likely) enkripsi file server keuangan
dilakukan pihak luar yang memakai akun VPN vendor.it01. Keyakinan sedang.
Dasar: login VPN dari IP asing (A1) diikuti penghapusan shadow copy (A1);
  IP tersebut pernah dilaporkan dipakai afiliasi ransomware (B3).
Alternatif: sabotase orang dalam belum dapat dikesampingkan (unlikely,
  bukan almost no chance); bukti yang mendukungnya (pemutusan kontrak,
  klaim anonim F6) tidak membedakan kedua hipotesis.
Yang akan mengubah penilaian: konfirmasi vendor tentang akun, dan apakah
  staf terkait pernah memegang kredensial vendor.it01.
```

### 4.4 Menulis ulang penilaian yang terlalu yakin

Versi buruk: "Serangan ini dilakukan oleh kelompok ransomware X dari Eropa Timur yang menargetkan sektor logistik. IP penyerang adalah 198.51.100[.]23."

Masalahnya: atribusi ke kelompok dan wilayah tanpa dasar yang ditunjukkan, tidak ada probabilitas atau keyakinan, "IP penyerang" mencampur fakta (IP yang login) dengan penilaian (IP milik penyerang), dan tidak ada alternatif.

Versi yang lebih baik: "Akun VPN vendor.it01 login dari 198.51.100[.]23 sebelum enkripsi (fakta, log VPN). Satu laporan vendor mengaitkan IP ini dengan afiliasi ransomware (B3). Kami belum punya dasar untuk mengaitkan insiden ini dengan kelompok tertentu; keyakinan atribusi rendah. Bila sampel encryptor tersedia, perbandingan dengan sampel publik dapat menaikkan keyakinan."

## 5. Lab praktik

Lab ini memakai editor teks saja. Skenario fiktif; jangan pakai data kerja; jangan mengakses forum kriminal.

1. **Kode sumber.** Ambil lima sumber fiktif (SIEM, vendor, blog peneliti, akun anonim, ISAC) dan beri kode Admiralty untuk satu butir informasi dari masing-masing. Tulis alasan huruf dan angka secara terpisah.
2. **Bahasa probabilitas.** Tulis tiga penilaian fiktif dengan istilah ICD 203 atau PHIA, masing-masing dengan kalimat keyakinan terpisah dan dasar ketidakpastiannya.
3. **Fakta, penilaian, spekulasi.** Ambil satu paragraf laporan publik apa pun dan tandai setiap kalimat. Hitung berapa kalimat penilaian yang tidak menyebut keyakinan.
4. **Key Assumptions Check.** Untuk kasus bagian 4, tambahkan dua asumsi yang belum ada di tabel 4.2 dan nilai dampaknya.
5. **ACH.** Buat kasus fiktif sendiri (misalnya akun cloud admin login dari negara tak biasa) dengan minimal empat hipotesis dan enam bukti berkode Admiralty. Isi matriks, hitung I, lalu lakukan analisis sensitivitas pada bukti terlemah.
6. **Atribusi.** Tulis satu pernyataan atribusi yang memisahkan clustering dari atribusi, menyebut keyakinan, dan menyebut kemungkinan false flag.
7. **Indicators of change.** Untuk kesimpulan ACH-mu, tulis dua observasi yang akan menaikkan keyakinan dan dua yang akan mengubah kesimpulan (lihat baris "Yang akan mengubah penilaian" di bagian 4.3).

**Hasil yang sebaiknya tersimpan:**

- Lima butir informasi dengan kode Admiralty dan alasannya.
- Tiga penilaian dengan probabilitas dan keyakinan di kalimat terpisah.
- Paragraf laporan yang sudah ditandai per kalimat.
- Tabel Key Assumptions Check.
- Matriks ACH lengkap dengan jumlah I, catatan bukti non-diagnostik, dan analisis sensitivitas.
- Pernyataan atribusi dan daftar indicators of change.

**Variasi tantangan:** kerjakan ACH yang sama dengan seorang rekan secara terpisah, lalu bandingkan isi sel yang berbeda. Perbedaan di sel biasanya menunjukkan asumsi yang tidak ditulis; diskusikan sampai asumsi itu eksplisit.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Atribusi terasa terlalu yakin | Hipotesis tunggal, attribution bias | Jalankan ACH; turunkan ke tingkat clustering bila bukti kurang |
| Pembaca salah paham kepastian | Fakta dan penilaian tercampur | Tandai setiap kalimat; pakai "kami menilai" untuk penilaian |
| "Mungkin" dipakai untuk menghindar | Takut berkomitmen | Pakai istilah dari skala yang dipilih tim |
| Matriks ACH semua C | Bukti tidak diagnostik atau hipotesis terlalu mirip | Cari bukti pembeda; gabungkan hipotesis yang tidak bisa dibedakan |
| Kesimpulan ACH berubah total saat satu sel diubah | Kesimpulan bertumpu pada satu bukti lemah | Laporkan sensitivitasnya; cari konfirmasi untuk bukti itu |

## 7. Kesalahan umum dan jebakan

- Memberi satu kode untuk sumber dan isi sekaligus. Kode Admiralty selalu dua karakter, dan isinya dinilai terpisah dari reputasi sumber.
- Mengode kesimpulan dengan Admiralty. Kode menempel pada butir informasi; kesimpulan memakai probabilitas dan keyakinan.
- Menghitung C di ACH. Yang menentukan adalah inkonsistensi dan kualitas bukti di balik inkonsistensi itu.
- Melewatkan analisis sensitivitas. Kesimpulan ACH yang bertumpu pada satu butir B3 harus dilaporkan begitu.
- Mencampur skala ICD 203 dan PHIA. Pilih satu dan tulis di template.
- Menganggap kesadaran bias sudah cukup. Heuer menunjukkan bias bertahan walau disadari; prosedur yang membantu [S4].

## 8. Catatan terkini

- ICD 203 ditandatangani pada 2 Januari 2015 dan mendapat amandemen teknis pada Desember 2022; tabel istilah probabilitas di bagian 3.3 tetap sama. Cek teks terbaru di situs ODNI bila kamu memakainya sebagai standar resmi [S2].
- Pemerintah Inggris menerbitkan penjelasan publik tentang PHIA Probability Yardstick pada Maret 2025, termasuk alasan skala ini memakai celah antar rentang [S3].
- Banyak vendor CTI memakai penamaan cluster (misalnya awalan UNC, TA, atau Storm) sebelum atribusi penuh. Penamaan ini adalah praktik kerendahan hati analitis dalam bentuk konkret.
- Day 04 masuk ke framework (Kill Chain, Diamond, ATT&CK, Pyramid of Pain) yang menstrukturkan analisis teknis.

## 9. Cheat sheet

```
ADMIRALTY   sumber A-F (rekam jejak) + info 1-6 (logis, terkonfirmasi) ; dinilai TERPISAH ; mis. B3
            F/6 = belum bisa dinilai, bukan buruk ; kesimpulan TIDAK dikode
ICD 203     almost no chance 1-5 | very unlikely 5-20 | unlikely 20-45 | roughly even 45-55
            likely 55-80 | very likely 80-95 | almost certain 95-99 (%)
PHIA        remote chance | highly unlikely | unlikely | realistic possibility | likely | highly likely | almost certain (ada celah)
KEYAKINAN   high/moderate/low = kekuatan DASAR penilaian ; tulis di kalimat terpisah dari probabilitas
KALIMAT     fakta (tercatat di...) | penilaian (kami menilai... + keyakinan) | spekulasi (diberi label)
BIAS        confirmation | anchoring | mirror imaging | availability | attribution
SAT         diagnostic: KAC, QoI check, indicators, ACH | contrarian: devil's advocacy, team A/B, HILP, what-if
            imaginative: brainstorming, outside-in, red team, alternative futures
ACH         hipotesis -> bukti -> matriks C/I/N -> buang non-diagnostik -> hitung I -> sensitivitas -> lapor semua -> milestone
ATRIBUSI    clustering < kelompok dilacak < entitas nyata ; jangan dari satu jenis bukti
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Admiralty code (ringkasan skala keandalan sumber dan kredibilitas informasi, merujuk US Army FM 2-22.3 dan UK JWP 2-00) | https://en.wikipedia.org/wiki/Admiralty_code | sekunder | diakses 2026-10-10 | Sedang. Label skala cocok dengan FM 2-22.3 lampiran B; cocokkan dengan doktrin primer bila dipakai formal |
| S2 | Office of the Director of National Intelligence: Intelligence Community Directive 203, Analytic Standards | https://www.dni.gov/files/documents/ICD/ICD-203.pdf | primer | 2015-01-02, amandemen 2022; diakses 2026-10-10 | Tinggi. Situs menolak akses otomatis; tabel istilah probabilitas juga direproduksi di taksonomi MISP estimative-language |
| S3 | UK Government: Explaining uncertainty in UK intelligence assessment (PHIA Probability Yardstick) | https://www.gov.uk/government/publications/explaining-uncertainty-in-uk-intelligence-assessment/explaining-uncertainty-in-uk-intelligence-assessment | primer | 2025-03-24; diakses 2026-10-10 | Tinggi |
| S4 | Richards J. Heuer Jr.: Psychology of Intelligence Analysis (CIA Center for the Study of Intelligence) | https://www.cia.gov/resources/csi/books-monographs/psychology-of-intelligence-analysis-2/ | primer | 1999; diakses 2026-10-10 | Tinggi. Bias kognitif dan delapan langkah ACH (bab 8) |
| S5 | US Government: A Tradecraft Primer: Structured Analytic Techniques for Improving Intelligence Analysis | https://www.cia.gov/resources/csi/static/Tradecraft-Primer-apr09.pdf | primer | 2009-03; diakses 2026-10-10 | Tinggi. Pengelompokan SAT dan Quality of Information Check |

**Catatan sumber:** rentang persen ICD 203 dikutip dari teks direktif sebagaimana direproduksi di sumber sekunder (taksonomi MISP); cocokkan dengan PDF ODNI bila tersedia. Tabel tingkat keyakinan high/moderate/low di bagian 3.3 adalah pedoman praktik umum, bukan definisi resmi ICD 203. Kode awal untuk jenis sumber siber di bagian 3.2 adalah titik mulai yang wajar, bukan peringkat baku.
