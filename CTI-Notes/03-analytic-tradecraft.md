---
day: 03
title: 'Analytic tradecraft: keandalan sumber (Admiralty), bahasa keyakinan, bias kognitif, dan ACH'
researched_on: 2026-10-10
versions_checked: 'ICD 203 (2015, amandemen teknis 2022); PHIA Probability Yardstick (gov.uk, Maret 2025); Tradecraft Primer (US Government, 2009); Heuer, Psychology of Intelligence Analysis (1999); skala Admiralty dari FM 2-22.3'
---

# Day 03: Analytic tradecraft

Cakupan: cara berpikir analis intelijen, yaitu menilai sumber dan informasi dengan skala Admiralty, menyatakan probabilitas dan keyakinan dengan istilah terdefinisi, mengenali bias, dan memakai structured analytic techniques seperti Key Assumptions Check dan ACH dengan contoh kerja.

## Ide inti

Tahap analysis dalam siklus intelijen (Day 02) adalah tempat data menjadi intelijen, dan di sinilah tradecraft menentukan kualitas. Dua analis dengan data yang sama bisa sampai ke kesimpulan berbeda. Yang membedakan analis yang bisa dipercaya adalah disiplinnya: menilai sumber dan isi informasi secara terpisah, menyatakan probabilitas dan keyakinan dengan istilah yang terdefinisi, menyadari bias, dan menguji penjelasan alternatif sebelum memilih satu. Tanpa itu, CTI berubah menjadi tebakan yang terdengar yakin karena dibungkus bahasa teknis.

Bagi analis forensik dan SOC, prinsipnya sudah akrab. Di forensik kamu menjaga rantai bukti dan memisahkan artefak dari interpretasi: "file ini dibuat pukul 02:05" berbeda dari "penyerang membuat file ini". Saat triage alert, kamu juga menimbang beberapa penjelasan sekaligus (serangan nyata, aktivitas admin yang sah, salah konfigurasi) sebelum menutup tiket, dan kamu memberi confidence pada alert berdasarkan kekuatan bukti, bukan berdasarkan dampaknya. Yang baru di Day ini adalah kosakata dan teknik terstruktur supaya penalaran itu bisa ditulis dan diperiksa rekan.

```
Butir informasi (log sendiri, laporan vendor, HR, posting anonim)
  -> nilai sumber (A-F) dan isi (1-6) secara terpisah  -> kode Admiralty per butir
  -> tulis asumsi yang menopang dugaan awal            -> Key Assumptions Check
  -> uji beberapa hipotesis terhadap semua bukti       -> ACH: hitung I, bukan C
  -> cek bukti mana yang paling menentukan             -> analisis sensitivitas
  -> tulis penilaian: probabilitas + keyakinan (kalimat terpisah) + alternatif + apa yang akan mengubahnya
Kode Admiralty menempel di butir informasi; kesimpulan memakai probabilitas dan keyakinan.
```

Situasi yang dipakai sepanjang Day ini: Sabtu 2026-10-03, sekitar 600 file di file server keuangan PT Logistik Contoh (PT LC, perusahaan logistik fiktif dengan gudang di Jakarta, Surabaya, dan Medan, dan banyak vendor yang masuk lewat VPN) berubah ekstensi menjadi `.lck`, dan muncul file catatan tebusan di setiap folder. Dugaan awal yang tertulis di tiket pagi itu: ransomware oleh afiliasi kriminal dari luar. Menjelang siang, CISO meneruskan pesan dari direksi:

> "HR bilang ada staf keuangan yang kemarin menerima surat pemutusan kontrak, dan ada akun anonim di media sosial yang menulis pelakunya orang dalam. Sebelum rapat jam dua, saya perlu tahu: ini serangan dari luar atau orang dalam? Seberapa bisa dipercaya info-info itu, dan seberapa yakin kalian?"

Pesan itu memuat lima pertanyaan:

1. Seberapa bisa dipercaya setiap informasi yang dimiliki tim, dari log VPN sampai posting anonim?
2. Bagaimana menyatakan "seberapa yakin" supaya semua direktur membacanya sama?
3. Bagaimana memisahkan apa yang tercatat di log dari tafsiran tim?
4. Bagaimana tim tidak terseret dugaan awal di tiket atau kabar yang terasa kuat secara emosional?
5. Bagaimana menguji "dari luar atau orang dalam" dan menulis jawaban atas "siapa pelakunya"?

Pertanyaan 1 dijawab di bagian 1.1 sampai 1.3 dan 2.1, pertanyaan 2 di bagian 1.4 dan 1.5, pertanyaan 3 di bagian 1.6, pertanyaan 4 di bagian 1.7, 1.8, dan 2.2, dan pertanyaan 5 di bagian 1.9, 1.10, 2.3, dan 2.4.

**Kapan relevan:** setiap penilaian intelijen, atribusi, jawaban RFI, dan produk tertulis.
**Kapan bukan jawaban:** teknik formal seperti ACH memakan waktu dan tidak cocok untuk RFI yang harus dijawab dalam satu jam. Untuk kasus seperti itu, pakai versi ringkas: kode sumber, satu kalimat keyakinan, dan satu alternatif yang dipertimbangkan.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Tabel ini memuat istilah yang muncul di Day ini. Kolom padanan memakai analogi SOC yang sama di semua Day CTI. Istilah dari Day sebelumnya (CTI, TTP, PIR, RFI, siklus intelijen dan tahap-tahapnya) tidak diulang; bahasa keyakinan dari Day 01 diulang karena Day ini memisahkannya dari probabilitas.

| Istilah | Arti singkat | Padanan di SOC |
|---|---|---|
| Analytic tradecraft | Disiplin penalaran analis yang bisa ditulis dan diperiksa rekan | Disiplin forensik: rantai bukti, artefak dipisah dari interpretasi |
| Keandalan sumber (reliability) | Seberapa bisa dipercaya sumbernya, dari rekam jejak dan kemampuannya mengetahui hal yang dilaporkan | Kualitas log source: sensor terkonfigurasi benar, waktu tersinkron |
| Kredibilitas informasi (credibility) | Seberapa masuk akal isi informasinya, dari logika dan konfirmasi sumber lain | Apakah satu event masuk akal dan terlihat juga di log lain |
| Kode Admiralty | Kode dua karakter: huruf untuk sumber, angka untuk isi (mis. B2) | Dua kolom terpisah: kualitas log source dan kualitas event |
| Bahasa probabilitas | Istilah baku dengan rentang angka untuk menyatakan seberapa mungkin sesuatu benar atau terjadi | "Kemungkinan besar true positive" di tiket, tetapi dengan rentang baku |
| Keyakinan (confidence) | Seberapa kuat dasar sebuah penilaian | Confidence pada alert |
| ICD 203 dan PHIA | Dua standar pemerintah (AS dan Inggris) yang menetapkan istilah probabilitas | Kamus severity yang disepakati tim |
| Fakta, penilaian, spekulasi | Observasi, kesimpulan dari bukti, dan dugaan tanpa dasar kuat | Artefak, interpretasi, dan dugaan di laporan forensik |
| Bias kognitif | Pola pikir yang menyimpangkan penilaian secara sistematis | Bertahan pada penilaian pertama di tiket walau bukti berubah |
| Structured analytic techniques (SAT) | Prosedur yang memaksa penalaran keluar dari jalur kebiasaan | Checklist investigasi yang memaksa memeriksa jalur lain |
| Key Assumptions Check | Daftar asumsi di balik kesimpulan beserta kapan asumsi itu salah | Menulis asumsi di catatan triage ("akun ini dipakai vendor") lalu mengeceknya |
| ACH | Analysis of Competing Hypotheses: menguji beberapa hipotesis terhadap seluruh bukti | Triage yang menguji beberapa penjelasan sekaligus: serangan, aktivitas sah, salah konfigurasi |
| Bukti diagnostik | Bukti yang membedakan satu hipotesis dari yang lain | Artefak yang hanya muncul bila penjelasan tertentu benar |
| Analisis sensitivitas | Memeriksa bagaimana kesimpulan berubah bila bukti tertentu salah | "Kalau log ini keliru, apakah kesimpulan tiketnya berubah?" |
| Atribusi dan clustering | Menisbahkan aktivitas ke aktor; clustering mengelompokkan aktivitas tanpa menyebut aktor | Mengelompokkan alert yang berbagi infrastruktur sebelum menamai pelakunya |

### 1.1 Keandalan sumber dan kredibilitas informasi

Pada Sabtu pagi tim PT LC punya butir informasi dari sumber yang sangat berbeda: log VPN sendiri, EDR, laporan vendor, HR, change calendar, dan posting anonim. Pertanyaan direksi "seberapa bisa dipercaya?" sebenarnya dua pertanyaan.

Dua hal ini berbeda dan sering dicampur [S1]:

- **Keandalan sumber (reliability):** seberapa bisa dipercaya sumbernya, dinilai dari rekam jejak dan kemampuannya mengetahui hal yang dilaporkan. Skala huruf A sampai F.
- **Kredibilitas informasi (credibility):** seberapa masuk akal informasi itu sendiri, dinilai dari konsistensi logis dan konfirmasi oleh sumber lain. Skala angka 1 sampai 6.

Keduanya dinilai terpisah agar reputasi sumber tidak memengaruhi penilaian isi. Hasilnya kode dua karakter seperti B2. Pemisahan ini mencegah dua kesalahan klasik: percaya informasi lemah karena sumbernya bagus, atau membuang informasi kuat karena sumbernya baru.

### 1.2 Skala Admiralty

Supaya enam butir informasi PT LC dinilai dengan ukuran yang sama, tim memakai skala Admiralty. Skala ini memberi setiap butir dua penilaian yang bisa dibandingkan dan diperiksa rekan.

Dua tabel berikut adalah skalanya. Tabel pertama menilai sumber, tabel kedua menilai isi; perhatikan baris terakhir masing-masing, karena keduanya paling sering disalahartikan.

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

Dua hal yang sering terlewat. Pertama, F dan 6 bukan nilai buruk; artinya "belum bisa dinilai". Sumber baru selalu mulai dari F, dan naik atau turun seiring rekam jejaknya. Kedua, kesimpulan analis tidak diberi kode Admiralty; kode menempel pada butir informasi, sedangkan kesimpulan memakai bahasa probabilitas dan keyakinan (bagian 1.4 dan 1.5) [S1].

### 1.3 Admiralty untuk sumber siber

Skala Admiralty lahir dari dunia intelijen klasik, sedangkan sumber PT LC adalah EDR, log VPN, laporan vendor, dan akun media sosial. "Rekam jejak" perlu diterjemahkan ke pertanyaan yang bisa dijawab untuk sumber seperti itu.

Tabel berikut memberi pertanyaan penilaian dan kode awal untuk jenis sumber yang umum di CTI. Kolom terakhir adalah titik mulai yang wajar, bukan peringkat baku.

| Sumber | Pertanyaan penilaian keandalan | Kode awal yang wajar |
|---|---|---|
| Telemetri sendiri (EDR, proxy) | Apakah sensor terkonfigurasi benar dan waktu tersinkron? | A untuk keandalan, kredibilitas tetap dinilai per data |
| Laporan vendor dengan bukti teknis | Apakah klaim lama vendor ini pernah dikoreksi? Apakah mereka menunjukkan bukti? | B |
| Advisori pemerintah | Apakah advisori menyebut dasar klaimnya? | B, bisa A untuk klaim teknis yang dapat diuji |
| Blog peneliti independen | Apakah penulis punya rekam jejak dan metode terbuka? | C sampai F |
| Akun media sosial anonim | Ada riwayat yang bisa diperiksa? | F atau E |

Angka kredibilitas menyangkut isi, jadi laporan vendor B bisa membawa informasi 2 (teknik yang dijelaskan dengan sampel), 3 (atribusi tanpa bukti yang ditunjukkan), atau 6 (klaim tentang niat aktor).

### 1.4 Bahasa probabilitas

Direksi PT LC bertanya "seberapa yakin kalian". Bila tim menjawab "mungkin dari luar", setiap direktur bisa membaca kata "mungkin" dengan angka yang berbeda.

Kata seperti "mungkin" atau "kemungkinan besar" ditafsirkan sangat berbeda oleh pembaca. Survei yang dikutip pemerintah Inggris menunjukkan frasa seperti "realistic possibility" dibaca dari sekitar 10% sampai hampir pasti oleh orang yang berbeda [S3]. Karena itu standar analitik menetapkan istilah dengan rentang angka.

Tabel berikut menyandingkan dua skala resmi. Cari baris yang rentangnya cocok dengan penilaianmu, lalu pakai istilah dari satu skala saja.

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

### 1.5 Keyakinan terpisah dari probabilitas

Misalkan tim PT LC menilai "kemungkinan besar dari luar". Kalimat itu belum memberi tahu direksi seberapa kuat dasarnya: log VPN dan EDR kuat, tetapi perangkat vendor belum bisa diperiksa.

Keyakinan (confidence) adalah hal lain. Probabilitas menjawab "seberapa mungkin hal ini benar atau terjadi"; keyakinan menjawab "seberapa kuat dasar penilaian kita". ICD 203 meminta analis menyatakan keduanya secara eksplisit dan menjelaskan dasar ketidakpastiannya [S2]. Di SOC, ini sama dengan confidence pada alert: ia menilai kekuatan bukti dan sumber, bukan seberapa parah dampaknya.

Tabel berikut adalah pedoman praktis tingkat keyakinan yang umum dipakai tim CTI. Pakai untuk memeriksa apakah dasar penilaianmu cukup untuk tingkat keyakinan yang kamu tulis.

| Keyakinan | Dasar yang biasanya dibutuhkan |
|---|---|
| High | Beberapa sumber independen berkualitas tinggi, sedikit gap, alternatif sudah diuji dan lemah |
| Moderate | Sumber kredibel tetapi belum terkonfirmasi silang, atau ada gap penting |
| Low | Sumber terbatas atau kualitasnya dipertanyakan, banyak asumsi |

Contoh kalimat yang benar: "Kami menilai kemungkinan besar (likely) aktor masuk lewat akun VPN vendor. Keyakinan sedang: bukti log kuat, tetapi kami belum bisa memeriksa perangkat vendor." Probabilitas dan keyakinan ditulis di kalimat terpisah agar tidak dibaca sebagai satu angka.

### 1.6 Fakta, penilaian, spekulasi

Laporan untuk rapat direksi akan dibaca orang yang tidak bisa membedakan isi log dari tafsiran tim, kecuali kalimatnya sendiri yang membedakan.

Tabel berikut memberi satu contoh untuk tiap jenis kalimat. Perhatikan kata kerja yang dipakai, karena di situlah pembaca mengenali jenisnya.

| Jenis | Arti | Contoh (fiktif) |
|---|---|---|
| Fakta | Observasi yang bisa diverifikasi | "Domain X di-resolve oleh host Y pada 2026-10-08 02:14 UTC menurut log DNS." |
| Penilaian | Kesimpulan dari bukti, dengan probabilitas dan keyakinan | "Kemungkinan besar domain X bagian dari kampanye Z (keyakinan sedang)." |
| Spekulasi | Dugaan tanpa dasar bukti kuat, ditandai jelas | "Bila pola ini berlanjut, aktor bisa saja beralih ke sektor lain." |

Teknik sederhana agar pembaca tahu jenis kalimat: fakta memakai kata kerja observasi ("tercatat di log"), penilaian diawali "kami menilai", dan spekulasi diberi label atau dihindari di produk eksekutif.

### 1.7 Bias kognitif dan penangkalnya

Di PT LC, dua tarikan muncul bersamaan. Dugaan awal "afiliasi kriminal dari luar" sudah tertulis di tiket sejak pagi, sementara kabar pemutusan kontrak dan posting "orang dalam" membuat sebagian tim yakin sebaliknya.

Heuer menunjukkan bahwa bias kognitif tidak hilang hanya karena analis menyadarinya; yang membantu adalah prosedur yang memaksa penalaran keluar dari jalur kebiasaan [S4]. Tabel berikut memetakan bias yang paling sering muncul di CTI ke bentuk konkret dan penangkalnya. Cari bias yang paling mungkin menimpa kasus yang sedang kamu kerjakan.

| Bias | Bentuknya di CTI | Penangkal |
|---|---|---|
| Confirmation bias | Hanya mencari log yang mendukung dugaan awal | ACH; tulis bukti yang akan membantah sebelum mencari |
| Anchoring | Penilaian pertama di tiket dipertahankan walau bukti berubah | Penilaian ulang terjadwal; rekan menilai tanpa melihat kesimpulan awal |
| Mirror imaging | Mengira aktor akan memilih cara yang menurut kita masuk akal | Red Team Analysis: tulis rencana dari sudut aktor |
| Availability | Ancaman yang sedang ramai di berita dianggap paling mungkin | Bandingkan dengan data insiden sektor, bukan berita |
| Attribution bias | Teknik mirip langsung dianggap aktor yang sama | Pisahkan clustering dari atribusi; ACH dengan hipotesis "aktor lain memakai alat sama" |

### 1.8 Structured analytic techniques

Karena menyadari bias saja tidak cukup, tim PT LC butuh prosedur yang bisa dijalankan dan diperiksa rekan. Prosedur seperti itu disebut structured analytic techniques.

Tradecraft Primer pemerintah Amerika Serikat (2009) mengelompokkan teknik terstruktur menjadi tiga jenis [S5]. Tabel berikut membantu memilih teknik; baca kolom terakhir untuk mencocokkan teknik dengan pertanyaan yang sedang kamu hadapi.

| Kelompok | Teknik | Kapan berguna di CTI |
|---|---|---|
| Diagnostic | Key Assumptions Check, Quality of Information Check, Indicators or Signposts of Change, ACH | Menilai atribusi, menguji kesimpulan insiden, menentukan indikator yang dipantau |
| Contrarian | Devil's Advocacy, Team A/Team B, High-Impact/Low-Probability Analysis, "What If?" Analysis | Menantang konsensus tim, menyiapkan skenario jarang tetapi berdampak besar |
| Imaginative thinking | Brainstorming, Outside-In Thinking, Red Team Analysis, Alternative Futures Analysis | Threat modeling, memperkirakan langkah aktor berikutnya |

Tiga teknik paling sering dipakai di CTI harian:

- **Key Assumptions Check:** daftar asumsi yang mendasari kesimpulan, lalu untuk setiap asumsi tanya: kenapa kita yakin ini benar, dalam kondisi apa ia salah, dan apa dampaknya pada kesimpulan bila salah. Asumsi yang lemah tetapi menopang kesimpulan adalah titik yang harus diselidiki dulu.
- **Quality of Information Check:** periksa sumber yang paling menentukan kesimpulan. Apakah ada konfirmasi independen? Apakah ada laporan yang sudah ditarik atau dikoreksi? Apakah informasi ambigu sudah diberi catatan? [S5]
- **Indicators or Signposts of Change:** daftar observasi yang, bila muncul, menandakan penilaian perlu diubah. Di CTI ini sering menjadi daftar pemantauan atau bahkan rule deteksi.

### 1.9 Analysis of Competing Hypotheses

Pertanyaan direksi "dari luar atau orang dalam?" adalah pertanyaan tentang hipotesis yang bersaing, dan jawabannya harus mempertimbangkan lebih dari dua kemungkinan itu. ACH dibuat untuk pertanyaan seperti ini.

ACH dikembangkan Richards Heuer untuk melawan confirmation bias dengan menguji beberapa hipotesis sekaligus terhadap seluruh bukti [S4]. Delapan langkahnya:

1. Identifikasi semua hipotesis yang masuk akal, sebaiknya lewat diskusi kelompok; termasuk yang tidak disukai.
2. Daftar bukti dan argumen yang signifikan, termasuk asumsi dan ketiadaan bukti yang seharusnya ada.
3. Susun matriks bukti terhadap hipotesis; tandai setiap sel konsisten (C), tidak konsisten (I), atau tidak relevan/netral (N).
4. Perbaiki matriks: hapus bukti yang tidak diagnostik (konsisten dengan semua hipotesis), gabungkan atau pecah hipotesis bila perlu.
5. Tarik kesimpulan sementara dengan mencoba membantah setiap hipotesis; yang paling sedikit inkonsistensinya paling kuat.
6. Analisis sensitivitas: bukti mana yang paling menentukan, dan bagaimana kesimpulan berubah bila bukti itu salah atau hasil penipuan.
7. Laporkan kesimpulan dengan membahas kemungkinan relatif semua hipotesis, bukan hanya pemenangnya.
8. Tetapkan milestone: observasi masa depan yang akan menandakan kesimpulan perlu diubah.

Inti ACH adalah logika pembantahan. Seratus bukti yang konsisten tidak membuktikan hipotesis bila bukti itu juga konsisten dengan hipotesis lain, sedangkan satu bukti kuat yang tidak konsisten bisa menggugurkannya. Karena itu menghitung C tidak berguna; yang dihitung adalah I, dan bobot I bergantung pada kualitas buktinya. Contoh kerja lengkap ada di bagian 2.3.

### 1.10 Atribusi dan kerendahan hati analitis

Pertanyaan pertama direksi PT LC adalah "siapa pelakunya?". Jawaban jujurnya bergantung pada tingkat atribusi mana yang benar-benar didukung bukti.

Atribusi (menisbahkan aktivitas ke aktor) adalah penilaian tersulit dan paling rawan bias.

- Atribusi adalah penilaian berprobabilitas dan berkeyakinan, bukan fakta.
- Bedakan tiga tingkat: clustering aktivitas ("cluster A dan B berbagi infrastruktur dan tooling"), atribusi ke kelompok yang dilacak ("cluster ini kemungkinan besar kelompok X"), dan atribusi ke entitas nyata (negara, organisasi, orang). Kebanyakan tim enterprise cukup sampai tingkat pertama atau kedua, karena keputusan defensif jarang bergantung pada tingkat ketiga.
- Indikator teknis bisa dipalsukan atau dibagi bersama: infrastruktur sewaan, malware yang dijual bebas, dan alat red team yang bocor dipakai banyak pihak.
- Jangan menyimpulkan dari satu jenis bukti. Atribusi yang kuat biasanya menggabungkan infrastruktur, tooling, TTP, korban, dan waktu operasi.

Menyatakan batas dan ketidakpastian adalah tanda tradecraft matang. Produk yang jujur tentang keyakinannya lebih dipercaya, dan ketika ternyata salah, kerusakannya lebih kecil karena pembaca sudah tahu batasnya.

## 2. Contoh artefak intelijen

Semua contoh di bagian ini fiktif dan berlabel ilustrasi; keempatnya memakai kasus file server keuangan PT LC dari bagian Ide inti.

### 2.1 Kode Admiralty untuk butir informasi kasus

Ini jawaban untuk pertanyaan pertama direksi: setiap butir informasi yang dimiliki tim diberi kode Admiralty beserta alasannya. Baca kolom Alasan untuk melihat bahwa huruf dan angka dinilai terpisah.

| Butir | Sumber | Kode | Alasan |
|---|---|---|---|
| E1: login VPN akun `vendor.it01` dari 198.51.100[.]23 pukul 01:40 | Log VPN sendiri | A1 | Sensor sendiri, waktu tersinkron, terlihat juga di log firewall |
| E2: `vssadmin delete shadows` dijalankan di file server pukul 02:05 | EDR | A1 | Tercatat di EDR dan event log server |
| E3: 198.51.100[.]23 pernah dipakai afiliasi ransomware | Laporan vendor publik | B3 | Vendor umumnya andal, tetapi laporan tidak menunjukkan bukti teknis untuk IP ini |
| E4: Seorang staf keuangan menerima surat pemutusan kontrak Jumat | HR | A1 | Fakta administratif |
| E5: Tidak ada pengujian red team atau proyek enkripsi di change calendar | Change management | B2 | Kalender kadang tidak lengkap |
| E6: Posting anonim di media sosial mengklaim "orang dalam" pelakunya | Akun anonim | F6 | Tidak ada dasar menilai |

### 2.2 Key Assumptions Check untuk dugaan awal

Sebelum membandingkan hipotesis, tim memeriksa asumsi di balik dugaan awal yang tertulis di tiket pada Sabtu pagi: "Ini ransomware oleh afiliasi kriminal dari luar." Tabel berikut menulis setiap asumsi beserta kondisi yang membuatnya salah; cari asumsi yang dampaknya tinggi bila salah.

| Asumsi | Kenapa dianggap benar | Kapan bisa salah | Dampak bila salah |
|---|---|---|---|
| Akun `vendor.it01` dipakai pihak luar | Login dari IP asing di luar jam kerja vendor | Vendor memang bekerja malam dari luar negeri | Tinggi: hipotesis orang dalam atau kelalaian vendor naik |
| IP 198.51.100[.]23 milik afiliasi ransomware | Laporan vendor (B3) | IP adalah VPN komersial yang dipakai banyak orang | Sedang: tidak menggugurkan, tetapi melemahkan kaitan |
| Penghapusan shadow copy bagian dari serangan | Pola umum ransomware | Admin menghapusnya untuk alasan ruang disk | Rendah: waktunya 25 menit sebelum enkripsi |

**Cara membaca hasil:** asumsi pertama paling menentukan dan paling murah dicek: telepon kontak vendor dan minta log sisi mereka. Itu tindakan pertama, sebelum menulis atribusi apa pun.

### 2.3 Matriks ACH

Ini inti jawaban untuk pertanyaan "dari luar atau orang dalam": empat hipotesis diuji terhadap bukti yang sama, lalu hasilnya ditulis sebagai penilaian untuk rapat pukul 14.00.

Hipotesis:

- H1: serangan ransomware oleh pihak luar lewat akun vendor yang dicuri.
- H2: sabotase orang dalam (staf yang kontraknya diputus) yang meniru ransomware.
- H3: kesalahan operasional, misalnya alat enkripsi atau backup yang salah konfigurasi.
- H4: pengujian red team yang tidak terkoordinasi.

Matriks berikut memuat setiap bukti beserta kode Admiralty-nya. Baca baris terakhir (jumlah I), bukan jumlah C, lalu periksa kode bukti di balik setiap I.

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

### 2.4 Menulis ulang penilaian yang terlalu yakin

Bila direksi meminta satu kalimat "siapa pelakunya", godaan menulis versi yang terlalu yakin sangat besar. Contoh berikut menunjukkan versi buruk, masalahnya, dan versi yang lebih baik.

Versi buruk: "Serangan ini dilakukan oleh kelompok ransomware X dari Eropa Timur yang menargetkan sektor logistik. IP penyerang adalah 198.51.100[.]23."

Masalahnya: atribusi ke kelompok dan wilayah tanpa dasar yang ditunjukkan, tidak ada probabilitas atau keyakinan, "IP penyerang" mencampur fakta (IP yang login) dengan penilaian (IP milik penyerang), dan tidak ada alternatif.

Versi yang lebih baik: "Akun VPN vendor.it01 login dari 198.51.100[.]23 sebelum enkripsi (fakta, log VPN). Satu laporan vendor mengaitkan IP ini dengan afiliasi ransomware (B3). Kami belum punya dasar untuk mengaitkan insiden ini dengan kelompok tertentu; keyakinan atribusi rendah. Bila sampel encryptor tersedia, perbandingan dengan sampel publik dapat menaikkan keyakinan."

## 3. Lab praktik

Lab ini memakai editor teks saja. Skenario fiktif; jangan pakai data kerja; jangan mengakses forum kriminal.

1. **Kode sumber.** Ambil lima sumber fiktif (SIEM, vendor, blog peneliti, akun anonim, ISAC) dan beri kode Admiralty untuk satu butir informasi dari masing-masing. Tulis alasan huruf dan angka secara terpisah.
2. **Bahasa probabilitas.** Tulis tiga penilaian fiktif dengan istilah ICD 203 atau PHIA, masing-masing dengan kalimat keyakinan terpisah dan dasar ketidakpastiannya.
3. **Fakta, penilaian, spekulasi.** Ambil satu paragraf laporan publik apa pun dan tandai setiap kalimat. Hitung berapa kalimat penilaian yang tidak menyebut keyakinan.
4. **Key Assumptions Check.** Untuk kasus file server keuangan di bagian 2, tambahkan dua asumsi yang belum ada di tabel bagian 2.2 dan nilai dampaknya.
5. **ACH.** Buat kasus fiktif sendiri (misalnya akun cloud admin login dari negara tak biasa) dengan minimal empat hipotesis dan enam bukti berkode Admiralty. Isi matriks, hitung I, lalu lakukan analisis sensitivitas pada bukti terlemah.
6. **Atribusi.** Tulis satu pernyataan atribusi yang memisahkan clustering dari atribusi, menyebut keyakinan, dan menyebut kemungkinan false flag.
7. **Indicators of change.** Untuk kesimpulan ACH-mu, tulis dua observasi yang akan menaikkan keyakinan dan dua yang akan mengubah kesimpulan (lihat baris "Yang akan mengubah penilaian" di bagian 2.3).

**Hasil yang sebaiknya tersimpan:**

- Lima butir informasi dengan kode Admiralty dan alasannya.
- Tiga penilaian dengan probabilitas dan keyakinan di kalimat terpisah.
- Paragraf laporan yang sudah ditandai per kalimat.
- Tabel Key Assumptions Check.
- Matriks ACH lengkap dengan jumlah I, catatan bukti non-diagnostik, dan analisis sensitivitas.
- Pernyataan atribusi dan daftar indicators of change.

**Variasi tantangan:** kerjakan ACH yang sama dengan seorang rekan secara terpisah, lalu bandingkan isi sel yang berbeda. Perbedaan di sel biasanya menunjukkan asumsi yang tidak ditulis; diskusikan sampai asumsi itu eksplisit.

## 4. Troubleshooting

Tabel ini dibaca dari kolom Gejala: cari keluhan yang mirip dengan yang kamu alami, lalu periksa penyebab yang paling sering.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Atribusi terasa terlalu yakin | Hipotesis tunggal, attribution bias | Jalankan ACH; turunkan ke tingkat clustering bila bukti kurang |
| Pembaca salah paham kepastian | Fakta dan penilaian tercampur | Tandai setiap kalimat; pakai "kami menilai" untuk penilaian |
| "Mungkin" dipakai untuk menghindar | Takut berkomitmen | Pakai istilah dari skala yang dipilih tim |
| Matriks ACH semua C | Bukti tidak diagnostik atau hipotesis terlalu mirip | Cari bukti pembeda; gabungkan hipotesis yang tidak bisa dibedakan |
| Kesimpulan ACH berubah total saat satu sel diubah | Kesimpulan bertumpu pada satu bukti lemah | Laporkan sensitivitasnya; cari konfirmasi untuk bukti itu |

## 5. Kesalahan umum dan jebakan

- Memberi satu kode untuk sumber dan isi sekaligus. Kode Admiralty selalu dua karakter, dan isinya dinilai terpisah dari reputasi sumber.
- Mengode kesimpulan dengan Admiralty. Kode menempel pada butir informasi; kesimpulan memakai probabilitas dan keyakinan.
- Menghitung C di ACH. Yang menentukan adalah inkonsistensi dan kualitas bukti di balik inkonsistensi itu.
- Melewatkan analisis sensitivitas. Kesimpulan ACH yang bertumpu pada satu butir B3 harus dilaporkan begitu.
- Mencampur skala ICD 203 dan PHIA. Pilih satu dan tulis di template.
- Menganggap kesadaran bias sudah cukup. Heuer menunjukkan bias bertahan walau disadari; prosedur yang membantu [S4].

## 6. Catatan terkini

Bagian ini menampung tanggal terbit dan perubahan standar yang dipakai di Day ini. Berguna saat mengutip standar secara resmi, tetapi tidak mengubah cara menilai sumber atau menulis penilaian.

- ICD 203 ditandatangani pada 2 Januari 2015 dan mendapat amandemen teknis pada Desember 2022; tabel istilah probabilitas di bagian 1.4 tetap sama. Cek teks terbaru di situs ODNI bila kamu memakainya sebagai standar resmi [S2].
- Pemerintah Inggris menerbitkan penjelasan publik tentang PHIA Probability Yardstick pada Maret 2025, termasuk alasan skala ini memakai celah antar rentang [S3].
- Banyak vendor CTI memakai penamaan cluster (misalnya awalan UNC, TA, atau Storm) sebelum atribusi penuh. Penamaan ini adalah praktik kerendahan hati analitis dalam bentuk konkret.
- Day 04 masuk ke framework (Kill Chain, Diamond, ATT&CK, Pyramid of Pain) yang menstrukturkan analisis teknis.

## 7. Cheat sheet

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

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Vendor ini biasanya andal (B), jadi semua klaim di laporannya, termasuk atribusi tanpa bukti yang ditunjukkan, bisa diberi kode B1." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Huruf menilai sumber, angka menilai isi, dan keduanya dinilai terpisah agar reputasi sumber tidak memengaruhi penilaian isi. Kode 1 berarti dikonfirmasi sumber independen lain. Laporan vendor B bisa membawa informasi 2 (teknik yang dijelaskan dengan sampel), 3 (atribusi tanpa bukti yang ditunjukkan), atau 6 (klaim tentang niat aktor). Di kasus PT LC, klaim vendor bahwa IP 198.51.100[.]23 pernah dipakai afiliasi ransomware diberi B3 karena laporan tidak menunjukkan bukti teknis untuk IP itu. Lihat bagian 1.1, 1.3, dan 2.1.

</details>

**2. Skenario keputusan.** Posting anonim yang mengklaim "orang dalam" pelakunya diberi kode F6. Apa yang sebaiknya dilakukan dengan butir ini?

- A. Buang dari analisis, karena F6 adalah nilai terburuk di skala Admiralty.
- B. Simpan dan masukkan ke matriks ACH dengan kodenya; F6 berarti belum bisa dinilai, dan butir ini ternyata konsisten dengan H2 tetapi netral untuk hipotesis lain, sehingga tidak membedakan H1 dari H2.
- C. Naikkan kodenya menjadi A1, karena isinya cocok dengan kabar pemutusan kontrak dari HR.

<details><summary>Jawaban</summary>

B. F dan 6 bukan nilai buruk; artinya tidak ada dasar menilai. Butir seperti ini tetap dicatat, tetapi bobotnya terlihat dari kodenya dan dari posisinya di matriks: E6 hanya konsisten dengan H2 dan netral untuk yang lain, jadi tidak membantah H1. A keliru karena F6 bukan nilai terburuk; sumber yang terbukti tidak andal adalah E, dan isi yang tidak logis dan bertentangan adalah 5. C keliru karena huruf menilai sumber dan sumber anonim tidak punya rekam jejak yang bisa diperiksa, dan kecocokan dengan E4 tidak sama dengan konfirmasi independen atas klaim "orang dalam". Lihat bagian 1.2, 2.1, dan 2.3.

</details>

**3. Pertanyaan jebakan.** "Di matriks ACH, H1 punya paling banyak sel C, jadi H1 adalah hipotesis terkuat." Apakah alasan itu benar?

<details><summary>Jawaban</summary>

Tidak. Kesimpulannya kebetulan sama di kasus PT LC, tetapi alasannya keliru. ACH bekerja dengan logika pembantahan: bukti yang konsisten dengan beberapa hipotesis sekaligus tidak membedakan apa pun, sedangkan satu bukti kuat yang tidak konsisten bisa menggugurkan hipotesis. Yang dihitung adalah I, dan bobot setiap I bergantung pada kualitas buktinya. H1 terkuat karena tidak punya inkonsistensi, dan satu-satunya I milik H2 berasal dari E3 yang berkode B3, sehingga kesimpulan itu harus disertai analisis sensitivitas. Lihat bagian 1.9 dan 2.3.

</details>

**4. Jelaskan ulang.** Jelaskan kepada direksi PT LC dalam tiga kalimat arti "kemungkinan besar (likely), keyakinan sedang" di laporan pukul 14.00.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "'Kemungkinan besar' adalah penilaian kami tentang seberapa mungkin pelakunya pihak luar yang memakai akun VPN vendor; di skala yang kami pakai, artinya sekitar 55 sampai 80 persen. 'Keyakinan sedang' menjelaskan seberapa kuat dasar penilaian itu: log VPN dan EDR kami kuat, tetapi kaitan IP dengan afiliasi ransomware hanya dari satu laporan vendor yang belum menunjukkan bukti, dan vendor belum mengonfirmasi akunnya. Kami belum mengesampingkan sabotase orang dalam, dan penilaian ini akan kami ubah bila konfirmasi vendor atau pemeriksaan akses staf menunjukkan hal lain."

Kesalahan yang sering muncul:
- Menganggap keyakinan sedang berarti probabilitasnya sekitar 50 persen. Probabilitas dan keyakinan menjawab dua pertanyaan berbeda.
- Memberi kode Admiralty pada kesimpulan. Kode menempel pada butir informasi, bukan pada penilaian.
- Mencampur istilah ICD 203 dan PHIA dalam satu penjelasan.

</details>

**5. Skenario keputusan.** Pukul 13.00, seorang anggota tim mengusulkan laporan untuk direksi berbunyi "pelakunya staf keuangan yang diputus kontraknya", karena kabar dari HR terasa sangat meyakinkan. Apa yang paling tepat?

- A. Setuju. Kabar HR berkode A1, jadi kesimpulan bahwa staf itu pelakunya juga A1.
- B. Laporkan bahwa pihak luar lewat akun vendor kemungkinan besar pelakunya dengan keyakinan sedang, sebut bahwa sabotase orang dalam belum dapat dikesampingkan, dan sebut apa yang akan mengubah penilaian (konfirmasi vendor, akses staf ke kredensial `vendor.it01`).
- C. Jangan laporkan apa pun sampai tim 100% yakin siapa pelakunya.

<details><summary>Jawaban</summary>

B. Itulah isi laporan ringkas hasil ACH: penilaian dengan probabilitas dan keyakinan, alternatif yang masih terbuka, dan observasi yang akan mengubahnya. A keliru karena E4 adalah fakta bahwa seseorang diputus kontraknya, bukan bukti bahwa ia pelakunya; E4 konsisten dengan H2 tetapi netral untuk H1, sehingga tidak membedakan keduanya, dan rasa yakin karena kabar yang kuat secara emosional adalah jebakan anchoring. Selain itu kode Admiralty tidak dipakai untuk kesimpulan. C keliru karena kerendahan hati analitis berarti menyatakan batas dan ketidakpastian, bukan menahan penilaian; produk yang jujur tentang keyakinannya tetap bisa dipakai untuk keputusan. Lihat bagian 1.10, 2.2, dan 2.3.

</details>

**6. Pertanyaan jebakan.** "Semua analis kita sudah ikut pelatihan bias kognitif, jadi penilaian mereka sudah aman dari bias." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Heuer menunjukkan bias kognitif tidak hilang hanya karena analis menyadarinya. Yang membantu adalah prosedur yang memaksa penalaran keluar dari jalur kebiasaan: ACH untuk confirmation bias, penilaian ulang terjadwal dan rekan yang menilai tanpa melihat kesimpulan awal untuk anchoring, Red Team Analysis untuk mirror imaging, serta memisahkan clustering dari atribusi untuk attribution bias. Lihat bagian 1.7 dan 1.8.

</details>

**7. Interview question (English).** "How do you communicate uncertainty when you attribute an incident to a threat actor?"

<details><summary>Sample answer</summary>

"I separate three things. First, I grade each piece of evidence on its own, rating the source and the information separately, for example with the Admiralty scale, so a good vendor doesn't automatically make an unproven claim look solid. Second, I state the judgement with a defined probability term from one scale, like ICD 203's 'likely', and I state my confidence in a separate sentence that explains what it rests on and what gaps remain. Third, I test competing hypotheses, for example with ACH, focusing on the evidence that is inconsistent with each one rather than counting what fits, and I check how sensitive the conclusion is to the weakest item. In the report I also distinguish clustering from attribution to a named group, mention the alternatives I couldn't rule out, and list what would change my assessment. For most enterprise decisions, a well-supported cluster or tracked group is enough; naming a country or a person rarely changes what we defend."

What makes this answer strong: it separates source and content grading, keeps probability and confidence apart, shows a structured way to test alternatives, and shows analytic humility by stating alternatives and what would change the judgement.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Admiralty code (ringkasan skala keandalan sumber dan kredibilitas informasi, merujuk US Army FM 2-22.3 dan UK JWP 2-00) | https://en.wikipedia.org/wiki/Admiralty_code | sekunder | diakses 2026-10-10 | Sedang. Label skala cocok dengan FM 2-22.3 lampiran B; cocokkan dengan doktrin primer bila dipakai formal |
| S2 | Office of the Director of National Intelligence: Intelligence Community Directive 203, Analytic Standards | https://www.dni.gov/files/documents/ICD/ICD-203.pdf | primer | 2015-01-02, amandemen 2022; diakses 2026-10-10 | Tinggi. Situs menolak akses otomatis; tabel istilah probabilitas juga direproduksi di taksonomi MISP estimative-language |
| S3 | UK Government: Explaining uncertainty in UK intelligence assessment (PHIA Probability Yardstick) | https://www.gov.uk/government/publications/explaining-uncertainty-in-uk-intelligence-assessment/explaining-uncertainty-in-uk-intelligence-assessment | primer | 2025-03-24; diakses 2026-10-10 | Tinggi |
| S4 | Richards J. Heuer Jr.: Psychology of Intelligence Analysis (CIA Center for the Study of Intelligence) | https://www.cia.gov/resources/csi/books-monographs/psychology-of-intelligence-analysis-2/ | primer | 1999; diakses 2026-10-10 | Tinggi. Bias kognitif dan delapan langkah ACH (bab 8) |
| S5 | US Government: A Tradecraft Primer: Structured Analytic Techniques for Improving Intelligence Analysis | https://www.cia.gov/resources/csi/static/Tradecraft-Primer-apr09.pdf | primer | 2009-03; diakses 2026-10-10 | Tinggi. Pengelompokan SAT dan Quality of Information Check |

**Catatan sumber:** rentang persen ICD 203 dikutip dari teks direktif sebagaimana direproduksi di sumber sekunder (taksonomi MISP); cocokkan dengan PDF ODNI bila tersedia. Tabel tingkat keyakinan high/moderate/low di bagian 1.5 adalah pedoman praktik umum, bukan definisi resmi ICD 203. Kode awal untuk jenis sumber siber di bagian 1.3 adalah titik mulai yang wajar, bukan peringkat baku.
