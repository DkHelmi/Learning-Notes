---
day: 19
title: 'IR dasar, glosarium A-Z, dan latihan interview: siklus NIST SP 800-61, chain of custody, RCA, dan lessons learned'
researched_on: 2026-10-22
versions_checked: 'NIST SP 800-61 Rev. 3 (3 Apr 2025, CSF 2.0 Community Profile); NIST SP 800-61 Rev. 2 (Agu 2012, ditarik 3 Apr 2025); NIST SP 800-86 (Agu 2006); NIST CSRC Glossary (chain of custody, root cause analysis; diakses 2026-10-22); CISA Federal Government Cybersecurity Incident and Vulnerability Response Playbooks (Nov 2021); Microsoft Learn revoke user access in Entra ID (diperbarui 2026-06-19); MITRE ATT&CK T1539 v1.5 (12 Mei 2026); SANS Incident Handler''s Handbook (2012)'
---

# Day 19: IR dasar, glosarium A-Z, dan latihan interview

Cakupan: Day penutup yang membahas dasar incident response (siklus NIST SP 800-61 Rev. 2 dan Rev. 3, preparation, detection and analysis, incident declaration, severity, incident commander, containment, eradication, recovery, chain of custody, RCA, komunikasi dan pemberitahuan, serta lessons learned), lalu merangkum seluruh istilah Day 01 sampai 19 dalam glosarium A-Z dan latihan interview berbahasa Inggris.

## Ide inti

Delapan belas Day sebelumnya mengajarkan cara mengenali masalah: alat apa yang melihat apa, serangan seperti apa, dan bagaimana alert dipilah. Day ini menjawab pertanyaan yang tersisa: setelah sebuah alert terbukti insiden, lalu apa? Incident response (IR) adalah cara organisasi bertindak dengan urutan yang sudah disepakati sebelumnya, supaya keputusan penting (memutus akses, menyimpan bukti, memberi tahu siapa) tidak diambil dengan panik. Urutan itu disebut siklus IR. Gagasan pengikatnya sederhana: tindakan yang paling cepat belum tentu yang paling tepat, dan setiap tindakan harus menjawab tiga hal sekaligus, yaitu menghentikan kerusakan, menjaga bukti, dan memastikan kejadian yang sama tidak berulang.

Bayangkan pemadam kebakaran sebuah gedung. Jauh sebelum ada api, gedung sudah memasang hidran, membagi zona dengan pintu tahan api, menunjuk komandan regu, dan rutin berlatih (preparation). Saat alarm berbunyi, petugas memastikan apakah benar ada api, di lantai mana, dan seberapa besar (detection and analysis). Pintu tahan api ditutup supaya api tidak menjalar (containment), api dipadamkan sampai bara terakhir (eradication), lalu gedung diperiksa, diperbaiki, dan dibuka kembali (recovery). Setelah itu penyelidik mencari sumber api dan alasan api bisa menjalar, dan regu membahas apa yang harus diperbaiki (root cause analysis dan lessons learned). Batas analogi ini: api tidak berpikir, sedangkan penyerang mengamati reaksi kita, bisa bersembunyi, dan bisa kembali lewat pintu lain. Bukti digital juga jauh lebih mudah berubah atau hilang daripada abu kebakaran, sehingga cara mengumpulkannya harus dicatat sejak menit pertama.

```
 Model empat fase (NIST SP 800-61 Rev. 2, 2012)

   Preparation --> Detection & Analysis <--> Containment, Eradication & Recovery --> Post-Incident Activity
        ^                                                                                   |
        +-----------------------------------------------------------------------------------+

 Model berbasis CSF 2.0 (NIST SP 800-61 Rev. 3, 2025)

   Respons insiden  :  DETECT  -->  RESPOND  -->  RECOVER
                          \            |            /
   Perbaikan terus  :      +----- Improvement (ID.IM) -----+   (pelajaran dari semua fungsi, kapan saja)
                          /            |            \
   Persiapan        :  GOVERN       IDENTIFY       PROTECT
```

Kamu adalah analyst L1 di SOC (Security Operations Center) PT Jaringan Anak Bangsa (PT JAB), ISP fiktif dengan sekitar 1.200 karyawan dan sekitar 400 ribu pelanggan internet rumah. Jumat 2027-08-27 adalah hari terakhir masa orientasimu. Shift pagi baru dimulai ketika alert `SOC-2027-0897` masuk pukul 07:05: akun Microsoft 365 milik Bagus Wicaksono, staf Pengadaan, dipakai dari IP `192.0.2.183`, alamat yang sama dengan sumber password spraying ke VPN sebelas hari lalu. Bagus sedang di kereta dan laptop kantornya mati. Pukul 07:22 mentormu, Sari Kusuma (analyst L2), menyatakan insiden `INC-2027-098`. Pukul 07:40, setelah akses penyerang diputus, Sari menulis di kanal tim:

> "Ini insiden pertamamu dari awal sampai akhir, jadi ikuti siklusnya dengan sadar. Kita pakai model NIST yang mana, yang empat fase atau yang CSF 2.0, dan kenapa interviewer masih menanyakan yang lama? Apa saja yang sudah kita siapkan sebelum pagi ini sampai bisa bergerak dalam 20 menit? Tadi kamu menelepon Bagus dulu sebelum eskalasi; itu bagian fase apa, dan apa yang membuat kita yakin ini insiden? Kenapa aku yang menyatakan insiden, kenapa SEV-3, dan siapa yang memimpin? Kita mencabut sesi dan menonaktifkan akun, tapi belum menghapus aturan inbox penyerang; kenapa urutannya begitu? Kapan akun Bagus boleh hidup lagi? Kalau Bagus nanti menyerahkan laptop pribadinya, bagaimana supaya bukti itu bisa dipercaya kalau suatu hari dibawa ke pengadilan? Penyebabnya apa, cookie dicuri atau aturan kita yang terlalu longgar? Siapa yang harus kita kabari, Pak Agus perlu tahu atau tidak, dan lewat saluran apa? Terakhir, jam 13:30 kita hotwash dan jam 15:00 Pak Dimas mau mock interview penutup orientasimu. Siapkan diri."

Pesan itu memuat sepuluh pertanyaan:

1. Model siklus IR NIST mana yang dipakai, dan apa beda model empat fase dengan model CSF 2.0?
2. Apa yang termasuk preparation, dan kenapa itu menentukan kecepatan pagi ini?
3. Apa yang dikerjakan di detection and analysis, dan apa yang membuat sebuah alert dianggap insiden?
4. Siapa yang menyatakan insiden, bagaimana severity ditentukan, dan siapa yang memimpin?
5. Apa itu containment, dan kenapa urutan tindakannya penting?
6. Apa beda eradication dan recovery, dan kapan sistem atau akun boleh dipulihkan?
7. Bagaimana menjaga bukti supaya bisa dipercaya (chain of custody)?
8. Bagaimana menemukan akar penyebab (RCA)?
9. Siapa yang dikabari, lewat saluran apa, dan kapan pemberitahuan menjadi kewajiban hukum?
10. Apa yang terjadi setelah insiden selesai (lessons learned)?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, pertanyaan 6 di bagian 1.6, pertanyaan 7 di bagian 1.7, pertanyaan 8 di bagian 1.8, pertanyaan 9 di bagian 1.9, dan pertanyaan 10 di bagian 1.10. Bagian 2 membedah `INC-2027-098` dari alert sampai hotwash. Bagian 3 adalah glosarium A-Z seluruh istilah Day 01 sampai 19, dan bagian 4 adalah mock interview Dimas sore itu.

**Kapan relevan:** saat sebuah alert terbukti insiden dan kamu harus tahu langkah berikutnya serta urutannya, saat mengumpulkan bukti yang mungkin dipakai pihak hukum, saat menulis laporan insiden atau ikut rapat lessons learned, saat menyusun playbook, dan saat interview untuk posisi SOC atau IR, di mana pertanyaan "jelaskan siklus IR" hampir selalu muncul.
**Kapan bukan jawaban:** siklus IR bukan resep langkah teknis per jenis serangan; langkah teknis ada di playbook dan runbook masing-masing (Day 10 bagian 1.9). Day ini juga bukan panduan forensik digital yang lengkap dan bukan nasihat hukum: keputusan menempuh jalur hukum dan isi pemberitahuan ke regulator ada di tangan manajemen, DPO, dan penasihat hukum. Untuk insiden besar, organisasi biasanya memanggil penyedia layanan IR yang punya kemampuan forensik penuh.

## 1. Konsep inti IR

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (event, alert, incident, triage, eskalasi, severity, playbook, runbook, infostealer, AiTM, UU PDP, BCP, DRP) tidak diulang di tabel ini; definisinya diulang satu kalimat di tempat pemakaiannya. Tabel berikut memuat istilah baru Day ini; kolom padanan memakai cerita pemadam kebakaran gedung supaya posisi setiap istilah dalam siklus mudah diingat.

| Istilah | Arti singkat | Padanan sehari-hari |
|---|---|---|
| Incident response (IR) | Seluruh kegiatan menyiapkan, mendeteksi, menangani, memulihkan, dan belajar dari insiden | Seluruh kerja pemadam kebakaran gedung, dari latihan sampai evaluasi |
| Siklus IR | Urutan tahap penanganan insiden; NIST Rev. 2 memakai empat fase, Rev. 3 memetakannya ke enam fungsi CSF 2.0 | Prosedur baku pemadaman dari alarm sampai gedung dibuka lagi |
| Preparation | Persiapan sebelum insiden: rencana, orang, alat, latihan, dan pencegahan | Hidran, pintu tahan api, regu, dan latihan rutin |
| Detection and analysis | Menemukan tanda insiden, memastikannya, menilai cakupan, dan menentukan prioritas | Memastikan alarm benar, mencari lantai yang terbakar, menilai besarnya api |
| Precursor / indicator | Tanda insiden mungkin akan terjadi / tanda insiden mungkin sedang atau sudah terjadi | Bau kabel terbakar / asap yang sudah keluar |
| Scoping | Menentukan seberapa luas insiden: aset, akun, data, dan waktu yang terdampak | Memeriksa ruangan mana saja yang ikut terbakar |
| Incident declaration | Keputusan resmi bahwa kejadian memenuhi kriteria insiden sehingga rencana IR dijalankan | Komandan menyatakan "kebakaran", seluruh prosedur darurat berjalan |
| Incident commander (IC) | Satu orang yang memimpin dan mengoordinasikan penanganan satu insiden | Komandan regu di lokasi kebakaran |
| Containment | Menahan insiden supaya tidak meluas | Menutup pintu tahan api |
| Eradication | Membersihkan penyebab dan sisa insiden: malware, persistence, akun disusupi, celah | Memadamkan bara terakhir |
| Recovery | Mengembalikan sistem ke operasi normal dan memastikan sistem bersih | Memeriksa, memperbaiki, lalu membuka gedung kembali |
| Evidence (bukti) | Data yang menjadi dasar membuktikan atau membantah apa yang terjadi | Sisa kabel, rekaman CCTV, keterangan saksi |
| Chain of custody | Catatan siapa memegang bukti, kapan, dan untuk apa, sejak dikumpulkan sampai dianalisis | Buku serah terima barang bukti di kantor polisi |
| Forensic image | Salinan utuh isi disk atau memori untuk dianalisis tanpa menyentuh aslinya | Fotokopi resmi dokumen; yang diperiksa fotokopinya |
| Order of volatility | Urutan pengambilan bukti dari yang paling cepat hilang ke yang paling awet | Memotret jejak kaki di salju sebelum mencairkan esnya |
| Root cause analysis (RCA) | Pendekatan sistematis untuk menemukan penyebab dasar, bukan hanya gejala | Penyelidik kebakaran mencari sumber api dan alasan api menjalar |
| Enabling condition | Kondisi yang membuat penyebab langsung bisa berhasil | Pintu tahan api yang diganjal kursi |
| Lessons learned | Peninjauan apa yang terjadi, apa yang dilakukan, seberapa efektif, dan apa yang harus diubah | Rapat evaluasi regu setelah kebakaran |
| Hotwash | Diskusi singkat segera setelah penanganan atau latihan, sebelum ingatan memudar | Briefing singkat regu begitu kembali ke pos |
| After-action report | Laporan akhir insiden: kejadian, tindakan, dan lessons learned | Berita acara kebakaran |
| Out-of-band communication | Saluran komunikasi cadangan di luar sistem yang mungkin dikuasai penyerang | Walkie-talkie saat telepon gedung ikut mati |
| Tabletop exercise | Latihan diskusi skenario insiden di atas meja tanpa menyentuh sistem | Simulasi kebakaran di atas denah gedung |
| Session token / cookie | Bukti login yang disimpan browser sehingga pengguna tidak perlu login ulang | Cap tangan di pintu taman hiburan: yang punya cap dianggap sudah bayar |

### 1.1 Siklus IR menurut NIST SP 800-61: model empat fase dan model CSF 2.0

Pertanyaan pertama Sari terdengar seperti soal teori, tetapi jawabannya menentukan cara tim berbicara: di laporan PT JAB tertulis "fase containment", sedangkan laporan ke komite memakai bahasa NIST CSF 2.0 (Day 18 bagian 1.5). Keduanya berasal dari dokumen yang sama, NIST SP 800-61, dalam dua revisi yang berbeda.

**Apa itu:** siklus IR (incident response life cycle) adalah model urutan kegiatan penanganan insiden. NIST SP 800-61 adalah panduan IR paling banyak dirujuk di dunia, dan ada dua versinya yang perlu kamu kenal:
- **Rev. 2 (Agustus 2012), "Computer Security Incident Handling Guide".** Memakai model empat fase: preparation; detection and analysis; containment, eradication, and recovery; dan post-incident activity [S2]. Rev. 2 resmi ditarik (withdrawn) pada 3 April 2025 dan digantikan Rev. 3 [S2].
- **Rev. 3 (3 April 2025), "Incident Response Recommendations and Considerations for Cybersecurity Risk Management".** Disusun sebagai CSF 2.0 Community Profile, yaitu rekomendasi IR yang diatur menurut fungsi, kategori, dan subkategori NIST CSF 2.0 [S1]. Model siklusnya memakai enam fungsi CSF: Govern, Identify, Protect, Detect, Respond, Recover [S1].

**Analogi:** model empat fase seperti prosedur pemadam kebakaran lama yang berbentuk lingkaran: latihan, kebakaran, pemadaman, evaluasi, lalu latihan lagi. Model Rev. 3 seperti pengelolaan keselamatan gedung modern: pencegahan dan kesiapan adalah urusan seluruh pengelola gedung sepanjang tahun, regu pemadam bergerak saat ada api, dan setiap temuan (dari inspeksi, latihan, atau kebakaran kecil) langsung dipakai memperbaiki aturan tanpa menunggu kebakaran berikutnya. Batasnya: kedua model menggambarkan hal yang sama dari sudut berbeda; organisasi boleh memakai salah satunya, dan NIST sendiri menyatakan organisasi sebaiknya memakai model yang paling cocok baginya [S1].

**Cara kerja:**

Model empat fase Rev. 2 bekerja sebagai berikut [S2]:
1. **Preparation:** membangun kemampuan IR (rencana, tim, alat) dan mencegah insiden lewat control yang dipilih dari penilaian risiko.
2. **Detection and analysis:** menemukan tanda insiden, memastikannya, mendokumentasikan, memprioritaskan, dan melaporkan ke pihak yang tepat.
3. **Containment, eradication, and recovery:** menahan, membersihkan, dan memulihkan. NIST mencatat kegiatan di fase ini sering kembali ke detection and analysis, misalnya untuk mencari host lain yang ikut terinfeksi; karena itu panah antara fase 2 dan 3 berbentuk dua arah di diagram Ide inti.
4. **Post-incident activity:** laporan tindak lanjut dan rapat lessons learned, yang hasilnya kembali menjadi bahan preparation.

Rev. 3 menjelaskan kenapa model itu diganti. Pada 2012 insiden relatif jarang, cakupannya sempit, dan biasanya selesai dalam satu atau dua hari, sehingga masuk akal memperlakukan IR sebagai kegiatan terpisah oleh tim terpisah. Sekarang insiden sering terjadi, kerusakannya jauh lebih besar, dan pemulihannya bisa berminggu-minggu atau berbulan-bulan; IR dianggap bagian dari manajemen risiko keamanan yang menyatu dengan operasi organisasi, dan pelajaran sebaiknya dibagikan begitu ditemukan, bukan menunggu pemulihan selesai [S1].

Model Rev. 3 terdiri dari tiga lapis [S1]:
- **Lapis bawah (persiapan): Govern, Identify, Protect.** Kegiatan ini bukan bagian dari respons insiden itu sendiri, tetapi kegiatan manajemen risiko yang lebih luas yang juga menopang IR.
- **Lapis atas (respons insiden): Detect, Respond, Recover.** Di sinilah insiden ditemukan, dikelola, diprioritaskan, ditahan, dibersihkan, dipulihkan, dan dilaporkan.
- **Lapis tengah (perbaikan berkelanjutan): kategori Improvement (ID.IM) di fungsi Identify.** Pelajaran dari semua kegiatan di semua fungsi masuk ke Improvement, dianalisis, diprioritaskan, lalu dipakai memperbaiki semua fungsi.

Rev. 3 juga memberi tabel padanan antara kedua model; tabel berikut merangkumnya supaya kamu bisa menerjemahkan laporan lama ke bahasa CSF dan sebaliknya [S1].

| Fase model Rev. 2 | Fungsi CSF 2.0 di Rev. 3 |
|---|---|
| Preparation | Govern; Identify (semua kategori); Protect |
| Detection and analysis | Detect; Identify (kategori Improvement) |
| Containment, eradication, and recovery | Respond; Recover; Identify (kategori Improvement) |
| Post-incident activity | Identify (kategori Improvement) |

**Model lain yang sering disebut:** SANS memakai enam langkah yang dikenal dengan singkatan PICERL: Preparation, Identification, Containment, Eradication, Recovery, Lessons learned [S6][S7]. Isinya hampir sama dengan Rev. 2; bedanya, SANS memecah fase ketiga NIST menjadi tiga langkah terpisah dan menyebut detection and analysis sebagai identification. Playbook IR CISA untuk instansi federal Amerika Serikat (November 2021) juga disusun mengikuti fase Rev. 2 [S4].

**Contoh di PT JAB:** prosedur IR PT JAB ditulis 2023 memakai empat fase Rev. 2, dan tiket insiden masih punya kolom "fase". Sejak PT JAB memakai NIST CSF 2.0 di laporan komite, tim memetakan setiap tindakan ke fungsi CSF memakai tabel di atas. Untuk `INC-2027-098`, pemetaan lengkapnya ada di bagian 2.4.

**Beda Rev. 2 dengan Rev. 3:** Rev. 2 adalah panduan teknis penanganan insiden (cara menganalisis, contoh daftar periksa, kriteria strategi containment). Rev. 3 adalah panduan manajemen risiko: ia tidak lagi memuat detail teknis karena detail itu terlalu cepat berubah, dan merujuk ke sumber daring yang dipetakan ke CSF [S1]. Karena itu interviewer masih sering menanyakan empat fase Rev. 2: model itu yang membentuk kosakata sehari-hari tim IR, dipakai di playbook CISA, dan mudah dijelaskan. Jawaban yang kuat menyebut keduanya.

**Salah paham umum:**
- "NIST sudah membuang containment, eradication, dan recovery." Tidak. Ketiganya tetap ada sebagai bagian dari fungsi Respond dan Recover di Rev. 3, misalnya subkategori "Incidents are contained" dan "Incidents are eradicated" [S1]. Yang berubah adalah bingkainya, bukan pekerjaannya.

### 1.2 Preparation

Bagian kedua pesan Sari: dari alert pukul 07:05 sampai akses penyerang terputus pukul 07:27 hanya 22 menit. Kecepatan itu tidak dimulai pagi ini; ia dibangun berbulan-bulan sebelumnya.

**Apa itu:** preparation adalah semua yang dikerjakan sebelum insiden supaya organisasi siap menangani insiden dan, sebisa mungkin, mencegahnya [S2]. Di Rev. 3, preparation tersebar di fungsi Govern (kebijakan, peran, wewenang), Identify (aset, risiko, rencana), dan Protect (control pencegah) [S1].

**Analogi:** hidran yang terpasang, peta gedung di pos satpam, daftar nomor telepon darurat, pintu tahan api, dan latihan evakuasi. Saat api muncul, tidak ada waktu untuk membeli selang. Batasnya: persiapan IR digital harus terus diperbarui karena "gedung"-nya berubah setiap minggu (aplikasi baru, akun baru, layanan cloud baru), sedangkan hidran bertahan bertahun-tahun.

**Cara kerja:** isi preparation yang paling sering disebut di panduan NIST dan CISA dapat dikelompokkan seperti tabel berikut; cari kolom contoh untuk melihat bentuknya di PT JAB.

| Kelompok | Isi | Contoh di PT JAB |
|---|---|---|
| Kebijakan dan rencana | Kebijakan IR berisi komitmen manajemen, tujuan, cakupan, definisi insiden, peran dan wewenang (termasuk siapa boleh menyita, memutus, atau mematikan aset), pedoman prioritas dan severity, serta ukuran kinerja [S1] | Kebijakan IR 2023, kriteria SEV-1 sampai SEV-4 (Day 11 bagian 1.6) |
| Prosedur dan playbook | Prosedur untuk jenis insiden paling umum, sering dalam bentuk playbook [S1] | PB-04 "Akun dicurigai diambil alih", runbook RB-12 dan RB-13 (Day 10 bagian 1.9) |
| Orang dan kontak | Daftar kontak tim, manajemen, hukum, humas, SDM, pemilik aset, penyedia layanan; saluran komunikasi cadangan [S1][S4] | Nomor telepon kantor setiap karyawan di direktori, kontak DPO Agus Setiawan, grup darurat di luar Microsoft 365 |
| Alat dan data | Log terpusat, EDR, akses ke konsol identitas, media penyimpan bukti, formulir chain of custody [S2] | Splunk, Defender for Endpoint, konsol Entra ID, lemari bukti terkunci di ruang SOC |
| Latihan | Tabletop exercise dan simulasi untuk menguji rencana dan menemukan perbaikan [S1] | Tabletop ransomware Mei 2027 |
| Pencegahan | Control yang dipilih dari penilaian risiko: patch, MFA, segmentasi, pelatihan [S2] | MFA number matching, DMARC reject, pelatihan phishing untuk Keuangan |

**Contoh di PT JAB:** tiga hal yang disiapkan jauh hari membuat pagi ini cepat. Pertama, IP `192.0.2.183` masuk watchlist Splunk sejak password spraying VPN `SOC-2027-0862` tanggal 16 Agustus (Day 11 bagian 2.1), sehingga login dari IP itu langsung memunculkan alert. Kedua, PB-04 sudah menulis langkah pertama: hubungi pemilik akun lewat telepon kantor, bukan lewat email akun yang dicurigai. Ketiga, Rina Anggraini dari Keuangan sudah terlatih memverifikasi perubahan rekening lewat telepon (Day 09 bagian 1.3), dan latihan itulah yang mencegah kerugian uang hari ini.

**Salah paham umum:**
- "Preparation berarti membeli alat." Alat tanpa rencana, wewenang yang jelas, dan latihan hanya memindahkan kebingungan ke layar yang lebih mahal. Pertanyaan "siapa boleh menonaktifkan akun direktur pukul dua pagi" harus terjawab di kebijakan, bukan saat insiden.

### 1.3 Detection and analysis

Pertanyaan ketiga: menelepon Bagus termasuk fase apa, dan apa yang membuat alert pagi ini dianggap insiden? Alert `SOC-2027-0897` baru dugaan; detection and analysis mengubah dugaan itu menjadi keputusan yang didukung fakta.

**Apa itu:** detection and analysis adalah fase menemukan tanda insiden, memastikan apakah insiden benar terjadi, menentukan jenis dan cakupannya, memprioritaskan, dan mulai mendokumentasikan [S2]. Rev. 2 membagi tanda insiden menjadi dua: **precursor**, tanda bahwa insiden mungkin akan terjadi, dan **indicator**, tanda bahwa insiden mungkin sudah atau sedang terjadi [S2]. NIST mencatat kebanyakan serangan tidak punya precursor yang terlihat dari sisi korban [S2]. Di Rev. 3, fase ini berada di fungsi Detect (pemantauan dan analisis adverse event) dan di kategori Respond seperti Incident Management dan Incident Analysis [S1].

**Analogi:** alarm asap berbunyi. Petugas tidak langsung menyemprotkan air ke seluruh gedung; ia memastikan dulu apakah ada api, di ruangan mana, apa yang terbakar, dan apakah api sudah menjalar ke ruangan sebelah. Batasnya: api terlihat dan berasap, sedangkan penyerang sering diam dan memakai akun sah, sehingga "melihat api" bisa butuh berjam-jam penelusuran log.

**Cara kerja:** langkah triage (pemeriksaan awal alert untuk memutuskan benar atau tidak, penting atau tidak, dan siapa yang menangani; Day 11 bagian 1.7) adalah pintu masuk fase ini. Setelah itu ada tiga pekerjaan yang berjalan bersamaan:
1. **Validasi.** Rev. 3 merekomendasikan tinjauan awal atas laporan insiden baru untuk memastikan insiden benar terjadi, lalu memperkirakan severity dan urgensinya [S1].
2. **Analisis dan scoping.** Menentukan urutan kejadian dan aset yang terlibat, kerentanan dan pelaku yang berperan, serta besaran insiden; Rev. 3 meminta pencarian IOC, persistence, dan tanda lain tidak hanya di aset yang diketahui diserang tetapi juga di target potensial lain, karena scoping yang dangkal membuat insiden terus berjalan di tempat lain tanpa diketahui [S1].
3. **Dokumentasi sejak awal.** Rev. 2 meminta setiap langkah sejak insiden terdeteksi sampai selesai didokumentasikan dengan cap waktu, dan menyarankan handler bekerja minimal berdua: satu mencatat, satu mengerjakan tugas teknis [S2].

Prioritas tidak ditentukan siapa yang datang duluan. Rev. 2 memakai tiga faktor: dampak fungsional (layanan apa yang terganggu), dampak informasi (kerahasiaan, keutuhan, ketersediaan data), dan kemampuan pulih (recoverability) [S2]. Rev. 3 memperluasnya menjadi faktor evaluasi risiko seperti kritikalitas aset, dampak fungsional, dampak data, tahap aktivitas yang teramati, karakter pelaku, dan kemampuan pulih [S1].

**Contoh di PT JAB:** fakta yang terkumpul dalam 17 menit pertama:
- Sign-in log Entra ID: akun `bagus.wicaksono@jab.example` dipakai dari `192.0.2.183` sejak 06:58:12 tanpa prompt MFA; persyaratan MFA tercatat terpenuhi oleh klaim yang sudah ada di token. Artinya penyerang tidak login dengan password, tetapi memakai sesi yang sudah jadi.
- Enrichment otomatis: `192.0.2.183` adalah IP hosting luar negeri yang 16 Agustus menyemprot 146 akun VPN. Sari mengingatkan, IP hosting bisa dipakai banyak penyewa, jadi kesamaan IP bukan bukti pelakunya orang yang sama (pelajaran IP CDN di Day 12 bagian 1.9).
- Telepon kantor ke Bagus pukul 07:14 (PB-04 langkah 1): ia di kereta, tidak membuka laptop, dan tidak mengenal IP itu.
- Pukul 07:16 Defender for Office 365 memunculkan `SOC-2027-0898`: aturan inbox baru di kotak surat Bagus memindahkan email berisi kata "rekening", "pembayaran", dan "transfer" ke folder RSS Feeds dan menandainya sudah dibaca.

Empat fakta ini memenuhi definisi insiden: kerahasiaan kotak surat Bagus benar-benar dilanggar tanpa wewenang (definisi incident di Day 11 bagian 1.1). Telepon ke Bagus adalah bagian validasi di fase detection and analysis; tanpa jawaban Bagus, login itu bisa saja Bagus yang memakai VPN pribadi.

**Beda dengan triage:** triage menjawab "alert ini perlu ditangani atau tidak" dalam hitungan menit; detection and analysis berlanjut setelah insiden dinyatakan, bahkan selama containment, karena cakupan insiden terus diperbarui saat temuan baru muncul [S2][S4].

**Salah paham umum:**
- "Analisis selesai begitu insiden dinyatakan." Scoping berjalan terus. Di `INC-2027-098`, jumlah email yang dibaca penyerang baru diketahui satu jam setelah insiden dinyatakan, dan fakta itulah yang membuat DPO terlibat (bagian 1.9).

### 1.4 Incident declaration, severity, dan incident commander

Pertanyaan keempat: kenapa Sari yang menyatakan insiden, kenapa SEV-3, dan siapa yang memimpin? Tiga hal ini menjawab satu kebutuhan: begitu insiden diakui, semua orang harus tahu seberapa serius kejadiannya dan kepada siapa harus melapor.

**Apa itu:**
- **Incident declaration** adalah keputusan resmi bahwa sebuah kejadian memenuhi kriteria insiden. Rev. 3 merumuskannya sebagai insiden dinyatakan ketika adverse event (kejadian yang membawa akibat negatif) memenuhi kriteria insiden yang sudah ditetapkan, dengan mempertimbangkan false positive yang sudah dikenal [S1]. Setelah dinyatakan, rencana IR dijalankan, termasuk koordinasi dengan pihak ketiga bila perlu [S1]. Playbook CISA juga memulai proses IR dari deklarasi, yaitu identifikasi insiden dan komunikasinya ke pihak yang berwenang [S4].
- **Severity insiden** adalah penilaian dampak insiden secara keseluruhan setelah diperiksa. Berbeda dengan severity alat (High, Medium, Low) dan priority alert (P1 sampai P4), severity insiden menentukan siapa dilibatkan dan seberapa sering manajemen diberi kabar (Day 11 bagian 1.6).
- **Incident commander (IC)** adalah satu orang yang memimpin penanganan satu insiden: menetapkan prioritas, membagi tugas, memutuskan atau meminta keputusan, dan menjaga semua orang mendapat informasi yang sama. Rev. 3 menyebutnya incident lead dan menyarankan organisasi menunjuk satu incident lead untuk setiap insiden [S1]. IC tidak harus orang yang paling jago teknis; tugasnya mengatur, bukan mengerjakan semuanya.

**Analogi:** saat komandan regu berteriak "kebakaran di lantai tiga", seluruh prosedur darurat berjalan: lift dimatikan, penghuni dievakuasi, pemadam dipanggil. Besarnya api menentukan berapa regu dikirim. Di lokasi hanya ada satu komandan, supaya tidak ada dua orang memberi perintah yang bertentangan. Batasnya: di insiden digital, besarnya "api" sering baru jelas berjam-jam kemudian, sehingga severity boleh naik atau turun ketika fakta baru ditemukan.

**Cara kerja:** di PT JAB, kriteria dan peran ditulis di kebijakan IR. Tabel berikut mengulang skala SEV dari Day 11 bagian 1.6 dan menambahkan siapa IC-nya; cari baris yang cocok dengan dampak, lalu baca kolom IC dan pihak yang dikabari.

| Severity | Kriteria (ringkas) | IC | Dikabari |
|---|---|---|---|
| SEV-1 | Layanan inti pelanggan lumpuh, kebocoran data pelanggan massal, atau domain AD dikuasai | Dimas Prasetyo (SOC lead) | Hendra Wijaya (Direktur Teknologi) segera dan berkala; direksi; DPO bila ada data pribadi |
| SEV-2 | Penyerang aktif di lebih dari satu sistem internal, atau layanan penting terganggu sebagian | Dimas Prasetyo | Hendra Wijaya berkala; DPO bila ada data pribadi |
| SEV-3 | Terbatas pada satu host atau satu akun yang bisa ditahan SOC | L2 yang bertugas | Dimas; DPO bila ada data pribadi |
| SEV-4 | Dampak minimal | L2 yang bertugas | Dicatat di laporan bulanan |

Yang menyatakan insiden adalah L2 atau SOC lead, sesuai Day 11 bagian 1.1. L1 mengeskalasi dengan paket fakta, L2 memutuskan.

**Contoh di PT JAB:** pukul 07:17 kamu mengeskalasi `SOC-2027-0897` ke Sari dengan lima fakta di bagian 1.3. Pukul 07:22 Sari menyatakan `INC-2027-098` dengan SEV-3: satu akun, belum ada tanda penyebaran ke sistem lain, dan bisa ditahan SOC. Karena SEV-3, Sari sendiri menjadi IC. Ia membagi tugas: kamu mencatat lini waktu dan mengekspor log, Yoga Pratama (L2 lain di shift pagi) menjalankan runbook penahanan. Severity sempat ditinjau ulang pukul 09:05 ketika ternyata ada data pribadi di kotak surat Bagus; SEV tetap 3 karena jumlahnya kecil dan tidak ada sistem lain yang terdampak, tetapi kriteria elevasi (melibatkan manajemen) terpenuhi, sehingga Sari mengabari Dimas dan DPO (bagian 1.9).

**Beda IC dengan analyst yang mengerjakan:** analyst mengerjakan tugas teknis (mengekspor log, mencabut sesi); IC menjaga gambaran besar dan keputusan. Di insiden kecil keduanya bisa orang yang sama, tetapi begitu lebih dari tiga orang terlibat, IC sebaiknya berhenti mengerjakan tugas teknis supaya ada yang melihat keseluruhan.

**Salah paham umum:**
- "Menyatakan insiden terlalu cepat itu memalukan bila ternyata bukan insiden." Insiden boleh diturunkan atau ditutup sebagai bukan insiden setelah analisis. Yang mahal adalah terlambat menyatakan, karena rencana IR, kewajiban pelaporan, dan sumber daya tambahan baru bergerak setelah deklarasi.

### 1.5 Containment

Pertanyaan kelima: kenapa sesi dicabut dan akun dinonaktifkan dulu, sedangkan aturan inbox penyerang dibiarkan sampai log diekspor? Containment adalah tentang menghentikan kerusakan tanpa merusak hal lain yang masih dibutuhkan.

**Apa itu:** containment adalah tindakan mencegah insiden meluas. Rev. 3 menyebut containment mencegah kerusakan tambahan dan menghindari sumber daya organisasi kewalahan, dan hampir semua insiden membutuhkan containment dalam bentuk tertentu [S1]. CISA merumuskan tujuannya sebagai mencegah kerusakan lanjutan dan mengurangi dampak langsung dengan menghilangkan akses penyerang [S4].

**Analogi:** menutup pintu tahan api dan memutus listrik di satu lantai. Api belum padam, tetapi tidak menjalar. Batasnya: pintu tahan api tidak memberi tahu api bahwa ia sedang dikurung, sedangkan penyerang bisa melihat bahwa aksesnya diputus dan bereaksi, misalnya mempercepat pencurian data atau masuk lewat pintu lain. CISA mengingatkan sebagian penyerang memantau tindakan pembela dan mengubah caranya [S4].

**Cara kerja:** strategi containment berbeda per jenis insiden; containment malware lewat email berbeda dengan containment DDoS [S2]. Rev. 2 memberi kriteria memilih strategi, dan kriteria ini masih dipakai di playbook CISA [S2][S4]:
- potensi kerusakan dan pencurian sumber daya;
- kebutuhan menjaga bukti;
- ketersediaan layanan (apakah tindakan memutus layanan untuk pelanggan atau pihak luar);
- waktu dan sumber daya yang dibutuhkan;
- efektivitas (penahanan penuh atau sebagian);
- lama solusi berlaku (darurat beberapa jam, sementara dua minggu, atau permanen).

Contoh tindakan containment yang umum: mengisolasi host atau segmen jaringan, memblokir IP atau domain, menutup port atau layanan tertentu, mengganti password admin dan rahasia akun layanan, mencabut akses berhak tinggi, serta mengambil image forensik sebelum sistem berubah [S4]. Rev. 2 juga mengingatkan dua jebakan. Pertama, membiarkan penyerang tetap aktif demi mengamati (misalnya mengalihkan ke sandbox) harus dibahas dulu dengan bagian hukum karena berbahaya. Kedua, sebagian malware bereaksi saat diputus, misalnya mengenkripsi disk ketika sambungan ke C2 gagal, jadi host yang sudah diputus belum tentu aman dari kerusakan lanjutan [S2].

Satu pertimbangan khas akun cloud: menonaktifkan akun dan mencabut sesi tidak serta-merta mematikan semua akses. Microsoft menjelaskan bahwa setelah akun dinonaktifkan dan refresh token dicabut, aplikasi yang memakai access token baru kehilangan akses saat token itu kedaluwarsa, yang secara bawaan berlaku satu jam, kecuali aplikasinya mendukung continuous access evaluation [S8]. Untuk lingkungan hybrid (AD lokal yang disinkronkan ke Entra ID), Microsoft menyarankan menonaktifkan akun di AD dan mereset password-nya, lalu menonaktifkan akun dan mencabut sesi di Entra ID [S8].

**Contoh di PT JAB:** urutan containment `INC-2027-098`:
1. 07:24 Yoga menonaktifkan akun Bagus di AD dan memaksa sinkronisasi lewat `JKT-SYNC01` (RB-12).
2. 07:25 Yoga menekan Revoke sessions di Entra ID (RB-13).
3. 07:27 Sari menambahkan `192.0.2.183` ke named location yang diblokir di Conditional Access (aturan akses bersyarat di Entra ID). Sejak ini tidak ada aktivitas baru yang berhasil dari IP itu; percobaan terakhir pukul 07:29:40 ditolak.
4. Aturan inbox penyerang sengaja belum dihapus. Aturan itu sudah tidak berbahaya karena akun nonaktif, sedangkan detailnya (nama, kondisi, waktu dibuat, IP pembuat) adalah bukti. Kamu mengekspor sign-in log dan audit log Microsoft 365 lebih dulu (bagian 1.7), baru aturan dihapus di tahap eradication.
5. Karena access token bisa berlaku sampai satu jam, Sari meminta kamu memantau aktivitas akun Bagus sampai 08:30. Tidak ada aktivitas.

Akses penyerang tercatat dari 06:58:12 sampai 07:27, sekitar 29 menit.

**Beda containment dengan eradication:** containment menghentikan penyebaran tanpa harus menghilangkan penyebabnya; eradication menghilangkan penyebabnya. Akun yang dinonaktifkan sudah tertahan, tetapi password yang mungkin ikut dicuri, aturan inbox, dan perangkat pribadi yang terinfeksi masih ada sampai eradication.

**Salah paham umum:**
- "Langkah pertama selalu mematikan komputer." Mematikan perangkat menghapus bukti di memori dan bisa memicu kerusakan. CISA menyarankan isolasi jaringan, dan mematikan perangkat hanya bila tidak bisa diputus dari jaringan (Day 16 bagian 2.4).

### 1.6 Eradication dan recovery

Pertanyaan keenam: kapan akun Bagus boleh hidup lagi? Jawabannya bergantung pada dua fase yang sering disatukan: membersihkan, lalu memulihkan.

**Apa itu:**
- **Eradication** adalah menghilangkan komponen insiden: menghapus malware, menonaktifkan akun yang dibobol, serta mengenali dan menutup semua kerentanan yang dipakai; selama eradication semua host yang terdampak harus diketahui supaya semuanya dibereskan [S2]. Rev. 3 menambahkan bahwa eradication menghilangkan mekanisme persistence dan jalan masuk [S1].
- **Recovery** adalah mengembalikan sistem ke operasi normal, memastikan sistem berfungsi normal, dan bila perlu memperbaiki kerentanan supaya kejadian serupa tidak terulang. Caranya bisa restore dari backup bersih, membangun ulang sistem, mengganti file yang disusupi, memasang patch, mengganti password, dan memperketat control [S2]. Rev. 3 meminta integritas backup dan aset pemulihan diperiksa sebelum dipakai, akar penyebab diperbaiki sebelum sistem kembali ke produksi, dan akhir pemulihan dinyatakan berdasarkan kriteria lalu didokumentasikan [S1].

**Analogi:** eradication adalah memadamkan bara terakhir, termasuk bara yang tersembunyi di balik dinding. Recovery adalah memeriksa instalasi listrik, memperbaiki ruangan, lalu membuka lantai itu kembali sambil petugas berjaga lebih ketat beberapa hari. Batasnya: penyerang sering meninggalkan lebih dari satu "bara" (backdoor, akun tambahan, aturan email), dan CISA mencatat penyerang bisa kembali ke area yang sudah "bersih" bila eradication tidak terkoordinasi [S4].

**Cara kerja:** CISA menetapkan syarat sebelum eradication dimulai: semua jalan akses persisten sudah diketahui, aktivitas penyerang sudah cukup tertahan, dan bukti sudah dikumpulkan [S4]. Contoh kegiatan eradication di playbook CISA: memulihkan semua lingkungan yang terinfeksi, reimage dari sumber "emas" (image standar yang bersih), membangun ulang perangkat keras bila ada rootkit, mengganti file yang disusupi, memasang patch, dan mereset password akun yang dibobol [S4]. Setelah eradication, pemantauan diteruskan untuk melihat apakah penyerang mencoba masuk lagi; bila ada, kembali ke containment dan analisis [S4]. Rev. 2 menyarankan pemulihan bertahap: perubahan cepat bernilai tinggi lebih dulu (hari sampai minggu), perubahan jangka panjang belakangan [S2].

Kriteria "boleh pulih" sebaiknya tertulis, bukan perasaan. Rev. 3 memakai istilah kriteria memulai pemulihan dan kriteria menyatakan akhir pemulihan [S1].

**Contoh di PT JAB:**
- 08:10 eradication di sisi cloud: aturan inbox dihapus (setelah diekspor), daftar metode MFA Bagus diperiksa (tidak ada metode baru), tidak ada aturan penerusan email ke luar, tidak ada aplikasi pihak ketiga yang diberi izin ke akunnya, dan email penyerang ke Rina ditarik dari kotak suratnya.
- Sumber masalah ada di laptop pribadi Bagus, bukan di laptop kantor `JKT-WS-1192` (`10.10.49.92`), yang menurut Defender for Endpoint bersih dan tidak dinyalakan sejak Kamis sore. Bagus mengaku memakai laptop pribadinya Kamis malam pukul 21:30 untuk membuka Outlook versi web, lalu pukul 22:05 memasang "aktivator" software bajakan dari sebuah forum. Pola ini cocok dengan infostealer, malware yang menyalin password dan cookie sesi dari browser (Day 16 bagian 1.5). Laptop pribadi itu diserahkan untuk diperiksa (bagian 1.7) dan tidak boleh lagi dipakai untuk akun kantor.
- Kriteria pemulihan akun yang ditetapkan Sari: tidak ada aktivitas dari IP penyerang setelah 07:29:40, semua token lama sudah melewati batas satu jam, password diganti, dan MFA didaftarkan ulang di depan analyst.
- 10:30 Bagus datang ke meja SOC. Password diganti (password lama dianggap ikut dicuri karena infostealer juga mengambil password tersimpan di browser), MFA didaftarkan ulang, akun diaktifkan kembali, dan Bagus login dari `JKT-WS-1192`. Rule watchlist untuk akunnya dipasang 14 hari sebagai pemantauan pasca-pemulihan.

**Beda eradication dengan recovery:** eradication bertanya "apakah penyerang dan alatnya sudah benar-benar hilang?", recovery bertanya "apakah layanan sudah kembali normal dan aman dipakai?". Recovery tanpa eradication yang tuntas mengulang insiden; eradication tanpa recovery membuat bisnis berhenti lebih lama dari perlu.

**Salah paham umum:**
- "Reset password sudah cukup." Pada pencurian sesi, password tidak dipakai sama sekali; sesi harus dicabut. Sebaliknya, pada infostealer password juga ikut dicuri, sehingga keduanya harus dilakukan, ditambah memeriksa aturan inbox, metode MFA, dan izin aplikasi yang mungkin ditanam penyerang.
- "Restore dari backup terbaru selalu aman." Backup bisa berisi malware atau celah yang sama; Rev. 3 meminta backup diperiksa dulu dari IOC dan kerusakan sebelum dipakai [S1].

### 1.7 Bukti dan chain of custody

Pertanyaan ketujuh: menjelang pukul 09:30 Bagus bersedia menyerahkan laptop pribadinya. Bagaimana supaya hasil pemeriksaannya bisa dipercaya, termasuk bila suatu hari dibawa ke polisi atau pengadilan?

**Apa itu:**
- **Evidence (bukti)** dalam IR adalah data yang menjadi dasar untuk percaya atau tidak percaya sesuatu, untuk membuktikan benar atau salah. Rev. 3 memakai definisi itu dan menegaskan bahwa data insiden tetap dianggap bukti walaupun tidak semua insiden berujung ke proses hukum [S1].
- **Chain of custody** adalah proses yang melacak perpindahan bukti sepanjang pengumpulan, pengamanan, dan analisisnya, dengan mencatat setiap orang yang memegang bukti, tanggal dan waktu bukti dikumpulkan atau dipindahkan, dan tujuan setiap perpindahan [S3].
- **Forensic image** adalah salinan utuh isi disk atau memori, dibuat supaya analisis dilakukan pada salinan, bukan pada barang asli. Keasliannya dibuktikan dengan hash, sidik jari data (Day 05 bagian 1.2): hash salinan yang sama dengan hash sumber berarti isinya identik.
- **Order of volatility** adalah prinsip umum forensik digital: ambil dulu bukti yang paling cepat hilang (isi memori, sambungan jaringan aktif, proses yang berjalan), lalu yang lebih awet (disk, arsip, log). Untuk panduan teknis, NIST punya SP 800-86 tentang memadukan teknik forensik ke dalam IR; panduan itu ditulis dari sudut pandang TI, bukan penegakan hukum, dan menyarankan berkonsultasi dengan manajemen dan bagian hukum sebelum praktiknya diterapkan [S5].

**Analogi:** barang bukti di kantor polisi dimasukkan ke kantong bersegel dengan label nomor, dan setiap kali berpindah tangan dicatat di buku serah terima lengkap dengan tanda tangan. Bila ada satu jam yang tidak tercatat, pengacara pihak lawan bisa bertanya "siapa yang memegang barang ini selama satu jam itu, dan apa yang ia lakukan?". Batasnya: bukti digital bisa berubah tanpa terlihat (cukup dengan menyalakan laptop), sehingga selain catatan serah terima dibutuhkan hash yang membuktikan isinya tidak berubah.

**Cara kerja:** Rev. 2 meminta bukti tercatat setiap saat; setiap kali berpindah tangan, formulir chain of custody mencatat perpindahan itu dengan tanda tangan kedua pihak [S2]. Log bukti memuat [S2]:
- identitas bukti (lokasi, nomor seri, model, hostname, MAC address, IP address);
- nama, jabatan, dan nomor telepon setiap orang yang mengumpulkan atau memegang bukti;
- tanggal dan waktu, termasuk zona waktu, setiap kali bukti ditangani;
- lokasi penyimpanan bukti.

Rev. 2 juga mencatat bahwa snapshot sistem apa adanya jauh lebih berharga daripada snapshot setelah handler dan admin tanpa sengaja mengubah keadaannya [S2]. Tidak semua insiden memerlukan prosedur bukti formal: Rev. 2 mencatat sebagian besar insiden malware tidak memerlukan pengambilan bukti formal, dan Rev. 3 menyebut sebagian besar insiden malware tidak berujung ke penuntutan [S1][S2]. Rev. 3 meminta bukti dikumpulkan dan disimpan sesuai prosedur dan kebijakan retensi organisasi, dengan mempertimbangkan kemungkinan penuntutan dan biaya menyimpan data beserta perangkat untuk membacanya di masa depan [S1]. Catatan kerja analyst sendiri juga harus dijaga kerahasiaan dan keutuhannya, karena berisi kerentanan yang dieksploitasi dan nama orang yang terlibat [S1].

**Contoh di PT JAB:** dua bukti `INC-2027-098` dicatat dengan nomor sendiri.
- `EV-2027-098-02`: ekspor sign-in log Entra ID dan audit log Microsoft 365 untuk akun Bagus, rentang 2027-08-26 00:00 sampai 2027-08-27 08:00, diekspor kamu pukul 07:45 dan disimpan di share bukti SOC beserta hash SHA-256-nya.
- `EV-2027-098-01`: laptop pribadi Bagus. Karena perangkat pribadi, penyerahannya didahului persetujuan tertulis Bagus yang disaksikan bagian SDM pukul 09:30. Laptop dalam keadaan mati, dan sengaja tidak dinyalakan supaya isinya tidak berubah; konsekuensinya isi memori tidak bisa diambil, dan Sari mencatat keputusan itu. Formulir chain of custody-nya ada di bagian 2.2.

**Beda chain of custody dengan log aktivitas analyst:** log aktivitas analyst mencatat apa yang dikerjakan tim (kapan akun dinonaktifkan, siapa yang memutuskan); chain of custody mencatat riwayat satu barang bukti. Keduanya dibutuhkan, dan keduanya harus bertanggal, berjam, dan mencantumkan nama.

**Salah paham umum:**
- "Chain of custody hanya urusan polisi." Keputusan bahwa sebuah insiden akan dibawa ke jalur hukum sering baru diambil berminggu-minggu kemudian, misalnya setelah ternyata ada kerugian uang atau pelakunya orang dalam. Bukti yang tidak dicatat sejak awal tidak bisa "dicatatkan" belakangan.

### 1.8 RCA (root cause analysis)

Pertanyaan kedelapan Sari: penyebabnya cookie yang dicuri, atau aturan PT JAB yang terlalu longgar? Jawabannya: keduanya, di tingkat yang berbeda.

**Apa itu:** RCA (root cause analysis) adalah pendekatan sistematis berbasis prinsip untuk mengenali penyebab dasar dari sekumpulan risiko tertentu [S3]. Rev. 3 meminta analisis insiden menentukan urutan kejadian, kerentanan, ancaman, dan pelaku yang terlibat, lalu mencari akar penyebab yang mendasar atau sistemik; informasi ini membantu menemukan kelemahan manajemen risiko supaya kejadian serupa tidak terulang [S1]. Playbook CISA menyebut langkah ini "identify root cause and enabling conditions", yaitu akar penyebab sekaligus kondisi yang memungkinkannya [S4].

**Analogi:** penyelidik kebakaran tidak berhenti di "apinya dari korsleting". Ia bertanya kenapa kabel itu korsleting (kabel tua yang tidak pernah diganti), kenapa api menjalar ke lantai lain (pintu tahan api diganjal kursi), dan kenapa alarm terlambat (detektor di ruangan itu dicopot saat renovasi). Batasnya: di insiden digital ada penyerang yang sengaja mencari celah, jadi menutup satu akar penyebab tidak menjamin ia tidak menemukan celah lain.

**Cara kerja:** RCA yang baik membedakan tiga lapis:
1. **Penyebab langsung (gejala teknis):** apa yang secara teknis terjadi.
2. **Enabling condition:** kondisi yang membuat penyebab langsung bisa berhasil.
3. **Akar penyebab sistemik:** keputusan, proses, atau kebijakan yang melahirkan kondisi itu.

Teknik sederhana yang banyak dipakai adalah "5 whys": bertanya "kenapa" berulang kali sampai jawabannya berupa sesuatu yang bisa diperbaiki organisasi, bukan kesalahan satu orang. Teknik ini praktik umum lapangan, bukan aturan NIST, dan berguna untuk menghindari RCA yang berhenti di "user ceroboh".

**Contoh di PT JAB:** hasil RCA sementara `INC-2027-098` yang dibahas saat hotwash:
- Penyebab langsung: cookie sesi Microsoft 365 milik Bagus dicuri dari browser laptop pribadinya dan dipakai ulang dari `192.0.2.183`. Teknik ini tercatat di MITRE ATT&CK sebagai Steal Web Session Cookie (T1539), dan MITRE menyebut beberapa keluarga infostealer sebagai pengguna teknik ini [S9].
- Enabling condition: Conditional Access PT JAB mengizinkan Outlook versi web penuh dari perangkat apa pun yang lolos MFA, termasuk perangkat pribadi yang tidak dikelola dan tidak ber-EDR.
- Akar penyebab sistemik: kebijakan perangkat pribadi 2025 dibuat demi kemudahan kerja dari rumah tanpa penilaian risiko pencurian sesi, dan pelatihan keamanan belum menyentuh bahaya software bajakan di perangkat yang dipakai untuk akun kantor.

RCA final menunggu hasil pemeriksaan laptop dan ditulis di after-action report (bagian 1.10). Rincian 5 whys ada di bagian 2.3.

**Beda RCA dengan mencari pelaku:** RCA mencari penyebab yang bisa diperbaiki organisasi; atribusi mencari siapa pelakunya (Day 14). Rev. 2 bahkan mengingatkan bahwa mengidentifikasi host penyerang bisa memakan waktu dan menjauhkan tim dari tujuan utama, yaitu memperkecil dampak bisnis [S2].

**Salah paham umum:**
- "Akar penyebabnya Bagus yang memasang software bajakan." Itu penyebab langsung yang melibatkan satu orang. Bila RCA berhenti di sini, satu-satunya tindakan adalah menegur Bagus, dan karyawan berikutnya dengan laptop pribadi yang terinfeksi akan mengulang kejadian yang sama.

### 1.9 Komunikasi dan pemberitahuan

Pertanyaan kesembilan: siapa yang harus dikabari, Pak Agus perlu tahu atau tidak, dan lewat saluran apa? Komunikasi yang buruk bisa merusak insiden yang secara teknis ditangani dengan baik.

**Apa itu:** Rev. 3 membagi komunikasi insiden menjadi empat jenis [S1]:
- **Koordinasi insiden:** berbagi kegiatan respons yang sedang dan akan dilakukan di antara pihak internal dan eksternal yang punya peran.
- **Pemberitahuan insiden (notification):** memberi tahu secara resmi pelanggan, karyawan, mitra, regulator, atau pihak lain yang terdampak tentang kebocoran data atau insiden lain.
- **Komunikasi publik:** menyampaikan status insiden ke publik, misalnya menjawab pertanyaan media.
- **Berbagi informasi insiden:** berbagi informasi ancaman dengan organisasi lain, biasanya sukarela, misalnya TTP ke ISAC sektor.

Rev. 3 juga meminta prosedur yang menyebut apa yang dilaporkan ke siapa dan kapan (pemberitahuan awal, pembaruan status berkala), pemberitahuan yang patuh pada hukum dan regulasi yang berlaku, serta pembaruan rutin ke pimpinan senior untuk insiden besar [S1].

**Analogi:** saat kebakaran, komandan regu melapor ke pengelola gedung, pengelola memberi tahu penghuni, dan humas menjawab wartawan; tidak semua orang boleh bicara ke wartawan. Bila telepon gedung ikut terbakar, regu memakai walkie-talkie. Batasnya: di insiden digital, "telepon gedung" (email dan chat kantor) bisa disadap penyerang tanpa terlihat terbakar.

**Cara kerja:** tiga prinsip yang dipakai PT JAB:
1. **Saluran yang tidak dikuasai penyerang.** Kotak surat Bagus dikuasai penyerang, jadi semua kontak dengan Bagus lewat telepon. Untuk insiden besar seperti domain AD dikuasai, email dan chat Microsoft 365 bisa ikut terpantau, sehingga dibutuhkan out-of-band communication, saluran cadangan di luar sistem yang mungkin dikuasai; playbook CISA memasukkan saluran out-of-band ke daftar persiapan [S4].
2. **Satu sumber kebenaran.** IC atau orang yang ditunjuk menulis pembaruan status di tiket insiden dengan jam tertentu; pihak lain tidak menyebarkan versi sendiri.
3. **Kewajiban hukum diputuskan pemiliknya.** Kebijakan pemberitahuan yang diatur undang-undang menjadi wewenang DPO dan penasihat hukum. UU No. 27 Tahun 2022 tentang Pelindungan Data Pribadi (UU PDP) mewajibkan pengendali data memberi pemberitahuan tertulis paling lambat 3 x 24 jam kepada subjek data dan lembaga pengawas bila terjadi kegagalan pelindungan data pribadi (Day 18 bagian 1.6). Tugas SOC adalah menyediakan fakta secepat dan seakurat mungkin: data apa, milik berapa orang, kapan, dan apa yang sudah dilakukan. PT JAB menetapkan SOC melapor ke DPO paling lambat 2 jam setelah ada indikasi data pribadi terlibat.

**Contoh di PT JAB:**
- 07:38 alert `SOC-2027-0899`: Rina Anggraini melaporkan email dari akun Bagus yang asli, pukul 07:19, berjudul "RE: Tagihan Agustus PT Mitra Data Sentosa - perubahan rekening", berisi permintaan membayar tagihan Rp 212.750.000 ke rekening baru. Email itu lolos SPF, DKIM, dan DMARC karena memang dikirim dari kotak surat PT JAB sendiri; berbeda dengan email BEC dari domain mirip di Day 09 bagian 2.1. Rina menelepon vendor di nomor yang tercatat di data induk vendor, vendor menyangkal ganti rekening, dan Rina tidak membayar.
- 08:55 scoping audit log selesai: penyerang membuka 214 email dalam 29 menit. Enam di antaranya berisi formulir pendaftaran vendor dengan pindaian KTP enam orang narahubung vendor.
- 09:05 Sari mengabari Agus Setiawan (DPO) dan Dimas, 1 jam 43 menit setelah insiden dinyatakan, di dalam batas 2 jam. Pukul 11:30 Agus, setelah mencocokkan isi keenam email, menetapkan kejadian ini sebagai kegagalan pelindungan data pribadi yang diketahui secara pasti. Bila titik itu dipakai sebagai awal hitungan, tenggat 3 x 24 jam jatuh pada Senin 2027-08-30 pukul 11:30. Isi dan penerima pemberitahuan diputuskan Agus bersama penasihat hukum.
- Pembaruan status ke Dimas pukul 07:30, 09:05, dan 11:45 lewat tiket insiden; Hendra tidak dikabari langsung karena SEV-3, tetapi masuk ringkasan harian.

**Beda pemberitahuan dengan berbagi informasi:** pemberitahuan sering wajib dan ditujukan ke pihak yang terdampak atau berwenang; berbagi informasi biasanya sukarela dan ditujukan ke komunitas supaya organisasi lain bisa bertahan. PT JAB mengirim IP `192.0.2.183` dan pola aturan inbox ke CSIRT sektor dengan label TLP (Day 12 bagian 1.12), tanpa data pribadi apa pun.

**Salah paham umum:**
- "SOC yang memutuskan apakah insiden wajib dilaporkan ke regulator." SOC menyediakan fakta dan mengabari DPO tepat waktu; keputusan dan isi pemberitahuan ada di DPO dan penasihat hukum (Day 18 bagian 1.6).

### 1.10 Lessons learned (post-incident activity)

Pertanyaan terakhir Sari: hotwash pukul 13:30. Insiden sudah tertahan dan akun pulih; kenapa masih perlu rapat?

**Apa itu:** post-incident activity adalah fase terakhir model Rev. 2, berisi lessons learned, laporan tindak lanjut, dan pemanfaatan data insiden [S2]. **Lessons learned** adalah peninjauan atas apa yang terjadi, apa yang dilakukan, dan seberapa efektif tindakan itu, untuk menemukan perbaikan. Rev. 2 menyebutnya salah satu bagian IR yang paling penting sekaligus yang paling sering dilewatkan [S2]. Rev. 3 memasukkannya ke kategori Improvement (ID.IM) dan menekankan bahwa pelajaran bisa didapat kapan saja, tidak hanya setelah insiden selesai [S1]. **Hotwash** adalah istilah playbook CISA untuk analisis lessons learned yang meninjau efektivitas dan efisiensi penanganan, mencatat akar penyebab awal, masalah saat menjalankan tindakan, serta kebijakan dan prosedur yang belum ada [S4]. **After-action report** adalah laporan yang mendokumentasikan insiden, tindakan respons dan pemulihan, serta lessons learned; Rev. 3 menjadikannya bagian dari menyatakan akhir pemulihan [S1].

**Analogi:** briefing regu pemadam begitu kembali ke pos (hotwash), lalu rapat evaluasi resmi beberapa hari kemudian bersama pengelola gedung, dan berita acara kebakaran (after-action report). Batasnya: evaluasi kebakaran jarang menyalahkan api, sedangkan evaluasi insiden mudah tergelincir menyalahkan orang; rapat lessons learned yang efektif membahas proses dan keputusan, bukan mencari kambing hitam.

**Cara kerja:** Rev. 2 menyarankan rapat lessons learned dengan semua pihak yang terlibat, wajib untuk insiden besar dan opsional untuk insiden kecil, diadakan dalam beberapa hari setelah insiden berakhir [S2]. Pertanyaan yang dijawab, antara lain [S2]:
- Apa tepatnya yang terjadi, dan pada jam berapa?
- Seberapa baik staf dan manajemen menangani insiden; apakah prosedur diikuti dan memadai?
- Informasi apa yang seharusnya didapat lebih cepat?
- Apakah ada tindakan yang justru menghambat pemulihan?
- Apa yang akan dilakukan berbeda bila kejadian serupa terulang?
- Tindakan korektif apa yang mencegah insiden serupa?
- Precursor atau indicator apa yang perlu dipantau ke depan?
- Alat atau sumber daya tambahan apa yang dibutuhkan?

Hasilnya harus berupa daftar tindakan dengan pemilik dan tenggat, dan prosedur yang ternyata kurang langkah harus diperbarui [S2]. CISA menambahkan penyesuaian sensor, alert, dan pengumpulan log supaya teknik penyerang yang berhasil kali ini terdeteksi di seluruh organisasi, serta menutup "blind spot" [S4]. Data insiden yang terkumpul dari waktu ke waktu juga dipakai untuk menilai tren dan kinerja tim, misalnya MTTD dan MTTR (Day 10 bagian 1.13) [S2].

**Contoh di PT JAB:** hotwash 30 menit pukul 13:30 dihadiri Sari, Yoga, kamu, dan Dimas. Rapat lessons learned resmi dijadwalkan Rabu 2027-09-01 pukul 10:00 dengan Agung Prabowo (Lead Infrastruktur, pemilik Conditional Access), Nina Kartika (Manajer Risiko dan Kepatuhan TI), Agus Setiawan, dan atasan Rina. After-action report ditargetkan Jumat 2027-09-03. Catatan hotwash dan daftar tindakan ada di bagian 2.4.

**Beda lessons learned dengan RCA:** RCA menjawab "kenapa insiden terjadi"; lessons learned menjawab "apa yang kita pelajari dari seluruh kejadian, termasuk cara kita menanganinya". Hasil RCA adalah salah satu masukan lessons learned.

**Salah paham umum:**
- "Insiden kecil tidak perlu lessons learned." Rev. 2 memang menjadikannya opsional untuk insiden kecil, tetapi insiden kecil yang memakai metode serangan baru tetap layak dibahas [S2]. `INC-2027-098` hanya SEV-3, tetapi teknik pencurian sesinya bisa mengenai karyawan mana pun yang memakai perangkat pribadi.

## 2. Contoh nyata: `INC-2027-098` dari alert sampai hotwash

Semua contoh di bagian ini adalah keluaran ilustrasi dari organisasi fiktif. Keempat artefak berikut adalah dokumen yang kamu tulis atau baca sepanjang Jumat itu, dan bersama-sama memperlihatkan siklus IR dari bagian 1 bekerja di satu insiden kecil.

### 2.1 Lini waktu `INC-2027-098`

Lini waktu adalah dokumen pertama yang diminta IC dan yang paling sering dibaca ulang. Sari memintamu menulisnya sejak 07:22 dengan satu aturan: setiap baris punya jam, sumber fakta, dan siapa yang bertindak.

```
INC-2027-098  Akun M365 bagus.wicaksono diambil alih lewat sesi curian      SEV-3   IC: Sari Kusuma
Zona waktu: WIB (UTC+7)

Kamis 2027-08-26
21:30          Bagus membuka Outlook web di laptop pribadi (keterangan Bagus)
22:05          Bagus memasang "aktivator" software bajakan di laptop yang sama (keterangan Bagus;
               dikonfirmasi analisis image 14:10)
Jumat 2027-08-27
06:58:12       Sign-in pertama dari 192.0.2.183, sesi dipakai ulang, tanpa prompt MFA (sign-in log Entra ID)
07:05          SOC-2027-0897 P2: watchlist IP 192.0.2.183 cocok dengan sign-in berhasil (Splunk)
07:10          Ack oleh kamu (L1)
07:14          Telepon kantor ke Bagus: tidak sedang login, di kereta (PB-04 langkah 1)
07:14-07:15    Aturan inbox "..": kata "rekening", "pembayaran", "transfer" ke RSS Feeds (audit log)
07:16          SOC-2027-0898 P2: aturan inbox mencurigakan (Defender for Office 365)
07:17          Eskalasi ke Sari (L2) dengan paket fakta
07:19          Email dari akun Bagus ke Rina Anggraini: "RE: Tagihan Agustus PT Mitra Data Sentosa
               - perubahan rekening", Rp 212.750.000 (audit log, laporan Rina)
07:22          INC-2027-098 dinyatakan, SEV-3, IC Sari
07:24          Akun dinonaktifkan di AD, sinkronisasi dipaksa (Yoga, RB-12)
07:25          Revoke sessions di Entra ID (Yoga, RB-13)
07:27          192.0.2.183 diblokir di Conditional Access (Sari)
07:29:40       Percobaan terakhir dari 192.0.2.183, ditolak
07:38          SOC-2027-0899: Rina melapor lewat tombol Report; vendor sudah ditelepon, tidak ada transfer
07:45          Ekspor sign-in log dan audit log, EV-2027-098-02 (kamu)
08:10          Eradication cloud: aturan inbox dihapus, email ke Rina ditarik, MFA/forwarding/izin aplikasi dicek
08:30          Pemantauan sisa access token selesai: tidak ada aktivitas
08:55          Scoping audit log: 214 email dibuka; 6 berisi pindaian KTP narahubung vendor
09:05          Lapor ke Agus Setiawan (DPO) dan Dimas (elevasi)
09:30          Persetujuan tertulis Bagus atas pemeriksaan laptop pribadi, disaksikan SDM
09:40          Laptop pribadi diserahkan ke Sari, EV-2027-098-01
10:15-11:40    Forensic image laptop (Yoga)
10:30          Password diganti, MFA didaftarkan ulang, akun aktif kembali; watchlist akun 14 hari
11:30          DPO menetapkan kegagalan pelindungan data pribadi diketahui secara pasti
13:30          Hotwash
14:10          Analisis image: file "aktivator" di folder Downloads dikenali sebagai infostealer
```

**Cara membaca:**
- Jarak dari aktivitas penyerang pertama (06:58:12) ke alert (07:05) adalah 6 menit 48 detik. Ini deteksi yang cepat, tetapi hanya karena IP penyerang kebetulan ada di watchlist; dengan IP baru, alert pertama baru akan muncul dari aturan inbox pukul 07:16. Hal ini dibahas di hotwash.
- Dari alert ke akses penyerang terputus (07:27) adalah 22 menit; seluruh akses penyerang berlangsung sekitar 29 menit (06:58:12 sampai 07:27).
- Baris 07:14 sampai 07:19 menunjukkan apa yang dicari penyerang: aturan inbox menyembunyikan balasan soal rekening, lalu email penipuan dikirim dari akun asli. Polanya BEC dari dalam (Day 09 bagian 1.3), hanya saja kali ini lewat akun yang sungguh-sungguh dibobol.
- Baris 08:55 adalah titik balik: insiden yang semula "hanya" akun diambil alih ternyata menyentuh data pribadi, sehingga kewajiban pemberitahuan muncul.

**Variasi:** pada insiden SEV-1, lini waktu yang sama dipegang orang khusus (scribe), bukan analyst yang juga mengerjakan tugas teknis, sesuai saran Rev. 2 agar handler bekerja berdua: satu mencatat, satu mengerjakan [S2].

### 2.2 Formulir chain of custody laptop pribadi

Pertanyaan ketujuh Sari dijawab di formulir ini. Setiap kali laptop berpindah tangan, satu baris ditambahkan dan ditandatangani kedua pihak.

```
FORMULIR CHAIN OF CUSTODY                                   No. bukti: EV-2027-098-01
Insiden      : INC-2027-098
Barang       : Laptop pribadi 14 inci milik Bagus Wicaksono (bukan aset PT JAB)
Nomor seri   : NB14-7Q2K91        Hostname: BAGUS-PC        MAC Wi-Fi: 00:00:5E:00:53:2A
Kondisi awal : Mati, layar tertutup, charger ikut diserahkan. Tidak dinyalakan.
Dasar        : Persetujuan tertulis pemilik, 2027-08-27 09:30 WIB, saksi Ratih Purnomo (SDM)

No  Tanggal/jam (WIB)   Dari                    Ke                     Tujuan                         Segel
1   2027-08-27 09:40    Bagus Wicaksono         Sari Kusuma (L2)       Penyerahan untuk pemeriksaan   S-0412 dipasang
2   2027-08-27 10:05    Sari Kusuma             Yoga Pratama (L2)      Pembuatan forensic image       S-0412 dibuka 10:10, disaksikan Sari
3   2027-08-27 11:50    Yoga Pratama            Sari Kusuma            Penyimpanan                    S-0413 dipasang
4   2027-08-27 11:55    Sari Kusuma             Lemari bukti SOC L2    Disimpan, kunci di Dimas       S-0413 utuh

Image        : EV-2027-098-01-IMG, dibuat 10:15-11:40 dengan write blocker
SHA-256 image: 7b9dbaf2f28a31ea772437b5b17a0103d3154e6d9af16db290e2067b83ff8bc3
Lokasi image : share bukti SOC (akses terbatas L2 dan SOC lead), salinan kedua di media terenkripsi
Catatan      : Memori tidak diambil karena laptop diterima dalam keadaan mati; keputusan Sari 09:40.
```

**Cara membaca:**
- Baris "Dasar" penting untuk perangkat pribadi. PT JAB tidak berhak memeriksa laptop karyawan tanpa izin; persetujuan tertulis dan saksi dari SDM melindungi organisasi dan karyawan.
- Setiap baris menjawab empat hal yang diminta Rev. 2: siapa, kapan (dengan zona waktu), apa yang terjadi, dan di mana barang berada [S2]. Tidak ada jam yang kosong antara 09:40 dan 11:55.
- Write blocker adalah alat yang membuat disk sumber hanya bisa dibaca selama penyalinan, sehingga pembuatan image tidak mengubah isi laptop. Hash SHA-256 menghubungkan barang fisik dan salinannya. Analisis dikerjakan pada salinan; bila hasilnya digugat, salinan baru bisa dibuat dari laptop dan hash-nya dicocokkan.
- Baris "Catatan" mencatat keputusan yang membatasi bukti. Menyembunyikan keterbatasan lebih berbahaya daripada mengakuinya.

**Kapan gagal:** formulir ini tidak berguna bila laptop sempat dinyalakan "sebentar untuk mengecek" sebelum image dibuat, bila segel dibuka tanpa saksi, atau bila ada perpindahan yang tidak dicatat, misalnya laptop dititipkan di meja selama makan siang.

### 2.3 Ringkasan RCA dan tindakan perbaikan

Pertanyaan kedelapan dijawab dengan 5 whys yang disusun bersama saat hotwash. Setiap jawaban menjadi pertanyaan berikutnya, sampai ketemu sesuatu yang bisa diperbaiki organisasi.

```
Masalah: penyerang membaca 214 email dan mengirim permintaan ganti rekening dari akun Bagus

Kenapa 1? Penyerang memegang cookie sesi Microsoft 365 yang masih berlaku.
Kenapa 2? Cookie dicuri infostealer dari browser laptop pribadi Bagus (T1539).
Kenapa 3? Laptop pribadi tanpa EDR dan tanpa pengelolaan boleh membuka Outlook web penuh.
Kenapa 4? Conditional Access hanya mensyaratkan MFA, tidak mensyaratkan perangkat yang dikelola.
Kenapa 5? Kebijakan perangkat pribadi 2025 dibuat demi kemudahan kerja dari rumah tanpa penilaian
          risiko pencurian sesi, dan pelatihan belum membahas software bajakan.

Penyebab langsung   : cookie sesi dicuri dan dipakai ulang
Enabling condition  : akses penuh dari perangkat tidak dikelola; sesi tidak terikat ke perangkat
Akar sistemik       : kebijakan perangkat pribadi tanpa penilaian risiko; celah materi pelatihan
Faktor yang menolong: watchlist IP, deteksi aturan inbox, verifikasi telepon oleh Rina
```

**Cara membaca:** jawaban "kenapa 2" adalah tempat RCA yang dangkal berhenti. Jawaban "kenapa 3" sampai "kenapa 5" mengubah pertanyaan dari "siapa yang salah" menjadi "aturan mana yang membuat kesalahan satu orang berdampak ke organisasi". Baris "Faktor yang menolong" sama pentingnya: control yang bekerja harus dipertahankan, bukan hanya celah yang ditambal.

**Kapan gagal:** 5 whys menghasilkan satu rantai, padahal insiden sering punya beberapa penyebab yang berjalan bersamaan. Untuk insiden besar, tim biasanya menyusun beberapa rantai sekaligus atau memakai teknik lain, dan RCA final menunggu bukti lengkap. Di `INC-2027-098`, rantai ini masih sementara sampai analisis laptop selesai.

### 2.4 Catatan hotwash dan pemetaan ke dua model

Catatan hotwash pukul 13:30 ditulis Dimas dan menjadi bahan rapat lessons learned Rabu depan. Tabel pertama berisi daftar tindakan; perhatikan bahwa setiap tindakan punya pemilik dan tenggat, karena tindakan tanpa pemilik jarang dikerjakan.

| No | Temuan | Tindakan | Pemilik | Tenggat |
|---|---|---|---|---|
| 1 | Perangkat pribadi bisa memegang sesi penuh | Conditional Access: perangkat tidak dikelola hanya boleh akses web terbatas (tanpa unduh); evaluasi fitur pengikatan sesi ke perangkat dan cek lisensinya | Agung Prabowo | 2027-09-30 |
| 2 | Deteksi bergantung pada IP yang kebetulan ada di watchlist | Use case baru: sesi dipakai dari IP atau ASN baru tanpa MFA interaktif | Sari Kusuma | 2027-09-15 |
| 3 | PB-04 belum menyebut aturan inbox, email terkirim, dan DPO | Tambah langkah: cek aturan inbox, email terkirim, izin aplikasi; lapor DPO bila kotak surat berisi data pribadi | Dimas Prasetyo | 2027-09-08 |
| 4 | Software bajakan di perangkat pribadi | Materi pelatihan: perangkat pribadi dan software bajakan; pengingat ke seluruh karyawan | Nina Kartika | 2027-09-30 |
| 5 | Formulir vendor berisi pindaian KTP tersimpan di email | Pindahkan dokumen vendor ke sistem pengadaan dengan akses terbatas; tinjau retensi | Agus Setiawan dan kepala Pengadaan | 2027-10-31 |
| 6 | Verifikasi telepon oleh Keuangan mencegah kerugian | Pertahankan; jadikan contoh di pelatihan | Nina Kartika | Berjalan |

Tabel kedua memetakan kegiatan hari itu ke dua model NIST di bagian 1.1; tabel ini adalah jawaban praktis untuk "kita pakai model yang mana".

| Kegiatan `INC-2027-098` | Fase Rev. 2 | Fungsi CSF 2.0 (Rev. 3) |
|---|---|---|
| Watchlist, PB-04, pelatihan Rina, Conditional Access dengan MFA | Preparation | Govern, Identify, Protect |
| Alert, telepon Bagus, scoping 214 email, deklarasi SEV-3 | Detection and analysis | Detect, Respond |
| Nonaktifkan akun, cabut sesi, blokir IP | Containment | Respond |
| Hapus aturan inbox, cek MFA dan izin aplikasi, ganti password | Eradication | Respond |
| Aktifkan akun, MFA ulang, pemantauan 14 hari | Recovery | Recover |
| Lapor DPO, berbagi IOC ke CSIRT sektor | Detection and analysis sampai post-incident | Respond, Recover |
| Hotwash, RCA, enam tindakan perbaikan | Post-incident activity | Identify (Improvement) |

**Cara membaca:** satu kegiatan bisa jatuh di fungsi yang berbeda dari fasenya, misalnya pemberitahuan berjalan sejak tengah insiden, bukan setelahnya. Itu sebabnya Rev. 3 tidak lagi menggambar siklus sebagai lingkaran yang rapi [S1].

**Metrik yang dicatat Dimas untuk dashboard bulanan (Day 10 bagian 1.13):** waktu sampai deteksi 6 menit 48 detik dari aktivitas penyerang pertama, waktu sampai ack 5 menit (07:05 ke 07:10), waktu sampai containment 22 menit dari alert, dan waktu sampai akun pulih 3 jam 25 menit dari alert (07:05 ke 10:30).

## 3. Glosarium A-Z (Day 01 sampai 19)

Glosarium ini merangkum semua istilah dari tabel 1.0 Day 01 sampai 19. Pakai untuk mengecek arti singkat sebelum interview atau saat membaca laporan; kolom Day menunjuk Day tempat istilah itu dijelaskan, dan bila lebih dari satu, istilah itu dibahas dari sudut berbeda di masing-masing Day. Istilah yang punya dua arti (misalnya policy, procedure, domain) dipecah menjadi dua baris dengan keterangan di dalam kurung.

| Istilah | Arti singkat | Day |
|---|---|---|
| 802.1X dan RADIUS | Standar autentikasi di port jaringan, dan server yang memutuskan | 03 |
| AAA | Singkatan authentication, authorization, accounting | 01 |
| Access broker | Penjahat yang membobol jaringan lalu menjual aksesnya | 16 |
| Access key | Pasangan ID dan secret untuk akses program ke cloud, berlaku sampai dicabut | 08 |
| Account lockout | Akun dikunci sementara setelah sejumlah login gagal | 15 |
| Accounting | Mencatat siapa memakai apa, kapan, dan berapa banyak | 01 |
| Active Directory (AD DS) | Directory service buatan Microsoft untuk jaringan Windows | 07 |
| Adversary (Diamond Model) | Pelaku atau organisasi di balik kejadian | 14 |
| Adverse event | Event yang membawa akibat negatif, apa pun penyebabnya | 11 |
| Adware / PUP | Software yang menampilkan iklan atau tidak diinginkan, berada di antara software sah dan malware | 16 |
| AES | Standar symmetric encryption yang paling banyak dipakai | 05 |
| After-action report | Laporan akhir insiden: kejadian, tindakan respons dan pemulihan, serta lessons learned | 19 |
| Agen (agent) | Program kecil yang dipasang di endpoint untuk mengawasi dan melapor | 06 |
| AiTM (adversary-in-the-middle) | Adversary-in-the-middle: situs palsu yang meneruskan login ke situs asli dan mencuri sesinya | 06, 09 |
| Akun | Rekaman di sebuah sistem yang dipakai identitas untuk login | 06 |
| Alert | Pemberitahuan dari alat atau rule bahwa satu atau beberapa event perlu diperiksa | 11 |
| Alert fatigue | Kelelahan dan kebal terhadap alert karena terlalu banyak alert yang tidak berarti | 11 |
| Alignment | Kecocokan domain From dengan domain yang lolos SPF atau DKIM | 09 |
| Allowlist | Daftar entitas yang sudah diketahui sah dan dikecualikan dari rule tertentu | 11 |
| Amplification | Jawaban server jauh lebih besar daripada permintaannya | 04 |
| Amplification factor (BAF) | Perbandingan ukuran jawaban dengan ukuran permintaan | 04 |
| Analisis dinamis | Menjalankan file di lingkungan terkendali dan mengamati perilakunya | 13 |
| Analisis statis | Memeriksa file tanpa menjalankannya | 13 |
| Anomali | Penyimpangan dari baseline; belum tentu jahat | 13 |
| Anomaly-based | Deteksi dengan membandingkan aktivitas terhadap profil normal | 03 |
| Antivirus | Program yang mengenali dan menghentikan malware, terutama dengan mencocokkan ciri yang sudah dikenal | 06 |
| Anycast | Satu alamat IP yang diumumkan dari banyak lokasi sekaligus | 04 |
| API | Pintu teknis tempat program mengirim perintah ke layanan, misalnya "buat bucket" | 08 |
| Application allowlisting | Hanya program yang ada di daftar persetujuan yang boleh berjalan | 06 |
| APT | Advanced persistent threat; pelaku bersumber daya besar yang bertahan lama | 14 |
| ARP | Protokol untuk mencari MAC address dari sebuah IP di jaringan lokal | 02 |
| AS | Autonomous System, satu jaringan besar dengan kebijakan routing sendiri, diberi nomor ASN | 04 |
| Asset | Apa pun yang bernilai bagi organisasi: data, sistem, perangkat, orang, fasilitas | 01 |
| Asymmetric encryption | Sepasang kunci berbeda: public key dan private key | 05 |
| Atribusi | Menentukan siapa pelaku sebuah serangan | 14 |
| Attack surface | Semua titik yang bisa dicoba penyerang untuk masuk atau mengambil data | 01 |
| Aturan 3-2-1 | Tiga salinan, dua jenis media, satu di luar lokasi | 18 |
| Audit | Pemeriksaan independen atas catatan dan kegiatan untuk menilai kecukupan control dan kepatuhan | 18 |
| Authentication | Membuktikan bahwa pengguna memang orang yang ia klaim | 01 |
| Authentication-Results | Catatan hasil pemeriksaan SPF, DKIM, DMARC oleh server penerima | 09 |
| Authenticator | Benda atau aplikasi yang membuktikan faktor (aplikasi HP, kunci FIDO2) | 06 |
| Authorization | Menentukan apa yang boleh dilakukan pengguna yang sudah dikenali | 01 |
| Availability | Informasi dan layanan bisa dipakai saat dibutuhkan | 01 |
| Availability Zone (AZ) | Satu atau beberapa data center terpisah di dalam satu region | 08 |
| Azure Activity Log | Log Azure yang mencatat operasi pengelolaan sumber daya | 08 |
| Azure RBAC | Sistem izin Azure berbasis role, diberikan pada scope tertentu | 08 |
| Backdoor | Jalan masuk tersembunyi yang melewati pemeriksaan normal | 16 |
| Backup | Salinan data yang disimpan terpisah untuk pemulihan | 18 |
| Bandwidth | Kapasitas jalur, diukur dalam bit per detik (Mbps, Gbps, Tbps) | 04 |
| Base64 | Encoding yang mengubah data apa pun menjadi 64 karakter teks aman | 05 |
| Baseline | Gambaran perilaku normal yang dihitung dari data masa lalu | 10, 13, 15 |
| BCP | Business continuity plan: rencana supaya proses bisnis tetap berjalan selama dan setelah gangguan besar | 18 |
| BCP 38 | Praktik ISP menolak paket dari pelanggan yang alamat asalnya bukan milik pelanggan itu | 04 |
| Beaconing | Malware menghubungi C2 secara berkala untuk melapor dan minta perintah | 16 |
| BEC (business email compromise) | Penipuan lewat email bisnis yang berujung transfer uang atau data | 09 |
| Benign positive (BP) | Alert benar mendeteksi aktivitas nyata, tetapi aktivitas itu sah dan diharapkan; disebut juga benign true positive | 11 |
| BGP | Protokol yang dipakai jaringan besar untuk saling mengumumkan alamat yang bisa dijangkau | 04 |
| BGP Flowspec | Mengirim aturan penyaring lalu lintas yang rinci lewat BGP ke router hulu | 04 |
| BIA | Business impact analysis: analisis proses mana yang paling penting dan berapa lama boleh terhenti | 18 |
| Block Public Access | Pengaturan S3 yang memblokir semua cara membuat bucket menjadi publik | 08 |
| Blue team | Tim yang bertahan: memantau, mendeteksi, dan merespons | 17 |
| Botnet | Jaringan perangkat terinfeksi yang dikendalikan bersama | 04, 16 |
| Brute force | Mencoba banyak tebakan password sampai ada yang benar | 15 |
| Bucket | Wadah penyimpanan file (object) di layanan seperti Amazon S3 | 08 |
| Bucket policy | Policy yang ditempel langsung ke bucket | 08 |
| Bug bounty | Program yang memberi imbalan bagi pelapor kerentanan yang sah | 17 |
| C2 (command and control) | Server dan saluran yang dipakai penyerang untuk memberi perintah ke malware | 16 |
| CA (certificate authority) | Pihak tepercaya yang menerbitkan dan mencabut sertifikat | 05 |
| Campaign | Rangkaian intrusi dalam periode tertentu dengan target dan tujuan yang sama | 14 |
| Canary token | Nama populer untuk honeytoken yang memanggil alamat tertentu saat dibuka, sehingga pembuatnya diberi tahu | 13 |
| Capability (Diamond Model) | Alat dan teknik yang dipakai pelaku | 14 |
| CASB | Cloud Access Security Broker: pengawas pemakaian aplikasi cloud oleh karyawan | 08 |
| CDN (content delivery network) | Jaringan server bersama yang melayani banyak situs dari IP yang sama | 04, 12 |
| CEO fraud | Jenis BEC yang meniru eksekutif untuk menekan karyawan | 09 |
| Certificate | Dokumen digital bertanda tangan CA yang mengikat public key ke sebuah nama | 05 |
| Chain of custody | Catatan yang melacak siapa memegang bukti, kapan, dan untuk apa, sejak dikumpulkan sampai dianalisis | 19 |
| CIA triad | Tiga sifat informasi yang dijaga: confidentiality, integrity, availability | 01 |
| Cipher suite | Paket algoritma yang dipakai sebuah sambungan TLS | 05 |
| CISA KEV | Katalog kerentanan yang sudah terbukti dieksploitasi di dunia nyata | 17 |
| Cloud computing | Memakai sumber daya komputasi milik penyedia lewat jaringan, sesuai kebutuhan, bayar sesuai pemakaian | 08 |
| Cloud IAM | Sistem pengatur identitas dan izin di dalam akun cloud | 08 |
| Cloud service provider (CSP) | Perusahaan penyedia layanan cloud, misalnya AWS, Microsoft Azure, Google Cloud | 08 |
| CloudTrail | Layanan log AWS yang mencatat aktivitas akun | 08 |
| CNA | Organisasi yang berwenang memberi nomor CVE dan menerbitkan CVE Record | 17 |
| CNAPP | Cloud-Native Application Protection Platform: paket gabungan CSPM, CWPP, dan pemeriksaan kode | 08 |
| Code signing | Tanda tangan digital pembuat software pada programnya | 15 |
| Collision | Dua data berbeda yang menghasilkan hash yang sama | 05 |
| Compliance | Keadaan memenuhi kewajiban dari luar dan dari dalam, beserta buktinya | 18 |
| Computer account | Akun milik satu komputer yang tergabung ke domain | 07 |
| Confidentiality | Hanya pihak yang berhak bisa melihat informasi | 01 |
| Confusion matrix | Tabel empat kotak yang menghitung TP, FP, FN, dan TN | 11 |
| Console | Halaman web untuk mengelola layanan cloud dengan klik | 08 |
| Containment | Menahan insiden supaya tidak meluas dan kerusakan tidak bertambah | 19 |
| Control | Pengaman (alat, aturan, atau proses) untuk menurunkan risiko | 01 |
| Control plane / data plane | Perintah mengelola sumber daya / perintah memakai isi sumber daya | 08 |
| Coordinated disclosure | Penemu melapor ke pemilik dulu, lalu diumumkan bersama setelah ada perbaikan | 17 |
| Corrective control | Pengaman yang membatasi kerusakan dan memulihkan | 01 |
| Correlation rule | Aturan yang mencocokkan dua kejadian atau lebih lalu memunculkan alert | 10 |
| Courses of action | Daftar tindakan bertahan per tahap (detect, deny, disrupt, degrade, deceive, destroy) | 14 |
| Credential stuffing | Mencoba pasangan username dan password yang bocor dari layanan lain | 15 |
| CSIRT | Computer security incident response team, tim tanggap insiden siber | 12 |
| CSPM | Cloud Security Posture Management: pemeriksa konfigurasi cloud | 08 |
| CSRF (cross-site request forgery) | Browser korban yang sudah login dibuat mengirim permintaan yang tidak ia maksud | 15 |
| CVE | Sistem penamaan publik untuk kerentanan; satu celah, satu nomor | 17 |
| CVSS | Standar skor 0,0 sampai 10,0 untuk keparahan teknis kerentanan | 17 |
| CWE | Daftar jenis kelemahan (akar masalah) di perangkat lunak dan perangkat keras | 17 |
| CWPP | Cloud Workload Protection Platform: pelindung server, container, dan fungsi di cloud | 08 |
| Cyber Kill Chain | Model tujuh tahap serangan dari Lockheed Martin | 14 |
| Cybercrime | Kejahatan siber yang terutama mengejar uang | 14 |
| D3FEND | Katalog tindakan bertahan dari MITRE, pasangan ATT&CK | 14 |
| DDoS | DoS yang dilakukan dari banyak sumber sekaligus | 04 |
| Deception | Strategi pertahanan yang sengaja menyesatkan penyerang dengan hal palsu | 13 |
| Defense in depth | Pengaman berlapis dengan jenis yang berbeda-beda | 01 |
| Denial (cyber denial) | Menghalangi atau melemahkan kemampuan penyerang menjalankan operasinya | 13 |
| Deny by default | Semua yang tidak diizinkan secara tegas ditolak | 03 |
| Detection and analysis | Menemukan tanda insiden, memastikannya, menilai cakupan, dan menentukan prioritas | 19 |
| Detection engineering | Pekerjaan menulis, menguji, dan merawat aturan deteksi | 13 |
| Detective control | Pengaman yang mengetahui dan mencatat kejadian | 01 |
| Deteksi proaktif | Cara menemukan ancaman yang tidak menunggu aturan otomatis berbunyi | 13 |
| Detonation | Menjalankan atau membuka file di sandbox untuk melihat perilakunya | 13 |
| Diamond Model | Model satu kejadian intrusi dengan empat sudut | 14 |
| Digital signature | Bukti kriptografis siapa pembuat data dan bahwa data tidak berubah | 05 |
| Directory service | Basis data terstruktur berisi informasi orang, komputer, dan sumber daya jaringan, plus cara mencarinya | 07 |
| Display name | Nama tampilan di depan alamat email (`"Hendra Wijaya" <...>`) | 09 |
| Disposisi / closure code | Kode yang menyatakan hasil akhir sebuah alert saat ditutup | 11 |
| Distribution group | Kumpulan alamat untuk email, tanpa fungsi keamanan | 07 |
| DKIM | Tanda tangan digital domain di setiap email | 09 |
| DLP | Data loss prevention: mengenali data sensitif dan mencegahnya keluar tanpa izin | 06 |
| DMARC | Kebijakan pemilik domain: cocokkan domain From dengan SPF/DKIM, apa tindakan bila gagal, ke mana laporan dikirim | 09 |
| DMZ | Segmen tempat server yang dibuka ke publik, terpisah dari jaringan dalam | 03 |
| DNS | Sistem yang menerjemahkan nama domain menjadi IP address | 02 |
| DNS cache poisoning | Jawaban DNS palsu masuk ke cache resolver dan dibagikan ke banyak penanya | 15 |
| DNS record | Satu baris data DNS, misalnya A, AAAA, MX, TXT, CNAME, PTR | 02 |
| DNS spoofing | Memberi jawaban DNS palsu kepada penanya | 15 |
| Domain (Active Directory) | Satu wilayah pengelolaan di AD dengan daftar akun dan aturan bersama | 07 |
| Domain Admins | Grup admin penuh satu domain | 07 |
| Domain ATT&CK (Enterprise, Mobile, ICS) | Kelompok matriks menurut jenis teknologi | 14 |
| Domain controller (DC) | Server yang menyimpan salinan data AD dan melayani login | 07 |
| DoS | Serangan yang membuat layanan tidak bisa dipakai pengguna yang berhak | 04 |
| Double extortion | Pemerasan ganda: data dienkripsi dan juga dicuri, lalu diancam dibocorkan | 16 |
| DPO | Pejabat atau petugas pelindungan data pribadi (PPDP) | 18 |
| Dropper | Malware tahap awal yang sudah membawa payload di dalam dirinya | 16 |
| DRP | Disaster recovery plan: rencana memulihkan sistem TI setelah gangguan besar, biasanya di lokasi lain | 18 |
| Duplikat (dedup) | Alert kedua untuk kejadian yang sama, digabung ke tiket pertama | 11 |
| EDR | Endpoint detection and response: merekam perilaku di endpoint, mendeteksi pola serangan, dan menyediakan tombol respons | 01, 06 |
| Egress filtering | Membatasi koneksi keluar hanya ke tujuan yang diizinkan | 15 |
| Elevasi | Melibatkan manajemen yang lebih tinggi | 11 |
| Enabling condition | Kondisi yang membuat penyebab langsung bisa berhasil, misalnya aturan akses yang terlalu longgar | 19 |
| Encoding | Mengubah format data dengan aturan publik, bisa dibalik siapa pun | 05 |
| Encryption / decryption (enkripsi / dekripsi) | Mengacak data memakai kunci / membukanya kembali | 01, 05 |
| Endpoint | Perangkat yang dipakai orang atau menjalankan layanan: laptop, PC, server, HP | 06 |
| Enrichment | Menambahkan konteks ke IOC atau alert (pemilik, umur, riwayat, reputasi) | 10, 12 |
| Envelope (MAIL FROM) | Alamat pengirim yang dipakai antarserver saat pengiriman, tidak tampil di aplikasi email | 09 |
| EPSS | Perkiraan peluang sebuah CVE dieksploitasi dalam 30 hari ke depan | 17 |
| Eradication | Membersihkan penyebab dan sisa insiden: malware, persistence, akun disusupi, celah yang dipakai | 19 |
| Eskalasi | Menaikkan kasus ke orang atau tim dengan wewenang atau keahlian lebih | 10, 11 |
| Event | Kejadian apa pun yang bisa diamati di sistem atau jaringan | 11 |
| Event ID | Nomor jenis kejadian di log Windows, misalnya 4624 | 07 |
| Evidence (bukti) | Data yang menjadi dasar membuktikan atau membantah apa yang terjadi | 19 |
| Exfiltration | Pemindahan data keluar tanpa izin | 15 |
| Exploit | Cara, kode, atau alat untuk memanfaatkan vulnerability | 01, 17 |
| Fail-open / fail-closed | Saat alat mati, lalu lintas tetap lewat / lalu lintas terhenti | 03 |
| Faktor autentikasi | Jenis bukti: sesuatu yang kamu tahu, punya, atau melekat padamu | 06 |
| False negative (FN) | Aktivitas jahat terjadi, tetapi tidak ada alert | 03, 11 |
| False positive (FP) | Alert berbunyi, tetapi aktivitas yang dituduhkan tidak ada atau salah dibaca | 03, 11 |
| False positive scan | Temuan scanner yang menyatakan ada kerentanan padahal tidak ada | 17 |
| Feed | Aliran IOC yang dikirim berkala dan biasanya otomatis | 12 |
| FIDO2 dan passkey | Standar login berbasis kunci kriptografi yang terikat ke alamat situs asli | 06 |
| Field | Satu kolom bernama di dalam log, misalnya `user` atau `src` | 10 |
| Fileless malware | Malware yang sebagian besar berjalan di memori atau memakai alat bawaan, tanpa file program sendiri di disk | 16 |
| FIM | File integrity monitoring: mendeteksi perubahan pada file penting | 06 |
| Firewall | Perangkat atau program yang mengizinkan atau menolak lalu lintas berdasarkan aturan | 01, 02, 03 |
| Firewall stateful | Mencatat sambungan yang sedang berjalan di state table | 03 |
| Firewall stateless (packet filter) | Memeriksa setiap paket sendiri-sendiri tanpa ingatan | 03 |
| Forensic image | Salinan utuh isi disk atau memori untuk dianalisis tanpa menyentuh aslinya | 19 |
| Forest | Kumpulan satu atau lebih domain yang berbagi struktur dan katalog | 07 |
| Forward proxy | Perantara di sisi klien (karyawan) untuk keluar ke internet | 03 |
| Forward secrecy | Kebocoran private key server di kemudian hari tidak membuka rekaman sambungan lama | 05 |
| gMSA | Group Managed Service Account, akun layanan yang password-nya dikelola Windows | 07 |
| Governance | Cara pimpinan menetapkan arah, peran, kebijakan, dan pengawasan keamanan | 18 |
| Group (ATT&CK) | Kumpulan aktivitas yang dilacak dengan satu nama di komunitas | 14 |
| Group Policy / GPO | Fitur dan objek berisi aturan konfigurasi yang diterapkan ke komputer dan user | 07 |
| Guideline | Saran yang dianjurkan, boleh dijalankan dengan cara lain | 18 |
| Hacktivist | Pelaku yang menyerang untuk pesan politik atau sosial | 14 |
| Handover | Serah terima pekerjaan dan kondisi dari satu shift ke shift berikutnya | 10 |
| Handshake TLS | Tahap pembuka TLS untuk saling kenal dan menyepakati kunci | 05 |
| Hash (digest) | Hasil hash function, biasanya ditulis heksadesimal | 05 |
| Hash function | Fungsi yang mengubah data sepanjang apa pun menjadi sidik jari pendek dengan panjang tetap | 05 |
| Hash password | Nilai tetap hasil perhitungan satu arah dari password | 07 |
| Header (paket) | Bagian awal paket berisi alamat dan informasi kendali | 02 |
| Header email | Bagian awal email berisi data pengirim, penerima, waktu, dan jejak perjalanan | 09 |
| Header From | Alamat dan nama pengirim yang tampil di aplikasi email | 09 |
| HIDS / HIPS | IDS / IPS yang berjalan di satu perangkat (host) | 03, 06 |
| High-interaction honeypot | Honeypot berupa sistem sungguhan yang bisa dimasuki dan diamati | 13 |
| Hipotesis (hunting) | Dugaan yang bisa diuji dengan data: "bila X terjadi, maka di data Y akan terlihat Z" | 13 |
| Honey account | Akun domain umpan yang tidak dipakai siapa pun | 13 |
| Honeypot | Sistem umpan yang dibuat menarik bagi penyerang dan tidak punya fungsi bagi pengguna sah | 13 |
| Honeytoken | Data umpan (file, akun, kredensial, kunci akses) yang memicu alert saat disentuh | 13 |
| Hotwash | Diskusi singkat segera setelah penanganan atau latihan selesai, sebelum ingatan memudar | 19 |
| HTTP / HTTPS | Protokol web tanpa enkripsi / protokol web di atas TLS yang terenkripsi | 02 |
| HTTP flood | Banjir permintaan web yang tampak sah | 04 |
| Hunt backlog | Daftar ide hunt yang menunggu dikerjakan | 13 |
| IaaS | Infrastructure as a Service: sewa server virtual, penyimpanan, dan jaringan | 08 |
| IAM | Identity and access management: pengelolaan identitas dan hak aksesnya | 06 |
| ICMP | Protokol pesan kendali dan laporan kesalahan, dipakai `ping` | 02 |
| Identitas | Siapa seseorang (atau sesuatu) sebenarnya dalam konteks organisasi | 06 |
| IdP | Identity provider: sistem pusat yang melakukan login dan menerbitkan bukti ke aplikasi | 06 |
| IDPS | Istilah payung untuk IDS dan IPS | 03 |
| IDS | Sistem yang mendeteksi tanda serangan lalu memberi alert | 03 |
| Immutable backup | Backup yang tidak bisa diubah atau dihapus sampai masa kuncinya habis | 18 |
| Impact | Seberapa besar kerugian bila terjadi | 01 |
| Impersonation (lookalike domain) | Meniru memakai nama atau domain yang mirip tetapi milik penyerang sendiri | 09 |
| Incident | Kejadian yang benar-benar atau hampir pasti mengancam CIA, atau melanggar hukum atau kebijakan | 11 |
| Incident commander (IC) | Satu orang yang memimpin dan mengoordinasikan penanganan satu insiden | 19 |
| Incident declaration | Keputusan resmi bahwa kejadian memenuhi kriteria insiden sehingga rencana IR dijalankan | 19 |
| Incident response (IR) | Seluruh kegiatan menyiapkan, mendeteksi, menangani, memulihkan, dan belajar dari insiden | 19 |
| Infostealer | Spyware yang khusus mencuri kredensial, cookie, dan data browser | 16 |
| Infrastructure (Diamond Model) | Saluran fisik atau logis yang dipakai pelaku (IP, domain, email) | 14 |
| Injection | Isian pengguna terbaca sebagai perintah oleh aplikasi | 15 |
| Inline | Alat berdiri di jalur; semua lalu lintas harus lewat dia | 03 |
| Insider | Orang yang punya atau pernah punya akses sah ke organisasi | 14 |
| Insider / insider threat | Orang dengan akses sah / risiko orang itu merugikan organisasi | 15 |
| Insider threat | Ancaman dari orang yang punya akses sah, baik disengaja maupun karena lalai | 15 |
| Integrity | Informasi tidak berubah atau rusak tanpa izin, dan asalnya asli | 01 |
| IOA (indicator of attack) | Tanda bahwa perilaku serangan sedang berjalan, terlepas dari alat atau alamat yang dipakai | 12 |
| IOC (indicator of compromise) | Artefak teknis yang menandakan serangan akan, sedang, atau sudah terjadi | 12 |
| IP address | Alamat sebuah perangkat di jaringan | 01, 02 |
| IP publik / IP privat | Alamat yang berlaku di internet / alamat yang hanya berlaku di jaringan internal | 02 |
| IPS | IDS yang juga berusaha menghentikan serangan | 03 |
| IPv4 / IPv6 | Versi alamat 32 bit / versi alamat 128 bit | 02 |
| ISAC | Information sharing and analysis center, wadah berbagi intel antarorganisasi satu sektor | 12 |
| ISO/IEC 27001 | Standar internasional berisi persyaratan sistem manajemen keamanan informasi (ISMS) yang bisa disertifikasi | 18 |
| Isolasi perangkat | Memutus perangkat dari jaringan kecuali ke konsol keamanan | 06 |
| Jitter | Variasi acak pada jeda beaconing supaya tidak terlihat teratur | 16 |
| Just-in-time (JIT) | Hak tinggi diberikan hanya saat dibutuhkan dan berakhir otomatis | 06 |
| KDC | Key Distribution Center, layanan penerbit tiket Kerberos di setiap DC | 07 |
| Kegagalan pelindungan data pribadi | Kegagalan menjaga kerahasiaan, keutuhan, atau ketersediaan data pribadi | 18 |
| Kerangka serangan | Cara baku menggambarkan serangan dengan bagian yang punya nama | 14 |
| Kerberos | Protokol autentikasi berbasis tiket yang menjadi bawaan AD | 07 |
| Key (kunci) | Nilai rahasia yang mengendalikan enkripsi dan dekripsi | 05 |
| Key exchange | Cara dua pihak menyepakati kunci rahasia lewat jalur terbuka | 05 |
| Keylogger | Program yang merekam ketikan keyboard | 16 |
| krbtgt | Akun khusus yang kuncinya dipakai KDC untuk mengamankan semua TGT | 07 |
| Kredensial | Bukti identitas untuk login: password, kode MFA, kunci, tiket, cookie sesi | 15 |
| Kredensial sementara | Kunci yang otomatis kedaluwarsa setelah waktu tertentu | 08 |
| Kriptografi | Ilmu dan teknik melindungi informasi dengan mengubah bentuknya memakai aturan matematis | 05 |
| Laporan user (user reported message) | Email mencurigakan yang dilaporkan karyawan lewat tombol Report | 09 |
| Lateral movement | Berpindah dari satu perangkat atau akun ke perangkat lain di dalam jaringan setelah berhasil masuk | 03, 14, 15 |
| LDAP | Protokol untuk membaca dan mengubah isi directory | 07 |
| Least privilege | Hak akses sekecil yang dibutuhkan untuk tugas | 01 |
| Lessons learned | Peninjauan apa yang terjadi, apa yang dilakukan, seberapa efektif, dan apa yang harus diubah | 19 |
| Likelihood | Seberapa mungkin ancaman benar-benar terjadi | 01 |
| Loader / downloader | Malware tahap awal yang tugasnya mengambil dan menjalankan malware lain | 16 |
| Log | Catatan kejadian yang ditulis otomatis oleh sistem | 01, 10 |
| Log entry | Satu baris atau satu catatan di dalam log, mewakili satu kejadian | 10 |
| Log management | Proses menghasilkan, mengirim, menyimpan, mengakses, dan membuang log | 10 |
| Log source | Perangkat atau layanan yang menghasilkan dan mengirim log | 10 |
| LOLBin | Alat bawaan sistem operasi yang dipakai untuk tujuan jahat | 16 |
| Low-interaction honeypot | Honeypot yang hanya meniru layanan, tanpa sistem sungguhan di baliknya | 13 |
| MAC address | Alamat perangkat keras kartu jaringan, hanya berarti di jaringan lokal | 02 |
| Malware | Program yang sengaja dibuat atau disisipkan untuk merugikan sistem | 16 |
| Matrix (ATT&CK) | Tabel ATT&CK: kolom tactic, isi technique | 14 |
| MD5, SHA-1, SHA-256 | Tiga hash function populer; dua yang pertama sudah rusak untuk keamanan | 05 |
| MDR | Managed detection and response: layanan pihak luar yang menjalankan pemantauan dan respons | 06 |
| Message-ID | Nomor unik untuk satu email | 09 |
| MFA | Multi-factor authentication: login dengan dua faktor berbeda atau lebih | 06 |
| MFA fatigue | Membanjiri pengguna dengan notifikasi MFA sampai ia menyetujui satu | 06 |
| Microsoft Entra ID | Layanan identitas cloud Microsoft (dulu Azure AD), sumber login untuk Microsoft 365, Azure, dan aplikasi lain | 08 |
| Misconfiguration | Pengaturan layanan yang salah sehingga membuka celah | 08 |
| MITM (man-in-the-middle) | Pihak lain berada di antara dua pihak yang berkomunikasi | 15 |
| MITRE ATT&CK | Basis pengetahuan perilaku penyerang dari pengamatan nyata | 14 |
| Model OSI | Model konsep tujuh lapisan untuk menjelaskan komunikasi jaringan | 02 |
| Model TCP/IP | Model empat lapisan yang benar-benar dipakai internet | 02 |
| MTD | Maximum tolerable downtime: lama maksimal proses bisnis boleh terhenti sebelum kerugian serius | 18 |
| MTTA | Mean time to acknowledge, rata-rata waktu dari alert muncul sampai mulai ditangani | 10 |
| MTTD | Mean time to detect, rata-rata waktu dari kejadian dimulai sampai terdeteksi | 10 |
| MTTR | Mean time to respond, resolve, atau recover; definisinya berbeda antar organisasi | 10 |
| NAC | Kontrol yang memeriksa perangkat sebelum diberi akses jaringan | 03 |
| NAT | Penerjemahan alamat privat menjadi alamat publik di batas jaringan | 02 |
| Nation-state actor | Pelaku yang bekerja untuk atau atas dukungan negara | 14 |
| Negotiate | Mekanisme Windows yang memilih Kerberos dan memakai NTLM hanya bila perlu | 07 |
| NetFlow / flow | Ringkasan aliran lalu lintas yang dikirim router: siapa ke siapa, port, jumlah paket dan byte | 04 |
| NGFW | Firewall stateful yang juga mengenali aplikasi, user, dan biasanya membawa fitur IPS | 03 |
| NIDS / NIPS | IDS / IPS yang mengamati lalu lintas jaringan | 03 |
| NIST CSF 2.0 | Framework NIST dengan enam fungsi: Govern, Identify, Protect, Detect, Respond, Recover | 18 |
| NOC | Network Operations Center, tim yang menjaga jaringan tetap hidup dan cepat | 10 |
| Non-repudiation | Bukti yang membuat pelaku tidak bisa menyangkal tindakannya | 01 |
| Normalisasi | Menyeragamkan nama field, format waktu, dan nilai dari sumber yang berbeda | 10 |
| Notable event / finding | Nama alert di Splunk Enterprise Security: notable event (ES 7 dan sebelumnya), finding (ES 8) | 11 |
| NTLM | Protokol autentikasi lama berbasis tantangan dan jawaban | 07 |
| NTP | Network Time Protocol, protokol untuk menyamakan jam perangkat | 10 |
| Number matching | Pengguna harus mengetik angka yang tampil di layar login ke aplikasi HP | 06 |
| NVD | Basis data kerentanan milik NIST yang memperkaya CVE dengan skor dan daftar produk | 17 |
| Object (Active Directory) | Satu entri di AD: user, computer, group, OU, GPO | 07 |
| Order of volatility | Urutan pengambilan bukti dari yang paling cepat hilang (memori) ke yang paling awet (disk, arsip) | 19 |
| Organizational unit (OU) | Wadah di dalam domain untuk mengelompokkan objek demi pengaturan dan pendelegasian | 07 |
| OTP | One-time password, kode sekali pakai yang dikirim ke HP | 01 |
| Out-of-band (passive) | Alat menonton salinan lalu lintas dari samping | 03 |
| Out-of-band communication | Saluran komunikasi cadangan di luar sistem yang mungkin sudah dikuasai penyerang | 19 |
| PaaS | Platform as a Service: sewa platform siap pakai untuk menjalankan aplikasi | 08 |
| Paket | Satuan kecil data yang dikirim lewat jaringan | 02 |
| PAM | Privileged access management: pengendalian akun dan akses berhak tinggi | 06 |
| Parsing | Membongkar baris log menjadi kolom-kolom (field) yang bisa dipakai | 10 |
| Password hashing scheme | Cara hash khusus password yang sengaja lambat dan memakai salt | 05 |
| Password spraying | Mencoba satu atau sedikit password umum ke banyak akun | 15 |
| Patch | Pembaruan perangkat lunak yang menutup kelemahan | 01 |
| Patch management | Proses menemukan, memprioritaskan, memasang, dan memverifikasi pembaruan | 17 |
| Payload | Bagian malware yang menjalankan tujuan utamanya | 16 |
| Penetration test (pentest) | Pengujian yang meniru serangan nyata untuk membuktikan celah bisa ditembus | 17 |
| Pengendali data pribadi | Pihak yang menentukan tujuan dan mengendalikan pemrosesan data pribadi | 18 |
| Persistence | Cara malware bertahan setelah restart atau logoff | 16 |
| Phishing | Pesan palsu yang meniru pihak tepercaya untuk mencuri data atau memancing tindakan | 09 |
| Phishing-resistant MFA | MFA yang rahasianya tidak bisa dipancing keluar oleh situs palsu | 06 |
| Pivot | Memakai satu temuan untuk menemukan temuan lain yang terkait | 14 |
| PKI | Seluruh sistem (aturan, orang, server) untuk menerbitkan, mengelola, dan mencabut sertifikat | 05 |
| Plaintext / ciphertext | Data asli yang bisa dibaca / data yang sudah diacak | 05 |
| Playbook | Prosedur penanganan per jenis kejadian: apa yang dilakukan, siapa, kapan eskalasi | 10 |
| Policy (cloud IAM) | Dokumen berisi izin: siapa boleh melakukan apa ke sumber daya mana | 08 |
| Policy (dokumen GRC) | Pernyataan tingkat tinggi tentang apa yang wajib dan kenapa | 18 |
| Policy-based | Deteksi pelanggaran aturan yang ditetapkan organisasi | 03 |
| Port | Nomor yang menunjuk layanan tertentu di sebuah perangkat | 02 |
| Port ephemeral | Port sementara yang dipilih perangkat untuk sisi pengirim | 02 |
| Port scan | Memeriksa dari jauh port mana yang terbuka di sebuah perangkat | 02 |
| Post-incident activity | Kegiatan setelah insiden: laporan, lessons learned, dan perbaikan | 19 |
| pps | Packets per second, jumlah paket per detik | 04 |
| Precision | Dari semua alert, berapa persen yang benar | 11 |
| Precursor / indicator (NIST) | Tanda insiden mungkin akan terjadi / tanda insiden mungkin sedang atau sudah terjadi | 19 |
| Preparation | Persiapan sebelum insiden: rencana, orang, alat, latihan, dan pencegahan | 19 |
| Pretexting | Membangun cerita karangan supaya permintaan terdengar wajar | 09 |
| Preventive control | Pengaman yang mencegah kejadian | 01 |
| Principal | Pihak yang mengirim permintaan: user, role, atau layanan | 08 |
| Priority | Urutan dan kecepatan penanganan, dari severity digabung konteks | 11 |
| Privilege escalation | Mendapat hak lebih tinggi dari yang seharusnya | 15 |
| Privileged group | Grup dengan hak sangat tinggi, misalnya Domain Admins | 07 |
| Procedure (ATT&CK) | Cara spesifik yang benar-benar dipakai pelaku tertentu | 14 |
| Procedure (dokumen GRC) | Langkah demi langkah untuk menjalankan tugas | 18 |
| Process injection | Menjalankan kode jahat di dalam proses lain yang sah | 16 |
| Protokol | Aturan baku cara dua pihak berkomunikasi | 02 |
| Proxy | Perantara yang membuat sambungan atas nama pihak lain | 03 |
| Public key / private key | Kunci yang boleh dibagikan / kunci yang wajib dirahasiakan pemiliknya | 05 |
| Purple team | Cara kerja di mana red team dan blue team berlatih bersama secara terbuka | 17 |
| Push notification | Permintaan "setujui login?" yang dikirim ke aplikasi di HP | 06 |
| Pyramid of Pain | Model enam tingkat jenis indikator, diurutkan dari yang paling murah sampai paling mahal diganti penyerang | 12 |
| Quarantine | Memindahkan file mencurigakan ke tempat terkunci sehingga tidak bisa dijalankan | 06 |
| Quishing | Phishing lewat kode QR | 09 |
| RaaS | Ransomware-as-a-Service, ransomware yang disewakan ke "afiliasi" dengan bagi hasil | 16 |
| Ransomware | Malware yang mengunci data (biasanya dengan enkripsi) lalu meminta tebusan | 16 |
| RAT | Remote access trojan, malware yang memberi penyerang kendali jarak jauh penuh | 16 |
| Rate limiting | Membatasi jumlah permintaan atau paket per satuan waktu | 04 |
| RBAC | Role-based access control: hak diberikan ke peran, lalu orang dimasukkan ke peran | 06 |
| RDP | Protokol Windows untuk memakai komputer lain dari jarak jauh, port 3389 | 15 |
| Received | Baris jejak yang ditambahkan setiap server yang dilewati | 09 |
| Recovery | Mengembalikan sistem ke operasi normal dan memastikan sistem bersih | 19 |
| Red team | Tim yang meniru penyerang sungguhan untuk menguji deteksi dan respons | 17 |
| Reflection | Memantulkan serangan lewat server pihak ketiga dengan alamat asal korban | 04 |
| Reflector | Server sah yang dimanfaatkan untuk memantulkan serangan | 04 |
| Region | Lokasi geografis berisi beberapa data center penyedia, misalnya `ap-southeast-3` (Jakarta) | 08 |
| Replikasi | Penyalinan perubahan data AD antar DC | 07 |
| Reply-To | Alamat tujuan balasan, bisa berbeda dari From | 09 |
| Reputasi | Penilaian layanan luar tentang seberapa sering sebuah IP, domain, atau file terlihat jahat | 12 |
| Resolver | Server yang mencarikan jawaban DNS untuk perangkat | 02 |
| Return-Path | Catatan alamat envelope di email yang sudah diterima, tujuan pesan gagal kirim | 09 |
| Reverse proxy | Perantara di sisi server yang menerima tamu atas nama server | 03 |
| Revocation | Pencabutan sertifikat sebelum masa berlakunya habis | 05 |
| Risk | Ukuran seberapa terancam, gabungan likelihood dan impact | 01 |
| Risk appetite | Jumlah dan jenis risiko yang secara umum mau diterima organisasi | 18 |
| Risk register | Catatan pusat semua risiko beserta pemilik, nilai, keputusan, dan statusnya | 18 |
| Risk treatment | Keputusan atas satu risiko: mitigate, transfer, avoid, atau accept | 18 |
| Role (cloud IAM) | Identitas berisi izin tertentu yang bisa "dipinjam" sementara | 08 |
| Root CA / intermediate CA | CA paling atas yang dipercaya langsung / CA perantara di bawahnya | 05 |
| Root cause analysis (RCA) | Pendekatan sistematis untuk menemukan penyebab dasar sebuah masalah, bukan hanya gejalanya | 19 |
| Rootkit | Kumpulan alat yang mengubah sistem untuk menyembunyikan keberadaan penyerang | 16 |
| RPO | Recovery point objective: titik waktu terakhir yang datanya harus bisa dikembalikan | 18 |
| rps | Requests per second, jumlah permintaan aplikasi per detik | 04 |
| RTBH / blackholing | Membuang semua lalu lintas ke satu alamat di tepi jaringan, dipicu lewat BGP | 04 |
| RTO | Recovery time objective: lama maksimal sebuah sistem boleh mati sebelum dampaknya tidak bisa diterima | 18 |
| Rule dan ruleset | Satu aturan izinkan/tolak, dan kumpulan aturan itu | 03 |
| Rules of engagement (RoE) | Aturan tertulis pengujian: cakupan, waktu, cara, dan kontak | 17 |
| Runbook | Instruksi langkah teknis untuk satu tugas di satu alat | 10 |
| SaaS | Software as a Service: pakai aplikasi jadi lewat browser | 08 |
| Safe Links / Safe Attachments | Fitur Defender for Office 365 untuk memeriksa tautan saat diklik dan membuka lampiran di lingkungan uji | 09 |
| Salt | Nilai acak unik per user yang digabung dengan password sebelum di-hash | 05 |
| Sandbox | Lingkungan tertutup dan terkendali untuk menjalankan program yang tidak dipercaya | 13 |
| Sandbox evasion | Teknik program jahat untuk mengenali sandbox lalu diam atau berpura-pura baik | 13 |
| SBOM | Daftar komponen yang menyusun sebuah perangkat lunak | 17 |
| Scoping | Menentukan seberapa luas insiden: aset, akun, data, dan rentang waktu yang terdampak | 19 |
| Scrubbing center | Fasilitas yang menyaring lalu lintas serangan lalu meneruskan yang bersih | 04 |
| Secure email gateway (SEG) | Sistem yang menyaring semua email sebelum sampai ke mailbox | 09 |
| Security group | Kumpulan akun yang diberi hak atau izin bersama | 07 |
| Segmentasi jaringan | Membagi jaringan menjadi zona dengan aturan di antaranya | 03 |
| Separation of duties | Tugas penting dipecah ke beberapa orang | 01 |
| Serangan application layer | Serangan yang menghabiskan tenaga aplikasi di lapisan 7 | 04 |
| Serangan protocol | Serangan yang menghabiskan tabel atau memori perangkat jaringan dan server di lapisan 3 dan 4 | 04 |
| Serangan volumetric | Serangan yang memenuhi bandwidth | 04 |
| Service account | Akun yang dipakai aplikasi atau layanan, bukan orang | 07 |
| Service ticket | Tiket untuk satu layanan tertentu | 07 |
| Sesi dan session cookie | Status "sudah login" yang diingat situs lewat token kecil di browser | 15 |
| Session hijacking | Memakai sesi milik orang lain yang sudah login | 15 |
| Session key | Kunci symmetric sementara untuk satu sambungan | 05 |
| Session token / cookie | Bukti login yang disimpan browser sehingga pengguna tidak perlu login ulang | 19 |
| Severity | Seberapa parah sesuatu bila benar terjadi | 11 |
| Shadow IT | Aplikasi atau layanan yang dipakai karyawan tanpa izin TI | 08 |
| Shared responsibility model | Pembagian tugas keamanan antara penyedia dan pelanggan | 08 |
| Shift | Giliran jaga dalam operasi 24 jam | 10 |
| SID | Security identifier, nomor unik permanen untuk setiap akun dan group | 07 |
| SIEM | Sistem yang mengumpulkan log dari banyak sumber, mencarinya, mengorelasikan, dan memunculkan alert | 01, 10 |
| Signature (antivirus) | Ciri khas malware yang sudah dikenal (pola isi, hash) | 06 |
| Signature-based | Deteksi dengan mencocokkan pola serangan yang sudah dikenal | 03 |
| Siklus IR (incident response life cycle) | Urutan tahap penanganan insiden; NIST Rev. 2 memakai empat fase, Rev. 3 memetakannya ke enam fungsi CSF 2.0 | 19 |
| SLA | Service level agreement, janji tertulis tentang layanan dan batas waktunya | 10 |
| Smishing | Phishing lewat SMS atau pesan teks | 09 |
| SNI | Nama situs yang dikirim browser di awal sambungan HTTPS | 02 |
| SOAR | Security orchestration, automation, and response, platform yang menyambungkan alat dan menjalankan langkah respons otomatis | 10 |
| SOC | Security Operations Center, tim dan fungsi yang memantau, mendeteksi, dan menangani kejadian keamanan | 10 |
| Social engineering | Menipu manusia supaya menyerahkan informasi, akses, atau uang | 09 |
| SPAN / TAP | Port switch yang menyalin lalu lintas / alat yang menyadap kabel untuk salinan | 03 |
| Spear phishing | Phishing yang disesuaikan untuk orang atau organisasi tertentu | 09 |
| SPF | Daftar server yang boleh mengirim email untuk sebuah domain, dipasang di DNS | 09 |
| SPN | Service principal name, nama unik sebuah layanan untuk Kerberos | 07 |
| Spoofing | Memalsukan alamat From memakai domain orang lain persis | 09 |
| Spyware | Malware yang diam-diam mengumpulkan informasi tentang orang atau organisasi | 16 |
| SQL injection | Injection yang mengubah perintah ke database | 15 |
| SSO | Single sign-on: satu login untuk membuka banyak aplikasi | 06 |
| Standard | Aturan rinci yang wajib dan seragam untuk memenuhi policy | 18 |
| Stateful protocol analysis | Membandingkan urutan dan isi protokol dengan perilaku yang lazim | 03 |
| STIX | Format baku (JSON) untuk menulis informasi ancaman | 12 |
| Strategic, operational, tactical | Tingkat intel menurut pembacanya: pimpinan, pengelola respons kampanye tertentu, tim teknis | 12 |
| Sub-technique | Varian yang lebih spesifik dari sebuah technique | 14 |
| Subnet dan CIDR | Satu blok alamat yang berurutan, ditulis dengan garis miring (`/24`) | 02 |
| Supply chain attack | Menyerang target lewat produk atau layanan pemasoknya | 15 |
| Suppression | Menyembunyikan alert yang cocok dengan kondisi tertentu, biasanya untuk sementara | 11 |
| Symmetric encryption | Satu kunci yang sama untuk mengunci dan membuka | 05 |
| SYN cookies | Teknik server menjawab SYN tanpa menyimpan catatan sampai handshake selesai | 04 |
| SYN flood | Banjir permintaan pembuka sambungan TCP yang tidak pernah diselesaikan | 04 |
| Tabletop exercise | Latihan diskusi skenario insiden di atas meja tanpa menyentuh sistem sungguhan | 19 |
| Tactic | Tujuan jangka pendek pelaku pada satu langkah ("kenapa") | 14 |
| TAXII | Protokol di atas HTTPS untuk mengirim dan mengambil data intel | 12 |
| TCP | Protokol yang membuka sambungan dan memastikan data sampai berurutan | 02 |
| Technique | Cara mencapai tujuan itu ("bagaimana") | 14 |
| Telemetri | Catatan aktivitas yang dikirim agen ke pusat (proses, file, koneksi, login) | 06 |
| TGT | Ticket-granting ticket, tiket awal setelah login, dipakai untuk meminta tiket lain | 07 |
| Threat | Keadaan atau kejadian yang berpotensi merugikan | 01 |
| Threat actor | Orang atau kelompok di balik ancaman yang disengaja | 01, 14 |
| Threat hunting | Pencarian aktif oleh manusia atas ancaman yang lolos dari deteksi otomatis | 13 |
| Threat intelligence | Informasi ancaman yang sudah dikumpulkan, dianalisis, dan diberi konteks untuk mengambil keputusan | 12 |
| Three-way handshake | Tiga langkah pembuka sambungan TCP: SYN, SYN-ACK, ACK | 02 |
| Throttling | Menahan rule supaya tidak membuat alert baru untuk hal yang sama dalam rentang waktu tertentu | 11 |
| Ticketing | Sistem pencatatan pekerjaan bernomor dengan status, pemilik, dan jejak waktu | 10 |
| Tier L1/L2/L3 | Pembagian kerja analyst berdasarkan kedalaman pekerjaan | 10 |
| TLP (Traffic Light Protocol) | Label warna yang menyatakan sejauh mana informasi boleh dibagikan | 12 |
| TLS | Protokol yang mengamankan sambungan: identitas server, kerahasiaan, keutuhan | 05 |
| TLS inspection | Membuka enkripsi, memeriksa, lalu mengenkripsi ulang | 03 |
| Triage | Pemeriksaan awal untuk memilah alert: benar atau tidak, penting atau tidak, ditangani siapa | 11, 13 |
| Trojan | Program yang tampak berguna tetapi punya fungsi jahat tersembunyi | 16 |
| True negative (TN) | Aktivitas normal, dan memang tidak ada alert | 11 |
| True positive (TP) | Alert berbunyi dan memang ada aktivitas jahat | 11 |
| Trust store | Daftar root CA yang dipercaya sistem operasi atau browser | 05 |
| TTP | Tactics, techniques, and procedures: perilaku penyerang, dari tujuan umum sampai langkah rinci | 12, 14 |
| Tuning | Menyetel logika, ambang, atau cakupan rule supaya lebih akurat | 03, 11 |
| UDP | Protokol yang mengirim tanpa sambungan dan tanpa jaminan sampai | 02 |
| UDP flood | Banjir paket UDP ke korban | 04 |
| UEBA | User and entity behavior analytics, deteksi berbasis penyimpangan dari baseline | 10 |
| Umur IOC (indicator aging) | Masa berlaku IOC sebelum dianggap usang | 12 |
| Unified Kill Chain | Model 18 tahap yang menggabungkan Kill Chain dan ATT&CK | 14 |
| Upstream / transit | Penyedia yang menghubungkan sebuah jaringan ke seluruh internet | 04 |
| Use case | Paket lengkap untuk mendeteksi satu skenario ancaman: alasan, sumber log, rule, prosedur, pemilik | 10 |
| User account | Akun milik satu orang | 07 |
| UU PDP | Undang-Undang No. 27 Tahun 2022 tentang Pelindungan Data Pribadi | 18 |
| Victim (Diamond Model) | Target dan aset yang diserang | 14 |
| Virtual patching | Aturan di WAF atau IPS yang menghadang eksploitasi tanpa mengubah kode yang rentan | 17 |
| Virus | Malware yang menyalin dirinya ke file atau program lain dan berjalan saat inangnya dibuka | 16 |
| Vishing | Phishing lewat suara (telepon) | 09 |
| VPN | Saluran terenkripsi di atas jaringan publik | 03 |
| Vulnerability | Kelemahan yang bisa dimanfaatkan untuk merusak kerahasiaan, keutuhan, atau ketersediaan | 01, 17 |
| Vulnerability assessment (VA) | Pemeriksaan sistematis untuk menemukan dan menilai kelemahan | 17 |
| Vulnerability scanner | Alat otomatis yang memeriksa aset terhadap daftar kerentanan yang dikenal | 17 |
| WAF | Firewall khusus aplikasi web yang membaca isi permintaan HTTP | 01, 03, 04 |
| Whaling | Spear phishing yang menyasar eksekutif senior | 09 |
| Wiper | Malware yang menghancurkan data tanpa niat mengembalikannya | 16 |
| WIPS | IPS untuk jaringan nirkabel (Wi-Fi) | 03 |
| Workload | Apa yang dijalankan di cloud: VM, container, fungsi serverless | 08 |
| Worm | Malware mandiri yang menyebar sendiri lewat jaringan | 16 |
| XDR | Extended detection and response: deteksi dan respons yang menggabungkan endpoint, email, identitas, cloud | 06 |
| XSS (cross-site scripting) | Skrip pihak lain ikut tampil di halaman situs asli dan berjalan di browser pengunjung | 15 |
| ZAP (zero-hour auto purge) | Penarikan otomatis email yang ternyata berbahaya setelah sudah terkirim | 09 |
| Zero trust | Tidak ada akses yang dipercaya otomatis hanya karena lokasinya | 01 |
| Zero-day | Kerentanan yang dimanfaatkan sebelum pembuatnya tahu atau sebelum ada perbaikan | 17 |

## 4. Latihan interview

Pukul 15:00 Dimas memanggilmu ke ruang rapat kecil untuk mock interview penutup orientasi. "Aku tanya seperti interviewer dari luar, dalam bahasa Inggris. Jawab singkat, beri satu contoh, dan bedakan istilah yang mirip." Sembilan belas pertanyaan berikut adalah yang paling sering muncul untuk posisi SOC L1 atau junior analyst. Coba jawab dengan suara keras dulu, baru buka contoh jawabannya; setiap jawaban menyebut Day tempat materinya dibahas.

**1. What is the CIA triad? Give an example of each.**

<details><summary>Sample answer</summary>

"The CIA triad is the three properties security protects: confidentiality, meaning only authorized people can see information; integrity, meaning information is accurate and not changed without authorization; and availability, meaning systems and data are usable when needed. A data leak from a customer portal hits confidentiality, a tampered invoice or bank account number hits integrity, and a DDoS or ransomware hits availability. The three often pull against each other, so controls are a balance, not a checklist." (Day 01)

</details>

**2. What is the difference between an IDS and an IPS?**

<details><summary>Sample answer</summary>

"An IDS detects suspicious activity and raises an alert; it usually watches a copy of the traffic out-of-band, for example from a SPAN port, so it does not add latency and cannot block on its own. An IPS sits inline in the traffic path and can drop or reset malicious traffic. The trade-off is that a false positive on an IPS blocks legitimate users, and you must decide whether it fails open or fails closed. A common approach is to run new signatures in detect mode, tune them, then switch to prevent mode. Many NGFWs include IPS features, so the difference is the function, not always the box." (Day 03)

</details>

**3. How is a firewall different from a WAF?**

<details><summary>Sample answer</summary>

"A traditional firewall filters traffic by addresses, ports, and connection state at layers 3 and 4, like a gate guard checking ID and destination. A next-generation firewall adds application awareness and often IPS. A WAF protects web applications at layer 7: it reads the HTTP request itself, such as parameters and headers, to block things like SQL injection or cross-site scripting. You usually need both: the firewall decides who can reach port 443, and the WAF decides whether a request to the web app looks malicious." (Day 03)

</details>

**4. How would you mitigate a DDoS attack?**

<details><summary>Sample answer</summary>

"First identify the type. Volumetric attacks like UDP or DNS amplification fill the bandwidth, so they must be stopped upstream: the ISP, a scrubbing center, a CDN with anycast, or as a last resort RTBH, which drops all traffic to the target IP. Protocol attacks like SYN floods exhaust state tables, so SYN cookies, rate limiting, and firewall protections help. Application layer attacks like HTTP floods look like real users, so a WAF with rate limiting and bot challenges is the main tool. Mitigation works best when it is contracted and tested before the attack, with a runbook shared between the SOC and the network team." (Day 04)

</details>

**5. What is the difference between hashing and encryption? Where does encoding fit?**

<details><summary>Sample answer</summary>

"Encoding, such as Base64, only changes the format with a public rule; anyone can reverse it, so it is not security. Hashing is one-way: it turns any input into a fixed-length fingerprint, used for integrity checks and for storing passwords with a salt and a slow algorithm. Encryption is two-way with a key: only someone with the right key can decrypt. Symmetric encryption uses one shared key, while asymmetric uses a public and private key pair. As an analyst, I use SHA-256 hashes to search for files and I never treat Base64 in a command line as hidden or safe." (Day 05)

</details>

**6. What is the difference between a SIEM and a SOAR?**

<details><summary>Sample answer</summary>

"A SIEM collects logs from many sources, parses and normalizes them, lets analysts search, and runs correlation rules that generate alerts. A SOAR connects tools and automates response steps from a playbook, such as enriching an alert with IP reputation, opening a ticket, or disabling an account after approval. The SIEM answers 'what happened and is it suspicious?', while the SOAR answers 'what do we do next, faster and consistently?'. A SOAR only automates good procedures; automating a noisy rule just repeats mistakes faster." (Day 10)

</details>

**7. Explain true positive, false positive, false negative, and benign positive. Which is the most dangerous?**

<details><summary>Sample answer</summary>

"A true positive is an alert for real malicious activity. A false positive is an alert where the suspected activity did not happen or was misread. A benign positive is an alert that correctly detected real activity, but the activity was legitimate, such as an approved vulnerability scanner. A false negative is malicious activity that produced no alert. False negatives are the most dangerous because nobody is looking, and they are only found by hunting, testing, or after damage. False positives are costly too, because they cause alert fatigue, so I tune rules instead of just closing the same alert every day." (Day 11)

</details>

**8. What is the difference between an IOC and an IOA?**

<details><summary>Sample answer</summary>

"An IOC, an indicator of compromise, is a technical artifact such as a file hash, IP address, domain, or URL that shows an attack happened or is happening. An IOA, an indicator of attack, describes attacker behavior, for example Office spawning PowerShell that downloads a file, regardless of which file or IP is used. IOCs are cheap for attackers to change, which is the bottom of the Pyramid of Pain, while behavior and TTPs are expensive to change. I use IOCs for fast sweeps, but I check context first, for example a shared CDN IP can match thousands of legitimate connections." (Day 12)

</details>

**9. Compare the Cyber Kill Chain and MITRE ATT&CK.**

<details><summary>Sample answer</summary>

"The Lockheed Martin Cyber Kill Chain is a seven-stage linear model, from reconnaissance to actions on objectives, useful for explaining that breaking any stage stops the attack. MITRE ATT&CK is a knowledge base built from real-world observations: tactics are the attacker's goals, techniques and sub-techniques are how they achieve them, and procedures are the specific implementations used by particular groups. Kill Chain is good for the big picture and management, while ATT&CK is better for mapping detections, finding coverage gaps, and describing what happened inside the network after initial access." (Day 14)

</details>

**10. A user reports a suspicious email. Walk me through your triage, including SPF, DKIM, and DMARC.**

<details><summary>Sample answer</summary>

"I check the header first: the real sending server from the trusted Received lines, the envelope sender versus the From address, Reply-To, and the Authentication-Results. SPF checks whether the sending server is allowed to send for the envelope domain; DKIM checks a domain's digital signature on the message; DMARC checks that the From domain aligns with a domain that passed SPF or DKIM and tells receivers what to do on failure. Passing all three only proves the email came from that domain, so a lookalike domain or a compromised internal account can still pass. Then I analyze URLs and attachments safely, search for other recipients, remove the messages, block indicators, and check whether anyone clicked or entered credentials." (Day 09)

</details>

**11. What would you do in the first hour of a suspected ransomware attack?**

<details><summary>Sample answer</summary>

"Contain first: isolate the affected hosts from the network with EDR rather than powering them off, because shutting down destroys memory evidence; only power off if isolation is impossible. Escalate immediately and declare an incident so the incident commander, management, and legal are involved. Scope quickly: which hosts, which accounts, whether shadow copies or backups were targeted, and whether data was exfiltrated, since double extortion is common. Disable or reset compromised accounts, especially admin accounts, and protect backups by keeping them offline or immutable. I preserve logs and evidence, document every action with timestamps, and leave decisions about notification and ransom to management and legal." (Day 16, Day 18, Day 19)

</details>

**12. What is the difference between a vulnerability, an exploit, and a zero-day? How do you prioritize patches?**

<details><summary>Sample answer</summary>

"A vulnerability is a weakness, an exploit is the method or code that takes advantage of it, and a zero-day is a vulnerability exploited before the vendor knows or before a fix exists. CVE gives the vulnerability an ID, and CVSS scores its technical severity from 0 to 10. CVSS alone is not enough for prioritization: I also look at EPSS, the probability of exploitation in the next 30 days, at whether it is in the CISA Known Exploited Vulnerabilities catalog, and at the asset's exposure and criticality. An internet-facing system with a KEV-listed vulnerability goes first, even if another bug has a higher CVSS score." (Day 17)

</details>

**13. How is EDR different from traditional antivirus?**

<details><summary>Sample answer</summary>

"Traditional antivirus mainly matches known signatures and quarantines files. EDR records behavior on the endpoint, such as process trees, command lines, network connections, and logons, detects suspicious patterns even without a known file, and gives response actions like isolating the device or collecting an investigation package. EDR is what lets an analyst see that Excel launched PowerShell which then connected to an unknown domain. Its limit is coverage: a server without the agent is invisible, so you still need other telemetry like a HIDS or network logs." (Day 06)

</details>

**14. Briefly explain how Kerberos works in Active Directory.**

<details><summary>Sample answer</summary>

"When a user logs in, the Key Distribution Center on a domain controller checks the credentials and issues a ticket-granting ticket, or TGT, protected with the krbtgt account's key. When the user wants a service, the client presents the TGT and receives a service ticket for that service's SPN, encrypted with the service account's key, and then shows it to the service. The password is not sent across the network for each service. Attacks abuse this design, for example Kerberoasting requests service tickets to crack weak service account passwords offline, which is why service accounts need long random passwords or gMSAs." (Day 07)

</details>

**15. What is the shared responsibility model in cloud?**

<details><summary>Sample answer</summary>

"Security duties are split between the cloud provider and the customer. The provider always secures the physical data centers and its core infrastructure, while the customer is always responsible for its data, identities, and access configuration. The split in between depends on the service model: in IaaS the customer manages the operating system, patches, and network rules; in PaaS the provider takes more of the platform; in SaaS the customer mainly manages users, permissions, and data. In practice, many cloud incidents start on the customer side, such as a public storage bucket or a leaked access key, which no provider control can fix for you." (Day 08)

</details>

**16. Brute force, password spraying, and credential stuffing: what is the difference and how do you detect each?**

<details><summary>Sample answer</summary>

"Brute force tries many passwords against one account, so it shows many failures for a single user and is stopped by lockout. Password spraying tries a few common passwords against many accounts to avoid lockout, so it shows one source failing across many users. Credential stuffing uses username and password pairs leaked from other sites, so the success rate is higher and failures come with some successes. MFA, blocking known bad sources, monitoring for many accounts per source, and checking breached-password lists help against all three." (Day 15)

</details>

**17. How is threat hunting different from alert triage?**

<details><summary>Sample answer</summary>

"Triage reacts to an alert that already fired and decides if it is real, how urgent it is, and who handles it. Threat hunting is proactive: an analyst starts from a hypothesis, for example 'service accounts are being used interactively', and searches the data for activity that no rule detected. Hunting looks for false negatives. A good hunt ends either with a finding, an incident, or a new detection rule, so the next time it becomes an alert instead of a manual search." (Day 13)

</details>

**18. Describe the incident response lifecycle.**

<details><summary>Sample answer</summary>

"The classic NIST SP 800-61 Revision 2 model has four phases: preparation; detection and analysis; containment, eradication, and recovery; and post-incident activity, with lessons learned feeding back into preparation. SANS splits the same work into six steps, known as PICERL. In April 2025 NIST published Revision 3, which maps incident response to the six CSF 2.0 functions: Govern, Identify, and Protect support preparation, Detect, Respond, and Recover are the response itself, and the Improvement category feeds lessons learned into everything continuously. In practice the phases overlap; for example, scoping continues while you contain, and notification can start in the middle of an incident." (Day 19)

</details>

**19. What is chain of custody and why does it matter for a SOC analyst?**

<details><summary>Sample answer</summary>

"Chain of custody is the record of who handled a piece of evidence, when, and for what purpose, from collection through storage and analysis. Each transfer is logged with names, timestamps including the time zone, and signatures, and digital evidence is verified with hashes so the copy can be proven identical to the original. It matters because the decision to take legal action often comes weeks later, and evidence that was not tracked from the start may be challenged or rejected. Even when no prosecution happens, a clean evidence trail makes the investigation itself more reliable." (Day 19)

</details>

**What makes these answers strong:** setiap jawaban mendefinisikan istilah dalam satu kalimat, membedakannya dari istilah yang mirip, memberi satu contoh nyata, dan menyebut batas atau trade-off. Interviewer untuk posisi junior jarang mencari hafalan; mereka mencari tanda bahwa kamu tahu apa yang dilakukan alat itu, apa yang tidak bisa ia lakukan, dan kapan harus eskalasi.

## 5. Salah paham umum

Butir berikut adalah salah paham lintas istilah tentang IR yang belum dibahas di subbagian 1.x.

- **Anggapan:** IR adalah pekerjaan tim SOC saja. **Kenyataannya:** Rev. 3 menyebut keberhasilan IR bergantung pada banyak pihak: pimpinan yang memutuskan tindakan berdampak besar seperti mematikan layanan penting, bagian hukum, humas, SDM (misalnya bila pelakunya karyawan), keamanan fisik, pemilik aset, dan pihak ketiga seperti penyedia cloud dan ISP [S1]. Di `INC-2027-098`, SDM menjadi saksi penyerahan laptop dan DPO memutuskan pemberitahuan.
- **Anggapan:** fase IR dikerjakan satu per satu secara berurutan. **Kenyataannya:** CISA menyebut banyak kegiatan IR berulang dan terus berkembang sampai insiden ditutup [S4], dan Rev. 2 sendiri mencatat containment sering kembali ke analisis ketika host baru ditemukan [S2]. Di `INC-2027-098`, scoping 214 email selesai setelah eradication cloud dimulai.
- **Anggapan:** semakin cepat penyerang diputus, semakin baik, dalam semua kasus. **Kenyataannya:** Rev. 3 meminta strategi respons menyeimbangkan kebutuhan pulih cepat dengan kebutuhan mengamati penyerang atau menyelidiki lebih dalam, dan menyebut setiap pilihan punya trade-off [S1]. Untuk satu akun yang sedang dipakai menipu Keuangan, memutus segera adalah pilihan yang benar; untuk penyusup canggih yang menguasai banyak sistem, memutus satu akses sebelum semua jalan masuk diketahui bisa membuatnya bersembunyi lebih dalam [S4].
- **Anggapan:** insiden selesai saat sistem kembali menyala. **Kenyataannya:** Rev. 3 menempatkan pernyataan akhir pemulihan berdasarkan kriteria, after-action report, dan pemantauan pasca-pemulihan sebagai bagian dari Recover [S1]. Akun Bagus aktif pukul 10:30, tetapi insiden baru ditutup setelah laporan akhir dan tindakan perbaikan punya pemilik.
- **Anggapan:** bila SOC dijalankan MSSP (managed security service provider, penyedia layanan pemantauan keamanan) atau datanya di cloud, IR menjadi tanggung jawab penyedia. **Kenyataannya:** Rev. 3 menyebut pembagian tugas IR dengan penyedia sebagai shared responsibility yang harus jelas di kontrak, termasuk alur informasi, koordinasi, dan wewenang bertindak atas nama organisasi [S1]. Kewajiban pemberitahuan kepada subjek data tetap pada pengendali data, seperti dibahas di Day 18 bagian 1.6.
- **Anggapan:** hafal glosarium berarti siap interview. **Kenyataannya:** glosarium di bagian 3 hanya titik awal; interviewer menilai apakah kamu bisa membedakan istilah yang mirip, memberi contoh, dan menyebut batas sebuah alat (bagian 4).

## 6. Catatan terkini

Bagian ini mencatat versi dan tanggal dokumen acuan yang perlu diketahui saat membaca sumber lain tentang IR.

- **NIST SP 800-61 Rev. 3** terbit final 3 April 2025 (draf publik 3 April 2024) dengan judul "Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile" [S1]. Detail teknis yang dulu ada di dokumen dipindah ke halaman proyek Incident Response NIST dan ke pemetaan di NIST Cybersecurity and Privacy Reference Tool (CPRT), supaya bisa diperbarui tanpa revisi dokumen [S1].
- **NIST SP 800-61 Rev. 2** (Agustus 2012) berstatus withdrawn sejak 3 April 2025 dan digantikan Rev. 3 [S2]. Dokumen ini masih banyak dirujuk materi pelatihan, playbook, dan pertanyaan interview, sehingga model empat fasenya tetap perlu dikuasai.
- **Playbook IR CISA** untuk instansi federal Amerika Serikat terbit November 2021 dan disusun mengikuti fase Rev. 2 [S4]. Berkas PDF yang dirujuk berada di jalur unggahan Agustus 2024 situs CISA. Playbook ini ditulis untuk instansi federal (misalnya kewajiban lapor ke CISA dalam satu jam untuk insiden besar), tetapi CISA mendorong organisasi lain memakainya sebagai pembanding.
- **NIST SP 800-86** (Agustus 2006) masih berstatus final tanpa revisi baru [S5].
- **SANS Incident Handler's Handbook** karya Patrick Kral terbit Februari 2012 [S6]; singkatan PICERL untuk enam langkahnya adalah sebutan lapangan.
- **Pencabutan akses di Entra ID:** halaman Microsoft yang dirujuk diperbarui 19 Juni 2026; masa berlaku bawaan access token satu jam dan dukungan continuous access evaluation bisa berubah, jadi cek dokumentasi terbaru sebelum menulis runbook [S8].
- **MITRE ATT&CK T1539** (Steal Web Session Cookie) versi 1.5, terakhir diubah 12 Mei 2026, berada di tactic Credential Access [S9].
- **UU PDP dan peraturan pelaksananya:** status PP No. 33 Tahun 2026 dan lembaga pengawas dicatat di Day 18 bagian 5.

## 7. Cheat sheet

```
IR                   : siapkan, deteksi, tangani, pulihkan, belajar; urutan disepakati sebelum insiden
NIST SP 800-61 Rev.2 : 2012, ditarik 3 Apr 2025; 4 fase: Preparation | Detection & Analysis |
                       Containment, Eradication & Recovery | Post-Incident Activity
NIST SP 800-61 Rev.3 : 3 Apr 2025, CSF 2.0 Community Profile; persiapan = GV ID PR;
                       respons = DE RS RC; perbaikan terus = ID.IM (Improvement)
SANS PICERL          : Preparation, Identification, Containment, Eradication, Recovery, Lessons learned
Preparation          : kebijakan IR, peran dan wewenang, playbook, kontak, alat, latihan, pencegahan
Precursor / indicator: tanda akan terjadi / tanda sedang atau sudah terjadi
Detection & analysis : validasi, scoping (cari juga di target lain), prioritas, dokumentasi sejak awal
Prioritas            : bukan siapa duluan; dampak fungsional, dampak data, kemampuan pulih, kritikalitas aset
Incident declaration : adverse event memenuhi kriteria insiden -> rencana IR berjalan
Severity PT JAB      : SEV-1 lumpuh/bocor massal/domain dikuasai; SEV-2 >1 sistem; SEV-3 1 host/akun; SEV-4 minimal
IC / incident lead   : satu orang memimpin satu insiden; mengatur, bukan mengerjakan semua
Containment          : cegah meluas; pilih strategi: kerusakan, bukti, layanan, waktu, efektivitas, durasi
Akun cloud           : nonaktifkan + revoke sessions; access token bisa hidup s.d. 1 jam (bawaan) kecuali continuous access evaluation
Eradication          : hapus malware, persistence, akun/aturan penyerang, tutup celah; cari semua host terdampak
Recovery             : backup bersih (cek dulu), rebuild, patch, ganti password; kriteria tertulis; pantau
Evidence             : dasar untuk membuktikan atau membantah; tetap bukti walau tidak ke pengadilan
Chain of custody     : siapa, kapan (zona waktu), untuk apa, di mana; tanda tangan tiap perpindahan
Forensic image       : salinan utuh; hash sumber = hash salinan; analisis pada salinan
Order of volatility  : memori dan koneksi aktif dulu, lalu disk, lalu arsip dan log
RCA                  : penyebab langsung -> enabling condition -> akar sistemik; 5 whys; jangan berhenti di "user"
Komunikasi           : koordinasi | notification | publik | berbagi info; out-of-band bila sistem dikuasai
UU PDP               : kegagalan pelindungan -> tertulis maks 3 x 24 jam; DPO yang memutuskan (Day 18)
Lessons learned      : dalam beberapa hari; apa terjadi, apa dilakukan, seberapa efektif, apa diubah
Hotwash              : evaluasi singkat segera setelah penanganan (istilah CISA)
After-action report  : kejadian, tindakan respons dan pemulihan, lessons learned; syarat menutup
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "NIST SP 800-61 Rev. 3 sudah menghapus containment, eradication, dan recovery, jadi model empat fase tidak perlu dipelajari lagi." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Rev. 3 mengganti bingkai siklus menjadi enam fungsi CSF 2.0, tetapi containment dan eradication tetap ada sebagai subkategori fungsi Respond, dan recovery menjadi fungsi Recover. Rev. 2 memang sudah ditarik, tetapi model empat fasenya masih membentuk kosakata tim IR, dipakai playbook CISA, dan sering ditanyakan di interview, jadi jawaban terbaik menyebut kedua model dan cara memetakannya. Lihat bagian 1.1 dan 6.

</details>

**2. Skenario keputusan.** Pukul 07:20 kamu yakin akun Microsoft 365 seorang staf sedang dipakai penyerang dari IP luar, dan ada aturan inbox mencurigakan di kotak suratnya. Apa urutan yang paling tepat?

- A. Hapus aturan inbox dan reset password segera, lalu periksa log nanti.
- B. Nonaktifkan akun dan cabut semua sesi, blokir IP, ekspor log dan detail aturan inbox sebagai bukti, baru hapus aturan dan lanjutkan eradication.
- C. Biarkan dulu sampai analisis lengkap supaya penyerang tidak sadar sedang diawasi.

<details><summary>Jawaban</summary>

B. Containment akun (nonaktifkan dan cabut sesi) menghentikan penyerang tanpa menghapus bukti, lalu bukti diamankan sebelum aturan dihapus di tahap eradication. A keliru karena reset password tidak mematikan sesi curian yang sedang dipakai, dan menghapus aturan sebelum diekspor menghilangkan bukti. C keliru karena penyerang sedang aktif memakai akun untuk menipu; menunda containment untuk mengamati hanya layak untuk kasus tertentu, dibahas dulu dengan bagian hukum, dan berbahaya bila penyerang bisa menimbulkan kerugian. Lihat bagian 1.5 dan 2.1.

</details>

**3. Pertanyaan jebakan.** "Hash image sudah cocok dengan hash disk aslinya, jadi formulir chain of custody tidak diperlukan." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Hash membuktikan isi salinan sama dengan sumbernya pada saat image dibuat, tetapi tidak menjawab siapa yang memegang laptop sebelum dan sesudahnya, kapan, dan untuk apa. Chain of custody mencatat setiap perpindahan dengan nama, waktu beserta zona waktunya, tujuan, dan tanda tangan. Keduanya saling melengkapi. Lihat bagian 1.7 dan 2.2.

</details>

**4. Skenario keputusan.** Saat menulis RCA `INC-2027-098`, tiga rekan mengusulkan rumusan akar penyebab. Mana yang paling tepat?

- A. "Bagus memasang software bajakan."
- B. "Akses penuh dari perangkat pribadi yang tidak dikelola diizinkan oleh kebijakan dan Conditional Access, sehingga cookie sesi yang dicuri dari perangkat itu bisa dipakai penyerang."
- C. "Penyerang dari `192.0.2.183` yang sebelumnya menyerang VPN."

<details><summary>Jawaban</summary>

B. Rumusan ini menyebut kondisi dan keputusan yang bisa diperbaiki organisasi, sesuai arahan Rev. 3 untuk mencari akar penyebab yang mendasar atau sistemik. A adalah penyebab langsung yang melibatkan satu orang; bila berhenti di situ, karyawan lain dengan perangkat pribadi terinfeksi akan mengulang kejadian. C adalah atribusi sumber serangan, bukan penyebab, dan kesamaan IP hosting bahkan belum membuktikan pelakunya sama. Lihat bagian 1.8 dan 2.3.

</details>

**5. Jelaskan ulang.** Jelaskan kepada anggota keluargamu yang bukan orang IT, dalam tiga kalimat, apa itu incident response.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Incident response itu seperti cara pemadam kebakaran menangani kebakaran di gedung kantor, tetapi untuk serangan di komputer. Ada persiapan sebelum kejadian, lalu saat ada serangan kami memastikan kejadiannya, menahan supaya tidak menyebar, membersihkan, dan memulihkan sistem sambil menyimpan bukti. Setelah selesai, kami mencari penyebabnya dan memperbaiki aturan supaya kejadian yang sama tidak terulang."

Kesalahan yang sering muncul:
- Hanya menyebut "membersihkan virus", tanpa persiapan, penyimpanan bukti, dan pembelajaran setelahnya.
- Memakai singkatan dan nama fase berbahasa Inggris kepada orang yang bukan orang IT.

</details>

**6. Pertanyaan jebakan.** "Insiden ini hanya SEV-3, jadi DPO tidak perlu dikabari." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Severity mengukur dampak teknis dan operasional secara keseluruhan, sedangkan keterlibatan data pribadi adalah kriteria tersendiri. Di PT JAB, SOC wajib mengabari DPO paling lambat 2 jam setelah ada indikasi data pribadi terlibat, apa pun SEV-nya, karena tenggat pemberitahuan UU PDP (3 x 24 jam) dihitung oleh DPO dan tidak menunggu insiden menjadi besar. Di `INC-2027-098`, SEV tetap 3 tetapi DPO dikabari pukul 09:05. Lihat bagian 1.4 dan 1.9.

</details>

**7. Interview question (English).** "Walk me through how you would respond to a compromised Microsoft 365 account."

<details><summary>Sample answer</summary>

"First I validate: I check the sign-in logs for the unusual IP, device, and whether MFA was actually performed or satisfied by an existing token, and I call the user on a known phone number instead of emailing the account that may be compromised. If it is confirmed, I escalate so an incident is declared and contain immediately: disable the account, revoke all sessions, and block the source, remembering that existing access tokens can stay valid for up to an hour by default. Before removing anything, I export the sign-in and audit logs and record the attacker's inbox rules, sent messages, and any new MFA methods or app consents as evidence. Then I eradicate those changes, reset the password, re-register MFA with the user, and restore access only when agreed criteria are met, with extra monitoring afterwards. I scope what the attacker read or sent, for example fraud emails to finance or personal data that requires the DPO to assess notification, and finally I contribute to the root cause analysis and lessons learned, such as tightening access from unmanaged devices."

What makes this answer strong: it follows the IR lifecycle in the right order, separates containment from eradication, protects evidence before cleanup, mentions a cloud-specific detail (session tokens outlive a password reset), and brings in business and legal impact instead of stopping at the technical fix.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | NIST SP 800-61r3: Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile | https://doi.org/10.6028/NIST.SP.800-61r3<br>https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf<br>https://csrc.nist.gov/pubs/sp/800/61/r3/final | primer | 2025-04-03; diakses 2026-10-22 | Tinggi. Model siklus CSF 2.0 (Fig. 2), tabel padanan dengan Rev. 2 (Table 1), alasan perubahan, peran IR, isi kebijakan IR, DE.AE-08, RS.MA, RS.AN-03/06/07/08, RS.CO, RS.MI, RC.RP, RC.CO, ID.IM |
| S2 | NIST SP 800-61r2: Computer Security Incident Handling Guide | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf<br>https://csrc.nist.gov/pubs/sp/800/61/r2/final | primer | 2012-08; ditarik 2025-04-03; diakses 2026-10-22 | Tinggi untuk model empat fase, precursor dan indicator, prioritas (3.2.6), strategi containment (3.3.1), bukti dan chain of custody (3.3.2), eradication dan recovery (3.3.4), lessons learned (3.4.1), checklist (Table 3-5). Dokumen sudah ditarik; dipakai untuk model yang masih umum |
| S3 | NIST CSRC Glossary: chain of custody; root cause analysis | https://csrc.nist.gov/glossary/term/chain_of_custody<br>https://csrc.nist.gov/glossary/term/root_cause_analysis | primer (glosarium NIST) | diakses 2026-10-22 | Tinggi. Definisi dari SP 800-72 dan SP 800-101 Rev. 1 (chain of custody), SP 800-30 Rev. 1 dan SP 800-39 (RCA) |
| S4 | CISA: Federal Government Cybersecurity Incident and Vulnerability Response Playbooks | https://cisa.gov/sites/default/files/2024-08/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf | primer | 2021-11; berkas versi unggahan 2024-08; diakses 2026-10-22 | Tinggi. Deklarasi insiden, kegiatan dan pertimbangan containment, syarat dan kegiatan eradication, recovery, root cause dan enabling conditions, hotwash, saluran out-of-band. Ditulis untuk instansi federal AS |
| S5 | NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response | https://csrc.nist.gov/pubs/sp/800/86/final | primer | 2006-08; diakses 2026-10-22 | Tinggi untuk status dan sudut pandang dokumen (TI, bukan penegakan hukum; konsultasi manajemen dan hukum). Isi teknis dokumen tidak dirujuk |
| S6 | SANS Institute: Incident Handler's Handbook (Patrick Kral) | https://www.sans.org/white-papers/33901 | sekunder (white paper SANS) | 2012-02-21; diakses 2026-10-22 | Sedang. Halaman menyebut enam fase penanganan insiden tanpa merincinya |
| S7 | Palo Alto Networks Cortex Marketplace: SANS content pack | https://cortex.marketplace.pan.dev/marketplace/details/SANS | sekunder (dokumentasi vendor) | diakses 2026-10-22 | Sedang. Daftar enam langkah Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned berdasarkan handbook Kral |
| S8 | Microsoft Learn: Revoke user access in an emergency in Microsoft Entra ID | https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access | primer (dokumentasi vendor) | diperbarui 2026-06-19; diakses 2026-10-22 | Tinggi. Langkah hybrid (nonaktifkan dan reset di AD, nonaktifkan dan Revoke sessions di Entra ID), access token bawaan satu jam, continuous access evaluation |
| S9 | MITRE ATT&CK: Steal Web Session Cookie (T1539) | https://attack.mitre.org/techniques/T1539/ | primer | v1.5, diubah 2026-05-12; diakses 2026-10-22 | Tinggi. Definisi teknik, tactic Credential Access, contoh infostealer yang mencuri cookie |

**Catatan sumber:** nama enam langkah SANS (PICERL) diambil dari dokumentasi vendor yang merujuk handbook Kral (S7), karena halaman SANS (S6) tidak merinci nama langkahnya dan PDF handbook tidak diperiksa langsung. Prinsip order of volatility ditulis sebagai praktik umum forensik digital; isi teknis NIST SP 800-86 tentang urutan pengumpulan data tidak diperiksa di tabel ini. Teknik "5 whys" adalah praktik umum lapangan tanpa sumber NIST. Seluruh isi PT JAB (alert `SOC-2027-0897` sampai `0899`, insiden `INC-2027-098`, tokoh Bagus Wicaksono dan Ratih Purnomo, laptop `JKT-WS-1192`, formulir bukti `EV-2027-098-01` dan `-02`, nomor segel, hash ilustrasi, skala SEV beserta pembagian IC, batas lapor DPO 2 jam, dan daftar tindakan hotwash) adalah contoh fiktif; hash SHA-256 di bagian 2.2 dihitung dari teks contoh, bukan dari image sungguhan.
