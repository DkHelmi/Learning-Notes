---
day: 20
title: 'Tabletop exercise: desain, inject, fasilitasi, dan tindak lanjut'
researched_on: 2026-10-15
versions_checked: 'NIST SP 800-84 (September 2006, status final); FEMA Homeland Security Exercise and Evaluation Program (HSEEP) Doctrine, revisi 2020; NIST SP 800-61 Rev. 3 (April 2025, ID.IM-02); NCSC UK Effective steps to cyber exercise creation (versi 1.0, terbit 3 Februari 2020); NCSC UK Exercise in a Box (halaman tanpa tanggal); CISA Tabletop Exercise Packages (halaman tanpa tanggal); Black Hills Information Security Backdoors & Breaches'
---

# Day 20: Tabletop exercise (desain, inject, fasilitasi, dan tindak lanjut)

Cakupan: membedakan tabletop exercise dari uji lain, menetapkan tujuan yang bisa dinilai, menyusun skenario dan inject bertahap, membagi peran latihan, memfasilitasi diskusi yang jujur, lalu mengubah temuan menjadi perbaikan yang dilacak sampai selesai.

## Ide inti

Tabletop exercise menguji keputusan dan koordinasi, bukan kemampuan mengetik perintah. Orang-orang yang punya peran di IR plan duduk bersama, seorang fasilitator memaparkan skenario sedikit demi sedikit, dan setiap informasi baru (inject) memaksa peserta menjawab pertanyaan yang sama dengan malam insiden: siapa yang memutuskan, berdasarkan informasi apa, lewat kanal apa, dan dalam berapa lama. Nilai latihan tidak terletak pada skenario yang canggih, tetapi pada dua hal yang sering dilewatkan: tujuan yang ditulis sebelum latihan sehingga hasilnya bisa dinilai, dan tindak lanjut yang benar-benar mengubah plan, kontak, atau akses sebelum insiden berikutnya. Latihan yang berakhir dengan semua peserta setuju dan tidak ada yang berubah hanya menghabiskan setengah hari.

Kamu sudah mengenal pola ini dari NOC. Drill gangguan di NOC tidak menyentuh perangkat: koordinator drill membacakan "link backbone Jakarta-Surabaya putus pukul 02:00", lalu memperhatikan siapa yang menelepon siapa, apakah prosedur reroute diikuti, dan kapan pelanggan korporat diberi tahu. Di tengah drill ia menambahkan kabar baru, misalnya "jalur cadangan juga down" atau "pelanggan bank menelepon direktur", untuk melihat bagian prosedur yang belum teruji. Setelah drill, tim langsung berkumpul untuk debrief singkat, dan temuan seperti "nomor vendor fiber sudah tidak aktif" diperbaiki minggu itu juga. Tabletop exercise IR memakai pola yang sama, dengan dua perbedaan: lawannya manusia yang bisa berubah arah, dan keputusan yang diuji sering keputusan bisnis dan hukum, bukan teknis.

```
kebutuhan latihan (plan, insiden terakhir, auditor, perubahan organisasi)
  |
  v
tujuan yang bisa dinilai  -->  kriteria evaluasi ditulis SEBELUM latihan
  |
  v
skenario singkat + inject bertahap (MSEL) + pertanyaan pemandu
  |
  v
pelaksanaan: fasilitator memimpin, evaluator mencatat, pemain memutuskan
  |
  v
hotwash (langsung setelah latihan)
  |
  v
after-action report + improvement plan (pemilik, tenggat, kriteria selesai)
  |
  v
perbaikan dilacak sampai selesai  -->  latihan berikutnya menguji perbaikan itu
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif yang menangani insiden dengan CSIRT virtual. IR plan `JAB-IRP-01` versi 2.0 butir 9 mewajibkan uji kontak mingguan, uji akses kuartalan, tabletop minimal sekali setahun, dan review setelah setiap SEV-1 dan SEV-2 (Day 02 bagian 2.1). Sepanjang Oktober dan November 2026 PT JAB menangani beberapa insiden besar, dan post-incident review `INC-2026-019` menghasilkan dua belas action item (Day 19 bagian 2.6). Rabu 11 November 2026, Direktur Teknologi Hendra Wijaya menulis kepada Nina Kartika, Manajer Risiko dan Kepatuhan TI:

> "Bu Nina, IR plan kita mewajibkan tabletop minimal setahun sekali dan audit internal Januari pasti minta buktinya. Saya mau latihannya sebelum akhir tahun, dan saya ikut. Tapi saya tidak mau presentasi yang semua orang mengangguk. Apa bedanya dengan uji telepon tiap Senin yang sudah jalan, dan kenapa tidak simulasi serangan sungguhan saja? Apa persisnya yang mau diuji, dan bagaimana kita tahu latihannya berhasil? Skenarionya apa dan seberapa detail? Siapa yang ikut dan siapa yang memimpin, apakah Dimas karena dia IC? Bagaimana supaya orang jujur dan tidak saling menyalahkan? Lalu hasilnya apa, dan bagaimana memastikan ada yang berubah, bukan laporan yang disimpan? Terakhir, apa yang perlu kita siapkan untuk auditor?"

Pesan itu memuat tujuh pertanyaan:

1. Apa bedanya tabletop dengan uji kontak dan uji akses, dan kenapa tidak simulasi teknis?
2. Apa yang diuji, dan bagaimana tahu latihan berhasil?
3. Skenarionya apa, dan seberapa detail?
4. Siapa yang ikut dan siapa yang memimpin latihan?
5. Bagaimana menjaga diskusi jujur tanpa saling menyalahkan?
6. Apa hasilnya, dan bagaimana memastikan ada perubahan?
7. Apa yang disiapkan untuk auditor?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, pertanyaan 6 di bagian 1.6, dan pertanyaan 7 di bagian 1.7. Bagian 2 berisi dokumen latihan `TTX-2026-01` yang dijalankan PT JAB pada Kamis 17 Desember 2026.

**Kapan relevan:** setelah IR plan atau playbook disetujui atau diubah, setelah insiden besar untuk menguji perbaikannya, saat struktur organisasi atau orang di peran kunci berganti, dan saat auditor atau regulator meminta bukti bahwa plan pernah diuji.
**Kapan bukan jawaban:** tabletop tidak membuktikan bahwa tindakan teknis benar-benar bisa dijalankan; restore dari backup, isolasi lewat EDR, atau akses on-call tetap harus diuji dengan cara teknis (uji akses di Day 02 bagian 1.7, uji restore). Tabletop juga bukan tempat menyusun IR plan dari nol: plan dan peran harus sudah ada, karena yang diuji adalah isinya.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (IR plan, playbook, RACI, IC, executive sponsor, scribe, out-of-band, post-incident review, action item, blameless) tidak diulang. Tabel berikut memuat istilah baru Day ini. Kolom padanan memakai analogi NOC dan SOC yang sama di semua Day IR.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Tabletop exercise (TTX) | Latihan berbasis diskusi atas skenario, untuk menguji peran, keputusan, dan koordinasi tanpa menyentuh sistem | Drill gangguan di NOC tanpa menyentuh perangkat |
| Functional exercise | Latihan yang menjalankan tugas di lingkungan simulasi untuk menguji kesiapan operasional | Uji switchover ke perangkat cadangan di lab |
| Inject | Potongan informasi baru yang diberikan pengendali latihan untuk menggerakkan skenario | Kabar baru dari koordinator drill: "jalur cadangan juga down" |
| Master Scenario Events List (MSEL) | Daftar kronologis inject dan tindakan yang diharapkan, dengan waktu, penerima, dan tujuan latihan | Skrip drill berisi jam, kejadian, dan siapa yang harus bereaksi |
| Contingency inject | Inject cadangan yang dipakai bila tindakan yang diharapkan tidak muncul | Petunjuk tambahan dari koordinator drill saat tim terpaku di satu langkah |
| Fasilitator | Orang yang memimpin diskusi menuju tujuan latihan, tidak ikut memutuskan | Koordinator drill yang tidak ikut menangani gangguan |
| Evaluator atau data collector | Orang yang mencatat apa yang terjadi terhadap kriteria yang sudah ditetapkan | Pengamat drill yang mencatat waktu dan langkah |
| Pemain (player) | Peserta yang menjalankan perannya di plan selama latihan | Engineer on-call yang mengikuti drill |
| Trusted agent | Anggota tim perancang yang tahu skenario dan tidak membocorkannya ke pemain | Orang yang menyiapkan skrip drill dan merahasiakannya |
| Artificiality | Kondisi tidak nyata yang disepakati, misalnya waktu dipadatkan atau sistem tidak disentuh | Asumsi drill: perangkat tidak benar-benar dimatikan |
| Situation manual (SitMan) | Dokumen pegangan peserta untuk latihan diskusi: tujuan, aturan, skenario awal | Briefing drill yang dibagikan sebelum mulai |
| Hotwash | Diskusi singkat langsung setelah latihan tentang kekuatan dan hal yang perlu diperbaiki | Debrief singkat di ruang NOC setelah drill |
| After-action report dan improvement plan (AAR/IP) | Laporan latihan berisi pengamatan, analisis per tujuan, dan daftar perbaikan berpemilik dan bertenggat | RFO drill beserta daftar tindak lanjut |

### 1.1 Tabletop menguji keputusan, uji lain menguji kesiapan teknis

Pertanyaan pertama Hendra wajar karena PT JAB sudah punya uji kontak setiap Senin dan uji akses setiap kuartal (Day 02 bagian 1.7). Keduanya menjawab "apakah orangnya bisa dihubungi" dan "apakah aksesnya jalan". Tidak satu pun menjawab "apakah orang-orang itu tahu harus memutuskan apa, dan apakah mereka memutuskan hal yang sama".

NIST SP 800-84 membedakan tiga jenis kegiatan dalam program test, training, and exercise (TT&E): pelatihan peran, latihan (exercise), dan uji (test). Untuk latihan, panduan itu membahas dua jenis yang paling sering dipakai satu organisasi [S1]:

- **Tabletop exercise:** latihan berbasis diskusi; peserta bertemu, fasilitator memaparkan skenario dan mengajukan pertanyaan, lalu peserta membahas peran, tanggung jawab, koordinasi, dan pengambilan keputusan. Tidak ada peralatan atau sumber daya yang benar-benar dikerahkan.
- **Functional exercise:** peserta menjalankan tugasnya di lingkungan operasional yang disimulasikan, untuk menguji kesiapan operasional peran, prosedur, dan aset tertentu.

Doktrin HSEEP 2020 dari FEMA memakai pembagian yang lebih luas: latihan berbasis diskusi (seminar, workshop, tabletop, dan game) yang berfokus pada isu strategis dan kebijakan, serta latihan berbasis operasi (drill, functional, dan full-scale) yang menjalankan tindakan sungguhan [S2]. HSEEP mendefinisikan tabletop sebagai latihan diskusi atas skenario untuk membangun pemahaman bersama, menemukan kekuatan dan area yang perlu diperbaiki, atau mengubah cara pandang terhadap plan, kebijakan, dan prosedur [S2].

Tabel berikut menempatkan kegiatan uji PT JAB pada pembagian itu. Cari kolom "Yang dibuktikan" untuk melihat celah yang tidak ditutup uji lain.

| Kegiatan | Jenis | Yang dibuktikan | Yang tidak dibuktikan |
|---|---|---|---|
| Uji kontak mingguan | Uji (test) | Nomor aktif dan dijawab dalam batas waktu | Orang yang menjawab tahu apa yang harus diputuskan |
| Uji akses kuartalan | Uji (test) | On-call bisa login ke EDR, SIEM, bastion; akun break-glass jalan | Urutan tindakan dan siapa yang memberi izin |
| Tabletop exercise | Latihan diskusi | Peran, wewenang, kanal, dan keputusan sesuai plan dan dipahami sama oleh semua | Tindakan teknis benar-benar berhasil |
| Functional exercise atau uji restore | Latihan atau uji berbasis operasi | Prosedur teknis berjalan di lingkungan simulasi atau cadangan | Keputusan bisnis dan komunikasi |

Kenapa tidak langsung simulasi serangan? Simulasi teknis seperti purple team atau uji restore menguji alat dan prosedur teknis, dan mahal karena butuh lingkungan, waktu tim teknis, dan risiko gangguan. Banyak kegagalan di insiden PT JAB justru di keputusan dan koordinasi: wewenang blokir yang tidak jelas di `INC-2026-012` (Day 02), alert tamper antivirus yang tidak dieskalasi di `INC-2026-017` (Day 14 bagian 1.2). Itu wilayah tabletop. NIST SP 800-84 menyebut tabletop sebagai cara hemat biaya untuk memastikan isi IR plan bisa dijalankan saat darurat [S1].

### 1.2 Tujuan yang bisa dinilai, ditulis sebelum latihan

Pertanyaan kedua Hendra ("bagaimana tahu berhasil?") hanya bisa dijawab bila tujuan dan kriteria evaluasi ditulis sebelum latihan. Tanpa itu, penilaian setelah latihan berubah menjadi kesan: "diskusinya bagus".

NIST SP 800-84 menetapkan tujuan dasar setiap tabletop: memvalidasi isi IT plan beserta kebijakan dan prosedurnya, memvalidasi peran dan tanggung jawab peserta sebagaimana tertulis, dan memvalidasi ketergantungan antar bagian yang tertulis di plan [S1]. Panduan itu juga meminta kriteria evaluasi disusun sebelum latihan supaya data collector tahu apa yang harus dicatat, dan supaya after-action report bisa menilai seberapa jauh tujuan tercapai [S1]. HSEEP meminta jumlah tujuan yang wajar dan setiap tujuan bersifat SMART: spesifik, terukur, bisa dicapai, relevan, dan berbatas waktu [S2]. NCSC menambahkan bahwa tujuan sebaiknya diambil dari bagian bisnis yang paling kritis, menimbang dampak dan kemungkinan risikonya, dan bahwa latihan menguji plan yang sudah ada, bukan membuat plan [S4].

Untuk PT JAB, sumber tujuan paling kuat adalah insiden sendiri. Kelemahan yang sudah terjadi sekali paling mungkin terjadi lagi, dan latihan bisa membuktikan apakah perbaikannya bekerja. Contoh perbedaan tujuan lemah dan tujuan yang bisa dinilai:

| Tujuan lemah | Tujuan yang bisa dinilai |
|---|---|
| Menguji kesiapan menghadapi ransomware | Dalam 30 menit waktu skenario setelah declare, IC memutuskan isolasi host dan blok IOC tanpa menunggu persetujuan di luar wewenang di muka `JAB-IRP-01` |
| Menguji komunikasi | Dalam 60 menit waktu skenario setelah bukti pencurian data, DPO dan Legal menetapkan titik mulai hitungan 3 x 24 jam dan pemilik draf pemberitahuan, dengan alasan tertulis |
| Menguji eskalasi | Alert tamper antivirus di server dieskalasi L1 ke L2 sesuai runbook dalam 15 menit waktu skenario, tanpa diminta fasilitator |

Tujuan yang bisa dinilai menyebut siapa, apa, batas waktu, dan acuan di plan. Kriterianya bisa dicatat evaluator dengan "ya, tidak, sebagian" beserta waktunya.

### 1.3 Skenario singkat, inject bertahap

Pertanyaan ketiga Hendra ("seberapa detail?") sering dijawab salah ke arah terlalu detail.

NIST SP 800-84 menyebut anggapan bahwa skenario harus sangat detail sebagai salah paham yang umum: dengan skenario panjang, peserta sering menghabiskan waktu membedah skenario daripada mengejar tujuan latihan; skenario yang singkat dan padat sering lebih efektif [S1]. Bila skenario detail tetap diperlukan, panduan itu meminta trusted agent yang paham plan dan prosedurnya ikut menyusun supaya akurat, dan fasilitator harus bisa mengembalikan fokus peserta ke tujuan [S1].

Skenario digerakkan dengan inject. NCSC meminta setiap inject punya tujuan dan respons yang diharapkan yang jelas, realistis, dikirim ke orang yang tepat, dan dicek ahli teknis supaya tidak menggelincirkan latihan [S4]. HSEEP mendefinisikan MSEL sebagai garis waktu kronologis berisi tindakan yang diharapkan dan kejadian yang disisipkan pengendali latihan, dengan tiga jenis entri: inject, contingency inject (dipakai bila tindakan kunci yang diharapkan tidak muncul), dan tindakan yang diharapkan [S2]. Setiap entri MSEL memuat nomor, waktu skenario, jenis, cara penyampaian, dari siapa, untuk siapa, pesan, respons yang diharapkan, tujuan latihan yang terkait, dan catatan [S2]. HSEEP menempatkan MSEL terutama di latihan berbasis operasi; untuk tabletop, format yang sama tetap berguna sebagai skrip fasilitator, dan dokumen inti pesertanya adalah situation manual [S2].

Dari sumber itu, PT JAB memakai aturan berikut untuk tabletop:

- **Skenario awal paling banyak setengah halaman.** Sisanya datang lewat inject.
- **Tiga sampai empat modul**, masing-masing mewakili satu fase insiden dengan loncatan waktu skenario yang jelas.
- **Setiap inject menjawab "keputusan apa yang ingin dipaksa keluar?"** Inject yang hanya menambah warna cerita dibuang.
- **Contingency inject disiapkan** untuk tujuan yang paling penting, supaya tujuan tetap teruji walau diskusi berbelok.
- **Setiap materi diberi label latihan.** NCSC menyarankan semua komunikasi latihan diawali "EXERCISE, EXERCISE, EXERCISE" dan nama latihannya, supaya tidak tertukar dengan kejadian nyata [S4].

### 1.4 Peran latihan: yang memimpin latihan tidak ikut bermain

Pertanyaan keempat Hendra ("apakah Dimas yang memimpin?") menyentuh kesalahan yang mudah terjadi: orang yang perannya diuji juga memimpin latihan.

NIST SP 800-84 meminta tim perancang menunjuk fasilitator yang memimpin diskusi dan data collector yang mencatat apa yang terjadi; keduanya harus paham isi plan dan tujuan latihan, bertemu sebelum latihan, dan meninjau hasil latihan sebelumnya [S1]. Panduan itu juga menyarankan tim tingkat pimpinan dan tim operasional berlatih terpisah lebih dulu karena tanggung jawabnya berbeda, lalu digabung dalam latihan bersama untuk menguji koordinasi di antara keduanya [S1]. Durasi tabletop tingkat pimpinan biasanya dua sampai empat jam, dan tingkat operasional dua sampai delapan jam [S1]. HSEEP menyebut perancang latihan biasanya bukan pemain, melainkan trusted agent yang tidak membocorkan skenario [S2].

Untuk `TTX-2026-01`, pembagian perannya:

| Peran latihan | Diisi oleh | Alasan |
|---|---|---|
| Penanggung jawab dan fasilitator | Nina Kartika (Manajer Risiko dan Kepatuhan TI) | Paham `JAB-IRP-01`, tidak memegang peran di CSIRT, sudah memfasilitasi PIR `INC-2026-019` |
| Trusted agent teknis | Konsultan retainer PT Forensik Digital Contoh | Menyusun inject teknis yang realistis tanpa menjadi pemain |
| Evaluator | Satu auditor internal dan satu konsultan retainer | Mencatat terhadap kriteria; auditor sekaligus melihat bukti latihan |
| Scribe latihan | Analyst L1 shift pagi yang tidak bertugas | Mencatat waktu dan keputusan seperti scribe insiden, sekaligus berlatih |
| Pemain | Gilang Ramadhan (L1 shift malam), Dimas (IC), Sari (technical lead), Yoga (L2 on-call), Bambang (NOC), Maya (Corporate Communication), Ratna (Legal), Agus (DPO), Hendra (executive sponsor, bergabung di modul 3 dan 4) | Peran yang tertulis di `JAB-IRP-01` |

Dimas tidak memimpin latihan karena keputusan IC termasuk yang diuji. Hendra bergabung di modul ketiga dan keempat supaya latihan menguji pola yang sama dengan insiden nyata: executive sponsor ditarik masuk saat keputusan bisnis muncul, bukan sejak awal. Latihan ini menggabungkan tingkat operasional dan pimpinan sejak awal, berbeda dengan urutan yang disarankan NIST SP 800-84, karena CSIRT PT JAB kecil dan ini tabletop pertama setelah `JAB-IRP-01` versi 2.0; konsekuensinya, pertanyaan untuk tingkat pimpinan dikumpulkan di modul 3 dan 4, dan latihan khusus tingkat pimpinan dicatat untuk program 2027.

### 1.5 Fasilitasi: jujur tanpa takut, keputusan dengan informasi yang tidak lengkap

Pertanyaan kelima Hendra adalah tantangan terbesar tabletop di organisasi yang hierarkis: peserta cenderung memberi jawaban yang terdengar benar di depan atasan, bukan yang benar-benar akan mereka lakukan pukul dua pagi.

HSEEP meminta semua peserta tabletop didorong berkontribusi dan diingatkan bahwa mereka memutuskan dalam lingkungan tanpa kesalahan (no-fault) [S2]. NCSC meminta peserta tidak "melawan skenario" walau terasa kurang realistis, dan menerima bahwa mereka harus memutuskan dengan informasi tidak lengkap seperti insiden nyata [S4]. NIST SP 800-84 menggambarkan alurnya: fasilitator membuka dengan perkenalan peran, memaparkan lingkup dan skenario, memulai dengan satu pertanyaan yang memancing keputusan atau koordinasi, membiarkan diskusi mengalir, lalu menyisipkan pertanyaan dari panduan fasilitator bila diskusi berhenti sampai semua tujuan tersentuh; peserta sebaiknya tidak duduk bersama timnya sendiri supaya berpikir mandiri dan mengenal bagian lain [S1].

Dari sumber itu, aturan main `TTX-2026-01` yang dibacakan di awal:

1. **Yang diuji plan dan prosesnya, bukan orangnya.** Jawaban "saya tidak tahu" adalah temuan yang berharga, bukan kegagalan pribadi. Prinsip ini sama dengan PIR blameless di Day 19 bagian 1.5.
2. **Jawab apa yang akan kamu lakukan, bukan apa yang tertulis.** Bila keduanya berbeda, sebutkan; perbedaan itu yang dicari latihan.
3. **Jangan melawan skenario.** Informasi di inject dianggap benar pada waktu itu.
4. **Putuskan dengan informasi yang ada.** Menunggu kepastian juga keputusan, dan harus disebut berapa lama menunggunya.
5. **Pimpinan bicara terakhir** pada setiap pertanyaan, supaya jawaban staf tidak menyesuaikan diri dengan jawaban atasan.

Teknik fasilitasi yang membantu: tanyakan ke orang yang perannya diuji lebih dulu ("Yoga, kamu on-call, apa yang kamu lakukan sekarang?"), minta bukti dari plan ("di bagian mana itu tertulis?"), dan tanyakan "lalu siapa yang diberi tahu, lewat apa?" setiap kali ada keputusan. Topik yang menarik tetapi di luar tujuan dicatat di papan "parkir" untuk dibahas setelah latihan.

### 1.6 Hasil latihan: hotwash, after-action report, dan perbaikan yang dilacak

Pertanyaan keenam Hendra ("bagaimana memastikan ada yang berubah?") dijawab oleh tiga langkah yang semuanya punya bentuk tertulis.

**Hotwash.** NIST SP 800-84 meminta fasilitator dan data collector mengadakan debrief, sering disebut hotwash, segera setelah diskusi selesai, dengan menanyakan area yang sudah baik, area yang butuh pelatihan tambahan, dan bagian plan yang perlu diperbarui [S1]. HSEEP menambahkan bahwa hotwash dipimpin fasilitator berpengalaman supaya tetap konstruktif, dan menjadi kesempatan peserta mengisi formulir umpan balik [S2]. NCSC menyarankan hotwash singkat langsung setelah latihan [S4].

**After-action report dan improvement plan (AAR/IP).** NIST SP 800-84 meminta AAR memuat latar belakang latihan (tujuan, sasaran, peserta, skenario), pengamatan fasilitator dan data collector, serta rekomendasi untuk memperbaiki plan; setelah itu koordinator plan memberi action item dan memperbarui plan [S1]. HSEEP menambahkan after-action meeting (AAM) untuk meninjau draf AAR/IP dan mencapai kesepakatan atas kekuatan, area perbaikan, corrective action, tenggat konkret, dan pemiliknya [S2]. Corrective action juga sebaiknya SMART, dicatat, dan dilaporkan terus sampai selesai, dengan cara memvalidasi bahwa perbaikan sebelumnya benar-benar berjalan [S2]. NCSC meminta laporan pasca latihan memuat pelajaran, rekomendasi, pemilik tindakan, dan ringkasan umpan balik peserta, dan rekomendasinya diterapkan sebelum latihan berikutnya [S4].

**Masuk ke siklus perbaikan.** NIST SP 800-61 Rev. 3 menempatkan latihan di ID.IM-02 dengan prioritas High: perbaikan diidentifikasi dari uji dan latihan keamanan, termasuk yang melibatkan pemasok dan pihak ketiga, dan merujuk ke SP 800-84 untuk bentuk latihannya [S3]. Bagi PT JAB, artinya action item latihan diperlakukan sama dengan action item PIR (Day 19 bagian 1.6): satu pemilik, tenggat, kriteria selesai, dan pelacakan di tempat yang sama, bukan di lampiran laporan latihan.

Satu aturan tambahan menutup lingkarannya: latihan berikutnya menguji perbaikan dari latihan ini. Perbaikan yang tidak pernah diuji ulang belum terbukti bekerja.

### 1.7 Bukti untuk auditor: program, bukan satu acara

Pertanyaan terakhir Hendra menyangkut audit internal Januari. Auditor biasanya tidak menilai seberapa seru latihannya; ia menilai apakah kewajiban di plan dijalankan dan apakah temuannya ditindaklanjuti.

NCSC menyarankan meminta persetujuan pimpinan untuk program latihan, bukan satu latihan, supaya pelajaran terbawa ke prosedur yang diperbarui [S4]. NIST SP 800-84 meminta latihan dijadwalkan berkala, setelah perubahan organisasi, pembaruan plan, atau panduan baru, dan meminta persetujuan manajemen sebagai langkah penting sebelum latihan dirancang [S1].

Paket bukti `TTX-2026-01` yang disiapkan untuk auditor:

| Bukti | Menjawab pertanyaan auditor |
|---|---|
| Persetujuan Hendra atas rencana latihan dan jadwal program 2027 | Apakah latihan direncanakan dan disetujui pimpinan? |
| Rencana latihan dengan tujuan dan kriteria evaluasi | Apakah yang diuji jelas sebelum latihan? |
| Daftar hadir per peran | Apakah peran di plan benar-benar ikut? |
| Catatan evaluator dan scribe | Apa yang terjadi, dengan waktu? |
| AAR/IP yang disetujui dan status corrective action | Apakah temuan ditindaklanjuti dan dipantau? |
| Versi `JAB-IRP-01` atau playbook yang diperbarui karena latihan | Apakah plan berubah karena latihan? |

Baris terakhir paling sering kosong, dan justru itu yang membedakan program latihan dari acara tahunan.

## 2. Contoh artefak dan langkah praktis di PT JAB

Semua isi bagian ini fiktif. Skenario latihan memakai nama sistem dan peran PT JAB supaya realistis, tetapi kejadiannya tidak pernah terjadi dan tidak boleh tertukar dengan insiden nyata; karena itu setiap dokumen diberi label latihan.

### 2.1 Rencana latihan `TTX-2026-01`

Dokumen ini menjawab pertanyaan pertama sampai keempat Hendra sekaligus, dan menjadi lampiran persetujuan yang diminta auditor. Disusun Nina bersama trusted agent, disetujui Hendra Senin 16 November 2026.

```
EXERCISE, EXERCISE, EXERCISE | TTX-2026-01 | Rencana latihan
Sponsor: Hendra Wijaya | Perancang dan fasilitator: Nina Kartika
Pelaksanaan: Kamis 2026-12-17 09:00-12:30 WIB, ruang rapat lantai 5 + bridge Bandung

ACUAN YANG DIUJI
JAB-IRP-01 v2.0 (wewenang, RACI, eskalasi, kanal, pelaporan), JAB-PB-01 Ransomware,
pohon keputusan pelaporan UU PDP, Lampiran E daftar kontak.

TUJUAN DAN KRITERIA EVALUASI (waktu = waktu skenario)
T1 Alert P2 tamper antivirus di server dieskalasi L1 ke L2 sesuai runbook dalam 15 menit,
   tanpa diminta fasilitator.
T2 IC aktif maks 15 menit setelah alert enkripsi; isolasi host dan blok IOC diputuskan
   maks 30 menit setelah declare tanpa persetujuan di luar wewenang di muka.
T3 Maks 60 menit setelah bukti pencurian data: DPO dan Legal menetapkan titik mulai
   3 x 24 jam dan pemilik draf pemberitahuan, dengan alasan tertulis.
T4 Maks 15 menit setelah indikasi kanal korporat dipantau: koordinasi pindah ke kanal
   out-of-band; maks 60 menit setelah pertanyaan media: holding statement satu pintu.
T5 Executive sponsor memutuskan urutan pemulihan dan sikap atas tebusan berdasarkan
   masukan backup, Legal, dan DPO, dan keputusannya tercatat.

LINGKUP
Di dalam: keputusan, wewenang, eskalasi, kanal, pelaporan, keputusan bisnis.
Di luar: tindakan teknis sungguhan, kecuali satu pesan uji di grup Signal JAB-CSIRT-OOB.

KONDISI TIDAK NYATA (artificialities)
1. Tidak ada sistem yang disentuh; semua tindakan diucapkan dan dicatat.
2. Waktu dipadatkan: skenario Jumat malam sampai Senin pagi dalam 3,5 jam.
3. Pihak luar (penyerang, media, pelanggan korporat, penegak hukum, regulator)
   diperankan fasilitator.
4. Informasi di inject dianggap benar pada waktunya; jangan melawan skenario.
5. Hendra bergabung mulai modul 3, seperti executive sponsor yang ditarik masuk.

JADWAL PERSIAPAN
18 Nov undangan per peran | 3 Des rapat perancang (MSEL final) | 10 Des situation
manual dikirim | 16 Des briefing fasilitator dan evaluator | 23 Des draf AAR/IP
```

Cara membaca elemennya:

- **Setiap tujuan punya angka, peran, dan acuan.** Evaluator cukup mencatat "ya, tidak, sebagian" beserta waktunya; tidak ada penilaian berdasarkan kesan.
- **Tujuan T1 dan T5 diambil dari `INC-2026-017`**, T2 dari `INC-2026-012`, T3 dan T4 dari pelajaran `INC-2026-019`. Latihan menguji perbaikan, bukan topik baru yang belum pernah jadi masalah.
- **Situation manual dikirim seminggu sebelumnya.** NIST SP 800-84 menyebut sekitar satu minggu sebagai jarak yang efektif: terlalu jauh terlupa, terlalu dekat tidak sempat dibaca [S1].
- **Persiapan lebih dari satu bulan**, sesuai saran NIST SP 800-84 untuk latihan yang tidak terlalu kompleks [S1].

### 2.2 Skenario awal dan Master Scenario Events List

Bagian ini menjawab pertanyaan ketiga Hendra. Skenario awal dibagikan di situation manual; MSEL hanya dipegang fasilitator, trusted agent, dan evaluator.

```
EXERCISE, EXERCISE, EXERCISE | TTX-2026-01 | Skenario awal (situation manual)
Jumat, 20:45 WIB. Shift malam SOC berjalan normal. Gilang (L1) memegang antrean,
Yoga (L2) on-call dari rumah, Dimas IC on-call. Minggu ini tagihan bulanan pelanggan
dijadwalkan terkirim Rabu. Tidak ada change yang terjadwal malam ini.
```

MSEL berikut adalah skrip fasilitator. Baca kolom "Respons yang diharapkan" dan "Tujuan", karena keduanya yang dinilai evaluator; kolom lain hanya alat penyampaian.

| No | Waktu latihan | Waktu skenario | Jenis | Ke | Pesan | Respons yang diharapkan | Tujuan |
|---|---|---|---|---|---|---|---|
| 1 | 09:15 | Jum 20:50 | Inject | Gilang | Alert P2 "tamper protection: setelan antivirus diubah" di `JKT-FS01` | L1 menelepon L2 sesuai runbook | T1 |
| 1a | 09:25 | Jum 21:05 | Contingency | Gilang | Alert yang sama muncul di `JKT-JUMP01` | Bila belum ada eskalasi: L1 menyadari pola dan menelepon L2 | T1 |
| 2 | 09:30 | Jum 21:32 | Inject | Gilang, Yoga | EDR: rename massal di share `Proyek` `JKT-FS01`, file baru `BACA-SEKARANG.txt` | L2 validasi, telepon IC; IC declare SEV-1; isolasi dan blok | T2 |
| 3 | 09:55 | Sab 01:10 | Inject | Yoga, Sari | Akun `svc_backup` login ke empat server dari `JKT-JUMP01` di luar jadwal backup | Scope diperluas; pertanyaan kompromi domain diajukan ke IC | T2 |
| 4 | 10:10 | Sab 02:00 | Inject | Sari, Bambang | Snapshot online file server terhapus; status salinan immutable di `JKT-BKP01` belum diketahui | Cek status backup ditugaskan dengan pemilik dan waktu | T5 |
| 5 | 10:50 | Sab 09:30 | Inject | Agus, Ratna, Hendra | Situs bocoran penyerang menampilkan contoh 1.000 baris data pelanggan (nama, NIK, alamat) dan tenggat tebusan 72 jam | DPO dan Legal menetapkan titik mulai dan pemilik draf; Hendra diberi tahu | T3 |
| 6 | 11:00 | Sab 10:15 | Inject | Maya | Wartawan mengirim pesan WhatsApp meminta konfirmasi kebocoran | Holding statement lewat satu pintu; tidak ada konfirmasi angka | T4 |
| 7 | 11:10 | Sab 10:40 | Inject | Dimas | Penyerang membalas pesan di kanal chat insiden dengan akun karyawan | Koordinasi pindah ke grup Signal OOB; pesan uji dikirim sungguhan | T4 |
| 8 | 11:35 | Sen 08:00 | Inject | Hendra, Sari | Restore dari `JKT-BKP01` diperkirakan 4 hari; tagihan bulanan harus terkirim Rabu | Urutan pemulihan diputuskan; sikap atas tebusan dengan masukan Legal dan DPO | T5 |
| 9 | 11:50 | Sen 09:00 | Inject | Ratna | Pelanggan korporat (bank) menagih pemberitahuan dalam 24 jam sesuai kontrak | Legal mengecek kewajiban kontrak dan pemilik komunikasinya | T3 |

Cara membaca elemennya:

- **Inject 1 dan 1a menguji satu hal dari dua arah.** Bila eskalasi muncul di inject 1, inject 1a dilewati; bila tidak, contingency inject memberi kesempatan kedua, dan keduanya dicatat.
- **Inject 7 satu-satunya tindakan nyata**: pesan uji berlabel latihan di grup Signal. Itu cara murah membuktikan grup OOB benar-benar berisi orang yang tepat.
- **Tidak ada inject yang hanya menambah cerita.** Setiap baris punya tujuan dan respons yang diharapkan, sesuai aturan inject NCSC [S4] dan isi entri MSEL di HSEEP [S2].

### 2.3 Panduan fasilitator: pertanyaan pemandu per modul

Panduan ini menjawab pertanyaan kelima Hendra dari sisi teknik bertanya. NIST SP 800-84 meminta pertanyaan untuk pimpinan bersifat umum dan berfokus pada keputusan dan pengawasan, sedangkan pertanyaan untuk tim operasional berfokus pada prosedur [S1].

| Modul | Pertanyaan untuk tim operasional | Pertanyaan untuk pimpinan |
|---|---|---|
| 1 Deteksi dan declare (inject 1-2) | Gilang, alert P2 di server ini, apa yang kamu lakukan dalam 5 menit? Di runbook bagian mana? Yoga, kapan kamu menelepon IC? | (Belum ada; Hendra bergabung di modul 3) |
| 2 Scope dan containment (inject 3-4) | Siapa yang memutuskan isolasi `JKT-JUMP01`, dan apakah perlu izin NOC? Apa yang membuat kalian menganggap domain terkompromi? Siapa yang mengecek backup, kapan hasilnya? | Dimas, keputusan mana yang masih di wewenangmu, dan mana yang harus naik ke Hendra? |
| 3 Data dan komunikasi (inject 5-7) | Agus, dari titik mana hitungan 3 x 24 jam dimulai, dan kenapa? Maya, apa yang boleh dan tidak boleh kamu katakan ke wartawan? Dimas, ke mana koordinasi pindah sekarang? | Hendra, informasi apa yang kamu butuhkan sebelum menyetujui pernyataan ke media? |
| 4 Pemulihan dan tebusan (inject 8-9) | Sari, layanan mana yang dipulihkan duluan dan kenapa? Ratna, kewajiban kontrak apa ke pelanggan bank? | Hendra, siapa yang ikut memutuskan sikap atas tebusan, dan apa yang harus diperiksa sebelumnya? |

Pertanyaan pembuka setiap modul selalu diarahkan ke orang yang perannya diuji, dan pimpinan menjawab terakhir (aturan 5 di bagian 1.5).

**Kapan gagal:** fasilitator menjawab sendiri ketika diskusi macet, atau membiarkan satu orang senior menjawab semua pertanyaan. Hasilnya terdengar lancar, tetapi evaluator tidak bisa menilai apakah pemegang peran tahu tugasnya.

### 2.4 Formulir evaluator dan catatan hasil

Formulir ini menjawab pertanyaan kedua Hendra dari sisi pelaksanaan: hasil dinilai terhadap kriteria di rencana, bukan kesan. Evaluator mengisi satu baris per tujuan, dengan waktu skenario dan bukti dari diskusi.

| Tujuan | Hasil | Waktu skenario | Pengamatan | Acuan di plan |
|---|---|---|---|---|
| T1 | Sebagian | 21:05 (inject 1a) | Gilang tahu alert server sekarang P2, tetapi akan "mengecek pagi" karena runbook tidak menyebut kapan menelepon L2 untuk P2; eskalasi baru muncul setelah alert kedua | Runbook L1 tidak memuat batas waktu untuk P2 |
| T2 | Ya | 21:41 IC aktif; 21:53 isolasi dan blok diputuskan | Dimas menyebut wewenang di muka dan Bambang menyatakan blok perimeter tidak butuh change darurat; pelajaran `INC-2026-012` terlihat | `JAB-IRP-01` wewenang di muka; RACI |
| T3 | Ya, dengan catatan | 10:05 (35 menit setelah inject 5) | Agus dan Ratna memakai pohon keputusan pelaporan dan mencatat alasan titik mulai; kewajiban kontrak ke pelanggan bank (inject 9) tidak ada yang tahu letak daftarnya | Pohon keputusan pelaporan; tidak ada daftar kewajiban kontrak |
| T4 | Sebagian | 10:52 pindah ke OOB; holding statement 10:55 | Pesan uji di grup Signal sungguhan menunjukkan Maya dan Ratna tidak ada di grup; holding statement disusun cepat dan lewat satu pintu | Lampiran E; kanal OOB di `JAB-IRP-01` |
| T5 | Sebagian | Sen 08:25 | Hendra memutuskan tidak membayar bersama Ratna dan Agus, dengan langkah pengecekan yang diucapkan tetapi tidak tertulis di playbook; tidak ada yang tahu waktu restore dari `JKT-BKP01` karena belum pernah diuji; urutan pemulihan diperdebatkan 20 menit | `JAB-PB-01` belum memuat urutan pemulihan dan langkah sebelum mempertimbangkan tebusan |

Cara membaca hasil:

- **"Sebagian" lebih banyak daripada "Ya"**, dan itu hasil latihan yang berguna. Latihan yang semua tujuannya "Ya" biasanya terlalu mudah atau dinilai terlalu longgar.
- **Kolom acuan menunjuk dokumen, bukan orang.** Gilang tidak "gagal"; runbook-nya tidak memberi batas waktu. Bentuk ini membuat perbaikannya jelas dan menjaga aturan no-fault.
- **T2 tercatat sebagai kekuatan.** Bukti bahwa perbaikan dari insiden sebelumnya bekerja sama pentingnya dengan menemukan kelemahan baru.

### 2.5 Hotwash, after-action report, dan improvement plan

Bagian ini menjawab pertanyaan keenam Hendra. Hotwash berlangsung 12:05 sampai 12:30 dipimpin Nina, dengan tiga pertanyaan dari NIST SP 800-84: apa yang sudah baik, di mana butuh pelatihan, dan bagian plan mana yang harus diperbarui [S1]. Peserta juga mengisi formulir umpan balik tentang latihan itu sendiri.

```
EXERCISE | TTX-2026-01 | Catatan hotwash (diringkas)
SUDAH BAIK
- Wewenang di muka dipahami IC dan NOC; blok tidak menunggu change darurat.
- DPO dan Legal memakai pohon keputusan dan mencatat alasan titik mulai.
- Holding statement keluar lewat satu pintu dalam 40 menit.
PERLU DIPERBAIKI
- Runbook L1 tidak memberi batas waktu eskalasi untuk P2.
- Grup Signal OOB tidak berisi Corporate Communication dan Legal.
- Waktu restore dari JKT-BKP01 tidak diketahui; belum pernah diuji.
- Urutan pemulihan layanan internal dan langkah sebelum mempertimbangkan tebusan
  tidak tertulis.
- Kewajiban notifikasi kontraktual pelanggan korporat tidak terdaftar.
TENTANG LATIHANNYA
- Modul 2 terlalu padat; inject 3 dan 4 sebaiknya dipisah 15 menit.
- Peserta Bandung sulit mengikuti diskusi lewat bridge; siapkan papan bersama.
```

Draf AAR/IP dikirim 23 Desember dan dibahas di after-action meeting 6 Januari 2027 untuk menyepakati pemilik dan tenggat, sesuai fungsi AAM di HSEEP [S2]. Improvement plan berikut adalah hasil pertemuan itu. Baca kolom "Kriteria selesai": tanpa kolom itu, item tidak pernah benar-benar selesai dan tidak pernah benar-benar gagal (Day 19 bagian 1.6).

| No | Temuan (tujuan) | Corrective action | Pemilik | Tenggat | Kriteria selesai |
|---|---|---|---|---|---|
| 1 | Eskalasi P2 tanpa batas waktu (T1) | Runbook L1: P2 di server dieskalasi ke L2 dengan telepon maksimal 15 menit | SOC (Sari) | 2027-01-15 | Runbook versi baru; diuji di uji kontak Senin dengan skenario P2 |
| 2 | Grup OOB tidak lengkap (T4) | Tambah Corporate Communication dan Legal; cocokkan anggota grup dengan Lampiran E setiap uji kontak | SOC lead (Dimas) | 2026-12-21 | Daftar anggota grup sama dengan Lampiran E; pesan uji dijawab semua |
| 3 | Waktu restore tidak diketahui (T5) | Uji restore share file server dari `JKT-BKP01` ke server cadangan, dengan waktu terukur | Infrastruktur | 2027-02-12 | Laporan uji dengan waktu restore; angka ditulis di `JAB-PB-01` |
| 4 | Urutan pemulihan tidak tertulis (T5) | Tambah urutan pemulihan layanan internal (MVO) ke `JAB-PB-01` | SOC lead (Dimas) bersama pemilik aplikasi | 2027-02-26 | `JAB-PB-01` versi baru disetujui Hendra |
| 5 | Langkah sebelum mempertimbangkan tebusan tidak tertulis (T5) | Tulis langkah wajib: cek backup, cek decryptor publik, penilaian Legal atas risiko hukum, keputusan executive sponsor tercatat | Legal (Ratna) | 2027-02-26 | Bagian baru di `JAB-PB-01` disetujui Hendra |
| 6 | Kewajiban kontrak tidak terdaftar (T3) | Daftar pelanggan korporat dengan kewajiban notifikasi kontraktual, batas waktunya, dan pemilik komunikasinya | Legal (Ratna) | 2027-01-29 | Daftar menjadi lampiran `JAB-IRP-01` |
| 7 | Program latihan 2027 | Jadwal: tabletop pimpinan (kuartal 1), uji restore fungsional (kuartal 2), tabletop BEC (kuartal 3); latihan berikutnya menguji item 1 sampai 6 | Risiko dan Kepatuhan TI (Nina) | 2027-01-15 | Jadwal disetujui Hendra |

Cara membaca elemennya:

- **Setiap item menunjuk tujuan latihan yang melahirkannya**, sehingga latihan berikutnya bisa menguji item itu dengan tujuan yang sama.
- **Item 3 adalah uji teknis, bukan tabletop.** Tabletop menemukan bahwa waktu restore tidak diketahui; menjawabnya butuh uji sungguhan (bagian 1.1).
- **Item dilacak di tempat yang sama dengan action item PIR** (Day 19 bagian 2.6), bukan di lampiran laporan latihan yang tidak pernah dibuka lagi.

**Kapan gagal:** AAR/IP dibuat berminggu-minggu setelah latihan tanpa after-action meeting, sehingga pemilik item tidak pernah menyetujui tenggatnya dan item berhenti di status "direkomendasikan".

## 3. Lab praktik

Lab ini berupa latihan merancang dan menjalankan tabletop mini untuk organisasi fiktif buatanmu sendiri, atau untuk PT JAB. Jangan memakai nama, sistem, atau kejadian dari tempat kerja nyata. Bila ada dua sampai empat rekan atau teman belajar, jalankan latihannya sungguhan; bila sendiri, perankan fasilitator dan tuliskan jawaban tiap peran.

1. **Pilih sumber tujuan.** Ambil satu insiden dari catatan ini (misalnya `INC-2026-021` BEC di Day 09 atau `INC-2026-025` cloud di Day 16) dan tulis tiga kelemahan keputusan atau koordinasi yang muncul di sana.
2. **Tulis tiga tujuan yang bisa dinilai** dengan format bagian 1.2: siapa, apa, batas waktu skenario, dan acuan di plan. Untuk setiap tujuan, tulis kriteria "ya, tidak, sebagian".
3. **Tulis rencana latihan** dengan format bagian 2.1, termasuk minimal tiga kondisi tidak nyata dan satu tindakan nyata yang murah untuk diuji (misalnya pesan uji di kanal OOB).
4. **Susun skenario dan MSEL.** Skenario awal maksimal lima kalimat. MSEL berisi enam sampai delapan inject dalam tiga modul, setiap inject dengan respons yang diharapkan dan tujuan terkait, ditambah satu contingency inject untuk tujuan terpenting.
5. **Tulis pertanyaan pemandu** per modul untuk tim operasional dan untuk pimpinan, dengan format bagian 2.3.
6. **Jalankan 60 sampai 90 menit.** Mulai dengan aturan main bagian 1.5. Satu orang menjadi evaluator dan mengisi formulir bagian 2.4. Catat waktu nyata dan waktu skenario setiap keputusan.
7. **Hotwash dan AAR/IP.** Jalankan hotwash 15 menit dengan tiga pertanyaan bagian 2.5, lalu tulis improvement plan dengan pemilik, tenggat, dan kriteria selesai. Tandai item mana yang harus diuji dengan cara teknis, bukan tabletop.

**Hasil yang sebaiknya tersimpan:**

- `latihan/day20-rencana.md` berisi tujuan, kriteria, lingkup, kondisi tidak nyata, dan jadwal persiapan.
- `latihan/day20-msel.md` berisi skenario awal, MSEL, dan pertanyaan pemandu.
- Formulir evaluator yang terisi dan catatan hotwash.
- `latihan/day20-aar-ip.md` berisi AAR singkat dan improvement plan.

**Variasi tantangan:** rancang ulang latihan yang sama untuk tingkat pimpinan saja, durasi dua jam. Pertanyaan mana yang dibuang, mana yang diubah dari prosedur menjadi keputusan, dan inject apa yang perlu ditambah? Bandingkan dengan saran NIST SP 800-84 tentang pertanyaan untuk pimpinan [S1].

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat merancang dan menjalankan tabletop. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Diskusi berputar di detail teknis skenario | Skenario terlalu panjang atau tidak akurat | Pendekkan skenario; libatkan trusted agent teknis; fasilitator mengembalikan ke tujuan [S1] |
| Semua tujuan dinilai "Ya" | Kriteria longgar atau dinilai setelah latihan | Tulis kriteria terukur sebelum latihan; evaluator bukan pemain [S1][S2] |
| Peserta senior menjawab semua pertanyaan | Hierarki; pertanyaan diarahkan ke ruangan, bukan ke peran | Tanya pemegang peran lebih dulu; pimpinan menjawab terakhir |
| Peserta berkata "itu tidak mungkin terjadi" | Melawan skenario | Ingatkan aturan main; catat keberatan sebagai parkir dan lanjutkan [S4] |
| Inject tertukar dengan kejadian nyata | Materi tanpa label latihan | Awali setiap materi dan pesan dengan label latihan [S4] |
| Tujuan penting tidak tersentuh | Diskusi berbelok; tidak ada contingency inject | Siapkan contingency inject untuk tujuan kunci [S2] |
| Temuan latihan tahun lalu muncul lagi | Corrective action tidak dilacak atau tidak diuji ulang | Lacak bersama action item PIR; uji item itu di latihan berikutnya [S2][S3] |

## 5. Kesalahan umum dan jebakan

- Menganggap tabletop membuktikan kemampuan teknis. Tabletop menguji keputusan dan koordinasi; restore, isolasi, dan akses tetap harus diuji dengan cara teknis.
- Memakai latihan untuk menyusun IR plan. Plan harus sudah ada; latihan menguji isinya [S4].
- Menulis tujuan setelah latihan, sehingga hasil apa pun terlihat berhasil.
- Skenario yang sangat panjang dan detail. Peserta membedah cerita, bukan mengambil keputusan [S1].
- Orang yang perannya diuji juga memimpin latihan.
- Mencampur pimpinan dan operasional tanpa memisahkan pertanyaannya, sehingga pimpinan diam atau staf ikut jawaban atasan.
- Menghukum jawaban "saya tidak tahu". Peserta belajar menyembunyikan celah, dan latihan berikutnya kehilangan nilainya [S2].
- Menyimpan AAR tanpa improvement plan berpemilik dan bertenggat, atau melacaknya terpisah dari action item insiden.
- Menganggap satu tabletop setahun cukup tanpa program. Perbaikan yang tidak diuji ulang belum terbukti bekerja.

## 6. Catatan terkini

Bagian ini menampung detail versi sumber yang bisa berubah. Berguna saat membuka sumbernya lagi, tetapi tidak mengubah cara merancang latihan.

- **NIST SP 800-84** terbit September 2006 dan halaman CSRC-nya masih mencantumkannya sebagai final; contoh di dalamnya (misalnya media salinan cadangan) sudah tua, tetapi alur tabletop-nya tetap dirujuk SP 800-61 Rev. 3 di ID.IM-02 [S1][S3].
- **HSEEP** yang dipakai adalah doktrin revisi 2020 dari FEMA. HSEEP dirancang untuk program latihan kedaruratan di Amerika Serikat; istilah dan dokumennya (MSEL, SitMan, AAR/IP, AAM) dipakai luas di latihan siber, termasuk paket latihan CISA [S2][S6].
- **CISA Tabletop Exercise Packages (CTEP)** menyediakan paket gratis berisi tujuan, skenario, dan pertanyaan diskusi yang bisa disesuaikan, dengan skenario siber seperti ransomware, ancaman orang dalam, phishing, dan kompromi ICS, serta template undangan, slide, formulir umpan balik, dan AAR [S6].
- **NCSC Exercise in a Box** menyediakan latihan gratis berupa micro exercise dan tabletop untuk topik seperti ransomware, phishing, dan rantai pasok, ditujukan antara lain untuk organisasi kecil dan menengah [S5]. Panduan NCSC tentang membuat latihan siber berversi 1.0, terbit Februari 2020 [S4].
- **Backdoors & Breaches** adalah permainan kartu dari Black Hills Information Security yang dipakai praktisi sebagai tabletop ringan: satu orang menyusun rantai serangan tersembunyi, tim defender menebaknya dengan kartu deteksi [S7]. Cocok untuk latihan tim teknis, bukan pengganti tabletop yang menguji wewenang dan pelaporan.

## 7. Cheat sheet

```
TABLETOP = latihan diskusi: menguji peran, wewenang, koordinasi, keputusan
  != uji kontak/akses (test) != functional exercise / uji restore (teknis)
  durasi: pimpinan 2-4 jam, operasional 2-8 jam (SP 800-84)

TUJUAN: ditulis SEBELUM latihan, SMART: siapa + apa + batas waktu + acuan di plan
  sumber terbaik: kelemahan dari insiden sendiri; latihan menguji plan, tidak membuatnya

SKENARIO: awal pendek (<= setengah halaman) + inject bertahap per modul
  MSEL: no | waktu | jenis | ke | pesan | respons diharapkan | tujuan | catatan
  inject tanpa tujuan dibuang | contingency inject untuk tujuan kunci
  label: "EXERCISE, EXERCISE, EXERCISE" + nama latihan

PERAN: fasilitator (bukan pemain) | evaluator/data collector | trusted agent | scribe | pemain
  pimpinan dan operasional: terpisah dulu, lalu gabungan

ATURAN MAIN: uji plan bukan orang (no-fault) | jawab yang akan dilakukan | jangan
  melawan skenario | putuskan dengan info tidak lengkap | pimpinan bicara terakhir

SETELAH: hotwash langsung (baik / perlu latihan / plan diperbarui)
  -> AAR/IP -> after-action meeting (pemilik + tenggat) -> lacak bersama action item PIR
  -> latihan berikutnya menguji perbaikan itu (ID.IM-02)

BUKTI AUDITOR: persetujuan + rencana + daftar hadir + catatan evaluator + AAR/IP
  + status perbaikan + versi plan yang berubah karena latihan
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "PT JAB sudah menjalankan uji kontak setiap Senin dan uji akses setiap kuartal, jadi kewajiban menguji IR plan sudah terpenuhi tanpa tabletop." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Uji kontak dan uji akses membuktikan orang bisa dihubungi dan akses berjalan, tetapi tidak menguji apakah pemegang peran tahu keputusan apa yang harus diambil, siapa yang berwenang, dan lewat kanal apa. Itu wilayah tabletop, latihan berbasis diskusi yang memvalidasi isi plan, peran, dan ketergantungannya. `JAB-IRP-01` sendiri mewajibkan ketiganya. Lihat bagian 1.1.

</details>

**2. Skenario keputusan.** Nina menyusun tujuan latihan. Mana yang paling tepat?

- A. "Menguji kesiapan PT JAB menghadapi ransomware."
- B. "Dalam 60 menit waktu skenario setelah bukti pencurian data, DPO dan Legal menetapkan titik mulai 3 x 24 jam dan pemilik draf pemberitahuan, dengan alasan tertulis."
- C. "Peserta memahami pentingnya pelaporan UU PDP."

<details><summary>Jawaban</summary>

B. Tujuan itu menyebut siapa, apa, batas waktu, dan acuannya, sehingga evaluator bisa menilai "ya, tidak, sebagian" dengan waktu. A terlalu luas: hasil apa pun bisa disebut "siap". C mengukur pemahaman yang tidak terlihat, bukan keputusan yang bisa diamati. Lihat bagian 1.2 dan 2.1.

</details>

**3. Pertanyaan jebakan.** "Skenario yang bagus harus sangat detail, lengkap dengan semua log dan IOC, supaya terasa nyata." Benarkah?

<details><summary>Jawaban</summary>

Tidak. NIST SP 800-84 menyebut anggapan itu salah paham yang umum: dengan skenario panjang, peserta menghabiskan waktu membedah cerita, bukan mengejar tujuan. Skenario awal dibuat pendek, informasi berikutnya datang lewat inject yang masing-masing punya tujuan dan respons yang diharapkan, dan bila detail teknis diperlukan, trusted agent memastikan akurasinya. Lihat bagian 1.3.

</details>

**4. Skenario keputusan.** Untuk `TTX-2026-01`, siapa yang paling tepat menjadi fasilitator?

- A. Dimas, karena ia IC dan paling paham alur insiden.
- B. Nina Kartika, yang paham `JAB-IRP-01` dan tidak memegang peran di CSIRT, dibantu trusted agent teknis dari retainer.
- C. Hendra, supaya peserta serius karena dipimpin direktur.

<details><summary>Jawaban</summary>

B. Fasilitator memimpin diskusi menuju tujuan dan tidak ikut memutuskan, jadi ia tidak boleh pemain yang perannya diuji. A keliru karena keputusan IC termasuk yang dinilai. C keliru karena kehadiran direktur sebagai pemimpin membuat staf cenderung menyesuaikan jawaban, padahal latihan butuh diskusi jujur dalam lingkungan no-fault. Lihat bagian 1.4 dan 1.5.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Hendra Wijaya, dalam tiga kalimat, kenapa hasil `TTX-2026-01` yang banyak "sebagian" justru menunjukkan latihan yang berguna.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Latihan ini dibuat untuk menemukan celah sebelum penyerang menemukannya, jadi setiap 'sebagian' adalah masalah yang ketahuan di ruang rapat, bukan pukul dua pagi saat insiden. Wewenang blokir yang dulu macet di `INC-2026-012` sekarang berjalan lancar, artinya perbaikan kita bekerja, dan lima temuan baru, misalnya grup darurat yang belum berisi Legal dan waktu restore yang belum diketahui, sudah punya pemilik dan tenggat. Kalau semua 'ya', kemungkinan besar latihannya terlalu mudah, dan kita tidak belajar apa-apa."

Kesalahan yang sering muncul:
- Menyebut nama orang sebagai penyebab "sebagian", padahal temuannya ada di runbook, grup, atau playbook.
- Tidak menyebut bahwa setiap temuan sudah punya pemilik dan tenggat.
- Memakai istilah seperti "MSEL" atau "inject" yang tidak dibutuhkan Hendra.

</details>

**6. Pertanyaan jebakan.** "Begitu after-action report latihan ditandatangani, kewajiban latihan tahun ini selesai." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Laporan baru berguna bila improvement plan-nya punya pemilik, tenggat, dan kriteria selesai yang disepakati di after-action meeting, dilacak sampai selesai bersama action item insiden, dan diuji ulang di latihan berikutnya. NIST SP 800-61 Rev. 3 menempatkan perbaikan dari latihan di ID.IM-02, dan auditor akan mencari bukti bahwa plan berubah karena latihan. Lihat bagian 1.6, 1.7, dan 2.5.

</details>

**7. Interview question (English).** "How would you design and run a tabletop exercise for an incident response team?"

<details><summary>Sample answer</summary>

"I start from what we actually need to test, usually weaknesses from our own recent incidents or a plan that just changed, and I get leadership to approve the exercise as part of a programme, not a one-off. I write three to five measurable objectives before anything else, each naming who, what decision, a time limit in scenario time, and the plan section it validates, so the evaluators can score yes, no or partial. The scenario itself stays short; the substance comes from injects grouped into a few modules, each with an expected response and a linked objective, plus contingency injects for the objectives that matter most, and everything labelled as an exercise. The facilitator is someone who isn't a player, supported by a technical trusted agent and separate evaluators. In the room I set ground rules: we test the plan, not people, answer with what you'd really do, don't fight the scenario, and senior people speak last. Straight after, I run a hotwash, then turn it into an after-action report and improvement plan with owners, deadlines and completion criteria, tracked alongside incident action items, and the next exercise tests whether those fixes work. I'm also clear that a tabletop tests decisions and coordination; things like restore times need a technical test."

What makes this answer strong: it ties objectives to real weaknesses and makes them measurable in advance, separates facilitation from play, explains how honest discussion is protected, closes the loop with tracked improvements, and knows the limits of a tabletop.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | NIST SP 800-84: Guide to Test, Training, and Exercise Programs for IT Plans and Capabilities (PDF) | https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-84.pdf | primer | September 2006 (lebih dari 3 tahun, masih final); diakses 2026-10-15 | Tinggi. Bagian 1 (jenis TT&E) dan 4 (tabletop: kebutuhan, desain, lingkup, tujuan, peserta, staf, materi, skenario singkat, pelaksanaan, hotwash, AAR) |
| S2 | FEMA: Homeland Security Exercise and Evaluation Program (HSEEP) Doctrine, revisi 2020 (PDF) | https://www.fema.gov/sites/default/files/2020-04/Homeland-Security-Exercise-and-Evaluation-Program-Doctrine-2020-Revision-2-2-25.pdf | primer | Januari 2020 (lebih dari 3 tahun, revisi terbaru menurut halaman FEMA); diakses 2026-10-15 | Tinggi. Jenis latihan, definisi TTX, lingkungan no-fault, tujuan SMART, MSEL dan jenis entrinya, SitMan, hotwash, AAM, corrective action SMART dan pelacakannya, trusted agent |
| S3 | NIST SP 800-61 Rev. 3 (PDF) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf | primer | April 2025; diakses 2026-10-15 | Tinggi. ID.IM-02: perbaikan dari uji dan latihan, rujukan ke SP 800-84 |
| S4 | NCSC UK: Effective steps to cyber exercise creation | https://www.ncsc.gov.uk/guidance/effective-steps-to-cyber-exercise-creation | primer | versi 1.0, terbit 3 Februari 2020; diakses 2026-10-15 | Tinggi. Sembilan langkah: tujuan dari risiko, endorsement program, format, tim, metrik, skenario, inject, panduan peserta, hotwash dan laporan; label EXERCISE |
| S5 | NCSC UK: Exercise in a Box | https://www.ncsc.gov.uk/information/exercise-in-a-box | primer | halaman tanpa tanggal; diakses 2026-10-15 | Tinggi. Latihan gratis (micro exercise dan tabletop), topik, sasaran pengguna |
| S6 | CISA: CISA Tabletop Exercise Packages | https://www.cisa.gov/resources-tools/services/cisa-tabletop-exercise-packages | primer | halaman tanpa tanggal; diakses 2026-10-15 | Tinggi. Isi paket, skenario siber, template pendukung |
| S7 | Black Hills Information Security: Backdoors & Breaches | https://www.blackhillsinfosec.com/projects/backdoorsandbreaches/ | komunitas (alat praktisi) | diakses 2026-10-15 | Sedang. Mode permainan kooperatif dengan rantai serangan tersembunyi dan kartu deteksi |

**Catatan sumber:** aturan main lima butir di bagian 1.5, aturan skenario dan inject PT JAB di bagian 1.3, dan paket bukti untuk auditor di bagian 1.7 adalah susunan catatan ini dari sumber yang disebut, bukan daftar resmi. HSEEP menempatkan MSEL terutama di latihan berbasis operasi; pemakaiannya sebagai skrip fasilitator tabletop di catatan ini adalah adaptasi. Semua isi PT JAB, termasuk tujuan, waktu, hasil evaluasi, dan improvement plan, adalah contoh fiktif.
