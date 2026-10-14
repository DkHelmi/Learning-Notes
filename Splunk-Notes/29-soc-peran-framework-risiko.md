---
day: 29
title: 'SOC, peran, framework, dan risiko: organisasi dan tier, Analyst/Engineer/Architect, framework industri di Splunk, CIA, dan manajemen risiko dasar'
researched_on: 2026-10-10
versions_checked: 'Splunk Tech Brief "Building a SOC with Splunk" (2017); MITRE "11 Strategies of a World-Class Cybersecurity Operations Center" (Mar 2022); NICE Workforce Framework Components v2.0.0 (Mar 2025); SANS 2026 SOC Survey (liputan 17 Jun 2026); NIST CSF 2.0 (26 Feb 2024); CIS Critical Security Controls v8.1 (Jun 2024); MITRE ATT&CK v19.2 (Agu 2026); ISO/IEC 27001:2022 dan Amd 1:2024; NIST SP 800-30 Rev. 1; FIPS 199; Splunk ES 8.7 (annotations)'
---

# Day 29: SOC, peran, framework, dan risiko

Cakupan: organisasi SOC tipikal dan pembagian tugas Analyst, Engineer, dan Architect; kontrol, standar, dan framework industri yang dipakai SOC beserta cara Splunk mengadopsinya; confidentiality, integrity, availability; dan cara berpikir risiko yang dipakai manajemen.

## Ide inti

Sampai sini catatan ini membahas data dan query: cara Splunk menyimpan log, cara menulis SPL, cara membuat knowledge object, dan cara data model menormalisasi sumber yang berbeda. Query hanya punya nilai kalau ada orang yang menanyakannya dan ada orang yang menindaklanjuti jawabannya. Itulah yang diatur oleh organisasi SOC: siapa yang triage, siapa yang memperbaiki detection, siapa yang memperbaiki desain platform, dan siapa yang berbicara ke manajemen. Framework industri adalah bahasa bersama ketiganya. Analyst berbicara dalam "teknik T1110", auditor dalam "kontrol 8.15", dan direksi dalam "risiko dan dampak". Splunk menjembatani ketiganya secara teknis: detection diberi annotation ATT&CK, CIS, atau NIST, lalu finding membawa label itu sampai ke dashboard dan laporan. Confidentiality, integrity, availability, dan cara berpikir risiko adalah lapisan terakhirnya, karena itulah yang menjelaskan kenapa satu kejadian dianggap serius dan kejadian lain cukup dicatat.

Kamu sudah mengenal tiga lapisan ini dari NOC. Ada tangga eskalasi yang jelas (L1 memantau NMS, L2 menyentuh konfigurasi, teknisi lapangan ke POP), ada kode kategori gangguan baku di sistem tiket yang membuat laporan bulanan bisa dibandingkan antar bulan, dan ada SLA yang menentukan gangguan mana yang dibangunkan tengah malam. Di SOC ketiganya ada dengan nama lain: tier dan peran, framework seperti ATT&CK dan NIST CSF, serta CIA dan penilaian risiko. Batas analogi: di NOC dampak hampir selalu bisa dihitung dalam pelanggan terdampak dan menit layanan mati, sedangkan kerusakan confidentiality bisa tidak terlihat di metrik mana pun dan tetap menjadi skenario terburuk, sehingga prioritas di SOC tidak bisa dibaca dari grafik ketersediaan.

```
Detection menyala
  -> finding masuk antrean (label ATT&CK / CIS / CSF melekat dari annotation)
  -> L1 triage dan disposisi      : tutup dengan bukti, atau eskalasi
  -> L2 investigasi dan mitigasi   : dampak ke confidentiality / integrity / availability
  -> Engineer                      : perbaiki logika detection, data, ambang, jadwal
  -> Architect                     : perbaiki kapasitas, topologi, strategi data dan retensi
  -> SOC lead                      : metrik dan laporan (teknik apa yang kena, kontrol mana lemah,
                                     risiko mana yang naik)
```

Situasi yang dipakai sepanjang Day ini: di PT Jaringan Anak Bangsa (PT JAB, ISP menengah fiktif dengan SOC internal enam analyst L1 tiga shift, dua analyst L2, satu detection engineer, dan satu SOC lead), tiket SOC-2026-0231 baru ditutup. Password spraying ke akun domain berakhir dengan satu login berhasil ke akun layanan `svc_backup` di `JKT-FS01`, dan findingnya baru muncul 25 menit setelah aktivitas dimulai. SOC lead menyiapkan rapat kuartalan dengan manajemen dan auditor internal, lalu menulis ke kamu:

> "Aku butuh dua halaman untuk rapat. Siapa mengerjakan apa setelah tiket ini ditutup, kenapa findingnya telat, dan dengan bahasa apa aku menjelaskan ini ke direksi. Auditor juga menanyakan kontrol logging dan monitoring kita, dan direksi akan bertanya ini risiko sebesar apa."

Pesan itu memuat enam pertanyaan:

1. SOC ini terdiri dari peran apa saja, dan kenapa bukan hanya soal jumlah analyst?
2. Setelah tiket ditutup, siapa yang memperbaiki apa, dan apa bedanya analyst, engineer, dan architect?
3. Ke mana karierku bisa diarahkan, dan dengan kerangka apa pengalamanku dinyatakan?
4. Kenapa laporan ke manajemen dan auditor memakai nama framework, dan framework mana yang relevan?
5. Di mana framework itu terlihat di Splunk, dan bagaimana mencarinya di data?
6. Apa arti "risiko" bagi manajemen, dan apa bedanya dengan risk score di Enterprise Security?

Pertanyaan 1 dijawab di bagian 1.1 dan 1.2, pertanyaan 2 di bagian 1.3 sampai 1.5, pertanyaan 3 di bagian 1.6, pertanyaan 4 di bagian 1.7 dan 1.8, pertanyaan 5 di bagian 1.9, dan pertanyaan 6 di bagian 1.10 dan 1.11. Bagian 2 menjalankan query yang dipakai masing-masing peran untuk menyiapkan jawaban itu.

**Kapan relevan:** saat menyiapkan laporan atau rapat dengan manajemen dan auditor, saat memutuskan ke siapa sebuah masalah diserahkan setelah alert selesai ditriage, saat memberi annotation pada detection, dan saat menjelaskan posisi serta arah pengembangan dirimu di interview.
**Kapan bukan jawaban:** ini bukan panduan menjalankan penilaian risiko formal untuk sertifikasi ISMS, dan bukan pengganti keahlian teknis. Struktur organisasi juga tidak memperbaiki detection yang buruk atau data yang tidak masuk; itu pekerjaan onboarding data dan detection engineering (Day 28 dan 36).

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah Splunk dari Day sebelumnya (index, sourcetype, detection, finding, data model, lookup) tidak diulang di sini. Tabel ini memuat istilah organisasi, framework, dan risiko yang dipakai Day ini; cari kolom padanan bila sebuah istilah terasa jauh dari pekerjaan harian.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| SOC | Fungsi yang memantau, mendeteksi, dan merespons ancaman, terdiri dari people, process, technology | NOC untuk keamanan: ruang, orang, prosedur, dan alat |
| Tier 1 / 2 / 3 | Tingkatan analyst menurut kedalaman pekerjaan dan wewenangnya | Tangga eskalasi L1, L2, teknisi lapangan |
| Tierless (kolaboratif) | Model tanpa tingkatan; analyst menangani kasus dari awal sampai selesai, triage awal dibantu otomasi | Tim kecil serba bisa yang memegang satu gangguan sampai tuntas |
| Analyst | Peran yang berorientasi kejadian: triage, investigasi, disposisi, hunting | Operator NMS yang menilai alarm |
| Engineer | Peran yang berorientasi sistem dan konten: data, parsing, detection, tuning, otomasi | Engineer yang memperbaiki template monitoring dan threshold |
| Architect | Peran yang berorientasi desain: topologi, kapasitas, strategi data, roadmap | Perencana kapasitas jaringan dan desain topologi |
| Threat modeling | Menentukan ancaman yang dipedulikan, jejaknya di data, dan cara mendeteksinya sebelum membuat detection | Menentukan skenario gangguan yang harus terpantau sebelum membeli probe |
| NICE Framework | Kerangka tenaga kerja siber NIST: kategori, work role, competency area, dan pernyataan Task, Knowledge, Skill | Matriks kompetensi teknisi per level |
| Kontrol | Tindakan atau mekanisme yang mengurangi risiko (preventif, detektif, korektif) | Kunci pintu rack, cadangan konfigurasi, alarm |
| Standar | Dokumen persyaratan yang bisa diaudit dan kadang disertifikasi | Standar instalasi yang diperiksa auditor |
| Framework | Struktur untuk mengorganisasi praktik, kontrol, atau pengetahuan; sering sukarela | Kode kategori gangguan baku di sistem tiket |
| NIST CSF 2.0 | Framework fungsi program keamanan: Govern, Identify, Protect, Detect, Respond, Recover | Pembagian besar pekerjaan: rencana, cegah, pantau, tangani, pulihkan |
| CIS Controls | Daftar kontrol keamanan yang diprioritaskan (v8.1, 18 kontrol) | Checklist pengerasan perangkat yang diurutkan dari paling berdampak |
| ISO/IEC 27001 | Standar persyaratan sistem manajemen keamanan informasi (ISMS) yang bisa disertifikasi | Standar mutu yang diaudit pihak ketiga |
| MITRE ATT&CK | Basis pengetahuan taktik (tujuan) dan teknik (cara) penyerang dari observasi nyata | Katalog pola gangguan yang pernah benar-benar terjadi |
| Cyber Kill Chain | Model tujuh fase intrusi dari Lockheed Martin | Urutan baku penyebab gangguan dari awal sampai dampak |
| Annotation (ES) | Label framework pada detection yang ikut muncul di finding dan dashboard risiko | Kode kategori yang ditempel ke tiket agar bisa direkap |
| Confidentiality, integrity, availability (CIA) | Tiga sifat informasi yang dilindungi: tidak terungkap, tidak berubah, tetap tersedia | SLA kerahasiaan data pelanggan, keutuhan konfigurasi, uptime layanan |
| Information assurance | Keyakinan bahwa informasi tetap C, I, A, ditambah authenticity dan non-repudiation | Jejak audit yang membuat perubahan konfigurasi tidak bisa disangkal |
| Threat dan vulnerability | Peristiwa yang berpotensi merugikan, dan kelemahan yang bisa dieksploitasi | Skenario gangguan, dan titik tunggal kegagalan di jaringan |
| Likelihood dan impact | Kemungkinan peristiwa terjadi dan besarnya kerugian bila terjadi | Frekuensi gangguan dan jumlah pelanggan terdampak |
| Inherent dan residual risk | Risiko sebelum kontrol, dan sisa risiko setelah kontrol | Risiko link tunggal, dan sisa risiko setelah ada link cadangan |
| Risk appetite | Batas risiko yang bersedia diterima organisasi | Target SLA yang disepakati manajemen |
| Risk score (RBA) | Akumulasi sinyal perilaku per entity di ES, bukan penilaian risiko organisasi | Skor reputasi per host yang naik setiap ada sinyal kecil |

### 1.1 SOC sebagai people, process, technology

SOC lead meminta "dua halaman", dan godaan pertama adalah menulis daftar alat. Pertanyaan yang lebih berguna: apa yang membuat SOC bekerja selain alatnya?

Tech brief Splunk tentang membangun SOC menekankan bahwa SOC butuh investasi pada process, people, dan technology [S1]:

- Process dimulai dari threat modeling: ancaman apa yang dipedulikan organisasi, seperti apa jejaknya di data, bagaimana mendeteksi atau memblokirnya, dan playbook apa untuk tiap jenis ancaman [S1].
- **People:** personel beragam dengan jalur promosi yang jelas antar tier dan pelatihan berkelanjutan [S1].
- **Technology:** platform analitik keamanan yang mengindeks data mesin dari berbagai sumber dan memperkayanya dengan konteks (AD, database aset, threat feed). Ditambah ticketing dan alat IR lanjutan (packet capture, disk forensics, reverse engineering) untuk tier atas [S1].

MITRE "11 Strategies of a World-Class Cybersecurity Operations Center" (edisi 2022) merumuskan strategi yang sejalan [S2]:

- tahu apa yang dilindungi dan kenapa;
- beri SOC otoritas;
- bangun struktur SOC sesuai kebutuhan organisasi (tiered atau tierless, terpusat atau terdistribusi, outsourcing);
- rekrut dan kembangkan staf berkualitas;
- prioritaskan respons insiden;
- CTI;
- pilih dan kumpulkan data yang tepat;
- alat yang mendukung alur kerja analyst;
- komunikasi dan kolaborasi;
- ukur kinerja;
- perluas fungsi SOC.

Dibaca untuk kasus SOC-2026-0231, dua strategi langsung menonjol: alat yang mendukung alur kerja analyst (finding yang telat 25 menit berarti alur kerjanya tidak didukung) dan ukur kinerja (tanpa metrik, keterlambatan itu tidak pernah terlihat di rapat).

### 1.2 Model tier dan tanpa tier

PT JAB memakai tiga shift L1 dan dua analyst L2, jadi pertanyaannya bukan "tier itu apa", tetapi kenapa pembagian itu ada dan kapan sebaiknya tidak dipakai.

Tabel berikut adalah contoh tiga tier dari tech brief Splunk; cari perbedaan wewenang dan kedalaman, bukan perbedaan senioritas semata.

| Tier | Fokus | Contoh tugas |
|---|---|---|
| Tier 1 | Monitoring dan triage | Memantau alert, membuka tiket, menutup false positive, investigasi dan mitigasi dasar |
| Tier 2 | Investigasi mendalam | Menginvestigasi eskalasi, mitigasi, merekomendasikan perubahan |
| Tier 3 | Investigasi lanjutan dan proaktif | Investigasi lanjutan, pencegahan, threat hunting, forensik, counter-intelligence, reverse engineering malware |

Alert datang dari platform analitik, help desk, atau departemen TI lain. Kasus yang tidak terselesaikan dieskalasi ke tier berikutnya [S1].

**Tierless atau kolaboratif:** MITRE membahas pilihan antara model tier dan tanpa tier sesuai kebutuhan organisasi [S2]. Model tanpa tier biasanya mengandalkan otomasi (SOAR) untuk triage awal, dan analyst menangani kasus dari awal sampai selesai. Tidak ada satu model yang selalu benar. Pilihan lain yang sama pentingnya dan juga dibahas MITRE adalah terpusat atau terdistribusi, jam operasi 8x5 atau 24x7, dan bagian mana yang di-outsource [S1][S2]. Strategi MITRE tentang membangun struktur SOC sesuai kebutuhan organisasi ini juga menjadi tema pembahasan praktisi [S6].

### 1.3 Analyst, engineer, architect

Finding SOC-2026-0231 telat 25 menit. Siapa yang memperbaikinya? Jawabannya tidak ada di tier, karena tier memisahkan kedalaman investigasi, bukan jenis pekerjaan.

Contoh struktur personel dari Splunk: SOC Director membawahi SOC Architect, Tier 1/2/3 Analyst, Forensics Specialist, dan Malware Engineer [S1]. Tabel berikut memisahkan tiga peran menurut pertanyaan utamanya; perhatikan kolom pertama, karena itulah yang membedakan mereka saat satu kasus selesai.

| Peran | Pertanyaan utama | Tugas khas | Dalam konteks Splunk dan ES |
|---|---|---|---|
| Analyst | "Apa yang terjadi, dan apa yang harus dilakukan?" | Triage, investigasi, eskalasi, disposisi, dokumentasi kasus, hunting (tier atas) | Bekerja di analyst queue (Incident Review di ES 7), menjalankan search dan pivot, memakai dashboard investigasi, menulis catatan kasus |
| Engineer | "Apakah tools dan data bekerja dengan benar?" | Onboarding data, parsing dan normalisasi, membuat dan tuning detection, integrasi, otomasi, kesehatan platform | TA dan CIM (Day 23), akselerasi (Day 26), detection dan filter macro (Day 45 dan 36), Asset & Identity, adaptive response dan SOAR (Day 41 dan 42), skipped searches |
| Architect | "Bagaimana sistem keamanan ini dirancang agar memenuhi kebutuhan sekarang dan nanti?" | Desain arsitektur, skala dan ketersediaan, strategi data dan retensi, pemilihan teknologi, standar, roadmap | Topologi (indexer dan search head cluster), kapasitas, strategi index dan data model, integrasi lintas produk, kebijakan retensi |

Sumber praktisi (2020, lebih dari 3 tahun) membedakan engineer dan architect sebagai pihak yang bertanggung jawab atas arsitektur keamanan secara keseluruhan dan memastikan keamanan menjadi bagian siklus pengembangan, sedangkan analyst berfokus pada mengidentifikasi kerentanan dan menilai ancaman yang ada [S3].

Garis batas di dunia nyata kabur. Di SOC kecil, satu orang bisa menjadi analyst dan engineer sekaligus, dan di PT JAB detection engineernya hanya satu orang. Pegang orientasinya: analyst mengurus kejadian, engineer mengurus sistem dan konten, architect mengurus desain.

### 1.4 Satu kasus dilihat dari tiga peran

Bagian ini menelusuri SOC-2026-0231 dari awal sampai ke rapat kuartalan, supaya pembagian peran di bagian 1.3 terlihat sebagai urutan kerja, bukan daftar jabatan. Angkanya ilustrasi untuk organisasi fiktif ini. Detection password spraying memunculkan finding untuk `JKT-FS01` pada pukul 02.10.

- **Analyst (tier 1):** membuka finding, melihat 40 akun gagal login dari satu `src` dalam 6 menit, lalu memeriksa apakah ada login berhasil setelahnya. Ada satu login berhasil ke akun layanan `svc_backup`. Kasus dieskalasi ke tier 2 dengan catatan timeline dan query yang dipakai.
- **Analyst (tier 2):** memastikan `JKT-FS01` menjalankan proses tidak biasa setelah login itu, mengisolasi host lewat EDR sesuai playbook, dan meminta reset kredensial `svc_backup`. Disposisinya true positive.
- **Engineer:** saat review pasca-insiden, menemukan bahwa finding baru muncul 25 menit setelah aktivitas dimulai karena search terjadwal sering skipped (bagian 2.2). Ia memindahkan jadwal search, menambah filter untuk akun layanan yang memang berisik, dan menambah detection kedua untuk login berhasil setelah rangkaian gagal.
- **Architect:** melihat bahwa skipped search terjadi karena search head ES kehabisan slot konkurensi pada jam backup. Rekomendasinya: kapasitas scheduler ditambah dan akselerasi data model dipindah ke jam yang lebih sepi, masuk roadmap kuartal berikutnya.
- **SOC lead:** membawa tiga hal ke rapat: teknik yang dipakai penyerang dengan nama framework (bagian 1.8), kontrol mana yang terbukti lemah, dan keterlambatan deteksi sebagai angka yang bisa diperbaiki.

Pola ini yang perlu kamu tunjukkan di interview: analyst menutup kejadian, engineer memperbaiki konten dan data yang membuat kejadian terlambat terlihat, architect memperbaiki desain yang membuat masalah itu bisa terjadi.

### 1.5 Fungsi pendukung dan pimpinan SOC

Di sekitar antrean alert ada fungsi yang bukan triage tetapi menentukan kualitas triage. Di PT JAB sebagian fungsi ini belum ada orangnya dan dikerjakan rangkap.

- **Threat intelligence (CTI):** memberi konteks dan prioritas (Day 30).
- **Threat hunting:** proaktif; sering tier 3 atau tim khusus (Day 38 dan 39).
- **Forensik dan malware analysis:** dukungan IR mendalam [S1].
- **Detection engineering:** peran yang makin dikenal sebagai fungsi tersendiri. Survei SANS bersama Anvilogic 2026 tentang detection engineering menunjukkan banyak praktisi merasa hanya mampu mengikuti atau tertinggal dari perkembangan ancaman [S7] `[sekunder]`.
- **SOC manager atau director:** operasi, staf, metrik, dan komunikasi ke manajemen [S1][S3].

### 1.6 Memetakan diri: NICE dan keadaan pasar

Pertanyaan ketiga SOC lead sebenarnya pertanyaan karier: dengan kerangka apa pengalaman dinyatakan supaya dipahami manajer perekrut dan HR.

NICE Workforce Framework for Cybersecurity (NIST) memakai Work Role Categories, Work Roles, Competency Areas, dan pernyataan Task, Knowledge, Skill (TKS). Pembaruan komponen v2.0.0 dirilis Maret 2025 [S4]. Work role seperti *Defensive Cybersecurity* dan *Incident Response* berada di kategori perlindungan dan pertahanan [S4], cek nama kategori dan work role persis di v2.0.0. Kerangka ini berguna untuk menulis CV dan rencana pengembangan karier, karena tugasmu bisa dipetakan ke TKS yang baku.

Sisi permintaannya terlihat dari SANS 2026 SOC Survey (444 praktisi dan 69 CISO atau eksekutif; liputan 17 Jun 2026) [S5]:

- SIEM adalah keterampilan yang paling dicari saat merekrut, hampir dua kali lipat EDR.
- 79% memakai alat AI atau ML, tetapi hanya 36% yang sudah memasukkannya ke alur kerja SOC yang terdefinisi.
- Ada kesenjangan persepsi soal staffing: 59% pemimpin berbanding 32% praktisi merasa manajemen memperhatikan kebutuhan SOC.
- Kurang dari 45% memantau aset OT atau IoT lewat SOC.

Penilaian untukmu: kombinasi SIEM (Splunk), forensik, dan kemampuan engineering konten adalah profil yang dicari pasar. Kesenjangan persepsi staffing juga menjelaskan kenapa laporan seperti yang diminta SOC lead penting: tanpa angka, kebutuhan SOC terdengar seperti keluhan.

### 1.7 Kontrol, standar, dan framework

Auditor internal menanyakan "kontrol logging dan monitoring", direksi menanyakan "risiko", dan detection di Splunk diberi label "T1110". Tiga kata itu berasal dari tiga jenis dokumen yang sering dicampur.

Tabel ini memisahkan ketiganya; cari kolom contoh untuk menguji apakah kamu bisa menempatkan dokumen yang kamu pakai sehari-hari.

| Istilah | Arti | Contoh |
|---|---|---|
| Kontrol | Tindakan atau mekanisme yang mengurangi risiko (preventif, detektif, korektif) | MFA, logging terpusat, backup, EDR |
| Standar | Dokumen persyaratan atau spesifikasi yang bisa diaudit | ISO/IEC 27001 (persyaratan ISMS, bisa disertifikasi), PCI DSS |
| Framework | Struktur untuk mengorganisasi praktik, kontrol, atau pengetahuan; sering sukarela | NIST CSF 2.0, CIS Controls, MITRE ATT&CK, Cyber Kill Chain |

Garisnya tidak selalu tajam. CIS Controls disebut "controls" tetapi berfungsi sebagai framework kontrol yang diprioritaskan.

### 1.8 Framework utama dan perannya di SOC

Untuk rapat kuartalan PT JAB, cukup lima nama berikut beserta keadaannya pada 2026.

- NIST CSF 2.0 (26 Feb 2024): enam fungsi, yaitu Govern (baru), Identify, Protect, Detect, Respond, Recover. Berlaku untuk semua organisasi, tidak hanya infrastruktur kritis [S8].
- CIS Critical Security Controls v8.1 (Juni 2024): pembaruan iteratif dari v8.0. Glosarium diperluas, kelas aset direvisi (menambah tipe aset *Documentation*), dan pemetaan fungsi keamanan diselaraskan dengan NIST CSF 2.0. Sampai Oktober 2026 belum ada v9 yang dirilis; cek situs CIS bila membaca catatan ini jauh setelahnya [S9].
- ISO/IEC 27001:2022 dan Amd 1:2024: standar persyaratan sistem manajemen keamanan informasi (ISMS) yang bisa disertifikasi [S14]. Klausul 4 sampai 10 berisi persyaratan sistem manajemen (konteks, kepemimpinan, perencanaan risiko, dukungan, operasi, evaluasi kinerja, perbaikan). Annex A memuat 93 kontrol dalam empat tema: organizational (37), people (8), physical (14), dan technological (34). Kontrol yang paling dekat dengan pekerjaan SOC ada di tema technological, misalnya 8.15 Logging, 8.16 Monitoring activities, dan 5.25 sampai 5.26 untuk penilaian dan respons insiden di tema organizational. Amd 1:2024 hanya menambahkan pertimbangan perubahan iklim di klausul konteks, tanpa mengubah kontrol. Dua nomor pertama itu yang dicari auditor PT JAB saat menanyakan logging dan monitoring.
- MITRE ATT&CK (v19.2, Agustus 2026): basis pengetahuan taktik (tujuan, misalnya Privilege Escalation, Command and Control) dan teknik (cara, misalnya Kerberoasting) berdasarkan observasi dunia nyata [S10][S11]. Sejak v18, deteksi dipetakan lewat Detection Strategies dan Analytics (Day 21).
- **Lockheed Martin Cyber Kill Chain:** tujuh fase intrusi, yaitu Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command & Control, Actions on Objectives. Ini model linear lama yang tetap dipakai sebagai annotation di ES [S10], cek penulisan nama fase di lookup annotation ES.

**Peran framework untuk SOC:** ATT&CK dan Kill Chain menjelaskan perilaku penyerang (tactical). CSF, CIS, dan ISO menjelaskan program pertahanan (strategis dan kontrol). Detection bisa dipetakan ke keduanya. Password spraying di SOC-2026-0231, misalnya, berkaitan dengan teknik ATT&CK tertentu dan sekaligus dengan fungsi CSF *Detect* serta kontrol logging dan monitoring yang ditanyakan auditor.

### 1.9 Bagaimana Splunk memakai framework

Label framework tidak berguna kalau hanya ada di slide. Di ES ia menjadi field yang bisa dicari, sehingga pertanyaan rapat "teknik apa yang paling sering kita lihat" bisa dijawab dari data (bagian 2.4).

Annotations di ES 8.7 [S10]:

- Framework managed bawaan: MITRE ATT&CK, CIS Critical Security Controls, NIST Cybersecurity Framework, Lockheed Martin Cyber Kill Chain, ditambah kontrol tata kelola PCI DSS 4.0.
- **Unmanaged annotations:** kustom, tanpa pengayaan standar industri.
- Definisi ATT&CK diisi di `security_framework_annotations.csv`.
- Annotation disimpan di `savedsearches.conf` dalam format JSON pada `action.correlationsearch.annotations`.
- Field hasil berpola `annotations.<framework>.<field>`, misalnya `annotations.mitre_attack.mitre_technique_id` dan `annotations.mitre_attack.mitre_tactic`.
- UI: Configure > Content management, pilih detection, lalu buka bagian Annotations (tombol + Framework untuk framework kustom).
- Annotation tampil sebagai label di Mission Control dan dashboard Risk Analysis, dan bisa dicari lewat `index=risk`.
- Framework kustom butuh intelligence download, lookup definition, dan automatic lookup. Bisa dikloning dari konfigurasi ATT&CK [S10].

Detail annotation di alur kerja Mission Control dibahas di Day 33. Di luar ES, pemetaan yang sama muncul di tempat lain: Splunk Security Essentials memetakan konten ke ATT&CK dan Kill Chain serta menyediakan dashboard ATT&CK dan Benchmark (Day 45 dan 27), setiap detection di research.splunk.com dan ESCU memuat mapping ATT&CK dan sering juga Kill Chain, CIS, dan NIST (Day 45), dan Splunk App for PCI Compliance memakai CIM yang sama (Day 23).

**Tanpa ES:** peran SOC tidak bergantung produk, dan pemetaan framework di level SPL bisa dilakukan di Splunk Enterprise biasa dengan lookup dan `eval`. Yang hilang adalah annotation terkelola, tampilannya di finding dan dashboard risiko, serta pemetaan ATT&CK di Detection Studio (Day 27) [S10]. Di ES, pemisahan peran juga terlihat dari role dan capability (misalnya role analyst ES dibanding admin ES); cek nama role bawaan ES 8.x (`ess_analyst`, `ess_admin`, dan sejenisnya) di dokumentasi ES 8.7.

### 1.10 CIA dan information assurance

Direksi PT JAB akan menanyakan "ini seberapa serius". Jawabannya tidak dimulai dari nama teknik, tetapi dari sifat informasi apa yang terancam.

Definisi FIPS 199 (FISMA) [S12]:

- **Confidentiality:** mempertahankan pembatasan akses dan pengungkapan informasi yang sah, termasuk melindungi privasi dan informasi proprietary. Pelanggarannya: pengungkapan tanpa izin.
- **Integrity:** menjaga dari modifikasi atau perusakan informasi yang tidak semestinya, termasuk menjamin non-repudiation dan authenticity. Pelanggarannya: modifikasi atau perusakan tanpa izin.
- **Availability:** menjamin akses dan penggunaan informasi yang tepat waktu dan andal. Pelanggarannya: gangguan akses atau penggunaan.

FIPS 199 menilai dampak hilangnya C, I, atau A sebagai low (terbatas), moderate (serius), atau high (parah atau katastrofik) [S12].

Tabel berikut menghubungkan jenis insiden ke pilar yang rusak dan ke sinyal yang bisa dicari di Splunk; cari kolom terakhir saat kamu harus membuktikan dampak, bukan hanya menyebutnya.

| Insiden | Pilar utama yang rusak | Sinyal di Splunk |
|---|---|---|
| Exfiltration data pelanggan | Confidentiality | Volume keluar besar (Network_Traffic atau Web), akses massal (Data_Access) |
| Defacement portal pelanggan | Integrity | Perubahan file web (Endpoint.Filesystem), upload POST (Web) |
| Ransomware | Availability (dan sering Confidentiality bila double extortion) | Banyak file dimodifikasi, proses mencurigakan (Endpoint), shadow copy dihapus |
| DDoS | Availability | Lonjakan koneksi (Network_Traffic), error layanan (Web status 5xx) |
| Log dihapus penyerang | Integrity (dan akuntabilitas) | Event 1102 "The audit log was cleared" di log Security, sumber berhenti mengirim (Day 21) |

Information assurance lebih luas dari keamanan teknis. Ia mencakup kepercayaan bahwa informasi tetap C, I, A, ditambah authenticity (benar dari sumber yang diklaim) dan non-repudiation (pelaku tidak bisa menyangkal tindakannya). Bagi SOC, logging yang lengkap dan terlindungi adalah kontrol non-repudiation yang nyata, dan itu alasan teknis kenapa penghapusan log diperlakukan sebagai temuan serius.

### 1.11 Cara berpikir risiko

Pertanyaan terakhir SOC lead memakai kata yang paling sering disalahpahami di SOC. "Risiko" di rapat manajemen bukan skor di dashboard ES.

Konsep dari NIST SP 800-30 Rev. 1 [S13]:

- **Threat:** keadaan atau peristiwa yang berpotensi berdampak buruk.
- **Vulnerability:** kelemahan pada sistem, prosedur, atau implementasi kontrol yang bisa dieksploitasi sumber ancaman.
- **Likelihood:** kemungkinan peristiwa ancaman terjadi dan menimbulkan dampak (memperhitungkan kemampuan, niat, dan penargetan adversary, serta kerentanan).
- **Impact:** besarnya kerugian (operasi, aset, individu, finansial, legal, reputasi).
- **Risk:** fungsi dari likelihood dan impact.

**Siklus manajemen risiko (umum):** identifikasi, analisis atau penilaian (likelihood dikali impact), evaluasi terhadap risk appetite, penanganan, lalu pemantauan dan tinjauan. Siklus ini berulang.

Tabel ini memuat empat opsi penanganan yang dipakai manajemen; cari kolom contoh untuk melihat bagian mana yang benar-benar pekerjaan SOC.

| Opsi | Arti | Contoh SOC |
|---|---|---|
| Mitigate atau modify | Mengurangi likelihood atau impact dengan kontrol | Tambah detection, MFA, segmentasi |
| Transfer atau share | Memindahkan sebagian ke pihak lain | Asuransi siber, MSSP |
| Avoid | Menghentikan aktivitas berisiko | Mematikan layanan yang tidak perlu |
| Accept atau retain | Menerima secara sadar dan terdokumentasi | Risiko rendah di aset non-kritis |

Inherent risk adalah risiko sebelum kontrol; residual risk adalah sisa setelah kontrol. Risiko tidak pernah nol, dan keputusan menerima residual risk adalah keputusan manajemen, bukan SOC. Untuk SOC-2026-0231, bahasa yang tepat di rapat bukan "akun `svc_backup` berhasil ditembus", tetapi "kontrol deteksi kita bekerja tetapi terlambat, sehingga residual risk untuk skenario pencurian kredensial akun layanan masih di atas yang kita kira".

**Kaitan dengan ES:** Risk-Based Alerting (Day 35) memakai konsep yang mirip tetapi berbeda. Skor risiko diberikan ke entity berdasarkan perilaku yang diamati, dan itu bukan penilaian risiko organisasi ala SP 800-30. Jangan mencampur istilahnya saat berbicara dengan manajemen: "risk" di RBA berarti akumulasi sinyal per entity.

## 2. Contoh SPL dan langkah di ES

> Keluaran di bawah adalah keluaran ilustrasi untuk PT JAB. Query ini menggambarkan jenis pertanyaan yang diajukan tiap peran saat menyiapkan rapat kuartalan.

### 2.1 Pertanyaan analyst lead dan manager: beban antrean

**Tujuan:** melihat distribusi finding per status, pemilik, dan urgensi, sebagai dasar menyeimbangkan beban tiga shift L1. ES 7.x menyimpan notable di index `notable` dan menyediakan macro `` `notable` ``:

```
`notable`
| stats count BY status_label owner urgency
| sort - count
```

- `` `notable` `` adalah macro bawaan ES yang mengambil notable event beserta field hasil pengayaannya, jadi kamu tidak perlu menulis nama index dan filter versinya sendiri.
- `stats count BY status_label owner urgency` menghasilkan satu baris per kombinasi status, pemilik, dan urgensi.
- `sort - count` menaruh kombinasi terbesar di atas, yang biasanya adalah tumpukan pekerjaan yang belum dipegang siapa pun.

Keluaran ilustrasi:

| status_label | owner | urgency | count |
|---|---|---|---|
| New | unassigned | medium | 23 |
| Resolved | fitri.handayani | medium | 11 |
| New | unassigned | high | 7 |
| In Progress | budi.santoso | medium | 5 |
| In Progress | andi.pratama | high | 3 |

- **Cara membaca hasil:** 7 finding urgency high yang belum punya owner adalah masalah yang lebih mendesak daripada 23 finding medium, karena antrean medium bisa dikerjakan bergiliran sedangkan high yang menganggur berarti tidak ada yang menilai kasus terpenting. Bandingkan juga jumlah per owner: beban yang menumpuk di satu nama biasanya tanda pembagian shift yang tidak jalan, bukan tanda orang itu rajin.
- **Variasi:** tambahkan `BY` pada nama detection untuk melihat detection mana yang mengisi antrean, atau ganti `count` menjadi `dc(...)` pada field entity untuk membedakan 23 finding dari 23 host dan 23 finding dari 2 host.
- **Kapan gagal:** di ES 8.x finding dan investigation dikelola di analyst queue (Mission Control), sehingga index, macro, dan nama field bisa berbeda (Day 31, 32, dan 34). Tanpa hak akses ke index ES, query ini tidak mengembalikan apa pun.

### 2.2 Pertanyaan engineer: apakah detection berjalan sehat?

**Tujuan:** menjawab kenapa finding SOC-2026-0231 telat 25 menit, dengan melihat eksekusi scheduled search yang tidak jalan.

```
index=_internal sourcetype=scheduler (status=skipped OR status=continued) earliest=-24h
| stats count BY app savedsearch_name status reason
| sort - count
```

- `sourcetype=scheduler` di `_internal` mencatat eksekusi scheduled search, termasuk yang gagal dijalankan.
- `status=skipped` berarti search tidak dijalankan sama sekali, misalnya karena batas konkurensi; `status=continued` berarti eksekusinya ditunda. Detection yang terlewat berarti buta pada periode itu.
- `reason` memuat alasan yang dilaporkan scheduler, dan inilah kolom yang menentukan apakah perbaikannya ada di jadwal, di query, atau di kapasitas.

Keluaran ilustrasi:

| app | savedsearch_name | status | reason | count |
|---|---|---|---|---|
| SplunkEnterpriseSecuritySuite | Brute Force Access Behavior Detected | skipped | maximum concurrent scheduled searches reached | 46 |
| SplunkEnterpriseSecuritySuite | Short Lived Domain Account | skipped | maximum concurrent scheduled searches reached | 31 |
| search | JAB - Login berhasil setelah rangkaian gagal | continued | search lagged behind schedule | 12 |

- **Cara membaca hasil:** 46 eksekusi yang dilewati dalam 24 jam pada detection brute force berarti ada jam-jam tanpa deteksi sama sekali, dan itu penjelasan langsung keterlambatan 25 menit di bagian 1.4. Search yang sering skipped perlu dioptimalkan (Day 14) atau dijadwal ulang; ini tugas engineer, bukan analyst.
- **Variasi:** tambahkan `| timechart span=1h count BY savedsearch_name` untuk melihat jam mana yang paling padat, yang biasanya berbarengan dengan jadwal backup atau akselerasi data model.
- **Kapan gagal:** nilai `status` dan isi field `reason` bergantung versi, jadi cek di versi-mu. Tanpa hak akses ke `_internal`, query ini kosong meskipun masalahnya ada.

### 2.3 Pertanyaan architect: pertumbuhan data dan kapasitas

**Tujuan:** melihat tren ingest per index sebagai dasar perencanaan kapasitas, retensi, dan biaya.

```
index=_internal source=*license_usage.log* type=Usage earliest=-30d
| eval GB=b/1024/1024/1024
| timechart span=1d sum(GB) AS daily_GB BY idx limit=10
```

- `license_usage.log` dengan `type=Usage` mencatat volume data yang diindeks per index.
- `b` adalah jumlah byte; `eval GB=b/1024/1024/1024` mengubahnya menjadi gigabyte.
- `timechart span=1d ... BY idx limit=10` memberi satu kolom per index untuk sepuluh index terbesar, sisanya digabung.

Keluaran ilustrasi untuk satu hari (kolom `daily_GB` per index): `dns` 42,3; `firewall` 18,1; `wineventlog` 12,6; `proxy` 9,4; `sysmon` 6,2; `o365` 2,1; `linux` 1,8; `netops` 1,5. Totalnya 94,0 GB per hari.

- **Cara membaca hasil:** pada profil ini `dns` sendiri hampir setengah volume, jadi keputusan sampling dan retensi DNS berdampak jauh lebih besar daripada mengurangi index lain. Untuk proyeksi kasar, 94 GB per hari selama 90 hari berarti sekitar 8,5 TB data mentah sebelum kompresi, dan angka itulah yang dibawa architect ke diskusi disk dan retensi.
- **Variasi:** ganti `BY idx` menjadi `BY st` untuk melihat sourcetype yang paling boros, atau hilangkan `BY` untuk tren total yang lebih mudah dibaca di slide.
- **Kapan gagal:** nama field (`b`, `idx`) dan lokasi log lisensi berbeda antar deployment, biasanya ada di license manager, jadi cek di deployment-mu.

### 2.4 Cakupan taktik dan teknik dari risk index (ES)

**Tujuan:** menjawab pertanyaan rapat "teknik apa yang paling sering kita lihat" dengan data, bukan kesan.

```
index=risk earliest=-30d
| stats count dc(risk_object) AS entities BY annotations.mitre_attack.mitre_tactic annotations.mitre_attack.mitre_technique_id
| sort - count
```

- `index=risk` memuat risk event (intermediate finding) yang dihasilkan detection ber-RBA.
- Field `annotations.mitre_attack.*` berasal dari annotation detection (bagian 1.9), jadi kualitas hasil query ini sama dengan kualitas annotation yang diisi engineer.
- `dc(risk_object)` menghitung jumlah entity berbeda, sehingga 300 risk event pada 2 host tidak terbaca sama dengan 300 risk event pada 50 host.

Keluaran ilustrasi:

| mitre_tactic | mitre_technique_id | count | entities |
|---|---|---|---|
| Credential Access | T1110 | 312 | 48 |
| Defense Evasion | T1078 | 156 | 23 |
| Execution | T1059.001 | 88 | 19 |
| Impact | T1490 | 4 | 2 |

- **Cara membaca hasil:** teknik yang dominan menunjukkan apa yang paling sering dilihat detection-mu, bukan cakupan deteksimu. T1110 di puncak konsisten dengan kasus SOC-2026-0231, sedangkan angka kecil pada T1490 bisa berarti dua hal yang sangat berbeda: jarang terjadi, atau hanya ada satu detection yang memantaunya. Cakupan dilihat di Detection Studio (Day 27).
- **Variasi:** tambahkan `| sort - entities` untuk melihat teknik yang menyebar ke paling banyak entity, yang biasanya lebih menarik untuk rapat daripada teknik dengan event terbanyak.
- **Kapan gagal:** `risk_object` adalah nama field klasik di risk index; cek nama field di ES 8.7, karena UI menyebutnya "entity". Detection tanpa annotation tidak akan muncul sama sekali di hasil.

### 2.5 Peta detection ke framework lewat REST (ES)

**Tujuan:** membuat tabel detection beserta label frameworknya, untuk lampiran laporan ke auditor.

```
| rest /servicesNS/-/-/saved/searches splunk_server=local count=0
| search action.correlationsearch.enabled=1
| table title action.correlationsearch.annotations
| spath input=action.correlationsearch.annotations
| table title mitre_attack{} cis20{} nist{} kill_chain_phases{}
```

- `| rest ...` membaca konfigurasi saved search langsung dari endpoint REST, jadi hasilnya konfigurasi, bukan event.
- `action.correlationsearch.enabled=1` menyaring detection yang aktif; ini atribut ES klasik, cek di ES 8.
- Annotation disimpan sebagai JSON di `action.correlationsearch.annotations` [S10], dan `spath` mengurai JSON itu menjadi field. Notasi `{}` mengambil seluruh nilai pada array, jadi satu detection dengan tiga teknik tetap terbaca.

Keluaran ilustrasi:

| title | mitre_attack{} | cis20{} | nist{} | kill_chain_phases{} |
|---|---|---|---|---|
| Brute Force Access Behavior Detected | T1110 | CIS 6 | DE.CM | Exploitation |
| JAB - Login berhasil setelah rangkaian gagal | T1078 T1110 | CIS 6 | DE.AE | Exploitation |

- **Cara membaca hasil:** detection dengan kolom framework kosong adalah pekerjaan engineer yang belum selesai, dan di laporan audit ia tampak seperti kontrol yang tidak bisa dibuktikan. Satu detection boleh punya lebih dari satu teknik.
- **Variasi:** tambahkan `| where isnull('mitre_attack{}')` untuk mendapat daftar kerja detection tanpa annotation.
- **Kapan gagal:** nama key framework (`mitre_attack`, `cis20`, `nist`, `kill_chain_phases`) perlu dicek di instance ES-mu dengan melihat isi JSON mentahnya lebih dulu, karena nama key inilah yang menentukan apakah `table` di akhir menghasilkan kolom atau kosong.

### 2.6 Matriks risiko sederhana dengan makeresults (latihan konsep)

**Tujuan:** melatih cara menyusun prioritas risiko yang bisa dijelaskan ke manajemen, tanpa perlu data nyata.

```
| makeresults format=csv data="risk,likelihood,impact
Ransomware di JKT-FS01,4,5
Phishing kredensial eksekutif,4,4
Laptop lab tanpa patch,3,1
DDoS portal pelanggan,2,2"
| eval score=likelihood*impact
| eval level=case(score>=15,"high", score>=8,"medium", true(),"low")
| eval treatment=case(level=="high","mitigate", level=="medium","mitigate/transfer", true(),"accept (dokumentasikan)")
| sort - score
```

- `makeresults format=csv` membuat event sintetis dari data inline, jadi tidak ada index yang disentuh.
- `score=likelihood*impact` adalah perkalian skala 1 sampai 5, dan `case` menerjemahkan skor menjadi level lalu menjadi opsi penanganan dari bagian 1.11.
- Skala 1 sampai 5 dan ambangnya adalah asumsi latihan, bukan standar.

Keluaran ilustrasi:

| risk | likelihood | impact | score | level | treatment |
|---|---|---|---|---|---|
| Ransomware di JKT-FS01 | 4 | 5 | 20 | high | mitigate |
| Phishing kredensial eksekutif | 4 | 4 | 16 | high | mitigate |
| DDoS portal pelanggan | 2 | 2 | 4 | low | accept (dokumentasikan) |
| Laptop lab tanpa patch | 3 | 1 | 3 | low | accept (dokumentasikan) |

- **Cara membaca hasil:** ini cara cepat menjelaskan prioritas ke manajemen, dan nilainya ada pada urutannya, bukan pada angkanya. Hubungkan setiap risiko "high" dengan detection dan data yang dibutuhkan (Day 21 dan 27), supaya diskusi berhenti menjadi daftar kekhawatiran dan menjadi daftar pekerjaan.
- **Variasi:** tambahkan kolom `residual_likelihood` setelah kontrol yang sudah ada, lalu bandingkan skor inherent dan residual di satu tabel.
- **Kapan gagal:** matriks menjadi tidak berguna begitu semua baris diberi nilai 4 atau 5. Kriteria likelihood dan impact harus ditulis lebih dulu, kalau tidak hasilnya hanya mencerminkan siapa yang paling keras bersuara.

### 2.7 Di ES (generik)

Langkah di UI yang dipakai tiap peran, ditulis generik karena nama menu bergeser antar versi:

- **Analyst:** analyst queue, investigation, catatan (note), disposisi.
- **Engineer:** content management, Detection Studio (Day 27), konfigurasi Asset & Identity dan data model. Untuk annotation: Configure > Content management, pilih detection, buka Annotations, lalu tambahkan teknik ATT&CK atau kontrol CIS dan NIST [S10]. Verifikasi bahwa annotation muncul pada finding dan di dashboard Risk Analysis [S10].
- **Architect:** desain deployment ES (search head khusus, kapasitas scheduler, akselerasi). Lantern menyebut ES sebagai pemroses batch yang berat (lihat Day 25).

## 3. Lab praktik

1. Buat tabel 3 kolom (Analyst, Engineer, Architect). Isi masing-masing dengan 5 tugas yang pernah kamu kerjakan, disamarkan dan tanpa data kerja.
2. Petakan setiap tugas ke work role NICE yang paling dekat [S4], cek nama work role di v2.0.0.
3. Jalankan bagian 2.2 di Splunk lab. Bila ada search yang skipped, jelaskan penyebabnya dari field `reason` dan tentukan perbaikannya sebagai engineer.
4. Jalankan bagian 2.3 bila punya akses log lisensi di lab, lalu proyeksikan kebutuhan disk 90 hari.
5. Ambil 3 detection dari research.splunk.com (Day 45). Catat mapping ATT&CK dan, bila ada, Kill Chain, CIS, dan NIST. Untuk masing-masing, tentukan fungsi NIST CSF 2.0 yang paling relevan (biasanya Detect; bila ada aksi respons, Respond).
6. Isi tabel CIA di bagian 1.10 untuk 3 skenario serangan di lab-mu (misalnya defacement BOTS v1, ransomware BOTS v1, brute force RDP lab), termasuk kolom sinyal di Splunk.
7. Jalankan bagian 2.6 dengan 6 risiko lab-mu sendiri, lalu tentukan penanganan untuk masing-masing dan tulis satu kalimat alasan per baris.
8. Dengan ES: tambahkan annotation ATT&CK ke satu detection kustom (misalnya detection dari Day 13 bagian 2.3), picu detection itu, lalu jalankan bagian 2.4 dan bagian 2.5 untuk melihat annotationnya muncul di dua tempat berbeda.
9. Tulis "elevator pitch" 60 detik untuk interview: posisimu sekarang, peran target (misalnya detection engineer), dan bukti dari catatan ini.

**Hasil yang sebaiknya tersimpan:**

- Tabel tugas per peran (15 tugas) dan pemetaannya ke NICE.
- Hasil bagian 2.2 beserta tafsirannya.
- Tabel pemetaan detection ke ATT&CK, CSF, dan CIS.
- Tabel CIA untuk 3 skenario.
- Matriks risiko lab dengan penanganan.
- Dengan ES: bukti annotation terlihat di risk index.
- Elevator pitch tertulis.

**Variasi tantangan:** pilih salah satu. Pertama, rancang struktur SOC untuk organisasi fiktif berukuran 800 karyawan dengan 6 FTE keamanan: pilih tiered atau tierless, jam operasi (8x5 atau 24x7, lihat tech brief Splunk [S1]), apa yang di-outsource, dan alasannya. Kedua, buat lookup kustom yang memetakan teknik ATT&CK ke kontrol CIS v8.1 yang relevan (minimal 5 baris, dibuat sendiri), lalu pakai di bagian 2.4 untuk menunjukkan kontrol mana yang paling sering diuji penyerang di lab, dan cocokkan dengan dokumen pemetaan resmi CIS dan ATT&CK bila tersedia.

## 4. Troubleshooting

Tabel ini mencampur gejala organisasi dan gejala teknis, karena keduanya sering muncul bersamaan: antrean yang kacau biasanya punya sebab di konten dan data.

| Gejala | Kemungkinan penyebab | Perbaikan |
|---|---|---|
| Tier 1 kewalahan, eskalasi berkualitas rendah | Terlalu banyak alert berisik; playbook tidak jelas | Tuning detection (engineer), RBA (Day 35), otomasi (SOAR) |
| Detection "ada" tetapi tidak pernah fire | Tidak ada pemilik engineering untuk data atau konten | Tetapkan peran engineer dan metrik kesehatan (Detection Studio) |
| Platform lambat, search terlewat | Arsitektur tidak mengikuti pertumbuhan | Perencanaan kapasitas (architect), lihat bagian 2.2 dan 2.3 |
| Analyst stagnan | Tidak ada jalur promosi atau pelatihan | Jalur karier antar tier [S1], pemetaan NICE [S4] |
| Kesenjangan persepsi manajemen dan SOC | Komunikasi dan metrik lemah | Metrik kinerja (Day 34) [S2][S5] |
| Field `annotations.*` tidak ada di risk index | Detection tanpa annotation, atau versi lama | Tambahkan annotation [S10]; cek isi event risk mentah |
| Framework kustom tidak terisi detailnya | Lookup definition atau automatic lookup belum dibuat | Lengkapi tiga komponen framework kustom [S10] |
| Mapping ATT&CK usang | Lookup ATT&CK lama; teknik berganti ID | Perbarui konten ESCU dan lookup; cek versi ATT&CK (v19.2) [S11] |
| Diskusi risiko macet di "semua high" | Skala tidak dikalibrasi | Definisikan kriteria likelihood dan impact secara tertulis lebih dulu |

## 5. Kesalahan umum dan jebakan

- Menyamakan "engineer" dengan "analyst senior". Engineer berorientasi sistem dan konten, bukan kasus (bagian 1.3).
- Menganggap model tier selalu benar. MITRE menekankan struktur sesuai kebutuhan organisasi [S2].
- Mengabaikan proses. Teknologi tanpa playbook dan threat model menghasilkan noise [S1].
- Menyamakan "risk" di RBA dengan penilaian risiko organisasi (bagian 1.11).
- Menganggap ATT&CK framework kepatuhan. Ia basis pengetahuan perilaku penyerang, bukan daftar persyaratan.
- Menyebut CSF 1.1 dengan lima fungsi padahal versi berlaku adalah 2.0 dengan Govern [S8].
- Menyebut CIS "Top 20", istilah era v7. Sejak v8 jumlahnya 18 kontrol, dan v8.1 tetap 18.
- Mengira availability hanya soal DDoS. Ransomware dan kesalahan konfigurasi juga merusak availability.
- Memakai sumber lama tanpa konteks. Tech brief Splunk (2017) dan artikel TechTarget (2020) masih berguna untuk konsep, tetapi nama produk dan istilahnya sudah berubah di ES 8.
- `[sekunder]` Data tren di Day ini berasal dari liputan survei SANS [S5][S7], bukan dari laporan lengkapnya. Angka persentase sebaiknya dicocokkan dengan laporan asli sebelum dikutip. Bagian framework, CIA, dan risiko bersumber dokumen primer dan tidak memakai sumber komunitas.

## 6. Catatan terkini

Bagian ini menampung detail versi dan edisi yang berubah lebih cepat daripada konsepnya.

- **SANS 2026 SOC Survey (Jun 2026):** SIEM adalah skill paling dicari; adopsi AI tinggi tetapi integrasi ke alur kerja rendah [S5].
- NICE Framework Components v2.0.0 (Mar 2025) [S4].
- ES 8.6 dan 8.7 memperkenalkan agen AI (misalnya "AI SOC Analyst"), yang berpotensi menggeser sebagian tugas triage tier 1, cek di release notes (Day 45).
- MITRE "11 Strategies" edisi 2022 tetap menjadi rujukan desain SOC [S2].
- NIST CSF 2.0 (Feb 2024) menambah fungsi Govern [S8].
- CIS Controls v8.1 (Jun 2024) diselaraskan dengan CSF 2.0 [S9].
- **ATT&CK v18 sampai v19.2:** perubahan model deteksi (Detection Strategies dan Analytics) dan rilis Agile (Day 21) [S11].
- ES 8.7 menyertakan annotation PCI DSS 4.0 selain empat framework utama [S10].

## 7. Cheat sheet

```
SOC = People + Process + Technology  (process dimulai dari threat modeling)
TIER  T1 monitor/triage/tutup FP/eskalasi | T2 investigasi mendalam/mitigasi | T3 investigasi lanjut, hunting, forensik, RE
PERAN Analyst = KEJADIAN (triage, investigasi, disposisi, hunting)
      Engineer = SISTEM & KONTEN (onboarding data, TA/CIM, detection & tuning, integrasi, otomasi, kesehatan)
      Architect = DESAIN (topologi, skala, strategi data/retensi, pemilihan teknologi, roadmap)
PENDUKUNG CTI | hunting | forensik/malware | detection engineering | SOC manager/director
MODEL tiered vs tierless ; terpusat vs terdistribusi ; 8x5 vs 24x7 ; outsourcing (MITRE 11 Strategies)
NICE  Work Role Categories > Work Roles > Competency Areas > TKS (v2.0.0, Mar 2025)
KONTROL = mekanisme (MFA, logging) | STANDAR = persyaratan teraudit (ISO 27001, PCI DSS) | FRAMEWORK = struktur (CSF, CIS, ATT&CK, Kill Chain)
CSF 2.0   Govern | Identify | Protect | Detect | Respond | Recover  (Feb 2024)
CIS       v8.1 (Jun 2024), 18 kontrol, selaras CSF 2.0
ISO 27001 :2022 (+Amd 1:2024) klausul 4-10 + Annex A 93 kontrol (org 37 / people 8 / physical 14 / tech 34)
          dekat SOC: 8.15 Logging, 8.16 Monitoring, 5.25-5.26 insiden
ATT&CK    taktik = TUJUAN ; teknik = CARA ; v19.2 ; v18: Detection Strategies + Analytics
KILL CHAIN Recon -> Weaponization -> Delivery -> Exploitation -> Installation -> C2 -> Actions on Objectives
ES ANNOT  managed: MITRE ATT&CK, CIS, NIST CSF, Kill Chain (+PCI DSS 4.0) | unmanaged: kustom
          annotations.<fw>.<field> ; savedsearches.conf action.correlationsearch.annotations (JSON)
          Configure > Content management > detection > Annotations ; terlihat di index=risk
CIA (FIPS 199)  C = cegah pengungkapan | I = cegah modifikasi (+authenticity, non-repudiation) | A = akses tepat waktu & andal
                dampak low / moderate / high
RISIKO    threat + vulnerability -> likelihood ; impact ; risk = f(likelihood, impact)
          treatment: mitigate | transfer | avoid | accept ; inherent vs residual ; appetite
          risk score RBA != risk assessment organisasi
QUERY     `notable` | stats count BY status_label owner urgency      (beban antrean)
          index=_internal sourcetype=scheduler status=skipped        (kesehatan detection)
          index=_internal source=*license_usage.log* type=Usage      (kapasitas)
          index=risk | stats count BY annotations.mitre_attack.*      (teknik yang sering terlihat)
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** SOC lead PT JAB berencana mempromosikan analyst L2 terbaiknya menjadi detection engineer "karena engineer itu analyst senior". Tepat?

<details><summary>Jawaban</summary>

Tidak tepat sebagai alasan. Engineer bukan tingkat di atas analyst, melainkan orientasi pekerjaan yang berbeda: analyst mengurus kejadian (triage, investigasi, disposisi), engineer mengurus sistem dan konten (onboarding data, parsing, membuat dan tuning detection, otomasi, kesehatan platform), dan architect mengurus desain. Analyst L2 yang hebat bisa menjadi engineer yang baik, tetapi keterampilan yang dinilai berbeda, dan di SOC kecil keduanya sering dirangkap satu orang. Lihat bagian 1.3.

</details>

**2. Skenario keputusan.** Review pasca-insiden SOC-2026-0231 menunjukkan finding muncul 25 menit setelah aktivitas dimulai, dan bagian 2.2 memperlihatkan 46 eksekusi detection brute force yang skipped dalam 24 jam dengan alasan batas konkurensi. Apa langkah yang paling tepat?

- A. Minta L1 memantau dashboard lebih sering supaya keterlambatan tertutupi.
- B. Engineer menjadwal ulang dan mengoptimalkan search serta menambah filter untuk akun layanan yang berisik, lalu architect menambah kapasitas scheduler dan memindahkan akselerasi data model ke jam sepi.
- C. Nonaktifkan beberapa detection lain supaya slot konkurensi cukup, lalu tutup temuan review.

<details><summary>Jawaban</summary>

B. Masalahnya ada di konten dan di kapasitas, jadi perbaikannya dibagi ke dua peran: engineer pada jadwal, query, dan filter; architect pada slot konkurensi dan jadwal akselerasi. A keliru karena memantau lebih sering tidak menghasilkan data yang tidak pernah dievaluasi scheduler. C keliru karena mematikan detection lain menukar satu titik buta dengan titik buta baru, tanpa catatan keputusan dan tanpa pemilik perbaikan. Lihat bagian 1.4 dan 2.2.

</details>

**3. Pertanyaan jebakan.** Di rapat kuartalan, SOC lead ingin menyebut host dengan risk score tertinggi di ES sebagai "risiko tertinggi perusahaan". Benarkah?

<details><summary>Jawaban</summary>

Tidak. Risk score di Risk-Based Alerting adalah akumulasi sinyal perilaku per entity, dengan bobot yang kamu tetapkan sendiri, jadi skor tinggi bisa berarti satu host berisik atau satu detection yang terlalu longgar. Risiko dalam arti manajemen adalah fungsi likelihood dan impact atas skenario tertentu, dinilai terhadap risk appetite, lalu ditangani dengan mitigate, transfer, avoid, atau accept. Dua hal itu memakai kata yang sama dan tidak boleh ditukar di rapat yang sama. Lihat bagian 1.11.

</details>

**4. Skenario keputusan.** Saat scoping SOC-2026-0231, L2 menemukan Event 1102 di `JKT-FS01`: audit log dibersihkan satu jam setelah login `svc_backup`. Pilar CIA mana yang paling tepat kamu sebut di laporan, dan kenapa itu penting?

- A. Availability, karena log tidak bisa diakses lagi.
- B. Integrity dan akuntabilitas, karena bukti dimodifikasi atau dihancurkan sehingga non-repudiation hilang.
- C. Confidentiality, karena penyerang membaca isi log sebelum menghapusnya.

<details><summary>Jawaban</summary>

B. Menurut FIPS 199, integrity berarti menjaga informasi dari modifikasi atau perusakan yang tidak semestinya, termasuk menjamin non-repudiation dan authenticity, dan penghapusan audit log tepat mengenai itu. A tidak tepat sebagai pilar utama karena masalahnya bukan layanan yang tidak bisa diakses, melainkan bukti yang hilang permanen. C hanya dugaan yang belum dibuktikan, dan menyebutnya sebagai pilar yang rusak berarti mengklaim pengungkapan data tanpa bukti. Lihat bagian 1.10.

</details>

**5. Pertanyaan jebakan.** Dalam draf laporan, seseorang menulis "kami mengikuti CIS Top 20 dan lima fungsi NIST CSF". Apa yang salah?

<details><summary>Jawaban</summary>

Dua istilah usang. "Top 20" adalah penamaan era CIS v7; sejak v8 jumlahnya 18 kontrol, dan v8.1 (Juni 2024) tetap 18 sekaligus diselaraskan dengan CSF 2.0. Lima fungsi adalah CSF 1.1; sejak CSF 2.0 (Februari 2024) ada enam fungsi karena Govern ditambahkan, dan cakupannya berlaku untuk semua organisasi, bukan hanya infrastruktur kritis. Salah nama versi di laporan audit membuat sisa laporan ikut diragukan. Lihat bagian 1.8 dan 6.

</details>

**6. Jelaskan ulang.** Jelaskan kepada rekan NOC dalam tiga kalimat beda kontrol, standar, dan framework, lalu beri satu contoh masing-masing dari pekerjaan PT JAB.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Kontrol itu mekanisme yang benar-benar mengurangi risiko, misalnya MFA di VPN dan logging terpusat ke Splunk. Standar itu dokumen persyaratan yang bisa diaudit dan kadang disertifikasi, misalnya ISO/IEC 27001:2022 yang kontrol logging dan monitoringnya ada di Annex A 8.15 dan 8.16, dan itulah yang ditanyakan auditor internal. Framework itu struktur untuk mengorganisasi praktik atau pengetahuan dan biasanya sukarela, misalnya MITRE ATT&CK untuk menamai teknik penyerang dan NIST CSF 2.0 untuk membagi program kita menjadi Govern sampai Recover."

Kesalahan yang sering muncul:

- Menyebut ATT&CK sebagai standar kepatuhan yang bisa "dipatuhi".
- Menganggap garis antara ketiganya selalu tajam, padahal CIS Controls berperan sebagai framework kontrol yang diprioritaskan walaupun namanya "controls".
- Berhenti di definisi tanpa menyebut contoh yang ada di organisasi sendiri, sehingga rekan NOC tidak tahu di mana ia terlibat.

</details>

**7. Interview question (English).** "Walk me through how a single alert in your SOC turns into something management cares about."

<details><summary>Sample answer</summary>

"A detection fires and a finding lands in the queue, and because our detections carry framework annotations, the finding already tells me the ATT&CK technique and the control it relates to. As tier 1 I triage it, decide the disposition with evidence, and escalate to tier 2 if it's a true positive or if I can't prove otherwise; tier 2 scopes it and contains the host. After that the work splits by role: the detection engineer fixes the content and data problem, in our case a scheduled search that kept getting skipped so the finding arrived twenty five minutes late, and the architect fixes the capacity issue behind it. For management I translate the same case into their language: which technique we saw, which control turned out to be weak, how late we were in detecting it, and what that means for residual risk on that scenario. I'm careful not to present an ES risk score as organisational risk, because that score is accumulated behavioural signal per entity, not likelihood times impact."

What makes this answer strong: it follows one case end to end, shows who owns each kind of fix instead of blaming the analyst, uses framework labels as data that already exists in the platform rather than slideware, and shows precision about the difference between an RBA risk score and a risk assessment, which is a common interview trap.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Splunk Tech Brief: Building a SOC with Splunk | https://www.splunk.com/en_us/pdfs/tech-brief/building-a-soc-with-splunk-tech-brief.pdf | primer (vendor) | 2017 (lebih dari 3 tahun); diakses 2026-10-07 | Tinggi untuk konsep tier dan peran; contoh produk usang |
| S2 | MITRE: 11 Strategies of a World-Class Cybersecurity Operations Center (rilis pers) | https://www.mitre.org/news-insights/news-release/mitre-publishes-11-strategies-world-class-cybersecurity-operations | primer | 2022-03-29 | Tinggi untuk daftar strategi |
| S3 | TechTarget: 5 key enterprise SOC team roles and responsibilities | https://techtarget.com/searchsecurity/tip/5-key-enterprise-SOC-roles-and-responsibilities | sekunder | 2020-09-23 (lebih dari 3 tahun); diakses 2026-10-07 | Sedang |
| S4 | NIST: NICE Framework Components v2.0.0 | https://www.nist.gov/document/nice-framework-components-poster-march-2025 | primer | 2025-03 | Tinggi untuk struktur; nama work role perlu dicek |
| S5 | Infosecurity Magazine: Staffing is top SOC challenge even as AI proliferates, says SANS (SANS 2026 SOC Survey) | https://www.infosecurity-magazine.com/news/staffing-top-soc-challenge-ai/ | sekunder | 2026-06-17; diakses 2026-10-07 | Sedang-tinggi |
| S6 | SANS Blueprint podcast: Strategy 3: Build a SOC structure | https://sans.org/podcasts/blueprint/strategy-3-build-a-soc-structure-to-match-your-organizational-needs-41 | sekunder | tanggal tidak tercatat | Sedang |
| S7 | SANS x Anvilogic: State of Detection Engineering 2026 | https://www.anvilogic.com/report/state-of-detection-engineering | sekunder | 2026 | Sedang |
| S8 | NIST: The NIST Cybersecurity Framework (CSF) 2.0 (NIST CSWP 29) | https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf | primer | 2024-02-26; diakses 2026-10-10 | Tinggi. Enam fungsi, cakupan semua organisasi |
| S9 | CIS: CIS Critical Security Controls v8.1 dan Change Log | https://www.cisecurity.org/insights/white-papers/cis-critical-security-controls-v8-1 | primer | 2024-06 | Tinggi |
| S10 | ES 8.7: Add annotations to detections in Splunk Enterprise Security | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/detections/add-annotations-to-detections-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi. Juga sumber nama fase Kill Chain yang ditampilkan sebagai annotation |
| S11 | MITRE ATT&CK: Updates (v19.2) | https://attack.mitre.org/resources/updates/ | primer | diakses 2026-10-07 | Tinggi |
| S12 | NIST FIPS 199: Standards for Security Categorization of Federal Information and Information Systems | https://csrc.nist.gov/pubs/fips/199/final | primer | 2004 (lebih dari 3 tahun); diakses 2026-10-10 | Tinggi untuk definisi CIA dan tingkat dampak |
| S13 | NIST SP 800-30 Rev. 1: Guide for Conducting Risk Assessments | https://csrc.nist.gov/pubs/sp/800/30/r1/final | primer | 2012-09 (lebih dari 3 tahun); diakses 2026-10-10 | Tinggi. Definisi di bagian 1.11 ditulis ulang dengan kata sendiri; cocokkan dengan glosarium dokumen bila dikutip |
| S14 | ISO: ISO/IEC 27001:2022 Information security management systems (halaman komite) | https://committee.iso.org/standard/82875.html | primer | 2022-10; diakses 2026-10-10 | Tinggi untuk edisi dan status; isi standar berbayar |

**Catatan sumber:** nama role bawaan ES 8.x dan struktur index notable atau finding di ES 8 belum terkonfirmasi dokumentasi, jadi cek di instance ES-mu. Angka survei SANS [S5][S7] berasal dari liputan, bukan laporan aslinya. Sumber [S6] hanya dipakai sebagai rujukan pendukung untuk tema strategi struktur SOC, bukan untuk fakta angka. Jumlah kontrol CIS v8.1 (18) dan penulisan nama fase Kill Chain di lookup annotation ES perlu dicek di instance ES-mu [S10]. Nomor dan judul kontrol ISO/IEC 27001 Annex A ditulis dari struktur standar edisi 2022; teks kontrolnya sendiri berbayar dan tidak disalin [S14]. Kasus SOC-2026-0231 di bagian 1.4 dan seluruh keluaran ilustrasi di bagian 2 adalah contoh fiktif untuk PT JAB, bukan hasil eksekusi.
