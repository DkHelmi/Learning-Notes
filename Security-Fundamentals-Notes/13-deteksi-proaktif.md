---
day: 13
title: 'Deteksi proaktif: threat hunting, hipotesis, sandbox, honeypot, honeytoken, dan deception'
researched_on: 2026-10-21
versions_checked: 'NIST CSRC Glossary: honeypot, sandbox (diakses 2026-10-21); NIST SP 800-53 Rev. 5 control RA-10 (Sep 2020, release 5.2.0 Agu 2025); Splunk PEAK Threat Hunting Framework (blog April, Mei, Juli 2023); Microsoft Defender XDR advanced hunting overview (ms.date 2026-08-07); Microsoft Defender for Endpoint deep analysis (ms.date 2026-07-02); Microsoft Learn event 4624 (ms.date 2021-09-07); MITRE Engage (diakses 2026-10-21); MITRE D3FEND Dynamic Analysis, File Analysis, Decoy User Credential (diakses 2026-10-21); MITRE ATT&CK T1497 v2.0 (diubah 2026-09-11); Canarytokens docs (diakses 2026-10-21)'
---

# Day 13: Deteksi proaktif (threat hunting, hipotesis, sandbox, honeypot, honeytoken, dan deception)

Cakupan: cara SOC mencari ancaman yang belum memicu alert (threat hunting berbasis hipotesis dan baseline), cara memeriksa file mencurigakan dengan aman (sandbox, analisis statis dan dinamis), dan cara memasang umpan yang membuat penyerang membuka dirinya sendiri (honeypot, honeytoken, deception).

## Ide inti

Semua alat yang dibahas di Day sebelumnya (firewall, IDS, EDR, SIEM, gateway email) bekerja dengan menunggu: mereka berbunyi bila sesuatu cocok dengan aturan yang sudah ditulis. Masalahnya, penyerang yang cermat justru berusaha tidak cocok dengan aturan apa pun. Deteksi proaktif adalah kumpulan cara untuk tidak hanya menunggu. Ada tiga arah. Pertama, analyst pergi mencari sendiri jejak penyerang yang lolos dari aturan (threat hunting). Kedua, file yang mencurigakan tidak hanya dicocokkan dengan daftar, tetapi dijalankan di ruang tertutup supaya perilakunya terlihat (sandbox). Ketiga, organisasi memasang umpan yang tidak punya fungsi bagi orang sah, sehingga siapa pun yang menyentuhnya hampir pasti sedang berbuat sesuatu yang tidak seharusnya (honeypot, honeytoken, deception).

Ketiga arah itu punya satu kesamaan: semuanya mengakui bahwa pertahanan otomatis pasti punya celah, lalu menambah cara melihat yang tidak bergantung pada celah yang sama. Hasil kerja proaktif yang baik juga tidak berhenti di "ketemu" atau "tidak ketemu": setiap hunt, setiap laporan sandbox, dan setiap umpan yang tersentuh seharusnya membuat aturan deteksi otomatis menjadi lebih baik.

Bayangkan satpam sebuah kompleks perkantoran. Satpam yang menanggapi alarm berbunyi sedang melakukan triage: ada sinyal, ia datang, ia menilai. Satpam yang berkeliling memeriksa pintu belakang dan gudang padahal alarm diam, karena ia menduga maling biasanya masuk lewat sana, sedang melakukan threat hunting. Paket mencurigakan tidak dibuka di meja resepsionis, tetapi dibawa ke ruang karantina dan dibuka sambil diamati: itu sandbox. Rumah kosong yang sengaja dibuat terlihat berisi barang berharga untuk memancing maling adalah honeypot, dan uang bertanda atau dokumen umpan yang memicu alarm saat disentuh adalah honeytoken. Batas analogi ini perlu diingat sejak awal: maling di dunia nyata tidak bisa mengecek apakah ruang karantina sedang mengamatinya, sedangkan program jahat bisa dan sering melakukannya; dan "berkeliling" di jaringan berarti membaca jutaan baris log, bukan berjalan kaki.

```
                    pertahanan menunggu                      deteksi proaktif
                 (alert dari aturan yang ada)          (tidak menunggu aturan berbunyi)

  kejadian ---> [firewall, IDS, EDR, SIEM] ---> ALERT ---> triage (Day 11)
      |                    |
      |               lolos aturan
      |                    |
      +------> threat hunting: hipotesis + baseline ---> temuan? ---> insiden / perbaikan
      |                                                        |
      +------> sandbox: jalankan file di ruang tertutup ---> perilaku ---> indikator, verdict
      |                                                        |
      +------> umpan (honeypot, honeytoken) disentuh ---> alert yang hampir pasti jahat
                                                               |
                                          semua hasil -------> detection baru, tuning, umpan baru
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP fiktif dengan sekitar 1.200 karyawan. SOC PT JAB memakai SIEM Splunk (sistem yang mengumpulkan log dari banyak sumber dan memunculkan alert, Day 10) dan EDR Microsoft Defender for Endpoint (agen di laptop dan server yang merekam perilaku program, Day 06 bagian 1.2). Sejak Februari 2027, analyst L2 PT JAB menjalankan program threat hunting: setiap hunt diberi nomor `HUNT-2027-NNN` dan catatannya disimpan di repositori internal `jab-hunt`. PT JAB juga sudah lama memasang umpan: setelah `INC-2026-023` (Kerberoasting akun layanan, akhir 2026), alert pertama insiden itu justru datang dari akun umpan `svc-sql-honey` yang sengaja dibuat SOC. Kamu analyst L1 yang sedang orientasi minggu ketiga. Kamis 2027-08-19 pukul 08:30, Sari Kusuma (analyst L2, mentormu) mengirim pesan:

> "Hari ini Kamis, jadwal hunting saya, dan kamu ikut. Pagi kita jalankan `HUNT-2027-031`: saya menduga ada akun layanan yang dipakai login seperti manusia dari laptop. Belum ada alert apa pun, jadi pertanyaan pertama: apa bedanya pekerjaan ini dengan antrean alert yang kamu kerjakan minggu lalu? Kedua, kalau tidak ada alert, dari mana kita mulai dan bagaimana tahu dugaan kita benar atau salah? Ketiga, bagaimana kita tahu mana yang 'tidak biasa' kalau belum tahu yang biasa? Setelah itu ada PR dari shift malam: Dwi menutup `SOC-2027-0872`, lampiran yang dilaporkan Maya dari Pengadaan, dengan alasan 'hasil sandbox bersih'. Keempat, apa sebenarnya yang dikerjakan sandbox, dan apa arti 'bersih'? Kelima, apa bedanya memeriksa file tanpa menjalankannya dengan menjalankannya? Terakhir, kamu sudah lihat di konsol ada alert dari 'honeypot' dan 'honeytoken'. Keenam, kenapa kita memasang server palsu, dan ketujuh, kenapa file palsu? Kedelapan, kalau semua umpan itu disebut deception, apa bedanya dengan pertahanan biasa? Dan kesembilan, hunt yang tidak menemukan penyerang itu gagal atau tidak?"

Pesan itu memuat sembilan pertanyaan:

1. Apa bedanya threat hunting dengan triage alert?
2. Dari mana hunt dimulai bila tidak ada alert, dan bagaimana tahu dugaan benar atau salah?
3. Bagaimana menentukan yang "tidak biasa" tanpa tahu yang biasa?
4. Apa yang dikerjakan sandbox, dan apa arti hasil "bersih"?
5. Apa bedanya memeriksa file tanpa menjalankannya dengan menjalankannya?
6. Kenapa memasang server palsu?
7. Kenapa memasang file atau akun palsu?
8. Apa bedanya deception dengan pertahanan biasa?
9. Apakah hunt yang tidak menemukan penyerang berarti gagal?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, pertanyaan 6 di bagian 1.6, pertanyaan 7 di bagian 1.7, pertanyaan 8 di bagian 1.8, dan pertanyaan 9 di bagian 1.9. Bagian 2 mengikuti hari Kamis itu dari pagi sampai sore: hunt pagi, hasil sandbox yang ternyata tidak bersih, alert honeytoken dan honeypot yang berbunyi di tengah hari, dan catatan hunt yang ditulis sore harinya.

**Kapan relevan:** saat menjelaskan kenapa SOC butuh pekerjaan di luar antrean alert; saat membaca laporan sandbox untuk lampiran atau file yang dilaporkan; saat menerima alert dari honeypot atau honeytoken dan harus memutuskan seberapa cepat menanggapinya; saat mengusulkan detection baru dari temuan; dan saat interview ditanya "apa itu threat hunting" atau "apa bedanya honeypot dengan honeytoken".

**Kapan bukan jawaban:** deteksi proaktif tidak menggantikan pertahanan dasar. Hunt tidak berguna bila log yang dibutuhkan tidak dikumpulkan, sandbox tidak menggantikan EDR di perangkat, dan umpan tidak mencegah serangan apa pun; ia hanya memberi tahu. Saat insiden sudah dinyatakan, pertanyaan "apa lagi yang terkena" adalah pekerjaan scoping dalam penanganan insiden (Day 19), bukan hunt bebas, walaupun tekniknya mirip.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya seperti SIEM, EDR, log, alert, hash, service account, dan Kerberos tidak diulang di tabel ini; definisinya diulang satu kalimat di tempat bila dibutuhkan. Tabel berikut memuat istilah baru di Day ini; pakai kolom padanan saat sebuah istilah terasa abstrak.

| Istilah | Arti singkat | Padanan sehari-hari |
|---|---|---|
| Deteksi proaktif | Cara menemukan ancaman yang tidak menunggu aturan otomatis berbunyi | Satpam yang tidak hanya duduk menunggu alarm |
| Threat hunting | Pencarian aktif oleh manusia atas ancaman yang lolos dari deteksi otomatis | Satpam berkeliling memeriksa tempat yang mungkin dimasuki maling walau alarm diam |
| Triage alert | Menilai alert yang sudah berbunyi: benar atau tidak, seberapa mendesak; dibahas di Day 11 | Satpam yang menanggapi alarm berbunyi |
| Hipotesis (hunting) | Dugaan yang bisa diuji dengan data: "bila X terjadi, maka di data Y akan terlihat Z" | Dugaan detektif yang bisa dibuktikan salah |
| Baseline | Gambaran perilaku normal yang dihitung dari data masa lalu | Kebiasaan gedung: jam ramai, siapa biasa lembur |
| Anomali | Penyimpangan dari baseline; belum tentu jahat | Lampu gudang menyala jam 2 pagi |
| Hunt backlog | Daftar ide hunt yang menunggu dikerjakan | Daftar titik patroli yang belum sempat dicek |
| Sandbox | Lingkungan tertutup dan terkendali untuk menjalankan program yang tidak dipercaya | Ruang karantina tempat paket mencurigakan dibuka dan diamati |
| Detonation | Menjalankan atau membuka file di sandbox untuk melihat perilakunya | Membuka paket di ruang karantina |
| Analisis statis | Memeriksa file tanpa menjalankannya | Memeriksa paket dari luar dan dengan sinar-X |
| Analisis dinamis | Menjalankan file di lingkungan terkendali dan mengamati perilakunya | Membuka paket di ruang karantina sambil direkam |
| Sandbox evasion | Teknik program jahat untuk mengenali sandbox lalu diam atau berpura-pura baik | Barang selundupan yang baru "bangun" setelah keluar dari ruang periksa |
| Honeypot | Sistem umpan yang dibuat menarik bagi penyerang dan tidak punya fungsi bagi pengguna sah | Rumah umpan |
| Low-interaction honeypot | Honeypot yang hanya meniru layanan, tanpa sistem sungguhan di baliknya | Maket rumah dengan pintu yang bisa diketuk |
| High-interaction honeypot | Honeypot berupa sistem sungguhan yang bisa dimasuki dan diamati | Rumah sungguhan yang dikosongkan dan dipasangi kamera |
| Honeytoken | Data umpan (file, akun, kredensial, kunci akses) yang memicu alert saat disentuh | Uang bertanda atau dokumen umpan yang memicu alarm bila disentuh |
| Canary token | Nama populer untuk honeytoken yang memanggil alamat tertentu saat dibuka, sehingga pembuatnya diberi tahu | Kertas umpan yang otomatis menelepon satpam saat dibuka |
| Honey account | Akun domain umpan yang tidak dipakai siapa pun | Kartu akses palsu yang sengaja ditinggal di meja |
| Deception | Strategi pertahanan yang sengaja menyesatkan penyerang dengan hal palsu | Denah palsu dan rumah umpan untuk menyesatkan maling |
| Denial (cyber denial) | Menghalangi atau melemahkan kemampuan penyerang menjalankan operasinya | Menutup jalan yang dipakai maling |
| Detection engineering | Pekerjaan menulis, menguji, dan merawat aturan deteksi | Tukang yang memasang dan menyetel sensor alarm |

### 1.1 Threat hunting dan bedanya dengan triage alert

Pertanyaan pertama Sari muncul karena minggu lalu pekerjaanmu selalu dimulai dari antrean alert. Pagi ini antrean tidak menjadi titik awal; yang menjadi titik awal adalah dugaan Sari tentang akun layanan.

**Apa itu:** threat hunting adalah pencarian aktif dan berulang atas ancaman yang sudah lolos dari pengaman yang ada. NIST memasukkannya sebagai control RA-10 di SP 800-53 Rev. 5: organisasi membangun dan memelihara kemampuan threat hunting untuk mencari indikator kompromi di sistemnya, serta mendeteksi, melacak, dan mengganggu ancaman yang lolos dari control yang ada, dengan frekuensi yang ditentukan organisasi [S3]. Penjelasan RA-10 menyebut hunting sebagai pertahanan yang aktif, dibandingkan dengan perlindungan yang lebih pasif seperti firewall, IDS/IPS, sandbox, dan SIEM, dan tujuannya menemukan penyerang sedini mungkin dalam urutan serangannya [S3]. David Bianco, perancang kerangka PEAK di Splunk, mendefinisikannya lebih praktis: proses manual atau dibantu mesin yang bertujuan menemukan insiden keamanan yang terlewat oleh deteksi otomatis [S4].

Triage alert, yang dibahas lengkap di Day 11, adalah kebalikannya dari sisi titik awal: ada alert yang sudah berbunyi, lalu analyst menilai apakah alert itu benar, seberapa mendesak, dan perlu dinaikkan atau tidak.

**Analogi:** triage adalah satpam yang berlari ke pintu ketika alarm berbunyi, lalu memutuskan apakah itu maling atau kucing. Threat hunting adalah satpam yang berkeliling memeriksa pintu belakang, gudang, dan atap walaupun alarm diam, karena ia menduga maling yang pintar akan masuk lewat tempat yang tidak dipasangi sensor. Batasnya: satpam berkeliling dengan mata, sedangkan hunter berkeliling dengan data. Hunter tidak bisa melihat tempat yang tidak punya log; patroli di lorong gelap tanpa senter tidak menemukan apa-apa, dan itu bukan bukti lorong itu aman.

**Cara kerja:** hunt berjalan dalam siklus. Kerangka PEAK membaginya menjadi tiga fase: Prepare (pilih topik, riset, susun hipotesis, tentukan cakupan), Execute (kumpulkan dan olah data, analisis, naikkan temuan penting ke tim respons insiden), dan Act with Knowledge (dokumentasikan, ubah temuan menjadi detection, kembalikan ide baru ke backlog) [S4][S5].

```
   ide (intel, insiden lama, celah deteksi, rasa penasaran)
        |
   PREPARE: hipotesis yang bisa diuji, data apa, rentang waktu, batas waktu kerja
        |
   EXECUTE: tarik data -> hitung baseline -> cari penyimpangan -> selidiki
        |                                              |
        |                                     ancaman nyata? --ya--> naik ke respons insiden
        |
   ACT: catat hasil (terbukti / tidak terbukti / data kurang),
        buat detection baru, perbaiki logging, ide baru ke backlog
        |
   kembali ke awal dengan hipotesis berikutnya
```

Hunter memakai alat yang sama dengan analyst triage, hanya cara memakainya berbeda. Di PT JAB alatnya Splunk dan advanced hunting di Microsoft Defender XDR, yaitu fitur pencarian berbasis query untuk menjelajah data mentah Defender sampai 30 hari ke belakang, termasuk mencari ancaman yang sudah dikenal maupun yang belum [S7].

**Contoh di PT JAB:** program hunt PT JAB berjalan sejak Februari 2027. Setiap Kamis satu analyst L2 bergiliran berburu, dan setiap hunt punya nomor, abstrak, query, dan laporan di repositori `jab-hunt`. Hunt pagi ini, `HUNT-2027-031`, berawal dari pelajaran `INC-2026-023`: password akun layanan pernah berhasil dicuri penyerang, dan pertanyaan Sari adalah apakah ada akun layanan lain yang sekarang dipakai dengan cara yang tidak wajar. Tidak ada alert yang menyuruhnya; itu murni dugaan berdasarkan pengalaman.

**Beda dengan triage alert:** tabel berikut membandingkan keduanya dari sisi pekerjaan sehari-hari; perhatikan baris "Hasil yang wajar", karena di situ orang sering salah paham.

| Aspek | Triage alert | Threat hunting |
|---|---|---|
| Titik awal | Alert yang sudah berbunyi | Hipotesis, intel, atau pertanyaan tentang data |
| Pertanyaan utama | "Alert ini benar dan seberapa mendesak?" | "Apakah ada sesuatu yang belum memicu alert?" |
| Siapa yang biasa mengerjakan | L1, lalu dinaikkan ke L2 bila perlu | L2 atau L3, atau tim khusus |
| Batas waktu | Mengikuti SLA alert (menit sampai jam) | Ditentukan di awal hunt (jam sampai hari) |
| Hasil yang wajar | Keputusan per alert: tutup, tuning, atau naik | Temuan, atau tidak ada temuan beserta catatan dan detection baru |
| Ukuran keberhasilan | Cepat dan tepat menilai | Pengetahuan baru dan deteksi yang membaik |

**Beda dengan scoping insiden:** setelah insiden dinyatakan, analyst juga mencari "laptop lain yang terkena", dan tekniknya mirip hunting. Bedanya, scoping berangkat dari fakta insiden yang sudah pasti, sedangkan hunt berangkat dari dugaan yang belum tentu benar.

**Salah paham umum:**
- "Threat hunting berarti mencari IOC dari laporan intel ke log." Mencocokkan IOC (indikator seperti hash atau IP yang sudah diketahui jahat, Day 12) memang bisa menjadi bagian dari hunt, dan RA-10 pun menyebut pencarian indikator kompromi [S3]. Tetapi bila hanya itu yang dikerjakan, pencarian itu bisa diotomatiskan menjadi rule. Nilai khas hunting ada pada perilaku yang belum punya rule.

### 1.2 Hipotesis

Pertanyaan kedua Sari ("dari mana kita mulai") dijawab dengan satu kalimat yang ia tulis di abstrak `HUNT-2027-031` sebelum menyentuh data.

**Apa itu:** hipotesis dalam threat hunting adalah dugaan terdidik tentang ancaman yang mungkin ada di jaringan, yang kemudian diuji dengan data [S5]. Hipotesis yang baik punya dua sifat: bisa diuji (bisa dibuktikan benar atau salah) dan cukup sempit untuk benar-benar bisa dikerjakan [S5]. Bianco memberi contoh: "data apa pun dicuri lewat cara apa pun" terlalu luas, sedangkan "data keuangan dicuri lewat DNS tunneling" bisa dihunt [S5]. Hipotesis juga boleh diperbaiki di tengah jalan bila data memberi petunjuk baru [S5].

**Analogi:** dugaan seorang detektif. "Pencurinya orang dalam" terlalu luas untuk diperiksa. "Bila pencurinya orang dalam, maka kartu aksesnya tercatat masuk ruang arsip di luar jam kerja minggu lalu" bisa dicek di catatan kartu akses, dan hasilnya bisa membuktikan dugaan itu salah. Batasnya: detektif boleh memakai firasat, tetapi hunter wajib menulis dugaannya sebelum melihat data, supaya ia tidak sekadar mencari data yang mendukung keyakinannya.

**Cara kerja:** pola penulisan yang dipakai PT JAB adalah tiga bagian: siapa melakukan apa, kenapa diduga, dan jejak apa yang akan terlihat di data mana.

```
Bila  [penyerang / kejadian]              akun layanan yang password-nya dicuri dipakai penyerang
maka  [jejak yang akan muncul]            login interaktif atau Remote Desktop dengan akun svc-*
di    [sumber data, rentang waktu]        Event 4624 di server Windows (Splunk) dan login di
                                          workstation (Defender advanced hunting), 30 hari terakhir
dan bukan [penjelasan normal yang dikecualikan]  login jenis Service atau Network dari server aplikasinya
```

Dari mana ide hipotesis datang? Paling sering dari empat tempat: laporan intel tentang teknik penyerang (TTP, dibahas di Day 12), insiden lama sendiri, celah yang diketahui di deteksi ("kita tidak punya rule untuk X"), dan hasil hunt sebelumnya. Setiap ide yang belum dikerjakan ditulis di hunt backlog.

Hasil sebuah hunt berbasis hipotesis selalu salah satu dari tiga: terbukti (ada jejak yang cocok dan bukan hal normal), tidak terbukti (data lengkap dan tidak ada jejak), atau tidak bisa disimpulkan (data yang dibutuhkan tidak ada atau tidak lengkap). Hasil ketiga sama pentingnya karena ia menunjuk celah visibilitas.

**Contoh di PT JAB:** abstrak `HUNT-2027-031` memakai pola di atas. Bagian "dan bukan" penting: akun layanan sah memang login setiap menit, tetapi lewat jenis login Service (Logon Type 5, layanan dijalankan oleh Windows) atau Network (Logon Type 3, akses dari jaringan seperti membuka folder bersama). Yang dicari adalah jenis yang dipakai manusia: Interactive (Logon Type 2, login di depan komputer), RemoteInteractive (Logon Type 10, Remote Desktop), dan CachedInteractive (Logon Type 11, login dengan kredensial tersimpan tanpa menghubungi DC) [S9]. Day 07 bagian 3.4 sudah menyebut bahwa login interaktif atau Remote Desktop dengan akun layanan adalah tanda yang patut dicurigai; hunt ini mengujinya di seluruh data, bukan per alert.

**Beda dengan rule deteksi:** rule adalah pertanyaan yang sudah pasti dan dijalankan terus-menerus oleh mesin. Hipotesis adalah pertanyaan yang belum pasti dan diuji sekali oleh manusia. Hipotesis yang terbukti berguna sering berakhir menjadi rule (bagian 1.9).

**Salah paham umum:**
- "Hipotesis yang tidak terbukti berarti waktu terbuang." Hipotesis yang dibuktikan salah tetap didokumentasikan dan memberi pengetahuan baru [S5]; minimal, sekarang SOC tahu bahwa perilaku itu tidak terjadi dalam rentang data yang diperiksa, dan tahu persis seperti apa perilaku normalnya.

### 1.3 Baseline dan tiga jenis hunt

Pertanyaan ketiga Sari ("bagaimana tahu yang tidak biasa") langsung terasa ketika kamu melihat data mentah: dalam 30 hari ada lebih dari 180 ribu login akun layanan. Tanpa tahu polanya, semuanya terlihat sama.

**Apa itu:** baseline adalah gambaran perilaku normal yang dihitung dari data masa lalu, biasanya 30 sampai 90 hari, berupa ringkasan statistik seperti rata-rata, nilai yang paling sering muncul, dan jumlah nilai berbeda [S6]. Anomali adalah penyimpangan dari baseline. Kerangka PEAK menyebut berburu dengan cara ini baseline hunting atau exploratory data analysis, dan menegaskan bahwa yang tidak biasa belum tentu jahat [S6]. Hasil baseline hunt yang baik berupa kamus data (arti tiap field), deskripsi statistik field penting, dan daftar penyimpangan yang sudah diketahui wajar, supaya hunt berikutnya tidak memeriksanya ulang [S6].

**Analogi:** kebiasaan sebuah gedung. Satpam lama tahu bahwa lantai 3 ramai sampai jam 21 menjelang tutup buku, bahwa petugas kebersihan masuk jam 05, dan bahwa ruang server hampir tidak pernah dibuka di akhir pekan. Lampu gudang yang menyala jam 2 pagi adalah anomali; bisa maling, bisa juga teknisi yang lupa mematikan lampu. Batasnya: kebiasaan gedung jarang berubah, sedangkan baseline jaringan berubah setiap ada aplikasi baru, karyawan baru, atau proyek baru, sehingga perlu dihitung ulang.

**Cara kerja:** kerangka PEAK mengenal tiga jenis hunt [S4]. Tabel berikut membandingkannya; cari kolom "Cocok untuk" untuk memilih jenis yang sesuai pertanyaanmu.

| Jenis | Titik awal | Cocok untuk | Contoh di PT JAB |
|---|---|---|---|
| Hypothesis-driven | Dugaan yang bisa diuji | Teknik serangan tertentu yang sudah bisa dibayangkan jejaknya | `HUNT-2027-031`: akun layanan login interaktif |
| Baseline (exploratory data analysis) | Data, tanpa dugaan spesifik | Memahami sumber data baru, mencari penyimpangan | `HUNT-2027-033` (backlog): pola Remote Desktop dari workstation ke server |
| Model-assisted (M-ATH) | Model machine learning | Pola yang terlalu rumit untuk aturan sederhana | Belum dipakai PT JAB |

Dua jenis pertama sering digabung: hipotesis menentukan apa yang dicari, baseline menentukan apa yang wajar. PEAK sendiri menyebut baselining sebagai langkah awal yang sangat baik sebelum hunt berbasis hipotesis atau model [S6]. Itulah yang dilakukan Sari: sebelum mencari login interaktif, ia menghitung dulu jenis login apa saja yang biasa dipakai setiap akun layanan.

**Contoh di PT JAB:** hasil baseline 30 hari untuk 26 akun `svc-*` dibahas lengkap di bagian 2.1. Satu temuan sampingan sudah terlihat di tahap ini: dua akun layanan tidak login sama sekali selama 30 hari. Akun yang tidak dipakai tetapi masih aktif adalah calon yang dinonaktifkan, karena penyerang menyukai akun yang tidak ada pemiliknya yang memperhatikan.

**Beda baseline dengan allowlist:** baseline adalah gambaran apa yang biasanya terjadi; allowlist adalah keputusan apa yang dibolehkan (dibahas di Day 06 dan Day 11). Sesuatu bisa biasa terjadi tetapi tetap tidak boleh, misalnya admin yang sudah bertahun-tahun memakai satu password untuk banyak server.

**Salah paham umum:**
- "Anomali sama dengan serangan." PEAK mengingatkan bahwa yang tidak normal belum tentu jahat [S6]. Anomali adalah tempat untuk mulai bertanya, bukan kesimpulan.

### 1.4 Sandbox

Setelah hunt pagi, Sari membuka `SOC-2027-0872`. Rabu sore, Maya Anggraini (staf Pengadaan) melaporkan email berisi lampiran `Penawaran_Harga_Q3.zip`. Shift malam mengirim file di dalamnya ke sandbox, laporannya tidak menunjukkan perilaku jahat, dan alert ditutup. Pertanyaan keempat Sari: apa yang sebenarnya dikerjakan sandbox?

**Apa itu:** sandbox adalah lingkungan eksekusi yang dibatasi dan dikendalikan, tempat program yang tidak dipercaya boleh berjalan tetapi tidak bisa menyentuh sumber daya di luar yang diizinkan [S2]. NIST juga mendefinisikannya sebagai sistem yang membiarkan aplikasi yang tidak dipercaya berjalan di lingkungan yang sangat terkendali dengan hak yang dibatasi [S2]. Di keamanan, sandbox untuk analisis file biasanya berupa mesin virtual yang direkam penuh: file dibuka atau dijalankan, lalu setiap proses, file yang ditulis, perubahan registry, dan koneksi jaringan dicatat. Menjalankan file di sandbox untuk melihat perilakunya sering disebut detonation.

**Analogi:** ruang karantina di bagian penerimaan barang. Paket mencurigakan tidak dibuka di meja resepsionis, tetapi dibawa ke ruang tertutup berdinding tebal, dibuka di sana, dan semua yang keluar dari paket direkam kamera. Bila isinya berbahaya, kerusakannya hanya di ruang itu. Batasnya: paket biasa tidak tahu sedang diperiksa, sedangkan program jahat bisa mengecek apakah ia berada di ruang karantina (mesin virtual, tidak ada aktivitas pengguna, jam yang dipercepat) lalu sengaja diam. Program jahat juga bisa sengaja menunggu lebih lama dari waktu pemeriksaan.

**Cara kerja:**

```
 file mencurigakan
      |
      v
 [sandbox: mesin virtual terisolasi, direkam penuh]
      |  dijalankan / dibuka, ditunggu beberapa menit
      |
      +--> proses apa yang lahir?           (misalnya program menjalankan PowerShell)
      +--> file apa yang ditulis atau dihapus?
      +--> registry apa yang diubah?         (cara bertahan setelah restart)
      +--> alamat apa yang dihubungi?        (server penyerang)
      |
      v
 laporan: daftar perilaku + observable (IP, domain, file) + verdict
      |
      v
 dipakai untuk: memutuskan alert, memblokir indikator, mencari perangkat lain yang terkena
```

Di Defender for Endpoint, fitur ini bernama Deep analysis. Microsoft menjelaskan bahwa Deep analysis menjalankan file di lingkungan cloud yang aman dan diinstrumentasi penuh, lalu menampilkan aktivitas file, perilaku yang teramati, dan artefak seperti file yang dijatuhkan, perubahan registry, dan komunikasi ke IP [S8]. Laporannya punya dua bagian, Behaviors dan Observables; bila tidak ada yang ditemukan, kedua bagian itu hanya berisi pesan singkat [S8]. Hasilnya juga dicocokkan dengan threat intelligence Microsoft dan bisa menghasilkan alert [S8]. Ada batas penting: Deep analysis hanya mendukung file PE (program Windows seperti `.exe` dan `.dll`) [S8]. Dokumen Office atau PDF diperiksa lewat jalur lain, misalnya Safe Attachments di Defender for Office 365 yang membuka lampiran di lingkungan virtual sebelum email dikirim (Day 09 bagian 1.10).

**Contoh di PT JAB:** isi ZIP di `SOC-2027-0872` adalah `Penawaran_Harga_Q3.pdf.exe`, program yang menyamar sebagai PDF dengan ekstensi ganda. Laporan Deep analysis-nya memang kosong. Tetapi analisis statis (bagian 1.5) memperlihatkan beberapa tanda bahaya, jadi Sari menjalankannya ulang di sandbox internal SOC yang terisolasi dengan waktu tunggu lebih lama. Hasil kedua sangat berbeda; keduanya dibahas di bagian 2.2.

**Beda dengan EDR:** EDR merekam perilaku program di perangkat sungguhan yang sedang dipakai orang, jadi ia melihat serangan yang benar-benar terjadi. Sandbox merekam perilaku program di lingkungan buatan sebelum atau tanpa korban, jadi ia aman tetapi bisa dikelabui. Keduanya saling mengisi: sandbox memberi daftar perilaku dan alamat yang dicari, EDR memberi tahu di laptop mana perilaku itu benar-benar muncul.

**Salah paham umum:**
- "Hasil sandbox bersih berarti file aman." Hasil bersih hanya berarti tidak ada perilaku jahat yang terlihat selama waktu pengamatan, di lingkungan itu. MITRE ATT&CK mencatat teknik Virtualization/Sandbox Evasion (T1497): program jahat memeriksa tanda mesin virtual, memeriksa ada tidaknya aktivitas pengguna asli, atau menunda perilakunya dengan timer, lalu diam atau menyembunyikan fungsi utamanya [S13].

### 1.5 Analisis statis vs analisis dinamis

Pertanyaan kelima Sari muncul karena keputusan menjalankan ulang `Penawaran_Harga_Q3.pdf.exe` tidak datang dari sandbox, tetapi dari hal-hal yang terlihat sebelum file dijalankan sama sekali.

**Apa itu:** analisis statis adalah memeriksa file tanpa menjalankannya: nama dan ekstensinya, hash-nya (sidik jari file, Day 05 bagian 1.2), tanda tangan digital, jenis file sebenarnya, teks yang terbaca di dalamnya, dan pola isinya. MITRE D3FEND mengelompokkan cara-cara ini di bawah File Analysis, misalnya mencocokkan hash dengan malware yang dikenal (File Hashing) dan mencocokkan isi file dengan pola atau aturan (File Content Analysis, File Content Rules) [S11]. Analisis dinamis adalah menjalankan file di sandbox, mesin virtual, atau emulator lalu mengamati interaksinya dengan sistem, sehingga perilakunya terlihat tanpa perlu membongkar kodenya [S11].

**Analogi:** analisis statis seperti memeriksa paket dari luar: membaca label pengirim, menimbang, menyinari dengan sinar-X. Analisis dinamis seperti membuka paket di ruang karantina sambil direkam. Batasnya: sinar-X tidak bisa membaca isi yang dibungkus rapat (file yang dikemas atau diacak), dan membuka di ruang karantina bisa menipu bila isi paket hanya bereaksi di rumah penerima.

**Cara kerja:** tabel berikut membandingkan keduanya; cari kolom "Tidak melihat" untuk memahami kenapa keduanya dipakai bersama.

| Aspek | Analisis statis | Analisis dinamis |
|---|---|---|
| File dijalankan? | Tidak | Ya, di lingkungan terkendali |
| Yang dilihat | Nama, hash, tanda tangan, jenis file, teks, struktur | Proses, file, registry, koneksi jaringan |
| Kecepatan | Detik | Menit sampai puluhan menit |
| Risiko | Sangat kecil | Perlu isolasi yang benar |
| Tidak melihat | Perilaku yang tersembunyi di kode yang dikemas atau diacak | Perilaku yang ditunda, yang menunggu kondisi tertentu, atau yang tahu sedang diamati [S11] |
| Contoh alat di PT JAB | Pemeriksaan hash dan reputasi, properti file di konsol Defender | Deep analysis Defender, sandbox internal SOC |

D3FEND mencatat beberapa keterbatasan analisis dinamis: program jahat bisa mengenali lingkungan palsu (misalnya jam yang dipercepat atau perangkat keras khas vendor mesin virtual), bisa memeriksa apakah sedang di-debug, dan bisa hanya aktif pada kondisi tertentu seperti tanggal atau perintah tertentu, sehingga pengamatan singkat di mesin virtual bisa melewatkannya [S11]. Karena itu lingkungan sandbox sebaiknya dibuat semirip mungkin dengan perangkat sungguhan [S11].

**Contoh di PT JAB:** temuan statis untuk `Penawaran_Harga_Q3.pdf.exe` adalah ekstensi ganda dengan ikon PDF, tidak ada tanda tangan digital, waktu kompilasi dua hari sebelum email dikirim, hash yang belum pernah terlihat di sumber intel mana pun, dan sangat sedikit teks yang terbaca (tanda isi file dikemas). Tidak satu pun membuktikan file itu jahat, tetapi gabungannya cukup untuk tidak percaya pada satu laporan sandbox yang kosong. Detailnya di bagian 2.2.

**Salah paham umum:**
- "Hash yang tidak dikenal berarti file baru yang aman." Hash yang tidak dikenal hanya berarti belum ada yang melaporkan file itu. Program jahat yang dibuat khusus untuk satu kampanye memang biasanya punya hash yang belum dikenal.

### 1.6 Honeypot (low-interaction dan high-interaction)

Di tengah hari, konsol menampilkan alert dari `JKT-FS03`. Kamu belum pernah mendengar server itu, dan Sari menjelaskan alasannya: server itu tidak dipakai siapa pun. Pertanyaan keenam Sari ("kenapa memasang server palsu") terjawab oleh alert itu sendiri.

**Apa itu:** honeypot adalah sistem (misalnya server web) atau sumber daya sistem (misalnya file di server) yang dirancang supaya menarik bagi penyerang, seperti madu yang menarik bagi beruang [S1]. Karena honeypot tidak punya fungsi bagi pengguna sah, lalu lintas apa pun yang menuju ke sana bisa dianggap mencurigakan, sehingga analisisnya jauh lebih mudah daripada memilah lalu lintas sah dan jahat [S15].

Honeypot dibedakan menurut seberapa banyak penyerang bisa berinteraksi dengannya [S15]:

- **Low-interaction honeypot** hanya meniru layanan (misalnya tampak seperti file server yang menerima koneksi berbagi file), memakai sedikit sumber daya, dan mengumpulkan data dasar seperti alamat asal dan waktu percobaan. Mudah dijalankan, tetapi lebih mudah dikenali penyerang. Kebanyakan honeypot produksi masuk jenis ini [S15].
- **High-interaction honeypot** adalah sistem sungguhan yang bisa dimasuki penyerang dalam waktu lama. Informasinya jauh lebih kaya (alat, langkah, dan perintah penyerang), tetapi butuh sumber daya besar dan pengurungan yang ketat supaya tidak dipakai menyerang sistem lain. Kebanyakan honeypot riset masuk jenis ini [S15].

Pembagian kedua adalah tujuan: honeypot produksi dipasang perusahaan untuk mendeteksi serangan ke jaringannya sendiri, sedangkan honeypot riset dipakai lembaga pemerintah, intelijen, atau peneliti untuk mempelajari cara kerja penyerang [S15].

**Analogi:** rumah umpan. Polisi menyiapkan rumah yang terlihat kosong dan berisi barang berharga, lalu menunggu siapa yang mencoba masuk. Low-interaction honeypot seperti maket rumah dengan pintu yang bisa diketuk: cukup untuk tahu siapa yang mengetuk, tetapi maling yang masuk segera sadar itu bukan rumah. High-interaction honeypot seperti rumah sungguhan yang dikosongkan dan dipasangi kamera di setiap ruangan: maling bisa berkeliling lama dan setiap gerakannya terekam, tetapi rumah itu harus dipagari supaya maling tidak menyeberang ke rumah tetangga. Batasnya: rumah umpan di dunia nyata jarang dikunjungi orang yang tersesat, sedangkan di jaringan kantor ada banyak "pengunjung tersesat" yang sah, misalnya pemindai kerentanan dan alat inventaris yang memang menyapa semua alamat.

**Cara kerja:**

```
  jaringan data center 10.20.0.0/16
  +-----------------------------------------------------------+
  |  JKT-FS01 (file server asli)   JKT-BKP01   JKT-DC01 ...   |
  |                                                           |
  |  JKT-FS03 (honeypot, 10.20.20.53)                          |
  |    - meniru file server Windows: share "Keuangan-Arsip",  |
  |      "IT-Backup"                                          |
  |    - tidak ada di menu, tidak ada di skrip, tidak dipakai |
  |      aplikasi apa pun                                     |
  |    - setiap koneksi / login / daftar share --> alert SIEM |
  +-----------------------------------------------------------+
       ^
       | siapa yang menyentuh? penyerang yang memetakan jaringan,
       | atau alat sah yang memindai semua alamat (perlu dikenali)
```

Honeypot di dalam jaringan internal punya keunggulan khusus: penyerang yang sudah masuk hampir selalu memetakan jaringan untuk mencari server menarik, dan ia tidak tahu mana yang asli. Satu sentuhan ke honeypot dari laptop karyawan adalah sinyal yang sangat kuat.

**Contoh di PT JAB:** `JKT-FS03` adalah low-interaction honeypot yang meniru file server Windows. Ia dipasang setelah `INC-2026-017` (ransomware share Keuangan, Oktober 2026), ketika penyerang terbukti sempat menjelajah folder bersama sebelum mengenkripsinya. Pada hari Kamis ini, `JKT-FS03` membunyikan dua alert: `SOC-2027-0874` dari laptop karyawan (serius, bagian 2.3) dan `SOC-2027-0875` dari pemindai kerentanan internal (sah, bagian 2.4).

**Beda dengan IDS:** IDS (alarm dan CCTV jaringan, Day 03 bagian 1.3) memeriksa lalu lintas sungguhan dan harus memilah mana yang jahat, sehingga false positive (alert yang ternyata bukan serangan) sering terjadi. Honeypot tidak memilah: ia hanya menunggu disentuh, dan karena tidak ada yang punya alasan sah menyentuhnya, hampir semua alertnya layak diperiksa.

**Salah paham umum:**
- "Honeypot melindungi server asli." Honeypot tidak menghalangi apa pun; ia hanya memberi tahu, dan hanya bila penyerang menyentuhnya. Penyerang yang langsung tahu alamat server asli tidak akan pernah lewat honeypot. CrowdStrike juga mengingatkan bahwa honeypot hanya satu bagian dari strategi yang lebih luas dan tidak bisa melindungi organisasi sendirian [S15].
- "Makin realistis makin baik, jadi pakai server sungguhan." High-interaction honeypot yang salah konfigurasi bisa menjadi jalan penyerang bergerak ke jaringan asli [S15]. Untuk SOC perusahaan, low-interaction yang dirawat dengan baik biasanya sudah cukup.

### 1.7 Honeytoken, canary token, dan honey account

Alert yang berbunyi beberapa menit sebelum `SOC-2027-0874` bukan dari server, tetapi dari sebuah file: `akun-server-lama-2025.xlsx` di folder `IT-Ops` di `JKT-FS01`. File itu tidak berisi password sungguhan. Pertanyaan ketujuh Sari ("kenapa file palsu") terjawab di sini.

**Apa itu:** honeytoken adalah data umpan, bukan sistem umpan: file, dokumen, akun, kredensial, kunci akses cloud, atau baris database yang tidak dipakai siapa pun dan memicu alert saat disentuh. Definisi NIST untuk honeypot sudah mencakup sumber daya sistem seperti file di server [S1], dan istilah honeytoken dipakai untuk umpan berbentuk data seperti ini. Canary token adalah nama populer untuk jenis yang paling mudah dipasang: proyek Canarytokens menyebutnya umpan gratis yang bekerja seperti kawat jebakan, dipasang di tempat yang tidak seharusnya dilihat siapa pun, lalu mengirim alert bila diakses [S14]. Jenisnya antara lain dokumen Word dan Excel, kunci API AWS, nama DNS, alamat web, dan folder jaringan [S14].

Honey account adalah honeytoken berbentuk akun domain. MITRE D3FEND menyebut Decoy User Credential sebagai kredensial yang dibuat untuk menipu penyerang; pembela membuat analitik yang menandai setiap kali kredensial umpan itu dipakai untuk autentikasi, lalu memantau atau mengendalikan aktivitas yang mengikutinya [S12].

**Analogi:** uang bertanda atau dokumen umpan. Bank menyelipkan uang yang nomor serinya dicatat; begitu uang itu dibelanjakan, polisi tahu. Kantor menaruh map berjudul "Daftar Password Server" di lemari arsip yang tidak pernah dibuka; begitu map itu dibuka, alarm berbunyi. Batasnya: honeytoken digital bisa memberi tahu lebih banyak daripada uang bertanda (misalnya alamat IP tempat dokumen dibuka), tetapi juga bisa tersentuh oleh hal yang tidak bermaksud jahat, seperti antivirus yang memindai semua file, pengindeks pencarian, proses backup, atau karyawan yang penasaran.

**Cara kerja:** dua mekanisme yang umum dipakai.

```
 (1) DIPANTAU DARI LUAR: audit akses file di server
     penyerang membaca \\JKT-FS01\IT-Ops\arsip\akun-server-lama-2025.xlsx
        --> server mencatat siapa dan dari IP mana file dibaca
        --> log dikirim ke Splunk --> rule "honeytoken disentuh" --> alert

 (2) MEMANGGIL PULANG: canary token di dalam dokumen
     dokumen dibuka di komputer mana pun (termasuk komputer penyerang di luar)
        --> dokumen meminta alamat web khusus milik layanan canary
        --> layanan canary mengirim email ke SOC: "dokumen dibuka, dari IP X, jam Y"
```

Mekanisme pertama hanya bekerja selama file masih di server PT JAB. Mekanisme kedua tetap bekerja setelah file dicuri dan dibuka di tempat lain, selama komputer yang membukanya tersambung ke internet dan aplikasi pembukanya mengizinkan permintaan itu. Honey account bekerja dengan cara lain: akun dibuat terlihat menarik (nama mirip akun layanan database, punya SPN sehingga tiketnya bisa diminta, keterangan "admin"), tidak dipakai siapa pun, dan setiap permintaan tiket Kerberos atau percobaan login untuk akun itu memicu alert. Kerberos dan serangan Kerberoasting, yaitu meminta tiket akun layanan lalu menebak password-nya di luar jaringan, dibahas di Day 07 bagian 1.6 dan 1.10.

**Contoh di PT JAB:** tiga honeytoken aktif di PT JAB:

| Honeytoken | Jenis | Alert bila | Asal-usul |
|---|---|---|---|
| `svc-sql-honey` | Honey account dengan SPN palsu | Ada permintaan tiket Kerberos atau login untuk akun ini | Dipasang sebelum `INC-2026-023`; alert pertama insiden itu datang dari akun ini |
| `\\JKT-FS01\IT-Ops\arsip\akun-server-lama-2025.xlsx` | Dokumen umpan dengan audit akses dan canary token | File dibaca dari share, atau dokumen dibuka di mana pun | Dipasang setelah `INC-2026-017` |
| Kunci akses AWS umpan di repositori internal lama | Canary token kunci cloud | Kunci dipakai untuk memanggil API AWS | Dipasang setelah `INC-2026-025` (access key bocor di repo GitHub) |

Tabel di atas memperlihatkan pola yang sama: setiap honeytoken diletakkan di tempat yang benar-benar pernah didatangi penyerang dalam insiden lama. Pada hari Kamis ini, dokumen umpan berbunyi dua kali: sekali saat dibaca dari share (`SOC-2027-0873`), dan sekali lagi 17 menit kemudian saat dibuka dari alamat di luar PT JAB (bagian 2.3).

**Beda honeytoken dengan honeypot:** honeypot adalah sistem utuh yang menunggu disambangi; honeytoken adalah sepotong data yang menunggu disentuh atau dibawa pergi. Honeytoken jauh lebih murah dan bisa ditebar di mana saja (folder, mailbox, repositori kode, database), dan beberapa jenis tetap memberi kabar setelah dicuri. Honeypot memberi lebih banyak informasi tentang apa yang dilakukan penyerang.

**Salah paham umum:**
- "Alert honeytoken tidak mungkin false positive." Jauh lebih jarang, tetapi mungkin: proses backup, antivirus, pengindeks, atau karyawan yang penasaran bisa menyentuh file umpan. Karena itu triage tetap memeriksa proses dan akun yang menyentuhnya. Yang berbeda adalah prioritasnya: alert honeytoken diperlakukan sebagai hampir pasti jahat sampai terbukti sebaliknya.

### 1.8 Deception

Pertanyaan kedelapan Sari ("apa bedanya dengan pertahanan biasa") menyatukan honeypot dan honeytoken di bawah satu strategi.

**Apa itu:** deception adalah strategi pertahanan yang sengaja menyesatkan penyerang. MITRE, lewat kerangka Engage, mendefinisikan cyber deception sebagai sengaja memperlihatkan fakta dan fiksi palsu untuk menyesatkan penyerang, sambil menyembunyikan fakta penting supaya penyerang tidak bisa menilai keadaan dengan benar atau mengambil tindakan yang tepat [S10]. Pasangannya adalah cyber denial, kemampuan mencegah atau melemahkan kemampuan penyerang menjalankan operasinya [S10]. Engage menyebut denial dan deception sebagai pilar adversary engagement, yaitu cara pembela berinteraksi secara proaktif dengan penyerang, dan menekankan bahwa cara ini dipakai berpasangan dengan teknologi defense in depth (pengaman berlapis dari jenis berbeda, Day 01 bagian 1.6) [S10].

Engage adalah kerangka untuk merencanakan dan mendiskusikan operasi adversary engagement [S10]. Matriksnya disusun dari tujuan, pendekatan, dan aktivitas; tujuan strategisnya Prepare, Operate, Understand, dan tujuan engagement-nya Expose (membuka keberadaan penyerang), Affect (memengaruhi apa yang bisa dilakukan penyerang), dan Elicit (memancing informasi tentang penyerang) [S10].

**Analogi:** denah palsu dan rumah umpan. Pemilik kompleks tidak hanya memasang pagar dan satpam, tetapi juga menyebar denah yang menunjukkan "brankas" di rumah umpan, menaruh map palsu di lemari, dan membuat rumah umpan itu terlihat ditinggali (lampu menyala, sepatu di depan pintu). Batasnya: penyerang yang menyadari sedang ditipu bisa berhenti, berbalik menipu balik dengan memberi informasi palsu ke honeypot, atau sengaja membanjiri umpan dengan sentuhan [S15]. Deception juga butuh perawatan: rumah umpan yang lampunya mati berbulan-bulan tidak menipu siapa pun.

**Cara kerja:** Engage menegaskan bahwa deception adalah proses, bukan teknologi yang dipasang lalu dilupakan [S10]. Untuk SOC perusahaan biasa, prosesnya kira-kira:

1. Tentukan tujuan: biasanya Expose, yaitu mengetahui keberadaan penyerang sedini mungkin.
2. Pilih tempat umpan berdasarkan jalur penyerang yang nyata (insiden lama, teknik yang umum di laporan intel).
3. Buat umpan yang meyakinkan dan konsisten dengan lingkungan: nama server mengikuti pola penamaan, akun punya keterangan wajar, dokumen punya isi yang masuk akal.
4. Pastikan setiap sentuhan menghasilkan alert yang jelas prioritasnya, dan catat alat sah yang mungkin menyentuhnya.
5. Rawat: ganti tanggal, perbarui isi, uji alert secara berkala.

D3FEND menyebut hal yang sama untuk kredensial umpan: kredensial itu sebaiknya ditempatkan dalam lingkungan umpan yang lebih luas dan perlu dirawat terus supaya tetap meyakinkan [S12].

**Contoh di PT JAB:** program deception PT JAB masih sederhana dan hanya bertujuan Expose: satu honeypot (`JKT-FS03`), satu honey account (`svc-sql-honey`), satu dokumen umpan, dan satu kunci cloud umpan. Tidak ada high-interaction honeypot, karena tim belum punya kapasitas untuk mengurung dan mengamati penyerang dengan aman. Dimas Prasetyo (SOC lead) mewajibkan setiap umpan baru dicatat di daftar aset SOC dan diberi tahu ke tim Infrastruktur, supaya tidak ada admin yang "membersihkan" server atau akun yang terlihat tidak terpakai.

**Beda dengan pertahanan biasa:** pertahanan biasa berusaha mengenali yang jahat di antara yang sah, sehingga selalu ada pertukaran antara alert yang terlewat dan alert palsu. Deception membalik logikanya: membuat sesuatu yang tidak punya pengguna sah, sehingga sentuhan apa pun bermakna. Engage merumuskan perbedaan sikapnya begini: dalam pertahanan biasa pembela harus selalu benar, sedangkan dengan adversary engagement penyerang cukup salah sekali [S10].

**Salah paham umum:**
- "Deception adalah produk yang dibeli." Ada produk deception komersial, tetapi Engage menekankan bahwa deception adalah proses yang direncanakan dan dirawat [S10]. Akun umpan dan dokumen umpan pertama PT JAB dibuat tanpa produk khusus.

### 1.9 Dari hasil hunt ke detection baru

Pertanyaan terakhir Sari ("hunt yang tidak menemukan penyerang itu gagal atau tidak") dijawab sore hari, saat ia menulis laporan `HUNT-2027-031` dan membuka editor rule di Splunk.

**Apa itu:** fase Act di kerangka PEAK meminta hunter menyimpan hunt untuk dipakai lagi, mendokumentasikan apakah hipotesis terbukti atau tidak, mengubah temuan menjadi rule deteksi produksi atau menyerahkannya ke tim detection engineering (pekerjaan menulis, menguji, dan merawat aturan deteksi), memasukkan ide baru ke backlog, dan mengomunikasikan hasil ke pihak terkait [S5]. Hasil sebuah hunt juga bisa berupa celah data dan salah konfigurasi yang ditemukan di tengah jalan [S5]. Microsoft mendukung jalur yang sama: query advanced hunting bisa dipakai ulang untuk membuat custom detection rule yang berjalan otomatis [S7].

**Analogi:** satpam yang setelah berkeliling menulis laporan: "Pintu gudang belakang ternyata tidak terpasang sensor; usul pasang sensor di sana." Patroli berikutnya tidak perlu lagi memeriksa pintu itu dengan tangan, karena alarm sudah menjaganya. Batasnya: sensor baru juga bisa berbunyi palsu, jadi rule hasil hunt perlu diuji dengan data lama dulu sebelum dinyalakan.

**Cara kerja:** hasil sebuah hunt bisa dibagi menjadi lima jenis keluaran.

| Keluaran | Contoh dari `HUNT-2027-031` | Siapa yang menindaklanjuti |
|---|---|---|
| Insiden | Tidak ada | Tim respons insiden |
| Temuan non-insiden (pelanggaran kebijakan, salah konfigurasi) | Developer memakai password akun layanan untuk Remote Desktop | Pemilik sistem, Lead Infrastruktur |
| Celah visibilitas | Log login workstation tidak masuk Splunk; harus dicek lewat Defender | Tim SIEM |
| Detection baru | Rule "akun `svc-*` dengan Logon Type 2, 10, atau 11" | SOC (pemilik rule) |
| Ide baru di backlog | `HUNT-2027-033`: pola Remote Desktop dari workstation ke server | Hunter berikutnya |

Ukuran keberhasilan program hunt bukan jumlah penyerang yang ditemukan, karena organisasi yang pertahanannya baik memang jarang punya penyerang yang bersembunyi. Ukurannya adalah apakah setiap hunt meninggalkan sesuatu: pengetahuan tentang data, celah yang ditutup, atau rule yang lebih baik.

**Contoh di PT JAB:** laporan `HUNT-2027-031` menyimpulkan hipotesis tidak terbukti (tidak ada tanda penyerang), menemukan satu pelanggaran kebijakan, dua akun yang bisa dinonaktifkan, dan satu celah logging, lalu menghasilkan satu rule baru. Detail dan uji rule-nya di bagian 2.4.

**Beda dengan tuning:** tuning (dibahas di Day 11) memperbaiki rule yang sudah ada supaya alert palsunya berkurang. Hunt menghasilkan rule yang sebelumnya belum ada sama sekali, atau membuktikan bahwa rule yang ada melewatkan sesuatu.

**Salah paham umum:**
- "Semua hasil hunt harus dijadikan rule." Tidak semua cocok. Pola yang terlalu jarang dan rumit, atau yang menghasilkan terlalu banyak penyimpangan wajar, lebih baik dijadikan hunt berkala atau dashboard daripada rule yang membanjiri antrean.

## 2. Contoh nyata

Semua contoh di bagian ini adalah keluaran ilustrasi dari organisasi fiktif PT JAB, bukan hasil eksekusi nyata. Nama host, alamat IP, akun, hash, dan angka dibuat untuk latihan. Bagian ini mengikuti hari Kamis 2027-08-19 dari pagi sampai sore.

### 2.1 Pagi: `HUNT-2027-031`, akun layanan yang login seperti manusia

Pertanyaan pertama sampai ketiga Sari dijawab dengan pekerjaan nyata pagi itu. Abstrak hunt ditulis sebelum data dibuka:

```
HUNT-2027-031  (jab-hunt/hunts/HUNT-2027-031/abstract.md)
Hunter      : Sari Kusuma (didampingi analyst L1 orientasi)
Tanggal     : Kamis 2027-08-19
Jenis       : hypothesis-driven, diawali baseline
Hipotesis   : Bila password akun layanan dicuri (pola INC-2026-023), penyerang akan
              memakainya untuk login interaktif atau Remote Desktop dari workstation.
              Jejaknya: Event 4624 dengan Logon Type 2, 10, atau 11 untuk akun svc-*.
Bukan       : Logon Type 3 (Network), 4 (Batch), 5 (Service) dari server aplikasinya.
Data        : Splunk, log Security server Windows, 2027-07-20 sampai 2027-08-18 (30 hari);
              Defender advanced hunting untuk login di workstation (30 hari).
Batas kerja : 3 jam
Hasil yang mungkin: terbukti / tidak terbukti / tidak bisa disimpulkan (data kurang)
```

Langkah pertama adalah baseline: berapa banyak login per jenis untuk semua akun `svc-*`. Query Splunk yang dipakai sengaja dibuat pendek:

```
index=wineventlog EventCode=4624 TargetUserName="svc-*"
    earliest="07/20/2027:00:00:00" latest="08/19/2027:00:00:00"
| stats count by LogonType
```

Baris pertama mengambil semua login berhasil (Event 4624, tercatat di komputer yang diakses [S9]) untuk akun berawalan `svc-` dalam rentang 30 hari yang ditulis absolut. Baris kedua menghitung jumlahnya per jenis login. Hasilnya, ditambah kolom arti yang ditulis Sari, terlihat seperti ini:

| LogonType | Arti [S9] | Jumlah 30 hari | Wajar untuk akun layanan? |
|---|---|---|---|
| 3 | Network | 182.406 | Ya, akses folder bersama dan layanan jaringan |
| 5 | Service | 1.240 | Ya, layanan dijalankan Windows |
| 4 | Batch | 720 | Ya, tugas terjadwal `svc-report` setiap jam (24 x 30) |
| 2 | Interactive | 1 | Tidak biasa |
| 10 | RemoteInteractive | 1 | Tidak biasa |
| Total | | 184.368 | |

Cara membacanya: dari 184.368 login, hanya 2 yang memakai jenis login manusia. Baseline membuat dua baris itu langsung menonjol; tanpa tabel ini, keduanya tenggelam di antara ratusan ribu baris. Langkah yang sama memperlihatkan bahwa 24 dari 26 akun `svc-*` punya aktivitas, sedangkan `svc-legacyftp` dan `svc-crmold` tidak login sama sekali selama 30 hari.

Dua login tidak biasa itu diselidiki satu per satu:

| Waktu | Akun | Logon Type | Ke | Dari | Penjelasan |
|---|---|---|---|---|---|
| 2027-07-28 22:14 | `svc-backup` | 2 | `JKT-BKP01` (konsol) | Konsol server | Pemeliharaan terjadwal tim Infrastruktur, tercatat di tiket perubahan; sah saat itu, tetapi berarti password akun layanan diketahui manusia (password ini sudah direset 2027-08-10, Day 07) |
| 2027-08-12 19:22 | `svc-report` | 10 | `JKT-RPT01` (`10.20.30.21`) | `10.10.43.31` (`JKT-WS-1131`, laptop Teguh Santoso, developer aplikasi laporan) | Teguh mengaku memakai password `svc-report` untuk Remote Desktop ke server laporan saat memperbaiki job yang gagal, karena akunnya sendiri tidak punya akses |

Login kedua bukan penyerang, tetapi pelanggaran kebijakan yang nyata: password akun layanan diketahui manusia dan dipakai dari laptop. Bila laptop Teguh suatu hari dikuasai penyerang, password itu ikut terbawa. Langkah terakhir adalah sisi workstation. Log Security workstation PT JAB tidak dikirim ke Splunk, jadi Sari memeriksa login akun `svc-*` di workstation lewat advanced hunting Defender (data 30 hari [S7]). Hasilnya nol, tetapi Sari mencatat bahwa kesimpulan ini hanya berlaku untuk laptop yang agen Defender-nya sehat.

Sebelum pukul 10:15, Sari menulis status sementara di abstrak: hipotesis tidak terbukti untuk serangan, satu pelanggaran kebijakan, dua akun tidak aktif, satu celah logging. Laporan lengkap ditulis sore (bagian 2.4).

**Kapan gagal:** baseline 30 hari tidak melihat akun yang disalahgunakan sejak lebih dari 30 hari lalu dengan pola yang sama setiap hari, karena pola itu ikut masuk ke "normal". Hunt ini juga buta terhadap login yang terjadi di komputer yang lognya tidak terkumpul sama sekali.

### 2.2 Menjelang siang: laporan sandbox `SOC-2027-0872` yang "bersih"

Pertanyaan keempat dan kelima Sari dijawab dengan membuka ulang alert yang ditutup shift malam. Ringkasan alert dan catatan penutupnya:

```
Alert     : SOC-2027-0872
Prioritas : P3
Dibuat    : 2027-08-18 17:20 WIB (dari laporan user via tombol Report)
Pelapor   : maya.anggraini@jab.example (Pengadaan)
Email     : 2027-08-18 16:47 WIB, "Penawaran harga Q3 - mohon dicek"
            dari sales@mitra-niaga.example (server pengirim 192.0.2.200)
            ke 4 penerima di Pengadaan
Lampiran  : Penawaran_Harga_Q3.zip
            isi: Penawaran_Harga_Q3.pdf.exe (1,8 MB)
Status    : Ditutup 2027-08-18 21:40 oleh Dwi Cahyono
Catatan   : Email dihapus dari 4 mailbox. Deep analysis: tidak ada perilaku
            berbahaya. Pelapor tidak membuka lampiran. Ditutup, tidak berbahaya.
```

Catatan penutup itu menjawab dua pertanyaan (apakah emailnya sudah dihapus, apakah pelapor membukanya), tetapi melewatkan dua pertanyaan penting: apakah tiga penerima lain membukanya, dan apakah "tidak ada perilaku berbahaya" bisa dipercaya. Sari mulai dari analisis statis, karena hasilnya bisa didapat dalam hitungan detik tanpa menjalankan apa pun.

| Pemeriksaan statis | Hasil | Arti |
|---|---|---|
| Nama file | `Penawaran_Harga_Q3.pdf.exe`, ikon PDF | Ekstensi ganda: program yang menyamar sebagai dokumen |
| Jenis file sebenarnya | Program Windows (PE) | Bukan PDF sama sekali |
| SHA-256 | `5d7101f5e55ec76ec68a06438a90c83027ac05a309481b2d6c57c7e58bfe5aef` | 64 karakter heksadesimal; belum pernah terlihat di sumber intel mana pun |
| Tanda tangan digital | Tidak ada | Penerbit tidak bisa diverifikasi |
| Waktu kompilasi | 2027-08-16 | Dua hari sebelum email dikirim |
| Teks yang terbaca | Sangat sedikit | Isi kemungkinan dikemas atau diacak, sehingga kode aslinya tidak terlihat |

Laporan Deep analysis yang dibaca Dwi berbentuk seperti ini:

```
Deep analysis  Penawaran_Harga_Q3.pdf.exe
Submitted   : 2027-08-18 19:12   Completed: 2027-08-18 19:31
Behaviors   : No behaviors were observed.
Observables : No observables were found.
```

Laporan itu tidak salah; selama pengamatan memang tidak ada perilaku yang terlihat. Masalahnya ada pada tafsirannya. Gabungan temuan statis (program menyamar, baru dikompilasi, tidak bertanda tangan, isinya dikemas) dengan laporan dinamis yang sama sekali kosong adalah pola klasik program yang menunggu sebelum bekerja, salah satu cara sandbox evasion yang dicatat MITRE [S13]. Pukul 10:22, Sari menjalankan file itu di sandbox internal SOC `jkt-sbx01`, mesin virtual di jaringan terisolasi tanpa akses ke jaringan kantor, dengan dua perubahan: waktu pengamatan 20 menit, dan skrip yang menggerakkan mouse dan membuka dokumen supaya terlihat ada pengguna. Hasilnya pukul 10:52:

```
Sandbox jkt-sbx01   run 2   Penawaran_Harga_Q3.pdf.exe
Durasi pengamatan : 20 menit (10:22 - 10:42)
+00:00  proses dimulai; memanggil fungsi tunggu 540 detik
+09:00  menulis %APPDATA%\PdfViewerUpdate\pvu.exe
+09:01  membuat scheduled task "PdfViewerUpdate" (jalan saat login)
+09:03  koneksi HTTPS ke 192.0.2.204:443, diulang setiap 60 detik
+09:05  menjalankan perintah daftar share jaringan
Verdict : berbahaya (downloader dengan persistence dan koneksi ke server penyerang)
```

Cara membacanya: 540 detik adalah 9 menit, jadi setiap pengamatan yang lebih pendek dari 9 menit pasti melihat program yang "diam". Scheduled task adalah cara program jahat bertahan setelah komputer dinyalakan ulang (persistence, dibahas di Day 16), dan `192.0.2.204` adalah server yang dihubungi penyerang (C2, juga Day 16). Laporan kedua memberi Sari tiga hal yang bisa dicari di perangkat sungguhan: hash file, nama scheduled task, dan alamat `192.0.2.204`.

Pencarian hash di advanced hunting Defender langsung menemukan satu perangkat: file itu dijalankan di `JKT-WS-1134` (`10.10.43.34`, laptop Rizky Firmansyah, staf Pengadaan dan salah satu penerima email) pada Rabu 2027-08-18 pukul 17:52:10, dan laptop itu menghubungi `192.0.2.204` pertama kali pukul 18:01:10. Selisihnya tepat 9 menit, sama dengan perilaku di sandbox. EDR merekam semua ini, tetapi tidak memunculkan alert, karena file belum dikenal dan perilakunya baru terlihat setelah laptop dipakai lagi. Pukul 10:52 itu, Sari ternyata sudah menangani alert lain dari laptop yang sama (bagian 2.3).

**Kapan gagal:** sandbox internal yang diberi waktu 20 menit pun bisa dikelabui program yang menunggu lebih lama atau yang hanya aktif di jaringan tertentu. Bila hasil statis dan konteks email sudah cukup mencurigakan, keputusan memeriksa siapa yang menjalankan file tidak perlu menunggu verdict sandbox.

### 2.3 Tengah hari: honeytoken dan honeypot berbunyi (`SOC-2027-0873`, `SOC-2027-0874`)

Pertanyaan keenam dan ketujuh Sari dijawab oleh dua alert yang muncul selagi sandbox kedua berjalan. Alert pertama:

```
Alert     : SOC-2027-0873
Prioritas : P1 (rule honeytoken)
Waktu     : 2027-08-19 10:41:07 WIB
Rule      : File umpan dibaca dari share
Objek     : \\JKT-FS01\IT-Ops\arsip\akun-server-lama-2025.xlsx
Akun      : rizky.firmansyah@jab.example
Sumber    : 10.10.43.34 (JKT-WS-1134)
Aksi      : file dibaca dan disalin (ukuran salinan sama dengan file asli)
```

Kamu bertanya kenapa alert ini P1 padahal file-nya tidak berisi password sungguhan. Jawaban Sari: karena tidak ada alasan sah bagi staf Pengadaan untuk membuka folder arsip IT, dan karena honeytoken memang dibuat supaya hampir semua sentuhannya bermakna (bagian 1.7). Langkah triage-nya tetap dijalankan: proses apa di laptop yang membaca file itu? EDR menunjukkan bukan Excel atau Explorer yang dibuka Rizky, melainkan `pvu.exe` dari `%APPDATA%\PdfViewerUpdate\`. Tiga menit kemudian, alert kedua:

```
Alert     : SOC-2027-0874
Prioritas : P1 (rule honeypot)
Waktu     : 2027-08-19 10:44:12 WIB
Honeypot  : JKT-FS03 (10.20.20.53, low-interaction, meniru file server)
Sumber    : 10.10.43.34 (JKT-WS-1134)
Aktivitas : koneksi berbagi file, login dengan akun rizky.firmansyah,
            meminta daftar share (melihat "Keuangan-Arsip", "IT-Backup")
```

Dua alert dari dua umpan berbeda, dari laptop yang sama, dalam tiga menit, menceritakan satu hal: ada yang sedang memetakan folder bersama dari laptop Rizky dengan akun Rizky. Tabel berikut merangkum lini waktu hari itu; baca kolom "Sumber informasi" untuk melihat alat mana yang menyumbang setiap baris.

| Waktu | Kejadian | Sumber informasi |
|---|---|---|
| Rabu 16:47 | Email lampiran diterima 4 staf Pengadaan | Log email |
| Rabu 17:20 | Maya melaporkan email | Tombol Report, `SOC-2027-0872` |
| Rabu 17:52:10 | Rizky menjalankan lampiran di `JKT-WS-1134` | EDR (tanpa alert) |
| Rabu 18:01:10 | Laptop menghubungi `192.0.2.204` | EDR (tanpa alert) |
| Rabu 19:31 | Deep analysis selesai, tidak ada perilaku | Sandbox cloud |
| Rabu 21:40 | `SOC-2027-0872` ditutup | Ticketing SOC |
| Kamis 10:22 | Sandbox internal mulai dijalankan | `jkt-sbx01` |
| Kamis 10:41:07 | File umpan dibaca dari share | Honeytoken, `SOC-2027-0873` |
| Kamis 10:44:12 | Laptop yang sama menyentuh honeypot | Honeypot, `SOC-2027-0874` |
| Kamis 10:49 | Sari mengisolasi `JKT-WS-1134` dari konsol Defender | EDR |
| Kamis 10:52 | Hasil sandbox kedua: berbahaya, C2 `192.0.2.204` | `jkt-sbx01` |
| Kamis 10:58:31 | Dokumen umpan dibuka dari `192.0.2.205` (di luar PT JAB) | Canary token |
| Kamis 11:05 | Dimas membuka insiden `INC-2027-092` | Ticketing SOC |

Baris pukul 10:58:31 paling penting untuk dipahami. Isolasi laptop pukul 10:49 menghentikan laptop itu berbicara ke jaringan, tetapi salinan dokumen yang diambil pukul 10:41 sudah keluar lebih dulu lewat koneksi ke server penyerang, dan dibuka di komputer penyerang 17 menit 24 detik setelah dibaca dari share. Canary token di dalam dokumen memberi tahu dua hal yang tidak bisa diberikan alat lain: data benar-benar sudah keluar dari PT JAB, dan dari alamat mana pelaku membukanya. Karena isi dokumen itu palsu, kerugian langsungnya nol; tetapi penyerang yang mengambil file berjudul "akun server" jelas sedang mencari kredensial, dan itu menentukan langkah respons berikutnya.

Dimas membuka `INC-2027-092`. Langkah awal yang diambil: memblokir `192.0.2.204` dan `192.0.2.205` di `jkt-fw01` dan `jkt-proxy01`, mereset password `rizky.firmansyah`, mencari hash, nama scheduled task, dan koneksi ke `192.0.2.204` di semua perangkat lain (hasilnya hanya `JKT-WS-1134`), dan memastikan tiga penerima lain tidak menjalankan lampiran. Penanganan insiden secara utuh dibahas di Day 19.

**Kapan gagal:** honeytoken dan honeypot hanya berbunyi bila penyerang kebetulan melewatinya. Penyerang yang langsung tahu alamat server Keuangan, misalnya dari email yang dicuri, tidak perlu menjelajah dan tidak akan menyentuh umpan mana pun. Canary token di dokumen juga tidak berbunyi bila dokumen dibuka di komputer tanpa internet atau di aplikasi yang memblokir permintaan keluar.

### 2.4 Sore: catatan hunt, detection baru, dan alert honeypot yang sah

Pertanyaan kedelapan dan kesembilan Sari dijawab setelah situasi `INC-2027-092` diserahkan ke tim insiden. Pukul 14:00, honeypot berbunyi lagi:

```
Alert     : SOC-2027-0875
Prioritas : P1 (rule honeypot)
Waktu     : 2027-08-19 14:00:03 WIB
Honeypot  : JKT-FS03 (10.20.20.53)
Sumber    : 10.20.10.61 (jkt-vscan01)
Aktivitas : koneksi ke port 445 dan 3389, tanpa login
```

`jkt-vscan01` adalah pemindai kerentanan internal yang setiap Kamis pukul 14:00 memeriksa semua alamat di data center. Alert ini sah (benign), dan Sari memakainya sebagai contoh keputusan yang hati-hati: rule honeypot tidak diberi pengecualian untuk seluruh alamat `jkt-vscan01`, tetapi hanya untuk kombinasi alamat `10.20.10.61`, jendela Kamis 14:00 sampai 16:00, dan aktivitas tanpa login. Bila suatu hari pemindai itu dikuasai penyerang dan mencoba login ke honeypot, alert tetap berbunyi. Sari juga mencatat pelajaran untuk program deception: daftar alat yang memang menyapa semua alamat (pemindai, inventaris, monitoring) harus diperiksa sebelum honeypot baru dipasang.

Setelah itu Sari menutup `HUNT-2027-031`. Ringkasan laporannya:

```
HUNT-2027-031  report.md (ringkasan)
Hasil hipotesis : TIDAK TERBUKTI (tidak ada tanda penyerang memakai akun layanan
                  secara interaktif dalam 30 hari, di server dan workstation ber-EDR)
Temuan          : 1. svc-report dipakai Remote Desktop oleh developer (2027-08-12);
                     password diganti, akses Teguh ke JKT-RPT01 dibuat lewat akun sendiri
                  2. svc-legacyftp dan svc-crmold tidak aktif 30 hari; usul nonaktif
                  3. Log Security workstation tidak ada di Splunk; cek lewat Defender saja
Detection baru  : "Akun svc-* dengan Logon Type 2, 10, atau 11" (Splunk, terjadwal 15 menit)
Uji rule        : dijalankan mundur 30 hari: 2 hasil (keduanya sudah dijelaskan di atas);
                  perkiraan beban: sekitar 2 alert per bulan
Backlog baru    : HUNT-2027-032  scheduled task baru dengan nama mirip pembaru software
                                 dibuat beberapa menit setelah program dari folder
                                 Downloads atau Temp dijalankan (dari laporan sandbox
                                 SOC-2027-0872)
                  HUNT-2027-033  baseline Remote Desktop dari workstation ke server
```

Cara membacanya: hipotesis tidak terbukti, tetapi hunt ini menghasilkan tiga perbaikan nyata dan satu rule baru. Uji mundur 30 hari menghasilkan 2 alert, yaitu dua login yang memang ditemukan di bagian 2.1; artinya rule itu akan menangkap pola tersebut tanpa membanjiri antrean. Ide `HUNT-2027-032` lahir dari laporan sandbox siang tadi: teknik penyerang (menunggu, lalu membuat scheduled task bernama mirip pembaru PDF) sekarang menjadi hipotesis yang bisa diuji di semua laptop, termasuk untuk varian yang memakai alamat dan hash lain. Di situlah tiga arah deteksi proaktif bertemu: sandbox memberi perilaku, umpan memberi peringatan dini, dan hunt mengubah keduanya menjadi detection yang tidak perlu menunggu.

## 3. Perbandingan istilah yang sering tertukar

### 3.1 Triage alert, threat hunting, dan scoping insiden

Ketiganya memakai alat dan query yang mirip, sehingga sering dicampur. Tabel berikut membedakannya dari titik awal dan hasil; cari kolom "Titik awal" bila ragu sedang mengerjakan yang mana.

| Pekerjaan | Titik awal | Pertanyaan | Hasil | Contoh Day ini |
|---|---|---|---|---|
| Triage alert | Alert berbunyi | Benar atau tidak, seberapa mendesak? | Tutup, tuning, atau naik | `SOC-2027-0873` |
| Threat hunting | Hipotesis atau data | Ada yang belum memicu alert? | Temuan, celah, detection baru | `HUNT-2027-031` |
| Scoping insiden | Insiden yang sudah pasti | Apa lagi yang terkena? | Daftar perangkat, akun, data terdampak | Mencari hash di semua perangkat untuk `INC-2027-092` |

### 3.2 Analisis statis, analisis dinamis, sandbox, dan EDR

Empat istilah ini sering dianggap sama karena semuanya "memeriksa program". Tabel berikut membedakan apa yang dijalankan dan di mana.

| Istilah | Program dijalankan? | Di mana | Kekuatan | Kelemahan |
|---|---|---|---|---|
| Analisis statis | Tidak | Di mana saja | Cepat, aman | Buta terhadap isi yang dikemas |
| Analisis dinamis | Ya | Lingkungan terkendali | Melihat perilaku nyata | Bisa dikelabui sandbox evasion |
| Sandbox | Ya (alat untuk analisis dinamis) | Mesin virtual terisolasi | Aman bagi jaringan | Lingkungan buatan, waktu terbatas |
| EDR | Ya, oleh pengguna sungguhan | Perangkat produksi | Melihat serangan yang benar-benar terjadi | Hanya di perangkat yang dipasangi agen |

### 3.3 Honeypot, honeytoken, honey account, dan deception

Tabel berikut membedakan bentuk umpan dan tingkatannya; cari kolom "Bentuk" untuk menentukan istilah yang tepat.

| Istilah | Bentuk | Berbunyi bila | Contoh di PT JAB |
|---|---|---|---|
| Honeypot | Sistem atau layanan umpan | Disambangi, dipindai, dicoba login | `JKT-FS03` |
| Honeytoken | Data umpan (file, kunci, baris data) | Dibaca, dipakai, atau dibuka di mana pun | Dokumen `akun-server-lama-2025.xlsx` |
| Honey account | Honeytoken berbentuk akun | Tiketnya diminta atau dipakai login | `svc-sql-honey` |
| Canary token | Honeytoken yang memanggil pulang | Dibuka atau dipakai, termasuk di luar jaringan | Canary di dokumen umpan dan kunci AWS umpan |
| Deception | Strategi yang memakai semua umpan di atas | Tidak berbunyi sendiri; ia adalah rencananya | Program umpan PT JAB dengan tujuan Expose |

## 4. Salah paham umum

- **Anggapan:** threat hunting hanya untuk SOC besar dengan tim khusus. **Kenyataannya:** RA-10 menyerahkan frekuensi hunting ke organisasi [S3], dan hunt kecil berbasis satu hipotesis bisa dijalankan satu analyst dalam beberapa jam dengan SIEM dan EDR yang sudah ada, seperti `HUNT-2027-031`. Yang dibutuhkan pertama adalah data yang terkumpul dan waktu yang dilindungi dari antrean alert.
- **Anggapan:** file yang lolos gateway email dan sandbox sudah diperiksa dua kali, jadi aman. **Kenyataannya:** keduanya bisa memakai jenis pemeriksaan yang sama (menjalankan file sebentar di mesin virtual), sehingga program yang menunggu atau mengenali mesin virtual lolos dari keduanya. Itu yang terjadi pada `SOC-2027-0872`. Dua pemeriksaan yang sama jenisnya bukan pertahanan berlapis.
- **Anggapan:** honeypot dan honeytoken adalah jebakan untuk menangkap penyerang. **Kenyataannya:** di SOC perusahaan, umpan dipakai untuk mendeteksi, bukan menangkap atau membalas. Tindakan terhadap penyerang (memblokir, mengisolasi) tetap dilakukan di sistem PT JAB sendiri, dan informasi seperti alamat `192.0.2.205` diserahkan ke proses respons insiden.
- **Anggapan:** umpan yang sudah dipasang akan bekerja selamanya. **Kenyataannya:** D3FEND dan Engage sama-sama menekankan perawatan [S10][S12]. Dokumen umpan dengan tanggal tiga tahun lalu, honeypot yang tidak lagi cocok dengan pola penamaan, atau rule alert yang diam-diam dimatikan membuat umpan tidak berguna.
- **Anggapan:** detection baru dari hunt bisa langsung dinyalakan. **Kenyataannya:** rule baru diuji dulu ke data lama untuk melihat berapa banyak alert yang akan dihasilkan dan apakah alert itu bermakna, seperti uji mundur 30 hari di bagian 2.4. Rule yang membanjiri antrean memperburuk alert fatigue (kelelahan karena terlalu banyak alert, Day 11).

## 5. Catatan terkini

Bagian ini mencatat versi dokumen acuan, tanggal terbit, dan perubahan yang perlu diketahui saat membaca sumber lain.

- **NIST SP 800-53 RA-10:** control Threat Hunting ditambahkan di Rev. 5 (September 2020; versi final yang diperbarui 10 Desember 2020). Halaman publikasi NIST mencantumkan release 5.2.0 pada 27 Agustus 2025 sebagai rilis minor dengan control baru dan yang direvisi [S3]. Situs pemetaan control mencatat RA-10 tidak masuk baseline mana pun, jadi organisasi yang mengikuti baseline minimum bisa saja tidak memilikinya [S3].
- **Kerangka hunting:** PEAK diperkenalkan Splunk pada April 2023 oleh David Bianco, yang juga ikut membuat Sqrrl Threat Hunting Reference Model (pertama terbit 2015). Bianco menyebut kerangka lama seperti Sqrrl dan TaHiTI mulai menua dan PEAK dimaksudkan memasukkan pelajaran beberapa tahun terakhir [S4]. Banyak materi lama masih memakai istilah "hunting loop" dari Sqrrl; konsepnya sejalan dengan fase Prepare, Execute, Act di PEAK.
- **Advanced hunting Defender XDR:** per dokumentasi yang diperbarui Agustus 2026, advanced hunting mencakup sampai 30 hari data mentah Defender XDR; data yang lebih lama butuh workspace Microsoft Sentinel atau streaming ke penyimpanan lain [S7]. Bandingkan dengan masa simpan telemetri EDR enam bulan di Day 06 bagian 1.2: keduanya adalah batas yang berbeda untuk keperluan yang berbeda. Query bisa ditulis lewat mode guided (pembuat query) atau advanced (Kusto Query Language) [S7].
- **Deep analysis Defender for Endpoint:** per dokumentasi Juli 2026, Deep analysis hanya mendukung file PE dan tidak mendukung executable dari Windows App Store; pengumpulan sampel punya batas waktu 3 jam dan bisa ada jeda sampai 10 menit sebelum fitur tersedia setelah file dikirim [S8].
- **MITRE ATT&CK T1497:** halaman Virtualization/Sandbox Evasion versi 2.0 (diubah 11 September 2026) memetakan teknik ini ke tactic Stealth dan Discovery, dengan tiga sub-technique: System Checks, User Activity Based Checks, dan Time Based Checks [S13]. Dokumen lama menyebut tactic Defense Evasion; perubahan nama tactic dibahas di Day 14.
- **MITRE Engage:** situs Engage memakai matriks yang ditandai "Engage Matrix V1" dan membagi pekerjaan menjadi fase Prepare, Operate, Understand dengan tujuan Expose, Affect, Elicit [S10]. Kerangka pertahanan pendamping MITRE, D3FEND, memuat teknik seperti Dynamic Analysis dan Decoy User Credential yang dipakai di Day ini [S11][S12].

## 6. Cheat sheet

```
Deteksi proaktif     : tidak menunggu aturan berbunyi; hunt, sandbox, umpan
Threat hunting       : pencarian aktif ancaman yang lolos control; NIST SP 800-53 RA-10
Triage alert         : menilai alert yang sudah berbunyi (Day 11); titik awal = alert
Hipotesis            : "bila X, maka di data Y terlihat Z"; bisa diuji, cukup sempit
Hasil hipotesis      : terbukti / tidak terbukti / tidak bisa disimpulkan (data kurang)
Baseline             : gambaran normal dari data 30-90 hari; anomali belum tentu jahat
Jenis hunt (PEAK)    : hypothesis-driven, baseline (EDA), model-assisted (M-ATH)
Fase PEAK            : Prepare, Execute, Act with Knowledge
Hunt backlog         : daftar ide hunt yang menunggu
Sandbox              : lingkungan tertutup untuk menjalankan program tak dipercaya
Detonation           : menjalankan file di sandbox untuk melihat perilakunya
Analisis statis      : periksa tanpa menjalankan (nama, hash, tanda tangan, isi)
Analisis dinamis     : jalankan di lingkungan terkendali, amati proses/file/registry/jaringan
Sandbox evasion      : malware diam bila tahu diamati (T1497: system, user activity, time)
"Sandbox bersih"     : tidak ada perilaku terlihat selama pengamatan, bukan "aman"
Honeypot             : sistem umpan; sentuhan apa pun mencurigakan
Low-interaction      : tiruan layanan; murah, risiko kecil, info dasar
High-interaction     : sistem sungguhan; info kaya, risiko dan biaya tinggi
Honeytoken           : data umpan (file, akun, kunci) yang memicu alert saat disentuh
Canary token         : honeytoken yang memanggil pulang saat dibuka, juga di luar jaringan
Honey account        : akun umpan (mis. svc-sql-honey) untuk menangkap Kerberoasting
Deception            : strategi menyesatkan penyerang; proses, bukan produk (MITRE Engage)
Denial               : menghalangi atau melemahkan operasi penyerang
Engage goals         : Expose, Affect, Elicit
Act / hasil hunt     : insiden, temuan, celah visibilitas, detection baru, ide backlog
```

## 7. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Analyst L1 yang mengerjakan antrean alert sepanjang shift sudah melakukan threat hunting, karena ia mencari ancaman setiap hari." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Yang membedakan keduanya adalah titik awalnya. Antrean alert dimulai dari alert yang sudah berbunyi, dan pertanyaannya adalah apakah alert itu benar dan seberapa mendesak; itu triage. Threat hunting dimulai dari hipotesis atau data, dan pertanyaannya adalah apakah ada ancaman yang belum memicu alert sama sekali. Keduanya memakai alat yang sama, tetapi hasil wajarnya berbeda: keputusan per alert untuk triage, temuan atau detection baru untuk hunt. Lihat bagian 1.1 dan 3.1.

</details>

**2. Skenario keputusan.** Kamu ingin mengusulkan hunt tentang pencurian data. Hipotesis mana yang paling baik?

- A. "Ada data yang dicuri dari PT JAB dengan cara apa pun."
- B. "Bila penyerang mengambil data dari folder Keuangan, maka satu akun karyawan akan membaca jauh lebih banyak file di share Keuangan daripada biasanya dalam satu hari; terlihat di log akses file `JKT-FS01` 30 hari terakhir."
- C. "Cari semua anomali di semua log selama setahun terakhir."

<details><summary>Jawaban</summary>

B. Hipotesis ini bisa diuji (jumlah file yang dibaca per akun per hari bisa dihitung dan dibandingkan dengan biasanya), cukup sempit, dan menyebut sumber data serta rentang waktunya. A terlalu luas untuk dibuktikan benar atau salah, persis contoh yang dihindari kerangka PEAK. C bukan hipotesis sama sekali; tanpa cakupan, hunt seperti itu menghasilkan ribuan anomali tanpa kesimpulan. Lihat bagian 1.2 dan 4.

</details>

**3. Pertanyaan jebakan.** "Laporan Deep analysis untuk sebuah lampiran menyatakan tidak ada perilaku berbahaya. Jadi alert bisa ditutup sebagai tidak berbahaya." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Hasil sandbox yang kosong hanya berarti tidak ada perilaku yang terlihat selama waktu pengamatan, di lingkungan sandbox itu. Program jahat bisa menunda perilakunya, memeriksa tanda mesin virtual, atau menunggu aktivitas pengguna (MITRE T1497). Pada `SOC-2027-0872`, program menunggu 540 detik sebelum bekerja, dan laporan pertama kosong; temuan statis (ekstensi ganda, tanpa tanda tangan, baru dikompilasi, isi dikemas) seharusnya membuat analyst ragu. Penutupan juga perlu memeriksa apakah penerima lain menjalankan file itu. Lihat bagian 1.4, 1.5, dan 2.2.

</details>

**4. Skenario keputusan.** Alert honeypot `JKT-FS03` berbunyi dari `10.20.10.61` (`jkt-vscan01`, pemindai kerentanan internal) setiap Kamis pukul 14:00, tanpa percobaan login. Apa tindakan yang paling tepat?

- A. Matikan rule honeypot, karena sudah terbukti sering false positive.
- B. Beri pengecualian sempit: hanya alamat pemindai, jendela jadwal pemindaian, dan aktivitas tanpa login; alert lain dari alamat yang sama tetap berbunyi.
- C. Beri pengecualian penuh untuk alamat `10.20.10.61` kapan pun dan untuk aktivitas apa pun.

<details><summary>Jawaban</summary>

B. Pemindai yang menyapa semua alamat memang sah, tetapi pemindai juga bisa dikuasai penyerang; pengecualian sempit menghilangkan alert yang sudah dipahami tanpa membuat titik buta. A keliru karena satu sumber sah yang dikenal tidak membuat honeypot kehilangan nilainya; justru setiap sentuhan lain tetap sangat bermakna. C keliru karena penyerang yang menguasai pemindai bisa memakai alamat itu dengan bebas tanpa pernah memicu alert. Lihat bagian 1.6 dan 2.4.

</details>

**5. Jelaskan ulang.** Jelaskan kepada anggota keluargamu yang bukan orang IT, dalam tiga kalimat, apa itu honeytoken dan kenapa kantormu memasangnya.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Honeytoken itu seperti map berjudul 'Daftar Password' yang sengaja ditaruh di lemari arsip padahal isinya palsu, dan begitu map itu dibuka, alarm berbunyi. Karyawan biasa tidak punya alasan membuka map itu, jadi kalau ada yang membukanya, kemungkinan besar itu orang yang sedang mencari sesuatu yang tidak seharusnya. Ada juga jenis yang tetap 'menelepon pulang' walaupun mapnya sudah dibawa keluar gedung, sehingga kami tahu datanya sudah dicuri dan dari mana."

Kesalahan yang sering muncul:
- Menyebut honeytoken mencegah pencurian. Ia hanya memberi tahu; datanya memang sengaja palsu supaya pencuriannya tidak merugikan.
- Menyamakan honeytoken dengan honeypot. Honeypot adalah server umpan; honeytoken adalah data umpan.
- Mengatakan alarmnya tidak mungkin salah. Antivirus, backup, atau orang yang penasaran juga bisa menyentuhnya, jadi tetap diperiksa.

</details>

**6. Pertanyaan jebakan.** "`HUNT-2027-031` tidak menemukan penyerang, jadi hunt itu gagal dan tiga jam kerja Sari terbuang." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Hipotesisnya tidak terbukti, dan hasil itu sendiri adalah pengetahuan: dalam 30 hari tidak ada akun layanan yang dipakai penyerang untuk login interaktif di perangkat yang lognya terkumpul. Hunt itu juga menemukan satu pelanggaran kebijakan (`svc-report` dipakai Remote Desktop oleh developer), dua akun yang bisa dinonaktifkan, satu celah logging workstation, dan menghasilkan satu rule baru yang sudah diuji mundur 30 hari. Keberhasilan program hunt diukur dari apa yang ditinggalkannya, bukan hanya dari jumlah penyerang yang ditemukan. Lihat bagian 1.9 dan 2.4.

</details>

**7. Interview question (English).** "What is the difference between a honeypot and a honeytoken, and how would you use them in a corporate SOC?"

<details><summary>Sample answer</summary>

"A honeypot is a decoy system, for example a fake file server that nobody legitimately uses, so any connection to it is suspicious by design. A honeytoken is decoy data rather than a system: a fake credentials document on a file share, a decoy domain account with a service principal name, or a fake cloud access key. Some honeytokens, often called canary tokens, call home when they are opened, so they keep working even after the data has been stolen and opened outside the network. In a corporate SOC I would use them for early detection, mainly the Expose goal in MITRE Engage terms: low-interaction honeypots on internal segments to catch network discovery, a decoy service account to catch Kerberoasting, and decoy documents placed where past attackers actually went. I would treat their alerts as high priority, but still triage them, because vulnerability scanners, backup jobs or curious employees can touch them too, and I would add narrow exceptions rather than broad ones. And I would maintain them, because deception is a process: stale decoys stop fooling anyone."

What makes this answer strong: it separates system from data clearly, explains why the alerts are high fidelity, ties placement to real attacker paths, mentions the call-home property, and shows operational maturity with triage, narrow exceptions and maintenance instead of treating deception as a product.

</details>

## 8. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | NIST CSRC Glossary: honeypot | https://csrc.nist.gov/glossary/term/honeypot | primer (glosarium NIST) | diakses 2026-10-21 | Tinggi. Definisi CNSSI 4009-2022 dari RFC 4949; mencakup sistem dan sumber daya seperti file |
| S2 | NIST CSRC Glossary: sandbox | https://csrc.nist.gov/glossary/term/sandbox | primer (glosarium NIST) | diakses 2026-10-21 | Tinggi. Empat definisi (CNSSI 4009-2022, SP 800-95, SP 800-125, SP 1800-21B) |
| S3 | NIST SP 800-53 Rev. 5, control RA-10 Threat Hunting (teks control dan pembahasan); halaman publikasi SP 800-53 Rev. 5 | https://opensecurityarchitecture.org/controls/ra-10<br>https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final | primer (teks control NIST, dibaca lewat situs pemetaan control) dan primer (halaman publikasi NIST) | Rev. 5 2020-09, diperbarui 2020-12-10, release 5.2.0 2025-08-27; diakses 2026-10-21 | Tinggi untuk isi control. Teks RA-10 dibaca dari situs pihak ketiga yang menyalin teks NIST; status "tidak masuk baseline" berasal dari situs itu |
| S4 | Splunk: Introducing the PEAK Threat Hunting Framework (David Bianco) | https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html | sekunder (blog vendor, penulis kerangka) | 2023-04-18; diakses 2026-10-21 | Tinggi untuk kerangka PEAK. Definisi hunting, tiga jenis hunt, fase, hubungan dengan Sqrrl dan TaHiTI |
| S5 | Splunk: Hypothesis-Driven Hunting with the PEAK Framework (David Bianco) | https://www.splunk.com/en_us/blog/security/peak-hypothesis-driven-threat-hunting.html | sekunder (blog vendor, penulis kerangka) | 2023-05-08; diakses 2026-10-21 | Tinggi. Hipotesis yang bisa diuji dan sempit, langkah Prepare/Execute/Act, hasil negatif tetap didokumentasikan |
| S6 | Splunk: Baseline Hunting with the PEAK Framework (David Bianco, Ryan Fetterman) | https://www.splunk.com/en_us/blog/security/peak-baseline-hunting | sekunder (blog vendor, penulis kerangka) | 2023-07-11; diakses 2026-10-21 | Tinggi. Baseline 30 sampai 90 hari, anomali belum tentu jahat, keluaran baseline |
| S7 | Microsoft Learn: Advanced hunting overview in Microsoft Defender XDR | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview | primer (dokumentasi vendor) | ms.date 2026-08-07; diakses 2026-10-21 | Tinggi. 30 hari data, mode guided dan advanced, query dipakai untuk custom detection rule |
| S8 | Microsoft Learn: Take response actions on a file in Microsoft Defender for Endpoint (bagian Deep analysis) | https://learn.microsoft.com/en-us/defender-endpoint/respond-file-alerts | primer (dokumentasi vendor) | ms.date 2026-07-02; diakses 2026-10-21 | Tinggi. Sandbox cloud, Behaviors dan Observables, hanya file PE, batas waktu dan jeda |
| S9 | Microsoft Learn: 4624(S) An account was successfully logged on | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624 | primer (dokumentasi vendor) | ms.date 2021-09-07; diakses 2026-10-21 | Tinggi. Tabel Logon Type; event tercatat di komputer yang diakses; rekomendasi memantau akun layanan |
| S10 | MITRE Engage: beranda, matriks, dan What Is Adversary Engagement | https://engage.mitre.org/<br>https://engage.mitre.org/matrix/<br>https://engage.mitre.org/learn-more-ae | primer (kerangka MITRE) | diakses 2026-10-21 | Tinggi. Definisi cyber denial dan cyber deception, Expose/Affect/Elicit, deception sebagai proses |
| S11 | MITRE D3FEND: Dynamic Analysis (D3-DA) dan File Analysis (D3-FA) | https://d3fend.mitre.org/technique/d3f:DynamicAnalysis/<br>https://d3fend.mitre.org/technique/d3f:FileAnalysis/ | primer (kerangka MITRE) | diakses 2026-10-21 | Tinggi. Definisi analisis dinamis, keterbatasannya, dan teknik analisis file statis |
| S12 | MITRE D3FEND: Decoy User Credential (D3-DUC) | https://d3fend.mitre.org/technique/d3f:DecoyUserCredential/ | primer (kerangka MITRE) | diakses 2026-10-21 | Tinggi. Kredensial umpan, analitik pemakaiannya, kebutuhan lingkungan umpan dan perawatan |
| S13 | MITRE ATT&CK: Virtualization/Sandbox Evasion (T1497) | https://attack.mitre.org/techniques/T1497/ | primer (kerangka MITRE) | v2.0, diubah 2026-09-11; diakses 2026-10-21 | Tinggi. Tiga sub-technique, tactic Stealth dan Discovery |
| S14 | Canarytokens documentation: guide | https://docs.canarytokens.org/guide/ | sekunder (dokumentasi proyek Thinkst) | diakses 2026-10-21 | Tinggi untuk cara kerja canary token. Analogi sensor gerak, jenis token |
| S15 | CrowdStrike: What is a Honeypot? (Narendran Vaideeswaran) | https://www.crowdstrike.com/en-us/cybersecurity-101/exposure-management/honeypots/ | sekunder (materi edukasi vendor) | 2025-01-16; diakses 2026-10-21 | Sedang. Low vs high interaction, produksi vs riset, manfaat dan keterbatasan |

**Catatan sumber:** glosarium NIST tidak punya entri "threat hunting" maupun "honeytoken" per 2026-10-21, jadi definisi hunting diambil dari control RA-10 dan kerangka PEAK [S3][S4], sedangkan honeytoken dijelaskan dari definisi honeypot NIST yang mencakup file [S1] dan dari dokumentasi Canarytokens [S14]. Teks RA-10 dibaca lewat situs pemetaan control pihak ketiga yang menyalin teks NIST, bukan dari PDF NIST langsung; klaim bahwa RA-10 tidak masuk baseline mana pun juga berasal dari situs itu dan sebaiknya dicek di katalog SP 800-53B. Pembagian low-interaction dan high-interaction honeypot hanya bersumber dari materi edukasi vendor [S15]. Pola penulisan hipotesis "bila, maka, di, dan bukan" serta lima jenis keluaran hunt di bagian 1.9 adalah susunan catatan ini berdasarkan PEAK [S5], bukan format resmi. Mekanisme audit akses file untuk dokumen umpan ditulis secara umum tanpa nomor event karena tidak diperiksa di sumber primer. Seluruh isi PT JAB (hunt `HUNT-2027-031` sampai `033`, alert `SOC-2027-0872` sampai `0875`, insiden `INC-2027-092`, host `JKT-FS03`, `JKT-RPT01`, `jkt-sbx01`, `jkt-vscan01`, akun, hash, dan angka) adalah contoh fiktif.
