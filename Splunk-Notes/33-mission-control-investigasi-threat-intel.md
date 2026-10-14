---
day: 33
title: 'Mission Control, investigation, threat intelligence, dan annotations di ES 8'
researched_on: 2026-10-10
versions_checked: 'Splunk Enterprise Security 8.7 (Mission Control user guide; Create response plans; Included response plans; Respond to investigations with response plans; Threat intelligence administer guide; Configure threat lists; Add annotations to detections); ES 8.3 (daftar sumber threat intelligence dan generic intelligence bawaan; release notes 8.3); ES 8.0 dan 8.6 (Add new threat intelligence sources; ESCU annotations); Splunk Threat Intelligence Management (Cloud) dan Intel Management (Legacy, end of sale); MITRE ATT&CK v19.2'
---

# Day 33: Mission Control, investigation, threat intelligence, dan annotations di ES 8

Cakupan: tempat analyst ES 8 bekerja sehari-hari, perjalanan satu finding menjadi investigation yang tertutup dengan disposition, response plan berisi phase dan task, dua jalur threat intelligence di ES 8 beserta isi feed bawaannya, dan annotations yang membuat finding serta laporan cakupan bisa direkap.

## Ide inti

Pekerjaan analyst di ES 8 adalah satu putaran yang selalu sama bentuknya: finding muncul di antrean, analyst mengambilnya, mengubahnya menjadi investigation, menjalankan langkah yang sudah distandarkan, menambahkan konteks dari luar, lalu menutupnya dengan disposition. Yang menentukan kualitas putaran itu bukan kecepatan, melainkan dua hal yang mudah dilewati. Pertama, konteks: threat intelligence menjelaskan apakah sebuah artefak sudah dikenal berbahaya, dan annotation menjelaskan perilaku apa yang sebenarnya dideteksi. Kedua, catatan: investigasi yang benar tetapi tidak terdokumentasi menghasilkan metrik yang salah, tuning yang tidak pernah terjadi, dan pengetahuan yang hilang saat orangnya pindah kerja.

Bentuk pekerjaan ini sudah kamu kenal dari antrean tiket di NOC. Tiket yang tidak diberi kode kategori tetap selesai, tetapi tidak muncul di rekap bulanan mana pun, sehingga gangguan yang terulang tidak pernah terbukti berulang; itu persis yang terjadi pada detection tanpa annotation. Daftar indikator dari feed intel bekerja seperti daftar recall serial perangkat dari vendor: sangat berguna saat masih segar, menyesatkan setelah perangkat yang sama berganti pemilik. Dan satu insiden yang dipecah menjadi tiga tiket terpisah membuat laporan durasi penanganan tidak bisa dipercaya, sama seperti satu gangguan fiber yang dicatat tiga kali karena tiga pelanggan menelepon.

```
Detection (Day 36) ---> finding / finding group ---> analyst queue (Mission Control)
   annotation melekat sejak di sini                        |
                                                           v
                                                     investigation
                                                      |  |  |  |
   response plan: phase > task  -----------------------+  |  |  |
   threat list -> threat match -> observable -------------+  |  |
   note: hipotesis, bukti, penilaian, keterbatasan ---------+  |
   disposition lalu tutup -------------------------------------+
                                                           |
                                      rekap: index=notable, index=risk, laporan cakupan
```

Situasi yang dipakai sepanjang Day ini: Enterprise Security di PT Jaringan Anak Bangsa (PT JAB, ISP fiktif) baru jalan sebulan di search head terpisah, dan SOC lead membuka tiket kerja `SOC-2026-0276` untukmu:

> "Tiga analyst L1 menangani kasus mirip dengan cara berbeda. Kasus kemarin: finding group untuk `JKT-WS-0417` dan akun `rina.wulandari`, karena workstation itu menghubungi domain `update-cdn.example` yang ada di daftar indikator dari forum berbagi informasi antar ISP, dan di hari yang sama ada login VPN berhasil dari `203.0.113.77`. Satu analyst membuat tiga investigation untuk satu insiden, satu lagi menutup finding tanpa disposition, dan note-nya hanya berbunyi 'sudah dicek, aman'. Kami juga sudah mengunggah 40 IP dan 12 domain dari forum itu, tetapi tab Intelligence di investigation tetap kosong, dan dua match pertama ternyata IP yang sekarang dipakai layanan sah. Terakhir, laporan cakupan ATT&CK kita tidak menghitung detection berawalan `JAB - ` yang kita tulis sendiri."

Pesan itu memuat enam pertanyaan:

1. Finding, finding group, dan investigation itu beda apa, dan kapan satu insiden boleh punya lebih dari satu investigation?
2. Urutan kerjanya seperti apa, dan apa yang wajib tertulis supaya kasus ini masih bisa dibaca enam bulan lagi?
3. Bagaimana membuat tiga analyst mengerjakan kasus serupa dengan langkah yang sama?
4. Disposition apa yang dipilih, dan kenapa itu bukan formalitas?
5. Kenapa tab Intelligence kosong padahal indikatornya sudah diunggah, dan kenapa ada match ke IP yang sudah berganti pemilik?
6. Kenapa detection buatan sendiri tidak muncul di laporan cakupan?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2 sampai 1.4, pertanyaan 3 di bagian 1.5, pertanyaan 4 di bagian 1.6, pertanyaan 5 di bagian 1.7 sampai 1.9, dan pertanyaan 6 di bagian 1.10. Bagian 2 mengerjakan semuanya sebagai langkah di ES dan sebagai search.

**Kapan relevan:** setiap shift triage di ES; saat menyusun prosedur SOC supaya hasil kerja antar analyst sebanding; saat menambah atau mengevaluasi feed intel; saat memberi annotation pada detection kustom; saat menilai kualitas kerja tim dari data; dan saat menyiapkan bahan interview, karena pertanyaan "ceritakan satu investigasi yang kamu kerjakan" dijawab dari catatan seperti ini.
**Kapan bukan jawaban:** saat pertanyaannya bagaimana sebuah finding lahir dan bagaimana logika detection ditulis (Day 35 dan Day 36), saat yang dibutuhkan kerangka lima tahap investigasi beserta metrik MTTR dan dwell time (Day 34), saat alur triage yang dilatih adalah alur L1 tanpa ES (Day 07), dan saat yang dicari arti istilah ES 7 dibanding ES 8 atau peta dashboard ES (Day 31 dan Day 32).

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah Splunk dan ES dari Day sebelumnya (index, data model, detection, entity, risk score, `index=risk`) tidak diulang di sini. Tabel ini memuat istilah yang khusus dipakai di Day ini. Baca kolom padanan sebagai jembatan ke pekerjaan yang sudah kamu lakukan di NOC dan SOC, dan jangan melewatkan kolom yang membedakan jalur native dari jalur cloud, karena di situ letak kebingungan yang paling sering terjadi.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Mission Control | Antarmuka ES 8 tempat analyst melakukan triage, investigasi, dan respons, lengkap dengan timeline [S1] | Konsol NOC tempat tiket dikerjakan, bukan hanya dilihat |
| Analyst queue | Daftar finding dan finding group yang menunggu ditriage | Antrean tiket SOC |
| Finding | Satu hasil detection yang perlu dilihat analyst | Alert yang masuk antrean triage |
| Intermediate finding | Jejak risiko yang dikumpulkan, bukan untuk ditriage satu per satu | Entri log perangkat yang hanya dipakai saat menyusun kronologi |
| Finding group | Kumpulan finding dan intermediate finding yang terkait pada satu entity | Satu tiket induk untuk banyak keluhan dari gangguan yang sama |
| Investigation | Wadah terstruktur untuk mengumpulkan bukti dan menjalankan respons [S1] | Berkas kasus: kronologi, lampiran, dan tindakan dalam satu tempat |
| Response plan | Template berisi phase dan task yang diikuti analyst untuk satu jenis insiden [S2] | Runbook penanganan gangguan yang dicentang per langkah |
| Phase dan task | Tahap dan satuan pekerjaan di dalam response plan; task bisa memuat search, action, atau playbook [S2][S4] | Tahap penanganan dan langkah teknis yang bisa diverifikasi selesai |
| Disposition | Keputusan akhir atas sebuah finding: true positive, benign positive, false positive, undetermined [S4] | Kode penyelesaian tiket yang menjadi bahan rekap |
| Note investigasi | Catatan analisis bertanggal di dalam investigation, termasuk query yang dijalankan | Catatan teknisi di tiket, bukan hanya kalimat "sudah diperbaiki" |
| Threat Intelligence Framework | Mesin intel klasik di ES: unduh sumber, parse indikator, muat ke KV store collection, lalu cocokkan [S7] | Proses menarik daftar recall vendor lalu mencocokkannya ke inventaris |
| Threat source dan threat list | Satu sumber indikator yang dikonfigurasi di ES; di ES 8 istilah intelligence workflow menjadi threat list | Satu daftar perangkat bermasalah dari satu vendor |
| Threat match | Pencocokan otomatis indikator intel dengan event yang masuk | Pencocokan serial perangkat dengan daftar recall |
| Observable | Data yang menandakan sebuah event teramati di sistem, jaringan, atau entitas digital lain [S5] | Jejak teknis yang menyertai gangguan: serial, MAC, nomor sirkuit |
| Generic intelligence | Data referensi yang memperkaya event tanpa menjadi daftar ancaman, misalnya daftar TLD atau ASN [S7] | Tabel referensi inventaris dan pemetaan wilayah di NOC |
| STIX dan TAXII | Format dan protokol pertukaran intel terstruktur yang didukung ES [S8] | Format pertukaran data antar operator, bukan isinya |
| OpenIOC | Format XML lama untuk mendeskripsikan indikator, juga didukung ES [S8] | Format berkas lama yang masih dipakai mitra tertentu |
| Masa berlaku dan confidence indikator | Kolom yang menyatakan sampai kapan sebuah indikator dipercaya dan seberapa kuat dasarnya | Tanggal kedaluwarsa daftar recall dan kejelasan asalnya |
| Threat Intelligence Management (Cloud) | Layanan intel terkelola untuk ES cloud, disingkat TIM; Intel Management (Legacy) sudah end of sale [S9] | Layanan daftar recall yang dikelola pihak lain, bukan diunduh sendiri |
| Annotation | Metadata konteks pada detection dan analytic story, misalnya ID teknik ATT&CK atau nomor kontrol [S10] | Kode kategori yang ditempel ke tiket supaya bisa direkap |
| Managed dan unmanaged annotation | Managed disediakan Splunk dan diperkaya konteks standar; unmanaged adalah label kustom tanpa pengayaan [S10] | Kode kategori baku dari sistem tiket dibanding label bebas buatan tim |

### 1.1 Mission Control: tempat pekerjaan itu terjadi

Analyst yang baru dipindahkan ke ES biasanya bertanya "di mana saya bekerja", dan jawabannya satu tempat: Mission Control. Dokumentasi Splunk menempatkannya sebagai tempat analyst melakukan triage, investigasi, dan respons terhadap insiden, lengkap dengan timeline untuk melihat kapan finding terjadi [S1]. Finding dan finding group yang muncul di analyst queue dihasilkan oleh detection, baik dari raw event maupun dari alert pihak ketiga [S1].

Empat objek yang perlu dibedakan sebelum menyentuh apa pun. Perhatikan kolom terakhir, karena di situ terlihat mana yang lahir otomatis dan mana yang lahir dari keputusan analyst.

| Objek | Apa itu | Dibuat oleh |
|---|---|---|
| Finding | Satu hasil detection yang perlu dilihat analyst (istilah ES 7: notable event) | Event-based detection (Day 36) |
| Intermediate finding | Jejak risiko yang dikumpulkan, bukan untuk ditriage satu per satu (istilah ES 7: risk event) | Risk rule atau detection dengan output risiko (Day 35) |
| Finding group | Kumpulan finding dan intermediate finding yang terkait pada satu entity, hasil finding-based detection | Finding-based detection (Day 35) |
| Investigation | Wadah terstruktur untuk mengumpulkan bukti dan menjalankan respons [S1] | Analyst, dari satu atau beberapa finding |

Perbedaan penting dalam praktik: finding adalah pemicu, investigation adalah pekerjaan. Satu investigation bisa menampung banyak finding, dan justru itu gunanya. Untuk kasus `SOC-2026-0276`, request proxy ke `update-cdn.example`, login VPN dari `203.0.113.77`, dan finding group pada `JKT-WS-0417` adalah satu insiden yang sama, jadi satu investigation. Membuat satu investigation per finding untuk insiden yang sama menghasilkan metrik yang menyesatkan dan pekerjaan ganda, dan itulah yang terjadi pada analyst pertama di pesan SOC lead.

Investigation terpisah dibuat hanya ketika insidennya memang terpisah: entity lain, waktu lain, dan tidak ada hubungan sebab akibat yang bisa kamu tunjukkan. Bila ragu, gabungkan dulu, karena memecah satu investigation nanti lebih mudah daripada menyatukan tiga laporan yang sudah ditutup.

### 1.2 Alur kerja satu finding sampai tertutup

Dokumentasi ES 8.7 menyusun alur kerjanya seperti ini [S1]:

1. Ambil finding (assign ke diri sendiri), ubah statusnya, simpan.
2. Mulai investigation, lalu tinjau event, field, note, dan file di dalamnya.
3. Tambahkan response plan supaya langkahnya standar untuk jenis insiden itu.
4. Jalankan action dan playbook untuk mengumpulkan informasi tambahan.
5. Pakai sumber threat intelligence untuk memperbarui investigation dan menilai risiko observable.
6. Jaga investigation tetap mutakhir supaya analyst lain bisa mengikuti perkembangannya.
7. Beri disposition, lalu tutup investigation ketika insiden selesai.

Yang perlu ditambahkan dari sisi praktik, karena dokumentasi tidak menuliskannya:

- **Assign sebelum bekerja, bukan sesudah.** Dua analyst yang mengerjakan finding yang sama adalah pemborosan paling umum di shift yang sibuk.
- **Tulis hipotesis di note sejak awal.** Satu kalimat: "dugaan awal: `JKT-WS-0417` menghubungi domain dari daftar indikator karena ada loader, bukan karena aplikasi sah". Hipotesis yang tertulis membuat bias lebih mudah dikoreksi.
- **Catat yang tidak kamu temukan.** "Tidak ada proses baru di luar baseline dalam 2 jam setelah request pertama" adalah temuan, bukan kekosongan.
- **Cantumkan cakupan data.** Rentang waktu, index, dan keterbatasan (Day 43 bagian 1.7). Ini yang membedakan laporan yang bisa dipertahankan dari laporan yang hanya terdengar meyakinkan. Di PT JAB keterbatasan itu nyata, misalnya Sysmon baru terpasang di sekitar 40 persen workstation.

### 1.3 Investigation sebagai wadah bukti

Investigation yang sehat di kasus `SOC-2026-0276` berisi lima hal, dan masing-masing menjawab pertanyaan berbeda saat laporan dibaca ulang:

- **Events:** finding dan event pendukung yang kamu tambahkan dari hasil search, misalnya request proxy dan event VPN yang relevan.
- **Fields:** entity yang terlibat (`rina.wulandari`, `JKT-WS-0417`, `203.0.113.77`) yang menjadi poros pivot.
- **Notes:** catatan analisis bertanggal, termasuk query yang kamu jalankan.
- **Files:** lampiran seperti hasil ekspor, screenshot dashboard, atau laporan triage.
- **Timeline:** urutan kejadian, bukan urutan pekerjaanmu.

Bedakan dua jenis waktu itu secara sadar. Timeline insiden berisi kapan penyerang melakukan sesuatu. Riwayat pekerjaan berisi kapan kamu melakukan sesuatu. Keduanya perlu, tetapi mencampurnya membuat laporan sulit dibaca dan membuat perhitungan dwell time salah (Day 34).

### 1.4 Note yang masih berguna enam bulan kemudian

Kerangka note yang terbukti praktis cukup lima baris, dan bentuknya sama untuk kasus apa pun:

```
[2026-10-10 14:22] Hipotesis: JKT-WS-0417 menghubungi domain dari daftar indikator forum ISP (finding group FG-0276); dugaan awal loader, bukan aplikasi sah.
[2026-10-10 14:35] Dicek: index=proxy earliest=-7d dest=update-cdn.example -> 36 request, 1 host, semuanya antara 14:00 dan 14:30, user rina.wulandari.
[2026-10-10 14:50] Dicek: index=sysmon host=JKT-WS-0417 EventCode=1 dalam 2 jam setelah request pertama -> tidak ada proses baru di luar baseline (first-seen bersih, Day 40).
[2026-10-10 15:05] Penilaian: kemungkinan aplikasi pihak ketiga yang memakai domain bekas (keyakinan sedang). Indikator berumur 9 bulan dan tanpa tanggal terakhir terlihat. Keterbatasan: Sysmon di host ini baru aktif 3 hari.
[2026-10-10 15:10] Tindakan: minta konfirmasi vendor aplikasi (tiket SOC-2026-0276), turunkan confidence indikator di daftar, tambah hunt harian untuk domain yang sama di semua resolver.
```

Empat unsur yang harus selalu ada: hipotesis, bukti beserta query dan rentangnya, penilaian dengan tingkat keyakinan, dan keterbatasan. Unsur kelima yang membedakan analyst senior: tindakan lanjutan yang spesifik dan punya pemilik. Satu kebiasaan yang membuat note jauh lebih berguna: tulis query lengkap beserta rentang waktunya di dalam note, bukan hanya kesimpulannya. Enam bulan kemudian, query itu yang membuat temuanmu bisa diulang. Note "sudah dicek, aman" gagal pada keempat unsur sekaligus, dan itu sebabnya kasus seperti itu tidak bisa dipakai saat kasus serupa muncul lagi.

### 1.5 Response plan: phase dan task

Keluhan SOC lead bahwa tiga analyst menangani kasus mirip dengan cara berbeda adalah masalah yang memang disediakan jawabannya oleh ES. Response plan adalah template berisi phase dan task yang diikuti analyst supaya investigasi untuk jenis insiden yang sama mendapat penanganan standar [S2]. ES 8 menyertakan beberapa plan bawaan, antara lain NIST 800-61 (fase dan task berdasar panduan penanganan insiden NIST) dan Generic Incident Response (fase dari deteksi sampai review) [S3].

Yang perlu diketahui saat membuat plan sendiri [S2]:

- Plan dibangun dari phase, dan setiap phase berisi task.
- Deskripsi task mendukung Markdown, jadi langkah bisa ditulis rapi dengan daftar dan blok kode.
- Satu task bisa dilampiri action atau playbook (Day 41 dan Day 42), sehingga analyst tidak perlu berpindah antarmuka.
- Satu task bisa memuat search yang bisa dijalankan langsung dari task itu. Saat dijalankan dari tab Response, search bawaan task berjalan untuk 24 jam terakhir secara default [S4].
- Plan hanya bisa dipasang ke investigation setelah statusnya Published.
- Plan bisa diimpor dari file JSON, dan JSON adalah satu-satunya format yang didukung.
- Plan bisa dipasang ke satu investigation saat bekerja, atau diikat ke sebuah investigation type supaya setiap investigation baru dengan jenis itu otomatis memakainya [S4].

Cara memakai fitur ini dengan baik: jangan menyalin prosedur panjang apa adanya. Satu task yang baik berbunyi seperti perintah yang bisa dijalankan dan diverifikasi ("jalankan search X untuk rentang Y, catat jumlah host terdampak"), bukan seperti kebijakan ("pastikan dampak dinilai dengan tepat").

### 1.6 Disposition dan penutupan

Saat menutup, analyst memberi disposition. Pilihan intinya di ES 8 mencakup true positive, benign positive, false positive, dan undetermined, dengan rincian seperti false positive karena logika analitik yang salah atau karena data tidak akurat (Day 34) [S4].

Kenapa ini bukan formalitas:

- Disposition adalah sumber data untuk mengukur kualitas detection. Tanpa itu, tidak ada cara objektif menentukan detection mana yang perlu di-tuning (Day 34).
- Benign positive memberi informasi berbeda dari false positive. Benign positive berarti deteksimu benar dan aktivitasnya nyata, tetapi diizinkan. Perbaikannya ada di allowlist yang terkelola (Day 40), bukan di logika.
- False positive karena data tidak akurat mengarahkan perbaikan ke onboarding (Day 28), bukan ke search.

Untuk kasus `SOC-2026-0276`, bila ternyata domain itu memang dipakai aplikasi pihak ketiga yang sah, dispositionnya benign positive dan tindak lanjutnya dua: baris allowlist dengan tanggal kedaluwarsa, dan penurunan confidence indikator di daftar intel. Menuliskannya sebagai false positive akan menyembunyikan dua hal sekaligus, yaitu bahwa deteksinya bekerja dan bahwa sumber intelnya yang lemah.

Aturan yang membuat metrik tetap bersih: disposition diberikan oleh orang yang mengerjakan, pada hari yang sama, dan selalu disertai satu baris alasan di note.

### 1.7 Dua jalur threat intelligence di ES 8

Ini bagian yang paling sering membuat bingung, dan perlu dibaca dengan teliti karena berbeda antar deployment. Tab Intelligence yang kosong di PT JAB bukan kesalahan konfigurasi indikator, melainkan akibat dua jalur yang terpisah.

**Jalur native (Threat Intelligence Framework klasik).** Modular input `threatlist` mengunduh atau membaca file yang diunggah, memparsenya, lalu menambahkan indikator ke koleksi KV store ES [S5]. Dari sana, threat matching search mencocokkan indikator dengan event dan menghasilkan finding. Alurnya tetap sama di dokumentasi ES 8: sumber intel diunduh, indikator diurai, dimuat ke KV store collection, lalu dipakai untuk threat matching [S7]. Format yang didukung mencakup berbagai jenis daftar indikator serta STIX dan OpenIOC [S6]. Jalur ini yang dipakai sebagian besar deployment self-managed, termasuk PT JAB.

**Jalur Threat Intelligence Management (Cloud), disingkat TIM.** Di ES 8.7, halaman konfigurasi threat list menyatakan dirinya berlaku hanya untuk pengguna TIM (Cloud), bukan untuk native threat intelligence [S5]. Di jalur ini kamu bisa membuat sampai lima threat list dari indikator yang dipublikasikan sumber data TIM, untuk dipakai di threat matching dan pengayaan investigasi. Setiap threat list punya tiga bagian yang bisa disesuaikan: detail, sumber intelijen, dan tipe daftar (misalnya indicator prioritization) [S5]. TIM tersedia otomatis untuk ES cloud versi 6.6 ke atas di region AWS tertentu, sedangkan Splunk Intel Management (Legacy) sudah end of sale [S9]; status terkini dan ketersediaannya untuk deployment on-prem perlu dicek di halaman rilis ES versimu.

Konsekuensi praktis yang wajib kamu ingat: halaman Intelligence di dalam sebuah investigation menampilkan data dari TIM (Cloud) saja, bukan dari koleksi KV store native [S5]. Jadi bila lab atau produksimu memakai jalur native lalu membuka tab Intelligence dan melihatnya kosong, pembuktian keberadaan indikator dilakukan dengan `| inputlookup` ke koleksinya (bagian 2.3), bukan di tab itu.

Istilah pendamping yang berubah di ES 8: intelligence workflow menjadi threat list, dan threat object atau indicator menjadi observable, yaitu data yang menandakan sebuah event teramati di sistem, jaringan, atau entitas digital lain [S5]. Istilah ES 7 masih beredar di dokumentasi dan tulisan lama (Day 31).

### 1.8 Isi yang sudah disediakan ES: sumber bawaan, format, dan jenis IOC

Sebelum menambah feed sendiri, pantas diketahui apa yang sudah dibawa ES, karena sebagian pertanyaan "kita perlu beli intel apa" terjawab dari daftar ini [S7]:

- **Sumber threat intelligence bawaan:** Emerging Threats (daftar IP yang dianggap terkompromi dan firewall IP rules), SANS blocklist, beberapa daftar I-Blocklist (Tor, Spyware, Web attacker, Proxy, dan lainnya), Malware domain host list lewat Hail a TAXII, dan Phishtank.
- **Generic intelligence**, yaitu data yang memperkaya event dan bukan daftar ancaman: Cisco Umbrella 1M sites, daftar TLD ICANN, MaxMind GeoIP ASN, Mozilla Public Suffix List, dan MITRE ATT&CK.

Untuk feed milik sendiri, metode dan format yang didukung mencakup STIX dan TAXII, OpenIOC, file terstruktur, API atau URL, dan database. Penambahan feed TAXII dilakukan lewat Configure > Threat Intelligence; nama menunya di ES 8.7 perlu dicek karena susunan menu berubah antar versi [S8]. Jenis IOC yang dikenali ES mencakup sembilan kelompok: sertifikat X509, email, file (nama dan hash), HTTP, IP dan domain, proses, registry, service, dan user [S8]. Tiap kelompok punya koleksi KV store sendiri, jadi indikator yang dimasukkan ke kelompok yang salah tidak akan pernah menghasilkan match.

Keputusan yang sering diabaikan: mengaktifkan semua sumber bawaan sekaligus terdengar aman, tetapi menghasilkan noise yang menumpuk di antrean. Untuk PT JAB sebagai ISP, daftar Tor dan proxy akan menghasilkan banyak match yang maknanya kebijakan, bukan malware, karena pelanggan broadband memang memakai layanan itu. Aktifkan per sumber, ukur hasilnya selama satu atau dua minggu dengan bagian 2.3 dan 2.4, lalu putuskan.

### 1.9 Masa berlaku dan confidence: kenapa match bisa menyesatkan

Dua match ke IP yang sekarang dipakai layanan sah adalah gejala yang bisa diperkirakan, bukan kecelakaan. Indikator technical cepat basi. IP di cloud publik atau hosting murah berganti penyewa dalam hitungan hari, domain bisa di-sinkhole atau kedaluwarsa, sedangkan hash tetap valid tetapi mudah diganti penyerang. Aturan praktis yang banyak dipakai tim SOC adalah memberi IP masa berlaku pendek (mingguan sampai bulanan), domain sedikit lebih panjang, dan hash paling panjang. Angka persisnya keputusan tim, jadi tulis kebijakannya dan terapkan konsisten. Feed yang tidak mencantumkan tanggal pertama atau terakhir terlihat sebaiknya diberi confidence lebih rendah.

Karena itu setiap daftar indikator, baik yang masuk ke ES maupun yang dipakai sendiri, sebaiknya punya kolom yang sama: `indicator`, `type`, `source`, `first_seen`, `expires`, dan `confidence`. Kolom `expires` dipakai untuk membuang baris yang sudah lewat masa berlakunya sebelum hasilnya dilihat analyst, dan `confidence` dipakai saat membaca hasil: match dengan confidence rendah dan sumber tunggal adalah petunjuk untuk diperiksa, bukan kesimpulan. Match yang muncul di beberapa sumber, atau yang cocok dengan perilaku lain di host yang sama, layak naik prioritas. Bentuk search-nya ada di bagian 2.9.

### 1.10 Annotations: label konteks yang membuat rekap mungkin

Laporan cakupan yang tidak menghitung detection berawalan `JAB - ` punya satu sebab yang hampir selalu benar: detection itu belum diberi annotation. Annotation adalah metadata yang ditempelkan pada detection, dan juga pada analytic story, untuk memetakan detection ke framework dan konteks [S10].

Empat tujuannya, diurutkan dari yang paling sering terasa manfaatnya:

1. **Konteks bagi analyst:** finding menunjukkan teknik ATT&CK atau kontrol terkait, sehingga analyst langsung tahu perilaku apa yang dicurigai tanpa membuka isi search.
2. **Pelaporan cakupan:** berapa teknik atau kontrol yang ditangani detection aktif, yang di ES 8.7 terlihat di Detection Studio (Day 27).
3. **Agregasi risiko:** event risiko membawa annotation, sehingga bisa dianalisis per taktik dan teknik di Risk Analysis (Day 35) [S10].
4. **Kepatuhan:** memetakan detection ke kontrol (CIS, NIST, PCI DSS) untuk audit, sehingga auditor dilayani dengan data yang sama yang dipakai analyst.

Cakupan dan sifatnya [S10]:

- **Framework managed di ES 8.7:** MITRE ATT&CK, CIS Critical Security Controls, NIST Cybersecurity Framework, Lockheed Martin Cyber Kill Chain, ditambah PCI DSS 4.0.
- **Annotation dari ESCU:** Analytic Story, Confidence, Context, dan Impact [S11].
- **Managed dibanding unmanaged:** managed disediakan Splunk atau ESCU dan diperkaya konteks standar seperti deskripsi teknik, platform, dan URL; unmanaged adalah label kustom tanpa pengayaan itu.
- **Di mana disimpan dan terlihat:** JSON di `savedsearches.conf` pada `action.correlationsearch.annotations`; field `annotations.<framework>.<field>` pada event; label di Mission Control (analyst queue) dan dashboard Risk Analysis; bisa dicari di `index=risk`. Annotation unmanaged muncul di `annotations._all` dan `annotations._frameworks`.
- **Framework tambahan:** bisa dibuat sendiri dengan tiga komponen, yaitu intelligence download, lookup definition, dan automatic lookup, misalnya dengan mengkloning konfigurasi ATT&CK.

Yang bukan annotation: annotation tidak mengubah logika deteksi. Ia label konteks. Detection tanpa annotation tetap berjalan dan tetap menghasilkan finding, tetapi analyst kehilangan konteks dan laporan cakupan menjadi bolong. Itu sebabnya jawaban untuk SOC lead bukan "laporan cakupannya salah", melainkan "detection kita belum dianotasi, dan ini daftarnya" (bagian 2.8 memberi cara membuat daftar itu).

**Tanpa ES:** seluruh pola di Day ini bisa dilatih dan dijalankan di Splunk Enterprise biasa, karena yang dilatih sebenarnya disiplin kerja dan bukan fitur. Antrean finding diganti alert Wazuh atau hasil scheduled search (Day 09), investigation diganti satu case di TheHive atau satu file Markdown per kasus, response plan diganti checklist phase dan task di file yang sama dengan task berisi query lengkap, dan disposition diganti satu field di catatanmu dengan nilai yang persis sama seperti di ES supaya kebiasaannya terbawa. Threat match ditiru dengan lookup CSV yang punya kolom masa berlaku dan confidence (bagian 2.9), dan annotation ditiru dengan lookup pemetaan detection ke teknik ATT&CK yang ditempel ke hasil detection (bagian 2.10). Yang hilang hanya pengelolaan terpusat, pengayaan konteks framework managed, dan tampilannya di antrean analyst serta dashboard risiko [S10].

## 2. Contoh SPL dan langkah di ES

Semua keluaran di bagian ini adalah keluaran ilustrasi dari lingkungan PT JAB, bukan hasil eksekusi. ES dideskripsikan generik; nama menu dicocokkan ke dokumentasi ES 8.7 dan perlu dicek bila versimu berbeda. Lima contoh pertama mengerjakan tiket `SOC-2026-0276` berurutan, sisanya mengukur hasil kerja dan menyiapkan pengganti untuk lab tanpa ES.

### 2.1 Triage satu finding, langkah demi langkah

**Tujuan:** menjalankan satu finding dari antrean sampai tertutup dengan urutan yang sama setiap kali.

1. Buka Mission Control, urutkan analyst queue berdasarkan urgency, lalu pilih satu finding.
2. Assign ke dirimu dan ubah status menjadi in progress. Ini mencegah pekerjaan ganda [S1].
3. Baca finding-nya sendiri dulu: detection apa yang memicunya, entity apa yang terlibat, annotation ATT&CK apa yang terbawa (bagian 1.10 dan Day 30).
4. Buat investigation dari finding itu, atau tambahkan ke investigation yang sudah ada bila insidennya sama (bagian 1.1).
5. Tulis note hipotesis (bagian 1.4) sebelum menjalankan search apa pun.
6. Tambahkan response plan yang sesuai jenis insiden lewat tab Response [S4].
7. Kerjakan task satu per satu. Jalankan search bawaan task dan sesuaikan rentang waktunya, karena default-nya 24 jam terakhir [S4].
8. Tambahkan event pendukung dan field entity ke investigation supaya timeline terbentuk.
9. Jalankan action atau playbook bila diperlukan, misalnya lookup reputasi atau pengumpulan artefak (Day 41 dan Day 42).
10. Periksa observable yang menyertai finding terhadap sumber intel yang tersedia (bagian 2.3 dan 2.4).
11. Tulis note penilaian, beri disposition, lalu tutup.

**Kapan gagal:** bila finding sudah lebih tua dari rentang default task, search bawaan task akan mengembalikan nol baris walau langkahnya benar. Ubah rentangnya sebelum menyimpulkan tidak ada bukti [S4].

### 2.2 Langkah di ES untuk intel dan annotation

**Tujuan:** menambah sumber intel sendiri dan memberi annotation pada detection kustom, dua pekerjaan yang membuat kasus `SOC-2026-0276` tidak terulang sebagai pertanyaan yang sama.

1. **Intel:** buka Configure > Threat Intelligence (atau menu threat list bila deployment-mu memakai TIM), periksa feed bawaan, aktifkan hanya yang relevan, lalu tambahkan feed TAXII atau CSV milik sendiri [S8]. Untuk PT JAB, 40 IP dan 12 domain dari forum ISP masuk sebagai satu sumber dengan nama yang menyebut asalnya, supaya kualitasnya bisa dievaluasi terpisah dari feed lain.
2. **Annotation:** buka Configure > Content management, pilih detection, buka bagian Annotations, lalu tambahkan ATT&CK, CIS, NIST, atau Kill Chain [S10]. Lakukan untuk semua detection berawalan `JAB - `.
3. Verifikasi di finding (analyst queue) bahwa label annotation muncul, dan di `index=risk` bahwa field `annotations.*` terisi (bagian 2.8).

**Kapan gagal:** framework kustom yang dibuat tanpa automatic lookup akan tersimpan tetapi tidak muncul sebagai label, karena pengayaannya tidak pernah dijalankan [S10].

### 2.3 Memeriksa isi koleksi intel dan membuktikan indikator masuk

**Tujuan:** membuktikan bahwa indikator yang diunggah benar-benar tersimpan, dan melihat feed mana yang menyumbang paling banyak.

```
| inputlookup ip_intel
| stats count BY threat_key
| sort - count
```

- `ip_intel` adalah koleksi indikator IP di Threat Intelligence Framework. Koleksi lain mengikuti jenis IOC (file, http, email, certificate, process, registry, service, user) [S6][S8], jadi cek nama persisnya di instance-mu, karena nama koleksi bawaan berbeda antar versi.
- `threat_key` menunjukkan sumber atau feed asal indikator; nama field ini perlu dicek karena berbeda antar versi.

Keluaran ilustrasi:

```
threat_key                     count
emerging_threats_compromised   28431
iblocklist_tor                  9276
forum_isp_2026_10                 40
phishtank                       1854
```

**Cara membaca hasil:** feed yang menyumbang puluhan ribu indikator berkualitas rendah adalah calon sumber false positive, sedangkan 40 indikator dari forum ISP adalah daftar kecil yang bisa dievaluasi satu per satu. Jumlah besar bukan tanda kualitas.

Untuk membuktikan satu indikator tertentu, cari barisnya langsung:

```
| inputlookup ip_intel | search ip=203.0.113.77 | table ip threat_key description
```

Pola yang sama dipakai untuk koleksi lain, misalnya `| inputlookup threat_group_intel | stats count BY threat_key` untuk melihat intel per kelompok ancaman.

**Kapan gagal:** koleksi kosong biasanya berarti feed nonaktif, unduhan gagal karena proxy atau firewall, atau parsing gagal, bukan indikator yang salah. Dan bila indikator masuk ke kelompok IOC yang salah, baris ini ada tetapi threat match tidak pernah terjadi (bagian 1.8).

### 2.4 Aktivitas yang cocok dengan intel

**Tujuan:** melihat threat match yang benar-benar terjadi di data, bukan sekadar isi daftar indikator.

```
| tstats summariesonly=false count from datamodel=Threat_Intelligence.Threat_Activity
    by Threat_Activity.threat_match_field Threat_Activity.threat_match_value Threat_Activity.threat_collection
| rename Threat_Activity.* AS *
| sort - count
```

- Data model Threat_Intelligence dengan dataset Threat_Activity berasal dari ES, bukan dari CIM umum, jadi nama dan field-nya perlu dicek di ES 8.7.
- `summariesonly=false` dipakai supaya hasilnya tidak bergantung pada status acceleration (Day 25 dan Day 26).

Keluaran ilustrasi:

```
threat_match_field  threat_match_value     threat_collection  count
query               update-cdn.example     domain_intel          36
dest                203.0.113.77           ip_intel               4
dest                198.51.100.212         ip_intel             612
```

**Cara membaca hasil:** 612 match ke satu IP dari banyak host adalah pola feed yang basi atau IP yang berganti pemilik, bukan 612 insiden. Match pada `dest` ke IP Tor bisa berarti user memakai Tor (pelanggaran kebijakan), bukan malware. Dan 36 match pada `query` dari satu host, seperti pada kasus `SOC-2026-0276`, adalah yang layak diinvestigasi karena terkonsentrasi pada satu entity.

**Variasi:** tambahkan `BY Threat_Activity.src` untuk melihat sebaran host, lalu bandingkan jumlah host unik dengan jumlah match. Rasio satu host untuk ratusan match berarti perilaku berulang, sedangkan ratusan host dengan satu match masing-masing hampir selalu masalah kualitas feed.

### 2.5 Kerangka response plan untuk kasus akun terkompromi

**Tujuan:** menyediakan satu plan yang membuat tiga analyst L1 PT JAB mengerjakan kasus serupa dengan langkah yang sama. Isi task ditulis sebagai perintah yang bisa diverifikasi.

```
PHASE 1  Validasi
  T1.1  Pastikan finding bukan hasil uji: cek tiket purple team 24 jam terakhir.
  T1.2  Search: index=wineventlog user=<user> earliest=-7d | stats count BY action src
        Catat: jumlah gagal, waktu sukses pertama, IP sumber.
  T1.3  Cek first-seen IP sumber dan domain lewat tabel first-seen milikmu (Day 40). Catat umur entitas.
  T1.4  Cek observable finding terhadap sumber intel (bagian 2.3). Catat feed asal, umur indikator, dan confidence.

PHASE 2  Penilaian dampak
  T2.1  Search proses di host tujuan 2 jam setelah login sukses atau request pertama.
  T2.2  Cek akses ke share dan aplikasi sensitif oleh akun itu.
  T2.3  Tentukan apakah akun punya hak administratif (Asset and Identity, Day 26).

PHASE 3  Penanggulangan
  T3.1  Reset kredensial dan cabut sesi aktif. Catat nomor tiket.
  T3.2  Blokir IP atau domain sumber bila masih aktif. Lampirkan playbook (Day 42).
  T3.3  Konfirmasi dengan pemilik sistem sebelum tindakan yang mengganggu layanan pelanggan.

PHASE 4  Penutupan dan umpan balik
  T4.1  Tulis note penilaian dengan keyakinan dan keterbatasan.
  T4.2  Beri disposition dan alasan satu baris.
  T4.3  Bila FP: buat tiket tuning. Bila BP: tambah baris allowlist dengan expires_at (Day 40) dan turunkan confidence indikator yang memicunya.
  T4.4  Bila TP: usulkan detection atau hunt baru dari apa yang terlewat, dan pastikan detection itu punya annotation.
```

Plan diimpor ke ES sebagai JSON, dan JSON adalah satu-satunya format yang didukung [S2]. Cara teraman mendapat struktur JSON yang benar: buat satu plan sederhana di UI, ekspor, lalu pakai hasil ekspor itu sebagai template, karena skemanya bisa berbeda antar versi.

**Kapan gagal:** plan yang masih berstatus draft tidak bisa dipasang ke investigation, berapa pun rapinya isinya [S2].

### 2.6 Distribusi disposition per detection

**Tujuan:** mengubah disposition menjadi keputusan tuning, bukan sekadar kolom yang terisi.

Finding di ES tetap bisa dianalisis dengan SPL. Nama index dan macro bisa berbeda antar versi, jadi mulai dengan memastikan mana yang tersedia di instance-mu:

```
| rest /services/data/indexes | search title IN ("notable","risk","finding*") | table title currentDBSizeMB totalEventCount
```

Bila index notable tersedia, distribusi disposition per detection bisa dilihat seperti ini:

```
index=notable earliest=-30d
| stats count BY search_name disposition
| eventstats sum(count) AS total BY search_name
| eval persen=round(count/total*100,1)
| where disposition IN ("false positive","FP - Incorrect Analytic Logic","FP - Inaccurate Data")
| sort - persen
| head 15
```

Keluaran ilustrasi:

```
search_name                              disposition                  count  total  persen
JAB - Proses dari folder profil user     FP - Incorrect Analytic Logic  41     52     78.8
JAB - Login dari negara tidak lazim      FP - Inaccurate Data           18     30     60.0
```

**Cara membacanya:** detection pertama bermasalah di logika, jadi perbaikannya ada di search dan allowlist. Detection kedua bermasalah di data, jadi perbaikannya ada di onboarding atau di lookup geolokasi (Day 28). Dua masalah yang terlihat sama di antrean analyst punya akar yang sangat berbeda.

**Kapan gagal:** nilai `disposition` tersimpan sebagai ID numerik di sebagian versi, sehingga perlu dipetakan lewat lookup bawaan ES. Cek bentuk nilainya sebelum membuat dashboard di atasnya.

### 2.7 Mengukur mutu triage sendiri

**Tujuan:** melihat apakah antrean dikerjakan sesuai urgency, dan apakah ada finding yang menggantung tanpa pemilik.

```
index=notable earliest=-30d
| eval waktu_ambil=review_time-_time, waktu_tutup=close_time-_time
| stats count p50(waktu_ambil) AS p50_ambil_detik p50(waktu_tutup) AS p50_tutup_detik BY urgency
| eval p50_ambil_menit=round(p50_ambil_detik/60,1), p50_tutup_jam=round(p50_tutup_detik/3600,2)
| table urgency count p50_ambil_menit p50_tutup_jam
```

Nama field waktu tinjauan dan penutupan bergantung versi ES, jadi periksa dulu field apa yang tersedia pada satu finding yang sudah tertutup. Yang dicari bukan angka absolut, melainkan dua hal: apakah finding urgency tinggi diambil lebih cepat daripada yang rendah, dan apakah ada finding yang menggantung berhari-hari tanpa pemilik.

**Variasi:** tambahkan `BY owner` untuk melihat sebaran beban antar analyst, dan jalankan versi tanpa filter disposition untuk menemukan finding yang ditutup tanpa disposition sama sekali.

### 2.8 Annotation pada event risiko

**Tujuan:** melihat detection mana yang menghasilkan risiko per taktik dan teknik, dan menemukan detection yang belum punya annotation.

```
index=risk earliest=-7d
| stats count dc(risk_object) AS entities values(source) AS detections
    BY annotations.mitre_attack.mitre_tactic annotations.mitre_attack.mitre_technique_id
| sort - count
```

Keluaran ilustrasi:

```
mitre_tactic   mitre_technique_id  count  entities  detections
Persistence    T1053.005             37      9      JAB - Scheduled task dari folder publik
Execution      T1059.001            122     31      JAB - PowerShell encoded command, ESCU - ...
Command and Control  T1071.001       36      1      JAB - Domain dari daftar indikator forum
```

- Kualitas hasil query ini sama dengan kualitas annotation yang diisi engineer [S10]. Detection tanpa annotation tidak muncul sama sekali, dan itulah yang membuat laporan cakupan PT JAB terlihat bolong.
- Untuk melihat label kustom, pakai `| stats count BY annotations._frameworks`, dan untuk seluruh label gabungan `annotations._all`; keduanya diisi oleh annotation unmanaged [S10].

**Variasi:** untuk mendapat daftar kerja detection yang belum dianotasi, baca konfigurasinya langsung, misalnya dengan `| rest /servicesNS/-/SplunkEnterpriseSecuritySuite/saved/searches` lalu `spath` pada `action.correlationsearch.annotations` dan saring yang kosong (Day 29).

**Kapan gagal:** `risk_object` adalah nama field klasik di risk index, sedangkan UI ES 8 menyebutnya entity; cek nama field di instance-mu sebelum membuat dashboard di atasnya.

### 2.9 Threat match dengan lookup di Splunk Enterprise biasa

**Tujuan:** meniru threat match di Splunk Enterprise biasa, sekaligus menegakkan masa berlaku indikator yang di bagian 1.9 disebut sebagai syarat agar hasilnya tidak menyesatkan.

Strukturnya cukup sederhana: satu baris per indikator dengan kolom `indicator`, `type`, `source`, `first_seen`, `expires`, dan `confidence`. Search lalu mencocokkan field data (misalnya `dest_ip` atau `query`) ke kolom `indicator`, dan hanya memakai baris yang belum kedaluwarsa:

```
index=dns earliest=-24h
| stats count min(_time) AS first max(_time) AS last BY src query
| lookup lab_ioc.csv indicator AS query OUTPUT type source expires confidence
| where isnotnull(source) AND strptime(expires, "%Y-%m-%d") > now()
| convert ctime(first) ctime(last)
```

- `lookup` ditaruh setelah `stats`, sehingga pencocokan hanya dilakukan pada nilai unik, bukan pada setiap event (Day 12). Di PT JAB ini penting karena index `dns` adalah index terbesar.
- `where ... expires > now()` membuang indikator yang sudah lewat masa berlakunya. Tanpa ini, IP yang dulu dipakai C2 dan kini dipakai layanan sah tetap memicu match, persis seperti dua match yang dikeluhkan SOC lead.

Keluaran ilustrasi:

```
src           query                count  first                 last                  type    source             expires     confidence
10.10.14.41   update-cdn.example       6   10/10/2026 14:03:11   10/10/2026 14:28:40   domain  forum_isp_2026_10  2026-12-31  medium
```

**Cara membaca hasil:** `10.10.14.41` adalah alamat `JKT-WS-0417`, jadi enam request dalam 24 jam di sini adalah bagian dari 36 request selama tujuh hari yang tercatat di note kasus `SOC-2026-0276`. Match dengan confidence rendah dan sumber tunggal adalah petunjuk untuk diperiksa, bukan kesimpulan. Match yang muncul di beberapa sumber, atau yang cocok dengan perilaku lain di host yang sama, layak naik prioritas.

**Kapan gagal:** `strptime` mengembalikan null bila format `expires` di CSV tidak sama persis dengan format di search, dan baris itu akan terbuang tanpa pesan kesalahan. Uji dengan satu baris yang sengaja dibuat kedaluwarsa dan satu yang masih berlaku.

### 2.10 Meniru annotation dengan lookup

**Tujuan:** memberi label konteks pada hasil detection sendiri tanpa fitur annotation ES, sehingga rekap per teknik tetap bisa dibuat.

```
index=sysmon EventCode=1 Image="*\\schtasks.exe" CommandLine="*/create*"
| stats count BY host User
| eval detection="jab_schtasks_create"
| lookup lab_detection_annotations.csv detection OUTPUT mitre_technique_id mitre_tactic kill_chain_phase
```

- `lab_detection_annotations.csv` dibuat sendiri dengan header `detection,mitre_technique_id,mitre_tactic,kill_chain_phase`, misalnya baris `jab_schtasks_create,T1053.005,Persistence,Installation`; cek ID dan taktiknya di ATT&CK v19 (Day 30).
- Ini meniru apa yang dilakukan annotation ES: label konteks yang menempel pada hasil detection, bukan bagian dari logikanya.

Keluaran ilustrasi:

```
host           User                  count  mitre_technique_id  mitre_tactic  kill_chain_phase
JKT-WS-0523    JAB\andi.pratama          2   T1053.005           Persistence   Installation
```

**Variasi:** tambahkan kolom `confidence` dan `impact` ke CSV itu untuk meniru annotation ESCU [S11], lalu rekap hasilnya dengan `| stats count BY mitre_tactic mitre_technique_id` supaya kamu punya laporan cakupan versi sendiri.

## 3. Lab praktik

**Prasyarat:** ES lab bila ada; bila tidak, Splunk Enterprise plus TheHive atau catatan Markdown. Data autentikasi dan proses dari Day 23 sampai Day 24, serta satu detection dari Day 36.

1. Picu satu detection lab dengan aktivitas jinak (brute force uji ke akun uji, lalu satu login sukses). Pastikan finding muncul di antrean.
2. Jalankan alur bagian 2.1 sampai selesai, termasuk menulis note hipotesis sebelum search pertama.
3. Buat response plan "Akun terkompromi (lab)" dengan empat phase seperti bagian 2.5. Bila di ES, publikasikan lalu pasang ke investigation; bila tidak, pakai sebagai checklist.
4. Tambahkan satu task yang memuat search dan satu task yang memanggil action atau playbook (Day 41 dan Day 42). Catat apa yang berubah dalam kecepatan kerjamu.
5. Tutup investigation dengan disposition dan satu baris alasan. Ulangi untuk dua finding lain dengan disposition berbeda (satu benign positive, satu false positive).
6. Jalankan analisis disposition (bagian 2.6) dan tulis satu paragraf: detection mana yang perlu tuning logika, mana yang perlu perbaikan data.
7. Buat CSV indikator fiktif atau uji (domain `.example`, IP dokumentasi `203.0.113.0/24`) dengan kolom lengkap termasuk `expires` dan `confidence`. Dengan ES: tambahkan sebagai threat source, picu trafik uji dari VM lab, lalu periksa threat match dengan bagian 2.3 dan 2.4. Tanpa ES: pakai lookup bagian 2.9 (Day 12).
8. Sengaja beri satu indikator tanggal `expires` yang sudah lewat, lalu buktikan ia tidak lagi menghasilkan hasil. Ini latihan yang paling sering dilewati dan paling cepat terasa manfaatnya.
9. Tulis satu detection perilaku (misalnya dari Day 30) dan beri annotation ATT&CK, lewat ES (bagian 2.2) atau lewat lookup bagian 2.10.
10. Jalankan bagian 2.8 atau versi lab-mu untuk melihat hasil yang sudah berlabel, lalu buat daftar detection lab-mu yang belum punya annotation.
11. Ekspor satu investigation menjadi laporan singkat satu halaman: ringkasan, timeline, temuan, penilaian dengan keyakinan, keterbatasan, tindakan. Simpan sebagai bahan portofolio dan bahan interview.

**Hasil yang sebaiknya tersimpan:**

- Satu investigation lengkap dengan note bertanggal dan query yang bisa diulang.
- Satu response plan milikmu sendiri (JSON atau Markdown).
- Tabel disposition per detection beserta paragraf keputusan tuning.
- Bukti satu indikator berjalan dari daftar sampai finding, dan bukti bahwa indikator kedaluwarsa tidak lagi memicu apa pun.
- Satu detection lab dengan annotation ATT&CK yang terlihat di dua tempat berbeda, plus daftar detection yang belum dianotasi.
- Satu laporan investigasi satu halaman.

**Variasi tantangan:** buat framework annotation kustom sederhana, misalnya pemetaan ke kontrol ISO/IEC 27001:2022 Annex A hanya dengan nomor dan judul singkat (misalnya 8.15 Logging, 8.16 Monitoring activities, 5.26 Response to information security incidents; jangan menyalin teks standar). Terapkan ke tiga detection lab, lalu pastikan ketiga komponen framework kustom (intelligence download, lookup definition, automatic lookup) benar-benar ada sehingga labelnya muncul [S10].

## 4. Troubleshooting

Tabel ini menghubungkan gejala yang muncul saat menjalankan bagian 2 dan 3 dengan penyebab yang paling sering, supaya kamu tidak memperbaiki konfigurasi yang sebenarnya sudah benar.

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Response plan tidak bisa dipasang | Statusnya masih draft, bukan Published | Buka daftar response plan, cek kolom status [S2] |
| Import response plan gagal | Format bukan JSON, atau skema tidak cocok dengan versi | Ekspor plan sederhana dari UI, bandingkan strukturnya |
| Tab Intelligence investigation kosong | Deployment memakai native threat intelligence, sedangkan tab itu menampilkan data TIM (Cloud) | Buktikan indikator dengan `\| inputlookup <koleksi>` [S5] |
| Koleksi intel kosong | Feed nonaktif, unduhan gagal karena proxy atau firewall, parsing gagal | Cek status threat source dan log unduhannya; lokasi log perlu dicek di versimu |
| Indikator tidak menghasilkan finding | Threat matching search tidak aktif, field CIM tidak terisi, atau indikator masuk ke koleksi jenis IOC yang salah | Jalankan threat matching search manual; cek `\| inputlookup <koleksi>` [S8] |
| Banyak threat match yang tidak bermakna | Feed berkualitas rendah atau basi, IP sudah berganti pemilik | Nonaktifkan feed lemah; terapkan masa berlaku indikator (bagian 1.9 dan 2.9) |
| Feed TAXII tidak terbaca | Versi TAXII atau format STIX tidak cocok | Cek format yang didukung di dokumentasi ES versimu [S8] |
| Annotation tidak muncul di finding | Detection lama belum dianotasi, atau framework kustom tanpa automatic lookup | Tambahkan annotation; lengkapi tiga komponen framework kustom [S10] |
| Field `annotations.*` kosong di `index=risk` | Detection yang memicu belum punya annotation | Jalankan bagian 2.8 lalu daftar detection tanpa annotation |
| Finding menggantung tanpa pemilik | Tidak ada proses assign di awal shift | Search finding dengan owner kosong dan umur lebih dari sehari |
| Disposition kosong di banyak finding | Penutupan dilakukan tanpa memilih disposition | `index=notable \| stats count BY disposition` termasuk nilai kosong |
| Search di dalam task mengembalikan kosong | Default rentangnya 24 jam terakhir, sedangkan insidennya lebih lama [S4] | Ubah rentang saat menjalankan task |
| Metrik dwell time tidak masuk akal | Timeline insiden dan riwayat pekerjaan tercampur | Pisahkan keduanya di note (bagian 1.3) |

## 5. Kesalahan umum dan jebakan

- Membuat satu investigation per finding untuk insiden yang sama, sehingga metrik dan pekerjaan terpecah.
- Mulai menjalankan search sebelum menulis hipotesis, lalu terjebak mencari yang mendukung dugaan awal.
- Menutup finding tanpa disposition, atau memberi false positive untuk aktivitas yang sebenarnya benign positive.
- Menulis note berisi kesimpulan tanpa query dan rentang waktu, sehingga temuannya tidak bisa diulang.
- Menyalin prosedur kebijakan ke dalam task, sehingga task tidak bisa diverifikasi selesai atau tidak.
- Mengira indikator yang diunggah akan muncul di semua tempat di ES, padahal jalur native dan TIM (Cloud) terpisah [S5].
- Mengaktifkan semua feed bawaan tanpa evaluasi relevansi, lalu menyalahkan analyst karena antrean penuh.
- Mencocokkan indikator tanpa melihat masa berlaku dan confidence-nya, sehingga IP yang sudah berganti pemilik tetap memicu finding (bagian 1.9).
- Menganggap annotation mengubah logika deteksi. Annotation adalah konteks, bukan logika, dan detection tanpa annotation tetap berjalan [S10].
- Membiarkan annotation ATT&CK tidak diperbarui saat versi ATT&CK berubah, sehingga laporan cakupan memakai ID dan taktik lama (Day 30).
- Menilai kualitas feed dari jumlah indikatornya, padahal yang menentukan adalah berapa banyak match yang berakhir true positive.
- Melupakan keterbatasan data di laporan, sehingga "tidak ditemukan bukti" terbaca sebagai "tidak terjadi".
- Membiarkan response plan tidak pernah diperbarui setelah insiden nyata mengajarkan sesuatu yang baru.

## 6. Catatan terkini

Bagian ini menampung detail yang bergantung versi dan paling sering membuat materi lama salah.

- Di ES 8.7, Mission Control adalah antarmuka utama analyst, dan istilah ES 7 (notable, Incident Review) sudah digantikan finding dan analyst queue. Dokumentasi masih memuat kedua istilah di beberapa tempat (Day 31 dan Day 32).
- Response plan bawaan mencakup NIST 800-61 dan Generic Incident Response, dan ES juga menyediakan jalur untuk mengubah dokumen prosedur organisasi menjadi response plan [S3]. Bila fitur itu dipakai, hasilnya tetap perlu ditinjau manusia supaya task-nya bisa diverifikasi.
- Pemisahan native threat intelligence dan Threat Intelligence Management (Cloud) adalah perubahan yang paling sering membuat materi lama salah. Batas lima threat list dan tampilan halaman Intelligence berlaku untuk jalur TIM (Cloud) [S5].
- Intel Management (Legacy) sudah end of sale, sedangkan Threat Intelligence Management (Cloud) disertakan pada ES cloud di region tertentu [S9]; status terkininya perlu dicek di halaman rilis versimu.
- ES 8.7 menyertakan annotation PCI DSS 4.0 selain empat framework utama [S10].
- ES 8.3.0 (19 November 2025) menambahkan manajemen versi detection yang lebih baik [S9]. Ini relevan karena annotation bisa berubah antar versi detection, sehingga laporan cakupan dua versi bisa berbeda tanpa ada yang mengubah logika.
- MITRE ATT&CK v19.2 dipakai sebagai generic intelligence di ES [S7]. Pastikan konten ES memperbarui lookup ATT&CK-nya, dan cek versi ATT&CK yang dibundel ES 8.7 di instance-mu.
- Nama field pada finding (termasuk field waktu dan bentuk nilai `disposition`) berbeda antar versi ES. Dashboard dan metrik yang dibangun di atasnya perlu dicek ulang setiap upgrade mayor.

## 7. Cheat sheet

```
OBJEK     finding (pemicu) | intermediate finding (jejak risiko) | finding group (kumpulan per entity) | investigation (pekerjaan)
ALUR      assign -> status -> investigation -> note hipotesis -> response plan -> action/playbook -> threat intel -> note penilaian -> disposition -> tutup
NOTE      hipotesis | bukti (query + rentang) | penilaian + keyakinan | keterbatasan | tindakan + pemilik
PLAN      phase > task ; deskripsi Markdown ; task bisa punya action/playbook/search (default 24 jam) ; harus Published ; import JSON saja
DISPOSITION TP | BP (benar, diizinkan -> allowlist ber-expiry) | FP logika (-> perbaiki search) | FP data (-> perbaiki onboarding) | undetermined
ES INTEL  native: threat source -> parse -> koleksi KV store -> threat match -> finding
          bawaan: Emerging Threats, SANS, I-Blocklist (Tor...), Hail a TAXII, Phishtank
          generic: Umbrella 1M, ICANN TLD, MaxMind ASN, Public Suffix, MITRE ATT&CK
          format: STIX/TAXII, OpenIOC, file, API/URL, DB ; IOC: cert, email, file, http, ip/domain, process, registry, service, user
          TIM (Cloud): maksimal 5 threat list, observable + prioritization, hanya ini yang tampil di tab Intelligence
          Legacy Intel Management end of sale ; indikator butuh expires + confidence
ANNOTATION TUJUAN: konteks finding | laporan cakupan | analisis risiko per teknik | kepatuhan
          CAKUPAN: detection & analytic story ; managed (ATT&CK, CIS, NIST CSF, Kill Chain, PCI DSS 4.0; ESCU: story/confidence/context/impact)
                   vs unmanaged (kustom) ; JSON di savedsearches.conf action.correlationsearch.annotations
                   annotations.<fw>.<field> ; unmanaged di annotations._all dan ._frameworks ; index=risk ; Mission Control/Risk Analysis
          framework kustom = intelligence download + lookup definition + automatic lookup ; BUKAN logika deteksi
UKUR      index=notable | stats count BY search_name disposition ; p50 waktu ambil dan tutup per urgency
          | inputlookup <koleksi>_intel | stats count BY threat_key ; tstats datamodel=Threat_Intelligence.Threat_Activity
TANPA ES  alert Wazuh/scheduled search + case TheHive/Markdown + checklist phase-task + field disposition sendiri
          lookup IOC ber-expires/confidence + lookup pemetaan detection ke ATT&CK
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Kamu mengunggah 40 IP dan 12 domain lewat jalur native, threat matching search menghasilkan finding, tetapi tab Intelligence di investigation tetap kosong. Apa yang perlu diperbaiki?

<details><summary>Jawaban</summary>

Tidak ada yang perlu diperbaiki pada konfigurasi indikator. Halaman Intelligence di dalam investigation menampilkan data dari Threat Intelligence Management (Cloud) saja, bukan dari koleksi KV store native [S5]. Pembuktian untuk jalur native dilakukan dengan `| inputlookup` ke koleksi yang sesuai jenis IOC-nya, dan bukti bahwa intel bekerja adalah threat match yang muncul di data model Threat_Activity. Lihat bagian 1.7 dan 2.3.

</details>

**2. Skenario keputusan.** Satu insiden di PT JAB menghasilkan tiga finding pada entity yang sama dalam dua jam: request ke domain dari daftar indikator, login VPN dari IP luar, dan satu proses baru di host yang sama. Apa yang kamu lakukan?

- A. Buat tiga investigation terpisah supaya setiap finding punya jejak sendiri.
- B. Buat satu investigation, tambahkan ketiga finding, lalu tutup dengan satu disposition dan satu laporan.
- C. Tutup dua finding sebagai duplikat tanpa disposition, kerjakan satu yang paling parah.

<details><summary>Jawaban</summary>

B. Satu investigation bisa menampung banyak finding, dan itu memang gunanya: finding adalah pemicu, investigation adalah pekerjaan. A memecah metrik dan menghasilkan pekerjaan ganda untuk insiden yang sama. C lebih buruk lagi, karena finding yang ditutup tanpa disposition menghilang dari semua rekap kualitas detection, sehingga tidak ada dasar untuk tuning. Lihat bagian 1.1 dan 1.6.

</details>

**3. Pertanyaan jebakan.** Detection kustom PT JAB tidak muncul di laporan cakupan ATT&CK. Apakah berarti detection itu tidak berjalan?

<details><summary>Jawaban</summary>

Tidak. Annotation adalah label konteks, bukan logika deteksi, jadi detection tanpa annotation tetap berjalan dan tetap menghasilkan finding. Yang hilang adalah konteks di antrean analyst, baris di laporan cakupan, dan kemampuan menganalisis risiko per taktik dan teknik di `index=risk` [S10]. Perbaikannya menambahkan annotation lewat Configure > Content management, bukan mengubah search. Lihat bagian 1.10 dan 2.8.

</details>

**4. Skenario keputusan.** Sebuah finding memang dipicu aktivitas nyata: agen backup pihak ketiga menghubungi domain yang ada di daftar indikator berumur sembilan bulan, dan aktivitas itu disetujui pemilik sistem. Disposition mana yang kamu pilih dan apa tindak lanjutnya?

- A. False positive, lalu perbaiki logika detection.
- B. Benign positive, lalu tambah baris allowlist dengan tanggal kedaluwarsa dan turunkan confidence indikatornya.
- C. True positive, lalu eskalasi ke L2 karena domainnya ada di daftar indikator.

<details><summary>Jawaban</summary>

B. Deteksinya benar dan aktivitasnya nyata tetapi diizinkan, dan itulah definisi benign positive. A menyembunyikan dua fakta sekaligus: bahwa detection bekerja, dan bahwa sumber intelnya yang lemah. C mengabaikan bahwa indikator technical cepat basi dan domain bisa berganti pemilik, sehingga keberadaan sebuah nilai di daftar indikator bukan kesimpulan. Lihat bagian 1.6 dan 1.9.

</details>

**5. Jelaskan ulang.** Jelaskan ke analyst L1 yang baru, dalam tiga kalimat, kenapa setiap indikator di daftar intel perlu kolom masa berlaku dan confidence.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh jawaban: "Indikator teknis seperti IP dan domain cepat basi, karena IP di hosting murah berganti penyewa dalam hitungan hari dan domain bisa di-sinkhole atau kedaluwarsa. Kolom masa berlaku membuat baris yang sudah lewat tidak lagi dicocokkan, sehingga kita tidak menginvestigasi layanan sah yang kebetulan memakai alamat bekas. Kolom confidence membuat kita membaca hasilnya dengan benar: match dari satu sumber tanpa tanggal terakhir terlihat adalah petunjuk untuk diperiksa, bukan bukti."

Kesalahan yang sering muncul: menyebut masa berlaku sebagai urusan housekeeping agar lookup tidak membesar, padahal fungsinya menjaga kebenaran hasil; menganggap hash perlu masa berlaku sependek IP, padahal hash justru paling tahan lama; dan menyamakan confidence tinggi dengan kesimpulan, sehingga investigasi berhenti di match. Lihat bagian 1.9.

</details>

**6. Pertanyaan jebakan.** Kamu sudah menulis response plan lengkap empat phase, tetapi saat membuka sebuah investigation plan itu tidak ada di daftar pilihan, dan ketika kamu mengimpor ulang dari file YAML impornya gagal. Dua hal apa yang salah?

<details><summary>Jawaban</summary>

Pertama, plan hanya bisa dipasang ke investigation setelah statusnya Published; selama masih draft ia tidak muncul sebagai pilihan. Kedua, response plan hanya bisa diimpor dari file JSON, dan JSON adalah satu-satunya format yang didukung, jadi YAML akan selalu gagal [S2]. Cara teraman mendapat struktur yang benar adalah mengekspor satu plan sederhana dari UI versimu lalu memakainya sebagai template. Tambahan yang sering menyusul: search di dalam task berjalan untuk 24 jam terakhir secara default saat dijalankan dari tab Response, jadi rentangnya perlu disesuaikan untuk insiden yang lebih lama [S4]. Lihat bagian 1.5 dan 2.5.

</details>

**7. Interview question (English).** "Walk me through what you do when a threat intelligence match raises an alert, from the queue to closing the case."

<details><summary>Sample answer</summary>

"First I assign the finding to myself and set it to in progress, so no one else works the same thing. Then I open or join an investigation, and before I run any search I write a one line hypothesis in the notes, for example that a workstation is contacting a domain from our indicator list because of a loader rather than a legitimate application. I check the match itself before I chase the host: which feed the indicator came from, how old it is, whether it has a last seen date, and what confidence we assigned it, because an IP on cheap hosting can change tenants in days. Then I scope it with searches, and I write down both what I find and what I do not find, with the query, the time range and the data limitations, in our case Sysmon only covering part of the fleet. I close it with a disposition and a one line reason: true positive if it is real and unauthorised, benign positive if the detection was right but the activity is approved, which also means an allowlist entry with an expiry date and lowering the confidence of that indicator, and false positive split into bad analytic logic or bad data, because those two get fixed by different people. Last thing, I make sure the detection that fired carries its framework annotation, otherwise the case never shows up in our coverage reporting even though the work was done."

What makes this answer strong: it shows the discipline of assigning and writing a hypothesis before searching, it treats the indicator as evidence to be evaluated rather than a verdict, it names the disposition categories and ties each one to a different follow-up owner, it mentions data limitations explicitly, and it closes the loop on annotations, which is the part most candidates forget.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Overview of Mission Control in Splunk Enterprise Security (ES 8.7) | https://help.splunk.com/en/splunk-enterprise-security-8/user-guide/8.7/mission-control | primer | dilihat 2026-10-09 | Tinggi. Alur kerja analyst dan definisi investigation |
| S2 | Create response plans in Splunk Enterprise Security (ES 8.7) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/response | primer | dilihat 2026-10-09 | Tinggi. Phase dan task, status Published, import JSON |
| S3 | Included response plans in Splunk Enterprise Security (ES 8.7) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/response/included-response-plans-in-splunk-enterprise-security | primer | dilihat 2026-10-09 | Tinggi. Daftar plan bawaan termasuk NIST 800-61 |
| S4 | Respond to investigations with response plans in Splunk Enterprise Security (ES 8.7) | https://help.splunk.com/en/splunk-enterprise-security-8/user-guide/8.7/mission-control/respond-to-investigations-with-response-plans-in-splunk-enterprise-security | primer | dilihat 2026-10-09 | Tinggi. Tab Response, task, search default 24 jam, disposition |
| S5 | Configure threat lists in Splunk Enterprise Security (ES 8.7) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/threat-intelligence/configure-threat-lists-in-splunk-enterprise-security | primer | dilihat 2026-10-09 | Tinggi. Batas lima threat list, berlaku untuk TIM (Cloud), tab Intelligence tidak menampilkan koleksi native, definisi observable |
| S6 | Supported types of threat intelligence in Splunk Enterprise Security (ES 8.7) dan Overview of threat intelligence | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/threat-intelligence | primer | dilihat 2026-10-09 | Tinggi untuk daftar tipe indikator dan modular input `threatlist` |
| S7 | ES 8.3: Available threat intelligence and generic intelligence sources included in Splunk Enterprise Security | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.3/threat-intelligence/available-threat-intelligence-and-generic-intelligence-sources-included-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi. Sumber bawaan dan generic intelligence, termasuk ATT&CK |
| S8 | ES 8: Add new threat intelligence sources (format, jenis IOC, TAXII) | https://help.splunk.com/ja-jp/splunk-enterprise-security-8/administer/8.0/threat-intelligence/add-new-threat-intelligence-sources-in-splunk-enterprise-security | primer | tanggal tidak tercatat | Sedang-tinggi. Menu perlu dicek di 8.7 |
| S9 | ES release notes 8.3; Threat Intelligence Management (Cloud); Intel Management (Legacy) end of sale | https://help.splunk.com/en/splunk-enterprise-security-8/release-notes-and-resources/8.3/splunk-enterprise-security-release-notes | primer | tanggal tidak tercatat | Sedang-tinggi |
| S10 | ES 8.7: Add annotations to detections in Splunk Enterprise Security | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/detections/add-annotations-to-detections-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi. Tujuan, cakupan, managed dan unmanaged, lokasi penyimpanan, framework kustom, PCI DSS 4.0 |
| S11 | ES 8: Add ESCU annotations to detections and analytic stories | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.6/managing-security-content/add-escu-annotations-to-detections-and-analytics-stories-in-splunk-enterprise-security | primer | tanggal tidak tercatat | Sedang-tinggi. Analytic Story, Confidence, Context, Impact |
| S12 | Splunk-Notes Day 30 (ATT&CK dan tingkatan intel), Day 31 (istilah ES), Day 32 (dashboard ES), Day 34 (lima tahap dan metrik), Day 35 (RBA), Day 36 (detection), Day 40 (allowlist dan first-seen), Day 41 (adaptive response), Day 42 (SOAR), Day 28 (onboarding) | (lokal) | rujukan internal | 2026-10-10 | Keterkaitan antar Day |

**Catatan sumber:** nama koleksi KV store untuk tiap tipe indikator, field `threat_key`, data model Threat_Intelligence beserta dataset Threat_Activity, nama field waktu pada finding, dan bentuk nilai `disposition` berbeda antar versi ES, jadi semuanya dicek langsung di instance sebelum dipakai di dashboard. Menu Threat Intelligence dan daftar sumber bawaan berasal dari dokumentasi ES 8.0 dan 8.3 [S7][S8] dan belum terkonfirmasi di dokumentasi 8.7. Status Threat Intelligence Management (Cloud) dan Intel Management (Legacy) berasal dari release notes 8.3 [S9] dan bisa sudah berubah. Masa berlaku indikator di bagian 1.9 adalah praktik umum tim SOC, bukan angka baku dari satu sumber. Struktur JSON response plan paling aman diperoleh dengan mengekspor plan dari UI versi yang kamu pakai. Kasus `SOC-2026-0276` dan seluruh keluaran ilustrasi di bagian 2 adalah contoh fiktif untuk PT JAB, bukan hasil eksekusi.
