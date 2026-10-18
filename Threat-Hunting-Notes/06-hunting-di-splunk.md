---
day: 06
title: 'Hunting di Splunk: data model dan tstats, efisiensi, hunt interaktif vs terjadwal, baseline dan artefak, serta Job Inspector'
researched_on: 2026-10-18
versions_checked: 'Splunk Enterprise 10.6 (rilis 2026-09-30; SPL Search Reference 10.6 tstats, outputlookup, collect; Search Manual 10.0 dan 10.6 Job Inspector; Knowledge Manager Manual 10.4 akselerasi data model dan berbagi summary antar search head; REST API Reference 10.4 admin/summarization; workload management 10.4); CIM 6.4 (4 Feb 2026) dan CIM 8.7 (2 Sep 2026, nomor versi disamakan dengan ES); ES 8.7; Splunk Add-on for Sysmon 5.0.1 (2026-07-06); Splunk Security Content (macro security_content_summariesonly, analytic diperbarui 2026-05-13)'
---

# Day 06: Hunting di Splunk (data model, efisiensi, baseline, dan Job Inspector)

Cakupan: cara menjalankan hunt di Splunk secara efisien, lengkap, dan dapat diulang di lingkungan bersama, mulai dari memilih raw search atau `tstats` atas data model terakselerasi, memastikan keduanya menjawab pertanyaan yang sama, memutuskan hunt interaktif atau terjadwal, menyimpan baseline dan artefak, membaca Job Inspector, sampai menjaga agar hunt tidak mengganggu search produksi.

## Ide inti

Hunt di Splunk berbeda dari search triage: rentangnya panjang (30 hari atau lebih), field yang dibutuhkan belum tentu standar, dan pertanyaannya berubah setiap kali kamu pivot. Kalau setiap pertanyaan dijawab dengan membaca ulang event mentah, hunt akan lambat dan, karena indexer dipakai bersama, ikut memperlambat correlation search yang menghasilkan alert. Pola yang sehat adalah dua tahap: persempit dulu dengan `tstats` atas data model yang sudah diringkas (cepat, tetapi hanya field standar), lalu perdalam dengan raw search bertarget pada irisan kecil (lambat per event, tetapi lengkap). Syaratnya ketat: versi cepat harus menjawab pertanyaan yang persis sama dengan versi lambat, ringkasannya harus lengkap untuk rentang yang diperiksa, dan query, baseline, serta angka Job Inspector disimpan supaya hunt bisa diulang dan dipertanggungjawabkan. Optimasi yang mengubah pertanyaan bukan optimasi, tetapi hunt lain.

Kamu sudah mengenal pola ini dari NOC. Untuk melihat tren utilisasi satu uplink selama sebulan, kamu membuka grafik MRTG atau RRD yang dibangun dari polling counter setiap 5 menit, bukan memutar ulang packet capture sebulan. Grafik itu murah dan cepat karena sudah diringkas. Begitu grafik menunjukkan lonjakan aneh pada satu jam di satu port, barulah kamu mengambil capture atau NetFlow detail untuk jam dan port itu saja. Batas analoginya: ringkasan hanya memuat field yang dipilih saat ringkasan didefinisikan, dan ringkasan bisa tertinggal atau bolong tanpa terlihat dari luar. Grafik MRTG yang kosong karena poller mati tidak berarti trafiknya nol, dan `tstats` yang kosong karena ringkasan bolong tidak berarti aktivitasnya tidak ada.

```
pertanyaan hunt
      |
      v
field yang dibutuhkan ada di data model? --tidak--> raw search, persempit di base search
      | ya                                            (index, host, term literal, rentang absolut)
      v
rentang di dalam summary range dan ringkasan lengkap? --tidak--> raw untuk bagian itu,
      | ya                                                      atau tulis "data tidak cukup"
      v
tstats: persempit (host, pasangan, waktu) ----> uji kesetaraan sekali dengan raw
      |                                          (resultCount harus sama)
      v
raw bertarget pada irisan kecil (CommandLine, user, parent) -> label tiap hasil
      |
      v
simpan: query .spl berkomentar + angka Job Inspector + baseline (lookup / summary index)
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan. SOC PT JAB memakai Splunk Enterprise 10.6 terdistribusi: Enterprise Security (ES) berjalan di search head terpisah `jkt-splunk-es01`, sedangkan analyst memakai search head umum `jkt-splunk-sh01`; keduanya membaca indexer yang sama. Sysmon terpasang di server Windows dan di workstation OU `Workstations-EDR` (sekitar 40% workstation). Sejak Februari 2027 kamu, analyst L2, memegang "Program hunt PT JAB" setiap Selasa dan Kamis, dengan role Splunk `jab_hunter` di `jkt-splunk-sh01` dan repositori GitLab internal `jab-hunt`. Kamis lalu, 2027-02-11, kamu membangun baseline parent-child untuk `HUNT-2027-006` dari raw Sysmon satu bulan penuh. Selasa 2027-02-16 pukul 08:15, admin Splunk yang baru, Reza Firmansyah dari tim Infrastruktur, menulis kepadamu:

> "Selamat pagi. Saya Reza dari tim Infrastruktur, baru pegang Splunk sejak awal bulan. Kamis lalu ada search dari akun kamu di jkt-splunk-sh01 yang jalan 40 menit, dan di jam yang sama beberapa correlation search ES tercatat skipped; Mbak Sari sempat tanya ke saya. Saya tidak keberatan hunting jalan, tapi saya perlu paham beberapa hal. Kenapa satu search bisa selama itu, dan kenapa search ES yang ada di search head lain ikut terlewat? Data model CIM kita kan sudah diakselerasi untuk ES; apakah hunt bisa pakai itu, dan apakah hasilnya sama lengkapnya dengan search biasa? Apakah sebaiknya semua hunt dijadwalkan malam hari saja supaya saya bisa atur jamnya? Baseline yang kamu simpan itu ada di mana dan apakah membebani? Kalau nanti ada search lambat lagi, angka apa dari Job Inspector yang perlu saya lihat? Terakhir, batasan apa yang masuk akal untuk role jab_hunter?"

Pesan itu memuat tujuh pertanyaan:

1. Kenapa satu search hunt bisa berjalan 40 menit?
2. Kenapa search itu ikut membuat correlation search ES terlewat, dan batasan apa yang masuk akal untuk role `jab_hunter`?
3. Bisakah hunt memakai data model CIM yang sudah diakselerasi, dan kapan raw search tetap perlu?
4. Apakah hasil dari data model sama lengkapnya dengan raw search?
5. Apakah semua hunt sebaiknya dijadwalkan malam hari?
6. Di mana baseline dan query hunt disimpan, dan apakah penyimpanannya membebani?
7. Angka Job Inspector mana yang dilihat bila search lambat?

Pertanyaan 1 dijawab di bagian 1.3 dan 1.6, pertanyaan 2 di bagian 1.8, pertanyaan 3 di bagian 1.1 dan 1.2, pertanyaan 4 di bagian 1.1 dan 2.5, pertanyaan 5 di bagian 1.4, pertanyaan 6 di bagian 1.5, dan pertanyaan 7 di bagian 1.6. Bagian 1.7 menambahkan dua jebakan akurasi yang tidak ditanyakan Reza tetapi sering membuat hasil hunt salah. Bagian 2 menjalankan `HUNT-2027-007` dengan pola dua tahap dan menutupnya dengan laporan serta balasan untuk Reza.

**Kapan relevan:** setiap hunt di Splunk, terutama yang menjelajah rentang panjang atau data besar; saat hunt harus diulang dengan hasil yang sama; dan saat admin atau pemilik detection bertanya kenapa search hunt membebani platform.
**Kapan bukan jawaban:** hunt yang berpusat pada artefak endpoint yang tidak pernah dikirim ke SIEM (isi registry mentah, prefetch, file di disk) lebih cocok di Velociraptor atau EDR (Day 09); data yang hanya ada di Wazuh indexer dibahas di Day 08; dan bila field yang kamu butuhkan tidak dikirim sama sekali, masalahnya kesiapan data (Day 04), bukan efisiensi query.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (stacking, long tail, baseline, first-seen, hunt abstract, backlog) tidak diulang. Tabel ini memuat istilah Splunk yang dipakai Day ini; kolom kanan memetakan tiap istilah ke hal yang sudah kamu kenal dari NOC atau SOC.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Raw search | Search yang membaca event mentah dari index (`index=... \| stats ...`) | Memutar ulang packet capture penuh |
| Base search | Bagian search sebelum pipe pertama; dikerjakan di indexer memakai tsidx | Filter capture di sisi sensor sebelum data dikirim |
| tsidx | File indeks Splunk yang memetakan term ke lokasi event | Tabel indeks di database NetFlow |
| Data model | Skema yang memetakan event dari banyak sumber ke field standar | Template SNMP yang sama untuk router berbagai vendor |
| CIM (Common Information Model) | Kumpulan data model standar Splunk, misalnya `Endpoint`, `Network_Traffic`, `Web` | MIB standar yang dipakai semua perangkat |
| Akselerasi data model (DMA) | Ringkasan tsidx yang dibangun dan diperbarui terjadwal untuk satu data model | Grafik MRTG/RRD hasil polling counter tiap 5 menit |
| Summary range | Seberapa jauh ke belakang ringkasan dibangun | Lama data RRD disimpan sebelum di-rollup |
| `tstats` | Command yang menghitung statistik dari indexed field atau ringkasan data model | Membaca grafik RRD, bukan capture |
| `summariesonly` | Argumen `tstats`: hanya membaca data yang sudah diringkas | Hanya percaya grafik, tanpa mengecek poller |
| Reader dan writer summary | Search head yang membangun ringkasan (writer) dan search head lain yang memakainya (reader) | NMS pusat yang polling dan NMS cabang yang hanya membaca grafiknya |
| Job Inspector | Tampilan rincian biaya dan properti satu search job | Rincian latency per hop dari traceroute |
| `scanCount`, `eventCount`, `resultCount` | Event yang dibaca dari disk, event yang cocok, dan hasil akhir | Paket ditangkap, paket cocok filter, baris laporan |
| Scan rate | `scanCount` dibagi `runDuration`, dalam event per detik | Throughput baca disk saat menarik capture |
| Skipped search | Run scheduled search yang dilewati scheduler karena batas konkurensi | Polling SNMP yang timeout karena uplink jenuh |
| Workload management | Fitur Splunk di Linux untuk membagi CPU/memori ke pool dan menerapkan aturan per role atau jenis search | QoS di uplink: kelas trafik dengan jatah bandwidth |
| Lookup dan `outputlookup` | Tabel CSV di search head dan command untuk menulisnya | Inventaris konfigurasi yang diekspor ke file |
| Summary index dan `collect` | Index khusus berisi hasil search terjadwal, dan command untuk menulisnya | Arsip statistik harian per POP |
| Search macro | Potongan SPL bernama yang bisa dipakai ulang dengan backtick | Template konfigurasi yang dipakai di banyak router |

### 1.1 Data model, akselerasi, dan tstats

Pertanyaan ketiga dan keempat Reza berangkat dari hal yang benar: PT JAB sudah membayar biaya akselerasi data model untuk ES. Di `jkt-splunk-es01`, data model CIM `Endpoint` diakselerasi dengan summary range 90 hari, sedangkan `Network_Traffic` dan `Web` diakselerasi 30 hari (sama dengan retensi index `proxy`). Pertanyaannya: apakah hunt boleh menumpang ringkasan itu, dan apa risikonya.

Tiga konsep yang harus dipegang:

- **Data model** adalah skema yang memetakan event dari berbagai sumber ke field standar CIM. Dataset `Endpoint.Processes`, misalnya, berisi `dest`, `user`, `process_name`, `process`, dan `parent_process_name` [S7]. Sysmon EID 1 dan Windows 4688 sama-sama bisa dipetakan ke dataset ini oleh technology add-on (TA) masing-masing. Batas dataset `Processes` adalah event yang diberi tag `process` dan `report` [S7]; event apa pun yang diberi dua tag itu oleh TA ikut masuk, jadi isi dataset bergantung pada TA, bukan hanya pada nama dataset.
- **Akselerasi data model** membuat ringkasan `.tsidx` di indexer yang diperbarui search terjadwal, default setiap 5 menit. Summary range menentukan seberapa jauh ke belakang ringkasan dibuat, dan tidak bisa melebihi retensi index sumbernya [S3]. Ringkasan dibangun per bucket, sehingga batas summary range bersifat perkiraan [S3].
- **`tstats`** membaca indexed field dan ringkasan tsidx, bukan event mentah [S2], sehingga jauh lebih cepat daripada `stats` atas raw di rentang panjang. Dokumentasi juga mengingatkan bahwa pola tertentu bisa membuat `tstats` lebih lambat daripada search biasa [S2], jadi kecepatan tetap diukur, bukan diasumsikan.

Field standar CIM punya nilai bawaan yang perlu dikenali saat membaca hasil hunt. Field `dest`, `user`, `process`, dan `parent_process` bernilai `unknown` bila kosong; `parent_process_name` diambil dari field aslinya, atau dari token pertama `parent_process` bila kosong, lalu `unknown` bila keduanya tidak ada [S7]. Field seperti `parent_process_path` dan `original_file_name` tidak punya nilai bawaan. Akibatnya untuk `tstats`: baris yang salah satu field `BY`-nya null dibuang diam-diam, kecuali kamu memberi `fillnull_value` [S2]. Argumen itu ditulis sebelum fungsi statistik, bukan setelah `BY`.

Dengan `summariesonly=true`, `tstats` hanya membaca data yang sudah diringkas: cepat, tetapi bisa tidak lengkap bila ringkasan tertinggal atau rentang hunt melebihi summary range. Dengan `false` (nilai bawaan [S2]), bagian yang belum diringkas dibaca dari raw: lengkap tetapi lebih lambat [S3]. Hasil "tidak ditemukan" dari ringkasan yang bolong bukan hasil sah, melainkan "data tidak cukup". Argumen lain yang sering muncul: `allow_old_summaries` (bawaan `false`) menentukan apakah ringkasan yang dibangun dengan definisi data model lama ikut dibaca [S2]. Bila definisi data model berubah, ringkasan dibangun ulang otomatis secara bawaan [S3].

Ada satu fakta arsitektur yang menjawab pertanyaan Reza secara langsung. Ringkasan data model terikat pada GUID search head atau search head cluster yang membangunnya [S3]. Search head lain hanya bisa memakainya bila data model di search head itu dikonfigurasi sebagai reader, dengan `acceleration.source_guid` berisi GUID writer di `datamodels.conf`, pada app yang sama dengan data model writer (misalnya `Splunk_SA_CIM`) [S10]. GUID search head tunggal ada di `etc/instance.cfg`; GUID cluster ada di `server.conf` stanza `[shclustering]` [S10]. Di sisi reader, ringkasan lokal dihapus, pemeliharaan ringkasan berhenti, data model tidak bisa diedit dari Splunk Web, dan `allow_old_summaries` menjadi `true` [S10]. Dokumentasi menyarankan `summariesonly=t` untuk `tstats` di reader, karena tanpa itu hasil bisa tercampur data yang belum diringkas dari sumber yang berbeda [S10].

Di PT JAB, `jkt-splunk-sh01` sudah dikonfigurasi sebagai reader untuk `Endpoint`, `Network_Traffic`, dan `Web` sejak search head itu dibangun untuk dashboard SOC, dengan writer `jkt-splunk-es01`. Jadi jawabannya: hunt boleh dan sebaiknya memakai ringkasan itu, dengan dua kewajiban. Pertama, karena sh01 adalah reader, query hunt memakai `summariesonly=true`. Kedua, karena `summariesonly=true` bisa diam-diam tidak lengkap, setiap hunt mengecek dua hal sebelum menyimpulkan: rentang hunt berada di dalam summary range, dan ringkasan untuk rentang itu lengkap (bagian 2.7). Tanpa reader, menjalankan `tstats` atas data model yang sama di sh01 berarti membangun ringkasan kedua, dan beban akselerasi dibayar dua kali.

Ada satu konsekuensi keamanan yang perlu Reza ketahui. Search filter, termasuk filter berbasis role (`srchFilter`), tidak diterapkan pada dataset data model terakselerasi [S2]. Bila suatu hari role `jab_hunter` dibatasi dengan `srchFilter`, batasan itu tidak berlaku untuk `tstats` atas data model.

Query di Day ini menulis opsi `tstats` secara eksplisit. Di instance yang memasang ES atau aplikasi Splunk Security Content, kamu akan sering melihat dua macro. `` `security_content_summariesonly` `` berisi `summariesonly`, `allow_old_summaries`, dan `fillnull_value`, dengan nilai bawaan di repo `false`, `true`, dan `null` [S8]; admin bisa mengubahnya. `` `drop_dm_object_name(Processes)` `` menghapus awalan `Processes.` dari nama field, padanannya `rename Processes.* AS *`. Analytic resmi Splunk untuk Office yang memunculkan proses tidak lazim, misalnya, memakai kedua macro itu di atas `Endpoint.Processes` dengan data Sysmon EID 1, Security 4688, atau EDR [S17]. Untuk hunt di sh01 yang berstatus reader, menulis `summariesonly=true` secara eksplisit lebih aman daripada bergantung pada nilai macro yang bisa diubah orang lain.

### 1.2 Raw search vs data model untuk hunt

Reza bertanya apakah hunt bisa sepenuhnya pindah ke data model. Jawabannya tidak, karena kedua cara punya kekuatan yang berbeda. Tabel berikut membandingkannya; baca baris "Field yang tersedia" dan "Jebakan", karena di dua baris itulah keputusan sebenarnya dibuat.

| Aspek | Raw search (`index=...`) | Data model (`tstats`) |
|---|---|---|
| Kecepatan di rentang panjang | Lambat; membaca dan mengekstrak event mentah | Cepat bila terakselerasi [S2][S3] |
| Field yang tersedia | Semua field, termasuk yang tidak dipetakan ke CIM | Hanya field yang ada di data model |
| Cocok untuk | Eksplorasi awal, field tidak lazim, pivot bebas | Stacking dan agregasi atas field standar, rentang panjang |
| Jebakan | Timeout, antrean panjang, membebani indexer bersama | Field yang dibutuhkan tidak ada; ringkasan tertinggal atau bolong; isi dataset bergantung TA |

Pola yang efisien: mulai eksplorasi dengan `tstats` atas data model terakselerasi untuk mempersempit (host, waktu, nilai menarik), lalu raw search bertarget hanya pada irisan kecil itu untuk melihat field lengkap seperti `CommandLine` atau hash. Ini menggabungkan kecepatan dan kedalaman. Di PT JAB, baseline `HUNT-2027-006` yang memakan 40 menit sebenarnya hanya membutuhkan path parent dan child per event, dan keduanya ada di `Endpoint.Processes` (`parent_process_path` dan `process_path` [S7]). Itu kandidat sempurna untuk `tstats` (bagian 2.3).

Ada tiga hal yang membuat raw dan `tstats` bisa menjawab pertanyaan yang berbeda walaupun query-nya terlihat setara:

- **Sumber yang ikut masuk dataset.** `Endpoint.Processes` di PT JAB menerima Sysmon EID 1 dari `index=sysmon` dan juga 4688 dari `index=wineventlog`, karena GPO `JAB-WS-Audit` di OU `Workstations-EDR` mengaktifkan audit process creation. Raw search atas `index=sysmon EventCode=1` hanya melihat yang pertama. Karena `index` adalah indexed field, `tstats` bisa dibatasi dengan `index=sysmon` di klausa `WHERE` (klausa itu hanya menerima indexed field [S2]).
- **Nama host.** `dest` di data model diisi TA dari field event (di PT JAB berupa FQDN, misalnya `JKT-WS-0583.corp.jab.example`), sedangkan `host` di raw berasal dari forwarder (nama pendek). Filter dan pivot harus memperhitungkan beda format ini.
- **Nilai kosong.** Data model mengisi `unknown` untuk beberapa field dan membuang baris null untuk field lain kecuali ada `fillnull_value` (bagian 1.1); raw `stats` membuang baris yang field `BY`-nya null.

Karena itu, setiap kali sebuah hunt dipindah dari raw ke `tstats`, jalankan uji kesetaraan sekali di rentang yang sama (bagian 2.5). Setelah lulus, versi `tstats` boleh dipakai berulang.

### 1.3 Efisiensi hunt: filter awal dan urutan command

Pertanyaan pertama Reza (kenapa 40 menit) sebagian besar dijawab di sini. Search pembangun baseline Kamis lalu membaca raw Sysmon EID 1 seluruh Januari, menormalisasi path dengan beberapa `replace()`, lalu menghitung pasangan. Tidak ada yang salah secara logika; masalahnya volume yang dibaca. Prinsip search efisien berlaku ganda untuk hunt karena rentangnya panjang [S4]:

- **Persempit di base search.** Bagian sebelum pipe pertama dikerjakan di indexer memakai tsidx; filter setelah pipe baru bekerja setelah event ditarik dan diekstrak. `index=sysmon EventCode=1 mshta.exe Image=*\\mshta.exe` jauh lebih murah daripada menarik semua EID 1 lalu memfilter dengan `where`. Filter dengan indexed field default (`host`, `source`, `sourcetype`) dan index yang spesifik sedini mungkin [S4].
- **Tambahkan term literal** bila filter field memakai wildcard di depan. Wildcard di awal term bisa menimbulkan masalah performa, dan wildcard paling baik diletakkan di akhir term [S16]. Wildcard di tengah string yang mengandung tanda baca (`-`, `_`) bisa memberi hasil tidak konsisten [S16]. Itu sebabnya filter workstation PT JAB ditulis `host="JKT-WS-*"`, bukan `host="*-WS-*"`.
- **Pakai `tstats` untuk hitungan**, bukan `stats` atas raw, bila field ada di data model.
- **Batasi field dan letakkan command non-streaming di akhir.** Command seperti `stats`, `sort`, dan `dedup` mengirim hasil ke search head dan mengurangi pemrosesan paralel di indexer, jadi letakkan selambat mungkin; pakai `fields` untuk membuang field yang tidak dipakai [S4].
- **Command pengurang data (`where`, `dedup`, `fields`) didahulukan** sebelum command mahal (`transaction`, `join`); banyak kebutuhan `transaction` bisa diganti `stats ... BY`.
- **Hati-hati dengan `BY` berkardinalitas tinggi.** Statistik dengan `BY` atas field yang nilainya sangat beragam memakan banyak memori; untuk `tstats`, kurangi jumlah nilai `BY` atau turunkan `chunk_size` [S4]. Analytic detection sering mengelompokkan per `process_guid` dan belasan field lain [S17] karena ingin satu baris per kejadian; stacking justru sebaiknya mengelompokkan sesedikit mungkin field.
- **Rentang dibulatkan** (`earliest=-30d@d`) untuk search terjadwal, agar dua kali menjalankan hunt di hari yang sama mencakup rentang identik. Untuk query yang masuk laporan hunt, tulis rentang absolut (`earliest="01/17/2027:00:00:00"`) supaya bisa diulang minggu depan dengan hasil yang sama.

### 1.4 Hunt interaktif vs terjadwal

Reza mengusulkan semua hunt dijadwalkan malam hari. Usul itu masuk akal dari sisi admin, tetapi bertentangan dengan sifat hunt yang bergerak mengikuti temuan. Tabel berikut memisahkan dua mode; baca kolom "Tujuan", karena tujuan itulah yang menentukan mode, bukan jam.

| Mode | Tujuan | Cara |
|---|---|---|
| Interaktif (ad hoc) | Eksplorasi, pivot mengikuti temuan | Search bar; simpan query yang berguna |
| Terjadwal | Baseline berkala; hunt yang diulang rutin | Saved search, summary index, `outputlookup` |

Begitu hunt interaktif terbukti berguna dan ingin diulang (misalnya pemeliharaan baseline parent-child), ubah menjadi saved search terjadwal. Ini bukan deteksi: tidak menghasilkan alert, hanya memelihara baseline. Hunt yang layak menjadi alert diserahkan lewat handover (Day 02) ke pemilik konten detection, di PT JAB Sari Kusuma.

Dua hal yang perlu Reza ketahui tentang search terjadwal. Pertama, search terjadwal dan ad hoc berbagi slot search yang sama; search ad hoc tidak punya batas bawaan dan bisa menghabiskan slot sehingga scheduler kehabisan [S12]. Menjadwalkan hunt tidak otomatis lebih ringan, hanya memindahkan bebannya ke jam lain. Kedua, banyak search yang dijadwalkan di awal jam (misalnya `0 * * * *`) adalah penyebab umum skipped search; `schedule_window` atau `allow_skew` menyebar waktu mulainya [S12]. Jadi jawaban untuk Reza: hunt eksploratif tetap interaktif di jam kerja Selasa dan Kamis, tetapi wajib dimulai dengan `tstats`; yang dijadwalkan hanya pemeliharaan baseline dan hunt yang sudah stabil, di luar jam puncak, dengan `schedule_window`.

### 1.5 Menyimpan baseline dan artefak hunt

Pertanyaan keenam Reza punya dua bagian: di mana baseline disimpan, dan apakah penyimpanannya membebani. Query yang hanya ada di riwayat search bar akan hilang. Simpan:

- **Baseline:** lookup CSV lewat `outputlookup` [S5] untuk daftar "pernah terlihat", misalnya `jab_hunt_baseline_parentchild.csv`; summary index lewat `collect` [S6] untuk statistik berkala yang ingin di-tren-kan berbulan-bulan tanpa menghitung ulang dari raw.
- **Query hunt:** file `.spl` di repo `jab-hunt` (`hunts/HUNT-2027-NNN/queries/`) dengan komentar hipotesis dan asumsi data. Ekspresi yang dipakai di banyak query, seperti normalisasi path, dijadikan search macro supaya raw dan `tstats` memakai ekspresi yang persis sama.
- **Hasil:** ekspor CSV atau screenshot yang disamarkan, plus laporan hunt (template di Day 01 bagian 2.4).
- **Angka Job Inspector:** `runDuration`, `scanCount`, `resultCount`, dan komponen termahal.

Beban penyimpanannya kecil bila caranya benar. Baseline parent-child berisi beberapa ribu baris, bukan jutaan event. Biaya sebenarnya ada di search yang membangunnya: bila setiap pembaruan membaca ulang raw sebulan, setiap pembaruan mengulang 40 menit Kamis lalu. Pembaruan inkremental dengan `tstats` hanya membaca ringkasan untuk hari yang baru.

Beberapa detail command yang menentukan apakah baseline aman:

- `outputlookup` secara bawaan menimpa file (`append=false`) [S5]. Pola aman: hitung data baru, gabungkan isi lama dengan `inputlookup append=true`, kelompokkan lagi, lalu tulis ulang.
- Dengan nilai bawaan `override_if_empty=true`, hasil search yang kosong menghapus file lookup yang sudah ada [S5]. Bila ringkasan atau index sedang bermasalah dan search pembaruan tidak menghasilkan apa-apa, baseline berminggu-minggu bisa hilang. Tulis `override_if_empty=false` di setiap search yang memelihara baseline.
- `collect` menulis ke summary index yang harus dibuat dulu; dengan sourcetype bawaan `stash`, data itu tidak dihitung ke lisensi, sedangkan sourcetype lain dihitung [S6].
- Rentang baseline harus berakhir di hari yang first-seen-nya sudah diambil, entah lewat laporan first-seen terjadwal atau lewat hunt. Bila hari berjalan, atau hari yang belum diambil first-seen-nya, ikut masuk baseline, pasangan baru hari itu dianggap "sudah pernah terlihat" dan tidak pernah muncul di hunt first-seen.

### 1.6 Job Inspector: menemukan bottleneck

Pertanyaan ketujuh Reza adalah alat diagnosis bersama antara kamu dan admin. Job Inspector dibuka dari menu Job > Inspect Job, saat atau setelah search berjalan, selama artefak job belum kedaluwarsa [S1]. Bagian atasnya memuat status, jumlah hasil, durasi, SID, dan tautan `search.log` [S1]. Job lain bisa dibuka dengan mengganti `sid` di URL; SID terlihat di Activity > Jobs [S1]. Job yang disimpan (Job > Save) secara bawaan dipertahankan 7 hari sejak terakhir dilihat (`default_save_ttl` di `limits.conf`) [S1]. Di bawah header ada dua bagian.

**Execution costs** memecah search menjadi komponen, masing-masing dengan durasi (detik), jumlah invocation, input count, dan output count [S1]. Tabel berikut adalah komponen yang paling sering menentukan diagnosis; baca kolom kanan untuk tindakan bila komponen itu dominan.

| Komponen | Arti | Bila dominan |
|---|---|---|
| `command.search` | Semua sebelum pipe pertama | Base search memikul beban terbesar |
| `command.search.index` | Mencari lokasi event cocok di tsidx | Rentang atau index terlalu luas |
| `command.search.rawdata` | Membaca event dari raw data | Terlalu banyak event mentah; pakai `tstats` atau persempit |
| `command.search.kv`, `.lookups` | Ekstraksi field, automatic lookup | Knowledge object berat atas banyak event; `fields` lebih awal |
| `command.<nama>` | Command setelah pipe (`command.stats`, `command.join`) | Command itu sendiri mahal |
| `dispatch.fetch` | Search head menunggu event dari peer | Lambat di jaringan atau peer |
| `dispatch.evaluate`, `startup.handoff` | Parsing dan persiapan search; membangun proses search | Subsearch berat; I/O lambat di `.conf` atau direktori dispatch |

Sub-komponen `command.search.*` berjalan bersamaan, jadi durasinya tidak dijumlahkan [S1].

**Search job properties** memuat antara lain `scanCount` (event dibaca dari disk), `eventCount` (event cocok, subset `scanCount`), `resultCount` (hasil akhir), `runDuration` (detik), `optimizedSearch` (bentuk search yang benar-benar dijalankan), `isSavedSearch` (apakah dijalankan scheduler), dan `diskUsage` [S1].

Dokumentasi Splunk memberi dua patokan: `scanCount` yang jauh lebih besar dari `resultCount` menandakan search sparse, dan performa dinilai dari scan rate (`scanCount` per detik), dengan sekitar 10-20 ribu event per detik dianggap baik [S1]. Patokan itu masih sama di dokumentasi 10.6 [S1]. Scan rate rendah berarti membaca lambat (disk, beban indexer, knowledge object berat). Scan rate tinggi tetapi durasi tetap lama berarti volumenya terlalu besar, dan solusinya membaca lebih sedikit.

Untuk Reza, angka yang perlu dikirim bersama keluhan "search lambat" cukup tujuh: SID, waktu mulai, rentang waktu search, `runDuration`, `scanCount`, `eventCount`, `resultCount`, ditambah tiga komponen termahal. Dari situ ia bisa membedakan masalah platform (scan rate rendah di semua search) dari masalah query (scan rate normal, volume berlebihan).

### 1.7 Hunt yang aman terhadap data statis dan multivalue

Dua jebakan akurasi ini tidak ditanyakan Reza, tetapi muncul begitu hunt mulai memakai dataset latihan dan log Security Windows:

- **Dataset statis:** untuk dataset latihan statis (misalnya BOTS v1 bertanggal Agustus 2016), `earliest=-30d` pasti kosong. Tulis rentang absolutnya (`earliest="08/01/2016:00:00:00" latest="09/01/2016:00:00:00"`). Hal yang sama berlaku untuk hunt PT JAB yang diulang minggu depan: query di laporan memakai rentang absolut, bukan relatif.
- **Field multivalue:** event 4624 dan 4625 format klasik memuat dua blok akun, Subject dan akun target, yang bisa sama-sama masuk ke field `Account_Name`. Saat `HUNT-2027-001` memeriksa logon jaringan (4624 tipe 3) sebelum eksekusi WMI di `JKT-WS-0517`, `Account_Name` di event itu berisi dua nilai. Stacking `BY Account_Name` lalu ikut menghitung akun komputer (berakhiran `$`) atau `-` sebagai user. Pakai field CIM `user`, atau ambil nilai target eksplisit (`mvindex(Account_Name, 1)`, setelah mengecek urutannya di data).

### 1.8 Hunt di infrastruktur bersama: skipped search, kuota role, dan workload management

Pertanyaan kedua Reza paling membingungkan baginya: search hunt berjalan di `jkt-splunk-sh01`, sedangkan correlation search ES berjalan di `jkt-splunk-es01`. Kenapa yang kedua ikut terlewat?

Pertama, cara Splunk membatasi search. Setiap search head punya jumlah slot search: total konkurensi kira-kira `max_searches_per_cpu` dikali jumlah core ditambah `base_max_searches` (bawaan 1 dan 6); scheduler mendapat `max_searches_perc` dari total itu (bawaan 50%), dan akselerasi data model mendapat `auto_summary_perc` dari jatah scheduler (bawaan 50%) [S12]. Bila semua slot scheduler terpakai, run berikutnya dilewati. Lantern mencatat alasan skip yang umum: kuota user atau role tercapai, satu scheduled search masih berjalan saat run berikutnya tiba (secara bawaan hanya satu instance yang boleh berjalan), batas search akselerasi tercapai, batas scheduled search instance tercapai, terlalu banyak search dijadwalkan di waktu yang sama, search ad hoc memakai terlalu banyak slot, dan utilisasi CPU indexer (P95) di atas 80% [S12].

Kedua, kenapa search head yang berbeda saling memengaruhi. Slot search head memang terpisah, tetapi indexer dipakai bersama. Raw search 40 menit yang membaca puluhan juta event menyita CPU dan I/O indexer. Correlation search ES yang biasanya selesai kurang dari satu menit lalu berjalan lebih lama dari intervalnya; saat run berikutnya tiba, run sebelumnya masih berjalan, dan scheduler di es01 melewatinya. Di log scheduler, alasannya adalah batas instance per scheduled search, bukan batas slot es01. Bagian 2.7 menunjukkan cara membuktikannya.

Ketiga, rem yang tersedia untuk admin. Tabel berikut adalah setting role di `authorize.conf` yang relevan untuk hunting; baca kolom kanan untuk usulan bagi `jab_hunter`.

| Setting | Arti dan nilai bawaan [S15] | Usulan untuk `jab_hunter` |
|---|---|---|
| `srchJobsQuota` | Search bersamaan per user; bawaan 3 | Biarkan 3 |
| `srchDiskQuota` | Ruang disk job per user (MB); bawaan 100 | Naikkan secukupnya bila ekspor hasil hunt sering gagal |
| `srchTimeWin` | Rentang waktu maksimum satu search (detik); tanpa batas | Jangan dipasang: `tstats` 90 hari ikut terblokir |
| `srchTimeEarliest` | Seberapa jauh ke belakang search boleh menjangkau; tanpa batas | Jangan dipasang dengan alasan yang sama |
| `srchIndexesAllowed` | Index yang boleh dicari | Index hunting saja; `_internal` hanya bila diperlukan |
| `cumulativeSrchJobsQuota` | Total search bersamaan semua anggota role; butuh `enable_cumulative_quota = true` di `limits.conf` | Pertimbangkan bila anggota role bertambah |

Rem yang lebih tepat sasaran adalah workload management: fitur Splunk Enterprise di Linux (cgroups v1 dan v2; sejak 9.4 versi cgroups dideteksi otomatis) [S14] yang membagi CPU dan memori ke beberapa pool, lalu menerapkan aturan. Aturan bisa menempatkan search ke pool menurut predikat seperti `role`, `search_type`, `index`, atau `search_time_range`; aturan monitoring bisa memberi alert, memindahkan, atau membatalkan search yang melewati `runtime` tertentu; admission rule bisa menolak search seperti `index=*` atau rentang all time. Aturan dievaluasi dari atas ke bawah dan berhenti di aturan pertama yang cocok [S13]. Usulan untuk Reza, ditulis dengan predikat dari contoh dokumentasi [S13]:

```
placement   role=jab_hunter AND search_type=adhoc            -> pool hunt (jatah CPU terbatas)
monitoring  role=jab_hunter AND runtime>15m                  -> alert (kirim notifikasi)
monitoring  role=jab_hunter AND runtime>30m                  -> abort
admission   role=jab_hunter AND (index=* OR search_time_range=alltime) -> filter
```

Server Splunk PT JAB berjalan di Linux, jadi fitur ini bisa dipakai; apakah workload management sudah aktif dan pool apa yang ada, cek bersama Reza sebelum aturan dibuat. Aturan abort 30 menit akan membatalkan search seperti baseline Kamis lalu. Itu disengaja: search seperti itu harus ditulis ulang dengan `tstats`, bukan diberi waktu lebih lama.

## 2. Contoh dan langkah praktis: `HUNT-2027-007` di Splunk PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Query ditulis untuk Splunk PT JAB; untuk latihan, jalankan versi yang disesuaikan di lab pribadi (bagian 3).

Asumsi data yang berlaku untuk semua query di bawah: Sysmon dikirim universal forwarder ke `index=sysmon` dengan `sourcetype=XmlWinEventLog` dan diparsing Splunk Add-on for Sysmon; `Endpoint.Processes` diakselerasi 90 hari di `jkt-splunk-es01` dan dibaca `jkt-splunk-sh01` sebagai reader. Workstation ber-Sysmon PT JAB berjumlah 153 dan semuanya di Jakarta (OU `Workstations-EDR` berada di bawah OU Jakarta), sehingga filter workstation cukup `JKT-WS-*`. Per Februari 2027 ada dua catatan cakupan dari pemeriksaan kesiapan data minggu lalu: Sysmon di `JKT-WS-0532` diam sejak Selasa 2027-02-02 10:14, dan `JKT-WS-0538` serta `JKT-WS-0448` adalah laptop yang sedang mati.

Hunt ini memakai ulang dua artefak `HUNT-2027-006`. Pertama, search macro `jab_norm_parentchild`, yang mengubah `ParentImage` dan `Image` menjadi `parent_n` dan `child_n`: huruf kecil, backslash menjadi `/`, folder profil pengguna menjadi `<user>`, segmen folder berversi menjadi `<ver>`, folder acak di `Temp` menjadi `<rnd>`, dan folder GUID menjadi `<guid>`. Contoh: `C:\Program Files\JAB DocSync\4.2.0\jabdocsync-migrate.exe` menjadi `c:/program files/jab docsync/<ver>/jabdocsync-migrate.exe`. Kedua, lookup `jab_hunt_baseline_parentchild.csv` (2.611 baris, Sysmon EID 1 1 sampai 31 Januari 2027) dengan kolom `parent_n`, `child_n`, `executions`, `hosts`, `first_seen`, dan `last_seen`. Karena macro membaca field `ParentImage` dan `Image`, query `tstats` di bawah me-rename `Processes.parent_process_path` dan `Processes.process_path` ke dua nama itu sebelum memanggil macro. Dengan begitu raw dan `tstats` memakai aturan normalisasi yang persis sama.

Abstract `HUNT-2027-007` ditulis Selasa pagi, setelah membalas Reza bahwa hunt hari itu akan menjadi contoh pola dua tahap:

```
ID             : HUNT-2027-007
Dibuat         : 2027-02-16 (Selasa), pemilik: <kamu>, reviewer: Dimas Prasetyo
Trigger        : Lanjutan HUNT-2027-006 (first-seen parent-child 1-10 Feb) dan permintaan admin
                 Splunk agar hunt rentang panjang tidak membebani indexer bersama
Tipe (PEAK)    : Baseline (long tail dan first-seen), diperdalam hypothesis-driven per temuan
Hipotesis      : Bila ada eksekusi lewat rantai proses yang belum pernah terlihat, atau lewat
                 binary proxy bertanda tangan yang jarang dipakai, di workstation ber-Sysmon,
                 pasangan parent-child itu tidak ada di baseline 1 Jan - 10 Feb atau binary itu
                 muncul di sangat sedikit host.
ATT&CK         : Execution (TA0002) dan System Binary Proxy Execution; contoh teknik: T1059,
                 T1204.002, T1218.003 CMSTP, T1218.004 InstallUtil, T1218.009 Regsvcs/Regasm,
                 T1127.001 MSBuild
Data           : Endpoint.Processes dari index=sysmon (Sysmon EID 1), dest JKT-WS-* (153 workstation);
                 binary proxy 2027-01-17 00:00 s.d. 2027-02-16 00:00 WIB (30 hari);
                 first-seen 2027-02-11 00:00 s.d. 2027-02-16 00:00 WIB
Di luar cakupan: 229 workstation tanpa Sysmon (sekitar 60%, termasuk semua workstation Bandung,
                 Surabaya, Medan); JKT-WS-0532 sejak 2 Feb 10:14 (Sysmon diam); server; Linux
Kriteria sukses: semua binary proxy langka dan semua pasangan first-seen diberi label
                 jinak / perlu investigasi / data tidak cukup; uji kesetaraan raw vs tstats lulus
FP yang diduga : rollout agent dan update, build developer, alat dan profil dari tim IT,
                 makro distribusi dokumen
Handover       : IR (Dimas) bila ditemukan; Sari Kusuma untuk catatan rule; Reza untuk angka beban
Target selesai : Selasa 2027-02-16
```

### 2.1 Persempit dengan tstats, lalu perdalam dengan raw

Langkah ini menjawab pertanyaan ketiga Reza dengan contoh: `tstats` menemukan di mana harus melihat, raw hanya dipakai untuk melihat lebih dalam. Binary yang dipilih adalah binary proxy yang jarang dipakai pengguna biasa; `mshta`, `certutil`, `bitsadmin`, `regsvr32`, dan `rundll32` sudah diperiksa di `HUNT-2027-002`.

**Tujuan:** menemukan workstation yang menjalankan `cmstp.exe`, `installutil.exe`, `regasm.exe`, `regsvcs.exe`, atau `msbuild.exe` dalam 30 hari, lalu melihat command line lengkapnya hanya di host yang langka.

Tahap 1, `tstats` cepat untuk melihat sebaran per binary:

```
| tstats summariesonly=true count dc(Processes.dest) AS hosts
    FROM datamodel=Endpoint.Processes
    WHERE index=sysmon Processes.dest="JKT-WS-*"
        Processes.process_name IN ("cmstp.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "msbuild.exe")
        earliest="01/17/2027:00:00:00" latest="02/16/2027:00:00:00"
    BY Processes.process_name
| rename Processes.* AS *
| sort count
```

| Bagian | Fungsi |
|---|---|
| `summariesonly=true` | Hanya membaca ringkasan; wajib di reader sh01 (bagian 1.1) |
| `index=sysmon` | Membatasi ke Sysmon, supaya 4688 dari `wineventlog` tidak ikut (bagian 1.2) |
| `Processes.dest="JKT-WS-*"` | Workstation saja; wildcard di akhir term |
| `Processes.process_name IN (...)` | `IN` dipakai di klausa `WHERE` `tstats` [S2]; di `eval` atau `where` pakai fungsi `in()` |
| `earliest=... latest=...` | Rentang absolut 30 hari di dalam klausa `WHERE`, yang menerima argumen waktu seperti command `search` [S2] |
| `BY Processes.process_name` | Satu baris per binary |

Keluaran ilustrasi:

```
process_name     count  hosts
cmstp.exe        1      1
regasm.exe       6      2
installutil.exe  14     3
msbuild.exe      1912   7
```

`regsvcs.exe` tidak muncul sama sekali. `msbuild.exe` di 7 host dan `regasm.exe` di 2 host diperiksa cepat dengan `tstats` yang sama ditambah `BY Processes.dest Processes.parent_process_name`: semuanya workstation tim DevOps (Lutfi Hakim) dengan parent `devenv.exe` atau `dotnet.exe`, pola build harian. `installutil.exe` di 3 host dijalankan oleh installer layanan dari tim IT. `cmstp.exe` satu kali di satu host adalah long tail yang diperdalam. Satu `tstats` lagi untuk mendapatkan host-nya:

```
| tstats summariesonly=true count min(_time) AS firstTime
    FROM datamodel=Endpoint.Processes
    WHERE index=sysmon Processes.process_name="cmstp.exe"
        earliest="01/17/2027:00:00:00" latest="02/16/2027:00:00:00"
    BY Processes.dest Processes.user
| rename Processes.* AS *
| convert ctime(firstTime)
```

```
dest                           user                 count  firstTime
JKT-WS-0583.corp.jab.example   JAB\taufik.hidayat   1      02/09/2027 10:41:26
```

Tahap 2, raw bertarget hanya pada host, binary, dan hari itu:

```
index=sysmon sourcetype=XmlWinEventLog EventCode=1 host=JKT-WS-0583 cmstp.exe Image="*\\cmstp.exe"
    earliest="02/09/2027:00:00:00" latest="02/10/2027:00:00:00"
| table _time User ParentImage Image CommandLine ProcessGuid
```

Keluaran ilustrasi:

```
_time                User                ParentImage                   CommandLine
2027-02-09 10:41:26  JAB\taufik.hidayat  C:\Windows\System32\cmd.exe   "C:\Windows\System32\cmstp.exe" /s /ns "C:\Tools\JAB\vendor-ras.inf"
```

- Tahap 1 membaca ringkasan; tahap 2 membaca raw hanya pada satu host dan satu hari. `host=JKT-WS-0583` adalah indexed field, dan term literal `cmstp.exe` membantu tsidx sebelum filter `Image` yang memakai wildcard di depan.
- **Cara membaca:** `cmstp.exe` memasang profil Connection Manager dari file INF; penyalahgunaannya (T1218.003) memakai INF yang memuat perintah untuk dijalankan saat instalasi. Dua pivot raw berikutnya di host dan hari yang sama: proses dengan `ParentImage="*\\cmstp.exe"` tidak ada, dan Sysmon EID 3 dari `cmstp.exe` tidak ada. Isi INF tidak tercatat di log mana pun, jadi bagian ini tidak bisa dijawab SIEM. Taufik Hidayat, staf helpdesk, menjelaskan bahwa ia memasang profil akses jarak jauh vendor untuk satu engineer NOC; hash file INF sama dengan salinan di repositori internal `jkt-repo01`, dan isinya (dibuka bersama helpdesk) hanya bagian profil koneksi tanpa bagian perintah. Label: jinak. Rekomendasi ke tim Infrastruktur: distribusi profil lewat CMSTP membuat detection CMSTP butuh pengecualian, jadi pertimbangkan cara lain.
- **Variasi:** ganti daftar `process_name` dengan binary lain dari kelompok yang sama, misalnya `msiexec.exe` atau `odbcconf.exe`; atau ganti `BY Processes.process_name` dengan `BY Processes.parent_process_name Processes.process_name` untuk melihat siapa yang memanggil binary itu.
- **Kapan gagal:** format `dest` di data model berbeda dengan `host` di raw (di sini FQDN vs nama pendek), sehingga tahap 2 kosong bila `dest` disalin apa adanya; binary diganti nama, sehingga `process_name` tidak cocok (pakai `original_file_name` bila TA mengisinya [S7]); atau rentang di luar summary range sehingga tahap 1 diam-diam tidak lengkap.

### 2.2 Stacking panjang yang tetap ringan

Ini stacking parent-child dari Day 05, dijalankan 30 hari atas data model. Hasilnya dipakai di bagian 2.5 untuk membandingkan raw dan `tstats`.

```
| tstats summariesonly=true count dc(Processes.dest) AS hosts
    FROM datamodel=Endpoint.Processes
    WHERE index=sysmon Processes.dest="JKT-WS-*"
        earliest="01/17/2027:00:00:00" latest="02/16/2027:00:00:00"
    BY Processes.parent_process_name Processes.process_name
| rename Processes.* AS *
| where parent_process_name!="unknown"
| where count <= 5 AND hosts <= 2
| sort count
```

- Stacking parent-child (Day 05) atas data model, sehingga 30 hari pun cepat.
- `where count <= 5 AND hosts <= 2` menyisakan pasangan yang jarang dan hanya di sedikit host: long tail.
- `where parent_process_name!="unknown"` membuang baris yang parent-nya diisi `unknown` oleh data model, karena versi raw membuang event yang `ParentImage`-nya kosong (bagian 2.5 menjelaskan kenapa baris ini perlu).
- Field `parent_process_name` ada di dataset `Processes` CIM [S7], tetapi terisi atau tidaknya bergantung pada TA yang memetakan sumbermu. Bila kolom ini berisi `unknown` semua, cek pemetaan TA.

Versi raw yang menjawab pertanyaan sama (dipakai untuk perbandingan di bagian 2.5):

```
index=sysmon sourcetype=XmlWinEventLog EventCode=1 host="JKT-WS-*"
    earliest="01/17/2027:00:00:00" latest="02/16/2027:00:00:00"
| eval parent_process_name=mvindex(split(ParentImage,"\\"),-1), process_name=mvindex(split(Image,"\\"),-1)
| stats count dc(host) AS hosts BY parent_process_name process_name
| where count <= 5 AND hosts <= 2
| sort count
```

`split(ParentImage,"\\")` memecah path di setiap backslash (string SPL `"\\"` adalah satu backslash), dan `mvindex(..., -1)` mengambil elemen terakhir, yaitu nama file. Event yang `ParentImage`-nya kosong menghasilkan `parent_process_name` null dan dibuang oleh `stats`.

Keluaran ilustrasi (ringkas, sama untuk kedua versi):

```
Event Sysmon EID 1 workstation dalam rentang : 19.952.079
Pasangan parent_process_name+process_name   : 1.967
Pasangan dengan count <= 5 dan hosts <= 2    : 389
```

**Cara membaca hasil:** 389 pasangan langka masih terlalu banyak untuk satu hari hunt, sama seperti 1.146 pasangan di `HUNT-2027-001` (Day 01 bagian 2.2). Karena itu `HUNT-2027-007` tidak meninjau long tail ini baris per baris, tetapi memakai dua penyaring yang lebih tajam: binary proxy langka (bagian 2.1) dan pasangan first-seen (bagian 2.4). Sisa long tail ditulis sebagai di luar cakupan.

**Kapan gagal:** stacking per nama file menggabungkan `cmd.exe` dari `System32` dengan `cmd.exe` palsu di folder lain; untuk itu dipakai path yang dinormalisasi (bagian 2.4). Filter `unknown` di versi `tstats` juga membuang event yang memang tidak punya parent, jadi pertanyaan "proses apa yang parent-nya tidak tercatat" harus diajukan terpisah.

### 2.3 Menyimpan baseline sebagai lookup

Search ini adalah pengganti `tstats` untuk search raw 40 menit Kamis lalu. Ia memperbarui `jab_hunt_baseline_parentchild.csv` secara inkremental dari ringkasan, hanya untuk hari yang first-seen-nya sudah ditinjau. Contoh di bawah adalah pembaruan penutup `HUNT-2027-007`: menambahkan 1-15 Februari ke baseline Januari. Kolom dan cara agregasinya sama dengan pembaruan yang dirancang di `HUNT-2027-006`.

```
| tstats summariesonly=true fillnull_value="null" count AS executions
        min(_time) AS first_seen max(_time) AS last_seen
    FROM datamodel=Endpoint.Processes
    WHERE index=sysmon Processes.dest="JKT-WS-*"
        earliest="02/01/2027:00:00:00" latest="02/16/2027:00:00:00"
    BY Processes.parent_process_path Processes.process_path Processes.dest
| rename Processes.parent_process_path AS ParentImage, Processes.process_path AS Image, Processes.dest AS dest
| `jab_norm_parentchild`
| stats sum(executions) AS executions dc(dest) AS hosts min(first_seen) AS first_seen
        max(last_seen) AS last_seen BY parent_n child_n
| inputlookup append=true jab_hunt_baseline_parentchild.csv
| stats sum(executions) AS executions max(hosts) AS hosts min(first_seen) AS first_seen
        max(last_seen) AS last_seen BY parent_n child_n
| outputlookup override_if_empty=false jab_hunt_baseline_parentchild.csv
```

| Bagian | Fungsi |
|---|---|
| `fillnull_value="null"` | Ditulis sebelum fungsi statistik; tanpa ini, event yang `parent_process_path`-nya kosong dibuang diam-diam [S2] |
| `BY ...parent_process_path ...process_path ...dest` | Path lengkap untuk normalisasi, dan host supaya `dc(dest)` tetap benar setelah beberapa path digabung |
| `rename ... AS ParentImage, ... AS Image` | Macro `jab_norm_parentchild` membaca dua field itu; nama disamakan dengan raw |
| `stats ... BY parent_n child_n` (pertama) | Beberapa path mentah menjadi satu pasangan setelah normalisasi |
| `inputlookup append=true` | Menggabungkan baseline lama ke hasil baru [S5] |
| `stats sum(...) max(hosts) min(...) max(...)` (kedua) | Menjumlahkan eksekusi, mempertahankan `first_seen` paling awal; `max(hosts)` adalah pendekatan karena host unik dua periode tidak bisa dijumlahkan |
| `outputlookup override_if_empty=false` | Menulis ulang file, tetapi tidak menghapusnya bila hasil kosong [S5] |

Keluaran ilustrasi pemeriksaan sebelum dan sesudah (`| inputlookup jab_hunt_baseline_parentchild.csv | stats count`):

```
Sebelum pembaruan : 2611 baris (baseline 1-31 Januari 2027)
Sesudah pembaruan : 2620 baris
Job Inspector     : runDuration 7.884 s, resultCount 2620
```

**Cara membaca hasil:** 9 pasangan baru masuk baseline: 5 dari 1-10 Februari yang sudah ditinjau di `HUNT-2027-006`, dan 4 dari 11-15 Februari yang ditinjau di bagian 2.4. Jumlah baris tidak boleh berkurang; bila berkurang, ada yang salah dengan `inputlookup` atau nama kolom. Bandingkan juga dengan biaya search raw yang membangun baseline Januari: 2.418 detik (bagian 2.5) untuk 31 hari, sedangkan pembaruan 15 hari ini 8 detik.

- Rentang berakhir di hari terakhir yang first-seen-nya sudah diambil (`latest="02/16/2027:00:00:00"`, yaitu sampai Senin 15 Februari 23:59:59). Bila hari yang belum diambil first-seen-nya ikut masuk baseline, pasangan baru hari itu dianggap "sudah pernah terlihat" dan tidak pernah muncul.
- `HUNT-2027-006` mengusulkan ke Sari pasangan saved search harian: laporan first-seen pukul 01:00, lalu pembaruan baseline pukul 01:30 untuk hari kemarin. Urutan itu aman karena pasangan baru sudah tercatat di laporan sebelum diserap baseline. Usulan tambahan dari Day ini: kedua saved search itu ditulis dengan `tstats` seperti di atas, sehingga setiap malam yang dibaca adalah ringkasan satu hari, bukan raw. Sampai usulan itu aktif, pembaruan dijalankan manual di akhir setiap hunt first-seen dengan rentang eksplisit.

**Kapan gagal:** nama kolom hasil search berbeda dengan kolom di lookup (misalnya `parent` vs `parent_n`), sehingga `stats` kedua memperlakukannya sebagai pasangan berbeda dan baseline berisi baris ganda; macro diubah setelah baseline dibangun; atau baseline dibangun dari periode yang sudah tercemar aktivitas penyerang, sehingga aktivitas itu dianggap normal. Day 05 membahas cara memilih periode baseline yang bersih.

### 2.4 Hunt first-seen memakai baseline

Langkah ini adalah inti `HUNT-2027-007`: pasangan parent-child yang pertama kali muncul antara Kamis 11 Februari dan Senin 15 Februari. Query membaca 1-15 Februari sekaligus supaya pasangan yang sudah muncul 1-10 Februari (dan sudah ditinjau di `HUNT-2027-006`) tidak muncul lagi, lalu membandingkannya dengan baseline Januari. Query ini dijalankan sebelum pembaruan baseline di bagian 2.3.

```
| tstats summariesonly=true fillnull_value="null" count min(_time) AS first_time
    FROM datamodel=Endpoint.Processes
    WHERE index=sysmon Processes.dest="JKT-WS-*"
        earliest="02/01/2027:00:00:00" latest="02/16/2027:00:00:00"
    BY Processes.parent_process_path Processes.process_path Processes.dest
| rename Processes.parent_process_path AS ParentImage, Processes.process_path AS Image, Processes.dest AS dest
| `jab_norm_parentchild`
| stats sum(count) AS executions dc(dest) AS hosts values(dest) AS host_list min(first_time) AS first_time
    BY parent_n child_n
| where first_time >= strptime("02/11/2027:00:00:00", "%m/%d/%Y:%H:%M:%S")
| lookup jab_hunt_baseline_parentchild.csv parent_n child_n OUTPUT first_seen AS baseline_first
| where isnull(baseline_first)
| eval host_list=if(hosts > 3, hosts." host", mvjoin(host_list, ", "))
| convert ctime(first_time)
| sort - hosts
```

| Bagian | Fungsi |
|---|---|
| `BY ... Processes.dest` | Host ikut dikelompokkan supaya `dc(dest)` tetap benar setelah normalisasi |
| `where first_time >= strptime(...)` | Hanya pasangan yang kemunculan pertamanya di 1-15 Februari jatuh pada 11 Februari atau sesudahnya |
| `lookup ... OUTPUT first_seen AS baseline_first` | Mencocokkan dengan baseline Januari |
| `where isnull(baseline_first)` | Belum pernah terlihat di baseline |
| `eval host_list=if(...)` | Ringkas: daftar host hanya ditampilkan bila sedikit |

Keluaran ilustrasi:

```
parent_n                                                    child_n                                                      executions hosts host_list                     first_time
c:/windows/system32/svchost.exe                             c:/program files/jab assetscan/assetscan.exe                 151        148   148 host                      02/12/2027 09:00:03
c:/program files/jab assetscan/assetscan.exe                c:/windows/system32/windowspowershell/<ver>/powershell.exe   296        148   148 host                      02/12/2027 09:00:11
c:/program files/microsoft office/root/office16/winword.exe c:/windows/system32/cmd.exe                                  1          1     JKT-WS-0592.corp.jab.example  02/15/2027 09:12:44
c:/windows/system32/cmd.exe                                 c:/windows/system32/msinfo32.exe                             1          1     JKT-WS-0605.corp.jab.example  02/11/2027 14:37:09
```

Empat pasangan ditinjau dengan raw bertarget (pola bagian 2.1):

- **JAB AssetScan (dua baris pertama):** agent inventaris aset baru dari tim Infrastruktur, dipasang lewat change ticket mulai Jumat 2027-02-12 pagi. Task terjadwal (dijalankan `svchost.exe` milik Task Scheduler) menyalakan agent, lalu agent memanggil PowerShell dua kali per host. 148 dari 153 workstation ber-Sysmon menjalankannya; lima sisanya mati atau Sysmon-nya diam pada hari itu (termasuk `JKT-WS-0538`, `JKT-WS-0448`, dan `JKT-WS-0532`). Pivot raw di jam pertama rollout: hanya ada satu nilai `CommandLine` untuk PowerShell itu (`-File "C:\Program Files\JAB AssetScan\collect.ps1"`), dan hash `assetscan.exe` seragam di semua host. Label: jinak.
- **WINWORD ke cmd di `JKT-WS-0592`:** raw menunjukkan `ParentCommandLine` membuka `C:\Users\maya.puspita\Downloads\Pembaruan-Template-Surat-2027.docm`, dan `CommandLine` berisi `cmd.exe /c copy /y "\\jkt-filesrv01\template$\JAB-Surat-2027.dotm"` ke folder template Word milik pengguna. Tidak ada proses anak dari `cmd.exe` itu, dan tidak ada koneksi keluar dari host pada menit yang sama. Dokumen dikirim tim Corporate Communication ke staf Marketing Senin pagi; dikonfirmasi ke pengirim dan ke Maya Puspita. Label: jinak. Catatan: distribusi template lewat makro melatih karyawan untuk mengaktifkan makro, dan pola ini akan memicu usulan rule "JAB - Office atau WMI memunculkan shell" dari `HUNT-2027-001`. Catatan ke Sari dan rekomendasi ke Corporate Communication serta IT: distribusikan template tanpa makro.
- **cmd ke msinfo32 di `JKT-WS-0605`:** dijalankan akun admin helpdesk `JAB\adm.taufik` (Taufik Hidayat) dari sesi bantuan jarak jauh, sesuai tiket helpdesk pada jam yang sama. Label: jinak.

**Cara membaca hasil:** pasangan yang muncul di 148 host dalam satu hari hampir selalu rollout; yang perlu dicek adalah change ticket, command line yang seragam, dan hash yang sama, bukan tiap host. Pasangan di satu host dengan parent Office adalah yang paling layak diperdalam, dan memang diperdalam.

**Kapan gagal:** baseline kosong atau baru dibangun sehari, sehingga hampir semua pasangan tampil sebagai "baru" (bangun baseline minimal beberapa minggu dulu); macro berbeda dengan saat baseline dibuat, sehingga semua pasangan terlihat baru; atau pasangan yang sudah dikenal muncul di host baru. First-seen per pasangan tidak melihat `WmiPrvSE.exe` ke `cmd.exe` di host selain `JKT-WS-0517`, karena pasangan itu sudah ada di baseline. Itu hipotesis terpisah di backlog sejak `HUNT-2027-001`.

### 2.5 Membaca Job Inspector: raw vs tstats

Perbandingan ini adalah bukti untuk pertanyaan pertama dan keempat Reza: kenapa raw lambat, dan apakah data model memberi hasil yang sama. Mulai dari job yang dikeluhkan Reza, search raw pembangun baseline `HUNT-2027-006` Kamis 2027-02-11 pukul 13:02. Ringkasan Job Inspector-nya (keluaran ilustrasi):

```
This search has completed and has returned 2,611 results by scanning 96,734,508 events in 2,418.644 seconds
eventCount   20164882
resultCount  2611
runDuration  2418.644
scanCount    96734508
```

Scan rate-nya 96.734.508 dibagi 2.418,644 detik, sekitar 40.000 event per detik, dan sekitar 79% event yang dibaca dibuang karena bukan EID 1. Indexer membaca cepat; search itu lambat karena membaca hampir 97 juta event untuk menghasilkan 2.611 baris.

Untuk perbandingan yang adil, jalankan versi raw dari bagian 2.2 atas 30 hari, lalu buka Inspect Job. Keluaran ilustrasi (diringkas):

```
This search has completed and has returned 389 results by scanning 64,906,108 events in 1,658.756 seconds

Execution costs
Duration (seconds)  Component                  Invocations  Input count  Output count
    23.640          command.eval                     1,536   19,952,079    19,952,079
 1,527.904          command.search                   1,536            -    19,952,079
    68.021          command.search.filter            1,536            -             -
   239.024          command.search.index             1,536            -             -
   321.650          command.search.kv                1,536            -             -
 1,229.310          command.search.rawdata           1,536            -             -
     0.003          command.sort                         1          389           389
    35.226          command.stats                    1,536   19,952,079         1,967
     0.004          command.where                        1        1,967           389
    51.402          dispatch.fetch                   1,537            -             -

Search job properties
eventCount   19952079
resultCount  389
runDuration  1658.756
scanCount    64906108
```

Cara membaca:

1. **Komponen terbesar.** `command.search` 1.528 dari 1.659 detik (sekitar 92%): hampir semua waktu habis sebelum pipe pertama, dengan `command.search.rawdata` 1.229 detik dominan. Sub-komponen berjalan bersamaan, jadi 1.229 + 322 + 239 + 68 tidak harus sama dengan 1.528.
2. **Rasio scan.** `scanCount` 64,9 juta dan `eventCount` 20,0 juta: sekitar 69% event yang dibaca dibuang. Term `EventCode=1` kurang selektif di tsidx karena angka `1` muncul di banyak event lain, sehingga indexer membaca sebagian besar event Sysmon dari host itu.
3. **Scan rate.** 64.906.108 dibagi 1.658,756 detik sekitar 39.129 event per detik, jauh di atas patokan 10-20 ribu [S1]. Indexer membaca cepat; masalahnya volume, jadi solusinya membaca lebih sedikit.
4. **Jalur data.** `command.stats` mengubah 20,0 juta event menjadi 1.967 pasangan, lalu `command.where` menyisakan 389. Command setelah pipe murah; yang mahal menarik 20,0 juta event.

Perbaikan: pakai versi `tstats` bagian 2.2. Run pertama, tanpa `index=sysmon` dan tanpa filter `unknown`, memberi hasil berbeda:

```
This search has completed and has returned 403 results ... in 24.117 seconds
```

403 bukan 389, jadi kedua versi belum menjawab pertanyaan yang sama. Untuk mencari sumber selisih, hitung isi dataset per index dan source:

```
| tstats summariesonly=true count FROM datamodel=Endpoint.Processes
    WHERE Processes.dest="JKT-WS-*"
        earliest="01/17/2027:00:00:00" latest="02/16/2027:00:00:00"
    BY index source
```

```
index        source                                               count
sysmon       XmlWinEventLog:Microsoft-Windows-Sysmon/Operational  19952079
wineventlog  XmlWinEventLog:Security                              18211437
```

Dua hal terbaca dari sini. Event 4688 ikut masuk dataset: proses yang dikecualikan konfigurasi Sysmon tetapi tercatat 4688 muncul sebagai pasangan langka baru, dan pasangan yang tercatat di kedua sumber terhitung dua kali sehingga sebagian tidak lagi langka. Jumlah dari `sysmon` (19.952.079) sama persis dengan `eventCount` raw EID 1, artinya TA di PT JAB hanya memasukkan EID 1 dari Sysmon ke dataset `Processes`. Bila angka itu lebih besar dari raw EID 1, berarti event Sysmon lain juga diberi tag `process` oleh TA, dan filter tambahan diperlukan. Run kedua dengan `index=sysmon`:

```
This search has completed and has returned 390 results ... in 19.826 seconds
```

Selisih tinggal satu baris, dan baris itu ber-parent `unknown`. Sebagian kecil event EID 1 tidak punya `ParentImage` (pemeriksaan kesiapan data minggu lalu mengukurnya sekitar 0,03%). Raw `stats` membuang event itu karena field `BY`-nya null, sedangkan data model mengisi `parent_process_name` dengan `unknown` [S7], sehingga muncul pasangan langka yang tidak ada di raw. Setelah `where parent_process_name!="unknown"` ditambahkan:

```
This search has completed and has returned 389 results ... in 19.402 seconds
resultCount  389
runDuration  19.402
```

`resultCount` sekarang 389, sama dengan raw, karena pertanyaannya sama. `runDuration` turun dari 1.659 ke 19 detik, sekitar 85 kali lebih cepat. `scanCount` versi `tstats` tidak sebanding karena yang dibaca ringkasan; bandingkan `runDuration` dan `resultCount`. Bila `resultCount` tetap berbeda, cek kelengkapan ringkasan 30 hari (bagian 2.7) dan cara TA mengisi `parent_process_name`.

Pola lain: bila `command.search.kv` atau `.lookups` dominan sementara `rawdata` kecil, knowledge object berat berjalan atas setiap event; persempit base search dan pakai `fields` lebih awal. Bila `command.join` atau `command.transaction` dominan, ganti dengan `stats ... BY`. Properti `optimizedSearch` menunjukkan apakah Splunk sudah memindahkan filter ke depan secara otomatis [S1].

**Kapan gagal:** membandingkan hanya `runDuration` dan menyatakan optimasi berhasil tanpa melihat `resultCount`; versi 403 dan 390 baris di atas lebih cepat, tetapi menjawab pertanyaan lain.

### 2.6 Menyimpan query sebagai artefak

Semua query `HUNT-2027-007` disimpan di `jab-hunt/hunts/HUNT-2027-007/queries/`: `01-proxybin-30d.spl`, `02-longtail-30d-tstats.spl`, `02-longtail-30d-raw.spl`, `03-firstseen.spl`, `04-baseline-update.spl`, `05-raw-deepen.spl`, dan `06-summary-check.spl`. Macro `jab_norm_parentchild` sudah ada di repo sejak `HUNT-2027-006`; query ini menyebut versinya di komentar. Contoh isi `03-firstseen.spl`:

```
# Hunt: HUNT-2027-007, first-seen parent-child (path dinormalisasi)
# Hipotesis: rantai proses yang belum pernah terlihat di workstation ber-Sysmon bisa menandakan eksekusi baru
# Data: datamodel Endpoint.Processes, index=sysmon (Sysmon EID 1), dest JKT-WS-* (153 workstation)
# Asumsi: jkt-splunk-sh01 adalah reader ringkasan dari jkt-splunk-es01 -> summariesonly=true wajib
# Asumsi: ringkasan Endpoint lengkap untuk rentang (jalankan 06-summary-check.spl sebelum menyimpulkan)
# Asumsi: baseline jab_hunt_baseline_parentchild.csv sampai 2027-01-31; 1-10 Feb dikeluarkan lewat first_time
# Asumsi: macro jab_norm_parentchild versi HUNT-2027-006, membaca field ParentImage dan Image
# Job Inspector 2027-02-16: runDuration 4.871 s, resultCount 4
# Jalankan: ganti rentang dan tanggal strptime; tinjau tiap hasil, beri label jinak/investigasi/data-kurang
| tstats summariesonly=true fillnull_value="null" count min(_time) AS first_time
    FROM datamodel=Endpoint.Processes
    WHERE index=sysmon Processes.dest="JKT-WS-*"
        earliest="02/01/2027:00:00:00" latest="02/16/2027:00:00:00"
    BY Processes.parent_process_path Processes.process_path Processes.dest
| rename Processes.parent_process_path AS ParentImage, Processes.process_path AS Image, Processes.dest AS dest
| `jab_norm_parentchild`
| stats sum(count) AS executions dc(dest) AS hosts values(dest) AS host_list min(first_time) AS first_time
    BY parent_n child_n
| where first_time >= strptime("02/11/2027:00:00:00", "%m/%d/%Y:%H:%M:%S")
| lookup jab_hunt_baseline_parentchild.csv parent_n child_n OUTPUT first_seen AS baseline_first
| where isnull(baseline_first)
```

Komentar membuat query bisa dipakai ulang tanpa mengingat konteks; baris Job Inspector memberi pembanding bila bulan depan query yang sama mendadak lambat. Untuk pasangan raw dan `tstats` (file `02-...`), simpan juga hasil uji kesetaraan (389 dan 389) beserta dua filter yang membuatnya setara (`index=sysmon` dan `unknown`) di komentar, supaya pembaca berikutnya tahu versi cepatnya sudah diuji.

**Kapan gagal:** query disimpan tanpa macro yang dipakainya, sehingga gagal dijalankan di search head lain; atau rentang di file ditulis relatif, sehingga hasil laporan tidak bisa direproduksi.

### 2.7 Memeriksa dampak dan kesiapan: skipped search dan kelengkapan ringkasan

Bagian ini menjawab sisi lain pertanyaan kedua Reza dengan data, dan sekaligus menjadi pemeriksaan wajib sebelum hunt memakai `summariesonly=true`. Search pertama dijalankan Reza (atau siapa pun dengan akses `_internal`) untuk melihat search apa yang terlewat Kamis lalu:

```
index=_internal sourcetype=scheduler status=skipped host=jkt-splunk-es01
    earliest="02/11/2027:12:00:00" latest="02/11/2027:15:00:00"
| stats count AS skipped min(_time) AS first_skip max(_time) AS last_skip BY savedsearch_name reason
| convert ctime(first_skip) ctime(last_skip)
| sort - skipped
```

Keluaran ilustrasi (reason dipersingkat):

```
savedsearch_name                                    reason                                                          skipped first_skip  last_skip
JAB - Banyak logon gagal VPN dari satu sumber       The maximum number of concurrent running jobs for this
                                                    historical scheduled search ... has been reached                4       13:15:00    13:40:00
JAB - Proses dari folder Temp di server             (sama)                                                          2       13:20:00    13:35:00
JAB - Login Entra dari negara tidak lazim           (sama)                                                          1       13:30:00    13:30:00
```

**Cara membaca:** tujuh run dari tiga correlation search terlewat antara 13:15 dan 13:40, di dalam jendela search baseline (13:02 sampai 13:42). Alasannya batas instance per scheduled search: run sebelumnya masih berjalan saat run berikutnya tiba [S12]. Itu konsisten dengan indexer yang jenuh, bukan dengan slot es01 yang habis. Bila alasannya "maximum number of concurrent historical scheduled searches on this instance", masalahnya slot scheduler di es01, dan itu urusan konfigurasi atau jadwal, bukan hunt. Teks reason persisnya bisa sedikit berbeda antar versi; kelompokkan per `reason` dulu seperti contoh Lantern [S12]. Untuk memastikan, lihat waktu jalan search yang sukses di jendela yang sama:

```
index=_internal sourcetype=scheduler status=success host=jkt-splunk-es01
    savedsearch_name="JAB - Banyak logon gagal VPN dari satu sumber"
    earliest="02/11/2027:11:00:00" latest="02/11/2027:15:00:00"
| timechart span=15m max(run_time) AS max_run_time_s
```

Keluaran ilustrasi: `max_run_time_s` sekitar 40 detik sebelum 13:00 dan sesudah 13:45, tetapi 312 sampai 497 detik di antara keduanya. Search yang dijadwalkan setiap 5 menit tidak mungkin selesai tepat waktu bila satu run memakan lebih dari 300 detik.

Pemeriksaan kedua adalah status ringkasan `Endpoint` di writer, lewat endpoint REST `admin/summarization` dengan `by_tstats=1` [S11]. Search ini dijalankan di `jkt-splunk-es01` oleh Reza:

```
| rest /services/admin/summarization by_tstats=1 splunk_server=local count=0
| search summary.id="DM_Splunk_SA_CIM_Endpoint"
| table summary.id summary.complete summary.earliest_time summary.latest_time summary.is_inprogress
    summary.last_error summary.latest_run_duration
```

```
summary.id                  DM_Splunk_SA_CIM_Endpoint
summary.complete            1.000000
summary.earliest_time       1794935560
summary.latest_time         1802742900
summary.is_inprogress       0
summary.last_error
summary.latest_run_duration 41.204
```

**Cara membaca:** `summary.id` berformat `DM_<app>_<data model>` [S11]. `summary.earliest_time` 1794935560 adalah 2026-11-18 00:12:40 WIB, sekitar 90 hari ke belakang sesuai summary range, dan `summary.latest_time` 1802742900 adalah 2027-02-16 08:55:00 WIB. Rentang 17 Januari sampai 16 Februari berada di dalamnya. `summary.complete` menyatakan apakah ringkasan lengkap; contoh di dokumentasi menampilkan nilai `1.000000` [S11], tetapi rentang nilainya tidak dijelaskan, jadi cek perilakunya di instance-mu saat ringkasan sedang dibangun.

Pemeriksaan ketiga bisa kamu jalankan sendiri di sh01 tanpa akses REST es01: hitungan harian dari ringkasan, untuk melihat hari yang bolong.

```
| tstats summariesonly=true count FROM datamodel=Endpoint.Processes
    WHERE index=sysmon Processes.dest="JKT-WS-*"
        earliest="01/17/2027:00:00:00" latest="02/16/2027:00:00:00"
    BY _time span=1d
| eval day=strftime(_time, "%a %Y-%m-%d")
| table day count
```

```
day             count
Sun 2027-01-17  369647
Mon 2027-01-18  816685
Tue 2027-01-19  810516
...
Fri 2027-02-12  782336
Sat 2027-02-13  352465
Sun 2027-02-14  355855
Mon 2027-02-15  819296
(30 baris, total 19952079; hari kerja 755281-831708, akhir pekan 349292-369687)
```

**Cara membaca:** pola hari kerja dan akhir pekan konsisten, tidak ada hari kerja yang anjlok, dan totalnya sama dengan `eventCount` raw di bagian 2.5. Hari kerja Februari sedikit lebih rendah daripada Januari, sesuai satu host yang Sysmon-nya diam sejak 2 Februari dan dua laptop yang mati. Hari kerja dengan hitungan jauh di bawah hari kerja lain adalah tanda ringkasan bolong atau forwarder bermasalah; untuk hari itu, jalankan raw atau tulis "data tidak cukup".

**Kapan gagal:** log `_internal` dari es01 tidak diteruskan ke indexer, sehingga search scheduler kosong walaupun ada skip; atau ringkasan "lengkap" untuk definisi data model lama, padahal definisinya baru diubah (lihat `allow_old_summaries`, bagian 1.1).

### 2.8 Laporan `HUNT-2027-007` dan balasan untuk Reza

Laporan ini menutup hunt dengan format yang sama dengan Day 01 bagian 2.4.

```
ID            : HUNT-2027-007                              Selesai: Selasa 2027-02-16
Hasil         : Tidak ditemukan aktivitas berbahaya
Cakupan nyata : 153 workstation ber-Sysmon (JKT-WS-*), Endpoint.Processes dari index=sysmon (EID 1).
                Binary proxy (cmstp, installutil, regasm, regsvcs, msbuild): 17 Jan - 16 Feb 2027.
                First-seen parent-child: 11 - 16 Feb 2027 terhadap baseline 1 Jan - 10 Feb 2027.
                Di luar cakupan: 229 workstation tanpa Sysmon (sekitar 60%); JKT-WS-0532 sejak 2 Feb
                (Sysmon diam); server; Linux; 389 pasangan long tail 30 hari yang bukan first-seen
Kelengkapan   : Ringkasan Endpoint lengkap sejak 18 Nov 2026; hitungan harian konsisten; uji kesetaraan
                raw vs tstats 389 = 389 (setelah index=sysmon dan filter parent unknown)
Jinak terkonfirmasi : cmstp profil vendor (JKT-WS-0583); msbuild/regasm build DevOps (7 dan 2 host);
                installutil installer IT (3 host); JAB AssetScan rollout 12 Feb (2 pasangan, 148 host);
                WINWORD -> cmd salin template (JKT-WS-0592); cmd -> msinfo32 tiket helpdesk (JKT-WS-0605)
Deteksi       : Pola WINWORD -> cmd akan memicu usulan rule "JAB - Office atau WMI memunculkan shell";
                catatan pengecualian dan rekomendasi distribusi template tanpa makro -> Sari Kusuma
Rekomendasi   : Distribusi profil koneksi lewat CMSTP diganti -> tim Infrastruktur (Agung Prabowo)
Efisiensi     : Stacking 30 hari raw 1.659 s vs tstats 19 s; baseline inkremental 8 s vs rebuild raw 2.419 s
Baseline      : Diperbarui sampai 2027-02-15 (2.611 -> 2.620 baris)
Hipotesis baru: (1) first-seen per host untuk pasangan yang sudah dikenal; (2) proses dengan parent
                tidak tercatat (parent unknown) -> backlog
```

Balasan untuk Reza dikirim Selasa siang. Setiap baris merujuk subbagian di atas supaya Reza bisa membaca alasannya.

| Pertanyaan Reza | Jawaban singkat | Dasar |
|---|---|---|
| Kenapa 40 menit | Raw membaca hampir 97 juta event Sysmon untuk 2.611 baris; scan rate normal, volumenya yang berlebihan | Bagian 1.3, 1.6, 2.5 |
| Kenapa search ES terlewat dan batasan role | Indexer jenuh membuat correlation search lebih lama dari intervalnya; usul workload rule untuk `jab_hunter`, bukan `srchTimeWin` | Bagian 1.8, 2.7 |
| Bisakah pakai data model | Bisa, sh01 sudah reader ringkasan es01; raw hanya untuk irisan kecil | Bagian 1.1, 1.2, 2.1 |
| Apakah sama lengkap | Sama bila filternya setara dan ringkasan lengkap; dibuktikan dengan uji kesetaraan dan cek ringkasan | Bagian 1.1, 2.5, 2.7 |
| Dijadwalkan malam semua | Tidak; eksplorasi tetap interaktif dengan `tstats`; yang terjadwal hanya laporan first-seen dan pemeliharaan baseline versi `tstats` | Bagian 1.4, 2.3 |
| Baseline di mana | Lookup kecil di sh01, diperbarui inkremental dengan `tstats` dan `override_if_empty=false`; query di repo `jab-hunt` | Bagian 1.5, 2.3, 2.6 |
| Angka Job Inspector | SID, waktu, rentang, `runDuration`, `scanCount`, `eventCount`, `resultCount`, tiga komponen termahal | Bagian 1.6, 2.5 |

**Kapan gagal:** balasan hanya berisi "ke depan saya pakai `tstats`" tanpa angka sebelum dan sesudah. Admin baru butuh bukti yang bisa ia cek sendiri di Job Inspector dan log scheduler.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** Splunk lab dengan Sysmon dari minimal satu VM Windows (snapshot bersih), dipetakan ke data model `Endpoint` lewat Splunk Add-on for Sysmon dan Splunk Common Information Model add-on, dengan akselerasi `Endpoint` aktif; baseline dan hipotesis dari Day 03 dan Day 05. Jangan memakai data, nama, atau kejadian dari pekerjaan nyata; PT JAB hanya contoh fiktif. Ganti semua rentang absolut di query bagian 2 dengan rentang data lab-mu, dan ganti filter host dengan nama VM-mu.

1. **Cek akselerasi.** Di Settings > Data models, catat status akselerasi dan summary range `Endpoint`. Jalankan query bagian 2.7 (REST `admin/summarization`) dan catat `summary.complete` serta `summary.earliest_time`. Jalankan query bagian 2.2 dengan `summariesonly=true` lalu `false`; selisih `resultCount` berarti ringkasan belum lengkap.
2. **Isi dataset.** Jalankan query `BY index source` dari bagian 2.5 di lab-mu. Bila kamu juga mengirim 4688, lihat apakah keduanya masuk `Endpoint.Processes`. Bandingkan hitungan Sysmon di data model dengan raw `EventCode=1` di rentang yang sama; bila berbeda, cari event code Sysmon mana yang diberi tag `process` oleh TA-mu (lihat `eventtypes.conf` dan `tags.conf` add-on).
3. **Raw vs tstats.** Jalankan kedua versi bagian 2.2 di rentang yang sama. Catat `runDuration`, `scanCount`, `eventCount`, `resultCount`, dan komponen termahal. Ulangi sampai `resultCount` sama, dan tulis apa yang harus diubah agar setara.
4. **Persempit lalu perdalam.** Jalankan bagian 2.1 dan bandingkan `scanCount` tahap 2 dengan menarik raw EID 1 seluruh rentang.
5. **Macro normalisasi di jalur `tstats`.** Buat macro normalisasi path seperti yang dipakai di bagian 2 (aturan huruf kecil, backslash ke `/`, `<user>`, `<ver>`, `temp/<rnd>`, `<guid>`; Day 05 memuat isi lengkapnya). Uji dulu dengan `| makeresults | eval ParentImage="C:\\Windows\\explorer.exe", Image="C:\\Users\\alice\\AppData\\Local\\Temp\\abc123\\setup.exe"` lalu panggil macro; hasil `child_n` yang diharapkan `c:/users/<user>/appdata/local/temp/<rnd>/setup.exe`. Lalu jalankan baseline yang sama dua kali, sekali dari raw dan sekali dari `tstats` dengan `rename` ke `ParentImage` dan `Image` (bagian 2.3), dan pastikan jumlah baris `parent_n`/`child_n` sama.
6. **Baseline aman.** Bangun baseline dengan pola bagian 2.3. Lalu, pada salinan lookup, jalankan search yang sengaja tidak menghasilkan apa-apa dengan `outputlookup` tanpa `override_if_empty=false`, dan amati file itu hilang. Ulangi dengan `override_if_empty=false` dan pastikan file tetap ada.
7. **First-seen dan bukti menangkap target.** Di VM lab dengan snapshot, buka `cmd.exe` lalu jalankan `msinfo32.exe`. Sysmon mencatat EID 1 dengan `ParentImage` berakhiran `cmd.exe` dan `Image` berakhiran `msinfo32.exe`, pasangan yang hampir pasti belum ada di baseline. Tunggu ringkasan diperbarui (default 5 menit), jalankan hunt first-seen bagian 2.4, pastikan pasangan itu muncul, lalu kembalikan snapshot.
8. **Job Inspector.** Untuk hunt paling lambat, hitung scan rate, tentukan apakah masalahnya kecepatan baca atau volume, optimalkan, dan ukur ulang dengan `resultCount` yang sama.
9. **Skipped search.** Buat dua scheduled search di lab: satu setiap menit yang sengaja lambat (misalnya raw atas seluruh data lab), satu lagi ringan. Setelah 15 menit, jalankan query skipped dari bagian 2.7 (tanpa filter `host` es01) dan catat `reason` yang muncul. Hapus scheduled search itu setelahnya.

**Hasil yang sebaiknya tersimpan:**

- Status akselerasi, nilai REST `admin/summarization`, dan perbandingan `summariesonly=true` vs `false`.
- Tabel raw vs `tstats` dengan angka Job Inspector, termasuk langkah yang membuat `resultCount` sama.
- Hasil uji macro normalisasi untuk minimal tiga contoh path.
- Bukti `override_if_empty` (sebelum dan sesudah).
- Hunt first-seen yang menangkap pasangan dari aktivitas uji, sebagai artefak `.spl` berkomentar dengan baris Job Inspector.
- Daftar `reason` skipped search dari lab dan artinya.

**Variasi tantangan:** ambil satu hunt yang di Day 05 kamu jalankan sebagai raw search, lalu tulis ulang sepenuhnya dengan `tstats` atas data model. Bandingkan tidak hanya waktu, tetapi juga field yang hilang (yang tidak ada di model). Putuskan untuk hunt itu apakah kecepatan sepadan dengan kehilangan field, dan tulis alasannya. Bila lab-mu punya dua search head, coba konfigurasi reader dengan `acceleration.source_guid` dan bandingkan hasil `summariesonly=true` di reader dan writer.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat menjalankan hunt di Splunk. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Hunt timeout atau antre lama | Base search terlalu luas; raw di rentang panjang | Persempit di awal; pakai `tstats` (bagian 2.1, 2.2) |
| `tstats` nol hasil, raw ada | Data model tidak terakselerasi; tag atau field CIM tidak dipetakan TA | Uji `summariesonly=false`; cek status akselerasi dan tag event raw |
| `tstats` nol hasil di search head lain | Search head itu bukan reader; `acceleration.source_guid` salah; data model reader di app berbeda | Cek `datamodels.conf` reader dan app-nya [S10] |
| `tstats` lebih sedikit hasil dari raw | Ringkasan tertinggal atau rentang hunt melebihi summary range | Bandingkan `summariesonly=true` vs `false`; cek REST dan hitungan harian (bagian 2.7) [S3] |
| `tstats` lebih banyak atau berbeda dari raw | Sumber lain masuk dataset (4688, event Sysmon selain EID 1) | Hitung `BY index source`; tambahkan `index=` (bagian 2.5) |
| Baris hilang dari hasil `tstats` | Field `BY` null dan tidak ada `fillnull_value` | Tambahkan `fillnull_value` sebelum fungsi statistik [S2] |
| Baseline first-seen menandai semua | Baseline kosong, rentang tumpang tindih, atau normalisasi berbeda | Bangun baseline dulu; pisahkan rentang; pakai macro yang sama (bagian 2.3, 2.4) |
| Lookup baseline mendadak hilang | `outputlookup` dengan hasil kosong dan `override_if_empty` bawaan | Pulihkan dari salinan; tambahkan `override_if_empty=false` [S5] |
| Correlation search skipped saat hunt berjalan | Indexer jenuh oleh raw search panjang | Cek log scheduler dan `run_time` (bagian 2.7); ganti ke `tstats`; workload rule (bagian 1.8) |
| Hitungan user salah | Field user multivalue (Subject vs target) | Pakai field CIM `user` atau ambil nilai target eksplisit (bagian 1.7) |
| Hunt di BOTS kosong | Rentang relatif atas dataset statis | Pakai rentang absolut dataset (bagian 1.7) |
| Macro tidak ditemukan | Macro tidak dibagikan ke app atau tidak ada izin baca | Cek Settings > Advanced search > Search macros dan permission-nya |
| Job Inspector tidak bisa dibuka | Job sudah kedaluwarsa | Jalankan ulang; simpan job (Job > Save) bila perlu dibuka lagi nanti [S1] |

## 5. Kesalahan umum dan jebakan

- **Menarik rentang panjang sebagai raw** lalu memfilter belakangan; persempit di base search.
- **Menyimpulkan "tidak ditemukan" dari `summariesonly=true`** padahal ringkasan bolong. Itu hasil "data tidak cukup".
- **Menganggap optimasi berhasil hanya karena lebih cepat**, tanpa mengecek `resultCount` tetap sama. Versi `tstats` tanpa `index=sysmon` di bagian 2.5 lebih cepat dan salah.
- **Menganggap nama dataset menjamin isinya.** `Endpoint.Processes` berisi apa pun yang diberi tag `process` dan `report` oleh TA [S7].
- **Menulis `fillnull_value` setelah `BY`.** Argumen itu milik `tstats` dan ditulis sebelum fungsi statistik.
- **Memakai `srchTimeWin` sebagai rem hunt.** Batas itu ikut memblokir `tstats` rentang panjang yang justru ringan; rem yang tepat adalah workload rule berbasis `runtime` (bagian 1.8).
- **Mengandalkan `srchFilter` untuk membatasi data hunter.** Search filter tidak berlaku pada data model terakselerasi [S2].
- **Baseline diperbarui dengan `latest=now`.** Hari yang belum ditinjau masuk baseline dan first-seen tidak pernah menemukannya.
- **Hunt yang tidak disimpan.** Query di riwayat search bar hilang; simpan artefak berkomentar beserta macro yang dipakainya.
- **Menjadwalkan hunt eksploratif sebagai alert.** Alert dibuat lewat proses deteksi setelah handover.
- `[komunitas, belum terkonfirmasi]` Banyak praktisi memulai hunt dengan `tstats` atas data model untuk mempersempit sebelum menyentuh raw. Pola ini konsisten dengan dokumentasi akselerasi Splunk [S3], tetapi hanya berlaku bila akselerasi di lingkunganmu sehat; cek status ringkasan dulu.

## 6. Catatan terkini

Bagian ini menampung detail versi dan perubahan produk yang tidak mengubah alur kerja di atas, tetapi berguna saat membaca dokumentasi atau query lama.

- Pendekatan `tstats` atas data model terakselerasi tetap cara tercepat menjalankan hunt agregat di rentang panjang [S2][S3]. Dokumentasi tstats dan Job Inspector versi 10.6 memuat isi yang dipakai Day ini, termasuk patokan scan rate 10-20 ribu event per detik [S1][S2].
- Splunk Enterprise 10.6 dirilis 30 September 2026 [S19]. Catatan rilisnya tidak mencantumkan perubahan untuk `tstats`, akselerasi data model, Job Inspector, atau workload management [S19].
- CIM 6.4.0 dirilis 4 Februari 2026 dan menambahkan beberapa field, termasuk field user di sebagian dataset `Endpoint` [S18]. Rilis berikutnya memakai nomor 8.x yang disamakan dengan nomor versi ES; CIM 8.7.0 dirilis 2 September 2026 dengan perubahan navigasi saja [S18]. Dataset `Processes` di CIM 8.7 tetap memakai tag `process` dan `report` dan field yang sama dengan yang dipakai Day ini [S18]. Dokumentasi lama yang menyebut "CIM 6.x" dan yang baru "CIM 8.x" merujuk add-on yang sama.
- Macro `security_content_summariesonly` di repo Security Content diperbarui pada 2026-05-13 dan kini merujuk ke tiga macro konfigurasi terpisah (`summariesonly_config`, `oldsummaries_config`, `fillnull_config`), dengan nilai bawaan `summariesonly=false` [S8]. Query lama yang mengasumsikan macro ini selalu `true` bisa berjalan lebih lambat tetapi lebih lengkap dari dugaanmu. Analytic "Windows Office Product Spawned Uncommon Process" versi 9 (diperbarui 2026-05-13) menggantikan beberapa analytic lama per child process (cmd, rundll32, regsvr32, dan lainnya) [S17].
- Splunk Add-on for Sysmon versi 5.0.1 (6 Juli 2026) kompatibel dengan Splunk 10.0 sampai 10.6 dan CIM 6.x menurut Splunkbase. Event code mana yang dipetakan ke `Endpoint.Processes` bisa berubah antar versi TA; cek ulang dengan uji `BY index source` (bagian 2.5) setiap kali TA diperbarui.
- Workload management mendukung cgroups v1 dan v2, dan sejak Splunk Enterprise 9.4 versi cgroups dideteksi otomatis [S14]. Splunk Cloud Platform tidak mendukung konfigurasi cgroups v2 [S14].
- Di ES 8.7, notable event disebut finding.
- Day 08 memindahkan hunting ke Wazuh indexer (OpenSearch) untuk data yang tidak ada di Splunk.

## 7. Cheat sheet

```
RAW vs DM  raw: field lengkap, lambat di rentang panjang | tstats: cepat (terakselerasi), hanya field CIM
AKSELERASI ringkasan tsidx di indexer, update tiap 5 menit ; summary range <= retensi index sumber
READER     ringkasan terikat GUID writer ; reader: acceleration.source_guid di datamodels.conf, app sama
           di reader pakai summariesonly=true + cek kelengkapan sendiri
SUMMONLY   true: cepat, bisa bolong | false (bawaan): bagian belum diringkas dibaca dari raw
FILLNULL   tstats fillnull_value="null" count ... BY ...   (sebelum fungsi, bukan setelah BY)
SETARA     raw dan tstats harus resultCount sama ; cek "| tstats count ... BY index source" ; index=sysmon ; buang parent "unknown"
POLA       tstats mempersempit (host/proses/waktu) -> raw bertarget pada irisan kecil (CommandLine, user)
EFISIEN    persempit di base search ; wildcard di akhir term ; term literal ; fields awal ; stats/sort di akhir
           BY kardinalitas tinggi = memori besar ; rentang absolut di laporan, -30d@d di jadwal
MODE       interaktif (eksplorasi, mulai dengan tstats) | terjadwal (baseline; schedule_window; bukan alert)
BASELINE   tstats inkremental -> inputlookup append=true -> stats min/max -> outputlookup override_if_empty=false
           latest = hari terakhir yang first-seen-nya sudah diambil, bukan now
SIMPAN     query .spl berkomentar + macro | hasil + laporan | angka Job Inspector | hasil uji kesetaraan
JOB INSP   Job > Inspect Job ; command.search.rawdata/.index tinggi -> baca lebih sedikit ; .kv/.lookups -> fields lebih awal
           scanCount >> resultCount -> sparse ; scan rate = scanCount/runDuration (10-20k/s baik)
           join/transaction mahal -> stats BY ; optimizedSearch = query yang benar-benar dijalankan
SKIPPED    index=_internal sourcetype=scheduler status=skipped | stats count BY savedsearch_name reason
           "running jobs for this historical scheduled search" = run sebelumnya masih jalan
RINGKASAN  | rest /services/admin/summarization by_tstats=1 -> summary.complete, earliest_time, latest_time
           | tstats count ... BY _time span=1d -> hari kerja yang anjlok = bolong
ROLE       srchJobsQuota 3 ; jangan srchTimeWin untuk hunter ; srchFilter tidak berlaku di DM terakselerasi
WLM        role=jab_hunter AND search_type=adhoc -> pool hunt ; runtime>30m -> abort ; index=* -> filter
AKURASI    dataset statis -> rentang absolut ; field user bisa multivalue (Subject vs target)
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Hunt first-seen dengan `tstats summariesonly=true` di `jkt-splunk-sh01` tidak mengembalikan baris apa pun untuk 11-15 Februari. Jadi hasilnya tidak ditemukan." Benarkah?

<details><summary>Jawaban</summary>

Belum tentu. Dengan `summariesonly=true`, `tstats` hanya membaca data yang sudah diringkas, sehingga hasil kosong bisa berarti ringkasan bolong, tertinggal, atau rentang hunt di luar summary range. Sebelum menulis "tidak ditemukan", cek status ringkasan di writer (REST `admin/summarization`: `summary.complete`, `summary.earliest_time`, `summary.latest_time`) dan hitungan harian dari ringkasan. Bila ringkasan tidak lengkap untuk rentang itu, hasilnya "data tidak cukup", bukan "tidak ditemukan". Lihat bagian 1.1 dan 2.7.

</details>

**2. Skenario keputusan.** Versi raw stacking 30 hari mengembalikan 389 baris dalam 1.659 detik. Versi `tstats` pertama mengembalikan 403 baris dalam 24 detik. Apa langkah yang tepat?

- A. Pakai versi `tstats`, karena lebih cepat dan lebih banyak baris berarti lebih lengkap.
- B. Cari sumber selisih dengan menghitung isi dataset per index dan source, tambahkan filter yang membuat kedua versi menjawab pertanyaan yang sama, lalu ulangi sampai `resultCount` sama sebelum memakai versi `tstats`.
- C. Tetap pakai raw untuk hunt ini dan seterusnya, karena data model terbukti tidak bisa dipercaya.

<details><summary>Jawaban</summary>

B. Optimasi tidak boleh mengubah pertanyaan; selisih 14 baris berarti kedua versi menjawab hal berbeda. Di PT JAB selisihnya berasal dari dua hal: 4688 di `wineventlog` yang ikut masuk `Endpoint.Processes` (`index=sysmon` membuat hasilnya 390), dan event tanpa `ParentImage` yang dibuang raw tetapi diisi `unknown` oleh data model (filter `unknown` membuat hasilnya 389). A keliru karena baris tambahan datang dari sumber lain, bukan dari kelengkapan, dan sebagian pasangan malah hilang karena terhitung dua kali. C keliru karena selisihnya bisa dijelaskan dan diperbaiki; menolak data model berarti terus membayar hampir 28 menit per run dan membebani indexer. Lihat bagian 1.2 dan 2.5.

</details>

**3. Pertanyaan jebakan.** "Scan rate search baseline Kamis lalu sekitar 40 ribu event per detik, di atas patokan 10-20 ribu. Jadi search itu sudah efisien, dan 40 menit itu salah indexer." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Scan rate yang tinggi berarti indexer membaca dengan cepat; masalahnya volume yang dibaca, hampir 97 juta event untuk menghasilkan beberapa ribu pasangan. Solusinya membaca lebih sedikit: membangun baseline dari ringkasan data model dengan `tstats` dan memperbaruinya secara inkremental, bukan meminta indexer lebih cepat. Scan rate rendah barulah tanda masalah kecepatan baca (disk, beban indexer, knowledge object berat). Lihat bagian 1.6 dan 2.5.

</details>

**4. Skenario keputusan.** Reza mengusulkan semua hunt dijadwalkan pukul 01:00 setiap malam supaya tidak bentrok dengan jam kerja. Jawaban mana yang paling tepat?

- A. Setuju; semua query hunt dijadikan saved search terjadwal dengan `latest=now`.
- B. Hunt eksploratif tetap interaktif di jam hunting, tetapi wajib dimulai dengan `tstats`; yang dijadwalkan hanya pemeliharaan baseline dan hunt yang sudah stabil, di luar jam puncak, dengan `schedule_window`, dan baseline berakhir di hari terakhir yang first-seen-nya sudah diambil.
- C. Tolak; hunting harus selalu interaktif dan tidak pernah dijadwalkan.

<details><summary>Jawaban</summary>

B. Hunt bergerak mengikuti temuan, jadi eksplorasi tidak bisa dijadwalkan; yang bisa dijadwalkan adalah pekerjaan yang berulang dan stabil, dengan waktu mulai yang disebar. A keliru karena memindahkan beban, bukan menguranginya, dan `latest=now` memasukkan hari yang belum ditinjau ke baseline. C keliru karena pemeliharaan baseline dan hunt berulang memang cocok dijadwalkan. Lihat bagian 1.4 dan 2.3.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Reza Firmansyah, dalam tiga kalimat, kenapa search hunt di `jkt-splunk-sh01` bisa membuat correlation search di `jkt-splunk-es01` terlewat.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Kedua search head punya slot search sendiri, tetapi membaca indexer yang sama, dan search baseline saya membaca hampir 97 juta event raw selama 40 menit sehingga indexer jenuh. Akibatnya correlation search yang biasanya selesai 40 detik berjalan 5 sampai 8 menit, lebih lama dari interval 5 menitnya, dan scheduler melewati run berikutnya karena run sebelumnya masih berjalan; itu terlihat di log scheduler sebagai skip dengan alasan batas instance per scheduled search. Ke depan search seperti itu saya ganti dengan `tstats` atas ringkasan yang sudah dibangun untuk ES, dan saya usulkan workload rule untuk role `jab_hunter` yang membatalkan search lebih dari 30 menit."

Kesalahan yang sering muncul:
- Menyebut slot es01 habis, padahal alasan skip di log menunjuk run sebelumnya yang masih berjalan.
- Tidak menyebut bukti yang bisa Reza cek sendiri (log scheduler dan `run_time`).
- Menawarkan `srchTimeWin` sebagai rem, padahal batas itu ikut memblokir `tstats` rentang panjang.

</details>

**6. Pertanyaan jebakan.** "Saved search baseline sebaiknya dijadwalkan harian dengan rentang sampai `now`, supaya baseline selalu paling baru dan first-seen lebih akurat." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Bila hari berjalan atau hari yang belum diambil first-seen-nya ikut masuk baseline, pasangan baru di hari itu dianggap "sudah pernah terlihat" dan tidak pernah muncul di hunt first-seen. Baseline harus berakhir di hari terakhir yang first-seen-nya sudah diambil; usulan harian dari `HUNT-2027-006` menjalankan laporan first-seen pukul 01:00 sebelum pembaruan pukul 01:30, dan sampai usulan itu aktif, pembaruan dijalankan manual di akhir setiap hunt first-seen dengan rentang eksplisit. Search pembaruan juga perlu `override_if_empty=false`, karena hasil kosong dengan nilai bawaan menghapus file lookup. Lihat bagian 1.5 dan 2.3.

</details>

**7. Interview question (English).** "How do you run threat hunts in Splunk over long time ranges without hurting production searches, and how do you know your faster query is still correct?"

<details><summary>Sample answer</summary>

"I work in two stages. First I narrow down with tstats against accelerated CIM data models, for example Endpoint.Processes, to find the hosts, process pairs or time windows worth a closer look. Then I run targeted raw searches only on that small slice to get command lines and context. Before I trust the fast version, I run it once side by side with the raw version over the same range and require the same result count; when they differ, I break the dataset down by index and source, because data models often include more than one source, like Sysmon and 4688. I also check that the summaries actually cover the range, because summariesonly can silently return partial data, and in that case my result is 'insufficient data', not 'nothing found'. I keep the queries, macros and Job Inspector numbers in a repo, and I agree with the Splunk admin on guardrails such as workload rules for the hunter role instead of hard time-window limits."

What makes this answer strong: it treats speed and correctness as separate requirements, shows a concrete equivalence check, recognizes incomplete summaries as a data gap rather than a negative result, and accounts for the shared platform and the admin's perspective.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Splunk Enterprise Search Manual: View search job properties (10.0; dicek ulang di 10.6) | https://help.splunk.com/en/splunk-enterprise/search/search-manual/10.0/manage-jobs/view-search-job-properties | primer | diakses 2026-10-10; dicek ulang 2026-10-18 (10.0 dan 10.6) | Tinggi. Cara membuka Job Inspector, execution costs, komponen, search job properties, patokan scan rate, `default_save_ttl` |
| S2 | SPL Search Reference: tstats (10.2; dicek ulang di 10.6) | https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.6/search-commands/tstats | primer | diakses 2026-10-10 (10.2); dicek ulang 2026-10-18 (10.2 dan 10.6) | Tinggi. Sintaks, `summariesonly`, `allow_old_summaries`, `fillnull_value`, klausa WHERE hanya indexed field, search filter tidak berlaku pada data model terakselerasi |
| S3 | Knowledge Manager Manual 10.4: Accelerate data models | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.4/use-data-summaries-to-accelerate-searches/accelerate-data-models | primer | diakses 2026-10-10; dicek ulang 2026-10-18 | Tinggi. Ringkasan tsidx, interval update 5 menit, summary range, ringkasan terikat GUID search head, rebuild otomatis, `summariesonly` |
| S4 | Search Manual 9.4: Write better searches | https://help.splunk.com/en/splunk-enterprise/search/search-manual/9.4/optimizing-searches/write-better-searches | primer | diakses 2026-10-10; dicek ulang 2026-10-18 | Tinggi. Filter awal dengan indexed field, `fields`, command non-streaming di akhir, BY kardinalitas tinggi pada `tstats` |
| S5 | SPL Search Reference: outputlookup (10.2; dicek ulang di 10.6) | https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.6/search-commands/outputlookup | primer | diakses 2026-10-10 (10.2); dicek ulang 2026-10-18 (10.6) | Tinggi. Menulis baseline ke lookup, `append`, `override_if_empty` |
| S6 | SPL Search Reference: collect (10.2; dicek ulang di 10.6) | https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.6/search-commands/collect | primer | diakses 2026-10-10 (10.2); dicek ulang 2026-10-18 (10.6) | Tinggi. Menulis hasil ke summary index, sourcetype `stash` dan lisensi |
| S7 | CIM 6.4: Endpoint data model | https://help.splunk.com/en/data-management/common-information-model/6.4/data-models/endpoint | primer | diakses 2026-10-10; dicek ulang 2026-10-18 | Tinggi. Dataset `Processes`, tag `process` dan `report`, field dan nilai bawaan `unknown` |
| S8 | Splunk Security Content (repo GitHub), macro `security_content_summariesonly` dan macro konfigurasinya | https://github.com/splunk/security_content | primer (vendor) | macro diubah 2026-05-13; diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi untuk definisi macro di repo; nilai di instance bisa diubah admin |
| S9 | Threat-Hunting Day 02-05 (loop, hipotesis, data, stacking/baseline) | (lokal) | rujukan internal | 2026-10-08 | Teknik yang dijalankan di Day ini |
| S10 | Knowledge Manager Manual 10.4: Share data model acceleration summaries among search heads | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.4/use-data-summaries-to-accelerate-searches/share-data-model-acceleration-summaries-among-search-heads | primer | diakses 2026-10-18 | Tinggi. `acceleration.source_guid`, lokasi GUID, syarat app yang sama, perubahan di reader, saran `summariesonly=t` |
| S11 | REST API Reference 10.4: Knowledge endpoint descriptions (`admin/summarization`) | https://help.splunk.com/en/splunk-enterprise/rest-api-reference/10.4/knowledge-endpoints | primer | diakses 2026-10-18 | Tinggi untuk daftar field `summary.*`; rentang nilai `summary.complete` tidak dijelaskan |
| S12 | Splunk Lantern: Reducing skipped searches | https://lantern.splunk.com/Platform_Data_Management/Transform_Data/Reducing_skipped_searches | sekunder (panduan vendor) | diakses 2026-10-18 | Sedang-tinggi. Alasan skip, rumus konkurensi dan nilai bawaan, query skipped, remedi. Contoh SPL `bin _time=1h` di halaman itu ditulis tidak lengkap; sintaks yang benar `bin _time span=1h` |
| S13 | Splunk Enterprise 10.4: Workload management examples | https://help.splunk.com/en/splunk-enterprise/administer/manage-workloads/10.4/workload-management-examples | primer | diakses 2026-10-18 | Tinggi. Pool, aturan per role dan jenis search, monitoring rule `runtime`, admission rule, urutan evaluasi |
| S14 | Splunk Enterprise 10.2: Configure cgroups v2 in Splunk Enterprise | https://help.splunk.com/en/splunk-enterprise/administer/manage-workloads/10.2/set-up-linux-for-workload-management/configure-cgroups-v2-in-splunk-enterprise | primer | diakses 2026-10-18 | Tinggi. Workload management di Linux, cgroups v1/v2, deteksi otomatis sejak 9.4 |
| S15 | Splunk Enterprise 10.2: Create and manage roles with authorize.conf | https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.2/perform-advanced-user-and-role-management-in-splunk-enterprise | primer | diakses 2026-10-18 | Tinggi. `srchJobsQuota`, `srchDiskQuota`, `srchTimeWin`, `srchTimeEarliest`, `srchIndexesAllowed`, `cumulativeSrchJobsQuota` dan nilai bawaannya |
| S16 | Search Manual 9.4: Wildcards | https://help.splunk.com/en/splunk-enterprise/search/search-manual/9.4/search-primer/wildcards | primer | diakses 2026-10-18 | Tinggi. Wildcard di awal term dan performa, wildcard di akhir, wildcard di tengah string bertanda baca |
| S17 | Splunk Research: Windows Office Product Spawned Uncommon Process | https://research.splunk.com/endpoint/55d8741c-fa32-4692-8109-410304961eb8/ | primer (konten vendor) | versi 9, diperbarui 2026-05-13; diakses 2026-10-18 | Tinggi untuk SPL analytic dan sumber data; contoh pemakaian `tstats` atas `Endpoint.Processes` |
| S18 | Splunk CIM: release notes 6.4 dan 8.7, Endpoint data model 8.7 | https://help.splunk.com/en/data-management/common-information-model/8.7/introduction/release-notes-for-the-splunk-common-information-model-add-on | primer | diakses 2026-10-18 | Tinggi. Tanggal rilis 6.4.0 dan 8.7.0, penyelarasan nomor versi dengan ES, dataset `Processes` di 8.7 |
| S19 | Splunk Enterprise 10.6 release notes | https://help.splunk.com/en/splunk-enterprise/release-notes-and-updates/release-notes/10.6 | primer | rilis 2026-09-30; diakses 2026-10-18 | Tinggi untuk tanggal rilis dan daftar perubahan |

**Catatan sumber:** angka Job Inspector, log scheduler, nilai REST, dan hitungan harian di bagian 2 adalah ilustrasi yang konsisten secara hitungan; daftar komponen di versi-mu akan berbeda. Patokan scan rate bersifat umum, bukan ambang untuk semua hardware. Rentang nilai `summary.complete` tidak dijelaskan di dokumentasi REST [S11]. Teks persis `reason` skipped search diambil dari ringkasan Lantern [S12], bukan dari spesifikasi produk, jadi cocokkan dengan log di instance-mu. Event code Sysmon mana yang dipetakan ke `Endpoint.Processes` bergantung pada versi TA dan tidak diperiksa dari dokumentasi TA; uji di lab dengan `BY index source`. Ketersediaan macro `drop_dm_object_name` bergantung pada aplikasi yang terpasang; cek di Settings > Advanced search > Search macros. Klaim wildcard yang sebelumnya dirujuk ke [S4] kini dirujuk ke [S16], karena halaman [S4] versi yang dibuka tidak memuat pembahasan wildcard. Seluruh isi `HUNT-2027-007`, konfigurasi reader `jkt-splunk-sh01`, dan usulan role serta workload rule adalah penerapan catatan ini pada organisasi fiktif, bukan hasil eksekusi nyata.
