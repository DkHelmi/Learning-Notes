---
day: 36
title: 'Correlation search (event-based detection): membuat dan menyetel di ES'
researched_on: 2026-10-10
versions_checked: Splunk ES 8.7 (Create event-based detections; Specify the time to run detections; annotations; adaptive response); Splunk Enterprise 10.6; CIM 6.4
---

# Day 36: Membuat dan menyetel correlation search (event-based detection) di ES

Cakupan: membuat correlation search di Enterprise Security.

## Ide inti

Semua yang dikerjakan sampai Day 35 berhenti di layar. Search yang benar, data model yang ternormalisasi, konteks aset dan identitas, annotation, dan skor risiko baru menjadi pekerjaan sebuah SOC ketika ada yang menjalankannya tanpa kamu, setiap belasan menit, juga saat kamu tidur. Detection adalah bentuk akhir itu: sebuah search yang dijadwalkan, diberi ambang, diberi identitas, dan diberi tujuan, yaitu menghasilkan finding yang masuk antrean, atau intermediate finding yang menambah skor risiko, atau keduanya. Membuatnya berarti mengambil keputusan yang tidak terlihat sama sekali di SPL-nya: seberapa sering ia berjalan, rentang waktu mana yang dibacanya, apa yang terjadi ketika data masuk terlambat, apa yang dilakukan terhadap hasil yang berulang, dan apa yang dilihat analyst pada detik ia menyala. Di ES 8 istilah resminya detection. Dokumentasi lama dan banyak tulisan praktisi menyebutnya correlation search, dan keduanya merujuk hal yang sama, yaitu search terjadwal yang menghasilkan finding atau notable dan/atau event risiko.

Yang membuat pekerjaan ini sulit bukan sintaksnya, melainkan kenyataan bahwa hampir semua kesalahan detection tidak memunculkan pesan error. Jendela waktu yang menempel ke "sekarang" kehilangan event yang masuk terlambat. Detection yang dijadwalkan di menit yang sama dengan semua detection lain akan di-skip ketika beban search head tinggi. Ambang yang ditebak menghasilkan false positive setiap hari, atau diam selamanya. Tuning yang ditulis di dalam search inti hilang pada update konten berikutnya. Semuanya terlihat normal di daftar detection, dan baru terbaca sebagai lubang ketika ada insiden yang seharusnya tertangkap.

Padanannya di NOC adalah memasang alarm di NMS, bukan membaca grafiknya. Begitu sebuah threshold dipasang, kamu langsung berhadapan dengan interval polling, dampening supaya satu link yang flapping tidak mengirim lima puluh notifikasi, dan pertanyaan siapa yang menerima notifikasi itu pukul tiga pagi. Batas analogi: alarm NMS berakhir sebagai notifikasi, sedangkan detection di ES berakhir sebagai objek kerja yang punya status, owner, disposisi, dan metrik. Karena itu kualitas sebuah detection diukur dari apa yang terjadi setelah ia menyala, bukan dari apakah ia menyala.

Di PT Jaringan Anak Bangsa (PT JAB, ISP menengah fiktif), kasus brute force VPN SOC-2026-0217 ditemukan analyst L1 lewat search manual pukul dua pagi. Day ini mengubah search itu menjadi detection yang berjalan sendiri setiap 15 menit, termasuk memutuskan lebar dan jeda jendela waktunya, kunci throttlingnya, ambangnya, dan apakah ia pantas menjadi finding atau cukup menambah skor risiko.

**Kapan relevan:** saat memproduksikan hunting query yang sudah terbukti berguna, saat menyetel detection bawaan yang terlalu berisik atau terlalu diam, saat menulis ulang detection yang kehilangan tuningnya setelah update konten, dan saat perlu menjelaskan ke orang lain kenapa sebuah detection ada dan apa batasnya.
**Kapan bukan jawaban:** detection tidak memperbaiki masalah yang sebenarnya ada di ingest, parsing, atau cakupan sumber data, dan tidak menyelamatkan logika deteksi yang dirancang tanpa melihat datanya lebih dulu. Untuk detection berfidelitas rendah yang tetap bernilai, jawabannya risk scoring, bukan finding (Day 35). Detection juga tidak memperbaiki keputusan triage; ia hanya menentukan apa yang sampai ke antrean.

## 1. Konsep inti

### 1.1 Membuat detection: jalur dan field

Jalur: Security content > Content management > + Content > Detection > Event-based detection > Submit untuk membuka detection editor [S1].

Field utama di editor [S1]:

| Bagian | Field | Catatan |
|---|---|---|
| Dasar | Name | Maks 83 karakter (99 dengan prefix/suffix) |
| | App | Lokasi penyimpanan. Menonaktifkan app ikut menonaktifkan detection |
| | UI dispatch context | App untuk tautan adaptive response |
| | Security domain | Threat, Access, Audit, Network, Endpoint, Identity |
| | Description | Apa yang dideteksi dan kenapa |
| | Mode | Guided (wizard) atau manual SPL |
| Search | Search | SPL, dengan preview dan validasi; preview time range default Last 24 hours; Open in search |
| Output | Output type | Finding, intermediate finding, atau keduanya |
| | Intermediate finding | Risk message, score, entity, entity type (Day 35) |
| | Finding | Name, description, entity, investigation type, severity, default owner, default status, next steps, recommended actions |
| Trigger | Conditions | Jumlah hasil/host/sumber, atau kustom |
| | Trigger frequency | Once atau for each result |
| Throttling | Window duration | Rentang throttling |
| | Fields to group by | Kunci throttling (mis. `src`, `user`) |
| Lainnya | Threat objects | Observable (domain, IP, hash, dll.) |
| | Annotations | ATT&CK, CIS, NIST, Kill Chain, dll. (Day 29/30) [S3] |
| | Adaptive response actions | Day 31/41 [S4] |

Field jadwal (cron, schedule window, priority) dijelaskan di bagian 1.2, cek letaknya di editor 8.7.

### 1.2 Menjadwalkan dengan benar

Menurut dokumentasi ES 8.7 [S2]:
- **Real-time schedule:** memprioritaskan data terkini dan performa. Detection di-skip bila tidak bisa berjalan tepat waktu, dan jendela yang terlewat tidak dipindai ulang.
- **Continuous schedule:** memprioritaskan kelengkapan. Detection tidak pernah di-skip.
- **Schedule window:** default auto, menggeser waktu mulai berdasarkan histori performa. Bisa diisi menit tertentu, atau 0 untuk menonaktifkan. Saat aktif, detection mendapat prioritas lebih rendah agar search lain jalan dulu.
- **Schedule priority:** Higher/Highest memaksa detection berjalan tepat waktu, mengesampingkan schedule window.
- **Cron:** mis. `*/15 * * * *` = tiap 15 menit.
- **Praktik terbaik:**
  - jangan jadwalkan semua detection di menit yang sama (staggering);
  - gunakan rentang waktu berjeda dan dibulatkan, mis. `earliest=-60m@m`;
  - pertimbangkan Index Time untuk data yang sering terlambat masuk, mis. sumber cloud [S2].

**Contoh pemilihan:** detection berbasis `tstats summariesonly=true` atas data model terakselerasi, berjalan tiap 15 menit dengan jendela 20 menit berjeda 5 menit (`earliest=-20m@m latest=-5m@m`). Jendelanya sedikit overlap untuk mengompensasi keterlambatan, sedangkan duplikasi dikendalikan throttling.

### 1.3 Mendesain output: finding, risk, atau keduanya

| Karakter detection | Output yang disarankan | Alasan |
|---|---|---|
| Fidelitas tinggi, butuh respons segera (mis. ransomware, credential dumping LSASS) | Finding (+ intermediate finding) | Harus langsung terlihat analyst |
| Fidelitas sedang/rendah, berguna sebagai konteks (mis. discovery commands, PowerShell anomali) | Intermediate finding saja | Masuk RBA; alert hanya bila menumpuk (Day 35) |
| Hanya untuk dashboard/hunting | Tidak keduanya; saved search biasa | Tidak membebani antrean |

### 1.4 Throttling vs suppression vs tuning

- Throttling (di editor): mencegah finding duplikat untuk kombinasi field yang sama dalam jendela tertentu [S1]. Contoh: satu finding per (`src`, `user`) per jam.
- **Tuning logika:** filter atau allowlist (lookup) di SPL. Pada konten ESCU, tuning dilakukan lewat filter macro (`*_filter`) agar tidak hilang saat update (Day 45).
- **Ubah output:** dari finding menjadi intermediate finding untuk detection yang terbukti berisik tetapi tetap bernilai (Day 35).
- Kalibrasi ambang dari data historis (bagian 2.3).
- ES 7 memiliki fitur *notable event suppression* (suppression berbasis search yang menyembunyikan notable dengan kriteria tertentu selama periode tertentu). Padanannya di ES 8.7 perlu dicek di instance.

### 1.5 Kartu detection (dokumentasi)

Setiap detection sebaiknya punya kartu, yaitu bentuk ringkas ADS (Alerting and Detection Strategy). ADS adalah template dokumentasi detection yang dipublikasikan tim incident response Palantir pada 2017. Bagian aslinya: goal, categorization (pemetaan ATT&CK), strategy abstract, technical context, blind spots and assumptions, false positives, validation (cara menguji), priority, dan response (langkah awal analyst). Tujuannya agar detection tidak dibuat sebelum alasan, batas, dan cara ujinya ditulis. Versi ringkas yang cukup untuk kartu:
- tujuan;
- teknik ATT&CK;
- data/data model;
- asumsi;
- blind spot;
- FP diketahui;
- cara uji;
- output (finding/risk);
- skor;
- throttling;
- jadwal;
- pemilik;
- riwayat versi. ES 8.3+ menambah manajemen versi detection (Day 33).

**Tanpa ES:** padanan detection di Splunk Enterprise biasa adalah saved search atau alert dengan jadwal, trigger condition, throttling, dan alert action, dan konsep jadwal serta throttling di Day ini berlaku penuh di sana. Yang tidak ada tanpa ES adalah finding, intermediate finding dan risk, annotation terkelola, adaptive response, analyst queue, serta Detection Studio untuk memantau kesehatan detection (Day 27); hasilnya berupa email, webhook, atau tiket, dan kartu dokumentasinya harus kamu simpan sendiri. Di PT JAB keduanya berjalan bersamaan karena ES baru dipasang di search head terpisah, sehingga detection yang sama kadang perlu ada dalam dua bentuk selama masa transisi.

## 2. Contoh SPL dan langkah di ES

> Keluaran berlabel ilustrasi. ID ATT&CK, cek di v19.

### 2.1 Detection lengkap: brute force diikuti login berhasil (CIM Authentication)

Search (catatan: `count(eval(...))` tidak didukung di `tstats` (Day 25), jadi hitung `count` per `action` lalu pisahkan dengan `stats`):

```
| tstats summariesonly=true allow_old_summaries=false count
    from datamodel=Authentication.Authentication
    where earliest=-20m@m latest=-5m@m
    by Authentication.src Authentication.user Authentication.dest Authentication.action
| rename Authentication.* AS *
| eval f=if(action="failure",count,0), s=if(action="success",count,0)
| stats sum(f) AS failures sum(s) AS successes values(dest) AS dest BY src user
| where failures >= 10 AND successes >= 1
| lookup lab_auth_allowlist.csv src OUTPUT allow
| where isnull(allow)
```

| Baris | Fungsi |
|---|---|
| `tstats ... by ... action` | Hitung per kombinasi termasuk `action` (cepat, data model; Day 25) |
| `earliest=-20m@m latest=-5m@m` | Jendela berjeda dan dibulatkan [S2] |
| `eval f/s` + `stats` | Memisahkan gagal dan sukses per (src, user) |
| `where failures>=10 AND successes>=1` | Logika inti. Ambang dikalibrasi (bagian 2.3). Catatan: jendela 15 menit tidak menjamin urutan (Day 13) |
| `lookup ... allowlist` | Tuning: sumber yang diizinkan (mis. scanner kerentanan) |

**Pengaturan editor (contoh):**

| Field | Nilai |
|---|---|
| Name | `Lab - Auth - Brute Force Followed By Success` |
| Security domain | Access |
| Schedule | Cron `*/15 * * * *`, continuous, schedule window auto |
| Trigger | Number of results > 0, for each result |
| Throttling | Window 1 jam; group by `src`, `user` |
| Output | Finding dan intermediate finding |
| Finding | Severity high; investigation type "Account Compromise"; next steps: cek login sukses dari `src`, reset kredensial bila perlu |
| Intermediate finding | Entity `user` (type user) score 40; entity `src` (type system) score 20; message `"$failures$ failures then success for $user$ from $src$"`, cek sintaks token |
| Threat objects | `src` (ip) bila eksternal |
| Annotations | ATT&CK T1110 Brute Force (Credential Access); untuk pola "gagal lalu sukses" tambahkan T1078 Valid Accounts |
| Adaptive response | Nslookup (src) ad hoc; opsional SOAR playbook akun (Day 42) |

### 2.2 Menguji sebelum mengaktifkan

```
| makeresults count=15
| streamstats count AS n
| eval src="203.0.113.45", user="rina.wulandari", dest="jkt-vpn01",
       action=if(n<=12,"failure","success"), count=1
| eval f=if(action="failure",count,0), s=if(action="success",count,0)
| stats sum(f) AS failures sum(s) AS successes BY src user
| where failures >= 10 AND successes >= 1
```

Hasil yang diharapkan: satu baris (12 gagal, 3 sukses). Ini membuktikan logika pasca-`tstats` sebelum menunggu data nyata (Day 12).

### 2.3 Kalibrasi ambang dari data 30 hari

```
| tstats summariesonly=true count from datamodel=Authentication.Authentication
    where Authentication.action="failure" earliest=-30d@d
    by _time span=15m Authentication.src Authentication.user
| stats perc95(count) AS p95 perc99(count) AS p99 max(count) AS max
```

- Ambang `failures` sebaiknya di atas p99 perilaku normal, lalu disesuaikan dengan toleransi FP.
- Ulangi per segmen (VPN vs AD) bila polanya berbeda.

### 2.4 Memantau detection setelah aktif

- Skipped/terlambat: `index=_internal sourcetype=scheduler savedsearch_name="Lab - Auth*"` (Day 29 bagian 2.2), cek nama saved search detection ES 8 di scheduler log.
- Kualitas: disposition per detection (Day 34); kesehatan di Detection Studio (Day 27).

### 2.5 Lab tanpa ES

Buat saved search/alert dengan search bagian 2.1, jadwal `*/15 * * * *`, trigger "for each result", throttle 1 jam per `src,user`, dan alert action webhook ke Shuffle, yang kemudian membuat case di TheHive (lab-mu).

## 3. Lab praktik

1. Uji logika dengan bagian 2.2.
2. Buat `lab_auth_allowlist.csv` (kosong atau berisi IP scanner lab).
3. **Dengan ES:** buat detection bagian 2.1 lengkap di editor (Security content > Content management > + Content > Detection) [S1].
   **Tanpa ES:** buat alert bagian 2.5.
4. Picu dari VM Windows lab: login RDP/SMB gagal 12 kali lalu berhasil (akun uji).
5. Verifikasi:
   - finding di analyst queue (atau case di TheHive);
   - intermediate finding di risk index;
   - throttling bekerja: picu lagi dalam 1 jam, seharusnya tidak ada finding baru.
6. Jalankan bagian 2.3 dan tetapkan ambang final. Tulis kartu detection (bagian 1.5).
7. Ubah output menjadi "intermediate finding saja", ulangi pemicu, lalu amati perbedaannya di antrean dan Risk analysis.

**Hasil yang sebaiknya tersimpan:**
- Logika teruji dengan makeresults.
- Detection/alert terjadwal dengan jendela berjeda.
- Finding + event risiko muncul; throttling terbukti.
- Ambang dikalibrasi dari data.
- Kartu detection lengkap.

**Variasi tantangan:** buat detection kedua dengan output intermediate finding saja (mis. discovery commands `whoami`, `net group`, `nltest`, cek daftar). Tunjukkan bahwa kombinasi detection ini dan detection bagian 2.1 memicu finding group lewat RBA (Day 35).

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Perbaikan |
|---|---|---|
| Detection tidak pernah fire | Data model tidak terakselerasi (summariesonly=true); jendela waktu tidak berisi data; ambang tinggi | Day 25 bagian 2.4; uji tanpa `summariesonly`; kalibrasi |
| Error saat menyimpan search | `count(eval())` di `tstats`; sintaks token | Pakai versi bagian 2.1 yang benar; cek preview [S1] |
| Finding duplikat | Throttling tidak diset/fields salah | Window + fields to group by [S1] |
| Detection sering skipped | Real-time schedule saat beban tinggi | Continuous; staggering; schedule window [S2] |
| Event terlambat tidak tertangkap | Jendela `_time` terlalu dekat sekarang | Jendela berjeda; Index Time [S2] |
| Tuning hilang setelah update ESCU | Mengedit search inti | Filter macro / kloning (Day 45) |

## 5. Kesalahan umum dan jebakan

- `count(eval(...))` di `tstats` (Day 25). Kesalahan klasik saat memindahkan logika dari `stats`.
- Semua detection di menit yang sama [S2].
- Jendela `earliest=-15m latest=now` tanpa jeda, sehingga event yang terlambat masuk hilang [S2].
- Semua detection menjadi finding. Ini membanjiri antrean. Pertimbangkan RBA (Day 35).
- Tanpa annotation dan kartu dokumentasi. Konteks dan cakupan hilang (Day 29/30).
- `[komunitas]` Praktik penjadwalan di Day ini berasal dari dokumentasi resmi [S2]; pengalaman praktisi soal jeda jendela waktu (5 sampai 10 menit) bervariasi menurut sumber data, jadi ukur ingest lag sendiri (Day 28).

## 6. Catatan terkini

Bagian ini menampung detail versi dan perubahan menu yang membuat dokumentasi lama dan baru terbaca berbeda.

- **ES 8.7:** pembuatan detection lewat Security content > Content management > + Content > Detection dengan editor yang mendukung mode guided/manual dan output finding/intermediate finding [S1].
- **Scheduling ES 8.7:** pilihan real-time vs continuous, schedule window auto, priority, dan Index Time untuk data terlambat [S2].
- **ES 8.3+:** manajemen versi detection (Day 33), cek cara memakainya di 8.7.
- Release notes ES 8.6/8.7 menyebut agen AI yang dapat membantu membuat detection. Hasil buatan AI tetap harus diuji seperti bagian 2.2 dan 2.3.

## 7. Cheat sheet

```
BUAT   Security content > Content management > + Content > Detection > Event-based > Submit
FIELD  Name(<=83) | App | UI dispatch context | Security domain (Threat/Access/Audit/Network/Endpoint/Identity) | Description
       Mode guided|manual | Search (+preview 24h, Open in search)
       Output: finding | intermediate finding | keduanya
         finding: name, desc, entity, investigation type, severity, owner, status, next steps, recommended actions
         intermediate: risk message, score, entity, entity type
       Trigger: conditions + once|for each result | Throttling: window + fields to group by
       Threat objects | Annotations | Adaptive response
JADWAL real-time (bisa di-skip) vs continuous (tidak pernah di-skip) | schedule window auto | priority Higher/Highest
       cron */15 * * * * | stagger | earliest=-20m@m latest=-5m@m | Index Time untuk data terlambat
TUNING throttling | filter macro/allowlist lookup | finding -> risk | kalibrasi p95/p99 | disposition feedback
JEBAKAN tstats + count(eval()) TIDAK BISA
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Rekanmu memilih real-time schedule untuk semua detection penting di PT JAB, dengan alasan "biar tidak ada yang terlewat". Kenapa alasan itu justru terbalik?

<details><summary>Jawaban</summary>

Karena real-time schedule memprioritaskan data terkini dan performa, bukan kelengkapan. Detection dengan jadwal itu di-skip ketika tidak bisa berjalan tepat waktu, dan jendela yang terlewat tidak dipindai ulang, jadi beban search head yang tinggi langsung menjadi lubang cakupan tanpa jejak di hasil detection. Pilihan yang benar untuk detection yang tidak boleh kehilangan apa pun adalah continuous schedule, yang tidak pernah di-skip, dan kalau detection itu memang harus berjalan tepat waktu, schedule priority Higher atau Highest dipakai untuk mengesampingkan schedule window. Lihat bagian 1.2.

</details>

**2. Skenario keputusan.** Sebuah detection ESCU di PT JAB menyala setiap hari karena satu scanner kerentanan internal di `10.20.30.9`. Isinya tetap berguna untuk sumber lain. Apa langkah yang paling tepat?

- A. Edit search inti detection itu dan tambahkan pengecualian `NOT src="10.20.30.9"`.
- B. Isi filter macro milik detection itu dengan pengecualian scanner, atau kloning detection-nya lalu setel klonnya.
- C. Naikkan window throttling menjadi 24 jam dengan group by `src`, supaya scanner hanya memunculkan satu finding per hari.

<details><summary>Jawaban</summary>

B. Konten ESCU diperbarui dari luar, jadi perubahan yang ditulis di dalam search inti akan tertimpa pada update berikutnya dan tuningnya hilang tanpa pemberitahuan. Itu sebabnya setiap detection ESCU menyediakan filter macro berakhiran `_filter` sebagai tempat resmi menaruh pengecualian, dan kloning dipakai bila perubahannya lebih dalam daripada sebuah filter. A adalah kesalahan yang persis dicegah mekanisme itu. C menyembunyikan gejalanya: satu finding scanner per hari tetap finding yang harus ditutup seseorang, dan throttling 24 jam atas `src` sekaligus menelan finding asli dari sumber lain yang kebetulan sama. Lihat bagian 1.4.

</details>

**3. Pertanyaan jebakan.** Sebuah detection berjalan tiap 15 menit dengan `earliest=-15m latest=now`. False positive-nya rendah dan tidak ada error di log scheduler, tetapi saat ditinjau ulang, beberapa kejadian yang eventnya jelas ada di index tidak pernah memunculkan finding. Apa dugaan pertamamu?

<details><summary>Jawaban</summary>

Event itu masuk ke index setelah search yang seharusnya membacanya sudah lewat. Jendela yang menempel ke `now` membaca menit-menit terakhir yang justru paling sering belum lengkap karena ingest lag, dan jendela yang sama tidak dibaca ulang pada jalan berikutnya, sehingga eventnya hilang dari cakupan detection walaupun tetap bisa dicari dengan tangan. Perbaikannya memakai rentang yang berjeda dan dibulatkan, misalnya `earliest=-20m@m latest=-5m@m`, dengan sedikit overlap untuk mengompensasi keterlambatan dan throttling untuk mengendalikan duplikasinya; untuk sumber yang sering terlambat seperti data cloud, pertimbangkan penjadwalan berbasis Index Time. Besar jedanya diukur dari ingest lag sumbermu sendiri, bukan diambil dari angka orang lain. Lihat bagian 1.2 dan 5.

</details>

**4. Jelaskan ulang.** Jelaskan ke engineer NOC yang biasa menyetel alarm NMS, dalam tiga kalimat, perbedaan antara throttling, tuning logika, dan mengubah output detection menjadi risk, beserta kapan masing-masing dipakai.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh jawaban: "Throttling adalah dampening: detection tetap menyala, tetapi finding duplikat untuk kombinasi field yang sama ditahan selama jendela tertentu, jadi ia dipakai ketika alertnya benar tetapi berulang untuk kejadian yang sama. Tuning logika mengubah apa yang dianggap mencurigakan, lewat filter atau allowlist di dalam SPL dan, untuk konten pihak ketiga, lewat filter macro supaya tidak hilang saat update, jadi ia dipakai ketika alertnya memang keliru. Mengubah output menjadi intermediate finding adalah pilihan ketiga: detection tetap hidup dan tetap memberi konteks sebagai skor risiko, tetapi tidak lagi membuat item di antrean, dan itu jawaban untuk detection yang sebenarnya benar tetapi tidak pernah cukup yakin sendirian."

Kesalahan yang sering muncul: memakai throttling untuk menutupi detection yang logikanya salah, sehingga kesalahannya tetap ada tetapi lebih sulit terlihat; menulis pengecualian di search inti konten yang dikelola pihak lain; dan mematikan detection berisik padahal yang dibutuhkan hanya memindahkannya ke risk scoring. Lihat bagian 1.3 dan 1.4.

</details>

**5. Interview question (English).** "You have a hunting query that found something real last month. How do you turn it into a production detection?"

<details><summary>Sample answer</summary>

"First I decide what the output should be. If it is high confidence and needs an immediate response, it becomes a finding; if it is useful but not conclusive on its own, it becomes a risk contribution instead, so it adds context without adding an item to the queue. Then I make the search safe to schedule: push it onto an accelerated CIM data model with tstats where possible, and use a lagged, snapped window such as earliest=-20m@m latest=-5m@m rather than anything ending at now, because the last few minutes are the ones most likely to be incomplete and a missed window is never rescanned. I calibrate the threshold from history rather than guessing, usually by looking at the 95th and 99th percentile of the normal behaviour per source and user over thirty days, and I segment that by population because VPN and domain authentication do not behave the same way. Before enabling it I prove the logic on synthetic data with makeresults, so I know the post-aggregation part is right without waiting for a real event. On the detection itself I set throttling with explicit group-by fields, add the ATT&CK annotation, choose continuous scheduling and stagger the cron so it does not compete with everything else, and keep tuning in a filter macro so an upstream content update cannot silently erase it. Finally I write the detection card: goal, technique, data source, assumptions, blind spots, known false positives, how to test it, and the first response steps. After it goes live I watch two things: the scheduler log for skipped or long-running executions, and the disposition of what it produces, because a detection whose findings are all closed as false positive is a detection that still needs work."

What makes this answer strong: it treats the SPL as the smallest part of the job, names the specific scheduling and windowing behaviour that causes silent gaps, derives the threshold from data instead of intuition, protects the tuning against content updates, and closes the loop with the two signals that tell you whether the detection is actually healthy.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | ES 8.7: Create event-based detections in Splunk Enterprise Security | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/detections/create-event-based-detections-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi |
| S2 | ES 8.7: Specify the time to run detections in Splunk Enterprise Security | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/detections/specify-the-time-to-run-detections-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi |
| S3 | ES 8.7: Add annotations to detections (lihat Day 29) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/detections/add-annotations-to-detections-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi |
| S4 | ES 8.7: Configure adaptive response actions (lihat Day 31) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/detections/configure-adaptive-response-actions-for-detections-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi |
| S5 | SPL Search Reference: tstats (batasan count(eval); lihat Day 25) | https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.2/search-commands/tstats | primer | diakses 2026-10-07 | Tinggi |
| S6 | Palantir: Alerting and Detection Strategy Framework | https://github.com/palantir/alerting-detection-strategy-framework | primer (penulis kerangka) | 2017; diakses 2026-10-10 | Tinggi untuk daftar bagian ADS |

**Catatan sumber:** letak field cron/schedule di editor 8.7, sintaks token risk message, padanan *notable event suppression* di ES 8, dan nama saved search detection di log scheduler perlu dicek di instance. Uraian bagian ADS mengikuti publikasi Palantir [S6].
