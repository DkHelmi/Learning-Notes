---
day: 08
title: 'Hunting di Wazuh dan OpenSearch: alerts vs archives, DQL dan Query DSL, agregasi untuk stacking, batas indexer, dan rule kustom'
researched_on: 2026-10-18
versions_checked: 'Wazuh 4.14.9 (rilis terbaru di catatan rilis, 14 Okt 2026; PT JAB masih di 4.14); dokumentasi Wazuh 4.14 (event logging/archives, logall_json, Filebeat archives, index lifecycle management, custom rules, rules XML syntax, decoders XML syntax, audit configuration, monitoring commands run as root, log_alert_level); ruleset Wazuh v4.14.0 (0365-auditd_rules.xml, 0040-auditd_decoders.xml, 0095-sshd_rules.xml, 0310-ssh_decoders.xml); Wazuh indexer (fork OpenSearch; paket 4.14 memakai seri OpenSearch 2.19); OpenSearch 2.19 docs (DQL, terms) dan docs terbaru (rare_terms, multi_terms, cardinality); Splunk Enterprise 10.6 (SPL pembanding)'
---

# Day 08: Hunting di Wazuh dan OpenSearch (alerts vs archives, DQL dan Query DSL, agregasi, dan rule kustom)

Cakupan: berburu di data Wazuh dengan membedakan alerts dan archives, mengaktifkan dan menghitung biaya archives, menulis DQL di Discover dan Query DSL untuk stacking, least-frequency, dan first-seen, memahami field Wazuh dan batas indexer dibanding Splunk, lalu mengubah temuan hunt menjadi rule kustom Wazuh.

## Ide inti

Wazuh secara default hanya menyimpan event yang cocok dengan rule berlevel minimal `log_alert_level` (default 3). Itu alerts. Hunting justru mencari aktivitas yang tidak memicu rule apa pun, dan event seperti itu hanya tersimpan di archives, yang nonaktif secara default karena memakan disk. Karena itu setiap hunt di Wazuh dimulai dengan satu pertanyaan sebelum query pertama: event yang kamu butuhkan memicu rule berlevel 3 ke atas atau tidak? Bila ya (misalnya login SSH berhasil), alerts sudah cukup dan riwayatnya panjang. Bila tidak (misalnya eksekusi proses dari auditd dengan key kustom yang hanya cocok dengan rule level 0), kamu butuh archives, dan riwayatmu hanya sepanjang archives aktif. Setelah datanya jelas, sisanya adalah OpenSearch: Wazuh indexer adalah fork OpenSearch, jadi DQL dipakai untuk menyaring di Discover, dan Query DSL dengan aggregation dipakai untuk stacking dan first-seen. Pola yang ditemukan dikembalikan ke manager sebagai rule kustom bernomor 100000 ke atas, sehingga hunt berikutnya tidak perlu mencari hal yang sama secara manual.

Kamu sudah mengenal pembagian ini dari NOC. Daftar alarm NMS hanya berisi pesan yang cocok dengan aturan alarm: link down, BGP flap, suhu kartu di atas ambang. Syslog server menyimpan semua pesan router, termasuk ribuan baris yang tidak pernah menjadi alarm. Saat mencari penyebab gangguan yang belum punya alarm, engineer membuka syslog server, bukan daftar alarm. Alerts Wazuh adalah daftar alarm, archives adalah syslog server. Batas analoginya: archives hanya berisi apa yang memang dikumpulkan agent (file dan channel yang dikonfigurasi), pesan yang tidak dikenali decoder hanya tersimpan sebagai teks mentah di `full_log`, dan menyimpan semuanya punya biaya disk yang harus diputuskan pemilik server, sama seperti retensi syslog server.

```
 agent (auditd, sshd, syslog, eventchannel)
      |
      v
 manager: decoder -> rule (level 0..16)
      |                                  \
      | level >= log_alert_level (3)      \ semua event (bila <logall_json>yes</logall_json>)
      v                                    v
 alerts.json                            archives.json
      |                                    |
      +---------- Filebeat ----------------+   (archives: enabled: true di filebeat.yml)
      v                                    v
 wazuh-alerts-*                         wazuh-archives-*      <- Wazuh indexer (OpenSearch)
      \                                    /
       +--- Discover (DQL) | Dev Tools (Query DSL: terms, rare_terms, multi_terms, min) ---+
                                     |
                         temuan -> rule kustom 100000+ di local_rules.xml -> alerts baru
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan. Sejak Februari 2027 kamu, analyst L2, memegang "Program hunt PT JAB" setiap Selasa dan Kamis. Selain Splunk Enterprise sebagai SIEM utama, PT JAB menjalankan Wazuh 4.14 (manager, indexer, dan dashboard dalam satu server) di `jkt-wazuh01` (`10.20.1.40`, jaringan manajemen). Wazuh dipasang Desember 2026 sebagai HIDS untuk empat server Linux tanpa EDR, yaitu `jkt-portal02`, `jkt-radius01`, `jkt-bastion01`, dan `jkt-billing02` (yang terakhir juga punya Microsoft Defender for Endpoint versi Linux), dan terpisah dari Splunk. Sampai pertengahan Februari hanya alerts yang diindeks. Pemeriksaan kesiapan data dua minggu sebelumnya menempatkan archives Wazuh sebagai "bukan prioritas sekarang" karena tidak mengubah hunt yang ada di backlog, dan mencatat bahwa rule auditd untuk syscall `execve` hanya terpasang di 6 dari 37 server Linux. Karena archives tidak butuh anggaran, hanya disk, Lead Infrastruktur Agung Prabowo setuju mencobanya selama satu minggu untuk keempat server: archives aktif sejak Selasa 2027-02-16 pukul 10:12. Kamu menulis dua abstract hunt untuk minggu uji coba itu.

Agung yang menulis, bukan Lutfi Hakim (Lead DevOps, pemilik operasional server aplikasi Linux), karena `jkt-wazuh01` dan disknya milik tim Infrastruktur dan keputusan mempertahankan archives ada di tangannya; Lutfi ikut di utas yang sama karena timnya yang akan menerima alert dari rule baru. Selasa 2027-02-23 pukul 08:30, Agung menulis di utas chat Infrastruktur dan SOC:

> "Archives di jkt-wazuh01 sudah seminggu jalan. Sebelum saya putuskan dipertahankan atau dimatikan, saya perlu beberapa jawaban. Dulu yang tersimpan cuma alert; sebenarnya apa yang bisa di-hunt di Wazuh tanpa archives, dan apa yang baru bisa setelah archives aktif? Berapa biaya disknya seminggu ini, dan kalau dipertahankan, retensinya berapa lama? Tim Pak Lutfi biasa buka Discover; query di sana bedanya apa dengan Splunk? Bisa tidak stacking dan first-seen seperti yang kamu kerjakan di Splunk? Field apa yang bisa dipercaya untuk server Linux kita? Kapan sebaiknya hunt dikerjakan di Splunk saja? Terakhir, kalau kamu menemukan pola yang perlu diawasi, bisa dijadikan rule di Wazuh tanpa membuat tim Pak Lutfi kebanjiran alert?"

Pesan itu memuat tujuh pertanyaan:

1. Apa yang bisa di-hunt di Wazuh bila yang tersimpan hanya alerts, dan apa yang baru mungkin dengan archives?
2. Berapa biaya archives, dan retensi berapa yang masuk akal?
3. Bagaimana query di Wazuh, dan apa bedanya dengan Splunk?
4. Bisakah stacking, least-frequency, dan first-seen dikerjakan di indexer?
5. Field apa yang bisa diandalkan untuk server Linux PT JAB?
6. Kapan hunt sebaiknya dikerjakan di Splunk?
7. Bagaimana temuan dijadikan rule kustom Wazuh tanpa membanjiri penerima alert?

Pertanyaan 1 dijawab di bagian 1.1 dan 1.2, pertanyaan 2 di bagian 1.3, pertanyaan 3 di bagian 1.4, pertanyaan 4 di bagian 1.5, pertanyaan 5 di bagian 1.6, pertanyaan 6 di bagian 1.7, dan pertanyaan 7 di bagian 1.8. Bagian 2 berisi dua hunt minggu uji coba (`HUNT-2027-010` dan `HUNT-2027-011`), pengukuran biaya archives, satu rule kustom yang lahir dari hunt, dan jawaban untuk Agung.

**Kapan relevan:** saat data yang kamu butuhkan hanya ada di Wazuh (server atau sumber yang tidak dikirim ke Splunk, FIM, SCA, rule kustom Wazuh); saat organisasi hanya memakai Wazuh; saat kamu ingin memburu event yang tidak pernah memicu rule; dan saat menguji rule kustom terhadap data nyata sebelum diaktifkan.

**Kapan bukan jawaban:** saat hunt butuh pivot berantai atau korelasi lintas banyak sumber (Splunk lebih luwes, Day 06); saat event yang dibutuhkan memang tidak dikumpulkan agent (archives tidak menciptakan telemetri, perbaiki pengumpulan dulu, Day 04); dan saat sumbernya belum punya decoder, karena stacking atas `full_log` mentah hampir selalu menghasilkan nilai unik.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (hunt, hipotesis, stacking, long tail, baseline, first-seen, abstract, handover, CDB list) tidak diulang. Kolom padanan memakai analogi NOC dan SOC yang sama dengan Day lain.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Wazuh manager | Komponen server yang menerima event dari agent, mendekodenya, dan mencocokkannya dengan rule | Collector yang sekaligus menjalankan aturan alarm |
| Wazuh indexer | Mesin penyimpanan dan pencarian Wazuh, fork dari OpenSearch | Database NMS tempat alarm dan log disimpan |
| Alerts (`wazuh-alerts-*`) | Event yang cocok dengan rule berlevel minimal `log_alert_level` | Daftar alarm NMS |
| Archives (`wazuh-archives-*`) | Semua event yang diterima manager, beralert atau tidak; nonaktif default | Syslog server yang menyimpan semua pesan router |
| `logall_json` | Opsi `ossec.conf` yang menulis archives dalam format JSON yang bisa diindeks | Mengaktifkan forwarding syslog lengkap, bukan hanya trap |
| `log_alert_level` | Level minimal rule agar event disimpan sebagai alert; default 3 | Ambang severity alarm yang ditampilkan |
| Rule level | Tingkat 0 sampai 16 pada rule Wazuh; level 0 berarti tidak menjadi alert | Severity alarm; severity "informational" tidak ditampilkan |
| Decoder | Aturan yang memecah log mentah menjadi field (`srcip`, `audit.exe`) | Parser syslog per vendor |
| `full_log` | Teks log asli yang dianalisis manager | Baris syslog mentah |
| DQL | Dashboards Query Language, bahasa filter di bilah pencarian Discover | Filter tampilan di konsol NMS |
| Query DSL | Query OpenSearch berbentuk JSON, termasuk aggregation | Query langsung ke database NMS |
| Aggregation | Perhitungan atas banyak dokumen: bucket (`terms`, `rare_terms`, `multi_terms`) atau metric (`min`, `cardinality`) | Laporan "top talker" dan "first seen" per interface |
| `keyword` vs `text` | Tipe field: `keyword` disimpan utuh dan bisa diagregasi; `text` dipecah per kata | Kolom ID perangkat vs kolom deskripsi bebas |
| Shard | Potongan fisik sebuah index; aggregation dihitung per shard lalu digabung | Satu POP menghitung statistiknya sendiri sebelum dikirim ke pusat |
| ISM | Index State Management OpenSearch: kebijakan otomatis, misalnya menghapus index setelah 30 hari | Kebijakan rotasi log di syslog server |
| Rule kustom | Rule buatan sendiri di `local_rules.xml`, ID 100000 sampai 120000 | Aturan alarm baru di NMS untuk pola yang ditemukan saat patroli |
| `wazuh-logtest` | Alat di manager untuk menguji decoder dan rule terhadap contoh log | Uji regex alarm di lab sebelum dipasang di NMS |
| Audit key | Label (`-k`) pada rule auditd yang ikut tercatat di setiap event | Tag pada aturan logging router |

### 1.1 Alerts vs archives: dua index, dua pertanyaan

Pertanyaan pertama Agung lahir dari keadaan sebelum 16 Februari: Discover di `jkt-wazuh01` hanya punya `wazuh-alerts-*`, dan tim Lutfi melihatnya sebagai "log server". Padahal isinya hanya event yang sudah dianggap penting oleh rule.

Tabel berikut adalah perbedaan yang menentukan apakah sebuah hunt bisa dikerjakan. Baca kolom "Untuk hunting".

| Index | Isi | Untuk hunting |
|---|---|---|
| `wazuh-alerts-*` | Hanya event yang memicu rule (di atas `log_alert_level`) | Terbatas: hanya yang sudah terdeteksi |
| `wazuh-archives-*` | Semua event yang diterima server, beralert atau tidak [S1] | Inti hunting: aktivitas yang belum punya rule |

Hunting di `wazuh-alerts-*` saja adalah jebakan bila pertanyaannya tentang perilaku yang belum punya rule: kamu hanya melihat yang sudah dideteksi, padahal hunting mencari yang lolos deteksi (Day 01). Archives berisi event mentah yang belum beralert, yang bisa kamu periksa untuk menemukan aktivitas baru, lalu menulis decoder dan rule untuknya [S1]. Dokumentasi Wazuh tentang hunting menyebut archives berguna untuk melacak penyebab event, komunikasi, waktu, dan rantai proses induk dan anak [S22].

Archives mahal secara storage dan nonaktif secara default [S1]. Dokumentasi menyebut alasannya: tanpa archives, manager tidak menyimpan log mentah tanpa batas di disk [S1]. Untuk lab, aktifkan selama periode hunting; untuk produksi, keputusan biaya dan retensi dibahas di bagian 1.3.

Untuk PT JAB, jawaban pertanyaan pertama Agung bukan "tanpa archives tidak ada yang bisa di-hunt". Jawabannya bergantung pada level rule, yang dibahas di subbagian berikut.

### 1.2 Level rule menentukan event mana yang ikut tersimpan

Agung bertanya apa yang bisa di-hunt dengan alerts saja. Cara menjawabnya: lihat rule yang dicocokkan event yang kamu butuhkan, lalu lihat levelnya.

Setiap event yang masuk ke manager melewati decoder, lalu pohon rule. Rule punya level 0 sampai 16 [S24]. Event disimpan ke `alerts.json` hanya bila rule terakhir yang cocok berlevel minimal `log_alert_level`, yang default-nya 3 [S17]. Rule level 0 dan rule dengan `noalert` dipakai sebagai rule pengelompok: event cocok, tetapi tidak menjadi alert [S24]. Dua contoh dari ruleset bawaan Wazuh 4.14 menunjukkan bedanya:

- **Login SSH berhasil.** Semua pesan sshd masuk ke rule pengelompok 5700 (level 0, `noalert`). Pesan "Accepted ..." cocok dengan rule 5715 "sshd: authentication success." yang berlevel 3 dan dipetakan ke T1078 dan T1021 [S14]. Karena level 3 sama dengan `log_alert_level` default, setiap login SSH berhasil sudah ada di `wazuh-alerts-*` sejak agent dipasang. Hunt first-seen login SSH bisa dikerjakan tanpa archives, dengan riwayat sejak Desember 2026.
- **Eksekusi proses dari auditd.** Semua event auditd cocok dengan rule dasar 80700 "Audit: Messages grouped." yang berlevel 0 [S12]. Rule 80792 "Audit: Command" (level 3) hanya cocok bila audit key event itu terdaftar sebagai `command` di CDB list `etc/lists/audit-keys` [S12]. Isi bawaan daftar itu adalah key `audit-wazuh-w`, `-r`, `-a`, `-x`, dan `-c` [S10]. Rule auditd PT JAB di enam server Linux memakai key `jab_exec` (standar hardening Linux internal, yang juga dipakai untuk mengirim `linux_audit` ke Splunk), sehingga event `execve` di Wazuh berhenti di rule 80700 level 0 dan tidak pernah menjadi alert. Sebelum 16 Februari, eksekusi proses di `jkt-bastion01` dan `jkt-billing02` diterima manager lalu dibuang.

Kalimat untuk Agung: tanpa archives, Wazuh bisa di-hunt untuk semua hal yang sudah punya rule berlevel minimal 3 (login, sudo, FIM, SCA, alert web, dan sejenisnya), dengan riwayat panjang. Archives membuka hal yang hanya cocok dengan rule level 0 atau tidak cocok dengan rule apa pun, dan untuk server Linux PT JAB yang paling bernilai adalah eksekusi proses dari auditd.

Perhatian: jalan pintas "tambahkan `jab_exec:command` ke CDB list `audit-keys` supaya execve menjadi alert" memang membuat event terlihat tanpa archives, tetapi setiap eksekusi menjadi alert level 3 [S10][S12]. Di dua server ber-auditd PT JAB itu berarti sekitar 200 ribu alert per hari (angka dari bagian 2.2). Alert dibuat untuk perilaku yang perlu dilihat orang, bukan untuk menyimpan semua event.

### 1.3 Mengaktifkan archives dan menghitung biayanya

Pertanyaan kedua Agung adalah pertanyaan pemilik disk. Jawabannya butuh tiga hal: bagaimana archives diaktifkan (supaya tahu apa yang tersimpan di mana), berapa yang terpakai, dan bagaimana menghapus otomatis.

Mengaktifkan archives terdiri dari dua langkah [S1]:

1. Di `/var/ossec/etc/ossec.conf` blok `<global>`, set `<logall_json>yes</logall_json>` (format JSON, yang bisa diindeks). `<logall>` menghasilkan format syslog `archives.log`; untuk hunting di indexer, `logall_json` yang dibutuhkan [S1]. Restart manager. Dokumentasi menyalakan keduanya; PT JAB hanya menyalakan `logall_json` supaya disk manager tidak menyimpan salinan kedua dalam format teks.
2. Di `/etc/filebeat/filebeat.yml`, set `archives: enabled` menjadi `true`, restart Filebeat. Lalu buat index pattern `wazuh-archives-*` dengan time field `timestamp` di dashboard lewat `Dashboard Management > Index patterns > Create index pattern` [S1].

Setelah itu, archives bisa dicari di Discover (`Explore > Discover`, pilih `wazuh-archives-*`) [S1] dan lewat Query DSL ke index `wazuh-archives-*`.

Biaya archives muncul di dua tempat, dan keduanya perlu kebijakan sendiri:

| Tempat | Isi | Cara dihapus |
|---|---|---|
| Disk manager | `/var/ossec/logs/archives/archives.json`, dirotasi harian menjadi file terkompresi per tahun dan bulan (misalnya `/var/ossec/logs/archives/2027/Feb/`) dengan checksum [S1] | Manager menyimpan tanpa batas; file terkompresi bisa dihapus setelah periode tertentu atau dipindah ke penyimpanan lain [S1] |
| Indexer | Index harian `wazuh-archives-*` | Kebijakan ISM, misalnya hapus setelah 30 hari [S18] |

Kebijakan retensi indexer di Wazuh memakai ISM dari OpenSearch: sebuah policy dengan state awal yang berpindah ke state hapus setelah `min_index_age` tertentu, ditempelkan ke index baru lewat `ism_template` dengan pola index [S18]. Halaman dokumentasi Wazuh mencontohkannya untuk `wazuh-alerts-*` dengan 90 hari; untuk archives, langkahnya sama dengan pola `wazuh-archives-*` [S18]. Policy baru hanya otomatis menempel ke index yang dibuat setelahnya; index yang sudah ada diberi policy lewat `Index Management > Indices > Actions > Apply policy` [S18].

Cara memilih angka retensi: tanya hunt apa yang butuh archives dan berapa panjang baseline-nya. First-seen atas eksekusi proses butuh baseline beberapa minggu; 7 hari terlalu pendek, karena hampir semua yang terlihat di minggu pertama tampak "baru". Biaya per hari diukur dari minggu uji coba (bagian 2.2), lalu dikalikan. Archives juga tidak terbatas pada hunting: dokumentasi Wazuh menyebut archives sebagai bahan untuk menulis decoder dan rule baru [S1], dan di PT JAB itulah tempat menguji rule kustom terhadap data nyata sebelum diaktifkan (bagian 2.8).

### 1.4 Tiga bahasa query: DQL, Query DSL, dan WQL

Pertanyaan ketiga Agung datang dari tim Lutfi yang biasa mengetik di bilah pencarian Discover. Ada tiga bahasa yang sering tertukar, dan masing-masing dipakai di tempat berbeda.

| Cara | Di mana | Untuk |
|---|---|---|
| DQL (Dashboard Query Language) | Bilah pencarian Discover | Filter cepat, eksplorasi interaktif |
| Query DSL (JSON) | `Indexer management > Dev Tools` di dashboard [S23], atau REST API indexer (port 9200, dengan kredensial indexer) | Agregasi, stacking, otomasi |
| WQL (Wazuh Query Language) | Parameter `q` di Wazuh server API dan bilah pencarian halaman manajemen | Data manajemen: agent, rule, decoder |

DQL berbentuk `field: nilai` yang digabung dengan `and`, `or`, `not` (tidak peka huruf besar/kecil; `not` diproses lebih dulu, lalu `and`, lalu `or`) [S3]. Contoh: `rule.level >= 7 and agent.name: jkt-bastion01`. Perhatikan range ditulis `rule.level >= 7`; bentuk `rule.level:>=7` adalah sintaks Lucene query string, bukan DQL, dan Lucene sendiri menulis range dengan kurung seperti `rule.level:[7 TO 16]` [S3]. Hal lain yang perlu diingat dari dokumentasi DQL [S3]:

- Wildcard hanya `*`, boleh di nilai dan di nama field. Wildcard tidak berlaku di dalam frasa bertanda kutip.
- Keberadaan field dicek dengan `field:*`.
- Daftar nilai ditulis `field: (a or b)`, setara dengan `field: a or field: b`.
- Karakter khusus di-escape dengan backslash, sehingga path Windows harus ditulis dengan `\\` ganda.
- DQL tidak mendukung regex, fuzzy, atau range eksklusif; itu fitur Lucene.

WQL tidak dipakai untuk event. Bentuknya `field=nilai` dengan `;` sebagai AND dan `,` sebagai OR, misalnya `os.platform=windows;status=active` [S7]. DQL yang dipakai di Discover untuk data event. Query DSL adalah JSON penuh yang mendukung aggregation, yang dibutuhkan untuk stacking dan first-seen.

Bedanya dengan Splunk ada di cara berpikir. SPL mengalirkan hasil lewat pipe: filter, lalu `stats`, lalu `where`, lalu `sort`. DQL hanya filter; ia tidak menghitung apa-apa. Perhitungan dikerjakan Query DSL, yang menata filter dan agregasi bersarang dalam satu dokumen JSON. OpenSearch juga punya PPL (Piped Processing Language) yang berbentuk pipe mirip SPL, tetapi butuh plugin SQL di indexer; ketersediaannya di Wazuh indexer dibahas di bagian 6.

### 1.5 Agregasi untuk teknik hunting

Pertanyaan keempat Agung: bisakah stacking dan first-seen dikerjakan di sini? Bisa. OpenSearch menyediakan aggregation yang memetakan ke teknik Day 05; tabel berikut adalah kamusnya. Baca kolom kanan sebagai padanan SPL.

| Teknik hunting (Day 05) | Aggregation OpenSearch | Padanan SPL |
|---|---|---|
| Stacking (hitung per nilai) | `terms` aggregation | `stats count BY field` |
| Least-frequency (nilai paling jarang) | `rare_terms` dengan `max_doc_count` [S19] | `stats count BY field \| where count <= N` |
| Stacking kombinasi beberapa field | `multi_terms` [S5], atau `terms` dengan sub-`terms` bersarang | `stats count BY a b` |
| Jumlah nilai unik | `cardinality` aggregation (perkiraan) [S6] | `dc(field)` |
| First-seen dan last-seen | `min` dan `max` pada `timestamp` sebagai sub-aggregation | `min(_time)`, `max(_time)` |
| Stacking per waktu | `date_histogram` plus sub-aggregation | `timechart` atau `bin _time` |
| Statistik (rata-rata, dll.) | `stats`/`extended_stats` aggregation | `stats avg() stdev()` |

Berbeda dari SPL yang mengalirkan hasil lewat pipe, OpenSearch menata agregasi secara bersarang (nested) dalam JSON. Stacking parent-child misalnya memakai `terms` pada satu field dengan sub-`terms` pada field lain.

Tiga hal teknis menentukan apakah hasil agregasi bisa dipercaya:

- **`size` dan `shard_size`.** `terms` default hanya mengembalikan 10 bucket. Setiap shard mengirim kandidat teratasnya sendiri, sebanyak `shard_size` yang default-nya `size * 1.5 + 10` [S4]. Field `doc_count_error_upper_bound` memberi batas kesalahan, tetapi hanya untuk urutan default (jumlah terbanyak) [S4].
- **Urutan naik tidak akurat.** `terms` dihitung per shard lalu digabung. Dokumentasi OpenSearch tidak menyarankan urutan `_count` naik karena nilai yang langka secara global bisa tampak umum di satu shard atau tidak terambil sama sekali dari shard lain, sehingga hasil long tail bisa salah [S4][S19]. Untuk nilai langka, pakai `rare_terms`: parameter `max_doc_count` (default 1, maksimum 100) menetapkan jumlah dokumen tertinggi yang masih dianggap langka [S19]. `rare_terms` sendiri juga perkiraan: dengan `precision` default 0,001, sebagian nilai langka bisa terlewat (false negative), dan galat sensitivitasnya jarang di atas 2,5% [S19]. Ia juga memakai pengumpulan breadth-first sehingga tidak cocok dengan sebagian sub-aggregation [S19].
- **`cardinality` adalah perkiraan.** Untuk jumlah host di lingkungan kecil hasilnya praktis tepat, tetapi untuk ratusan ribu nilai unik anggap sebagai angka kira-kira [S6].

First-seen di OpenSearch tidak punya padanan langsung `outputlookup`. Dua pendekatannya:

1. **`min` aggregation:** cari kapan tiap kombinasi pertama muncul, bandingkan dengan jendela hunt. `min` pada `timestamp` memberi waktu pertama kombinasi itu muncul di seluruh data yang tersimpan, jadi first-seen hanya bermakna sejauh retensi index yang dipakai. Untuk login SSH di alerts, retensinya sejak Desember; untuk eksekusi proses di archives, hanya sejak 16 Februari.
2. **Index baseline terpisah:** simpan kombinasi yang pernah terlihat ke index `th-baseline-*` lewat skrip terjadwal, lalu bandingkan. Lebih mirip pola lookup Splunk, tetapi butuh skrip sendiri. Alternatif di sisi manager adalah CDB list yang dicocokkan rule (Day 05 bagian 1.3).

### 1.6 Field Wazuh yang bisa diandalkan

Pertanyaan kelima Agung tentang field. Untuk server Linux PT JAB, yang relevan adalah field auditd dan sshd; untuk agent Windows (di lab-mu), field eventchannel.

Event di archives memakai struktur JSON yang sama dengan alerts: `timestamp`, `agent.id` dan `agent.name` (sumber event), `manager.name`, `rule.*` (id, level, description, groups, mitre), `decoder.name`, `full_log` (teks mentah), dan `data.*` untuk field hasil decoder. Tabel berikut adalah field yang dipakai di Day ini; kolom kanan menyebut sumber dan jebakannya.

| Sumber | Field | Catatan |
|---|---|---|
| auditd (decoder `auditd`) | `data.audit.type`, `data.audit.key`, `data.audit.exe`, `data.audit.command`, `data.audit.execve.a0` sampai `a7`, `data.audit.cwd`, `data.audit.pid`, `data.audit.ppid`, `data.audit.auid`, `data.audit.uid`, `data.audit.euid`, `data.audit.session`, `data.audit.tty` [S13] | `auid` dan `euid` berupa angka UID, bukan nama; argumen di atas `a7` tidak diekstrak; induk proses hanya `ppid`, tanpa path induk |
| sshd (decoder `sshd-success` untuk "Accepted ...") | `data.srcip`, `data.srcport`, `data.dstuser` [S15] | Decoder menulis `user`, yang di Wazuh adalah alias `dstuser` [S16]; metode autentikasi (password atau publickey) tidak diekstrak, hanya ada di `full_log` |
| Windows eventchannel | `data.win.system.*` (misalnya `eventID`, `channel`, `computer`) dan `data.win.eventdata.*` dengan huruf awal kecil (`image`, `parentImage`, `commandLine`, `targetFilename`) | Hanya di agent Windows; PT JAB tidak punya agent Windows di Wazuh |

Agar log `audit.log` sampai ke manager, agent Linux butuh blok `<localfile>` dengan `log_format` `audit` untuk `/var/log/audit/audit.log`; dokumentasi menyebut blok itu ditambahkan otomatis bila auditd sudah terpasang sebelum agent [S10]. Format `audit` menggabungkan record satu event (misalnya SYSCALL, EXECVE, CWD, PATH) menjadi satu event Wazuh, sehingga `data.audit.exe` dan `data.audit.execve.a1` ada di dokumen yang sama. Ini berbeda dengan `linux_audit` mentah di Splunk, yang menyimpan tiap record sebagai event terpisah.

Untuk stacking, field harus bertipe `keyword` agar `terms` bekerja; field bertipe `text` dipecah per kata dan tidak bisa diagregasi langsung [S4]. Template index Wazuh memetakan sebagian besar field string sebagai `keyword`, sehingga `terms` biasanya langsung jalan. Field yang tidak ada di template bisa dipetakan dinamis sebagai `text` dengan sub-field `.keyword`. Cek tipe field yang akan kamu agregasi dengan `GET wazuh-archives-*/_mapping/field/data.audit.exe` (atau `data.win.eventdata.image` di lab Windows).

Catatan penting: di archives, event yang tidak didekode penuh mungkin hanya punya `full_log` tanpa field terstruktur. Stacking atas `full_log` tidak berguna (hampir semua unik). Hunting di Wazuh paling efektif untuk sumber yang sudah punya decoder (sshd, auditd, Windows eventchannel, FIM), bukan log mentah yang belum didekode. Di PT JAB contohnya log aplikasi RADIUS di `jkt-radius01`: ikut masuk archives, tetapi tanpa decoder hanya berupa `full_log`, jadi belum bisa di-stack sampai decoder kustom ditulis.

### 1.7 Batas indexer dibanding Splunk

Pertanyaan keenam Agung: kapan hunt sebaiknya di Splunk saja? Untuk server ber-auditd PT JAB, data `execve` ada di dua tempat (Splunk `linux_audit` dan Wazuh archives), jadi pilihannya nyata. Tabel berikut membandingkan; baca baris yang sesuai bentuk hunt-mu.

| Aspek | Wazuh indexer (OpenSearch) | Splunk |
|---|---|---|
| Pivoting berantai | Agregasi bersarang JSON; kurang luwes | Pipe SPL sangat luwes |
| join antar index | Terbatas | `join`, `lookup`, subsearch |
| Proses induk di Linux | Hanya `ppid`; menghubungkan ke path induk butuh skrip atau notebook di luar indexer | `eventstats` atau `join` atas `pid` dan `ppid` dalam satu search |
| Baseline tersimpan | Manual (index terpisah atau CDB list) | `outputlookup`, summary index |
| Retensi | Bergantung konfigurasi ISM dan disk | Bergantung lisensi dan index |
| Biaya menambah data | Disk server sendiri | Volume ingest lisensi |
| Kekuatan | Dekat ke sumber Wazuh (FIM, SCA, rule), menguji rule kustom | Analitik dan korelasi lanjut, lintas sumber |

Untuk hunting eksploratif dengan banyak pivot, Splunk lebih nyaman. Untuk memburu data yang hanya ada di Wazuh, atau di lingkungan yang hanya ber-Wazuh, indexer sudah cukup untuk stacking, first-seen, dan filter. Untuk PT JAB, pembagiannya: eksekusi di server Linux yang juga mengirim `linux_audit` ke Splunk boleh dikerjakan di mana saja, dengan Splunk lebih unggul untuk rantai induk proses dan riwayat lebih panjang; sumber yang hanya dikumpulkan Wazuh (syslog umum dan log aplikasi di `jkt-portal02` dan `jkt-radius01`, FIM, SCA) hanya bisa di Wazuh; dan setiap pola yang akan dijadikan rule Wazuh diuji di archives.

### 1.8 Dari temuan ke rule kustom Wazuh

Pertanyaan terakhir Agung, dan yang paling ditunggu Lutfi: bila hunt menemukan pola yang layak diawasi, bagaimana menjadikannya rule tanpa banjir alert?

Aturan dasarnya dari dokumentasi Wazuh [S9]:

- Rule kustom ditaruh di `/var/ossec/etc/rules/local_rules.xml` untuk perubahan kecil, atau file baru di `/var/ossec/etc/rules/` untuk yang lebih besar.
- ID rule kustom memakai rentang 100000 sampai 120000 supaya tidak bentrok dengan rule bawaan.
- Jangan mengedit file di `/var/ossec/ruleset/rules`, karena tertimpa saat upgrade. Untuk mengubah rule bawaan, salin ke `/var/ossec/etc/rules/`, ubah, dan tambahkan `overwrite="yes"`; `if_sid` dan sejenisnya tidak bisa diubah lewat overwrite.
- Uji dengan `/var/ossec/bin/wazuh-logtest`: tempel contoh log, lalu lihat fase pre-decoding, decoding, dan rule yang cocok beserta ID, level, dan group-nya. Menyimpan file rule sudah cukup untuk diuji di `wazuh-logtest`; untuk menghasilkan alert sungguhan, restart manager.

Elemen rule yang dipakai di Day ini [S24]:

- `<if_sid>` menyambung rule ke rule induk yang sudah cocok (misalnya 80700 untuk semua event auditd).
- `<field name="...">` mencocokkan field hasil decoder dengan regex; atribut `type` bisa `osregex` (default), `osmatch`, atau `pcre2`, dan beberapa `<field>` digabung sebagai AND.
- Level 0 sampai 16; level 0 berarti tidak menjadi alert.
- `<mitre><id>...</id></mitre>` memetakan rule ke teknik ATT&CK.

Supaya penerima tidak kebanjiran, empat kebiasaan dipakai di PT JAB:

1. **Ukur dulu di archives.** Logika rule diterjemahkan menjadi Query DSL dan dijalankan atas archives minggu uji coba, plus `linux_audit` di Splunk untuk riwayat lebih panjang. Volume yang diharapkan ditulis di usulan.
2. **Pengecualian sebagai rule anak level 0.** Pengecualian ditulis sebagai rule level 0 dengan `if_sid` ke rule utama dan kondisi sempit (path dan akun persis), bukan dengan mengecualikan seluruh host. Pengecualian punya tanggal review.
3. **Nama dan pemilik jelas.** Deskripsi diawali `JAB - ` seperti detection kustom di Splunk; file rule di `jkt-wazuh01` dikelola tim Infrastruktur (Agung), isinya direview Sari Kusuma sebagai pemilik konten detection.
4. **Sebut cakupannya.** Rule atas event auditd hanya bekerja di server yang punya rule `execve`; tulis itu di usulan, supaya tidak ada yang mengira semua server Linux terlindungi.

Rule kustom tidak bergantung pada archives: rule dievaluasi di manager untuk setiap event yang diterima, dan alert-nya masuk `wazuh-alerts-*` walaupun archives dimatikan. Archives dibutuhkan untuk menemukan pola dan mengujinya, bukan untuk menjalankannya.

## 2. Contoh dan langkah praktis: minggu uji coba archives di `jkt-wazuh01`

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. DQL dijalankan di Discover; Query DSL di `Indexer management > Dev Tools`. Asumsi: nama index `wazuh-alerts-4.x-YYYY.MM.DD` dan `wazuh-archives-4.x-YYYY.MM.DD` (dicari dengan pola `wazuh-alerts-*` dan `wazuh-archives-*`), time field `timestamp`, dan field `data.audit.*`, `data.srcip`, `data.dstuser`, `agent.name`, `rule.id` bertipe `keyword` sesuai template Wazuh. Cek nama index dengan `GET _cat/indices/wazuh-*?v` dan tipe field dengan `_mapping` sebelum menjalankan. Semua rentang ditulis dengan offset `+07:00` (WIB) supaya tidak bergantung pada zona waktu browser.

### 2.1 Abstract `HUNT-2027-010` dan `HUNT-2027-011`

Dua abstract ini ditulis Selasa 2027-02-16 sore, beberapa jam setelah archives aktif, dan dikerjakan Selasa 2027-02-23. Satu hunt sengaja membutuhkan archives, satu lagi sengaja tidak, supaya jawaban untuk pertanyaan pertama Agung berdasar pada hasil, bukan teori.

```
ID             : HUNT-2027-010
Dibuat         : 2027-02-16 (Selasa), dikerjakan 2027-02-23, reviewer: Dimas Prasetyo
Trigger        : Sumber data baru (archives Wazuh); eksekusi proses di server Linux tanpa EDR
                 belum pernah dilihat di Wazuh karena hanya cocok dengan rule 80700 level 0
Tipe (PEAK)    : Baseline (EDA), dilanjutkan hypothesis-driven atas lokasi eksekusi
Hipotesis      : Penyerang yang masuk ke server Linux PT JAB menjalankan tool yang ditaruh di
                 folder yang bisa ditulis siapa saja (/tmp, /var/tmp, /dev/shm) atau biner yang
                 jarang dijalankan operator, tanpa memicu rule Wazuh
ATT&CK         : T1059.004 (Unix Shell), T1105 (Ingress Tool Transfer)
Data           : wazuh-archives-*, data.audit.key = jab_exec, 2027-02-16 10:15 sampai 2027-02-23 00:00 WIB
Cakupan nyata  : 2 dari 4 server ber-Wazuh yang punya rule auditd execve: jkt-bastion01, jkt-billing02
Di luar cakupan: jkt-portal02 dan jkt-radius01 (Wazuh ada, rule execve tidak ada); 33 server Linux
                 lain tanpa agent Wazuh (4 di antaranya ber-auditd execve, terlihat di Splunk saja)
Kriteria sukses: semua biner dengan maksimal 5 eksekusi dan semua eksekusi dari folder temp
                 berlabel jinak / perlu investigasi / data tidak cukup
Pembanding     : jumlah event SYSCALL key jab_exec di Splunk linux_audit, rentang yang sama
Handover       : IR (Dimas) bila ditemukan; usulan rule Wazuh ke Agung dan Sari; celah ke Lutfi
```

```
ID             : HUNT-2027-011
Dibuat         : 2027-02-16 (Selasa), dikerjakan 2027-02-23, reviewer: Dimas Prasetyo
Trigger        : jkt-bastion01 adalah pintu SSH ke server lain; pola INC-2026-017 (akses awal ke
                 server tanpa EDR) membuat pertanyaan "siapa masuk dari mana" layak diulang rutin
Tipe (PEAK)    : Hypothesis-driven
Hipotesis      : Akun sah yang dicuri, atau kunci SSH yang ditanam, dipakai untuk login ke
                 jkt-bastion01 dari sumber atau sebagai user yang belum pernah terlihat
ATT&CK         : T1078 (Valid Accounts), T1021.004 (Remote Services: SSH); terkait T1098.004
Data           : wazuh-alerts-*, rule.id 5715 (level 3, tidak butuh archives)
                 Baseline 2026-12-14 00:00 (agent terdaftar) sampai 2027-02-16 00:00 WIB
                 Jendela hunt 2027-02-16 00:00 sampai 2027-02-23 00:00 WIB
Di luar cakupan: login gagal, login ke server lain, sesi yang tidak lewat sshd
Kriteria sukses: setiap pasangan (user, IP sumber) yang pertama kali muncul di jendela hunt
                 dikonfirmasi pemiliknya; konteks sesi dicek di archives (execve auid yang sama)
Handover       : IR (Dimas) bila ditemukan; usulan laporan first-seen ke Sari
```

Cara membaca elemennya:

- **Cakupan nyata `HUNT-2027-010`** dihitung dari fakta yang sudah ada: rule `execve` hanya di 6 dari 37 server Linux, dan dua dari enam itu kebetulan juga ber-Wazuh. Baris ini yang mencegah laporan "tidak ditemukan" dibaca sebagai "server Linux bersih".
- **Pembanding** ditulis karena ini minggu pertama archives. Sebelum mempercayai archives untuk sumber yang hanya ada di Wazuh, cocokkan dulu dengan sumber yang sama di Splunk.
- **`HUNT-2027-011` memakai alerts**, karena rule 5715 berlevel 3 (bagian 1.2). Archives hanya dipakai untuk konteks.

**Kapan gagal:** abstract `HUNT-2027-010` tidak menyebut server tanpa rule `execve`. Di Discover, `jkt-portal02` dan `jkt-radius01` tetap muncul di `wazuh-archives-*` (dari syslog dan sshd), sehingga mudah mengira keempat server tercakup.

### 2.2 Mengukur archives setelah satu minggu

Pengukuran ini menjawab bagian "berapa biaya disknya" dari pertanyaan kedua Agung, dan sekaligus memastikan archives lengkap sebelum dipakai untuk hunt.

**Tujuan:** menghitung ukuran index archives per hari, volume per agent, dan membandingkan jumlah eksekusi dengan Splunk.

**Langkah 1: ukuran index.**

```
GET _cat/indices/wazuh-archives-*?v&h=index,docs.count,pri.store.size&s=index
```

| Bagian | Fungsi |
|---|---|
| `_cat/indices/wazuh-archives-*` | Daftar index yang cocok dengan pola, dalam format tabel |
| `v` | Tampilkan judul kolom |
| `h=index,docs.count,pri.store.size` | Hanya kolom nama, jumlah dokumen, dan ukuran shard primer |
| `s=index` | Urutkan per nama (per tanggal) |

Keluaran ilustrasi:

```
index                            docs.count pri.store.size
wazuh-archives-4.x-2027.02.16        152311          238mb
wazuh-archives-4.x-2027.02.17        281904          440mb
wazuh-archives-4.x-2027.02.18        296530          463mb
wazuh-archives-4.x-2027.02.19        276118          431mb
wazuh-archives-4.x-2027.02.20        259402          405mb
wazuh-archives-4.x-2027.02.21        256977          402mb
wazuh-archives-4.x-2027.02.22        319362          499mb
```

**Cara membaca hasil:** total 1.842.604 dokumen dan 2.878 MB (sekitar 2,8 GB). Index 16 Februari hanya berisi sejak 10:12, jadi rata-rata dihitung dari enam hari penuh: sekitar 281.700 dokumen dan 440 MB per hari. Retensi 30 hari berarti sekitar 13 GB di indexer, 90 hari sekitar 40 GB. `jkt-wazuh01` berjalan sebagai satu node dengan replica 0; bila nanti menjadi cluster dengan satu replica, angka ini dua kali lipat. Di disk manager, `archives.json` yang dirotasi dan dikompresi menambah sekitar 55 MB per hari (dicek dengan `du -sh /var/ossec/logs/archives/2027/Feb/`). Sebagai pembanding, `wazuh-alerts-*` dalam tujuh hari yang sama hanya 21.380 dokumen dan 38 MB.

**Langkah 2: volume per agent dan per jenis event.**

```
GET wazuh-archives-*/_search
{
  "size": 0,
  "query": { "range": { "timestamp": { "gte": "2027-02-16T10:12:00+07:00", "lt": "2027-02-23T00:00:00+07:00" } } },
  "aggs": {
    "per_agent": {
      "terms": { "field": "agent.name", "size": 10 },
      "aggs": {
        "decoders": { "terms": { "field": "decoder.name", "size": 5 } },
        "execve":   { "filter": { "term": { "data.audit.key": "jab_exec" } } }
      }
    }
  }
}
```

| Bagian | Fungsi |
|---|---|
| `"size": 0` | Tidak mengembalikan dokumen, hanya agregasi |
| `range` pada `timestamp` | Rentang absolut minggu uji coba, dengan offset WIB |
| `terms` pada `agent.name` | Satu bucket per server |
| sub-`terms` pada `decoder.name` | Decoder terbanyak per server: apa yang mengisi archives |
| sub-`filter` `data.audit.key: jab_exec` | Berapa dokumen yang merupakan eksekusi auditd |

Keluaran ilustrasi (diringkas):

```
agent.name       doc_count   execve      decoder teratas
jkt-billing02    1.536.220   1.288.412   auditd, pam, cron
jkt-bastion01      214.903      61.940   auditd, sshd, pam
jkt-portal02        58.311           0   (tanpa decoder), sshd, pam
jkt-radius01        33.170           0   (tanpa decoder), sshd, pam
total            1.842.604   1.350.352
```

**Cara membaca hasil:** 73% dokumen archives adalah eksekusi proses dari dua server ber-auditd, dan sebagian besar dari `jkt-billing02`, yang menjalankan job cron billing setiap menit. Itulah sumber biaya terbesar, dan sekaligus satu-satunya sumber eksekusi proses di Wazuh. `jkt-portal02` dan `jkt-radius01` tidak punya satu pun event `jab_exec`, sesuai dengan fakta bahwa rule `execve` tidak terpasang di sana. Di kedua server itu, bucket terbesar adalah event tanpa decoder (log aplikasi yang hanya ada di `full_log`).

**Langkah 3: pembanding Splunk.** Jumlah event yang sama dihitung di Splunk, yang menerima `audit.log` dari dua server itu lewat jalur lain:

```
index=linux sourcetype=linux_audit type=SYSCALL key="jab_exec"
    host IN ("jkt-bastion01", "jkt-billing02")
    earliest="02/16/2027:10:15:00" latest="02/23/2027:00:00:00"
| stats count BY host
```

Hasil ilustrasi: 1.350.389 di Splunk dibanding 1.350.352 di Wazuh (dengan rentang Wazuh yang disamakan mulai 10:15), selisih 37 event atau kurang dari 0,01%. Selisih sekecil itu wajar, karena `timestamp` Wazuh adalah waktu event diterima manager sedangkan `_time` Splunk diambil dari record audit, sehingga event di dekat batas rentang bisa jatuh di sisi berbeda. Filter `type=SYSCALL` penting: tanpa itu Splunk menghitung setiap record (SYSCALL, EXECVE, CWD, PATH) sebagai event terpisah, sedangkan Wazuh menggabungkannya menjadi satu dokumen (bagian 1.6).

**Variasi:** `GET _cat/shards/wazuh-archives-*?v` untuk melihat berapa shard per index harian; angka ini menentukan seberapa besar risiko akurasi `terms` dengan urutan naik (bagian 1.5).

**Kapan gagal:** ukuran dibaca dari `store.size` di cluster dengan replica (angkanya sudah termasuk salinan); atau minggu uji coba bertepatan dengan kejadian tidak biasa (patch massal, rilis besar) sehingga rata-rata harian terlalu tinggi atau terlalu rendah. Minggu ini memuat satu rilis billing (Kamis malam), yang terlihat sebagai kenaikan kecil di index 18 Februari.

### 2.3 Kebijakan retensi archives dengan ISM

Kebijakan ini adalah usulan konkret untuk pertanyaan "retensinya berapa lama". Angka 30 hari diambil dari kebutuhan baseline first-seen eksekusi proses (beberapa minggu) dan biaya sekitar 13 GB (bagian 2.2).

**Tujuan:** menghapus index archives otomatis setelah 30 hari.

Policy ditulis di `Indexer management > Index Management > State management policies > Create policy`, lalu pilih JSON editor [S18]:

```
{
  "policy": {
    "description": "JAB - hapus wazuh-archives setelah 30 hari",
    "default_state": "retention_state",
    "states": [
      {
        "name": "retention_state",
        "actions": [],
        "transitions": [
          { "state_name": "delete_archives", "conditions": { "min_index_age": "30d" } }
        ]
      },
      {
        "name": "delete_archives",
        "actions": [ { "delete": {} } ],
        "transitions": []
      }
    ],
    "ism_template": [
      { "index_patterns": ["wazuh-archives-*"], "priority": 1 }
    ]
  }
}
```

| Bagian | Fungsi |
|---|---|
| `default_state` | State awal setiap index yang terkena policy |
| `retention_state` | Tidak melakukan apa-apa; hanya menunggu transisi |
| `min_index_age: 30d` | Pindah ke state hapus setelah umur index 30 hari (dihitung dari pembuatan index) |
| `delete_archives` | Menghapus index |
| `ism_template` dengan `wazuh-archives-*` | Policy otomatis menempel ke index archives baru [S18] |

Policy ID diisi `jab-archives-retention`. Tujuh index yang sudah ada diberi policy lewat `Index Management > Indices`, pilih index, `Actions > Apply policy` [S18].

**Cara membaca hasil:** setelah policy aktif, kolom policy di daftar index menampilkan `jab-archives-retention` untuk setiap `wazuh-archives-*`. Karena `min_index_age` dihitung dari pembuatan index harian, data tersimpan sekitar 30 sampai 31 hari.

**Variasi:** tambahkan state `warm` sebelum hapus bila nanti ada node dengan disk lebih murah. Di sisi manager, file archives terkompresi di `/var/ossec/logs/archives/` dihapus setelah 7 hari dengan job terjadwal milik tim Infrastruktur, karena salinan yang bisa dicari sudah ada di indexer selama 30 hari. Pemeriksaan sampingan: `wazuh-alerts-*` di `jkt-wazuh01` belum punya policy ISM sama sekali sejak Desember; itu masuk usulan untuk Agung, dengan angka yang ia putuskan sendiri.

**Kapan gagal:** `ism_template` berprioritas lebih rendah dari policy lain yang polanya juga cocok (misalnya policy umum `wazuh-*`), sehingga policy ini tidak pernah menempel; atau policy hanya ditempel ke index lama dan index baru tetap tanpa policy.

### 2.4 DQL: eksplorasi cepat di Discover

Sebelum menulis agregasi, kamu melihat bentuk event dulu di Discover. Langkah ini menjawab pertanyaan ketiga Agung dengan contoh yang bisa langsung dipakai tim Lutfi.

**Tujuan:** melihat event `execve` dari folder temp dan login SSH ke bastion, lalu membandingkan jumlah hasil di archives dan alerts.

```
data.audit.key: jab_exec and data.audit.exe: /tmp/*
```

```
data.audit.key: jab_exec and (data.audit.exe: /tmp/* or data.audit.exe: /var/tmp/* or data.audit.exe: /dev/shm/*)
```

```
rule.id: 5715 and agent.name: jkt-bastion01 and not data.srcip: 10.20.5.21
```

| Query | Fungsi |
|---|---|
| Baris pertama | Eksekusi biner yang path-nya diawali `/tmp/`; wildcard `*` di akhir nilai |
| Baris kedua | Tiga folder yang bisa ditulis siapa saja, digabung dengan `or` di dalam kurung |
| Baris ketiga | Login SSH berhasil ke bastion, selain dari runner CI yang sudah dikenal |

Keluaran ilustrasi (rentang di time picker: 16 Februari 10:15 sampai 23 Februari 00:00):

```
query baris kedua, index wazuh-archives-* : 5 hits   (semua jkt-billing02, 18 Feb 22:10-22:14)
query baris kedua, index wazuh-alerts-*   : 0 hits
query baris ketiga, index wazuh-alerts-*  : 675 hits
```

**Cara membaca hasil:** query yang sama mengembalikan 5 hasil di archives dan 0 di alerts. Itu bukti langsung dari bagian 1.2: eksekusi auditd dengan key `jab_exec` tidak pernah menjadi alert. Query login SSH justru dijalankan di alerts, karena rule 5715 sudah menyimpannya. DQL cocok untuk mempersempit sebelum melihat event mentah, tetapi ia tidak menjawab "berapa biner berbeda" atau "mana yang paling jarang"; untuk itu dibutuhkan Query DSL.

**Variasi:**

- `data.srcip: 203.0.113.*` memakai wildcard; bila field bertipe `ip`, DQL mungkin menolak wildcard, jadi ganti dengan notasi CIDR (`data.srcip: "203.0.113.0/24"`). Cek tipe field di lingkunganmu.
- Untuk agent Windows: `data.win.system.eventID: 1 and data.win.eventdata.image: *mshta.exe`. Backslash adalah karakter escape di DQL, sehingga path Windows harus ditulis dengan `\\` ganda (misalnya `*\\Users\\Public\\*`). Untuk eksplorasi, wildcard di akhir nama file seperti `*mshta.exe` lebih aman daripada menulis path lengkap.

**Kapan gagal:** script dijalankan lewat interpreter (`bash /tmp/x.sh`): `data.audit.exe` berisi `/usr/bin/bash` dan path script ada di `data.audit.execve.a1`, sehingga filter atas `exe` saja tidak melihatnya (ditangani di bagian 2.6); atau time picker Discover memakai zona waktu browser yang berbeda dari WIB sehingga batas hari bergeser.

### 2.5 `HUNT-2027-010`: stacking dan least-frequency eksekusi proses

Query ini adalah langkah Execute pertama `HUNT-2027-010`, dan jawaban praktis untuk pertanyaan keempat Agung: stacking di indexer memakai aggregation, bukan pipe.

**Tujuan:** menghitung berapa biner berbeda yang dijalankan di dua server ber-auditd, lalu mengambil biner yang paling jarang beserta host, akun, dan waktu pertamanya.

```
GET wazuh-archives-*/_search
{
  "size": 0,
  "query": { "bool": { "filter": [
    { "term":  { "data.audit.key": "jab_exec" } },
    { "terms": { "agent.name": ["jkt-bastion01", "jkt-billing02"] } },
    { "range": { "timestamp": { "gte": "2027-02-16T10:15:00+07:00", "lt": "2027-02-23T00:00:00+07:00" } } }
  ] } },
  "aggs": {
    "exe_unik": { "cardinality": { "field": "data.audit.exe" } },
    "exe_langka": {
      "rare_terms": { "field": "data.audit.exe", "max_doc_count": 5 },
      "aggs": {
        "host":  { "terms": { "field": "agent.name", "size": 2 } },
        "auid":  { "terms": { "field": "data.audit.auid", "size": 5 } },
        "first": { "min": { "field": "timestamp" } }
      }
    }
  }
}
```

| Bagian | Fungsi |
|---|---|
| `bool.filter` | Filter tanpa skor relevansi: key auditd, dua server, rentang absolut |
| `cardinality` pada `data.audit.exe` | Jumlah biner berbeda (perkiraan) [S6] |
| `rare_terms` dengan `max_doc_count: 5` | Biner yang dijalankan maksimal lima kali di seluruh shard [S19] |
| sub-`terms` `agent.name` dan `data.audit.auid` | Di server mana dan oleh login UID siapa |
| sub-`min` pada `timestamp` | Kapan pertama terlihat di jendela ini |

Keluaran ilustrasi (diringkas):

```
exe_unik: 431
exe_langka: 58 bucket
  key                                         doc_count  host           auid   first
  /tmp/jab-release-4.7.2/bin/rollback-check    1          jkt-billing02  1501   2027-02-18T22:13:52+07:00
  /tmp/jab-release-4.7.2/bin/migrate           2          jkt-billing02  1501   2027-02-18T22:10:37+07:00
  /tmp/jab-release-4.7.2/bin/verify-schema     2          jkt-billing02  1501   2027-02-18T22:12:05+07:00
  /usr/sbin/tcpdump                            3          jkt-bastion01  1007   2027-02-19T09:41:16+07:00
  /usr/bin/lsof                                4          jkt-bastion01  1012   2027-02-17T15:02:44+07:00
  ...
```

**Cara membaca hasil:** 431 biner berbeda dalam seminggu, 58 di antaranya dijalankan maksimal lima kali. Semua 58 ditinjau dengan melihat dokumen lengkapnya (argumen `a0` sampai `a7`, `cwd`, `auid`, `tty`) dan memetakan `auid` ke akun lewat `/etc/passwd` server bersama tim Lutfi:

| Kelompok | Jumlah | Contoh | Label |
|---|---|---|---|
| Tool admin yang jarang dipakai, dijalankan akun admin dari sesi interaktif | 32 | `tcpdump`, `lsof`, `ss`, `strace` di `jkt-bastion01` | Jinak |
| Paket dan patch | 14 | skrip `unattended-upgrades` dan `dpkg` hari Minggu | Jinak |
| Skrip pemeliharaan terjadwal mingguan | 9 | `logrotate`, skrip arsip billing | Jinak |
| Biner dari `/tmp` | 3 | `/tmp/jab-release-4.7.2/bin/*` di `jkt-billing02` | Ditinjau lebih lanjut di bagian 2.6 |

**Variasi:**

- Stacking per kombinasi biner dan akun dengan `multi_terms` atas `data.audit.exe` dan `data.audit.auid`, untuk melihat biner umum yang dijalankan akun yang tidak biasa.
- Bila `rare_terms` dengan sub-aggregation menolak dijalankan (bagian 1.5), pecah menjadi dua langkah: `rare_terms` saja untuk daftar biner, lalu query `terms` biasa yang difilter ke biner-biner itu untuk host, akun, dan waktu.
- Untuk lab dengan satu shard, `terms` dengan `"order": { "_count": "asc" }` adalah padanan `sort count` di SPL, tetapi jangan dibawa ke index berbanyak shard.

**Kapan gagal:** path berversi (seperti `jab-release-4.7.2`) memecah satu program menjadi biner "langka" baru di setiap rilis; `auid` bernilai `4294967295` (tidak ada login UID, misalnya proses dari layanan) sehingga akun tidak bisa ditelusuri; atau penyerang memakai biner sistem yang umum (`curl`, `bash`), yang tidak pernah langka. Pola terakhir butuh stacking atas argumen, bukan atas `exe`.

### 2.6 `HUNT-2027-010`: eksekusi dari folder yang bisa ditulis siapa saja

Langkah ini adalah define/refine `HUNT-2027-010`. Hipotesisnya dipersempit dari "biner langka" ke "dijalankan dari folder temp", termasuk lewat interpreter yang lolos dari filter `exe` di bagian 2.4.

**Tujuan:** menemukan semua eksekusi biner atau script dari `/tmp`, `/var/tmp`, dan `/dev/shm`.

```
GET wazuh-archives-*/_search
{
  "size": 50,
  "_source": ["timestamp", "agent.name", "data.audit.exe", "data.audit.execve.a0",
              "data.audit.execve.a1", "data.audit.auid", "data.audit.euid", "data.audit.cwd"],
  "sort": [ { "timestamp": "asc" } ],
  "query": { "bool": {
    "filter": [
      { "term":  { "data.audit.key": "jab_exec" } },
      { "range": { "timestamp": { "gte": "2027-02-16T10:15:00+07:00", "lt": "2027-02-23T00:00:00+07:00" } } }
    ],
    "should": [
      { "prefix": { "data.audit.exe": "/tmp/" } },
      { "prefix": { "data.audit.exe": "/var/tmp/" } },
      { "prefix": { "data.audit.exe": "/dev/shm/" } },
      { "prefix": { "data.audit.execve.a1": "/tmp/" } },
      { "prefix": { "data.audit.execve.a1": "/var/tmp/" } },
      { "prefix": { "data.audit.execve.a1": "/dev/shm/" } }
    ],
    "minimum_should_match": 1
  } }
}
```

| Bagian | Fungsi |
|---|---|
| `_source` | Hanya field yang perlu dibaca, supaya hasil ringkas |
| `sort` `timestamp` naik | Urutan kejadian |
| `should` dengan enam `prefix` dan `minimum_should_match: 1` | Cocok bila biner atau argumen pertama berada di salah satu folder temp |
| `prefix` pada `data.audit.execve.a1` | Menangkap `bash /tmp/x.sh`, `python3 /tmp/x.py`, dan sejenisnya |

Keluaran ilustrasi:

```
timestamp                  agent          exe                                       a1                                    auid euid
2027-02-18T22:10:02+07:00  jkt-billing02  /usr/bin/bash                             /tmp/jab-release-4.7.2/install.sh     1501 1501
2027-02-18T22:10:37+07:00  jkt-billing02  /tmp/jab-release-4.7.2/bin/migrate        --check                               1501 1501
2027-02-18T22:11:49+07:00  jkt-billing02  /tmp/jab-release-4.7.2/bin/migrate        --apply                               1501 1501
2027-02-18T22:12:05+07:00  jkt-billing02  /tmp/jab-release-4.7.2/bin/verify-schema  billing                               1501 1501
2027-02-18T22:12:58+07:00  jkt-billing02  /tmp/jab-release-4.7.2/bin/verify-schema  billing_archive                       1501 1501
2027-02-18T22:13:52+07:00  jkt-billing02  /tmp/jab-release-4.7.2/bin/rollback-check (kosong)                              1501 1501
```

**Cara membaca hasil:** enam eksekusi, semua di `jkt-billing02` dalam empat menit Kamis malam, semua oleh UID 1501 (`svc-deploy`, akun deploy), dan semua dari satu folder rilis. Lima cocok lewat `exe`, satu lagi (`install.sh`) hanya tertangkap lewat `a1`. Tidak ada eksekusi dari folder temp di `jkt-bastion01`.

Konfirmasi ke Lutfi Selasa siang: rilis aplikasi billing 4.7.2 dijadwalkan Kamis 2027-02-18 pukul 22:00 sampai 23:00 lewat tiket change rilis billing, dijalankan pipeline CI yang login sebagai `svc-deploy`, dan paket rilis memang diekstrak ke `/tmp` lalu dijalankan dari sana. Sesi yang sama terlihat di `jkt-bastion01` (login `svc-deploy` dari runner CI pukul 22:09). Label: jinak. Lutfi setuju pola ini sendiri yang bermasalah, karena tidak bisa dibedakan dari tool penyerang yang diunduh ke `/tmp`; mulai rilis berikutnya paket diekstrak ke `/opt/jab-release/`.

Hasil `HUNT-2027-010`: tidak ditemukan aktivitas berbahaya di dua server ber-auditd, satu jinak terkonfirmasi (rilis billing), dan satu usulan rule kustom (bagian 2.8).

**Variasi:** tambahkan `/home/` ke daftar prefix untuk melihat biner yang dijalankan dari home directory; di server PT JAB ini menambah eksekusi dari skrip pribadi admin, jadi tinjau terpisah.

**Kapan gagal:** penyerang memakai `memfd` atau menghapus file setelah dijalankan (path `exe` tetap tercatat, tetapi file tidak bisa diambil lagi); penyerang menjalankan dari folder lain yang bisa ditulis (misalnya folder upload aplikasi); atau argumen script bukan di `a1` (misalnya `bash -c` dengan perintah inline, yang muncul di `a2`).

### 2.7 `HUNT-2027-011`: first-seen login SSH ke `jkt-bastion01`

Hunt ini sengaja dikerjakan di alerts, untuk menunjukkan ke Agung bahwa sebagian hunt tidak butuh archives, dan bahwa riwayat alerts yang panjang justru keuntungan untuk baseline.

**Tujuan:** menemukan pasangan user dan IP sumber yang pertama kali login SSH berhasil ke bastion di jendela hunt, dibanding baseline sejak agent terdaftar.

```
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": { "bool": { "filter": [
    { "term":  { "rule.id": "5715" } },
    { "term":  { "agent.name": "jkt-bastion01" } },
    { "range": { "timestamp": { "gte": "2026-12-14T00:00:00+07:00", "lt": "2027-02-23T00:00:00+07:00" } } }
  ] } },
  "aggs": {
    "user_unik": { "cardinality": { "field": "data.dstuser" } },
    "src_unik":  { "cardinality": { "field": "data.srcip" } },
    "pasangan": {
      "multi_terms": {
        "terms": [ { "field": "data.dstuser" }, { "field": "data.srcip" } ],
        "size": 500,
        "order": { "first_seen": "desc" }
      },
      "aggs": {
        "first_seen": { "min": { "field": "timestamp" } },
        "last_seen":  { "max": { "field": "timestamp" } }
      }
    }
  }
}
```

| Bagian | Fungsi |
|---|---|
| `rule.id: 5715` | Login SSH berhasil (rule level 3, ada di alerts sejak agent dipasang) [S14] |
| `range` sejak 2026-12-14 | Baseline dan jendela hunt dalam satu query; `min` dihitung atas seluruhnya |
| `multi_terms` atas `data.dstuser` dan `data.srcip` | Satu bucket per pasangan, mirip `by user, src` di SPL [S5] |
| `size: 500` | Lebih besar dari jumlah pasangan yang mungkin, supaya tidak ada yang terpotong |
| `order` berdasarkan `first_seen` turun | Pasangan yang paling baru pertama kali muncul ada di atas |
| `min` dan `max` pada `timestamp` | First-seen dan last-seen tiap pasangan |

Keluaran ilustrasi (diringkas):

```
total hits (14 Des - 23 Feb): 10.518      user_unik: 14     src_unik: 20
pasangan: 27 bucket
  key                           doc_count  first_seen                  last_seen
  [svc-deploy, 10.20.5.22]      212        2027-02-17T14:03:41+07:00   2027-02-22T23:41:07+07:00
  [adm.agung, 10.10.17.40]      61         2027-01-06T08:12:30+07:00   2027-02-22T17:20:55+07:00
  [svc-deploy, 10.20.5.21]      4.877      2026-12-14T16:40:12+07:00   2027-02-22T23:58:31+07:00
  ...
```

**Cara membaca hasil:** baseline (14 Desember sampai 16 Februari) berisi 9.412 login, 14 user, 19 IP sumber, dan 26 pasangan. Jendela hunt berisi 1.106 login, 11 user, 15 IP sumber, dan 17 pasangan. Hanya satu pasangan yang `first_seen`-nya di dalam jendela hunt: `svc-deploy` dari `10.20.5.22`, 212 login sejak Rabu 2027-02-17 14:03. Tidak ada user baru; IP sumber baru hanya satu itu. Baris kedua (`adm.agung`) first-seen-nya Januari, jadi masuk baseline.

Konfirmasi: `10.20.5.22` adalah `jkt-runner02`, runner GitLab kedua yang dipasang tim Lutfi Rabu 2027-02-17 sesuai tiket change, memakai kunci deploy yang sama dengan `jkt-runner01` (`10.20.5.21`). Konteks dari archives: eksekusi dengan `auid` `svc-deploy` di bastion pada jendela hunt hanya `git`, `rsync`, dan `ssh` ke `jkt-billing02`, sama dengan pola runner pertama. Label: jinak. Hasil `HUNT-2027-011`: tidak ditemukan.

**Variasi:**

- Hanya pasangan baru, tanpa membaca daftar: tambahkan pipeline `bucket_selector` di dalam `pasangan` dengan `"buckets_path": { "fs": "first_seen" }` dan script `params.fs >= 1802710800000L` (epoch milidetik untuk 2027-02-16 00:00 WIB). Cek bahwa `bucket_selector` diterima di bawah `multi_terms` di versi indexer-mu; bila tidak, pakai `terms` bersarang.
- First-seen per user saja dan per IP saja dengan dua `terms` terpisah, untuk melihat user baru dari sumber lama atau sumber baru untuk user lama.

**Kapan gagal:** IP sumber berubah karena DHCP, sehingga setiap pergantian lease tampak "baru" (di PT JAB workstation admin memakai reservasi DHCP; bila tidak, petakan IP ke host lewat log DHCP dulu); login lewat metode yang tidak menghasilkan pesan "Accepted" yang dikenali decoder; atau baseline sudah tercemar sebelum agent dipasang, karena first-seen hanya bermakna sejauh 14 Desember.

### 2.8 Rule kustom yang lahir dari `HUNT-2027-010`

Usulan ini menjawab pertanyaan ketujuh Agung dengan rule nyata. Polanya dari bagian 2.6: eksekusi dari folder temp di server Linux ber-auditd jarang terjadi dan, setelah rilis billing pindah ke `/opt`, seharusnya tidak terjadi sama sekali.

**Tujuan:** alert untuk eksekusi biner atau script dari `/tmp`, `/var/tmp`, atau `/dev/shm` di server dengan rule auditd `jab_exec`, dengan satu pengecualian sempit untuk rilis billing sampai pipeline dipindah.

Isi yang ditambahkan ke `/var/ossec/etc/rules/local_rules.xml` di `jkt-wazuh01`:

```xml
<group name="local,jab,audit,">

  <!-- HUNT-2027-010: biner dijalankan dari folder yang bisa ditulis siapa saja -->
  <rule id="100200" level="10">
    <if_sid>80700</if_sid>
    <field name="audit.key">^jab_exec$</field>
    <field name="audit.exe" type="pcre2">^/(tmp|var/tmp|dev/shm)/</field>
    <description>JAB - Eksekusi biner dari folder temp: $(audit.exe)</description>
    <mitre>
      <id>T1105</id>
    </mitre>
    <group>jab_hunt,audit_command,</group>
  </rule>

  <!-- HUNT-2027-010: script dari folder temp dijalankan lewat interpreter -->
  <rule id="100201" level="10">
    <if_sid>80700</if_sid>
    <field name="audit.key">^jab_exec$</field>
    <field name="audit.exe" type="pcre2">/(ba|da)?sh$|/python3(\.\d+)?$|/perl$</field>
    <field name="audit.execve.a1" type="pcre2">^/(tmp|var/tmp|dev/shm)/</field>
    <description>JAB - Script dari folder temp dijalankan interpreter: $(audit.execve.a1)</description>
    <mitre>
      <id>T1059.004</id>
    </mitre>
    <group>jab_hunt,audit_command,</group>
  </rule>

  <!-- Pengecualian sementara: rilis billing dari /tmp oleh svc-deploy (UID 1501). Review 2027-03-31 -->
  <rule id="100202" level="0">
    <if_sid>100200, 100201</if_sid>
    <field name="audit.auid">^1501$</field>
    <field name="audit.cwd" type="pcre2">^/tmp/jab-release-[0-9.]+$</field>
    <description>JAB - Pengecualian rilis billing dari /tmp (sementara)</description>
  </rule>

</group>
```

| Bagian | Fungsi |
|---|---|
| `id` 100200, 100201, 100202 | Rentang rule kustom 100000 sampai 120000 [S9] |
| `<if_sid>80700</if_sid>` | Hanya event yang sudah dikenali sebagai auditd [S12] |
| `<field name="audit.key">^jab_exec$</field>` | Hanya event dari rule auditd standar PT JAB |
| `type="pcre2"` | Regex PCRE2 untuk alternasi folder [S24] |
| Level 10 | Di atas `log_alert_level`, sehingga menjadi alert dan menonjol di dashboard |
| `$(audit.exe)` di deskripsi | Nilai field ikut tampil di judul alert |
| `<mitre>` | T1105 untuk biner yang dibawa masuk, T1059.004 untuk script shell |
| 100202 level 0 dengan `if_sid` ke dua rule utama | Pengecualian: akun deploy dan `cwd` folder rilis persis; menghasilkan event tanpa alert |

Pengecualian memakai `cwd` (folder kerja), bukan `exe`, karena saat `install.sh` dijalankan lewat `bash`, `exe` berisi `/usr/bin/bash`. Pemilihan field ini perlu dicek terhadap event nyata: cocokkan nilai `data.audit.cwd` keenam event di bagian 2.6 sebelum rule dipasang, dan bila skrip rilis berpindah folder sebelum menjalankan biner, persempit pengecualian ke `audit.exe` dan `audit.execve.a1` saja.

**Uji sebelum dipasang:**

1. Ambil `full_log` salah satu event bagian 2.6 dari archives, tempel ke `/var/ossec/bin/wazuh-logtest`, dan pastikan fase rule menunjukkan 100200 lalu 100202 [S9].
2. Buat event uji di server lab dengan rule auditd yang sama (bagian 3), dan pastikan 100200 cocok tanpa 100202.
3. Ukur volume. Logika rule dijalankan sebagai Query DSL atas archives minggu uji coba: 6 event (bagian 2.6), semuanya tertangkap pengecualian, jadi 0 alert. Riwayat lebih panjang dicek di Splunk:

```
index=linux sourcetype=linux_audit type=SYSCALL key="jab_exec"
    host IN ("jkt-bastion01", "jkt-billing02")
    (exe="/tmp/*" OR exe="/var/tmp/*" OR exe="/dev/shm/*")
    earliest="01/01/2027:00:00:00" latest="02/16/2027:00:00:00"
| stats count earliest(_time) AS first latest(_time) AS last BY host exe auid
| convert ctime(first) ctime(last)
```

Hasil ilustrasi: 4 event, semuanya rilis billing 4.7.1 Kamis 2027-01-21 sekitar 22:05 oleh UID 1501. Varian interpreter (rule 100201) tidak bisa dicek dengan cara ini, karena di `linux_audit` mentah argumen ada di record EXECVE terpisah dari record SYSCALL; cukup dari archives.

**Cara membaca hasil:** volume yang diharapkan 0 alert per minggu selama pengecualian berlaku, dan dua sampai empat alert per rilis bila pipeline belum pindah sementara pengecualian sudah dicabut. Penerima alert: SOC lewat tinjauan dashboard Wazuh pagi hari; Lutfi diberi tahu bila host-nya terkena.

**Usulan yang dikirim:** ke Agung (pemasangan di `jkt-wazuh01`, restart manager di jendela change) dan Sari (review nama dan isi). Cakupan ditulis di usulan: rule hanya bekerja di `jkt-bastion01` dan `jkt-billing02`. Untuk `jkt-portal02` dan `jkt-radius01`, rule baru berguna setelah tim Lutfi memasang rule auditd `jab_exec` di sana.

**Kapan gagal:** regex `audit.exe` di 100201 tidak mencakup interpreter yang dipakai penyerang (misalnya `/usr/bin/python3.11` sudah tercakup, tetapi `php` atau `node` belum); pengecualian 100202 dibiarkan setelah 31 Maret; atau `local_rules.xml` diedit tanpa restart sehingga rule hanya bekerja di `wazuh-logtest`.

### 2.9 Laporan dua hunt dan jawaban untuk Agung

Laporan ini adalah langkah Finalize untuk kedua hunt, dan tabel di bawahnya adalah balasan yang dikirim ke utas Agung Selasa sore.

```
ID            : HUNT-2027-010                         Selesai: Selasa 2027-02-23
Hasil         : Tidak ditemukan aktivitas berbahaya
Cakupan nyata : jkt-bastion01, jkt-billing02; wazuh-archives-*, key jab_exec,
                2027-02-16 10:15 sampai 2027-02-23 00:00 WIB; 1.350.352 eksekusi, 431 biner
                Di luar cakupan: jkt-portal02 dan jkt-radius01 (tanpa rule execve);
                33 server Linux tanpa Wazuh; parent proses (hanya ppid)
Ambang        : rare_terms max_doc_count 5 (58 biner, semua ditinjau); semua eksekusi dari
                /tmp, /var/tmp, /dev/shm lewat exe atau a1 (6 event)
Jinak terkonfirmasi : rilis billing 4.7.2 dari /tmp oleh svc-deploy, 18 Feb 22:10-22:14 (Lutfi)
Pembanding    : Splunk linux_audit SYSCALL 1.350.389 vs Wazuh 1.350.352 (selisih < 0,01%)
Celah data    : rule auditd jab_exec belum ada di jkt-portal02 dan jkt-radius01 -> Lutfi
                log aplikasi RADIUS tanpa decoder (hanya full_log) -> Agung dan Lutfi
Deteksi       : rule Wazuh 100200, 100201, pengecualian 100202 (review 2027-03-31)
                -> Agung (pemasangan) dan Sari (review)
Hipotesis baru: stacking argumen curl/wget di server ber-auditd (biner umum tidak pernah langka)

ID            : HUNT-2027-011                         Selesai: Selasa 2027-02-23
Hasil         : Tidak ditemukan
Cakupan nyata : jkt-bastion01, wazuh-alerts-* rule 5715; baseline 14 Des 2026 - 16 Feb 2027
                (9.412 login, 26 pasangan), jendela 16-23 Feb 2027 (1.106 login, 17 pasangan)
                Di luar cakupan: login gagal; metode autentikasi (hanya di full_log)
Jinak terkonfirmasi : svc-deploy dari 10.20.5.22 (jkt-runner02, dipasang 17 Feb, tiket change)
Deteksi       : usulan laporan mingguan first-seen login SSH bastion (query bagian 2.7 dengan
                bucket_selector) -> Sari, bukan alert
```

| Pertanyaan Agung | Jawaban singkat | Dasar |
|---|---|---|
| Apa yang bisa di-hunt tanpa archives | Semua yang punya rule level 3 ke atas, misalnya login SSH (`HUNT-2027-011` tidak butuh archives). Eksekusi auditd dengan key `jab_exec` hanya cocok dengan rule level 0, jadi baru terlihat setelah archives aktif | Bagian 1.1, 1.2, 2.4 |
| Biaya dan retensi | Sekitar 440 MB per hari di indexer plus 55 MB di disk manager; usulan dipertahankan dengan ISM 30 hari (sekitar 13 GB) dan file manager 7 hari. Alerts juga perlu policy ISM; angkanya keputusan Infrastruktur | Bagian 1.3, 2.2, 2.3 |
| Query di Discover vs Splunk | DQL hanya filter; perhitungan dikerjakan Query DSL di Dev Tools. WQL hanya untuk data manajemen | Bagian 1.4, 2.4 |
| Stacking dan first-seen | Bisa: `rare_terms`, `multi_terms`, `min`; hindari `terms` urutan naik di index berbanyak shard | Bagian 1.5, 2.5, 2.7 |
| Field yang bisa dipercaya | `data.audit.*` (exe, a0 sampai a7, auid, cwd) dan `data.srcip`/`data.dstuser`; UID berupa angka, parent hanya `ppid`; log tanpa decoder hanya `full_log` | Bagian 1.6 |
| Kapan di Splunk | Rantai induk proses, korelasi lintas sumber, riwayat panjang `linux_audit`. Wazuh untuk sumber yang hanya ada di Wazuh dan untuk menguji rule | Bagian 1.7 |
| Rule tanpa banjir | Ukur di archives dan Splunk dulu, pengecualian sempit sebagai rule level 0 bertanggal review, ID 100200 ke atas. Rule pertama: 0 alert per minggu yang diharapkan | Bagian 1.8, 2.8 |

Agung memutuskan Rabu pagi: archives dipertahankan, policy `jab-archives-retention` dipasang hari itu, dan rule 100200 sampai 100202 dipasang di jendela change Kamis malam setelah review Sari.

**Kapan gagal:** balasan hanya berisi "archives berguna" tanpa angka biaya dan tanpa cakupan; atau rule dipasang tanpa menyebut bahwa ia buta di dua dari empat server ber-Wazuh.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** Wazuh 4.x lab (manager, indexer, dashboard; all-in-one cukup) dengan satu agent Linux yang punya auditd, satu VM Linux kedua untuk login SSH, dan opsional satu agent Windows dengan Sysmon (channel `Microsoft-Windows-Sysmon/Operational` dikumpulkan sebagai `eventchannel`); akses Dev Tools atau REST API indexer; snapshot manager dan agent. PT JAB hanya contoh fiktif; jangan memakai data kerja.

1. **Aktifkan archives.** Di manager lab, set `<logall_json>yes</logall_json>`, restart; aktifkan `archives` di Filebeat, restart; buat index pattern `wazuh-archives-*` dengan time field `timestamp` (bagian 1.3). Catat jam aktif.
2. **auditd dengan key kustom.** Di agent Linux, pasang rule `-a always,exit -F arch=b64 -S execve -k lab_exec` dan versi `arch=b32`, muat ulang dengan `auditctl -R`, cek dengan `auditctl -l`. Pastikan `ossec.conf` agent punya `<localfile>` dengan `log_format` `audit` untuk `/var/log/audit/audit.log` [S10]. Bandingkan dengan rule contoh dokumentasi Wazuh yang memakai `-F euid=0` dan key `audit-wazuh-c` [S11]: tulis satu kalimat tentang apa yang tidak terlihat bila hanya perintah root yang diaudit.
3. **Archives vs alerts.** Jalankan beberapa perintah biasa, lalu di Discover cari `data.audit.key: lab_exec` di `wazuh-archives-*` dan `wazuh-alerts-*`. Archives harus berisi hasil, alerts kosong. Lalu ganti key ke `audit-wazuh-c` di satu rule uji dan ulangi: kali ini perintah yang diaudit muncul di alerts sebagai rule 80792 (bagian 1.2). Kembalikan.
4. **Event uji folder temp.** Salin biner jinak (misalnya `/usr/bin/id`) ke `/tmp/id-uji` dan jalankan; buat `/tmp/halo.sh` berisi `echo halo` dan jalankan dengan `bash /tmp/halo.sh`. Jalankan query bagian 2.6 dengan rentang lab-mu; kedua event harus muncul, satu lewat `exe` dan satu lewat `a1`.
5. **Mapping dan shard.** Jalankan `GET wazuh-archives-*/_mapping/field/data.audit.exe` dan `GET _cat/shards/wazuh-archives-*?v`. Catat tipe field dan jumlah shard per index.
6. **Stacking.** Jalankan query bagian 2.5 (ganti key dan nama agent). Bandingkan hasil `rare_terms` dengan `terms` berurutan `_count` naik; catat apakah keduanya sama di lab-mu dan kenapa (jumlah shard).
7. **First-seen SSH.** Dari VM kedua, login SSH ke agent dengan akun baru. Jalankan query bagian 2.7 di `wazuh-alerts-*` dengan baseline sejak agent lab dipasang. Pasangan baru harus ada di bucket teratas.
8. **Rule kustom.** Tulis rule seperti bagian 2.8 dengan key `lab_exec` di `local_rules.xml` lab. Ambil `full_log` event langkah 4 dari archives, uji di `wazuh-logtest`, restart manager, ulangi langkah 4, dan pastikan alert 100200 dan 100201 muncul di `wazuh-alerts-*`. Tambahkan pengecualian level 0 untuk satu folder uji, ulangi, dan pastikan alert tidak muncul untuk folder itu tetapi tetap muncul untuk folder lain.
9. **Agent Windows (opsional).** Jalankan query berikut di Dev Tools. Stacking parent-child Sysmon EID 1:

```
GET wazuh-archives-*/_search
{
  "size": 0,
  "query": { "bool": { "filter": [
    { "term": { "data.win.system.eventID": "1" } },
    { "range": { "timestamp": { "gte": "now-14d" } } }
  ] } },
  "aggs": {
    "parents": {
      "terms": { "field": "data.win.eventdata.parentImage", "size": 50 },
      "aggs": {
        "children": { "terms": { "field": "data.win.eventdata.image", "size": 10 } },
        "hosts": { "cardinality": { "field": "agent.name" } }
      }
    }
  }
}
```

   `terms` pada `parentImage` dengan sub-`terms` pada `image` adalah stacking parent-child bersarang (Day 05), dan `cardinality` pada `agent.name` menghitung host. First-seen pasangan parent-child memakai `multi_terms` atas `data.win.eventdata.parentImage` dan `data.win.eventdata.image` dengan sub-aggregation `min` pada `timestamp`, seperti bagian 2.7. Untuk eksekusi yang tidak beralert, salin satu binary jinak (misalnya `whoami.exe` dari `System32`) ke `C:\Users\Public\` lalu jalankan dari sana; yang harus terlihat adalah Sysmon EID 1 dengan `data.win.eventdata.image` berakhiran `\Users\Public\whoami.exe` dan `parentImage` berupa shell yang kamu pakai. Cari dengan filter `wildcard` `data.win.eventdata.image` bernilai `*\\Users\\Public\\*` ditambah `must_not` `range` `rule.level` `gte` 3 (cocok untuk event tanpa level maupun level di bawah 3). Pastikan event itu ada di `wazuh-archives-*`; bila juga muncul di `wazuh-alerts-*`, catat rule mana yang memicunya. Kembalikan snapshot.
10. **Biaya dan retensi.** Setelah beberapa hari, jalankan `_cat/indices` seperti bagian 2.2 dan `du -sh /var/ossec/logs/archives/`. Pasang policy ISM seperti bagian 2.3 dengan `min_index_age` `7d` untuk lab.
11. **Laporan.** Isi template laporan hunt (Day 01 bagian 2.4) untuk hunt folder temp dan hunt first-seen SSH di lab-mu, termasuk cakupan dan yang di luar cakupan.

**Hasil yang sebaiknya tersimpan:**

- Archives aktif dan terindeks di `wazuh-archives-*`, dengan jam aktif tercatat.
- Bukti bahwa event auditd dengan key kustom ada di archives tetapi tidak di alerts, dan bahwa key `audit-wazuh-c` mengubahnya.
- Tipe field `data.audit.exe` dan jumlah shard per index.
- Hasil `rare_terms` dibanding `terms` urutan naik, dengan penjelasan.
- Pasangan SSH baru yang tertangkap query first-seen.
- Rule kustom dengan hasil `wazuh-logtest`, bukti alert, dan bukti pengecualian bekerja.
- Ukuran archives per hari di indexer dan di disk manager, plus policy ISM.
- Dua laporan hunt lab.

**Variasi tantangan:** matikan archives setelah hunting dan ukur selisih pertumbuhan disk `/var/ossec` selama periode aktif. Tulis satu paragraf tentang trade-off menyimpan archives permanen (kemampuan hunt historis) versus biaya storage, dan usulkan kebijakan retensi archives untuk lab-mu. Lalu tulis decoder kustom untuk satu log aplikasi lab yang hari ini hanya muncul sebagai `full_log`, dan ulangi stacking atas field hasil decoder itu.

## 4. Troubleshooting

Tabel ini memuat gejala yang paling sering muncul saat berburu di Wazuh. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| `wazuh-archives-*` kosong | `logall_json` atau Filebeat archives belum aktif | Cek `ossec.conf` dan `filebeat.yml`; restart keduanya [S1] |
| Event auditd tidak ada di archives | `<localfile>` `log_format` `audit` tidak ada, atau rule auditd belum dimuat | Cek `ossec.conf` agent [S10]; `auditctl -l` di agent |
| Event auditd ada di archives, tidak di alerts | Key tidak terdaftar di `audit-keys`, event berhenti di rule 80700 level 0 | Memang begitu (bagian 1.2); buat rule kustom terarah, jangan daftarkan key ke `command` |
| Agregasi `terms` kosong atau error | Field bertipe `text` | Cek `_mapping/field/<nama>`; pakai sub-field `.keyword` bila ada |
| Long tail berbeda tiap kali dijalankan | `terms` urutan naik di index berbanyak shard | Pakai `rare_terms` (bagian 1.5); cek `_cat/shards` |
| `rare_terms` error dengan sub-aggregation | Pengumpulan breadth-first tidak cocok dengan sub-aggregation tertentu | Pecah menjadi dua query (bagian 2.5) [S19] |
| Stacking `full_log` semuanya unik | Event belum didekode | Hunt sumber yang punya decoder; tulis decoder kustom (bagian 1.6) |
| DQL path Windows tidak cocok | Escaping backslash | Pakai `\\` ganda atau wildcard di nama file; cek nilai di Discover |
| Filter `/tmp/*` tidak menangkap script | Script dijalankan interpreter, path ada di `a1` | Tambahkan `prefix` pada `data.audit.execve.a1` (bagian 2.6) |
| Batas hari bergeser di hasil | Rentang tanpa offset zona waktu | Tulis `+07:00` di setiap `range` |
| Disk `/var/ossec` cepat penuh | Archives menyimpan semua event tanpa batas | Atur penghapusan file terkompresi; pertimbangkan menonaktifkan `logall` teks [S1] |
| Index archives tidak pernah terhapus | Policy ISM tidak menempel ke index baru | Cek `ism_template` dan prioritasnya; tempel manual ke index lama [S18] |
| `must_not exists rule.level` tidak menyaring | Event archives yang cocok dengan rule level 0 tetap membawa `rule.level` | Pakai `must_not` `range` `rule.level` `gte` 3, yang cocok untuk keduanya |
| Rule kustom cocok di `wazuh-logtest`, tidak ada alert | Manager belum direstart | Restart manager di jendela change [S9] |

## 5. Kesalahan umum dan jebakan

- **Berburu hanya di `wazuh-alerts-*` untuk perilaku yang belum punya rule.** Itu hanya yang sudah terdeteksi; hunting atas event tanpa rule butuh archives [S1].
- **Menganggap semua hunt butuh archives.** Login SSH, sudo, dan FIM sudah punya rule berlevel minimal 3; alerts punya riwayat lebih panjang untuk baseline (bagian 1.2, 2.7).
- **Mendaftarkan key auditd kustom sebagai `command` di `audit-keys` supaya terlihat.** Setiap eksekusi menjadi alert level 3; di PT JAB sekitar 200 ribu alert per hari [S10][S12].
- **Stacking atas `full_log`** untuk sumber yang belum didekode; hasilnya hampir semua unik.
- **Mengagregasi field bertipe `text`** sehingga agregasi gagal atau pecah per kata; cek mapping dulu.
- **Memakai `terms` urutan `_count` naik sebagai long tail di index berbanyak shard.** Pakai `rare_terms` [S4][S19].
- **Menulis range dengan sintaks Lucene di DQL** (`rule.level:>=7`); DQL memakai `rule.level >= 7`.
- **Menulis rentang tanpa offset zona waktu** sehingga hasil Discover, Dev Tools, dan Splunk tidak bisa dicocokkan.
- **Membiarkan archives aktif permanen tanpa kebijakan retensi**, sehingga disk penuh [S1]. Kebijakan dibutuhkan di dua tempat: indexer dan disk manager.
- **Menghitung archives tanpa pembanding pada minggu pertama.** Archives yang kehilangan event (misalnya Filebeat tertinggal) terlihat sama dengan archives lengkap sampai dicocokkan dengan sumber lain.
- **Menyebut hasil hunt atas auditd berlaku untuk "server Linux".** Hanya untuk server yang punya rule `execve`; di PT JAB itu 2 dari 4 server ber-Wazuh.
- **Pengecualian rule per host.** Pengecualian `jkt-billing02` seluruhnya akan membutakan rule di server yang justru paling bernilai; pengecualian ditulis per akun dan path, dengan tanggal review.
- **Mengedit rule bawaan di `/var/ossec/ruleset/rules`.** Tertimpa saat upgrade; pakai `local_rules.xml` dan `overwrite="yes"` [S9].
- **Mengharapkan pivot ala SPL di OpenSearch.** Agregasi bersarang kurang luwes; pindah ke Splunk untuk pivot kompleks dan rantai induk proses.
- `[komunitas, belum terkonfirmasi]` Praktisi sering mengaktifkan archives hanya selama kampanye hunting tertentu lalu mematikannya karena biaya storage. Dokumentasi Wazuh menegaskan archives nonaktif default karena konsumsi storage besar [S1]; sesuaikan dengan kapasitas lab.

## 6. Catatan terkini

Bagian ini menampung detail versi dan perubahan produk yang berguna saat membaca dokumentasi, tetapi tidak mengubah langkah di atas.

- **Versi Wazuh.** Rilis terbaru di halaman catatan rilis adalah 4.14.9 (14 Oktober 2026), rilis kumulatif yang berisi perbaikan keamanan manager, agent, dan SCA, tanpa perubahan indexer yang disebut [S20]. PT JAB masih di 4.14. Per tanggal riset, halaman catatan rilis belum mencantumkan rilis 5.0 [S20].
- Archives Wazuh memakai `logall_json` dan index `wazuh-archives-*`, nonaktif default [S1]. Di dokumentasi 4.14 halaman ini berjudul "Event logging"; panduan versi lama (4.4, 4.7) memakai menu `Stack management > Index patterns`, sedangkan 4.14 memakai `Dashboard Management > Index patterns` dan `Explore > Discover` [S1].
- **Dasar OpenSearch.** Wazuh indexer adalah fork OpenSearch [S2]. Paket 4.14 memakai seri OpenSearch 2.19 (catatan port FreeBSD menyebut 2.19.3 di 4.14.1 dan 2.19.4 di 4.14.2) [S21]. Versi persis di instance-mu dicek dengan `GET /` di Dev Tools; aggregation `terms`, `rare_terms`, `multi_terms`, `cardinality`, `min`, dan `date_histogram` tersedia di seri itu [S4][S5][S6][S19].
- **Dashboard.** Modul Threat Hunting ada di menu `Dashboards > Threat intelligence`, berdampingan dengan Vulnerability Detection dan MITRE ATT&CK [S23]. Halaman yang dibaca tidak menjelaskan apakah modul itu bisa diarahkan ke `wazuh-archives-*`, jadi untuk archives pakai Discover; cek di versi-mu. Dokumentasi juga menyebut alert audit Linux tampil di modul Threat Hunting [S10].
- **PPL.** `[komunitas, belum terkonfirmasi]` Satu utas forum Wazuh 2022 mencantumkan plugin `opensearch-sql` di Wazuh indexer dan contoh query SQL lewat Dev Tools, dan satu tulisan pihak ketiga memakai PPL atas data Wazuh. Dokumentasi resmi Wazuh yang dibaca tidak menyebutnya. Cek dengan `GET _cat/plugins` di instance-mu sebelum mengandalkan PPL.
- Wazuh 5.0 yang sedang dikembangkan membawa perubahan arsitektur dan skema data; nama index dan field untuk hunting bisa berubah, jadi cek catatan rilis 5.0 saat GA sebelum memindahkan query dari Day ini.
- Day 09 memindahkan hunting ke endpoint langsung dengan Velociraptor, untuk artefak yang tidak masuk ke indexer.

## 7. Cheat sheet

```
INDEX      wazuh-alerts-* (rule level >= log_alert_level, default 3) | wazuh-archives-* (semua event, nonaktif default)
TANYA DULU event-ku cocok rule level >= 3? ya -> alerts cukup (riwayat panjang) ; tidak -> archives (riwayat sejak aktif)
AKTIFKAN   ossec.conf <global><logall_json>yes</logall_json> + filebeat.yml archives: enabled: true
           + index pattern wazuh-archives-* (time field timestamp) ; restart manager dan filebeat
BIAYA      _cat/indices/wazuh-archives-*?v&h=index,docs.count,pri.store.size ; du -sh /var/ossec/logs/archives
RETENSI    ISM policy: retention_state -> (min_index_age 30d) -> delete ; ism_template wazuh-archives-*
QUERY      DQL di Discover: field: nilai and/or/not ; rule.level >= 7 ; field:* ; field: (a or b) ; path Windows \\
           Query DSL di Indexer management > Dev Tools ; WQL hanya data manajemen (q=field=val;...)
STACKING   terms (+ sub-terms) ; cardinality = dc() ; rare_terms max_doc_count N (<= 100) untuk long tail
           JANGAN terms order _count asc di index berbanyak shard
FIRST-SEEN multi_terms [a,b] + min(timestamp), order first_seen desc ; bermakna sejauh retensi index
FIELD      auditd: data.audit.key/exe/command/execve.a0-a7/cwd/auid/euid/ppid ; sshd: data.srcip/dstuser
           Windows: data.win.system.eventID, data.win.eventdata.image/parentImage/commandLine
           keyword utk agg ; hindari full_log ; cek _mapping/field/<nama>
TAK BERALERT must_not range rule.level gte 3
WAKTU      range timestamp "gte": "2027-02-16T00:00:00+07:00" (selalu dengan offset)
RULE       /var/ossec/etc/rules/local_rules.xml ; id 100000-120000 ; if_sid ke rule induk (80700 auditd)
           field type="pcre2" ; level 0 = pengecualian ; <mitre><id>Txxxx</id></mitre>
           uji: /var/ossec/bin/wazuh-logtest ; aktifkan: restart manager ; jangan edit ruleset/rules
BATAS      pivot kurang luwes dari SPL ; parent Linux hanya ppid ; baseline manual (index terpisah/CDB list)
PILIH      data hanya di Wazuh / uji rule Wazuh -> indexer ; pivot kompleks, rantai proses -> Splunk (Day 06)
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Sebelum archives diaktifkan 16 Februari, login SSH ke `jkt-bastion01` tidak bisa di-hunt di Wazuh, karena Wazuh hanya menyimpan alert." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Login SSH berhasil cocok dengan rule 5715 yang berlevel 3, sama dengan `log_alert_level` default, jadi setiap login sudah tersimpan di `wazuh-alerts-*` sejak agent dipasang Desember 2026. Karena itu `HUNT-2027-011` dikerjakan di alerts dengan baseline sejak 14 Desember. Yang tidak tersimpan sebelum archives adalah event yang hanya cocok dengan rule level 0, seperti eksekusi auditd dengan key `jab_exec` yang berhenti di rule 80700. Lihat bagian 1.2 dan 2.7.

</details>

**2. Skenario keputusan.** Lutfi mengusulkan cara cepat supaya eksekusi proses di dua server ber-auditd terlihat di Wazuh tanpa archives. Usulan mana yang paling tepat?

- A. Tambahkan `jab_exec:command` ke CDB list `audit-keys`, sehingga setiap eksekusi cocok dengan rule 80792 dan masuk alerts.
- B. Biarkan eksekusi tersimpan di archives untuk hunting, lalu tulis rule kustom terarah (misalnya eksekusi dari folder temp) yang volumenya sudah diukur di archives.
- C. Turunkan `log_alert_level` ke 0 supaya semua event menjadi alert.

<details><summary>Jawaban</summary>

B. Archives menyimpan semua eksekusi untuk hunting, dan alert hanya dibuat untuk pola yang perlu dilihat orang, dengan volume yang sudah diukur (rule 100200 diharapkan 0 alert per minggu). A keliru karena setiap eksekusi menjadi alert level 3, sekitar 200 ribu per hari di dua server itu. C keliru karena mengubah semua event menjadi alert, yang pada dasarnya archives yang dibungkus sebagai alert, dan menenggelamkan alert yang penting. Lihat bagian 1.2 dan 2.8.

</details>

**3. Pertanyaan jebakan.** "`jkt-wazuh01` hanya satu node, jadi `terms` dengan `"order": { "_count": "asc" }` di `wazuh-archives-*` memberi long tail yang akurat." Benarkah?

<details><summary>Jawaban</summary>

Belum tentu. Akurasi `terms` bergantung pada jumlah shard, bukan jumlah node: aggregation dihitung per shard lalu digabung, dan satu node bisa menyimpan index harian yang terbagi ke beberapa shard. Nilai yang langka secara global bisa tidak terambil dari shard tertentu. Dokumentasi OpenSearch menyarankan `rare_terms` untuk nilai langka, dan jumlah shard dicek dengan `_cat/shards`. Lihat bagian 1.5 dan 2.2.

</details>

**4. Skenario keputusan.** Agung harus memutuskan nasib archives setelah minggu uji coba. Pilihan mana yang paling bisa dipertanggungjawabkan?

- A. Pertahankan archives tanpa batas waktu, karena hunting butuh riwayat sepanjang mungkin.
- B. Pertahankan archives dengan policy ISM 30 hari di indexer (sekitar 13 GB) dan penghapusan file manager setelah 7 hari, karena baseline eksekusi butuh beberapa minggu dan rule kustom diuji di sana.
- C. Matikan archives, karena eksekusi di `jkt-bastion01` dan `jkt-billing02` sudah ada di Splunk `linux_audit`.

<details><summary>Jawaban</summary>

B. Angka retensinya diturunkan dari kebutuhan hunt dan biaya yang diukur (sekitar 440 MB per hari), dan kebijakan dibuat di dua tempat biaya: indexer dan disk manager. A keliru karena manager dan indexer akan menyimpan tanpa batas sampai disk penuh. C keliru karena archives juga memuat sumber yang hanya ada di Wazuh (log di `jkt-portal02` dan `jkt-radius01`) dan menjadi tempat menguji rule kustom terhadap data nyata; Splunk hanya menggantikan sebagian. Lihat bagian 1.3, 1.7, 2.2, dan 2.3.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Lutfi Hakim, dalam tiga kalimat, kenapa rule 100200 punya pengecualian untuk rilis billing tetapi ia tetap diminta memindahkan ekstraksi rilis dari `/tmp` ke `/opt/jab-release/`.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Rule baru memberi alert setiap kali ada program dijalankan dari `/tmp`, karena itu cara paling umum penyerang menjalankan tool yang baru diunduh, dan dalam seminggu archives satu-satunya yang begitu adalah rilis billing Kamis malam. Supaya timmu tidak menerima alert setiap rilis, aku buat pengecualian sempit: hanya akun `svc-deploy` di folder rilis yang persis, dan pengecualian itu berakhir 31 Maret. Selama pengecualian ada, penyerang yang memakai akun deploy dan meniru nama folder rilis tidak akan terlihat, jadi memindahkan rilis ke `/opt/jab-release/` membuat pengecualian bisa dicabut dan rule kembali mengawasi semua eksekusi dari `/tmp`."

Kesalahan yang sering muncul:
- Mengusulkan pengecualian seluruh `jkt-billing02`, padahal itu server yang paling bernilai.
- Tidak menyebut tanggal review, sehingga pengecualian sementara menjadi permanen.
- Lupa menyebut bahwa rule hanya bekerja di server yang punya rule auditd `jab_exec`.

</details>

**6. Pertanyaan jebakan.** "`HUNT-2027-010` tidak menemukan apa-apa, jadi server Linux PT JAB yang dipantau Wazuh bersih dari tool penyerang yang dijalankan dari `/tmp`." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Hasilnya hanya berlaku untuk `jkt-bastion01` dan `jkt-billing02`, dua dari empat server ber-Wazuh yang punya rule auditd `execve`, untuk 16 sampai 23 Februari. `jkt-portal02` dan `jkt-radius01` tidak menghasilkan satu pun event `jab_exec`, sehingga eksekusi di sana tidak terlihat sama sekali, dan 33 server Linux lain tidak memakai Wazuh. Karena itu laporan menulis celah ini dan meneruskannya ke Lutfi. Lihat bagian 2.1, 2.2, dan 2.9.

</details>

**7. Interview question (English).** "Your Wazuh deployment only indexes alerts. How would you hunt for activity that never triggered a rule?"

<details><summary>Sample answer</summary>

"First I check whether I really need more data. If the event I care about already matches a rule at or above the alert level, for example successful SSH logins, the alerts index is enough and its history is longer. If it only hits a level 0 rule, like auditd execve events with a custom key, it is dropped unless archives are on, so I enable logall_json and the Filebeat archives input for the agents in scope, and I put a retention policy on both the indexer and the manager disk before I start. In the first week I reconcile archive counts against another copy of the same source, then hunt with Query DSL: rare_terms for least frequency rather than terms sorted ascending, multi_terms with a min on the timestamp for first-seen, and always absolute time ranges with a timezone offset. Whatever pattern survives review goes back to the manager as a local rule in the 100000 range, tested in wazuh-logtest and measured against the archives first, with narrow, dated exceptions. And I write down which hosts actually produce that telemetry, because a negative result only covers them."

What makes this answer strong: it starts from rule levels instead of assuming archives are always needed, treats storage and data validation as part of the hunt, names the aggregation pitfalls, and closes the loop to a measured custom rule with an explicit scope.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Wazuh documentation: Event logging (Wazuh archives) | https://documentation.wazuh.com/current/user-manual/manager/event-logging.html | primer | diakses 2026-10-10 (URL lama `wazuh-archives.html`), dicek ulang 2026-10-18 | Tinggi. logall vs logall_json, path archives dan rotasi, Filebeat `archives: enabled`, index pattern `wazuh-archives-*` dengan `timestamp`, menu 4.14, peringatan storage, penyimpanan tanpa batas |
| S2 | wazuh/wazuh-indexer (repositori GitHub) | https://github.com/wazuh/wazuh-indexer | primer | diakses 2026-10-10, dicek ulang 2026-10-18 | Tinggi. Indexer sebagai fork OpenSearch |
| S3 | OpenSearch documentation: Dashboards Query Language (DQL) | https://docs.opensearch.org/latest/dashboards/dql/ | primer | diakses 2026-10-10; versi 2.19 dicek 2026-10-18 | Tinggi. Sintaks DQL, range, wildcard, exists, daftar nilai, escaping, perbandingan dengan Lucene |
| S4 | OpenSearch documentation: Terms aggregation | https://docs.opensearch.org/latest/aggregations/bucket/terms/ | primer | diakses 2026-10-10; versi 2.19 dicek 2026-10-18 | Tinggi. size default 10, shard_size `size * 1.5 + 10`, doc_count_error_upper_bound, akurasi per shard |
| S5 | OpenSearch documentation: Multi-terms aggregation | https://docs.opensearch.org/latest/aggregations/bucket/multi-terms/ | primer | diakses 2026-10-10 | Tinggi. multi_terms, urutan berdasarkan sub-aggregation metric |
| S6 | OpenSearch documentation: Cardinality aggregation | https://docs.opensearch.org/latest/aggregations/metric/cardinality/ | primer | diakses 2026-10-10 | Tinggi. cardinality (perkiraan) |
| S7 | Wazuh documentation: API queries | https://documentation.wazuh.com/current/user-manual/api/queries.html | primer | diakses 2026-10-10 | Tinggi. Sintaks WQL parameter q |
| S8 | Threat-Hunting Day 04-06 (data, teknik, hunt di Splunk) | (lokal) | rujukan internal | 2026-10-08 | Teknik dan paritas |
| S9 | Wazuh documentation: Custom rules | https://documentation.wazuh.com/current/user-manual/ruleset/rules/custom.html | primer | diakses 2026-10-18 | Tinggi. local_rules.xml, ID 100000-120000, wazuh-logtest, restart, overwrite |
| S10 | Wazuh documentation: Audit configuration (system calls monitoring) | https://documentation.wazuh.com/current/user-manual/capabilities/system-calls-monitoring/audit-configuration.html | primer | diakses 2026-10-18 | Tinggi. CDB list audit-keys bawaan, localfile `log_format` audit, ruleset auditd, alert di modul Threat Hunting |
| S11 | Wazuh 4.14 documentation: Monitoring commands run as root | https://documentation.wazuh.com/4.14/user-manual/capabilities/system-calls-monitoring/use-cases/monitoring-commands-run-as-root.html | primer | diakses 2026-10-18 | Tinggi. Rule auditd contoh `-F euid=0 -S execve -k audit-wazuh-c`, alert rule 80792 |
| S12 | Wazuh ruleset v4.14.0: 0365-auditd_rules.xml | https://raw.githubusercontent.com/wazuh/wazuh/v4.14.0/ruleset/rules/0365-auditd_rules.xml | primer (kode sumber) | tag v4.14.0; diakses 2026-10-18 | Tinggi. Rule 80700 level 0, 80792 level 3 dengan lookup `command` |
| S13 | Wazuh ruleset v4.14.0: 0040-auditd_decoders.xml | https://raw.githubusercontent.com/wazuh/wazuh/v4.14.0/ruleset/decoders/0040-auditd_decoders.xml | primer (kode sumber) | tag v4.14.0; diakses 2026-10-18 | Tinggi. Field audit.* termasuk exe, command, execve.a0-a7, cwd, auid, euid, ppid |
| S14 | Wazuh ruleset v4.14.0: 0095-sshd_rules.xml | https://raw.githubusercontent.com/wazuh/wazuh/v4.14.0/ruleset/rules/0095-sshd_rules.xml | primer (kode sumber) | tag v4.14.0; diakses 2026-10-18 | Tinggi. Rule 5700 level 0 noalert, 5715 level 3 (T1078, T1021) |
| S15 | Wazuh ruleset v4.14.0: 0310-ssh_decoders.xml | https://raw.githubusercontent.com/wazuh/wazuh/v4.14.0/ruleset/decoders/0310-ssh_decoders.xml | primer (kode sumber) | tag v4.14.0; diakses 2026-10-18 | Tinggi. Decoder `sshd-success`: user, srcip, srcport |
| S16 | Wazuh documentation: Decoders XML syntax | https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/decoders.html | primer | diakses 2026-10-18 | Tinggi. `user` adalah alias `dstuser` |
| S17 | Wazuh documentation: ossec.conf alerts (log_alert_level) | https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/alerts.html | primer | diakses 2026-10-18 | Tinggi. log_alert_level default 3 |
| S18 | Wazuh documentation: Index lifecycle management | https://documentation.wazuh.com/current/user-manual/wazuh-indexer-cluster/index-lifecycle-management.html | primer | diakses 2026-10-18 | Tinggi. Policy ISM retensi (contoh `wazuh-alerts-*` 90 hari), ism_template, langkah dashboard, apply policy ke index lama |
| S19 | OpenSearch documentation: Rare terms aggregation | https://docs.opensearch.org/latest/aggregations/bucket/rare-terms/ | primer | diakses 2026-10-18 | Tinggi. max_doc_count default 1 maks 100, precision, perkiraan, breadth-first, peringatan terms urutan naik |
| S20 | Wazuh documentation: Release notes (4.14.9) | https://documentation.wazuh.com/current/release-notes/index.html | primer | 4.14.9 rilis 2026-10-14; diakses 2026-10-18 | Tinggi. Versi terbaru 4.14.9; belum ada 5.0 di daftar |
| S21 | FreshPorts: security/wazuh-indexer | https://www.freshports.org/security/wazuh-indexer | sekunder (paket FreeBSD) | diakses 2026-10-18 | Sedang. Dependensi seri OpenSearch 2.19 untuk paket 4.14; bukan pernyataan resmi Wazuh |
| S22 | Wazuh 4.14 documentation: Threat hunting (use case) | https://documentation.wazuh.com/4.14/getting-started/use-cases/threat-hunting.html | primer | diakses 2026-10-18 | Sedang-tinggi. Archives untuk melacak penyebab, waktu, dan rantai proses; halaman ringkas bergaya pengantar |
| S23 | Wazuh documentation: Navigating the Wazuh dashboard | https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/navigating-the-wazuh-dashboard.html | primer | diakses 2026-10-18 | Tinggi. Menu Threat Hunting di Threat intelligence, `Indexer management > Dev Tools` |
| S24 | Wazuh documentation: Rules XML syntax | https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html | primer | diakses 2026-10-18 | Tinggi. `<field>` dengan type osregex/osmatch/pcre2, `<if_sid>`, level 0-16, noalert, `<mitre>` |

**Catatan sumber:** versi OpenSearch yang menjadi dasar Wazuh indexer 4.14 hanya dikonfirmasi lewat paket pihak ketiga [S21]; cek di instance dengan `GET /`. Pemetaan tipe field oleh template Wazuh (termasuk `data.audit.*`, `data.srcip`, dan `data.dstuser` sebagai `keyword`) dan jumlah shard per index harian perlu dicek per instance sebelum agregasi. Belum ada sumber resmi yang menjelaskan apakah event archives yang tidak cocok dengan rule apa pun tetap membawa objek `rule`; filter `must_not` `range` `rule.level` `gte` 3 dipilih karena benar untuk kedua kemungkinan. Penerimaan `bucket_selector` di bawah `multi_terms` dan kecocokan `rare_terms` dengan sub-aggregation tertentu perlu diuji di versi indexer-mu. Klaim tentang plugin SQL/PPL di Wazuh indexer berasal dari forum dan tulisan pihak ketiga. Seluruh isi PT JAB (angka archives, hunt `HUNT-2027-010` dan `HUNT-2027-011`, rule 100200 sampai 100202, akun dan host) adalah penerapan catatan ini pada organisasi fiktif, bukan hasil eksekusi nyata.
