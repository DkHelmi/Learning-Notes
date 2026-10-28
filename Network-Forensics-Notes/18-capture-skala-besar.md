---
day: 18
title: 'Capture skala besar: retensi nyata, Arkime, memotong, menyaring, dan mencuplik'
researched_on: 2026-10-29
versions_checked: 'Arkime v6.9.1 (rilis GitHub 22 Okt 2026; Arkime 7 belum rilis), halaman FAQ, Settings, Rules format, dan Estimators arkime.com diakses 2026-10-29; Wireshark dan dumpcap 4.6.9 (stabil; 4.4.19 old stable; 5.0.0rc1 rilis pengembangan); Zeek 9.0.1 LTS (LTS sebelumnya 8.0.11), dokumentasi capture_loss.log; Suricata 8.0.7 (15 Sep 2026), dokumentasi pcap-log cabang latest; nfdump 1.7.10; RFC 5475, RFC 3176, RFC 7011; rujukan Day 01, 02, 05, 06, 08, 09, 10, 12, 15, 16, 17'
---

# Day 18: Capture skala besar

Cakupan: menjalankan perekaman paket di jaringan yang terlalu besar untuk disimpan seluruhnya, mengukur retensi yang benar-benar tersedia, memilih apa yang dibuang (memotong, menyaring, atau mencuplik) beserta akibatnya, dan tetap bisa menjawab pertanyaan insiden lewat metadata, perekaman sesuai permintaan, dan kebijakan retensi tertulis.

## Ide inti

Day 02 sampai Day 16 bekerja di atas pcap yang kebetulan masih ada. Di jaringan sungguhan, itu jarang terjadi: perekaman penuh pada satu tautan 1 Gbps tanpa kompresi memakan sekitar 11 TB disk per hari, dan contoh untuk 2,5 Gbps selama tujuh hari mencapai sekitar 192,5 TB [S1]. Angka itu yang menentukan arsitektur, bukan preferensi teknis. Karena itu pekerjaan di skala besar selalu berupa kompromi yang disadari: apa yang disimpan utuh, apa yang disimpan sebagai metadata saja, berapa lama masing-masing, dan apa yang direlakan hilang. Gagasan inti Day ini ada tiga. Pertama, retensi pcap adalah akibat dari kapasitas dibagi laju tulis, sehingga harus diukur sebagai angka setiap hari, bukan dibaca dari dokumen rencana. Kedua, metadata dan paket punya umur berbeda, dan metadata yang panjang adalah yang menyelamatkan investigasi ketika paketnya sudah tertimpa. Ketiga, memotong, menyaring, dan mencuplik sering disebut bergantian padahal akibatnya sangat berbeda; keputusan yang tidak tertulis akan dilupakan lalu menjadi kejutan buruk saat insiden.

Dari NOC kamu sudah kenal ring buffer: `logging buffered` di router menyimpan sejumlah entri, lalu menimpa yang tertua. Saat router bermasalah jam dua pagi dan kamu baru login jam delapan, entri yang kamu butuhkan sering sudah hilang. Ring buffer pcap sama persis, hanya skalanya terabyte; batas analoginya, bukti yang sudah tertimpa tidak bisa diambil mundur dari mana pun, dan "jumlah entri" ring pcap diukur dalam byte, sehingga satu lonjakan trafik memperpendek jendela waktu untuk semua orang. Kamu juga sudah kenal membaca kapasitas link dari puncak yang berkelanjutan (persentil 95, jam sibuk), bukan dari rata-rata harian: retensi nyata ring buffer dibaca dengan cara yang sama. Batasnya, link yang penuh menurunkan kualitas layanan secara terlihat, sedangkan ring buffer yang memendek tidak memberi gejala apa pun sampai seseorang mencari paket yang sudah hilang. Terakhir, kebiasaan mengambil `show tech-support` sebelum me-reload router yang bermasalah adalah padanan "mengunci pcap" (case hold): ambil buktinya dulu, baru lanjutkan. Batasnya, `show tech` diambil oleh orang yang sedang menangani perangkat, sedangkan case hold harus berjalan otomatis atau dalam hitungan menit setelah alert, oleh siapa pun yang sedang jaga.

```
 Jumat 18:00 sampai Senin 09:40 WIB: seed backup jkt-bkp01 10.20.6.40 -> 203.0.113.194:443 (NAT 198.51.100.218), sekitar 600 Mbps

 kantor + server DC --> [jkt-fw01, sisi dalam] --TAP egress--> jkt-npb01 --+--> jkt-zeek01   metadata, index zeek (90 hari)
                                                                          +--> jkt-ids01    alert, index suricata
                                                                          +--> jkt-pcap01   ring 8.400 file x 1 GB = 8,4 TB
                                                                          +--> jkt-arkime01 pilot sejak 2027-06-07

 jendela ring = 8,4 TB / laju tulis
   minggu biasa  ~27,5 MB/s (rata-rata 22% dari 1 Gbps)       -> sekitar 85 jam
   akhir pekan   ~85 MB/s  (kantor 8% + seed 600 Mbps)        -> sekitar 27,5 jam

 Jumat 14:05 (SOC-2027-0686) tertimpa Sabtu sekitar 19:05 WIB
 Senin 08:00: paket tertua Minggu 04:10 WIB, jendela 27,8 jam, target 72 jam
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan, kantor pusat dan data center di Jakarta, dan NOC 24/7 yang satu lantai dengan SOC. Sejak Mei 2027 PT JAB menjalankan "Program NSM PT JAB": TAP egress Jakarta di sisi dalam firewall `jkt-fw01` dan SPAN core switch data center masuk ke packet broker `jkt-npb01` (`10.20.70.10`), yang membagikan salinan trafik ke Zeek `jkt-zeek01` (`10.20.70.12`), Suricata `jkt-ids01` (`10.20.70.11`), dan ring buffer pcap `jkt-pcap01` (`10.20.70.13`, egress Jakarta saja). `jkt-pcap01` punya 12 disk 1 TB dalam RAID 6 dan ring buffer 8,4 TB: dumpcap mengganti file setiap 15 menit atau 1 GB, mana yang lebih dulu, dengan target retensi 72 jam pada trafik rata-rata (Day 01 bagian 2.3). Link internet kantor dan korporat yang di-TAP berkapasitas 1 Gbps. Analisis dilakukan dari `jkt-nsm-ws01` (`10.20.70.20`), yang me-mount ring buffer read-only di `/mnt/pcap01/ring/`. Rencana awal program menyebut pcap untuk core switch data center baru dievaluasi Juli.

Jumat 2027-06-18 pukul 14:07 WIB, Microsoft Defender for Endpoint (MDE) membuat alert `SOC-2027-0686` di `JKT-WS-2086` (`10.10.60.186`) milik `maya.puspita` dari Customer Care: `wscript.exe` menjalankan skrip dari arsip zip yang baru diunduh, lalu membuka koneksi jaringan; MDE menghentikan prosesnya dan menghapus skrip itu. Analyst L1 Dwi Cahyono men-triage pukul 16:40 dan menandai tiket "menunggu analisis L2 Senin". Pukul 18:00 hari yang sama, tim Agung Prabowo (Lead Infrastruktur) memulai seed pertama backup offsite `DC-BACKUP-OFFSITE` dari server backup `jkt-bkp01` (`10.20.6.40`) ke penyimpanan objek `objek.awanarsip.example` (`203.0.113.194`), dibatasi sekitar 600 Mbps dan berjalan terus sepanjang akhir pekan. Sabtu sekitar 05:45, saved search `JAB-PCAP-HEALTH-01` membuat alert `SOC-2027-0685` (jendela ring di bawah 48 jam), yang dicatat petugas jaga Gilang Ramadhan untuk Senin. Senin 2027-06-21 pukul 07:30, Sari Kusuma (analyst L2) mencoba mengambil pcap Jumat 14:05, mendapati paket tertua sudah Minggu subuh, lalu memindai seluruh ring untuk alamat tujuan unduhan; pukul 08:05 muncul `SOC-2027-0687`, drop di interface capture `jkt-pcap01`. Pukul 08:30, SOC lead Dimas Prasetyo menulis kepadamu, dengan Manajer NOC Bambang Hartono dan Agung di CC:

> "Pagi. Kabar buruk dulu: Sari mau tarik pcap Jumat 14:05 untuk SOC-2027-0686 (laptop Maya di Customer Care), dan paket tertua di jkt-pcap01 sekarang Minggu subuh. Alert retensi 0685 sudah bunyi dari Sabtu. Kata Pak Agung, sejak Jumat sore seed backup offsite jalan terus sampai pagi ini. Tolong siapkan bahan untuk evaluasi tengah program dengan Pak Hendra hari Kamis. Satu, kenapa 72 jam kita jadi sehari, dan berapa sebenarnya retensi kita selama ini. Dua, untuk kasus Maya, apa yang masih bisa dijawab tanpa pcap. Tiga, Juli rencananya pcap diperluas ke core DC; berapa disk yang dibutuhkan kalau mau tujuh hari. Empat, Pak Agung menawarkan tiga cara hemat: buang trafik backup dari rekaman, potong paket jadi header saja, atau rekam satu dari sepuluh paket. Mana yang aman? Lima, pilot Arkime Pak Agung sudah dua minggu; layak diteruskan atau tidak, dan apa yang harus dibereskan. Enam, Pak Bambang tanya kenapa ada drop di pcap padahal link tidak error, dan bagaimana kita tahu rekaman kita lengkap. Tujuh, alert seperti Jumat harus langsung mengunci pcap-nya; bagaimana caranya, dan siapa yang menyalakan perekaman khusus kalau perlu. Delapan, Bu Nina dan Pak Agus minta kebijakan retensi tertulis dengan angka yang bisa dipertanggungjawabkan. Rapat internal jam 14:00."

Pesan itu memuat delapan pertanyaan:

1. Kenapa retensi pcap turun dari target 72 jam menjadi sekitar sehari, dan berapa retensi nyata selama ini?
2. Apa yang masih bisa dijawab untuk kasus `JKT-WS-2086` tanpa pcap?
3. Berapa kebutuhan disk bila pcap diperluas ke core switch data center dengan retensi tujuh hari?
4. Dari tiga usulan Agung (menyaring trafik backup, memotong paket, mencuplik satu dari sepuluh), mana yang aman dan apa akibatnya?
5. Layakkah pilot Arkime diteruskan, dan apa yang harus dibereskan?
6. Kenapa ada drop di pcap padahal link tidak error, dan bagaimana membuktikan rekaman lengkap?
7. Bagaimana mengunci pcap begitu alert muncul, dan siapa yang menyalakan perekaman khusus?
8. Seperti apa kebijakan retensi tertulis yang angkanya bisa dipertanggungjawabkan?

Pertanyaan 1 dijawab di bagian 1.1, 2.1, dan 2.2, pertanyaan 2 di bagian 1.2 dan 2.3, pertanyaan 3 di bagian 1.3 dan 2.4, pertanyaan 4 di bagian 1.4 dan 2.5, pertanyaan 5 di bagian 1.5 dan 2.6, pertanyaan 6 di bagian 1.6 dan 2.7, pertanyaan 7 di bagian 1.7 dan 2.8, dan pertanyaan 8 di bagian 1.8 dan 2.9. Bagian 2.10 berisi jawaban untuk Dimas, Bambang, dan Agung.

**Kapan relevan:** saat merancang atau memperluas sensor pcap; saat menjanjikan retensi kepada manajemen, auditor, atau DPO; saat ada yang mengusulkan filter, snaplen, atau sampling untuk menghemat disk; saat pcap yang dicari ternyata sudah tertimpa; saat sensor melaporkan drop; dan saat data flow bercuplik dipakai sebagai angka di laporan insiden.
**Kapan bukan jawaban:** saat yang dibutuhkan adalah isi trafik terenkripsi, karena berapa pun retensinya isi TLS tetap tertutup (Day 06, 15, 16); saat trafik tidak pernah lewat sensor (antar workstation di switch akses yang sama, kantor cabang tanpa sensor, cloud, Day 17); saat pertanyaannya tentang proses di host, yang dijawab data endpoint; dan saat yang dibutuhkan hanya volume dan tren, karena flow sudah cukup dan jauh lebih murah (Day 10).

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (pcap, SPAN, TAP, packet broker, ring buffer, snaplen, capture filter dan display filter, `conn.log`, `files.log`, `capture_loss.log`, flow, sampling flow, timeout flow) tidak diulang; definisinya ada di Day 01 sampai 16 [S6]. Tabel ini memuat istilah yang dipakai Day ini; kolom kanan memakai padanan dari pekerjaan NOC dan ISP.

| Istilah | Arti singkat | Padanan di NOC/ISP |
|---|---|---|
| Retensi rencana | Jendela waktu yang tertulis di dokumen, misalnya "72 jam" | Kapasitas link di kontrak |
| Retensi nyata | Selisih waktu antara paket tertua yang masih ada dan sekarang | Throughput yang benar-benar dirasakan pelanggan |
| Laju tulis berkelanjutan | Rata-rata laju yang bertahan selama jendela retensi, bukan rata-rata harian umum | Persentil 95 atau jam sibuk saat capacity planning |
| SPI data | Istilah Arkime untuk metadata sesi yang diindeks di OpenSearch atau Elasticsearch | Ringkasan per sesi seperti CDR |
| Capture dan viewer (Arkime) | Komponen penulis pcap dan pembuat metadata, dan komponen web untuk mencari serta menghapus pcap | Probe dan portal NMS |
| Kedaluwarsa indeks (ILM/ISM, `db.pl expire`) | Kebijakan atau tugas terjadwal yang menghapus indeks metadata lama | Rotasi dan purge database NMS |
| `freeSpaceG` | Ambang ruang kosong; di bawahnya Arkime menghapus pcap tertua | Threshold disk yang memicu housekeeping |
| Memotong (truncation) | Menyimpan hanya N byte pertama tiap paket (snaplen), atau hanya N paket pertama tiap sesi | Mirror header saja ke analyzer |
| Menyaring (filtering) | Seleksi deterministik berdasarkan isi atau perlakuan paket; yang tidak terpilih tidak disimpan | ACL pada sesi monitor |
| Mencuplik (sampling) | Seleksi yang tidak deterministik terhadap isi: berdasarkan posisi paket atau keputusan acak | NetFlow atau sFlow 1:N |
| Hash-based selection | Memilih paket bila hash dari field tertentu jatuh di rentang yang ditentukan; secara formal termasuk penyaringan | Load balancing per hash di LAG |
| Conditional pcap | Menyimpan paket hanya untuk flow yang memicu alert atau ditandai rule | Capture otomatis yang dipicu trap |
| Case hold (mengunci pcap) | Menyalin bagian ring yang terkait tiket ke tempat terpisah sebelum tertimpa | `show tech-support` sebelum reload |
| Perekaman sesuai permintaan | Capture tambahan bertarget, berbatas waktu dan ukuran, dinyalakan atas tiket | `monitor session` sementara saat troubleshooting |
| Register filter | Daftar semua filter dan pengecualian capture beserta alasan, pemilik, dan tanggal tinjau | Daftar ACL pengecualian dengan nomor change |

### 1.1 Retensi rencana dan retensi nyata

Pertanyaan pertama Dimas lahir dari angka yang tidak pernah dilihat siapa pun sampai dibutuhkan: target 72 jam tertulis di kebijakan akses (Day 01 bagian 2.8), tetapi ring buffer `jkt-pcap01` tidak tahu apa-apa tentang target itu.

Ring buffer dumpcap di `jkt-pcap01` berbasis ukuran: 8.400 file, masing-masing ditutup saat mencapai sekitar 1 GB atau berumur 15 menit, mana yang lebih dulu, lalu file tertua ditimpa [S10]. Day 01 bagian 1.6 sudah menjelaskan konsekuensinya: ring berbasis ukuran menjamin pemakaian disk, bukan jendela waktu. Rumusnya sederhana:

```
jendela (detik) = kapasitas ring (byte) / laju tulis rata-rata selama jendela itu (byte per detik)
```

Yang sering terlewat adalah kata "selama jendela itu". Laju yang menentukan bukan rata-rata bulanan atau rata-rata hari kerja, melainkan rata-rata trafik yang benar-benar ditulis dalam 72 jam terakhir. Seed backup sekitar 600 Mbps yang berjalan terus dari Jumat sore menaikkan laju tulis akhir pekan dari sekitar 10 MB per detik ke sekitar 85 MB per detik, sehingga 8,4 TB hanya cukup untuk sekitar 27,5 jam. Tidak ada yang salah di dumpcap; yang berubah hanya trafiknya.

Batas rotasi 15 menit juga perlu dibaca dengan hitungan. File 1 GB terisi dalam 15 menit hanya bila laju tulis di bawah 1.000.000.000 byte dibagi 900 detik, sekitar 1,11 MB per detik atau sekitar 8,9 Mbps. Di link egress PT JAB laju itu hampir tidak pernah tercapai, kecuali saat link putus atau pemeliharaan. Artinya ukuran yang hampir selalu menentukan rotasi; batas waktu hanya menjaga agar file tidak terbuka berjam-jam saat trafik sepi.

Ada dua pelajaran perencanaan dari kasus ini:

- **Hitung dengan laju puncak yang berkelanjutan, bukan rata-rata harian.** Rata-rata 22% dalam sebulan memberi sekitar 85 jam; satu akhir pekan dengan seed backup memberi kurang dari 28 jam. Perubahan trafik yang terencana (backup baru, migrasi, pembaruan OS massal) harus melewati SOC sebagai pemilik sensor, karena perubahan itu langsung memotong retensi.
- **Pantau retensi nyata sebagai angka, bukan sebagai asumsi dari konfigurasi.** Penghapusan berkas tertua saat kapasitas habis berarti kapasitas yang kurang diam-diam memperpendek retensi nyatamu [S1]. Satu-satunya cara mengetahuinya adalah membaca waktu paket tertua secara rutin, mencatatnya, dan memberi alarm bila angkanya di bawah ambang (bagian 2.1).

Istilah resminya: retensi rencana adalah angka di dokumen, retensi nyata adalah usia paket tertua yang masih ada. Yang dilaporkan di tiket, laporan insiden, dan kepada auditor adalah retensi nyata.

### 1.2 Dua jenis data dengan umur berbeda

Pertanyaan kedua Dimas ("apa yang masih bisa dijawab tanpa pcap") hanya bisa dijawab positif karena PT JAB menyimpan dua jenis data dengan umur berbeda: paket di `jkt-pcap01` beberapa hari, dan metadata Zeek di index `zeek` Splunk 90 hari, sama dengan kebijakan index jaringan lain seperti `firewall`.

Arkime membagi datanya menjadi dua dengan cara yang sama, dan pembagian ini adalah pola yang berlaku umum, bukan khas satu alat [S1]. Tabel berikut membandingkan keduanya; perhatikan kolom ukuran, karena di situlah alasan umurnya berbeda.

| Jenis | Isi | Disimpan di | Ukuran relatif |
|---|---|---|---|
| SPI data | Metadata sesi | OpenSearch atau Elasticsearch | Perkiraan kasar 5 persen dari ukuran pcap untuk retensi yang sama [S1] |
| PCAP | Paket mentah | Sistem berkas di mesin capture | Besar; sekitar 11 TB per hari per Gbps tanpa kompresi [S1] |

Keduanya dihapus secara terpisah, dan menghapus salah satu tidak menghapus yang lain [S1]. Pemisahan itu disengaja dan berguna: kamu bisa menyimpan metadata enam bulan sementara paket mentah hanya tujuh hari, sehingga pertanyaan "apakah host ini pernah berbicara dengan alamat itu" tetap bisa dijawab jauh ke belakang walaupun isinya sudah hilang.

Di PT JAB, peran SPI data dipegang Zeek. Untuk kasus `JKT-WS-2086`, `http.log` di hop core dan hop egress masih mencatat URL, method, ukuran body, dan `uid`; `files.log` masih mencatat tipe file, ukuran, dan SHA-256; log `jkt-proxy01` (30 hari) masih mencatat akun dan URL. Yang hilang bersama pcap adalah isi: file zip itu sendiri dan isi body `POST` yang dikirim skrip. Pembagian tugasnya jadi jelas:

| Pertanyaan | Bisa dijawab metadata? | Butuh paket? |
|---|---|---|
| Siapa, kapan, ke mana, berapa byte | Ya | Tidak |
| File apa (tipe, hash, ukuran) | Ya, bila hash dihitung sensor | Tidak |
| Host lain yang menerima file yang sama | Ya, lewat hash | Tidak |
| Isi file dan isi data yang dikirim | Tidak | Ya, bila protokolnya polos |
| Isi trafik TLS | Tidak | Tidak juga, tanpa kunci |

Baris terakhir penting untuk rapat Kamis: retensi pcap yang panjang tidak menambah apa pun untuk trafik terenkripsi. Nilai pcap terbesar ada di protokol polos dan di bukti tingkat paket untuk kasus yang sudah dipilih.

### 1.3 Angka untuk perencanaan

Pertanyaan ketiga Dimas menyangkut fase berikutnya: pcap untuk segmen server data center lewat `jkt-npb01`, yang menurut counter Bambang membawa puncak 2,3 Gbps setelah deduplikasi (Day 08 bagian 1.8). Angka perencanaannya diambil dari dokumentasi Arkime [S1]:

- Trafik 1 Gbps tanpa kompresi memakan sekitar 11 TB disk per hari.
- Contoh 2,5 Gbps selama tujuh hari membutuhkan sekitar 192,5 TB.
- Perkiraan kasar disk untuk metadata adalah 5 persen dari penyimpanan pcap untuk retensi yang sama.
- Sisakan minimal 1 persen dari ukuran data kluster sebagai heap, dan bagi memori kira-kira setengah untuk mesin pencarian dan setengah untuk cache disk.
- Dianjurkan minimal 30 GB memori per node mesin pencarian, ditambah 30 GB cache disk, dan menjalankan capture terpisah dari mesin pencarian. Mesin capture dianjurkan punya 64 sampai 96 GB RAM.
- Replikasi menggandakan pemakaian disk di node; Arkime tidak mengaktifkan replikasi secara bawaan [S8].

Angka 11 TB sedikit di atas hitungan murni (125 MB per detik kali 86.400 detik sama dengan 10,8 TB, Day 01 bagian 1.6); selisihnya wajar sebagai overhead format. Yang penting adalah ordenya.

Dua cara menurunkan kebutuhan yang disebut dokumentasinya adalah kompresi dan tidak menyimpan sesi TLS secara penuh [S1]. Kompresi pcap sudah aktif secara bawaan sejak Arkime 4.0, dengan `simpleCompression` bawaan `zstd` sejak Arkime 5 [S5][S8]. Yang kedua masuk akal karena isi TLS tidak bisa dibaca (Day 06, 15, dan 16), sehingga menyimpan muatannya hanya menghabiskan disk tanpa menambah kemampuan analisis. Kalkulator resmi Arkime bahkan meminta persentase TLS sebagai masukan, bersama laju rata-rata, hari retensi, ukuran dan jumlah disk, level RAID, kompresi, dan jumlah replika [S8].

Ada satu jebakan yang baru terlihat ketika angka metadata dihitung untuk retensi panjang. Ukuran metadata bergantung pada jumlah sesi, bukan pada byte muatan, sehingga membuang muatan TLS mengecilkan pcap tetapi hampir tidak mengecilkan SPI data. Ditambah aturan heap minimal 1 persen dari data kluster, retensi metadata yang panjang di Arkime bisa menjadi komponen termahal, bukan pcap-nya (bagian 2.4). Di PT JAB, metadata jangka panjang sudah dipegang Zeek di Splunk, sehingga SPI data Arkime tidak perlu dipaksa menyamai 90 hari.

Satu perilaku yang perlu kamu ketahui supaya tidak salah menyimpulkan saat latihan: Arkime pada capture langsung menulis rekaman sesi ketika sesi berakhir, sehingga sesi baru bisa butuh beberapa menit untuk muncul [S1]. Indeks mesin pencarian juga baru di-refresh sekitar sekali per menit [S1].

### 1.4 Tiga cara mengurangi data, dan akibatnya

Pertanyaan keempat Dimas memuat tiga usulan Agung yang terdengar mirip: "buang trafik backup", "potong jadi header saja", dan "rekam satu dari sepuluh paket". Ketiganya sering disebut bergantian padahal akibatnya sangat berbeda. Tabel berikut adalah pegangan utamanya; perhatikan kolom "Yang hilang".

| Cara | Yang dilakukan | Yang hilang | Cocok untuk |
|---|---|---|---|
| Memotong (snaplen) | Menyimpan hanya N byte pertama tiap paket | Muatan, sebagian header lapis atas | Jaringan dengan trafik terenkripsi dominan |
| Menyaring (filter) | Tidak menyimpan trafik yang cocok aturan | Seluruh trafik yang disaring, tanpa jejak | Trafik yang sudah pasti tidak relevan |
| Mencuplik (sampling) | Menyimpan sebagian paket atau alur menurut aturan pemilihan | Sebagian kejadian, secara statistik | Pengukuran volume dan tren |

Pembedaan ketiga yang paling sering disalahpahami di pekerjaan keamanan. RFC 5475 mendefinisikan teknik pemilihan paket secara formal: penyaringan adalah seleksi deterministik berdasarkan isi atau perlakuan paket, yang tidak pernah bergantung pada posisi paket atau keputusan acak; sampling adalah semua seleksi lain [S2]. RFC yang sama membedakan sampling sistematis berbasis hitungan atau waktu, sampling acak n dari N, dan sampling probabilistik seragam [S2]. Ada satu kejutan dalam kerangka itu: seleksi berbasis hash (paket dipilih bila hash dari field tertentu jatuh di rentang yang ditentukan) secara formal termasuk penyaringan, karena hasilnya deterministik [S2]. Bagi analis, akibatnya nyata: seleksi berbasis hash per flow menyimpan seluruh paket untuk flow yang terpilih dan tidak menyimpan apa pun untuk flow lain, sedangkan sampling per paket menyimpan serpihan dari semua flow.

Konsekuensinya untuk analisis: data hasil cuplikan tidak bisa menjawab pertanyaan tentang kejadian tunggal. Ini batas yang keras. Pada cuplikan satu dari seribu, satu koneksi tunggal ke alamat jahat punya peluang besar tidak terekam sama sekali. Karena itu data sFlow atau IPFIX bercuplik berguna untuk mengetahui siapa pembicara terbesar dan bagaimana trennya, tetapi tidak berguna untuk membuktikan sebuah koneksi tidak pernah terjadi [S3][S4]. Kalimat "tidak ditemukan koneksi ke alamat itu" atas data bercuplik hampir selalu menyesatkan. Untuk pcap, sampling per paket bahkan lebih buruk daripada untuk flow: stream TCP tidak bisa dirakit ulang bila sebagian besar segmennya hilang, sehingga Follow Stream dan Export Objects tidak bekerja sama sekali.

Penyaringan punya bahaya lain: trafik yang disaring hilang tanpa jejak, dan enam bulan kemudian tidak ada yang ingat bahwa ia disaring. Setiap aturan filter harus tercatat beserta alasannya dan tanggal tinjauannya, persis seperti pengecualian pada rule deteksi: pengecualian tanpa pemilik dan tanggal tinjau akan bertahan lebih lama dari alasannya dan menjadi titik buta permanen. Untuk trafik yang dikenal, seperti backup `jkt-bkp01`, filter yang sempit (host sumber, host tujuan, dan port sekaligus) jauh lebih aman daripada filter yang lebar.

Memotong punya dua bentuk. Snaplen memotong setiap paket di posisi yang sama, sehingga header tetap ada dan muatan hilang untuk semua protokol, termasuk protokol polos yang justru paling berguna. Pemotongan per sesi menyimpan N paket pertama sebuah sesi lalu berhenti; untuk TLS, N paket pertama memuat handshake (SNI, sertifikat pada TLS 1.2, JA3/JA4), sedangkan sisanya muatan terenkripsi. Arkime mendukung bentuk kedua lewat `dontSaveBPFs` dengan akhiran `:N` dan lewat rule `_maxPacketsToSave` [S5][S7]; dumpcap hanya mendukung snaplen dan capture filter BPF [S10]. Karena itu "buang muatan TLS, simpan handshake" adalah pilihan dengan rasio terbaik, tetapi hanya tersedia di alat yang mengenali sesi.

### 1.5 Arkime: komponen dan dua mekanisme retensi

Pertanyaan kelima Dimas menyangkut pilot `jkt-arkime01` (`10.20.70.15`) yang dipasang Agung sejak Senin 2027-06-07, dengan satu node OpenSearch `jkt-os01` (`10.20.70.16`), membaca salinan egress dari port cadangan `jkt-npb01`. Alasan pilot itu terlihat jelas pagi ini: untuk mencari satu alamat di ring dumpcap, Sari harus membaca 8.400 file satu per satu, sedangkan Arkime menyimpan indeks sesi yang menunjuk langsung ke file dan posisi paketnya.

Komponen Arkime ada tiga [S1]. Capture membaca antarmuka langsung atau berkas pcap, menghasilkan metadata sesi, dan menulis paket mentah ke disk; cara menjalankannya mirip tcpdump. Viewer menyajikan antarmuka web untuk pencarian dan menampilkan paket, sekaligus menangani penghapusan pcap di tiap node capture. Dan OpenSearch atau Elasticsearch menyimpan metadata sesinya.

Dua mekanisme retensi berbeda, dan hanya satu yang otomatis [S1]:

- **PCAP.** Viewer memeriksa ruang disk kosong saat mulai lalu setiap menit. Ketika ruang kosong turun di bawah ambang `freeSpaceG` yang bawaannya 5 persen, ia menghapus berkas pcap tertua, dan selalu menyisakan minimal sepuluh berkas. Dengan `maxFileSizeG` bawaan 12 GB, disk pcap harus muat minimal sepuluh kali ukuran itu, sekitar 120 GB [S1][S5].
- **Metadata sesi.** Tidak ada yang dihapus otomatis. Kamu harus menyiapkan kebijakan siklus hidup indeks (ILM di Elasticsearch, ISM di OpenSearch) atau cron yang menjalankan `db.pl ... expire`, dan contoh resminya menyimpan 90 hari dengan cron harian tengah malam [S1].

Baris kedua adalah penyebab kegagalan yang paling sering terjadi di pemasangan baru: pcap berotasi dengan rapi sementara indeks tumbuh terus sampai klusternya bermasalah. Tetapkan kedaluwarsa metadata di hari pertama, bukan setelah ada keluhan. Pilot PT JAB sudah berjalan dua minggu tanpa kedaluwarsa; bagian 2.6 memeriksanya.

Satu aturan tata letak yang tegas: pcap dan data OpenSearch atau Elasticsearch tidak boleh berbagi sistem berkas [S1]. Bila keduanya satu disk, rotasi pcap yang dipicu disk penuh akan bersaing dengan kebutuhan indeks, dan keduanya rusak bersama. Dokumentasi juga mencatat bahwa disk yang benar-benar habis bisa menghasilkan berkas pcap nol byte [S1].

Pengaturan capture yang paling relevan untuk keputusan kapasitas, dengan nilai bawaannya [S5]:

| Pengaturan | Bawaan | Yang diatur |
|---|---|---|
| `pcapDir` | `/opt/arkime/raw` (sejak 5.5.0) | Direktori pcap; bisa beberapa, dipisah titik koma |
| `maxFileSizeG` | 12 | Perkiraan ukuran maksimal satu berkas pcap |
| `maxFileTimeM` | 0 | Rotasi berdasarkan waktu; 0 berarti hanya berdasarkan ukuran |
| `freeSpaceG` | 5% | Ruang kosong yang dijaga viewer di disk pcap, persen atau GB |
| `snapLen` | 16384 | Ukuran maksimal paket yang dibaca dari antarmuka |
| `bpf` | kosong | Filter BPF yang membuat Arkime tidak melihat trafik sama sekali |
| `dontSaveBPFs` | kosong | Filter BPF yang menghentikan penyimpanan pcap sebuah sesi; akhiran `:N` menyimpan N paket pertama |
| `maxPacketsInQueue` | 200000 | Antrean paket per thread; bila penuh, paket di-drop |

Untuk `snapLen`, dokumentasi menganjurkan mematikan fitur offload NIC daripada menaikkan nilainya [S5]. Offload membuat kartu jaringan menggabungkan segmen menjadi "paket" raksasa sebelum sampai ke capture; hasilnya paket terlihat lebih besar daripada di kabel.

Urutan cara mengurangi disk menurut dampaknya, dari yang paling besar, juga disebut dokumentasi: `bpf` yang membuat Arkime tidak melihat trafik, lalu `packet-drop-ips` yang menjaga paket alamat tertentu keluar dari antrean pemrosesan, lalu rule yang mengatur apakah paket ditulis ke disk [S1]. Paket yang di-drop lewat `dontSaveBPFs` tetap dihitung di metadata sesinya, hanya tidak disimpan [S1]. Itu perbedaan penting dari filter `bpf`: dengan `dontSaveBPFs`, sesinya masih ada di indeks (siapa, kapan, berapa byte), hanya paketnya yang tidak ada.

### 1.6 Kehilangan paket di skala besar

Pertanyaan keenam berasal dari Bambang: `SOC-2027-0687` menyebut drop di `jkt-pcap01` pukul 07:42 sampai 08:02, padahal counter router edge dan firewall bersih. Bagi orang NOC, drop berarti link bermasalah; di sensor, drop hampir selalu berarti sensor tidak sanggup mengikuti.

Paket bisa hilang di setiap mata rantai antara kabel dan disk, dan setiap mata rantai punya counter sendiri:

| Mata rantai | Contoh penyebab | Counter yang dibaca |
|---|---|---|
| SPAN di switch | Port sumber lebih ramai daripada port tujuan, switch sibuk | Counter port SPAN di switch |
| Packet broker | Port keluar lebih kecil dari total masukan, deduplikasi | Counter port `jkt-npb01` |
| NIC sensor | Ring NIC penuh | `ethtool -S`, `ip -s link` |
| Kernel dan buffer capture | Buffer capture terlalu kecil, proses lambat mengambil | Statistik drop dumpcap, `kernel_drops` Suricata |
| Proses analisis | Antrean penuh, satu worker kelebihan beban | `capture_loss.log` Zeek, `drop:` dan antrean Arkime |
| Disk | Penulisan tidak secepat laju masuk, I/O bersaing | Latensi dan antrean disk, buffer yang menumpuk |

Tiap alat melaporkan kehilangan dengan cara berbeda, dan itu memengaruhi cara membacanya:

- **dumpcap** melaporkan paket yang diterima dan di-drop per antarmuka, termasuk pembagian `pcap`, `dumpcap`, `flushed`, dan `ps_ifdrop` (Day 01 bagian 2.4). Buffer capture diatur dengan `-B` dalam MiB, bawaannya 2 MiB, dan sistem atau antarmuka bisa diam-diam membatasi atau menaikkan nilainya [S10].
- **Zeek** tidak menghitung drop; `capture_loss.log` memperkirakan kehilangan dari celah nomor urut TCP yang tidak pernah terlihat, kira-kira setiap 15 menit, dan hanya untuk TCP [S12]. Dokumentasi menyebut sedikit kehilangan masih bisa ditoleransi dan contohnya tidak pernah melewati 1% [S12].
- **Suricata** menghitung paket yang dibuang kernel di `capture.kernel_drops` (Day 09 bagian 2.12).
- **Arkime** menulis kemajuan berkala dengan counter `drop:` dari antarmuka dan rincian paket yang dibuang karena antrean paket kelebihan beban; ia juga melaporkan antrean penulisan disk yang tertunda [S1].

Untuk sensor pcap, mata rantai terakhir sering dilupakan. Menulis 1 Gbps penuh berarti menulis sekitar 125 MB per detik terus-menerus. Disk yang sama juga dibaca analis saat mengambil ekstrak kasus, dan pembacaan besar (memindai seluruh ring untuk satu alamat) bersaing dengan penulisan. Saat penulisan tertunda, buffer capture terisi, lalu kernel mulai membuang paket. Gejala ini tidak terlihat di router mana pun, karena router memang tidak kehilangan apa-apa.

Pembuktian bahwa rekaman lengkap selalu punya dua bagian: counter drop di sensor untuk jendela waktu yang diselidiki, dan pembanding dari sensor lain yang menerima salinan yang sama. Bila Zeek di `jkt-zeek01` tidak mencatat kehilangan di menit yang sama, sedangkan `jkt-pcap01` mencatat drop, masalahnya ada di `jkt-pcap01`, bukan di TAP atau `jkt-npb01`. Untuk laporan, kalimat "tidak ada paket ke alamat itu" dari pcap yang drop-nya bukan nol harus menyebut angka drop-nya.

### 1.7 Berlapis, mengunci pcap, dan perekaman sesuai permintaan

Pertanyaan ketujuh Dimas lahir dari dua kesempatan yang terlewat: tiket `SOC-2027-0686` dibuat Jumat 14:07 dan paketnya masih ada sampai Sabtu sekitar 19:05; alert retensi `SOC-2027-0685` berbunyi Sabtu 05:45, juga sebelum paket itu tertimpa. Yang tidak ada adalah prosedur.

Pendekatan yang bekerja adalah berlapis, bukan seragam:

1. **Metadata untuk semua.** Zeek atau SPI data untuk seluruh trafik, dengan retensi panjang. Ini yang menjawab sebagian besar pertanyaan.
2. **Paket penuh untuk segmen bernilai tinggi.** Perimeter, segmen server, dan jalur manajemen. Retensi pendek, misalnya tujuh sampai tiga puluh hari.
3. **Paket penuh sesuai permintaan.** Kemampuan menyalakan perekaman penuh di segmen tertentu saat ada insiden, dengan prosedur yang sudah disiapkan sebelumnya.
4. **Cuplikan untuk kapasitas.** sFlow atau IPFIX bercuplik untuk perencanaan kapasitas dan tren, bukan untuk forensik kejadian tunggal.

Lapis ketiga sering dilupakan dan paling murah. Yang dibutuhkan bukan perangkat keras tambahan, melainkan prosedur, izin, dan latihan sehingga perekaman bisa dinyalakan dalam hitungan menit, bukan hari.

Di antara lapis dua dan tiga ada dua alat yang membuat jendela pendek tetap berguna:

- **Case hold (mengunci pcap).** Begitu tiket dengan indikator jaringan dibuat, paket ring untuk host dan jendela waktu kejadian disalin ke direktori kasus, dengan hash, sebelum ring menimpanya. Ini mengubah pertanyaan "berapa lama ring bertahan" menjadi "berapa cepat kita mengunci": dengan jendela 27 jam pun, case hold dalam 30 menit menyelamatkan kasus Jumat.
- **Conditional pcap.** Suricata bisa menulis pcap hanya untuk flow yang memicu alert lewat `pcap-log` dengan `conditional: alerts`, atau hanya paket yang ditandai rule dengan keyword `tag` lewat `conditional: tag`; bawaannya `all` [S11]. Untuk TCP, Suricata memakai data dari stream engine untuk mencatat data yang memicu alert [S11]. Volumenya kecil karena hanya flow ber-alert yang disimpan, sehingga retensinya bisa berminggu-minggu. Batasnya jelas: kejadian yang tidak memicu alert, seperti unduhan zip Jumat, tidak pernah tersimpan.

Perekaman sesuai permintaan adalah capture kedua yang bertarget, misalnya hanya trafik ke satu alamat tujuan, dengan batas waktu dan ukuran, menulis ke volume terpisah dari ring. Karena ia memproses trafik yang lebih sempit untuk tiket yang sudah dibuka, dasar pemakaiannya sama dengan pemotongan per kasus di Day 02 bagian 2.1. Perekaman yang menarget semua trafik satu karyawan tetap butuh persetujuan SOC lead, DPO, dan Legal menurut kebijakan akses di Day 01 bagian 2.8.

### 1.8 Menuliskan kebijakan retensi

Pertanyaan kedelapan datang dari Nina Kartika (Manajer Risiko dan Kepatuhan TI) dan Agus Setiawan (DPO). Draf kebijakan akses v0.1 hanya punya satu baris retensi: "target 72 jam pada trafik rata-rata". Minggu ini membuktikan bahwa satu baris itu tidak cukup.

Kebijakan retensi adalah dokumen keamanan sekaligus dokumen hukum. Yang harus ada di dalamnya:

- Apa yang direkam di tiap segmen, dan apa yang tidak.
- Berapa lama masing-masing disimpan, dipisahkan antara metadata dan paket.
- Aturan filter yang berlaku, beserta alasan dan tanggal tinjauannya.
- Siapa yang bisa mengakses, dan bagaimana aksesnya dicatat.
- Apa yang terjadi saat disk penuh, dinyatakan terang-terangan.

Butir terakhir lebih penting daripada kelihatannya. Perilaku bawaan menghapus berkas tertua ketika ruang kosong menipis [S1], yang berarti kapasitas yang kurang diam-diam memperpendek retensi nyatamu. Kebijakan yang jujur menulis retensi sebagai "target, diukur harian, dengan ambang alarm", bukan sebagai jaminan.

Ada sisi privasi yang membuat batas atas sama pentingnya dengan batas bawah. Pcap berisi isi komunikasi karyawan, dan prinsip minimisasi dalam UU PDP berarti paket disimpan sesingkat kebutuhan investigasinya (Day 01 bagian 1.7). Retensi panjang untuk metadata dan pendek untuk paket bukan hanya pilihan hemat disk; itu juga yang paling mudah dipertahankan di depan DPO. Kebijakan perlu menyebut kedua arah: retensi minimal yang dijaga untuk keperluan investigasi, dan retensi maksimal untuk isi.

Ekstrak kasus (hasil case hold) adalah kategori sendiri. Ia disimpan dengan nomor insiden dan hash, dihapus saat kasus ditutup ditambah masa simpan yang ditetapkan Legal, dan tidak ikut aturan penimpaan ring.

## 2. Contoh dan langkah praktis: Senin pagi di `jkt-pcap01`

Semua keluaran di bagian ini adalah keluaran ilustrasi untuk organisasi fiktif PT JAB, bukan hasil eksekusi nyata. Asumsi lingkungannya sama dengan Day sebelumnya: `jkt-pcap01` dan `jkt-nsm-ws01` memakai jam UTC, Splunk menampilkan WIB untuk akun SOC, dan `jkt-flow01` menyimpan flow dengan jam WIB di `/flow/<router>/YYYY/MM/DD/` (Day 10). File ring dumpcap bernama `egress-jkt_NNNNN_YYYYMMDDHHMMSS.pcapng`, ditulis di `/data/pcap/ring/` di sensor dan terlihat di `/mnt/pcap01/ring/` dari `jkt-nsm-ws01`. Nilai konfigurasi dan nama opsi berubah antar versi, jadi cocokkan dengan versi yang kamu pasang.

### 2.1 Mengukur retensi nyata `jkt-pcap01`: `SOC-2027-0685`

Artefak pertama menjawab pertanyaan 1 dengan angka. Sebelum menjelaskan apa pun ke Dimas, pastikan dulu berapa jendela ring yang benar-benar ada pagi ini.

**Tujuan:** menemukan paket tertua dan terbaru di ring, jumlah file, dan sisa disk, lalu menghitung retensi nyata.

```bash
# file tertua dan terbaru menurut waktu modifikasi, dan jumlah file
ls -1tr /mnt/pcap01/ring/ | head -1
ls -1tr /mnt/pcap01/ring/ | tail -1
ls -1 /mnt/pcap01/ring/ | wc -l

# waktu paket pertama dan terakhir di file tertua
capinfos -a -e /mnt/pcap01/ring/egress-jkt_63871_20270619211007.pcapng

# ruang disk volume ring, dilihat dari mount read-only
df -h /mnt/pcap01
```

Penjelasan tiap bagian:

- `ls -1tr` mengurutkan dari yang paling lama dimodifikasi; waktu modifikasi file ring adalah saat file terakhir ditulis, jadi file tertua adalah yang pertama. Nama file juga memuat jam pembuatan file dalam UTC (Day 02 bagian 2.1), dan keduanya harus cocok.
- `wc -l` memastikan ring memang penuh. Bila jumlah file di bawah 8.400, ring belum pernah berputar penuh sejak restart terakhir, dan jendelanya dibatasi waktu restart, bukan kapasitas.
- `capinfos -a -e` menampilkan waktu paket pertama dan terakhir. Paket tertua yang masih ada adalah paket pertama di file tertua.
- `df -h` menampilkan ukuran dalam pangkat 1024 (T berarti TiB). 8.400 file sekitar 1 GB adalah sekitar 7,64 TiB (Day 01 bagian 2.3).

Keluaran ilustrasi:

```
egress-jkt_63871_20270619211007.pcapng
egress-jkt_72270_20270621005946.pcapng
8400

File name:           /mnt/pcap01/ring/egress-jkt_63871_20270619211007.pcapng
First packet time:   2027-06-19 21:10:07.004113
Last packet time:    2027-06-19 21:10:18.861402

Filesystem              Size  Used Avail Use% Mounted on
jkt-pcap01:/data/pcap   9.1T  7.7T  1.4T  85% /mnt/pcap01
```

**Cara membaca hasil:**

- Paket tertua 2027-06-19 21:10:07 UTC, yaitu Minggu 2027-06-20 04:10:07 WIB. Pemeriksaan dijalankan Senin 08:00 WIB (01:00 UTC), dan file terbaru dibuat 00:59:46 UTC. Retensi nyata pagi ini sekitar 27 jam 50 menit, atau 27,8 jam.
- File tertua yang 1 GB itu hanya mencakup 11,86 detik (21:10:07,00 sampai 21:10:18,86). Itu laju tulis sekitar 84 MB per detik, sekitar 675 Mbps, padahal Minggu subuh kantor hampir kosong. Laju sebesar itu di jam itu adalah petunjuk pertama bahwa ada trafik non-kantor yang besar (bagian 2.2).
- Nomor urut 63871 sampai 72270 adalah tepat 8.400 file, sehingga ring sudah penuh dan sedang menimpa.
- Volume 85% terpakai dengan 1,4 TiB tersisa untuk OS dan ekstrak kasus. Ini bukan masalah disk; ring bekerja persis seperti dikonfigurasi.

Untuk pemantauan rutin, skrip kecil di `jkt-pcap01` menulis satu baris status setiap 15 menit ke syslog, yang diteruskan ke `index=netops`; saved search `JAB-PCAP-HEALTH-01` membacanya:

```
index=netops host=jkt-pcap01 "pcap_ring" earliest="05/10/2027:00:00:00" latest="06/21/2027:08:15:00"
| eval window_h=round((strptime(newest_pkt,"%Y-%m-%dT%H:%M:%SZ")-strptime(oldest_pkt,"%Y-%m-%dT%H:%M:%SZ"))/3600,1)
| where strftime(_time,"%a %H:%M")="Mon 08:00"
| table _time oldest_pkt newest_pkt files window_h
```

Penjelasan tiap bagian:

- `oldest_pkt` dan `newest_pkt` ditulis skrip dalam UTC dengan akhiran `Z`. Karena `window_h` adalah selisih dua waktu yang di-parse dengan format yang sama, zona waktu Splunk tidak memengaruhi hasilnya.
- `where strftime(...)="Mon 08:00"` mengambil satu titik per minggu, Senin 08:00 WIB, sebagai tren mingguan. Saved search alert-nya sendiri berjalan setiap 15 menit dengan `where window_h < 48`.

Keluaran ilustrasi:

```
_time             oldest_pkt            newest_pkt            files  window_h
05/10/2027 08:00  2027-05-06T13:10:41Z  2027-05-10T00:59:52Z  8400   83.8
05/17/2027 08:00  2027-05-13T11:02:15Z  2027-05-17T00:59:40Z  8400   86.0
05/24/2027 08:00  2027-05-20T14:00:09Z  2027-05-24T00:59:57Z  8400   83.0
05/31/2027 08:00  2027-05-27T12:01:33Z  2027-05-31T00:59:49Z  8400   85.0
06/07/2027 08:00  2027-06-03T15:00:20Z  2027-06-07T00:59:45Z  8400   82.0
06/14/2027 08:00  2027-06-10T15:59:30Z  2027-06-14T00:59:58Z  8400   81.0
06/21/2027 08:00  2027-06-19T21:10:07Z  2027-06-21T00:59:46Z  8400   27.8
```

**Cara membaca hasil:** enam minggu pertama berada di 81 sampai 86 jam, di atas target 72 jam, dan sedikit menurun dari minggu ke minggu (tren yang menurun adalah peringatan dini bahwa trafik tumbuh). Minggu ini jatuh ke 27,8 jam. Log alert menunjukkan jendela pertama kali di bawah 48 jam pada Sabtu 2027-06-19 sekitar 05:45 WIB, yaitu saat `SOC-2027-0685` dibuat. Angka yang dilaporkan ke Dimas adalah angka ini, bukan angka di dokumen kebijakan. Senin 05-10 cocok dengan pengamatan sekitar 84 jam yang dicatat waktu itu (Day 05).

**Variasi:** ganti `where` dengan `timechart span=1h min(window_h)` untuk melihat kapan tepatnya jendela mulai turun; gabungkan dengan `if_rx` dari baris status yang sama untuk melihat laju tulis per jam.

**Kapan meleset:** laju rata-rata bukan laju puncak. Hitung dengan laju puncak yang berkelanjutan, bukan rata-rata harian, atau retensi nyatamu akan jauh lebih pendek dari rencana. Pemeriksaan ini juga gagal bila skrip status mati diam-diam; tambahkan alert untuk ketiadaan baris `pcap_ring` lebih dari 30 menit.

Jadikan ini pemeriksaan rutin: catat usia berkas tertua setiap minggu dan buat grafiknya. Tren yang menurun adalah peringatan dini bahwa trafik tumbuh melampaui kapasitas.

### 2.2 Dari mana laju tulisnya: flow router DC dan router edge

Artefak kedua menjawab separuh kedua pertanyaan 1 (kenapa) dan sekaligus menjadi latihan membaca data bercuplik. Bambang membuka `jkt-flow01` untuk seed backup, yang lewat dua exporter: router data center tanpa sampling (alamat dalam `10.20.6.40`) dan router edge Jakarta dengan sampling 1:1000 (alamat sesudah NAT `198.51.100.218`).

**Tujuan:** mengukur volume seed sejak Jumat 18:00 sampai Senin 08:00 WIB dari dua sumber, dan membandingkan akurasinya.

```bash
# router data center, sampling 1:1, alamat dalam
nfdump -r /flow/dc-rtr/2027/06/ -N -s dstip/bytes -n 3 \
  'src ip 10.20.6.40 and first seen >= 2027-06-18T18:00:00 and last seen <= 2027-06-21T08:00:00'

# router edge Jakarta, sampling 1:1000, alamat sesudah NAT
nfdump -r /flow/jkt-edge/2027/06/ -N -s dstip/bytes -n 3 \
  'src ip 198.51.100.218 and first seen >= 2027-06-18T18:00:00 and last seen <= 2027-06-21T08:00:00'
```

| Bagian | Fungsi |
|---|---|
| `-r /flow/<router>/2027/06/` | Membaca semua file flow bulan itu untuk satu router (Day 10 bagian 2.1) |
| `-N` | Angka penuh, tanpa singkatan K/M/G |
| `-s dstip/bytes -n 3` | Tiga tujuan dengan byte terbanyak |
| `first seen >= ... and last seen <= ...` | Jendela absolut dalam WIB, jam `jkt-flow01` |

Keluaran ilustrasi:

```
# dc-rtr (1:1)
Dst IP Addr        Flows       Packets            Bytes
203.0.113.194       2991    11513989000   16718322841600
10.20.2.53            48            96            7104
10.20.0.21            12           744           98208

# jkt-edge (1:1000, sudah dikalikan rasio oleh nfcapd)
Dst IP Addr        Flows       Packets            Bytes
203.0.113.194       2988    11514327000   16719004200000
```

**Cara membaca hasil:**

- Router DC menghitung, bukan memperkirakan: 16.718.322.841.600 byte dalam 62 jam (223.200 detik), sekitar 74,9 MB per detik atau sekitar 599 Mbps. Itu batas 600 Mbps yang dipasang Agung, berjalan rata sepanjang akhir pekan. Ukuran paket rata-rata 1.452 byte, cocok dengan unggahan besar yang hampir semua paketnya penuh.
- Router edge memperkirakan 16.719.004.200.000 byte, selisih sekitar 0,004% dari hitungan router DC. Dengan sekitar 11,5 juta paket tersampel, galat relatif kira-kira 1 dibagi akar jumlah sampel, sekitar 0,03%, atau sekitar 0,06% pada keyakinan 95% (Day 10 bagian 1.3). Untuk volume sebesar ini, flow bercuplik sangat bisa dipercaya.
- Angka di edge selalu kelipatan 1.000 karena `nfcapd` sudah mengalikan counter dengan rasio sampling (Day 10 bagian 1.3).

Selalu tulis laju cuplikannya di samping setiap angka dari data bercuplik:

```
# volume sebenarnya diperkirakan dari cuplikan
perkiraan byte = byte tercuplik x laju cuplikan
```

Pagi yang sama, Sari bertanya kepada Bambang apakah flow edge bisa memastikan berapa kali `203.0.113.195` (tujuan unduhan `JKT-WS-2086`) dihubungi Jumat. Dua query untuk Jumat 14:00 sampai 15:00 WIB:

```bash
nfdump -r /flow/dc-rtr/2027/06/18/ -N -o long 'ip 203.0.113.195'
nfdump -r /flow/jkt-edge/2027/06/18/ -N -o long 'ip 203.0.113.195'
```

Keluaran ilustrasi (kolom diringkas, hanya arah dari server):

```
# dc-rtr (1:1)
Date first seen          Proto  Src IP Addr:Port       Dst IP Addr:Port      Packets    Bytes
2027-06-18 14:05:12.418  TCP    203.0.113.195:80   ->  10.20.3.60:51722          291   424620
2027-06-18 14:06:51.904  TCP    203.0.113.195:80   ->  10.20.3.60:51748            5     749
2027-06-18 14:31:05.227  TCP    203.0.113.195:80   ->  10.20.3.60:52906          290   424568

# jkt-edge (1:1000)
Date first seen          Proto  Src IP Addr:Port       Dst IP Addr:Port      Packets    Bytes
2027-06-18 14:31:05.611  TCP    203.0.113.195:80   ->  198.51.100.120:40873     1000  1500000
```

**Cara membaca hasil:** router DC melihat tiga koneksi dari `jkt-proxy01` ke `203.0.113.195`, dua unduhan sekitar 424 KB dan satu koneksi kecil. Router edge hanya punya satu record, dari satu paket 1.500 byte yang kebetulan terpilih, yang setelah dikalikan menjadi 1.000 paket dan 1.500.000 byte: lebih dari tiga kali ukuran unduhan sebenarnya. Peluang koneksi sekitar 290 paket terwakili minimal satu paket pada sampling 1:1000 adalah 1 - (1 - 1/1000)^290, sekitar 25%; untuk koneksi lima sampai delapan paket, di bawah 1%. Jadi edge "melihat satu koneksi" adalah kebetulan, dan edge "tidak melihat koneksi" tidak berarti apa-apa.

Tiga aturan penulisan laporan untuk data bercuplik:

- Sebutkan laju cuplikan setiap kali kamu menyebut angka volume, dan tulis angkanya sebagai perkiraan.
- Jangan pernah menulis kalimat yang menyatakan sesuatu tidak terjadi berdasarkan data bercuplik.
- Untuk pertanyaan tentang kejadian tunggal, nyatakan terus terang bahwa sumbernya tidak sesuai dan sebutkan sumber apa yang dibutuhkan.

Dua yang terakhir sering terasa seperti kelemahan, padahal justru itu yang membuat laporanmu bisa dipertanggungjawabkan.

**Variasi:** `-s srcip/bytes` di router DC tanpa filter host, jendela Jumat 18:00 sampai Senin 08:00, untuk memastikan tidak ada sumber besar lain selain `jkt-bkp01` yang ikut memotong retensi.

**Kapan gagal:** exporter tidak mengumumkan rasio sampling dan `nfcapd` tidak diberi `-s`, sehingga angka edge terlihat seribu kali lebih kecil (Day 10 bagian 1.3); atau filter `last seen <=` memotong flow yang masih aktif di batas jendela (dengan timeout aktif 300 detik, selisihnya paling banyak lima menit).

### 2.3 `INC-2027-077` tanpa pcap: apa yang masih dijawab metadata

Artefak ketiga menjawab pertanyaan 2. Pcap Jumat sudah tertimpa, tetapi `index=zeek` (90 hari) dan log proxy (30 hari) masih ada. Satu catatan lingkungan: `jkt-proxy01` tidak menyimpan cache objek, sehingga setiap unduhan lewat proxy menghasilkan koneksi keluar sendiri.

**Tujuan:** merekonstruksi unduhan dan kiriman Jumat dari log transaksi, lalu mencari host lain yang menerima file yang sama.

```
index=zeek sourcetype=bro:http:json earliest="06/18/2027:13:30:00" latest="06/18/2027:15:30:00"
    (host="dl.unduhcepat.example" OR id.resp_h=203.0.113.195 OR uri="http://203.0.113.195/*")
| table _time uid id.orig_h id.resp_h id.resp_p method host uri request_body_len response_body_len status_code
| sort _time
```

Penjelasan tiap bagian:

- Tiga syarat `OR` menangkap kedua hop: hop core (workstation ke `10.20.3.60:3128`, `uri` absolut karena proxy eksplisit) dan hop egress (proxy ke `203.0.113.195:80`, `uri` relatif). Satu unduhan lewat proxy adalah dua koneksi dengan `uid` berbeda (Day 08).
- `request_body_len` dan `response_body_len` adalah ukuran body tanpa header; isi body tidak disimpan Zeek.
- `sourcetype=bro:http:json` mengikuti pola sourcetype yang ditetapkan program (Day 08 bagian 1.9).

Keluaran ilustrasi:

```
_time                uid                 id.orig_h     id.resp_h      id.resp_p  method  uri                                               request_body_len  response_body_len  status_code
06/18/2027 14:05:12  CwT4p0aZ1nQe8YkLb   10.10.60.186  10.20.3.60     3128       GET     http://dl.unduhcepat.example/f/tagihan-0618.zip   0                 412380             200
06/18/2027 14:05:12  C8kHw2rVb5mJ0sTq1   10.20.3.60    203.0.113.195  80         GET     /f/tagihan-0618.zip                               0                 412380             200
06/18/2027 14:06:51  CnR7e1LdX4o9WbZ3k   10.10.60.186  10.20.3.60     3128       POST    http://203.0.113.195/g                            1204              37                 200
06/18/2027 14:06:51  CpB2y6QmT8hVa1Ue4   10.20.3.60    203.0.113.195  80         POST    /g                                                1204              37                 200
06/18/2027 14:31:05  CzL5s3NfR0gKc7DyP   10.10.60.188  10.20.3.60     3128       GET     http://dl.unduhcepat.example/f/tagihan-0618.zip   0                 412380             200
06/18/2027 14:31:05  CgV9d4HkW2pXe6JoA   10.20.3.60    203.0.113.195  80         GET     /f/tagihan-0618.zip                               0                 412380             200
```

Lalu file dan hash-nya:

```
index=zeek sourcetype=bro:files:json earliest="06/01/2027:00:00:00" latest="06/21/2027:09:15:00"
    sha256="9b2e*c41d"
| stats min(_time) AS pertama max(_time) AS terakhir count values(uid) AS uids
        values(mime_type) AS mime max(total_bytes) AS bytes max(missing_bytes) AS missing BY sha256
```

Keluaran ilustrasi:

```
sha256        pertama              terakhir             count  mime             bytes   missing
9b2e...c41d   06/18/2027 14:05:12  06/18/2027 14:31:05  4      application/zip  412380  0
```

**Cara membaca hasil:**

- Empat baris `files.log` untuk satu hash: dua hop untuk unduhan `JKT-WS-2086` pukul 14:05:12 dan dua hop untuk unduhan `JKT-WS-2088` (`10.10.60.188`, `hadi.susanto`, Customer Care) pukul 14:31:05. `missing_bytes` 0 berarti hash mewakili file utuh. Temuan host kedua dibuat sebagai `SOC-2027-0688` pukul 09:12.
- Log proxy untuk unduhan pertama mencatat 412.776 byte, 396 byte lebih besar daripada `response_body_len`, karena field `bytes` proxy menghitung header balasan (Day 12).
- Pukul 14:06:51, 99 detik setelah unduhan, `JKT-WS-2086` mengirim `POST` 1.204 byte ke alamat IP literal `203.0.113.195`, lalu menerima 37 byte. MDE menghentikan `wscript.exe` pukul 14:06:58 (dari timeline MDE), dan tidak ada koneksi lain ke alamat itu dari host mana pun sampai Senin pagi.
- MDE di `JKT-WS-2088` menunjukkan zip tersimpan di folder Downloads tetapi tidak pernah dibuka; MDE menghapusnya Senin pukul 09:31.

Yang tidak bisa dijawab: isi zip (skrip sudah dihapus MDE Jumat, dan pengambilan file dari host gagal karena file tidak ada lagi; salinan di `JKT-WS-2088` dihapus sebelum diambil, sebuah kesalahan prosedur kecil yang dicatat) dan isi 1.204 byte yang dikirim. Keduanya protokol polos, sehingga pcap Jumat akan memberikannya utuh lewat Export Objects dan Follow Stream (Day 02). Tanpa isi body, tidak bisa dipastikan apakah yang terkirim hanya informasi sistem atau juga data pribadi, sehingga Agus (DPO) menerima catatan bahwa dampak data belum bisa ditentukan.

Dimas membuka `INC-2027-077` pukul 09:40, dan `JKT-WS-2086` diisolasi lewat MDE pukul 09:46 sebagai langkah hati-hati.

Garis waktu kesempatan yang terlewat, untuk rapat Kamis; tabel ini ada supaya terlihat bahwa masalahnya prosedur, bukan alat:

| Waktu (WIB) | Kejadian | Paket Jumat 14:05 masih ada? |
|---|---|---|
| Jumat 14:07 | `SOC-2027-0686` dibuat MDE | Ya |
| Jumat 16:40 | Triage L1, tiket ditunda ke Senin tanpa case hold | Ya |
| Jumat 18:00 | Seed backup mulai, laju tulis naik ke sekitar 85 MB per detik | Ya |
| Sabtu 05:45 | `SOC-2027-0685`: jendela di bawah 48 jam, dicatat untuk Senin | Ya |
| Sabtu sekitar 19:05 | Data Jumat 14:05 tertimpa | Tidak |
| Senin 07:30 | Sari mencari pcap Jumat | Tidak |

Jam penimpaan dihitung dari volume: Jumat 14:05 sampai 18:00 sekitar 0,62 TB (35% dari 1 Gbps), Jumat 18:00 sampai 24:00 sekitar 1,94 TB (sekitar 90 MB per detik), lalu sisa 5,84 TB dari 8,4 TB terisi dalam sekitar 19,1 jam pada 85 MB per detik, yaitu Sabtu sekitar 19:05.

**Variasi:** stacking `files.log` per `sha256` untuk semua `application/zip` yang datang dari domain berumur kurang dari tujuh hari di hop egress, sebagai saved search baru.

**Kapan gagal:** hash kosong bila skrip hash file tidak dimuat; file di dalam HTTPS yang tidak di-bump tidak pernah masuk `files.log`; dan proxy yang meng-cache objek membuat unduhan kedua tidak terlihat di hop egress sama sekali.

### 2.4 Menghitung kebutuhan fase berikutnya

Artefak keempat menjawab pertanyaan 3. Hitungan kasar ini bisa kamu lakukan di awal rapat, memakai angka dari dokumentasi [S1]:

```
laju rata-rata (Gbps) x 11 TB per hari per Gbps x jumlah hari = kebutuhan pcap
kebutuhan pcap x 0,05 = perkiraan kasar disk metadata
```

Contoh umum untuk tautan 2 Gbps dengan target retensi paket 14 hari:

```
2 x 11 x 14      = 308 TB untuk pcap
308 x 0,05       = sekitar 15 TB untuk metadata
```

Lalu kurangi dengan kompresi dan dengan tidak menyimpan muatan TLS penuh [S1]. Yang penting dari latihan ini bukan ketepatan angkanya, melainkan bahwa semua orang di ruangan melihat ordenya sebelum menjanjikan retensi kepada siapa pun.

Untuk PT JAB, masukan dari Bambang adalah counter port keluar `jkt-npb01` setelah deduplikasi (egress Jakarta dan SPAN core switch data center), ditambah pengukuran dari `conn.log`. Tabel ini merangkum masukannya; cari baris laju desain, karena itu yang dipakai di hitungan.

| Masukan | Nilai | Sumber |
|---|---|---|
| Rata-rata 24 jam hari kerja Juni | 1,1 Gbps | Counter `jkt-npb01` |
| Laju desain: rata-rata 24 jam hari kerja tersibuk, termasuk backup harian setelah seed | 1,3 Gbps | Perkiraan Bambang dan Agung |
| Puncak satu jam | 2,3 Gbps | Counter `jkt-npb01` (Day 08 bagian 1.8) |
| Porsi byte TLS dan QUIC | 78% | `conn.log`, `service` ssl dan quic, satu minggu |
| Retensi paket yang diminta | 7 hari | Dimas |

Hitungan paket untuk Arkime egress dan core DC, tujuh hari:

```
pcap mentah per hari          1,3 x 11            = 14,3 TB
tujuh hari, tanpa pengurangan 14,3 x 7            = 100,1 TB
batas atas (2,3 Gbps terus)   2,3 x 11 x 7        = 177,1 TB
setelah muatan TLS dipangkas  100,1 x 0,26        =  26,0 TB
  (asumsi 26% tersisa: 22% non-TLS + sekitar 4% handshake dan sesi TLS pendek)
cadangan 30%                  26,0 x 1,3          =  33,8 TB
ruang freeSpaceG 5%           33,8 / 0,95         =  35,6 TB usable minimal
contoh perangkat              12 disk 4 TB RAID 6 =  40 TB usable
```

Hitungan metadata (SPI data) memakai volume sebelum pemangkasan, karena jumlah sesi tidak berkurang ketika muatan TLS tidak disimpan:

```
SPI 14 hari, 0 replika   0,05 x 14,3 x 14 = 10,0 TB  -> heap minimal 1% = 100 GB -> 4 node x 30 GB
SPI 14 hari, 1 replika   10,0 x 2         = 20,0 TB  -> heap 200 GB             -> 7 node
SPI 30 hari, 0 replika   0,05 x 14,3 x 30 = 21,5 TB  -> heap 215 GB             -> 8 node
SPI 90 hari, 0 replika   0,05 x 14,3 x 90 = 64,4 TB  -> heap 644 GB             -> 22 node
setiap node: minimal 30 GB memori mesin pencarian + 30 GB cache disk
```

**Cara membaca hasil:**

- Pemangkasan TLS adalah tuas terbesar: dari sekitar 100 TB menjadi sekitar 26 TB untuk tujuh hari. Tanpa itu, fase berikutnya butuh tiga kali lipat disk.
- Metadata panjang di Arkime ternyata komponen termahal. SPI 90 hari butuh sekitar 22 node mesin pencarian, padahal PT JAB sudah menyimpan metadata 90 hari di Splunk lewat Zeek. SPI 14 hari dengan empat node cukup untuk tugas Arkime yang sebenarnya: menemukan paket dengan cepat selama paketnya masih ada.
- Batas atas 177,1 TB ada di tabel supaya semua orang tahu dari mana angka desain berasal. Mendesain dengan 2,3 Gbps sepanjang hari terlalu mahal; mendesain dengan 1,1 Gbps mengulang kejadian minggu ini. Laju desain 1,3 Gbps ditambah cadangan 30%, plus pemantauan retensi nyata (bagian 2.1), adalah kompromi yang bisa dipertahankan.
- Faktor 0,26 adalah asumsi terbesar di hitungan ini. Ukur di pilot: bandingkan byte yang ditulis Arkime sebelum dan sesudah rule TLS aktif (bagian 2.6).

**Variasi:** hitung opsi yang jauh lebih murah untuk core DC: Suricata `pcap-log` dengan `conditional: alerts` di `jkt-ids01` (bagian 2.8) ditambah perekaman sesuai permintaan, tanpa Arkime. Kebutuhan disknya ditentukan oleh `limit` dan `max-files`, bukan oleh laju trafik.

**Kapan meleset:** laju rata-rata bukan laju puncak; replikasi diaktifkan belakangan tanpa menghitung ulang disk; atau kompresi dianggap bonus padahal belum diukur. Kompresi sebaiknya dihitung sebagai cadangan, bukan sebagai pengurang di depan.

### 2.5 Memotong, menyaring, atau mencuplik: tiga usulan Agung

Artefak kelima menjawab pertanyaan 4 dengan menghitung akibat tiap usulan pada `jkt-pcap01` dan pada kasus nyata minggu ini. Dua pengaturan yang punya dampak terbesar pada kebutuhan disk, dan keduanya punya biaya analisis, terlihat seperti ini di konfigurasi Arkime [S5]:

```
# memotong: hanya simpan N byte pertama tiap paket
# akibat: header tetap ada, muatan hilang
snapLen = 16384         # bawaan Arkime; dumpcap dan tcpdump bawaan 262144 (praktis penuh)
snapLen = 96            # cukup untuk header, bukan untuk isi
```

```
# menyaring saat capture, mirip BPF di tcpdump
bpf = not (host 10.20.70.16 and port 9200)
```

Filter kedua relevan untuk fase core DC: lalu lintas antara node capture dan node OpenSearch `jkt-os01` lewat core switch, sehingga tanpa filter itu sensor merekam metadata yang sedang ia kirim sendiri.

Yang perlu dicatat setiap kali kamu mengubah salah satunya:

| Yang diubah | Yang masih bisa dijawab | Yang tidak bisa lagi |
|---|---|---|
| snaplen kecil | Siapa bicara ke siapa, kapan, berapa banyak | Isi, rekonstruksi berkas, sebagian analisis protokol |
| filter BPF | Semua di luar yang disaring | Apa pun tentang trafik yang disaring, termasuk bahwa ia ada |
| tanpa muatan TLS | Metadata handshake, SNI bila ada | Tidak banyak yang hilang, karena isinya memang terenkripsi |

Baris ketiga adalah pilihan dengan rasio terbaik, dan itu yang sebaiknya dilakukan lebih dulu sebelum menurunkan snaplen atau menambah filter [S1]. Di `jkt-pcap01`, dumpcap tidak mengenali sesi, sehingga pilihan itu tidak tersedia; yang tersedia hanya capture filter dan snaplen [S10].

**Usulan 1, menyaring trafik backup.** Perintah ring yang sudah berjalan ditambah capture filter sempit:

```bash
sudo dumpcap -i ens2f0 -B 1024 \
  -f "not (host 10.20.6.40 and host 203.0.113.194 and tcp port 443)" \
  -b filesize:1000000 -b duration:900 -b files:8400 \
  -w /data/pcap/ring/egress-jkt.pcapng
```

| Bagian | Fungsi |
|---|---|
| `-f "not (...)"` | Capture filter BPF; ketiga syarat harus cocok sekaligus, sehingga hanya sesi backup yang dibuang [S10] |
| `host 10.20.6.40` | Alamat dalam `jkt-bkp01`; TAP di sisi dalam `jkt-fw01` melihat alamat sebelum NAT `198.51.100.218` |
| `-B 1024` | Buffer capture 1024 MiB [S10] |
| `-b filesize:1000000 -b duration:900 -b files:8400` | Ganti file pada sekitar 1 GB atau 900 detik, mana yang lebih dulu, dan putar 8.400 file [S10] |

Hitungannya: tanpa backup, hari kerja menulis sekitar 2,376 TB per hari (22% dari 1 Gbps), sehingga jendela sekitar 84,8 jam. Backup harian setelah seed direncanakan tiga jam per malam pada 600 Mbps, sekitar 0,81 TB; tanpa filter, total 3,186 TB per hari memberi sekitar 63,3 jam, di bawah target 72 jam. Dengan filter, jendela kembali sekitar 85 jam.

Yang hilang perlu disebut terang-terangan. `objek.awanarsip.example` adalah layanan penyimpanan objek yang dipakai banyak pelanggannya sekaligus, jadi alamat `203.0.113.194` bukan milik PT JAB saja. Penyerang yang menguasai `jkt-bkp01` dan mengunggah ke bucket miliknya sendiri di layanan yang sama akan lolos dari pcap. Yang menutup celah itu: Zeek dan Suricata tetap menerima trafik backup karena `jkt-npb01` memberi salinan terpisah untuk tiap sensor, sehingga `conn.log` dan `ssl.log` tetap mencatat setiap sesi; volume per malam dipantau dari flow router DC (pola saved search volume keluar per host dan tujuan di Day 12 bagian 2.1 dipakai juga untuk `jkt-bkp01`, dengan ambang sendiri); dan isi sesi itu TLS, sehingga pcap-nya memang tidak menambah isi. Filter ini masuk register (bagian 2.9).

**Usulan 2, memotong semua paket menjadi header saja.** Dengan rata-rata ukuran paket egress hari kerja sekitar 900 byte (dari `capinfos` file Kamis pukul 10:00) dan asumsi overhead per paket sekitar 32 byte di format pcapng, snaplen 128 menyimpan sekitar (128 + 32) / (900 + 32), kira-kira 17% dari volume, sehingga jendela menjadi hampir enam kali lebih panjang. Harganya: 128 byte habis untuk header Ethernet, IP, dan TCP, ditambah sekitar 60 byte awal HTTP. Pada kasus `JKT-WS-2086`, zip tidak bisa direkonstruksi dan isi `POST` 1.204 byte hilang, padahal dua hal itulah satu-satunya alasan pcap Jumat dicari. Snaplen kecil masuk akal untuk segmen yang hampir seluruhnya terenkripsi, bukan untuk egress yang masih membawa HTTP polos.

**Usulan 3, mencuplik satu dari sepuluh paket.** Dumpcap tidak menyediakan sampling paket; usulan Agung adalah memasangnya di port `jkt-npb01` ke `jkt-pcap01`, dan ada tidaknya fitur itu perlu dicek di dokumentasi perangkatnya. Hitungannya cukup untuk menolak usulan ini:

```
unduhan 290 paket, cuplik 1:10    harapan tersimpan 29 paket; peluang semua tersimpan 0,1^290 (praktis nol)
POST 8 paket, cuplik 1:10         peluang minimal satu paket tersimpan 1 - 0,9^8 = sekitar 57%
```

Stream TCP dengan 90% segmen hilang tidak bisa dirakit ulang, sehingga Follow Stream dan Export Objects tidak menghasilkan apa-apa. Untuk kejadian tunggal, sampling paket memberi pcap yang tampak ada tetapi tidak berguna, dan itu lebih berbahaya daripada tidak ada sama sekali, karena orang mengira buktinya tersedia.

**Keputusan yang diusulkan:** terapkan usulan 1 dengan filter sempit dan entri register; tolak usulan 2 untuk egress; tolak usulan 3. Pemangkasan muatan TLS per sesi menunggu jalur Arkime.

**Kapan gagal:** mengganti capture filter butuh restart dumpcap, yang membuat jendela buta beberapa detik; umumkan seperti deploy Zeek (Day 08 bagian 1.8). Filter yang ditulis dengan satu `host` saja (`not host 203.0.113.194`) membuang semua trafik ke layanan itu dari host mana pun, termasuk unggahan oleh penyerang dari workstation.

### 2.6 Pilot Arkime: memeriksa pcap, metadata, dan memasang rule TLS

Artefak keenam menjawab pertanyaan 5. Pilot `jkt-arkime01` berjalan sejak Senin 2027-06-07 dengan konfigurasi hampir bawaan: `pcapDir=/data/arkime/raw` di volume 20 TB tersendiri, `maxFileSizeG=12`, `freeSpaceG=5%`, `simpleCompression=none` supaya ukuran mentah bisa diukur, tanpa rule, dan OpenSearch di host terpisah `jkt-os01` dengan disk data 2 TB. Syarat sistem berkas terpisah sudah terpenuhi karena host-nya berbeda [S1].

**Tujuan:** memeriksa retensi pcap nyata, memastikan kedaluwarsa metadata berjalan, dan mengukur efek rule TLS.

Langkah pertama, retensi nyata pcap di node capture (jam sistem UTC):

```bash
# berkas pcap tertua yang masih ada
ls -lt /data/arkime/raw/ | tail -3

# ruang kosong, yang menentukan kapan penghapusan dimulai
df -h /data/arkime/raw
```

Keluaran ilustrasi:

```
-rw-r----- 1 arkime arkime 12G Jun 18 11:04 jkt-arkime01-270618-00003391.pcap
-rw-r----- 1 arkime arkime 12G Jun 18 11:00 jkt-arkime01-270618-00003390.pcap
-rw-r----- 1 arkime arkime 12G Jun 18 10:55 jkt-arkime01-270618-00003389.pcap

Filesystem      Size  Used Avail Use% Mounted on
/dev/sdb1        19T   18T  932G  95% /data/arkime/raw
```

**Cara membaca hasil:** pemakaian 95 persen berarti sistem berada tepat di ambang bawaan `freeSpaceG` 5 persen, sehingga penghapusan berkas tertua sedang berjalan terus-menerus [S1]. Berkas tertua ditutup Jumat 10:55 UTC, yaitu 17:55 WIB; retensi nyata pilot sekitar 62 jam. Volume yang lebih besar memberi jendela lebih panjang daripada `jkt-pcap01`, tetapi tetap kehilangan Jumat 14:05, karena seed backup ikut disimpan penuh. Berkas tertua yang ada memberi tahu retensi nyatamu hari ini, dan angka itulah yang harus dilaporkan, bukan angka di dokumen kebijakan.

Langkah kedua, metadata:

```bash
# daftar indeks sesi beserta ukurannya
curl -s "http://10.20.70.16:9200/_cat/indices/arkime_sessions3*?v&s=index&h=health,status,index,docs.count,store.size"

# pemakaian disk per node
curl -s "http://10.20.70.16:9200/_cat/allocation?v"
```

Keluaran ilustrasi:

```
health status index                    docs.count store.size
green  open   arkime_sessions3-270607    46118204    131.2gb
green  open   arkime_sessions3-270608    48902551    139.0gb
...
green  open   arkime_sessions3-270620    13407992     38.6gb
green  open   arkime_sessions3-270621     9880417     28.1gb

shards disk.indices disk.used disk.avail disk.total disk.percent host        node
    23        1.4tb     1.4tb      410gb      1.8tb           78 10.20.70.16 jkt-os01
```

**Cara membaca hasil:** indeks tertua yang masih ada menunjukkan retensi metadata nyata. Lima belas indeks harian, 2027-06-07 sampai hari ini, tidak satu pun dihapus: tidak ada kedaluwarsa yang berjalan [S1]. Disk node sudah 78% setelah dua minggu, dan hari kerja menambah sekitar 130 sampai 140 GB, sehingga disk penuh dalam beberapa hari kerja. Bila indeks dari enam bulan lalu masih ada padahal kebijakanmu 90 hari, berarti kedaluwarsa tidak berjalan; periksa kebijakan siklus hidup indeks atau cron kedaluwarsanya. Nama indeks di atas memakai prefiks `arkime_` dan rotasi harian; nama persisnya bergantung pada pengaturan prefiks dan rotasi di versi-mu, jadi selalu mulai dari `_cat/indices`.

Perbaikan metadata, mengikuti pola contoh resmi [S1]:

```bash
# crontab pengguna arkime di jkt-arkime01, setiap hari 00:30 UTC
30 0 * * * /opt/arkime/db/db.pl http://10.20.70.16:9200 expire daily 14
```

Argumen `daily` mengikuti rotasi indeks harian, dan `14` adalah jumlah indeks yang disimpan. Alternatifnya kebijakan ISM di OpenSearch; bila ISM dipakai, cron kedaluwarsa tidak diperlukan, tetapi `db.pl optimize-admin` sebaiknya dijalankan sesekali [S1]. Setelah cron pertama berjalan, jalankan ulang `_cat/indices` dan pastikan indeks 270607 hilang. Konfigurasi yang terlihat benar tidak membuktikan apa pun; indeks yang hilang membuktikannya.

Langkah ketiga, rule TLS. Rule Arkime ditulis di berkas YAML yang dirujuk `rulesFiles=` di `config.ini`, dibaca ulang otomatis saat berubah, dan tiap rule butuh `name`, `when`, `ops`, serta salah satu dari `fields`, `bpf`, atau `expression` [S7]:

```yaml
# /opt/arkime/etc/jab-rules.yaml, dirujuk rulesFiles=/opt/arkime/etc/jab-rules.yaml
---
version: 1
rules:
  - name: "JAB batasi paket TLS dan QUIC"
    when: "fieldSet"
    fields:
      protocols:
        - tls
        - quic
    ops:
      _maxPacketsToSave: 20
```

| Bagian | Fungsi |
|---|---|
| `when: "fieldSet"` | Diperiksa setiap kali sebuah field diisi, pilihan yang paling umum [S7] |
| `fields: protocols: [tls, quic]` | Berlaku untuk sesi yang dikenali sebagai TLS atau QUIC, apa pun port-nya |
| `_maxPacketsToSave: 20` | Simpan sekitar 20 paket pertama sesi (handshake), lalu berhenti; capture bisa sesekali menyimpan beberapa paket lebih [S7] |

Rule ini berbeda dari `dontSaveBPFs=tcp port 443:20`, yang juga menyimpan 20 paket pertama tetapi berdasarkan port, sehingga melewatkan TLS di port lain dan ikut memangkas trafik non-TLS di port 443 [S5]. Metadata sesi yang dipangkas tetap lengkap; yang tidak disimpan hanya paketnya [S1].

**Cara mengukur efeknya:** catat laju tulis di `/data/arkime/raw` selama 24 jam sebelum dan sesudah rule aktif, lalu bandingkan. Angka itu menggantikan asumsi 0,26 di bagian 2.4. Satu hal yang tidak boleh dilupakan saat menguji: rekaman sesi ditulis ketika sesi berakhir, sehingga sesi baru bisa butuh beberapa menit untuk muncul [S1]. Sesi panjang (unggahan backup berjam-jam) ditulis berkala setiap `maxPackets` paket, bawaannya 10.000 [S5].

**Variasi:** tambahkan rule kedua dengan `_dontSaveSPI: 1` untuk sesi yang metadatanya pun tidak berguna, misalnya health check internal berfrekuensi tinggi; atau `_dropByDst` untuk tujuan yang alamatnya berganti-ganti seperti layanan cloud [S7]. Keduanya membuang data, jadi masuk register.

**Kapan gagal:** kedaluwarsa dipasang tetapi tidak pernah dijalankan karena kesalahan jadwal atau izin. Pemeriksaan `_cat/indices` menangkapnya; konfigurasi yang terlihat benar tidak menangkapnya. Rule TLS juga tidak menolong bila klasifikasi protokol gagal, misalnya pada versi QUIC yang tidak dikenali (Day 16).

### 2.7 Drop di `jkt-pcap01`: `SOC-2027-0687`

Artefak ketujuh menjawab pertanyaan 6. Baris status `pcap_ring` yang sama di `index=netops` juga memuat counter antarmuka capture `ens2f0` (`if_rx` dan `if_drop`, kumulatif, dibaca skrip dari statistik antarmuka); alert `SOC-2027-0687` berbunyi bila drop dalam satu jendela 15 menit di atas 0,5%.

**Tujuan:** mengukur drop per jendela, memastikan di mata rantai mana ia terjadi, dan menemukan penyebabnya.

```
index=netops host=jkt-pcap01 "pcap_ring" earliest="06/21/2027:07:15:00" latest="06/21/2027:08:20:00"
| sort _time
| streamstats current=f last(if_rx) AS rx0 last(if_drop) AS d0
| eval rx=if_rx-rx0, drop=if_drop-d0, drop_pct=round(drop/rx*100,2)
| where isnotnull(rx0)
| table _time rx drop drop_pct

index=zeek sourcetype=bro:capture_loss:json earliest="06/21/2027:07:15:00" latest="06/21/2027:08:20:00"
| stats max(percent_lost) AS maks_persen BY peer
```

Penjelasan tiap bagian:

- `streamstats current=f last(...)` mengambil nilai counter dari baris sebelumnya, sehingga `rx` dan `drop` adalah selisih per 15 menit. Counter kumulatif kembali ke nol saat sensor restart; selisih negatif berarti ada restart di jendela itu.
- Query kedua adalah pembanding dari sensor lain yang menerima salinan yang sama dari `jkt-npb01` (Day 08 bagian 2.10).

Keluaran ilustrasi:

```
_time             rx        drop    drop_pct
06/21/2027 07:45  87500000  157505  0.18
06/21/2027 08:00  87500000  787523  0.90
06/21/2027 08:15  88100000  105003  0.12

peer        maks_persen
worker-1-1  0.02
...         (10 worker, semua di bawah 0.03)
```

**Cara membaca hasil:**

- Laju sekitar 87,5 juta paket per 15 menit adalah sekitar 97 ribu paket per detik, cocok dengan sekitar 700 Mbps (seed 600 Mbps ditambah kantor yang mulai ramai). Link jauh dari penuh.
- Total drop 07:42 sampai 08:02 sekitar 1,05 juta dari sekitar 116,7 juta paket, 0,90%. Zeek di jendela yang sama tidak melewati 0,03%, sehingga TAP dan `jkt-npb01` mengirim lengkap; masalahnya di `jkt-pcap01`.
- Waktunya persis jendela pemindaian Sari: delapan proses `tshark` paralel membaca seluruh ring lewat mount `/mnt/pcap01` untuk mencari `203.0.113.195`. Agung membaca `iostat -x` di sensor: utilisasi array 100% dan waktu tunggu penulisan naik dari beberapa milidetik ke ratusan milidetik. Penulisan tertunda, buffer capture 1024 MiB (sekitar 12 detik pada 87,5 MB per detik) penuh, dan kernel mulai membuang paket.

Jawaban untuk Bambang: link dan router memang bersih; drop terjadi di dalam sensor karena disk yang ditulis ring juga sedang dibaca habis-habisan. Yang ditulis di tiket: "07:42 sampai 08:02 WIB, `jkt-pcap01` kehilangan sekitar 0,9% paket karena pemindaian ring penuh dari `jkt-nsm-ws01`; Zeek dan Suricata tidak terdampak; ketiadaan paket di pcap untuk jendela itu tidak membuktikan ketiadaan trafik."

Tindak lanjutnya tiga. Pertama, pemindaian ring penuh dilarang; urutan kerjanya selalu metadata dulu (Zeek memberi waktu dan `uid`), lalu potong hanya file yang mencakup waktu itu, berurutan, bukan paralel (bagian 2.8). Kedua, buffer capture dinaikkan ke 4096 MiB sebagai bantalan, dengan catatan bahwa sistem bisa diam-diam membatasi nilainya [S10]. Ketiga, inilah alasan teknis terkuat untuk Arkime: indeks sesi menunjuk langsung ke berkas dan posisi paket, sehingga pencarian satu alamat tidak membaca 8,4 TB.

**Variasi:** tambahkan `ethtool -S ens2f0` ke skrip status untuk memisahkan drop di NIC dari drop di kernel, dan counter port keluar `jkt-npb01` ke `jkt-pcap01` untuk mata rantai sebelumnya.

**Kapan gagal:** counter antarmuka hanya melihat paket yang sampai ke NIC sensor; paket yang dibuang port SPAN atau `jkt-npb01` harus dibaca di perangkat itu. `capture_loss.log` hanya menilai TCP [S12], sehingga kehilangan pada UDP tidak terlihat di pembanding.

### 2.8 Mengunci pcap dan perekaman sesuai permintaan

Artefak kedelapan menjawab pertanyaan 7. Kerangka prosedurnya disiapkan sebelum dibutuhkan, karena saat dibutuhkan tidak akan ada waktu menyusunnya:

```
1. Segmen mana yang bisa direkam penuh, dan siapa yang berwenang menyalakannya
2. Perintah persis yang dijalankan, termasuk tujuan penyimpanan dan rotasinya
3. Batas waktu dan batas ukuran, supaya tidak memenuhi disk produksi
4. Cara memverifikasi perekaman benar-benar berjalan dan menangkap yang diharapkan
5. Siapa yang memegang hasilnya dan bagaimana rantai penyimpanannya dicatat (Day 01)
6. Kapan perekaman dimatikan dan siapa yang memutuskan
```

Butir keempat yang paling sering dilewat. Perekaman yang menyala tetapi melihat segmen yang salah adalah kegagalan yang baru ketahuan setelah insiden selesai. Verifikasi dengan menghasilkan trafik yang kamu kendalikan sendiri, lalu memastikan ia muncul.

**Bagian A, case hold.** Aturan baru: setiap tiket dengan indikator jaringan (alamat, domain, atau host dengan waktu kejadian) dikunci dalam 30 menit oleh petugas jaga, tanpa menunggu L2. Contoh berikut adalah yang seharusnya dijalankan untuk `SOC-2027-0686` Jumat sekitar 14:15, untuk jendela 13:50 sampai 14:20 WIB (06:50 sampai 07:20 UTC):

```bash
T=SOC-2027-0686
mkdir -p /cases/$T/carve
ls /mnt/pcap01/ring/egress-jkt_*.pcapng \
  | awk -F_ '{ts=substr($NF,1,14)} ts>="20270618064900" && ts<"20270618072000"' \
  > /cases/$T/files.txt
wc -l < /cases/$T/files.txt

while read f; do
  tshark -n -r "$f" \
    -Y 'ip.addr == 203.0.113.195 && frame.time >= "2027-06-18T06:50:00Z" && frame.time < "2027-06-18T07:20:00Z"' \
    -w "/cases/$T/carve/$(basename "$f")"
done < /cases/$T/files.txt

mergecap -w /cases/$T/${T}_203.0.113.195_0650Z-0720Z.pcapng /cases/$T/carve/*.pcapng
sha256sum /cases/$T/${T}_*.pcapng > /cases/$T/SHA256SUMS
```

| Bagian | Fungsi |
|---|---|
| `awk ... ts>="20270618064900"` | Memilih file dari jam di nama file, satu menit sebelum jendela supaya file yang sedang berjalan ikut (Day 02 bagian 2.1) |
| `ip.addr == 203.0.113.195` | Di hop egress, sumber unduhan adalah proxy, jadi yang dikunci adalah tujuan; workstation dicocokkan lewat log proxy dan Zeek |
| `frame.time >= "...Z"` | Batas waktu dengan zona eksplisit |
| `while read` berurutan | Satu file sekali baca, tidak paralel, supaya tidak bersaing dengan penulisan ring (bagian 2.7) |
| `sha256sum` | Hash ekstrak kasus untuk rantai penyimpanan |

Keluaran ilustrasi: `files.txt` berisi 80 file (30 menit pada sekitar 43,75 MB per detik adalah sekitar 79 GB, ditambah satu file awal), dan ekstrak kasus sekitar 1 MB. Pembacaan 80 file berurutan selesai dalam hitungan menit, jauh di bawah 19 jam yang tersisa sebelum data itu tertimpa.

**Bagian B, perekaman sesuai permintaan.** Senin 10:15, setelah `INC-2027-077` dibuka, Dimas menyetujui capture tambahan untuk semua trafik ke dan dari `203.0.113.195` selama 72 jam. Yang menjalankan adalah tim Agung di sensor, karena analyst tidak punya akses tulis ke `jkt-pcap01`:

```bash
sudo mkdir -p /data/pcap/hold/INC-2027-077
sudo dumpcap -i ens2f0 -B 256 -f "host 203.0.113.195" \
  -b duration:3600 -b files:72 -a duration:259200 \
  -w /data/pcap/hold/INC-2027-077/hold-195.pcapng
```

| Bagian | Fungsi |
|---|---|
| `-f "host 203.0.113.195"` | Hanya trafik ke dan dari alamat itu, dari host mana pun; tidak menarget satu karyawan |
| `-b duration:3600 -b files:72` | File per jam, maksimal 72 file [S10] |
| `-a duration:259200` | Berhenti otomatis setelah 72 jam [S10] |
| `/data/pcap/hold/` | Di luar direktori ring, sehingga tidak ditimpa dumpcap ring |

Verifikasi pukul 10:17: dari `JKT-WS-2085` (`10.10.60.185`), workstation uji SOC, dikirim satu SYN langsung ke `203.0.113.195:443` tanpa proxy. Firewall menolaknya, sehingga tidak ada koneksi yang terbentuk, tetapi TAP di sisi dalam `jkt-fw01` melihat paket itu (Day 16 bagian 1.3 memakai sifat yang sama). Pukul 10:18, `tshark -r` atas file hold yang sedang ditulis menampilkan satu SYN dari `10.10.60.185`; peringatan file terpotong di akhir wajar karena file belum ditutup. Hasilnya dicatat di tiket bersama jam mulai, jam berhenti otomatis, dan nama penanggung jawab. Kamis pagi, Dimas memutuskan apakah perekaman diperpanjang.

**Bagian C, conditional pcap untuk core DC.** Untuk fase Juli, usulan termurah adalah membiarkan `jkt-ids01` menyimpan paket dari flow yang memicu alert [S11]:

```yaml
outputs:
  - pcap-log:
      enabled: yes
      filename: alert-%n-%t.pcap
      limit: 1000
      max-files: 300
      mode: multi
      conditional: alerts
      compression: lz4
```

| Bagian | Fungsi |
|---|---|
| `mode: multi` dan `%n`, `%t` | Satu file per thread, nama memuat nomor thread dan timestamp; lebih cepat daripada `normal` [S11] |
| `limit: 1000` dan `max-files: 300` | Ukuran file dalam MB dan jumlah file; keduanya berlaku per thread [S11] |
| `conditional: alerts` | Hanya flow yang memicu alert yang disimpan [S11] |
| `compression: lz4` | Kompresi sebelum ditulis [S11] |

Dengan 16 thread capture di `jkt-ids01` (Day 09 bagian 2.12), batas totalnya 16 x 300 x 1000 MB, sekitar 4,8 juta MB atau sekitar 4,6 TiB bila MB berarti MiB. Angka per thread inilah yang sering mengejutkan: konfigurasi yang tampak "300 file" sebenarnya 4.800 file. Rule ET yang berisik harus sudah di-tuning (Day 09 bagian 2.10) sebelum ini dinyalakan, karena setiap alert palsu kini juga menghabiskan disk.

**Kapan gagal:** case hold yang menunggu L2 sama saja dengan tidak ada case hold; perekaman tambahan yang tidak diverifikasi bisa merekam antarmuka yang salah selama tiga hari; dan conditional pcap tidak pernah menyimpan kejadian yang tidak memicu alert, seperti unduhan zip Jumat.

### 2.9 Kebijakan retensi NSM v0.2 dan register filter

Artefak kesembilan menjawab pertanyaan 8. Draf ini adalah lampiran untuk kebijakan akses v0.1 (Day 01 bagian 2.8) dan disusun dari daftar di bagian 1.8.

```
LAMPIRAN RETENSI, KEBIJAKAN AKSES DATA NSM PT JAB (DRAF v0.2, 2027-06-23)
Pemilik      : Dimas Prasetyo (SOC lead). Reviewer: Nina Kartika (Risiko dan Kepatuhan TI),
               Agus Setiawan (DPO), Ratna Sari (Legal)

Yang direkam : Paket penuh: egress Jakarta (jkt-pcap01). Core DC: tanpa paket penuh (fase Juli
               dievaluasi: conditional pcap jkt-ids01). Metadata: Zeek egress + core DC.
               Tidak direkam: switch akses kantor, kantor cabang, trafik pelanggan.
Retensi      : Paket ring jkt-pcap01  target minimal 72 jam, maksimal 7 hari; diukur tiap 15 menit
                                      (JAB-PCAP-HEALTH-01); alarm bila < 48 jam.
               Metadata index zeek   90 hari. Alert index suricata 90 hari. eve-proto di sensor 7 hari.
               Pilot Arkime          pcap mengikuti kapasitas (freeSpaceG 5%); SPI 14 hari (cron expire).
               Ekstrak kasus         sampai kasus ditutup + masa simpan dari Legal; nomor tiket + SHA-256.
Disk penuh   : Ring menimpa file tertua tanpa peringatan. Retensi nyata dilaporkan mingguan
               (usia paket tertua, Senin 08:00). Perubahan trafik besar terencana (backup, migrasi)
               wajib lewat SOC sebelum change disetujui.
Filter       : Hanya yang tercatat di register filter, dengan pemilik dan tanggal tinjau.
               Snaplen dan sampling paket tidak dipakai di egress.
Case hold    : Wajib dalam 30 menit untuk tiket dengan indikator jaringan, oleh petugas jaga.
Perekaman    : Atas tiket, disetujui SOC lead, dijalankan admin sensor, berbatas waktu dan ukuran,
tambahan       diverifikasi dengan trafik uji. Target satu karyawan: perlu SOC lead, DPO, dan Legal.
Akses        : Sesuai v0.1. Pemindaian ring penuh tidak diizinkan; cari lewat metadata dulu.
Tinjauan     : Akhir percobaan (Juli 2027), dan setiap kali retensi nyata < 48 jam lebih dari 24 jam.
```

Register filter dimulai dengan satu entri. Tabelnya ada supaya pertanyaan "kenapa trafik ini tidak ada di pcap" enam bulan lagi punya jawaban tertulis; kolom tanggal tinjau adalah yang paling penting.

| ID | Sensor | Filter | Alasan | Yang masih merekam | Pemilik | Berlaku | Tinjau |
|---|---|---|---|---|---|---|---|
| `NSM-FLT-001` | `jkt-pcap01` | `not (host 10.20.6.40 and host 203.0.113.194 and tcp port 443)` | Backup offsite TLS sekitar 0,81 TB per malam; muatan tidak terbaca | Zeek, Suricata, flow router DC | Agung Prabowo | 2027-06-22 | 2027-09-22 |

**Cara membaca dokumen ini:** baris Retensi menulis target dan cara mengukurnya, bukan jaminan; baris Disk penuh menjawab pertanyaan yang paling sering dihindari; batas maksimal tujuh hari untuk paket adalah jawaban untuk DPO bahwa isi tidak disimpan lebih lama dari kebutuhan investigasi.

**Kapan gagal:** kebijakan dibuat tetapi angka retensinya tidak pernah dibandingkan dengan pengukuran; atau register filter ada tetapi filter ditambahkan langsung di sensor tanpa entri.

### 2.10 Jawaban untuk Dimas, Bambang, dan Agung

Ringkasan yang dibawa ke rapat jam 14:00, satu baris per pertanyaan; kolom kanan menunjuk bagian yang menjadi dasarnya.

| Pertanyaan | Jawaban singkat | Bagian |
|---|---|---|
| 1. Kenapa 72 jam jadi sehari | Ring berbasis ukuran; seed backup sekitar 600 Mbps menaikkan laju tulis akhir pekan ke sekitar 85 MB per detik, jendela 27,8 jam. Enam minggu sebelumnya 81 sampai 86 jam | 1.1, 2.1, 2.2 |
| 2. Kasus Maya tanpa pcap | Metadata menjawab siapa, kapan, URL, ukuran, hash, dan host kedua (`JKT-WS-2088`); isi zip dan isi `POST` 1.204 byte hilang. `INC-2027-077` dibuka | 1.2, 2.3 |
| 3. Disk core DC tujuh hari | Sekitar 100 TB mentah, sekitar 26 TB setelah muatan TLS dipangkas, sekitar 36 TB usable dengan cadangan; SPI 14 hari butuh sekitar 4 node, SPI 90 hari sekitar 22 node | 1.3, 2.4 |
| 4. Tiga usulan hemat | Saring backup secara sempit dan catat di register; tolak snaplen kecil dan sampling paket untuk egress | 1.4, 2.5 |
| 5. Pilot Arkime | Teruskan untuk egress dengan rule TLS dan kedaluwarsa SPI 14 hari; metadata sudah 15 hari tanpa dihapus, disk 78% | 1.5, 2.6 |
| 6. Drop tanpa link error | Drop di dalam `jkt-pcap01` (0,9%, 07:42 sampai 08:02) karena pemindaian ring penuh; Zeek bersih | 1.6, 2.7 |
| 7. Mengunci pcap | Case hold 30 menit oleh petugas jaga; perekaman tambahan `INC-2027-077` aktif sampai Kamis 10:15, terverifikasi; conditional pcap untuk core DC | 1.7, 2.8 |
| 8. Kebijakan retensi | Lampiran v0.2 dengan target, cara ukur, alarm, batas maksimal, dan register filter | 1.8, 2.9 |

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** VM lab dengan disk yang bisa dipenuhi dengan aman, Arkime atau alat setara, dan generator trafik sederhana. Konkretnya: VM sensor Linux dengan dumpcap 4.6.x, Zeek 9.0, dan Suricata 8.0.7 (Day 08 dan 09); VM Arkime 6.x dengan satu node OpenSearch dan disk data terpisah dari disk pcap; jaringan host-only `192.168.56.0/24`; semua dengan snapshot. Pakai disk virtual kecil (misalnya 20 GB untuk pcap) supaya perilaku disk penuh terlihat dalam hitungan jam. Tidak ada data PT JAB di lab, dan tidak ada sampel malware.

1. Hitung kebutuhan penyimpanan untuk tiga skenario laju trafik memakai rumus bagian 2.4, lalu bandingkan dengan kapasitas yang benar-benar kamu punya.
2. Pasang Arkime di lab dengan disk kecil yang disengaja, jalankan perekaman sampai disk hampir penuh, lalu amati perilaku penghapusan berkas tertua dan catat pada persentase berapa ia mulai.
3. Ukur retensi nyata dengan memeriksa usia berkas tertua, lalu bandingkan dengan retensi yang kamu rencanakan sebelum percobaan.
4. Biarkan metadata tumbuh tanpa kebijakan kedaluwarsa selama beberapa hari, amati pertumbuhan indeksnya, lalu pasang kedaluwarsa dan buktikan indeks lama benar-benar hilang.
5. Jalankan perekaman yang sama dengan tiga nilai snaplen berbeda, lalu bandingkan ukuran hasil dan apa yang masih bisa kamu analisis dari masing-masing.
6. Terapkan satu filter capture, lalu buktikan bahwa trafik yang disaring tidak meninggalkan jejak apa pun. Tulis ini sebagai alasan kenapa filter harus didokumentasikan.
7. Hasilkan seribu koneksi pendek ke satu alamat, lalu ambil cuplikan satu dari seratus dari data yang sama. Hitung berapa koneksi yang terlihat di cuplikan dan tulis kesimpulan tentang pertanyaan apa yang masih bisa dijawab.
8. Ulangi langkah 7 dengan satu koneksi tunggal, bukan seribu. Catat apakah ia muncul di cuplikan.
9. Susun kebijakan retensi satu halaman untuk lab-mu memakai daftar bagian 1.8, lengkap dengan angka nyata dari langkah 1 sampai 4.
10. Tulis prosedur perekaman saat insiden mengikuti bagian 2.8, lalu uji dengan menjalankannya dari awal sampai akhir dan ukur waktunya.

Variasi dan tantangan:

- **Ring dumpcap berbasis waktu vs ukuran.** Jalankan `-b duration:300 -b files:12` lalu `-b filesize:50000 -b files:12` dengan trafik yang dinaikkan di tengah percobaan; catat mana yang menjaga jendela waktu dan mana yang menjaga disk.
- **Rule TLS Arkime.** Pasang rule `_maxPacketsToSave: 20` untuk `tls` dan `quic` (bagian 2.6), unduh beberapa berkas besar lewat HTTPS dan lewat HTTP, lalu bandingkan byte pcap yang ditulis dan apa yang masih terlihat di metadata sesi.
- **Conditional pcap Suricata.** Aktifkan `pcap-log` dengan `conditional: alerts` dan satu rule lokal yang memicu pada string uji di HTTP lab; pastikan hanya flow itu yang tersimpan, lalu hitung total `limit` kali `max-files` kali jumlah thread.
- **Drop karena I/O.** Saat ring menulis, baca seluruh direktori ring dengan beberapa proses `tshark` paralel; catat statistik drop dumpcap saat dihentikan dan bandingkan dengan `capture_loss.log` Zeek dari salinan trafik yang sama.
- **Sampling dengan seleksi hash.** Dari pcap langkah 7, buat dua cuplikan: satu dengan memilih setiap paket ke-100, satu dengan memilih koneksi yang hash lima-tuple-nya jatuh di 1% rentang. Bandingkan berapa koneksi yang bisa dirakit ulang dari masing-masing (bagian 1.4).

**Hasil yang sebaiknya tersimpan:**

- Perhitungan kebutuhan penyimpanan untuk tiga skenario.
- Catatan perilaku penghapusan saat disk hampir penuh, beserta ambangnya.
- Perbandingan retensi nyata dan retensi rencana.
- Bukti pertumbuhan indeks tanpa kedaluwarsa, dan bukti kedaluwarsa bekerja setelah dipasang.
- Perbandingan tiga nilai snaplen beserta kemampuan analisis masing-masing.
- Bukti bahwa trafik yang disaring tidak meninggalkan jejak.
- Hasil percobaan cuplikan untuk seribu koneksi dan untuk satu koneksi.
- Kebijakan retensi satu halaman dengan angka nyata.
- Prosedur perekaman insiden beserta waktu pelaksanaan nyatanya.
- Perbandingan byte pcap sebelum dan sesudah rule TLS, dan perbandingan cuplikan per paket dengan seleksi hash per koneksi.

## 4. Troubleshooting

Tabel ini dipakai saat hasil tidak sesuai harapan; mulai dari kolom gejala.

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Retensi pcap jauh lebih pendek dari rencana | Trafik melebihi perkiraan; penghapusan berjalan terus | Periksa usia berkas tertua dan ruang kosong (bagian 2.1); cari sumber volume di flow router DC (bagian 2.2) |
| Kluster pencarian bermasalah seiring waktu | Metadata tidak pernah dikedaluwarsakan [S1] | Periksa indeks tertua; pasang kebijakan siklus hidup atau cron (bagian 2.6) |
| Pcap dan indeks sama-sama rusak saat disk penuh | Keduanya berbagi sistem berkas [S1] | Pisahkan; ini syarat, bukan anjuran |
| Berkas pcap nol byte | Disk benar-benar habis [S1] | Periksa `freeSpaceG` dan apakah viewer berjalan, karena viewer yang menghapus |
| Sesi baru tidak muncul beberapa menit | Rekaman sesi ditulis saat sesi berakhir [S1] | Wajar; jangan simpulkan perekaman gagal |
| Paket ada tetapi muatan kosong | snaplen terlalu kecil | Periksa konfigurasi snaplen; sesuaikan untuk segmen penting |
| Paket terlihat lebih besar dari MTU | Offload NIC aktif | Matikan offload, jangan menaikkan `snapLen` [S5] |
| Trafik tertentu tidak pernah muncul | Tersaring filter capture | Periksa register filter; trafik tersaring tidak meninggalkan jejak |
| Sesi ada di metadata Arkime tetapi paketnya tidak ada | `dontSaveBPFs` atau rule `_maxPacketsToSave` memangkasnya [S1][S7] | Periksa rule dan jumlah paket tersimpan sesi itu |
| Angka volume tidak masuk akal | Data bercuplik dipakai sebagai angka pasti | Kalikan dengan laju cuplikan dan tulis sebagai perkiraan |
| Koneksi yang diketahui ada tidak ditemukan | Data bercuplik, atau segmen tidak direkam | Periksa cakupan perekaman sebelum menyimpulkan |
| Drop di sensor pcap tanpa error di router | Penulisan disk tertunda, buffer capture penuh | Statistik drop per jendela, bandingkan dengan `capture_loss.log` (bagian 2.7); cek I/O disk |
| Arkime membuang paket saat ramai | Antrean paket per thread penuh (`maxPacketsInQueue`) [S5] | Baca counter `drop:` dan rincian antrean di log kemajuan capture [S1] |
| Total pcap Suricata jauh di atas perkiraan | `limit` dan `max-files` berlaku per thread [S11] | Kalikan dengan jumlah thread |
| Mesin pencarian kehabisan memori | Heap atau memori per node kurang [S1] | Rujuk angka perencanaan di bagian 1.3 |

## 5. Kesalahan umum dan jebakan

- Menjanjikan retensi tertentu tanpa menghitung kebutuhan disknya lebih dulu.
- Menghitung dengan laju rata-rata, bukan laju puncak yang berkelanjutan.
- Menyetujui perubahan trafik besar (backup offsite, migrasi, pembaruan massal) tanpa menghitung dampaknya ke retensi sensor.
- Memasang perekaman tanpa kebijakan kedaluwarsa metadata sejak hari pertama [S1].
- Menaruh pcap dan indeks pada sistem berkas yang sama [S1].
- Melaporkan retensi dari dokumen kebijakan, bukan dari usia berkas tertua yang nyata.
- Menambahkan filter capture tanpa mencatat alasan dan tanggal tinjauannya.
- Menulis filter dengan satu syarat lebar (satu alamat tujuan layanan bersama) padahal yang dimaksud satu sesi backup.
- Menurunkan snaplen di segmen yang justru paling butuh isi paket.
- Mencuplik paket untuk pcap forensik, lalu mengira bukti tersedia karena berkasnya ada.
- Menganggap seleksi berbasis hash sama dengan sampling acak, padahal ia deterministik dan menyimpan flow utuh [S2].
- Menyatakan sesuatu tidak terjadi berdasarkan data bercuplik.
- Menyebut angka volume dari data bercuplik tanpa menyebut laju cuplikannya.
- Memindai seluruh ring untuk satu alamat, sehingga merusak rekaman yang sedang ditulis.
- Menunda case hold sampai analis L2 sempat, padahal ring tidak menunggu.
- Menyiapkan prosedur perekaman insiden hanya di atas kertas, tanpa pernah mengujinya.

## 6. Catatan terkini

Bagian ini menampung detail versi, angka perencanaan, dan perilaku alat yang perlu dipantau, tetapi tidak mengubah langkah di atas.

- Angka perencanaan dari dokumentasi Arkime, yaitu sekitar 11 TB per hari per Gbps tanpa kompresi dan perkiraan metadata 5 persen dari ukuran pcap [S1], adalah titik awal yang cukup untuk rapat. Ukur sendiri di lingkunganmu, karena komposisi trafik sangat memengaruhinya.
- Tidak menyimpan sesi TLS secara penuh disebut sebagai salah satu cara menurunkan kebutuhan penyimpanan [S1]. Dengan makin luasnya enkripsi (Day 15 dan Day 16), pilihan ini makin masuk akal dan makin sedikit yang dikorbankan. Dokumentasi format rule Arkime memberi contoh rule yang membatasi paket tersimpan untuk sesi TLS dan QUIC [S7].
- Penghapusan pcap dipicu ambang ruang kosong, bukan jadwal [S1]. Artinya retensi nyata adalah akibat dari kapasitas dan trafik, bukan sesuatu yang kamu tetapkan; pantau sebagai angka yang berubah.
- Metadata tidak pernah dihapus otomatis [S1]. Ini perbedaan perilaku yang paling sering mengejutkan orang yang baru memasang, dan penyebab masalah kluster yang muncul beberapa bulan kemudian.
- Rilis Arkime terbaru per 2026-10-29 adalah v6.9.1 (22 Oktober 2026), rilis ulang cepat v6.9.0 dengan versi Node.js yang lebih baru; FAQ sudah memuat catatan peningkatan ke Arkime 7, tetapi menyebut Arkime 7 belum dirilis dan peningkatan itu mensyaratkan 6.5.0 ke atas [S1][S9]. Bawaan `pcapDir` berubah menjadi `/opt/arkime/raw` sejak 5.5.0, dan bawaan `maxFileSizeG` 12 sejak 4.0.0 [S5].
- Kompresi pcap Arkime aktif secara bawaan sejak 4.0 [S8]; `simpleCompression` bawaannya `gzip` di 4.0 sampai 5 dan `zstd` sejak 5, dan dokumentasi tidak menganjurkan `zstd` sebelum 4.5.1 [S5]. FAQ menyarankan mematikan kompresi di jaringan bertrafik rendah karena kompresi membuat lebih banyak data tertahan di buffer [S1].
- Satuan `-B` dumpcap adalah MiB dengan bawaan 2 MiB, dan `-b files` harus di bawah 100000 [S10]. Man page 4.6.9 tidak menegaskan apakah kB di `filesize` berarti 1000 atau 1024 byte; contohnya menyebut `filesize:1000` sebagai satu megabyte, yang mengarah ke desimal [S10].
- Versi alat per 2026-10-29: Wireshark 4.6.9 stabil, 4.4.19 old stable, 5.0.0rc1 rilis pengembangan [S13]; Zeek 9.0.1 LTS dengan 8.0.11 sebagai LTS sebelumnya [S15]; Suricata 8.0.7 stabil sejak 15 September 2026, cabang 7.x EOL dengan rilis terakhir 7.0.17 [S14]. `jkt-zeek01` di Day lain disebut memakai 9.0; pembaruan ke 9.0.1 perlu dicek di catatan rilisnya sebelum dijadwalkan.
- Dokumentasi `pcap-log` Suricata menyebut opsi `conditional` dengan nilai `all`, `alerts`, dan `tag`, serta catatan bahwa `limit` dan `max-files` berlaku per thread [S11].
- Di lingkungan cloud, perekaman paket penuh punya mekanisme dan biaya sendiri, dan sering flow log adalah satu-satunya yang tersedia (Day 17). Rancang kebijakan retensi yang mencakup keduanya, bukan hanya yang di pusat data.

## 7. Cheat sheet

```
ANGKA PERENCANAAN (Arkime)
  1 Gbps tanpa kompresi  ~ 11 TB / hari
  contoh 2,5 Gbps 7 hari ~ 192,5 TB
  disk metadata          ~ 5% dari ukuran pcap untuk retensi sama (hitung dari volume SEBELUM pangkas TLS)
  heap >= 1% ukuran data kluster; memori ~ setengah mesin cari, setengah cache disk
  >= 30 GB memori + 30 GB cache per node mesin cari; capture TERPISAH; mesin capture 64-96 GB RAM
  replikasi MENGGANDAKAN pemakaian disk (bawaan Arkime: tanpa replika)
  hitung pakai laju PUNCAK berkelanjutan, bukan rata-rata
  PT JAB core+egress 7 hari: 100,1 TB mentah -> ~26 TB pangkas TLS -> ~35,6 TB usable; SPI 14 hari ~4 node

RETENSI NYATA
  jendela = kapasitas ring / laju tulis selama jendela itu
  jkt-pcap01 8,4 TB: 27,5 MB/s -> ~85 jam ; 85 MB/s -> ~27,5 jam
  rotasi "15 menit atau 1 GB": ukuran dominan bila laju > ~8,9 Mbps
  ukur: ls -1tr | head -1 ; capinfos -a -e <tertua> ; df -h ; JAB-PCAP-HEALTH-01 (alarm < 48 jam)

DUA JENIS DATA, DUA UMUR
  SPI/metadata -> OpenSearch/Elasticsearch | PCAP -> sistem berkas node capture
  dihapus TERPISAH; hapus satu tidak menghapus yang lain
  PT JAB: zeek 90 hari | pcap ring ~3,5 hari | ekstrak kasus sampai kasus ditutup

RETENSI ARKIME
  PCAP     OTOMATIS: viewer cek ruang kosong tiap menit; di bawah freeSpaceG (bawaan 5%)
           hapus berkas TERTUA; selalu sisakan minimal 10 berkas (>= 10 x maxFileSizeG 12 = 120 GB)
  METADATA TIDAK OTOMATIS -> ILM/ISM atau cron: db.pl <url> expire daily N (contoh resmi 90)
  PCAP dan indeks TIDAK BOLEH satu sistem berkas
  cek: ls -lt <pcapDir> | tail -3 ; df -h ; curl _cat/indices/arkime_sessions3* ; _cat/allocation

MENGURANGI DATA (akibatnya BEDA)
  potong (snaplen)    header tetap, MUATAN hilang          Arkime snapLen bawaan 16384; dumpcap 262144
  potong per sesi     N paket pertama                       dontSaveBPFs "bpf:N" ; rule _maxPacketsToSave
  saring (BPF)        trafik hilang TANPA JEJAK             wajib register + tanggal tinjau
  cuplik (sampling)   sebagian kejadian hilang STATISTIK    pcap tercuplik tidak bisa dirakit ulang
  seleksi hash        secara formal FILTER (deterministik)  flow terpilih utuh
  urutan terbaik: buang muatan TLS dulu (isinya toh terenkripsi), baru pertimbangkan sisanya

DATA BERCUPLIK
  perkiraan = tercuplik x laju; selalu sebut lajunya; tulis sebagai PERKIRAAN
  peluang koneksi k paket terlihat di 1:N = 1 - (1 - 1/N)^k   (290 paket @1:1000 ~ 25%)
  JANGAN PERNAH menyatakan sesuatu TIDAK terjadi dari data bercuplik

DROP (cek tiap mata rantai)
  SPAN -> npb01 -> NIC (ethtool -S) -> kernel/buffer (dumpcap -B MiB) -> proses -> DISK
  Zeek capture_loss = perkiraan dari celah TCP saja ; Suricata kernel_drops ; Arkime drop: + antrean
  drop di pcap + Zeek bersih = masalah di sensor pcap, bukan link
  jangan pindai ring penuh: metadata dulu, lalu potong file yang relevan, berurutan

BERLAPIS   metadata semua (retensi panjang) | pcap penuh segmen bernilai tinggi (pendek)
           pcap sesuai permintaan (PROSEDUR siap + DIUJI) | cuplikan untuk kapasitas saja
CASE HOLD  <= 30 menit, petugas jaga, /cases/<tiket>/ + SHA256SUMS
TAMBAHAN   dumpcap -f "host X" -b duration:3600 -b files:72 -a duration:259200 ; verifikasi dengan SYN uji
SURICATA   pcap-log conditional: alerts|tag|all ; limit x max-files x THREAD

PERILAKU   rekaman sesi Arkime ditulis saat sesi BERAKHIR -> sesi baru butuh beberapa menit muncul
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Kebijakan akses NSM menulis "retensi pcap 72 jam", dan ring buffer `jkt-pcap01` dirancang untuk itu. Seorang analyst L1 menyimpulkan bahwa tiket Jumat siang tidak perlu dikunci karena pcap-nya pasti masih ada Senin pagi. Benarkah?

<details><summary>Jawaban</summary>

Tidak. Ring buffer berbasis ukuran menjamin pemakaian disk, bukan jendela waktu: jendelanya sama dengan kapasitas dibagi laju tulis selama jendela itu. Pada minggu biasa `jkt-pcap01` memberi 81 sampai 86 jam, tetapi seed backup sekitar 600 Mbps menaikkan laju tulis akhir pekan ke sekitar 85 MB per detik, sehingga jendela turun ke sekitar 27,8 jam dan data Jumat 14:05 tertimpa Sabtu sekitar 19:05. Angka 72 jam adalah retensi rencana; yang menentukan adalah retensi nyata, dan tiket dengan indikator jaringan harus di-case hold dalam 30 menit.

Lihat bagian 1.1, 2.1, dan 2.8.

</details>

**2. Skenario keputusan.** Backup offsite malam hari dari `jkt-bkp01` ke layanan penyimpanan objek bersama memotong retensi `jkt-pcap01` dari sekitar 85 jam ke sekitar 63 jam. Apa yang kamu usulkan?

- A. Turunkan snaplen ring ke 128 byte untuk semua trafik, supaya jendela naik hampir enam kali.
- B. Tambahkan capture filter sempit yang membuang hanya sesi `jkt-bkp01` ke alamat dan port backup, catat di register filter dengan pemilik dan tanggal tinjau, dan pastikan Zeek serta flow tetap mencatat sesi itu.
- C. Pasang sampling 1:10 di port packet broker ke `jkt-pcap01`, karena volume backup tetap bisa diperkirakan.

<details><summary>Jawaban</summary>

B. Trafik backup adalah TLS yang muatannya memang tidak terbaca, dan filter yang memakai host sumber, host tujuan, dan port sekaligus hanya membuang sesi itu. Sisa risikonya (unggahan penyerang dari `jkt-bkp01` ke bucket lain di layanan yang sama) tertutup oleh Zeek, Suricata, dan flow router DC yang tetap melihatnya. A membuang isi semua protokol polos, termasuk unduhan zip dan isi `POST` yang justru dicari di `INC-2027-077`. C membuat stream TCP tidak bisa dirakit ulang; pcap tercuplik tampak ada tetapi tidak berguna untuk kejadian tunggal.

Lihat bagian 1.4 dan 2.5.

</details>

**3. Hitung.** Ring buffer 8,4 TB menerima laju tulis rata-rata 75 MB per detik selama dua hari. Berapa jam jendela retensinya, dan apakah paket dari 40 jam lalu masih ada?

<details><summary>Jawaban</summary>

8.400.000.000.000 byte dibagi 75.000.000 byte per detik sama dengan 112.000 detik, sekitar 31,1 jam. Paket dari 40 jam lalu sudah tertimpa. Bila laporan membutuhkan kejadian itu, sumbernya adalah metadata (Zeek, proxy, flow) atau ekstrak kasus yang dikunci lebih awal, bukan ring.

Lihat bagian 1.1 dan 2.1.

</details>

**4. Pertanyaan jebakan.** "Flow router edge Jakarta (sampling 1:1000) hanya punya satu record ke `203.0.113.195` hari Jumat, jadi hanya ada satu koneksi ke alamat itu." Apa yang salah?

<details><summary>Jawaban</summary>

Data bercuplik tidak bisa menjawab pertanyaan kejadian tunggal. Koneksi sekitar 290 paket hanya punya peluang sekitar 25% terwakili minimal satu paket pada sampling 1:1000, dan koneksi kecil di bawah 1%. Router data center yang tidak di-sampling melihat tiga koneksi dari `jkt-proxy01`, dan record edge yang satu itu pun menggelembung menjadi 1.500.000 byte dari satu paket 1.500 byte. Yang benar: tulis bahwa sumbernya tidak sesuai untuk pertanyaan itu, dan pakai flow 1:1, `conn.log`, atau log proxy.

Lihat bagian 1.4 dan 2.2.

</details>

**5. Skenario keputusan.** Dua minggu setelah pilot Arkime dipasang, disk node OpenSearch sudah 78% dan `_cat/indices` menunjukkan lima belas indeks harian sejak hari pertama. Apa langkahmu?

- A. Tambah disk node OpenSearch, karena pertumbuhan indeks adalah tanda pilot sukses.
- B. Pasang cron `db.pl ... expire daily 14` atau kebijakan ISM, lalu buktikan indeks tertua benar-benar hilang setelah tugas pertama berjalan.
- C. Turunkan `freeSpaceG` supaya viewer menghapus lebih banyak data.

<details><summary>Jawaban</summary>

B. Arkime tidak pernah menghapus metadata secara otomatis; kedaluwarsa harus disiapkan lewat ILM/ISM atau cron, dan buktinya adalah indeks lama yang hilang, bukan konfigurasi yang terlihat benar. A hanya menunda masalah yang sama. C keliru sasaran: `freeSpaceG` mengatur penghapusan pcap di node capture, bukan indeks di OpenSearch, dan pcap serta indeks dihapus oleh mekanisme yang terpisah.

Lihat bagian 1.5 dan 2.6.

</details>

**6. Jelaskan ulang.** Jelaskan ke Bambang dalam tiga kalimat kenapa `jkt-pcap01` mencatat drop 0,9% padahal router edge dan firewall tidak mencatat error apa pun.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh jawaban: "Paketnya tidak hilang di jaringan; ia hilang di dalam sensor pcap, karena disk yang sedang menulis ring juga dibaca habis-habisan oleh pemindaian seluruh ring dari workstation analisis, sehingga penulisan tertunda, buffer capture penuh, dan kernel membuang paket. Buktinya, Zeek yang menerima salinan yang sama dari packet broker tidak mencatat kehilangan di menit yang sama. Jadi link aman; yang diperbaiki adalah cara kami mencari di pcap (metadata dulu, potong file yang relevan saja) dan buffer capture-nya."

Kesalahan yang sering muncul: menganggap drop di sensor sebagai bukti masalah link; menyimpulkan "tidak ada trafik" dari pcap yang drop-nya bukan nol tanpa menyebut angkanya; dan memakai `capture_loss.log` sebagai counter drop, padahal ia perkiraan dari celah TCP saja.

</details>

**7. Interview question (English).** "Full packet capture for our whole network would cost hundreds of terabytes a month. How would you design capture and retention so we can still investigate incidents?"

<details><summary>Sample answer</summary>

"I'd layer it. Session metadata, from Zeek or an indexed capture tool, covers everything and is kept for months, because most questions are who, when, where, and how much. Full packets go only where content still matters, like the internet egress and key server segments, with a short window measured in days. Before trimming anything I'd cut the cheapest thing first: payload of TLS sessions after the handshake, since we can't read it anyway. I'd avoid packet sampling for forensics entirely, because sampled pcap can't be reassembled, and I'd treat every capture filter as an exception with an owner and a review date. Retention is a result of disk divided by traffic, so I'd measure the age of the oldest packet every day and alarm on it, and I'd require changes that add big flows, like a new offsite backup, to go through the team that owns the sensors. Finally, I'd make the short window survivable: any alert with a network indicator gets its packets carved into a case folder within thirty minutes, and we keep a tested procedure to switch on targeted capture during an incident."

What makes this answer strong: it separates metadata from packets with different retention, picks the reduction method with the lowest analytic cost first, explains why sampling fails for single events, treats retention as a measured number rather than a promise, and closes the gap with case hold and on-demand capture.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Arkime FAQ (dokumentasi resmi) | https://arkime.com/faq | primer | dilihat 2026-10-09; diakses ulang 2026-10-29 | Tinggi. Pemisahan SPI data dan pcap, komponen capture dan viewer, perilaku penghapusan pcap berdasarkan `freeSpaceG` bawaan 5 persen dengan minimal sepuluh berkas disisakan (minimal 10 x `maxFileSizeG`), ketiadaan kedaluwarsa otomatis untuk metadata (ILM/ISM atau `db.pl expire`, contoh 90 hari), angka 11 TB per hari per Gbps dan contoh 192,5 TB, perkiraan metadata 5 persen, anjuran memori (30 GB plus 30 GB cache per node, heap minimal 1 persen data, mesin capture 64 sampai 96 GB), larangan berbagi sistem berkas, berkas nol byte saat disk habis, urutan cara mengurangi disk, `dontSaveBPFs`, counter `drop:`, dan perilaku penulisan rekaman sesi saat sesi berakhir. Halaman memuat catatan Arkime 7 tetapi menyebut Arkime 7 belum rilis |
| S2 | RFC 5475: Sampling and Filtering Techniques for IP Packet Selection | https://www.rfc-editor.org/rfc/rfc5475.html | primer | dirujuk 2026-10-09; diakses ulang 2026-10-29 | Tinggi untuk pembedaan formal antara penyaringan dan pencuplikan, jenis sampling sistematis dan acak, serta seleksi berbasis hash sebagai penyaringan. Bagian akhir dokumen tidak dibaca |
| S3 | RFC 7011: Specification of the IP Flow Information Export (IPFIX) Protocol | https://www.rfc-editor.org/rfc/rfc7011.html | primer | dirujuk 2026-10-09 | Tinggi untuk ekspor informasi alur (dipakai juga di Day 10) |
| S4 | RFC 3176: InMon Corporation's sFlow | https://www.rfc-editor.org/rfc/rfc3176.html | primer | dirujuk 2026-10-09 | Sedang-tinggi. Dokumen informasional yang menjelaskan sFlow dan sifat pencuplikannya |
| S5 | Arkime: Architecture dan Settings | https://arkime.com/architecture ; https://arkime.com/settings | primer | architecture dirujuk 2026-10-09; settings diakses 2026-10-29 | Tinggi untuk nama dan bawaan pengaturan: `snapLen` 16384, `bpf`, `dontSaveBPFs` dengan akhiran `:num`, `maxPackets` 10000, `maxFileSizeG` 12 (sejak 4.0.0), `maxFileTimeM` 0, `freeSpaceG` 5%, `pcapDir` `/opt/arkime/raw` (sejak 5.5.0), `maxPacketsInQueue` 200000, `simpleCompression`; anjuran mematikan offload NIC. Halaman sangat panjang dan dibaca sebagian |
| S6 | Network-Forensics Day 01, 02, 05, 06, 08, 09, 10, 12, 15, 16, 17 (lokal) | (lokal) | rujukan internal | 2026-10-10, diperbarui 2026-10-29 | Sensor, ring buffer, hitungan disk, proxy, Zeek, Suricata, flow, dan sampling PT JAB |
| S7 | Arkime: Rules Format | https://arkime.com/rulesformat | primer | diakses 2026-10-29 | Tinggi. Struktur rule YAML, nilai `when`, op `_maxPacketsToSave`, `_dontSaveSPI`, `_minPacketsBeforeSavingSPI`, `_dropByDst`, dan contoh pembatasan paket untuk TLS dan QUIC |
| S8 | Arkime: Estimators | https://arkime.com/estimators | primer | diakses 2026-10-29 | Sedang-tinggi. Masukan kalkulator (laju, retensi, disk, RAID, persentase TLS, kompresi, replika), kompresi bawaan sejak 4.0, replikasi tidak aktif secara bawaan; rumus tidak ditulis eksplisit |
| S9 | Arkime releases (GitHub) | https://github.com/arkime/arkime/releases | primer | diakses 2026-10-29 | Tinggi untuk nomor versi: v6.9.1 (22 Okt 2026) sebagai rilis terbaru, v6.9.0, v6.8.0; entri "Latest Commit" adalah build bergulir, bukan rilis |
| S10 | Wireshark: dumpcap manual page | https://www.wireshark.org/docs/man-pages/dumpcap.html | primer | versi 4.6.9; diakses 2026-10-29 | Tinggi. Opsi `-b` (duration, filesize, files, interval, packets, printname), `-a` autostop, `-s` bawaan 262144, `-B` dalam MiB bawaan 2 MiB, `-f`. Satuan kB tidak didefinisikan tegas |
| S11 | Suricata docs: suricata.yaml, Packet log (pcap-log) | https://docs.suricata.io/en/latest/configuration/suricata-yaml.html | primer | dokumentasi cabang latest, berlaku juga untuk 8.0.x; diakses 2026-10-29 | Tinggi. `filename` dengan `%n`/`%i`/`%t`, `limit` (MB, bawaan 32), `max-files`, catatan per thread, `compression: lz4`, `mode` normal/multi, `conditional` all/alerts/tag, `bpf-filter` |
| S12 | Zeek docs: capture_loss.log and reporter.log | https://docs.zeek.org/en/master/logs/capture-loss-and-reporter.html | primer | diakses 2026-10-29 | Tinggi. Perkiraan kehilangan dari celah nomor urut TCP, hanya TCP, interval sekitar 15 menit, field `gaps`, `acks`, `percent_lost` |
| S13 | Wireshark: Download | https://www.wireshark.org/download.html | primer | diakses 2026-10-29 | Tinggi untuk versi stabil 4.6.9, old stable 4.4.19, dan 5.0.0rc1; halaman tidak memuat tanggal |
| S14 | Suricata: Download | https://suricata.io/download/ | primer | diakses 2026-10-29 | Tinggi. 8.0.7 stabil sejak 15 September 2026; 7.0.17 EOL |
| S15 | Zeek: Get Zeek | https://zeek.org/get-zeek/ | primer | diakses 2026-10-29 | Tinggi. LTS 9.0.1, LTS sebelumnya 8.0.11 |

**Catatan sumber:** nama pengaturan `snapLen`, `bpf`, `dontSaveBPFs`, dan `freeSpaceG` kini dicocokkan dengan halaman settings Arkime [S5]; bawaan `snapLen` Arkime adalah 16384, bukan 262144 seperti dumpcap, sehingga contoh konfigurasi di bagian 2.5 ditulis ulang. Nama dan bentuk indeks `arkime_sessions3-YYMMDD` di bagian 2.6 mengikuti pola prefiks dan rotasi harian, dan nama persisnya berbeda antar versi dan pengaturan; halaman yang diperiksa tidak menyebutnya. Angka perencanaan di bagian 1.3 berasal dari dokumentasi Arkime dan bersifat perkiraan yang sangat bergantung komposisi trafik, jadi perlakukan sebagai orde besaran dan ukur sendiri. Rumus perkiraan di bagian 2.4 adalah turunan sederhana dari angka tersebut, bukan rumus resmi; faktor 0,26 untuk pemangkasan TLS, penghitungan SPI dari volume sebelum pemangkasan, dan pembagian heap ke node 30 GB adalah asumsi penulis yang perlu diukur di pilot. Overhead sekitar 32 byte per paket di pcapng (bagian 2.5) dipakai sebagai asumsi hitung dan perlu dicek terhadap spesifikasi format. Galat sampling di bagian 2.2 memakai asumsi sampling acak, bukan klaim vendor. Ketersediaan sampling paket di packet broker dan nama counter antarmuka di skrip status bergantung perangkat dan perlu dicek. Perilaku nomor urut lima digit nama file dumpcap setelah 99999 belum dicek ke dokumentasi.
