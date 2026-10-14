---
day: 01
title: 'Cara Splunk menyimpan dan mencari data: index, sourcetype, waktu, search mode, dan job'
researched_on: 2026-10-14
versions_checked: 'Splunk Enterprise 10.6 (SPL Search Reference: search, halaman diperbarui 2026-09-09; Search Tutorial "Use fields to search", diperbarui 2026-08-25); Search Manual 10.4 (Select time ranges, Specify time modifiers, About jobs and job management; diperbarui 2026-05-16), 10.2 (Manage search jobs, 2026-01-09), 10.0 (Search modes dan Extending job lifetimes, 2025-07-18), 9.4 (How time zones are processed, 2025-07-03); Knowledge Management Manual 10.4 (Use default fields, 2026-05-13); Getting Data In 10.4 (Why source types matter, 2026-05-13); Managing Indexers 10.0 (Create custom indexes, 2025-07-18); Splunk Enterprise Security 8.7.0 (Configure and deploy indexes, 2026-09-01); CIM 6.4; dataset BOTS v1'
---

# Day 01: Cara Splunk menyimpan dan mencari data (index, sourcetype, waktu, search mode, dan job)

Cakupan: apa yang sebenarnya disimpan Splunk untuk satu event, bagaimana index, sourcetype, source, dan host menentukan apa yang bisa kamu temukan, bagaimana `_time` dan `_indextime` terbentuk, cara memilih rentang waktu yang benar, apa yang berubah saat search mode diganti, dan cara menyerahkan hasil search sebagai job, bukan screenshot.

## Ide inti

Splunk tidak memaksa skema sebelum data masuk. Yang disimpan adalah teks event apa adanya di `_raw`, ditambah beberapa label yang ditempelkan saat ingest: index tempat event itu disimpan, sourcetype yang menentukan cara mem-parse-nya, source dan host yang menyebut asalnya, dan `_time` yang dibaca dari isi event. Hampir semua field lain yang kamu pakai saat triage dihitung saat search dijalankan, bukan saat data disimpan. Konsekuensinya, hasil search ditentukan oleh empat keputusan: index mana yang kamu sebut, sourcetype apa yang mem-parse data itu, rentang waktu yang kamu pilih, dan mode search yang sedang aktif. Kebanyakan laporan "datanya tidak ada di Splunk" berakhir di salah satu dari empat keputusan itu, bukan pada data yang benar-benar tidak ada.

Kamu sudah punya versi manual dari semua ini dari waktu mengelola server syslog di ISP. Log dipisah ke folder per kelompok perangkat (itu index), setiap vendor butuh template parsing sendiri supaya kolomnya terbaca (itu sourcetype), nama file dan pengirimnya dicatat (itu source dan host), dan ada dua waktu yang sering berbeda: jam yang tertulis di baris log dan jam ketika baris itu sampai ke kolektor (itu `_time` dan `_indextime`). Investigasi selalu dimulai dengan memilih rentang tanggal sebelum menyaring kata kunci, karena itu filter paling murah. Dua hal yang tidak ada padanannya di server syslog: index di Splunk sekaligus menjadi batas hak akses dan batas retensi, dan setiap search menjadi sebuah job yang punya status, hasil, masa simpan, dan bisa dibagikan ke orang lain.

Organisasi yang dipakai di seluruh catatan Splunk ini adalah PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan, layanan broadband rumah dan dedicated internet korporat, kantor pusat dan data center di Jakarta, serta POP di Bandung, Surabaya, dan Medan. SOC internalnya duduk satu lantai dengan NOC 24/7: enam analyst L1 dalam tiga shift, dua analyst L2, satu detection engineer, dan satu SOC lead. Splunk Enterprise sudah lama menjadi SIEM di sana; Enterprise Security (ES) baru dipasang di search head terpisah, sehingga sebagian besar pekerjaan L1 masih dilakukan di app Search & Reporting dengan report dan alert biasa. Seluruh contoh di catatan ini memakai index, host, akun, dan nomor tiket PT JAB yang sama supaya bisa dibaca ulang sebagai satu rangkaian.

```
Perangkat / server  ->  forwarder atau syslog
   |
   v  index time (sekali, permanen untuk data itu)
 parsing: pecah event, baca timestamp -> _time, catat _indextime
 label  : index, sourcetype, source, host
   |
   v  disimpan di index (bucket)
 _raw + default field + indexed field
   |
   v  search time (setiap kali search dijalankan)
 filter rentang waktu  -> filter index/sourcetype/host -> kata kunci
 field extraction sesuai sourcetype dan search mode
 pipeline SPL -> hasil disimpan sebagai search job
```

Situasi yang dipakai sepanjang Day ini: pagi pertama kamu memegang akun di search head PT JAB. SOC lead menulis di channel SOC:

> "Akun kamu sudah masuk role `soc_analyst`. Sebelum pegang antrean alert, biasakan dulu tiga hal. Pertama, cek sendiri data apa saja yang benar-benar masuk Splunk kita dan sejak kapan, jangan percaya daftar di wiki. Kedua, buka ulang event di tiket SOC-2026-0198: koneksi VPN pukul 23.40 tanggal 12, yang kata shift sebelumnya 'tidak ada di Splunk' padahal sekarang ada. Saya mau tahu kenapa bisa begitu. Ketiga, hasilnya kirim ke saya sebagai search yang bisa saya buka, bukan screenshot."

NOC menambahkan di thread yang sama:

> "Sekalian, dashboard kami menunjukkan lonjakan query DNS pelanggan tiap pukul 02.00. Bisa dipastikan datanya memang masuk ke Splunk, atau kami yang salah baca?"

Pesan itu memuat lima pertanyaan:

1. Data apa yang ada, disimpan di index mana, dan di-parse sebagai sourcetype apa?
2. Kenapa event yang sama bisa "tidak ada" pukul 23.45 lalu muncul pukul 00.20?
3. Rentang waktu mana yang dipakai supaya hasilnya bisa diulang orang lain, termasuk untuk dataset latihan yang datanya sudah lama?
4. Kenapa daftar field di sebelah kiri berubah-ubah, dan kadang field yang kamu butuhkan tidak terlihat?
5. Bagaimana menyerahkan hasil search tanpa screenshot, dan apa risikonya?

Pertanyaan 1 dijawab di bagian 1.1 sampai 1.3, pertanyaan 2 di bagian 1.4, pertanyaan 3 di bagian 1.5, pertanyaan 4 di bagian 1.6, dan pertanyaan 5 di bagian 1.7. Bagian 1.8 menutup dengan sintaks dasar yang menentukan apakah filter-mu benar-benar menyaring. Bagian 2 menjalankan semuanya sebagai search.

**Kapan relevan:** setiap kali kamu membuka Splunk untuk pertanyaan baru, memverifikasi bahwa sebuah sumber log benar-benar masuk, menilai apakah hasil nol berarti "tidak terjadi" atau "salah cari", dan setiap kali hasil search harus diserahkan ke orang lain.
**Kapan bukan jawaban:** saat masalahnya ada di sisi ingest (forwarder mati, sourcetype salah dikonfigurasi, timestamp salah di-parse secara permanen). Day ini mengajarkan cara mengenali gejalanya; perbaikannya ada di onboarding data dan konfigurasi index-time (Day 28). Day ini juga bukan tempat belajar mempercepat search; pengukuran dan Job Inspector dibahas di Day 14.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Tabel ini memuat istilah yang dipakai di Day ini, termasuk istilah yang sering dipakai keliru di percakapan sehari-hari (index, sourcetype, source). Kolom padanan memakai pengalaman NOC dan forensik; baca kolom arti dulu, lalu kembali ke sini saat ada istilah yang terlupa.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Event | Satu kejadian yang disimpan Splunk sebagai satu hasil search | Satu baris log di server syslog |
| `_raw` | Teks asli event, apa adanya | Isi baris log sebelum diolah |
| `_time` | Waktu kejadian menurut isi event, disimpan sebagai epoch | Timestamp yang tertulis di baris log |
| `_indextime` | Waktu event selesai diproses dan disimpan Splunk | Waktu baris log diterima kolektor |
| Index | Kumpulan tempat event disimpan, sekaligus batas hak akses dan retensi | Folder log per kelompok perangkat, tetapi dengan ACL dan masa simpan sendiri |
| Sourcetype | Nama format data yang menentukan cara event dipecah, waktunya dibaca, dan field-nya diekstrak | Template parsing per vendor |
| Source | Nama file, stream, atau input asal event | Path file log atau port syslog |
| Host | Nama atau IP perangkat asal event | Nama perangkat pengirim log |
| Default field | Field yang selalu ada karena diisi saat ingest (`host`, `index`, `source`, `sourcetype`, dan lain-lain) | Kolom tetap di CDR: waktu, perangkat, jenis |
| Internal field | Field berawalan garis bawah (`_raw`, `_time`, `_indextime`) yang dipakai mesin search | Metadata file log: nama, waktu tulis |
| App Search & Reporting | App bawaan tempat menulis search ad hoc | Konsol query, bukan dashboard jadi |
| Time picker | Pemilih rentang waktu di sebelah kanan search bar | Memilih tanggal log sebelum `grep` |
| Time modifier | `earliest` dan `latest` yang ditulis di dalam search | Argumen rentang waktu di skrip, menimpa pilihan manual |
| Snap-to | Pembulatan rentang waktu ke batas satuan, misalnya awal hari (`@d`) | "Sejak jam 00.00", bukan "24 jam terakhir" |
| Search mode (Fast, Smart, Verbose) | Pilihan seberapa lengkap field diekstrak saat search | Level detail output `show` di router: ringkas atau lengkap |
| Field discovery | Proses mengekstrak field saat search dijalankan | Parsing baris log saat dibaca, bukan saat ditulis |
| Selected fields | Field yang ditampilkan di bawah tiap event | Kolom yang dipilih tampil di tabel monitoring |
| Interesting fields | Field yang muncul di minimal 20% event hasil search | Kolom yang hampir selalu terisi di sampel log |
| Search job | Satu eksekusi search beserta status, hasil, dan masa simpannya | Tiket kueri yang bisa dibagikan dan kedaluwarsa |
| Job lifetime | Lama hasil job disimpan sebelum dihapus | Masa simpan hasil ekspor di server |
| Dispatch disk quota | Batas disk hasil search per user, diatur per role | Kuota folder hasil ekspor per operator |

### 1.1 Satu event dan label yang menempel padanya

Sebelum menjawab pertanyaan SOC lead, perlu jelas dulu apa yang sebenarnya ada di dalam satu event, karena itu yang membatasi apa yang bisa dicari.

Yang disimpan Splunk untuk setiap event adalah teks aslinya di `_raw`, ditambah sekelompok field yang diisi saat ingest. Dokumentasi memisahkan dua kelompok. Internal field berawalan garis bawah: `_raw`, `_time`, `_indextime`, `_cd`, dan `_bkt`. Default field adalah `host`, `index`, `linecount`, `punct`, `source`, `sourcetype`, `splunk_server`, dan `timestamp`; field ini di-index dan otomatis tersedia di daftar field [S6].

Beberapa sifat yang langsung berguna saat triage [S6]:

- `_time` disimpan internal dalam UTC dan dikonversi ke waktu yang terbaca saat hasil search dirender. Jadi jam yang kamu lihat adalah hasil tampilan, bukan isi yang tersimpan.
- `_indextime` adalah field tersembunyi. Ia tidak muncul di hasil search kecuali kamu me-rename-nya atau memakainya di `eval`. Inilah sebabnya banyak analyst tidak pernah melihat field ini walau selalu ada.
- `host` berisi nama atau IP perangkat asal dan menerima wildcard, misalnya `host=JKT-WS-0*`.
- `linecount` adalah jumlah baris event sebelum di-index. Berguna untuk memisahkan event multi-baris (log Windows klasik, stack trace) dari event satu baris.
- `punct` adalah pola tanda baca yang diekstrak dari event. Dipakai untuk mengelompokkan event yang bentuknya sama walau nilainya berbeda.

Yang tidak termasuk kelompok di atas, misalnya nama akun, IP tujuan, atau status HTTP, umumnya baru dihitung saat search dijalankan sesuai sourcetype-nya. Itu kabar baik: aturan ekstraksi bisa diperbaiki kapan saja tanpa memasukkan ulang data. Kabar buruknya, field yang kamu harapkan bisa saja tidak ada sama sekali karena aturan ekstraksinya belum dipasang, padahal nilainya terlihat jelas di `_raw`.

### 1.2 Index: tempat simpan, batas akses, dan batas retensi

SOC lead meminta kamu tidak percaya daftar di wiki. Langkah pertamanya adalah tahu index apa yang ada dan kenapa data dipisah ke beberapa index.

Data yang masuk indexer disimpan di sebuah index; tanpa pengaturan lain, semuanya masuk ke index `main` [S11]. Dokumentasi menyebut tiga alasan membuat index tambahan [S11]:

1. Mengatur hak akses. Role dapat dibatasi hanya boleh mencari index tertentu, dan ini cara utama memisahkan siapa boleh melihat data apa.
2. Menampung kebijakan retensi yang berbeda. Setiap index bisa punya kebijakan arsip dan retensi sendiri.
3. Mempercepat search tertentu. Memisahkan sumber bervolume besar dari sumber bervolume kecil membuat search atas data kecil tidak perlu melewati data besar.

Satu peringatan yang penting saat onboarding: event yang dirutekan ke index yang belum dibuat akan dibuang oleh indexer [S11]. Jadi "data tidak ada" bisa benar-benar berarti data itu tidak pernah tersimpan. Dokumentasi juga menyebut role bisa punya daftar index default yang dicari bila kamu tidak menyebut `index=` [S11]; artinya search tanpa `index=` di akunmu dan di akun rekanmu bisa menghasilkan jumlah yang berbeda.

Index di PT JAB dan isinya. Tabel ini dipakai ulang di seluruh catatan; cari baris index yang sesuai dengan pertanyaanmu sebelum menulis search, karena menyebut index adalah filter paling murah setelah rentang waktu.

| Index | Isi | Sourcetype yang umum muncul |
|---|---|---|
| `wineventlog` | Windows Security dan System dari DC, file server, jump host, workstation | `XmlWinEventLog`, `WinEventLog` |
| `sysmon` | Sysmon dari server Windows dan sebagian workstation | sesuai add-on Sysmon |
| `powershell` | PowerShell Operational | sesuai add-on Windows |
| `firewall` | Firewall perimeter data center dan kantor | sesuai add-on vendor |
| `proxy` | Web proxy karyawan | sesuai add-on vendor |
| `dns` | Resolver internal karyawan dan resolver pelanggan | sesuai add-on vendor |
| `vpn` | VPN karyawan dan vendor | sesuai add-on vendor |
| `linux` | Server Linux: RADIUS/AAA pelanggan, billing, portal, bastion | `linux_secure`, `linux_audit` |
| `o365` | Entra ID sign-in dan audit, M365 Management Activity | sesuai add-on Microsoft |
| `netops` | Syslog router dan switch POP, dikelola NOC dan dibaca SOC | `syslog` atau sourcetype vendor |

Dua catatan operasional yang berasal dari daftar ini. Pertama, pertanyaan NOC soal DNS pelanggan menyentuh index `dns`, yang volumenya jauh lebih besar daripada index lain karena memuat resolver pelanggan; search tanpa rentang waktu sempit di index ini adalah cara tercepat membuat search head sibuk. Kedua, index `netops` dipakai NOC, bukan SOC, jadi akun SOC belum tentu punya hak membacanya.

**Tanpa ES:** semua isi Day ini berjalan di Splunk Enterprise biasa lewat app Search & Reporting. Enterprise Security menambah index miliknya sendiri untuk menyimpan hasil kerjanya, antara lain `notable`, `notable_summary`, `risk`, dan `threat_activity`, yang dibuat saat ES dipasang dan harus ada di semua indexer pada deployment terdistribusi [S13]. Di PT JAB, index log mentah di tabel atas tetap sama; yang berubah hanyalah ada search head kedua tempat ES berjalan. Bila sebuah dashboard ES kosong padahal log mentahnya ada, kecurigaan pertama adalah hak akses role terhadap index sumber, bukan detection-nya.

### 1.3 Sourcetype: parser yang menentukan field dan timestamp

NOC bertanya apakah DNS pelanggan "memang masuk". Data bisa masuk tetapi tidak terbaca, dan yang menentukan itu adalah sourcetype.

Sourcetype adalah nama format data yang menentukan bagaimana Splunk memformat data yang masuk, sehingga event tersimpan dengan timestamp dan pemecahan event yang benar [S10]. Splunk membawa banyak sourcetype bawaan dan mencoba mengenali format secara otomatis dengan mencocokkan tanda tangan dari beberapa ribu baris pertama sebuah file atau stream dengan sourcetype yang sudah dikenal; contoh yang dibawa produk antara lain `access_combined`, `apache_error`, dan `cisco_syslog` [S10]. Sourcetype juga bisa ditetapkan eksplisit di input, diatur per source, atau dibuat baru untuk data yang tidak dikenali [S10].

Yang perlu dipegang saat triage:

- Sourcetype salah berarti pemecahan event dan pembacaan timestamp bisa salah. Gejalanya khas: satu kejadian terpecah menjadi banyak event, banyak baris menyatu menjadi satu event, atau `_time` meleset jauh.
- Field bergantung sourcetype. Aturan ekstraksi, alias, dan tag dipasang per sourcetype oleh add-on. Dua host yang mengirim log vendor yang sama dengan sourcetype berbeda akan menghasilkan nama field berbeda, dan search yang menyebut satu nama field hanya menemukan separuh data.
- Sourcetype bukan source. Source adalah nama file, stream, atau input asal event, sedangkan sourcetype adalah format datanya [S6]. Add-on Windows modern memakai satu sourcetype generik dan membedakan channel lewat `source` (Day 03), jadi kebiasaan menyaring dengan `sourcetype=` saja tidak selalu cukup.
- Nama sourcetype tidak dijamin rapi. Di deployment yang sudah berumur seperti PT JAB, satu sumber bisa punya beberapa nama sourcetype dari masa konfigurasi berbeda.

Pertanyaan praktisnya bukan "apa sourcetype yang benar", melainkan "sourcetype apa yang benar-benar ada di data saya". Bagian 2.1 menjawabnya dengan satu search.

### 1.4 `_time` dan `_indextime`: kenapa event bisa datang terlambat

Inilah inti pertanyaan kedua SOC lead. Event VPN pukul 23.40 memang belum ada di Splunk ketika shift sebelumnya mencarinya, dan sekarang ada.

Saat ingest, indexer mencari timestamp di setiap event dan mengubahnya menjadi epoch yang disimpan di `_time`, tidak peduli format aslinya; bila event tidak punya timestamp, waktu indexing yang dipakai [S3]. Timestamp tanpa keterangan zona waktu dianggap berada di zona waktu instance Splunk yang memprosesnya, dan ini bisa ditimpa per source [S3]. Di samping itu, `_indextime` mencatat kapan event selesai diproses dan disimpan [S6].

Jarak antara keduanya adalah ingest lag, dan penyebabnya biasa saja: forwarder atau heavy forwarder sempat menumpuk antrean, pengumpulan log cloud lewat API berjalan per interval, atau syslog relay sempat terhenti. Dampaknya untuk analyst ada dua, dan keduanya menjelaskan kejadian di tiket SOC-2026-0198:

- Search dengan rentang 15 menit terakhir yang dijalankan pukul 23.45 menyaring menurut `_time`, bukan `_indextime`. Event yang `_time`-nya 23.40 tetapi baru tersimpan pukul 00.12 tidak akan muncul, karena pada pukul 23.45 event itu belum ada di index. Search yang sama dijalankan lagi keesokan pagi akan menemukannya.
- Alert terjadwal punya masalah yang sama dalam bentuk lebih parah, karena ia hanya berjalan sekali untuk setiap rentang. Alert yang dijadwalkan tiap 5 menit untuk rentang 5 menit terakhir akan melewatkan semua event yang lag-nya lebih dari 5 menit. Cara mengukur lag ada di bagian 2.2, dan penanganannya di penjadwalan alert (Day 09).

Zona waktu menambah satu lapisan lagi. Dokumentasi memisahkan dua jenis rentang [S3]:

- Rentang relatif seperti "Last 24 hours" diproses sebagai epoch, jadi dua orang di zona waktu berbeda mendapat event yang sama.
- Rentang yang terikat batas kalender, seperti "Since 00:00:00", "Today", atau snap-to `@d` dan `@mon`, mengikuti tengah malam di zona waktu user. Dua orang di zona waktu berbeda bisa mendapat hasil berbeda untuk search yang sama.

Saran dokumentasi adalah menyebut waktu berdasarkan zona waktu tempat indexer berada [S3]. Untuk PT JAB yang semua indexer-nya di Jakarta, artinya biasakan menulis waktu dalam WIB dan sebutkan zonanya di tiket. Zona waktu akun Splunk-mu sendiri diatur di pengaturan user; cek nilainya di instance-mu sebelum memakai rentang berbasis kalender, karena nilai itulah yang menentukan di mana batas `@d` jatuh.

### 1.5 Time picker dan time modifier: rentang yang bisa diulang

Pertanyaan ketiga SOC lead menyangkut hal ini: hasil harus bisa dibuka ulang orang lain dan memberi angka yang sama.

Time picker menyediakan beberapa cara memilih rentang [S1]:

| Cara | Isinya | Kapan dipakai |
|---|---|---|
| Presets | Rentang bawaan yang didefinisikan di `times.conf`: Last 15 minutes sampai Last 30 days, Today, Yesterday, Week to date, Previous week, All time, dan beberapa preset real-time | Pemeriksaan cepat |
| Relative | Rentang relatif yang kamu susun sendiri dalam satuan detik sampai hari, dihitung dari Now atau dari awal satuan, dengan pilihan snap-to. Bawaannya Earliest tanpa snap-to dan Latest = Now | Baseline dan perbandingan periode |
| Real-time | Hanya Earliest, karena Latest tidak berlaku. Butuh role Admin, dan search real-time berbarengan bisa memengaruhi kinerja indexing. Ketersediaannya berbeda antar jenis deployment | Pemantauan sesaat, hampir tidak pernah untuk investigasi |
| Date Range | Antara dua tanggal, sebelum, atau sejak tanggal tertentu | Investigasi berhari-hari |
| Date & Time Range | Tanggal dan jam untuk awal dan akhir | Rekonstruksi insiden |
| Advanced | Epoch atau notasi relatif seperti `-3d@d`; nilai epoch yang kamu masukkan dikonversi ke waktu lokal dan ditampilkan di bawah kolom untuk diperiksa | Menyalin rentang persis dari alat lain |

Rentang bawaan untuk search ad hoc di Search & Reporting adalah Last 24 hours [S1]. Dokumentasi juga mencatat bahwa untuk user di zona waktu berbeda, search berbasis waktu memakai timestamp event dari instance yang mengindeks data [S1].

Yang lebih penting untuk pekerjaan yang harus bisa diulang adalah time modifier di dalam search. Sintaksnya `earliest=<time_modifier> latest=<time_modifier>` [S2]:

- Rentang yang ditulis di search bar atau di sebuah saved search menimpa pilihan di time picker [S2]. Jadi bila search-mu memuat `earliest`, apa pun yang dipilih orang lain di time picker tidak mengubah hasil. Inilah cara membuat hasil bisa diulang.
- Format absolut yang diterima adalah `%m/%d/%Y:%H:%M:%S`, misalnya `earliest=10/12/2026:23:30:00 latest=10/13/2026:00:10:00` [S2].
- Bila hanya `earliest` yang disebut, `latest` dianggap `now`. Bila `latest` disebut, `earliest` wajib disebut juga [S2].
- Rentang relatif ditulis dengan tanda `-` atau `+`, angka, dan satuan: `s`, `m` (menit), `h`, `d`, `w`, `mon` (bulan), `q`, `y`. Satuan tanpa angka berarti satu [S2].
- Snap-to ditulis `[+|-]<angka><satuan>@<satuan>` dan selalu membulatkan ke belakang, ke batas terakhir yang tidak melewati waktu yang dimaksud. Pukul 15.45, `earliest=-h@h` menjadi pukul 14.00 [S2]. Tanpa satuan snap, pembulatannya ke detik [S2].
- Hari dalam minggu memakai `@w0` (Minggu) sampai `@w6` (Sabtu), dan `w7` juga berarti Minggu [S2]. Bulan lalu ditulis `earliest=-mon@mon latest=@mon` [S2].
- Modifier berantai dievaluasi berurutan: `-mon@mon+7d` berarti mundur satu bulan, dibulatkan ke tanggal 1, lalu ditambah tujuh hari [S2].
- Rentang di time picker berlaku untuk subsearch kecuali search bar menyebut rentangnya sendiri; rentang di search utama tidak berlaku untuk subsearch, dan rentang di dalam subsearch hanya berlaku untuk subsearch itu [S2].

Untuk dataset statis, rentang relatif selalu salah. BOTS v1 adalah dataset latihan yang dibuat pada 2016, dipasang sebagai index `botsv1`, dan README resminya memakai contoh `index=botsv1 earliest=0` [S12]. Jadi urutan kerjanya: cari dulu rentang waktu aslinya, catat, lalu pakai rentang absolut di semua search berikutnya. Langkahnya ada di bagian 2.5.

### 1.6 Search mode dan fields sidebar

Pertanyaan keempat muncul pada hari pertama hampir semua orang: kenapa daftar field di kiri berubah-ubah, dan kenapa field yang jelas ada di `_raw` tidak muncul di sana.

Ada tiga search mode, dan Smart adalah bawaannya [S4]:

| Mode | Yang dilakukan | Akibatnya |
|---|---|---|
| Fast | Mengutamakan kecepatan, mengembalikan data event yang penting saja seperti default field dan indexed field. Field discovery mati, jadi tidak ada ekstraksi field search-time | Field yang disebut eksplisit di search tetap keluar; field lain tidak muncul di sidebar. Cocok untuk melihat sourcetype, source, atau host apa yang ada di sebuah index |
| Smart | Berganti perilaku sesuai jenis search. Search event biasa diperlakukan seperti Verbose dengan semua field ditemukan; search transforming diperlakukan seperti Fast | Pilihan bawaan untuk hampir semua search |
| Verbose | Mengembalikan semua field dan data event yang bisa didapat, termasuk ekstraksi otomatis dan buatan sendiri, serta tetap membuat daftar event dan timeline | Paling lengkap, paling lambat; report tidak bisa memakai report acceleration dalam mode ini |

Dua perilaku yang perlu diingat soal report [S4]: report yang dijalankan memakai mode yang berlaku saat search itu disimpan, dan report terjadwal memakai Smart dan tidak bisa diganti modenya. Jadi search yang kamu uji di Verbose bisa berperilaku lain begitu dijadikan report terjadwal.

Fields sidebar di sebelah kiri hasil search punya dua daftar [S5]:

- Selected Fields, yang ditampilkan di bawah setiap event. Saat search pertama dijalankan, isinya default field `host`, `source`, dan `sourcetype`.
- Interesting Fields, yaitu field yang muncul di minimal 20% event hasil search. Field di bawah ambang itu tidak hilang, hanya tidak masuk daftar; buka All Fields di atas sidebar untuk memilih field lain, dan dialognya juga memperlihatkan jumlah nilai unik per field.

Gabungan dua hal di atas menjelaskan gejala yang paling sering membingungkan: di mode Fast sidebar nyaris kosong karena field discovery mati, dan di mode Smart atau Verbose sebuah field yang hanya terisi di sebagian kecil event tetap tidak masuk Interesting Fields karena tidak mencapai 20%. Keduanya bukan bukti bahwa field itu tidak ada. Cara yang lebih jujur adalah bertanya ke data dengan `fieldsummary` atau `stats count` atas field yang kamu curigai, seperti di bagian 2.6.

Satu aturan sintaks yang berasal dari dokumentasi fields: nama field peka huruf besar-kecil, sedangkan nilainya tidak [S5]. `TargetUserName` dan `targetusername` adalah dua field berbeda, tetapi `adm.rina` dan `ADM.RINA` sebagai nilai di command `search` dianggap sama.

### 1.7 Search job: status, masa simpan, berbagi, dan ekspor

Permintaan ketiga SOC lead, "kirim search yang bisa saya buka, bukan screenshot", adalah soal job.

Setiap kali kamu menjalankan search, membuka report, atau memuat panel dashboard, Splunk membuat sebuah job [S7]. Job itu punya hasil yang disimpan di disk, status, dan masa simpan.

Yang perlu kamu kuasai sebagai analyst:

- **Masa simpan.** Job disimpan selama job lifetime-nya. Bawaannya 10 menit, dihitung dari saat job dijalankan [S7][S9]. Pilihan di Job > Edit Job Settings > Lifetime hanya dua: 10 menit atau 7 hari [S9]. Mengakses job yang masih aktif mengulang hitungan masa simpannya dari saat itu; job yang sudah kedaluwarsa tidak bisa diperpanjang [S9].
- **Job search terjadwal** disimpan dua kali interval jadwalnya; search yang berjalan tiap 6 jam menyimpan job-nya 12 jam. Ini diatur `dispatch.ttl`, bawaannya `2p` [S9].
- **Berbagi.** Job bawaannya privat [S8]. Membagikan link job memperpanjang masa simpannya menjadi 7 hari dan mengubah read permission menjadi Everyone [S7][S8]. Perhatian: "Everyone" di sini berarti semua pengguna Splunk yang bisa membaca job, sehingga hasil search atas index sensitif ikut terbuka. Untuk data yang dibatasi, lebih baik kirim teks SPL-nya dan biarkan penerima menjalankannya dengan haknya sendiri (Day 44).
- **Ekspor.** Dari halaman job, hasil bisa diekspor dalam beberapa format, antara lain CSV, JSON, PDF, Raw Events, dan XML; pilihan yang tersedia tergantung jenis artefak job-nya [S8].
- **Mengelola job.** Di Splunk Web, daftar job ada di Activity > Jobs [S8]. Dari sana job bisa dibuka di Search & Reporting, diperiksa, diubah setelannya, diperpanjang, diekspor, dibagikan, atau dihapus; pause dan stop punya ikon sendiri [S8]. Menu Job di halaman search sendiri memuat Edit Job Settings, Send Job to Background, Inspect Job, dan Delete Job [S7].
- **Job yang dikirim ke background** terus berjalan walau komputermu masuk mode sleep atau hibernate [S7]. Ini cara menjalankan search panjang di akhir shift tanpa menahan layar.
- **Kuota disk.** Hasil job memakai disk, dan batasnya diatur per role lewat `srchDiskQuota` di `authorize.conf`, dengan bawaan 100MB [S7]. Karena itu kebiasaan menjalankan search All time lalu membiarkan banyak job 7 hari bisa membuat search-mu sendiri gagal karena kuota penuh.

Inspect Job membuka Search Job Inspector, tempat melihat metrik dan biaya eksekusi job [S7]. Day 14 memakainya untuk mengukur dan memperbaiki search; di Day ini cukup tahu itu pintu yang sama.

### 1.8 Sintaks dasar yang menentukan apakah filter-mu menyaring

Bagian ini menutup lubang terakhir: beberapa aturan kecil di command `search` yang membuat dua search yang terlihat sama memberi hasil berbeda.

Command `search` tersirat di awal setiap search, jadi tidak perlu ditulis di posisi itu; ia juga bisa dipakai lagi di tengah pipeline untuk menyaring hasil sebelumnya [S14]. Aturan yang paling sering menjatuhkan orang [S14]:

- **Tanda kutip dan escape.** Tanda kutip harus berpasangan. Frasa dan nilai yang memuat spasi atau karakter khusus perlu dikutip, dan kutip juga dipakai bila kamu ingin mencari kata yang kebetulan punya arti khusus di SPL. Backslash dipakai untuk escape; urutan `\|` mengirim karakter pipe ke command, bukan memecah pipeline.
- **Wildcard.** Wildcard `*` boleh dipakai pada nilai field dan sebagai kata, misalnya `host=JKT-WS-0*` atau `fail*`.
- **Operator `IN`.** `status IN (400, 402, 404, 500)` lebih ringkas daripada rantai `OR`, dan di command `search` nilainya boleh memakai wildcard. Wildcard tidak boleh dipakai pada daftar nilai fungsi `in()` di `eval` dan `where` [S14][S15]. Beda kecil ini dibahas lagi di Day 02.
- **Urutan evaluasi boolean.** Di command `search`, urutannya tanda kurung, lalu `NOT`, lalu `OR`, lalu `AND`, dan `search` tidak mendukung `XOR` [S14]. Urutan ini berbeda dari `eval` dan `where`, jadi biasakan memakai tanda kurung eksplisit untuk kondisi campuran. Operator `AND`, `OR`, dan `NOT` ditulis huruf besar; nama command sendiri tidak perlu huruf besar.
- **`NOT` bukan `!=`.** `NOT fieldA=*` mengembalikan event yang `fieldA`-nya null atau tidak ada, sedangkan `fieldA!=*` tidak pernah mengembalikan apa pun [S14]. Secara umum `NOT` membuang event yang cocok termasuk event yang tidak punya field itu, sedangkan `!=` menuntut field-nya ada dengan nilai berbeda. Perbandingan lengkapnya di Day 14.
- **Huruf besar-kecil.** Kata kunci dicari tanpa membedakan huruf besar-kecil; directive `CASE()` dipakai bila kamu butuh pencocokan yang peka huruf [S14]. Nama field tetap peka huruf besar-kecil [S5].

## 2. Contoh SPL dan langkah praktis

Semua keluaran di bagian ini adalah keluaran ilustrasi, bukan hasil eksekusi. Asumsi PT JAB: Splunk Enterprise 10.6, app Search & Reporting tanpa ES, index sesuai tabel di bagian 1.2, akun di role `soc_analyst`, zona waktu akun WIB, dan indexer berada di Jakarta. Rentang waktu ditulis eksplisit di setiap search supaya hasilnya bisa diulang orang lain.

### 2.1 Inventaris: data apa yang masuk, dari mana, dan sejak kapan

Ini jawaban untuk permintaan pertama SOC lead, dan sekaligus cara memastikan DNS pelanggan yang ditanya NOC benar-benar masuk.

**Tujuan:** melihat kombinasi index, sourcetype, dan host yang benar-benar ada, beserta event pertama dan terakhir per kombinasi.

```
index=dns earliest=-24h latest=now
| stats count min(_time) AS pertama max(_time) AS terakhir dc(host) AS jumlah_host
        values(host) AS contoh_host BY sourcetype
| eval pertama=strftime(pertama, "%Y-%m-%d %H:%M:%S"), terakhir=strftime(terakhir, "%Y-%m-%d %H:%M:%S")
| sort - count
```

| Bagian | Penjelasan |
|---|---|
| `index=dns earliest=-24h latest=now` | Index disebut eksplisit supaya tidak bergantung pada daftar index default role, dan rentang ditulis di search supaya tidak bergantung time picker [S2][S11] |
| `min(_time)` dan `max(_time)` | Menjawab "sejak kapan" dan "sampai kapan" per sourcetype |
| `dc(host)` dan `values(host)` | Jumlah host unik dan daftar nama host; `values()` mengembalikan nilai distinct terurut secara leksikografis [S16] |
| `strftime(...)` | `stats` menyimpan waktu sebagai epoch, jadi perlu diformat agar terbaca |

Keluaran ilustrasi:

```
sourcetype              count       pertama              terakhir             jumlah_host  contoh_host
dns_resolver_pelanggan  412980551   2026-10-13 06:00:02  2026-10-14 05:59:58  6            jkt-res01 jkt-res02 ...
dns_resolver_karyawan   18450220    2026-10-13 06:00:01  2026-10-14 05:59:59  2            jkt-dns01 jkt-dns02
```

**Cara membaca hasil:** dua sourcetype berbeda hidup di satu index, dan yang volumenya besar adalah resolver pelanggan. Jawaban untuk NOC: datanya masuk dan tidak terputus dalam 24 jam terakhir, jadi lonjakan pukul 02.00 di dashboard mereka layak ditelusuri sebagai perilaku, bukan sebagai celah data. Perhatikan juga bahwa dua sourcetype ini punya nama field yang bisa berbeda, sehingga search lintas keduanya harus diuji di masing-masing.
**Variasi:** ganti `BY sourcetype` menjadi `BY index sourcetype` dan hapus filter index untuk melihat gambaran seluruh deployment. Lakukan hanya dengan rentang pendek, misalnya `earliest=-15m`, karena search ini membaca event.
**Kapan gagal:** di index bervolume besar, rentang 24 jam bisa berat dan memakan kuota search. Cara murah untuk inventaris rutin adalah membaca metadata index tanpa menyentuh event, yang dibahas bersama `tstats` (Day 25 bagian 1.1). Index yang tidak masuk daftar index yang boleh dicari role-mu akan terlihat seolah tidak ada; minta daftar hak akses role-mu bila sebuah index yang kamu tahu ada tidak pernah muncul [S11].

### 2.2 Mengukur ingest lag dengan `_indextime`

Sebelum menjelaskan tiket SOC-2026-0198, ukur dulu seberapa terlambat data sampai. Ini satu-satunya cara memakai `_indextime`, karena field itu tersembunyi [S6].

**Tujuan:** melihat lag ingest per sourcetype dan host dalam satuan detik.

```
index=vpn earliest=-24h latest=now
| eval lag_detik = _indextime - _time
| stats count avg(lag_detik) AS lag_rata max(lag_detik) AS lag_maks
        perc95(lag_detik) AS lag_p95 BY sourcetype host
| eval lag_rata=round(lag_rata, 1), lag_p95=round(lag_p95, 1)
| sort - lag_maks
```

- `_indextime - _time`: keduanya epoch, jadi selisihnya langsung dalam detik.
- `perc95(lag_detik)`: nilai yang tidak dilewati 95% event, lebih berguna daripada rata-rata karena lag biasanya tidak merata.
- `BY sourcetype host`: lag hampir selalu masalah per jalur pengiriman, bukan per deployment.

Keluaran ilustrasi:

```
sourcetype   host           count    lag_rata  lag_maks  lag_p95
vpn_gateway  jkt-vpn01      182440   6.4       2051      31.0
vpn_gateway  jkt-vpn02      176905   5.9       28        12.0
```

**Cara membaca hasil:** lag biasa di jalur ini beberapa detik, tetapi `jkt-vpn01` pernah mencatat 2.051 detik, sekitar 34 menit. Itu cukup untuk menjelaskan tiket SOC-2026-0198: event pukul 23.40 baru tersimpan setelah pukul 00.12, sehingga search 15 menit terakhir yang dijalankan pukul 23.45 tidak mungkin menemukannya. Angka ini juga yang dipakai untuk menentukan jeda penjadwalan alert di index itu (Day 09).
**Variasi:** ganti `BY sourcetype host` dengan `BY index` dan hapus filter index untuk membandingkan jalur ingest antar sumber, memakai rentang pendek.
**Kapan gagal:** bila timestamp event salah di-parse, lag bisa terlihat negatif atau sangat besar. Lag negatif berarti `_time` lebih baru daripada `_indextime`, yang biasanya gejala zona waktu salah diasumsikan saat ingest [S3], bukan gejala jaringan.

### 2.3 Membuka ulang event tiket SOC-2026-0198 dengan rentang absolut

Sekarang ambil event yang dimaksud dengan rentang yang bisa diulang siapa pun.

**Tujuan:** menampilkan event VPN di sekitar pukul 23.40 tanggal 12 Oktober 2026 beserta dua waktu yang membedakannya.

```
index=vpn earliest="10/12/2026:23:30:00" latest="10/13/2026:00:10:00" user=rina.wulandari
| eval waktu_kejadian=strftime(_time, "%Y-%m-%d %H:%M:%S"),
       waktu_masuk_splunk=strftime(_indextime, "%Y-%m-%d %H:%M:%S"),
       lag_detik=_indextime - _time
| table waktu_kejadian waktu_masuk_splunk lag_detik host user src action
| sort waktu_kejadian
```

- Rentang absolut memakai format `%m/%d/%Y:%H:%M:%S` [S2]. Dengan ini, hasilnya sama walau penerima membuka search pekan depan dengan time picker apa pun, karena modifier di search menimpa time picker [S2].
- Rentang dibuat lebih lebar daripada kejadian (23.30 sampai 00.10) supaya event tepat di tepi tidak terpotong.
- `user=rina.wulandari` sebagai nilai tidak peka huruf besar-kecil, tetapi nama field `user` peka [S5][S14].

Keluaran ilustrasi:

```
waktu_kejadian       waktu_masuk_splunk   lag_detik  host       user             src            action
2026-10-12 23:40:12  2026-10-13 00:12:40  1948       jkt-vpn01  rina.wulandari   203.0.113.45   success
```

**Cara membaca hasil:** satu event, dua waktu. Kejadiannya 23.40.12, masuk Splunk 00.12.40, selisih 1.948 detik atau 32 menit 28 detik. Catat dua waktu ini di tiket; itu jawaban langsung untuk "kenapa shift sebelumnya tidak menemukannya". Pelajaran operasionalnya: saat sebuah kejadian dilaporkan tidak ada, ulangi search dengan rentang lebih lebar dan periksa lag sebelum menyimpulkan data hilang.
**Variasi:** untuk kasus di mana kamu ingin melihat apa yang baru masuk tanpa peduli kapan kejadiannya, pakai modifier berbasis waktu index. Nama modifier-nya perlu dicek di SPL Search Reference versi-mu sebelum dipakai di alert, karena perilakunya berbeda dari `earliest` dan `latest` biasa.
**Kapan gagal:** nama field `user` dan `src` berbeda antar add-on VPN. Bila hasilnya nol, hapus dulu filter field dan cari dengan kata kunci (`index=vpn "rina.wulandari"`), lalu lihat field apa yang sebenarnya ada.

### 2.4 Snap-to untuk rekap yang maknanya tetap

Rekap shift dan rekap harian butuh rentang yang artinya sama setiap kali dijalankan, bukan "24 jam terakhir dihitung dari sekarang".

**Tujuan:** menghitung koneksi VPN sukses dan gagal untuk kemarin penuh, dari pukul 00.00 sampai 00.00.

```
index=vpn earliest=-1d@d latest=@d
| stats count BY action
```

| Modifier | Artinya | Kapan dipakai |
|---|---|---|
| `earliest=-1d@d latest=@d` | Kemarin penuh, pukul 00.00 sampai 00.00 | Rekap harian yang bisa dibandingkan antar hari |
| `earliest=@d` | Sejak tengah malam hari ini | Rekap shift pagi |
| `earliest=-7d@d latest=@d` | Tujuh hari penuh terakhir, tanpa hari ini | Baseline mingguan |
| `earliest=-mon@mon latest=@mon` | Bulan kalender lalu [S2] | Laporan bulanan ke SOC lead |
| `earliest=@w1 latest=now` | Sejak Senin pukul 00.00 [S2] | Rekap pekan berjalan |
| `earliest=-1h@h latest=@h` | Satu jam penuh terakhir | Perbandingan per jam tanpa jam berjalan yang belum lengkap |

- Snap-to selalu membulatkan ke belakang: pukul 15.45, `-h@h` menjadi 14.00 [S2].
- Modifier berantai dievaluasi berurutan, misalnya `@d-2h` berarti awal hari ini lalu mundur dua jam, yaitu pukul 22.00 malam sebelumnya [S2].

Keluaran ilustrasi:

```
action    count
success   3124
failure   908
```

**Cara membaca hasil:** angka ini bisa dibandingkan dengan hari sebelumnya karena batasnya sama, sedangkan "Last 24 hours" yang dijalankan pukul 09.17 dan pukul 14.02 tidak bisa dibandingkan.
**Kapan gagal:** batas `@d` jatuh di tengah malam menurut zona waktu user, bukan epoch [S3]. Bila rekanmu di POP lain memakai zona waktu akun yang berbeda, angka rekapnya akan berbeda walau SPL-nya sama. Sebut zona waktunya di tiket, dan untuk laporan yang diaudit pakai rentang absolut.

### 2.5 Dataset latihan BOTS v1: cari rentangnya dulu

Latihan di catatan ini memakai BOTS v1, yang datanya dari 2016 [S12]. Rentang relatif tidak akan pernah menemukan apa pun di sana.

**Tujuan:** menentukan rentang waktu asli dataset, lalu memakainya sebagai rentang absolut.

```
| tstats min(_time) AS awal max(_time) AS akhir count WHERE index=botsv1 BY sourcetype
| eval awal=strftime(awal, "%Y-%m-%d %H:%M:%S"), akhir=strftime(akhir, "%Y-%m-%d %H:%M:%S")
| sort - count
```

- Search ini dimulai dengan pipe karena `tstats` membaca metadata index, bukan event, sehingga murah walau datanya besar. Cara kerjanya dibahas di Day 25 bagian 1.1.
- Alternatif tanpa `tstats`, sesuai contoh di README dataset: `index=botsv1 earliest=0 | stats min(_time) AS awal max(_time) AS akhir BY sourcetype` [S12]. `earliest=0` berarti sejak epoch 0, yaitu semua waktu.

Keluaran ilustrasi (nilai sebenarnya ditentukan dari lab-mu, bukan dari catatan ini):

```
sourcetype                  awal                 akhir                count
stream:http                 ...                  ...                  ...
WinEventLog:Security        ...                  ...                  ...
```

**Cara membaca hasil:** catat `awal` dan `akhir` sebagai rentang tetap, lalu tulis semua search latihan dengan rentang absolut itu, misalnya `earliest="08/10/2016:00:00:00" latest="08/26/2016:00:00:00"` setelah kamu memastikan tanggalnya di lab. Simpan catatannya; setiap Day yang memakai BOTS akan memakai rentang yang sama.
**Kapan gagal:** `tstats` membaca summary dan indexed field, jadi hasilnya bergantung pada apa yang tersedia; bila hasilnya kosong, pakai versi `earliest=0`. Jangan pernah memakai `earliest=0` untuk index produksi PT JAB: itu berarti memindai seluruh retensi.

### 2.6 Membuktikan sebuah field benar-benar ada

Pertanyaan keempat SOC lead sering muncul sebagai keluhan: "field-nya tidak ada di sidebar". Search ini menjawabnya dengan angka, bukan dengan tampilan.

**Tujuan:** memeriksa apakah sebuah field terisi, di berapa persen event, dan dengan nilai seperti apa.

```
index=proxy earliest=-1h latest=now
| fieldsummary maxvals=5
| table field count distinct_count values
| sort - count
```

Versi yang lebih langsung untuk satu field yang kamu curigai:

```
index=proxy earliest=-1h latest=now
| eval ada=if(isnull(user), "kosong", "terisi")
| stats count BY sourcetype ada
```

- `fieldsummary` merangkum field yang ditemukan di hasil search, beserta jumlah event yang mengisinya dan contoh nilainya. Jalankan di mode Smart atau Verbose; di mode Fast ekstraksi field search-time tidak dijalankan sehingga hasilnya menyesatkan [S4].
- Versi kedua memisahkan "field tidak ada" dari "field ada tetapi kosong", yang akan sering kamu butuhkan saat menilai kelayakan sebuah sumber data.

Keluaran ilustrasi untuk versi kedua:

```
sourcetype       ada       count
proxy_squid      terisi    184220
proxy_squid      kosong    31
proxy_bluecoat   kosong    20114
```

**Cara membaca hasil:** field `user` terisi di satu sourcetype dan kosong di sourcetype lain di index yang sama. Angka 20.114 event tanpa `user` menjelaskan kenapa `user` bisa tidak masuk Interesting Fields pada search yang mencampur keduanya: ambangnya 20% event hasil search [S5]. Kesimpulan untuk pekerjaan: search yang mengandalkan `user` harus menyebut sourcetype-nya, atau menunggu normalisasi field dari add-on (Day 23).
**Variasi:** jalankan search yang sama dalam mode Fast lalu bandingkan sidebar dan hasil `fieldsummary`-nya. Itu demonstrasi tercepat tentang arti field discovery.
**Kapan gagal:** `fieldsummary` ikut menghitung field hasil ekstraksi otomatis yang namanya mirip, sehingga daftarnya bisa panjang dan membingungkan. Batasi dengan `| fields user* src*` sebelum `fieldsummary`, atau pakai versi kedua.

### 2.7 Menyerahkan hasil: job, bukan screenshot

Permintaan terakhir SOC lead. Langkah di bawah dijalankan di Splunk Web, dan nama menunya perlu dicocokkan dengan versi di instance-mu.

1. Jalankan search final dengan rentang absolut di dalam search, bukan dari time picker, supaya penerima mendapat hasil yang sama [S2].
2. Buka Job > Edit Job Settings. Ubah Lifetime menjadi 7 days bila hasilnya perlu dibuka besok, karena bawaannya hanya 10 menit dari saat job dijalankan [S7][S9].
3. Di dialog yang sama ambil Job URL bila ingin mengirim tautan. Membagikan tautan job memperpanjang masa simpannya menjadi 7 hari dan mengubah read permission menjadi Everyone [S7][S8]. Untuk hasil dari index sensitif, lewati langkah ini dan kirim teks SPL-nya saja.
4. Untuk lampiran tiket, ekspor hasil dari halaman job. Format yang tersedia antara lain CSV, JSON, PDF, Raw Events, dan XML, tergantung jenis artefak job [S8].
5. Bila search-nya panjang, pilih Send Job to Background supaya tetap berjalan walau laptopmu masuk sleep, lalu ambil hasilnya dari Activity > Jobs [S7][S8].
6. Bersihkan job lama yang tidak perlu dari Activity > Jobs. Hasil job memakai kuota disk per role, bawaannya 100MB [S7].

**Isi yang ditulis di tiket SOC-2026-0198:** satu kalimat kesimpulan ("event ada, tidak hilang; penyebab laporan 'tidak ada' adalah ingest lag 1.948 detik di jalur `jkt-vpn01`"), teks SPL lengkap dengan rentang absolutnya, dua waktu dari bagian 2.3, dan angka lag dari bagian 2.2. Dengan itu orang lain bisa mengulang pemeriksaanmu tanpa bertanya.

## 3. Lab praktik (di VM lab terisolasi)

Lab memakai satu instance Splunk Enterprise di VM lab milikmu, dataset BOTS v1, dan satu file log kecil yang kamu buat sendiri. Jangan memakai log dari pekerjaan.

1. **Inventaris instance-mu.** Jalankan versi bagian 2.1 untuk setiap index yang ada di lab. Catat index, sourcetype, host, dan rentang waktu datanya dalam satu tabel.
2. **Rentang BOTS v1.** Jalankan dua versi di bagian 2.5 (`tstats` dan `earliest=0`). Catat rentang waktu yang dihasilkan, lalu buktikan bahwa `index=botsv1 earliest=-7d` mengembalikan nol hasil. Simpan rentang absolutnya sebagai catatan tetap.
3. **Lag ingest buatan.** Buat file teks berisi 20 baris log bergaya syslog dengan timestamp satu jam yang lalu, lalu masukkan lewat Add Data > Upload. Setelah masuk, jalankan versi bagian 2.2 dan pastikan `lag_detik` kira-kira 3.600. Ini membuktikan `_time` berasal dari isi event, bukan dari waktu upload.
4. **Sourcetype salah.** Masukkan file yang sama dua kali: sekali dengan sourcetype yang cocok, sekali dengan sourcetype lain yang jelas tidak cocok (misalnya `access_combined`). Bandingkan `_time`, jumlah event (`linecount`), dan field yang muncul di sidebar. Tulis satu paragraf tentang apa yang rusak dan apa yang tidak.
5. **Zona waktu.** Catat zona waktu akunmu, jalankan `index=<index lab> earliest=@d | stats count min(_time) max(_time)`, lalu ubah zona waktu akun (atau pakai akun uji kedua dengan zona berbeda) dan jalankan ulang search yang sama. Bandingkan hasilnya dengan search yang memakai rentang absolut. Catat selisihnya.
6. **Search mode.** Jalankan satu search event yang sama di Fast, Smart, dan Verbose. Catat tiga hal per mode: jumlah Interesting Fields, apakah field hasil ekstraksi search-time muncul, dan waktu eksekusi dari Job Inspector.
7. **Ambang 20%.** Buat kondisi di mana sebuah field hanya terisi di sebagian kecil event (misalnya gabungkan dua sourcetype dalam satu search), lalu buktikan field itu tidak masuk Interesting Fields walau `stats count` menunjukkan ia ada. Ulangi dengan proporsi di atas 20%.
8. **Job.** Jalankan satu search, ubah Lifetime menjadi 10 menit, tunggu sampai kedaluwarsa, dan catat apa yang terjadi saat tautannya dibuka. Ulangi dengan 7 hari. Bagikan satu job ke akun uji kedua dan periksa apakah akun itu bisa membukanya. Terakhir, ekspor hasil ke CSV dan periksa apakah kolomnya sesuai dengan yang di layar.
9. **Sintaks.** Buktikan di data lab-mu: `user=Admin` dan `user=admin` memberi hasil sama, sedangkan `User=admin` dan `user=admin` tidak; `NOT user=*` dan `user!=*` memberi hasil berbeda; `status IN (40*, 50*)` jalan di command `search`.

**Hasil yang sebaiknya tersimpan:**

- Tabel inventaris index, sourcetype, host, dan rentang waktu untuk instance lab-mu.
- Rentang waktu absolut BOTS v1 yang sudah diverifikasi.
- Catatan `lag_detik` dari file yang kamu upload sendiri.
- Perbandingan `_time` dan jumlah event untuk dua sourcetype pada file yang sama.
- Dua hasil search `@d` dari dua zona waktu, beserta hasil versi rentang absolutnya.
- Tabel tiga search mode dengan jumlah Interesting Fields dan waktu eksekusi.
- Catatan perilaku job: kedaluwarsa, berbagi, dan ekspor.
- Satu halaman berisi aturan sintaks yang kamu buktikan sendiri.

**Variasi tantangan:** tulis satu search yang bisa kamu tempel di tiket mana pun untuk menjawab "apakah data sumber X masuk dan sampai kapan", dengan rentang absolut dan tanpa field yang hanya ada di satu sourcetype. Lalu jalankan di lab dan ukur biayanya di Job Inspector; bila mahal, tulis versi murahnya setelah membaca Day 25.

## 4. Troubleshooting

Tabel ini untuk saat hasil search tidak seperti yang kamu harapkan. Mulai dari kolom gejala, dan perhatikan bahwa hampir semua baris berakhir pada satu dari empat keputusan di Ide inti.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Search mengembalikan nol hasil padahal kejadiannya pasti ada | Rentang waktu terlalu sempit dibandingkan ingest lag | Lebarkan rentang, lalu ukur lag dengan `_indextime - _time` (bagian 2.2) |
| Event baru muncul berjam-jam kemudian | Antrean forwarder, pengumpulan API per interval, relay syslog terhenti | Ukur lag per host dan sourcetype; eskalasi ke pemilik jalur ingest |
| Data ada di wiki tetapi tidak ada di search | Index belum dibuat saat routing (event dibuang), atau role tidak boleh mencari index itu | Cek inventaris bagian 2.1; minta daftar index yang boleh dicari role-mu [S11] |
| Search tanpa `index=` memberi jumlah berbeda antar analyst | Daftar index default berbeda per role | Selalu sebut `index=` di search yang dibagikan [S11] |
| Satu kejadian terpecah menjadi banyak event, atau sebaliknya | Sourcetype salah, aturan pemecahan event tidak cocok | Bandingkan `linecount` dan `_raw`; cek sourcetype input (Day 28) [S10] |
| `_time` meleset berjam-jam | Timestamp tanpa zona waktu diasumsikan zona instance, atau salah di-parse | Bandingkan `_time` dengan isi `_raw`; perbaikan di sisi ingest [S3] |
| `lag_detik` negatif | Zona waktu salah diasumsikan saat ingest | Cek pengaturan zona waktu per source [S3] |
| Field yang jelas ada di `_raw` tidak muncul di sidebar | Mode Fast (field discovery mati), atau field terisi di bawah 20% event | Ganti ke Smart atau Verbose; buktikan dengan `fieldsummary` atau `stats` (bagian 2.6) [S4][S5] |
| Search dengan nama field tidak cocok, padahal nilainya benar | Nama field peka huruf besar-kecil | Cocokkan nama persisnya dari sidebar atau `fieldsummary` [S5] |
| Rekap harian berbeda antara dua analyst | Rentang berbasis kalender mengikuti zona waktu user | Pakai rentang absolut untuk laporan [S3] |
| Hasil yang dibagikan tidak bisa dibuka rekan | Job sudah kedaluwarsa (bawaan 10 menit) atau masih privat | Ubah Lifetime ke 7 days, atau bagikan tautannya [S7][S8][S9] |
| Search gagal dengan keluhan kuota disk | Terlalu banyak job besar yang masih disimpan | Hapus job lama di Activity > Jobs; `srchDiskQuota` per role bawaannya 100MB [S7] |
| Search di dataset latihan selalu kosong | Rentang relatif pada dataset statis | Tentukan rentang absolutnya dulu (bagian 2.5) [S12] |
| Report terjadwal berperilaku berbeda dari saat diuji | Report terjadwal memakai Smart dan tidak bisa diganti modenya | Uji ulang search-nya dalam mode Smart [S4] |

## 5. Kesalahan umum dan jebakan

- Menyimpulkan "tidak ada di Splunk" dari satu search bertenggang waktu pendek. Nol hasil adalah pernyataan tentang filter-mu, bukan tentang dunia. Periksa rentang, index, sourcetype, dan nama field dulu.
- Menyamakan `_time` dengan waktu data masuk. Keduanya berbeda, dan `_indextime` tidak akan terlihat sampai kamu memakainya di `eval` [S6].
- Memakai rentang relatif pada dataset statis. Semua latihan BOTS harus memakai rentang absolut [S12].
- Mengandalkan time picker untuk search yang dibagikan. Modifier di dalam search menimpa time picker, jadi tulis rentangnya di search bila hasilnya harus bisa diulang [S2].
- Memakai "Last 24 hours" untuk rekap yang dibandingkan antar hari. Batasnya bergerak mengikuti jam kamu menjalankan search; pakai `-1d@d` sampai `@d`.
- Melupakan zona waktu pada rentang berbasis kalender. "Today" dan `@d` mengikuti zona waktu user, sedangkan rentang relatif tidak [S3].
- Menilai ketersediaan field dari sidebar. Interesting Fields hanya memuat field yang muncul di minimal 20% event hasil search, dan mode Fast mematikan ekstraksi field search-time [S4][S5].
- Mencari dengan nama field yang hurufnya tidak persis. Nama field peka huruf besar-kecil; nilainya tidak [S5].
- Memakai `!=` untuk membuang event. `fieldA!=*` tidak pernah mengembalikan apa pun, dan `!=` juga membuang event yang tidak punya field itu; `NOT` berperilaku lain [S14].
- Menyebut satu sumber log dengan sourcetype tunggal tanpa memeriksanya. Satu index bisa memuat beberapa sourcetype dengan nama field berbeda (bagian 2.1 dan 2.6).
- Membagikan job yang berisi hasil dari index sensitif. Berbagi tautan job mengubah read permission menjadi Everyone [S7][S8].
- Menyerahkan screenshot sebagai bukti. Screenshot tidak menyimpan rentang waktu, SPL, maupun nama index, sehingga tidak bisa diulang.
- Membiarkan banyak job 7 hari. Hasil job memakai kuota disk per role [S7].
- `[komunitas, belum terkonfirmasi]` Ambang 20% untuk Interesting Fields sering disebut bisa diubah lewat pengaturan, dan sebagian praktisi juga menyebut field tetap bisa dilihat lewat All Fields walau di bawah ambang. Bagian All Fields memang tercantum di dokumentasi [S5]; kemungkinan mengubah ambangnya tidak dikonfirmasi oleh halaman resmi yang dibuka untuk Day ini, jadi perlakukan ambang 20% sebagai perilaku bawaan dan uji di lab bila instance-mu berbeda.

## 6. Catatan terkini

Bagian ini menampung versi dan tanggal halaman dokumentasi yang dipakai. Tidak ada yang mengubah cara kerja search di atas, tetapi nama menu dan beberapa detail berbeda antar versi.

- Dokumentasi Splunk kini dibaca di help.splunk.com, dan nomor versi halaman tidak selalu sejalan dengan versi produk terbaru. Halaman SPL Search Reference dan Search Tutorial sudah tersedia untuk 10.6 (diperbarui 9 September 2026 dan 25 Agustus 2026), sedangkan beberapa halaman Search Manual yang dipakai di Day ini masih terbit sebagai 10.4 (16 Mei 2026), 10.2 (9 Januari 2026), 10.0 (18 Juli 2025), dan 9.4 (3 Juli 2025) [S1][S2][S3][S4][S5][S8][S9][S14].
- Nama halaman daftar job berbeda antar versi: halaman 10.2 menyebut jalur Activity > Jobs, sedangkan halaman 10.4 menyebut Job Management page [S7][S8]. Cek nama yang dipakai di instance-mu.
- Halaman 10.4 menyebut autopause menyala secara bawaan hanya untuk klik dari summary dashboard, dengan batas 30 detik sebelum job dihentikan sementara [S7].
- Ketersediaan search real-time berbeda antar jenis deployment, dan di Splunk Cloud ada perbedaan antara Victoria dan Classic experience; search real-time juga butuh role Admin [S1].
- Daftar preset di time picker berasal dari `times.conf` dan bisa disesuaikan administrator, termasuk menonaktifkan preset tertentu [S1]. Jangan berasumsi preset di instance orang lain sama dengan punyamu.
- Beberapa index yang didaftar dokumentasi ES 8.7 tidak lagi dipakai di rilis itu (`ioc`, `cim_summary`), dan `ubaroute` tidak memuat event [S13]. Daftar index ES juga berubah mengikuti app yang dipasang.
- BOTS v1 dibuat dengan Splunk Enterprise 6.5.2 dan add-on yang sudah lama, antara lain Splunk Add-on for Microsoft Windows 4.8.3, dan dirilis dengan lisensi CC0 [S12]. Karena itu nama sourcetype di dataset ini berbeda dari add-on modern (Day 03).

## 7. Cheat sheet

```
EMPAT KEPUTUSAN     index | sourcetype | rentang waktu | search mode

LABEL BAWAAN        internal: _raw _time _indextime _cd _bkt
                    default : host index linecount punct source sourcetype splunk_server timestamp
_time               waktu kejadian (disimpan UTC, ditampilkan sesuai zona user)
_indextime          waktu masuk Splunk; TERSEMBUNYI -> hanya terlihat lewat eval/rename
LAG                 | eval lag_detik = _indextime - _time

INDEX               alasan dipisah: hak akses | retensi | kecepatan
                    index belum ada saat routing -> event DIBUANG
                    tanpa index= -> ikut daftar index default role

TIME MODIFIER       earliest=... latest=...   (menimpa time picker)
absolut             earliest="10/12/2026:23:30:00"   format %m/%d/%Y:%H:%M:%S
relatif             -60m  -24h  -7d   satuan: s m h d w mon q y
snap-to             @d awal hari | @h awal jam | @w1 Senin | @mon awal bulan
                    kemarin penuh: -1d@d sampai @d
                    bulan lalu   : -mon@mon sampai @mon
                    pukul 15.45 + -h@h -> 14.00 (selalu membulat ke belakang)
hanya earliest      latest dianggap now | latest tanpa earliest = error
dataset statis      cari rentangnya dulu (earliest=0), lalu pakai absolut

SEARCH MODE         Fast    : field discovery MATI, hanya default + indexed field
                    Smart   : bawaan; event seperti Verbose, transforming seperti Fast
                    Verbose : semua field, paling lambat, tanpa report acceleration
                    report terjadwal selalu Smart
SIDEBAR             Selected: host source sourcetype | Interesting: muncul di >= 20% event
                    buktikan field ada dengan fieldsummary atau stats, bukan sidebar

SINTAKS             nama field PEKA huruf, nilai TIDAK | CASE() untuk peka huruf
                    AND OR NOT huruf besar | search: ( ) lalu NOT lalu OR lalu AND
                    IN (a*, b*) boleh wildcard di command search
                    in() di eval/where TIDAK boleh wildcard
                    NOT field=*  -> event tanpa field itu | field!=*  -> selalu kosong
                    \| untuk mengirim karakter pipe

JOB                 bawaan hidup 10 menit | bisa diubah ke 7 hari
                    bagikan tautan -> 7 hari + read permission Everyone (hati-hati!)
                    terjadwal: dispatch.ttl 2p (dua kali interval)
                    Activity > Jobs: pause, stop, inspect, export (CSV JSON PDF Raw XML)
                    Send Job to Background untuk search panjang
                    srchDiskQuota per role, bawaan 100MB
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Shift malam PT JAB mencari koneksi VPN pukul 23.40 dengan rentang "Last 15 minutes" pada pukul 23.45 dan tidak menemukan apa pun. Ia menulis di tiket bahwa log VPN tidak masuk Splunk. Benarkah kesimpulannya?

<details><summary>Jawaban</summary>

Tidak. Rentang waktu di search menyaring menurut `_time`, yaitu waktu kejadian menurut isi event, sedangkan event baru bisa dicari setelah tersimpan, yang dicatat di `_indextime`. Pada kasus tiket SOC-2026-0198 selisihnya 1.948 detik, sehingga pukul 23.45 event itu memang belum ada di index walau `_time`-nya 23.40. Kesimpulan yang benar adalah "pada saat dicari, event belum masuk", dan buktinya diperoleh dengan `| eval lag_detik = _indextime - _time`. Lihat bagian 1.4 dan 2.2.

</details>

**2. Skenario keputusan.** Kamu harus membuat rekap jumlah koneksi VPN gagal "kemarin" yang akan dibandingkan antar hari oleh SOC lead. Rentang mana yang dipakai?

- A. Time picker "Last 24 hours", karena paling praktis.
- B. `earliest=-1d@d latest=@d` di dalam search.
- C. `earliest=-24h latest=now` di dalam search.

<details><summary>Jawaban</summary>

B. Snap-to `@d` membulatkan ke awal hari, sehingga rentangnya pukul 00.00 sampai 00.00 dan artinya sama setiap kali search dijalankan. A keliru karena batas rentangnya bergerak mengikuti jam kamu menjalankan search, sehingga dua rekap tidak bisa dibandingkan, dan pilihan time picker juga tidak ikut tersimpan saat SPL-nya dikirim ke orang lain. C punya masalah yang sama dengan A, hanya ditulis di dalam search. Catatan tambahan: rentang berbasis kalender seperti `@d` mengikuti zona waktu user, jadi sebutkan zonanya, dan untuk laporan yang diaudit pakai rentang absolut. Lihat bagian 1.5 dan 2.4.

</details>

**3. Pertanyaan jebakan.** "Field `user` tidak ada di fields sidebar, berarti sourcetype ini tidak punya field `user`." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Ada dua sebab lain yang lebih sering. Pertama, search mode Fast mematikan field discovery, sehingga tidak ada ekstraksi field search-time dan sidebar hanya berisi default field dan indexed field. Kedua, Interesting Fields hanya memuat field yang muncul di minimal 20% event hasil search, jadi field yang hanya terisi di sebagian kecil event tidak masuk daftar walau benar-benar ada. Cara menilainya adalah dengan angka: `fieldsummary`, atau `stats count` yang memisahkan event yang field-nya terisi dan kosong. Lihat bagian 1.6 dan 2.6.

</details>

**4. Skenario keputusan.** Kamu diminta menyerahkan hasil search ke SOC lead yang baru akan membukanya besok pagi. Hasilnya berasal dari index `wineventlog` yang aksesnya dibatasi. Apa yang kamu lakukan?

- A. Jalankan search, bagikan tautan job, dan beri tahu lewat chat.
- B. Screenshot tabel hasilnya dan tempel di tiket.
- C. Kirim teks SPL lengkap dengan rentang absolutnya di tiket, dan lampirkan ekspor hasil bila memang perlu.

<details><summary>Jawaban</summary>

C. Teks SPL dengan rentang absolut bisa dijalankan ulang oleh penerima dengan haknya sendiri, dan hasilnya akan sama karena modifier di dalam search menimpa time picker. A berisiko: membagikan tautan job mengubah read permission job menjadi Everyone dan memperpanjang masa simpannya tujuh hari, sehingga hasil dari index yang dibatasi ikut terbuka bagi pengguna lain. B tidak bisa diulang karena screenshot tidak menyimpan rentang waktu, SPL, maupun nama index; dan bila kamu hanya menjalankan search tanpa mengubah apa pun, job-nya sudah hilang setelah 10 menit. Lihat bagian 1.7 dan 2.7.

</details>

**5. Jelaskan ulang.** Jelaskan kepada rekan NOC, dalam tiga kalimat, beda index dan sourcetype, dan kenapa keduanya menentukan apakah ia menemukan datanya.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Index itu tempat event disimpan, sekaligus batas hak akses dan masa simpan; kalau akunmu tidak boleh mencari index `netops`, datanya ada tetapi tidak akan pernah muncul di hasilmu. Sourcetype itu format datanya, yang menentukan bagaimana event dipecah, bagaimana jam kejadiannya dibaca, dan field apa yang terekstrak; satu index bisa memuat beberapa sourcetype dengan nama field berbeda. Jadi sebelum menulis filter field, cek dulu index dan sourcetype apa yang benar-benar ada di datamu, karena search yang menyebut satu nama field bisa menemukan separuh data saja."

Kesalahan yang sering muncul:
- Menyamakan sourcetype dengan source. Source adalah nama file, stream, atau input asal event; sourcetype adalah format datanya.
- Menganggap index hanya soal penyimpanan, padahal index juga menentukan siapa yang boleh melihat dan berapa lama data disimpan.
- Lupa menyebut bahwa search tanpa `index=` mengikuti daftar index default role, sehingga dua orang bisa mendapat jumlah berbeda.

</details>

**6. Pertanyaan jebakan.** Seorang rekan menyalin contoh dari catatan latihan: `index=botsv1 sourcetype=stream:http earliest=-30d`, lalu melaporkan bahwa dataset BOTS v1 di lab rusak karena kosong. Apa yang sebenarnya terjadi?

<details><summary>Jawaban</summary>

Datanya tidak rusak; rentang waktunya yang salah. BOTS v1 adalah dataset statis dari 2016, jadi rentang relatif 30 hari terakhir tidak akan pernah memuat datanya. Urutan yang benar adalah menentukan dulu rentang asli dataset, misalnya dengan `index=botsv1 earliest=0 | stats min(_time) max(_time) BY sourcetype` atau versi `tstats`-nya, mencatat hasilnya, lalu memakai rentang absolut dengan format `%m/%d/%Y:%H:%M:%S` di semua search latihan. `earliest=0` hanya untuk dataset latihan; di index produksi itu berarti memindai seluruh retensi. Lihat bagian 1.5 dan 2.5.

</details>

**7. Interview question (English).** "A user reports that an event is missing from Splunk. How do you check whether the data is really not there?"

<details><summary>Sample answer</summary>

"I treat zero results as a statement about my filter, not about the world, so I work through four things. First the index: I confirm which index the source should land in, and whether my role is even allowed to search it, because an index the role can't search looks exactly like missing data. Second the source type, because that decides event breaking, timestamp parsing, and which fields exist, and one index often holds several source types with different field names. Third the time range: I widen it and compare the event's `_time` with `_indextime`, since ingest lag means an event that happened at 23:40 may only become searchable after midnight, and that alone explains most 'missing' events, including for scheduled alerts. Fourth the presentation layer: Fast mode turns off field discovery and the sidebar only lists fields present in at least twenty percent of results, so I verify a field exists with `fieldsummary` or a stats count rather than by looking at the sidebar. If all four check out, then the data really is absent, and at that point I look at the ingest path, including whether events were routed to an index that doesn't exist, because those get dropped."

What makes this answer strong: it refuses to accept zero results as evidence, separates the four independent causes, names the specific mechanism for each one, and ends at the ingest path instead of stopping at the search bar.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Splunk Enterprise 10.4 Search Manual: Select time ranges to apply to your search | https://help.splunk.com/en/splunk-enterprise/search/search-manual/10.4/specify-time-ranges/select-time-ranges-to-apply-to-your-search | primer | diperbarui 2026-05-16; diakses 2026-10-14 | Tinggi. Preset, relative, real-time, date range, advanced epoch, bawaan Last 24 hours, `times.conf` |
| S2 | Splunk Enterprise 10.4 Search Manual: Specify time modifiers in your search | https://help.splunk.com/en/splunk-enterprise/search/search-manual/10.4/specify-time-ranges/specify-time-modifiers-in-your-search | primer | diperbarui 2026-05-16; diakses 2026-10-14 | Tinggi. Sintaks `earliest`/`latest`, format absolut, snap-to, menimpa time picker, perilaku subsearch |
| S3 | Splunk Enterprise 9.4 Search Manual: How time zones are processed by the Splunk platform | https://help.splunk.com/en/splunk-enterprise/search/search-manual/9.4/specify-time-ranges/how-time-zones-are-processed-by-the-splunk-platform | primer | diperbarui 2025-07-03; diakses 2026-10-14 | Tinggi. Konversi ke epoch, asumsi zona waktu, beda rentang relatif dan rentang kalender |
| S4 | Splunk Enterprise 10.0 Search Manual: Search modes | https://help.splunk.com/en/splunk-enterprise/search/search-manual/10.0/using-the-search-app/search-modes | primer | diperbarui 2025-07-18; diakses 2026-10-14 | Tinggi. Fast, Smart, Verbose, field discovery, perilaku report terjadwal |
| S5 | Splunk Enterprise 10.6 Search Tutorial: Use fields to search | https://help.splunk.com/en/splunk-enterprise/get-started/search-tutorial/10.6/part-4-searching-the-tutorial-data/use-fields-to-search | primer | diperbarui 2026-08-25; diakses 2026-10-14 | Tinggi. Ambang 20% Interesting Fields, Selected Fields bawaan, All Fields, nama field peka huruf |
| S6 | Splunk Enterprise 10.4 Knowledge Management Manual: Use default fields | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.4/fields-and-field-extractions/use-default-fields | primer | diperbarui 2026-05-13; diakses 2026-10-14 | Tinggi. Daftar internal dan default field, `_time` UTC, `_indextime` tersembunyi |
| S7 | Splunk Enterprise 10.4 Search Manual: About jobs and job management | https://help.splunk.com/en/splunk-enterprise/search/search-manual/10.4/manage-jobs/about-jobs-and-job-management | primer | diperbarui 2026-05-16; diakses 2026-10-14 | Tinggi. Menu Job, masa simpan, berbagi, background job, `srchDiskQuota` 100MB, autopause |
| S8 | Splunk Enterprise 10.2 Search Manual: Manage search jobs | https://help.splunk.com/en/splunk-enterprise/search/search-manual/10.2/manage-jobs/manage-search-jobs | primer | diperbarui 2026-01-09; diakses 2026-10-14 | Tinggi. Jalur Activity > Jobs, aksi job, job privat secara bawaan, format ekspor |
| S9 | Splunk Enterprise 10.0 Search Manual: Extending job lifetimes | https://help.splunk.com/en/splunk-enterprise/search/search-manual/10.0/manage-jobs/extending-job-lifetimes | primer | diperbarui 2025-07-18; diakses 2026-10-14 | Tinggi. Bawaan 10 menit, pilihan 7 hari, `dispatch.ttl` `2p`, job kedaluwarsa tidak bisa diperpanjang |
| S10 | Splunk Enterprise 10.4 Getting Data In: Why source types matter | https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/10.4/configure-source-types/why-source-types-matter | primer | diperbarui 2026-05-13; diakses 2026-10-14 | Tinggi. Peran sourcetype pada timestamp dan pemecahan event, pengenalan otomatis, cara menimpa |
| S11 | Splunk Enterprise 10.0: Create custom indexes | https://help.splunk.com/en/data-management/manage-splunk-enterprise-indexers/10.0/manage-indexes/create-custom-indexes | primer | diperbarui 2025-07-18; diakses 2026-10-14 | Tinggi. Tiga alasan memisahkan index, index `main`, event dibuang bila index tidak ada, index default per role |
| S12 | GitHub splunk/botsv1 | https://github.com/splunk/botsv1 | primer | dataset 2016; diakses 2026-10-14 | Tinggi. Index `botsv1`, contoh `earliest=0`, lisensi CC0, versi Splunk dan add-on pembuat dataset |
| S13 | Splunk Enterprise Security 8.7: Configure and deploy indexes for Splunk Enterprise Security | https://help.splunk.com/en/splunk-enterprise-security-8/install/8.7/installation/configure-and-deploy-indexes-for-splunk-enterprise-security | primer | diperbarui 2026-09-01; diakses 2026-10-14 | Tinggi. Index milik ES (`notable`, `risk`, `threat_activity`), kebutuhan membuatnya di semua indexer |
| S14 | Splunk Enterprise 10.6 SPL Search Reference: search | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/search | primer | diperbarui 2026-09-09; diakses 2026-10-14 | Tinggi. `search` tersirat, operator `IN` dengan wildcard, kutip dan escape, urutan boolean, `NOT` vs `!=`, `CASE()` |
| S15 | Splunk Enterprise 10.6 SPL Search Reference: Comparison and Conditional functions | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/evaluation-functions/comparison-and-conditional-functions | primer | diperbarui 2026-09-09; diakses 2026-10-14 | Tinggi. Fungsi `in()` tidak menerima wildcard dan harus dibungkus `case`, `if`, atau `validate` |
| S16 | Splunk Enterprise 10.6 SPL Search Reference: Multivalue stats and chart functions | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/statistical-and-charting-functions/multivalue-stats-and-chart-functions | primer | diperbarui 2026-09-09; diakses 2026-10-14 | Tinggi. Sifat `values()` yang distinct dan terurut leksikografis |

**Catatan sumber:** halaman Search Manual untuk versi 10.6 tidak tersedia untuk semua topik saat riset, sehingga rentang waktu, search mode, dan job dirujuk dari halaman 10.4, 10.2, 10.0, dan 9.4 yang masih menjadi versi terbit dokumentasi itu; cocokkan nama menu dengan versi di instance-mu. Letak pengaturan zona waktu per user tidak diambil dari halaman yang dibuka untuk Day ini, jadi yang dinyatakan di bagian 1.4 hanya dampaknya terhadap rentang berbasis kalender, bukan letak menunya; cek pengaturannya di instance-mu. Rentang tanggal persis BOTS v1 tidak tercantum di README dataset, sehingga Day ini menyuruh menentukannya sendiri dengan `earliest=0` atau `tstats`, bukan menyebut tanggal. Perilaku `fieldsummary` di bagian 2.6 dipakai sebagai alat pemeriksa dan tidak dirujuk ke halaman command-nya; sintaks lengkapnya perlu dicek di SPL Search Reference versi-mu. Klaim bahwa ambang 20% Interesting Fields dapat diubah tidak dikonfirmasi sumber primer dan ditandai sebagai klaim komunitas di bagian 5.
