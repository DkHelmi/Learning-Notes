---
day: 09
title: 'Report, scheduled alert, throttle, dan dashboard tanpa ES'
researched_on: 2026-10-14
versions_checked: 'Splunk Enterprise 10.6 (Alerting Manual: Create scheduled alerts, Alert scheduling tips, Use cron expressions, Configure alert trigger conditions, Throttle alerts, Define alert suppression groups, Set up alert actions, Email notification action, Use a webhook alert action; halaman diperbarui 2026-08-25); Splunk Cloud Platform 10.6 Alerting Manual (Log events, 2026-08-25); Splunk Enterprise 10.6 Reporting Manual (Schedule reports, 2026-08-25); Splunk Enterprise 10.6 Knowledge Manager Manual (Manage knowledge object permissions, 2026-09-09); Splunk Enterprise 10.6 Dashboard Studio (What is Dashboard Studio 2026-05-05, Create a dashboard 2026-04-10, Chain searches 2026-04-20, Input configuration options 2026-09-13); Splunk Enterprise 10.6 Simple XML Dashboards (Getting started, 2026-09-13); Splunk Enterprise 10.6 release notes (rilis 2026-09-30, Deprecated and removed in version 10.6, 2026-07-30); Splunk Lantern "Preventing concurrency issues and skipped searches"'
---

# Day 09: Report, scheduled alert, throttle, dan dashboard tanpa ES

Cakupan: mengubah search yang berguna menjadi report terjadwal, scheduled alert dengan kondisi trigger dan throttle, alert action yang menghasilkan jejak, serta dashboard yang ringan, semuanya di Splunk Enterprise biasa tanpa Enterprise Security.

## Ide inti

Search yang bagus tetapi hanya hidup di kepala satu analyst tidak menambah kemampuan SOC. Yang menambah kemampuan adalah search yang berjalan sendiri pada jadwal yang jelas, mengirim hasilnya ke tempat yang dibaca orang, dan meninggalkan jejak yang bisa dihitung. Splunk Enterprise menyediakan tiga bentuk penyimpanan untuk itu: report (search tersimpan yang bisa dijadwalkan, dan aksinya berjalan setiap kali report jalan), alert (search terjadwal yang aksinya hanya berjalan ketika kondisi trigger terpenuhi), dan dashboard (panel yang dibaca sekilas saat shift dimulai). Ketiganya memakai mesin yang sama: scheduler, rentang waktu, dan hak akses.

Kualitas ketiganya ditentukan oleh empat hal yang gampang dilewatkan: jadwal yang selaras dengan rentang waktu search (supaya tidak ada event yang terlewat atau dihitung dua kali), kondisi trigger yang benar (sekali per jalan, atau sekali per hasil), throttle (supaya satu insiden tidak menjadi ratusan notifikasi), dan permission (supaya objeknya tidak mati ketika pembuatnya pindah).

Kamu sudah mengenal pola ini dari NOC. Report terjadwal adalah job rekap trafik yang masuk ke inbox setiap pagi, apa pun isinya. Alert dengan throttle adalah alarm NMS dengan dampening: perangkat yang flapping tidak boleh mengirim seribu trap dalam sepuluh menit, jadi alarm pertama dikirim lalu sisanya ditahan selama jendela tertentu. Dashboard adalah layar besar di ruang NOC: panel metrik yang dibaca sambil berdiri. Batas analoginya ada tiga. Pertama, alert Splunk tidak menahan apa pun secara otomatis; throttle harus kamu nyalakan sendiri. Kedua, dashboard Splunk bukan layar pasif, tiap panel adalah search yang benar-benar jalan setiap kali dashboard dibuka, sehingga dashboard yang berat membebani search head untuk semua orang. Ketiga, alarm NMS punya status dan clear, sedangkan alert Splunk hanya kejadian; status dan owner baru ada kalau hasilnya dibawa ke sistem tiket atau ke antrean ES.

```
search ad hoc di Search & Reporting
  |
  +-- Save As > Report   -> jadwal (preset atau cron) -> action jalan SETIAP kali report jalan
  |
  +-- Save As > Alert    -> jadwal + rentang waktu
  |                         -> kondisi trigger (sekali per jalan / sekali per hasil)
  |                         -> throttle (periode + field suppress)
  |                         -> alert action (email, log event, webhook, output lookup)
  |
  +-- Save As > New dashboard panel -> base search + chain search -> input dan token
  |
  +-- permission: private / app / global ; pemilik menentukan hidup matinya objek
```

Situasi yang dipakai sepanjang Day ini: di PT Jaringan Anak Bangsa (PT JAB, ISP menengah fiktif), alert VPN yang memicu tiket SOC-2026-0217 ternyata dibuat buru-buru oleh analyst yang sudah pindah tim, tanpa throttle dan tanpa pemilik. SOC lead menulis permintaan berikut:

> "Alert VPN yang kemarin menghasilkan SOC-2026-0217 belum ada yang merawat. Tolong buat ulang dari search-nya: jadwalnya jelas, jangan mengirim 180 email untuk satu serangan, dan harus ada jejak yang bisa kita hitung. Tambahkan satu layar yang dibaca L1 saat shift mulai. Jangan di search head ES dulu, L1 belum punya akses ke sana."

Permintaan itu memuat enam pertanyaan:

1. Mana yang disimpan sebagai report dan mana sebagai alert?
2. Jadwal dan rentang waktunya bagaimana supaya tidak ada event yang terlewat atau dihitung dua kali?
3. Kapan alert boleh menyala, sekali per jalan atau sekali per hasil?
4. Bagaimana supaya satu serangan tidak menghasilkan ratusan notifikasi?
5. Hasil alert dikirim ke mana, dan jejak apa yang ditinggalkannya?
6. Siapa yang boleh melihat dan mengubahnya, dan dashboard shift dibuat di framework mana supaya ringan?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, dan pertanyaan 6 di bagian 1.6 sampai 1.8. Bagian 2 mengerjakan semuanya untuk PT JAB.

**Kapan relevan:** setiap kali sebuah search diulang lebih dari sekali per shift, setiap kali seseorang harus tahu sesuatu tanpa membuka Splunk, dan di deployment atau tim yang belum memakai Enterprise Security sehingga pekerjaan L1 masih berjalan di app Search & Reporting.
**Kapan bukan jawaban:** alert terjadwal bukan pengganti detection yang dirawat sebagai konten (risk based alerting dan correlation search dibahas di Day 35 dan Day 36), dan bukan tempat menumpuk korelasi lintas sumber yang rumit. Dashboard juga bukan tempat triage: keputusan atas satu alert tetap mengikuti alur Day 07. Kalau yang kamu butuhkan adalah antrean kasus dengan owner, status, dan disposisi, itu pekerjaan ES (Day 31 dan Day 33), bukan email dari scheduled alert.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dasar dari Day 01 sampai Day 08 (index, sourcetype, time picker, `stats`, `timechart`, search mode) tidak diulang di sini. Tabel ini memuat istilah penyimpanan, penjadwalan, dan dashboard yang dipakai Day ini; pakai kolom padanan bila sebuah istilah terasa asing.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Report | Search tersimpan yang bisa dijalankan ulang dan dijadwalkan. Aksinya berjalan setiap kali report jalan | Job rekap terjadwal yang hasilnya dikirim apa pun isinya |
| Scheduled alert | Search terjadwal yang aksinya hanya berjalan bila kondisi trigger terpenuhi | Alarm NMS yang hanya berbunyi saat ambang terlampaui |
| Real-time alert | Alert yang berjalan terus menerus, bukan pada jadwal | Polling kontinu yang memegang sumber daya selama hidup |
| Cron expression | Lima kolom (menit, jam, tanggal, bulan, hari) yang menentukan kapan search jalan | Jadwal cron di server kolektor |
| Rentang waktu terjadwal | `Earliest` dan `Latest` yang dipakai saat search terjadwal jalan, menimpa rentang di search | Jendela data yang ditarik tiap kali job jalan |
| Trigger condition | Pola yang diuji atas hasil search untuk memutuskan alert menyala atau tidak | Ambang dan arah alarm (naik, turun, ada atau tidak) |
| Per-result | Trigger yang menyala sekali untuk setiap baris hasil | Satu trap per port yang bermasalah |
| Throttle (suppression) | Menahan alert agar tidak menyala lagi selama periode tertentu | Dampening alarm pada perangkat yang flapping |
| Field suppress | Daftar field yang nilainya menentukan "ini alert yang sama" saat throttle | Kunci dampening per perangkat atau per interface |
| Suppression group | Kelompok alert sejenis, satu menyala maka yang lain ditahan | Satu alarm induk menahan alarm turunan |
| Alert action | Aksi yang dijalankan saat alert menyala: email, log event, webhook, output ke lookup | Notifikasi dan integrasi tiket di NMS |
| Log event action | Alert action yang menulis event baru ke index, sehingga riwayat alert bisa di-search | Menulis alarm ke tabel riwayat supaya bisa dilaporkan |
| Triggered Alerts | Daftar alert yang pernah menyala, dengan masa simpan yang bisa diatur | Daftar alarm aktif dan historis di konsol NMS |
| Dashboard Classic | Framework dashboard lama, sumbernya Simple XML | Layar NOC yang tata letaknya baris dan kolom |
| Dashboard Studio | Framework dashboard baru, sumbernya JSON, tata letak absolute atau grid | Layar NOC yang elemennya bisa ditata bebas |
| Input | Kontrol di dashboard (rentang waktu, dropdown, multiselect, number) yang mengisi token | Filter di konsol: pilih site, pilih perangkat |
| Token | Variabel bernilai dari input atau hasil search, dipakai di dalam SPL panel | Variabel di template laporan yang diisi saat dijalankan |
| Base search dan chain search | Satu search induk yang dipakai ulang oleh beberapa panel lewat search turunan | Satu polling yang hasilnya dipakai beberapa grafik |
| Permission (private, app, global) | Lingkup berbagi knowledge object: hanya pemilik, satu app, atau semua app | Draft pribadi, dibagikan ke tim, dipakai seluruh organisasi |
| Orphaned object | Objek yang pemiliknya dihapus, sehingga jadwalnya berhenti | Job terjadwal yang mati karena akun pembuatnya dinonaktifkan |

### 1.1 Report atau alert: yang membedakan bukan search-nya

Pertanyaan pertama SOC lead sebenarnya pertanyaan tentang aksi, bukan tentang SPL. Search yang sama bisa disimpan sebagai report atau sebagai alert; yang berbeda adalah kapan aksinya berjalan.

Dokumentasi Splunk membedakannya dengan tegas: aksi sebuah scheduled report berjalan setiap kali report itu jalan, sedangkan aksi sebuah alert berjalan hanya ketika kondisi trigger terpenuhi. Contoh resminya memakai search check-in hotel: sebagai report terjadwal tiap jam, email terkirim setiap jam; sebagai alert, email hanya terkirim bila ada event check-in [S2].

Dari situ muncul aturan praktis untuk PT JAB:

| Kebutuhan | Simpan sebagai | Alasan |
|---|---|---|
| Rekap harian login gagal VPN per akun dan per sumber untuk dibaca shift pagi | Report terjadwal | Nilainya justru ketika angkanya kecil atau nol; kamu tetap ingin membacanya |
| Lonjakan login gagal dari satu sumber yang harus ditindak malam itu | Alert | Tidak ada gunanya memberi tahu kalau tidak ada apa-apa |
| Jumlah event per index per hari untuk memantau sumber log yang mati | Report terjadwal, plus satu alert bila nol | Rekap untuk tren, alert untuk kegagalan |
| Tampilan yang dibaca saat shift mulai | Dashboard | Dibaca saat orang datang, bukan dikirim |

Satu hal teknis yang membedakan report dari search biasa: report yang dijadwalkan tidak boleh punya time range picker. Dokumentasi menyatakan scheduled report selalu berjalan pada jadwal, sehingga picker-nya dihapus saat report dijadwalkan [S11]. Rentang waktunya menjadi bagian dari definisi jadwal.

Report terjadwal di 10.6 bisa memicu sampai empat aksi per jalan: email ringkasan, menulis hasil ke CSV lookup, webhook, dan log event. Aksi "Run a script" sudah deprecated dan digantikan custom alert action [S11][S17].

### 1.2 Jadwal, cron, dan rentang waktu yang selaras

Pertanyaan kedua adalah sumber kesalahan paling mahal di Day ini: alert yang jadwal dan rentang waktunya tidak selaras akan melewatkan serangan atau menghitungnya dua kali, dan tidak ada yang menyadarinya karena alert tetap "jalan".

Saat menyimpan alert lewat Save As > Alert, langkahnya: isi judul dan deskripsi, atur permission, pilih penjadwalan, lalu (opsional) ubah `Expires`, atur kondisi trigger, atur throttle, pilih satu atau lebih alert action, dan simpan [S1]. Penjadwalannya punya dua jalur [S1]:

- Memilih salah satu opsi jadwal bawaan lalu menentukan waktunya. Tidak ada langkah tambahan.
- Memilih `Run on Cron Schedule`, mengisi `Earliest` dan `Latest` sebagai rentang waktu search, lalu menulis cron expression. Rentang di sini menimpa rentang asli search, dan dokumentasi meminta rentang itu dicocokkan dengan interval jalannya supaya tidak ada gap atau overlap [S1].

Cron Splunk memakai lima kolom [S3]:

| Kolom | Rentang nilai |
|---|---|
| Menit | 0-59 |
| Jam | 0-23 |
| Tanggal | 1-31 |
| Bulan | 1-12 |
| Hari (0 = Minggu) | 0-6 |

Format nilai yang didukung: satu nilai (`9`), daftar (`9,15`), rentang inklusif (`9-17`), semua (`*`), setiap N (`*/N`), beberapa rentang (`9-12,15-17`), dan setiap N di dalam rentang (`9-12/2`) [S3]. Dua perilaku yang perlu diingat: `*/N` memakai kelipatan N dihitung dari awal kolom, sehingga `*/9` di kolom menit menghasilkan 0, 9, 18, 27, 36, 45, 54 lalu kembali ke 0, sedangkan di bentuk `I-J/N` hitungannya mulai dari angka pertama rentang, sehingga `13-36/10` menghasilkan 13, 23, 33 [S3].

Contoh dari dokumentasi [S3]: `5 9 * * *` jalan 09:05 setiap hari, `30 * * * *` jalan di menit 30 setiap jam, `0 12 * * *` jalan 12:00 setiap hari, `*/20 * * * 1-5` jalan setiap 20 menit dari menit 0 pada Senin sampai Jumat, dan `0 9 1-7 * *` jalan 09:00 pada tujuh hari pertama setiap bulan.

Zona waktunya penting untuk SOC yang membaca waktu dalam WIB. Splunk Cloud Platform selalu memakai UTC, sedangkan Splunk Enterprise memakai zona waktu yang dikonfigurasi di search head, dan itu bisa dilihat atau diubah di Settings > Searches, reports, and alerts > Scheduled time [S3].

Dua tips penjadwalan yang mengubah cara kamu menulis rentang [S2]:

1. Bila rentang waktu search lebih panjang dari interval jadwal, dua kali jalan akan mengevaluasi data yang sama, sehingga alert bisa menyala dua kali untuk satu kejadian. Bila rentang lebih pendek dari interval, ada event yang tidak pernah dievaluasi sama sekali.
2. Beri delay minimal satu menit. Di deployment terdistribusi, event bisa tiba di indexer terlambat; search yang menarik data sampai `now` akan melewatkan event yang baru masuk setelahnya.

Contoh resminya memakai delay 30 menit: Alert Type `Scheduled`, Time Range `Run on Cron Schedule`, `Earliest` `-90m`, `Latest` `-30m`, cron `30 * * * *`. Alert jalan tiap jam di menit 30 dan mengambil satu jam data; pada 15:30 ia memeriksa 14:00 sampai 15:00, dan karena jendela dan interval sama-sama satu jam, tidak ada overlap atau gap [S2].

Untuk deteksi keamanan, overlap sering justru diinginkan: brute force yang melintasi batas jendela baru terlihat kalau jendelanya lebih panjang dari interval. Lantern menyarankan jendela seperti `-70m@m` sampai `-10m@m` untuk mengakomodasi keterlambatan ingest dan akselerasi data model, dan menyarankan menyebar menit awal antar search terjadwal supaya tidak semua jalan bersamaan: untuk search tiap jam pakai `1 * * * *`, `2 * * * *`, dan seterusnya; untuk search lima menit pakai `0-55/5 * * * *` lalu `1-56/5 * * * *` [S18]. Konsekuensi dari overlap yang sengaja itu adalah throttle menjadi wajib, bukan opsional (bagian 1.4).

Satu lagi yang sering tidak disadari: scheduled report dan alert bersaing di scheduler yang sama. Di deployment yang hanya mengizinkan sedikit search terjadwal berjalan bersamaan, search yang bentrok dijalankan berurutan, dan prioritasnya bisa diubah [S2]. Scheduled report punya `Schedule Window` (mengizinkan scheduler menunda report supaya yang lebih penting jalan lebih dulu) dan `Schedule Priority`, yang hanya berguna bila sedikit report yang prioritasnya dinaikkan [S11]. Di ES, mengatur schedule window ke auto membuat urutan jalan diatur sendiri sehingga skipped search dan starvation berkurang, dengan catatan riwayat jadwal hilang bila search head standalone di-restart [S18].

### 1.3 Kondisi trigger: sekali per jalan atau sekali per hasil

Alert tidak harus menyala setiap kali search-nya mengembalikan hasil. Kondisi trigger adalah pola yang diuji atas hasil, dan throttle adalah kontrol terpisah yang menahan alert setelah menyala [S4].

Pilihan yang tersedia [S4]:

| Jenis alert | Kondisi trigger | Perilaku |
|---|---|---|
| Scheduled | Opsi bawaan jumlah hasil atau jumlah nilai field (misalnya `Number of Hosts`), atau custom condition | Menyala sekali per jalan bila hasil cocok, atau sekali per hasil yang cocok |
| Real-time, per-result | Tidak ada kondisi trigger | Default-nya menyala sekali untuk setiap hasil yang cocok |
| Real-time dengan rolling time window | Opsi bawaan atau custom condition, ditambah jendela atau interval | Menyala sekali per kecocokan, atau sekali per hasil |

Opsi bawaan juga bisa memantau perilaku, misalnya penurunan jumlah host sebanyak lima [S4]. Untuk pemantauan sumber log yang mati, itu lebih tepat daripada menghitung event.

Custom condition punya satu sifat yang wajib dipahami sebelum dipakai: ia berjalan sebagai search kedua atas hasil base search. Bila search kedua itu tidak mengembalikan apa pun, alert tidak menyala. Yang penting, field hasil yang tersedia untuk notifikasi dan alert action berasal dari base search, bukan dari kondisi trigger [S4]. Dokumentasi memberi contoh: base search `stats count by log_level`, custom condition `search count > 10`. Alert hanya menyala bila ada log_level dengan count di atas sepuluh, tetapi notifikasinya tetap memuat count semua log_level. Kalau filter itu dipindah ke base search, field yang tersedia untuk notifikasi ikut menyempit [S4].

Pilihan antara sekali per jalan dan sekali per hasil menentukan bentuk notifikasi dan cara throttle bekerja:

- Sekali per jalan cocok bila satu notifikasi berisi tabel semua baris sudah cukup, misalnya "ada 7 sumber dengan login gagal massal dalam 15 menit terakhir".
- Sekali per hasil cocok bila setiap baris harus menjadi tiket sendiri, misalnya satu tiket per IP sumber. Harganya: tanpa throttle, 7 baris berarti 7 notifikasi, dan 180 baris berarti 180 notifikasi.

Untuk alert "tidak ada event" (sumber log mati), dokumentasi menyarankan menambahkan `earliest=0 latest=now | stats count` ke search lalu memasang kondisi trigger `count=0` [S4]. Polanya penting untuk SOC ISP: sumber log yang diam sering lebih berbahaya daripada sumber log yang ramai.

### 1.4 Throttle, field suppress, dan suppression group

Pertanyaan keempat SOC lead ("jangan 180 email") dijawab throttle. Throttle (disebut juga suppression) menghentikan alert agar tidak menyala lagi selama periode tertentu, dan ia terpisah dari kondisi trigger [S5].

Cara setelnya bergantung jenis alert dan opsi triggernya [S5]:

| Jenis alert | Opsi trigger | Yang disetel saat throttle |
|---|---|---|
| Scheduled | Sekali per jalan | Hanya periode suppression |
| Scheduled | Per-result | Daftar field dipisah koma, ditambah periode |
| Real-time | Rolling time window | Hanya periode suppression |
| Real-time | Per-result | Daftar field dipisah koma, ditambah periode |

Aturan isinya [S5]:

- Field suppress menentukan apa artinya "alert yang sama". Event yang nilainya sama pada semua field yang didaftarkan akan ditahan. Contoh di dokumentasi: throttle pada `product_category` dan `best_sellers` hanya menahan event yang kedua nilainya sama dengan event yang sudah memicu alert.
- Periode diisi angka dan satuan waktu, dan nilainya harus lebih besar dari nol.
- Untuk real-time alert, dokumentasi menyarankan mulai dari periode throttle yang sama dengan rentang waktu base search, lalu diperpanjang bila notifikasi berulang masih muncul.

Satu perilaku yang sering mengejutkan: mengubah detail alert atau setelan throttle-nya membatalkan throttle yang sedang berjalan. Itu termasuk mengubah field throttle, SPL correlation search-nya, atau cron schedule-nya; file throttle dihapus, sehingga throttle baru mulai berlaku setelah ada event yang memicu alert dengan setelan baru [S5]. Praktisnya: jangan menyunting alert di tengah insiden yang sedang berlangsung kecuali kamu memang ingin notifikasi mengalir lagi.

Bila beberapa alert sejenis berjalan atas data yang sama, suppression group menahan mereka bersama tanpa harus digabung menjadi satu alert besar. Ketika salah satu anggota menyala, anggota lain ditahan selama periode suppression alert yang menyala itu, dan hanya alert yang menyala yang menjalankan alert action-nya. Contoh dokumentasi: lima alert satu grup, satu di antaranya punya periode 5 menit dan aksi email; saat ia menyala, kelimanya ditahan 5 menit, tetapi hanya email dari alert itu yang terkirim [S6]. Pengaturannya manual: Settings > Searches, reports, and alerts, lalu Edit > Advanced Edit, lalu isi field `alert.suppress.group_name` dengan nama grup yang sama untuk setiap anggota [S6]. Batasannya: alert milik user berbeda tidak bisa satu grup, dan dokumentasi menyarankan anggota grup memakai periode suppression, alert action, dan field suppress yang sama, karena bila field suppress-nya berbeda beberapa anggota bisa menyala atas kumpulan data yang berbeda [S6].

Berapa lama periode throttle yang pantas tidak ditentukan produk. Lantern memakai contoh default sekitar empat jam untuk correlation search keamanan [S18]. Untuk PT JAB, cara memilihnya: periode harus cukup panjang untuk menutup satu insiden yang sedang berjalan, tetapi tidak lebih panjang dari waktu yang kamu butuhkan untuk tahu bahwa serangan yang sama kembali setelah ditangani.

### 1.5 Alert action: email, log event, webhook, dan output lookup

Pertanyaan kelima adalah soal ke mana hasilnya pergi. Alert action adalah aksi yang dijalankan saat alert menyala, dan satu alert boleh mengaktifkan lebih dari satu [S7].

Aksi yang tersedia di 10.6 [S7]:

| Alert action | Yang dilakukannya | Kapan dipakai di SOC |
|---|---|---|
| Email notification | Mengirim email saat alert menyala | Pemberitahuan ke mailbox tim atau ke on-call |
| Webhook | Mengirim HTTP POST ke URL | Integrasi ke sistem tiket atau kanal chat |
| Output results to CSV lookup | Menulis hasil ke file CSV lookup | Membangun daftar sumber yang pernah menyala untuk dipakai search lain |
| Log events | Menulis event baru yang bisa di-index dan di-search | Jejak alert untuk metrik dan audit |
| Monitor triggered alerts | Menambahkan alert ke daftar Triggered Alerts | Pemantauan ringan dari dalam Splunk |
| Send to Splunk Mobile | Mengirim alert ke pengguna Splunk Mobile | Di luar cakupan Day ini |
| Script | Menjalankan skrip. Sudah deprecated, digantikan custom alert action | Jangan dipakai untuk hal baru |

Email adalah aksi yang paling banyak pilihannya, dan pilihan itu menentukan apakah emailnya berguna atau hanya mengganggu. Sebelum dipakai, mail server disetel admin di Settings > Server settings > Email settings (mail host, jenis autentikasi Simple atau OAuth 2.0 yang didukung sejak 10.0, alamat pengirim, domain tujuan yang diizinkan, dan footer) [S8]. Di form alert, aksinya ditambahkan lewat Add Actions > Send email, lalu diisi [S8]:

- `To`, dipisah koma, dengan CC dan BCC di balik "Show CC and BCC".
- `Priority`, opsional, dan penegakannya bergantung pada mail client penerima.
- `Subject` dan `Message`, keduanya menerima token.
- Pilihan isi: tautan ke alert atau report, tautan ke hasil search, teks search-nya, hasil inline sebagai tabel atau raw event atau CSV, kondisi trigger, waktu trigger, lampiran CSV, lampiran PDF, dan opsi mengizinkan lampiran kosong bila tidak ada hasil.
- `Type`: HTML dan plain text (default) atau plain text saja.

Token `$result.recipient$` bisa dipakai di field `To`, sehingga penerima ditentukan dari hasil search lewat `eval`; dokumentasi mencatat alamat dari token baru divalidasi saat search jalan [S8]. Hak aksesnya perlu diperhatikan: mengirim email lewat command `sendemail` ke server yang butuh autentikasi SMTP memerlukan role `admin`, ke server tanpa autentikasi memerlukan capability `list_settings`, dan user di luar role itu butuh `list_settings` sekaligus `schedule_search`. Pengiriman PDF butuh `schedule_search` dan `list_settings`, ditambah `admin_all_objects` bila mail host memerlukan kredensial [S8].

Webhook mengirim HTTP POST ke URL yang kamu isi, dengan body JSON. Isi payload-nya: search ID (SID) saved search yang memicu alert, tautan ke hasil search, pemilik dan app search itu, serta baris hasil pertama dari search yang memicu [S9]. Kata "baris hasil pertama" itu penting: webhook bukan cara mengirim seluruh tabel ke sistem tiket. Sejak Splunk Enterprise 9.0 (dan Splunk Cloud Platform 8.2203), URL tujuan harus terdaftar di webhook allow list sebelum alert boleh mengirim request; pengaturannya ada di bagian Manage alert and alert action permissions [S9]. Langkahnya: Save As > Alert atau edit aksi alert yang ada, pilih Webhook dari Add Actions, isi URL yang sudah masuk allow list, lalu simpan [S9].

Log event adalah aksi yang paling sering dilupakan padahal paling berguna untuk metrik. Aksi ini membuat event log kustom supaya metadata alert bisa di-index dan di-search; ia bisa dipakai sendiri atau bersama aksi lain. Field yang diisi: teks event (boleh plain text atau token), source dan sourcetype, host, serta destination index, dengan index `main` sebagai default dan index lain boleh dipilih selama sudah ada. Memakainya butuh capability `edit_log_alert_event`, dan token yang tersedia untuk email notification juga berlaku di sini. Di lingkungan terdistribusi, `outputs.conf` harus benar (`[tcpout]` dan `[indexAndForward]`) dan index tujuan harus terdefinisi di search head maupun di indexer [S10].

Konsekuensinya untuk PT JAB: dengan log event action, pertanyaan "berapa kali alert ini menyala bulan lalu dan berapa yang berakhir false positive" bisa dijawab dengan SPL, bukan dengan ingatan. Tanpa itu, satu-satunya jejak adalah email di mailbox orang.

### 1.6 Permission, kepemilikan, dan objek yatim

Pertanyaan keenam dimulai dari hal yang membuat alert lama di PT JAB mati: pemiliknya pindah tim. Report, alert, dan dashboard adalah knowledge object, dan semuanya mengikuti model permission yang sama.

Aturan yang perlu dipegang [S12]:

- Objek baru hanya terlihat oleh pembuatnya.
- Berbagi dilakukan lewat `Display for`, dengan pilihan satu app saja atau semua app (global). Mempromosikan objek ke global artinya seluruh app bisa memakainya.
- Secara default hanya role admin dan power yang bisa berbagi dan mempromosikan objek. Admin bisa mengubah permission objek apa pun, power hanya objek miliknya sendiri. Role lain bisa diberi kemampuan itu dengan memberi Read dan Write pada halaman Permissions app di Manage Apps.
- Read berarti bisa melihat dan menjalankan objek tanpa mengubah definisinya; Write berarti bisa mengubah definisinya; tanpa keduanya objek tidak terlihat. Baris Everyone menjadi dasar bagi semua role.
- Menghapus objek milik sebuah app butuh Write pada app itu. Memindahkan objek butuh status pembuat sekaligus Write pada app-nya, sedangkan cloning tetap boleh tanpa Write.
- Menghapus user membuat objek miliknya menjadi yatim. Scheduled report dan alert yang yatim berhenti berjalan, dan aksi serta panel dashboard yang bergantung padanya ikut mati. Pencegahannya adalah memindahkan kepemilikan ke user lain sebelum akunnya dihapus. Capability `edit_saved_search_owner` tidak menghapus kebutuhan membuat ulang user yang sudah dihapus untuk memindahkan objek yatim, dan dokumentasi mengingatkan bahwa pemilik capability itu bisa mengambil alih saved search beserta propertinya.

Dua aturan tambahan khusus penjadwalan [S11]:

- Membuat scheduled report butuh capability `schedule_search`. Melihat atau mengatur Schedule Priority butuh `edit_search_schedule_priority`, dan Schedule Window butuh `edit_search_schedule_window`.
- Scheduled report selalu berjalan sebagai pemilik (run as owner). Report yang tadinya diset berjalan sebagai user yang membukanya akan diubah menjadi owner begitu dijadwalkan.

Aturan terakhir itu punya dampak keamanan yang nyata: alert yang dimiliki akun dengan akses luas akan membaca semua index yang bisa dibaca akun itu, siapa pun penerima emailnya. Itu alasan email alert tidak boleh berisi field sensitif secara sembarangan, karena email keluar dari jangkauan RBAC Splunk (dibahas di Day 44).

Praktik yang dipakai di catatan ini untuk PT JAB: alert dan report operasional dimiliki satu akun fungsional tim SOC, bukan akun pribadi analyst, dan permission-nya dibagikan ke app SOC dengan Write hanya untuk role detection engineer dan SOC lead.

### 1.7 Dashboard: Classic atau Dashboard Studio

PT JAB butuh satu layar untuk L1. Di Splunk 10.6 ada dua framework dashboard, dan pilihannya dibuat di awal karena memindahkannya belakangan berarti membangun ulang.

Dokumentasi 10.6 menggambarkan keduanya: Classic memakai Simple XML sebagai source code dengan antarmuka yang lebih terbatas, sedangkan Dashboard Studio memakai stanza berformat JSON dan visual editor dengan banyak pilihan format, tempat visualisasi ditambahkan langsung ke dashboard lalu dihubungkan ke data source [S16]. Dashboard Studio ikut terpasang bersama Splunk Enterprise dan Splunk Cloud Platform sebagai default application, dan mematikan app itu bisa membuat perilaku tak terduga [S13].

Alur membuat dashboard baru di 10.6 [S14]:

1. Buka halaman Dashboards lalu pilih `Create New Dashboard`.
2. Isi judul dan deskripsi.
3. Opsional: lewat `Edit ID` di bawah Dashboard Title, ubah ID dashboard yang secara default mengikuti judul. Judul masih bisa diubah nanti, ID tidak.
4. Di bagian Permissions, tentukan apakah dashboard bisa dilihat orang lain atau tetap privat.
5. Pilih Dashboard Studio untuk membangunnya. Untuk memakai framework Classic (Simple XML), dokumentasi mengarahkan ke manual dashboard Classic.
6. Pilih layout `Absolute` (menempatkan elemen dengan presisi, bisa menambahkan bentuk, ikon, dan gambar latar) atau `Grid` (panel menempel ke baris yang sudah ditentukan).
7. Pilih `Create`.

Jadi di 10.6 pembuatan dashboard tetap menanyakan framework-nya, dan Dashboard Studio adalah pilihan yang disorot di alur itu. Peringatan yang perlu diingat: jangan mengubah format layout pada dashboard yang sudah terisi, karena berpindah layout (terutama dari absolute ke grid) besar kemungkinan mengosongkan dashboard dan menimbulkan error [S14]. Halaman Dashboards juga punya Example Hub yang memuat dashboard contoh beserta source code dan SPL-nya [S13][S14].

Perbedaan yang paling memengaruhi pekerjaan SOC, menurut tabel perbandingan 10.6 [S13]:

| Hal | Classic (Simple XML) | Dashboard Studio |
|---|---|---|
| Tata letak | Baris dan kolom | Absolute (bebas) dan grid |
| JavaScript dan CSS kustom | Didukung | Tidak didukung |
| Default untuk data source, visualisasi, dan token | Tidak ada | Ada |
| Input | Termasuk radio, checkbox, link list | Radio, checkbox, dan link list tidak didukung |
| Token | Logika token kustom seperti if/then tersedia | Didukung dengan batasan; event handler unset dan condition tidak ada |
| Elemen khusus | Tidak ada | Bentuk, garis, text box, ikon, gambar, parallel coordinates, Sankey, timeline, choropleth berbasis SVG |
| Search turunan | Post-process search | Chain search, setara post-process dan bisa diatur dari visual editor |
| Ekspor | PDF | PDF, plus unduh dashboard atau satu visualisasi sebagai PNG |

Arah pengembangan Splunk terlihat dari daftar deprecation 10.6: dukungan custom visualization di Classic dashboard dinyatakan deprecated dengan saran memindahkan dashboard-nya ke Dashboard Studio, sedangkan ekspor dan pengiriman PDF untuk Classic Simple XML sudah deprecated sejak 9.4.0 dan akan dihapus di rilis mendatang [S17]. Untuk dashboard baru di PT JAB, Dashboard Studio adalah pilihan yang aman; Classic tetap perlu kamu kenali karena dashboard lama dan banyak app pihak ketiga masih memakainya, dan karena fitur seperti JavaScript kustom hanya ada di sana [S13].

### 1.8 Input, token, dan base search supaya dashboard tidak membebani search head

Dashboard yang berat adalah masalah operasional, bukan masalah estetika: setiap panel adalah search yang jalan setiap kali dashboard dibuka, dan sepuluh panel dengan raw search yang mirip berarti sepuluh kali kerja yang sama di search head yang juga menjalankan alert terjadwal.

Input adalah kontrol yang membuat satu dashboard dipakai untuk banyak pertanyaan. Yang perlu dipegang dari referensi opsi input Dashboard Studio 10.6:

- Dropdown dan multiselect bisa diisi nilai statis, dinamis, atau campuran. Nilai statis ditulis sebagai daftar pasangan label dan value; nilai dinamis diambil dari hasil sebuah data source [S19].
- Setiap input terhubung ke sebuah token. Di definisi input, token ditulis sebagai nama biasa, dan di dalam SPL ia dipanggil dengan tanda dolar di kedua sisi, misalnya `$dd1$` [S19].
- `defaultValue` menentukan nilai saat dashboard dibuka dan bertahan sampai pengguna mengubahnya. `clearDefaultOnSelection` (default `true`) menentukan apakah nilai default tetap terpilih ketika pengguna memilih opsi lain di multiselect. `isCascadingInput` mengatur agar input kembali ke default ketika token di data source-nya berubah, yang dipakai untuk input berantai (pilih POP dulu, lalu daftar host menyesuaikan). `hideWhenNoData` menyembunyikan input yang tidak punya opsi, dan `hideInViewMode` menyembunyikannya dari pengguna di View mode [S19].
- Input number memakai `min`, `max`, dan `step` [S19].

Base search dan chain search adalah cara menurunkan beban. Base search adalah data source yang memuat SPL bersama; chain search (`ds.chain`) adalah data source yang bercabang dari base search atau dari chain search lain untuk menambahkan SPL lanjutan, dan karena hasil base dipakai ulang, base search hanya jalan sekali [S15]. Aturannya [S15]:

- Dari satu base search bisa dibuat sampai 10 chain search.
- Dari satu chain search hanya boleh bercabang satu chain tambahan; cabang tingkat ketiga tidak diizinkan.
- Token bekerja di base maupun chain, kecuali token waktu yang hanya bekerja di base search.
- Bila base search bukan transforming search, field yang dibutuhkan chain harus disebut dengan `| fields` di base search, karena field yang tidak dirujuk di base akan null di chain.
- Perilaku refresh: perubahan nilai token di base menyegarkan seluruh pohon base dan chain, perubahan token hanya di chain menyegarkan chain itu saja, sedangkan auto refresh atau refresh manual di base maupun chain menyegarkan seluruh pohon.

Di visual editor, chain dibuat dengan memilih visualisasi, membuat chain search di bagian data source-nya, lalu memilih base search sebagai Parent search; SPL base akan tampil lebih dulu dan SPL chain ditulis di bawahnya [S15]. Pola yang dipakai di catatan ini untuk dashboard shift: satu base search transforming yang sudah di-`stats` sampai tingkat yang paling kasar, lalu tiap panel memfilter atau mengurutkan hasil itu.

## 2. Contoh dan langkah praktis di PT JAB

Semua keluaran di bagian ini adalah keluaran ilustrasi untuk organisasi fiktif PT JAB, bukan hasil eksekusi nyata. Asumsi data: log VPN di `index=vpn` dengan field gaya CIM Authentication (`user`, `src`, `action` bernilai `success` atau `failure`), log Windows Security di `index=wineventlog`. Nama field persis bergantung add-on vendor VPN, jadi cek di instance-mu. Jejak alert ditulis ke `index=soc_alerts`, index yang disediakan khusus untuk menyimpan riwayat alert SOC. Waktu dibaca dalam WIB sesuai preferensi zona waktu user, dan zona waktu scheduler dicek di Settings > Searches, reports, and alerts > Scheduled time [S3].

### 2.1 Report harian: rekap login gagal VPN untuk shift pagi

Ini jawaban untuk bagian pertama permintaan SOC lead: yang dibaca setiap hari apa pun isinya disimpan sebagai report, bukan alert.

**Tujuan:** memberi shift pagi satu tabel akun dengan login gagal terbanyak dalam 24 jam terakhir, beserta apakah ada yang akhirnya berhasil.

```
index=vpn earliest=-1d@d latest=@d
| stats count(eval(action="failure")) AS gagal count(eval(action="success")) AS sukses
        dc(src) AS sumber values(eval(if(action="success", src, null()))) AS src_sukses BY user
| where gagal >= 20
| sort - gagal
| head 20
```

- `earliest=-1d@d latest=@d`: tepat satu hari kalender penuh, dibulatkan ke awal hari. Rentang ini stabil, jadi report yang jalan pukul 07:05 selalu melaporkan hari sebelumnya, bukan sebagian hari ini.
- `count(eval(...))`: menghitung dua kondisi dalam satu `stats`, sehingga gagal dan sukses muncul berdampingan.
- `values(eval(if(action="success", src, null())))`: hanya mengumpulkan sumber dari login yang sukses, sehingga baris dengan `gagal` tinggi dan `src_sukses` terisi langsung menonjol.
- `where gagal >= 20`: ambang yang membuang kesalahan password biasa. Angka ini kebijakan tim, bukan aturan produk.
- `head 20`: membatasi panjang email.

Keluaran ilustrasi:

```
user             gagal  sukses  sumber  src_sukses
rina.wulandari   180    1       3       203.0.113.45
andi.pratama     64     2       2
budi.santoso     41     1       1
svc_billing      22     0       1
```

**Cara membaca hasil:** baris pertama adalah pola yang sudah dikenal dari SOC-2026-0217. Baris terakhir lebih halus: akun service yang gagal 22 kali dan tidak pernah berhasil biasanya berarti konfigurasi atau kredensial kedaluwarsa, bukan serangan, tetapi tetap perlu tiket ke pemilik sistem.

**Langkah menyimpan dan menjadwalkannya:**

1. Jalankan search, lalu Save As > Report, beri judul `VPN - rekap login gagal harian` dan deskripsi satu baris.
2. Setelah tersimpan, pilih Schedule. Kalau report-nya masih punya time range picker, picker itu dihapus saat dijadwalkan, karena scheduled report selalu jalan pada jadwalnya [S11].
3. Pilih `Run on Cron Schedule` dengan cron `5 7 * * *` supaya jalan 07:05 setiap hari, lima menit sebelum handover shift pukul 07:00 selesai dibahas. Rentang waktunya dibiarkan mengikuti definisi report (`-1d@d` sampai `@d`) [S11].
4. Isi Schedule Window bila tim kalian ingin report ini mengalah terhadap search yang lebih penting. Melihat atau mengatur Schedule Window butuh capability `edit_search_schedule_window` [S11].
5. Tambahkan aksi email ke milis SOC dengan isi: tautan ke report, hasil inline sebagai tabel, dan teks search-nya supaya penerima bisa mengulangnya [S8].

**Variasi:** ganti `BY user` menjadi `BY src` untuk melihat sumbernya, atau tambahkan `| lookup` identitas supaya departemen ikut muncul (pola lookup ada di Day 07).

**Kapan gagal:** bila add-on VPN tidak menormalkan `action`, nilainya bisa `Login failed` atau kode angka, sehingga kedua `count(eval(...))` menghasilkan nol. Jalankan `index=vpn | stats count BY action` dulu. Dan ingat report ini berjalan sebagai pemiliknya [S11]: kalau pemiliknya tidak punya akses ke `index=vpn`, hasilnya kosong tanpa pesan error.

### 2.2 Scheduled alert: jadwal dan rentang waktu untuk brute force VPN

Sekarang bagian yang membuat tiket. Search-nya mirip, tetapi dikelompokkan per sumber dan diberi ambang yang sesuai dengan jendela pendek.

**Tujuan:** menyala ketika satu IP sumber mencatat banyak login gagal ke banyak akun dalam jendela 15 menit, dan menunjukkan apakah ada yang berhasil.

```
index=vpn
| stats count(eval(action="failure")) AS gagal count(eval(action="success")) AS sukses
        dc(user) AS akun values(eval(if(action="success", user, null()))) AS user_sukses
        min(_time) AS awal max(_time) AS akhir BY src
| where gagal >= 100 AND akun >= 10
| eval durasi_menit=round((akhir-awal)/60, 1)
| table src gagal sukses akun user_sukses durasi_menit
| sort - gagal
```

- Tidak ada `earliest`/`latest` di dalam search, karena rentangnya diisi di form alert. Menulisnya di dua tempat adalah cara termudah membuat alert yang rentangnya tidak sesuai dugaan, sebab rentang di jadwal menimpa rentang search [S1].
- `where gagal >= 100 AND akun >= 10`: dua syarat sekaligus membedakan password spraying dari satu orang yang lupa password. Ambangnya kebijakan tim.
- `durasi_menit`: membantu triage membedakan 100 percobaan dalam 2 menit (otomatis) dari 100 percobaan dalam 15 menit (lebih lambat, mungkin alat yang sengaja memperlambat).

Keluaran ilustrasi:

```
src             gagal  sukses  akun  user_sukses      durasi_menit
203.0.113.45    180    1       25    rina.wulandari   14.6
198.51.100.77   142    0       19                     12.1
```

**Setelan jadwalnya di Save As > Alert:**

| Field | Nilai | Alasan |
|---|---|---|
| Alert Type | Scheduled, `Run on Cron Schedule` | Jendela dan interval perlu diatur sendiri |
| Earliest | `-20m@m` | Jendela 15 menit ditambah 5 menit delay |
| Latest | `-5m@m` | Delay untuk event yang tiba terlambat di indexer [S2] |
| Cron Expression | `*/5 * * * *` | Jalan setiap 5 menit |
| Expires | 30 hari | Berapa lama catatan alert yang menyala tersimpan di halaman Triggered Alerts [S1] |

Jendela 15 menit dengan interval 5 menit berarti setiap event dievaluasi sampai tiga kali. Itu sengaja: serangan yang melintasi batas jendela tetap tertangkap, dan jendela pendek membuat alert cepat. Harganya adalah notifikasi berulang untuk satu serangan, dan itu yang diselesaikan throttle di bagian 2.4. Bila yang kamu inginkan adalah satu evaluasi per event tanpa duplikat, jendela harus sama panjang dengan interval, misalnya `-20m@m` sampai `-5m@m` dengan cron `*/15 * * * *` [S2].

Penyesuaian terakhir: beri menit awal yang berbeda dari alert lain. Bila PT JAB punya empat alert lima-menitan, pakai `0-55/5 * * * *`, `1-56/5 * * * *`, dan seterusnya supaya keempatnya tidak jalan di detik yang sama dan scheduler tidak melewatkan search [S18].

### 2.3 Kondisi trigger: sekali per jalan atau satu tiket per sumber

Search di bagian 2.2 sudah memfilter dengan `where`, jadi setiap baris hasil adalah temuan. Yang tersisa adalah memutuskan bentuk notifikasinya.

| Pilihan | Setelan | Hasilnya untuk keluaran ilustrasi di atas |
|---|---|---|
| Satu notifikasi berisi tabel | Trigger: `Number of Results` is greater than `0`, Trigger: `Once` | Satu email berisi dua baris, satu tiket induk |
| Satu notifikasi per sumber | Trigger: `Number of Results` is greater than `0`, Trigger: `For each result` | Dua email, dua tiket, masing-masing satu IP |

PT JAB memilih per hasil, karena setiap IP sumber ditangani sebagai tiket sendiri dan webhook ke sistem tiket hanya membawa baris hasil pertama [S9]. Pilihan itu membuat field suppress menjadi wajib (bagian 2.4).

Alternatif dengan custom condition dipakai bila kamu ingin field lengkap tetap tersedia di notifikasi. Kalau `where gagal >= 100 AND akun >= 10` dipindah dari search ke custom condition, isinya menjadi:

```
search gagal >= 100 AND akun >= 10
```

Dengan begitu base search hanya `stats ... BY src` tanpa filter, dan email tetap memuat semua sumber beserta angkanya, sementara alert hanya menyala bila ada baris yang melewati ambang [S4]. Yang perlu diingat: field yang tersedia untuk notifikasi dan alert action berasal dari base search, bukan dari kondisi trigger [S4]. Jadi dua desain itu menukar hal yang berbeda: filter di base search membuat notifikasi ringkas, filter di custom condition membuat notifikasi punya konteks pembanding.

Untuk sumber log yang mati, polanya terbalik. Search-nya menghitung event, bukan menyaringnya:

```
index=vpn
| stats count
```

Dengan jadwal `*/15 * * * *`, rentang `-30m@m` sampai `-5m@m`, dan custom condition `search count=0`, alert menyala justru ketika tidak ada log VPN yang masuk selama jendela itu. Dokumentasi menyebut pola yang sama: tambahkan `| stats count` lalu pasang kondisi trigger `count=0` [S4]. Untuk ISP seperti PT JAB, alert semacam ini sering lebih penting daripada alert serangan, karena resolver dan gateway yang berhenti mengirim log membuat semua detection lain diam tanpa ada yang tahu.

### 2.4 Throttle: satu serangan, satu notifikasi

Tanpa throttle, alert bagian 2.2 akan menyala setiap 5 menit selama serangan berlangsung, dan karena per hasil, setiap IP sumber ikut dikalikan. Untuk SOC-2026-0217 itu berarti belasan email untuk satu kejadian.

Setelan yang dipakai PT JAB:

| Setelan | Nilai | Alasan |
|---|---|---|
| Throttle | aktif | Jendela search sengaja tumpang tindih dengan interval jadwal |
| Suppress results containing field value | `src` | Satu IP sumber sama dengan satu kejadian yang sama [S5] |
| Suppress triggering for | 60 menit | Cukup untuk satu putaran triage dan eskalasi L1 ke L2 |

Konsekuensinya, `203.0.113.45` memicu satu notifikasi lalu ditahan 60 menit, sementara `198.51.100.77` tetap memicu notifikasinya sendiri karena nilai `src`-nya berbeda [S5]. Kalau field suppress diisi `src, user_sukses`, penahanan hanya berlaku bila kedua nilainya sama, sehingga penyerang yang berhasil masuk ke akun kedua akan memicu notifikasi baru. Itu bisa diinginkan, tetapi harus disadari: makin banyak field suppress, makin sempit arti "alert yang sama", makin banyak notifikasi [S5].

Tiga hal yang harus kamu catat sebelum menyentuh alert ini lagi:

1. Mengubah detail alert atau setelan throttle membatalkan throttle yang sedang berjalan, termasuk bila yang kamu ubah adalah field throttle, SPL-nya, atau cron-nya [S5]. Jangan menyunting alert di tengah insiden kecuali kamu memang ingin notifikasi mengalir lagi.
2. Periode throttle bukan periode tenang untuk penyerang. Alert tetap jalan dan hasilnya tetap bisa dilihat; yang ditahan adalah aksinya.
3. Bila PT JAB nanti punya tiga alert VPN yang sumber datanya sama (login gagal massal, login dari negara tak lazim, login di luar jam kerja), ketiganya bisa dimasukkan ke satu suppression group lewat Advanced Edit dengan `alert.suppress.group_name` yang sama, supaya satu insiden tidak memicu tiga notifikasi dari tiga alert berbeda. Syaratnya ketiganya dimiliki user yang sama, dan sebaiknya periode suppression, field suppress, serta alert action-nya juga sama [S6].

### 2.5 Alert action: email yang bisa dibaca, jejak yang bisa dihitung, tiket yang otomatis

Tiga aksi dipasang bersama di alert yang sama, masing-masing untuk pembaca yang berbeda.

**Email ke on-call.** Isi yang dipilih: tautan ke alert, tautan ke hasil, kondisi trigger, waktu trigger, dan hasil inline sebagai tabel. Lampiran CSV dan PDF dimatikan [S8]. Alasannya operasional dan sekaligus soal data: email keluar dari jangkauan kontrol akses Splunk, jadi isinya dibatasi pada field yang memang perlu dilihat on-call (`src`, `gagal`, `akun`, `user_sukses`). Subject memakai token supaya langsung terbaca di ponsel:

```
Subject : [SOC] VPN brute force dari $result.src$ ($result.gagal$ gagal, $result.akun$ akun)
Message : Sumber $result.src$ mencatat $result.gagal$ login gagal ke $result.akun$ akun VPN.
          Login sukses: $result.user_sukses$
          Triage sesuai alur L1; jangan tutup tanpa bukti.
```

Token `$result.<field>$` mengambil nilai dari hasil search, dan dokumentasi mencatat bahwa alamat email yang berasal dari token baru divalidasi saat search jalan [S8]. Daftar token yang berlaku ada di halaman token notifikasi versi-mu, jadi cek di sana sebelum memakai token metadata job.

**Log event untuk jejak.** Setelan: Event text berisi pasangan field yang mudah diparse, source `splunk_alert`, sourcetype `jab:soc:alert`, host search head, dan destination index `soc_alerts` [S10].

```
Event text : alert="vpn_bruteforce" src="$result.src$" gagal="$result.gagal$" akun="$result.akun$"
             user_sukses="$result.user_sukses$" sev="high"
Index      : soc_alerts
```

Memakai aksi ini butuh capability `edit_log_alert_event`, index tujuannya harus sudah ada, dan di lingkungan terdistribusi index itu harus terdefinisi di search head maupun indexer [S10]. Hasilnya: riwayat alert menjadi data yang bisa di-search.

```
index=soc_alerts sourcetype=jab:soc:alert alert="vpn_bruteforce" earliest=-30d@d
| stats count AS menyala dc(src) AS sumber min(_time) AS pertama max(_time) AS terakhir
| eval pertama=strftime(pertama,"%F %T"), terakhir=strftime(terakhir,"%F %T")
```

Keluaran ilustrasi:

```
menyala  sumber  pertama               terakhir
37       21      2026-09-15 03:12:40   2026-10-14 02:06:41
```

**Cara membaca hasil:** 37 kali menyala dari 21 sumber berbeda dalam 30 hari adalah angka yang bisa dibawa ke rapat tuning. Bila dipadukan dengan disposisi dari sistem tiket (Day 07), angka ini menjadi dasar menghitung berapa persen alert ini berakhir false positive.

**Webhook ke sistem tiket.** URL internal, misalnya `https://tiket.jab.example/hooks/splunk`, harus lebih dulu masuk webhook allow list; sejak Splunk Enterprise 9.0 alert tidak boleh mengirim request ke URL di luar allow list [S9]. Payload-nya memuat SID saved search, tautan ke hasil, pemilik dan app, serta baris hasil pertama [S9]. Karena hanya baris pertama yang ikut, webhook di alert per hasil tetap menghasilkan satu tiket per baris, tetapi webhook di alert sekali per jalan hanya membawa satu baris ke tiket. Itu salah satu alasan PT JAB memilih per hasil.

**Kapan gagal:** email tidak terkirim karena mail server belum disetel di Settings > Server settings > Email settings atau karena role pemilik alert tidak punya capability yang dibutuhkan [S8]; webhook gagal tanpa pesan jelas karena URL belum ada di allow list [S9]; log event tidak muncul karena index tujuan belum dibuat di indexer [S10].

### 2.6 Dashboard shift L1 dengan base search dan chain search

Permintaan terakhir SOC lead adalah satu layar untuk dibaca saat shift mulai. Dibuat di Dashboard Studio dengan layout grid, karena tujuannya membaca angka, bukan menata gambar [S14].

**Langkahnya:** Dashboards > Create New Dashboard, isi judul `SOC L1 - layar shift`, atur Permissions supaya tim bisa melihatnya, pilih Dashboard Studio, pilih layout Grid, lalu Create [S14].

**Base search** diisi sebagai data source dan sudah berbentuk transforming, supaya panel-panel di bawahnya bekerja atas tabel kecil, bukan atas event mentah:

```
index=vpn earliest=$tok_waktu.earliest$ latest=$tok_waktu.latest$ src_site=$tok_pop$
| stats count(eval(action="failure")) AS gagal count(eval(action="success")) AS sukses
        dc(user) AS akun values(eval(if(action="success", user, null()))) AS user_sukses BY src
```

- `$tok_waktu.earliest$` dan `$tok_waktu.latest$` adalah token dari input rentang waktu. Nama token waktu di dashboard-mu bisa berbeda, jadi cek di definisi input atau source editor sebelum menyalin pola ini.
- `$tok_pop$` adalah token dari input dropdown berisi POP (`*`, `JKT`, `BDG`, `SBY`, `MDN`) dengan `defaultValue` `*` [S19]. Nama field `src_site` di sini asumsi; sesuaikan dengan field lokasi yang ada di log VPN-mu.
- Token waktu hanya bekerja di base search, tidak di chain search [S15]. Itu alasan rentang waktu diurus di sini.

**Tiga panel sebagai chain search** dari base itu [S15]:

| Panel | SPL chain | Visualisasi |
|---|---|---|
| Sumber dengan login gagal terbanyak | `\| sort - gagal \| head 10` | Tabel |
| Sumber yang gagal banyak lalu berhasil | `\| where sukses > 0 AND gagal >= 20 \| sort - gagal` | Tabel |
| Total percobaan gagal pada rentang terpilih | `\| stats sum(gagal) AS total_gagal` | Single value |

Keluaran ilustrasi panel kedua:

```
src             gagal  sukses  akun  user_sukses
203.0.113.45    180    1       25    rina.wulandari
```

**Cara membaca hasil:** panel kedua adalah panel yang paling sering memulai tiket. Panel pertama menunjukkan kebisingan, panel ketiga menunjukkan apakah hari ini lebih ramai dari biasanya.

Panel keempat, tren login gagal per jam (`timechart span=1h`, pola di Day 08), tidak bisa menjadi chain dari base di atas, karena base sudah mengagregasi dan membuang `_time`. Panel itu memakai data source sendiri. Ini batas yang perlu kamu ingat saat merancang: satu base search hanya bisa menjadi induk bagi panel yang membutuhkan bentuk hasil yang sama. Dari satu base boleh dibuat sampai 10 chain, dan dari satu chain hanya boleh bercabang satu chain lagi [S15].

Bila suatu saat base search-mu bukan transforming (misalnya hanya `index=vpn ... | fields ...`), sebutkan field yang dipakai chain dengan `| fields` di base, karena field yang tidak dirujuk di base akan null di chain [S15].

**Kapan gagal:** dropdown POP kosong karena search pengisinya tidak mengembalikan apa pun (`hideWhenNoData` bisa menyembunyikannya, yang membuat masalahnya tidak terlihat) [S19]; dashboard tampak lambat karena setiap panel memakai data source sendiri padahal SPL awalnya sama; dan dashboard yang di-auto refresh menyegarkan seluruh pohon base dan chain, bukan hanya satu panel [S15].

### 2.7 Menyerahkan ketiganya ke tim, bukan ke satu orang

Langkah terakhir yang membedakan alert yang dirawat dari alert yang mati bersama pembuatnya.

1. Simpan report, alert, dan dashboard di app SOC, lalu atur `Display for` ke app itu. Objek baru hanya terlihat oleh pembuatnya sampai langkah ini dilakukan [S12].
2. Beri Read ke role analyst L1 dan Write hanya ke role detection engineer dan SOC lead. Read berarti bisa melihat dan menjalankan tanpa mengubah definisi [S12].
3. Pindahkan kepemilikan ke akun fungsional tim. Menghapus user membuat objeknya yatim, dan scheduled report serta alert yang yatim berhenti berjalan beserta aksi dan panel yang bergantung padanya [S12].
4. Catat di deskripsi objek: pemilik, tujuan, ambang yang dipakai, dan nomor tiket contohnya (misalnya SOC-2026-0217). Deskripsi adalah satu-satunya dokumentasi yang selalu ikut pindah bersama objeknya.
5. Pastikan akun pemilik punya akses ke index yang dibutuhkan, karena scheduled report selalu berjalan sebagai pemilik [S11].

## 3. Lab praktik (di VM lab terisolasi)

Lab memakai satu instance Splunk Enterprise lab tanpa ES, index lab sendiri, dan data sintetis dari `makeresults` bila log VPN tidak tersedia. Semua langkah dijalankan di lab terisolasi, dan endpoint webhook yang dipakai adalah endpoint uji di dalam lab, bukan layanan publik.

1. **Siapkan data.** Kirim log autentikasi dari VM lab ke sebuah index (misalnya `index=lab_auth`), atau buat data sintetis dengan pola `makeresults` dari Day 07 lalu simpan ke index lab lewat summary index sederhana. Catat nama field `user`, `src`, dan `action` yang benar-benar ada.
2. **Buat report dan jadwalkan.** Simpan search bagian 2.1 (disesuaikan ke index lab) sebagai report, jadwalkan dengan cron `5 7 * * *`, lalu ubah sementara menjadi `*/5 * * * *` supaya kamu bisa melihatnya jalan. Buka Settings > Searches, reports, and alerts dan catat kolom jadwal serta pemiliknya.
3. **Buat alert dengan jadwal dan rentang yang selaras.** Simpan search bagian 2.2 sebagai alert dengan `Earliest` `-20m@m`, `Latest` `-5m@m`, cron `*/5 * * * *`. Turunkan ambang `where` sampai alert benar-benar menyala di data lab-mu, lalu catat ambangnya.
4. **Uji dua bentuk trigger.** Jalankan satu versi dengan Trigger `Once` dan satu versi dengan `For each result` pada data yang sama. Hitung dulu jumlah notifikasi yang kamu harapkan dari jumlah baris hasil, lalu bandingkan dengan jumlah yang benar-benar muncul di halaman Triggered Alerts.
5. **Uji throttle.** Nyalakan throttle dengan field `src` dan periode 15 menit, lalu picu serangan lab yang sama dua kali dalam 10 menit. Hasil yang diharapkan: notifikasi hanya sekali per nilai `src`. Setelah itu sunting alert (misalnya ubah cron-nya) lalu picu lagi, dan catat bahwa throttle yang sedang berjalan dibatalkan oleh penyuntingan.
6. **Uji suppression group.** Buat alert kedua atas data yang sama (misalnya login gagal di luar jam kerja), beri keduanya `alert.suppress.group_name` yang sama lewat Edit > Advanced Edit, lalu picu data yang memenuhi keduanya. Catat alert mana yang menjalankan aksinya dan alert mana yang ditahan.
7. **Pasang log event action dan hitung jejaknya.** Arahkan ke index lab (buat dulu index-nya), picu alert beberapa kali dalam beberapa hari, lalu jalankan search riwayat dari bagian 2.5. Bandingkan jumlah baris dengan jumlah entri di halaman Triggered Alerts.
8. **Uji alert "tidak ada data".** Buat alert dengan `| stats count` dan custom condition `search count=0` atas index lab, lalu matikan pengiriman log dari VM lab selama satu jendela. Hasil yang diharapkan: alert menyala saat pengiriman mati, dan diam setelah dinyalakan kembali.
9. **Bangun dashboard shift.** Buat dashboard Dashboard Studio layout grid dengan satu base search transforming dan tiga chain search seperti bagian 2.6, ditambah satu input rentang waktu dan satu input dropdown. Lalu buat versi pembanding dengan tiga panel yang masing-masing memakai data source sendiri. Bandingkan waktu muat dan jumlah search job yang terbentuk dari Job Inspector atau Activity > Jobs.
10. **Uji permission dan kepemilikan.** Bagikan ketiga objek ke app, beri satu role Read saja, lalu masuk sebagai user dengan role itu dan coba menyunting. Setelah itu pindahkan kepemilikan ke user lain lewat Settings > Searches, reports, and alerts > Edit > Edit Owner dan pastikan jadwalnya tetap jalan.

**Hasil yang sebaiknya tersimpan:**
- Tabel ambang yang akhirnya dipakai di lab (gagal, akun, periode throttle) beserta alasannya.
- Perbandingan jumlah notifikasi antara trigger `Once` dan `For each result`, dengan angka yang kamu hitung lebih dulu.
- Bukti bahwa throttle bekerja, dan catatan bahwa penyuntingan membatalkannya.
- Hasil search riwayat alert dari index log event.
- Angka waktu muat dashboard versi base dan chain dibanding versi tanpa base search.
- Satu paragraf prosedur serah terima objek (pemilik, permission, deskripsi) untuk dipakai ulang.

**Variasi tantangan:** buat alert ketiga yang memakai custom condition alih-alih `where` di base search, lalu bandingkan isi emailnya dengan alert bagian 2.2. Jelaskan dalam dua kalimat kapan kamu memilih masing-masing desain.

## 4. Troubleshooting

Tabel ini memuat gejala yang paling sering muncul saat alert, report, atau dashboard tidak berperilaku seperti dugaan. Cari gejalanya di kolom pertama.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Alert jalan tetapi tidak pernah menyala | Rentang waktu di jadwal menimpa rentang di search, sehingga jendelanya bukan yang kamu kira [S1] | Buka Edit > Edit Alert, cocokkan `Earliest` dan `Latest` dengan ambang di `where` |
| Ada serangan yang terlewat padahal alert aktif | Rentang waktu lebih pendek dari interval jadwal, sehingga ada event yang tidak pernah dievaluasi [S2] | Panjangkan jendela atau percepat interval sampai jendela tidak lebih pendek dari interval |
| Satu kejadian menghasilkan banyak notifikasi | Jendela tumpang tindih dengan interval dan throttle mati [S2][S5] | Nyalakan throttle dengan field yang menandai "kejadian yang sama" |
| Throttle tiba-tiba tidak berlaku | Alert baru disunting, sehingga throttle yang berjalan dibatalkan [S5] | Tunggu trigger berikutnya dengan setelan baru; hindari menyunting saat insiden berjalan |
| Notifikasi tidak memuat field yang kamu harapkan | Filter dipindah ke base search, atau field hanya ada di kondisi trigger [S4] | Ingat field notifikasi berasal dari base search; pindahkan filter ke custom condition bila konteksnya dibutuhkan |
| Email tidak terkirim | Mail server belum disetel, atau role pemilik kurang capability [S8] | Cek Settings > Server settings > Email settings dan capability `list_settings` serta `schedule_search` |
| Webhook tidak mengirim apa pun | URL belum masuk webhook allow list [S9] | Tambahkan URL ke allow list, lalu uji ulang |
| Tiket hanya berisi satu baris padahal hasilnya banyak | Payload webhook hanya memuat baris hasil pertama [S9] | Pakai trigger per hasil, atau kirim lewat log event dan ambil dari index |
| Log event tidak muncul di index | Index belum ada, belum terdefinisi di indexer, atau capability `edit_log_alert_event` tidak dimiliki [S10] | Buat index di search head dan indexer, cek capability role pemilik |
| Report terjadwal hasilnya kosong | Report berjalan sebagai pemilik, dan pemilik tidak punya akses ke index itu [S11] | Pindahkan kepemilikan ke akun yang punya akses, atau beri akses ke pemilik |
| Report atau alert berhenti jalan sendiri | Pemiliknya dihapus sehingga objeknya yatim [S12] | Pindahkan kepemilikan sebelum akun dihapus; reassign objek yatim |
| Time range picker hilang setelah dijadwalkan | Scheduled report tidak boleh punya time range picker [S11] | Wajar; atur rentangnya di definisi jadwal |
| Dashboard lambat dibuka | Tiap panel memakai data source sendiri dengan SPL awal yang sama | Satukan menjadi base search lalu chain search [S15] |
| Panel chain kosong padahal base ada hasil | Base bukan transforming dan field yang dibutuhkan tidak disebut dengan `fields` [S15] | Tambahkan `\| fields` di base search |
| Token waktu tidak bekerja di panel | Token waktu hanya berlaku di base search [S15] | Pindahkan rentang waktu ke base search |
| Dashboard kosong setelah ganti layout | Layout diubah pada dashboard yang sudah terisi [S14] | Jangan ganti layout; buat dashboard baru |
| Banyak search terjadwal terlewat (skipped) | Terlalu banyak search jalan bersamaan di menit yang sama [S18] | Sebar menit awal cron, atau atur schedule window |

## 5. Kesalahan umum dan jebakan

- Menulis `earliest`/`latest` di dalam SPL alert sekaligus mengisi rentang di jadwal. Yang menang adalah rentang di jadwal [S1], sehingga alert berperilaku berbeda dari yang kamu uji di search bar.
- Menyimpan sesuatu sebagai alert padahal yang dibutuhkan laporan rutin. Alert yang tidak pernah menyala tidak memberi tahu apa pun, termasuk ketika sumber datanya mati [S2].
- Membuat alert per hasil tanpa throttle. Satu serangan dengan 20 sumber berarti 20 notifikasi tiap kali alert jalan [S5].
- Menganggap periode throttle sebagai pengaman permanen. Menyunting alert membatalkan throttle yang sedang berjalan [S5].
- Memasukkan alert milik beberapa user ke satu suppression group. Anggota grup harus dimiliki user yang sama [S6].
- Mengandalkan webhook untuk mengirim seluruh tabel ke sistem tiket. Payload-nya hanya memuat baris hasil pertama [S9].
- Melampirkan CSV atau PDF berisi field sensitif ke email alert. Email keluar dari jangkauan kontrol akses Splunk, dan report berjalan sebagai pemiliknya yang bisa punya akses jauh lebih luas daripada penerima [S11].
- Tidak memasang log event atau output lookup, sehingga satu-satunya jejak alert ada di mailbox orang. Riwayat yang tidak bisa di-search tidak bisa dipakai untuk tuning maupun metrik [S10].
- Membiarkan report dan alert dimiliki akun pribadi. Saat orangnya pindah atau akunnya dihapus, objeknya yatim dan jadwalnya berhenti [S12].
- Membuat dashboard dengan sepuluh panel yang SPL awalnya sama. Setiap panel adalah search yang jalan setiap dashboard dibuka; base search dan chain search ada untuk itu [S15].
- Mengganti layout dashboard yang sudah terisi, lalu kehilangan isinya [S14].
- Membangun dashboard baru di Classic karena terbiasa, padahal dukungan custom visualization di Classic sudah deprecated dan ekspor PDF Classic juga sudah deprecated [S17].
- Menyalakan banyak alert dengan cron yang sama persis, lalu bingung kenapa ada search yang skipped [S18].

## 6. Catatan terkini

Bagian ini mencatat detail versi dan perubahan yang tidak mengubah cara kerja report, alert, dan dashboard, tetapi menjelaskan kenapa tampilan atau dokumentasi yang kamu temui bisa berbeda.

- Splunk Enterprise 10.6 dirilis 30 September 2026, dan sejak rilis itu Splunk memakai format versi empat segmen (misalnya 10.6.0.5) untuk Splunk Cloud Platform maupun produk yang dikelola sendiri. Skrip atau integrasi yang memparsing string versi perlu diperiksa [S20].
- Field filter di 10.6 sudah generally available dan aktif secara default untuk meredaksi field sensitif di hasil search. Dokumentasi rilis menyebut `mpreview` dan `mstats` tidak bekerja pada index yang memakai field filter, dan data model terakselerasi serta field extraction tingkat user bisa terpengaruh [S20]. Report, alert, dan dashboard yang bergantung pada field itu ikut terpengaruh, jadi cek bila sebuah panel tiba-tiba kosong.
- Dukungan custom visualization di Classic dashboard dinyatakan deprecated di 10.6, dengan saran memindahkan dashboard-nya ke Dashboard Studio. Ekspor dan pengiriman PDF untuk Classic Simple XML sudah deprecated sejak 9.4.0 dan akan dihapus di rilis mendatang. Analytics Workspace dihapus di 10.6 sehingga panel Classic yang memakainya terbuka di app Search [S17].
- Alert action "Run a script" sudah deprecated dan digantikan custom alert action framework [S7][S17]. Untuk integrasi baru, pakai webhook atau custom alert action.
- Zona waktu scheduler berbeda antar produk: Splunk Cloud Platform selalu UTC, Splunk Enterprise mengikuti zona waktu search head [S3]. Pada SOC yang bekerja dalam WIB, bedanya terasa pada cron harian seperti report pukul 07:05.
- Halaman langkah-langkah log event alert action yang dipakai di catatan ini berasal dari Alerting Manual versi Splunk Cloud Platform 10.6 [S10], sedangkan halaman lain berasal dari Alerting Manual Splunk Enterprise 10.6. Isi kedua manual itu sejajar, tetapi cek halaman Enterprise di instance-mu bila nama field di formnya berbeda.
- Jumlah chain search maksimum dan aturan percabangannya tercatat di dokumentasi Dashboard Studio 10.6 (10 chain dari satu base, satu tingkat percabangan tambahan) [S15]. Dokumentasi Dashboard Studio berubah per rilis dan halaman perbandingan fiturnya sendiri menyebut daftar itu bisa berubah [S13], jadi cek ulang saat naik versi.

## 7. Cheat sheet

```
PILIH BENTUK
  report  = aksi jalan SETIAP kali report jalan   -> rekap rutin, dibaca walau nol
  alert   = aksi jalan HANYA bila trigger cocok   -> hal yang harus ditindak
  dashboard = panel yang dibaca saat shift mulai  -> tiap panel = search yang jalan

JADWAL
  Save As > Alert: judul -> permission -> jadwal -> Expires -> trigger -> throttle -> action
  Run on Cron Schedule: Earliest/Latest MENIMPA rentang di search
  cron: menit(0-59) jam(0-23) tanggal(1-31) bulan(1-12) hari(0-6, 0=Minggu)
        N | N,M | I-J | * | */N | I-J/N      ex: 5 9 * * * ; 30 * * * * ; */20 * * * 1-5
  jendela == interval  -> tanpa gap/overlap ; jendela > interval -> duplikat (butuh throttle)
  jendela < interval   -> ADA EVENT YANG TIDAK PERNAH DIEVALUASI
  beri delay >= 1 menit (latest=-5m@m) untuk event yang tiba terlambat
  sebar menit awal antar alert: 0-55/5 ; 1-56/5 ; ...

TRIGGER
  scheduled : jumlah hasil / jumlah nilai field / custom condition ; Once | For each result
  custom condition = search kedua atas hasil ; field notifikasi dari BASE SEARCH
  tidak ada data: ... | stats count  + kondisi count=0

THROTTLE
  per-result -> field suppress (dipisah koma) + periode ; once -> periode saja
  field sama nilainya = alert yang sama ; periode harus > 0
  MENYUNTING alert membatalkan throttle yang berjalan
  suppression group: Advanced Edit -> alert.suppress.group_name (satu pemilik, setelan seragam)

ACTION
  email (To, Subject/Message pakai token, inline table, trigger time, attach CSV/PDF)
  log event (event text, source, sourcetype, host, index; butuh edit_log_alert_event) -> jejak bisa di-search
  webhook (HTTP POST JSON: SID, link hasil, owner, app, BARIS PERTAMA; URL wajib di allow list)
  output results to CSV lookup | monitor triggered alerts | script = deprecated

PERMISSION
  objek baru = private ; Display for: app / All apps ; default hanya admin & power yang bisa share
  Read = lihat & jalankan ; Write = ubah definisi ; scheduled report = run as OWNER
  schedule_search (jadwalkan) ; edit_search_schedule_window ; edit_search_schedule_priority
  user dihapus -> objek yatim -> report & alert BERHENTI jalan

DASHBOARD
  Dashboards > Create New Dashboard -> judul -> permission -> framework -> layout (Absolute|Grid)
  jangan ganti layout pada dashboard terisi
  base search + chain search (ds.chain): base jalan sekali ; maks 10 chain ; 1 tingkat cabang
  token waktu HANYA di base ; base non-transforming -> sebut field dengan | fields
  input: dropdown/multiselect (statis/dinamis), number (min,max,step) ; token dipanggil $nama$
  defaultValue | clearDefaultOnSelection | isCascadingInput | hideWhenNoData | hideInViewMode
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Kamu menulis `index=vpn earliest=-15m latest=now` di dalam SPL, lalu menyimpannya sebagai alert dengan `Run on Cron Schedule`, `Earliest` `-24h`, `Latest` `now`, cron `*/5 * * * *`. Rentang mana yang dipakai saat alert jalan?

<details><summary>Jawaban</summary>

Yang dipakai adalah rentang di jadwal, yaitu 24 jam terakhir, karena rentang pada `Run on Cron Schedule` menimpa rentang asli search. Akibatnya alert menghitung 24 jam data setiap 5 menit: jauh lebih berat, dan ambang `where`-mu yang dirancang untuk jendela 15 menit akan terlampaui terus sehingga alert menyala tanpa henti. Praktik yang aman adalah tidak menulis `earliest`/`latest` di dalam SPL alert dan mengatur rentangnya hanya di form jadwal. Lihat bagian 1.2 dan 2.2.

</details>

**2. Skenario keputusan.** Alert brute force VPN perlu menangkap serangan yang berlangsung sekitar 10 sampai 15 menit, dan event VPN kadang tiba di indexer terlambat beberapa menit. Setelan mana yang paling tepat?

- A. Jendela `-15m` sampai `now` dengan cron `*/15 * * * *`.
- B. Jendela `-20m@m` sampai `-5m@m` dengan cron `*/5 * * * *`, ditambah throttle pada field `src`.
- C. Jendela `-5m@m` sampai `now` dengan cron `*/15 * * * *`.

<details><summary>Jawaban</summary>

B. Jendela 15 menit menangkap serangan yang panjang, delay 5 menit memberi waktu bagi event yang tiba terlambat, dan interval 5 menit membuat alert cepat. Karena jendela lebih panjang dari interval, satu kejadian akan dievaluasi sampai tiga kali, dan itulah sebabnya throttle pada `src` wajib. A keliru karena menarik data sampai `now` sehingga event yang tiba terlambat terlewat, dan karena jendelanya sama dengan intervalnya, serangan yang melintasi batas jendela bisa terpecah menjadi dua bagian di bawah ambang. C paling berbahaya: jendela 5 menit dengan interval 15 menit berarti 10 menit dari setiap 15 menit tidak pernah dievaluasi sama sekali. Lihat bagian 1.2 dan 2.2.

</details>

**3. Pertanyaan jebakan.** "Throttle 60 menit sudah dipasang, jadi selama satu jam ke depan tidak mungkin ada notifikasi berulang dari alert ini." Benarkah?

<details><summary>Jawaban</summary>

Tidak, dalam dua hal. Pertama, throttle hanya menahan kombinasi nilai field suppress yang sama; sumber lain dengan nilai `src` berbeda tetap memicu notifikasinya sendiri. Kedua, mengubah detail alert atau setelan throttle-nya membatalkan throttle yang sedang berjalan, termasuk bila yang kamu ubah hanya cron atau SPL-nya, sehingga notifikasi bisa mengalir lagi setelah trigger berikutnya. Karena itu jangan menyunting alert di tengah insiden yang sedang berlangsung kecuali kamu memang menginginkannya. Lihat bagian 1.4 dan 2.4.

</details>

**4. Skenario keputusan.** Alert menghasilkan 20 baris, satu per IP sumber, dan setiap IP harus menjadi tiket sendiri di sistem tiket PT JAB lewat webhook. Desain mana yang benar?

- A. Trigger `Once`, webhook ke sistem tiket, tanpa throttle.
- B. Trigger `For each result`, webhook ke sistem tiket, throttle pada field `src` selama 60 menit.
- C. Trigger `Once`, email dengan lampiran CSV berisi 20 baris, lalu minta on-call membuat tiket manual.

<details><summary>Jawaban</summary>

B. Payload webhook hanya memuat baris hasil pertama, jadi trigger sekali per jalan hanya akan membuat satu tiket untuk 20 sumber. Trigger per hasil membuat satu panggilan webhook per baris, dan throttle pada `src` mencegah tiket ganda ketika alert jalan lagi pada jendela yang tumpang tindih. A salah karena 19 sumber tidak akan pernah masuk tiket. C memindahkan pekerjaan mesin ke manusia pada pukul dua pagi, dan lampiran CSV berisi nama akun memperluas data ke luar kontrol akses Splunk. Lihat bagian 1.3, 1.5, dan 2.5.

</details>

**5. Pertanyaan jebakan.** Rekanmu memindahkan `| where gagal >= 100` dari base search ke custom condition supaya "search-nya lebih ringan". Apa yang berubah pada emailnya?

<details><summary>Jawaban</summary>

Emailnya justru menjadi lebih panjang, bukan lebih ringan. Custom condition berjalan sebagai search kedua atas hasil base search, dan field hasil yang tersedia untuk notifikasi serta alert action berasal dari base search, bukan dari kondisi trigger. Jadi alert tetap hanya menyala bila ada sumber dengan 100 gagal atau lebih, tetapi email memuat semua sumber beserta angkanya. Desain itu berguna bila kamu ingin konteks pembanding di dalam notifikasi, dan merugikan bila kamu ingin notifikasi ringkas atau memakai webhook yang hanya membawa baris pertama. Lihat bagian 1.3 dan 2.3.

</details>

**6. Jelaskan ulang.** Jelaskan kepada SOC lead PT JAB dalam tiga kalimat kenapa dashboard shift dibangun dengan satu base search dan tiga chain search, bukan tiga panel yang masing-masing punya search sendiri.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Setiap panel di dashboard adalah search yang benar-benar jalan setiap kali dashboard dibuka, jadi tiga panel dengan SPL awal yang sama berarti tiga kali pekerjaan yang sama di search head yang juga menjalankan alert terjadwal kita. Dengan satu base search yang sudah di-`stats`, bagian beratnya jalan sekali, lalu tiap panel hanya memfilter atau mengurutkan hasil yang kecil itu. Batasnya: token waktu hanya bekerja di base search, dan panel yang butuh bentuk data berbeda seperti `timechart` tetap memerlukan data source sendiri."

Kesalahan yang sering muncul:
- Menyebut base search sebagai penghemat ruang penyimpanan, padahal yang dihemat adalah beban search.
- Mengira semua panel bisa dijadikan chain dari satu base, termasuk panel tren waktu dari base yang sudah diagregasi.
- Lupa menyebut bahwa base search non-transforming harus menyebut field yang dipakai chain dengan `fields`.

</details>

**7. Interview question (English).** "How do you set up a scheduled alert in Splunk so that it catches real activity without flooding the team?"

<details><summary>Sample answer</summary>

"I start from the question the alert answers, then I make the schedule and the search window match that question. I set the window in the alert's cron settings rather than in the SPL, because the scheduled range overrides whatever the search had, and I leave a few minutes of delay at the end so late-arriving events are still counted. If the window is longer than the interval, which I usually want for brute force style detections, I accept that one event gets evaluated more than once and I rely on throttling: suppress on the field that defines 'the same thing', such as the source IP, for a period long enough to cover one round of triage. Then I decide whether it should trigger once per run or once per result, because that drives everything downstream: a webhook only carries the first result row, so one ticket per source means per-result triggering. I always add a log event action so the alert's own history is searchable, which is what lets us measure how often it fires and what share ends up as a false positive, and I keep ownership on a team account with app-level permissions so the alert doesn't die when someone leaves."

What makes this answer strong: it ties schedule, window and trigger type together instead of treating them as separate switches, it treats throttling as a design decision rather than a checkbox, it shows awareness of what each alert action can actually carry, and it ends with the operational concerns (measurement and ownership) that separate an alert that gets maintained from one that gets ignored.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Splunk Enterprise 10.6 Alerting Manual: Create scheduled alerts | https://help.splunk.com/en/splunk-enterprise/alert-and-respond/alerting-manual/10.6/create-alerts/create-scheduled-alerts | primer | diakses 2026-10-14 | Tinggi. Urutan form Save As > Alert, Run on Cron Schedule, rentang menimpa search, Expires |
| S2 | Splunk Enterprise 10.6 Alerting Manual: Alert scheduling tips | https://help.splunk.com/en/splunk-enterprise/alert-and-respond/alerting-manual/10.6/create-alerts/alert-scheduling-tips | primer | diperbarui 2026-08-25; diakses 2026-10-14 | Tinggi. Selaras jadwal dan rentang, delay minimal satu menit, contoh delay 30 menit, report vs alert |
| S3 | Splunk Enterprise 10.6 Alerting Manual: Use cron expressions for alert scheduling | https://help.splunk.com/en/splunk-enterprise/alert-and-respond/alerting-manual/10.6/create-alerts/use-cron-expressions-for-alert-scheduling | primer | diakses 2026-10-14 | Tinggi. Lima kolom, format nilai, contoh, zona waktu Cloud vs Enterprise |
| S4 | Splunk Enterprise 10.6 Alerting Manual: Configure alert trigger conditions | https://help.splunk.com/en/splunk-enterprise/alert-and-respond/alerting-manual/10.6/manage-alert-trigger-conditions-and-throttling/configure-alert-trigger-conditions | primer | diakses 2026-10-14 | Tinggi. Opsi per jenis alert, custom condition sebagai search kedua, field notifikasi dari base search, pola count=0 |
| S5 | Splunk Enterprise 10.6 Alerting Manual: Throttle alerts | https://help.splunk.com/en/splunk-enterprise/alert-and-respond/alerting-manual/10.6/manage-alert-trigger-conditions-and-throttling/throttle-alerts | primer | diakses 2026-10-14 | Tinggi. Tabel setelan per jenis alert, field suppress, periode > 0, penyuntingan membatalkan throttle |
| S6 | Splunk Enterprise 10.6 Alerting Manual: Define alert suppression groups to throttle sets of similar alerts | https://help.splunk.com/en/splunk-enterprise/alert-and-respond/alerting-manual/10.6/manage-alert-trigger-conditions-and-throttling/define-alert-suppression-groups-to-throttle-sets-of-similar-alerts | primer | diperbarui 2026-08-25; diakses 2026-10-14 | Tinggi. `alert.suppress.group_name`, satu pemilik, saran setelan seragam |
| S7 | Splunk Enterprise 10.6 Alerting Manual: Set up alert actions | https://help.splunk.com/en/splunk-enterprise/alert-and-respond/alerting-manual/10.6/configure-alert-actions/set-up-alert-actions | primer | diperbarui 2026-08-25; diakses 2026-10-14 | Tinggi. Daftar alert action, script deprecated |
| S8 | Splunk Enterprise 10.6 Alerting Manual: Email notification action | https://help.splunk.com/en/splunk-enterprise/alert-and-respond/alerting-manual/10.6/configure-alert-actions/email-notification-action | primer | diperbarui 2026-08-25; diakses 2026-10-14 | Tinggi. Email settings, opsi isi email, token `$result.recipient$`, capability |
| S9 | Splunk Enterprise 10.6 Alerting Manual: Use a webhook alert action | https://help.splunk.com/en/splunk-enterprise/alert-and-respond/alerting-manual/10.6/configure-alert-actions/use-a-webhook-alert-action | primer | diperbarui 2026-08-25; diakses 2026-10-14 | Tinggi. HTTP POST, isi payload termasuk baris hasil pertama, allow list sejak 9.0 |
| S10 | Splunk Cloud Platform 10.6 Alerting Manual: Log events | https://help.splunk.com/en/splunk-cloud-platform/alert-and-respond/alerting-manual/10.6/configure-alert-actions/log-events | primer | diperbarui 2026-08-25; diakses 2026-10-14 | Tinggi. Field form, index `main` sebagai default, capability `edit_log_alert_event`. Halaman versi Splunk Enterprise tidak terbuka saat penulisan |
| S11 | Splunk Enterprise 10.6 Reporting Manual: Schedule reports | https://help.splunk.com/en/splunk-enterprise/create-dashboards-and-reports/reporting-manual/10.6/report-management/schedule-reports | primer | diperbarui 2026-08-25; diakses 2026-10-14 | Tinggi. Tanpa time range picker, empat aksi, run as owner, Schedule Window dan Priority, capability |
| S12 | Splunk Enterprise 10.6 Knowledge Manager Manual: Manage knowledge object permissions | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/get-started-with-knowledge-objects/manage-knowledge-object-permissions | primer | diperbarui 2026-09-09; diakses 2026-10-14 | Tinggi. Private sebagai default, Display for, admin vs power, Read/Write, objek yatim |
| S13 | Splunk Enterprise 10.6 Dashboard Studio: What is Splunk Dashboard Studio? | https://help.splunk.com/en/splunk-enterprise/create-dashboards-and-reports/dashboard-studio/10.6/introduction-to-splunk-dashboard-studio | primer | diperbarui 2026-05-05; diakses 2026-10-14 | Tinggi. Default application, tabel perbandingan Classic vs Studio, catatan daftar fitur bisa berubah |
| S14 | Splunk Enterprise 10.6 Dashboard Studio: Create a dashboard in Dashboard Studio | https://help.splunk.com/en/splunk-enterprise/create-dashboards-and-reports/dashboard-studio/10.6/create-a-dashboard-in-dashboard-studio/create-a-dashboard-in-dashboard-studio | primer | diperbarui 2026-04-10; diakses 2026-10-14 | Tinggi. Create New Dashboard, Edit ID, permission, pilihan framework, layout, peringatan ganti layout |
| S15 | Splunk Enterprise 10.6 Dashboard Studio: Chain searches together with a base search and chain searches | https://help.splunk.com/en/splunk-enterprise/create-dashboards-and-reports/dashboard-studio/10.6/use-data-sources/chain-searches-together-with-a-base-search-and-chain-searches | primer | diperbarui 2026-04-20; diakses 2026-10-14 | Tinggi. Base jalan sekali, maksimum 10 chain, satu tingkat cabang, token waktu, `fields`, perilaku refresh |
| S16 | Splunk Enterprise 10.6 Simple XML Dashboards: Getting started | https://help.splunk.com/en/splunk-enterprise/create-dashboards-and-reports/simple-xml-dashboards/10.6/introduction/getting-started | primer | diperbarui 2026-09-13; diakses 2026-10-14 | Tinggi untuk pembedaan dua framework. Halaman tidak menyatakan framework mana yang default |
| S17 | Splunk Enterprise 10.6 release notes: Deprecated and removed in version 10.6 | https://help.splunk.com/en/splunk-enterprise/release-notes-and-updates/release-notes/10.6/deprecated-features/deprecated-and-removed-in-version-10.6 | primer | diperbarui 2026-07-30; diakses 2026-10-14 | Tinggi. Custom visualization Classic deprecated, PDF Classic deprecated sejak 9.4.0, Analytics Workspace dihapus, script action deprecated |
| S18 | Splunk Lantern: Preventing concurrency issues and skipped searches | https://lantern.splunk.com/Security_Use_Cases/Threat_Hunting/Preventing_concurrency_issues_and_skipped_searches | primer (Lantern resmi) | tanggal tidak terlihat; diakses 2026-10-14 | Tinggi untuk praktik: menyebar menit cron, contoh throttle sekitar 4 jam, jendela `-70m@m` sampai `-10m@m`, schedule window auto |
| S19 | Splunk Enterprise 10.6 Dashboard Studio: Input configuration options | https://help.splunk.com/en/splunk-enterprise/create-dashboards-and-reports/dashboard-studio/10.6/configuration-options-reference/input-configuration-options | primer | diperbarui 2026-09-13; diakses 2026-10-14 | Tinggi. Nilai statis dan dinamis, token, `defaultValue`, `clearDefaultOnSelection`, `isCascadingInput`, `hideWhenNoData` |
| S20 | Splunk Enterprise 10.6 release notes: Welcome to Splunk Enterprise 10.6 | https://help.splunk.com/en/splunk-enterprise/release-notes-and-updates/release-notes/10.6/whats-new/welcome-to-splunk-enterprise-10.6 | primer | diperbarui 2026-09-30; diakses 2026-10-14 | Tinggi. Tanggal rilis 30 September 2026, format versi empat segmen, field filter GA |

**Catatan sumber:** ambang di contoh PT JAB (100 login gagal, 10 akun, throttle 60 menit, report pukul 07:05) adalah kebijakan organisasi fiktif yang disusun untuk catatan ini, bukan nilai yang disarankan produk; contoh periode throttle sekitar empat jam dan pola penyebaran menit cron berasal dari Lantern [S18] dan ditujukan untuk correlation search ES, jadi sesuaikan untuk alert biasa. Nama token waktu di dashboard (`$tok_waktu.earliest$`) mengikuti pola token input dan perlu dicek di definisi dashboard versi-mu; dokumentasi input yang dipakai di sini [S19] merinci opsi dropdown, multiselect, dan number, bukan daftar lengkap semua jenis input. Halaman langkah log event alert action untuk Splunk Enterprise tidak terbuka saat penulisan, sehingga yang dipakai adalah halaman versi Splunk Cloud Platform 10.6 [S10]. Dokumentasi 10.6 yang dibaca tidak menyatakan framework dashboard mana yang menjadi default untuk dashboard baru [S13][S16]; yang bisa dipastikan adalah alur Create New Dashboard tetap meminta kamu memilih framework dan layout [S14].
