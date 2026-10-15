---
day: 19
title: 'Workflow action: GET, POST, dan Search untuk pivot investigasi'
researched_on: 2026-10-14
versions_checked: 'Splunk Enterprise 10.6 (Knowledge Manager Manual: About workflow actions, Set up a GET workflow action, Set up a POST workflow action, Set up a search workflow action; Admin Manual: workflow_actions.conf 10.6.0.5); ES 8.7.0 (Triage findings and finding groups)'
---

# Day 19: Workflow action GET, POST, dan Search untuk pivot investigasi

Cakupan: membuat menu klik yang membawa nilai field dari satu event ke tempat lain, yaitu URL eksternal lewat GET, sistem lain lewat POST, dan search baru di Splunk lewat Search workflow action, beserta cara membatasinya ke field atau event type tertentu dan risiko data internal yang ikut keluar.

## Ide inti

Triage L1 sebagian besar berisi perpindahan: dari satu IP di alert ke riwayat trafiknya, dari satu hash ke reputasinya, dari satu event ke tiket. Perpindahan itu biasanya dikerjakan dengan menyalin nilai field, membuka tab lain, lalu menempelkannya. Workflow action memindahkan langkah itu ke dalam Splunk: sebuah menu yang muncul di event atau di field, membawa nilai field yang sedang kamu lihat, dan mengantarkannya ke salah satu dari tiga tujuan. GET membuat link HTML ke sumber daya web, POST mengirim HTTP request ke sebuah URI, dan Search menjalankan search kedua memakai nilai field dari event itu [S1].

Yang berubah bukan kecepatan beberapa detik per klik, melainkan siapa yang menentukan langkah berikutnya. Selama pivot masih berupa kebiasaan, setiap analyst punya versi sendiri: rentang waktu berbeda, index berbeda, layanan reputasi berbeda. Setelah pivot menjadi workflow action, langkahnya menjadi objek yang dirawat, bisa dibatasi ke field yang aman, dan bisa dibaca ulang enam bulan kemudian. Harganya juga ikut menjadi eksplisit, dan di sinilah Day ini punya sisi yang tidak nyaman: GET ke layanan luar berarti nilai field dari log-mu dikirim ke pihak ketiga, dan POST bisa mengirim lebih banyak lagi.

Kamu sudah memakai pola ini di NOC: klik kanan di konsol untuk pivot, misalnya membuka looking glass dari satu alamat IP, membuka halaman inventaris dari nama perangkat, atau membuka tiket dari satu alarm. Batas analoginya satu dan penting. Klik kanan di NMS internal tetap berada di dalam jaringanmu, sedangkan GET workflow action ke layanan reputasi mengirim nilai field itu ke organisasi lain, dan yang mengirim adalah browser analyst, bukan server Splunk. Itu artinya jejaknya ada di dua tempat sekaligus: log layanan pihak ketiga dan log proxy perusahaanmu sendiri.

```
Satu event di Events tab
  |
  +-- Event Actions (menu tingkat event)
  |      dipakai bila aksinya butuh beberapa field sekaligus, atau seluruh event
  |
  +-- Actions pada satu field di dalam event (menu tingkat field)
         dipakai bila aksinya cukup satu nilai

Tiga jenis tujuan (Action type):
  link  + Link method get   -> buka URL berisi $field$        (keluar organisasi bila URL eksternal)
  link  + Link method post  -> kirim key/value ke URI         (isi payload ditentukan Post arguments)
  search                    -> jalankan search baru di Splunk (tetap di dalam organisasi)

Pembatas kemunculan menu:
  Apply only to the following fields       -> daftar field, default *
  Apply only to the following event types  -> daftar event type, boleh wildcard
  Show action in                           -> Event menu / Fields menus / Both
```

Situasi yang dipakai sepanjang Day ini: di PT Jaringan Anak Bangsa (PT JAB, ISP menengah fiktif, SOC internal satu lantai dengan NOC), IP `203.0.113.45` yang dulu memicu tiket SOC-2026-0217 muncul lagi, kali ini di log firewall perimeter. Tiket baru SOC-2026-0244 dibuka oleh shift pagi. SOC lead menulis di grup shift:

> "Tiga shift terakhir menghabiskan waktu untuk hal yang sama: menyalin IP dari alert, membuka portal reputasi, lalu mengetik ulang search riwayat 24 jam. Tolong jadikan tiga klik: cek reputasi, buka tiket di sistem tiket kita, dan riwayat trafik IP itu di Splunk. Satu syarat dari tim compliance: jangan ada ID pelanggan atau isi log mentah yang nyasar ke layanan luar. Dan menunya jangan muncul di semua field, kemarin ada yang mengklik reputasi untuk field nama akun."

Permintaan itu memuat enam pertanyaan:

1. Apa yang sebenarnya dibuat, dan di mana menunya muncul?
2. Bagaimana membatasi menu itu supaya tidak muncul di field atau event yang salah?
3. Bagaimana membuat pivot ke layanan reputasi, dan apa yang ikut terkirim ke sana?
4. Bagaimana membuat satu klik yang mengirim data ke sistem tiket, dan sejauh mana isinya boleh ditentukan?
5. Bagaimana pivot ke riwayat trafik di Splunk dengan rentang waktu yang benar?
6. Apa yang harus dicek sebelum ketiga menu itu dibagikan ke semua L1?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3 dan 1.6, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, dan pertanyaan 6 di bagian 1.7. Bagian 2 membuat ketiganya untuk PT JAB sampai berbentuk setelan yang bisa disalin.

**Kapan relevan:** setiap kali satu langkah pivot diulang lebih dari sekali per shift, setiap kali kamu ingin satu rentang waktu dan satu daftar index dipakai sama oleh semua analyst, dan setiap kali ada enrichment di luar Splunk yang hasilnya cukup dibaca, bukan disimpan.

**Kapan bukan jawaban:** workflow action tidak menyimpan hasil enrichment ke dalam event, jadi ia bukan pengganti lookup (Day 12) atau normalisasi. Ia juga bukan otomasi respons: aksi yang perlu persetujuan, jejak audit, dan status pekerjaan adalah adaptive response dan playbook (Day 41 dan Day 42). Bila yang kamu butuhkan adalah enrichment yang ikut masuk ke data dan bisa dipakai detection, itu pekerjaan lookup dan threat intelligence framework, bukan menu klik.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dasar dari Day sebelumnya (index, sourcetype, field, event type, knowledge object, permission) tidak diulang di sini. Tabel ini hanya memuat istilah yang dipakai Day ini; cari kolom padanan bila sebuah istilah terasa asing.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Workflow action | Knowledge object berisi satu langkah pivot yang muncul sebagai menu di event atau field [S1] | Klik kanan di konsol NMS untuk membuka halaman terkait |
| Event Actions | Menu tingkat event di Events tab, tempat workflow action tingkat event muncul [S1] | Menu konteks pada satu baris alarm |
| Actions (menu field) | Menu pada satu field di dalam event, tempat workflow action tingkat field muncul [S1] | Menu konteks pada satu kolom di tabel alarm |
| Action type | Pilihan jenis aksi: `link` (GET atau POST) atau `search` [S2][S3][S4] | Jenis shortcut: buka halaman, kirim data, atau jalankan kueri |
| Link method | Metode HTTP untuk action type `link`: `get` atau `post`, default `get` [S5] | Membuka halaman vs mengirim formulir |
| `$field$` | Penanda yang diganti nilai field event saat menu diklik, dipakai di Label, URI, Post arguments, dan Search string [S2][S3][S5] | Variabel di template perintah atau template tiket |
| `$!field$` | Bentuk yang mencegah Splunk melakukan escaping pada nilai field [S2][S3] | Mode "kirim apa adanya" pada template |
| Post arguments | Pasangan key dan value yang dikirim ke URI saat Link method `post` [S3] | Field formulir yang diisi otomatis saat membuka tiket |
| Destination app | App tempat definisi workflow action disimpan [S1] | Folder konfigurasi tempat shortcut itu hidup |
| Show action in | Pilihan tempat menu muncul: Event menu, Fields menus, atau Both [S2][S3] | Memilih menu konteks mana yang mendapat shortcut |
| `display_location` | Nama setelan Show action in di file konfigurasi, default `both` [S5] | Baris konfigurasi dari pilihan yang sama |
| `search.preserve_timerange` | Setelan yang membuat search baru memakai rentang waktu search asal, default `false` dan diabaikan bila earliest atau latest diisi [S5] | Mewarisi rentang waktu dari layar sebelumnya |
| Drill-down search (ES) | Search bawaan yang dibuka dari detail finding di Splunk Enterprise Security [S6] | Tombol "lihat detail" di antrean tiket |

### 1.1 Satu klik yang dirawat sebagai objek

Permintaan SOC lead berbunyi "jadikan tiga klik", dan itu persis bentuk kerja workflow action: tiga definisi terpisah, masing-masing satu langkah pivot.

Semua definisi dibuat di satu tempat, yaitu Settings > Fields > Workflow actions, lalu klik New untuk membuat baru atau klik nama action yang ada untuk menyuntingnya [S1]. Setiap action baru butuh Name dan Destination app [S1]. Name adalah nama objeknya, dan yang dilihat analyst adalah Label, yang boleh statis atau memuat nilai field [S2].

Tiga jenisnya dan untuk apa masing-masing dipakai [S1]:

- GET membuat link HTML biasa, misalnya pencarian Google atau WHOIS atas sebuah IP. Hasilnya tab browser baru di komputer analyst.
- POST mengirim HTTP POST request ke URI yang kamu tentukan, misalnya membuat entri di sistem manajemen isu eksternal.
- Search menjalankan search kedua memakai nilai field dari event itu, misalnya mencocokkan nilai `ipaddress` dan `http_status` pada sebuah rentang waktu.

Perbedaan yang paling penting untuk keputusan sehari-hari bukan teknisnya, melainkan ke mana datanya pergi. Search workflow action tetap di dalam Splunk-mu. GET dan POST keluar dari Splunk, dan bila URI-nya milik pihak ketiga, data itu keluar dari organisasi. Bagian 1.6 membahas konsekuensinya.

Definisi ini juga punya bentuk file, yaitu `workflow_actions.conf`, dan file default-nya ada di `$SPLUNK_HOME/etc/apps/search/default/` [S5]. Perubahan lewat file butuh restart Splunk, kecuali disunting lewat manager di Splunk Web [S5]. Bentuk file berguna untuk dua hal: menyalin definisi antar lingkungan, dan membaca ulang semua setelan dalam satu halaman saat review.

### 1.2 Di mana menunya muncul, dan cara membatasinya

Keluhan terakhir SOC lead (ada yang mengklik reputasi untuk field nama akun) adalah soal pembatasan, dan ini bagian yang paling sering dilewatkan.

Tempat munculnya ada dua [S1]:

- Action tingkat event muncul di menu Event Actions pada Events tab.
- Action tingkat field muncul di menu Actions pada satu field di dalam event.
- Satu action boleh tingkat event, tingkat field, atau keduanya, dan pilihannya diatur di Show action in dengan nilai Event menu, Fields menus, atau Both [S1][S2][S3]. Di file konfigurasi, setelan ini bernama `display_location` dengan nilai `field_menu`, `event_menu`, atau `both`, dan default-nya `both` [S5].

Dua pembatas yang menentukan kapan menu itu pantas muncul:

**Apply only to the following fields.** Isinya daftar field dipisah koma, dan default-nya `*` yang berarti semua field [S1]. Perilakunya tidak sesederhana "tampilkan bila salah satu field ada". Bila kamu menyebut beberapa field, action muncul untuk setiap field yang disebut, tetapi di menu event ia hanya muncul bila semua field yang disebut ada di event itu [S1]. Memakai `*` bersama nama field lain membuat action berlaku untuk semua field hanya ketika field lain itu ada, dan bila tidak ada, ia tidak berlaku untuk field mana pun [S1]. Di file konfigurasi setelannya bernama `fields`, default `*`, dipisah koma atau spasi, dan menerima wildcard [S5].

**Apply only to the following event types.** Isinya satu event type atau daftar dipisah koma, dan wildcard `*` didukung [S1]. Bila diisi, action hanya muncul di menu event untuk event yang termasuk event type itu [S1]. Di file konfigurasi namanya `eventtypes`, dan wildcard yang disebut spesifikasinya adalah bentuk akhiran `*` [S5].

Keduanya boleh digabung, dan dokumentasi memberi contoh pola yang persis dibutuhkan PT JAB: buat event type untuk kelompok event yang relevan (contohnya `errors_in_500_range` untuk event dengan `http_status` minimal 500), lalu isi field action dengan `http_status` dan event type action dengan event type itu [S1]. Hasilnya menu yang muncul hanya di tempat yang masuk akal. Pembuatan event type-nya sendiri dibahas di Day 17.

Aturan praktis untuk SOC: jangan pernah meninggalkan `*` pada workflow action yang mengirim data ke luar. Daftar field yang eksplisit adalah kontrol keamanan, bukan kerapian.

### 1.3 GET: membuka URL yang memuat nilai field

Permintaan pertama, cek reputasi, adalah GET. Setelan yang perlu diisi, dengan nama persis seperti di form [S2]:

| Setelan | Isi | Catatan |
|---|---|---|
| Label | Teks yang muncul di menu, statis atau memuat `$field$` | Label yang memuat nilai field membuat analyst tahu apa yang akan dikirim sebelum mengklik |
| Apply only to the following fields | Daftar field | Kosong atau `*` berarti semua field |
| Apply only to the following event types | Daftar event type | Membatasi ke event yang termasuk event type itu |
| Show action in | Event menu, Fields menus, atau Both | Untuk aksi satu nilai, Fields menus cukup |
| Action type | `link` | Memunculkan setelan link di bawahnya |
| URI | Alamat sumber daya luar, nama field ditulis di antara tanda dolar | Nilai yang disisipkan di URI di-URL-encode otomatis [S2][S5] |
| Open link in | Current window atau New window | Di file konfigurasi: `link.target`, default `blank` (jendela baru), nilai lain `self` [S5] |
| Link method | `get` | Default di file konfigurasi juga `get` [S5] |

Dua hal tentang `$field$` yang perlu dipahami sebelum dipakai:

**Encoding otomatis.** Nilai yang lewat URI GET di-URL-encode, sehingga spasi dan tanda baca tidak merusak URL-nya [S2]. Ini bagus untuk nilai seperti nama proses atau user agent yang penuh spasi.

**Mematikan encoding dengan `$!`.** Bila sebuah field sudah berisi alamat HTTP lengkap dan harus sampai ke browser tanpa diubah, tulis `$!http$` dan bukan `$http$`; prefix `$!` mencegah URL escape pada GET dan HTTP form escape pada POST [S2][S3]. Dokumentasi memberi contoh URI yang isinya hanya `$!http$` [S2]. Kemampuan ini berguna untuk URL internal, misalnya halaman wiki runbook atau looking glass per POP. Untuk URL yang berasal dari log proxy, pikir dua kali: membuka URL yang belum dinilai dari workstation kantor berarti mengunjungi infrastruktur yang mungkin dikendalikan penyerang. Bagian 2.2 membahas versi yang aman.

Contoh yang ada di dokumentasi: pencarian Google dengan Label `Google $topic$` yang muncul di semua event, dan WHOIS dengan Label `WHOIS: $domain$` serta URI `http://whois.net/whois/$domain$` yang dibatasi ke field `domain` [S2].

### 1.4 POST: mengirim nilai field ke sistem lain

Permintaan kedua, membuka tiket, adalah POST. Alurnya sama sampai Action type `link`, lalu Link method diisi `post`, dan muncul satu bagian tambahan [S3]:

| Setelan | Isi | Catatan |
|---|---|---|
| URI | Alamat sumber daya web yang menerima POST request | Ini endpoint API sistem tujuan, bukan halaman biasa |
| Post arguments | Pasangan key dan value; key di kolom pertama, value di kolom kedua | Nama field dalam tanda dolar boleh dipakai di kedua sisi, dan pasangan baru ditambahkan dengan Add another field [S3] |
| Link method | `post` | Nilai yang dikirim di-HTTP-form-encode otomatis [S3][S5] |

Di file konfigurasi, pasangan itu bernama `link.postargs.<int>.<key/value>` dan hanya dipakai ketika `link.method = post` [S5]. Nilainya di-HTML-form-encode [S5], dan `$!` dipakai bila sebuah nilai justru harus dikirim tanpa escaping [S3].

Contoh di dokumentasi: action untuk event error dengan `http_status` di rentang 500 lewat event type `errors_in_500_range`, dengan argumen pertama mengirim `server error $http_status$` ke field `title` dan argumen kedua mengirim field `_raw` ke field `description` yang memuat stacktrace [S3].

Argumen kedua itu adalah contoh yang bagus sekaligus peringatan. Mengirim `$_raw$` berarti mengirim seluruh isi event. Pada log aplikasi internal milik sendiri, itu memang yang kamu inginkan. Pada ISP seperti PT JAB, satu event log portal pelanggan bisa memuat ID pelanggan, nomor layanan, atau alamat IP yang bisa dipetakan ke pelanggan tertentu, sehingga `$_raw$` ke sistem pihak ketiga berubah menjadi jalur keluar data pelanggan. Aturan yang dipakai di Day ini: `$_raw$` hanya ke sistem internal, dan ke sistem pihak ketiga hanya field yang sudah disepakati satu per satu.

Satu catatan praktis tentang POST: yang mengirim request adalah browser analyst, bukan server Splunk, sehingga endpoint tujuan harus bisa dijangkau dari jaringan tempat analyst bekerja, dan autentikasi endpoint itu harus bisa dilayani oleh sesi browser. Endpoint API yang menuntut header otorisasi khusus biasanya tidak cocok untuk POST workflow action dan lebih tepat dikerjakan alert action atau playbook (Day 09 dan Day 42). Cek perilaku ini di lingkunganmu sebelum menjanjikan integrasi tiket satu klik.

### 1.5 Search workflow action: pivot ke event terkait

Permintaan ketiga, riwayat trafik 24 jam, adalah Search workflow action. Setelan Action type diisi `search`, dan bagian konfigurasi search muncul [S4]:

| Setelan | Isi | Catatan |
|---|---|---|
| Label | Teks menu, boleh memuat `$field$` | Contoh dokumentasi: `See other errors for $controller$ over past 24h` [S4] |
| Search string | Search lengkap dengan penanda nilai field dalam tanda dolar | Contoh dokumentasi: `clientip=$clientip$` dan `sourcetype=rails controller=$controller$ error=*` [S4] |
| App tempat search dijalankan | Nama app | Di file konfigurasi: `search.app`, default app yang sedang dipakai [S5] |
| View tempat search dibuka | Nama view bila bukan view saat ini | Di file konfigurasi: `search.view`, default view saat ini [S5] |
| Jendela | Current window atau new window | Di file konfigurasi: `search.target`, nilai `blank` atau `self` seperti `link.target` [S5] |
| Earliest time dan Latest time | Modifier waktu relatif atau absolut | Bila keduanya dibiarkan kosong, search berjalan atas all time [S4] |
| Memakai rentang waktu search asal | Pilihan untuk memakai rentang waktu search yang menghasilkan daftar field itu | Di file konfigurasi: `search.preserve_timerange`, default `false`, dan diabaikan bila `search.earliest` atau `search.latest` diisi [S5] |

Tiga hal yang membuat Search workflow action gampang salah:

**All time adalah default yang berbahaya.** Dua kolom waktu yang kosong berarti search berjalan atas seluruh data [S4]. Di PT JAB, `index=dns` berisi resolver pelanggan dengan volume besar, dan satu klik yang tidak sengaja menjalankan all time di sana membebani search head untuk semua orang. Selalu isi minimal Earliest.

**Nilai field tidak diberi tanda kutip oleh Splunk.** Spesifikasi `workflow_actions.conf` menyebut bahwa nilai yang disisipkan ke `search.search_string` tidak diperiksa soal quoting atau escaping [S5]. Berbeda dari GET dan POST yang melakukan encoding, di sini isi field masuk ke search string apa adanya. Konsekuensinya dua. Pertama, nilai yang memuat spasi atau tanda kutip membuat search gagal atau mencari hal lain. Kedua, isi log adalah data yang berasal dari luar, dan nilai field yang memuat karakter khusus bisa mengubah bentuk search yang dijalankan. Mitigasinya: beri tanda kutip sendiri pada penanda (`src="$src$"`), dan batasi action ke field yang nilainya memang terstruktur, misalnya hasil ekstraksi IP atau port, bukan `_raw` atau user agent.

**Rentang waktu asal berguna untuk data statis.** Untuk dataset statis seperti BOTS, rentang relatif selalu salah. Di situ pilihan memakai rentang waktu search asal yang tepat dipakai, karena rentang absolut yang sudah kamu pilih di time picker ikut terbawa. Ingat bahwa pilihan ini diabaikan begitu Earliest atau Latest diisi [S5], jadi jangan mengisi keduanya lalu berharap rentang asal yang menang.

Contoh lengkap di dokumentasi: Label `See other errors for $controller$ over past 24h`, Action type Search, Search string `sourcetype=rails controller=$controller$ error=*`, Earliest time `-24h`, Latest time dibiarkan kosong, dan action dibatasi ke event type `controller_error` serta ke event yang memuat field `error` dan `controller` [S4].

### 1.6 Apa yang ikut keluar: risiko mengirim data internal ke layanan pihak ketiga

Syarat dari tim compliance di permintaan SOC lead bukan formalitas. Workflow action adalah salah satu jalur paling mudah untuk mengirim data internal ke luar, justru karena terasa seperti sekadar membuka halaman.

Yang perlu dipahami dari mekanismenya:

- Nilai field disisipkan ke URI dan dikirim sebagai bagian dari permintaan web [S2][S5]. Artinya nilai itu tercatat di log server pihak ketiga, dan pada GET ia berada di dalam URL, sehingga juga tercatat di log proxy perusahaanmu, di riwayat browser analyst, dan mungkin di log perangkat di antaranya.
- URL encoding bukan perlindungan kerahasiaan. Ia hanya membuat karakter khusus aman untuk URL [S2].
- Pada POST, isi yang dikirim ditentukan Post arguments, dan `$_raw$` mengirim seluruh event [S3].
- Yang mengirim adalah browser analyst, sehingga kontrol teknis yang berlaku adalah kontrol di endpoint dan proxy, bukan kontrol di server Splunk.

Pertanyaan yang dijawab sebelum sebuah workflow action eksternal dibuat:

1. Field apa yang benar-benar dibutuhkan layanan itu? Untuk reputasi IP, cukup satu IP publik. IP privat (`10.10.0.0/16`, `10.20.0.0/16`, dan `10.30.0.0/16` di PT JAB) tidak punya reputasi eksternal, jadi mengirimnya hanya membocorkan skema pengalamatan internal.
2. Apakah field itu bisa dikaitkan ke orang? Di ISP, alamat IP pelanggan dan ID pelanggan termasuk kategori ini. Mengirim `customer_id` ke layanan reputasi tidak menghasilkan apa pun selain risiko.
3. Apakah layanan itu menyimpan dan membagikan apa yang dikirim? Banyak layanan reputasi dan sandbox publik menjadikan kiriman sebagai bahan yang bisa dilihat pihak lain. Periksa ketentuan layanannya sebelum dipakai, dan catat hasil pemeriksaan itu, karena ini keputusan kebijakan, bukan keputusan teknis.
4. Apakah pivotnya bisa dikerjakan di dalam, misalnya dengan lookup threat intel yang sudah diunduh ke Splunk (Day 12 dan Day 33)? Bila ya, Search workflow action ke lookup internal lebih disukai daripada GET ke luar.

Cara teknis membatasi, memakai mekanisme yang sudah dibahas:

- Isi Apply only to the following fields dengan nama field yang spesifik, misalnya hanya `src` dan `dest`, bukan `*` [S1].
- Tambahkan event type sebagai pembatas kedua, supaya menu hanya muncul pada event perimeter dan tidak pada log internal [S1].
- Tulis Label yang memuat nilai yang akan dikirim, misalnya `Reputasi IP: $src$`, supaya analyst melihat apa yang keluar sebelum mengklik [S2].
- Hindari `$_raw$` pada URI atau Post arguments yang mengarah ke luar [S3].
- Untuk aset internal, buat satu workflow action terpisah yang menunjuk halaman internal, supaya tidak ada alasan memakai yang eksternal.

### 1.7 Yang menentukan apakah menu itu muncul untuk semua orang

Sebelum tiga menu itu dibagikan ke semua L1, ada empat hal yang perlu dicek, dan tiga di antaranya bukan tentang isi action.

**Destination app dan permission.** Setiap workflow action punya Destination app [S1], dan seperti knowledge object lain ia punya permission private, app, atau global (Day 15). Action yang dibuat dengan permission private hanya muncul untuk pembuatnya, dan action yang dibagikan sebatas app tertentu tidak muncul ketika analyst bekerja di app lain. Gejalanya membingungkan karena tidak ada pesan error: menunya hanya tidak ada.

**Field dan event type harus benar-benar ada di hasil.** Action tingkat field hanya muncul bila field itu ada di event yang sedang dibuka, dan pembatas event type hanya terpenuhi bila event itu memang anggota event type tersebut [S1]. Bila ekstraksi field bergantung search mode, menu bisa muncul di Verbose dan tidak muncul di Fast. Cek dengan membuka satu event dan memastikan field itu terdaftar.

**Tempat melihatnya.** Dokumentasi menempatkan menu di Events tab: Event Actions untuk tingkat event dan menu Actions pada field di dalam event [S1]. Setelah search memakai transforming command, yang kamu lihat adalah Statistics tab, dan di sana event aslinya tidak ada lagi. Bila sebuah workflow action tidak muncul setelah `stats`, periksa dulu apakah kamu sedang melihat tab yang benar sebelum menuduh permission. Apakah menu ini tersedia di panel event pada dashboard tergantung jenis panel dan versi, jadi cek di versi-mu bila dashboard menjadi tempat kerja utama L1.

**Perubahan lewat file butuh restart.** Bila definisi disunting langsung di `workflow_actions.conf`, Splunk harus di-restart agar konfigurasinya aktif, kecuali perubahannya dilakukan lewat manager di Splunk Web [S5].

**Tanpa ES:** workflow action adalah fitur Splunk Enterprise biasa, jadi ketiga menu di Day ini bisa dipakai L1 PT JAB yang masih bekerja di app Search & Reporting, tanpa lisensi tambahan. Di Enterprise Security 8.7, halaman triage finding mendokumentasikan drill-down search yang membuka search bawaan di tab baru sebagai cara mengumpulkan konteks tambahan [S6], dan tidak menyebut workflow action. Jadi bila nanti pekerjaan L1 pindah ke analyst queue ES, jangan berasumsi menu yang kamu buat ikut muncul di sana; cek dokumentasi ES versi-mu dan siapkan drill-down search sebagai padanannya.

## 2. Contoh workflow action untuk PT JAB

Semua setelan di bawah ditulis sebagai tabel supaya bisa disalin ke form, dan semua keluaran di bagian ini adalah keluaran ilustrasi, bukan hasil eksekusi. Nilai yang dipakai konsisten dengan tiket SOC-2026-0244: IP eksternal `203.0.113.45`, host firewall perimeter, dan index sesuai daftar PT JAB.

### 2.1 GET ke layanan reputasi, dibatasi ke satu field

**Tujuan:** memberi L1 satu klik dari IP publik di event firewall ke halaman reputasi, tanpa memungkinkan klik yang sama pada field lain.

| Setelan | Nilai |
|---|---|
| Name | `jab_reputasi_ip` |
| Destination app | `search` |
| Label | `Reputasi IP: $src$` |
| Apply only to the following fields | `src` |
| Apply only to the following event types | `jab_fw_blocked_external` |
| Show action in | Fields menus |
| Action type | link |
| URI | `https://reputasi.example.net/lookup?ip=$src$` |
| Open link in | New window |
| Link method | get |

**Penjelasan tiap bagian.** Label memuat `$src$` supaya analyst membaca IP yang akan dikirim sebelum mengklik [S2]. Daftar field berisi satu nama, sehingga menu tidak pernah muncul di `user`, `customer_id`, atau `_raw` [S1]. Event type `jab_fw_blocked_external` (kamu buat sendiri dengan cara Day 17 bagian 2.1, berisi event firewall dengan `action=blocked` dan tujuan di luar ruang alamat internal, misalnya `index=firewall action=blocked NOT dest=10.10.0.0/16 NOT dest=10.20.0.0/16 NOT dest=10.30.0.0/16`) menjadi pembatas kedua, sehingga log internal tidak mendapat menu ini [S1]. Link method `get` membuat Splunk membangun URL berisi nilai field yang sudah di-URL-encode [S2].

**Keluaran ilustrasi.** Pada satu event firewall dengan `src=203.0.113.45`, menu Actions untuk field `src` berisi satu baris baru:

```
src = 203.0.113.45
  Actions
    Reputasi IP: 203.0.113.45
```

URL yang dibuka: `https://reputasi.example.net/lookup?ip=203.0.113.45`.

**Cara membacanya.** Yang perlu dicatat di note tiket bukan "sudah dicek reputasi", melainkan nama layanan, waktu pengecekan, dan kesimpulannya, karena halaman reputasi berubah dari waktu ke waktu dan tidak meninggalkan jejak di Splunk.

**Variasi.** Untuk field `dest` pada koneksi keluar, buat satu action lagi dengan daftar field `dest` dan Label `Reputasi tujuan: $dest$`. Memasukkan `src` dan `dest` ke satu action bisa dilakukan, tetapi ingat perilakunya: menu muncul untuk setiap field yang disebut, sedangkan di menu event ia hanya muncul bila kedua field ada [S1].

**Kapan gagal.** Bila `src` berisi IP privat, hasilnya halaman kosong atau menyesatkan, dan skema pengalamatan internal ikut terkirim. Tambahkan syarat di event type, misalnya hanya event dengan sumber di luar `10.0.0.0/8`, atau buat Label yang jelas menyebut "publik". Bila event dibuka dari Statistics tab, menunya tidak ada sama sekali, karena event aslinya sudah berubah menjadi tabel hasil [S1].

### 2.2 GET ke halaman internal, dan kapan `$!` dipakai

**Tujuan:** membuka runbook internal untuk sebuah event, tanpa escaping yang merusak URL.

| Setelan | Nilai |
|---|---|
| Name | `jab_runbook_sourcetype` |
| Label | `Runbook: $sourcetype$` |
| Apply only to the following fields | `sourcetype` |
| Show action in | Fields menus |
| Action type | link |
| URI | `https://wiki.corp.jab.example/soc/runbook?st=$sourcetype$` |
| Open link in | New window |
| Link method | get |

Pada URI di atas, encoding otomatis justru yang kamu inginkan: nilai `sourcetype` dikirim sebagai parameter, dan karakter titik dua di nama sourcetype aman setelah di-encode [S2].

Bentuk `$!` dipakai ketika isi field sudah berupa URL lengkap. Contohnya lookup internal yang memetakan nama POP ke URL dashboard NOC-nya, sehingga event memuat field `pop_dashboard_url`:

| Setelan | Nilai |
|---|---|
| Name | `jab_buka_dashboard_pop` |
| Label | `Dashboard POP $pop$` |
| Apply only to the following fields | `pop_dashboard_url` |
| Action type | link |
| URI | `$!pop_dashboard_url$` |
| Link method | get |

Prefix `$!` mencegah URL escape, sehingga alamat itu sampai ke browser tanpa diubah [S2]. Dokumentasi memberi contoh pola yang sama dengan field `http` [S2].

**Kapan gagal, dan kapan jangan dipakai.** Pola `$!` menjadi masalah ketika field-nya berasal dari data yang tidak kamu kendalikan. URL dari log proxy, misalnya, adalah URL yang mungkin dikunjungi penyerang atau justru milik penyerang. Membukanya langsung dari workstation analyst sama dengan mengunjungi situs itu dengan identitas jaringan perusahaan. Untuk field seperti itu, Search workflow action ke log proxy jauh lebih tepat, dan penilaian URL dikerjakan di tempat yang memang disiapkan untuk itu.

### 2.3 Search workflow action: riwayat 24 jam satu IP lintas index

**Tujuan:** mengganti tiga search yang diketik ulang setiap shift menjadi satu klik dengan rentang waktu dan daftar index yang sama untuk semua analyst.

| Setelan | Nilai |
|---|---|
| Name | `jab_riwayat_ip_24jam` |
| Label | `Riwayat 24 jam: $src$` |
| Apply only to the following fields | `src` |
| Show action in | Fields menus |
| Action type | search |
| Search string | `index IN (firewall, vpn, proxy) (src="$src$" OR dest="$src$") \| stats count AS jumlah, min(_time) AS pertama, max(_time) AS terakhir BY index, sourcetype, action \| eval pertama=strftime(pertama,"%F %T"), terakhir=strftime(terakhir,"%F %T") \| sort - jumlah` |
| App tempat search dijalankan | `search` |
| Jendela | New window |
| Earliest time | `-24h` |
| Latest time | kosong |

**Penjelasan tiap bagian.** Operator `IN (...)` dipakai di command `search` untuk menyebut tiga index sekaligus. Penanda `$src$` ditulis di dalam tanda kutip karena Splunk tidak menambahkan quoting pada nilai yang disisipkan ke search string [S5]. Kondisi `src=... OR dest=...` dipakai supaya satu klik menjawab dua arah sekaligus: IP itu sebagai sumber dan sebagai tujuan. `stats` memberi jumlah per index, sourcetype, dan `action`, sedangkan `min(_time)` dan `max(_time)` memberi batas waktu aktivitas yang nantinya dipakai untuk rentang absolut di note tiket. `strftime` mengubah epoch menjadi waktu yang bisa dibaca. Earliest `-24h` mencegah search berjalan atas all time, yang akan terjadi bila kedua kolom waktu dibiarkan kosong [S4].

**Keluaran ilustrasi** untuk `src=203.0.113.45`:

```
index     sourcetype        action   jumlah  pertama              terakhir
firewall  jab:fw:traffic    blocked  1842    2026-10-13 22:04:11  2026-10-14 06:51:02
vpn       jab:vpn:auth      failure  180     2026-10-13 23:52:07  2026-10-14 00:06:41
vpn       jab:vpn:auth      success  1       2026-10-14 00:06:58
```

**Cara membaca hasil.** Total baris ini 1842 + 180 + 1 = 2023 event dalam 24 jam, dan bentuknya bercerita: percobaan login VPN gagal 180 kali dalam 14 menit lalu satu sukses (pola yang sama dengan tiket SOC-2026-0217), sementara firewall memblokir 1842 koneksi dari IP yang sama sampai pagi. Yang menarik justru baris yang tidak ada: tidak ada baris `index=proxy`, jadi tidak ada indikasi host internal yang menghubungi IP itu lewat proxy. Satu baris `success` adalah yang menentukan eskalasi, bukan angka 1842.

**Variasi.**

- Ganti daftar index menjadi `index IN (firewall, vpn, proxy, dns, netops)` bila pertanyaannya mencakup perangkat POP.
- Untuk pivot dari akun, bukan IP, buat action kedua dengan daftar field `user` dan search string `index IN (wineventlog, vpn, o365) user="$user$" | stats count BY index, sourcetype, action`.
- Untuk dataset statis seperti BOTS, kosongkan Earliest dan Latest lalu aktifkan pilihan memakai rentang waktu search asal, sehingga rentang absolut yang sudah kamu set di time picker ikut terbawa [S4][S5].

**Kapan gagal.** Bila nilai `src` berisi karakter yang punya arti di SPL, search bisa gagal atau berubah arti, karena nilai yang disisipkan tidak di-escape [S5]; tanda kutip pada penanda mengurangi, bukan menghapus, risiko itu. Bila `action` tidak ada di salah satu sourcetype, barisnya akan kosong pada kolom itu, jadi jangan menyimpulkan "tidak ada yang diblokir" dari kolom kosong. Bila Earliest dan Latest sama-sama kosong dan pilihan rentang asal tidak aktif, search berjalan atas all time [S4].

### 2.4 Search workflow action tingkat event: dari satu event ke sesi di sekitarnya

**Tujuan:** dari satu event VPN yang mencurigakan, melihat semua aktivitas akun dan IP yang sama dalam jendela sempit di sekitar event itu, tanpa mengetik rentang waktu manual.

| Setelan | Nilai |
|---|---|
| Name | `jab_konteks_sesi_vpn` |
| Label | `Konteks sesi: $user$ dari $src$` |
| Apply only to the following fields | `user, src` |
| Apply only to the following event types | `jab_vpn_auth` |
| Show action in | Event menu |
| Action type | search |
| Search string | `index IN (vpn, wineventlog, o365) (user="$user$" OR src="$src$") \| table _time, index, sourcetype, action, user, src, dest \| sort _time` |
| Earliest time | `-1h` |
| Latest time | kosong |

**Penjelasan tiap bagian.** Karena Label dan search string memakai dua field, action ini pantas berada di Event menu: menu event hanya muncul bila semua field yang disebut ada di event itu [S1], dan di sini memang keduanya dibutuhkan. Event type `jab_vpn_auth` menjaga agar menu tidak muncul di event yang tidak punya makna sesi.

**Keluaran ilustrasi.** Dari satu event sukses pada 2026-10-14 00:06:58:

```
_time                index         sourcetype      action   user            src             dest
2026-10-14 00:06:41  vpn           jab:vpn:auth    failure  rina.wulandari  203.0.113.45    jkt-vpn01
2026-10-14 00:06:58  vpn           jab:vpn:auth    success  rina.wulandari  203.0.113.45    jkt-vpn01
2026-10-14 00:08:12  wineventlog   XmlWinEventLog  success  rina.wulandari  10.10.44.19     JKT-FS01
2026-10-14 00:09:03  o365          o365:management success  rina.wulandari  203.0.113.45    -
```

**Cara membaca hasil.** Empat baris ini menjawab pertanyaan eskalasi lebih cepat daripada tiga search terpisah: sukses VPN diikuti akses file server dalam dua menit, dan pada menit yang sama ada aktivitas cloud dari IP publik yang sama. Perhatikan bahwa `src` pada baris Windows adalah IP internal setelah tunnel terbentuk, jadi dua nilai `src` yang berbeda di tabel ini bukan kontradiksi.

**Variasi.** Perlebar Earliest menjadi `-4h` untuk pertanyaan handover, atau tambahkan `index=netops` bila perangkat POP perlu ikut diperiksa.

**Kapan gagal.** Bila field `user` di sourcetype lain bernama lain (`Account_Name` di log Windows format klasik), hasilnya terlihat kosong padahal datanya ada. Di situlah field alias dan normalisasi berperan (Day 16, Day 23, dan Day 24); workflow action hanya sebaik nama field di datamu. Perlu diingat juga bahwa log Windows format klasik bisa memuat dua akun dalam satu event, sehingga field akun berpotensi multivalue dan nilai yang terbawa ke search belum tentu akun yang kamu maksud.

### 2.5 POST ke sistem tiket internal

**Tujuan:** membuat tiket di sistem tiket PT JAB dari satu event firewall, dengan isi yang sudah terisi, tanpa menyalin apa pun.

| Setelan | Nilai |
|---|---|
| Name | `jab_buat_tiket_soc` |
| Label | `Buat tiket SOC untuk $src$` |
| Apply only to the following fields | `src` |
| Apply only to the following event types | `jab_fw_blocked_external` |
| Show action in | Event menu |
| Action type | link |
| URI | `https://tiket.corp.jab.example/api/v1/issues` |
| Open link in | New window |
| Link method | post |
| Post arguments 1 | key `title`, value `SOC: koneksi diblokir dari $src$` |
| Post arguments 2 | key `queue`, value `soc-l1` |
| Post arguments 3 | key `sumber_event`, value `$sourcetype$ di $host$ pada $_time$` |
| Post arguments 4 | key `description`, value `$_raw$` |

**Penjelasan tiap bagian.** Pasangan key dan value ditambahkan satu per satu, dan nama field dalam tanda dolar boleh berada di kedua sisi [S3]. Argumen `queue` statis supaya tiket selalu masuk antrean yang benar. Argumen `description` dengan `$_raw$` mengikuti pola contoh dokumentasi yang mengirim `_raw` ke field deskripsi [S3], dan di sini aman karena tujuannya sistem internal. Semua nilai di-HTTP-form-encode otomatis [S3][S5].

**Keluaran ilustrasi.** Setelah menu diklik, sistem tiket membalas dengan halaman tiket baru:

```
Tiket SOC-2026-0244 dibuat
title        : SOC: koneksi diblokir dari 203.0.113.45
queue        : soc-l1
sumber_event : jab:fw:traffic di JKT-FW01 pada 2026-10-14 06:51:02
```

**Cara membaca hasil.** Yang dihasilkan satu tiket per klik, dan tidak ada idempotensi: dua klik menghasilkan dua tiket. Biasakan mengecek antrean sebelum mengklik, atau minta sistem tiket melakukan deduplikasi berdasarkan `title`.

**Variasi.** Untuk sistem tiket yang menerima JSON, POST workflow action dengan pasangan key dan value seringkali tidak cocok; di situ alert action atau playbook lebih tepat (Day 09 dan Day 42).

**Kapan gagal.** Endpoint yang menuntut header otorisasi khusus tidak akan menerima request dari browser analyst, dan gejalanya halaman error dari sistem tiket, bukan error di Splunk. Bila tujuan POST adalah layanan pihak ketiga, hapus argumen `$_raw$` lebih dulu; di PT JAB satu baris log portal pelanggan bisa memuat ID pelanggan, dan field itu tidak boleh keluar organisasi.

### 2.6 Membaca ulang semua setelan dari file

**Tujuan:** memeriksa tiga action sekaligus saat review, dan memindahkannya ke lingkungan lain tanpa mengisi form dua kali.

Bentuk file dari dua action di atas, sesuai nama setelan di spesifikasi [S5]:

```
[jab_reputasi_ip]
type = link
label = Reputasi IP: $src$
fields = src
eventtypes = jab_fw_blocked_external
display_location = field_menu
link.uri = https://reputasi.example.net/lookup?ip=$src$
link.target = blank
link.method = get

[jab_riwayat_ip_24jam]
type = search
label = Riwayat 24 jam: $src$
fields = src
display_location = field_menu
search.search_string = index IN (firewall, vpn, proxy) (src="$src$" OR dest="$src$") | stats count AS jumlah BY index, sourcetype, action | sort - jumlah
search.app = search
search.target = blank
search.earliest = -24h
```

**Cara membacanya saat review.** Tiga baris yang paling layak diperiksa: `fields` (apakah masih `*`), `link.uri` (apakah tujuannya pihak ketiga), dan `search.earliest` (apakah ada, supaya tidak all time). Default yang perlu diingat: `fields` default `*`, `display_location` default `both`, `link.target` default `blank`, `link.method` default `get`, dan `search.preserve_timerange` default `false` [S5].

**Kapan gagal.** Menyunting file secara langsung butuh restart Splunk agar aktif, kecuali perubahan dilakukan lewat manager di Splunk Web [S5]. Di deployment terdistribusi, definisi ini perlu ada di search head tempat analyst bekerja, bukan di indexer.

## 3. Lab praktik (di VM lab terisolasi)

Lab ini tidak perlu data produksi dan tidak boleh diarahkan ke layanan pihak ketiga. URL eksternal yang dipakai cukup domain dokumentasi, dan yang diperiksa adalah URL yang terbentuk, bukan jawaban layanannya.

1. **Siapkan event uji tanpa onboarding data.** Jalankan search berikut, simpan sebagai report, lalu buka satu event dari Events tab:

   ```
   | makeresults count=3
   | streamstats count AS n
   | eval _time=strptime("2026-10-14 06:00:00","%Y-%m-%d %H:%M:%S") + (n-1)*600
   | eval src=case(n==1,"203.0.113.45",n==2,"10.20.10.11",n==3,"198.51.100.77")
   | eval user=case(n==1,"rina.wulandari",n==2,"svc_billing",n==3,"andi.pratama")
   | eval action="blocked", sourcetype_uji="jab:fw:traffic"
   ```

   Tiga event ini memberi satu IP publik dokumentasi, satu IP internal, dan satu IP publik lain, cukup untuk menguji pembatasan field dan perilaku IP privat.

2. **Buat GET workflow action dengan daftar field `*`.** URI: `https://example.com/lookup?ip=$src$`. Buka satu event, lalu catat di field mana saja menu itu muncul. Jumlahnya harus sama dengan jumlah field pada event itu.
3. **Perketat ke satu field.** Ubah Apply only to the following fields menjadi `src`, lalu ulangi langkah 2. Catat selisihnya. Ini bukti bahwa pembatasan field adalah kontrol, bukan kosmetik.
4. **Uji perilaku daftar beberapa field.** Isi daftar field dengan `src, user`, lalu bandingkan menu field dan menu event pada event yang punya kedua field dan pada event yang hanya punya satu. Tulis satu kalimat tentang perbedaannya, lalu bandingkan dengan aturan di bagian 1.2.
5. **Uji encoding dan `$!`.** Tambahkan `| eval catatan="uji spasi & tanda"` ke search langkah 1, lalu buat dua GET action dengan URI `https://example.com/q=$catatan$` dan `https://example.com/q=$!catatan$`. Klik keduanya dan catat URL yang terbentuk di address bar browser. Tulis mana yang aman dan kenapa.
6. **Buat Search workflow action tanpa rentang waktu.** Search string `index=_internal sourcetype=splunkd`, kedua kolom waktu dibiarkan kosong. Jalankan, lalu buka Job Inspector dan catat rentang waktu yang dipakai. Cocokkan dengan aturan all time di bagian 1.5.
7. **Perbaiki rentang waktunya.** Isi Earliest `-1h`, jalankan ulang, dan catat perbedaan waktu eksekusi serta jumlah event yang dipindai. Angka ini yang kamu pakai untuk meyakinkan rekan kerja bahwa kolom waktu bukan opsional.
8. **Uji quoting.** Buat Search workflow action dengan search string `index=_internal $catatan$` lalu dengan `index=_internal "$catatan$"`, pada event yang field `catatan`-nya memuat spasi. Catat mana yang berjalan dan apa pesan errornya. Jangan memakai nilai yang memuat pipe di luar lab.
9. **Uji permission dan app context.** Set permission salah satu action menjadi private, lalu buka Splunk dengan user lain (atau role lain) dan catat apakah menunya muncul. Lalu set sharing ke app `search` saja, pindah ke app lain, dan catat hasilnya.
10. **Uji tab.** Tambahkan `| stats count BY src` ke search langkah 1, lalu cari menu workflow action di Statistics tab. Catat hasilnya dan kaitkan ke penjelasan di bagian 1.7.
11. **Baca bentuk filenya.** Buka definisi lewat Settings > Fields > Workflow actions sekali lagi, lalu catat semua setelan yang kamu isi dalam bentuk stanza seperti bagian 2.6, termasuk setelan yang kamu biarkan default.

**Hasil yang sebaiknya tersimpan:**
- Dua catatan jumlah menu dari langkah 2 dan 3, sebagai bukti efek pembatasan field.
- Satu kalimat dari langkah 4 tentang perbedaan menu field dan menu event untuk daftar beberapa field.
- Dua URL hasil langkah 5, berdampingan.
- Dua angka dari langkah 6 dan 7 (rentang waktu dan jumlah event yang dipindai).
- Pesan error dari langkah 8.
- Hasil langkah 9 dan 10 dalam dua baris, sebagai daftar periksa pertama saat menu tidak muncul.
- Stanza dari langkah 11, sebagai templat untuk action berikutnya.

**Variasi tantangan:** buat satu Search workflow action yang hanya memakai pilihan rentang waktu search asal (kedua kolom waktu kosong), lalu jalankan dari dua time picker berbeda dan catat rentang yang terbawa. Setelah itu isi Earliest, ulangi, dan buktikan sendiri bahwa pilihan rentang asal diabaikan [S5]. Catatan hasil ini yang nanti kamu pakai untuk dataset statis.

## 4. Troubleshooting

Tabel ini memuat gejala yang paling sering muncul saat workflow action tidak berperilaku seperti yang diharapkan. Cari gejalanya di kolom pertama.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Menu tidak muncul di field mana pun | Permission private atau sharing terbatas ke app lain (Day 15) | Cek permission objek dan app yang sedang kamu pakai; Destination app menentukan tempat definisi hidup [S1] |
| Menu tidak muncul walau field ada | Pembatas event type tidak terpenuhi [S1] | Cek apakah event itu benar anggota event type tersebut (Day 17) |
| Menu hilang setelah search diubah | Hasil sudah berupa tabel, bukan event; menu ada di Events tab [S1] | Buka event aslinya tanpa transforming command |
| Menu muncul di terlalu banyak field | Daftar field masih `*`, yang berarti semua field [S1][S5] | Isi Apply only to the following fields dengan nama field eksplisit |
| Menu tidak muncul di menu event walau salah satu field ada | Dengan beberapa field, menu event butuh semua field hadir [S1] | Pecah menjadi beberapa action, satu per field |
| Menu muncul tetapi field tidak terisi | Field belum terekstrak pada mode search yang dipakai | Buka event dan pastikan field terdaftar; cek search mode |
| URL yang terbuka rusak atau terpotong | Nilai field memuat karakter khusus, atau justru sudah URL lengkap sehingga encoding merusaknya [S2] | Pakai `$!field$` untuk nilai yang sudah berupa URL [S2] |
| Layanan tujuan menolak nilai | Nilai dikirim ter-encode, sementara layanan mengharapkan bentuk mentah [S2][S3] | Uji dengan `$!` pada satu field dulu, lalu catat mana yang diterima |
| Search workflow action berjalan sangat lama | Kedua kolom waktu kosong, sehingga search berjalan atas all time [S4] | Isi minimal Earliest, atau aktifkan pilihan rentang waktu search asal [S4][S5] |
| Rentang waktu asal tidak terbawa | `search.preserve_timerange` diabaikan karena earliest atau latest diisi [S5] | Kosongkan keduanya bila yang kamu inginkan rentang asal |
| Search gagal pada nilai tertentu | Nilai yang disisipkan tidak diberi quoting atau escaping oleh Splunk [S5] | Beri tanda kutip sendiri pada penanda, dan batasi ke field terstruktur |
| POST tidak menghasilkan apa pun | Endpoint butuh autentikasi atau header yang tidak dikirim browser | Uji endpoint-nya di luar Splunk dulu; pertimbangkan alert action atau playbook (Day 09, Day 42) |
| Perubahan di file tidak berlaku | Konfigurasi file butuh restart kecuali disunting lewat manager [S5] | Restart, atau sunting lewat Splunk Web |
| Action muncul di search head satu dan tidak di yang lain | Definisi hanya ada di satu search head | Distribusikan app yang memuat definisinya ke search head yang dipakai analyst |
| Menu tidak ada di panel event dashboard | Perilaku bergantung jenis panel dan versi | Cek di versi-mu; untuk kebutuhan tetap, sediakan drilldown panel sebagai pengganti |

## 5. Kesalahan umum dan jebakan

- Membiarkan daftar field `*` pada action yang mengirim data ke luar. Satu klik yang salah pada field `customer_id` atau `user` mengirim data internal ke pihak ketiga, dan tidak ada cara menariknya kembali.
- Menganggap URL encoding sebagai perlindungan. Encoding hanya membuat nilai aman untuk URL [S2], bukan rahasia; nilainya tetap tercatat di log pihak ketiga dan di log proxy sendiri.
- Memakai `$_raw$` sebagai isi Post arguments ke layanan pihak ketiga. Contoh dokumentasi memakainya untuk stacktrace aplikasi sendiri [S3]; pada log ISP, satu event bisa memuat identitas pelanggan.
- Membiarkan kedua kolom waktu kosong pada Search workflow action. Default-nya all time [S4], dan pada index DNS resolver pelanggan itu membebani search head untuk semua orang.
- Mengisi Earliest lalu berharap rentang waktu search asal yang dipakai. Pilihan itu diabaikan bila earliest atau latest diisi [S5].
- Menyisipkan nilai field ke search string tanpa tanda kutip. Nilai yang disisipkan tidak diperiksa soal quoting atau escaping [S5], jadi nilai dari data bisa mengubah bentuk search.
- Memakai rentang relatif pada dataset statis. Untuk BOTS, pakai pilihan rentang waktu search asal dan set rentang absolutnya di time picker.
- Membuka URL dari log proxy dengan `$!` dari workstation kantor. Itu mengunjungi infrastruktur yang belum dinilai dengan identitas jaringan perusahaan.
- Mencari menu workflow action di Statistics tab. Menu itu hidup di event, dan setelah transforming command event aslinya tidak ada lagi [S1].
- Menyimpan action dengan permission private lalu menjanjikannya ke tim. Objek yang tidak dibagikan tidak terlihat orang lain, dan objek milik user yang keluar bisa menjadi yatim (Day 15).
- Menulis "sudah dicek reputasi" di note tiket tanpa menyebut layanan, waktu, dan kesimpulan. Hasil GET tidak meninggalkan jejak apa pun di Splunk.
- Mengandalkan POST sebagai otomasi respons. Tidak ada status, tidak ada retry, dan tidak ada jejak audit; dua klik menghasilkan dua tiket.
- Mengira workflow action yang dibuat di Splunk Enterprise otomatis muncul di antrean ES. Dokumentasi triage ES 8.7 menyebut drill-down search sebagai cara mengumpulkan konteks tambahan [S6], jadi siapkan padanannya di sana.
- Membuat satu action gabungan untuk `src` dan `dest` lalu heran menu event tidak muncul. Menu event butuh semua field yang disebut hadir [S1].
- Lupa bahwa field akun pada log Windows format klasik berpotensi multivalue, sehingga nilai yang terbawa ke search belum tentu akun yang kamu maksud.

## 6. Catatan terkini

Bagian ini menampung detail versi dan nama setelan yang berbeda antara form di Splunk Web dan file konfigurasi, supaya catatan ini masih bisa dipakai ketika tampilan form berubah.

- Nama setelan di form dan di file tidak selalu sama. Show action in menjadi `display_location` (nilai `field_menu`, `event_menu`, `both`, default `both`), Open link in menjadi `link.target` (nilai `blank` dan `self`, default `blank`), dan pilihan memakai rentang waktu search asal menjadi `search.preserve_timerange` (default `false`) [S5].
- Default yang perlu diingat saat review: `fields` default `*`, `link.method` default `get`, dan `disabled` default `False` [S5]. Spesifikasi `workflow_actions.conf` yang dibaca untuk catatan ini berasal dari berkas versi 10.6.0.5 [S5].
- Halaman setup di dokumentasi 10.6 menyebut jalur Settings > Fields > Workflow Actions dengan tombol New, sedangkan halaman ikhtisarnya menyebut Add new untuk membuat baru [S1][S2]. Keduanya menunjuk hal yang sama; cek label tombol di versi-mu.
- Halaman setup Search workflow action 10.6 tidak memberi nama resmi untuk beberapa kolom (app, view, jendela, dan pilihan rentang waktu search asal) dan hanya menjelaskan fungsinya [S4]. Nama yang dipakai di Day ini diambil dari nama setelan di file konfigurasi [S5], jadi label di layar bisa berbeda.
- Pencegahan escaping dengan prefix `$!` disebut untuk GET (URL escape) dan POST (HTTP form escape) [S2][S3]. Untuk Search workflow action, spesifikasi justru menyebut bahwa nilai yang disisipkan tidak diperiksa soal quoting atau escaping [S5], jadi di sanalah tanggung jawab pindah ke penulis search string.
- Di Enterprise Security 8.7, halaman triage finding mendokumentasikan drill-down search yang membuka search bawaan di tab baru [S6] dan tidak menyebut workflow action. Bila nanti L1 bekerja di analyst queue, cek dokumentasi ES versi-mu untuk mekanisme pivot yang setara.
- Dokumentasi resmi kini di help.splunk.com, dan tautan docs.splunk.com lama masih beredar untuk halaman yang sama.

## 7. Cheat sheet

```
TEMPAT MEMBUAT
  Settings > Fields > Workflow actions > New        (butuh Name + Destination app)
  bentuk file: workflow_actions.conf  (restart kecuali disunting lewat manager)

TIGA JENIS
  Action type link + Link method get   -> buka URL berisi $field$   (KELUAR organisasi bila URL eksternal)
  Action type link + Link method post  -> kirim Post arguments ke URI
  Action type search                   -> jalankan search baru di Splunk

PEMBATAS KEMUNCULAN
  Apply only to the following fields      default * (= semua field)   -> isi eksplisit untuk aksi eksternal
  Apply only to the following event types daftar event type, wildcard didukung
  Show action in                          Event menu / Fields menus / Both   (conf: display_location, default both)
  beberapa field  -> menu field muncul per field; menu EVENT butuh SEMUA field hadir

PENANDA NILAI
  $field$     nilai field, di-encode otomatis (URL encode di GET, form encode di POST)
  $!field$    tanpa escaping; untuk field yang sudah berisi URL lengkap
  search string: TIDAK di-escape, TIDAK di-quote  -> tulis sendiri: src="$src$"

SETELAN FILE (default)
  type, label                         wajib
  fields = *                          link.target = blank (self = jendela sama)
  display_location = both             link.method = get
  link.uri                            link.postargs.<int>.<key/value>   (hanya saat method post)
  search.search_string                search.app = app saat ini   search.view = view saat ini
  search.earliest / search.latest     search.target = blank|self
  search.preserve_timerange = false   (DIABAIKAN bila earliest atau latest diisi)

WAKTU
  Earliest + Latest kosong            -> ALL TIME (jangan)
  Earliest -24h, Latest kosong        -> pola triage harian
  dataset statis (BOTS)               -> kosongkan keduanya, aktifkan pakai rentang search asal

DAFTAR PERIKSA SEBELUM DIBAGIKAN
  [ ] fields bukan *                  [ ] tidak ada $_raw$ ke pihak ketiga
  [ ] earliest terisi                 [ ] label menampilkan nilai yang akan dikirim
  [ ] permission dan app sudah benar  [ ] sudah diuji dari event nyata di Events tab
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "GET workflow action aman dari sisi kerahasiaan, karena Splunk hanya membuat link dan nilainya di-URL-encode." Tepat?

<details><summary>Jawaban</summary>

Tidak. Encoding hanya membuat karakter khusus aman di dalam URL, bukan membuat nilainya rahasia. Nilai field dikirim sebagai bagian dari permintaan web ke pihak ketiga, dan karena yang mengirim adalah browser analyst, URL itu juga tercatat di log proxy perusahaan dan riwayat browser. Perlindungan yang nyata adalah membatasi field yang boleh dipakai dan tidak pernah mengirim field yang bisa dikaitkan ke orang atau pelanggan. Lihat bagian 1.3 dan 1.6.

</details>

**2. Skenario keputusan.** Rekanmu membuat workflow action reputasi IP dengan Apply only to the following fields dikosongkan, alasannya "biar fleksibel, analyst tahu field mana yang pantas diklik". Apa yang kamu lakukan?

- A. Setuju, karena pembatasan field hanya soal kerapian menu dan analyst sudah dilatih.
- B. Isi daftar field dengan `src` dan `dest` saja, tambahkan event type perimeter sebagai pembatas kedua, dan buat Label yang menampilkan nilai yang akan dikirim.
- C. Tolak workflow action eksternal sepenuhnya dan minta analyst tetap menyalin manual.

<details><summary>Jawaban</summary>

B. Daftar field kosong atau `*` berarti menu muncul di semua field, termasuk field yang memuat akun, ID pelanggan, dan nilai internal lain, sehingga satu klik keliru menjadi pengiriman data ke pihak ketiga. Pembatasan field dan event type adalah kontrol teknis yang tersedia tanpa biaya, dan Label yang memuat nilai membuat analyst melihat apa yang akan keluar sebelum mengklik. A memindahkan kontrol ke kedisiplinan manusia pada saat shift malam. C menghapus manfaatnya sekaligus tidak menghilangkan risiko, karena menyalin manual ke portal yang sama mengirim data yang sama. Lihat bagian 1.2 dan 1.6.

</details>

**3. Pertanyaan jebakan.** "Search workflow action yang kolom Earliest dan Latest-nya kosong akan memakai rentang waktu search yang sedang kamu buka." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Bila kedua kolom waktu dibiarkan kosong, search berjalan atas all time. Memakai rentang waktu search asal adalah pilihan tersendiri (`search.preserve_timerange` di file konfigurasi, default `false`), dan pilihan itu diabaikan begitu Earliest atau Latest diisi. Jadi ada dua keputusan terpisah: mengisi rentang sendiri, atau mengosongkan keduanya dan menyalakan pilihan rentang asal. Lihat bagian 1.5.

</details>

**4. Jelaskan ulang.** Jelaskan kepada network engineer NOC PT JAB dalam tiga kalimat apa itu workflow action dan apa beda ketiga jenisnya.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Workflow action itu menu klik kanan yang kita definisikan sendiri di Splunk: ia muncul di sebuah event atau di satu field, lalu membawa nilai field itu ke tempat lain. Ada tiga tujuan: GET membuka URL yang memuat nilai itu, misalnya halaman reputasi IP, POST mengirim nilai itu sebagai data ke sistem lain, misalnya membuat tiket, dan Search menjalankan search baru di Splunk, misalnya riwayat 24 jam untuk IP yang sama. Bedanya yang paling penting bukan teknisnya tetapi ke mana datanya pergi: Search tetap di dalam Splunk kita, sedangkan GET dan POST ke layanan luar berarti nilai field itu keluar dari organisasi lewat browser analyst."

Kesalahan yang sering muncul:
- Menyebutnya otomasi respons. Workflow action tidak punya status, persetujuan, atau jejak audit.
- Lupa menyebut bahwa pengirimnya browser analyst, bukan server Splunk.
- Mengira hasil enrichment GET ikut tersimpan ke dalam event. Tidak ada yang tersimpan; yang tersimpan hanya apa yang kamu tulis di note tiket.

</details>

**5. Skenario keputusan.** Tim ingin satu klik yang mengirim event ke layanan sandbox publik untuk dinilai, dengan Post arguments `description` berisi `$_raw$`. Event yang dimaksud berasal dari log portal pelanggan. Apa keputusanmu?

- A. Jalankan, karena `_raw` memberi konteks paling lengkap untuk penilaian dan contoh dokumentasi memang memakai `$_raw$`.
- B. Kirim hanya field yang sudah disepakati (misalnya hash dan nama berkas), tambahkan satu field referensi internal seperti nomor tiket, dan tahan `$_raw$` untuk sistem internal saja.
- C. Buat action-nya tetapi beri tahu analyst agar berhati-hati memakainya.

<details><summary>Jawaban</summary>

B. Contoh dokumentasi memakai `$_raw$` untuk mengirim stacktrace aplikasi sendiri ke sistem isu, dan konteksnya internal. Log portal pelanggan di ISP memuat identitas yang bisa dikaitkan ke pelanggan, jadi `$_raw$` ke layanan publik berubah menjadi jalur keluar data pelanggan, apalagi karena banyak layanan publik membuat kiriman dapat dilihat pihak lain. Mengirim field yang sudah disepakati memberi hasil yang sama bergunanya untuk penilaian, dan field referensi internal menjaga jejaknya di tiket. A mengabaikan perbedaan konteks data. C memindahkan keputusan kebijakan ke analyst saat shift, padahal pembatasan bisa dipasang di definisinya. Lihat bagian 1.4 dan 1.6.

</details>

**6. Pertanyaan jebakan.** "Karena Splunk melakukan encoding otomatis pada nilai field, Search workflow action aman terhadap nilai yang memuat spasi atau tanda kutip." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Encoding otomatis berlaku untuk URI pada GET dan untuk argumen pada POST. Untuk Search workflow action, spesifikasinya justru menyebut bahwa nilai yang disisipkan ke search string tidak diperiksa soal quoting maupun escaping, sehingga nilai dengan spasi membuat search mencari hal lain dan nilai dengan karakter khusus bisa mengubah bentuk search. Yang perlu kamu lakukan: beri tanda kutip sendiri pada penanda (`src="$src$"`) dan batasi action ke field yang nilainya terstruktur, bukan ke `_raw` atau user agent. Lihat bagian 1.5.

</details>

**7. Interview question (English).** "How would you let tier-1 analysts pivot from an IP in an alert to its traffic history and to an external reputation service, and what would you worry about?"

<details><summary>Sample answer</summary>

"I'd build it as two separate workflow actions instead of leaving it to copy and paste, because then the pivot becomes an object we maintain rather than a habit that differs per analyst. The internal one is a search workflow action scoped to the `src` field: it runs a fixed search across the firewall, VPN and proxy indexes for that IP as source or destination, with an explicit earliest of minus twenty four hours, because if you leave both time fields blank the search runs over all time and on a large DNS index that hurts everybody. I always quote the placeholder myself, like `src=\"$src$\"`, since Splunk does not quote or escape values that go into a search string. The external one is a GET action, and that is the one I worry about: the analyst's browser sends the field value to a third party, so the value ends up in their logs and in our own proxy logs, and URL encoding is not confidentiality. So I scope it to `src` and `dest` only, never a wildcard, I add an event type restriction so it only shows on perimeter events, I put the value in the label so the analyst sees what is about to leave, and I never put `$_raw$` into anything pointing outside, because at an ISP one raw line can identify a subscriber. And I treat whether we may use that service at all as a policy decision to be recorded, not a technical one."

What makes this answer strong: it separates the internal pivot from the external one and explains why that distinction matters, names two concrete traps with consequences (all-time default and unescaped search strings), shows the scoping controls as security controls rather than cosmetics, and ends by putting the third-party question where it belongs, in policy.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Splunk Enterprise 10.6 Knowledge Manager Manual: About workflow actions in Splunk Web | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/workflow-actions | primer | diakses 2026-10-14 | Tinggi. Tiga jenis action (GET, POST, search), jalur Settings > Fields > Workflow actions, Name dan Destination app, letak menu di Event Actions dan menu Actions pada field, aturan pembatasan daftar field termasuk perilaku `*` dan beberapa field, pembatasan event type dengan wildcard, dan contoh gabungan dengan event type `errors_in_500_range` |
| S2 | Splunk Enterprise 10.6 Knowledge Manager Manual: Set up a GET workflow action | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/workflow-actions/set-up-a-get-workflow-action | primer | diakses 2026-10-14 | Tinggi. Nama setelan Label, Apply only to the following fields, Apply only to the following event types, Show action in, Action type, URI, Open link in, Link method; `$field$` di Label dan URI; URL encoding otomatis; prefix `$!`; contoh Google dan WHOIS |
| S3 | Splunk Enterprise 10.6 Knowledge Manager Manual: Set up a POST workflow action | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/workflow-actions/set-up-a-post-workflow-action | primer | diakses 2026-10-14 | Tinggi. Link method post, Post arguments key dan value beserta Add another field, HTTP form encoding otomatis, prefix `$!` untuk mencegah form escaping, contoh pengiriman `title` dan `description` berisi `_raw` ke sistem isu |
| S4 | Splunk Enterprise 10.6 Knowledge Manager Manual: Set up a search workflow action | https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.6/workflow-actions/set-up-a-search-workflow-action | primer | diakses 2026-10-14 | Tinggi untuk alur dan contoh. Action type search, Search string dengan `$field$`, app dan view tujuan, pilihan jendela, Earliest time dan Latest time, all time bila keduanya kosong, pilihan memakai rentang waktu search asal, contoh Ruby on Rails dan `clientip=$clientip$`. Beberapa kolom tidak diberi nama resmi di halaman ini |
| S5 | Splunk Enterprise 10.6 Admin Manual: workflow_actions.conf (spesifikasi 10.6.0.5) | https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.6/configuration-file-reference/10.6.0-configuration-file-reference/workflow_actions.conf | primer | diakses 2026-10-14 | Tinggi. Nama dan default setiap setelan: `type`, `label`, `fields` (default `*`), `eventtypes`, `display_location` (default `both`), `disabled`, `link.uri`, `link.target` (default `blank`), `link.method` (default `get`), `link.postargs.<int>.<key/value>`, `search.search_string` (nilai tidak diperiksa soal quoting dan escaping), `search.app`, `search.view`, `search.target`, `search.earliest`, `search.latest`, `search.preserve_timerange` (default `false`, diabaikan bila earliest atau latest diisi), lokasi file default, dan keharusan restart |
| S6 | Splunk Enterprise Security 8.7 User Guide: Triage findings and finding groups | https://help.splunk.com/en/splunk-enterprise-security-8/user-guide/8.7/mission-control/triage-findings-and-finding-groups-in-splunk-enterprise-security | primer | diakses 2026-10-14 | Tinggi untuk satu hal: halaman ini mendokumentasikan drill-down search yang membuka search bawaan di tab baru untuk mengumpulkan konteks, dan tidak menyebut workflow action |

**Catatan sumber:** daftar pertanyaan kebijakan di bagian 1.6 (apa yang dibutuhkan layanan, apakah nilainya bisa dikaitkan ke orang, apakah layanan menyimpan dan membagikan kiriman, apakah pivotnya bisa dikerjakan di dalam) adalah praktik kerja yang disusun untuk catatan ini, bukan daftar dari dokumentasi; yang berasal dari dokumentasi hanya mekanismenya, yaitu bahwa nilai field disisipkan ke URI dan dikirim sebagai permintaan web [S2][S5] dan bahwa isi POST ditentukan Post arguments [S3]. Pernyataan bahwa URL GET juga tercatat di log proxy dan riwayat browser adalah konsekuensi langsung dari cara kerja link di browser, bukan kutipan. Perilaku menu di panel event dashboard dan ketersediaannya di Statistics tab tidak dibahas halaman yang dibaca; yang disebut dokumentasi hanya letaknya di Events tab dan di menu field dalam event [S1], jadi buktikan sendiri dengan langkah 10 di bagian 3. Nama kolom untuk app, view, jendela, dan pilihan rentang waktu pada Search workflow action diambil dari nama setelan di file konfigurasi [S5] karena halaman setup-nya tidak memberi nama resmi [S4]. Semua keluaran di bagian 2 adalah keluaran ilustrasi yang disusun agar konsisten dengan tiket SOC-2026-0217 dan SOC-2026-0244, bukan hasil eksekusi.
