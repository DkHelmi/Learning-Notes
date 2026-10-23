---
day: 24
title: 'Browser dan artefak cloud sync: riwayat, transisi, unduhan, OneDrive, Teams, dan batas artefak cloud'
researched_on: 2026-10-22
versions_checked: 'Chromium source (page_transition_types.h, visit_database.cc, download_database.cc, HEAD per 2026-10-22); Hindsight v2026.06 (rilis 2026-07-08, dukungan Firefox); odl.py (ydkhatri/OneDrive, general.keystore sejak 2022); OneDriveExplorer (Beercow, opsi -s untuk database SQLite); dfindexeddb (Google); Microsoft Teams baru berbasis WebView2 (makalah CEUR Vol-4198 paper14, terbit 2026-04-23, build uji 25072.125072.1611.3570); Microsoft Learn Clear the Teams client cache; Microsoft Purview audit-log-activities (ms.date 2026-10-15) dan audit-solutions-overview (ms.date 2026-05-18, Audit Standard 180 hari); Firefox nsINavHistoryService.idl; Windows 11 23H2 (build 22631); EZ Tools 2026.5.0 (dibekukan untuk INC-2027-010)'
---

# Day 24: Browser dan artefak cloud sync

Cakupan: membaca riwayat, transisi kunjungan, unduhan, dan cache browser berbasis Chromium dan Firefox, lalu klien OneDrive (database dan log) dan Teams baru berbasis WebView2, sampai batas yang hanya bisa dijawab audit log layanan cloud, dikerjakan sebagai adendum laporan forensik `INC-2027-010`.

## Ide inti

Browser dan klien sinkronisasi cloud mencatat apa yang dilakukan aplikasi di laptop itu, bukan apa yang sampai ke pihak lain. Riwayat browser mencatat navigasi (alamat, waktu, dan cara alamat itu dibuka), tetapi hampir tidak pernah mencatat unggahan: lampiran webmail dikirim lewat permintaan latar belakang yang tidak menjadi baris riwayat. Klien OneDrive mencatat operasi sinkronisasi yang ia jalankan, tetapi tidak tahu siapa yang membuka berkas dari browser di perangkat lain atau apakah tautan berbagi dibuat di web. Teams menyimpan cache percakapan yang pernah ditampilkan, bukan arsip lengkap. Jadi pertanyaan "berkas apa keluar lewat mana" selalu terbelah dua: bagian yang dijawab host (navigasi yang disengaja, berkas yang dipegang klien, waktu yang bisa dikorelasikan) dan bagian yang hanya dijawab layanan cloud (berbagi, akses dari perangkat lain, pesan terkirim). Pekerjaan forensik endpoint di wilayah ini adalah menyelesaikan bagian host sampai tuntas, menunjuk sumber cloud untuk sisanya, dan tidak menulis kalimat yang melompati garis itu.

Hal kedua: wilayah ini paling cepat berubah. Skema database browser bertambah kolom setiap beberapa rilis, log OneDrive berganti cara obfuskasi, dan klien Teams pindah arsitektur sehingga semua jalur lamanya tidak berlaku. Karena itu setiap jalur dan nama kolom di Day ini ditulis bersama cara memeriksanya di salinan bukti, dan setiap alat dipakai bersama satu pembanding.

Polanya sudah kamu kenal dari NOC. Di CPE pelanggan kamu bisa melihat sesi PPPoE, counter byte keluar, dan log DNS lokal: kapan pelanggan online, ke domain mana, berapa byte. Kamu tidak bisa melihat dari CPE siapa yang mengunduh berkas dari server pelanggan atau apa isi trafik terenkripsi; itu ada di log server tujuan. Browser adalah CPE-nya: catatan sesi dan tujuan, bukan isi. Klien OneDrive mirip agent backup konfigurasi yang mengirim berkas ke server pusat: log agent menunjukkan apa yang dikirim agent dari perangkat itu, sedangkan siapa yang kemudian mengambil berkas dari server pusat hanya tercatat di server. Batas analoginya: browser menyimpan sedikit lebih banyak dari counter CPE (judul halaman, cara alamat dibuka, cache), dan sebagian artefak Windows di luar browser (dialog pemilihan berkas) bisa menunjukkan berkas mana yang dipilih, sesuatu yang tidak pernah dimiliki CPE.

```
pertanyaan Legal: "berkas keluar lewat webmail, cloud, OneDrive, atau Teams?"
        |
        v
DI HOST (image E01-W1)                              DI LUAR HOST (izin Legal)
 browser   : profil, History (visits, transition)    proxy kantor (ekspor Januari)
             Downloads, cache (metadata)              audit log Microsoft Purview
 Windows   : dialog file (OpenSavePidlMRU)             (OneDrive, berbagi, Teams)
 OneDrive  : akun, database settings, log .odl        sign-in Entra (Splunk o365)
 Teams     : IndexedDB/LevelDB, cache                 penyedia webmail pribadi
        |                                              (hanya lewat proses hukum)
        v                                                     |
  yang dilakukan KLIEN di laptop  +  yang terjadi di LAYANAN  -+
        |
        v
adendum laporan: temuan per jalur, keyakinan, dan batas yang ditulis eksplisit
```

Situasi yang dipakai sepanjang Day ini melanjutkan kasus `INC-2027-010` di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan. Ringkasnya: Arif Wicaksono (`arif.wicaksono`), account manager Divisi Enterprise Sales Jakarta, mengundurkan diri dengan hari kerja terakhir Jumat 2027-01-08. Laptopnya `JKT-WS-0516` (`10.10.51.16`, Windows 11 23H2 build 22631, Defender for Endpoint, Sysmon, GPO audit `JAB-WS-Audit`) di-image utuh oleh Yoga Pratama sebagai `INC-2027-010-E01`, dengan salinan kerja `E01-W1`. Analisis Januari menemukan 19 berkas (11 harga kontrak portofolio Arif, 7 harga kontrak portofolio lain, dan `Daftar-PIC-Korporat-2026.xlsx`) disalin dari share `\\JKT-FS01\Enterprise-Sales\` ke `C:\Users\arif.wicaksono\Documents\Kontrak-Ref\` Rabu 2027-01-06 pukul 15:12 WIB, dua di antaranya tercatat berada di flashdisk pribadi Kamis malam, dan tiga sesi webmail pribadi Rabu 15:20 sampai 15:41 WIB dari kantor yang hanya terlihat sebagai volume di proxy (total kirim 182.336 byte) dan sebagai tiga kunjungan di riwayat Edge. Laporan final `INC-2027-010-LAP-01` versi 1.0 diserahkan Kamis 2027-01-21 dengan template `JAB-DFIR-TPL-01`. Temuan jalur online di laporan itu bertumpu pada proxy dan daftar kunjungan saja; artefak browser dan klien cloud belum dibedah, karena lingkup Januari tidak meminta lebih.

Senin 2027-02-22, PT JAB menerima tanggapan tertulis dari kuasa hukum Arif. Legal (Ratna Sari) mengeluarkan memo lingkup tambahan pukul 15:00. Selasa 2027-02-23 pukul 09:00, Dimas Prasetyo (SOC lead, incident commander) menulis kepadamu di kanal `#inc-2027-010`:

> "Pagi. Bu Ratna minta adendum laporan 010. Kuasa hukum Arif bilang laporan kita cuma bahas flashdisk dan 'tidak ada bukti apa pun bahwa klien kami mengirim data lewat internet'. Legal mau tahu persis apa yang bisa dan tidak bisa kita katakan soal jalur selain flashdisk: webmail pribadi yang tiga sesi itu, cloud pribadi, OneDrive kantor (ada berkas yang di-share keluar atau tersinkron ke perangkat lain?), dan Teams (ada berkas dikirim ke orang luar?). Memo lingkup baru sudah keluar kemarin sore: semua artefak browser, OneDrive, dan Teams di E01-W1, metadata saja untuk yang pribadi; plus audit log M365 untuk akun Arif 1 Desember sampai 8 Januari, diekspor Pak Agung. Isi email pribadi tetap tidak boleh dibuka. Draf adendum saya perlu Jumat 26 Februari jam 10:00. Tolong jangan sampai adendumnya terbaca seperti kita mengubah laporan final."

Pesan itu memuat tujuh pertanyaan:

1. Profil browser apa yang ada dan dipakai akun Arif, dan apakah riwayatnya dibuat di laptop ini atau tersinkron dari perangkat lain?
2. Apakah tiga sesi webmail pribadi di proxy terlihat di browser, dan apakah alamatnya dibuka sendiri (diketik) atau hasil pengalihan dan tautan?
3. Apakah ada jejak berkas dilampirkan, diunggah, atau diunduh lewat browser pada 4 sampai 8 Januari?
4. Apakah ada jejak penyimpanan cloud pribadi, lewat klien sync maupun lewat browser?
5. Apakah berkas harga atau daftar PIC masuk OneDrive korporat, dibagikan keluar, atau tersinkron ke perangkat lain?
6. Apakah ada berkas yang dikirim lewat Teams, terutama ke pihak luar?
7. Apa yang tidak bisa dijawab laptop dan butuh audit log Microsoft 365, dan bagaimana semuanya ditulis sebagai adendum tanpa mengubah laporan final?

Pertanyaan 1 dijawab konsepnya di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.1 dan 1.4, pertanyaan 5 di bagian 1.4 dan 1.6, pertanyaan 6 di bagian 1.5, dan pertanyaan 7 di bagian 1.6 dan 1.7. Bagian 2 berisi pengerjaannya atas `E01-W1` dan sumber di luar host, sampai teks adendum.

**Kapan relevan:** kasus kebocoran data, orang dalam, atau sengketa yang bertanya "lewat mana data keluar"; titik masuk malware dari unduhan browser; pertanyaan apakah berkas tersinkron ke cloud atau dibagikan; laporan yang harus membedakan bukti host dari bukti layanan cloud.
**Kapan bukan jawaban:** isi email pribadi atau isi akun cloud pribadi (hanya penyedia, lewat proses hukum yang diputuskan Legal); pertanyaan yang sepenuhnya ada di tenant, seperti siapa saja yang membuka berkas di SharePoint (audit log, bukan forensik endpoint); analisis keamanan ekstensi browser atau pencurian cookie sesi (topik lain); dan penilaian niat atau kesalahan (wewenang HR dan Legal).

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (LNK, Jump List, ShellBags, RecentDocs, OpenSavePidlMRU dan LastVisitedPidlMRU, `$J`, `$MFT`, Prefetch, proxy dan dekripsi TLS, tangga bukti, skala keyakinan, template `JAB-DFIR-TPL-01`, riwayat versi laporan) tidak diulang. Tabel ini hanya memuat istilah baru Day ini; kolom padanan memakai analogi NOC dan SOC yang sama di semua Day.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Profil browser | Folder data satu identitas browser (riwayat, cache, cookie, akun yang masuk); satu pengguna Windows bisa punya beberapa | Beberapa akun PPPoE di satu CPE: trafik harus dipisah per akun, bukan per perangkat |
| `History` (Chromium) dan `places.sqlite` (Firefox) | Database SQLite riwayat navigasi dan unduhan | Accounting sesi di BRAS: tujuan dan waktu, bukan isi trafik |
| Transisi kunjungan (`transition`, `visit_type`) | Kode cara sebuah halaman dibuka: diketik, tautan, pengalihan, form, reload | Cause code di log sesi: dial oleh pelanggan vs pengalihan otomatis captive portal |
| Rantai pengalihan (redirect chain) | Urutan kunjungan dari alamat awal sampai alamat akhir setelah redirect | Rantai pengalihan HTTP di captive portal: alamat yang diminta pelanggan berbeda dengan alamat yang akhirnya dilayani |
| Kunjungan tersinkron | Baris riwayat yang dibuat di perangkat lain lalu disalin oleh fitur sync browser | Log yang ditarik NMS dari perangkat lain lalu tampil di konsol yang sama |
| Cache HTTP | Salinan respons yang disimpan browser untuk dipakai ulang; menyimpan apa yang diterima, hampir tidak pernah yang dikirim | Cache DNS di resolver: membuktikan jawaban pernah diterima, bukan apa yang dikirim pelanggan |
| Klien sync (OneDrive) | Aplikasi yang menyamakan folder lokal dengan penyimpanan cloud dan mencatat operasinya | Agent backup konfigurasi yang mengirim berkas ke server pusat |
| Log ODL (`.odl`, `.odlgz`, `.odlsent`, `.aold`) | Log biner klien OneDrive yang sebagian isinya diobfuskasi | Log debug agent dalam format vendor yang butuh dekoder dan kunci |
| `general.keystore` | Berkas kunci yang dipakai klien OneDrive baru untuk mengenkripsi string di log | Kunci dekripsi capture yang harus ikut diambil, kalau tidak capture tidak terbaca |
| Known Folder Move (KFM) | Fitur OneDrive yang memindahkan Desktop, Documents, dan Pictures ke dalam folder OneDrive | Redirect folder konfigurasi ke server pusat: berkas yang terlihat lokal sebenarnya ikut terkirim |
| WebView2 | Komponen Microsoft yang menanam mesin Edge (Chromium) ke aplikasi Windows; dipakai Teams baru | Modul bersama yang dipakai beberapa aplikasi NMS: format datanya mengikuti modul, bukan aplikasinya |
| IndexedDB (di atas LevelDB) | Database key-value di browser tempat aplikasi web menyimpan data terstruktur seperti percakapan | Cache lokal di klien NMS: sebagian data yang pernah ditampilkan, bukan arsip server |
| Audit log Microsoft Purview | Log layanan Microsoft 365 untuk operasi pengguna dan admin (berkas, berbagi, pesan) | Log di NMS pusat atau server tujuan, bukan di CPE |

### 1.1 Profil browser dan sinkronisasi: riwayat milik siapa dan dari mana

Pertanyaan pertama Dimas terdengar administratif, tetapi menentukan apakah semua jawaban berikutnya sah. Bila kamu membaca profil yang salah, semua jawaban "tidak ditemukan" kehilangan nilai. Bila kamu membaca kunjungan yang ternyata dibuat di ponsel lalu tersinkron, kamu menempatkan aktivitas di laptop yang tidak pernah melakukannya.

Dua keluarga browser dipakai di Windows, dengan penyimpanan yang berbeda. Tabel ini dipakai untuk memilih kueri; perhatikan kolom format waktu, karena itulah sumber kesalahan paling mahal.

| Keluarga | Contoh | Database riwayat | Format waktu |
|---|---|---|---|
| Berbasis Chromium | Chrome, Edge, Brave, Opera | `History` (SQLite) per profil | Mikrodetik sejak 1 Januari 1601 UTC |
| Gecko | Firefox | `places.sqlite` per profil | Mikrodetik sejak 1 Januari 1970 UTC |

Salah konversi menggeser garis waktu ratusan tahun (mudah terlihat) atau beberapa jam bila zona waktu ikut salah (sulit terlihat dan jauh lebih berbahaya).

Browser berbasis Chromium menyimpan beberapa profil di satu direktori data pengguna (`%LocalAppData%\Microsoft\Edge\User Data\` untuk Edge, `%LocalAppData%\Google\Chrome\User Data\` untuk Chrome). Folder profil bernama `Default`, `Profile 1`, `Profile 2`, dan seterusnya, dan nama yang dilihat pengguna ("Kerja", "Pribadi") tidak sama dengan nama foldernya. Peta folder ke nama tampilan, akun yang masuk, dan waktu terakhir aktif ada di berkas JSON `Local State` di direktori data pengguna. Profil yang aktif belum tentu `Default`. Firefox menyimpan profil di folder bernama acak di bawah `%AppData%\Mozilla\Firefox\Profiles\`, dan pemetaannya ada di `profiles.ini` di direktori induknya [S5].

Sinkronisasi profil membawa riwayat dari perangkat lain ke database yang sama. Di Chromium, tabel `visits` punya kolom `originator_cache_guid`: untuk kunjungan yang disinkron dari mesin lain, kolom ini berisi pengenal unik mesin tempat kunjungan dibuat, sedangkan kunjungan lokal ditulis dengan string kosong [S10]. Kolom `is_known_to_sync` menandai kunjungan yang diketahui fitur sync, baik kunjungan jarak jauh maupun kunjungan lokal yang sudah dikirim ke sync [S10]. Jadi pertanyaan "apakah kunjungan ini dibuat di laptop ini" punya jawaban di database itu sendiri, asal kolomnya dibaca. Dari laptop kamu tidak bisa tahu perangkat mana yang dimaksud GUID itu; yang bisa kamu katakan adalah kunjungan itu bukan dari laptop ini.

Tiga batas berlaku untuk semua profil dan perlu ditulis di laporan:

- **Mode privat.** Sesi InPrivate atau Incognito tidak ditulis ke database riwayat. Ketiadaan riwayat bukan bukti tidak ada aktivitas; pembandingnya adalah proxy, DNS, dan memori bila ada.
- **Pembersihan.** Riwayat bisa dihapus pengguna, sebagian atau seluruhnya, dan penghapusan biasanya hanya meninggalkan jejak tidak langsung (halaman bebas SQLite, berkas WAL, cache yang tersisa, proxy).
- **Profil pribadi di laptop kantor.** Akun pribadi yang masuk ke profil kedua adalah data pribadi karyawan. Memo Legal menentukan apa yang boleh dibaca; prinsip kebutuhan dari Day 17 bagian 1.2 tetap berlaku: hitung dan catat keberadaan di dalam jendela kasus, jangan membaca isi di luar kebutuhan pertanyaan.

**Kapan gagal:** analyst langsung membuka `Default\History`, tidak melihat apa pun yang mencurigakan, dan menulis "tidak ada aktivitas browser", padahal pengguna bekerja di `Profile 1`. Atau kunjungan tersinkron dari ponsel dibaca sebagai aktivitas laptop pada jam yang sama.

### 1.2 Riwayat dan transisi kunjungan: membedakan yang dibuka sendiri

Pertanyaan kedua Dimas punya inti yang pasti ditanyakan kuasa hukum: apakah webmail itu dibuka dengan sengaja, atau muncul karena tautan, pengalihan, atau tab yang dipulihkan. Daftar URL saja tidak menjawabnya. Kolom transisi yang menjawab.

Tiga tabel Chromium yang dipakai:

- `urls`: satu baris per URL, dengan `visit_count`, `typed_count`, `last_visit_time`, dan judul.
- `visits`: satu baris per kunjungan, dengan `visit_time`, `from_visit` (kunjungan perujuk; 0 bila tidak ada perujuk), `opener_visit` (kunjungan yang membuka tab ini; 0 bila tidak ada), `transition`, `visit_duration`, dan kolom sync di bagian 1.1 [S10].
- `downloads` dan `downloads_url_chains` (bagian 1.3).

Nilai `transition` adalah bilangan 32 bit yang terdiri dari tipe inti di 8 bit terbawah dan qualifier di bit atas [S9]. Tipe inti diambil dengan `transition & 0xFF`. Tabel ini memuat tipe inti dan qualifier yang paling sering dipakai dalam kasus; cari baris `TYPED` dan `GENERATED`, karena dua itulah yang paling sering ditanyakan.

| Nilai | Nama | Arti untuk kasus |
|---|---|---|
| 0 | `LINK` | Mengikuti tautan di halaman |
| 1 | `TYPED` | Alamat dimasukkan di address bar; juga beberapa navigasi eksplisit lain [S9] |
| 2 | `AUTO_BOOKMARK` | Dibuka dari bookmark |
| 3, 4 | `AUTO_SUBFRAME`, `MANUAL_SUBFRAME` | Konten di dalam frame |
| 5 | `GENERATED` | Pengguna memilih saran address bar yang bukan URL (misalnya kata kunci pencarian), jadi tidak mengetik atau melihat URL tujuannya [S9] |
| 6 | `AUTO_TOPLEVEL` | Dibuka otomatis di tingkat atas, misalnya halaman awal |
| 7 | `FORM_SUBMIT` | Pengguna mengisi dan mengirim form; pengiriman oleh skrip bisa tidak mendapat tipe ini [S9] |
| 8 | `RELOAD` | Reload, Enter ulang di address bar, pemulihan sesi, atau membuka kembali tab yang ditutup [S9] |
| 9, 10 | `KEYWORD`, `KEYWORD_GENERATED` | Kata kunci mesin pencari kustom |
| `0x01000000` | `FORWARD_BACK` | Tombol maju atau mundur |
| `0x02000000` | `FROM_ADDRESS_BAR` | Navigasi berasal dari address bar |
| `0x10000000` | `CHAIN_START` | Awal rantai pengalihan |
| `0x20000000` | `CHAIN_END` | Akhir rantai pengalihan |
| `0x40000000` | `CLIENT_REDIRECT` | Pengalihan oleh halaman (skrip atau meta refresh) |
| `0x80000000` | `SERVER_REDIRECT` | Pengalihan oleh server (HTTP 3xx) |

Contoh pembacaan: nilai `0x12000001` adalah `TYPED` (1) dengan `FROM_ADDRESS_BAR` dan `CHAIN_START`. Nilai `0xA0000001` adalah `TYPED` dengan `SERVER_REDIRECT` dan `CHAIN_END`: halaman akhir setelah server mengalihkan alamat yang diketik. Tipe inti tetap `TYPED` di sepanjang rantai, jadi niat awal terbawa sampai halaman akhir. Karena bit tertinggi dipakai `SERVER_REDIRECT`, alat atau kueri yang membaca kolom sebagai bilangan bertanda bisa menampilkan nilai negatif; tampilkan dalam heksadesimal dan ambil `& 0xFF` untuk tipe inti.

Firefox memakai skema sendiri: `moz_places` (URL) dan `moz_historyvisits` (kunjungan, dengan `visit_date`, `from_visit`, dan `visit_type`). Nilai `visit_type` berbeda dari Chromium dan dimulai dari 1: `TRANSITION_LINK` 1, `TRANSITION_TYPED` 2 (diketik di address bar, dipilih dari autocomplete, atau diklik dari tampilan riwayat), `TRANSITION_BOOKMARK` 3, `TRANSITION_EMBED` 4, `TRANSITION_REDIRECT_PERMANENT` 5, `TRANSITION_REDIRECT_TEMPORARY` 6, `TRANSITION_DOWNLOAD` 7, `TRANSITION_FRAMED_LINK` 8, dan `TRANSITION_RELOAD` 9 [S15]. Angka 1 berarti tautan di Firefox dan diketik di Chromium; menyalin tabel tafsiran dari satu browser ke browser lain adalah kesalahan yang sama kelasnya dengan menyalin konversi epoch.

Dua batas transisi yang harus ditulis:

- **"Diketik" bukan "diketik huruf demi huruf".** `TYPED` di Chromium juga mencakup memilih URL dari saran address bar, dan `TRANSITION_TYPED` di Firefox mencakup autocomplete [S9][S15]. Kalimat yang aman: "alamat dibuka dari address bar oleh pengguna profil itu", bukan "pengguna mengetik alamat lengkap".
- **Transisi membuktikan cara navigasi, bukan identitas.** Seperti semua artefak host, ia menunjuk profil dan sesi, bukan orang di depan keyboard.

**Kapan gagal:** kolom `transition` ditafsirkan sebagai angka utuh (805306368 dibaca sebagai "tipe aneh"), atau tipe inti Firefox dibaca dengan tabel Chromium. Selalu pisahkan tipe inti dan qualifier, dan tulis di laporan cara kamu menafsirkannya.

### 1.3 Unduhan, unggahan, dan yang tidak dicatat browser

Pertanyaan ketiga Dimas adalah tempat kuasa hukum dan Legal paling mungkin salah paham, dari dua arah: "tidak ada di riwayat berarti tidak ada lampiran" dan "ada sesi webmail berarti berkas terkirim". Keduanya melompati apa yang sebenarnya dicatat browser.

**Unduhan tercatat dengan baik.** Tabel `downloads` di Chromium menyimpan, antara lain, `target_path` dan `current_path`, `start_time` dan `end_time`, `received_bytes` dan `total_bytes`, `state`, `danger_type`, `interrupt_reason`, `opened`, `referrer`, `site_url`, `tab_url`, `tab_referrer_url`, `mime_type`, dan `hash` [S11]. Tabel `downloads_url_chains` menyimpan rantai URL per unduhan dengan `chain_index`: indeks 0 adalah URL awal dan indeks tertinggi adalah URL setelah semua pengalihan [S11]. Untuk kasus, yang relevan biasanya URL awal dan `tab_url`, karena keduanya menunjukkan halaman tempat pengguna berada, bukan server CDN yang akhirnya melayani berkas. Nilai `state` 1 berarti selesai dan 4 berarti terputus menurut komentar skema di source [S11]; nilai lain cek di salinanmu. Di Firefox, unduhan versi lama ada di tabel `moz_downloads`, sedangkan versi yang lebih baru menyimpannya sebagai anotasi (`moz_annos` dengan atribut `downloads/destinationFileURI`) yang menunjuk ke baris `moz_places` [S16]. Unduhan selalu dicocokkan dengan `$MFT` dan `$J` (Day 08) untuk membuktikan berkasnya ada atau pernah ada di disk.

**Unggahan hampir tidak pernah tercatat.** Webmail modern mengunggah lampiran lewat permintaan latar belakang (XHR atau fetch) dari halaman yang sudah terbuka. Permintaan itu bukan navigasi, jadi tidak menjadi baris `visits`; isi yang dikirim juga bukan respons, jadi tidak masuk cache. Pengiriman form klasik bisa tercatat sebagai `FORM_SUBMIT`, tetapi pengiriman lewat skrip bisa tidak mendapat tipe itu [S9], dan URL hasil form tidak memuat nama berkas. Kesimpulannya: ketiadaan jejak unggahan di riwayat dan cache browser hampir tidak bernilai sebagai bukti tidak ada unggahan.

**Jejak tidak langsung di luar browser.** Saat pengguna memilih berkas lewat tombol "lampirkan", browser di Windows membuka dialog pemilihan berkas milik Windows. Dialog itu adalah sumber yang sama dengan OpenSavePidlMRU dan LastVisitedPidlMRU (Day 10 bagian 1.5): nama berkas per ekstensi dan folder terakhir per aplikasi. Bila LastVisitedPidlMRU memuat entri `msedge.exe` dengan folder `Documents\Kontrak-Ref`, itu jejak bahwa sebuah berkas dipilih dari folder itu lewat dialog di Edge. Batasnya tegas: hanya pemilihan lewat dialog yang tercatat (seret dan lepas dari Explorer ke halaman tidak melewati dialog), MRU hanya menyimpan nilai terbaru per kunci, dan pemilihan bukan pengiriman. Perilaku dialog browser versi yang sama perlu kamu amati sendiri di lab sebelum dipakai di laporan (bagian 3).

**Cache HTTP: bukti penerimaan, bukan pengiriman.** Cache di `Cache\Cache_Data` (berkas `index`, `data_0` sampai `data_3`, dan `f_XXXXXX`) menyimpan respons yang diterima beserta URL dan header-nya. Cache bisa menunjukkan halaman webmail mana yang dimuat dan kapan, bahkan setelah riwayat dihapus, tetapi tidak menyimpan isi yang dikirim. Membuka isi cache webmail pribadi berarti membaca email pribadi; di kasus ini memo Legal hanya mengizinkan metadata (URL, waktu, ukuran).

Tabel berikut adalah pegangan untuk kalimat laporan; baca kolom "Tidak membuktikan", karena kalimat yang salah selalu melompati kolom itu.

| Artefak | Membuktikan | Tidak membuktikan |
|---|---|---|
| `visits` dengan `TYPED` | Alamat dibuka dari address bar di profil itu, pada waktu itu | Apa yang dilakukan di halaman; siapa di depan keyboard |
| `downloads` | Berkas diterima ke path tertentu, dari halaman tertentu, selesai atau tidak | Berkas dibuka; berkas masih ada |
| OpenSavePidlMRU / LastVisitedPidlMRU (aplikasi browser) | Berkas atau folder dipilih lewat dialog Windows di aplikasi itu | Berkas terkirim; berkas yang diseret ke halaman |
| Cache HTTP | Respons tertentu diterima pada waktu tertentu | Data yang dikirim; isi lampiran keluar |
| Volume kirim di proxy | Laptop mengirim sejumlah byte ke domain itu | Isi; berkas mana; penerima |

**Kapan gagal:** laporan menulis "tidak ada lampiran yang dikirim" karena riwayat tidak memuat URL unggahan, atau sebaliknya menulis "berkas dikirim lewat webmail" karena volume proxy cukup besar. Yang bisa ditulis adalah gabungan yang terlihat dan batasnya.

### 1.4 Klien OneDrive: akun, database, dan log

Pertanyaan keempat dan kelima Dimas menyentuh OneDrive dari dua sisi: OneDrive pribadi (akun Microsoft pribadi) sebagai jalur keluar, dan OneDrive korporat (tenant PT JAB) sebagai tempat berkas bisa dibagikan atau tersinkron ke perangkat lain. Klien yang sama melayani keduanya, dengan folder terpisah per akun: `Personal` untuk akun pribadi dan `Business1` sampai `Business9` untuk akun kerja atau sekolah, baik di folder pengaturan `%LocalAppData%\Microsoft\OneDrive\settings\` maupun di folder log `%LocalAppData%\Microsoft\OneDrive\logs\` [S3]. Keberadaan folder `Personal` adalah langkah pertama menjawab "apakah OneDrive pribadi dikonfigurasi di klien"; ketiadaannya tidak menutup akses lewat browser.

Klien OneDrive meninggalkan tiga kelompok artefak yang menjawab pertanyaan berbeda:

- **Konfigurasi akun.** Di NTUSER, key `Software\Microsoft\OneDrive\Accounts\` memuat satu subkey per akun dengan email akun dan folder lokalnya; nama value persis cek di build-mu. Dari sini kamu tahu akun mana yang tersambung dan di mana folder sinkronnya. Periksa juga apakah Known Folder Move aktif: bila Documents dialihkan ke dalam folder OneDrive, berkas yang "disimpan di Documents" sebenarnya ikut tersinkron. Cara cepat memeriksanya adalah path itu sendiri: berkas di `C:\Users\<nama>\Documents\` berada di luar OneDrive, sedangkan KFM membuat Documents berada di bawah `C:\Users\<nama>\OneDrive - <organisasi>\Documents\`; konfirmasi dengan nilai `Personal` di `User Shell Folders` NTUSER.
- **Database sinkronisasi.** Versi lama menyimpan struktur folder di `<UserCid>.dat` dan `<UserCid>.dat.previous`, yang bisa direkonstruksi menjadi pohon folder termasuk berkas yang hanya ada di cloud [S3]. Versi baru beralih ke database SQLite di folder `settings\<akun>`, dan OneDriveExplorer membacanya dengan opsi `-s` yang diarahkan ke folder pengaturan, bukan ke satu berkas [S3]. Nama berkas database yang beredar di komunitas antara lain `SyncEngineDatabase.db`; cek nama dan isinya di instalasi lab dengan versi klien yang sama sebelum menulisnya di laporan. Database ini menjawab "apa saja yang ada di akun menurut klien", termasuk placeholder berkas cloud-only yang tidak pernah diunduh.
- **Log ODL.** Log biner klien dengan ekstensi `.odl`, `.odlgz`, `.odlsent`, dan `.aold` [S2][S3]. Isinya sebagian diobfuskasi. Klien lama menulis tabel pemetaan `ObfuscationStringMap.txt`; sejak sekitar April 2022 klien bisa tidak lagi membuat berkas itu dan sebagai gantinya mengenkripsi data dengan AES, dengan kunci di `general.keystore` yang harus berada di lokasi yang sama dengan log saat diurai [S2]. Ada juga log diagnostik teks yang memuat kemajuan unggah dan unduh beserta jumlah berkas [S4].

Tiga batas log OneDrive:

- **Rotasi.** Log berputar dan terkompresi dengan riwayat terbatas [S4]. Sebelum menjanjikan jawaban, lihat tanggal berkas log tertua; jendela itu yang ditulis di temuan.
- **Kunci ikut atau log tidak terbaca.** Koleksi yang hanya mengambil `*.odl` tanpa `general.keystore` (atau `ObfuscationStringMap.txt` di klien lama) menghasilkan log yang tidak bisa dibaca. Masukkan keduanya ke daftar koleksi.
- **Tafsiran fungsi log butuh uji.** Log ODL adalah log debug vendor; nama fungsi dan parameternya tidak didokumentasikan sebagai antarmuka. Satu baris yang terlihat seperti "unggah" perlu dibandingkan dengan aktivitas yang kamu kendalikan sendiri di lab sebelum dikutip.

**Kapan gagal:** analyst menyimpulkan "berkas tidak pernah di OneDrive" dari pencarian nama berkas di folder OneDrive lokal saja, padahal berkas cloud-only tidak punya isi lokal dan berkas yang dihapus dari cloud tidak lagi ada di folder. Atau log diambil tanpa kuncinya.

### 1.5 Teams baru berbasis WebView2: cache percakapan, bukan arsip

Pertanyaan keenam Dimas ("ada berkas dikirim ke orang luar lewat Teams?") membutuhkan dua pengetahuan: di mana Teams baru menyimpan datanya, dan bagaimana berkas di Teams sebenarnya dikirim.

Pada 2023 Microsoft memindahkan klien Teams desktop Windows dari Electron ke WebView2, yang memakai lingkungan Edge yang sudah terpasang untuk penyimpanan datanya; perubahan ini membuat banyak alat dan metode forensik lama tidak berlaku [S1]. Microsoft Learn menyebut folder cache Teams baru di `%userprofile%\appdata\local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams` [S13]. Di bawahnya ada profil WebView2 dengan struktur Chromium biasa: `Local Storage\leveldb`, `IndexedDB\https_teams.microsoft.com_0.indexeddb.leveldb`, dan `Cache\Cache_Data` [S1]. Nama subfolder profil WebView2 di antara keduanya tidak didokumentasikan resmi; temukan dengan pencarian di salinan bukti dan catat jalur nyatanya. Nama folder origin IndexedDB mengikuti domain yang dipakai klien versi itu, jadi cek juga di versi-mu. Folder klien Teams lama (`%AppData%\Microsoft\Teams`) bisa masih ada dari masa sebelum migrasi dan harus dibedakan dari data klien baru.

Makalah yang memetakan klien baru (build 25072.125072.1611.3570, divalidasi ulang terhadap rilis Februari 2026) menemukan 95 object store di 56 database IndexedDB, dengan tiga yang paling penting [S1]:

- `conversations`: satu entri per percakapan, dengan `id` yang polanya menunjukkan jenis (obrolan 1:1 berakhiran `@unq.gbl.spaces`, grup `@thread.v2`, channel `@thread.tacv2`, rapat `19:meeting_...`), daftar `members`, `chatTitle`, dan `lastMessage`.
- `replychains`: isi pesan, dengan `content`, `messageType`, `originalArrivalTime`, `creator`, `imDisplayName`, `isSentByCurrentUser`, dan `properties` yang bisa memuat `files` dan `links`.
- `profiles`: pemetaan ID pengguna ke `displayName` dan `email`, dipakai untuk atribusi.

Makalah itu juga mencatat bahwa alat gratis lama seperti forensicsim dan LevelDBDumper tidak efektif untuk klien baru karena format serialisasi berubah dan comparator `idb_cmp1` tidak didukung; peneliti memakai dfindexeddb dari Google untuk parsing tingkat rendah [S1][S17]. LevelDB menyimpan perubahan di berkas log dan bisa menyisakan record lama atau yang sudah dihapus sampai dipadatkan [S1], jadi pesan yang dihapus kadang masih terbaca, tetapi tidak dijamin.

Hal yang paling sering dilupakan: berkas yang dilampirkan di obrolan Teams tidak "dikirim" sebagai lampiran seperti email. Berkas diunggah ke OneDrive pengirim (folder yang biasanya bernama `Microsoft Teams Chat Files`) lalu dibagikan ke peserta obrolan. Artinya jejak pengiriman berkas lewat Teams ada di tiga tempat: pesan di `replychains` dengan `properties.files`, berkas di folder OneDrive pengirim (database klien OneDrive bila tersinkron), dan operasi unggah serta berbagi di audit log. Nama folder bisa berbeda menurut bahasa dan versi; cek di tenant-mu.

Batas Teams yang harus ditulis:

- **Cache, bukan arsip.** IndexedDB berisi percakapan yang pernah dimuat klien di laptop itu. Pesan yang dikirim dari ponsel atau web dan tidak pernah dibuka di laptop bisa tidak ada.
- **Versi menentukan format.** Hasil makalah berlaku untuk build yang diuji. Sebelum memakai temuan, buat percakapan uji di klien versi yang sama dan buktikan alatmu menemukannya; tanpa itu kamu tidak tahu apa yang tidak ditemukan alatmu.
- **Isi pesan adalah data pribadi pihak lain.** Peserta obrolan bukan subjek kasus. Memo Legal di kasus ini mengizinkan metadata dan nama berkas, bukan isi pesan.

**Kapan gagal:** jalur Teams disalin dari blog lama (folder Electron) dan analyst menulis "tidak ada data Teams", atau hasil alat yang belum diuji di versi itu dikutip sebagai lengkap.

### 1.6 Batas artefak host dan sumber di luar host

Pertanyaan kelima dan ketujuh Dimas menuntut garis yang jelas antara yang dijawab laptop dan yang dijawab layanan. Garis ini bukan kelemahan forensik endpoint; ia bagian dari kesimpulan.

Artefak di laptop hanya menceritakan apa yang klien lakukan di mesin itu. Pertanyaan berikut hanya dijawab audit log layanan Microsoft 365: siapa lagi yang mengakses berkas, apakah tautan berbagi dibuat (termasuk dari web), apakah berkas diunduh ke perangkat lain, dan pesan apa yang terkirim. Audit log Microsoft Purview mencatat operasi berkas OneDrive dan SharePoint, antara lain `FileUploaded` dan `FileDownloaded` (lewat situs), `FileSyncUploadedFull` dan `FileSyncDownloadedFull` (lewat klien sync OneDrive.exe), `FileAccessed` (akses ulang oleh pengguna yang sama atas berkas yang sama tidak dicatat lagi selama lima menit), `FileModified`, dan `FileDeleted` [S8]. Operasi berbagi punya nama sendiri: `SharingSet` (berbagi ke pengguna di direktori organisasi, member atau guest), `SharingInvitationCreated` (berbagi ke pengguna di luar direktori), `AnonymousLinkCreated` dan `AnonymousLinkUsed` (tautan tanpa autentikasi), `CompanyLinkCreated` (tautan untuk seluruh organisasi), `SecureLinkCreated` dan `AddedToSecureLink` [S8]. Untuk Teams, `MessageSent` tercatat untuk pesan di chat atau channel, tetapi untuk chat event ini hanya dibuat bila ada guest, pengguna federasi, atau pengguna anonim, dan statusnya masih public preview [S8]. Setiap record memuat akun, waktu, alamat IP klien, dan user agent, sehingga akses lewat klien sync di laptop bisa dibedakan dari akses lewat browser di perangkat lain.

Tabel ini memetakan pertanyaan Legal ke sumber yang bisa menjawabnya; baca kolom "Batas", karena di situlah kalimat adendum ditentukan.

| Pertanyaan | Di laptop | Di luar host | Batas |
|---|---|---|---|
| Webmail pribadi: sesi dan cara dibuka | Riwayat, transisi, cache (metadata) | Proxy kantor (ekspor yang tersimpan) | Isi hanya di penyedia; trafik dari luar kantor tidak lewat proxy |
| Webmail pribadi: lampiran | Dialog file (MRU) bila dipakai | Penyedia webmail | Hanya lewat proses hukum; keputusan Legal |
| Cloud pribadi | Folder `Personal` OneDrive, klien lain, profil pribadi, riwayat | Proxy | Akun pribadi di luar tenant; tidak ada audit PT JAB untuknya |
| OneDrive korporat: berkas ada | Database dan log klien, folder lokal | Audit `FileSync*`, `FileUploaded` | Log klien berputar; database hanya keadaan terakhir |
| OneDrive korporat: dibagikan keluar | Tidak ada | Audit operasi berbagi | Hanya dalam retensi audit |
| OneDrive korporat: perangkat lain | Tidak ada | Audit `FileSyncDownloadedFull` dan `FileDownloaded` (IP, user agent), sign-in Entra | Atribusi perangkat lewat IP dan user agent, bukan nama host |
| Teams: berkas ke pihak luar | IndexedDB (`properties.files`), OneDrive `Microsoft Teams Chat Files` | Audit unggah dan berbagi; `MessageSent` untuk chat dengan pihak luar | Cache tidak lengkap; isi pesan tidak ada di audit |

Retensi menentukan apakah sumber itu masih ada. Audit (Standard), yang tersedia di lisensi Microsoft 365 E3 milik PT JAB, menyimpan record 180 hari; Audit (Premium) menyimpan record Entra ID, Exchange, OneDrive, dan SharePoint satu tahun secara default dan bisa diperpanjang dengan kebijakan retensi [S14]. Retensi bawaan Audit (Standard) berubah dari 90 ke 180 hari untuk record yang dibuat sejak 17 Oktober 2023 [S14]. Untuk kasus Januari 2027 yang dibuka lagi akhir Februari, record 1 Desember 2026 sampai 8 Januari 2027 masih di dalam jendela 180 hari. Sumber lain tidak seberuntung itu: advanced hunting Defender dan index `proxy` di Splunk hanya 30 hari, jadi data Januari tidak bisa dikueri ulang; yang tersisa adalah ekspor yang disimpan saat analisis Januari.

Pembagian kerja yang dipakai PT JAB: analyst forensik endpoint menyusun pertanyaan dan kriteria pencarian, admin Microsoft 365 yang berwenang menjalankan pencarian audit dan mengekspor hasilnya ke folder kasus beserta hash, dan analyst membaca ekspor itu sebagai sumber pendukung. Day ini tidak membedah audit log secara mendalam; yang dibahas adalah kapan ia dibutuhkan, apa yang bisa dan tidak bisa ia jawab, dan bagaimana hasilnya dikaitkan dengan artefak host.

**Kapan gagal:** adendum menulis "OneDrive tidak dibagikan ke luar" berdasarkan database klien di laptop, padahal berbagi dilakukan di web dan hanya tercatat di audit; atau menulis hasil audit tanpa menyebut jendela retensi dan siapa yang mengekspornya.

### 1.7 Adendum: menambah temuan tanpa mengubah laporan final

Pertanyaan ketujuh Dimas juga menyangkut bentuk dokumen. Laporan final yang sudah diserahkan adalah dokumen yang bisa dibandingkan pihak lain kata demi kata. Aturan di Day 19 bagian 1.10 berlaku: data baru setelah final terbit sebagai versi 1.1 dengan riwayat perubahan, dan versi 1.0 tidak ditimpa.

Praktik adendum yang dipakai PT JAB:

- **Satu dokumen, versi baru, bagian baru.** `INC-2027-010-LAP-01` versi 1.1 memuat isi versi 1.0 tanpa perubahan ditambah "Adendum A" di akhir bagian 4, entri baru di bagian 9 (yang belum diketahui), lampiran C dan D yang diperbarui, dan riwayat versi yang menjelaskan alasannya (permintaan Legal, memo lingkup 2027-02-22).
- **Pertanyaan baru dinomori sendiri.** Pertanyaan adendum ditulis sebagai A.1, A.2, dan seterusnya, supaya tidak tercampur dengan pertanyaan 1 sampai 7 laporan awal.
- **Temuan lama disebut status keyakinannya.** Untuk setiap temuan laporan awal yang tersentuh adendum, tulis apakah keyakinannya berubah, dari tingkat apa ke tingkat apa, dan bukti apa yang menyebabkannya. Bila tidak berubah, tulis "tidak berubah" (aturan konsistensi penilaian di Day 19 bagian 1.10).
- **Skala dan frasa sama.** Adendum memakai skala keyakinan yang sama dengan laporan final (Day 19 bagian 1.4); "tidak ditemukan" selalu disertai cakupan.
- **Tidak menjawab argumen pihak lain.** Adendum tidak membantah atau menyetujui kalimat kuasa hukum. Ia menjawab pertanyaan Legal dengan fakta dan batasnya; Legal yang memakai fakta itu.

**Kapan gagal:** adendum ditulis sebagai email terpisah yang mengubah kalimat di laporan final ("abaikan butir 6, ganti dengan ..."), sehingga beredar dua versi yang saling bertentangan tanpa riwayat versi.

## 2. Contoh dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi yang disusun untuk kasus ini, bukan hasil eksekusi. Perintah PowerShell dan EZ Tools dijalankan di workstation analisis `JKT-DFIR01` atas salinan kerja `E01-W1` yang di-mount read-only sebagai `G:`; alat berbasis Python (`odl.py`, `dfindexeddb`) dijalankan di `jkt-dfir02` atas salinan artefak di disk lokalnya; hasil disimpan di `\\jkt-evid01\cases\INC-2027-010\analysis\E01-W1\adendum-A\` (di `jkt-dfir02` di-mount sebagai `/mnt/cases`). Narasi memakai WIB (UTC+7). Database Chromium dan Firefox, log OneDrive, IndexedDB Teams, dan audit log Microsoft 365 menyimpan waktu dalam UTC (UTC = WIB dikurangi 7 jam); setiap keluaran diberi label zonanya.

Alat analisis `INC-2027-010` dibekukan saat kasus dibuka (EZ Tools 2026.5.0). Adendum ini butuh alat yang belum ada di inventaris kasus: `sqlite3` (CLI resmi SQLite), Hindsight v2026.06, OneDriveExplorer, `odl.py`, dan `dfindexeddb`. Keputusannya dicatat di case notes: alat lama tetap dipakai untuk artefak yang sudah dianalisis, alat baru hanya untuk artefak baru, dan versi serta hash setiap alat baru ditambahkan ke Lampiran B laporan (bagian 6).

### 2.1 Lingkup, persiapan, dan salinan artefak

Langkah ini memastikan setiap jawaban ke Dimas berdiri di atas lingkup tertulis dan salinan yang bisa diverifikasi. Case notes pembuka adendum (WIB):

```
INC-2027-010 | Case notes forensik, Adendum A | <kamu> | TZ catatan: UTC+7 (WIB)
2027-02-23 09:00  Permintaan Dimas (#inc-2027-010) meneruskan Legal (Ratna Sari): 7 pertanyaan jalur
                  selain flashdisk. Draf Jumat 2027-02-26 10:00.
                  Lingkup: memo Legal 2027-02-22 15:00 (Lampiran A memo):
                  - E01-W1: artefak browser (semua profil), OneDrive, Teams; jendela 2026-12-01 s/d 2027-01-08;
                    untuk profil dan akun pribadi: metadata saja (URL/domain, waktu, nama berkas, ukuran).
                  - Isi email pribadi, isi halaman webmail, dan isi pesan Teams: TIDAK dibuka.
                  - Audit log Microsoft 365 akun arif.wicaksono 2026-12-01 s/d 2027-01-08, diekspor admin
                    M365 (Agung Prabowo), hash di titik ekspor.
                  - Sign-in Entra dari Splunk index o365, jendela sama.
2027-02-23 09:15  E01-W1: hash 9 segmen cocok manifest. Mount read-only sebagai G: di JKT-DFIR01.
2027-02-23 09:20  Catatan: proxy dan advanced hunting Defender (retensi 30 hari) tidak bisa dikueri ulang
                  untuk Januari. Sumber yang tersisa: ekspor proxy mentah yang disimpan 2027-01-12
                  (analysis\proxy\proxy-2027-01-04_08.csv, hash di case notes Januari).
```

**Tujuan:** menyalin folder profil browser, OneDrive, dan Teams dari mount read-only ke folder kerja, lengkap dengan berkas pendamping SQLite dan LevelDB, lalu meng-hash setiap berkas.

```powershell
$src = 'G:\Users\arif.wicaksono\AppData\Local'
$w   = 'C:\DFIR\work\INC-2027-010\E01-W1\adendum-A'
robocopy "$src\Microsoft\Edge\User Data" "$w\Edge" /E /COPY:DT /DCOPY:T /R:0 /W:0 /NP /LOG:"$w\robocopy-edge.log"
robocopy "$src\Microsoft\OneDrive" "$w\OneDrive" /E /COPY:DT /DCOPY:T /R:0 /W:0 /NP /LOG:"$w\robocopy-onedrive.log"
robocopy "$src\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams" "$w\Teams" /E /COPY:DT /DCOPY:T /R:0 /W:0 /NP /LOG:"$w\robocopy-teams.log"
Get-ChildItem $w -Recurse -File -Exclude 'robocopy-*.log' | Get-FileHash -Algorithm SHA256 |
  Export-Csv "$w\hash-adendum-A.csv" -NoTypeInformation
```

- `robocopy ... /E`: menyalin seluruh subfolder termasuk yang kosong, sehingga berkas `-wal`, `-journal`, `LOG`, `MANIFEST-*`, dan `CURRENT` ikut. Menyalin hanya `History` atau hanya `.ldb` adalah kesalahan paling umum (bagian 4).
- `/COPY:DT /DCOPY:T`: menyalin data dan timestamp berkas serta folder, tanpa atribut keamanan yang tidak dibutuhkan untuk analisis.
- `/R:0 /W:0`: tidak mengulang bila gagal; mount read-only dari image tidak punya berkas terkunci, jadi kegagalan berarti ada masalah lain yang harus dicatat.
- `/LOG`: daftar berkas yang disalin dan yang gagal, disimpan bersama hasil.
- `Get-FileHash` ke CSV: setiap berkas punya SHA-256, sehingga orang lain bisa memverifikasi bahwa analisis memakai salinan yang sama.

Keluaran ilustrasi (ringkasan log):

```
Edge      : Dirs 1.204  Files 3.214  Failed 0
OneDrive  : Dirs   212  Files   396  Failed 0
Teams     : Dirs   418  Files 1.087  Failed 0
hash-adendum-A.csv : 4.697 baris
```

**Cara membaca hasil:** `Failed 0` di ketiga salinan berarti tidak ada berkas yang terlewat. Jumlah baris CSV hash (4.697) sama dengan jumlah berkas yang disalin (3.214 + 396 + 1.087), jadi tidak ada berkas tanpa hash.

**Variasi:** di host yang masih hidup, browser dan klien cloud mengunci berkasnya; salin dari shadow copy atau lewat koleksi yang membaca raw (KAPE, Velociraptor), dan catat bahwa aplikasi masih berjalan saat koleksi.

**Kapan gagal:** salinan dibuat dari profil yang sedang dipakai di host hidup tanpa berkas WAL, atau database dibuka langsung dari mount dengan alat yang menulis (beberapa alat SQLite membuat berkas `-shm` atau menjalankan checkpoint saat membuka).

### 2.2 Peta profil browser: `Local State`, Chrome, dan Firefox

Langkah ini menjawab pertanyaan pertama Dimas dan menentukan database mana yang dibaca di langkah berikutnya.

**Tujuan:** memetakan folder profil Edge ke nama tampilan, akun yang masuk, dan waktu terakhir aktif.

```powershell
$ls = Get-Content "$w\Edge\Local State" -Raw | ConvertFrom-Json
$ls.profile.info_cache.PSObject.Properties | ForEach-Object {
  [pscustomobject]@{
    Folder        = $_.Name
    NamaTampilan  = $_.Value.name
    Akun          = $_.Value.user_name
    AktifTerakhir = [DateTimeOffset]::FromUnixTimeSeconds([int64]$_.Value.active_time).UtcDateTime
  }
}
```

- `ConvertFrom-Json`: `Local State` adalah JSON; objek `profile.info_cache` berisi satu properti per folder profil.
- `name`, `user_name`, `active_time`: nama tampilan, akun yang masuk ke profil, dan waktu terakhir aktif dalam detik Unix. Nama field bisa berubah antar versi; bila kosong, buka JSON-nya dan cari di bawah `profile`.
- `FromUnixTimeSeconds`: mengubah detik Unix ke UTC.

Keluaran ilustrasi (UTC):

```
Folder     NamaTampilan  Akun                         AktifTerakhir
Default    Kerja         arif.wicaksono@jab.example   2027-01-07 10:36:12
Profile 1  Pribadi       arifw@pribadi.example        2026-12-19 13:14:40
```

Pemeriksaan browser lain, atas mount read-only:

```powershell
Test-Path 'G:\Users\arif.wicaksono\AppData\Local\Google\Chrome\User Data'
Test-Path 'G:\Users\arif.wicaksono\AppData\Roaming\Mozilla\Firefox\profiles.ini'
Get-ChildItem 'G:\Windows\Prefetch' -Filter '*.pf' | Where-Object Name -match '^(CHROME|FIREFOX|BRAVE|OPERA)'
```

Keluaran ilustrasi: `False`, `False`, dan tidak ada berkas Prefetch yang cocok.

**Cara membaca hasil:**

- Profil kerja (`Default`, akun `arif.wicaksono@jab.example`) aktif terakhir Kamis 2027-01-07 17:36:12 WIB, sekitar dua setengah menit sebelum laptop terputus dari jaringan kantor pukul 17:38:47 (Day 17). Ini profil yang dipakai sehari-hari.
- Profil kedua bernama "Pribadi", masuk dengan akun Microsoft pribadi, aktif terakhir Sabtu 2026-12-19 20:14:40 WIB. Sesuai memo, profil ini hanya dihitung dan dicatat keberadaannya; isinya di luar jendela tidak dibaca.
- Chrome, Firefox, Brave, dan Opera tidak terpasang untuk profil Arif dan tidak pernah dijalankan dalam jendela Prefetch. Prefetch hanya menyimpan delapan waktu run terakhir per program dan bisa dinonaktifkan (Day 07 bagian 1.2), jadi kalimat yang aman adalah "tidak ditemukan", bukan "tidak pernah".

**Variasi:** untuk Chrome, `Local State` ada di `...\Google\Chrome\User Data\`; untuk Firefox, buka `profiles.ini` lalu folder profil yang ditunjuknya [S5].

**Kapan gagal:** `active_time` dibaca sebagai waktu lokal, atau nama tampilan "Kerja" dianggap nama folder dan analyst mencari folder `Kerja` yang tidak ada.

### 2.3 Riwayat webmail dan transisi di profil `Default`

Langkah ini menjawab pertanyaan kedua: tiga sesi di proxy, dilihat dari browser.

**Tujuan:** menampilkan semua kunjungan ke `webmail.example` di profil `Default` pada 4 sampai 8 Januari WIB, dengan transisi yang sudah dipisah dan asal kunjungan (lokal atau tersinkron).

```sql
-- sqlite3 -readonly "C:\DFIR\work\INC-2027-010\E01-W1\adendum-A\Edge\Default\History"
.headers on
.mode column
SELECT v.id,
       datetime(v.visit_time/1000000 - 11644473600, 'unixepoch')           AS waktu_utc,
       u.url,
       printf('0x%08X', v.transition & 0xFFFFFFFF)                         AS transisi_hex,
       v.transition & 0xFF                                                 AS inti,
       v.from_visit,
       CASE WHEN ifnull(v.originator_cache_guid,'') = '' THEN 'lokal' ELSE 'sinkron' END AS asal,
       v.visit_duration/1000000                                            AS durasi_s
FROM visits v JOIN urls u ON u.id = v.url
WHERE u.url LIKE 'https://webmail.example/%'
  AND v.visit_time >= (strftime('%s','2027-01-03 17:00:00') + 11644473600) * 1000000
  AND v.visit_time <  (strftime('%s','2027-01-08 17:00:00') + 11644473600) * 1000000
ORDER BY v.visit_time;
```

- `sqlite3 -readonly`: membuka salinan tanpa izin menulis. Bila berkas `History-wal` ada di folder yang sama, SQLite membacanya sebagai bagian database; itulah alasan berkas pendamping harus ikut disalin.
- `visit_time/1000000 - 11644473600`: mikrodetik sejak 1601 menjadi detik Unix; 11644473600 adalah selisih detik antara epoch 1601 dan 1970.
- `printf('0x%08X', v.transition & 0xFFFFFFFF)`: menampilkan transisi dalam heksadesimal, aman walaupun nilainya tersimpan sebagai bilangan bertanda; `& 0xFF` mengambil tipe inti [S9].
- `originator_cache_guid`: kosong berarti kunjungan lokal, berisi berarti tersinkron dari mesin lain [S10].
- `visit_duration`: lama kunjungan dalam mikrodetik; perilakunya saat tab tetap terbuka di latar perlu dicek di lab, jadi angka ini hanya pendukung.
- Batas waktu ditulis dalam UTC: 4 Januari 00:00 WIB adalah 3 Januari 17:00 UTC, dan akhir 8 Januari 24:00 WIB adalah 8 Januari 17:00 UTC.

Keluaran ilustrasi (UTC):

```
id     waktu_utc            url                                 transisi_hex  inti  from_visit  asal   durasi_s
48211  2027-01-06 08:20:14  https://webmail.example/            0x12000001    1     0           lokal  0
48212  2027-01-06 08:20:15  https://webmail.example/mail/inbox  0xA0000001    1     48211       lokal  272
48230  2027-01-06 08:33:02  https://webmail.example/            0x12000001    1     0           lokal  0
48231  2027-01-06 08:33:03  https://webmail.example/mail/inbox  0xA0000001    1     48230       lokal  316
48247  2027-01-06 08:40:51  https://webmail.example/            0x12000001    1     0           lokal  0
48248  2027-01-06 08:40:52  https://webmail.example/mail/inbox  0xA0000001    1     48247       lokal  10
```

Pembanding dari ekspor proxy mentah Januari, dikelompokkan per sesi:

```powershell
Import-Csv '\\jkt-evid01\cases\INC-2027-010\analysis\proxy\proxy-2027-01-04_08.csv' |
  Where-Object dest_host -eq 'webmail.example' | Group-Object session_id | ForEach-Object {
    [pscustomobject]@{ Sesi = $_.Name
      Mulai   = ($_.Group | Sort-Object waktu_wib | Select-Object -First 1).waktu_wib
      Selesai = ($_.Group | Sort-Object waktu_wib | Select-Object -Last 1).waktu_wib
      Kirim   = ($_.Group | Measure-Object bytes_out -Sum).Sum
      Terima  = ($_.Group | Measure-Object bytes_in -Sum).Sum } }
```

- Ekspor berisi satu baris per koneksi tunnel `CONNECT webmail.example:443`, karena TLS ke webmail terkategori tidak didekripsi; tidak ada URL, metode, atau ukuran per permintaan di dalamnya.
- `session_id`: pengelompokan sesi oleh proxy, sama dengan yang dipakai kueri Splunk Januari (Day 17 bagian 2.7).

Keluaran ilustrasi (WIB):

```
Sesi  Mulai     Selesai   Kirim    Terima
1     15:20:14  15:24:47   21504    812433
2     15:33:02  15:38:19  147456   1402117
3     15:40:51  15:41:02   13376    204441
                          ------   -------
                          182336   2418991
```

Pola sebelum jendela kasus, dihitung dengan kueri yang sama untuk 1 sampai 31 Desember 2026 dan hanya kolom tanggal serta transisi inti yang dicatat: kunjungan ke `webmail.example` ada di 14 dari 19 hari kerja Desember, tersebar antara 08:00 dan 17:30 WIB, hampir semuanya dengan tipe inti `TYPED`.

**Cara membaca hasil:**

- Tiga rantai kunjungan dimulai pukul 15:20:14, 15:33:02, dan 15:40:51 WIB, sama persis dengan awal tiga sesi proxy. Setiap rantai dimulai dengan `0x12000001` (`TYPED`, `FROM_ADDRESS_BAR`, `CHAIN_START`): alamat dibuka dari address bar profil `Default`, bukan dari tautan atau tab yang dipulihkan. Satu detik kemudian server mengalihkan ke `/mail/inbox` (`0xA0000001`, `SERVER_REDIRECT`, `CHAIN_END`), dan `from_visit` menunjuk ke kunjungan awal.
- Semua kunjungan lokal: dibuat di laptop ini, bukan tersinkron dari perangkat lain.
- `durasi_s` sejalan dengan panjang sesi proxy (272 detik untuk sesi 15:20:14 sampai 15:24:47, 316 detik untuk 15:33:02 sampai 15:38:19, 10 detik untuk 15:40:51 sampai 15:41:02), sehingga dua sumber independen menggambarkan tiga sesi yang sama.
- Webmail pribadi bukan aktivitas baru: polanya sudah ada sepanjang Desember. Tiga sesi Rabu sore tidak menonjol dari sisi kebiasaan; yang membuatnya relevan hanya waktunya, 8 sampai 28 menit setelah 19 berkas disalin ke `Kontrak-Ref`.
- Riwayat tidak memuat satu pun URL yang menunjukkan pengiriman pesan atau unggahan lampiran. Itu sesuai harapan (bagian 1.3) dan tidak bernilai sebagai bukti tidak ada lampiran.

**Variasi:** untuk Firefox, ganti tabel dan konversi waktu (`moz_historyvisits.visit_date/1000000`, tanpa 11644473600) dan baca `visit_type` dengan tabel Firefox (bagian 1.2). Untuk melihat rantai lengkap, ikuti `from_visit` mundur sampai 0.

**Kapan gagal:** batas waktu ditulis dalam WIB tanpa konversi, sehingga tujuh jam terakhir 8 Januari hilang dan tujuh jam sebelum 4 Januari ikut; atau `transition` ditampilkan sebagai bilangan desimal bertanda dan dibaca sebagai tipe yang tidak ada.

### 2.4 Unduhan, cache, dan dialog pemilihan berkas

Langkah ini menjawab pertanyaan ketiga dari tiga arah: apa yang diterima browser, apa yang dimuat dari webmail, dan apakah ada berkas yang dipilih lewat dialog Windows.

**Tujuan pertama:** semua unduhan di profil `Default` (dan `Profile 1`) pada 4 sampai 8 Januari.

```sql
SELECT d.id,
       datetime(d.start_time/1000000 - 11644473600, 'unixepoch') AS mulai_utc,
       datetime(d.end_time/1000000 - 11644473600, 'unixepoch')   AS selesai_utc,
       d.target_path, d.received_bytes, d.total_bytes, d.state, d.danger_type,
       d.tab_url, c.url AS url_awal
FROM downloads d
LEFT JOIN downloads_url_chains c ON c.id = d.id AND c.chain_index = 0
WHERE d.start_time >= (strftime('%s','2027-01-03 17:00:00') + 11644473600) * 1000000
  AND d.start_time <  (strftime('%s','2027-01-08 17:00:00') + 11644473600) * 1000000
ORDER BY d.start_time;
```

- `c.chain_index = 0`: URL awal rantai; indeks tertinggi adalah URL setelah pengalihan [S11]. Tanpa syarat ini, satu unduhan muncul sebanyak panjang rantainya.
- `tab_url`: halaman tempat pengguna berada saat unduhan dimulai [S11].
- `received_bytes` dan `total_bytes`: sama berarti berkas diterima lengkap; `state` 1 berarti selesai [S11].

Keluaran ilustrasi (UTC), profil `Default`:

```
id   mulai_utc            selesai_utc          target_path                                                received_bytes  total_bytes  state  danger_type  tab_url                              url_awal
412  2027-01-05 02:12:40  2027-01-05 02:12:41  C:\Users\arif.wicaksono\Downloads\Formulir-Exit-Clearance.pdf  248113  248113  1  0  https://hr.jab.example/exit/formulir  https://hr.jab.example/exit/formulir/unduh
```

Profil `Profile 1`: nol baris dalam jendela.

**Cara membaca hasil:** satu unduhan dalam jendela, Selasa 2027-01-05 09:12:40 WIB, formulir exit clearance dari portal HR internal, selesai lengkap. `$MFT` dari analisis Januari mencatat berkas itu dibuat 09:12:41 WIB di `Downloads`. Rabu 6 Januari tidak ada unduhan sama sekali, termasuk dari webmail.

**Tujuan kedua:** metadata cache untuk `webmail.example` di jendela tiga sesi, tanpa membuka isi. Hindsight dipakai karena sekaligus menjadi pembanding kueri manual (bagian 2.5); cache ada di sheet atau tabel hasilnya. Ringkasan keluaran ilustrasi (UTC):

```
Sumber: Edge\Default\Cache\Cache_Data  | filter: host = webmail.example, 2027-01-06 08:20 s/d 08:42 UTC
Entri     : 1.146  (sesi 1: 388, sesi 2: 571, sesi 3: 187)
Jenis     : skrip, stylesheet, gambar antarmuka, respons JSON daftar pesan
Isi       : tidak dibuka (memo Legal 2027-02-22)
```

**Cara membaca hasil:** cache membuktikan halaman webmail dimuat di tiga sesi itu, sejalan dengan riwayat dan proxy. Cache menyimpan respons yang diterima, bukan permintaan yang dikirim, jadi tidak ada entri yang bisa menunjukkan lampiran keluar. Membuka respons JSON daftar pesan berarti membaca email pribadi, di luar memo.

**Tujuan ketiga:** apakah dialog pemilihan berkas Windows dipakai dalam jendela kasus, oleh aplikasi apa pun.

```powershell
$ez  = 'C:\DFIR\tools\EZTools-2026-10-15\net9'
$out = '\\jkt-evid01\cases\INC-2027-010\analysis\E01-W1\adendum-A'
& "$ez\RECmd\RECmd.exe" -f "G:\Users\arif.wicaksono\NTUSER.DAT" --bn "$ez\RECmd\BatchExamples\UserActivity.reb" --csv "$out\Registry" --csvf E01-W1_RECmd_UserActivity_arif.csv
```

- `-f` satu hive dan `--bn UserActivity.reb`: batch yang memuat `ComDlg32\OpenSavePidlMRU` dan `ComDlg32\LastVisitedPidlMRU`, cara yang sama dengan Day 10 bagian 2.5.
- Hive dibaca dari mount read-only; transaction log dipakai bila hive dirty (default RECmd).

Keluaran ilustrasi, kunci ComDlg32 (LastWriteTime UTC):

```
Key                                   Isi (MRU 0 lebih dulu)                                         LastWriteTime
ComDlg32\LastVisitedPidlMRU           msedge.exe -> C:\Users\arif.wicaksono\Downloads, OUTLOOK.EXE   2026-12-22 03:41:09
                                      -> C:\Users\arif.wicaksono\Documents\Proposal, ...
ComDlg32\OpenSavePidlMRU\*            ...\Downloads\Jadwal-Cuti-2027.pdf, ...                        2026-12-22 03:41:09
ComDlg32\OpenSavePidlMRU\xlsx         ...\Documents\Proposal\Proposal-Upgrade-Q1.xlsx, ...           2026-12-17 06:02:51
(tidak ada nilai yang menunjuk Documents\Kontrak-Ref atau E:\)
```

**Cara membaca hasil:**

- Dialog pemilihan berkas terakhir dipakai Selasa 2026-12-22 10:41:09 WIB, oleh Edge, di folder Downloads. Tidak ada perubahan ComDlg32 dalam jendela 4 sampai 8 Januari, dan tidak ada nilai yang menunjuk `Kontrak-Ref` atau flashdisk.
- Artinya tidak ditemukan jejak berkas dipilih lewat dialog Windows saat sesi webmail. Ini inferensi dari ketiadaan, keyakinan rendah: seret dan lepas dari Explorer ke halaman webmail tidak melewati dialog, dan perilaku dialog Edge versi itu belum diuji di lab PT JAB (bagian 3).

**Variasi:** di kasus lain, bila LastVisitedPidlMRU memuat `msedge.exe` dengan folder yang relevan, cocokkan LastWriteTime kuncinya dengan waktu sesi webmail dan dengan volume kirim proxy. Hasil terbaiknya tetap "berkas X dipilih di dialog Edge pada waktu Y", bukan "berkas X terkirim".

**Kapan gagal:** hasil negatif ComDlg32 ditulis "tidak ada lampiran", atau isi cache webmail dibuka untuk "memastikan" dan laporan kehilangan dasar lingkupnya.

### 2.5 Hindsight sebagai pembanding

Satu temuan penting tidak bertumpu pada satu alat. Hindsight mengurai profil browser berbasis Chromium (riwayat, unduhan, cache, preferensi, dan lainnya); versi v2026.06 menambah dukungan Firefox, deteksi otomatis browser dan variannya seperti Edge, serta perluasan parsing unduhan [S6][S12].

**Tujuan:** mengurai profil `Default` dengan Hindsight dan membandingkan baris webmail dan unduhan dengan kueri manual.

```powershell
& 'C:\DFIR\tools\hindsight-2026.06\hindsight.exe' -i "$w\Edge\Default" -o "$out\hindsight\E01-W1_Edge_Default" -f xlsx
```

- `-i`: folder profil (bukan berkas `History`), supaya semua artefak profil ikut diurai.
- `-o` dan `-f`: nama keluaran dan formatnya. Opsi lain (zona waktu tampilan, log) cek dengan `-h` di versi-mu.

Keluaran ilustrasi (ringkas): sheet Timeline memuat 6 baris `webmail.example` pada 2027-01-06 dengan waktu yang sama dengan kueri manual dan kolom transisi terurai sebagai "typed; from address bar; chain start" dan "typed; server redirect; chain end"; sheet unduhan memuat 1 baris dalam jendela (`Formulir-Exit-Clearance.pdf`).

**Cara membaca hasil:** dua cara baca memberi baris, waktu, dan transisi yang sama. Bila berbeda, cari penyebabnya sebelum menulis temuan: zona waktu tampilan, berkas WAL yang tidak terbaca salah satu alat, atau kolom baru yang belum dikenal alat.

**Kapan gagal:** keluaran Hindsight dibaca dalam zona waktu lokal workstation tanpa label, lalu dicampur dengan kueri manual yang UTC.

### 2.6 OneDrive: akun, database klien, dan log ODL

Langkah ini menjawab pertanyaan keempat dan bagian host dari pertanyaan kelima.

**Tujuan pertama:** akun OneDrive yang tersambung dan status Known Folder Move.

```powershell
& "$ez\RECmd\RECmd.exe" -f "G:\Users\arif.wicaksono\NTUSER.DAT" --kn "Software\Microsoft\OneDrive\Accounts" --csv "$out\Registry" --csvf E01-W1_OneDriveAccounts.csv
& "$ez\RECmd\RECmd.exe" -f "G:\Users\arif.wicaksono\NTUSER.DAT" --kn "Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" --csv "$out\Registry" --csvf E01-W1_UserShellFolders.csv
```

- `--kn`: membaca satu key beserta value-nya; opsi ini dan sintaksnya cek dengan `RECmd.exe -h` di versi-mu.

Keluaran ilustrasi:

```
Accounts\Business1   UserEmail   arif.wicaksono@jab.example
                     UserFolder  C:\Users\arif.wicaksono\OneDrive - PT Jaringan Anak Bangsa
(tidak ada subkey Accounts\Personal)
User Shell Folders   Personal    %USERPROFILE%\Documents
                     Desktop     %USERPROFILE%\Desktop
```

Folder pengaturan yang tersalin: `OneDrive\settings\Business1\` ada, `OneDrive\settings\Personal\` tidak ada.

**Cara membaca hasil:** hanya akun kerja yang tersambung di klien. Documents dan Desktop masih lokal, jadi Known Folder Move tidak aktif, dan folder `Documents\Kontrak-Ref` berada di luar OneDrive: penyalinan 19 berkas Rabu tidak otomatis tersinkron ke cloud. OneDrive pribadi tidak dikonfigurasi di klien; aksesnya lewat browser dijawab di bagian 2.3 dan riwayat profil `Profile 1`.

**Tujuan kedua:** isi akun `Business1` menurut database klien.

```powershell
& 'C:\DFIR\tools\OneDriveExplorer\OneDriveExplorer.exe' -s "$w\OneDrive\settings\Business1"
```

- `-s`: arahkan ke folder pengaturan akun pada klien baru yang memakai SQLite [S3]. README menyebut keluaran JSON, CSV, atau HTML bergantung opsi; opsi formatnya cek dengan `-h` di versi-mu, dan simpan keluaran di folder `adendum-A\onedrive\`.

Keluaran ilustrasi (ringkas, dari CSV):

```
Akun Business1  | folder 7 | berkas 41 (29 tersedia lokal, 12 cloud-only)
Folder: Dokumen-Kerja, Proposal, Serah-Terima, Microsoft Teams Chat Files, Foto-Event, Template, Arsip-2025
Microsoft Teams Chat Files : 3 berkas, terakhir berubah 2026-11-18
Serah-Terima               : Catatan-Serah-Terima.docx (28.672 byte)
Nama cocok 'HK-2026-*' atau 'Daftar-PIC*' : 0 (termasuk cloud-only)
```

**Tujuan ketiga:** operasi klien dari log ODL, di `jkt-dfir02`.

```bash
cp -a /mnt/cases/INC-2027-010/work/E01-W1-adendum-A/OneDrive/logs/Business1 /data/INC-2027-010/odl-Business1
ls -l --time-style=+%F /data/INC-2027-010/odl-Business1 | sort -k6 | head -3
ls /data/INC-2027-010/odl-Business1/general.keystore
python3 ~/tools/OneDrive/odl.py -o /mnt/cases/INC-2027-010/analysis/E01-W1/adendum-A/onedrive/odl_Business1.csv /data/INC-2027-010/odl-Business1
```

- `cp -a` ke disk lokal: parser membaca banyak berkas kecil; bekerja di salinan lokal lebih cepat dan tidak menyentuh salinan di share.
- `ls ... | sort | head`: tanggal berkas log tertua, yaitu awal jendela yang bisa dijawab log.
- `general.keystore` harus ada di folder log yang sama, karena klien baru mengenkripsi string log dan kuncinya disimpan di berkas itu [S2].
- `odl.py -o <csv> <folder>`: mengurai semua berkas `.odl`, `.odlgz`, `.odlsent`, dan `.aold` di folder [S2]. Opsi `-s` hanya perlu untuk klien lama bila `ObfuscationStringMap.txt` berada di folder lain; `-d` menampilkan semua data termasuk fungsi yang biasanya disaring [S2].

Keluaran ilustrasi (ringkas, UTC):

```
Berkas log tertua : SyncEngine-2026-12-27.0921.4412.1.odlgz
Berkas log terbaru: SyncEngine-2027-01-07.1012.4412.3.odl (entri terakhir 2027-01-07 14:46:58)
Entri yang menyebut nama berkas, 2027-01-03 17:00 s/d 2027-01-08 17:00:
2027-01-05 03:31:02  ... Serah-Terima\Catatan-Serah-Terima.docx  (perubahan lokal terdeteksi)
2027-01-05 03:31:09  ... Catatan-Serah-Terima.docx  28672  (unggah selesai)
2027-01-07 10:38:51  ... jaringan tidak tersedia, sinkronisasi ditunda
Nama cocok 'HK-2026-*' atau 'Daftar-PIC*' : 0
```

**Cara membaca hasil:**

- Log menjangkau 27 Desember 2026 sampai Kamis 7 Januari 21:46:58 WIB, jadi seluruh jendela 4 sampai 8 Januari tercakup (laptop dimatikan 21:47:12, Day 17).
- Satu berkas diunggah klien dalam jendela: `Catatan-Serah-Terima.docx`, Selasa 2027-01-05 10:31:09 WIB, berkas serah terima di folder `Serah-Terima`. Tidak ada operasi atas nama berkas harga atau daftar PIC.
- Kamis 17:38:51 WIB klien mencatat jaringan tidak tersedia, empat detik setelah WLAN terputus (17:38:47, Day 17): sesi flashdisk malam itu memang tidak punya jalur sinkron.
- Teks fungsi pada log ODL adalah tafsiran parser atas log debug vendor; label "unggah selesai" di atas disamakan dengan baris audit `FileSyncUploadedFull` pada bagian 2.8 sebelum dipakai.

**Kapan gagal:** folder log disalin tanpa `general.keystore`, parser menghasilkan string terenkripsi, dan analyst menulis "log tidak memuat nama berkas".

### 2.7 Teams baru: lokasi, IndexedDB, dan berkas di obrolan

Langkah ini menjawab bagian host dari pertanyaan keenam.

**Tujuan pertama:** menemukan database IndexedDB Teams di salinan, tanpa mengandalkan jalur dari catatan mana pun.

```powershell
Get-ChildItem "$w\Teams" -Recurse -Directory -Filter '*.indexeddb.leveldb' | Select-Object FullName
Get-ChildItem 'G:\Program Files\WindowsApps' -Directory -Filter 'MSTeams_*' | Select-Object Name
Test-Path 'G:\Users\arif.wicaksono\AppData\Roaming\Microsoft\Teams'
```

Keluaran ilustrasi:

```
...\adendum-A\Teams\EBWebView\WV2Profile_tfw\IndexedDB\https_teams.microsoft.com_0.indexeddb.leveldb
MSTeams_<versi>_x64__8wekyb3d8bbwe
True
```

**Cara membaca hasil:** IndexedDB Teams baru ditemukan di bawah folder cache yang disebut Microsoft Learn [S13], di subfolder profil WebView2 yang namanya dicatat apa adanya di case notes. Versi paket dicatat dari nama folder `WindowsApps`. Folder klien lama di `Roaming\Microsoft\Teams` masih ada; tanggal berkas terakhirnya (Maret 2025) menunjukkan sisa sebelum migrasi, sehingga tidak dipakai untuk jendela kasus.

**Tujuan kedua:** mengurai IndexedDB di `jkt-dfir02` dan meringkas percakapan, pesan, dan berkas pada 4 sampai 8 Januari.

```bash
python3 -m venv ~/venv/dfidb && . ~/venv/dfidb/bin/activate && pip install dfindexeddb
dfindexeddb db_info -s /data/INC-2027-010/teams-idb/https_teams.microsoft.com_0.indexeddb.leveldb --format chrome
dfindexeddb db -s /data/INC-2027-010/teams-idb/https_teams.microsoft.com_0.indexeddb.leveldb --format chrome \
  > /mnt/cases/INC-2027-010/analysis/E01-W1/adendum-A/teams/teams-idb.jsonl
```

- Instalasi di virtualenv terpisah, di jendela proxy yang dibuka lewat NOC seperti pembaruan alat di Day 02; versi paket dicatat ke inventaris kasus.
- `db_info`: daftar database dan object store, untuk memastikan `conversations`, `replychains`, dan `profiles` ada [S17][S1].
- `db -s ... --format chrome`: mengurai seluruh record IndexedDB format Chromium [S17]. Keluaran diarahkan ke berkas; opsi format keluaran lain cek dengan `dfindexeddb db -h`.
- Ringkasan dibuat dengan skrip filter kecil atas JSONL: per percakapan, jumlah pesan dengan `isSentByCurrentUser` benar per hari, dan pesan yang `properties.files` atau `properties.links`-nya tidak kosong. Isi `content` tidak diekspor ke ringkasan (memo Legal).

Keluaran ilustrasi (ringkasan, waktu UTC dari `originalArrivalTime`):

```
Rentang cache replychains : 2026-11-30 01:12:44 s/d 2027-01-07 10:36:12
Percakapan aktif 4-8 Jan  : 11  (8 chat 1:1 internal, 1 grup "Enterprise Sales Jakarta",
                                 2 chat 1:1 federasi, domain pelanggan portofolio Arif)
Pesan dikirim akun Arif   : 64
properties.files tidak kosong (dikirim Arif)  : 0
properties.links tidak kosong (dikirim Arif)  : 1
  2027-01-05 03:42:30  chat 1:1 ke galih.pramudya@jab.example  tautan OneDrive .../Serah-Terima/Catatan-Serah-Terima.docx
```

**Cara membaca hasil:**

- Cache menjangkau seluruh jendela sampai Kamis 17:36:12 WIB, waktu yang sama dengan aktif terakhir profil Edge, sebelum laptop terputus.
- Dalam jendela, akun Arif tidak mengirim berkas di obrolan mana pun yang tersimpan di cache. Satu pesan berisi tautan berkas serah terima ke Galih Pramudya, Selasa 10:42:30 WIB, dua menit sebelum email serah terima 10:44 (Day 17).
- Dua obrolan federasi adalah dengan pelanggan dalam portofolio Arif sendiri, keduanya tercantum di daftar serah terima; tidak ada berkas di dalamnya.
- Ini hasil cache: pesan yang dikirim dari ponsel atau Teams web dan tidak pernah dimuat di laptop bisa tidak ada. Bagian 2.8 menutup sebagian celah itu dari audit log.

**Kapan gagal:** alat lama (forensicsim) dijalankan atas klien baru, tidak menghasilkan apa pun, dan hasil kosong itu ditulis sebagai "tidak ada percakapan" [S1].

### 2.8 Sumber di luar host: audit log Microsoft 365 dan sign-in Entra

Langkah ini menjawab bagian pertanyaan kelima dan ketujuh yang tidak bisa dijawab laptop. Analisisnya sengaja dangkal: tujuannya menutup pertanyaan host, bukan membedah tenant.

Pencarian audit dijalankan Agung Prabowo (admin Microsoft 365, tim Infrastruktur) Selasa 2027-02-23 13:40 sampai 14:10 WIB, dengan kriteria dari case notes. Bentuk perintahnya:

```powershell
Search-UnifiedAuditLog -StartDate '2026-11-30 17:00' -EndDate '2027-01-08 17:00' `
  -UserIds 'arif.wicaksono@jab.example' -SessionId 'inc-2027-010-A' -SessionCommand ReturnLargeSet -ResultSize 5000 |
  Export-Csv '\\jkt-evid01\cases\INC-2027-010\analysis\M365\audit-arif-2026-12-01_2027-01-08.csv' -NoTypeInformation
```

- `-StartDate` dan `-EndDate`: jendela 1 Desember sampai 8 Januari WIB yang ditulis sebagai UTC; cara cmdlet menafsirkan zona waktu tanggal cek di dokumentasinya dan catat di case notes.
- `-SessionId` dengan `ReturnLargeSet`: mengambil hasil bertahap bila lebih dari satu halaman; panggil berulang sampai tidak ada hasil baru.
- `Export-Csv`: kolom `AuditData` berisi JSON per record (IP klien, user agent, item). Hash CSV dihitung Agung di titik ekspor dan dicatat di evidence log sebagai sumber pendukung, bukan bukti nomor E.

Ringkasan keluaran ilustrasi, hanya operasi yang menjawab pertanyaan (UTC):

```
Workload OneDrive/SharePoint, 2026-12-01 s/d 2027-01-08
  FileSyncUploadedFull     37   dalam jendela kasus: 1  2027-01-05 03:31:10  Catatan-Serah-Terima.docx
  FileSyncDownloadedFull   22   ClientIP 198.51.100.120 (19), 203.0.113.88 (3); semua user agent klien sync Windows
  FileUploaded (web)        0
  FileDownloaded (web)      0
  SecureLinkCreated         1   2027-01-05 03:41:52  Catatan-Serah-Terima.docx
  AddedToSecureLink         1   2027-01-05 03:41:52  galih.pramudya@jab.example (member)
  SharingSet / SharingInvitationCreated / AnonymousLinkCreated / CompanyLinkCreated : 0
  Nama item cocok 'HK-2026-*' atau 'Daftar-PIC*' : 0
Workload MicrosoftTeams
  MessageSent               9   2 chat federasi (domain pelanggan portofolio Arif); tanpa isi
```

Pembanding identitas perangkat dari sign-in Entra di Splunk (index `o365`, retensi satu tahun; waktu WIB):

```
index=o365 sourcetype="azure:monitor:aad" user="arif.wicaksono@jab.example"
  earliest="12/01/2026:00:00:00" latest="01/09/2027:00:00:00"
| stats count AS signin dc(app) AS aplikasi values(src_ip) AS src_ip by device_id
```

Keluaran ilustrasi: satu baris, `device_id` milik `JKT-WS-0516`, 1.912 sign-in, 9 aplikasi, `src_ip` `198.51.100.120` dan `203.0.113.88`.

**Cara membaca hasil:**

- Audit dan host sepakat: satu-satunya unggahan klien sync dalam jendela kasus adalah berkas serah terima, pada detik yang sama dengan log ODL (10:31:09 dan 10:31:10 WIB). Satu tautan aman dibuat untuk akun internal Galih Pramudya pukul 10:41:52 WIB, 38 detik sebelum pesan Teams berisi tautan itu. Tidak ada berbagi ke pengguna di luar direktori, tautan anonim, atau tautan untuk seluruh organisasi.
- Unduhan lewat klien sync hanya dari dua IP: NAT kantor `198.51.100.120` dan `203.0.113.88`, dengan user agent klien sync Windows. Sign-in Entra menunjukkan satu perangkat untuk akun ini di jendela yang sama, dengan dua IP yang sama; `203.0.113.88` adalah IP yang dipakai laptop itu dari luar kantor. Tidak terlihat perangkat lain yang menyinkron OneDrive akun ini. Atribusi ini lewat IP, user agent, dan `device_id`, bukan nama host di record audit, jadi keyakinannya sedang.
- `MessageSent` tercatat untuk dua chat federasi, sejalan dengan cache Teams; isi pesan tidak ada di audit, dan event ini masih public preview [S8]. Tidak ada unggahan ke `Microsoft Teams Chat Files` dalam jendela.
- Akun Microsoft pribadi dan webmail pribadi berada di luar tenant PT JAB. Audit ini tidak mengatakan apa pun tentang keduanya.
- Record 1 Desember 2026 akan keluar dari retensi 180 hari Audit (Standard) akhir Mei 2027 [S14]. Ekspor dan hash hari ini adalah satu-satunya salinan yang akan tersisa setelah itu.

**Kapan gagal:** analyst meminta "semua log M365 Arif" tanpa kriteria, menerima ribuan baris tanpa hash dan tanpa nama pengekspor, lalu mengutip satu baris di laporan tanpa bisa menunjukkan asal-usulnya.

### 2.9 Adendum A di template `JAB-DFIR-TPL-01`

Langkah ini menjawab pertanyaan ketujuh dari sisi dokumen. Adendum ditulis di `INC-2027-010-LAP-01` versi 1.1 sebagai bagian 4 "Adendum A", dengan pembaruan bagian 9, Lampiran B, C, dan D. Teks di bawah adalah draf yang dikirim Kamis 2027-02-25 16:30 ke Dimas, Sari Kusuma (review teknis), dan Ratna Sari (review bahasa dan distribusi), disimpan sebagai `\\jkt-evid01\cases\INC-2027-010\report\INC-2027-010-LAP-01_v1.1-draf.md`.

```
4. TEMUAN
(Temuan 1-6 versi 1.0 tidak berubah.)

ADENDUM A: Jalur browser dan layanan cloud (versi 1.1)
Dasar: permintaan Legal 2027-02-23; memo lingkup 2027-02-22 15:00. Sumber: salinan kerja E01-W1
(profil browser, OneDrive, Teams), ekspor proxy 2027-01-12, audit log Microsoft 365 akun tersebut
2026-12-01 s/d 2027-01-08 (diekspor admin M365 2027-02-23 14:10, SHA-256 di Lampiran A), sign-in Entra.
Isi email pribadi, isi halaman webmail, dan isi pesan Teams tidak dibuka. Semua waktu WIB.

A.1 Profil browser. Laptop memiliki dua profil Edge: profil kerja (akun korporat, dipakai sehari-hari)
    dan profil pribadi (akun Microsoft pribadi, terakhir aktif 19 Desember 2026, tanpa kunjungan pada
    4-8 Januari). Chrome dan Firefox tidak ditemukan. Seluruh kunjungan yang dibahas tercatat dibuat di
    laptop ini, bukan tersinkron dari perangkat lain.                                Keyakinan: Tinggi
A.2 Webmail pribadi. Tiga sesi Rabu 6 Januari dimulai 15:20:14, 15:33:02, dan 15:40:51 dengan alamat
    dibuka dari address bar profil kerja, bersamaan dengan tiga sesi di proxy kantor. Webmail yang sama
    dibuka dari laptop ini pada 14 hari kerja Desember 2026.                         Keyakinan: Tinggi
A.3 Lampiran dan unggahan. Browser tidak mencatat unggahan, dan tidak ditemukan jejak berkas dipilih
    lewat dialog Windows pada 4-8 Januari (pemilihan dengan seret-dan-lepas tidak meninggalkan jejak
    itu). Volume kirim per sesi 21.504, 147.456, dan 13.376 byte. Apakah berkas dilampirkan atau
    dikirim lewat webmail: tidak dapat ditentukan dari data yang tersedia.           Keyakinan: Rendah
    untuk "tidak ditemukan pemilihan lewat dialog"; tidak dapat ditentukan untuk lampiran.
    Satu unduhan pada 4-8 Januari: formulir exit clearance dari portal HR, Selasa 09:12.
A.4 Cloud pribadi. Tidak ditemukan klien penyimpanan cloud pribadi, akun OneDrive pribadi di klien
    OneDrive, atau kunjungan ke layanan penyimpanan online di kedua profil pada 4-8 Januari.
    Keyakinan: Sedang (berlaku untuk laptop dan trafik kantor; jaringan rumah, ponsel, dan akun
    pribadi di luar pemeriksaan).
A.5 OneDrive korporat. Berkas harga kontrak dan daftar PIC tidak ditemukan di database klien, log
    klien (sejak 27 Desember 2026), maupun audit log (1 Desember-8 Januari). Folder salinan lokal
    berada di luar OneDrive. Satu berkas serah terima diunggah Selasa 10:31 dan dibagikan ke akun
    internal penerima serah terima 10:41; tidak tercatat berbagi ke luar organisasi atau tautan
    anonim.                                                                          Keyakinan: Tinggi
    Tidak terlihat perangkat lain yang menyinkron OneDrive akun ini.                 Keyakinan: Sedang
A.6 Teams. Tidak ditemukan berkas yang dikirim akun ini di obrolan Teams pada 4-8 Januari (cache
    laptop dan audit log). Dua obrolan dengan pihak luar adalah dengan pelanggan dalam portofolio
    akun ini, tanpa berkas.                                                          Keyakinan: Sedang
    (cache laptop tidak lengkap untuk pesan dari perangkat lain; isi pesan tidak diperiksa)

Status temuan versi 1.0: Temuan 6 (jalur online, Rendah sampai sedang) tidak berubah tingkatnya.
Adendum menambah cakupan pemeriksaan (OneDrive korporat, Teams, profil browser) dan menegaskan
bahwa isi sesi webmail tetap tidak dapat ditentukan. Temuan 1-5 tidak tersentuh.

9. YANG BELUM DIKETAHUI (tambahan versi 1.1)
- Isi tiga sesi webmail pribadi: hanya dari penyedia webmail, lewat proses hukum (keputusan Legal).
- Trafik dari jaringan rumah dan ponsel: di luar pemeriksaan.
- Audit log 1 Desember 2026 keluar dari retensi akhir Mei 2027: ekspor 2027-02-23 disimpan dan di-hash.
```

Riwayat versi di Lampiran D diperbarui:

```
Versi  Tanggal      Status                     Perubahan
0.1    2027-01-13   Ringkasan sementara        Ringkasan forensik untuk rapat HR/Legal/DPO 14 Januari
0.9    2027-01-20   Draf untuk review          Struktur JAB-DFIR-TPL-01; lampiran A-E
1.0    2027-01-21   Final                      Setelah catatan D.1-D.5 diselesaikan
1.1    2027-02-26   Final dengan Adendum A     Permintaan Legal 2027-02-23 (memo lingkup 2027-02-22):
                    (draf dikirim 2027-02-25)  jalur browser dan layanan cloud; Lampiran A (hash ekspor
                                               audit), B (alat baru dan versinya), C.A1-C.A6 diperbarui.
                                               Tidak ada temuan versi 1.0 yang berubah tingkat keyakinannya.
```

Cara membaca elemennya:

- **"Temuan 1-6 versi 1.0 tidak berubah"** ditulis di kalimat pertama bagian 4, supaya pembaca yang membandingkan dua versi tahu di mana harus mencari perubahan.
- **A.3 punya dua tingkat** karena dua pernyataan berbeda: pemeriksaan dialog (rendah, inferensi dari ketiadaan) dan lampiran (tidak dapat ditentukan). Angka volume per sesi ditulis tanpa dibandingkan dengan ukuran berkas di halaman ini; perbandingan itu ada di lampiran dengan kalimat batasnya, seperti pola 182.336 vs 1.187.840 di Day 19 bagian 2.3.
- **A.2 menulis pola Desember** karena itu fakta yang sama kuatnya dengan sesi Rabu, dan menghilangkannya akan membuat sesi Rabu terlihat lebih janggal dari yang ditunjukkan bukti.
- **A.5 dipecah dua keyakinan**: keberadaan berkas (host dan audit sepakat, tinggi) dan perangkat lain (atribusi lewat IP dan user agent, sedang).
- **Tidak ada kalimat yang menjawab kuasa hukum.** Kalimat "tidak ada bukti apa pun bahwa klien kami mengirim data lewat internet" tidak dikutip, dibantah, atau disetujui; adendum hanya menyatakan apa yang diperiksa dan batasnya.

Kalimat dilarang yang ditambahkan ke lembar batas bukti rapat Legal:

- "Arif tidak mengirim berkas lewat webmail" (lampiran tidak dapat ditentukan).
- "Arif mengirim berkas harga lewat webmail" (tidak ada artefak yang menunjuk berkas mana pun).
- "Data tidak keluar lewat cloud" (hanya laptop, trafik kantor, dan tenant PT JAB yang diperiksa).
- "Sesi webmail itu tidak biasa" (pola Desember menunjukkan sebaliknya).

**Kapan gagal:** draf adendum memperbarui kalimat Temuan 6 versi 1.0 langsung di tempatnya tanpa riwayat versi, sehingga versi 1.0 yang sudah dibaca kuasa hukum dan versi 1.1 tidak bisa dibandingkan.

## 3. Lab praktik (di VM lab terisolasi)

Lab ini menghasilkan kebenaran dasar yang kamu kendalikan sendiri, supaya setiap kalimat di bagian 1 dan 2 (transisi, dialog file, log OneDrive, IndexedDB Teams) bisa kamu uji di versi alat dan aplikasi yang sama. Nomor kasus lab `CASE-2026-LAB-024`.

**Prasyarat:**

- `LAB-WS01` (`172.16.50.10`, Windows 11) dengan snapshot bersih, akun `lab.user`, Edge dengan dua profil (`Default` dan satu profil bernama "Pribadi-Lab"), Firefox, klien OneDrive yang masuk dengan akun Microsoft uji milik lab (bukan akun kerja atau akun pribadimu), dan Teams baru dengan akun uji bila tersedia. Bila Teams tidak bisa dipakai dengan akun uji, lewati langkah Teams dan catat alasannya.
- `LAB-DFIR01` (`172.16.50.20`) untuk analisis, dengan `sqlite3`, Hindsight, OneDriveExplorer, `odl.py`, `dfindexeddb`, dan EZ Tools.
- Jaringan: langkah yang butuh internet (webmail uji, OneDrive, Teams) dijalankan di jendela terpisah dengan adapter NAT sementara; analisis dikerjakan di host-only `172.16.50.0/24`. Catat jam buka dan tutup jendela itu.
- Web server lab sederhana di `LAB-DFIR01` port 8080 dengan halaman `index.html`, halaman yang mengalihkan (HTTP 302) ke `index.html`, form unggah berkas, dan satu berkas unduhan; untuk menghasilkan transisi dan unduhan tanpa internet.
- Berkas uji `rahasia-lab.xlsx` (sekitar 60 KB) dan `daftar-tiruan.xlsx` di `C:\Users\lab.user\Documents\Ref-Lab24\`.
- Catatan kebenaran dasar `kebenaran-dasar-024.md`: setiap aksi dengan jam (WIB) dan detiknya, ditulis saat aksi dilakukan.

Langkah:

1. Di profil `Default`, ketik `http://172.16.50.20:8080/` di address bar, klik satu tautan di halaman itu, buka alamat yang mengalihkan, lalu buka satu alamat dari saran address bar dan satu kata kunci pencarian. Catat jamnya.
2. Tutup Edge dengan normal. Salin seluruh `User Data` ke `LAB-DFIR01` dan hash. Jalankan kueri bagian 2.3 (tanpa filter domain) dan buktikan setiap aksi langkah 1 terbedakan lewat tipe inti dan qualifier. Catat nilai heksadesimal tiap aksi, terutama apakah pemilihan saran address bar tercatat `TYPED` atau `GENERATED`.
3. Cek apakah nilai `transition` untuk kunjungan dengan `SERVER_REDIRECT` tersimpan negatif bila dibaca tanpa `& 0xFFFFFFFF`. Catat hasilnya untuk versi Edge lab.
4. Unduh berkas dari web server lab sampai selesai, lalu unduh lagi dan batalkan di tengah. Bandingkan baris `downloads` (`state`, `received_bytes`, `total_bytes`, `interrupt_reason`) dan `downloads_url_chains` (`chain_index`) keduanya, lalu cocokkan dengan `$MFT` dan `$J` di `LAB-WS01`.
5. Unggah `rahasia-lab.xlsx` lewat form di web server lab dua kali: sekali lewat tombol pilih berkas (dialog Windows), sekali dengan seret dan lepas dari Explorer. Setelah itu ambil `NTUSER.DAT` (lewat KAPE atau dari snapshot) dan jalankan RECmd seperti bagian 2.4. Catat apakah LastVisitedPidlMRU dan OpenSavePidlMRU berubah untuk masing-masing cara, dan apakah riwayat browser mencatat unggahan dengan tipe apa. Bandingkan dengan log akses web server lab yang mencatat permintaan unggah.
6. Ulangi langkah 1 di Firefox. Jalankan kueri bagian 2.3 apa adanya (konversi Chromium) atas `places.sqlite`, catat selisih waktunya, lalu perbaiki konversi dan baca `visit_type` dengan tabel Firefox.
7. Buka Edge InPrivate, kunjungi dua halaman di web server lab, tutup. Cari jejaknya di `History`, cache, dan log akses web server lab. Tulis kesimpulan tentang apa yang bisa dan tidak bisa disimpulkan dari ketiadaan di riwayat.
8. Jalankan Hindsight atas profil `Default` dan atas profil Firefox (fitur baru v2026.06), lalu bandingkan dengan hasil kuerimu. Catat setiap perbedaan dan penyebabnya.
9. OneDrive akun uji: salin `rahasia-lab.xlsx` ke folder OneDrive, buat satu berkas baru, ubah satu berkas, hapus satu berkas, jadikan satu berkas cloud-only, lalu bagikan satu berkas dari OneDrive web dengan tautan. Hentikan klien. Salin `settings` dan `logs` (pastikan `general.keystore` ikut), jalankan OneDriveExplorer `-s` dan `odl.py`, lalu bandingkan dengan kebenaran dasar. Catat secara khusus apakah pembuatan tautan berbagi di web terlihat di artefak host.
10. Ulangi langkah 9 tanpa `general.keystore` dan catat apa yang terjadi pada keluaran `odl.py`.
11. Periksa berkas log OneDrive tertua di VM-mu dan catat berapa hari ke belakang yang benar-benar bisa dijawab.
12. Teams (bila tersedia): kirim tiga pesan dan satu berkas di obrolan uji, lalu tutup Teams. Temukan folder IndexedDB dengan pencarian (bagian 2.7), catat jalur nyata dan versi paket, jalankan `dfindexeddb db_info` dan `db`, lalu buktikan pesan dan berkas uji ditemukan. Cari berkas yang dikirim di folder OneDrive pengirim.
13. Susun tabel seperti adendum bagian 2.9 dari seluruh aktivitas lab, dengan kolom "terlihat di host", "hanya terlihat di layanan", dan "tidak terlihat sama sekali".

**Hasil yang sebaiknya tersimpan:**

- Tabel nilai `transition` heksadesimal per aksi langkah 1 untuk versi Edge lab, termasuk hasil uji saran address bar dan nilai negatif.
- Perbandingan baris unduhan selesai dan batal, dengan kecocokan `$MFT`/`$J`.
- Hasil uji dialog vs seret-dan-lepas: kunci ComDlg32 mana yang berubah, dan apakah riwayat mencatat unggahan.
- Bukti selisih waktu bila konversi Chromium dipakai pada Firefox, dan tabel `visit_type` Firefox yang terbaca.
- Kesimpulan tertulis tentang InPrivate.
- Perbandingan Hindsight dengan kueri manual untuk Edge dan Firefox.
- Rekonstruksi OneDrive vs kebenaran dasar, dengan catatan khusus tentang tautan berbagi web dan keluaran tanpa `general.keystore`.
- Rentang log OneDrive yang tersedia di lab.
- Jalur IndexedDB Teams, versi paket, dan daftar object store yang ditemukan; bukti pesan dan berkas uji terbaca.
- Tabel terlihat di host, hanya di layanan, dan tidak terlihat.

## 4. Troubleshooting

Tabel ini berisi gejala yang paling sering muncul saat membaca artefak browser dan cloud; baca kolom "Cara memeriksa" sebelum menyimpulkan apa pun dari hasil kosong.

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Database terkunci saat dibuka | Aplikasi masih berjalan (host hidup) | Bekerja atas salinan dari image, shadow copy, atau koleksi raw [S4] |
| Transaksi terakhir tidak ada | Berkas `-wal` atau `-journal` tidak ikut disalin | Salin seluruh folder profil (bagian 2.1), bukan satu berkas |
| Waktu meleset ratusan tahun | Konversi epoch keluarga browser lain | Chromium epoch 1601, Firefox epoch 1970 (bagian 1.1) |
| Waktu meleset tepat 7 jam | Batas kueri ditulis WIB padahal kolom UTC, atau alat menampilkan waktu lokal workstation | Tulis batas dalam UTC; beri label zona di setiap keluaran (bagian 2.3) |
| `transition` bernilai negatif | Bit `SERVER_REDIRECT` dibaca sebagai bilangan bertanda | Tampilkan `& 0xFFFFFFFF` dalam heksadesimal, ambil `& 0xFF` untuk tipe inti |
| Profil `Default` kosong padahal pengguna aktif | Pengguna memakai profil lain | Baca `Local State` (bagian 2.2) |
| Kunjungan pada jam laptop mati | Kunjungan tersinkron dari perangkat lain | Periksa `originator_cache_guid` [S10] |
| Satu unduhan muncul beberapa kali | Join ke `downloads_url_chains` tanpa filter `chain_index` | Tambahkan `chain_index = 0` [S11] |
| Log OneDrive berisi string acak | `general.keystore` atau `ObfuscationStringMap.txt` tidak ikut | Ambil ulang dari salinan; untuk klien baru kunci di folder log yang sama [S2] |
| Tidak ada log OneDrive untuk tanggal kasus | Log sudah berputar | Catat berkas tertua; tulis jendela di temuan [S4] |
| OneDriveExplorer gagal membaca `.dat` | Klien baru memakai SQLite | Pakai `-s` ke folder `settings\<akun>` [S3] |
| Tidak ada folder Teams di `Roaming` | Teams baru menyimpan di `Packages\MSTeams_8wekyb3d8bbwe` | Cari dengan pencarian folder (bagian 2.7) [S13] |
| Alat Teams tidak menghasilkan pesan | Alat lama tidak mendukung format dan comparator klien baru | Pakai `dfindexeddb`, uji dulu dengan percakapan buatan sendiri [S1][S17] |
| Tidak bisa membuktikan berkas terkirim atau dibagikan | Artefak host hanya mencatat operasi klien | Minta audit log; tulis batasnya (bagian 1.6) |

## 5. Kesalahan umum dan jebakan

- Membuka database bukti dengan alat yang menulis, bukan salinan dalam mode baca saja.
- Menyalin berkas SQLite atau LevelDB tanpa berkas pendampingnya.
- Membaca hanya profil `Default` dan menulis "tidak ada aktivitas browser".
- Memakai konversi epoch Chromium pada Firefox, atau tabel transisi Chromium untuk `visit_type` Firefox.
- Menyajikan daftar URL tanpa kolom transisi, sehingga kunjungan yang dibuka sendiri tidak terbedakan dari pengalihan dan tautan.
- Menulis "pengguna mengetik alamat lengkap" dari `TYPED`, padahal tipe itu juga mencakup memilih saran address bar.
- Menganggap semua kunjungan terjadi di laptop yang diperiksa tanpa membaca `originator_cache_guid`.
- Menulis "tidak ada lampiran" karena riwayat dan cache tidak memuat unggahan, atau menulis "berkas terkirim" karena volume proxy cukup besar.
- Menganggap hasil negatif ComDlg32 menutup kemungkinan seret dan lepas.
- Membuka isi cache webmail pribadi atau isi pesan Teams di luar memo lingkup.
- Mencari berkas hanya di folder OneDrive lokal tanpa database klien, sehingga berkas cloud-only terlewat.
- Lupa memeriksa Known Folder Move, sehingga tidak tahu apakah Documents tersinkron.
- Mengambil log OneDrive tanpa `general.keystore`.
- Menyalin jalur Teams dari catatan lama (Electron) dan menulis "tidak ada data Teams".
- Lupa bahwa berkas di obrolan Teams disimpan di OneDrive pengirim dan dibagikan, sehingga jejaknya juga ada di OneDrive dan audit.
- Menyimpulkan "tidak dibagikan ke luar" dari artefak host.
- Menunda ekspor audit log sampai mendekati batas retensi.
- Menulis adendum dengan mengubah kalimat laporan final di tempat, tanpa versi baru dan riwayat versi.

## 6. Catatan terkini

Bagian ini mencatat perubahan versi dan keputusan alat yang mempengaruhi cara membaca Day ini.

- **Hindsight v2026.06** (rilis 2026-07-08) menambah dukungan Firefox, deteksi otomatis browser dan varian seperti Edge dan Brave, parsing data Service Worker, dan perluasan parsing unduhan; v2026.04 sebelumnya menaikkan dukungan Chrome sampai versi 145 dan menambah analisis serta rekonstruksi sesi Chrome [S12]. Sebelum v2026.06, Hindsight hanya untuk browser berbasis Chromium; catatan lama yang menyebutnya begitu sudah usang.
- **Skema `visits` Chromium** kini memuat kolom sinkronisasi (`originator_cache_guid`, `originator_visit_id`, `originator_from_visit`, `originator_opener_visit`, `is_known_to_sync`) dan kolom lain seperti `opener_visit`, `consider_for_ntp_most_visited`, `visited_link_id`, dan `app_id` [S10]. Kueri yang memakai `SELECT *` dari catatan lama tetap jalan, tetapi tafsirannya tidak lengkap tanpa kolom asal kunjungan.
- **Log OneDrive:** sejak sekitar April 2022 klien bisa tidak lagi membuat `ObfuscationStringMap.txt` dan mengenkripsi data log dengan AES, dengan kunci di `general.keystore` [S2]. Daftar koleksi yang hanya menyebut berkas pemetaan perlu diperbarui.
- **OneDrive SQLite:** klien baru beralih dari `<UserCid>.dat` ke database SQLite; OneDriveExplorer membacanya dengan opsi `-s` [S3]. Nama berkas database dan skemanya tidak didokumentasikan resmi, jadi cek di lab dengan versi klien yang sama.
- **Teams baru:** makalah CEUR Vol-4198 (konferensi ITASEC dan SERICS, 9 sampai 13 Februari 2026; terbit di CEUR 2026-04-23) menguji build 25072.125072.1611.3570 dan memvalidasi alatnya terhadap rilis produksi Februari 2026 [S1]. Folder cache resmi menurut Microsoft Learn adalah `LocalCache\Microsoft\MSTeams` di paket `MSTeams_8wekyb3d8bbwe` [S13]. Nama subfolder profil WebView2 dan nama folder origin IndexedDB tidak didokumentasikan resmi.
- **Audit Purview:** retensi Audit (Standard) 180 hari untuk record sejak 17 Oktober 2023; Audit (Premium) satu tahun untuk Entra ID, Exchange, OneDrive, dan SharePoint, sampai 10 tahun dengan add-on [S14]. `MessageSent` untuk chat Teams masih public preview dan hanya dibuat bila ada guest, pengguna federasi, atau anonim [S8].
- **Keputusan alat untuk `INC-2027-010`:** EZ Tools tetap 2026.5.0 (dibekukan). Alat baru adendum (sqlite3, Hindsight v2026.06, OneDriveExplorer dari commit terbaru saat diunduh, `odl.py`, `dfindexeddb`) dicatat versi dan hash-nya di Lampiran B versi 1.1 dan diuji di `LAB-WS01` sebelum dipakai. Klien Teams dan OneDrive versi Januari 2027 tidak bisa dipasang ulang persis di lab, sehingga uji lab memakai versi terdekat dan perbedaannya dicatat sebagai batas.

## 7. Cheat sheet

```
PROFIL     Edge  : %LocalAppData%\Microsoft\Edge\User Data\{Default,Profile N}\   peta: "Local State" (profile.info_cache)
           Chrome: %LocalAppData%\Google\Chrome\User Data\...
           Firefox: %AppData%\Mozilla\Firefox\Profiles\<acak>\places.sqlite        peta: profiles.ini
           SALIN SELURUH FOLDER (wal/journal/LOG/MANIFEST) -> buka salinan read-only

WAKTU      Chromium: mikrodetik sejak 1601 UTC -> /1000000 - 11644473600
           Firefox : mikrodetik sejak 1970 UTC -> /1000000
           batas kueri ditulis dalam UTC (WIB - 7)

CHROMIUM   urls | visits (visit_time, from_visit, opener_visit, transition, visit_duration,
                          originator_cache_guid: kosong = lokal, isi = tersinkron)
           downloads (target_path, received/total_bytes, state 1=selesai 4=terputus, tab_url, hash)
           downloads_url_chains (chain_index 0 = URL awal)
TRANSISI   inti = transition & 0xFF: 0 LINK 1 TYPED 2 BOOKMARK 5 GENERATED 7 FORM_SUBMIT 8 RELOAD
           qualifier: 0x02000000 FROM_ADDRESS_BAR 0x10000000 CHAIN_START 0x20000000 CHAIN_END
                      0x40000000 CLIENT_REDIRECT 0x80000000 SERVER_REDIRECT (bisa tampil negatif)
           0x12000001 = TYPED dari address bar, awal rantai | 0xA0000001 = akhir rantai redirect server
FIREFOX    moz_places | moz_historyvisits.visit_type: 1 LINK 2 TYPED 3 BOOKMARK 5/6 REDIRECT 7 DOWNLOAD 9 RELOAD
           unduhan: moz_annos 'downloads/destinationFileURI' (versi baru) | moz_downloads (lama)

UNGGAHAN   TIDAK dicatat riwayat/cache (XHR/fetch). Jejak tidak langsung:
           ComDlg32 OpenSavePidlMRU / LastVisitedPidlMRU (msedge.exe) = DIPILIH via dialog, bukan TERKIRIM
           seret-dan-lepas = tidak ada jejak dialog | proxy = volume, bukan isi

ONEDRIVE   NTUSER Software\Microsoft\OneDrive\Accounts\{Business1..9,Personal}; cek KFM (User Shell Folders)
           settings\<akun>\ : <UserCid>.dat(.previous) LAMA | SQLite BARU -> OneDriveExplorer -s <folder>
           logs\<akun>\ : .odl .odlgz .odlsent .aold + general.keystore (BARU) / ObfuscationStringMap.txt (LAMA)
           odl.py -o out.csv <folder_log>    | cek berkas log TERTUA = awal jendela

TEAMS BARU %LocalAppData%\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\
           ...\<profil WebView2>\IndexedDB\https_teams.microsoft.com_0.indexeddb.leveldb  (CARI, jangan salin)
           store: conversations | replychains (properties.files/links) | profiles
           dfindexeddb db -s <folder> --format chrome      (forensicsim lama tidak efektif)
           berkas di chat = OneDrive pengirim "Microsoft Teams Chat Files" + berbagi -> cek OneDrive + audit

DI LUAR HOST  audit Purview: FileSyncUploadedFull/DownloadedFull, FileUploaded/Downloaded,
              SharingSet, SharingInvitationCreated (luar direktori), AnonymousLinkCreated/Used,
              CompanyLinkCreated, SecureLinkCreated, AddedToSecureLink, MessageSent (preview)
              retensi Standard 180 hari -> ekspor + hash SEKARANG
              akun pribadi & webmail pribadi = di luar tenant

ADENDUM    versi 1.1, 1.0 tidak ditimpa | pertanyaan A.n | status keyakinan temuan lama ditulis
           "tidak ditemukan" + cakupan | tidak menjawab argumen pihak lain
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Riwayat Edge dan cache tidak memuat satu pun URL unggahan selama tiga sesi webmail, jadi adendum bisa menulis bahwa tidak ada lampiran yang dikirim." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Webmail mengunggah lampiran lewat permintaan latar belakang yang bukan navigasi, jadi tidak menjadi baris riwayat, dan cache hanya menyimpan respons yang diterima, bukan yang dikirim. Ketiadaan jejak unggahan di riwayat dan cache hampir tidak bernilai sebagai bukti. Yang bisa ditulis: browser tidak mencatat unggahan, tidak ditemukan pemilihan berkas lewat dialog Windows dalam jendela (keyakinan rendah, karena seret dan lepas tidak tercatat), dan apakah ada lampiran tidak dapat ditentukan dari data yang tersedia. Lihat bagian 1.3.

</details>

**2. Skenario keputusan.** Kueri atas `History` memberi kunjungan ke webmail dengan `transition` bernilai -1610612735. Rekanmu mengusulkan menulis di laporan bahwa "kunjungan memakai tipe transisi tidak dikenal". Apa yang kamu lakukan?

- A. Ikuti usulan itu, karena nilai negatif tidak ada di tabel tipe inti.
- B. Tampilkan nilai sebagai heksadesimal dengan `& 0xFFFFFFFF`, ambil tipe inti dengan `& 0xFF`, dan baca qualifier-nya.
- C. Abaikan kolom transisi dan laporkan URL serta waktunya saja.

<details><summary>Jawaban</summary>

B. Nilai -1610612735 adalah `0xA0000001` yang dibaca sebagai bilangan bertanda: tipe inti 1 (`TYPED`) dengan `SERVER_REDIRECT` dan `CHAIN_END`, yaitu halaman akhir setelah server mengalihkan alamat yang dibuka dari address bar. A salah karena bit tertinggi qualifier membuat nilai tampak negatif, bukan tipe yang tidak dikenal. C membuang satu-satunya kolom yang membedakan kunjungan yang dibuka sendiri dari tautan atau pengalihan, padahal itu inti pertanyaan Legal. Lihat bagian 1.2.

</details>

**3. Jelaskan ulang.** Jelaskan kepada Ratna Sari (Legal) dalam tiga kalimat kenapa adendum bisa menulis keyakinan tinggi bahwa berkas harga tidak ada di OneDrive korporat, tetapi hanya keyakinan sedang bahwa tidak ada perangkat lain yang menyinkron OneDrive akun itu.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh jawaban: "Untuk keberadaan berkas, tiga sumber yang berbeda sifatnya sepakat: database klien OneDrive di laptop, log klien sejak 27 Desember, dan audit log Microsoft 365 sejak 1 Desember, dan tidak satu pun memuat nama berkas harga atau daftar PIC. Untuk perangkat lain, kita hanya bisa membaca alamat IP, jenis aplikasi, dan identitas perangkat dari log layanan, bukan nama perangkat yang pasti, sehingga kesimpulannya bertumpu pada kecocokan IP dan identitas perangkat dengan laptop ini. Keduanya berlaku dalam jendela audit 1 Desember sampai 8 Januari dan hanya untuk tenant PT JAB, bukan akun pribadi."

Kesalahan yang sering muncul: menyamakan dua pernyataan menjadi satu keyakinan; menyebut database klien di laptop sebagai bukti tidak ada berbagi atau tidak ada perangkat lain, padahal itu hanya terlihat di audit; lupa menyebut jendela waktu dan bahwa akun pribadi di luar tenant.

</details>

**4. Pertanyaan jebakan.** "Kunjungan webmail Rabu sore tercatat di `History` laptop Arif, jadi pasti dilakukan di laptop itu." Benarkah tanpa pemeriksaan tambahan?

<details><summary>Jawaban</summary>

Tidak tanpa membaca kolom asal kunjungan. Profil yang masuk dengan akun dan sinkronisasi aktif bisa menerima kunjungan dari perangkat lain. Di Chromium, `originator_cache_guid` kosong berarti kunjungan lokal dan berisi berarti tersinkron dari mesin lain. Di kasus ini keenam baris webmail lokal, dan waktunya cocok dengan tiga sesi proxy dari IP laptop, jadi dua sumber independen sepakat. Kunjungan tetap menunjuk profil dan sesi, bukan orang di depan keyboard. Lihat bagian 1.1 dan 2.3.

</details>

**5. Skenario keputusan.** Saat menyusun daftar koleksi standar untuk kasus kebocoran data berikutnya, Yudha Prakoso mengusulkan target OneDrive yang mengambil `*.odl` dan `*.odlgz` dari folder log. Apa koreksimu?

- A. Cukup; berkas log memuat semua informasi.
- B. Tambahkan `general.keystore` (dan `ObfuscationStringMap.txt` bila ada) dari folder yang sama, seluruh folder `settings\<akun>`, dan berkas `.odlsent` serta `.aold`; catat juga berkas log tertua.
- C. Tidak perlu log; database `settings` sudah cukup.

<details><summary>Jawaban</summary>

B. Klien baru mengenkripsi string log dengan kunci di `general.keystore`, dan tanpa kunci itu log tidak terbaca; klien lama memakai `ObfuscationStringMap.txt`. Parser juga membaca `.odlsent` dan `.aold`. Database di `settings` menjawab keadaan akun menurut klien, sedangkan log menjawab operasi dan waktunya, jadi keduanya dibutuhkan. A gagal karena log tanpa kunci tidak bisa diurai. C kehilangan urutan operasi, misalnya waktu unggah yang di kasus ini dicocokkan dengan audit. Lihat bagian 1.4 dan 2.6.

</details>

**6. Pertanyaan jebakan.** "Cache Teams di laptop tidak memuat berkas yang dikirim Arif ke pihak luar, dan database OneDrive klien tidak memuat tautan berbagi keluar, jadi Arif tidak pernah membagikan berkas ke luar lewat Microsoft 365." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Cache Teams hanya berisi percakapan yang pernah dimuat di laptop itu, dan pembuatan tautan berbagi bisa dilakukan dari web atau perangkat lain tanpa jejak di laptop. Berbagi ke luar direktori, tautan anonim, dan pesan ke pihak luar dijawab audit log Purview (`SharingInvitationCreated`, `AnonymousLinkCreated`, `MessageSent`, dan seterusnya). Di kasus ini audit untuk 1 Desember sampai 8 Januari memang tidak memuat berbagi keluar, sehingga kalimat yang aman adalah "tidak tercatat berbagi ke luar organisasi atau tautan anonim dalam jendela audit", tetap terbatas pada tenant PT JAB. Lihat bagian 1.5, 1.6, dan 2.8.

</details>

**7. Interview question (English).** "Legal asks you whether a departing employee uploaded confidential files to his personal webmail from his corporate laptop. How do you approach it, and what can you realistically conclude?"

<details><summary>Sample answer</summary>

"First I'd confirm the written scope, because personal webmail content is off-limits without a legal process. On the image, I'd map every browser profile from Local State, then pull the visits for the webmail domain with the transition type split into core type and qualifiers, and check whether each visit was local or synced. I'd correlate those visits with proxy sessions and per-session outbound volume. For uploads, I'd be explicit that browser history and cache don't record them, so I'd look at indirect traces like the Windows file dialog MRU keys for the browser process, knowing drag-and-drop leaves nothing there. I'd also close the other paths: cloud sync clients, corporate OneDrive and Teams, using the client database, the ODL logs with the keystore, the Teams IndexedDB, and the Microsoft 365 audit log for sharing events. A realistic conclusion is usually: the sessions were deliberately opened from the laptop at specific times, the volume sent per session was X, and whether any file was attached cannot be determined from the available data; only the provider can answer that through a legal process."

What makes this answer strong: it starts with scope and privacy, separates what the host proves (deliberate navigation, timing, volume) from what it cannot (attachment content), names concrete artifacts and their limits, closes alternative paths with the right off-host source, and ends with a calibrated conclusion instead of a yes or no.

</details>

## 9. Sumber

| # | Judul | URL | Tipe | Tanggal / diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Bertolotti, Epifani, Lagorio: A Forensic Analysis of the WebView2-based Microsoft Teams Client (CEUR Workshop Proceedings Vol-4198, ITASEC dan SERICS 2026) | https://ceur-ws.org/Vol-4198/paper14.pdf | Primer (makalah penelitian) | Konferensi 2026-02-09 s/d 13, terbit 2026-04-23; diakses 2026-10-22 | Sedang-tinggi. Perpindahan Electron ke WebView2 (2023), build uji 25072.125072.1611.3570, struktur Local Storage/IndexedDB/Cache, 95 object store di 56 database, `conversations`, `replychains`, `profiles`, pola ID percakapan, forensicsim dan LevelDBDumper tidak efektif, dfindexeddb; satu kelompok peneliti, belum direplikasi |
| S2 | OneDrive log .ODL reader (odl.py, Yogesh Khatri) | https://github.com/ydkhatri/OneDrive | Primer (kode dan dokumentasi alat) | Diakses 2026-10-22 | Sedang-tinggi. Sintaks `odl.py`, opsi `-o`, `-s`, `-k`, `-d`; ekstensi `.odl`, `.odlgz`, `.odlsent`, `.aold`; enkripsi AES dengan `general.keystore` sejak sekitar April 2022 |
| S3 | OneDriveExplorer (Beercow) | https://github.com/Beercow/OneDriveExplorer | Primer (kode dan dokumentasi alat) | Diakses 2026-10-22 | Sedang-tinggi. Rekonstruksi `<UserCid>.dat` dan `.dat.previous`, opsi `-s` untuk SQLite klien baru, `-r`, `-rb`, lokasi `settings` dan `logs` per akun, kunci log; nama berkas database SQLite tidak disebut |
| S4 | Reading OneDrive Logs (Yogesh Khatri, swiftforensics) | http://www.swiftforensics.com/2022/02/reading-onedrive-logs.html | Sekunder (riset praktisi) | 2022; dirujuk 2026-10-09 | Sedang. Letak dan penamaan log, obfuskasi, berkas diagnostik teks, rotasi log; berumur beberapa tahun, detail format perlu diuji ulang |
| S5 | Mozilla: Profiles, where Firefox stores your data | https://support.mozilla.org/en-US/kb/profiles-where-firefox-stores-user-data | Primer | Dirujuk 2026-10-09 | Tinggi untuk letak dan penamaan direktori profil |
| S6 | Hindsight (parser riwayat browser) | https://github.com/obsidianforensics/hindsight | Primer (kode dan dokumentasi alat) | Dirujuk 2026-10-09 | Sedang-tinggi. Dipakai sebagai pembanding kueri manual |
| S7 | Endpoint-Forensics-Notes Day 08, 10, 17, 19 | (lokal) | Rujukan internal | 2026-10-22 | Keterkaitan antar Day |
| S8 | Microsoft Learn: Audit log activities (Microsoft Purview) | https://learn.microsoft.com/en-us/purview/audit-log-activities | Primer | ms.date 2026-10-15; diakses 2026-10-22 | Tinggi. Operasi berkas (jeda lima menit `FileAccessed`, `FileSyncUploadedFull`, `FileSyncDownloadedFull`), operasi berbagi, `MessageSent` (preview, chat dengan guest/federasi/anonim) |
| S9 | Chromium source: `ui/base/page_transition_types.h` | https://chromium.googlesource.com/chromium/src/+/HEAD/ui/base/page_transition_types.h | Primer (kode sumber) | HEAD, diakses 2026-10-22 | Tinggi. Nilai tipe inti dan qualifier, arti `TYPED`, `GENERATED`, `FORM_SUBMIT`, `RELOAD` |
| S10 | Chromium source: `components/history/core/browser/visit_database.cc` | https://chromium.googlesource.com/chromium/src/+/HEAD/components/history/core/browser/visit_database.cc | Primer (kode sumber) | HEAD, diakses 2026-10-22 | Tinggi. Kolom tabel `visits`, arti `originator_cache_guid` dan `is_known_to_sync`, `from_visit` dan `opener_visit` 0 bila tidak ada |
| S11 | Chromium source: `components/history/core/browser/download_database.cc` | https://chromium.googlesource.com/chromium/src/+/HEAD/components/history/core/browser/download_database.cc | Primer (kode sumber) | HEAD, diakses 2026-10-22 | Tinggi untuk kolom `downloads` dan `downloads_url_chains` (`chain_index`); arti `state` hanya dari komentar skema (1 selesai, 4 terputus) |
| S12 | Hindsight releases | https://github.com/obsidianforensics/hindsight/releases | Primer (catatan rilis) | v2026.06 rilis 2026-07-08; diakses 2026-10-22 | Tinggi untuk fitur per versi: dukungan Firefox, deteksi Edge/Brave, unduhan diperluas (v2026.06); Chrome sampai 145 dan sesi (v2026.04) |
| S13 | Microsoft Learn: Clear the Teams client cache | https://learn.microsoft.com/en-us/troubleshoot/microsoftteams/teams-administration/clear-teams-cache | Primer | Diakses 2026-10-22 | Tinggi untuk folder cache Teams baru `MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams`; bukan dokumentasi forensik |
| S14 | Microsoft Learn: Learn about auditing solutions in Microsoft Purview | https://learn.microsoft.com/en-us/purview/audit-solutions-overview | Primer | ms.date 2026-05-18; diakses 2026-10-22 | Tinggi. Retensi Audit (Standard) 180 hari sejak 17 Oktober 2023, Audit (Premium) satu tahun dan 10 tahun dengan add-on |
| S15 | Mozilla source: `nsINavHistoryService.idl` (Searchfox) | https://searchfox.org/mozilla-central/source/toolkit/components/places/nsINavHistoryService.idl | Primer (kode sumber) | Diakses 2026-10-22 | Tinggi untuk nilai `TRANSITION_*` Firefox |
| S16 | Autopsy 4.19.0 `Firefox.java` (Recent Activity) | https://sleuthkit.org/autopsy/docs/api-docs/4.19.0/_firefox_8java_source.html | Sekunder (kode alat forensik) | Diakses 2026-10-22 | Sedang. Kueri riwayat (`visit_date/1000000`) dan unduhan Firefox (`moz_downloads` lama, `moz_annos` `downloads/destinationFileURI` sejak versi 24) |
| S17 | dfindexeddb (Google) | https://github.com/google/dfindexeddb | Primer (kode dan dokumentasi alat) | Diakses 2026-10-22 | Sedang-tinggi. Instalasi, `db -s ... --format chrome`, `db_info`, format chrome/firefox/safari; opsi keluaran untuk format chrome cek `-h` |

**Catatan sumber:** nama tabel dan kolom database browser diambil dari kode sumber Chromium HEAD (S9 sampai S11) dan Mozilla (S15), bukan dari dokumentasi antarmuka publik; vendor bisa mengubahnya, jadi verifikasi skema di salinan bukti. Penafsiran `visit_duration` dan apakah pemilihan saran address bar dicatat `TYPED` di Edge versi tertentu belum diuji dan ditulis sebagai hal yang dicek di lab (bagian 3). Bahwa dialog unggah berkas browser menulis OpenSavePidlMRU dan LastVisitedPidlMRU didasarkan pada perilaku dialog Windows yang dibahas di Day 10, bukan pada sumber khusus browser; uji di lab dengan versi yang sama. Nama berkas database SQLite OneDrive (`SyncEngineDatabase.db`) beredar di komunitas tetapi tidak disebut di S3 atau dokumentasi resmi. Nama subfolder profil WebView2 Teams tidak disebut di S1 atau S13; jalur di bagian 2.7 adalah keluaran ilustrasi. Folder `Microsoft Teams Chat Files` sebagai tempat berkas obrolan disimpan adalah perilaku umum Microsoft 365 yang tidak dikutip dari halaman tertentu di Day ini; cek di tenant-mu. Angka retensi log OneDrive tidak ditulis karena tidak ada sumber resmi; ukur di lab.
