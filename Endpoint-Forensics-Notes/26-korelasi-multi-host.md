---
day: 26
title: 'Korelasi multi-host dan timeline kolaboratif: dari satu host ke sebuah insiden'
researched_on: 2026-10-22
versions_checked: 'Timesketch 20261014 (rilis terbaru per 2026-10-23; minimum Plaso 20260720; computer_name menjadi hostname, body menjadi message_body; RBAC grup OIDC); impor CSV/JSONL (field wajib message, datetime, timestamp_desc; batas nilai 32766 byte); analyzer Sigma Timesketch (fungsi alpha, hanya rule berstatus stable, field ts_sigma_rule dan ts_ttp); dfTimewolf (repo log2timeline, commit terakhir 2026-10-20, tanpa rilis bertag); Plaso 20260720; Volatility 3 2.28.2 dan EZ Tools 2026.5.0 (versi kasus INC-2026-017)'
---

# Day 26: Korelasi multi-host dan timeline kolaboratif

Cakupan: menyusun satu garis waktu dari banyak host dan banyak jenis sumber, menyamakan zona waktu dan jam antar sumber, menamai dan menyiapkan data agar bisa digabung, melakukan pivot lintas host dengan urutan yang masuk akal, memakai analyzer Sigma tanpa menyerahkan kesimpulan ke mesin, dan menulis cerita kasus yang bisa ditelusuri kembali ke event aslinya bersama analyst lain dan retainer.

## Ide inti

Satu host menjawab "apa yang terjadi di mesin ini". Sebuah insiden menanyakan hal lain: dari mana penyerang datang, ke mana ia pergi, dan dalam urutan apa. Pertanyaan itu tidak bisa dijawab dengan menumpuk sepuluh laporan per host, karena jawabannya ada di sambungan antar host: logon jaringan di satu mesin yang cocok dengan kredensial eksplisit di mesin lain, koneksi di log firewall yang cocok dengan sisa koneksi di memori, pembacaan share di file server yang cocok dengan proses di workstation. Sambungan itu hanya terlihat bila semua sumber berada di satu sumbu waktu yang sama, setiap baris membawa nama host asalnya, dan setiap pasangan baris yang dihubungkan punya bukti penghubung selain kedekatan waktu. Logon ID, PID, dan nomor record hanya bermakna di dalam satu host; di antara host, yang menghubungkan adalah alamat IP sumber dan tujuan, akun, nama share, hash, dan waktu yang sudah dikalibrasi. Karena itu kerja multi-host adalah disiplin data lebih dulu (zona waktu, jam host, nama host, skema, penamaan), baru kemudian pencarian. Begitu lebih dari satu orang bekerja di data yang sama, disiplin itu juga harus tertulis: kosakata tag yang disepakati, satu wadah per kasus, dan cerita yang setiap kalimatnya menunjuk ke pencarian yang menghasilkannya.

Kamu sudah mengenal pola ini dari NOC. Saat gangguan besar merambat ke beberapa POP, RFO tidak bisa disusun dari log satu router. Syslog router Jakarta, switch agregasi Bandung, dan BRAS Surabaya ditarik ke satu collector, lalu engineer menyamakan dulu tiga hal sebelum membaca urutan: timezone tiap perangkat (ada yang dikonfigurasi UTC, ada yang WIB), selisih NTP (perangkat yang NTP-nya mati bisa meleset satu menit), dan penamaan (satu vendor menulis `Gi0/1`, vendor lain `GigabitEthernet0/1`). Baru setelah itu link down di satu sisi bisa dicocokkan dengan BFD down di sisi lain, dan kuncinya bukan hanya waktu, tetapi circuit ID atau alamat interface yang sama di kedua log. Batas analoginya: di jaringan, topologi fisik memberi tahu perangkat mana yang mungkin saling memengaruhi; di insiden, sebaran mengikuti kredensial dan pilihan penyerang, sehingga host yang tidak punya data sama sekali bisa tetap berada di tengah rantai, dan "tidak ada baris" di wadah bersama sering berarti sumbernya tidak pernah dimasukkan.

```
SUMBER PER HOST DAN DI LUAR HOST (bukti dan ekspor yang tersimpan)
  image disk (Plaso) | memori (Volatility) | log server (Splunk) | firewall | proxy
        |
        v
SERAGAMKAN DULU          zona waktu -> UTC, zona asal dicatat per sumber
                         jam host: selisih terukur per sumber, timestamp asli TIDAK digeser
                         nama host dan akun: satu ejaan, di SETIAP baris
                         skema: message | datetime | timestamp_desc + field penghubung
        |
        v
SATU SKETCH PER KASUS    timeline per host per sumber, nama baku, kosakata tag disepakati
        |
        v
PIVOT DARI JANGKAR       jendela waktu -> identitas -> artefak -> jaringan -> jangkar baru
        |                analyzer Sigma = titik awal pemeriksaan, bukan temuan
        v
CERITA YANG BISA DITELUSURI
  tiap baris: waktu | host | sumber | kejadian | BUKTI PENGHUBUNG | keyakinan
  + celah (host tanpa data, sumber yang lewat retensi) + lampiran daftar timeline dan zona asal
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan dan data pribadi sekitar 400 ribu pelanggan broadband. Kasusnya `INC-2026-017`, ransomware SEV-1 Oktober 2026 yang sudah ditutup. Ringkasnya: akses awal Rabu 2026-10-07 sekitar 03:10 WIB lewat kerentanan pada server aplikasi lama yang menghadap internet `jkt-dmz-app01` (`10.20.9.20`, tanpa EDR), beacon ke `sync-win.example.net` (`203.0.113.205:443`), dump kredensial dan pemakaian ulang local admin; Kamis 2026-10-08 pukul 12:08 PsExec dari server itu ke workstation Keuangan `JKT-WS-0441` (`siti.rahayu`, `10.10.44.41`), persistence di sana pukul 14:24, lalu pukul 19:02 RDP dengan akun domain `budi.santoso` ke `JKT-WS-0457` (`10.10.45.57`), yang diberi service `WinHlpSvc` dan WMI subscription untuk payload `hlpsvc.exe` pukul 19:11. Jumat 2026-10-09 terjadi exfil sekitar 6 GB dari `JKT-WS-0457` ke `198.51.100.205` pukul 18:40 sampai 20:10, tamper antivirus pukul 20:52, penghapusan shadow copy di `JKT-WS-0441` pukul 21:05, lalu enkripsi 5.231 berkas di share `Keuangan` pada file server `JKT-FS01` (`10.20.10.21`) dari `10.10.45.57` pukul 21:31:58 sampai 22:17:04. Kedua workstation diisolasi tanpa dimatikan, memori dan paket investigasi diambil Sabtu, image disk Senin 2026-10-12. Analisis per host sudah selesai: disk kedua workstation (Day 11) dan memori `JKT-WS-0457` (Day 16), dengan satu pertanyaan yang tetap terbuka: proses mana yang mengirim data exfil.

Januari 2027, rencana kapabilitas forensik PT JAB memasukkan pilot Timesketch di jaringan manajemen dengan akses terbatas dan tinjauan DPO (Day 20 bagian 1.13, rencana nomor 8). Pilot berjalan sejak Senin 2027-03-01 di server baru `jkt-tsketch01`, dan uji penerimaan pertamanya (impor ulang `.plaso` laptop `JKT-WS-0412` dari Day 13 dengan angka corong tagging yang sama) lulus Jumat 2027-03-05. Kamis 2027-03-18 pukul 09:00, Dimas Prasetyo (SOC lead) menulis kepadamu di kanal `#soc-forensik`:

> "Pilot Timesketch sudah lolos uji satu host. Sebelum review pilot Rabu 31 Maret, aku mau tahu apakah ini benar-benar mengubah cara kita kerja di insiden banyak host. Tolong bangun ulang 017 sebagai satu timeline bersama: dua workstation dari image E05 dan E06, memori 0457, log `JKT-FS01`, firewall dan proxy dari ekspor Splunk, dan server DMZ kalau datanya ada. Ajak retainer sekalian, Senin mereka bisa satu sesi. Yang mau kubawa ke review: apakah urutan antar host tetap konsisten setelah zona waktu dan jam tiap sumber disamakan, bisakah kita pivot dari satu IOC atau akun dan menemukan host yang dulu terlewat, apakah pertanyaan proses exfil yang masih terbuka bisa dipersempit, dan apakah cara kerja ini siap dipakai untuk insiden berikutnya. Kirim Rabu 24 Maret sore."

Pesan itu memuat enam pertanyaan:

1. Sumber apa yang ada untuk tiap host, dan host atau sumber mana yang tidak punya data?
2. Apakah urutan kejadian antar host konsisten setelah zona waktu dan jam tiap sumber disamakan?
3. Bagaimana data dari alat yang berbeda disiapkan dan dinamai supaya bisa digabung dan tetap bisa ditelusuri ke bukti asalnya?
4. Bisakah pivot dari satu IOC atau satu akun menemukan host yang dulu terlewat?
5. Bisakah pertanyaan terbuka tentang proses exfil dipersempit, dan dengan keyakinan berapa?
6. Apakah cara kerja ini (analyzer, otomasi, kerja bersama retainer, cerita yang bisa ditelusuri) siap dipakai untuk insiden berikutnya, dan dengan syarat apa?

Pertanyaan 1 dijawab di bagian 1.1 dan 1.2, pertanyaan 2 di bagian 1.1, pertanyaan 3 di bagian 1.3 dan 1.4, pertanyaan 4 di bagian 1.6, pertanyaan 5 di bagian 1.6 dan 1.8, dan pertanyaan 6 di bagian 1.5, 1.7, dan 1.8. Bagian 2 berisi persiapan data, impor, kalibrasi, pivot, analyzer, dan jawaban tertulis yang kamu kirim ke Dimas.

**Kapan relevan:** saat insiden melibatkan lebih dari satu host atau lebih dari satu jenis sumber (image, memori, log server, firewall, proxy), saat pertanyaannya tentang urutan dan arah pergerakan, saat lebih dari satu analyst atau pihak luar bekerja di data yang sama, dan saat cerita akhir harus bisa diperiksa ulang orang lain.
**Kapan bukan jawaban:** Day ini tidak menggantikan analisis per host (artefak tetap dibaca dengan aturan Day 05 sampai Day 25), bukan alat scoping ke seluruh fleet (itu hunt Velociraptor atau Defender, Day 04), tidak bisa memunculkan data dari host yang tidak pernah dikoleksi atau log yang sudah lewat retensi, dan bukan tempat menaruh data pribadi tanpa minimisasi dan izin DPO.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (super-timeline, `.plaso`, `timestamp_desc`, event filter, tagging, sketch, view, story, analyzer, garis waktu kurasi, zona waktu dan jam host, Logon ID, 4624, 4648, 5145, netscan, beacon, pivot dari IOC, scope, skala keyakinan) tidak diulang. Tabel berikut hanya memuat istilah baru Day ini; kolom padanan memakai analogi NOC dan SOC yang sama di semua Day.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Korelasi lintas host | Menautkan baris dari host atau sumber berbeda menjadi satu kejadian atau satu urutan | Mencocokkan link down di router A dengan BFD down di router B saat menyusun RFO |
| Bukti penghubung | Nilai yang sama di dua baris dari sumber berbeda (IP sumber dan tujuan, akun, nama share, hash, port) sehingga tautannya tidak hanya bergantung pada kedekatan waktu | Circuit ID atau alamat interface yang sama di log kedua ujung link |
| Jangkar | Satu event yang waktunya pasti dan maknanya yakin, dipakai sebagai titik awal pencarian ke sekitar dan ke host lain | Alarm pertama yang sudah diverifikasi, tempat engineer mulai menelusuri log perangkat sekitar |
| Kalibrasi lintas sumber | Mengukur selisih jam antar sumber dari pasangan kejadian yang sama di dua sisi, lalu memakai selisih itu sebagai toleransi saat membandingkan | Membandingkan timestamp syslog satu paket di kedua ujung link untuk mengukur selisih NTP |
| Skema timeline bersama | Kesepakatan field minimum yang wajib ada di setiap baris semua timeline: tiga field wajib Timesketch plus field host dan field penghubung | Format syslog standar yang disepakati sebelum perangkat baru boleh masuk collector |
| Kosakata tag | Daftar label tetap yang disepakati sebelum analisis, dipakai semua orang di sketch yang sama | Kode penyebab gangguan baku di tiket NOC |
| Analyzer Sigma | Analyzer Timesketch yang mengubah rule Sigma menjadi query, lalu menandai event yang cocok dengan nama rule dan tag ATT&CK-nya | Aturan korelasi alarm otomatis di NMS yang memberi label pada event cocok |
| Orkestrasi pemrosesan | Merangkai langkah pengumpulan, pemrosesan, dan impor menjadi alur yang sama untuk setiap host (misalnya dfTimewolf) | Skrip provisioning yang sama untuk semua perangkat baru |

### 1.1 Tiga masalah yang muncul saat host bertambah

Pertanyaan pertama dan kedua Dimas menyentuh masalah yang tidak terasa saat hanya satu host dianalisis. Di Day 13, laptop `JKT-WS-0412` punya satu jam, satu zona, dan satu nama; semua artefaknya ditulis mesin yang sama, sehingga urutannya di dalam laptop tidak dipengaruhi selisih jam. Begitu enam sumber dari empat mesin dan dua perangkat jaringan masuk ke satu wadah, tiga hal itu tidak lagi bisa dianggap sama.

Tabel berikut adalah daftar masalahnya; baca kolom "Penangkal", karena itu yang dikerjakan sebelum data masuk, bukan setelah hasilnya terlihat janggal.

| Masalah | Akibat bila diabaikan | Penangkal |
|---|---|---|
| Zona waktu berbeda per sumber | Urutan antar host salah, dan kesimpulan ikut salah | Semua dikonversi ke UTC, zona asal dicatat per sumber (Day 13 bagian 1.3) |
| Jam sumber berbeda | Dua kejadian yang berurutan tampak terbalik bila selisihnya lebih besar dari jarak keduanya | Selisih diukur per pasangan sumber dari kejadian yang sama di kedua sisi; timestamp asli tidak digeser |
| Identitas ditulis berbeda | Satu orang atau satu host terlihat seperti beberapa | Normalisasi nama akun dan host di satu tempat, saat konversi (bagian 1.3 dan 2.2) |
| Asal event tidak jelas | Tidak bisa menjawab event ini dari mesin mana | Nama timeline yang disiplin dan field host yang konsisten di setiap baris (bagian 1.4) |

Masalah terakhir yang paling sering diremehkan. Begitu lima timeline masuk ke satu wadah, field yang menyebut host asal menjadi field terpenting, dan ia harus ada di setiap baris, bukan hanya tersirat dari nama berkasnya.

**Zona waktu.** Masalahnya tidak hanya di image Windows. Event log, `$MFT`, dan registry menyimpan UTC; Volatility menulis UTC; tetapi ekspor dari SIEM mengikuti cara ekspor dibuat. Search Splunk yang mengekspor `_time` apa adanya membawa offset zona, sedangkan search yang memformat waktu dengan `strftime` tanpa `%z` menulis jam dinding di zona pengguna yang mengekspor, tanpa label. Baris seperti itu tidak salah, tetapi tidak bisa ditafsirkan tanpa tahu siapa yang mengekspor dan dengan zona apa. Aturannya sama dengan Day 13: zona asal setiap sumber ditulis di daftar timeline, dan konversi ke UTC dilakukan di skrip, bukan ditebak saat membaca.

**Jam sumber.** Zona yang benar tidak memperbaiki jam yang meleset. Di satu host, selisih jam tidak mengubah urutan karena semua artefak ditulis jam yang sama. Antar host, selisih itu langsung masuk ke urutan. Cara mengukurnya adalah mencari kejadian yang tercatat di dua sisi: koneksi yang dicatat firewall dan logon yang dicatat host tujuan, kredensial eksplisit di host sumber dan logon di server, sisa koneksi di memori dan baris firewall untuk sesi yang sama. Selisih per pasangan itu menjadi toleransi saat membandingkan. Host domain PT JAB menyetel jam ke domain controller lewat W32Time (`NT5DS`, Day 09 bagian 1.3), sehingga selisih antar workstation dan server biasanya di bawah satu detik; perangkat jaringan menyetel ke `jkt-ntp01`. Itu harapan, bukan bukti: kalibrasi di bagian 2.4 yang membuktikannya untuk kasus ini.

**Identitas.** Tiga bentuk akun yang sama muncul di sumber berbeda: `JAB\budi.santoso` di event Windows, `budi.santoso` di proxy, `BUDI.SANTOSO` di ekspor lain. Nama host juga: `JKT-WS-0457` di inventaris, `JKT-WS-0457.corp.jab.example` di record event log, `jkt-ws-0457` di log lain, dan `10.10.45.57` di firewall. Normalisasi dilakukan sekali, di skrip konversi: akun huruf kecil tanpa domain di field `user`, domain di field terpisah bila perlu; host dengan ejaan inventaris di field host, alamat IP di field `src_ip` dan `dest_ip`. Satu hal tidak bisa dinormalisasi: Logon ID dan PID. Keduanya hanya unik di dalam satu host (Day 05 bagian 1.2), sehingga dua baris dari host berbeda dengan Logon ID sama tidak berarti apa-apa. Penghubung antar host adalah pasangan yang tercatat di kedua sisi, misalnya 4648 di host sumber yang menyebut server tujuan dan akun (Day 11 bagian 1.3), lalu 4624 type 3 di server dengan akun yang sama dan alamat sumber host itu.

**Host tanpa data.** Pertanyaan pertama Dimas juga meminta daftar yang tidak ada. Host di tengah rantai yang tidak pernah dikoleksi tetap muncul di wadah bersama, tetapi hanya sebagai alamat IP di log host lain dan perangkat jaringan. Bagi pembaca timeline, host seperti itu mudah terlupakan karena tidak punya timeline sendiri. Karena itu daftar timeline di lampiran cerita (bagian 1.8) memuat juga baris "tidak ada data" untuk host yang relevan, dengan alasannya.

### 1.2 Wadah bersama dan isinya

Pertanyaan keenam Dimas menyangkut kerja bersama: dua analyst internal, analyst retainer, dan nanti on-call baru. Timesketch menyusun pekerjaan dalam sketch, yaitu wadah tingkat atas yang biasanya mewakili satu kasus, dan tiap sketch memuat beberapa timeline serta view [S1]. Timeline adalah kumpulan data yang ditambahkan ke sketch, bisa diunggah lewat antarmuka web, diimpor dari berkas CSV atau JSON dan JSONL, atau dikirim lewat API [S1]. Semua data di Timesketch disimpan di OpenSearch [S1].

Yang membuatnya berguna untuk kerja bersama adalah lapisan anotasi di atas datanya [S1]:

- **Tag** disimpan di field `tag` pada event, bisa ditambahkan lewat API, klien baris perintah, atau antarmuka web, dan sumber data seperti Plaso juga bisa menambahkannya saat pemrosesan.
- **Bintang** ditandai dari daftar event, bisa difilter, dan bisa dimasukkan ke story.
- **Komentar** disimpan per sketch. Ini detail penting: bila timeline yang sama ditambahkan ke dua sketch, komentar di satu sketch tidak muncul di sketch lain [S1].
- **View** adalah kueri pencarian yang disimpan, dibuat lewat antarmuka, API, atau oleh analyzer.
- **Agregasi** meringkas event sketch (misalnya terms per field) dan hasilnya bisa disimpan ke story [S1].
- **Story** adalah dokumen untuk menulis hasil investigasi, bisa memuat view, agregasi, dan teks markdown; untuk mengekspornya, seluruh sketch diekspor dan arsip zip-nya memuat setiap story [S1].

Label adalah mekanisme lama yang menyimpan penanda di basis data, bukan di OpenSearch, dan sedang ditinggalkan dari antarmuka [S1]. Pakai tag.

Dua konsekuensi untuk kerja bersama. Pertama, satu kasus harus benar-benar satu sketch: analyst yang menyalin timeline ke sketch pribadinya untuk "coba-coba" akan menulis komentar yang tidak pernah dilihat orang lain. Kedua, wadah bersama menyimpan data, jadi aksesnya adalah keputusan tata kelola, bukan hanya teknis. Timeline workstation memuat nama dokumen kerja karyawan, jam kerja, dan riwayat penelusuran; log proxy memuat situs yang dibuka orang. Pilot PT JAB karena itu berjalan dengan syarat yang ditinjau DPO Agus Setiawan sebelum data kasus pertama masuk (bagian 2.1): data diminimalkan ke jendela dan host yang relevan, akun per orang, dan retensi sketch yang tertulis. Mulai rilis 20261014, Timesketch juga mendukung kontrol akses berbasis grup dan peran lewat OIDC [S8]; pilot PT JAB belum memakainya dan masih memakai akun lokal per orang.

### 1.3 Skema minimum agar sumber apa pun bisa masuk

Pertanyaan ketiga Dimas dijawab dengan kesepakatan format, karena kesepakatan itu yang membuat keluaran Plaso, Volatility, dan ekspor Splunk bisa disatukan. Impor CSV atau JSONL mewajibkan tiga field [S2]:

| Field | Isi | Catatan |
|---|---|---|
| `message` | Deskripsi event yang informatif | Ini yang dibaca manusia di daftar event |
| `datetime` | Waktu event dalam format ISO 8601 | Contoh resminya memuat offset UTC, misalnya `2015-07-24T19:01:01+00:00` [S2] |
| `timestamp_desc` | Jenis timestamp, misalnya waktu berkas dibuat | Menjelaskan arti waktunya |

Tanpa ketiganya Timesketch tidak bisa menampilkan event di antarmuka [S2]. Bila salah satu tidak ada, pemetaan header di antarmuka bisa memetakan kolom yang ada ke field wajib, membuat kolom baru dengan nilai bawaan, atau menggabungkan beberapa kolom menjadi satu [S2]. Kolom tambahan bebas jumlahnya dan tetap disimpan [S2]. Nama berkas harus berakhiran `.csv` atau `.jsonl`, baris pertama CSV adalah header, dan JSONL bisa dialirkan dari disk sehingga jauh lebih hemat memori daripada JSON biasa [S2].

Satu batas teknis yang perlu diketahui: nilai yang lebih besar dari 32766 byte tetap diindeks sebagai teks dan bisa dicari secara penuh, tetapi tidak punya sub-field keyword dan wildcard, sehingga tidak bisa dipakai di grafik, agregasi, atau pengurutan, dan kueri keyword atau wildcard tidak akan cocok dengannya [S2]. Ini mengenai field seperti command line atau blok skrip yang sangat panjang, jadi pertimbangkan memotongnya ke field terpisah bila kamu butuh mengagregasinya.

`timestamp_desc` adalah field yang paling sering diisi asal-asalan dan paling disesali kemudian. Isi dengan arti waktunya yang sebenarnya, misalnya waktu koneksi dibuat, waktu sesi firewall dimulai, waktu event dicatat server, karena satu baris tanpa arti waktu tidak bisa ditafsirkan. Di gabungan multi-host, arti waktu juga membedakan kejadian dari pengamatan: `Created` di netscan adalah waktu objek koneksi dibuat di memori host, waktu sesi di firewall adalah saat perangkat jaringan melihat paket pertama, dan waktu event 5145 adalah saat file server memeriksa akses.

Di atas tiga field wajib, PT JAB menetapkan field minimum tambahan untuk semua timeline buatan sendiri:

| Field | Isi | Kenapa wajib |
|---|---|---|
| `hostname` | Nama host asal baris, ejaan inventaris (`JKT-WS-0457`); untuk perangkat jaringan nama perangkatnya | Menjawab "dari mesin mana" tanpa melihat nama timeline; nama field sama dengan field Plaso 20260720 [S8] |
| `source_tool` | Alat atau sistem yang menulis baris (`splunk-firewall`, `vol3-netscan`) | Membedakan dua sumber dari host yang sama |
| `evidence_id` | Nomor bukti asal (`INC-2026-017-E07`) | Jalan kembali ke master dan hash |
| `src_ip`, `dest_ip`, `dest_port` | Alamat dan port, bila ada | Bukti penghubung jaringan |
| `user` | Akun, huruf kecil, tanpa domain | Bukti penghubung identitas |
| `tz_source` | Zona asal waktu sebelum dikonversi (`UTC`, `Asia/Jakarta`) | Membuktikan konversi bisa diperiksa ulang |

Nama `hostname` dipilih karena Plaso 20260720 mengganti `computer_name` menjadi `hostname` dan `body` menjadi `message_body`; analyzer bawaan Timesketch 20261014 mendukung kedua nama, tetapi view dan query buatan sendiri perlu diperbarui [S8]. Dengan nama field yang sama, satu query `hostname:` bekerja di timeline Plaso dan timeline buatan sendiri. Isi `hostname` di baris Plaso berasal dari sumbernya: untuk event log adalah nama komputer di record, yang biasanya FQDN; baris dari sumber lain bisa kosong. Cek isinya di versi-mu, lalu pakai wildcard (`hostname:JKT-WS-0457*`) dan jaga aturan satu timeline Plaso hanya untuk satu host.

### 1.4 Konvensi penamaan yang membuat kasus bisa dibaca

Pertanyaan ketiga Dimas juga menyangkut penamaan. Tetapkan sebelum data pertama masuk, karena mengubahnya setelah sepuluh timeline masuk jauh lebih mahal. Polanya sederhana: siapa, dari alat apa dan bukti mana, rentang kapan.

```
<host>_<sumber>-<bukti>_<rentang YYYYMMDD-YYYYMMDD>
JKT-WS-0441_plaso-E06W1_20261007-20261010
JKT-WS-0457_plaso-E05W1_20261007-20261010
JKT-WS-0457_vol-netscan-E01_20261010
JKT-FS01_splunk-wineventlog-E07_20261007-20261010
fw-perimeter_splunk-E07_20261007-20261010
proxy_splunk-E07_20261007-20261010
```

Garis bawah memisahkan tiga bagian, karena nama host PT JAB sendiri mengandung tanda hubung; dengan pemisah tanda hubung, `JKT-WS-0441-plaso` tidak bisa dipecah kembali dengan andal oleh skrip. Tiga aturan menyertainya. Nama host ditulis sama persis di nama timeline dan di field `hostname`, termasuk huruf besar kecilnya. Setiap baris punya field yang menyebut host, bukan hanya nama timeline-nya. Sumber yang bukan milik satu host, seperti firewall perimeter, proxy, dan log identitas, diberi nama perangkat atau layanan yang jelas bukan nama host, supaya tidak tertukar. Bila timeline diimpor ulang karena perbaikan, tambahkan akhiran versi (`_v2`) dan beri alasan di deskripsi timeline; timeline lama dihapus dari sketch setelah semua tag dan komentarnya dipindah, bukan dibiarkan berdampingan.

Kosakata tag ditetapkan bersamaan dengan penamaan. PT JAB memakai dua lapis: tag isi (`jangkar`, `akses-awal`, `lateral`, `persistensi`, `c2`, `exfil`, `enkripsi`, `responder`, `rutin`, `perlu-dicek`) dan tag status (`diperiksa`, ditambahkan manusia setelah baris dibaca dan dinilai). Tag `responder` wajib untuk setiap jejak tim sendiri (akun `ir-admin`, driver WinPmem, koleksi), seperti aturan pemisahan di Day 07 dan Day 11. Kosakata yang disepakati adalah yang membuat dua orang bisa bekerja di sketch yang sama tanpa saling mengacaukan; tag yang ditulis bebas (`exfil`, `Exfil`, `exfiltrasi`) memecah satu pencarian menjadi tiga.

### 1.5 Analyzer dan Sigma

Pertanyaan keenam Dimas menanyakan apakah analyzer menghemat kerja. Analyzer adalah komponen Python yang memperkaya data timeline di latar belakang, bisa menandai event dengan tag, memberi bintang, membuat view, dan sebagian menghasilkan story [S1]. Contoh yang disebut dokumentasi: analyzer Sigma, analyzer domain yang mengambil informasi domain dan TLD dari event dengan field `url` atau `domain`, dan analyzer chain yang menautkan event berkaitan seperti unduhan browser yang diikuti eksekusi berkas itu [S1].

Sigma adalah format rule deteksi generik berbasis YAML. Satu rule memuat bagian `logsource` (jenis log, misalnya `product: windows` dan `category: process_creation`), bagian `detection` yang berisi kumpulan kondisi atas nama field (misalnya `ParentImage|endswith: '\WINWORD.EXE'` dan `Image|endswith: '\mshta.exe'`) serta ekspresi `condition` yang menggabungkannya, lalu metadata seperti `level`, `status`, dan tag ATT&CK [S7]. Karena rule ditulis atas nama field, bukan sintaks satu produk, rule yang sama bisa dipakai di SIEM dan di Timesketch. Nilai praktisnya: rule yang dipakai tim deteksi bisa dipakai kembali untuk menandai event di timeline, sehingga pekerjaan deteksi dan forensik memakai sumber logika yang sama.

Cara kerjanya di Timesketch perlu diketahui sebelum hasilnya dipercaya [S3]:

- Rule disimpan di basis data Timesketch, bukan di folder. Timesketch sengaja tidak membawa kumpulan rule; rule disalin dari repositori komunitas atau dibuat sendiri, lewat Studio di antarmuka, tab Sigma di sketch, atau impor massal dengan `tsctl import-sigma-rules` dari CLI admin.
- Analyzer Sigma hanya mengambil rule berstatus `stable`. Rule `experimental`, `deprecated`, dan status lain tidak dijalankan, dan rule yang bermasalah disarankan diberi status `deprecated`.
- Setiap rule diubah menjadi query OpenSearch. Event yang cocok diberi field `ts_sigma_rule` berisi judul rule dan `ts_ttp` berisi tag ATT&CK dari rule; semua hasil dicari dengan `ts_sigma_rule:*`.
- Nama field generik Sigma diterjemahkan ke nama field Timesketch lewat `sigma_config.yaml` (misalnya `EventID` menjadi `event_identifier`); banyak field Windows dipetakan ke `xml_string` karena isi XML EVTX sering tidak valid sebagai XML. Pemetaan yang hilang bisa menghasilkan query yang terlalu lebar.
- Dokumentasi menyebut dukungan Sigma sebagai fungsi alpha dengan masalah kinerja dan fungsi yang sudah diketahui; rule dengan banyak kombinasi `OR` dan `AND` bisa menghasilkan query mahal yang timeout, dan terlalu banyak rule `stable` bisa membuat analyzer berjalan berjam-jam dan menahan analyzer lain. Jeda antar query diatur dengan `SIGMA_TAG_DELAY` di `timesketch.conf`.

Dua catatan yang perlu dijaga. Pertama, analyzer menandai, bukan menyimpulkan; tag dari analyzer adalah titik awal pemeriksaan, bukan temuan, dan analyzer tidak tahu mana jejak responder. Kedua, cakupan rule yang benar-benar bekerja bergantung pada apakah field di timeline-mu cocok dengan field yang diasumsikan rule dan pemetaan, dan itu jarang cocok sempurna di data gabungan dari banyak sumber. Periksa berapa rule yang benar-benar jalan, bukan berapa yang dimuat. Tiga angka yang dicatat setiap kali analyzer dijalankan: berapa rule `stable` yang dijalankan, berapa yang menghasilkan tag, dan berapa yang tidak mungkin cocok karena field yang dipakainya tidak ada di sketch ini. Angka ketiga adalah daftar perbaikan skema konversi untuk kasus berikutnya; rule yang nol hasil dengan field yang tersedia adalah hasil negatif yang hanya sekuat rule itu.

### 1.6 Urutan pivot lintas host

Pertanyaan keempat dan kelima Dimas adalah pertanyaan pivot. Pencarian acak di timeline besar menghabiskan waktu tanpa hasil. Urutan yang bekerja berangkat dari satu titik pasti lalu melebar:

1. **Tetapkan satu jangkar.** Satu event yang kamu yakini benar dan tahu waktunya, misalnya sesi pertama ke IP exfil di firewall atau logon PsExec di host tujuan.
2. **Sempitkan jendela.** Lihat beberapa menit sebelum dan sesudah jangkar, di semua timeline sekaligus, dengan toleransi jam dari kalibrasi. Sebagian besar cerita insiden terbaca di sini.
3. **Pivot lewat identitas.** Akun yang sama di host lain (4624 dan 4648, Day 05 dan Day 11), lalu di log server dan proxy. Pisahkan pemakaian sah pemilik akun dari pemakaian penyerang dengan konteks: jam, host sumber, dan proses.
4. **Pivot lewat artefak.** Hash, nama berkas, named pipe, atau nama service yang sama di host lain.
5. **Pivot lewat jaringan.** Alamat dan nama domain yang sama, dari sisi endpoint, memori, dan log jaringan.
6. **Tetapkan jangkar baru** di host berikutnya, lalu ulangi.

Setiap kali menemukan sesuatu, beri tag dengan kosakata yang disepakati (bagian 1.4).

Dua batas menentukan arti hasil pivot. Pertama, pivot hanya melihat sumber yang ada di sketch. Pivot IP C2 di log firewall menemukan semua host yang lewat firewall ke IP itu, tetapi hanya bila ekspor firewall disaring berdasarkan tujuan, bukan berdasarkan host yang sudah dicurigai. Lalu lintas antar workstation di VLAN yang sama tidak lewat firewall perimeter sama sekali. Karena itu hasil "tidak ada host lain" selalu ditulis bersama filter ekspor dan jalur yang tidak terlihat. Kedua, pivot dari IOC atomik (IP, domain, hash) lemah terhadap penyerang yang menggantinya; pivot dari perilaku (pola beacon, service baru di `C:\ProgramData`, kredensial eksplisit dari service ke file server) lebih tahan lama, tetapi butuh sumber yang mencatat perilaku itu di host lain. Untuk menyapu seluruh fleet, alatnya adalah hunt (Day 04), bukan sketch; sketch hanya memeriksa ulang sumber yang sempat dikumpulkan.

Mempersempit pertanyaan yang tetap terbuka, seperti proses pengirim exfil, memakai urutan yang sama dengan satu tambahan: tulis dulu apa yang harus benar bila sebuah kandidat adalah jawabannya, lalu cari baris yang mendukung atau membantah setiap syarat itu di semua sumber. Satu kandidat yang hanya "satu-satunya proses mencurigakan yang terlihat" adalah tebakan (Day 16 bagian 2.8); kandidat yang dihubungkan oleh beberapa bukti penghubung independen dan tidak dibantah sumber mana pun adalah tafsiran berkeyakinan sedang. Kalimat akhirnya memakai skala keyakinan laporan (Day 19 bagian 1.4), dan "tidak dapat ditentukan" tetap hasil yang sah.

### 1.7 Otomasi pengumpulan dan pemrosesan

Pertanyaan keenam Dimas juga menanyakan apakah cara kerja ini bisa diulang di insiden berikutnya, dengan host yang lebih banyak dan waktu yang lebih sempit. Untuk kasus dengan banyak host, langkah dari bukti mentah sampai timeline siap analisis sebaiknya tidak dikerjakan manual berulang kali. dfTimewolf adalah kerangka orkestrasi pengumpulan, pemrosesan, dan ekspor data forensik: modul collector, processor, dan exporter saling meneruskan data, dan "recipe" yang sudah ditetapkan mengatur urutannya [S4]. Recipe dijalankan dengan nama dan argumennya, misalnya `dftimewolf local_plaso <path1>,<path2> --incident_id <nomor>`, dengan `--incident_id` dipakai Timesketch sebagai deskripsi sketch; `dftimewolf -h` menampilkan semua recipe dan `dftimewolf <recipe> -h` opsi satu recipe [S11]. Recipe yang disebut di panduan itu mencakup pemrosesan lokal dengan Plaso dan beberapa alur cloud (AWS, GCP) yang berakhir di Timesketch; modul lain seperti log2timeline dipasang terpisah [S11]. Repositori proyek masih aktif (commit terakhir 2026-10-20) tetapi tidak menerbitkan rilis bertag [S4][S12], sehingga versi yang dipakai harus dicatat sebagai commit, bukan nomor rilis.

Nilainya bukan kecepatan, melainkan keseragaman. Sepuluh host yang diproses dengan alur yang sama menghasilkan timeline yang bentuknya sama, dan itu syarat agar penggabungan di bagian 1.4 benar-benar bekerja. Keseragaman juga punya sisi buruk: kesalahan di satu langkah (zona waktu, filter ekspor) terulang di semua host tanpa terlihat. Karena itu alur otomatis tetap diuji dengan satu host yang jawabannya sudah diketahui sebelum dipakai di kasus, sama seperti uji alat pada data yang diketahui di Day 02. Periksa recipe dan modul yang didukung commit yang kamu pasang, karena daftarnya berubah.

Untuk PT JAB, pilihannya ditentukan dua hal: data berasal dari sumber yang beragam (image di `jkt-evid01`, ekspor Splunk, keluaran Volatility) dan sebagian besar bukan cloud. Keputusan pilot (bagian 2.9): alur dibakukan sebagai skrip konversi dan perintah impor di repositori `jab-ir-tools`, dengan versi alat dibekukan per kasus; dfTimewolf dicoba di lab (bagian 3) dan dinilai ulang saat jumlah host per kasus membuat skrip manual tidak lagi praktis.

### 1.8 Menulis cerita yang bisa ditelusuri

Pertanyaan kelima dan keenam Dimas berujung pada bentuk akhir: cerita yang bisa dibaca peserta review dan diperiksa ulang retainer. Story di Timesketch memuat view, agregasi, dan teks markdown, dan ikut terekspor bersama sketch [S1]. Susun dengan pola tetap:

```
1. Ringkasan satu paragraf: apa yang terjadi, kapan, di host mana
2. Garis waktu ringkas: tabel kejadian utama, waktu UTC dan WIB, host, sumber
3. Tiap kejadian merujuk ke view yang menghasilkannya, dan tiap tautan antar host menyebut bukti penghubungnya
4. Celah: apa yang tidak bisa dijawab dan kenapa (host tanpa data, sumber lewat retensi, jalur yang tidak terlihat)
5. Lampiran: daftar timeline beserta sumber, bukti, rentang, zona asal, dan selisih jam terukur
```

Bagian kelima yang paling sering dilupakan dan paling sering dibutuhkan saat seseorang memeriksa ulang pekerjaanmu. Tanpa daftar itu, tidak ada yang bisa mengetahui apakah sebuah kekosongan berarti tidak terjadi apa-apa atau berarti datanya memang tidak pernah dikumpulkan.

Bentuk tabel yang dibawa ke laporan (Day 19 bagian 1.6) menambah satu kolom yang tidak ada di garis waktu satu host: bukti penghubung. Setiap baris menyebut apa yang menghubungkannya ke baris lain. Baris tanpa bukti penghubung berarti kamu sedang menduga dari kedekatan waktu, dan itu harus ditulis sebagai dugaan dengan keyakinan yang sesuai. Kedekatan waktu sendiri hanya kuat bila jendelanya sempit dibanding kepadatan kejadian lain di jendela itu: dua kejadian dalam satu detik di jam sepi bermakna, dua kejadian dalam satu menit di jam kerja hampir tidak.

Satu aturan lagi khusus untuk kerja bersama: kesimpulan yang berubah ditulis sebagai perubahan, bukan ditimpa. Bila cerita baru mengubah status jawaban lama (misalnya dari "tidak dapat dipastikan" menjadi "kandidat berkeyakinan sedang"), tulis status lama, status baru, dan bukti yang menggesernya, supaya laporan kasus yang sudah terbit bisa diberi catatan revisi dengan dasar yang jelas (Day 19 bagian 1.10).

## 2. Contoh dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi; angka di keluaran dihitung agar konsisten antar tabel dan dengan Day 11 dan Day 16. Plaso dan skrip konversi dijalankan di `jkt-dfir02` (Ubuntu LTS) atas salinan kerja dan ekspor yang hash-nya sudah dicocokkan dengan master di `jkt-evid01`; Timesketch berjalan di `jkt-tsketch01`. Narasi memakai WIB (UTC+7). Timesketch menyimpan waktu dalam UTC; setiap keluaran diberi label zona waktunya, dan tabel kalibrasi memakai UTC supaya selisih antar sumber terbaca langsung. Nama kolom dan opsi alat dicocokkan dengan versi di lab-mu.

### 2.1 Inventaris sumber, wadah pilot, dan syarat DPO

Langkah ini menjawab pertanyaan pertama Dimas: apa yang ada, apa yang tidak, dan di wadah apa data itu boleh ditaruh.

Wadah pilot sudah disiapkan sebelum pesan Dimas. Tabel berikut adalah catatan konfigurasinya, dibuat Senin 2027-03-01 saat server dipasang; baca kolom "Kenapa", karena setiap baris adalah keputusan tata kelola yang akan ditanyakan di review.

| Hal | Nilai di pilot | Kenapa |
|---|---|---|
| Server | `jkt-tsketch01` (`10.20.1.45`), Ubuntu LTS, jaringan manajemen, tidak join domain | Sama dengan `jkt-evid01` dan `jkt-velo01`: data bukti tidak ditaruh di domain yang bisa diinvestigasi |
| Versi | Timesketch 20261014 (rilis terbaru saat dipasang), worker memakai Plaso 20260720 | Rilis ini menolak `.plaso` dari Plaso yang lebih lama dari 20260720 [S8]; Plaso kasus PT JAB sudah 20260720 (Day 13) |
| Akses jaringan | HTTPS hanya dari `JKT-DFIR01`, `jkt-dfir02`, dan pool VPN vendor ke jaringan manajemen | Retainer bisa bekerja tanpa menyalin data ke luar |
| Akun | Akun lokal per orang: kamu, Sari Kusuma, Yoga Pratama, Rudi Hartanto, satu akun per analyst retainer; tanpa akun bersama | Jejak siapa menambah tag dan komentar; OIDC dan grup belum dipakai |
| Retensi | Sketch pilot dihapus paling lambat 90 hari setelah pilot ditutup; ekspor sketch (zip) disimpan sebagai lampiran kasus di `jkt-evid01` | Timeline memuat data pribadi karyawan; sumber aslinya tetap di `jkt-evid01` |
| Tinjauan DPO | Agus Setiawan, Rabu 2027-03-03: minimisasi jendela dan host, URL proxy dipangkas ke nama host tujuan, tanpa isi email, akses tercatat | Syarat ini berlaku untuk setiap kasus di Timesketch, bukan hanya pilot |
| Uji penerimaan | Jumat 2027-03-05: `.plaso` E16-W1 (Day 13) diimpor ulang, angka corong tagging sama dengan Day 13 | Ukuran selesai rencana nomor 8 di Day 20 |

Bukti yang dipakai untuk rekonstruksi `INC-2026-017` sudah ada sejak Oktober. Tabel berikut mendaftar asal tiap sumber; baca kolom "Zona asal", karena kolom itulah yang menentukan cara konversi di bagian 2.2.

| Bukti | Isi | Diambil | Zona asal |
|---|---|---|---|
| `INC-2026-017-E01` | Memori `JKT-WS-0457` (Day 16); keluaran `windows.netscan` 187 baris | Sabtu 2026-10-10 12:42:05 sampai 12:57:30 | UTC (Volatility) |
| `INC-2026-017-E05` | Image disk `JKT-WS-0457`, salinan kerja `E05-W1` (Day 11) | Senin 2026-10-12 09:00 | Campuran; Plaso menyimpan UTC |
| `INC-2026-017-E06` | Image disk `JKT-WS-0441`, salinan kerja `E06-W1` (Day 11) | Senin 2026-10-12 09:00 | Campuran; Plaso menyimpan UTC |
| `INC-2026-017-E07` | Ekspor CSV hasil search Splunk: `wineventlog` `JKT-FS01` (4624, 4634, 5145), `firewall`, dan `proxy`, rentang Rabu 2026-10-07 00:00 sampai Sabtu 2026-10-10 13:15 WIB | Yoga, Senin 2026-10-12 sekitar 14:00, dengan SHA-256 per berkas | Firewall dan `wineventlog`: ISO 8601 dengan `+07:00`; proxy: jam dinding WIB tanpa offset |

Ekspor E07 adalah alasan pilot ini mungkin dilakukan lima bulan setelah insiden. Index `proxy` di Splunk PT JAB hanya menyimpan 30 hari; data proxy Oktober sudah tidak ada di Splunk sejak November, dan E07 adalah satu-satunya salinannya. Filter search firewall di E07 penting untuk pertanyaan pivot (bagian 2.5): ia mengambil semua baris dengan tujuan `203.0.113.205` atau `198.51.100.205` dari sumber mana pun, ditambah semua baris dari dan ke `10.20.9.20`. Filter proxy hanya mengambil dua alamat workstation, dan filter `wineventlog` hanya event `JKT-FS01` dari tiga alamat kasus.

Tiga hal tidak ada, dan ketiganya ditulis di lampiran cerita:

- **`jkt-dmz-app01` tidak punya data host.** Server itu tidak memakai EDR, tidak mengirim log ke Splunk, dan dibangun ulang dari image bersih setelah isolasi tanpa image atau koleksi triage. Ia hanya terlihat sebagai `10.20.9.20` di log firewall dan di 4624 `JKT-WS-0441`. Apa yang terjadi di dalamnya antara Rabu 03:10 dan Kamis 12:08 (dump kredensial, penemuan jaringan) tidak bisa direkonstruksi dari sketch ini.
- **Memori dan paket investigasi `JKT-WS-0441` (E03, E04)** tidak dimasukkan; tidak ada pertanyaan pilot yang membutuhkannya, dan E03 belum pernah dianalisis dengan netscan.
- **Paket investigasi `JKT-WS-0457` (E02)** tidak diimpor sebagai timeline karena isinya potret satu saat tanpa riwayat; ia dipakai sebagai pembanding di bagian 2.7, sama seperti di Day 16.

**Kapan gagal:** inventaris yang hanya mendaftar apa yang ada membuat pembaca cerita menganggap rantai dimulai di `JKT-WS-0441`, karena host pertama tidak punya satu baris pun di daftar timeline.

### 2.2 Menyiapkan sumber non-Plaso menjadi JSONL

Langkah ini menjawab bagian pertanyaan ketiga Dimas untuk sumber yang tidak dibaca Plaso: ekspor Splunk dan keluaran netscan. Dikerjakan Kamis 2027-03-18 pukul 09:40 sampai 11:30 di `jkt-dfir02`, atas salinan E07 dan `netscan.csv` Day 16 yang hash-nya dicocokkan dulu dengan master.

**Tujuan:** mengubah setiap sumber ke skema bersama (bagian 1.3) dengan konversi zona yang eksplisit, normalisasi identitas di satu tempat, dan field host di setiap baris.

Potongan skrip konversi (`konversi-timeline.py` di repositori `jab-ir-tools`), bagian untuk firewall dan proxy:

```python
import json
import pandas as pd

WIB = "Asia/Jakarta"

def ke_utc(seri, zona_asal):
    t = pd.to_datetime(seri)
    if t.dt.tz is None:                     # jam dinding tanpa offset: zona WAJIB disebut
        t = t.dt.tz_localize(zona_asal)
    return t.dt.tz_convert("UTC")

def tulis_jsonl(df, path):
    with open(path, "w") as f:
        for rec in df.to_dict(orient="records"):
            f.write(json.dumps(rec, default=str) + "\n")

fw = pd.read_csv("E07_firewall.csv")        # _time ISO 8601 dengan +07:00
out = pd.DataFrame({
    "datetime": ke_utc(fw["_time"], WIB).dt.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
    "timestamp_desc": "Firewall session start",
    "message": fw["action"] + " " + fw["src_ip"] + " -> " + fw["dest_ip"] + ":" + fw["dest_port"].astype(str)
               + " out=" + fw["bytes_out"].astype(str) + " in=" + fw["bytes_in"].astype(str),
    "hostname": "fw-perimeter",
    "source_tool": "splunk-firewall",
    "evidence_id": "INC-2026-017-E07",
    "src_ip": fw["src_ip"], "dest_ip": fw["dest_ip"], "dest_port": fw["dest_port"],
    "bytes_out": fw["bytes_out"], "bytes_in": fw["bytes_in"],
    "tz_source": "Asia/Jakarta (offset tertulis)",
})
tulis_jsonl(out, "fw-perimeter_splunk-E07_20261007-20261010.jsonl")

px = pd.read_csv("E07_proxy.csv")           # kolom waktu: jam dinding WIB TANPA offset
out = pd.DataFrame({
    "datetime": ke_utc(px["waktu"], WIB).dt.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
    "timestamp_desc": "Proxy request logged",
    "message": px["method"] + " " + px["dest_host"] + " user=" + px["cs_username"].fillna("-"),
    "hostname": px["src_ip"].map({"10.10.44.41": "JKT-WS-0441", "10.10.45.57": "JKT-WS-0457"}),
    "source_tool": "splunk-proxy",
    "evidence_id": "INC-2026-017-E07",
    "src_ip": px["src_ip"], "dest_ip": px["dest_ip"], "dest_port": px["dest_port"],
    "user": px["cs_username"].str.lower().str.replace(r"^jab\\", "", regex=True),
    "bytes_out": px["bytes_out"],
    "tz_source": "Asia/Jakarta (tanpa offset, ditetapkan dari cara ekspor)",
})
tulis_jsonl(out, "proxy_splunk-E07_20261007-20261010_v2.jsonl")
```

- `ke_utc`: bila waktu sumber sudah membawa offset, ia dikonversi apa adanya; bila tidak, zona asal wajib disebut. Fungsi ini sengaja tidak punya nilai bawaan, supaya sumber tanpa offset tidak diam-diam dianggap UTC.
- Tiga field wajib (`datetime`, `timestamp_desc`, `message`) dibuat eksplisit [S2]; sisanya kolom tambahan yang tetap disimpan [S2].
- `datetime` ditulis ISO 8601 dengan offset `+00:00`, bentuk yang sama dengan contoh dokumentasi [S2].
- `hostname` ada di setiap baris, dengan ejaan inventaris; untuk proxy, alamat sumber dipetakan ke nama host dari daftar aset kasus, bukan dari DNS hari ini.
- `user` dinormalisasi huruf kecil tanpa domain di skrip, bukan nanti saat analisis. Akun mesin (`JKT-WS-0457$`) ikut menjadi huruf kecil dan tetap membawa tanda `$`.
- `message` ringkas dan bisa dibaca; URL lengkap tidak dibawa, hanya nama host tujuan, sesuai syarat DPO.
- Bagian lain skrip mengubah ekspor `wineventlog` `JKT-FS01` (field `Account_Name`, `Source_Address`, `Logon_ID`, `Share_Name`, `Relative_Target_Name`, `Accesses`) dan `netscan.csv` Day 16 (kolom `Created` UTC, `timestamp_desc` "Connection object created (memori)", `hostname` `JKT-WS-0457`) dengan pola yang sama.

Keluaran ilustrasi (satu baris JSONL firewall dan satu baris netscan, dipotong):

```
{"datetime": "2026-10-09T13:08:41+00:00", "timestamp_desc": "Firewall session start", "message": "allow 10.10.45.57 -> 198.51.100.205:443 out=512887210 in=1904331", "hostname": "fw-perimeter", "source_tool": "splunk-firewall", "evidence_id": "INC-2026-017-E07", "src_ip": "10.10.45.57", "dest_ip": "198.51.100.205", ...}
{"datetime": "2026-10-09T13:08:41+00:00", "timestamp_desc": "Connection object created (memori)", "message": "TCPv4 10.10.45.57:51544 -> 198.51.100.205:443 CLOSED owner=N/A", "hostname": "JKT-WS-0457", "source_tool": "vol3-netscan", "evidence_id": "INC-2026-017-E01", ...}
```

**Cara membaca hasil:** dua baris dari dua sumber yang tidak saling tahu (perangkat jaringan dan memori host) jatuh di detik yang sama, dengan alamat dan port tujuan yang sama. Bentuk seperti ini yang disebut bukti penghubung: nilai yang sama di dua sumber independen, bukan hanya waktu.

**Variasi:** ekspor Splunk yang dibuat dengan `| table _time ...` membawa `_time` dalam ISO 8601 dengan offset; ekspor yang memformat waktu dengan `strftime(_time, "%Y-%m-%d %H:%M:%S")` membawa jam dinding di zona pengguna yang mengekspor. Untuk ekspor berikutnya, PT JAB menambahkan `%z` ke format dan mencatat zona akun pengekspor di `evidence-log.csv`.

**Kapan gagal:** ekspor proxy E07 memformat waktu tanpa offset. Versi pertama skrip memperlakukannya dengan `pd.to_datetime(..., utc=True)`, sehingga semua baris proxy bergeser tujuh jam. Gejalanya dan perbaikannya ada di bagian 2.4; nama `_v2` di timeline proxy berasal dari situ.

### 2.3 Plaso untuk dua workstation dan impor ke satu sketch

Langkah ini memproses image kedua workstation dengan alur yang sama dengan Day 13, lalu mengimpor semua timeline ke satu sketch. Plaso dijalankan Kamis 10:05 sampai Jumat 01:55: `E06-W1` lebih dulu (10:05 sampai 17:40), lalu `E05-W1` (17:50 sampai 01:55).

**Tujuan:** dua storage file `.plaso` lengkap per host, lalu hanya jendela kasus yang masuk Timesketch.

```bash
PLASO=log2timeline/plaso@sha256:e4b7...      # digest yang sama dengan Day 13 (20260720)
docker run --rm -v /srv/dfir/work/INC-2026-017:/work:ro -v /srv/dfir/out/INC-2026-017:/out "$PLASO" \
  log2timeline.py --storage-file /out/E06-W1/E06-W1_lengkap.plaso --parsers win7_slow \
  --timezone Asia/Jakarta --partitions all --vss_stores none --unattended \
  --logfile /out/E06-W1/log2timeline.log.gz /work/E06-W1/E06-W1.vhdx
```

- Opsi dan alasannya sama dengan Day 13 bagian 2.3; zona host diambil dari registry `E06-W1` dan `E05-W1` (`SE Asia Standard Time`) sebelum run, dan dicek ulang dengan `pinfo.py -v`.
- Salinan kerja dibaca read-only (`:ro`); output ke folder terpisah, lalu disalin ke `/cases/INC-2026-017/analysis/<bukti>/plaso-20260720/` bersama hash-nya.
- Format VHDX dibaca Plaso lewat lapisan dfVFS; bila build-mu tidak membacanya, `pinfo.py` akan menunjukkan nol event dari partisi sistem, jadi uji dulu dengan run terarah singkat.

Impor ke sketch, Jumat 2027-03-19 pukul 08:30, dengan filter jendela kasus dalam UTC (Rabu 2026-10-07 00:00 WIB sampai Sabtu 2026-10-10 13:15 WIB):

```bash
timesketch_importer.py --sketch-name "INC-2026-017 rekonstruksi pilot" --sketch-strategy oldest \
  --timeline_name "JKT-WS-0441_plaso-E06W1_20261007-20261010" \
  --plaso-event-filter 'date >= DATETIME("2026-10-06T17:00:00") and date <= DATETIME("2026-10-10T06:15:00")' \
  /srv/dfir/out/INC-2026-017/E06-W1/E06-W1_lengkap.plaso
```

- `--sketch-name` memakai sketch yang sudah ada dengan nama itu; karena nama sketch tidak unik, `--sketch-strategy` menentukan yang dipilih bila ada lebih dari satu (`ask` bawaan, `newest`, atau `oldest`) [S9].
- `--plaso-event-filter` mengimpor sebagian event saja dengan sintaks filter Plaso [S9]; `.plaso` lengkap tetap di `jkt-evid01`.
- `--timeline_name` memberi nama timeline sesuai konvensi bagian 1.4. Nama opsi ini berbeda antar versi klien, jadi cek dengan `timesketch_importer.py -h`; bila tidak ada, ganti nama timeline di antarmuka segera setelah impor.
- Koneksi dan kredensial dibaca dari `~/.timesketchrc` akun analyst (Day 13 bagian 1.7); akun per orang, bukan akun bersama.
- Untuk JSONL buatan sendiri, perintahnya sama tanpa `--plaso-event-filter`; nama berkas harus berakhiran `.jsonl` atau `.csv` [S2].

Keluaran ilustrasi (daftar timeline di sketch setelah impor, Jumat 10:10). Tabel ini juga menjadi lampiran cerita; baca kolom "Zona asal" dan "Baris" bersama-sama, karena jumlah baris tanpa zona asal tidak bisa diperiksa ulang.

| Timeline | Host | Bukti | Zona asal | Baris | Lama impor |
|---|---|---|---|---|---|
| `JKT-WS-0441_plaso-E06W1_20261007-20261010` | `JKT-WS-0441` | E06 | Campuran, Plaso UTC (`Asia/Jakarta` untuk sumber waktu lokal) | 684.215 | 38 menit |
| `JKT-WS-0457_plaso-E05W1_20261007-20261010` | `JKT-WS-0457` | E05 | Sama | 912.388 | 51 menit |
| `JKT-WS-0457_vol-netscan-E01_20261010` | `JKT-WS-0457` | E01 | UTC | 187 | kurang dari 1 menit |
| `JKT-FS01_splunk-wineventlog-E07_20261007-20261010` | `JKT-FS01` | E07 | ISO dengan `+07:00` | 38.733 | 2 menit |
| `fw-perimeter_splunk-E07_20261007-20261010` | `fw-perimeter` | E07 | ISO dengan `+07:00` | 4.906 | kurang dari 1 menit |
| `proxy_splunk-E07_20261007-20261010_v2` | `JKT-WS-0441`, `JKT-WS-0457` | E07 | WIB tanpa offset | 18.377 | 1 menit |
| Total | | | | 1.658.806 | |
| (tidak ada) `jkt-dmz-app01` | `jkt-dmz-app01` | tidak ada | tidak ada | 0 | Tidak dikoleksi sebelum dibangun ulang; hanya terlihat di firewall dan 4624 `JKT-WS-0441` |

Rincian dua timeline Splunk, supaya jumlahnya bisa dicocokkan dengan E07. `JKT-FS01`: 5145 sebanyak 38.519 baris (11.622 pemeriksaan akses baca dari `10.10.45.57` Jumat 18:41:00 sampai 20:06:47, 26.155 selama enkripsi 21:31:58 sampai 22:17:04, dan 742 akses lain pada jam kerja), 4624 sebanyak 107 baris, dan 4634 sebanyak 107 baris. Firewall: 1.073 sesi `10.20.9.20` ke `203.0.113.205:443`, 2.104 sesi `10.10.44.41` ke alamat yang sama, 337 sesi `10.10.45.57` ke alamat yang sama, 12 sesi `10.10.45.57` ke `198.51.100.205:443`, 260 sesi `10.20.9.20` ke `10.10.44.0/24` port 445, dan 1.120 sesi masuk dari internet ke `10.20.9.20`.

**Cara membaca hasil:** 1,66 juta baris dari enam timeline masuk dalam sekitar 95 menit. Dua timeline Plaso adalah 96 persen isinya; sumber yang paling menentukan untuk pertanyaan lintas host (firewall, `JKT-FS01`, netscan) justru yang terkecil. Itu pola umum: timeline host memberi konteks, timeline jaringan dan server memberi sambungan.

**Kapan gagal:** filter jendela ditulis dalam WIB padahal `.plaso` menyimpan UTC, sehingga tujuh jam pertama Rabu ikut terpotong dan tujuh jam terakhir Sabtu ikut masuk. Selalu tulis filter dalam UTC dan uji dengan satu event yang waktunya sudah diketahui, seperti di Day 13.

### 2.4 Kalibrasi lintas sumber dan urutan antar host

Langkah ini menjawab pertanyaan kedua Dimas. Dikerjakan Jumat 10:20 sampai 11:40, sebelum pencarian apa pun.

**Tujuan:** mengukur selisih jam antar sumber dari kejadian yang tercatat di dua sisi, lalu memastikan urutan rantai tidak berubah setelah semua sumber berada di UTC.

Query yang dipakai untuk setiap pasangan memakai rentang waktu dan field penghubung [S10]; contoh untuk pasangan PsExec:

```
datetime:[2026-10-08T05:08:00 TO 2026-10-08T05:08:30] AND (dest_ip:"10.10.44.41" OR event_identifier:4624)
```

- `datetime:[... TO ...]`: rentang waktu dalam UTC [S10].
- `dest_ip:"10.10.44.41"`: baris firewall ke workstation tujuan; `event_identifier:4624`: logon di timeline Plaso workstation.
- Hasil dibaca di daftar event yang diurutkan waktu, lalu disaring ke dua baris yang punya bukti penghubung (alamat sumber `10.20.9.20` di kedua sisi).

Keluaran ilustrasi (tabel kalibrasi, semua waktu UTC). Baca kolom "Penghubung" dulu: pasangan tanpa penghubung yang sama tidak boleh dipakai untuk mengukur jam.

| Pasangan | Sisi A | Sisi B | Penghubung | Selisih B terhadap A |
|---|---|---|---|---|
| PsExec masuk | Firewall: sesi `10.20.9.20` ke `10.10.44.41:445` mulai Kamis 05:08:13 | `JKT-WS-0441`: 4624 type 3 05:08:14 | IP sumber, port | +1 s |
| RDP | `JKT-WS-0441`: Prefetch MSTSC 12:02:08, MRU 12:02:10 | `JKT-WS-0457`: 1149 12:02:11, 4624 type 10 12:02:12 | IP `10.10.44.41`, akun `budi.santoso` | +1 sampai +4 s, urutan klien lalu server terjaga |
| Kredensial ke file server | `JKT-WS-0457`: 4648 Jumat 11:40:58 | `JKT-FS01`: 4624 type 3 11:40:59 | Akun, server tujuan, IP sumber | +1 s |
| Beacon sebelum isolasi | Firewall: sesi ke `203.0.113.205:443` 16:07:39 dan 16:12:44 | E01 netscan: `Created` 16:07:39 dan 16:12:44 | IP dan port tujuan | 0 s |
| Exfil, sesi terakhir | Firewall: sesi ke `198.51.100.205:443` 13:08:41 | E01 netscan: `Created` 13:08:41 | IP dan port tujuan | 0 s |
| SMB sebelum enkripsi | `JKT-FS01`: 4624 type 3 `budi.santoso` dari `10.10.45.57` 14:30:05 | E01 netscan: objek ke `10.20.10.21:445` `Created` 14:30:05 | IP, port | 0 s |
| Proxy v1 (salah) | Firewall: sesi ke `198.51.100.205` 11:40:51 | Proxy v1: baris yang sama 18:40:51 | IP tujuan, byte | +7 j 0 s |
| Proxy v2 | Firewall: 11:40:51 | Proxy v2: 11:40:51 | IP tujuan, byte | 0 s |

**Cara membaca hasil:**

- **Semua host domain dan perangkat jaringan berada dalam satu detik.** Selisih +1 s di dua pasangan logon bisa berasal dari jam, dari jeda nyata antara paket pertama dan selesainya autentikasi, atau dari pembulatan detik; ketiganya tidak bisa dipisahkan dan tidak perlu. Toleransi yang dipakai untuk membandingkan sumber di kasus ini ditetapkan 2 detik.
- **Urutan rantai tidak berubah.** Setelah semua sumber di UTC, urutannya sama dengan yang disusun per host di Day 11 dan Day 16: firewall melihat server DMZ menghubungi C2 sejak Rabu 03:14:07 WIB, PsExec ke `JKT-WS-0441` Kamis 12:08, beacon `JKT-WS-0441` sejak 14:25:10, RDP ke `JKT-WS-0457` 19:02, beacon `JKT-WS-0457` sejak 19:11:38, exfil Jumat 18:40:51 sampai 20:10:12, SMB ke `JKT-FS01` 21:30:05, enkripsi 21:31:58. Tidak ada pasangan yang jaraknya lebih kecil dari toleransi sehingga urutannya bisa terbalik.
- **Satu sumber salah tujuh jam, dan ketahuan karena kalibrasi.** Proxy v1 menaruh sesi exfil pada Sabtu 01:40:51 sampai 03:10:12 WIB, setelah `JKT-WS-0457` diisolasi pukul 23:18 Jumat, sesuatu yang mustahil. Selisihnya tepat tujuh jam di semua pasangan, tanda kesalahan zona, bukan jam yang meleset (jam yang meleset jarang tepat kelipatan jam). Penyebabnya ekspor tanpa offset (bagian 2.2). Timeline v1 dihapus setelah tiga tag yang sudah sempat ditambahkan dipindah ke v2, dan kejadiannya dicatat di deskripsi timeline v2.
- **Beacon konsisten dengan memori.** Firewall mencatat 337 sesi `10.10.45.57` ke `203.0.113.205:443` dari Kamis 19:11:38 sampai Jumat 23:12:44 WIB, dengan selisih antar sesi median 5 menit 1 detik (terpendek 4:52, terpanjang 5:09). Dua titik dari netscan Day 16 jatuh tepat di dua baris firewall terakhir, dan interval yang dihitung Day 16 dari enam objek Sabtu (4:56 sampai 5:07) berada di dalam rentang firewall. Pertanyaan yang Day 16 serahkan ke tim SOC (interval dari log firewall) terjawab di sini.

**Variasi:** bila tidak ada pasangan langsung antara dua sumber (misalnya proxy dan memori), kalibrasi lewat sumber ketiga yang punya pasangan dengan keduanya (proxy dengan firewall, firewall dengan memori), dan tulis jalurnya di lampiran.

**Kapan gagal:** kalibrasi memakai pasangan yang hanya dekat waktunya tanpa penghubung yang sama, misalnya "logon Budi pagi hari" dengan "sesi proxy pertama pagi itu". Hasilnya angka selisih yang tampak presisi tetapi tidak mengukur apa pun.

### 2.5 Pivot lintas host: dari IOC dan akun ke host yang mungkin terlewat

Langkah ini menjawab pertanyaan keempat Dimas. Dikerjakan Jumat 13:00 sampai 16:30, setelah kalibrasi.

**Tujuan:** memeriksa ulang, dengan sumber yang tersimpan, apakah ada host lain yang menghubungi infrastruktur penyerang atau dimasuki dengan akun dan jalur yang sama.

Pivot pertama memakai IP C2 di semua timeline. Query dan agregasinya:

```
dest_ip:"203.0.113.205" OR message:"203.0.113.205"
```

- `dest_ip`: field dari timeline firewall, proxy, dan netscan (bagian 2.2); `message`: menangkap baris Plaso yang menyebut alamat itu di teks.
- Hasil diringkas dengan agregasi terms pada field `src_ip`, lalu disimpan sebagai view `pivot-ip-c2-semua-sumber`.

Keluaran ilustrasi (agregasi `src_ip`, waktu WIB):

```
src_ip         baris  pertama                 terakhir
10.10.44.41    2104   Kamis 2026-10-08 14:25:10   Sabtu 2026-10-10 (sampai blok firewall)
10.20.9.20     1073   Rabu 2026-10-07 03:14:07    Sabtu 2026-10-10 (sampai blok firewall)
10.10.45.57     337   Kamis 2026-10-08 19:11:38   Jumat 2026-10-09 23:12:44
(netscan E01)     8   Jumat 23:07:39 (2 baris)   Sabtu 12:41:47 (6 baris setelah isolasi, tidak sampai firewall)
```

**Cara membaca hasil:** hanya tiga sumber yang pernah menghubungi `203.0.113.205` lewat firewall perimeter, dan ketiganya host yang sudah diketahui. Karena filter ekspor firewall E07 menyaring berdasarkan tujuan, bukan berdasarkan host yang dicurigai (bagian 2.1), hasil ini berlaku untuk semua host PT JAB yang keluar lewat firewall perimeter dalam jendela itu. Pivot yang sama untuk `198.51.100.205` hanya menemukan `10.10.45.57` (12 sesi). Domain `sync-win.example.net` tidak muncul di proxy sama sekali, cocok dengan Day 16: payload menghubungi IP langsung, sehingga pivot lewat DNS atau proxy untuk domain itu tidak akan menemukan apa pun dan tidak boleh dibaca sebagai bukti tidak ada host lain.

Pivot kedua memakai jalur masuk: semua lalu lintas dari server DMZ ke jaringan kantor.

```
src_ip:"10.20.9.20" AND dest_port:445
```

Keluaran ilustrasi (diringkas; waktu WIB):

```
Kamis 2026-10-08 11:51:02 - 11:53:40   254 sesi ke 10.10.44.1 - 10.10.44.254 port 445
                                         231 tanpa jawaban; 23 alamat menjawab, semua <= 1.214 byte, durasi < 2 s
Kamis 2026-10-08 12:08:13 - 12:20:04   6 sesi ke 10.10.44.41:445, sesi pertama sekitar 0,4 MB
```

**Cara membaca hasil:** server DMZ menyapu satu subnet kantor port 445 sekitar 17 menit sebelum PsExec, lalu hanya `10.10.44.41` yang menerima sesi besar. Ini dua hal yang tidak tercatat di berkas kasus Oktober. Pertama, aturan firewall mengizinkan `10.20.9.20` membuka port 445 ke subnet kantor; status aturan itu sekarang ditanyakan ke tim jaringan. Kedua, 22 alamat lain menjawab sapuan. Ukuran byte (paling besar 1.214 byte, kurang dari dua detik) cocok dengan negosiasi SMB tanpa autentikasi yang berhasil, tetapi itu inferensi dari ukuran, bukan bukti logon. Bukti langsungnya adalah event logon di 22 host itu untuk Kamis 11:51 sampai 11:54, dan sumber itu sudah tidak tersedia: log Security workstation sudah berputar dan data advanced hunting Defender hanya 30 hari. Berkas kasus tidak mencatat apakah 22 alamat itu diperiksa lewat Defender saat insiden. Jawaban yang ditulis: tidak ada host baru yang terbukti dimasuki; keyakinan sedang bahwa server DMZ tidak membuat sesi berautentikasi ke 22 alamat itu lewat SMB; alamat-alamat itu belum dipetakan ke nama host. Pilot tidak mengubah scope insiden; ia menunjukkan sampai mana sumber yang tersimpan bisa memeriksa ulang scope itu.

Pivot ketiga memakai akun `budi.santoso`, dengan pemisahan pemilik sah dan penyerang:

```
user:"budi.santoso" OR xml_string:"budi.santoso"
```

Keluaran ilustrasi (diringkas per sumber; waktu WIB):

```
proxy        2.917 baris  Rabu-Jumat 08:03 - 16:58  dari 10.10.45.57; situs kerja; tidak ada baris setelah 16:58 Jumat
JKT-FS01     106 x 4624   104 di jam kerja (07:58 - 16:57) + Jumat 18:40:59 + Jumat 21:30:05; semua dari 10.10.45.57
JKT-WS-0457  4624 type10  Kamis 19:02:12 dari 10.10.44.41 (RDP penyerang, Day 11)
             4648         Jumat 18:40:58, Subject JKT-WS-0457$, Account budi.santoso, Target JKT-FS01
JKT-WS-0441  MRU/UsernameHint Kamis 19:02 (sisi sumber RDP, Day 11)
```

**Cara membaca hasil:** akun yang sama dipakai dua pihak. Baris jam kerja (proxy dan logon file server dari workstation Budi sendiri) adalah pemilik akun yang bekerja; tidak ada yang menunjuk host lain. Pemakaian penyerang terpisah oleh jam dan konteks: RDP dari `JKT-WS-0441`, dan dua logon file server di luar jam kerja. Akun `budi.santoso` tidak dipakai dari alamat lain di sumber mana pun, termasuk ke `JKT-FS01`. Logon file server pukul 18:40:59 punya pasangan di `JKT-WS-0457`: 4648 satu detik sebelumnya, dengan akun subjek `JKT-WS-0457$`, yaitu proses berkonteks SYSTEM yang memakai kredensial Budi secara eksplisit. Baris itu menjadi jangkar baru untuk pertanyaan exfil (bagian 2.7).

**Variasi:** pivot hash payload (`sync.exe` `3b7d...`, `hlpsvc.exe` `a4e9...`, Day 16) di sketch hanya menemukan host asalnya, karena sketch tidak berisi data host lain. Pencarian hash ke seluruh fleet adalah pekerjaan hunt (Day 04), bukan sketch; hasilnya, bila dijalankan, diimpor sebagai timeline tersendiri dengan nama yang menyebut hunt-nya.

**Kapan gagal:** menulis "tidak ada host lain" tanpa menyebut bahwa pivot hanya melihat lalu lintas yang melewati firewall perimeter, ekspor yang disaring per tujuan, dan dua workstation yang di-image. Lalu lintas antar workstation di subnet yang sama tidak pernah lewat firewall itu.

### 2.6 Analyzer Sigma: tiga angka yang dicatat

Langkah ini menjawab bagian pertanyaan keenam Dimas tentang analyzer. Dikerjakan Jumat 13:05 sampai 13:52 (analyzer berjalan di latar saat pivot dikerjakan).

**Tujuan:** menjalankan rule yang sama dengan tim deteksi di sketch, lalu mencatat berapa yang benar-benar bekerja.

Sari memilih 46 rule Sigma untuk Windows, jaringan, dan Linux dari repositori komunitas dan dari rule tim deteksi, lalu mengimpornya dengan `tsctl import-sigma-rules` [S3]. Delapan berstatus `experimental` dan tidak dijalankan analyzer; 38 berstatus `stable` [S3]. Hasil dicari dengan `ts_sigma_rule:*` [S3], lalu diringkas per rule.

Keluaran ilustrasi (rule yang menghasilkan tag; nama rule diringkas):

| Rule (ringkas) | Host | Event | Waktu (WIB) | Penilaian manusia |
|---|---|---|---|---|
| Pemasangan service PsExec | `JKT-WS-0441` | 1 (7045 `PSEXESVC`) | Kamis 12:08:16 | Penyerang; sudah di Day 11 |
| Service baru dengan binary di `C:\ProgramData` | `JKT-WS-0457` | 1 (7045 `WinHlpSvc`) | Kamis 19:11:30 | Penyerang; sudah di Day 11 |
| WMI `CommandLineEventConsumer` | `JKT-WS-0457` | 2 (Sysmon 20 dan 21) | Kamis sekitar 19:11 | Penyerang; sudah di Day 11 |
| Scheduled task dengan path menyamar di `\Microsoft\Windows\` | `JKT-WS-0441` | 1 (4698) | Kamis 14:24:55 | Penyerang; sudah di Day 11 |
| Penghapusan shadow copy lewat command line | `JKT-WS-0441` | 1 (4688) | Jumat 21:05 | Penyerang; sinyal sebelum enkripsi |
| Perubahan pengaturan perlindungan Defender | `JKT-WS-0457` | 3 | Jumat 20:52 | Penyerang; tamper antivirus |
| Driver kernel dipasang sebagai service | `JKT-WS-0441`, `JKT-WS-0457` | 2 (7045 `pmem`) | Sabtu 10:06:15 dan 12:42:08 | Responder (WinPmem, Yoga); diberi tag `responder` |

Tiga angka yang dicatat di deskripsi sketch:

```
rule stable dijalankan                          38   (8 experimental tidak dijalankan)
rule yang menghasilkan tag                       7   (11 event)
rule yang tidak mungkin cocok (field tidak ada) 12   5 proxy/firewall (nama field beda: dst_ip, c-uri vs dest_ip, dest_host)
                                                     4 Linux/auditd (tidak ada sumber Linux)
                                                     3 query DNS (tidak ada log DNS di sketch)
rule nol hasil dengan field yang tersedia       19
```

**Cara membaca hasil:**

- **Analyzer menemukan ulang yang sudah diketahui.** Enam rule penyerang menandai kejadian yang semuanya sudah ada di Day 11 dan berkas kasus. Untuk kasus yang sudah dibedah, ini uji bahwa rule dan pemetaan bekerja; untuk kasus baru, ini daftar periksa awal yang menghemat waktu.
- **Analyzer tidak tahu responder.** Dua event driver WinPmem diberi tag oleh rule yang sama dengan yang dipakai untuk penyerang. Tanpa tag `responder` dan tag status `diperiksa`, peserta review yang membuka view `ts_sigma_rule:*` akan menghitung jejak tim sendiri sebagai temuan.
- **Kejadian kunci multi-host tidak ditandai.** Tidak ada rule yang menandai 4648 dari service ke file server, sapuan port 445 dari DMZ, atau RDP dengan akun Keuangan. Temuan baru di pilot ini datang dari pivot (bagian 2.5 dan 2.7), bukan dari analyzer.
- **Angka 12 adalah pekerjaan rumah.** Lima rule jaringan gagal hanya karena nama field skema PT JAB berbeda dari nama yang diterjemahkan pemetaan. Perbaikannya ada dua pilihan: menyesuaikan nama field di skrip konversi, atau menambah pemetaan di `sigma_config.yaml`; PT JAB memilih yang pertama supaya timeline juga konsisten dengan nama field yang dipakai rule di tempat lain. Rule yang nol hasil dengan field tersedia (19) hanya berarti rule itu tidak cocok, bukan aktivitas itu tidak terjadi.

**Kapan gagal:** melaporkan "46 rule Sigma dijalankan, tidak ada temuan baru" ke review. Yang benar: 38 dijalankan, 12 tidak mungkin cocok dengan skema saat ini, dan analyzer tidak dirancang untuk menemukan kejadian lintas host.

### 2.7 Mempersempit pertanyaan proses exfil

Langkah ini menjawab pertanyaan kelima Dimas. Dikerjakan Senin 2027-03-22 sore dan Selasa 2027-03-23, setelah sesi bersama retainer (bagian 2.8).

**Tujuan:** mengganti pertanyaan "proses apa" dengan daftar syarat yang harus benar bila sebuah kandidat adalah pengirimnya, lalu menguji setiap syarat di semua sumber.

Jangkarnya baris firewall sesi exfil pertama, Jumat 18:40:51 WIB (11:40:51 UTC). View jendela dua menit di semua timeline:

```
datetime:[2026-10-09T11:39:51 TO 2026-10-09T11:42:51] AND NOT tag:"rutin"
```

Keluaran ilustrasi (baris yang tersisa setelah rutin dikeluarkan; waktu UTC):

```
11:40:51  fw-perimeter        allow 10.10.45.57 -> 198.51.100.205:443 (sesi 1 dari 12)
11:40:51  proxy (v2)          CONNECT 198.51.100.205:443 user=jkt-ws-0457$ src=10.10.45.57
11:40:58  JKT-WS-0457 (E05)   4648 Subject JKT-WS-0457$ (0x3e7) Account budi.santoso Target JKT-FS01
                              Process ID 0x190c  Process Name C:\ProgramData\WinHlpSvc\hlpsvc.exe
11:40:59  JKT-FS01 (E07)      4624 type 3 budi.santoso dari 10.10.45.57, Logon ID 0x2C1F0A77
11:41:00  JKT-FS01 (E07)      5145 \\*\Keuangan ReadData, SubjectLogonId 0x2C1F0A77 (awal 11.622 baris s.d. 13:06:47)
```

Tabel berikut menguji kandidat `hlpsvc.exe` (PID 6412) syarat demi syarat. Baca kolom "Hasil" dan "Sumber" bersama-sama: syarat yang hanya dipenuhi satu sumber lebih lemah daripada yang dipenuhi beberapa sumber independen.

| Syarat bila `hlpsvc.exe` pengirimnya | Hasil | Sumber |
|---|---|---|
| Proses hidup sepanjang 18:40:51 sampai 20:10:12 WIB | Terpenuhi: PID 6412 berjalan sejak Kamis 19:11:31 dan masih hidup Sabtu | E01 (Day 16), 7045 E05 |
| Proses punya akses ke data yang dikirim | Terpenuhi: 4648 dari PID `0x190C` (6412) memakai kredensial `budi.santoso` ke `JKT-FS01`; satu detik kemudian logon file server, lalu pembacaan share `Keuangan` dengan Logon ID yang sama di file server sampai 20:06:47 | E05 (4648), E07 (4624, 5145); dua host, penghubung akun, IP, server tujuan, waktu 1 s |
| Konteks akun pengirim cocok | Terpenuhi: proxy mencatat 12 sesi exfil dengan akun mesin `jkt-ws-0457$`, artinya proses berkonteks SYSTEM atau service jaringan; `hlpsvc.exe` berjalan sebagai LocalSystem | E07 proxy, E01 dan E05 |
| Tidak ada proses baru lain yang cocok | Terpenuhi dengan batas: 64 baris 4688 di `JKT-WS-0457` antara 18:35 dan 20:15, semuanya komponen Windows dan agen keamanan dari `C:\Windows` dan `C:\Program Files`, tidak ada yang berinduk `hlpsvc.exe` atau berjalan dari path yang bisa ditulis pengguna | E05 (4688, audit Process Creation aktif); tidak melihat kode yang berjalan di dalam proses yang sudah ada |
| Pola jaringan cocok dengan kanal C2 | Tidak terpenuhi: beacon `hlpsvc.exe` langsung ke IP tanpa proxy (Day 16), sedangkan exfil lewat proxy dengan autentikasi akun mesin | E07 firewall dan proxy, E02 |
| Ada catatan proses pemilik koneksi exfil | Tidak tersedia: sisa koneksi di memori tanpa pemilik (Day 16); Sysmon EID 3 di OU `Workstations-EDR` hanya dikonfigurasi untuk daftar image tertentu (antara lain `powershell.exe` dan `wscript.exe`), sehingga tidak mencatat `hlpsvc.exe` maupun koneksi exfil | E01, konfigurasi Sysmon OU |
| Tidak ada kode penyerang di proses SYSTEM lain | Belum diperiksa: `windows.malware.malfind` belum dijalankan atas E01 untuk proses SYSTEM | Pekerjaan terbuka (bagian 2.8) |

**Cara membaca hasil:**

- **Pembacaan share oleh `hlpsvc.exe`: keyakinan tinggi.** Tiga event dari dua host, dihubungkan akun, server tujuan, alamat sumber, dan Logon ID di sisi file server, dalam dua detik. 11.622 baris 5145 dalam jendela exfil mencakup 3.874 berkas berbeda di share `Keuangan`; daftarnya diserahkan ke Agus Setiawan untuk dicocokkan dengan dasar pelaporan data pribadi Oktober, tanpa mengubah keputusan yang sudah diambil.
- **Pengiriman ke `198.51.100.205` oleh `hlpsvc.exe`: keyakinan sedang.** Proses yang membaca data adalah satu-satunya proses non-standar berkonteks SYSTEM yang hidup sepanjang jendela, dan akun proxy cocok dengan konteks itu. Yang menahan keyakinan: tidak ada sumber yang mencatat proses pemilik koneksi keluar, jalur jaringannya berbeda dari kanal C2, dan kode di dalam proses SYSTEM lain belum diperiksa.
- **Status berubah, dan perubahannya ditulis.** Day 16 menulis "proses exfil tidak dapat dipastikan" dan melarang menulis `hlpsvc.exe` hanya karena ia satu-satunya proses mencurigakan yang terlihat. Larangan itu tetap benar untuk bukti waktu itu. Yang menggeser status bukan kecurigaan, tetapi tiga bukti penghubung baru dari sumber yang dulu tidak dibaca bersama: 4648 di disk, logon dan 5145 di file server, dan akun di proxy.

**Kapan gagal:** menulis "proses exfil adalah `hlpsvc.exe`" di ringkasan review tanpa kata keyakinan dan tanpa syarat yang tidak terpenuhi. Pembaca akan membawanya sebagai fakta ke laporan revisi.

### 2.8 Sesi bersama retainer dan story

Langkah ini menjawab bagian pertanyaan keenam Dimas tentang kerja bersama. Sesi berlangsung Senin 2027-03-22 pukul 09:00 sampai 12:00; dari retainer hadir Rangga Pradipta lewat VPN vendor dengan akun Timesketch miliknya sendiri.

Satu kejadian pada jam pertama menjadi pelajaran utama sesi itu. Rangga menyalin keenam timeline ke sketch baru `017-pfdc` supaya tidak mengganggu sketch utama, lalu menulis sembilan komentar di sana. Komentar disimpan per sketch, sehingga timeline yang sama di sketch lain tidak memperlihatkan komentarnya [S1]; tidak ada yang melihat sembilan komentar itu sampai Rangga menyebutnya. Komentar dipindah manual ke sketch utama, sketch `017-pfdc` dihapus, dan aturan pilot ditambah: satu kasus satu sketch, analyst retainer diberi hak edit di sketch utama, dan sketch pribadi tidak dipakai untuk data kasus.

Masukan Rangga yang dipakai:

- Sebelum keyakinan pengiriman exfil dinaikkan dari sedang, jalankan `windows.malware.malfind` dan `windows.vadinfo` atas E01 untuk proses SYSTEM yang hidup sepanjang jendela exfil, untuk menyingkirkan kode penyerang di proses lain. Ditetapkan sebagai pekerjaan terbuka: Rudi Hartanto, tenggat Jumat 2027-04-02.
- Lampiran daftar timeline harus memuat selisih jam terukur, bukan hanya zona asal; tabel kalibrasi bagian 2.4 ikut dilampirkan.

Story `Rekonstruksi INC-2026-017` ditulis mengikuti pola bagian 1.8. Tabel garis waktu di dalamnya, yang juga dibawa ke dokumen review, adalah bagian terpentingnya; baca kolom "Bukti penghubung", karena kolom itulah yang membedakan rekonstruksi lintas host dari tumpukan laporan per host.

| Waktu (WIB) | Host | Sumber | Kejadian | Bukti penghubung | Keyakinan |
|---|---|---|---|---|---|
| Rabu 03:14:07 | `jkt-dmz-app01` (tanpa data host) | Firewall | Koneksi pertama ke C2 `203.0.113.205:443` | IP C2 sama dengan beacon dua workstation | Tinggi untuk koneksi; isi server tidak diketahui |
| Kamis 11:51:02 sampai 11:53:40 | `jkt-dmz-app01` ke `10.10.44.0/24` | Firewall | Sapuan port 445, 254 alamat, 23 menjawab | IP sumber `10.20.9.20` | Tinggi untuk sapuan; sedang bahwa hanya negosiasi |
| Kamis 12:08:13 sampai 12:08:16 | `jkt-dmz-app01` ke `JKT-WS-0441` | Firewall, E06 | PsExec dengan local Administrator | IP `10.20.9.20`, port 445, 4624 Logon ID `0x2E55A1`, 7045 `PSEXESVC` | Tinggi |
| Kamis 14:24:41 sampai 14:25:10 | `JKT-WS-0441` | E06, firewall | Persistence `sync.exe` (Run, task), lalu beacon pertama | Logon ID `0x2E55A1`; IP C2 | Tinggi |
| Kamis 19:02:08 sampai 19:02:12 | `JKT-WS-0441` ke `JKT-WS-0457` | E06, E05 | RDP akun `budi.santoso` | IP `10.10.44.41`, akun, MRU dan 1149/4624 type 10 | Tinggi |
| Kamis 19:11:30 sampai 19:11:38 | `JKT-WS-0457` | E05, E01, firewall | Service `WinHlpSvc` dan WMI subscription, beacon pertama `hlpsvc.exe` | Path payload, PID 6412, IP C2 | Tinggi |
| Kamis 19:11:38 sampai Jumat 23:12:44 | `JKT-WS-0457` | Firewall, E01 | 337 sesi beacon, median 5:01 | IP C2; dua titik netscan identik | Tinggi |
| Jumat 18:40:51 sampai 20:10:12 | `JKT-WS-0457` ke `198.51.100.205` | Firewall, proxy, E01 | Exfil 12 sesi, 6.437.912.576 byte keluar | IP tujuan; sisa netscan 20:08:41 | Tinggi untuk exfil |
| Jumat 18:40:58 sampai 20:06:47 | `JKT-WS-0457` ke `JKT-FS01` | E05, E07 | `hlpsvc.exe` membaca share `Keuangan` dengan kredensial `budi.santoso`, 3.874 berkas | 4648, 4624, 5145; akun, IP, Logon ID file server | Tinggi |
| Jumat 18:40:51 sampai 20:10:12 | `JKT-WS-0457` | Gabungan | Pengirim exfil: kandidat `hlpsvc.exe` | Lihat bagian 2.7 | Sedang |
| Jumat 20:52 | `JKT-WS-0457` | E05 | Tamper Defender | Tag analyzer dan event Defender | Tinggi |
| Jumat 21:05 | `JKT-WS-0441` | E06 | Penghapusan shadow copy | 4688 | Tinggi |
| Jumat 21:30:05 | `JKT-WS-0457` ke `JKT-FS01` | E07, E01, E05 | Logon SMB `budi.santoso`; share dibuka | IP, port 445, ShellBags 21:30 | Tinggi |
| Jumat 21:31:58 sampai 22:17:04 | `JKT-FS01` | E07 | Enkripsi 5.231 berkas `.lck` dari `10.10.45.57` | IP sumber, akun | Tinggi |
| Jumat 23:18 | `JKT-WS-0457` | Case notes | Isolasi lewat EDR | Beacon berhenti di firewall setelah 23:12:44 | Tinggi |
| Sabtu 10:06 dan 12:42 | `JKT-WS-0441`, `JKT-WS-0457` | E06, E05 | Akuisisi memori (driver `pmem`) | Case notes Yoga | Responder |

Celah yang ditulis di story: isi `jkt-dmz-app01` dari Rabu 03:10 sampai Kamis 12:08 (tidak ada data host); logon di 22 alamat yang menjawab sapuan (sumber sudah lewat retensi); lalu lintas antar workstation di subnet yang sama (tidak lewat firewall perimeter); proses pengirim exfil di atas keyakinan sedang (tidak ada sumber yang mencatat pemilik koneksi keluar); proses yang menjalankan enkripsi (bukan pertanyaan pilot).

**Kapan gagal:** story yang ditulis tanpa view di balik setiap baris. Rangga bisa memeriksa ulang setiap baris di sesi itu karena setiap kejadian menunjuk view bernama (misalnya `exfil-jendela-2-menit-jangkar-fw`); baris yang hanya berupa teks harus dicari ulang dari awal oleh siapa pun yang meragukannya.

### 2.9 Jawaban tertulis untuk Dimas

Langkah ini menutup permintaan Dimas. Jawaban dikirim Rabu 2027-03-24 pukul 16:30, disimpan di repositori `jab-ir-tools` sebagai `docs/forensik/pilot-timesketch-017-2027-03.md`, dengan ekspor sketch (zip, termasuk story) di `/cases/INC-2026-017/analysis/timesketch-pilot/` beserta hash-nya.

```
Pilot Timesketch: rekonstruksi INC-2026-017 lintas host | Rabu 2027-03-24 16:30 WIB
Dari: <kamu> | Untuk: Dimas Prasetyo | Tembusan: Sari Kusuma, Agus Setiawan (DPO)
Sketch: "INC-2026-017 rekonstruksi pilot" di jkt-tsketch01 (Timesketch 20261014, Plaso 20260720)
Sumber: E01 (netscan), E05-W1, E06-W1, E07 (ekspor Splunk Okt 2026). 6 timeline, 1.658.806 baris.
Tidak ada data host: jkt-dmz-app01 (dibangun ulang tanpa koleksi).

1. URUTAN LINTAS HOST: konsisten. Semua host domain, firewall, dan memori dalam 1 detik
   (6 pasangan kalibrasi berpenghubung, toleransi 2 s). Satu sumber (proxy) salah 7 jam karena ekspor tanpa
   offset; ketahuan dari kalibrasi, diperbaiki (v2). Interval beacon dari firewall: 337 sesi,
   median 5:01, cocok dengan memori.
2. PIVOT: tidak ada host baru yang terbukti terkompromi. Hanya 3 sumber pernah ke IP C2 lewat
   firewall perimeter. Hal baru yang tidak tercatat Oktober: server DMZ menyapu 10.10.44.0/24
   port 445 (Kamis 11:51), 22 alamat selain 0441 menjawab tingkat negosiasi; logon di host itu
   tidak bisa diperiksa lagi (retensi). Aturan firewall DMZ ke kantor port 445: ditanyakan ke
   tim jaringan. Batas: lalu lintas antar workstation satu subnet tidak terlihat.
3. PROSES EXFIL: dipersempit. Pembacaan share Keuangan 18:41-20:06 oleh hlpsvc.exe dengan
   kredensial budi.santoso: TINGGI (4648 + 4624 + 5145, dua host). Pengiriman ke 198.51.100.205
   oleh hlpsvc.exe: SEDANG (akun proxy = akun mesin, tidak ada proses baru lain; tetapi tidak
   ada pencatat pemilik koneksi, dan jalurnya beda dengan C2). Status lama "tidak dapat
   dipastikan" diganti; laporan kasus perlu catatan revisi. Terbuka: malfind proses SYSTEM E01
   (Rudi, 2 April). Daftar 3.874 berkas yang dibaca sudah ke Agus.
4. SIAP UNTUK INSIDEN BERIKUTNYA: ya, dengan syarat.
   a. Ekspor sumber di luar host saat insiden, disaring per IOC/tujuan, waktu dengan offset.
   b. Skema dan penamaan baku + skrip konversi di jab-ir-tools (dibekukan per kasus).
   c. Satu kasus satu sketch; akun per orang termasuk retainer; syarat DPO berlaku tiap kasus.
   d. Analyzer Sigma = daftar periksa: 38 rule jalan, 7 bertag, 12 tidak mungkin cocok (skema).
   e. Baru kamu dan Sari yang pernah menjalankan alur ini: latihan untuk Rudi dan Yudha April.
   f. Otomasi: skrip dulu; dfTimewolf diuji di lab, dinilai ulang bila host per kasus > 10.
   Usul: pilot naik ke operasional terbatas (SEV-2/SEV-3 multi-host) setelah review 31 Maret.
```

Cara membaca elemennya:

- **Butir 1** menjawab pertanyaan Dimas dengan angka kalibrasi, bukan dengan "sepertinya konsisten", dan menyebut kesalahan yang ditemukan sendiri. Kesalahan zona yang tertangkap adalah bukti bahwa kalibrasi bekerja.
- **Butir 2** memisahkan "tidak ada host baru yang terbukti" dari "tidak ada host lain". Kalimat kedua tidak bisa ditulis dengan sumber yang ada.
- **Butir 3** memakai dua kalimat dengan dua tingkat keyakinan untuk dua klaim yang berbeda (membaca dan mengirim), dan menyebut perubahan status terhadap laporan lama.
- **Butir 4** menjawab "siap atau tidak" dengan syarat yang masing-masing punya pemilik atau tempat, bukan dengan "siap".

**Kapan gagal:** dokumen review yang melaporkan fitur Timesketch (bisa impor CSV, ada analyzer, ada story) alih-alih jawaban atas pertanyaan kasus. Dimas tidak bertanya apakah alatnya lengkap; ia bertanya apakah cara kerja ini menghasilkan jawaban yang tidak bisa didapat sebelumnya.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** `LAB-WS01` (`172.16.50.10`) dan `LAB-WS02` (`172.16.50.11`), keduanya Windows 11 dengan Sysmon dan audit diperluas (Process Creation dengan command line, Logon, Special Logon, Detailed File Share), `LAB-DFIR01` (`172.16.50.20`) dengan share `\\LAB-DFIR01\lab-src` dan audit Detailed File Share, serta `LAB-TL01` (`172.16.50.40`, Ubuntu LTS dengan Docker, Plaso, dan Timesketch dari lab Day 13), semuanya di jaringan host-only `172.16.50.0/24` tanpa jalur ke internet saat lab berjalan. Akun lab `lab.user` dan admin lokal `lab.ir` dipakai seperti di Day 12. Folder kasus `CASE-2026-LAB-026` dengan struktur `evidence\`, `work\`, `analysis\<bukti>\<versi alat>\`, `notes\`. Semua aktivitas jinak memakai fitur administrasi biasa, dan jamnya kamu catat sendiri di case notes lab: catatan itulah kunci jawabanmu. Snapshot bersih semua VM sebelum mulai.

1. **Konvensi dulu.** Tulis `notes\konvensi-026.md`: pola nama timeline `<host>_<sumber>-<bukti>_<rentang>`, field minimum (bagian 1.3), dan kosakata tag dua lapis (bagian 1.4). Jangan impor apa pun sebelum berkas ini ada.
2. **Jam yang sengaja meleset.** Matikan sinkronisasi waktu di `LAB-WS02` lalu majukan jamnya 90 detik. Catat selisih ketiga VM terhadap `LAB-TL01` dengan membaca jamnya pada saat yang sama. Selisih inilah yang harus ditemukan ulang di langkah 7.
3. **Aktivitas lintas host berwaktu.** Dari `LAB-WS01`, RDP ke `LAB-WS02` dengan `lab.user`. Di sesi itu, buka Command Prompt lalu petakan `\\LAB-DFIR01\lab-src` dengan `net use` dan kredensial eksplisit `lab.ir`, salin satu berkas teks dari share ke `C:\Users\Public\`, lalu putuskan petanya. Aktifkan log Windows Firewall (koneksi yang diizinkan) di `LAB-DFIR01` sebelum langkah ini. Catat setiap jam dari jam `LAB-TL01`.
4. **Koleksi.** Matikan `LAB-WS01` dan `LAB-WS02` secara normal, salin disk VM ke `evidence\`, hash, buat salinan kerja di `work\`, lalu bawa ke `LAB-TL01` dan verifikasi hash. Dari `LAB-DFIR01`, ekspor `Security.evtx` dan berkas log firewall Windows, hash keduanya.
5. **Konversi.** Jalankan Plaso atas kedua salinan kerja (alur Day 13). Ubah `Security.evtx` `LAB-DFIR01` ke CSV dengan EvtxECmd di `LAB-DFIR01`, lalu ke JSONL dengan skrip seperti bagian 2.2. Ubah log firewall Windows ke JSONL; periksa dulu apakah waktunya lokal atau UTC di versi Windows lab-mu, dan tulis hasilnya di `tz_source`.
6. **Impor.** Buat sketch `CASE-2026-LAB-026`, impor semua timeline dengan nama sesuai konvensi. Periksa dengan query bahwa setiap timeline punya `hostname` dan `timestamp_desc` yang berarti di setiap baris.
7. **Kalibrasi.** Temukan tiga pasangan: MRU RDP di `LAB-WS01` dengan 1149 dan 4624 type 10 di `LAB-WS02`; 4648 di `LAB-WS02` dengan 4624 type 3 dan 5145 di `LAB-DFIR01`; log firewall `LAB-DFIR01` dengan 4624 yang sama. Hitung selisih per pasangan dan buktikan bahwa angka 90 detik dari langkah 2 muncul kembali. Tunjukkan satu pasangan yang urutannya terbalik bila selisih itu diabaikan.
8. **Zona salah.** Impor ulang log firewall dengan zona asal yang sengaja salah sebagai timeline kedua. Tunjukkan bagaimana kalibrasi menangkapnya (selisih tepat kelipatan jam), lalu hapus timeline yang salah setelah tag-nya dipindah.
9. **Pivot tanpa melihat kunci jawaban.** Tetapkan jangkar di `LAB-DFIR01` (5145 pembacaan berkas), lalu ikuti urutan bagian 1.6 sampai menemukan sesi RDP dari `LAB-WS01`. Catat langkah, query, dan waktu yang dibutuhkan, lalu bandingkan dengan kunci jawaban.
10. **Analyzer Sigma.** Impor beberapa rule `stable` untuk Windows (misalnya logon dengan kredensial eksplisit dan akses share) dan satu rule jaringan dengan nama field yang berbeda dari skema JSONL-mu. Jalankan analyzer, catat tiga angka (bagian 2.6), perbaiki nama field di skrip konversi, impor ulang, jalankan ulang, dan buktikan rule jaringan itu kini menghasilkan tag.
11. **Kerja bersama.** Buat akun Timesketch kedua. Dengan akun itu, salin satu timeline ke sketch baru dan beri komentar; buktikan komentar itu tidak terlihat di sketch utama. Pindahkan komentarnya, lalu hapus sketch salinan.
12. **Story dan ekspor.** Tulis story dengan pola bagian 1.8, termasuk tabel dengan kolom bukti penghubung, daftar celah, dan lampiran timeline dengan zona asal dan selisih jam. Ekspor sketch, hash zip-nya, simpan di `analysis\`.

**Hasil yang sebaiknya tersimpan:**

- `konvensi-026.md` dan case notes lab dengan jam setiap aktivitas dan selisih jam yang disetel.
- Hash semua bukti lab, salinan kerja, storage `.plaso`, CSV, JSONL, dan zip ekspor sketch.
- Skrip konversi beserta versi Python dan pustaka yang dipakai.
- Tabel kalibrasi tiga pasangan dengan selisih terukur dan satu contoh urutan yang terbalik.
- Bukti timeline zona salah tertangkap dan dihapus.
- Catatan pivot: jangkar, langkah, query, waktu, dan perbandingan dengan kunci jawaban.
- Tiga angka analyzer Sigma sebelum dan sesudah perbaikan skema.
- Bukti komentar per sketch.
- Story dengan tabel bukti penghubung, celah, dan lampiran.

**Variasi tantangan:** pasang dfTimewolf di `LAB-TL01` dari repositori resminya, catat commit yang dipakai, lalu jalankan recipe `local_plaso` atas salinan kerja `LAB-WS02` (`dftimewolf local_plaso <path> --incident_id CASE-2026-LAB-026`). Bandingkan timeline hasilnya dengan timeline manual dari langkah 5: jumlah event, nama sketch dan timeline yang dibuat, dan apakah zona waktu bisa diatur di recipe itu. Tulis apakah alur ini cocok untuk kasus dengan lebih dari sepuluh host.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat menggabungkan banyak host di satu sketch. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Impor ditolak | Nama berkas tidak berakhiran `.csv` atau `.jsonl` [S2] | Ganti nama berkas; periksa juga tiga field wajib |
| Event tidak tampil walau impor berhasil | Field wajib kosong atau tidak terpetakan [S2] | Pakai pemetaan header, atau buat kolomnya saat konversi |
| `.plaso` ditolak Timesketch 20261014 | Dibuat Plaso yang lebih lama dari 20260720 [S8] | Proses ulang dengan Plaso 20260720, atau ekspor ke JSONL dengan psort lama lalu impor JSONL [S8] |
| Satu sumber selalu terpaut tepat beberapa jam | Ekspor tanpa offset ditafsirkan sebagai UTC | Cek cara ekspor; tetapkan zona asal di skrip, impor ulang sebagai `_v2` |
| Urutan antar host janggal beberapa detik sampai menit | Jam salah satu host meleset | Kalibrasi dengan pasangan berpenghubung (bagian 2.4); jangan geser timestamp asli |
| Satu akun muncul sebagai beberapa | Normalisasi identitas tidak dilakukan saat konversi | Normalisasi di skrip, lalu impor ulang |
| Query `hostname:` tidak menemukan baris Plaso | Isi `hostname` di baris itu FQDN atau kosong | Pakai wildcard; jaga satu timeline Plaso per host |
| View lama tidak mengembalikan apa pun | Query memakai `computer_name` atau `body` dari Plaso lama [S8] | Ganti ke `hostname` dan `message_body` |
| Command line panjang tidak bisa diagregasi | Nilai melebihi 32766 byte sehingga tidak punya sub-field keyword [S2] | Simpan versi terpotong di kolom terpisah |
| Komentar rekan tidak terlihat | Timeline yang sama ada di sketch berbeda; komentar disimpan per sketch [S1] | Bekerja di satu sketch yang sama |
| Rule Sigma tidak pernah dijalankan | Status bukan `stable` [S3] | Cek status rule di Studio |
| Analyzer Sigma hampir tidak menandai apa pun | Nama field di timeline tidak cocok dengan pemetaan | Catat rule yang tidak mungkin cocok; seragamkan skema (bagian 2.6) |
| Analyzer Sigma berjalan berjam-jam | Terlalu banyak rule `stable` atau rule dengan `OR` panjang [S3] | Pecah rule, kurangi rule yang tidak relevan dengan sumber di sketch |
| Pivot IOC hanya menemukan host yang sudah diketahui | Ekspor sumber disaring per host yang dicurigai | Ekspor ulang disaring per tujuan bila data masih ada; tulis batasnya bila tidak |
| Sketch jadi lambat | Terlalu banyak event tanpa penyempitan | Impor hanya jendela kasus dengan `--plaso-event-filter`; pakai view |

## 5. Kesalahan umum dan jebakan

- **Mengimpor sebelum konvensi disepakati.** Nama timeline dan kosakata tag yang ditetapkan setelah sepuluh timeline masuk berarti mengganti nama dan tag di mana-mana.
- **Mengandalkan nama timeline sebagai penanda host**, bukan field `hostname` di setiap baris.
- **Mengisi `timestamp_desc` sama untuk semua sumber**, sehingga perbedaan arti waktu (koneksi dibuat di memori, sesi dilihat firewall, akses diperiksa file server) hilang.
- **Menggabungkan sumber tanpa menyeragamkan zona dan jam lebih dulu.** Urutan yang dibaca sebelum kalibrasi bisa terbalik tanpa ada pesan galat.
- **Menggeser timestamp asli untuk "membetulkan" jam.** Selisih dipakai sebagai toleransi saat membandingkan dan dicatat di lampiran; baris tetap memakai jam sumbernya.
- **Menautkan dua host dengan Logon ID atau PID.** Keduanya hanya unik di dalam satu host.
- **Mengira host tanpa timeline berarti host tanpa peran.** `jkt-dmz-app01` adalah awal rantai walau tidak punya satu baris pun dari dirinya sendiri.
- **Menulis "tidak ada host lain" dari pivot IOC** tanpa menyebut filter ekspor dan jalur yang tidak terlihat.
- **Memperlakukan tag analyzer sebagai temuan**, termasuk tag pada jejak responder.
- **Melaporkan jumlah rule Sigma yang dimuat**, bukan yang benar-benar bisa cocok dengan skema.
- **Menaikkan keyakinan karena sebuah kandidat satu-satunya yang terlihat.** Yang menaikkan keyakinan adalah bukti penghubung baru, dan syarat yang tidak terpenuhi tetap ditulis.
- **Bekerja di sketch salinan** sehingga komentar dan tag tidak terlihat orang lain.
- **Menulis kesimpulan di story tanpa menautkannya ke view** yang menghasilkannya, dan melupakan lampiran daftar timeline dengan zona asal dan selisih jam.
- **Mengunggah data ke wadah bersama tanpa minimisasi dan izin DPO**, atau data pekerjaan dan klien ke instance lab.

## 6. Catatan terkini

Bagian ini mencatat versi dan perubahan alat per 2026-10-23 yang memengaruhi kerja di atas.

- **Timesketch 20261014** adalah rilis terbaru di halaman rilis; sebelumnya 20260630 dan 20260617 [S8]. Rilis ini mewajibkan Plaso minimal 20260720 di sisi worker dan memakai API pembaca storage Plaso secara langsung; `.plaso` dari versi lebih lama gagal diimpor, dengan saran ekspor ke JSONL memakai psort lama lalu impor JSONL [S8]. Rilis yang sama memperbaiki impor event dengan field string besar, menambah `OPENSEARCH_INDEX_PREFIX` opsional untuk instalasi baru, dan menambah kontrol akses berbasis grup dan peran lewat OIDC [S8]. Keputusan pilot PT JAB: versi dibekukan selama pilot dan setiap kasus; sebelum memperbarui, baca catatan rilis untuk syarat versi Plaso, karena syarat itu menentukan `.plaso` mana yang masih bisa diimpor.
- **Nama field Plaso berubah di 20260720:** `computer_name` menjadi `hostname` dan `body` menjadi `message_body`. Analyzer dan grafik bawaan mendukung kedua nama, tetapi view dan query buatan sendiri perlu diperbarui [S8]. Skema PT JAB memakai `hostname` untuk semua timeline buatan sendiri supaya satu query bekerja di semua timeline.
- **Analyzer Sigma** masih disebut fungsi alpha dengan masalah kinerja dan fungsi yang diketahui; rule disimpan di basis data sejak 2022, hanya rule `stable` yang dijalankan, dan hasilnya ditulis ke `ts_sigma_rule` dan `ts_ttp` [S3]. Halaman itu masih memakai alat `sigmac` lama untuk memverifikasi rule terhadap pemetaan; cek apakah versi-mu sudah berpindah ke pustaka Sigma yang lebih baru sebelum mengandalkan langkah verifikasi itu.
- **Label** di event sedang ditinggalkan dari antarmuka; tag penggantinya [S1].
- **Pencarian** memakai mode query string bergaya Lucene secara bawaan, dengan mode pencarian wildcard yang tidak membedakan huruf besar kecil dan butuh pemetaan wildcard di index timeline; timeline lama kembali ke mode query string [S10].
- **dfTimewolf** tetap aktif (commit terakhir 2026-10-20) tanpa rilis bertag [S12][S4]; panduan memulainya memasang dari repositori dengan `pip`, dengan log2timeline dipasang terpisah [S11]. Catat commit yang dipakai sebagai versi.
- **Alat pihak ketiga yang mengekspor ke Timesketch** makin umum. Contohnya, Nextron merilis `thor2ts` (Juni 2025) yang mengubah log pemindai THOR menjadi JSONL siap impor dengan `timestamp_desc` per event, supaya temuan pemindai bisa dibaca berdampingan dengan sumber lain dari banyak host [S13]. Polanya sama dengan skrip konversi PT JAB: arti waktu ditetapkan per baris saat konversi.

## 7. Cheat sheet

```
MASALAH MULTI-HOST   zona beda | jam beda | identitas ditulis beda | asal event tak jelas
                     -> UTC + zona asal per sumber | kalibrasi pasangan berpenghubung, JANGAN geser timestamp
                     -> normalisasi akun/host saat KONVERSI | hostname di SETIAP baris
                     Logon ID / PID hanya unik per host: TIDAK menghubungkan host

WADAH     sketch = 1 kasus | timeline = 1 host x 1 sumber | view = pencarian tersimpan | story = tulisan hasil
          tag (field tag) | label (lama) | bintang | komentar PER SKETCH -> retainer kerja di sketch utama
          akses per orang | minimisasi + izin DPO | retensi sketch tertulis

SKEMA     wajib: message | datetime (ISO 8601 + offset) | timestamp_desc (ARTI waktunya)
          PT JAB: hostname | source_tool | evidence_id | src_ip | dest_ip | dest_port | user | tz_source
          berkas .csv / .jsonl | nilai > 32766 byte: cari teks ya, agregasi/urut TIDAK
          Plaso 20260720: computer_name -> hostname, body -> message_body (perbarui view lama)

NAMA      <host>_<sumber>-<bukti>_<YYYYMMDD-YYYYMMDD>[_v2]    JKT-WS-0457_plaso-E05W1_20261007-20261010
          sumber non-host: fw-perimeter, proxy | host tanpa data: tetap ditulis di lampiran

IMPOR     timesketch_importer.py --sketch-name "<kasus>" --sketch-strategy oldest
          --plaso-event-filter 'date >= DATETIME("<UTC>") and date <= DATETIME("<UTC>")'
          (cek nama opsi timeline dengan -h) | Timesketch 20261014 butuh Plaso >= 20260720

KALIBRASI pasangan sama di dua sisi: fw <-> 4624 | 4648 <-> 4624 server | netscan Created <-> fw | MRU <-> 1149
          selisih tepat kelipatan jam = salah ZONA, bukan jam | toleransi ditulis di lampiran

PIVOT     jangkar -> jendela (semua timeline) -> identitas -> artefak -> jaringan -> jangkar baru
          pivot hanya melihat sumber di sketch; tulis filter ekspor dan jalur tak terlihat
          kandidat: tulis SYARAT, uji tiap syarat di semua sumber; "satu-satunya yang terlihat" = tebakan

SIGMA     hanya status stable | hasil: ts_sigma_rule:* dan ts_ttp | alpha, query bisa mahal
          catat: dijalankan | menghasilkan tag | tidak mungkin cocok (field tak ada) | nol hasil
          analyzer tidak tahu responder -> tag responder + diperiksa

OTOMASI   dfTimewolf: recipe (local_plaso ...), versi = commit | nilai = keseragaman, uji dulu di data diketahui

STORY     ringkasan | tabel waktu-host-sumber-kejadian-BUKTI PENGHUBUNG-keyakinan | tiap baris -> view
          celah (host tanpa data, retensi, jalur tak terlihat) | lampiran timeline + zona asal + selisih jam
          status yang berubah: tulis lama, baru, dan bukti penggesernya

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Logon ID `0x2E55A1` milik sesi PsExec di `JKT-WS-0441`. Kalau di timeline `JKT-FS01` ada event dengan Logon ID yang sama, berarti sesi penyerang yang sama juga masuk ke file server." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Logon ID dan PID hanya unik di dalam satu host; dua host bisa memakai nilai yang sama untuk sesi yang sama sekali tidak berhubungan. Penghubung antar host adalah pasangan yang tercatat di kedua sisi dengan nilai yang sama: misalnya 4648 di host sumber yang menyebut server tujuan dan akun, lalu 4624 type 3 di server dengan akun itu dan alamat sumber host tersebut, dalam toleransi jam yang sudah diukur. Lihat bagian 1.1.

</details>

**2. Skenario keputusan.** Setelah impor, semua baris proxy untuk sesi exfil tampak tepat tujuh jam lebih lambat dari baris firewall untuk sesi yang sama, sehingga exfil terlihat terjadi setelah host diisolasi. Apa langkah yang tepat?

- A. Geser tampilan timeline proxy minus tujuh jam di Timesketch dan lanjutkan analisis.
- B. Periksa cara ekspor proxy, tetapkan zona asalnya di skrip konversi, impor ulang sebagai timeline `_v2`, pindahkan tag dari timeline lama, lalu hapus timeline lama dan catat kejadiannya di lampiran.
- C. Abaikan timeline proxy, karena firewall sudah cukup.

<details><summary>Jawaban</summary>

B. Selisih yang tepat kelipatan jam di semua pasangan adalah tanda kesalahan zona, biasanya ekspor yang menulis jam dinding tanpa offset lalu ditafsirkan sebagai UTC. Perbaikannya di konversi, dengan zona asal tertulis, supaya bisa diperiksa ulang. A keliru karena menyembunyikan kesalahan di tampilan tanpa jejak, sehingga orang berikutnya bisa mengulanginya atau mengoreksinya dua kali. C keliru karena proxy membawa informasi yang tidak dimiliki firewall, misalnya akun yang terautentikasi, yang di kasus ini menjadi salah satu bukti untuk mempersempit proses exfil. Lihat bagian 2.2 dan 2.4.

</details>

**3. Pertanyaan jebakan.** "Pivot IP C2 di log firewall hanya menemukan tiga host yang sudah kita kenal, jadi tidak ada host lain yang terkompromi." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Pivot hanya melihat sumber yang ada di sketch. Hasilnya berlaku untuk host yang keluar lewat firewall perimeter ke IP itu, dan hanya karena ekspor firewall disaring berdasarkan tujuan, bukan berdasarkan host yang dicurigai. Host yang tidak menghubungi IP itu (misalnya hanya dimasuki dan belum diberi payload), lalu lintas antar workstation di subnet yang sama, dan sumber yang sudah lewat retensi tidak terlihat. Kalimat yang bisa ditulis adalah "tidak ada host baru yang terbukti", disertai filter ekspor dan jalur yang tidak terlihat. Lihat bagian 1.6 dan 2.5.

</details>

**4. Skenario keputusan.** Analyzer Sigma memberi tag "driver kernel dipasang sebagai service" pada dua event 7045 bernama `pmem`, satu di setiap workstation, Sabtu pagi dan siang setelah insiden. Apa yang kamu lakukan?

- A. Masukkan sebagai temuan persistence tingkat kernel di kedua host.
- B. Cocokkan waktu, nama service, dan path dengan case notes dan inventaris toolkit, lalu beri tag `responder` dan `diperiksa` sebelum view analyzer dibagikan.
- C. Hapus kedua event dari timeline supaya tidak membingungkan pembaca.

<details><summary>Jawaban</summary>

B. Analyzer tidak tahu siapa yang memasang driver; ia hanya mencocokkan pola. Waktu Sabtu 10:06 dan 12:42 cocok dengan akuisisi memori Yoga, dan `pmem` adalah driver WinPmem dari toolkit. Jejak responder dilabeli, bukan dihapus. A keliru karena menjadikan jejak tim sendiri temuan penyerang. C keliru karena menghapus data membuat timeline tidak bisa diperiksa ulang dan menyembunyikan aktivitas yang memang terjadi di host. Lihat bagian 1.5 dan 2.6.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Dimas, dalam tiga kalimat, kenapa status proses exfil boleh berubah dari "tidak dapat dipastikan" menjadi "kandidat `hlpsvc.exe`, keyakinan sedang", padahal Day 16 melarang menulis `hlpsvc.exe` sebagai pengirim.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Larangan di Day 16 berlaku karena satu-satunya alasan waktu itu adalah `hlpsvc.exe` proses mencurigakan yang terlihat, dan itu tebakan. Sekarang ada bukti baru dari sumber yang dibaca bersama: 4648 di `JKT-WS-0457` menunjukkan `hlpsvc.exe` memakai kredensial Budi ke `JKT-FS01` satu detik sebelum file server mencatat logon dan pembacaan share `Keuangan`, dan proxy mencatat sesi exfil dengan akun mesin, cocok dengan proses berkonteks SYSTEM. Keyakinannya tetap sedang karena tidak ada sumber yang mencatat proses pemilik koneksi keluar, jalur jaringannya berbeda dengan kanal C2, dan proses SYSTEM lain belum diperiksa dengan malfind."

Kesalahan yang sering muncul:
- Menulis "pengirim exfil adalah `hlpsvc.exe`" tanpa tingkat keyakinan.
- Mencampur dua klaim: pembacaan share (tinggi) dan pengiriman ke luar (sedang).
- Tidak menyebut syarat yang tidak terpenuhi dan pekerjaan terbuka.

</details>

**6. Pertanyaan jebakan.** "Analyst retainer menyalin timeline ke sketch pribadinya dan menulis komentar di sana. Karena timelinenya sama, komentar itu ikut terlihat di sketch utama." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Komentar disimpan per sketch; bila timeline yang sama ada di dua sketch, komentar di satu sketch tidak muncul di sketch lain. Itu sebabnya satu kasus harus benar-benar satu sketch, dan analyst retainer diberi akses ke sketch utama dengan akun miliknya sendiri, bukan bekerja di salinan. Lihat bagian 1.2 dan 2.8.

</details>

**7. Interview question (English).** "You have disk images from two workstations, a memory image, file server logs, and firewall and proxy exports. How do you build one timeline across them, and how do you know the cross-host ordering is right?"

<details><summary>Sample answer</summary>

"Before I search anything, I agree on a schema and naming: every row gets message, datetime in ISO 8601 with an offset, and a timestamp description that states what the time means, plus a hostname, the evidence ID, and the join fields like source and destination IP, port, and normalized account. I convert every source to UTC in the conversion script and record its original time zone, because SIEM exports often write wall-clock time without an offset. Then I calibrate: I find events recorded on both sides with the same join key, such as a firewall session and the 4624 on the destination, an explicit-credential 4648 on the source and the logon on the file server, or a netscan connection and the firewall session, and I measure the offset per pair instead of shifting any timestamps. An offset that is an exact multiple of an hour means a time zone error, not clock drift. I never link hosts by logon ID or PID, since those are only unique per host. Only after that do I pivot from a solid anchor, and every cross-host link in the final story names its join evidence and a confidence level, with the gaps written down, including hosts that have no data at all."

What makes this answer strong: it puts data discipline before searching, separates time zone errors from clock drift with a concrete test, uses calibration pairs with real join keys rather than proximity in time, rules out per-host identifiers as cross-host links, and ends with traceability and explicit gaps.

</details>

## 9. Sumber

| # | Judul | URL | Tipe | Tanggal / diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Timesketch: Basic concepts | https://timesketch.org/guides/user/basic-concepts/ | primer | dilihat 2026-10-09; diakses ulang 2026-10-23 | Tinggi. Sketch (biasanya satu kasus), timeline dari JSON/JSONL/CSV, data di OpenSearch, tag di field `tag`, label sedang ditinggalkan, bintang, komentar yang hanya tampil di sketch tempat ditulis, view, agregasi, story (ekspor lewat zip sketch), analyzer Sigma, domain, dan chain |
| S2 | Timesketch: Import from JSON or CSV | https://timesketch.org/guides/user/import-from-json-csv/ | primer | dilihat 2026-10-09; diakses ulang 2026-10-22 | Tinggi. Tiga field wajib (`message`, `datetime` ISO 8601 dengan contoh offset, `timestamp_desc`), pemetaan header (dropdown dan checkbox), kolom tambahan bebas, ekstensi `.csv`/`.jsonl`, JSONL hemat memori, batas nilai 32766 byte |
| S3 | Timesketch: Sigma | https://timesketch.org/guides/user/sigma/ | primer | dirujuk 2026-10-09; diakses 2026-10-22 | Tinggi. Rule di basis data sejak 2022, tidak membawa rule, Studio dan `tsctl import-sigma-rules`, hanya status `stable`, `ts_sigma_rule` dan `ts_ttp`, `sigma_config.yaml` (banyak field ke `xml_string`), `SIGMA_TAG_DELAY`, status alpha dan batas kinerja |
| S4 | dfTimewolf (repo log2timeline) | https://github.com/log2timeline/dftimewolf | primer | dirujuk 2026-10-09; diakses 2026-10-22 | Sedang-tinggi. Kerangka orkestrasi pengumpulan, pemrosesan, dan ekspor; collector, processor, exporter, dan recipe; lisensi Apache-2.0; bagian Releases kosong; daftar modul berubah antar commit |
| S5 | Timesketch (repo resmi) | https://github.com/google/timesketch | primer | dirujuk 2026-10-09 | Tinggi untuk versi dan perubahan antar rilis; rincian rilis di S8 |
| S6 | Endpoint-Forensics Day 05, 09, 11, 13, 16, 19, 20 | (lokal) | rujukan internal | 2026-10-23 | Keterkaitan antar Day: Logon ID, zona dan jam host, rantai `INC-2026-017`, Plaso dan Timesketch satu host, memori `JKT-WS-0457`, skala keyakinan, rencana nomor 8 |
| S7 | Sigma rule specification (SigmaHQ) | https://github.com/SigmaHQ/sigma-specification | primer | dirujuk 2026-10-10 | Tinggi untuk struktur rule (`logsource`, `detection`, `condition`) dan modifier field |
| S8 | Timesketch releases (GitHub) | https://github.com/google/timesketch/releases | primer | 20261014 (14 Oktober 2026); diakses 2026-10-22 | Tinggi. 20261014 Latest; minimum Plaso 20260720; `.plaso` lama gagal diimpor (saran JSONL); `computer_name` menjadi `hostname`, `body` menjadi `message_body`; perbaikan impor field besar; `OPENSEARCH_INDEX_PREFIX`; RBAC grup OIDC |
| S9 | Timesketch: Upload data | https://timesketch.org/guides/user/upload-data/ | primer | diakses 2026-10-22 | Tinggi. `timesketch_importer.py`, `--sketch-name`, `--sketch-strategy` (`ask`, `newest`, `oldest`), `--plaso-event-filter`; halaman tidak merinci opsi nama timeline |
| S10 | Timesketch: Search query guide | https://timesketch.org/guides/user/search-query-guide/ | primer | diakses 2026-10-23 | Tinggi. Query string `field:value`, AND/OR/NOT, rentang `datetime:[... TO ...]`, wildcard, regex, karakter yang di-escape; mode wildcard tidak membedakan huruf besar kecil |
| S11 | dfTimewolf: Getting started | https://dftimewolf.readthedocs.io/en/latest/getting-started.html | primer (dokumentasi proyek) | diakses 2026-10-22 | Sedang-tinggi. Instalasi dari repositori dengan `pip` di virtual environment, log2timeline dipasang terpisah, `dftimewolf <recipe> -h`, contoh `local_plaso ... --incident_id` sebagai deskripsi sketch, recipe AWS dan GCP |
| S12 | dfTimewolf commits (GitHub API) | https://api.github.com/repos/log2timeline/dftimewolf/commits?per_page=3 | primer (repo resmi) | diakses 2026-10-22 | Tinggi untuk tanggal: commit terakhir 2026-10-20, sebelumnya 2026-10-01 |
| S13 | Nextron Systems: From THOR Scan to Timeline: Correlating Findings in Timesketch | https://www.nextron-systems.com/2025/06/11/from-thor-scan-to-timeline-correlating-findings-in-timesketch/ | sekunder (blog vendor) | 2025-06-11; diakses 2026-10-22 | Sedang. Alat `thor2ts` mengubah log THOR ke JSONL untuk Timesketch dengan `timestamp_desc` per event; korelasi dengan sumber lain dari banyak host; tidak membahas field host |

**Catatan sumber:** opsi `--timeline_name` pada `timesketch_importer.py` di bagian 2.3 tidak tercantum di halaman upload yang diperiksa [S9]; cocokkan dengan `-h` klien versi-mu. Pembacaan VHDX oleh Plaso lewat dfVFS tidak dikutip dari halaman dokumentasi Plaso di Day ini dan harus diuji dengan run singkat. Urutan pivot (bagian 1.6), pola story (bagian 1.8), daftar syarat kandidat (bagian 2.7), dan skema field tambahan PT JAB (bagian 1.3) adalah praktik kerja yang disusun dari Day-Day sebelumnya [S6], bukan prosedur baku dari dokumentasi mana pun. Tafsiran bahwa sesi SMB berukuran paling besar 1.214 byte dan kurang dari dua detik hanya berisi negosiasi tanpa autentikasi yang berhasil adalah inferensi dari ukuran, bukan dari sumber; ukur sendiri sesi SMB gagal dan berhasil di lab sebelum memakai ambang serupa. Dukungan dan cakupan analyzer Sigma berbeda antar versi Timesketch [S3], jadi ketiga angka di bagian 2.6 harus diukur sendiri. Semua isi PT JAB, termasuk `jkt-tsketch01`, bukti `INC-2026-017-E07`, jumlah baris, sesi firewall dan proxy, sapuan port 445, 4648 dari `hlpsvc.exe`, Logon ID file server, konfigurasi Sysmon EID 3, dan nama analyst retainer, adalah contoh fiktif yang disusun agar konsisten dengan Day 11 dan Day 16, bukan kejadian nyata.
