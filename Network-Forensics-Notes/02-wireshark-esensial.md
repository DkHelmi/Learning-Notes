---
day: 02
title: 'Wireshark esensial: membuka pcap dengan aman, profil, waktu, capture vs display filter, Statistics, Follow Stream, Export Objects, dan tshark'
researched_on: 2026-10-22
versions_checked: 'Wireshark 4.6.9 dan 4.4.19 (23 Sep 2026), 5.0.0rc1 rilis pengembangan (21 Okt 2026); man page tshark, dumpcap, capinfos, mergecap, dan wireshark-filter versi 4.6.9; catatan rilis Wireshark 4.6.0 dan 4.6.9; display filter reference 4.6.9 (frame, tcp, http, tls, dns); pcap-filter(7) tcpdump.org; advisory wnpa-sec-2026-92 sampai 110; MITRE ATT&CK T1218.005'
---

# Day 02: Wireshark esensial (membuka pcap dengan aman, profil, waktu, filter, Statistics, Follow Stream, Export Objects, dan tshark)

Cakupan: keterampilan Wireshark dan tshark yang dipakai di semua Day berikutnya: menyiapkan dan membuka pcap tak tepercaya dengan aman, profil analisis yang bisa diulang, membaca waktu dan zona waktu, dua jenis filter, Statistics, Follow Stream, Export Objects, Expert Information, dan ekstraksi field dari command line.

## Ide inti

Wireshark menunjukkan fakta tentang paket, bukan kesimpulan, dan setiap fakta itu hanya sebaik tiga hal yang kamu pastikan sebelum mulai membaca: apakah file itu aman dibuka di mesin analisis, jam berapa sebenarnya sebuah paket lewat (dalam zona waktu apa), dan paket mana yang memang tersimpan di file. Setelah tiga hal itu jelas, alur kerjanya hampir selalu sama: orientasi dengan Statistics (apa isi file, siapa bicara dengan siapa, berapa banyak), persempit dengan display filter, baca satu sesi utuh dengan Follow Stream, pulihkan file dengan Export Objects, lalu keluarkan field yang dibutuhkan dengan tshark supaya bisa dicocokkan dengan log lain. Wireshark dipakai untuk kedalaman satu atau beberapa file; ratusan GB dipotong atau diringkas dulu dengan tshark atau Zeek (Day 08).

Sebagai orang NOC, kamu sudah memakai pola yang sama setiap hari di CLI router. `show logging | include BGP` menyembunyikan baris lain tanpa menghapusnya dari buffer: itu display filter. ACL yang dipasang pada `monitor capture` menentukan paket apa yang pernah direkam; yang tidak cocok tidak akan pernah ada: itu capture filter. `show ip flow top-talkers` menjawab "siapa yang paling banyak bicara" sebelum kamu membuka satu sesi pun: itu Statistics > Conversations. Dan `service timestamps log datetime msec localtime show-timezone` ada karena log dari router berzona UTC dan router berzona WIB tidak bisa dibandingkan tanpa tahu zonanya: itu kolom waktu Wireshark. Batas analoginya ada dua. Pertama, `| include` mencocokkan teks mentah, sedangkan display filter bekerja pada field hasil penguraian protokol, sehingga filter yang salah nama field gagal dengan diam-diam atau ditolak, bukan sekadar tidak cocok. Kedua, keluaran `show` dibuat oleh router-mu sendiri dan bisa dipercaya, sedangkan isi pcap sebagian dibuat oleh pihak luar, termasuk penyerang, dan parser yang membacanya bisa diserang.

```
 jkt-pcap01 (ring buffer, 1 GB per file, nama file = jam pembuatan file, sensor ber-zona UTC)
        |  pilih file per rentang waktu (nama file, lalu capinfos)
        v
 jkt-nsm-ws01 (user biasa, Wireshark 4.6.9, resolusi nama jaringan mati)
        |  potong: tshark -Y "<host> && <rentang waktu>" -w ; gabung: mergecap ; catat SHA-256
        v
 pcap kasus  SOC-2027-0605_noc-direct_0215Z-0345Z.pcapng
        |
        +--> capinfos / Protocol Hierarchy / Conversations / Endpoints   (orientasi)
        |
        +--> display filter --> Follow Stream --> Export Objects --> hash (tidak dijalankan)
        |
        +--> IO Graph (pola waktu)        tshark -T fields --> CSV --> Splunk (WIB) dan flow NOC
        v
 sinyal + penjelasan jinak + korroborasi --> keputusan: tutup, atau eskalasi
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan dan sekitar 400 ribu pelanggan broadband, yang SOC-nya satu lantai dengan NOC 24/7 di Jakarta. Senin 2027-05-03, Direktur Teknologi Hendra Wijaya menyetujui "Program NSM PT JAB" sebagai percobaan Mei sampai Juli 2027, dengan kamu (analyst L2), Bambang Hartono (Manajer NOC), dan Agung Prabowo (Lead Infrastruktur) sebagai pelaksana di bawah SOC lead Dimas Prasetyo. Selasa 2027-05-04 pukul 09:00 WIB, sensor pertama mulai uji coba: `jkt-pcap01` (10.20.70.13) merekam salinan trafik dari TAP egress kantor Jakarta di sisi dalam firewall `jkt-fw01`, dengan ring buffer file 1 GB. Analisis dikerjakan di `jkt-nsm-ws01` (10.20.70.20), workstation analisis yang punya akses read-only ke direktori pcap sensor. Kantor Jakarta keluar ke internet lewat dua jalur: browsing lewat proxy `jkt-proxy01` dengan NAT `198.51.100.120`, dan aturan firewall lama `NOC-VENDOR-DIRECT` yang mengizinkan lima workstation engineering NOC (`JKT-WS-2005` sampai `JKT-WS-2009`, 10.10.60.20 sampai 10.10.60.24) keluar langsung tanpa proxy ke portal dan mirror vendor perangkat, dengan NAT `198.51.100.202`. Pukul 10:40, Bambang menulis di kanal SOC-NOC:

> "Pagi. Dari flow edge di jkt-flow01 ada yang ganjil: dari sekitar jam 09.20 sampai sekitar jam 10.00 WIB, 198.51.100.202 menarik data besar dari 203.0.113.162 port 8080, perkiraan dari sampel sekitar 1,4 sampai 1,5 GB. 198.51.100.202 itu NAT untuk NOC-VENDOR-DIRECT, jadi pasti salah satu dari lima PC engineering-ku. Flow cuma kasih IP NAT. pcap01 kan baru jalan tadi pagi: bisa lihat PC mana dan isinya apa? Jam di dashboard flow kami WIB."

Dimas membuka tiket `SOC-2027-0605` dan menambahkan pukul 10:52:

> "Silakan, ini kasus pertama pcap01. Tiga hal. Satu, pastikan aman membuka pcap trafik internet di ws01; jangan sampai alat analisisnya sendiri jadi pintu masuk. Dua, kerjakan dengan cara yang bisa diulang Sari besok pagi, termasuk profil dan filternya, dan pastikan jam yang kamu laporkan cocok dengan dashboard NOC dan Splunk. Tiga, Agung tanya apakah pcap01 cukup menyimpan port 80 dan 443 saja supaya disk awet. Kalau ternyata ada hal lain di pcap itu, aku perlu daftar request lengkap dan file yang diunduh, untuk dicocokkan ke Splunk."

Dua pesan itu memuat tujuh pertanyaan:

1. Amankah membuka pcap egress di `jkt-nsm-ws01`, dan bagaimana caranya?
2. Bagaimana supaya analisis bisa diulang orang lain, misalnya Sari besok pagi?
3. Jam berapa paket itu sebenarnya lewat, dan bagaimana mencocokkannya dengan dashboard flow (WIB) dan Splunk?
4. Cukupkah `jkt-pcap01` menyimpan port 80 dan 443 saja?
5. PC mana yang ada di balik `198.51.100.202`, dan dengan siapa saja ia bicara?
6. Apa isi koneksi ke port 8080, dan adakah hal lain di pcap yang perlu dilihat?
7. Bagaimana menyerahkan daftar request lengkap dan file yang diunduh untuk dicocokkan ke Splunk?

Pertanyaan 1 dijawab di bagian 1.1 dan 2.1, pertanyaan 2 di bagian 1.2 dan 2.2, pertanyaan 3 di bagian 1.3, 2.1, dan 2.8, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, 1.6, 2.3, dan 2.4, pertanyaan 6 di bagian 1.7, 1.8, 2.5, 2.6, dan 2.7, dan pertanyaan 7 di bagian 1.9 dan 2.8. Bagian 2.9 memisahkan sinyal dari kesimpulan, dan bagian 2.10 berisi jawaban yang dikirim ke Bambang dan Dimas.

**Kapan relevan:** analisis pcap mendalam atas satu atau beberapa file; menjawab pertanyaan spesifik tentang satu sesi (siapa, kapan, apa isinya, file apa yang lewat); memotong pcap besar menjadi pcap kasus; dan menyiapkan field untuk dikorelasikan dengan SIEM.
**Kapan bukan jawaban:** pcap yang sangat besar atau sangat banyak, yang lebih cepat diringkas dengan Zeek (Day 08) lalu di-pivot; pertanyaan tentang isi sesi TLS tanpa kunci (yang terlihat hanya metadata, Day 06); dan pertanyaan tentang kejadian yang tidak pernah lewat titik sensor, karena Wireshark hanya bisa membaca yang tersimpan.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day 01 (NSM, full packet capture, flow, SPAN/TAP, ring buffer, blind spot, capinfos) tidak diulang. Tabel ini memuat istilah yang baru dipakai di Day ini; kolom kanan memakai padanan dari pekerjaan NOC.

| Istilah | Arti singkat | Padanan di NOC/ISP |
|---|---|---|
| Dissector | Modul Wireshark yang mengurai satu protokol dari byte mentah menjadi field | Parser `show` yang mengubah register perangkat menjadi tabel yang bisa dibaca |
| Capture filter (BPF) | Filter saat menangkap; paket yang tidak cocok tidak pernah disimpan | ACL pada `monitor capture` atau sesi SPAN yang hanya membawa VLAN tertentu |
| Display filter | Filter atas paket yang sudah tersimpan; hanya menyembunyikan, tidak menghapus | `show ... \| include` atas buffer yang tetap utuh |
| Profil konfigurasi | Kumpulan preferensi, kolom, coloring rules, filter tersimpan, dan protokol yang dimatikan | Template konfigurasi terminal dan alias yang dipakai seluruh shift |
| Zona waktu tampilan | Zona waktu yang dipakai Wireshark untuk menampilkan timestamp yang tersimpan dalam UTC | `clock timezone` dan `service timestamps ... localtime` |
| Delta time | Selisih waktu dari paket sebelumnya (yang ditangkap atau yang ditampilkan) | Selisih antar baris log `debug` untuk melihat jeda |
| Stream index (`tcp.stream`) | Nomor urut sesi TCP di dalam satu file, dipakai Follow Stream | Nomor sesi di `show tcp brief` |
| Follow Stream | Tampilan yang merangkai isi satu sesi dua arah menjadi satu percakapan | Membaca transkrip satu sesi Telnet dari capture |
| Conversations / Endpoints | Statistik per pasangan alamat dan per alamat: paket, byte, waktu mulai, durasi | Top talkers NetFlow per pasangan dan per host |
| Protocol Hierarchy | Proporsi paket dan byte per protokol, tersusun berlapis | NBAR protocol discovery per interface |
| IO Graph | Grafik paket atau byte per interval waktu, dengan filter per grafik | Grafik utilisasi interface di NMS dengan filter per kelas trafik |
| Export Objects | Fitur untuk menyimpan file yang ditransfer lewat protokol plaintext tertentu | Mengambil ulang file konfigurasi yang terlihat lewat TFTP di capture |
| Expert Information | Daftar anomali hasil analisis Wireshark (retransmission, segmen hilang, malformed) | Error counter interface: menunjukkan masalah, bukan pelaku |
| tshark | Versi command line Wireshark, memakai dissector yang sama | Menjalankan `show` lewat skrip, bukan dari layar NMS |
| Pcap kasus | Cuplikan pcap yang hanya memuat host dan rentang waktu yang relevan, diberi nomor kasus dan hash | Cuplikan log yang dilampirkan ke tiket gangguan |

### 1.1 Membuka pcap tak tepercaya dengan aman

Pertanyaan pertama Dimas ("jangan sampai alat analisisnya sendiri jadi pintu masuk") bukan kehati-hatian berlebihan. Pcap egress berisi byte yang dikirim server di internet, termasuk server milik penyerang, dan setiap byte itu akan diurai oleh ratusan dissector Wireshark.

Kenapa ini nyata:

- Rilis 4.6.9 dan 4.4.19 (23 September 2026) memperbaiki 19 advisory keamanan, wnpa-sec-2026-92 sampai wnpa-sec-2026-110 [S18]. Sebagian besar berupa crash, infinite loop, atau kehabisan memori di dissector protokol dan parser file [S14][S18]. Bagi analyst, crash berarti analisis terhenti; sebagian kecil advisory menyebut kemungkinan eksekusi kode.
- Salah satunya, wnpa-sec-2026-106, menyangkut impor profil konfigurasi: profil yang dibuat khusus bisa membuat Wireshark crash dan mungkin menjalankan kode. Versi terdampak 4.6.0 sampai 4.6.8 dan 4.4.0 sampai 4.4.18; tidak ada workaround selain memperbarui ke 4.6.9, 4.4.19, atau yang lebih baru [S15]. Ini relevan langsung untuk pertanyaan kedua Dimas, karena profil akan dibagikan antar analyst (bagian 1.2).
- Dokumentasi Wireshark tentang hak capture menyebut alasan pemisahan hak: hampir seluruh kode Wireshark sebaiknya berjalan sebagai user biasa, dan hanya `dumpcap` yang diberi hak menangkap paket [S16]. Menjalankan Wireshark sebagai Administrator disebut sangat tidak aman, karena eksploit apa pun akan berjalan dengan hak penuh [S16].

Prinsip yang dipakai PT JAB, disusun dari sumber di atas:

1. **Versi stabil terbaru.** `jkt-nsm-ws01` memakai Wireshark 4.6.9, bukan rilis kandidat 5.0, dan diperbarui setiap ada rilis keamanan [S2][S14].
2. **User biasa, tanpa hak capture.** Workstation analisis hanya membaca file, jadi tidak perlu hak capture sama sekali. Di sensor, yang diberi hak hanya `dumpcap` (di Linux lewat file capabilities `cap_net_raw` dan `cap_net_admin`), bukan Wireshark GUI [S16].
3. **Bekerja di salinan, dengan hash.** File asli di sensor tidak diubah. Pcap kasus yang dipotong dari ring buffer diberi hash SHA-256 begitu selesai dibuat, dan hash itu dicatat di tiket (bagian 2.1).
4. **Resolusi nama jaringan mati.** Dokumentasi Wireshark mencatat bahwa resolusi nama bisa menambah paket DNS ke capture yang sedang berjalan, hasilnya bisa berbeda di mesin lain, dan cache-nya bisa basi [S1]. Untuk pcap tak tepercaya ada alasan tambahan: reverse lookup atas IP penyerang mengirim pertanyaan PTR yang pada akhirnya dijawab server DNS yang dikelola pemilik blok alamat itu, sehingga pemiliknya bisa melihat bahwa alamatnya sedang diperiksa. Di tshark, `-n` mematikan resolusi nama jaringan dan port [S8].
5. **Potong dulu, buka kemudian.** File ratusan GB tidak dibuka di GUI. Potong dengan tshark ke host dan rentang waktu yang relevan (bagian 2.1), supaya jumlah byte asing yang diurai GUI sekecil mungkin dan analisis tidak tersendat.
6. **File hasil Export Objects adalah sampel.** File yang diekstrak dari pcap (bagian 1.8) disimpan di folder kasus tanpa izin eksekusi, di-hash, dan tidak dibuka dengan aplikasi bawaan. Kebijakan akses pcap PT JAB dari Day 01 bagian 2.8 juga berlaku: pcap tidak disalin ke perangkat lain, dan data sensitif yang terlihat tanpa sengaja tidak disalin ke tiket.

Istilah resminya: dissector adalah modul yang mengurai satu protokol; advisory keamanan Wireshark diberi ID `wnpa-sec-YYYY-NN` [S14].

### 1.2 Profil forensik: kolom, coloring, dan filter tersimpan

Pertanyaan kedua Dimas ("bisa diulang Sari besok pagi") menyentuh masalah yang sering diremehkan. Dua analyst yang membuka pcap yang sama dengan setelan berbeda melihat kolom waktu berbeda, nama host berbeda (karena resolusi nama), dan warna berbeda, lalu menulis laporan yang tidak cocok satu sama lain.

Wireshark menyimpan setelan seperti itu di profil konfigurasi [S1]. Isi profil:

- preferensi, capture filter, dan display filter tersimpan;
- display filter macro dan coloring rules;
- protokol yang dimatikan dan aturan "Decode As";
- setelan "recent" seperti lebar kolom dan pilihan di menu View [S1].

Setelan di luar daftar itu disimpan di folder konfigurasi pribadi dan dipakai bersama oleh semua profil [S1]. Profil dikelola lewat `Edit > Configuration Profiles` atau Shift+Ctrl+A, diganti dari bagian "Profile" di status bar, dan bisa diekspor ke zip lalu diimpor di mesin lain; profil Default dan profil global tidak ikut diekspor [S1]. Profil juga bisa berganti otomatis lewat "Auto Switch Filter": saat file dibuka, Wireshark mencocokkan filter itu pada sejumlah paket pertama dan memakai profil pertama yang cocok [S1]. tshark memakai profil yang sama dengan opsi `-C <nama profil>` [S8].

Untuk forensik, profil berisi [S1]:

- **Kolom berguna**, misalnya `tcp.stream`, `http.host`, `dns.qry.name`, `tls.handshake.extensions_server_name`, delta time, dan kolom waktu UTC.
- **Coloring rules** untuk menyorot, misalnya reset merah dan DNS kuning.
- **Filter favorit tersimpan** sebagai tombol filter.
- **Resolusi nama jaringan mati** (bagian 1.1).

Profil membuat analisis konsisten dan cepat. Simpan dan versikan di repo (konfigurasi, bukan pcap). Karena impor profil pernah menjadi celah keamanan [S15], profil hanya diimpor dari repo tim, bukan dari zip kiriman orang lain, dan hanya di Wireshark 4.6.9 atau lebih baru.

### 1.3 Waktu di pcap: UTC tersimpan, zona waktu tampilan, dan delta

Pertanyaan ketiga datang dari kalimat terakhir Bambang: "jam di dashboard flow kami WIB". Bila ini tidak dibereskan, laporan SOC akan menyebut 02:21 dan Bambang akan mencari kejadian jam 02:21 WIB yang tidak pernah ada.

Yang perlu dipegang:

- **Yang tersimpan adalah UTC.** Format pcap dan pcapng, juga sebagian besar format capture lain, menyimpan waktu kedatangan paket sebagai UTC; Wireshark pun merepresentasikan timestamp secara internal dalam UTC [S7].
- **Yang ditampilkan adalah waktu lokal mesin pembaca.** Secara default Wireshark menampilkan timestamp dalam zona waktu komputer yang membuka file, sehingga dua orang di zona berbeda melihat jam yang berbeda untuk paket yang sama [S7]. `jkt-nsm-ws01` diset ke UTC seperti server lain, jadi kolom "Date and Time of Day" di sana menampilkan UTC, sedangkan laptop analyst yang ber-zona WIB menampilkan jam yang tujuh jam lebih maju.
- **UTC tidak berubah sepanjang tahun.** Dokumentasi Wireshark menyarankan perangkat jaringan dan server memakai UTC, mengatur zona waktu dulu baru jam lokal, dan menjaga jam dengan NTP [S7]. Indonesia tidak memakai daylight saving, tetapi pcap dari vendor atau korban di negara lain bisa memakainya.
- **Format tampilan dipilih di `View > Time Display Format`.** Pilihannya antara lain tanggal dan jam, jam saja, detik sejak epoch, detik sejak paket pertama, detik sejak paket sebelumnya yang ditangkap, dan detik sejak paket sebelumnya yang ditampilkan [S1]. Ada juga varian UTC; sejak 4.6.0, kolom waktu berformat UTC diberi akhiran "Z" sesuai ISO 8601, sedangkan kolom waktu lokal tidak, bahkan bila zona lokalnya UTC [S17]. Cek label menu persisnya di versi-mu.
- **Delta time menjawab "berapa lama jedanya".** "Seconds Since Previous Displayed Packet" (field `frame.time_delta_displayed`) berguna setelah display filter dipasang: jeda antar Client Hello ke satu tujuan langsung terlihat sebagai angka [S1][S3].

Field waktu yang dipakai di filter dan tshark [S3]:

| Field | Isi | Kapan dipakai |
|---|---|---|
| `frame.time` | Waktu kedatangan, ditampilkan dalam waktu lokal mesin | Membaca cepat di mesin yang zonanya kamu tahu |
| `frame.time_utc` | Waktu kedatangan dalam UTC | Laporan dan korelasi antar tim |
| `frame.time_epoch` | Detik sejak 1970-01-01 UTC | Skrip, CSV, dan Splunk (tidak ambigu) |
| `frame.time_relative` | Detik sejak paket pertama atau paket referensi | Durasi di dalam satu file |
| `frame.time_delta_displayed` | Jeda dari paket sebelumnya yang ditampilkan | Interval setelah filter (beacon, Day 11) |

Dua hal yang bergantung versi:

- Sejak 4.6.0, waktu absolut yang dikeluarkan lewat `-T fields`, PDML, dan custom column berpindah dari format bergaya asctime (contoh lama: `Dec 18, 2017 05:28:39.071704055 EST`) ke ISO 8601; preferensi `protocols.display_abs_time_ascii` mengembalikan format lama untuk sementara [S17]. Skrip lama yang mem-parsing format asctime akan rusak setelah upgrade. Dengan `-T json`, waktu absolut selalu ditulis ISO 8601 dalam UTC [S17].
- Di display filter, literal waktu ditulis ISO 8601 (misalnya `"2027-05-04T02:15:00Z"`) atau format lama; zona waktu bisa ditulis "Z" atau offset seperti `+07:00`. Bila zona tidak ditulis, nilainya dianggap waktu lokal mesin [S9]. Filter yang sama tanpa "Z" memberi hasil berbeda di `jkt-nsm-ws01` (UTC) dan di laptop ber-zona WIB.

Satu hal yang tidak bisa diperbaiki di Wireshark: akurasi jam sensor. Timestamp diberikan saat paket ditangkap oleh jam sensor; bila jam itu melenceng, semua analisis ikut melenceng. Karena itu selisih jam sensor terhadap NTP dicatat di laporan sensor, dan saat korelasi pertama dengan sumber lain, satu kejadian yang terlihat di kedua sumber dipakai untuk memeriksa selisihnya (bagian 2.8).

### 1.4 Capture filter vs display filter

Pertanyaan keempat datang dari Agung: bolehkah `jkt-pcap01` hanya menyimpan port 80 dan 443 supaya ring buffer 72 jam aman? Jawabannya bergantung pada perbedaan dua jenis filter berikut [S1].

| Aspek | Capture filter (BPF) | Display filter |
|---|---|---|
| Kapan | Saat menangkap; menentukan paket apa yang disimpan | Setelah ditangkap; menentukan paket apa yang ditampilkan |
| Sintaks | Berkeley Packet Filter (`host`, `port`, `tcp`, `net`) | Sintaks Wireshark (`ip.addr`, `tcp.port`, `http.request`) |
| Efek | Paket yang tidak cocok hilang permanen | Paket tetap di file, hanya disembunyikan |
| Forensik | Hati-hati: membuang bukti; biasanya tangkap luas | Aman: tidak mengubah pcap; pakai bebas |

Prinsip forensik: untuk analisis pcap yang sudah ada, kamu hampir selalu memakai display filter (tidak mengubah bukti). Capture filter dipakai saat menangkap sendiri, dan di forensik biasanya ditangkap luas (minim filter) agar tidak kehilangan bukti, lalu dipersempit dengan display filter.

Sintaks BPF yang perlu dikenali, dari man page pcap-filter [S13]:

- Primitive terdiri dari qualifier jenis (`host`, `net`, `port`, `portrange`), arah (`src`, `dst`; tanpa arah berarti `src or dst`), dan protokol (`ip`, `ip6`, `tcp`, `udp`, `arp`), dengan urutan protokol dulu lalu jenis, misalnya `tcp dst port 80`.
- `net 10.10.0.0/16` memakai notasi CIDR; `port 53` cocok untuk TCP, UDP, atau SCTP port 53, sedangkan `tcp port 443` hanya TCP.
- Negasi (`not`) punya prioritas tertinggi; `and` dan `or` setara dan dibaca dari kiri ke kanan. Pakai tanda kurung bila mencampur keduanya.
- Kata kunci `vlan` mengubah offset untuk sisa ekspresi karena mengasumsikan paket bertag 802.1Q [S13]. Di link trunk, filter `host 10.10.60.22` tanpa `vlan` bisa tidak cocok dengan paket bertag, dan sebaliknya.

Kembali ke pertanyaan Agung. Filter `tcp port 80 or tcp port 443` di `jkt-pcap01` akan membuang:

- koneksi ke port 8080 yang sedang ditanyakan Bambang, sehingga `SOC-2027-0605` tidak bisa dijawab dari pcap sama sekali;
- C2 dan exfiltration di port tidak lazim, yang justru yang paling ingin dilihat;
- protokol non-TCP seperti DNS dari resolver ke internet, NTP, dan QUIC (UDP 443).

Konfigurasi uji coba di Day 01 bagian 2.4 sudah memutuskan tanpa capture filter, karena interface capture tidak punya alamat IP sehingga trafik manajemen sensor tidak ikut terekam. Bila disk benar-benar menekan, opsi yang lebih aman adalah membuang trafik besar yang sudah dikenal dan bernilai forensik rendah (misalnya replikasi backup ke satu tujuan tetap) dengan filter yang sempit, tertulis, dan disetujui, atau mengurangi snaplen, bukan membatasi ke port tertentu. Setiap filter di sensor ditulis di laporan, karena "tidak ada di pcap" selalu dibaca bersama "apa yang memang tidak direkam".

### 1.5 Display filter yang sering dipakai dan jebakan operatornya

Pertanyaan kelima Bambang ("PC mana di balik NAT, dan dengan siapa saja ia bicara") dijawab dengan display filter. Tabel berikut adalah daftar kerja; cari baris tujuan yang sesuai pertanyaanmu.

| Tujuan | Filter |
|---|---|
| IP tertentu (sumber atau tujuan) | `ip.addr == 203.0.113.162` |
| Hanya dari/ke | `ip.src == ...` / `ip.dst == ...` |
| Satu subnet (CIDR) | `ip.addr == 10.10.60.0/24` |
| Beberapa host atau rentang (set) | `ip.addr in {10.10.60.20 .. 10.10.60.24}` |
| Port atau protokol | `tcp.port == 443`, `tcp.port in {80, 443, 8080}`, `dns`, `http`, `tls` |
| Request HTTP | `http.request`, `http.request.method == "POST"` |
| Host HTTP tertentu | `http.host contains "example"` |
| Query DNS | `dns.qry.name contains "tunnel"` |
| TLS SNI | `tls.handshake.extensions_server_name contains "..."` |
| Error/reset TCP | `tcp.flags.reset == 1`, `tcp.analysis.flags` |
| Rentang waktu tanpa ambigu zona | `frame.time >= "2027-05-04T03:10:00Z" && frame.time < "2027-05-04T03:15:00Z"` |
| Gabungan | `http.request and ip.dst == 203.0.113.162` |

Display filter mendukung `and`, `or`, `not`, perbandingan, `contains`, dan `matches` (regex). Wireshark memberi autocomplete dan mewarnai filter hijau (valid) atau merah (tidak valid) [S1]. Detail operator dari man page wireshark-filter 4.6.9 [S9]:

- **`==` dan `!=` pada field yang muncul lebih dari sekali.** `ip.addr` muncul dua kali di setiap paket IP (sumber dan tujuan). `==` (alias `any_eq`) berarti "salah satu sama", dan `!=` (alias `all_ne`) berarti "semua tidak sama", yaitu negasi logis dari `==` [S9]. Jadi `ip.addr != 203.0.113.162` menyembunyikan semua paket yang melibatkan alamat itu, sama dengan `!(ip.addr == 203.0.113.162)`. Ada juga `===` (semua sama) dan `!==` (ada yang tidak sama) [S9]. Panduan lama sering menyarankan bentuk `!(ip.addr == X)`; bentuk itu tetap benar dan paling jelas maksudnya.
- **Set dan rentang.** Operator `in` menerima daftar nilai di kurung kurawal, termasuk rentang dengan `..`, baik untuk port maupun alamat IP [S9].
- **CIDR** dipakai pada field alamat IP, misalnya `ip.addr == 129.111.0.0/16` [S9].
- **`contains`** mencari urutan karakter atau byte di sebuah protokol atau field, dan tidak bisa dipakai pada field atomik seperti angka atau alamat IP [S9]. Bila ragu soal huruf besar dan kecil, bandingkan setelah `lower()`, misalnya `lower(http.host) contains "example"` [S9].
- **`matches`** (alias `~`) memakai regex PCRE2 dan secara default tidak peka huruf besar dan kecil; awali pola dengan `(?-i)` bila perlu peka huruf [S9].
- **Fungsi** seperti `lower()`, `upper()`, `len()`, dan `string()` tersedia; `string()` mengubah field seperti nomor frame atau alamat menjadi teks supaya bisa dipakai dengan `matches` [S9].

Dua jebakan yang sering membuat filter "valid tetapi salah": nama field yang benar untuk versi lain (cek di display filter reference [S3]), dan `ip.addr` untuk trafik IPv6 (pakai `ipv6.addr`).

### 1.6 Statistics: memahami pcap besar sebelum membaca paket

Pertanyaan kelima juga punya sisi "dengan siapa saja". Membaca 1,4 juta paket satu per satu tidak menjawabnya; menu Statistics menjawabnya dalam satu menit [S1]. Tabel berikut adalah urutan pakainya; kolom kanan menyebut pertanyaan forensik yang dijawab.

| Statistik | Memberi | Kegunaan forensik |
|---|---|---|
| Capture File Properties | Rentang waktu, jumlah paket, ukuran, hash file | Memastikan file mencakup waktu kejadian |
| Protocol Hierarchy | Proporsi tiap protokol | Melihat apa isi pcap; protokol tak lazim |
| Conversations | Pasangan endpoint dengan byte/paket | Siapa bicara dengan siapa, volume (exfil) |
| Endpoints | Daftar host dengan trafik | Host paling aktif; IP eksternal |
| IO Graph | Trafik per waktu | Lonjakan, pola beacon (Day 11) |
| DNS, HTTP, dll. | Statistik per protokol | Query, request terbanyak |

Detail yang membuat angka-angka itu terbaca benar:

- **Protocol Hierarchy** menghitung satu paket di setiap protokol yang dikandungnya, sehingga persentase antar baris tidak dijumlahkan menjadi 100% [S1]. Kolom "End Packets" dan "End Bytes" hanya menghitung paket di mana protokol itu adalah lapisan teratas [S1]. Baris HTTP yang kecil di bawah TCP yang besar biasanya berarti sebagian besar paket adalah segmen data tanpa lapisan atas sendiri, misalnya bagian body unduhan yang baru dirakit di segmen terakhir.
- **Conversations** menampilkan alamat, port (untuk TCP dan UDP), paket dan byte per arah, waktu mulai relatif atau absolut, durasi, dan bit rate per arah [S1]. Opsi "Limit to display filter" membatasi daftar ke filter aktif, "Absolute start time" mengganti waktu relatif menjadi jam, dan tombol Copy mengekspor daftar ke CSV, YAML, atau JSON [S1]. Dari dialog ini kamu bisa langsung membuka Follow Stream, grafik TCP, atau IO Graph untuk conversation yang dipilih [S1].
- **Sejak 4.6.0**, Conversations dan Endpoints bisa menampilkan angka byte dan bit rate persis, bukan format SI seperti "1 GB"; bawaannya mengikuti preferensi `conv.machine_readable`, yang juga memengaruhi `-z conv` dan `-z endpoints` di tshark [S17]. Untuk laporan, angka persis lebih aman daripada pembulatan.

Alur umum: buka pcap besar, lihat Protocol Hierarchy (apa isinya), lalu Conversations (siapa dan berapa), lalu pivot ke sesi menarik dengan display filter dan Follow Stream. Ini mencegah tenggelam di ribuan paket.

### 1.7 Follow Stream

Pertanyaan keenam ("isinya apa") dijawab di sini. Setelah Conversations menunjukkan pasangan yang menarik, Follow Stream merangkai satu sesi (TCP, UDP, HTTP, TLS) menjadi satu tampilan terurut [S1]:

- Klik kanan paket, Follow, lalu TCP/UDP/HTTP/TLS Stream.
- Menampilkan isi sesi: untuk HTTP, request dan response; untuk TCP mentah, byte dua arah.
- Wireshark otomatis menerapkan display filter `tcp.stream eq N` untuk sesi itu.

Detail dari User's Guide 4.6 [S1]:

- Jenis stream yang bisa diikuti: TCP, UDP, DCCP, TLS, HTTP, HTTP/2, QUIC, WebSocket, SIP, dan USB CDC. Pilihan yang tidak relevan untuk paket terpilih tidak muncul di menu.
- Data dari client ke server berwarna merah, dari server ke client biru (bergantung tema).
- Format tampilan: ASCII, C Arrays, EBCDIC, Hex Dump, UTF-8, UTF-16, YAML, dan Raw. Raw dipakai untuk menyimpan data apa adanya ke alat lain.
- "Filter Out This Stream" menyembunyikan sesi itu dari daftar paket, berguna untuk menyisihkan sesi yang sudah dinilai jinak. Tombol "Back" mengembalikan filter sebelumnya, sedangkan "Close" mempertahankan filter stream.
- Kotak "Find" mencari teks di dalam stream, dan pilihan arah bisa membatasi tampilan ke satu sisi.
- Follow TLS hanya menampilkan isi bila kunci sesi TLS tersedia [S1].

Forensik: Follow Stream mengubah ratusan paket menjadi satu percakapan yang bisa dibaca. Untuk HTTP tanpa enkripsi, kamu melihat URL, header, dan isi; untuk TLS, hanya metadata (kecuali ada keylog, Day 06). Header seperti `Authorization` juga ikut terlihat, sehingga kebijakan pengungkapan data sensitif berlaku di sini: kredensial yang terlihat tidak disalin ke tiket (bagian 2.5).

tshark punya padanannya, `-z follow,<protokol>,<mode>,<filter>`, dengan protokol antara lain tcp, udp, tls, http, http2, dan quic, mode ascii, hex, raw, utf-8, atau yaml, dan filter berupa pasangan IP:port atau nomor stream [S8].

### 1.8 Export Objects dan Expert Information

Sisa pertanyaan keenam ("file apa yang diunduh, dan apakah capture-nya utuh") dijawab dua fitur ini.

- **Export Objects** (`File > Export Objects > DICOM/FTP-DATA/HTTP/IMF/SMB/TFTP`): mengekstrak file yang ditransfer lewat protokol tertentu dari pcap [S1]. Dialognya menampilkan nomor paket, hostname, content type, ukuran, dan nama file; untuk HTTP nama file diambil dari bagian akhir URI [S1]. "Save" menyimpan satu objek, "Save All" menyimpan semua objek ke satu folder, termasuk yang tidak tampil karena text filter [S1]. Berguna memulihkan file yang diunduh (payload, dokumen) untuk hashing dan pencocokan ke intel atau YARA. Hanya untuk protokol tanpa enkripsi.
- **Export Objects di tshark:** `--export-objects <protokol>,<folder>` menyimpan objek langsung ke folder; nama yang sama diberi nomor urut sebelum ekstensi, dan `--export-objects help` menampilkan daftar protokol yang didukung versi-mu [S8]. Sejak 4.6.0 ada tambahan `x509af` untuk sertifikat X.509 [S17].
- **Expert Information** (`Analyze > Expert Information`): daftar anomali yang dideteksi Wireshark (retransmission, reset, malformed) [S1]. Berguna menemukan masalah koneksi dan sebagian sinyal, tetapi bukan deteksi ancaman; tafsir dengan konteks. tshark punya `-z expert`, yang bisa dibatasi ke tingkat keparahan dan filter, misalnya `-z expert,warn` [S8].

Hubungan keduanya penting: Export Objects merakit file dari segmen TCP yang tersimpan. Bila Expert Information menunjukkan "Previous segment not captured" di stream yang sama, file hasil ekspor kemungkinan tidak utuh dan hash-nya tidak akan cocok dengan file aslinya. Peringatan itu bisa berarti paket memang hilang di jaringan, atau sensor yang tidak sempat merekam; statistik drop sensor (Day 01 bagian 2.4) membantu membedakannya.

Parser objek juga bagian dari permukaan serangan: rilis 4.6.9 memperbaiki antara lain masalah memori di ekspor objek DICOM dan SMB [S18]. Ini satu alasan lagi untuk selalu memakai versi terbaru di workstation analisis.

### 1.9 tshark untuk command line

Pertanyaan ketujuh Dimas ("daftar request lengkap untuk dicocokkan ke Splunk") tidak praktis dijawab dengan menyalin dari layar. tshark adalah Wireshark versi command line dengan dissector yang sama [S1]:

- Membaca pcap: `tshark -r file.pcap`.
- Display filter: `-Y "http.request"`.
- Field tertentu: `-T fields -e ip.src -e http.host`.
- Statistik: `-z` (mis. `-z conv,tcp`).

tshark berguna untuk otomasi ringan, memproses banyak pcap, dan mengekstrak field ke CSV untuk analisis lanjut. Untuk skala besar, Zeek (Day 08) lebih cocok; tshark untuk ekstraksi cepat dan skrip.

Opsi yang paling sering dipakai, dari man page tshark 4.6.9 [S8]. Baca kolom kanan untuk jebakan yang sering muncul.

| Opsi | Fungsi | Catatan |
|---|---|---|
| `-r <file>` | Membaca file capture | Filter yang ditulis di akhir perintah saat membaca file diperlakukan sebagai display filter |
| `-Y <filter>` | Display filter; paket yang cocok dicetak atau ditulis | Bersama `-w`, filter menentukan paket yang ditulis ke file baru |
| `-2 -R <filter>` | Analisis dua tahap dengan read filter di tahap pertama | `-R` hanya berarti bila ada `-2`; untuk satu tahap pakai `-Y` |
| `-w <file>` | Menulis paket mentah ke file (default pcapng) | Tidak mencetak paket ke layar |
| `-n` | Mematikan resolusi nama jaringan dan port | Wajib untuk pcap tak tepercaya (bagian 1.1) |
| `-t ud` / `-t ad` / `-t e` | Format waktu kolom: UTC dengan tanggal, lokal dengan tanggal, epoch | Juga ada `r` (sejak paket pertama), `d` dan `dd` (delta) |
| `-T fields -e <field>` | Mencetak nilai field yang dipilih | Minimal satu `-e` |
| `-E header=y` | Baris pertama berisi nama field | Juga `separator=,`, `quote=d`, `occurrence=f` (hanya kemunculan pertama), `aggregator=` |
| `-q -z <statistik>` | Hanya statistik, tanpa daftar paket | `conv,tcp`, `endpoints,ip`, `io,phs`, `io,stat,<detik>`, `http,tree`, `expert` |
| `-C <profil>` | Memakai profil konfigurasi tertentu | Kolom dan preferensi sama dengan GUI |
| `-o <pref>:<nilai>` | Mengubah satu preferensi untuk satu kali jalan | Tidak disimpan |
| `--export-objects <proto>,<folder>` | Menyimpan objek ke folder | Daftar protokol: `--export-objects help` |

Untuk field yang bisa muncul lebih dari sekali di satu paket, default `-E occurrence=a` mencetak semuanya dipisah koma [S8]; ini sumber kolom CSV yang bergeser bila tidak diantisipasi.

## 2. Contoh dan langkah praktis: pcap pertama dari `jkt-pcap01`

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi; analisis atas pcap publik untuk latihan (misalnya pcap dari malware-traffic-analysis.net, dipakai sebagai metode [S4]) atau pcap lab sendiri dikerjakan di bagian 3. IOC di-defang bila dicatat di luar sistem kasus. Domain eksternal memakai akhiran `.example` atau `.example.net`, dan IP eksternal dari rentang dokumentasi. Format keluaran tshark dan capinfos bisa sedikit berbeda antar versi; yang dipakai di sini 4.6.9.

**Asumsi lingkungan:** `jkt-nsm-ws01` (Linux, zona waktu UTC, Wireshark/tshark 4.6.9) me-mount direktori `/pcap` milik `jkt-pcap01` secara read-only di `/mnt/pcap01`. File di sana dibuat dumpcap dengan konfigurasi Day 01 bagian 2.4 (`-b filesize:1000000 -b files:8400`), sehingga namanya berpola `egress-jkt_NNNNN_YYYYMMDDhhmmss.pcapng`. Folder kasus berada di `/cases/<nomor tiket>/`.

### 2.1 Menyiapkan pcap kasus dari ring buffer

Langkah ini menjawab pertanyaan pertama dan sebagian pertanyaan ketiga: file mana yang dibuka, bagaimana memotongnya dengan aman, dan bagaimana memastikan rentang waktunya benar sebelum satu paket pun dibaca di GUI.

**Tujuan:** membuat satu pcap kasus berisi trafik lima workstation `NOC-VENDOR-DIRECT` pada 09:15 sampai 10:45 WIB, lengkap dengan hash dan rentang waktu yang terverifikasi.

**Langkah 1, menerjemahkan waktu.** Bambang menyebut 09:20 sampai 10:00 WIB. Jendela kerja diambil sedikit lebih lebar, 09:15 sampai 10:45 WIB, yaitu 02:15:00 sampai 03:45:00 UTC (WIB adalah UTC+7). Man page dumpcap menyebut nama file ring buffer memakai tanggal dan jam pembuatan file, tetapi tidak menyebut zona waktunya [S10]. Karena itu semua sensor PT JAB diset UTC, dan nama file pertama dicocokkan sekali dengan `capinfos -a` saat uji coba dimulai.

**Langkah 2, memilih file.** Pada jam kerja, egress Jakarta rata-rata sekitar 35% dari 1 Gbps, kira-kira 43,75 MB per detik (Day 01 bagian 2.3), sehingga satu file 1 GB hanya mencakup sekitar 23 detik. Jendela 90 menit berarti sekitar 239 file.

```bash
mkdir -p /cases/SOC-2027-0605/carve
ls /mnt/pcap01/egress-jkt_*.pcapng \
  | awk -F_ '{ts=substr($NF,1,14)} ts>="20270504021400" && ts<"20270504034500"' \
  > /cases/SOC-2027-0605/files.txt
wc -l < /cases/SOC-2027-0605/files.txt
```

| Bagian | Fungsi |
|---|---|
| `awk -F_ '{ts=substr($NF,1,14)}'` | Mengambil 14 digit timestamp dari bagian terakhir nama file |
| `ts>="20270504021400"` | Mulai satu menit sebelum jendela, supaya file yang sedang berjalan pada 02:15:00 ikut terbawa |
| `ts<"20270504034500"` | Berhenti di file yang dibuat sebelum 03:45:00 |
| `files.txt` | Daftar file sumber, disimpan di folder kasus sebagai catatan asal bukti |

Keluaran ilustrasi: `239`.

**Langkah 3, memotong dan menggabungkan.**

```bash
while read f; do
  tshark -n -r "$f" \
    -Y 'ip.addr in {10.10.60.20 .. 10.10.60.24} && frame.time >= "2027-05-04T02:15:00Z" && frame.time < "2027-05-04T03:45:00Z"' \
    -w "/cases/SOC-2027-0605/carve/$(basename "$f")"
done < /cases/SOC-2027-0605/files.txt

mergecap -w /cases/SOC-2027-0605/SOC-2027-0605_noc-direct_0215Z-0345Z.pcapng \
  /cases/SOC-2027-0605/carve/*.pcapng
```

| Bagian | Fungsi |
|---|---|
| `tshark -n -r "$f"` | Membaca satu file sumber tanpa resolusi nama |
| `ip.addr in {10.10.60.20 .. 10.10.60.24}` | Lima workstation di belakang NAT `198.51.100.202`, ditulis sebagai rentang di dalam set [S9] |
| `frame.time >= "...Z"` | Batas waktu dengan zona eksplisit; tanpa "Z", nilai dibaca sebagai waktu lokal mesin [S9] |
| `-w` | Paket yang cocok dengan `-Y` ditulis ke file baru [S8] |
| `mergecap -w <keluaran> <masukan>` | Menggabungkan file secara kronologis berdasarkan timestamp tiap frame [S12] |

Pemotongan ini adalah pemrosesan trafik lima workstation untuk tiket keamanan yang sudah dibuka, dengan rentang 90 menit, dan dicatat di tiket. Itu berbeda dengan permintaan mengambil semua trafik milik satu karyawan, yang menurut kebijakan akses di Day 01 bagian 2.8 butuh persetujuan SOC lead, DPO, dan Legal.

**Langkah 4, ringkasan dan hash.**

```bash
capinfos -M -c -s -d -u -S -x -z -H \
  /cases/SOC-2027-0605/SOC-2027-0605_noc-direct_0215Z-0345Z.pcapng
```

| Opsi | Fungsi [S11] |
|---|---|
| `-M` | Angka mentah, tanpa singkatan SI |
| `-c`, `-s`, `-d` | Jumlah paket, ukuran file, ukuran data |
| `-u` | Durasi antara paket paling awal dan paling akhir |
| `-S` | Waktu paling awal dan paling akhir sebagai detik sejak 1970 |
| `-x`, `-z` | Laju byte rata-rata, ukuran paket rata-rata |
| `-H` | Hash SHA256 dan SHA1 file |

Keluaran ilustrasi:

```
File name:            /cases/SOC-2027-0605/SOC-2027-0605_noc-direct_0215Z-0345Z.pcapng
Number of packets:    1440536
File size:            1529131546 bytes
Data size:            1483034394 bytes
Capture duration:     5399.612789 seconds
Earliest packet time: 1809396900.183412
Latest packet time:   1809402299.796201
Data byte rate:       274655.69 bytes/s
Average packet size:  1029.50 bytes
SHA256:               <64 karakter heksadesimal, dicatat di tiket>
SHA1:                 <40 karakter heksadesimal>
```

**Cara membaca hasil:**

- Epoch `1809396900` sama dengan 2027-05-04 02:15:00 UTC dan `1809402299` sama dengan 03:44:59 UTC; konversi di shell: `date -u -d @1809396900`. Paket pertama dan terakhir masuk jendela, jadi filter waktu bekerja.
- Durasi 5.399,6 detik, sekitar 90 menit, sesuai jendela.
- Laju rata-rata sekitar 274,7 KB per detik (sekitar 2,2 Mbps) dan ukuran paket rata-rata 1.029,5 byte. Rata-rata yang tinggi ini sudah memberi petunjuk: sebagian besar paket berukuran penuh, khas unduhan besar.
- `-S` dipakai karena epoch tidak bergantung zona waktu mesin. Man page menyebut SHA1 bisa dihapus di versi mendatang [S11], jadi yang dicatat di tiket adalah SHA256.

**Variasi:** bila `tcpdump` tersedia, pemotongan berdasarkan alamat saja bisa dikerjakan dengan capture filter BPF atas file (`tcpdump -r <file> -w <keluaran> 'host 10.10.60.20 or host 10.10.60.21 ...'`), yang tidak mengurai protokol sehingga biasanya jauh lebih cepat daripada `-Y`; batas waktu lalu dipasang di tahap kedua dengan tshark. Ukur perbandingan kecepatannya di lab sebelum memakainya sebagai standar. Untuk pemotongan berdasarkan rentang waktu saja, `editcap` juga bisa dipakai; cek opsinya di man page versi-mu.

**Kapan gagal:**

- Filter waktu ditulis tanpa "Z" di mesin ber-zona WIB, sehingga jendela bergeser tujuh jam dan pcap kasus kosong atau salah isi.
- Ring buffer sudah menimpa file yang dibutuhkan; di jam kerja, 8.400 file mencakup sekitar 53 jam, bukan 72 (Day 01 bagian 2.3).
- File terakhir masih sedang ditulis dumpcap, sehingga hasil potongnya belum lengkap; ulangi setelah file itu ditutup.
- Pemotongan memakan waktu lama: menguraikan sekitar 239 GB dengan tshark bisa berlangsung puluhan menit. Pada kasus ini prosesnya berjalan dari 10:58 sampai 11:41 WIB.

### 2.2 Profil `JAB-NSM`

Profil ini menjawab pertanyaan kedua: Sari akan membuka pcap yang sama besok pagi dengan kolom, warna, dan filter yang sama.

**Tujuan:** satu profil tim yang menampilkan waktu UTC, kolom forensik, dan filter favorit, tanpa resolusi nama jaringan.

Isi profil, dibuat di `Edit > Configuration Profiles` lalu `View > Time Display Format` dan `Edit > Preferences > Appearance > Columns` [S1]:

```
Profil      : JAB-NSM (dibuat 2027-05-04, pemilik: <kamu>, reviewer: Sari Kusuma)
Waktu       : UTC Date and Time of Day (label menu cek di versi-mu); presisi otomatis
Kolom       : No. | Time (UTC) | Delta displayed | Source | Src port | Destination | Dst port |
              Protocol | Length | tcp.stream | http.host | tls.handshake.extensions_server_name |
              dns.qry.name | Info
Coloring    : tcp.flags.reset == 1  -> merah
              dns                   -> kuning
              http.request          -> hijau muda
              ip.addr in {10.10.60.20 .. 10.10.60.24}  -> biru muda (host NOC-VENDOR-DIRECT)
Tombol filter: "HTTP req"    http.request
              "ClientHello" tls.handshake.type == 1
              "RST"         tcp.flags.reset == 1
              "Non-HTTP 80" tcp.port == 80 && !http
Name resolution: network OFF, transport OFF, MAC ON (nama vendor dari OUI)
Ekspor      : zip ke repo GitLab internal jab-nsm/wireshark-profiles; impor hanya dari repo ini,
              hanya di Wireshark >= 4.6.9 (wnpa-sec-2026-106)
```

Cara membaca elemennya:

- **Delta displayed** adalah `frame.time_delta_displayed`; setelah filter ke satu tujuan, kolom ini langsung menampilkan interval antar koneksi (bagian 2.7).
- **Kolom SNI dan `http.host`** membuat nama tujuan terlihat tanpa membuka detail paket, dan menggantikan kebutuhan resolusi nama: nama berasal dari isi paket itu sendiri, bukan dari lookup saat analisis.
- **Resolusi nama MAC tetap menyala** karena hanya memakai file OUI lokal, tanpa trafik keluar. Resolusi jaringan dan port dimatikan (bagian 1.1).
- Lokasi folder profil di mesin-mu terlihat di `Help > About Wireshark > Folders`.

**Variasi:** pakai profil yang sama di tshark dengan `tshark -C JAB-NSM -r <file>`, supaya kolom keluaran teks sama dengan yang dilihat di GUI [S8].

**Kapan gagal:** profil diekspor dari mesin lain dengan versi Wireshark berbeda dan custom column merujuk field yang namanya berubah; kolom itu kosong tanpa pesan error. Cek setiap kolom setelah impor, dan simpan versi Wireshark pembuat profil di catatan repo.

### 2.3 Orientasi pcap baru

Langkah ini menjawab bagian "dengan siapa saja" dari pertanyaan kelima, sebelum satu paket pun dibaca.

Langkah pertama membuka pcap yang belum dikenal:

```
# di Wireshark GUI: Statistics > Protocol Hierarchy
# lalu Statistics > Conversations (tab TCP/UDP), sortir Bytes
```

Dengan tshark:

```
tshark -r capture.pcap -q -z io,phs
tshark -r capture.pcap -q -z conv,tcp
```

- `-z io,phs` menampilkan protocol hierarchy; `-z conv,tcp` conversations TCP.
- Cara membaca: Protocol Hierarchy menunjukkan apa isi pcap (HTTP? TLS? DNS banyak?); Conversations menunjukkan pasangan dengan volume terbesar (kandidat exfil) dan IP eksternal.

Untuk pcap kasus `SOC-2027-0605`, perintahnya:

```bash
cd /cases/SOC-2027-0605
tshark -n -r SOC-2027-0605_noc-direct_0215Z-0345Z.pcapng -q -z io,phs
tshark -n -r SOC-2027-0605_noc-direct_0215Z-0345Z.pcapng -q -z endpoints,ip
```

Keluaran ilustrasi Protocol Hierarchy (diringkas):

```
Protocol Hierarchy Statistics
eth                        frames:1440536 bytes:1483034394
  ip                       frames:1440536 bytes:1483034394
    tcp                    frames:1440536 bytes:1483034394
      tls                  frames:4156    bytes:3011873
      http                 frames:4       bytes:2134
        media              frames:2       bytes:1498
```

Keluaran ilustrasi Endpoints IPv4 (diringkas, diurutkan menurut paket):

```
Address          Packets     Bytes
10.10.60.21      1434936     1479485126
203.0.113.162    1433834     1478753906
10.10.60.20         1530        1021877
10.10.60.23         1388         905114
10.10.60.24         1344         898215
10.10.60.22         1338         724062
203.0.113.163        492         161944
... (alamat portal vendor lain, masing-masing di bawah 1.200 paket)
```

Lalu Conversations di GUI, tab TCP, diurutkan menurut Bytes, dengan "Absolute start time" aktif dan angka persis (bagian 1.6). Hasil yang disalin dengan Copy > as CSV (diringkas ke kolom utama):

```
Address A,Port A,Address B,Port B,Packets,Bytes,Packets A->B,Bytes A->B,Packets B->A,Bytes B->A,Abs Start,Duration
10.10.60.21,51744,203.0.113.162,8080,1433834,1478753906,477947,31544724,955887,1447209182,2027-05-04 02:21:07.552Z,2496.766
10.10.60.22,52318,203.0.113.163,443,15,4912,8,1406,7,3506,2027-05-04 03:13:05.611Z,0.602
10.10.60.22,52310,203.0.113.163,80,12,4760,7,760,5,4000,2027-05-04 03:12:41.161Z,0.412
... (334 conversation lain: 31 sesi lain ke 203.0.113.163:443 dan 303 sesi TLS ke portal vendor)
```

**Cara membaca hasil:**

- **Tidak ada UDP sama sekali.** Workstation memakai resolver internal `jkt-res01` dan `jkt-res02`, yang tidak berada di jalur egress; yang keluar ke internet adalah resolver itu sendiri. Jadi pertanyaan DNS untuk kasus ini dijawab dari index `dns`, bukan dari pcap egress.
- **Satu conversation memakan hampir semua byte.** `10.10.60.21` (`JKT-WS-2006`) ke `203.0.113.162:8080`: 1.478.753.906 byte, sekitar 99,7% dari total data, mulai 02:21:07 UTC (09:21:07 WIB) selama 2.496,8 detik (sekitar 41,6 menit, berakhir 10:02:44 WIB). Ini yang dilihat Bambang. Arah B ke A (server ke workstation) membawa 1.447.209.182 byte: unduhan, bukan unggahan.
- **Satu tujuan kecil yang tidak disebut Bambang.** `10.10.60.22` (`JKT-WS-2007`) berbicara dengan `203.0.113.163`: satu koneksi HTTP port 80 pukul 03:12:41 UTC (10:12:41 WIB), lalu 32 sesi TLS ke port 443 mulai 03:13:05 UTC. Totalnya hanya 492 paket. Dengan sampling 1:1000 di router edge, peluang satu koneksi 12 paket terwakili minimal satu paket di flow hanya sekitar 1,2% (1 - 0,999^12), dan peluang ke-33 koneksi itu muncul sama sekali sekitar 39% (1 - 0,999^492). Itulah sebabnya Bambang tidak melihatnya. Cara menghitungnya sama dengan Day 01 bagian 1.4.
- **HTTP hanya 4 frame.** Baris `http` di Protocol Hierarchy menghitung frame tempat request atau response selesai dirakit; segmen data unduhan besar tercatat sebagai TCP saja (bagian 1.6). Dua request, dua response.

**Variasi:** `tshark -q -z conv,tcp` memberi tabel yang sama di terminal, diurutkan menurut jumlah frame [S8]; `-z http,tree` memberi distribusi metode dan kode status HTTP [S8].

**Kapan gagal:** pcap kasus dipotong hanya berdasarkan IP eksternal yang disebut pelapor (`203.0.113.162`); `203.0.113.163` tidak akan pernah terlihat. Potong berdasarkan host internal yang dipertanyakan, bukan hanya tujuan yang sudah diketahui.

### 2.4 Mempersempit dengan display filter

Langkah ini adalah pivot dari Statistics ke paket: dua tujuan, dua pertanyaan berbeda.

```
ip.addr == 203.0.113.20
http.request and ip.dst == 203.0.113.20
dns.qry.name contains "example"
tls.handshake.type == 1
```

- `tls.handshake.type == 1` memfilter Client Hello (berisi SNI, Day 06).
- Gabungkan untuk fokus: request HTTP ke IP tertentu, atau query DNS yang mencurigakan.
- Cek nama field (mis. `tls.handshake.extensions_server_name`) di Wireshark 4.6.

Filter yang dipakai untuk `SOC-2027-0605`, dengan profil `JAB-NSM`:

```
http.request
ip.addr == 203.0.113.163
ip.addr == 203.0.113.163 && tls.handshake.type == 1
!(ip.addr == 203.0.113.162) && !(tcp.port == 443 && !(ip.addr == 203.0.113.163))
```

| Filter | Pertanyaan yang dijawab |
|---|---|
| `http.request` | Request HTTP plaintext apa saja yang keluar dari lima host itu |
| `ip.addr == 203.0.113.163` | Seluruh interaksi `JKT-WS-2007` dengan tujuan kecil itu, urut waktu |
| `... && tls.handshake.type == 1` | Client Hello saja: SNI dan jeda antar sesi TLS |
| Baris keempat | Sisa trafik setelah unduhan besar dan TLS ke portal vendor disisihkan; dipakai untuk memastikan tidak ada protokol lain yang terlewat |

Keluaran ilustrasi untuk `http.request` (kolom profil `JAB-NSM`, diringkas):

```
No.      Time (UTC)                  Source       Destination    Dst port  tcp.stream  http.host                            Info
418      2027-05-04 02:21:07.596118Z 10.10.60.21  203.0.113.162  8080      21          fw-mirror.oltvendor.example:8080     GET /olt/gpon-x9/firmware/x9-r8.4.2.bin HTTP/1.1
1437794  2027-05-04 03:12:41.204381Z 10.10.60.22  203.0.113.163  80        218         203.0.113.163                        GET /a.hta HTTP/1.1
```

Keluaran ilustrasi untuk Client Hello ke `203.0.113.163` (enam baris pertama dan dua baris terakhir dari 32):

```
No.      Time (UTC)                  Delta displayed  Source       Destination    SNI
1437806  2027-05-04 03:13:05.611Z    0.000000         10.10.60.22  203.0.113.163  static-update.example.net
1437890  2027-05-04 03:14:06.011Z    60.400000        10.10.60.22  203.0.113.163  static-update.example.net
1437973  2027-05-04 03:15:05.711Z    59.700000        10.10.60.22  203.0.113.163  static-update.example.net
1438058  2027-05-04 03:16:06.911Z    61.200000        10.10.60.22  203.0.113.163  static-update.example.net
1438141  2027-05-04 03:17:05.811Z    58.900000        10.10.60.22  203.0.113.163  static-update.example.net
1438226  2027-05-04 03:18:06.111Z    60.300000        10.10.60.22  203.0.113.163  static-update.example.net
...
1440326  2027-05-04 03:43:09.111Z    60.000000        10.10.60.22  203.0.113.163  static-update.example.net
1440410  2027-05-04 03:44:08.911Z    59.800000        10.10.60.22  203.0.113.163  static-update.example.net
```

**Cara membaca hasil:**

- Kolom Delta displayed pada baris pertama bernilai nol karena itu paket pertama yang tampil setelah filter; sebelum filter dipasang, nilainya akan berbeda.
- 32 Client Hello dengan 31 jeda; median 60,1 detik, minimum 57,8, maksimum 62,6. Interval yang rapat seperti ini adalah kandidat beacon; cara mengukurnya dengan benar (koefisien variasi, jitter) ada di Day 11. Mulainya 24 detik setelah unduhan `/a.hta` juga dicatat sebagai urutan waktu, bukan bukti hubungan.
- Request firmware memakai `http.host` dengan nama vendor dan port 8080; request `/a.hta` memakai IP langsung sebagai Host. Request yang memakai IP mentah sebagai Host adalah sinyal, karena browser dan aplikasi sah biasanya memakai nama.

**Variasi:** tambahkan `&& frame.time >= "2027-05-04T10:10:00+07:00"` untuk memakai offset WIB secara eksplisit; hasilnya sama dengan menulis `03:10:00Z` [S9].

**Kapan gagal:** filter `ip.addr != 203.0.113.162 || tcp.port != 443` ditulis dengan maksud "bukan unduhan dan bukan TLS"; karena `||`, filter itu meloloskan hampir semua paket. Tulis negasi dengan `!( ... )` dan baca ulang logikanya sebelum percaya hasilnya.

### 2.5 Follow Stream untuk membaca sesi

Langkah ini menjawab pertanyaan keenam untuk dua stream: unduhan besar yang ditanyakan Bambang, dan request kecil yang muncul di bagian 2.3.

```
# klik kanan paket HTTP > Follow > HTTP Stream
# atau display filter manual:
tcp.stream eq 12
```

Keluaran ilustrasi (HTTP stream, tanpa enkripsi):

```
GET /a.hta HTTP/1.1
Host: 203.0.113.20
User-Agent: Mozilla/4.0 (compatible; ...)

HTTP/1.1 200 OK
Content-Type: application/octet-stream
...
```

- Cara membaca: User-Agent tidak lazim, path aneh (`/a.hta`), dan response berisi konten yang diunduh adalah sinyal. File `.hta` (HTML Application) dijalankan oleh `mshta.exe`, program bawaan Windows; penyerang sering memakai program bawaan seperti ini (disebut LOLBin, living-off-the-land binary) untuk mengunduh dan menjalankan kode tanpa membawa alat sendiri (ATT&CK T1218.005) [S6]. Di kabel, jejaknya adalah request HTTP biasa dengan User-Agent milik komponen Windows, bukan browser, ke host yang sering berupa IP langsung. Follow Stream menyatukan request dan response itu dalam satu tampilan.

Untuk `SOC-2027-0605`, stream pertama adalah `tcp.stream eq 21` (unduhan besar). Keluaran ilustrasi bagian awal, dengan kredensial disamarkan:

```
GET /olt/gpon-x9/firmware/x9-r8.4.2.bin HTTP/1.1
Host: fw-mirror.oltvendor.example:8080
User-Agent: OLT-EMS-Updater/5.2
Authorization: Basic [disamarkan, tidak disalin ke tiket]
Accept: */*

HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Length: 1384120320
...
```

Cara membaca stream 21:

- Host `fw-mirror.oltvendor.example`, path firmware OLT seri GPON-X9 versi r8.4.2, dan User-Agent aplikasi element management OLT. `Content-Length` 1.384.120.320 byte, sekitar 1,29 GiB, cocok dengan perkiraan Bambang dari flow.
- Bambang mengonfirmasi bahwa engineer di `JKT-WS-2006` memang mengunduh firmware untuk jendela upgrade OLT malam itu. Konfirmasi manusia saja belum cukup; hash file di bagian 2.6 melengkapinya.
- Header `Authorization: Basic` berarti username dan password akun mirror vendor terkirim dalam bentuk yang bisa didekode siapa pun di jalur. Sesuai kebijakan akses pcap (Day 01 bagian 2.8), nilainya tidak disalin ke tiket atau chat; di tiket hanya ditulis "kredensial akun mirror vendor terlihat plaintext", dilaporkan ke DPO sesuai kebijakan, dan Bambang diminta mengganti password akun itu serta meminta vendor menyediakan HTTPS.

Stream kedua adalah `tcp.stream eq 218`. Keluaran ilustrasi:

```
GET /a.hta HTTP/1.1
Host: 203.0.113.163
User-Agent: Mozilla/4.0 (compatible; ...)
Accept: */*
Connection: Keep-Alive

HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Length: 3412
...
<html> ... blok <script> ... (isi tidak disalin ke catatan)
```

Cara membaca stream 218:

- Pola yang sama dengan contoh di atas: path `.hta`, Host berupa IP mentah, dan User-Agent bergaya `Mozilla/4.0 (compatible; ...)` yang tidak sama dengan browser Edge berbasis Chromium yang dipakai armada workstation PT JAB. String User-Agent persisnya bergantung komponen Windows yang membuat request, jadi yang dinilai adalah ketidakcocokannya dengan browser standar, bukan string tertentu.
- Response 3.412 byte berisi HTML dengan blok script. Isi script tidak dianalisis di Day ini; file diekspor dan diserahkan (bagian 2.6).
- Ini sinyal kuat, bukan kesimpulan: ia menjadi kesimpulan setelah dikorroborasi dengan telemetri host (bagian 2.9).

**Variasi:** `tshark -n -r <pcap kasus> -q -z follow,tcp,ascii,218` mencetak isi stream yang sama di terminal [S8], berguna untuk dilampirkan ke kasus tanpa tangkapan layar.

**Kapan gagal:** Follow HTTP pada unduhan 1,38 GB membuat GUI berusaha menampilkan seluruh body. Untuk stream besar, batasi tampilan ke arah client ke server (request saja) atau pakai `-z follow` dengan `head`; jangan menyalin isi body ke mana pun.

### 2.6 Export Objects untuk memulihkan file

Langkah ini menjawab bagian "file yang diunduh" dari permintaan Dimas, untuk dua objek HTTP di pcap kasus.

```
# File > Export Objects > HTTP
# pilih objek, Save; lalu hash file hasil
```

- Mengekstrak file yang ditransfer lewat HTTP (payload, dokumen). Hash hasil (`sha256sum`) untuk dicocokkan ke intel/YARA.
- Hanya untuk protokol tanpa enkripsi (HTTP, SMB, FTP); TLS terenkripsi kecuali ada keylog (Day 06).
- Cek protokol yang didukung Export Objects di versi lab.

Dialog Export Objects HTTP untuk pcap kasus (keluaran ilustrasi):

```
Packet   Hostname                              Content Type               Size            Filename
1437086  fw-mirror.oltvendor.example:8080      application/octet-stream   1384120320 bytes x9-r8.4.2.bin
1437797  203.0.113.163                         application/octet-stream   3412 bytes       a.hta
```

Untuk objek besar dan untuk dilampirkan ke kasus, versi tshark lebih praktis. Agar hanya objek yang relevan yang tersimpan, potong dulu stream-nya, lalu ekspor:

```bash
cd /cases/SOC-2027-0605
mkdir -p objects && chmod 700 objects
tshark -n -r SOC-2027-0605_noc-direct_0215Z-0345Z.pcapng -Y 'tcp.stream eq 218' -w stream218.pcapng
tshark -n -r stream218.pcapng -q --export-objects http,objects/
chmod a-x objects/*
sha256sum objects/*
```

| Bagian | Fungsi |
|---|---|
| `-Y 'tcp.stream eq 218' -w stream218.pcapng` | Pcap kecil berisi satu stream, juga berguna sebagai lampiran untuk IR |
| `--export-objects http,objects/` | Menyimpan semua objek HTTP di file itu ke folder `objects/` [S8] |
| `-q` | Tidak mencetak daftar paket |
| `chmod a-x` | Memastikan file hasil ekspor tidak bisa dijalankan |
| `sha256sum` | Hash untuk pencocokan intel dan untuk diserahkan ke IR |

Keluaran ilustrasi:

```
<sha256 a.hta, 64 karakter heksadesimal>  objects/a.hta
```

Untuk firmware, langkah yang sama dijalankan atas stream 21, lalu hash-nya dibandingkan dengan hash SHA-256 yang diterbitkan vendor di portal resminya. Pada kasus ini keduanya cocok, dan Expert Information (di bawah) tidak menunjukkan segmen hilang di stream 21, sehingga file hasil ekspor utuh.

Pemeriksaan kelengkapan dengan Expert Information:

```bash
tshark -n -r SOC-2027-0605_noc-direct_0215Z-0345Z.pcapng -q -z expert,warn
```

Keluaran ilustrasi (diringkas):

```
Warns (3)
=============
   Frequency      Group           Protocol  Summary
           3   Sequence             TCP  Previous segment not captured
```

**Cara membaca hasil:**

- Tiga peringatan "Previous segment not captured" berada di stream TLS ke portal vendor dari `10.10.60.23`, bukan di stream 21 atau 218 (dicek dengan menambahkan filter `tcp.stream eq 21` dan `tcp.stream eq 218` ke `-z expert`). Objek yang diekspor berasal dari stream yang utuh.
- Hash firmware yang cocok dengan hash vendor membuktikan dua hal sekaligus: file itu firmware resmi, dan rakitan dari pcap lengkap.
- Hash `a.hta` dicocokkan ke threat intel PT JAB dan diserahkan ke IR. Hasil pencocokan, cocok atau tidak, tidak mengubah fakta bahwa file itu dijalankan atau tidak; itu dijawab telemetri host.

**Kapan gagal:**

- Body HTTP dikirim dengan chunked encoding atau kompresi, dan versi Wireshark menampilkan objek yang sudah didekompres; hash-nya lalu berbeda dengan hash file yang ditulis server. Catat apakah hash dihitung dari objek hasil dekode.
- Objek berukuran sangat besar diekspor lewat GUI dan memakan memori; pakai tshark atas pcap satu stream.
- File hasil ekspor dibuka di workstation dengan aplikasi bawaan untuk "melihat isinya". Itu menjalankan sampel; jangan.

### 2.7 IO Graph untuk pola waktu

Langkah ini menunjukkan kepada Bambang dan Dimas pola yang sulit dilihat dari daftar paket: satu unduhan panjang yang stabil, dan satu tujuan kecil yang muncul tiap menit.

```
# Statistics > I/O Graph
# tambah grafik untuk IP/filter tertentu; amati pola per waktu
```

- Cara membaca: trafik ke satu IP yang muncul pada interval teratur adalah kandidat beacon (Day 11). Lonjakan besar keluar adalah kandidat exfil (Day 12). IO Graph memvisualisasikan pola yang sulit dilihat dari daftar paket.

Untuk pcap kasus, dua grafik di jendela yang sama [S1]:

| Grafik | Display filter | Y Axis | Interval |
|---|---|---|---|
| Unduhan firmware | `tcp.stream eq 21` | Bits | 10 detik |
| Client Hello ke tujuan kecil | `ip.addr == 203.0.113.163 && tls.handshake.type == 1` | Packets | 10 detik |

Aktifkan "Time of day" supaya sumbu X menunjukkan jam, bukan detik sejak paket pertama [S1].

**Cara membaca hasil:**

- Grafik pertama datar di sekitar 4,4 Mbps dari 02:21 sampai 03:02 UTC (1.384.120.632 byte payload dalam sekitar 2.497 detik). Unduhan dari mirror yang lambat, bukan lonjakan yang memenuhi link.
- Grafik kedua berisi satu batang setiap enam interval (sekitar 60 detik), mulai 03:13 UTC sampai akhir jendela. Ini cara cepat menunjukkan periodisitas ke orang yang tidak membaca daftar paket.
- Grafik bisa disalin sebagai CSV atau disimpan sebagai gambar lewat "Save As" untuk lampiran tiket [S1].

**Variasi:** tshark mengeluarkan angka yang sama tanpa GUI: `tshark -n -r <pcap kasus> -q -z 'io,stat,60,ip.addr==203.0.113.163 && tls.handshake.type==1'` menghitung paket yang cocok per 60 detik [S8].

**Kapan gagal:** interval grafik lebih besar dari interval beacon (misalnya 5 menit untuk beacon 60 detik); semua batang sama tinggi dan periodisitasnya tidak terlihat. Mulai dengan interval kecil, lalu perbesar.

### 2.8 Ekstraksi field dengan tshark

Langkah ini menjawab pertanyaan ketujuh: daftar request dan Client Hello dalam bentuk yang bisa diimpor atau dicocokkan di Splunk, dengan waktu yang tidak ambigu.

```
tshark -r capture.pcap -Y "http.request" -T fields -e frame.time -e ip.src -e ip.dst -e http.host -e http.request.uri
```

- Mengekstrak field request HTTP ke tabel (bisa diarahkan ke CSV). Berguna untuk stacking (host/URI terbanyak) di luar Wireshark.
- Variasi DNS: `-Y "dns.flags.response == 0" -T fields -e frame.time -e ip.src -e dns.qry.name` untuk query (Day 05).
- Cek nama field di versi lab.

Versi yang dipakai untuk `SOC-2027-0605`:

```bash
cd /cases/SOC-2027-0605
tshark -n -r SOC-2027-0605_noc-direct_0215Z-0345Z.pcapng \
  -Y 'http.request || (tls.handshake.type == 1 && ip.addr == 203.0.113.163)' \
  -T fields -E header=y -E separator=, -E quote=d -E occurrence=f \
  -e frame.time_epoch -e frame.time_utc -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport \
  -e http.host -e http.request.method -e http.request.uri -e http.user_agent \
  -e tls.handshake.extensions_server_name \
  > SOC-2027-0605_requests.csv
```

| Bagian | Fungsi |
|---|---|
| `-Y 'http.request \|\| (...)'` | Request HTTP plus Client Hello ke tujuan kecil |
| `-E header=y` | Baris pertama berisi nama field [S8] |
| `-E separator=, -E quote=d` | CSV dengan tanda kutip ganda, aman untuk User-Agent yang berisi koma [S8] |
| `-E occurrence=f` | Hanya kemunculan pertama tiap field, supaya kolom tidak bergeser [S8] |
| `-e frame.time_epoch` | Kolom untuk mesin: tidak bergantung zona waktu |
| `-e frame.time_utc` | Kolom untuk manusia: UTC eksplisit |
| `-e tcp.srcport` | Port sumber, untuk dicocokkan dengan log NAT firewall |

Keluaran ilustrasi (header dan tiga baris pertama dari 34):

```
"frame.time_epoch","frame.time_utc","ip.src","tcp.srcport","ip.dst","tcp.dstport","http.host","http.request.method","http.request.uri","http.user_agent","tls.handshake.extensions_server_name"
"1809397267.596118","2027-05-04T02:21:07.596118000Z","10.10.60.21","51744","203.0.113.162","8080","fw-mirror.oltvendor.example:8080","GET","/olt/gpon-x9/firmware/x9-r8.4.2.bin","OLT-EMS-Updater/5.2",""
"1809400361.204381","2027-05-04T03:12:41.204381000Z","10.10.60.22","52310","203.0.113.163","80","203.0.113.163","GET","/a.hta","Mozilla/4.0 (compatible; ...)",""
"1809400385.611000","2027-05-04T03:13:05.611000000Z","10.10.60.22","52318","203.0.113.163","443","","","","","static-update.example.net"
```

**Cara membaca hasil:**

- 34 baris: dua request HTTP dan 32 Client Hello. Format persis `frame.time_utc` di 4.6 mengikuti ISO 8601 dengan akhiran Z [S17]; jumlah digit pecahan detik bisa berbeda, jadi skrip memakai `frame.time_epoch`.
- **Mencocokkan waktu dengan sumber lain.** Splunk PT JAB menampilkan waktu dalam WIB untuk akun SOC; epoch `1809400361` adalah 10:12:41 WIB. Dashboard flow NOC juga WIB: unduhan firmware mulai 09:21:07 WIB, sesuai "sekitar 09.20" dari Bambang. Pencocokan satu kejadian yang terlihat di dua sumber seperti ini sekaligus memeriksa bahwa jam sensor tidak melenceng (bagian 1.3).
- **Mencocokkan port dengan NAT.** Log NAT `jkt-fw01` di index `firewall` untuk `10.10.60.21:51744` menunjukkan translasi ke `198.51.100.202` dengan port publik tertentu; itulah record yang dilihat Bambang di flow edge. Tanpa pcap di sisi dalam firewall, rantai NAT ini satu-satunya cara menebak workstation di balik IP NAT.
- **Pivot ke Splunk.** Waktu dan IP `JKT-WS-2007` dipakai untuk mencari di index `dns` (query `static-update.example.net` dari `10.10.60.22` sekitar 10:13:05 WIB) dan di telemetri endpoint (bagian 2.9).

**Variasi DNS untuk kasus ini:** perintah variasi DNS di atas menghasilkan nol baris untuk pcap kasus, karena workstation tidak mengirim DNS ke internet (bagian 2.3). Nol baris di sini adalah fakta tentang titik sensor, bukan tanda tidak ada aktivitas DNS.

**Kapan gagal:**

- Skrip lama yang mem-parsing `frame.time` bergaya asctime rusak setelah upgrade ke 4.6 [S17].
- `-E occurrence` tidak diset, dan paket dengan dua header `Host` atau field berulang menghasilkan sel berisi beberapa nilai dipisah koma, yang memecah CSV bila `quote` juga tidak diset.
- CSV dibuka di spreadsheet yang mengubah epoch menjadi notasi ilmiah; impor kolom itu sebagai teks.

### 2.9 Membedakan sinyal dari kesimpulan

Wireshark menunjukkan fakta (field, isi, waktu), bukan verdict. Prinsip (Day 01) [S5]:
- Expert Info "retransmission" adalah masalah jaringan, bukan ancaman.
- User-Agent tidak lazim adalah sinyal, bukan bukti malware (bisa aplikasi sah).
- Periodisitas di IO Graph adalah kandidat beacon, bisa juga polling sah seperti pemeriksa update atau heartbeat aplikasi (Day 11).

Selalu sebut penjelasan jinak dan cari korroborasi sebelum menyimpulkan.

Penerapan pada dua temuan `SOC-2027-0605`, ditulis sebagai tabel supaya setiap sinyal punya penjelasan jinak dan korroborasi di baris yang sama:

| Temuan | Sinyal dari pcap | Penjelasan jinak yang mungkin | Korroborasi | Keputusan |
|---|---|---|---|---|
| `JKT-WS-2006` ke `203.0.113.162:8080` | Unduhan 1,38 GB lewat HTTP plaintext, di luar proxy | Firmware vendor untuk upgrade terjadwal | Konfirmasi Bambang; hash cocok dengan hash resmi vendor; jendela upgrade tercatat | Jinak. `SOC-2027-0605` ditutup; temuan sampingan: kredensial plaintext dan aturan `NOC-VENDOR-DIRECT` |
| `JKT-WS-2007` ke `203.0.113.163` | `.hta` dari IP mentah dengan User-Agent bukan browser, lalu 32 Client Hello tiap sekitar 60 detik | Alat vendor lama yang memakai HTA untuk updater; agent yang melapor tiap menit | Alert MDE `SOC-2027-0607` 10:12:44 WIB tentang `mshta.exe` yang membuka URL jarak jauh; query DNS `static-update.example.net` dari host yang sama; engineer pemilik PC tidak mengenali aktivitas itu | Eskalasi. `SOC-2027-0606` dibuka, digabung dengan `SOC-2027-0607` ke `INC-2027-061` |

Dua catatan untuk keputusan itu:

- Pcap tidak pernah membuktikan `mshta.exe` berjalan; ia hanya membuktikan request dengan pola tertentu keluar dari `10.10.60.22`. Bukti eksekusi datang dari host (MDE). Yang ditambahkan pcap adalah isi request, isi file, waktu yang presisi, dan pola koneksi lanjutan yang tidak tercatat di sumber lain.
- Alert MDE `SOC-2027-0607` berseverity rendah sudah ada di antrean L1 sejak 10:12:44 WIB dan belum disentuh saat pcap dibuka. Ini catatan untuk proses triage, bukan untuk Wireshark, tetapi perlu ditulis di laporan kasus.

**Kapan gagal:** temuan kedua ditutup sebagai "aplikasi vendor" karena host-nya milik NOC dan berada di aturan pengecualian vendor. Pengecualian firewall menjelaskan kenapa koneksi diizinkan, bukan kenapa koneksi itu terjadi.

### 2.10 Jawaban untuk Bambang dan Dimas

Ringkasan berikut dikirim pukul 12:45 WIB di kanal SOC-NOC dan dicatat di `SOC-2027-0605`. Setiap baris merujuk subbagian di atas.

| Pertanyaan | Jawaban singkat | Dasar |
|---|---|---|
| Aman membuka pcap di ws01 | Ya, dengan Wireshark 4.6.9 sebagai user biasa, resolusi nama mati, pcap kasus dipotong dulu, file ekspor tidak dijalankan | Bagian 1.1, 2.1 |
| Bisa diulang Sari | Profil `JAB-NSM` di repo tim; perintah potong, filter, dan ekstraksi tersimpan di folder kasus | Bagian 1.2, 2.2 |
| Jam | pcap tersimpan dalam UTC; laporan menulis WIB dan UTC; CSV memakai epoch; unduhan mulai 09:21:07 WIB, cocok dengan flow NOC | Bagian 1.3, 2.1, 2.8 |
| Simpan 80/443 saja | Tidak: kasus ini sendiri di port 8080; filter port membuang C2 di port tidak lazim dan semua UDP | Bagian 1.4 |
| PC di balik `198.51.100.202` | Unduhan besar dari `JKT-WS-2006` (10.10.60.21); plus temuan lain di `JKT-WS-2007` (10.10.60.22) | Bagian 2.3, 2.4 |
| Isi koneksi 8080 | Firmware OLT X9 r8.4.2, 1,29 GiB, hash cocok dengan vendor: jinak. Kredensial mirror terkirim plaintext: ganti password, minta HTTPS | Bagian 2.5, 2.6 |
| Hal lain | `.hta` dari `203.0.113.163` pukul 10:12:41 WIB dan TLS tiap sekitar 60 detik ke `static-update.example.net`; dikorroborasi MDE; eskalasi `INC-2027-061` | Bagian 2.5, 2.7, 2.9 |
| Daftar request dan file | `SOC-2027-0605_requests.csv` (34 baris), `stream218.pcapng`, `a.hta` dengan SHA-256, di folder kasus | Bagian 2.6, 2.8 |

Tindak lanjut di luar SOC:

- Agung dan Bambang: tinjau aturan `NOC-VENDOR-DIRECT`. Lima workstation yang keluar langsung tanpa proxy tidak punya log proxy, tidak melewati dekripsi TLS proxy, dan bergantung penuh pada pcap egress untuk visibilitas web.
- Dimas: `INC-2027-061` dipegang IR mulai 12:55 WIB; pcap kasus, CSV, dan hash diserahkan beserta daftar file sumber dari ring buffer.

**Kapan gagal:** jawaban hanya menjawab yang ditanyakan Bambang (unduhan besar, jinak) dan berhenti di sana. Pertanyaan pelapor menentukan titik awal analisis, bukan batasnya.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** Wireshark 4.6.x di VM analisis (user biasa, bukan root); satu pcap publik untuk latihan (unduh sendiri dari sumber latihan yang sah, cek lisensi [S4]) atau pcap lab buatan sendiri dari jaringan host-only `192.168.56.0/24`; tidak ada pcap kerja. Snapshot VM sebelum mulai. Jangan membuka file hasil Export Objects dengan aplikasi apa pun.

1. **Profil.** Buat profil forensik dengan kolom berguna (tcp.stream, http.host, dns.qry.name, SNI, delta displayed, waktu UTC) dan coloring (reset merah). Matikan resolusi nama jaringan dan port. Simpan, lalu ekspor ke zip dan impor ulang di user lain di VM yang sama (bagian 1.2 dan 2.2).
2. **Ringkasan dan hash.** Jalankan `capinfos -M -c -u -S -H` pada pcap latihan. Konversi epoch awal dan akhir dengan `date -u -d @<epoch>` dan catat SHA256 (bagian 2.1).
3. **Zona waktu.** Buka pcap yang sama dua kali: sekali dengan zona waktu VM `UTC`, sekali dengan `Asia/Jakarta` (misalnya `TZ=Asia/Jakarta wireshark <file>` bila distribusimu mendukung variabel TZ untuk aplikasi GUI). Catat jam paket pertama di kolom "Date and Time of Day" dan di format UTC untuk kedua kondisi. Ulangi dengan display filter waktu tanpa "Z" dan dengan "Z", lalu catat jumlah paket yang tampil (bagian 1.3).
4. **Orientasi.** Buka pcap. Lihat Protocol Hierarchy dan Conversations (bagian 2.3). Catat protokol dominan dan pasangan dengan volume terbesar. Aktifkan "Absolute start time" dan salin daftar ke CSV.
5. **Persempit.** Pilih satu IP eksternal menarik; filter ke sesinya (bagian 2.4). Uji juga `ip.addr != X` dan `!(ip.addr == X)` dan pastikan jumlah paketnya sama; lalu uji satu filter `||` dengan dua negasi dan catat kenapa hasilnya terlalu luas.
6. **Follow Stream.** Follow satu sesi HTTP; baca request/response (bagian 2.5). Catat URL, User-Agent, dan apa yang ditransfer. Bila ada header kredensial, latih cara mencatatnya tanpa menyalin nilainya.
7. **Export.** Bila ada file HTTP, Export Objects dan hash hasilnya (bagian 2.6). Ulangi dengan `tshark --export-objects http,<folder>` atas pcap satu stream dan bandingkan hash-nya. Jalankan `-z expert,warn` dan catat apakah stream sumber objek utuh.
8. **Pola waktu.** Buat IO Graph untuk satu IP; amati apakah ada pola teratur (bagian 2.7). Coba dua interval berbeda dan catat interval mana yang memperlihatkan polanya.
9. **tshark.** Ekstrak field request HTTP dan query DNS dengan tshark ke CSV ber-header, dengan kolom `frame.time_epoch` dan `frame.time_utc` (bagian 2.8). Stacking host/query terbanyak dengan `sort | uniq -c | sort -rn`.
10. **Potong dan gabung.** Pecah pcap latihan menjadi beberapa file (misalnya dengan `editcap -c <jumlah paket>`), lalu ulangi alur bagian 2.1: pilih file, potong dengan `-Y` ke satu host dan rentang waktu ber-"Z", gabungkan dengan `mergecap`, dan bandingkan jumlah paket hasil dengan filter yang sama di file utuh.
11. **Tafsir.** Untuk tiap temuan, tulis sinyal vs kemungkinan jinak dan korroborasi yang dibutuhkan, dengan format tabel bagian 2.9.

**Hasil yang sebaiknya tersimpan:**

- Profil forensik dibuat, diekspor ke zip, dan diimpor ulang tanpa kolom kosong.
- Ringkasan capinfos dengan epoch terkonversi dan SHA256.
- Tabel kecil jam paket pertama di dua zona waktu, dan jumlah paket filter waktu dengan dan tanpa "Z".
- Protokol dominan dan conversations teratas dicatat (CSV).
- Satu sesi di-follow dan dibaca (URL, User-Agent, transfer).
- File HTTP (bila ada) diekspor dan di-hash dengan GUI dan tshark, ditambah status Expert Information stream-nya.
- IO Graph menunjukkan pola waktu satu IP, dengan interval yang dipakai.
- Field diekspor dengan tshark ke CSV ber-header; stacking dibuat.
- Pcap hasil potong dan gabung, dengan jumlah paket yang dibandingkan.
- Tiap temuan menyebut sinyal, kemungkinan jinak, dan korroborasi.

**Variasi tantangan:** ambil pcap besar dan bandingkan dua pendekatan: analisis langsung di Wireshark vs ekstraksi field dengan tshark lalu stacking di luar. Catat untuk pertanyaan apa tiap pendekatan lebih cepat, dan kapan kamu akan beralih ke Zeek (Day 08) untuk pcap yang lebih besar lagi. Ukur juga waktu pemotongan satu file 1 GB dengan `tshark -Y` dibandingkan BPF (`tcpdump -r ... -w ... 'host ...'`) bila tcpdump tersedia di VM.

## 4. Troubleshooting

Tabel ini memuat masalah yang paling sering muncul saat membuka dan memotong pcap. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Display filter merah (tidak valid) | Sintaks atau nama field salah | Pakai autocomplete; cek nama field di versi [S1][S3] |
| Filter valid tetapi hasil kosong | Field ada di versi lain, atau IPv6 memakai `ip.addr` | Cek display filter reference [S3]; pakai `ipv6.addr` |
| Follow Stream kosong/terenkripsi | Sesi TLS | Hanya metadata; butuh keylog untuk isi (Day 06) |
| Export Objects tidak menampilkan file | Protokol terenkripsi atau tidak didukung | Hanya protokol plaintext; cek dukungan versi (`--export-objects help`) [S8] |
| Hash objek tidak cocok dengan hash sumber | Segmen hilang di stream, atau objek sudah didekode (chunked/kompresi) | `-z expert,warn` untuk stream itu; cek header `Content-Encoding` |
| Pcap terlalu besar, lambat | File besar di Wireshark | Potong dengan tshark (bagian 2.1); atau Zeek (Day 08) |
| Capture filter membuang bukti | BPF terlalu ketat saat menangkap | Tangkap luas; persempit dengan display filter |
| Capture filter tidak menangkap apa pun di link trunk | Paket bertag 802.1Q dan filter tanpa `vlan` | Tambahkan `vlan` sesuai kebutuhan [S13] |
| Field tshark kosong | Nama field salah atau protokol tidak terdekode | Cek nama field; pastikan dissector mengenali (Decode As untuk port tidak standar) |
| Jam di laporan beda 7 jam dengan Splunk/NOC | Wireshark menampilkan waktu lokal mesin, dan mesin ber-zona UTC atau sebaliknya | Pakai format UTC dan tulis "Z" atau "WIB" di setiap jam [S7] |
| Filter waktu menghasilkan jendela yang salah | Literal waktu tanpa zona dibaca sebagai waktu lokal | Tulis "Z" atau offset `+07:00` [S9] |
| Skrip parsing waktu rusak setelah upgrade | Format waktu absolut berubah ke ISO 8601 di 4.6 | Pakai `frame.time_epoch`, atau sementara `protocols.display_abs_time_ascii` [S17] |
| Kolom CSV bergeser | Field multi-occurrence dan tanpa quote | `-E occurrence=f -E quote=d` [S8] |
| Wireshark crash saat membuka file | Bug dissector atau parser file | Perbarui versi [S14]; buka dengan profil yang mematikan dissector bermasalah; laporkan bila bisa direproduksi |
| Profil impor gagal atau kolom kosong | Versi berbeda, atau zip dari sumber tak dikenal | Impor hanya dari repo tim di 4.6.9+ [S15]; cek kolom satu per satu |
| Hanya satu IP publik terlihat untuk semua host | Pcap diambil di sisi luar NAT | Pakai pcap dari sisi dalam firewall, atau cocokkan port dengan log NAT (bagian 2.8) |

## 5. Kesalahan umum dan jebakan

- **Mencampur capture dan display filter.** Sintaks dan efeknya berbeda; capture filter membuang bukti.
- **Memakai capture filter ketat di forensik.** Tangkap luas; persempit dengan display filter yang tidak mengubah bukti. Filter port 80/443 di sensor egress akan membuang kasus seperti `SOC-2027-0605` (bagian 1.4).
- **Membaca paket satu per satu di pcap besar.** Mulai dari Statistics, lalu pivot.
- **Memotong pcap kasus hanya berdasarkan IP yang disebut pelapor.** Temuan yang lebih penting di kasus ini justru tujuan yang tidak disebut siapa pun (bagian 2.3).
- **Mengira Expert Info = ancaman.** Itu anomali jaringan, bukan deteksi. Sebaliknya, abaikan Expert Info sebelum mengekspor objek dan hash-nya bisa tidak utuh tanpa kamu sadari.
- **Over-claim dari satu sinyal.** User-Agent aneh atau periodisitas adalah kandidat; sebut kemungkinan jinak.
- **Menulis jam tanpa zona.** "02:21" di laporan SOC dan "09:21" di dashboard NOC adalah paket yang sama. Setiap jam di laporan diberi "Z" atau "WIB" (bagian 1.3).
- **Menulis literal waktu tanpa "Z" di display filter.** Hasilnya bergantung zona waktu mesin yang menjalankan filter, sehingga filter yang sama memberi hasil berbeda di mesin Sari dan mesinmu [S9].
- **Memakai `!=` dengan `||` tanpa membaca ulang logikanya.** Pakai `!( ... )` untuk negasi yang jelas.
- **Menjalankan Wireshark sebagai root atau Administrator untuk "menghindari masalah izin".** Hanya `dumpcap` yang butuh hak capture, dan workstation analisis tidak butuh sama sekali [S16].
- **Mengimpor profil dari zip kiriman orang lain.** Impor profil pernah menjadi celah eksekusi kode di 4.6.0 sampai 4.6.8 [S15].
- **Menyalin kredensial yang terlihat di Follow Stream ke tiket atau chat.** Catat bahwa kredensial terlihat, bukan nilainya.
- **Membuka file hasil Export Objects untuk "melihat isinya".** Hash dulu, serahkan, analisis di lingkungan yang memang untuk sampel.
- `[komunitas, belum terkonfirmasi]` Analis pcap umumnya mulai dari Protocol Hierarchy dan Conversations untuk orientasi, lalu Follow Stream untuk kedalaman; tshark dipakai untuk ekstraksi field dan banyak pcap. Pola ini umum; sesuaikan dengan ukuran pcap-mu.

## 6. Catatan terkini

Bagian ini menampung detail versi dan perubahan perilaku yang berguna saat membaca dokumentasi atau tutorial lama; alur kerja di atas tidak bergantung padanya kecuali disebut.

- Wireshark 4.6.9 (23 Sep 2026) adalah rilis stabil terbaru; seri 4.6, dengan 4.4.19 masih dirawat [S2]. Rilis ini fokus perbaikan keamanan: 19 advisory, wnpa-sec-2026-92 sampai 110, sebagian besar crash dan loop di dissector serta parser file, ditambah satu masalah impor profil yang bisa berujung eksekusi kode [S18][S15].
- Wireshark 5.0.0rc1 dirilis 21 Okt 2026 sebagai rilis pengembangan [S2]. Untuk workstation analisis, tetap di cabang 4.6 sampai 5.0 stabil.
- Sejak 4.6.0: waktu absolut di `-T fields`, PDML, dan custom column berformat ISO 8601 (format bergaya asctime ditinggalkan, bisa dikembalikan sementara dengan `protocols.display_abs_time_ascii`); kolom waktu UTC diberi akhiran "Z"; `-T json` selalu menulis waktu absolut dalam ISO 8601 UTC [S17].
- Sejak 4.6.0: Conversations dan Endpoints bisa menampilkan angka persis lewat preferensi `conv.machine_readable`, yang juga berlaku untuk `-z conv` dan `-z endpoints`; Export Objects menambah X.509 (`x509af`); `tshark -G` tanpa argumen dihapus, diganti `tshark -G fields`; dukungan WinPcap dan AirPcap dihapus, di Windows pakai Npcap [S17].
- Rilis 4.6.9 juga mengubah perhitungan JA4 agar mengabaikan nilai GREASE [S18]; relevan untuk Day 06.
- Nama field display filter kadang berubah antar versi (terutama TLS), cek di versi lab. Field yang dipakai di Day ini (`frame.*`, `tcp.stream`, `http.*`, `tls.handshake.*`, `dns.*`) tercantum di display filter reference untuk 4.6.9 [S3].
- Export Objects dan Follow Stream hanya membuka protokol tanpa enkripsi; TLS butuh keylog (Day 06).
- Day 03 memperdalam analisis protokol; Day 08 beralih ke Zeek untuk skala.

## 7. Cheat sheet

```
AMAN       Wireshark 4.6.9+ | user biasa (hak capture hanya dumpcap) | resolusi nama jaringan OFF (tshark -n)
           potong dulu, buka kemudian | kerja di salinan + SHA256 | file ekspor = sampel, chmod a-x, jangan dibuka
WAKTU      pcap simpan UTC, Wireshark tampil waktu LOKAL mesin | View > Time Display Format (UTC, delta displayed)
           frame.time | frame.time_utc | frame.time_epoch (skrip) | frame.time_delta_displayed (interval)
           filter: frame.time >= "2027-05-04T02:15:00Z"  (tanpa Z = waktu lokal!) | WIB = UTC+7
FILTER     capture (BPF: host/port/tcp, saat tangkap, buang bukti) vs display (ip.addr/tcp.port/http, setelah, aman)
BPF        [proto] [dir] [type] nilai: tcp dst port 80 | net 10.10.0.0/16 | not > and = or | vlan geser offset
DISPLAY    ip.addr== | ip.src/ip.dst== | tcp.port== | dns/http/tls | http.request[.method=="POST"] | http.host contains
           dns.qry.name contains | tls.handshake.type==1 (Client Hello) | tcp.flags.reset==1 | and/or/not/contains/matches
           ip.addr in {10.10.60.20 .. 10.10.60.24} | ip.addr==10.10.60.0/24 | != berarti "semua tidak sama" -> pakai !(a==b)
           matches = PCRE2, tidak peka huruf (pakai (?-i)) | lower(field) contains "x"
PROFIL     Edit > Configuration Profiles | ekspor zip ke repo | impor hanya dari repo, 4.6.9+ | tshark -C <profil>
FOLLOW     klik kanan > Follow > TCP/HTTP/TLS Stream ; tcp.stream eq N ; HTTP plaintext = URL/header/isi, TLS = metadata saja
           tshark -q -z follow,tcp,ascii,N
STATISTICS Protocol Hierarchy (isi pcap) | Conversations (siapa+volume, Abs Start, Copy CSV) | Endpoints | IO Graph (pola waktu)
EKSTRAK    File > Export Objects (DICOM/FTP-DATA/HTTP/IMF/SMB/TFTP, plaintext) -> hash ; Analyze > Expert Information
           tshark --export-objects http,<dir> ; -z expert,warn (cek segmen hilang sebelum percaya hash)
TSHARK     tshark -n -r f.pcap -Y "filter" -T fields -E header=y -E separator=, -E quote=d -E occurrence=f -e ...
           -z io,phs | conv,tcp | endpoints,ip | http,tree | io,stat,60,"<filter>" ; -t ud (UTC) ; -w <hasil-potong>
POTONG     tshark -n -r <file> -Y "<host> && frame.time >= \"...Z\"" -w <out> ; mergecap -w <kasus> <hasil-potong...>
RINGKAS    capinfos -M -c -u -S -H <pcap>  (-S = epoch; date -u -d @<epoch>)
ORIENTASI  pcap baru: Protocol Hierarchy -> Conversations -> filter -> Follow Stream ; sinyal != kesimpulan
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Kolom waktu Wireshark di `jkt-nsm-ws01` menunjukkan unduhan mulai 02:21:07. Jadi engineer NOC mengunduh firmware jam dua pagi." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Pcap menyimpan waktu dalam UTC, dan Wireshark menampilkannya dalam zona waktu lokal mesin pembaca. `jkt-nsm-ws01` diset UTC, jadi 02:21:07 adalah 02:21:07 UTC, sama dengan 09:21:07 WIB, sesuai "sekitar 09.20" dari Bambang. Setiap jam di laporan perlu diberi "Z" atau "WIB", dan untuk skrip dipakai `frame.time_epoch`. Lihat bagian 1.3 dan 2.8.

</details>

**2. Skenario keputusan.** Agung mengusulkan capture filter `tcp port 80 or tcp port 443` di `jkt-pcap01` supaya ring buffer 72 jam lebih aman. Jawaban mana yang paling tepat?

- A. Setuju, karena hampir semua trafik web memakai port 80 dan 443, dan display filter tetap bisa dipakai setelahnya.
- B. Tolak filter port. Kasus pertama sensor ini sendiri berada di port 8080, filter itu juga membuang C2 di port tidak lazim dan semua UDP. Bila disk menekan, buang trafik besar yang sudah dikenal dengan filter sempit yang tertulis dan disetujui, atau kurangi snaplen.
- C. Setuju sementara, lalu tambahkan port lain begitu ada insiden yang membutuhkannya.

<details><summary>Jawaban</summary>

B. Capture filter membuang paket secara permanen, dan dengan filter itu `SOC-2027-0605` tidak bisa dijawab dari pcap sama sekali. A keliru karena display filter hanya bekerja atas paket yang sudah tersimpan; yang dibuang capture filter tidak bisa dipulihkan. C keliru karena bukti jaringan tidak bisa diambil mundur: port ditambahkan setelah insiden berarti insiden itu sendiri tidak terekam. Lihat bagian 1.4.

</details>

**3. Pertanyaan jebakan.** "Filter `ip.addr != 203.0.113.162` di Wireshark 4.6 tetap menampilkan paket dari dan ke 203.0.113.162, karena alamat lain di paket yang sama tidak sama dengan 203.0.113.162." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Di Wireshark 4.6, `!=` adalah `all_ne`: semua kemunculan field harus tidak sama, yaitu negasi logis dari `==`. Paket yang sumber atau tujuannya 203.0.113.162 disembunyikan, sama dengan `!(ip.addr == 203.0.113.162)`. Yang berperilaku "ada yang tidak sama" adalah operator terpisah, `!==` (`any_ne`). Bentuk `!(ip.addr == X)` tetap yang paling jelas maksudnya. Lihat bagian 1.5.

</details>

**4. Skenario keputusan.** Export Objects menghasilkan `a.hta` (3.412 byte). Langkah mana yang paling tepat berikutnya?

- A. Buka file dengan editor teks di `jkt-nsm-ws01` untuk melihat script-nya, lalu tulis ringkasannya di tiket.
- B. Simpan di folder kasus tanpa izin eksekusi, hitung SHA-256, cek Expert Information untuk stream sumbernya, lalu serahkan hash, file, dan pcap satu stream ke IR bersama korroborasi host.
- C. Hapus file karena berbahaya; cukup catat URL dan User-Agent.

<details><summary>Jawaban</summary>

B. File hasil ekspor adalah sampel: disimpan tanpa izin eksekusi, di-hash, dan diperiksa kelengkapannya lewat Expert Information supaya hash-nya bisa dipercaya, lalu diserahkan bersama pcap satu stream. A keliru karena membuka sampel di workstation analisis memperbesar risiko dan menyalin isi script ke tiket tidak diperlukan. C keliru karena file dan hash-nya adalah bukti dan bahan intel yang dibutuhkan IR. Lihat bagian 1.8 dan 2.6.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Bambang Hartono, dalam tiga kalimat, kenapa koneksi `JKT-WS-2007` ke `203.0.113.163` tidak terlihat di flow edge padahal unduhan firmware terlihat jelas.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Router edge men-sampling 1 dari 1.000 paket, jadi unduhan firmware yang berisi sekitar 1,4 juta paket tetap terwakili sekitar 1.400 paket sampel, sedangkan satu koneksi HTTP berisi 12 paket hanya punya peluang sekitar 1,2% untuk terwakili sama sekali. Seluruh 33 koneksi ke 203.0.113.163 hanya 492 paket, sehingga peluang muncul di flow sekitar 39% dan polanya per menit tidak mungkin terbaca. Selain itu flow edge hanya melihat IP NAT 198.51.100.202, sedangkan pcap di sisi dalam firewall melihat 10.10.60.22 dan isi request-nya."

Kesalahan yang sering muncul:
- Menyalahkan kolektor flow seolah-olah rusak, padahal sampling bekerja sesuai desain untuk capacity planning.
- Lupa menyebut NAT, sehingga Bambang mengira flow juga bisa menunjuk workstation.
- Menyebut angka peluang tanpa asumsi jumlah paket per koneksi.

</details>

**6. Pertanyaan jebakan.** "Hash `x9-r8.4.2.bin` hasil Export Objects cocok dengan hash resmi vendor, jadi capture `jkt-pcap01` pasti lengkap untuk seluruh pcap kasus." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Hash yang cocok membuktikan stream 21 terekam utuh dan filenya firmware resmi, bukan bahwa seluruh pcap kasus utuh. Expert Information menunjukkan tiga "Previous segment not captured" di stream lain (TLS ke portal vendor dari 10.10.60.23). Kelengkapan dinilai per stream lewat Expert Information, dan untuk sensor secara keseluruhan lewat statistik drop dumpcap. Lihat bagian 1.8 dan 2.6.

</details>

**7. Interview question (English).** "You receive a 1.5 GB pcap from a perimeter sensor and a vague report about a suspicious connection. Walk me through your first 30 minutes in Wireshark."

<details><summary>Sample answer</summary>

"First I make sure I can trust both the file and my tools: I work on a copy, record its SHA-256 with capinfos, confirm the first and last packet times in UTC, and open it with an up-to-date Wireshark as a normal user, with network name resolution off. If the file is much bigger, I carve it with tshark to the hosts and time window that matter, writing time filters with an explicit 'Z'. Then I orient before reading packets: Protocol Hierarchy to see what's in there, Conversations sorted by bytes with absolute start times, and Endpoints to spot external addresses, including ones nobody mentioned in the report. I pivot with display filters to the interesting pairs, use Follow Stream to read plaintext sessions, export objects and hash them only after checking Expert Info for missing segments, and use an I/O graph or delta-time column to check for periodic behaviour. Finally I extract the key fields with tshark to CSV using epoch timestamps, correlate with proxy, DNS, firewall NAT and EDR logs, and write each finding as signal, benign explanation and corroboration before I call anything malicious."

What makes this answer strong: it starts with evidence integrity and analyst safety, handles time zones explicitly, uses statistics before packets, does not stop at the reported indicator, checks capture completeness before trusting extracted files, and separates signals from conclusions with corroboration from other sources.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Wireshark User's Guide (filter, Follow Stream, Statistics: Conversations, Protocol Hierarchy, I/O Graphs; Export Objects; Configuration Profiles; Name Resolution; menu File dan View; tshark) | https://www.wireshark.org/docs/wsug_html_chunked/ | primer | diakses 2026-10-09, dicek ulang 2026-10-22 | Tinggi. Fitur dan filter. Halaman menu View belum mencantumkan varian UTC pada Time Display Format; keberadaannya dikonfirmasi catatan rilis 4.6.0 [S17] |
| S2 | Wireshark news/releases (4.6.9, 5.0.0rc1) | https://www.wireshark.org/news/ | primer | 4.6.9 dan 4.4.19, 2026-09-23; 5.0.0rc1, 2026-10-21; diakses 2026-10-09, dicek ulang 2026-10-22 | Tinggi. Versi |
| S3 | Wireshark display filter reference | https://www.wireshark.org/docs/dfref/ | primer | diakses 2026-10-09, dicek ulang 2026-10-22 | Tinggi; nama field, cek per versi. Field `frame.time*`, `tcp.stream`, `http.*`, `tls.handshake.*`, `dns.*` tercantum untuk 4.6.9 |
| S4 | malware-traffic-analysis.net (metode latihan pcap) | https://www.malware-traffic-analysis.net/ | sekunder | diakses 2026-10-09 | Sedang. Sumber pcap latihan; cek lisensi |
| S5 | Network-Forensics Day 01 (sumber bukti, NSM, privasi) | (lokal) | rujukan internal | 2026-10-09 | Konteks forensik |
| S6 | MITRE ATT&CK T1218.005: System Binary Proxy Execution: Mshta | https://attack.mitre.org/techniques/T1218/005/ | primer | diakses 2026-10-10 | Tinggi. Penyalahgunaan `mshta.exe` untuk menjalankan file HTA |
| S7 | Wireshark User's Guide: Time Zones | https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTimezones.html | primer | diakses 2026-10-22 | Tinggi. pcap/pcapng menyimpan UTC; tampilan dalam waktu lokal mesin; saran UTC dan NTP untuk server dan perangkat jaringan |
| S8 | Wireshark: tshark manual page | https://www.wireshark.org/docs/man-pages/tshark.html | primer | versi 4.6.9; diakses 2026-10-22 | Tinggi. Opsi `-r`, `-Y` (termasuk dengan `-w`), `-2 -R`, `-n`, `-t`, `-T fields`, `-E`, `-z` (conv, endpoints, io,phs, io,stat, http,tree, follow, expert), `-C`, `-o`, `--export-objects` |
| S9 | Wireshark: wireshark-filter manual page | https://www.wireshark.org/docs/man-pages/wireshark-filter.html | primer | versi 4.6.9; diakses 2026-10-22 | Tinggi. Operator `==`/`!=`/`===`/`!==`, `contains`, `matches` (PCRE2, tidak peka huruf), `in` dengan rentang, CIDR, fungsi, literal waktu dan zona |
| S10 | Wireshark: dumpcap manual page | https://www.wireshark.org/docs/man-pages/dumpcap.html | primer | versi 4.6.9; diakses 2026-10-22 | Tinggi. Nama file ring buffer (nomor dan tanggal-jam pembuatan); zona waktu nama file tidak disebut |
| S11 | Wireshark: capinfos manual page | https://www.wireshark.org/docs/man-pages/capinfos.html | primer | versi 4.6.9; diakses 2026-10-22 | Tinggi. `-a`, `-e`, `-u`, `-S`, `-M`, `-H` (SHA256 dan SHA1, SHA1 mungkin dihapus) |
| S12 | Wireshark: mergecap manual page | https://www.wireshark.org/docs/man-pages/mergecap.html | primer | versi 4.6.9; diakses 2026-10-22 | Tinggi. Penggabungan kronologis, `-a`, `-w`, `-F` (default pcapng) |
| S13 | tcpdump/libpcap: pcap-filter(7) | https://www.tcpdump.org/manpages/pcap-filter.7.html | primer | diakses 2026-10-22 | Tinggi. Qualifier BPF, CIDR, prioritas operator, efek kata kunci `vlan` |
| S14 | Wireshark Security Advisories | https://www.wireshark.org/security/ | primer | diakses 2026-10-22 | Tinggi. Daftar advisory `wnpa-sec`, versi perbaikan; tidak memuat panduan menjalankan Wireshark dengan aman |
| S15 | Wireshark advisory wnpa-sec-2026-106: Profile import crash and possible code execution | https://www.wireshark.org/security/wnpa-sec-2026-106 | primer | 2026-09-23; diakses 2026-10-22 | Tinggi. Terdampak 4.6.0-4.6.8 dan 4.4.0-4.4.18; diperbaiki 4.6.9 dan 4.4.19; tanpa workaround |
| S16 | Wireshark Wiki: CaptureSetup/CapturePrivileges | https://wiki.wireshark.org/CaptureSetup/CapturePrivileges | primer (wiki proyek) | diakses 2026-10-22 | Tinggi. Pemisahan hak: hanya dumpcap dengan hak capture, `setcap cap_net_raw,cap_net_admin`, risiko menjalankan sebagai Administrator |
| S17 | Wireshark 4.6.0 Release Notes | https://www.wireshark.org/docs/relnotes/wireshark-4.6.0.html | primer | diakses 2026-10-22 | Tinggi. Format waktu ISO 8601 untuk `-T fields`/PDML/custom column, akhiran Z untuk kolom UTC, `-T json` UTC, `conv.machine_readable`, `x509af`, `tshark -G fields`, penghapusan WinPcap/AirPcap |
| S18 | Wireshark 4.6.9 Release Notes | https://www.wireshark.org/docs/relnotes/wireshark-4.6.9.html | primer | diakses 2026-10-22 | Tinggi. 19 advisory (wnpa-sec-2026-92 sampai 110), perbaikan memori di ekspor objek DICOM dan SMB, JA4 mengabaikan GREASE |

**Catatan sumber:** fitur Wireshark di Day ini mengikuti User's Guide dan man page versi 4.6.9; nama field display filter (terutama TLS) dan daftar protokol yang didukung Export Objects bisa berubah antar versi, jadi cocokkan dengan display filter reference dan `--export-objects help` di versi-mu. Halaman User's Guide tentang menu View belum menyebut varian UTC pada Time Display Format, sedangkan catatan rilis 4.6.0 dan opsi `-t ud` di tshark menunjukkan bahwa tampilan UTC ada; label menu persisnya perlu dicek di GUI. Man page dumpcap tidak menyebut zona waktu timestamp di nama file ring buffer dan tidak menegaskan apakah kB berarti 1000 atau 1024 byte, sehingga keduanya diperiksa di sensor. Alasan mematikan resolusi nama karena reverse lookup bisa terlihat oleh pemilik blok alamat adalah penalaran dari cara kerja DNS, bukan pernyataan sumber. Klaim bahwa pemotongan dengan BPF lebih cepat daripada `-Y` adalah perkiraan berdasarkan cara kerjanya dan perlu diukur di lab. Lisensi pcap publik untuk latihan dicek sendiri sebelum dipakai. Seluruh isi PT JAB (alert, insiden, host, IP, angka paket dan byte, hash, nama file, waktu) adalah penerapan catatan ini pada organisasi fiktif dan keluaran ilustrasi, bukan hasil eksekusi nyata; angka di keluaran ilustrasi dihitung agar saling konsisten (misalnya total paket dan byte per endpoint, epoch, dan peluang sampling).
