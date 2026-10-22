---
day: 08
title: 'Zeek: dari trafik ke log transaksi (conn, dns, http, ssl, files, notice, weird), uid, kapasitas sensor, dan onboarding ke Splunk'
researched_on: 2026-10-22
versions_checked: 'Zeek 9.0.0 LTS (14 Sep 2026; LTS sebelumnya 8.0.10, 19 Agu 2026; NEWS cabang master sudah memuat catatan Zeek 9.1.0 yang belum dirilis); Zeek NEWS (files.log tanpa tx_hosts/rx_hosts sejak 5.1; Community ID bawaan dan private address space dianggap lokal sejak 6.0; ZeroMQ backend default zeekctl sejak 8.1; Broker deprecated di 9.0); skrip conn/main.zeek, files/main.zeek, capture-loss.zeek, site.zeek, local.zeek (cabang master, dibaca 2026-10-22); TA for Zeek 1.0.11 (Splunkbase 5466, Corelight, 21 Agu 2025; Splunk 9.3 sampai 10.6, CIM 6.x); Splunk Research data source Zeek conn/http/ssl (bro:*:json, TA 1.0.11)'
---

# Day 08: Zeek, dari trafik ke log transaksi yang bisa dirangkai

Cakupan: cara Zeek mengubah trafik menjadi log transaksi per protokol, cara membaca log inti (conn, dns, http, ssl, files, notice, weird, capture_loss) beserta `conn_state` dan `history`, cara merangkai satu kejadian lintas log lewat `uid` dan `fuid`, kapasitas dan cluster sederhana untuk satu sensor, serta pilihan format dan sourcetype saat log Zeek masuk Splunk.

## Ide inti

Zeek tidak menyimpan paket dan tidak terutama mencari signature. Ia membaca trafik yang lewat sensor, merakit ulang alirannya, mengenali protokolnya, lalu menulis satu baris log untuk setiap transaksi: satu koneksi di `conn.log`, satu query DNS di `dns.log`, satu request HTTP di `http.log`, satu handshake TLS di `ssl.log`, satu file di `files.log`. Setiap baris yang berasal dari koneksi yang sama membawa `uid` yang sama. Karena itu cara membaca Zeek selalu sama: mulai dari `conn.log` untuk tahu siapa bicara ke siapa, berapa lama, berapa byte, dan bagaimana koneksinya berakhir; lalu pakai `uid` untuk melompat ke log protokol yang menjelaskan apa yang terjadi di dalamnya; lalu pakai `fuid` dan hash untuk mengikuti file. Yang tidak berbagi `uid` (query DNS ke resolver, sambungan kedua di balik proxy) harus disambungkan dengan waktu, alamat, dan isi, bukan dengan `uid`.

Log Zeek hanya sejujur sensornya. Bila sensor kehilangan paket, Zeek mencatatnya sebagai celah (`missed_bytes`, `capture_loss.log`), bukan sebagai kejadian. Bila skrip tertentu tidak dimuat, field-nya tidak ada. Jadi setiap jawaban dari Zeek perlu dua kalimat pendamping: dari titik sensor mana datanya, dan apakah sensor sehat pada jam itu.

Kamu sudah mengenal bentuk ini dari telco: CDR (call detail record) mencatat satu baris per percakapan, dan log SIP, billing, serta mediasi untuk percakapan yang sama disambungkan lewat satu Call-ID. Zeek adalah CDR untuk jaringan data, dan `uid` adalah Call-ID-nya. Batas analoginya ada dua. Pertama, Zeek juga mengurai isi protokol (nama domain, URL, sertifikat, tipe file dari isinya), bukan hanya siapa, kapan, dan berapa lama. Kedua, `uid` hanya berlaku untuk satu koneksi di satu sensor: query DNS sebelum koneksi, atau sambungan proxy ke internet, adalah koneksi lain dengan `uid` lain, dan sensor lain (misalnya Suricata) tidak mengenal `uid` itu sama sekali.

```
 kantor JKT ---(core switch DC, SPAN)---+                  +--- TAP egress JKT (sisi dalam jkt-fw01)
                                        v                  v
                                   jkt-npb01 10.20.70.10 (agregasi + dedup)
                                        |
                                   jkt-zeek01 10.20.70.12   zeekctl: manager, logger, proxy, worker AF_PACKET
                                        |
                       /opt/zeek/logs/current/*.log (JSON)  --- Splunk UF ---> index=zeek sourcetype=bro:<log>:json
                                        |
     satu unduhan lewat proxy eksplisit menjadi dua koneksi:

     WS 10.10.60.83 --> jkt-proxy01:3128     uid CqP7nX4dLw2bR9tFa   conn + http + files (fuid Fk2Wq9...)
                        jkt-proxy01 --> jkt-res01:53           uid CdN5sQ8vKj3mT1yHw   dns  (query oleh proxy, bukan WS)
                        jkt-proxy01 --> 203.0.113.174:80       uid CHt3vR2kPq8sW1xYe   conn + http + files (fuid Fp8Zc3...)
                                                    \___ disambung lewat waktu, host+uri, dan sha256 yang sama ___/
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan, kantor pusat dan data center di Jakarta, dan NOC 24/7 yang satu lantai dengan SOC. Senin 2027-05-03, Direktur Teknologi Hendra Wijaya menyetujui "Program NSM PT JAB" sebagai percobaan Mei sampai Juli 2027: sensor dipasang di TAP egress Jakarta (sisi dalam firewall `jkt-fw01`) dan SPAN core switch data center, keduanya lewat packet broker `jkt-npb01`. Sampai pekan lalu, bukti jaringan SOC hanya pcap uji coba dari `jkt-pcap01` (egress saja), flow NOC, firewall, proxy `jkt-proxy01` (proxy eksplisit di `10.20.3.60:3128`), dan resolver `jkt-res01` (`10.20.2.53`). Selasa 2027-05-18 pukul 08:00, tim Agung Prabowo (Lead Infrastruktur) menyatakan `jkt-zeek01` produksi, dan log-nya mulai masuk Splunk index `zeek`. Hari pertama itu langsung ramai: notice capture loss pukul 09:16 (`SOC-2027-0635`), unduhan executable bernama PDF di `JKT-WS-2037` pukul 10:42 yang menjadi `INC-2027-067` (`SOC-2027-0636`), ribuan notice sertifikat tidak valid (`SOC-2027-0637`), pemindaian dari `203.0.113.175` ke halaman status pelanggan di `198.51.100.208` (`SOC-2027-0638`), dan jeda log enam setengah menit setelah perubahan konfigurasi siang hari (`SOC-2027-0639`). Pukul 16:30, SOC lead Dimas Prasetyo menulis kepadamu:

> "Zeek sudah jalan seharian dan langsung kepakai di INC-2027-067. Besok pagi aku lapor ke Pak Hendra dan Pak Bambang, tolong bantu jawab. Sebenarnya Zeek ini menghasilkan log apa saja, dan mana yang dipakai L1 tiap hari? Satu unduhan di JKT-WS-2037 kok tersebar di lima log dan dua koneksi berbeda; bagaimana cara menyambungkannya, dan kenapa nama host tidak ada di dns.log? Sari lihat ShR dan S0 di conn.log, itu artinya apa, kita sedang di-scan? Query files.log Sari yang dari blog lama pakai tx_hosts dan hasilnya kosong; Zeek-nya rusak? Lalu notice.log dan weird.log itu alert atau bukan? Weird ada ratusan ribu, Pak Bambang khawatir sensornya drop. Pagi ada notice capture loss dan siang log sempat berhenti; cukup satu server, atau perlu cluster? Terakhir, kita pakai sourcetype apa di Splunk, JSON atau TSV, dan berapa GB per hari?"

Pesan itu memuat tujuh pertanyaan:

1. Log apa saja yang dihasilkan Zeek, dan mana yang dipakai setiap hari?
2. Bagaimana menyambungkan satu kejadian yang tersebar di beberapa log dan beberapa koneksi?
3. Apa arti `ShR`, `S0`, dan kode lain di `conn.log`; apakah PT JAB sedang di-scan?
4. Kenapa `tx_hosts` kosong, dan bagaimana tahu arah file?
5. Apakah `notice.log` dan `weird.log` adalah alert, dan apakah weird yang banyak berarti sensor drop?
6. Cukupkah satu server, dan kapan perlu cluster?
7. Sourcetype apa di Splunk, JSON atau TSV, dan berapa volumenya per hari?

Pertanyaan 1 dijawab di bagian 1.1 dan 1.2, pertanyaan 2 di bagian 1.3, pertanyaan 3 di bagian 1.4, pertanyaan 4 di bagian 1.5, pertanyaan 5 di bagian 1.6, pertanyaan 6 di bagian 1.8, dan pertanyaan 7 di bagian 1.9. Bagian 1.7 menjelaskan skrip, paket, dan format keluaran yang menopang semuanya. Bagian 2 berisi artefak hari pertama `jkt-zeek01`: perintah offline di `jkt-nsm-ws01`, pembacaan `INC-2027-067` lintas log, triage lima alert, onboarding Splunk, dan satu halaman jawaban untuk Dimas.

**Kapan relevan:** saat trafik terlalu besar atau terlalu panjang untuk Wireshark; saat pertanyaannya "ke mana saja host ini bicara selama seminggu" atau "siapa lagi yang mengunduh file ini"; saat butuh metadata protokol (domain, URL, SNI, tipe file, hash) untuk SIEM; dan saat merangkai satu kejadian lintas banyak koneksi.
**Kapan bukan jawaban:** saat butuh byte persis di dalam paket atau payload utuh (pakai pcap dan Wireshark); saat kejadiannya terjadi sebelum sensor hidup atau di segmen yang tidak lewat sensor; dan saat sensor sedang kehilangan paket pada jam itu, karena log yang kosong lalu tidak berarti "tidak terjadi".

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (pcap, SPAN, TAP, packet broker, ring buffer, display filter, SNI, JA3/JA4) tidak diulang. Tabel ini hanya memuat istilah yang dipakai Day ini; kolom padanan memakai pengalaman NOC dan ISP.

| Istilah | Arti singkat | Padanan di NOC/ISP |
|---|---|---|
| Zeek | Network analysis framework yang mengubah trafik menjadi log transaksi per protokol | Mediation system yang menghasilkan CDR dari trafik |
| Log transaksi | Satu baris per kejadian protokol (koneksi, query, request, handshake, file) | CDR: satu baris per percakapan |
| `uid` | ID unik satu koneksi, muncul di semua log yang berasal dari koneksi itu | Call-ID yang sama di CDR, log SIP, dan billing |
| `fuid` | ID unik satu file yang dianalisis, menghubungkan `files.log` dengan file hasil ekstraksi | Nomor tiket per paket data yang dikirim dalam satu sesi |
| `conn_state` | Ringkasan nasib koneksi (S0, SF, REJ, RSTO, OTH, dan lainnya) | Kode akhir panggilan (answered, busy, no answer) |
| `history` | Urutan kejadian koneksi per huruf; huruf besar dari originator, huruf kecil dari responder | Jejak sinyal panggilan langkah demi langkah |
| Originator / responder | Pihak yang memulai koneksi / pihak yang dihubungi | Calling party / called party |
| DPD (dynamic protocol detection) | Pengenalan protokol dari isi trafik, bukan dari nomor port | Mengenali jenis layanan dari pola trafik, bukan dari nomor port di ACL |
| Notice | Kejadian yang ditandai skrip Zeek sebagai layak diperhatikan, ditulis ke `notice.log` | Event NMS berlabel "minor" yang perlu dilihat, belum tentu tiket |
| Weird | Keganjilan protokol yang ditemui analyzer, ditulis ke `weird.log` | Counter error atau malformed packet di interface |
| Capture loss | Perkiraan persentase trafik yang tidak sampai ke Zeek, dihitung dari celah TCP | Counter drop/discard di port monitoring |
| Worker, manager, logger, proxy | Peran proses dalam cluster Zeek | Line card, supervisor, syslog collector, dan modul bantu di satu chassis |
| AF_PACKET | Mekanisme Linux untuk membagi paket dari satu interface ke beberapa proses worker | Load balancing per flow di LAG atau ECMP |
| `local.zeek` | Skrip situs yang menentukan skrip dan paket tambahan yang dimuat | Konfigurasi template standar yang dipasang di semua router |
| `zkg` | Package manager Zeek untuk paket komunitas (misalnya JA3, JA4) | Repositori plugin tambahan untuk NMS |
| Community ID | Hash standar dari 5-tuple, sama di Zeek dan Suricata | Kunci flow yang dipakai bersama oleh dua kolektor berbeda |
| `Site::local_nets` | Daftar subnet yang dianggap lokal, mengisi `local_orig` dan `local_resp` | Daftar prefiks pelanggan sendiri vs prefiks luar di kolektor flow |
| TA for Zeek | Add-on Splunk (Splunkbase 5466) yang mem-parse log Zeek dan memetakannya ke CIM | Parser vendor untuk format CDR tertentu di sistem billing |
| Sourcetype | Label format data di Splunk yang menentukan cara parsing | Tipe template di kolektor (NetFlow v9 vs IPFIX) |

### 1.1 Apa itu Zeek, dan bedanya dengan IDS dan Wireshark

Pertanyaan pertama Dimas sering dijawab "Zeek itu IDS". Jawaban itu menimbulkan harapan yang salah: L1 akan menunggu Zeek berbunyi seperti alarm.

Zeek adalah network analysis framework yang mengamati trafik dan menghasilkan log kejadian; ia tidak bekerja dengan mencocokkan signature seperti IDS klasik [S1]. Ia memahami protokol (DNS, HTTP, TLS, SMB, dan lainnya) dan mencatat metadata terstruktur. Suricata dan Snort berfokus pada alert berbasis rule; Zeek berfokus pada pencatatan kaya yang bisa dianalisis belakangan. Keduanya saling melengkapi, dan PT JAB memasang Suricata di `jkt-ids01` sehari setelah Zeek (Day 09).

Dibanding Wireshark, Zeek bekerja di skala yang berbeda. Wireshark bagus untuk membaca paket detail, tetapi tidak praktis untuk trafik besar atau jangka panjang. Zeek (dulu bernama Bro) mengotomasi banyak pembacaan yang di minggu pertama program dikerjakan manual dari pcap: SNI, request HTTP, query DNS, tipe file [S5]. Hasilnya bisa di-grep, dihitung, dan dikorelasi. Tabel berikut adalah aturan praktis kapan memakai yang mana; cari baris yang paling mirip dengan pertanyaanmu.

| Kebutuhan | Alat |
|---|---|
| Detail byte/paket satu koneksi | Wireshark |
| Trafik besar/jangka panjang | Zeek |
| Korelasi lintas banyak koneksi | Zeek (`uid`) |
| Umpan ke SIEM | Zeek (log terstruktur) |
| Rekonstruksi file cepat | Wireshark Export Objects / Zeek files |
| Pencarian pola di jutaan koneksi | Zeek + alat teks/SIEM |

Keduanya dipakai bersama: Zeek untuk melihat luas dan menemukan koneksi menarik, Wireshark untuk menyelam ke paket koneksi itu. Di PT JAB, alur ini menjadi nyata karena `jkt-pcap01` menyimpan pcap egress 72 jam: koneksi yang ditemukan di index `zeek` bisa diekstrak pcap-nya di `jkt-nsm-ws01` selama masih di dalam ring buffer.

Jawaban untuk Dimas: Zeek bukan alarm. Ia buku catatan lengkap tentang setiap percakapan yang lewat sensor. Alarm datang dari tiga tempat: notice yang dibuat skrip Zeek (bagian 1.6), saved search di Splunk di atas log Zeek (bagian 2.6), dan Suricata (Day 09).

### 1.2 Model log dan log inti

Bagian kedua pertanyaan pertama Dimas adalah log mana yang dipakai L1 setiap hari. Hari pertama `jkt-zeek01` menghasilkan lebih dari dua puluh file log, dan Gilang (L1) bertanya apakah semuanya harus dibaca.

Prinsip Zeek: satu kejadian per baris, satu file log per tipe kejadian [S2]. Dokumentasi Zeek membahas log populer berikut: conn, dns, http, files, ftp, ssl, x509, smtp, ssh, pe, dhcp, ntp, log SMB (dengan DCE-RPC, Kerberos, NTLM), irc, ldap, postgresql, quic, rdp, traceroute, tunnel, known_* dan software, weird dan notice, DPD dan analyzer, serta capture_loss dan reporter [S2]. Tabel berikut adalah log yang paling sering dipakai di forensik; kolom kanan adalah pertanyaan yang dijawab masing-masing.

| Log | Isi | Pertanyaan yang dijawab |
|---|---|---|
| conn.log | Semua koneksi (4-tuple, durasi, byte, state) | Siapa bicara ke siapa, berapa lama, berapa data, bagaimana berakhir |
| dns.log | Query dan response DNS | Nama apa ditanyakan, dijawab apa |
| http.log | Permintaan dan respons HTTP | URL, user agent, status, tipe isi |
| ssl.log | Handshake TLS: SNI, versi, cipher (JA3/JA4 hanya bila paket tambahan dimuat) | Ke server bernama apa sesi terenkripsi itu |
| files.log | File yang terlihat di trafik (hash, tipe, ukuran) | File apa yang berpindah, dari siapa ke siapa |
| x509.log | Detail sertifikat | Siapa penerbit, kapan kedaluwarsa |
| notice.log | Hal yang ditandai menarik oleh skrip | Apa yang menurut skrip Zeek perlu dilihat |
| weird.log | Keganjilan protokol | Apa yang tidak sesuai standar protokol |
| capture_loss.log | Perkiraan trafik yang hilang per interval | Apakah sensor sehat pada jam itu |
| dhcp, smb, ftp, ssh, dll. | Per protokol | Detail protokol masing-masing |

Field dipisah tab; baris header (diawali `#`) menjelaskan nama dan tipe field. Format modern juga tersedia sebagai JSON, yang memudahkan SIEM (bagian 1.7 dan 1.9).

Log inti untuk forensik dan field yang paling sering dipakai:

- **conn.log:** titik awal. Field `ts`, `uid`, `id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p`, `proto`, `service`, `duration`, `orig_bytes`, `resp_bytes`, `conn_state`, `history`, `missed_bytes`. Memberi siapa bicara ke siapa, berapa lama, berapa data. `ts` adalah waktu paket pertama. `service` adalah daftar protokol yang dikonfirmasi, dipisah koma [S6]. `orig_bytes` dan `resp_bytes` adalah byte payload; untuk TCP angkanya diambil dari sequence number dan bisa tidak akurat pada koneksi besar [S6]. Byte di level IP (`orig_ip_bytes`, `resp_ip_bytes`) dan jumlah paket hanya terisi bila analyzer ukuran koneksi aktif [S6]. `missed_bytes` yang bukan nol menandakan celah konten akibat packet loss, dan biasanya membuat analisis protokol gagal [S6]. `duration` tidak menghitung paket penutup yang tidak membawa payload baru, misalnya ACK terakhir [S6].
- **dns.log:** `query`, `qtype_name`, `rcode_name`, `answers`. Untuk tunneling dan DGA (Day 05).
- **http.log:** `method`, `host`, `uri`, `user_agent`, `status_code`, `resp_mime_types`, `resp_fuids`. Untuk anomali HTTP (Day 05).
- **ssl.log:** `server_name` (SNI), `version`, `cipher`, `established`, `ssl_history`. Field `ja3`/`ja3s` atau `ja4` hanya muncul bila paket JA3 atau paket JA4 dari FoxIO dimuat; Zeek bawaan tidak menghitungnya. Untuk metadata TLS (Day 06).
- **files.log:** dibahas tersendiri di bagian 1.5 karena perubahan field sejak Zeek 5.1.

Satu sifat penting yang sering terlupa: baris `conn.log` ditulis saat koneksi selesai atau kedaluwarsa, bukan saat dimulai. Koneksi panjang yang masih berjalan belum punya baris `conn.log`, walaupun log protokolnya (misalnya `ssl.log` untuk handshake) sudah ada. Dokumentasi Zeek memberi contoh `weird.log` dan `notice.log` yang punya `uid` tanpa baris `conn.log`, yang mungkin berarti koneksinya masih berjalan [S8].

Jawaban untuk L1 PT JAB: yang dibuka setiap hari adalah conn, dns, http, ssl, files, dan notice. Weird dan capture_loss dibuka saat sensor diragukan, bukan saat triage biasa.

### 1.3 `uid`, `fuid`, dan cara membaca satu koneksi lintas log

Pertanyaan kedua Dimas datang dari `INC-2027-067`. Alert `SOC-2027-0636` menunjuk `files.log`, tetapi Sari menemukan unduhan yang sama di lima log dan dua koneksi berbeda, dan `dns.log` sama sekali tidak memuat `JKT-WS-2037`.

Setiap koneksi punya `uid` unik yang muncul di banyak log. Satu permintaan HTTP di `http.log` punya `uid` yang sama dengan koneksinya di `conn.log`, dan dengan file yang diunduhnya di `files.log`. Dokumentasi Zeek menyebut bahwa mencari berdasarkan `uid` adalah cara mengkorelasikan entri antar log [S7]. `uid` memungkinkan merangkai cerita: dari koneksi (conn) ke apa yang terjadi di dalamnya (http, dns, ssl) dan file yang ditransfer (files). Ini kekuatan utama Zeek untuk korelasi.

`fuid` adalah identifier untuk satu file, mirip `uid` untuk koneksi; ia dipakai untuk menemukan isi file hasil ekstraksi di disk [S7]. Di `http.log`, `fuid` file yang diunduh muncul di `resp_fuids`, dan yang diunggah di `orig_fuids`.

Ada tiga hal yang tidak bisa disambung dengan `uid`, dan ketiganya muncul di `INC-2027-067`:

- **Query DNS.** Query yang mendahului koneksi tidak berbagi `uid` dengan koneksi TCP-nya, karena DNS adalah koneksi terpisah (biasanya UDP) ke resolver. Hubungkan lewat `answers` di `dns.log` yang memuat IP tujuan, lalu cek bahwa `ts` query sedikit lebih awal dari `ts` koneksi.
- **Proxy eksplisit.** Workstation PT JAB tidak bicara langsung ke web server. Ia membuka koneksi ke `jkt-proxy01:3128` (terlihat di SPAN core), lalu proxy membuka koneksi baru ke server tujuan (terlihat di TAP egress). Dua koneksi, dua `uid`, dua baris `files.log` dengan `fuid` berbeda. Yang sama di keduanya adalah waktu (selisih milidetik), `host` dan path di `http.log`, ukuran file, dan hash. Proxy juga yang me-resolve nama domain, sehingga `dns.log` memuat query dari `10.20.3.60`, bukan dari workstation. Itu jawaban "kenapa nama host tidak ada di dns.log".
- **Sensor lain.** `uid` dibuat oleh Zeek. Suricata dan flow NOC tidak mengenalnya. Penghubung lintas alat adalah Community ID (bagian 1.7) atau 5-tuple dan waktu.

Satu catatan dari NEWS Zeek 5.1: bila Zeek mengaitkan satu file dengan beberapa koneksi, setiap koneksi menghasilkan baris `files.log` sendiri dengan `uid` berbeda dan `fuid` yang sama [S4]. Jadi `fuid` yang sama di beberapa baris berarti satu file yang dibawa beberapa koneksi; `fuid` berbeda dengan hash yang sama (kasus proxy) berarti dua salinan file yang dianalisis terpisah.

Urutan baca yang dipakai PT JAB untuk satu kejadian:

1. Mulai dari baris yang memicu (alert, hash, domain), ambil `uid` dan `ts`-nya.
2. Cari `uid` itu di semua log, lalu baca `conn.log`-nya dulu: arah, byte, `conn_state`, `history`, `missed_bytes`.
3. Baca log protokol dengan `uid` yang sama: `http.log` atau `ssl.log`, lalu `files.log`.
4. Cari koneksi pasangan yang tidak berbagi `uid`: DNS sebelum koneksi (lewat `answers` dan waktu), hop proxy (lewat waktu, host, path, hash).
5. Tulis setiap langkah dengan nama log dan field yang menjadi buktinya.

Pembacaan lengkap `INC-2027-067` dengan urutan ini ada di bagian 2.7.

### 1.4 `conn_state` dan `history`: nasib sebuah koneksi

Pertanyaan ketiga Dimas datang dari dua temuan Sari: `ShR` dari `203.0.113.175` ke `198.51.100.208` (alert `SOC-2027-0638`), dan `S0` dari `jkt-proxy01` ke `203.0.113.174` setelah alamat itu diblokir di firewall.

Field `conn_state` meringkas apa yang terjadi pada koneksi TCP, berguna untuk mengenali scan dan koneksi gagal [S2]. Tabel berikut adalah daftar lengkapnya; kolom kanan menunjukkan pola yang paling sering kamu temui di PT JAB.

| conn_state | Arti | Contoh di PT JAB |
|---|---|---|
| S0 | SYN terlihat, tidak ada balasan (host/port mati atau terfilter) | Proxy mencoba `203.0.113.174:80` setelah diblokir `jkt-fw01` |
| S1 | Koneksi terbentuk, belum ditutup | Sesi panjang yang masih berjalan saat Zeek berhenti |
| SF | Terbentuk dan ditutup normal | Unduhan HTTP yang selesai |
| REJ | Upaya koneksi ditolak (SYN dibalas RST) | Port yang diizinkan firewall tetapi tidak ada layanan di server |
| S2 | Terbentuk, originator mencoba menutup, responder tidak membalas | Jarang; cek arah capture |
| S3 | Terbentuk, responder mencoba menutup, originator tidak membalas | Jarang; cek arah capture |
| RSTO | Terbentuk, lalu originator mengirim RST | Klien membatalkan koneksi; juga hasil SYN scan ke port terbuka |
| RSTR | Terbentuk, lalu responder mengirim RST | Server memutus sesi |
| RSTOS0 | Originator mengirim SYN lalu RST, tanpa SYN-ACK terlihat | Scanner yang membatalkan sebelum balasan |
| RSTRH | Responder mengirim SYN-ACK lalu RST, tanpa SYN dari originator terlihat | Capture satu arah atau asimetris |
| SH | Originator mengirim SYN lalu FIN, tanpa SYN-ACK terlihat | Scan dengan flag tidak lazim |
| SHR | Responder mengirim SYN-ACK lalu FIN, tanpa SYN dari originator terlihat | Capture satu arah atau asimetris |
| OTH | Tidak ada SYN terlihat, hanya trafik di tengah koneksi | Koneksi yang sudah berjalan saat sensor mulai, atau setelah restart |

Dokumentasi di kode sumber Zeek menambahkan dua hal yang berguna. Pertama, S1 dan SF dibedakan dari ada tidaknya byte count di ringkasan koneksi [S6]. Kedua, `conn_state` juga diisi untuk UDP dengan aturan yang lebih sederhana: SF bila kedua sisi aktif, S0 bila hanya originator yang mengirim, SHR bila hanya responder, OTH bila tidak keduanya [S6]. Query DNS tanpa jawaban karena itu muncul sebagai S0 walaupun UDP tidak punya SYN.

Field `history` melengkapinya dengan urutan kejadian per huruf. Huruf besar berarti dari originator, huruf kecil dari responder. Tabel berikut adalah daftar lengkap huruf menurut kode sumber Zeek [S6]; enam huruf pertama yang paling sering dipakai.

| Huruf | Arti |
|---|---|
| `S` | SYN tanpa bit ACK |
| `H` | SYN+ACK (handshake) |
| `A` | ACK murni |
| `D` | paket berisi data |
| `F` | paket dengan bit FIN |
| `R` | paket dengan bit RST |
| `C` | paket dengan checksum salah (berlaku juga untuk UDP) |
| `G` | celah konten (content gap) |
| `T` | paket dengan payload yang dikirim ulang (retransmisi) |
| `W` | paket dengan zero window |
| `I` | paket tidak konsisten (misalnya FIN dan RST bersamaan) |
| `Q` | paket multi-flag (SYN+FIN atau SYN+RST) |
| `^` | arah koneksi dibalik oleh heuristik Zeek |
| `X` | analisis koneksi parsial (misalnya batas terlampaui) |

Aturan pencatatannya juga perlu diketahui supaya tidak salah hitung [S6]. Huruf `A`, `D`, `I`, dan `Q` dicatat maksimal sekali per arah. Huruf `F`, `H`, `R`, dan `S` bisa tercatat berkali-kali bila sequence number-nya berbeda dari paket sebelumnya dengan flag yang sama; SYN yang dikirim ulang dengan sequence number sama tidak menambah huruf. Huruf `C`, `G`, `T`, dan `W` dicatat secara logaritmik: huruf kedua berarti kejadian itu terlihat minimal 10 kali, huruf ketiga minimal 100 kali.

Contoh pembacaan:

| history | Cerita |
|---|---|
| `ShADadFf` | Handshake lengkap, data dua arah, ditutup dua pihak: koneksi normal |
| `S` | Hanya SYN: kandidat scan ke port tertutup yang terfilter, atau host mati, atau tujuan diblokir firewall di jalur |
| `Sr` | SYN dibalas RST: port tertutup (biasanya `conn_state` REJ) |
| `ShR` | SYN, SYN-ACK, lalu originator RST: pola khas SYN scan ke port yang terbuka |
| `ShADad` lalu berhenti | Terbentuk dan bertukar data, capture berakhir sebelum ditutup (S1) |
| `ShADadtt` | Koneksi dengan retransmisi dari responder minimal 10 kali |

Pola `ShR` penting: scanner half-open menemukan port terbuka tanpa pernah menyelesaikan handshake, sehingga aplikasi di host tidak mencatat apa pun, tetapi Zeek mencatatnya. Menurut logika fungsi `conn_state` di kode sumber Zeek, originator yang mengirim RST saat responder sudah aktif menghasilkan RSTO [S6], jadi `ShR` umumnya muncul sebagai RSTO. Kombinasi flag kecil bisa jatuh ke state yang berbeda, jadi cek di lab-mu (bagian 3); `history` lebih bisa diandalkan untuk membaca urutannya.

Membaca keduanya membuat scan (banyak S0/REJ dari satu sumber) dan koneksi normal (SF) mudah dibedakan di skala besar, tanpa membaca paket satu per satu. Satu peringatan: capture yang dimulai di tengah koneksi panjang menghasilkan OTH, jadi OTH dalam jumlah kecil di awal pcap, di jam pertama sensor produksi, atau sesaat setelah sensor di-restart adalah artefak capture, bukan anomali.

Untuk `SOC-2027-0638`, jawabannya tidak bisa diambil dari Zeek saja. TAP egress PT JAB berada di sisi dalam `jkt-fw01` (Day 01 bagian 1.5), sehingga SYN yang ditolak firewall tidak pernah sampai ke sensor. Firewall mencatat 997 penolakan dari `203.0.113.175`; Zeek hanya melihat tiga koneksi yang diizinkan firewall dan sampai ke server. Dari tiga baris itu, dua `ShR` (port 80 dan 443 terbuka) dan satu `Sr` (port 8080 diizinkan aturan lama firewall tetapi tidak ada layanan). Ya, PT JAB sedang di-scan, seperti setiap alamat publik di internet. Nilai Zeek di sini adalah menjawab apa yang tembus: hanya port yang memang dipublikasikan, plus satu aturan firewall lama yang perlu dibersihkan. Hitungannya ada di bagian 2.9.

### 1.5 `files.log` dan arah file

Pertanyaan keempat Dimas datang dari query Sari yang disalin dari tutorial lama: `tx_hosts` dan `rx_hosts` kosong di semua baris.

Zeek tidak rusak. NEWS Zeek 5.1 mencatat bahwa secara bawaan `files.log` tidak lagi memuat `tx_hosts`, `rx_hosts`, dan `conn_uids`; ketiganya diganti field `uid` dan `id` yang lebih umum dipakai [S4]. Field lama bisa dimunculkan lagi lewat skrip `frameworks/files/deprecated-txhosts-rxhosts-connuids`, tetapi NEWS yang sama menyebut skrip itu akan dihapus di Zeek 6.1, dan konsumen `files.log` diminta beralih ke `uid` dan `id` [S4]. PT JAB memakai Zeek 9.0, jadi tidak ada jalan kembali: query lama harus ditulis ulang.

Field `files.log` yang dipakai, dengan maknanya menurut dokumentasi dan kode sumber Zeek [S7][S14]:

- **`fuid`:** identifier file (bagian 1.3).
- **`uid` dan `id.*`:** koneksi yang membawa file. `id.orig_h` adalah originator koneksi, bukan otomatis pengirim file.
- **`is_orig`:** apakah file dikirim oleh originator koneksi. `F` berarti responder yang mengirim file [S7]. Pada unduhan HTTP, `is_orig` = `F`: file datang dari server. Pada unggahan (HTTP POST, SMB write ke share), `is_orig` = `T`.
- **`source`:** protokol atau sumber pembawa (HTTP, SMB, FTP_DATA, SMTP).
- **`mime_type`:** tipe dari tanda tangan file magic terkuat pada awal isi file, bukan dari ekstensi [S14].
- **`filename`:** nama file bila tersedia dari sumbernya, sering dari header `Content-Disposition` [S14]. Bisa kosong.
- **`seen_bytes`, `total_bytes`, `missing_bytes`:** byte yang dilihat, ukuran yang seharusnya, dan byte yang terlewat (misalnya karena paket drop) [S14]. `missing_bytes` bukan nol berarti hash tidak mewakili file utuh.
- **`analyzers`:** analyzer file yang aktif (misalnya `PE`, `EXTRACT`, `MD5`, `SHA256`) [S7].
- **`md5`, `sha1`, `sha256`:** hanya terisi bila hashing file diaktifkan, misalnya lewat `local.zeek` yang memuat `frameworks/files/hash-all-files`, yang menghitung MD5, SHA1, dan SHA256 untuk semua file [S4].
- **`extracted`:** nama file hasil ekstraksi di disk sensor, hanya bila ekstraksi diaktifkan [S7].
- **`local_orig`:** apakah data berasal dari jaringan lokal menurut `Site::local_nets` [S14].

Cara menulis ulang arah file untuk query Sari: pengirim adalah `id.orig_h` bila `is_orig` = `T`, dan `id.resp_h` bila `is_orig` = `F`; penerima kebalikannya. Di SPL, rumus ini satu baris `eval` (bagian 2.6).

Satu alasan lain kenapa `files.log` menjadi pemicu `SOC-2027-0636`: `mime_type` Zeek berasal dari isi, sehingga file bernama `invoice_0518.pdf` yang isinya PE Windows tercatat `application/x-dosexec`. Nama dan isi yang tidak cocok adalah sinyal kuat penyamaran payload (Day 05), tetapi tetap indikator. Penjelasan jinak yang perlu disingkirkan: installer sah yang diberi nama keliru oleh sistem dokumen internal, atau server yang salah mengirim nama file.

### 1.6 `notice.log`, `weird.log`, `capture_loss.log`, dan `reporter.log`

Pertanyaan kelima Dimas punya dua bagian: apakah notice dan weird itu alert, dan apakah 180 ribu weird dalam delapan jam berarti sensor drop, seperti dikhawatirkan Bambang Hartono (Manajer NOC).

Empat log ini sering dicampur, padahal fungsinya berbeda. Tabel berikut memisahkannya; baca kolom "Dipakai untuk" sebelum menjadikan salah satunya alert.

| Log | Asal | Sifat | Dipakai untuk |
|---|---|---|---|
| `notice.log` | Skrip Zeek memanggil fungsi `NOTICE` | Sinyal semantik; dokumentasi Zeek menyebutnya hal paling dekat dengan alert IDS di Zeek [S8] | Bahan alert di Splunk setelah dituning |
| `weird.log` | Analyzer protokol menemui keganjilan | Kebanyakan noise; sering bisa diabaikan karena volumenya [S8] | Diagnosis sensor dan protokol aneh |
| `capture_loss.log` | Skrip `misc/capture-loss` | Kesehatan sensor | Menilai apakah log pada jam itu bisa dipercaya |
| `reporter.log` | Zeek sendiri | Peringatan dan error internal [S10] | Diagnosis Zeek (konfigurasi, sumber daya) |

**Notice.** Skrip analisis Zeek menandai aktivitas yang mungkin menarik dengan memanggil `NOTICE`; deteksi dipisahkan dari pelaporan, dan hook `Notice::policy` memutuskan notice mana yang diberi aksi [S9]. Field `notice.log` yang dipakai: `note` (tipe notice), `msg` (deskripsi), `sub` (sub-pesan), `src`, `dst`, `uid`, `n` (nilai numerik), `actions`, dan `suppress_for` [S9]. Notice dengan `note` dan identifier yang sama dianggap duplikat dan disupresi selama periode tertentu; interval `0secs` mematikan supresi [S9]. Aksi yang tersedia antara lain `Notice::ACTION_LOG` (tulis ke `notice.log`), `Notice::ACTION_ALARM` (tulis ke alarm stream), dan `Notice::ACTION_EMAIL` [S9]. Contoh tipe notice bawaan: `SSH::Password_Guessing`, `SSL::Invalid_Server_Cert` (rantai sertifikat gagal divalidasi terhadap CA yang dikenal), dan `Weird::Activity` [S9]. Dokumentasi Zeek memberi contoh jaringan rumah dengan ratusan `SSL::Invalid_Server_Cert` dalam 24 jam karena alasan seperti "unable to get local issuer certificate" dan sertifikat self-signed [S8]. Itu persis pola `SOC-2027-0637` di PT JAB: 2.316 notice dari `jkt-mon01` (`10.20.4.30`, server monitoring) yang memeriksa antarmuka manajemen server (BMC) bersertifikat self-signed di `10.20.250.0/24`. Notice yang benar menurut skrip belum tentu insiden.

**Weird.** Weird kebanyakan di-hardcode oleh penulis analyzer, sebagian kecil dibuat skrip [S8]. Contoh nama dari dokumentasi Zeek: `window_recision`, `unknown_protocol`, `truncated_IP`, `TCP_seq_underflow_or_misorder`, `non_ip_packet_in_ethernet`, `line_terminated_with_single_CR`, `DNS_RR_unknown_type`, `data_after_reset`, `bad_TCP_header_len`, `bad_HTTP_request` [S8]. Field yang dipakai: `ts`, `uid`, `id.*`, `name`, `notice`, `peer` [S8]. Weird berguna dalam dua situasi: lonjakan satu nama weird setelah perubahan di sensor (tanda masalah capture), dan weird yang menempel pada satu `uid` yang sedang diinvestigasi (protokol yang dipakai secara tidak lazim). Banyaknya weird bukan ukuran drop.

**Capture loss.** Ukuran drop ada di `capture_loss.log`. Field-nya: `ts`, `ts_delta` (panjang interval), `peer` (nama node Zeek), `gaps` (jumlah celah sequence TCP yang dianggap trafik hilang), `acks` (jumlah ACK yang diamati), dan `percent_lost` [S10]. Contoh di dokumentasi cocok dengan `gaps` dibagi `acks` dikali 100, dan nilainya sudah persen: 0,412 berarti 0,412%, bukan 41% [S10]. Kode sumber skrip `capture-loss.zeek` di cabang master memakai interval pengukuran 15 menit, pengukuran awal 1 menit setelah start, dan ambang `too_much_loss` 0,1; notice `CaptureLoss::Too_Much_Loss` dibuat bila `percent_lost` minimal 10% [S10]. Skrip ini dimuat oleh `local.zeek` bawaan (`misc/capture-loss`) [S13]. Dokumentasi menyebut sedikit loss masih bisa ditoleransi [S10]; PT JAB menetapkan ambang operasional sendiri: di atas 1% per worker diperiksa, di atas 5% ditulis sebagai catatan di setiap laporan yang memakai data jam itu.

Karena perkiraannya berasal dari celah TCP, capture loss tidak mengukur UDP, dan angka satu interval adalah rata-rata 15 menit. Satu menit drop berat di interval itu bisa terlihat kecil.

Jawaban untuk Bambang: 180 ribu weird adalah perilaku normal di jaringan nyata. Yang menunjukkan drop adalah `SOC-2027-0635`: satu worker 12,4% pada interval 09:00 sampai 09:15, sementara tiga worker lain sekitar 3%. Penyebab dan perbaikannya dibahas di bagian 1.8.

### 1.7 Skrip, paket, format keluaran, dan `zeek-cut`

Semua jawaban di atas bergantung pada skrip yang dimuat `jkt-zeek01`. Saat Sari mengolah ulang pcap `INC-2027-067` di `jkt-nsm-ws01`, hash di `files.log`-nya kosong, padahal di Splunk hash ada. Bedanya hanya satu kata di command line.

Perilaku Zeek ditentukan skrip yang dimuat. `zeek -r capture.pcap` hanya memuat skrip dasar; menambahkan argumen `local` memuat `site/local.zeek`, yang di instalasi bawaan mengaktifkan hal seperti hashing semua file dan beberapa deteksi tambahan. `local.zeek` bawaan di cabang master antara lain memuat `misc/capture-loss`, `misc/stats`, `protocols/ssl/validate-certs`, `protocols/ssh/detect-bruteforcing`, `protocols/http/detect-sql-injection`, `protocols/conn/known-hosts`, `protocols/conn/known-services`, dan `frameworks/files/hash-all-files`; baris `policy/protocols/conn/community-id-logging` tersedia tetapi masih dikomentari [S13]. Karena itu dua analis yang memproses pcap yang sama bisa mendapat log berbeda bila skrip yang dimuat berbeda. Catat perintah persisnya di laporan.

Paket tambahan dipasang dengan pengelola paket `zkg`. Yang sering dipakai di forensik: paket JA3 dan paket JA4 dari FoxIO (menambah fingerprint klien ke `ssl.log`). Community ID dulu juga berupa plugin eksternal; sejak Zeek 6.0, Zeek punya dukungan Community ID bawaan lewat skrip `protocols/conn/community-id-logging` (menambah field `community_id` ke `conn.log`) dan `frameworks/notice/community-id` (ke `notice.log`), dan NEWS menyebut memakai skrip bawaan bersama plugin eksternal tidak didukung [S4]. Community ID adalah hash 5-tuple standar yang sama dengan yang dihasilkan Suricata, sehingga log Zeek dan alert Suricata bisa digabung tanpa mencocokkan IP dan port satu per satu. PT JAB mengaktifkan skrip bawaan itu di `local.zeek` sebelum produksi, supaya `jkt-ids01` yang hidup besoknya langsung bisa dikorelasi (Day 09).

`Site::local_nets` menentukan isi `local_orig` dan `local_resp` [S6]. Sejak Zeek 6.0, alamat private (rentang yang menurut IANA tidak dirutekan di internet) otomatis dianggap lokal [S4]. Daftar itu di kode sumber Zeek ternyata juga memuat rentang dokumentasi `192.0.2.0/24`, `198.51.100.0/24`, dan `203.0.113.0/24` [S13]. Catatan ini memakai rentang dokumentasi sebagai pengganti alamat publik, dan log PT JAB di bagian 2 ditulis seolah alamat itu publik sungguhan (`local_resp` = `F` untuk `203.0.113.174`). Di lab yang memakai alamat dokumentasi, Zeek akan menandainya lokal kecuali `Site::local_nets` ditulis eksplisit dan opsi `Site::private_address_space_is_local` dimatikan [S4]. Di PT JAB, `networks.cfg` mendaftarkan `10.0.0.0/8` dan blok publik PT JAB, karena alamat publik sendiri (misalnya `198.51.100.208`) tidak otomatis dianggap lokal di dunia nyata.

Format bawaan adalah TSV dengan header `#fields`: writer ASCII menghasilkan file dipisah tab, dengan baris metadata di awal file [S12]. Untuk SIEM, JSON lebih praktis: jalankan dengan `LogAscii::use_json=T` di command line, atau muat skrip `policy/tuning/json-logs` di `local.zeek`; isi skrip itu memang satu baris `redef LogAscii::use_json=T` [S13]. Dokumentasi logging framework juga menyebut cara mengubah hanya satu log ke JSON lewat konfigurasi filter [S12]. Isi field sama; hanya bentuknya berubah, dan `zeek-cut` hanya membaca format TSV. Untuk JSON di command line, `jq` adalah padanannya.

Log Zeek TSV bisa dianalisis dengan alat Unix. `zeek-cut` (dulu `bro-cut`, berganti nama di Zeek 3.0 [S4]) mengekstrak field berdasarkan nama dari header, lalu `sort`, `uniq -c`, `awk` meringkas. Contoh pola analisis: hitung koneksi per tujuan, top SNI, domain DNS paling sering, UA unik. Ini membuat pertanyaan skala besar ("ke mana saja host X menyambung sepekan") cepat dijawab, yang tak praktis di Wireshark. Perintah-perintahnya ada di bagian 2.2 sampai 2.8.

### 1.8 Kapasitas dan cluster sederhana

Pertanyaan keenam Dimas lahir dari dua kejadian: `SOC-2027-0635` pukul 09:16 dan jeda log pukul 13:58 (`SOC-2027-0639`) setelah perubahan konfigurasi untuk memperbaiki yang pertama.

Kata "cluster" di Zeek tidak berarti banyak server. Zeek tidak multithread, jadi beban dibagi ke beberapa proses atau mesin oleh frontend yang membagi trafik per flow; Zeek sendiri tidak melakukan pembagian itu [S11]. Satu server dengan banyak core pun dijalankan sebagai cluster, dengan peran berikut [S11]:

- **Worker:** menangkap trafik dan menganalisis protokol dari aliran yang dirakit ulang. Worker mengerjakan sebagian besar pekerjaan dan butuh CPU serta memori terbaik.
- **Manager:** menerima log dan notice dari node lain dan menghasilkan satu log, bukan banyak log terpisah; juga menjalankan fungsi yang butuh pandangan global.
- **Logger (opsional):** menerima log dari node lain untuk mengurangi beban manager.
- **Proxy:** menampung penyimpanan data atau beban tambahan; skrip bawaan memakainya minimal, dan sering berjalan di host manager.

Pembagian trafik di satu host Linux umumnya memakai AF_PACKET. Dokumentasi Zeek menyebut pembagian bawaan AF_PACKET berdasarkan hash flow simetris, sehingga dua arah satu koneksi sampai ke worker yang sama; bug kernel tertentu bisa merusak hash simetris itu [S11]. Worker bergabung ke satu fanout group (ID bawaan 23), offloading NIC perlu dimatikan (misalnya dengan `ethtool -K`) supaya paket terlihat seperti saat datang, dan proses butuh kapabilitas `CAP_NET_RAW` dan `CAP_NET_ADMIN` [S11]. Panduan jumlah worker yang diberikan dokumentasi hanya kualitatif: jangan menjalankan worker lebih dari satu atau dua kurang dari jumlah core, pisahkan worker dari manager bila memungkinkan, pakai logger untuk mengurangi beban manager, dan pinning CPU bisa membantu [S11].

Angka throughput per core tidak ada di dokumentasi resmi. Panduan perangkat keras WLCG SOC Working Group (CERN) memakai patokan satu core menangani 800 Mbps sampai 1 Gbps, sangat bergantung pada skrip yang aktif, minimal 12 core fisik dan 64 GB RAM untuk 10 Gbps, dan rata-rata 6 GB RAM per worker; halaman yang sama menyebut jumlah koneksi lebih menentukan daripada bandwidth mentah [S16]. Patokan lama yang beredar di komunitas Zeek, sekitar 250 Mbps per core, jauh lebih konservatif. Kedua angka adalah titik awal; yang memutuskan adalah `capture_loss.log` di trafikmu sendiri.

Komunikasi antarproses cluster sejak Zeek 8.1 memakai ZeroMQ secara bawaan; untuk cluster satu host seperti `jkt-zeek01`, komunikasi itu tetap di dalam mesin, dan enkripsinya baru relevan untuk multi-host (riwayat perubahannya di bagian 6) [S4].

Penerapannya di `jkt-zeek01` pada hari pertama:

- **Perangkat:** 24 core fisik, 128 GB RAM, satu port 10G capture dari `jkt-npb01` (tanpa IP), satu port manajemen di `10.20.70.12`, disk log 8 TB. `jkt-npb01` mengagregasi SPAN core dan TAP egress dan menjalankan deduplikasi, karena koneksi `jkt-proxy01` ke internet lewat kedua titik.
- **Trafik:** counter port `jkt-npb01` yang dibaca Bambang menunjukkan puncak 2,3 Gbps pukul 09:00 sampai 10:00.
- **Konfigurasi awal:** zeekctl satu host (manager, logger, proxy, 4 worker AF_PACKET). Dengan 2,3 Gbps dibagi 4, setiap worker rata-rata menerima 575 Mbps, masih di bawah patokan 800 Mbps per core.
- **Yang terjadi:** `worker-1-2` mencatat 12,4% loss (159.285 gap dari 1.284.560 ACK) pada interval 09:00 sampai 09:15; tiga worker lain 3,0% sampai 3,7%. Satu worker yang jauh di atas yang lain adalah tanda elephant flow: hash simetris menaruh seluruh flow besar ke satu worker. Flow-nya adalah replikasi storage antar dua host di DC yang berjalan tiap pagi.
- **Perbaikan:** worker dinaikkan ke 10 (2,3 Gbps dibagi 10 sama dengan 230 Mbps per worker, sesuai patokan konservatif 250 Mbps per core), dengan pinning CPU; flow replikasi storage dikeluarkan di `jkt-npb01` dan dicatat sebagai blind spot tertulis. RAM: 10 worker kali 6 GB sama dengan 60 GB dari 128 GB.
- **Efek samping:** `zeekctl deploy` pertama pukul 13:58 gagal karena salah ketik daftar `pin_cpus`; deploy kedua berhasil 14:03, dan log `conn` kembali masuk Splunk 14:04:40. Jeda 13:58:10 sampai 14:04:40 (6 menit 30 detik) memicu `SOC-2027-0639`. Setelah restart, `conn.log` juga memuat lonjakan OTH karena koneksi yang sudah berjalan dilihat dari tengah (bagian 1.4).

Jawaban untuk Dimas: satu server cukup untuk egress Jakarta dan core DC fase ini, asalkan dijalankan sebagai cluster satu host dengan worker yang cukup, flow raksasa yang sudah dikenal dikeluarkan dan didokumentasikan, dan setiap deploy diumumkan ke SOC sebagai jendela buta. Cluster multi-host baru dipertimbangkan bila capture loss tetap di atas 1% setelah tuning, atau bila Bandung dan Medan ikut dipasang sensor.

### 1.9 Zeek ke Splunk: JSON atau TSV, dan sourcetype

Pertanyaan terakhir Dimas menentukan apakah semua query di Day ini dan Day berikutnya bisa dijalankan: sourcetype apa, format apa, berapa besar.

**Add-on.** Add-on yang dipakai adalah "TA for Zeek" (Splunkbase app 5466), versi 1.0.11 tertanggal 21 Agustus 2025. Halaman app menyebut add-on ini mem-parse data Zeek open source dalam format JSON dan TSV dan memetakannya ke data model CIM; dulu dirawat Splunk dengan nama lain ("Splunk Add-on for Zeek aka Bro") dan kini dirawat Corelight; kompatibel dengan Splunk Enterprise dan Splunk Cloud 9.3, 9.4, dan 10.0 sampai 10.6, serta CIM 6.x [S15].

**Sourcetype.** Halaman app tidak menuliskan daftar sourcetype [S15]. Splunk Research mendaftarkan sumber data Zeek conn, http, dan ssl dengan sourcetype `bro:conn:json`, `bro:http:json`, dan `bro:ssl:json`, dengan TA for Zeek 1.0.11 sebagai app pendukung [S17]. Untuk `bro:conn:json`, daftar field-nya memuat field asli Zeek (`id.orig_h`, `conn_state`, `history`, `uid`, `missed_bytes`) sekaligus field CIM hasil add-on (`src_ip`, `dest_ip`, `dest_port`, `bytes_in`, `bytes_out`, `action`, `conn_state_meaning`, `vendor_product`) [S17]. Awalan `bro:` masih dipakai walaupun nama alatnya sudah Zeek. Panduan komunitas menunjukkan cara lain yang juga didukung add-on: input memakai `sourcetype = bro:json` dengan `source = bro.conn.log` (dan seterusnya per log), lalu transform add-on yang menetapkan sourcetype akhir; penulisnya menyebut source dan sourcetype harus mengikuti format yang diharapkan add-on supaya props dan eventtype-nya cocok, dan menyarankan sourcetype ditulis manual di `inputs.conf` untuk sistem bervolume tinggi [S18].

**Keputusan PT JAB:**

| Hal | Keputusan | Alasan |
|---|---|---|
| Format di sensor | JSON (`policy/tuning/json-logs`) | Nama field ikut di setiap baris, sehingga field baru dari versi Zeek atau paket tidak merusak parsing; add-on mendukung keduanya [S15] |
| Index | `zeek` | Sudah ditetapkan program; retensi mengikuti kebijakan index jaringan |
| Sourcetype | Ditulis eksplisit per log di `inputs.conf`: `bro:conn:json`, `bro:dns:json`, `bro:http:json`, `bro:ssl:json`, `bro:files:json`, `bro:x509:json`, `bro:notice:json`, `bro:weird:json`, `bro:capture_loss:json`, dan seterusnya | Pola conn/http/ssl dari Splunk Research [S17]; ditulis manual untuk volume tinggi [S18] |
| Validasi | Sebelum produksi, data uji dikirim ke index staging dan dicek dengan `\| metadata type=sourcetypes index=<staging>` serta keberadaan field CIM (`src_ip`, `dest_ip`, `conn_state_meaning`) | Nama sourcetype selain conn/http/ssl mengikuti pola yang sama tetapi tidak tercantum di sumber yang diperiksa |
| Waktu | `_time` dari field `ts` (epoch), diatur oleh add-on | Cek di staging bahwa `_time` sama dengan `ts`, bukan waktu index |

Bila validasi menunjukkan add-on tidak mengenali sourcetype eksplisit untuk log tertentu, jalur cadangannya adalah pola `bro:json` dengan `source = bro.<log>.log` [S18].

**JSON atau TSV, dalam angka.** Satu baris `conn.log` hop proxy `INC-2027-067` (bagian 2.7) berukuran 407 byte sebagai JSON ringkas dan 139 byte sebagai TSV untuk 21 field yang sama, sekitar 2,9 kali lipat; selisihnya adalah nama field yang diulang di setiap baris JSON. Splunk menghitung lisensi dari volume data mentah yang di-index, jadi JSON lebih mahal. PT JAB tetap memilih JSON karena ketahanannya terhadap perubahan field, dan menekan volume dengan memilih log yang dikirim, bukan dengan format.

**Volume.** Hari pertama, 08:00 sampai 16:00, index `zeek` menerima 26.536.400 event, sekitar 11,26 GB (rincian per log di bagian 2.11). Grafik trafik NOC menunjukkan delapan jam kerja itu membawa sekitar 60% trafik harian egress dan core DC, sehingga proyeksi harian sekitar 18,8 GB. Angka ini harus diukur ulang setelah satu minggu penuh, karena hari pertama memuat lonjakan dari tuning.

## 2. Contoh dan langkah praktis: hari pertama `jkt-zeek01`

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Log PT JAB memakai alamat dokumentasi sebagai pengganti alamat publik (bagian 1.7). IOC di-defang di laporan; di query ditulis apa adanya karena hanya ada di Splunk. Perintah offline dijalankan di `jkt-nsm-ws01` (`10.20.70.20`) terhadap ekstrak pcap dari `jkt-pcap01`; untuk latihan, pakai lab pribadi (bagian 3). Waktu dalam WIB; `ts` di log adalah epoch UTC.

### 2.1 Mengolah pcap menjadi log (offline)

Langkah ini dipakai Sari untuk mencocokkan log live `jkt-zeek01` dengan pcap egress `INC-2027-067` dari `jkt-pcap01`, sekaligus contoh perintah dasar untuk lab.

**Tujuan:** mengubah pcap menjadi log Zeek di direktori kasus yang bersih, dengan skrip yang sama dengan sensor.

```
mkdir -p /cases/lab008/zeek && cd /cases/lab008/zeek
zeek -C -r /cases/lab008/capture.pcap local
# varian JSON untuk diumpankan ke SIEM
zeek -C -r /cases/lab008/capture.pcap local LogAscii::use_json=T

# PT JAB: ekstrak egress 10:40-10:45 dari jkt-pcap01, diproses di jkt-nsm-ws01
mkdir -p /cases/INC-2027-067/zeek-offline && cd /cases/INC-2027-067/zeek-offline
zeek -C -r /cases/INC-2027-067/egress_20270518_1040-1045.pcapng local
```

Penjelasan tiap bagian:

- `-r` membaca pcap offline; `-C` mengabaikan checksum salah akibat offloading (tanpa ini sebagian koneksi bisa hilang dari log); `local` memuat `site/local.zeek` sehingga hashing file aktif (bagian 1.7).
- Menghasilkan `conn.log`, `dns.log`, `http.log`, `ssl.log`, `files.log`, `x509.log`, `weird.log`, dan lainnya di direktori kerja. Jalankan di direktori kosong per kasus supaya log tidak tercampur.
- `LogAscii::use_json=T` mengubah semua log ke JSON tanpa mengubah `local.zeek`.

Keluaran ilustrasi (daftar file di direktori kasus PT JAB):

```
conn.log  dns.log  files.log  http.log  packet_filter.log  pe.log  ssl.log  weird.log  x509.log
```

**Cara membaca hasil:** mulai dari `conn.log` untuk peta koneksi, lalu log protokol untuk detail. Periksa juga `weird.log`: banyak entri checksum berarti `-C` lupa dipakai. `pe.log` muncul karena ada file PE di trafik; isinya metadata executable. Pcap ini hanya memuat egress, jadi hop workstation ke proxy (SPAN core) tidak ada di hasil offline; hanya log live `jkt-zeek01` yang memuat kedua hop. `capture_loss.log` tidak muncul karena interval 15 menit pertama belum lewat untuk pcap lima menit.

**Variasi:** muat skrip tambahan di command line tanpa mengubah `local.zeek`, misalnya `zeek -C -r capture.pcap local policy/protocols/conn/community-id-logging`, supaya `community_id` di hasil offline sama dengan sensor.

**Kapan gagal:** pcap terpotong (snaplen kecil) membuat log protokol kosong walau `conn.log` terisi; pcap yang tidak memuat awal koneksi menghasilkan banyak OTH; dan perintah tanpa `local` menghasilkan `files.log` tanpa hash, persis yang dialami Sari (bagian 1.7).

### 2.2 Membaca `conn.log`

Langkah ini adalah titik awal setiap kasus, termasuk `INC-2027-067`.

**Tujuan:** melihat peta koneksi dengan kolom yang menjawab siapa, ke mana, berapa lama, berapa byte, dan bagaimana berakhir.

```
zeek-cut id.orig_h id.resp_h id.resp_p proto service duration orig_bytes resp_bytes conn_state < conn.log

# PT JAB, dengan uid, history, dan waktu yang bisa dibaca manusia
zeek-cut -d ts uid id.orig_h id.resp_h id.resp_p service duration orig_bytes resp_bytes conn_state history < conn.log \
  | grep -E '203\.0\.113\.174'
```

Penjelasan tiap bagian:

- `zeek-cut <field...>` mengambil kolom berdasarkan nama di header `#fields`; urutan output mengikuti urutan argumen.
- `-d` mengubah `ts` epoch menjadi tanggal yang bisa dibaca; cek opsi di `zeek-cut -h` versi-mu.
- `grep -E` menyaring alamat tujuan; titik di-escape supaya tidak cocok dengan karakter apa pun.

Keluaran ilustrasi (egress offline, dua baris):

```
2027-05-18T03:42:06+0000  CHt3vR2kPq8sW1xYe  10.20.3.60  203.0.113.174  80  http  1.842117  371  912870  SF  ShADadFf
2027-05-18T03:58:31+0000  CwE4uI9oP2aS7dFg5  10.20.3.60  203.0.113.174  80  -     -         -    -       S0  S
```

**Cara membaca hasil:** tiap baris satu koneksi. `conn_state` SF berarti normal, S0/REJ berarti gagal atau scan (bagian 1.4). `resp_bytes` besar berarti unduhan besar; `orig_bytes` besar berarti kemungkinan exfiltration (Day 12). Baris pertama adalah hop proxy unduhan `INC-2027-067`: 912.870 byte payload dari server dalam 1,84 detik, ditutup normal. Baris kedua, 16 menit kemudian, adalah proxy mencoba lagi untuk `JKT-WS-2036` setelah `jkt-fw01` memblokir alamat itu pukul 10:56: hanya SYN, tanpa balasan, tanpa byte. S0 di sini adalah bukti bahwa blokir bekerja, bukan scan. Waktu `-d` ditampilkan dalam UTC; 03:42 UTC adalah 10:42 WIB.

**Variasi:** tambahkan `missed_bytes` untuk melihat apakah koneksi penting terkena packet loss; nilai bukan nol berarti isi `http.log` dan `files.log` untuk `uid` itu bisa tidak lengkap.

**Kapan gagal:** `conn.log` baru ditulis saat koneksi selesai, jadi koneksi yang masih berjalan belum muncul (bagian 1.2); dan field kosong ditulis `-`, sehingga `awk` yang menjumlahkan kolom harus menyaringnya (bagian 2.8).

### 2.3 Top tujuan dan SNI

Langkah ini dipakai pada jam pertama produksi untuk mengenali "normal" egress PT JAB sebelum mencari yang aneh.

**Tujuan:** menghitung tujuan dan SNI paling sering.

```
zeek-cut id.resp_h < conn.log | sort | uniq -c | sort -rn | head
zeek-cut server_name < ssl.log | sort | uniq -c | sort -rn | head
```

Penjelasan tiap bagian: `sort | uniq -c` menghitung kemunculan tiap nilai; `sort -rn` mengurutkan dari jumlah terbesar; `head` mengambil sepuluh teratas.

Keluaran ilustrasi (`ssl.log` egress 08:00 sampai 09:00, lima baris teratas):

```
 41822 login.microsoftonline.example
 30175 outlook.office.example
 18904 update.vendor-av.example
 12611 teams.messaging.example
  9037 cdn.media.example
```

**Cara membaca hasil:** tujuan dan SNI paling sering memberi gambaran ke mana host menyambung; domain tak dikenal dengan volume tinggi layak diperiksa (reputasi, Day 05 dan 06). Di egress PT JAB, sumber koneksi web hampir selalu `jkt-proxy01`, jadi daftar ini adalah daftar tujuan proxy. Pertanyaan "workstation mana" dijawab dari hop core (workstation ke proxy) atau log proxy.

**Variasi:** stacking terbalik (`sort -n | head`) untuk melihat SNI yang paling jarang, yang biasanya lebih menarik untuk hunting.

**Kapan gagal:** SNI kosong untuk sesi yang memakai ECH atau klien yang tidak mengirim SNI (Day 15); dan koneksi TLS yang diterowongkan lewat proxy eksplisit dengan `CONNECT` di hop core perlu dicek apakah tercatat di `ssl.log` versi-mu.

### 2.4 DNS untuk tunneling, DGA, dan scoping

Langkah ini menjawab bagian "kenapa nama host tidak ada di dns.log" dari pertanyaan kedua Dimas.

**Tujuan:** melihat pola query, dan mencari siapa yang me-resolve domain kasus.

```
zeek-cut query qtype_name rcode_name < dns.log | sort | uniq -c | sort -rn | head
zeek-cut query rcode_name < dns.log | grep NXDOMAIN

# PT JAB: siapa yang me-resolve domain kasus
zeek-cut -d ts uid id.orig_h id.resp_h query qtype_name rcode_name answers < dns.log | grep docs-share
```

Penjelasan tiap bagian: kolom `query`, `qtype_name`, dan `rcode_name` memberi nama, tipe record, dan hasilnya; `answers` memuat jawaban (alamat atau nama).

Keluaran ilustrasi (log live, dua baris):

```
2027-05-18T03:42:06+0000  CdN5sQ8vKj3mT1yHw  10.20.3.60  10.20.2.53     docs-share.example  A  NOERROR  203.0.113.174
2027-05-18T03:42:06+0000  CjU2xB7cRf4nE6tMq  10.20.2.53  198.51.100.53  docs-share.example  A  NOERROR  203.0.113.174
```

**Cara membaca hasil:** banyak NXDOMAIN nama acak adalah pola DGA (Day 05); banyak query panjang ke satu domain induk adalah pola tunneling. Zeek membuat ini terhitung cepat di skala besar. Untuk kasus PT JAB: baris pertama adalah `jkt-proxy01` bertanya ke `jkt-res01`, baris kedua adalah `jkt-res01` bertanya ke server otoritatif domain itu (dicontohkan dengan `198.51.100.53`). Tidak ada baris dari `10.10.60.83`, karena dengan proxy eksplisit workstation tidak me-resolve nama tujuan web. Untuk `JKT-WS-2036` pukul 10:58 tidak ada query baru sama sekali: jawaban masih di cache proxy (TTL). Scoping "siapa lagi yang mengakses domain ini" di PT JAB karena itu dilakukan di `http.log` hop core atau log proxy, bukan di `dns.log`.

**Variasi:** `zeek-cut query < dns.log | awk '{print length($1), $1}' | sort -rn | head` untuk query terpanjang.

**Kapan gagal:** host yang memakai DoH atau resolver publik tidak muncul di `dns.log` sensor (Day 16); dan cache resolver atau proxy membuat query kedua dan seterusnya tidak terlihat.

### 2.5 HTTP: user agent dan MIME

Langkah ini memperlihatkan hop core `INC-2027-067`, yaitu satu-satunya tempat alamat workstation dan URL lengkap muncul bersama.

**Tujuan:** membaca request HTTP dengan user agent dan tipe isi respons.

```
zeek-cut method host uri user_agent status_code resp_mime_types < http.log

# PT JAB, log live, request ke domain kasus
zeek-cut -d ts uid id.orig_h id.resp_h method host uri status_code resp_mime_types resp_fuids < http.log | grep docs-share
```

Keluaran ilustrasi (empat baris; kolom `user_agent` ditampilkan terpisah di bawah):

```
2027-05-18T03:42:06+0000  CqP7nX4dLw2bR9tFa  10.10.60.83  10.20.3.60     GET  docs-share.example  http://docs-share.example/inv/invoice_0518.pdf  200  application/x-dosexec  Fk2Wq9LmB7xRt4Nd1A
2027-05-18T03:42:06+0000  CHt3vR2kPq8sW1xYe  10.20.3.60   203.0.113.174  GET  docs-share.example  /inv/invoice_0518.pdf                           200  application/x-dosexec  Fp8Zc3Vn6HsQ1Ky5Ue
2027-05-18T03:58:31+0000  CbR6tY1nM8qW3zLp2  10.10.60.82  10.20.3.60     GET  docs-share.example  http://docs-share.example/inv/invoice_0518.pdf  503  text/html              Fr5Ty8Uq2Wd4Kc9Lz1
user_agent (ketiga request): Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Edg/...
```

**Cara membaca hasil:** UA kosong atau khas tool, atau `resp_mime_types` executable pada URI yang menyamar (Day 05), muncul sebagai baris yang mudah disaring. Baris pertama: `JKT-WS-2037` (`10.10.60.83`) meminta URL lengkap ke proxy; `uri` berbentuk URL absolut karena itulah bentuk request ke proxy eksplisit. Baris kedua: proxy meneruskan ke server dengan path saja. UA sama di kedua hop karena proxy meneruskannya; itu UA browser biasa, jadi unduhan terjadi lewat browser pengguna, bukan tool. Baris ketiga: `JKT-WS-2036` (`10.10.60.82`) meminta URL yang sama 16 menit kemudian dan mendapat 503 dari proxy, karena koneksi proxy ke server diblokir (baris S0 di bagian 2.2). `text/html` di baris itu adalah halaman error proxy, bukan file berbahaya. Kode status persis untuk kegagalan koneksi tergantung produk proxy.

**Variasi:** `zeek-cut user_agent < http.log | sort | uniq -c | sort -n | head` untuk UA paling jarang di hop core.

**Kapan gagal:** HTTPS yang tidak didekripsi tidak punya `http.log` isi (hanya `ssl.log`); dan bila request ke proxy dikirim lewat TLS, isinya tidak terlihat sama sekali.

### 2.6 `files.log`: payload, hash, dan arah

Langkah ini adalah dasar alert `SOC-2027-0636`, sekaligus jawaban untuk query `tx_hosts` Sari (pertanyaan keempat).

**Tujuan:** melihat file yang berpindah beserta tipe nyata, ukuran, hash, dan arahnya.

```
zeek-cut uid id.orig_h id.resp_h is_orig source mime_type filename total_bytes sha256 < files.log
```

Saved search Splunk `JAB-ZEEK-001 Executable bernama non-executable` (berjalan tiap 5 menit, rentang 10 menit terakhir; versi di bawah memakai rentang absolut untuk kasus ini):

```
index=zeek sourcetype=bro:files:json mime_type="application/x-dosexec"
    earliest="05/18/2027:10:30:00" latest="05/18/2027:10:50:00"
| where isnotnull(filename) AND NOT match(lower(filename), "\.(exe|dll|msi|scr|sys|com)$")
| eval sender=if(is_orig="true", 'id.orig_h', 'id.resp_h'),
       receiver=if(is_orig="true", 'id.resp_h', 'id.orig_h')
| stats min(_time) AS first_seen values(uid) AS uids values(sender) AS senders
        values(receiver) AS receivers values(filename) AS filenames
        max(total_bytes) AS bytes BY sha256
| convert ctime(first_seen)
```

| Bagian | Fungsi |
|---|---|
| `mime_type="application/x-dosexec"` | Isi file PE Windows menurut tanda tangan magic, bukan ekstensi (bagian 1.5) |
| `where isnotnull(filename) AND NOT match(...)` | Hanya file yang namanya tidak berakhiran ekstensi executable; nama kosong dibuang supaya tidak semua unduhan tanpa nama ikut |
| `eval sender=..., receiver=...` | Pengganti `tx_hosts`/`rx_hosts`: arah dari `is_orig` dan `id.*`. Field dengan titik ditulis dalam kutip tunggal di `eval` |
| `stats ... BY sha256` | Satu baris per isi file, walaupun file itu dibawa beberapa koneksi (hop proxy) |

Keluaran ilustrasi:

```
sha256        first_seen           uids                                  senders                    receivers                 filenames          bytes
4c1e...9a07   05/18/2027 10:42:06  CHt3vR2kPq8sW1xYe CqP7nX4dLw2bR9tFa   10.20.3.60 203.0.113.174   10.10.60.83 10.20.3.60    invoice_0518.pdf   912384
```

**Cara membaca hasil:** file yang ditransfer beserta hash dan tipe nyata (dari isi, bukan ekstensi). `source` menyebut protokol pembawa (HTTP, SMB, FTP_DATA); `is_orig` = `F` pada unduhan HTTP berarti file datang dari server. Hash bisa dicek reputasinya tanpa menyimpan file. Zeek bisa mengekstrak file bila dikonfigurasi; jangan simpan payload di repo. Satu baris `sha256` dengan dua `uid` adalah dua hop dari satu unduhan: server ke proxy, lalu proxy ke workstation. `invoice_0518.pdf` yang isinya PE Windows adalah nama dan isi yang tidak cocok, sinyal kuat penyamaran payload (Day 05). Ukuran 912.384 byte sama di kedua hop; `resp_bytes` di `conn.log` sedikit lebih besar karena ikut menghitung header HTTP.

**Variasi:** ganti filter `mime_type` dengan daftar tipe lain yang berisiko (skrip, arsip), atau hapus `where` untuk melihat semua executable yang lewat, lalu stacking per `sha256` untuk menemukan hash yang hanya muncul sekali.

**Kapan gagal:** hash kosong bila `hash-all-files` tidak dimuat; `missing_bytes` bukan nol membuat hash tidak mewakili file utuh; file di dalam HTTPS yang tidak didekripsi tidak pernah masuk `files.log`; dan nilai `is_orig` di JSON adalah boolean, sehingga perbandingan string `"true"` perlu dicek dengan satu event contoh di Splunk-mu.

### 2.7 Merangkai `INC-2027-067` lewat `uid`, waktu, dan hash

Langkah ini adalah jawaban lengkap pertanyaan kedua Dimas: lima log, dua koneksi, satu cerita.

**Tujuan:** menyusun urutan kejadian unduhan dengan bukti per langkah, lalu menentukan cakupan.

```
# ambil UID koneksi menarik dari conn.log, lalu cari di log lain
grep CmX3a21 conn.log http.log ssl.log files.log
# query DNS punya UID sendiri (koneksi UDP ke resolver), jadi pivot lewat nama atau IP
zeek-cut ts query answers < dns.log | grep 198.51.100.7
```

Dua perintah di atas adalah pola umum untuk lab (`CmX3a21` dan `198.51.100.7` adalah contoh pengganti). Di PT JAB, log live ada di Splunk; search berikut mengambil semua baris dari tiga `uid` kasus dan baris DNS dalam satu tabel waktu:

```
index=zeek earliest="05/18/2027:10:42:00" latest="05/18/2027:10:43:00"
    (uid IN ("CqP7nX4dLw2bR9tFa", "CHt3vR2kPq8sW1xYe", "CdN5sQ8vKj3mT1yHw")
     OR (sourcetype=bro:dns:json query="docs-share.example"))
| eval src='id.orig_h', dst='id.resp_h'
| table _time sourcetype uid src dst conn_state history query answers method uri mime_type fuid sha256 total_bytes
| sort _time
```

| Bagian | Fungsi |
|---|---|
| `earliest`/`latest` absolut | Satu menit di sekitar kejadian; bisa diulang dengan hasil sama |
| `uid IN (...)` | Semua log dari tiga koneksi: hop core, hop egress, dan query DNS proxy |
| `OR (... query=...)` | Query DNS lain untuk domain yang sama, termasuk dari resolver ke internet |
| `eval src=..., dst=...` | Menyalin field bertitik ke nama pendek supaya tabel rapi |
| `table ... \| sort _time` | Urutan waktu lintas sourcetype |

Keluaran ilustrasi, diringkas menjadi timeline kasus:

```
10:42:06.881  conn/http  CqP7nX4dLw2bR9tFa  10.10.60.83 -> 10.20.3.60:3128   GET http://docs-share.example/inv/invoice_0518.pdf
10:42:06.889  dns        CdN5sQ8vKj3mT1yHw  10.20.3.60 -> 10.20.2.53:53      docs-share.example A -> 203.0.113.174
10:42:06.903  conn/http  CHt3vR2kPq8sW1xYe  10.20.3.60 -> 203.0.113.174:80   GET /inv/invoice_0518.pdf  200
10:42:08.745  files      Fp8Zc3Vn6HsQ1Ky5Ue (uid CHt3...)  is_orig=F  application/x-dosexec  912384  sha256 4c1e...9a07
10:42:08.851  files      Fk2Wq9LmB7xRt4Nd1A (uid CqP7...)  is_orig=F  application/x-dosexec  912384  sha256 4c1e...9a07
10:42:08.852  conn       CqP7nX4dLw2bR9tFa  SF ShADadFf  resp_bytes 912955   (baris ditulis saat koneksi selesai)
```

**Cara membaca hasil:** satu `uid` menghubungkan koneksi ke permintaan HTTP, handshake TLS, dan file di dalamnya. Ini merangkai "koneksi ini mengunduh file itu lewat permintaan ini" menjadi satu cerita. Untuk kasus ini, ceritanya dibaca per langkah dengan bukti masing-masing:

1. `JKT-WS-2037` meminta URL ke proxy pukul 10:42:06.881 (`http.log`, `uid` `CqP7...`, field `id.orig_h`, `uri`).
2. Proxy me-resolve domain 8 milidetik kemudian (`dns.log`, `uid` `CdN5...`, `answers` = `203.0.113.174`). Waktunya lebih awal dari koneksi egress, cocok dengan urutan resolve lalu connect.
3. Proxy menghubungi server 14 milidetik setelah query (`conn.log` dan `http.log`, `uid` `CHt3...`), path sama dengan URL di langkah 1.
4. Server mengirim file PE 912.384 byte (`files.log`, `fuid` `Fp8Z...`, `is_orig` = `F`, `mime_type`, `sha256`).
5. Proxy meneruskan file yang sama ke workstation (`files.log`, `fuid` `Fk2W...`, hash sama). Dua `fuid` berbeda karena dua koneksi menganalisis dua salinan; hash yang sama membuktikan isinya identik.

Yang di luar Zeek melengkapi cerita: log proxy (`index=proxy`) mencatat sumber `10.10.60.83` untuk URL yang sama, dan Microsoft Defender for Endpoint mengkarantina file itu di `JKT-WS-2037` pukul 10:42:19 tanpa catatan eksekusi. Dimas membuka `INC-2027-067` pukul 11:02.

Cakupan yang ditulis di tiket, dengan bukti Zeek:

- **Siapa lagi:** `http.log` hop core sejak 08:00 hanya memuat dua host untuk `docs-share.example`: `10.10.60.83` (`JKT-WS-2037`, berhasil) dan `10.10.60.82` (`JKT-WS-2036`, 503 setelah blokir). Sebelum 08:00 tidak ada data Zeek; log proxy 30 hari tidak memuat host lain.
- **Komunikasi lanjutan:** tidak ada koneksi dari `10.20.3.60` atau dari kedua workstation ke `203.0.113.174` antara 10:42:09 dan 16:00, selain satu S0 setelah blokir.
- **Kesehatan sensor:** `capture_loss.log` interval 10:30 sampai 10:45 di bawah 1% untuk semua worker; `missed_bytes` = 0 untuk kedua koneksi unduhan.
- **Di luar cakupan:** trafik HTTPS yang tidak didekripsi proxy (hanya metadata), dan workstation yang memakai jalur selain proxy.

Indikator bukan kesimpulan. Yang terbukti dari Zeek: file PE bernama PDF dikirim ke `JKT-WS-2037` lewat proxy. Yang tidak terbukti dari Zeek: apakah file itu berbahaya (perlu analisis hash dan sampel oleh pihak yang berwenang) dan apakah sempat dijalankan (bukti endpoint dari MDE). Jebakan: query DNS yang mendahului koneksi tidak berbagi `uid` dengan koneksi TCP-nya, karena DNS adalah koneksi terpisah ke resolver; dan di balik proxy eksplisit, query itu milik proxy, bukan workstation.

**Variasi:** setelah `community_id` aktif, tambahkan field itu ke `table` untuk mencari alert Suricata yang sama di index `suricata` (mulai 2027-05-19, Day 09).

**Kapan gagal:** jam sistem sensor tidak sinkron (selisih milidetik antar hop tidak bisa dipercaya bila NTP bermasalah); deduplikasi di packet broker mati sehingga hop egress tercatat dua kali; atau koneksi masih berjalan sehingga baris `conn.log`-nya belum ada saat search dijalankan.

### 2.8 Ringkasan per host dengan `awk`

Langkah ini dipakai untuk pertanyaan "pasangan mana yang mengunggah paling banyak hari ini", bahan awal untuk Day 12.

**Tujuan:** menjumlahkan byte keluar per pasangan sumber dan tujuan.

```
# total byte keluar per pasangan sumber-tujuan, hanya koneksi yang memuat data
zeek-cut id.orig_h id.resp_h orig_bytes < conn.log \
  | awk '$3 != "-" {sum[$1" "$2]+=$3} END {for (k in sum) print sum[k], k}' \
  | sort -rn | head
```

Penjelasan tiap bagian: `$3 != "-"` membuang baris tanpa nilai byte; `sum[$1" "$2]+=$3` menjumlahkan per pasangan; `END` mencetak total; `sort -rn | head` mengambil pasangan terbesar.

Keluaran ilustrasi (egress offline 10:40 sampai 10:45, tiga baris teratas):

```
1840221907 10.20.3.60 203.0.113.140
 412887310 10.20.3.60 192.0.2.210
  96541022 10.20.3.60 192.0.2.211
```

**Cara membaca hasil:** baris teratas adalah pasangan dengan upload terbesar, bahan awal untuk Day 12. Nilai `-` (field kosong) disaring supaya awk tidak menjumlahkan teks. Di egress PT JAB, sumber hampir selalu proxy, jadi tujuan yang menonjol diterjemahkan kembali ke workstation lewat hop core atau log proxy sebelum disebut temuan. Unggahan besar ke layanan backup atau penyimpanan cloud resmi adalah penjelasan jinak yang paling umum.

**Variasi:** ganti `orig_bytes` dengan `resp_bytes` untuk unduhan terbesar, atau tambahkan `id.resp_p` ke kunci untuk memisahkan per layanan.

**Kapan gagal:** `orig_bytes` diambil dari sequence number dan bisa tidak akurat pada koneksi besar (bagian 1.2); koneksi panjang yang belum selesai belum masuk `conn.log`.

### 2.9 `conn_state` untuk `SOC-2027-0638` dan uji penerimaan sensor

Langkah ini menjawab pertanyaan ketiga Dimas dengan angka, lalu memakai field yang sama untuk menguji kesehatan SPAN, seperti diingatkan rancangan sensor di Day 01 bagian 2.2.

**Tujuan pertama:** melihat apa saja dari `203.0.113.175` yang sampai ke `198.51.100.208` (`jkt-dmz-status01`, halaman status layanan pelanggan `status.jab.example`).

```
index=zeek sourcetype=bro:conn:json id.orig_h="203.0.113.175"
    earliest="05/18/2027:13:00:00" latest="05/18/2027:13:10:00"
| stats count BY id.resp_h id.resp_p conn_state history
```

Keluaran ilustrasi:

```
id.resp_h        id.resp_p  conn_state  history  count
198.51.100.208   80         RSTO        ShR      1
198.51.100.208   443        RSTO        ShR      1
198.51.100.208   8080       REJ         Sr       1
```

Pembanding dari firewall (`index=firewall`, rentang sama): 1.000 percobaan port TCP dari `203.0.113.175` ke `198.51.100.208` antara 13:01:12 dan 13:04:40, 997 ditolak dan 3 diizinkan.

**Cara membaca hasil:** tiga baris Zeek cocok dengan tiga yang diizinkan firewall (997 ditambah 3 sama dengan 1.000). Dua `ShR` adalah SYN scan yang menemukan port terbuka 80 dan 443, lalu dibatalkan scanner sebelum handshake selesai; server web tidak mencatat apa-apa karena koneksi tidak pernah terbentuk. Satu `Sr` di 8080 adalah port yang masih diizinkan aturan firewall lama walaupun layanannya sudah tidak ada. Kesimpulan: pemindaian internet biasa, tanpa sesi lanjutan dari `203.0.113.175` setelah 13:04:40; tindak lanjutnya membersihkan aturan 8080 di `jkt-fw01`. Alert ditutup sebagai aktivitas pemindaian tanpa dampak.

**Tujuan kedua:** uji penerimaan SPAN core, yaitu memastikan Zeek melihat dua arah koneksi.

```
index=zeek sourcetype=bro:conn:json proto=tcp earliest="05/18/2027:08:00:00" latest="05/18/2027:09:00:00"
| eval sides=case(match(history, "[A-Z]") AND match(history, "[a-z]"), "dua_arah",
                  match(history, "[A-Z]"), "hanya_orig", true(), "hanya_resp")
| stats count BY sides conn_state
| sort - count
```

Keluaran ilustrasi (lima baris teratas):

```
sides       conn_state  count
dua_arah    SF          3962114
dua_arah    S1          401873
dua_arah    OTH         188420
hanya_orig  S0          97455
dua_arah    REJ         21008
```

**Cara membaca hasil:** dominasi `dua_arah` berarti SPAN dan TAP menyalin rx dan tx. Bila sebagian besar koneksi `hanya_orig` atau `hanya_resp`, SPAN dikonfigurasi satu arah dan Zeek hanya melihat setengah koneksi. OTH 188.420 di jam pertama wajar karena koneksi yang sudah berjalan sebelum 08:00 dilihat dari tengah. S0 `hanya_orig` adalah upaya koneksi tanpa balasan (termasuk yang ditolak firewall di jalur keluar); bila jumlahnya melonjak hanya untuk satu segmen, cek apakah VLAN balasan ikut di-SPAN. Kelas regex di Splunk peka huruf besar/kecil, jadi `[A-Z]` dan `[a-z]` memisahkan dua arah dengan benar; huruf `^` tidak masuk keduanya.

**Variasi:** `stats count BY id.orig_h conn_state | where in(conn_state, "S0", "REJ")` untuk mencari satu sumber dengan banyak upaya gagal ke banyak tujuan, pola sweep internal (Day 04).

**Kapan gagal:** pemindaian yang ditolak firewall tidak terlihat sama sekali oleh sensor di sisi dalam; dan scanner yang sangat lambat tersebar di banyak interval sehingga tidak menonjol dalam satu jendela 10 menit.

### 2.10 Notice, weird, dan capture loss: `SOC-2027-0635` dan `SOC-2027-0637`

Langkah ini menjawab pertanyaan kelima Dimas dengan tiga search pendek.

**Tujuan:** memisahkan kesehatan sensor dari sinyal keamanan.

```
index=zeek sourcetype=bro:capture_loss:json earliest="05/18/2027:08:00:00" latest="05/18/2027:12:00:00"
| table _time peer gaps acks percent_lost
| where percent_lost >= 1
```

Keluaran ilustrasi:

```
_time                 peer        gaps    acks     percent_lost
2027-05-18 09:15:12   worker-1-1  41210   1301877  3.165
2027-05-18 09:15:12   worker-1-2  159285  1284560  12.400
2027-05-18 09:15:12   worker-1-3  47930   1296455  3.697
2027-05-18 09:15:12   worker-1-4  38877   1279310  3.039
```

**Cara membaca hasil:** `percent_lost` sudah dalam persen dan sama dengan `gaps` dibagi `acks` dikali 100 (159.285 dibagi 1.284.560 sama dengan 12,40%). Hanya `worker-1-2` yang melewati 10%, sehingga hanya ia yang memicu `CaptureLoss::Too_Much_Loss` dan alert `SOC-2027-0635` pukul 09:16. Pola satu worker jauh lebih tinggi menunjuk elephant flow, bukan kekurangan CPU merata (bagian 1.8). Untuk laporan, catat bahwa data 09:00 sampai 09:15 dari worker itu tidak lengkap.

```
index=zeek sourcetype=bro:notice:json earliest="05/18/2027:08:00:00" latest="05/18/2027:11:15:00"
| stats count dc(dst) AS servers BY note src
| sort - count
| head 5
```

Keluaran ilustrasi:

```
note                       src          count  servers
SSL::Invalid_Server_Cert   10.20.4.30   2316   193
CaptureLoss::Too_Much_Loss -            1      -
SSH::Password_Guessing     10.10.60.86  1      1
```

**Cara membaca hasil:** 2.316 notice sertifikat dari `jkt-mon01` ke 193 antarmuka BMC di `10.20.250.0/24`. Konfirmasi ke Agung: antarmuka BMC memakai sertifikat self-signed bawaan pabrik, dan `jkt-mon01` memeriksanya terus. Label: jinak (`SOC-2027-0637` ditutup), dengan dua tindak lanjut: saved search notice di Splunk mengecualikan pasangan `src=10.20.4.30` dan `dst` di `10.20.250.0/24` untuk tipe ini saja, dan penggantian sertifikat BMC masuk rencana Infrastruktur. Baris `SSH::Password_Guessing` dari `10.10.60.86` (`JKT-WS-2038`) adalah percobaan SSH berulang ke satu server lab NOC oleh engineer yang salah memasukkan password kunci; dicek ke pemiliknya dan ditutup tanpa alert terpisah. Notice adalah bahan triage, bukan vonis.

```
index=zeek sourcetype=bro:weird:json earliest="05/18/2027:08:00:00" latest="05/18/2027:16:00:00"
| stats count BY name
| sort - count
| head 5
```

Keluaran ilustrasi:

```
name                              count
TCP_seq_underflow_or_misorder     61204
window_recision                   38117
data_after_reset                  29870
line_terminated_with_single_CR    17402
bad_HTTP_request                  9311
```

**Cara membaca hasil:** total weird hari itu 180.000; lima nama teratas di atas menyumbang 155.904. Semua nama itu tercantum sebagai contoh weird umum di dokumentasi Zeek, dan volumenya stabil per jam kecuali saat tuning. Weird bukan ukuran drop; ukuran drop adalah tabel capture loss di atas. Lonjakan `TCP_seq_underflow_or_misorder` yang tiba-tiba setelah perubahan di `jkt-npb01` adalah alasan untuk mengecek deduplikasi dan simetri trafik.

**Variasi:** `stats count BY name uid` lalu join manual ke `uid` kasus untuk melihat apakah koneksi yang diinvestigasi punya keganjilan protokol.

**Kapan gagal:** notice yang disupresi tidak muncul berulang, jadi jumlah notice bukan jumlah kejadian; dan capture loss tidak mengukur UDP.

### 2.11 Onboarding Splunk: `inputs.conf`, validasi, volume, dan `SOC-2027-0639`

Langkah ini adalah jawaban pertanyaan ketujuh Dimas dalam bentuk konfigurasi dan angka.

**Tujuan:** mengirim log JSON `jkt-zeek01` ke index `zeek` dengan sourcetype yang dikenali TA for Zeek, lalu memantau kelancarannya.

```
# /opt/splunkforwarder/etc/apps/jab_zeek_inputs/local/inputs.conf di jkt-zeek01
[monitor:///opt/zeek/logs/current/conn.log]
index = zeek
sourcetype = bro:conn:json

[monitor:///opt/zeek/logs/current/dns.log]
index = zeek
sourcetype = bro:dns:json

[monitor:///opt/zeek/logs/current/files.log]
index = zeek
sourcetype = bro:files:json

# ... satu stanza per log yang dikirim: http, ssl, x509, notice, weird, capture_loss, pe, smb_*, kerberos, ntlm, dce_rpc
```

| Bagian | Fungsi |
|---|---|
| `monitor:///opt/zeek/logs/current/<log>.log` | File log aktif zeekctl; file lama yang sudah dirotasi tidak dibaca ulang |
| `index = zeek` | Index program NSM |
| `sourcetype = bro:<log>:json` | Sourcetype eksplisit per log (bagian 1.9); add-on TA for Zeek terpasang di indexer dan search head |

Validasi di index staging sebelum produksi:

```
| metadata type=sourcetypes index=zeek_staging
| table sourcetype totalCount lastTime

index=zeek_staging sourcetype=bro:conn:json | head 1 | table _time ts src_ip dest_ip dest_port conn_state conn_state_meaning
```

**Cara membaca hasil:** semua sourcetype yang dikirim harus muncul; event `bro:conn:json` harus punya field CIM (`src_ip`, `dest_ip`, `conn_state_meaning`) dan `_time` yang sama dengan `ts`. Bila field CIM tidak ada, add-on tidak mengenali sourcetype itu.

Volume hari pertama (dari `index=_internal` metrik lisensi per sourcetype, 08:00 sampai 16:00). Tabel ini dipakai untuk menjawab "berapa GB per hari"; perhatikan bahwa conn dan dns sudah lebih dari 70% total.

| Sourcetype | Event | Rata-rata byte/event | Volume |
|---|---|---|---|
| `bro:conn:json` | 14.200.000 | 420 | 5,964 GB |
| `bro:dns:json` | 6.100.000 | 380 | 2,318 GB |
| `bro:ssl:json` | 3.400.000 | 450 | 1,530 GB |
| `bro:http:json` | 1.250.000 | 620 | 0,775 GB |
| `bro:files:json` | 410.000 | 520 | 0,213 GB |
| `bro:x509:json` | 95.000 | 900 | 0,086 GB |
| `bro:weird:json` | 180.000 | 300 | 0,054 GB |
| `bro:notice:json` | 1.400 | 500 | 0,001 GB |
| lainnya (smb, kerberos, dhcp, capture_loss, dll.) | 900.000 | 350 | 0,315 GB |
| Total | 26.536.400 | | 11,256 GB |

Proyeksi harian: 11,256 GB dibagi 0,6 sama dengan sekitar 18,8 GB per hari (asumsi delapan jam kerja membawa 60% trafik harian). conn dan dns bersama 8,282 GB, 73,6% dari total. Bila anggaran lisensi tidak cukup, opsi yang dibahas adalah mengurangi log yang dikirim (misalnya tidak mengirim `weird` ke Splunk dan membacanya di sensor saja), bukan beralih ke TSV, karena parsing JSON lebih tahan perubahan.

Saved search `JAB-ZEEK-HEALTH-01` (tiap 5 menit) untuk mendeteksi jeda log:

```
| tstats latest(_time) AS last_event WHERE index=zeek sourcetype=bro:conn:json BY host
| eval lag_sec=now() - last_event
| where lag_sec > 300
```

**Cara membaca hasil:** satu baris berarti `conn.log` dari host itu tidak masuk lebih dari 5 menit. Pukul 14:05 search ini memicu `SOC-2027-0639` untuk jeda 13:58:10 sampai 14:04:40 setelah `zeekctl deploy` (bagian 1.8). Tindak lanjut: setiap deploy dicatat di change log dengan jam mulai dan selesai, diumumkan ke SOC, dan jendela itu ditulis sebagai celah data di laporan yang mencakup jam tersebut.

**Variasi:** ganti `sourcetype=bro:conn:json` dengan `bro:capture_loss:json` untuk memastikan skrip capture loss tetap berjalan; ketiadaan capture loss berarti tidak ada ukuran kesehatan.

**Kapan gagal:** `conn.log` sepi di malam hari bisa memicu alert palsu bila ambang terlalu ketat; nama sourcetype yang salah ketik di satu stanza membuat log itu tidak ter-parse tanpa error yang jelas; dan file yang dirotasi saat forwarder mati bisa terlewat bila hanya `current/` yang dipantau.

### 2.12 Satu halaman jawaban untuk Dimas

Ringkasan ini dikirim pukul 17:30 untuk laporan pagi Dimas ke Hendra dan Bambang. Setiap baris merujuk subbagian, supaya Dimas bisa membaca alasannya bila ditanya.

| Pertanyaan | Jawaban singkat | Dasar |
|---|---|---|
| Log apa saja, mana yang dipakai | Lebih dari dua puluh log; harian: conn, dns, http, ssl, files, notice; weird dan capture_loss untuk kesehatan sensor | Bagian 1.1, 1.2 |
| Menyambung satu kejadian | `uid` untuk satu koneksi; waktu, URL, dan hash untuk DNS dan hop proxy; proxy yang me-resolve nama, bukan workstation | Bagian 1.3, 2.7 |
| `ShR`, `S0`, scan atau bukan | `ShR` SYN scan ke port terbuka, `S0` tanpa balasan (termasuk blokir yang bekerja); PT JAB di-scan seperti semua alamat publik, yang tembus hanya 80, 443, dan satu aturan 8080 lama | Bagian 1.4, 2.9 |
| `tx_hosts` kosong | Dihapus sejak Zeek 5.1; arah dari `is_orig` dan `id.*`; query sudah ditulis ulang | Bagian 1.5, 2.6 |
| Notice dan weird | Notice bahan alert setelah tuning; weird kebanyakan noise; drop diukur dari capture loss, bukan weird | Bagian 1.6, 2.10 |
| Satu server atau cluster | Satu server sebagai cluster satu host, 10 worker, flow replikasi storage dikeluarkan; deploy diumumkan sebagai jendela buta | Bagian 1.8 |
| Sourcetype, format, volume | TA for Zeek 1.0.11, JSON, `bro:<log>:json` eksplisit, sekitar 18,8 GB per hari (ukur ulang setelah seminggu) | Bagian 1.9, 2.11 |

**Kapan gagal:** jawaban dikirim tanpa menyebut jendela buta hari pertama (sebelum 08:00, 09:00 sampai 09:15 di satu worker, dan 13:58 sampai 14:04). Tanpa itu, pembaca akan menganggap Zeek melihat seluruh hari.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** instalasi Zeek di lab (VM sensor Linux dengan snapshot) atau log Zeek contoh; pcap lab atau pcap publik dari sumber tepercaya; Wireshark untuk penyelaman paket; Splunk lab dengan TA for Zeek bila ingin mengerjakan langkah 9 dan 10; jaringan host-only `192.168.56.0/24`. Jangan memakai pcap kerja; PT JAB hanya contoh fiktif.

1. **Olah.** `zeek -C -r capture.pcap local`; identifikasi log apa yang muncul (bagian 2.1). Ulangi tanpa `local` di direktori lain, lalu bandingkan `files.log` keduanya: catat field mana yang kosong tanpa `local`.
2. **conn.log.** Baca peta koneksi; tandai `conn_state` S0/REJ (scan atau gagal) vs SF (bagian 2.2). Catat jumlah tiap `conn_state` dengan `zeek-cut conn_state < conn.log | sort | uniq -c`.
3. **Top tujuan/SNI.** Hitung tujuan dan SNI tersering (bagian 2.3); periksa yang tak dikenal.
4. **DNS.** Cari NXDOMAIN dan query panjang (bagian 2.4); kaitkan ke DGA atau tunneling.
5. **HTTP/files.** Periksa UA dan MIME (bagian 2.5); daftar file dan hash dari `files.log` (bagian 2.6). Tulis arah setiap file dengan aturan `is_orig` (bagian 1.5).
6. **UID.** Pilih satu koneksi menarik; rangkai ceritanya lewat `uid` di semua log (bagian 2.7). Cari query DNS pasangannya lewat `answers` dan selisih `ts`.
7. **Wireshark.** Ambil satu koneksi dari Zeek dan buka paketnya di Wireshark untuk detail; bandingkan apa yang Zeek ringkas vs apa yang paket tunjukkan.
8. **conn_state dari scan sendiri.** Di VM lab, jalankan SYN scan dari VM penyerang lab ke VM target lab (`192.168.56.0/24`) untuk beberapa port terbuka dan tertutup, dengan firewall host target menolak sebagian port secara diam. Capture di VM sensor, olah dengan Zeek, lalu catat pasangan `history` dan `conn_state` untuk port terbuka, tertutup (RST), dan difilter (diam). Bandingkan dengan tabel bagian 1.4, khususnya apakah `ShR` jatuh ke RSTO di versi Zeek-mu.
9. **JSON vs TSV.** Olah pcap yang sama dengan dan tanpa `LogAscii::use_json=T`. Hitung ukuran `conn.log` keduanya dengan `wc -c` dan rasio per baris. Bandingkan dengan rasio sekitar 2,9 di bagian 1.9.
10. **Splunk.** Kirim log JSON ke index lab dengan sourcetype `bro:conn:json` dan `bro:files:json`, lalu jalankan validasi bagian 2.11 dan saved search bagian 2.6 (sesuaikan rentang absolut). Catat nama sourcetype dan field CIM yang benar-benar muncul.
11. **Capture loss.** Jalankan Zeek live di VM sensor selama minimal 30 menit sambil membangkitkan trafik, lalu baca `capture_loss.log`. Hitung ulang `percent_lost` dari `gaps` dan `acks` untuk satu baris.

**Hasil yang sebaiknya tersimpan:**

- Log inti dikenali dan dipahami isinya, termasuk perbedaan dengan dan tanpa `local`.
- `conn_state` dipakai membedakan scan/gagal dari koneksi normal, dengan tabel pasangan `history` dan `conn_state` dari scan sendiri.
- Top tujuan/SNI/DNS dihitung dan yang mencurigakan ditandai.
- `files.log` dipakai mendapat hash/tipe nyata dan arah file tanpa menyimpan payload.
- `uid` dipakai merangkai cerita lintas log, dengan DNS pasangan yang disambung lewat waktu.
- Perbandingan Zeek (ringkas, luas) vs Wireshark (detail) dinyatakan.
- Ukuran JSON vs TSV terukur, dan daftar sourcetype serta field CIM dari Splunk lab.
- Satu baris `capture_loss.log` yang dihitung ulang.

**Variasi tantangan:** dari log Zeek satu pcap infeksi, tulis timeline berbasis `uid`: koneksi awal, query DNS/SNI tujuan, unduhan file (hash dari `files.log`), lalu koneksi C2. Sertakan IOC yang di-defang (domain, IP, hash) dan nyatakan field log mana yang menjadi bukti tiap langkah. Tambahkan satu VM Squid sebagai proxy eksplisit untuk VM klien, ulangi unduhan, lalu rangkai dua hop seperti bagian 2.7. Ini menyiapkan integrasi ke Splunk (Day 13).

## 4. Troubleshooting

Tabel ini memuat masalah yang muncul saat menjalankan Zeek offline, di sensor, dan di Splunk. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Log kosong untuk protokol | Trafik tidak terlihat/terenkripsi | ssl.log ada tapi http.log kosong berarti HTTPS |
| ja3/ja4 tidak ada di ssl.log | Paket fingerprint tidak dimuat | Pasang paket JA3 atau JA4 lewat `zkg`, lalu muat di `local.zeek` |
| zeek-cut tak kenal field | Nama field beda versi/log, atau log berformat JSON | Lihat baris header `#fields` di log; untuk JSON pakai `jq` |
| files.log kosong atau tanpa hash | Trafik terenkripsi, atau `local` tidak dimuat | Perlu trafik polos; jalankan dengan `local` agar hashing aktif |
| Kolom `tx_hosts` kosong | Field sudah dihapus sejak Zeek 5.1 | Pakai `uid`, `id.*`, dan `is_orig` (bagian 1.5) |
| Terlalu banyak log | Trafik besar | Saring dengan zeek-cut + grep; umpan ke SIEM |
| conn_state membingungkan | Beberapa state mirip | Baca `history` (bagian 1.4) untuk urutan flag yang sebenarnya |
| Banyak `weird` checksum, koneksi hilang (offline) | `-C` tidak dipakai pada capture dari host dengan offloading | Ulangi dengan `-C` |
| `capture_loss` tinggi di satu worker saja | Elephant flow di satu hash, atau hash tidak simetris | Cari flow terbesar pada interval itu; keluarkan flow yang dikenal di packet broker atau tambah worker (bagian 1.8) |
| `capture_loss` tinggi merata | Worker kurang, offloading NIC aktif, atau skrip berat | Tambah worker, matikan offloading dengan `ethtool -K`, tinjau skrip di `local.zeek` [S11] |
| Sebagian besar koneksi hanya satu sisi di `history` | SPAN satu arah atau VLAN balasan tidak ikut | Uji bagian 2.9; perbaiki sesi SPAN |
| Koneksi tercatat dobel, banyak `T` di `history` | Paket yang sama datang dari SPAN dan TAP | Aktifkan deduplikasi di packet broker; cek ulang setelah perubahan |
| Lonjakan OTH setelah jam tertentu | Sensor di-restart atau baru mulai | Cocokkan dengan change log; abaikan sebagai artefak bila sesuai |
| `local_orig`/`local_resp` kosong atau salah | `Site::local_nets` tidak diisi, atau alamat dokumentasi dianggap private | Isi `networks.cfg`; di lab, tulis `local_nets` eksplisit (bagian 1.7) |
| Sourcetype aneh muncul (misalnya `bro_00`) atau field CIM tidak ada | Sourcetype atau source tidak sesuai pola yang diharapkan add-on | Tulis sourcetype eksplisit atau pakai pola `bro:json` dengan `source = bro.<log>.log` [S18] |
| `_time` di Splunk berbeda dengan `ts` | Timestamp tidak dibaca dari field `ts` | Cek props add-on dan satu event contoh di staging |
| Jeda log di Splunk setelah perubahan | Deploy zeekctl, forwarder mati, atau disk penuh | Saved search jeda (bagian 2.11), `reporter.log`, dan change log |

## 5. Kesalahan umum dan jebakan

- **Mengira Zeek adalah IDS signature.** Zeek mencatat kejadian; alert signature lebih ke Suricata (Day 09). Keduanya berbeda fokus. Notice adalah yang paling dekat dengan alert, dan tetap perlu tuning.
- **Mengabaikan `uid`.** Tanpa `uid`, log terasa terpisah; `uid` yang merangkainya menjadi cerita.
- **Mengira `uid` menyambung semuanya.** DNS, hop proxy, dan sensor lain punya `uid` berbeda atau tidak punya sama sekali; sambung dengan waktu, alamat, URL, dan hash (bagian 1.3).
- **Mencari workstation di `dns.log` padahal ada proxy eksplisit.** Proxy yang me-resolve nama tujuan web; scoping lewat `http.log` hop core atau log proxy (bagian 2.4).
- **Percaya ekstensi, bukan `mime_type` di files.log.** `mime_type` Zeek dari isi, lebih tepat.
- **Membaca `id.orig_h` di `files.log` sebagai pengirim file.** Pengirim ditentukan `is_orig`; pada unduhan HTTP, pengirim adalah responder (bagian 1.5).
- **Menyimpan file hasil ekstraksi.** Catat hash; jangan simpan payload di repo.
- **Mengira Zeek menggantikan Wireshark.** Zeek untuk luas, Wireshark untuk detail paket; saling melengkapi.
- **Menganggap weird yang banyak sebagai drop, atau weird nol sebagai sensor sehat.** Kesehatan diukur dari `capture_loss.log` dan `missed_bytes` (bagian 1.6).
- **Membaca `percent_lost` 0,4 sebagai 40%.** Nilainya sudah persen [S10].
- **Menyimpulkan "tidak ada koneksi" dari log Zeek pada jam ketika sensor drop atau di-restart.** Tulis jendela buta di setiap laporan.
- **Menganggap firewall dan Zeek melihat hal yang sama.** Sensor di sisi dalam firewall tidak melihat yang ditolak firewall (bagian 1.4).
- **Memakai alamat dokumentasi di lab tanpa mengatur `local_nets`.** Zeek 6.0 ke atas menganggap `198.51.100.0/24` dan `203.0.113.0/24` lokal secara bawaan (bagian 1.7).
- **Mengira JSON memuat lebih banyak informasi daripada TSV.** Isinya sama; JSON hanya mengulang nama field dan karena itu lebih besar (bagian 1.9).
- **Menyalin query dengan sourcetype `bro:*` atau `zeek:*` dari panduan lain tanpa cek.** Nama sourcetype tergantung add-on dan konfigurasi input; cek dengan `| metadata type=sourcetypes index=zeek`.
- `[komunitas, belum terkonfirmasi]` Analis memakai `conn.log` sebagai titik awal hampir semua investigasi Zeek, lalu pivot ke log protokol lewat `uid`; pola ini umum di NSM dengan Zeek. Nama field dan `conn_state` bisa berbeda antar versi, cek terhadap header log di versi-mu.
- `[komunitas, belum terkonfirmasi]` Patokan sekitar 250 Mbps per core beredar luas di forum Zeek sebagai angka lama; angka per core yang lebih baru dari panduan WLCG [S16] jauh lebih tinggi. Keduanya hanya titik awal sebelum pengukuran capture loss.

## 6. Catatan terkini

Bagian ini menampung detail versi dan perubahan perilaku Zeek dan add-on Splunk yang relevan saat membaca dokumentasi atau tutorial lain.

- Zeek 9.0.0 adalah LTS terbaru (14 Sep 2026) dengan 8.0.10 (19 Agu 2026) sebagai LTS sebelumnya [S3]; field inti conn/dns/http/ssl stabil, tetapi cek catatan rilis bila memakai skrip lama. NEWS di cabang master sudah memuat catatan untuk Zeek 9.1.0 yang belum dirilis, antara lain analyzer DHCPv6 awal dengan `dhcpv6.log` [S4].
- Perubahan `files.log` di Zeek 5.1 (hilangnya `tx_hosts`/`rx_hosts`/`conn_uids`, dan baris terpisah per koneksi dengan `fuid` sama) masih membuat banyak tutorial lama keliru [S4].
- Sejak Zeek 6.0: Community ID bawaan (skrip `community-id-logging`), dan alamat private termasuk rentang dokumentasi dianggap lokal secara bawaan [S4][S13].
- Sejak Zeek 8.1: ZeroMQ menjadi backend cluster bawaan zeekctl (tidak terenkripsi secara bawaan), dan `zeek.conf` dengan `zeek-systemd-generator` tersedia untuk deployment satu node lewat systemd. Zeek 8.2 menambah enkripsi CURVE untuk ZeroMQ, yang di zeekctl aktif otomatis bila terdeteksi cluster multi-node. Zeek 9.0 membuat Broker deprecated (kemungkinan dihapus di 10.1), menghentikan pengembangan Management Framework, memperluas `zeek.conf` untuk beberapa interface dan multi-host, dan menambah kebijakan escape string JSON [S4].
- JA3/JA4 ditambahkan lewat paket (`zkg`), bukan bawaan; versi paket JA4 yang kompatibel dengan Zeek 9.0 perlu dicek di repo paketnya.
- TA for Zeek (Splunkbase 5466) versi 1.0.11 (21 Agu 2025) dirawat Corelight dan menggantikan add-on lama yang dirawat Splunk [S15]; Splunk Research memakai sourcetype `bro:conn:json`, `bro:http:json`, dan `bro:ssl:json` dengan add-on ini [S17].
- Banyak pipeline memakai Zeek sebagai sumber log jaringan utama ke SIEM, dengan Suricata untuk alert; keduanya dipasang berdampingan. Day 09 (Suricata) dan Day 13 (integrasi ke Splunk) membangun di atas log Zeek.

## 7. Cheat sheet

```
OLAH       zeek -C -r capture.pcap local [LogAscii::use_json=T]  -> conn/dns/http/ssl/files/x509/weird .log
           tanpa "local" = tanpa hash, tanpa capture-loss, tanpa validate-certs
conn.log   ts uid id.orig_h id.resp_h id.resp_p proto service duration orig_bytes resp_bytes conn_state history missed_bytes
           ditulis saat koneksi SELESAI ; orig/resp_bytes = payload (TCP dari seq, bisa tak akurat)
CONN_STATE S0 (SYN tanpa balasan) | SF (normal) | REJ (ditolak) | RSTO/RSTR (reset) | OTH (tengah koneksi)
           UDP: SF dua arah, S0 hanya orig ; ShR biasanya RSTO (cek di lab)
HISTORY    besar=orig kecil=resp ; S SYN, H SYN-ACK, A ACK, D data, F FIN, R RST ; ShR = SYN scan ke port terbuka
           C checksum, G gap, T retransmisi, W zero window, ^ arah dibalik ; C/G/T/W logaritmik (2x = >=10, 3x = >=100)
dns.log    query qtype_name rcode_name answers  -> NXDOMAIN+acak=DGA ; panjang ke 1 induk=tunneling
           proxy eksplisit: yang me-resolve = PROXY, bukan workstation
http.log   method host uri user_agent status_code resp_mime_types resp_fuids  -> UA aneh, MIME executable
ssl.log    server_name(SNI) version cipher established (+ja3/ja4 bila paket dimuat)
files.log  fuid uid id.orig_h id.resp_h is_orig source mime_type filename total_bytes missing_bytes sha256
           tx_hosts/rx_hosts hilang sejak 5.1 ; pengirim = is_orig ? orig_h : resp_h
UID        perekat: grep <UID> di semua log = rangkai cerita 1 koneksi
           DNS & hop proxy = uid lain -> sambung lewat answers, ts, host+uri, sha256
NOTICE     sinyal skrip (paling dekat alert) ; tuning dulu ; disupresi per note+identifier
WEIRD      keganjilan protokol, kebanyakan noise ; BUKAN ukuran drop
CAPLOSS    capture_loss.log: percent_lost = gaps/acks*100 (sudah persen) ; interval 15 mnt ; notice >= 10%
CLUSTER    worker (analisis) | manager | logger | proxy ; AF_PACKET hash simetris ; 1 flow = 1 worker
           worker <= core-2 ; ~6 GB RAM/worker ; patokan 250 Mbps s.d. 1 Gbps per core -> ukur capture loss
SPLUNK     TA for Zeek (5466) 1.0.11 ; index=zeek sourcetype=bro:<log>:json ; JSON ~2.9x TSV per baris
           | metadata type=sourcetypes index=zeek ; field bertitik di eval: 'id.orig_h'
ANALISIS   zeek-cut <field> < log | sort | uniq -c | sort -rn | head      (JSON: jq)
PAKAI      Zeek=luas/korelasi/SIEM ; Wireshark=detail paket 1 koneksi
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Query Sari di `files.log` memakai `tx_hosts` dan hasilnya kosong di semua baris. Berarti `jkt-zeek01` tidak melihat arah transfer file, dan sensornya perlu diperiksa." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Sejak Zeek 5.1, `files.log` secara bawaan tidak lagi memuat `tx_hosts`, `rx_hosts`, dan `conn_uids`; field itu diganti `uid` dan `id`, dan skrip untuk memunculkannya kembali sudah dihapus di Zeek 6.1. Sensornya sehat; query-nya yang usang. Arah file dibaca dari `is_orig`: bila `T`, pengirim adalah `id.orig_h`; bila `F`, pengirim adalah `id.resp_h`, seperti pada unduhan HTTP. Lihat bagian 1.5.

</details>

**2. Skenario keputusan.** `capture_loss.log` interval 09:00 sampai 09:15 menunjukkan `worker-1-2` 12,4% sementara tiga worker lain sekitar 3%. Trafik puncak 2,3 Gbps dibagi ke 4 worker. Langkah mana yang paling tepat?

- A. Abaikan, karena dokumentasi Zeek menyebut sedikit loss masih bisa ditoleransi, dan weird.log tidak menunjukkan lonjakan.
- B. Cari flow terbesar pada interval itu, karena satu worker yang jauh di atas yang lain menunjuk elephant flow yang ditaruh hash simetris ke satu worker; tambah worker, keluarkan flow yang dikenal di packet broker sebagai blind spot tertulis, dan catat jendela loss di laporan.
- C. Tambah RAM sensor dua kali lipat, karena loss selalu berarti memori tidak cukup.

<details><summary>Jawaban</summary>

B. Pola loss tinggi di satu worker saja cocok dengan elephant flow, karena AF_PACKET membagi trafik dengan hash flow simetris sehingga satu flow besar selalu jatuh ke satu worker; perbaikannya menambah worker dan mengeluarkan flow yang sudah dikenal, sambil menulis jendela loss dan blind spot-nya. A keliru karena 12,4% sudah melewati ambang notice 10%, dan weird bukan ukuran drop. C keliru karena masalahnya distribusi beban per worker, bukan memori total; dengan 6 GB per worker, RAM 128 GB sudah cukup untuk 10 worker. Lihat bagian 1.6 dan 1.8.

</details>

**3. Pertanyaan jebakan.** "Untuk mencari siapa lagi yang mengakses `docs-share.example`, cukup cari nama itu di `dns.log`; host yang tidak muncul di sana berarti tidak pernah mengakses domain itu." Benarkah untuk PT JAB?

<details><summary>Jawaban</summary>

Tidak. Workstation PT JAB keluar ke web lewat proxy eksplisit `jkt-proxy01`, sehingga yang me-resolve nama tujuan adalah proxy, bukan workstation; `dns.log` memuat query dari `10.20.3.60` dan dari resolver ke internet, tidak dari `10.10.60.83`. Cache proxy juga membuat akses berikutnya tidak menghasilkan query baru, seperti `JKT-WS-2036` pukul 10:58. Scoping dilakukan lewat `http.log` hop core (workstation ke proxy) atau log proxy. Lihat bagian 1.3 dan 2.4.

</details>

**4. Skenario keputusan.** `conn.log` menunjukkan dua baris `ShR` dari `203.0.113.175` ke `198.51.100.208` port 80 dan 443, dan satu `Sr` ke port 8080, sementara firewall mencatat 997 penolakan dari alamat yang sama dalam empat menit. Kesimpulan mana yang paling tepat?

- A. Server status pelanggan sudah dibobol, karena Zeek mencatat koneksi ke port 80 dan 443.
- B. Pemindaian SYN dari internet; hanya port yang diizinkan firewall sampai ke server, 80 dan 443 terbuka tanpa handshake selesai, dan 8080 adalah aturan firewall lama tanpa layanan. Cek tidak ada sesi lanjutan dari alamat itu, lalu bersihkan aturan 8080.
- C. Zeek salah mencatat, karena firewall melihat 1.000 percobaan sedangkan Zeek hanya 3.

<details><summary>Jawaban</summary>

B. `ShR` adalah SYN, SYN-ACK, lalu RST dari originator: pola SYN scan yang menemukan port terbuka tanpa pernah menyelesaikan handshake, dan `Sr` adalah port tertutup yang dibalas RST. Tiga baris Zeek cocok dengan tiga koneksi yang diizinkan firewall, karena sensor ada di sisi dalam firewall. A keliru karena tidak ada handshake lengkap atau data, apalagi sesi lanjutan. C keliru karena perbedaan angka justru menunjukkan posisi sensor: yang ditolak firewall tidak pernah sampai ke sensor. Lihat bagian 1.4 dan 2.9.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Bambang Hartono (Manajer NOC), dalam tiga kalimat, beda `notice.log`, `weird.log`, dan `capture_loss.log`, dan mana yang menjawab kekhawatirannya bahwa sensor drop.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "`notice.log` berisi hal yang ditandai skrip Zeek sebagai layak diperhatikan, seperti sertifikat tidak valid atau tebakan password SSH, mirip event minor di NMS yang perlu dilihat tetapi belum tentu tiket. `weird.log` berisi keganjilan protokol, mirip counter malformed packet: di jaringan nyata jumlahnya memang ratusan ribu dan kebanyakan noise. Yang mengukur drop adalah `capture_loss.log`, mirip counter discard di port monitoring, dan hari ini hanya satu worker yang melewati 10% selama 15 menit karena satu flow replikasi besar, yang sudah ditangani."

Kesalahan yang sering muncul:
- Menyebut weird yang banyak sebagai bukti drop, padahal drop diukur dari celah TCP di `capture_loss.log`.
- Menyebut notice sebagai insiden, padahal 2.316 notice sertifikat hari ini jinak.
- Membaca `percent_lost` 12,4 sebagai rasio, bukan persen.

</details>

**6. Pertanyaan jebakan.** "Kita pilih JSON karena log Zeek berformat JSON memuat lebih banyak field dan informasi daripada TSV, jadi biaya lisensi Splunk yang hampir tiga kali lipat per baris sepadan." Benarkah alasannya?

<details><summary>Jawaban</summary>

Kesimpulannya boleh, tetapi alasannya salah. Isi field JSON dan TSV sama; JSON lebih besar karena nama field diulang di setiap baris (407 byte vs 139 byte untuk baris `conn.log` yang sama, sekitar 2,9 kali). Alasan PT JAB memilih JSON adalah ketahanan parsing terhadap field baru dari versi Zeek atau paket, dan add-on mendukung keduanya. Volume ditekan dengan memilih log yang dikirim, bukan dengan menganggap JSON lebih kaya. Lihat bagian 1.7 dan 1.9.

</details>

**7. Interview question (English).** "Walk me through how you would investigate a suspicious file download using only Zeek logs."

<details><summary>Sample answer</summary>

"I start from whatever triggered the case, say a files.log entry where the MIME type is a Windows executable but the filename says PDF, and I take its uid, fuid, timestamp and hash. Then I pivot on the uid: conn.log tells me who talked to whom, how many bytes, how the connection ended and whether there were missed bytes, and http.log gives me the host, URI, user agent and status. I check direction with is_orig, because the originator of the connection is not necessarily the sender of the file. Some pieces never share the uid, so I join them by time and content: the DNS lookup through the answers field, and in a network with an explicit proxy, the second hop from the proxy to the internet, which has its own uid and fuid but the same hash and URL. Before I write the scope, I check capture_loss.log and sensor restarts for that window, because a quiet log during packet loss is not evidence of absence. Finally I separate what Zeek proves, a PE file delivered to this host, from what it cannot prove, whether it executed, which I hand to endpoint telemetry."

What makes this answer strong: it follows a repeatable pivot order, knows the limits of the uid (DNS, proxy hops), reads file direction correctly, validates sensor health before claiming absence, and separates network indicators from host conclusions.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Zeek documentation (overview) | https://docs.zeek.org/en/master/ | primer | diakses 2026-10-10 | Tinggi. Konsep Zeek |
| S2 | Zeek docs: Logs (conn, dns, http, ssl, files; conn_state) | https://docs.zeek.org/en/current/logs/index.html | primer | diakses 2026-10-09 (Day 01), dicek ulang 2026-10-22 | Tinggi. Field log; daftar log populer |
| S3 | Zeek: Get Zeek (versi/rilis) | https://zeek.org/get-zeek/ | primer | diakses 2026-10-09 (Day 01), dicek ulang 2026-10-22 | Tinggi. 9.0.0 LTS 14 Sep 2026; 8.0.10 LTS sebelumnya 19 Agu 2026 |
| S4 | Zeek NEWS (catatan rilis; perubahan files.log di 5.1) dan skrip `hash-all-files.zeek` | https://github.com/zeek/zeek | primer | diakses 2026-10-10, NEWS cabang master dibaca ulang 2026-10-22 | Tinggi. Penggantian `tx_hosts`/`rx_hosts` dengan `uid`/`id`, field `is_orig`, hashing MD5/SHA1/SHA256 lewat `hash-all-files`; Community ID bawaan dan private address space lokal (6.0); ZeroMQ default zeekctl (8.1); CURVE (8.2); Broker deprecated dan escape JSON (9.0); catatan 9.1.0 belum rilis; `bro-cut` menjadi `zeek-cut` (3.0) |
| S5 | Network-Forensics Day 01-07 (lokal) | (lokal) | rujukan internal | 2026-10-09 | Protokol dan anomali |
| S6 | Zeek source: `scripts/base/protocols/conn/main.zeek` (dokumentasi field conn.log dan fungsi `conn_state`) | https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/protocols/conn/main.zeek | primer (kode sumber proyek) | cabang master; diakses 2026-10-22 | Tinggi. Daftar `conn_state` termasuk UDP, huruf `history` lengkap dan aturan pencatatan, `orig_bytes` dari sequence number, `missed_bytes`, `duration`, `local_orig` |
| S7 | Zeek docs: files.log | https://docs.zeek.org/en/master/logs/files.html | primer | diakses 2026-10-22 | Tinggi. `fuid`, `uid` untuk korelasi, `is_orig` = false berarti responder mengirim file, `analyzers`, `extracted`; contoh event JSON |
| S8 | Zeek docs: weird.log and notice.log | https://docs.zeek.org/en/master/logs/weird-and-notice.html | primer | diakses 2026-10-22 | Tinggi. Weird sering noise, notice paling dekat dengan alert IDS, contoh nama weird, contoh `SSL::Invalid_Server_Cert` |
| S9 | Zeek docs: Notice Framework | https://docs.zeek.org/en/master/frameworks/notice.html | primer | diakses 2026-10-22 | Tinggi. Fungsi `NOTICE`, hook `Notice::policy`, field notice.log, aksi, supresi |
| S10 | Zeek docs: capture_loss.log and reporter.log; skrip `scripts/policy/misc/capture-loss.zeek` | https://docs.zeek.org/en/master/logs/capture-loss-and-reporter.html ; https://raw.githubusercontent.com/zeek/zeek/master/scripts/policy/misc/capture-loss.zeek | primer | diakses 2026-10-22 | Tinggi. Field capture_loss, `percent_lost` dalam persen, interval 15 menit, ambang `too_much_loss` 0,1, reporter.log untuk error internal |
| S11 | Zeek docs: Cluster Setup (arsitektur, AF_PACKET) | https://docs.zeek.org/en/master/cluster-setup.html | primer | diakses 2026-10-22 | Tinggi. Peran worker/manager/logger/proxy, Zeek tidak multithread, hash simetris AF_PACKET, fanout ID 23, offloading, jumlah worker maksimal satu atau dua kurang dari core; tanpa angka Mbps per core |
| S12 | Zeek docs: Logging Framework | https://docs.zeek.org/en/master/frameworks/logging.html | primer | diakses 2026-10-22 | Tinggi. Writer ASCII TSV bawaan, `LogAscii::use_json`, JSON per filter, rotasi bawaan mati di luar zeekctl, kebijakan escape JSON (9.0) |
| S13 | Zeek source: `scripts/base/utils/site.zeek`, `scripts/site/local.zeek`, `scripts/policy/tuning/json-logs.zeek` | https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/utils/site.zeek ; https://raw.githubusercontent.com/zeek/zeek/master/scripts/site/local.zeek ; https://raw.githubusercontent.com/zeek/zeek/master/scripts/policy/tuning/json-logs.zeek | primer (kode sumber proyek) | cabang master; diakses 2026-10-22 | Tinggi. `private_address_space` memuat rentang dokumentasi RFC 5737; isi `local.zeek` bawaan; `json-logs` = `redef LogAscii::use_json=T` |
| S14 | Zeek source: `scripts/base/frameworks/files/main.zeek` (dokumentasi field files.log) | https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/frameworks/files/main.zeek | primer (kode sumber proyek) | cabang master; diakses 2026-10-22 | Tinggi. `mime_type` dari file magic, `filename` dari Content-Disposition, `seen_bytes`/`total_bytes`/`missing_bytes`, `is_orig`, `local_orig` |
| S15 | Splunkbase: TA for Zeek (app 5466) | https://splunkbase.splunk.com/app/5466 | primer (halaman add-on) | versi 1.0.11, 2025-08-21; diakses 2026-10-22 | Tinggi. Parsing JSON dan TSV ke CIM, dirawat Corelight, kompatibilitas Splunk 9.3 sampai 10.6 dan CIM 6.x; tidak mencantumkan nama sourcetype |
| S16 | WLCG SOC Working Group (CERN): Zeek hardware requirements | https://wlcg-soc-wg-doc.web.cern.ch/data_sources/zeek/hardware_requirements.html | sekunder | tanpa tanggal; diakses 2026-10-22 | Sedang-tinggi. 800 Mbps sampai 1 Gbps per core, minimal 12 core dan 64 GB RAM untuk 10 Gbps, sekitar 6 GB RAM per worker; asumsi trafik 10 Gbps |
| S17 | Splunk Research: Data Source Zeek Conn, Bro http, Bro ssl | https://research.splunk.com/sources/01dff429-9c29-4181-87ae-ea19cde20031/ ; https://research.splunk.com/sources/c5d9612b-0ffd-44d3-8247-3cf3486ec5e2/ ; https://research.splunk.com/sources/22c637eb-f62e-41f0-8637-ebf62e11f0a8/ | primer (konten riset Splunk) | diakses 2026-10-22 | Tinggi. Sourcetype `bro:conn:json`, `bro:http:json`, `bro:ssl:json` dengan TA for Zeek 1.0.11; daftar 52 field `bro:conn:json` termasuk field CIM |
| S18 | Jason Murray: Zeek Installation and Splunk CIM Data Normalization Guide | https://jasonmurray.org/posts/2022/zeekinstallandsplunklog/ | komunitas | 2022; diakses 2026-10-22 | Sedang. Pola `sourcetype = bro:json` dengan `source = bro.<log>.log`, perlunya format source/sourcetype yang cocok dengan add-on, saran sourcetype manual untuk volume tinggi; ditulis untuk versi add-on lebih lama |

**Catatan sumber:** nama field log dan definisi `conn_state` mengikuti dokumentasi Zeek [S2] dan kode sumbernya [S6]; arti huruf `history` adalah konvensi Zeek yang stabil, tetapi `conn_state` persis untuk kombinasi flag yang jarang (misalnya SYN scan ke port terbuka) perlu dicek di lab; pernyataan bahwa `ShR` jatuh ke RSTO adalah pembacaan logika fungsi di [S6], bukan kalimat dokumentasi. Ketersediaan paket JA3/JA4 untuk Zeek 9.0 dan nama skrip JSON (`policy/tuning/json-logs`, terkonfirmasi ada di cabang master [S13]) perlu dicocokkan dengan versi yang terpasang. Halaman TA for Zeek [S15] tidak mencantumkan sourcetype; nama `bro:conn:json`, `bro:http:json`, dan `bro:ssl:json` berasal dari Splunk Research [S17], sedangkan `bro:dns:json`, `bro:files:json`, `bro:notice:json`, `bro:weird:json`, `bro:capture_loss:json`, dan lainnya mengikuti pola yang sama dan harus divalidasi dengan `| metadata` di Splunk-mu; pola `bro:json` dengan `source` berasal dari panduan komunitas untuk versi add-on lebih lama [S18]. Angka throughput per core [S16] adalah patokan satu organisasi, dan patokan 250 Mbps per core hanya dikenal dari diskusi komunitas. Rumus `percent_lost` sama dengan `gaps` dibagi `acks` disimpulkan dari contoh di [S10] dan dari skrip `capture-loss.zeek`. Bentuk `uri` absolut di `http.log` untuk request ke proxy eksplisit, kode status proxy saat koneksi ke server gagal, dan pencatatan TLS di balik `CONNECT` perlu dicek di versi Zeek dan produk proxy-mu. Rasio ukuran JSON dan TSV (407 dan 139 byte) dihitung dari satu baris contoh di catatan ini, bukan dari sumber. Seluruh isi PT JAB (alert `SOC-2027-0635` sampai `-0639`, `INC-2027-067`, host, `uid`, angka volume, capture loss, dan label) adalah penerapan catatan ini pada organisasi fiktif, bukan hasil eksekusi nyata.
