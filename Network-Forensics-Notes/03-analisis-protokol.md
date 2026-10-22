---
day: 03
title: 'Analisis protokol: TCP/UDP, HTTP, DNS, TLS awal, SMB, dan FTP dari sudut forensik'
researched_on: 2026-10-22
versions_checked: 'Wireshark 4.6.9 (stable) dan 4.4.19 (old stable); Wireshark Display Filter Reference tcp, dns, http, tls, smb2, ftp (rentang 1.0.0 sampai 4.6.9); Wireshark User''s Guide TCP Analysis; Zeek 9.0.0 LTS (14 Sep 2026), dokumentasi conn.log (master); RFC 9293 (TCP, 2022); RFC 9110 (HTTP); RFC 1035 dan RFC 3596 (DNS); RFC 8446 dan RFC 9846 (TLS 1.3, Jul 2026); RFC 959 (FTP); RFC 7208 (SPF); MS-SMB2 (header dan NEGOTIATE); MITRE ATT&CK v20.0: T1571 v1.3, T1021.002 v1.3'
---

# Day 03: Analisis protokol (TCP/UDP, HTTP, DNS, TLS awal, SMB, dan FTP dari sudut forensik)

Cakupan: membaca percakapan TCP/UDP, HTTP, DNS, TLS awal, SMB, dan FTP dari sudut forensik, yaitu bentuk percakapan yang normal, field yang menjawab pertanyaan investigasi, sinyal yang layak dikejar, dan cara membedakan masalah jaringan atau capture dari perilaku yang mencurigakan.

## Ide inti

Setiap protokol punya bentuk percakapan yang bisa ditebak. TCP dibuka dengan SYN, SYN-ACK, ACK dan ditutup dengan FIN atau RST; DNS adalah satu query dan satu response dengan ID yang sama; HTTP adalah request dengan method, host, dan path, lalu response dengan status; FTP adalah urutan perintah teks dan kode balasan tiga digit. Analisis protokol dari sudut forensik adalah membandingkan percakapan yang terlihat di pcap dengan bentuk normal itu, lalu menanyakan dua hal. Pertama, apakah penyimpangannya berasal dari mekanika jaringan atau dari alat capture (retransmission, segmen yang tidak tertangkap, RST dari firewall), yang hampir selalu bukan ancaman. Kedua, apakah percakapan yang bentuknya normal itu dipakai untuk hal yang tidak normal: siapa bicara ke siapa, lewat port apa, seberapa sering, dengan field aplikasi apa. Bahan forensik yang bermakna hampir selalu ada di pertanyaan kedua.

Kamu sudah melakukan hal yang sama di NOC setiap kali membaca `debug` sesi BGP. BGP berjalan di atas TCP port 179, dan neighbor yang macet di Active atau Connect berarti SYN dikirim tetapi SYN-ACK tidak pernah datang, sedangkan NOTIFICATION yang diikuti penutupan sesi adalah teardown yang sengaja. Kamu juga sudah tahu bahwa error counter yang naik di interface bisa berarti link rusak, bisa juga berarti optic di sisi alat ukur yang bermasalah. Batas analoginya: state machine BGP memberi nama status secara langsung, sedangkan di pcap kamu menyusun status itu sendiri dari flag dan urutan paket. Dan BGP peer tidak berusaha menipumu, sedangkan penyerang sengaja membuat percakapannya berbentuk normal (HTTP biasa, port yang diizinkan), sehingga yang membedakan biasanya bukan bentuk percakapan, melainkan konteksnya.

```
 paket di pcap
      |
      v
 bentuk percakapan normal?  (handshake, query/response, request/response, perintah/kode)
      |                                  |
     tidak                               ya
      |                                  |
      v                                  v
 penyebab mekanis?                  dipakai untuk apa?
  - capture (segmen tidak            - siapa ke siapa (titik pandang sensor: proxy, resolver, NAT)
    tertangkap, ACKed unseen)        - port dan protokol cocok?
  - jaringan (retransmission,        - frekuensi, interval, volume
    zero window)                     - field aplikasi (method, UA, qtype, SNI, STOR)
  - kebijakan (RST dari firewall)         |
      |                                  v
      v                            sinyal + penjelasan jinak + korroborasi
 catat, jangan eskalasi                  |
                                         v
                            jinak terkonfirmasi | perlu investigasi (IR) | data tidak cukup
```

Situasi Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan, kantor pusat dan data center di Jakarta, serta NOC 24/7 yang satu lantai dengan SOC. Sampai April 2027 semua bukti jaringan PT JAB hanya berupa log firewall `jkt-fw01`, proxy `jkt-proxy01` (`10.20.3.60`, proxy eksplisit port 3128), resolver `jkt-res01` (`10.20.2.53`) dan `jkt-res02` (`10.20.2.54`), serta flow NOC di kolektor `jkt-flow01`. Senin 2027-05-03, Program NSM PT JAB dimulai. Kamu, analyst L2 dengan latar belakang tujuh tahun di NOC, menjadi pelaksananya bersama Bambang Hartono (Manajer NOC) dan Agung Prabowo (Lead Infrastruktur). Sensor pertama yang hidup adalah ring buffer pcap `jkt-pcap01` (`10.20.70.13`), uji coba sejak Selasa 2027-05-04 dengan TAP di link egress Jakarta, yaitu antara core switch dan sisi dalam `jkt-fw01`, sebelum NAT. Retensinya ditargetkan 72 jam. Analisis dilakukan dari workstation `jkt-nsm-ws01` (`10.20.70.20`) yang punya Wireshark, tshark, Zeek offline, dan akses read-only ke `jkt-pcap01`. Zeek dan Suricata produksi belum hidup.

Rabu 2027-05-05 pagi, antrean SOC berisi lima item yang semuanya menyentuh trafik egress Jakarta: tiket NOC `SOC-2027-0610` (Expert Info pcap uji coba penuh retransmission), `SOC-2027-0611` (workstation `JKT-WS-2011` berulang kali ditolak firewall saat menghubungi `203.0.113.164` port 4444), `SOC-2027-0612` (volume query DNS TXT tinggi), `SOC-2027-0613` (POST berulang lewat proxy dengan User-Agent usang), dan `SOC-2027-0614` (FTP tanpa enkripsi keluar dari data center pukul 01:30). Pukul 09:40, Sari Kusuma, analyst L2, menulis kepadamu:

> "Pagi. Aku sudah tarik cuplikan pcap egress 09:00 sampai 09:15 dari jkt-pcap01, dan lima item di antrean ini kebetulan semuanya kelihatan di sana. Sebelum anak L1 mulai pakai pcap, tolong jelaskan ke aku cara baca percakapan protokolnya, dan mana yang normal mana yang tidak. Pak Bambang tanya, Expert Info isinya ribuan retransmission, itu link egress kita bermasalah, serangan, atau alat capture-nya? Yang port 4444 itu kok setiap SYN dibalas RST, artinya apa? Terus aku bingung, di pcap hampir semua HTTP dan DNS sumbernya proxy dan resolver, workstation aslinya dicari di mana? POST berulang ke update-relay itu dan TXT yang banyak itu, mana yang perlu dikejar? Dari HTTPS kita masih bisa lihat apa? FTP malam itu bahaya atau tidak, dan kalau ada lateral movement lewat SMB, pcap ini bisa lihat? Terakhir, buatkan aku semacam peta: pertanyaan investigasi apa dijawab protokol apa."

Pesan itu memuat delapan pertanyaan:

1. Bagaimana membaca satu percakapan TCP dari pembukaan sampai penutupan, dan apa arti SYN yang selalu dibalas RST?
2. Ribuan retransmission di Expert Info: link bermasalah, serangan, atau alat capture?
3. Kenapa sumber HTTP dan DNS di pcap egress hampir semuanya proxy dan resolver, dan di mana workstation aslinya dicari?
4. Apa yang membuat POST berulang ke `update-relay.example` dan koneksi ke port 4444 layak dikejar?
5. Apakah volume DNS TXT yang tinggi berarti tunneling?
6. Apa yang masih terlihat dari HTTPS?
7. Apakah FTP malam itu berbahaya, dan apakah pcap egress bisa melihat lateral movement lewat SMB?
8. Pertanyaan investigasi apa dijawab protokol apa, dan bagaimana menjaga agar sinyal tidak dibaca sebagai kesimpulan?

Pertanyaan 1 dijawab di bagian 1.1, 1.2, dan 2.2, pertanyaan 2 di bagian 1.3 dan 2.1, pertanyaan 3 di bagian 1.4, pertanyaan 4 di bagian 1.5, 1.10, 2.2, dan 2.3, pertanyaan 5 di bagian 1.6 dan 2.4, pertanyaan 6 di bagian 1.7 dan 2.5, pertanyaan 7 di bagian 1.8, 1.9, 2.6, dan 2.7, dan pertanyaan 8 di bagian 1.11, 1.12, dan 2.8. Bagian 2.9 berisi jawaban satu halaman untuk Sari.

**Kapan relevan:** setiap kali membaca pcap, baik dari ring buffer sensor, capture troubleshooting, maupun pcap lab; saat alert dari firewall, proxy, atau DNS perlu dikonfirmasi di tingkat paket; dan saat NOC dan SOC melihat gejala yang sama (retransmission, RST, timeout) dari sudut yang berbeda.
**Kapan bukan jawaban:** saat isi yang dibutuhkan terenkripsi (TLS hanya memberi metadata; isi butuh dekripsi atau artefak endpoint, Day 06); saat trafik yang dicari tidak lewat titik capture (lateral movement antar workstation tidak lewat TAP egress); dan saat pertanyaannya "proses apa yang membuat koneksi ini", karena pcap tidak pernah memuat nama proses.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah Wireshark dari Day 02 (display filter, capture filter, Follow Stream, Statistics, Export Objects, Expert Information, tshark) tidak diulang. Tabel ini memuat istilah protokol yang dipakai Day ini; kolom kanan memakai padanan dari pekerjaan NOC dan ISP.

| Istilah | Arti singkat | Padanan di NOC/ISP |
|---|---|---|
| Three-way handshake | SYN, SYN-ACK, ACK yang membuka koneksi TCP dan menyepakati initial sequence number | Sesi BGP naik dari Connect ke Established |
| Teardown | Penutupan koneksi: FIN dari kedua sisi (normal) atau RST (dibatalkan) | NOTIFICATION lalu sesi ditutup, atau peer di-reset |
| RST | Segmen TCP yang membatalkan koneksi atau menolak koneksi ke port yang tidak menerima | `%BGP-3-NOTIFICATION ... connection refused` dari neighbor |
| Retransmission | Segmen yang dikirim ulang karena pengirim menduga segmen sebelumnya hilang | Paket hilang yang terlihat dari CRC/output drop di interface |
| Lost segment / ACKed unseen segment | Wireshark tidak melihat segmen sebelumnya; atau penerima meng-ACK segmen yang tidak pernah tertangkap | Counter error di port SPAN laptop, bukan di link produksi |
| Zero window | Penerima mengiklankan window 0: buffernya penuh, pengirim harus berhenti | Antrean output penuh di router yang kelebihan beban |
| Conversation completeness | Nilai bit Wireshark yang mencatat bagian percakapan TCP mana yang terlihat (SYN, SYN-ACK, ACK, data, FIN, RST) | Ringkasan state sesi dari awal sampai tutup |
| `conn_state` dan `history` | Ringkasan status dan urutan flag satu koneksi di Zeek `conn.log` | Kolom state di tabel sesi firewall |
| Titik pandang sensor | Apa yang bisa dan tidak bisa dilihat sensor dari posisinya (sebelum/sesudah NAT, proxy, resolver) | Posisi titik ekspor NetFlow di topologi |
| Domain induk | Bagian nama yang didaftarkan (misalnya `example.net` dari `a1b2.c3.example.net`) | Prefix agregat dari banyak /32 |
| SNI | Nama server di ClientHello TLS, terlihat tanpa dekripsi kecuali memakai ECH | Header tujuan yang masih terbaca di paket terenkripsi |
| Admin share | Share tersembunyi Windows (`C$`, `ADMIN$`, `IPC$`) yang butuh hak admin di host tujuan | Akses enable ke perangkat orang lain |
| Port non-standar | Protokol dipakai di port yang bukan port lazimnya (ATT&CK T1571) | Layanan yang dipindah port supaya lolos ACL |

### 1.1 TCP: handshake dan teardown

Pertanyaan pertama Sari dimulai dari bentuk dasar. Sebelum menilai 15 SYN ke port 4444 yang semuanya dibalas RST, kamu perlu tahu seperti apa percakapan TCP yang normal, karena "tidak normal" hanya bermakna bila ada pembandingnya.

TCP adalah dasar banyak protokol aplikasi [S3]:

- **Handshake:** klien mengirim SYN, server membalas SYN-ACK, klien menutup dengan ACK. Ketiganya menyepakati initial sequence number (ISN) kedua arah. ISN dipilih dari jam yang digabung fungsi pseudorandom atas identitas koneksi dan kunci rahasia, supaya pihak di luar jalur tidak mudah menebaknya [S3]. Di Wireshark, flag dibaca dari `tcp.flags` dan field per bit seperti `tcp.flags.syn`, `tcp.flags.ack`, `tcp.flags.fin`, dan `tcp.flags.reset` [S1].
- **Teardown normal:** masing-masing sisi mengirim FIN dan menerima ACK. Sisi yang menutup lebih dulu menunggu di state TIME-WAIT selama 2 kali MSL; RFC 9293 menetapkan MSL 2 menit, jadi TIME-WAIT berlangsung 4 menit [S3]. Ini sebabnya port lokal yang sama tidak langsung dipakai ulang untuk tujuan yang sama.
- **Teardown abrupt:** RST membatalkan koneksi tanpa penutupan bertahap (bagian 1.2).
- **Sequence dan acknowledgment:** `tcp.seq` dan `tcp.ack` melacak urutan byte. Dari sinilah Wireshark menyimpulkan retransmission dan segmen yang hilang (bagian 1.3).
- **Nomor sesi:** `tcp.stream` memberi nomor percakapan yang dipakai Follow Stream (Day 02) [S1].

Wireshark juga merangkum seberapa lengkap percakapan yang terlihat lewat `tcp.completeness`. Nilainya adalah jumlah bit: 1 SYN, 2 SYN-ACK, 4 ACK, 8 DATA, 16 FIN, 32 RST [S7]. Tabel berikut adalah nilai yang paling sering dipakai; cari nilai yang cocok dengan pola yang kamu curigai.

| Nilai | Komponen | Cara membacanya |
|---|---|---|
| 7 | SYN + SYN-ACK + ACK | Handshake saja, tanpa data dan tanpa penutupan dalam capture |
| 31 | 7 + DATA + FIN | Percakapan lengkap yang ditutup normal |
| 47 | 7 + DATA + RST | Percakapan lengkap yang ditutup dengan RST |
| 63 | Semua bit | Data, lalu FIN dan RST sekaligus |
| 33 | SYN + RST | SYN tanpa SYN-ACK, dibalas RST (ditolak); nilai ini dihitung dari definisi bit, cek tampilannya di lab |

Percakapan dianggap lengkap bila pembukaan dan penutupannya terlihat, terlepas dari ada atau tidaknya data [S7]. Bagi analisis forensik, nilai ini cepat memisahkan koneksi yang benar-benar terjadi (ada data) dari percobaan yang tidak pernah tersambung.

Zeek merangkum hal yang sama dengan cara lain. Kolom `conn_state` di `conn.log` memberi status seperti `S0` (percobaan tanpa balasan), `REJ` (percobaan ditolak), `SF` (dibuka dan ditutup normal), `RSTO` dan `RSTR` (dibatalkan RST oleh originator atau responder), dan `OTH` (tidak ada SYN, hanya trafik di tengah sesi) [S8]. Kolom `history` mencatat urutan flag dengan huruf (`s` SYN, `h` SYN-ACK, `a` ACK murni, `d` data, `f` FIN, `r` RST, `t` payload yang dikirim ulang, `w` zero window); huruf besar berasal dari originator dan huruf kecil dari responder [S8]. Zeek produksi baru hidup di Day 08, tetapi Zeek offline di `jkt-nsm-ws01` sudah bisa dipakai untuk membaca cuplikan pcap (bagian 2.2).

TCP sendiri jarang membuktikan ancaman. Ia memberi struktur sesi, yaitu siapa membuka koneksi, apakah tersambung, berapa lama, dan bagaimana ditutup, tempat protokol aplikasi (HTTP dan lainnya) dibaca.

### 1.2 RST dan penolakan koneksi

Bagian kedua pertanyaan pertama Sari adalah tentang RST. Di pcap egress, 15 SYN dari `JKT-WS-2011` ke `203.0.113.164:4444` masing-masing dibalas RST dalam satu milidetik. Untuk menafsirkannya, kamu perlu tahu kapan RST dikirim menurut spesifikasi dan siapa saja yang bisa mengirimnya.

RFC 9293 mengatur pembuatan RST [S3]:

- Bila koneksi tidak ada (state CLOSED), setiap segmen yang datang dibalas RST, kecuali segmen RST itu sendiri. Ini kasus SYN ke port yang tidak punya layanan: server membalas RST, dan klien langsung tahu koneksi ditolak.
- Di state yang belum tersinkron (LISTEN, SYN-SENT, SYN-RECEIVED), RST dikirim untuk ACK yang tidak bisa diterima.
- Di state yang sudah tersinkron, segmen yang tidak bisa diterima dibalas ACK kosong, bukan RST.
- RST hanya dianggap sah bila nomor sequence-nya berada di dalam window penerima [S3]. Aturan ini mempersulit pihak di luar jalur menyuntikkan RST palsu.

Dalam praktik, RST dikirim oleh tiga jenis pihak, dan membedakannya adalah pekerjaan utama saat membaca RST di pcap:

| Pengirim RST | Contoh | Petunjuk di pcap |
|---|---|---|
| Server tujuan | Port tertutup; aplikasi membatalkan koneksi | RST datang setelah jeda sebesar round-trip ke server; nilai TTL mirip dengan paket lain dari server yang sama |
| Klien | Aplikasi ditutup paksa; klien membatalkan unduhan | RST dari sisi dalam; sering setelah data |
| Perangkat di tengah | Firewall yang menolak dengan reset; IPS; proxy | RST datang jauh lebih cepat daripada round-trip ke tujuan; TTL tidak cocok dengan paket lain dari IP yang sama |

Petunjuk TTL di tabel adalah heuristik, bukan aturan protokol. TTL berkurang satu di setiap hop, jadi paket dari server di internet tiba dengan TTL yang lebih kecil daripada paket dari perangkat satu hop di sebelah sensor. Nilai awal TTL berbeda per sistem operasi dan perangkat, jadi bandingkan dengan paket lain dari IP yang sama di pcap yang sama, bukan dengan angka hafalan.

Sinyal forensik dari RST:

- Banyak SYN tanpa SYN-ACK ke banyak port dari satu sumber adalah pola pemindaian (Day 04).
- SYN yang berulang pada interval teratur ke satu tujuan yang selalu ditolak adalah pola program yang terus mencoba tersambung. Ini menarik karena manusia jarang mencoba ulang dengan interval yang rapi.
- RST di tengah sesi bisa berarti koneksi diputus aplikasi, timeout state di perangkat tengah, atau injeksi oleh perangkat keamanan. Sebagian besar jinak.

### 1.3 Retransmission dan anomali TCP: jaringan, capture, atau serangan

Pertanyaan Bambang ("link egress bermasalah, serangan, atau alat capture-nya") adalah pertanyaan yang paling sering diajukan NOC tentang pcap, dan jawabannya ada di definisi flag analisis Wireshark.

Wireshark menganalisis sequence number setiap segmen bila preferensi "Analyze TCP sequence numbers" di dissector TCP aktif [S7]. Tabel berikut meringkas flag yang paling sering muncul di Expert Info. Perhatikan kolom "Arah tafsir", karena di sana terlihat bahwa sebagian flag menunjuk ke alat capture, bukan ke jaringan.

| Flag (`tcp.analysis.*`) | Kondisi yang dipakai Wireshark (ringkas) | Arah tafsir |
|---|---|---|
| `retransmission` | Segmen berisi data (atau SYN/FIN), bukan keepalive, dan sequence-nya lebih kecil dari sequence berikutnya yang diharapkan [S7] | Pengirim mengirim ulang; biasanya kehilangan paket di jaringan |
| `fast_retransmission` | Seperti retransmission, didahului minimal dua duplicate ACK dari arah sebaliknya, dan ACK terakhir terlihat kurang dari 20 ms sebelumnya [S7] | Pemulihan cepat TCP setelah kehilangan; jaringan |
| `spurious_retransmission` | Segmen berisi data yang sudah di-ACK sebelumnya [S7] | Pengiriman ulang yang tidak perlu; timer terlalu agresif atau ACK terlambat |
| `duplicate_ack` | Segmen tanpa data, window tidak berubah (atau ada SACK), bukan SYN/FIN/RST [S7] | Penerima memberi tahu ada celah urutan |
| `out_of_order` | Segmen datang di luar urutan dalam ambang waktu iRTT (default 3 ms bila iRTT tidak ada) [S7] | Jalur ganda atau penyeimbangan beban |
| `lost_segment` | Segmen sebelumnya tidak tertangkap (deskripsi field: previous segment(s) not captured) [S1] | Bisa jaringan, bisa capture |
| `ack_lost_segment` | ACK untuk segmen yang tidak pernah tertangkap (ACKed segment that was not captured) [S1] | Penerima menerima segmen itu, jadi yang kehilangan adalah alat capture |
| `zero_window` | Penerima mengiklankan window 0 [S7] | Penerima kewalahan; masalah host atau aplikasi |
| `keep_alive` | Segmen 0 atau 1 byte dengan sequence satu kurang dari yang diharapkan [S7] | Menjaga koneksi idle; normal |
| `reused_ports` | SYN baru memakai pasangan alamat dan port yang sama dengan percakapan lama, dengan ISN berbeda [S7] | Port sumber dipakai ulang; normal pada volume tinggi, juga muncul pada pemindaian |

Kuncinya ada di dua baris `lost_segment` dan `ack_lost_segment`. Bila Wireshark melihat celah urutan, lalu penerima meng-ACK byte di celah itu tanpa ada retransmission, berarti segmennya sampai ke penerima tetapi tidak sampai ke alat capture. Itu kehilangan di sensor (SPAN yang kelebihan beban, buffer kartu capture, disk yang lambat), bukan di link produksi. Sebaliknya, retransmission yang benar-benar terjadi berarti pengirim tidak menerima ACK dan mengirim ulang: itu kehilangan nyata di jalur.

Hubungannya dengan ancaman lemah. Retransmission dan dup ACK hampir selalu masalah jaringan atau beban. Beberapa pola memang terkait serangan (pemindaian memunculkan `reused_ports`; banjir SYN memunculkan banyak koneksi setengah terbuka), tetapi polanya terlihat dari jumlah sumber, tujuan, dan port, bukan dari flag analisis itu sendiri. Satu frame juga bisa membawa lebih dari satu flag analisis, dan sebagian flag menggantikan flag lain [S7], jadi jangan menjumlahkan baris Expert Info seolah-olah saling lepas.

Dari pengalaman NOC: ini sama dengan membedakan error counter di interface produksi dari error counter di port SPAN tempat laptop Wireshark dicolokkan. Pembanding terbaik untuk pcap adalah counter interface router dan statistik drop di sensor itu sendiri pada jam yang sama.

### 1.4 UDP dan titik pandang sensor egress

Pertanyaan ketiga Sari ("workstation aslinya dicari di mana") bukan soal protokol, tetapi soal posisi sensor. Namun jawabannya menentukan cara membaca setiap protokol di bawah, jadi ia dibahas sebelum HTTP dan DNS.

UDP tidak punya handshake, sequence, atau teardown. Satu datagram berdiri sendiri; yang mengikat query dan response adalah protokol aplikasinya. Untuk DNS, pengikatnya adalah transaction ID (`dns.id`), dan Wireshark menautkan pasangan itu lewat `dns.response_in` serta menghitung jedanya di `dns.time` [S1]. Wireshark juga menandai `dns.retransmission` (query yang dikirim ulang) dan `dns.unsolicited` (response tanpa query yang terlihat) [S1]. Karena tidak ada handshake, "percobaan yang ditolak" di UDP biasanya hanya terlihat sebagai query tanpa response.

Titik pandang `jkt-pcap01` di PT JAB menentukan siapa yang terlihat sebagai sumber:

```
 JKT-WS-2011 (10.10.60.31)
     |  HTTP/HTTPS ke proxy :3128          DNS ke resolver :53
     v                                      v
 jkt-proxy01 (10.20.3.60)            jkt-res01/02 (10.20.2.53/.54)
     |                                      |
     +-----------------+--------------------+
                       |
              core switch Jakarta
                       |
            [TAP] ---> jkt-pcap01 (melihat: proxy, resolver, mail gateway,
                       |               server DC, dan koneksi langsung yang dicoba workstation)
                  jkt-fw01 (NAT ke 198.51.100.120 untuk kantor, 198.51.100.203 untuk server DC tertentu)
                       |
                    internet
```

Akibatnya, di pcap egress:

- **HTTP dan HTTPS kantor** bersumber dari `10.20.3.60`. Workstation asli hanya ada di log proxy (`index=proxy`).
- **DNS kantor** bersumber dari resolver, dan yang terlihat hanyalah query yang tidak terjawab dari cache. Klien asli hanya ada di log resolver (`index=dns`), dan jumlah query di log resolver lebih besar daripada di pcap egress.
- **Koneksi langsung workstation ke internet** (yang tidak lewat proxy) memang terlihat dengan IP workstation, karena TAP berada sebelum NAT. Di PT JAB, firewall menolak koneksi langsung seperti itu, jadi yang terlihat biasanya percobaan yang ditolak.
- **Trafik antar workstation dan antar server di dalam** (SMB, RDP, WinRM) tidak lewat TAP egress sama sekali.

Jadi cara menemukan workstation asli adalah mencocokkan waktu dan tujuan pcap dengan log proxy atau resolver. Pcap memberi bukti paket; log memberi identitas klien. Bila `jkt-pcap01` kelak dipindah ke sisi luar firewall, semua sumber akan menjadi IP NAT, dan pencocokan dengan log firewall menjadi wajib.

### 1.5 HTTP: method, header, status

Item `SOC-2027-0613` adalah POST berulang ke `update-relay.example` dengan User-Agent `Mozilla/4.0 (compatible)`. Karena trafiknya HTTP tanpa enkripsi, seluruh request terbaca di pcap, dan field-field berikut menentukan apakah polanya layak dikejar.

HTTP tanpa enkripsi sangat kaya bahan forensik [S2]. Tabel berikut memetakan field Wireshark ke arti forensiknya [S1]; baca kolom kanan untuk tahu field mana yang menjawab pertanyaan apa.

| Field | Arti forensik |
|---|---|
| `http.request.method` | GET, POST (POST sering untuk upload/exfil atau C2) |
| `http.host` | Domain yang dihubungi |
| `http.request.uri` | Path; path aneh atau acak mencurigakan |
| `http.user_agent` | Klien; User-Agent tidak lazim atau salah format adalah sinyal |
| `http.response.code` | 200, 404, 302; pola response |
| `http.content_type` | Tipe isi; octet-stream untuk unduhan biner |
| `http.content_length` | Ukuran body; ukuran yang identik berulang-ulang menarik |
| `http.file_data` | Isi (bisa diekspor, Day 02) |
| `http.location` | Tujuan redirect pada response 3xx |

Menurut RFC 9110, GET meminta representasi sumber daya, sedangkan POST meminta server memproses isi request sesuai semantik sumber dayanya [S2]. Karena itu POST adalah method alami untuk mengirim data keluar, termasuk data sah seperti formulir dan telemetri.

Sinyal: User-Agent yang menyamar atau tidak lazim, path yang terlihat di-generate otomatis, POST berulang ke satu host dengan interval teratur (kandidat C2, Day 11), atau unduhan executable (`Content-Type` biner). Semua itu sinyal, bukan bukti; tool sah juga punya User-Agent aneh, dan agen telemetri sah juga POST berulang.

Di PT JAB, request dari workstation melewati proxy eksplisit, jadi di pcap egress yang tampak adalah request yang diteruskan proxy dari `10.20.3.60`. Header aplikasi seperti User-Agent dan path tetap diteruskan apa adanya, sehingga pola request tetap terbaca, sedangkan identitas klien diambil dari log proxy (bagian 1.4). Untuk HTTPS, isi request tidak terlihat (bagian 1.7).

### 1.6 DNS: query, response, tipe

Item `SOC-2027-0612` adalah lonjakan query TXT. Untuk menilainya, kamu perlu tahu field DNS mana yang membedakan tunneling dari pemakaian TXT yang sah.

DNS adalah jalur umum C2 dan exfil (Day 05, 11, 12) [S4]. Struktur dasarnya dari RFC 1035: label maksimal 63 oktet, nama maksimal 255 oktet, dan pesan UDP klasik maksimal 512 oktet di luar header IP dan UDP [S4]. Batas 63 oktet per label inilah yang membuat subdomain tunneling sering terlihat panjang dan mendekati batas.

Tabel berikut adalah field Wireshark yang paling sering dipakai [S1]; baca kolom kanan untuk tahu apa yang dicari.

| Field | Arti forensik |
|---|---|
| `dns.qry.name` | Nama yang di-query; subdomain panjang/acak adalah kandidat tunneling |
| `dns.qry.name.len` | Panjang nama; memudahkan filter nama panjang |
| `dns.qry.type` | Tipe record: A, AAAA, TXT, NULL, CNAME (TXT/NULL sering dipakai tunneling) |
| `dns.flags.response` | 0 query, 1 response |
| `dns.flags.rcode` | Kode balasan; 3 berarti nama tidak ada (NXDOMAIN) |
| `dns.a` / `dns.aaaa` | Alamat IPv4/IPv6 hasil resolusi |
| `dns.count.answers` | Jumlah jawaban |
| `dns.id` | Transaction ID yang mengikat query dan response |

Nilai tipe dan kode yang perlu dihafal untuk membaca keluaran tshark, yang menampilkan angka, bukan nama: A 1, NS 2, CNAME 5, SOA 6, NULL 10, PTR 12, MX 15, TXT 16 [S4], dan AAAA 28 [S10]. RCODE 0 berarti tanpa error, 2 server failure, 3 name error (NXDOMAIN, bermakna hanya dari server otoritatif), dan 5 refused [S4].

Perhatian untuk catatan lama dan cheat sheet di internet: field `dns.resp.addr` hanya ada di Wireshark 1.4 sampai 1.10 [S1]. Di Wireshark 4.6, alamat hasil resolusi dibaca dari `dns.a` dan `dns.aaaa`.

Sinyal: query luar biasa panjang (subdomain mengkodekan data), frekuensi tinggi ke satu domain induk, tipe record tidak lazim dalam volume, dan domain yang baru atau tidak bereputasi. DNS tunneling (Day 05) memakai kombinasi ini. Satu sinyal saja tidak cukup. TXT dipakai sah untuk banyak hal; contoh yang paling umum di perusahaan adalah SPF, kebijakan pengirim email yang wajib dipublikasikan sebagai record TXT (tipe 16) [S12]. Mail gateway yang memeriksa SPF setiap email masuk akan menghasilkan query TXT dalam volume besar, tetapi ke banyak domain induk yang berbeda, bukan ke satu domain dengan ribuan subdomain.

### 1.7 TLS awal: apa yang masih terlihat dari HTTPS

Pertanyaan keenam Sari muncul karena sebagian besar trafik proxy di pcap egress adalah TLS. Day 06 membahas TLS secara mendalam; bagian ini hanya menjawab apa yang tersisa untuk dibaca di awal percakapan.

Di TLS 1.3, ClientHello dan ServerHello dikirim tanpa enkripsi. ClientHello memuat random, daftar cipher suite, dan ekstensi; ServerHello memuat cipher suite yang dipilih dan ekstensi minimum yang dibutuhkan untuk menyiapkan koneksi, seperti `supported_versions` dan `key_share` [S9]. Semua pesan handshake setelah ServerHello dienkripsi, termasuk Certificate [S9]. Akibatnya, di TLS 1.3 sertifikat server tidak terlihat di pcap, sedangkan di TLS 1.2 sertifikat masih dikirim terbuka.

Field versi juga perlu dibaca dengan benar. Field `legacy_version` di ClientHello dan ServerHello TLS 1.3 diisi 0x0303, yaitu nomor versi TLS 1.2, demi kompatibilitas dengan middlebox; versi sebenarnya dipilih lewat ekstensi `supported_versions`, dengan nilai 0x0304 untuk TLS 1.3 [S9]. Jadi `tls.handshake.version == 0x0303` tidak membuktikan TLS 1.2; lihat `tls.handshake.extensions.supported_version` di ServerHello [S1].

Yang masih bisa dibaca dari awal percakapan TLS:

| Yang terlihat | Field Wireshark [S1] | Arti forensik |
|---|---|---|
| Nama server (SNI) | `tls.handshake.extensions_server_name` | Domain yang dituju, selama tidak memakai ECH (Day 15) |
| Versi terpilih | `tls.handshake.extensions.supported_version` di ServerHello | TLS 1.3 atau lebih lama |
| Protokol aplikasi (ALPN) | `tls.handshake.extensions_alpn_str` | Misalnya `h2` atau `http/1.1` |
| Cipher suite | `tls.handshake.ciphersuite` | Daftar klien dan pilihan server; bahan fingerprint (Day 06) |
| Alert TLS | `tls.alert_message.desc` | Kegagalan handshake, misalnya sertifikat ditolak |
| Fingerprint klien | `tls.handshake.ja3`, `tls.handshake.ja4` | Dibahas di Day 06 dan Day 15 |

Spesifikasi TLS 1.3 diperbarui pada Juli 2026 sebagai RFC 9846, yang menggantikan RFC 8446 tanpa mengubah nomor versi dan tetap kompatibel ke belakang [S11]. Bagi analisis pcap, perilaku di atas tidak berubah.

### 1.8 SMB: share dan transfer file

Pertanyaan ketujuh Sari menyebut lateral movement lewat SMB. Jawaban singkatnya ada di bagian 1.4: SMB antar host di dalam tidak lewat TAP egress. Namun pengetahuan membaca SMB tetap dibutuhkan untuk pcap lab dan untuk sensor data center yang menyusul (Day 08 dan Day 19).

SMB dipakai untuk berbagi file dan lateral movement [S5]:

- Versi: SMB1 (lama, berisiko) dan SMB2/3 (modern). Dialek SMB2/3 dinegosiasikan di NEGOTIATE dengan nilai 0x0202 (SMB 2.0.2), 0x0210 (2.1), 0x0300 (3.0), 0x0302 (3.0.2), dan 0x0311 (3.1.1) [S5]. Di Wireshark, field-nya `smb2.dialect` [S1].
- Operasi: tree connect (akses share), create/read/write (file), termasuk akses admin share (C$, ADMIN$). Kode command di header SMB2 antara lain NEGOTIATE 0x0000, SESSION_SETUP 0x0001, TREE_CONNECT 0x0003, CREATE 0x0005, CLOSE 0x0006, READ 0x0008, WRITE 0x0009, dan IOCTL 0x000B [S5].
- Field Wireshark `smb2.*`, antara lain `smb2.cmd`, `smb2.tree`, `smb2.filename`, `smb2.nt_status`, `smb2.acct`, dan `smb2.write_length` [S1].

Sinyal forensik:

- Akses admin share (C$, ADMIN$) dari host ke host: kandidat lateral movement. Share administratif ini hanya bisa dipakai akun dengan hak admin lokal di host tujuan, sehingga workstation biasa yang memetakannya ke workstation lain jarang punya alasan sah (Day 19 membahas polanya lebih dalam). ATT&CK mencatat pola ini sebagai T1021.002 SMB/Windows Admin Shares: akun valid, biasanya setingkat admin, mengakses `C$`, `ADMIN$`, atau `IPC$` untuk berpindah host, mentransfer file, dan menjalankan program [S13].
- Transfer file executable lewat SMB.
- SMB1 yang masih dipakai (risiko, sebagian exploit lama).
- File yang ditulis ke share bisa diekspor (Export Objects SMB, Day 02).
- Trafik SMB yang menuju internet. Di egress PT JAB, port 445 dan 139 keluar diblokir firewall, jadi SMB apa pun yang terlihat di TAP egress adalah temuan yang perlu dijelaskan.

### 1.9 FTP dan protokol transfer lain

Item `SOC-2027-0614` adalah unggahan FTP dari server data center pukul 01:30. Untuk menilainya, kamu perlu tahu bentuk percakapan FTP yang normal dan apa saja yang terbuka di kabel.

FTP (tanpa enkripsi) mengirim perintah dan kredensial dalam teks [S1][S14]:

- FTP memakai dua koneksi: koneksi kontrol untuk perintah dan balasan, dan koneksi data untuk isi file dan daftar direktori [S14].
- Perintah: USER (identitas pengguna), PASS (password, segera setelah USER), RETR (unduh: server mengirim salinan file), STOR (unggah: server menyimpan data sebagai file, menimpa file dengan nama sama), LIST, PORT (klien memberi tahu port datanya), dan PASV (server membuka port data dan menunggu klien) [S14].
- Kode balasan tiga digit: 220 layanan siap, 331 username diterima dan butuh password, 230 login berhasil, 530 tidak login, 227 masuk mode pasif dengan alamat dan port, 150 koneksi data akan dibuka, 226 transfer selesai dan koneksi data ditutup, 550 aksi tidak dilakukan (file tidak ada atau akses ditolak) [S14].
- Alamat di PORT dan balasan 227 ditulis sebagai enam angka `h1,h2,h3,h4,p1,p2` [S14]; nomor port data adalah `p1 x 256 + p2`.
- Field Wireshark: `ftp.request.command`, `ftp.request.arg`, `ftp.response.code`, `ftp.response.arg`, `ftp.passive.ip`, `ftp.passive.port` [S1].
- Kredensial terlihat jelas (hati-hati, jangan simpan nilai kredensial).

Sinyal: STOR (unggah) file ke server eksternal (exfil), kredensial yang bocor, rangkaian 530 berulang (tebak password, Day 04), atau transfer file mencurigakan. Protokol transfer lain (TFTP, SFTP terenkripsi) punya karakteristik berbeda; SFTP hanya memberi metadata karena berjalan di atas SSH.

### 1.10 Protokol di port tak lazim

Item `SOC-2027-0611` adalah koneksi ke port 4444. Pertanyaan keempat Sari ("kenapa layak dikejar") sebagian dijawab oleh port itu sendiri, dan sebagian oleh apa yang terjadi di sana.

Trafik di port tidak lazim (bukan 80/443/53) layak diperiksa. Memakai protokol di port yang bukan port standarnya, misalnya HTTP di 8443 atau protokol kustom di 4444, adalah teknik yang tercatat di ATT&CK sebagai T1571 Non-Standard Port (taktik Command and Control) [S6]; tujuannya melewati aturan firewall yang hanya memeriksa port. Halaman teknik itu memberi contoh HTTPS di port 8088 dan aktor yang memakai HTTP di port 808 dan 880, serta mencatat port 4444 di antara contoh prosedur [S6].

Wireshark mencoba mengenali protokol dari port dan heuristik. Bila gagal, periksa byte mentah lewat Follow Stream untuk mencari pola, karena mungkin isinya protokol kustom atau terenkripsi. Bila protokolnya dikenali tetapi di port lain, pakai Decode As.

Port tak lazim tetap hanya sinyal: aplikasi internal, panel admin vendor, dan alat pemantauan sering memakai port sendiri. Yang membuat `SOC-2027-0611` menarik bukan angka 4444 saja, tetapi kombinasi: workstation biasa, koneksi langsung yang melewati proxy, interval yang rapi, dan tujuan yang sama dengan POST berulang di `SOC-2027-0613` (bagian 2.8).

### 1.11 Memetakan protokol ke pertanyaan

Sari meminta peta. Tabel ini adalah peta itu: mulai dari pertanyaan investigasi di kolom kiri, lalu pakai protokol dan field di kolom kanan, dan ingat titik pandang sensor dari bagian 1.4.

| Pertanyaan forensik | Protokol dan field | Catatan titik pandang di PT JAB |
|---|---|---|
| Domain apa yang dihubungi | DNS `dns.qry.name`, HTTP `http.host`, TLS SNI (Day 06) | Klien asli dari log resolver dan proxy |
| Apakah koneksi benar-benar tersambung | TCP handshake, `tcp.completeness`, Zeek `conn_state` | Pcap egress melihat percobaan yang ditolak firewall |
| File apa yang diunduh/diunggah | HTTP (Export Objects), SMB, FTP STOR/RETR | HTTPS hanya ukuran dan waktu |
| Apakah ada pemindaian | TCP SYN pattern (Day 04) | Pemindaian internal tidak lewat TAP egress |
| Apakah ada C2 | HTTP POST berulang, DNS tunneling, beacon (Day 11), port non-standar | Pcap egress kuat untuk ini |
| Apakah ada lateral movement | SMB admin share, named pipe ke layanan jarak jauh (Day 19); konfirmasi di log host | Tidak terlihat dari TAP egress |
| Kredensial bocor | FTP/HTTP plaintext (catat keberadaan, bukan nilai) | Hanya trafik yang lewat egress |
| Masalah jaringan atau capture | `tcp.analysis.*`, counter interface, statistik drop sensor | Bandingkan dengan counter router edge |

[komunitas, belum terkonfirmasi] Pemetaan pertanyaan ke protokol seperti tabel ini umum dipakai analis pcap; susunannya adalah praktik, bukan standar. Field persisnya sudah dicek di display filter reference Wireshark 4.6.9 [S1].

### 1.12 Sinyal vs kesimpulan

Pertanyaan terakhir Sari adalah cara menjaga L1 agar tidak membaca sinyal sebagai vonis. Setiap protokol memberi sinyal, bukan verdict (Day 01 dan Day 02). Tabel berikut memasangkan sinyal yang muncul di Day ini dengan penjelasan jinaknya; kolom kanan adalah korroborasi yang memisahkan keduanya.

| Sinyal | Penjelasan jinak | Korroborasi yang dicari |
|---|---|---|
| User-Agent aneh | Aplikasi internal buatan sendiri, agen vendor lama | Siapa pemiliknya, sejak kapan, berapa host memakainya, proses di endpoint |
| DNS TXT volume tinggi | Layanan sah (sebagian antivirus, pemeriksaan SPF) | Jumlah domain induk, panjang subdomain, klien asli |
| SMB admin share | Administrasi sah dari jump host | Akun, host asal, tiket perubahan, event di host tujuan |
| RST | Jaringan normal, port tertutup, firewall menolak | Siapa pengirim RST (TTL, waktu), pola waktu percobaan |
| Retransmission | Kehilangan paket di jaringan, capture yang drop | Counter interface, `ack_lost_segment`, statistik drop sensor |
| Port tak lazim | Aplikasi internal, panel vendor | Protokol yang sebenarnya, pemilik tujuan, host lain yang memakai |
| FTP STOR ke luar | Transfer rutin ke mitra | Jadwal, akun, tujuan terdaftar, ukuran dibanding hari lain |

Selalu sebut penjelasan jinak dan cari korroborasi (volume, frekuensi, tujuan, konteks endpoint) sebelum menyimpulkan. Pcap memberi bukti kuat tentang apa yang lewat kabel, tetapi tidak tentang niat dan tidak tentang proses.

## 2. Contoh dan langkah praktis: lima item egress PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Perintah dijalankan di `jkt-nsm-ws01` atas cuplikan pcap dari `jkt-pcap01`; cuplikan utama adalah `egress-20270505-0900.pcap` (Rabu 2027-05-05 09:00:00 sampai 09:14:59 WIB). IOC di keluaran ilustrasi di-defang (`[.]`) supaya tidak bisa diklik; tshark sendiri tidak men-defang. Nama field mengikuti Wireshark 4.6.9 [S1]. Untuk latihan, jalankan versi yang sama atas pcap lab (bagian 3).

### 2.1 Expert Info dan retransmission di pcap uji coba (`SOC-2027-0610`)

Item ini menjawab pertanyaan Bambang. Tiketnya dibuka pukul 09:20: "Expert Info cuplikan 09:00 penuh retransmission dan previous segment not captured, link egress bermasalah?"

**Tujuan:** memisahkan kehilangan paket nyata di jaringan dari kehilangan di alat capture, sebelum siapa pun membuka tiket gangguan link atau eskalasi keamanan.

**Sintaks:** filter display dasar untuk TCP, lalu hitungan per flag analisis.

```
tcp.flags.syn == 1 and tcp.flags.ack == 0
tcp.analysis.retransmission
tcp.flags.reset == 1
```

```bash
F=egress-20270505-0900.pcap
tshark -r "$F" -Y "tcp" | wc -l
for f in retransmission fast_retransmission duplicate_ack lost_segment ack_lost_segment zero_window; do
  printf "%-22s " "$f"; tshark -r "$F" -Y "tcp.analysis.$f" | wc -l
done
```

Penjelasan tiap bagian:

| Bagian | Fungsi |
|---|---|
| `tcp.flags.syn == 1 and tcp.flags.ack == 0` | SYN murni (awal koneksi atau pemindaian). Banyak ke banyak port dari satu sumber adalah scan (Day 04) |
| `tcp.analysis.retransmission` | Retransmission; biasanya masalah jaringan, jarang ancaman |
| `tcp.flags.reset == 1` | Koneksi diputus atau ditolak |
| `tshark -r "$F" -Y "tcp" \| wc -l` | Jumlah frame TCP sebagai penyebut |
| `for f in ...` | Hitungan per flag analisis; tiap baris dihitung terpisah |

Keluaran ilustrasi:

```
1162408
retransmission         4812
fast_retransmission    2214
duplicate_ack          3105
lost_segment           1906
ack_lost_segment       1877
zero_window              64
```

Langkah kedua memisahkan arah retransmission. Karena TAP berada di sisi dalam firewall, IP sumber di jaringan `10.0.0.0/8` berarti arah dari dalam ke internet.

```bash
tshark -r "$F" -Y "tcp.analysis.retransmission" -T fields -e ip.src \
  | awk '{ if ($1 ~ /^10\./) d++; else i++ } END { print "internet -> dalam", i; print "dalam -> internet", d; print "total", i+d }'
```

Keluaran ilustrasi:

```
internet -> dalam 3982
dalam -> internet 830
total 4812
```

Pembanding dari NOC pada jam yang sama: counter interface router edge Jakarta menunjukkan 0 input error dan 0 output drop, dengan utilisasi puncak sekitar 4,1 Gbps dari 10 Gbps. Log layanan capture di `jkt-pcap01` mencatat drop pada pukul 09:06 sampai 09:08 saat trafik puncak (nama counter-nya bergantung software capture yang dipakai).

**Cara membaca hasil:**

- Retransmission 4.812 dari 1.162.408 frame TCP adalah sekitar 0,41%. Sekitar 82,8% (3.982) datang dari internet ke dalam, terutama unduhan besar yang diterima proxy. Tiga stream ke satu CDN video menyumbang 1.204 frame (25,0%). Itu pola beban di sisi server atau jalur internet, bukan pola serangan.
- `lost_segment` 1.906 dan `ack_lost_segment` 1.877 hampir sama. Artinya 1.877 dari 1.906 celah (98,5%) kemudian di-ACK penerima tanpa ada pengiriman ulang: segmennya sampai, hanya tidak tertangkap. Bersama log drop di `jkt-pcap01` pada menit yang sama, ini menunjuk ke kapasitas capture, bukan ke link.
- Satu frame bisa membawa lebih dari satu flag analisis (bagian 1.3), jadi angka per baris tidak dijumlahkan.
- Disposisi `SOC-2027-0610`: bukan insiden keamanan dan bukan gangguan link. Tindak lanjutnya tiket ke Agung untuk kapasitas capture `jkt-pcap01` (buffer dan penulisan disk), karena pcap yang kehilangan segmen akan merusak Follow Stream dan Export Objects di kasus berikutnya.

**Variasi:** `tcp.analysis.flags && !tcp.analysis.window_update` menampilkan semua frame bermasalah kecuali window update yang tidak berbahaya. Untuk melihat stream mana yang paling banyak retransmission, ganti `-e ip.src` dengan `-e tcp.stream` lalu `sort | uniq -c | sort -rn | head`.

**Kapan gagal:** preferensi "Analyze TCP sequence numbers" dimatikan, sehingga semua `tcp.analysis.*` kosong [S7]; pcap dimulai di tengah sesi, sehingga awal setiap stream terlihat sebagai celah; atau pcap disatukan dari dua titik capture (misalnya SPAN dan TAP), sehingga paket yang sama tertangkap dua kali dan bisa ditandai sebagai retransmission. Cara memeriksa yang terakhir perlu dicek di lab: bandingkan IP ID dan timestamp paket yang ditandai.

### 2.2 SYN ke port 4444 yang selalu dibalas RST (`SOC-2027-0611`)

Item ini menjawab pertanyaan pertama Sari tentang RST dan sebagian pertanyaan keempat. Alertnya muncul pukul 08:25 dari rule Splunk atas `index=firewall`: workstation menghubungi port non-standar ke internet dan ditolak lebih dari 10 kali.

**Tujuan:** memastikan apa yang terjadi di tingkat paket: apakah koneksi pernah tersambung, siapa yang mengirim RST, dan bagaimana pola waktunya.

**Sintaks:**

```
tcp.port == 4444
ip.addr == 203.0.113.164 && tcp.port == 4444
```

```bash
tshark -r "$F" -Y "ip.addr == 203.0.113.164 && tcp.port == 4444" \
  -T fields -e frame.time -e ip.src -e ip.dst -e ip.ttl -e tcp.flags -e tcp.stream -e tcp.completeness
```

Tabel berikut menjelaskan tiap bagian perintah; perhatikan kolom TTL dan flag, karena keduanya dipakai untuk menebak pengirim RST.

| Bagian | Fungsi |
|---|---|
| `ip.addr == 203.0.113.164 && tcp.port == 4444` | Semua paket dua arah ke dan dari tujuan di port itu |
| `-e ip.ttl` | TTL saat paket tiba di TAP, untuk menebak siapa pengirim RST |
| `-e tcp.flags` | Flag dalam heksadesimal: 0x0002 SYN, 0x0012 SYN-ACK, 0x0010 ACK, 0x0014 RST-ACK. Jumlah digit bisa berbeda antar versi (0x002 atau 0x0002) |
| `-e tcp.stream` | Nomor percakapan |
| `-e tcp.completeness` | Seberapa lengkap percakapan yang terlihat (bagian 1.1) |

Keluaran ilustrasi (empat baris pertama dari 30):

```
May  5, 2027 09:00:12.418 WIB  10.10.60.31     203.0.113.164  127  0x0002  4102  33
May  5, 2027 09:00:12.419 WIB  203.0.113.164   10.10.60.31     64  0x0014  4102  33
May  5, 2027 09:01:12.507 WIB  10.10.60.31     203.0.113.164  127  0x0002  4377  33
May  5, 2027 09:01:12.508 WIB  203.0.113.164   10.10.60.31     64  0x0014  4377  33
```

Pembanding dari cuplikan yang sama: proxy `10.20.3.60` membuka koneksi ke IP yang sama di port 80 (bagian 2.3), dan SYN-ACK dari `203.0.113.164:80` tiba di TAP dengan TTL 49 setelah sekitar 38 ms.

```bash
tshark -r "$F" -Y "ip.src == 203.0.113.164 && tcp.flags.syn == 1 && tcp.flags.ack == 1" \
  -T fields -e ip.ttl -e tcp.analysis.initial_rtt -e tcp.srcport | sort | uniq -c
```

```
      3 49  0.038112000  80
```

Zeek offline atas cuplikan yang sama memberi ringkasan yang sama dalam satu baris per koneksi [S8]:

```bash
zeek -C -r "$F"
cat conn.log | zeek-cut ts id.orig_h id.resp_h id.resp_p conn_state history | awk '$4 == 4444' | head -2
```

```
1809482412.418  10.10.60.31  203.0.113.164  4444  REJ  Sr
1809482472.507  10.10.60.31  203.0.113.164  4444  REJ  Sr
```

`-C` membuat Zeek mengabaikan checksum yang salah, yang umum pada capture karena checksum offloading di kartu jaringan. Cek opsi ini di versi Zeek-mu sebelum memakai.

**Cara membaca hasil:**

- Ada 15 percobaan dalam 15 menit (30 paket), masing-masing satu SYN dan satu RST-ACK. Tidak ada SYN-ACK, tidak ada data. `tcp.completeness` 33 (SYN dan RST) dan Zeek `REJ` dengan history `Sr` (SYN dari originator, RST dari responder) sama-sama berarti koneksi tidak pernah tersambung.
- RST datang 1 ms setelah SYN dengan TTL 64, padahal paket asli dari `203.0.113.164` tiba dengan TTL 49 setelah 38 ms. RST itu hampir pasti dibuat perangkat di dekat sensor, yaitu `jkt-fw01` yang menolak dengan reset atas nama tujuan. Log firewall mengonfirmasi aksi deny untuk sesi yang sama. Jadi server tujuan tidak pernah menerima SYN ini.
- Interval antarpercobaan 60 detik dengan selisih di bawah satu detik. Log firewall menunjukkan percobaan pertama pukul 08:12:12, sehingga sampai 09:14:12 ada 63 percobaan. Manusia tidak mencoba ulang serapi itu; program yang melakukannya.
- Yang terbukti dari pcap: `JKT-WS-2011` terus mencoba koneksi langsung ke `203.0.113.164:4444` dan ditolak. Yang belum terbukti: program apa, dan apakah tujuan itu berbahaya. Itu dijawab dengan menggabungkan item lain (bagian 2.8) dan data endpoint.

**Variasi:** `tcp.completeness == 33` menampilkan semua percobaan yang ditolak di cuplikan itu, bukan hanya ke port 4444. Stacking tujuan dan port dari hasil filter itu (`-e ip.dst -e tcp.dstport | sort | uniq -c | sort -rn`) menunjukkan workstation lain yang mencoba keluar langsung.

**Kapan gagal:** firewall dikonfigurasi menolak tanpa reset (drop diam), sehingga yang terlihat hanya SYN berulang dengan retransmission SYN dan Zeek mencatat `S0`; atau sensor berada di luar firewall, sehingga SYN yang ditolak tidak pernah terlihat. Heuristik TTL juga gagal bila perangkat tengah meniru TTL tujuan.

### 2.3 POST berulang lewat proxy (`SOC-2027-0613`)

Item ini menjawab bagian lain pertanyaan keempat. Alertnya muncul pukul 08:40 dari rule `index=proxy`: POST berulang dengan User-Agent yang tidak dipakai browser modern.

**Tujuan:** membaca request HTTP lengkap di pcap egress, menilai pola waktunya, lalu menemukan workstation asli lewat log proxy (bagian 1.4).

**Sintaks filter:**

```
http.request
http.request.method == "POST"
http.user_agent
http.content_type contains "octet-stream"
```

**Stacking POST per host dan User-Agent:**

```bash
tshark -r "$F" -Y 'http.request.method == "POST"' -T fields -e http.host -e http.user_agent \
  | sort | uniq -c | sort -rn
```

Keluaran ilustrasi:

```
     38 telemetry.printvendor.example   PrintAgent/5.2
     15 api.netprobe.example            NetProbe/3.1
      3 update-relay.example            Mozilla/4.0 (compatible)
```

**Ekstraksi request lengkap** dengan perintah tshark dari Day 02, ditambah waktu dan sumber:

```bash
tshark -r "$F" -Y "http.request && http.host contains \"update-relay\"" -T fields \
  -e frame.time -e ip.src -e ip.dst -e http.host -e http.request.method -e http.request.uri -e http.user_agent -e http.content_length
```

Tabel berikut menjelaskan bagian yang paling berpengaruh pada cara membaca hasil.

| Bagian | Fungsi |
|---|---|
| `http.request && http.host contains "update-relay"` | Hanya request ke host itu |
| `-e ip.src` | Sumber di pcap egress; untuk trafik kantor ini selalu proxy |
| `-e http.request.uri` | Path; path yang sama berulang menarik |
| `-e http.content_length` | Ukuran body POST |

Keluaran ilustrasi:

```
May  5, 2027 09:02:41.733 WIB  10.20.3.60  203.0.113.164  update-relay[.]example  POST  /upload  Mozilla/4.0 (compatible)  412
May  5, 2027 09:07:41.902 WIB  10.20.3.60  203.0.113.164  update-relay[.]example  POST  /upload  Mozilla/4.0 (compatible)  412
May  5, 2027 09:12:41.655 WIB  10.20.3.60  203.0.113.164  update-relay[.]example  POST  /upload  Mozilla/4.0 (compatible)  412
```

Response yang ditautkan (`http.response_for.uri contains "/upload"`, field `http.response.code` dan `http.content_length`) adalah 200 dengan body 64 byte untuk ketiga request.

**Pivot ke log proxy** untuk klien asli:

```
index=proxy "update-relay.example" earliest="05/05/2027:00:00:00" latest="05/05/2027:09:15:00"
| stats count min(_time) AS first max(_time) AS last values(http_user_agent) AS ua BY src http_method
| convert ctime(first) ctime(last)
```

Tabel berikut menjelaskan tiap bagian search.

| Bagian | Fungsi |
|---|---|
| `"update-relay.example"` dan rentang absolut | Semua request ke host itu sejak tengah malam sampai akhir cuplikan |
| `stats ... BY src http_method` | Siapa klien aslinya dan method apa |
| `min(_time)` / `max(_time)` | Kapan pertama dan terakhir terlihat |

Nama field `src`, `http_method`, dan `http_user_agent` mengikuti normalisasi add-on proxy di Splunk PT JAB; cek nama field di lingkunganmu.

Keluaran ilustrasi:

```
src          http_method  count  first                last                 ua
10.10.60.31  POST         13     05/05/2027 08:12:41  05/05/2027 09:12:41  Mozilla/4.0 (compatible)
```

**Cara membaca hasil:**

- POST berulang ke satu host dengan User-Agent sama, path tetap, ukuran body identik (412 byte), dan interval 300 detik adalah kandidat C2 (Day 11). Dari 08:12:41 sampai 09:12:41 dengan interval 300 detik ada 13 request, cocok dengan log proxy.
- Dua penjelasan jinak di baris atas stacking (printer vendor, agen pemantauan NetProbe) juga POST berulang. Bedanya: keduanya dipakai banyak host, punya pemilik yang diketahui, dan User-Agent-nya menyebut produk. `update-relay.example` hanya dipakai satu klien, dengan User-Agent generik yang tidak dipakai browser modern.
- Klien aslinya `10.10.60.31`, yaitu `JKT-WS-2011`, workstation yang sama dengan `SOC-2027-0611`, dan IP tujuannya pun sama (`203.0.113.164`). Dua kanal ke satu tujuan dari satu host mengubah dua sinyal lemah menjadi satu cerita (bagian 2.8).
- Unduhan dengan `Content-Type` octet-stream adalah kandidat payload (Export Objects, Day 02). Di cuplikan ini response-nya hanya 64 byte dan bukan file.

**Variasi:** Statistics > HTTP > Requests di Wireshark memberi ringkasan host dan path tanpa tshark. Untuk interval, `-e frame.time_delta_displayed` di filter yang sama langsung memberi jeda antarrequest.

**Kapan gagal:** trafiknya HTTPS tanpa dekripsi, sehingga yang terlihat di pcap hanya SNI dan ukuran (bagian 2.5); proxy menyamarkan atau mengganti User-Agent; atau rentang log proxy di Splunk berbeda zona waktu dengan pcap, sehingga pencocokan waktu meleset. Pastikan keduanya memakai WIB atau keduanya UTC.

### 2.4 Query TXT dari resolver (`SOC-2027-0612`)

Item ini menjawab pertanyaan kelima Sari. Alertnya muncul pukul 09:05 dari rule `index=dns`: proporsi query TXT melonjak dibanding minggu lalu.

**Tujuan:** menentukan apakah volume TXT berasal dari satu domain induk dengan banyak subdomain (pola tunneling) atau dari banyak domain berbeda (pola layanan sah).

**Sintaks filter:**

```
dns.flags.response == 0
dns.qry.type == 16
dns.qry.name
```

**Ekstraksi query** dengan perintah dari Day 02:

```bash
tshark -r "$F" -Y "dns.flags.response == 0" -T fields -e frame.time -e ip.src -e dns.qry.name -e dns.qry.type
```

**Stacking tipe query:**

```bash
tshark -r "$F" -Y "dns.flags.response == 0" -T fields -e dns.qry.type | sort | uniq -c | sort -rn
```

Keluaran ilustrasi:

```
  21904 1
   5730 28
   2418 16
    812 12
    506 15
    190 lainnya
```

Total query keluar 31.560. TXT (16) 2.418, atau sekitar 7,66%.

**Stacking sumber dan nama untuk TXT:**

```bash
tshark -r "$F" -Y "dns.flags.response == 0 && dns.qry.type == 16" -T fields -e ip.src | sort | uniq -c
tshark -r "$F" -Y "dns.flags.response == 0 && dns.qry.type == 16" -T fields -e dns.qry.name \
  | awk '{ n[$1]++; if (length($1) > m) m = length($1) } END { print "nama unik", length(n); print "panjang maks", m }'
```

Keluaran ilustrasi:

```
   1302 10.20.2.53
   1116 10.20.2.54
nama unik 1106
panjang maks 34
```

**Pivot ke log resolver** untuk klien asli:

```
index=dns query_type=TXT earliest="05/05/2027:09:00:00" latest="05/05/2027:09:15:00"
| stats count dc(query) AS nama_unik BY src
| sort - count
```

Keluaran ilustrasi:

```
src          count  nama_unik
10.20.2.25   3402   1063
(lainnya)     138     51
```

Nama field `query_type`, `query`, dan `src` mengikuti normalisasi log resolver PT JAB; cek di lingkunganmu.

**Cara membaca hasil:**

- Di pcap egress, sumber TXT hanya dua resolver (1.302 + 1.116 = 2.418). Pcap tidak tahu siapa yang bertanya.
- Log resolver mencatat 3.540 query TXT dari klien (3.402 + 138), lebih banyak dari 2.418 di egress. Selisihnya dijawab dari cache resolver. Ini contoh langsung bagian 1.4: jumlah di pcap egress bukan jumlah permintaan klien.
- 96% query TXT (3.402 dari 3.540) berasal dari `10.20.2.25`, mail gateway `jkt-mailgw01`. Nama yang di-query adalah 1.106 nama berbeda dengan panjang maksimal 34 karakter, dan sebagian besar adalah domain pengirim email itu sendiri. Itu bentuk pemeriksaan SPF (bagian 1.6), bukan tunneling: tunneling menghasilkan banyak subdomain unik di bawah satu domain induk, sering dengan label mendekati 63 karakter.
- Lonjakan dibanding minggu lalu dicocokkan ke tim email: kampanye newsletter mitra masuk sejak pukul 08:30, menaikkan email masuk dan pemeriksaan SPF. Disposisi `SOC-2027-0612`: jinak terkonfirmasi. Rule perlu dikecualikan untuk `10.20.2.25` dengan batas sempit (hanya TXT, hanya bila domain induk beragam), bukan dimatikan.

**Variasi:** `dns.qry.name.len > 50` menampilkan nama panjang langsung. Untuk NXDOMAIN, `dns.flags.response == 1 && dns.flags.rcode == 3`. Untuk menautkan query ke response, `dns.response_in` dan `dns.time` memberi pasangan dan jedanya.

**Kapan gagal:** klien memakai DNS over HTTPS atau resolver luar (Day 16), sehingga query tidak lewat resolver PT JAB; log resolver tidak memuat kode jawaban, sehingga rasio NXDOMAIN harus dihitung dari pcap; atau domain tunneling memakai label pendek dan pelan, sehingga statistik panjang tidak menonjol (Day 05).

### 2.5 TLS ClientHello: SNI dan versi

Item ini menjawab pertanyaan keenam Sari: dari HTTPS yang tidak didekripsi, apa yang tetap bisa dipakai.

**Tujuan:** menghitung ClientHello per SNI, memastikan versi TLS yang benar-benar dipakai, dan memeriksa apakah tujuan dari item lain muncul sebagai TLS.

**Sintaks:**

```bash
tshark -r "$F" -Y "tls.handshake.type == 1" -T fields -e ip.src -e tls.handshake.extensions_server_name \
  | awk '{ print $1 }' | sort | uniq -c | sort -rn
tshark -r "$F" -Y "tls.handshake.type == 1 && !tls.handshake.extensions_server_name" | wc -l
tshark -r "$F" -Y "tls.handshake.type == 2" -T fields -e tls.handshake.extensions.supported_version \
  | sort | uniq -c
tshark -r "$F" -Y 'tls.handshake.extensions_server_name contains "update-relay"' | wc -l
```

Tabel berikut menjelaskan filter yang dipakai; baris terakhir menjelaskan kenapa versi dibaca dari ServerHello.

| Bagian | Fungsi |
|---|---|
| `tls.handshake.type == 1` | ClientHello |
| `tls.handshake.type == 2` | ServerHello |
| `!tls.handshake.extensions_server_name` | ClientHello tanpa SNI |
| `-e tls.handshake.extensions.supported_version` di ServerHello | Versi yang dipilih server; kosong berarti tidak ada ekstensi itu (TLS 1.2 atau lebih lama) |

Keluaran ilustrasi:

```
  18105 10.20.3.60
    337 (server data center lain)
212
  15880 0x0304
   2341
0
```

**Cara membaca hasil:**

- Ada 18.442 ClientHello (18.105 dari proxy, 337 dari server data center yang mengambil pembaruan). 212 di antaranya tanpa SNI; itu umum untuk koneksi ke IP langsung dan perlu dilihat lebih jauh hanya bila tujuannya tidak dikenal.
- Ada 18.221 ServerHello: 15.880 memilih TLS 1.3 (0x0304) dan 2.341 tanpa ekstensi `supported_versions`, yaitu TLS 1.2 atau lebih lama. Selisih 221 terhadap ClientHello adalah handshake yang tidak dijawab atau gagal dan bisa dicek dengan `tls.alert_message.desc` serta `tcp.flags.reset == 1`.
- Sertifikat server hanya terlihat untuk sesi TLS 1.2 (paling banyak 2.341 sesi; sesi yang dilanjutkan tanpa sertifikat lebih sedikit). Di TLS 1.3 Certificate terenkripsi [S9], jadi analisis sertifikat di pcap makin sempit (Day 06).
- `update-relay.example` tidak muncul sebagai SNI sama sekali: kanal itu murni HTTP polos di port 80 (bagian 2.3). HTTP tanpa enkripsi ke domain yang tidak dikenal pada 2027 sudah merupakan detail yang menarik.

**Variasi:** `tls.handshake.extensions_alpn_str` memisahkan HTTP/2 dari HTTP/1.1. `tls.handshake.ja4` memberi fingerprint klien (Day 06); untuk trafik lewat proxy, fingerprint yang terlihat adalah milik proxy, bukan workstation.

**Kapan gagal:** ClientHello memakai ECH, sehingga SNI yang terlihat hanya nama luar milik penyedia (Day 15); trafik memakai QUIC di UDP 443, sehingga filter `tls.handshake` di atas TCP tidak menangkapnya (Day 16); atau ClientHello terpecah ke beberapa segmen dan capture kehilangan salah satunya (bagian 2.1).

### 2.6 FTP malam ke mitra (`SOC-2027-0614`)

Item ini menjawab bagian pertama pertanyaan ketujuh Sari. Alertnya muncul pukul 01:31 dari rule `index=firewall`: aplikasi FTP keluar dari subnet data center. Cuplikan yang dipakai adalah `egress-20270505-0130.pcap`.

**Tujuan:** membaca rangkaian perintah FTP, menentukan arah dan ukuran transfer, dan mencatat paparan kredensial tanpa menyimpan nilainya.

**Sintaks filter:**

```
ftp.request.command == "STOR"
ftp.request.command == "RETR"
ftp
ftp-data
```

```bash
F2=egress-20270505-0130.pcap
tshark -r "$F2" -Y "ftp" -T fields -e frame.time -e ip.src -e ftp.request.command -e ftp.request.arg -e ftp.response.code -e ftp.response.arg
```

Tabel berikut menjelaskan field yang diekstrak.

| Bagian | Fungsi |
|---|---|
| `-Y "ftp"` | Hanya koneksi kontrol (port 21) |
| `ftp.request.command` / `ftp.request.arg` | Perintah klien dan argumennya |
| `ftp.response.code` / `ftp.response.arg` | Balasan server |
| `ftp-data` | Koneksi data; Wireshark mengenalinya dari balasan 227 atau perintah PORT |

Keluaran ilustrasi (argumen PASS disamarkan di catatan; di pcap nilainya terbaca):

```
01:30:05.112  203.0.113.165  -     -                         220  Service ready
01:30:05.150  10.20.15.41    USER  recon_jab
01:30:05.188  203.0.113.165  -     -                         331  Password required
01:30:05.190  10.20.15.41    PASS  <disamarkan>
01:30:05.241  203.0.113.165  -     -                         230  User logged in
01:30:05.243  10.20.15.41    TYPE  I
01:30:05.280  203.0.113.165  -     -                         200  Type set to I
01:30:05.282  10.20.15.41    PASV
01:30:05.319  203.0.113.165  -     -                         227  Entering Passive Mode (203,0,113,165,195,80)
01:30:05.322  10.20.15.41    STOR  rekon_20270504.csv
01:30:05.401  203.0.113.165  -     -                         150  Opening data connection
01:30:09.877  203.0.113.165  -     -                         226  Transfer complete
01:30:09.915  10.20.15.41    QUIT
```

Ukuran koneksi data dari Statistics > Conversations (TCP), atau:

```bash
tshark -r "$F2" -Y "ip.dst == 203.0.113.165 && tcp.dstport == 50000" -T fields -e tcp.len \
  | awk '{ s += $1 } END { print s }'
```

```
4218880
```

**Cara membaca hasil:**

- Sumbernya `10.20.15.41`, server `jkt-recon01` (aplikasi rekonsiliasi pembayaran), ke `203.0.113.165`, server FTP mitra pembayaran `ftp.mitrabayar.example`. Di internet, sumbernya terlihat sebagai IP NAT data center `198.51.100.203`.
- Balasan 227 memberi port data `195 x 256 + 80 = 50000`. Satu STOR, 4.218.880 byte (sekitar 4,0 MiB), selesai dalam sekitar 4,5 detik dengan balasan 226.
- STOR (unggah) ke server eksternal adalah kandidat exfil; RETR (unduh) bisa payload. Di kasus ini, tujuan, akun, nama file, jam, dan ukuran cocok dengan job terjadwal yang tercatat di dokumentasi aplikasi; ukurannya sebanding dengan malam-malam sebelumnya di log firewall. Transfernya jinak.
- Namun USER dan PASS terkirim tanpa enkripsi melewati internet. Catat bahwa kredensial akun `recon_jab` terpapar, jangan simpan nilainya di tiket atau laporan. Disposisi `SOC-2027-0614`: jinak sebagai aktivitas, tetapi temuan risiko: rekomendasi pindah ke SFTP atau FTPS dan rotasi password akun itu, dengan pemilik aplikasi sebagai penanggung jawab.

**Variasi:** Follow TCP Stream sesi kontrol menampilkan seluruh rangkaian perintah dalam satu tampilan. `ftp.response.code == 530` menampilkan login gagal (tebak password, Day 04). File yang diunggah bisa direkonstruksi dari koneksi data dengan Follow Stream bila diperlukan untuk pembuktian; perlakukan isinya sebagai data sensitif mitra.

**Kapan gagal:** server memakai FTPS (FTP di atas TLS), sehingga perintah dan kredensial terenkripsi; mode aktif (PORT) dengan koneksi data dari server ke klien yang ditolak firewall, sehingga hanya terlihat 425 atau timeout; atau capture hanya memuat koneksi kontrol karena koneksi data lewat jalur lain.

### 2.7 SMB: cek egress dan contoh pcap lab

Item ini menjawab bagian kedua pertanyaan ketujuh Sari: apakah pcap egress bisa melihat lateral movement lewat SMB.

**Tujuan:** memastikan tidak ada SMB yang keluar ke internet, lalu menunjukkan filter yang dipakai bila pcap memuat SMB (pcap lab sekarang, sensor data center nanti).

**Cek di egress:**

```bash
tshark -r "$F" -Y "tcp.port == 445 || tcp.port == 139 || smb || smb2" | wc -l
```

```
0
```

Nol baris di egress adalah hasil yang diharapkan: port 445 dan 139 keluar diblokir, dan SMB antar host di dalam tidak lewat TAP. Nol di sini tidak berarti tidak ada lateral movement, hanya bahwa titik pandang ini tidak bisa melihatnya.

**Filter SMB** (dipakai atas pcap lab dengan jaringan host-only `192.168.56.0/24`):

```
smb2.cmd
smb2.tree contains "C$"
smb2.tree contains "ADMIN$"
smb2.filename
smb2.dialect
smb
```

```bash
tshark -r lab-smb.pcap -Y "smb2.cmd == 3 || smb2.cmd == 5" \
  -T fields -e frame.time -e ip.src -e ip.dst -e smb2.cmd -e smb2.tree -e smb2.filename -e smb2.nt_status
```

Tabel berikut menjelaskan filter dan field; kode command mengikuti bagian 1.8.

| Bagian | Fungsi |
|---|---|
| `smb2.cmd == 3` | TREE_CONNECT: akses share |
| `smb2.cmd == 5` | CREATE: membuka atau membuat file |
| `smb2.tree` | Path share, misalnya `\\192.168.56.20\ADMIN$` |
| `smb2.filename` | File yang dibuka atau dibuat |
| `smb2.nt_status` | Status balasan; 0 berarti berhasil |

Keluaran ilustrasi dari lab:

```
10:14:02.118  192.168.56.10  192.168.56.20  3  \\192.168.56.20\ADMIN$
10:14:02.121  192.168.56.20  192.168.56.10  3                                       0x00000000
10:14:02.130  192.168.56.10  192.168.56.20  5                         tool.exe
10:14:02.133  192.168.56.20  192.168.56.10  5                         tool.exe      0x00000000
```

**Cara membaca hasil:**

- Filter akses admin share (C$, ADMIN$) adalah kandidat lateral movement; `smb2.filename` menunjukkan file yang diakses atau ditulis.
- Host yang mengakses admin share host lain, lalu menulis executable, adalah pola lateral movement klasik: berkas ditaruh lewat SMB, lalu dijalankan dari jarak jauh, misalnya dengan membuat service baru. Konfirmasinya ada di host tujuan, yaitu event pembuatan service atau proses baru pada jam yang sama (di Windows, Event ID 7045 untuk service baru dan 4688 untuk proses baru bila audit-nya aktif). ATT&CK mendeskripsikan analytic serupa: akses `ADMIN$` atau `C$` dikorelasikan dengan pembuatan service, penjadwalan task, atau eksekusi proses di host tujuan [S13].
- `smb2.dialect` di NEGOTIATE menunjukkan dialek; SMB1 (filter `smb`) yang masih dipakai adalah temuan tersendiri.

**Variasi:** File > Export Objects > SMB memulihkan file yang ditulis (Day 02). Statistics > Conversations yang difilter `tcp.port == 445` menunjukkan pasangan host mana yang paling banyak bertukar SMB.

**Kapan gagal:** SMB 3.x dengan enkripsi aktif, sehingga nama file dan isi tidak terbaca dan hanya header yang tersisa; pcap hanya memuat SMB1 sehingga field `smb2.*` kosong (pakai `smb.*`); atau trafiknya tidak lewat titik capture sama sekali, seperti di egress PT JAB.

### 2.8 Menggabungkan protokol menjadi satu cerita (`INC-2027-062`)

Bagian ini menjawab pertanyaan kedelapan Sari dengan contoh: satu protokol memberi sepotong, beberapa protokol bersama menceritakan sesi.

Untuk satu pcap, jawab dengan protokol yang tepat (bagian 1.11). Tabel berikut adalah langkahnya.

| Pertanyaan | Langkah |
|---|---|
| Domain yang dihubungi | tshark DNS `dns.qry.name` dan HTTP `http.host`; stacking |
| File ditransfer | HTTP Export Objects; SMB/FTP filename/command |
| C2 | HTTP POST berulang (IO Graph, Day 02); DNS tunneling; port non-standar |
| Lateral | SMB admin share (sensor yang tepat) |

Untuk `JKT-WS-2011`, cuplikan tambahan `egress-20270505-0810.pcap` dan log proxy serta resolver disusun menjadi satu timeline. Tabel berikut menunjukkan sumber tiap baris, supaya jelas mana bukti paket dan mana bukti log.

| Waktu (WIB) | Kejadian | Protokol / sumber |
|---|---|---|
| 08:12:12 | SYN `10.10.60.31` ke `203.0.113.164:4444`, RST dari `jkt-fw01` | TCP, pcap egress dan log firewall |
| 08:12:38 | Proxy me-resolve `update-relay.example` ke `203.0.113.164`; klien yang meminta lewat proxy adalah `10.10.60.31` | DNS dari `jkt-res01` di pcap; log proxy |
| 08:12:41 | POST pertama `/upload`, UA `Mozilla/4.0 (compatible)`, 412 byte | HTTP, pcap egress dan log proxy |
| 08:12 sampai 09:15 | SYN ke 4444 tiap 60 detik (63 kali), POST tiap 300 detik (13 kali) | TCP dan HTTP |

**Cara membaca hasil:**

- Polanya konsisten dengan program yang mencoba kanal langsung lebih dulu, lalu memakai proxy saat kanal langsung ditolak. Dua kanal, satu tujuan, satu host, interval teratur.
- Yang masih sinyal, bukan kesimpulan: tujuan belum diketahui berbahaya dari reputasi, dan pcap tidak memberi nama proses. Penjelasan jinak yang perlu digugurkan: aplikasi kantor yang sah dengan fallback proxy (tidak ada di daftar aset dan tidak dipakai host lain), atau alat uji tim NOC (tidak ada tiket perubahan).
- Pukul 10:05, SOC memeriksa `JKT-WS-2011` di Microsoft Defender for Endpoint: koneksi ke `203.0.113.164` berasal dari proses tanpa tanda tangan digital di folder `AppData` milik pengguna, yang mulai berjalan pagi itu. Pukul 10:35, Dimas Prasetyo menyatakan `INC-2027-062` dan menyerahkannya ke IR; pukul 10:41, `JKT-WS-2011` diisolasi lewat EDR. Isi investigasi endpoint di luar cakupan Day ini; peran pcap di sini adalah memberi bukti paket yang bisa diulang dan timeline jaringan.
- `jkt-pcap01` menyimpan 72 jam. Cuplikan pcap yang dipakai disalin ke penyimpanan bukti sebelum tertimpa ring buffer, beserta hash-nya (Day 01).

**Kapan gagal:** timeline disusun dari pcap saja, sehingga klien asli tidak pernah diketahui; atau disusun dari log saja, sehingga pertanyaan "apakah koneksi ke 4444 pernah tersambung" dijawab dengan tebakan. Pcap dan log saling melengkapi.

### 2.9 Satu halaman jawaban untuk Sari

Ringkasan ini kamu kirim ke Sari Rabu siang. Setiap baris merujuk subbagian di atas, supaya L1 bisa membaca alasannya.

| Pertanyaan Sari | Jawaban singkat | Dasar |
|---|---|---|
| Cara membaca TCP dan arti SYN selalu RST | Handshake, data, FIN; SYN yang dibalas RST berarti ditolak. Di kasus 4444, RST dibuat firewall (TTL 64, 1 ms), bukan server | Bagian 1.1, 1.2, 2.2 |
| Retransmission di Expert Info | 0,41% dan sebagian besar unduhan dari internet; celah urutan 98,5% ACKed unseen, jadi kapasitas capture `jkt-pcap01`. Bukan serangan, bukan link | Bagian 1.3, 2.1 |
| Workstation asli di mana | Pcap egress melihat proxy dan resolver; klien asli dari `index=proxy` dan `index=dns` lewat waktu dan tujuan | Bagian 1.4 |
| POST update-relay dan port 4444 | Satu host, dua kanal, satu tujuan, interval 60 dan 300 detik; menjadi `INC-2027-062` setelah EDR | Bagian 1.5, 1.10, 2.2, 2.3, 2.8 |
| TXT banyak | Mail gateway memeriksa SPF; banyak domain induk, nama pendek. Jinak; rule dikecualikan sempit | Bagian 1.6, 2.4 |
| HTTPS | SNI, versi terpilih, ALPN, cipher, alert; sertifikat hanya di TLS 1.2 | Bagian 1.7, 2.5 |
| FTP malam dan SMB | FTP jinak sebagai transfer, tetapi kredensial terpapar: pindah ke SFTP/FTPS. SMB internal tidak terlihat dari egress | Bagian 1.8, 1.9, 2.6, 2.7 |
| Peta pertanyaan ke protokol | Tabel pertanyaan, protokol, field, dan titik pandang | Bagian 1.11, 1.12 |

**Kapan gagal:** jawaban dikirim sebagai "aman" untuk SMB karena pcap egress tidak menemukan apa-apa. Yang benar adalah "tidak terlihat dari titik ini"; sensor data center (Day 08) yang akan menjawabnya.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** Wireshark 4.6.x dan tshark; Zeek di VM sensor lab (opsional, untuk langkah 8); pcap publik (unduh sendiri, cek lisensi) atau pcap lab yang kamu buat sendiri di jaringan host-only `192.168.56.0/24`; tidak ada pcap kerja. Jangan memakai data PT JAB; PT JAB hanya contoh fiktif.

1. **TCP.** Filter SYN murni dan reset (bagian 2.1). Cari pola (scan? koneksi normal?). Catat. Hitung `tcp.completeness` untuk 10 stream pertama dan cocokkan dengan tabel bagian 1.1.
2. **RST dan penolakan.** Dari VM klien, buka koneksi ke port tertutup di VM server lab, lalu ke port yang diblokir firewall VM (misalnya aturan reject dengan TCP reset). Bandingkan TTL dan jeda RST kedua kasus (bagian 2.2). Ulangi dengan aturan drop diam dan catat apa yang berubah.
3. **Retransmission dan capture loss.** Jalankan transfer besar antar VM sambil membatasi buffer capture di sisi sensor (misalnya buffer sangat kecil). Hitung `lost_segment`, `ack_lost_segment`, dan `retransmission` seperti bagian 2.1, lalu ulangi tanpa batas buffer. Catat flag mana yang naik karena capture, bukan karena jaringan.
4. **HTTP.** Ekstrak request dengan tshark (bagian 2.3). Stacking host dan method. Temukan POST berulang atau unduhan; follow satu stream.
5. **DNS.** Ekstrak query (bagian 2.4). Stacking tipe, domain induk, dan panjang. Cari query panjang/berulang. Bila VM lab punya resolver sendiri, bandingkan jumlah query klien dengan jumlah query keluar resolver.
6. **TLS.** Hitung ClientHello per SNI dan ServerHello per versi terpilih (bagian 2.5). Periksa apakah ada `tls.handshake.version == 0x0303` di sesi yang sebenarnya TLS 1.3.
7. **SMB.** Bila pcap punya SMB, filter akses share dan file (bagian 2.7). Catat akses admin share bila ada. Di lab, akses `ADMIN$` dari satu VM Windows ke VM lain dengan akun admin lokal lab, lalu cocokkan waktu TREE_CONNECT dengan event di VM tujuan.
8. **FTP.** Bila ada FTP, periksa STOR/RETR (bagian 2.6). Catat transfer (defang host). Hitung port data dari balasan 227. Bila tidak ada FTP di pcap publik, pasang server FTP di VM lab dengan akun uji, lakukan satu unggahan, dan pastikan kredensial uji terlihat di capture (lalu jangan dipakai lagi).
9. **Protokol aneh.** Cari port tak lazim (bagian 1.10 dan 2.2); periksa apakah dikenali. Pakai Decode As untuk protokol yang dikenal di port lain.
10. **Zeek offline.** Jalankan Zeek atas pcap yang sama dan bandingkan `conn_state` serta `history` dengan `tcp.completeness` untuk stream yang sama (bagian 1.1).
11. **Jawab pertanyaan.** Untuk pcap-mu, jawab: domain apa yang dihubungi, file apa yang ditransfer, adakah pola C2. Sebut sinyal vs kemungkinan jinak.

**Hasil yang sebaiknya tersimpan:**

- Pola TCP (scan/reset) diperiksa dan ditafsirkan, dengan nilai `tcp.completeness` per pola.
- Perbandingan RST dari server, dari firewall reject, dan efek drop diam (TTL, jeda, `conn_state`).
- Angka capture loss dengan dan tanpa batas buffer, plus satu kalimat kesimpulan flag mana yang menunjuk ke capture.
- HTTP request di-stacking; POST berulang atau unduhan ditemukan dan di-follow.
- DNS query di-stacking; anomali panjang/volume diperiksa; selisih klien vs resolver bila ada.
- Hitungan TLS per SNI dan per versi terpilih.
- SMB/FTP (bila ada) diperiksa untuk transfer dan akses share, dengan korelasi event host untuk SMB.
- Protokol di port tak lazim diperiksa.
- Pertanyaan investigasi dijawab dengan sinyal vs kemungkinan jinak.

**Variasi tantangan:** ambil satu pcap yang berisi campuran protokol dan buat ringkasan "sesi penting": untuk tiap sesi menarik, catat protokol, pasangan IP (defang), apa yang terjadi (transfer/query/koneksi), dan apakah sinyal mencurigakan dengan kemungkinan jinaknya. Ini melatih membaca pcap sebagai kumpulan cerita, bukan paket. Tambahkan satu timeline gabungan seperti bagian 2.8 yang memisahkan bukti paket dari bukti log.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat membaca protokol di pcap. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| HTTP tidak terlihat | Trafik TLS (terenkripsi) | Hanya metadata; lihat TLS SNI (bagian 2.5, Day 06) |
| Protokol tidak dikenali | Port tak standar; protokol kustom | Decode As; periksa byte mentah (Follow Stream) |
| Field `smb2` tidak ada | SMB1 atau versi field beda | Cek versi SMB; filter `smb` untuk SMB1; `smb2.dialect` untuk dialek |
| DNS query tidak muncul | Filter response, bukan query | `dns.flags.response == 0` untuk query |
| Filter `dns.resp.addr` tidak dikenal | Field lama (Wireshark 1.4 sampai 1.10) | Pakai `dns.a` dan `dns.aaaa` [S1] |
| Banyak retransmission | Masalah jaringan | Biasanya bukan ancaman; fokus protokol aplikasi; bandingkan counter interface |
| Banyak previous segment not captured dan ACKed unseen | Capture kehilangan paket (SPAN/buffer/disk sensor) | Bandingkan `lost_segment` dengan `ack_lost_segment`; cek statistik drop sensor (bagian 2.1) |
| Semua `tcp.analysis.*` kosong | Preferensi Analyze TCP sequence numbers mati | Aktifkan di preferensi protokol TCP [S7] |
| RST dari IP tujuan, tetapi TTL dan jedanya aneh | RST dibuat firewall atau IPS di dekat sensor | Bandingkan dengan paket lain dari IP yang sama; cek log firewall (bagian 2.2) |
| Query DNS tanpa response | UDP hilang, resolver tidak menjawab, atau routing asimetris | `dns.flags.response == 0 && !dns.response_in`; cek apakah sensor melihat dua arah |
| Semua sumber HTTP adalah proxy | Titik pandang sensor egress | Klien asli dari log proxy (bagian 1.4) |
| Zeek memberi `OTH` untuk sesi yang jelas TCP | Capture dimulai di tengah sesi | Wajar untuk cuplikan ring buffer; cari cuplikan sebelumnya |
| Zeek tidak menghasilkan log untuk sebagian koneksi | Checksum salah karena offloading | Jalankan dengan `-C` (bagian 2.2) |
| FTP tidak ada kredensial | FTPS/SFTP terenkripsi | Hanya metadata; FTP plaintext yang menampilkan kredensial |
| Koneksi data FTP tidak dikenali | Koneksi kontrol tidak tertangkap | Hitung port dari 227/PORT, lalu Decode As `ftp-data` |
| `tls.handshake.version` 0x0303 di semua sesi | Field legacy di TLS 1.3 | Baca `supported_version` di ServerHello (bagian 1.7) |

## 5. Kesalahan umum dan jebakan

- **Mengira TCP anomali (retransmission/reset) adalah ancaman.** Biasanya masalah jaringan, capture, atau kebijakan firewall (bagian 1.2, 1.3).
- **Membuka tiket gangguan link dari Expert Info.** Celah yang di-ACK tanpa retransmission adalah kehilangan di alat capture, bukan di link (bagian 2.1).
- **Menganggap RST berasal dari IP yang tertulis di header.** Firewall dan IPS bisa membuat RST atas nama tujuan; TTL dan jeda membantu membedakan.
- **Over-claim dari User-Agent atau DNS TXT.** Keduanya sinyal; sebut kemungkinan jinak (agen vendor, pemeriksaan SPF).
- **Mengabaikan konteks volume dan frekuensi.** Satu query/POST berbeda dari ratusan yang berulang.
- **Mengira sumber di pcap egress adalah klien asli.** Di jaringan dengan proxy eksplisit dan resolver internal, sumbernya adalah perantara (bagian 1.4).
- **Membandingkan jumlah query DNS di pcap egress dengan jumlah di log resolver.** Cache resolver membuat angka egress lebih kecil.
- **Menyebut "tidak ada SMB" sebagai "tidak ada lateral movement".** Pcap egress tidak melihat trafik internal.
- **Menyimpan kredensial plaintext** dari FTP/HTTP; catat keberadaan, bukan nilai.
- **Lupa protokol terenkripsi hanya metadata.** HTTP memberi isi; HTTPS memberi metadata (Day 06).
- **Memakai field dari cheat sheet lama tanpa cek.** Contoh: `dns.resp.addr` tidak ada di Wireshark 4.6 [S1].
- **Membaca `tls.handshake.version` sebagai versi TLS.** Di TLS 1.3 nilainya 0x0303 demi kompatibilitas [S9].
- **Menjumlahkan baris Expert Info.** Satu frame bisa membawa beberapa flag analisis (bagian 1.3).

## 6. Catatan terkini

Bagian ini menampung detail versi dan perubahan sumber yang berguna saat membuka dokumentasi, tetapi tidak mengubah langkah di atas.

- Protokol inti (TCP, HTTP, DNS, SMB, FTP) stabil; nama field Wireshark bisa berubah antar versi, terutama field protokol kompleks. Per 2026-10-22, rilis stabil Wireshark adalah 4.6.9 dan old stable 4.4.19 [S15]. Semua field di Day ini tercantum di display filter reference untuk rentang yang mencakup 4.6.9 [S1].
- `dns.resp.addr` hanya tercantum untuk Wireshark 1.4.0 sampai 1.10.14; field modernnya `dns.a` dan `dns.aaaa` [S1].
- RFC 9293 (2022) adalah spesifikasi TCP yang berlaku dan menggantikan RFC 793 [S3].
- TLS 1.3 diterbitkan ulang sebagai RFC 9846 (Juli 2026), menggantikan RFC 8446 dan juga RFC 5246 (TLS 1.2), dengan nomor versi tetap dan kompatibel ke belakang [S11].
- ATT&CK v20.0: T1571 Non-Standard Port versi 1.3, terakhir diubah 3 September 2026 [S6]; T1021.002 SMB/Windows Admin Shares versi 1.3, terakhir diubah 12 Mei 2026, dengan detection strategy DET0530 [S13].
- Zeek 9.0.0 adalah LTS terbaru (14 September 2026); definisi `conn_state` dan `history` di Day ini diambil dari dokumentasi `conn.log` [S8].
- HTTP dan FTP tanpa enkripsi semakin jarang; banyak trafik kini TLS (Day 06), sehingga metadata (SNI, sertifikat) makin penting, dan di TLS 1.3 sertifikat sudah tidak terlihat.
- SMB1 ditinggalkan karena risiko; kehadirannya sendiri bisa jadi temuan.
- Day 04 masuk ke pemindaian dan brute force; Day 05 ke anomali DNS dan HTTP.

## 7. Cheat sheet

```
TCP      tcp.flags.syn==1 and tcp.flags.ack==0 (SYN murni/scan) | tcp.flags.reset==1 | tcp.stream
         tcp.completeness: 1 SYN 2 SYN-ACK 4 ACK 8 DATA 16 FIN 32 RST ; 31 lengkap+FIN, 47 lengkap+RST, 33 ditolak
         TIME-WAIT = 2 x MSL = 4 menit (RFC 9293)
RST      server (jeda ~RTT, TTL cocok) | firewall/IPS (jeda kecil, TTL beda) | klien
ANALISIS retransmission/fast/spurious/dup_ack = jaringan ; lost_segment + ack_lost_segment tanpa retrans = capture
         jangan jumlahkan baris Expert Info ; cek "Analyze TCP sequence numbers"
ZEEK     conn_state S0 (tanpa balasan) REJ (ditolak) SF (normal) RSTO/RSTR (RST) OTH (tengah sesi)
         history: s h a d f r t w (huruf besar=originator, kecil=responder; contoh Sr = SYN lalu RST) ; zeek -C -r file.pcap
UDP/DNS  dns.flags.response==0 (query) | dns.qry.name | dns.qry.name.len | dns.qry.type==16 (TXT)
         dns.a / dns.aaaa (bukan dns.resp.addr) | dns.flags.rcode==3 (NXDOMAIN) | dns.id, dns.response_in, dns.time
         tipe: A1 NS2 CNAME5 SOA6 NULL10 PTR12 MX15 TXT16 AAAA28 ; label <=63, nama <=255
HTTP     http.request[.method=="POST"] | http.host | http.request.uri | http.user_agent | http.content_type
         http.content_length | http.response.code | Export Objects
TLS      tls.handshake.type==1 ClientHello / ==2 ServerHello | extensions_server_name (SNI)
         versi asli = extensions.supported_version di ServerHello (0x0304 = 1.3); version 0x0303 = legacy
         TLS 1.3: Certificate terenkripsi
SMB      smb2.cmd (3 TREE_CONNECT, 5 CREATE, 9 WRITE) | smb2.tree contains "C$"/"ADMIN$" (lateral, T1021.002)
         smb2.filename | smb2.dialect (0x0202..0x0311) | smb = SMB1 = risiko
FTP      ftp.request.command=="STOR"(unggah/exfil)/"RETR"(unduh) | 227 (h1,h2,h3,h4,p1,p2): port = p1*256+p2
         220 331 230 530 150 226 550 | kredensial plaintext (catat keberadaan, bukan nilai)
PORT     T1571 non-standard port ; Decode As ; Follow Stream untuk byte mentah
SENSOR   egress PT JAB: HTTP = proxy 10.20.3.60, DNS = resolver ; klien asli di index=proxy / index=dns
         SMB internal tidak lewat TAP egress
PETA     domain: DNS/HTTP/SNI | file: HTTP/SMB/FTP | scan: TCP SYN | C2: HTTP POST/DNS/port | lateral: SMB admin share
PRINSIP  sinyal != kesimpulan ; sebut kemungkinan jinak ; volume/frekuensi/tujuan ; terenkripsi = metadata saja
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Expert Info cuplikan pcap egress menunjukkan 1.906 previous segment not captured. Berarti link egress kehilangan 1.906 segmen dan NOC perlu membuka tiket gangguan." Benarkah?

<details><summary>Jawaban</summary>

Tidak. "Previous segment not captured" hanya berarti Wireshark tidak melihat segmen sebelumnya. Bila penerima kemudian meng-ACK byte di celah itu tanpa ada retransmission (`ack_lost_segment`), segmennya sampai ke penerima dan yang kehilangan adalah alat capture. Di cuplikan PT JAB, 1.877 dari 1.906 celah (98,5%) seperti itu, counter interface router 0 error, dan sensor mencatat drop di menit yang sama. Tindak lanjutnya kapasitas capture, bukan tiket link. Lihat bagian 1.3 dan 2.1.

</details>

**2. Skenario keputusan.** Di pcap egress, setiap SYN dari sebuah workstation ke `203.0.113.164:4444` dibalas RST dalam 1 ms dengan TTL 64, sedangkan SYN-ACK dari IP yang sama di port 80 tiba setelah 38 ms dengan TTL 49. Kesimpulan mana yang paling tepat?

- A. Server `203.0.113.164` aktif menolak koneksi di port 4444, jadi layanannya mati dan item ini bisa ditutup.
- B. RST kemungkinan besar dibuat perangkat di dekat sensor (firewall yang menolak dengan reset), jadi server tujuan tidak pernah menerima SYN; pola percobaan berulang itulah yang perlu dikejar, dikonfirmasi lewat log firewall.
- C. Penyerang memalsukan RST untuk memutus koneksi workstation.

<details><summary>Jawaban</summary>

B. Jeda 1 ms jauh lebih kecil dari round-trip ke server (38 ms), dan TTL 64 tidak cocok dengan TTL 49 dari paket asli server itu, jadi RST dibuat perangkat dekat sensor, yaitu firewall. A keliru karena server tidak pernah menerima SYN, sehingga status layanannya tidak diketahui, dan item tidak bisa ditutup hanya karena koneksi gagal. C keliru karena tidak ada bukti pihak luar; RST dari firewall cocok dengan log deny. TTL adalah heuristik, jadi konfirmasinya di log firewall. Lihat bagian 1.2 dan 2.2.

</details>

**3. Pertanyaan jebakan.** "Di pcap egress PT JAB, semua POST ke `update-relay.example` bersumber dari `10.20.3.60`. Berarti server proxy itu yang terinfeksi." Benarkah?

<details><summary>Jawaban</summary>

Tidak. `10.20.3.60` adalah `jkt-proxy01`, proxy eksplisit yang meneruskan request workstation. Dari titik pandang TAP egress, semua HTTP dan HTTPS kantor tampak bersumber dari proxy. Klien aslinya dicari di log proxy dengan mencocokkan waktu dan tujuan; di kasus ini `10.10.60.31` (`JKT-WS-2011`). Lihat bagian 1.4 dan 2.3.

</details>

**4. Skenario keputusan.** Rule DNS memicu alert karena query TXT naik menjadi sekitar 7,66% dari query keluar. Langkah mana yang paling tepat sebelum memutuskan?

- A. Langsung eskalasi sebagai DNS tunneling karena TXT sering dipakai tunneling.
- B. Matikan rule karena TXT dipakai banyak layanan sah.
- C. Hitung klien asli di log resolver, jumlah domain induk, dan panjang nama; bila sebagian besar dari mail gateway ke banyak domain berbeda dengan nama pendek, label jinak dan kecualikan secara sempit.

<details><summary>Jawaban</summary>

C. Tunneling dan pemakaian sah sama-sama memakai TXT, tetapi bentuknya berbeda: tunneling memakai banyak subdomain panjang di bawah satu domain induk, sedangkan pemeriksaan SPF memakai banyak domain pengirim yang berbeda. A keliru karena satu sinyal (tipe record) bukan kesimpulan. B keliru karena mematikan rule menghilangkan deteksi untuk tunneling sungguhan; pengecualian sempit untuk satu klien dan satu bentuk pola sudah cukup. Lihat bagian 1.6 dan 2.4.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Bambang Hartono (Manajer NOC), dalam tiga kalimat, kenapa pcap egress `jkt-pcap01` tidak bisa memastikan ada atau tidaknya lateral movement lewat SMB.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "TAP `jkt-pcap01` dipasang di link antara core switch dan firewall, jadi ia hanya melihat trafik yang keluar dan masuk internet, mirip titik ekspor NetFlow yang hanya di uplink. SMB antar workstation atau dari workstation ke server berjalan di dalam jaringan dan tidak pernah lewat link itu, sehingga nol paket SMB di egress hanya berarti tidak ada SMB ke internet. Untuk melihat lateral movement kita butuh sensor di segmen data center atau antar zona, ditambah log host seperti pembuatan service di host tujuan."

Kesalahan yang sering muncul:
- Mengatakan "pcap tidak menemukan SMB, jadi aman".
- Lupa menyebut apa yang dibutuhkan untuk menutup celah itu (sensor lain dan log host).
- Menjelaskan SMB secara detail, padahal pertanyaannya tentang posisi sensor.

</details>

**6. Pertanyaan jebakan.** "Di ServerHello, `tls.handshake.version` bernilai 0x0303, jadi server ini masih memakai TLS 1.2 dan sertifikatnya pasti bisa dibaca di pcap." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Di TLS 1.3, field versi legacy tetap diisi 0x0303 demi kompatibilitas dengan middlebox; versi yang sebenarnya dipilih ada di ekstensi `supported_versions` (0x0304 untuk TLS 1.3). Bila server memilih TLS 1.3, pesan Certificate dienkripsi dan tidak terbaca di pcap. Lihat bagian 1.7 dan 2.5.

</details>

**7. Interview question (English).** "You open a pcap and Wireshark's Expert Information shows thousands of retransmissions and resets. How do you decide whether this is a security issue?"

<details><summary>Sample answer</summary>

"I first treat retransmissions and resets as transport mechanics, not as findings. For retransmissions I check direction and concentration, and I compare 'previous segment not captured' with 'ACKed unseen segment': if the receiver acknowledged data the capture never saw, the loss is in the sensor, so I check the sensor's drop counters and the router interface counters before anyone opens a link ticket. For resets I ask who sent them: a reset that arrives in one millisecond with a TTL that doesn't match other packets from that address was most likely generated by a nearby firewall, which I confirm in its log. Only then do I look at what the connections were used for: who talked to whom through which port, how regularly, and with which application fields. A workstation retrying the same non-standard port every sixty seconds is interesting because of the pattern and destination, not because of the resets. I always write the benign explanation next to each signal and corroborate with proxy, DNS or endpoint data before calling anything malicious."

What makes this answer strong: it separates capture artefacts, network behaviour and policy enforcement from attacker behaviour, uses concrete Wireshark fields and a TTL comparison instead of guesswork, and ends with corroboration rather than a verdict from packets alone.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Wireshark Display Filter Reference (tcp, dns, http, tls, smb2, ftp) | https://www.wireshark.org/docs/dfref/ | primer | diakses 2026-10-09 (Day 02), dicek ulang 2026-10-22 | Tinggi. Field per protokol, rentang versi sampai 4.6.9; `dns.resp.addr` hanya 1.4.0 sampai 1.10.14 |
| S2 | RFC 9110 (HTTP semantics) | https://www.rfc-editor.org/rfc/rfc9110 | primer | diakses 2026-10-09 | Tinggi. Method, header, status |
| S3 | RFC 9293 (TCP) | https://www.rfc-editor.org/rfc/rfc9293 | primer | 2022; diakses 2026-10-09, dicek ulang 2026-10-22 | Tinggi. Handshake, ISN (3.4.1), MSL 2 menit (3.4.2), aturan RST (3.5.2, 3.5.3), TIME-WAIT 2xMSL (3.6.1); menggantikan RFC 793 |
| S4 | RFC 1035 dan pembaruan (DNS) | https://www.rfc-editor.org/rfc/rfc1035 | primer | diakses 2026-10-09, dicek ulang 2026-10-22 | Tinggi. Tipe record (3.2.2), RCODE (4.1.1), batas label/nama/UDP |
| S5 | Microsoft SMB protocol documentation (MS-SMB2), termasuk SMB2 Packet Header dan SMB2 NEGOTIATE Request | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/ | primer | diakses 2026-10-09, dicek ulang 2026-10-22 | Tinggi. Operasi SMB2, kode command, nilai dialek |
| S6 | MITRE ATT&CK T1571: Non-Standard Port | https://attack.mitre.org/techniques/T1571/ | primer | diakses 2026-10-10, dicek ulang 2026-10-22 | Tinggi. Definisi teknik port non-standar; v1.3, diubah 2026-09-03, ATT&CK v20.0 |
| S7 | Wireshark User's Guide: TCP Analysis | https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html | primer | diakses 2026-10-22 | Tinggi. Kondisi tiap flag `tcp.analysis.*`, preferensi analisis, nilai conversation completeness |
| S8 | Zeek documentation: base/protocols/conn/main.zeek (`conn.log`) | https://docs.zeek.org/en/master/scripts/base/protocols/conn/main.zeek.html | primer | diakses 2026-10-22 | Tinggi. Nilai `conn_state` dan huruf `history`; dokumentasi cabang master |
| S9 | RFC 8446 (TLS 1.3) | https://www.rfc-editor.org/rfc/rfc8446 | primer | 2018-08; diakses 2026-10-22 | Tinggi. Isi ClientHello/ServerHello (4.1.2, 4.1.3), handshake terenkripsi setelah ServerHello (1.2, 2), `supported_versions` (4.2.1). Kini digantikan RFC 9846 |
| S10 | RFC 3596 (DNS Extensions to Support IPv6) | https://www.rfc-editor.org/rfc/rfc3596 | primer | 2003-10; diakses 2026-10-22 | Tinggi. Nilai tipe AAAA 28 (2.1) |
| S11 | RFC 9846 (The Transport Layer Security (TLS) Protocol Version 1.3) | https://www.rfc-editor.org/rfc/rfc9846 | primer | 2026-07; diakses 2026-10-22 | Tinggi. Menggantikan RFC 8446 dan RFC 5246; versi tetap, kompatibel ke belakang |
| S12 | RFC 7208 (Sender Policy Framework) | https://www.rfc-editor.org/rfc/rfc7208 | primer | diakses 2026-10-22 | Tinggi. SPF wajib dipublikasikan sebagai TXT tipe 16 (3.1) |
| S13 | MITRE ATT&CK T1021.002: Remote Services: SMB/Windows Admin Shares | https://attack.mitre.org/techniques/T1021/002/ | primer | diakses 2026-10-22 | Tinggi. v1.3, diubah 2026-05-12; DET0530 mengorelasikan akses ADMIN$/C$ dengan aktivitas di host tujuan |
| S14 | RFC 959 (File Transfer Protocol) | https://www.rfc-editor.org/rfc/rfc959 | primer | 1985-10; diakses 2026-10-22 | Tinggi. Perintah, kode balasan, format PORT/PASV, koneksi kontrol dan data |
| S15 | Wireshark: Download | https://www.wireshark.org/download.html | primer | diakses 2026-10-22 | Tinggi. Rilis stabil 4.6.9 dan old stable 4.4.19; tanggal rilis tidak tercantum di halaman |

**Catatan sumber:** field protokol mengikuti display filter reference Wireshark dan RFC; semua field yang dipakai di Day ini dicek ada untuk rentang versi yang mencakup 4.6.9 [S1]. RFC dipakai untuk struktur protokol, dengan nomor bagian di tabel bila tersedia. Nilai `tcp.completeness` 33 untuk SYN yang dibalas RST dihitung dari definisi bit [S7], bukan dari contoh di dokumentasi; cek tampilannya di lab. Heuristik TTL dan jeda untuk menebak pengirim RST, serta nilai awal TTL per sistem operasi, adalah praktik analisis jaringan yang tidak diambil dari sumber primer di tabel ini; uji di lab sebelum dipakai sebagai argumen di laporan. Format keluaran tshark untuk `tcp.flags` (jumlah digit heksadesimal) dan format `frame.time` bisa berbeda antar versi. Kemungkinan paket ganda dari dua titik capture ditandai sebagai retransmission belum dikonfirmasi sumber primer dan perlu dicek di lab. Seluruh isi PT JAB (lima item `SOC-2027-0610` sampai `-0614`, `INC-2027-062`, host, IP, angka, dan timeline) adalah penerapan catatan ini pada organisasi fiktif, bukan hasil eksekusi nyata. Sinyal forensik adalah pengetahuan NSM mapan; kemungkinan jinak selalu disebut.
