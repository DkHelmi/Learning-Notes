---
day: 04
title: 'Pemindaian dan brute force dari trafik: tipe scan, sweep vertikal dan horizontal, brute force vs spray, dan scanner jinak'
researched_on: 2026-10-22
versions_checked: 'Wireshark/tshark 4.6.9 (stabil; 4.4.19 old stable), display filter reference ftp/ssh/tcp 4.6.9, editcap/mergecap/dumpcap man page 4.6.9; Nmap 7.992 (changelog 2026-10-15); MITRE ATT&CK v20.0 (13 Okt 2026): T1595 v1.0 (24 Okt 2025), T1046 v3.2 (12 Mei 2026), T1110 v2.8 (12 Mei 2026), T1110.001 v1.7 (12 Mei 2026), T1110.003 v1.8 (24 Okt 2025); nfdump 1.7.10 (man page); RFC 959, RFC 4253, RFC 9293, RFC 792; Censys Opt Out (diperbarui 2026-03-24) dan Scanning FAQ (diperbarui 2025-12-09)'
---

# Day 04: Pemindaian dan brute force dari trafik (tipe scan, sweep, brute force vs spray, dan scanner jinak)

Cakupan: mengenali jejak pemindaian port dan percobaan login berulang dari pcap, log firewall, dan flow, mengukur cakupan dan hasilnya, membedakan brute force dari password spraying, dan memisahkan penyerang dari scanner riset internet atau alat internal yang sah, semuanya dari sudut deteksi dan investigasi.

## Ide inti

Pemindaian dan brute force adalah dua aktivitas paling berisik di internet, sehingga yang sulit bukan menemukannya, tetapi menjawab tiga pertanyaan sesudahnya: apa yang berhasil dipelajari atau didapat penyerang, apakah ini penyerang atau scanner yang sah, dan sensor mana yang sebenarnya melihat kejadian itu. Setiap tipe scan memancing respons yang berbeda dari target, dan respons itulah yang dibaca di pcap: SYN-ACK berarti port terbuka, RST berarti tertutup, diam berarti terfilter. Untuk login berulang, protokol plaintext (FTP, HTTP basic) memperlihatkan kode gagal dan berhasil, sedangkan protokol terenkripsi (SSH, VPN TLS) hanya memperlihatkan bentuk koneksinya, sehingga kesimpulan "berhasil login" selalu butuh log host atau aplikasi. Bentuk itu juga yang membedakan brute force (banyak percobaan ke sedikit akun) dari password spraying (sedikit percobaan ke banyak akun, sering dari banyak sumber). Day ini tidak membahas cara melakukan scan atau brute force; semuanya dari sisi yang menerima trafik.

Kamu sudah mengenal pola ini dari NOC. NMS melakukan auto-discovery dengan menyapu subnet manajemen setiap malam: ping dan SNMP ke setiap alamat, lalu mencatat perangkat yang menjawab. Dari sisi trafik, sweep itu sama persis dengan horizontal scan penyerang; yang membuatnya sah adalah sumbernya dikenal, jadwalnya tetap, dan pemiliknya jelas. Hal yang sama berlaku untuk login: puluhan `Authentication failed` TACACS dari satu alamat ke satu router adalah brute force, sedangkan satu kegagalan di masing-masing dari dua ratus router dari banyak alamat adalah pola yang tidak akan pernah memicu alarm per perangkat. Batas analoginya: auto-discovery NMS tidak berusaha bersembunyi, sedangkan penyerang sengaja membagi percobaan ke banyak sumber dan waktu supaya tetap di bawah ambang; dan berbeda dengan counter router, setiap sensor hanya melihat trafik yang lewat di titiknya.

```
 internet: 203.0.113.166 (scan + login FTP/SSH), 203.0.113.167 (scanner riset), 37 IP spray VPN
      |
 [router edge] -- flow 1:1000 --> jkt-flow01   scan 2.000 probe 1 paket -> rata-rata ~2 paket tersampel
      |       \
      |        [jkt-vpn01] 198.51.100.20   (sejajar firewall; login VPN TIDAK lewat TAP egress)
      |
 [jkt-fw01]  log deny/allow ke index firewall   melihat semua 1.000 port yang di-probe
      |      DNAT 198.51.100.204 -> 10.20.9.45
 TAP egress (sisi dalam) --> jkt-npb01 --> jkt-pcap01   hanya melihat probe yang DIIZINKAN firewall
      |
 [core switch DC] --> DMZ 10.20.9.0/24: jkt-dmz-ftp01 10.20.9.45 (FTP 21, SSH 22, HTTPS 443)
      |
 [router DC] -- flow 1:1 --> jkt-flow01   melihat sweep kantor ke data center (JKT-WS-2017)
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif di Jakarta yang sedang menjalankan "Program NSM PT JAB" (percobaan Mei sampai Juli 2027). Pada tahap ini Zeek dan Suricata belum hidup; yang tersedia adalah ring buffer `jkt-pcap01` (uji coba sejak Selasa 2027-05-04, TAP egress Jakarta di sisi dalam firewall `jkt-fw01`, target retensi 72 jam), log firewall, log VPN, log server di Splunk, dan flow NOC di `jkt-flow01`. Server FTP lama `jkt-dmz-ftp01` (`10.20.9.45`, alamat publik `198.51.100.204`) dipakai teknisi lapangan dan mitra instalasi untuk mengambil firmware ONT (modem fiber pelanggan) dan jadwal instalasi. Kamis malam 2027-05-06 sampai Jumat pagi 2027-05-07 muncul lima alert:

- `SOC-2027-0615` (Kamis 22:15): rule port scan firewall, `203.0.113.166` ke `198.51.100.204`.
- `SOC-2027-0616` (Kamis 22:51): rule "lebih dari 100 FAIL LOGIN FTP per sumber per jam" di `jkt-dmz-ftp01`, sumber `203.0.113.166`. Shift malam memberinya prioritas P3 dan mencatat "brute force gagal, tidak ada login berhasil".
- `SOC-2027-0617` (Jumat 02:03): rule sweep firewall, `203.0.113.167` menyentuh hampir semua alamat `198.51.100.0/24`.
- `SOC-2027-0618` (Jumat 07:02): rule "lebih dari 100 login VPN gagal per jam (total)" di `jkt-vpn01`.
- `SOC-2027-0619` (Jumat 08:24): dibuat manual atas laporan Bambang Hartono (Manajer NOC): flow router data center menunjukkan `JKT-WS-2017` (`10.10.60.43`) menyentuh port 445 di 1.024 alamat data center.

Jumat 2027-05-07 pukul 08:45, SOC lead Dimas Prasetyo menulis kepadamu:

> "Semalam ramai, dan ini minggu pertama pcap kita jalan, jadi tolong pakai. Pertama, scan dari .166 ke server FTP itu scan apa, dan port apa saja yang dia temukan? Aneh, firewall bilang dia coba seribu port, tapi pcap katanya cuma belasan paket, terus flow NOC hampir kosong. Mana yang benar? Kedua, dia juga mencoba login FTP ribuan kali; shift malam bilang gagal semua, betul? Kalau ada yang berhasil, apa yang diambil? Ketiga, SSH di server yang sama juga dicoba, apakah ada yang tembus, padahal isinya terenkripsi? Keempat, Sari lihat login VPN gagal ratusan pagi ini dari banyak IP, tapi rule brute force per IP kita diam saja. Itu spray? Kelima, .167 menyapu semua IP publik kita, dan laptop JKT-WS-2017 menyapu port 445 ke data center. Dua-duanya perlu insiden atau tidak? Terakhir, siapkan ringkasan untuk Pak Hendra: apa yang sebenarnya hilang atau terbuka."

Pesan itu memuat enam pertanyaan:

1. Tipe scan apa yang dilakukan `203.0.113.166`, dan port apa yang ia temukan terbuka?
2. Kenapa firewall, pcap, dan flow memberi angka yang sangat berbeda untuk scan yang sama?
3. Apakah brute force FTP gagal semua, dan bila ada yang berhasil, apa yang diambil?
4. Bagaimana menilai brute force SSH yang isinya terenkripsi?
5. Apakah kegagalan login VPN pagi ini password spraying, dan kenapa rule per IP tidak menangkapnya?
6. Apakah sweep `203.0.113.167` dan `JKT-WS-2017` perlu dijadikan insiden, dan apa dampak keseluruhan malam itu?

Pertanyaan 1 dijawab di bagian 1.1 dan 1.2, pertanyaan 2 di bagian 1.3, pertanyaan 3 di bagian 1.4 dan 1.7, pertanyaan 4 di bagian 1.5, pertanyaan 5 di bagian 1.4, dan pertanyaan 6 di bagian 1.6 dan 1.7. Bagian 2 memakai data malam itu: memotong ring buffer, membaca log firewall, filter dan perintah tshark untuk scan, sweep, UDP, FTP, SSH, analisis spray VPN, pemisahan scanner sah, lalu timeline `INC-2027-063` dan satu halaman jawaban untuk Dimas.

**Kapan relevan:** saat ada alert scan atau login gagal dari firewall, server, atau VPN; saat perlu mengukur apa yang dipetakan penyerang dan apakah scan diikuti login atau eksploitasi; saat memutuskan apakah sebuah sweep berasal dari penyerang, scanner riset, atau alat internal; dan saat menjelaskan kenapa angka antar sensor berbeda.
**Kapan bukan jawaban:** saat pertanyaannya "akun mana yang berhasil dibobol" di protokol terenkripsi, karena jawabannya ada di log autentikasi, bukan di paket; saat scan berasal dari ribuan sumber yang masing-masing hanya mengirim satu probe, karena pola per sumber tidak terlihat dari satu titik; dan saat trafiknya tidak lewat sensor (login VPN di `jkt-vpn01`, trafik antar workstation di switch akses yang sama).

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day 01 sampai 03 (pcap, flow, SPAN, TAP, ring buffer, display filter, handshake TCP, flag TCP) tidak diulang. Tabel ini hanya memuat istilah yang baru dipakai di Day ini.

| Istilah | Arti singkat | Padanan di NOC/ISP |
|---|---|---|
| Port scan | Mengirim probe ke banyak port untuk mengetahui layanan apa yang menjawab | `show ip interface brief` dari luar: siapa saja yang "up" |
| SYN scan (half-open) | Kirim SYN, baca balasan, lalu reset tanpa menyelesaikan handshake | Ping ke alamat tanpa membuka sesi manajemen |
| Connect scan | Handshake penuh lalu ditutup; aplikasi target sempat melihat koneksi | Login telnet yang langsung diputus |
| FIN/NULL/Xmas scan | Probe dengan kombinasi flag tidak lazim untuk memancing respons berbeda | Paket uji dengan header aneh untuk melihat perilaku ACL |
| UDP scan | Probe UDP; port tertutup dijawab ICMP port unreachable | Uji SNMP ke perangkat yang tidak membalas |
| ACK scan | Probe ACK untuk memetakan aturan firewall, bukan layanan | Uji jalur ACL stateless vs stateful |
| Port state | Hasil yang disimpulkan dari respons: open, closed, filtered, unfiltered, open\|filtered, closed\|filtered | Status interface up/down/admin-down |
| Vertical scan | Satu sumber ke banyak port di satu host | Mengecek semua layanan di satu router |
| Horizontal sweep | Satu sumber ke satu atau beberapa port di banyak host | Auto-discovery NMS yang menyapu satu subnet |
| Banner grabbing | Membuka koneksi untuk membaca identitas layanan (banner SSH, sertifikat TLS) | Membaca `show version` dari prompt login |
| Brute force (password guessing) | Banyak percobaan password ke satu atau sedikit akun | Banyak `Authentication failed` TACACS ke satu router |
| Password spraying | Satu atau sedikit password dicoba ke banyak akun agar tidak memicu lockout | Satu password default dicoba sekali di setiap router |
| Credential stuffing | Pasangan username dan password bocor dari layanan lain dicoba di layanan target | Kredensial perangkat dari vendor yang bocor dicoba di semua POP |
| Lockout | Akun dikunci setelah N kegagalan | Port-security yang mematikan port setelah pelanggaran |
| Research scanner | Organisasi yang memindai seluruh internet untuk riset atau layanan pencarian eksposur | Looking glass atau route collector publik: mengamati semua orang, bukan menyerang |
| DNAT | Firewall menerjemahkan alamat tujuan publik ke alamat internal | Static NAT di router CPE pelanggan korporat |
| `tcp.completeness` | Field Wireshark berupa bitmask yang merangkum tahap koneksi TCP yang terlihat | Ringkasan status sesi BGP: Idle, Active, Established |

### 1.1 Tipe pemindaian port dan respons yang dibaca

Pertanyaan pertama Dimas ("scan apa") dijawab dengan membaca respons, bukan probe. Probe dari scanner mana pun selalu tampak sama: banyak paket kecil ke banyak port. Yang membedakan tipe scan adalah flag yang dipakai dan apa yang dikirim scanner setelah target menjawab.

Tabel berikut adalah ringkasan perilaku yang didokumentasikan Nmap, scanner open source yang perilakunya dijadikan acuan umum [S6]. Baca kolom "Pola paket" sebagai apa yang kamu cari di pcap, dan kolom "Catatan" untuk tahu kapan pola itu menyesatkan.

| Tipe | Pola paket | Catatan |
|---|---|---|
| SYN scan (half-open) | SYN keluar; SYN-ACK (port terbuka) atau RST (tertutup); scanner mengirim RST, tidak menyelesaikan handshake | Umum; cepat; tidak membuka koneksi penuh |
| Connect scan | Handshake penuh (SYN, SYN-ACK, ACK) lalu RST/FIN | Membuka koneksi penuh; lebih terlog |
| FIN/NULL/Xmas scan | Paket dengan flag tidak lazim (FIN saja, tanpa flag, FIN+PSH+URG) | Mencoba menghindari deteksi; respons bergantung OS |
| UDP scan | Paket UDP; ICMP port unreachable (tertutup) atau tidak ada respons (terbuka/terfilter) | Lambat; andalkan ICMP |
| ACK scan | Paket ACK; untuk memetakan firewall rule | Respons RST menunjukkan tidak difilter |

Sinyal umum semua scan: satu sumber mengirim ke banyak port/host dalam waktu singkat, dengan banyak koneksi tidak selesai atau RST.

Respons diterjemahkan menjadi port state. Nmap memakai enam state, dan nama-nama ini akan kamu temui di laporan scanner internal maupun di write-up insiden [S7]:

- **open:** ada aplikasi yang menerima koneksi di port itu.
- **closed:** port bisa dijangkau dan menjawab, tetapi tidak ada aplikasi yang mendengarkan.
- **filtered:** filter (firewall, ACL router, firewall host) menghalangi probe, sehingga tidak bisa dipastikan terbuka atau tidak. Filter lebih sering membuang probe diam-diam daripada membalas ICMP error [S7].
- **unfiltered:** port bisa dijangkau tetapi tidak bisa dipastikan terbuka atau tertutup; hanya dipakai ACK scan [S7].
- **open|filtered:** tidak bisa dibedakan antara terbuka dan terfilter, terjadi bila port terbuka memang tidak membalas tipe probe itu (UDP, FIN/NULL/Xmas) [S7].
- **closed|filtered:** hanya dipakai idle scan [S7].

Detail respons per tipe yang berguna saat membaca pcap [S6]:

- SYN scan: SYN-ACK berarti open; RST berarti closed; tanpa respons setelah beberapa kali kirim ulang, atau ICMP unreachable type 3 code 0, 1, 2, 3, 9, 10, atau 13, berarti filtered.
- UDP scan: ICMP port unreachable (type 3 code 3) berarti closed; ICMP unreachable code lain (0, 1, 2, 9, 10, 13) berarti filtered; balasan UDP berarti open; tanpa respons berarti open|filtered.
- FIN/NULL/Xmas: RST berarti closed; tanpa respons berarti open|filtered. Windows, banyak perangkat Cisco, BSDI, dan IBM OS/400 mengirim RST apa pun state port-nya, sehingga semua port tampak closed [S6]. Bila kamu melihat FIN scan ke server Windows dan semua dijawab RST, itu bukan berarti tidak ada layanan.
- Connect scan: lebih mungkin tercatat di target daripada SYN scan, karena banyak layanan Unix menulis syslog saat koneksi dibuka lalu ditutup tanpa data [S6].

Dua angka membantu mengenali scan otomatis. Nmap secara default memindai 1.000 port paling umum per protokol [S8], sehingga satu sumber yang menyentuh tepat sekitar 1.000 port TCP berbeda dalam satu menit adalah ciri konfigurasi default. Port yang tidak menjawab dikirim ulang beberapa kali karena scanner tidak bisa membedakan probe yang dibuang dari kemacetan jaringan [S7]; akibatnya jumlah paket selalu lebih besar daripada jumlah port. Hitung port unik, bukan paket.

Untuk scan dari `203.0.113.166`: probe berupa SYN tanpa ACK, port terbuka menjawab SYN-ACK, dan scanner langsung mengirim RST. Itu SYN scan, dan bagian 2.4 menunjukkan paketnya.

### 1.2 Sweep vertikal, horizontal, dan maksud di baliknya

Bagian kedua pertanyaan pertama Dimas adalah "apa yang dicari". Arah scan menjawabnya, dan arah itu juga yang menjadi pembeda pertama antara `203.0.113.166`, `203.0.113.167`, dan `JKT-WS-2017`.

Tabel ini memetakan bentuk scan ke maksud yang paling mungkin. Baca kolom "Tujuan penyerang" sebagai hipotesis, bukan kesimpulan.

| Jenis | Pola | Tujuan penyerang |
|---|---|---|
| Vertikal (port scan) | Satu host sumber ke banyak port pada satu host tujuan | Memetakan layanan di satu host |
| Horizontal (sweep) | Satu host sumber ke satu port pada banyak host tujuan | Mencari host dengan layanan tertentu (mis. SMB 445) di subnet |
| Blok | Banyak port banyak host | Pemetaan luas |

Membedakannya menentukan maksud: vertikal berarti penyerang fokus pada satu target; horizontal berarti mencari target dengan kerentanan tertentu di seluruh jaringan. Conversations dan Endpoints (Day 02) memperlihatkan pola ini [S5].

ATT&CK memisahkan scan menurut posisi pelakunya, dan pemisahan ini berguna saat menulis laporan:

- **T1595 Active Scanning** (taktik Reconnaissance) adalah scan dari luar terhadap infrastruktur korban lewat trafik jaringan, dengan sub-teknik T1595.001 Scanning IP Blocks, T1595.002 Vulnerability Scanning, dan T1595.003 Wordlist Scanning [S11]. ATT&CK mencatat teknik ini sulit dicegah dengan kontrol preventif dan menyarankan meminimalkan data yang terpapar ke luar [S11]. Scan `203.0.113.166` dan sweep `203.0.113.167` masuk ke sini.
- **T1046 Network Service Discovery** (taktik Discovery) adalah pencarian daftar layanan di host lain dari dalam lingkungan, biasanya dengan port scan atau vulnerability scan dari alat yang dibawa ke sistem [S12]. Salah satu analitik deteksinya memakai NetFlow atau pcap untuk menangkap koneksi cepat ke banyak layanan atau host [S12]. Sweep port 445 dari `JKT-WS-2017` ke data center berbentuk T1046, walaupun pelakunya belum tentu penyerang (bagian 1.6).

Untuk PT JAB: `203.0.113.166` adalah vertikal (1.000 port ke satu alamat), `203.0.113.167` horizontal ke luar (tiga port ke 254 alamat), dan `JKT-WS-2017` horizontal ke dalam (satu port ke 1.024 alamat). Bentuk yang sama, posisi dan pelaku berbeda, sehingga keputusannya juga berbeda.

### 1.3 Mengenali scan di pcap, firewall, dan flow

Pertanyaan kedua Dimas ("firewall seribu port, pcap belasan paket, flow hampir kosong, mana yang benar?") jawabannya: ketiganya benar untuk titik observasinya masing-masing. Ini konsep terpenting Day ini, karena setiap angka di laporan harus menyebut dari sensor mana angka itu berasal.

Sinyal di Wireshark:

- Banyak SYN dari satu sumber ke port berurutan atau banyak host (`tcp.flags.syn == 1 and tcp.flags.ack == 0`).
- Banyak RST (port tertutup) atau SYN-ACK (terbuka) sebagai respons.
- Koneksi yang tidak diselesaikan (SYN tanpa data).
- Waktu antar-paket sangat rapat (scan otomatis cepat).
- Statistics Conversations: satu sumber dengan sangat banyak pasangan (port/host).

Cara mengukur cakupan: dari Conversations atau tshark, hitung berapa port/host unik yang disentuh sumber, dan mana yang merespons terbuka (SYN-ACK). Port terbuka adalah yang penyerang temukan.

Wireshark juga merangkum tahap setiap koneksi TCP di field `tcp.completeness`, bitmask dengan nilai 1 (SYN), 2 (SYN-ACK), 4 (ACK), 8 (DATA), 16 (FIN), dan 32 (RST) [S15]. Nilai 7 berarti hanya three-way handshake; 31, 47, atau 63 berarti koneksi lengkap dengan data [S15]. Dari bitmask itu, koneksi SYN scan ke port terbuka bernilai 1 + 2 + 32 = 35, ke port tertutup 1 + 32 = 33, dan connect scan yang ditutup dengan RST 1 + 2 + 4 + 32 = 39. Tiga nilai turunan ini dihitung dari definisi bit, bukan dari dokumentasi; cek di lab bahwa Wireshark versi-mu menghitung RST dari kedua arah.

Posisi sensor menentukan berapa banyak scan yang terlihat. Tabel berikut adalah tiga titik observasi PT JAB untuk scan yang sama; baca kolom "Yang terlihat" dan "Yang tidak terlihat" sebelum membandingkan angka.

| Titik | Sumber | Yang terlihat | Yang tidak terlihat |
|---|---|---|---|
| Router edge | Flow `jkt-flow01`, sampling 1:1000 | Sekitar satu dari seribu paket; scan besar terlihat sebagai beberapa record kecil | Hampir semua probe satu paket; periodisitas; isi |
| Firewall `jkt-fw01` | Log allow/deny, index `firewall` | Setiap probe yang sampai firewall, termasuk yang dibuang, dengan port tujuan | Isi, balasan server, apa yang terjadi setelah koneksi diizinkan |
| TAP egress sisi dalam | pcap `jkt-pcap01` | Hanya probe yang diizinkan firewall, setelah DNAT, beserta balasan server dan isi plaintext | Probe yang dibuang firewall; trafik yang tidak lewat firewall (login VPN) |

Akibatnya untuk scan `203.0.113.166`: firewall mencatat 1.000 port, pcap hanya melihat empat port yang diizinkan aturan (21, 22, 80, 443) beserta balasannya, dan flow edge hampir kosong karena sampling. Sampling 1:1000 berarti sekitar 2.000 probe satu paket menghasilkan rata-rata sekitar 2 paket tersampel; probabilitas satu probe tertentu tercatat hanya 0,1%. Hitungan ini adalah aritmetika peluang sederhana, bukan perilaku vendor tertentu; cara sampling setiap router (acak atau deterministik per N paket) perlu dicek di konfigurasi exporter.

Satu sumber tidak cukup. Firewall menjawab "seberapa lebar scan-nya", pcap menjawab "apa yang dijawab server dan apa yang terjadi sesudahnya", dan flow router data center (1:1, tanpa sampling) menjawab pertanyaan internal seperti sweep `JKT-WS-2017`. Kalimat untuk laporan: "tidak ada di pcap" berarti "tidak sampai ke TAP", bukan "tidak terjadi".

### 1.4 Brute force, password spraying, dan kode respons

Pertanyaan ketiga dan kelima Dimas sama-sama soal login berulang, tetapi bentuknya berlawanan. FTP semalam dicoba ribuan kali ke empat akun; VPN pagi ini dicoba dua kali ke ratusan akun dari puluhan alamat.

Brute force mencoba banyak kredensial pada satu akun/layanan; password spray mencoba sedikit kata sandi umum pada banyak akun, sengaja pelan agar tidak memicu penguncian akun. ATT&CK mencatat keduanya di bawah T1110 Brute Force (spray sebagai T1110.003) [S3]. Perbedaan bentuknya penting untuk deteksi: brute force terlihat sebagai banyak kegagalan untuk satu akun dalam waktu singkat, sedangkan spray terlihat sebagai sedikit kegagalan per akun tetapi banyak akun berbeda dari satu sumber.

T1110 di ATT&CK v20 punya empat sub-teknik: T1110.001 Password Guessing, T1110.002 Password Cracking (offline, terhadap hash yang sudah dicuri), T1110.003 Password Spraying, dan T1110.004 Credential Stuffing [S3]. Untuk analis jaringan, yang terlihat di kabel hanya tiga: guessing, spraying, dan stuffing; cracking terjadi di mesin penyerang. Beberapa catatan dari halaman ATT&CK:

- Password guessing bisa memicu kegagalan berulang dan lockout, bergantung kebijakan organisasi [S14]. Analitik deteksinya menyebut pola kegagalan SSH berulang yang diikuti login berhasil dari host yang sama [S14]. Pola itu persis yang dicari di FTP semalam.
- Password spraying mencoba satu atau sedikit password umum ke banyak akun untuk menghindari lockout [S13]. Analitiknya mencari banyak kegagalan dengan satu atau sedikit password ke banyak identitas dalam jendela singkat, dan mengingatkan bahwa penyerang bisa menahan laju percobaan [S13].
- Layanan yang sering diincar menurut kedua halaman: SSH (22/TCP), Telnet (23/TCP), FTP (21/TCP), NetBIOS/SMB (139 dan 445/TCP), LDAP (389/TCP), Kerberos (88/TCP), RDP (3389/TCP), HTTP management (80 dan 443/TCP), MSSQL (1433/TCP), Oracle (1521/TCP), MySQL (3306/TCP), VNC (5900/TCP); halaman password guessing menambahkan SNMP (161/UDP dan 162/TCP/UDP) [S13][S14]. Port di daftar ini adalah prioritas saat membaca hasil scan: port terbuka yang ada di daftar itu cenderung didatangi lagi.
- Halaman T1110 mencatat VPN dan perangkat edge sebagai sasaran brute force oleh beberapa kelompok [S3].

Tabel berikut adalah jejak brute force per protokol di pcap. Baca kolom "Jejak" untuk filter yang dipakai di bagian 2.

| Protokol | Jejak |
|---|---|
| FTP (plaintext) | Banyak USER/PASS, banyak response 530 (login gagal) |
| HTTP (plaintext/basic) | Banyak POST ke login, banyak 401/403 atau redirect |
| SMB | Banyak session setup gagal (`STATUS_LOGON_FAILURE`) |
| SSH (terenkripsi) | Banyak koneksi singkat ke port 22, tidak ada isi (hanya pola) |
| RDP | Banyak koneksi ke 3389 |

Sinyal: banyak upaya autentikasi dalam waktu singkat dari satu sumber. Untuk protokol plaintext, respons gagal terlihat; untuk terenkripsi (SSH), hanya pola koneksi (banyak sesi pendek ke port 22) yang terlihat, bukan isi.

Kode respons FTP yang perlu dihafal berasal dari RFC 959 [S9]: 220 layanan siap untuk user baru; 331 username diterima, password dibutuhkan; 230 user logged in; 530 not logged in; 150 status file oke, koneksi data akan dibuka; 226 koneksi data ditutup setelah aksi file berhasil; 550 aksi tidak dilakukan, file tidak tersedia (misalnya tidak ada akses); 421 layanan ditutup. RFC 959 tidak mendefinisikan enkripsi untuk kanal kontrol, sehingga argumen `PASS` lewat sebagai teks biasa kecuali implementasinya menambah proteksi [S9]. Konsekuensinya etis, bukan hanya teknis: password yang dicoba penyerang, termasuk password yang benar, terbaca di pcap. Catat keberadaannya, jangan nilainya.

Ringkasan bentuk yang membedakan pola di PT JAB:

- FTP semalam: satu sumber, empat akun, sekitar 578 percobaan per akun. Itu brute force (password guessing).
- VPN pagi ini: 37 sumber, 206 akun, dua percobaan per akun. Itu password spraying yang sekaligus terdistribusi, sehingga rule "gagal per IP" dan "gagal per akun" sama-sama diam. Sinyalnya hanya muncul bila dihitung per populasi akun dalam satu jendela waktu (bagian 2.9).
- Credential stuffing akan tampak seperti spraying (sedikit percobaan per akun), tetapi pasangan username dan password-nya berbeda per akun dan tingkat keberhasilannya lebih tinggi. Bedanya baru terlihat bila log aplikasi mencatat apakah username ada, bukan dari jaringan.

### 1.5 Brute force terenkripsi: membaca pola, bukan isi

Pertanyaan keempat Dimas ("SSH juga dicoba, apa ada yang tembus?") tidak bisa dijawab dari isi paket. Yang bisa dibaca adalah bentuk koneksi dan sedikit metadata yang dikirim sebelum enkripsi.

SSH brute force tidak menampilkan kredensial (terenkripsi), tetapi meninggalkan pola koneksi:

- Banyak koneksi TCP ke port 22 dari satu sumber dalam waktu singkat.
- Tiap koneksi pendek (login gagal lalu putus).
- Tidak ada sesi panjang (yang berarti login berhasil dan interaktif).

Membedakan brute force berhasil: setelah banyak koneksi pendek, satu koneksi yang panjang (banyak data, durasi lama) bisa menandakan login berhasil. Ini sinyal; konfirmasinya di log host, yaitu baris `Accepted password` atau `Accepted publickey` dari `sshd` untuk sumber dan jam yang sama.

Ada satu hal yang tetap terbaca: identification string. RFC 4253 mewajibkan kedua sisi mengirim string berformat `SSH-protoversion-softwareversion SP comments CR LF`, maksimal 255 karakter termasuk CR dan LF, saat koneksi dibuka, dan key exchange baru dimulai setelahnya [S10]. Karena string itu dikirim sebelum enkripsi berlaku, Wireshark menampilkannya di field `ssh.protocol` [S1][S10]. Wireshark 3.6 ke atas juga menghitung fingerprint HASSH dari key exchange klien dan server (`ssh.kex.hassh`, `ssh.kex.hasshserver`) [S1]. Dua hal ini memberi indikator otomasi: 148 sesi dengan string klien yang identik dan berbeda dari klien OpenSSH yang dipakai admin PT JAB. Itu indikator, bukan identitas alat; banyak alat sah memakai pustaka SSH yang sama.

Batas pola untuk kesimpulan "berhasil":

- Login berbasis kunci bisa berhasil dan langsung menjalankan satu perintah singkat, sehingga sesinya pendek. Sesi pendek tidak membuktikan gagal.
- Sesi panjang bisa berarti login berhasil, tetapi juga bisa berarti server lambat menutup koneksi, atau klien sengaja menahan koneksi. Sesi panjang tidak membuktikan berhasil.
- Kesimpulan selalu dari log autentikasi: `sshd` di `/var/log/auth.log` atau index `linux`, log VPN, atau log aplikasi.

Untuk VPN TLS berlaku hal yang sama dengan satu perbedaan di PT JAB: `jkt-vpn01` tersambung sejajar firewall, sehingga sesi login VPN tidak lewat TAP egress. Untuk spray pagi ini, pcap tidak punya apa pun; buktinya hanya log VPN dan flow edge yang tersampel.

### 1.6 Membedakan dari aktivitas sah

Pertanyaan kelima Dimas memasangkan dua sweep yang bentuknya mirip penyerang. Keputusan untuk keduanya diambil dari identitas dan konteks sumber, karena pola paketnya sama.

Banyak pola scan juga muncul pada aktivitas sah:

- Vulnerability scanner internal (Nessus, Qualys) melakukan scan sah terjadwal.
- Monitoring/health check menyentuh banyak port/host.
- Load balancer dan discovery tool membuat banyak koneksi.

Karena itu, scan yang dikenali harus ditimbang: apakah sumbernya scanner sah yang diketahui? Apakah terjadwal? Apakah dari dalam atau luar? Scan dari IP eksternal tak dikenal ke layanan sensitif lebih mencurigakan daripada scanner internal terjadwal. Nyatakan kemungkinan jinak (Day 01-03).

**Scanner riset internet.** Beberapa organisasi memindai seluruh ruang alamat IPv4 terus-menerus untuk riset atau layanan pencarian eksposur. Censys adalah contoh yang mendokumentasikan dirinya dengan baik: scan berjalan terus, layanan yang lebih tua dari 24 jam dipindai ulang setiap hari, dan Censys menyatakan tidak pernah mencoba login, mengakses database, atau memperoleh akses terautentikasi [S20]. Censys menerbitkan daftar subnet pemindai (16 rentang IPv4 /24 dan 4 rentang IPv6) dan tiga ASN, memakai user agent HTTP yang memuat `CensysInspect/1.1`, dan menyediakan cara opt-out dengan membuang trafik dari subnet itu di firewall [S19]. Daftarnya berubah: halaman opt-out diperbarui Maret 2026 setelah scan datang dari rentang yang sebelumnya belum diterbitkan [S19]. Opt-out tidak menghapus data historis, dan Censys mengingatkan bahwa memblokir bisa membuatmu kehilangan peringatan tentang sistem rentan [S19].

Ciri yang dicek untuk menilai apakah sebuah sweep berasal dari scanner riset:

1. Alamat ada di daftar yang diterbitkan organisasi itu, dicek dari halaman resminya pada hari kejadian, bukan dari salinan forum.
2. Reverse DNS menunjuk domain organisasi itu, dan forward lookup nama tersebut kembali ke alamat yang sama.
3. Perilaku sesuai pernyataan: satu sentuhan per port per alamat, banner grabbing, tanpa percobaan login, tanpa payload exploit.
4. Pola berulang dengan jadwal yang konsisten di log firewall minggu sebelumnya.

Bila keempatnya terpenuhi, sweep itu kebisingan latar (noise), bukan insiden. Keputusan memblokir atau tidak adalah keputusan kebijakan, bukan keharusan. Yang lebih berguna adalah membaca ulang apa yang mereka lihat: bila scanner riset melihat SSH terbuka di server FTP, penyerang mana pun juga melihatnya.

**Alat internal.** PT JAB punya pemindai kerentanan resmi `jkt-vscan01` (`10.20.10.61`) milik tim Agung Prabowo, yang memindai subnet kantor setiap Senin dini hari dan seluruh data center sebulan sekali. Sweep dari workstation biasa seperti `JKT-WS-2017` tidak cocok dengan daftar itu. Keputusan untuk sweep internal punya tiga kemungkinan, dan yang membedakannya adalah konteks host dan orangnya, bukan paket:

| Kemungkinan | Ciri | Tindak lanjut |
|---|---|---|
| Insiden (T1046 oleh penyerang) | Proses tidak dikenal, akun tidak lazim, didahului alert lain di host itu, diikuti koneksi ke port yang terbuka | Investigasi host, buka insiden |
| Pelanggaran kebijakan | Orang yang sah menjalankan alat atau skrip tanpa tiket perubahan, dari host yang bukan pemindai resmi | Konfirmasi ke orang dan atasannya, catat, minta diulang dari `jkt-vscan01` dengan tiket |
| Jinak terjadwal | Sumber dan jadwal ada di daftar aset dan kalender | Tutup, perbarui allowlist dengan batas sempit (alamat, jam, port) |

### 1.7 Mengukur dampak

Pertanyaan terakhir Dimas ("apa yang sebenarnya hilang atau terbuka") adalah alasan semua analisis di atas. Laporan "ada scan dan brute force" tidak membantu Hendra; laporan "penyerang menemukan FTP dan SSH terbuka, masuk ke satu akun FTP mitra, dan mengunduh satu file berisi data pelanggan" membantu.

Setelah mengenali scan, ukur apa yang penyerang pelajari:

- Port/layanan apa yang merespons terbuka (SYN-ACK).
- Host mana yang hidup (merespons).
- Apakah scan diikuti koneksi ke port terbuka (eksploitasi atau akses lanjut).

Ini mengubah "ada scan" menjadi "penyerang menemukan X terbuka dan lalu melakukan Y", yang jauh lebih bernilai untuk investigasi dan respons.

Untuk login berulang, dampak diukur dengan tiga pertanyaan berurutan:

1. Apakah ada login berhasil? Di FTP, cari 230 dari server setelah rangkaian 530. Di SSH dan VPN, cari di log autentikasi.
2. Bila berhasil, apa yang dilakukan dalam sesi itu? Di FTP plaintext, perintah `LIST`, `RETR` (unduh), `STOR` (unggah), dan `DELE` terbaca beserta kode responsnya. Unduhan dianggap terjadi bila ada `RETR` yang diikuti 150 dan 226, bukan hanya `RETR`.
3. Bila tidak ada yang berhasil, apakah ada akun yang password-nya benar tetapi diblokir lapisan lain (misalnya MFA)? Akun itu sudah bocor password-nya walaupun belum dimasuki.

Kesimpulan dampak selalu dipisahkan dari indikator. "Ada `RETR` dan 226 untuk file X sebesar N byte" adalah bukti dari pcap; "data pelanggan bocor" adalah kesimpulan yang butuh konfirmasi isi file dari pemiliknya dan dinilai bersama DPO. Kewajiban pelindungan data pribadi dibahas umum di Day 01 bagian 1.7.

## 2. Contoh dan langkah praktis: malam scan dan pagi spray di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi; angka dihitung ulang supaya konsisten satu sama lain. Analisis pcap dilakukan di workstation analisis `jkt-nsm-ws01` (`10.20.70.20`, Wireshark/tshark 4.6.x, akses read-only ke `jkt-pcap01`), dengan zona waktu WIB. Untuk latihan, jalankan versi yang disesuaikan di lab pribadi (bagian 3). IOC ditulis memakai rentang dokumentasi; filter yang bergantung versi disebut.

### 2.1 Memotong ring buffer ke jendela kejadian

Sebelum filter apa pun, data malam itu harus diselamatkan dari ring buffer. `jkt-pcap01` memutar file sekitar 1 GB dengan nama `egress-jkt_NNNNN_YYYYMMDDHHMMSS.pcapng`; dumpcap menamai file ring buffer dengan nomor urut lima digit dan waktu pembuatan file [S17]. Pada malam hari laju egress sekitar 11 MB/s, sehingga satu file 1 GB mencakup sekitar 89 detik dan jendela Kamis 22:00 sampai Jumat 02:00 (14.400 detik) tersebar di sekitar 162 file.

**Tujuan:** membuat satu file kasus berisi semua paket dari dan ke `203.0.113.166` dan `203.0.113.167` di jendela kejadian, sebelum file aslinya tertimpa.

```bash
mkdir -p /cases/inc-2027-063/slice
for f in /pcap/egress-jkt_*_2027050622*.pcapng /pcap/egress-jkt_*_2027050623*.pcapng \
         /pcap/egress-jkt_*_2027050700*.pcapng /pcap/egress-jkt_*_2027050701*.pcapng \
         /pcap/egress-jkt_*_2027050702*.pcapng; do
  tshark -r "$f" -Y "ip.addr == 203.0.113.166 or ip.addr == 203.0.113.167" \
         -w "/cases/inc-2027-063/slice/$(basename "$f")"
done
mergecap -w /cases/inc-2027-063/inc063-merged.pcapng /cases/inc-2027-063/slice/*.pcapng
editcap -A "2027-05-06 22:00:00+07:00" -B "2027-05-07 03:00:00+07:00" \
        /cases/inc-2027-063/inc063-merged.pcapng /cases/inc-2027-063/inc063-ext.pcapng
sha256sum /cases/inc-2027-063/inc063-ext.pcapng > /cases/inc-2027-063/inc063-ext.sha256
```

Tabel berikut menjelaskan tiap bagian.

| Bagian | Fungsi |
|---|---|
| Glob `_2027050622*` dan seterusnya | Memilih file dari timestamp di nama file; file yang dibuat 21:59 bisa berisi paket 22:00, jadi ambil satu file sebelum batas bila perlu |
| `tshark -r ... -Y ... -w` | Membaca satu file, menyaring dengan display filter, dan menulis hanya paket yang cocok |
| `mergecap -w` | Menggabungkan file secara kronologis berdasarkan timestamp; tanpa `-a`, urutan file masukan tidak penting [S16] |
| `editcap -A ... -B ...` | Memotong ke jendela waktu: `-A` inklusif (pada atau setelah), `-B` eksklusif (sebelum). Format ISO 8601 boleh diberi zona waktu; tanpa zona, dianggap waktu lokal [S16] |
| `sha256sum` | Hash file kasus untuk rantai bukti |

Keluaran ilustrasi (`capinfos` atas file hasil):

```
File name:           /cases/inc-2027-063/inc063-ext.pcapng
Number of packets:   48 k
File size:           31 MB
First packet time:   2027-05-06 22:14:03.118
Last packet time:    2027-05-07 02:41:37.904
```

**Cara membaca hasil:** paket pertama 22:14:03 cocok dengan log firewall untuk awal scan, dan paket terakhir 02:41:37 cocok dengan akhir sweep `203.0.113.167`. File kasus 31 MB jauh lebih kecil dari 162 GB data mentah, dan tidak akan tertimpa.

**Variasi:** untuk kasus yang hanya butuh satu protokol, tambahkan syarat port di filter (`and tcp.port == 21`), atau buat file terpisah per alamat supaya file kasus tidak mencampur dua pelaku.

**Kapan gagal:** display filter `ip.addr` membuang paket IPv6 dan paket ICMP error yang memuat alamat penyerang hanya di header dalam; zona waktu tidak disebut sehingga editcap memotong tujuh jam meleset di mesin ber-UTC; atau ring buffer sudah menimpa file yang dibutuhkan karena lonjakan trafik (Day 01 bagian 1.6 menjelaskan kenapa target 72 jam bukan jaminan).

### 2.2 Lebar scan dari log firewall

Query ini menjawab bagian "firewall bilang seribu port" dari pertanyaan kedua. Log firewall adalah satu-satunya sumber PT JAB yang melihat probe yang dibuang.

**Tujuan:** menghitung port unik, alamat tujuan, aksi firewall, dan rentang waktu scan `203.0.113.166`.

**Asumsi data:** log `jkt-fw01` di `index=firewall` dengan field gaya CIM Network Traffic (`src_ip`, `dest_ip`, `dest_port`, `transport`, `action`); `dest_ip` adalah alamat publik sebelum DNAT. Cek nama field di parsing firewall-mu.

```
index=firewall src_ip=203.0.113.166
    earliest="05/06/2027:22:00:00" latest="05/07/2027:03:00:00"
| stats count AS events dc(dest_port) AS ports dc(dest_ip) AS hosts
        min(_time) AS first max(_time) AS last
        BY src_ip transport action
| eval first=strftime(first,"%F %T"), last=strftime(last,"%F %T")
| sort transport action
```

| Bagian | Fungsi |
|---|---|
| `earliest=... latest=...` | Rentang absolut, supaya angka di laporan bisa diulang |
| `stats ... BY src_ip transport action` | Memisahkan TCP dan UDP, serta yang diizinkan dan dibuang |
| `dc(dest_port)` | Port unik: ukuran scan yang sebenarnya, bukan jumlah paket |
| `dc(dest_ip)` | Satu alamat berarti vertikal; banyak alamat berarti horizontal |

Keluaran ilustrasi:

```
src_ip          transport action   events ports hosts first               last
203.0.113.166   tcp       allowed    926     7     1 2027-05-06 22:14:05 2027-05-07 01:52:40
203.0.113.166   tcp       blocked   1992   996     1 2027-05-06 22:14:03 2027-05-06 22:14:41
203.0.113.166   udp       blocked    200   100     1 2027-05-06 22:15:02 2027-05-06 22:16:10
```

**Cara membaca hasil:**

- Baris `blocked` TCP: 996 port dibuang, masing-masing dua kali (996 kali 2 sama dengan 1.992 event), dalam 38 detik. Probe kedua adalah kiriman ulang untuk port yang tidak menjawab (bagian 1.1).
- Baris `allowed` TCP mencampur dua hal: empat probe scan ke port yang diizinkan aturan (21, 22, 80, 443) dan semua koneksi brute force sesudahnya. Bila dipecah per `dest_port` (variasi di bawah), port 21 punya 772 koneksi, port 22 punya 149, port 80 dan 443 masing-masing 1, dan tiga port pasif FTP di rentang 40000 sampai 40100 masing-masing 1 koneksi data (satu `LIST` dan dua `RETR`, bagian 2.7). 772 + 149 + 1 + 1 + 3 = 926 event, dan 4 + 3 = 7 port unik.
- Total port TCP unik yang di-probe saat scan: 996 dibuang ditambah 4 diizinkan, sama dengan 1.000. Angka bulat itu cocok dengan konfigurasi default 1.000 port paling umum [S8].
- Baris UDP: 100 port, semua dibuang, masing-masing dua kali.

**Variasi:** `| stats count dc(dest_port) BY dest_port action` untuk memecah baris `allowed`; ganti `src_ip` dengan `dest_ip=198.51.100.204` dan `stats dc(src_ip)` untuk melihat apakah malam itu ada sumber lain yang memindai server yang sama.

**Kapan gagal:** firewall tidak mencatat deny untuk aturan default (implicit deny tanpa log), sehingga baris `blocked` kosong dan scan tampak kecil; log firewall menulis alamat sesudah DNAT di `dest_ip` sehingga query dengan alamat publik kosong; atau rule scan firewall memakai ambang per detik sehingga scan lambat tidak pernah tercatat sebagai alert walaupun event deny-nya ada.

### 2.3 Mengenali SYN scan di pcap

Filter ini membaca empat probe yang sampai ke TAP dan menjawab pertanyaan pertama Dimas: tipe scan.

**Tujuan:** menampilkan SYN awal dari penyerang dan menghitung target per sumber.

```
tcp.flags.syn == 1 and tcp.flags.ack == 0
```

Dengan tshark, hitung target per sumber:

```
tshark -r capture.pcap -Y "tcp.flags.syn==1 and tcp.flags.ack==0" -T fields -e ip.src -e ip.dst -e tcp.dstport
```

- Arahkan ke stacking: satu sumber dengan banyak `tcp.dstport` unik ke satu `ip.dst` = vertikal; banyak `ip.dst` pada satu port = horizontal.
- Cara membaca: ratusan SYN dari satu sumber ke port berurutan dalam detik adalah scan otomatis. Bandingkan jumlah dengan lalu lintas normal.

Versi PT JAB, dengan stacking langsung di shell untuk seluruh file kasus:

```bash
tshark -r /cases/inc-2027-063/inc063-ext.pcapng \
  -Y "ip.src == 203.0.113.166 and tcp.flags.syn == 1 and tcp.flags.ack == 0" \
  -T fields -e ip.dst -e tcp.dstport | sort | uniq -c | sort -rn
```

| Bagian | Fungsi |
|---|---|
| `ip.src == 203.0.113.166` | Hanya SYN dari penyerang |
| `tcp.flags.syn == 1 and tcp.flags.ack == 0` | SYN awal (bukan SYN-ACK) [S1][S2] |
| `-T fields -e ip.dst -e tcp.dstport` | Hanya kolom tujuan dan port, dipisah tab |
| `sort \| uniq -c \| sort -rn` | Stacking: hitung kombinasi, terbanyak di atas |

Keluaran ilustrasi:

```
    772 10.20.9.45	21
    149 10.20.9.45	22
      1 10.20.9.45	80
      1 10.20.9.45	443
      1 10.20.9.45	40017
      1 10.20.9.45	40052
      1 10.20.9.45	40088
```

**Cara membaca hasil:**

- Tujuan sudah `10.20.9.45`, bukan `198.51.100.204`, karena TAP di sisi dalam firewall melihat paket setelah DNAT. Saat mencocokkan dengan log firewall, pakai kedua alamat.
- Hanya empat port layanan yang muncul, ditambah tiga port pasif FTP yang dibuka untuk transfer data di sesi yang berhasil (bagian 2.7). Dari pcap saja, scan ini tampak seperti empat koneksi; lebarnya (1.000 port) hanya ada di log firewall (bagian 2.2).
- 772 SYN ke port 21 dan 149 ke port 22 adalah satu probe scan ditambah 771 koneksi brute force FTP dan 148 koneksi brute force SSH. Stacking seluruh malam mencampur scan dan brute force; pisahkan dengan jendela waktu (variasi).

**Variasi:** potong ke jendela scan dengan `-Y "... and frame.time >= \"2027-05-06 22:14:00\" and frame.time < \"2027-05-06 22:15:00\""`, atau buat file terpisah dengan `editcap -A/-B`. Untuk horizontal, ganti kolom menjadi `-e tcp.dstport -e ip.dst` lalu hitung `ip.dst` unik per port.

**Kapan gagal:** scan sangat lambat (satu probe per beberapa menit) tidak tampak "rapat" dan baru terlihat dalam jendela berjam-jam; atau sumber scan berganti-ganti alamat sehingga stacking per sumber tidak pernah menunjukkan jumlah besar.

### 2.4 Port terbuka vs tertutup: hasil scan

Langkah ini mengubah "ada scan" menjadi "ini yang ditemukan penyerang", bagian kedua pertanyaan pertama Dimas.

**Tujuan:** menampilkan balasan server untuk probe scan dan tipe scan dari perilaku scanner setelah SYN-ACK.

```
tcp.flags.syn == 1 and tcp.flags.ack == 1
tcp.flags.reset == 1
```

- SYN-ACK (`syn==1 and ack==1`) dari target = port terbuka (target merespons). RST = tertutup.
- Cara membaca: filter SYN-ACK dari target scan untuk melihat port apa yang terbuka, yaitu yang penyerang temukan. Ini "hasil" scan.

Keluaran ilustrasi (tshark SYN-ACK, contoh lab):

```
ip.src(target)  tcp.srcport
10.0.0.5        22
10.0.0.5        80
10.0.0.5        445
```

Target 10.0.0.5 punya port 22, 80, 445 terbuka, yang ditemukan scan.

Versi PT JAB untuk jendela scan, menampilkan setiap paket dengan flag-nya:

```bash
editcap -A "2027-05-06 22:14:00+07:00" -B "2027-05-06 22:15:00+07:00" \
        /cases/inc-2027-063/inc063-ext.pcapng /cases/inc-2027-063/scan-166.pcapng
tshark -r /cases/inc-2027-063/scan-166.pcapng -Y "tcp" -t ad \
  -T fields -e frame.time -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport \
  -e tcp.flags.str -e tcp.completeness
```

Field `tcp.flags.str` menampilkan flag sebagai teks, dan `tcp.completeness` merangkum tahap koneksi (bagian 1.3) [S1][S15]. Keluaran ilustrasi (kolom waktu diringkas):

```
22:14:05.204  203.0.113.166 51244  10.20.9.45    21    ··········S·  35
22:14:05.205  10.20.9.45    21     203.0.113.166 51244 ·······A··S·  35
22:14:05.231  203.0.113.166 51244  10.20.9.45    21    ·········R··  35
22:14:11.870  203.0.113.166 51244  10.20.9.45    22    ··········S·  35
22:14:11.871  10.20.9.45    22     203.0.113.166 51244 ·······A··S·  35
22:14:11.896  203.0.113.166 51244  10.20.9.45    22    ·········R··  35
22:14:19.552  203.0.113.166 51244  10.20.9.45    80    ··········S·  33
22:14:19.553  10.20.9.45    80     203.0.113.166 51244 ·······A·R··  33
22:14:27.019  203.0.113.166 51244  10.20.9.45    443   ··········S·  35
22:14:27.020  10.20.9.45    443    203.0.113.166 51244 ·······A··S·  35
22:14:27.046  203.0.113.166 51244  10.20.9.45    443   ·········R··  35
```

**Cara membaca hasil:**

- Port 21, 22, dan 443 dijawab SYN-ACK: open. Port 80 dijawab RST-ACK: closed (aturan firewall mengizinkannya, tetapi tidak ada layanan yang mendengarkan).
- Setelah SYN-ACK, penyerang langsung mengirim RST tanpa ACK. Itu tanda SYN scan (half-open); connect scan akan mengirim ACK dulu dan bernilai `tcp.completeness` 39, bukan 35.
- Port sumber yang sama (51244) untuk semua probe adalah ciri lain scan otomatis; klien biasa memakai port sumber berbeda per koneksi.
- Total 11 paket: empat SYN, tiga SYN-ACK, satu RST-ACK, tiga RST dari penyerang. Itu "belasan paket" yang membingungkan Dimas.
- Hasil scan untuk penyerang: FTP (21), SSH (22), dan HTTPS (443) terbuka di `198.51.100.204`. Dua di antaranya ada di daftar layanan yang sering diincar brute force (bagian 1.4), dan dalam 22 menit berikutnya keduanya memang didatangi.

**Variasi:** `tcp.completeness == 35` menampilkan semua sesi half-open ke port terbuka dalam file; `tcp.completeness == 33` menampilkan probe ke port tertutup. Untuk scan besar di lab, `tshark -q -z conv,tcp` memberi satu baris per pasangan socket dengan durasi, dan ribuan baris berdurasi milidetik adalah scan.

**Kapan gagal:** SYN-ACK datang dari perangkat di depan server (load balancer, proxy SYN, atau firewall dengan SYN proxy) sehingga semua port tampak terbuka; atau RST dikirim firewall atas nama server (aturan "reject") sehingga "closed" sebenarnya "filtered". Cocokkan TTL dan MAC sumber balasan dengan paket lain dari server untuk tahu siapa yang menjawab.

### 2.5 Sweep horizontal: dari luar dan dari dalam

Dua sweep di pertanyaan kelima Dimas dibaca dari sumber yang berbeda: sweep `203.0.113.167` dari firewall dan pcap, sweep `JKT-WS-2017` dari flow router data center.

**Filter dasar (pcap):**

```
tcp.flags.syn == 1 and tcp.flags.ack == 0 and tcp.dstport == 445
```

- Satu port (445 SMB) ke banyak host: sweep mencari SMB di subnet.
- Dengan tshark, hitung `ip.dst` unik untuk port itu dari satu sumber. Banyak host = sweep horizontal.
- Cara membaca: penyerang mencari layanan tertentu (SMB, RDP) di seluruh jaringan; port yang disweep menunjukkan apa yang mereka incar.

**Sweep `203.0.113.167` di log firewall.** Query bagian 2.2 dengan `src_ip=203.0.113.167` memberi keluaran ilustrasi:

```
src_ip          transport action   events ports hosts first               last
203.0.113.167   tcp       allowed      2     2     1 2027-05-07 02:00:05 2027-05-07 02:41:37
203.0.113.167   tcp       blocked    757     3   253 2027-05-07 02:00:05 2027-05-07 02:41:37
```

**Cara membaca:** tiga port (22, 443, 8443) ke 253 alamat, tanpa kiriman ulang. Scanner menyapu `198.51.100.1` sampai `.254` (254 alamat kali 3 port sama dengan 762 probe); 253 alamat lewat firewall, karena `198.51.100.20` milik `jkt-vpn01` yang sejajar firewall. 253 kali 3 sama dengan 759 event: 757 dibuang dan 2 diizinkan (`198.51.100.204` port 22 dan 443). Laju sekitar 759 event dalam 2.492 detik, kira-kira satu probe setiap 3,3 detik: pelan dan rata, tidak seperti scan `203.0.113.166` yang 1.000 port dalam 38 detik.

**Sweep `203.0.113.167` di pcap.** Dua koneksi yang diizinkan sampai ke TAP:

```bash
tshark -r /cases/inc-2027-063/inc063-ext.pcapng -Y "ip.addr == 203.0.113.167" -q -z conv,tcp
```

Keluaran ilustrasi (kolom diringkas):

```
TCP Conversations
                                         <-  Frames Bytes  ->  Frames Bytes  Total  Rel Start   Duration
10.20.9.45:22   <-> 203.0.113.167:40112      6    1402        7     918       13    13771.34    0.6123
10.20.9.45:443  <-> 203.0.113.167:40188      8    5236        8    1044       16    15244.17    0.5810
```

**Cara membaca:** masing-masing satu koneksi kurang dari satu detik. Di port 22, `ssh.protocol` menunjukkan klien mengirim identification string lalu menutup koneksi setelah menerima banner server, tanpa key exchange lengkap; di port 443, ada TLS ClientHello tanpa SNI (scanner menyapa alamat, bukan nama), lalu koneksi ditutup setelah sertifikat server diterima. Itu banner grabbing, bukan percobaan login. User agent HTTP yang dikirim di dalam TLS tidak terlihat di pcap; yang terlihat hanya di access log server HTTPS `jkt-dmz-ftp01` (bagian 2.10).

**Sweep `JKT-WS-2017` di flow router data center.** Trafik kantor ke data center tidak lewat TAP egress, tetapi lewat router data center yang mengekspor flow tanpa sampling. Bambang menjalankan nfdump di `jkt-flow01`; contoh di bawah mengasumsikan kolektor menyimpan file nfcapd per router di `/flow/dc-rtr/`, jadi cek path dan nama router di kolektor NOC.

```bash
nfdump -R /flow/dc-rtr/2027/05/07/ -t 2027/05/07.08:00:00-2027/05/07.08:30:00 \
  -A srcip,dstport 'src ip 10.10.60.43 and proto tcp and dst port 445 and flags S and not flags AFRPU'
nfdump -R /flow/dc-rtr/2027/05/07/ -t 2027/05/07.08:00:00-2027/05/07.08:30:00 \
  -s srcip/flows -n 5 'dst ip 10.10.60.43 and proto tcp and src port 445 and flags S and flags A'
```

| Bagian | Fungsi |
|---|---|
| `-R <dir>` | Membaca semua file di direktori itu [S18] |
| `-t YYYY/MM/dd.hh:mm:ss-...` | Jendela waktu (sintaks lama yang masih didukung; versi baru menyarankan filter `first seen` dan `last seen`) [S18] |
| `-A srcip,dstport` | Agregasi per sumber dan port tujuan, sehingga keluarannya satu baris ringkasan [S18] |
| `flags S and not flags AFRPU` | Flow yang hanya berisi SYN: percobaan koneksi tanpa jawaban di arah itu [S18] |
| `-s srcip/flows -n 5` | Statistik per sumber, diurutkan jumlah flow [S18] |
| `src port 445 ... flags S and flags A` | Flow balik dari host yang menjawab SYN-ACK: SMB terbuka |

Keluaran ilustrasi (diringkas):

```
Date first seen          Duration  Proto  Src IP Addr:Port   Dst Port  Packets  Bytes   Flows
2027-05-07 08:05:12.410  876.402   TCP    10.10.60.43:0      445       1024     53248   1024

Top 5 Src IP Addr ordered by flows:
Src IP Addr      Flows
10.20.8.15         1
10.20.8.16         1
...
Summary: total flows: 61
```

**Cara membaca:** 1.024 flow SYN-only dari `10.10.60.43` ke port 445, satu paket per flow (53.248 byte dibagi 1.024 sama dengan 52 byte per SYN), selama sekitar 876 detik (08:05:12 sampai 08:19:48), ke `10.20.8.0/22`. Hanya 61 alamat menjawab SYN-ACK. Ini sweep horizontal ke dalam: satu port, banyak host. Bentuknya T1046; siapa pelakunya ditentukan di bagian 2.10.

Perhatikan cara flow mencatat flag: nfdump mencocokkan bila salah satu flag yang disebut ada, dan flag satu flow adalah gabungan semua paketnya [S18]. Pada sampling 1:1 seperti router data center, SYN-only berarti tidak ada balasan di flow arah itu; pada sampling 1:1000 di edge, SYN-only hanya berarti paket lain tidak tersampel.

**Kapan gagal:** sweep horizontal yang dibagi ke banyak sumber (setiap sumber hanya beberapa host) tidak tampak dari stacking per sumber; sweep lewat ARP atau ICMP di segmen yang sama tidak lewat router sama sekali; atau flow router menggabungkan semua SYN dari satu sumber karena aggregation cache sehingga jumlah flow tidak sama dengan jumlah host.

### 2.6 UDP dan scan dengan flag tak lazim

Bagian ini menjelaskan baris UDP di log firewall (100 port dibuang) dan apa yang seharusnya dicari di pcap.

```
icmp.type == 3 and icmp.code == 3
tcp.flags == 0x000
(tcp.flags.fin == 1 and tcp.flags.syn == 0 and tcp.flags.ack == 0)
```

- ICMP type 3 code 3 (port unreachable) sebagai respons UDP = port UDP tertutup; scan UDP mengandalkan ini [S4][S6].
- `tcp.flags == 0x000` adalah NULL scan (tanpa flag); FIN scan dengan FIN saja. Flag tidak lazim menandakan scan evasif.
- `tcp.flags` adalah unsigned integer 16 bit di Wireshark 4.6.9 dan subfield `tcp.flags.fin`, `.syn`, `.ack`, `.reset`, `.push`, `.urg` adalah boolean, sehingga filter di atas valid di versi itu [S1]. Untuk Xmas (FIN+PSH+URG), filter `tcp.flags.fin == 1 and tcp.flags.push == 1 and tcp.flags.urg == 1`.

Versi PT JAB:

```bash
tshark -r /cases/inc-2027-063/inc063-ext.pcapng -Y "ip.src == 203.0.113.166 and udp" | wc -l
tshark -r /cases/inc-2027-063/inc063-ext.pcapng -Y "icmp.type == 3" | wc -l
```

Keluaran ilustrasi:

```
0
0
```

**Cara membaca hasil:** tidak ada satu pun paket UDP dari penyerang di pcap, dan tidak ada ICMP unreachable. Ini konsisten dengan log firewall: 100 port UDP dibuang diam-diam sebelum TAP. Dari sisi penyerang, semua port UDP berstatus open|filtered, artinya scan UDP tidak memberinya informasi. Dari sisi analis, angka nol di pcap bukan bukti tidak ada scan UDP; log firewall yang membuktikannya.

**Variasi:** di lab tanpa firewall, scan UDP ke VM Linux akan menghasilkan banyak ICMP type 3 code 3 dari target; hitung rasionya terhadap probe. Bila firewall membalas dengan ICMP unreachable alih-alih membuang diam-diam, filter `icmp.type == 3 and icmp.code == 13` menampilkan salah satu code yang dibaca scanner sebagai filtered [S6]; arti tiap code ada di tabel parameter ICMP, jadi cek code yang dipakai firewall-mu.

**Kapan gagal:** OS target membatasi laju ICMP unreachable sehingga hanya sebagian port tertutup yang dijawab dan sisanya tampak open|filtered; atau FIN scan ke host Windows dijawab RST untuk semua port (bagian 1.1).

### 2.7 Brute force plaintext: FTP

Bagian ini menjawab pertanyaan ketiga Dimas. Rule `SOC-2027-0616` menghitung FAIL LOGIN dan shift malam menyimpulkan "gagal semua"; pcap FTP plaintext bisa memeriksa apakah ada 230.

```
ftp.response.code == 530
http.response.code == 401
```

- FTP 530 (login gagal) berulang, atau HTTP 401 berulang ke endpoint login = brute force.
- Dengan tshark, hitung response gagal per sumber dalam jendela waktu.
- Cara membaca: banyak kegagalan lalu satu keberhasilan (230 FTP, 200/302 HTTP) bisa menandakan brute force berhasil. Catat; jangan simpan kredensial.

Field FTP yang dipakai ada di display filter reference Wireshark 4.6.9: `ftp.request.command` dan `ftp.request.arg` (string), `ftp.response.code` (integer), `ftp.response.arg` (string) [S1].

**Langkah 1: hitung kode respons.**

```bash
tshark -r /cases/inc-2027-063/inc063-ext.pcapng -Y "ftp.response.code" \
  -T fields -e ftp.response.code | sort | uniq -c | sort -rn
```

Keluaran ilustrasi:

```
   2311 331
   2310 530
    771 220
      3 150
      3 226
      3 227
      2 250
      1 257
      1 230
      1 221
      1 550
```

**Cara membaca:** 771 banner 220, satu per sesi kontrol; probe scan ke port 21 tidak mendapat banner karena handshake-nya tidak pernah selesai (bagian 2.4). 770 sesi masing-masing berisi tiga percobaan gagal sebelum server menutup koneksi tanpa kode balasan, ditambah satu sesi yang berhasil di percobaan pertama: 770 kali 3 ditambah 1 sama dengan 2.311 kali 331, yaitu username diterima dan dimintai password. 2.310 kali 530 dan satu 230: ada tepat satu login berhasil. "Gagal semua" keliru. Kode 150, 221, 226, 227, 250, 257, dan 550 hanya muncul di sesi yang berhasil (langkah 3).

**Langkah 2: username yang dicoba, tanpa password.**

```bash
tshark -r /cases/inc-2027-063/inc063-ext.pcapng -Y 'ftp.request.command == "USER"' \
  -T fields -e ftp.request.arg | sort | uniq -c | sort -rn
```

Filter sengaja hanya mengambil `USER`. Argumen `PASS` terbaca sebagai teks biasa (bagian 1.4), dan tidak boleh ditulis ke file kasus, tiket, atau laporan.

Keluaran ilustrasi:

```
    640 admin
    590 ftp
    541 mitra.instalasi
    540 teknisi
```

**Cara membaca:** 640 + 590 + 541 + 540 = 2.311, sama dengan jumlah 331. Empat akun, ratusan percobaan per akun: brute force (T1110.001), bukan spray. Akun `mitra.instalasi` adalah akun nyata untuk mitra pemasangan; tiga lainnya nama umum. 541 untuk `mitra.instalasi` berarti 540 gagal ditambah satu berhasil.

**Langkah 3: sesi yang berhasil.** Cari stream yang memuat 230, lalu tampilkan semua perintah dan respons di stream itu:

```bash
tshark -r /cases/inc-2027-063/inc063-ext.pcapng -Y "ftp.response.code == 230" \
  -T fields -e tcp.stream -e frame.time
tshark -r /cases/inc-2027-063/inc063-ext.pcapng -Y "tcp.stream == 1187 and ftp" -t ad \
  -T fields -e frame.time -e ftp.request.command -e ftp.request.arg -e ftp.response.code -e ftp.response.arg \
  | grep -v $'\tPASS\t'
```

Keluaran ilustrasi (baris `PASS` dibuang oleh `grep`, waktu diringkas):

```
1187   2027-05-07 01:47:11.902

01:47:11.640                                  220  (FTP server ready)
01:47:11.701  USER  mitra.instalasi
01:47:11.702                                  331  Please specify the password.
01:47:12.118                                  230  Login successful.
01:47:13.004  PWD
01:47:13.005                                  257  "/" is the current directory
01:47:14.210  PASV
01:47:14.211                                  227  Entering Passive Mode (...)
01:47:14.230  LIST
01:47:14.233                                  150  Here comes the directory listing.
01:47:14.240                                  226  Directory send OK.
01:47:21.502  CWD   firmware
01:47:21.503                                  250  Directory successfully changed.
01:47:22.860  PASV
01:47:22.861                                  227  Entering Passive Mode (...)
01:47:22.880  RETR  ont-fw-v3.2.1.bin
01:47:22.884                                  150  Opening BINARY mode data connection (18874368 bytes).
01:47:31.012                                  226  Transfer complete.
01:48:40.115  CWD   /mitra
01:48:40.116                                  250  Directory successfully changed.
01:48:41.610  PASV
01:48:41.611                                  227  Entering Passive Mode (...)
01:48:41.630  RETR  jadwal-instalasi-2027-05.xlsx
01:48:41.633                                  150  Opening BINARY mode data connection (284160 bytes).
01:48:41.910                                  226  Transfer complete.
01:52:30.402  STOR  t.txt
01:52:30.404                                  550  Permission denied.
01:52:40.017  QUIT
01:52:40.018                                  221  Goodbye.
```

Setiap transfer (`LIST` dan dua `RETR`) didahului `PASV` sendiri dan memakai koneksi data ke port pasif yang berbeda (40017, 40052, 40088 di bagian 2.3). Itulah sumber tiga 150, tiga 226, dan tiga 227 di langkah 1. Alamat di dalam balasan 227 disingkat `(...)` di sini.

**Cara membaca:**

- Login berhasil 01:47:12, setelah 2.310 kegagalan sejak 22:36:10. Rule malam itu menghitung kegagalan dan tidak punya kondisi "berhasil setelah gagal", sehingga keberhasilan tidak memicu apa pun.
- Dua unduhan selesai (150 diikuti 226): firmware ONT 18.874.368 byte (18 MiB) dan `jadwal-instalasi-2027-05.xlsx` 284.160 byte. Firmware bersifat publik bagi teknisi dan risikonya rendah; jadwal instalasi memuat data pelanggan dan menjadi inti `INC-2027-063`.
- `STOR` ditolak 550: akun itu hanya baca, sehingga tidak ada bukti file ditanam di server.
- Ukuran dari respons 150 adalah klaim server; ukuran yang benar-benar lewat dicek di koneksi data (port pasif 40000 sampai 40100). Wireshark memisahkan isi koneksi data sebagai `ftp-data`; isinya bisa diekspor untuk diserahkan ke pemilik data dengan hash, bukan dibuka di workstation analis.

**Variasi:** untuk HTTP basic auth atau form login, pakai `http.response.code == 401` dan `http.request.method == "POST"` dengan path login, lalu cari 200 atau 302 dari server setelah rangkaian 401. Untuk menghitung laju, `-T fields -e frame.time_epoch` pada respons 530, lalu bagi jumlah dengan rentang waktu: 2.311 percobaan dalam 11.462 detik (22:36:10 sampai 01:47:12) adalah sekitar 0,2 percobaan per detik, atau sekitar 12 per menit.

**Kapan gagal:** FTP memakai TLS (FTPS) sehingga kanal kontrol terenkripsi dan hanya pola koneksi yang terlihat (bagian 2.8); server mengirim 530 dengan teks yang berbeda untuk "user tidak ada" dan "password salah", sehingga hitungan per username perlu membaca `ftp.response.arg`; atau sesi kontrol terpecah di dua file ring buffer dan filter stream harus dijalankan di file gabungan.

### 2.8 Brute force terenkripsi: SSH

Bagian ini menjawab pertanyaan keempat Dimas. Port 22 di `jkt-dmz-ftp01` terbuka ke internet lewat aturan lama `ALLOW-ANY-FTP01-SSH` yang dibuat 2024 untuk akses vendor dan tidak pernah dicabut.

```
tcp.port == 22
```

- Filter port 22; lihat Conversations (Day 02). Banyak koneksi pendek dari satu sumber = kandidat brute force SSH.
- Cara membaca: hitung koneksi (`tcp.stream` unik) ke port 22 dari sumber dalam waktu singkat; durasi pendek seragam = upaya gagal. Satu koneksi panjang setelahnya = kemungkinan berhasil (korelasi dengan log host).
- Isi terenkripsi; hanya pola yang terlihat (bagian 1.5).

**Langkah 1: bentuk koneksi.**

```bash
tshark -r /cases/inc-2027-063/inc063-ext.pcapng -q -z "conv,tcp,ip.addr==203.0.113.166 and tcp.port==22"
```

`-z conv,tcp[,filter]` memberi satu baris per pasangan socket, dengan frame dan byte per arah, waktu mulai relatif, dan durasi; `-q` menyembunyikan keluaran per paket [S1]. Keluaran ilustrasi diringkas dari 149 baris:

```
                                           Total Frames  Total Bytes   Rel Start   Duration
10.20.9.45:22 <-> 203.0.113.166:51244              3          174        8.7520     0.0261   (probe scan)
10.20.9.45:22 <-> 203.0.113.166:41022             27         3188     1442.1120     2.6034
10.20.9.45:22 <-> 203.0.113.166:41030             26         3072     1448.9080     2.1177
...
10.20.9.45:22 <-> 203.0.113.166:56918             28         3402     2307.4410     3.7952

Ringkasan 148 sesi selain probe scan: durasi 2,1 sampai 3,8 detik, total 3,0 sampai 3,4 KB,
mulai 22:38:05 sampai 22:52:30 (865 detik), tidak ada sesi di atas 4 detik atau 4 KB
```

**Langkah 2: identification string.**

```bash
tshark -r /cases/inc-2027-063/inc063-ext.pcapng -Y "ssh.protocol and ip.src == 203.0.113.166" \
  -T fields -e ssh.protocol | sort | uniq -c
```

Keluaran ilustrasi:

```
    148 SSH-2.0-Go
```

**Cara membaca:**

- 148 sesi dalam 865 detik, rata-rata satu sesi setiap sekitar 5,8 detik, dengan durasi dan ukuran yang seragam. Tidak ada sesi panjang. Pola ini konsisten dengan kegagalan berulang.
- String klien identik di semua sesi dan bukan `SSH-2.0-OpenSSH_...` yang dipakai admin PT JAB. Itu indikator otomasi, bukan identitas alat (bagian 1.5).
- Probe scan (3 frame, 26 milidetik) tercatat sebagai pasangan socket terpisah dan sengaja tidak dihitung.

**Langkah 3: konfirmasi di host.** Log `sshd` `jkt-dmz-ftp01` dikirim ke `index=linux`:

```
index=linux host=jkt-dmz-ftp01 sourcetype=linux_secure "sshd"
    earliest="05/06/2027:22:30:00" latest="05/07/2027:03:00:00"
| rex "(?<outcome>Failed password|Accepted password|Accepted publickey|Invalid user) for (invalid user )?(?<user>\S+) from (?<src>\S+)"
| stats count BY src outcome user
```

Keluaran ilustrasi:

```
src             outcome          user   count
203.0.113.166   Failed password  admin    148
203.0.113.166   Failed password  root     296
```

**Cara membaca:** 444 `Failed password` (148 sesi kali 3 percobaan), tanpa satu pun `Accepted`. Kesimpulan "tidak ada login SSH berhasil dari `203.0.113.166`" sekarang berdiri di atas log host, dan pola pcap mendukungnya. Temuan sampingan yang sama pentingnya: SSH tidak seharusnya terbuka ke internet.

**Variasi:** stacking `ssh.kex.hassh` untuk melihat apakah fingerprint klien yang sama muncul dari alamat lain di hari berbeda; atau hitung sesi per menit dengan `frame.time` untuk melihat apakah alat menahan laju.

**Kapan gagal:** server memakai `MaxAuthTries` tinggi sehingga satu sesi panjang memuat ratusan percobaan dan tampak seperti "sesi panjang berhasil"; `sshd` menulis log ke journald yang tidak dikirim ke Splunk; atau penyerang berhasil memakai kunci yang dicuri dalam satu sesi pendek (bagian 1.5).

### 2.9 Password spraying VPN: log dan flow, tanpa pcap

Bagian ini menjawab pertanyaan kelima Dimas tentang VPN. Login VPN tidak lewat TAP egress (bagian 1.5), jadi analisis memakai log `jkt-vpn01` di `index=vpn` dan flow edge.

**Tujuan:** membuktikan pola spray dan menemukan akun yang password-nya benar.

**Asumsi data:** event login VPN dengan field `user`, `src`, `result` (`success` atau `fail`), dan `reason`; nama field mengikuti parsing PT JAB dan perlu dicek.

**Langkah 1: kenapa rule per IP dan per akun diam.**

```
index=vpn host=jkt-vpn01 result=fail
    earliest="05/07/2027:06:00:00" latest="05/07/2027:09:00:00"
| stats count AS fails dc(user) AS users BY src
| stats count AS sources sum(fails) AS total_fails max(fails) AS max_per_src
        avg(fails) AS avg_per_src
| eval avg_per_src=round(avg_per_src,1)
```

Keluaran ilustrasi:

```
sources total_fails max_per_src avg_per_src
     37         412          14        11.1
```

**Cara membaca:** 412 kegagalan dari 37 sumber, paling banyak 14 per sumber dalam 2,5 jam. Rule "20 gagal per sumber dalam 10 menit" tidak mungkin terpicu. 412 dibagi 37 sama dengan sekitar 11,1.

**Langkah 2: bentuk per akun dan per jam.**

```
index=vpn host=jkt-vpn01 result=fail
    earliest="05/07/2027:06:00:00" latest="05/07/2027:09:00:00"
| bin _time span=1h
| stats count AS fails dc(user) AS users dc(src) AS sources BY _time
| eval per_user=round(fails/users,1)
```

Keluaran ilustrasi:

```
_time                fails users sources per_user
2027-05-07 06:00       158    79      37      2.0
2027-05-07 07:00       172    86      35      2.0
2027-05-07 08:00        82    41      29      2.0
```

**Cara membaca:** 158 + 172 + 82 = 412 kegagalan dan 79 + 86 + 41 = 206 akun, masing-masing tepat dua percobaan, tersebar di 37 sumber. Sedikit percobaan per akun, banyak akun, banyak sumber: password spraying terdistribusi (T1110.003). Satu-satunya rule yang terpicu adalah rule total per jam (`SOC-2027-0618`, 158 kegagalan untuk jam 06:00), dan rule itu tidak menyebut bentuknya. Hitungan akun dilakukan per jam; akun yang sama tidak muncul di dua jam berbeda di contoh ini, sehingga jumlah per jam boleh dijumlahkan. Di data nyata, hitung `dc(user)` untuk seluruh jendela juga.

**Langkah 3: akun yang password-nya benar.**

```
index=vpn host=jkt-vpn01
    earliest="05/07/2027:06:00:00" latest="05/07/2027:09:00:00"
    [ search index=vpn host=jkt-vpn01 result=fail earliest="05/07/2027:06:00:00" latest="05/07/2027:09:00:00"
      | stats count BY src | fields src ]
| stats count BY result reason
```

Keluaran ilustrasi:

```
result reason        count
fail   auth-failed     410
fail   mfa-denied        2
```

**Cara membaca:** tidak ada `success` dari 37 sumber itu, tetapi dua kegagalan beralasan `mfa-denied` untuk `fajar.nugroho@jab.example` dan `wulan.sari@jab.example`. Pada percobaan kedua, password kedua akun itu benar dan yang menolak adalah MFA. Dua akun ini harus direset password-nya hari itu dan dicek apakah password yang sama dipakai di layanan lain; ini bagian dari `INC-2027-063` sebagai temuan terkait, bukan bukti bahwa spray dan brute force FTP dilakukan pelaku yang sama.

**Langkah 4: kenapa flow NOC tidak melihatnya.** Bambang menghitung dari flow edge (sampling 1:1000). Satu percobaan login VPN TLS yang gagal berisi sekitar 30 paket (asumsi ilustrasi; ukur di lab). 412 sesi kali 30 paket sama dengan 12.360 paket, sehingga rata-rata sekitar 12 paket tersampel. Peluang satu sesi terwakili minimal satu paket adalah 1 - 0,999^30, sekitar 3,0%, sehingga hanya sekitar 12 dari 412 sesi yang muncul di flow, tenggelam di antara ribuan sesi VPN karyawan yang mulai bekerja pagi itu. Flow edge tidak salah; ia memang tidak dirancang untuk ini.

**Kapan gagal:** log VPN mencatat username yang tidak ada dengan alasan yang sama dengan password salah, sehingga spray dengan daftar username tebakan terlihat sama dengan spray ke akun nyata; `src` berisi alamat load balancer di depan VPN, bukan alamat penyerang; atau spray dijalankan berhari-hari dengan satu percobaan per akun per hari, sehingga jendela tiga jam tidak cukup dan perlu `bin span=1d` selama seminggu.

### 2.10 Membedakan dari scanner sah

Bagian ini menutup pertanyaan kelima Dimas: `203.0.113.167` dan `JKT-WS-2017`.

```
# periksa sumber scan terhadap daftar scanner yang diketahui
ip.src == <ip_scanner_internal>
```

- Bila sumber adalah scanner internal yang diketahui (Nessus, Qualys) dan terjadwal, scan kemungkinan sah. Bandingkan dengan daftar aset/scanner.
- Scan dari IP eksternal tak dikenal ke layanan sensitif lebih mencurigakan.
- Cara membaca: identitas dan konteks sumber menentukan apakah scan sah atau berbahaya; pola paketnya sama.

**`203.0.113.167`.** Empat ciri dari bagian 1.6 dicek satu per satu:

| Ciri | Bukti | Hasil |
|---|---|---|
| Ada di daftar resmi | Halaman "scanner IPs" `research.example` pada 2027-05-07 memuat `203.0.113.167` | Cocok |
| Reverse dan forward DNS | PTR `scan-07.research.example`; nama itu resolve kembali ke `203.0.113.167` | Cocok |
| Perilaku | Satu probe per port per alamat, banner SSH dan sertifikat TLS saja, tanpa key exchange lengkap atau login (bagian 2.5); access log HTTPS `jkt-dmz-ftp01` mencatat satu `GET /` dengan user agent yang memuat URL opt-out `research.example` | Cocok |
| Pola berulang | Log firewall Jumat 2027-04-30 02:00 sampai 02:43 menunjukkan sweep yang sama dari alamat yang sama | Cocok |

Keputusan: `SOC-2027-0617` ditutup sebagai benign (scanner riset), tanpa blokir. Catatan untuk Agung: scanner riset itu sudah mengindeks SSH terbuka di `198.51.100.204`, jadi perbaiki eksposurnya, bukan pemindainya.

**`JKT-WS-2017`.** Alamat `10.10.60.43` bukan `jkt-vscan01` (`10.20.10.61`), dan Jumat pagi bukan jadwalnya. Pivot ke Defender for Endpoint menunjukkan `powershell.exe` menjalankan `inventory-smb.ps1` dari folder dokumen `andre.saputra`, engineer di tim Agung, yang dimulai 08:05:10. Andre dan Agung mengonfirmasi skrip itu dibuat untuk mendata server yang masih menerima SMBv1, tanpa tiket perubahan. Tidak ada koneksi lanjutan ke 61 host yang terbuka selain probe itu sendiri, dan tidak ada alert lain di host itu.

Keputusan: `SOC-2027-0619` ditutup sebagai pelanggaran kebijakan, bukan insiden. Tindak lanjut: skrip dijalankan ulang dari `jkt-vscan01` dengan tiket, dan daftar 61 host SMB yang menjawab diserahkan ke Agung.

**Kapan gagal:** daftar scanner riset diambil dari salinan forum yang sudah usang (bagian 1.6); scanner sah yang dikuasai penyerang mulai mencoba login, sehingga allowlist per alamat membuat aktivitas berbahaya tidak terlihat. Pengecualian untuk scanner sebaiknya sempit: alamat, jendela waktu, dan "tanpa percobaan login".

### 2.11 Dampak, timeline `INC-2027-063`, dan jawaban untuk Dimas

Insiden `INC-2027-063` dinyatakan Jumat 2027-05-07 pukul 09:40, setelah 230 dan dua `RETR` ditemukan di bagian 2.7. Timeline berikut menggabungkan semua sumber. Kolom "Sumber" penting karena setiap baris hanya sekuat sensornya.

| Waktu (WIB) | Kejadian | Sumber | Bukti atau kesimpulan |
|---|---|---|---|
| Kamis 22:14:03 sampai 22:14:41 | SYN scan 1.000 port TCP ke `198.51.100.204`; 996 dibuang, 4 diizinkan | Firewall, pcap | Bukti |
| 22:14:05 sampai 22:14:27 | Port 21, 22, 443 open; 80 closed | pcap | Bukti |
| 22:15:02 sampai 22:16:10 | Scan UDP 100 port, semua dibuang, tanpa respons | Firewall | Bukti |
| 22:36:10 | Brute force FTP dimulai, 4 akun | pcap, log FTP | Bukti |
| 22:38:05 sampai 22:52:30 | 148 sesi SSH pendek, 444 `Failed password`, 0 `Accepted` | pcap, `index=linux` | Bukti; tidak ada login SSH berhasil |
| 22:51 | `SOC-2027-0616` terpicu, diberi P3, dicatat "gagal semua" | Splunk | Keputusan yang keliru |
| Jumat 01:47:12 | `230 Login successful` untuk `mitra.instalasi` setelah 2.310 kegagalan | pcap | Bukti |
| 01:47:31 | Unduhan firmware ONT 18.874.368 byte selesai | pcap | Bukti |
| 01:48:41 | Unduhan `jadwal-instalasi-2027-05.xlsx` 284.160 byte selesai | pcap | Bukti; isi file dikonfirmasi pemilik data |
| 01:52:30 | `STOR` ditolak 550 | pcap | Bukti; tidak ada file yang diunggah |
| 02:00:05 sampai 02:41:37 | Sweep `203.0.113.167` | Firewall, pcap, DNS | Benign (bagian 2.10) |
| 06:02:15 sampai 08:31:40 | Spray VPN 412 gagal, 206 akun, 37 sumber, 2 `mfa-denied` | `index=vpn` | Bukti; dua password valid |
| 08:05:12 sampai 08:19:48 | Sweep 445 dari `JKT-WS-2017` ke 1.024 alamat | Flow DC, Defender | Pelanggaran kebijakan |
| 09:40 | `INC-2027-063` dinyatakan | SOC | |

Tindakan yang diambil Jumat pagi: akun `mitra.instalasi` dinonaktifkan dan password-nya diganti setelah mitra dihubungi; `203.0.113.166` diblok di `jkt-fw01` dengan logging; aturan `ALLOW-ANY-FTP01-SSH` dicabut; password `fajar.nugroho` dan `wulan.sari` direset; Agus Setiawan (DPO) menerima informasi tentang file jadwal instalasi untuk penilaian kewajiban pelindungan data pribadi.

Satu halaman jawaban untuk Dimas. Setiap baris merujuk subbagian supaya Dimas bisa membaca alasannya bila ditanya Hendra.

| Pertanyaan Dimas | Jawaban singkat | Dasar |
|---|---|---|
| Scan apa, port apa yang ditemukan | SYN scan 1.000 port default; open: FTP 21, SSH 22, HTTPS 443 | Bagian 1.1, 2.3, 2.4 |
| Kenapa angka firewall, pcap, flow berbeda | Firewall melihat semua probe, pcap di sisi dalam hanya yang diizinkan, flow edge tersampel 1:1000 | Bagian 1.3, 2.2 |
| FTP gagal semua? | Tidak: satu login berhasil 01:47:12, dua file diunduh, unggah ditolak | Bagian 1.4, 2.7 |
| SSH tembus? | Tidak, dikonfirmasi log `sshd`; tetapi SSH tidak boleh terbuka ke internet | Bagian 1.5, 2.8 |
| VPN spray? | Ya, terdistribusi; dua akun password-nya benar dan ditahan MFA | Bagian 1.4, 2.9 |
| `.167` dan `JKT-WS-2017` | `.167` scanner riset (benign); `JKT-WS-2017` pelanggaran kebijakan, bukan insiden | Bagian 1.6, 2.10 |
| Untuk Pak Hendra | Satu akun mitra dibobol, satu file data pelanggan keluar, dua password karyawan bocor; eksposur SSH sudah ditutup | Bagian 1.7, 2.11 |

Usulan deteksi yang lahir dari malam ini (diserahkan ke Sari Kusuma): rule "login berhasil dari sumber yang punya lebih dari N kegagalan dalam 24 jam" untuk FTP, SSH, dan VPN; rule spray "lebih dari 30 akun berbeda gagal login VPN per jam, dari sumber mana pun"; dan rule "alasan `mfa-denied` dari sumber yang juga punya `auth-failed` untuk akun lain".

**Kapan gagal:** timeline ditulis dengan jam dari sensor berbeda tanpa menyamakan zona waktu dan offset jam (pcap UTC, firewall WIB), sehingga 230 tampak terjadi sebelum kegagalan pertama; atau kolom "Bukti atau kesimpulan" dihapus supaya tabel terlihat rapi, padahal itu yang membedakan "file diunduh" dari "data bocor".

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** Wireshark 4.6.x; pcap lab berisi scan dan/atau brute force (buat sendiri di lab terisolasi, atau pcap publik latihan; cek lisensi); tidak ada pcap kerja. Jaringan host-only lab, misalnya `192.168.56.0/24`, dengan satu VM "penyerang" lab, satu VM target Linux dengan FTP dan SSH, dan snapshot bersih untuk keduanya. Scan dan percobaan login hanya ditujukan ke VM milikmu sendiri di jaringan itu. Data PT JAB di atas hanya contoh fiktif.

1. **SYN scan.** Filter SYN murni (bagian 2.3). Tentukan sumber, dan apakah vertikal (banyak port satu host) atau horizontal (satu port banyak host).
2. **Port terbuka.** Filter SYN-ACK dari target (bagian 2.4). Daftar port terbuka yang ditemukan scan.
3. **Sweep.** Bila ada, kenali sweep horizontal untuk port tertentu (bagian 2.5). Catat berapa host disentuh.
4. **UDP/flag aneh.** Periksa ICMP port unreachable dan flag tak lazim (bagian 2.6) bila ada.
5. **Brute force.** Bila pcap punya FTP/HTTP, hitung kegagalan autentikasi (bagian 2.7). Bila SSH, hitung pola koneksi (bagian 2.8).
6. **Sah vs berbahaya.** Nilai sumber scan: internal terjadwal atau eksternal tak dikenal (bagian 2.10). Nyatakan kemungkinan jinak.
7. **Dampak.** Tentukan apa yang penyerang temukan (port terbuka) dan apakah diikuti koneksi lanjut (bagian 1.7).
8. **SYN vs connect.** Rekam dua scan berbeda ke VM target: SYN scan dan connect scan. Bandingkan nilai `tcp.completeness` untuk port terbuka di kedua capture, dan cek apakah syslog target mencatat connect scan tetapi tidak mencatat SYN scan (bagian 1.1). Catat apakah nilai yang kamu dapat sama dengan 35 dan 39 dari bagian 1.3.
9. **Efek firewall.** Aktifkan firewall host di VM target yang hanya mengizinkan 21 dan 22, lalu ulangi SYN scan. Capture di dua titik: di VM penyerang dan di VM target (di belakang firewall host). Hitung port unik di masing-masing; selisihnya adalah pelajaran bagian 1.3. Ulangi dengan aturan "reject" alih-alih "drop" dan catat bedanya di pcap (RST atau ICMP code 13).
10. **Brute force vs spray di log.** Buat sepuluh akun uji di VM target. Dari VM penyerang, lakukan login FTP manual dengan password salah: dua puluh kali ke satu akun, lalu satu kali ke masing-masing sepuluh akun. Hitung keduanya dengan query bagian 2.7 dan dengan log FTP di target, lalu tulis aturan sederhana yang menangkap bentuk kedua tetapi tidak bentuk pertama.
11. **Sampling.** Dari capture langkah 8, hitung berapa paket per sesi. Hitung peluang satu sesi tercatat di flow dengan sampling 1:1000, memakai rumus 1 - 0,999^N dari bagian 2.9.

**Hasil yang sebaiknya tersimpan:**

- Tipe scan dikenali; vertikal vs horizontal dibedakan.
- Port terbuka yang ditemukan scan didaftar.
- Sweep horizontal (bila ada) diukur cakupannya.
- Brute force dikenali dari pola (plaintext respons atau koneksi terenkripsi).
- Sumber scan dinilai sah vs berbahaya dengan konteks.
- Dampak (apa yang ditemukan, tindak lanjut) dinyatakan.
- Tabel nilai `tcp.completeness` untuk SYN scan, connect scan, port terbuka, dan port tertutup dari lab-mu sendiri.
- Hitungan port unik di dua titik capture (depan dan belakang firewall host), untuk drop dan reject.
- Aturan deteksi spray dari langkah 10 beserta hasil uji positif dan negatifnya.
- Hash SHA-256 setiap pcap lab yang dipakai.

**Variasi tantangan:** dalam pcap yang sama, tentukan urutan: apakah scan diikuti koneksi ke salah satu port terbuka (kemungkinan eksploitasi atau akses), lalu aktivitas lanjut. Tulis timeline singkat (scan, temuan port terbuka, koneksi lanjut) dan nyatakan di mana bukti berhenti dan di mana kesimpulan mulai (mis. koneksi ke port terbuka belum tentu eksploitasi berhasil). Format tabel timeline bagian 2.11, dengan kolom "Bukti atau kesimpulan", bisa dipakai langsung.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat membaca scan dan brute force dari trafik. Cari gejalanya di kolom kiri; baris baru di bawah enam baris pertama berasal dari pengalaman situasi PT JAB di bagian 2.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Banyak SYN tapi bukan scan | Retry koneksi sah; aplikasi berisik | Periksa apakah ke banyak port/host atau satu layanan |
| Tidak ada respons scan | Port terfilter firewall; host mati | Tidak ada SYN-ACK/RST = terfilter atau mati |
| Brute force SSH tak jelas | Terenkripsi; hanya pola | Hitung koneksi pendek; korelasi log host |
| Scanner sah terlihat berbahaya | Scanner internal terjadwal | Cek daftar scanner; konteks sumber |
| UDP scan tak terlihat | Tidak ada ICMP (terfilter) | UDP scan sulit; andalkan ICMP bila ada |
| Flag scan tak cocok filter | Sintaks flag beda versi | `tcp.flags` (uint16) dan subfield boolean valid di 4.6.9 [S1]; cek di versi lain dengan menu filter Wireshark |
| pcap hanya punya beberapa paket untuk scan yang besar | TAP di sisi dalam firewall; probe dibuang sebelum TAP | Ambil lebar scan dari log firewall (bagian 2.2) |
| Alamat tujuan di pcap tidak cocok dengan alert | DNAT: alert memakai alamat publik, pcap alamat internal | Cari kedua alamat; catat pemetaan NAT di laporan |
| Flow edge tidak menunjukkan scan atau spray | Sampling 1:1000 | Pakai firewall, log aplikasi, atau flow router 1:1 (bagian 1.3, 2.9) |
| File pcap untuk jam kejadian tidak ada | Ring buffer sudah menimpa | Ekstrak segera setelah alert (bagian 2.1); catat celah di laporan |
| editcap memotong di jam yang salah | Zona waktu tidak disebut, mesin analis ber-UTC | Tulis offset `+07:00` di `-A` dan `-B` [S16] |
| Hitungan 530 tidak sama dengan jumlah USER | Server menutup sesi sebelum menjawab, atau sesi terpecah di dua file | Hitung di file gabungan; bandingkan 331, 530, dan 230 |
| Rule spray per IP tidak pernah terpicu | Spray terdistribusi | Hitung `dc(user)` per jam lintas sumber (bagian 2.9) |
| Login VPN tidak ada di pcap | `jkt-vpn01` tidak lewat TAP | Pakai `index=vpn`; catat sebagai blind spot |

## 5. Kesalahan umum dan jebakan

- **Mengira semua SYN banyak = scan jahat.** Bisa scanner internal sah atau aplikasi berisik; cek konteks.
- **Tidak mengukur dampak.** "Ada scan" kurang berguna; tentukan port terbuka yang ditemukan dan tindak lanjutnya.
- **Mengira brute force SSH bisa dibaca isinya.** Terenkripsi; hanya pola koneksi.
- **Menyimpan kredensial** dari brute force plaintext; catat keberadaan, bukan nilai. Filter `USER` saja dan buang baris `PASS` sebelum keluaran disimpan (bagian 2.7).
- **Tidak membedakan vertikal dan horizontal.** Maksud penyerang berbeda (fokus satu host vs cari layanan di banyak host).
- **Menghitung paket, bukan port.** Kiriman ulang membuat jumlah paket dua kali atau lebih jumlah port (bagian 2.2).
- **Membandingkan angka dari sensor berbeda tanpa menyebut titiknya.** Firewall 1.000 port dan pcap 4 port sama-sama benar (bagian 1.3).
- **Rule brute force yang hanya menghitung kegagalan.** Yang paling penting justru keberhasilan setelah kegagalan; shift malam PT JAB menulis "gagal semua" karena rule tidak punya kondisi itu (bagian 2.7, 2.11).
- **Mendeteksi spray dengan ambang per IP atau per akun.** Spray terdistribusi sengaja berada di bawah keduanya; ATT&CK juga mencatat penyerang bisa menahan laju percobaan [S13].
- **Mengabaikan kegagalan beralasan MFA.** Password akun itu sudah benar; perlakukan sebagai kredensial bocor (bagian 2.9).
- **Memblokir scanner riset sebagai "respons insiden".** Itu kebijakan, bukan tindakan wajib, dan tidak menghapus apa yang sudah mereka lihat [S19]. Tutup eksposurnya.
- **Allowlist scanner per alamat tanpa batas.** Scanner yang dikuasai penyerang tetap diizinkan; batasi alamat, jam, dan perilaku (bagian 2.10).
- **Menyimpulkan "berhasil" dari satu sesi SSH panjang, atau "gagal" dari sesi pendek.** Keduanya indikator; kesimpulan dari log autentikasi (bagian 1.5).
- `[komunitas, belum terkonfirmasi]` Analis membedakan scan dari lalu lintas normal lewat jumlah target unik per sumber dan rasio koneksi tidak selesai; scanner sah dibedakan lewat identitas sumber dan jadwal. Pola ini umum; konteks sumber menentukan, cek terhadap daftar scanner lingkunganmu.

## 6. Catatan terkini

Bagian ini menampung detail versi dan perubahan sumber yang tidak mengubah filter atau keputusan di atas.

- Pola scan (SYN, connect, FIN/NULL/Xmas, UDP) dan brute force stabil. Field yang dipakai di Day ini (`tcp.flags.*`, `ftp.request.*`, `ftp.response.*`, `ssh.protocol`) tersedia di Wireshark 1.0 sampai 4.6.9; `tcp.completeness` sejak 3.6 dan `ssh.kex.hassh` sejak 3.6 [S1]. Wireshark 4.6.9 adalah rilis stabil per Oktober 2026, dengan 4.4.19 sebagai old stable.
- Nmap 7.992 tercatat di changelog dengan tanggal 2026-10-15. Perilaku dan state port yang dirangkum di bagian 1.1 berasal dari Reference Guide, yang tidak berubah untuk hal-hal yang dipakai di sini [S6][S7][S8].
- MITRE ATT&CK v20.0 dirilis 13 Oktober 2026, menggantikan v19.2. Versi halaman yang dibaca: T1595 v1.0 (diubah 24 Oktober 2025), T1046 v3.2 (12 Mei 2026), T1110 v2.8 (12 Mei 2026), T1110.001 v1.7 (12 Mei 2026), T1110.003 v1.8 (24 Oktober 2025) [S3][S11][S12][S13][S14].
- Daftar subnet scanner Censys diperbarui 2026-03-24 setelah scan dari rentang yang belum diterbitkan; halaman Scanning FAQ diperbarui 2025-12-09 [S19][S20]. Daftar seperti ini harus dicek di halaman resmi pada hari kejadian.
- nfdump 1.7.10 menyebut opsi `-t` sebagai sintaks lama dan menyarankan filter `first seen` dan `last seen`; `-t` masih bisa dipakai [S18].
- Banyak layanan kini terenkripsi (SSH, HTTPS), sehingga brute force makin hanya terlihat sebagai pola koneksi, bukan isi.
- Scan sering dari sumber terdistribusi, menyulitkan deteksi dari satu titik; korelasi lintas sumber membantu.
- Day 05 masuk ke anomali DNS dan HTTP; Day 06 ke TLS.

## 7. Cheat sheet

```
SCAN TYPE  SYN (syn==1 ack==0, lalu RST dari scanner) | connect (handshake penuh + RST) | FIN/NULL/Xmas (flag aneh) | UDP (ICMP port unreachable)
POLA       vertikal: 1 sumber -> banyak port, 1 host | horizontal/sweep: 1 sumber -> 1 port, banyak host | blok: banyak-banyak
TERBUKA    SYN-ACK (syn==1 ack==1) dari target = port terbuka (temuan scan) | RST = tertutup | tak ada = terfilter/mati
STATE      open | closed | filtered | unfiltered (ACK scan) | open|filtered (UDP, FIN/NULL/Xmas) | closed|filtered (idle)
COMPLETE   tcp.completeness bit: 1 SYN, 2 SYN-ACK, 4 ACK, 8 DATA, 16 FIN, 32 RST
           SYN scan open = 35 | closed = 33 | connect + RST = 39 | handshake saja = 7 | lengkap + data = 31/47/63
SENSOR     firewall = semua probe | pcap sisi dalam = hanya yang diizinkan, setelah DNAT | flow edge 1:1000 = hampir buta
           hitung PORT UNIK, bukan paket (ada kiriman ulang)
BRUTE      FTP 530 | HTTP 401 berulang | SMB STATUS_LOGON_FAILURE | SSH/RDP = pola koneksi (terenkripsi, hanya pola)
FTP        220 siap | 331 user ok | 230 login OK | 530 gagal | 150 buka data | 226 transfer selesai | 550 ditolak
           unduhan = RETR + 150 + 226 ; filter USER saja, JANGAN simpan argumen PASS
SSH        banyak koneksi PENDEK ke port 22 = kandidat ; 1 koneksi PANJANG setelahnya = kemungkinan berhasil (korelasi log)
           ssh.protocol (identification string, sebelum enkripsi) | ssh.kex.hassh ; konfirmasi: Accepted/Failed di sshd
SPRAY      brute force = banyak percobaan per akun | spray = sedikit per akun, banyak akun, sering banyak sumber
           hitung dc(user) per jam lintas sumber ; mfa-denied = password BENAR
SAH?       scanner internal terjadwal vs IP eksternal tak dikenal ; pola sama, konteks beda
           riset: daftar resmi + PTR/forward cocok + tanpa login + pola berulang ; internal: daftar aset + jadwal + tiket
ATT&CK     T1595 Active Scanning (luar) | T1046 Network Service Discovery (dalam) | T1110.001 guessing | .003 spraying | .004 stuffing
POTONG     tshark -r f -Y "ip.addr==X" -w out ; mergecap -w all *.pcapng ; editcap -A "YYYY-MM-DD HH:MM:SS+07:00" -B "..."
DAMPAK     port terbuka yang ditemukan + apakah diikuti koneksi lanjut ; sinyal != kesimpulan
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "pcap `jkt-pcap01` hanya memuat 11 paket TCP dari `203.0.113.166` selama scan, jadi scan itu kecil dan log firewall yang menyebut 1.000 port pasti keliru." Benarkah?

<details><summary>Jawaban</summary>

Tidak. TAP egress berada di sisi dalam `jkt-fw01`, sehingga pcap hanya melihat probe yang diizinkan firewall, yaitu empat port (21, 22, 80, 443) beserta balasannya. Firewall melihat semua probe, termasuk 996 port yang dibuang masing-masing dua kali. Kedua angka benar untuk titik observasinya, dan lebar scan diambil dari log firewall, sedangkan hasil scan (port mana yang menjawab) dari pcap. Lihat bagian 1.3 dan 2.2.

</details>

**2. Skenario keputusan.** Login VPN gagal 412 kali dalam 2,5 jam dari 37 sumber ke 206 akun, dua percobaan per akun. Rule "20 gagal per sumber dalam 10 menit" diam. Langkah mana yang paling tepat?

- A. Turunkan ambang rule per sumber menjadi 5 gagal dalam 10 menit.
- B. Hitung jumlah akun berbeda yang gagal per jam lintas semua sumber, lalu cari kegagalan beralasan MFA untuk menemukan akun yang password-nya benar.
- C. Minta Bambang menarik flow edge untuk 37 alamat itu supaya terlihat sesi mana yang berhasil.

<details><summary>Jawaban</summary>

B. Spray terdistribusi sengaja berada di bawah ambang per sumber dan per akun, sehingga sinyalnya hanya muncul bila dihitung per populasi akun dalam satu jendela waktu; kegagalan `mfa-denied` menunjukkan password yang sudah benar. A keliru karena maksimal per sumber hanya 14 dalam 2,5 jam, sehingga ambang 5 per 10 menit tetap tidak terpicu dan malah menambah false positive dari karyawan yang salah ketik. C keliru karena flow edge tersampel 1:1000 sehingga hanya sekitar 3% sesi yang terwakili, dan flow tidak pernah memuat hasil autentikasi. Lihat bagian 1.4 dan 2.9.

</details>

**3. Pertanyaan jebakan.** "Dari 148 sesi SSH dari `203.0.113.166`, tidak ada satu pun yang panjang. Jadi sudah pasti tidak ada login SSH yang berhasil, dan log host tidak perlu dicek." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Pola sesi pendek yang seragam konsisten dengan kegagalan berulang, tetapi itu indikator. Login berbasis kunci bisa berhasil dan langsung menjalankan satu perintah singkat, sehingga sesinya tetap pendek. Kesimpulan "tidak ada yang berhasil" baru berdiri setelah log `sshd` menunjukkan 444 `Failed password` dan nol `Accepted` untuk sumber dan jam yang sama. Lihat bagian 1.5 dan 2.8.

</details>

**4. Skenario keputusan.** `203.0.113.167` menyapu 253 alamat publik PT JAB di tiga port, PTR dan forward DNS-nya cocok dengan organisasi riset yang menerbitkan daftar alamat pemindainya, hanya mengambil banner tanpa login, dan polanya sama minggu lalu. Apa tindakan yang paling tepat?

- A. Buka insiden reconnaissance dan blokir seluruh ASN organisasi itu.
- B. Tutup alert sebagai benign, tanpa kewajiban memblokir, lalu periksa layanan apa yang terlihat olehnya dan perbaiki eksposur yang tidak seharusnya ada.
- C. Tambahkan alamat itu ke allowlist permanen semua rule supaya tidak pernah muncul lagi.

<details><summary>Jawaban</summary>

B. Keempat ciri scanner riset terpenuhi, sehingga ini noise latar; yang bernilai adalah membaca apa yang ia lihat, misalnya SSH terbuka di server FTP, karena penyerang melihat hal yang sama. A keliru karena memblokir adalah keputusan kebijakan, bukan respons insiden, dan tidak menghapus apa yang sudah terindeks. C keliru karena allowlist tanpa batas membuat aktivitas berbahaya dari alamat itu tidak terlihat bila suatu hari perilakunya berubah; pengecualian harus sempit. Lihat bagian 1.6 dan 2.10.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Bambang Hartono (Manajer NOC), dalam tiga kalimat, kenapa flow edge `jkt-flow01` hampir tidak menunjukkan scan semalam dan spray VPN pagi ini, padahal datanya tidak rusak.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Router edge mengekspor flow dengan sampling 1:1000, jadi scan 2.000 probe yang masing-masing satu paket rata-rata hanya meninggalkan sekitar dua paket tersampel, dan peluang satu probe tertentu tercatat cuma 0,1%. Untuk spray VPN, satu percobaan login sekitar 30 paket, jadi peluang satu sesi terwakili sekitar 3%, dan 12-an sesi itu tenggelam di antara ribuan sesi VPN karyawan pagi hari. Flow edge tetap paling berguna untuk volume dan retensi panjang, sedangkan scan kita ambil dari log firewall dan spray dari log VPN, dan untuk trafik kantor ke data center kita pakai flow router DC yang 1:1."

Kesalahan yang sering muncul:
- Menyalahkan kolektor atau exporter rusak, padahal sampling bekerja sesuai rancangan.
- Lupa menyebut sumber pengganti untuk masing-masing pertanyaan.
- Menganggap flow 1:1 di router data center juga melihat trafik internet, padahal titiknya berbeda.

</details>

**6. Pertanyaan jebakan.** "pcap FTP menunjukkan `230 Login successful` untuk `mitra.instalasi`. Berarti penyerang sudah mengambil data dari server." Benarkah?

<details><summary>Jawaban</summary>

Belum tentu. 230 hanya membuktikan login berhasil. Unduhan dianggap terjadi bila ada `RETR` yang diikuti 150 dan 226 untuk file tertentu, dan di sesi itu memang ada dua: firmware ONT dan file jadwal instalasi. Bahwa file jadwal berisi data pelanggan adalah kesimpulan yang butuh konfirmasi isi dari pemilik data, dan `STOR` yang ditolak 550 menunjukkan tidak ada file yang diunggah. Lihat bagian 1.7 dan 2.7.

</details>

**7. Interview question (English).** "How do you tell brute force from password spraying using network data, and what can't the network tell you?"

<details><summary>Sample answer</summary>

"I look at the shape across three dimensions: attempts per account, number of accounts, and number of sources over a time window. Brute force is many attempts against a few accounts, usually from one source, so per-account or per-source thresholds catch it. Spraying is one or two attempts per account across many accounts, often from many sources and throttled, so I count distinct failing accounts per hour across all sources instead. For plaintext protocols like FTP I can see the reply codes in the pcap, and I always look for a success after failures, not just the failures. For SSH or TLS VPN the network only shows connection patterns and the cleartext SSH identification string, so I confirm success or failure in the authentication logs, and I treat MFA rejections as compromised passwords. I also state which sensor I'm using: a firewall sees every probe, a sensor behind it sees only what was allowed, and sampled flow will miss most of it."

What makes this answer strong: it defines both patterns by measurable dimensions, explains why per-source rules miss spraying, separates network indicators from authentication evidence, and shows awareness of sensor placement and sampling.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Wireshark display filter reference (tcp.flags, icmp, ftp, http, ssh) | https://www.wireshark.org/docs/dfref/ | primer | diakses 2026-10-09 (Day 02), dicek ulang 2026-10-22 untuk halaman ftp, ssh, tcp (Versions 1.0.0 to 4.6.9) | Tinggi. Field filter dan tipenya; `tshark -z conv,tcp` dari man page tshark di situs yang sama |
| S2 | RFC 9293 (TCP flags dan handshake) | https://www.rfc-editor.org/rfc/rfc9293 | primer | diakses 2026-10-09 (Day 03) | Tinggi |
| S3 | MITRE ATT&CK T1110: Brute Force (termasuk T1110.003 Password Spraying) | https://attack.mitre.org/techniques/T1110/ | primer | diakses 2026-10-10, dicek ulang 2026-10-22 (v2.8, diubah 12 Mei 2026) | Tinggi. Definisi brute force dan password spray; empat sub-teknik; VPN dan perangkat edge sebagai sasaran |
| S4 | RFC 792 (ICMP, port unreachable untuk UDP scan) | https://www.rfc-editor.org/rfc/rfc792 | primer | diakses 2026-10-09 | Tinggi |
| S5 | Network-Forensics Day 02-03 (Wireshark, protokol) | (lokal) | rujukan internal | 2026-10-09 | Filter dan protokol |
| S6 | Nmap Reference Guide: Port Scanning Techniques | https://nmap.org/book/man-port-scanning-techniques.html | primer | diakses 2026-10-10, dicek ulang 2026-10-22 | Tinggi. Perilaku SYN, connect, FIN/NULL/Xmas, UDP, dan ACK scan beserta respons yang diharapkan, kode ICMP unreachable, OS yang selalu mengirim RST |
| S7 | Nmap Reference Guide: Port Scanning Basics | https://nmap.org/book/man-port-scanning-basics.html | primer | diakses 2026-10-22 | Tinggi. Enam port state; filter lebih sering membuang diam-diam; kiriman ulang untuk port yang tidak menjawab |
| S8 | Nmap Reference Guide: Port Specification and Scan Order | https://nmap.org/book/man-port-specification.html | primer | diakses 2026-10-22 | Tinggi. Default 1.000 port paling umum per protokol |
| S9 | RFC 959: File Transfer Protocol (FTP) | https://www.rfc-editor.org/rfc/rfc959 | primer | diakses 2026-10-22 | Tinggi. Arti kode balasan 150, 220, 221, 226, 230, 331, 421, 530, 550; PASS sebagai string Telnet tanpa enkripsi |
| S10 | RFC 4253: The Secure Shell (SSH) Transport Layer Protocol | https://www.rfc-editor.org/rfc/rfc4253 | primer | diakses 2026-10-22 | Tinggi. Format identification string, panjang maksimal 255, dikirim sebelum key exchange |
| S11 | MITRE ATT&CK T1595: Active Scanning | https://attack.mitre.org/techniques/T1595/ | primer | diakses 2026-10-22 (v1.0, diubah 24 Okt 2025) | Tinggi. Taktik Reconnaissance, sub-teknik .001 sampai .003, mitigasi pre-compromise |
| S12 | MITRE ATT&CK T1046: Network Service Discovery | https://attack.mitre.org/techniques/T1046/ | primer | diakses 2026-10-22 (v3.2, diubah 12 Mei 2026) | Tinggi. Taktik Discovery; analitik berbasis NetFlow/pcap |
| S13 | MITRE ATT&CK T1110.003: Password Spraying | https://attack.mitre.org/techniques/T1110/003/ | primer | diakses 2026-10-22 (v1.8, diubah 24 Okt 2025) | Tinggi. Definisi spray, daftar layanan dan port, penahanan laju |
| S14 | MITRE ATT&CK T1110.001: Password Guessing | https://attack.mitre.org/techniques/T1110/001/ | primer | diakses 2026-10-22 (v1.7, diubah 12 Mei 2026) | Tinggi. Lockout, analitik gagal lalu berhasil, daftar layanan termasuk SNMP |
| S15 | Wireshark User's Guide: TCP Analysis (Conversation Completeness) | https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html | primer | diakses 2026-10-22 | Tinggi. Bit `tcp.completeness` dan contoh nilai 7, 31, 47, 63 |
| S16 | Wireshark man page: editcap dan mergecap (4.6.9) | https://www.wireshark.org/docs/man-pages/editcap.html ; https://www.wireshark.org/docs/man-pages/mergecap.html | primer | diakses 2026-10-22 | Tinggi. `-A` inklusif, `-B` eksklusif, format waktu ISO 8601 dengan zona opsional; mergecap kronologis secara default, `-a` untuk menyambung |
| S17 | Wireshark man page: dumpcap (4.6.9) | https://www.wireshark.org/docs/man-pages/dumpcap.html | primer | diakses 2026-10-22 | Tinggi. Pola nama file ring buffer |
| S18 | nfdump(1) man page | https://github.com/phaag/nfdump/blob/master/man/nfdump.1 | primer (dokumentasi proyek) | diakses 2026-10-22 (nfdump 1.7.10) | Tinggi. `-R`, `-t`, `-A`, `-s`, `-n`, filter port, net, dan flags |
| S19 | Censys: Opt Out of Data Collection | https://docs.censys.com/docs/opt-out-of-data-collection | sekunder (dokumentasi vendor scanner) | diperbarui 2026-03-24; diakses 2026-10-22 | Tinggi untuk perilaku Censys sendiri. Jumlah rentang, ASN, user agent, opt-out |
| S20 | Censys: Scanning FAQ | https://docs.censys.com/docs/scanning-faq | sekunder (dokumentasi vendor scanner) | diperbarui 2025-12-09; diakses 2026-10-22 | Tinggi untuk pernyataan Censys tentang dirinya. Scan kontinu, rescan harian, tanpa login |

**Catatan sumber:** tabel tipe scan di bagian 1.1 sejalan dengan perilaku yang didokumentasikan Nmap [S6]. Pola koneksi SSH brute force (banyak sesi pendek, lalu satu sesi panjang bila berhasil) adalah pengetahuan NSM umum, bukan kutipan dari satu sumber primer. Field filter Wireshark (`tcp.flags`, `ftp.request.*`, `ftp.response.code`, `ssh.protocol`, `ssh.kex.hassh`) sudah dicek di display filter reference 4.6.9 [S1]; kode SMB status tidak dicek ulang di Day ini. Nilai `tcp.completeness` 33, 35, dan 39 diturunkan dari definisi bit [S15], bukan dari contoh di dokumentasi, dan perlu dicek di lab. Ciri scanner riset di bagian 1.6 disusun dari dokumentasi Censys [S19][S20] sebagai contoh satu organisasi; organisasi lain bisa berperilaku berbeda, dan pernyataan "tidak mencoba login" adalah klaim Censys sendiri. Hitungan sampling (2 paket dari 2.000 probe, sekitar 3% sesi VPN tersampel) adalah aritmetika peluang dengan asumsi sampling acak per paket dan 30 paket per sesi; cara sampling router nyata perlu dicek di konfigurasi exporter. Pembedaan sah vs berbahaya bergantung konteks lingkungan. Seluruh isi PT JAB (alert `SOC-2027-0615` sampai `0619`, `INC-2027-063`, host `jkt-dmz-ftp01`, akun, file, angka, dan keluaran perintah) adalah contoh fiktif, bukan hasil eksekusi nyata.
