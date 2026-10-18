---
day: 12
title: 'Hunting C2 dan exfiltration: beaconing, DNS tunneling, koneksi tidak lazim, dan transfer keluar besar'
researched_on: 2026-10-18
versions_checked: 'MITRE ATT&CK v20.0 (13 Okt 2026): T1071.001 v1.5, T1071.004 v1.4, T1572 v1.1, T1048 v1.6, T1041 v2.4, T1567 v1.5, T1571 v1.3, T1568 v1.1, T1176 v2.0, T1176.001 v1.1; RITA v5.1.2 (7 Mei 2026); Zeek conn.log (dokumentasi master); Sysmon EID 3/22; Atomic Red Team T1071.004; Splunk Enterprise 10.6 (SPL); Splunk CIM 6.4 Network Traffic; Splunk Add-on for Palo Alto Networks 4.0.0; PAN-OS traffic log fields; Squid logformat; RFC 8484 (DoH); RFC 9849 (ECH, Mar 2026); kebijakan Microsoft Edge DnsOverHttpsMode dan ExtensionInstallBlocklist (2026); Velociraptor Windows.Applications.Chrome.Extensions'
---

# Day 12: Hunting C2 dan exfiltration (beacon, DNS tunneling, volume keluar, dan batas data kantor)

Cakupan: hunting command and control (beaconing, DNS tunneling, port tidak lazim) dan exfiltration (volume keluar, transfer ke tujuan baru) dari data proxy, firewall, resolver, dan endpoint, cara membedakannya dari layanan sah lewat konteks tujuan, korelasi C2 lalu exfil sebagai sinyal risk, serta jalur keluar yang tidak terlihat dari data kantor.

Catatan ruang lingkup: Day ini memburu jejak command and control dan exfiltration dari sisi defensif. Tidak ada tool atau teknik C2/exfiltration yang dijelaskan cara membuatnya; uji jinak di lab memakai beacon dan transfer buatan sendiri, atau test terdokumentasi yang dirujuk ke katalog Atomic lewat ID/GUID, dengan isi test dan jejak yang diharapkan dijelaskan di tabel bagian 3.

## Ide inti

C2 dan exfiltration meninggalkan tiga bentuk jejak di data jaringan: keteraturan (beacon yang kembali pada interval yang mirip), pengodean di nama (data yang diselipkan di subdomain DNS), dan volume serta arah (lebih banyak byte keluar daripada yang wajar untuk host itu). Setiap bentuk hanya terlihat di sumber data yang dilewati trafiknya. Beacon lewat proxy terlihat di log proxy, tetapi tidak di firewall yang hanya melihat proxy sebagai sumber; DNS tunneling terlihat di log resolver, tetapi tidak bila program memakai DNS over HTTPS; unggahan dari laptop di rumah tidak terlihat di mana pun di data kantor bila VPN memakai split tunnel. Karena itu hunt C2 dan exfil adalah pekerjaan mencocokkan bentuk jejak ke sumber data, lalu menulis dengan jujur jalur mana yang tidak tercakup. Bentuk jejak itu juga dimiliki banyak layanan sah, jadi yang memutus jinak atau tidak adalah konteks tujuan: berapa host yang menghubunginya, siapa pemiliknya, sejak kapan tujuan itu terlihat, dan proses apa yang memanggilnya.

Polanya sama dengan membaca trafik pelanggan di NOC. Polling SNMP terjadwal dari sumber yang tidak dikenal adalah beacon: teratur, kecil, dan kembali ke tujuan yang sama. Lonjakan utilisasi upstream satu pelanggan dibanding profil hariannya adalah bentuk exfiltration: arahnya terbalik dari kebiasaan, karena pelanggan rumahan biasanya lebih banyak mengunduh. Dan pelanggan yang trafiknya lewat ISP lain tidak pernah muncul di NetFlow-mu, sebagus apa pun kolektornya. Batas analoginya ada tiga. Agent sah juga beacon, dan penyerang menambahkan jitter supaya intervalnya tidak rapi. Penyerang bisa memecah transfer menjadi pecahan kecil atau menumpang jam backup, sehingga volume yang terlihat normal tidak membuktikan tidak ada exfil. Dan berbeda dengan pelanggan yang pindah ISP karena alasan bisnis, penyerang sengaja memilih jalur yang tidak kamu lihat.

```
 bentuk jejak               sumber data yang melihatnya             yang TIDAK melihatnya
 ------------               ---------------------------             ---------------------
 keteraturan (beacon)  ---> proxy (src, dest), firewall (sesi),    trafik split tunnel,
                            Sysmon EID 3, MDE                       tunnel panjang (satu sesi)
 pengodean di nama     ---> log resolver, Sysmon EID 22            DoH, resolver luar
 volume dan arah       ---> proxy (%>st), firewall (bytes_out)     split tunnel, pecahan kecil
          |
          v
 konteks tujuan: prevalence | pemilik | first-seen | proses | ukuran | pola harian
          |
          v
 label: jinak terkonfirmasi | perlu investigasi (IR) | inkonklusif | data tidak cukup
          |
          v
 laporan + baseline tujuan diperbarui + celah data + sinyal risk (bukan alert langsung)
```

Situasi Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan, kantor pusat dan data center di Jakarta, dan POP regional di Bandung, Surabaya, dan Medan. SOC PT JAB memakai Splunk Enterprise dengan Enterprise Security (ES). Trafik web karyawan kantor Jakarta dan Bandung lewat proxy Squid eksplisit (`index=proxy`, retensi 30 hari), query DNS kantor lewat empat resolver internal (`index=dns`, retensi 30 hari), dan enam firewall Palo Alto mengirim log sesi ke `index=firewall`. Sejak Februari 2027 kamu (analyst L2) memegang Program hunt PT JAB setiap Selasa dan Kamis. Dua pekerjaan C2 menunggu di backlog: kandidat inkonklusif dari `HUNT-2027-005` (laptop sales Bandung `BDG-WS-0196` milik `rizal.siregar` yang menghubungi `api.statuspulse.example` di `198.51.100.77` tiap 1.800 detik lewat `msedge.exe`) dan hipotesis DNS tunneling `HUNT-2027-003` yang berstatus siap dijalankan sejak 4 Februari. Lalu Kamis 2027-02-25, `INC-2027-040` dinyatakan setelah sebuah hunt persistence menemukan laptop sales POP Surabaya `SBY-WS-0107` terinfeksi installer palsu yang dijalankan dari rumah, sehingga jejak awalnya tidak pernah lewat proxy maupun resolver PT JAB. Selasa 2027-03-09 pukul 08:05, Bambang Hartono, Manajer NOC, menulis di kanal SOC:

> "Mas, soal INC-2027-040: laptop Surabaya itu kena dari rumah dan tidak kelihatan di proxy. Anak NOC jadi tanya, sebenarnya data apa saja yang kita punya untuk lihat komunikasi keluar, dan apa yang tidak kelihatan? Palo Alto kita mencatat bytes per sesi, bisa tidak dipakai untuk lihat ada yang kirim data besar keluar, dan ambangnya dari mana? Satu lagi, laptop Bandung yang polling tiap 30 menit bulan lalu itu akhirnya apa?"

Pukul 08:30, SOC lead Dimas Prasetyo menambahkan:

> "Sekalian, hari ini tolong jalankan tiga hunt C2 dan exfil yang sudah antre: beacon lanjutan, DNS tunneling -003, dan volume keluar. Aku perlu tahu beacon seperti apa yang lolos dari hunt Februari, bagaimana DNS tunneling dicari dari data resolver, dan bagaimana membedakan semua ini dari layanan sah supaya tiap minggu tidak ada laptop sales yang dicurigai. Kalau ternyata ekstensi browser, apa ekstensinya perlu kita atur kebijakannya? Terakhir, ada yang layak jadi rule?"

Dua pesan itu memuat tujuh pertanyaan:

1. Data apa yang PT JAB punya untuk melihat komunikasi keluar, dan teknik C2 serta exfil mana yang bisa diburu dengannya?
2. Beacon seperti apa yang lolos dari hunt Februari, dan bagaimana menangkapnya?
3. Laptop Bandung itu akhirnya apa, dan apakah ekstensi browser perlu tindakan kebijakan?
4. Bagaimana memburu DNS tunneling dari data resolver?
5. Bisakah bytes firewall dan proxy dipakai untuk melihat data keluar besar, dan dari mana ambangnya?
6. Bagaimana membedakan semua pola ini dari layanan sah?
7. Apa yang tidak terlihat dari data kantor, dan apa yang layak dijadikan rule?

Pertanyaan 1 dijawab di bagian 1.1, 1.2, dan 1.3, pertanyaan 2 di bagian 1.4 dan 2.1, pertanyaan 3 di bagian 2.2, pertanyaan 4 di bagian 1.5 dan 2.3, pertanyaan 5 di bagian 1.6, 2.4, dan 2.5, pertanyaan 6 di bagian 1.7, dan pertanyaan 7 di bagian 1.8 dan 2.7. Bagian 2.6 memeriksa port tidak lazim, dan bagian 2.8 berisi laporan ketiga hunt (`HUNT-2027-020` sampai `-022`) plus jawaban untuk Bambang dan Dimas.

**Kapan relevan:** hunt terencana atas pola C2 dan exfil; setelah host mencurigakan ditemukan oleh hunt persistence, execution, atau lateral movement, untuk melihat komunikasi keluarnya; saat NOC atau pemilik sistem bertanya "trafik ini wajar atau tidak"; dan saat menilai apa yang bisa dan tidak bisa dikatakan SOC tentang exfil.
**Kapan bukan jawaban:** saat C2 sepenuhnya menumpang layanan sah populer yang dipakai ratusan host (pola jaringannya tidak bisa dibedakan tanpa data endpoint atau isi trafik); saat jalur keluarnya tidak tercatat sama sekali (split tunnel, DoH, host tanpa sensor), karena di sana hasilnya celah data, bukan "tidak ditemukan"; dan saat ada insiden aktif, karena mencari komunikasi keluar host yang sudah dikompromikan adalah scoping IR.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (hipotesis, ABLE, stacking, baseline, first-seen, prevalence, beacon, jitter, coefficient of variation, DNS tunneling, domain induk, allowlist) tidak diulang. Tabel ini memuat istilah baru yang dipakai Day ini; kolom kanan memakai padanan dari pekerjaan NOC dan SOC.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Command and control (C2) | Kanal komunikasi penyerang dengan sistem yang dikuasainya (TA0011) | Kanal manajemen out-of-band yang dipakai orang yang tidak berhak |
| Exfiltration | Mengeluarkan data dari jaringan korban (TA0010) | Trafik upstream pelanggan yang melonjak di luar profilnya |
| Non-standard port | Protokol dipasangkan dengan port yang tidak lazim untuknya (TLS di 8088) | Layanan yang dipindah ke port lain supaya lolos ACL |
| Protocol tunneling | Protokol dibungkus di dalam protokol lain | GRE atau tunnel di atas link pelanggan |
| Dynamic resolution | Malware menghitung domain, IP, atau port C2 secara dinamis | Failover ke alamat cadangan yang tidak tercantum di dokumentasi |
| Host-day | Satu baris ringkasan per host per hari (misalnya total byte keluar) | Utilisasi harian per port pelanggan |
| `bytes_out` / `bytes_in` | Byte arah klien ke server dan sebaliknya, menurut sumber log | Upstream dan downstream per pelanggan |
| Persentil (p95, p99) | Nilai yang dilampaui 5% atau 1% data | Ambang 95th percentile billing |
| Split tunnel | VPN yang hanya membawa trafik ke jaringan kantor; trafik internet langsung keluar dari jaringan pengguna | Pelanggan multihoming yang trafik internetnya lewat ISP lain |
| DNS over HTTPS (DoH) | Query DNS dibawa di dalam HTTPS, biasanya port 443 | Query yang tidak pernah sampai ke resolver ISP |
| Encrypted Client Hello (ECH) | Ekstensi TLS yang mengenkripsi ClientHello, termasuk nama server (SNI) | Header tujuan yang dienkripsi sehingga hanya terlihat alamat tepi |
| Ekstensi browser | Program tambahan yang berjalan di dalam browser dengan izin tertentu | Plugin di NMS yang punya akses ke data perangkat |
| Risk event | Catatan skor risiko untuk satu objek (host, user) yang dijumlahkan dengan sinyal lain sebelum menjadi alert | Alarm minor yang baru dieskalasi bila beberapa terkumpul di satu node |

### 1.1 Teknik C2 yang umum diburu

Pertanyaan pertama Bambang ("data apa yang kita punya") baru bisa dijawab setelah jelas apa yang dicari. Pada `INC-2026-026` tahun lalu, laptop Bandung `BDG-WS-0163` beacon 73 kali ke domain baru selama akhir pekan tanpa satu alert pun; itulah contoh C2 lewat protokol web yang menjadi pemicu banyak hunt di program ini.

Tabel berikut adalah teknik C2 yang paling sering diburu. Baca kolom "Sinyal yang diburu" dan "Data", karena keduanya menentukan sumber mana yang dibutuhkan; ID dan nama mengikuti ATT&CK v20.0 [S1][S6][S7][S8][S12][S13].

| Teknik | ID | Sinyal yang diburu | Data |
|---|---|---|---|
| Application Layer Protocol: Web Protocols | T1071.001 | Beaconing HTTP/S; user-agent tidak lazim; domain muda | Proxy, firewall, Zeek http/ssl, Sysmon EID 3 |
| Application Layer Protocol: DNS | T1071.004 | Query panjang/sering ke satu domain; tipe record tak lazim | Sysmon EID 22, DNS resolver, Zeek dns |
| Non-Standard Port | T1571 | Protokol di port tidak lazim (mis. TLS di port aneh) | Zeek, firewall, Sysmon EID 3 |
| Protocol Tunneling | T1572 | Protokol dibungkus protokol lain | Zeek, DNS, firewall |
| Encrypted Channel | T1573 | TLS ke tujuan tidak lazim; sertifikat aneh | Zeek ssl/x509 |
| Dynamic Resolution | T1568 | Banyak domain acak gagal di-resolve, IP berganti cepat | DNS resolver (perlu kode jawaban), Zeek dns |
| Ingress Tool Transfer | T1105 | Unduh tahap kedua lewat binary atau interpreter (Day 10, Day 13) | Sysmon EID 1/3, proxy |

Beberapa catatan dari halaman ATT&CK yang mengubah cara berburu:

- **T1071.001** menyebut HTTP/S dan WebSocket, dan menekankan bahwa banyak field dan header HTTP bisa dipakai menyembunyikan data, sehingga trafiknya mirip trafik web biasa [S6]. Detection strategy-nya, DET0027, memuat analytic yang mencari pola berulang mirip beacon atau POST berat ke domain langka dari klien HTTP non-browser [S6]. Artinya, beacon dari proses browser seperti kasus `BDG-WS-0196` justru di luar fokus analytic itu dan perlu penalaran konteks.
- **T1071.004** mencatat bahwa beacon DNS berkomunikasi jarang, sehingga sulit dibedakan dari resolusi nama biasa, dan beberapa malware memakai DoH untuk me-resolve infrastrukturnya [S7].
- **T1572** memberi contoh SSH tunneling dan menyebut DoH sebagai cara membungkus query DNS di dalam HTTPS, yang dipakai bersama Dynamic Resolution [S8].
- **T1571** memberi contoh HTTPS di port 8088 dan aktor yang memakai HTTP di port 808 dan 880 [S12]. Port tidak lazim baru bermakna bila protokolnya bisa dikenali, misalnya lewat identifikasi aplikasi di firewall.
- **T1568** memiliki tiga sub-teknik: Fast Flux DNS, Domain Generation Algorithms, dan DNS Calculation [S13]. Hunt DGA butuh rasio query gagal (NXDOMAIN), dan log resolver PT JAB tidak memuat kode jawaban (Day 04), jadi teknik ini di luar jangkauan hari ini.

Ciri inti C2: keteraturan (beacon), tujuan tidak lazim (domain baru, IP tak dikenal), dan kadang penyamaran (port atau protokol tidak biasa).

### 1.2 Teknik exfiltration yang umum diburu

Pertanyaan Bambang tentang "kirim data besar keluar" adalah pertanyaan exfiltration. Tabel berikut memuat teknik yang paling sering diburu; baca kolom "Sinyal", karena di sana terlihat bahwa tidak semua exfil berbentuk volume besar [S1][S9][S10][S11].

| Teknik | ID | Sinyal yang diburu | Data |
|---|---|---|---|
| Exfiltration Over C2 Channel | T1041 | Volume keluar besar di kanal C2 yang sama | Zeek conn, firewall bytes, proxy |
| Exfiltration Over Alternative Protocol | T1048 | Data keluar lewat DNS/ICMP/protokol lain | Sysmon EID 22, resolver, Zeek, firewall |
| Exfiltration Over Web Service | T1567 | Unggahan besar ke layanan cloud/web | Proxy, Zeek http |
| Data Transfer Size Limits | T1030 | Pecahan kecil berulang (menghindari ambang) | Zeek conn, firewall, proxy |

Tiga hal dari halaman teknik yang perlu diingat saat menulis hipotesis:

- **T1041** mendefinisikan pencurian data lewat kanal C2 yang sudah ada, dengan data dikodekan supaya menyatu dengan trafik C2 [S10]. Detection strategy DET0348 mencari volume keluar yang tidak cocok dengan prosesnya, terutama setelah ada akses file, dengan parameter yang disetel per lingkungan seperti ambang volume dan daftar proses yang sah mengirim banyak data (misalnya updater) [S10].
- **T1048** adalah exfil lewat protokol selain kanal C2 atau ke lokasi selain server C2, dengan tiga sub-teknik berdasarkan enkripsi (simetris, asimetris, tidak terenkripsi) [S9]. Inilah sebabnya `HUNT-2027-003` memetakan DNS tunneling ke T1048 bila kanal exfil-nya terpisah dari C2, dan ke T1041 bila lewat kanal C2 yang sama.
- **T1567** memakai layanan web sah yang sudah dihubungi host dan sudah diizinkan firewall, dengan isi terlindung TLS penyedia; sub-tekniknya Exfiltration to Code Repository, to Cloud Storage, to Text Storage Sites, dan Over Webhook [S11]. Unggahan karyawan ke layanan seperti itu adalah false positive paling umum untuk hunt volume.

Ciri inti exfiltration: volume keluar yang tidak wajar untuk host itu, atau pola pecahan kecil yang menghindari ambang. Analisis volumetrik (Day 05 bagian 1.5) adalah alat utamanya.

### 1.3 Data jaringan PT JAB dan celahnya

Inti pertanyaan Bambang ada di sini. Jawabannya bukan daftar index, tetapi "sumber mana melihat jalur mana". Di PT JAB, satu koneksi dari laptop Jakarta ke internet melewati proxy eksplisit, lalu keluar lewat firewall data center dengan proxy sebagai sumbernya. Firewall tidak pernah melihat IP laptop itu untuk trafik web.

Tabel berikut memetakan sumber ke apa yang diberikannya. Baca kolom "Catatan dan batas", karena di sanalah jawaban "apa yang tidak kelihatan".

| Sumber | Memberi | Catatan dan batas |
|---|---|---|
| Sysmon EID 3 | Koneksi per proses (siapa menghubungi apa) | Field `Image`, `DestinationIp`, `DestinationPort`, `DestinationHostname`; tidak melihat isi; konfigurasi biasanya memfilter proses berisik karena volumenya besar [S2]. Di PT JAB 198 host; dengan proxy eksplisit, tujuan workstation hanya terlihat sebagai proxy (Day 05 bagian 2.3) |
| Sysmon EID 22 | Query DNS per proses | Kuat untuk DNS tunneling; field `Image`, `QueryName`, `QueryStatus`, `QueryResults`; dicatat lewat klien DNS Windows, jadi proses yang memakai resolver sendiri bisa lolos [S2]. Di PT JAB 186 host |
| Log resolver (`index=dns`) | Semua query DNS dari klien resolver internal | Tanpa konteks proses, tanpa kode jawaban (tidak ada rasio NXDOMAIN); 30 hari |
| Proxy Squid (`index=proxy`) | Host tujuan, metode, byte, durasi per IP klien kantor Jakarta dan Bandung | Tanpa nama proses; HTTPS tanpa inspeksi TLS hanya tercatat sebagai CONNECT ke host dan port; 30 hari. Kolom `bytes` adalah data yang dikirim ke klien [S26]; volume unggahan butuh kode `%>st` di logformat (bagian 2.4) |
| Firewall Palo Alto (`index=firewall`, `pan:traffic`) | Sesi per IP sumber dan tujuan, port, aplikasi, byte per arah | Untuk trafik web kantor Jakarta dan Bandung, sumbernya adalah proxy; IP workstation hanya terlihat untuk trafik yang tidak lewat proxy, misalnya workstation POP Surabaya dan Medan yang keluar lewat firewall POP masing-masing, dan server data center |
| MDE (`DeviceNetworkEvents`, portal) | Koneksi per proses di workstation Jakarta dan Bandung, di mana pun laptop berada | 30 hari; terpisah dari Splunk; tidak ada di 23 workstation POP Surabaya dan Medan |
| Zeek | conn, dns, http, ssl, x509 (metadata kaya) | Butuh sensor jaringan; PT JAB tidak punya, jadi semua contoh Zeek di Day ini untuk lab |
| VPN GlobalProtect (`index=vpn`) | Siapa tersambung dari luar, kapan, dari IP publik mana | Split tunnel: isi trafik internet laptop di luar kantor tidak tercatat di mana pun |

Byte di firewall punya arah yang jelas di sisi vendor. Di log traffic PAN-OS, `Bytes Sent` adalah byte arah klien ke server, `Bytes Received` arah sebaliknya, dan `Bytes` jumlah keduanya; subtype log membedakan `start`, `end`, `drop`, dan `deny` [S22]. Di data model CIM Network Traffic, `bytes_in` dan `bytes_out` didefinisikan dari sudut pandang perangkat pelapor, dan `bytes` adalah jumlah keduanya [S23]. Add-on Splunk untuk Palo Alto memetakan `pan:traffic` ke data model Network Traffic dan menyediakan eventtype terpisah untuk log awal dan akhir sesi (`pan_traffic_start`, `pan_traffic_end`) [S24]. Konsekuensinya: menjumlahkan byte dari log awal dan akhir sesi sekaligus bisa menghitung dua kali, dan arah `bytes_out` di add-on-mu perlu dicek sekali dengan transfer uji sebelum dipakai untuk exfil.

Kesimpulan untuk Bambang: data PT JAB cukup untuk beacon lewat proxy, beacon langsung lewat firewall, DNS tunneling lewat resolver, dan volume keluar dari server serta workstation POP. Volume unggahan per workstation Jakarta dan Bandung hanya terukur bila proxy mencatat ukuran request. Yang tidak terlihat sama sekali dibahas di bagian 1.8.

### 1.4 Pola hunting C2: beaconing dan ambang yang diselaraskan

Pertanyaan Dimas "beacon seperti apa yang lolos dari hunt Februari" dijawab dengan membaca ulang batas `HUNT-2027-005`. Hunt itu hanya membaca 7 hari proxy, mensyaratkan minimal 100 koneksi dan aktif di minimal 24 jam berbeda, dan menulis di luar cakupan: beacon dengan interval di atas satu jam, trafik yang tidak lewat proxy, server, dan POP selain Jakarta dan Bandung (Day 05 bagian 2.1).

Beacon adalah koneksi berulang ke tujuan yang sama pada interval teratur. Hunt beaconing punya tiga langkah:

1. Kelompokkan per pasangan sumber-tujuan.
2. Hitung jumlah koneksi dan keteraturan interval (deviasi standar relatif terhadap rata-rata, yaitu CV).
3. Saring polling sah (update, telemetri, sinkronisasi) dengan daftar tujuan yang dikenal.

Hitungan sederhana memperlihatkan beacon yang lolos. Beacon tiap 4 jam di workstation yang menyala sekitar sembilan jam per hari kerja menghasilkan dua sampai tiga koneksi per hari, atau sekitar 40 sampai 57 dalam empat minggu kerja, dan paling banyak 15 dalam seminggu. Ambang 100 koneksi per minggu tidak pernah tersentuh. Karena itu hunt lanjutan memakai jendela 28 hari, ambang jumlah koneksi yang jauh lebih rendah, batas atas interval 4 jam, dan membatasi diri ke tujuan berprevalence rendah supaya daftar kandidat tetap bisa ditinjau (bagian 2.1).

Jitter (variasi interval yang disengaja) membuat deviasi standar naik dan bisa membuat beacon lolos. Versi lama Day ini memakai syarat `sd_int < avg_int*0.15` (CV di bawah 0,15). Program hunt PT JAB sejak Day 05 memakai CV maksimal 0,2 setelah membuang jeda yang lebih panjang dari tiga kali median, dan Day ini diselaraskan ke angka itu. Alasannya ada tiga:

- **Margin terlalu tipis.** Deret beacon 300 detik dengan jitter sekitar 20% di Day 05 bagian 1.5 punya CV 0,132. Angka itu memang di bawah 0,15, tetapi selisihnya hanya 0,018. CV yang dihitung dari sampel ikut berfluktuasi, dan sedikit jitter tambahan sudah mendorongnya melewati batas.
- **Hitungannya bisa diperiksa.** Bila jitter tersebar merata sampai plus minus j dari interval, deviasi standarnya sekitar j dibagi akar 3, sehingga CV sekitar j/1,732. Jitter plus minus 20% memberi CV sekitar 0,115, jitter plus minus 26% sudah sekitar 0,150, dan ambang 0,2 baru dilewati pada jitter sekitar plus minus 35% (0,35/1,732 = 0,202). Angka 0,132 di deret Day 05 sedikit di atas teori 0,115 karena hanya 10 interval.
- **Satu ambang untuk satu program.** Laporan mingguan beacon (usulan Day 05) dan hunt ini harus bisa dibandingkan. Dua ambang berbeda untuk pertanyaan yang sama membuat "tidak ditemukan" di satu laporan tidak berarti apa-apa di laporan lain.

Tanpa membuang jeda, ambang apa pun tidak berguna: satu jeda malam membuat deret yang rapi tampak sangat tidak teratur (CV 2,984 pada deret C Day 05). Trade-off tetap berlaku: ambang yang lebih longgar menangkap beacon berjitter tetapi menambah false positive dari polling sah, dan pembedanya ada di konteks (bagian 1.7), bukan di ambang.

Alat yang matang menggabungkan keteraturan dengan sinyal lain. RITA (Real Intelligence Threat Analytics) dari Active Countermeasures menganalisis log Zeek untuk beaconing, koneksi yang berlangsung sangat lama (long connection), DNS tunneling, dan kecocokan dengan feed threat intel [S16]; skor beacon-nya menggabungkan keteraturan waktu, keteraturan ukuran, durasi, dan pola per jam (Day 05 bagian 1.6). Long connection adalah sisi lain dari beacon: C2 yang memakai satu sesi panjang tidak teratur karena memang hanya satu koneksi, dan di proxy tanpa inspeksi TLS ia hanya muncul sebagai satu baris CONNECT.

### 1.5 Pola hunting C2: DNS tunneling

Pertanyaan keempat Dimas sudah separuh dijawab di Februari: `HUNT-2027-003` sudah punya abstract, ABLE, dan cek Evidence (Day 03 bagian 2.3 sampai 2.6). Yang tersisa adalah menjalankannya pada rentang 28 hari dan membaca hasilnya.

DNS tunneling membawa data dalam subdomain. Sinyalnya:

- Query luar biasa panjang (subdomain base64/hex).
- Frekuensi tinggi ke satu domain induk.
- Tipe record tidak lazim (TXT, NULL) dalam volume.
- Entropi tinggi pada nama query.

Hunt: stacking domain induk dengan jumlah query, jumlah subdomain unik, dan panjang rata-rata; yang panjang dan sering menonjol. FP: layanan sah yang memang memakai DNS intensif (beberapa CDN, antivirus, telemetri, layanan reputasi email).

Dua hal yang diperketat dari Februari:

- **Dua jalur ambang.** Ambang volume (`unique_sub > 200 AND avg_sub_len > 30`) menangkap tunneling yang ramai. Exfil yang lambat tetapi panjang, misalnya puluhan subdomain mendekati batas 63 karakter per label dari satu atau dua klien selama sebulan, butuh jalur kedua: banyak subdomain unik dalam jumlah kecil, panjang maksimum tinggi, dan klien sedikit.
- **Pembanding dari baseline.** Agregat domain induk 7 Januari sampai 4 Februari yang disimpan di `jab_hunt_baseline_dns_parent.csv` (Day 03 bagian 2.6) dipakai untuk melihat apakah sebuah domain induk sudah berpola sama sebelumnya. Pola yang stabil sejak Januari dari klien yang sama lebih mungkin layanan; domain induk yang baru muncul layak ditinjau lebih dulu.

Allowlist tetap sempit: kombinasi domain induk dan klien, bukan domain induk saja, supaya host lain yang tiba-tiba memakai domain yang sama tetap muncul.

### 1.6 Pola hunting exfiltration: volumetrik dan ambang dari distribusi

Pertanyaan kelima Bambang ("ambangnya dari mana") adalah pertanyaan tentang distribusi. Versi lama Day ini memakai ambang tetap 100 MB keluar dan rasio keluar-masuk di atas 3 sebagai asumsi; di PT JAB angka itu diganti dengan ambang yang dihitung dari data.

Empat pola volumetrik yang diburu:

1. **Volume keluar per host.** Jumlahkan byte keluar per host per hari; host yang jauh di atas baseline-nya ditinjau.
2. **Rasio keluar-masuk.** Host yang mengirim jauh lebih banyak daripada menerima (tidak lazim untuk workstation).
3. **Tujuan tunggal besar.** Banyak data ke satu tujuan eksternal yang tidak dikenal, apalagi yang baru pertama terlihat.
4. **Pecahan berulang.** Banyak koneksi kecil berukuran serupa ke satu tujuan (menghindari ambang, T1030).

Ambang dari distribusi bekerja dalam dua lapis:

- **Lapis global.** Hitung total byte keluar per host-day untuk seluruh host dalam rentang, lalu ambil p99. Nilai di atas p99 adalah 1% host-day teratas. Lapis ini memastikan yang ditinjau memang besar menurut ukuran PT JAB, bukan menurut tebakan.
- **Lapis per host.** p99 global saja menandai host yang memang selalu besar, misalnya server backup yang mengirim salinan setiap malam. Karena itu host-day juga harus melampaui kelipatan median host itu sendiri (di PT JAB tiga kali median). Menghitung p99 per host juga mungkin, tetapi dengan sekitar 20 hari aktif per host dalam 28 hari, p99 per host praktis sama dengan nilai maksimumnya dan tidak memberi pembanding; median per host lebih stabil.

Lapis per host punya kelemahan yang harus ditulis: host yang baru aktif satu atau dua hari tidak punya median yang bermakna, karena host-day itu sendiri menjadi median-nya. Host seperti itu ditinjau terpisah bila melampaui p99 global.

Volumetrik butuh data byte dengan arah yang benar. Tanpa itu, exfil besar sulit diburu dari endpoint saja; itu celah visibilitas yang penting dicatat. Sysmon EID 3 tidak memberi byte, dan proxy Squid format native hanya mencatat data yang dikirim ke klien [S26]. Logformat Squid punya kode terpisah untuk ukuran request yang diterima dari klien (`%>st`), ukuran balasan ke klien (`%<st`), dan jumlah keduanya (`%st`); format native memakai `%<st` [S25].

### 1.7 Konteks: domain, tujuan, dan membedakan dari layanan sah

Pertanyaan keenam Dimas ("supaya tidak tiap minggu laptop sales dicurigai") dijawab dengan konteks. Day 05 bagian 1.6 sudah memuat tabel sinyal yang membedakan beacon dari agent sah: prevalence, pemilik, ukuran data, proses pemanggil, umur dan reputasi tujuan, dan pola harian. Day ini menerapkannya ke C2 dan exfil sekaligus.

Hunting C2/exfil menguat dengan konteks tujuan:

- Umur domain (domain yang baru didaftarkan lebih mencurigakan).
- Reputasi IP/domain dari feed threat intel atau layanan reputasi (dipakai sebagai konteks, bukan vonis: domain bersih di feed belum tentu aman).
- Apakah tujuan pernah dihubungi sebelumnya (first-seen, Day 05 bagian 1.3).
- Geografi dan ASN yang tidak lazim untuk organisasi.

Konteks ini mengubah "koneksi keluar" menjadi "koneksi keluar ke tujuan yang baru, muda, dan tak bereputasi", yang jauh lebih bermakna.

Untuk beacon dari proses browser, satu konteks tambahan menentukan: ekstensi mana yang memanggil dan izin apa yang dimilikinya. ATT&CK v20 mencatat ekstensi browser di bawah T1176 Software Extensions, sub-teknik T1176.001 Browser Extensions, di taktik Persistence [S14]. Ekstensi berbahaya bisa menjelajah situs di latar belakang, mencuri data yang diketik di browser termasuk kredensial, menjadi installer remote access tool, dan mengubah setelan keamanan browser; botnet juga pernah memakai backdoor berbentuk ekstensi Chrome untuk C2 [S14]. Ekstensi bisa masuk lewat toko resmi dengan menyamar sebagai ekstensi sah, lewat file lokal atau URL update yang diubah, atau lewat modifikasi file Preferences browser Chromium saat browser tertutup [S14]. Detection strategy DET0044 untuk Windows mengaitkan pemasangan ekstensi baru dengan penulisan file oleh proses browser dan koneksi keluar ke domain yang tidak tepercaya, memakai Sysmon EID 11, 3, 22, 13, dan 14 serta Security 4688 [S14].

Dari situ, ekstensi yang beacon dinilai dengan empat pertanyaan: apakah pengguna mengakui memasangnya dan untuk apa; apakah ekstensi itu berasal dari toko resmi dengan penerbit yang cocok; izin apa yang dimintanya (izin sempit hanya ke API-nya sendiri sangat berbeda dengan izin membaca semua halaman); dan apakah ada host lain yang memakainya. Bagian 2.2 menerapkannya ke `BDG-WS-0196`.

Konteks ini tidak memberi vonis sendirian. Penyerang yang menumpang layanan sah dengan prevalence tinggi akan lolos semua penyaring di atas; itulah batas pertama di bagian "Kapan bukan jawaban".

### 1.8 Yang tidak terlihat dari data kantor: split tunnel, DoH, dan ECH

Pertanyaan terakhir Bambang lahir dari `INC-2027-040`: installer di `SBY-WS-0107` dijalankan dari rumah, dan selama laptop di luar kantor trafiknya tidak pernah lewat proxy maupun resolver PT JAB. Ada tiga jalur yang membuat hunt C2 dan exfil buta, dan ketiganya harus ditulis di setiap laporan.

**Split tunnel.** GlobalProtect PT JAB hanya membawa trafik ke jaringan kantor. Trafik internet dan query DNS untuk domain publik dari laptop di luar kantor keluar langsung dari jaringan rumah atau seluler pengguna. Proxy, resolver, dan firewall PT JAB tidak melihatnya; log VPN hanya memberi tahu bahwa laptop itu tersambung. Untuk workstation Jakarta dan Bandung, MDE tetap mencatat koneksi per proses di mana pun laptop berada, sehingga hunt di advanced hunting MDE menjadi satu-satunya jalur untuk periode di luar kantor (dengan retensi 30 hari). Untuk 23 workstation POP Surabaya dan Medan tanpa MDE dan tanpa Sysmon, tidak ada jalur sama sekali; Velociraptor hanya memberi keadaan host saat ini, bukan riwayat koneksinya.

**DNS over HTTPS.** DoH membawa query dan jawaban DNS di dalam HTTPS, dengan media type `application/dns-message`, dan skema https mengimplikasikan port 443 [S17]. RFC 8484 menyebut bahwa memakai port 443 dan berbagi koneksi dengan trafik HTTPS lain membuat perangkat di jalur lebih sulit mengganggu dan menganalisis DNS [S17]. Dari sisi hunter: program yang memakai DoH tidak pernah muncul di log resolver, sehingga hunt DNS tunneling buta terhadapnya. ATT&CK mencatat malware yang memakai DoH untuk me-resolve infrastruktur C2-nya [S7][S8]. Di jaringan kantor PT JAB, DoH dari browser lewat proxy sebagai CONNECT ke host resolver DoH, sehingga yang bisa diburu adalah daftar host resolver DoH yang dikenal, bukan isi query-nya. Untuk Microsoft Edge, kebijakan `DnsOverHttpsMode` punya tiga nilai (`off`, `automatic`, `secure`), dan pada perangkat terkelola yang tidak mengatur kebijakan ini Edge tidak mengirim query DoH [S19]. Browser lain dan malware punya perilaku sendiri, jadi kebijakan Edge saja tidak menutup celah ini.

**Encrypted Client Hello.** RFC 9849 (Maret 2026) mengenkripsi seluruh ClientHello bagian dalam, termasuk SNI, ke kunci publik server di sisi klien [S18]. Pengamat pasif masih melihat ClientHello luar dengan `public_name` milik server penerima di SNI luarnya, alamat IP server, dan query DNS yang tidak terenkripsi; ECH hanya menyembunyikan tujuan di antara situs lain yang berbagi penyedia yang sama [S18]. Konfigurasi ECH dipublikasikan lewat DNS, di record SVCB dan HTTPS [S18]. Dampaknya berbeda per jalur. Di proxy eksplisit PT JAB, browser tetap menyebut host tujuan di permintaan CONNECT, sehingga log proxy tetap berguna. Di jalur tanpa proxy (server data center, workstation POP), identifikasi aplikasi dan kategori URL di firewall yang bergantung pada SNI akan melihat nama penyedia, bukan situs tujuan; cek perilaku firewall-mu terhadap ECH di dokumentasi vendornya.

Batas ini mengubah cara melaporkan. "Tidak ditemukan exfil" di laporan hari ini hanya berlaku untuk trafik kantor yang lewat proxy dan firewall PT JAB; untuk laptop di luar kantor, hasilnya "data tidak cukup", bukan "bersih".

## 2. Contoh dan langkah praktis: tiga hunt hari Selasa

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Query ditulis untuk Splunk PT JAB; untuk latihan, jalankan versi yang disesuaikan di lab pribadi (bagian 3). Semua domain eksternal memakai akhiran `.example` atau `.example.net`, dan semua IP eksternal dari rentang dokumentasi.

**Asumsi data proxy:** sama dengan Day 05: `index=proxy sourcetype=squid:access`, field `src`, `dest` (host tujuan; untuk CONNECT tanpa port), `bytes` (ukuran balasan ke klien), `duration` (milidetik), `http_method`, `user`, `http_user_agent`. Field `bytes_out` dari kode `%>st` diperiksa di bagian 2.4.

**Asumsi data firewall:** `index=firewall sourcetype=pan:traffic`, diparsing add-on Splunk untuk Palo Alto ke nama CIM: `src`, `dest`, `dest_port`, `app`, `action`, `bytes_out`, `bytes_in`, `duration` (detik). Cek nama field dan arah byte di versi add-on-mu.

**Lookup bantu:** `jab_hunt_egress_infra.csv` (kolom `ip`, `name`, `role`) memuat IP tiga server proxy (`jkt-proxy01`, `jkt-proxy02`, `bdg-proxy01`), empat resolver, dan mail gateway `jkt-mailgw01` (`10.20.2.25`). Lookup ini dipakai untuk membuang sumber yang memang mewakili banyak klien dari analisis firewall.

### 2.1 `HUNT-2027-020`: beacon lanjutan di luar ambang Februari

Hunt ini menjawab pertanyaan kedua Dimas sekaligus menutup kandidat inkonklusif `HUNT-2027-005`. Abstract-nya ditulis pukul 08:50, setelah pesan Dimas.

```
ID             : HUNT-2027-020
Dibuat         : 2027-03-09 (Selasa) 08:50, pemilik: <kamu>, reviewer: Dimas Prasetyo
Trigger        : Lanjutan HUNT-2027-005 (di luar cakupan: interval > 1 jam, non-proxy, server, POP)
                 + kandidat inkonklusif BDG-WS-0196 + backlog "beacon ke domain baru" (INC-2026-026)
Tipe (PEAK)    : Baseline (analisis frekuensi), dilanjutkan hypothesis-driven per kandidat
Hipotesis      : Ada host PT JAB yang berkomunikasi ke tujuan eksternal berprevalence rendah dengan
                 interval teratur antara 30 detik dan 4 jam, lewat proxy atau langsung lewat firewall,
                 dan tujuan itu tidak dimiliki layanan atau agent yang dikenal.
ATT&CK         : T1071.001 Web Protocols; T1571 Non-Standard Port bila port tidak cocok dengan aplikasi;
                 T1176.001 Browser Extensions bila pemanggilnya ekstensi browser
Data           : index=proxy (src 10.10.0.0/16, 10.30.0.0/16) dan index=firewall pan:traffic (semua
                 sumber internal kecuali proxy, resolver, mail gateway), Selasa 2027-02-09 00:00
                 sampai Selasa 2027-03-09 00:00 WIB (28 hari); MDE dan Velociraptor untuk pivot proses
Di luar cakupan: laptop di luar kantor (split tunnel), interval > 4 jam, tujuan dengan dest_hosts > 10,
                 C2 dalam satu sesi panjang, DoH
Kriteria sukses: Semua pasangan yang lolos tahap B ditinjau dan diberi label; BDG-WS-0196 ditutup
                 dengan label akhir
FP diketahui   : Heartbeat lisensi, agent perangkat, aplikasi SaaS desktop, ekstensi browser
Handover       : IR (Dimas) bila ditemukan; Sari Kusuma untuk usulan sinyal risk;
                 Agung Prabowo untuk perangkat data center yang punya akses internet langsung
Target selesai : Selasa 2027-03-09
```

**Tujuan tahap A:** mengurangi semua pasangan `src` dan `dest` selama 28 hari menjadi kandidat berprevalence rendah yang punya cukup koneksi untuk diukur, sambil membuang tujuan polling yang sudah dikenal.

```
index=proxy sourcetype=squid:access
    earliest="02/09/2027:00:00:00" latest="03/09/2027:00:00:00"
    (src=10.10.0.0/16 OR src=10.30.0.0/16)
| bin span=1h _time AS hour
| stats count AS conns dc(hour) AS hours_seen min(_time) AS first_seen BY src dest
| eventstats dc(src) AS dest_hosts BY dest
| where dest_hosts <= 10 AND conns >= 20 AND hours_seen >= 12
| lookup jab_hunt_baseline_beacon.csv dest OUTPUT owner
| where isnull(owner)
| outputlookup override_if_empty=false jab_hunt_020_candidates.csv
```

Tabel berikut menjelaskan bagian yang berbeda dari tahap A `HUNT-2027-005`.

| Bagian | Fungsi |
|---|---|
| `earliest="02/09/2027:00:00:00" latest="03/09/2027:00:00:00"` | 28 hari absolut; dengan retensi proxy 30 hari, rentang ini masih utuh hari ini |
| `min(_time) AS first_seen` | Kapan pasangan pertama terlihat di rentang, untuk konteks "baru" |
| `where dest_hosts <= 10` | Hanya tujuan berprevalence rendah. Dipasang setelah `eventstats` supaya prevalence dihitung dari semua pasangan |
| `conns >= 20 AND hours_seen >= 12` | Jauh lebih rendah dari Februari (100 dan 24), supaya beacon tiap 4 jam di workstation ikut masuk |
| `lookup jab_hunt_baseline_beacon.csv dest OUTPUT owner` | Tujuan polling teratur yang sudah dikonfirmasi pemiliknya (dibuat di `HUNT-2027-005`) dibuang |
| `outputlookup override_if_empty=false ...` | Kandidat disimpan untuk tahap B; file lama tidak dihapus bila hasil kosong |

Keluaran ilustrasi (ringkas):

```
Event proxy dari 10.10.0.0/16 dan 10.30.0.0/16        : 233.871.096
Host sumber unik (IP)                                  : 368
Pasangan src-dest unik                                 : 401.233
Pasangan lolos tahap A (setelah baseline beacon dibuang) : 1.212
```

**Tujuan tahap B:** mengukur keteraturan 1.212 kandidat dengan cara yang sama persis dengan Day 05 bagian 2.2, ditambah batas atas interval.

```
index=proxy sourcetype=squid:access
    earliest="02/09/2027:00:00:00" latest="03/09/2027:00:00:00"
    [| inputlookup jab_hunt_020_candidates.csv | fields src dest]
| eval start=_time-(duration/1000)
| sort 0 src dest start
| streamstats current=f last(start) AS prev_start BY src dest
| eval delta=round(start-prev_start, 1)
| where isnotnull(delta)
| eventstats median(delta) AS med_int BY src dest
| where delta <= 3*med_int
| stats count AS intervals avg(delta) AS avg_int stdev(delta) AS sd_int
        avg(bytes) AS avg_bytes max(med_int) AS med_int BY src dest
| eval cv=round(sd_int/avg_int, 3)
| where med_int >= 30 AND med_int <= 14400 AND cv <= 0.2
| lookup jab_hunt_020_candidates.csv src dest OUTPUT conns hours_seen dest_hosts first_seen
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M")
| sort dest_hosts cv
```

| Bagian | Fungsi |
|---|---|
| `[\| inputlookup jab_hunt_020_candidates.csv \| fields src dest]` | Subsearch yang mengubah kandidat menjadi filter; 1.212 baris masih di bawah batas default subsearch 10.000 hasil |
| `eval start=_time-(duration/1000)` | Squid mencatat waktu selesai; waktu mulai diperkirakan dari durasi (Day 05 bagian 1.5) |
| `eventstats median(delta) ...` lalu `where delta <= 3*med_int` | Membuang jeda malam, akhir pekan, dan laptop dibawa pulang |
| `where med_int >= 30 AND med_int <= 14400 AND cv <= 0.2` | Interval 30 detik sampai 4 jam, CV maksimal 0,2 (ambang program, bagian 1.4) |
| `strftime(first_seen, ...)` | Mengubah epoch menjadi tanggal untuk dibaca bersama hasil |

Keluaran ilustrasi, diringkas per tujuan dengan `| stats count AS pairs max(dest_hosts) AS dest_hosts median(med_int) AS med_int median(cv) AS med_cv BY dest`:

```
dest                       pairs  dest_hosts  med_int  med_cv
api.statuspulse.example        1           1     1800   0.070
lic.fiberplan.example          4           4     3600   0.010
push.kanbanapp.example         2           2      900   0.040
```

Satu baris per tujuan, mewakili tiap kelompok:

```
src          dest                     conns  hours_seen  med_int  avg_int  sd_int  cv     avg_bytes  dest_hosts  first_seen
10.30.12.54  api.statuspulse.example    583         296     1800   1797.9   125.9  0.070       5907           1  2027-02-15 08:47
10.10.61.11  lic.fiberplan.example      176         171     3600   3601.4    36.0  0.010       1214           4  2027-02-09 08:12
10.10.51.18  push.kanbanapp.example     412         109      900    902.3    36.1  0.040        822           2  2027-02-22 10:31
```

**Cara membaca hasil:**

- **Tujuh pasangan di tiga tujuan.** Tidak satu pun berprevalence lebih dari 4 host, dan semuanya lolos karena ambang yang dilonggarkan: `lic.fiberplan.example` beacon tiap 3.600 detik hanya selama aplikasinya terbuka, sehingga dalam seminggu jumlah koneksinya di bawah 100; `push.kanbanapp.example` baru muncul 22 Februari, setelah jendela `HUNT-2027-005`.
- **`lic.fiberplan.example`.** Empat workstation tim Network Planning Jakarta (`JKT-WS-0611`, `JKT-WS-0614`, `JKT-WS-0619`, `JKT-WS-0623`) menjalankan aplikasi perencanaan jaringan fiber yang mengirim heartbeat lisensi tiap jam. Host-host itu ber-Sysmon, tetapi karena proxy eksplisit Sysmon hanya melihat koneksi ke proxy; pencocokan waktu dengan log proxy menunjuk ke proses aplikasi itu di `Program Files`, bertanda tangan vendornya, sesuai tiket pengadaan lisensi tim IT. Label: jinak.
- **`push.kanbanapp.example`.** Dua workstation Marketing (`JKT-WS-0388`, `JKT-WS-0392`) memakai aplikasi desktop papan proyek yang dipasang lewat permintaan software 22 Februari; aplikasi itu memeriksa notifikasi tiap 15 menit. Pemilik dan tiketnya jelas. Label: jinak. Pasangan ini penting untuk bagian 2.7: tujuan baru, teratur, prevalence rendah, dan tetap sah.
- **`api.statuspulse.example`.** Laptop `BDG-WS-0196` kembali tersambung sejak Senin 15 Februari dan polanya tidak berubah: 1.800 detik, ukuran seragam sekitar 5,9 KB, CV 0,07. Penutupannya dibahas di bagian 2.2.

**Variasi 1, firewall (trafik yang tidak lewat proxy).** Tahap A dan B yang sama dijalankan di `pan:traffic`, dengan pasangan `src`, `dest`, dan `dest_port`. Hanya log akhir sesi yang dibaca supaya satu sesi tidak terhitung dua kali, dan sumber yang mewakili banyak klien dibuang:

```
index=firewall sourcetype=pan:traffic eventtype=pan_traffic_end
    earliest="02/09/2027:00:00:00" latest="03/09/2027:00:00:00"
    NOT dest=10.0.0.0/8 NOT dest=172.16.0.0/12 NOT dest=192.168.0.0/16
| lookup jab_hunt_egress_infra.csv ip AS src OUTPUT role
| where isnull(role)
| eval start=_time-duration
| bin span=1h start AS hour
| stats count AS conns dc(hour) AS hours_seen values(app) AS apps BY src dest dest_port
| eventstats dc(src) AS dest_hosts BY dest
| where dest_hosts <= 10 AND conns >= 20 AND hours_seen >= 12
```

Tahap B untuk firewall sama dengan tahap B proxy, dengan `start=_time-duration` (CIM `duration` dalam detik) dan `BY src dest dest_port`. Keluaran ilustrasi tahap B: dua pasangan.

```
src          dest          dest_port  apps  conns  med_int  cv     dest_hosts
10.20.8.37   203.0.113.61       8883  ssl     672     3600  0.002           2
10.20.8.38   203.0.113.61       8883  ssl     672     3600  0.002           2
```

Kedua sumber adalah `jkt-pdu07` dan `jkt-pdu08`, power distribution unit di rak data center, yang melapor ke cloud vendornya (`telemetry.pduvendor.example` di `index=dns`) tiap jam lewat TLS di port 8883. 672 koneksi sama dengan 28 hari kali 24 jam: perangkat menyala terus. Pemiliknya tim Fasilitas data center, dan fungsinya sesuai dokumentasi perangkat. Label: jinak. Catatan ke Agung: perangkat manajemen di data center punya akses internet langsung tanpa proxy; itu keputusan segmentasi, bukan temuan hunt, tetapi layak masuk tiket.

**Variasi 2, Sysmon EID 3 (host yang terhubung langsung, dan lab).** Untuk host yang tidak memakai proxy, beacon bisa diukur langsung dari Sysmon. Ini versi yang diselaraskan dari query lama Day ini (jeda dibuang, CV maksimal 0,2):

```
index=sysmon EventCode=3
    earliest="02/09/2027:00:00:00" latest="03/09/2027:00:00:00"
    NOT DestinationIp=10.0.0.0/8 NOT DestinationIp=172.16.0.0/12 NOT DestinationIp=192.168.0.0/16
| sort 0 host DestinationIp _time
| streamstats current=f last(_time) AS prev BY host DestinationIp
| eval delta=_time-prev
| where isnotnull(delta)
| eventstats median(delta) AS med_int BY host DestinationIp
| where delta <= 3*med_int
| stats count AS intervals avg(delta) AS avg_int stdev(delta) AS sd_int max(med_int) AS med_int
        values(DestinationPort) AS ports values(Image) AS images BY host DestinationIp
| eval cv=round(sd_int/avg_int, 3)
| where intervals >= 50 AND med_int >= 30 AND cv <= 0.2
| sort - intervals
```

- Filter CIDR di command `search` membuang tujuan privat. Di `eval` dan `where`, padanannya adalah `cidrmatch("10.0.0.0/8", DestinationIp)`.
- Sysmon tidak punya durasi, jadi `_time` dipakai langsung.
- `values(Image)` langsung memberi proses pemanggil, kelebihan utama Sysmon dibanding proxy dan firewall.
- Di PT JAB query ini dijalankan untuk 45 server ber-`NetworkConnect` dan tidak menghasilkan pasangan selain tujuan yang sudah dikenal.

**Kapan gagal:** beacon dengan interval di atas 4 jam atau jitter di atas sekitar 35%; C2 dalam satu tunnel HTTPS panjang (satu baris CONNECT); laptop di luar kantor; sumber yang berganti IP karena DHCP di tengah 28 hari; dan tujuan berprevalence tinggi yang ditumpangi penyerang, yang sengaja dibuang oleh `dest_hosts <= 10`.

### 2.2 Menutup `BDG-WS-0196`: manifest ekstensi dan pertanyaan kebijakan

Bagian ini menjawab pertanyaan ketiga Bambang dan Dimas. Day 05 meninggalkan tiga langkah: konfirmasi pengguna, cek inventaris ekstensi di lisensi MDE, dan cari host lain di `dns` dan `firewall`.

**Langkah 1, konfirmasi pengguna (Senin 2027-02-15).** Saat kembali dari cuti, `rizal.siregar` dihubungi Yoga Pratama atas permintaan Dimas. Ia mengakui memasang ekstensi pemantau status layanan dari toko Edge Add-ons pada 19 Januari, untuk memeriksa apakah layanan SaaS yang dipakai pelanggan korporatnya sedang gangguan sebelum menjawab keluhan. Pengakuan itu belum cukup untuk label jinak, karena penyerang juga bisa memasang ekstensi dengan nama yang sama; yang perlu dibuktikan adalah identitas ekstensi dan izinnya.

**Langkah 2, inventaris ekstensi.** MDE Plan 2 PT JAB tidak memuat browser extensions assessment; fitur itu termasuk kemampuan premium Defender Vulnerability Management, lewat add-on untuk Plan 2 atau versi standalone [S20]. Jalurnya pindah ke Velociraptor, yang client-nya terpasang di semua workstation sejak 22 sampai 24 Februari. Artifact `Windows.Applications.Chrome.Extensions` mem-parsing `manifest.json` ekstensi dan melaporkan nama, identifier, versi, penulis, dan izin; default-nya hanya mencari di folder Chrome, sehingga parameter `extensionGlobs` diganti ke folder profil Edge [S21].

```
Artifact   : Windows.Applications.Chrome.Extensions  (client BDG-WS-0196, 2027-03-09 10:05)
Parameter  : extensionGlobs = \AppData\Local\Microsoft\Edge\User Data\*\Extensions\*\*\manifest.json
```

Keluaran ilustrasi (satu dari 4 ekstensi di profil itu; tiga lainnya ekstensi bawaan atau yang dipasang tim IT):

```
User         : rizal.siregar
Name         : StatusPulse - Service Status Monitor
Identifier   : kfjpmhoedlgcabnbfaoeicmpdhbgnlpk
Version      : 3.2.1
Permissions  : alarms, storage, notifications
Host access  : https://api.statuspulse.example/*
```

**Cara membaca hasil:** izinnya sempit. Tidak ada izin membaca semua situs, membaca tab, mencegat request, atau membaca cookie; ekstensi ini hanya bisa menjadwalkan alarm, menyimpan setelan, menampilkan notifikasi, dan memanggil API-nya sendiri. Alarm tiap 30 menit cocok dengan interval 1.800 detik, dan ukuran seragam sekitar 5,9 KB cocok dengan balasan status berbentuk JSON. Identifier-nya cocok dengan halaman ekstensi di toko Edge Add-ons, dengan penerbit yang sama dengan nama domain API-nya. Kolom yang ditampilkan artifact bisa berbeda per versi; artifact ini juga sudah ditandai deprecated dan akan digantikan `Generic.Forensic.SQLiteHunter` [S21], jadi cek ketersediaannya di versi server-mu.

**Langkah 3, host lain.** Dua query cepat atas rentang 28 hari yang sama:

```
index=dns earliest="02/09/2027:00:00:00" latest="03/09/2027:00:00:00" query="*statuspulse.example*"
| stats count dc(src) AS clients values(src) AS client_list
```

```
index=firewall sourcetype=pan:traffic earliest="02/09/2027:00:00:00" latest="03/09/2027:00:00:00"
    dest=198.51.100.77
| stats count dc(src) AS sources values(src) AS source_list
```

Keluaran ilustrasi: `index=dns` menunjukkan satu klien, `10.30.12.54`; `index=firewall` hanya menunjukkan sumber `bdg-proxy01`, yaitu proxy yang meneruskan permintaan laptop itu, tanpa sumber workstation lain. Prevalence tetap satu host.

Label akhir: jinak terkonfirmasi. Tujuan `api.statuspulse.example` masuk `jab_hunt_baseline_beacon.csv` dengan pemilik `rizal.siregar`, interval 1.800 detik, catatan "ekstensi pribadi, identifier `kfjpmhoedlgcabnbfaoeicmpdhbgnlpk`", dan tanggal review tiga bulan lagi. Pengecualiannya per tujuan dan identifier, sehingga bila host lain mulai menghubungi tujuan yang sama, pasangan itu tetap muncul di laporan mingguan.

**Apakah ekstensinya perlu tindakan kebijakan?** Untuk ekstensi ini sendiri, tidak. Tetapi kasus ini membuka dua celah yang lebih besar dari satu laptop:

- **Tidak ada kebijakan ekstensi.** Bila kebijakan `ExtensionInstallBlocklist` tidak diatur, pengguna bisa memasang ekstensi apa pun di Edge [S19]. Model yang lebih ketat adalah blocklist `*` ditambah allowlist ekstensi yang disetujui. Dokumentasi Edge juga mencatat bahwa ekstensi yang sudah terpasang langsung dinonaktifkan bila diblokir, tanpa cara bagi pengguna untuk mengaktifkannya lagi [S19]. Karena itu kebijakan tidak bisa dipasang sebelum tahu ekstensi apa yang sedang dipakai, atau puluhan karyawan kehilangan alat kerjanya pada hari yang sama.
- **Tidak ada inventaris.** Inventaris ekstensi tidak tersedia di lisensi MDE saat ini [S20]. Velociraptor bisa mengumpulkannya untuk semua workstation Windows.

Usulan ke Dimas (dengan tembusan Nina Kartika untuk sisi kebijakan): (1) kandidat backlog baru, stacking identifier ekstensi browser di semua workstation lewat Velociraptor (T1176.001), dengan ekstensi yang hanya ada di satu atau dua host dan berizin luas ditinjau pertama; (2) setelah inventaris ada, keputusan model allowlist ekstensi Edge diambil bersama tim IT. Ini bukan insiden dan bukan bagian `HUNT-2027-020`; hunt ini selesai dengan label akhir untuk satu kandidat.

**Kapan gagal:** label jinak diberikan hanya dari pengakuan pengguna; atau ekstensi diblokir massal tanpa inventaris, sehingga kebijakan keamanan dipersepsikan sebagai gangguan dan dibatalkan.

### 2.3 `HUNT-2027-021`: menjalankan `HUNT-2027-003` (DNS tunneling 28 hari)

Hunt ini menjawab pertanyaan keempat Dimas. Abstract, ABLE, dan cek Evidence-nya sudah ada sejak 4 Februari (Day 03 bagian 2.3 sampai 2.6); `HUNT-2027-021` adalah eksekusinya pada rentang 28 hari yang baru, karena rentang lama (7 Januari sampai 4 Februari) sudah lewat retensi.

```
ID             : HUNT-2027-021 (eksekusi HUNT-2027-003)
Dimulai        : 2027-03-09 (Selasa) 09:00
Data           : index=dns, 4 resolver, Selasa 2027-02-09 00:00 sampai Selasa 2027-03-09 00:00 WIB
Allowlist      : jab_hunt_allowlist_dns.csv (kolom parent, src, reason)
Pembanding     : jab_hunt_baseline_dns_parent.csv (7 Jan - 4 Feb 2027, unique_sub > 50)
Jalur ambang   : 1-volume (unique_sub > 200 AND avg_sub_len > 30);
                 2-lambat-panjang (unique_sub > 50 AND max_sub_len >= 50 AND clients <= 3)
```

**Tujuan:** menemukan domain induk yang menerima banyak subdomain unik yang panjang, atau sedikit subdomain yang sangat panjang dari klien sedikit, setelah pasangan domain dan klien yang sudah disetujui dibuang.

```
index=dns earliest="02/09/2027:00:00:00" latest="03/09/2027:00:00:00"
| eval q=lower(rtrim(query, "."))
| rex field=q "^(?<sub>.+)\.(?<parent>[^.]+\.[^.]+)$"
| lookup jab_hunt_allowlist_dns.csv parent src OUTPUT reason
| where isnull(reason)
| eval sub_len=len(sub)
| stats count AS queries dc(sub) AS unique_sub avg(sub_len) AS avg_sub_len max(sub_len) AS max_sub_len
        dc(src) AS clients values(record_type) AS rtypes BY parent
| where unique_sub > 50
| lookup jab_hunt_baseline_dns_parent.csv parent OUTPUT unique_sub AS base_unique_sub
| eval pass=case(unique_sub > 200 AND avg_sub_len > 30, "1-volume",
                 max_sub_len >= 50 AND clients <= 3, "2-lambat-panjang",
                 true(), null())
| where isnotnull(pass)
| eval avg_sub_len=round(avg_sub_len, 1)
| table pass parent queries unique_sub avg_sub_len max_sub_len clients rtypes base_unique_sub
```

Tabel berikut menjelaskan bagian yang baru dibanding query Day 03.

| Bagian | Fungsi |
|---|---|
| `lookup jab_hunt_allowlist_dns.csv parent src OUTPUT reason` | Dua field input: baris allowlist cocok hanya bila domain induk dan klien sama-sama cocok. Dipasang sebelum `stats` supaya klien lain ke domain yang sama tetap dihitung |
| `where unique_sub > 50` | Batas bawah yang sama dengan agregat baseline Day 03, supaya pembandingnya setara |
| `lookup jab_hunt_baseline_dns_parent.csv ...` | Berapa subdomain unik domain induk itu pada 7 Januari sampai 4 Februari; kosong berarti domain induk itu belum berpola sama saat itu |
| `case(..., true(), null())` | Memberi label jalur ambang; baris yang tidak lolos jalur mana pun bernilai null lalu dibuang |

Lookup per event pada sekitar 438 juta event membuat search ini berjalan sekitar 40 menit di `jkt-splunk-sh01` (keluaran ilustrasi); karena itu ia dijalankan paling pagi, sebelum dua hunt lain.

Keluaran ilustrasi:

```
Event dns 9 Feb - 9 Mar 2027        : 438.661.209
Domain induk unik                   : 386.115
Domain induk dengan unique_sub > 50 : 4.402

pass              parent                      queries  unique_sub  avg_sub_len  max_sub_len  clients  rtypes  base_unique_sub
1-volume          hashbl.mailrep.example.net     7204        3512         36.0           36        1  A                  3390
2-lambat-panjang  id.printvendor.example          288         140         48.0           56        3  A                   131
2-lambat-panjang  rbl.mailrep.example.net         201          97         41.2           58        1  A,TXT                88
2-lambat-panjang  crash.mapviewer.example         129          61         44.3           52        2  A
```

**Cara membaca hasil:**

- **`avcloud.example` tidak muncul.** Allowlist Februari (domain itu dengan klien `10.20.3.60`, engine antivirus `jkt-proxy01`) bekerja, dan tidak ada klien lain yang memakai domain yang sama.
- **`hashbl.mailrep.example.net`.** Panjang subdomain selalu 36 karakter (rata-rata sama dengan maksimum), cocok dengan 32 karakter heksadesimal hash MD5 ditambah label `.uri`. Satu klien, `10.20.2.25` (`jkt-mailgw01`), dan pola yang hampir sama sudah ada di baseline Januari (3.390 subdomain unik). Mail gateway memeriksa reputasi URL di email masuk lewat DNS ke vendornya; tim Infrastruktur mengonfirmasi dan dokumentasi vendor menyebut domain itu. Label: jinak.
- **`rbl.mailrep.example.net`.** Klien yang sama, layanan reputasi kedua dari vendor yang sama, menanyakan domain pengirim email sebagai subdomain; panjang bervariasi karena nama domain pengirim bervariasi, dan record TXT dipakai untuk teks alasan. Label: jinak.
- **`id.printvendor.example`.** Tiga workstation Keuangan yang menjalankan agent printer cloud (tujuan `cloudprint.printvendor.example` di Day 05) mengirim ID perangkat berbentuk base32 di subdomain; polanya sama dengan Januari. Label: jinak.
- **`crash.mapviewer.example`.** Tidak ada di baseline, jadi ditinjau paling teliti. Dua klien, `JKT-WS-0611` dan `JKT-WS-0614` (Network Planning), memasang komponen penampil peta dari vendor perencanaan fiber pada pertengahan Februari; Sysmon EID 22 di kedua host menunjukkan `Image` milik aplikasi itu di `Program Files`, dan subdomainnya adalah ID laporan crash. Label: jinak.

Ketujuh kombinasi domain dan klien itu masuk `jab_hunt_allowlist_dns.csv` sebagai tujuh baris baru, masing-masing dengan alasan dan tanggal.

**Variasi 1, tipe record TXT dari workstation.** Tunneling sering memakai TXT karena jawaban bisa membawa lebih banyak data. Query `index=dns ... record_type=TXT (src=10.10.0.0/16 OR src=10.30.0.0/16) | stats count dc(query) AS names BY parent` memberi keluaran ilustrasi 1.204 query TXT dari workstation dalam 28 hari ke 3 domain induk, masing-masing dengan paling banyak 6 nama unik. Volume dan keragamannya terlalu kecil untuk membawa data.

**Variasi 2, DNS keluar langsung tanpa resolver.** Program yang menembak resolver publik langsung tidak tercatat di `index=dns`. Firewall menjawabnya; perhatikan bahwa query ini sengaja tidak membatasi eventtype akhir sesi, karena sesi yang ditolak tercatat dengan subtype `deny` atau `drop` [S22]:

```
index=firewall sourcetype=pan:traffic dest_port=53
    earliest="02/09/2027:00:00:00" latest="03/09/2027:00:00:00"
    NOT dest=10.0.0.0/8 NOT dest=172.16.0.0/12 NOT dest=192.168.0.0/16
| lookup jab_hunt_egress_infra.csv ip AS src OUTPUT role
| eval from_resolver=if(role="resolver", "ya", "tidak")
| stats count dc(src) AS sources BY from_resolver action
```

Keluaran ilustrasi: semua sesi `allowed` berasal dari empat resolver; dari sumber lain ada 2.310 sesi `blocked` dari 9 IP, yaitu 7 layar ruang rapat dan 2 perangkat uji NOC yang memakai resolver publik tertanam (`192.0.2.53`, `203.0.113.53`). Kebijakan firewall menutup jalur itu; daftar perangkatnya dikirim ke Bambang untuk dikonfigurasi ulang.

**Variasi 3, atribusi proses dengan Sysmon EID 22 (dan lab).** Versi lama Day ini memburu tunneling langsung dari Sysmon, per domain induk per host. Di PT JAB versi ini dipakai untuk 186 host ber-EID 22 dan untuk lab:

```
index=sysmon EventCode=22
    earliest="02/09/2027:00:00:00" latest="03/09/2027:00:00:00"
| eval qlen=len(QueryName)
| rex field=QueryName "\.(?<parent>[^.]+\.[^.]+)$"
| stats count AS queries avg(qlen) AS avg_len max(qlen) AS max_len dc(QueryName) AS unique_sub
        values(Image) AS images BY parent, host
| where queries > 100 AND avg_len > 40 AND unique_sub > 50
| sort - queries
```

- `rex` mengambil domain induk (dua label terakhir); stacking per domain induk per host.
- `unique_sub` di sini menghitung nama query penuh yang unik. Karena tunneling memakai subdomain yang hampir selalu baru, jumlah nama unik mendekati jumlah subdomain unik.
- `values(Image)` memberi proses; analytic ATT&CK untuk DNS tunneling menyoroti query dalam jumlah besar dari proses non-browser (Day 03 bagian 2.6).
- Panjang `qlen` mencakup domain induk, jadi ambang `avg_len > 40` tidak setara dengan `avg_sub_len > 30` di query resolver.

**Kapan gagal:** domain induk memakai TLD dua label seperti `co.id`, sehingga regex memotong di tempat yang salah; tunneling yang memakai banyak domain induk sekaligus sehingga tiap domain di bawah 50 subdomain unik; program yang memakai DoH atau resolver luar yang diizinkan; laptop di luar kantor; dan search yang kehabisan memori karena `dc()` atas ratusan ribu domain induk, yang tidak bisa diakali dengan menjumlahkan hasil per hari (jumlah unik tidak bisa dijumlahkan).

### 2.4 `HUNT-2027-022`: cek Evidence byte dan volume keluar per host

Hunt ini menjawab pertanyaan kelima Bambang. Sebelum menjumlahkan apa pun, dua hal harus dibuktikan: field byte keluar ada, dan arahnya benar.

```
ID             : HUNT-2027-022
Dibuat         : 2027-03-09 (Selasa) 11:00, pemilik: <kamu>, reviewer: Dimas Prasetyo
Trigger        : Pertanyaan NOC (Bambang) + pelajaran INC-2027-040 + backlog exfil volumetrik
Tipe (PEAK)    : Baseline (analisis volumetrik)
Hipotesis      : Ada host PT JAB yang pada suatu hari mengirim data keluar jauh di atas ukuran normal
                 PT JAB dan di atas kebiasaannya sendiri, ke tujuan eksternal, lewat proxy atau firewall.
ATT&CK         : T1041, T1048, T1567 (dan T1030 untuk pola pecahan)
Data           : index=proxy (bytes_out dari %>st), index=firewall pan:traffic eventtype=pan_traffic_end;
                 Selasa 2027-02-09 00:00 sampai Selasa 2027-03-09 00:00 WIB
Ambang         : host-day > p99 seluruh host-day AND > 3x median host itu AND rasio keluar:masuk > 3
Di luar cakupan: laptop di luar kantor (split tunnel), exfil di bawah p99 per hari, pecahan kecil
                 yang tersebar ke banyak tujuan, trafik terenkripsi di dalam layanan berprevalence tinggi
Handover       : IR (Dimas) bila ditemukan; Agung untuk celah logformat bila field tidak ada
```

**Langkah 1, field byte keluar di proxy.** Logformat Squid PT JAB adalah logformat kustom (Day 05 menambahkan user agent). Pertanyaannya: apakah ukuran request dari klien (`%>st`) ikut dicatat [S25].

```
index=proxy sourcetype=squid:access earliest="03/08/2027:00:00:00" latest="03/09/2027:00:00:00"
| stats count AS events count(bytes_out) AS has_out count(bytes) AS has_in
        sum(eval(if(http_method="CONNECT", 1, 0))) AS connect_lines BY host
```

Keluaran ilustrasi:

```
host          events      has_out     has_in      connect_lines
bdg-proxy01   1.402.118   1.402.118   1.402.118   1.093.652
jkt-proxy01   4.118.903   4.118.903   4.118.903   3.212.744
jkt-proxy02   3.597.226   3.597.226   3.597.226   2.805.836
```

`bytes_out` terisi 100% di ketiga proxy. Sekitar 78% baris adalah CONNECT (HTTPS tanpa inspeksi TLS), jadi yang paling penting adalah apakah `%>st` pada baris CONNECT mencakup byte yang dikirim klien lewat tunnel. Itu tidak dijelaskan di dokumentasi yang dibaca, sehingga diuji: pukul 08:50 Hari Wibisono (`adm.hari`) mengunggah file uji 50.000.000 byte lewat HTTPS dari satu workstation, dan baris CONNECT-nya mencatat `bytes_out` 50.612.408 (selisih sekitar 1,2% untuk header dan overhead TLS). Arah dan besarnya benar. Cek perilaku ini di versi Squid-mu sebelum memakai angkanya.

**Langkah 2, arah byte di firewall.** Transfer uji yang sama terlihat di firewall sebagai sesi dari `jkt-proxy01` dengan `bytes_out` sekitar 50,6 juta, sesuai definisi `Bytes Sent` arah klien ke server [S22]. Uji ini sekaligus memperlihatkan batas firewall: sumbernya proxy, bukan workstation.

**Langkah 3, volume keluar per host-day di proxy.**

```
index=proxy sourcetype=squid:access
    earliest="02/09/2027:00:00:00" latest="03/09/2027:00:00:00"
    (src=10.10.0.0/16 OR src=10.30.0.0/16)
| bin span=1d _time AS day
| stats sum(bytes_out) AS out_b sum(bytes) AS in_b dc(dest) AS dests BY src day
| eventstats perc99(out_b) AS p99_all
| eventstats median(out_b) AS med_host dc(day) AS days_active BY src
| eval ratio=round(out_b/(in_b+1), 2), out_mb=round(out_b/1024/1024, 1), in_mb=round(in_b/1024/1024, 1),
       med_mb=round(med_host/1024/1024, 1), x_med=round(out_b/med_host, 1)
| where out_b > p99_all AND out_b > 3*med_host AND ratio > 3
| eval day=strftime(day, "%Y-%m-%d")
| table src day out_mb in_mb ratio med_mb x_med days_active dests
| sort - out_mb
```

| Bagian | Fungsi |
|---|---|
| `bin span=1d _time AS day` lalu `stats ... BY src day` | Satu baris per host-day: total byte keluar dan masuk, dan jumlah tujuan |
| `eventstats perc99(out_b) AS p99_all` | Lapis global: p99 dari seluruh host-day (bagian 1.6) |
| `eventstats median(out_b) AS med_host dc(day) AS days_active BY src` | Lapis per host: median byte keluar per hari host itu, dan berapa hari ia aktif |
| `where out_b > p99_all AND out_b > 3*med_host AND ratio > 3` | Besar menurut PT JAB, besar menurut kebiasaan host itu, dan lebih banyak mengirim daripada menerima |
| `out_b/1024/1024` | Megabyte biner (MiB), sama dengan satuan di versi lama Day ini |

Keluaran ilustrasi (ringkas):

```
Host sumber (IP)                     : 368
Host-day                             : 6.904
p50 / p95 / p99 out per host-day     : 19,4 / 88,7 / 236,5 MB
Host-day di atas p99                 : 69 (di 41 host)
Lolos ketiga syarat                  : 9 host-day di 6 host

src          day         out_mb   in_mb  ratio  med_mb  x_med  days_active
10.10.51.18  2027-03-03  2031.7   225.9   8.99    24.1   84.3           20
10.10.51.18  2027-02-17  1912.4   210.6   9.08    24.1   79.4           20
10.10.48.33  2027-03-04  1843.2   140.7  13.10    31.5   58.5           19
10.10.51.18  2027-02-24  1744.0   198.2   8.80    24.1   72.4           20
10.10.61.14  2027-03-08   702.9    88.1   7.98    20.2   34.8           18
10.10.61.11  2027-03-08   684.3    92.4   7.41    21.7   31.5           19
10.30.14.22  2027-03-03   512.8    77.0   6.66    15.3   33.5           17
10.10.22.71  2027-02-26   318.6    61.2   5.21    17.9   17.8           20
10.10.22.71  2027-03-01   296.1    58.3   5.08    17.9   16.5           20
```

**Cara membaca hasil:**

- **Angkanya konsisten dengan definisi.** p99 dari 6.904 host-day memisahkan sekitar 1% teratas, dan 69 host-day memang sekitar 1% dari 6.904. Dari 69 itu, hanya 9 yang juga melampaui tiga kali median host-nya dan mengirim lebih banyak daripada menerima; sisanya host yang memang rutin besar atau host yang banyak mengunduh.
- **`10.10.51.18` (`JKT-WS-0388`, Marketing), tiga Rabu berturut-turut.** Unggahan video kampanye mingguan ke `upload.videoshare.example`, kanal video korporat PT JAB; median host itu hanya 24,1 MB karena unggahan terjadi seminggu sekali. Bentuknya persis T1567, tetapi jadwal, tujuan, dan pemiliknya jelas. Label: jinak.
- **`10.10.48.33` (`JKT-WS-0552`, `arif.kurniawan`, engineer NOC).** Bundel tech-support router (konfigurasi dan log) ke portal kasus vendor `support.routervendor.example`, sesuai nomor kasus yang dibuka NOC 4 Maret. Label: jinak.
- **`10.10.61.11` dan `10.10.61.14` (Network Planning).** File proyek peta ke portal berbagi file vendor perencanaan fiber `files.fiberplan.example` untuk kasus dukungan yang sama, Senin 8 Maret. Label: jinak.
- **`10.30.14.22` (`BDG-WS-0177`, sales korporat Bandung).** Dokumen tender ke portal pengadaan calon pelanggan `eproc.clientportal.example`. Label: jinak, dikonfirmasi atasan pengguna.
- **`10.10.22.71` (`JKT-WS-0471`, `nur.aini`, Keuangan).** Unggahan berkas pajak ke `efiling.taxportal.example` di akhir dan awal bulan. Label: jinak.

**Langkah 4, firewall (server dan workstation POP).** Query yang sama dijalankan di `pan:traffic eventtype=pan_traffic_end`, dengan `bytes_out` dan `bytes_in`, sumber dari `jab_hunt_egress_infra.csv` dibuang. Keluaran ilustrasi: 3.410 host-day, p99 1,9 GB, 34 host-day di atas p99. Dua puluh delapan di antaranya milik `jkt-backup01` (`10.20.4.15`), satu per hari, yang mengirim salinan backup ke `vault.backupvendor.example` (`203.0.113.200`) dengan median 96,2 GB per hari; lapis per host membuang semuanya kecuali Minggu 2027-02-28 (327,5 GB keluar, 2,1 GB masuk, rasio 155,95, 3,4 kali median), yaitu backup penuh bulanan sesuai jadwal tim Infrastruktur. Enam host-day lain di atas p99 tidak melampaui tiga kali median host-nya. Label: jinak. Workstation POP Surabaya dan Medan tidak ada yang mendekati p99.

**Variasi 1, pecahan berulang (T1030).** Untuk exfil yang sengaja di bawah ambang harian, cari banyak sesi berukuran mirip ke satu tujuan: `... | stats count AS sessions avg(bytes_out) AS avg_out stdev(bytes_out) AS sd_out sum(bytes_out) AS total BY src dest | eval cv_out=sd_out/avg_out | where sessions >= 50 AND cv_out < 0.1 AND avg_out > 100000`. Keseragaman ukuran adalah sinyal yang sama dengan `cv_bytes` di hunt beacon; layanan sinkronisasi sah sering lolos syarat ini, jadi tinjau per tujuan.

**Variasi 2, Zeek conn.log (lab).** Di lab dengan sensor Zeek, dengan `index=zeek sourcetype=zeek:conn` dan field `orig_bytes`, `resp_bytes`, `id.orig_h`, `id.resp_h`: di conn.log Zeek, `orig_bytes` adalah byte payload yang dikirim pihak pemulai koneksi dan `resp_bytes` byte dari pihak penerima [S4]. Untuk TCP, angka itu diambil dari sequence number dan bisa tidak akurat, misalnya pada koneksi besar; `missed_bytes` yang bukan nol menandakan ada celah konten akibat packet loss, dan `orig_ip_bytes` (byte di level IP) hanya terisi bila analyzer ukuran koneksi aktif [S5]. Versi lama Day ini memakai query berikut, dengan ambang asumsi 100 MB dan rasio 3 yang harus diganti dengan ambang dari distribusi seperti langkah 3:

```
index=zeek sourcetype=zeek:conn earliest="MM/DD/YYYY:00:00:00" latest="MM/DD/YYYY:00:00:00"
    NOT id.resp_h=10.0.0.0/8 NOT id.resp_h=172.16.0.0/12 NOT id.resp_h=192.168.0.0/16
| stats sum(orig_bytes) AS out_bytes sum(resp_bytes) AS in_bytes count AS conns BY id.orig_h
| eval ratio=round(out_bytes/(in_bytes+1),2), out_mb=round(out_bytes/1024/1024,1)
| where out_mb > 100 AND ratio > 3
| sort - out_mb
```

**Variasi 3, mengukur celah split tunnel.** `index=vpn sourcetype=pan:globalprotect earliest="02/09/2027:00:00:00" latest="03/09/2027:00:00:00" | stats dc(user) AS users` memberi keluaran ilustrasi 241 akun yang tersambung GlobalProtect dari luar kantor dalam 28 hari. Angka itu ditulis di laporan sebagai ukuran populasi yang volume internetnya di luar cakupan. Cek nama field user di add-on-mu.

**Kapan gagal:** `%>st` tidak dicatat atau tidak mencakup byte tunnel CONNECT; log awal dan akhir sesi firewall dijumlahkan bersama; host yang baru aktif satu atau dua hari (median-nya adalah dirinya sendiri, sehingga tidak pernah melampaui tiga kali median; tinjau terpisah bila di atas p99); exfil yang menyebar ke banyak hari di bawah p99; dan unggahan ke layanan berprevalence tinggi yang ukurannya wajar.

### 2.5 `HUNT-2027-022` lanjutan: transfer besar ke tujuan baru

Langkah ini melengkapi volume harian: unggahan yang tidak sampai p99 tetap layak ditinjau bila tujuannya belum pernah terlihat. Versi lama Day ini memakai Zeek dan lookup tujuan yang dibangun terpisah; di PT JAB baseline tujuan dibangun hari ini dari proxy.

**Langkah 1, baseline tujuan.** Semua tujuan yang terlihat di proxy pada 21 hari pertama rentang:

```
index=proxy sourcetype=squid:access
    earliest="02/09/2027:00:00:00" latest="03/02/2027:00:00:00"
| stats min(_time) AS first_seen max(_time) AS last_seen dc(src) AS hosts BY dest
| outputlookup override_if_empty=false jab_hunt_baseline_dest.csv
```

Keluaran ilustrasi: 58.902 tujuan tersimpan. `first_seen` di sini berarti "pertama terlihat sejak 9 Februari", karena retensi proxy 30 hari; lookup ini diperbarui harian setelah hari ini (bagian 2.7), sehingga maknanya memanjang seiring waktu.

**Langkah 2, transfer besar ke tujuan yang tidak ada di baseline.**

```
index=proxy sourcetype=squid:access
    earliest="03/02/2027:00:00:00" latest="03/09/2027:00:00:00"
    (src=10.10.0.0/16 OR src=10.30.0.0/16)
| stats sum(bytes_out) AS out_bytes min(_time) AS first_conn BY src dest
| lookup jab_hunt_baseline_dest.csv dest OUTPUT first_seen AS seenBefore
| where isnull(seenBefore) AND out_bytes > 10485760
| eval out_mb=round(out_bytes/1024/1024, 1), first_conn=strftime(first_conn, "%Y-%m-%d %H:%M")
| sort - out_bytes
```

- Transfer keluar lebih dari 10 MB (10.485.760 byte) ke tujuan yang belum pernah dihubungi siapa pun di 21 hari sebelumnya. Tujuan baru plus volume besar adalah sinyal exfil yang kuat.
- Jendela hunt (2 sampai 9 Maret) berakhir tepat di batas baseline, sehingga keduanya tidak tumpang tindih (Day 05 bagian 1.2).

Keluaran ilustrasi:

```
src          dest                           out_mb  first_conn
10.10.48.33  support.routervendor.example   1802.6  2027-03-04 13:40
10.10.61.14  files.fiberplan.example         690.4  2027-03-08 10:02
10.10.61.11  files.fiberplan.example         671.0  2027-03-08 09:55
10.30.14.22  eproc.clientportal.example      498.3  2027-03-03 14:18
10.10.51.18  transfer.agencyshare.example     46.2  2027-03-05 16:20
```

**Cara membaca hasil:** empat dari lima pasangan sudah dijelaskan di bagian 2.4; nilai per tujuan lebih kecil dari total host-day karena host itu juga mengirim ke tujuan lain hari itu. Pasangan kelima hanya 46,2 MB dan tidak mendekati p99, tetapi muncul di sini karena tujuannya baru: `JKT-WS-0388` mengirim materi kampanye ke layanan transfer file agensi iklan PT JAB, sesuai email permintaan agensi. Label: jinak. Inilah gunanya dua langkah: volume menangkap yang besar, tujuan baru menangkap yang tidak lazim walaupun kecil.

**Kapan gagal:** baseline tujuan mencakup jendela hunt sehingga tidak ada yang "baru"; tujuan berupa IP untuk sebagian baris sehingga satu layanan tercatat dengan beberapa nama; dan penyerang yang memakai tujuan yang sudah umum (layanan cloud yang dipakai ratusan host).

### 2.6 Pemeriksaan pendukung: koneksi ke port tidak lazim

Pemeriksaan ini bagian dari `HUNT-2027-020` dan menjawab sisi T1571: proses yang berkomunikasi ke luar lewat port yang tidak biasa. Versi lama Day ini memakai Sysmon EID 3:

```
index=sysmon EventCode=3
    earliest="02/09/2027:00:00:00" latest="03/09/2027:00:00:00"
    NOT DestinationIp=10.0.0.0/8 NOT DestinationIp=172.16.0.0/12 NOT DestinationIp=192.168.0.0/16
| stats count dc(host) AS hosts values(host) AS host_list BY DestinationPort Image
| where NOT (DestinationPort IN (80, 443, 53, 123)) AND count < 20
| sort count
```

- Proses yang membuat koneksi keluar ke port tidak lazim (bukan 80/443/53/123) dan jarang. Pivot ke proses dan tujuan.
- `IN (...)` di sini berada di dalam `where NOT (...)`; untuk aman di semua versi, padanannya `where NOT in(DestinationPort, 80, 443, 53, 123)`.
- FP: aplikasi sah yang memakai port khusus; bandingkan dengan baseline per proses.

Keluaran ilustrasi (workstation ber-Sysmon jarang muncul karena hampir semua trafiknya lewat proxy):

```
DestinationPort  Image                                         count  hosts  host_list
22               C:\Program Files\PuTTY\putty.exe                 14      2  JKT-WS-0552, JKT-WS-0547
22               C:\Program Files (x86)\WinSCP\WinSCP.exe          9      1  JKT-WS-0552
```

**Cara membaca hasil:** dua engineer NOC membuka SSH ke perangkat CPE pelanggan korporat di IP publik pelanggan, bagian dari pekerjaan rutin NOC. Label: jinak per peran.

**Variasi, firewall dengan identifikasi aplikasi.** Port tidak lazim lebih bermakna bila protokolnya diketahui: `index=firewall sourcetype=pan:traffic eventtype=pan_traffic_end ... | stats count dc(src) AS sources BY app dest_port | where (app="ssl" AND dest_port!=443) OR (app="web-browsing" AND dest_port!=80)`. Keluaran ilustrasi: satu kombinasi, `ssl` di port 8883 dari `jkt-pdu07` dan `jkt-pdu08` (bagian 2.1). Cek nama aplikasi di App-ID PAN-OS-mu.

**Kapan gagal:** penyerang memakai port standar (443) dengan protokol lain, yang hanya terlihat bila firewall mengidentifikasi aplikasinya; atau aplikasi sah dengan port khusus dianggap mencurigakan tanpa melihat proses dan perannya.

### 2.7 Korelasi C2 lalu exfil, dan usulan sinyal risk

Bagian ini menjawab pertanyaan terakhir Dimas ("ada yang layak jadi rule?"). Rantai yang dicari: host yang menunjukkan beacon, lalu transfer keluar besar ke tujuan yang sama atau terkait. Korelasi lintas sinyal seperti ini paling rapi dengan risk scoring: tiap hunt menulis risk event (objek host, skor, teknik) alih-alih alert, lalu search kedua menjumlahkan skor per host dalam jendela waktu. Beri skor pada host dengan beacon (T1071) dan pada host dengan volume keluar tinggi (T1041/T1048/T1567); host yang mengumpulkan keduanya, apalagi ke tujuan yang sama, naik ke atas.

Tanpa fitur risk, hasil yang sama bisa didekati dengan menggabungkan dua hasil hunt lalu menghitung jumlah sinyal per host:

```
| inputlookup jab_hunt_020_candidates.csv
| eval signal="beacon_prevalence_rendah"
| fields src dest signal
| append
    [ search index=proxy sourcetype=squid:access
        earliest="02/09/2027:00:00:00" latest="03/09/2027:00:00:00"
        (src=10.10.0.0/16 OR src=10.30.0.0/16)
      | stats sum(bytes_out) AS out_bytes BY src dest
      | where out_bytes > 10485760
      | eval signal="unggahan_besar"
      | fields src dest signal ]
| stats dc(signal) AS signals values(signal) AS signal_list dc(dest) AS dests values(dest) AS dest_list BY src
| where signals >= 2
```

- Baris pertama memuat kandidat tahap A `HUNT-2027-020`, sebelum penyaringan CV, supaya korelasi tidak bergantung pada satu ambang.
- `append` menggabungkan hasil subsearch unggahan di bawah hasil pertama.
- `dc(signal)` per host: host dengan kedua sinyal naik ke atas; `dest_list` menunjukkan apakah tujuannya sama.

Keluaran ilustrasi: dua host, `10.10.51.18` dan `10.10.61.11`, punya kedua sinyal, tetapi ke tujuan berbeda (aplikasi papan proyek dan unggahan video; heartbeat lisensi dan portal file vendor) yang semuanya sudah dijelaskan. Tidak ada host dengan beacon dan unggahan besar ke tujuan yang sama. `BDG-WS-0196` hanya punya sinyal beacon.

**Usulan ke Sari Kusuma: sinyal risk, bukan alert langsung.** Dari ketiga hunt, satu pola layak dijaga terus: beacon ke domain baru, pola `INC-2026-026` (beacon tiap lima menit ke domain yang baru didaftarkan). Usulannya:

```
Nama          : JAB - Beacon ke domain baru (risk)
Jenis         : risk event, bukan alert/finding langsung untuk L1
Logika        : pasangan proxy dengan CV <= 0.2 setelah jeda > 3x median dibuang, med_int 30 s - 4 jam,
                dest_hosts <= 10, tujuan tidak ada di jab_hunt_baseline_beacon.csv,
                first_seen tujuan di jab_hunt_baseline_dest.csv dalam 14 hari terakhir
Objek / skor  : host (src dipetakan ke nama host), skor awal 30, T1071.001
Jadwal        : harian 02:00, membaca 7 hari terakhir; jab_hunt_baseline_dest.csv diperbarui 02:30
Sinyal kedua  : "JAB - Unggahan besar ke tujuan baru (risk)" (bagian 2.5), skor 30, T1567/T1041
Ambang alert  : risk yang sama-sama menunjuk satu host dari minimal dua sinyal berbeda dalam 7 hari
Volume uji    : 28 hari terakhir menghasilkan 2 risk event beacon (push.kanbanapp.example, 2 host), jinak
```

Alasannya bukan alert langsung: dalam 28 hari, satu-satunya pasangan yang memenuhi logika itu adalah aplikasi sah yang baru dipasang, dan `api.statuspulse.example` akan memenuhi logika yang sama pada Januari. Sebagai alert, pola ini menghasilkan tiket yang hampir selalu jinak; sebagai risk event, ia diam sampai ada sinyal kedua di host yang sama. Jadwal pembaruan baseline tujuan setelah risk search penting: bila baseline diperbarui lebih dulu, tujuan baru kemarin sudah dianggap lama (Day 05 bagian 1.3). Cara mengubah usulan ini menjadi detection yang diuji dibahas di Day 14.

**Kapan gagal:** sinyal risk dibuat tanpa daftar tujuan dikenal yang dirawat, sehingga skor menumpuk di agent sah; atau ambang alert hanya satu sinyal, sehingga risk event berubah menjadi alert biasa dengan nama lain.

### 2.8 Laporan tiga hunt dan jawaban untuk Bambang dan Dimas

Tiga laporan berikut adalah langkah Finalize TaHiTI dan fase Act PEAK untuk Selasa ini.

```
ID            : HUNT-2027-020                        Selesai: Selasa 2027-03-09 15:40
Hasil         : Tidak ditemukan C2; BDG-WS-0196 ditutup jinak terkonfirmasi
Cakupan nyata : Proxy Jakarta dan Bandung (368 IP, 401.233 pasangan) dan firewall (sumber non-proxy),
                9 Feb - 9 Mar 2027; Sysmon EID 3 di 45 server ber-NetworkConnect
Ambang        : dest_hosts <= 10, conns >= 20, hours_seen >= 12 (1.212 kandidat proxy);
                30 s <= med_int <= 4 jam, CV <= 0.2 setelah jeda > 3x median dibuang
Jinak         : lic.fiberplan.example (4 PC Network Planning, 1 jam), push.kanbanapp.example (2 PC
                Marketing, 15 menit), telemetri PDU data center (2 perangkat, 1 jam, TLS 8883),
                api.statuspulse.example (ekstensi Edge StatusPulse 3.2.1, izin sempit, 1 host)
Di luar cakupan: laptop di luar kantor, interval > 4 jam, dest_hosts > 10, tunnel panjang, DoH
Artefak       : jab_hunt_baseline_beacon.csv + 4 tujuan; jab_hunt_egress_infra.csv;
                jab_hunt_020_candidates.csv dihapus setelah laporan
Celah/usulan  : PDU data center dengan akses internet langsung -> Agung; tidak ada kebijakan dan
                inventaris ekstensi browser -> Dimas dan Nina (kandidat backlog stacking ekstensi)
```

```
ID            : HUNT-2027-021 (eksekusi HUNT-2027-003)   Selesai: Selasa 2027-03-09 11:20
Hasil         : Tidak ditemukan DNS tunneling
Cakupan nyata : index=dns 4 resolver, 9 Feb - 9 Mar 2027, 438.661.209 event, 386.115 domain induk
Ambang        : jalur 1 unique_sub > 200 AND avg_sub_len > 30; jalur 2 unique_sub > 50 AND
                max_sub_len >= 50 AND clients <= 3; allowlist domain+klien; pembanding baseline Januari
Jinak         : 4 domain induk (2 layanan reputasi mail gateway, agent printer Keuangan, crash report
                aplikasi peta Network Planning); 7 baris allowlist baru
Pendukung     : TXT dari workstation 1.204 query ke 3 domain (maks 6 nama); DNS keluar langsung hanya
                dari resolver, 2.310 sesi diblokir dari 9 perangkat (ke NOC)
Di luar cakupan: DoH, resolver luar dari laptop split tunnel, < 50 subdomain unik per domain induk,
                DGA (tidak ada kode jawaban di log resolver)
```

```
ID            : HUNT-2027-022                        Selesai: Selasa 2027-03-09 16:50
Hasil         : Tidak ditemukan exfiltration
Cakupan nyata : Proxy (bytes_out dari %>st, terverifikasi uji 50 MB) dan firewall pan:traffic akhir sesi,
                9 Feb - 9 Mar 2027; 6.904 host-day proxy, 3.410 host-day firewall
Ambang        : > p99 global (proxy 236,5 MB; firewall 1,9 GB) AND > 3x median host AND rasio > 3;
                transfer > 10 MB ke tujuan baru (baseline tujuan 9 Feb - 2 Mar)
Jinak         : 9 host-day proxy di 6 host (video Marketing, tech-support NOC, file vendor Network
                Planning, tender sales Bandung, pajak Keuangan); backup penuh bulanan jkt-backup01;
                1 transfer kecil ke tujuan baru (agensi iklan)
Di luar cakupan: 241 akun VPN yang bekerja dari luar kantor (split tunnel), exfil di bawah p99 per hari,
                host dengan hari aktif sangat sedikit, unggahan ke layanan berprevalence tinggi
Artefak       : jab_hunt_baseline_dest.csv (58.902 tujuan, diperbarui harian)
Deteksi       : Usulan dua sinyal risk (beacon ke domain baru, unggahan besar ke tujuan baru) -> Sari
```

Tabel berikut adalah jawaban yang dikirim ke Bambang dan Dimas Selasa sore. Setiap baris merujuk subbagian di atas.

| Pertanyaan | Jawaban singkat | Dasar |
|---|---|---|
| (Bambang) Data apa yang kita punya | Proxy (web kantor Jakarta dan Bandung), firewall (server, POP, trafik non-proxy), resolver, Sysmon di 198/186 host, MDE untuk laptop di mana pun; firewall tidak melihat IP workstation untuk trafik web | Bagian 1.1, 1.2, 1.3 |
| (Dimas) Beacon yang lolos Februari | Interval di atas 1 jam, aplikasi yang baru muncul setelah jendela, trafik non-proxy; hunt 28 hari dengan ambang lebih rendah menemukan 9 pasangan, semua jinak | Bagian 1.4, 2.1 |
| Laptop Bandung | Ekstensi Edge pemantau status, izin sempit, satu host, dikonfirmasi pengguna dan manifest; jinak | Bagian 2.2 |
| Kebijakan ekstensi | Ekstensi ini tidak perlu tindakan; yang perlu adalah inventaris ekstensi dulu, lalu keputusan allowlist, karena blocklist langsung menonaktifkan ekstensi terpasang | Bagian 2.2 |
| DNS tunneling | `-003` dijalankan 28 hari dengan dua jalur ambang; 4 domain induk jinak, tidak ditemukan | Bagian 1.5, 2.3 |
| (Bambang) Bytes untuk data besar keluar | Bisa: firewall untuk server dan POP, proxy untuk workstation setelah `%>st` diverifikasi; ambang dari p99 dan median per host | Bagian 1.6, 2.4, 2.5 |
| Membedakan dari layanan sah | Prevalence, pemilik, first-seen tujuan, proses, ukuran, izin ekstensi | Bagian 1.7 |
| Yang tidak terlihat | Laptop di luar kantor (split tunnel), DoH, sebagian visibilitas SNI di jalur tanpa proxy karena ECH | Bagian 1.8 |
| Layak jadi rule | Dua sinyal risk, bukan alert langsung; alert bila dua sinyal menunjuk host yang sama | Bagian 2.7 |

**Kapan gagal:** jawaban ke Bambang berbunyi "tidak ada exfil" tanpa menyebut 241 akun yang bekerja dari luar kantor. NOC akan membaca itu sebagai jaminan untuk laptop yang justru menjadi pelajaran `INC-2027-040`.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** Splunk/Wazuh lab dengan Sysmon EID 3 dan 22 aktif di konfigurasi; jika ada, Zeek, proxy Squid, atau log firewall; VM dengan snapshot; web server lab untuk tujuan uji. Jangan memakai data, nama, atau kejadian dari pekerjaan nyata; PT JAB hanya contoh fiktif. Sesuaikan index, sourcetype, dan rentang absolut dengan data lab-mu.

1. **Peta teknik ke data.** Untuk teknik C2 (bagian 1.1) dan exfil (bagian 1.2), isi data lab dan blind spot dengan format tabel bagian 1.3. Tandai yang tidak ada (mis. Zeek, proxy, firewall bytes) dan jalur yang tidak tercatat (misalnya VM yang memakai resolver publik).
2. **Beaconing.** Jalankan query Sysmon EID 3 di bagian 2.1 (variasi 2). Di VM lab dengan snapshot, buat beacon jinak: skrip buatan sendiri yang memanggil satu URL lab pada interval tetap 60 detik selama 60 menit (jangan pakai tool C2). Ulangi hunt, pastikan beacon muncul. Kembalikan snapshot.
   - Durasi menentukan apakah ambang terpenuhi. Query menghitung `intervals` dari selisih antar koneksi, jadi N koneksi menghasilkan N-1 selisih. Syarat `intervals >= 50` dengan interval 60 detik butuh minimal 51 koneksi, atau sekitar 51 menit. Dengan 60 menit kamu mendapat sekitar 60 koneksi dan 59 selisih, sedikit di atas ambang.
   - Nilai yang diharapkan (keluaran ilustrasi): `avg_int` sekitar 60 detik dan `sd_int` di bawah 1-2 detik (hanya variasi penjadwalan), jauh di bawah batas CV 0,2, yaitu 12 detik. Bila `sd_int` jauh lebih besar, cek apakah ada koneksi lain dari host yang sama ke IP yang sama.
   - Perhatian: web server lab biasanya ber-IP privat, sedangkan query membuang rentang privat. Untuk uji, ganti filter itu dengan `DestinationIp=<IP server lab>` atau hapus sementara. Pastikan juga skrip membuka koneksi baru tiap panggilan (tanpa keep-alive), karena koneksi yang dipakai ulang tidak menghasilkan EID 3 baru.
3. **Beacon berjitter dan jeda.** Ubah skrip agar menunggu acak antara 48 dan 72 detik (plus minus 20%) selama 70 menit, lalu hitung CV-nya. Bandingkan dengan teori di bagian 1.4 (sekitar 0,115) dan dengan dua ambang: 0,15 (versi lama) dan 0,2. Ulangi dengan rentang 39 sampai 81 detik (plus minus 35%). Lalu matikan VM 30 menit di tengah uji pertama dan bandingkan CV dengan dan tanpa baris `where delta <= 3*med_int`.
4. **DNS tunneling.** Jalankan query Sysmon EID 22 di bagian 2.3 (variasi 3) dan, bila lab punya log resolver, versi resolver di bagian 2.3. Untuk menguji, pakai test Atomic T1071.004 di tabel bawah dengan domain diganti ke domain lab yang kamu kontrol (jangan ke internet). Pastikan hunt menandainya, dan catat syarat mana yang gagal bila tidak.
5. **Volume keluar.** Bila ada data byte, jalankan bagian 2.4 (atau variasi Zeek) dan 2.5; buat transfer uji (unggah file besar fiktif ke server lab) dan catat apakah arah byte di sumbermu benar, seperti uji 50 MB di bagian 2.4. Bila tidak ada data byte, dokumentasikan sebagai celah visibilitas.
6. **Non-standard port.** Jalankan bagian 2.6, lalu buat koneksi uji ke server lab di port tidak lazim (misalnya HTTPS di 8443) dan pastikan muncul.
7. **Ekstensi browser.** Di VM lab, pasang satu ekstensi dari toko resmi, lalu kumpulkan manifest-nya (dengan Velociraptor dan artifact seperti bagian 2.2 bila lab punya Velociraptor, atau dengan membaca `manifest.json` di folder profil). Catat identifier, izin, dan host access, lalu nilai dengan empat pertanyaan di bagian 1.7.
8. **Korelasi.** Jalankan beacon dan transfer pada host yang sama, lalu tinjau apakah keduanya terlihat (bagian 2.7).
9. **Handover.** Tulis usulan sinyal risk untuk pola yang ditemukan dan laporan hunt (template Day 01 bagian 2.4 atau bagian 2.8). Tandai yang harus ke IR dan jalur yang tidak tercakup.

**Test Atomic yang dirujuk (isi test, bukan resep):**

Ketiga test di bawah dijalankan lewat PowerShell dan default-nya mengirim query tipe TXT ke `127.0.0.1.nip.io` (layanan DNS publik yang menjawab dengan IP yang tertulis di nama). Di lab terisolasi, ganti domain ke zona DNS lab. Query yang gagal di-resolve tetap tercatat di EID 22 dengan `QueryStatus` bukan nol [S3].

| Test dan GUID | Apa yang terjadi | Yang harus terlihat di log |
|---|---|---|
| DNS Large Query Volume, `1700f5d6-5a44-487b-84de-bc66f507b0a6` | Mengirim 1.000 query TXT berturut-turut; tiap nama memakai subdomain `atomicredteam` ditambah angka acak, jadi semuanya berbeda | EID 22 dari `powershell.exe` dengan ratusan `QueryName` unik di satu domain induk. Di query EID 22 bagian 2.3, `queries` dan `unique_sub` jauh di atas ambang, tetapi nama query relatif pendek sehingga syarat `avg_len > 40` bisa gagal; hitung panjangnya di data lab. Dengan domain default, regex dua label terakhir menghasilkan induk `nip.io` |
| DNS Regular Beaconing, `3efc144e-1af8-46bb-8ca2-1376bb6db8b6` | Selama 30 menit mengirim query TXT setiap sekitar 30 detik dengan jitter 20%, meniru implant yang sedang idle | Sekitar 60 query dari satu proses ke nama yang sama. Volume rendah, jadi query tunneling tidak menandainya; yang cocok adalah analisis interval seperti bagian 2.1 yang dijalankan di EID 22 per pasangan `host` dan `QueryName`. Dengan jitter 20%, CV diharapkan sekitar 0,12 sampai 0,13, di bawah ambang 0,2; tetapi median bisa sedikit di bawah 30 detik, jadi turunkan `med_int >= 30` ke 20 untuk uji ini |
| DNS Long Domain Query, `fef31710-223a-40ee-8462-a396d6b66978` | Mengirim query dengan nama yang makin panjang sampai batas label DNS (63 karakter) | EID 22 dengan `QueryName` lebih dari 63 karakter dari satu proses. Menguji `max_len`; jumlah query-nya kecil, jadi syarat `queries > 100` tidak terpenuhi. Pecah hunt menjadi dua: volume, dan panjang maksimum (jalur 2 di bagian 2.3) |

Test keempat di halaman yang sama (DNS C2) butuh listener C2 eksternal dan tidak dipakai di Day ini.

**Hasil yang sebaiknya tersimpan:**

- Peta teknik ke data dengan blind spot terisi; celah visibilitas jaringan dan jalur yang tidak tercatat ditandai.
- Hunt beaconing menangkap beacon jinak uji, dengan angka CV tanpa jitter, dengan jitter 20% dan 35%, dan dengan jeda, sebelum dan sesudah filter median.
- Hunt DNS tunneling menandai query uji panjang berulang, dengan catatan syarat mana yang gagal untuk tiap test Atomic.
- Hunt volume keluar dijalankan dengan bukti arah byte dari transfer uji (atau celah data dicatat).
- Hunt non-standard port dijalankan dengan satu koneksi uji yang tertangkap.
- Manifest satu ekstensi dengan penilaian izinnya.
- Usulan sinyal risk dan laporan tersimpan; temuan untuk IR ditandai.

**Variasi tantangan:** jalankan hunt beaconing dengan beacon uji ber-jitter besar (plus minus 40% atau lebih) dan interval panjang (misalnya 20 menit selama 8 jam). Lihat apakah CV maksimal 0,2 masih menangkapnya; bila tidak, coba MAD dibagi median (Day 05 bagian 2.2) dan catat trade-off antara menangkap beacon berjitter dan FP polling sah. Tulis rekomendasi ambang untuk lab-mu.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat menjalankan hunt C2 dan exfil. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| EID 3 kosong | Sysmon tidak mencatat network connection | Tambah rule `NetworkConnect` di konfigurasi, dengan exclude proses berisik; sampai aktif, catat sebagai celah visibilitas |
| EID 22 kosong | DNS query logging nonaktif | Aktifkan EID 22 atau pakai log resolver |
| EID 3 workstation hanya menunjuk proxy | Proxy eksplisit | Cocokkan waktu dengan log proxy; pakai MDE untuk proses |
| Beacon tidak terdeteksi | Jitter besar; koneksi sedikit; jeda belum dibuang | Buang jeda dengan median, pakai CV maksimal 0,2; perpanjang rentang dan turunkan ambang jumlah koneksi (bagian 2.1) |
| Beacon penuh FP | Polling sah (update, telemetri, lisensi) | Batasi ke prevalence rendah; daftar tujuan dikenal dengan pemilik |
| Subsearch kandidat terpotong | Kandidat lebih dari 10.000 baris | Perketat tahap A atau pecah per subnet |
| DNS tunneling regex salah domain | TLD majemuk (co.id) | Sesuaikan regex domain induk |
| Allowlist DNS tidak membuang apa pun | Nama kolom lookup tidak sama dengan field (`parent`, `src`) | Samakan nama kolom atau pakai `AS` di `lookup` |
| Search DNS 28 hari kehabisan memori | `dc()` atas ratusan ribu domain induk | Persempit per subnet klien; jangan menjumlahkan `dc()` per hari |
| Volume keluar tak bisa dihitung | Tidak ada data byte keluar | Celah visibilitas; tambah `%>st` di logformat Squid, atau pakai firewall/Zeek (Day 04) |
| Volume firewall dua kali lipat | Log awal dan akhir sesi dijumlahkan | Pakai hanya log akhir sesi (`pan_traffic_end`) [S24] |
| Semua workstation tampak sama di firewall | Sumber web adalah proxy | Pakai proxy untuk workstation; firewall untuk server dan POP |
| Server backup selalu muncul | Hanya ambang global | Tambahkan lapis median per host (bagian 2.4) |
| Tidak ada tujuan "baru" | Baseline tujuan mencakup jendela hunt | Akhiri baseline sebelum jendela hunt (bagian 2.5) |

## 5. Kesalahan umum dan jebakan

- **Mengira semua koneksi teratur adalah C2.** Polling sah juga teratur; butuh daftar tujuan dikenal dan konteks tujuan.
- **Memburu volume tanpa data byte.** Endpoint EID 3 tidak memberi byte; exfil besar butuh proxy dengan ukuran request, firewall, atau Zeek.
- **Memakai firewall untuk volume workstation di belakang proxy eksplisit.** Firewall hanya melihat proxy sebagai sumber.
- **Menjumlahkan log awal dan akhir sesi firewall.** Satu sesi terhitung dua kali.
- **Mengabaikan konteks tujuan.** "Koneksi keluar" bermakna setelah ditambah umur domain, reputasi, prevalence, dan first-seen.
- **Ambang yang ditebak.** Tetapkan dari distribusi: p99 global ditambah median per host (bagian 1.6).
- **Lupa jitter, atau ambang CV yang terlalu dekat dengan jitter yang umum.** CV 0,15 hanya memberi margin tipis di atas beacon berjitter 20% (CV sekitar 0,13); program memakai 0,2 setelah jeda dibuang (bagian 1.4).
- **Menutup kandidat beacon browser hanya dari pengakuan pengguna.** Buktikan identitas dan izin ekstensi dari manifest-nya.
- **Memblokir semua ekstensi tanpa inventaris.** Ekstensi terpasang langsung dinonaktifkan dan pekerjaan pengguna terganggu [S19].
- **Melaporkan "tidak ditemukan" untuk laptop di luar kantor.** Dengan split tunnel, itu data tidak cukup.
- **Menganggap log resolver mencakup semua DNS.** DoH dan resolver luar tidak pernah sampai ke sana.
- **Menjadikan beacon ke domain baru alert langsung.** Aplikasi sah yang baru dipasang memenuhi pola yang sama; jadikan risk event.
- `[komunitas, belum terkonfirmasi]` Praktisi menilai data jaringan (Zeek, proxy, firewall) sebagai yang paling sering kurang di lingkungan kecil, sejalan dengan survei SANS 2026 yang menempatkan data sebagai hambatan utama (Day 01 bagian 1.7). Nilai dulu apa yang ada sebelum merancang hunt C2/exfil, cek di lab-mu.

## 6. Catatan terkini

Bagian ini menampung detail versi, tanggal, dan perubahan sumber yang tidak mengubah langkah kerja di atas.

- ATT&CK v20.0 dirilis 13 Oktober 2026, menggantikan v19.2 (28 April sampai 12 Oktober 2026) [S15]. Per v20.0: T1071.001 versi 1.5 (diubah 11 September 2026, DET0027) [S6]; T1071.004 versi 1.4 (3 September 2026, DET0400) [S7]; T1572 versi 1.1 (3 September 2026, DET0538) [S8]; T1048 versi 1.6 (3 September 2026, DET0131) [S9]; T1041 versi 2.4 (11 September 2026, DET0348) [S10]; T1567 versi 1.5 (12 Mei 2026, DET0548) [S11]; T1571 versi 1.3 (3 September 2026, DET0227) [S12]; T1568 versi 1.1 (12 Mei 2026, DET0039) [S13].
- T1176 bernama Software Extensions (versi 2.0, diubah 24 Oktober 2025) dengan sub-teknik T1176.001 Browser Extensions (dibuat 30 Maret 2025, versi 1.1) dan T1176.002 IDE Extensions, di taktik Persistence [S14]. Karena sub-teknik itu sudah ada sejak Maret 2025, penggantian nama dari Browser Extensions terjadi sebelum v20, bukan di v20; dokumentasi lama masih menyebut T1176 sebagai Browser Extensions tanpa sub-teknik. Cek riwayat versi di halaman versions ATT&CK bila tanggal persisnya dibutuhkan.
- RITA versi terbaru di GitHub adalah v5.1.2 (7 Mei 2026), sebelumnya v5.1.1 dan v5.1.0 [S16]. README RITA menyebut AC-Hunter sebagai produk lanjutannya untuk otomasi hunting, visualisasi, dan pengayaan data [S16].
- ECH distandarkan sebagai RFC 9849 (Maret 2026, Standards Track); distribusi konfigurasinya lewat record SVCB/HTTPS dirinci di RFC terpisah yang dirujuknya [S18]. DoH tetap RFC 8484 (Oktober 2018, Proposed Standard) [S17].
- Kebijakan Edge `DnsOverHttpsMode` didukung sejak Edge 83 di Windows; `ExtensionInstallBlocklist` sejak Edge 77; halaman kebijakan diperbarui sepanjang 2026 [S19].
- Browser extensions assessment tetap kemampuan premium Defender Vulnerability Management (add-on untuk MDE Plan 2 atau standalone), tidak termasuk di inti MDE Plan 2 [S20].
- Artifact Velociraptor `Windows.Applications.Chrome.Extensions` ditandai deprecated dan akan digantikan `Generic.Forensic.SQLiteHunter` [S21].
- Add-on Splunk untuk Palo Alto Networks yang didukung Splunk berversi 4.0.0 di halaman dokumentasinya [S24].
- Beaconing dan DNS tunneling tetap pola C2 yang paling bisa diburu dari endpoint (Sysmon EID 3/22) tanpa sensor jaringan; volume exfil butuh data byte. Day 13 melanjutkan ke living-off-the-land dan abuse script, yang sering menjadi mekanisme C2 dan exfil.

## 7. Cheat sheet

```
C2          T1071.001 web (beacon, UA aneh) | T1071.004 DNS | T1571 port tak lazim | T1572 tunneling
            T1573 encrypted | T1568 dynamic resolution (butuh NXDOMAIN) | T1105 unduh tahap kedua
EXFIL       T1041 over C2 | T1048 alt protocol (DNS/ICMP) | T1567 web service | T1030 pecahan
DATA        proxy (web kantor, CONNECT host) | firewall (server, POP, non-proxy; proxy = sumber web)
            resolver (semua klien, tanpa proses) | Sysmon EID3/22 (proses) | MDE (laptop di mana pun)
BEACON      28 hari | dest_hosts <= 10 | conns >= 20, hours >= 12 | buang delta > 3x median
            30 s <= med <= 4 jam | CV <= 0.2 (jitter +-20% ~0.115-0.13; +-35% ~0.2) | baseline beacon
DNS TUNNEL  stats dc(sub) avg/max(len(sub)) dc(src) BY parent ; allowlist parent+src SEBELUM stats
            jalur 1 volume (>200, avg>30) | jalur 2 lambat-panjang (>50, max>=50, clients<=3)
EXFIL VOL   host-day: sum(bytes_out) ; > p99 global AND > 3x median host AND rasio > 3
            proxy butuh %>st ; firewall: hanya akhir sesi ; uji arah byte dengan file uji
TUJUAN BARU baseline tujuan berakhir SEBELUM jendela hunt ; out > 10 MB ke dest tanpa first_seen
EKSTENSI    T1176.001 ; manifest: identifier, izin, host access ; toko + penerbit ; prevalence
            blocklist "*" menonaktifkan yang terpasang -> inventaris dulu
CELAH       split tunnel (laptop luar kantor) | DoH (443, lewat proxy sebagai CONNECT) | ECH (SNI)
RISK        beacon ke domain baru = risk event, bukan alert ; alert bila >= 2 sinyal di host sama
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Beacon dengan jitter sekitar 20% punya CV sekitar 0,13, jadi syarat CV di bawah 0,15 dari versi lama sudah cukup dan tidak perlu diubah." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Selisih 0,13 dengan 0,15 hanya 0,018, sedangkan CV yang dihitung dari sampel berfluktuasi; secara teori jitter plus minus 26% sudah memberi CV sekitar 0,15. Ambang 0,2 baru dilewati pada jitter sekitar plus minus 35%. Program hunt PT JAB juga memakai satu ambang (CV maksimal 0,2 setelah jeda lebih dari tiga kali median dibuang) supaya laporan mingguan dan hunt bisa dibandingkan, dan tanpa membuang jeda, ambang apa pun rusak oleh satu jeda malam. Lihat bagian 1.4.

</details>

**2. Skenario keputusan.** Pengguna `BDG-WS-0196` mengakui memasang ekstensi pemantau status, dan Velociraptor menunjukkan ekstensi dengan izin `alarms`, `storage`, `notifications` dan host access hanya ke `api.statuspulse.example`, tanpa host lain yang menghubungi tujuan itu. Langkah mana yang paling tepat?

- A. Nyatakan insiden, blokir domain, dan hapus ekstensi dari laptop karena ekstensi browser adalah teknik persistence di ATT&CK.
- B. Beri label jinak terkonfirmasi, masukkan tujuan itu ke daftar tujuan beacon dikenal dengan pemilik, identifier, dan tanggal review, lalu ajukan inventaris ekstensi dan keputusan kebijakan ke Dimas sebagai usulan terpisah.
- C. Biarkan inkonklusif sampai PT JAB punya inspeksi TLS untuk melihat isi permintaannya.

<details><summary>Jawaban</summary>

B. Label jinak bertumpu pada bukti yang saling menguatkan: pengakuan pengguna, identifier dan izin dari manifest yang sempit, interval dan ukuran yang cocok dengan fungsinya, dan prevalence satu host. Celah kebijakan dan inventaris adalah temuan terpisah yang lebih besar dari satu laptop. A keliru karena tidak ada indikasi aktivitas berbahaya, dan tercantum di ATT&CK bukan bukti; menyatakan insiden juga membuang kepercayaan pengguna dan NOC. C keliru karena data yang ada sudah cukup untuk memutuskan, dan menunggu kemampuan yang belum ada membuat backlog tidak pernah selesai. Lihat bagian 2.2.

</details>

**3. Pertanyaan jebakan.** "Firewall Palo Alto mencatat `bytes_out` per sesi, jadi hunt volume keluar per workstation Jakarta cukup memakai `index=firewall`." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Trafik web workstation Jakarta dan Bandung lewat proxy eksplisit, sehingga di firewall sumbernya adalah server proxy, bukan workstation. Volume per workstation harus diukur di proxy, dan itu hanya bisa bila logformat mencatat ukuran request dari klien (`%>st`) dan arahnya sudah diverifikasi dengan transfer uji, karena kolom `bytes` Squid adalah data yang dikirim ke klien. Firewall berguna untuk server data center dan workstation POP yang tidak lewat proxy, dengan hanya log akhir sesi supaya tidak terhitung dua kali. Lihat bagian 1.3 dan 2.4.

</details>

**4. Skenario keputusan.** Hunt volume dengan ambang p99 global saja menandai `jkt-backup01` di 28 dari 28 hari. Apa langkah yang tepat?

- A. Naikkan ambang global ke p99,9 supaya server backup tidak muncul.
- B. Tambahkan lapis per host (melampaui tiga kali median host itu sendiri), tinjau terpisah host yang hari aktifnya terlalu sedikit untuk punya median, dan tinjau hari yang masih lolos.
- C. Masukkan `jkt-backup01` ke pengecualian permanen karena ia server backup.

<details><summary>Jawaban</summary>

B. Lapis per host membuang hari-hari backup rutin dan hanya meninggalkan hari yang menyimpang dari kebiasaan server itu sendiri, di PT JAB satu hari backup penuh bulanan yang lalu dikonfirmasi dengan jadwal. A keliru karena menaikkan ambang global juga membuang workstation yang unggahannya besar menurut ukuran PT JAB, dan server backup tetap muncul. C keliru karena server backup yang mengirim data ke luar justru jalur exfil yang menarik bagi penyerang; pengecualian permanen membuatnya buta. Lihat bagian 1.6 dan 2.4.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Bambang Hartono, dalam tiga kalimat, kenapa hasil "tidak ditemukan exfil" hari ini tidak berlaku untuk laptop seperti `SBY-WS-0107` saat di rumah.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "VPN kita split tunnel, jadi saat laptop di rumah, trafik internet dan query DNS-nya keluar langsung dari jaringan rumah tanpa lewat proxy, resolver, maupun firewall kita; log VPN hanya mencatat bahwa laptop itu tersambung. Untuk laptop Jakarta dan Bandung masih ada MDE yang mencatat koneksi per proses di mana pun, tetapi 23 laptop POP Surabaya dan Medan seperti `SBY-WS-0107` tidak punya MDE maupun Sysmon, jadi untuk mereka tidak ada data sama sekali. Karena itu laporan hari ini menulis 241 akun yang bekerja dari luar kantor sebagai di luar cakupan, dan itu celah data yang harus diputuskan di level kebijakan VPN atau endpoint, bukan bukti bahwa mereka bersih."

Kesalahan yang sering muncul:
- Mengatakan "tidak ada exfil" tanpa menyebut cakupan, sehingga NOC menganggap laptop di luar kantor ikut diperiksa.
- Lupa bahwa MDE masih menutup sebagian celah untuk workstation Jakarta dan Bandung.
- Menyebut DoH atau ECH sebagai penyebab utama kasus ini, padahal yang membuat laptop itu buta adalah split tunnel.

</details>

**6. Pertanyaan jebakan.** "Beacon ke domain baru adalah pola `INC-2026-026`, jadi sebaiknya langsung dijadikan alert untuk L1 supaya tidak terlewat lagi." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Dalam 28 hari, satu-satunya pasangan yang memenuhi logika itu adalah aplikasi papan proyek yang sah dan baru dipasang di dua workstation Marketing, dan ekstensi `api.statuspulse.example` akan memenuhi logika yang sama pada Januari. Sebagai alert, pola ini menghasilkan tiket yang hampir selalu jinak. Usulannya adalah risk event dengan skor dan teknik, yang baru menjadi alert bila minimal dua sinyal berbeda (misalnya beacon ke domain baru dan unggahan besar ke tujuan baru) menunjuk host yang sama dalam 7 hari. Lihat bagian 2.7.

</details>

**7. Interview question (English).** "How would you hunt for data exfiltration when all you have is proxy and firewall logs?"

<details><summary>Sample answer</summary>

"First I'd check what the logs can actually see. With an explicit proxy, the firewall only sees the proxy as the source of web traffic, so per-host upload volume has to come from the proxy, and only if it logs request size; I'd prove the direction with a test upload before trusting any number. The firewall then covers servers and sites that don't use the proxy, using only session-end records so nothing is double counted. For thresholds I'd build host-day totals over about four weeks, take the 99th percentile across all hosts as the floor, and also require the day to be well above that host's own median, so a backup server doesn't show up every night. A second pass looks for transfers over a modest size to destinations not seen before, which catches small but unusual uploads. Every hit gets context: who owns the host, what the destination is, and whether there's a business reason. And I'd state what's out of scope, like remote laptops on a split-tunnel VPN, because there 'nothing found' really means 'no data'."

What makes this answer strong: it starts with visibility rather than queries, verifies byte direction, derives thresholds from distributions at two levels, adds a destination-novelty pass, and is explicit about blind spots instead of overclaiming a negative result.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | MITRE ATT&CK: Command and Control (TA0011) dan Exfiltration (TA0010) | https://attack.mitre.org/tactics/TA0011/ | primer | diakses 2026-10-09 | Tinggi. Teknik dan prosedur |
| S2 | Microsoft Learn: Sysmon (EID 3 NetworkConnect, EID 22 DNSEvent) | https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon | primer | diakses 2026-10-10 | Tinggi. Event dan field |
| S3 | Atomic Red Team: T1071.004 | https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1071.004/T1071.004.md | primer | diakses 2026-10-10 | Tinggi. Isi test, parameter default, GUID |
| S4 | Zeek documentation: conn.log | https://docs.zeek.org/en/master/logs/conn.html | primer | diakses 2026-10-10; percobaan ulang 2026-10-18 dibatasi situs | Tinggi. Field `orig_bytes`, `resp_bytes`, `id.orig_h`; situs kadang membatasi akses otomatis |
| S5 | Zeek source: `scripts/base/protocols/conn/main.zeek` (komentar dokumentasi field conn.log) | https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/protocols/conn/main.zeek | primer (kode sumber proyek) | cabang master; diakses 2026-10-18 | Tinggi. `orig_bytes` dari sequence number dan bisa tidak akurat, `missed_bytes`, `orig_ip_bytes` butuh analyzer ukuran, `duration`, `conn_state` |
| S6 | MITRE ATT&CK: T1071.001 Application Layer Protocol: Web Protocols | https://attack.mitre.org/techniques/T1071/001/ | primer | v1.5, diubah 2026-09-11; konten v20.0; diakses 2026-10-18 | Tinggi. Definisi, HTTP/S dan WebSocket, DET0027 dengan analytic AN0075 sampai AN0079 |
| S7 | MITRE ATT&CK: T1071.004 Application Layer Protocol: DNS | https://attack.mitre.org/techniques/T1071/004/ | primer | v1.4, diubah 2026-09-03; diakses 2026-10-18 | Tinggi. Beacon DNS jarang berkomunikasi, tipe record, malware yang memakai DoH, DET0400 |
| S8 | MITRE ATT&CK: T1572 Protocol Tunneling | https://attack.mitre.org/techniques/T1572/ | primer | v1.1, diubah 2026-09-03; diakses 2026-10-18 | Tinggi. SSH tunneling, DoH bersama Dynamic Resolution, DET0538 |
| S9 | MITRE ATT&CK: T1048 Exfiltration Over Alternative Protocol | https://attack.mitre.org/techniques/T1048/ | primer | v1.6, diubah 2026-09-03; diakses 2026-10-18 | Tinggi. Definisi, tiga sub-teknik, DET0131 |
| S10 | MITRE ATT&CK: T1041 Exfiltration Over C2 Channel dan DET0348 | https://attack.mitre.org/techniques/T1041/ ; https://attack.mitre.org/detectionstrategies/DET0348/ | primer | v2.4, diubah 2026-09-11; diakses 2026-10-18 | Tinggi. Definisi; analytic AN0988 (volume tidak cocok dengan proses setelah akses file, `DataVolumeThreshold`, `KnownBenignProcesses`) |
| S11 | MITRE ATT&CK: T1567 Exfiltration Over Web Service | https://attack.mitre.org/techniques/T1567/ | primer | v1.5, diubah 2026-05-12; diakses 2026-10-18 | Tinggi. Definisi, empat sub-teknik, DET0548 |
| S12 | MITRE ATT&CK: T1571 Non-Standard Port | https://attack.mitre.org/techniques/T1571/ | primer | v1.3, diubah 2026-09-03; diakses 2026-10-18 | Tinggi. Contoh pasangan port dan protokol, DET0227 |
| S13 | MITRE ATT&CK: T1568 Dynamic Resolution | https://attack.mitre.org/techniques/T1568/ | primer | v1.1, diubah 2026-05-12; diakses 2026-10-18 | Tinggi. Tiga sub-teknik, DET0039 |
| S14 | MITRE ATT&CK: T1176 Software Extensions, T1176.001 Browser Extensions, dan DET0044 | https://attack.mitre.org/techniques/T1176/ ; https://attack.mitre.org/techniques/T1176/001/ ; https://attack.mitre.org/detectionstrategies/DET0044/ | primer | T1176 v2.0 (2025-10-24), T1176.001 v1.1 (dibuat 2025-03-30, diubah 2025-09-22); diakses 2026-10-18 | Tinggi. Nama, taktik, kemampuan dan cara pemasangan ekstensi berbahaya, mitigasi, analytic AN0123 |
| S15 | MITRE ATT&CK: Versions of ATT&CK | https://attack.mitre.org/resources/versions/ | primer | diakses 2026-10-18 | Tinggi. v20.0 sejak 2026-10-13; v19.2 2026-04-28 sampai 2026-10-12 |
| S16 | Active Countermeasures: RITA (README dan daftar rilis) | https://github.com/activecm/rita ; https://github.com/activecm/rita/releases | primer (proyek open source) | v5.1.2 2026-05-07; diakses 2026-10-18 | Tinggi. Beaconing, long connection, DNS tunneling, threat intel; input Zeek; AC-Hunter |
| S17 | IETF RFC 8484: DNS Queries over HTTPS (DoH) | https://www.rfc-editor.org/rfc/rfc8484 | primer (standar) | Oktober 2018; diakses 2026-10-18 | Tinggi. `application/dns-message`, GET/POST, port 443, catatan analisis trafik |
| S18 | IETF RFC 9849: TLS Encrypted Client Hello | https://www.rfc-editor.org/rfc/rfc9849.html | primer (standar) | Maret 2026; diakses 2026-10-18 | Tinggi. Apa yang dienkripsi, `public_name` di SNI luar, apa yang masih terlihat pengamat pasif, distribusi lewat SVCB/HTTPS |
| S19 | Microsoft Learn: kebijakan Microsoft Edge `DnsOverHttpsMode` dan `ExtensionInstallBlocklist` (dan indeks kebijakan) | https://learn.microsoft.com/en-us/deployedge/microsoft-edge-browser-policies/dnsoverhttpsmode ; https://learn.microsoft.com/en-us/deployedge/microsoft-edge-browser-policies/extensioninstallblocklist ; https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies | primer (dokumentasi vendor) | diperbarui 2026; diakses 2026-10-18 | Tinggi. Nilai mode DoH dan perilaku default di perangkat terkelola; blocklist `*`, penonaktifan ekstensi terpasang, perilaku bila kebijakan tidak diatur |
| S20 | Microsoft Learn: Compare Microsoft Defender Vulnerability Management plans and capabilities | https://learn.microsoft.com/en-us/defender-vulnerability-management/defender-vulnerability-management-capabilities | primer (dokumentasi vendor) | diperbarui 2026-04-13; diakses 2026-10-18 | Tinggi. Browser extensions assessment hanya di add-on dan standalone, bukan inti MDE Plan 2; bukan dokumen lisensi resmi |
| S21 | Velociraptor docs: `Windows.Applications.Chrome.Extensions` | https://docs.velociraptor.app/artifact_references/pages/windows.applications.chrome.extensions/ | primer (dokumentasi proyek) | diakses 2026-10-18 | Tinggi. Field yang dilaporkan, `extensionGlobs` default Chrome, status deprecated |
| S22 | Palo Alto Networks: Traffic Log Fields (PAN-OS / NGFW) | https://docs.paloaltonetworks.com/ngfw/administration/monitoring/use-syslog-for-monitoring/syslog-field-descriptions/traffic-log-fields | primer (dokumentasi vendor) | diakses 2026-10-18 | Tinggi. Subtype start/end/drop/deny, Bytes, Bytes Sent (klien ke server), Bytes Received, Elapsed Time, Session End Reason |
| S23 | Splunk Docs: CIM 6.4 Network Traffic data model | https://help.splunk.com/en/data-management/common-information-model/6.4/data-models/network-traffic | primer | CIM 6.4; diakses 2026-10-18 | Tinggi. `bytes`, `bytes_in`, `bytes_out` dari sudut pandang perangkat pelapor; `action`, `dest_port`, `duration` dalam detik |
| S24 | Splunk Add-on for Palo Alto Networks: dokumentasi dan pemetaan CIM | https://splunk.github.io/splunk-add-on-for-palo-alto-networks/ ; https://splunk.github.io/splunk-add-on-for-palo-alto-networks/Cimmapping/ | primer (dokumentasi vendor) | versi 4.0.0; diakses 2026-10-18 | Sedang-tinggi. `pan:traffic` ke Network Traffic, eventtype `pan_traffic`, `pan_traffic_start`, `pan_traffic_end`; pemetaan per field tidak tercantum di halaman yang dibaca |
| S25 | Squid configuration directive: logformat | https://www.squid-cache.org/Doc/config/logformat/ | primer (dokumentasi proyek) | diakses 2026-10-18 | Tinggi. Kode `%>st`, `%<st`, `%st`, dan string format native |
| S26 | Squid wiki: Feature: Customizable Log Formats (LogFormat) | https://wiki.squid-cache.org/Features/LogFormat | primer (dokumentasi proyek) | diakses 2026-10-18 | Tinggi. Kolom `bytes` native adalah data yang dikirim ke klien, termasuk header |

**Catatan sumber:** pola beaconing dan DNS tunneling di Day ini berasal dari Day 03 dan 05 topik yang sama. Parameter default test Atomic diambil per 2026-10-10 dan bisa berubah; panjang nama query yang dihasilkan test perlu dihitung dari data lab. Apakah `%>st` Squid mencakup byte yang dikirim klien di dalam tunnel CONNECT tidak dijelaskan di [S25]; di PT JAB hal itu diuji dengan transfer uji, dan perlu diuji ulang di versi Squid-mu. Nama field add-on Palo Alto (`src`, `dest`, `bytes_out`, `duration`) dan arah `bytes_out` tidak tercantum per field di [S24]; definisi arah diambil dari dokumentasi PAN-OS [S22] dan perlu dicek dengan transfer uji. Nama App-ID (`ssl`, `web-browsing`) dan perilaku firewall terhadap ECH perlu dicek di dokumentasi PAN-OS versi-mu. Rumus CV untuk jitter merata (sekitar j dibagi akar 3) adalah hitungan statistik dasar untuk distribusi seragam, bukan dari sumber yang dirujuk; tanggal persis penggantian nama T1176 tidak tercantum di halaman yang dibaca. Halaman Zeek [S4] membatasi akses otomatis saat dicek ulang, sehingga detail akurasi byte diambil dari kode sumber Zeek [S5]. Seluruh isi PT JAB (`HUNT-2027-020` sampai `-022`, host, angka, domain, ekstensi `StatusPulse`, label) adalah penerapan catatan ini pada organisasi fiktif, bukan hasil eksekusi nyata.
