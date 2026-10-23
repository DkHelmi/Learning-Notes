---
day: 15
title: 'Ketika SNI ikut terenkripsi: ECH (RFC 9849), batas visibilitas baru, dan JA4+'
researched_on: 2026-10-23
versions_checked: 'RFC 9849 TLS Encrypted Client Hello (Standards Track, Maret 2026; ekstensi 0xfe0d, ech_outer_extensions 0xfd00, alert ech_required 121); RFC 9848 Bootstrapping ECH with DNS Service Bindings (Standards Track, Maret 2026; SvcParamKey ech nomor 5); RFC 9460 (SVCB dan HTTPS RR); Wireshark 4.6.9 stabil dan 4.4.19 old stable, 5.0.0rc1 rilis pengembangan (field tls.ech.* sejak 4.2.0, tls.ech_accepted dan tls.ech_rejected sejak 4.6.0; dns.svcb.svcparam.echconfig hanya 3.6.0 sampai 4.0.17); Zeek 9.0.0 (ssl.log docs current); JA4+ FoxIO repo (JA4 BSD 3-Clause, JA4+ lain FoxIO License 1.1), plugin Zeek zeek/foxio/ja4 v1.0.0 (14 Agu 2026, port C++, butuh Zeek 7.0+) dan v1.0.1 (31 Agu 2026); Microsoft Edge policy EncryptedClientHelloEnabled (Edge 108+); Cloudflare ECH docs; Chromium Intent to Ship ECH (Chrome 117)'
---

# Day 15: ECH dan JA4+ ketika SNI ikut terenkripsi

Cakupan: apa yang hilang dari pandangan sensor ketika Encrypted Client Hello dipakai, apa yang masih tersisa untuk dianalisis, cara membedakan ECH sungguhan dari GREASE, dan bagaimana keluarga fingerprint JA4+ mengisi sebagian celahnya.

## Ide inti

Day 06 bertumpu pada satu kenyataan yang menyenangkan: walaupun isi TLS terenkripsi, ClientHello dikirim polos, sehingga SNI memberi tahu tujuan koneksi. Hampir semua praktik pemantauan dan penyaringan berbasis nama host bersandar pada satu field itu. Encrypted Client Hello (ECH) menutupnya. Klien membungkus ClientHello yang sebenarnya (berisi SNI asli dan ALPN) dalam ClientHello luar yang terenkripsi ke kunci publik penyedia, lalu menaruh nama publik milik penyedia di SNI luar [S1]. Sejak RFC 9849 terbit Maret 2026 sebagai Standards Track [S1], ini bukan lagi eksperimen.

Gagasan yang membuat sisa Day ini masuk akal: ECH menyembunyikan satu field, bukan seluruh koneksi. Alamat IP server, kueri DNS yang masih polos, fingerprint klien, dan pola ukuran serta waktu tetap terlihat, dan spesifikasinya sendiri menyatakan hal itu [S1]. Pekerjaan analyst bergeser dari "baca SNI" menjadi "rangkai bukti yang tersisa": DNS dan rekaman HTTPS yang membawa konfigurasi ECH, log perangkat yang memang melihat nama tujuan (proxy), fingerprint keluarga JA4 yang kini bisa dihitung Zeek, dan pola beacon. Ada satu jebakan besar di tengahnya: browser modern menyisipkan ekstensi ECH palsu (GREASE) di hampir setiap ClientHello, sehingga "ada ekstensi ECH" tidak sama dengan "SNI tersembunyi". Menghitung celah visibilitas tanpa memisahkan keduanya menghasilkan angka yang menakutkan dan salah.

Kamu sudah mengenal bentuk ini dari NOC. Pelanggan remote access VPN semuanya terlihat menuju IP concentrator yang sama; tujuan sebenarnya ada di dalam tunnel, dan yang tersisa untuk NOC hanya alamat concentrator, volume, waktu, dan log concentrator itu sendiri. ECH bekerja seperti itu untuk satu pesan: SNI luar menunjuk "concentrator" milik penyedia (client-facing server), tujuan sebenarnya ada di dalam. GREASE ECH mirip dummy packet di ESP (next header 59) yang sengaja dikirim agar pengamat tidak bisa membedakan trafik sungguhan dari pengisi. Batas analoginya ada dua. Concentrator VPN biasanya milik satu organisasi, sedangkan client-facing server ECH melayani ribuan situs tak berhubungan sehingga IP-nya hampir tidak bercerita apa pun. Dan berbeda dengan tunnel, ECH hanya menutup ClientHello: kueri DNS sebelum koneksi tetap bisa membocorkan nama tujuan bila DNS masih polos.

```
                         klien (browser / aplikasi / implant)
                                     |
          DNS polos: HTTPS RR "sync.harbor-ledger.example" -> ech=..., ipv4hint=...
                                     |            (terlihat di index=dns dan dns.log)
                                     v
   ClientHelloOuter  SNI = public_name (ech.edgefront.example)   <- yang dilihat sensor
                     ekstensi encrypted_client_hello: config_id, cipher, enc, payload
                     +--------------------------------------------------+
                     | ClientHelloInner (terenkripsi HPKE)              |
                     | SNI asli: sync.harbor-ledger.example, ALPN asli   |
                     +--------------------------------------------------+
                                     |
                                     v
              client-facing server (IP CDN bersama, 203.0.113.188)
                     |  dekripsi berhasil (accept)     | gagal (reject)
                     v                                 v
              backend server asli           handshake dengan CH luar,
                                            sertifikat public_name, retry_configs,
                                            klien coba ulang di koneksi baru
```

Situasi Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif di Jakarta dengan sekitar 1.200 karyawan. Sejak Senin 2027-05-03 SOC menjalankan Program NSM PT JAB, percobaan Mei sampai Juli 2027. Kamu analyst L2 dengan latar tujuh tahun di NOC dan menjadi pelaksana program. Sensor yang hidup: `jkt-zeek01` (`10.20.70.12`, Zeek 9.0, sejak Selasa 2027-05-18) dan `jkt-ids01` (`10.20.70.11`, Suricata 8.0.7, sejak Rabu 2027-05-19), keduanya dari SPAN core switch data center dan TAP egress Jakarta lewat packet broker `jkt-npb01`; ring buffer pcap `jkt-pcap01` (`10.20.70.13`) di egress Jakarta dengan target retensi 72 jam; dan kolektor flow NOC `jkt-flow01`. TAP egress berada di sisi dalam `jkt-fw01`, sebelum NAT. Trafik web kantor keluar lewat proxy eksplisit `jkt-proxy01` (`10.20.3.60:3128`, Squid SslBump), yang mendekripsi (bump) domain baru dan tidak terkategori dan meneruskan apa adanya (splice) kategori dikenal; konsekuensinya untuk fingerprint di egress dibahas di Day 06 bagian 1.7. Sejak Kamis 2027-06-10 10:00 WIB, Rudi Hartanto (analyst L2) mengaktifkan plugin JA4+ FoxIO di `jkt-zeek01`, sehingga `ssl.log`, `conn.log`, dan `http.log` di index `zeek` kini membawa fingerprint keluarga JA4. Bersamaan dengan itu, rule Splunk baru `NSM - JA4 langka di egress` dijadwalkan berjalan pertama kali Senin 06:00 WIB.

Senin 2027-06-14 pukul 08:20, SOC lead Dimas Prasetyo menulis di kanal SOC:

> "Pagi. Gilang iseng hitung satu file pcap egress jam 07:00 tadi: 68,6% ClientHello bawa ekstensi ECH. Artinya dua pertiga trafik kita sudah tidak bisa dibaca SNI-nya? Lalu rule JA4 baru langsung keluar dua alert, 0670 dan 0672. Yang 0670 SNI-nya `ech.edgefront.example`, itu kan nama CDN, bukan tujuan. Kalau SNI tidak bisa dipercaya, tujuan sebenarnya kita tahu dari mana? Bambang tanya apa ECH bisa dimatikan saja di firewall. Satu lagi, Rudi mau pakai JA4S, JA4H, JA4SSH yang ikut terpasang. Aman lisensinya? Siang ini aku perlu jawaban untuk Pak Hendra."

Pesan itu memuat tujuh pertanyaan:

1. Apa persisnya yang disembunyikan ECH, dan apa yang tetap terlihat?
2. Bagaimana ECH bekerja, sampai SNI `ech.edgefront.example` bisa muncul untuk tujuan yang berbeda-beda?
3. Benarkah 68,6% trafik sudah tertutup, atau angka itu salah baca?
4. Di jaringan PT JAB yang memakai proxy eksplisit, di mana ECH sebenarnya mengurangi visibilitas?
5. Bila SNI tidak bisa dipercaya, dari mana tujuan sebenarnya diketahui?
6. Apa saja anggota JA4+, bagaimana memakainya untuk `SOC-2027-0670` dan `SOC-2027-0672`, dan bagaimana lisensinya?
7. Bisakah ECH dimatikan, dan siapa yang berhak memutuskan?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2 dan 1.3, pertanyaan 3 di bagian 1.4, pertanyaan 4 di bagian 1.5, pertanyaan 5 di bagian 1.6, pertanyaan 6 di bagian 1.7 dan 1.8, dan pertanyaan 7 di bagian 1.9. Bagian 2 menerapkan semuanya ke data Senin pagi, membuka `INC-2027-074`, dan diakhiri jawaban untuk Dimas di bagian 2.10.

Day ini hanya membaca metadata yang memang terlihat oleh siapa pun di jalur dan mendekripsi trafik lab milik sendiri. Semua data PT JAB fiktif, IP luar memakai rentang dokumentasi, dan domain memakai akhiran `.example`.

**Kapan relevan:** ketika SNI di `ssl.log` atau pcap menunjuk nama penyedia yang sama untuk banyak tujuan; ketika harus mengukur seberapa besar celah visibilitas TLS dengan angka yang bisa dipertanggungjawabkan; ketika mencari klien tak lazim di trafik terenkripsi dengan JA4, JA4S, JA4H, JA4T, atau JA4SSH; ketika manajemen bertanya apakah ECH perlu diblokir atau dimatikan lewat kebijakan.
**Kapan bukan jawaban:** ketika pertanyaannya tentang isi sesi (file apa yang dikirim), karena ECH dan JA4+ hanya memberi metadata; ketika DNS juga terenkripsi dan klien memakai QUIC, karena jalur DNS ikut tertutup dan itu pokok Day 16; ketika trafik lewat proxy dekripsi yang sudah mencatat nama tujuan, karena di sana log proxy lebih langsung daripada analisis ECH; dan ketika yang dibutuhkan adalah identitas proses di host, karena itu pekerjaan data endpoint.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (pcap, SPAN, TAP, ring buffer, `uid`, `conn_state`, SNI, ALPN, ClientHello, ServerHello, JA3, JA4 dasar, GREASE, splice dan bump, beacon, CV, prevalence) tidak diulang [S4]; ECH dan JA4+ hanya disebut sekilas di Day 06, jadi rinciannya ada di sini. Tabel ini memuat istilah yang dipakai Day ini; kolom kanan memakai padanan dari pekerjaan NOC dan ISP.

| Istilah | Arti singkat | Padanan di NOC/ISP |
|---|---|---|
| ECH (Encrypted Client Hello) | Ekstensi TLS 1.3 yang mengenkripsi ClientHello sebenarnya, termasuk SNI dan ALPN, ke kunci publik penyedia | Remote access VPN: hanya alamat concentrator yang terlihat, tujuan di dalam tunnel |
| ClientHelloOuter / ClientHelloInner | Amplop polos yang dilihat sensor / ClientHello sebenarnya yang terenkripsi di dalam amplop | Header luar tunnel GRE/IPsec / paket asli pelanggan di dalamnya |
| `public_name` | Nama DNS client-facing server yang ditaruh di SNI luar; sama untuk semua situs di belakang penyedia itu | Nama concentrator VPN yang sama untuk semua pelanggan |
| Client-facing server / backend server | Server yang mendekripsi ClientHello luar / server tujuan sebenarnya; bisa satu entitas (shared mode) atau terpisah (split mode) | Concentrator / server di belakang concentrator |
| ECHConfig, `ECHConfigList`, `config_id` | Paket konfigurasi berisi kunci publik HPKE, cipher, `public_name`, `maximum_name_length`; `config_id` satu byte menandai konfigurasi yang dipakai | Profil tunnel dengan ID kebijakan yang bisa dibaca di header |
| HPKE | Hybrid Public Key Encryption, skema enkripsi yang dipakai ECH untuk ClientHelloInner | Pertukaran kunci untuk SA, di sini satu arah ke kunci publik server |
| HTTPS RR / SVCB | Tipe rekaman DNS (HTTPS = tipe 65) yang membawa parameter layanan seperti `alpn`, `ipv4hint`, dan `ech` | Rekaman provisioning yang memberi tahu CPE parameter tunnel sebelum terhubung |
| GREASE ECH | Ekstensi ECH palsu berisi data acak yang dikirim klien ketika tidak punya konfigurasi, supaya ECH sungguhan tidak menonjol | Dummy packet ESP (next header 59) untuk menyamarkan pola trafik |
| `retry_configs` | Konfigurasi ECH terbaru yang dikirim server saat menolak ECH, terenkripsi di EncryptedExtensions | Concentrator membalas "profil kunci sudah berganti, pakai yang ini" |
| `ech_required` | Alert TLS nomor 121 yang dikirim klien sebelum menutup koneksi yang ECH-nya ditolak | Pesan teardown dengan kode alasan |
| Accept confirmation | Sinyal di 8 byte terakhir `ServerHello.random` yang menyatakan ECH diterima; hanya bisa diverifikasi pihak yang tahu ClientHelloInner | Bit status di header yang hanya bermakna bagi ujung tunnel |
| Prakonfigurasi ECH | Konfigurasi ECH ditanam di aplikasi, tanpa mengambil dari DNS | Profil tunnel yang di-hardcode di firmware CPE |
| JA4S, JA4H, JA4X, JA4SSH | Fingerprint respons server TLS, klien HTTP, sertifikat X.509, dan sesi SSH dari keluarga JA4+ | Tanda pengenal implementasi untuk protokol yang berbeda |
| JA4T/JA4TS, JA4L/JA4LS | Fingerprint parameter TCP klien/server dan ukuran latensi klien ke server/server ke klien | Sidik jari OS dari opsi TCP dan RTT yang diukur dari dua sisi |
| FoxIO License 1.1 | Lisensi JA4+ selain JA4: boleh untuk akademik dan internal bisnis, tidak untuk monetisasi tanpa lisensi OEM | Lisensi feature set router: boleh dipakai sendiri, tidak boleh dijual ulang |
| Peta celah visibilitas | Daftar domain dan sumber yang tujuannya tidak lagi bisa dibaca dari jaringan, beserta angkanya | Daftar link yang tidak di-export NetFlow |

### 1.1 Yang hilang dan yang tersisa

Pertanyaan pertama Dimas ("dua pertiga trafik tidak bisa dibaca?") baru bisa dijawab setelah jelas apa persisnya yang ditutup ECH. Tanpa itu, setiap angka tentang "trafik tertutup" tidak punya definisi.

Tabel berikut membandingkan unsur ClientHello sebelum dan sesudah ECH. Cari baris yang tetap terbaca, karena di situlah analisis berikutnya bertumpu.

| Unsur | Sebelum ECH | Dengan ECH |
|---|---|---|
| SNI (nama server tujuan) | Terbaca di ClientHello | Berada di ClientHelloInner yang terenkripsi [S1] |
| ALPN | Terbaca | Ikut terlindungi [S1] |
| Alamat IP server | Terbaca | Tetap terbaca [S1] |
| Nama publik penyedia | Tidak ada | Terbaca di `server_name` luar sebagai `public_name` [S1] |
| `config_id`, cipher suite HPKE, kunci terenkapsulasi (`enc`) | Tidak ada | Terbaca di ClientHello luar [S1] |
| Kueri DNS | Terbaca bila DNS polos | Tetap terbaca bila DNS polos [S1] |
| Ukuran, arah, dan waktu paket | Terbaca | Tetap terbaca |

Baris kueri DNS yang paling penting untuk pekerjaan sehari-hari. Spesifikasinya sendiri menyatakan ECH tidak menyembunyikan segalanya: kueri DNS yang masih polos dan alamat IP server yang terlihat tetap bisa mengungkap tujuannya, sehingga DNS terenkripsi dianjurkan dipakai bersama ECH [S1]. Selama DNS di jaringanmu belum terenkripsi, ECH saja belum membuatmu buta. Begitu keduanya dipakai bersama, barulah celahnya lebar, dan itu pokok Day 16. RFC 9849 juga mencatat jalur bocor lain: lalu lintas pemeriksaan pencabutan sertifikat (OCSP, CRL) dan cookie HelloRetryRequest yang tidak terenkripsi bisa mengungkap identitas server [S1].

Satu hal hilang dan sulit diganti: sertifikat server. Pada TLS 1.3 sertifikat sudah terenkripsi (Day 06), jadi identifikasi lewat sertifikat hanya tersisa untuk koneksi TLS 1.2 yang makin sedikit. ECH sendiri hanya bekerja di TLS 1.3, sehingga koneksi ber-ECH tidak pernah punya sertifikat polos.

Contoh konkret dari dunia nyata: Cloudflare mengaktifkan ECH secara bawaan untuk zona Free dan memakai satu nama, `cloudflare-ech.com`, sebagai SNI luar untuk semua situs di belakangnya [S12]. Dokumentasinya menyatakan pihak di tengah bisa tahu pengunjung memakai Cloudflare, tetapi tidak tahu situs yang mana [S12]. Di PT JAB, penyedia fiktif `edgefront.example` dengan `public_name` `ech.edgefront.example` memainkan peran itu.

Seberapa jauh log Zeek ikut kehilangan informasi terlihat dari contoh di dokumentasi `ssl.log`: kunjungan ke situs uji ESNI/ECH yang memakai DNS over HTTPS menghasilkan entri tanpa `server_name` dan tanpa data sertifikat, hanya versi, cipher, curve, `resumed`, dan `established` [S10]. Contoh itu memakai varian lama (ESNI); pada ECH menurut RFC 9849, SNI luar berisi `public_name`, sehingga `server_name` kemungkinan terisi nama penyedia, bukan kosong. Cek perilaku Zeek-mu di lab sebelum menulis rule yang bergantung pada kolom itu.

### 1.2 Mekanika: dua ClientHello, `public_name`, dan konfigurasi dari DNS

Pertanyaan kedua Dimas muncul dari `SOC-2027-0670`: SNI `ech.edgefront.example` dipakai untuk tujuan yang berbeda-beda. Untuk memahami kenapa, kamu perlu tahu siapa membuat amplop apa.

Tiga peran [S1]: klien yang menyusun handshake terlindungi; client-facing server yang mendekripsi ClientHello luar, yang bisa merupakan entitas yang sama dengan backend (shared mode) atau pihak terpisah (split mode); dan backend server yang menyelesaikan handshake dengan klien ketika ECH diterima.

Dua ClientHello [S1]. Yang dalam adalah yang sebenarnya, memuat nama server asli dan preferensi klien. Yang luar adalah amplop berisi ekstensi `encrypted_client_hello` (kode 0xfe0d, atau 65037 desimal) yang memuat pesan dalam dalam bentuk terenkripsi, dan amplop itu diautentikasi dengan memakai dirinya sendiri sebagai associated data pada enkripsi HPKE. Isi ekstensi di ClientHello luar terbaca sebagian: `config_id`, cipher suite, `enc`, dan `payload` terenkripsi [S1]. Ekstensi yang tidak sensitif boleh disalin dari ClientHello dalam ke luar, dan RFC menyediakan ekstensi `ech_outer_extensions` (0xfd00, hanya muncul di ClientHello dalam) untuk merujuk ekstensi luar tanpa mengirimnya dua kali [S1].

Nama publik [S1]. Klien sebaiknya menaruh `public_name` dari konfigurasi ECH di ekstensi `server_name` luar. Nama itu mengidentifikasi client-facing server dan dipakai untuk mengautentikasi koneksi bila ECH ditolak. Konsekuensi praktis bagi pemeriksa: SNI yang kamu lihat pada koneksi ber-ECH adalah nama penyedia, bukan tujuan sebenarnya. Menyimpulkan tujuan dari SNI pada koneksi semacam itu akan salah secara sistematis.

Padding [S1]. Panjang ClientHelloInner bisa membocorkan panjang nama tujuan, jadi klien menambah padding: nama dipadatkan sampai `maximum_name_length` dari konfigurasi, dan hasil akhirnya dibulatkan ke kelipatan 32 byte. Akibatnya, ukuran ekstensi ECH tidak bisa dipakai menebak panjang nama tujuan.

Cara klien memperoleh konfigurasi [S1][S5]. Konfigurasi berbentuk `ECHConfigList` berisi kunci enkripsi dan metadata. RFC 9849 mendelegasikan publikasi lewat DNS ke RFC 9460, dengan RFC 9848 mengatur pengumumannya di rekaman SVCB dan HTTPS [S1][S3]. RFC 9848 mendefinisikan SvcParamKey `ech` bernomor 5; bentuk tampilannya Base64 dari `ECHConfigList` [S5]. Rekaman HTTPS sendiri (tipe 65) membawa parameter layanan lain seperti `alpn` dan `ipv4hint` [S3]. Cara lain, seperti prakonfigurasi di aplikasi, juga dimungkinkan [S1]. Untuk pemeriksa, ini berarti rekaman HTTPS di DNS menjadi artefak baru yang layak dikumpulkan, karena kueri HTTPS memuat nama tujuan asli dan jawabannya memuat `public_name` di dalam `ech`.

RFC 9848 menambahkan dua aturan perilaku yang berguna dibaca dari sisi sensor [S5]. Pertama, bila semua alternatif endpoint di rekaman HTTPS punya parameter `ech`, klien wajib memakai mode "SVCB-reliant": tidak jatuh kembali ke koneksi tanpa ECH. Kedua, klien yang mendukung ECH tidak boleh mengirim ClientHello sampai resolusi SVCB selesai. Urutan di kabel karenanya hampir selalu kueri HTTPS dulu, lalu koneksi TLS. Dalam bahasa korelasi: cari kueri HTTPS (tipe 65) beberapa detik sebelum koneksi ber-ECH.

Chromium memperoleh konfigurasi lewat rekaman HTTPS, dan pengumuman peluncurannya menyebut Chrome bisa mengambil rekaman itu lewat DoH dan lewat resolver bawaan Chrome [S13]. ECH aktif bawaan sejak Chrome 117 [S13]. Edge, yang berbasis Chromium dan dipakai di workstation PT JAB, punya kebijakan `EncryptedClientHelloEnabled` sejak Edge 108; dokumentasinya menyatakan Edge bisa memakai atau tidak memakai ECH tergantung dukungan server, ketersediaan rekaman HTTPS, dan status rollout [S11].

### 1.3 Penolakan, percobaan ulang, dan sinyal penerimaan

Bagian kedua pertanyaan Dimas menyentuh hal yang lebih halus: kalau ECH bisa gagal, seperti apa kegagalannya di kabel? Pola ini nanti menjadi salah satu bukti terkuat di `INC-2027-074`.

Bila server tidak bisa atau tidak mau mendekripsi ekstensinya, ia mengabaikan ekstensi itu dan menyelesaikan handshake dengan ClientHello luar, dan klien mengautentikasi koneksi terhadap nama publik [S1]. Bila server punya konfigurasi ECH, ia mengirim `retry_configs` berisi kunci terbaru di EncryptedExtensions [S1]. Klien harus memvalidasi sertifikat untuk `public_name`; bila validasi gagal, klien membatalkan koneksi dan tidak boleh memakai `retry_configs` [S1]. Bila validasi berhasil, klien boleh mencoba ulang dengan konfigurasi baru lewat koneksi transport baru, dan wajib mengirim alert `ech_required` (nomor 121) sebelum menutup koneksi yang ditolak [S1]. Klien tidak boleh kembali ke ClientHello tanpa enkripsi, tidak boleh menganggap penolakan sebagai sinyal untuk mematikan ECH kecuali server mematikannya secara aman, dan tidak boleh memakai koneksi yang ditolak itu untuk data aplikasi [S1].

Pola penolakan dan percobaan ulang itu punya bentuk yang khas di kabel: satu koneksi yang handshake-nya selesai tanpa data aplikasi, ditutup dalam waktu singkat, lalu koneksi baru ke tujuan yang sama. Pada TLS 1.3, `retry_configs` dan alert `ech_required` sendiri sudah terenkripsi, jadi sensor tidak membacanya. Yang terbaca adalah bentuk koneksinya dan satu detail yang sering terlewat: `config_id` di ClientHello luar berubah antara koneksi pertama dan kedua, karena koneksi kedua memakai konfigurasi dari `retry_configs`.

Penolakan paling sering terjadi ketika klien memakai konfigurasi yang sudah kedaluwarsa. Penyedia merotasi kunci ECH secara berkala, dan klien yang mengambil konfigurasi dari DNS biasanya selalu mendapat yang terbaru. Klien yang menyimpan konfigurasi lama, atau aplikasi yang ditanam konfigurasi (prakonfigurasi), akan ditolak setiap kali kunci berganti. Dalam investigasi, ini petunjuk tentang bagaimana klien dikonfigurasi, dan kadang tentang alat apa yang dipakai.

Sinyal sebaliknya, ECH diterima, dikirim backend dengan menimpa 8 byte terakhir `ServerHello.random` dengan nilai turunan HKDF dari transkrip ClientHelloInner; peluang kebetulan cocok sekitar 1 banding 2 pangkat 64 [S1]. Wireshark sejak 4.6.0 punya label `tls.ech_accepted` dan `tls.ech_rejected` yang menyatakan apakah konfirmasi hasil hitungan cocok dengan byte di Server Random [S6]. Karena hitungannya memakai ClientHelloInner, label ini hanya bisa muncul bila Wireshark punya bahan untuk membuka bagian dalam, misalnya keylog berisi `ECH_SECRET` dari klien lab milikmu (Day 06 bagian 1.8). Di pcap produksi tanpa keylog, jangan berharap label itu muncul; cek perilakunya di lab dengan versi Wireshark-mu.

### 1.4 GREASE ECH: ekstensi ada belum tentu SNI tertutup

Pertanyaan ketiga Dimas (68,6%) terjawab di sini. Angka Gilang menghitung ClientHello yang membawa ekstensi `encrypted_client_hello`, tetapi tidak semua ekstensi itu berisi ECH sungguhan.

RFC 9849 meminta klien yang mendukung ECH tetapi tidak punya konfigurasi untuk tujuan tertentu mengirim ekstensi ECH palsu, disebut GREASE ECH: `config_id` acak, cipher suite yang masuk akal, `enc` acak, dan `payload` acak dengan ukuran seperti yang asli [S1]. Tujuannya memberi "perlindungan" bagi ECH sungguhan: bila setiap ClientHello browser membawa ekstensi itu, jaringan tidak bisa memblokir pemakai ECH tanpa merusak hampir semua koneksi [S1]. Chromium menerapkan GREASE ECH dan menyebutnya akan terlihat seperti ekstensi tak dikenal biasa bagi server yang tidak mendukung ECH [S13]. Pada koneksi GREASE, SNI luar tetap nama tujuan yang asli, karena memang tidak ada amplop.

Bagian 10.10.4 RFC 9849 menyatakan ECH dirancang menyerupai handshake TLS biasa, tetapi klaim tidak bisa dibedakannya terbatas: hanya berlaku terhadap pengamat pasif yang tidak tahu `ECHConfigList`, dan secara eksplisit tidak mencakup `config_id`, SNI luar, versi TLS yang dinegosiasikan, dan munculnya HelloRetryRequest [S1]. Pengamat yang mengumpulkan konfigurasi ECH dari DNS bisa memisahkan keduanya. Itu yang dilakukan bagian 2.2.

Tabel berikut adalah pegangan untuk memisahkan ECH sungguhan dari GREASE di data pasif. Baca kolom "Cara cek" untuk tahu field mana yang dipakai.

| Ciri | ECH sungguhan | GREASE ECH | Cara cek |
|---|---|---|---|
| SNI luar | Sama dengan `public_name` penyedia, berulang untuk banyak tujuan | Nama tujuan asli | Cocokkan SNI dengan daftar `public_name` dari rekaman HTTPS |
| `config_id` | Sama untuk banyak klien ke penyedia yang sama selama satu periode kunci | Acak per koneksi | Stacking `tls.ech.config_id` per SNI |
| Kueri DNS sebelumnya | Kueri HTTPS (tipe 65) untuk nama asli dengan jawaban `ech=` | Tidak harus ada | `index=dns query_type=HTTPS` atau `dns.log` |
| JA4 klien | Sama dengan GREASE untuk klien yang sama | Sama | Tidak bisa dipakai membedakan |

Baris terakhir perlu ditekankan. JA4 menghitung ekstensi tanpa nilai GREASE, tetapi GREASE ECH memakai kode ekstensi yang asli (0xfe0d), bukan nilai GREASE yang dicadangkan [S1][S2]. Akibatnya, ClientHello Edge ber-ECH sungguhan dan ClientHello Edge ber-GREASE ECH menghasilkan jumlah ekstensi dan hash ekstensi yang sama, sehingga JA4-nya identik. Kesimpulan ini adalah penalaran dari definisi kedua spesifikasi; buktikan sendiri di lab dengan membandingkan dua ClientHello dari browser yang sama (bagian 3, langkah 3).

Jadi angka 68,6% menjawab pertanyaan "berapa ClientHello dari klien yang mendukung ECH", bukan "berapa koneksi yang SNI-nya tertutup". Bagian 2.1 dan 2.2 menghitung ulang angka kedua untuk file yang sama.

### 1.5 ECH di jaringan dengan proxy eksplisit

Pertanyaan keempat Dimas membutuhkan peta PT JAB. ECH tidak mengurangi visibilitas secara merata; dampaknya bergantung pada siapa yang membuat ClientHello yang lewat sensor dan siapa yang melihat nama tujuan sebelum enkripsi.

Ada empat jalur trafik TLS di TAP egress Jakarta. Tabel ini memetakan apa yang tersisa untuk tiap jalur; cari kolom "Nama tujuan masih terlihat di", karena itu jawaban praktisnya.

| Jalur | ClientHello di egress | Bisa membawa ECH sungguhan? | Nama tujuan masih terlihat di |
|---|---|---|---|
| Workstation lewat proxy, kategori di-bump | Buatan `jkt-proxy01` | Tidak teramati di PT JAB; ClientHello buatan proxy tidak membawa ekstensi ECH | Log proxy (`CONNECT` host dan URL) |
| Workstation lewat proxy, kategori di-splice | Milik klien asli, diteruskan apa adanya | Ya, bila klien memakainya | Log proxy (`CONNECT` host), kecuali klien sengaja `CONNECT` ke `public_name` |
| Server data center keluar langsung (NAT `198.51.100.206`) | Milik aplikasi di server | Ya, bila library aplikasi mendukung | `dns.log` dan `index=dns`, bila server memakai resolver internal |
| Wi-Fi tamu `JAB-Tamu` (`10.10.250.0/24`, keluar langsung lewat `jkt-fw01` dengan NAT `198.51.100.215`, tanpa proxy) | Milik perangkat tamu | Ya; perangkat tidak dikelola, kebijakan browser PT JAB tidak berlaku | `dns.log` bila perangkat memakai resolver DHCP; tidak ada bila memakai DoH |

Baris pertama dan kedua menunjukkan kabar baik untuk workstation: proxy eksplisit melihat nama tujuan di permintaan `CONNECT host:443` sebelum TLS dimulai (Day 06 bagian 1.3), jadi ECH di jalur luar tidak menghapus nama itu dari log proxy. Celahnya muncul pada satu pola: klien yang sengaja meminta `CONNECT` ke `public_name` itu sendiri. Proxy hanya tahu nama penyedia, kategori CDN biasanya di-splice, dan ClientHello ber-ECH keluar apa adanya. Itulah pola `SOC-2027-0670`.

Bagian 8.1.2 RFC 9849 membahas proxy yang mengakhiri TLS tetapi tidak mendukung ECH. Proxy seperti itu harus mengabaikan parameter yang tidak dikenal dan terhubung seolah ke nama di ClientHello luar, yaitu `public_name`, tanpa meneruskan ECH; hasilnya bergantung pada apakah klien menerima sertifikat proxy untuk nama publik itu, yang bisa memicu percobaan ulang atau kegagalan koneksi [S1]. Proxy yang tidak berwenang atas `public_name` juga tidak bisa memalsukan sinyal untuk mematikan ECH [S1]. Untuk PT JAB, artinya bump terhadap klien yang memakai ECH sungguhan berpotensi gagal atau berperilaku aneh. Apakah Squid versi PT JAB menghasilkan pola itu, dan apakah Edge memakai ECH sama sekali ketika dikonfigurasi memakai proxy eksplisit, belum diukur. Rudi menjadwalkan uji dengan workstation uji SOC `JKT-WS-2070` (`10.10.60.150`); sampai hasilnya ada, perlakukan kedua hal itu sebagai pertanyaan terbuka, bukan fakta.

Wi-Fi tamu adalah sumber ECH sungguhan terbesar di egress, karena perangkat tamu memakai browser dengan pengaturan bawaan. Trafik itu juga data pribadi pihak ketiga. Kebijakan akses pcap program (Day 01) berlaku: analisis segmen tamu cukup agregat (jumlah koneksi, persentase), tanpa membuka sesi individu, kecuali ada insiden dan persetujuan sesuai prosedur.

### 1.6 Pengganti SNI

Pertanyaan kelima Dimas ("tujuan sebenarnya dari mana?") dijawab dengan empat bahan yang tersisa, plus log perangkat yang melihat nama sebelum enkripsi. Urutan di bawah dari yang paling kuat ke yang paling lemah untuk jaringan seperti PT JAB.

1. **Log perangkat perantara.** Di jaringan dengan proxy eksplisit, log proxy mencatat host di `CONNECT`. Ini bukan data jaringan pasif, tetapi paling langsung, kecuali klien sengaja `CONNECT` ke `public_name` (bagian 1.5).
2. **DNS.** Selama belum terenkripsi, kueri DNS menjelaskan tujuan yang hendak dihubungi [S1]. Untuk ECH, kueri HTTPS (tipe 65) paling informatif karena menyebut nama asli tepat sebelum koneksi ber-ECH (bagian 1.2). Korelasikan kueri dan koneksi berdasarkan waktu dan alamat jawaban. Ini jalur paling produktif selama masa transisi, dan Day 16 membahas apa yang terjadi ketika jalur ini pun tertutup.
3. **Alamat IP server dan konteksnya.** Tetap terlihat [S1]. Nilainya bergantung pada apakah alamat itu dipakai bersama banyak layanan. Client-facing server ECH hampir selalu IP CDN bersama, sehingga nilainya kecil untuk koneksi ber-ECH; di luar itu, alamat masih sangat berguna.
4. **Fingerprint.** Karakteristik klien dan server tetap bisa diukur, dan di sinilah keluarga JA4 bekerja (bagian 1.7). ECH tidak mengubah daftar cipher dan ekstensi ClientHello luar secara berarti, sehingga fingerprint klien tetap terbaca.
5. **Pola lalu lintas.** Ukuran, arah, dan waktu paket tetap terlihat, dan pola beaconing tetap terdeteksi tanpa mengetahui nama tujuan sama sekali (Day 11 bagian 1.3).

Ada satu jebakan dalam memakai sumber di luar rekaman. Untuk alamat yang perlu diidentifikasi, kamu bisa memakai data pasif tentang alamat dan nama, informasi pendaftaran, dan rekaman DNS historis. Nyatakan di laporan bahwa identifikasi itu berasal dari sumber luar, bukan dari rekaman trafik. Dan jangan melakukan kueri aktif ke domain milik penyerang dari jaringan kantor sebelum bukti pasif habis dibaca: kueri itu bisa terlihat oleh pemilik nameserver.

### 1.7 Keluarga JA4+ dan cara memakainya untuk hunting

Pertanyaan keenam Dimas dimulai dari plugin yang baru dipasang Rudi. Day 06 bagian 1.6 memakai JA4 untuk handshake klien TLS; JA4+ sebenarnya kumpulan metode yang lebih luas [S2].

Tabel berikut daftar metode JA4+ menurut repo resminya, ditambah di mana plugin Zeek menaruh hasilnya. Kolom terakhir yang menentukan query Splunk-mu.

| Nama pendek | Yang di-fingerprint [S2] | Di Zeek (plugin `zeek/foxio/ja4`) [S8] |
|---|---|---|
| JA4 | Handshake klien TLS | `ssl.log` |
| JA4S | Respons dan sesi server TLS | `ssl.log` |
| JA4H | Klien HTTP | `http.log` |
| JA4L dan JA4LS | Latensi klien ke server dan server ke klien | `conn.log` |
| JA4X | Sertifikat X.509 | Belum; README plugin menyebutnya menunggu dukungan objek di Zeek |
| JA4SSH | Trafik SSH | `ja4ssh.log` (log baru) |
| JA4T dan JA4TS | Klien TCP dan respons server TCP | `conn.log` |
| JA4D dan JA4D6 | Trafik DHCP dan DHCPv6 | `ja4d.log`; JA4D6 menunggu dukungan DHCPv6 di Zeek |
| JA4N | Trafik NTP | Tidak disebut di README plugin |
| JA4TScan, JA4Scan-TLS, JA4Scan-QUIC | Pemindai aktif TCP, server TLS, server QUIC | Bukan untuk sensor pasif |

Dua sifat format yang penting untuk hunting [S2]. Pertama, setiap fingerprint memakai struktur `a_b_c` dengan tiap bagian mewakili unsur yang berbeda, sehingga kamu bisa memburu memakai hanya bagian `a`, hanya `c`, atau kombinasinya. Kedua, JA4 mengurutkan cipher dan ekstensi, sehingga pengaruh cipher stunting dan pengacakan urutan ekstensi berkurang; pengurutan itu tidak menghilangkan keunikan karena algoritma tanda tangan ikut disertakan.

Perbandingan yang diberikan dokumentasinya enak dibayangkan: pemindai yang terus mengganti satu cipher akan menghasilkan JA3 baru setiap kali, sedangkan pada JA4 hanya bagian `b` yang berubah sementara `a` dan `c` tetap, sehingga pelakunya masih bisa dilacak [S2]. Dokumentasinya juga berpendapat TLS 1.3 justru mempermudah fingerprinting klien, karena klien mendukung lebih banyak ekstensi meski menegosiasikan sedikit cipher [S2]. FoxIO juga mengingatkan bahwa fingerprint JA4 berubah ketika library TLS aplikasi diperbarui, kira-kira setahun sekali [S2]. Peringatan itu menjelaskan `SOC-2027-0672` (bagian 2.6).

Untuk ECH, JA4 punya satu kelebihan dan satu batas. Kelebihannya: JA4 dihitung dari ClientHello luar yang tetap polos, jadi ECH tidak menghapus fingerprint klien. Batasnya: karakter keempat bagian `a` bernilai `d` karena SNI luar ada (berisi `public_name`), sehingga JA4 tidak memberi tahu apakah SNI itu asli; dan seperti dibahas di bagian 1.4, JA4 tidak membedakan ECH sungguhan dari GREASE.

Pola kerja yang berguna di Zeek dengan plugin JA4+:

- Hitung frekuensi tiap nilai JA4 di jaringanmu, lalu periksa ekor yang paling jarang. Klien yang tidak lazim muncul di sini.
- Pakai pemisahan `a_b_c` untuk memburu lebih longgar [S2]. Bila kamu mencurigai satu alat yang mengganti cipher terus-menerus, cari berdasarkan bagian `a` dan `c` saja.
- Pasangkan JA4 dengan JA4S untuk melihat kombinasi klien dan server yang tidak lazim [S2].
- Untuk trafik SSH yang tidak punya SNI sejak awal, JA4SSH memberi sumbu analisis yang setara [S2].
- JA4H di `http.log` hanya bermakna untuk HTTP yang terbaca: di PT JAB itu hop core antara workstation dan proxy (permintaan HTTP polos ke `jkt-proxy01`), bukan sesi HTTPS di egress.

Plugin Zeek JA4+ dirilis ulang sebagai plugin C++ pada versi 1.0.0 (14 Agustus 2026): JA4, JA4S, JA4H, JA4SSH, dan JA4T kini fungsi BiF terkompilasi, sedangkan JA4L dan JA4D tetap skrip murni, dan syarat minimumnya naik dari Zeek 5.0 ke Zeek 7.0 [S9]. README plugin menyebut pengujian dengan Zeek 8.0.6 dan butuh compiler C++20 [S8]. Kolom mentah (`_raw`) untuk JA4, JA4S, dan JA4H diatur di `config.zeek` sebelum build dan tidak bisa diubah dengan `redef` saat berjalan; sebaliknya, tiap metode bisa dimatikan saat berjalan, dan kolomnya tetap ada tetapi kosong [S8]. PT JAB memasang v1.0.1 di Zeek 9.0 setelah uji di lab, karena README belum menyebut Zeek 9.0; nama kolom persis (`ja4`, `ja4s`, `ja4h`, `ja4t`, dan seterusnya) dicek dengan `| fieldsummary` di Splunk sebelum rule dibuat.

**Kapan gagal:** satu nilai fingerprint dipakai oleh jutaan klien sah, sehingga ia tidak pernah menjadi bukti sendirian. Di balik proxy yang mendekripsi, fingerprint di egress milik proxy (Day 06 bagian 1.7). Fingerprint berguna untuk mengelompokkan dan menyempitkan, bukan untuk mengidentifikasi.

### 1.8 Lisensi JA4+

Bagian terakhir pertanyaan keenam ("aman lisensinya?") bukan detail kecil. Dimas perlu jawaban yang bisa diteruskan ke Hendra tanpa menjadi nasihat hukum.

JA4 untuk fingerprinting klien TLS bersifat open source di bawah lisensi BSD 3-Clause, sama seperti JA3, dan FoxIO menyatakan tidak punya klaim paten atas JA4 [S2]. Seluruh metode JA4+ lainnya berstatus patent-pending dan berlisensi FoxIO License 1.1, yang disebut permisif untuk pemakaian akademik dan internal bisnis, tetapi tidak untuk monetisasi; vendor yang ingin menjualnya dalam produk perlu lisensi OEM [S2]. "JA4+" dan "JA4" juga merek dagang FoxIO [S2].

Untuk SOC PT JAB yang memakai JA4S, JA4H, JA4T, dan JA4SSH di sensor internal untuk melindungi jaringan sendiri, ketentuan itu biasanya bukan hambatan. Pertanyaannya berubah bila PT JAB menjual layanan keamanan terkelola ke pelanggan korporat yang memakai JA4+ sebagai fitur, atau menjual laporan berbasis JA4+; saat itu teks lisensi perlu dibaca Legal (Ratna Sari). Catat keputusan ini di dokumentasi sensor supaya tidak terlupa ketika layanan baru dirancang. Ini bukan nasihat hukum, hanya catatan supaya pertanyaan itu tidak terlewat.

Daftar alat yang mendukung JA4 di repo FoxIO juga berguna untuk percakapan dengan vendor: selain Wireshark, Zeek, dan Arkime, banyak CDN dan load balancer kini mencatat JA4 (repo menyebut antara lain Cloudflare, AWS CloudFront, Akamai, dan Azure Front Door untuk JA4) [S2]. Untuk Suricata, repo FoxIO masih menandainya "under development" [S2], sedangkan dokumentasi Suricata 8 sudah punya keyword `ja4.hash` (Day 09). Perbedaan itu kemungkinan soal cakupan JA4+ di luar JA4; cek catatan rilis Suricata sebelum mengandalkan anggota JA4+ lain di sana.

### 1.9 Bisakah ECH dimatikan, dan siapa yang memutuskan

Pertanyaan ketujuh datang dari Bambang: "matikan saja di firewall". Dari sudut NOC ini wajar, karena masalah protokol biasanya diselesaikan dengan ACL. Untuk ECH, jawabannya bergantung pada siapa kliennya.

Pilihan yang tersedia, dari yang paling terkendali:

- **Kebijakan browser di perangkat yang dikelola.** Edge punya kebijakan `EncryptedClientHelloEnabled` (Edge 108 ke atas, Windows, macOS, Android); bila dinonaktifkan, Edge tidak mengaktifkan ECH [S11]. Dokumentasinya menyebut kebijakan ini sebagai langkah sementara yang akan diganti kontrol final ketika protokolnya matang [S11]. RFC 9849 sendiri mengakui organisasi bisa mematikan ECH lewat kebijakan grup, dan klien sebaiknya menghormatinya [S1].
- **Di resolver.** Cloudflare menyarankan jaringan yang ingin mematikan ECH agar resolver menjawab kueri HTTPS dengan "no error no answer" atau NXDOMAIN, dan menjawab domain canary `use-application-dns.net` supaya Firefox tidak memakai ECH [S12]. Efek sampingnya, parameter lain di rekaman HTTPS (misalnya `alpn` untuk HTTP/3) ikut hilang. Cara ini hanya mengenai klien yang memakai resolver PT JAB, bukan yang memakai DoH.
- **Di firewall.** Firewall pasif tidak bisa membedakan ECH sungguhan dari GREASE dengan andal, karena ECH dirancang menyerupai handshake biasa [S1]. Memblokir semua ClientHello ber-ekstensi 0xfe0d berarti memblokir hampir semua koneksi Edge. Memblokir berdasarkan daftar `public_name` berarti memblokir semua situs di belakang CDN itu.
- **Intersepsi.** Spesifikasi ECH menyebut intersepsi dan dekripsi koneksi klien sebagai salah satu alternatif bagi pemakaian yang bergantung SNI, tetapi menyatakan kelayakannya bergantung pada penerapan masing-masing dan tidak membahas rinciannya [S1]. RFC yang sama mencontohkan dampak lain: penyeimbangan beban berbasis SNI yang perlu diperbarui [S1].

Satu hal tidak bisa diselesaikan oleh pilihan mana pun: aplikasi yang membawa konfigurasi ECH sendiri (prakonfigurasi) atau mengambilnya lewat DoH tidak peduli pada kebijakan browser atau jawaban resolver. Mematikan ECH di Edge mengurangi kebisingan, bukan menutup jalur penyerang. Deteksi untuk klien seperti itu tetap bertumpu pada log proxy, DNS, JA4, dan pola.

Perlakukan semua ini sebagai keputusan arsitektur dan kebijakan, bukan keputusan teknis analyst. Intersepsi TLS dan pemblokiran punya konsekuensi hukum, privasi, dan keamanan tersendiri. Di PT JAB, perubahan kebijakan dekripsi dan pemantauan melibatkan DPO (Agus Setiawan) dan Legal (Ratna Sari), dan keputusan akhirnya ada di Hendra. Pekerjaanmu adalah menyatakan dengan jelas apa yang bisa dan tidak bisa dijawab dari posisi jaringan, dengan angka, lalu membiarkan keputusan diambil di tempat yang tepat dengan informasi yang lengkap. Hilangnya visibilitas adalah temuan arsitektur, bukan kegagalan analisis.

## 2. Contoh dan langkah praktis: Senin pagi dengan ECH dan JA4+

Semua keluaran di bagian ini adalah keluaran ilustrasi untuk organisasi fiktif PT JAB, bukan hasil eksekusi nyata. Hash JA4 fiktif kecuali `t13d1516h2_8daaf6152771_b186095e22b6`, string contoh dari spesifikasi JA4 yang di Day 06 dipakai mewakili Edge. Nama field berbeda antar versi Wireshark dan Zeek, jadi cocokkan di lab-mu.

**Asumsi lingkungan:** pcap egress dari `jkt-pcap01` dibaca di `jkt-nsm-ws01` lewat `/mnt/pcap01/ring/` (zona waktu UTC; WIB = UTC + 7); log Zeek di `index=zeek` (sourcetype `bro:ssl:json`, `bro:conn:json`, dan `bro:dns:json`; dua yang terakhir divalidasi dengan `| metadata` seperti di Day 08); log resolver BIND di `index=dns` (`sourcetype=isc:bind:query`, field `src`, `query`, `query_type`; hanya query, tanpa jawaban); log `jkt-proxy01` di `index=proxy` dengan logformat PT JAB (`src`, `user`, `method`, `url`, `category`, `tls` berisi `splice` atau `bump`, `status`, `bytes`, `http_user_agent`). Splunk menampilkan WIB.

### 2.1 Mengulang hitungan Gilang: ClientHello ber-ekstensi ECH

Langkah pertama untuk pertanyaan ketiga Dimas adalah mengulang angka 68,6% dari file yang sama, lalu memecahnya per sumber. Angka yang tidak bisa diulang tidak boleh masuk laporan ke Hendra.

**Tujuan:** menghitung ClientHello dan ClientHello yang membawa ekstensi `encrypted_client_hello` di satu file ring 15 menit, lalu memecahnya per kelompok sumber.

```
cp /mnt/pcap01/ring/egress-jkt_*_20270614000000.pcapng \
   /cases/SOC-2027-0670/egress_20270614_0700.pcapng
F=/cases/SOC-2027-0670/egress_20270614_0700.pcapng

tshark -r $F -Y "tls.handshake.type == 1" | wc -l
tshark -r $F -Y "tls.handshake.type == 1 and tls.handshake.extension.type == 65037" | wc -l

tshark -r $F -Y "tls.handshake.type == 1" \
  -T fields -e ip.src -e tls.ech.config_id \
  | awk -F'\t' '{ g = ($1=="10.20.3.60") ? "proxy" : ($1 ~ /^10\.10\.250\./) ? "tamu" : "server-dc";
                 ch[g]++; if ($2 != "") ech[g]++ }
           END  { for (g in ch) printf "%-10s %6d %6d\n", g, ch[g], ech[g] }'
```

Penjelasan tiap bagian:

- File ring berpola `egress-jkt_NNNNN_YYYYMMDDHHMMSS.pcapng` dengan jam UTC; `20270614000000` adalah file yang dimulai 00:00 UTC, yaitu 07:00 WIB. Nomor urutnya diganti `*`. File disalin ke folder kasus dulu supaya tidak tertimpa ring buffer.
- `tls.handshake.type == 1` memilih ClientHello. `tls.handshake.extension.type == 65037` memilih ClientHello yang membawa ekstensi dengan kode 0xfe0d [S1][S6]. Field ekstensi muncul berkali-kali dalam satu ClientHello; di Wireshark 4.x, `==` berarti "salah satu nilai sama", jadi filter ini cocok bila ekstensi itu ada di mana pun dalam daftar.
- Perintah ketiga mencetak IP sumber dan `tls.ech.config_id` (ada sejak Wireshark 4.2.0 [S6]); kolom kedua kosong bila tidak ada ekstensi ECH. `awk` mengelompokkan sumber menjadi proxy, Wi-Fi tamu, dan sisanya (server data center yang keluar langsung).

Keluaran ilustrasi:

```
18420
12639

proxy       14466  10608
tamu         2874   2031
server-dc    1080      0
```

**Cara membaca hasil:** 12.639 dari 18.420 ClientHello membawa ekstensi ECH, yaitu 68,6%. Angka Gilang benar sebagai hitungan. Pecahannya menunjukkan dari mana asalnya: 10.608 dari proxy (73,3% dari 14.466 ClientHello proxy), 2.031 dari Wi-Fi tamu (70,7% dari 2.874), dan nol dari server data center. Belum ada yang menjawab apakah SNI-nya tertutup; itu tugas bagian 2.3.

Pecahan ClientHello proxy per JA4 menjelaskan lebih jauh:

```
tshark -r $F -Y "ip.src == 10.20.3.60 and tls.handshake.type == 1" \
  -T fields -e tls.handshake.ja4 -e tls.ech.config_id \
  | awk -F'\t' '{ n[$1]++; if ($2 != "") e[$1]++ } END { for (j in n) printf "%7d %7d  %s\n", n[j], e[j], j }' \
  | sort -rn | head -4
```

Keluaran ilustrasi:

```
  10512   10512  t13d1516h2_8daaf6152771_b186095e22b6
   2311       0  t13d1512h2_8daaf6152771_e99876c6e365
   1643      96  (gabungan JA4 lain, diringkas)
```

Baris pertama adalah Edge yang di-splice: setiap ClientHello-nya membawa ekstensi ECH. Baris kedua adalah ClientHello buatan proxy untuk koneksi yang di-bump (Day 06 bagian 2.5): tidak satu pun membawa ekstensi ECH, sehingga untuk sesi yang di-bump, ECH tidak pernah sampai ke egress. Sisanya aplikasi lain dengan 96 ClientHello ber-ekstensi ECH. Jumlahnya 10.512 + 0 + 96 = 10.608, cocok dengan baris proxy di atas.

Filter tampilan Wireshark untuk pekerjaan yang sama, dari catatan lama:

```
tls.handshake.type == 1 and tls.handshake.extension.type == 65037
```

Alternatif yang tidak bergantung nomor ekstensi:

```
tls.handshake.type == 1 and tls.handshake.extensions_server_name
```

lalu bandingkan nilai SNI yang muncul dengan daftar nama publik penyedia. SNI yang selalu bernilai nama penyedia pada banyak koneksi ke alamat berbeda adalah tanda `public_name` sedang dipakai [S1]. Di Wireshark 4.2.0 ke atas, cara yang paling langsung adalah `tls.ech.payload` atau `tls.ech.config_id` sebagai filter keberadaan [S6].

Bentuk yang perlu kamu kenali di daftar paket (diringkas dari file yang sama, dua koneksi Wi-Fi tamu dan satu dari server data center):

```
No.    Waktu (UTC)   Sumber         Tujuan          SNI luar                  Ekstensi ECH
41207  00:02:11.084  10.10.250.37   203.0.113.188   ech.edgefront.example     ada
41233  00:02:11.311  10.10.250.61   203.0.113.189   ech.edgefront.example     ada
45512  00:04:02.770  10.20.45.22    203.0.113.170   ...                       tidak ada
```

Dua baris pertama menuju alamat berbeda dengan SNI yang sama persis. Itu bukan dua koneksi ke host yang sama, melainkan dua koneksi yang tujuan sebenarnya disembunyikan di balik nama publik yang sama [S1]. Di dunia nyata, nama serupa yang paling sering terlihat adalah `cloudflare-ech.com` [S12].

**Variasi:** ganti file ke jam sibuk (misalnya `20270614030000`, 10:00 WIB) untuk melihat apakah proporsinya berubah; tambahkan `-e tls.handshake.extensions_server_name` untuk mengumpulkan SNI yang dipakai bagian 2.3.

**Kapan gagal:** versi Wireshark sebelum 4.2.0 tidak punya field `tls.ech.*` dan menampilkan ekstensi ini sebagai ekstensi tak dikenal; filter berbasis nomor 65037 tetap bekerja, tetapi isi ekstensi harus dibaca dari byte mentah [S6]. Hitungan ini juga hanya mencakup TLS di atas TCP; ClientHello di QUIC berada di dalam paket QUIC yang terlindungi dan perlu penanganan lain (Day 16).

### 2.2 Rekaman HTTPS dari DNS: daftar `public_name` dan siapa menanyakan apa

Untuk memisahkan ECH sungguhan dari GREASE, kamu butuh daftar `public_name` yang aktif. Daftar itu tidak perlu ditebak: konfigurasi ECH dipublikasikan di rekaman HTTPS [S1][S5], dan resolver PT JAB menanyakannya ke internet secara polos lewat egress.

**Tujuan:** mengumpulkan `public_name` dari jawaban HTTPS di pcap egress, lalu mencari klien internal yang menanyakan rekaman HTTPS.

Dari pcap egress (jawaban yang diterima resolver `jkt-res01` dan `jkt-res02` dari server otoritatif):

```
tshark -r $F -Y "dns.flags.response == 1 and dns.qry.type == 65 and dns.svcb.svcparam.key == 5" \
  -T fields -e ip.dst -e tls.ech.echconfigcontents.public_name -e tls.ech.hpke.keyconfig.config_id \
  | sort | uniq -c | sort -rn
```

Penjelasan tiap bagian:

- `dns.qry.type == 65` memilih kueri dan jawaban HTTPS; `dns.flags.response == 1` hanya jawaban.
- `dns.svcb.svcparam.key == 5` memilih jawaban yang membawa SvcParamKey `ech` [S5][S7].
- `tls.ech.echconfigcontents.public_name` dan `tls.ech.hpke.keyconfig.config_id` adalah field ECHConfig di Wireshark 4.2.0 ke atas [S6]. Field DNS lama `dns.svcb.svcparam.echconfig` hanya ada di 3.6.0 sampai 4.0.17 [S7]; apakah Wireshark 4.6.x mengurai `ECHConfigList` di dalam paket DNS dengan field `tls.ech.*`, cek di versimu. Bila kolomnya kosong, ambil nilai Base64 dengan `dig` (di bawah) dan urai di lab.

Keluaran ilustrasi:

```
    146 10.20.2.53  ech.edgefront.example      42
     23 10.20.2.54  cover.nimbus-edge.example   7
      9 10.20.2.53  ech-pub.cdnmesh.example    191
```

**Cara membaca hasil:** dalam 15 menit itu, resolver menerima 178 jawaban HTTPS ber-`ech` (146 + 23 + 9) yang menunjuk tiga `public_name`. Angka di kolom pertama adalah jumlah jawaban, bukan jumlah situs; nama yang sudah ada di cache resolver tidak ditanyakan ulang dan tidak terlihat di egress, jadi daftar ini harus diakumulasi setiap hari ke lookup Splunk `ech_public_names.csv`. Kolom terakhir adalah `config_id` yang sedang aktif. Senin pagi, `edgefront.example` memakai `config_id` 42. Ekstraksi yang sama dari file Jumat 2027-06-11 02:00 UTC (09:00 WIB) menunjukkan `config_id` 23 untuk penyedia yang sama: kunci ECH `edgefront.example` berganti antara Jumat dan Senin. Detail ini dipakai lagi di bagian 2.7. File Jumat itu sudah mendekati batas target retensi 72 jam, jadi salin ke folder kasus sebelum mengerjakan yang lain.

Dari sisi klien, siapa yang menanyakan rekaman HTTPS? Log resolver memberi jawabannya untuk 30 hari:

```
index=dns sourcetype=isc:bind:query query_type=HTTPS src=10.10.6*
    earliest="06/07/2027:00:00:00" latest="06/14/2027:09:00:00"
| stats count min(_time) AS pertama values(query) AS nama BY src
| convert ctime(pertama)
| sort count
```

Penjelasan tiap bagian:

- `query_type=HTTPS` memilih kueri tipe 65. `src=10.10.6*` membatasi ke rentang workstation `10.10.60.0` sampai `10.10.69.x`.
- `stats ... BY src` meringkas per workstation, dengan nama yang ditanyakan dan waktu pertama.
- `sort count` menaruh workstation paling jarang di atas: workstation di balik proxy eksplisit biasanya tidak me-resolve nama situs sendiri, karena proxy yang melakukannya (Day 08), jadi kueri HTTPS dari workstation sudah layak dilihat.

Keluaran ilustrasi:

```
src            count  pertama               nama
10.10.60.152   1      06/11/2027 09:13:52   sync.harbor-ledger.example
10.10.60.150   14     06/09/2027 13:20:07   (14 nama situs uji ECH, workstation uji SOC JKT-WS-2070)
```

**Cara membaca hasil:** `10.10.60.150` adalah workstation uji SOC yang dipakai Rudi untuk uji ECH, jadi jinak. `10.10.60.152` (`JKT-WS-2072`) menanyakan rekaman HTTPS untuk satu nama, `sync.harbor-ledger.example`, sekali, Jumat 09:13:52 WIB. Nama itu tidak pernah ditanyakan host lain. Karena log resolver tidak memuat jawaban, isi jawabannya diambil dari `dns.log` Zeek di hop core (kueri dari workstation ke resolver lewat SPAN core) atau dari pcap egress Jumat (kueri resolver ke otoritatif). Kamu membuka `SOC-2027-0671` untuk temuan ini pukul 09:20 WIB dan menautkannya ke `SOC-2027-0670`.

```
index=zeek sourcetype=bro:dns:json query="sync.harbor-ledger.example"
    earliest="06/11/2027:09:00:00" latest="06/11/2027:09:30:00"
| table _time id.orig_h id.resp_h query qtype_name rcode_name answers
```

Keluaran ilustrasi:

```
_time                 id.orig_h     id.resp_h   query                       qtype_name  rcode_name  answers
06/11/2027 09:13:52   10.10.60.152  10.20.2.53  sync.harbor-ledger.example  HTTPS       NOERROR     (kosong)
```

Kolom `answers` kosong. Apakah Zeek 9.0 mengisi `answers` untuk rekaman HTTPS perlu dicek di versimu; di PT JAB kolom itu kosong, sehingga isi jawaban diambil dari pcap egress Jumat:

```
tshark -r /cases/SOC-2027-0670/egress_20270611_0900.pcapng \
  -Y 'dns.qry.name == "sync.harbor-ledger.example" and dns.flags.response == 1' -V \
  | grep -E "SvcParamKey|ALPN|IP:|Public Name|Config Id"
```

Keluaran ilustrasi:

```
        SvcParamKey: alpn (1)
            ALPN: h2
        SvcParamKey: ipv4hint (4)
            IP: 203.0.113.188
            IP: 203.0.113.189
        SvcParamKey: ech (5)
            Config Id: 23
            Public Name: ech.edgefront.example
```

**Cara membaca hasil:** domain `sync.harbor-ledger.example` dilayani lewat `edgefront.example` dengan `public_name` `ech.edgefront.example`, `config_id` 23, dan alamat `203.0.113.188` dan `203.0.113.189`. Inilah penghubung antara nama asli dan koneksi ber-ECH yang SNI-nya hanya menyebut penyedia.

Bentuk `dig` dari catatan lama untuk mengambil rekaman HTTPS satu domain:

```
dig +short HTTPS www.contoh.co.id
```

Keluaran ilustrasi bentuk umum:

```
1 . alpn="h3,h2" ipv4hint=198.51.100.10 ech=AEX+DQBBxx...
```

Cara memakainya: keberadaan parameter `ech` memberi tahu bahwa domain itu mempublikasikan konfigurasi ECH, sehingga koneksi ke sana memang akan menyembunyikan SNI. Nilai Base64 `AEX+DQ...` diawali dua byte panjang daftar (0x0045) lalu versi ECHConfig 0xfe0d, yang sama dengan kode ekstensi [S1][S5]. Parameter `alpn` memberi tahu protokol yang ditawarkan, termasuk HTTP/3 (Day 16), dan `ipv4hint` memberi alamat yang bisa dikorelasikan dengan koneksi yang kamu amati [S3]. Versi `dig` yang lebih lama mungkin belum mengenal nama tipe `HTTPS`; pakai `TYPE65` sebagai gantinya.

Untuk domain yang dicurigai milik penyerang, jangan jalankan `dig` dari jaringan kantor sebelum bukti pasif habis dibaca (bagian 1.6). Jalankan dari jaringan analisis yang terpisah bila memang perlu, dan catat waktunya di tiket.

- Di Zeek, kumpulkan kueri HTTPS dari `dns.log` dan simpan sebagai daftar domain yang memakai ECH di lingkunganmu. Daftar itu adalah bahan peta celah ECH-mu (bagian 2.9).
- **Kapan gagal:** kalau kliennya memakai DNS terenkripsi, kamu tidak melihat kueri ini sama sekali; itu pokok bahasan Day 16. Resolver yang menjawab dari cache juga tidak menghasilkan kueri ke otoritatif, jadi pcap egress tidak memuat jawabannya. Dan aplikasi dengan prakonfigurasi tidak perlu menanyakan rekaman HTTPS sama sekali.

### 2.3 Memisahkan GREASE dari ECH sungguhan

Dengan daftar `public_name` dari bagian 2.2, angka 68,6% bisa dipecah menjadi dua: ECH sungguhan dan GREASE (bagian 1.4).

**Tujuan:** menghitung ClientHello yang SNI luarnya adalah `public_name` (ECH sungguhan) dan yang SNI-nya nama asli dengan ekstensi ECH palsu (GREASE).

```
printf "ech.edgefront.example\ncover.nimbus-edge.example\nech-pub.cdnmesh.example\n" > /cases/SOC-2027-0670/public_names.txt

tshark -r $F -Y "tls.handshake.type == 1 and tls.ech.config_id" \
  -T fields -e ip.src -e tls.handshake.extensions_server_name -e tls.ech.config_id \
  | awk -F'\t' 'NR==FNR { pub[$1]=1; next }
                { g = ($1=="10.20.3.60") ? "proxy" : ($1 ~ /^10\.10\.250\./) ? "tamu" : "lain";
                  k = ($2 in pub) ? "ECH" : "GREASE"; n[g" "k]++ }
                END { for (x in n) print x, n[x] }' /cases/SOC-2027-0670/public_names.txt - | sort
```

Penjelasan tiap bagian:

- File `public_names.txt` berisi tiga nama dari bagian 2.2. Di Splunk, peran yang sama dipegang lookup `ech_public_names.csv`.
- `tls.ech.config_id` sebagai filter keberadaan memilih ClientHello yang membawa ekstensi ECH.
- `awk` membaca daftar nama dulu (`NR==FNR`), lalu untuk tiap ClientHello menandai ECH bila SNI luar ada di daftar dan GREASE bila tidak, per kelompok sumber.

Keluaran ilustrasi:

```
proxy ECH 2
proxy GREASE 10606
tamu ECH 412
tamu GREASE 1619
```

**Cara membaca hasil:** dari 12.639 ClientHello ber-ekstensi ECH, hanya 414 yang ECH sungguhan (2 dari proxy dan 412 dari Wi-Fi tamu); sisanya 12.225 adalah GREASE (10.606 + 1.619). Terhadap seluruh 18.420 ClientHello, ECH sungguhan 2,2% dan GREASE 66,4%. Untuk Wi-Fi tamu saja, ECH sungguhan 412 dari 2.874 ClientHello, atau 14,3%. Jadi jawaban untuk Dimas: pada jam itu, SNI tertutup untuk sekitar 2,2% ClientHello di egress, hampir semuanya dari perangkat tamu. Dua ClientHello ber-ECH sungguhan dari proxy adalah anomali tersendiri, karena 10.512 ClientHello Edge yang lewat proxy semuanya GREASE.

Pengecekan kedua memakai `config_id`. ECH sungguhan ke satu penyedia dalam satu periode kunci memakai `config_id` yang sama; GREASE memakai nilai acak:

```
tshark -r $F -Y 'tls.handshake.extensions_server_name == "ech.edgefront.example"' \
  -T fields -e tls.ech.config_id -e ip.src | awk '{ print $1, ($2=="10.20.3.60") ? "proxy" : "lain" }' \
  | sort | uniq -c
```

Keluaran ilustrasi:

```
      1 23 proxy
      1 42 proxy
    318 42 lain
```

Semua 318 koneksi tamu ke `ech.edgefront.example` memakai `config_id` 42, yang sedang aktif Senin pagi (bagian 2.2). Satu koneksi dari proxy memakai 23, konfigurasi lama yang aktif Jumat. Satu klien di balik proxy masih memegang kunci Jumat: tanda konfigurasi disimpan, bukan diambil segar dari DNS. Bagian 2.7 membaca dua koneksi ini lebih dekat.

**Variasi:** jalankan pada satu hari penuh (96 file) dan simpan hasilnya per jam ke Splunk sebagai metrik celah; tambahkan kolom JA4 untuk melihat klien mana yang memakai ECH sungguhan.

**Kapan gagal:** `config_id` hanya satu byte, jadi GREASE kadang kebetulan memakai nilai yang sama dengan konfigurasi asli; SNI tetap kunci utamanya, `config_id` hanya pengecekan kedua. Daftar `public_name` yang belum lengkap membuat ECH sungguhan terhitung GREASE; penyedia baru muncul terus, jadi daftar perlu diperbarui harian dari rekaman HTTPS. Dan nama asli yang kebetulan sama dengan `public_name` (situs penyedia itu sendiri) terhitung ECH.

### 2.4 Pivot ke alamat dan pola

Ketika nama tidak tersedia, kembali ke alamat dan perilaku. Untuk `SOC-2027-0670`, pertanyaannya: apakah alamat `203.0.113.188` dan `203.0.113.189` cukup untuk membedakan koneksi mencurigakan?

**Tujuan:** melihat siapa saja yang terhubung ke alamat client-facing server, dan dengan SNI apa.

Bentuk dari catatan lama, untuk log TSV di lab:

```
# Zeek: koneksi ke port 443, kolom yang perlu untuk pengelompokan per host sumber
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p duration orig_bytes resp_bytes \
  | awk '$3 == 443'
```

Lalu susun dua tabel: alamat tujuan yang paling sering dihubungi per host, dan alamat tujuan yang hanya dihubungi satu atau dua host (Day 08). Yang menarik adalah tabel kedua, dengan alasan yang sama seperti stacking di hunting: yang langka lebih informatif daripada yang sering.

Versi Splunk untuk PT JAB:

```
index=zeek sourcetype=bro:conn:json id.resp_h IN (203.0.113.188, 203.0.113.189) id.resp_p=443
    earliest="06/14/2027:07:00:00" latest="06/14/2027:09:00:00"
| eval sumber=case(cidrmatch("10.10.250.0/24", 'id.orig_h'), "tamu",
                   'id.orig_h'="10.20.3.60", "proxy", true(), 'id.orig_h')
| stats count dc(id.orig_h) AS host BY sumber
```

```
index=zeek sourcetype=bro:ssl:json id.orig_h=10.20.3.60 id.resp_h IN (203.0.113.188, 203.0.113.189)
    earliest="06/14/2027:07:00:00" latest="06/14/2027:09:00:00"
| stats count BY server_name
| sort - count
```

Penjelasan tiap bagian:

- Query pertama menghitung koneksi ke dua alamat itu per kelompok sumber. `cidrmatch` memisahkan Wi-Fi tamu; field dengan titik ditulis dalam tanda kutip tunggal di `eval`.
- Query kedua melihat SNI koneksi proxy ke alamat yang sama di `ssl.log`.

Keluaran ilustrasi:

```
sumber  count  host
proxy   2347   1
tamu    1207   58

server_name                    count
portal.kursus-daring.example   912
static.berita-kini.example     655
cdn.toko-alat.example          412
api.cuaca-nusantara.example    361
ech.edgefront.example          7
```

**Cara membaca hasil:** dalam dua jam, 2.347 koneksi dari proxy dan 1.207 koneksi dari 58 perangkat tamu menuju dua alamat itu. Alamat ini milik CDN bersama; memblokir atau menandainya akan mengenai ribuan koneksi sah. Di sisi proxy, 2.340 koneksi (912 + 655 + 412 + 361) membawa SNI nama situs asli, karena Edge di balik proxy hanya mengirim GREASE ECH (bagian 2.3). Tujuh koneksi membawa SNI `ech.edgefront.example`. Di jalur proxy, SNI yang sama dengan `public_name` sendiri sudah langka, dan tujuh koneksi itu (07:01:14, 07:01:15, lalu tiap sekitar 20 menit sampai 08:41) adalah bahan bagian 2.5 sampai 2.8.

Untuk alamat yang perlu diidentifikasi, pakai sumber di luar rekaman: data pasif tentang alamat dan nama, informasi pendaftaran, dan rekaman DNS historis. Nyatakan di laporan bahwa identifikasi itu berasal dari sumber luar dan bukan dari rekaman trafik.

**Variasi:** ganti `stats count BY server_name` dengan `timechart span=20m count BY server_name` untuk melihat ritme; koneksi ke `ech.edgefront.example` dari proxy akan tampak sebagai garis datar berisi satu koneksi per 20 menit, berbeda dari browsing yang naik turun mengikuti jam kerja.

**Kapan gagal:** di hop egress, semua koneksi workstation bersumber dari `10.20.3.60`, jadi `dc(id.orig_h)` untuk proxy selalu 1; identitas workstation hanya dari log proxy (bagian 2.8). Untuk client-facing server yang melayani ribuan situs, alamat tidak pernah cukup sebagai indikator.

### 2.5 JA4 langka di `ssl.log`: `SOC-2027-0670`

Rule yang memunculkan `SOC-2027-0670` adalah penerapan pola "periksa ekor yang paling jarang" dari bagian 1.7. Memahami query-nya membantu menilai alert dan tahu kapan rule ini buta.

**Tujuan:** menemukan JA4 yang hanya dipakai untuk satu SNI dan paling banyak dua alamat tujuan, dan belum ada di allowlist.

Bentuk dari catatan lama, untuk log TSV di lab (dengan plugin JA4+ versi 1.x, JA4 berada di `ssl.log`, bukan di log terpisah [S8]):

```
# bentuk lama, bila paket JA4 menulis ja4.log tersendiri
cat ja4.log | zeek-cut uid ja4 | sort -k2 | uniq -c -f1 | sort -rn | head -30

# plugin zeek/foxio/ja4 v1.x: kolom ja4 di ssl.log; tail = paling jarang
zeek-cut ja4 < ssl.log | sort | uniq -c | sort -rn | tail -30
```

Bentuk pertama mengurutkan per nilai JA4 (`sort -k2`) lalu menghitung baris yang sama dengan mengabaikan kolom `uid` (`uniq -c -f1`). Bentuk kedua langsung menghitung kolom `ja4`; `tail` mengambil yang paling jarang.

Rule `NSM - JA4 langka di egress` di Splunk:

```
index=zeek sourcetype=bro:ssl:json ja4=*
    earliest="06/10/2027:10:00:00" latest="06/14/2027:06:00:00"
| stats count dc(server_name) AS n_sni dc(id.resp_h) AS n_tujuan values(server_name) AS sni
        min(_time) AS pertama BY ja4
| where n_sni=1 AND n_tujuan<=2 AND count<500
| lookup ja4_allowlist.csv ja4 OUTPUT catatan
| where isnull(catatan)
| convert ctime(pertama)
```

Penjelasan tiap bagian:

- Jendela dimulai Kamis 10:00, saat plugin aktif; sebelum itu kolom `ja4` tidak ada.
- `stats ... BY ja4` meringkas per fingerprint: jumlah koneksi, jumlah SNI, jumlah alamat tujuan, dan waktu pertama.
- `where n_sni=1 AND n_tujuan<=2 AND count<500` memilih fingerprint yang hanya bicara ke satu nama dan sedikit alamat, dengan volume kecil. Klien seperti ini adalah aplikasi khusus: agent, updater, atau implant.
- `lookup ja4_allowlist.csv` membuang fingerprint yang sudah dikenal dan diterima, misalnya skrip telemetri NOC (Day 06).

Keluaran ilustrasi (dua alert dari run pertama Senin 06:00):

```
ja4                                   count  n_sni  n_tujuan  sni                     pertama
t13d1010h2_61a7ad8aa9b6_3a8073edd8ef  25     1      2         ech.edgefront.example   06/11/2027 09:14:02
t13d1414h2_2b729b4bf6f3_c4b8e1a59f02  96     1      1         api.meetvendor.example  06/11/2027 16:05:40
```

**Cara membaca hasil:** baris pertama menjadi `SOC-2027-0670`, baris kedua `SOC-2027-0672` (bagian 2.6). Baris pertama: TLS 1.3 di atas TCP, ada SNI, 10 cipher, 10 ekstensi, ALPN `h2`. Fingerprint ini hanya pernah bicara ke `ech.edgefront.example` di dua alamat, 25 kali sejak Jumat 09:14:02 WIB. Karena SNI-nya `public_name`, nilai `n_sni=1` di sini tidak berarti satu tujuan: di balik nama itu bisa ada banyak backend. Yang berarti adalah bahwa tidak ada klien lain di jaringan dengan fingerprint ini. Di hop egress, sumbernya `10.20.3.60`, dan koneksi ke kategori CDN di-splice, jadi fingerprint ini milik klien asli di balik proxy, bukan milik proxy (Day 06 bagian 1.7).

Langkah lanjutan untuk fingerprint langka:

```
index=zeek sourcetype=bro:ssl:json earliest=-30d@d latest=now
| eval ja4_a=mvindex(split(ja4, "_"), 0), ja4_c=mvindex(split(ja4, "_"), 2)
| search ja4_a="t13d1010h2" ja4_c="3a8073edd8ef"
| stats count values(ja4) AS ja4 values(ja4s) AS ja4s values(server_name) AS sni BY id.orig_h
```

Penjelasan: `split` memecah JA4 di garis bawah; `mvindex` mengambil bagian `a` dan `c`. Mencari dengan `a` dan `c` saja menangkap varian yang hanya berbeda daftar cipher (bagian 1.7) [S2]. Kolom `ja4s` menambah sisi server: pasangan JA4 dan JA4S yang sama di semua koneksi menunjukkan klien dan server yang selalu bernegosiasi dengan cara sama. Rentang waktu relatif di sini aman karena data live, bukan dataset statis.

Keluaran ilustrasi:

```
id.orig_h    count  ja4                                   ja4s                     sni
10.20.3.60   35     t13d1010h2_61a7ad8aa9b6_3a8073edd8ef  t130200_1301_a56c5b993250  ech.edgefront.example
```

Tidak ada varian lain: 35 koneksi (25 Jumat, 10 Senin sampai 10:00), satu fingerprint, satu JA4S. Fingerprint TCP (`ja4t`) dan latensi (`ja4l`) di `conn.log` untuk koneksi yang sama tidak membantu di sini: koneksi TCP ke server dibuka oleh proxy, jadi JA4T di egress milik tumpukan TCP `jkt-proxy01`, bukan workstation, walaupun ClientHello di dalamnya milik klien. Ini perbedaan halus antara splice TLS dan koneksi TCP yang perlu diingat ketika memakai anggota JA4+ selain JA4.

**Variasi:** turunkan `count<500` untuk lingkungan kecil atau naikkan untuk menangkap updater yang lebih ramai; tambahkan `where n_tujuan>=5` di query terpisah untuk mencari fingerprint langka yang justru menyebar ke banyak alamat (pemindai).

**Kapan gagal:** fingerprint klien yang memakai library umum (Go, Python, OpenSSL bawaan) dipakai juga oleh skrip sah, sehingga tidak langka dan tidak muncul di rule ini. Implant yang meniru ClientHello browser tidak pernah langka. Dan untuk koneksi yang di-bump, JA4 di egress milik proxy (Day 06 bagian 1.7).

### 2.6 JA4 berubah karena pembaruan: `SOC-2027-0672`

Alert kedua dari run yang sama adalah contoh peringatan FoxIO bahwa JA4 berubah ketika library TLS aplikasi diperbarui (bagian 1.7). Menutupnya dengan benar sama pentingnya dengan menaikkan alert pertama.

**Tujuan:** memeriksa apakah fingerprint baru `t13d1414h2_2b729b4bf6f3_c4b8e1a59f02` adalah aplikasi sah yang diperbarui.

```
index=proxy method=CONNECT url="api.meetvendor.example:443"
    earliest="06/11/2027:00:00:00" latest="06/14/2027:09:30:00"
| stats dc(src) AS workstation count min(_time) AS pertama BY http_user_agent tls
| convert ctime(pertama)
```

Penjelasan: log proxy menjembatani fingerprint di egress ke workstation dan User-Agent aplikasi. Kolom `tls` memastikan koneksinya di-splice, sehingga JA4 di egress memang milik aplikasi.

Keluaran ilustrasi:

```
http_user_agent              tls     workstation  count  pertama
MeetVendorDesktop/6.4.2      splice  312          9874   06/11/2027 07:02:15
MeetVendorDesktop/6.5.0      splice  41           2117   06/11/2027 16:05:38
```

**Cara membaca hasil:** versi 6.5.0 muncul pertama Jumat 16:05:38 dari `10.10.60.154` (`JKT-WS-2074`) dan kini dipakai 41 workstation. Jadwal perubahan tim End User Computing mencatat pilot pembaruan klien rapat ke 12 workstation Jumat 16:00 dan rollout lebih luas Senin 08:00. Perbandingan fingerprint lama yang sudah ada di allowlist dengan yang baru:

```
lama  t13d1413h2_2b729b4bf6f3_9e7b989ebec8
baru  t13d1414h2_2b729b4bf6f3_c4b8e1a59f02
```

Bagian `b` sama: daftar cipher tidak berubah. Bagian `a` hanya berbeda di jumlah ekstensi (13 menjadi 14), dan bagian `c` berubah karena daftar ekstensinya berubah. Pola ini cocok dengan library TLS yang menambah satu ekstensi setelah pembaruan, bukan dengan klien yang berbeda sama sekali. Bersama jadwal perubahan, User-Agent versi baru, dan prevalence yang naik dari 1 ke 41 workstation, `SOC-2027-0672` ditutup jinak pukul 09:50 WIB, dan fingerprint baru ditambahkan ke `ja4_allowlist.csv` dengan catatan versi aplikasi. Biner aplikasinya dicek bertanda tangan vendor oleh tim endpoint; itu data host, bukan data jaringan.

**Kapan gagal:** User-Agent bisa dipalsukan, jadi kecocokan versi tidak cukup tanpa jadwal perubahan dan data host. Bila prevalence fingerprint baru tetap satu host setelah rollout selesai, perlakukan seperti `SOC-2027-0670`.

### 2.7 Mengenali penolakan dan percobaan ulang ECH

Dua koneksi dari proxy pada 07:01:14 dan 07:01:15 dengan `config_id` berbeda (bagian 2.3) terlihat seperti pola penolakan dan percobaan ulang dari bagian 1.3. Bagian ini memastikannya dari pcap.

Pola di kabel yang dicari, mengikuti perilaku yang diwajibkan spesifikasi [S1]:

```
1. Koneksi A: ClientHello dengan ekstensi ECH, handshake selesai
2. Koneksi A: TIDAK ada data aplikasi
3. Koneksi A: ditutup
4. Koneksi B: ke alamat yang sama, ClientHello baru, handshake selesai
5. Koneksi B: ada data aplikasi
```

**Tujuan:** memeriksa dua koneksi itu: nomor stream, `config_id`, dan jumlah record terenkripsi.

```
tshark -r $F -Y 'ip.src == 10.20.3.60 and tls.handshake.extensions_server_name == "ech.edgefront.example"' \
  -T fields -e frame.time -e tcp.stream -e tcp.srcport -e ip.dst -e tls.ech.config_id

tshark -r $F -Y "tcp.stream in {4127 4131} and (tls.record.content_type == 23 or tls.record.opaque_type == 23)" \
  -T fields -e tcp.stream | sort | uniq -c
```

Penjelasan tiap bagian:

- Perintah pertama mendaftar ClientHello dari proxy dengan SNI `public_name`, beserta stream dan `config_id`.
- Perintah kedua menghitung record ber-tipe 23 per stream. Filter Wireshark dari catatan lama untuk satu stream adalah `tls.handshake.type == 2 and tcp.stream eq <nomor>`, lalu periksa apakah stream itu memuat `tls.record.content_type == 23` (Application Data).

Ada satu koreksi penting untuk filter lama itu. Pada TLS 1.3, setiap record terenkripsi diberi tipe luar 23 (application_data), termasuk pesan handshake terenkripsi seperti EncryptedExtensions, Certificate, dan Finished, serta alert [S14]. Wireshark menampilkan tipe luar itu sebagai field `tls.record.opaque_type` untuk record yang tidak didekripsi [S6]. Jadi "ada record tipe 23" tidak berarti "ada data aplikasi". Bedanya terlihat dari jumlah dan ukuran: koneksi yang ditolak hanya membawa beberapa record handshake dan satu alert, sedangkan koneksi yang dipakai membawa lebih banyak. Apakah `tls.record.content_type` di versimu juga cocok dengan record TLS 1.3 yang tidak didekripsi, cek di lab; filter di atas memakai keduanya supaya aman.

Keluaran ilustrasi:

```
Jun 14, 2027 00:01:14.402 UTC  4127  41822  203.0.113.188  23
Jun 14, 2027 00:01:15.031 UTC  4131  41826  203.0.113.189  42

      4 4127
     23 4131
```

Dilengkapi `conn.log` untuk dua koneksi itu:

```
index=zeek sourcetype=bro:conn:json id.orig_h=10.20.3.60 id.orig_p IN (41822, 41826)
    earliest="06/14/2027:07:01:00" latest="06/14/2027:07:02:00"
| table _time id.orig_p id.resp_h duration orig_bytes resp_bytes conn_state history
```

```
_time                 id.orig_p  id.resp_h      duration  orig_bytes  resp_bytes  conn_state  history
06/14/2027 07:01:14   41822      203.0.113.188  0.381     2118        3904        SF          ShADadFf
06/14/2027 07:01:15   41826      203.0.113.189  2.412     6502        5377        SF          ShADadFf
```

**Cara membaca hasil:** stream 4127 memakai `config_id` 23 (kunci Jumat), membawa hanya 4 record terenkripsi, dan selesai normal (`SF`) dalam 0,381 detik. Kurang dari 0,7 detik kemudian, stream 4131 dari klien yang sama memakai `config_id` 42 (kunci Senin) dan membawa 23 record. Di `ssl.log`, keduanya bisa tercatat `established` karena handshake luar selesai; `ssl.log` saja tidak menunjukkan penolakan. Gabungan tiga hal (`config_id` berubah, koneksi pertama pendek tanpa data, koneksi kedua segera menyusul) cocok dengan penolakan ECH lalu percobaan ulang dengan `retry_configs`. Alamat tujuan bisa berbeda (`.188` lalu `.189`) karena keduanya alamat client-facing server yang sama dari `ipv4hint`.

Kenapa ini berguna: browser yang mengambil konfigurasi dari DNS mendapat `config_id` 42 Senin pagi, seperti 318 koneksi tamu. Klien ini memakai kunci Jumat, artinya ia menyimpan konfigurasi sejak Jumat dan tidak menanyakan DNS lagi (cocok dengan satu-satunya kueri HTTPS dari `10.10.60.152` Jumat 09:13:52 di bagian 2.2). Itu perilaku aplikasi yang membawa konfigurasinya sendiri, bukan browser.

**Variasi:** cari pola ini di seluruh egress sehari dengan Splunk: koneksi dari sumber yang sama ke alamat client-facing server dengan `duration<1` dan koneksi berikutnya kurang dari 2 detik kemudian; lalu cek `config_id` di pcap untuk kandidatnya.

**Kapan gagal:** koneksi yang gagal karena sebab lain (sertifikat ditolak, timeout aplikasi, pembatalan pengguna) juga pendek tanpa data. Jangan menyimpulkan dari satu kejadian; cari polanya berulang dan pastikan dengan perubahan `config_id`. Penolakan juga hanya muncul ketika kunci berganti; klien dengan konfigurasi yang selalu segar tidak pernah menghasilkan pola ini.

### 2.8 Atribusi lewat proxy dan pembukaan `INC-2027-074`

Fingerprint langka, SNI `public_name` dari jalur proxy, kunci ECH yang disimpan, dan kueri HTTPS dari workstation sudah mengarah ke satu klien. Langkah terakhir dari sisi jaringan adalah log proxy, satu-satunya jembatan dari `10.20.3.60` ke workstation (Day 11 bagian 2.8).

**Tujuan:** menemukan workstation dan pengguna di balik koneksi `CONNECT` ke `ech.edgefront.example`, lalu urutan kejadiannya.

```
index=proxy method=CONNECT url="ech.edgefront.example:443"
    earliest="05/15/2027:00:00:00" latest="06/14/2027:10:00:00"
| stats count min(_time) AS pertama max(_time) AS terakhir values(tls) AS tls
        values(category) AS kategori values(http_user_agent) AS ua BY src user
| convert ctime(pertama) ctime(terakhir)
```

```
index=proxy url="*harbor-ledger.example*"
    earliest="05/15/2027:00:00:00" latest="06/14/2027:10:00:00"
| table _time src user method url category tls status bytes
```

Penjelasan tiap bagian:

- Query pertama mencari semua klien yang meminta `CONNECT` ke `public_name` itu dalam 30 hari retensi proxy. Browser normal meminta `CONNECT` ke nama situs asli, bukan ke `public_name`.
- Query kedua mencari domain induk yang ditemukan di kueri HTTPS (bagian 2.2), untuk melihat apakah ada interaksi lain dengan domain itu.

Keluaran ilustrasi:

```
src           user          count  pertama               terakhir              tls     kategori          ua
10.10.60.152  yusuf.rahman  35     06/11/2027 09:14:01   06/14/2027 09:41:12   splice  Content Delivery  Go-http-client/1.1

_time                 src           user          method   url                                                   category       tls   status  bytes
06/11/2027 09:12:20   10.10.60.152  yusuf.rahman  CONNECT  files.harbor-ledger.example:443                       Uncategorized  bump  200     -
06/11/2027 09:12:21   10.10.60.152  yusuf.rahman  GET      https://files.harbor-ledger.example/dl/LedgerSync_Setup.zip  Uncategorized  bump  200     4812336
```

**Cara membaca hasil:** satu workstation saja, `10.10.60.152` (`JKT-WS-2072`, pengguna `yusuf.rahman`, bagian Keuangan), 35 kali dalam 30 hari, semuanya sejak Jumat 09:14:01. User-Agent `Go-http-client/1.1` di permintaan `CONNECT` bukan Edge. Kategori CDN membuat proxy meneruskan sesi apa adanya, sehingga baik proxy maupun pcap hanya melihat `public_name`. Urutan Jumat:

| Waktu (WIB) | Sumber | Kejadian |
|---|---|---|
| 09:12:21 | `index=proxy` | Edge mengunduh `LedgerSync_Setup.zip` (4.812.336 byte) dari domain baru `files.harbor-ledger.example` (di-bump, URL tercatat) |
| 09:13:52 | `index=dns`, `dns.log` | `10.10.60.152` menanyakan rekaman HTTPS `sync.harbor-ledger.example`; jawaban: `public_name` `ech.edgefront.example`, `config_id` 23, `203.0.113.188` dan `.189` |
| 09:14:01 | `index=proxy` | `CONNECT ech.edgefront.example:443` dari `10.10.60.152`, UA `Go-http-client/1.1`, splice |
| 09:14:02 | `ssl.log`, pcap | ClientHello ber-ECH sungguhan, JA4 `t13d1010h2_61a7ad8aa9b6_3a8073edd8ef`, lalu tiap sekitar 20 menit sampai 17:14 (25 koneksi) |
| Senin 07:01:14 | pcap, `conn.log` | Koneksi pertama setelah akhir pekan memakai `config_id` 23, ditolak; 07:01:15 percobaan ulang dengan `config_id` 42 |

Interval 25 koneksi Jumat (24 interval) punya median 1.200 detik dan CV 0,11, memenuhi ambang beacon program (CV maksimal 0,2, minimal 24 interval, median 30 detik sampai 4 jam; Day 11 bagian 1.3). Nama tujuan sebenarnya, `sync.harbor-ledger.example`, tidak pernah terlihat di sesi TLS; ia disimpulkan dari kueri HTTPS sembilan detik sebelum pola dimulai, alamat `ipv4hint` yang cocok, dan domain induk yang sama dengan unduhan kurang dari dua menit sebelumnya. Itu korelasi yang kuat, tetapi tetap korelasi; tulis demikian di laporan.

Dimas membuka `INC-2027-074` pukul 10:30 WIB dan menyerahkannya ke IR. Tim endpoint menemukan proses tanpa tanda tangan di folder profil pengguna yang membuka koneksi ke `10.20.3.60:3128` tiap sekitar 20 menit, dan `JKT-WS-2072` diisolasi lewat MDE pukul 10:48 WIB. Dari sisi jaringan, catatan untuk IR berisi: indikator (JA4, `public_name`, domain `harbor-ledger.example`, alamat CDN yang tidak boleh diblokir sendirian), batas pengamatan (isi sesi tidak terlihat; nama tujuan dari korelasi DNS), dan penjelasan jinak yang sudah disingkirkan (aplikasi sah dengan konfigurasi ECH tertanam tetap mungkin, tetapi tidak cocok dengan unduhan dari domain baru, pengguna Keuangan, dan biner tanpa tanda tangan).

**Kapan gagal:** bila implant meminta `CONNECT` ke alamat IP literal, proxy PT JAB mem-bump-nya (Day 06), dan perilaku ECH di sesi yang di-bump belum diukur (bagian 1.5). Bila implant memakai DoH untuk mengambil konfigurasi, kueri HTTPS tidak ada di `index=dns`. Bila retensi proxy 30 hari sudah lewat, jembatan ke workstation hilang.

### 2.9 Peta celah ECH dan baseline JA4

Keluaran akhir Day ini adalah peta celah ECH PT JAB per Senin 2027-06-14: apa yang masih terlihat di sensor dan proxy setelah ECH, apa yang hilang, dan sumber penggantinya. Peta ini, bersama baseline JA4, menjawab pertanyaan Hendra yang akan datang setelah ini: "seberapa buta kita sekarang, dan apakah makin parah?"

Tabel pertama adalah peta celah ECH dalam bentuk ringkas per jalur trafik. Baca kolom "Yang hilang" dan "Sumber pengganti" berpasangan: tiap baris yang kehilangan SNI harus punya pengganti, atau tercatat sebagai celah terbuka.

| Jalur (Senin 2027-06-14) | Yang masih terlihat di sensor dan proxy | Yang hilang | Sumber pengganti |
|---|---|---|---|
| Workstation lewat proxy, di-bump | URL dan host di log proxy; JA4 milik proxy di egress | Tidak ada karena ECH; ClientHello buatan proxy tanpa ECH | Log proxy |
| Workstation lewat proxy, di-splice (Edge) | Host di `CONNECT`; SNI asli di egress (GREASE ECH saja) | Tidak ada, selama Edge tidak memakai ECH sungguhan di balik proxy (masih diuji) | Log proxy, `ssl.log` |
| Klien yang `CONNECT` ke `public_name` | `CONNECT` ke nama penyedia, JA4 klien, pola, alamat CDN | Nama tujuan asli, di proxy maupun egress | Kueri HTTPS di `index=dns`, JA4, pola (`INC-2027-074`) |
| Server data center keluar langsung | SNI asli; belum ada ECH sungguhan teramati | Belum ada | `ssl.log`, `dns.log` |
| Wi-Fi tamu `JAB-Tamu` | Alamat, JA4, pola; kueri DNS ke resolver PT JAB | SNI asli untuk 14,3% ClientHello (ECH sungguhan) | `dns.log` agregat; tidak ada bila perangkat memakai DoH |
| DNS terenkripsi dan QUIC | Di luar cakupan Day ini | Jalur DNS ikut tertutup | Dibahas di Day 16 |

Tabel itu didukung dua berkas angka dan satu baseline yang layak disimpan dan diperbarui berkala.

Bentuk dari catatan lama:

```
peta-celah-tls.csv
domain,punya_ech,alpn,alamat,terakhir_dilihat
www.contoh.co.id,ya,"h3,h2",198.51.100.10,2026-10-09
```

```
baseline-ja4.csv
ja4,jumlah_host,jumlah_koneksi,perkiraan_klien,pertama_dilihat
t13d1516h2_8daaf6152771_02713d6af862,142,98211,browser korporat,2026-07-01
```

Versi PT JAB memisahkan celah per sumber, karena keputusan untuk tiap sumber berbeda (bagian 1.9):

```
peta-celah-ech-20270614.csv
sumber,clienthello,ech_ekstensi,ech_sungguhan,persen_tertutup,catatan
proxy,14466,10608,2,0.01,nama tujuan tetap ada di log proxy kecuali CONNECT ke public_name
tamu,2874,2031,412,14.3,perangkat tidak dikelola; agregat saja
server-dc,1080,0,0,0.0,belum ada library server yang memakai ECH
total,18420,12639,414,2.2,file 07:00-07:15 WIB
```

```
ech-domain-20270614.csv
domain,public_name,config_id,alpn,alamat,terakhir_dilihat
sync.harbor-ledger.example,ech.edgefront.example,23,h2,203.0.113.188 203.0.113.189,2027-06-11
```

```
baseline-ja4.csv (ringkas)
ja4,klien,sumber_atribusi,pertama_dilihat,status
t13d1516h2_8daaf6152771_b186095e22b6,Edge (splice),log proxy,2027-06-10,allowlist
t13d1512h2_8daaf6152771_e99876c6e365,jkt-proxy01 (bump),Day 06,2027-06-10,allowlist
t13d1414h2_2b729b4bf6f3_c4b8e1a59f02,MeetVendorDesktop 6.5.0,jadwal perubahan EUC,2027-06-11,allowlist
t13d1010h2_61a7ad8aa9b6_3a8073edd8ef,implant INC-2027-074,log proxy + EDR,2027-06-11,IOC
```

Cara membaca: kolom `persen_tertutup` proxy dihitung 2 dari 14.466, yaitu 0,014%, dibulatkan 0,01. Peta celah ECH dan berkas angkanya menjawab pertanyaan manajemen "seberapa buta kita sekarang" dengan angka, bukan dengan perasaan. Tabel JA4 adalah dasar hunting di bagian 2.5, dan nilainya tumbuh seiring waktu; kolom `sumber_atribusi` mencatat dari mana kamu tahu klien itu, karena di egress semuanya bersumber dari proxy.

**Kapan gagal:** satu file 15 menit di pagi hari bukan gambaran sehari; ulangi untuk jam sibuk dan akhir pekan sebelum angka masuk laporan bulanan. Daftar `public_name` yang tidak diperbarui membuat angka ECH sungguhan terlalu kecil.

### 2.10 Jawaban untuk Dimas

Jawaban dikirim ke Dimas pukul 11:30 WIB dalam satu halaman. Tabel berikut adalah ringkasannya; kolom kanan menunjukkan bagian yang menjadi dasarnya, supaya Dimas bisa meneruskan ke Hendra tanpa kehilangan jejak.

| Pertanyaan | Jawaban singkat | Dasar |
|---|---|---|
| Apa yang disembunyikan ECH | SNI dan ALPN asli; IP, DNS polos, fingerprint, dan pola tetap terlihat | Bagian 1.1 |
| Kenapa SNI `ech.edgefront.example` untuk banyak tujuan | Itu `public_name` penyedia di ClientHello luar; tujuan asli terenkripsi di dalam | Bagian 1.2, 2.1 |
| 68,6% tertutup? | Tidak. 68,6% membawa ekstensi ECH, tetapi 66,4% GREASE; yang tertutup sungguhan 2,2%, hampir semuanya Wi-Fi tamu | Bagian 1.4, 2.3 |
| Di mana ECH mengurangi visibilitas PT JAB | Wi-Fi tamu dan klien yang `CONNECT` ke `public_name`; untuk workstation lain, log proxy tetap memuat nama tujuan | Bagian 1.5, 2.4 |
| Tujuan asli dari mana | Log proxy, kueri HTTPS di DNS, JA4, dan pola; alamat CDN hampir tidak membantu | Bagian 1.6, 2.2, 2.8 |
| JA4+ dan dua alert | 0670: implant, `INC-2027-074`, `JKT-WS-2072` diisolasi; 0672: pembaruan klien rapat, jinak, masuk allowlist | Bagian 1.7, 2.5 sampai 2.8 |
| Lisensi | JA4 BSD 3-Clause; JA4S, JA4H, JA4SSH, dan lainnya FoxIO License 1.1, aman untuk pemakaian internal, perlu ditinjau Legal bila menjadi bagian layanan berbayar | Bagian 1.8 |
| Matikan ECH di firewall? | Tidak bisa dengan andal; pilihan yang masuk akal adalah kebijakan Edge untuk perangkat dikelola dan opsi resolver untuk Wi-Fi tamu, keduanya keputusan Hendra dengan DPO dan Legal; keduanya tidak menghentikan implant seperti di `INC-2027-074` | Bagian 1.9 |

Peta celah ECH dari bagian 2.9 dilampirkan. Rekomendasi yang ditulis di bawah tabel: (1) lanjutkan uji Rudi di `JKT-WS-2070` untuk menjawab apakah Edge memakai ECH di balik proxy eksplisit dan apa yang terjadi saat bump; (2) jadikan `CONNECT` ke `public_name` dari User-Agent non-browser sebagai rule Splunk; (3) perbarui `ech_public_names.csv` harian dari jawaban HTTPS di pcap egress; (4) bawa keputusan kebijakan ECH untuk Wi-Fi tamu dan workstation ke rapat program berikutnya bersama Agus dan Ratna.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** VM lab di jaringan host-only (misalnya `192.168.56.0/24`) dengan Wireshark 4.6.x dan Zeek dengan plugin `zeek/foxio/ja4` (Day 08 untuk instalasi Zeek); akses ke resolver yang bisa mengembalikan rekaman HTTPS; dan browser yang mendukung ECH, dengan snapshot sebelum mulai. Untuk langkah yang butuh internet, pakai NAT lab yang terpisah dari jaringan kantor. Data PT JAB tidak dipakai di lab.

1. Ambil rekaman HTTPS lewat DNS untuk sepuluh domain populer dan sepuluh domain lokal. Hitung berapa yang mempublikasikan parameter `ech`, dan simpan sebagai baris pertama peta celahmu. Catat juga `public_name` dan `config_id` dari tiap konfigurasi (bagian 2.2).
2. Rekam trafik saat mengunjungi satu domain yang mempublikasikan ECH, lalu temukan ekstensi ECH di ClientHello dan catat nilai SNI luarnya.
3. Ulangi untuk domain yang tidak memakai ECH, lalu bandingkan kedua ClientHello berdampingan. Tulis apa persisnya yang berbeda: SNI luar, `config_id`, panjang `payload`. Bandingkan juga JA4 keduanya; menurut bagian 1.4 seharusnya sama, buktikan.
4. Kunjungi beberapa domain berbeda yang berada di balik penyedia yang sama, lalu buktikan bahwa SNI luarnya identik walaupun tujuannya berbeda.
5. Korelasikan koneksi ECH dengan kueri DNS yang mendahuluinya berdasarkan waktu dan alamat jawaban. Hitung berapa persen koneksi yang bisa kamu identifikasi tujuannya lewat jalur ini.
6. Matikan DNS polos di klien lab (aktifkan DNS terenkripsi di browser) dan ulangi langkah 5. Catat berapa persen yang masih bisa diidentifikasi, dan tulis selisihnya sebagai ukuran celah visibilitas.
7. Jalankan Zeek atas rekaman yang sama, hasilkan JA4 dan JA4S, lalu buat baseline frekuensi. Periksa lima nilai paling jarang dan identifikasi kliennya. Catat nama kolom persis yang ditulis plugin di `ssl.log` dan `conn.log`.
8. Ganti cipher atau pengaturan klien di lab untuk mensimulasikan cipher stunting (misalnya `curl` dengan `--ciphers` atau `--tls13-ciphers` yang berbeda), lalu buktikan bahwa bagian `a` dan `c` dari JA4 tetap sementara `b` berubah [S2]. Bila jumlah cipher ikut berubah, bagian `a` juga berubah di karakter 5 dan 6; catat kasus itu.
9. Cari pola penolakan dan percobaan ulang ECH di rekamanmu memakai bagian 2.7. Bila tidak menemukannya, catat itu dan jelaskan kenapa polanya mungkin tidak muncul di lab.
10. Tulis setengah halaman untuk pembaca non-teknis yang menjelaskan apa yang berubah, berapa besar celahnya di angka, dan pilihan apa yang tersedia, termasuk konsekuensi masing-masing.
11. Pisahkan GREASE dari ECH sungguhan di rekamanmu dengan cara bagian 2.3: buat daftar `public_name` dari langkah 1, lalu hitung kedua kelompok. Bandingkan dengan hitungan naif "ada ekstensi ECH".
12. Di browser lab berbasis Chromium, nonaktifkan ECH lewat kebijakan `EncryptedClientHelloEnabled` (bagian 1.9), ulangi langkah 2, dan catat apakah ekstensi ECH (sungguhan maupun GREASE) masih muncul.

**Variasi tantangan:** pasang Squid dengan SslBump di lab, arahkan browser ke proxy eksplisit, lalu ukur dua hal yang di PT JAB masih terbuka (bagian 1.5): apakah browser memakai ECH sungguhan di balik proxy eksplisit, dan apa yang terlihat di sisi luar proxy ketika sesi ber-ECH di-splice dan di-bump. Bila kamu punya keylog dengan `ECH_SECRET` dari klien lab, buka pcap dengan keylog itu dan periksa apakah `tls.ech_accepted` muncul (bagian 1.3).

**Hasil yang sebaiknya tersimpan:**

- Peta celah berisi domain yang mempublikasikan ECH beserta `public_name`, `config_id`, alamat, dan ALPN-nya.
- Perbandingan ClientHello dengan dan tanpa ECH, berdampingan, termasuk JA4 keduanya.
- Bukti bahwa SNI luar identik untuk tujuan berbeda di balik penyedia yang sama.
- Dua angka persentase identifikasi tujuan: dengan DNS polos dan tanpa DNS polos.
- Baseline frekuensi JA4 beserta identifikasi lima nilai paling jarang dan nama kolom plugin.
- Bukti perilaku bagian `a_b_c` saat cipher diubah.
- Catatan pola penolakan dan percobaan ulang, atau catatan kenapa tidak ditemukan.
- Hitungan GREASE dan ECH sungguhan, dibandingkan dengan hitungan naif.
- Hasil uji kebijakan browser.
- Setengah halaman penjelasan untuk pembaca non-teknis.

## 4. Troubleshooting

Tabel ini memetakan gejala yang paling sering muncul saat menganalisis ECH dan JA4+ ke penyebab dan cara memeriksanya. Cari gejalamu di kolom pertama.

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Ekstensi ECH tidak muncul di Wireshark | Versi Wireshark sebelum 4.2.0 tidak mengurai ekstensinya | Filter `tls.handshake.extension.type == 65037` dan baca byte mentah; perbarui alat [S6] |
| Hampir semua ClientHello browser membawa ekstensi ECH | GREASE ECH, bukan ECH sungguhan [S1][S13] | Cocokkan SNI luar dengan daftar `public_name`; stacking `config_id` (bagian 2.3) |
| Semua koneksi punya SNI yang sama | Itu `public_name`, bukan tujuan sebenarnya [S1] | Jangan simpulkan tujuan dari SNI pada koneksi ber-ECH |
| Rekaman HTTPS tidak dikembalikan | Resolver tidak mendukung tipe rekaman itu, atau sengaja menjawab kosong untuk mematikan ECH [S12] | Pakai resolver lain; periksa dengan tipe rekaman eksplisit (`HTTPS` atau `TYPE65`) |
| Kolom `public_name` kosong saat mengurai jawaban DNS | Field DNS lama `dns.svcb.svcparam.echconfig` hilang setelah 4.0.17; penguraian di 4.6.x perlu dicek [S7] | Ambil nilai Base64 `ech=` dengan `dig` dan urai di lab |
| Kolom `answers` di `dns.log` kosong untuk tipe HTTPS | Zeek belum mengisi jawaban HTTPS di versimu | Ambil jawaban dari pcap egress (bagian 2.2) |
| Korelasi DNS dan koneksi gagal | Jawaban DNS di-cache sehingga kueri tidak muncul | Perpanjang jendela korelasi; pertimbangkan TTL; aplikasi bisa menyimpan konfigurasi berhari-hari |
| Tidak ada kueri DNS sama sekali | Klien memakai DNS terenkripsi atau konfigurasi ECH tertanam | Pokok bahasan Day 16; catat sebagai celah; cari di log proxy dan JA4 |
| JA4 tidak dihasilkan Zeek | Plugin JA4 belum terpasang, dimatikan dengan `redef`, atau gagal build (butuh Zeek 7.0+ dan C++20) [S8][S9] | `zkg list`; cek kolom `ja4` ada tetapi kosong (metode dimatikan) atau tidak ada sama sekali (plugin tidak dimuat) |
| Kolom `ja4_r` tidak ada | Opsi `_raw` diatur saat build, bukan saat berjalan [S8] | Ubah `config.zeek`, build ulang plugin |
| JA4X tidak ada di Zeek | Plugin masih menunggu dukungan objek di Zeek [S8] | Pakai JA4X dari Wireshark plugin atau alat lain |
| JA4T di egress sama untuk semua workstation | Koneksi TCP ke server dibuka proxy | JA4T di egress milik proxy; JA4 TLS milik klien hanya untuk sesi splice (bagian 2.5) |
| Fingerprint yang sama dipakai banyak host sah | Memang sifatnya; fingerprint mengelompokkan, bukan mengidentifikasi | Pakai sebagai penyempit, selalu dengan bukti lain |
| JA4 aplikasi sah tiba-tiba berubah | Pembaruan library TLS [S2] | Bandingkan bagian `a`, `b`, `c`; cek jadwal perubahan dan User-Agent (bagian 2.6) |
| Pola penolakan ECH tidak ditemukan | Konfigurasi klien masih mutakhir, jadi tidak ada penolakan | Wajar; catat sebagai tidak teramati |
| Filter `tls.record.content_type == 23` tidak cocok di TLS 1.3 | Record TLS 1.3 yang tidak didekripsi memakai tipe luar di `tls.record.opaque_type` [S6][S14] | Pakai keduanya dengan `or` (bagian 2.7) |
| `tls.ech_accepted` tidak pernah muncul | Butuh ClientHelloInner, jadi butuh keylog berisi `ECH_SECRET` | Hanya untuk trafik lab sendiri (bagian 1.3) |

## 5. Kesalahan umum dan jebakan

- Menyimpulkan tujuan koneksi dari SNI pada koneksi yang memakai ECH, padahal itu nama publik penyedia [S1].
- Menghitung "ClientHello dengan ekstensi ECH" lalu melaporkannya sebagai "trafik yang SNI-nya tertutup", padahal sebagian besar GREASE (bagian 2.3).
- Menganggap ECH membuat analisis mustahil, padahal alamat IP, DNS polos, fingerprint, dan pola lalu lintas tetap ada [S1].
- Lupa bahwa ECH tanpa DNS terenkripsi masih menyisakan jalur identifikasi lewat kueri DNS, terutama kueri HTTPS tepat sebelum koneksi [S1][S5].
- Memblokir atau menandai alamat client-facing server, padahal alamat itu dipakai ribuan situs sah (bagian 2.4).
- Memakai fingerprint sebagai identifikasi, bukan sebagai pengelompokan.
- Memakai JA4 untuk membedakan ECH sungguhan dari GREASE, padahal keduanya menghasilkan JA4 yang sama untuk klien yang sama.
- Membaca JA4T atau JA4L di egress sebagai milik workstation, padahal TCP-nya dibuka proxy.
- Menutup alert JA4 baru sebagai jinak hanya karena User-Agent cocok, tanpa jadwal perubahan, prevalence, atau data host.
- Memakai metode JA4+ selain JA4 dalam produk atau jasa berbayar tanpa memeriksa lisensinya [S2].
- Menyimpulkan penolakan ECH dari satu koneksi tanpa data aplikasi, atau dari filter `content_type == 23` yang di TLS 1.3 juga cocok dengan record handshake terenkripsi.
- Menjalankan `dig` ke domain penyerang dari jaringan kantor sebelum bukti pasif habis dibaca.
- Menganggap kebijakan browser atau jawaban resolver menutup jalur penyerang, padahal aplikasi dengan konfigurasi ECH tertanam tidak terpengaruh (bagian 1.9).
- Membuka sesi individu perangkat tamu tanpa dasar insiden dan persetujuan.
- Melaporkan hilangnya visibilitas sebagai kegagalan analisis, bukan sebagai temuan arsitektur yang butuh keputusan.
- Mengusulkan intersepsi TLS sebagai solusi teknis tanpa membahas konsekuensi hukum dan keamanannya.

## 6. Catatan terkini

Bagian ini mencatat status standar, versi alat, dan perubahan yang terkait ECH dan JA4+ per Oktober 2026.

- RFC 9849 berstatus Standards Track dan terbit Maret 2026 [S1]. Perubahan ini sudah resmi, jadi perencanaan visibilitas jaringan tidak bisa lagi menundanya sebagai urusan masa depan. RFC 9848, yang mengatur publikasi konfigurasi ECH lewat rekaman SVCB dan HTTPS, terbit bersamaan [S5].
- TLS 1.3 kini didefinisikan oleh RFC 9846 (Juli 2026), yang menggantikan RFC 8446; aturan tipe luar record terenkripsi (selalu 23) tetap sama [S14].
- Spesifikasinya menyatakan sendiri bahwa ECH tidak menyembunyikan semuanya, dan menganjurkan DNS terenkripsi dipakai bersamanya [S1]. Kombinasi keduanya, bukan ECH sendirian, yang benar-benar menutup identifikasi tujuan di lapisan jaringan.
- Bagian tentang dampak pada pemakaian yang bergantung SNI menyebut contoh konkret seperti penyeimbangan beban berbasis SNI dan organisasi yang mematikan ECH lewat kebijakan [S1]. Dua hal itu kemungkinan besar akan muncul dalam diskusi arsitektur di tempat kerja, jadi siapkan jawaban yang tidak hanya teknis.
- Chrome mengaktifkan ECH bawaan sejak versi 117 dan menerapkan GREASE ECH [S13]. Edge menyediakan kebijakan `EncryptedClientHelloEnabled` sejak versi 108 dan menyebutnya kontrol sementara yang akan diganti [S11]. Cek ulang dokumentasi kebijakan sebelum menulis GPO, karena namanya bisa berubah.
- Cloudflare mengaktifkan ECH bawaan untuk zona Free dan memakai `cloudflare-ech.com` sebagai SNI luar bersama [S12]. Tingkat penerapan ECH di penyedia lain dan di browser selain Chromium tidak dituliskan di sini karena belum ada angka resmi yang bisa dijadikan pegangan; ukur di jaringanmu dengan cara bagian 2.3.
- Wireshark 4.6.9 adalah rilis stabil per Oktober 2026, dengan 4.4.19 sebagai old stable dan 5.0.0rc1 sebagai rilis pengembangan. Field `tls.ech.*` ada sejak 4.2.0; `tls.ech_accepted` dan `tls.ech_rejected` ditambahkan di 4.6.0 [S6].
- Plugin JA4+ untuk Zeek berubah dari skrip murni menjadi plugin C++ di versi 1.0.0 (14 Agustus 2026), dengan syarat minimum naik ke Zeek 7.0; versi 1.0.1 (31 Agustus 2026) adalah perbaikan bug, termasuk JA4H yang kini mengabaikan pseudo-header HTTP/2 dan penentuan penanda `q`/`t` dari konteks paket [S9]. README plugin menyebut pengujian dengan Zeek 8.0.6 [S8]; kompatibilitas dengan Zeek 9.0 perlu diuji sebelum dipasang di sensor produksi.
- JA4 untuk klien TLS berlisensi BSD 3-Clause, sedangkan seluruh metode JA4+ lainnya patent-pending dengan FoxIO License 1.1 yang melarang monetisasi tanpa lisensi OEM [S2]. Pastikan hal ini sebelum metodenya masuk ke alat yang dijual.
- Dokumentasi JA4 berpendapat TLS 1.3 justru mempermudah fingerprinting klien karena klien mendukung lebih banyak ekstensi [S2]. Ini kebalikan dari dugaan umum, dan layak diuji sendiri terhadap data lab-mu.

## 7. Cheat sheet

```
ECH (RFC 9849, Standards Track, Maret 2026; hanya TLS 1.3)
HILANG    SNI asli (pindah ke ClientHelloInner terenkripsi) | ALPN
TERSISA   alamat IP server | public_name di server_name LUAR | config_id, cipher, enc, payload
          kueri DNS (kalau masih polos) | ukuran/arah/waktu paket | fingerprint ClientHello luar
PERAN     klien | client-facing server (dekripsi CH luar; shared vs split mode) | backend server
KODE      ekstensi encrypted_client_hello 0xfe0d (65037) | ech_outer_extensions 0xfd00 | alert ech_required 121
NAMA LUAR SNI pada koneksi ber-ECH = nama PENYEDIA, BUKAN tujuan -> jangan simpulkan tujuan dari situ
CONFIG    ECHConfigList lewat rekaman SVCB/HTTPS (tipe 65) di DNS (RFC 9460, RFC 9848; SvcParamKey ech = 5)
          dig +short HTTPS <domain>   -> parameter ech=, alpn=, ipv4hint=   (dig lama: TYPE65)
          semua endpoint punya ech -> klien SVCB-reliant, tidak fallback; ClientHello setelah resolusi SVCB
TOLAK     server tak bisa dekripsi -> handshake pakai CH luar, klien autentikasi ke public_name
          server boleh kirim retry_configs (terenkripsi di EE) -> klien coba ulang di KONEKSI TRANSPORT BARU
          klien kirim ech_required, TIDAK boleh fallback tanpa enkripsi, TIDAK pakai koneksi ditolak untuk data
          POLA DI KABEL: koneksi pendek tanpa data, lalu koneksi baru ke tujuan sama, config_id BERUBAH
TERIMA    8 byte akhir ServerHello.random = accept confirmation; tls.ech_accepted butuh ECH_SECRET (lab)
GREASE    ekstensi ECH palsu, config_id acak, SNI luar = nama ASLI; Chromium kirim di hampir semua CH
          ECH sungguhan: SNI luar = public_name, config_id sama untuk banyak klien
          JA4 TIDAK membedakan keduanya

WIRESHARK tls.handshake.extension.type == 65037 | tls.ech.config_id | tls.ech.payload (4.2.0+)
          tls.ech.echconfigcontents.public_name | tls.ech_accepted / tls.ech_rejected (4.6.0+)
          dns.qry.type == 65 and dns.svcb.svcparam.key == 5
          TLS 1.3: record terenkripsi -> tls.record.opaque_type == 23 (bukan tanda data aplikasi)

PENGGANTI SNI (PT JAB, urut kuat ke lemah)
          1 log proxy (CONNECT host)  2 DNS (kueri HTTPS sebelum koneksi)  3 alamat IP (lemah di CDN)
          4 fingerprint (JA4+)         5 pola lalu lintas (beaconing, Day 11)
          sertifikat: terenkripsi di TLS 1.3, hanya tersisa untuk TLS 1.2

JA4+      JA4 klien TLS | JA4S server TLS | JA4H HTTP | JA4X sertifikat | JA4SSH | JA4T/JA4TS TCP
          JA4L/JA4LS latensi | JA4D/JA4D6 DHCP | JA4N NTP | JA4TScan, JA4Scan-TLS, JA4Scan-QUIC (aktif)
          format a_b_c -> bisa berburu pakai a saja, c saja, atau a+c
          mengurutkan cipher & ekstensi -> tahan cipher stunting dan pengacakan urutan ekstensi
          cipher diganti terus: JA3 berubah tiap kali; JA4 hanya bagian b yang berubah
          berubah saat library TLS diperbarui (~setahun sekali) -> cek jadwal perubahan
ZEEK      zkg install zeek/foxio/ja4 (v1.x, Zeek 7.0+, C++20)
          ssl.log ja4 ja4s | http.log ja4h | conn.log ja4t ja4ts ja4l ja4ls | ja4ssh.log | ja4d.log
          _raw diatur saat build; metode bisa dimatikan dengan redef (kolom tetap ada, kosong)
PROXY     sesi splice: JA4 TLS milik klien, JA4T/JA4L milik proxy ; sesi bump: semuanya milik proxy
LISENSI   JA4 = BSD 3-Clause (bebas) ; JA4+ lain = FoxIO 1.1, patent-pending,
          boleh internal/akademik, TIDAK boleh monetisasi tanpa lisensi OEM

MATIKAN?  Edge: EncryptedClientHelloEnabled = disabled (108+) | resolver: HTTPS kosong/NXDOMAIN,
          canary use-application-dns.net (Firefox) | firewall: tidak andal | implant tertanam: tidak terpengaruh
SIKAP     hilangnya visibilitas = TEMUAN ARSITEKTUR, bukan kegagalan analisis
          intersepsi TLS dan pemblokiran = keputusan kebijakan + hukum, bukan keputusan analyst
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Satu file pcap egress menunjukkan 68,6% ClientHello membawa ekstensi `encrypted_client_hello`. Bolehkah laporan menulis "68,6% trafik TLS kita sudah tidak bisa dibaca tujuannya"?

<details><summary>Jawaban</summary>

Tidak. Browser berbasis Chromium mengirim GREASE ECH, yaitu ekstensi ECH palsu dengan `config_id` acak, di hampir setiap ClientHello ketika tidak punya konfigurasi untuk tujuan itu. Pada GREASE, SNI luar tetap nama asli. Untuk menghitung yang benar-benar tertutup, cocokkan SNI luar dengan daftar `public_name` dari rekaman HTTPS. Di file PT JAB, hasilnya 2,2% ECH sungguhan dan 66,4% GREASE.

Lihat bagian 1.4 dan 2.3.

</details>

**2. Skenario keputusan.** `ssl.log` menunjukkan koneksi berkala tiap sekitar 20 menit dari `10.20.3.60` ke `203.0.113.188` dengan SNI `ech.edgefront.example`, dan JA4-nya tidak dipakai klien lain. Apa langkahmu berikutnya?

- A. Blokir `203.0.113.188` di firewall karena itu tujuan C2.
- B. Cari kueri HTTPS di `index=dns` dan `CONNECT` ke `ech.edgefront.example` di log proxy untuk menemukan workstation dan nama asli, lalu periksa pola penolakan ECH di pcap.
- C. Tutup sebagai jinak karena SNI-nya nama CDN terkenal.

<details><summary>Jawaban</summary>

B. Log proxy adalah satu-satunya jembatan dari `10.20.3.60` ke workstation, dan kueri HTTPS biasanya muncul tepat sebelum koneksi ber-ECH dengan nama asli tujuan. A keliru karena alamat itu milik client-facing server CDN yang dipakai ribuan situs sah; di PT JAB lebih dari 2.300 koneksi proxy dan 58 perangkat tamu ke alamat yang sama dalam dua jam. C keliru karena SNI pada koneksi ber-ECH adalah `public_name` penyedia, bukan tujuan; nama CDN tidak mengatakan apa pun tentang backend.

Lihat bagian 1.6, 2.2, 2.4, dan 2.8.

</details>

**3. Pertanyaan jebakan.** Dua ClientHello dari Edge yang sama punya JA4 identik. Satu memakai ECH sungguhan dan satu GREASE. Apakah JA4 salah hitung?

<details><summary>Jawaban</summary>

Tidak. JA4 menghitung daftar ekstensi tanpa nilai GREASE yang dicadangkan, tetapi GREASE ECH memakai kode ekstensi asli 0xfe0d. Jumlah ekstensi dan hash ekstensinya sama, dan SNI luar ada di keduanya sehingga karakter SNI di bagian `a` sama-sama `d`. JA4 memang tidak dirancang membedakan keduanya; pakai SNI luar dan `config_id`.

Lihat bagian 1.4 dan 1.7.

</details>

**4. Jelaskan ulang.** Bambang bertanya, "Kenapa ECH tidak bisa dimatikan saja di firewall seperti protokol lain?" Jelaskan dalam tiga kalimat.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh jawaban: "Firewall tidak bisa membedakan ECH sungguhan dari ekstensi palsu yang dikirim browser di hampir setiap koneksi, jadi memblokir ekstensinya berarti memblokir hampir semua browsing, dan memblokir nama atau alamat CDN berarti memblokir ribuan situs. Yang bisa dikendalikan adalah klien: kebijakan Edge untuk laptop kantor dan jawaban resolver untuk perangkat yang memakai DNS kita. Keduanya tidak berlaku untuk malware yang membawa konfigurasi ECH sendiri, jadi deteksi tetap lewat log proxy, DNS, dan fingerprint."

Kesalahan yang sering muncul: menjanjikan bahwa kebijakan browser menutup celah sepenuhnya; mengusulkan intersepsi TLS tanpa menyebut bahwa itu keputusan Hendra bersama DPO dan Legal; atau menyebut ECH "tidak bisa dideteksi", padahal SNI luar dan `config_id` terbaca.

</details>

**5. Skenario keputusan.** Tim produk PT JAB ingin menjual layanan "deteksi klien mencurigakan" ke pelanggan korporat dengan memakai JA4H dan JA4SSH dari sensor PT JAB. Apa sikapmu?

- A. Aman, karena JA4+ open source seperti JA3.
- B. Sampaikan bahwa JA4 berlisensi BSD 3-Clause, tetapi JA4H, JA4SSH, dan anggota JA4+ lain berlisensi FoxIO License 1.1 yang tidak mengizinkan monetisasi tanpa lisensi OEM, lalu minta Legal meninjau sebelum layanan dirancang.
- C. Larang pemakaian JA4+ sama sekali, termasuk di SOC internal.

<details><summary>Jawaban</summary>

B. Hanya JA4 (klien TLS) yang BSD 3-Clause; anggota JA4+ lain patent-pending dengan FoxIO License 1.1 yang permisif untuk pemakaian internal dan akademik tetapi tidak untuk monetisasi. A keliru karena menyamakan seluruh keluarga dengan JA4. C keliru karena pemakaian internal untuk melindungi jaringan sendiri justru yang diizinkan lisensi itu.

Lihat bagian 1.8.

</details>

**6. Pertanyaan jebakan.** Di pcap, satu stream TLS 1.3 berisi empat record ber-tipe 23 lalu ditutup dalam 0,4 detik, dan stream berikutnya dari klien yang sama memakai `config_id` berbeda. Gilang menulis "ada data aplikasi di stream pertama, jadi bukan penolakan ECH". Benarkah?

<details><summary>Jawaban</summary>

Tidak. Pada TLS 1.3, setiap record terenkripsi bertipe luar 23, termasuk EncryptedExtensions, Certificate, Finished, dan alert, jadi record tipe 23 tidak membuktikan ada data aplikasi. Yang membedakan adalah jumlah dan ukuran record, durasi, dan perubahan `config_id` pada koneksi berikutnya. Empat record, 0,4 detik, lalu koneksi baru dengan `config_id` baru cocok dengan penolakan lalu percobaan ulang memakai `retry_configs`.

Lihat bagian 1.3 dan 2.7.

</details>

**7. Interview question (English).** "Encrypted Client Hello is spreading. As a network forensics analyst, what do you lose, and how do you keep investigating?"

<details><summary>Sample answer</summary>

"With ECH the real server name and ALPN move into an encrypted inner ClientHello, and the outer SNI only shows the provider's public name, so I stop treating SNI as the destination on those connections. What I keep is a lot: the server IP, plaintext DNS including the HTTPS record queries that carry the ECH config and usually precede the connection, the outer ClientHello for JA4 fingerprinting, and timing and size patterns for beaconing. I also have to measure the gap honestly, because Chromium sends GREASE ECH almost everywhere, so I separate real ECH from GREASE by matching the outer SNI against known public names and stacking the config ID. Behind an explicit proxy the CONNECT log still names the destination, unless a client deliberately connects to the public name, which is itself a strong signal. Finally I report reduced visibility as an architecture finding with numbers, and leave policy choices like disabling ECH or intercepting TLS to management, privacy and legal."

What makes this answer strong: it separates what ECH hides from what it does not, names concrete replacement sources in a sensible order, shows awareness of the GREASE trap that inflates naive counts, adapts to the proxy architecture, and keeps policy decisions with the right owners instead of proposing interception as a technical fix.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | RFC 9849: TLS Encrypted Client Hello | https://www.rfc-editor.org/rfc/rfc9849.html | primer | Standards Track, Maret 2026; dilihat 2026-10-09, dibaca ulang lengkap 2026-10-23 | Tinggi. Tujuan ECH, ClientHelloOuter dan Inner, `public_name` di server_name luar, peran client-facing dan backend server, publikasi config lewat SVCB dan HTTPS (RFC 9460 dan RFC 9848), perilaku penolakan dan `retry_configs`, `ech_required` (121), accept confirmation, padding, GREASE ECH, batas indistinguishability (10.10.4), proxy yang mengakhiri TLS (8.1.2), kode 0xfe0d dan 0xfd00, serta pernyataan bahwa ECH tidak menyembunyikan DNS polos dan alamat IP |
| S2 | JA4+ Network Fingerprinting (FoxIO, README resmi) | https://github.com/FoxIO-LLC/ja4 | primer | dilihat 2026-10-09, dicek ulang 2026-10-23 | Tinggi. Daftar lengkap metode JA4+ termasuk pemindai aktif, struktur `a_b_c`, pengurutan cipher dan ekstensi, perbandingan perilaku dengan JA3, perubahan JA4 saat library diperbarui, daftar alat pendukung, dan ketentuan lisensi BSD 3-Clause untuk JA4 serta FoxIO License 1.1 untuk metode lainnya |
| S3 | RFC 9460: Service Binding and Parameter Specification via the DNS (SVCB dan HTTPS RR) | https://www.rfc-editor.org/rfc/rfc9460.html | primer | dirujuk 2026-10-09 | Tinggi untuk bentuk rekaman HTTPS yang membawa parameter `ech`, `alpn`, dan `ipv4hint` |
| S4 | Network-Forensics-note Day 05, 06, 08, 11 | (lokal) | rujukan internal | 2026-10-09, diperbarui 2026-10-23 | Keterkaitan antar Day: DNS di PT JAB, proxy splice dan bump, plugin Zeek, beaconing |
| S5 | RFC 9848: Bootstrapping TLS Encrypted ClientHello with DNS Service Bindings | https://www.rfc-editor.org/rfc/rfc9848.html | primer | Standards Track, Maret 2026; diakses 2026-10-23 | Tinggi. SvcParamKey `ech` nomor 5, format Base64, perilaku SVCB-reliant tanpa fallback, ClientHello setelah resolusi SVCB, risiko DNS tanpa autentikasi |
| S6 | Wireshark display filter reference: Transport Layer Security (tls) | https://www.wireshark.org/docs/dfref/t/tls.html | primer | diakses 2026-10-23 | Tinggi. Field `tls.ech.*` (4.2.0 sampai 4.6.9), `tls.ech_accepted` dan `tls.ech_rejected` (4.6.0 sampai 4.6.9), `tls.handshake.ja4`, `tls.record.opaque_type` |
| S7 | Wireshark display filter reference: Domain Name System (dns) | https://www.wireshark.org/docs/dfref/d/dns.html | primer | diakses 2026-10-23 | Tinggi. Field `dns.svcb.svcparam.*`; `dns.svcb.svcparam.echconfig` hanya 3.6.0 sampai 4.0.17 |
| S8 | FoxIO JA4+: Zeek README | https://github.com/FoxIO-LLC/ja4/blob/main/zeek/README.md | primer | diakses 2026-10-23 | Tinggi. `zkg install zeek/foxio/ja4`, Zeek 7.0+, diuji dengan 8.0.6, C++20, lokasi log tiap metode, opsi `_raw` saat build, `redef` untuk mematikan metode, JA4X dan JA4D6 belum tersedia |
| S9 | FoxIO JA4+: GitHub releases (v1.0.0 dan v1.0.1) | https://github.com/FoxIO-LLC/ja4/releases | primer | v1.0.0 14 Agustus 2026, v1.0.1 31 Agustus 2026; diakses 2026-10-23 | Tinggi. Port plugin Zeek ke C++, syarat Zeek 5.0 menjadi 7.0, daftar perbaikan v1.0.1 |
| S10 | Zeek docs: ssl.log | https://docs.zeek.org/en/current/logs/ssl.html | primer | diakses 2026-10-23 | Tinggi. Field `ssl.log` dan contoh entri ESNI/ECH tanpa `server_name` dan tanpa sertifikat |
| S11 | Microsoft Edge Browser Policy: EncryptedClientHelloEnabled | https://learn.microsoft.com/en-us/deployedge/microsoft-edge-browser-policies/encryptedclienthelloenabled | primer | diperbarui 2026-06-15; diakses 2026-10-23 | Tinggi. Edge 108+, perilaku enabled/disabled, ketergantungan pada rekaman HTTPS, status kebijakan sementara, nilai GPO dan registry |
| S12 | Cloudflare docs: Encrypted Client Hello (ECH) | https://developers.cloudflare.com/ssl/edge-certificates/ech/ | primer (vendor) | diakses 2026-10-23 | Tinggi untuk perilaku Cloudflare: ECH bawaan di zona Free, `public_name` `cloudflare-ech.com`, saran resolver untuk jaringan yang mematikan ECH, canary Firefox |
| S13 | Chromium blink-dev: Intent to Ship: TLS Encrypted Client Hello (ECH) | https://groups.google.com/a/chromium.org/g/blink-dev/c/CmlXjQeNWDI/m/r-AUe0OqAQAJ | primer (vendor) | 11 September 2023; diakses 2026-10-23 | Tinggi. Konfigurasi dari rekaman HTTPS lewat DoH dan resolver bawaan Chrome, GREASE ECH, target Chrome 117 |
| S14 | RFC 9846: The Transport Layer Security (TLS) Protocol Version 1.3 | https://www.rfc-editor.org/rfc/rfc9846.html | primer | Standards Track, Juli 2026; diakses 2026-10-23 | Tinggi. Menggantikan RFC 8446; `opaque_type` record terenkripsi selalu 23 |

**Catatan sumber:** nomor ekstensi `encrypted_client_hello` adalah 0xfe0d (65037 desimal) sesuai RFC 9849 [S1]; nama field Wireshark untuk menguraikannya mengikuti display filter reference 4.6.9 [S6][S7], dan apakah `ECHConfigList` di paket DNS diurai dengan field `tls.ech.*` di 4.6.x perlu dicek di lab. Label `tls.ech_accepted` memerlukan bahan dari ClientHelloInner; kesimpulan bahwa label itu tidak muncul tanpa keylog adalah penalaran dari RFC 9849 bagian 7.2, bukan pernyataan dokumentasi Wireshark. Pernyataan bahwa JA4 tidak membedakan ECH sungguhan dari GREASE adalah penalaran dari definisi JA4 [S2] dan GREASE ECH [S1], perlu dibuktikan di lab. Keluaran `dig` bentuk umum di bagian 2.2 adalah ilustrasi dengan bentuk parameter yang umum, bukan salinan jawaban nyata. Nama kolom JA4+ di Zeek mengikuti README plugin [S8] secara umum; nama kolom persis dan kompatibilitas dengan Zeek 9.0 perlu dicocokkan dengan plugin di lab-mu. Contoh `ssl.log` di dokumentasi Zeek memakai situs uji ESNI [S10], sehingga perilaku `server_name` untuk ECH RFC 9849 perlu dicek. Apakah browser Chromium memakai ECH ketika dikonfigurasi memakai proxy eksplisit tidak ditemukan di sumber resmi; pengumuman Chromium hanya menyebut pengambilan rekaman HTTPS lewat DoH dan resolver bawaan [S13], jadi perilaku itu diperlakukan sebagai pertanyaan terbuka. Tingkat penerapan ECH di browser dan penyedia tidak dituliskan karena belum ada angka resmi yang bisa dijadikan pegangan. Seluruh isi PT JAB (Wi-Fi tamu `JAB-Tamu`, penyedia `edgefront.example` dan `public_name` lain, domain `harbor-ledger.example` dan `meetvendor.example`, hash JA4 dan JA4S selain contoh spesifikasi, angka pcap dan log, `config_id`, alert `SOC-2027-0670` sampai `SOC-2027-0672`, dan `INC-2027-074`) adalah penerapan catatan ini pada organisasi fiktif, bukan hasil eksekusi nyata.
