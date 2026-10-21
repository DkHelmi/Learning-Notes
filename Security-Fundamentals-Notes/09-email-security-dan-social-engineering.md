---
day: 09
title: 'Email security dan social engineering: phishing, BEC, header email, SPF, DKIM, DMARC, dan laporan user'
researched_on: 2026-10-21
versions_checked: 'RFC 5321 (SMTP, Okt 2008); RFC 5322 (Internet Message Format, Okt 2008); RFC 7208 (SPF, Apr 2014); RFC 6376 (DKIM, Sep 2011); RFC 9989 (DMARC, Mei 2026, menggantikan RFC 7489 dan RFC 9091; pelaporan di RFC 9990 dan RFC 9991); RFC 8601 (Authentication-Results, Mei 2019); NIST SP 800-177 Rev. 1 (Feb 2019); NIST CSRC Glossary; CISA Avoiding Social Engineering and Phishing Attacks (Feb 2021, arsip); FBI IC3 PSA I-091124-PSA (Sep 2024); FBI IC3 2025 Annual Report; FBI IC3 PSA I-011822-PSA (Jan 2022); MITRE ATT&CK T1566 v2.8; Microsoft Learn Defender for Office 365 (halaman diperbarui Mei sampai Okt 2026)'
---

# Day 09: Email security dan social engineering (phishing, BEC, header email, SPF, DKIM, DMARC, dan laporan user)

Cakupan: cara penyerang menipu manusia lewat email, SMS, telepon, dan kode QR (social engineering, phishing, spear phishing, whaling, BEC, smishing, vishing, quishing, pretexting), cara membaca header email dasar, tiga mekanisme autentikasi email (SPF, DKIM, DMARC) beserta batasnya, peran secure email gateway, bahaya URL dan lampiran, serta kenapa laporan user menjadi salah satu sensor terbaik SOC.

## Ide inti

Email dirancang di masa ketika semua orang di internet saling percaya. Protokol pengiriman email tidak memeriksa apakah pengirim benar orang yang ia akui; nama dan alamat yang kamu lihat di kolom "Dari" ditulis sendiri oleh pengirim [S9][S15]. Penyerang memanfaatkan dua kelemahan sekaligus: kelemahan teknis (alamat pengirim bisa dikarang) dan kelemahan manusia (orang cenderung menuruti atasan, panik saat diburu waktu, dan percaya pada nama yang dikenalnya). Social engineering adalah seni memanfaatkan kelemahan kedua, dan email, SMS, serta telepon adalah salurannya.

Pertahanannya juga berlapis dua. Di sisi teknis, SPF, DKIM, dan DMARC membuat pemilik domain bisa menyatakan server mana yang sah dan menandatangani email miliknya, sehingga penerima bisa menolak email yang memalsukan domain itu persis. Secure email gateway menyaring sisanya: spam, malware, tautan berbahaya, dan peniruan. Tetapi semua mekanisme itu hanya menjawab pertanyaan "apakah email ini benar dari domain yang tertulis?", bukan "apakah domain yang tertulis itu jujur?". Penyerang yang mendaftarkan domain mirip lalu mengatur SPF, DKIM, dan DMARC dengan rapi akan lolos semua pemeriksaan. Di titik itu, yang tersisa adalah manusia yang curiga, memverifikasi lewat jalur lain, dan melapor. Karena itu laporan user bukan pelengkap, melainkan sensor yang menangkap hal yang tidak ditangkap mesin.

Bayangkan surat kertas. Nama pengirim yang ditulis di depan amplop bisa ditulis siapa saja (header From), sedangkan data pengiriman yang dicatat kantor pos saat surat diserahkan adalah hal lain lagi (envelope). Perusahaan bisa mengumumkan daftar kantor pos resmi yang boleh mengirim surat atas namanya (SPF), menempelkan segel atau cap resmi di setiap suratnya (DKIM), dan memberi instruksi ke semua kantor pos: "bila ada surat atas nama kami yang tanpa segel atau dikirim dari kantor tak resmi, tolak, lalu kirimi kami laporan" (DMARC). Social engineering adalah penipu yang menelepon mengaku dari bank dan meminta kode OTP-mu. Batas analogi ini: di email, "segel" dan "daftar kantor pos" hanya berlaku untuk nama domain yang persis sama. Surat dari "PT JAB Direksi" dengan segel milik "PT JAB Direksi" yang asli dibuat penipu akan tampak sah sempurna bagi kantor pos, dan email bisa dikirim ribuan kali per menit tanpa biaya.

```
 Penyerang                                   PT JAB (Microsoft 365 + Defender for Office 365)
 ---------                                   --------------------------------------------------
 1. daftar domain mirip, atur SPF/DKIM/DMARC
 2. riset target (LinkedIn, situs perusahaan)
 3. kirim email "dari Direktur"  ------->  [secure email gateway]
                                             - SPF: server pengirim sah untuk domainnya?    pass
                                             - DKIM: segel domain pengirim utuh?            pass
                                             - DMARC: domain From cocok dengan SPF/DKIM?    pass
                                             - reputasi, peniruan nama, tautan, lampiran    tidak tertangkap
                                                      |
                                                      v
                                             Inbox staf Keuangan
                                                      |
                                    manusia: curiga, telepon balik lewat nomor resmi, klik Report
                                                      |
                                                      v
                                             phishing-report@jab.example  ->  alert SOC  ->  cari dan hapus salinan lain
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), sebuah ISP menengah fiktif dengan sekitar 1.200 karyawan. Email karyawan PT JAB memakai Microsoft 365 (Exchange Online) dengan perlindungan tambahan Microsoft Defender for Office 365 Plan 2, dan domain `jab.example` sudah memasang SPF, DKIM, dan DMARC dengan kebijakan paling ketat (`p=reject`). Ada kotak lapor khusus, `phishing-report@jab.example`, yang menerima setiap email yang dilaporkan karyawan lewat tombol Report di Outlook; setiap laporan menjadi alert (peringatan) di antrean SOC (Security Operations Center, tim yang memantau dan menangani kejadian keamanan). Oktober 2026 PT JAB pernah kena credential phishing bertema "password M365 kedaluwarsa" (`INC-2026-020`), ketika email palsu sampai ke 34 mailbox dan satu karyawan menyerahkan password-nya.

Kamu analyst L1 baru yang sedang menjalani orientasi minggu kedua. Kamis 2027-08-12 pukul 08:53, alert `SOC-2027-0848` masuk: Rina Anggraini, staf Keuangan bagian pembayaran vendor, melaporkan email "dari Pak Hendra Wijaya" (Direktur Teknologi) yang meminta transfer mendesak Rp 486.500.000 ke rekening vendor baru. Rina tidak membayar; ia menelepon Pak Hendra di nomor ekstensi kantor, Pak Hendra menyangkal, lalu Rina menekan tombol Report. Pukul 09:15 mentormu, Sari Kusuma (analyst L2), mengirim pesan:

> "Pagi ini ramai. Selain laporan Rina, tadi malam Dewi Lestari dari Customer Service dapat SMS 'paket tertahan' dengan tautan aneh, dan ada email berisi PDF dengan kode QR 'verifikasi ulang MFA'. Siang nanti pasti ada lagi. Sebelum kita bedah bareng, coba pikirkan: email ke Rina itu phishing, spear phishing, whaling, atau BEC? Apa bedanya, dan kenapa semuanya disebut social engineering? SMS dan kode QR itu masuk jenis apa? Nama pengirimnya tertulis 'Hendra Wijaya' dan fotonya pun mirip; kenapa bisa begitu kalau bukan dia? Coba buka header-nya: dari mana email itu sebenarnya datang? Domain kita sudah SPF, DKIM, dan DMARC reject, tapi kok hasil di header-nya pass semua? Defender kita Plan 2, kenapa email ini tetap sampai ke Inbox? Lalu apa bahayanya tautan dan lampiran, termasuk QR itu? Terakhir, email yang sama ternyata dikirim ke tiga orang Keuangan. Kenapa satu laporan dari Rina lebih berharga daripada semua filter kita pagi ini?"

Pesan itu memuat delapan pertanyaan:

1. Apa itu social engineering, dan kenapa manusia menjadi sasarannya?
2. Email ke Rina itu phishing, spear phishing, whaling, atau BEC, dan apa bedanya?
3. SMS "paket tertahan", PDF berisi kode QR, dan telepon yang mengaku dari pihak resmi masuk jenis apa, dan apa peran cerita karangan penyerang?
4. Kenapa nama pengirim bisa tertulis "Hendra Wijaya" padahal bukan dia, dan bagaimana membaca header email?
5. Bagaimana SPF, DKIM, dan DMARC bekerja, dan kenapa email ini lolos semuanya?
6. Apa yang bisa dan tidak bisa dilakukan secure email gateway seperti Defender for Office 365?
7. Apa bahayanya URL dan lampiran berbahaya, termasuk kode QR?
8. Kenapa laporan user begitu penting bagi SOC?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2 dan 1.3, pertanyaan 3 di bagian 1.4 dan 1.5, pertanyaan 4 di bagian 1.6, pertanyaan 5 di bagian 1.7, 1.8, dan 1.9, pertanyaan 6 di bagian 1.10, pertanyaan 7 di bagian 1.11, dan pertanyaan 8 di bagian 1.12. Bagian 2 membaca header email `SOC-2027-0848`, record DNS email `jab.example`, laporan DMARC, kasus PDF berisi QR, serta kasus SMS dan telepon yang berujung pada insiden `INC-2027-088`.

**Kapan relevan:** setiap kali kamu menangani laporan email mencurigakan dari user, membaca alert email dari Defender for Office 365 atau SIEM, menilai apakah sebuah email benar dari domain yang tertulis, menjelaskan ke user atau atasan kenapa email palsu bisa lolos filter, dan saat menjawab pertanyaan interview tentang phishing, BEC, atau SPF/DKIM/DMARC.
**Kapan bukan jawaban:** SPF, DKIM, dan DMARC tidak menilai isi email, niat pengirim, atau keamanan tautan, jadi hasil "pass" tidak pernah menjadi alasan untuk menutup laporan. Day ini juga tidak membahas analisis malware di dalam lampiran secara teknis (Day 13 dan Day 16) dan tidak menggantikan prosedur penanganan insiden lengkap (Day 19).

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (CIA triad, threat, vulnerability, control dari Day 01; IP address, DNS, record TXT, port, HTTPS dari Day 02) tidak diulang di tabel ini, tetapi definisinya diulang satu kalimat saat dipakai. Tabel ini memuat semua istilah email dan social engineering di Day ini; cari kolom ketiga bila sebuah istilah terasa abstrak.

| Istilah | Arti singkat | Padanan sehari-hari |
|---|---|---|
| Social engineering | Menipu manusia supaya menyerahkan informasi, akses, atau uang | Penipu yang menelepon mengaku dari bank |
| Phishing | Pesan palsu yang meniru pihak tepercaya untuk mencuri data atau memancing tindakan | Umpan pancing yang dilempar ke kolam ramai |
| Spear phishing | Phishing yang disesuaikan untuk orang atau organisasi tertentu | Tombak yang diarahkan ke satu ikan |
| Whaling | Spear phishing yang menyasar eksekutif senior | Memburu ikan paus, bukan ikan kecil |
| BEC (business email compromise) | Penipuan lewat email bisnis yang berujung transfer uang atau data | Surat palsu "dari atasan" ke kasir agar mencairkan uang |
| CEO fraud | Jenis BEC yang meniru eksekutif untuk menekan karyawan | Orang yang menyamar sebagai direktur di telepon ke bagian keuangan |
| Smishing | Phishing lewat SMS atau pesan teks | SMS "paket tertahan" dari kurir palsu |
| Vishing | Phishing lewat suara (telepon) | Telepon dari "petugas bank" yang meminta OTP |
| Quishing | Phishing lewat kode QR | Stiker QR palsu ditempel di atas QR asli di meja kasir |
| Pretexting | Membangun cerita karangan supaya permintaan terdengar wajar | Penipu mengaku petugas PLN yang perlu masuk rumah untuk "cek meteran" |
| Header email | Bagian awal email berisi data pengirim, penerima, waktu, dan jejak perjalanan | Label dan cap pos di amplop |
| Envelope (MAIL FROM) | Alamat pengirim yang dipakai antarserver saat pengiriman, tidak tampil di aplikasi email | Data pengiriman yang dicatat kantor pos |
| Header From | Alamat dan nama pengirim yang tampil di aplikasi email | Nama pengirim yang ditulis di depan amplop |
| Display name | Nama tampilan di depan alamat email (`"Hendra Wijaya" <...>`) | Nama yang ditulis tangan di amplop, tanpa bukti |
| Reply-To | Alamat tujuan balasan, bisa berbeda dari From | Tulisan "balas ke alamat ini" di amplop |
| Return-Path | Catatan alamat envelope di email yang sudah diterima, tujuan pesan gagal kirim | Alamat pengembalian bila surat tidak sampai |
| Received | Baris jejak yang ditambahkan setiap server yang dilewati | Cap pos dari setiap kantor pos yang dilewati |
| Message-ID | Nomor unik untuk satu email | Nomor resi |
| Authentication-Results | Catatan hasil pemeriksaan SPF, DKIM, DMARC oleh server penerima | Catatan petugas pos penerima: "segel utuh, kantor asal resmi" |
| SPF | Daftar server yang boleh mengirim email untuk sebuah domain, dipasang di DNS | Daftar kantor pos resmi yang boleh mengirim atas nama perusahaan |
| DKIM | Tanda tangan digital domain di setiap email | Segel atau cap resmi yang ditempel di surat |
| DMARC | Kebijakan pemilik domain: cocokkan domain From dengan SPF/DKIM, apa tindakan bila gagal, ke mana laporan dikirim | Instruksi perusahaan ke kantor pos plus permintaan laporan |
| Alignment | Kecocokan domain From dengan domain yang lolos SPF atau DKIM | Nama di amplop cocok dengan nama di segel |
| Spoofing | Memalsukan alamat From memakai domain orang lain persis | Menulis nama perusahaan lain di amplop |
| Impersonation (lookalike domain) | Meniru memakai nama atau domain yang mirip tetapi milik penyerang sendiri | Toko "lndomart" yang meniru papan nama toko terkenal |
| Secure email gateway (SEG) | Sistem yang menyaring semua email sebelum sampai ke mailbox | Ruang sortir surat di gedung kantor |
| Safe Links / Safe Attachments | Fitur Defender for Office 365 untuk memeriksa tautan saat diklik dan membuka lampiran di lingkungan uji | Petugas yang mengecek alamat tujuan sebelum kurir berangkat, dan membuka paket di ruang khusus |
| ZAP (zero-hour auto purge) | Penarikan otomatis email yang ternyata berbahaya setelah sudah terkirim | Petugas yang menarik kembali surat dari meja karyawan setelah tahu surat itu palsu |
| AiTM (adversary-in-the-middle) | Halaman login palsu yang meneruskan login ke situs asli sambil mencuri sesi | Loket palsu yang meneruskan urusanmu ke loket asli sambil memotret kartu antreanmu |
| Laporan user (user reported message) | Email mencurigakan yang dilaporkan karyawan lewat tombol Report | Tetangga yang melapor ke satpam kompleks soal orang mencurigakan |

### 1.1 Social engineering

Pertanyaan pertama Sari adalah dasar dari semua kasus pagi ini: email ke Rina, SMS ke Dewi, dan PDF berisi QR tidak membobol sistem apa pun. Ketiganya mencoba membuat manusia melakukan sesuatu.

**Apa itu:** social engineering adalah upaya menipu seseorang supaya ia menyerahkan informasi (password, kode OTP, data pelanggan), memberi akses, atau melakukan tindakan yang merugikan (mentransfer uang, menjalankan file) [S1]. Glosarium NIST mencatat beberapa definisi, intinya sama: menipu orang untuk membuka informasi atau akses, sering dengan membangun rasa percaya lebih dulu [S1]. CISA menggambarkannya sebagai pemakaian interaksi manusia (kemampuan sosial) untuk mendapatkan atau membobol informasi tentang organisasi [S3].

**Analogi:** penipu yang menelepon mengaku dari bank: "Ada transaksi mencurigakan di rekening Bapak, tolong sebutkan kode yang baru masuk ke HP supaya kami blokir." Penipu tidak membobol brankas bank; ia membuat nasabah sendiri yang membukakan pintu. Batasnya: di dunia digital penipu bisa mengirim ribuan "telepon" sekaligus dalam bentuk email dan SMS, memalsukan nama dan nomor pengirim, dan meniru tampilan resmi sampai ke logo dan tanda tangan email.

**Cara kerja:** hampir semua serangan social engineering memakai beberapa tuas psikologis yang sama:

- Otoritas: permintaan datang "dari direktur", "dari bank", "dari IT".
- Urgensi: "hari ini sebelum jam 11", "akun akan diblokir dalam 24 jam".
- Kerahasiaan atau isolasi: "jangan telepon, saya sedang rapat", "jangan bilang siapa-siapa dulu".
- Rasa takut atau iming-iming: denda, paket hilang, hadiah, bonus.
- Kebiasaan: memakai proses yang memang ada (pembayaran vendor, reset password, notifikasi kurir) supaya permintaan terlihat rutin.

Tanda peringatan yang disebut CISA cocok dengan tuas ini: alamat pengirim yang meniru perusahaan asli dengan beberapa huruf diubah, tautan yang tidak cocok dengan teks yang ditampilkan, lampiran yang tidak diminta dan diberi kesan mendesak, serta permintaan informasi pribadi atau keuangan [S3].

**Contoh di PT JAB:** email ke Rina memakai tiga tuas sekaligus: otoritas (nama Direktur Teknologi), urgensi (transfer sebelum pukul 11.00 supaya pengiriman perangkat tidak tertunda), dan isolasi ("saya sedang rapat di luar, jangan telepon, balas email saja"). Tuas isolasi itu justru membuat Rina curiga, karena Pak Hendra biasanya meminta pembayaran lewat sistem pengadaan, bukan lewat email pribadi.

**Beda dengan serangan teknis:** serangan teknis memanfaatkan celah di perangkat lunak atau konfigurasi (vulnerability, dibahas di Day 01 dan Day 17). Social engineering memanfaatkan celah di manusia dan proses. Keduanya sering digabung: email phishing (social engineering) membawa lampiran yang memanfaatkan celah teknis.

**Salah paham umum:**
- "Yang tertipu social engineering itu orang yang kurang pintar." Serangan yang baik dirancang untuk orang sibuk yang sedang menjalankan tugasnya dengan benar. Rina sehari-hari memang memproses pembayaran vendor; penyerang memilihnya justru karena itu.

Kenapa ini penting untuk security: FBI IC3 mencatat 191.561 pengaduan phishing/spoofing pada 2025, dan definisinya mencakup email, SMS, dan telepon yang mengaku dari perusahaan sah [S7]. Kontrol teknis bisa mengurangi jumlah pesan yang sampai, tetapi tidak bisa menghapus keputusan manusia dari rantai.

### 1.2 Phishing dan spear phishing

Pertanyaan kedua Sari dimulai dari kata yang paling sering dipakai: phishing. Email ke Rina jelas phishing, tetapi jenis yang mana?

**Apa itu:** phishing adalah pesan elektronik palsu yang meniru pihak tepercaya (perusahaan, bank, atasan, layanan IT) untuk mencuri informasi sensitif atau memancing korban ke situs palsu [S2]. NIST mencatat bentuk yang paling khas: email yang tampak asli meminta informasi atau mengarahkan pengguna ke situs tiruan [S2]. Spear phishing adalah phishing yang diarahkan ke orang, perusahaan, atau sektor tertentu, sedangkan phishing biasa disebar luas tanpa target khusus, misalnya kampanye spam massal [S4]. MITRE ATT&CK, katalog teknik penyerang yang dibahas di Day 14, mencatat Phishing sebagai teknik akses awal T1566 dengan empat sub-teknik: lampiran (T1566.001), tautan (T1566.002), lewat layanan pihak ketiga seperti media sosial (T1566.003), dan suara (T1566.004) [S4].

**Analogi:** phishing biasa seperti melempar umpan pancing ke kolam ramai; ikan mana pun yang menggigit sudah untung. Spear phishing seperti tombak yang diarahkan ke satu ikan yang sudah diamati: penyerang tahu namanya, jabatannya, dan proses kerjanya. Batasnya: di email, membuat tombak hampir semurah melempar umpan, karena informasi target tersedia di situs perusahaan dan media sosial, dan alat bantu tulis otomatis membuat pesan yang dipersonalisasi bisa dibuat massal.

**Cara kerja:** phishing biasa mengandalkan jumlah. Ribuan email "password Anda kedaluwarsa" dikirim, dan cukup sebagian kecil penerima yang mengisi password di halaman palsu. Spear phishing mengandalkan riset: penyerang mengumpulkan nama atasan, nama vendor, istilah internal, dan jadwal kegiatan, lalu menulis pesan yang hanya masuk akal bagi target itu. Karena isinya spesifik, filter yang mencari pola kampanye massal lebih sulit menangkapnya.

**Contoh di PT JAB:** `INC-2026-020` (Oktober 2026) adalah phishing yang cukup umum: email "password M365 kedaluwarsa" ke 34 mailbox dengan tautan ke halaman login palsu. Email ke Rina adalah spear phishing: menyebut nama Direktur Teknologi dengan benar, menyebut proyek pengadaan perangkat core router yang memang sedang berjalan, dan dikirim hanya ke tiga staf Keuangan yang mengurus pembayaran vendor.

**Beda dengan spam:** spam adalah email massal yang tidak diminta, biasanya iklan. Phishing punya niat menipu untuk mencuri sesuatu. Banyak phishing terkirim dengan cara seperti spam, tetapi tidak semua spam adalah phishing.

Kenapa ini penting untuk security: membedakan phishing massal dan spear phishing mengubah respons SOC. Phishing massal biasanya ditangani dengan menarik semua salinan dan memblokir pengirim. Spear phishing menandakan ada yang sudah meriset PT JAB dan mungkin akan mencoba lagi dengan cara lain, jadi target lain di unit yang sama perlu diperingatkan.

### 1.3 Whaling dan BEC

Lanjutan pertanyaan kedua: email ke Rina memakai nama direktur. Apakah itu whaling? Apakah itu BEC?

**Apa itu:** whaling adalah spear phishing yang menyasar eksekutif senior (direktur, CEO, CFO), karena mereka punya akses ke data sensitif dan wewenang atas uang [S5]. BEC (business email compromise) adalah penipuan yang menyasar bisnis atau perorangan yang rutin melakukan transfer dana, dengan membobol atau meniru akun email (dan belakangan juga nomor telepon dan aplikasi rapat virtual) untuk memicu transfer dana yang tidak sah [S7]. CEO fraud adalah jenis BEC yang meniru eksekutif untuk menekan karyawan; Proofpoint membedakannya dari whaling: pada whaling eksekutif menjadi sasaran, pada CEO fraud eksekutif menjadi topeng [S5].

**Analogi:** whaling seperti memburu paus, bukan ikan kecil: sasarannya sedikit tetapi hasilnya besar. BEC seperti surat palsu "dari atasan" yang diserahkan ke kasir agar mencairkan uang; kasirnya bekerja benar sesuai prosedur, yang palsu adalah perintahnya. Batasnya: BEC tidak selalu memakai nama atasan. Variasi yang sangat merugikan memakai akun email vendor sungguhan yang sudah dibobol, sehingga email datang dari alamat asli yang sudah lama berkorespondensi.

**Cara kerja:** pola BEC yang paling umum:

1. Penyerang memilih proses keuangan (pembayaran vendor, gaji, pengadaan) dan orang yang menjalankannya.
2. Penyerang meniru atau membobol akun pihak yang berwenang: eksekutif, vendor, atau mitra.
3. Permintaan dikirim dengan urgensi dan alasan yang masuk akal: rekening vendor berubah, pembayaran harus hari ini, rahasia karena akuisisi.
4. Uang ditransfer ke rekening penampung, lalu cepat dipindahkan ke rekening lain.

BEC sering tidak membawa tautan atau lampiran sama sekali; isinya hanya teks permintaan. Itu sebabnya filter yang mencari malware dan tautan berbahaya sering tidak menangkapnya. FBI IC3 mencatat kerugian BEC yang dilaporkan sebesar USD 55.499.915.582 dari 305.033 insiden di seluruh dunia antara Oktober 2013 dan Desember 2023 [S6], dan USD 3.046.598.558 dari 24.768 pengaduan pada 2025 saja, kategori kerugian terbesar kedua setelah penipuan investasi [S7]. Saran IC3 untuk mencegahnya adalah memverifikasi setiap perubahan data rekening lewat jalur kedua, memeriksa alamat pengirim dengan teliti, dan menampilkan alamat email lengkap (bukan hanya nama) di komputer karyawan [S6].

**Contoh di PT JAB:** email ke Rina adalah BEC jenis CEO fraud: Pak Hendra dijadikan topeng, sasarannya staf Keuangan. Bukan whaling, karena yang diserang bukan Pak Hendra. Bulan lalu Pak Hendra sendiri pernah menerima email "surat panggilan pengadilan" dengan lampiran yang meminta login; itu contoh whaling. Yang menyelamatkan Rina adalah aturan internal Keuangan: setiap perubahan rekening vendor dan setiap permintaan transfer di luar sistem pengadaan wajib dikonfirmasi lewat telepon ke nomor yang tercatat di direktori kantor atau data master vendor, bukan nomor di email.

**Beda dengan phishing kredensial:** phishing kredensial (seperti `INC-2026-020`) ingin password atau sesi login; BEC ingin uang atau data. Keduanya sering bersambung: akun yang dicuri lewat phishing kredensial dipakai untuk BEC dari dalam, karena email dari akun asli jauh lebih meyakinkan.

**Salah paham umum:**
- "BEC hanya mengincar perusahaan besar." Definisi IC3 justru menyebut bisnis maupun perorangan yang rutin bertransaksi dengan pemasok, di semua ukuran [S7].

Kenapa ini penting untuk security: BEC adalah serangan yang paling langsung berubah menjadi kerugian uang, dan sering lolos semua kontrol teknis karena tidak membawa malware. Kontrol yang paling efektif adalah proses bisnis (verifikasi lewat jalur kedua), dan SOC harus memperlakukan laporan BEC dengan cepat karena uang yang sudah ditransfer hanya bisa diupayakan kembali bila bank segera dihubungi [S6].

### 1.4 Smishing, vishing, dan quishing

Pertanyaan ketiga Sari menyangkut saluran selain email: SMS ke Dewi, PDF berisi kode QR, dan telepon. Penipuannya sama; salurannya berbeda.

**Apa itu:** smishing adalah social engineering lewat SMS atau pesan teks, biasanya berisi tautan yang membuka situs atau menelepon nomor tertentu saat disentuh [S3]. Vishing adalah social engineering lewat suara atau telepon, sering memakai caller ID palsu yang mudah dibuat lewat layanan VoIP (telepon lewat internet) [S3]. Quishing adalah phishing yang menyembunyikan tautan di kode QR; FBI IC3 mencatat penjahat mengganti kode QR asli, digital maupun fisik, dengan kode yang mengarah ke situs pencuri login dan data keuangan [S8].

**Analogi:** smishing adalah SMS "paket tertahan" dari kurir palsu. Vishing adalah telepon dari "petugas bank" yang meminta OTP. Quishing seperti stiker QR palsu yang ditempel di atas QR asli di meja kasir restoran: tampilannya sama, tujuannya lain. Batasnya: di dunia nyata kamu masih bisa melihat stiker yang menutupi kode asli, sedangkan di email atau PDF tidak ada "kode asli" untuk dibandingkan.

**Cara kerja:** tabel berikut membandingkan ketiganya; cari kolom "Kenapa sulit dideteksi" untuk memahami kenapa saluran ini makin disukai penyerang.

| Jenis | Saluran | Umpan khas | Kenapa sulit dideteksi |
|---|---|---|---|
| Smishing | SMS, WhatsApp, pesan teks | "Paket tertahan", "poin hadiah kedaluwarsa", "tagihan belum dibayar" | Masuk ke HP, sering HP pribadi, di luar filter email dan proxy kantor |
| Vishing | Telepon, voice note | "IT helpdesk butuh kode OTP", "petugas bank memblokir transaksi" | Tidak meninggalkan log di sistem kantor; caller ID bisa dipalsukan [S3] |
| Quishing | Kode QR di email, PDF, poster, stiker | "Pindai untuk verifikasi ulang MFA", "pindai untuk membayar" | Tautan berbentuk gambar, bukan teks; dipindai dengan HP yang di luar perlindungan kantor |

Saran IC3 untuk QR: periksa alamat situs setelah memindai karena domain palsu sering beda satu huruf, waspada saat diminta login atau data keuangan dari situs hasil pindaian, dan konfirmasi ke pengirim lewat jalur kontak yang sudah diketahui [S8].

**Contoh di PT JAB:** Rabu malam pukul 21:40, Dewi Lestari (Customer Service) menerima SMS "[KurirKita] Paket Anda tertahan karena alamat tidak lengkap. Perbarui dalam 24 jam:" dengan tautan ke `cek-paket-id.example`. Kamis pagi, email berisi PDF "Kebijakan MFA 2027" dengan kode QR "pindai untuk verifikasi ulang MFA" masuk ke 52 mailbox. Kamis siang, Dewi ditelepon seseorang yang mengaku "IT helpdesk" dan meminta kode OTP yang baru masuk ke HP-nya. Ketiganya dibahas utuh di bagian 2.3 dan 2.4.

**Beda dengan phishing email biasa:** pesannya sama-sama penipuan; yang berbeda adalah alat pertahanan mana yang melihatnya. Email melewati secure email gateway dan tercatat di log. SMS, telepon, dan QR yang dipindai HP pribadi hampir tidak terlihat oleh SOC, sehingga satu-satunya sensor adalah laporan user.

**Salah paham umum:**
- "Kode QR lebih aman daripada tautan karena tidak bisa diklik." Kode QR hanyalah tautan yang dibungkus gambar. Setelah dipindai, korban tetap dibawa ke situs yang sama berbahayanya, dan sering di HP yang tidak dilindungi kebijakan kantor.

Kenapa ini penting untuk security: penyerang memindahkan serangan ke saluran yang paling lemah pengawasannya. Bila SOC hanya memantau email, separuh cerita hilang. Kebijakan "IT tidak pernah meminta kode OTP lewat telepon" harus diumumkan berulang, supaya setiap permintaan seperti itu langsung dikenali sebagai penipuan.

### 1.5 Pretexting

Telepon ke Dewi tidak sekadar meminta OTP; penelepon membuka dengan cerita panjang. Cerita itulah yang disebut pretext.

**Apa itu:** pretexting adalah membangun skenario atau identitas karangan supaya permintaan terdengar wajar dan korban merasa sedang membantu proses resmi. Penyerang menyiapkan peran (petugas IT, auditor, vendor, polisi), alasan (migrasi sistem, audit, keadaan darurat), dan detail kecil yang membuat cerita meyakinkan. Ini bukan saluran tersendiri, melainkan teknik yang dipakai di email, SMS, telepon, dan tatap muka; definisi NIST tentang social engineering yang menyebut membangun hubungan dan rasa percaya menggambarkan inti teknik ini [S1].

**Analogi:** penipu yang mengaku petugas PLN dan perlu masuk rumah untuk "cek meteran". Ia memakai rompi, membawa papan klip, dan menyebut nama pelanggan. Yang membuat pintu dibuka bukan seragamnya, melainkan cerita yang cocok dengan hal yang memang biasa terjadi. Batasnya: di telepon dan email, penyerang tidak perlu kostum; cukup nama yang benar, istilah internal, dan nomor yang tampak resmi.

**Cara kerja:** pretext yang baik memakai informasi yang benar untuk menyelundupkan permintaan yang salah. Penelepon ke Dewi menyebut nama lengkap Dewi, unit kerjanya, dan nama aplikasi tiket internal yang memang dipakai CS, lalu berkata akun Dewi "sedang dipindahkan ke server baru" dan "akan terkunci bila verifikasi tidak selesai lima menit lagi". Semua detail pertama benar dan mudah dicari dari profil media sosial; permintaan terakhir (kode OTP) adalah tujuannya.

**Contoh di PT JAB:** email ke Rina juga memakai pretext: pengadaan perangkat core router memang sedang berjalan, dan nama vendor baru "PT Mitra Jaringan Prima" terdengar wajar. Penyerang kemungkinan mendapat informasi proyek dari lowongan kerja dan unggahan media sosial karyawan yang menyebut "upgrade core network".

**Beda dengan phishing:** phishing adalah bentuk serangannya (pesan palsu); pretexting adalah cerita di dalamnya. Phishing massal sering memakai pretext umum ("password kedaluwarsa"), spear phishing dan vishing memakai pretext yang sangat spesifik.

Kenapa ini penting untuk security: pretext yang memakai informasi benar membuat korban mengira penelepon "orang dalam". Pertahanannya adalah prosedur yang tidak bisa ditawar oleh cerita apa pun: kode OTP tidak pernah dibagikan ke siapa pun, dan permintaan yang tidak biasa selalu diverifikasi dengan menelepon balik ke nomor resmi.

### 1.6 Header email: envelope vs header From, Return-Path, Received, Message-ID, Authentication-Results

Pertanyaan keempat Sari: kenapa nama "Hendra Wijaya" bisa muncul padahal bukan dia? Jawabannya ada di cara email dibangun.

**Apa itu:** setiap email punya dua lapis informasi pengirim. Lapis pertama adalah envelope (amplop pengiriman), yaitu data yang dipertukarkan antarserver lewat protokol SMTP (Simple Mail Transfer Protocol, protokol pengiriman email antarserver di port 25, dibahas singkat di Day 02): alamat pengirim di perintah `MAIL FROM` dan alamat penerima di `RCPT TO` [S9]. Lapis kedua adalah isi pesan, yang terdiri dari header (baris-baris seperti `From:`, `To:`, `Subject:`, `Date:`) dan body (isi surat) [S9][S10]. Aplikasi email menampilkan header From, bukan envelope; envelope dipakai untuk mengantar dan untuk mengirim laporan gagal kirim [S9][S15].

**Analogi:** header From adalah nama pengirim yang ditulis di depan amplop: siapa saja bisa menulis nama apa saja. Envelope adalah data pengiriman yang dicatat kantor pos saat surat diserahkan: siapa yang menyerahkan, dari loket mana. Received adalah cap pos dari setiap kantor pos yang dilewati, Message-ID adalah nomor resi, dan Return-Path adalah alamat pengembalian bila surat tidak sampai. Batasnya: di email, "data kantor pos" pun sebagian ditulis oleh pengirim; hanya catatan yang dibuat server yang kamu percaya (server penerima milik organisasimu) yang benar-benar bisa dipegang.

**Cara kerja:** tabel berikut merangkum field header yang paling sering dibaca analyst. Cari kolom "Siapa yang menulis", karena itu yang menentukan seberapa jauh field bisa dipercaya.

| Field | Isi | Siapa yang menulis | Bisa dipercaya? |
|---|---|---|---|
| `From` | Nama tampilan dan alamat penulis pesan [S10] | Pengirim | Tidak dengan sendirinya; diperiksa lewat DMARC |
| `Reply-To` | Alamat tujuan balasan; bila kosong, balasan ke From [S10] | Pengirim | Tidak; sering dipakai BEC untuk membelokkan balasan |
| `To`, `Subject`, `Date` | Penerima, judul, waktu tulis dengan zona waktu (`+0700`, `+0000`) [S10] | Pengirim | Tidak; jam pengirim bisa salah atau dikarang |
| `Message-ID` | Nomor unik pesan, tanggung jawab host pembuatnya [S10] | Server atau aplikasi pengirim | Berguna untuk mencari pesan yang sama di semua mailbox |
| `Return-Path` | Alamat envelope (`MAIL FROM`), dicatat server tujuan akhir [S9] | Server tujuan akhir, dari data envelope | Mencerminkan envelope, bukan bukti pengirim jujur |
| `Received` | Satu baris per server: dari siapa (nama dan IP), oleh siapa, kapan [S9] | Setiap server yang dilewati, ditambahkan di paling atas | Hanya baris dari server milikmu atau penyedia tepercaya |
| `Authentication-Results` | Hasil SPF, DKIM, DMARC dari server penerima [S14] | Server penerima | Hanya yang ditulis server penerima milikmu [S14] |
| `DKIM-Signature` | Tanda tangan digital domain pengirim (bagian 1.8) [S12] | Server pengirim | Dibuktikan lewat pemeriksaan kunci, bukan dibaca begitu saja |

Beberapa aturan membaca header:

- **Baca Received dari bawah ke atas.** Setiap server menambahkan baris Received di paling atas dan tidak boleh mengubah baris yang sudah ada [S9]. Baris paling bawah adalah yang paling awal, baris paling atas adalah hop terakhir sebelum sampai ke mailbox. Waktu di setiap baris dicatat dengan zona waktunya sendiri, sering UTC (`+0000`); tambahkan tujuh jam untuk WIB.
- **Cari baris Received pertama yang ditulis server tepercaya.** Baris itu menyebut IP yang benar-benar menyerahkan email ke organisasimu. Baris di bawahnya ditulis sebelum email sampai ke server yang kamu kendalikan, sehingga bisa saja dikarang pengirim.
- **Bandingkan tiga alamat:** domain di `From` (yang dilihat user), domain di `Return-Path` atau `smtp.mailfrom` (envelope), dan domain di `Reply-To`. Microsoft memberi contoh klasik spoofing: envelope dari satu domain, From dari domain bank yang ditiru [S15].
- **Authentication-Results hanya dipercaya bila ditulis server penerima milikmu.** RFC 8601 mewajibkan server penerima menghapus header Authentication-Results yang mengaku dari dirinya tetapi datang dari luar, karena header ini bisa dipalsukan pengirim [S14]. RFC yang sama mengingatkan bahwa hasil "pass" tidak membuat pesan layak dipercaya; spammer pun bisa menandatangani spam dengan DKIM yang sah [S14].

**Contoh di PT JAB:** di email ke Rina, header From berbunyi `"Hendra Wijaya" <hendra.wijaya@jab-direksi.example>`. Outlook di laptop Rina menampilkan nama "Hendra Wijaya" dengan jelas, dan foto profil Pak Hendra muncul karena Outlook mencocokkan nama tampilan dengan kontak yang mirip di buku alamat (fitur tampilan aplikasi, bukan bukti identitas). Alamat sesungguhnya memakai domain `jab-direksi.example`, bukan `jab.example`. `Reply-To` mengarah ke `hendra.wijaya.jab@freemail.example`, layanan webmail gratis. Header lengkapnya dibaca di bagian 2.1.

**Beda dengan display name spoofing:** pada email ke Rina, penyerang memakai domain mirip. Variasi yang lebih sederhana adalah display name spoofing: nama tampilan "Hendra Wijaya" dipasang di depan alamat webmail gratis seperti `hendra.wijaya.jab@freemail.example`. Di HP, banyak aplikasi email hanya menampilkan nama tampilan, sehingga alamatnya tidak terlihat sama sekali. Itu sebabnya IC3 menyarankan pengaturan yang menampilkan alamat email lengkap [S6].

**Salah paham umum:**
- "Nama dan foto pengirim yang benar membuktikan emailnya asli." Nama tampilan ditulis pengirim, dan foto ditampilkan aplikasi berdasarkan nama atau alamat yang mirip. Yang dibuktikan secara teknis hanyalah domain, dan itu pun lewat DMARC (bagian 1.9).

Kenapa ini penting untuk security: membaca header adalah langkah pertama setiap analisis email. Dari header kamu tahu IP dan server asal yang sebenarnya, domain mana yang dipakai di setiap lapis, dan hasil pemeriksaan autentikasi. Message-ID dan domain pengirim juga menjadi kunci pencarian untuk menemukan salinan email yang sama di mailbox lain.

### 1.7 SPF

Pertanyaan kelima Sari: domain PT JAB sudah memasang SPF, DKIM, dan DMARC, jadi kenapa email "dari direktur" lolos? Kita mulai dari SPF.

**Apa itu:** SPF (Sender Policy Framework) adalah cara pemilik domain mengumumkan, lewat record TXT di DNS (sistem yang menerjemahkan nama domain menjadi data, termasuk IP; dibahas di Day 02 bagian 1.9), daftar server yang boleh mengirim email atas nama domain itu [S11]. Server penerima memeriksa IP pengirim terhadap record SPF milik domain di envelope (`MAIL FROM`) dan nama di perintah `HELO`, bukan domain di header From [S11].

**Analogi:** daftar kantor pos resmi yang boleh mengirim surat atas nama perusahaan. Saat surat tiba, kantor pos penerima melihat dari kantor pos mana surat dikirim, lalu mencocokkannya dengan daftar yang diumumkan perusahaan. Batasnya: yang dicocokkan adalah nama perusahaan di data pengiriman kantor pos (envelope), bukan nama yang ditulis di depan amplop. Penipu bisa memakai daftar kantor pos milik perusahaan palsunya sendiri, lalu menulis nama perusahaan lain di amplop.

**Cara kerja:** record SPF diawali `v=spf1`, lalu berisi mekanisme yang menyebut sumber sah, dan diakhiri aturan untuk sumber lain [S11]:

```
jab.example.  IN  TXT  "v=spf1 ip4:198.51.100.11 include:spf.protection.outlook.com -all"
                        |      |                  |                                |
                        |      |                  |                                +-- -all: selain yang di atas, gagal (fail)
                        |      |                  +-- server Microsoft 365 boleh mengirim
                        |      +-- satu IP server mail lama PT JAB boleh mengirim
                        +-- penanda versi SPF
```

Mekanisme yang umum adalah `ip4`, `ip6`, `a`, `mx`, `include`, dan `all`; awalan `-` berarti fail, `~` softfail, `?` neutral, dan tanpa awalan berarti pass [S11]. Hasil pemeriksaan SPF adalah salah satu dari tujuh nilai berikut; cari kolom "Artinya" saat membaca `spf=` di header.

| Hasil | Artinya [S11] |
|---|---|
| `pass` | IP pengirim termasuk sumber sah domain itu |
| `fail` | Domain menyatakan tegas IP ini tidak sah (`-all`) |
| `softfail` | Domain menyatakan IP ini mungkin tidak sah, tanpa ketegasan (`~all`) |
| `neutral` | Domain tidak menyatakan apa-apa tentang IP ini (`?all`) |
| `none` | Domain tidak punya record SPF |
| `temperror` | Kesalahan sementara, biasanya DNS; bisa berhasil bila dicoba ulang |
| `permerror` | Record SPF rusak, misalnya lebih dari 10 pencarian DNS |

Mekanisme yang memicu pencarian DNS (`include`, `a`, `mx`, `exists`, `redirect`) dibatasi 10 per pemeriksaan; lebih dari itu hasilnya permerror [S11][S25]. Microsoft menyarankan `include:spf.protection.outlook.com` untuk domain yang mengirim lewat Microsoft 365, dan `-all` bila DKIM dan DMARC juga dipasang [S25].

**Contoh di PT JAB:** Record SPF `jab.example` yang juga muncul di Day 02 bagian 2.3 memuat dua sumber sah: server mail lama (`mail.jab.example`, sekarang hanya dipakai aplikasi internal untuk mengirim notifikasi) ditambah Microsoft 365. Untuk email ke Rina, SPF diperiksa terhadap domain envelope `jab-direksi.example` milik penyerang. Penyerang memasang record SPF yang mengizinkan servernya sendiri, `192.0.2.161`, sehingga hasilnya `spf=pass`. SPF bekerja dengan benar; ia hanya menjawab pertanyaan yang berbeda dari yang dikira user.

**Beda dengan DKIM:** SPF memeriksa dari server mana email dikirim; DKIM memeriksa apakah isi email ditandatangani domain tertentu dan tidak berubah di jalan (bagian 1.8).

**Salah paham umum:**
- "SPF pass berarti alamat From asli." SPF hanya mengotorisasi identitas `MAIL FROM` dan `HELO`; RFC 7208 menegaskan hasil itu tidak menjamin identitas lain di pesan [S11]. Microsoft memberi contoh penyerang yang mendaftarkan domain sendiri, memasang SPF, lalu memakai domain lain di From, dan lolos SPF [S15].
- "SPF selalu stabil." Email yang diteruskan (forwarding) oleh server lain sering gagal SPF karena yang diperiksa adalah IP server penerus, yang tidak tercantum di record domain asal [S11][S15].

Kenapa ini penting untuk security: SPF mencegah server mana pun di internet memakai domain PT JAB di envelope tanpa izin, dan menjadi salah satu dari dua bahan DMARC. Tetapi SPF sendirian tidak melindungi nama yang dilihat user.

### 1.8 DKIM

Hasil kedua di header email ke Rina adalah `dkim=pass`. DKIM adalah segel di email, dan segel itu milik penyerang.

**Apa itu:** DKIM (DomainKeys Identified Mail) adalah cara sebuah domain menyatakan bertanggung jawab atas sebuah email dengan menempelkan tanda tangan digital di header `DKIM-Signature` [S12]. Tanda tangan digital (dibahas di Day 05) adalah nilai yang dihitung dari isi pesan memakai private key (kunci rahasia) pengirim, dan bisa diperiksa siapa pun memakai public key (kunci publik) pasangannya; bila isi diubah, pemeriksaan gagal. Kunci publik domain dipasang di DNS sebagai record TXT di nama `<selector>._domainkey.<domain>` [S12].

**Analogi:** segel atau cap resmi yang ditempel di surat. Kantor pos penerima mencocokkan segel dengan contoh segel yang diumumkan perusahaan; bila segel utuh, surat tidak dibuka dan tidak diubah di jalan. Batasnya: segel menunjukkan perusahaan mana yang menempelkannya, bukan bahwa perusahaan itu sama dengan nama yang ditulis di depan amplop. Penipu bisa membuat perusahaan sendiri, membuat segel sendiri, dan segelnya akan dinyatakan utuh.

**Cara kerja:** server pengirim menghitung sidik jari (hash, dibahas di Day 05) dari body dan dari header terpilih, lalu menandatanganinya dengan private key, dan menulis hasilnya di header `DKIM-Signature` [S12]. Tag yang paling sering dibaca analyst:

- `d=`: domain penanda tangan, yaitu domain yang bertanggung jawab [S12];
- `s=`: selector, nama kunci yang dipakai, karena satu domain bisa punya beberapa kunci [S12];
- `h=`: daftar header yang ikut ditandatangani [S12];
- `bh=` dan `b=`: hash body dan nilai tanda tangan [S12].

Server penerima mengambil kunci publik dari `s._domainkey.d` di DNS, menghitung ulang, lalu menulis `dkim=pass` atau `dkim=fail` di Authentication-Results. RFC 6376 menegaskan dua hal: domain di `d=` tidak wajib sama dengan alamat di header mana pun, dan DKIM tidak menilai apakah pesan baik atau spam; gagal verifikasi pun tidak memaksa pesan ditolak [S12].

**Contoh di PT JAB:** email ke Rina membawa `DKIM-Signature` dengan `d=jab-direksi.example; s=mail2027`. Kunci publiknya ada di `mail2027._domainkey.jab-direksi.example`, dipasang penyerang sendiri. Hasilnya `dkim=pass header.d=jab-direksi.example`: segelnya utuh, dan memang milik domain penyerang. Email karyawan PT JAB yang asli ditandatangani Microsoft 365 dengan `d=jab.example`.

**Beda dengan enkripsi email:** DKIM tidak menyembunyikan isi; siapa pun di jalur tetap bisa membaca email (kecuali sambungan antarserver memakai TLS, enkripsi jalur yang dibahas di Day 05). DKIM hanya membuktikan siapa yang menandatangani dan bahwa bagian yang ditandatangani tidak berubah.

**Salah paham umum:**
- "DKIM pass berarti emailnya aman." DKIM pass hanya berarti domain di `d=` menandatanganinya dan isinya utuh. Microsoft memberi contoh penyerang yang mendaftarkan domain, memasang DKIM, lalu memakai domain lain di From, dan tetap lolos DKIM [S15].

Kenapa ini penting untuk security: berbeda dengan SPF, tanda tangan DKIM tetap utuh saat email diteruskan, selama isinya tidak diubah [S12][S15]. Karena itu DKIM menjadi bahan DMARC yang lebih tahan terhadap forwarding.

### 1.9 DMARC

DMARC adalah satu-satunya dari tiga mekanisme ini yang melihat alamat From yang dilihat user. Itu sebabnya domain PT JAB terlindungi, tetapi email ke Rina tetap lolos.

**Apa itu:** DMARC (Domain-based Message Authentication, Reporting, and Conformance) memungkinkan pemilik domain memasang record TXT di `_dmarc.<domain>` yang menyatakan tiga hal: email yang memakai domain ini di header From harus lolos SPF atau DKIM dengan domain yang cocok (aligned), apa yang sebaiknya dilakukan penerima terhadap email yang gagal, dan ke mana laporan dikirim [S13]. Domain yang diperiksa DMARC adalah Author Domain, yaitu domain di header From [S13]. Sejak Mei 2026, DMARC didefinisikan RFC 9989 (Proposed Standard), yang menggantikan RFC 7489 dari 2015; format laporan agregat ada di RFC 9990 dan laporan kegagalan di RFC 9991 [S13].

**Analogi:** instruksi tertulis perusahaan ke semua kantor pos: "Surat yang memakai nama kami di depan amplop harus dikirim dari kantor pos resmi kami atau membawa segel kami. Bila tidak, tolak. Setiap hari, kirimi kami rekap surat atas nama kami yang kalian terima." Batasnya: instruksi ini hanya berlaku untuk nama perusahaan yang persis sama. Surat atas nama "PT JAB Direksi" tidak terkena instruksi PT JAB; ia tunduk pada instruksi "PT JAB Direksi", yang dibuat penipu sendiri.

**Cara kerja:** DMARC lolos bila minimal satu dari dua syarat terpenuhi [S13]:

1. SPF pass, dan domain envelope (`MAIL FROM`) cocok dengan domain From; atau
2. DKIM pass, dan domain `d=` cocok dengan domain From.

Kecocokan (alignment) punya dua mode. Mode relaxed (bawaan) menerima domain yang punya Organizational Domain sama, misalnya `mail.jab.example` dan `jab.example`. Mode strict menuntut domain identik [S13]. Kebijakan ditulis di tag `p`:

| Tag dan nilai | Artinya [S13] |
|---|---|
| `p=none` | Pemilik domain tidak meminta tindakan; dipakai untuk memantau lewat laporan |
| `p=quarantine` | Email yang gagal dianggap mencurigakan, misalnya dipindah ke Junk atau karantina |
| `p=reject` | Email yang gagal dianggap jelas tidak sah dan sebaiknya ditolak |
| `sp=` dan `np=` | Kebijakan untuk subdomain yang ada dan subdomain yang tidak ada |
| `rua=` | Alamat penerima laporan agregat (rekap harian) |
| `ruf=` | Alamat penerima laporan kegagalan per pesan |
| `adkim=`, `aspf=` | Mode alignment untuk DKIM dan SPF (`r` relaxed, `s` strict) |
| `t=y` | Mode uji: penerima diminta menerapkan satu tingkat lebih lunak |

Penerima tetap yang memutuskan tindakan akhir. Microsoft 365, misalnya, punya pengaturan "Honor DMARC record policy" yang menentukan apakah `p=quarantine` dan `p=reject` dari domain pengirim dituruti, dan tindakan apa yang dipakai [S16]. Microsoft juga memakai composite authentication (`compauth`), gabungan hasil SPF, DKIM, DMARC, dan sinyal lain seperti reputasi, yang ditulis di Authentication-Results [S15][S17].

**Contoh di PT JAB:** record DMARC `jab.example` adalah `v=DMARC1; p=reject; rua=mailto:dmarc-rua@jab.example`. Artinya, email yang memakai `@jab.example` di From tetapi tidak lolos SPF atau DKIM yang aligned akan ditolak oleh penerima yang menuruti DMARC, termasuk Microsoft 365 milik PT JAB sendiri. Penyerang tahu itu, jadi ia tidak memalsukan `jab.example`; ia memakai `jab-direksi.example` dan memasang DMARC sendiri dengan `p=none`. Di email ke Rina, domain From, domain envelope, dan domain DKIM semuanya `jab-direksi.example`, sehingga alignment sempurna dan hasilnya `dmarc=pass`. Bagian 2.2 memperlihatkan email lain hari yang sama yang memalsukan `jab.example` persis, dan bagaimana DMARC menghentikannya.

**Beda dengan SPF dan DKIM:** SPF dan DKIM masing-masing menjawab "domain mana yang terbukti?"; DMARC menjawab "apakah domain yang terbukti itu sama dengan domain yang dilihat user, dan apa yang harus dilakukan bila tidak?". Tanpa DMARC, SPF dan DKIM bisa lolos untuk domain penyerang sementara user melihat domain lain [S15].

**Salah paham umum:**
- "DMARC p=reject di domain kita melindungi karyawan dari semua email palsu atas nama direksi." DMARC hanya melindungi domain yang persis tertulis. Ia tidak melindungi dari domain mirip, nama tampilan palsu, atau akun asli yang dibobol. Microsoft menyebut peniruan dengan domain mirip yang memasang record autentikasi sah bisa lolos SPF, DKIM, dan DMARC [S16].
- "DMARC pass berarti email aman." RFC 9989 menegaskan DMARC pass hanya menunjukkan pemilik domain mengizinkan pemakaian domainnya, bukan bahwa pesannya aman [S13].

Kenapa ini penting untuk security: DMARC `p=reject` membuat penipu tidak bisa memakai `@jab.example` persis untuk menipu pelanggan, mitra, maupun karyawan PT JAB sendiri. Laporan DMARC juga memperlihatkan siapa saja di internet yang mencoba memakai nama domain PT JAB (bagian 2.2). Akibatnya penyerang terdorong memakai domain mirip, dan perlindungan untuk itu harus datang dari lapisan lain: secure email gateway dan manusia.

### 1.10 Secure email gateway (dan Defender for Office 365)

Pertanyaan keenam Sari: PT JAB membayar Defender for Office 365 Plan 2, jadi kenapa email ini tetap sampai ke Inbox Rina?

**Apa itu:** secure email gateway (SEG) adalah sistem yang memeriksa semua email masuk (dan biasanya keluar) sebelum sampai ke mailbox: spam, malware, phishing, tautan berbahaya, peniruan, dan pelanggaran kebijakan. Model klasik dipasang di jalur pengiriman dengan mengubah record MX (record DNS yang menunjuk server penerima email domain, Day 02 bagian 1.9) ke gateway, atau lewat konektor dan aturan alur email di layanan email cloud; model yang lebih baru membaca mailbox lewat API setelah email terkirim [S23]. Di Microsoft 365, perlindungan bawaan (anti-malware, anti-spam, anti-spoofing, karantina, ZAP) sudah ada di semua mailbox cloud; Defender for Office 365 Plan 1 menambah perlindungan peniruan (impersonation), Safe Links, dan Safe Attachments, dan Plan 2 menambah alat investigasi seperti Threat Explorer, simulasi phishing, dan investigasi otomatis (AIR) [S18].

**Analogi:** ruang sortir surat di gedung kantor. Semua surat masuk lewat ruang ini; petugas memeriksa segel dan asal surat, membuang brosur, menahan paket mencurigakan untuk dibuka di ruang khusus, dan mencatat semua yang lewat. Bila belakangan ternyata sebuah surat palsu, petugas bisa mengambilnya kembali dari meja karyawan. Batasnya: petugas sortir hanya bisa menahan surat yang terlihat mencurigakan. Surat sopan tanpa lampiran dari "perusahaan" yang segelnya sah, berisi permintaan transfer, terlihat seperti surat bisnis biasa.

**Cara kerja:** fungsi utama gateway dan padanannya di Defender for Office 365 dirangkum di tabel berikut; cari kolom "Tidak menangkap" untuk memahami celah yang tersisa.

| Fungsi | Di Defender for Office 365 | Menangkap | Tidak menangkap |
|---|---|---|---|
| Autentikasi pengirim | Anti-spoofing, compauth, Honor DMARC [S15][S16] | Pemalsuan domain persis | Domain mirip yang punya SPF/DKIM/DMARC sah |
| Peniruan (impersonation) | Perlindungan user dan domain, mailbox intelligence [S16] | Nama dan domain yang mirip orang atau domain yang dilindungi | Orang yang tidak dimasukkan ke daftar perlindungan |
| Tautan | Safe Links: periksa sebelum kirim dan saat diklik [S19] | URL yang dikenal atau terdeteksi berbahaya | Tautan yang baru berbahaya setelah dicek, tautan di gambar atau QR yang tidak terbaca |
| Lampiran | Safe Attachments: dibuka di lingkungan virtual sebelum dikirim (detonation) [S20] | Malware yang berperilaku jahat saat dibuka | Lampiran berpassword yang tidak bisa dibuka, file yang menunda perilaku jahatnya |
| Penarikan setelah kirim | ZAP [S18] | Email yang belakangan dinilai berbahaya | Email yang sudah dibuka dan ditindaklanjuti user |
| Laporan user | Tombol Report, User reported settings [S21] | Apa pun yang dicurigai manusia | Hanya bila user melapor |

Safe Links menulis ulang tautan supaya setiap klik melewati pemeriksaan Microsoft lebih dulu, dan URL yang reputasinya belum jelas diperiksa di latar belakang [S19]. Safe Attachments membuka lampiran di lingkungan virtual sebelum email dikirim, biasanya selesai dalam 15 menit; mode Dynamic Delivery mengirim body lebih dulu dengan penanda di tempat lampiran sampai pemeriksaan selesai [S20]. Perlindungan peniruan user hanya bekerja untuk alamat yang dimasukkan ke daftar "users to protect", maksimal 350 per kebijakan, dan default-nya kosong [S16].

**Contoh di PT JAB:** email ke Rina tidak membawa tautan atau lampiran, jadi Safe Links dan Safe Attachments tidak punya bahan. SPF, DKIM, dan DMARC semuanya pass untuk domain penyerang. Daftar "users to protect" di kebijakan anti-phishing PT JAB baru berisi Direktur Utama dan Direktur Keuangan; Pak Hendra belum masuk, sehingga perlindungan peniruan user tidak memeriksanya. Satu-satunya tanda dari Defender adalah first contact safety tip, pesan "You don't often get email from ..." di atas email, karena Rina belum pernah menerima email dari alamat itu [S16][S17]. Hasil review Sari: Pak Hendra dan semua direktur lain dimasukkan ke daftar perlindungan, dan domain `jab-direksi.example` diblokir di Tenant Allow/Block List.

**Beda dengan firewall dan proxy:** firewall (penjaga gerbang yang memeriksa alamat dan port, dibahas di Day 03) melihat sambungan SMTP sebagai lalu lintas biasa ke port 25. Proxy web (perantara akses web karyawan, juga di Day 03) hanya melihat tautan yang benar-benar diklik dari jaringan kantor. Gateway email adalah satu-satunya yang membaca header, isi, tautan, dan lampiran email secara utuh.

**Salah paham umum:**
- "Gateway yang bagus menangkap semua phishing." Microsoft sendiri menyebut kegagalan composite authentication tidak otomatis memblokir pesan, dan peniruan dengan domain mirip bisa lolos semua pemeriksaan autentikasi [S15][S16]. Gateway mengurangi volume; ia tidak menghapus kebutuhan akan verifikasi manusia.

Kenapa ini penting untuk security: analyst perlu tahu lapisan mana yang bekerja dan mana yang tidak untuk setiap email yang lolos. Pertanyaan "kenapa lolos?" sering berujung pada perbaikan konfigurasi yang nyata, seperti daftar perlindungan peniruan yang belum lengkap.

### 1.11 URL dan lampiran berbahaya (termasuk QR dan AiTM)

Pertanyaan ketujuh Sari menyangkut dua muatan klasik phishing: tautan dan lampiran. Email PDF berisi QR pagi ini memakai keduanya.

**Apa itu:** URL berbahaya adalah tautan yang membawa korban ke halaman palsu (biasanya halaman login tiruan), ke unduhan malware (program jahat, jenisnya dibahas di Day 16), atau ke rangkaian pengalihan yang berakhir di salah satunya. Lampiran berbahaya adalah file yang dirancang untuk menjalankan kode jahat saat dibuka (dokumen dengan makro, skrip, file pintasan, arsip berisi program) atau untuk membawa korban ke URL berbahaya (PDF atau HTML berisi tautan atau kode QR). MITRE ATT&CK memisahkan keduanya menjadi T1566.001 (lampiran) dan T1566.002 (tautan) [S4].

**Analogi:** URL berbahaya seperti alamat kantor cabang palsu di brosur bank: papan namanya mirip, loketnya mirip, tetapi semua formulir yang kamu isi dibaca penipu. Lampiran berbahaya seperti paket yang dikirim ke kantor; begitu dibuka, isinya bekerja. Batasnya: alamat palsu di internet bisa dibuat dalam beberapa menit dan berganti setiap hari, dan "paket" digital bisa terlihat seperti dokumen biasa sampai detik ia dibuka.

**Cara kerja:** tanda URL berbahaya yang paling sering muncul:

- Domain mirip (lookalike): huruf ditukar, ditambah, atau diganti karakter yang bentuknya serupa (`ćóntoso` untuk `contoso`, contoh dari Microsoft) [S16], atau kata tambahan seperti `jab-direksi`, `login-jab-verify`.
- Teks tautan yang berbeda dengan alamat sesungguhnya; CISA menyebut tautan yang tidak cocok dengan teks yang ditampilkan sebagai tanda peringatan [S3].
- Domain yang baru didaftarkan beberapa hari sebelumnya.
- HTTPS dan ikon gembok tidak membuktikan apa-apa tentang pemilik situs; Day 02 bagian 1.10 menjelaskan bahwa situs phishing juga bisa memakai sertifikat sah.

AiTM (adversary-in-the-middle) adalah bentuk halaman phishing yang lebih maju. Halaman palsu bekerja sebagai perantara (proxy) antara korban dan halaman login asli: semua yang diketik korban diteruskan ke situs asli, jawaban situs asli diteruskan ke korban, sehingga tampilannya identik dan MFA (verifikasi tambahan seperti kode atau persetujuan di HP, dibahas di Day 06) pun benar-benar terjadi [S22]. Setelah login berhasil, penyerang menyalin session cookie, yaitu "tiket" kecil yang disimpan browser sebagai bukti sudah login, lalu memakainya untuk masuk tanpa perlu password atau MFA lagi [S22]. Microsoft menegaskan ini bukan celah di MFA: yang dicuri adalah sesi setelah MFA selesai [S22]. Kampanye yang dilaporkan Microsoft pada 2022 mencoba menyasar lebih dari 10.000 organisasi sejak September 2021 dan berlanjut ke BEC: penyerang membaca mailbox, membuat aturan inbox untuk menyembunyikan balasan, lalu mengirim permintaan pembayaran palsu di utas percakapan yang asli [S22]. Pencurian sesi semacam ini dibahas lebih luas di Day 15.

```
 Korban (browser)        Halaman AiTM penyerang              Halaman login asli
      |  username, password  ->  |  -- diteruskan -->               |
      |  <- minta MFA ------------|  <-- minta MFA ---               |
      |  setujui MFA ---------->  |  -- diteruskan -->               |
      |                           |  <-- session cookie ------------ |
      |  <- "login berhasil" ---- |  (cookie disalin penyerang)      |
                                  penyerang masuk memakai cookie, tanpa password dan MFA
```

**Contoh di PT JAB:** PDF "Kebijakan MFA 2027" di `SOC-2027-0851` berisi kode QR yang mengarah ke `login-jab-verify.example`, halaman AiTM yang meniru login Microsoft 365 PT JAB, di `192.0.2.163`. Pelajaran dari `INC-2026-022` (pencurian sesi yang melewati MFA, akhir 2026) membuat SOC PT JAB langsung memeriksa sign-in log untuk setiap penerima. Rinciannya di bagian 2.3.

**Beda dengan phishing kredensial biasa:** halaman phishing biasa hanya mengumpulkan password; MFA masih menghentikan penyerang. Halaman AiTM mencuri sesi yang sudah lolos MFA, sehingga satu-satunya pertahanan yang benar-benar menutup celah ini adalah metode MFA yang tahan phishing (misalnya kunci FIDO2 atau autentikasi berbasis sertifikat) dan kebijakan akses bersyarat yang membatasi pemakaian sesi curian [S22].

**Salah paham umum:**
- "Kalau user tidak memasukkan password, mengklik tautan tidak berbahaya." Tautan bisa langsung mengunduh file atau membawa ke halaman yang memanfaatkan celah browser. Klik saja sudah layak diperiksa, walaupun tingkat risikonya lebih rendah daripada memasukkan password atau menjalankan file.

Kenapa ini penting untuk security: tautan dan lampiran adalah titik di mana social engineering berubah menjadi akses teknis. Untuk SOC, setiap laporan phishing berisi URL harus dijawab dengan tiga pertanyaan: siapa saja yang menerima, siapa yang mengklik, dan siapa yang memasukkan kredensial atau menjalankan file.

### 1.12 Pelaporan phishing oleh user

Pertanyaan terakhir Sari: email yang sama dikirim ke tiga staf Keuangan, filter tidak menangkapnya, dan hanya Rina yang melapor. Kenapa satu laporan itu sangat berharga?

**Apa itu:** pelaporan phishing oleh user adalah mekanisme yang membuat karyawan bisa mengirim email mencurigakan ke tim keamanan dengan satu klik, sehingga email itu bisa dianalisis, dicari salinannya, dan ditarik dari mailbox lain. Di Microsoft 365, tombol Report bawaan Outlook mengirim pesan yang dilaporkan ke Microsoft, ke reporting mailbox organisasi, atau ke keduanya, sesuai User reported settings [S21]. Microsoft juga menyediakan alert policy "Email reported by user as malware or phish" yang harus aktif agar laporan bisa memicu investigasi [S21].

**Analogi:** tetangga yang melapor ke satpam kompleks: "Ada orang mengaku petugas PDAM mengetuk rumah-rumah di blok C." Satpam tidak bisa melihat semua pintu sekaligus, tetapi satu laporan membuatnya bisa memperingatkan seluruh blok dan berjaga di gerbang. Batasnya: laporan tetangga hanya berguna bila satpam menanggapinya dengan cepat dan tetangga tidak takut ditegur saat laporannya ternyata keliru.

**Cara kerja:** di PT JAB, alurnya seperti ini:

```
 user klik Report di Outlook
        |
        v
 salinan ke phishing-report@jab.example (+ ke Microsoft untuk analisis)
        |
        v
 alert di antrean SOC (mis. SOC-2027-0848)
        |
        v
 analyst: baca header, cek domain dan URL, cari pesan serupa di semua mailbox
        |
        +--> berbahaya: tarik semua salinan, blokir pengirim/domain/URL, cek siapa yang klik atau membalas
        +--> aman: tutup, beri tahu user hasilnya dan terima kasih
```

Laporan user mengisi celah yang tidak bisa ditutup filter: email tanpa tautan dan lampiran (BEC), domain mirip yang lolos autentikasi, serta saluran di luar email seperti SMS dan telepon. Laporan juga cepat; user biasanya melapor beberapa menit setelah email tiba, sebelum penerima lain sempat bertindak. Microsoft menyediakan opsi agar user otomatis menerima hasil investigasi lewat email bila memakai AIR di Plan 2 [S21], dan umpan balik semacam ini menjaga kebiasaan melapor.

**Contoh di PT JAB:** Rina melapor pukul 08:52, 21 menit setelah email tiba. Dari laporannya, Sari mencari di Threat Explorer (alat penelusuran email di Defender for Office 365 Plan 2) [S18] semua pesan dari domain `jab-direksi.example`: ada tiga, ke tiga staf Keuangan. Satu staf belum membuka emailnya, staf lain sudah membuka tetapi belum membalas. Kedua salinan itu ditarik dari mailbox, domain diblokir, dan Keuangan diberi peringatan. Bila tidak ada laporan, satu-satunya jejak adalah first contact safety tip yang tidak menimbulkan alert apa pun.

**Beda dengan simulasi phishing:** simulasi phishing (Attack simulation training di Plan 2 [S18]) adalah email palsu buatan tim keamanan untuk melatih karyawan. Laporan user adalah hasil yang diharapkan dari pelatihan itu. Ukuran keberhasilan program bukan hanya berapa sedikit yang mengklik, tetapi juga berapa banyak dan seberapa cepat yang melapor.

**Salah paham umum:**
- "Kalau user ragu, lebih baik tidak melapor supaya SOC tidak terbebani." SOC lebih suka menutup sepuluh laporan aman daripada melewatkan satu BEC. Mengatakan "terima kasih, ini aman" adalah bagian dari pekerjaan, dan menegur pelapor membuat orang berhenti melapor.

Kenapa ini penting untuk security: laporan user adalah sensor yang paling murah dan paling sering menangkap serangan yang dirancang untuk lolos mesin. MITRE ATT&CK menempatkan pelatihan user sebagai mitigasi pertama untuk phishing, di samping antimalware, pembatasan konten web, dan SPF/DKIM yang ditegakkan DMARC [S4].

## 2. Contoh nyata

Semua header, record DNS, laporan, pesan, dan log di bagian ini adalah keluaran ilustrasi untuk organisasi fiktif PT JAB, bukan hasil eksekusi nyata. Format disederhanakan; nama server Microsoft diganti nama fiktif, dan nama field di produk sungguhan bisa berbeda.

### 2.1 Membaca header email BEC `SOC-2027-0848`

Ini header email yang dilaporkan Rina, diambil dari salinan di `phishing-report@jab.example`. Urutannya seperti di pesan aslinya: baris paling atas ditambahkan paling akhir.

```
Return-Path: <bounce-7731@jab-direksi.example>
Received: from edge07.eop.example (10.200.7.7) by mbx31.exo.example (10.200.31.31)
 with Microsoft SMTP Server; Thu, 12 Aug 2027 01:31:12 +0000
Authentication-Results: spf=pass (sender IP is 192.0.2.161)
 smtp.mailfrom=jab-direksi.example; dkim=pass (signature was verified)
 header.d=jab-direksi.example; dmarc=pass action=none
 header.from=jab-direksi.example; compauth=pass reason=100
Received: from mx.jab-direksi.example (192.0.2.161) by edge07.eop.example
 (10.200.7.7) with ESMTPS; Thu, 12 Aug 2027 01:31:10 +0000
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=jab-direksi.example;
 s=mail2027; h=From:To:Subject:Date:Message-ID:Reply-To; bh=...; b=...
From: "Hendra Wijaya" <hendra.wijaya@jab-direksi.example>
Reply-To: <hendra.wijaya.jab@freemail.example>
To: <rina.anggraini@jab.example>
Subject: Mendesak: pembayaran vendor hari ini
Date: Thu, 12 Aug 2027 08:31:07 +0700
Message-ID: <20270812013107.4F2A9C@mx.jab-direksi.example>
X-Forefront-Antispam-Report: CIP:192.0.2.161;DIR:INB;SFV:NSPM;SFTY:9.25;

Rina, saya sedang rapat di luar sampai sore, jangan telepon, balas email saja.
Pembayaran lisensi dan pengiriman perangkat core router dari vendor baru
PT Mitra Jaringan Prima harus lunas sebelum pukul 11.00 hari ini, kalau tidak
pengiriman mundur dua minggu. Mohon transfer Rp 486.500.000 ke rekening
di bawah ini dan kirim bukti transfernya ke saya.
```

Tabel berikut membaca header baris demi baris; kolom terakhir menunjuk subbagian yang menjelaskan istilahnya.

| Field | Nilai | Artinya | Bagian |
|---|---|---|---|
| `Received` paling bawah | dari `mx.jab-direksi.example (192.0.2.161)`, 01:31:10 UTC | Server pertama yang menyerahkan email ke Microsoft 365; IP asal yang bisa dipegang | 1.6 |
| `Received` paling atas | `edge07` ke `mbx31`, 01:31:12 UTC | Perjalanan di dalam Microsoft 365 sampai mailbox Rina | 1.6 |
| `Date` | 08:31:07 `+0700` | Sama dengan 01:31:07 UTC, tiga detik sebelum diterima; waktu konsisten | 1.6 |
| `From` | `"Hendra Wijaya" <hendra.wijaya@jab-direksi.example>` | Nama benar, domain mirip, bukan `jab.example` | 1.6, 1.11 |
| `Reply-To` | `hendra.wijaya.jab@freemail.example` | Balasan dibelokkan ke webmail gratis | 1.6 |
| `Return-Path` / `smtp.mailfrom` | `jab-direksi.example` | Envelope memakai domain penyerang | 1.6, 1.7 |
| `spf` | `pass`, IP `192.0.2.161` | IP pengirim tercantum di SPF `jab-direksi.example` | 1.7 |
| `dkim` | `pass`, `header.d=jab-direksi.example` | Segel domain penyerang utuh | 1.8 |
| `dmarc` | `pass`, `header.from=jab-direksi.example` | From, envelope, dan DKIM satu domain, jadi aligned | 1.9 |
| `compauth` | `pass reason=100` | Microsoft: SPF atau DKIM lolos dan aligned dengan From [S17] | 1.9 |
| `CIP` | `192.0.2.161` | IP yang tersambung ke Microsoft 365 [S17] | 1.6 |
| `SFV` | `NSPM` | Filter spam menilai bukan spam, dikirim ke Inbox [S17] | 1.10 |
| `SFTY` | `9.25` | First contact safety tip: Rina jarang atau belum pernah menerima email dari alamat ini [S17] | 1.10 |
| `Message-ID` | `<20270812013107.4F2A9C@mx.jab-direksi.example>` | Kunci pencarian salinan email yang sama | 1.6 |

**Cara membaca:** semua pemeriksaan teknis menyatakan email ini benar berasal dari `jab-direksi.example`. Itu tepat: domain itu milik penyerang, dan penyerang memasang SPF, DKIM, dan DMARC-nya dengan rapi. Yang palsu adalah klaim bahwa `jab-direksi.example` ada hubungannya dengan PT JAB. Tanda-tanda yang seharusnya dibaca manusia ada di luar baris autentikasi: domain yang bukan `jab.example`, Reply-To ke webmail gratis, safety tip kontak pertama, dan isi yang memakai tiga tuas social engineering (bagian 1.1).

**Pemeriksaan lanjutan:** pencarian enrichment menunjukkan `jab-direksi.example` didaftarkan Selasa 2027-08-10, dua hari sebelum email dikirim, dan `192.0.2.161` tidak pernah mengirim email ke PT JAB sebelumnya. Threat Explorer menemukan tiga pesan dengan domain dan Message-ID berpola sama, ke tiga staf Keuangan, semua diterima antara 01:31:10 dan 01:31:14 UTC.

**Keputusan:** dua salinan lain ditarik dari mailbox, domain `jab-direksi.example` dan alamat `hendra.wijaya.jab@freemail.example` diblokir di Tenant Allow/Block List, dan kebijakan perlindungan peniruan diperbarui. Tidak ada uang yang ditransfer dan tidak ada akun PT JAB yang dibobol, jadi `SOC-2027-0848` ditutup sebagai true positive (alert yang memang menunjukkan serangan sungguhan, istilahnya dibahas di Day 11) tanpa dinaikkan menjadi insiden. Keuangan diminta melaporkan bila ada telepon lanjutan yang mengaku dari Pak Hendra.

**Kapan cara baca ini gagal:** bila penyerang memakai akun email asli yang dibobol (misalnya akun vendor sungguhan), domain, SPF, DKIM, dan DMARC semuanya benar-benar milik pihak sah. Header tidak akan menunjukkan kejanggalan; yang tersisa adalah isi permintaan, perubahan rekening, dan verifikasi lewat telepon.

### 2.2 Record DNS email `jab.example`, spoofing yang ditolak, dan laporan DMARC

Untuk menjawab "kenapa penyerang tidak memakai `jab.example` saja?", Sari membuka record DNS email PT JAB.

```
jab.example.                       3600 IN TXT "v=spf1 ip4:198.51.100.11 include:spf.protection.outlook.com -all"
selector1._domainkey.jab.example.  3600 IN TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqh...IDAQAB"
_dmarc.jab.example.                3600 IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc-rua@jab.example"
```

**Cara membaca:** record pertama adalah SPF: hanya server mail lama `198.51.100.11` dan server Microsoft 365 yang sah mengirim dengan envelope `jab.example`, sisanya gagal (`-all`) (bagian 1.7). Record kedua adalah kunci publik DKIM dengan selector `selector1`, dipakai untuk memeriksa tanda tangan `d=jab.example` (bagian 1.8); isi kuncinya dipotong. Record ketiga adalah DMARC: email dengan `@jab.example` di From yang tidak lolos SPF atau DKIM aligned harus ditolak, dan rekap harian dikirim ke `dmarc-rua@jab.example` (bagian 1.9).

Pada hari yang sama pukul 10:05 WIB, Microsoft 365 PT JAB menerima email lain yang memalsukan `jab.example` persis dan mencatatnya sebagai alert informasional `SOC-2027-0849`. Bagian Authentication-Results-nya (disederhanakan, kolom `action` dihilangkan):

```
Authentication-Results: spf=pass (sender IP is 192.0.2.164)
 smtp.mailfrom=bulk-relay.example; dkim=none (message not signed)
 header.d=none; dmarc=fail header.from=jab.example;
 compauth=fail reason=000
From: "IT Helpdesk PT JAB" <helpdesk@jab.example>
Subject: Akun Anda akan dinonaktifkan hari ini
```

**Cara membaca:** SPF lolos, tetapi untuk `bulk-relay.example`, bukan `jab.example`, jadi tidak aligned. Tidak ada tanda tangan DKIM. Tidak ada jalur yang aligned dengan From, sehingga `dmarc=fail`. Kode `compauth=fail reason=000` berarti pesan gagal autentikasi eksplisit: gagal DMARC dan domain From punya kebijakan quarantine atau reject [S17]. Karena kebijakan anti-phishing PT JAB mengaktifkan Honor DMARC record policy dengan tindakan Quarantine untuk `p=reject` [S16], email ini masuk karantina dan tidak pernah sampai ke Inbox. DMARC bekerja persis seperti dirancang; itu sebabnya penyerang BEC pagi tadi memilih domain mirip.

Seminggu sekali Sari membaca ringkasan laporan agregat DMARC (rekap yang dikirim penyedia email lain ke alamat `rua`). Tabel berikut merangkum laporan dari satu penyedia email besar untuk Rabu 2027-08-11 (00:00 sampai 23:59 UTC); cari kolom "Hasil DMARC" dan "Tindakan penerima".

| Sumber | Jumlah email | SPF (aligned?) | DKIM (aligned?) | Hasil DMARC | Tindakan penerima |
|---|---|---|---|---|---|
| Exchange Online (banyak IP Microsoft) | 18.655 | pass, ya | pass, ya | pass | dikirim |
| `198.51.100.11` (mail lama PT JAB) | 2.140 | pass, ya | none | pass | dikirim |
| `192.0.2.164` | 1.312 | pass untuk `bulk-relay.example`, tidak | none | fail | ditolak (reject) |
| **Total** | **22.107** | | | | |

**Cara membaca:** total 18.655 ditambah 2.140 ditambah 1.312 sama dengan 22.107 email yang memakai `jab.example` di From dan sampai ke penyedia itu dalam sehari. Dua sumber pertama adalah PT JAB sendiri dan lolos. Sumber ketiga, `192.0.2.164`, IP yang sama dengan spoofing ke helpdesk tadi, mengirim 1.312 email atas nama `jab.example` ke pelanggan penyedia itu, semuanya ditolak. Tanpa DMARC `p=reject`, 1.312 email palsu "dari PT JAB" itu bisa sampai ke inbox pelanggan broadband PT JAB. Server mail lama tidak menandatangani DKIM; ia tetap lolos lewat SPF aligned, tetapi akan gagal bila emailnya diteruskan, jadi Sari mencatat usulan agar server itu juga menandatangani DKIM.

**Kapan laporan ini menyesatkan:** laporan agregat hanya dikirim oleh penerima yang mendukung pelaporan DMARC, dan isinya ringkasan per IP, bukan isi email. Laporan juga baru datang sekitar sehari kemudian, jadi bukan alat deteksi waktu nyata.

### 2.3 PDF berisi QR yang mengarah ke halaman AiTM (`SOC-2027-0851`)

Ini kasus quishing yang disebut Sari di pesannya. Kamis 2027-08-12 pukul 07:42 WIB, 52 mailbox PT JAB menerima email dari `no-reply@hr-update.example` dengan subjek "Kebijakan MFA 2027: wajib verifikasi ulang" dan lampiran `Kebijakan_MFA_2027.pdf`. Dua penerima melaporkannya lewat tombol Report sejak 08:40, dan pukul 09:31 Defender menarik semua salinan lewat ZAP dan membuat alert `SOC-2027-0851`.

```
Alert        : SOC-2027-0851  Email dengan URL berbahaya ditarik setelah terkirim (ZAP)
Waktu kirim  : 2027-08-12 07:42:18 s.d. 07:42:51 WIB
Pengirim     : no-reply@hr-update.example  (IP 192.0.2.162)
Autentikasi  : spf=pass dkim=pass dmarc=pass (semua untuk hr-update.example)
Penerima     : 52 mailbox
Lampiran     : Kebijakan_MFA_2027.pdf (1 halaman, berisi kode QR, tanpa makro, tanpa skrip)
URL di QR    : https://login-jab-verify.example/m365/?u=<alamat penerima>
Resolusi DNS : login-jab-verify.example -> 192.0.2.163 (domain didaftarkan 2027-08-11)
Penilaian    : halaman login tiruan Microsoft 365 jenis AiTM
ZAP          : 52 salinan dipindah ke karantina pukul 09:31 WIB
Dibuka sebelum ZAP : 9 penerima
```

**Cara membaca:** lampiran itu sendiri tidak berbahaya secara teknis: tidak ada makro atau skrip, jadi pemeriksaan lampiran tidak menemukan perilaku jahat. Bahayanya ada di gambar QR, yang berisi URL ke halaman AiTM (bagian 1.11). Karena QR dipindai dengan HP, kunjungan ke halaman itu terjadi lewat jaringan seluler dan tidak melewati proxy kantor. Selama hampir dua jam (07:42 sampai 09:31), sembilan orang sempat membuka email.

**Langkah Sari:**

1. Untuk sembilan orang yang membuka email, periksa sign-in log Entra ID (layanan identitas cloud Microsoft yang dipakai login M365) sejak 07:42: adakah login berhasil dari `192.0.2.163` atau IP tak dikenal, terutama yang memakai sesi tanpa langkah MFA baru.
2. Blokir `login-jab-verify.example` di Tenant Allow/Block List, di proxy web kantor `jkt-proxy01`, dan arahkan ke DNS sinkhole `jkt-sink01` (server DNS yang menjawab domain berbahaya dengan alamat aman milik PT JAB, dibahas di Day 03), supaya laptop kantor yang terhubung ke Wi-Fi tidak bisa membuka domain itu.
3. Kirim pesan singkat ke 52 penerima: "IT tidak pernah meminta verifikasi MFA lewat QR. Bila kamu sempat memindai dan login, segera hubungi SOC ext. 1199."

**Hasil:** sign-in log menunjukkan tidak ada login berhasil dari `192.0.2.163` atau IP asing lain untuk sembilan orang itu. Dua orang menelepon SOC dan mengaku sempat memindai tetapi berhenti di halaman login karena alamatnya terasa aneh. Alert ditutup sebagai true positive tanpa korban.

**Variasi yang perlu dikenali:** QR bisa ditaruh langsung di body email sebagai gambar, di lampiran HTML, di dokumen Office, atau di poster dan stiker fisik [S8]. Teks di sekitar QR hampir selalu memakai urgensi dan tema keamanan ("verifikasi ulang", "akun akan dikunci") karena tema itu membuat orang merasa sedang berbuat benar.

### 2.4 SMS "paket tertahan" dan telepon "IT helpdesk" yang berujung `INC-2027-088`

Kasus terakhir memakai dua saluran di luar email, keduanya ke orang yang sama, Dewi Lestari (Customer Service, laptop `JKT-WS-1091`, `10.10.39.45`).

**Pukul 08:10, `SOC-2027-0850` (smishing).** Dewi meneruskan tangkapan layar SMS dari tadi malam ke `soc@jab.example`:

```
Dari   : +62 8xx xxxx xxxx (nomor ponsel biasa, bukan nama layanan)
Waktu  : Rabu 2027-08-11 21:40 WIB
Isi    : [KurirKita] Paket Anda tertahan karena alamat tidak lengkap.
         Perbarui dalam 24 jam: https://cek-paket-id.example/r/8KX2
```

Dewi tidak sedang menunggu paket dan tidak membuka tautannya. Pemeriksaan domain: `cek-paket-id.example` didaftarkan 2027-08-11, mengarah ke `192.0.2.165`. Log `jkt-proxy01` dan resolver DNS kantor `jkt-res01` tidak mencatat satu pun akses ke domain itu dari jaringan PT JAB; kalaupun ada yang membuka dari HP dengan data seluler, log kantor tidak akan melihatnya. Domain diblokir di proxy dan diarahkan ke sinkhole sebagai pencegahan. Ini smishing massal (bagian 1.4); ia tidak menyasar PT JAB secara khusus.

**Pukul 14:05, `SOC-2027-0852` (vishing).** Dewi menelepon SOC di ext. 1199: lima menit sebelumnya, seseorang yang mengaku "Andi dari IT helpdesk" menelepon ke HP-nya. Layar HP menampilkan nomor yang mirip nomor kantor. Penelepon menyebut nama lengkap Dewi, unitnya, dan aplikasi tiket CS, lalu berkata akun Dewi "sedang dipindahkan ke server baru" dan memintanya menyebutkan kode yang baru masuk ke aplikasi autentikator. Dewi memang baru menerima permintaan persetujuan MFA yang tidak ia minta. Ia menolak, menutup telepon, dan menelepon SOC.

Kamu dan Sari membuka sign-in log Entra ID untuk akun Dewi:

```
Waktu (WIB)          User                      IP              Hasil
2027-08-12 13:58:41  dewi.lestari@jab.example  192.0.2.167     Password benar, MFA dibutuhkan, MFA ditolak user
2027-08-12 14:01:09  dewi.lestari@jab.example  192.0.2.167     Password benar, MFA dibutuhkan, MFA tidak diselesaikan
2027-08-12 14:03:30  dewi.lestari@jab.example  192.0.2.167     Password benar, MFA dibutuhkan, MFA tidak diselesaikan
```

**Cara membaca:** tiga percobaan dari `192.0.2.167`, semuanya dengan password yang benar, semuanya berhenti di MFA. Artinya password Dewi sudah diketahui penyerang, dan telepon "IT helpdesk" adalah upaya melewati MFA dengan pretext (bagian 1.5). MFA dan kewaspadaan Dewi menahan serangan ini, tetapi password yang bocor tetap berarti akun sudah sebagian dikuasai.

**Keputusan:** kasus ini dinaikkan menjadi insiden `INC-2027-088` dengan severity SEV-3 dan diserahkan ke analyst L2 Yoga Pratama. Langkah pertama: reset password Dewi, cabut semua sesi aktif, periksa aturan inbox dan login lain dari `192.0.2.167` di seluruh tenant, lalu cari dari mana password bocor (situs lain dengan password yang sama, email phishing yang terlewat, atau perangkat pribadi). Telepon tidak meninggalkan log di sistem PT JAB; tanpa laporan Dewi, SOC hanya akan melihat tiga kegagalan MFA, pola yang mudah dikira user salah tekan.

**Pelajaran lintas kasus:** dari lima alert hari itu (`SOC-2027-0848` sampai `0852`), tiga berawal dari laporan user (0848, 0850, 0852), satu dari ZAP Defender (0851), dan satu (0849, spoofing helpdesk di bagian 2.2) dari karantina otomatis tanpa perlu tindakan analyst. Satu-satunya yang berujung insiden justru terlihat pertama kali lewat telepon seorang staf CS.

## 3. Perbandingan istilah yang sering tertukar

Tabel pertama membedakan jenis serangan berdasarkan sasaran dan tujuan; cari kolom "Siapa sasarannya" dan "Yang diinginkan" karena dua kolom itu yang membedakan istilahnya.

| Istilah | Saluran | Siapa sasarannya | Yang diinginkan | Contoh di Day ini |
|---|---|---|---|---|
| Phishing | Email (umumnya) | Siapa saja, massal | Password, data, klik | `INC-2026-020` "password M365 kedaluwarsa" |
| Spear phishing | Email | Orang atau unit tertentu | Sama, dengan riset target | Email ke tiga staf Keuangan |
| Whaling | Email, telepon | Eksekutif senior | Data sensitif, akses, persetujuan transfer | Email "surat panggilan" ke Pak Hendra |
| BEC | Email (kadang telepon, rapat virtual) | Orang yang memproses uang atau data | Transfer dana, data karyawan | Permintaan transfer Rp 486.500.000 |
| CEO fraud | Email, telepon | Karyawan di bawah eksekutif | Transfer dana | Nama Pak Hendra dipakai sebagai topeng |
| Smishing | SMS, pesan teks | Massal atau tertentu | Klik, data, login | SMS "paket tertahan" |
| Vishing | Telepon | Tertentu | Kode OTP, password, tindakan | Telepon "IT helpdesk" ke Dewi |
| Quishing | Kode QR | Massal atau tertentu | Login di halaman palsu | PDF "Kebijakan MFA 2027" |
| Pretexting | Semua saluran | Siapa pun | Membuat permintaan terdengar wajar | "Akun sedang dipindahkan ke server baru" |

Tabel kedua membandingkan tiga mekanisme autentikasi email; cari baris "Melihat header From?" karena itu yang paling sering disalahpahami.

| Aspek | SPF | DKIM | DMARC |
|---|---|---|---|
| Pertanyaan yang dijawab | Server ini boleh mengirim untuk domain envelope? | Domain di `d=` menandatangani dan isinya utuh? | Domain From sama dengan domain yang lolos SPF atau DKIM? Apa tindakan bila tidak? |
| Melihat header From? | Tidak [S11] | Tidak [S12] | Ya, inilah tujuannya [S13] |
| Dipasang di DNS | TXT di domain | TXT di `selector._domainkey.domain` | TXT di `_dmarc.domain` |
| Tahan forwarding? | Tidak, sering gagal [S11] | Ya, selama isi tidak diubah [S12] | Bergantung SPF/DKIM yang lolos |
| Analogi | Daftar kantor pos resmi | Segel resmi di surat | Instruksi ke kantor pos plus laporan |
| Lolos untuk domain mirip milik penyerang? | Ya | Ya | Ya |

Tabel ketiga membedakan dua cara meniru pengirim; cari baris "Dihentikan oleh".

| Aspek | Spoofing | Impersonation (domain mirip atau nama tampilan) |
|---|---|---|
| Yang dipakai | Domain orang lain persis (`helpdesk@jab.example`) | Domain milik penyerang yang mirip (`jab-direksi.example`) atau nama tampilan palsu |
| Hasil SPF/DKIM/DMARC | Gagal DMARC bila domain asli memasang DMARC ketat | Bisa lolos semua [S16] |
| Dihentikan oleh | DMARC `p=reject` atau `p=quarantine` | Perlindungan peniruan di gateway, mata user, verifikasi lewat jalur lain |
| Contoh di Day ini | Bagian 2.2 | Bagian 2.1 |

## 4. Salah paham umum

Butir berikut adalah salah paham yang melintasi beberapa istilah sekaligus. Salah paham yang khusus satu istilah sudah ditulis di subbagiannya.

- **Anggapan:** email yang SPF, DKIM, dan DMARC-nya pass berarti asli dan aman. **Kenyataannya:** pass hanya membuktikan email benar dari domain yang tertulis di From. Domain itu bisa milik penyerang, seperti `jab-direksi.example` (bagian 1.9 dan 2.1).
- **Anggapan:** kalau domain perusahaan sudah memasang DMARC `p=reject`, karyawan aman dari email palsu atas nama perusahaan. **Kenyataannya:** DMARC hanya menghentikan pemakaian domain yang persis sama. Domain mirip, nama tampilan palsu, dan akun asli yang dibobol tidak terhentikan (bagian 1.9 dan 3).
- **Anggapan:** email tanpa tautan dan lampiran tidak berbahaya. **Kenyataannya:** BEC biasanya hanya berisi teks permintaan, dan justru karena itu lolos pemeriksaan tautan dan lampiran. Kerugiannya terbesar kedua menurut IC3 2025 [S7] (bagian 1.3).
- **Anggapan:** MFA membuat phishing tidak berbahaya lagi. **Kenyataannya:** AiTM mencuri sesi setelah MFA selesai, dan vishing meminta korban sendiri menyetujui MFA. MFA menaikkan biaya serangan, terutama metode yang tahan phishing, tetapi tidak menghapus risiko (bagian 1.11 dan 2.4).
- **Anggapan:** ikon gembok dan HTTPS di halaman login membuktikan halaman itu resmi. **Kenyataannya:** situs phishing pun bisa punya sertifikat sah. Yang diperiksa adalah nama domainnya. Saran lama untuk mengecek gembok sebelum mengirim data masih tercantum di halaman CISA yang kini diarsipkan [S3], dan tidak lagi cukup (bagian 1.11 dan 5).
- **Anggapan:** SOC bisa melihat semua serangan phishing di log. **Kenyataannya:** SMS, telepon, dan QR yang dipindai HP pribadi hampir tidak meninggalkan jejak di sistem kantor. Laporan user adalah satu-satunya sensor untuk saluran itu (bagian 1.4, 1.12, dan 2.4).
- **Anggapan:** user yang melapor email aman membuang waktu SOC. **Kenyataannya:** laporan yang ternyata aman adalah harga murah untuk menangkap laporan yang ternyata BEC. Menegur pelapor membuat laporan berhenti datang (bagian 1.12).

## 5. Catatan terkini

Bagian ini mencatat perubahan standar, angka, dan dokumen yang memengaruhi cara membaca materi lama tentang email security.

- **DMARC menjadi standar IETF (Mei 2026).** RFC 9989 menggantikan RFC 7489 (2015, berstatus Informational) dan RFC 9091 (ekstensi PSD yang eksperimental), dan berstatus Proposed Standard [S13]. Pelaporan dipecah: laporan agregat di RFC 9990, laporan kegagalan di RFC 9991 [S13]. Versi record tetap `v=DMARC1`, jadi record lama tetap berlaku. Perubahan yang terlihat: tag `pct` dihapus, ada tag baru `np` (kebijakan subdomain yang tidak ada), `psd`, dan `t` (mode uji), serta penentuan Organizational Domain lewat penelusuran pohon DNS (DNS tree walk) menggantikan Public Suffix List [S13]. Materi dan header lama yang masih menyebut `pct=` atau nilai `pct.quarantine` akan terus beredar; dokumentasi header Microsoft per 2026 masih mendokumentasikan nilai `action=pct.quarantine` dan `pct.reject` [S17].
- **Angka BEC dan phishing terbaru.** IC3 2025 Annual Report mencatat 24.768 pengaduan BEC dengan kerugian USD 3.046.598.558 (naik dari 21.442 pengaduan pada 2024) dan 191.561 pengaduan phishing/spoofing [S7]. Laporan yang sama mencatat lebih dari USD 30 juta kerugian BEC yang melibatkan AI, misalnya email tiruan gaya eksekutif dan kloning suara [S7]. Angka IC3 adalah pengaduan ke FBI, sebagian besar dari Amerika Serikat, bukan seluruh dunia.
- **Halaman CISA tentang social engineering** (Februari 2021) kini ditandai sebagai konten arsip [S3]. Definisinya masih berlaku, tetapi saran mengecek "https" dan ikon gembok sebelum mengirim data sudah tidak cukup.
- **NIST SP 800-177 Rev. 1** (Februari 2019) adalah panduan NIST tentang email tepercaya yang mencakup SPF, DKIM, DMARC, TLS antarserver, dan S/MIME [S24]. Dokumen ini terbit sebelum RFC 9989, jadi rujukan DMARC di dalamnya masih ke RFC 7489.
- **Dokumentasi Defender for Office 365** berubah cepat; halaman yang dirujuk Day ini diperbarui antara Mei dan Oktober 2026 [S15][S16][S17][S18][S19][S20][S21][S25]. Nama menu, batas jumlah (misalnya 350 user dilindungi per kebijakan), dan perilaku default bisa berubah; cek di tenant dan versi dokumentasimu.
- **MITRE ATT&CK T1566 (Phishing)** versi 2.8, terakhir diubah 18 September 2026, masih memakai empat sub-teknik: lampiran, tautan, lewat layanan, dan suara [S4].

## 6. Cheat sheet

```
SOCIAL ENGINEERING  menipu manusia agar menyerahkan info/akses/uang; tuas: otoritas, urgensi, isolasi, takut/iming-iming
PHISHING            pesan palsu meniru pihak tepercaya; massal; ATT&CK T1566 (.001 lampiran .002 link .003 layanan .004 suara)
SPEAR PHISHING      phishing yang diriset untuk orang/unit tertentu
WHALING             spear phishing yang MENYASAR eksekutif
BEC                 penipuan email bisnis untuk transfer dana/data; sering tanpa link/lampiran
CEO FRAUD           BEC yang MEMAKAI NAMA eksekutif untuk menekan karyawan
SMISHING            lewat SMS/pesan teks       VISHING  lewat telepon (caller ID bisa palsu)
QUISHING            lewat kode QR; tautan berbentuk gambar, dipindai HP pribadi
PRETEXTING          cerita karangan yang membuat permintaan terdengar wajar

ENVELOPE            MAIL FROM / RCPT TO antarserver (RFC 5321); tidak tampil; diperiksa SPF
HEADER FROM         yang tampil di aplikasi (RFC 5322); ditulis pengirim; diperiksa DMARC
REPLY-TO            tujuan balasan; BEC sering membelokkan ke webmail gratis
RETURN-PATH         catatan envelope oleh server tujuan akhir; tujuan bounce
RECEIVED            satu baris per server, ditambah di ATAS; baca dari BAWAH; percayai hanya baris server milikmu
MESSAGE-ID          nomor unik pesan; kunci cari salinan di mailbox lain
AUTH-RESULTS        hasil spf/dkim/dmarc oleh server PENERIMA (RFC 8601); yang dari luar harus dibuang

SPF                 TXT "v=spf1 ... -all"; IP pengirim vs domain envelope; hasil pass|fail|softfail|neutral|none|temperror|permerror; maks 10 lookup
DKIM                tanda tangan digital; d= domain, s= selector; kunci di s._domainkey.d; tahan forwarding
DMARC               TXT di _dmarc.domain; pass bila SPF ATAU DKIM lolos DAN aligned dengan From
                    p=none|quarantine|reject; rua= laporan agregat; RFC 9989 (Mei 2026) gantikan RFC 7489
PASS SEMUA          = email benar dari domain yang TERTULIS; bukan bukti domain itu jujur

SPOOFING            pakai domain orang lain persis -> dihentikan DMARC p=reject
IMPERSONATION       domain mirip/nama tampilan -> lolos autentikasi; butuh perlindungan peniruan + manusia
SEG                 saring email sebelum mailbox; MX/konektor (inline) atau API
DEFENDER O365       anti-spoof, impersonation, Safe Links (cek saat klik), Safe Attachments (detonation), ZAP, Report button
AiTM                proxy login palsu; curi session cookie setelah MFA; lawan: MFA tahan phishing + akses bersyarat
LAPORAN USER        sensor untuk BEC, domain mirip, SMS, telepon; balas setiap laporan, jangan tegur pelapor

CEK CEPAT EMAIL MENCURIGAKAN
1 domain From persis jab.example?   2 Reply-To beda?   3 IP/ Received pertama tepercaya?
4 spf/dkim/dmarc untuk domain APA?  5 domain baru didaftarkan?   6 permintaan uang/kredensial/urgensi?
7 siapa lagi menerima, siapa klik, siapa isi password?
```

## 7. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Header email yang dilaporkan menunjukkan `spf=pass`, `dkim=pass`, dan `dmarc=pass`, jadi email itu asli dan laporan user bisa ditutup." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Ketiga hasil itu hanya membuktikan email benar berasal dari domain yang tertulis di header From. Bila domain itu milik penyerang, seperti `jab-direksi.example` di `SOC-2027-0848`, penyerang cukup memasang SPF, DKIM, dan DMARC untuk domainnya sendiri dan semuanya akan pass. Yang harus diperiksa berikutnya adalah domain apa yang lolos, apakah domain itu milik PT JAB atau mitra yang dikenal, Reply-To, umur domain, dan isi permintaan. Lihat bagian 1.9 dan 2.1.

</details>

**2. Skenario keputusan.** Staf Keuangan menerima email dari alamat vendor lama yang sudah bertahun-tahun berkorespondensi. Domainnya benar, SPF, DKIM, dan DMARC pass, tidak ada tautan atau lampiran. Isinya: "Mulai bulan ini rekening kami pindah ke bank lain, mohon pembayaran tagihan berikut ke rekening baru." Langkah mana yang paling tepat?

- A. Bayar ke rekening baru, karena email terbukti dari domain vendor yang asli.
- B. Telepon vendor lewat nomor yang tercatat di data master vendor atau kontrak, bukan nomor di email, untuk mengonfirmasi perubahan, dan laporkan email itu ke SOC.
- C. Balas email itu dan minta vendor mengonfirmasi bahwa perubahan rekening memang benar.

<details><summary>Jawaban</summary>

B. Email dari domain asli bisa berasal dari akun vendor yang sudah dibobol; dalam kasus itu semua pemeriksaan teknis lolos. Verifikasi lewat jalur kedua adalah kontrol yang disarankan IC3 untuk setiap perubahan data rekening. A keliru karena autentikasi email tidak membuktikan permintaannya sah. C keliru karena balasan akan dibaca penyerang yang menguasai akun atau yang membelokkan Reply-To, dan ia tentu akan mengonfirmasi. Lihat bagian 1.3 dan 1.12.

</details>

**3. Pertanyaan jebakan.** "PT JAB sudah memasang DMARC `p=reject` untuk `jab.example`, jadi tidak mungkin ada email yang tampil dengan nama 'Hendra Wijaya' sampai ke Inbox karyawan kecuali Pak Hendra sendiri yang mengirim." Benarkah?

<details><summary>Jawaban</summary>

Tidak. DMARC hanya melindungi domain yang persis sama di header From. Nama tampilan bisa dipasang di depan alamat apa pun, misalnya `"Hendra Wijaya" <hendra.wijaya@jab-direksi.example>` atau alamat webmail gratis, dan domain-domain itu tidak terkena kebijakan DMARC `jab.example`. Yang dihentikan DMARC PT JAB adalah email yang memakai `@jab.example` persis tanpa lolos SPF atau DKIM aligned, seperti spoofing ke helpdesk di bagian 2.2. Lihat bagian 1.6, 1.9, dan 3.

</details>

**4. Skenario keputusan.** Kamu menerima telepon di HP dari nomor yang tampil seperti nomor kantor. Penelepon mengaku dari IT helpdesk, menyebut namamu dan unitmu dengan benar, lalu berkata akunmu sedang dimigrasi dan memintamu menyebutkan kode yang baru masuk ke aplikasi autentikator. Apa yang kamu lakukan?

- A. Sebutkan kodenya, karena nomornya nomor kantor dan ia tahu data kamu.
- B. Tolak, tutup telepon, lalu hubungi SOC atau helpdesk lewat nomor resmi yang kamu cari sendiri (misalnya ext. 1199) dan laporkan.
- C. Sebutkan kodenya, lalu segera ganti password setelah telepon selesai.

<details><summary>Jawaban</summary>

B. Caller ID bisa dipalsukan, dan detail pribadi yang benar mudah dicari; itu bagian dari pretext. Permintaan kode MFA yang tidak kamu minta berarti seseorang sedang login dengan password-mu, jadi laporan cepat memungkinkan SOC mereset password dan mencabut sesi. A keliru karena IT yang sah tidak pernah meminta kode OTP. C keliru karena begitu kode diberikan, penyerang langsung mendapat sesi login yang tetap berlaku walaupun password diganti, sampai sesi itu dicabut. Lihat bagian 1.4, 1.5, dan 2.4.

</details>

**5. Jelaskan ulang.** Jelaskan kepada anggota keluargamu yang bukan orang IT, dalam tiga kalimat, apa itu phishing dan apa yang sebaiknya mereka lakukan saat menerima pesan yang mencurigakan.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Phishing itu pesan palsu lewat email, SMS, atau telepon yang mengaku dari bank, kurir, kantor, atau atasan, supaya kamu menyerahkan password, kode OTP, atau uang. Tandanya biasanya mendesak, menakut-nakuti, atau minta dirahasiakan, dan nama pengirimnya bisa saja terlihat benar. Jangan klik tautannya dan jangan berikan kode apa pun; hubungi sendiri bank atau kantornya lewat nomor resmi yang kamu cari sendiri, dan kalau di kantor, laporkan ke tim keamanan."

Kesalahan yang sering muncul:
- Hanya menyebut email, padahal SMS, telepon, dan kode QR sama berbahayanya.
- Menyarankan "lihat apakah ada gembok di browser", padahal situs palsu juga bisa memakai HTTPS.
- Menyarankan membalas atau menelepon nomor yang tertera di pesan untuk konfirmasi, padahal nomor itu milik penipu.

</details>

**6. Pertanyaan jebakan.** "Untuk tahu dari mana sebuah email berasal, baca baris `Received` paling atas, karena itu server pengirim aslinya." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Setiap server menambahkan baris Received di paling atas, jadi baris paling atas adalah hop terakhir di dalam sistem penerima, dan baris paling awal ada di bawah. Baca dari bawah ke atas, lalu cari baris Received pertama yang ditulis server milik organisasimu atau penyedia emailmu: IP di baris itu adalah pihak yang benar-benar menyerahkan email. Baris di bawahnya ditulis sebelum email sampai ke server tepercaya dan bisa dikarang pengirim. Di `SOC-2027-0848`, baris itu menyebut `mx.jab-direksi.example (192.0.2.161)`. Lihat bagian 1.6 dan 2.1.

</details>

**7. Interview question (English).** "A finance employee reports an email that looks like it came from a company director asking for an urgent wire transfer. The headers show SPF, DKIM and DMARC all passing. Walk me through how you would handle it, and explain how an email can pass all three checks and still be malicious."

<details><summary>Sample answer</summary>

"First I'd confirm no money has moved; if a transfer was made, finance has to call the bank immediately to try to recall it, because speed matters most in BEC. Then I'd read the headers from the bottom up and find the first Received line written by our own mail system, which gives me the real sending IP. I'd compare three domains: the From domain the user sees, the envelope or Return-Path domain, and the Reply-To. SPF, DKIM and DMARC only prove that the message really comes from the domain written in From. If the attacker registered a lookalike domain and published their own SPF, DKIM and DMARC records, everything passes, because the domain is authentic, it just isn't ours. Our own DMARC reject policy only stops exact spoofing of our domain. So I'd check domain age and reputation, search for the same sender or Message-ID across all mailboxes, pull the other copies, block the domain and the reply-to address, and check whether anyone replied or clicked. Finally I'd look at why it got through, for example whether the director was on the impersonation protection list, and thank the reporter, because user reports are often the only sensor for text-only BEC."

What makes this answer strong: it starts with the business impact (stopping or recalling the transfer), reads headers in the correct order, explains precisely what SPF, DKIM and DMARC prove and what they do not, separates spoofing from lookalike impersonation, covers scoping and containment across all recipients, and ends with a control improvement and the value of user reporting.

</details>

## 8. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | NIST CSRC Glossary: social engineering | https://csrc.nist.gov/glossary/term/social_engineering | primer (glosarium NIST) | diakses 2026-10-21 | Tinggi. Definisi dari SP 800-82r3, SP 800-115, SP 1800-21B, SP 800-63-4 |
| S2 | NIST CSRC Glossary: phishing | https://csrc.nist.gov/glossary/term/phishing | primer (glosarium NIST) | diakses 2026-10-21 | Tinggi. Definisi dari SP 800-12r1, SP 800-115, SP 800-44v2, SP 800-63-4, dan lainnya |
| S3 | CISA: Avoiding Social Engineering and Phishing Attacks | https://www.cisa.gov/news-events/news/avoiding-social-engineering-and-phishing-attacks | primer (lembaga pemerintah AS) | 2021-02-01, ditandai arsip; diakses 2026-10-21 | Sedang-tinggi. Definisi social engineering, phishing, vishing, smishing, tanda peringatan; saran gembok HTTPS sudah usang |
| S4 | MITRE ATT&CK T1566: Phishing | https://attack.mitre.org/techniques/T1566/ | primer (basis pengetahuan MITRE) | versi 2.8, diubah 2026-09-18; diakses 2026-10-21 | Tinggi. Empat sub-teknik, beda spearphishing dan non-targeted, mitigasi |
| S5 | Proofpoint: What Is Whaling? | https://www.proofpoint.com/us/threat-reference/whaling | sekunder (vendor) | diakses 2026-10-21 | Sedang. Definisi whaling dan beda dengan CEO fraud |
| S6 | FBI IC3 PSA I-091124-PSA: Business Email Compromise: The $55 Billion Scam | https://www.ic3.gov/PSA/2024/PSA240911 | primer (FBI) | 2024-09-11; diakses 2026-10-21 | Tinggi. USD 55.499.915.582 dan 305.033 insiden Okt 2013 sampai Des 2023; saran verifikasi jalur kedua |
| S7 | FBI IC3 2025 Annual Report | https://www.ic3.gov/AnnualReport/Reports/2025_IC3Report.pdf | primer (FBI) | 2026; diakses 2026-10-21 | Tinggi. BEC 24.768 pengaduan dan USD 3.046.598.558; phishing/spoofing 191.561; definisi BEC dan phishing/spoofing; BEC dengan AI lebih dari USD 30 juta |
| S8 | FBI IC3 PSA I-011822-PSA: Cybercriminals Tampering with QR Codes to Steal Victim Funds | https://www.ic3.gov/PSA/2022/PSA220118 | primer (FBI) | 2022-01-18; diakses 2026-10-21 | Tinggi. Penggantian QR digital dan fisik, saran verifikasi |
| S9 | RFC 5321: Simple Mail Transfer Protocol | https://www.rfc-editor.org/rfc/rfc5321.html | primer (standar IETF) | Oktober 2008; diakses 2026-10-21 | Tinggi. Envelope vs isi, Received ditambahkan di atas, Return-Path oleh server tujuan akhir |
| S10 | RFC 5322: Internet Message Format | https://www.rfc-editor.org/rfc/rfc5322.html | primer (standar IETF) | Oktober 2008; diakses 2026-10-21 | Tinggi. From, Reply-To, Date dengan zona waktu, Message-ID unik |
| S11 | RFC 7208: Sender Policy Framework (SPF) Version 1 | https://www.rfc-editor.org/rfc/rfc7208.html | primer (standar IETF) | April 2014; diakses 2026-10-21 | Tinggi. Identitas MAIL FROM dan HELO, mekanisme, tujuh hasil, batas 10 lookup, forwarding, tidak menjamin identitas lain |
| S12 | RFC 6376: DomainKeys Identified Mail (DKIM) Signatures | https://www.rfc-editor.org/rfc/rfc6376.html | primer (standar IETF) | September 2011; diakses 2026-10-21 | Tinggi. Tag d, s, h, bh, b; kunci di _domainkey; d tidak wajib sama dengan From; tidak menilai spam |
| S13 | RFC 9989: Domain-based Message Authentication, Reporting, and Conformance (DMARC) | https://www.rfc-editor.org/rfc/rfc9989.html | primer (standar IETF, Proposed Standard) | Mei 2026; diakses 2026-10-21 | Tinggi. Menggantikan RFC 7489 dan RFC 9091; Author Domain, alignment, p/sp/np/t, rua merujuk RFC 9990, ruf merujuk RFC 9991, DNS tree walk |
| S14 | RFC 8601: Message Header Field for Indicating Message Authentication Status | https://www.rfc-editor.org/rfc/rfc8601.html | primer (standar IETF) | Mei 2019; diakses 2026-10-21 | Tinggi. Format Authentication-Results, kewajiban menghapus header palsu, pass tidak berarti tepercaya |
| S15 | Microsoft Learn: How email authentication works in Microsoft 365 | https://learn.microsoft.com/en-us/defender-office-365/email-authentication-about | primer (dokumentasi vendor) | diperbarui 2026-07; diakses 2026-10-21 | Tinggi. P1/P2 sender, contoh spoofing, kelemahan SPF dan DKIM sendirian, composite authentication |
| S16 | Microsoft Learn: Anti-phishing policies in Microsoft 365 | https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-policies-about | primer (dokumentasi vendor) | diperbarui 2026-08; diakses 2026-10-21 | Tinggi. Spoofing vs impersonation, Honor DMARC, first contact safety tip, maksimal 350 user dilindungi |
| S17 | Microsoft Learn: Anti-spam message headers | https://learn.microsoft.com/en-us/defender-office-365/message-headers-eop-mdo | primer (dokumentasi vendor) | diperbarui 2026-08; diakses 2026-10-21 | Tinggi. Field CIP, SFV, SFTY 9.25, sintaks Authentication-Results Microsoft, kode reason compauth 000 dan 100 |
| S18 | Microsoft Learn: Why do I need Microsoft Defender for Office 365? | https://learn.microsoft.com/en-us/defender-office-365/mdo-about | primer (dokumentasi vendor) | diperbarui 2026-06; diakses 2026-10-21 | Tinggi. Perlindungan bawaan, Plan 1, Plan 2, ZAP, Threat Explorer, AIR, Attack simulation training |
| S19 | Microsoft Learn: Safe Links overview | https://learn.microsoft.com/en-us/defender-office-365/safe-links-about | primer (dokumentasi vendor) | diperbarui 2026-10-14; diakses 2026-10-21 | Tinggi. Penulisan ulang URL, pemeriksaan saat klik, detonasi URL tanpa reputasi |
| S20 | Microsoft Learn: Safe Attachments | https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-about | primer (dokumentasi vendor) | diperbarui 2026-08; diakses 2026-10-21 | Tinggi. Detonation di lingkungan virtual, umumnya selesai dalam 15 menit, Dynamic Delivery, lampiran berpassword |
| S21 | Microsoft Learn: Configure user reported message settings | https://learn.microsoft.com/en-us/defender-office-365/submissions-user-reported-messages-custom-mailbox | primer (dokumentasi vendor) | diperbarui 2026-10-01; diakses 2026-10-21 | Tinggi. Tombol Report bawaan, tujuan laporan, alert policy laporan user, notifikasi hasil AIR |
| S22 | Microsoft Security Blog: From cookie theft to BEC: Attackers use AiTM phishing sites as entry point to further financial fraud | https://www.microsoft.com/en-us/security/blog/2022/07/12/from-cookie-theft-to-bec-attackers-use-aitm-phishing-sites-as-entry-point-to-further-financial-fraud/ | sekunder (blog riset vendor) | 2022-07-12; diakses 2026-10-21 | Sedang-tinggi. Cara kerja AiTM, bukan celah MFA, lebih dari 10.000 organisasi, lanjutan BEC, mitigasi |
| S23 | Barracuda Glossary: Inline Email Security Deployment | https://www.barracuda.com/support/glossary/inline-deployment | sekunder (vendor) | diakses 2026-10-21 | Sedang. Model gateway berbasis MX, konektor, dan API; materi pemasaran vendor |
| S24 | NIST SP 800-177 Rev. 1: Trustworthy Email | https://csrc.nist.gov/pubs/sp/800/177/r1/final | primer (publikasi NIST) | Februari 2019; diakses 2026-10-21 | Tinggi untuk cakupan; hanya halaman ringkasan yang diperiksa |
| S25 | Microsoft Learn: Set up SPF to identify valid email sources for your Microsoft 365 domain | https://learn.microsoft.com/en-us/defender-office-365/email-authentication-spf-configure | primer (dokumentasi vendor) | diperbarui 2026-07; diakses 2026-10-21 | Tinggi. `include:spf.protection.outlook.com`, saran `-all`, batas 10 lookup |

**Catatan sumber:** definisi whaling dan pembedaannya dari CEO fraud hanya bersumber sekunder dari vendor [S5]; NIST CSRC Glossary tidak punya entri whaling, spear phishing, atau pretexting saat diperiksa, sehingga definisi pretexting ditulis sendiri berdasarkan definisi social engineering NIST [S1]. Istilah quishing tidak dipakai dalam dokumen FBI yang dirujuk; IC3 menggambarkan tekniknya (penggantian kode QR) tanpa nama itu [S8]. Definisi secure email gateway berasal dari materi vendor [S23]. Untuk NIST SP 800-177 Rev. 1 hanya halaman ringkasannya yang diperiksa [S24]. Tanggal terbit RFC 9989 (Mei 2026) diambil dari teks RFC; halaman info RFC Editor mengonfirmasi status Proposed Standard dan dokumen yang digantikan [S13]. Angka IC3 adalah pengaduan yang diterima FBI, bukan total kerugian global. Seluruh header, record DNS, laporan DMARC, SMS, sign-in log, nama host, nama orang, dan alamat di bagian 1 dan 2 adalah ilustrasi untuk organisasi fiktif PT JAB, bukan hasil eksekusi nyata.
