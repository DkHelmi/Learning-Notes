---
day: 10
title: 'Kompromi identitas Entra ID: sign-in log, mencabut sesi dan token, Conditional Access'
researched_on: 2026-10-15
versions_checked: 'Microsoft Entra ID, halaman Sign-in logs (ms.date 2025-11-07), Non-interactive sign-in logs (2026-02-09), Sign-in log activity details (2026-03-04), Data retention (2026-01-06); Microsoft Graph signIn resource beta (2025-11-27); Refresh tokens (2025-11-05); Revoke user access in an emergency (2026-06-19); Continuous access evaluation (2026-04-08); Token protection (2026-08-14); Session lifetime (2026-04-08); Authentication strengths (2025-03-04); Control security information registration (2026-03-24); ID Protection risk detections (2026-04-22); Audit log activity reference (2025-03-25); Token theft playbook (2023-07-28); Microsoft Graph PowerShell SDK cmdlet reference (2026-09-22); Detect and remediate illicit consent grants (2026-07-03)'
---

# Day 10: Kompromi identitas Entra ID (sign-in log, mencabut sesi dan token, Conditional Access)

Cakupan: memahami kenapa akun dengan MFA tetap bisa diambil alih lewat pencurian token, membaca sign-in log dan audit log Entra ID untuk menyusun apa yang dilakukan penyerang, mencabut semua sesi dan persistence di identitas dengan urutan yang benar, menilai apakah akun admin milik orang yang sama ikut tersentuh, dan memilih perubahan Conditional Access yang benar-benar menutup jalur yang dipakai.

## Ide inti

Di Entra ID, yang dipakai untuk mengakses Exchange, SharePoint, atau Teams bukan password, melainkan token yang diterbitkan setelah login berhasil. Password dan MFA hanya diperiksa saat token diterbitkan. Siapa pun yang memegang token yang masih berlaku akan dilayani, dari mana pun ia datang, sampai token itu kedaluwarsa atau dicabut. Karena itu kompromi identitas di cloud punya tiga pertanyaan yang berbeda dari kompromi host: token mana yang dipegang penyerang, apa yang sudah ia tanam supaya bisa masuk lagi (metode MFA, perangkat, consent aplikasi, aturan mailbox), dan apa yang bisa ia jangkau dari identitas itu. Mengganti password menjawab sebagian kecil dari ketiganya.

Pola ini sudah kamu kenal dari layanan broadband. Pelanggan PPPoE diautentikasi RADIUS sekali saat sesi dibuka; setelah itu BRAS melayani sesi tersebut sampai session-timeout, tanpa menanyakan password lagi. CPE menyimpan kredensial sehingga sesi tersambung ulang otomatis. Mengganti password pelanggan di RADIUS tidak memutus sesi yang sedang berjalan; untuk itu NOC mengirim Disconnect-Message atau CoA ke BRAS. Di Entra ID, access token adalah sesi dengan timeout pendek, refresh token dan session cookie adalah kredensial yang disimpan CPE, dan Revoke sessions serta Continuous Access Evaluation (CAE) adalah Disconnect-Message-nya. Bedanya, token Entra ID bisa disalin ke mesin lain di internet dan tetap dilayani, dan tidak semua aplikasi mendengarkan sinyal pencabutan.

```
Rina klik tautan phishing
   |
   v
proxy AiTM 198.51.100.141  <-->  halaman login Microsoft yang asli
   |  Rina mengetik password dan menyetujui MFA (sah, number matching)
   |  proxy meneruskan, lalu menyimpan session cookie yang membawa klaim MFA
   v
VPS penyerang 198.51.100.152 memutar ulang cookie
   |  session ID sama, IP dan ASN berbeda, tanpa deviceId
   +-- membaca mailbox dan OneDrive (Day 09)
   +-- mendaftarkan metode MFA baru  (persistence)
   +-- mencoba login adm.rina         (gagal, password salah)
   v
containment identitas: revoke sessions + hapus metode asing + reset + cek akun admin
   v
perbaikan Conditional Access: tutup jalur yang dipakai, bukan menambah prompt MFA
```

Situasi yang dipakai sepanjang Day ini adalah `INC-2026-022` di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif. AD on-premises `corp.jab.example` disinkronkan ke Entra ID dengan password hash sync, dan email karyawan ada di Microsoft 365. Lisensi PT JAB adalah Microsoft 365 E3 ditambah Defender for Office 365 Plan 2 dan Defender for Endpoint Plan 2. Entra ID yang ikut di E3 adalah P1: Conditional Access tersedia, sign-in log dan audit log disimpan Entra ID selama 30 hari, tetapi deteksi risiko premium ID Protection hanya muncul sebagai "Additional risk detected" tanpa detail [S5][S10]. Karena itu log sign-in dan audit Entra ID dialirkan ke Splunk dan disimpan satu tahun di sana.

Rabu 2026-10-28 pukul 16:47, Rina Wulandari, staf IT Infrastruktur yang juga memegang akun admin terpisah `adm.rina`, membuka tautan "Jadwal Maintenance POP Q4" dari email dan login di halaman yang tampak seperti halaman Microsoft. Alert pertama `SOC-2026-0230` (metode MFA didaftarkan dari IP di luar lokasi PT JAB) muncul 17:06 sebagai P3 dan ditutup L1 sore itu dengan catatan "kemungkinan pengguna ganti HP", tanpa menghubungi Rina. Kamis 08:05 rule korelasi harian `SOC-2026-0236` (satu session ID dipakai dari lebih dari satu ASN) naik ke Sari Kusuma (L2). Sari menelepon Rina, Rina memastikan nomor telepon yang terdaftar bukan miliknya, lalu Rina meminta helpdesk me-reset password-nya; helpdesk menjalankannya di AD pukul 08:45. Dimas Prasetyo menyatakan insiden SEV-2 pukul 08:50, lalu menulis di kanal `#inc-2026-022` pukul 09:05:

> "Sar, password Rina sudah di-reset helpdesk jam 08:45. Itu sudah cukup belum? Saya juga belum paham bagaimana bisa tembus, MFA kan wajib. Dari log mana kita tahu apa saja yang dilakukan penyerang, dan kenapa katanya banyak aktivitas yang tidak kelihatan di tab sign-in yang biasa kita buka? Nomor telepon asing itu artinya apa buat kita? Yang paling saya khawatirkan `adm.rina`: tersentuh atau tidak? Setelah ini Conditional Access kita harus diubah apa supaya tidak terulang?"

Pesan itu memuat tujuh pertanyaan:

1. Bagaimana penyerang lolos padahal MFA wajib?
2. Log mana yang dipakai, dan kenapa tidak semua aktivitas terlihat di tab yang biasa dibuka?
3. Bagaimana membaca satu baris sign-in dan menghubungkannya ke aktivitas penyerang lain?
4. Apakah reset password sudah cukup?
5. Apa arti metode MFA asing, dan persistence apa lagi yang perlu dicari?
6. Apakah akun admin `adm.rina` ikut tersentuh?
7. Perubahan Conditional Access apa yang menutup jalur ini?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, pertanyaan 6 di bagian 1.6, dan pertanyaan 7 di bagian 1.7. Bagian 2 berisi query, perintah, dan dokumen yang dipakai PT JAB pagi itu, termasuk hunting sign-in untuk semua penerima email yang sama (bagian 2.7) dan checklist pemulihan akun yang dipakai untuk setiap kompromi identitas (bagian 2.8).

**Kapan relevan:** setiap kali akun cloud dicurigai dipakai orang lain, terutama setelah phishing ke halaman login, alert sign-in dari lokasi atau ASN tidak biasa, metode MFA baru yang tidak dikenali pengguna, atau deteksi token anomali; juga saat menilai apakah kontrol identitas PT JAB cukup sebelum insiden.
**Kapan bukan jawaban:** Day ini tidak membahas isi mailbox (inbox rule, `MailItemsAccessed`, pesan yang dikirim penyerang), karena itu bagian Day 09, dan tidak membahas serangan terhadap AD on-premises seperti Kerberoasting atau DCSync (Day 11 dan 12). Bila token dicuri dari endpoint, misalnya oleh infostealer, langkah di Day ini perlu ditambah investigasi dan pembersihan host seperti di Day 04 sampai 06.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (containment, scoping, blast radius, revoke session, disable akun, scope statement, jam H) tidak diulang. Tabel berikut memuat istilah baru Day ini. Kolom padanan memakai analogi NOC dan SOC yang sama di semua Day IR.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Access token | Token berumur pendek yang dibawa aplikasi ke layanan (Exchange, SharePoint); default satu jam | Sesi PPPoE dengan session-timeout pendek |
| Refresh token dan session cookie | Artefak berumur panjang untuk mendapat access token baru tanpa login ulang | Kredensial PPPoE yang disimpan di CPE untuk reconnect otomatis |
| Pencurian token (token theft) | Penyerang memakai token milik pengguna yang sudah lolos password dan MFA | Menumpang sesi SSH ke router yang masih terbuka di jump host |
| AiTM (adversary in the middle) | Proxy di antara pengguna dan halaman login asli yang meneruskan login lalu menyimpan password dan session cookie | Perangkat sisipan di jalur yang meneruskan sesi sambil menyalin isinya |
| MFA fatigue (push bombing) | Membanjiri pengguna dengan notifikasi MFA sampai disetujui | Spam permintaan verifikasi ke pelanggan sampai ia mengiyakan |
| Sign-in log interactive | Login yang pengguna memberikan faktor (password, MFA) | Access-Request RADIUS saat pelanggan login |
| Sign-in log non-interactive | Login atas nama pengguna oleh aplikasi memakai token, tanpa faktor baru | Interim-Update accounting yang tercatat tanpa pelanggan mengetik apa pun |
| Session ID | Identifier sesi yang dibuat saat sign-in; ikut terbawa ke sign-in berikutnya dalam sesi yang sama | Acct-Session-Id yang mengikat semua record satu sesi |
| Revoke sessions | Mencabut semua refresh token dan session cookie pengguna | Disconnect-Message ke BRAS untuk semua sesi pelanggan |
| CAE (Continuous Access Evaluation) | Layanan yang mendukung menolak token yang belum kedaluwarsa saat ada kejadian kritis | CoA RADIUS yang memutus sesi aktif di tengah jalan |
| Security info (metode autentikasi) | Metode MFA dan pemulihan yang terdaftar di akun | Nomor HP verifikasi pelanggan di CRM |
| Conditional Access (CA) | Kebijakan yang menentukan syarat token boleh diterbitkan: siapa, dari mana, perangkat apa, metode apa | Policy di BRAS berdasarkan atribut RADIUS |
| Authentication strength | Syarat CA tentang jenis metode MFA yang boleh dipakai, misalnya hanya yang phishing-resistant | Syarat autentikasi berbeda untuk akses console dan akses pelanggan |
| Token protection | Kontrol CA yang hanya menerima token yang terikat ke perangkat terdaftar | Kredensial yang hanya sah dari MAC tertentu |

### 1.1 Lolos MFA: penyerang tidak perlu mengalahkan MFA, cukup mengambil hasilnya

Pertanyaan pertama Dimas ("MFA kan wajib") adalah salah paham yang paling sering muncul. MFA tidak dilewati; MFA dijalankan oleh Rina sendiri, dengan benar, di halaman yang ternyata proxy.

Microsoft menggambarkan AiTM sebagai proxy yang berdiri di antara korban dan situs asli, memegang dua sesi TLS, sehingga bisa menangkap password dan session cookie yang membuktikan pengguna sudah login. Cookie itu diambil setelah autentikasi selesai, jadi penyerang tidak perlu melewati MFA, apa pun metode yang dipilih pengguna; Microsoft menegaskan ini bukan kerentanan MFA [S16]. Di kampanye yang diamati Microsoft, cookie itu dipakai membuka Outlook on the web tak lama kemudian, dan penipuan pembayaran bisa dimulai dalam hitungan menit setelah pencurian [S16]. Token theft playbook Microsoft merumuskannya sama: penyerang memutar ulang token yang diterbitkan untuk pengguna, walaupun pengguna sudah memenuhi MFA, dan karena syarat autentikasi terpenuhi, aksesnya diberikan [S9].

Ada beberapa jalan lain menuju hasil yang mirip. Bedanya penting karena menentukan apa yang dibersihkan:

| Jalur | Ciri di log | Yang dibersihkan selain identitas |
|---|---|---|
| AiTM | Login interactive dengan MFA sukses dari IP proxy, bukan IP pengguna; sesi yang sama lalu dipakai dari IP lain | Tidak ada di endpoint; perangkat pengguna bersih kecuali ada temuan lain |
| MFA fatigue | Banyak permintaan MFA ditolak atau tidak dijawab, lalu satu disetujui | Password sudah bocor lebih dulu; cari dari mana |
| Pencurian token dari endpoint | Token dipakai dari IP lain tanpa login interactive baru; alert EDR di perangkat | Host pengguna (infostealer, akses ke PRT); butuh investigasi endpoint |

Tabel ini dibaca dari kolom tengah: jalur mana yang cocok dengan log yang kamu lihat. Untuk `INC-2026-022`, sign-in 16:47 menunjukkan password dan Microsoft Authenticator dengan number matching sukses satu kali, tanpa penolakan sebelumnya, dari IP `198.51.100.141` padahal Rina sedang di kantor. Itu pola AiTM, bukan fatigue. Defender for Endpoint di `JKT-WS-0431` tidak menunjukkan alert atau proses mencurigakan; riwayat browser hanya menunjukkan kunjungan ke `jab-portal365.example.net` pukul 16:46. Safe Links di Defender for Office 365 mengizinkan klik itu karena domain tersebut baru didaftarkan dan belum dikenal berbahaya saat itu; perlindungan berbasis reputasi tautan tidak bisa diandalkan untuk menahan halaman AiTM yang baru dibuat. Token theft playbook memang meminta investigasi dipisah ke dua konteks, sesi pengguna dan perangkat, karena tindakannya berbeda [S9].

### 1.2 Log yang dipakai: interactive, non-interactive, audit, dan masa simpannya

Pertanyaan kedua Dimas punya jawaban teknis yang sederhana: tab yang biasa dibuka hanya separuh cerita.

Sign-in log Entra ID terbagi menjadi empat jenis: interactive user, non-interactive user, service principal, dan managed identity; tampilan sign-in log versi lama hanya berisi yang interactive [S1]. Sign-in non-interactive dilakukan atas nama pengguna oleh aplikasi atau komponen OS, tanpa pengguna memberikan faktor autentikasi, misalnya aplikasi yang memakai refresh token untuk mendapat access token baru [S2]. Aktivitas penyerang yang memutar ulang token banyak tercatat di sini, karena penyerang tidak mengetik password lagi. Token theft playbook meminta perhatian khusus untuk deteksi pada sign-in non-interactive, dan ID Protection menyebut sifat login tak dikenal pada sign-in non-interactive patut dicurigai lebih karena risiko token replay [S9][S10].

Ada tiga hal teknis yang mengubah cara membaca log ini:

- **Pengelompokan.** Di portal, sign-in non-interactive yang identik kecuali waktunya digabung menjadi satu baris bila aplikasi, pengguna, IP, status, dan resource ID sama; kolom jumlah sign-in menunjukkan berapa yang digabung [S2]. Satu baris di portal bisa berarti puluhan refresh token.
- **IP yang tercatat.** Untuk sign-in non-interactive oleh confidential client, IP yang tercatat adalah IP saat token pertama kali diterbitkan, bukan sumber permintaan refresh [S2]. IP di baris non-interactive tidak selalu menunjukkan dari mana penyerang sekarang.
- **Audit log terpisah dari sign-in log.** Perubahan di tenant, seperti pendaftaran metode MFA, perubahan role, atau registrasi perangkat, ada di audit log, bukan sign-in log [S1]. Audit log dan sign-in log Entra ID juga terpisah dari Unified Audit Log Microsoft 365, yang masa simpannya diatur Purview [S5].

Masa simpan menentukan apakah investigasi bisa dilakukan sama sekali. Entra ID menyimpan audit log dan sign-in log selama 7 hari di lisensi Free dan 30 hari di P1 atau P2. Upgrade lisensi tidak mengembalikan data yang sudah lewat; log bisa disimpan lebih lama dengan mengalirkannya lewat Azure Monitor ke storage atau alat analitik [S5]. Untuk sign-in berisiko, P1 menyimpan 30 hari dan P2 90 hari [S5]. Di PT JAB, tanpa aliran ke Splunk, insiden yang baru ditemukan pada minggu kelima sudah tidak punya sign-in log di Entra ID.

Konsekuensi lisensi P1 untuk investigasi juga perlu diketahui sejak awal. Detail sebagian besar deteksi risiko butuh P2; tenant tanpa P2 hanya melihat "Additional risk detected" dengan `riskEventType` `generic` [S10]. Field `riskLevelDuringSignIn` dan `riskDetail` di sign-in log bernilai `hidden` untuk tenant tanpa P2 [S4]. Deteksi Attacker in the Middle bahkan butuh Microsoft 365 E5 dengan EMS E5 [S10]. Jadi di PT JAB, analyst tidak bisa menunggu ID Protection memberi tahu; rule di Splunk yang harus melakukannya.

### 1.3 Membaca satu baris sign-in: siapa, bagaimana, apa, dan identifier yang mengikat

Pertanyaan ketiga adalah keterampilan inti Day ini. Dokumentasi Entra ID menyarankan membaca sign-in dari tiga komponen: siapa (user), bagaimana (aplikasi klien, authentication requirement), dan apa (resource yang diakses), lalu memakai identifier unik untuk menghubungkan sign-in ke aktivitas lain [S3].

Tabel berikut berisi field yang paling sering dipakai saat insiden. Kolom kanan menunjukkan pertanyaan yang dijawab field itu; nama field mengikuti properti Microsoft Graph [S4], dan kolom yang sama (misalnya `SessionId` dan `UniqueTokenIdentifier`) tersedia saat log diekspor ke Azure Monitor [S18].

| Field | Isi | Pertanyaan yang dijawab |
|---|---|---|
| `isInteractive`, `signInEventTypes` | `interactiveUser` atau `nonInteractiveUser` | Pengguna memberikan faktor, atau token dipakai ulang? |
| `ipAddress`, `autonomousSystemNumber`, `location` | IP, ASN, perkiraan lokasi | Dari jaringan mana? ASN hosting atau VPS lebih bermakna daripada negara |
| `userAgent`, `deviceDetail` | Browser, OS, `deviceId`, status compliant dan join | Perangkat terdaftar PT JAB, atau perangkat tanpa identitas? |
| `sessionId` | Identifier sesi yang dibuat saat sign-in | Sign-in mana yang berasal dari sesi yang sama? |
| `correlationId` | Identifier dari klien saat sign-in dimulai | Langkah mana yang termasuk satu percobaan login (misalnya beberapa event MFA)? |
| `uniqueTokenIdentifier` | Identifier untuk melacak token saat dipakai di resource provider | Token mana yang dipakai di layanan lain? |
| `authenticationRequirement`, `authenticationDetails` | Tahap autentikasi yang dicapai dan urutan metode beserta hasilnya | Login ini benar-benar memakai MFA, atau MFA dipenuhi klaim token lama? |
| `incomingTokenType` | Jenis token yang dibawa ke Entra ID (misalnya `primaryRefreshToken`, `refreshToken`) | Login memakai token apa? |
| `conditionalAccessStatus`, `appliedConditionalAccessPolicies` | `success`, `failure`, `notApplied` per kebijakan | Kebijakan mana yang dievaluasi dan hasilnya |
| `status.errorCode` | 0 berarti sukses; selain itu kode `AADSTS` | Kenapa gagal? |

Beberapa catatan dari dokumentasi yang sering membuat analyst salah baca [S3][S4]:

- Correlation ID didasarkan pada parameter dari klien, sehingga Entra ID tidak menjamin akurasinya. Pakai untuk mengelompokkan, bukan sebagai bukti.
- `authenticationRequirement` mencatat tahap autentikasi yang dicapai. Bila password gagal, sign-in tidak dievaluasi Conditional Access dan nilainya `singleFactorAuthentication`.
- Status CA `notApplied` berarti sign-in tidak memenuhi kriteria kebijakan atau tidak sampai dievaluasi, bukan berarti kebijakannya tidak ada. Status `success` bisa muncul walaupun hanya kondisi user dan aplikasi yang dievaluasi.
- Tab Authentication Details bisa sementara menampilkan "satisfied by claim in the token" secara keliru sebelum log selesai digabung.
- Waktu di portal ditampilkan dalam zona waktu orang yang membuka portal, sedangkan `createdDateTime` di Graph selalu UTC.
- Lokasi dari IP hanya perkiraan; VPN dan operator seluler bisa memberi IP yang jauh dari lokasi fisik pengguna.

Untuk AiTM, field yang paling berguna adalah `sessionId`. Microsoft menyebut salah satu indikator kampanye AiTM: session ID yang pertama terlihat saat login ke OfficeHome, lalu dipakai ulang di aplikasi lain, terutama dari negara lain [S16]. Di `INC-2026-022`, session ID dari login Rina 16:47 lewat proxy muncul lagi 16:52 dari `198.51.100.152`, ASN hosting yang tidak pernah dipakai pegawai PT JAB, dan semua baris itu tidak punya `deviceId`, sedangkan login Rina yang sah dari `JKT-WS-0431` selalu membawa `deviceId` perangkat hybrid joined yang compliant. Tiga sinyal itu (session sama, jaringan beda, perangkat tanpa identitas) lebih kuat daripada lokasi negara.

### 1.4 Reset password belum cukup: kelas token yang berbeda dicabut oleh tindakan yang berbeda

Pertanyaan keempat Dimas dijawab dengan tabel pencabutan token dari dokumentasi Microsoft. Day 05 bagian 1.5 sudah membahas bahwa access token tetap berlaku sampai kedaluwarsa setelah revoke; bagian ini menjelaskan kenapa reset password saja tidak bisa diandalkan.

Refresh token default berumur 90 hari (24 jam untuk single-page application), terikat ke kombinasi pengguna dan klien, tetapi tidak terikat ke resource atau tenant tertentu, sehingga satu refresh token bisa dipakai meminta access token untuk resource lain yang diizinkan [S7]. Server bisa mencabutnya karena perubahan kredensial, tindakan pengguna, atau tindakan admin. Dokumentasi membagi token menjadi lima kelas dan menunjukkan bahwa reset password tidak mencabut semuanya [S7]:

| Tindakan | Cookie berbasis password | Token berbasis password | Cookie bukan berbasis password | Token bukan berbasis password | Token confidential client |
|---|---|---|---|---|---|
| Pengguna mengganti password | Dicabut | Dicabut | Tetap hidup | Tetap hidup | Tetap hidup |
| Admin reset password di Entra admin center | Dicabut | Dicabut | Tetap hidup | Dicabut | Dicabut |
| Admin mencabut semua refresh token pengguna | Dicabut | Dicabut | Dicabut | Dicabut | Dicabut |

Tabel ini dibaca per baris: hanya baris terakhir yang mencabut semua kolom. Reset yang dijalankan helpdesk PT JAB di AD on-premises lalu disinkronkan ke cloud tidak tercantum sebagai baris tersendiri di dokumentasi, jadi efeknya pada setiap kelas token tidak bisa diasumsikan; cek perilakunya di lab bila ingin tahu. Karena itu Revoke sessions dijalankan eksplisit, tidak mengandalkan efek samping reset.

Revoke sessions pun punya batas yang sudah dibahas di Day 05: aplikasi yang memakai access token kehilangan akses saat token kedaluwarsa, dan aplikasi dengan session token sendiri baru berhenti saat sesinya berakhir atau aplikasinya mencabut [S6]. CAE memperpendek celah ini untuk layanan yang mendukungnya. Exchange Online, SharePoint Online, dan Teams berlangganan kejadian kritis dari Entra ID: akun dihapus atau dinonaktifkan, password diganti atau di-reset, MFA diaktifkan untuk pengguna, admin mencabut semua refresh token, dan risiko pengguna tinggi terdeteksi ID Protection [S8]. Targetnya hampir real time, tetapi jeda sampai 15 menit bisa terjadi karena propagasi [S8]. Ada dua hal yang sering terlewat:

- Klien yang mendukung CAE menerima access token berumur panjang, sampai 28 jam, karena pencabutan digerakkan kejadian, bukan waktu [S8]. Tanpa sinyal pencabutan, token itu tetap berlaku lebih lama daripada token biasa.
- Tidak semua kombinasi klien dan layanan didukung; misalnya Office web apps untuk Exchange Online tercatat tidak didukung, dan Teams hanya didukung sebagian [S8].

**Memverifikasi pencabutan.** Setelah Revoke sessions, verifikasi dilakukan di sign-in log, bukan dari keluaran perintah. Cari semua sign-in, interactive dan non-interactive, yang memakai session ID lama atau datang dari IP dan ASN penyerang. Yang diharapkan: permintaan refresh dari sesi lama ditolak dengan `50173` (grant dicabut, perlu token baru) dan cookie lama ditolak dengan `50133` (sesi tidak sah karena perubahan password) [S21], sedangkan sign-in sukses berikutnya untuk pengguna itu adalah login interactive baru dengan MFA dari perangkat yang dikenal. Ketiadaan baris dari penyerang belum membuktikan aksesnya berhenti, karena pemakaian access token yang sudah terbit terjadi di layanan dan tidak selalu punya entri di sign-in log; token theft playbook meminta log aktivitas layanan dan audit log ikut diperiksa [S9]. Di PT JAB, log mailbox dan OneDrive pengguna dipantau setidaknya satu jam setelah revoke, sesuai umur access token default, dan lebih lama untuk klien yang tidak mendukung CAE.

Selain token, reset password juga tidak menyentuh tiga hal: metode MFA yang sudah didaftarkan penyerang, perangkat yang mungkin ia daftarkan, dan apa yang sudah ia ambil. Microsoft, dalam kasus AiTM yang lain, menyatakan reset password bukan solusi efektif karena sesinya sudah terkompromi, dan meminta session cookie dicabut serta perubahan MFA yang dibuat penyerang dikembalikan [S17]. Token theft playbook menyusunnya sebagai daftar: ganti password, blokir pengguna, cabut token, tandai akun terkompromi, hapus kredensial dan perangkat yang ditambahkan sebelum akun diaktifkan lagi, lalu ulangi sampai semua akun dan perangkat terdampak ditemukan [S9].

### 1.5 Persistence di identitas: metode MFA, perangkat, consent, dan aturan mailbox

Pertanyaan kelima Dimas ("nomor telepon asing itu artinya apa?") menyentuh pola yang sering muncul setelah pencurian token: penyerang menanam jalan masuk baru sebelum token yang dicuri habis.

Dalam kasus AiTM yang dilaporkan Microsoft pada 2023, penyerang menambahkan metode OTP berbasis telepon di samping metode MFA milik pengguna, dan Microsoft mencatat bahwa menambahkan metode MFA secara default tidak meminta autentikasi ulang [S17]. Dengan metode itu, penyerang yang kelak mendapat password baru (misalnya lewat phishing berikutnya) bisa menyelesaikan MFA sendiri tanpa Rina. Token theft playbook menyebut empat bentuk persistence yang dicari: pendaftaran MFA, pendaftaran perangkat, aturan forwarding mailbox, dan inbox rule [S9]. Consent aplikasi OAuth adalah bentuk kelima yang umum, dan dicatat di audit log.

Tabel berikut memetakan setiap bentuk ke nama aktivitas di audit log Entra ID [S11], supaya pencarian tidak bergantung pada ingatan. Aturan mailbox tidak ada di audit log Entra ID; itu dicari di log Exchange (Day 09 bagian 1.3 dan 2.1).

| Persistence | Nama aktivitas di audit log | Kategori |
|---|---|---|
| Metode MFA baru oleh pengguna | `User registered security info`, `User changed default security info` | UserManagement |
| Metode MFA diubah admin | `Admin registered security info`, `Admin updated security info` | UserManagement |
| Perangkat didaftarkan | `Register device` | Device |
| Consent aplikasi | `Consent to application` | ApplicationManagement |
| Kredensial ditambahkan ke service principal | `Add service principal credentials` | ApplicationManagement |
| Role ditambahkan | `Add member to role`, `Add eligible member to role` | RoleManagement |

Di `INC-2026-022`, audit log menunjukkan `User registered security info` pukul 17:04:55 dengan inisiator `rina.wulandari@jab.example` dari `198.51.100.152`, untuk metode telepon `+1 555 0163`. Tidak ada `Register device`, `Consent to application`, atau perubahan role dari akun Rina atau dari IP penyerang. Pemeriksaan aturan mailbox diserahkan ke Yoga dengan langkah Day 09 bagian 2.1.

Alert `SOC-2026-0230` sebenarnya sudah menangkap kejadian ini pukul 17:06, tetapi L1 menutupnya sebagai "kemungkinan ganti HP" tanpa verifikasi ke pengguna. Pendaftaran metode MFA dari jaringan yang tidak pernah dipakai pengguna adalah salah satu sinyal token theft yang disebut playbook Microsoft [S9]; verifikasinya murah, cukup telepon ke nomor yang tercatat di HR, bukan ke nomor yang baru didaftarkan.

### 1.6 Akun admin milik orang yang sama: kesimpulan dari bukti, rotasi karena murah

Pertanyaan keenam Dimas adalah pertanyaan blast radius (Day 03 bagian 1.5) untuk identitas. Akun `adm.rina` punya role Entra ID User Administrator dan hak admin server di AD; bila penyerang memegangnya, insiden berubah menjadi SEV-1.

Token theft playbook meminta akun berhak tinggi yang terdampak diperiksa dengan meninjau perubahan yang dibuat setelah kompromi, dan memberi contoh query untuk perubahan security info pada pengguna dengan role admin [S9]. Dari sana, PT JAB memakai empat pertanyaan yang masing-masing dijawab dari log yang berbeda:

1. **Apakah ada sign-in sukses `adm.rina` dari jaringan atau perangkat yang tidak biasa?** Sign-in log interactive dan non-interactive, 30 hari terakhir di Splunk.
2. **Apakah ada aktivitas di audit log yang diinisiasi `adm.rina` di luar pekerjaan yang diketahui?** Audit log, terutama `RoleManagement`, `UserManagement`, dan reset password pengguna lain.
3. **Apakah ada logon `adm.rina` di AD dari host yang tidak semestinya?** Event logon Windows di domain controller; kebijakan PT JAB hanya mengizinkan `adm.rina` dari `JKT-JUMP01`.
4. **Apakah penyerang bisa mendapat kredensial `adm.rina` dari apa yang ia baca?** Isi mailbox dan OneDrive Rina yang diakses penyerang (Day 09 bagian 1.5 dan 2.3).

Hasilnya di `INC-2026-022`: satu sign-in interactive `adm.rina` pukul 17:31:08 dari `198.51.100.152` gagal dengan `50126` (username atau password salah) [S21]; `authenticationRequirement` bernilai `singleFactorAuthentication` dan CA `notApplied`, sesuai perilaku saat password gagal [S3]. Tidak ada sign-in sukses dari luar `JKT-JUMP01`, tidak ada aktivitas audit yang tidak dikenal, dan pencarian Yoga atas item mailbox yang dibuka penyerang tidak menemukan password `adm.rina`. Log tidak mencatat password apa yang dicoba, jadi tidak bisa disimpulkan apakah penyerang mencoba password Rina.

Kesimpulan ditulis dengan tingkat keyakinan, bukan "aman": tidak ada bukti `adm.rina` dipakai penyerang, dengan keyakinan sedang, karena penyerang jelas berniat mencobanya. Tindakan pencegahan untuk `adm.rina` (reset dua kali dan revoke sessions) tetap dijalankan karena harganya hanya beberapa menit kerja Rina. Ini berbeda dengan menyatakan `adm.rina` terkompromi: pernyataan itu akan memicu pemeriksaan semua akun yang pernah di-reset `adm.rina` dan menaikkan severity, padahal buktinya tidak ada.

### 1.7 Conditional Access: tutup jalur yang dipakai, jangan hanya menambah prompt

Pertanyaan terakhir Dimas biasanya dijawab dengan "MFA lebih sering". Itu jawaban yang keliru, karena MFA Rina berjalan dengan benar.

Conditional Access hanya dievaluasi saat token diterbitkan, setelah autentikasi awal [S13]. Perbaikan yang efektif adalah syarat yang tidak bisa dipenuhi penyerang yang memutar ulang token dari VPS. Tabel berikut membandingkan pilihan untuk PT JAB berdasarkan jalur yang dipakai di `INC-2026-022`; kolom "Menutup jalur ini?" adalah yang harus dibaca lebih dulu.

| Kontrol | Apa yang dilakukan | Menutup jalur ini? | Batas |
|---|---|---|---|
| Wajib perangkat compliant atau hybrid joined untuk M365 | Token hanya diterbitkan untuk perangkat yang dikelola PT JAB | Ya untuk replay dari VPS tanpa identitas perangkat; Microsoft merekomendasikannya melawan AiTM [S16][S17] | Butuh pengecualian dan proses untuk perangkat pribadi |
| Kebijakan untuk user action Register security information | Pendaftaran metode dari luar lokasi tepercaya butuh authentication strength tertentu; pengguna baru memakai Temporary Access Pass [S12] | Ya untuk pendaftaran metode dari VPS, bila strength yang diminta tidak bisa dipenuhi klaim MFA dari sesi curian | Mulai 6 Juli 2026 kebijakan ini juga berlaku saat registrasi Windows Hello for Business; uji di report-only [S12] |
| Authentication strength phishing-resistant untuk akun admin | Hanya Windows Hello for Business, FIDO2, atau certificate-based authentication multifactor [S13] | Ya untuk akun admin: metode ini terikat ke halaman login asli sehingga proxy tidak bisa meneruskannya | Perlu distribusi kunci FIDO2 atau WHfB ke admin |
| Token protection | Hanya menerima sign-in session token yang terikat ke perangkat (PRT) [S14] | Sebagian: untuk aplikasi native di Exchange, SharePoint, dan Teams; untuk aplikasi berbasis browser masih preview dan terbatas pada aplikasi yang mengakses Azure Resource Manager [S14] | Tidak melindungi Outlook on the web yang dipakai penyerang di kasus ini |
| Sign-in frequency lebih pendek | Memaksa login ulang setelah waktu tertentu; default rolling window 90 hari [S15] | Tidak; hanya memperpendek umur sesi curian | Microsoft mengingatkan prompt terlalu sering membuat pengguna terbiasa memasukkan kredensial dan rentan phishing [S15] |
| Blokir IP penyerang di CA | Menolak token dari IP tertentu | Tidak; penyerang mengganti IP dengan murah [S9] | Berguna sebagai containment jangka pendek saja |

Semua kontrol baru diterapkan dulu dalam mode report-only, lalu dinaikkan ke On setelah dampaknya dibaca dari sign-in log; dokumentasi Microsoft menyarankan pola ini untuk token protection dan kebijakan registrasi [S12][S14]. Akun break-glass dikecualikan dari setiap kebijakan baru [S12].

Ada dua kontrol yang tidak bisa dipakai PT JAB dengan lisensi sekarang: kebijakan berbasis risiko pengguna dan risiko sign-in, karena deteksi risiko yang rinci butuh P2 [S10]. Ini dicatat di rekomendasi post-incident sebagai keputusan anggaran untuk executive sponsor, bukan sebagai hal yang diam-diam dilewati.

## 2. Contoh artefak dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Log sign-in dan audit Entra ID masuk ke index `o365` di Splunk lewat Event Hub. Tim SOC PT JAB membuat field alias yang mengikuti nama properti Graph supaya query tidak bergantung pada struktur JSON add-on: `user` (userPrincipalName), `signin_type` (`interactiveUser` atau `nonInteractiveUser`), `app`, `src_ip`, `src_asn`, `session_id`, `device_id`, `auth_req`, `auth_method`, `ca_status`, dan `result_code`; untuk audit log `activity`, `initiated_by`, `target`, dan `src_ip`. Nama field asli dan sourcetype bergantung pada add-on dan cara ekspor yang kamu pakai, jadi cek di lingkunganmu sebelum menyalin query. Semua waktu dalam WIB.

### 2.1 Semua sign-in Rina dalam satu urutan waktu

Query ini menjawab pertanyaan kedua dan ketiga Dimas: menampilkan sign-in interactive dan non-interactive bersamaan, sehingga sesi penyerang terlihat utuh.

**Tujuan:** menyusun timeline sign-in `rina.wulandari` dari Rabu sore sampai setelah containment.

```
index=o365 sourcetype="azure:monitor:aad" signin_type=*
    user="rina.wulandari@jab.example"
    earliest="10/28/2026:16:00:00" latest="10/29/2026:10:30:00"
| eval device=if(isnull(device_id) OR device_id="", "-", "terdaftar")
| table _time signin_type app src_ip src_asn session_id auth_req auth_method ca_status device result_code
| sort _time
```

Penjelasan tiap bagian:

- `signin_type=*` sengaja tidak memfilter jenis, supaya interactive dan non-interactive muncul bersama. Bila ekspor di lingkunganmu hanya berisi sign-in interactive, query ini akan tampak "bersih" padahal tidak.
- `device` mengubah `device_id` menjadi tanda ada atau tidak ada, karena yang dicari adalah perangkat tanpa identitas, bukan nilai ID-nya.
- `session_id` ditampilkan utuh untuk dipakai di query bagian 2.2.

Keluaran ilustrasi (session ID diringkas):

```
_time                signin_type          app                 src_ip           src_asn  session_id  auth_req                    auth_method                     ca_status   device     result_code
2026-10-28 08:02:11  interactiveUser      Windows Sign In     198.51.100.120   64500    0d7e...     multiFactorAuthentication   PRT                             success     terdaftar  0
2026-10-28 16:47:12  interactiveUser      OfficeHome          198.51.100.141   64502    a3f1...     multiFactorAuthentication   Password; Authenticator (push)  success     -          0
2026-10-28 16:52:40  interactiveUser      Outlook Web         198.51.100.152   64501    a3f1...     multiFactorAuthentication   satisfied by claim in token     success     -          0
2026-10-28 17:04:31  interactiveUser      My Signins          198.51.100.152   64501    a3f1...     multiFactorAuthentication   satisfied by claim in token     success     -          0
2026-10-28 17:52:40  nonInteractiveUser   Outlook Web         198.51.100.152   64501    a3f1...     multiFactorAuthentication   -                               success     -          0
2026-10-28 22:10:05  nonInteractiveUser   OneDrive            198.51.100.152   64501    a3f1...     multiFactorAuthentication   -                               success     -          0
2026-10-29 07:41:19  interactiveUser      Windows Sign In     198.51.100.120   64500    5c22...     multiFactorAuthentication   PRT                             success     terdaftar  0
2026-10-29 09:41:02  nonInteractiveUser   Outlook Web         198.51.100.152   64501    a3f1...     multiFactorAuthentication   -                               failure     -          50173
2026-10-29 09:44:17  interactiveUser      OfficeHome          198.51.100.152   64501    a3f1...     singleFactorAuthentication  -                               notApplied  -          50133
2026-10-29 10:02:48  interactiveUser      OfficeHome          198.51.100.158   64501    -           singleFactorAuthentication  Password                        notApplied  -          50126
```

Cara membaca hasil:

- Baris 08:02 dan 07:41 adalah Rina sendiri: IP egress kantor `198.51.100.120` (ASN PT JAB `64500`), token PRT, perangkat terdaftar. Dua baris ini menjadi pembanding untuk semua baris lain.
- Baris 16:47 adalah login Rina lewat proxy AiTM. MFA-nya sah, tetapi IP dan ASN adalah milik proxy, dan perangkat tidak dikenali karena browser Rina tidak berbicara langsung ke Entra ID.
- Baris 16:52 sampai 22:10 memakai session ID yang sama dari `198.51.100.152`. MFA dipenuhi klaim token, bukan prompt baru. Baris 17:04 ke My Signins tepat sebelum metode telepon didaftarkan pukul 17:04:55 (bagian 2.3).
- Setelah Revoke sessions pukul 09:31, refresh dari sesi lama ditolak dengan `50173` (grant dicabut, perlu token baru) dan cookie lama ditolak dengan `50133` (sesi tidak sah karena perubahan password) [S21]. Pukul 10:02 penyerang pindah ke `198.51.100.158` dan mencoba password, gagal `50126`. Perpindahan IP itu yang membuat blokir IP tidak bisa diandalkan.

**Variasi:** ganti `user` dengan `adm.rina@jab.example` untuk pertanyaan bagian 1.6, atau hapus filter `user` dan ganti dengan `src_ip IN ("198.51.100.141", "198.51.100.152", "198.51.100.158")` untuk mencari korban lain dari infrastruktur yang sama.

**Kapan gagal:** kategori non-interactive tidak ikut diekspor ke SIEM, atau ekspor baru dikonfigurasi setelah insiden sehingga hanya 30 hari terakhir yang bisa diambil dari Entra ID [S5].

### 2.2 Session ID yang dipakai dari lebih dari satu jaringan

Query ini adalah dasar rule `SOC-2026-0236` dan menjawab pertanyaan ketiga untuk seluruh tenant: siapa lagi yang sesinya dipakai dari tempat lain.

**Tujuan:** menemukan session ID yang muncul dari lebih dari satu ASN dalam 24 jam, pola reuse yang disebut Microsoft untuk AiTM [S16].

```
index=o365 sourcetype="azure:monitor:aad" signin_type=* result_code=0
    earliest=-24h
| where isnotnull(session_id) AND session_id!=""
| stats dc(src_asn) as asn_count values(src_asn) as asn values(src_ip) as ip
        values(app) as apps dc(device_id) as dev_count min(_time) as first max(_time) as last
        by user session_id
| where asn_count > 1
| convert ctime(first) ctime(last)
| sort - asn_count
```

Penjelasan tiap bagian:

- `result_code=0` hanya mengambil sign-in sukses; sesi yang gagal tidak memberi akses.
- `dc(src_asn)` dipakai, bukan `dc(src_ip)`, karena IP pengguna sah bisa berganti dalam satu ASN (DHCP operator seluler) tanpa berarti apa-apa.
- `dev_count` membantu membedakan: sesi yang sah biasanya dari satu perangkat.

Keluaran ilustrasi:

```
user                          session_id  asn_count  asn            ip                              apps                                   dev_count  first                last
rina.wulandari@jab.example    a3f1...     2          64501 64502    198.51.100.141 198.51.100.152   OfficeHome Outlook Web My Signins OneDrive  0     10/28/2026 16:47:12  10/28/2026 22:10:05
maya.lestari@jab.example      91bc...     2          64500 64510    198.51.100.120 203.0.113.158     OfficeHome Teams                        1          10/28/2026 18:20:44  10/28/2026 19:02:10
```

Cara membaca hasil: sesi Rina punya dua ASN yang keduanya bukan PT JAB dan nol perangkat, pola yang cocok dengan bagian 1.3. Sesi Maya Lestari berpindah dari kantor ke `64510`, yang setelah dicek adalah operator seluler tempat laptop Maya ditambatkan ke HP saat pulang, dengan perangkat yang sama; ini benign dan dicatat sebagai pengecualian yang diketahui.

**Kapan gagal:** session ID kosong untuk jenis sign-in tertentu, atau penyerang memakai proxy residensial di ASN operator yang sama dengan pengguna. Karena itu rule ini digabung dengan sinyal lain (perangkat tanpa identitas, user agent) sebelum dinaikkan.

### 2.3 Audit log: persistence dan perubahan oleh akun terkait

Query ini menjawab pertanyaan kelima dan sebagian pertanyaan keenam: apa yang diubah di tenant oleh atau terhadap Rina dan `adm.rina`, serta apa saja yang datang dari IP penyerang.

**Tujuan:** mencari aktivitas persistence dan perubahan berhak tinggi dalam jendela insiden, memakai nama aktivitas dari referensi audit log Entra ID [S11].

```
index=o365 sourcetype="azure:monitor:aad" activity=*
    earliest="10/28/2026:16:00:00" latest="10/29/2026:10:30:00"
    (initiated_by IN ("rina.wulandari@jab.example", "adm.rina@jab.example")
     OR target IN ("rina.wulandari@jab.example", "adm.rina@jab.example")
     OR src_ip IN ("198.51.100.141", "198.51.100.152", "198.51.100.158"))
| search activity IN ("User registered security info", "User changed default security info",
    "User deleted security info", "Admin registered security info", "Admin updated security info",
    "Register device", "Consent to application", "Add service principal credentials",
    "Add member to role", "Add eligible member to role", "Reset password", "Update user",
    "Disable account")
| table _time activity initiated_by target src_ip
| sort _time
```

Penjelasan tiap bagian:

- Tiga kondisi digabung dengan `OR`: aktivitas oleh akun terkait, aktivitas terhadap akun terkait (misalnya admin lain menambahkan role), dan aktivitas apa pun dari IP penyerang.
- Daftar aktivitas memuat bentuk persistence dari bagian 1.5 dan tindakan berhak tinggi yang bisa dilakukan `adm.rina` sebagai User Administrator.

Keluaran ilustrasi:

```
_time                activity                         initiated_by                    target                          src_ip
2026-10-28 17:04:55  User registered security info    rina.wulandari@jab.example      rina.wulandari@jab.example      198.51.100.152
2026-10-29 08:45:37  Reset password                   Entra Connect (sync)         rina.wulandari@jab.example      -
2026-10-29 09:31:10  Admin deleted security info      adm.yoga@jab.example            rina.wulandari@jab.example      10.20.1.20
2026-10-29 09:32:04  Reset password                   Entra Connect (sync)         adm.rina@jab.example            -
```

Cara membaca hasil:

- Satu-satunya perubahan dari IP penyerang adalah pendaftaran security info. Tidak ada perangkat, consent, kredensial aplikasi, atau role.
- Reset 08:45 adalah reset helpdesk di AD yang tersinkron; reset 09:32 adalah reset pencegahan `adm.rina` di jam H.
- Penghapusan metode 09:31 oleh `adm.yoga` dari bastion adalah tindakan containment (bagian 2.4).
- Tidak ada baris dengan `initiated_by` `adm.rina` di jendela ini. Ini salah satu bukti untuk pertanyaan keenam.

**Kapan gagal:** aktivitas dilakukan lewat portal atau API dengan nama aktivitas yang tidak ada di daftar. Untuk jendela yang lebih lebar, jalankan dulu tanpa filter `activity` dan baca semua aktivitas dari IP penyerang.

### 2.4 Containment identitas: perintah dan urutannya

Langkah ini menjawab pertanyaan keempat Dimas. Semua tindakan dijalankan Kamis pukul 09:30 dalam satu jendela, dari bastion `jkt-bastion01` dengan akun `adm.yoga` yang tidak pernah login ke perangkat Rina, mengikuti urutan bagian 1.4 dan prinsip serentak di Day 05 bagian 1.7.

**Tujuan:** mencabut semua token Rina, menghapus metode MFA penyerang, menyelesaikan reset kedua, dan menjalankan rotasi pencegahan untuk `adm.rina`.

```powershell
# AD on-premises (modul ActiveDirectory): reset kedua untuk Rina, dua kali untuk adm.rina
Set-ADAccountPassword -Identity rina.wulandari -Reset -NewPassword (Read-Host -AsSecureString "Password acak Rina")
Set-ADAccountPassword -Identity adm.rina -Reset -NewPassword (Read-Host -AsSecureString "Password acak adm 1")
Set-ADAccountPassword -Identity adm.rina -Reset -NewPassword (Read-Host -AsSecureString "Password acak adm 2")

# Entra ID (Microsoft Graph PowerShell SDK)
Connect-MgGraph -Scopes "User.ReadWrite.All","Directory.AccessAsUser.All","UserAuthenticationMethod.ReadWrite.All"

# 1. Lihat semua metode autentikasi Rina
Get-MgUserAuthenticationMethod -UserId rina.wulandari@jab.example |
    Select-Object Id, @{n='Type';e={$_.AdditionalProperties['@odata.type']}}

# 2. Hapus metode telepon yang didaftarkan penyerang (Id dari langkah 1)
Remove-MgUserAuthenticationPhoneMethod -UserId rina.wulandari@jab.example -PhoneAuthenticationMethodId $PhoneMethodId

# 3. Cabut semua refresh token dan session cookie
Revoke-MgUserSignInSession -UserId rina.wulandari@jab.example
Revoke-MgUserSignInSession -UserId adm.rina@jab.example
```

Penjelasan tiap bagian:

- Reset kedua untuk Rina menyelesaikan pola reset dua kali [S6], karena reset helpdesk 08:45 baru satu kali. `adm.rina` di-reset dua kali sebagai pencegahan.
- `Get-MgUserAuthenticationMethod` menampilkan semua metode yang terdaftar beserta jenisnya; `Remove-MgUserAuthenticationPhoneMethod` menghapus satu metode telepon berdasarkan Id-nya [S19][S20]. Metode dihapus sebelum Rina diizinkan login lagi, sesuai urutan di token theft playbook [S9].
- `Revoke-MgUserSignInSession` mencabut semua kelas refresh token dan cookie [S7], dan menjadi kejadian kritis untuk layanan yang mendukung CAE [S8].
- Akun Rina tidak dinonaktifkan. Rina perlu bekerja hari itu, penyerang tidak lagi punya password atau metode MFA, dan semua sesinya dicabut; menonaktifkan akun tidak menambah perlindungan yang berarti dibanding harganya. Pilihan ini ditulis di case notes beserta alasannya.

Keluaran ilustrasi (diringkas):

```
PS> Get-MgUserAuthenticationMethod -UserId rina.wulandari@jab.example | Select Id, Type
Id                                    Type
--                                    ----
28c10230-6103-485e-b985-444c60001490  #microsoft.graph.passwordAuthenticationMethod
6e2f9a41-0d3b-4c7e-9f15-2b8d7c4e1a90  #microsoft.graph.microsoftAuthenticatorAuthenticationMethod
3179e48a-750b-4051-897c-87b9720928f7  #microsoft.graph.phoneAuthenticationMethod

PS> Revoke-MgUserSignInSession -UserId rina.wulandari@jab.example
Value
-----
True
```

Cara membaca hasil: tiga metode terdaftar. Password dan Authenticator dikenali Rina (Authenticator terdaftar sejak 2025 dari perangkat kantor); metode telepon adalah yang didaftarkan 17:04:55. `True` dari revoke berarti permintaan diterima, belum berarti penyerang sudah tidak punya akses; buktinya dicari di sign-in log setelah 09:31 (bagian 2.1, baris 09:41 sampai 10:02).

**Variasi:** bila yang didaftarkan penyerang adalah aplikasi Authenticator, pakai cmdlet penghapus untuk jenis metode itu dengan Id dari langkah 1; token theft playbook memberi contoh panggilan Graph untuk menghapus metode email dan Authenticator serta perangkat yang didaftarkan [S9].

**Kapan gagal:** akun yang menjalankan perintah tidak punya role yang cukup. Menonaktifkan akun yang memegang role admin butuh Privileged Authentication Administrator, bukan User Administrator [S6]; role yang dibutuhkan untuk mengelola metode autentikasi akun admin juga perlu dicek di dokumentasi role Entra ID. Karena itu role untuk `adm.yoga` disiapkan sebelum jam H, bukan diminta di tengah jendela.

### 2.5 Penilaian `adm.rina` untuk IC

Dokumen ini menjawab pertanyaan keenam Dimas. Bentuknya sama dengan scope statement di Day 03: yang diketahui, yang tidak, keyakinan, dan tindakan.

```
INC-2026-022 | Penilaian akun adm.rina | Kamis 2026-10-29 10:20 WIB
Disusun: Sari Kusuma (TL) | Untuk: Dimas Prasetyo (IC)

PERTANYAAN: apakah penyerang memakai atau memegang kredensial adm.rina?

BUKTI
1. Sign-in Entra ID 2026-09-29 s.d. 2026-10-29 (Splunk, interactive + non-interactive):
   satu percobaan dari 198.51.100.152, Rabu 17:31:08, gagal 50126 (password salah).
   Tidak ada sign-in sukses dari luar JKT-JUMP01 / egress kantor.
2. Audit log Entra ID: tidak ada aktivitas dengan initiated_by adm.rina di jendela
   insiden. Aktivitas 30 hari terakhir cocok dengan tiket perubahan Rina.
3. Logon AD adm.rina (event logon di JKT-DC01, JKT-DC02): hanya dari JKT-JUMP01.
4. Mailbox dan OneDrive Rina (analisis Yoga, Day 09 bagian 2.3): tidak ada item berisi password
   adm.rina di antara item yang dibuka penyerang.

YANG TIDAK DIKETAHUI
- Password yang dicoba pukul 17:31 tidak tercatat di log.

KESIMPULAN: tidak ada bukti adm.rina dipakai atau dipegang penyerang. Keyakinan
sedang, karena penyerang jelas mencoba akun itu.

TINDAKAN (sudah, 09:32): reset dua kali, revoke sessions.
REKOMENDASI: severity tetap SEV-2. adm.rina dimasukkan ke kebijakan CA admin
(phishing-resistant + JKT-JUMP01) saat kebijakan itu diaktifkan (bagian 2.6).
```

Cara membaca elemennya:

- **Setiap bukti menyebut sumber log dan rentang waktunya.** "Tidak ada sign-in sukses" tanpa rentang dan sumber tidak bisa diperiksa ulang.
- **Yang tidak diketahui ditulis.** Kesimpulan yang terdengar lebih pasti daripada buktinya akan dipakai orang lain sebagai fakta.
- **Tindakan pencegahan dipisah dari kesimpulan.** Rotasi tidak berarti `adm.rina` terkompromi.

### 2.6 Usulan perubahan Conditional Access

Usulan ini menjawab pertanyaan ketujuh dan dikirim Sari ke Dimas dan Bambang Hartono (pemilik konfigurasi tenant di tim Infrastruktur) setelah containment. Setiap kebijakan dimulai dalam report-only.

| No | Kebijakan | Target | Syarat | Mode awal | Menutup |
|---|---|---|---|---|---|
| CA-10 | Register security information | Semua pengguna, kecuali break-glass dan tamu | Di luar lokasi tepercaya PT JAB wajib authentication strength phishing-resistant; pengguna baru memakai Temporary Access Pass | Report-only 14 hari | Pendaftaran metode dari VPS seperti 17:04:55 |
| CA-11 | Admin phishing-resistant | Semua akun `adm.*` dan role Entra ID | Authentication strength phishing-resistant dan hanya dari `JKT-JUMP01` | Report-only 7 hari, pilot 3 admin | Akun admin tidak bisa diproxy AiTM |
| CA-12 | M365 dari perangkat terkelola | Semua pengguna untuk Exchange, SharePoint, Teams | Perangkat compliant atau hybrid joined; perangkat pribadi hanya akses web terbatas | Report-only 30 hari | Replay token dari perangkat tanpa identitas |
| CA-13 | Token protection | Pilot IT dan Keuangan, aplikasi native Windows | Sign-in session token harus terikat perangkat | Report-only, analisis sign-in interactive dan non-interactive | Replay token aplikasi native dari mesin lain |

Cara membaca elemennya:

- **Kolom "Menutup" mengaitkan setiap kebijakan ke langkah penyerang** yang benar-benar terjadi. Kebijakan yang tidak bisa diisi kolom ini perlu alasan lain.
- **CA-12 punya masa report-only paling lama** karena dampaknya ke seluruh pegawai paling besar, termasuk staf POP yang memakai perangkat pribadi.
- **Kebijakan berbasis risiko tidak ada di tabel** karena butuh P2; dicatat terpisah di laporan sebagai keputusan anggaran.

**Kapan gagal:** kebijakan dinaikkan ke On tanpa membaca hasil report-only, lalu staf NOC yang memakai perangkat pribadi saat on-call malam tidak bisa membuka Teams. Kebijakan dicabut darurat, dan perbaikannya mundur berbulan-bulan.

### 2.7 Hunting sign-in untuk semua penerima phishing sekaligus

Langkah ini menjawab pertanyaan scoping yang muncul setiap kali satu akun terbukti kena: siapa lagi dari penerima email yang sama yang sesinya atau password-nya ikut dipakai. Email "Jadwal Maintenance POP Q4" dikirim ke tujuh orang di IT Infrastruktur dan NOC; daftar penerimanya diambil dari message trace (Day 08 bagian 2.2) dan disimpan sebagai lookup `inc022_penerima.csv` dengan satu kolom `user`.

**Tujuan:** untuk setiap penerima, merangkum sign-in dari luar jaringan kantor sejak email diterima, dengan sinyal yang dipakai di bagian 1.3: sukses atau gagal, perangkat tanpa identitas, dan jumlah sesi.

```
index=o365 sourcetype="azure:monitor:aad" signin_type=*
    [| inputlookup inc022_penerima.csv | fields user]
    earliest="10/28/2026:16:40:00" latest="10/29/2026:10:30:00"
| where src_asn!="64500"
| eval tanpa_device=if(isnull(device_id) OR device_id="", 1, 0)
| stats count(eval(result_code="0")) as sukses count(eval(result_code!="0")) as gagal
        sum(tanpa_device) as tanpa_device dc(session_id) as sesi
        values(src_asn) as asn values(src_ip) as ip min(_time) as first
        by user
| convert ctime(first)
| sort - sukses
```

Penjelasan tiap bagian:

- Subsearch `inputlookup` mengubah daftar penerima menjadi filter `user=... OR user=...`, sehingga satu query mencakup semua penerima.
- `src_asn!="64500"` membuang sign-in dari jaringan kantor PT JAB; yang tersisa adalah sign-in dari rumah, operator seluler, VPN, atau penyerang.
- `count(eval(...))` menghitung sukses dan gagal terpisah. Gagal yang banyak lalu sukses adalah pola password yang dicuri; sukses tanpa gagal dengan perangkat kosong adalah pola cookie yang dipakai ulang.

Keluaran ilustrasi:

```
user                         sukses  gagal  tanpa_device  sesi  asn          ip                               first
rina.wulandari@jab.example        5      3             8     1  64501 64502  198.51.100.141 198.51.100.152    10/28/2026 16:47:12
                                                                             198.51.100.158
fajar.nugraha@jab.example         4      0             0     1  64505        203.0.113.144                    10/28/2026 19:15:30
```

Cara membaca hasil:

- Lima penerima tidak muncul sama sekali: semua sign-in mereka di jendela ini dari jaringan kantor.
- Rina muncul dengan pola yang sudah dibahas di bagian 2.1. Angka gagal 3 adalah percobaan setelah containment.
- Fajar Nugraha, teknisi POP Bandung, punya empat sign-in sukses dari operator seluler, semuanya dengan perangkat terdaftar dan satu sesi. Sari mengonfirmasi lewat telepon bahwa Fajar memakai tethering di lokasi POP; benign, dicatat di case notes.
- Hasil ini masuk ke scope statement: satu dari tujuh penerima terdampak, dengan dasar data sign-in, bukan dengan asumsi "yang lain tidak klik".

**Variasi:** jalankan query audit bagian 2.3 dengan `target` dari lookup yang sama untuk mencari pendaftaran security info pada penerima lain. Untuk phishing kredensial tanpa proxy, seperti halaman palsu yang hanya mengambil password, perhatikan pola gagal lalu sukses dari ASN yang sama, karena penyerang login sendiri dan harus melewati MFA; sinyal session ID tidak relevan di pola itu.

**Kapan gagal:** daftar penerima tidak lengkap, misalnya karena email diteruskan ke orang lain atau ada salinan di grup distribusi. Ambil daftar dari message trace termasuk ekspansi grup, dan tambahkan siapa pun yang membuka domain phishing di log proxy.

### 2.8 Checklist pemulihan akun setelah kompromi identitas

Checklist ini dipakai PT JAB untuk setiap akun yang terbukti dipakai penyerang, termasuk Rina. Urutannya penting: semua yang ditanam penyerang dihapus sebelum akun dinyatakan pulih, karena token theft playbook meminta metode dan perangkat asing dihapus sebelum akun diaktifkan kembali [S9]. Kolom "Verifikasi" adalah yang dicentang di case notes, bukan kolom "Langkah".

| No | Langkah | Kenapa | Verifikasi |
|---|---|---|---|
| 1 | Revoke sessions | Mencabut semua kelas refresh token dan cookie [S7] | Sign-in dari sesi lama ditolak `50173` atau `50133` (bagian 1.4) |
| 2 | Hapus metode MFA dan perangkat yang tidak dikenali pengguna | Persistence yang tidak hilang saat password diganti [S9][S17] | Daftar metode dicek bersama pengguna lewat telepon ke nomor yang tercatat di HR |
| 3 | Cabut consent aplikasi OAuth dan app role assignment yang tidak dikenal | Aplikasi yang sudah diberi consent tetap bisa mengakses data walaupun password di-reset atau MFA diwajibkan [S22] | Halaman Applications pengguna kosong dari aplikasi asing; `Remove-MgOauth2PermissionGrant` atau `Remove-MgServicePrincipalAppRoleAssignment` untuk yang dicabut lewat PowerShell [S22] |
| 4 | Hapus inbox rule dan forwarding yang dibuat penyerang | Penyerang tetap menerima atau menyembunyikan email tanpa login (Day 09 bagian 1.3) [S9] | Daftar rule mailbox dicek ulang setelah penghapusan |
| 5 | Reset password dua kali di AD | Mengurangi risiko pass-the-hash dan keterlambatan replikasi [S6] | `PasswordLastSet` dan aktivitas reset di audit log |
| 6 | Kembalikan perubahan yang dibuat akun selama dikuasai | Role, pengguna lain, atau konfigurasi yang diubah penyerang [S9] | Query audit bagian 2.3 kosong dari perubahan yang belum dikembalikan |
| 7 | Daftar ulang MFA bila metode asli diragukan | Bila tidak jelas metode mana milik pengguna, hapus semua lalu terbitkan Temporary Access Pass setelah identitas diverifikasi; TAP memenuhi syarat MFA untuk registrasi [S12] | Pengguna mendaftar dari perangkat kantor; audit menunjukkan `User registered security info` dari jaringan kantor |
| 8 | Aktifkan kembali akun bila sempat dinonaktifkan | Hanya setelah langkah 1 sampai 7 [S9] | Login pertama pengguna sukses dari perangkat yang dikenal |
| 9 | Pantau | Penyerang yang masih memegang sesuatu akan mencoba lagi | Rule untuk session ID, IP, dan ASN penyerang serta security info baru pada akun itu aktif minimal 14 hari |

Untuk Rina, langkah 1, 2, 5, dan 9 dijalankan; langkah 3 dan 6 diperiksa dan tidak ada temuan (bagian 2.3); langkah 4 menunggu hasil Yoga; langkah 7 tidak perlu karena Authenticator milik Rina terdaftar sejak 2025 dari perangkat kantor dan dikenali Rina; langkah 8 tidak relevan karena akun tidak dinonaktifkan.

**Kapan gagal:** checklist dijalankan dari atas tanpa verifikasi per baris, atau langkah 2 diverifikasi dengan menelepon nomor yang baru didaftarkan penyerang. Satu langkah yang hanya dianggap selesai sudah cukup untuk membuat penyerang masuk lagi.

## 3. Lab praktik

Lab ini butuh tenant uji Entra ID dengan lisensi P1 atau lebih (misalnya tenant trial), dua akun uji, dan satu VM Windows. Jangan memakai tenant kantor atau akun nyata. Lab ini tidak memasang phishing kit atau proxy AiTM; perilaku "token dipakai dari tempat lain" cukup didekati dengan login dari jaringan berbeda. Bila tidak punya tenant, kerjakan langkah 2, 3, dan 6 memakai keluaran ilustrasi bagian 2 yang diimpor ke Splunk lab sebagai CSV.

1. **Interactive dan non-interactive.** Login akun uji di browser VM, buka Outlook web dan OneDrive, biarkan satu jam. Buka sign-in log dan catat berapa baris di tab interactive dan non-interactive, serta kolom jumlah sign-in pada baris yang digabung.
2. **Membaca satu baris.** Pilih satu sign-in dan isi tabel bagian 1.3 dari detailnya: session ID, correlation ID, authentication requirement, metode, status CA, perangkat. Bandingkan waktu di portal dengan `createdDateTime` dari Graph.
3. **Session dari dua jaringan.** Login akun uji yang sama dari VM lewat dua jaringan berbeda (misalnya jaringan rumah lalu tethering HP). Cari apakah session ID berubah, lalu tulis query bagian 2.2 versi lab.
4. **Persistence dan audit log.** Daftarkan metode telepon kedua pada akun uji. Temukan aktivitasnya di audit log, lalu hapus metode itu dengan cmdlet bagian 2.4 dan temukan aktivitas penghapusannya.
5. **Revoke dan timing.** Dengan Outlook web dan aplikasi Outlook desktop terbuka, jalankan Revoke sessions. Catat berapa menit sampai masing-masing meminta login ulang, dan kode error apa yang muncul di sign-in log.
6. **Kebijakan report-only.** Buat kebijakan CA-10 dalam report-only. Ulangi langkah 4 dari jaringan yang tidak termasuk lokasi tepercaya, lalu baca hasil report-only di detail sign-in.

**Hasil yang sebaiknya tersimpan:**

- `latihan/day10-signin-fields.md` berisi tabel field dari langkah 2 dan catatan zona waktu.
- Query Splunk lab untuk timeline per pengguna, session ID multi-jaringan, dan audit persistence.
- Catatan waktu langkah 5 per aplikasi, beserta kode error yang muncul.
- `latihan/day10-penilaian-admin.md` berisi penilaian akun admin dengan format bagian 2.5 untuk skenario lab.

**Variasi tantangan:** tulis rule Splunk yang menaikkan alert hanya bila tiga sinyal muncul dalam sesi yang sama: ASN baru untuk pengguna, tanpa `device_id`, dan pendaftaran security info dalam satu jam. Uji dengan data langkah 3 dan 4, lalu catat berapa false positive dari data login normalmu.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat menginvestigasi dan menahan kompromi identitas Entra ID. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Tidak ada aktivitas penyerang setelah login awal | Hanya tab interactive yang dibaca, atau ekspor SIEM tanpa sign-in non-interactive | Baca tab non-interactive; cek kategori log yang diekspor [S1][S2] |
| Jumlah baris di portal dan SIEM berbeda | Portal menggabung sign-in non-interactive; event MFA tampil satu baris di portal tetapi beberapa baris di Azure Monitor | Bandingkan dengan correlation ID, bukan jumlah baris [S2][S3] |
| Waktu di log tidak cocok dengan cerita pengguna | Portal memakai zona waktu pembaca; Graph memakai UTC | Konversi semua ke satu zona (WIB) di timeline [S3][S4] |
| IP di sign-in non-interactive tidak pernah dipakai penyerang | Untuk confidential client, IP yang tercatat adalah IP penerbitan token awal | Jangan memblokir atau menyimpulkan dari IP baris non-interactive saja [S2] |
| Detail risiko `hidden` atau "Additional risk detected" | Tenant tanpa P2 | Andalkan rule SIEM; catat sebagai keterbatasan [S4][S10] |
| Pengguna masih bisa membaca email beberapa menit setelah revoke | Access token yang sudah terbit, propagasi CAE sampai 15 menit, atau klien tidak mendukung CAE | Pantau sign-in dan log mailbox selama satu jam setelah revoke [S6][S8] |
| Status CA `notApplied` padahal kebijakan ada | Password gagal sehingga CA tidak dievaluasi, atau sign-in tidak memenuhi kondisi | Baca `authenticationRequirement` dan error code [S3][S21] |
| Kebijakan CA baru tidak langsung berlaku untuk sesi aktif | Perubahan kebijakan dan grup bisa butuh sampai satu hari untuk efektif di layanan CAE | Revoke sessions untuk pengguna yang harus segera terkena [S8] |
| Log sudah tidak ada saat investigasi | Lewat masa simpan 7 atau 30 hari, dan upgrade lisensi tidak retroaktif | Alirkan log ke penyimpanan jangka panjang sebelum insiden [S5] |

## 5. Kesalahan umum dan jebakan

- Menganggap MFA mencegah pengambilalihan akun. AiTM dan pencurian token memakai hasil MFA yang sah [S9][S16].
- Berhenti setelah reset password. Tidak semua kelas token dicabut, dan metode MFA atau perangkat yang ditanam penyerang tetap ada [S7][S17].
- Membaca hanya sign-in interactive. Pemakaian token oleh penyerang banyak tercatat di non-interactive [S2][S9].
- Menutup alert pendaftaran metode MFA dengan asumsi "ganti HP" tanpa menghubungi pengguna lewat nomor yang sudah tercatat sebelumnya.
- Mengaktifkan akun kembali sebelum metode dan perangkat asing dihapus [S9].
- Memblokir IP penyerang dan menganggap selesai. Penyerang di `INC-2026-022` pindah IP dalam 20 menit.
- Menyimpulkan akun admin "aman" tanpa menyebut sumber log, rentang waktu, dan apa yang tidak diketahui.
- Menjawab insiden token theft dengan sign-in frequency yang lebih sering. Prompt yang terlalu sering justru membuat pengguna terbiasa memasukkan kredensial [S15].
- Menaikkan kebijakan CA langsung ke On tanpa report-only [S12][S14].
- Menjalankan containment dari akun admin yang perlu role lebih tinggi daripada yang dimilikinya, lalu meminta role itu di tengah jendela [S6].

## 6. Catatan terkini

Bagian ini menampung detail versi, status preview, dan perilaku produk yang bisa berubah. Berguna saat memakai fitur yang disebut, tetapi tidak mengubah alur investigasi dan containment di atas.

- **Masa simpan log** dicek dari halaman retensi Entra ID bertanggal 6 Januari 2026: 7 hari untuk Free, 30 hari untuk P1 dan P2, risky sign-ins 90 hari untuk P2. Microsoft Graph activity logs hanya tersedia untuk P1 dan P2 dan tidak disimpan kecuali diekspor [S5].
- **Sign-in FIDO2** yang memperoleh refresh token sejak 11 April 2025 tercatat di log non-interactive [S2]. Pencarian login passkey yang hanya membaca tab interactive akan meleset.
- **Kebijakan Register security information** mulai 6 Juli 2026 juga berlaku saat registrasi Windows Hello for Business dan macOS Platform SSO [S12].
- **Token protection** (halaman bertanggal 14 Agustus 2026) GA untuk aplikasi native di Windows, iOS/iPadOS, dan macOS; dukungan aplikasi berbasis browser masih preview dan terbatas pada aplikasi yang mengakses Azure Resource Manager [S14]. Cek status ini sebelum merencanakan kebijakan untuk Outlook on the web.
- **CAE strict location enforcement** masih public preview pada halaman CAE bertanggal 8 April 2026 [S8].
- **Deteksi Attacker in the Middle** di ID Protection butuh Microsoft 365 E5 dengan EMS E5; deteksi lain yang relevan (Anomalous token, Unfamiliar sign-in properties) butuh P2 [S10].
- **Token theft playbook** Microsoft bertanggal 28 Juli 2023 dan masih memakai nama lama (Azure AD) di sebagian tautan; isinya tetap dipakai untuk alur investigasi dan remediasi [S9].
- **Modul PowerShell Azure AD dan MSOnline** sudah usang; contoh di Day ini memakai Microsoft Graph PowerShell SDK [S6].

## 7. Cheat sheet

```
TOKEN, BUKAN PASSWORD
  access token: default 1 jam; klien CAE bisa sampai 28 jam (dicabut lewat kejadian kritis)
  refresh token: default 90 hari (SPA 24 jam); terikat user+klien, bukan resource
  AiTM: proxy meneruskan login asli, menyimpan cookie dengan klaim MFA -> MFA tidak dilewati, hasilnya dicuri

LOG
  interactive (faktor diberikan) | non-interactive (token dipakai ulang)  -> baca KEDUANYA
  portal menggabung non-interactive (app+user+IP+status+resource sama)
  audit log terpisah: security info, register device, consent, role
  retensi Entra: Free 7 hari | P1/P2 30 hari | tidak retroaktif -> alirkan ke SIEM
  P1: risiko premium = "Additional risk detected", riskLevel = hidden

FIELD
  sessionId (reuse dari ASN lain = AiTM) | deviceId kosong | ASN hosting
  authenticationRequirement | authenticationDetails | conditionalAccessStatus
  correlationId (dari klien, tidak dijamin) | uniqueTokenIdentifier
  error: 50126 password salah | 50173 grant dicabut | 50133 sesi tidak sah setelah ganti password
         53003 diblok CA
  notApplied != kebijakan tidak ada (password gagal -> CA tidak dievaluasi)

CONTAINMENT (satu jendela, dari bastion, role cukup)
  reset 2x (AD) | hapus metode/perangkat asing | Revoke sessions | cek aplikasi dengan sesi sendiri
  hanya "admin revoke all refresh tokens" yang mencabut semua kelas token
  validasi: 50173/50133 dari sesi lama; percobaan dari IP baru

HUNTING PENERIMA: lookup penerima (message trace + grup) -> sign-in non-kantor per user
  cookie replay: sukses tanpa gagal, device kosong | password dicuri: gagal lalu sukses

PEMULIHAN AKUN (verifikasi tiap baris): revoke | hapus metode/perangkat asing | cabut consent
  | hapus inbox rule | reset 2x | rollback perubahan | TAP + daftar ulang bila ragu
  | aktifkan kembali | pantau 14 hari

PERSISTENCE (audit log)
  User registered security info | Register device | Consent to application
  Add service principal credentials | Add member to role | + inbox rule (Day 09)

AKUN ADMIN ORANG YANG SAMA
  sign-in sukses? | audit oleh akun itu? | logon AD dari host lain? | kredensial terbaca?
  kesimpulan + keyakinan + yang tidak diketahui; rotasi pencegahan karena murah

CONDITIONAL ACCESS
  compliant/hybrid joined device | Register security information policy | phishing-resistant untuk admin
  token protection (native GA, browser preview terbatas) | blokir IP & SIF pendek = bukan solusi
  report-only dulu | break-glass dikecualikan | risk-based butuh P2
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "MFA di PT JAB wajib untuk semua pengguna, jadi akun Rina hanya bisa diambil alih bila Rina menyetujui notifikasi MFA yang dikirim penyerang." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Di AiTM, Rina menyetujui MFA untuk login miliknya sendiri, yang diteruskan proxy ke halaman Microsoft yang asli. Proxy menyimpan session cookie yang dihasilkan setelah MFA selesai, lalu penyerang memutar ulang cookie itu. Microsoft menegaskan ini bukan kerentanan MFA; penyerang memakai hasil autentikasi yang sah. Pola menyetujui notifikasi penyerang adalah MFA fatigue, dan cirinya di log berbeda: banyak prompt ditolak atau tidak dijawab sebelum satu disetujui. Lihat bagian 1.1.

</details>

**2. Skenario keputusan.** Helpdesk sudah me-reset password Rina di AD pukul 08:45. Apa langkah yang tepat berikutnya?

- A. Cukup. Password baru tidak diketahui penyerang, jadi semua aksesnya hilang.
- B. Dalam satu jendela: reset kedua, hapus metode MFA asing dan perangkat asing bila ada, Revoke sessions, lalu validasi di sign-in log bahwa sesi lama ditolak.
- C. Nonaktifkan akun Rina selama 90 hari sampai semua refresh token pasti kedaluwarsa.

<details><summary>Jawaban</summary>

B. Dokumentasi Microsoft menunjukkan reset password tidak mencabut semua kelas token, sedangkan pencabutan semua refresh token oleh admin mencabut semuanya. Metode telepon yang didaftarkan penyerang juga tetap ada setelah reset, dan bisa dipakai menyelesaikan MFA bila penyerang kelak mendapat password baru. A keliru karena alasan itu. C keliru karena Revoke sessions sudah mencabut refresh token tanpa menunggu umurnya habis, sementara menonaktifkan akun selama 90 hari menghentikan pekerjaan Rina tanpa perlindungan tambahan yang berarti. Lihat bagian 1.4, 1.5, dan 2.4.

</details>

**3. Pertanyaan jebakan.** "Tab sign-in interactive tidak menunjukkan apa pun dari `198.51.100.152` setelah pukul 17:04, jadi penyerang berhenti beraktivitas sore itu." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Penyerang yang memakai token tidak memberikan faktor autentikasi baru, sehingga aktivitasnya tercatat di sign-in non-interactive, yang di portal juga digabung bila aplikasi, pengguna, IP, status, dan resource sama. Di `INC-2026-022`, sesi yang sama masih dipakai pukul 17:52 dan 22:10 dari IP yang sama, dan baru ditolak setelah revoke Kamis pagi. Lihat bagian 1.2 dan 2.1.

</details>

**4. Skenario keputusan.** Sari menemukan satu sign-in `adm.rina` gagal dengan `50126` dari IP penyerang dan tidak menemukan bukti lain. Apa yang sebaiknya ditulis untuk IC?

- A. "`adm.rina` aman, tidak perlu tindakan."
- B. "`adm.rina` terkompromi; naikkan ke SEV-1 dan periksa semua akun yang pernah di-reset `adm.rina`."
- C. Kesimpulan bahwa tidak ada bukti `adm.rina` dipakai atau dipegang penyerang, dengan sumber log dan rentang waktunya, keyakinan sedang, hal yang tidak diketahui, dan rotasi pencegahan yang sudah dijalankan.

<details><summary>Jawaban</summary>

C. Bukti yang ada mendukung kesimpulan bahwa tidak ada pemakaian, tetapi percobaan login menunjukkan niat, dan password yang dicoba tidak tercatat di log. Karena rotasi `adm.rina` murah, rotasi dijalankan sebagai pencegahan tanpa menyatakan akun itu terkompromi. A keliru karena tidak menyebut dasar dan keterbatasannya, dan melewatkan rotasi murah. B keliru karena menyatakan kompromi tanpa bukti, yang memicu pemeriksaan besar dan menaikkan severity tanpa dasar. Lihat bagian 1.6 dan 2.5.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Rina, dalam tiga kalimat, kenapa setelah password-nya diganti tim IR masih meminta ia login ulang di semua perangkat dan mengecek ulang metode MFA-nya.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Penyerang tidak menyimpan password kamu, tetapi tiket login yang terbentuk setelah kamu login dan menyetujui MFA di halaman palsu itu, dan tiket seperti itu tidak semuanya batal hanya karena password diganti. Karena itu kami mencabut semua tiket login kamu sekaligus, sehingga semua perangkat, termasuk milik penyerang, harus login ulang. Penyerang juga sempat menambahkan nomor telepon sebagai metode MFA, jadi kami sudah menghapusnya, dan kami minta kamu mengecek bahwa yang tersisa hanya Authenticator di HP kantormu."

Kesalahan yang sering muncul:
- Memakai istilah seperti "refresh token", "AiTM", atau "CAE" yang tidak dibutuhkan Rina.
- Menyalahkan Rina karena mengklik tautan, sehingga ia enggan melapor lain kali.
- Tidak menyebut apa yang perlu Rina lakukan.

</details>

**6. Pertanyaan jebakan.** "Sign-in `adm.rina` pukul 17:31 berstatus Conditional Access `notApplied`, artinya kebijakan CA untuk akun admin tidak berlaku pada akun itu dan harus segera diperbaiki." Benarkah?

<details><summary>Jawaban</summary>

Belum tentu. Sign-in itu gagal di tahap password (`50126`). Bila autentikasi awal gagal, sign-in tidak dievaluasi Conditional Access, dan `authenticationRequirement` bernilai `singleFactorAuthentication`. Status `notApplied` di sini adalah akibat password salah, bukan bukti kebijakannya tidak mencakup `adm.rina`. Cakupan kebijakan dicek dari sign-in yang sukses atau dari hasil report-only. Lihat bagian 1.3 dan 1.6.

</details>

**7. Interview question (English).** "A user fell for a phishing page and their Microsoft 365 account was taken over, even though MFA was enforced. How do you investigate and respond?"

<details><summary>Sample answer</summary>

"First I'd figure out how MFA was bypassed, because that decides what we clean up. If the user completed a normal MFA prompt on the phishing page, it's most likely an adversary-in-the-middle proxy that stole the session cookie, so the user's device is probably clean and the problem is the stolen token. I'd pull both interactive and non-interactive sign-in logs, because token replay mostly shows up as non-interactive, and pivot on the session ID: the same session showing up from a hosting ASN with no device ID is a strong signal. Then I'd check the audit log for persistence: new MFA methods, registered devices, app consents, role changes, plus inbox rules on the mailbox side. Containment happens in one window: remove the attacker's methods and devices, revoke all sessions explicitly, because a password reset alone doesn't revoke every token type, and reset the password. I'd verify in the logs that the old session gets rejected. If the person also has an admin account, I'd check that account's sign-ins, audit activity and on-prem logons, write the conclusion with its confidence level, and rotate it as a cheap precaution. Finally, I'd fix the actual gap with Conditional Access, like requiring managed devices, protecting security info registration, and phishing-resistant MFA for admins, rolling each out in report-only first."

What makes this answer strong: it explains why MFA didn't help, names the right logs and the pivot field, separates identity from device cleanup, covers persistence beyond the password, justifies explicit session revocation, handles the related admin account with evidence, and ends with controls that close the specific path.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Microsoft Learn: Sign-in logs in Microsoft Entra ID | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins | primer (dokumentasi vendor) | ms.date 2025-11-07; diakses 2026-10-15 | Tinggi. Empat jenis sign-in log, tampilan lama hanya interactive, audit log terpisah |
| S2 | Microsoft Learn: Non-interactive sign-in logs | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-noninteractive-sign-ins | primer (dokumentasi vendor) | ms.date 2026-02-09; diakses 2026-10-15 | Tinggi. Definisi, contoh, pengelompokan, IP confidential client, FIDO2 sejak April 2025 |
| S3 | Microsoft Learn: Learn about the sign-in log activity details | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-in-log-activity-details | primer (dokumentasi vendor) | ms.date 2026-03-04; diakses 2026-10-15 | Tinggi. Who/how/what, correlation ID, status CA, authentication requirement, zona waktu, event MFA di Azure Monitor |
| S4 | Microsoft Graph beta: signIn resource type | https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-beta | primer (dokumentasi vendor) | ms.date 2025-11-27; diakses 2026-10-15 | Tinggi. Properti `sessionId`, `uniqueTokenIdentifier`, `incomingTokenType`, `riskLevelDuringSignIn` hidden tanpa P2, filter non-interactive |
| S5 | Microsoft Learn: Microsoft Entra data retention | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-reports-data-retention | primer (dokumentasi vendor) | ms.date 2026-01-06; diakses 2026-10-15 | Tinggi. Retensi per lisensi, tidak retroaktif, UAL terpisah |
| S6 | Microsoft Learn: Revoke user access in an emergency in Microsoft Entra ID | https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access | primer (dokumentasi vendor) | ms.date 2026-06-19; diakses 2026-10-15 | Tinggi. Reset dua kali, revoke, role yang dibutuhkan, access token dan session token aplikasi |
| S7 | Microsoft Learn: Refresh tokens in the Microsoft identity platform | https://learn.microsoft.com/en-us/entra/identity-platform/refresh-tokens | primer (dokumentasi vendor) | ms.date 2025-11-05; diakses 2026-10-15 | Tinggi. Umur refresh token, keterikatan user dan klien, tabel pencabutan per kelas token |
| S8 | Microsoft Learn: Continuous access evaluation in Microsoft Entra | https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation | primer (dokumentasi vendor) | ms.date 2026-04-08; diakses 2026-10-15 | Tinggi. Kejadian kritis, jeda 15 menit, token sampai 28 jam, dukungan klien, jeda perubahan kebijakan |
| S9 | Microsoft Learn: Token theft playbook | https://learn.microsoft.com/en-us/security/operations/token-theft-playbook | primer (dokumentasi vendor) | ms.date 2023-07-28 (lebih dari 2 tahun); diakses 2026-10-15 | Tinggi untuk alur investigasi, containment, dan remediasi; sebagian tautan masih memakai nama Azure AD |
| S10 | Microsoft Learn: What are risk detections? (ID Protection) | https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks | primer (dokumentasi vendor) | ms.date 2026-04-22; diakses 2026-10-15 | Tinggi. Lisensi per deteksi, "Additional risk detected", Attacker in the Middle, non-interactive |
| S11 | Microsoft Learn: Microsoft Entra audit log activity reference | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities | primer (dokumentasi vendor) | ms.date 2025-03-25; diakses 2026-10-15 | Tinggi. Nama aktivitas dan kategori audit |
| S12 | Microsoft Learn: Control security information registration with Conditional Access | https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-security-info-registration | primer (dokumentasi vendor) | ms.date 2026-03-24; diakses 2026-10-15 | Tinggi. User action Register security information, Temporary Access Pass, pengecualian, report-only, perubahan 6 Juli 2026 |
| S13 | Microsoft Learn: Overview of Conditional Access authentication strengths | https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths | primer (dokumentasi vendor) | ms.date 2025-03-04; diakses 2026-10-15 | Tinggi. Strength bawaan, metode phishing-resistant, CA dievaluasi setelah autentikasi awal |
| S14 | Microsoft Learn: How token protection enhances Conditional Access policies | https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-token-protection | primer (dokumentasi vendor) | ms.date 2026-08-14; diakses 2026-10-15 | Tinggi. Platform, resource yang didukung, status preview browser, saran report-only |
| S15 | Microsoft Learn: Conditional Access adaptive session lifetime policies | https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-session-lifetime | primer (dokumentasi vendor) | ms.date 2026-04-08; diakses 2026-10-15 | Tinggi. Default 90 hari, risiko prompt terlalu sering |
| S16 | Microsoft Security Blog: From cookie theft to BEC, attackers use AiTM phishing sites as entry point to further financial fraud | https://www.microsoft.com/en-us/security/blog/2022/07/12/from-cookie-theft-to-bec-attackers-use-aitm-phishing-sites-as-entry-point-to-further-financial-fraud/ | sekunder (laporan vendor) | 2022-07-12 (lebih dari 3 tahun); diakses 2026-10-15 | Sedang-tinggi. Mekanisme AiTM, bukan kerentanan MFA, indikator session ID reuse, rekomendasi |
| S17 | Microsoft Security Blog: Detecting and mitigating a multi-stage AiTM phishing and BEC campaign | https://www.microsoft.com/en-us/security/blog/2023/06/08/detecting-and-mitigating-a-multi-stage-aitm-phishing-and-bec-campaign/ | sekunder (laporan vendor) | 2023-06-08 (lebih dari 3 tahun); diakses 2026-10-15 | Sedang-tinggi. Penambahan metode OTP telepon, reset password tidak efektif, cabut cookie dan perubahan MFA |
| S18 | Microsoft Learn: Azure Monitor Logs reference, SigninLogs | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs | primer (dokumentasi vendor) | ms.date 2026-08-27; diakses 2026-10-15 | Tinggi. Kolom `SessionId`, `UniqueTokenIdentifier`, `IncomingTokenType` tersedia saat log diekspor ke Azure Monitor |
| S19 | Microsoft Learn: Get-MgUserAuthenticationMethod | https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.signins/get-mguserauthenticationmethod | primer (dokumentasi vendor) | ms.date 2026-09-22; diakses 2026-10-15 | Tinggi. Sintaks dan izin |
| S20 | Microsoft Learn: Remove-MgUserAuthenticationPhoneMethod | https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.signins/remove-mguserauthenticationphonemethod | primer (dokumentasi vendor) | ms.date 2026-09-22; diakses 2026-10-15 | Tinggi. Sintaks dan izin |
| S21 | Microsoft Learn: Microsoft Entra authentication and authorization error codes | https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes | primer (dokumentasi vendor) | ms.date 2025-02-03; diakses 2026-10-15 | Tinggi. Arti `50126`, `50133`, `50173`, `53003` |
| S22 | Microsoft Learn: Detect and remediate illicit consent grants | https://learn.microsoft.com/en-us/defender-office-365/detect-and-remediate-illicit-consent-grants | primer (dokumentasi vendor) | ms.date 2026-07-03; diakses 2026-10-15 | Tinggi. Consent tidak terpengaruh reset password dan MFA, cara mencabut lewat portal dan PowerShell |

**Catatan sumber:** sourcetype `azure:monitor:aad` dan field alias di bagian 2 adalah konfigurasi fiktif PT JAB; nama sourcetype, nama field, dan apakah kategori non-interactive ikut terekspor perlu dicek di dokumentasi add-on yang kamu pakai. Pembagian jalur AiTM, MFA fatigue, dan pencurian token dari endpoint di bagian 1.1, empat pertanyaan untuk akun admin di bagian 1.6, tabel pilihan Conditional Access di bagian 1.7, dan urutan checklist pemulihan akun di bagian 2.8 adalah susunan catatan ini dari sumber yang disebut, bukan daftar resmi. Efek reset password di AD on-premises yang disinkronkan ke cloud terhadap setiap kelas token tidak tercantum di tabel pencabutan [S7] dan perlu diuji di lab. Penilaian bahwa metode phishing-resistant tidak bisa diteruskan proxy AiTM didasarkan pada definisi strength itu sebagai metode yang butuh interaksi antara metode dan permukaan sign-in [S13] dan rekomendasi Microsoft [S16]. Cara reset password yang tersinkron dari AD ditampilkan di audit log Entra ID (nama inisiator di bagian 2.3) adalah ilustrasi dan perlu dicek di tenant-mu. Bahwa Microsoft 365 E3 mencakup Entra ID P1 perlu dicek di halaman lisensi Microsoft yang berlaku. Semua isi PT JAB, termasuk ASN `64500` sampai `64510` (rentang dokumentasi), alamat IP, nomor telepon, dan hasil query, adalah contoh fiktif.
