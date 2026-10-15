---
day: 09
title: 'BEC dan kompromi mailbox M365: Unified Audit Log, MailItemsAccessed, inbox rule, dan OAuth consent'
researched_on: 2026-10-15
versions_checked: 'Microsoft Defender for Office 365, Respond to a compromised email account (ms.date 2026-07-03); Microsoft Purview, Use MailItemsAccessed to investigate compromised accounts (ms.date 2026-06-19); Manage mailbox auditing (ms.date 2026-06-19); Manage audit log retention policies (ms.date 2026-06-19); Audited activities (ms.date 2026-10-01); Search-UnifiedAuditLog (diperbarui 2026-06-01); Get-MessageTraceV2 (diperbarui 2026-02-27); Detect and remediate Outlook rules and custom forms injection attacks (ms.date 2026-07-03); Detect and remediate illicit consent grants (ms.date 2026-07-03); FBI IC3 PSA I-091124-PSA (11 September 2024); UU 27/2022 Pasal 46'
---

# Day 09: BEC dan kompromi mailbox M365 (Unified Audit Log, MailItemsAccessed, inbox rule, dan OAuth consent)

Cakupan: mengenali pola business email compromise (BEC) di Microsoft 365, menyusun timeline dari Unified Audit Log, menemukan inbox rule dan forwarding yang dipasang penyerang, menjawab "email apa saja yang dibaca" dengan MailItemsAccessed, mencabut aplikasi OAuth yang diberi consent, menahan dan memulihkan mailbox dengan urutan yang benar, serta menangani sisi uang, pelanggan, dan data pribadi.

## Ide inti

BEC adalah penipuan pembayaran yang menumpang percakapan sah. Penyerang tidak perlu malware di laptop korban: cukup akses ke mailbox, satu inbox rule yang menyembunyikan balasan, dan satu email balasan di thread tagihan yang sudah berjalan dengan permintaan "mohon transfer ke rekening baru". Semua jejaknya ada di cloud, bukan di endpoint, sehingga investigasi bertumpu pada audit log Microsoft 365. Log itu punya tiga batas yang harus kamu ketahui sebelum insiden: jeda sampai muncul, masa simpan yang bergantung lisensi, dan aksi yang tidak dicatat secara default. Akses penyerang juga tidak hanya lewat password: inbox rule, forwarding, sesi yang masih berlaku, metode MFA tambahan, dan aplikasi yang diberi consent OAuth semuanya bertahan setelah password diganti.

Kamu sudah mengenal pola ini dari NOC. Bayangkan seseorang memegang akun engineer NOC, memasang filter di NMS yang diam-diam menekan alarm untuk satu pelanggan, lalu memakai kanal tiket resmi untuk meminta pelanggan itu mengubah konfigurasi peering ke router milik penyerang. Tidak ada perangkat yang rusak dan semua perintah sah secara teknis; satu-satunya tanda adalah permintaan yang tidak biasa. Yang berbeda di BEC: log yang kamu butuhkan disimpan penyedia cloud dengan aturan mereka, bukan di syslog server milikmu, dan aksesnya tidak hilang hanya karena kata sandi akun diganti.

```
phishing AiTM --> sesi dicuri --> akses mailbox (OWA, aplikasi OAuth)
                                       |
          +----------------------------+----------------------------+
          v                            v                            v
 inbox rule "." sembunyikan   baca thread pembayaran        consent aplikasi
 balasan pelanggan            (MailItemsAccessed)           (akses tanpa password)
          |                            |
          +------------> balas thread: "rekening baru" --> pelanggan transfer
                                                                |
                                       pelanggan menelepon untuk konfirmasi
                                                                |
                                       laporan ke SOC --> insiden dinyatakan
```

Situasi yang dipakai sepanjang Day ini adalah `INC-2026-021` di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif yang memakai Microsoft 365 dengan AD on-premises tersinkron ke Entra ID. Senin 2026-10-26 pukul 09:05, Lina Marlina dari bagian keuangan PT Sentosa Makmur Contoh, pelanggan dedicated internet korporat, menelepon nomor meja Fitri Handayani (staf piutang pelanggan korporat, Keuangan Jakarta) yang tercantum di kontrak. Lina ingin memastikan permintaan email Jumat lalu untuk membayar tagihan `INV-JAB-2026-10-0871` sebesar Rp 487.500.000 ke rekening baru. Fitri tidak pernah mengirim email itu. Pukul 09:20 Fitri melapor ke hotline SOC (`SOC-2026-0220`), pukul 09:40 helpdesk mengganti password Fitri atas permintaannya, dan pukul 09:50 IC Dimas Prasetyo menyatakan `INC-2026-021` dengan severity SEV-2, dengan analyst L2 Rudi Hartanto sebagai technical lead. Pukul 11:00, Direktur Teknologi Hendra Wijaya menulis di kanal `#inc-2026-021`:

> "Dim, saya sudah bicara dengan Keuangan dan Legal. Fitri pakai MFA, kok penyerang bisa kirim email dari akunnya? Kenapa Fitri tidak lihat balasan dari pelanggan? Password Fitri sudah diganti jam 09:40, berarti sudah aman kan? Legal dan DPO tanya, email apa saja yang dibaca penyerang, ada data pelanggan yang ikut terbaca atau tidak? Pelanggan lain siapa saja yang dikirimi email palsu? Lalu apa yang harus Keuangan lakukan soal uangnya, dan apa urutan kerja kalian sekarang?"

Pesan itu memuat tujuh pertanyaan:

1. Bagaimana penyerang bisa masuk dan apa pola serangannya?
2. Dari mana kita tahu apa yang dilakukan penyerang, dan apa batas sumber itu?
3. Kenapa Fitri tidak melihat balasan pelanggan?
4. Apakah mengganti password sudah cukup?
5. Email apa saja yang dibaca penyerang?
6. Apa urutan kerja menahan dan memulihkan mailbox?
7. Apa yang dilakukan soal uang, pelanggan, dan data pribadi?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, pertanyaan 6 di bagian 1.6, dan pertanyaan 7 di bagian 1.7. Bagian 2 berisi perintah, query, dan dokumen yang dipakai tim PT JAB hari itu.

**Kapan relevan:** setiap kali ada tanda mailbox Microsoft 365 dipakai orang lain: permintaan perubahan rekening yang tidak dikenal pengirimnya, email hilang atau tidak sampai, inbox rule aneh, pelanggan atau vendor yang menerima email janggal dari akun internal, atau alert login mencurigakan yang diikuti aktivitas mailbox.
**Kapan bukan jawaban:** Day ini tidak membahas analisis email phishing yang masuk dan purge dari banyak mailbox (Day 08), juga tidak membahas sign-in log, Conditional Access, dan pencabutan token di Entra ID secara mendalam (Day 10). BEC yang memakai domain mirip tanpa membobol mailbox internal juga hanya disentuh sedikit: tanpa kompromi akun, tidak ada audit mailbox internal yang perlu diperiksa.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (insiden, severity, IC, executive sponsor, scoping, scope statement, containment, revoke session, jam H) tidak diulang. Tabel berikut memuat istilah baru Day ini. Kolom padanan memakai analogi NOC dan SOC yang sama di semua Day IR.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Business email compromise (BEC) | Penipuan transfer dana lewat akun email sah yang dibobol atau ditiru | Perintah perubahan konfigurasi palsu yang dikirim lewat kanal tiket resmi |
| Adversary-in-the-middle (AiTM) phishing | Halaman phishing yang meneruskan login ke situs asli lalu mencuri cookie sesi setelah MFA | Proxy transparan yang menyalin sesi TACACS setelah engineer login |
| Unified Audit Log (UAL) | Log audit Microsoft 365 yang menggabungkan aktivitas Exchange, SharePoint, OneDrive, Entra ID, Teams, dan layanan lain | Log TACACS accounting di sisi server, bukan di perangkat |
| Mailbox auditing | Pencatatan aksi pemilik, delegate, dan admin di mailbox; aktif secara default | Log perintah per sesi di router |
| Inbox rule | Aturan di mailbox yang memproses email masuk: pindah folder, tandai sudah dibaca, hapus, teruskan | Filter alarm di NMS yang menekan alarm tertentu |
| Mailbox forwarding | Pengaturan mailbox yang meneruskan semua email ke alamat lain | Port mirror permanen ke tujuan di luar |
| MailItemsAccessed | Aksi audit yang mencatat akses ke item email lewat protokol dan klien | NetFlow yang menunjukkan data apa yang lewat, bukan hanya siapa yang login |
| Sync dan bind | Sync: klien mengunduh isi satu folder; bind: akses ke satu email | Transfer file konfigurasi utuh vs membaca satu baris di console |
| OAuth consent | Izin yang diberikan pengguna atau admin agar aplikasi mengakses data atas namanya | Memberi kunci API read-only NMS ke portal vendor |
| Illicit consent grant | Consent yang diperoleh penyerang dengan menipu pengguna agar menyetujui aplikasinya | Kunci API yang diberikan ke "vendor" palsu |
| Message trace | Catatan perjalanan email lewat sistem email: pengirim, penerima, waktu, status | Log syslog MTA atau log SMTP relay |

### 1.1 Pola BEC: masuk lewat sesi, tinggal lewat aturan, menipu lewat thread asli

Pertanyaan pertama Hendra ("Fitri pakai MFA, kok bisa?") adalah pertanyaan yang hampir selalu muncul di insiden BEC sekarang.

FBI IC3 mendefinisikan BEC (disebut juga email account compromise) sebagai penipuan yang menyasar bisnis dan perorangan yang melakukan permintaan transfer dana yang sah, sering dengan membobol akun email asli lewat social engineering atau intrusi [S11]. IC3 mencatat 305.033 insiden dengan kerugian terekspos sekitar 55,5 miliar dolar AS dari Oktober 2013 sampai Desember 2023, dan menyebut kerugian terekspos naik 9% dari Desember 2022 ke Desember 2023 [S11]. Angka ini dari laporan ke IC3, sehingga lebih menggambarkan skala daripada angka pasti.

Microsoft Threat Intelligence menggambarkan rantai yang sama dengan `INC-2026-021` dalam kampanye AiTM tahun 2022 [S10]:

- **Masuk.** Server proxy penyerang berdiri di antara korban dan halaman login Microsoft. Korban memasukkan password dan menyetujui MFA di halaman yang terlihat asli; proxy meneruskan semuanya ke Microsoft, lalu menyimpan cookie sesi yang terbit setelah MFA. Penyerang memakai cookie itu di browsernya sendiri tanpa perlu login ulang. Microsoft menegaskan ini bukan celah di MFA: cookie dicuri setelah pengguna selesai login [S10].
- **Cepat.** Dalam kampanye itu, penipuan pembayaran dimulai paling cepat lima menit setelah korban memasukkan kredensial [S10].
- **Mencari thread pembayaran.** Penyerang membuka email dan lampiran terkait keuangan setiap beberapa jam, mencari percakapan pembayaran yang sedang berjalan, lalu membalas thread itu [S10].
- **Menyembunyikan.** Penyerang membuat inbox rule yang memindahkan email dari domain target ke folder Archive dan menandainya sudah dibaca, serta menghapus balasannya dari Sent Items dan Deleted Items [S10].

Detail sign-in AiTM, termasuk cara mengenali cookie yang dipakai ulang dari lokasi lain dan kontrol Conditional Access yang mencegahnya, dibahas di Day 10 bagian 1.3 dan 1.7. Di Day ini cukup dipegang satu hal: MFA berbasis persetujuan atau kode tidak menghentikan AiTM, sehingga "korban pakai MFA" bukan alasan untuk menolak hipotesis kompromi mailbox.

Di `INC-2026-021`, timeline yang tersusun dari audit log (bagian 2.2) mengikuti pola itu: email phishing "dokumen pembayaran dibagikan" dari `notifikasi@jab-dokumen.example.net` tiba Kamis 2026-10-22 10:12, Fitri memasukkan kredensial dan menyetujui MFA di halaman AiTM (`198.51.100.124`) pukul 10:17 dari `JKT-WS-0469`, dan sesi curian dipakai dari `203.0.113.131` pukul 10:22.

Ada satu alasan lagi kenapa penyerang repot membobol mailbox Fitri. Domain email `jab.example` memakai DMARC dengan kebijakan `p=reject`, sehingga email dari luar yang memalsukan alamat `@jab.example` ditolak server penerima yang menegakkan DMARC. Email yang dikirim dari mailbox Fitri sendiri justru lolos autentikasi seperti email sah lainnya. DMARC melindungi dari pemalsuan alamat, bukan dari akun asli yang dipakai orang lain.

### 1.2 Unified Audit Log: sumber utama, dengan tiga batas

Pertanyaan kedua ("dari mana kita tahu?") dijawab dengan audit log Microsoft 365. Sebelum membaca isinya, pahami batasnya, karena batas itulah yang menentukan apa yang boleh kamu tulis di laporan.

**Apa yang dicatat.** Unified Audit Log berisi event dari Exchange Online, SharePoint, OneDrive, Entra ID, Teams, Power BI, dan layanan Microsoft 365 lain [S5]. Mailbox auditing aktif secara default di semua organisasi dan mencatat aksi pemilik (Owner), delegate, dan admin dengan set aksi bawaan per jenis sign-in [S3]. Untuk investigasi BEC, aksi yang paling sering dipakai beserta nama operasinya [S6]:

| Aksi | Operasi | Catatan untuk investigasi |
|---|---|---|
| Membuat inbox rule di Outlook web | `New-InboxRule` | Parameter aturan (nama, kondisi, aksi) tercatat |
| Mengubah inbox rule di Outlook web | `Set-InboxRule` | Penyerang sering memperluas aturan untuk target baru |
| Membuat, mengubah, menghapus aturan dari klien Outlook | `UpdateInboxRules` | Aturan yang dibuat dari Outlook desktop muncul di sini |
| Mengirim, membalas, meneruskan email | `Send` | Menunjukkan email yang dikirim dari mailbox |
| Memindahkan ke Deleted Items | `MoveToDeletedItems` | Jejak penghapusan bukti |
| Menghapus dari Deleted Items | `SoftDelete` | Item pindah ke Recoverable Items |
| Menghapus permanen dari Recoverable Items | `HardDelete` | Item hilang dari mailbox |
| Mengakses item email | `MailItemsAccessed` | Dibahas di bagian 1.5 |
| Mencari di mailbox | `SearchQueryInitiated` | Tidak dicatat secara default untuk pemilik |

**Batas pertama: aksi yang tidak dicatat secara default.** Tabel aksi mailbox Microsoft menandai `SearchQueryInitiated` sebagai aksi yang bisa dicatat untuk pemilik, tetapi bukan bagian set bawaan, begitu juga `MailboxLogin` [S3]. Artinya, tidak adanya event pencarian di audit log PT JAB tidak berarti penyerang tidak mencari kata "rekening"; aksi itu memang tidak direkam kecuali diaktifkan sebelum insiden. Selain itu, set aksi pada mailbox yang pernah diubah manual tidak lagi dikelola Microsoft, sehingga aksi baru yang ditambahkan Microsoft tidak otomatis tercatat di mailbox itu [S3]. Pengguna yang diberi audit bypass dengan `Set-MailboxAuditBypassAssociation` sama sekali tidak tercatat aksinya [S3]; daftar bypass perlu dicek saat mempersiapkan IR, bukan saat insiden.

**Batas kedua: jeda.** Microsoft menyebut entri audit bisa butuh 30 menit sampai 24 jam untuk muncul di hasil pencarian setelah event terjadi [S8]. Hasil pencarian pukul 10:30 tidak menjamin aktivitas pukul 10:00 sudah lengkap.

**Batas ketiga: masa simpan.** Audit (Standard) disimpan 180 hari untuk log yang dibuat sejak 17 Oktober 2023 (sebelumnya 90 hari). Audit (Premium) punya kebijakan default yang menyimpan record Exchange, SharePoint, OneDrive, dan Entra ID selama satu tahun untuk pengguna berlisensi E5 atau add-on yang setara, dan bisa diperpanjang sampai 10 tahun dengan add-on khusus [S4]. Masa simpan ditentukan oleh lisensi pengguna yang melakukan aktivitas, bukan lisensi analyst yang mencari [S4]. Untuk BEC yang baru diketahui berbulan-bulan kemudian, ini bisa berarti awal kompromi sudah tidak terlihat; karena itu PT JAB juga mengirim audit log ke Splunk (index `o365`) dengan retensinya sendiri.

**Cara mencari.** Pencarian bisa dilakukan di halaman Audit portal Microsoft Purview atau Defender, atau dengan cmdlet `Search-UnifiedAuditLog` di Exchange Online PowerShell. Hal yang sering menjebak saat memakai cmdlet [S5]:

- Tanpa `SessionCommand`, cmdlet hanya mengembalikan sampai 100 record. `ReturnLargeSet` memberi akses sampai 50.000 record lewat paging dengan `SessionId` yang sama, dalam urutan tidak tersortir; `ReturnNextPreviewPage` tersortir tetapi maksimal 5.000 record. Mencampur keduanya dalam satu `SessionId` membatasi hasil ke 10.000.
- `ResultSize` maksimal 5.000 per panggilan.
- Waktu disimpan dalam UTC, dan nilai `StartDate`/`EndDate` tanpa zona waktu dianggap UTC. Jam WIB harus dikurangi tujuh jam.
- Parameter `HighCompleteness` (preview) memilih kelengkapan daripada kecepatan; tanpa parameter itu, hasil bisa ada yang terlewat.
- Untuk menarik data audit secara terprogram dan berulang, Microsoft menyarankan Management Activity API, bukan skrip yang memanggil cmdlet ini.

### 1.3 Inbox rule dan forwarding: kenapa Fitri tidak melihat balasan

Pertanyaan ketiga Hendra punya jawaban yang ditemukan Rudi di menit-menit pertama: aturan bernama "." di mailbox Fitri.

Inbox rule berbahaya dipakai untuk dua tujuan. Pertama, menyembunyikan: email dari pelanggan yang menjadi target atau yang mengandung kata kunci pembayaran dipindah ke folder yang jarang dibuka dan ditandai sudah dibaca, sehingga korban tidak melihat balasan atau pertanyaan konfirmasi [S10]. Kedua, mengalirkan data: email diteruskan atau di-redirect ke alamat di luar organisasi. Microsoft memasukkan aturan yang meneruskan email ke alamat tak dikenal, aturan yang memindahkan email ke folder Notes, Junk Email, atau RSS Subscriptions, dan forwarding eksternal yang baru ditambahkan sebagai gejala mailbox yang terkompromi [S1].

Riset Proofpoint atas akun yang diambil alih pada kuartal 4 2025 memberi gambaran pola di lapangan [S13]:

- Sekitar 10% akun yang terkompromi punya minimal satu aturan berbahaya yang dibuat tidak lama setelah akses awal, dengan selang tercepat sekitar 5 detik.
- Nama aturan paling sering adalah karakter minimal: "." (16%), "..." (8,5%), ".." (8%), ";" (6%), dan ";;;" (4%).
- Aksi yang umum: menghapus email dari pengirim atau berisi kata tertentu, dan memindahkan email ke folder Conversation History, Archive, atau RSS Subscriptions.

Tiga hal penting tentang inbox rule dalam IR:

- **Aturan tersimpan di server.** Aturan dan custom form tersinkron dari cloud ke setiap instalasi Outlook, sehingga instal ulang Outlook atau mengganti laptop korban tidak menghapusnya [S7]. Mengganti password juga tidak menghapusnya; aturan tetap bekerja sampai dihapus.
- **Ada aturan yang tersembunyi.** `Get-InboxRule` dengan `-IncludeHidden` menampilkan juga aturan yang tidak terlihat di daftar biasa [S1].
- **Forwarding punya dua tempat.** Selain inbox rule (`ForwardTo`, `ForwardAsAttachmentTo`, `RedirectTo`), mailbox bisa punya forwarding di level mailbox (`ForwardingAddress` untuk penerima internal, `ForwardingSmtpAddress` untuk penerima eksternal, dan `DeliverToMailboxAndForward`) [S1]. Keduanya dicek.

Di `INC-2026-021`, aturan "." dibuat pukul 10:26 Kamis, empat menit setelah sesi curian pertama dipakai: setiap email yang subjek atau isinya mengandung "rekening", "transfer", "pembayaran", atau "bukti bayar" dipindah ke RSS Subscriptions, ditandai sudah dibaca, dan pemrosesan aturan lain dihentikan. Jumat 08:58, aturan itu diubah dengan menambah kata "INV-JAB" dan "konfirmasi", sesaat sebelum email palsu dikirim. Balasan Lina pada Senin 08:47 yang meminta konfirmasi masuk ke RSS Subscriptions, dan itulah sebabnya Lina menelepon.

### 1.4 Ganti password belum cukup: semua jalan masuk yang tersisa

Pertanyaan keempat Hendra ("password sudah diganti, berarti aman?") dijawab dengan daftar akses yang tidak bergantung pada password.

| Akses yang tersisa | Kenapa tidak hilang saat password diganti | Cara menutup |
|---|---|---|
| Sesi dan refresh token yang sudah terbit | Token yang sudah dipegang penyerang tetap bisa dipakai sampai dicabut atau kedaluwarsa | Revoke sessions [S1]; detail token di Day 10 bagian 1.4 |
| Metode MFA yang didaftarkan penyerang | Penyerang bisa login ulang dengan password baru bila ia juga memegang metode MFA | Tinjau dan hapus metode MFA yang tidak dikenal [S1] |
| Aplikasi OAuth yang diberi consent | Aplikasi memegang izinnya sendiri; reset password dan MFA tidak efektif terhadap serangan ini [S8] | Cabut consent grant aplikasi [S8] |
| Inbox rule dan forwarding | Konfigurasi mailbox, bukan kredensial | Nonaktifkan lalu hapus aturan dan forwarding [S1][S7] |
| App password | Tidak otomatis dicabut saat password direset [S1] | Hapus app password lama |
| Peran admin yang ditambahkan | Hak di directory, bukan kredensial | Tinjau peran yang diberikan ke akun [S1] |

Aplikasi OAuth perlu penjelasan khusus. Dalam illicit consent grant, penyerang mendaftarkan aplikasi di Entra ID yang meminta akses ke email, kontak, atau dokumen, lalu menipu pengguna agar memberi consent. Setelah consent diberikan, aplikasi itu punya akses setingkat akun ke data tanpa memerlukan akun di organisasi, dan langkah perbaikan biasa seperti reset password atau MFA tidak efektif [S8]. Jejaknya ada di audit log sebagai aktivitas **Consent to application**; field `IsAdminConsent` bernilai True berarti consent diberikan dengan hak admin untuk akses yang lebih luas [S8].

Di `INC-2026-021`, pukul 10:44 Kamis Fitri tercatat memberi consent ke aplikasi "Mail Sync Helper" dengan izin delegated `Mail.Read`, `Mail.Send`, `offline_access`, dan `User.Read`, dari sesi `203.0.113.131`. Fitri tidak pernah membuka halaman consent: consent itu diberikan penyerang yang memakai sesinya. Aplikasi itu lalu membaca email dari `203.0.113.136` sejak Jumat dini hari, dan audit menunjukkan aplikasi masih membaca email Fitri pukul 09:58 Senin, delapan belas menit setelah password diganti. Reset pukul 09:40 juga dilakukan sebelum scope diketahui: kesalahan yang sama dengan reset dini di Day 05 bagian 1.5, karena penyerang masih punya jalan lain dan kini tahu ia ketahuan.

### 1.5 MailItemsAccessed: menjawab "email apa saja yang dibaca"

Pertanyaan kelima datang dari Legal dan DPO, dan jawabannya menentukan kewajiban hukum, jadi harus akurat dan jujur tentang batasnya.

`MailItemsAccessed` mencatat akses ke data email oleh protokol dan klien email: POP, IMAP, MAPI, EWS, Exchange ActiveSync, dan REST. Aksi ini bagian dari Audit (Standard) dan aktif secara default untuk pengguna berlisensi Office 365 atau Microsoft 365 E3/E5 [S2][S3]. Ada dua jenis akses yang dicatat dengan cara berbeda [S2]:

- **Sync** hanya dicatat saat mailbox diakses Outlook desktop untuk Windows atau Mac. Karena klien mengunduh banyak item sekaligus, satu record dibuat per folder, bukan per item. Semua item di folder yang di-sync dianggap terkompromi.
- **Bind** adalah akses ke satu email. Setiap email diidentifikasi dengan `InternetMessageId`. Semua bind dalam selang dua menit digabung menjadi satu record, dengan daftar item di field `Folders` dan jumlahnya di `OperationCount`.

Microsoft juga menyaring duplikat: bind yang sama dalam satu jam tidak dicatat ulang, dan sync difilter dalam interval satu jam, kecuali salah satu properti konteks berbeda (`ClientIPAddress`, `ClientInfoString`, `ParentFolder`, jenis logon, `MailAccessType`, `MailboxUPN`, pengguna, atau `SessionId`) [S2]. `SessionId` membantu memisahkan aktivitas penyerang dari aktivitas harian pengguna di akun yang sama [S2].

Langkah investigasi yang disarankan Microsoft [S2]:

1. Tentukan mailbox yang dikompromi dan rentang waktu penyerang punya akses.
2. Cari record sync. Bila ada sync dalam konteks penyerang (IP dan protokol yang sama), anggap penyerang mengunduh semua item di folder itu, dan bila semua folder, seluruh mailbox. Penyerang yang sudah mengunduh bisa membaca secara offline tanpa jejak di server.
3. Cari record bind untuk mendapatkan `InternetMessageId` setiap email yang diakses, lalu periksa isinya untuk data sensitif.

Prinsip yang dipegang Microsoft: dalam investigasi akun email yang terkompromi, anggap data yang terkompromi lebih banyak daripada yang tertelusuri dari kehadiran penyerang, dan bila akses tidak pasti, anggap data terkompromi [S2]. Bagi DPO, ini berarti angka dari `MailItemsAccessed` adalah batas bawah yang terbukti, bukan batas atas.

Dua catatan lain:

- **Lisensi dan sejarah.** Dulu `MailItemsAccessed` hanya tersedia di Audit (Premium). Microsoft mengumumkan perluasan ke pelanggan Audit (Standard) dan rilisnya bertahap pada pertengahan 2024 [S15]. Menurut sumber yang sama, aksi baru itu hanya otomatis ditambahkan ke mailbox yang set auditnya belum pernah diubah manual; mailbox dengan konfigurasi khusus perlu diperbarui sendiri [S15]. Halaman Microsoft tentang mailbox auditing juga menyebut aksi baru tidak otomatis masuk ke mailbox yang set auditnya sudah dikustomisasi [S3]. Cek `DefaultAuditSet` mailbox-mu sebelum insiden.
- **Throttling.** [komunitas, belum terkonfirmasi] Praktisi melaporkan bahwa bila sebuah mailbox menghasilkan lebih dari 1.000 record `MailItemsAccessed` dalam 24 jam, pencatatan aksi itu berhenti selama 24 jam berikutnya, dan record yang terkena ditandai `IsThrottled` bernilai True; dalam kasus itu seluruh mailbox dianggap terkompromi untuk periode tersebut [S14]. Halaman Microsoft yang diperiksa untuk Day ini tidak lagi menyebut throttling, sehingga ambang dan perilakunya perlu dicek di dokumentasi Microsoft terbaru. Langkah aman: selalu periksa field itu sebelum menyimpulkan apa pun dari jumlah record.

Di `INC-2026-021`, analisis di bagian 2.3 menemukan 47 email dibuka lewat sesi OWA penyerang pada Kamis, dan 312 email dibaca aplikasi "Mail Sync Helper" sejak Jumat. Setelah tumpang tindih 28 email dihilangkan, ada 331 `InternetMessageId` unik. Sembilan di antaranya memuat lampiran salinan KTP PIC pelanggan korporat untuk pendaftaran kontrak. Tidak ada record sync dari konteks penyerang dan tidak ada record dengan `IsThrottled` bernilai True.

### 1.6 Menahan dan memulihkan mailbox: urutan kerja

Pertanyaan keenam ("apa urutan kerja kalian?") dijawab dengan urutan yang mengikuti panduan Microsoft untuk akun email yang terkompromi [S1], digabung dengan prinsip containment serentak dari Day 05.

Panduan Microsoft memberi enam langkah untuk menutup cara penyerang bertahan, dan meminta setiap langkah dikerjakan [S1]:

1. **Nonaktifkan akun** selama investigasi. Bila tidak bisa, reset password. Untuk akun yang disinkron dari AD, reset password di AD dua kali untuk mengurangi risiko pass-the-hash. Password baru tidak dikirim lewat email karena penyerang mungkin masih membaca mailbox.
2. **Cabut sesi** dengan `Revoke-MgUserSignInSession`, yang membatalkan refresh token.
3. **Tinjau metode MFA** yang terdaftar dan hapus yang tidak dikenal.
4. **Tinjau aplikasi yang diberi consent** dan cabut yang tidak seharusnya.
5. **Tinjau peran admin** yang diberikan ke akun.
6. **Tinjau forwarding dan inbox rule**, termasuk aturan tersembunyi.

Setelah investigasi selesai, password direset, akun diaktifkan kembali, dan bila mailbox sempat dipakai mengirim spam dalam jumlah besar, akun dikeluarkan dari daftar Restricted entities [S1].

Tiga penyesuaian untuk PT JAB:

- **Bukti dulu, hapus belakangan.** Detail aturan, consent, dan hasil audit diekspor sebelum diubah. Aturan dinonaktifkan dengan `Disable-InboxRule` saat jam H, yang menghentikan pemrosesan tetapi menyimpan aturan untuk investigasi [S7], lalu dihapus saat eradication.
- **Serentak.** Disable akun, revoke sessions, cabut consent, dan nonaktifkan aturan dijalankan dalam satu jendela, karena mencabut satu jalan memberi tahu penyerang untuk memakai jalan lain. Menonaktifkan sign-in akun juga memutus akses aplikasi ke data akun itu, sehingga langkah ini menjadi pengaman sementara sampai consent dicabut [S8].
- **Akun hybrid.** Akun Fitri dikelola dari AD on-premises, jadi status disable diubah di AD dan tersinkron ke Entra ID pada siklus sinkronisasi berikutnya; revoke sessions dijalankan langsung di Entra ID supaya tidak menunggu siklus itu, sama seperti di Day 05 bagian 2.3.

Untuk custom form dan aturan dengan aksi menjalankan aplikasi, Microsoft menyebut Outlook yang terbaru memblok kedua mekanisme itu secara default, dan aturan yang memakai aksi itu ditandai dengan referensi ke file EXE, ZIP, atau URL [S7]. Di `INC-2026-021` aturan "." hanya memindahkan email, tetapi pemeriksaan custom form tetap masuk daftar cek.

### 1.7 Di luar mailbox: uang, pelanggan, dan data pribadi

Pertanyaan terakhir Hendra menyentuh hal yang tidak bisa diselesaikan tim SOC sendirian.

**Uang.** IC3 menyarankan korban BEC segera menghubungi lembaga keuangannya untuk meminta penarikan kembali dana (recall) dan dokumen yang dibutuhkan, dengan catatan kebijakan tiap lembaga berbeda, serta segera melapor ke penegak hukum [S11]. Saran itu ditulis untuk konteks Amerika Serikat; prinsip yang dipakai PT JAB adalah kecepatan: semakin cepat bank pengirim dan bank penerima dihubungi, semakin besar kemungkinan dana bisa ditahan. Prosedur penahanan dana dan jalur laporan pidana di Indonesia diurus Keuangan bersama Legal dan bank, dan perlu dicek di prosedur bank yang bersangkutan.

**Pelanggan.** Message trace dan audit `Send` menunjukkan tiga pelanggan korporat menerima email palsu dari mailbox Fitri pada Jumat 2026-10-23: PT Sentosa Makmur Contoh (Rp 487.500.000, belum transfer karena menelepon dulu), PT Cahaya Logistik Contoh (`INV-JAB-2026-10-0855`, Rp 126.400.000, sudah transfer Jumat 15:30), dan CV Mitra Data Contoh (`INV-JAB-2026-10-0862`, Rp 58.900.000, belum transfer). Totalnya Rp 672.800.000 yang terekspos. Setiap pelanggan dihubungi lewat nomor telepon yang tercantum di kontrak, bukan dengan membalas email, karena mailbox masih dalam investigasi. IC3 menyarankan perubahan informasi rekening diverifikasi lewat kanal kedua [S11], dan itu persis yang menyelamatkan Rp 487,5 juta milik PT Sentosa.

**Data pribadi.** Mailbox Fitri berisi data pribadi PIC pelanggan korporat: nama, nomor telepon, email, dan sembilan email dengan salinan KTP. UU 27/2022 tentang Pelindungan Data Pribadi Pasal 46 mewajibkan pengendali data pribadi, bila terjadi kegagalan pelindungan data pribadi, menyampaikan pemberitahuan tertulis paling lambat 3 x 24 jam kepada subjek data pribadi dan lembaga, dengan isi minimal data yang terungkap, kapan dan bagaimana data terungkap, serta upaya penanganan dan pemulihan [S12]. Titik mulai hitungan 3 x 24 jam tidak tertulis di bunyi pasal itu; apakah dihitung sejak kejadian, sejak diketahui, atau sejak tervalidasi perlu dicek ke penjelasan resmi dan aturan pelaksanaannya oleh Legal. Penilaian apakah akses ke 331 email memenuhi kriteria kegagalan pelindungan data pribadi adalah keputusan DPO Agus Setiawan dan Legal Ratna Sari, bukan tim SOC. Tugas tim SOC adalah memberi fakta yang bisa dipertanggungjawabkan: email mana yang terbukti diakses, kapan, dari mana, dan apa batas pengetahuan itu (bagian 1.5). Catatan ini bukan nasihat hukum.

## 2. Contoh artefak dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Perintah PowerShell dijalankan dari jump host admin yang tidak termasuk scope, dengan akun admin yang tidak pernah login ke `JKT-WS-0469`. UPN karyawan PT JAB memakai domain `jab.example`. IP NAT kantor Jakarta ke internet adalah `198.51.100.120`, sehingga akses sah Fitri dari kantor terlihat dari IP itu di audit log Microsoft 365.

### 2.1 Cek cepat mailbox: inbox rule dan forwarding

Langkah ini menjawab pertanyaan ketiga Hendra dan dijalankan Rudi pukul 09:35, sebelum insiden dinyatakan.

**Tujuan:** melihat forwarding di level mailbox dan semua inbox rule, termasuk yang tersembunyi.

```powershell
Connect-ExchangeOnline
Get-Mailbox -Identity fitri.handayani@jab.example | Format-List Forwarding*Address,DeliverTo*
Get-InboxRule -Mailbox fitri.handayani@jab.example -IncludeHidden |
    Format-List Name,Enabled,Priority,SubjectOrBodyContainsWords,MoveToFolder,MarkAsRead,StopProcessingRules,RedirectTo,Forward*,Identity
```

Penjelasan tiap bagian [S1]:

- `Forwarding*Address` menampilkan `ForwardingAddress` (internal) dan `ForwardingSmtpAddress` (eksternal); `DeliverTo*` menampilkan `DeliverToMailboxAndForward`, yang menentukan apakah email tetap dikirim ke mailbox asli.
- `-IncludeHidden` menyertakan aturan yang tidak tampil di daftar biasa.
- `RedirectTo`, `ForwardTo`, dan `ForwardAsAttachmentTo` yang terisi berarti email dikirim ke penerima lain. `Identity` dipakai untuk melihat atau menonaktifkan aturan tertentu.

Keluaran ilustrasi (diringkas):

```
ForwardingAddress          :
ForwardingSmtpAddress      :
DeliverToMailboxAndForward : False

Name                       : Piutang Korporat
Enabled                    : True
Priority                   : 1
SubjectOrBodyContainsWords :
MoveToFolder               : Piutang Korporat
...
Identity                   : fitri.handayani\17228413306732085249

Name                       : .
Enabled                    : True
Priority                   : 2
SubjectOrBodyContainsWords : {rekening, transfer, pembayaran, bukti bayar, INV-JAB, konfirmasi}
MoveToFolder               : RSS Subscriptions
MarkAsRead                 : True
StopProcessingRules        : True
RedirectTo                 :
ForwardTo                  :
ForwardAsAttachmentTo      :
Identity                   : fitri.handayani\17228413306732085250
```

Cara membaca hasil:

- Tidak ada forwarding di level mailbox dan tidak ada aturan yang meneruskan email keluar. Data tidak dialirkan lewat jalur ini, tetapi jalur lain (aplikasi OAuth) belum dicek.
- Aturan "Piutang Korporat" cocok dengan pekerjaan Fitri; Fitri mengonfirmasi ia membuatnya.
- Aturan "." punya tiga ciri aturan penyerang sekaligus: nama karakter minimal, tujuan folder yang jarang dibuka, dan kombinasi `MarkAsRead` dengan `StopProcessingRules` [S10][S13]. Kata kuncinya menyasar percakapan pembayaran.

**Variasi:** untuk memeriksa semua mailbox di tenant sekaligus, Microsoft menyebut skrip `Get-AllTenantRulesAndForms.ps1` yang mengekspor semua aturan dan custom form ke CSV; kolom `IsPotentiallyMalicious` bernilai `TRUE` dan `ActionType` bernilai `ID_ACTION_CUSTOM` adalah tanda aturan berbahaya [S7]. Di PT JAB, perburuan tenant dilakukan lewat Splunk (bagian 2.5).

**Kapan gagal:** aturan dibuat lewat cara yang tidak memakai inbox rule biasa, misalnya transport rule oleh akun admin yang terkompromi, atau aplikasi yang membaca langsung lewat API. Karena itu cek aturan selalu diikuti pencarian audit dan pemeriksaan consent.

### 2.2 Timeline dari Unified Audit Log

Langkah ini menjawab pertanyaan pertama dan kedua: urutan yang dilakukan penyerang di mailbox Fitri.

**Tujuan:** menarik semua aksi mailbox dan aturan untuk akun Fitri dari Kamis 2026-10-22 00:00 sampai Senin 2026-10-26 12:00 WIB.

```powershell
# 22 Okt 00:00 WIB = 21 Okt 17:00 UTC; 26 Okt 12:00 WIB = 26 Okt 05:00 UTC
$ops = "New-InboxRule","Set-InboxRule","UpdateInboxRules","Send",
       "MoveToDeletedItems","SoftDelete","HardDelete"
$r = Search-UnifiedAuditLog -StartDate "2026-10-21 17:00:00z" -EndDate "2026-10-26 05:00:00z" `
       -UserIds fitri.handayani@jab.example -Operations $ops `
       -SessionId "INC021-timeline" -SessionCommand ReturnLargeSet -ResultSize 5000
$r | ForEach-Object {
    $d = $_.AuditData | ConvertFrom-Json
    [pscustomobject]@{ TimeUtc = $d.CreationTime; Operation = $d.Operation; ClientIP = $d.ClientIP }
} | Sort-Object TimeUtc | Format-Table
```

Penjelasan tiap bagian:

- Rentang waktu ditulis dalam UTC dengan akhiran `z`, karena audit log disimpan dalam UTC [S5].
- `SessionId` dan `SessionCommand ReturnLargeSet` dipakai supaya hasil tidak berhenti di 100 record; perintah diulang dengan `SessionId` yang sama sampai tidak ada hasil baru [S5]. Hasil `ReturnLargeSet` tidak tersortir, jadi diurutkan sendiri.
- `AuditData` adalah JSON; nama field IP bisa berbeda antar jenis record (`ClientIP` di record admin Exchange, `ClientIPAddress` di record mailbox), jadi periksa satu record mentah sebelum membuat tabel.
- `MailItemsAccessed` sengaja dipisah ke bagian 2.3 karena volumenya jauh lebih besar.

Keluaran ilustrasi (jam UTC, diringkas; kolom WIB ditambahkan untuk laporan):

```
TimeUtc              WIB                 Operation           ClientIP
2026-10-22 03:26:41  22 Okt 10:26:41     New-InboxRule       203.0.113.131
2026-10-22 03:47:55  22 Okt 10:47:55     MoveToDeletedItems  203.0.113.131
2026-10-22 03:48:02  22 Okt 10:48:02     SoftDelete          203.0.113.131
2026-10-23 01:58:12  23 Okt 08:58:12     Set-InboxRule       203.0.113.131
2026-10-23 02:12:30  23 Okt 09:12:30     Send                203.0.113.131
2026-10-23 02:14:05  23 Okt 09:14:05     Send                203.0.113.131
2026-10-23 02:16:47  23 Okt 09:16:47     Send                203.0.113.131
2026-10-23 02:18:20  23 Okt 09:18:20     MoveToDeletedItems  203.0.113.131
2026-10-23 02:18:26  23 Okt 09:18:26     SoftDelete          203.0.113.131
```

Cara membaca hasil:

- Semua aksi berasal dari `203.0.113.131`, bukan dari NAT kantor `198.51.100.120`. Aksi Fitri sendiri di periode itu (dari kantor) disaring di tabel ini supaya ringkas, tetapi tetap disimpan di hasil lengkap.
- `MoveToDeletedItems` lalu `SoftDelete` pukul 10:47 menghapus email phishing asli dari kotak masuk Fitri, sesuai pola di bagian 1.1 [S10].
- Tiga `Send` berurutan pukul 09:12 sampai 09:16 Jumat adalah tiga email palsu ke tiga pelanggan, lalu dihapus dari Sent Items dan Deleted Items pukul 09:18. Item yang di-`SoftDelete` masih ada di Recoverable Items, sehingga salinannya bisa diambil untuk bukti; bila ada `HardDelete`, item itu sudah hilang dari mailbox.
- Detail penerima tiap `Send` dicocokkan dengan message trace, misalnya `Get-MessageTraceV2 -SenderAddress fitri.handayani@jab.example -StartDate "10/23/2026" -EndDate "10/24/2026"`. Cmdlet ini mencakup data 90 hari terakhir, maksimal 10 hari per query, dan menampilkan waktu dalam UTC [S9]. Karena PT JAB memakai Defender for Office 365 Plan 2, Rudi juga bisa melihat email yang sama di Threat Explorer; hasil keduanya dicocokkan sebelum daftar penerima ditulis di laporan.

**Variasi:** tambahkan `-FreeText "INV-JAB"` untuk mencari record yang memuat teks tertentu, atau `-IPAddresses 203.0.113.131` untuk melihat semua aksi dari IP penyerang di seluruh tenant, bukan hanya akun Fitri [S5].

**Kapan gagal:** aktivitas berada di luar masa simpan audit, atau baru terjadi dan belum muncul karena jeda 30 menit sampai 24 jam [S4][S8]. Ulangi pencarian keesokan harinya sebelum menutup timeline.

### 2.3 Email apa saja yang dibaca: menganalisis MailItemsAccessed

Langkah ini menjawab pertanyaan kelima, dan hasilnya dikirim ke DPO dan Legal.

**Tujuan:** memisahkan sync dan bind, mengelompokkan per konteks (IP dan aplikasi), memeriksa throttling, lalu menghasilkan daftar `InternetMessageId` yang diakses penyerang.

```powershell
$r = Search-UnifiedAuditLog -StartDate "2026-10-21 17:00:00z" -EndDate "2026-10-26 05:00:00z" `
       -UserIds fitri.handayani@jab.example -Operations MailItemsAccessed `
       -SessionId "INC021-mia" -SessionCommand ReturnLargeSet -ResultSize 5000
$rows = $r | ForEach-Object {
    $d = $_.AuditData | ConvertFrom-Json
    $p = @{}; $d.OperationProperties | ForEach-Object { $p[$_.Name] = $_.Value }
    [pscustomobject]@{
        TimeUtc   = $d.CreationTime
        Ip        = $d.ClientIPAddress
        Client    = $d.ClientInfoString
        AppId     = $d.AppId
        Session   = $d.SessionId
        Type      = $p['MailAccessType']
        Throttled = $p['IsThrottled']
        Items     = @($d.Folders.FolderItems.InternetMessageId)
    }
}
$rows | Where-Object Throttled -eq 'True'          # harus kosong sebelum lanjut
$rows | Group-Object Ip,Type | ForEach-Object {
    [pscustomobject]@{ Konteks = $_.Name; Record = $_.Count
                       Item = ($_.Group.Items | Sort-Object -Unique).Count }
}
```

Penjelasan tiap bagian:

- `MailAccessType` di `OperationProperties` membedakan `Sync` dan `Bind` [S2]; contoh resmi Microsoft memfilternya dengan pencocokan teks pada `AuditData`, dan versi di atas mengurai JSON supaya bisa dikelompokkan.
- `ClientIPAddress`, `ClientInfoString`, dan `SessionId` adalah properti konteks yang dipakai Microsoft untuk membedakan penyerang dari pengguna [S2]. `AppId` ditambahkan untuk mengenali akses lewat aplikasi; cek nama field ini di record mentah tenant-mu.
- Daftar item bind diambil dari `Folders`, tempat `InternetMessageId` disimpan untuk setiap record gabungan dua menit [S2]. Struktur bersarangnya perlu dicek di satu record mentah sebelum skrip dipakai.
- Pemeriksaan `IsThrottled` dijalankan paling awal karena hasilnya mengubah cara membaca semua angka lain [S14].

Keluaran ilustrasi:

```
(tidak ada record dengan IsThrottled = True)

Konteks                 Record  Item
198.51.100.120, Sync        14     0
203.0.113.131, Bind          9    47
203.0.113.136, Bind         58   312
```

Cara membaca hasil:

- `198.51.100.120, Sync` adalah Outlook desktop Fitri di kantor; sync dicatat per folder, sehingga kolom item kosong. Karena konteksnya bukan konteks penyerang, record ini bukan dasar untuk menganggap seluruh folder dibaca penyerang [S2].
- `203.0.113.131, Bind`: 9 record gabungan berisi 47 email yang dibuka lewat OWA dengan sesi curian pada Kamis 10:31 sampai 10:52.
- `203.0.113.136, Bind`: 58 record berisi 312 email yang dibaca aplikasi "Mail Sync Helper" (`AppId` aplikasi itu) dari Jumat 02:04 sampai Senin 10:12 WIB. Record terakhir pukul 09:58 dan 10:12 terjadi setelah password direset pukul 09:40.
- Gabungan kedua kelompok penyerang, setelah 28 email yang sama dihilangkan, adalah 331 `InternetMessageId` unik. Daftar itu dicocokkan dengan isi mailbox untuk mencari data pribadi; hasilnya sembilan email dengan salinan KTP PIC pelanggan.

Ringkasan untuk DPO ditulis dengan batasnya:

```
INC-2026-021 | Akses penyerang ke mailbox fitri.handayani | per 26-10-2026 13:30 WIB
TERBUKTI: 331 email unik diakses (47 via OWA 22 Okt; 312 via aplikasi Mail Sync Helper
          23-26 Okt; 28 tumpang tindih). 9 email berisi lampiran salinan KTP PIC pelanggan.
TIDAK DITEMUKAN: sync dari konteks penyerang; record throttled.
BATAS: pencarian di mailbox (SearchQueryInitiated) tidak tercatat di tenant PT JAB;
       record bisa muncul sampai 24 jam setelah aktivitas, pencarian diulang 27 Okt 13:30;
       Microsoft menganjurkan menganggap data terkompromi lebih luas dari yang tertelusuri.
```

**Variasi:** bila kamu hanya peduli beberapa email sensitif, cari record yang memuat `InternetMessageId` email itu untuk melihat siapa yang mengaksesnya [S2].

**Kapan gagal:** lisensi atau konfigurasi audit mailbox tidak mencakup `MailItemsAccessed` (misalnya set audit yang pernah dikustomisasi), record throttled, atau ada sync dari konteks penyerang. Dalam semua kasus itu, angka "email yang diakses" tidak bisa dipakai sebagai batas atas, dan laporan ke DPO harus menyebut asumsi seluruh folder atau seluruh mailbox.

### 2.4 Consent aplikasi: menemukan dan mencabut

Langkah ini menjawab bagian pertanyaan keempat tentang akses yang bertahan setelah password diganti.

**Tujuan:** menemukan aktivitas consent di audit, lalu menginventarisasi dan mencabut grant aplikasi pada akun Fitri.

Di halaman Audit portal Defender, Rudi mencari semua aktivitas di rentang Kamis sampai Senin tanpa filter aktivitas, mengurutkan kolom Activity, lalu membuka entri **Consent to application** dan memeriksa `IsAdminConsent` [S8]. Entri yang ditemukan: Kamis 10:44:09 WIB, aplikasi "Mail Sync Helper", `IsAdminConsent` False, dari `203.0.113.131`. Nilai False berarti consent hanya untuk data Fitri, bukan seluruh tenant.

```powershell
Connect-MgGraph -Scopes "DelegatedPermissionGrant.ReadWrite.All","Application.Read.All","User.Read.All"
$u = Get-MgUser -UserId fitri.handayani@jab.example
Get-MgUserOauth2PermissionGrant -UserId $u.Id | ForEach-Object {
    $sp = Get-MgServicePrincipal -ServicePrincipalId $_.ClientId
    [pscustomobject]@{ App = $sp.DisplayName; AppId = $sp.AppId; ConsentType = $_.ConsentType
                       Scope = $_.Scope; GrantId = $_.Id }
} | Format-Table -AutoSize

# Saat jam H, setelah hasil di atas disimpan sebagai bukti:
Remove-MgOauth2PermissionGrant -OAuth2PermissionGrantId "<GrantId Mail Sync Helper>"
```

Penjelasan tiap bagian:

- Grant delegated per pengguna punya `ConsentType` `Principal`; `AllPrincipals` berarti aplikasi bisa mengakses data semua pengguna di tenant dan, untuk aplikasi non-Microsoft, harus ditinjau teliti [S8].
- `Scope` berisi izin yang diberikan. Izin baca dan tulis atau izin `All` perlu ditinjau teliti [S8].
- `Remove-MgOauth2PermissionGrant` mencabut consent delegated; untuk izin aplikasi (app role), Microsoft menyebut `Remove-MgServicePrincipalAppRoleAssignment` [S8].

Keluaran ilustrasi:

```
App               AppId                                 ConsentType Scope                                      GrantId
---               -----                                 ----------- -----                                      -------
Mail Sync Helper  6f1e2c3a-0b7d-4e59-9a14-2d8c5b7e0f31  Principal   User.Read Mail.Read Mail.Send offline_access 8kR2...Qw
```

Cara membaca hasil: satu aplikasi dengan nama generik, izin baca dan kirim email, dan `offline_access` yang membuat aplikasi bisa terus memperoleh token tanpa pengguna hadir. Nama yang hambar atau mirip layanan sah adalah salah satu ciri yang disebut Microsoft untuk aplikasi yang perlu dicurigai [S8]. `AppId` ini dipakai sebagai IOC untuk perburuan di bagian 2.5.

**Kapan gagal:** consent diberikan dengan `IsAdminConsent` True atau `AllPrincipals`, sehingga yang perlu dicabut bukan hanya grant satu pengguna; atau aplikasi berbahaya terdaftar di tenant sendiri oleh akun yang terkompromi, sehingga aplikasinya sendiri juga harus diperiksa.

### 2.5 Berburu di seluruh tenant dengan Splunk

Query ini menjawab pertanyaan lanjutan dari scoping: apakah mailbox lain di PT JAB punya aturan serupa atau consent ke aplikasi yang sama. Hasilnya dicatat sebagai `SOC-2026-0221` (aturan) dan `SOC-2026-0222` (consent).

**Tujuan:** menampilkan semua pembuatan dan perubahan inbox rule dalam 30 hari terakhir, lalu menandai aturan yang punya ciri penyerang.

```
index=o365 Operation IN ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
earliest="09/26/2026:00:00:00" latest="10/26/2026:12:00:00"
| eval params=mvzip('Parameters{}.Name', 'Parameters{}.Value', "=")
| eval rule_name=replace(mvindex(mvfilter(match(params, "^Name=")), 0), "^Name=", "")
| eval move_to=replace(mvindex(mvfilter(match(params, "^MoveToFolder=")), 0), "^MoveToFolder=", "")
| eval hide=if(isnotnull(mvfilter(match(params, "^(MarkAsRead|DeleteMessage)=True$"))), "yes", "no")
| eval suspicious=case(match(rule_name, "^[\.,;\s]+$"), "nama minimal",
                       match(move_to, "(?i)RSS|Archive|Conversation History") AND hide="yes", "sembunyikan",
                       true(), "-")
| table _time UserId ClientIP Operation rule_name move_to hide suspicious
| sort _time
```

Penjelasan tiap bagian:

- Field `Operation`, `UserId`, `ClientIP`, dan pasangan `Parameters{}.Name`/`Parameters{}.Value` mengikuti event Management Activity API yang di-ingest add-on Microsoft 365 untuk Splunk; nama field bisa berbeda di add-on dan versi-mu, jadi cek satu event mentah dulu.
- `mvzip` memasangkan nama dan nilai parameter menjadi `Nama=Nilai`, lalu `mvfilter` mengambil parameter tertentu.
- `suspicious` memakai ciri dari bagian 1.3: nama karakter minimal, atau pindah ke folder yang jarang dibuka sambil disembunyikan [S10][S13]. `UpdateInboxRules` dari Outlook desktop tidak membawa parameter dengan bentuk yang sama, sehingga barisnya muncul dengan kolom aturan kosong dan perlu dibuka satu per satu.

Keluaran ilustrasi (jam WIB):

```
_time                UserId                        ClientIP        Operation         rule_name         move_to            hide  suspicious
2026-10-14 13:02:55  maya.lestari@jab.example      198.51.100.120  New-InboxRule     Media Monitoring  Media Monitoring   no    -
2026-10-22 10:26:41  fitri.handayani@jab.example   203.0.113.131   New-InboxRule     .                 RSS Subscriptions  yes   nama minimal
2026-10-23 08:58:12  fitri.handayani@jab.example   203.0.113.131   Set-InboxRule     .                 RSS Subscriptions  yes   nama minimal
2026-10-24 19:40:03  irawan.setiadi@jab.example    198.51.100.120  UpdateInboxRules                                       no    -
```

Cara membaca hasil:

- Hanya mailbox Fitri yang punya aturan dengan ciri penyerang. Aturan Maya Lestari jelas berhubungan dengan pekerjaannya di Corporate Communication.
- Baris `UpdateInboxRules` milik Irawan Setiadi (Kepala Divisi Keuangan) kosong parameternya. Rudi memeriksanya langsung dengan `Get-InboxRule -IncludeHidden` di mailbox Irawan dan mengonfirmasi dengan Irawan bahwa aturan itu dibuatnya dari Outlook desktop di kantor.

**Variasi:** ganti baris pertama dengan `index=o365 Operation="Consent to application*"` lalu cari `AppId` "Mail Sync Helper" di detail event, untuk melihat apakah pengguna lain memberi consent ke aplikasi yang sama; dan cari `MailItemsAccessed` dengan `AppId` itu di seluruh tenant. Di `INC-2026-021` keduanya hanya menemukan akun Fitri. Empat penerima lain email phishing yang sama diperiksa sign-in-nya dengan langkah Day 10 bagian 2.7.

**Kapan gagal:** audit log tidak di-ingest ke Splunk atau ingest tertinggal, sehingga hasil kosong dibaca sebagai "bersih". Cocokkan jumlah event di Splunk dengan pencarian Audit di portal untuk satu hari yang sama sebelum memercayai hasil kosong.

### 2.6 Rencana jam H mailbox dan update ke Hendra

Rencana ini menjawab pertanyaan keenam. Jam H ditetapkan 11:45, setelah bukti diekspor. Kolom R dan A mengikuti RACI PT JAB (Day 02 bagian 2.2).

| Menit | Tindakan | R (pelaksana) | A | Verifikasi |
|---|---|---|---|---|
| H-15 | Ekspor bukti: detail aturan, daftar consent, hasil audit bagian 2.2 dan 2.3, salinan email palsu dari Recoverable Items | Rudi | IC | File di `/evidence/INC-2026-021/` dengan hash |
| H+0 | Disable akun `fitri.handayani` di AD, paksa siklus sinkronisasi | Infrastruktur | IC | `Enabled False` di AD dan status di Entra ID |
| H+0 | `Revoke-MgUserSignInSession` untuk Fitri | Infrastruktur | IC | Nilai `True`; sign-in gagal di log Entra (Day 10 bagian 1.4) |
| H+0 | Cabut consent "Mail Sync Helper" | Rudi | IC | Grant tidak lagi muncul |
| H+0 | `Disable-InboxRule` aturan "." | Rudi | IC | `Enabled False` |
| H+5 | Hapus metode MFA yang didaftarkan penyerang; tinjau peran admin dan app password | Infrastruktur | IC | Daftar metode dan peran |
| H+10 | Keuangan menelepon tiga pelanggan lewat nomor di kontrak | Irawan Setiadi | Hendra | Konfirmasi tiap pelanggan tercatat |
| H+30 | Validasi: tidak ada `MailItemsAccessed` dari `203.0.113.136` atau `AppId` aplikasi setelah H+0 | Rudi | IC | Pencarian diulang 24 jam kemudian karena jeda audit |
| Eradication | Hapus aturan "." dan aplikasi dari akun; reset password dua kali di AD; aktifkan akun; Fitri mendaftar ulang MFA bersama helpdesk | Infrastruktur, Rudi | IC | Checklist pemulihan Day 10 bagian 2.8 |

Update yang dikirim Dimas pukul 13:30 sesuai ritme SEV-2 (update setiap 4 jam):

```
INC-2026-021 | Update 13:30 | SEV-2 | untuk Hendra Wijaya
CARA MASUK: phishing 22 Okt 10:12, halaman login palsu mencuri sesi Fitri setelah MFA.
CONTAINMENT (jam H 11:45, terverifikasi): akun Fitri dinonaktifkan, sesi dicabut,
  aplikasi "Mail Sync Helper" dicabut, aturan penyembunyi email dinonaktifkan,
  metode MFA milik penyerang dihapus.
  Catatan: reset password 09:40 tidak memutus akses; aplikasi masih membaca email
  sampai 10:12. Mulai sekarang reset hanya dilakukan dalam jam H.
DAMPAK KEUANGAN: 3 pelanggan menerima email palsu (Rp 672,8 juta terekspos).
  PT Cahaya Logistik sudah transfer Rp 126,4 juta Jumat 15:30; Keuangan dan Legal
  menghubungi bank sejak 12:10. Sentosa dan Mitra Data belum transfer, sudah dikonfirmasi.
DATA PRIBADI: 331 email terbukti diakses, 9 berisi salinan KTP PIC pelanggan.
  Ringkasan dan batasnya sudah dikirim ke DPO dan Legal untuk penilaian UU PDP.
BERIKUTNYA: cek sign-in empat penerima phishing lainnya; ulang pencarian audit besok.
Update berikutnya: 17:30.
```

Cara membaca elemennya:

- **Reset 09:40 ditulis terang-terangan** sebagai pelajaran, bukan disembunyikan. Itu juga dasar perubahan prosedur helpdesk setelah insiden.
- **Dampak keuangan dan data pribadi dipisah**, karena pemilik keputusannya berbeda: Keuangan dan bank untuk uang, DPO dan Legal untuk data pribadi.
- **Pencarian audit diulang besok**, karena jeda audit bisa sampai 24 jam (bagian 1.2).

## 3. Lab praktik

Lab ini memakai tenant uji Microsoft 365 (trial atau tenant developer bila tersedia untukmu) dengan dua akun uji, tanpa data nyata. Jangan memakai tenant kantor atau akun orang lain. Bila tenant-mu berlisensi E3 atau E5, `MailItemsAccessed` seharusnya tercatat; cek dulu di langkah 1.

1. **Kesiapan audit.** Jalankan `Get-OrganizationConfig | Format-List AuditDisabled` dan `Get-Mailbox <akun-uji> | Format-List DefaultAuditSet` [S3]. Catat masa simpan audit tenant-mu menurut lisensinya [S4].
2. **Aturan penyerang tiruan.** Login sebagai akun uji A lewat Outlook web dari jaringan berbeda (misalnya hotspot ponsel). Buat aturan bernama "." yang memindahkan email berisi "rekening" ke RSS Subscriptions dan menandainya sudah dibaca. Kirim email uji dari akun B dan pastikan email itu tidak terlihat di Inbox.
3. **Temukan aturannya.** Sebagai admin, jalankan perintah bagian 2.1. Lalu tunggu, dan catat berapa lama sampai `New-InboxRule` muncul di pencarian bagian 2.2.
4. **Sync dan bind.** Buka lima email tertentu di akun A lewat Outlook web, lalu buka akun A di Outlook desktop dan biarkan sync. Jalankan skrip bagian 2.3. Bandingkan record bind (dengan daftar `InternetMessageId`) dan record sync (per folder).
5. **Consent.** Daftarkan aplikasi uji milikmu sendiri di Entra ID tenant uji dengan izin delegated `Mail.Read`, beri consent sebagai akun A, lalu temukan aktivitas **Consent to application** di Audit dan grant-nya dengan perintah bagian 2.4. Reset password akun A dan catat apakah grant masih ada. Cabut grant-nya.
6. **Jam H dan laporan.** Tulis rencana jam H dengan format bagian 2.6 untuk akun A, jalankan, lalu tulis ringkasan akses untuk "DPO" dengan format bagian 2.3, termasuk bagian BATAS.

**Hasil yang sebaiknya tersimpan:**

- `latihan/day09-kesiapan-audit.md` berisi status audit, `DefaultAuditSet`, dan masa simpan.
- Catatan waktu jeda antara pembuatan aturan dan munculnya record audit.
- Keluaran skrip bagian 2.3 dengan penjelasan perbedaan sync dan bind.
- Bukti bahwa grant aplikasi masih ada setelah reset password, lalu hilang setelah dicabut.
- `latihan/day09-jam-h.md` berisi rencana jam H dan ringkasan akses untuk DPO.

**Variasi tantangan:** bila tenant uji-mu mengirim audit log ke Splunk lewat add-on Microsoft 365, jalankan query bagian 2.5 dan cocokkan jumlah event `New-InboxRule` dengan hasil pencarian di portal. Berapa selisih waktu antara portal dan Splunk?

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat menyelidiki mailbox yang terkompromi. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| `Search-UnifiedAuditLog` hanya mengembalikan 100 record | Tanpa `SessionCommand` | Pakai `SessionId` dan `SessionCommand ReturnLargeSet`, ulangi sampai hasil habis [S5] |
| Hasil berhenti di 10.000 record | `ReturnLargeSet` dan `ReturnNextPreviewPage` dicampur di satu `SessionId` | Pakai satu nilai `SessionCommand` per `SessionId` [S5] |
| Aktivitas yang dilaporkan pengguna tidak ada di hasil | Jeda audit 30 menit sampai 24 jam, atau rentang waktu salah zona | Ulangi pencarian kemudian; tulis waktu dalam UTC [S5][S8] |
| Tidak ada `MailItemsAccessed` sama sekali | Lisensi, atau set audit mailbox pernah dikustomisasi | Cek `DefaultAuditSet` dan aksi audit pemilik [S3][S15] |
| Tidak ada jejak pencarian penyerang | `SearchQueryInitiated` tidak dicatat secara default | Tulis sebagai batas di laporan; aktifkan untuk mailbox berisiko sebelum insiden [S3] |
| Jumlah `MailItemsAccessed` tiba-tiba berhenti | Kemungkinan throttling | Cari record dengan `IsThrottled` True; anggap seluruh mailbox terkompromi untuk periode itu [S14] |
| Penyerang masih membaca email setelah password direset | Aplikasi OAuth dengan consent, atau sesi belum dicabut | Cabut consent dan revoke sessions di jam H [S1][S8] |
| Aturan muncul lagi setelah dihapus | Penyerang masih punya akses, atau aturan dibuat dari perangkat yang masih tersinkron | Tutup semua jalan masuk dulu; periksa semua perangkat yang memakai Outlook [S7] |
| Pengguna tidak bisa mengirim email setelah dipulihkan | Mailbox masuk Restricted entities karena volume kirim | Keluarkan dari Restricted entities [S1] |
| Skrip `Get-AllTenantRulesAndForms.ps1` gagal terhubung | Metode koneksi lama di skrip arsip | Hapus baris koneksi lama dan hubungkan ke Exchange Online PowerShell lebih dulu [S7] |

## 5. Kesalahan umum dan jebakan

- Menolak hipotesis kompromi mailbox karena "korban pakai MFA". AiTM mencuri sesi setelah MFA [S10].
- Mengganti password lalu menganggap selesai. Sesi, metode MFA, consent aplikasi, aturan, forwarding, dan app password tetap ada [S1][S8].
- Mengganti password sebelum scope diketahui, di luar jam H. Penyerang diberi tahu dan memakai jalan lain.
- Menghapus aturan berbahaya sebelum detailnya diekspor. Kondisi dan kata kunci aturan adalah bukti niat dan petunjuk target.
- Menyimpulkan "penyerang tidak mencari apa-apa" dari ketiadaan `SearchQueryInitiated` [S3].
- Menulis jumlah email dari `MailItemsAccessed` sebagai batas atas, tanpa memeriksa sync dari konteks penyerang dan throttling [S2][S14].
- Mencari audit dengan jam WIB tanpa konversi ke UTC [S5].
- Menyimpulkan hasil pencarian audit sudah lengkap padahal belum lewat 24 jam [S8].
- Mengirim password baru atau peringatan ke pelanggan lewat email dari mailbox yang masih diselidiki [S1].
- Menunggu investigasi selesai sebelum Keuangan menghubungi bank. Untuk dana yang sudah ditransfer, kecepatan menentukan peluang penahanan [S11].
- Memutuskan sendiri apakah insiden wajib dilaporkan menurut UU PDP. Itu keputusan DPO dan Legal berdasarkan fakta dari tim IR.

## 6. Catatan terkini

Bagian ini menampung detail versi dan perubahan layanan yang bisa berubah. Berguna saat memakai fitur yang disebut, tetapi tidak mengubah urutan investigasi.

- **Masa simpan Audit (Standard)** naik dari 90 hari ke 180 hari untuk log yang dibuat sejak 17 Oktober 2023 [S4].
- **`MailItemsAccessed` dan `Send` untuk Audit (Standard)** diumumkan Microsoft pada Juli 2023 dan rilisnya bertahap sekitar Juni 2024 menurut roadmap Microsoft 365 [S15]. Halaman Microsoft yang diperiksa (ms.date 2026-06-19) menyebut `MailItemsAccessed` bagian dari Audit (Standard) untuk lisensi E3 dan E5 [S2].
- **Throttling `MailItemsAccessed`** dijelaskan di dokumentasi Microsoft versi lama dan masih dilaporkan praktisi pada 2025 [S14], tetapi tidak disebut di halaman Microsoft yang diperiksa untuk Day ini. Cek status terbarunya.
- **`HighCompleteness`** di `Search-UnifiedAuditLog` masih preview dan belum tersedia di semua organisasi [S5].
- **Message trace**: `Get-MessageTraceV2` menggantikan `Get-MessageTrace`; data 90 hari, 10 hari per query, maksimal 5.000 hasil, tanpa paging bawaan (lanjutkan dengan `StartingRecipientAddress` dan `EndDate`) [S9].
- **Skrip `Get-AllTenantRulesAndForms.ps1`** sudah diarsipkan sejak Januari 2021; baris koneksinya memakai remote PowerShell yang tidak didukung lagi sejak Juli 2023 [S7].
- **Panduan consent Microsoft** kini memakai Microsoft Graph PowerShell SDK; skrip inventaris `Get-AzureADPSPermissions.ps1` yang disebut di halaman itu dijalankan setelah `Connect-MgGraph` [S8].

## 7. Cheat sheet

```
POLA BEC: AiTM curi sesi (setelah MFA) -> rule sembunyikan -> baca thread bayar
  -> balas thread "rekening baru" -> hapus dari Sent/Deleted -> (consent app untuk bertahan)

AUDIT M365 (UAL)
  mailbox auditing default ON | cek AuditDisabled, DefaultAuditSet, audit bypass
  TIDAK default untuk owner: SearchQueryInitiated, MailboxLogin
  jeda 30 menit - 24 jam | simpan: Standard 180 hari (sejak 17-10-2023), Premium 1 tahun+
  Search-UnifiedAuditLog: UTC | default 100 | ReturnLargeSet s.d. 50.000 (SessionId sama)
    | ResultSize maks 5.000 | jangan campur SessionCommand

OPERASI PENTING: New-InboxRule | Set-InboxRule | UpdateInboxRules | Send
  | MoveToDeletedItems | SoftDelete | HardDelete | MailItemsAccessed | Consent to application

RULE: Get-InboxRule -IncludeHidden | nama ".", "..", ";" | RSS/Archive/Conversation History
  + MarkAsRead + StopProcessingRules | forwarding: ForwardingSmtpAddress, RedirectTo, ForwardTo
  bertahan setelah ganti password, ganti laptop, instal ulang Outlook
  Disable-InboxRule (simpan bukti) -> Remove-InboxRule saat eradication

MAILITEMSACCESSED
  sync = per folder (Outlook desktop) -> konteks penyerang = folder/mailbox terkompromi
  bind = per email, InternetMessageId, gabung per 2 menit (Folders, OperationCount)
  konteks: ClientIPAddress, ClientInfoString, SessionId (+ AppId)
  cek IsThrottled dulu | angka = batas bawah, bukan batas atas

CONSENT: audit "Consent to application" | IsAdminConsent | ConsentType Principal vs AllPrincipals
  reset password/MFA TIDAK mencabut | Remove-MgOauth2PermissionGrant

URUTAN (Microsoft): disable akun (AD: reset 2x) | revoke sessions | metode MFA
  | consent app | peran admin | forwarding + rule  -> semua di jam H, bukti dulu

DI LUAR MAILBOX: bank secepatnya | pelanggan via nomor di kontrak, bukan email
  | DPO + Legal menilai UU PDP Pasal 46 (3 x 24 jam; titik mulai cek ke Legal)
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Password Fitri sudah diganti pukul 09:40, jadi sejak 09:40 penyerang tidak bisa lagi membaca email Fitri." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Aplikasi "Mail Sync Helper" sudah diberi consent dan memegang izin `Mail.Read` dengan `offline_access`, dan Microsoft menyebut reset password dan MFA tidak efektif terhadap illicit consent grant. Audit menunjukkan aplikasi itu masih membaca email pukul 09:58 dan 10:12. Selain itu, sesi yang sudah terbit, metode MFA milik penyerang, dan inbox rule juga tidak hilang karena reset password. Lihat bagian 1.4 dan 2.3.

</details>

**2. Skenario keputusan.** Di kasus lain, audit menunjukkan record `MailItemsAccessed` jenis Sync untuk folder Inbox dari IP dan protokol yang sama dengan sesi penyerang, ditambah 20 record Bind berisi 60 email. Apa yang kamu sampaikan ke DPO?

- A. Penyerang terbukti mengakses 60 email; daftar `InternetMessageId`-nya terlampir.
- B. Seluruh isi folder Inbox dianggap terkompromi, ditambah 60 email dari record Bind di folder lain, dengan penjelasan bahwa sync memungkinkan penyerang membaca secara offline tanpa jejak.
- C. Belum ada bukti email dibaca, karena sync hanya mengunduh dan bind tidak membuktikan email benar-benar dibaca.

<details><summary>Jawaban</summary>

B. Sync dicatat per folder, dan Microsoft meminta semua item di folder yang di-sync dalam konteks penyerang dianggap terkompromi, karena penyerang bisa membaca salinan lokal tanpa berinteraksi dengan server. A keliru karena hanya menghitung bind dan mengabaikan sync. C keliru karena Microsoft justru meminta data dianggap terkompromi bila akses tidak pasti, dan `MailItemsAccessed` mencatat akses walaupun tidak ada tanda email itu dibaca. Lihat bagian 1.5 dan 2.3.

</details>

**3. Pertanyaan jebakan.** "Kami tidak menemukan event `SearchQueryInitiated` di audit mailbox Fitri, jadi penyerang tidak mencari email berisi kata 'rekening'." Benarkah?

<details><summary>Jawaban</summary>

Tidak. `SearchQueryInitiated` bisa dicatat untuk pemilik mailbox, tetapi bukan bagian set aksi bawaan, sehingga tidak direkam kecuali diaktifkan sebelum insiden. Ketiadaan event itu adalah batas sumber, bukan bukti bahwa pencarian tidak terjadi, dan harus ditulis sebagai batas di laporan. Lihat bagian 1.2.

</details>

**4. Skenario keputusan.** Pukul 09:35 Rudi menemukan aturan "." di mailbox Fitri. Analyst L1 yang mendampinginya berkata, "Hapus saja sekarang biar Fitri bisa lihat emailnya lagi." Respons mana yang tepat?

- A. Hapus sekarang dengan `Remove-InboxRule`, karena aturan itu jelas berbahaya.
- B. Ekspor detail aturan sebagai bukti, lalu nonaktifkan aturan bersama tindakan containment lain di jam H; hapus saat eradication.
- C. Biarkan aturan aktif sampai investigasi selesai supaya penyerang tidak curiga.

<details><summary>Jawaban</summary>

B. Kondisi dan kata kunci aturan adalah bukti niat dan petunjuk target, jadi diekspor dulu. Menonaktifkan dengan `Disable-InboxRule` menghentikan aturan tetapi menyimpannya untuk investigasi, dan dijalankan bersama disable akun, revoke sessions, dan pencabutan consent supaya penyerang tidak berpindah ke jalan lain. A keliru karena bukti hilang dan penyerang yang masih punya akses diberi tanda. C keliru karena aturan itu sedang menyembunyikan balasan pelanggan dalam penipuan yang berjalan; menunda sampai investigasi selesai membiarkan kerugian bertambah. Lihat bagian 1.3, 1.6, dan 2.6.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Irawan Setiadi (Kepala Divisi Keuangan), dalam tiga kalimat, kenapa setiap permintaan perubahan rekening harus dikonfirmasi lewat telepon ke nomor yang sudah tercatat, walaupun emailnya datang dari alamat yang benar.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Email palsu ke PT Sentosa dikirim dari mailbox Fitri yang asli, di thread tagihan yang asli, jadi tidak ada yang terlihat aneh dari alamat atau isinya. Penyerang juga menyembunyikan balasan pelanggan dari Fitri, sehingga satu-satunya cara memotong penipuan ini adalah kanal kedua yang tidak bisa ia kendalikan, yaitu telepon ke nomor di kontrak. Telepon dari Bu Lina itulah yang menyelamatkan Rp 487,5 juta, sedangkan pelanggan yang tidak menelepon sudah terlanjur transfer."

Kesalahan yang sering muncul:
- Menyarankan memeriksa alamat pengirim, padahal di kompromi mailbox alamatnya memang asli.
- Menelepon nomor yang tertulis di email permintaan itu sendiri, bukan nomor yang sudah tercatat.
- Memakai istilah seperti "AiTM" atau "inbox rule" yang tidak dibutuhkan Keuangan.

</details>

**6. Pertanyaan jebakan.** "Saya menjalankan `Search-UnifiedAuditLog` untuk akun Fitri dan mendapat tepat 100 record. Itu berarti seluruh aktivitas Fitri di periode itu hanya 100 aksi." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Tanpa `SessionCommand`, cmdlet hanya mengembalikan sampai 100 record; angka bulat 100 adalah tanda hasil terpotong. Pakai `SessionId` dan `SessionCommand ReturnLargeSet` lalu ulangi sampai hasil habis. Pastikan juga rentang waktunya ditulis dalam UTC, dan ingat record bisa muncul sampai 24 jam setelah aktivitas. Lihat bagian 1.2 dan 2.2.

</details>

**7. Interview question (English).** "Walk me through how you would investigate a suspected business email compromise in Microsoft 365."

<details><summary>Sample answer</summary>

"I start by confirming what happened from the business side, like which payment request was sent and to whom, and I make sure finance contacts the bank immediately if money has moved. On the technical side, I check the mailbox for forwarding and inbox rules, including hidden ones, because hiding replies is the classic BEC move. Then I build a timeline from the unified audit log in UTC: rule creation, sends, deletions, and consent grants, and I pivot on the attacker's IPs and session. To answer what the attacker read, I use MailItemsAccessed: sync in the attacker's context means I treat the whole folder as compromised, bind records give me message IDs, and I check for throttling first. I also check sign-in logs and registered MFA methods, because a password reset alone doesn't remove sessions, OAuth apps, rules or MFA methods. Containment is done in one window: disable the account, revoke sessions, revoke the app consent, disable the rule after exporting it, and remove attacker MFA methods. Finally I give legal and the privacy officer a summary of what is proven and what the logging limits are, and I hunt across the tenant for the same rule patterns and app."

What makes this answer strong: it puts the money first, covers the main persistence mechanisms, uses MailItemsAccessed correctly including its limits, explains why password resets are not enough, executes containment as one coordinated step, and separates technical facts from the legal decision.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Microsoft Learn: Respond to a compromised email account in Microsoft 365 | https://learn.microsoft.com/en-us/defender-office-365/responding-to-a-compromised-email-account | primer (dokumentasi vendor) | ms.date 2026-07-03; diakses 2026-10-15 | Tinggi. Gejala, enam langkah pemulihan, reset dua kali untuk akun AD, app password, forwarding, `Get-InboxRule -IncludeHidden`, Restricted entities |
| S2 | Microsoft Learn: Use MailItemsAccessed to investigate compromised accounts | https://learn.microsoft.com/en-us/purview/audit-log-investigate-accounts | primer (dokumentasi vendor) | ms.date 2026-06-19; diakses 2026-10-15 | Tinggi. Protokol, sync vs bind, agregasi dua menit, deduplikasi, properti konteks, langkah investigasi, anggapan data terkompromi |
| S3 | Microsoft Learn: Manage mailbox auditing | https://learn.microsoft.com/en-us/purview/audit-mailboxes | primer (dokumentasi vendor) | ms.date 2026-06-19; diakses 2026-10-15 | Tinggi. Auditing default, aksi bawaan per jenis logon, `SearchQueryInitiated` dan `MailboxLogin` bukan bawaan, `DefaultAuditSet`, audit bypass |
| S4 | Microsoft Learn: Manage audit log retention policies | https://learn.microsoft.com/en-us/purview/audit-log-retention-policies | primer (dokumentasi vendor) | ms.date 2026-06-19; diakses 2026-10-15 | Tinggi. Standard 180 hari sejak 17 Oktober 2023, Premium satu tahun, sampai 10 tahun dengan add-on, retensi menurut lisensi pengguna |
| S5 | Microsoft Learn: Search-UnifiedAuditLog | https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/search-unifiedauditlog | primer (dokumentasi vendor) | diperbarui 2026-06-01; diakses 2026-10-15 | Tinggi. Batas 100, `ReturnLargeSet` 50.000, `ResultSize` 5.000, UTC, `HighCompleteness` preview, saran Management Activity API |
| S6 | Microsoft Learn: Audited activities | https://learn.microsoft.com/en-us/purview/audit-log-activities | primer (dokumentasi vendor) | ms.date 2026-10-01; diakses 2026-10-15 | Tinggi. Nama dan arti operasi mailbox (`New-InboxRule`, `Set-InboxRule`, `UpdateInboxRules`, `Send`, `SoftDelete`, `HardDelete`, `MailItemsAccessed`, `SearchQueryInitiated`) |
| S7 | Microsoft Learn: Detect and remediate Outlook rules and custom forms injection attacks | https://learn.microsoft.com/en-us/defender-office-365/detect-and-remediate-outlook-rules-forms-attack | primer (dokumentasi vendor) | ms.date 2026-07-03; diakses 2026-10-15 | Tinggi. Aturan tersinkron dari cloud, skrip arsip, indikator, `Disable-InboxRule`, `Remove-InboxRule` |
| S8 | Microsoft Learn: Detect and remediate illicit consent grants | https://learn.microsoft.com/en-us/defender-office-365/detect-and-remediate-illicit-consent-grants | primer (dokumentasi vendor) | ms.date 2026-07-03; diakses 2026-10-15 | Tinggi. Definisi, reset password tidak efektif, Consent to application, `IsAdminConsent`, `AllPrincipals`, jeda audit 30 menit sampai 24 jam, cara mencabut |
| S9 | Microsoft Learn: Get-MessageTraceV2 | https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-messagetracev2 | primer (dokumentasi vendor) | diperbarui 2026-02-27; diakses 2026-10-15 | Tinggi. 90 hari, 10 hari per query, maksimal 5.000, UTC, tanpa paging |
| S10 | Microsoft Security Blog: From cookie theft to BEC, attackers use AiTM phishing sites as entry point to further financial fraud | https://www.microsoft.com/en-us/security/blog/2022/07/12/from-cookie-theft-to-bec-attackers-use-aitm-phishing-sites-as-entry-point-to-further-financial-fraud/ | sekunder (laporan vendor) | 2022-07-12 (lebih dari 3 tahun); diakses 2026-10-15 | Tinggi untuk pola AiTM dan BEC: pencurian cookie setelah MFA, lima menit, aturan ke Archive, penghapusan Sent Items. Kampanye spesifik bisa berbeda dengan pola saat ini |
| S11 | FBI IC3: Business Email Compromise, The $55 Billion Scam (I-091124-PSA) | https://www.ic3.gov/PSA/2024/PSA240911 | primer | 2024-09-11; diakses 2026-10-15 | Tinggi. Definisi BEC, statistik Oktober 2013 sampai Desember 2023, saran verifikasi lewat kanal kedua, recall dana. Konteks Amerika Serikat |
| S12 | Pasal.id: UU 27/2022 Pasal 46 | https://pasal.id/peraturan/uu/uu-no-27-tahun-2022/pasal-46 | sekunder | diakses 2026-10-15 | Sedang. Bunyi pasal 3 x 24 jam dan isi minimal pemberitahuan; penjelasan pasal tidak tampil. Cocokkan dengan teks resmi di JDIH |
| S13 | Proofpoint: mailbox rules as an O365 post-exploitation tactic in cloud account takeover | https://www.proofpoint.com/us/blog/threat-insight/mailbox-rules-o365-post-exploitation-tactic-cloud-ato | sekunder (riset vendor) | 2026-04-13; diakses 2026-10-15 | Sedang. Statistik dari data pelanggan Proofpoint kuartal 4 2025; persentase nama aturan dan aksi |
| S14 | NVISO Labs: What did the attacker read? MailItemsAccessed tells you | https://blog.nviso.eu/2025/10/02/what-did-the-attacker-read-mailitemaccessed-tells-you/ | komunitas (blog praktisi DFIR) | 2025-10-02, diperbarui 2026-05-29; diakses 2026-10-15 | Sedang. Throttling lebih dari 1.000 event per 24 jam dan `IsThrottled`; belum dikonfirmasi halaman Microsoft terbaru |
| S15 | Office 365 for IT Pros: Microsoft finally delivers promised audit events to Purview Audit Standard tenants | https://office365itpros.com/2024/05/23/new-audit-events-may24/ | sekunder | 2024-05-23; diakses 2026-10-15 | Sedang. Perluasan `MailItemsAccessed` dan `Send` ke Audit (Standard), roadmap Juni 2024, mailbox dengan set audit khusus perlu diperbarui manual |

**Catatan sumber:** throttling `MailItemsAccessed` (ambang 1.000 per 24 jam dan `IsThrottled`) di bagian 1.5 hanya didukung sumber praktisi [S14] dan tidak muncul di halaman Microsoft yang diperiksa, sehingga ditandai belum terkonfirmasi. Waktu rilis `MailItemsAccessed` untuk Audit (Standard) berasal dari sumber sekunder [S15]. Field `AppId` di record `MailItemsAccessed`, struktur `Folders.FolderItems`, perbedaan nama `ClientIP` dan `ClientIPAddress` antar jenis record, serta nama field Splunk di bagian 2.5 ditulis dari bentuk record umum dan perlu dicek di record mentah tenant dan add-on-mu. Prosedur penahanan dana di bank Indonesia dan titik mulai 3 x 24 jam UU PDP tidak dibahas sumber yang diperiksa dan harus dicek bersama Legal dan bank. Urutan jam H, ciri aturan yang dipakai di query Splunk, dan isi ringkasan untuk DPO adalah susunan catatan ini dari sumber yang disebut. Semua isi PT JAB adalah contoh fiktif.
