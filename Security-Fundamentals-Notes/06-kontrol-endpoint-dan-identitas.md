---
day: 06
title: 'Kontrol endpoint dan identitas: antivirus, EDR, XDR, MDR, HIDS, FIM, DLP, allowlisting, IAM, MFA, SSO, RBAC, dan PAM'
researched_on: 2026-10-21
versions_checked: 'NIST SP 800-63-4, SP 800-63B-4 (final Juli 2025, menggantikan revisi 3); NIST SP 800-94 (Feb 2007); NIST SP 800-167 (Okt 2015); NIST CSRC Glossary (entri diakses 2026-10-21); CISA fact sheet Implementing Phishing-Resistant MFA dan Implementing Number Matching in MFA Applications (Okt 2022); Microsoft Learn: Defender for Endpoint, Defender XDR, Entra ID number matching, authentication strengths, Privileged Identity Management, Purview DLP, Application Control for Windows (halaman diperbarui 2025-2026); Wazuh documentation (current, 4.x); FIDO Alliance passkeys'
---

# Day 06: Kontrol endpoint dan identitas (antivirus, EDR, XDR, MDR, HIDS, FIM, DLP, allowlisting, IAM, MFA, SSO, RBAC, dan PAM)

Cakupan: pengaman yang bekerja di dalam perangkat (antivirus, EDR, XDR, MDR, HIDS, FIM, DLP, application allowlisting) dan pengaman yang mengatur siapa boleh masuk dan boleh apa (IAM, identitas dan akun, MFA beserta faktor dan jenisnya, SSO, RBAC, PAM), dengan cara membedakan istilah yang sering tertukar dan membaca alert yang dihasilkannya.

## Ide inti

Pengaman jaringan (firewall, IDS, IPS, yang dibahas di Day 03) menjaga jalan dan pintu gerbang. Tetapi hampir semua serangan modern berakhir di dua tempat yang tidak bisa dijaga dari jalan: di dalam perangkat, tempat program jahat dijalankan, dan di akun, tempat penyerang menyamar sebagai karyawan yang sah. Laptop yang dibawa pulang tidak lewat firewall kantor, lalu lintas web terenkripsi tidak terbaca isinya oleh perangkat jaringan biasa, dan penyerang yang login dengan password curian terlihat seperti pegawai biasa. Karena itu organisasi memasang dua keluarga pengaman lagi. Keluarga pertama hidup di endpoint (laptop, PC, server) dan mengawasi apa yang terjadi di dalamnya. Keluarga kedua mengatur identitas: membuktikan siapa yang masuk, membatasi apa yang boleh ia lakukan, dan memperketat pengawasan untuk akun yang paling berkuasa.

Dua keluarga ini saling membutuhkan. EDR yang melihat program jahat di laptop tidak berguna banyak bila penyerang cukup login ke email dari tempat lain dengan password curian. Sebaliknya, MFA yang kuat tidak menolong bila laptop yang sudah login dikuasai program jahat yang memakai sesi pemiliknya. Karena itu analyst SOC hampir selalu memeriksa keduanya untuk satu alert: apa yang terjadi di perangkat, dan akun mana yang terlibat.

Bayangkan sebuah gedung kantor. Di lobi ada resepsionis yang mencocokkan wajah tamu dengan KTP (authentication) lalu memberi kartu tamu yang hanya membuka lantai yang dituju (authorization). Di setiap lantai ada satpam yang berpatroli di dalam ruangan (EDR), bukan hanya berjaga di gerbang. Ada pemeriksa tas di pintu keluar yang memastikan dokumen rahasia tidak dibawa pulang (DLP), dan ada daftar tamu undangan yang membuat siapa pun yang tidak tercantum tidak boleh masuk ruang tertentu (allowlisting). Kunci ruang server tidak dipegang siapa pun secara permanen; kunci itu dipinjam dari lemari kunci dengan tanda tangan, dipakai sebentar, lalu dikembalikan (PAM). Batas analogi ini: satpam hanya berpatroli di ruangan yang dipasangi satpam, sehingga perangkat tanpa agen EDR adalah ruangan tanpa penjaga; dan di dunia digital "KTP" bisa dicuri dari jarak jauh, jadi kekuatan bukti identitas bergantung pada seberapa sulit bukti itu dipalsukan atau dipancing keluar.

```
                         KELUARGA ENDPOINT                            KELUARGA IDENTITAS
                 (apa yang terjadi di dalam perangkat)              (siapa masuk, boleh apa)

  antivirus  : kenali dan karantina file jahat              IAM   : kelola identitas, akun, hak sepanjang masa kerja
  EDR        : rekam perilaku, deteksi, respons            MFA   : buktikan identitas dengan 2 faktor atau lebih
  XDR        : gabungkan endpoint + email + identitas + ...  SSO   : satu login untuk banyak aplikasi
  MDR        : layanan orang luar yang menjalankan deteksi  RBAC  : hak diberikan lewat peran, bukan per orang
  HIDS / FIM : pantau log host / perubahan file penting     PAM   : kendalikan akun berhak tinggi (admin)
  DLP        : cegah data sensitif keluar
  allowlist  : hanya program yang disetujui boleh jalan

          laptop / server  <---- dipakai oleh ---->  akun milik seorang identitas
                  \                                        /
                   +------> alert ke SOC: periksa keduanya <+
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), sebuah ISP (penyedia layanan internet) fiktif dengan sekitar 1.200 karyawan. SOC (Security Operations Center, tim yang memantau dan menangani kejadian keamanan) PT JAB memakai Microsoft Defender for Endpoint Plan 2 sebagai EDR di semua workstation dan server Windows, Wazuh `jkt-wazuh01` untuk server Linux yang tidak dipasangi EDR, akun karyawan dari Active Directory `corp.jab.example` yang tersinkron ke Microsoft Entra ID (layanan identitas cloud Microsoft), dan Microsoft 365 untuk email. Kamu adalah analyst L1 (lini pertama yang memeriksa alert) yang baru bergabung Senin 2027-08-02. Senin 2027-08-09 pukul 08:45, minggu kedua orientasi, mentormu Sari Kusuma (analyst L2) memanggilmu ke mejanya. Antrean alert pagi itu berisi lima hal yang berbeda jenis, dan Sari sengaja memakainya sebagai bahan:

> "Pagi ini lengkap. Ada alert antivirus `SOC-2027-0836` di laptop `JKT-WS-1064` yang statusnya sudah quarantined, dan ada alert EDR `SOC-2027-0833` di `JKT-WS-1061` berisi rangkaian proses dari Excel ke PowerShell. Yang pertama aku tutup, yang kedua laptopnya langsung aku isolasi. Kenapa beda? Portal Defender menggabungkan alert EDR itu dengan email lampiran yang sama di enam kotak surat lain; itu yang disebut XDR. Minggu lalu Pak Dimas meneruskan tawaran MDR dari vendor; apa bedanya dengan XDR yang sudah kita punya? Lalu ada alert Wazuh `SOC-2027-0837`: file konfigurasi di `jkt-radius01` berubah jam dua pagi. Server itu tidak punya EDR, jadi alat apa yang melihatnya, dan apa yang tidak bisa ia lihat? Ada alert DLP `SOC-2027-0834`: file berisi data pelanggan diunggah ke situs kirim file pribadi. Bagaimana sistem tahu isinya data pelanggan, dan apakah DLP menangkap semua kebocoran? Helpdesk juga minta hak admin permanen untuk staf Marketing yang ingin memasang aplikasi edit video; kenapa aku tolak, dan apa hubungannya dengan PC loket yang hanya bisa menjalankan aplikasi tertentu? Reza dari NOC menelepon: dia menerima sembilan notifikasi MFA padahal tidak sedang login, semua dia tolak, lalu ada pesan WhatsApp yang mengaku helpdesk dan menanyakan angka di layar. Akunnya yang mana saja yang harus kita urus? Kenapa MFA aplikasi di HP-nya berbeda dengan kunci FIDO2 yang dipakai admin, dan kenapa `INC-2026-022` dulu bisa lolos MFA? Kenapa sekali login pagi kita bisa membuka Outlook, Teams, dan Splunk tanpa password lagi, dan apakah itu berbahaya? Siapa yang menentukan kamu boleh menjalankan scan tapi tidak boleh mengisolasi laptop? Terakhir, kalau bukan admin permanen, bagaimana seharusnya orang memakai hak admin?"

Pesan itu memuat sebelas pertanyaan:

1. Kenapa alert antivirus yang sudah quarantined cukup dicatat, sedangkan alert EDR membuat laptop langsung diisolasi?
2. Apa itu XDR, dan apa bedanya dengan MDR yang ditawarkan vendor?
3. Alat apa yang melihat perubahan file di server Linux tanpa EDR, dan apa batasnya?
4. Bagaimana DLP tahu sebuah file berisi data pelanggan, dan apakah DLP menangkap semua kebocoran?
5. Kenapa permintaan admin permanen ditolak, dan apa hubungannya dengan PC loket yang hanya bisa menjalankan aplikasi tertentu?
6. Akun Reza yang mana saja yang harus diurus, dan apa beda identitas dengan akun?
7. Kenapa sembilan notifikasi yang semuanya ditolak tetap tanda bahaya, dan apa beda jenis MFA (aplikasi di HP, SMS, kunci FIDO2)? Kenapa `INC-2026-022` lolos MFA?
8. Kenapa sekali login bisa membuka banyak aplikasi, dan apakah itu berbahaya?
9. Siapa yang menentukan analyst L1 boleh apa di alat SOC?
10. Bagaimana seharusnya orang memakai hak admin?
11. Bagaimana semua alert itu dibaca dalam praktik?

Pertanyaan 1 dijawab di bagian 1.1 dan 1.2, pertanyaan 2 di bagian 1.3, pertanyaan 3 di bagian 1.4, pertanyaan 4 di bagian 1.5, pertanyaan 5 di bagian 1.6 dan 1.11, pertanyaan 6 di bagian 1.7, pertanyaan 7 di bagian 1.8, pertanyaan 8 di bagian 1.9, pertanyaan 9 di bagian 1.10, pertanyaan 10 di bagian 1.11, dan pertanyaan 11 di bagian 2.

**Kapan relevan:** setiap kali alert datang dari laptop, server, email, atau sistem login; saat memutuskan apakah sebuah perangkat perlu diisolasi atau sebuah akun perlu direset; saat menjawab permintaan akses dari helpdesk atau atasan; dan saat interview ditanya beda antivirus dengan EDR, beda EDR dengan XDR, atau jenis MFA mana yang tahan phishing.
**Kapan bukan jawaban:** istilah Day ini tidak menjelaskan cara memasang atau mengonfigurasi produk tertentu, tidak menggantikan prosedur penanganan insiden, dan tidak berlaku untuk perangkat yang tidak dipasangi agen atau aplikasi yang tidak tersambung ke sistem identitas pusat. Untuk lalu lintas jaringan yang tidak menyentuh endpoint terkelola, jawabannya ada di kontrol jaringan (Day 03).

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day 01 (CIA triad, AAA, least privilege, separation of duties, zero trust, control) dan Day 02 (IP address, port, HTTPS) tidak diulang di sini; bila istilah itu penting, definisinya diulang satu kalimat di subbagian yang memakainya. Tabel ini memuat istilah baru Day ini; cari kolom ketiga bila sebuah istilah terasa abstrak.

| Istilah | Arti singkat | Padanan sehari-hari |
|---|---|---|
| Endpoint | Perangkat yang dipakai orang atau menjalankan layanan: laptop, PC, server, HP | Ruangan-ruangan di dalam gedung |
| Agen (agent) | Program kecil yang dipasang di endpoint untuk mengawasi dan melapor | Satpam yang ditempatkan di satu ruangan |
| Antivirus | Program yang mengenali dan menghentikan malware, terutama dengan mencocokkan ciri yang sudah dikenal | Petugas yang mencocokkan wajah tamu dengan daftar buronan |
| Signature | Ciri khas malware yang sudah dikenal (pola isi, hash) | Foto di daftar buronan |
| Quarantine | Memindahkan file mencurigakan ke tempat terkunci sehingga tidak bisa dijalankan | Barang sitaan yang disimpan di lemari terkunci |
| EDR | Endpoint detection and response: merekam perilaku di endpoint, mendeteksi pola serangan, dan menyediakan tombol respons | Satpam yang berpatroli di dalam ruangan dan mencatat semua gerak-gerik |
| Telemetri | Catatan aktivitas yang dikirim agen ke pusat (proses, file, koneksi, login) | Rekaman patroli satpam |
| Isolasi perangkat | Memutus perangkat dari jaringan kecuali ke konsol keamanan | Mengunci satu ruangan, hanya satpam yang boleh masuk |
| XDR | Extended detection and response: deteksi dan respons yang menggabungkan endpoint, email, identitas, cloud | Ruang kendali yang menyatukan laporan satpam, resepsionis, dan petugas surat |
| MDR | Managed detection and response: layanan pihak luar yang menjalankan pemantauan dan respons | Perusahaan jasa keamanan yang menempatkan petugasnya |
| HIDS | Host-based intrusion detection system: deteksi intrusi dari dalam satu host (log, file, proses) | Alarm dan CCTV yang dipasang di dalam satu ruangan |
| FIM | File integrity monitoring: mendeteksi perubahan pada file penting | Segel di lemari arsip yang ketahuan bila dibuka |
| DLP | Data loss prevention: mengenali data sensitif dan mencegahnya keluar tanpa izin | Pemeriksa tas di pintu keluar |
| Application allowlisting | Hanya program yang ada di daftar persetujuan yang boleh berjalan | Daftar tamu undangan di pintu acara |
| IAM | Identity and access management: pengelolaan identitas dan hak aksesnya | Bagian personalia dan kartu akses gedung |
| Identitas | Siapa seseorang (atau sesuatu) sebenarnya dalam konteks organisasi | Orangnya, dengan KTP dan nomor induk karyawan |
| Akun | Rekaman di sebuah sistem yang dipakai identitas untuk login | Kartu akses untuk satu gedung atau satu lemari |
| Faktor autentikasi | Jenis bukti: sesuatu yang kamu tahu, punya, atau melekat padamu | PIN, kunci fisik, sidik jari |
| MFA | Multi-factor authentication: login dengan dua faktor berbeda atau lebih | PIN ATM ditambah kartu ATM |
| Authenticator | Benda atau aplikasi yang membuktikan faktor (aplikasi HP, kunci FIDO2) | Kunci atau token yang dipegang pemiliknya |
| Push notification | Permintaan "setujui login?" yang dikirim ke aplikasi di HP | Telepon dari bank yang bertanya "betul Bapak yang bertransaksi?" |
| Number matching | Pengguna harus mengetik angka yang tampil di layar login ke aplikasi HP | Kode yang hanya diketahui orang yang berdiri di depan mesin |
| MFA fatigue | Membanjiri pengguna dengan notifikasi MFA sampai ia menyetujui satu | Bel pintu ditekan terus sampai penghuni membuka hanya supaya berhenti |
| Phishing-resistant MFA | MFA yang rahasianya tidak bisa dipancing keluar oleh situs palsu | Kunci yang hanya pas di lubang kunci rumah aslinya |
| FIDO2 dan passkey | Standar login berbasis kunci kriptografi yang terikat ke alamat situs asli | Kunci yang otomatis menolak berputar di pintu palsu |
| AiTM | Adversary-in-the-middle: situs palsu yang meneruskan login ke situs asli dan mencuri sesinya | Penipu yang berdiri di antara kamu dan teller, meneruskan semua ucapanmu |
| SSO | Single sign-on: satu login untuk membuka banyak aplikasi | Satu kartu akses untuk semua pintu yang menjadi hakmu |
| IdP | Identity provider: sistem pusat yang melakukan login dan menerbitkan bukti ke aplikasi | Resepsionis pusat yang menerbitkan kartu tamu |
| RBAC | Role-based access control: hak diberikan ke peran, lalu orang dimasukkan ke peran | Kartu akses per jabatan, bukan per nama |
| PAM | Privileged access management: pengendalian akun dan akses berhak tinggi | Lemari kunci ruang server dengan buku pinjam |
| Just-in-time (JIT) | Hak tinggi diberikan hanya saat dibutuhkan dan berakhir otomatis | Kunci yang dipinjam satu jam lalu wajib dikembalikan |

### 1.1 Endpoint dan antivirus

Pertanyaan pertama Sari dimulai dari alert yang paling sederhana: `SOC-2027-0836`, antivirus di laptop `JKT-WS-1064` mendeteksi file berbahaya di folder Downloads dan memindahkannya ke karantina. Untuk memahami kenapa alert ini boleh ditutup, kamu perlu tahu dulu apa yang dikerjakan antivirus, dan apa yang tidak.

**Apa itu:** endpoint adalah perangkat di ujung jaringan yang dipakai orang atau menjalankan layanan: laptop, PC, server, HP, juga perangkat seperti printer dan kamera jaringan. Antivirus adalah program yang memantau komputer untuk mengenali jenis-jenis malware (program jahat) yang umum, lalu mencegah atau membatasi kejadian malware [S1]. Cara utama antivirus tradisional mengenali malware adalah signature, yaitu ciri khas yang sudah dikenal dari malware tertentu, misalnya pola isi file atau hash (sidik jari file yang dibahas di Day 05) [S2]. Bila ketemu, antivirus biasanya membersihkan file itu atau memindahkannya ke quarantine, tempat terkunci di mana file tidak bisa dijalankan [S2].

**Analogi:** petugas di pintu yang mencocokkan wajah setiap tamu dengan daftar buronan. Tamu yang wajahnya ada di daftar langsung ditahan. Batasnya: petugas ini hanya mengenali orang yang fotonya sudah ada di daftar. Buronan baru yang belum difoto, atau buronan yang memakai wig, bisa lolos. Antivirus modern sudah menambah cara lain (lihat Cara kerja), tetapi pada dasarnya ia menilai file dan program satu per satu, bukan menyusun cerita lengkap sebuah serangan.

**Cara kerja:** antivirus bekerja di beberapa momen.

1. Saat file muncul di disk (diunduh, disalin dari USB, diekstrak dari ZIP), antivirus memeriksanya. Pemeriksaan otomatis ini disebut real-time protection atau on-access scanning.
2. Saat terjadwal, antivirus memindai disk secara berkala (scheduled scan).
3. Bila file cocok dengan signature, antivirus menjalankan tindakan yang dikonfigurasi: blokir, bersihkan, atau karantina, lalu menulis alert.
4. Signature diperbarui terus dari vendor, karena malware baru muncul setiap hari.

Antivirus generasi baru, yang sering disebut next-generation antivirus, menambah machine learning lokal dan di cloud, analisis perilaku, dan heuristik (aturan perkiraan seperti "program tanpa tanda tangan yang menulis ke folder sistem patut dicurigai"). Microsoft Defender Antivirus, misalnya, memakai model machine learning lokal dan cloud, analisis perilaku, dan heuristik, serta perlindungan cloud yang hampir seketika untuk ancaman baru [S5]. Paket yang menggabungkan antivirus dengan pengaman endpoint lain (firewall host, kontrol perangkat USB) sering disebut EPP, endpoint protection platform.

NIST mencatat batas yang tetap berlaku: antivirus hanya mendeteksi malware, bukan jenis serangan lain, dan untuk ancaman yang benar-benar baru, antivirus sering baru bisa mengenalinya setelah vendor merilis signature [S2]. Penyerang yang tidak memakai file jahat sama sekali, misalnya memakai PowerShell bawaan Windows atau login dengan password curian, tidak meninggalkan file yang bisa dicocokkan.

**Contoh di PT JAB:** alert `SOC-2027-0836` di `JKT-WS-1064` milik Lestari Wulandari (staf Administrasi Umum). Pukul 07:52, ia mengunduh `invoice_0821.zip` dari email; saat ZIP diekstrak, Defender Antivirus mengenali file `invoice_0821.js` di dalamnya sebagai downloader (program yang tugasnya mengunduh malware lain) dan memindahkannya ke karantina. Status alert: Remediated. Sari tetap memeriksa dua hal sebelum menutupnya: apakah file itu sempat dijalankan (telemetri EDR menunjukkan tidak ada proses yang menjalankannya), dan apakah email yang sama diterima orang lain. Bagian 2.1 membedah alert ini berdampingan dengan alert EDR.

**Beda dengan EDR:** antivirus menjawab "apakah file ini jahat?" dan bertindak terhadap file itu. EDR menjawab "apa yang sedang terjadi di perangkat ini, dan apakah rangkaiannya mirip serangan?" dan memberi analyst rekaman serta tombol respons. Perbedaan lengkapnya ada di bagian 1.2 dan 3.1.

**Salah paham umum:**
- "Alert antivirus yang sudah quarantined berarti selesai." Biasanya ya untuk file itu, tetapi tetap cek apakah file sempat berjalan sebelum dikarantina, dari mana file datang, dan apakah perangkat lain menerima file yang sama. Satu file yang tertangkap bisa jadi satu dari banyak percobaan.

### 1.2 EDR (endpoint detection and response)

Alert kedua Sari, `SOC-2027-0833` di `JKT-WS-1061`, tidak menyebut file jahat sama sekali. Isinya rangkaian proses: Outlook membuka Excel, Excel menjalankan PowerShell dengan perintah tersembunyi, PowerShell mengunduh file dari `192.0.2.131`, lalu membuat tugas terjadwal. Antivirus tidak berteriak, karena file yang diunduh belum dikenal. Yang menangkapnya adalah EDR.

**Apa itu:** EDR (endpoint detection and response) adalah teknologi yang terus merekam aktivitas di endpoint, mendeteksi aktivitas yang mencurigakan dari pola perilakunya, dan memberi tim keamanan alat untuk menyelidiki dan merespons [S6]. Di Microsoft Defender for Endpoint, kemampuan EDR menghasilkan deteksi yang hampir real-time dan bisa ditindaklanjuti, dan alert yang memakai teknik serupa atau berasal dari penyerang yang sama digabung menjadi satu incident [S4]. Defender for Endpoint mengumpulkan telemetri perilaku dengan pola pikir "assume breach" (anggap pelaku mungkin sudah di dalam): informasi proses, aktivitas jaringan, login pengguna, perubahan registry dan file system, dan lainnya; data ini disimpan enam bulan sehingga analyst bisa melihat kembali sampai awal serangan [S4].

**Analogi:** satpam yang berpatroli di dalam ruangan, bukan hanya berjaga di pintu. Ia mencatat siapa masuk ruangan, lemari mana yang dibuka, dan barang apa yang dipindahkan. Ia bisa curiga walaupun tidak ada wajah buronan, misalnya ketika tukang servis AC tiba-tiba membuka brankas. Saat perlu, ia bisa mengunci ruangan itu. Batasnya: satpam hanya ada di ruangan yang dipasangi satpam. Perangkat tanpa agen EDR adalah ruangan tanpa penjaga; inilah pelajaran `INC-2026-017`, ransomware Oktober 2026 yang masuk lewat server aplikasi lama `jkt-dmz-app01` yang tidak punya EDR.

**Cara kerja:**

```
  [laptop JKT-WS-1061]                                    [konsol Defender, dipakai SOC]
   agen EDR (sensor)
     | rekam: proses lahir, perintah, file ditulis,
     |        koneksi jaringan, login, registry
     +---- telemetri terus-menerus ------------------> analitik (aturan + machine learning + intel)
                                                          |
                                                          | pola cocok: "Office menjalankan PowerShell
                                                          |  tersembunyi lalu mengunduh file"
                                                          v
                                                       ALERT + process tree (pohon proses)
                                                          |
     <---- tombol respons (dijalankan analyst) -----------+
           isolasi perangkat, hentikan dan karantina file,
           jalankan scan, kumpulkan paket investigasi
```

Tiga kemampuan membedakan EDR dari antivirus:

1. Rekaman (telemetri). EDR menyimpan apa yang terjadi, bukan hanya yang dianggap jahat. Analyst bisa bertanya "proses apa yang dijalankan PowerShell ini lima menit kemudian?" walaupun saat itu tidak ada alert.
2. Deteksi perilaku. EDR menilai rangkaian kejadian. Excel yang menjalankan PowerShell bukan pelanggaran hukum, tetapi Excel yang dibuka dari lampiran email lalu menjalankan PowerShell tersembunyi yang mengunduh program dari internet adalah pola serangan yang dikenal.
3. Respons. Analyst bisa bertindak dari konsol. Di Defender for Endpoint, bahkan Plan 1 sudah menyediakan tindakan manual seperti menjalankan scan antivirus, mengisolasi perangkat, menghentikan dan mengarantina file, dan menambah indikator untuk memblokir file [S4]; Plan 2 menambah kemampuan investigasi dan respons yang lebih lengkap [S3].

Microsoft sendiri mengingatkan bahwa sensor EDR bukan alat audit yang mencatat setiap operasi; ada pembatasan untuk kejadian identik yang berulang [S4]. Jadi EDR adalah rekaman yang sangat kaya, tetapi bukan rekaman sempurna.

**Contoh di PT JAB:** begitu membaca alert `SOC-2027-0833`, Sari mengisolasi `JKT-WS-1061` dari konsol Defender. Laptop milik Fajar Nugroho (staf Pengadaan) itu tetap menyala dan tetap bisa diperiksa dari konsol, tetapi tidak bisa lagi berbicara ke server lain atau ke `192.0.2.131`. Alasannya: rangkaian prosesnya menunjukkan kode penyerang sudah berjalan dan sudah menanam cara untuk berjalan lagi (tugas terjadwal), sesuatu yang tidak bisa dibereskan hanya dengan mengarantina satu file. Sari membuka insiden `INC-2027-085`. Bagian 2.1 memperlihatkan pohon prosesnya.

**Beda dengan antivirus:** antivirus fokus pada file dan sebagian besar bertindak otomatis; EDR fokus pada perilaku dan cerita lengkap, dan sebagian besar nilainya ada di tangan analyst yang membaca dan merespons. Di produk modern keduanya sering satu paket (Defender Antivirus dan Defender for Endpoint memakai agen yang sama), tetapi fungsinya tetap berbeda.

**Beda dengan HIPS:** HIPS (host-based intrusion prevention system) adalah IDS/IPS yang bekerja di dalam satu host dan bisa memblokir, dibahas sebagai jenis IDS di Day 03. EDR seperti Defender for Endpoint atau CrowdStrike Falcon lebih tepat disebut EDR, bukan HIPS dalam arti klasik, karena kekuatannya ada pada rekaman perilaku, investigasi, dan respons dari konsol, bukan hanya aturan blokir di satu host.

**Salah paham umum:**
- "Sudah ada EDR, jadi antivirus tidak perlu." Keduanya saling melengkapi; antivirus menghentikan ribuan malware yang sudah dikenal secara otomatis, sehingga EDR dan analyst bisa fokus pada yang tidak dikenal.
- "EDR melindungi semua perangkat perusahaan." EDR hanya melihat perangkat yang dipasangi agen dan agennya sehat. Daftar perangkat tanpa agen adalah daftar ruangan tanpa satpam.

### 1.3 XDR dan MDR

Setelah mengisolasi laptop, Sari membuka incident di portal Defender. Alert EDR `SOC-2027-0833` ternyata sudah digabung dengan alert lain: email berlampiran `PO_Agustus.xlsm` yang sama diterima enam kotak surat lain. Itu satu pertanyaan. Pertanyaan berikutnya datang dari email Dimas Prasetyo (SOC lead) minggu lalu: vendor menawarkan layanan MDR. Dua istilah ini mirip bunyinya tetapi menjawab hal yang sama sekali berbeda.

**Apa itu:**
- **XDR** (extended detection and response) adalah platform deteksi dan respons yang mengumpulkan dan menghubungkan data dari beberapa komponen keamanan sekaligus. Gartner mendefinisikannya sebagai platform deteksi dan respons insiden yang terpadu, yang otomatis mengumpulkan dan mengorelasikan data dari banyak komponen keamanan [S9]. XDR memakai kemampuan EDR, lalu memperluasnya ke email, identitas, jaringan, dan cloud [S9]. Microsoft Defender XDR, misalnya, mengoordinasikan deteksi, pencegahan, investigasi, dan respons lintas endpoint, identitas, email, dan aplikasi, dan menggabungkan alert dari produk-produk itu menjadi satu incident [S7].
- **MDR** (managed detection and response) adalah layanan, bukan produk: penyedia pihak luar yang menggabungkan teknologi dengan analyst manusia untuk memantau, berburu ancaman, dan merespons atas nama pelanggan, sering 24 jam [S8]. Layanan MDR biasanya mencakup pemantauan dan respons sepanjang waktu, threat hunting yang dipimpin manusia, penahanan (containment) agar serangan tidak menyebar, dan laporan berkala [S8].

**Analogi:** XDR adalah ruang kendali yang menyatukan laporan satpam lantai (endpoint), resepsionis (identitas), dan petugas surat (email) di satu layar, sehingga satu kejadian terlihat sebagai satu cerita: surat mencurigakan masuk, tamu yang menerimanya membuka sesuatu, lalu kartu aksesnya dipakai di lantai lain. MDR adalah perusahaan jasa keamanan yang menempatkan petugasnya untuk duduk di ruang kendali itu dan bertindak. Batasnya: XDR hanya menyatukan sumber yang tersambung dan berlisensi, dan MDR hanya sebaik akses dan wewenang yang diberikan pelanggan; petugas MDR tidak tahu bahwa server tertentu sedang dalam pemeliharaan kecuali diberi tahu.

**Cara kerja:**

```
  XDR (platform, produk)                               MDR (layanan, orang)

  endpoint (EDR) ----+                                 analyst penyedia MDR
  email          ----+--> korelasi --> 1 incident        |  memantau 24 jam
  identitas      ----+    otomatis     + respons         |  memakai EDR/XDR/SIEM
  aplikasi cloud ----+                 lintas produk     |  berburu ancaman
                                                         v
                                              eskalasi / tindakan atas nama pelanggan
```

Salah satu contoh respons lintas produk dari dokumentasi Microsoft: bila sebuah file berbahaya terdeteksi di endpoint, Defender XDR bisa memerintahkan Defender for Office 365 memindai dan menghapus file itu dari semua email [S7]. Microsoft juga mencatat bahwa korelasi hanya terjadi antar produk yang memang dilisensikan dan diaktifkan organisasi [S7].

Perbedaan MDR dengan MSSP (managed security service provider, penyedia layanan keamanan terkelola versi lama) juga sering ditanyakan: Microsoft menggambarkan MSSP umumnya memantau dan mengirim alert ke tim internal tetapi tidak aktif merespons, sedangkan MDR ikut merespons [S8]. Dalam praktik, batas keduanya ditentukan kontrak, jadi baca dulu apa yang boleh dan tidak boleh dilakukan penyedia.

**Contoh di PT JAB:** PT JAB punya EDR (Defender for Endpoint Plan 2) dan Defender for Office 365 Plan 2 untuk email. Keduanya tampil di portal Defender yang sama, sehingga alert EDR dari `JKT-WS-1061` otomatis tergabung dengan alert email lampiran `PO_Agustus.xlsm`. Dari incident itu Sari melihat enam penerima lain dan meminta lampiran yang sama dihapus dari kotak surat mereka. Itu XDR yang bekerja. Tawaran MDR yang diteruskan Dimas adalah hal lain: vendor menawarkan analyst-nya untuk menangani alert malam hari dan akhir pekan. PT JAB punya SOC internal, jadi pertanyaannya bukan "XDR atau MDR", melainkan "apakah perlu tambahan orang di jam tertentu, dan wewenang apa yang mau diberikan ke orang luar". Keputusan itu ada di Dimas dan manajemen; tugas L1 cukup memahami bedanya.

**Beda XDR dengan SIEM:** SIEM (sistem yang mengumpulkan log dari banyak sumber, mencarinya, dan memunculkan alert; dibahas di Day 10) mengumpulkan data apa saja yang dikirim kepadanya, termasuk dari firewall, aplikasi buatan sendiri, dan produk vendor lain. XDR biasanya berangkat dari keluarga produk keamanan yang sudah saling kenal, dengan korelasi dan respons yang siap pakai. PT JAB memakai keduanya: Splunk sebagai SIEM untuk semua log, portal Defender sebagai XDR untuk endpoint, email, dan identitas Microsoft.

**Salah paham umum:**
- "XDR adalah EDR versi baru, jadi cukup ganti nama." XDR baru berarti bila sumber selain endpoint benar-benar tersambung. EDR saja yang diberi label XDR tetap hanya melihat endpoint.
- "Pakai MDR berarti SOC internal tidak perlu." MDR mengambil sebagian pekerjaan, tetapi keputusan bisnis, konteks internal, dan tanggung jawab tetap di organisasi.

### 1.4 HIDS dan FIM

Alert `SOC-2027-0837` datang dari tempat lain: Wazuh `jkt-wazuh01` melaporkan file `/etc/raddb/clients.conf` di server RADIUS `jkt-radius01` berubah pukul 02:14. Server Linux itu tidak dipasangi EDR, karena tidak semua server Linux PT JAB tercakup EDR. Pertanyaan ketiga Sari: alat apa yang melihat perubahan itu, dan apa yang tidak bisa ia lihat?

**Apa itu:**
- **HIDS** (host-based intrusion detection system) adalah IDS yang memantau ciri dan kejadian di dalam satu host (komputer atau server) untuk mencari aktivitas mencurigakan. NIST menyebut contoh yang dipantau: lalu lintas jaringan host itu, log sistem, proses yang berjalan, akses dan perubahan file, serta perubahan konfigurasi sistem dan aplikasi [S2]. HIDS sebagai salah satu jenis IDS, bersama NIDS, NIPS, dan HIPS, dibahas di Day 03; di sini fokusnya sisi endpoint. Contoh HIDS yang tepat adalah OSSEC, yang menyebut dirinya HIDS gratis dan open source dengan analisis log, FIM, dan active response [S11], dan Wazuh, yang dikembangkan dari garis yang sama dan memakai agen di host [S10].
- **FIM** (file integrity monitoring) adalah pemantauan perubahan file penting. NIST menjelaskan teknik dasarnya: secara berkala menghitung checksum kriptografis (misalnya hash) untuk file penting, membandingkannya dengan nilai acuan, dan menandai perbedaan; pemeriksaan atribut seperti pemilik dan permission berjalan dengan cara yang sama [S2]. FIM bisa menjadi fitur di dalam HIDS (Wazuh, OSSEC) atau produk tersendiri; Tripwire Enterprise adalah contoh produk yang dikenal sebagai alat FIM dan manajemen konfigurasi [S12].

**Analogi:** HIDS adalah alarm dan CCTV yang dipasang di dalam satu ruangan, membaca buku catatan ruangan itu dan mengawasi lemari-lemarinya. FIM adalah segel di lemari arsip: bila segel rusak, kamu tahu lemari pernah dibuka. Batasnya: segel memberi tahu bahwa lemari dibuka dan isi apa yang berubah, tetapi tidak memberi tahu siapa yang membuka dan untuk apa. Segel juga baru diperiksa setelah kejadian, sehingga FIM pada dasarnya alat deteksi setelah perubahan terjadi [S2].

**Cara kerja FIM:**

```
  1. BASELINE   agen menghitung hash + atribut setiap file yang dipantau
                /etc/raddb/clients.conf  sha256=AAA...  size=3412  owner=root
  2. PANTAU     terjadwal (misalnya tiap 12 jam) atau real-time saat file disentuh
  3. BANDINGKAN hash/atribut sekarang vs baseline
                sha256=BBB...  size=3561   -> berbeda
  4. ALERT      "Integrity checksum changed" + detail (ukuran, waktu, isi yang berubah bila diaktifkan)
  5. BASELINE BARU disimpan; perubahan berikutnya dibandingkan dengan yang ini
```

Wazuh menjalankan langkah ini dengan baseline checksum dan atribut, pemindaian terjadwal maupun real-time, dan alert saat file dibuat, diubah, atau dihapus [S10]. Wazuh juga punya pengaturan lanjutan "who-data" yang bisa menambah informasi siapa pelaku perubahan bila diaktifkan [S10].

Kenapa FIM penting untuk security: banyak serangan meninggalkan jejak berupa perubahan file yang seharusnya jarang berubah, misalnya program sistem yang diganti versi bertrojan, file daftar kunci SSH yang ditambah kunci penyerang, atau konfigurasi layanan yang diubah. NIST menyebut contoh yang sama: program sistem yang diganti trojan atau rootkit [S2].

**Contoh di PT JAB:** `clients.conf` di `jkt-radius01` berisi daftar perangkat jaringan yang boleh bertanya ke server RADIUS beserta rahasia bersamanya. Perubahan di file itu bisa berarti penambahan perangkat baru yang sah, atau penyerang yang mendaftarkan perangkatnya sendiri. Alert FIM hanya bisa memberi tahu apa yang berubah dan kapan. Untuk menjawab siapa dan kenapa, analyst mencocokkan dengan tiket perubahan dan bertanya ke pemilik server. Bagian 2.4 menunjukkan alert dan cara menyelesaikannya.

**Beda HIDS dengan EDR:** keduanya hidup di host. HIDS klasik banyak bertumpu pada analisis log dan aturan, FIM, dan active response sederhana (misalnya memblokir IP setelah banyak login gagal). EDR merekam perilaku proses jauh lebih rinci, punya analitik perilaku, dan tombol respons dari konsol. Di PT JAB, Wazuh dipakai untuk server Linux yang tidak bisa atau belum dipasangi EDR; ia adalah pengganti yang lebih ringan, bukan kembaran EDR.

**Beda FIM dengan backup:** FIM memberi tahu bahwa file berubah; backup menyimpan salinan untuk memulihkan. FIM tidak bisa mengembalikan isi file lama kecuali fitur pelaporan perubahan diaktifkan dan isinya ikut dicatat.

**Salah paham umum:**
- "Semua alert FIM adalah serangan." Kebanyakan perubahan file adalah pekerjaan admin dan pembaruan sistem. FIM yang memantau terlalu banyak file (termasuk log dan file sementara) akan menenggelamkan analyst dalam alert. Pilih file yang memang jarang berubah dan penting.

### 1.5 DLP (data loss prevention)

Alert `SOC-2027-0834` pukul 08:31: dari laptop `JKT-WS-1066`, Andi Saputra (staf Customer Care) mengunggah file `pelanggan_jakbar_juli.xlsx` ke situs kirim file pribadi `kirimfile.example`. Unggahan itu diblokir. Pertanyaan keempat Sari: bagaimana sistem tahu isinya data pelanggan, dan apakah DLP selalu menangkapnya?

**Apa itu:** DLP (data loss prevention) adalah kemampuan sistem untuk mengenali, memantau, dan melindungi data saat dipakai (data in use, misalnya disalin di endpoint), saat bergerak (data in motion, misalnya dikirim lewat jaringan), dan saat tersimpan (data at rest), dengan cara memeriksa isi dan konteks transaksi di bawah satu manajemen pusat [S13]. Tujuannya mendeteksi dan mencegah pemakaian atau pengiriman data sensitif tanpa izin [S13].

**Analogi:** pemeriksa tas di pintu keluar gedung yang membuka map dan mengecek apakah ada dokumen berstempel "RAHASIA". Batasnya: pemeriksa hanya memeriksa pintu yang ia jaga, hanya mengenali dokumen yang cirinya sudah diajarkan, dan tidak bisa membaca dokumen yang dimasukkan ke amplop tersegel yang tidak boleh ia buka. Orang yang memotret dokumen dengan HP pribadi tidak lewat pemeriksa tas sama sekali.

**Cara kerja:**

1. Tentukan data yang dilindungi. Organisasi mendefinisikan jenis data sensitif: nomor KTP (NIK), nomor kartu kredit, data kesehatan, dokumen berlabel "Rahasia".
2. Kenali isinya. DLP modern tidak sekadar mencari kata. Microsoft Purview DLP, misalnya, memakai kata kunci, regular expression (pola teks seperti "16 digit angka"), validasi fungsi (misalnya checksum nomor kartu kredit), kecocokan data pendukung di dekat data utama (kata "NIK" di dekat 16 digit), dan machine learning [S14].
3. Pilih tempat pemeriksaan. DLP bisa berjalan di endpoint (agen yang melihat file disalin ke USB atau diunggah browser), di jaringan (proxy atau gateway yang memeriksa unggahan), di email, dan di layanan cloud.
4. Tentukan tindakan. Pilihan umumnya: hanya mencatat (audit), menampilkan peringatan ke pengguna (policy tip), memblokir tetapi mengizinkan pengguna melanjutkan dengan alasan tertulis (override), atau memblokir penuh [S14].
5. Uji dulu. Microsoft menyarankan kebijakan DLP dijalankan dulu dalam simulation mode untuk melihat dampaknya sebelum diaktifkan dengan tindakan blokir [S14], karena DLP yang belum di-tuning bisa memblokir pekerjaan sah.

**Contoh di PT JAB:** forward proxy kantor `jkt-proxy01` membuka enkripsi HTTPS untuk domain yang baru atau belum terkategori, lalu memeriksa isi unggahan dengan aturan DLP. Situs `kirimfile.example` (`192.0.2.135`) belum terkategori, sehingga unggahan Andi dibuka dan diperiksa. File itu berisi 1.240 baris dengan pola NIK dan nomor HP pelanggan; aturan "minimal 10 NIK dalam satu unggahan ke situs non-perusahaan" terpicu, unggahan diblokir, dan alert dikirim ke SOC. Andi menjelaskan ia ingin melanjutkan pekerjaan dari rumah. Niatnya bukan mencuri, tetapi tindakannya tetap melanggar kebijakan dan berisiko; kasus ini diteruskan ke atasannya dan ke Agus Setiawan (DPO, petugas pelindungan data pribadi). Bagian 2.2 membaca alertnya.

**Beda dengan enkripsi:** enkripsi membuat data tidak terbaca oleh yang tidak punya kunci; DLP mencegah data keluar ke tempat yang salah. Keduanya saling melengkapi: file yang lolos DLP masih aman bila terenkripsi, dan file terenkripsi yang dibawa keluar oleh pemegang kuncinya tetap bocor.

**Salah paham umum:**
- "DLP menghentikan semua kebocoran." DLP hanya melihat jalur yang ia jaga. Bila Andi memakai situs berbagi file terkenal yang tidak dibuka enkripsinya oleh proxy, atau mengirim lewat HP pribadi, DLP jaringan tidak melihat isinya. Karena itu DLP dipasang di beberapa titik dan didukung kebijakan serta pelatihan.

### 1.6 Application allowlisting

Pertanyaan kelima Sari menyangkut permintaan helpdesk: Dewi Anggraini dari Marketing ingin hak admin permanen di laptopnya supaya bisa memasang aplikasi edit video sendiri. Sari menolak dan menyebut PC loket di kantor layanan pelanggan sebagai contoh kebalikannya: PC itu hanya bisa menjalankan aplikasi kasir, browser kantor, dan beberapa program lain yang disetujui.

**Apa itu:** application allowlisting adalah cara mengendalikan program yang boleh berjalan di sebuah host dengan memakai daftar aplikasi dan komponen aplikasi yang diizinkan [S15]. NIST menyebut tujuannya menghentikan eksekusi malware, software tanpa lisensi, dan software lain yang tidak diizinkan [S15]. Istilah lama yang masih dipakai di dokumen NIST tahun 2015 adalah application whitelisting; istilah yang kini umum dipakai adalah allowlist, dengan lawannya blocklist (daftar yang diblokir). Microsoft menyebut teknologi sejenis di Windows sebagai application control, dengan dua pilihan: App Control for Business dan AppLocker [S16].

**Analogi:** daftar tamu undangan di pintu acara. Penjaga tidak perlu mengenali wajah penjahat; siapa pun yang namanya tidak ada di daftar tidak boleh masuk. Bandingkan dengan antivirus, yang seperti daftar buronan: semua orang boleh masuk kecuali yang wajahnya ada di daftar. Batasnya: daftar tamu harus dirawat. Tamu sah yang lupa didaftarkan akan ditolak, dan tamu yang menyamar memakai nama orang yang diundang bisa lolos bila penjaga hanya mengecek nama tanpa mengecek identitas.

**Cara kerja:** daftar dibuat dari atribut file. NIST membahas atribut yang bisa dipakai dan kekuatannya [S15]:

| Atribut | Contoh aturan | Kekuatan dan kelemahan |
|---|---|---|
| File path (lokasi folder) | Semua program di `C:\Program Files\Kasir\` boleh jalan | Paling longgar; siapa pun yang bisa menulis ke folder itu bisa menitipkan program |
| Nama file | `kasir.exe` boleh jalan | Mudah dipalsukan dengan mengganti nama |
| Ukuran file | Hanya dipakai bersama atribut lain | Sangat lemah sendirian |
| Digital signature atau publisher | Semua program yang ditandatangani vendor kasir boleh jalan | Kuat dan tidak perlu diubah setiap update; tetapi mempercayai semua program dari vendor itu |
| Cryptographic hash | Hanya file dengan hash tertentu boleh jalan | Paling tepat; tetapi harus diperbarui setiap kali program di-update |

Tabel ini dipakai untuk memilih atribut; NIST menyarankan atribut sederhana seperti path, nama, dan ukuran tidak dipakai sendirian, dan kombinasi digital signature atau publisher dengan hash umumnya memberi hasil paling akurat [S15]. Digital signature dan hash dibahas di Day 05.

Penerapan biasanya bertahap. Allowlisting dijalankan dulu dalam audit mode, yang membiarkan program di luar daftar tetap berjalan tetapi mencatatnya; setelah daftar lengkap, baru dinaikkan ke enforcement mode yang memblokir [S15]. NIST sangat menyarankan uji coba dalam mode pemantauan sebelum memblokir [S15]. Application control di Windows juga bisa mencakup script, installer MSI, dan PowerShell interaktif, bukan hanya file `.exe` [S16].

**Contoh di PT JAB:** PC loket di kantor layanan pelanggan menjalankan application control dalam enforcement mode: aplikasi kasir dan browser kantor diizinkan berdasarkan publisher, dan beberapa tool internal berdasarkan hash. Perangkat dengan fungsi tetap seperti ini adalah tempat terbaik untuk allowlisting, karena daftar programnya jarang berubah. Laptop Marketing jauh lebih beragam, sehingga allowlisting ketat di sana mahal dirawat. Tetapi jawabannya bukan memberi admin permanen ke pengguna: aplikasi edit video dipasang oleh tim IT dari katalog aplikasi yang disetujui, dan bila aplikasi itu dibutuhkan banyak orang, ia ditambahkan ke katalog. Alasan menolak admin permanen dibahas lagi di bagian 1.11.

**Beda dengan antivirus:** antivirus mengizinkan semua kecuali yang dikenal jahat; allowlisting menolak semua kecuali yang dikenal baik. Microsoft menegaskan application control bukan pengganti antivirus; keduanya dijalankan berdampingan [S16].

**Salah paham umum:**
- "Allowlisting berarti malware tidak mungkin jalan." Penyerang bisa menyalahgunakan program yang sudah diizinkan (misalnya PowerShell atau program bawaan Windows lain) bila aturan terlalu longgar. Karena itu aturan berbasis path saja dianggap lemah, dan program bawaan yang sering disalahgunakan perlu dibatasi juga.

### 1.7 IAM, identitas, dan akun

Pertanyaan keenam datang dari telepon Reza Firmansyah, engineer NOC, ke ext. 1199 (nomor SOC). Ia menerima sembilan notifikasi MFA antara pukul 06:58 dan 07:12, padahal tidak sedang login. Sebelum bicara MFA, Sari bertanya: "Reza itu punya akun apa saja di PT JAB?" Pertanyaan itu ternyata tidak sesederhana kelihatannya.

**Apa itu:**
- **IAM** (identity and access management) adalah pengelolaan identitas individu di dalam sebuah sistem; di TI perusahaan, artinya menetapkan dan mengelola peran dan hak akses setiap pengguna jaringan [S17]. IAM mencakup seluruh perjalanan seseorang di organisasi: dibuatkan akun saat masuk (joiner), haknya diubah saat pindah bagian (mover), dan akunnya dimatikan saat keluar (leaver).
- **Identitas** adalah siapa seseorang atau sesuatu dalam konteks tertentu. NIST mendefinisikan identitas digital sebagai atribut atau kumpulan atribut yang secara unik menggambarkan satu subjek dalam konteks tertentu [S18]. Subjek bisa orang, tetapi juga perangkat, aplikasi, atau layanan; akun layanan (service account) dan identitas perangkat adalah identitas non-manusia.
- **Akun** adalah rekaman di sebuah sistem yang dipakai identitas untuk login. NIST memakai istilah subscriber account: akun yang dibuat penyedia layanan identitas untuk setiap pengguna terdaftar, berisi atribut dan authenticator yang terikat padanya [S18]. Satu identitas bisa punya banyak akun.

**Analogi:** identitas adalah orangnya, dengan KTP dan nomor induk karyawan. Akun adalah kartu akses: satu untuk gedung kantor, satu untuk ruang server, satu untuk parkir. Batasnya: di dunia digital satu kartu sering membuka banyak pintu sekaligus (lihat SSO di bagian 1.9), dan ada "orang" yang bukan manusia, misalnya program yang punya kartu sendiri untuk bekerja otomatis.

**Cara kerja:** di organisasi seperti PT JAB, identitas karyawan bersumber dari data personalia. Dari situ akun dibuat di direktori pusat (Active Directory), lalu disinkronkan ke Entra ID untuk layanan cloud. Aplikasi lain sebisa mungkin memakai akun pusat itu lewat SSO, sehingga mematikan satu akun pusat menutup banyak pintu sekaligus. Akun yang tidak tersambung ke pusat (akun lokal di router, akun bawaan aplikasi lama) harus dicatat terpisah, karena di situlah akun sering terlupa saat orang pindah atau keluar.

**Contoh di PT JAB:** identitas Reza Firmansyah, engineer NOC, punya beberapa akun. Tabel berikut dipakai Sari untuk memutuskan akun mana yang diurus pagi itu; perhatikan kolom "Terdampak?".

| Akun | Dipakai untuk | Terdampak? |
|---|---|---|
| `reza.firmansyah@jab.example` (AD `corp.jab.example`, tersinkron ke Entra ID) | Laptop, email, Teams, VPN, aplikasi lewat SSO | Ya: password-nya terbukti diketahui pelaku, karena notifikasi MFA hanya muncul setelah password benar |
| `adm.reza` (akun admin AD terpisah) | Pekerjaan admin lewat jump host `JKT-JUMP01` | Diperiksa: password berbeda, login wajib kunci FIDO2; tidak ada percobaan di log |
| Akun di sistem monitoring jaringan NOC | Melihat status perangkat jaringan | Diperiksa: login lewat SSO, jadi ikut terlindungi bila akun utama diamankan |
| Akun lokal darurat di beberapa router lama | Akses saat RADIUS mati | Tidak terkait langsung, tetapi dicatat untuk ditinjau karena tidak tersambung ke pusat |

Kesimpulan untuk pertanyaan Sari: yang diurus segera adalah akun utama (reset password, cabut semua sesi yang sedang aktif), lalu memastikan akun admin dan akun lain tidak ikut dipakai. Detail urutannya ada di bagian 2.3.

**Beda identitas dengan akun:** identitas tetap walaupun akun berganti; akun bisa dihapus, dibuat ulang, atau digandakan. Saat insiden, pertanyaan "orang ini siapa" (identitas) dan "akun mana yang dipakai pelaku" (akun) harus dijawab terpisah, karena pelaku memakai akun, bukan identitas.

**Beda IAM dengan authentication:** authentication (membuktikan siapa yang login, Day 01 bagian 1.2) adalah satu momen. IAM adalah seluruh pengelolaan di sekitarnya: siapa dibuatkan akun, hak apa yang diberikan, kapan ditinjau, kapan dicabut.

**Salah paham umum:**
- "Akun yang tidak dipakai tidak berbahaya." Akun milik karyawan yang sudah keluar atau akun uji yang terlupa justru favorit penyerang, karena pemiliknya tidak akan melapor bila ada login aneh.

### 1.8 MFA: faktor, jenis, dan ketahanan terhadap phishing

Ini inti pertanyaan ketujuh Sari. Reza menolak semua sembilan notifikasi, jadi pelaku tidak masuk. Tetapi Sari tetap menganggapnya serius, dan ia ingin kamu paham kenapa aplikasi MFA di HP Reza berbeda kekuatannya dengan kunci FIDO2 yang dipakai admin, dan kenapa insiden `INC-2026-022` dulu bisa lolos MFA.

**Apa itu:** MFA (multi-factor authentication) adalah authentication yang memakai dua atau lebih faktor yang berbeda jenis [S20]. Day 01 bagian 1.2 sudah menyebut tiga faktor; NIST merumuskannya sebagai berikut [S19][S20]:

| Faktor | Arti | Contoh |
|---|---|---|
| Sesuatu yang kamu tahu | Rahasia yang diingat | Password, PIN |
| Sesuatu yang kamu punya | Benda atau perangkat yang dikuasai | HP dengan aplikasi authenticator, kunci FIDO2, smart card |
| Sesuatu yang melekat padamu | Ciri biologis atau perilaku (biometrik) | Sidik jari, wajah |

Tabel ini dipakai untuk menguji klaim "sudah MFA": dua bukti dari baris yang sama (password ditambah pertanyaan rahasia) tetap satu faktor. NIST juga menetapkan bahwa biometrik hanya boleh dipakai sebagai bagian dari MFA bersama authenticator fisik, bukan sebagai satu-satunya bukti [S19]; sidik jari yang membuka kunci HP berfungsi membuka authenticator di HP itu, bukan dikirim ke server. Benda atau aplikasi yang membuktikan faktor disebut authenticator.

**Analogi:** mengambil uang di ATM butuh kartu ATM (punya) dan PIN (tahu). Pencuri yang hanya mengintip PIN atau hanya mencuri kartu tetap gagal. Batasnya: di internet, penipu bisa meminta kedua bukti sekaligus lewat halaman palsu, dan beberapa jenis bukti (kode OTP, persetujuan push) bisa diserahkan korban ke penipu tanpa sadar. Karena itu jenis authenticator menentukan kekuatan MFA, bukan hanya jumlah faktornya.

**Cara kerja: jenis-jenis MFA dari yang paling lemah ke paling kuat.** CISA menyusun urutan berdasarkan kerentanan terhadap ancaman yang dikenal [S21]:

| Jenis | Cara pakai | Rentan terhadap |
|---|---|---|
| Kode lewat SMS atau telepon suara | Kode dikirim ke nomor HP, diketik ke halaman login | Phishing, penyadapan jaringan seluler (celah SS7), SIM swap (nomor dipindah ke kartu SIM pelaku) |
| Push tanpa number matching | Notifikasi "setujui login?" di aplikasi, cukup tekan Setujui | MFA fatigue (push bombing) dan salah tekan pengguna |
| OTP dari aplikasi atau token, push dengan number matching | Kode 6 digit dari aplikasi; atau pengguna mengetik angka dari layar login ke aplikasi | Phishing (kode atau angka bisa dipancing lewat halaman palsu atau telepon) |
| Phishing-resistant: FIDO2/WebAuthn, PKI (smart card) | Kunci kriptografi yang terikat ke alamat situs asli | Tahan phishing; push bombing, SS7, dan SIM swap tidak berlaku |

Tabel ini dibaca dari atas ke bawah sebagai urutan prioritas migrasi. CISA menyebut MFA apa pun lebih baik daripada tanpa MFA, tetapi phishing-resistant MFA adalah standar tertinggi; SMS dan suara hanya sebagai pilihan terakhir atau solusi sementara [S21].

Beberapa istilah di tabel perlu dijelaskan satu per satu.

- **OTP** (one-time password) adalah kode sekali pakai. Ia membuktikan kamu memegang HP atau token, tetapi kode itu bisa diketik siapa pun yang mengetahuinya dalam beberapa puluh detik, termasuk penipu yang memintanya.
- **Push notification** adalah notifikasi dari layanan login ke aplikasi authenticator di HP. Versi paling sederhana hanya meminta pengguna menekan Setujui.
- **MFA fatigue** (juga disebut push bombing atau push fatigue) adalah teknik pelaku yang sudah memegang password: ia mencoba login berulang-ulang sehingga HP korban dibanjiri notifikasi, sampai korban menyetujui satu karena salah tekan, kesal, atau mengira itu permintaan sah [S22].
- **Number matching** memaksa pengguna mengetik angka yang tampil di layar login ke aplikasi di HP. Pengguna yang tidak melihat layar login tidak bisa menyetujui, dan setiap percobaan memunculkan angka baru, sehingga membanjiri notifikasi tidak efektif [S22]. CISA menyebutnya mitigasi sementara terbaik bagi organisasi yang belum bisa memakai phishing-resistant MFA, walaupun tidak sekuat phishing-resistant MFA [S22]. Di Microsoft Entra ID, number matching aktif untuk semua notifikasi push Microsoft Authenticator dan pengguna tidak bisa mematikannya [S23]. NIST SP 800-63B-4 juga meminta authentication lewat perangkat terpisah (out-of-band) memindahkan rahasia, misalnya mengetik kode yang tampil, bukan sekadar persetujuan, dan menyarankan membatasi jumlah notifikasi yang dikirim [S19].
- **Phishing-resistant MFA** adalah authentication yang mencegah rahasia login dan hasil authentication jatuh ke situs palsu, tanpa bergantung pada kewaspadaan pengguna [S19]. NIST menegaskan password tidak tahan phishing, demikian juga OTP, look-up secret, dan metode out-of-band; ketahanan phishing dicapai dengan authentication kriptografis yang mengikat ke saluran atau ke nama situs, contohnya WebAuthn/FIDO2 [S19].
- **FIDO2/WebAuthn** adalah standar yang dikembangkan FIDO Alliance dan W3C; satu-satunya authentication tahan phishing yang tersedia luas menurut CISA [S21]. Authenticator-nya bisa berupa kunci fisik terpisah (USB atau NFC) atau tertanam di laptop dan HP [S21].
- **Passkey** adalah kredensial berbasis standar FIDO yang disimpan di HP, komputer, atau kunci keamanan, dan dibuka dengan cara yang sama seperti membuka kunci perangkat [S25]. Setiap passkey terikat ke satu akun di satu situs atau aplikasi, sehingga situs tiruan tidak bisa memakainya [S25]. Ada dua jenis: synced passkey yang disimpan di layanan cloud dan tersinkron ke perangkat lain milik pengguna, dan device-bound passkey yang tidak pernah meninggalkan satu perangkat, termasuk yang ada di kunci FIDO [S25].

Kenapa FIDO2 tahan phishing, dalam bahasa sederhana: saat kunci didaftarkan ke `login.microsoftonline.com`, kunci membuat pasangan kunci kriptografi khusus untuk alamat itu (konsep public key dan private key dibahas di Day 05). Saat login, browser memberi tahu kunci alamat situs yang sedang meminta. Bila alamatnya `login-microsoft-secure.example`, kunci tidak punya pasangan untuk alamat itu dan tidak menjawab. Pengguna tidak perlu jeli membaca alamat; kunci yang melakukannya.

```
  OTP / push + number matching                         FIDO2 / passkey

  korban --password+kode--> SITUS PALSU                korban --> SITUS PALSU (alamat palsu)
                               | teruskan                             | minta tanda tangan
                               v                                      v
                         situs asli: login sah         kunci FIDO2: "tidak ada kunci untuk alamat ini"
                               |                                      |
                     pelaku dapat sesi (cookie)                 login gagal, pelaku tidak dapat apa-apa
```

Diagram ini adalah inti `INC-2026-022`, insiden AiTM (adversary-in-the-middle) di PT JAB tahun lalu: pelaku memasang situs palsu yang meneruskan semua isian korban ke halaman login asli, korban memasukkan password dan menyetujui MFA dengan benar, lalu pelaku mencuri cookie sesi (tanda bahwa login sudah berhasil, sehingga situs tidak meminta login lagi) dan memakainya tanpa perlu MFA lagi. MFA berjalan sempurna; masalahnya, MFA jenis itu bisa diteruskan.

NIST juga memakai tingkatan AAL (authenticator assurance level) untuk menyatakan kekuatan authentication [S19]:

| Tingkat | Syarat ringkas |
|---|---|
| AAL1 | Satu faktor atau lebih |
| AAL2 | Dua faktor berbeda, dan setidaknya satu pilihan tahan phishing harus ditawarkan |
| AAL3 | Authenticator kriptografis tahan phishing dengan kunci yang tidak bisa diekspor |

Tabel ini berguna saat membaca kebijakan atau kontrak yang menyebut "AAL2" atau "AAL3". Karena synced passkey bisa disalin ke perangkat lain, NIST mengizinkannya sampai AAL2 tetapi tidak untuk AAL3 [S19]; untuk AAL3 dipakai kunci yang terikat ke satu perangkat. NIST juga menggolongkan pemakaian jaringan telepon (SMS dan panggilan suara) untuk authentication sebagai "restricted": masih boleh, tetapi dengan syarat tambahan dan harus ada pilihan lain [S19].

**Contoh di PT JAB:** karyawan biasa memakai password ditambah Microsoft Authenticator dengan number matching. Akun admin `adm.<nama>` wajib memakai kunci FIDO2, dan Conditional Access di Entra ID (fitur yang tersedia dengan lisensi Entra ID P1 milik PT JAB) mewajibkan authentication strength "Phishing-resistant MFA" untuk akun itu [S24]. Microsoft menyebut metode yang masuk kategori tersebut: Windows Hello for Business atau platform credential, kunci keamanan FIDO2, dan certificate-based authentication multifaktor [S24]. Untuk Reza, number matching bekerja: sembilan notifikasi muncul, tetapi tanpa angka dari layar pelaku, Reza tidak bisa menyetujuinya. Pelaku lalu mencoba jalan lain: mengirim pesan WhatsApp yang mengaku helpdesk dan menanyakan "angka di layar". Inilah batas number matching yang disebut CISA: tahan push bombing, tetapi tetap rentan phishing dan rekayasa sosial [S21]. Reza tidak memberikan angkanya dan melapor. Yang paling penting dari kejadian ini justru hal pertama: notifikasi MFA hanya muncul setelah password benar, jadi password Reza sudah diketahui pelaku.

**Beda MFA dengan 2-step verification:** dua langkah tidak otomatis dua faktor. Password lalu kode yang dikirim ke email yang dibuka dengan password yang sama di browser yang sama hanya menambah langkah, belum tentu menambah jenis bukti.

**Salah paham umum:**
- "Semua MFA sama kuatnya." Urutan CISA di atas menunjukkan sebaliknya; SMS dan push tanpa number matching jauh di bawah FIDO2 [S21].
- "Pengguna menolak semua notifikasi, jadi tidak ada masalah." Notifikasi yang muncul berarti faktor pertama sudah jebol. Tindak lanjut tetap wajib: reset password dan cari tahu dari mana password bocor.

### 1.9 SSO (single sign-on)

Pertanyaan kedelapan Sari terdengar seperti keluhan pengguna: pagi hari kamu login sekali di laptop, lalu Outlook, Teams, portal HR, ticketing SOC, dan Splunk terbuka tanpa minta password lagi. Apakah itu tidak berbahaya?

**Apa itu:** SSO (single sign-on) adalah proses authentication di mana satu akun beserta authenticator-nya dipakai untuk mengakses banyak aplikasi dengan mulus, biasanya diterapkan dengan protokol federation [S18]. Federation adalah penyampaian informasi identitas dan authentication di antara sistem-sistem yang terhubung [S18]. Di dalam federation ada dua peran: IdP (identity provider), yang memegang authenticator utama pengguna dan menerbitkan pernyataan (assertion) tentang pengguna itu, dan relying party (RP), aplikasi yang memercayai pernyataan IdP untuk memberi akses [S18]. Protokol yang umum adalah SAML dan OpenID Connect.

**Analogi:** satu kartu akses yang membuka semua pintu yang menjadi hakmu, diterbitkan oleh resepsionis pusat. Setiap pintu tidak memeriksa KTP-mu lagi; pintu cukup memercayai kartu yang diterbitkan resepsionis. Batasnya: kartu itu sekarang sangat berharga. Bila dicuri, semua pintu yang menjadi hakmu ikut terbuka. Sebaliknya, bila kartu diblokir di resepsionis, semua pintu ikut tertutup sekaligus.

**Cara kerja:**

```
  1. kamu buka Splunk (RP)  ---> "belum login, silakan ke IdP"
  2. browser ke Entra ID (IdP): password + MFA (sekali)
  3. IdP menerbitkan pernyataan bertanda tangan: "ini reza.firmansyah, sudah MFA"
  4. Splunk memeriksa tanda tangan IdP, lalu memberi akses
  5. buka Teams, portal HR: IdP melihat sesi masih aktif, langsung terbitkan pernyataan baru
     tanpa minta password lagi (selama sesi berlaku dan kebijakan mengizinkan)
```

Aplikasi tidak pernah melihat password; ia hanya menerima pernyataan yang ditandatangani IdP. Tanda tangan digital itu (Day 05) yang membuat aplikasi yakin pernyataan tidak dipalsukan.

**Contoh di PT JAB:** Entra ID adalah IdP untuk Microsoft 365, Splunk, ticketing SOC, dan portal HR. Keuntungannya terasa saat insiden Reza: satu reset password ditambah pencabutan sesi di Entra ID memutus akses pelaku ke semua aplikasi yang memakai SSO, tanpa perlu mengurus aplikasi satu per satu. CISA juga mencatat bahwa dukungan MFA untuk aplikasi bisnis sering bisa ditambahkan lewat integrasi dengan sistem identitas perusahaan dan SSO [S21]; aplikasi lama yang tidak mendukung MFA menjadi terlindungi bila login-nya diserahkan ke IdP. Risikonya juga nyata, dan `INC-2026-022` membuktikannya: cookie sesi yang dicuri dari login ke IdP membuka semua aplikasi sekaligus. Karena itu PT JAB membatasi masa berlaku sesi untuk aplikasi sensitif dan mewajibkan login ulang dengan MFA untuk tindakan tertentu.

**Beda SSO dengan password yang sama di semua aplikasi:** dengan password yang sama, setiap aplikasi menyimpan dan memeriksa password sendiri, sehingga satu aplikasi yang bocor membocorkan semuanya, dan mematikan akses harus dilakukan di setiap aplikasi. Dengan SSO, password hanya diperiksa di IdP, dan aplikasi menerima pernyataan, bukan password.

**Salah paham umum:**
- "SSO mengurangi keamanan karena satu password membuka semua." SSO memusatkan risiko, tetapi juga memusatkan pertahanan: MFA kuat, pemantauan login, dan pencabutan akses cukup dilakukan di satu tempat. Yang berbahaya adalah IdP yang dilindungi lemah.

### 1.10 RBAC (role-based access control)

Pertanyaan kesembilan Sari muncul saat kamu mencoba mengklik "Isolate device" di konsol Defender untuk latihan dan mendapat pesan bahwa kamu tidak punya izin, padahal tombol "Run antivirus scan" bisa kamu klik. Siapa yang menentukan itu?

**Apa itu:** RBAC (role-based access control) adalah cara mengatur hak akses dengan mengaitkan tindakan yang diizinkan ke peran (role), bukan ke orang satu per satu [S26]. Pengguna mendapat sekumpulan hak dari peran yang diberikan kepadanya; peran biasanya mencerminkan hak yang dibutuhkan untuk sebuah fungsi di organisasi, bisa bertingkat dan mewarisi hak dari peran lain, dan satu peran bisa dipegang satu atau banyak orang [S26]. RBAC adalah salah satu cara mewujudkan authorization (menentukan "boleh apa", Day 01 bagian 1.2) dan least privilege (hak sekecil yang dibutuhkan, Day 01 bagian 1.7).

**Analogi:** kartu akses per jabatan. Semua resepsionis mendapat kartu yang membuka lobi dan ruang arsip tamu; semua teknisi mendapat kartu yang membuka ruang panel listrik. Saat ada resepsionis baru, ia cukup diberi kartu "resepsionis", tidak perlu menyusun daftar pintu satu per satu. Batasnya: peran yang terlalu umum ("semua staf IT") memberi hak terlalu luas, dan peran yang terlalu banyak (satu peran per orang) membuat RBAC kehilangan manfaatnya. Pengecualian per orang yang menumpuk di luar peran juga merusak rapinya sistem.

**Cara kerja:**

```
  izin (permission)           peran (role)                 orang
  - lihat alert         \
  - jalankan AV scan     >--> SOC-L1  ------------------> kamu, Gilang, Dwi
  - komentar di insiden /
  - semua izin SOC-L1   \
  - isolasi perangkat    >--> SOC-L2  ------------------> Sari, Yoga, Rudi
  - tutup insiden       /
  - semua izin SOC-L2   \
  - ubah aturan deteksi  >--> SOC-Admin ----------------> Dimas
```

Langkahnya: daftar izin yang ada di sistem, kelompokkan ke peran sesuai fungsi kerja, masukkan orang ke peran, dan tinjau berkala siapa memegang peran apa. Saat orang pindah tugas, ia dipindahkan ke peran baru dan dikeluarkan dari peran lama.

**Contoh di PT JAB:** di konsol Defender dan di Splunk, SOC memakai tiga peran seperti diagram di atas. Kamu (L1) bisa melihat alert, menjalankan scan antivirus, dan menulis catatan; mengisolasi perangkat butuh peran L2 karena isolasi memutus pekerjaan seseorang dan harus diputuskan analyst yang lebih berpengalaman. Itulah kenapa pagi ini Sari yang mengisolasi `JKT-WS-1061`. Di Active Directory, pola yang sama diterapkan dengan group: hak akses folder bersama diberikan ke group "Keuangan-Read", bukan ke nama orang. Group, OU, dan GPO dibahas di Day 07; role dan policy di cloud dibahas di Day 08.

**Beda RBAC dengan ABAC:** RBAC memutuskan berdasarkan peran. ABAC (attribute-based access control) memutuskan berdasarkan atribut yang lebih beragam, misalnya departemen, lokasi, jam, dan kondisi perangkat. Conditional Access yang memeriksa lokasi dan kondisi perangkat sebelum memberi akses adalah contoh keputusan berbasis atribut. Banyak organisasi memakai keduanya bersama.

**Salah paham umum:**
- "RBAC otomatis berarti least privilege." RBAC hanya serapi perannya. Peran yang dibuat terlalu luas, atau orang yang dibiarkan memegang peran lama setelah pindah bagian (privilege creep), tetap melanggar least privilege.

### 1.11 PAM (privileged access management)

Pertanyaan terakhir Sari kembali ke permintaan helpdesk: bila bukan admin permanen, bagaimana seharusnya orang memakai hak admin? Jawabannya adalah PAM.

**Apa itu:** PAM (privileged access management) adalah pengendalian akun dan akses yang berhak tinggi (privileged), seperti admin domain, admin server, root di Linux, dan admin layanan cloud. Akun ini paling diincar penyerang, karena satu akun admin bisa membuka seluruh sistem. Unsur PAM yang umum adalah: akun admin terpisah dari akun harian; hak admin diberikan hanya saat dibutuhkan dan berakhir otomatis (just-in-time); persetujuan dan alasan tertulis sebelum hak aktif; MFA kuat saat mengaktifkan hak; penyimpanan password akun bersama di vault (brankas digital) yang mencatat siapa meminjam; akses lewat jump host atau bastion (server perantara yang menjadi satu-satunya jalan masuk ke sistem penting); dan rekaman serta tinjauan berkala atas pemakaian hak itu.

Microsoft Entra Privileged Identity Management (PIM) adalah contoh produk yang menerapkan sebagian unsur tersebut untuk peran di Entra ID dan Azure: akses just-in-time, akses terbatas waktu dengan tanggal mulai dan akhir, persetujuan untuk mengaktifkan peran, MFA wajib saat aktivasi, alasan tertulis, notifikasi, access review, dan riwayat audit [S27]. PIM membedakan penugasan eligible (berhak mengaktifkan peran saat perlu) dengan active (peran langsung berlaku tanpa tindakan) [S27]. PIM membutuhkan lisensi tersendiri [S27].

**Analogi:** lemari kunci ruang server di bagian keamanan gedung. Tidak ada karyawan yang membawa pulang kunci ruang server. Teknisi yang perlu masuk mengisi buku pinjam (siapa, untuk apa, sampai jam berapa), petugas menyerahkan kunci setelah mengecek identitas, kunci dikembalikan setelah pekerjaan selesai, dan CCTV merekam selama ia di dalam. Batasnya: lemari kunci tidak menolong bila ada duplikat kunci yang beredar di luar lemari, misalnya akun admin lama yang terlupa atau password admin yang ditulis di skrip.

**Cara kerja:**

```
  TANPA PAM (standing privilege)              DENGAN PAM (just-in-time)

  dewi.anggraini = admin laptop, 24 jam        adm.agung  (akun admin terpisah, FIDO2)
  agung = Domain Admin di akun harian            |
     |                                           | 1. minta aktivasi: "patch JKT-FS01, 2 jam", tiket
     | phishing / malware di akun harian         | 2. disetujui, MFA, hak aktif 2 jam
     v                                           | 3. masuk lewat JKT-JUMP01 (sesi tercatat)
  pelaku langsung memegang hak admin             | 4. hak berakhir otomatis
                                                 v
                                     pelaku yang mencuri akun harian tidak dapat hak admin
```

**Contoh di PT JAB:** PT JAB belum memakai produk PAM penuh, tetapi sudah menerapkan beberapa unsurnya. Setiap admin punya akun terpisah `adm.<nama>` yang tidak dipakai untuk email dan browsing, login dengan kunci FIDO2, dan hanya bisa dipakai dari jump host Windows `JKT-JUMP01`; akses admin ke server Linux lewat bastion `jkt-bastion01` yang mencatat sesi SSH. Aktivasi just-in-time dengan PIM sedang dievaluasi karena membutuhkan lisensi tambahan di atas Entra ID P1 yang dimiliki PT JAB. Untuk permintaan helpdesk Dewi: memberi hak admin permanen ke akun harian adalah kebalikan dari semua unsur itu. Satu lampiran jahat yang dibuka Dewi akan berjalan dengan hak admin, bisa mematikan pengaman, dan bisa memasang apa saja. Pemasangan aplikasi oleh tim IT dari katalog yang disetujui menyelesaikan kebutuhan Dewi tanpa menciptakan akun berhak tinggi baru.

**Beda PAM dengan IAM:** IAM mengelola semua identitas dan akses; PAM adalah bagian dari IAM yang memberi pengendalian ekstra untuk akses yang paling berbahaya bila disalahgunakan.

**Beda PAM dengan RBAC:** RBAC menentukan peran apa yang dimiliki seseorang; PAM menentukan bagaimana peran berhak tinggi itu dipakai: kapan aktif, berapa lama, lewat jalan mana, dan dengan catatan apa.

**Salah paham umum:**
- "Admin yang dipercaya boleh memakai akun admin untuk semua pekerjaan." Masalahnya bukan kepercayaan pada orangnya, tetapi pada semua yang bisa terjadi pada akunnya: email phishing, situs yang terinfeksi, atau lampiran jahat yang dibuka dengan akun admin langsung berjalan dengan hak admin.

## 2. Contoh nyata

Semua contoh di bagian ini adalah keluaran ilustrasi dari organisasi fiktif PT JAB, bukan hasil eksekusi nyata. Nama host, akun, alamat IP, nomor, dan angka dibuat untuk latihan; format tampilan disederhanakan dan tidak persis sama dengan tampilan produk aslinya.

### 2.1 Dua alert endpoint: antivirus `SOC-2027-0836` dan EDR `SOC-2027-0833`

Pertanyaan pertama Sari dijawab dengan meletakkan dua alert berdampingan. Ringkasan alert antivirus di `JKT-WS-1064`:

```
Alert      : SOC-2027-0836            Prioritas: P4
Sumber     : Microsoft Defender Antivirus
Waktu      : 2027-08-09 07:52:41 WIB
Perangkat  : JKT-WS-1064 (10.10.36.44)   Pengguna: lestari.wulandari@jab.example
Deteksi    : TrojanDownloader (generik), dikenali dari signature
File       : C:\Users\lestari.wulandari\Downloads\invoice_0821\invoice_0821.js
Asal       : invoice_0821.zip, lampiran email
Tindakan   : Quarantined
Status     : Remediated
```

Ringkasan alert EDR di `JKT-WS-1061`, dengan pohon proses (process tree) yang menunjukkan proses mana melahirkan proses mana:

```
Alert      : SOC-2027-0833            Prioritas: P2
Sumber     : Microsoft Defender for Endpoint (EDR)
Judul      : Suspicious PowerShell command launched by Office application
Waktu      : 2027-08-09 08:14:05 sampai 08:14:38 WIB
Perangkat  : JKT-WS-1061 (10.10.36.21)   Pengguna: fajar.nugroho@jab.example

Process tree:
  OUTLOOK.EXE
   └─ EXCEL.EXE  "C:\...\Content.Outlook\PO_Agustus.xlsm"              08:14:05
       └─ powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand JAB...   08:14:09
           ├─ koneksi keluar 192.0.2.131:443                           08:14:11
           ├─ tulis file C:\Users\fajar.nugroho\AppData\Roaming\updsvc.exe  08:14:14
           └─ schtasks.exe /create /tn "UpdSvc" /tr "...\updsvc.exe" /sc onlogon  08:14:38
File updsvc.exe : tidak dikenali antivirus (belum ada signature), tanpa tanda tangan digital
```

Cara membacanya: alert pertama adalah antivirus yang bekerja sesuai tugasnya. File dikenali dari signature dan dikarantina sebelum dijalankan; telemetri EDR untuk laptop yang sama tidak menunjukkan proses apa pun yang menjalankan `invoice_0821.js`. Alert kedua bercerita lain. Excel yang dibuka dari lampiran Outlook menjalankan PowerShell tersembunyi (`-WindowStyle Hidden`) dengan perintah yang disandikan (`-EncodedCommand`, isi perintah ditulis dalam base64 supaya tidak langsung terbaca; base64 adalah encoding, bukan enkripsi, dibahas di Day 05). Dalam 33 detik (08:14:05 sampai 08:14:38), PowerShell menghubungi IP luar, menulis program baru, dan membuat tugas terjadwal yang menjalankan program itu setiap kali pengguna login. Tidak satu pun file di rangkaian ini dikenali antivirus. Tabel berikut merangkum kenapa keputusannya berbeda; pakai kolom Pertanyaan kunci sebagai urutan berpikir saat menerima alert endpoint.

| Pertanyaan kunci | `SOC-2027-0836` (antivirus) | `SOC-2027-0833` (EDR) |
|---|---|---|
| Apakah kode pelaku sempat berjalan? | Tidak; dikarantina sebelum dijalankan | Ya; PowerShell berjalan dan mengunduh program |
| Apakah pelaku menanam cara untuk kembali? | Tidak | Ya; tugas terjadwal `UpdSvc` |
| Apakah ada koneksi ke luar? | Tidak | Ya; `192.0.2.131:443` |
| Keputusan | Catat, cek penerima lain, tutup | Isolasi perangkat, buka insiden `INC-2027-085`, reset password Fajar |

Langkah XDR mengikuti: portal Defender menggabungkan `SOC-2027-0833` dengan alert email untuk lampiran `PO_Agustus.xlsm` yang dikirim dari alamat pengirim luar ke tujuh karyawan, termasuk Fajar. Enam penerima lain belum membuka lampirannya; email dihapus dari kotak surat mereka, alamat `192.0.2.131` dan hash `updsvc.exe` ditambahkan sebagai indikator blokir di Defender. Analisis lengkap email phishing dibahas di Day 09.

### 2.2 Alert DLP `SOC-2027-0834`

Pertanyaan keempat Sari dijawab dengan membaca alert dari proxy `jkt-proxy01`:

```
Alert       : SOC-2027-0834            Prioritas: P3
Sumber      : jkt-proxy01, modul DLP
Waktu       : 2027-08-09 08:31:17 WIB
Pengguna    : andi.saputra@jab.example
Perangkat   : JKT-WS-1066 (10.10.36.66)
Tujuan      : https://kirimfile.example/upload (192.0.2.135), kategori: Uncategorized
Dekripsi TLS: ya (kebijakan: domain baru atau tidak terkategori)
File        : pelanggan_jakbar_juli.xlsx (2,3 MB)
Aturan      : DLP-PDP-01 "Data pribadi pelanggan ke situs non-perusahaan"
Kecocokan   : NIK (16 digit + kata pendukung "NIK") = 1.240
              Nomor HP (pola 08xx) = 1.238
              Ambang aturan: minimal 10 NIK per unggahan
Tindakan    : Blocked
```

Cara membacanya: aturan terpicu karena dua syarat bertemu, isi file (1.240 kecocokan NIK, jauh di atas ambang 10) dan tujuan (situs di luar daftar layanan perusahaan). Kata "NIK" di dekat 16 digit dipakai sebagai data pendukung supaya deretan angka lain, misalnya nomor seri perangkat, tidak ikut terhitung. Baris "Dekripsi TLS: ya" adalah alasan DLP bisa membaca isi file sama sekali; isi HTTPS tidak terbaca oleh perangkat di tengah jalan kecuali enkripsinya dibuka di proxy (Day 02 bagian 1.10).

Variasi yang perlu kamu sadari: seandainya Andi memakai layanan berbagi file terkenal yang sudah terkategori dan tidak termasuk daftar dekripsi, proxy hanya melihat nama situs dan ukuran unggahan, bukan isinya, dan alert ini tidak akan muncul. DLP di endpoint (agen yang melihat file sebelum dienkripsi browser) atau pembatasan situs berbagi file pribadi adalah lapisan yang menutup celah itu. Tindak lanjutnya bukan tugas teknis saja: Sari mencatat alert, memastikan tidak ada unggahan lain yang lolos dari perangkat yang sama, dan meneruskan kasusnya ke atasan Andi dan ke DPO.

### 2.3 Sembilan notifikasi MFA: alert `SOC-2027-0835`

Pertanyaan keenam dan ketujuh Sari dijawab dari log sign-in Entra ID untuk akun Reza. Sari menyaring log berdasarkan akun dan IP asal:

```
Alert: SOC-2027-0835   Prioritas: P2   Dibuka dari laporan pengguna (telepon ext. 1199, 07:20)
Akun : reza.firmansyah@jab.example

Waktu (WIB)   IP asal        Aplikasi        Password  MFA (Authenticator, number matching)
06:58:12      192.0.2.136    Office 365      benar     ditolak pengguna
06:59:40      192.0.2.136    Office 365      benar     ditolak pengguna
07:01:05      192.0.2.136    Office 365      benar     tidak dijawab (timeout)
07:02:51      192.0.2.136    Office 365      benar     ditolak pengguna
07:04:30      192.0.2.136    Office 365      benar     ditolak pengguna
07:06:02      192.0.2.136    Office 365      benar     tidak dijawab (timeout)
07:08:19      192.0.2.136    Office 365      benar     ditolak pengguna
07:10:44      192.0.2.136    Office 365      benar     tidak dijawab (timeout)
07:12:03      192.0.2.136    Office 365      benar     ditolak pengguna
Login berhasil dari 192.0.2.136: 0
07:14  pesan WhatsApp dari nomor tidak dikenal "IT Helpdesk JAB": minta angka yang tampil di layar
```

Cara membacanya: ada sembilan percobaan dari IP yang sama dalam 14 menit (06:58 sampai 07:12); enam ditolak Reza dan tiga dibiarkan sampai kedaluwarsa, sehingga tidak satu pun berhasil. Kolom Password berisi "benar" di semua baris, dan ini temuan terpenting: pelaku memegang password Reza. Number matching mencegah Reza menyetujui tanpa sengaja, dan pesan WhatsApp pukul 07:14 adalah usaha pelaku mendapatkan angka itu lewat rekayasa sosial, persis kelemahan yang disebut CISA [S21]. Langkah yang diambil Sari, dari yang paling mendesak:

1. Reset password akun utama Reza dan cabut semua sesi aktif di Entra ID, sehingga semua aplikasi SSO meminta login ulang (bagian 1.9).
2. Periksa akun lain milik identitas yang sama (tabel di bagian 1.7): `adm.reza` tidak menunjukkan percobaan login, dan memang hanya bisa dipakai dengan FIDO2 dari `JKT-JUMP01`.
3. Cari asal kebocoran password: apakah Reza memakai password yang sama di situs lain, atau pernah memasukkan password di halaman palsu. Analisis phishing dibahas di Day 09.
4. Cari akun lain yang mendapat percobaan dari `192.0.2.136`; tidak ada pada pagi itu. IP itu ditambahkan ke daftar pantau.
5. Usulkan Reza masuk gelombang pertama migrasi ke kunci FIDO2 untuk engineer NOC, karena akunnya dipakai untuk mengakses sistem jaringan.

### 2.4 Alert FIM Wazuh `SOC-2027-0837`

Pertanyaan ketiga Sari dijawab dengan alert dari Wazuh untuk server `jkt-radius01`:

```
Alert      : SOC-2027-0837            Prioritas: P3
Sumber     : Wazuh jkt-wazuh01, modul FIM (syscheck)
Waktu      : 2027-08-09 02:14:37 WIB
Agen       : jkt-radius01
Aturan     : 550 "Integrity checksum changed." (level 7)
File       : /etc/raddb/clients.conf
Atribut    : size 3412 -> 3561 byte
             sha256  9c1e...7a40 -> 4b7f...e21d
             mtime   2027-07-12 10:03 -> 2027-08-09 02:14
             owner/permission: tidak berubah (root:radiusd, 640)
Who-data   : tidak aktif
Isi berubah (report_changes):
  + client olt-mdn-07 {
  +     ipaddr = 10.40.7.2
  +     secret = ********
  + }
```

Cara membacanya: FIM memberi tahu apa yang berubah (satu blok baru yang mendaftarkan perangkat `olt-mdn-07` sebagai klien RADIUS, sehingga file bertambah 149 byte), kapan (02:14), dan bahwa pemilik serta permission file tidak berubah. FIM tidak memberi tahu siapa yang mengubahnya, karena who-data tidak aktif, dan tidak memberi tahu apakah perubahan itu sah. Untuk itu Sari mencari tiket perubahan dan menemukan `CHG-2027-0731`: penambahan OLT (perangkat akses fiber) baru di POP Medan, dikerjakan tim Infrastruktur Agung Prabowo malam itu lewat bastion `jkt-bastion01`. Log sesi bastion menunjukkan login `adm.agung` pukul 02:09 sampai 02:21, cocok dengan waktu perubahan. Alert ditutup sebagai aktivitas sah, dengan catatan bahwa jendela perubahan di tiket tertulis 01:00 sampai 02:00, jadi pekerjaan selesai lewat jadwal; catatan itu diteruskan ke Agung.

Variasi yang perlu dikenali: bila tidak ada tiket, tidak ada sesi admin di bastion, atau alamat yang didaftarkan berada di luar rentang perangkat jaringan PT JAB, perubahan yang sama harus diperlakukan sebagai kemungkinan intrusi. Pelaku yang bisa mendaftarkan perangkat sendiri ke RADIUS bisa mencoba memakai server itu untuk menebak password pengguna.

## 3. Perbandingan istilah yang sering tertukar

### 3.1 Antivirus, EDR, XDR, MDR, dan SIEM

Lima istilah ini sering muncul di satu kalimat brosur vendor. Tabel berikut membedakannya dari jenis barangnya dan pertanyaan yang dijawab; cari kolom Jenis lebih dulu, karena MDR satu-satunya yang berupa layanan orang.

| Istilah | Jenis | Pertanyaan yang dijawab | Melihat | Contoh di PT JAB |
|---|---|---|---|---|
| Antivirus | Produk di endpoint | Apakah file ini malware yang dikenal? | File di satu perangkat | Defender Antivirus mengarantina `invoice_0821.js` |
| EDR | Produk di endpoint + konsol | Apa yang terjadi di perangkat ini, dan apakah polanya serangan? | Proses, file, koneksi, login di perangkat ber-agen | Pohon proses Excel ke PowerShell di `JKT-WS-1061` |
| XDR | Platform lintas produk | Bagaimana satu serangan terlihat di endpoint, email, identitas, cloud sekaligus? | Semua produk yang tersambung dan berlisensi | Alert EDR digabung dengan email `PO_Agustus.xlsm` |
| MDR | Layanan pihak luar | Siapa yang memantau dan merespons, terutama di luar jam kerja? | Apa pun yang diberi akses oleh pelanggan | Tawaran vendor yang sedang dipertimbangkan Dimas |
| SIEM | Platform log | Apa yang terlihat bila semua log dikumpulkan dan dicari di satu tempat? | Log apa pun yang dikirim | Splunk `jkt-splunk-sh01` |

### 3.2 HIDS, FIM, HIPS, dan EDR

Empat istilah ini sama-sama hidup di host dan sering dicampur, termasuk di materi pelatihan. Tabel berikut memisahkannya; perhatikan kolom Contoh yang tepat, karena contoh yang salah (misalnya menyebut Tripwire sebagai HIDS lengkap atau CrowdStrike sebagai HIPS) sering muncul.

| Istilah | Fungsi utama | Bisa memblokir? | Contoh yang tepat |
|---|---|---|---|
| HIDS | Deteksi intrusi dari log, file, proses di satu host | Umumnya tidak; sebagian punya active response | OSSEC, Wazuh |
| FIM | Deteksi perubahan file penting dengan membandingkan checksum | Tidak; mendeteksi setelah perubahan | Tripwire, modul FIM di Wazuh dan OSSEC |
| HIPS | Seperti HIDS, tetapi dirancang untuk menghentikan aktivitas yang terdeteksi | Ya | Dibahas di Day 03 |
| EDR | Rekaman perilaku, analitik, investigasi, dan respons dari konsol | Ya, termasuk isolasi perangkat | Microsoft Defender for Endpoint, CrowdStrike Falcon |

### 3.3 Jenis MFA

Bagian 1.8 menjelaskan setiap jenis; tabel ini merangkumnya untuk keputusan cepat. Cari kolom "Tahan phishing?" saat menilai akun berisiko tinggi.

| Jenis | Faktor kedua | Tahan MFA fatigue? | Tahan phishing? | Catatan |
|---|---|---|---|---|
| SMS atau suara | Punya (nomor HP) | Tidak relevan | Tidak | Rentan SS7 dan SIM swap; pilihan terakhir |
| Push tanpa number matching | Punya (HP) | Tidak | Tidak | NIST tidak lagi menerima persetujuan tanpa pemindahan rahasia |
| Push dengan number matching | Punya (HP) | Ya | Tidak | Angka bisa dipancing lewat telepon atau pesan |
| OTP aplikasi atau token | Punya (HP atau token) | Ya | Tidak | Kode bisa diketik ke halaman palsu |
| FIDO2 / passkey / smart card | Punya (kunci kriptografi), sering dibuka dengan PIN atau biometrik | Ya | Ya | Terikat ke alamat situs asli; synced passkey sampai AAL2, device-bound untuk AAL3 |

### 3.4 IAM, SSO, RBAC, PAM, dan MFA

Lima istilah identitas ini bekerja bersama, tetapi masing-masing menjawab pertanyaan yang berbeda. Tabel berikut dipakai saat menulis temuan audit atau laporan insiden: tentukan dulu pertanyaan mana yang gagal dijawab.

| Istilah | Pertanyaan yang dijawab | Bila gagal | Contoh di PT JAB |
|---|---|---|---|
| IAM | Siapa punya akun apa, sejak kapan, dan kapan dicabut? | Akun karyawan keluar masih aktif | Akun Reza tercatat lengkap, termasuk akun lokal router |
| MFA | Apakah yang login benar pemilik akun? | Password curian cukup untuk masuk | Number matching menahan sembilan percobaan |
| SSO | Bagaimana satu login dipakai untuk banyak aplikasi? | Password tersebar di banyak aplikasi; pencabutan akses tidak serentak | Entra ID sebagai IdP untuk Splunk dan ticketing |
| RBAC | Hak apa yang dimiliki peran ini? | Hak diberikan per orang dan menumpuk | Peran SOC-L1, SOC-L2, SOC-Admin |
| PAM | Bagaimana hak tinggi dipakai, kapan, lewat mana, dan tercatat di mana? | Akun harian memegang hak admin permanen | `adm.<nama>`, FIDO2, `JKT-JUMP01`, `jkt-bastion01` |

## 4. Salah paham umum

- **Anggapan:** pengaman di jaringan sudah cukup, endpoint tidak perlu dijaga khusus. **Kenyataannya:** laptop dibawa keluar kantor, lalu lintas HTTPS tidak terbaca isinya oleh perangkat jaringan biasa, dan alert `SOC-2027-0833` di bagian 2.1 hanya terlihat dari dalam perangkat. Pengaman jaringan dan endpoint adalah lapisan berbeda jenis dalam defense in depth (Day 01 bagian 1.6).
- **Anggapan:** pengaman endpoint yang terpasang di semua laptop berarti semua aset terlindungi. **Kenyataannya:** server Linux, perangkat jaringan, dan server lama sering tidak bisa dipasangi agen yang sama. Setiap perangkat tanpa agen butuh pengganti (HIDS, FIM, pembatasan jaringan, log ke SIEM) dan harus tercatat, seperti pelajaran `INC-2026-017`.
- **Anggapan:** MFA membuat akun tidak bisa diambil alih. **Kenyataannya:** MFA yang tidak tahan phishing bisa diteruskan lewat situs AiTM seperti pada `INC-2026-022`, dan cookie sesi yang dicuri tidak meminta MFA lagi [S19][S21]. MFA menaikkan biaya serangan; jenis MFA menentukan berapa banyak.
- **Anggapan:** semakin banyak alat keamanan di endpoint, semakin aman. **Kenyataannya:** dua antivirus yang aktif bersamaan bisa saling mengganggu, dan setiap alat menambah alert yang harus dibaca. Yang menentukan adalah apakah setiap alat dirawat, di-tuning, dan alert-nya benar-benar dibaca.
- **Anggapan:** pengguna yang meminta hak lebih pasti punya niat buruk, atau sebaliknya, karyawan senior boleh punya hak apa saja. **Kenyataannya:** least privilege, RBAC, dan PAM tidak menilai niat orang. Mereka membatasi kerugian bila akun orang itu dicuri, salah klik, atau disusupi program jahat.
- **Anggapan:** alat yang mencegah (allowlisting, DLP blokir, IPS di host) lebih baik daripada alat yang hanya mendeteksi. **Kenyataannya:** pencegahan yang belum di-tuning memblokir pekerjaan sah, sehingga orang mencari jalan pintas. Karena itu allowlisting dan DLP dijalankan dulu dalam audit atau simulation mode [S14][S15], dan alat deteksi tetap dibutuhkan untuk yang lolos.

## 5. Catatan terkini

Bagian ini mencatat versi dokumen acuan, perubahan nama produk, dan perubahan rekomendasi yang perlu diketahui saat membaca sumber lain.

- NIST SP 800-63-4 (Digital Identity Guidelines) beserta volume SP 800-63A-4, 800-63B-4, dan 800-63C-4 terbit final Juli 2025 dan menggantikan revisi 3, yang versi terakhirnya bertanggal Maret 2020 [S18][S19]. Perubahan yang relevan untuk Day ini: AAL2 kini wajib menawarkan setidaknya satu pilihan tahan phishing; persetujuan push tanpa memindahkan rahasia tidak lagi dianggap cukup karena ancaman authentication fatigue; dan ada lampiran baru tentang syncable authenticator (passkey yang tersinkron), yang diizinkan sampai AAL2 [S19]. Dokumen lama yang masih beredar memakai aturan revisi 3.
- CISA menerbitkan dua fact sheet MFA pada Oktober 2022: Implementing Phishing-Resistant MFA dan Implementing Number Matching in MFA Applications [S21][S22]. Isinya masih menjadi rujukan umum untuk urutan kekuatan jenis MFA.
- Microsoft Entra ID mengaktifkan number matching untuk semua notifikasi push Microsoft Authenticator, tanpa pilihan untuk mematikan [S23]. Halaman lama atau tangkapan layar lama yang memperlihatkan tombol Approve/Deny tanpa angka berasal dari sebelum perubahan itu.
- Microsoft mengganti nama produk keamanannya beberapa kali: Microsoft 365 Defender menjadi Microsoft Defender XDR, dan dokumentasi terbaru sering menyebut portalnya cukup "Microsoft Defender" [S3][S7]. Microsoft Defender ATP adalah nama lama Defender for Endpoint. Azure AD berganti nama menjadi Microsoft Entra ID.
- NIST SP 800-167 (Guide to Application Whitelisting) terbit Oktober 2015 dan masih memakai istilah whitelist dan blacklist [S15]. Dokumentasi vendor yang lebih baru memakai istilah allowlist dan blocklist, dan Microsoft memakai istilah application control, dengan App Control for Business (sebelumnya dikenal sebagai Windows Defender Application Control, WDAC) dan AppLocker [S16].
- NIST SP 800-94 (Guide to Intrusion Detection and Prevention Systems) yang dipakai untuk definisi HIDS dan file integrity checking terbit Februari 2007 [S2]. Konsep dasarnya stabil, tetapi contoh produk di dalamnya sudah lama; EDR modern belum dibahas di dokumen itu.
- Wazuh memakai dokumentasi bernomor versi 4.x untuk rilis stabil, dan versi 5.0 sedang dalam tahap beta saat Day ini ditulis [S10]. Nama aturan dan nomor aturan FIM di bagian 2.4 perlu dicek ulang di versi yang dipakai.
- Microsoft Defender for Endpoint menyimpan telemetri perilaku selama enam bulan menurut dokumentasi per 2026 [S4]; angka retensi ini bisa berbeda per produk dan per lisensi.

## 6. Cheat sheet

```
Endpoint            : perangkat ujung: laptop, PC, server, HP
Antivirus           : kenali dan karantina malware, terutama lewat signature; generasi baru + ML/perilaku
Signature           : ciri khas malware yang sudah dikenal (pola, hash)
Quarantine          : file dipindah ke tempat terkunci, tidak bisa dijalankan
EDR                 : rekam perilaku endpoint, deteksi pola serangan, tombol respons (isolasi)
Telemetri           : catatan aktivitas yang dikirim agen ke pusat
XDR                 : deteksi + respons lintas endpoint, email, identitas, cloud; satu incident
MDR                 : LAYANAN pihak luar yang memantau dan merespons (orang + alat)
MSSP                : penyedia layanan keamanan terkelola; umumnya memantau dan melapor, tidak merespons
HIDS                : IDS di dalam satu host: log, file, proses (OSSEC, Wazuh)
FIM                 : deteksi perubahan file penting lewat checksum (Tripwire, modul FIM Wazuh)
DLP                 : kenali data sensitif, cegah keluar (endpoint, jaringan, email, cloud)
App allowlisting    : hanya program di daftar yang boleh jalan; audit mode dulu, lalu enforce
IAM                 : kelola identitas dan hak dari masuk, pindah, sampai keluar
Identitas vs akun   : orangnya (atau perangkat/layanan) vs kartu login di satu sistem
Faktor              : tahu (password), punya (HP/kunci), melekat (biometrik)
MFA                 : 2 faktor BERBEDA atau lebih
MFA fatigue         : banjir notifikasi push sampai korban menyetujui
Number matching     : ketik angka dari layar login ke HP; tahan push bombing, tidak tahan phishing
Phishing-resistant  : FIDO2/WebAuthn, passkey, smart card (PKI); terikat ke alamat situs asli
AiTM                : situs palsu meneruskan login dan mencuri sesi; lolos MFA non-phishing-resistant
SSO                 : satu login (di IdP) untuk banyak aplikasi; pusatkan MFA dan pencabutan
IdP / RP            : penerbit pernyataan identitas / aplikasi yang memercayainya
RBAC                : hak ke peran, orang ke peran; tinjau berkala
PAM                 : akun admin terpisah, JIT, persetujuan, vault, jump host, rekaman sesi
JIT                 : hak tinggi aktif hanya saat dibutuhkan, berakhir otomatis
```

## 7. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Laptop `JKT-WS-1061` sudah pakai antivirus terbaru dan tidak ada alert antivirus sama sekali pagi itu, jadi laptop itu bersih." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Antivirus terutama mengenali file yang cirinya sudah dikenal, dan penyerang di `SOC-2027-0833` memakai Excel dan PowerShell bawaan lalu mengunduh program yang belum punya signature. Rangkaian itu hanya terlihat oleh EDR, yang merekam perilaku proses dan mengenali pola "aplikasi Office menjalankan PowerShell tersembunyi yang mengunduh program". Tidak adanya alert antivirus hanya berarti tidak ada file yang dikenali, bukan berarti tidak ada serangan. Lihat bagian 1.1, 1.2, dan 2.1.

</details>

**2. Skenario keputusan.** Dimas bertanya kepadamu: "Vendor bilang produk XDR mereka sudah termasuk tim analyst 24 jam. Jadi itu XDR atau MDR?" Jawaban mana yang paling tepat?

- A. Itu XDR, karena produknya bernama XDR.
- B. Itu dua hal yang dijual bersama: XDR adalah platform yang menyatukan dan mengorelasikan data lintas produk, sedangkan tim analyst 24 jam yang memantau dan merespons adalah layanan MDR (sering disebut managed XDR).
- C. Itu MDR, dan dengan MDR PT JAB tidak lagi membutuhkan SOC internal.

<details><summary>Jawaban</summary>

B. XDR adalah produk atau platform; MDR adalah layanan orang yang menjalankan pemantauan dan respons, dan bisa memakai EDR, XDR, atau SIEM sebagai alatnya. A keliru karena nama produk tidak mengubah fakta bahwa analyst 24 jam adalah layanan. C keliru karena MDR mengambil sebagian pekerjaan, tetapi konteks internal, keputusan bisnis, dan tanggung jawab tetap di organisasi. Lihat bagian 1.3 dan 3.1.

</details>

**3. Pertanyaan jebakan.** "Reza menolak semua sembilan notifikasi MFA dan tidak ada login yang berhasil, jadi alert `SOC-2027-0835` bisa ditutup tanpa tindakan." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Notifikasi MFA hanya muncul setelah password yang dimasukkan benar, dan log menunjukkan password benar di kesembilan percobaan. Artinya faktor pertama sudah dikuasai pelaku. Pesan WhatsApp yang meminta angka di layar juga menunjukkan pelaku masih berusaha. Tindakan minimal: reset password, cabut sesi aktif, periksa akun lain milik Reza, dan cari asal kebocoran password. Lihat bagian 1.7, 1.8, dan 2.3.

</details>

**4. Skenario keputusan.** PT JAB ingin melindungi akun Direktur Teknologi Hendra Wijaya dari serangan seperti `INC-2026-022`. Pilihan mana yang paling tepat?

- A. Ganti push notification dengan kode OTP lewat SMS, karena SMS tidak bisa dibanjiri seperti push.
- B. Wajibkan kunci FIDO2 atau passkey (phishing-resistant MFA) untuk akunnya, karena kunci itu terikat ke alamat situs asli dan tidak akan menjawab situs palsu.
- C. Pertahankan push dengan number matching, karena number matching sudah menghentikan semua jenis serangan MFA.

<details><summary>Jawaban</summary>

B. `INC-2026-022` adalah AiTM: situs palsu meneruskan password dan persetujuan MFA ke situs asli lalu mencuri sesi. Hanya authenticator kriptografis yang terikat ke nama situs, seperti FIDO2/WebAuthn, yang menolak menjawab situs palsu tanpa bergantung pada kejelian pengguna. A keliru karena SMS justru jenis yang paling lemah: rentan phishing, SS7, dan SIM swap. C keliru karena number matching tahan push bombing, tetapi angka dan kode masih bisa dipancing lewat halaman palsu atau telepon. Lihat bagian 1.8 dan 3.3.

</details>

**5. Jelaskan ulang.** Jelaskan kepada anggota keluargamu yang bukan orang IT, dalam tiga kalimat, kenapa kantor tidak memberi hak admin permanen di laptop karyawan, padahal karyawan itu jujur.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Hak admin itu seperti kunci serep semua ruangan di rumah: berguna, tapi kalau dompet berisi kunci itu dicopet, pencurinya bisa masuk ke mana saja. Di komputer, 'pencopet' bisa berupa lampiran email jahat yang dibuka tanpa sengaja, dan lampiran itu langsung bekerja dengan semua hak pemilik akun. Jadi kantor memasangkan aplikasi yang dibutuhkan lewat tim IT, dan kunci serep hanya dipinjamkan sebentar ke petugas yang memang perlu, dengan catatan siapa meminjam."

Kesalahan yang sering muncul:
- Menjelaskan seolah-olah kantor mencurigai karyawannya, padahal tujuannya membatasi kerugian bila akun dicuri atau disusupi program jahat.
- Memakai istilah seperti least privilege, PAM, atau malware tanpa penjelasan kepada orang awam.
- Tidak menyebut jalan keluarnya (aplikasi dipasangkan tim IT), sehingga terdengar seperti larangan tanpa solusi.

</details>

**6. Pertanyaan jebakan.** "Alert FIM `SOC-2027-0837` menunjukkan siapa yang mengubah `clients.conf` dan apakah perubahannya sah, jadi analyst cukup membaca alert itu." Benarkah?

<details><summary>Jawaban</summary>

Tidak. FIM membandingkan checksum dan atribut file dengan baseline, sehingga ia tahu apa yang berubah dan kapan, dan bila pelaporan perubahan aktif, baris apa yang ditambah. FIM tidak tahu siapa pelakunya (who-data tidak aktif di contoh itu) dan tidak tahu apakah perubahan itu sah. Sari harus mencocokkannya dengan tiket `CHG-2027-0731` dan log sesi `adm.agung` di bastion. Tanpa tiket dan sesi admin yang cocok, perubahan yang sama harus dianggap kemungkinan intrusi. Lihat bagian 1.4 dan 2.4.

</details>

**7. Interview question (English).** "What is the difference between antivirus, EDR, and XDR, and where does MDR fit in?"

<details><summary>Sample answer</summary>

"Antivirus answers one question: is this file known to be malicious? It mainly uses signatures, plus machine learning and heuristics in newer products, and it acts on the file, for example by quarantining it. EDR records what happens on the endpoint (processes, command lines, file writes, network connections, logons), detects suspicious behavior chains, and gives the analyst response actions such as isolating the device. A typical example is Excel spawning a hidden PowerShell that downloads an unsigned binary and creates a scheduled task: no file signature fires, but EDR sees the pattern. XDR extends that across domains, correlating endpoint, email, identity and cloud alerts into one incident, so I can see the phishing email, the endpoint execution and the account activity together and respond across products. MDR is different in kind: it is a service, where an external team uses those tools to monitor, hunt and respond on our behalf, often around the clock. The tools only cover devices and sources that are actually onboarded, so I always check which assets have no agent."

What makes this answer strong: it separates products from services, explains each term by the question it answers, gives a concrete behavior-based example, and ends with a practical limitation (coverage gaps) that shows operational experience.

</details>

## 8. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | NIST CSRC Glossary: antivirus software | https://csrc.nist.gov/glossary/term/antivirus_software | primer (glosarium NIST) | diakses 2026-10-21 | Tinggi. Definisi dari SP 800-83 Rev. 1 |
| S2 | NIST SP 800-94: Guide to Intrusion Detection and Prevention Systems (IDPS) | https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-94.pdf | primer | 2007-02; diakses 2026-10-21 | Tinggi untuk konsep host-based IDPS, file integrity checking, dan batas antivirus berbasis signature. Dokumen lama; tidak membahas EDR |
| S3 | Microsoft Learn: Microsoft Defender for Endpoint | https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-endpoint | primer (dokumentasi vendor) | diperbarui 2026-07-28; diakses 2026-10-21 | Tinggi untuk produk Microsoft. Kemampuan, platform, dan opsi lisensi |
| S4 | Microsoft Learn: Overview of endpoint detection and response capabilities | https://learn.microsoft.com/en-us/defender-endpoint/overview-endpoint-detection-response | primer (dokumentasi vendor) | diperbarui 2026-06-02; diakses 2026-10-21 | Tinggi. Telemetri, retensi enam bulan, alert menjadi incident, tindakan manual Plan 1, catatan bahwa sensor bukan alat audit |
| S5 | Microsoft Learn: Overview of next-generation protection in Microsoft Defender for Endpoint | https://learn.microsoft.com/en-us/defender-endpoint/next-generation-protection | primer (dokumentasi vendor) | diperbarui 2026-06-02; diakses 2026-10-21 | Tinggi. Antivirus modern dengan ML, perilaku, heuristik, perlindungan cloud |
| S6 | Microsoft Security 101: What is EDR? | https://www.microsoft.com/en-us/security/business/security-101/what-is-edr-endpoint-detection-response | sekunder (materi edukasi vendor) | diakses 2026-10-21 | Sedang. Definisi umum EDR dan perbedaannya dengan antivirus; ditulis vendor EDR |
| S7 | Microsoft Learn: What is Microsoft Defender XDR? | https://learn.microsoft.com/en-us/defender-xdr/microsoft-365-defender | primer (dokumentasi vendor) | diperbarui 2026-08-07; diakses 2026-10-21 | Tinggi untuk produk Microsoft. Korelasi lintas produk, contoh penghapusan file dari email, catatan lisensi |
| S8 | Microsoft Security 101: What is managed detection and response (MDR)? | https://www.microsoft.com/en-us/security/business/security-101/what-is-mdr-managed-detection-response | sekunder (materi edukasi vendor) | diakses 2026-10-21 | Sedang. Definisi MDR, layanan umum, beda dengan EDR, XDR, MSSP, SIEM |
| S9 | CrowdStrike: What is Extended Detection and Response (XDR)? | https://www.crowdstrike.com/en-us/cybersecurity-101/endpoint-security/extended-detection-and-response-xdr/ | sekunder (materi edukasi vendor) | diakses 2026-10-21 | Sedang. Dipakai untuk definisi Gartner tentang XDR yang dikutip di halaman ini dan hubungan XDR dengan EDR |
| S10 | Wazuh documentation: File integrity monitoring | https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html | primer (dokumentasi proyek) | diakses 2026-10-21 | Tinggi untuk Wazuh. Baseline checksum, pemindaian terjadwal dan real-time, who-data |
| S11 | OSSEC: halaman utama proyek | https://www.ossec.net/ | primer (situs proyek) | diakses 2026-10-21 | Sedang-tinggi. Deskripsi diri OSSEC sebagai HIDS dengan analisis log, FIM, active response |
| S12 | Fortra: Tripwire Enterprise | https://www.fortra.com/products/tripwire-enterprise | sekunder (halaman produk vendor) | diakses 2026-10-21 | Sedang. Hanya dipakai untuk menyebut Tripwire Enterprise sebagai produk FIM dan manajemen konfigurasi |
| S13 | NIST CSRC Glossary: data loss prevention | https://csrc.nist.gov/glossary/term/data_loss_prevention | primer (glosarium NIST) | diakses 2026-10-21 | Tinggi. Definisi CNSSI 4009-2022: data in use, in motion, at rest |
| S14 | Microsoft Learn: Learn about data loss prevention (Microsoft Purview) | https://learn.microsoft.com/en-us/purview/dlp-learn-about-dlp | primer (dokumentasi vendor) | diperbarui 2026-09-16; diakses 2026-10-21 | Tinggi. Metode pengenalan isi, tindakan (policy tip, override, blokir), simulation mode |
| S15 | NIST SP 800-167: Guide to Application Whitelisting | https://csrc.nist.gov/pubs/sp/800/167/final<br>https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-167.pdf | primer | 2015-10; diakses 2026-10-21 | Tinggi. Definisi, atribut (path, nama, ukuran, signature/publisher, hash), audit vs enforcement mode |
| S16 | Microsoft Learn: Application Control for Windows | https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol | primer (dokumentasi vendor) | diperbarui 2026-10-08; diakses 2026-10-21 | Tinggi. App Control for Business dan AppLocker; bukan pengganti antivirus; cakupan script, MSI, PowerShell |
| S17 | NIST CSRC Glossary: identity and access management | https://csrc.nist.gov/glossary/term/identity_and_access_management | primer (glosarium NIST) | diakses 2026-10-21 | Tinggi. Definisi dari SP 800-175A |
| S18 | NIST SP 800-63-4: Digital Identity Guidelines; NIST CSRC Glossary: single sign-on | https://csrc.nist.gov/pubs/sp/800/63/4/final<br>https://pages.nist.gov/800-63-4/sp800-63.html<br>https://csrc.nist.gov/glossary/term/single_sign_on | primer | 2025-07; diakses 2026-10-21 | Tinggi. Digital identity, subscriber account, federation, IdP, relying party, SSO |
| S19 | NIST SP 800-63B-4: Authentication and Authenticator Management | https://csrc.nist.gov/pubs/sp/800/63/b/4/final<br>https://pages.nist.gov/800-63-4/sp800-63b.html | primer | 2025-07; diakses 2026-10-21 | Tinggi. Faktor, biometrik hanya bersama authenticator fisik, definisi phishing resistance, AAL1-3, authentication fatigue, syncable authenticator, PSTN restricted |
| S20 | NIST CSRC Glossary: multi-factor authentication | https://csrc.nist.gov/glossary/term/multi_factor_authentication | primer (glosarium NIST) | diakses 2026-10-21 | Tinggi. Definisi CNSSI 4009-2022, SP 800-171r3, SP 800-53 Rev. 5, SP 800-63-4 |
| S21 | CISA: Implementing Phishing-Resistant MFA (fact sheet) | https://www.cisa.gov/sites/default/files/publications/fact-sheet-implementing-phishing-resistant-mfa-508c.pdf | primer | 2022-10; diakses 2026-10-21 | Tinggi. Ancaman terhadap MFA (phishing, push bombing, SS7, SIM swap), urutan jenis MFA, FIDO/WebAuthn dan PKI |
| S22 | CISA: Implementing Number Matching in MFA Applications (fact sheet) | https://www.cisa.gov/sites/default/files/publications/fact-sheet-implement-number-matching-in-mfa-applications-508c.pdf | primer | 2022-10; diakses 2026-10-21 | Tinggi. Definisi MFA fatigue dan cara number matching memitigasinya |
| S23 | Microsoft Learn: How number matching works in MFA push notifications for Authenticator | https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-number-match | primer (dokumentasi vendor) | diperbarui 2026-02-13; diakses 2026-10-21 | Tinggi. Number matching aktif untuk semua push Authenticator, tidak bisa dimatikan pengguna |
| S24 | Microsoft Learn: Overview of Conditional Access authentication strengths | https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths | primer (dokumentasi vendor) | diperbarui 2026-06-26; diakses 2026-10-21 | Tinggi. Kategori Phishing-resistant MFA (Windows Hello for Business, FIDO2, CBA multifaktor); Conditional Access butuh Entra ID P1 |
| S25 | FIDO Alliance: Passkeys | https://fidoalliance.org/passkeys/ | primer (badan standar) | diakses 2026-10-21 | Tinggi. Definisi passkey, synced vs device-bound, keterikatan ke situs |
| S26 | NIST CSRC Glossary: role-based access control | https://csrc.nist.gov/glossary/term/role_based_access_control | primer (glosarium NIST) | diakses 2026-10-21 | Tinggi. Definisi SP 800-95 dan SP 800-53 Rev. 5 |
| S27 | Microsoft Learn: What is Microsoft Entra Privileged Identity Management? | https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-configure | primer (dokumentasi vendor) | diperbarui 2026-04-24; diakses 2026-10-21 | Tinggi untuk produk Microsoft. Just-in-time, time-bound, persetujuan, MFA saat aktivasi, eligible vs active, butuh lisensi |

**Catatan sumber:** definisi Gartner untuk XDR diambil dari kutipan di halaman vendor [S9], bukan dari publikasi Gartner langsung, dan definisi MDR serta perbedaannya dengan MSSP bersumber dari materi edukasi Microsoft [S8]; kedua sumber ditulis vendor yang menjual produk sejenis. Definisi PAM dan daftar unsurnya (akun terpisah, vault, jump host, rekaman sesi) disusun catatan ini dari praktik umum; entri PAM di glosarium NIST hanya memuat singkatan tanpa definisi, dan contoh fitur just-in-time diambil dari dokumentasi Microsoft PIM [S27]. Deskripsi HIPS dan pernyataan bahwa CrowdStrike Falcon lebih tepat disebut EDR daripada HIPS klasik adalah pembedaan fungsi yang dipakai catatan ini, bukan definisi dari satu sumber resmi. Pernyataan bahwa Wazuh berasal dari garis OSSEC tidak diambil dari halaman yang dirujuk; cek di dokumentasi atau riwayat proyek Wazuh bila dibutuhkan untuk dokumen formal. Nomor aturan Wazuh 550 di bagian 2.4 perlu dicek di versi Wazuh yang dipakai. Seluruh isi PT JAB (alert `SOC-2027-0833` sampai `SOC-2027-0837`, insiden `INC-2027-085`, nama karyawan, host, IP, tiket `CHG-2027-0731`, peran SOC, dan kebijakan DLP) adalah contoh fiktif.
