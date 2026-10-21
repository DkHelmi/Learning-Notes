---
day: 08
title: 'Cloud security dasar: IaaS/PaaS/SaaS, shared responsibility, cloud IAM, misconfiguration, CSPM, CASB, CWPP, dan log cloud'
researched_on: 2026-10-21
versions_checked: 'NIST SP 800-145 (Sep 2011, final); AWS Shared Responsibility Model (diakses 2026-10-21); Microsoft Learn Shared responsibility in the cloud (diperbarui 2026-08-24); AWS IAM User Guide (roles, policies, evaluation logic, identifiers, best practices; diakses 2026-10-21); Amazon S3 User Guide (Block Public Access, CloudTrail events); AWS CloudTrail User Guide (format event 1.11); Azure Monitor Activity Log (diperbarui 2026-05-04); Azure RBAC overview; Microsoft Defender for Cloud overview (2026-08-10); Microsoft Defender for Cloud Apps overview; Microsoft Entra new name (2025-05-07); CSA Top Threats to Cloud Computing 2024; NSA dan CISA cloud security information sheets (Maret 2024)'
---

# Day 08: Cloud security dasar (IaaS/PaaS/SaaS, shared responsibility, cloud IAM, misconfiguration, CSPM, CASB, CWPP, dan log cloud)

Cakupan: istilah dasar keamanan cloud, yaitu definisi cloud computing dan region, tiga model layanan IaaS, PaaS, dan SaaS, pembagian tanggung jawab antara penyedia dan pelanggan, cloud IAM (role, policy, access key, dan kredensial sementara), misconfiguration dengan contoh bucket publik, tiga jenis alat keamanan cloud (CSPM, CASB, CWPP), serta log cloud seperti AWS CloudTrail dan Azure Activity Log, masing-masing pada level konsep.

## Ide inti

Cloud berarti memakai komputer, penyimpanan, dan aplikasi milik perusahaan lain lewat internet, lalu membayar sesuai pemakaian. Begitu sebuah organisasi pindah ke cloud, keamanan tidak hilang dan tidak sepenuhnya pindah ke penyedia. Keamanan dibagi dua. Penyedia menjaga gedung, mesin, dan jaringan fisiknya; pelanggan tetap menjaga datanya, akun-akunnya, dan pengaturan setiap layanan yang ia pakai. Pembagian ini disebut shared responsibility model, dan hampir semua istilah lain di Day ini berputar di sekitarnya.

Dari pembagian itu lahir dua kebiasaan penting untuk analyst. Pertama, di cloud hampir semua pintu dibuka dan ditutup lewat pengaturan, bukan lewat kabel. Satu klik atau satu baris pengaturan bisa membuat data perusahaan terbuka untuk seluruh internet, sehingga penyebab insiden cloud yang paling sering adalah salah konfigurasi (misconfiguration) dan kredensial yang bocor, bukan jebolnya pusat data penyedia [S20]. Kedua, karena semua perubahan dilakukan lewat permintaan ke layanan penyedia, setiap perubahan bisa tercatat di log cloud, asalkan log itu dinyalakan, disimpan cukup lama, dan dikirim ke SOC. Alat seperti CSPM memeriksa pengaturan, CASB mengawasi pemakaian aplikasi cloud oleh karyawan, CWPP menjaga server dan container yang berjalan di cloud, dan log seperti CloudTrail menjawab siapa mengubah apa.

Bayangkan tiga cara punya tempat tinggal. Kamu bisa menyewa tanah kosong lalu membangun rumah sendiri: pemilik tanah hanya menjamin tanahnya, sisanya urusanmu (IaaS). Kamu bisa menyewa apartemen berperabot: gedung, lift, dan perabot disediakan, kamu tinggal mengisi barang dan mengatur siapa yang boleh masuk (PaaS). Atau kamu menginap di hotel: semuanya disediakan, kamu hanya membawa barang pribadi dan menjaga kunci kamarmu (SaaS). Di semua pilihan, pengelola gedung menjaga gedung, tetapi penyewa tetap mengunci pintu unitnya sendiri. Bucket penyimpanan yang dibuka untuk publik ibarat lemari arsip yang ditaruh di lobi tanpa kunci, dan CloudTrail ibarat buku tamu sekaligus rekaman CCTV gedung cloud. Batas analogi ini perlu diingat sejak awal: di cloud, "pintu unit" bisa dibuka dari jarak jauh oleh siapa saja yang memegang kunci digital yang sah, tidak ada satpam yang melihat wajah orang itu, dan lemari di lobi bisa ditemukan program pemindai otomatis dalam hitungan jam, bukan oleh tamu yang kebetulan lewat.

```
                    On-premises   IaaS        PaaS        SaaS
                    (milik sendiri)(tanah)    (apartemen) (hotel)
Data dan isi        PELANGGAN     PELANGGAN   PELANGGAN   PELANGGAN
Akun dan identitas  PELANGGAN     PELANGGAN   PELANGGAN   PELANGGAN
Pengaturan layanan  PELANGGAN     PELANGGAN   PELANGGAN   PELANGGAN
Aplikasi            PELANGGAN     PELANGGAN   bersama     bersama
Kontrol jaringan    PELANGGAN     PELANGGAN   bersama     penyedia
Sistem operasi      PELANGGAN     PELANGGAN   penyedia    penyedia
Server fisik        PELANGGAN     penyedia    penyedia    penyedia
Jaringan fisik      PELANGGAN     penyedia    penyedia    penyedia
Gedung data center  PELANGGAN     penyedia    penyedia    penyedia

Tiga baris teratas TIDAK PERNAH pindah ke penyedia.
Di situlah misconfiguration, kredensial bocor, dan data terbuka terjadi.
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), sebuah ISP (penyedia layanan internet) fiktif dengan sekitar 1.200 karyawan dan sekitar 400 ribu pelanggan internet rumah. Selain server di data center Jakarta, PT JAB memakai tiga layanan cloud: Amazon Web Services (AWS) untuk backend aplikasi self-care pelanggan "MyJAB" di region Jakarta (`ap-southeast-3`), satu subscription Microsoft Azure bernama `JAB-Azure-Prod`, dan Microsoft 365 untuk email dan dokumen karyawan. Tahun lalu PT JAB pernah mengalami insiden `INC-2026-025`: access key AWS milik seorang developer tertinggal di repo GitHub publik, lalu dipakai pihak luar untuk menjalankan cryptocurrency miner dan mengambil data ekspor. Kamu adalah analyst L1 (lini pertama yang memeriksa setiap alert) yang baru bergabung di SOC (Security Operations Center) PT JAB. Rabu 2027-08-11, hari kedelapan orientasi, pukul 09:15, mentormu Sari Kusuma (analyst L2) mengajakmu ke ruang rapat. Di sana sudah ada Lutfi Hakim, Lead DevOps yang mengelola MyJAB di AWS. Di layar terbuka alert `SOC-2027-0843` dari alat pemeriksa konfigurasi cloud: sebuah bucket penyimpanan baru di akun AWS MyJAB bisa dibaca siapa pun di internet.

Lutfi membuka percakapan:

> "Bucket itu dibuat tim web kemarin sore untuk gambar promo MyJAB, memang mau dibuka biar aplikasi bisa ambil gambarnya. Lagian AWS kan yang jaga keamanannya, mereka punya tim ribuan orang. Kenapa SOC sampai bikin alert High?"

Sari lalu menoleh ke arahmu:

> "Pertanyaan Mas Lutfi bagus untuk orientasi. Coba kamu jawab bertahap. Sebenarnya cloud itu apa, dan kenapa ada kode `ap-southeast-3`? AWS, Azure, dan Microsoft 365 yang kita pakai itu jenis layanannya sama atau beda? Kalau AWS yang jaga, siapa sebenarnya yang bertanggung jawab atas bucket ini? Bagaimana seorang developer bisa membuka bucket ke publik, izin apa yang dia pakai? Kenapa kami selalu minta tim DevOps pakai role, bukan access key, setelah kejadian tahun lalu? Kenapa salah setting seperti ini disebut penyebab insiden cloud paling umum? Alert ini datang dari CSPM; apa bedanya dengan CASB dan CWPP yang juga sedang kami uji? Terakhir, log apa yang kita buka untuk tahu siapa yang mengubah setting, dan apakah kita bisa tahu siapa yang sudah mengunduh isinya?"

Percakapan itu memuat delapan pertanyaan:

1. Apa itu cloud computing, dan apa arti region seperti `ap-southeast-3`?
2. Apa beda IaaS, PaaS, dan SaaS, dan PT JAB memakai yang mana di AWS, Azure, dan Microsoft 365?
3. Siapa yang bertanggung jawab atas bucket ini bila AWS "yang menjaga"?
4. Bagaimana developer bisa membuka bucket ke publik: izin apa, diberikan lewat apa?
5. Kenapa role dengan kredensial sementara lebih aman daripada access key?
6. Kenapa misconfiguration disebut penyebab insiden cloud paling umum, dan apa itu bucket publik?
7. Apa itu CSPM, dan bedanya dengan CASB dan CWPP?
8. Log apa yang dibuka untuk tahu siapa mengubah setting, dan apakah bisa diketahui siapa yang mengunduh isinya?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, pertanyaan 6 di bagian 1.6, pertanyaan 7 di bagian 1.7, 1.8, dan 1.9, dan pertanyaan 8 di bagian 1.10. Bagian 2 membedah alert `SOC-2027-0843`, membaca log CloudTrail di baliknya, lalu memperlihatkan dua alert cloud lain dari Azure dan dari CASB.

**Kapan relevan:** setiap kali alert, insiden, atau pertanyaan menyangkut layanan yang tidak berjalan di data center sendiri: akun AWS atau Azure, Microsoft 365, aplikasi SaaS yang dipakai karyawan, access key yang bocor, atau data yang ternyata terbuka di internet. Istilah ini juga muncul di hampir setiap interview SOC karena hampir semua perusahaan sudah memakai cloud.
**Kapan bukan jawaban:** istilah Day ini tidak menjelaskan cara mengonfigurasi layanan cloud tertentu langkah demi langkah, dan tidak menggantikan prosedur respons insiden. Shared responsibility juga bukan alat untuk menyalahkan pihak lain saat insiden; yang dibutuhkan saat itu adalah menutup paparan, mengamankan kredensial, dan mengumpulkan log, lalu baru membahas siapa yang seharusnya mencegah.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day 01 dan Day 02 (CIA triad, control, least privilege, attack surface, IP publik, HTTPS) tidak diulang di tabel ini; definisinya diulang satu kalimat di tempat bila dibutuhkan. Tabel ini memuat semua istilah cloud yang dipakai Day ini; cari kolom ketiga bila sebuah istilah terasa abstrak.

| Istilah | Arti singkat | Padanan sehari-hari |
|---|---|---|
| Cloud computing | Memakai sumber daya komputasi milik penyedia lewat jaringan, sesuai kebutuhan, bayar sesuai pemakaian | Menyewa tempat tinggal alih-alih membangun dan merawat semuanya sendiri |
| Cloud service provider (CSP) | Perusahaan penyedia layanan cloud, misalnya AWS, Microsoft Azure, Google Cloud | Pengelola gedung atau pemilik hotel |
| API | Pintu teknis tempat program mengirim perintah ke layanan, misalnya "buat bucket" | Formulir permintaan resmi ke pengelola gedung |
| Console | Halaman web untuk mengelola layanan cloud dengan klik | Loket layanan pengelola gedung |
| Region | Lokasi geografis berisi beberapa data center penyedia, misalnya `ap-southeast-3` (Jakarta) | Cabang jaringan hotel di satu kota |
| Availability Zone (AZ) | Satu atau beberapa data center terpisah di dalam satu region | Gedung-gedung terpisah milik cabang yang sama |
| IaaS | Infrastructure as a Service: sewa server virtual, penyimpanan, dan jaringan | Sewa tanah kosong, bangun rumah sendiri |
| PaaS | Platform as a Service: sewa platform siap pakai untuk menjalankan aplikasi | Sewa apartemen berperabot |
| SaaS | Software as a Service: pakai aplikasi jadi lewat browser | Menginap di hotel |
| Shared responsibility model | Pembagian tugas keamanan antara penyedia dan pelanggan | Pengelola gedung menjaga gedung, penyewa mengunci unitnya |
| Cloud IAM | Sistem pengatur identitas dan izin di dalam akun cloud | Kantor pengelola kartu akses gedung |
| Principal | Pihak yang mengirim permintaan: user, role, atau layanan | Orang yang menempelkan kartu di pintu |
| Policy | Dokumen berisi izin: siapa boleh melakukan apa ke sumber daya mana | Daftar pintu yang tertulis di kartu akses |
| Role | Identitas berisi izin tertentu yang bisa "dipinjam" sementara | Kartu akses tamu harian sesuai tugas |
| Access key | Pasangan ID dan secret untuk akses program ke cloud, berlaku sampai dicabut | Kunci duplikat permanen |
| Kredensial sementara | Kunci yang otomatis kedaluwarsa setelah waktu tertentu | Kartu tamu yang mati sendiri di akhir hari |
| Bucket | Wadah penyimpanan file (object) di layanan seperti Amazon S3 | Lemari arsip |
| Bucket policy | Policy yang ditempel langsung ke bucket | Tulisan di pintu lemari: siapa boleh membuka |
| Block Public Access | Pengaturan S3 yang memblokir semua cara membuat bucket menjadi publik | Gembok induk yang mencegah lemari dipindah ke lobi |
| Misconfiguration | Pengaturan layanan yang salah sehingga membuka celah | Pintu unit yang lupa dikunci |
| Control plane / data plane | Perintah mengelola sumber daya / perintah memakai isi sumber daya | Mengubah denah gedung / mengambil barang dari lemari |
| CSPM | Cloud Security Posture Management: pemeriksa konfigurasi cloud | Inspektur gedung yang berkeliling memeriksa kunci tiap unit |
| CASB | Cloud Access Security Broker: pengawas pemakaian aplikasi cloud oleh karyawan | Petugas yang mencatat dokumen kantor dibawa ke layanan luar mana |
| Shadow IT | Aplikasi atau layanan yang dipakai karyawan tanpa izin TI | Gudang sewaan pribadi yang tidak diketahui kantor |
| CWPP | Cloud Workload Protection Platform: pelindung server, container, dan fungsi di cloud | Satpam yang berpatroli di dalam unit |
| Workload | Apa yang dijalankan di cloud: VM, container, fungsi serverless | Penghuni dan aktivitas di dalam unit |
| CNAPP | Cloud-Native Application Protection Platform: paket gabungan CSPM, CWPP, dan pemeriksaan kode | Satu perusahaan keamanan yang memegang inspeksi dan patroli sekaligus |
| CloudTrail | Layanan log AWS yang mencatat aktivitas akun | Buku tamu dan rekaman CCTV gedung cloud |
| Azure Activity Log | Log Azure yang mencatat operasi pengelolaan sumber daya | Buku tamu gedung kedua |
| Azure RBAC | Sistem izin Azure berbasis role, diberikan pada scope tertentu | Kartu akses yang berlaku untuk satu lantai atau seluruh gedung |
| Microsoft Entra ID | Layanan identitas cloud Microsoft (dulu Azure AD), sumber login untuk Microsoft 365, Azure, dan aplikasi lain | Kantor pusat penerbit kartu karyawan untuk semua gedung |

### 1.1 Cloud computing dan region

Pertanyaan pertama Sari terdengar sederhana, tetapi jawabannya menentukan cara berpikir untuk sisa Day ini: apa yang sebenarnya disewa PT JAB, dan di mana barang itu berada.

**Apa itu:** cloud computing adalah model yang memungkinkan akses lewat jaringan, kapan saja dan sesuai kebutuhan, ke kumpulan sumber daya komputasi yang bisa diatur (jaringan, server, penyimpanan, aplikasi, layanan), yang bisa disediakan dan dilepas dengan cepat dan dengan sedikit campur tangan penyedia [S1]. Definisi resmi ini berasal dari NIST SP 800-145. Region adalah lokasi geografis tempat penyedia menaruh sekumpulan data center. Di AWS, region Jakarta berkode `ap-southeast-3` dan memiliki tiga Availability Zone, yaitu kelompok data center terpisah di dalam region yang sama [S23].

**Analogi:** menyewa tempat tinggal alih-alih membangun dan merawat rumah sendiri. Kamu bisa pindah ke unit yang lebih besar besok pagi, membayar sesuai lama tinggal, dan tidak perlu memikirkan genset gedung. Region seperti cabang jaringan hotel di satu kota; kamu memilih menginap di cabang Jakarta atau Singapura. Batasnya: unit di gedung yang sama dipakai banyak penyewa lain, dan kamu tidak bisa masuk ke ruang mesin gedung untuk memeriksa sendiri.

**Cara kerja:** NIST menyebut lima ciri pokok yang membedakan cloud dari "server di tempat orang lain" biasa [S1]:

| Ciri | Artinya dengan bahasa sederhana | Akibat untuk keamanan |
|---|---|---|
| On-demand self-service | Pelanggan menyalakan server atau penyimpanan sendiri tanpa menelepon penyedia | Siapa pun yang punya izin bisa membuat sumber daya baru dalam hitungan detik, termasuk yang salah setting |
| Broad network access | Layanan diakses lewat jaringan dari laptop, HP, atau program | Console dan API bisa dicoba dari mana saja di internet, jadi kredensial menjadi pintu utama |
| Resource pooling | Sumber daya penyedia dipakai bersama banyak pelanggan (multi-tenant); pelanggan biasanya hanya memilih lokasi tingkat tinggi seperti negara atau region | Pemisahan antar pelanggan adalah tugas penyedia; pemilihan region adalah keputusan pelanggan |
| Rapid elasticity | Kapasitas bisa ditambah atau dikurangi dengan cepat, sering otomatis | Penyerang yang memegang kredensial juga bisa menyalakan ratusan server, misalnya untuk miner |
| Measured service | Pemakaian diukur dan ditagih | Lonjakan tagihan sering menjadi tanda pertama penyalahgunaan |

NIST juga membedakan empat model penempatan (deployment model): private cloud (dipakai satu organisasi saja), community cloud (dipakai komunitas organisasi dengan kebutuhan sama), public cloud (terbuka untuk umum, berada di tempat penyedia), dan hybrid cloud (gabungan dua atau lebih model yang tetap terpisah tetapi bisa saling memindahkan data dan aplikasi) [S1]. AWS, Azure, dan Microsoft 365 yang dipakai PT JAB adalah public cloud; bila digabung dengan data center Jakarta, keseluruhannya sering disebut hybrid.

Semua pengelolaan cloud dilakukan lewat API, yaitu pintu teknis tempat program atau console mengirim perintah ke layanan ("buat bucket", "ubah izin"). Klik di console pun di belakangnya menjadi panggilan API. Karena itu log cloud bisa mencatat hampir setiap perubahan (bagian 1.10).

**Contoh di PT JAB:** backend MyJAB berjalan di region `ap-southeast-3` supaya dekat dengan pelanggan di Indonesia. Region ini termasuk region yang harus diaktifkan dulu oleh pemilik akun sebelum bisa dipakai (opt-in), berbeda dengan region lama yang aktif sejak awal [S23]. Bagi SOC, kode region muncul di setiap baris log AWS. Aktivitas di region yang tidak pernah dipakai PT JAB, misalnya pembuatan puluhan server (event `RunInstances` di log AWS) di region yang jauh, adalah tanda kuat penyalahgunaan; pola ini pula yang terlihat pada `INC-2026-025`.

**Beda dengan hosting atau colocation biasa:** menitipkan server sendiri di data center pihak lain (colocation) atau menyewa satu server fisik bulanan belum memenuhi ciri self-service, elastisitas cepat, dan pengukuran pemakaian. Pada colocation, kamu masih memiliki dan merawat mesinnya.

**Salah paham umum:**
- "Memilih region Jakarta berarti semua yang berhubungan dengan akun itu ada di Jakarta." Sebagian layanan bersifat global. Contohnya IAM di AWS: identitas dan izinnya berlaku di semua region, sehingga alamat sumber daya IAM tidak memuat nama region [S8]. Pemilihan region mengatur lokasi sumber daya yang memang regional, seperti server dan bucket.

### 1.2 IaaS, PaaS, SaaS

Pertanyaan kedua Sari membandingkan tiga layanan yang dipakai PT JAB. Ketiganya sama-sama "cloud", tetapi yang disewa dan yang harus dijaga sendiri berbeda jauh.

**Apa itu:** NIST mendefinisikan tiga model layanan [S1]:
- **IaaS (Infrastructure as a Service):** pelanggan menyewa sumber daya dasar seperti pemrosesan, penyimpanan, dan jaringan, lalu bebas memasang sistem operasi dan aplikasi apa pun. Pelanggan tidak mengelola infrastruktur fisik, tetapi mengendalikan sistem operasi, penyimpanan, aplikasi, dan sebagian komponen jaringan seperti firewall di host.
- **PaaS (Platform as a Service):** pelanggan memasang aplikasi buatannya di atas platform penyedia (bahasa pemrograman, pustaka, layanan, dan alat yang didukung penyedia). Pelanggan tidak mengelola server dan sistem operasi, tetapi mengendalikan aplikasinya dan pengaturan lingkungan tempat aplikasi berjalan.
- **SaaS (Software as a Service):** pelanggan memakai aplikasi jadi milik penyedia, biasanya lewat browser. Pelanggan tidak mengelola apa pun di bawah aplikasi, kecuali pengaturan aplikasi yang terbatas untuk penggunanya.

Microsoft memberi contoh di ekosistemnya: Azure Virtual Machines dan virtual network adalah IaaS; Azure App Service, Azure Functions, Azure SQL Database, dan Azure Storage adalah PaaS; Microsoft 365 adalah SaaS [S3].

**Analogi:** tanah kosong, apartemen berperabot, dan hotel. Di tanah kosong (IaaS) kamu membangun rumah, memasang pintu, mengecat, dan memperbaiki atap sendiri. Di apartemen berperabot (PaaS) kamu tinggal masuk dan menata barang; pipa dan lift diurus pengelola. Di hotel (SaaS) kamu hanya membawa koper dan menjaga kunci kamar. Alternatif yang sering dipakai di buku: pizza as a service, yaitu membuat pizza sendiri di rumah, membeli pizza beku lalu memanggangnya, atau memesan pizza diantar. Batasnya: di hotel sungguhan kamu tidak bisa mengubah pengaturan kamar yang membuat pintunya terbuka untuk semua orang, sedangkan di SaaS kamu bisa, misalnya dengan membagikan folder ke "siapa saja yang punya tautan". Pengaturan semacam itu tetap tanggung jawab pelanggan.

**Cara kerja:** semakin ke kanan (IaaS ke SaaS), semakin banyak lapisan yang diurus penyedia, dan semakin sedikit yang bisa kamu atur sendiri. Konsekuensinya untuk SOC juga bergeser:

| Model | Contoh | Yang paling sering salah di sisi pelanggan | Log yang paling berguna untuk SOC |
|---|---|---|---|
| IaaS | Amazon EC2, Azure Virtual Machines | Sistem operasi belum di-patch, port pengelolaan terbuka ke internet, kunci akses disimpan di server | Log sistem operasi dan EDR di VM, log jaringan cloud, log aktivitas akun |
| PaaS | Amazon S3, AWS Lambda, Azure App Service, Azure SQL Database | Pengaturan akses (bucket publik, database terbuka), izin role terlalu luas | Log aktivitas akun (CloudTrail, Activity Log), log akses data bila dinyalakan |
| SaaS | Microsoft 365, aplikasi CRM, file sharing | Akun tanpa MFA, berbagi file ke publik, aplikasi pihak ketiga diberi izin berlebihan | Log sign-in dan audit aplikasi, CASB |

S3 sebenarnya layanan penyimpanan yang diabstraksi: AWS menjalankan infrastruktur, sistem operasi, dan platformnya, sementara pelanggan hanya mengelola data dan izinnya [S2]. Karena itu S3 lebih dekat ke PaaS daripada IaaS, walaupun banyak orang memasukkannya ke "infrastruktur".

**Contoh di PT JAB:** tabel berikut memetakan tiga layanan cloud PT JAB; cari kolom "Kunci unit yang dipegang PT JAB" untuk melihat apa yang tetap harus dijaga sendiri.

| Layanan | Model | Dipakai untuk | Kunci unit yang dipegang PT JAB |
|---|---|---|---|
| AWS akun MyJAB (`ap-southeast-3`) | Campuran IaaS dan PaaS | Server API MyJAB di EC2 (IaaS), gambar dan file di S3 (PaaS), fungsi kecil di Lambda (PaaS) | Patch server EC2, izin IAM, pengaturan bucket, log |
| Azure `JAB-Azure-Prod` | Campuran IaaS dan PaaS | Server cadangan beberapa aplikasi internal, storage account untuk backup | Patch VM, role assignment, pengaturan storage, log |
| Microsoft 365 | SaaS | Email, OneDrive, SharePoint, Teams | Akun dan MFA, pengaturan berbagi file, aplikasi pihak ketiga yang diizinkan |

**Beda dengan deployment model:** IaaS, PaaS, dan SaaS menjawab "apa yang disewa". Public, private, community, dan hybrid menjawab "siapa yang memakai infrastrukturnya bersama" (bagian 1.1). Sebuah layanan bisa SaaS dan public cloud sekaligus, seperti Microsoft 365.

**Salah paham umum:**
- "SaaS berarti tidak ada yang perlu dikonfigurasi." Microsoft menegaskan bahwa data, konfigurasi dan pengaturan, serta identitas dan pengguna tetap tanggung jawab pelanggan di semua model, termasuk SaaS [S3].

### 1.3 Shared responsibility model

Kalimat Lutfi ("AWS kan yang jaga keamanannya") adalah pertanyaan ketiga dalam bentuk anggapan. Separuhnya benar: AWS memang menjaga banyak hal. Separuh lainnya justru tempat alert `SOC-2027-0843` berada.

**Apa itu:** shared responsibility model adalah pembagian tugas keamanan dan kepatuhan antara penyedia cloud dan pelanggan. AWS merumuskannya sebagai keamanan "of the cloud" (dari cloud) yang menjadi tugas AWS, dan keamanan "in the cloud" (di dalam cloud) yang menjadi tugas pelanggan [S2]. AWS melindungi perangkat keras, perangkat lunak, jaringan, dan fasilitas yang menjalankan layanannya, termasuk kontrol fisik dan lingkungan; pelanggan mengelola datanya, mengklasifikasikan asetnya, memilih enkripsi, dan mengatur izin dengan IAM [S2]. Microsoft memakai pembagian yang sama dan menegaskan bahwa di semua model, pelanggan memiliki dan melindungi data dan identitasnya [S3].

**Analogi:** penyewa apartemen dan pengelola gedung. Pengelola menjaga gerbang, lift, listrik, pemadam kebakaran, dan dinding gedung. Penyewa mengunci pintu unitnya sendiri, memilih siapa yang diberi kunci duplikat, dan tidak menaruh barang berharga di lorong. Bila pencuri masuk karena penyewa meninggalkan pintu terbuka, pengelola tidak bisa disalahkan. Batasnya: di dunia nyata pembagian ini tertulis di kontrak sewa yang jelas; di cloud, garis pembagiannya bergeser untuk setiap layanan yang dipakai, sehingga satu perusahaan bisa punya puluhan garis berbeda sekaligus.

**Cara kerja:** garis pembagian bergeser mengikuti model layanan. Ringkasan dari matriks Microsoft [S3]:

| Area tanggung jawab | IaaS | PaaS | SaaS |
|---|---|---|---|
| Data pelanggan | Pelanggan | Pelanggan | Pelanggan |
| Konfigurasi dan pengaturan | Pelanggan | Pelanggan | Pelanggan |
| Identitas dan pengguna | Pelanggan | Pelanggan | Pelanggan |
| Perangkat klien (laptop, HP) | Pelanggan | Pelanggan | Bersama |
| Aplikasi | Pelanggan | Bersama | Bersama |
| Kontrol jaringan | Pelanggan | Bersama | Penyedia |
| Sistem operasi | Pelanggan | Penyedia | Penyedia |
| Host, jaringan, dan data center fisik | Penyedia | Penyedia | Penyedia |

Ada juga kontrol yang dikerjakan kedua pihak tetapi di wilayah masing-masing. AWS menyebut contohnya: patch (AWS menambal infrastruktur, pelanggan menambal sistem operasi tamu dan aplikasinya), manajemen konfigurasi (AWS mengatur perangkat infrastrukturnya, pelanggan mengatur sistem operasi, database, dan aplikasinya), serta pelatihan (masing-masing melatih karyawannya sendiri) [S2]. Untuk layanan IaaS seperti EC2, AWS menyebut pelanggan harus melakukan semua konfigurasi keamanan yang diperlukan, termasuk patch sistem operasi tamu dan pengaturan security group (aturan firewall bawaan EC2) [S2].

NSA, bersama CISA, menempatkan "menjunjung shared responsibility model" sebagai strategi pertama dari sepuluh strategi mitigasi keamanan cloud yang diterbitkan Maret 2024 [S22]. Urutan itu masuk akal: strategi lain (IAM, manajemen kunci, keamanan data, log) baru bisa dijalankan bila pelanggan tahu bagian mana yang menjadi tugasnya.

**Contoh di PT JAB:** untuk bucket di alert `SOC-2027-0843`, pembagiannya jelas.

| Hal | Siapa | Alasan |
|---|---|---|
| Disk fisik tempat file tersimpan tidak dicuri dari data center | AWS | Keamanan fisik "of the cloud" |
| Layanan S3 tidak bocor ke pelanggan AWS lain | AWS | Pemisahan antar pelanggan adalah bagian infrastruktur |
| Bucket hanya bisa dibaca pihak yang berhak | PT JAB | Pengaturan akses dan data adalah "in the cloud" |
| File yang seharusnya tidak ada di bucket itu | PT JAB | Klasifikasi data adalah tugas pelanggan |
| Pencatatan siapa membaca file di bucket | PT JAB | Log akses data harus dinyalakan pelanggan (bagian 1.10) |

Jawaban untuk Lutfi: AWS menjaga gedungnya dengan sangat baik, tetapi pintu bucket dibuka oleh akun PT JAB sendiri, sehingga konsekuensinya sepenuhnya di sisi PT JAB.

**Beda dengan outsourcing keamanan:** memakai layanan keamanan terkelola (misalnya SOC pihak ketiga) memindahkan pekerjaan, bukan tanggung jawab. Shared responsibility berbeda: ia membagi wilayah. Wilayah pelanggan tetap milik pelanggan walaupun pekerjaannya diserahkan ke vendor.

**Salah paham umum:**
- "Cloud lebih aman daripada data center sendiri, jadi tidak perlu khawatir." Microsoft memang mencatat bahwa cloud bisa menutup banyak tanggung jawab yang sering terabaikan di data center sendiri, seperti keamanan fisik dan perangkat yang sudah tua [S3]. Tetapi tiga baris teratas (data, konfigurasi, identitas) tidak pernah berpindah, dan justru di situlah insiden cloud paling sering terjadi.

### 1.4 Cloud IAM: principal, role, dan policy

Pertanyaan keempat Sari mencari tahu bagaimana seorang developer bisa membuka bucket ke publik. Jawabannya ada di cloud IAM, sistem yang mengatur siapa boleh melakukan apa di dalam akun cloud.

IAM (identity and access management) secara umum adalah pengelolaan identitas dan hak akses, yang dibahas di Day 06; Day itu juga membahas RBAC, yaitu pemberian hak berdasarkan peran pekerjaan. Di Day ini cukup diingat bahwa authentication menjawab "kamu siapa" dan authorization menjawab "boleh apa" (Day 01 bagian 1.2). Cloud IAM adalah IAM khusus di dalam akun cloud, dan fokusnya hampir seluruhnya pada authorization.

**Apa itu:** di AWS, setiap permintaan dikirim oleh principal, yaitu pihak yang bisa melakukan aksi: root user (pemilik akun), IAM user, atau role, dan juga layanan AWS [S4]. Izin diatur dengan policy, yaitu objek yang bila ditempelkan ke identitas atau sumber daya menentukan izinnya; sebagian besar policy berbentuk dokumen JSON [S5]. Role adalah identitas di dalam akun yang punya izin tertentu, mirip IAM user, tetapi tidak melekat ke satu orang dan tidak punya password atau access key permanen. Siapa pun yang diizinkan bisa "memakai" (assume) role itu dan mendapat kredensial sementara untuk sesinya [S4].

**Analogi:** kantor pengelola kartu akses gedung. Policy adalah daftar pintu yang tertulis di kartu ("boleh membuka lantai 3 dan ruang arsip B, hanya jam kerja"). Role adalah kartu tamu harian sesuai tugas, misalnya "kartu teknisi lift", yang boleh dipinjam teknisi mana pun yang terdaftar dan dikembalikan sore hari. Batasnya: di gedung, satpam bisa melihat orang yang memegang kartu; di cloud, siapa pun yang memegang kartu yang sah dianggap pemiliknya, dari mana pun ia mengirim permintaan.

**Cara kerja:** satu pernyataan (statement) policy di AWS terdiri dari beberapa elemen [S5]:

| Elemen | Pertanyaan yang dijawab | Contoh |
|---|---|---|
| `Effect` | Mengizinkan atau menolak? | `Allow` atau `Deny` |
| `Principal` | Untuk siapa? (hanya di policy yang ditempel ke sumber daya) | Satu role, satu akun, atau `"*"` yang berarti siapa saja |
| `Action` | Boleh melakukan apa? | `s3:GetObject` (membaca file di S3) |
| `Resource` | Terhadap sumber daya mana? | `arn:aws:s3:::nama-bucket/*` (semua file di bucket itu) |
| `Condition` | Dalam keadaan apa saja? | Hanya bila login memakai MFA, hanya dari jaringan tertentu |

Ada dua tempat policy biasa ditempel. Identity-based policy ditempel ke user, group, atau role dan menentukan apa yang boleh dilakukan identitas itu. Resource-based policy ditempel ke sumber daya, dan contoh paling umumnya adalah bucket policy di S3 serta trust policy di role [S5]. Trust policy menentukan siapa yang boleh memakai sebuah role; permissions policy menentukan apa yang boleh dilakukan setelah role dipakai [S4].

Aturan penilaiannya penting untuk dipahami. Bila tidak ada policy yang mengizinkan, permintaan ditolak secara bawaan. Bila policy identitas atau policy sumber daya mengizinkan, permintaan diizinkan. Bila ada satu `Deny` yang eksplisit di policy mana pun, `Deny` itu mengalahkan semua `Allow` [S6]. Selain itu, ACL (access control list) adalah jenis izin lama di S3 yang tidak memakai format JSON [S5]; kamu akan menemuinya di dokumentasi lama.

```
permintaan masuk: "role X ingin s3:PutBucketPolicy ke bucket Y"
   |
   +-- ada Deny eksplisit yang cocok?          ya  -> DITOLAK
   |        tidak
   +-- ada Allow di policy role atau bucket?   tidak -> DITOLAK (bawaan)
   |        ya
   +-- ada pembatas lain (mis. Block Public Access) yang menolak?  ya -> DITOLAK
            tidak
            -> DIIZINKAN, lalu dicatat di CloudTrail
```

Azure memakai sistem yang mirip dengan nama berbeda. Azure RBAC memberikan akses lewat role assignment yang terdiri dari tiga unsur: security principal (user, group, service principal, atau managed identity), role definition (kumpulan izin, misalnya Owner, Contributor, Reader, atau role khusus), dan scope (management group, subscription, resource group, atau satu resource) [S15]. Scope mengikuti hubungan induk dan anak: role yang diberikan di tingkat subscription berlaku untuk semua resource di bawahnya [S15].

**Contoh di PT JAB:** developer web MyJAB, Rangga Pratomo, login ke AWS lewat akun Microsoft Entra ID-nya. Microsoft Entra ID, dulu bernama Azure Active Directory, adalah layanan identitas cloud Microsoft yang dipakai Microsoft 365 dan Azure; namanya diganti antara lain supaya tidak tertukar dengan Active Directory kantor (Windows Server AD) [S24]. Akun karyawan PT JAB dibuat di Active Directory `corp.jab.example` (Day 07) lalu disinkronkan ke Entra ID, sehingga satu akun yang sama dipakai untuk laptop, Microsoft 365, dan AWS. Cara login dengan satu akun perusahaan ke banyak layanan ini disebut federation atau SSO, dibahas di Day 06. Setelah login, Rangga memakai role `myjab-web-deploy`. Permissions policy role itu disusun dua tahun lalu dengan izin `s3:*` ke semua bucket berawalan `myjab-`, karena "lebih praktis". Izin `s3:*` mencakup `s3:PutBucketPolicy` dan `s3:PutBucketPublicAccessBlock`, jadi Rangga bisa mematikan pengaman publik di bucket dan menempelkan bucket policy yang mengizinkan `"Principal": "*"`. Tidak ada yang melanggar aturan teknis; izinnya memang diberikan. Masalahnya ada di least privilege, yaitu prinsip memberi hak sekecil yang dibutuhkan tugas (Day 01 bagian 1.7).

**Beda role dengan IAM user:** IAM user biasanya mewakili satu orang atau satu program dan punya kredensial permanen. Role tidak dimiliki siapa pun secara tetap dan hanya memberi kredensial sementara. AWS menyarankan IAM user hanya dipakai untuk kasus yang tidak didukung federation, misalnya alat pihak ketiga tertentu dan akun darurat [S4].

**Beda identity-based policy dengan bucket policy:** policy identitas berkata "Rangga boleh melakukan X ke bucket mana saja yang disebut". Bucket policy berkata "bucket ini boleh diakses oleh siapa saja yang disebut". Keduanya dijumlahkan untuk akses di akun yang sama [S6], jadi bucket bisa terbuka walaupun policy identitas semua karyawan sudah ketat.

**Salah paham umum:**
- "Policy yang ditulis `Resource: "*"` hanya berlaku di akun kita, jadi aman." Benar bahwa policy identitas tidak memberi akses ke akun lain, tetapi bintang di `Action` atau `Resource` di dalam akun sendiri tetap memberi hak ke semua sumber daya, termasuk yang dibuat besok. AWS menyarankan memulai dari izin minimum lalu menambah sesuai kebutuhan [S5].

### 1.5 Access key vs role dengan kredensial sementara

Pertanyaan kelima Sari menyinggung pelajaran dari `INC-2026-025`. Cara sebuah program atau orang membuktikan dirinya ke AWS menentukan seberapa besar kerusakan bila buktinya bocor.

**Apa itu:** access key adalah kredensial jangka panjang untuk akses program ke AWS (lewat command line, SDK, atau API), terdiri dari access key ID dan secret access key, dan biasanya milik IAM user [S5][S7]. Access key tetap berlaku sampai dinonaktifkan atau dihapus. Kredensial sementara adalah kredensial yang diberikan saat sebuah role dipakai; ia terdiri dari access key ID, secret, dan session token, dan kedaluwarsa sendiri. Lama sesi bisa diatur sampai maksimal 12 jam, tergantung pengaturan role [S4]. Dari awalan ID-nya, analyst bisa membedakan keduanya: access key permanen berawalan `AKIA`, sedangkan kredensial sementara dari AWS STS (Security Token Service, layanan pembuat kredensial sementara) berawalan `ASIA` [S8].

**Analogi:** access key adalah kunci duplikat permanen; siapa pun yang menemukannya di jalan bisa membuka pintu sampai gemboknya diganti. Role dengan kredensial sementara adalah kartu tamu harian yang mati sendiri di akhir hari. Batasnya: kartu harian yang dicuri tetap bisa dipakai sampai kedaluwarsa, dan bila pencuri juga bisa meminta kartu baru (karena menguasai akun orang yang berhak), masa berlaku pendek saja tidak cukup.

**Cara kerja:** praktik terbaik IAM dari AWS menyarankan tiga hal yang langsung terkait [S7]:

1. Pengguna manusia login lewat federation dengan identity provider perusahaan, lalu memakai role yang memberi kredensial sementara.
2. Workload (program dan server) memakai role. Untuk program yang berjalan di EC2 atau Lambda, AWS sendiri mengantarkan kredensial sementara role ke mesin itu, sehingga tidak ada key yang perlu disimpan di file konfigurasi.
3. Bila access key permanen memang tidak bisa dihindari, perbarui (rotasi) dan hapus key yang tidak dipakai, dengan bantuan informasi kapan key terakhir dipakai.

```
ACCESS KEY PERMANEN (AKIA...)              ROLE + KREDENSIAL SEMENTARA (ASIA...)
dibuat sekali, disimpan di file/kode        diminta saat dibutuhkan
   |                                           |
berlaku sampai dicabut manusia             kedaluwarsa sendiri (menit sampai 12 jam)
   |                                           |
bocor di repo GitHub = bisa dipakai        bocor = bisa dipakai sampai sesi habis,
berbulan-bulan                              lalu tidak berguna
```

**Contoh di PT JAB:** pada `INC-2026-025`, access key `AKIA...` milik IAM user seorang developer tersimpan di file konfigurasi yang ikut ter-upload ke repo GitHub publik. Program pemindai milik pihak luar menemukannya, lalu key itu dipakai menyalakan server untuk miner dan menyalin data ekspor. Sejak itu, kebijakan Lutfi untuk tim DevOps: tidak ada IAM user baru untuk manusia, semua login lewat Entra ID lalu memakai role, dan server MyJAB di EC2 memakai role yang ditempel ke instance. Itu sebabnya event di alert hari ini (bagian 2.2) memperlihatkan key berawalan `ASIA` dan identitas berjenis role yang sedang dipakai, bukan IAM user.

**Beda dengan password console:** password console dipakai manusia untuk login ke halaman web dan bisa dilindungi MFA. Access key dipakai program dan tidak meminta MFA saat dipakai, kecuali policy-nya mensyaratkan MFA lewat `Condition` [S5]. Karena itu access key yang bocor sering lebih berbahaya daripada password yang bocor.

**Salah paham umum:**
- "Setelah access key yang bocor dihapus, insidennya selesai." Menghapus key menghentikan pemakaian berikutnya, tetapi tidak membatalkan apa yang sudah dilakukan dengan key itu: server yang sudah dibuat, user baru yang ditambahkan pelaku, atau data yang sudah disalin. Log aktivitas akun selama key itu hidup harus diperiksa (bagian 1.10).

### 1.6 Misconfiguration dan bucket publik

Pertanyaan keenam Sari adalah inti alert hari ini. Tidak ada exploit canggih, tidak ada malware; hanya satu pengaturan yang membuat lemari arsip berpindah ke lobi.

**Apa itu:** misconfiguration adalah pengaturan aset cloud yang salah sehingga aset itu terbuka untuk akses tanpa izin, kebocoran data, atau gangguan layanan. Cloud Security Alliance (CSA), organisasi industri keamanan cloud, menempatkan "misconfiguration and inadequate change control" di urutan pertama laporan Top Threats to Cloud Computing 2024, menggeser IAM yang berada di urutan pertama pada edisi 2022 [S20]. Bucket adalah wadah penyimpanan file (disebut object) di layanan seperti Amazon S3. Bucket publik adalah bucket yang isinya bisa dibaca, dan kadang ditulis, oleh siapa pun di internet.

Di S3, akses publik bisa diberikan lewat tiga jalan: ACL, access point policy, dan bucket policy [S9]. S3 menganggap ACL publik bila memberi izin ke grup bawaan `AllUsers` (semua orang) atau `AuthenticatedUsers` (semua pemilik akun AWS mana pun) [S9]. Bucket policy dianggap publik kecuali izinnya dibatasi ke nilai tetap seperti principal tertentu, rentang IP tertentu, atau akun tertentu; contoh paling jelas adalah `"Principal": "*"` tanpa `Condition` yang membatasi [S9].

**Analogi:** lemari arsip yang ditaruh di lobi gedung tanpa kunci. Isinya mungkin sebagian memang brosur yang boleh diambil tamu, tetapi siapa pun yang lewat bisa membuka laci lain. Batasnya: lobi gedung hanya dilewati tamu yang datang, sedangkan bucket publik bisa ditemukan program pemindai yang terus-menerus menebak nama bucket, dan pengambilan isinya tidak meninggalkan jejak bila pencatatan akses data tidak dinyalakan.

**Cara kerja:** AWS menyediakan S3 Block Public Access, empat pengaturan yang bekerja sebagai gembok induk di atas ACL dan bucket policy [S9]:

| Pengaturan | Yang dicegah |
|---|---|
| `BlockPublicAcls` | Permintaan yang memasang ACL publik ditolak |
| `IgnorePublicAcls` | ACL publik yang sudah ada diabaikan |
| `BlockPublicPolicy` | Bucket policy yang mengizinkan akses publik ditolak saat dipasang |
| `RestrictPublicBuckets` | Bucket yang sudah punya policy publik hanya bisa diakses layanan AWS dan pengguna sah di akun pemilik |

Pengaturan ini bisa dipasang di tingkat organisasi (beberapa akun sekaligus), akun, bucket, dan access point. Bila tingkatnya berbeda, S3 memakai kombinasi yang paling ketat [S9]. Artinya, bila Block Public Access aktif di tingkat akun, mematikannya di satu bucket tidak membuat bucket itu publik. Sebaliknya, mematikan pengaturan ini tidak mengubah policy yang sudah ada: bucket yang punya policy publik langsung terbuka lagi begitu gembok induk dilepas [S9]. Sejak April 2023, setiap bucket baru otomatis dibuat dengan Block Public Access aktif dan ACL dinonaktifkan [S10], jadi bucket baru yang menjadi publik hampir selalu berarti ada orang yang sengaja mematikan pengaman itu.

Misconfiguration tidak hanya bucket publik. Contoh lain yang sering muncul: database yang menerima koneksi dari seluruh internet, security group yang membuka port pengelolaan seperti 22 (SSH) atau 3389 (RDP) ke `0.0.0.0/0`, log aktivitas yang dimatikan, role yang bisa dipakai oleh akun luar, dan disk cadangan (snapshot) yang dibagikan ke publik. Pola umumnya sama: pengaturan berubah tanpa review, dan tidak ada yang memeriksa ulang. Itulah kenapa CSA menggabungkan misconfiguration dengan "inadequate change control" (pengendalian perubahan yang lemah) dalam satu ancaman [S20].

**Contoh di PT JAB:** bucket `myjab-promo-assets-prod` dibuat Selasa sore. Rangga mematikan keempat pengaturan Block Public Access di tingkat bucket, lalu memasang bucket policy yang mengizinkan `s3:GetObject` untuk `"Principal": "*"`. Block Public Access di tingkat akun MyJAB ternyata belum pernah dinyalakan sejak akun dibuat, jadi tidak ada gembok induk yang menahan. Sampai sini, niatnya sah: gambar promo memang untuk publik. Masalah muncul di bagian 2.1: selain 211 gambar, bucket itu juga berisi tiga file CSV hasil ekspor kampanye yang tersalin ikut oleh skrip unggah.

**Beda misconfiguration dengan vulnerability:** vulnerability adalah kelemahan yang bisa dimanfaatkan, misalnya bug perangkat lunak (Day 01 bagian 1.3). Misconfiguration adalah salah satu jenis vulnerability, tetapi penyebabnya pengaturan, bukan kode. Patch dari penyedia tidak bisa menutupnya; hanya pemilik akun yang bisa memperbaikinya.

**Salah paham umum:**
- "Nama bucket yang panjang dan acak membuatnya aman walaupun publik." Nama bisa bocor lewat kode aplikasi, halaman web, atau log, dan bucket publik tetap bisa diakses siapa pun yang tahu namanya. Kerahasiaan nama bukan kontrol akses.

### 1.7 CSPM (Cloud Security Posture Management)

Pertanyaan ketujuh Sari dimulai dari sumber alert. `SOC-2027-0843` tidak berasal dari serangan yang terdeteksi, tetapi dari alat yang memeriksa pengaturan.

**Apa itu:** CSPM adalah kemampuan atau alat yang terus-menerus memeriksa konfigurasi sumber daya cloud terhadap kebijakan keamanan dan standar, lalu melaporkan pengaturan yang melanggar sebagai temuan (finding) beserta rekomendasi perbaikannya. Microsoft menggambarkan CSPM sebagai komponen yang memeriksa dan memperbaiki postur keamanan sumber daya cloud, dengan kebijakan yang diterjemahkan menjadi rekomendasi untuk setiap resource yang melanggar dan skor keamanan yang naik saat rekomendasi dikerjakan [S16]. Postur (posture) di sini berarti keadaan keamanan sebuah lingkungan secara keseluruhan pada satu waktu.

**Analogi:** inspektur gedung yang berkeliling setiap hari dengan daftar periksa: apakah pintu tiap unit terkunci, apakah jendela darurat tertutup, apakah alat pemadam ada di tempatnya. Ia mencatat pelanggaran dan memberi tahu penghuni. Batasnya: inspektur tidak melihat siapa yang keluar masuk dan tidak menghentikan pencuri; ia hanya memeriksa keadaan kunci pada saat inspeksi. Bila pintu dibuka dan ditutup lagi di antara dua inspeksi, ia bisa tidak tahu.

**Cara kerja:**

```
akun AWS / subscription Azure / project cloud lain
        |  (dibaca lewat API, biasanya tanpa agen)
        v
[CSPM] bandingkan setiap resource dengan aturan:
        - bucket tidak boleh publik
        - log aktivitas harus aktif
        - port 22/3389 tidak boleh terbuka ke internet
        - akun root harus pakai MFA
        |
        v
finding + tingkat keparahan + rekomendasi + skor postur
        |
        v
dikirim ke SOC (SIEM / ticketing) dan ke pemilik resource
```

CSPM bekerja dari luar workload: ia membaca konfigurasi lewat API penyedia, sehingga biasanya tidak perlu memasang agen di setiap server. Aturan pemeriksaannya biasanya diambil dari benchmark (kumpulan praktik baik yang terdokumentasi), misalnya benchmark bawaan penyedia atau CIS Benchmark, ditambah aturan khusus organisasi.

**Contoh di PT JAB:** PT JAB memakai kemampuan CSPM dasar dari Microsoft Defender for Cloud, yang bisa membaca subscription Azure sekaligus akun AWS yang dihubungkan [S16]. Temuan dengan tingkat High dikirim otomatis ke Splunk, SIEM yang dipakai SOC PT JAB, dan menjadi alert seperti `SOC-2027-0843`. Selain bucket publik, CSPM yang sama juga melaporkan bahwa Block Public Access tingkat akun MyJAB belum aktif; temuan ini sudah muncul sejak CSPM dipasang, tetapi berstatus Medium dan belum dikerjakan. Bagian 2.1 membedah isi alert-nya.

**Beda dengan vulnerability scanner:** vulnerability scanner mencari kelemahan perangkat lunak di dalam server, seperti versi aplikasi yang punya bug yang diketahui. CSPM mencari kelemahan pengaturan di tingkat layanan cloud. Keduanya saling melengkapi; banyak produk CNAPP (bagian 1.9) menggabungkannya.

**Salah paham umum:**
- "Skor postur 90% berarti lingkungan aman." Skor menghitung rekomendasi yang sudah dikerjakan, tanpa melihat apakah satu-satunya yang belum dikerjakan adalah bucket berisi data pelanggan. Prioritaskan temuan berdasarkan data dan dampak, bukan persentase.

### 1.8 CASB (Cloud Access Security Broker)

Sari menyebut CASB sebagai alat yang "sedang diuji". Berbeda dengan CSPM yang memeriksa pengaturan akun cloud milik PT JAB, CASB memperhatikan sisi lain: aplikasi cloud apa saja yang dipakai karyawan, termasuk yang tidak pernah disetujui.

**Apa itu:** CASB adalah titik penegakan kebijakan keamanan yang berada di antara pengguna dan layanan cloud. Kategori ini dirumuskan oleh Gartner dengan empat pilar: visibility (menemukan layanan cloud yang dipakai, termasuk shadow IT), compliance (menegakkan aturan data dan akses), data security (melindungi data, misalnya dengan DLP dan enkripsi), dan threat protection (mendeteksi dan menghentikan ancaman terhadap layanan cloud dan penggunanya) [S18]. Shadow IT adalah aplikasi atau layanan yang dipakai karyawan tanpa sepengetahuan atau izin bagian TI. DLP (data loss prevention) adalah kontrol yang mencegah data sensitif keluar dari tempat yang diizinkan, dibahas di Day 06.

**Analogi:** petugas di pintu keluar kantor yang mencatat ke layanan luar mana karyawan membawa dokumen: jasa fotokopi resmi, gudang sewaan pribadi, atau kurir yang tidak dikenal. Ia bisa memberi tahu, meminta dokumen dibawa lewat jalur resmi, atau melarang. Batasnya: CASB hanya melihat lalu lintas dan aplikasi yang bisa ia amati, yaitu lewat log jaringan kantor, lewat sambungan API ke aplikasi yang didaftarkan, atau lewat proxy. Laptop yang dibawa pulang tanpa jalur kantor dan HP pribadi bisa luput.

**Cara kerja:** CASB umumnya memakai beberapa cara sekaligus.

1. Discovery dari log: membaca log firewall atau proxy untuk mengetahui aplikasi cloud apa saja yang diakses, lalu memberi skor risiko setiap aplikasi. Microsoft Defender for Cloud Apps, misalnya, menilai aplikasi yang ditemukan dengan lebih dari 90 indikator risiko [S17].
2. Koneksi API: menyambung langsung ke aplikasi SaaS yang dipakai resmi (misalnya Microsoft 365) untuk melihat file, pengguna, dan aktivitas di dalamnya.
3. Proxy: meneruskan sesi pengguna lewat CASB supaya aksi tertentu bisa dicegah saat terjadi, misalnya mengunduh file sensitif ke perangkat yang tidak dikelola.

**Contoh di PT JAB:** sejak Juli 2027 PT JAB menguji Defender for Cloud Apps dengan membaca log proxy kantor `jkt-proxy01`. Alert `SOC-2027-0845` di bagian 2.4 berasal dari sini: satu laptop mengunggah file besar ke layanan berbagi file yang tidak termasuk daftar aplikasi resmi.

**Beda dengan CSPM:** CSPM memeriksa "apakah akun cloud milik kita disetel dengan benar". CASB memeriksa "bagaimana karyawan kita memakai aplikasi cloud, milik siapa pun". Bucket publik di AWS milik PT JAB adalah urusan CSPM; karyawan yang mengunggah data pelanggan ke layanan berbagi file pribadi adalah urusan CASB.

**Beda dengan proxy web biasa:** proxy web biasa memutuskan berdasarkan alamat dan kategori situs. CASB memahami aplikasi cloud: ia tahu bahwa satu domain adalah layanan berbagi file dengan risiko tertentu, bisa melihat aksi di dalam aplikasi (unggah, bagikan, unduh), dan bisa terhubung ke aplikasi lewat API.

### 1.9 CWPP (Cloud Workload Protection Platform) dan CNAPP

Bagian terakhir pertanyaan ketujuh menyangkut CWPP. Bila CSPM adalah inspektur yang memeriksa kunci dari luar, CWPP adalah penjaga yang berada di dalam unit.

**Apa itu:** CWPP adalah platform yang melindungi workload cloud, yaitu apa pun yang dijalankan di cloud: virtual machine (VM, komputer virtual), container (paket aplikasi ringan yang membawa semua kebutuhannya), dan fungsi serverless (kode kecil yang dijalankan penyedia hanya saat dipanggil) [S19]. Kemampuan umumnya: pemindaian kerentanan, pemeriksaan konfigurasi di dalam workload, analisis image container, perlindungan saat berjalan (runtime) dan pemantauan perilaku, deteksi intrusi di host, dan pada sebagian produk microsegmentation (pembatasan komunikasi antar workload) [S19]. Microsoft menggambarkan CWPP sebagai komponen yang melindungi VM, container, storage, database, dan fungsi serverless dari ancaman [S16].

**Analogi:** satpam yang berpatroli di dalam unit apartemen, mengenali tamu yang mencurigakan dan perilaku aneh. Batasnya: satpam hanya ada di unit yang memberinya akses. CWPP berbasis agen hanya melindungi workload yang dipasangi agen, sedangkan pemindaian tanpa agen lewat API penyedia lebih mudah dipasang tetapi memberi visibilitas yang lebih terbatas [S19].

**Cara kerja:** CWPP bisa dilihat sebagai EDR yang diperluas untuk lingkungan cloud. EDR (endpoint detection and response, dibahas di Day 06) adalah agen yang mengawasi perilaku program di komputer atau server. CWPP membawa ide yang sama ke VM di cloud, lalu menambahkan pemahaman tentang container dan fungsi serverless, yang umurnya bisa hanya beberapa menit dan tidak cocok dijaga dengan cara lama.

CNAPP (Cloud-Native Application Protection Platform) adalah istilah untuk platform yang menggabungkan beberapa alat keamanan cloud supaya aplikasi terlindungi sepanjang siklus hidupnya. Microsoft menyebut tiga komponen intinya: CSPM, CWPP, dan pemeriksaan keamanan di tahap pengembangan (DevSecOps), misalnya mencari salah konfigurasi di template infrastruktur dan secret yang tertinggal di kode [S16]. Bagi analyst, CNAPP berarti satu konsol yang bisa menghubungkan "bucket ini publik" (CSPM), "server ini punya kerentanan kritis" (CWPP), dan "kode yang membuat bucket ini ada di repo X" (DevSecOps).

**Contoh di PT JAB:** server API MyJAB di EC2 sudah dipasangi Defender for Endpoint, EDR yang juga dipakai di server Windows dan workstation PT JAB, lewat paket perlindungan server Defender for Cloud [S16]. Image container untuk fitur baru MyJAB dipindai sebelum dipakai; pada minggu yang sama, pemindaian menemukan satu pustaka dengan kerentanan kritis di image `myjab-api:2027.08.2`, dan tim Lutfi menahan rilisnya sampai pustaka diperbarui. Seandainya CWPP sudah ada pada `INC-2026-025`, miner yang dinyalakan pelaku di server baru memang tetap mungkin lolos karena server itu dibuat pelaku tanpa agen. Untuk kasus seperti itu, yang lebih berguna adalah CSPM, log aktivitas akun, dan peringatan lonjakan tagihan.

**Beda dengan CSPM:** CSPM melihat dari luar (pengaturan layanan dan resource), CWPP melihat dari dalam (proses, file, dan kerentanan di dalam workload). Bucket publik hanya terlihat oleh CSPM; proses miner di dalam VM hanya terlihat oleh CWPP atau EDR.

### 1.10 Log cloud: AWS CloudTrail dan Azure Activity Log

Pertanyaan terakhir Sari ada dua: siapa yang mengubah pengaturan bucket, dan siapa yang sudah mengunduh isinya. Pertanyaan pertama bisa dijawab dengan log yang aktif secara bawaan. Pertanyaan kedua hanya bisa dijawab bila log tambahan sudah dinyalakan sebelum kejadian.

**Apa itu:** AWS CloudTrail adalah layanan yang mencatat aksi yang dilakukan user, role, atau layanan AWS sebagai event, termasuk aksi dari console, command line, SDK, dan API [S11]. Azure Activity Log adalah log di Azure Monitor yang mencatat operasi pengelolaan resource Azure, misalnya membuat VM atau mengubah izin [S14]. Keduanya terutama mencatat operasi control plane, yaitu perintah untuk mengelola sumber daya (membuat, mengubah, menghapus, mengatur izin). Lawannya adalah operasi data plane, yaitu pemakaian isi sumber daya, seperti membaca file dari bucket atau mengambil secret dari brankas kunci [S11][S14].

**Analogi:** buku tamu dan rekaman CCTV gedung cloud. Setiap kali ada yang mengubah denah, memasang pintu, atau mengganti kunci, kejadiannya tercatat lengkap dengan nama, jam, dan dari pintu mana ia datang. Batasnya: secara bawaan, kamera ini merekam pekerjaan renovasi, tetapi tidak merekam setiap orang yang membuka laci lemari. Rekaman laci (data event) harus dinyalakan dan dibayar terpisah, dan rekaman hanya disimpan 90 hari bila tidak dipindahkan ke tempat lain.

**Cara kerja:** tabel berikut merangkum apa yang tercatat secara bawaan dan apa yang harus dinyalakan; cari kolom "Aktif bawaan" karena di situlah celah investigasi paling sering muncul.

| Jenis log | Isi | Aktif bawaan | Lama disimpan bawaan |
|---|---|---|---|
| CloudTrail Event history | Management event (control plane), per region | Ya | 90 hari, bisa dicari di console [S11] |
| CloudTrail trail | Management event dikirim terus-menerus ke bucket S3, opsional ke layanan log lain | Tidak, harus dibuat | Selama bucket tujuan menyimpan [S11] |
| CloudTrail data event | Aksi data plane, misalnya `GetObject`, `PutObject`, `DeleteObject` di S3 | Tidak, harus dipilih per jenis resource, biaya tambahan | Mengikuti trail [S11][S13] |
| Azure Activity Log | Operasi pengelolaan resource (create, update, delete, aksi); biasanya tidak mencatat operasi baca | Ya | 90 hari; diperpanjang lewat diagnostic setting ke Log Analytics, storage, atau Event Hubs [S14] |
| Azure resource log | Operasi data plane di dalam resource | Tidak, harus dikonfigurasi lewat diagnostic setting | Mengikuti tujuan [S14] |

Untuk S3, CloudTrail secara bawaan mencatat aksi tingkat bucket seperti `CreateBucket`, `PutBucketPolicy`, dan `PutBucketPublicAccessBlock`, tetapi tidak mencatat permintaan ke object di dalam bucket [S13]. Satu event CloudTrail memuat field yang menjawab pertanyaan dasar analyst [S12]:

| Field | Pertanyaan yang dijawab |
|---|---|
| `eventTime` | Kapan? (selalu UTC, jadi tambah 7 jam untuk WIB) |
| `eventSource`, `eventName` | Layanan apa, aksi apa? (`s3.amazonaws.com`, `PutBucketPolicy`) |
| `awsRegion` | Di region mana? |
| `userIdentity` | Siapa? (jenis identitas, ARN, access key yang dipakai) |
| `sourceIPAddress`, `userAgent` | Dari alamat mana, dengan alat apa? |
| `requestParameters` | Apa isi permintaannya? (misalnya isi policy yang dipasang) |
| `errorCode` | Apakah gagal, dan kenapa? (kosong bila berhasil) |
| `readOnly`, `eventCategory` | Hanya membaca atau mengubah? Management atau data? |

ARN (Amazon Resource Name) yang muncul di `userIdentity` adalah nama lengkap unik sebuah sumber daya AWS, dengan format `arn:partisi:layanan:region:akun:resource` [S8]. Untuk role yang sedang dipakai, ARN-nya berbentuk `arn:aws:sts::<akun>:assumed-role/<nama role>/<nama sesi>`, dan nama sesi sering berisi nama pengguna yang memakai role itu [S8].

**Contoh di PT JAB:** akun AWS MyJAB punya satu trail yang mengirim management event ke bucket log terpisah, lalu diteruskan ke Splunk. Dari trail itu, kamu bisa menemukan siapa yang membuat bucket dan mematikan Block Public Access (bagian 2.2). Data event S3 tidak pernah dinyalakan untuk bucket promo karena "isinya cuma gambar", dan S3 server access logging (log akses milik S3 sendiri) juga tidak aktif. Akibatnya, pertanyaan kedua Sari ("siapa yang sudah mengunduh isinya?") tidak bisa dijawab. Di Azure, Activity Log subscription `JAB-Azure-Prod` dikirim lewat diagnostic setting ke Log Analytics dan diteruskan ke Splunk, sehingga perubahan izin seperti di bagian 2.3 tetap bisa dicari setelah lewat 90 hari.

**Beda CloudTrail dengan log aplikasi:** CloudTrail mencatat apa yang dilakukan terhadap layanan AWS. Ia tidak mencatat apa yang dilakukan pelanggan MyJAB di dalam aplikasi (login, membayar, mengganti paket); itu ada di log aplikasi MyJAB sendiri. Begitu pula Activity Log tidak mencatat login karyawan ke Microsoft 365; login itu ada di log sign-in Entra ID, dibahas di Day 06.

**Salah paham umum:**
- "Log cloud aktif otomatis, jadi semua sudah tercatat." Yang aktif otomatis hanya log pengelolaan selama 90 hari. Penyimpanan jangka panjang, data event, dan pengiriman ke SIEM harus disiapkan sebelum insiden; setelah insiden terjadi, log yang tidak pernah dinyalakan tidak bisa dibuat mundur.

## 2. Contoh nyata

Semua alert, log, dan angka di bagian ini adalah keluaran ilustrasi untuk organisasi fiktif PT JAB, bukan hasil eksekusi nyata. Format log disederhanakan; nama field dan rekomendasi di produk sungguhan bisa berbeda. Nomor akun AWS `111122223333` adalah format contoh yang dipakai dokumentasi AWS.

### 2.1 Membedah alert CSPM `SOC-2027-0843`

Ini alert yang terbuka di layar saat Lutfi bergabung. Ringkasannya di Splunk, hasil kiriman dari CSPM:

```
Alert       : SOC-2027-0843
Dibuat      : 2027-08-11 08:40:00 WIB
Sumber      : CSPM (Defender for Cloud, konektor AWS)
Judul       : S3 bucket allows public read access
Severity    : High
Akun AWS    : 111122223333 (myjab-prod)
Region      : ap-southeast-3
Resource    : arn:aws:s3:::myjab-promo-assets-prod
Temuan      : Block Public Access (bucket) : keempat pengaturan OFF
              Block Public Access (akun)   : belum dikonfigurasi
              Bucket policy                : Principal "*" , Action s3:GetObject
Isi bucket  : 214 object (211 .jpg/.png, 3 .csv)
Rekomendasi : aktifkan Block Public Access; sajikan file publik lewat CDN
Temuan terkait (lama, Medium): account-level Block Public Access not enabled
```

**Cara membaca:** baca dari bawah ke atas lapisan pengaman. Gembok induk tingkat akun tidak ada, gembok tingkat bucket dimatikan, lalu bucket policy membuka akses baca untuk semua orang (`"*"`). Ketiganya harus terjadi bersamaan supaya bucket menjadi publik (bagian 1.6). Baris "Isi bucket" adalah petunjuk terpenting untuk menentukan dampak: 211 file gambar memang dimaksudkan untuk publik, tetapi 3 file CSV jelas bukan materi promo.

Tabel berikut memetakan alert ke istilah Day ini; pakai kolom kanan sebagai pola saat menulis ringkasan alert cloud sendiri.

| Istilah | Di alert ini |
|---|---|
| Model layanan | S3, penyimpanan yang diabstraksi, lebih dekat ke PaaS |
| Shared responsibility | Pengaturan akses dan isi bucket adalah tanggung jawab PT JAB |
| Misconfiguration | Block Public Access tingkat akun tidak aktif, tingkat bucket dimatikan |
| Policy | Bucket policy dengan `"Principal": "*"` |
| Alat pendeteksi | CSPM (pemeriksa konfigurasi), bukan deteksi serangan |
| Sifat CIA yang terancam | Confidentiality, karena isi CSV bisa dibaca siapa saja |
| Log yang dibutuhkan | CloudTrail management event (siapa mengubah), data event (siapa mengunduh) |

Saat kamu membuka salah satu CSV bersama Lutfi lewat akses resmi, isinya 1.250 baris data peserta kampanye: nama, nomor HP, dan paket langganan. Keputusan Sari: alert dinaikkan menjadi insiden.

### 2.2 Membaca CloudTrail di balik alert

Pertanyaan berikutnya adalah siapa yang mengubah pengaturan dan kapan. Sari mencari event untuk bucket itu di data CloudTrail yang sudah masuk ke Splunk. Tiga event yang relevan, disederhanakan:

```
eventTime        : 2027-08-10T06:58:05Z
eventSource      : s3.amazonaws.com
eventName        : CreateBucket
awsRegion        : ap-southeast-3
userIdentity     : type=AssumedRole
                   arn=arn:aws:sts::111122223333:assumed-role/myjab-web-deploy/rangga.pratomo@jab.example
                   accessKeyId=ASIA************7Q2M
sourceIPAddress  : 198.51.100.120
requestParameters: bucketName=myjab-promo-assets-prod
errorCode        : (kosong)

eventTime        : 2027-08-10T07:02:11Z
eventName        : PutBucketPublicAccessBlock
userIdentity     : (sama dengan di atas)
sourceIPAddress  : 198.51.100.120
requestParameters: bucketName=myjab-promo-assets-prod
                   BlockPublicAcls=false IgnorePublicAcls=false
                   BlockPublicPolicy=false RestrictPublicBuckets=false
errorCode        : (kosong)

eventTime        : 2027-08-10T07:03:40Z
eventName        : PutBucketPolicy
userIdentity     : (sama dengan di atas)
sourceIPAddress  : 198.51.100.120
requestParameters: bucketName=myjab-promo-assets-prod
                   policy: Effect=Allow  Principal="*"  Action=s3:GetObject
                           Resource=arn:aws:s3:::myjab-promo-assets-prod/*
errorCode        : (kosong)
```

**Cara membaca:**

- Waktu: `eventTime` dalam UTC. Tambah 7 jam untuk WIB, jadi bucket dibuat pukul 13:58:05 WIB, pengaman dimatikan pukul 14:02:11 WIB, dan policy publik dipasang pukul 14:03:40 WIB, Selasa 2027-08-10.
- Siapa: `type=AssumedRole` dan awalan `ASIA` menunjukkan kredensial sementara dari role (bagian 1.5). Nama sesi `rangga.pratomo@jab.example` menunjuk orang yang memakai role itu.
- Dari mana: `198.51.100.120` adalah alamat NAT kantor Jakarta, yaitu satu alamat publik yang dipakai semua laptop kantor saat keluar ke internet (Day 02 bagian 1.11). Perubahan dilakukan dari kantor, bukan dari alamat luar yang tidak dikenal.
- Apa: urutan tiga event persis sama dengan tiga lapis pengaman di bagian 2.1. Ketiganya berhasil karena `errorCode` kosong.

**Kesimpulan:** tidak ada tanda akun Rangga diambil alih. Ini perubahan sah oleh pemilik akses yang izinnya terlalu luas, tanpa review, dengan isi bucket yang tidak diperiksa. Istilah yang tepat untuknya adalah misconfiguration, bukan serangan.

**Yang tidak ada:** tidak ada satu pun event `GetObject`. Bukan karena tidak ada yang mengunduh, tetapi karena data event S3 tidak dinyalakan (bagian 1.10). Hitung jendela paparan: bucket publik sejak 14:03:40 WIB Selasa sampai Rangga dan Lutfi menyalakan kembali Block Public Access dan menghapus policy pukul 09:52:10 WIB Rabu, yaitu 19 jam 48 menit 30 detik. CSPM baru melaporkan pukul 08:40:00 WIB, 18 jam 36 menit 20 detik setelah policy publik terpasang, karena CSPM memeriksa secara berkala, bukan saat setiap perubahan terjadi.

Karena data pribadi 1.250 pelanggan bisa diakses publik selama hampir 20 jam dan tidak ada log yang bisa membuktikan bahwa tidak ada yang mengunduhnya, Sari membuka insiden `INC-2027-087` dan menyerahkan penilaian kewajiban pemberitahuan kepada Agus Setiawan, DPO (petugas pelindungan data pribadi) PT JAB. Tindak lanjut yang disepakati dengan Lutfi pada hari yang sama tercatat di tabel berikut; cari kolom Jenis control untuk melihat keseimbangan pencegahan dan deteksi (Day 01 bagian 1.5).

| Tindak lanjut | Jenis control | Pemilik |
|---|---|---|
| Aktifkan Block Public Access di tingkat akun MyJAB (dan rencanakan di tingkat organisasi) | Preventive | Lutfi Hakim |
| Ganti `s3:*` di role `myjab-web-deploy` dengan izin yang dibutuhkan saja; pemasangan bucket policy hanya lewat review | Preventive | Lutfi Hakim |
| Gambar promo disajikan lewat CDN dengan akses khusus ke bucket privat, bukan bucket publik | Preventive | Tim web MyJAB |
| Rule Splunk real-time untuk `PutBucketPublicAccessBlock`, `DeleteBucketPublicAccessBlock`, dan `PutBucketPolicy` yang mengandung `"Principal":"*"` | Detective | SOC (Sari) |
| Nyalakan data event S3 untuk bucket yang menyimpan data pelanggan | Detective | Lutfi Hakim dan SOC |
| Skrip unggah memakai daftar file yang diizinkan, bukan seluruh folder | Preventive | Tim web MyJAB |

### 2.3 Membaca Azure Activity Log: role assignment `SOC-2027-0844`

Pagi yang sama, satu alert cloud lain masuk dari subscription Azure, kali ini dari rule Splunk yang membaca Activity Log. Sari memakainya untuk memperlihatkan bahwa konsep di AWS punya padanan di Azure.

```
Alert          : SOC-2027-0844  Role assignment at subscription scope to guest account
Waktu          : 2027-08-11 07:31:52 WIB
Sumber log     : Azure Activity Log (kategori Administrative), via Log Analytics
Operation      : Microsoft.Authorization/roleAssignments/write
Status         : Succeeded
Caller         : adm.agung@jab.example
Caller IP      : 198.51.100.120
Scope          : /subscriptions/<id JAB-Azure-Prod>
Role           : Contributor
Principal baru : support@backupvendor.example (akun tamu di Entra ID)
```

**Cara membaca:** satu role assignment terdiri dari tiga unsur (bagian 1.4): principal (akun tamu milik vendor backup), role definition (Contributor, yang boleh membuat dan mengelola resource apa pun), dan scope (seluruh subscription). Pemberinya adalah akun admin terpisah `adm.agung` milik Agung Prabowo, Lead Infrastruktur, dari alamat NAT kantor. Akun admin terpisah adalah praktik PT JAB supaya pekerjaan sehari-hari tidak memakai akun berhak tinggi.

**Keputusan:** kamu menelepon Agung. Ada tiket perubahan untuk memberi vendor backup akses selama dua hari, jadi aksinya sah. Tetapi vendor hanya perlu mengelola resource di satu resource group backup, bukan seluruh subscription. Sari menutup alert sebagai aktivitas sah dengan catatan perbaikan: scope dipersempit ke resource group backup dan role assignment diberi tanggal hapus. Kasus ini memperlihatkan nilai Activity Log: tanpa log itu, pemberian akses seluas ini bisa bertahan bertahun-tahun tanpa diketahui, dan Microsoft mencatat bahwa Activity Log adalah satu-satunya tempat yang menyimpan siapa pembuat sebuah resource, sehingga penyimpanannya perlu diperpanjang melewati 90 hari [S14].

### 2.4 Alert CASB `SOC-2027-0845`: unggahan ke aplikasi yang tidak resmi

Contoh ketiga berasal dari CASB yang sedang diuji, untuk memperlihatkan bahwa masalah cloud tidak selalu terjadi di akun AWS atau Azure milik perusahaan.

```
Alert        : SOC-2027-0845  Large upload to unsanctioned cloud app
Waktu        : 2027-08-11 10:05 sampai 10:41 WIB
Sumber       : CASB cloud discovery (log jkt-proxy01)
Pengguna     : maya.anggraini@jab.example (Divisi Marketing)
Perangkat    : JKT-WS-1084 (10.10.38.21)
Aplikasi     : fileshare.example (192.0.2.154) - status: belum dinilai
Skor risiko  : 3/10 (rendah: tanpa sertifikasi keamanan, tanpa SSO perusahaan)
Aktivitas    : 23 unggahan, total 1,8 GB
```

**Cara membaca:** CASB melihat aplikasi yang tidak ada di daftar resmi (shadow IT, bagian 1.8), menilainya berisiko, dan melihat volume unggahan yang besar. Alert seperti ini belum berarti kebocoran; ia memunculkan pertanyaan: data apa yang diunggah, dan kenapa tidak lewat aplikasi resmi?

**Keputusan:** Maya menjelaskan bahwa ia mengirim video iklan mentah ke agensi kreatif yang memakai layanan itu. Isinya bukan data pelanggan. Alert ditutup sebagai aktivitas sah, aplikasi ditandai tidak resmi di CASB, dan Maya diarahkan memakai fitur berbagi eksternal OneDrive milik Microsoft 365 PT JAB, yang tercatat dan bisa dicabut. Bandingkan dengan bagian 2.1: di sana data keluar karena pengaturan akun cloud milik PT JAB (CSPM), di sini data keluar karena pilihan aplikasi oleh karyawan (CASB).

## 3. Perbandingan istilah yang sering tertukar

### 3.1 IaaS, PaaS, SaaS, dan on-premises

Tabel ini merangkum bagian 1.2 dan 1.3 dari sudut pandang "apa yang masih harus aku jaga". Cari kolom "Tetap tugas pelanggan" saat menilai alert di layanan cloud apa pun.

| | On-premises | IaaS | PaaS | SaaS |
|---|---|---|---|---|
| Analogi | Rumah milik sendiri | Tanah kosong, bangun sendiri | Apartemen berperabot | Hotel |
| Yang disewa | Tidak ada | Server virtual, disk, jaringan | Platform untuk menjalankan aplikasi atau menyimpan data | Aplikasi jadi |
| Contoh | Data center Jakarta PT JAB | Amazon EC2, Azure VM | Amazon S3, AWS Lambda, Azure App Service | Microsoft 365 |
| Patch sistem operasi | Pelanggan | Pelanggan | Penyedia | Penyedia |
| Tetap tugas pelanggan | Semuanya | OS, aplikasi, jaringan virtual, data, identitas, konfigurasi | Aplikasi dan pengaturannya, data, identitas, konfigurasi | Data, identitas, pengaturan berbagi dan aplikasi |
| Misconfiguration khas | Aturan firewall terlalu longgar | Port 22/3389 terbuka ke internet | Bucket atau database publik | Berbagi file ke "siapa saja yang punya tautan" |

### 3.2 CSPM, CASB, CWPP, CNAPP

Empat singkatan ini sering muncul bersamaan di presentasi vendor. Tabel berikut membedakannya dengan satu pertanyaan kunci; cari kolom "Tidak melihat" untuk tahu kapan alat itu tidak bisa diandalkan.

| Alat | Pertanyaan kunci | Melihat dari | Contoh temuan | Tidak melihat | Analogi |
|---|---|---|---|---|---|
| CSPM | Apakah akun cloud kita disetel dengan benar? | Luar, lewat API penyedia | Bucket publik, log dimatikan, root tanpa MFA | Proses di dalam VM, pemakaian aplikasi oleh karyawan | Inspektur gedung |
| CASB | Aplikasi cloud apa yang dipakai karyawan, dan data apa yang dibawa ke sana? | Log jaringan, API aplikasi SaaS, proxy | Unggahan besar ke aplikasi tidak resmi, file sensitif dibagikan ke publik | Pengaturan akun IaaS/PaaS milik sendiri | Petugas pintu keluar kantor |
| CWPP | Apakah workload yang berjalan aman dan tidak sedang diserang? | Dalam workload (agen) atau pemindaian image | Kerentanan kritis di image container, proses miner di VM | Workload tanpa agen, pengaturan layanan di luar workload | Satpam di dalam unit |
| CNAPP | Bisakah semua itu dilihat dalam satu tempat, dari kode sampai runtime? | Gabungan | Jalur serangan: VM rentan yang punya role dengan akses ke bucket data | Tergantung komponen yang benar-benar dibeli dan dipasang | Satu perusahaan keamanan untuk inspeksi dan patroli |

### 3.3 Log cloud yang sering tertukar

Analyst baru sering mencari di log yang salah. Tabel berikut memetakan pertanyaan investigasi ke log yang menjawabnya.

| Pertanyaan | Log yang dibuka | Aktif bawaan? |
|---|---|---|
| Siapa mengubah pengaturan bucket, membuat VM, atau memberi izin di AWS? | CloudTrail management event | Ya (90 hari di Event history) |
| Siapa membaca atau mengunduh file dari bucket S3? | CloudTrail data event S3 (atau S3 server access log) | Tidak |
| Siapa memberi role assignment atau menghapus resource di Azure? | Azure Activity Log | Ya (90 hari) |
| Siapa membaca secret di brankas kunci Azure atau isi database? | Azure resource log | Tidak |
| Siapa login ke Microsoft 365 atau Azure portal, dari mana, dengan MFA atau tidak? | Log sign-in Entra ID | Ya, masa simpan tergantung lisensi (dibahas di Day 06) |
| Apa yang dilakukan pelanggan di aplikasi MyJAB? | Log aplikasi MyJAB | Tergantung aplikasi |

### 3.4 Access key, kredensial sementara, dan password console

Ketiganya sama-sama "kunci" ke akun cloud, tetapi cara bocornya dan cara menanganinya berbeda.

| | Password console | Access key permanen | Kredensial sementara (role) |
|---|---|---|---|
| Dipakai oleh | Manusia, lewat halaman web | Program, command line, SDK | Manusia lewat federation, atau workload |
| Awalan ID di log | Tidak ada (event `ConsoleLogin`) | `AKIA` | `ASIA` |
| Masa berlaku | Sampai diganti | Sampai dinonaktifkan atau dihapus | Kedaluwarsa sendiri, maksimal 12 jam |
| Bisa dilindungi MFA saat dipakai | Ya | Hanya lewat `Condition` di policy | Ya, saat login sebelum memakai role |
| Cara bocor yang umum | Phishing | Tertinggal di repo kode, file konfigurasi, image | Dicuri dari mesin yang sedang memakainya |
| Langkah pertama bila bocor | Reset password, cabut sesi | Nonaktifkan key, lalu periksa CloudTrail selama key hidup | Cabut sesi role, periksa siapa yang memakai role itu |

## 4. Salah paham umum

Butir berikut melintasi beberapa istilah sekaligus. Salah paham yang khusus satu istilah sudah ditulis di subbagiannya.

- **Anggapan:** pindah ke cloud berarti keamanan menjadi urusan penyedia. **Kenyataannya:** data, konfigurasi, dan identitas tetap tanggung jawab pelanggan di semua model layanan [S3], dan NSA menempatkan pemahaman shared responsibility sebagai strategi pertama dari sepuluh strategi mitigasi keamanan cloud [S22]. `SOC-2027-0843` terjadi di wilayah PT JAB, bukan di wilayah AWS (bagian 1.3 dan 2.1).
- **Anggapan:** insiden cloud biasanya terjadi karena penyedia diretas. **Kenyataannya:** CSA menempatkan misconfiguration dan IAM sebagai dua ancaman teratas 2024, sementara ancaman di sisi infrastruktur penyedia seperti kerentanan teknologi bersama dan kehilangan data di penyedia dinilai cukup rendah sehingga dikeluarkan dari laporan [S20].
- **Anggapan:** bila tidak ada log pengunduhan, berarti tidak ada yang mengunduh. **Kenyataannya:** data event S3 tidak aktif secara bawaan [S11][S13], jadi ketiadaan event `GetObject` hanya berarti tidak ada yang mencatat. Itulah sebabnya `INC-2027-087` diperlakukan sebagai kemungkinan kebocoran (bagian 2.2).
- **Anggapan:** perubahan oleh karyawan sah dari alamat kantor tidak perlu dicurigai. **Kenyataannya:** dalam kasus `SOC-2027-0843` dan `SOC-2027-0844`, pelakunya sah dan dari kantor, tetapi dampaknya tetap nyata. Penilaian alert cloud perlu memisahkan dua pertanyaan: apakah akunnya diambil alih (bukan), dan apakah perubahannya membuka risiko (ya).
- **Anggapan:** satu alat keamanan cloud sudah cukup. **Kenyataannya:** CSPM tidak melihat proses di dalam VM, CWPP tidak melihat bucket publik, dan keduanya tidak melihat karyawan yang mengunggah data ke aplikasi tidak resmi (bagian 3.2). Prinsip defense in depth, yaitu lapisan pengaman berbeda jenis (Day 01 bagian 1.6), tetap berlaku di cloud.
- **Anggapan:** role selalu aman karena kredensialnya sementara. **Kenyataannya:** role dengan izin `s3:*` tetap bisa membuka bucket ke publik dalam tiga panggilan API (bagian 2.2). Kredensial sementara mengurangi dampak kunci yang bocor, tetapi tidak memperbaiki izin yang terlalu luas.
- **Anggapan:** di cloud tidak ada perimeter, jadi aturan jaringan tidak penting. **Kenyataannya:** security group dan aturan jaringan virtual tetap tugas pelanggan di IaaS (bagian 1.3), tetapi perimeter utama bergeser ke identitas dan konfigurasi, sejalan dengan zero trust yang tidak mempercayai akses hanya karena lokasinya (Day 01 bagian 1.8).

## 5. Catatan terkini

Bagian ini mencatat versi dokumen acuan, perubahan bawaan layanan, dan perubahan nama produk yang perlu diketahui saat membaca sumber lain.

- **NIST SP 800-145** (The NIST Definition of Cloud Computing) terbit September 2011 dan per 2026-10-21 masih berstatus final tanpa revisi di halaman publikasinya [S1]. Definisinya tetap menjadi rujukan baku walaupun banyak layanan baru (container, serverless) muncul setelahnya.
- **Bawaan S3 sejak April 2023:** AWS mulai menerapkan dua pengaturan bawaan untuk semua bucket baru, yaitu Block Public Access aktif dan ACL dinonaktifkan, dengan peluncuran mulai 5 April 2023 di semua region [S10]. Bucket yang dibuat sebelum itu tidak otomatis berubah, jadi bucket lama perlu diperiksa sendiri, biasanya lewat CSPM.
- **Block Public Access tingkat organisasi:** dokumentasi S3 saat ini menyebut pengaturan bisa dipasang di tingkat AWS Organizations, berlaku untuk akun anggota, dan di tingkat itu keempat pengaturan hanya bisa dinyalakan atau dimatikan bersama [S9]. Cek ketersediaan fitur ini di akun organisasimu sebelum mengandalkannya.
- **Format event CloudTrail** saat ini versi 1.11 [S12]. CloudTrail juga punya jenis event network activity untuk panggilan API lewat VPC endpoint dan Insights event untuk lonjakan aktivitas yang tidak biasa; keduanya tidak aktif secara bawaan dan berbayar [S11].
- **Kebijakan IAM AWS** terbaru menyarankan MFA yang tahan phishing seperti passkey dan security key untuk IAM user dan root user yang masih dibutuhkan [S7]. Jenis policy yang didukung AWS sekarang mencakup antara lain service control policy (SCP) dan resource control policy (RCP) di tingkat organisasi, yang membatasi izin maksimum tanpa memberi izin [S5].
- **Microsoft Defender for Cloud** menyebut dirinya CNAPP dan sedang dipindahkan sebagian ke portal Microsoft Defender; nama menu dan letak fitur bisa berbeda antara Azure portal dan Defender portal [S16]. Halaman shared responsibility Microsoft (diperbarui 2026-08-24) juga merujuk ke model shared responsibility khusus untuk workload AI generatif dan AI agent [S3].
- **Nama Microsoft Entra ID** diumumkan 11 Juli 2023 sebagai pengganti nama Azure Active Directory; fitur, lisensi, dan URL login tidak berubah, jadi dokumen dan log lama yang menyebut Azure AD merujuk layanan yang sama [S24].
- **Azure Activity Log:** cara ekspor lama bernama log profile sudah menjadi metode legacy; cara yang dipakai sekarang adalah diagnostic setting [S14].
- **Panduan pemerintah AS:** pada 7 Maret 2024 NSA menerbitkan "Top Ten Cloud Security Mitigation Strategies", sepuluh lembar informasi yang masing-masing membahas satu strategi, dari shared responsibility sampai pengelolaan log cloud untuk threat hunting [S22]. CISA menerbitkan bersama lima di antaranya pada hari yang sama: IAM, manajemen kunci, segmentasi jaringan dan enkripsi, keamanan data, serta risiko dari managed service provider [S21]. Sumber berita menyebut CISA terlibat di enam dari sepuluh; daftar resmi di halaman CISA hanya mencantumkan lima.
- **CSA Top Threats to Cloud Computing 2024** terbit 6 Agustus 2024 dengan sebelas ancaman; urutan pertama sampai ketiga adalah misconfiguration dan pengendalian perubahan yang lemah, IAM, serta interface dan API yang tidak aman [S20].

## 6. Cheat sheet

```
Cloud computing      : akses lewat jaringan ke sumber daya penyedia, self-service, elastis, diukur (NIST SP 800-145)
Region / AZ          : lokasi geografis penyedia (ap-southeast-3 = Jakarta) / data center terpisah di dalamnya
Public/private/      : siapa yang memakai infrastruktur: umum / satu organisasi / gabungan
  hybrid cloud
IaaS                 : sewa server virtual, disk, jaringan; OS dan atas = pelanggan (tanah kosong)
PaaS                 : sewa platform; aplikasi, data, pengaturan = pelanggan (apartemen berperabot)
SaaS                 : pakai aplikasi jadi; data, akun, pengaturan berbagi = pelanggan (hotel)
Shared responsibility: penyedia jaga "of the cloud" (fisik, host, jaringan fisik);
                       pelanggan jaga "in the cloud" (data, identitas, konfigurasi) di SEMUA model
API / console        : pintu perintah ke layanan / halaman web; klik console = panggilan API
Cloud IAM            : siapa (principal) boleh apa (action) ke mana (resource) dalam keadaan apa (condition)
Policy               : dokumen izin JSON; identity-based (di user/role) atau resource-based (bucket policy)
Penilaian izin AWS   : tolak bawaan -> Allow mengizinkan -> Deny eksplisit menang atas semua Allow
Role                 : identitas yang dipinjam sementara; trust policy = siapa boleh pakai
Access key AKIA      : kredensial permanen; bocor = bisa dipakai sampai dicabut
Kredensial ASIA      : kredensial sementara dari role (STS), kedaluwarsa sendiri, maks. 12 jam
Azure RBAC           : role assignment = principal + role definition + scope (MG/sub/RG/resource)
Misconfiguration     : pengaturan salah yang membuka celah; ancaman cloud no. 1 versi CSA 2024
Bucket publik        : isi bucket bisa dibaca siapa saja (ACL AllUsers / policy Principal "*")
Block Public Access  : 4 gembok S3 (BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy,
                       RestrictPublicBuckets); level org/akun/bucket; yang paling ketat menang
CSPM                 : periksa konfigurasi cloud lewat API, finding + rekomendasi (inspektur gedung)
CASB                 : awasi pemakaian aplikasi cloud oleh karyawan, shadow IT, DLP (petugas pintu keluar)
CWPP                 : lindungi VM, container, serverless dari dalam (satpam di dalam unit)
CNAPP                : CSPM + CWPP + keamanan pengembangan dalam satu platform
Control vs data plane: kelola resource (buat, ubah izin) vs pakai isi (baca file, ambil secret)
CloudTrail           : log aktivitas AWS; management event aktif bawaan (90 hari);
                       data event (GetObject dll.) TIDAK aktif bawaan
Azure Activity Log   : log operasi pengelolaan Azure; aktif bawaan 90 hari; perpanjang via diagnostic setting
Field CloudTrail     : eventTime (UTC), eventName, awsRegion, userIdentity, sourceIPAddress, errorCode
```

## 7. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Microsoft 365 adalah SaaS, jadi bila ada file rahasia PT JAB yang dibagikan ke publik lewat OneDrive, itu tanggung jawab Microsoft." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Di model SaaS, penyedia menjaga hampir semua lapisan teknis, tetapi data, identitas, serta konfigurasi dan pengaturan tetap tanggung jawab pelanggan di semua model layanan. Pengaturan berbagi file adalah konfigurasi yang dibuat pengguna PT JAB, dan file yang dibagikan adalah data PT JAB. Microsoft bertanggung jawab bila layanannya sendiri membocorkan data ke pelanggan lain, bukan bila pelanggan sengaja atau tidak sengaja membuka filenya. Lihat bagian 1.2 dan 1.3.

</details>

**2. Skenario keputusan.** Kamu menemukan event CloudTrail berikut di akun MyJAB: `eventName=RunInstances` (perintah menyalakan server EC2), `awsRegion=sa-east-1` (region São Paulo), `userIdentity.type=IAMUser`, `accessKeyId=AKIA...`, `sourceIPAddress=192.0.2.151`, jam 02:14 WIB. PT JAB hanya memakai region `ap-southeast-3` dan sudah tidak membuat IAM user untuk manusia. Apa langkah yang paling tepat?

- A. Tutup sebagai aktivitas sah, karena access key yang dipakai milik akun PT JAB sendiri.
- B. Perlakukan sebagai kemungkinan access key bocor: nonaktifkan key itu, periksa semua event CloudTrail yang memakai key itu sejak dibuat, dan cari resource yang dibuat di region yang tidak biasa.
- C. Hapus semua server di region `sa-east-1`, lalu tutup alert tanpa memeriksa log lebih jauh.

<details><summary>Jawaban</summary>

B. Kombinasi tandanya kuat: key permanen berawalan `AKIA` dari IAM user (yang seharusnya sudah tidak dipakai manusia), region yang tidak pernah dipakai PT JAB, alamat luar, dan jam dini hari. Pola ini sama dengan `INC-2026-025`. A keliru karena kredensial yang sah tidak berarti pemakainya sah; siapa pun yang memegang key dianggap pemiliknya. C keliru karena menghapus server hanya membersihkan satu jejak; tanpa memeriksa log selama key hidup, kamu tidak tahu apakah pelaku juga membuat user baru, mengubah izin, atau menyalin data. Lihat bagian 1.1, 1.5, dan 3.4.

</details>

**3. Pertanyaan jebakan.** "Block Public Access di tingkat bucket sudah dimatikan, jadi bucket itu pasti publik." Benarkah?

<details><summary>Jawaban</summary>

Belum tentu. Ada dua syarat lain. Pertama, S3 memakai kombinasi pengaturan yang paling ketat dari tingkat organisasi, akun, dan bucket, jadi bila Block Public Access aktif di tingkat akun, bucket itu tetap terlindungi. Kedua, mematikan gembok tidak otomatis membuka bucket; harus ada ACL publik atau bucket policy yang mengizinkan semua orang. Di kasus `SOC-2027-0843`, bucket menjadi publik karena ketiganya terjadi bersamaan: gembok akun tidak ada, gembok bucket dimatikan, dan policy dengan `"Principal": "*"` dipasang. Lihat bagian 1.6 dan 2.1.

</details>

**4. Skenario keputusan.** Direktur Teknologi, Hendra Wijaya, ingin membeli satu alat untuk mencegah terulangnya kasus `SOC-2027-0843`. Vendor menawarkan tiga produk. Mana yang paling langsung menjawab masalah itu?

- A. CWPP berbasis agen untuk semua VM di AWS.
- B. CSPM yang membaca konfigurasi semua akun AWS dan subscription Azure, ditambah rule real-time di SIEM untuk perubahan Block Public Access dan bucket policy.
- C. CASB yang membaca log proxy kantor.

<details><summary>Jawaban</summary>

B. Masalahnya adalah pengaturan layanan cloud milik PT JAB, dan itu wilayah CSPM. Karena CSPM memeriksa secara berkala, rule real-time di SIEM yang membaca CloudTrail menutup jeda belasan jam antara perubahan dan temuan. A keliru karena CWPP melihat dari dalam workload, sedangkan bucket bukan workload dan tidak dipasangi agen. C keliru karena CASB mengawasi aplikasi cloud yang dipakai karyawan, bukan pengaturan akun AWS milik perusahaan. Lihat bagian 1.7, 1.8, 1.9, dan 2.2.

</details>

**5. Jelaskan ulang.** Jelaskan kepada anggota keluargamu yang bukan orang IT, dalam tiga kalimat, kenapa data perusahaan bisa bocor dari "cloud" walaupun penyedia cloud-nya tidak diretas.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Menyimpan data di cloud itu seperti menyewa apartemen: pengelola gedung menjaga gerbang, lift, dan dinding, tapi kunci pintu unit tetap dipegang penyewa. Kalau penyewa lupa mengunci pintu atau menaruh lemari arsipnya di lobi, pencuri bisa mengambil isinya tanpa perlu membobol gedung. Kebanyakan kebocoran di cloud terjadi seperti itu, karena pengaturan yang salah atau kunci yang tercecer, bukan karena gedung penyedianya jebol."

Kesalahan yang sering muncul:
- Mengatakan cloud "tidak aman", padahal masalahnya ada di pembagian tanggung jawab, bukan di cloud itu sendiri.
- Memakai istilah teknis seperti bucket, IAM, atau misconfiguration tanpa penjelasan.
- Lupa menyebut bahwa penyewa juga memegang "kunci duplikat" (kredensial) yang bisa tercecer.

</details>

**6. Pertanyaan jebakan.** "Kita punya CloudTrail aktif di akun MyJAB, jadi kita pasti bisa tahu siapa saja yang mengunduh file dari bucket promo selama bucket itu publik." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Secara bawaan CloudTrail hanya mencatat management event, yaitu operasi pengelolaan seperti `CreateBucket`, `PutBucketPublicAccessBlock`, dan `PutBucketPolicy`. Pembacaan file (`GetObject`) adalah data event yang harus dinyalakan terpisah per jenis resource dan berbiaya tambahan, dan di PT JAB tidak dinyalakan untuk bucket itu. Karena itu kamu bisa tahu siapa yang membuka bucket ke publik, tetapi tidak bisa tahu siapa yang mengambil isinya, sehingga kasusnya diperlakukan sebagai kemungkinan kebocoran. Lihat bagian 1.10 dan 2.2.

</details>

**7. Interview question (English).** "Explain the cloud shared responsibility model, and give an example of a cloud incident that is clearly on the customer's side."

<details><summary>Sample answer</summary>

"The shared responsibility model splits security between the cloud provider and the customer. AWS describes it as security of the cloud versus security in the cloud: the provider protects the physical data centers, hardware, hypervisor and the services themselves, while the customer protects what they put in and configure on top. Where the line sits depends on the service model. With IaaS, like EC2, the customer still patches the operating system and manages network rules; with PaaS, like S3, the provider runs the platform; with SaaS, like Microsoft 365, the provider runs almost everything. But three things never move to the provider in any model: the data, the identities and permissions, and the configuration settings. A clear customer-side example is a storage bucket made public. A developer disables Block Public Access on the bucket and attaches a bucket policy that allows anyone to read objects. Nothing in the provider was breached; the customer's own role had permission to do it. As an analyst I would confirm the change in CloudTrail management events, check whether the identity was compromised or just over-privileged, close the exposure, and then check whether data events or access logs exist to tell us who downloaded anything. If they don't, we have to treat it as a possible data breach."

What makes this answer strong: it uses the provider's own framing, shows how the line shifts across IaaS, PaaS and SaaS instead of reciting a definition, names the three responsibilities that never move, and turns the concept into concrete analyst actions, including the common blind spot that object-level access is not logged by default.

</details>

## 8. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | NIST SP 800-145: The NIST Definition of Cloud Computing | https://csrc.nist.gov/pubs/sp/800/145/final<br>https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-145.pdf | primer | 2011-09; diakses 2026-10-21 | Tinggi. Lima ciri pokok, tiga model layanan, empat model penempatan; status final tanpa revisi |
| S2 | AWS: Shared Responsibility Model | https://aws.amazon.com/compliance/shared-responsibility-model/ | primer (dokumentasi penyedia) | diakses 2026-10-21 | Tinggi. "Security of" vs "security in" the cloud, contoh EC2 vs S3, kontrol bersama |
| S3 | Microsoft Learn: Shared responsibility in the cloud | https://learn.microsoft.com/en-us/azure/security/fundamentals/shared-responsibility | primer (dokumentasi penyedia) | diperbarui 2026-08-24; diakses 2026-10-21 | Tinggi. Matriks tanggung jawab on-premises, IaaS, PaaS, SaaS; contoh layanan per model |
| S4 | AWS IAM User Guide: IAM roles | https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html | primer | diakses 2026-10-21 | Tinggi. Role vs user, kredensial sementara, trust policy, durasi sesi maksimal 12 jam |
| S5 | AWS IAM User Guide: Policies and permissions in IAM | https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html | primer | diakses 2026-10-21 | Tinggi. Jenis policy, elemen JSON, contoh `Condition` MFA, saran least privilege |
| S6 | AWS IAM User Guide: Policy evaluation logic | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html | primer | diakses 2026-10-21 | Tinggi. Gabungan policy identitas dan sumber daya; Deny eksplisit mengalahkan Allow |
| S7 | AWS IAM User Guide: Security best practices in IAM | https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html | primer | diakses 2026-10-21 | Tinggi. Federation dan kredensial sementara untuk manusia dan workload, rotasi access key, MFA tahan phishing |
| S8 | AWS IAM User Guide: IAM identifiers | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html | primer | diakses 2026-10-21 | Tinggi. Format ARN, ARN assumed-role, awalan `AKIA` dan `ASIA`, IAM bersifat global |
| S9 | Amazon S3 User Guide: Blocking public access to your Amazon S3 storage | https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html | primer | diakses 2026-10-21 | Tinggi. Empat pengaturan, tingkat organisasi/akun/bucket/access point, arti "public" untuk ACL dan policy |
| S10 | AWS What's New: Amazon S3 now applies two security best practices to all new buckets by default | https://aws.amazon.com/about-aws/whats-new/2023/04/amazon-s3-security-best-practices-buckets-default | primer (pengumuman penyedia) | 2023-04-28; diakses 2026-10-21 | Tinggi. Block Public Access aktif dan ACL nonaktif bawaan, peluncuran mulai 2023-04-05 |
| S11 | AWS CloudTrail User Guide: What is AWS CloudTrail; CloudTrail concepts | https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html<br>https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html | primer | diakses 2026-10-21 | Tinggi. Event history 90 hari, trail, management vs data event, data event tidak aktif bawaan dan berbayar |
| S12 | AWS CloudTrail User Guide: CloudTrail record contents | https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html | primer | diakses 2026-10-21 | Tinggi. Field event, `eventTime` dalam UTC, versi format 1.11 |
| S13 | Amazon S3 User Guide: Amazon S3 CloudTrail events | https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html | primer | diakses 2026-10-21 | Tinggi. Aksi tingkat bucket yang tercatat bawaan (`PutBucketPolicy`, `PutBucketPublicAccessBlock`), object-level tidak |
| S14 | Microsoft Learn: Activity Log in Azure Monitor | https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/activity-log | primer | diperbarui 2026-05-04; diakses 2026-10-21 | Tinggi. Control plane vs data plane, aktif bawaan, retensi 90 hari, diagnostic setting, pembuat resource |
| S15 | Microsoft Learn: What is Azure role-based access control (Azure RBAC)? | https://learn.microsoft.com/en-us/azure/role-based-access-control/overview | primer | 2024-03-12; diakses 2026-10-21 | Tinggi. Role assignment = principal, role definition, scope; empat tingkat scope |
| S16 | Microsoft Learn: Microsoft Defender for Cloud overview | https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction | primer (dokumentasi vendor) | 2026-08-10; diakses 2026-10-21 | Tinggi untuk produk Microsoft. Definisi CNAPP, CSPM, CWPP versi Microsoft, dukungan AWS |
| S17 | Microsoft Learn: Overview of Microsoft Defender for Cloud Apps | https://learn.microsoft.com/en-us/defender-cloud-apps/what-is-defender-for-cloud-apps | primer (dokumentasi vendor) | 2024-06-14; diakses 2026-10-21 | Tinggi untuk produk Microsoft. Fungsi CASB, cloud discovery, lebih dari 90 indikator risiko |
| S18 | Cisco: What Is a CASB? | https://www.cisco.com/c/en/us/products/security/what-is-a-casb.html | sekunder (vendor) | diakses 2026-10-21 | Sedang. Definisi CASB dan empat pilar yang dirumuskan Gartner; halaman Gartner sendiri tidak dapat diakses |
| S19 | Palo Alto Networks Cyberpedia: What Is CWPP? | https://www.paloaltonetworks.com/cyberpedia/what-is-cwpp-cloud-workload-protection-platform | sekunder (vendor) | diakses 2026-10-21 | Sedang. Jenis workload, kemampuan umum, agen vs tanpa agen, beda dengan CSPM |
| S20 | Cloud Security Alliance: Cloud Security Alliance Releases Top Threats to Cloud Computing 2024 Report | https://cloudsecurityalliance.org/press-releases/2024/08/06/cloud-security-alliance-releases-top-threats-to-cloud-computing-2024-report | sekunder (organisasi industri) | 2024-08-06; diakses 2026-10-21 | Sedang sampai tinggi. Sebelas ancaman, misconfiguration urutan pertama; berbasis survei pakar, bukan data insiden |
| S21 | CISA: CISA and NSA Release Cybersecurity Information Sheets on Cloud Security Best Practices | https://cisa.gov/news-events/alerts/2024/03/07/cisa-and-nsa-release-cybersecurity-information-sheets-cloud-security-best-practices | primer | 2024-03-07; diakses 2026-10-21 | Tinggi. Lima lembar informasi bersama CISA dan NSA |
| S22 | Infosecurity Magazine: NSA Launches Top 10 Cloud Security Mitigation Strategies | https://www.infosecurity-magazine.com/news/nsa-top-10-cloud-security/ | sekunder (media) | 2024-03-11; diakses 2026-10-21 | Sedang. Daftar sepuluh strategi NSA; siaran pers NSA dan PDF di media.defense.gov tidak dapat diakses saat riset |
| S23 | AWS Documentation: AWS Regions | https://docs.aws.amazon.com/global-infrastructure/latest/regions/aws-regions.html | primer | diakses 2026-10-21 | Tinggi. `ap-southeast-3` Asia Pacific (Jakarta), tiga AZ, region opt-in |
| S24 | Microsoft Learn: New name for Azure Active Directory | https://learn.microsoft.com/en-us/entra/fundamentals/new-name | primer | diperbarui 2025-05-07; diakses 2026-10-21 | Tinggi. Azure AD menjadi Microsoft Entra ID (diumumkan 2023-07-11), alasan penggantian nama, Active Directory on-premises tidak berganti nama |

**Catatan sumber:** definisi CSPM di bagian 1.7 disusun dari deskripsi Microsoft [S16] karena halaman glosarium Gartner untuk CSPM, CASB, dan CWPP tidak dapat diakses; definisi CASB dan empat pilarnya diambil dari ringkasan Cisco atas rumusan Gartner [S18], dan definisi CWPP dari Palo Alto Networks [S19], keduanya sumber vendor. Daftar sepuluh strategi NSA berasal dari media [S22] karena dokumen NSA sendiri tidak dapat diakses; yang dikonfirmasi sumber primer hanya lima lembar yang diterbitkan bersama CISA [S21]. Peringkat CSA [S20] adalah hasil survei pakar, bukan statistik insiden, jadi dipakai sebagai gambaran prioritas, bukan angka frekuensi. Pengelompokan S3 sebagai "lebih dekat ke PaaS" mengikuti contoh Microsoft yang memasukkan Azure Storage ke PaaS [S3] dan deskripsi AWS tentang layanan yang diabstraksi [S2]; sebagian sumber lain memasukkan penyimpanan objek ke IaaS. Contoh misconfiguration selain bucket publik di bagian 1.6 adalah susunan catatan ini. Seluruh isi PT JAB (alert `SOC-2027-0843` sampai `0845`, insiden `INC-2027-087`, nama bucket, role, akun, angka, dan waktu) adalah contoh fiktif.
