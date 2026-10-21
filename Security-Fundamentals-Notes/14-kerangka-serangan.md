---
day: 14
title: 'Kerangka serangan: Cyber Kill Chain, MITRE ATT&CK, Diamond Model, APT, dan kategori threat actor'
researched_on: 2026-10-21
versions_checked: 'MITRE ATT&CK v20.0 (13 Okt 2026), v19 (28 Apr 2026, Defense Evasion dipecah menjadi Stealth dan Defense Impairment), v18 (28 Okt 2025); ATT&CK: Design and Philosophy (revisi Maret 2020); Hutchins, Cloppert, Amin: Intrusion Kill Chains (Lockheed Martin, 2011); Caltagirone, Pendergast, Betz: The Diamond Model of Intrusion Analysis (2013); Unified Kill Chain (Pols, 2017, whitepaper 2021); MITRE D3FEND 1.6.0; NIST CSRC Glossary; CISA Defining Insider Threats dan Nation-State Cyber Actors; ENISA Threat Landscape 2025 (Okt 2025)'
---

# Day 14: Kerangka serangan (Cyber Kill Chain, MITRE ATT&CK, Diamond Model, APT, dan threat actor)

Cakupan: tiga cara baku untuk menggambarkan sebuah serangan, yaitu Cyber Kill Chain (tahapan), MITRE ATT&CK (katalog tujuan dan cara: tactic, technique, sub-technique, procedure), dan Diamond Model (empat unsur satu kejadian), ditambah istilah untuk pelakunya: APT dan kategori threat actor (nation-state, cybercrime, hacktivist, insider).

## Ide inti

Sebuah serangan jarang terjadi dalam satu langkah. Pelaku mencari target, menyiapkan alat, masuk, bertahan, berpindah, lalu baru mengerjakan tujuannya. Kerangka serangan adalah cara baku untuk memotong rangkaian itu menjadi bagian yang punya nama, supaya analyst, atasan, dan tim lain membicarakan hal yang sama dengan kata yang sama. Tanpa kerangka, laporan insiden hanya berupa kronologi jam per jam yang sulit dibandingkan dengan insiden lain dan sulit diubah menjadi perbaikan.

Tiga kerangka di Day ini menjawab pertanyaan yang berbeda, jadi ketiganya saling melengkapi, bukan saling menggantikan. Cyber Kill Chain menjawab "serangan ini sudah sampai tahap mana, dan di tahap mana seharusnya bisa diputus". MITRE ATT&CK menjawab "pada setiap langkah, apa tujuan pelaku dan cara apa yang dipakai", dengan nomor baku yang dipakai alert, laporan intelijen, dan alat keamanan di seluruh dunia. Diamond Model menjawab "siapa, memakai kemampuan apa, lewat infrastruktur apa, terhadap korban siapa", sehingga satu kejadian bisa dihubungkan dengan kejadian lain. Istilah pelaku (threat actor, APT, nation-state, cybercrime, hacktivist, insider) dipakai untuk mengisi sudut pelaku itu dengan hati-hati: menebak kategori pelaku jauh lebih mudah daripada membuktikan nama pelakunya.

Bayangkan sebuah perampokan bank. Polisi bisa menceritakannya sebagai tahapan, dari survei lokasi sampai kabur membawa uang (Kill Chain). Polisi juga punya buku katalog modus kejahatan, yang mencatat tujuan (masuk gedung, membuka brankas), cara (mencongkel pintu belakang, menyamar sebagai petugas kebersihan), dan cara khas komplotan tertentu (komplotan X selalu masuk lewat atap pada malam Minggu) (ATT&CK). Saat menyelidiki, detektif memasang papan investigasi dengan empat sudut: pelaku, kemampuan, kendaraan dan rumah persembunyian, serta korban, lalu menarik benang antar sudut (Diamond Model). Batas analogi ini: serangan siber tidak selalu berjalan lurus dari tahap satu ke tahap tujuh, pelaku bisa mengulang tahap di dalam jaringan, dan pelaku digital jarang meninggalkan wajah di CCTV, sehingga sudut "pelaku" di papan sering tetap kosong.

```
                 CYBER KILL CHAIN              MITRE ATT&CK                      DIAMOND MODEL
 pertanyaan      "sudah sampai tahap mana?"    "tujuannya apa, caranya apa?"     "siapa, pakai apa, lewat mana,
                                                                                  terhadap siapa?"
 bentuk          7 tahap berurutan             matriks: kolom tactic (tujuan),   satu kejadian = 4 sudut
                                               sel technique (cara), plus        (adversary, capability,
                                               procedure (cara pelaku tertentu)   infrastructure, victim)
 paling berguna  memilih titik memutus         memberi label alert, mengukur     menghubungkan kejadian,
 untuk           serangan                      cakupan deteksi, bahasa bersama   pivot, dasar menilai pelaku
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan dan sekitar 400 ribu pelanggan internet rumah. Kamu adalah analyst L1 (lapis pertama yang memeriksa alert) di SOC PT JAB, tim yang memantau keamanan perusahaan 24 jam. Alert adalah peringatan otomatis dari sistem pemantauan, dan insiden adalah kejadian yang sudah dipastikan merugikan dan ditangani secara resmi. Pada Oktober 2026, sebelum kamu bergabung, PT JAB terkena ransomware (program jahat yang mengunci file lalu meminta tebusan; jenis-jenisnya dibahas di Day 16) yang tercatat sebagai insiden `INC-2026-017`: pelaku masuk lewat server aplikasi lama `jkt-dmz-app01` yang tidak dipasangi EDR (agen pengawas perilaku program di komputer dan server, Day 06), lalu mengenkripsi folder bersama (share) divisi Keuangan di file server `JKT-FS01`.

Jumat 2027-08-20, hari ke-14 orientasi, pukul 08:30, SOC lead Dimas Prasetyo mengirim pesan:

> "Laporan `INC-2026-017` masih berupa kronologi jam per jam. Untuk latihan, coba petakan ke Cyber Kill Chain dan MITRE ATT&CK. Pertama, tahap Kill Chain mana saja yang dilalui pelaku, dan di tahap mana seharusnya kita bisa memutusnya? Kedua, aku curiga ada bagian yang tidak muat di Kill Chain; benar begitu, dan adakah model yang lebih pas? Ketiga, ATT&CK itu sebenarnya apa, dan matriks mana yang kita pakai? Keempat, pisahkan tactic, technique, sub-technique, dan procedure di pemetaanmu; kenapa satu teknik bisa muncul di beberapa kolom? Kelima, alert kita sekarang diberi label seperti T1490; apa arti angka itu, dan kenapa di dashboard baru tidak ada lagi kolom Defense Evasion? Keenam, susun temuan dengan Diamond Model supaya bisa dihubungkan dengan serangan lain."

Sari Kusuma, mentormu (analyst L2), menambahkan di bawahnya:

> "Satu lagi dari aku: siapa kira-kira pelakunya? Pak Hendra pernah tanya di rapat apakah itu APT negara asing atau geng ransomware biasa. Jawab dengan alasan, bukan tebakan."

Dua pesan itu memuat tujuh pertanyaan:

1. Tahap Kill Chain mana saja yang dilalui pelaku, dan di mana seharusnya bisa diputus?
2. Bagian mana yang tidak muat di Kill Chain, dan adakah model yang lebih pas?
3. Apa itu MITRE ATT&CK, dan matriks mana yang dipakai?
4. Apa beda tactic, technique, sub-technique, dan procedure, dan kenapa satu teknik bisa muncul di beberapa kolom?
5. Apa arti label seperti T1490, dan kenapa kolom Defense Evasion hilang?
6. Bagaimana menyusun temuan dengan Diamond Model?
7. Siapa kira-kira pelakunya: APT negara atau kelompok cybercrime?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, 1.5, dan 1.6, pertanyaan 5 di bagian 1.4 dan 1.5, pertanyaan 6 di bagian 1.7, dan pertanyaan 7 di bagian 1.8 dan 1.9. Bagian 2 berisi pemetaan lengkap `INC-2026-017` dan empat alert hari ini (`SOC-2027-0876` sampai `SOC-2027-0879`) yang dibaca dengan kerangka yang sama.

**Kapan relevan:** saat menulis ringkasan alert atau laporan insiden, saat membaca laporan intelijen ancaman yang memakai nomor teknik ATT&CK, saat menilai seberapa jauh serangan sudah berjalan (alert di tahap akhir jauh lebih mendesak daripada di tahap awal), saat mencari bagian pertahanan yang kosong, dan saat menjawab pertanyaan interview tentang Kill Chain dan ATT&CK.
**Kapan bukan jawaban:** kerangka tidak menggantikan bukti. Memberi label T1486 pada alert tidak membuktikan ada enkripsi, dan menempelkan nama kelompok APT tanpa bukti hanya menambah kebingungan. Kerangka juga bukan prosedur respons; saat ransomware sedang berjalan, isolasi host lebih dulu, pemetaan dikerjakan sesudahnya.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (threat, threat actor, vulnerability, exploit, risk di Day 01; port scan di Day 02; EDR di Day 06; phishing di Day 09) tidak diulang di tabel ini, kecuali bila Day ini memberinya arti tambahan. Kolom padanan memakai analogi perampokan bank dan kantor polisi yang dipakai sepanjang Day ini.

| Istilah | Arti singkat | Padanan sehari-hari |
|---|---|---|
| Kerangka serangan | Cara baku menggambarkan serangan dengan bagian yang punya nama | Format laporan polisi yang dipakai semua kantor polisi |
| Cyber Kill Chain | Model tujuh tahap serangan dari Lockheed Martin | Tahapan perampokan bank dari survei lokasi sampai kabur membawa uang |
| Courses of action | Daftar tindakan bertahan per tahap (detect, deny, disrupt, degrade, deceive, destroy) | Rencana pengamanan bank per tahap perampokan |
| Unified Kill Chain | Model 18 tahap yang menggabungkan Kill Chain dan ATT&CK | Tahapan perampokan yang juga mencatat gerak di dalam gedung |
| MITRE ATT&CK | Basis pengetahuan perilaku penyerang dari pengamatan nyata | Buku katalog modus kejahatan milik polisi |
| Matrix | Tabel ATT&CK: kolom tactic, isi technique | Daftar isi katalog per tujuan kejahatan |
| Domain (Enterprise, Mobile, ICS) | Kelompok matriks menurut jenis teknologi | Katalog terpisah untuk bank, toko HP, dan pabrik |
| Tactic | Tujuan jangka pendek pelaku pada satu langkah ("kenapa") | Tujuan modus: masuk gedung, membuka brankas |
| Technique | Cara mencapai tujuan itu ("bagaimana") | Cara: mencongkel pintu belakang |
| Sub-technique | Varian yang lebih spesifik dari sebuah technique | Mencongkel pintu belakang dengan linggis vs dengan kunci palsu |
| Procedure | Cara spesifik yang benar-benar dipakai pelaku tertentu | Komplotan X selalu masuk lewat atap pada malam Minggu |
| TTP | Tactics, techniques, and procedures; gaya kerja pelaku | Ciri khas modus satu komplotan |
| Group | Kumpulan aktivitas yang dilacak dengan satu nama di komunitas | Berkas komplotan di kantor polisi |
| Campaign | Rangkaian intrusi dalam periode tertentu dengan target dan tujuan yang sama | Serangkaian perampokan bank di satu kota selama satu bulan |
| Diamond Model | Model satu kejadian intrusi dengan empat sudut | Papan investigasi detektif dengan empat sudut |
| Adversary | Pelaku atau organisasi di balik kejadian | Sudut pelaku di papan |
| Capability | Alat dan teknik yang dipakai pelaku | Sudut kemampuan: linggis, kunci palsu, keahlian |
| Infrastructure | Saluran fisik atau logis yang dipakai pelaku (IP, domain, email) | Kendaraan, nomor telepon, rumah persembunyian |
| Victim | Target dan aset yang diserang | Bank dan brankasnya |
| Pivot | Memakai satu temuan untuk menemukan temuan lain yang terkait | Melacak plat nomor mobil untuk menemukan rumah persembunyian |
| Threat actor (kategori) | Pelaku dikelompokkan menurut motif dan sumber daya | Jenis pelaku: agen asing, komplotan perampok, demonstran, orang dalam |
| Nation-state actor | Pelaku yang bekerja untuk atau atas dukungan negara | Agen intelijen asing |
| Cybercrime | Kejahatan siber yang terutama mengejar uang | Komplotan perampok bank |
| Hacktivist | Pelaku yang menyerang untuk pesan politik atau sosial | Demonstran yang mencoret tembok kantor |
| Insider | Orang yang punya atau pernah punya akses sah ke organisasi | Pegawai yang memegang kunci |
| APT | Advanced persistent threat; pelaku bersumber daya besar yang bertahan lama | Komplotan profesional yang menyewa ruko di seberang bank berbulan-bulan |
| Atribusi | Menentukan siapa pelaku sebuah serangan | Menetapkan tersangka |
| D3FEND | Katalog tindakan bertahan dari MITRE, pasangan ATT&CK | Buku pedoman pengamanan milik satpam |
| Lateral movement | Berpindah dari satu komputer ke komputer lain di dalam jaringan; dibahas di Day 15 | Pindah dari lobi ke ruang brankas |

### 1.1 Cyber Kill Chain

Pertanyaan pertama Dimas meminta kamu melihat `INC-2026-017` sebagai rangkaian tahap, bukan sebagai satu kejadian "server kena ransomware". Kerangka tahapan yang paling tua dan paling sering disebut adalah Cyber Kill Chain.

**Apa itu:** Cyber Kill Chain adalah model yang membagi sebuah intrusi (masuknya penyerang ke sistem) menjadi tujuh tahap yang harus dilalui pelaku untuk mencapai tujuannya [S20][S21]. Model ini diperkenalkan peneliti Lockheed Martin, Eric Hutchins, Michael Cloppert, dan Rohan Amin, dalam paper tentang pertahanan jaringan yang digerakkan intelijen (intelligence-driven computer network defense) [S20]. Nama "kill chain" dipinjam dari doktrin militer AS: proses menemukan, mengunci posisi, melacak, membidik, menyerang, dan menilai hasil. Disebut rantai karena kekurangan di satu mata rantai saja memutus seluruh proses [S20]. Lockheed Martin menyebut tujuh tahap itu membantu analyst memahami TTP pelaku [S21].

Tujuh tahapnya, diringkas dari paper aslinya [S20]:

1. **Reconnaissance:** meneliti, mengenali, dan memilih target, misalnya mengumpulkan alamat email dari situs web, hubungan sosial, atau teknologi yang dipakai target.
2. **Weaponization:** menggabungkan program pengendali jarak jauh dengan exploit menjadi muatan (payload) yang siap dikirim, sering berupa dokumen PDF atau Office.
3. **Delivery:** mengirim "senjata" itu ke lingkungan target. Tim respons Lockheed Martin mencatat tiga jalur tersering pada 2004 sampai 2010: lampiran email, situs web, dan USB [S20].
4. **Exploitation:** memicu kode pelaku di komputer korban. Biasanya lewat kerentanan aplikasi atau sistem operasi, tetapi bisa juga dengan menipu user agar menjalankannya sendiri [S20].
5. **Installation:** memasang program pengendali (backdoor) supaya pelaku bisa kembali, yaitu persistence (bertahan di sistem; dibahas di Day 16).
6. **Command and Control (C2):** komputer korban menghubungi server kendali milik pelaku di internet, biasanya secara berkala (beacon). Setelah saluran ini terbentuk, pelaku bisa mengetik perintah langsung di dalam jaringan korban [S20].
7. **Actions on Objectives:** baru sekarang pelaku mengerjakan tujuan sebenarnya: mencuri data, merusak keutuhan atau ketersediaan sistem, atau memakai komputer pertama sebagai batu loncatan ke komputer lain [S20].

**Analogi:** perampokan bank. Komplotan mensurvei lokasi dan jadwal satpam (reconnaissance), menyiapkan linggis dan kunci palsu (weaponization), membawa alat itu ke bank (delivery), membobol pintu belakang (exploitation), menyembunyikan kunci duplikat supaya bisa kembali (installation), memakai walkie-talkie untuk menerima perintah dari bos di mobil (C2), lalu membuka brankas dan kabur membawa uang (actions on objectives). Batasnya ada tiga. Pertama, perampokan nyata hampir selalu berurutan, sedangkan serangan siber bisa melompat dan mengulang tahap: pelaku yang memakai password curian tidak butuh weaponization. Kedua, dua tahap pertama terjadi di luar bank, jadi bank hampir tidak bisa melihatnya. Ketiga, orang dalam yang sudah memegang kunci tidak melewati sebagian besar tahap ini.

**Cara kerja:** nilai utama Kill Chain bukan daftar tahapnya, tetapi cara berpikirnya: pelaku harus menyelesaikan semua tahap, sedangkan pembela cukup memutus satu tahap. Paper aslinya menyebut satu mitigasi saja sudah memutus rantai [S20]. Karena itu, untuk setiap tahap, pembela menyusun courses of action, yaitu tindakan bertahan yang dipinjam dari doktrin operasi informasi militer: detect (mengetahui), deny (menolak), disrupt (mengganggu saat berjalan), degrade (memperlambat atau melemahkan), deceive (menipu), dan destroy (menghancurkan) [S20]. Contoh di paper: pada tahap exploitation, HIDS mendeteksi, patch menolak, dan fitur pencegah eksekusi memori mengganggu exploit yang sudah berjalan [S20].

```
  luar jaringan korban (sulit dilihat)          di dalam lingkungan korban (bisa dilihat)
 +--------------------------------------+   +-----------------------------------------------------+
 | 1 Reconnaissance                     |   | 4 Exploitation  ->  5 Installation  ->  6 C2         |
 | 2 Weaponization                      |   |                                         |            |
 | 3 Delivery (perbatasan: email, web)  |-->|                                 7 Actions on         |
 +--------------------------------------+   |                                   Objectives         |
                                             +-----------------------------------------------------+
  pembela cukup memutus SATU mata rantai; makin awal diputus, makin kecil kerugiannya
```

Satu hal lagi yang ditekankan paper itu: pelaku cenderung memakai ulang bagian rangkaiannya (alat, alamat server, pola email). Bila satu tahap tercatat rapi, serangan berikutnya dari pelaku yang sama bisa diputus lebih awal, walaupun exploit-nya baru [S20].

**Contoh di PT JAB:** ringkasnya, `INC-2026-017` melalui semua tahap. Pelaku memindai IP publik PT JAB (reconnaissance), memakai exploit untuk komponen web lama (weaponization, tidak terlihat), mengirim permintaan HTTP berisi exploit ke `jkt-dmz-app01` (delivery), menjalankan kodenya di server itu (exploitation), menanam web shell (installation), membuka saluran HTTPS ke server kendali (C2), lalu mencuri password akun layanan, berpindah ke `JKT-FS01`, menghapus salinan pemulihan, dan mengenkripsi share Keuangan (actions on objectives). Tabel lengkap dengan waktu, bukti, dan titik putus ada di bagian 2.1.

**Beda dengan siklus respons insiden:** Kill Chain menggambarkan langkah pelaku. Siklus respons insiden (persiapan, deteksi dan analisis, containment, eradication, recovery; Day 19) menggambarkan langkah pembela. Keduanya bertemu di titik deteksi: tahap Kill Chain tempat serangan terdeteksi menentukan seberapa besar kerusakan yang harus dipulihkan.

**Salah paham umum:**
- "Kill Chain hanya untuk malware lewat email." Model ini memang lahir dari serangan berbasis malware dan lampiran [S20], tetapi tahapnya bisa dipakai untuk serangan lewat aplikasi web, VPN, atau akun curian, selama kamu ingat bahwa sebagian tahap bisa dilewati.

### 1.2 Batas Kill Chain dan Unified Kill Chain

Pertanyaan kedua Dimas muncul saat kamu mengisi tahap ketujuh. Dari pukul 01:10 sampai 04:40, pelaku mencuri password, berpindah server, menghapus salinan pemulihan, dan mengenkripsi file. Semua itu masuk satu kotak, actions on objectives, padahal di situlah sebagian besar pekerjaan SOC terjadi.

**Apa itu:** kritik yang paling sering terhadap Kill Chain ada tiga. Tahap awalnya terjadi di luar jaringan pembela sehingga sulit dideteksi, model ini dianggap memperkuat pola pikir pertahanan perimeter dan pencegahan malware, dan model ini kurang cocok untuk insider yang sudah berada di dalam [S24]. Unified Kill Chain (UKC) adalah model yang dikembangkan Paul Pols pada 2017, bersama Fox-IT dan Universitas Leiden, untuk menjawab kritik itu. UKC menggabungkan Kill Chain Lockheed Martin dengan MITRE ATT&CK menjadi 18 tahap yang mencakup aktivitas di luar dan di dalam jaringan [S23][S24]. Tahap-tahap itu dikelompokkan dalam tiga bagian besar: masuk (In), bergerak di dalam (Through), dan mengambil atau merusak (Out) [S23]. Whitepaper UKC yang lebih baru terbit 2021 [S24].

**Analogi:** laporan perampokan versi lama hanya menulis "pelaku masuk lalu membawa uang". Versi baru juga mencatat gerak di dalam gedung: pelaku mencari kunci di laci satpam, naik ke lantai dua, menonaktifkan alarm, baru membuka brankas. Batasnya: semakin rinci tahapnya, semakin banyak waktu untuk mengisinya; untuk ringkasan ke direksi, tujuh tahap sering sudah cukup.

**Cara kerja:** di lapangan, banyak SOC memakai Kill Chain untuk gambaran besar (sudah sampai mana) dan ATT&CK untuk rincian di dalam jaringan, bukan UKC secara penuh. UKC berguna terutama sebagai pengingat bahwa fase "Through" bisa mengulang tahap Kill Chain di setiap komputer baru: pelaku yang berpindah dari `jkt-dmz-app01` ke `JKT-FS01` pada dasarnya menjalankan rangkaian kecil eksploitasi dan pemasangan lagi di server kedua.

**Contoh di PT JAB:** di pemetaan `INC-2026-017`, kotak actions on objectives dipecah menjadi empat kegiatan yang punya titik putus berbeda: pencurian kredensial (bisa dicegah dengan tidak menyimpan password di file konfigurasi), perpindahan ke file server (bisa dicegah aturan firewall yang melarang DMZ menghubungi jaringan dalam, seperti yang sekarang berlaku), penghapusan salinan pemulihan, dan enkripsi. ATT&CK memberi nama dan nomor untuk keempatnya (bagian 2.2).

**Beda Unified Kill Chain dengan ATT&CK:** UKC tetap berbentuk urutan tahap. ATT&CK tidak mengatur urutan; ia katalog tujuan dan cara yang bisa dipakai dalam urutan apa pun.

### 1.3 MITRE ATT&CK: basis pengetahuan, matriks, dan domain

Pertanyaan ketiga Dimas: ATT&CK sebenarnya apa? Kamu sudah melihat nomornya di Day sebelumnya, misalnya T1046 di Day 02, T1499.004 di Day 04, T1558.003 di Day 07, dan T1566 di Day 09. Bagian ini menjelaskan dari mana nomor itu berasal.

**Apa itu:** MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) adalah basis pengetahuan dan model perilaku penyerang yang dikurasi MITRE, sebuah organisasi nirlaba di AS. Isinya disusun dari pengamatan serangan nyata, bukan dari daftar teori semua kemungkinan [S5]. Komponen intinya: tactic (tujuan jangka pendek pelaku), technique (cara mencapai tujuan itu), sub-technique (cara yang lebih spesifik), dan catatan penggunaan teknik oleh pelaku nyata, yaitu procedure [S5]. ATT&CK sengaja bukan daftar lengkap semua celah perangkat lunak; untuk itu MITRE punya katalog lain seperti CWE (jenis kelemahan, Day 17) [S5].

**Analogi:** buku katalog modus kejahatan milik polisi. Setiap bab adalah tujuan (masuk gedung, membuka brankas, kabur), setiap entri di bab adalah cara, dan setiap entri memuat contoh kasus nyata: komplotan mana yang pernah memakai cara itu dan bagaimana persisnya. Batasnya: katalog hanya memuat modus yang pernah teramati dan dilaporkan, jadi modus yang belum pernah tertangkap tidak ada di sana. Katalog juga tidak memberi peringkat bahaya, dan mencocokkan kejadian dengan entri katalog bukan bukti bahwa kejahatan itu terjadi.

**Cara kerja:** ATT&CK disajikan sebagai matrix, yaitu tabel dengan kolom berupa tactic dan isi kolom berupa technique. Satu matriks berlaku untuk satu domain teknologi. Tabel berikut merangkum tiga domain di ATT&CK v20 (terbit 13 Oktober 2026); cari kolom "Untuk" untuk menentukan matriks yang dipakai.

| Domain | Untuk | Tactic | Technique | Sub-technique |
|---|---|---|---|---|
| Enterprise | Jaringan perusahaan: Windows, Linux, macOS, cloud, perangkat jaringan, container | 15 | 227 | 479 |
| Mobile | Perangkat Android dan iOS | 12 | 78 | 47 |
| ICS | Sistem kendali industri (pembangkit, pabrik, pengolahan air) | 12 | 78 | 26 |

Angka di tabel berasal dari catatan rilis v20 [S3]. Platform yang bisa menjadi sasaran satu technique tercantum di halamannya; Exploit Public-Facing Application, misalnya, mencakup Windows, Linux, macOS, perangkat jaringan, IaaS, container, dan ESXi [S8].

Lima belas tactic Enterprise di v20, berurutan seperti di matriks [S1][S2]:

```
 TA0043 Reconnaissance        mengumpulkan informasi untuk merencanakan operasi
 TA0042 Resource Development  menyiapkan sumber daya (server, akun, alat)
 TA0001 Initial Access        masuk ke jaringan
 TA0002 Execution             menjalankan kode atau perintah
 TA0003 Persistence           mempertahankan pijakan
 TA0004 Privilege Escalation  mendapat hak yang lebih tinggi
 TA0005 Stealth               bersembunyi, tampak seperti aktivitas normal
 TA0112 Defense Impairment    merusak alat dan jalur pertahanan supaya pembela tidak bisa melihat
 TA0006 Credential Access     mencuri nama akun dan password
 TA0007 Discovery             memahami lingkungan korban
 TA0008 Lateral Movement      berpindah di dalam lingkungan
 TA0009 Collection            mengumpulkan data yang diincar
 TA0011 Command and Control   berkomunikasi dengan sistem yang dikuasai
 TA0010 Exfiltration          mencuri data keluar
 TA0040 Impact                memanipulasi, mengganggu, atau menghancurkan sistem dan data
```

Selain technique, ATT&CK juga mencatat group (kumpulan aktivitas yang dilacak dengan satu nama di komunitas keamanan), software (malware dan alat), dan campaign (rangkaian intrusi pada periode tertentu dengan target dan tujuan yang sama) [S18]. Halaman group dan campaign per Oktober 2026 memuat 182 group dan 61 campaign [S18].

Sejarah singkatnya menjelaskan kenapa ATT&CK berfokus pada perilaku setelah pelaku masuk. Model pertama dibuat September 2013 di lingkungan riset MITRE untuk meniru dan mendeteksi pelaku APT di jaringan Windows, dengan pola pikir "anggap saja pelaku sudah di dalam". Versi publik pertama terbit Mei 2015 dengan 96 technique dalam 9 tactic. Mac dan Linux masuk pada 2017, Mobile terbit 2017, cloud masuk ke Enterprise pada 2019, ICS terbit 2020, dan sub-technique ditambahkan pada 2020 [S5].

**Contoh di PT JAB:** PT JAB memakai matriks Enterprise untuk hampir semua pekerjaan SOC, karena sasaran yang dipantau adalah laptop Windows, server, AD, Microsoft 365, AWS, dan Azure. Matriks Mobile relevan bila suatu hari ada kasus HP karyawan yang dipakai untuk email kantor. Matriks ICS hampir tidak relevan untuk ISP seperti PT JAB, kecuali untuk sistem pendukung gedung data center bila kelak dipantau.

**Beda dengan Kill Chain:** paper desain ATT&CK sendiri menempatkan Kill Chain sebagai model tingkat tinggi yang berguna untuk memahami proses dan tujuan besar, tetapi kurang efektif untuk menggambarkan tindakan satu per satu, hubungan antar tindakan, dan kaitannya dengan sumber data dan pertahanan. ATT&CK menyebut dirinya model tingkat menengah, di antara model tingkat tinggi seperti Kill Chain dan database exploit atau malware yang sangat rinci [S5].

**Salah paham umum:**
- "ATT&CK adalah daftar periksa; kalau semua kotak sudah punya rule deteksi, kita aman." Satu technique bisa dijalankan dengan banyak procedure yang berbeda, jadi satu rule jarang mencakup seluruh technique. Paper desainnya mengingatkan bahwa membahas cakupan sebuah technique itu sulit karena procedure-nya tidak diketahui sebelumnya [S5].

### 1.4 Tactic

Pertanyaan keempat dan kelima Dimas dimulai dari kolom matriks. Setiap baris pemetaanmu harus menjawab: pada langkah ini, pelaku sedang berusaha mencapai apa?

**Apa itu:** tactic adalah "kenapa" sebuah technique dipakai, yaitu tujuan taktis pelaku: alasan ia melakukan sebuah tindakan [S5]. Contoh: bertahan di sistem, mencari informasi, berpindah ke komputer lain, menjalankan file, mencuri data keluar [S5]. Di ATT&CK, tactic berperan seperti label: satu technique ditempel ke satu atau lebih tactic sesuai hasil yang bisa dicapai dengannya [S5]. ID tactic diawali `TA`, misalnya `TA0040` untuk Impact [S2].

**Analogi:** bab di katalog polisi: "Masuk gedung", "Membuka brankas", "Menghilangkan jejak". Batasnya: satu perbuatan bisa masuk dua bab sekaligus. Kunci curian dipakai untuk masuk gedung, tetapi juga membuat pelaku terlihat seperti pegawai biasa.

**Cara kerja:** cara paling cepat menentukan tactic adalah membaca kalimat tujuan di halaman tactic: "The adversary is trying to ..." lalu mencocokkannya dengan apa yang dicapai pelaku pada langkah itu [S2]. Dua aturan membantu:

1. Tactic ditentukan oleh hasil yang dicapai, bukan oleh alatnya. PowerShell yang mengunduh file adalah Execution; PowerShell yang menghapus salinan pemulihan adalah bagian dari Impact.
2. Satu technique bisa tercantum di beberapa tactic. Valid Accounts (T1078), yaitu memakai akun sah yang dicuri, tercantum di Initial Access, Persistence, Privilege Escalation, dan Stealth, karena akun curian bisa dipakai untuk masuk, untuk kembali, untuk mendapat hak lebih tinggi, dan untuk tampak normal [S9]. Saat memetakan, pilih tactic yang sesuai konteks kejadianmu.

Ini menjawab pertanyaan Dimas tentang kolom yang hilang. Sampai v18, Enterprise punya 14 tactic, termasuk Defense Evasion [S4]. Di v19 (28 April 2026), MITRE memecah Defense Evasion menjadi dua tactic: Stealth, yang memakai ulang ID lama `TA0005`, dan Defense Impairment, tactic baru `TA0112` [S4][S7]. Stealth mencakup teknik untuk bersembunyi dan tampak seperti aktivitas normal tanpa mematikan pertahanan, misalnya menyamarkan nama file (Masquerading, T1036), mengaburkan isi file (Obfuscated Files or Information, T1027), dan menghapus jejak (Indicator Removal, T1070) [S7]. Defense Impairment mencakup teknik yang langsung merusak alat dan jalur pertahanan supaya pembela tidak bisa melihat atau tidak bisa memercayai apa yang terjadi, misalnya mematikan atau mengubah EDR, antivirus, IDS, dan agen log (Disable or Modify Tools, T1685) [S7]. Karena itu jumlah tactic Enterprise menjadi 15 [S1].

**Contoh di PT JAB:** dashboard SOC PT JAB yang menghitung alert per tactic dulu punya kolom Defense Evasion. Sejak rule deteksi dipetakan ulang ke versi baru, alert untuk percobaan mematikan Defender masuk kolom Defense Impairment, sedangkan alert untuk file yang menyamar sebagai program Windows masuk kolom Stealth. Laporan insiden 2026, termasuk `INC-2026-017`, masih memakai istilah lama, jadi kamu harus mengenali keduanya.

**Beda tactic dengan tahap Kill Chain:** tahap Kill Chain punya urutan tetap. Tactic ATT&CK tidak; urutan kolom di matriks hanya mengikuti alur yang umum. Pelaku bisa melakukan Discovery sebelum dan sesudah Lateral Movement, dan Credential Access bisa terjadi berkali-kali.

### 1.5 Technique dan sub-technique

Pertanyaan kelima Dimas menyebut label T1490 di alert. Label seperti itu adalah ID technique, dan bila ada titik serta tiga angka di belakangnya, ID sub-technique.

**Apa itu:** technique adalah "bagaimana" pelaku mencapai tujuan taktisnya dengan melakukan sebuah tindakan, misalnya mengambil kredensial dari sistem operasi untuk mendapatkan akun yang berguna [S5]. Untuk tactic Discovery, technique juga bisa berarti "apa" yang dicari pelaku [S5]. Sub-technique memecah technique menjadi cara yang lebih spesifik [S5]. Contoh dari paper desainnya: di bawah OS Credential Dumping ada sub-technique untuk mengambil kredensial dari memori LSASS (proses Windows yang mengelola login), dari database akun lokal (SAM), atau dari file `/etc/passwd` dan `/etc/shadow` di Linux [S5][S14].

**Analogi:** di bab "Membuka brankas", entri "Membobol kunci" adalah technique, sedangkan "membobol kunci dengan bor" dan "membobol kunci dengan kode yang diintip" adalah sub-technique. Batasnya: tidak semua entri punya varian. Exploit Public-Facing Application (T1190) tidak punya sub-technique sama sekali [S8].

**Cara kerja:** format ID-nya selalu sama, dan membacanya cukup dengan tiga langkah.

```
   T1059.001
   |    |  |
   |    |  +-- .001 = sub-technique pertama di bawah T1059  -> PowerShell
   |    +----- 1059 = nomor technique                       -> Command and Scripting Interpreter
   +---------- T    = technique (TA = tactic, G = group, S = software, C = campaign)

   tactic-nya TIDAK tertulis di ID; lihat halaman technique (T1059 -> Execution)
```

Contoh nyata dari halaman ATT&CK: T1059 Command and Scripting Interpreter, yaitu penyalahgunaan antarmuka baris perintah dan bahasa skrip untuk menjalankan perintah, punya 13 sub-technique, antara lain T1059.001 PowerShell, T1059.003 Windows Command Shell (`cmd.exe`), dan T1059.004 Unix Shell [S10]. Remote Services (T1021), yaitu login ke layanan jarak jauh dengan akun sah lalu bertindak sebagai user itu, punya delapan sub-technique, termasuk T1021.001 RDP dan T1021.004 SSH [S11].

Dengan format ini, nomor di Day sebelumnya bisa dibaca ulang:

| Nomor | Dibaca sebagai | Tactic | Muncul di |
|---|---|---|---|
| T1046 | Technique Network Service Discovery | Discovery | Day 02 (port scan) |
| T1499.004 | Sub-technique ke-4 dari Endpoint Denial of Service (exploitation aplikasi atau sistem) | Impact | Day 04 (DoS) |
| T1027.010 | Sub-technique ke-10 dari Obfuscated Files or Information (pengaburan perintah) | Stealth (sebelum v19: Defense Evasion) | Day 05 (Base64) |
| T1558.003 | Sub-technique ke-3 dari Steal or Forge Kerberos Tickets (Kerberoasting) | Credential Access | Day 07 (AD) |
| T1566 | Technique Phishing, dengan empat sub-technique (.001 sampai .004) | Initial Access | Day 09 (email) [S17] |

Satu catatan untuk port scan di Day 02. T1046 menggambarkan pelaku yang mendata layanan di host lain, termasuk dengan alat yang dibawa ke sistem yang sudah dikuasai, sehingga paling pas untuk scan dari dalam jaringan setelah pelaku masuk [S15]. Scan dari internet sebelum pelaku masuk, seperti alert port scan di Day 02, lebih tepat dipetakan ke Active Scanning (T1595) di tactic Reconnaissance, dengan sub-technique T1595.001 Scanning IP Blocks dan T1595.002 Vulnerability Scanning [S15]. Perilakunya mirip, tujuannya berbeda, jadi tactic dan technique-nya berbeda.

**Contoh di PT JAB:** T1490 di alert adalah Inhibit System Recovery: pelaku menghapus data pemulihan bawaan dan mematikan layanan pemulihan supaya sistem yang rusak tidak bisa dikembalikan. Halaman itu menyebut `vssadmin` bisa dipakai untuk menghapus semua volume shadow copy, yaitu salinan cadangan otomatis Windows [S13]. Technique ini tidak punya sub-technique dan berada di tactic Impact [S13]. Karena Impact adalah tujuan akhir, alert T1490 berarti pelaku mungkin sudah melewati hampir semua tahap lain (lihat bagian 2.4).

**Beda technique dengan sub-technique:** technique menjawab cara secara umum, sub-technique menjawab variannya. Bila buktimu cukup spesifik, petakan ke sub-technique; bila tidak, cukup technique-nya. Paper desain ATT&CK memakai aturan yang sama untuk contoh procedure: informasi yang ambigu dicatat di tingkat technique [S5].

**Salah paham umum:**
- "Nomor ATT&CK tidak pernah berubah." Sebagian besar ID technique lama stabil, tetapi technique bisa dicabut (revoked) dan diganti. Di v19, Impair Defenses dicabut dan digantikan Disable or Modify Tools (T1685) [S4]. Penghapusan log Windows, yang di banyak dokumen lama tertulis di bawah Indicator Removal, sekarang ada sebagai sub-technique T1685.005 Clear Windows Event Logs di Defense Impairment [S7]. Saat mengutip nomor, sebut versi ATT&CK-nya.

### 1.6 Procedure, TTP, group, dan campaign

Bagian keempat pertanyaan Dimas meminta procedure dipisahkan dari technique. Di pemetaanmu, procedure adalah kalimat yang menceritakan apa persisnya yang dilakukan pelaku `INC-2026-017`, bukan nama teknik umumnya.

**Apa itu:** procedure adalah implementasi spesifik yang benar-benar dipakai pelaku untuk sebuah technique atau sub-technique [S5]. Paper desain ATT&CK memberi contoh: kelompok APT28 memakai PowerShell untuk menyuntikkan kode ke proses `lsass.exe` dan mengambil kredensial dari memorinya. Satu procedure itu mencakup beberapa technique sekaligus: PowerShell, Process Injection, dan LSASS Memory [S5]. Di situs ATT&CK, procedure dicatat di bagian "Procedure Examples" setiap halaman technique [S5]. Gabungan ketiganya disebut TTP (tactics, techniques, and procedures), yaitu gaya kerja pelaku; hubungan TTP dengan indikator teknis seperti IP dan hash dibahas di Day 12.

**Analogi:** di katalog polisi, technique adalah "masuk lewat atap", sedangkan procedure adalah "komplotan X memotong genteng dengan gergaji listrik bertenaga baterai pada malam Minggu, lalu turun dengan tali". Batasnya: procedure satu komplotan bisa berubah setiap kali ia sadar polisi sudah tahu caranya.

**Cara kerja:** procedure ditulis sebagai kalimat lengkap yang memuat siapa, alat atau perintah apa, dan terhadap apa. Tiga contoh dari halaman PowerShell (T1059.001) memperlihatkan bentuknya [S10]:

- Sandworm Team menjalankan alat pencuri kredensial di memori lewat skrip PowerShell supaya tidak terdeteksi.
- Ransomware Akira menjalankan perintah PowerShell untuk menghapus volume shadow copy sebelum enkripsi.
- APT29 mengunggah skrip PowerShell yang di-encode untuk mengunduh dan memasang backdoor.

Contoh kedua menarik untuk PT JAB: satu procedure (menghapus shadow copy dengan PowerShell) menyentuh dua technique, T1059.001 di Execution dan T1490 di Impact.

Group dan campaign adalah wadah untuk procedure. Group adalah kumpulan aktivitas yang dilacak dengan nama yang sama di komunitas keamanan [S18]. Nama itu sering berbeda antar vendor: APT29 (`G0016`) juga dikenal antara lain sebagai Cozy Bear, NOBELIUM, dan Midnight Blizzard, dan ATT&CK mencatatnya sebagai associated groups dengan peringatan bahwa kecocokannya tidak selalu persis [S18]. Campaign adalah rangkaian intrusi pada periode tertentu dengan target dan tujuan yang sama [S18], dengan ID diawali `C`.

**Contoh di PT JAB:** baris procedure untuk `INC-2026-017` ditulis seperti ini: "Pelaku menjalankan `vssadmin delete shadows /all /quiet` di `JKT-FS01` pukul 03:05 memakai akun `svc-app01` melalui sesi RDP dari `jkt-dmz-app01`." Kalimat itu dipetakan ke T1490 (Impact), sedangkan sesi RDP dan akunnya dipetakan ke T1021.001 dan T1078.002 di baris lain (bagian 2.2).

**Beda procedure dengan technique:** technique bisa dipakai siapa saja dan berlaku umum; procedure melekat pada satu pelaku, satu alat, atau satu kejadian. Dua kelompok bisa memakai technique yang sama dengan procedure yang sangat berbeda, sehingga rule deteksi yang hanya mengenali satu procedure bisa melewatkan procedure lain untuk technique yang sama.

### 1.7 Diamond Model

Pertanyaan keenam Dimas meminta temuan disusun supaya bisa dihubungkan dengan serangan lain. Kill Chain dan ATT&CK menggambarkan langkah pelaku; Diamond Model menggambarkan unsur di balik setiap langkah.

**Apa itu:** Diamond Model of Intrusion Analysis adalah model analisis intrusi yang ditulis Sergio Caltagirone, Andrew Pendergast, dan Christopher Betz pada 2013 [S22]. Model ini menetapkan event (kejadian) sebagai satuan terkecil intrusi. Setiap event punya empat core feature (unsur inti), yaitu adversary, capability, infrastructure, dan victim, yang saling terhubung dan digambar berbentuk berlian [S22]. Aksioma pertamanya: untuk setiap kejadian intrusi ada pelaku yang mengambil satu langkah menuju tujuannya dengan memakai kemampuan lewat infrastruktur terhadap korban, dan langkah itu menghasilkan sesuatu [S22].

Empat sudutnya [S22]:
- **Adversary:** pelaku atau organisasi yang memakai kemampuan terhadap korban untuk mencapai niatnya. Paper membedakan adversary operator (orang yang benar-benar melakukan intrusi) dan adversary customer (pihak yang mendapat manfaat; bisa sama, bisa berbeda). Sudut ini biasanya kosong saat kejadian baru ditemukan.
- **Capability:** alat dan teknik yang dipakai pelaku, dari menebak password secara manual sampai teknik otomatis yang canggih.
- **Infrastructure:** struktur komunikasi fisik atau logis yang dipakai untuk mengirim kemampuan, mengendalikan, dan mengambil hasil: alamat IP, nama domain, alamat email, sampai USB yang sengaja ditinggal di parkiran. Paper membedakan infrastruktur tipe 1 (dikuasai penuh pelaku) dan tipe 2 (dikuasai perantara, sadar atau tidak, misalnya server orang lain yang sudah dibobol). Tipe 2 inilah yang biasanya terlihat korban.
- **Victim:** target pelaku, dipisah menjadi victim persona (organisasi, orang, industri, jabatan) dan victim asset (jaringan, host, alamat email, akun).

Selain empat sudut, setiap event punya meta-feature: waktu mulai dan selesai, phase (tahap, misalnya tahap Kill Chain), result (hasil), direction (arah, misalnya dari infrastruktur ke korban), methodology (golongan aktivitas), dan resources (sumber daya yang dibutuhkan) [S22]. Setiap unsur juga diberi tingkat keyakinan (confidence) [S22].

**Analogi:** papan investigasi detektif dengan empat sudut: foto atau sketsa pelaku, daftar alat dan keahliannya, kendaraan dan rumah persembunyiannya, serta korban dan barang yang diambil. Benang merah ditarik antar sudut dan antar papan. Plat nomor mobil yang sama di dua papan perampokan berbeda membuat detektif curiga komplotannya sama. Batasnya: sudut pelaku sering tetap kosong sampai akhir, satu papan hanya untuk satu kejadian (serangan panjang butuh banyak papan yang dihubungkan), dan benang dari "infrastruktur" bisa menyesatkan bila infrastruktur itu dipakai bersama banyak orang tak bersalah, misalnya alamat IP layanan cloud.

**Cara kerja:** kekuatan utama Diamond Model adalah pivot. Pivot adalah teknik analisis: mengambil satu unsur data, lalu memakainya bersama sumber data lain untuk menemukan unsur lain yang terkait. Pada dasarnya pivot adalah menguji hipotesis [S22]. Bentuk berlian menunjukkan arah pivot: dari satu sudut, analyst bisa menemukan sudut lain yang terhubung [S22].

```
                         ADVERSARY
                   (siapa? sering kosong)
                      /             \
                     /               \
           CAPABILITY ----------------- INFRASTRUCTURE
       (alat, exploit, teknik)        (IP, domain, email)
                     \               /
                      \             /
                          VICTIM
                (persona: PT JAB, Keuangan;
                 asset: jkt-dmz-app01, JKT-FS01)

 contoh pivot: IP C2 (infrastructure)  -> cari di log firewall -> host lain yang menghubunginya (victim)
               web shell (capability)  -> cari file serupa di server lain (victim)
```

Paper Diamond Model menyebut Kill Chain sebagai model operasi pelaku yang sangat berpengaruh, dan menempatkan Diamond Model sebagai pelengkap: tahap Kill Chain dicatat sebagai meta-feature phase, sementara Diamond menambah rincian hubungan antar kejadian [S22]. Event yang berurutan dirangkai menjadi activity thread, yaitu alur kejadian satu pelaku terhadap satu korban [S22].

**Contoh di PT JAB:** event "eksploitasi `jkt-dmz-app01`" diisi seperti ini: adversary tidak diketahui; capability berupa exploit publik untuk komponen web lama lalu web shell; infrastructure berupa `192.0.2.211` (pengirim exploit) dan `192.0.2.212` (server C2); victim berupa PT JAB (persona) dan `jkt-dmz-app01` (asset). Diamond lengkap dan hasil pivot-nya ada di bagian 2.3.

**Beda dengan Kill Chain dan ATT&CK:** Kill Chain dan ATT&CK menjawab "apa yang dilakukan pelaku"; Diamond menjawab "unsur apa saja yang terlibat dan bagaimana hubungannya". Satu baris ATT&CK di pemetaan biasanya menjadi sudut capability di satu event Diamond.

**Salah paham umum:**
- "Diamond Model baru berguna kalau pelakunya sudah diketahui." Kebalikannya: model ini dirancang untuk bekerja dengan sudut yang kosong, karena paper-nya sendiri menyebut sebagian besar unsur biasanya belum diketahui saat kejadian ditemukan [S22]. Tiga sudut yang terisi sudah cukup untuk pivot.

### 1.8 Kategori threat actor: nation-state, cybercrime, hacktivist, insider

Pertanyaan Sari ("siapa kira-kira pelakunya") tidak meminta nama orang. Ia meminta kategori pelaku, karena kategori menentukan motif, kesabaran, dan apa yang mungkin terjadi berikutnya.

**Apa itu:** threat actor adalah individu atau kelompok yang menjadi sumber ancaman; NIST juga menyebutnya pemicu risiko yang punya kemampuan untuk merugikan [S27] (definisi dasarnya ada di Day 01 bagian 1.3). Di lapangan, pelaku dikelompokkan menurut motif dan sumber dayanya. Empat kategori yang paling sering dipakai:

- **Nation-state actor:** pelaku yang bekerja untuk negara atau atas dukungan negara. CISA menggambarkan ancaman negara melalui pelaku APT yang bersumber daya besar dan melakukan intrusi panjang. Motif yang dicatat CISA untuk beberapa negara antara lain spionase, pencurian kekayaan intelektual, menekan aktivitas sosial dan politik, merusak lawan, dan, untuk Korea Utara, menghasilkan uang [S30].
- **Cybercrime:** pelaku yang terutama mengejar uang, misalnya lewat ransomware, pencurian data untuk dijual, atau penipuan. ENISA menilai ransomware sebagai ancaman dengan dampak terbesar di Uni Eropa pada periode Juli 2024 sampai Juni 2025 [S31].
- **Hacktivist:** pelaku yang menyerang untuk menyampaikan pesan politik atau sosial. Pada periode yang sama, ENISA mencatat hacktivism sebagai hampir 80% dari sekitar 4.875 insiden yang dikurasinya, sebagian besar DDoS berdampak rendah ke situs web (DDoS dibahas di Day 04), dan hanya sekitar 2% yang benar-benar mengganggu layanan [S31].
- **Insider:** siapa pun yang punya atau pernah punya akses sah atau pengetahuan tentang sumber daya organisasi, termasuk karyawan, kontraktor, dan vendor. Insider threat adalah ancaman bahwa orang dalam memakai aksesnya, sengaja atau tidak, untuk merugikan organisasi [S29][S28]. CISA membaginya menjadi tidak disengaja (lalai atau salah kirim), disengaja, bersekongkol dengan pelaku luar, dan pihak ketiga yang diberi akses [S29].

**Analogi:** empat jenis pelaku di sekitar bank. Agen intelijen asing ingin membaca dokumen nasabah tertentu dan bersedia menunggu berbulan-bulan tanpa ketahuan (nation-state). Komplotan perampok ingin uang secepatnya (cybercrime). Demonstran mencoret tembok bank dan memblokir pintu supaya diliput media (hacktivist). Pegawai yang memegang kunci bisa mengambil uang, tetapi juga bisa sekadar lupa mengunci brankas (insider). Batasnya: di dunia siber, kategori ini sering tumpang tindih. ENISA mencatat kemiripan TTP yang makin besar antar kelompok, termasuk pelaku yang terkait negara tetapi menyamar sebagai hacktivist ("faketivism") [S31].

**Cara kerja:** kategori pelaku ditebak dari pola, bukan dari satu bukti. Tabel berikut adalah pola umum; cari kolom "Tanda di lapangan" saat menilai sebuah insiden.

| Kategori | Motif utama | Gaya kerja umum | Tanda di lapangan |
|---|---|---|---|
| Nation-state | Spionase, posisi strategis, gangguan | Sabar, tersembunyi, target dipilih | Bertahan lama tanpa ketahuan, data tertentu diincar, berusaha tampak normal |
| Cybercrime | Uang | Cepat, sering oportunis (siapa saja yang bolong) | Tebusan, pencurian data untuk diperas, celah publik yang sudah dikenal |
| Hacktivist | Pesan dan perhatian publik | Terang-terangan, ingin terlihat | DDoS, defacement (halaman diganti), klaim di media sosial |
| Insider | Uang, dendam, atau kelalaian | Memakai akses sah | Akses di luar tugas, unduhan besar sebelum resign, salah kirim data |

**Contoh di PT JAB:** sebagai ISP, PT JAB bisa didatangi keempatnya. Kelompok cybercrime mengincar data pelanggan dan uang tebusan. Hacktivist bisa menyerang layanan saat ada isu politik. Pelaku nation-state bisa tertarik pada infrastruktur jaringan karena ISP membawa trafik banyak organisasi lain. Insider tidak disengaja sudah terjadi berkali-kali dalam bentuk ringan, misalnya file tagihan pelanggan yang dikirim ke alamat email yang salah. Jawaban untuk pertanyaan Sari tentang `INC-2026-017` ada di bagian 2.5.

**Beda kategori pelaku dengan atribusi:** kategori ("kemungkinan besar cybercrime") adalah penilaian kasar yang bisa dibuat SOC dari bukti internal. Atribusi (menetapkan nama kelompok atau negara) butuh intelijen dari banyak korban dan banyak sumber, dan biasanya dikerjakan tim intelijen ancaman atau vendor, bukan analyst L1.

**Salah paham umum:**
- "Insider berarti karyawan jahat." Definisi CISA mencakup yang tidak disengaja, dan kelalaian adalah bagian yang paling sering terjadi sehari-hari [S29].

### 1.9 APT (advanced persistent threat)

Bagian kedua pertanyaan Sari menyebut APT. Istilah ini sering dipakai sebagai sinonim "hacker negara", padahal arti resminya lebih sempit dan lebih berguna.

**Apa itu:** NIST mendefinisikan APT sebagai pelaku dengan keahlian canggih dan sumber daya besar yang memakai berbagai jalur serangan (siber, fisik, dan penipuan) untuk membangun dan memperluas pijakan di lingkungan TI organisasi, demi mencuri informasi atau mengganggu misi organisasi, sekarang atau nanti. Pelaku itu mengejar tujuannya berulang-ulang dalam waktu lama, menyesuaikan diri dengan upaya pembela, dan tetap bertekad mempertahankan aksesnya [S26]. Definisi NIST yang lebih baru juga mencakup beberapa kelompok yang bekerja sama atau kebetulan bertemu di target yang sama [S26]. Paper Kill Chain memakai istilah ini untuk pelaku terlatih dengan sumber daya besar yang menjalankan kampanye intrusi bertahun-tahun terhadap informasi ekonomi, rahasia dagang, atau keamanan nasional [S20]. Lockheed Martin meringkas tiga hurufnya: advanced dan persistent berarti terarah, terkoordinasi, dan bertujuan; threat berarti orang dengan niat, kesempatan, dan kemampuan [S21].

**Analogi:** komplotan profesional yang menyewa ruko di seberang bank selama berbulan-bulan, mempelajari jadwal, menyusupkan orang sebagai petugas kebersihan, dan bila satu jalan masuk ditutup, mencari jalan lain tanpa menyerah. Perampok biasa justru pindah ke bank lain yang lebih mudah. Batasnya: "advanced" tidak selalu berarti alat yang canggih. Banyak kelompok APT memakai alat umum dan teknik sederhana; yang membedakan adalah sumber daya, kesabaran, dan tujuan yang terarah.

**Cara kerja:** tiga pertanyaan membantu memutuskan apakah sebuah kejadian berpola APT:

1. Persistent: apakah pelaku berusaha bertahan lama tanpa ketahuan, dan kembali setelah diusir?
2. Terarah: apakah targetnya dipilih (organisasi tertentu, data tertentu), bukan siapa saja yang kebetulan bolong?
3. Beradaptasi: apakah pelaku mengganti cara setelah satu caranya diblokir?

Pelaku APT dilacak sebagai group di ATT&CK, dan banyak namanya memakai pola APT diikuti angka, misalnya APT29 [S18]. Paper desain ATT&CK menyebut group sebagai kumpulan intrusi, kelompok pelaku, atau kampanye yang biasanya mewakili ancaman terarah dan persisten [S5].

**Contoh di PT JAB:** ISP adalah target yang menarik bagi pelaku APT karena membawa trafik dan data banyak organisasi. Bila suatu hari SOC menemukan akun admin perangkat jaringan dipakai diam-diam selama berbulan-bulan dari alamat yang berganti-ganti, tanpa tebusan dan tanpa kerusakan, pola itu jauh lebih mirip APT daripada geng ransomware.

**Beda APT dengan nation-state:** nation-state adalah kategori menurut siapa yang berada di belakang pelaku; APT adalah gambaran menurut cara kerjanya (sumber daya, kesabaran, keterarahan). Keduanya sering bertemu, karena CISA menggambarkan ancaman negara melalui pelaku APT [S30], tetapi definisi NIST tentang APT tidak mensyaratkan negara [S26].

**Salah paham umum:**
- "Serangannya canggih, jadi pasti APT." Kecanggihan alat bukan ukuran. Exploit yang canggih bisa dibeli atau diunduh oleh siapa saja; yang menunjukkan APT adalah kesabaran, keterarahan, dan adaptasi sepanjang waktu.

## 2. Contoh nyata

Semua contoh di bagian ini adalah keluaran ilustrasi dari organisasi fiktif PT JAB, bukan hasil eksekusi nyata. Kronologi `INC-2026-017` disederhanakan untuk latihan; nama host, alamat IP, akun, waktu, dan angka dibuat untuk belajar.

### 2.1 `INC-2026-017` dipetakan ke Cyber Kill Chain

Ini jawaban pertama untuk Dimas. Kronologi laporan lama dipotong menjadi tujuh tahap; kolom paling kanan menunjukkan control yang seharusnya bisa memutus rantai di tahap itu.

| Tahap | Waktu (WIB) | Yang terjadi | Bukti | Titik putus yang seharusnya ada |
|---|---|---|---|---|
| 1 Reconnaissance | 2026-09-28 sampai 30 | `192.0.2.210` memindai `198.51.100.0/24` di port 80, 443, 8080 | Log `jkt-fw01` | Mengurangi attack surface: aplikasi lama tidak perlu terbuka ke internet |
| 2 Weaponization | Tidak diketahui | Pelaku menyiapkan exploit publik untuk komponen web lama yang dipakai aplikasi | Tidak ada (terjadi di pihak pelaku) | Tidak bisa diputus PT JAB; hanya bisa diantisipasi lewat patch |
| 3 Delivery | 2026-10-09 22:41 | `192.0.2.211` mengirim permintaan HTTPS berisi exploit ke `jkt-dmz-app01` (`198.51.100.95`) | Log web server aplikasi | WAF di depan aplikasi (waktu itu tidak ada) |
| 4 Exploitation | 2026-10-09 22:41 | Komponen web yang belum di-patch menjalankan kode pelaku | Proses `cmd.exe` muncul di bawah proses web server | Patch komponen web (tertunda berbulan-bulan) |
| 5 Installation | 2026-10-09 22:44 | Web shell `img_thumb.aspx` ditulis di folder unggahan | File baru di folder aplikasi | EDR atau FIM di server (tidak ada) |
| 6 C2 | 2026-10-09 22:58 dan seterusnya | `jkt-dmz-app01` menghubungi `192.0.2.212:443` setiap 60 detik | Log `jkt-fw01`, sambungan keluar berpola tetap | Aturan firewall yang melarang server DMZ membuka sambungan keluar sembarangan |
| 7 Actions on Objectives | 2026-10-10 01:10 sampai 04:40 | Password `svc-app01` dibaca dari file konfigurasi; RDP ke `JKT-FS01`; shadow copy dihapus; share Keuangan dienkripsi | Log Windows di `JKT-FS01`, log `jkt-fw01`, catatan tebusan | Tidak menyimpan password di file; firewall DMZ ke jaringan dalam; least privilege untuk `svc-app01` |

**Cara membacanya:** dari permintaan exploit pertama (22:41) sampai enkripsi selesai (04:40) hanya sekitar enam jam, dan semuanya terjadi Jumat malam sampai Sabtu dini hari; staf Keuangan menemukan file terkunci Sabtu pukul 07:30. Rantai ini sebenarnya punya banyak titik putus, tetapi hampir semuanya kosong di server itu: tidak ada WAF, patch tertunda, tidak ada EDR, dan aturan firewall waktu itu mengizinkan server DMZ menghubungi file server. Pelajaran terbesarnya ada di kolom kanan, bukan di kolom tengah. Sebagian titik putus itu sekarang sudah dipasang, misalnya larangan server DMZ menghubungi file server dan DC.

Bila disusun dalam bentuk courses of action (bagian 1.1), setiap tahap sebaiknya punya lebih dari satu tindakan: misalnya untuk C2, `jkt-ids01` dan log `jkt-proxy01` mendeteksi (detect), firewall yang melarang server DMZ keluar sembarangan menolak (deny), dan domain C2 yang diarahkan ke sinkhole `jkt-sink01` menipu malware agar menghubungi server milik PT JAB (deceive).

### 2.2 `INC-2026-017` dipetakan ke MITRE ATT&CK

Ini jawaban untuk pertanyaan ketiga sampai kelima Dimas. Setiap baris memisahkan procedure (apa yang dilakukan pelaku di PT JAB) dari technique dan tactic-nya; pemetaan memakai ATT&CK v20.

| Waktu (WIB) | Procedure di PT JAB | Tactic | Technique / sub-technique |
|---|---|---|---|
| 09-28 sampai 09-30 | `192.0.2.210` memindai rentang IP publik PT JAB | Reconnaissance | T1595.001 Scanning IP Blocks [S15] |
| Tidak diketahui | Pelaku menyiapkan exploit dan server | Resource Development | Tidak dipetakan (tidak ada bukti) |
| 10-09 22:41 | Exploit dikirim ke aplikasi web lama di `jkt-dmz-app01` | Initial Access | T1190 Exploit Public-Facing Application [S8] |
| 10-09 22:44 | Web shell `img_thumb.aspx` ditanam di folder unggahan | Persistence | T1505.003 Web Shell [S16] |
| 10-09 22:50 | Lewat web shell, `cmd.exe` menjalankan perintah untuk melihat akun aktif dan isi folder aplikasi | Execution (isi perintahnya: Discovery) | T1059.003 Windows Command Shell [S10] |
| 10-09 22:58 | Beacon HTTPS ke `192.0.2.212:443` setiap 60 detik | Command and Control | T1071.001 Web Protocols [S16] |
| 10-10 01:10 | Password akun domain `svc-app01` dibaca dari file konfigurasi aplikasi | Credential Access | T1552.001 Credentials In Files [S16] |
| 10-10 02:31 | RDP dari `jkt-dmz-app01` ke `JKT-FS01` | Lateral Movement | T1021.001 Remote Desktop Protocol [S11] |
| 10-10 02:31 | Akun `svc-app01` yang ternyata admin lokal di `JKT-FS01` dipakai untuk login | Privilege Escalation (juga terdaftar di Initial Access, Persistence, Stealth) | T1078.002 Domain Accounts [S9] |
| 10-10 03:05 | `vssadmin delete shadows /all /quiet` di `JKT-FS01` | Impact | T1490 Inhibit System Recovery [S13] |
| 10-10 03:12 sampai 04:40 | Share Keuangan dienkripsi, catatan tebusan ditinggal di setiap folder | Impact | T1486 Data Encrypted for Impact [S12] |
| Tidak terbukti | Catatan tebusan mengklaim data sudah dicuri | Exfiltration | Tidak dipetakan (log tidak menunjukkan transfer keluar yang mencurigakan) |

**Cara membacanya:** pemetaan berisi 10 technique atau sub-technique dalam 10 tactic: Reconnaissance, Initial Access, Persistence, Execution, Discovery, Command and Control, Credential Access, Lateral Movement, Privilege Escalation, dan Impact. Lima tactic sisanya (15 dikurangi 10) tidak muncul: Resource Development (terjadi di pihak pelaku), Stealth, Defense Impairment, Collection, dan Exfiltration (diklaim tetapi tidak terbukti). Dua hal layak dicatat. Pertama, tidak ada Defense Impairment karena memang tidak ada EDR yang perlu dimatikan di `jkt-dmz-app01`; ketiadaan sebuah tactic bisa berarti pertahanannya juga tidak ada. Kedua, baris Exfiltration sengaja dikosongkan: peta ATT&CK hanya diisi dari bukti, bukan dari klaim pelaku atau dugaan.

Kenapa satu langkah (02:31) menjadi dua baris? Karena satu procedure bisa menyentuh beberapa technique, seperti contoh APT28 di bagian 1.6. Sesi RDP adalah cara berpindah (Lateral Movement), sedangkan akun yang dipakai adalah cara mendapat hak admin di server tujuan.

Peta ini juga menjadi daftar perbaikan: setiap baris technique dipasangkan dengan satu penghalang, misalnya aturan `jkt-fw01` yang sekarang melarang server DMZ membuka RDP ke jaringan dalam (T1021.001), pencabutan hak admin lokal `svc-app01` di file server dan akses share lewat group `GG-Keuangan-Share` (T1078.002), larangan menyimpan password akun layanan sebagai teks biasa di file konfigurasi (T1552.001), dan alert Splunk untuk `vssadmin delete shadows` di semua server (T1490).

### 2.3 Diamond Model untuk event eksploitasi dan hasil pivot

Ini jawaban untuk pertanyaan keenam Dimas. Satu event dipilih, yaitu eksploitasi pukul 22:41, lalu keempat sudut dan meta-feature-nya diisi.

```
Event      : INC-2026-017 / E1  eksploitasi jkt-dmz-app01
Timestamp  : 2026-10-09 22:41 WIB (mulai) - 22:44 WIB (web shell tertulis)
Phase      : Kill Chain 3-5 (delivery, exploitation, installation)
Result     : berhasil
Direction  : infrastructure -> victim
Methodology: eksploitasi aplikasi web publik

ADVERSARY       : tidak diketahui                          confidence: -
CAPABILITY      : exploit publik komponen web lama;        confidence: tinggi
                  web shell img_thumb.aspx (T1190, T1505.003)
INFRASTRUCTURE  : 192.0.2.211 (pengirim exploit)           confidence: tinggi
                  192.0.2.212 (C2, dipakai di event E3)
                  192.0.2.210 (pemindai, event E0)         confidence: sedang
VICTIM persona  : PT JAB, ISP, divisi Keuangan (target akhir)
VICTIM asset    : jkt-dmz-app01 (198.51.100.95), lalu JKT-FS01
```

**Cara membacanya:** sudut adversary kosong, dan itu normal. Keyakinan untuk `192.0.2.210` hanya sedang karena pemindaian rentang IP dilakukan banyak pihak setiap hari (Day 02); hubungannya dengan pelaku hanya didukung waktu yang berdekatan dan port yang sama. Dua alamat lain langsung terlihat dalam rantai kejadian, jadi keyakinannya tinggi.

Sari lalu menunjukkan tiga pivot yang dijalankan Agustus 2027 untuk menguji apakah pelaku yang sama pernah kembali. Tabel berikut mencatat dari sudut mana setiap pivot dimulai dan apa hasilnya; perhatikan kolom "Kesimpulan" untuk melihat bahwa hasil kosong juga temuan.

| Pivot dari | Dicari di | Hasil | Kesimpulan |
|---|---|---|---|
| Infrastructure: `192.0.2.211`, `192.0.2.212` | Log `jkt-fw01`, `jkt-proxy01`, dan DNS 90 hari terakhir di Splunk | 0 sambungan | Tidak ada tanda pelaku memakai server yang sama lagi; tidak membuktikan pelaku tidak kembali, karena infrastruktur mudah diganti |
| Capability: nama dan pola web shell | Daftar file di folder aplikasi web semua server DMZ | Tidak ditemukan | Tidak ada web shell serupa di server lain |
| Victim asset: komponen web lama yang sama | Inventaris aplikasi | 1 server lain memakai versi lama, sudah di belakang WAF | Satu temuan untuk dijadwalkan patch |

Pivot pertama menunjukkan batas indikator teknis: alamat IP adalah bagian yang paling mudah diganti pelaku. Pivot dari capability dan victim lebih tahan lama. Hubungan antara jenis indikator dan seberapa sulit diganti pelaku dibahas di Day 12.

### 2.4 Empat alert hari ini dibaca dengan tactic dan tahap

Siang itu, Sari mengajakmu melihat antrean alert Jumat 2027-08-20. Rule di Splunk sekarang memberi label ATT&CK pada setiap alert, dan label itu membantu menentukan seberapa jauh serangan sudah berjalan.

```
Alert         Waktu   Prioritas  Host / sumber                          ATT&CK (v20)                 Tactic
SOC-2027-0876 08:12   P3         192.0.2.214 -> portal.jab.example      T1595.002 Vulnerability      Reconnaissance
                                 (203.0.113.8, via jkt-waf01)           Scanning
                                 1.260 permintaan, 1.260 ditolak WAF atau dijawab 404
SOC-2027-0877 09:47   P3         JKT-WS-1142 (10.10.44.25)              T1059.001 PowerShell         Execution
                                 powershell.exe -EncodedCommand ...
SOC-2027-0878 13:21   P1         JKT-WS-1146 (10.10.44.31)              T1490 Inhibit System         Impact
                                 vssadmin.exe delete shadows /all /quiet  Recovery
                                 (diblokir Defender)
SOC-2027-0879 13:24   P1         JKT-WS-1146 (10.10.44.31)              korelasi: 3 tactic berbeda   Execution,
                                 user hendro.saputro@jab.example        dalam 30 menit               Defense Impairment,
                                                                                                     Impact
```

Tabel berikut membaca keempatnya; kolom "Tahap Kill Chain" dan "Keputusan" memperlihatkan kenapa prioritasnya berbeda jauh.

| Alert | Tahap Kill Chain | Arti posisinya | Keputusan |
|---|---|---|---|
| `SOC-2027-0876` | Reconnaissance | Pelaku belum masuk; ini mengetuk pintu | Semua permintaan ditolak; dicatat, tidak dieskalasi |
| `SOC-2027-0877` | Exploitation atau installation, bila jahat | PowerShell ber-encode (Base64, Day 05) bisa jahat, bisa sah | Dicek ke pemilik host: skrip inventaris tim IT yang terdaftar; ditutup sebagai aktivitas sah |
| `SOC-2027-0878` | Actions on Objectives | Impact adalah tujuan akhir; tahap sebelumnya sudah terlewati tanpa alert | Dieskalasi segera ke Sari |
| `SOC-2027-0879` | Gabungan | Beberapa tactic di satu host dalam waktu singkat adalah pola rangkaian serangan, bukan kejadian tunggal | Host diisolasi, insiden `INC-2027-093` dibuka |

**Cara membacanya:** dua alert pertama ada di tahap awal atau ambigu, jadi P3 wajar. Alert ketiga berbeda: begitu label menyebut Impact, pertanyaan pertama bukan "apakah ini jahat?" tetapi "tahap mana saja yang kita lewatkan?". Rule korelasi di `SOC-2027-0879` menghitung jumlah tactic berbeda pada satu host dalam 30 menit; tiga tactic sekaligus hampir tidak pernah terjadi pada aktivitas sah.

Sari lalu membaca mundur rantai di `JKT-WS-1146`, dari tahap akhir ke awal. Tabel berikut adalah hasilnya; baca dari bawah ke atas untuk urutan waktu yang sebenarnya.

| Waktu | Kejadian | Tactic / technique | Tahap Kill Chain |
|---|---|---|---|
| 13:21 | `vssadmin delete shadows` diblokir Defender | Impact, T1490 | Actions on Objectives |
| 13:15 | Program yang sama mencoba mematikan perlindungan real-time Defender; ditolak tamper protection | Defense Impairment, T1685 Disable or Modify Tools [S7] | Actions on Objectives (persiapan) |
| 13:02 | User menjalankan `KMS_Activator_2027.exe` dari folder Downloads | Execution, T1204.002 Malicious File [S16] | Exploitation (menipu user) |
| 12:58 | File diunduh dari situs "aktivator gratis" di `192.0.2.219` lewat `jkt-proxy01` | (cara masuknya; dipetakan tim L2) | Delivery |

`INC-2027-093` dicatat sebagai SEV-3: satu laptop, enkripsi tidak terjadi, salinan pemulihan utuh, dan host sudah diisolasi. Hendro Saputro mengaku mengunduh "aktivator" untuk program kantor yang lisensinya habis. Rincian jenis program jahat seperti ini dibahas di Day 16. Rantai ini diputus di tahap terakhir oleh EDR, bukan di tahap awal; itu tetap keberhasilan, tetapi tindak lanjutnya adalah memblokir kategori situs unduhan bajakan di `jkt-proxy01` supaya rantai berikutnya putus lebih awal.

### 2.5 Jawaban untuk Sari: APT negara atau cybercrime?

Ini jawaban untuk pertanyaan ketujuh. Tabel berikut membandingkan bukti `INC-2026-017` dengan tanda APT dari bagian 1.9 dan pola kategori dari bagian 1.8; baca kolom "Lebih cocok dengan".

| Bukti | Lebih cocok dengan | Alasan |
|---|---|---|
| Tebusan diminta, file dienkripsi | Cybercrime | Motif uang dan kerusakan yang terlihat; pelaku APT umumnya ingin tetap tersembunyi |
| Rentang IP dipindai luas, celah yang dipakai sudah publik | Cybercrime | Pola oportunis: siapa saja yang bolong, bukan target yang dipilih |
| Sekitar enam jam dari masuk sampai enkripsi | Cybercrime | Tidak ada usaha bertahan lama tanpa ketahuan |
| Tidak ada tanda pelaku kembali setelah dibersihkan (pivot bagian 2.3) | Cybercrime | APT cenderung berusaha kembali dan beradaptasi |
| Klaim pencurian data tidak terbukti | Netral | Klaim pelaku bukan bukti, dan ketiadaan bukti tidak membuktikan tidak ada pencurian |

**Kesimpulan yang dikirim ke Sari:** "Pelaku `INC-2026-017` kemungkinan besar kelompok cybercrime ransomware yang oportunis, bukan APT negara. Keyakinan sedang: semua bukti menunjuk ke motif uang dan kerja cepat, tetapi kami tidak punya intelijen eksternal, dan pelaku yang terkait negara kadang menyamar sebagai penjahat biasa. Nama kelompok tidak kami tetapkan; perbaikan di bagian 2.2 tidak bergantung pada nama itu."

## 3. Perbandingan istilah yang sering tertukar

### 3.1 Kill Chain, Unified Kill Chain, ATT&CK, Diamond Model, dan D3FEND

Lima kerangka ini sering disebut bersamaan di laporan dan interview. Tabel berikut memisahkan pertanyaan yang dijawab masing-masing; cari kolom "Tidak cocok untuk" saat memilih kerangka.

| Kerangka | Pembuat dan tahun | Bentuk | Menjawab | Tidak cocok untuk |
|---|---|---|---|---|
| Cyber Kill Chain | Lockheed Martin (Hutchins, Cloppert, Amin), 2011 [S20] | 7 tahap berurutan | Sudah sampai tahap mana; di mana memutus | Rincian aktivitas di dalam jaringan, insider |
| Unified Kill Chain | Paul Pols, 2017 [S23][S24] | 18 tahap dalam tiga kelompok (In, Through, Out) | Urutan lengkap, termasuk gerak di dalam | Ringkasan cepat ke manajemen |
| MITRE ATT&CK | MITRE, publik 2015, sekarang v20 [S5][S3] | Matriks tactic dan technique, plus procedure, group, campaign | Tujuan dan cara setiap langkah, dengan ID baku | Menentukan urutan atau prioritas risiko |
| Diamond Model | Caltagirone, Pendergast, Betz, 2013 [S22] | 4 sudut per event, plus meta-feature | Unsur yang terlibat dan hubungannya; pivot | Menggambarkan seluruh rangkaian dalam satu gambar |
| MITRE D3FEND | MITRE [S25] | Katalog tindakan bertahan: Model, Harden, Detect, Isolate, Deceive, Evict, Restore | Pertahanan apa yang menangkal sebuah teknik | Menggambarkan perilaku penyerang |

### 3.2 Tactic, technique, sub-technique, procedure

Empat tingkat ATT&CK ini paling sering tertukar saat menulis laporan. Tabel berikut memakai satu contoh yang sama dari `INC-2026-017`; cari kolom "Pertanyaan" untuk menentukan tingkat yang kamu tulis.

| Tingkat | Pertanyaan | Contoh | Bentuk ID |
|---|---|---|---|
| Tactic | Kenapa? Apa tujuannya? | Lateral Movement | `TA0008` |
| Technique | Bagaimana, secara umum? | Remote Services | `T1021` |
| Sub-technique | Bagaimana, lebih spesifik? | Remote Desktop Protocol | `T1021.001` |
| Procedure | Apa persisnya yang dilakukan pelaku ini? | RDP dari `jkt-dmz-app01` ke `JKT-FS01` pukul 02:31 dengan akun `svc-app01` | Tidak ada ID; kalimat |

## 4. Salah paham umum

- **Anggapan:** ATT&CK sudah menggantikan Kill Chain, jadi Kill Chain tidak perlu dipelajari. **Kenyataannya:** paper desain ATT&CK sendiri menempatkan Kill Chain sebagai model tingkat tinggi yang tetap berguna untuk memahami proses besar, dan ATT&CK sebagai model tingkat menengah untuk rinciannya [S5]. Laporan ke manajemen sering memakai Kill Chain; laporan teknis dan alert memakai ATT&CK.
- **Anggapan:** alert yang diberi label technique ATT&CK berarti teknik itu pasti dipakai pelaku. **Kenyataannya:** label menunjukkan perilaku yang dicari rule, bukan bukti niat jahat. `SOC-2027-0877` berlabel T1059.001, tetapi ternyata skrip sah tim IT. Label membantu triage; keputusan tetap dari pemeriksaan.
- **Anggapan:** semakin banyak kotak ATT&CK yang tertutup rule deteksi, semakin aman. **Kenyataannya:** satu technique punya banyak procedure, dan satu rule sering hanya menangkap sebagian. Peta cakupan berguna untuk mencari bagian yang kosong, bukan untuk menyatakan sebuah technique sudah tertutup.
- **Anggapan:** atribusi (menyebut nama kelompok) adalah tugas utama SOC setelah insiden. **Kenyataannya:** perbaikan pertahanan di `INC-2026-017` sama sekali tidak bergantung pada nama pelaku. SOC cukup menilai kategori dan polanya; nama kelompok membutuhkan intelijen dari banyak korban.
- **Anggapan:** hacktivist selalu tidak berbahaya karena hanya DDoS ringan. **Kenyataannya:** data ENISA memang menunjukkan sebagian besar insiden hacktivism berdampak rendah [S31], tetapi ENISA juga mencatat penyamaran pelaku terkait negara sebagai hacktivist. Klaim "kami hacktivist" di media sosial perlu dinilai dari bukti, bukan diterima begitu saja.
- **Anggapan:** pemetaan ke kerangka dikerjakan sambil insiden berjalan supaya laporannya rapi. **Kenyataannya:** saat Impact sedang terjadi, isolasi dan containment datang lebih dulu. Pemetaan lengkap seperti bagian 2.1 dan 2.2 dikerjakan sesudahnya, dari bukti yang sudah diamankan.

## 5. Catatan terkini

Bagian ini mencatat versi kerangka, tanggal terbit, dan perubahan yang perlu diketahui saat membaca dokumen lama atau alat yang belum diperbarui.

- **ATT&CK v20.0** terbit 13 Oktober 2026 dan menjadi versi berjalan per 2026-10-21. Rilis ini antara lain menambah campaign baru tentang serangan ke utilitas air di AS dan pembobolan yang dibantu AI, serta technique baru terkait AI [S3]. Versi sebelumnya: v19.2 berlaku 28 April sampai 12 Oktober 2026, v18.1 berlaku 28 Oktober 2025 sampai 27 April 2026 [S3].
- **ATT&CK v19 (28 April 2026)** memecah Defense Evasion di Enterprise menjadi Stealth (`TA0005`) dan Defense Impairment (`TA0112`), menambah sub-technique ke ICS, dan memulai detection strategies di Mobile [S4]. Impair Defenses dicabut dan digantikan Disable or Modify Tools (T1685) [S4]. Alat dan rule yang masih memakai pemetaan v18 perlu dipetakan ulang. Perhatian: perubahan ini hanya untuk Enterprise. Matriks Mobile v20 masih memakai Defense Evasion, dan matriks ICS memakai nama Evasion [S6].
- **ATT&CK v18 (28 Oktober 2025)** memindahkan informasi deteksi dari halaman technique ke objek baru bernama detection strategies dan analytics, serta menghentikan data sources di ketiga domain [S19].
- **Jumlah isi v20** per domain: Enterprise 15 tactic, 227 technique, 479 sub-technique; Mobile 12, 78, 47; ICS 12, 78, 26 [S3]. Angka ini berubah setiap rilis (MITRE merilis dua kali setahun, April dan Oktober), jadi sebut versinya bila mengutip.
- **Paper desain ATT&CK** ("ATT&CK: Design and Philosophy") terakhir direvisi Maret 2020 dan masih memakai istilah lama seperti PRE-ATT&CK, yang sekarang sudah menjadi tactic Reconnaissance dan Resource Development di Enterprise [S5][S2]. Konsep tactic, technique, sub-technique, dan procedure-nya tetap berlaku.
- **Paper Kill Chain** Hutchins, Cloppert, dan Amin umumnya dikutip sebagai terbitan 2011; halaman resmi Lockheed Martin saat ini memperkenalkan Kill Chain sebagai bagian dari model Intelligence Driven Defense tanpa mencantumkan daftar tahapnya [S20][S21].
- **Unified Kill Chain** pertama dikembangkan 2017 dan dirilis dengan lisensi GNU GPL v2; whitepaper yang lebih baru terbit 2021 [S23][S24].
- **MITRE D3FEND**, katalog tindakan bertahan yang dipasangkan dengan teknik ATT&CK, tercatat versi 1.6.0 di situsnya per 2026-10-21, dengan tujuh tactic: Model, Harden, Detect, Isolate, Deceive, Evict, Restore [S25].
- **ENISA Threat Landscape 2025** terbit 1 Oktober 2025 dan mencakup Juli 2024 sampai Juni 2025. Phishing (sekitar 60%) dan eksploitasi kerentanan (21,3%) adalah dua jalur masuk teratas [S31]. Halaman ENISA juga memuat revisi PDF laporan yang lebih baru; cek revisi terakhir sebelum mengutip angka di dokumen formal.

## 6. Cheat sheet

```
Kerangka serangan    : cara baku memotong serangan menjadi bagian bernama
Cyber Kill Chain     : 7 tahap Lockheed Martin: recon, weaponization, delivery, exploitation,
                       installation, C2, actions on objectives; putus satu mata rantai = gagal
Courses of action    : detect, deny, disrupt, degrade, deceive, destroy per tahap
Batas Kill Chain     : tahap awal di luar jaringan; aktivitas di dalam tertumpuk di tahap 7;
                       kurang pas untuk insider
Unified Kill Chain   : Pols 2017; 18 tahap; In, Through, Out; gabungan Kill Chain + ATT&CK
MITRE ATT&CK         : basis pengetahuan perilaku penyerang dari pengamatan nyata; v20 (Okt 2026)
Domain               : Enterprise (15 tactic), Mobile (12), ICS (12)
Tactic (TAxxxx)      : "kenapa": tujuan pelaku pada satu langkah
Technique (Txxxx)    : "bagaimana": cara mencapai tactic; bisa di beberapa tactic (T1078)
Sub-technique (.xxx) : varian spesifik technique (T1059.001 PowerShell)
Procedure            : cara spesifik pelaku tertentu; kalimat, tanpa ID; bisa menyentuh beberapa technique
TTP                  : tactics, techniques, procedures; gaya kerja pelaku (Day 12)
Group / Campaign     : Gxxxx kumpulan aktivitas bernama; Cxxxx rangkaian intrusi satu periode
Stealth (TA0005)     : bersembunyi, tampak normal (v19+; dulu bagian Defense Evasion)
Defense Impairment   : TA0112; merusak alat pertahanan (T1685) (v19+)
T1490 / T1486        : Inhibit System Recovery (hapus shadow copy) / Data Encrypted for Impact
T1595 vs T1046       : scan dari luar (Reconnaissance) vs scan dari dalam (Discovery)
Diamond Model        : 1 event = adversary, capability, infrastructure, victim (+ meta-feature)
Pivot                : pakai satu unsur untuk menemukan unsur terkait; sudut kosong itu normal
Threat actor         : nation-state (negara), cybercrime (uang), hacktivist (pesan), insider (akses sah)
APT                  : sumber daya besar, persisten, terarah, beradaptasi; tidak wajib negara
Atribusi             : menetapkan nama pelaku; butuh intel luas; bukan tugas utama L1
D3FEND               : katalog pertahanan MITRE: Model, Harden, Detect, Isolate, Deceive, Evict, Restore
```

## 7. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "ATT&CK lebih rinci dan lebih baru, jadi Cyber Kill Chain sudah usang dan tidak perlu dipakai lagi." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Keduanya menjawab pertanyaan berbeda. Kill Chain adalah model tingkat tinggi yang menjawab "sudah sampai tahap mana" dan "di mana memutus rantai", cocok untuk ringkasan dan perencanaan pertahanan. ATT&CK adalah model tingkat menengah yang memberi nama dan nomor untuk setiap langkah, dan paper desain ATT&CK sendiri menempatkan Kill Chain sebagai model tingkat tinggi yang tetap berguna. Di PT JAB, laporan `INC-2026-017` memakai keduanya: tujuh tahap untuk gambaran besar, ATT&CK untuk rinciannya. Lihat bagian 1.1, 1.3, dan 2.1.

</details>

**2. Skenario keputusan.** Pukul 13:21 muncul alert P1 di sebuah laptop: `vssadmin delete shadows /all /quiet`, label T1490, diblokir EDR. Belum ada alert lain di laptop itu. Apa langkah yang paling tepat?

- A. Turunkan ke P3, karena perintahnya sudah diblokir dan hanya ada satu technique.
- B. Perlakukan sebagai mendesak: T1490 ada di tactic Impact, artinya tahap-tahap sebelumnya kemungkinan sudah terlewati tanpa alert; eskalasi, isolasi bila perlu, lalu telusuri mundur rantainya.
- C. Tunggu sampai muncul alert T1486, karena tanpa enkripsi belum ada ransomware.

<details><summary>Jawaban</summary>

B. Impact adalah tujuan akhir pelaku, jadi alert di tactic ini berarti serangan sudah jauh berjalan dan tahap awalnya lolos dari deteksi. Itulah yang terjadi di `SOC-2027-0878`: penelusuran mundur menemukan file unduhan, eksekusi oleh user, dan percobaan mematikan Defender. A keliru karena satu perintah yang diblokir tidak berarti program jahatnya berhenti; ia bisa mencoba cara lain. C keliru karena menunggu enkripsi berarti membiarkan kerusakan terjadi, padahal penghapusan shadow copy biasanya dilakukan tepat sebelum enkripsi. Lihat bagian 1.5 dan 2.4.

</details>

**3. Pertanyaan jebakan.** "Di ATT&CK v20 sudah tidak ada Defense Evasion, berarti teknik penyamaran dan penghapusan jejak sudah tidak dicatat, dan semua matriks ATT&CK sudah berubah." Benarkah?

<details><summary>Jawaban</summary>

Tidak, dua-duanya keliru. Teknik itu tetap ada, hanya dipindah: sejak v19, Defense Evasion di Enterprise dipecah menjadi Stealth (`TA0005`, bersembunyi dan tampak normal, misalnya Masquerading dan Obfuscated Files or Information) dan Defense Impairment (`TA0112`, merusak alat pertahanan, misalnya Disable or Modify Tools T1685). Perubahan itu hanya untuk Enterprise; matriks Mobile v20 masih memakai Defense Evasion dan ICS memakai Evasion. Lihat bagian 1.4 dan 5.

</details>

**4. Skenario keputusan.** Program jahat di sebuah laptop mencoba mematikan perlindungan real-time Microsoft Defender. Di tactic mana langkah ini dipetakan menurut ATT&CK v20?

- A. Stealth, karena tujuannya agar tidak ketahuan.
- B. Defense Impairment, karena langkah ini langsung merusak alat pertahanan.
- C. Impact, karena sistem menjadi tidak aman.

<details><summary>Jawaban</summary>

B. Defense Impairment mencakup teknik yang langsung mengganggu alat dan jalur pertahanan supaya pembela tidak bisa melihat, termasuk mematikan EDR atau antivirus (Disable or Modify Tools, T1685). A keliru karena Stealth dipakai untuk bersembunyi dan tampak normal tanpa mematikan pertahanan, misalnya menyamarkan nama file. C keliru karena Impact adalah merusak sistem dan data milik korban sebagai tujuan, seperti enkripsi atau penghapusan salinan pemulihan. Lihat bagian 1.4 dan 2.4.

</details>

**5. Jelaskan ulang.** Jelaskan kepada anggota keluargamu yang bukan orang IT, dalam tiga kalimat, apa itu Diamond Model dan kenapa berguna walaupun pelakunya tidak diketahui.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Bayangkan papan investigasi detektif dengan empat sudut: siapa pelakunya, alat apa yang dipakai, kendaraan atau nomor telepon yang dipakai, dan siapa korbannya. Untuk setiap kejadian, kami mengisi sudut yang kami tahu, dan sudut pelaku memang sering kosong. Dari sudut yang terisi, misalnya nomor telepon pelaku, kami bisa mencari kejadian lain yang memakai nomor yang sama, sehingga satu serangan bisa dihubungkan dengan serangan lain."

Kesalahan yang sering muncul:
- Mengira model ini baru bisa dipakai setelah pelakunya ketahuan, padahal justru dirancang untuk bekerja dengan sudut kosong.
- Lupa menyebut manfaat utamanya: menghubungkan kejadian (pivot), bukan hanya mengisi formulir.
- Memakai istilah adversary, capability, infrastructure, victim tanpa menjelaskannya.

</details>

**6. Pertanyaan jebakan.** "Pelaku `INC-2026-017` memakai exploit dan web shell, lalu mengenkripsi file dalam satu malam. Itu canggih, jadi pelakunya pasti APT negara asing." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Kecanggihan alat bukan ukuran APT; exploit untuk celah publik bisa dipakai siapa saja. Tanda APT adalah persistensi, target yang dipilih, dan adaptasi dalam waktu lama. Bukti `INC-2026-017` menunjuk ke arah sebaliknya: tebusan uang, pemindaian luas yang oportunis, sekitar enam jam dari masuk sampai enkripsi, dan tidak ada tanda pelaku kembali. Kesimpulan yang wajar adalah "kemungkinan besar cybercrime ransomware, keyakinan sedang", tanpa menetapkan nama kelompok. Lihat bagian 1.9 dan 2.5.

</details>

**7. Interview question (English).** "How would you use MITRE ATT&CK in a SOC, and how is it different from the Cyber Kill Chain?"

<details><summary>Sample answer</summary>

"The Cyber Kill Chain is a high-level, seven-stage model from Lockheed Martin: reconnaissance, weaponization, delivery, exploitation, installation, command and control, and actions on objectives. Its main idea is that the attacker has to complete every stage, while the defender only needs to break one link, so it is good for explaining how far an attack got and where we should have stopped it. MITRE ATT&CK is a more granular knowledge base built from real-world observations. Tactics are the attacker's goal at a given step, techniques and sub-techniques are how they achieve it, and procedures are what a specific actor actually did. In a SOC I use ATT&CK in three ways: tagging alerts so I can see where in an attack they sit, which drives priority, since an Impact-stage alert like T1490 means earlier stages were missed; mapping incidents after the fact to find which controls were missing; and reviewing detection coverage to find gaps. I also keep in mind that the matrix changes, for example the Enterprise Defense Evasion tactic was split into Stealth and Defense Impairment in version 19, so I always state the version I mapped to."

What makes this answer strong: it explains both models correctly instead of treating them as competitors, gives concrete SOC uses with an example of how the tactic affects priority, separates tactics, techniques, and procedures precisely, and shows awareness that ATT&CK is versioned and recently changed.

</details>

## 8. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | MITRE ATT&CK: Enterprise Matrix | https://attack.mitre.org/matrices/enterprise/ | primer (basis pengetahuan MITRE) | v20; diakses 2026-10-21 | Tinggi. Urutan dan jumlah 15 tactic |
| S2 | MITRE ATT&CK: Enterprise Tactics | https://attack.mitre.org/tactics/enterprise/ | primer (basis pengetahuan MITRE) | v20; diakses 2026-10-21 | Tinggi. ID dan kalimat tujuan setiap tactic |
| S3 | MITRE ATT&CK: Updates (v20) dan Version History | https://attack.mitre.org/resources/updates/<br>https://attack.mitre.org/resources/versions/ | primer (catatan rilis MITRE) | v20.0 terbit 2026-10-13; diakses 2026-10-21 | Tinggi. Tanggal versi, jumlah tactic, technique, sub-technique per domain. Jumlah per domain tidak sama dengan total gabungan di halaman yang sama karena ada isi yang dipakai beberapa domain |
| S4 | MITRE ATT&CK: Updates April 2026 (v19); Enterprise Matrix v18 | https://attack.mitre.org/resources/updates/updates-april-2026/<br>https://attack.mitre.org/versions/v18/matrices/enterprise/ | primer (catatan rilis MITRE) | v19 terbit 2026-04-28; diakses 2026-10-21 | Tinggi. Pemecahan Defense Evasion, Impair Defenses dicabut, 14 tactic di v18 dan rencana deprecation |
| S5 | MITRE: ATT&CK: Design and Philosophy | https://attack.mitre.org/docs/ATTACK_Design_and_Philosophy_March_2020.pdf | primer (paper MITRE) | revisi Maret 2020; diakses 2026-10-21 | Tinggi untuk definisi tactic, technique, sub-technique, procedure, sejarah, dan posisi terhadap Kill Chain. Daftar tactic di dalamnya sudah lama |
| S6 | MITRE ATT&CK: Mobile Matrix dan ICS Matrix | https://attack.mitre.org/matrices/mobile/<br>https://attack.mitre.org/matrices/ics/ | primer (basis pengetahuan MITRE) | v20; diakses 2026-10-21 | Tinggi. Mobile masih memakai Defense Evasion; ICS memakai Evasion |
| S7 | MITRE ATT&CK: TA0005 Stealth, TA0112 Defense Impairment, T1685 Disable or Modify Tools, T1685.001 | https://attack.mitre.org/tactics/TA0005/<br>https://attack.mitre.org/tactics/TA0112/<br>https://attack.mitre.org/techniques/T1685/<br>https://attack.mitre.org/techniques/T1685/001/ | primer (basis pengetahuan MITRE) | TA0112 dibuat 2026-04-14; T1685 diubah 2026-09-11; diakses 2026-10-21 | Tinggi. Ruang lingkup kedua tactic, daftar technique, T1685.005 Clear Windows Event Logs |
| S8 | MITRE ATT&CK T1190: Exploit Public-Facing Application | https://attack.mitre.org/techniques/T1190/ | primer (basis pengetahuan MITRE) | versi 2.8, diubah 2026-05-12; diakses 2026-10-21 | Tinggi. Tanpa sub-technique; platform |
| S9 | MITRE ATT&CK T1078: Valid Accounts | https://attack.mitre.org/techniques/T1078/ | primer (basis pengetahuan MITRE) | versi 3.0, diubah 2026-05-12; diakses 2026-10-21 | Tinggi. Empat tactic, empat sub-technique termasuk T1078.002 |
| S10 | MITRE ATT&CK T1059 dan T1059.001: Command and Scripting Interpreter, PowerShell | https://attack.mitre.org/techniques/T1059/<br>https://attack.mitre.org/techniques/T1059/001/ | primer (basis pengetahuan MITRE) | T1059 versi 2.7, diubah 2026-05-12; T1059.001 versi 1.6, diubah 2026-09-18; diakses 2026-10-21 | Tinggi. 13 sub-technique; contoh procedure Sandworm Team, Akira, APT29 |
| S11 | MITRE ATT&CK T1021: Remote Services | https://attack.mitre.org/techniques/T1021/ | primer (basis pengetahuan MITRE) | versi 1.6, diubah 2025-10-24; diakses 2026-10-21 | Tinggi. Delapan sub-technique termasuk RDP dan SSH |
| S12 | MITRE ATT&CK T1486: Data Encrypted for Impact | https://attack.mitre.org/techniques/T1486/ | primer (basis pengetahuan MITRE) | versi 1.5, diubah 2026-05-12; diakses 2026-10-21 | Tinggi |
| S13 | MITRE ATT&CK T1490: Inhibit System Recovery | https://attack.mitre.org/techniques/T1490/ | primer (basis pengetahuan MITRE) | versi 1.6, diubah 2026-05-12; diakses 2026-10-21 | Tinggi. `vssadmin` untuk menghapus shadow copy |
| S14 | MITRE ATT&CK T1003: OS Credential Dumping | https://attack.mitre.org/techniques/T1003/ | primer (basis pengetahuan MITRE) | versi 2.2, diubah 2025-10-24; diakses 2026-10-21 | Tinggi. Delapan sub-technique, termasuk LSASS Memory dan SAM |
| S15 | MITRE ATT&CK T1595: Active Scanning dan T1046: Network Service Discovery | https://attack.mitre.org/techniques/T1595/<br>https://attack.mitre.org/techniques/T1046/ | primer (basis pengetahuan MITRE) | T1595 versi 1.0, diubah 2025-10-24; T1046 versi 3.2, diubah 2026-05-12; diakses 2026-10-21 | Tinggi. Beda scan sebagai Reconnaissance dan Discovery |
| S16 | MITRE ATT&CK T1505.003 Web Shell, T1552.001 Credentials In Files, T1071.001 Web Protocols, T1204.002 Malicious File | https://attack.mitre.org/techniques/T1505/003/<br>https://attack.mitre.org/techniques/T1552/001/<br>https://attack.mitre.org/techniques/T1071/001/<br>https://attack.mitre.org/techniques/T1204/002/ | primer (basis pengetahuan MITRE) | diubah antara 2026-05-12 dan 2026-09-11; diakses 2026-10-21 | Tinggi. Dipakai untuk pemetaan bagian 2.2 dan 2.4 |
| S17 | MITRE ATT&CK T1566: Phishing | https://attack.mitre.org/techniques/T1566/ | primer (basis pengetahuan MITRE) | versi 2.8, diubah 2026-09-18; diakses 2026-10-21 | Tinggi |
| S18 | MITRE ATT&CK: Groups dan Campaigns | https://attack.mitre.org/groups/<br>https://attack.mitre.org/campaigns/ | primer (basis pengetahuan MITRE) | diakses 2026-10-21 | Tinggi. Definisi group dan campaign, 182 group, 61 campaign, alias APT29 |
| S19 | MITRE ATT&CK: Updates October 2025 (v18) | https://attack.mitre.org/resources/updates/updates-october-2025/ | primer (catatan rilis MITRE) | v18 terbit 2025-10-28; diakses 2026-10-21 | Tinggi. Detection strategies, analytics, data sources dihentikan |
| S20 | Hutchins, Cloppert, Amin: Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains | https://www.lockheedmartin.com/content/dam/lockheed-martin/rms/documents/cyber/LM-White-Paper-Intel-Driven-Defense.pdf | primer (paper asli Lockheed Martin) | umumnya dikutip 2011 (metadata PDF 2010); diakses 2026-10-21 | Tinggi. Tujuh tahap, asal-usul militer, courses of action, definisi APT |
| S21 | Lockheed Martin: Cyber Kill Chain | https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html | primer (halaman resmi) | diakses 2026-10-21 | Sedang. Halaman tidak mencantumkan nama tahap; dipakai untuk posisi Kill Chain dan ringkasan APT |
| S22 | Caltagirone, Pendergast, Betz: The Diamond Model of Intrusion Analysis | https://www.activeresponse.org/wp-content/uploads/2013/07/diamond.pdf<br>https://apps.dtic.mil/sti/pdfs/ADA586960.pdf | primer (paper asli) | 2013; diakses 2026-10-21 | Tinggi. Aksioma, empat sudut, meta-feature, pivot, hubungan dengan Kill Chain. Salinan DTIC menolak akses otomatis saat riset; isi dibaca dari salinan pertama |
| S23 | Unified Kill Chain | https://www.unifiedkillchain.com/ | primer (situs pembuat) | diakses 2026-10-21 | Sedang. Penulis, gabungan Kill Chain dan ATT&CK, tiga kelompok besar; halaman tidak mencantumkan daftar 18 tahap |
| S24 | Wikipedia: Cyber kill chain | https://en.wikipedia.org/wiki/Cyber_kill_chain | sekunder (ensiklopedia) | diakses 2026-10-21 | Sedang. Kritik terhadap Kill Chain, 18 tahap UKC, tahun 2017 dan 2021 |
| S25 | MITRE D3FEND | https://d3fend.mitre.org/ | primer (basis pengetahuan MITRE) | versi 1.6.0; diakses 2026-10-21 | Tinggi untuk definisi dan tujuh tactic |
| S26 | NIST CSRC Glossary: advanced persistent threat | https://csrc.nist.gov/glossary/term/advanced_persistent_threat | primer (glosarium NIST) | diakses 2026-10-21 | Tinggi. Definisi SP 800-39 dan versi yang lebih baru |
| S27 | NIST CSRC Glossary: threat actor | https://csrc.nist.gov/glossary/term/threat_actor | primer (glosarium NIST) | diakses 2026-10-21 | Tinggi. Definisi SP 800-150 dan SP 800-221 |
| S28 | NIST CSRC Glossary: insider threat | https://csrc.nist.gov/glossary/term/insider_threat | primer (glosarium NIST) | diakses 2026-10-21 | Tinggi |
| S29 | CISA: Defining Insider Threats | https://www.cisa.gov/topics/physical-security/insider-threat-mitigation/defining-insider-threats | primer (panduan pemerintah AS) | diakses 2026-10-21 | Tinggi. Definisi insider dan jenis insider threat |
| S30 | CISA: Nation-State Cyber Actors | https://www.cisa.gov/topics/cyber-threats-and-advisories/nation-state-cyber-actors | primer (panduan pemerintah AS) | diakses 2026-10-21 | Tinggi. Hubungan ancaman negara dengan APT, motif per negara |
| S31 | ENISA: EU consistently targeted by diverse yet convergent threat groups (ENISA Threat Landscape 2025) | https://www.enisa.europa.eu/news/etl-2025-eu-consistently-targeted-by-diverse-yet-convergent-threat-groups | primer (badan siber Uni Eropa) | 2025-10-01; diakses 2026-10-21 | Tinggi. Kategori pelaku, porsi hacktivism, ransomware, jalur masuk, konvergensi TTP. Angka dari siaran pers, bukan dari PDF laporan lengkap |

**Catatan sumber:** daftar 18 tahap Unified Kill Chain tidak ditulis di Day ini karena situs pembuatnya tidak menampilkannya dan sumber yang memuatnya hanya sekunder [S23][S24]. Kritik terhadap Kill Chain di bagian 1.2 berasal dari sumber sekunder [S24]. Tabel "Tanda di lapangan" per kategori pelaku di bagian 1.8 dan tiga pertanyaan APT di bagian 1.9 adalah susunan catatan ini dari definisi NIST, CISA, dan ENISA, bukan daftar resmi. Angka ENISA diambil dari siaran persnya; laporan lengkapnya sudah punya revisi PDF yang lebih baru. Seluruh isi PT JAB (kronologi dan bukti `INC-2026-017` yang disederhanakan, alert `SOC-2027-0876` sampai `SOC-2027-0879`, insiden `INC-2027-093`, akun, host, alamat IP, dan perbaikan) adalah contoh fiktif.
