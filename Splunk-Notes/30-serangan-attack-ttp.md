---
day: 30
title: 'Serangan, ATT&CK, TTP, dan tingkatan threat intelligence'
researched_on: 2026-10-10
versions_checked: 'MITRE ATT&CK v19 (Enterprise, 15 taktik; v19 rilis 28 Apr 2026; v19.2 Agu 2026; T1053.005 versi 1.8 dimodifikasi 12 Mei 2026 dengan Detection Strategy DET0441 dan Analytic AN1221); NIST CSRC Glossary (TTP dari SP 800-150, APT dari SP 800-39, zero trust dari SP 800-207); MWR InfoSecurity/CPNI/CERT-UK "Threat Intelligence: Collecting, Analysing, Evaluating" (2015); MITRE "TTP-Based Hunting" (Mar 2019); Pyramid of Pain (Bianco, 2013); Verizon DBIR 2026 (19 Mei 2026); FBI IC3 Internet Crime Report 2025 (via liputan); Windows Security event 4698 (Microsoft Learn); Splunk CIM 6.4; Splunk ES 8.7'
---

# Day 30: Serangan, ATT&CK, TTP, dan tingkatan threat intelligence

Cakupan: jenis serangan dan attack vector beserta istilah yang sering tertukar, cara perilaku penyerang dideskripsikan sebagai tactics, techniques, dan procedures di MITRE ATT&CK v19, dan empat tingkatan threat intelligence beserta cara memakainya saat triage, hunting, dan menulis detection.

## Ide inti

Satu laporan ancaman selalu memuat tiga lapisan yang tercampur: apa yang terjadi (jenis serangan dan jalan masuknya), bagaimana penyerang berperilaku (tactics, techniques, and procedures, yang di industri dipetakan ke MITRE ATT&CK), dan daftar indikator teknis seperti IP, domain, dan hash. Pekerjaan analyst adalah memilah laporan itu ke lapisannya, karena tiap lapisan punya konsumen, masa berlaku, dan tindak lanjut yang berbeda. Indikator dipakai cepat lalu basi; perilaku bertahan lintas kampanye dan menjadi dasar detection dan hunting; gambaran besar ancaman menentukan apa yang diprioritaskan tahun ini.

Kamu sudah melakukan pemilahan serupa di NOC. Memblokir satu serial number modem yang nakal menyelesaikan satu kasus, sedangkan mengenali pola gangguan yang terulang di semua modem seri itu menyelesaikan seluruh keluhan. Laporan gangguan yang sama juga dibaca tiga pihak dengan cara berbeda: direksi mencari dampak dan tren, engineer mencari metode perbaikan, dan NOC mencari daftar perangkat yang harus di-reset malam ini. Threat intelligence bekerja sama persis: satu laporan, tiga sampai empat pembaca, dan nilainya hilang kalau semua orang hanya menyalin daftar indikator di lampiran.

```
Laporan ancaman (satu dokumen)
  |
  +-- jenis serangan dan attack vector  : apa yang terjadi, lewat mana masuknya   (bagian 1.1, 1.2)
  +-- angka tren dan kerugian           : apa yang perlu diprioritaskan            (bagian 1.3)
  +-- perilaku (TTP, ID ATT&CK)         : detection dan hipotesis hunting          (bagian 1.4 - 1.8)
  +-- indikator teknis (IP, domain, hash): blokir dan retro-hunt, masa berlaku pendek (bagian 1.7, 1.9)
  |
  +-- siapa yang memakainya: board, detection engineer, analyst L1, sistem otomatis (bagian 1.9)
```

Situasi yang dipakai sepanjang Day ini: SOC lead PT Jaringan Anak Bangsa (PT JAB, ISP fiktif) meneruskan laporan ancaman dari forum berbagi informasi antar ISP ke channel SOC dan membuka tiket kerja `SOC-2026-0263`:

> "Ada laporan kampanye yang menyasar ISP di kawasan ini. Ringkasnya: masuk lewat kerentanan di aplikasi portal yang menghadap internet, lalu bikin scheduled task bernama mirip layanan update yang menjalankan script dari `C:\Users\Public` setiap logon, ambil data billing, dan di beberapa korban berakhir ransomware. Lampirannya 40 IP, 12 domain, dan 6 hash. Direksi minta slide dua halaman minggu depan. Pertanyaanku: ini jenis serangan apa dan masuknya lewat mana, apa yang harus aku bilang ke direksi soal prioritas, bagian mana dari laporan ini yang jadi detection, dan kalau kita sudah punya alert schtasks apakah kita boleh bilang sudah aman?"

Pesan itu memuat enam pertanyaan:

1. Bagian mana dari laporan yang menyebut vector dan bagian mana yang menyebut jenis serangan, dan kenapa bedanya penting?
2. Istilah di laporan (supply chain, exfiltration, C2, ransomware, BEC) artinya persis apa, dan sinyal datanya di Splunk ada di mana?
3. Apa yang dipakai untuk menjawab direksi soal prioritas?
4. Kalimat "membuat scheduled task untuk persistence" itu berada di tingkat mana, dan bagaimana menuliskannya dalam bahasa ATT&CK v19?
5. Kenapa 40 IP dan 6 hash di lampiran bukan bagian paling bernilai dari laporan itu?
6. Apakah satu alert `schtasks /create` berarti teknik itu sudah tertutup?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4 sampai 1.6, pertanyaan 5 di bagian 1.7 dan 1.9, dan pertanyaan 6 di bagian 1.8. Bagian 2 menjalankan semuanya sebagai search, dan bagian 1.10 merangkai laporan itu menjadi detection.

**Kapan relevan:** membaca laporan ancaman atau laporan vendor dan memutuskan tindak lanjutnya, menulis atau menilai annotation ATT&CK pada detection, menyusun hipotesis hunting dari intel, menjelaskan kondisi ancaman ke manajemen, dan menyeragamkan istilah di note tiket supaya tidak ada dua orang memakai kata yang sama untuk hal berbeda.
**Kapan bukan jawaban:** saat alert sudah ada di depanmu dan pertanyaannya "benar atau tidak" (itu alur triage di Day 07), saat yang dibutuhkan sintaks SPL atau normalisasi field (Day 11 sampai 14 dan Day 23 sampai 25), dan saat pertanyaannya tentang konfigurasi feed intel atau annotation di dalam Enterprise Security (Day 33).

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah Splunk dari Day sebelumnya (index, sourcetype, data model, `tstats`, detection) tidak diulang. Tabel ini memuat istilah kerangka ancaman yang dipakai di Day ini; definisi jenis serangan sendiri ada di tabel bagian 1.2, supaya tidak ditulis dua kali. Kolom padanan memakai hal yang sudah kamu kerjakan di NOC dan SOC.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Attack vector | Jalan masuk atau metode yang dipakai untuk mendapatkan akses awal | Penyebab gangguan: fiber putus, catu daya POP mati |
| Attack type | Jenis serangan menurut cara atau tujuannya | Gejala yang dilaporkan pelanggan: internet mati, lambat |
| IOC (indicator of compromise) | Nilai teknis yang menandai aktivitas berbahaya: IP, domain, hash, nama file | Serial number perangkat yang masuk daftar bermasalah |
| TTP | Perilaku aktor pada tiga tingkat: tactic, technique, procedure | Tiga tingkat di laporan gangguan: tujuan, metode, perintah persis |
| Tactic | Tujuan penyerang pada satu tahap, misalnya Persistence | Tujuan penanganan: memulihkan layanan |
| Technique | Cara umum mencapai tujuan itu, misalnya memakai scheduled task | Metode: reroute trafik, ganti modul |
| Sub-technique | Varian yang lebih sempit dari sebuah technique | Varian metode per platform perangkat |
| Procedure | Implementasi spesifik satu aktor: alat, perintah, parameter | Perintah persis yang diketik teknisi di perangkat |
| MITRE ATT&CK | Basis pengetahuan perilaku penyerang yang memberi ID pada taktik, teknik, aktor, dan alat | Katalog kode gangguan bersama yang dipakai semua vendor |
| Procedure example | Contoh nyata pemakaian satu teknik oleh group atau software di ATT&CK | Catatan kasus nyata di knowledge base NOC |
| Detection Strategy dan Analytic | Objek ATT&CK sejak v18 yang menjelaskan apa perilakunya dan cara mendeteksinya per platform | Prosedur deteksi gangguan beserta counter yang harus dilihat |
| Pyramid of Pain | Urutan indikator menurut biaya penggantiannya bagi penyerang | Urutan dari memblokir satu serial perangkat sampai mengenali pola gangguannya |
| Threat intelligence | Pengetahuan tentang ancaman yang sudah diolah sehingga bisa dipakai mengambil keputusan | Laporan gangguan yang sudah dianalisis, bukan dump log mentah |
| Tingkatan intel (strategic, operational, tactical, technical) | Pembagian intel menurut konsumen dan horizon waktunya | Satu laporan gangguan yang dibaca direksi, engineer, dan NOC dengan cara berbeda |
| Threat match | Pencocokan otomatis indikator intel dengan data yang masuk | Pencocokan serial perangkat dengan daftar recall vendor |
| Annotation | Label konteks pada detection, misalnya ID teknik ATT&CK | Kode kategori gangguan yang ditempel di tiket |
| Cakupan (coverage) | Seberapa banyak perilaku yang benar-benar tertangkap detection aktif | Cakupan titik monitoring: hanya segmen yang dipantau yang terlihat |

### 1.1 Attack vector dan attack type: dua pertanyaan berbeda

Laporan yang diteruskan SOC lead PT JAB menyebut "kerentanan di aplikasi portal" dan "berakhir ransomware" dalam satu kalimat. Keduanya bukan hal yang sejenis, dan menyamakannya membuat tindak lanjutnya salah sasaran.

- **Attack vector:** jalur atau metode masuk. Contoh: phishing email, eksploitasi aplikasi yang menghadap internet, kredensial curian di VPN, perangkat atau USB, dan pihak ketiga (supply chain).
- **Attack type:** jenis serangan menurut cara atau tujuannya. Contoh: ransomware, DoS dan DDoS, exfiltration, BEC, defacement.

Satu insiden biasanya punya satu vector awal dan beberapa tahap. Contoh: phishing (vector), lalu eksekusi makro, C2, exfiltration, dan akhirnya ransomware (type atau impact). Di PT JAB, vector yang realistis adalah portal pelanggan yang menghadap internet, kredensial VPN vendor yang dipakai bersama, dan phishing ke staf billing. Vector menentukan apa yang harus ditutup oleh tim infrastruktur; type menentukan seberapa besar dampaknya dan siapa yang harus dilibatkan saat kejadian.

**Tren vector terbaru:** Verizon DBIR 2026 (rilis 19 Mei 2026; 22.000 breach terkonfirmasi) melaporkan eksploitasi kerentanan (31%) untuk pertama kalinya mengalahkan penyalahgunaan kredensial (13%) sebagai vector akses awal teratas. Ransomware muncul di 48% breach, dan breach yang melibatkan pihak ketiga atau supply chain naik sekitar 60% [S1]. Angka ini diambil dari liputan media atas laporan tersebut, jadi cocokkan dengan laporan aslinya sebelum masuk ke slide direksi.

### 1.2 Glosarium istilah serangan dan sinyal datanya

Pertanyaan kedua SOC lead adalah arti persis istilah di laporan. Tabel ini memuat definisi dengan kata sendiri, teknik ATT&CK yang terkait, dan tempat mencari sinyalnya di Splunk; kolom terakhir memakai nama data model dan field CIM 6.4 [S17], jadi bacanya sebagai titik awal pencarian, bukan sebagai detection siap pakai.

| Istilah | Definisi (kata sendiri) | ATT&CK terkait | Sinyal di Splunk/CIM |
|---|---|---|---|
| Supply chain attack | Mengkompromikan produk, pembaruan, atau penyedia sebelum sampai ke korban, sehingga korban membuka jalan bagi penyerang lewat jalur tepercaya | T1195 Supply Chain Compromise (.001 dependensi dan alat dev, .002 software supply chain, .003 hardware), taktik Initial Access [S2] | Proses anak tak biasa dari updater atau agen vendor (Endpoint.Processes), koneksi baru dari aplikasi tepercaya (Network_Traffic) |
| Ransomware | Malware yang mengenkripsi atau mengunci data dan sistem lalu meminta tebusan. Sering disertai pencurian data (double extortion) | Impact: T1486 Data Encrypted for Impact, T1490 Inhibit System Recovery (hapus shadow copy dan backup); sering juga mematikan alat keamanan (Defense Impairment) | Banyak modifikasi file (Endpoint.Filesystem), `vssadmin` dan `wbadmin` (Endpoint.Processes), catatan tebusan |
| Registry | Basis data konfigurasi hierarkis Windows (hive, key, value). Disalahgunakan untuk persistence, konfigurasi malware, atau melemahkan pertahanan | Persistence: T1547.001 Registry Run Keys / Startup Folder; T1112 Modify Registry (cek taktiknya di v19, dulu Defense Evasion) | Sysmon EID 12-14 ke Endpoint.Registry (`registry_path`, `registry_value_data`) |
| Exfiltration | Mengeluarkan data dari lingkungan korban | Taktik TA0010 [S6] | Volume keluar besar atau tak biasa (`bytes_out`), unggahan ke cloud storage (Web.Storage), DNS tunneling (Network_Resolution) |
| Social engineering | Memanipulasi manusia agar memberi akses, data, atau melakukan tindakan | T1566 Phishing (Initial Access) | Email (Email DM), klik URL (Web), login setelah phishing (Authentication) |
| DoS | Membuat layanan tidak tersedia dari satu sumber atau sedikit sumber | Impact: T1498 Network Denial of Service, T1499 Endpoint Denial of Service | Lonjakan koneksi dari satu `src`, error 5xx |
| DDoS | DoS dari banyak sumber terdistribusi (sering botnet), sehingga sulit diblokir per IP | Impact | Lonjakan dari banyak `src` sekaligus (Network_Traffic), `dc(src)` tinggi |
| Bot dan botnet | Bot: perangkat yang dikendalikan otomatis oleh penyerang. Botnet: jaringan bot yang dikendalikan terpusat lewat C2 | Resource Development, C2 | Beaconing periodik (Day 39), koneksi ke infrastruktur C2 yang dikenal |
| C2 (command and control) | Kanal komunikasi penyerang dengan sistem yang dikompromikan | Taktik TA0011, yaitu penyerang berusaha berkomunikasi dengan sistem terkompromi untuk mengendalikannya. Teknik: Application Layer Protocol T1071, Encrypted Channel T1573, Dynamic Resolution T1568, Proxy T1090, Remote Access Tools T1219 [S3] | DNS atau HTTP periodik, domain baru dan DGA, user agent aneh, alat remote access tak resmi |
| Zero trust | Prinsip keamanan yang meminimalkan ketidakpastian dalam keputusan akses least privilege per permintaan, dengan asumsi jaringan sudah terkompromi (NIST SP 800-207) [S4] | Konsep pertahanan, bukan teknik | Log keputusan akses IdP dan ZTNA, MFA, posture device (Authentication) |
| Account takeover (ATO) | Penyerang menguasai akun sah (kredensial curian, credential stuffing, session hijacking) dan memakainya seperti pemilik | T1078 Valid Accounts, Credential Access | Login dari lokasi atau perangkat baru, impossible travel, reset MFA, aktivitas tidak biasa setelah login |
| Email compromise atau BEC | Penipuan lewat email (sering memakai akun sah yang diambil alih atau pemalsuan), umumnya untuk transfer dana atau data. Bisa memakai ATO sebagai sarana | Phishing, Valid Accounts, aturan kotak masuk: T1114.003 Email Forwarding Rule, T1564.008 Email Hiding Rules (cek taktik T1564 di v19) | Pembuatan inbox rule dan forwarding di M365 (`o365:management:activity`, cek nama operasi), login aneh ke email |
| Threat actor | Individu atau kelompok yang melakukan atau berniat melakukan aktivitas berbahaya (kriminal, negara, hacktivist, insider) | Groups di ATT&CK | Konteks dari intel (bagian 1.9) |
| APT | Adversary dengan keahlian dan sumber daya signifikan yang memakai banyak vektor untuk membangun pijakan, mengejar tujuan berulang dalam waktu lama, beradaptasi terhadap pertahanan, dan bertekad mempertahankan akses (NIST, dari SP 800-39) [S5] | Groups (misalnya Gxxxx) | Dwell time panjang, teknik low and slow, living off the land |
| Adversary | Istilah umum untuk pihak yang berlawanan, yaitu yang melakukan serangan. Dipakai ATT&CK sebagai sudut pandang perilaku adversary | Seluruh ATT&CK | Tidak ada sinyal khusus |

**Membedakan istilah yang mirip:**

- Threat actor adalah siapa yang mungkin menyerang. Adversary adalah pihak yang menyerang dalam konteks spesifik atau berlawanan. APT adalah jenis adversary yang canggih dan persisten.
- BEC adalah tujuan atau penipuan lewat email. ATO adalah cara menguasai akun. BEC sering memakai ATO, tetapi bisa juga memakai domain mirip tanpa ATO.
- DoS dan DDoS dibedakan oleh jumlah dan sebaran sumber, bukan oleh besarnya trafik.

### 1.3 Dampak dan prioritas: data 2025-2026

Direksi PT JAB tidak akan membaca ID teknik. Yang bisa dipakai di slide dua halaman adalah angka tren dan kerugian, dengan catatan dari mana angkanya.

Laporan IC3 FBI 2025, diakses lewat liputan media [S7]:

- **BEC:** sekitar USD 3,046 miliar kerugian yang dilaporkan dari 24.768 aduan. Ini ancaman berorientasi bisnis yang paling merusak secara finansial di AS. Ada kerugian BEC dengan keterkaitan AI.
- **Ransomware:** kerugian yang dilaporkan hanya sekitar USD 32,3 juta, tetapi 63 varian baru teridentifikasi.

Angka kerugian ransomware di IC3 jauh di bawah kesan umum karena hanya mencakup yang dilaporkan dan dihitung IC3. Biaya downtime dan pemulihan umumnya tidak tercakup. Hal ini sering disebut dalam analisis laporan IC3, perlu dicek di laporan aslinya di ic3.gov. Angka total kerugian juga berbeda antar liputan (sekitar USD 17 miliar untuk penipuan siber dibanding 20,877 miliar untuk kejahatan berbasis siber), jadi rujuk laporan aslinya sebelum angka itu dipakai.

Cara memakai dua laporan ini di PT JAB: DBIR menjawab "lewat mana orang kebobolan" sehingga mengarahkan prioritas penutupan vector (patching portal yang menghadap internet, kebersihan kredensial vendor), sedangkan IC3 menjawab "apa yang paling mahal" sehingga mengarahkan perhatian ke BEC di sisi keuangan dan billing. Dua pertanyaan itu bisa menghasilkan prioritas berbeda, dan keduanya tetap harus dibandingkan dengan paparan PT JAB sendiri: ISP punya portal pelanggan, RADIUS, dan data billing, yang tidak persis sama dengan rata-rata responden laporan.

### 1.4 Tactic, technique, procedure: tiga tingkat perilaku

Kalimat di laporan PT JAB, "membuat scheduled task bernama mirip layanan update yang menjalankan script dari `C:\Users\Public` setiap logon", memuat tiga tingkat sekaligus. Memisahkannya menentukan bagian mana yang pantas dijadikan detection dan bagian mana yang hanya bertahan beberapa hari.

NIST SP 800-150 mendefinisikan TTP sebagai perilaku aktor, dengan tiga tingkat [S8]:

- **Tactic:** deskripsi tingkat tertinggi, yaitu tujuan (kenapa).
- **Technique:** deskripsi lebih rinci tentang perilaku dalam konteks sebuah taktik, yaitu cara umum (bagaimana).
- **Procedure:** deskripsi tingkat terendah dan sangat rinci dalam konteks teknik, yaitu implementasi spesifik berupa alat, perintah, dan parameter yang dipakai aktor tertentu.

Tabel berikut menurunkan satu contoh dari tingkat paling umum ke paling spesifik; perhatikan bahwa hanya baris terakhir yang berisi hal yang mudah diganti penyerang.

| Tingkat | Contoh |
|---|---|
| Tactic | Persistence (TA0003): penyerang ingin bertahan di sistem |
| Technique | Scheduled Task/Job (T1053) |
| Sub-technique | Scheduled Task (T1053.005) |
| Procedure | "Aktor X menjalankan `schtasks /create /sc onlogon /tr C:\Users\Public\u.bat` dari PowerShell", atau Sandworm Team memakai scheduled task lewat GPO untuk menjalankan wiper pada waktu tertentu (procedure example di ATT&CK) [S10] |

Jadi untuk laporan PT JAB: taktiknya Persistence (dan Execution saat task berjalan), tekniknya T1053.005, sedangkan nama task dan path `C:\Users\Public` adalah detail procedure yang bisa diubah penyerang dalam satu menit.

### 1.5 Taktik ATT&CK v19 sebagai peta

Taktik adalah kolom paling kiri dari peta yang dipakai hampir semua laporan, detection, dan dashboard cakupan. ATT&CK Enterprise kini memiliki 15 taktik [S6]:

| ID | Taktik | ID | Taktik |
|---|---|---|---|
| TA0043 | Reconnaissance | TA0006 | Credential Access |
| TA0042 | Resource Development | TA0007 | Discovery |
| TA0001 | Initial Access | TA0008 | Lateral Movement |
| TA0002 | Execution | TA0009 | Collection |
| TA0003 | Persistence | TA0011 | Command and Control |
| TA0004 | Privilege Escalation | TA0010 | Exfiltration |
| TA0005 | Stealth | TA0040 | Impact |
| TA0112 | Defense Impairment | | |

**Perubahan v19 (28 Apr 2026):** taktik Defense Evasion dipecah menjadi Stealth (mewarisi ID TA0005, yaitu menyembunyikan aktivitas di balik perilaku sah) dan Defense Impairment (TA0112, baru, yaitu menonaktifkan, merusak, atau mengkompromikan kontrol keamanan seperti logging dan alat keamanan). Beberapa teknik dipetakan ke keduanya [S6][S9].

Banyak materi lama, termasuk laporan vendor dan slide pelatihan, masih menyebut 14 taktik dengan Defense Evasion. Kenali keduanya supaya tidak salah saat membaca tulisan lama, dan selalu sebut versi ATT&CK saat kamu sendiri menulis pemetaan.

### 1.6 Anatomi halaman teknik ATT&CK dan objek lainnya

Saat menulis annotation atau membalas laporan intel, yang dibuka adalah halaman teknik. Isinya punya pola tetap. Ambil contoh T1053.005 Scheduled Task (versi 1.8, dimodifikasi 12 Mei 2026), yang persis teknik di laporan PT JAB [S10]:

- **Parent technique:** T1053 Scheduled Task/Job.
- **Taktik:** Execution (TA0002), Persistence (TA0003), Privilege Escalation (TA0004). Satu teknik bisa melayani beberapa taktik, karena tujuan menentukan taktik, bukan alatnya.
- **Procedure examples:** contoh nyata dari Groups (misalnya APT29 G0016, Sandworm Team G0034) dan Software (misalnya Agent Tesla S0331) [S10]. Ini level procedure.
- **Mitigations:** misalnya M1047 Audit, M1028 OS Configuration, M1026 Privileged Account Management, M1018 User Account Management [S10].
- **Detection:** sejak v18 berupa Detection Strategy (misalnya DET0441) dan Analytic (misalnya AN1221), yang menjelaskan apa perilakunya dan bagaimana mendeteksinya per platform: pembuatan, modifikasi, atau penghapusan task lewat Task Scheduler, WMI, PowerShell, atau API, serta pola eksekusi anomali [S10].

Objek lain di ATT&CK punya format ID sendiri. Tabel ini dipakai untuk membaca ID yang muncul di laporan orang lain dan memilih ID yang benar saat kamu menulis pemetaan.

| Objek | Format ID | Contoh | Dipakai untuk |
|---|---|---|---|
| Tactic | TAxxxx | TA0003 Persistence | Mengelompokkan detection dan finding menurut tujuan penyerang |
| Technique | Txxxx | T1053 Scheduled Task/Job | Satuan utama pemetaan detection dan laporan cakupan |
| Sub-technique | Txxxx.yyy | T1053.005 Scheduled Task | Pemetaan yang lebih presisi; pakai bila tersedia |
| Group | Gxxxx | G0016 APT29 | Menghubungkan aktor dengan teknik yang pernah dipakai |
| Software | Sxxxx | S0331 Agent Tesla | Malware dan tool beserta tekniknya |
| Campaign | Cxxxx | Kampanye dengan rentang waktu tertentu | Aktivitas spesifik dalam periode tertentu |
| Mitigation | Mxxxx | M1047 Audit | Kontrol pencegahan per teknik |
| Detection Strategy | DETxxxx | DET0441 | Gambaran cara mendeteksi satu teknik (v18 ke atas) |
| Analytic | ANxxxx | AN1221 | Logika deteksi per platform di dalam Detection Strategy |
| Data Component | DCxxxx | Misalnya pembuatan scheduled job | Jenis telemetri yang dibutuhkan analytic |

Pakai ID sub-technique bila tersedia, dan selalu sebut versi ATT&CK, karena nama dan penempatan taktik bisa berubah antar versi seperti pada pemecahan Defense Evasion di bagian 1.5.

### 1.7 Kenapa TTP: Pyramid of Pain dan TTP-based hunting

Pertanyaan kelima SOC lead adalah kenapa 40 IP dan 6 hash di lampiran bukan bagian paling bernilai. Jawabannya sudah berumur lebih dari satu dekade dan masih dipakai.

Pyramid of Pain (David Bianco, 2013) mengurutkan indikator menurut seberapa "sakit" bagi penyerang bila indikator itu dideteksi dan ditolak [S11][S12]:

```
            TTPs              <- paling sulit diubah penyerang ("Tough!")
           Tools
     Network/Host Artifacts
        Domain Names
        IP Addresses
        Hash Values           <- paling mudah diubah ("Trivial")
```

Bila kamu mendeteksi dan menolak TTP dengan cepat, penyerang terpaksa mempelajari perilaku baru, dan itu hal paling mahal baginya [S12]. Mengganti hash atau IP murah sekali.

Tabel berikut menjabarkan tiap level menjadi biaya penggantian bagi penyerang dan konsekuensinya bagi SOC; cari baris yang cocok dengan isi lampiran laporan yang sedang kamu baca.

| Level | Contoh | Biaya bagi penyerang untuk mengganti | Konsekuensi untuk SOC |
|---|---|---|---|
| Hash values | SHA256 file loader | Hampir nol: kompilasi ulang atau ubah satu byte | Bagus untuk retro-hunt dan blokir cepat, tidak tahan lama |
| IP addresses | IP server C2 | Rendah: sewa VPS baru, pakai proxy atau layanan cloud | Cepat basi, dan IP bisa berpindah ke pemilik sah, jadi indikator IP perlu masa berlaku |
| Domain names | Domain C2 | Rendah sampai sedang: registrasi dan reputasi butuh sedikit waktu | Sedikit lebih awet dari IP; perhatikan domain baru dan NXDomain |
| Network/host artifacts | Pola URI, user agent, nama file, nama task, registry key | Sedang: harus mengubah konfigurasi tool | Mulai menyentuh perilaku; masih bisa diakali dengan konfigurasi |
| Tools | Tool dump kredensial tertentu, framework C2 tertentu | Tinggi: harus mencari atau membuat tool lain | Detection berbasis karakteristik tool, bukan hash-nya |
| TTPs | Membuat scheduled task untuk persistence, dump LSASS | Paling tinggi: harus mengganti cara kerja | Detection perilaku bertahan lintas kampanye dan tool |

Cara memakai tabel ini di pekerjaan: saat menerima laporan intel, pisahkan isinya ke level piramida. Level bawah dimasukkan ke threat list dengan masa berlaku. Level atas diubah menjadi hipotesis hunting dan detection perilaku.

TTP-Based Hunting (MITRE, Mar 2019) sampai pada kesimpulan sejenis dari arah lain [S13]: mengumpulkan dan memfilter data berdasarkan pengetahuan TTP adalah cara efektif mendeteksi aktivitas berbahaya, karena teknologi tempat penyerang beroperasi membatasi jumlah dan jenis teknik yang bisa mereka pakai setelah kompromi. Pendekatan ini disebut efisien dan relatif murah dibanding manfaatnya. Laporan tersebut dibuat untuk Cyber National Mission Force (USCYBERCOM) [S13].

**Keseimbangan:** IOC tetap berguna untuk respons cepat dan retro-hunt. Yang dilakukan program deteksi yang matang adalah memprioritaskan TTP dan mengukur cakupan per teknik (Detection Studio, Day 27), bukan membuang IOC.

### 1.8 Procedure dibanding technique: masalah cakupan

Pertanyaan terakhir SOC lead, "kalau kita sudah punya alert `schtasks`, apakah kita boleh bilang sudah aman", adalah pertanyaan cakupan. Jawaban jujurnya tidak, dan alasannya struktural.

Detection biasanya menangkap satu atau beberapa procedure, bukan seluruh teknik. Contoh T1053.005:

- Detection "`schtasks.exe /create` dari PowerShell" menangkap satu procedure.
- Ia tidak menangkap task yang dibuat lewat COM atau API, WMI, atau GPO. Semua cara itu disebut di Detection Strategy teknik tersebut [S10].

Jadi "cakupan T1053.005" harus dibaca sebagai "cakupan procedure X dan Y dari T1053.005". Karena itu cakupan sebaiknya dilaporkan per procedure, dan setiap teknik prioritas didukung lebih dari satu sumber data. Satu sumber data bisa hilang (agen mati, audit policy berubah), dan satu procedure bisa diganti penyerang dengan mudah.

Tabel berikut memetakan procedure T1053.005 di Windows ke sumber data yang menangkapnya; pakai sebagai daftar periksa saat menilai cakupan, dan perhatikan bahwa beberapa baris hanya terlihat bila audit policy tertentu aktif.

| Procedure | Sumber data yang menangkapnya | Event dan field kunci |
|---|---|---|
| `schtasks.exe /create` dari shell atau script | Sysmon EID 1 atau Security 4688 dengan command line | `process_name=schtasks.exe`, `process` berisi `/create` |
| Cmdlet `Register-ScheduledTask` atau `New-ScheduledTask` | PowerShell Script Block Logging (4104), Security 4698 | Teks cmdlet di script block; task baru di 4698 |
| API Task Scheduler (COM) langsung dari program | Security 4698, log `Microsoft-Windows-TaskScheduler/Operational` | 4698 berisi XML task; Operational EID 106 (task registered) |
| Task dibuat lewat WMI atau dari host lain (remote) | Security 4698 di host target, logon jaringan (4624 type 3) | Subject di 4698 berasal dari sesi remote |
| Task di-deploy lewat GPO | 4698 di banyak host dalam waktu berdekatan, perubahan di SYSVOL | Pola massal, bukan satu host |
| Modifikasi task yang sudah ada | Security 4702 (task updated), Operational EID 140 | Perubahan `Command` pada task lama |
| Jejak file dan registry | Sysmon EID 11 (file di `C:\Windows\System32\Tasks\`), Sysmon EID 12/13 (key `TaskCache\Tree`) | Berguna bila log Security tidak lengkap |

Event Security lain dari keluarga yang sama: 4699 (task deleted), 4700 (task enabled), dan 4701 (task disabled). Semuanya membutuhkan subkategori audit "Audit Other Object Access Events" [S14]. Eksekusi task terlihat di Operational EID 200 (action started) dan 201 (action completed), serta sebagai proses anak dari `svchost.exe` yang menjalankan layanan Schedule, atau `taskeng.exe` di Windows lama.

### 1.9 Tingkatan threat intelligence dan gunanya bagi analyst

Laporan yang diteruskan SOC lead punya lebih dari satu pembaca di PT JAB, dan masing-masing mengambil bagian yang berbeda. Pembagian yang paling banyak dipakai adalah model empat tipe berbasis konsumen dari MWR, CPNI, dan CERT-UK (2015) [S15]. Baca tabel ini dengan pertanyaan "bagian laporan ini untuk siapa dan berapa lama berlakunya".

| Tingkat | Isi | Konsumen | Horizon | Contoh pemakaian di SOC |
|---|---|---|---|---|
| Strategic | Risiko yang berubah, tren, motif, dampak bisnis | Board, eksekutif | Panjang | Brief kuartalan untuk CISO; prioritas investasi |
| Operational | Detail serangan spesifik yang akan datang ke organisasi | Defender, kepala IR | Pendek | Peringatan kampanye hacktivist yang mengumumkan target; langka |
| Tactical | TTP, yaitu bagaimana aktor beroperasi | Arsitek, sysadmin, detection engineer | Panjang | Detection berbasis perilaku; hipotesis hunting |
| Technical | Indikator: IP, domain, hash | SOC dan IR, sistem otomatis | Pendek, cepat basi | Threat list, blokir, threat match |

**Perhatian:** banyak vendor memakai model tiga tipe dengan arti berbeda. Di model itu, tactical berarti IOC dan operational berarti TTP atau kampanye [S16]. Dalam diskusi, sebutkan isinya, misalnya "intel berbasis IOC" atau "intel TTP". Jangan hanya menyebut labelnya.

**Penerapan pada analisis ancaman:**

- Technical intel dicocokkan otomatis dengan data (threat match, yang di Enterprise Security dikelola lewat threat list; lihat Day 33). Ini cepat, tetapi rapuh dan berumur pendek, jadi setiap indikator perlu masa berlaku.
- Tactical intel diubah menjadi detection perilaku dan hipotesis hunting (Day 38 dan 39). Ini lebih tahan lama, sesuai urutan di bagian 1.7.
- Strategic dan operational menentukan apa yang diprioritaskan SOC: data yang di-onboard, detection yang dibangun, dan latihan yang dijalankan.

Untuk laporan PT JAB, pemilahannya menjadi: paragraf tren dan dampak ke slide direksi (strategic), kalimat tentang scheduled task dan pengambilan data billing ke backlog detection dan hunting (tactical), lampiran 40 IP, 12 domain, dan 6 hash ke daftar indikator dengan masa berlaku untuk blokir dan retro-hunt (technical). Bagian operational biasanya tidak ada di laporan semacam ini, dan ketiadaannya pantas dicatat supaya tidak ada yang mengira laporan ini adalah peringatan serangan yang sedang menuju PT JAB.

### 1.10 Dari laporan ancaman ke detection: urutan kerja

Lima langkah berikut adalah cara mengerjakan tiket `SOC-2026-0263` dari awal sampai laporan cakupan, memakai semua bagian di atas.

1. **Pisahkan level piramida.** Nama task dan path script adalah host artifact yang mudah diganti. Membuat scheduled task untuk persistence adalah TTP: T1053.005, taktik Persistence, dan Execution saat task berjalan (bagian 1.4 dan 1.7).
2. **Tulis hipotesis hunting.** "Bila aktor ini ada di lingkungan PT JAB, akan ada task baru dengan action yang menjalankan file dari folder yang bisa ditulis user biasa, dibuat oleh proses selain installer yang dikenal."
3. **Pilih procedure dan sumber data.** Dari tabel bagian 1.8: Sysmon EID 1 untuk `schtasks.exe`, 4698 untuk semua cara pembuatan task, dan 4104 untuk cmdlet PowerShell. Di PT JAB, Sysmon baru ada di server Windows dan sekitar 40% workstation, jadi 4698 adalah sumber yang lebih merata, asalkan audit policy-nya aktif.
4. **Bangun detection.** Satu detection perilaku (bagian 2.6), satu detection berbasis 4698 yang memeriksa path di action (bagian 2.7), dan satu lookup berisi artifact dan indikator dari laporan beserta masa berlakunya untuk retro-hunt.
5. **Laporkan cakupan per procedure.** Contoh kalimat untuk SOC lead: "T1053.005 di PT JAB: `schtasks` dari shell tertutup lewat Sysmon EID 1 di server dan 40% workstation, semua cara pembuatan task tertutup lewat 4698 di host yang audit policy-nya aktif, cmdlet PowerShell belum tertutup di server lama tanpa script block logging."

Hasilnya lebih jujur daripada satu baris "T1053.005: covered", dan langsung menunjukkan di mana celahnya.

### 1.11 Di mana konteks ini muncul di Splunk

Definisi di Day ini tidak bergantung produk, tetapi Splunk punya tempat khusus untuk menyimpannya supaya analyst tidak perlu menghafal:

- **Annotation pada detection:** detection dipetakan ke `annotations.mitre_attack.mitre_technique_id` dan taktiknya, lalu label itu terbawa sampai ke finding dan dashboard risiko (Day 29 dan Day 33).
- **research.splunk.com:** detection dan analytic story ESCU dikelompokkan per teknik ATT&CK, termasuk analytic story per jenis serangan seperti ransomware dan BEC (Day 45).
- **SSE:** dashboard MITRE ATT&CK Framework dan Benchmark untuk menilai cakupan (Day 27).
- **Detection Studio (ES 8.7):** skor cakupan teknik untuk detection yang aktif (Day 27).
- **Threat intelligence ES:** feed indikator dan threat match untuk level technical (Day 33).

**Tanpa ES:** semua konsep di Day ini tetap berlaku di Splunk Enterprise biasa. Pemetaan ATT&CK disimpan sebagai lookup buatan sendiri yang ditempel ke hasil detection, indikator intel dicocokkan dengan `lookup` biasa, dan cakupan dihitung dari daftar report dan alert terjadwal milikmu. Yang hilang hanya pengelolaannya yang terpusat dan tampilannya di antrean analyst, bukan kemampuan memetakan perilaku.

## 2. Contoh SPL dan langkah di ES

Semua keluaran di bagian ini adalah keluaran ilustrasi dari lingkungan PT JAB, bukan hasil eksekusi, dan setiap ambang di dalamnya adalah asumsi yang harus diuji dulu di data sendiri, misalnya dengan data sintetis `makeresults` (Day 12). Lima contoh pertama mengikuti jenis serangan di bagian 1.2, empat contoh sisanya mengerjakan tiket `SOC-2026-0263` sesuai urutan kerja di bagian 1.10.

### 2.1 Ransomware: penghapusan shadow copy

**Tujuan:** menemukan perintah yang menghapus kemampuan pemulihan Windows, langkah klasik sebelum enkripsi.

```
| tstats summariesonly=false count min(_time) AS first max(_time) AS last values(Processes.process) AS cmd
    from datamodel=Endpoint.Processes
    where (Processes.process_name="vssadmin.exe" Processes.process="*delete*shadows*")
       OR (Processes.process_name="wmic.exe" Processes.process="*shadowcopy*delete*")
       OR (Processes.process_name="wbadmin.exe" Processes.process="*delete*")
    by Processes.dest Processes.user Processes.parent_process_name
| rename Processes.* AS *
| convert ctime(first) ctime(last)
```

- Tiga kondisi `OR` mewakili tiga alat yang sama fungsinya. Di ATT&CK ini T1490 Inhibit System Recovery di taktik Impact.
- `by` memakai `dest`, `user`, dan `parent_process_name` karena ketiganya yang membedakan aksi penyerang dari pekerjaan rutin backup.
- Wildcard di nilai `Processes.process` didukung di `tstats` (Day 25). Leading wildcard tetap mahal (Day 14).

Keluaran ilustrasi, dengan kolom `first` dan `last` dihilangkan supaya ringkas:

| dest | user | parent_process_name | count | cmd |
|---|---|---|---|---|
| JKT-FS01 | JAB\svc_backup | vendorbackup.exe | 6 | `wbadmin delete backup -keepVersions:3` |
| JKT-WS-0523 | JAB\rina.wulandari | wscript.exe | 2 | `vssadmin.exe delete shadows /all /quiet` |

- **Cara membaca hasil:** baris pertama adalah pekerjaan agen backup yang berulang setiap hari dan dijalankan akun service, jadi wajar. Baris kedua dijalankan dari `wscript.exe` oleh akun karyawan biasa dengan `/all /quiet`, dan itu pola ransomware.
- **Variasi:** tambahkan `Processes.process_name="powershell.exe" Processes.process="*Win32_Shadowcopy*"` untuk cara yang memakai WMI lewat PowerShell, dan jalankan ulang per minggu untuk membangun daftar pelaku rutin yang sah.
- **Kapan gagal:** bila command line tidak tercatat (audit process creation tanpa command line, atau Sysmon tidak dipasang), semua kondisi di atas tidak akan pernah cocok. Day 03 bagian 1.2 menjelaskan setelan yang dibutuhkan.

### 2.2 Registry persistence: Run key

**Tujuan:** melihat penambahan autostart di registry, salah satu persistence paling umum.

```
| tstats summariesonly=false count values(Registry.registry_value_data) AS data
    from datamodel=Endpoint.Registry
    where Registry.registry_path="*\\CurrentVersion\\Run*" Registry.action=modified
    by Registry.dest Registry.registry_path Registry.registry_value_name
| rename Registry.* AS *
```

- Pola `*\\CurrentVersion\\Run*` mencakup `Run` dan `RunOnce`, baik di HKLM maupun HKCU.
- Cek nama objek `Endpoint.Registry` dan nilai `action` (misalnya `modified`, `created`) di CIM 6.4 dan add-on Sysmon-mu.

Keluaran ilustrasi, dengan kolom `registry_path` dihilangkan supaya ringkas:

| dest | registry_value_name | count | data |
|---|---|---|---|
| JKT-WS-0523 | EdgeUpdate | 1 | `C:\Users\rina.wulandari\AppData\Roaming\upd.vbs` |
| JKT-JUMP01 | SecurityHealth | 1 | `C:\Program Files\Windows Defender\MSASCuiL.exe` |

- **Cara membaca hasil:** nilai yang menunjuk ke `%APPDATA%`, `%TEMP%`, atau `C:\Users\Public` lebih mencurigakan daripada `Program Files`. Nama value yang meniru produk resmi, seperti baris pertama, adalah upaya menyamarkan diri.
- **Variasi:** ganti path ke `*\\Services\\*` untuk service baru, atau ke key `*\\CurrentVersion\\Winlogon*`.
- **Kapan gagal:** tanpa Sysmon EID 12 sampai 14 atau EDR yang mengirim event registry, data model Registry akan kosong walaupun search-nya benar.

### 2.3 Exfiltration: volume keluar tidak biasa per host

**Tujuan:** menemukan pasangan sumber dan tujuan yang mengirim data keluar jauh di atas kebiasaan.

```
| tstats summariesonly=false sum(All_Traffic.bytes_out) AS out from datamodel=Network_Traffic.All_Traffic
    where earliest=-24h by All_Traffic.src All_Traffic.dest
| rename All_Traffic.* AS *
| eventstats avg(out) AS avg_out stdev(out) AS sd_out
| where out > avg_out + 3*sd_out
| eval out_MB=round(out/1024/1024,1)
| sort - out
```

- `eventstats` menghitung rata-rata dan simpangan baku seluruh pasangan tanpa membuang barisnya, lalu `where` menyisakan yang jauh di atas rata-rata. Ini outlier sederhana (Day 39).
- Rentang relatif `earliest=-24h` dipakai karena index PT JAB berisi data live.

Keluaran ilustrasi dengan `avg_out` sekitar 180 MB dan `sd_out` sekitar 450 MB, sehingga ambangnya sekitar 1.530 MB:

| src | dest | out_MB |
|---|---|---|
| 10.20.30.7 | 198.51.100.188 | 12288.0 |
| 10.10.14.57 | 203.0.113.219 | 3072.0 |

- **Cara membaca hasil:** 12 GB keluar dari satu host layanan di data center ke satu IP eksternal dalam 24 jam layak diinvestigasi, apalagi bila tujuan itu bukan mitra yang dikenal.
- **Penjelasan jinak:** backup ke luar, sinkronisasi cloud, pembaruan OS, dan replikasi antar POP.
- **Variasi:** pecah per jam dengan `span=1h` untuk melihat apakah transfer terjadi di luar jam kerja, dan tambahkan `by All_Traffic.app` bila add-on menyediakannya.
- **Kapan gagal:** bila hanya ada satu atau dua pasangan yang dominan, simpangan bakunya menjadi besar dan tidak ada yang lolos ambang. Pada data dengan sedikit host, pakai persentil atau ambang absolut.

### 2.4 DDoS atau DoS: satu sumber atau banyak sumber

**Tujuan:** membedakan pola DoS dari DDoS pada satu tujuan yang sedang bermasalah, misalnya saat NOC PT JAB melapor portal pelanggan tidak responsif.

```
| tstats summariesonly=false count dc(All_Traffic.src) AS sources from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.dest="203.0.113.8" earliest=-1h by _time span=1m
| eval pattern=case(sources>500, "banyak sumber (DDoS?)", count>10000 AND sources<5, "sedikit sumber (DoS?)", true(), "normal")
```

- `dc(src)` per menit adalah pembedanya: DoS memakai sumber sedikit dengan volume tinggi, DDoS memakai sumber banyak.
- `203.0.113.8` adalah IP publik portal pelanggan PT JAB di contoh ini.

Keluaran ilustrasi:

| _time | count | sources | pattern |
|---|---|---|---|
| 11:10 | 820 | 96 | normal |
| 11:14 | 48210 | 1327 | banyak sumber (DDoS?) |
| 11:15 | 52140 | 1480 | banyak sumber (DDoS?) |

- **Cara membaca hasil:** lonjakan `sources` yang naik bersamaan dengan `count` mengarah ke DDoS, sehingga mitigasinya rate limit atau layanan scrubbing, bukan blokir per IP.
- **Variasi:** tambahkan `by All_Traffic.dest_port` untuk melihat apakah serangan menyasar satu layanan, dan ganti `dest` dengan rentang untuk melihat beberapa layanan sekaligus.
- **Kapan gagal:** ambang 500 dan 10.000 di `case` adalah ilustrasi. Di ISP, 1.300 sumber unik per menit bisa normal untuk portal publik, jadi tentukan ambang dari baseline sendiri.

### 2.5 BEC: inbox rule mencurigakan di Microsoft 365

**Tujuan:** menemukan aturan kotak masuk yang meneruskan atau menyembunyikan email, pola yang hampir selalu ada di kasus BEC dan ATO.

```
index=o365 sourcetype="o365:management:activity" (Operation="New-InboxRule" OR Operation="Set-InboxRule") earliest=-7d
| stats count values(Parameters{}.Value) AS params BY UserId ClientIP
```

- Dua operasi dipakai sekaligus karena penyerang bisa membuat aturan baru atau mengubah aturan yang sudah ada.
- `Parameters{}.Value` berpotensi multivalue: satu aturan memuat beberapa parameter, misalnya nama aturan, kondisi, dan tujuan forward.
- Index disebut eksplisit, bukan `index=*`, karena `index=*` memaksa Splunk memeriksa semua index yang boleh dibaca role-mu (Day 14).

Keluaran ilustrasi:

| UserId | ClientIP | count | params |
|---|---|---|---|
| fitri.handayani@jab.example | 203.0.113.212 | 1 | `Name: .`, `ForwardTo: arsip.keuangan@mail-archive.example`, `StopProcessingRules: True` |
| budi.santoso@jab.example | 10.10.14.22 | 1 | `MoveToFolder: Projects`, `Name: Project filter` |

- **Cara membaca hasil:** baris pertama memuat tiga tanda sekaligus, yaitu nama aturan satu karakter yang sulit dilihat di Outlook, forward ke domain eksternal, dan penghentian aturan lain, dan dibuat dari IP publik yang tidak dikenal. Baris kedua adalah aturan kerja biasa.
- **Variasi:** tambahkan `Operation="Set-Mailbox"` untuk perubahan forwarding di level mailbox, dan bandingkan `ClientIP` dengan IP login terakhir pengguna itu.
- **Kapan gagal:** nama operasi, nama field (`UserId`, `ClientIP`, `Parameters{}`), dan index bergantung pada add-on Office 365 yang kamu pakai, jadi cek dulu di instance-mu.

### 2.6 IOC dibandingkan TTP untuk ancaman yang sama

**Tujuan:** membuktikan di data sendiri kenapa detection perilaku lebih tahan lama daripada daftar hash dari laporan `SOC-2026-0263`.

Pendekatan IOC, memakai enam hash dari lampiran laporan:

```
| tstats count from datamodel=Endpoint.Processes
    where Processes.process_hash IN ("<hash1>","<hash2>") by Processes.dest
```

Pendekatan TTP, procedure `schtasks /create` yang dijalankan dari script host:

```
| tstats summariesonly=false count min(_time) AS first values(Processes.process) AS cmd
    from datamodel=Endpoint.Processes
    where Processes.process_name="schtasks.exe" Processes.process="*/create*"
      (Processes.parent_process_name IN ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe"))
    by Processes.dest Processes.user Processes.parent_process_name
| rename Processes.* AS *
| convert ctime(first)
```

- Pendekatan pertama gagal begitu penyerang mengompilasi ulang malware, karena hash-nya berubah.
- Pendekatan kedua menangkap perilaku apa pun malware-nya, selama prosedurnya sama.
- `<field> IN (...)` didukung di klausa WHERE `tstats` (lihat sintaks di Day 25 bagian 1.4). Bila hasilnya aneh di versi lama, ganti dengan rangkaian `OR`.

Keluaran ilustrasi untuk versi TTP, tanpa kolom `first`:

| dest | user | parent_process_name | count | cmd |
|---|---|---|---|---|
| JKT-WS-0523 | JAB\rina.wulandari | wscript.exe | 1 | `schtasks.exe /create /sc onlogon /tn EdgeUpdate /tr C:\Users\Public\u.bat` |

- **Cara membaca hasil:** satu baris pun cukup untuk membuka investigasi, karena pembuatan scheduled task dari `wscript.exe` oleh akun karyawan bukan pekerjaan rutin. Host yang sama juga muncul di bagian 2.1 dan 2.2, yang memperkuat dugaan.
- **Variasi:** hapus filter `parent_process_name` untuk melihat seluruh pembuatan task, lalu bangun daftar parent yang sah di PT JAB (agen deployment, installer vendor) dan kecualikan daftar itu saja.
- **Kapan gagal:** procedure yang tidak memakai `schtasks.exe` sama sekali, misalnya cmdlet PowerShell atau API Task Scheduler, tidak akan muncul di sini. Itu alasan bagian 2.7 ada.

### 2.7 Menambah sumber kedua untuk procedure lain

**Tujuan:** menutup cara pembuatan task yang tidak lewat `schtasks.exe`, memakai event Windows 4698.

```
index=wineventlog source="XmlWinEventLog:Security" EventCode=4698 earliest=-24h
| stats count values(TaskName) AS tasks BY host SubjectUserName
```

- Event 4698 ("A scheduled task was created") mencatat pembuatan task apa pun caranya, asalkan subkategori audit "Audit Other Object Access Events" aktif [S14]. Isinya: akun pembuat (Subject), nama task, dan isi lengkap task dalam bentuk XML (`TaskContent`), termasuk trigger, akun yang menjalankan, dan `<Command>` serta `<Arguments>` di bagian action.
- Di add-on Windows modern, channel dibedakan lewat `source`; pada data lama atau BOTS v1 saringannya `sourcetype="WinEventLog:Security"` (Day 03 bagian 1.1).
- Cek nama field (`TaskName`, `SubjectUserName`, `TaskContent`) di add-on-mu, karena format klasik dan XML berbeda.

Versi yang lebih tajam memeriksa isi action:

```
index=wineventlog source="XmlWinEventLog:Security" EventCode=4698 earliest=-24h
| rex field=TaskContent "<Command>(?<task_command>[^<]+)</Command>"
| eval suspicious_path=if(match(lower(task_command), "\\\\users\\\\public\\\\|\\\\appdata\\\\|\\\\temp\\\\|\\\\programdata\\\\"), 1, 0)
| where suspicious_path=1
| table _time host SubjectUserName TaskName task_command
```

- `rex` mengambil isi `<Command>` dari XML task (Day 11).
- `match(lower(...))` mencari folder yang bisa ditulis user biasa. Satu backslash literal di regex ditulis `\\` oleh PCRE, dan karena string `eval` juga memakai backslash sebagai escape, di dalam tanda kutip SPL ia menjadi `\\\\`.

Keluaran ilustrasi:

| _time | host | SubjectUserName | TaskName | task_command |
|---|---|---|---|---|
| 2026-10-10 02:41:07 | JKT-FS01 | svc_billing | \EdgeUpdateCheck | `C:\ProgramData\upd\svc.exe` |

- **Cara membaca hasil:** task dari folder yang bisa ditulis user biasa, dibuat akun non-admin atau di luar jam deployment, layak diinvestigasi. Task dari agen vendor biasanya menunjuk ke `Program Files`. Baris di atas penting karena hostnya file server dan pembuatnya akun service, dua hal yang tidak biasa membuat task baru.
- **Variasi:** ganti `EventCode=4698` dengan `EventCode IN (4698,4702)` untuk menyertakan modifikasi task, lalu bandingkan hasilnya dengan bagian 2.6 untuk melihat procedure mana yang hanya tertangkap satu sumber.
- **Kapan gagal:** pada format klasik, XML bisa ter-escape (`&lt;Command&gt;`), sehingga regex harus disesuaikan. Command yang memakai variabel lingkungan (`%PUBLIC%`) juga lolos dari pola di atas, jadi tambahkan variasinya setelah diuji dengan `makeresults`. Di host yang audit policy-nya belum diatur, event ini tidak ada sama sekali.
- Kombinasi bagian 2.6 dan 2.7 menutup lebih banyak procedure dari T1053.005, sesuai arahan Detection Strategy teknik itu [S10].

### 2.8 Cakupan teknik dari detection yang aktif

**Tujuan:** menjawab pertanyaan SOC lead dengan angka, bukan dengan kesan.

```
| rest /servicesNS/-/-/saved/searches splunk_server=local count=0
| search action.correlationsearch.enabled=1 disabled=0
| spath input=action.correlationsearch.annotations path=mitre_attack{} output=technique
| mvexpand technique
| stats dc(title) AS detections values(title) AS names BY technique
| sort - detections
```

- `rest` membaca definisi semua saved search, lalu `search` menyisakan yang benar-benar menjadi detection aktif.
- `spath` membongkar annotation yang tersimpan sebagai JSON, dan `mvexpand` memecah detection yang dipetakan ke beberapa teknik menjadi satu baris per teknik. Field `technique` di sini berpotensi multivalue sebelum di-`mvexpand`.
- Cek path JSON dan nama atributnya di ES 8.7 (Day 29).

Keluaran ilustrasi:

| technique | detections | names |
|---|---|---|
| T1110 | 4 | Brute force VPN, Brute force Windows, ... |
| T1053.005 | 1 | Scheduled task created from script host |
| T1490 | 1 | Shadow copy deletion |

- **Cara membaca hasil:** teknik dengan satu detection berbasis satu procedure adalah cakupan tipis, dan itulah jawaban untuk pertanyaan "apakah kita sudah aman" di bagian 1.8.
- **Variasi:** tambahkan `BY technique, source` atau bandingkan daftar ini dengan teknik prioritas dari laporan intel supaya terlihat teknik mana yang belum punya detection sama sekali.
- **Kapan gagal:** detection tanpa annotation tidak muncul di hasil, sehingga cakupan bisa tampak lebih buruk daripada kenyataannya. Detection yang dinonaktifkan juga sengaja dibuang oleh filter.

### 2.9 Langkah di ES dan sumber konten

1. Cari analytic story ESCU untuk ransomware, BEC dan Office 365, serta supply chain di content management, lalu baca detection di dalamnya sebelum menulis sendiri (Day 45).
2. Buka Detection Studio dan lihat cakupan per teknik, lalu bandingkan dengan teknik prioritas dari laporan intel (Day 27).
3. Periksa annotation ATT&CK pada detection milikmu terhadap v19. Teknik yang dulu berada di Defense Evasion kini bisa dipetakan ke Stealth atau Defense Impairment, dan itu mengubah laporan cakupan (Day 29 dan Day 33).
4. Untuk setiap teknik prioritas, pastikan ada minimal dua procedure atau dua sumber data, seperti pasangan bagian 2.6 dan 2.7.

## 3. Lab praktik (di VM lab terisolasi)

Lab ini punya tiga bagian: membaca sumber resmi, memilah satu laporan nyata, lalu membuktikan di data sendiri bahwa satu detection tidak sama dengan satu teknik. Snapshot VM dulu sebelum langkah yang mengubah sistem.

1. **Kartu glosarium.** Buat kartu dari tabel bagian 1.2 dengan empat kolom: istilah, definisi dengan kata sendiri, ID ATT&CK, dan sinyal data. Lalu buka attack.mitre.org v19 dan periksa dua hal yang di tabel itu disebut masih perlu dicek, yaitu taktik T1112 dan T1564 di v19, lalu perbaiki kartumu.
2. **Membaca satu halaman teknik.** Buka T1053.005 di ATT&CK v19 dan tulis: daftar taktiknya, tiga procedure examples beserta ID group atau software, mitigations, dan ID Detection Strategy serta Analytic-nya [S10].
3. **Memilah satu laporan nyata.** Ambil satu laporan ancaman publik (sebut penerbit dan tahunnya, jangan menyalin isinya). Pecah isinya dua kali: pertama ke empat tingkatan intel di bagian 1.9, kedua ke level Pyramid of Pain di bagian 1.7. Tandai tingkat yang tidak ada isinya, yang biasanya operational. Tulis satu kalimat tindak lanjut untuk tiap bagian.
4. **Dua cara membuat scheduled task.** Di VM Windows lab, jalankan (a) `schtasks /create ...` dari PowerShell, lalu (b) cmdlet `Register-ScheduledTask`, yang memakai API dan bukan `schtasks.exe`. Bisa juga lewat Atomic Red Team T1053.005; cek nomor test-nya di repo itu.
5. **Buktikan batas cakupan.** Jalankan bagian 2.6. Hasil yang diharapkan: (a) terdeteksi, (b) tidak. Lalu aktifkan audit "Audit Other Object Access Events" bila belum, ulangi (b), dan jalankan bagian 2.7. Hasil yang diharapkan: (b) terdeteksi lewat 4698.
6. **Persistence dan ransomware.** Jalankan Atomic Red Team untuk T1547.001 (Run key), cek nomor test-nya, lalu satu test penghapusan shadow copy hanya bila snapshot tersedia, karena test itu merusak kemampuan pemulihan VM. Jalankan bagian 2.1 dan 2.2.
7. **Exfiltration.** Jalankan bagian 2.3 di data lab, lalu buat transfer besar dari VM, misalnya menyalin file 500 MB ke share lain, dan lihat apakah pasangan itu lolos ambang outlier.
8. **Dataset latihan.** Di BOTS v1, yang berisi skenario ransomware, cari bukti penghapusan shadow copy atau modifikasi registry dengan pola bagian 2.1 dan 2.2. Dataset ini bertanggal 2016, jadi tentukan dulu rentang absolutnya (Day 01 bagian 2.5) dan jangan memakai rentang relatif. Fokus pada metodenya, bukan pada jawabannya.
9. **Tabel cakupan.** Tulis tabel cakupan T1053.005 dengan kolom procedure, sumber data, detection, dan status, lalu ubah menjadi satu kalimat laporan seperti contoh di bagian 1.10 langkah 5.

**Hasil yang sebaiknya tersimpan:**

- Kartu glosarium lengkap dengan ID ATT&CK v19 yang sudah diverifikasi.
- Ringkasan halaman ATT&CK T1053.005.
- Satu laporan publik yang sudah dipecah ke empat tingkatan intel dan ke level piramida, dengan tindak lanjut per bagian.
- Bukti bahwa bagian 2.6 menangkap (a) tetapi tidak (b), dan bahwa bagian 2.7 menangkap (b).
- Minimal dua sketsa deteksi dari bagian 2 yang sudah diuji dengan data lab, beserta penjelasan jinak masing-masing.
- Tabel cakupan per procedure dan kalimat laporannya.

**Variasi tantangan:** pilih satu laporan publik tentang serangan supply chain, petakan tahapannya ke taktik v19, dan tentukan sumber data Splunk untuk tiap tahap. Lalu pilih satu teknik dengan banyak procedure, misalnya T1059.001 PowerShell, dan buat matriks procedure dibanding sumber data (Sysmon EID 1, PowerShell Script Block Logging 4104 di log `Microsoft-Windows-PowerShell/Operational`, AMSI) untuk menentukan kombinasi minimum yang cakupannya layak.

## 4. Troubleshooting

Tabel ini menghubungkan gejala yang muncul saat menjalankan bagian 2 dan 3 dengan penyebab yang paling sering, supaya kamu tidak memperbaiki search yang sebenarnya sudah benar.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Sketsa Endpoint tidak menemukan apa pun | Sysmon atau EDR tidak mencatat command line dan registry; data model tidak terisi | Cek profil Sysmon (Day 21) dan tag serta field CIM (Day 23) |
| `bytes_out` kosong | Sumber firewall tidak menyediakan field itu, atau add-on tidak memetakannya | Jalankan `tstats` dengan `by sourcetype` dan lihat field yang tersedia (Day 24) |
| Event 4698 tidak muncul | Subkategori audit tidak aktif | Aktifkan "Audit Other Object Access Events", misalnya dengan `auditpol /set /subcategory:"Other Object Access Events" /success:enable` |
| Detection TTP berisik | Installer atau agen sah ikut membuat task | Filter sempit (path vendor yang dikenal, nama task spesifik), bukan mengecualikan semua task yang dibuat SYSTEM, karena penyerang dengan hak admin juga membuat task sebagai SYSTEM |
| Cakupan tampak penuh padahal tes lolos | Satu procedure dianggap satu teknik | Laporkan cakupan per procedure (bagian 1.8) |
| Pemetaan ATT&CK di laporan berbeda dari catatan ini | Laporan memakai ATT&CK sebelum v19 | Perbarui ke ID dan taktik v19, dan catat versinya [S6][S9] |
| Annotation teknik usang di detection sendiri | Pemetaan dibuat sebelum v19 | Perbarui annotation dan jalankan ulang bagian 2.8 (Day 29) |
| Statistik ancaman berbeda antar artikel | Sumber sekunder dengan metodologi berbeda | Rujuk laporan aslinya (DBIR, IC3) [S1][S7] |

## 5. Kesalahan umum dan jebakan

- Menyebut "Defense Evasion" sebagai taktik ATT&CK terkini. Di v19 taktik itu sudah dipecah [S6][S9]. Saat membaca tulisan orang lain, perhatikan versi ATT&CK yang mereka pakai, dan saat menulis sendiri, sebutkan versinya.
- Menyamakan technique dengan tactic. Tactic adalah tujuan, technique adalah cara [S8].
- Menganggap satu teknik selalu milik satu taktik. Banyak teknik memetakan ke beberapa taktik; T1053.005 ada di tiga [S10].
- Mengklaim cakupan satu teknik dari satu detection procedure (bagian 1.8).
- Menganggap nama task atau path script dari laporan intel sebagai TTP. Itu artifact; TTP-nya adalah perilaku membuat task untuk persistence (bagian 1.10).
- Mengandalkan 4698 tanpa memastikan audit policy aktif di semua host. Cakupan nyata sama dengan persentase host yang benar-benar mengirim event itu.
- Mengabaikan IOC sepenuhnya. IOC tetap berguna untuk respons cepat dan retro-hunt; yang keliru adalah menjadikannya satu-satunya andalan [S12].
- Menganggap feed IOC sudah sama dengan threat intelligence yang lengkap. Itu baru level technical [S15].
- Memakai label tingkatan intel tanpa menyebut isinya, padahal arti tactical dan operational berbeda antar sumber [S15][S16].
- Menyamakan BEC dengan phishing biasa. BEC berfokus pada penipuan bisnis dan sering tanpa malware.
- Menyamakan DoS dan DDoS. Bedanya ada pada jumlah dan sebaran sumber.
- Menganggap APT selalu berarti negara. Definisi NIST menekankan kemampuan, persistensi, dan adaptasi, bukan afiliasi [S5].
- Mengutip angka tren dari sumber sekunder tanpa membuka laporan aslinya [S1][S7].

## 6. Catatan terkini

Bagian ini menampung hal yang bergantung versi dan tanggal, supaya isi di atas tetap bisa dibaca ketika versinya berganti.

- **ATT&CK v18 (Okt 2025):** bagian detection pada halaman teknik diganti menjadi Detection Strategies (DETxxxx) dan Analytics (ANxxxx), sehingga pemetaan lama yang hanya menyebut data source kini kurang lengkap (Day 21).
- **ATT&CK v19 (28 Apr 2026):** Defense Evasion dipecah menjadi Stealth (TA0005) dan Defense Impairment (TA0112), sehingga Enterprise memiliki 15 taktik. v19.2 (Agu 2026) adalah rilis Agile pertama [S6][S9].
- Halaman T1053.005 diperbarui 12 Mei 2026 (versi 1.8) dan memuat DET0441 serta AN1221 [S10].
- Teknik T1219 kini bernama "Remote Access Tools" [S3]. Materi lama menyebutnya "Remote Access Software", perlu dicek saat membaca pemetaan lama.
- **DBIR 2026:** eksploitasi kerentanan menjadi vector akses awal teratas, ransomware muncul di 48% breach, dan peran AI dalam serangan meningkat [S1].
- **IC3 2025:** BEC tetap penyebab kerugian bisnis terbesar, dan muncul kasus BEC dengan keterkaitan AI [S7].
- Model empat tingkatan intel yang dipakai di bagian 1.9 berasal dari dokumen 2015 [S15]. Konsepnya masih dipakai, tetapi banyak vendor sekarang memakai model tiga tipe dengan arti berbeda [S16], jadi istilahnya perlu dijelaskan setiap kali dipakai di rapat.

## 7. Cheat sheet

```
VECTOR (jalan masuk): phishing | eksploitasi publik | kredensial curian | pihak ketiga | media fisik
TYPE (jenis/tujuan): ransomware | DoS/DDoS | exfiltration | BEC | defacement
ATT&CK v19 15 taktik: Recon TA0043 | ResDev TA0042 | InitAcc TA0001 | Exec TA0002 | Persist TA0003 | PrivEsc TA0004
                      | Stealth TA0005 | Defense Impairment TA0112 | CredAcc TA0006 | Disc TA0007 | LatMov TA0008
                      | Collect TA0009 | C2 TA0011 | Exfil TA0010 | Impact TA0040
Supply chain T1195 (.001 dep/tools .002 software .003 hardware) | C2: T1071 T1573 T1568 T1090 T1219
APT (NIST SP 800-39): canggih + sumber daya + multi-vektor + berulang lama + adaptif + bertekad
Zero trust (SP 800-207): least privilege PER PERMINTAAN, jaringan dianggap sudah kompromi
DoS = sedikit sumber ; DDoS = banyak sumber (botnet) ; Bot = mesin dikendalikan ; Botnet = jaringan bot via C2
BEC = penipuan bisnis via email ; ATO = pengambilalihan akun (sering sarana BEC)
SINYAL: shadow copy delete (ransomware) | Run key (registry persistence) | bytes_out outlier (exfil) | dc(src) (DDoS) | inbox rule (BEC)

TTP (NIST SP 800-150): perilaku aktor ; Tactic = tujuan (why) ; Technique = cara (how) ; Procedure = implementasi spesifik
ATT&CK   Tactic TAxxxx > Technique Txxxx > Sub-technique Txxxx.yyy > Procedure examples (Groups Gxxxx, Software Sxxxx, Campaigns Cxxxx)
         + Mitigations Mxxxx + Detection Strategy DETxxxx + Analytic ANxxxx (v18+)
CONTOH   T1053.005 Scheduled Task -> Execution, Persistence, PrivEsc ; DET0441/AN1221 ; M1047 M1028 M1026 M1018
         sumber data: Sysmon EID 1 / 4688 (schtasks) | 4698 semua cara | 4104 cmdlet | 4702 modifikasi | Operational 106/140/200/201
PYRAMID  hash < IP < domain < network/host artifacts < tools < TTPs (paling sakit bagi penyerang)
INDUSTRI TTP-based hunting (MITRE 2019): teknologi membatasi teknik penyerang, jadi deteksi TTP efektif dan efisien
CAKUPAN  detection = procedure ; teknik butuh >=2 procedure/sumber data ; laporkan per procedure

TIER (MWR, 4)  Strategic: risiko/tren -> board | Operational: serangan spesifik akan datang -> defender (langka)
               Tactical: TTP -> arsitek/detection eng. (awet) | Technical: IOC -> SOC/otomasi (cepat basi)
               AWAS: model 3-tier vendor -> "tactical"=IOC. Sebut ISINYA.
               Pemilahan laporan: tren ke slide direksi | perilaku ke detection/hunting | indikator ke threat list + masa berlaku
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Seorang rekan menyusun laporan cakupan PT JAB dan menulis "detection kami menutupi 9 dari 14 taktik ATT&CK, termasuk Defense Evasion". Apa yang keliru?

<details><summary>Jawaban</summary>

Dua hal. Pertama, jumlah taktiknya: sejak v19 (28 Apr 2026) ATT&CK Enterprise punya 15 taktik, karena Defense Evasion dipecah menjadi Stealth (tetap TA0005) dan Defense Impairment (TA0112, baru). Kedua, nama taktiknya: menyebut Defense Evasion berarti laporan itu memakai pemetaan sebelum v19, jadi detection yang dulu dihitung di satu taktik sekarang bisa jatuh ke dua taktik atau hanya ke salah satunya. Perbaikannya adalah menyebut versi ATT&CK di laporan dan memeriksa ulang annotation detection terhadap v19. Lihat bagian 1.5.

</details>

**2. Skenario keputusan.** Laporan di tiket `SOC-2026-0263` memuat paragraf tren, kalimat tentang scheduled task yang menjalankan script dari folder publik, dan lampiran 40 IP, 12 domain, serta 6 hash. Kamu punya waktu satu hari. Apa yang kamu kerjakan?

- A. Masukkan 58 indikator itu ke daftar blokir dan ke threat list, tutup tiket, karena itu bagian laporan yang paling konkret dan bisa langsung dipakai.
- B. Pilah laporan: tren ke bahan slide direksi, perilaku scheduled task menjadi hipotesis hunting dan dua detection dari dua sumber data, indikator masuk daftar dengan masa berlaku untuk blokir dan retro-hunt, lalu laporkan cakupan per procedure.
- C. Buang lampiran indikatornya karena level bawah piramida tidak bernilai, dan hanya kerjakan detection perilakunya.

<details><summary>Jawaban</summary>

B. Satu laporan memuat beberapa tingkatan intel sekaligus, dan tiap tingkatan punya konsumen serta masa berlaku sendiri. A keliru karena berhenti di level technical, yang paling murah diganti penyerang: begitu IP dan hash diganti, pekerjaan itu habis nilainya, dan perilaku yang disebut di laporan tidak pernah tertangkap. C keliru karena IOC tetap berguna untuk respons cepat dan retro-hunt; yang salah adalah menjadikannya satu-satunya andalan. Lihat bagian 1.7, 1.9, dan 1.10.

</details>

**3. Pertanyaan jebakan.** PT JAB sudah punya detection yang berbunyi ketika `schtasks.exe /create` dijalankan dari PowerShell. Bolehkah laporan cakupan menulis "T1053.005: covered"?

<details><summary>Jawaban</summary>

Tidak. Detection itu menangkap satu procedure, sedangkan teknik yang sama bisa dijalankan lewat cmdlet `Register-ScheduledTask`, API Task Scheduler (COM), WMI dari host lain, atau GPO, dan semuanya disebut di Detection Strategy teknik tersebut. Yang benar adalah melaporkan cakupan per procedure beserta sumber datanya, misalnya `schtasks` dari shell lewat Sysmon EID 1 dan semua cara pembuatan task lewat event 4698 di host yang audit policy-nya aktif. Setiap teknik prioritas sebaiknya ditopang minimal dua procedure atau dua sumber data, karena satu sumber bisa hilang ketika agen mati atau audit policy berubah. Lihat bagian 1.8.

</details>

**4. Jelaskan ulang.** Jelaskan kepada analyst L1 baru di PT JAB, dalam tiga kalimat, beda tactic, technique, dan procedure, memakai kalimat di laporan `SOC-2026-0263` sebagai contoh.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Tactic adalah tujuan penyerang di satu tahap, dan di laporan ini tujuannya bertahan di sistem, yaitu Persistence TA0003. Technique adalah cara umum mencapai tujuan itu, di sini memakai scheduled task, yaitu T1053.005. Procedure adalah implementasi persisnya, yaitu nama task yang mirip layanan update dan script di `C:\Users\Public`, dan justru bagian inilah yang paling mudah diganti penyerang, jadi detection kita dibangun dari perilakunya, bukan dari nama task itu."

Kesalahan yang sering muncul:

- Menyebut procedure sebagai "teknik yang lebih detail" tanpa menyebut bahwa itu implementasi satu aktor tertentu.
- Mengira satu teknik hanya punya satu taktik; T1053.005 ada di Execution, Persistence, dan Privilege Escalation.
- Menjadikan nama task atau path file sebagai isi detection, padahal itu artifact yang berumur pendek.

</details>

**5. Skenario keputusan.** SOC lead meminta satu halaman prioritas untuk direksi. Kamu punya DBIR 2026 (eksploitasi kerentanan 31% sebagai vector akses awal teratas, kredensial 13%, ransomware di 48% breach) dan IC3 2025 (kerugian BEC sekitar USD 3,046 miliar, kerugian ransomware yang dilaporkan sekitar USD 32,3 juta). Apa isi halaman itu?

- A. Fokus tunggal ke ransomware, karena muncul di 48% breach dan paling sering jadi berita.
- B. Turunkan prioritas ransomware, karena kerugian yang dilaporkan IC3 hanya USD 32,3 juta, jauh di bawah BEC.
- C. Pakai kedua laporan untuk dua pertanyaan berbeda, yaitu DBIR untuk "lewat mana orang kebobolan" dan IC3 untuk "apa yang paling mahal", sebut bahwa angkanya diambil dari liputan dan perlu dicocokkan dengan laporan asli, lalu bandingkan dengan paparan PT JAB sendiri.
- D. Tunda sampai kedua laporan asli dibaca utuh, karena angka dari liputan tidak boleh dipakai sama sekali.

<details><summary>Jawaban</summary>

C. Dua laporan itu menjawab pertanyaan berbeda, dan keduanya harus diuji terhadap paparan PT JAB yang punya portal pelanggan, RADIUS, dan data billing. A keliru karena memakai satu angka untuk semua keputusan dan mengabaikan vector yang harus ditutup. B keliru karena angka IC3 hanya mencakup kerugian yang dilaporkan dan dihitung IC3, tanpa biaya downtime dan pemulihan, jadi angka kecil itu bukan ukuran dampak nyata. D berlebihan: angka dari liputan boleh dipakai asal disebut asalnya dan ditandai untuk dicocokkan, dan itu justru cara kerja yang jujur. Lihat bagian 1.1 dan 1.3.

</details>

**6. Pertanyaan jebakan.** Dalam satu tiket, rekanmu menulis: "Kasus `fitri.handayani` ini BEC, jadi tidak perlu dicek loginnya; BEC itu kan phishing." Apa yang perlu dikoreksi?

<details><summary>Jawaban</summary>

Tiga istilah dicampur. BEC adalah jenis penipuan bisnis lewat email yang tujuannya uang atau data, dan sering berjalan tanpa malware. ATO adalah cara menguasai akun sah, dan BEC sering memakai ATO sebagai sarana, walaupun bisa juga memakai domain yang mirip tanpa menyentuh akun korban. Phishing adalah teknik social engineering (T1566) yang bisa menjadi langkah awalnya. Karena di kasus ini ada inbox rule baru yang meneruskan email ke domain luar, dugaan ATO justru harus diperiksa, yaitu login dari IP dan perangkat baru, impossible travel, dan perubahan MFA. Lihat bagian 1.2.

</details>

**7. Interview question (English).** "A threat intel report lands on your desk. Walk me through what you do with it."

<details><summary>Sample answer</summary>

"First I split the report by what each part actually is. The trend and impact parts are strategic intel, so they go into the quarterly brief for management, not into my queue. The behavioural parts are tactical intel, so I map them to MITRE ATT&CK, name the version I used, and turn them into a hunting hypothesis and detections. The indicators at the end are technical intel, so they go into a list with an expiry date for blocking and retro-hunting, because an attacker can rotate an IP or recompile a binary in minutes. Then I check coverage honestly: a detection usually catches one procedure, not a whole technique, so for a technique like scheduled task persistence I want at least two procedures or two data sources, for example process creation with command line plus the Windows event for task creation, and I report coverage per procedure with the percentage of hosts that actually send those events. What I never do is close the ticket after loading the indicators, because that is the part of the report with the shortest shelf life."

What makes this answer strong: it separates intel by consumer and shelf life, shows the ATT&CK mapping habit including the version, treats detection coverage as per procedure rather than per technique, and names the common failure mode of stopping at indicators.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | TechRepublic: New Verizon report reveals the security gap attackers are exploiting most (DBIR 2026), beserta liputan lain | https://www.techrepublic.com/article/news-verizon-dbir-vulnerability-exploitation-2026/ | sekunder | 2026-05 | Sedang. Angka perlu dicocokkan dengan laporan Verizon |
| S2 | MITRE ATT&CK: T1195 Supply Chain Compromise | https://attack.mitre.org/techniques/T1195/ | primer | diakses 2026-10-07 | Tinggi |
| S3 | MITRE ATT&CK: TA0011 Command and Control | https://attack.mitre.org/tactics/TA0011/ | primer | diakses 2026-10-07 | Tinggi |
| S4 | NIST CSRC Glossary: zero trust (SP 800-207) | https://csrc.nist.gov/glossary/term/zero_trust | primer | diakses 2026-10-07 | Tinggi |
| S5 | NIST CSRC Glossary: advanced persistent threat (SP 800-39) | https://csrc.nist.gov/glossary/term/advanced_persistent_threat | primer | diakses 2026-10-07 | Tinggi |
| S6 | MITRE ATT&CK: Enterprise tactics (v19) | https://attack.mitre.org/tactics/enterprise/ | primer | diakses 2026-10-07 | Tinggi. Sumber daftar 15 taktik |
| S7 | Liputan FBI IC3 2025 Internet Crime Report (McDonald Hopkins, The Record, JD Supra) | https://therecord.media/cyber-fraud-surges-to-17-billion-fbi-ic3 | sekunder | 2026 | Sedang. Angka total berbeda antar liputan |
| S8 | NIST CSRC Glossary: Tactics, Techniques, and Procedures (SP 800-150) | https://csrc.nist.gov/glossary/term/tactics_techniques_and_procedures | primer | diakses 2026-10-07 | Tinggi |
| S9 | MITRE ATT&CK: Updates April 2026 (v19), beserta blog D3 Security tentang pemecahan Defense Evasion | https://attack.mitre.org/resources/updates/updates-april-2026/ | primer dan sekunder | 2026-04-28 | Tinggi |
| S10 | MITRE ATT&CK: T1053.005 Scheduled Task (v19) | https://attack.mitre.org/techniques/T1053/005/ | primer | dimodifikasi 2026-05-12; diakses 2026-10-07 | Tinggi. Taktik, procedure examples, mitigations, Detection Strategy |
| S11 | TaHiTI Threat Hunting Methodology whitepaper (memuat gambar Pyramid of Pain) | https://www.betaalvereniging.nl/wp-content/uploads/2026/03/TaHiTI-Threat-Hunting-Methodology-whitepaper.pdf | primer (mengutip Bianco) | diakses 2026-10-07 | Tinggi untuk urutan level |
| S12 | David J Bianco: The Pyramid of Pain (slide asli) | https://speakerdeck.com/davidjbianco/the-pyramid-of-pain-intel-driven-detection-and-response-to-increase-your-adversarys-cost-of-operations | primer (penulis) | 2013, lebih dari tiga tahun | Tinggi untuk konsep |
| S13 | MITRE: TTP-Based Hunting (Daszczyszak dkk.) | https://www.mitre.org/news-insights/publication/ttp-based-hunting | primer | 2019-03, lebih dari tiga tahun | Tinggi untuk argumen |
| S14 | Microsoft Learn: 4698(S) A scheduled task was created; Audit Other Object Access Events | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698 | primer | diakses 2026-10-10 | Tinggi. Field event dan subkategori audit; halaman berada di arsip dokumentasi Windows 10 |
| S15 | MWR/CPNI/CERT-UK: Threat Intelligence: Collecting, Analysing, Evaluating | https://www.ismsforum.es/ficheros/descargas/threat-intelligence--collecting-analysing.pdf | primer | 2015, lebih dari tiga tahun; diakses 2026-10-07 | Tinggi untuk taksonomi |
| S16 | Flashpoint: Three types of threat intelligence | https://flashpoint.io/blog/three-types-of-threat-intelligence/ | sekunder | 2025-09, diperbarui 2026-04; diakses 2026-10-07 | Sedang. Konvensi alternatif |
| S17 | CIM 6.4 data models | https://help.splunk.com/en/data-management/common-information-model/6.4/data-models | primer | diakses 2026-10-07 | Tinggi. Nama data model dan field di kolom sinyal |

**Catatan sumber:** daftar 15 taktik v19.2 berasal dari halaman taktik ATT&CK [S6]. ID teknik yang stabil lintas versi (T1486, T1490, T1547.001, T1112, T1566, T1078, T1498, T1499, T1114.003, T1564.008) ditulis apa adanya, sedangkan penempatan taktik v19 untuk T1112 dan T1564 (Stealth atau Defense Impairment) perlu dicek di halaman tekniknya. Angka DBIR 2026 [S1] dan IC3 2025 [S7] berasal dari liputan media, jadi cocokkan dengan laporan aslinya sebelum dikutip di dokumen resmi. Nomor event log `Microsoft-Windows-TaskScheduler/Operational` (106, 140, 200, 201) dan jejak `TaskCache\Tree` di registry berasal dari pengetahuan umum forensik Windows, bukan dari satu dokumen di tabel ini; uji di VM lab sebelum dijadikan detection. Biaya penggantian per level di tabel Pyramid of Pain adalah penjabaran konsep Bianco [S12], bukan angka terukur. Model empat tingkatan intel berasal dari dokumen 2015 [S15], sedangkan model tiga tipe yang arti labelnya berbeda dirujuk dari sumber sekunder [S16]. Nama field dan operasi Office 365 di bagian 2.5 serta nama objek dan nilai `action` pada `Endpoint.Registry` perlu dicek di add-on dan CIM versi-mu. Laporan ancaman di tiket `SOC-2026-0263` dan seluruh keluaran di bagian 2 adalah ilustrasi fiktif. Tidak ada klaim dari sumber komunitas di Day ini; definisi berasal dari NIST dan MITRE, sedangkan angka tren dari liputan laporan.
