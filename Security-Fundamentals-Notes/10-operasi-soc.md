---
day: 10
title: 'Operasi SOC: log, SIEM, correlation rule, use case, UEBA, SOAR, playbook, tier, metrik, SLA, dan handover'
researched_on: 2026-10-21
versions_checked: 'NIST SP 800-92 (Sep 2006, final); NIST SP 800-92 Rev. 1 initial public draft (Okt 2023); NIST SP 800-61r3 (Apr 2025); NIST CSRC Glossary (SIEM, SOAR, SOC, SLA; diakses 2026-10-21); CISA dan ASD ACSC Implementing SIEM and SOAR Platforms (27 Mei 2025); Splunk Enterprise Security 8.0 docs (detections); Splunk Common Information Model 5.2 docs; Microsoft Sentinel UEBA docs (diperbarui 2026-07-17)'
---

# Day 10: Operasi SOC (log, SIEM, correlation rule, use case, UEBA, SOAR, playbook, tier, metrik, SLA, dan handover)

Cakupan: cara kerja sebuah SOC dari ujung ke ujung, yaitu dari mana log datang (log source), apa yang dilakukan SIEM terhadapnya (parsing, normalisasi, correlation rule), bagaimana deteksi dikemas (use case, UEBA), bagaimana respons dijalankan dan dibantu otomasi (playbook, runbook, SOAR), siapa mengerjakan apa (tier L1/L2/L3, ticketing), bagaimana kinerja diukur (SLA, MTTD, MTTA, MTTR), dan bagaimana pekerjaan berpindah antar shift (handover).

## Ide inti

Semua pengaman yang dibahas di Day 03 sampai Day 09 (firewall, IDS, WAF, EDR, log cloud, filter email) menghasilkan catatan dan peringatan. SOC adalah tempat semua catatan itu bertemu dan diubah menjadi keputusan. Alurnya hampir selalu sama. Perangkat mencatat kejadian (log). Catatan dikirim ke satu tempat (SIEM). Di sana catatan dibongkar dan diseragamkan supaya bisa dibandingkan (parsing dan normalisasi), lalu dicocokkan dengan aturan (correlation rule) atau dengan kebiasaan normal (UEBA). Hasilnya menjadi alert di antrean. Setiap alert menjadi tiket yang dikerjakan orang di tingkat tertentu (tier), mengikuti prosedur tertulis (playbook dan runbook), sebagian dibantu otomasi (SOAR), dengan janji waktu (SLA) dan ukuran kinerja (MTTD, MTTA, MTTR), oleh tim yang bergantian jaga 24 jam (shift dan handover).

Gagasan yang mengikat semua istilah itu: rantai ini hanya sekuat mata rantai terlemahnya, dan sebagian besar mata rantainya bukan alat, melainkan kebiasaan kerja. SIEM tidak melihat apa yang tidak dikirim kepadanya. Rule yang ditulis dengan benar tidak berguna bila log sumbernya berhenti, dan ia tidak akan protes; ia hanya diam. Prosedur yang bagus tidak berguna bila shift berikutnya tidak tahu ada pekerjaan yang menggantung. Karena itu analyst SOC yang baik selalu bertanya dua hal sekaligus: apa yang terlihat sekarang, dan apa yang saat ini tidak bisa terlihat.

Bayangkan gedung perkantoran besar. Setiap pos satpam punya buku catatan (log). Semua kamera dan catatan pos dialirkan ke satu ruang monitor CCTV (SIEM), tempat petugas bisa melihat seluruh gedung dari satu layar. Di ruang itu ada aturan tertulis ("bila tamu yang sama ditolak di tiga pintu lalu berhasil masuk lewat pintu keempat, panggil kepala regu"), ada satpam lama yang hafal kebiasaan penghuni (UEBA), ada prosedur penanganan kebakaran gedung (playbook) dan instruksi tombol untuk setiap panel alarm (runbook), ada asisten yang menjalankan prosedur rutin otomatis (SOAR), ada buku laporan kejadian bernomor (ticketing), dan setiap pergantian jaga dilakukan dengan serah terima buku laporan (handover). Batas analogi ini perlu diingat sejak awal: ruang monitor hanya melihat kamera yang terpasang dan mengirim gambar. Kamera yang mati tidak membunyikan alarm dengan sendirinya; layar yang gelap bisa terlihat seperti lorong yang sepi.

```
  SUMBER (log source)            SIEM                                     ORANG DAN PROSES
  firewall, VPN, DC, EDR,   kumpulkan -> parsing -> normalisasi      antrean alert -> tiket
  WAF, proxy, DNS, cloud    -> simpan -> correlation rule / UEBA  -> L1 triage -> L2/L3 bila perlu
        |                             |                                  |       (playbook, runbook)
        |   log berhenti = rule ikut buta                                |   SOAR: otomasi langkah rutin
        +--- dipantau: "apakah setiap sumber masih mengirim?"           |   SLA: janji waktu per tiket
                                                                         |   MTTD/MTTA/MTTR: ukuran rata-rata
                                                                         +-- shift 24 jam, handover tiap 8 jam
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), sebuah ISP (penyedia layanan internet) fiktif dengan sekitar 1.200 karyawan dan sekitar 400 ribu pelanggan internet rumah, berkantor pusat di Jakarta dengan kantor regional di Bandung. PT JAB punya SOC (Security Operations Center) internal yang bekerja 24 jam dalam tiga shift dan memakai Splunk Enterprise Security sebagai SIEM. Kamu adalah analyst L1 (lapis pertama yang memeriksa alert) yang mulai orientasi Senin 2027-08-02. Jumat 2027-08-13, akhir minggu kedua, kamu pertama kali ikut shift sore (15:00 sampai 23:00) bersama mentormu Sari Kusuma (analyst L2). Pukul 14:50 Dwi Cahyono (analyst L1 shift pagi) menyerahkan catatan serah terima; satu baris menonjol: alert `SOC-2027-0853`, firewall kantor Bandung `bdg-fw01` berhenti mengirim log sejak 13:42. Sore itu antrean juga berisi alert login VPN yang mencurigakan (`SOC-2027-0854`), alert unduhan file yang tidak biasa (`SOC-2027-0855`), alert program iklan yang diblokir di laptop (`SOC-2027-0856`), dan menjelang malam alert serangan web ke portal pelanggan (`SOC-2027-0857`). Pukul 18:30 Dimas Prasetyo (SOC lead) mampir membawa dashboard metrik bulan Juli dan mengirim pesan:

> "Sari bilang kamu ikut shift sore. Bagus, Jumat sore biasanya jujur menunjukkan cara SOC bekerja. Sebelum pulang, aku mau kamu bisa menjawab ini dengan bahasamu sendiri. Kita ini kerjanya apa, dan kenapa NOC di sebelah tidak mengerjakan hal yang sama? Log yang masuk ke Splunk itu datang dari mana? Splunk melakukan apa dengan log itu, dan kenapa log VPN dan log RADIUS untuk login yang sama terlihat begitu berbeda? Kenapa waktu firewall Bandung diam, rule kita ikut diam tanpa protes? Tim sering mencampur rule, use case, playbook, dan runbook; bedanya apa? Alert soal Ratna dari Keuangan tadi muncul dari mana, padahal tidak ada rule yang bilang 'jangan unduh seribu file'? Kenapa kita belum beli SOAR? Siapa mengerjakan apa antara L1, L2, dan L3, dan kenapa semuanya harus lewat tiket? Di dashboard ini ada MTTD, MTTA, MTTR, dan persentase SLA; cara menghitungnya bagaimana, dan kenapa vendor yang presentasi kemarin bisa mengklaim MTTR 15 menit? Terakhir, jam 23:00 kamu serah terima ke Gilang. Apa yang wajib ada di catatanmu?"

Pesan itu memuat sebelas pertanyaan:

1. Apa pekerjaan SOC, dan apa bedanya dengan NOC?
2. Dari mana log datang?
3. Apa yang dilakukan SIEM terhadap log itu?
4. Kenapa log VPN dan log RADIUS untuk login yang sama terlihat berbeda, dan bagaimana diseragamkan?
5. Kenapa rule ikut diam saat firewall Bandung berhenti mengirim log?
6. Apa beda rule, use case, playbook, dan runbook?
7. Dari mana alert unduhan Ratna muncul tanpa rule yang eksplisit?
8. Apa itu SOAR, dan kenapa PT JAB belum memakainya penuh?
9. Siapa mengerjakan apa di L1, L2, dan L3, dan kenapa semua lewat tiket?
10. Bagaimana menghitung MTTD, MTTA, MTTR, dan SLA, dan kenapa klaim vendor bisa jauh berbeda?
11. Apa yang wajib ada di catatan serah terima shift?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, pertanyaan 6 di bagian 1.5, 1.6, dan 1.9, pertanyaan 7 di bagian 1.7, pertanyaan 8 di bagian 1.8, pertanyaan 9 di bagian 1.10 dan 1.11, pertanyaan 10 di bagian 1.12 dan 1.13, dan pertanyaan 11 di bagian 1.14. Bagian 2 mengikuti shift sore itu dari catatan serah terima yang diterima sampai catatan yang diserahkan, termasuk satu alert yang dibedah dari log mentah sampai menjadi insiden `INC-2027-089`.

**Kapan relevan:** saat kamu pertama kali bekerja di SOC atau MSSP dan perlu memahami alur kerja, saat membaca dashboard dan laporan metrik SOC, saat menulis atau menerima catatan serah terima, saat ditanya "kenapa alert ini tidak muncul", dan saat interview yang menanyakan beda SIEM dan SOAR, peran L1 dan L2, atau arti MTTD dan MTTR.
**Kapan bukan jawaban:** Day ini menjelaskan wadah kerjanya, bukan cara memutuskan sebuah alert asli atau palsu. Cara memilah alert (true positive, false positive, severity, priority, eskalasi, tuning) dibahas di Day 11, dan langkah penanganan insiden dibahas di Day 19. Day ini juga tidak mengajarkan bahasa query atau konfigurasi produk SIEM tertentu.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (alert, log, firewall, EDR, VPN, RADIUS, MFA, WAF) dipakai tanpa diulang panjang; definisi satu kalimatnya muncul di subbagian yang memakainya. Tabel ini memuat istilah operasi SOC yang dipakai Day ini; cari kolom ketiga bila sebuah istilah terasa abstrak.

| Istilah | Arti singkat | Padanan sehari-hari |
|---|---|---|
| SOC | Security Operations Center, tim dan fungsi yang memantau, mendeteksi, dan menangani kejadian keamanan | Ruang kontrol keamanan gedung beserta tim satpamnya |
| NOC | Network Operations Center, tim yang menjaga jaringan tetap hidup dan cepat | Tim teknisi gedung (listrik, lift, air) |
| Log | Catatan kejadian yang ditulis otomatis oleh sistem | Buku catatan satpam |
| Log entry | Satu baris atau satu catatan di dalam log, mewakili satu kejadian | Satu baris di buku catatan satpam |
| Log source | Perangkat atau layanan yang menghasilkan dan mengirim log | Pos satpam atau kamera yang mengirim catatan ke ruang monitor |
| Log management | Proses menghasilkan, mengirim, menyimpan, mengakses, dan membuang log | Aturan pengelolaan arsip buku catatan semua pos |
| SIEM | Sistem yang mengumpulkan log dari banyak sumber, mencarinya, mengorelasikan, dan memunculkan alert | Ruang monitor CCTV seluruh gedung |
| Parsing | Membongkar baris log menjadi kolom-kolom (field) yang bisa dipakai | Menyalin catatan tulisan tangan ke kolom formulir |
| Field | Satu kolom bernama di dalam log, misalnya `user` atau `src` | Kolom "nama tamu" atau "jam masuk" di formulir |
| Normalisasi | Menyeragamkan nama field, format waktu, dan nilai dari sumber yang berbeda | Semua pos memakai formulir baku, jam ditulis dalam satu zona waktu |
| Correlation rule | Aturan yang mencocokkan dua kejadian atau lebih lalu memunculkan alert | "Bila tamu yang sama ditolak di tiga pintu lalu masuk lewat pintu keempat, panggil kepala regu" |
| Use case | Paket lengkap untuk mendeteksi satu skenario ancaman: alasan, sumber log, rule, prosedur, pemilik | Rencana pengamanan untuk satu jenis kejadian, lengkap dengan kamera yang dibutuhkan |
| Baseline | Gambaran perilaku normal yang dihitung dari riwayat | Kebiasaan harian penghuni yang sudah dikenal |
| UEBA | User and entity behavior analytics, deteksi berbasis penyimpangan dari baseline | Satpam lama yang hafal kebiasaan penghuni |
| SOAR | Security orchestration, automation, and response, platform yang menyambungkan alat dan menjalankan langkah respons otomatis | Asisten yang menjalankan prosedur rutin otomatis |
| Enrichment | Menambahkan konteks ke alert (pemilik akun, reputasi IP, riwayat) | Petugas yang menempelkan data tamu dari buku tamu ke laporan |
| Playbook | Prosedur penanganan per jenis kejadian: apa yang dilakukan, siapa, kapan eskalasi | Prosedur penanganan kebakaran gedung |
| Runbook | Instruksi langkah teknis untuk satu tugas di satu alat | Instruksi tombol di panel alarm dan pintu darurat |
| Tier L1/L2/L3 | Pembagian kerja analyst berdasarkan kedalaman pekerjaan | Satpam pos depan, kepala regu, penyidik |
| Eskalasi | Menyerahkan kasus ke tingkat atau pihak yang lebih berwenang; dibahas di Day 11 | Satpam memanggil kepala regu |
| Ticketing | Sistem pencatatan pekerjaan bernomor dengan status, pemilik, dan jejak waktu | Buku laporan kejadian bernomor |
| SLA | Service level agreement, janji tertulis tentang layanan dan batas waktunya | Janji teknisi datang paling lambat 4 jam |
| MTTD | Mean time to detect, rata-rata waktu dari kejadian dimulai sampai terdeteksi | Rata-rata berapa lama sampai asap ketahuan |
| MTTA | Mean time to acknowledge, rata-rata waktu dari alert muncul sampai mulai ditangani | Rata-rata berapa lama sampai petugas menjawab alarm |
| MTTR | Mean time to respond, resolve, atau recover; definisinya berbeda antar organisasi | Rata-rata berapa lama sampai api dikendalikan, atau sampai gedung pulih |
| Shift | Giliran jaga dalam operasi 24 jam | Giliran jaga satpam |
| Handover | Serah terima pekerjaan dan kondisi dari satu shift ke shift berikutnya | Serah terima jaga satpam dengan buku laporan |
| NTP | Network Time Protocol, protokol untuk menyamakan jam perangkat | Semua pos menyetel jam dinding dari satu jam induk |

### 1.1 SOC dan bedanya dengan NOC

Pertanyaan pertama Dimas menyinggung tetangga satu lantai. Di PT JAB, SOC dan NOC duduk di lantai yang sama, sama-sama punya layar besar dan sama-sama jaga 24 jam. Orang luar sering mengira keduanya satu tim.

**Apa itu:** SOC (security operations center) adalah tim, proses, dan teknologi yang terus-menerus memantau organisasi, mendeteksi kejadian keamanan, memeriksanya, dan menangani yang terbukti berbahaya. Glosarium NIST hanya mencantumkan singkatan SOC dan dokumen yang memakainya [S3], tetapi NIST SP 800-61r3 menempatkan SOC sebagai salah satu bentuk tim penanganan insiden: bisa staf internal, bisa dialihdayakan ke MSSP (managed security services provider), atau gabungan keduanya [S4]. Yang membuat SOC berbeda dari sekadar "orang yang membaca alert" adalah kontinuitasnya: alert dan log dipantau terus, dan setiap temuan punya jalur penanganan sampai selesai [S4].

NOC (network operations center) adalah tim yang menjaga jaringan tetap tersedia dan berkinerja baik: memantau link, router, kapasitas, gangguan, dan perbaikan [S10]. Fokus NOC adalah availability dan performa; fokus SOC adalah melindungi organisasi dari ancaman keamanan [S10].

**Analogi:** di gedung perkantoran, NOC adalah tim teknisi gedung yang memastikan listrik, lift, dan air tetap jalan, sedangkan SOC adalah ruang kontrol keamanan dan tim satpamnya. Saat lift mati, yang dipanggil teknisi; saat ada orang asing membuka pintu ruang arsip, yang dipanggil satpam. Batasnya: di dunia TI, kejadian yang sama sering menyentuh keduanya. Serangan DDoS (Day 04) terlihat oleh NOC sebagai link penuh dan oleh SOC sebagai serangan. Lift yang macet karena disabotase juga urusan keduanya.

**Cara kerja:** pekerjaan SOC berputar dalam siklus yang tidak pernah berhenti.

```
  pantau (log, alert)  ->  pilah (triage)  ->  periksa (investigasi)  ->  tangani (respons)
          ^                                                                      |
          +----------  perbaiki deteksi dan prosedur (pelajaran dari setiap kasus) <+
```

NIST SP 800-61r3 menyusun rekomendasi ini mengikuti fungsi CSF 2.0: data kejadian dianalisis terus (Detect), alert disalurkan ke staf dan alat yang berwenang termasuk SOC, insiden dinyatakan bila memenuhi kriteria, lalu respons dikelola berdasarkan prioritas risiko, bukan siapa yang datang duluan [S4].

**Contoh di PT JAB:** SOC PT JAB terdiri dari analyst L1, analyst L2, dan SOC lead Dimas Prasetyo, bekerja dalam tiga shift. NOC dipimpin Bambang Hartono dan memegang router, BGP, dan kapasitas link. Sore ini perbedaannya terlihat jelas: ketika `bdg-fw01` berhenti mengirim log, NOC tidak melihat masalah apa pun karena firewall itu tetap meneruskan lalu lintas dengan normal. Yang kehilangan sesuatu adalah SOC, yang tiba-tiba buta terhadap jaringan Bandung.

**Beda dengan MSSP dan MDR:** MSSP dan MDR adalah layanan pihak luar yang menjalankan sebagian atau seluruh fungsi SOC untuk pelanggannya; bedanya dibahas di Day 06 bagian 1.3. SOC adalah fungsinya, MSSP dan MDR adalah salah satu cara mendapatkan fungsi itu.

**Salah paham umum:**
- "SOC adalah ruangan dengan layar besar." Yang membuat SOC adalah fungsi dan prosesnya. SOC kecil bisa berupa tiga orang dengan satu SIEM dan prosedur yang jelas; ruangan megah tanpa proses penanganan hanyalah ruang pameran.

### 1.2 Log dan log source

Pertanyaan kedua Dimas berawal dari catatan Dwi: satu sumber berhenti mengirim dan sebagian pandangan SOC hilang. Untuk memahami apa yang hilang, kamu harus tahu dulu apa saja yang biasanya masuk.

**Apa itu:** log adalah catatan kejadian yang terjadi di sistem dan jaringan organisasi; log tersusun dari log entry, dan setiap entry memuat informasi tentang satu kejadian tertentu [S1]. NIST SP 800-61r3 menyebut kejadian (event) sebagai peristiwa apa pun yang bisa diamati, misalnya percobaan login, pemasangan update, atau aplikasi yang menjawab permintaan [S4]. Log source adalah perangkat, sistem operasi, atau aplikasi yang menghasilkan log. NIST mengelompokkannya menjadi tiga: perangkat lunak keamanan (antivirus, firewall, IDS/IPS), sistem operasi di server, komputer, dan perangkat jaringan, serta aplikasi [S1]. Log management adalah proses menghasilkan, mengirim, menyimpan, mengakses, dan membuang data log [S2]; versi 2006 menyebut "menganalisis" di posisi "mengakses" [S1].

**Analogi:** buku catatan satpam. Setiap pos menulis siapa lewat, jam berapa, dan apa yang terjadi. Batasnya: buku itu hanya mencatat yang memang diperintahkan untuk dicatat. Bila satpam pos belakang tidak diminta mencatat jam keluar tamu, catatan itu tidak akan ada saat dibutuhkan. Hal yang sama berlaku di log: banyak perangkat secara bawaan tidak mencatat hal yang penting untuk keamanan.

**Cara kerja:** log berpindah dari sumber ke SIEM dengan dua cara [S1]:

- **Agentless:** sumber mengirim (push) lognya ke server pengumpul, atau server menarik (pull) log dari sumber. Firewall dan perangkat jaringan biasanya mengirim lewat syslog, protokol pengiriman log yang sederhana dan umum.
- **Agent-based:** program kecil (agent) dipasang di sumber untuk menyaring, merangkum, dan menormalisasi log sebelum mengirimnya, biasanya hampir seketika. Cara ini umum untuk server Windows.

NIST menyebut empat kesulitan klasik dari banyaknya log source: jumlah sumbernya banyak, isi log tidak seragam (sumber A mencatat IP tapi tidak mencatat user, sumber B sebaliknya), timestamp tidak konsisten karena setiap perangkat memakai jamnya sendiri, dan formatnya berbeda-beda [S1]. Untuk timestamp, NIST menyarankan semua sumber disinkronkan ke jam bersama memakai NTP; bila jam satu perangkat meleset, kejadian A bisa tercatat terjadi sebelum B padahal sebenarnya sesudahnya [S1].

Satu tugas operasional yang sering dilupakan: NIST memasukkan "memantau status logging semua log source" ke daftar tugas rutin pengelola log [S1]. Sumber yang diam harus diketahui secepat sumber yang mengirim tanda serangan.

**Contoh di PT JAB:** tabel berikut adalah log source utama PT JAB; cari kolom ketiga untuk tahu pertanyaan apa yang tidak bisa dijawab bila sumber itu berhenti.

| Log source | Isi utama | Yang hilang bila sumber ini diam |
|---|---|---|
| `jkt-fw01`, `bdg-fw01` (firewall Jakarta dan Bandung) | Koneksi yang diizinkan dan ditolak, IP, port | Siapa bicara ke siapa di batas jaringan kantor itu |
| `jkt-waf01` (WAF portal) | Permintaan web ke portal, yang diblokir dan diloloskan | Serangan ke aplikasi portal pelanggan |
| `jkt-ids01` (IDS Suricata) | Alert pola serangan di lalu lintas data center | Tanda serangan yang lewat jaringan data center |
| `jkt-proxy01` (proxy web) | Situs yang dibuka karyawan | Unduhan dan komunikasi web dari laptop kantor |
| `jkt-vpn01`, `jkt-radius01` (VPN dan RADIUS) | Login jarak jauh, hasil MFA, alamat yang diberikan | Siapa masuk dari luar dan dari mana |
| `JKT-DC01`, `JKT-DC02` (domain controller) | Login domain, perubahan akun dan group | Pemakaian akun di dalam jaringan |
| Microsoft Defender for Endpoint | Alert dan aktivitas proses di laptop dan server | Apa yang terjadi di dalam perangkat |
| Microsoft 365 dan Entra ID | Login cloud, MFA, aktivitas email | Login dan email yang tidak lewat jaringan kantor |
| AWS CloudTrail, Azure Activity Log | Perubahan di cloud | Siapa mengubah apa di cloud (Day 08) |
| `jkt-wazuh01` (HIDS server Linux tanpa EDR) | Perubahan file dan login di server Linux | Aktivitas di server Linux yang tidak punya EDR |
| `jkt-res01`, `jkt-res02` (resolver DNS) | Nama domain yang dicari setiap perangkat | Jejak awal hampir semua koneksi keluar |

Firewall dan perangkat jaringan mengirim syslog ke kolektor `jkt-logcol01`, yang meneruskannya ke Splunk. Server Windows memakai agent. Log cloud ditarik lewat API. Splunk juga menjalankan rule "log source diam lebih dari 30 menit"; rule inilah yang memunculkan `SOC-2027-0853`.

**Beda log dengan alert:** log adalah catatan semua kejadian yang dicatat, kebanyakan biasa saja. Alert adalah peringatan yang muncul karena sebuah aturan menilai satu atau beberapa kejadian perlu diperiksa. Satu alert bisa lahir dari ribuan baris log; hubungan event, alert, dan incident dibahas di Day 11.

**Salah paham umum:**
- "Kirim semua log ke SIEM, makin banyak makin aman." Log yang dikirim tanpa tujuan membebani penyimpanan dan biaya, dan menenggelamkan analyst. Panduan CISA dan mitranya mengingatkan bahwa biaya bisa membengkak bila ingest tidak dikelola, karena banyak SIEM dihargai per volume data [S6]; sumber dipilih berdasarkan use case (bagian 1.6) [S11].

### 1.3 SIEM

Pertanyaan ketiga Dimas: setelah semua log itu sampai di Splunk, lalu apa? Jawabannya adalah fungsi SIEM, dan cara termudah memahaminya adalah membandingkannya dengan server syslog biasa yang hanya menyimpan.

**Apa itu:** SIEM (security information and event management) adalah program yang menyediakan kemampuan logging terpusat untuk berbagai jenis log [S3]. NIST SP 800-92 menggambarkan produk SIEM sebagai satu atau lebih server analisis log dan server database yang menyimpan log [S1]. Setelah log terkumpul, SIEM menyaring dan merangkum (filtering dan aggregation), menormalisasi, lalu menganalisis log itu [S1]. SIEM umumnya sudah "mengenal" puluhan jenis log source dan tahu field penting setiap jenis, misalnya bahwa kolom ke-12 log aplikasi tertentu berisi IP sumber; inilah yang membuat normalisasi dan korelasinya lebih baik daripada alat log biasa [S1]. NIST SP 800-61r3 merekomendasikan alat seperti SIEM untuk memantau log terus-menerus terhadap aktivitas jahat yang dikenal, dan untuk menghubungkan data terkait dari banyak sumber [S4].

**Analogi:** ruang monitor CCTV seluruh gedung. Dari satu ruangan, petugas melihat lobi, parkir, lorong, dan pintu belakang sekaligus, bisa memutar ulang rekaman kemarin, dan alarm berbunyi bila sesuatu cocok dengan aturan. Batasnya: ruang monitor hanya melihat kamera yang terpasang dan mengirim gambar. Lorong tanpa kamera tidak terlihat, dan kamera yang mati tidak membuat lorong itu berbahaya atau aman; lorong itu hanya tidak diketahui.

**Cara kerja:** di dalam SIEM, satu baris log melewati beberapa tahap.

```
 terima log  ->  parsing (bongkar jadi field)  ->  normalisasi (seragamkan)  ->  simpan (index)
                                                                                    |
           dashboard dan pencarian investigasi  <--+--  correlation rule terjadwal  <-+
                                                   |    analitik perilaku (UEBA)
                                                   +--> alert ke antrean analyst
```

Selain normalisasi (bagian 1.4) dan korelasi (bagian 1.5), SIEM biasanya juga melakukan event filtering, yaitu menyisihkan entry yang hampir pasti tidak berguna seperti duplikat tanpa mengubah log aslinya, dan event aggregation, yaitu menggabungkan entry yang mirip menjadi satu dengan hitungan; seribu baris dari satu port scan bisa menjadi satu entry "seribu host dipindai" [S1]. Log disimpan sesuai masa simpan dan bisa dicari ulang saat investigasi.

**Contoh di PT JAB:** Splunk PT JAB menerima log dari sumber di bagian 1.2, menyimpannya, dan menjalankan rule terjadwal. Analyst mencari dan membuka alert lewat search head `jkt-splunk-sh01`. Alert muncul di antrean analyst, dan setiap alert otomatis menjadi tiket di sistem ticketing SOC (bagian 1.11).

**Beda dengan server syslog biasa:** server syslog mengumpulkan dan menyimpan log, tetapi tidak memahami isinya, tidak menyeragamkannya, dan tidak menghubungkan kejadian dari sumber berbeda. SIEM mengerjakan ketiganya. Kolektor `jkt-logcol01` adalah server syslog; ia hanya meneruskan.

**Beda dengan XDR:** SIEM menerima log dari sumber apa pun yang dikirim kepadanya, termasuk aplikasi buatan sendiri. XDR berangkat dari keluarga produk keamanan yang saling kenal dengan korelasi siap pakai (Day 06 bagian 1.3). Banyak SOC memakai keduanya, dan PT JAB salah satunya.

**Salah paham umum:**
- "Beli SIEM berarti langsung punya deteksi." SIEM tanpa log source yang tepat, parsing yang benar, rule yang dirawat, dan orang yang membaca hasilnya hanyalah gudang log yang mahal. Panduan CISA dan mitranya menyebut implementasi SIEM dan SOAR sebagai proses yang intensif dan terus-menerus, yang butuh personel terampil untuk memilih log, aturan, dan penyetelannya [S6].

### 1.4 Parsing dan normalisasi

Pertanyaan keempat Dimas muncul dari alert `SOC-2027-0854`. Login VPN yang sama tercatat di tiga sumber, dan ketiganya menulisnya dengan cara berbeda. Di `jkt-vpn01` user ditulis `teguh.wibowo@jab.example` dengan jam WIB. Di `jkt-radius01` user ditulis `CORP\teguh.wibowo` dengan jam UTC tanpa tahun. Di log Entra ID, user ditulis `Teguh.Wibowo@jab.example` dengan huruf besar. Ketiganya orang yang sama dan detik yang hampir sama.

**Apa itu:**
- **Parsing** adalah mengambil data dari log supaya nilai-nilainya bisa dipakai proses lain. Contoh paling sederhana dari NIST: membaca file teks berisi sepuluh nilai yang dipisah koma per baris, lalu mengambil kesepuluh nilai itu dari setiap baris [S1]. Hasil parsing adalah field, kolom bernama seperti `user`, `src`, atau `action`.
- **Normalisasi** adalah mengubah setiap field ke satu bentuk representasi dan kategori yang konsisten. Penggunaan paling umum adalah menyeragamkan format tanggal dan jam: satu sumber menulis jam 12 jam dengan zona waktu di belakang, sumber lain menulis jam 24 jam dan menaruh zona waktu di field terpisah [S1]. Normalisasi juga menyeragamkan nama field (satu sistem menyebut "User", yang lain "Uname") dan nilainya [S11]; NIST memberi contoh FTP yang di satu log ditulis sebagai nama ("FTP") dan di log lain sebagai nomor port (21) [S1].

**Analogi:** setiap pos satpam menulis buku catatannya dengan gaya sendiri: pos depan menulis "Pak Teguh, 15.46", pos belakang menulis "T. Wibowo, 08:46 GMT". Sebelum dibandingkan, semua catatan disalin ke formulir baku: kolom nama, kolom jam dalam WIB, kolom pintu, kolom hasil. Batasnya: menyalin ke formulir bisa salah. Bila petugas salin salah membaca nama, catatan dua orang berbeda bisa dianggap satu orang, atau sebaliknya. Parsing yang salah sama berbahayanya dengan log yang hilang.

**Cara kerja:**

```
 MENTAH (3 sumber, satu kejadian)                          SETELAH NORMALISASI
 jkt-vpn01   2027-08-13T15:46:02+07:00 ... user=teguh.wibowo@jab.example   _time=15:46:02 WIB  user=teguh.wibowo
 jkt-radius  Aug 13 08:46:01 ... user="CORP\teguh.wibowo"                   _time=15:46:01 WIB  user=teguh.wibowo
 Entra ID    "createdDateTime":"2027-08-13T08:44:49Z" ... "Teguh.Wibowo@..." _time=15:44:49 WIB  user=teguh.wibowo
             parsing: ambil field   ->   normalisasi: UTC+7, buang domain, huruf kecil, nama field baku
```

Tiga jenis normalisasi yang paling sering dibutuhkan:

1. **Waktu:** semua timestamp dikonversi ke satu zona waktu. NIST mencatat ini sering menjadi bagian tersulit, terutama bila jam perangkat tidak sinkron [S1].
2. **Nama field:** IP asal ditulis `src`, `source_ip`, `SrcAddr`, atau `ipAddress` oleh produk berbeda; semua dipetakan ke satu nama.
3. **Nilai:** `login=success`, `Auth OK`, dan `status: 0` dipetakan ke satu nilai seperti `action=success`.

Di Splunk, normalisasi dibantu Common Information Model (CIM): model bersama berisi nama field dan tag untuk setiap domain data (misalnya Authentication untuk semua jenis login), yang diterapkan saat pencarian sehingga data mentah tetap utuh [S8]. Karena login VPN, login Windows, dan login cloud dipetakan ke nama field yang sama, satu rule bisa membaca semuanya sekaligus [S8]. Nama field seperti `user`, `src`, dan `action` di Day ini dipakai sebagai contoh; daftar resminya ada di referensi data model CIM versi-mu.

**Contoh di PT JAB:** sebelum CIM diterapkan untuk log RADIUS, rule "login gagal berulang" PT JAB tidak pernah menghitung kegagalan dari `jkt-radius01`, karena user di sana ditulis dengan awalan `CORP\` sedangkan rule mencari nama tanpa awalan. Tidak ada error yang muncul; rule hanya tidak pernah cocok. Pembedahan lengkap tiga log `SOC-2027-0854` ada di bagian 2.2.

**Beda parsing dengan normalisasi:** parsing menjawab "nilai ini ada di kolom mana", normalisasi menjawab "nilai ini artinya sama dengan nilai apa di sumber lain". Log bisa ter-parsing dengan sempurna tetapi tetap tidak bisa dibandingkan karena belum dinormalisasi.

**Salah paham umum:**
- "Normalisasi mengubah log asli." Normalisasi yang baik membuat tampilan baku tanpa menghapus aslinya. Log asli tetap disimpan karena dibutuhkan sebagai bukti, dan NIST menyebut menjaga log asli tidak berubah penting untuk keperluan pembuktian [S1].

### 1.5 Correlation rule

Pertanyaan kelima Dimas adalah inti dari `SOC-2027-0853`. Selama `bdg-fw01` diam, dua rule yang mengawasi jaringan Bandung tetap berjalan sesuai jadwal, tetap selesai tanpa error, dan tetap menghasilkan nol alert. Nol alert itu terlihat seperti "aman".

**Apa itu:** event correlation adalah menemukan hubungan antara dua log entry atau lebih [S1]. Bentuk yang paling umum adalah rule-based correlation: aturan yang mencocokkan beberapa entry dari satu atau banyak sumber berdasarkan nilai seperti timestamp, IP, dan jenis kejadian [S1]. Korelasi juga bisa memakai metode statistik [S1]. Bila korelasi otomatis berhasil, hasilnya biasanya entry baru yang mengumpulkan informasi yang tersebar itu di satu tempat, dan sistem bisa memunculkan alert bahwa kejadian itu perlu diperiksa [S1]. NIST SP 800-61r3 merekomendasikan memakai teknologi korelasi seperti SIEM untuk mengumpulkan data terkait dari banyak sumber [S4].

Istilah produknya berbeda-beda. Di Splunk Enterprise Security 8, rule semacam ini disebut detection, yaitu correlation search atau risk rule terjadwal yang bisa mencari banyak jenis sumber data; bila menemukan kemungkinan ancaman, ia bisa membuat finding yang tampil di analyst queue [S7]. Dokumentasi dan versi ES yang lebih lama banyak memakai istilah correlation search; cek glosarium ES versi-mu untuk padanan istilah lama dan baru.

**Analogi:** aturan tertulis di ruang monitor: "bila tamu yang sama ditolak di tiga pintu lalu berhasil masuk lewat pintu keempat dalam 15 menit, panggil kepala regu". Satu penolakan tidak mencurigakan; urutannya yang mencurigakan. Batasnya: aturan itu hanya bekerja bila keempat pintu punya kamera yang mengirim gambar. Bila kamera pintu keempat mati, aturan tetap "berjalan" dan tetap tidak pernah terpenuhi.

**Cara kerja:** rule terjadwal biasanya punya lima bagian.

```
 1. sumber      : data apa yang dibaca (log VPN, log EDR, log firewall Bandung)
 2. kondisi     : pola apa yang dicari (minimal 5 MFA ditolak, lalu 1 login berhasil)
 3. pengelompok : per apa dihitung (per user dan per IP asal)
 4. jendela     : dalam rentang waktu berapa (15 menit) dan seberapa sering dijalankan (tiap 5 menit)
 5. keluaran    : alert dengan prioritas tertentu, diteruskan ke antrean dan tiket
```

Dua jenis korelasi yang sering dipakai:

- **Urutan dalam satu sumber:** beberapa kejadian di satu sumber yang membentuk pola, misalnya banyak MFA ditolak lalu satu disetujui di log VPN.
- **Gabungan beberapa sumber:** kejadian di satu sumber dihubungkan dengan kejadian di sumber lain lewat nilai yang sama (user, IP, host), misalnya laptop yang mendapat alert EDR lalu dalam satu jam terhubung ke IP luar yang ada di daftar blokir menurut log firewall.

**Contoh di PT JAB:** dua rule yang buta selama `bdg-fw01` diam:

| Rule | Logika | Sumber yang dibutuhkan |
|---|---|---|
| UC-021 Koneksi keluar ke IP terblokir | Koneksi keluar ke IP di daftar intel blokir, lalu dicocokkan dengan alert EDR di host yang sama dalam 1 jam | Firewall (`jkt-fw01` dan `bdg-fw01`), Defender for Endpoint |
| UC-034 Port scan internal | Satu host internal mencoba lebih dari 100 kombinasi IP dan port dalam 5 menit | Firewall internal (`bdg-fw01` untuk `10.30.0.0/16`) |

Tabel di atas memperlihatkan kenapa diamnya satu sumber tidak menghasilkan error. Rule UC-034 membaca log firewall Bandung, tidak menemukan apa pun karena memang tidak ada data, lalu selesai dengan hasil nol. Splunk tidak bisa membedakan "tidak ada port scan" dari "tidak ada log". Itulah sebabnya PT JAB punya rule terpisah yang memantau kesehatan sumber (`SOC-2027-0853`), dan itulah sebabnya rule korelasi yang dijalankan terjadwal tidak otomatis memeriksa ulang log yang masuk terlambat: rule yang berjalan pukul 17:00 hanya melihat beberapa menit terakhir, sedangkan log susulan bertanggal 13:42 sampai 16:25. Celah itu harus diperiksa manual (bagian 2.4).

**Beda correlation rule dengan signature IDS:** signature IDS (Day 03) mencocokkan pola di satu paket atau satu sesi lalu lintas. Correlation rule bekerja di atas log yang sudah tersimpan, bisa menggabungkan sumber yang sama sekali berbeda (VPN, EDR, cloud), dan bisa melihat rentang waktu yang panjang.

**Salah paham umum:**
- "Rule yang tidak pernah berbunyi berarti tidak ada serangan." Bisa juga berarti sumbernya diam, parsing-nya rusak (bagian 1.4), atau logikanya salah. Rule perlu diuji dengan kasus positif secara berkala, dan sumbernya perlu dipantau.

### 1.6 Use case

Pertanyaan keenam Dimas menyinggung kebiasaan tim mencampur istilah. Kode `UC-017`, `UC-021`, dan `UC-034` di PT JAB bukan nama rule, melainkan nama use case. Rule hanyalah satu bagian di dalamnya.

**Apa itu:** use case SIEM adalah paket lengkap untuk mendeteksi dan menangani satu skenario ancaman tertentu. Isinya bukan hanya logika deteksi, tetapi juga alasan ancaman itu penting, log source yang dibutuhkan beserta pengaturannya, normalisasi yang harus ada, prioritas, prosedur respons, pemilik, dan cara mengujinya. Artikel ISACA tentang implementasi SIEM menyebut definisi use case sebagai tempat nilai SIEM "didapat atau hilang", dan menganjurkan logging yang berangkat dari tujuan: tentukan use case dan playbook lebih dulu, baru tentukan log yang dibutuhkan, aktifkan di sumbernya, dan masukkan ke SIEM [S11]. Cara ini lebih baik daripada membiarkan pengaturan bawaan (banyak titik buta) atau mengirim semua log (mahal dan menenggelamkan analyst) [S11].

**Analogi:** rencana pengamanan untuk satu jenis kejadian, misalnya "pencurian di gudang malam hari": kenapa gudang itu penting, kamera mana yang harus dipasang dan ke arah mana, aturan kapan alarm berbunyi, siapa yang dipanggil, dan latihan berkala untuk memastikan alarmnya masih berbunyi. Batasnya: rencana di atas kertas tidak berguna bila kameranya tidak pernah dipasang; use case yang log source-nya belum masuk SIEM hanyalah dokumen.

**Cara kerja:** satu use case di PT JAB ditulis sebagai kartu. Tabel berikut adalah kartu `UC-017`, use case yang memunculkan `SOC-2027-0854`; perhatikan bahwa rule hanya mengisi satu baris.

| Bagian | Isi UC-017 "MFA fatigue di VPN" |
|---|---|
| Skenario ancaman | Penyerang yang sudah tahu password mengirim permintaan MFA push berulang sampai korban menyetujui karena lelah atau bingung |
| Kenapa penting | Akun VPN memberi akses ke jaringan internal; insiden AiTM 2026-2027 menunjukkan MFA bisa dilewati |
| Log source | `jkt-vpn01` (wajib), `jkt-radius01`, log login Entra ID (pelengkap) |
| Normalisasi | Field `user` tanpa domain dan huruf kecil; `action` = success/failure; waktu WIB |
| Rule | Minimal 5 MFA ditolak untuk user yang sama dalam 15 menit, lalu login berhasil dalam 10 menit; dijalankan tiap 5 menit |
| Prioritas | P2 |
| Respons | Playbook PB-04 "Akun dicurigai diambil alih" (bagian 1.9) |
| Pemilik | Sari Kusuma |
| Uji | Simulasi tiap 3 bulan dengan akun uji; terakhir 2027-06-14 |

**Contoh di PT JAB:** saat `bdg-fw01` diam, kartu UC-021 dan UC-034 memberi tahu Dwi dengan cepat use case mana yang terdampak, karena kolom log source-nya menyebut `bdg-fw01`. Tanpa kartu, Dwi harus membuka setiap rule satu per satu.

**Beda use case dengan correlation rule:** correlation rule adalah logika deteksinya; use case adalah seluruh paket di sekitarnya, termasuk kenapa dan apa yang dilakukan setelah alert muncul. Satu use case bisa punya lebih dari satu rule.

**Salah paham umum:**
- "Use case diambil dari daftar kepatuhan." Daftar kepatuhan berguna untuk memeriksa cakupan, tetapi use case yang baik berangkat dari ancaman nyata terhadap aset organisasi. ISACA juga mencatat pustaka use case bawaan produk sering terbatas cakupannya [S11].

### 1.7 UEBA

Pertanyaan ketujuh Dimas menyangkut `SOC-2027-0855`. Pukul 17:10 muncul alert: akun `ratna.handayani@jab.example` (Keuangan) mengunduh 1.240 file dari folder bersama `\\JKT-FS01\Keuangan` antara 16:40 dan 17:05. Tidak ada rule yang menulis "jangan unduh lebih dari seribu file". Alert itu muncul karena angkanya jauh dari kebiasaan Ratna.

**Apa itu:** UEBA (user and entity behavior analytics) adalah pendekatan deteksi yang membangun profil perilaku normal (baseline) untuk user dan entitas lain (host, alamat IP, aplikasi), lalu menandai aktivitas yang menyimpang dari profil itu. Contohnya Microsoft Sentinel: UEBA di sana memakai machine learning untuk membangun profil perilaku, mendeteksi anomali dengan membandingkan aktivitas sekarang dengan baseline, dan ditujukan untuk menemukan akun yang diambil alih, serangan orang dalam, dan pergerakan di dalam jaringan [S9]. Baseline setiap entitas dibentuk dari riwayatnya sendiri, dari kelompok sejenisnya (peer group, misalnya rekan satu divisi), dan dari pola organisasi secara keseluruhan; penyimpangan lalu diberi skor risiko [S9].

**Analogi:** satpam lama yang hafal kebiasaan penghuni. Ia tahu Bu Ratna biasa datang jam delapan dan membawa satu map. Hari ini Bu Ratna keluar membawa tiga kardus arsip; tidak ada aturan yang melarang, tetapi satpam itu bertanya. Batasnya ada dua. Pertama, satpam yang baru dua minggu bertugas belum hafal siapa-siapa; UEBA butuh waktu belajar sebelum baseline-nya berguna. Kedua, kebiasaan baru yang sah (pindah divisi, persiapan audit, proyek akhir tahun) juga terlihat aneh. Anomali berarti "tidak biasa", bukan "jahat".

**Cara kerja:**

```
 riwayat 30 hari Ratna : rata-rata 35 file per hari
 peer group Keuangan   : 14 orang, rata-rata 42 file per hari per orang
 hari ini 16:40-17:05  : 1.240 file      -> 1.240 / 35 = lebih dari 35 kali kebiasaannya
                                          -> skor penyimpangan tinggi -> alert P3 SOC-2027-0855
```

Perbedaan utamanya dengan correlation rule: rule bertanya "apakah pola X terjadi", UEBA bertanya "apakah ini normal untuk orang atau perangkat ini". UEBA berguna untuk ancaman yang tidak punya pola tetap, misalnya akun sah yang dipakai orang lain atau karyawan yang mengumpulkan data sebelum keluar.

**Contoh di PT JAB:** PT JAB belum memakai modul UEBA khusus. Yang dipakai adalah search terjadwal di Splunk yang menghitung baseline 30 hari per user dan per divisi untuk beberapa perilaku (jumlah file yang dibuka, jam login, negara asal login), sehingga cara kerjanya mirip UEBA sederhana. Untuk `SOC-2027-0855`, kamu menghubungi atasan Ratna. Pukul 17:40 atasannya mengonfirmasi bahwa Ratna sedang menyiapkan arsip 2026 untuk auditor eksternal atas permintaannya. Tiket ditutup sebagai aktivitas sah dengan catatan, dan Sari menyarankan permintaan semacam itu ke depan diberitahukan ke SOC lebih dulu. Cara menggolongkan hasil alert seperti ini dibahas di Day 11.

**Beda UEBA dengan correlation rule:** rule mendeteksi pola yang sudah diketahui dan ditulis manusia; UEBA mendeteksi penyimpangan dari kebiasaan tanpa perlu tahu polanya lebih dulu. Rule lebih mudah dijelaskan dan diuji; UEBA lebih mungkin menangkap yang belum terbayangkan, dengan harga lebih banyak alert yang ternyata sah.

**Salah paham umum:**
- "Skor UEBA tinggi berarti orangnya pelaku." Skor hanya mengatakan perilakunya tidak biasa. Keputusan tetap butuh konteks yang tidak dimiliki mesin, seperti permintaan audit yang hanya diketahui atasan.

### 1.8 SOAR

Pertanyaan kedelapan Dimas muncul karena seorang vendor baru saja menawarkan SOAR. Sore ini kamu sudah melihat versi kecilnya: saat `SOC-2027-0854` muncul, dua detik kemudian tiketnya sudah berisi reputasi IP `192.0.2.171` dan data pemilik akun, tanpa ada yang mengetik.

**Apa itu:** SOAR (security orchestration, automation, and response) adalah platform yang menyambungkan berbagai alat keamanan (orchestration), menjalankan langkah-langkah tanpa campur tangan manusia (automation), dan memakai keduanya untuk mempercepat penanganan alert dan insiden (response). Glosarium NIST mencantumkan istilah ini dari SP 800-61r3 dan beberapa publikasi lain tanpa teks definisi panjang [S3]; SP 800-61r3 menyebut SOAR bersama SIEM sebagai alat untuk memantau log, mengorelasikan data, dan memperkirakan dampak kejadian [S4]. Panduan bersama CISA, NSA, dan ASD ACSC (Mei 2025) menggambarkan SOAR sebagai perangkat lunak yang mengotomatiskan respons terhadap aktivitas tidak normal yang terdeteksi di jaringan, dan mengingatkan bahwa SOAR harus diatur supaya hanya bertindak pada insiden nyata, bukan pada aktivitas jaringan yang normal [S6].

**Analogi:** asisten yang menjalankan prosedur rutin otomatis. Begitu alarm pintu belakang berbunyi, asisten langsung menarik rekaman kamera terdekat, mencocokkan wajah dengan daftar karyawan, dan menaruh semuanya di meja kepala regu sebelum kepala regu sempat bertanya. Batasnya: asisten hanya sebaik prosedur yang diberikan kepadanya, dan ia mengulang kesalahan dengan sangat cepat. Asisten yang diperintah "kunci semua pintu bila alarm berbunyi" akan mengunci karyawan sah di dalam gedung setiap kali alarm salah bunyi.

**Cara kerja:** SOAR menjalankan alur kerja otomatis yang di banyak produk juga disebut playbook (bagian 1.9 membahas bedanya dengan playbook dokumen).

```
 alert masuk dari SIEM
     |
     +--> enrichment otomatis : reputasi IP, data pemilik akun, riwayat alert host   (aman, tanpa mengubah apa pun)
     +--> tindakan pendukung  : buat tiket, kirim notifikasi, ambil log tambahan     (aman)
     +--> tindakan penahanan  : putus sesi, nonaktifkan akun, isolasi host           (berdampak: biasanya
                                                                                      butuh persetujuan analyst)
```

Semakin kanan dan bawah, semakin besar dampaknya bila alert ternyata salah. Banyak organisasi mulai dari enrichment, baru kemudian tindakan yang berdampak, dan untuk tindakan berdampak menaruh tombol persetujuan manusia di tengah alurnya.

**Contoh di PT JAB:** PT JAB belum memakai platform SOAR penuh. Yang ada adalah otomasi kecil di Splunk: enrichment otomatis setiap alert (pemilik aset dari daftar inventaris, data karyawan dari AD, reputasi IP, jumlah alert lain di host yang sama tujuh hari terakhir) dan pembuatan tiket otomatis. Alasan Dimas menunda SOAR penuh: sebagian rule masih sering salah bunyi, dan otomasi penahanan di atas rule yang belum stabil akan memutus sesi karyawan sah. Rencana pilot SOAR di 2027 dibatasi pada dua playbook (phishing yang dilaporkan user dan PB-04 akun diambil alih), dengan langkah penahanan tetap menunggu persetujuan L2. Contoh otomasi yang sudah berjalan sore ini: `SOC-2027-0856`, program iklan yang diblokir Defender di laptop `JKT-WS-1107` (`10.10.40.107`); enrichment otomatis menunjukkan file sudah dikarantina dan tidak ada alert lain di laptop itu selama tujuh hari, sehingga kamu menutupnya sesuai runbook dalam enam menit (19:30 sampai 19:36).

**Beda SOAR dengan SIEM:** SIEM melihat dan memberi tahu; SOAR bertindak dan menyambungkan alat. SOAR hampir selalu menerima alert dari SIEM atau alat deteksi lain, jadi kualitas SOAR dibatasi kualitas alert yang masuk.

**Salah paham umum:**
- "SOAR menggantikan analyst." Panduan bersama CISA dan mitranya menekankan bahwa platform ini tetap butuh personel terampil yang terus menyetelnya [S6]. SOAR memindahkan pekerjaan berulang dari manusia; keputusan yang butuh konteks tetap di manusia.

### 1.9 Playbook vs runbook

Setelah `SOC-2027-0854` dieskalasi, Sari membuka dua dokumen di layar: "PB-04 Akun dicurigai diambil alih" dan "RB-11 Memutus sesi VPN di jkt-vpn01". Keduanya prosedur, tetapi menjawab pertanyaan yang berbeda.

**Apa itu:**
- **Playbook** berisi langkah atau tugas yang bisa langsung dikerjakan orang untuk satu jenis skenario atau situasi. NIST SP 800-61r3 menyebut banyak organisasi membuat playbook sebagai bagian dari dokumentasi prosedurnya, dan menyusun prosedur dalam bentuk playbook membuatnya lebih mudah dipakai [S4]. Playbook menjawab: kejadian jenis ini ditangani bagaimana, siapa melakukan apa, keputusan apa yang harus diambil, dan kapan eskalasi.
- **Runbook** berisi latar belakang dan langkah demi langkah untuk satu tugas rutin atau satu tindakan teknis, dalam format baku supaya cepat ditemukan dan diikuti; isinya biasanya masalah, gejala, langkah penyelesaian, uji validasi, dan kriteria eskalasi [S12]. Runbook menjawab: di alat ini, tombol atau perintah apa yang ditekan, berurutan.

Di lapangan pemakaiannya tidak seragam. Tulisan TechTarget menyebut bedanya sebagian besar soal kebiasaan: orang bisnis lebih sering memakai kata playbook, orang TI lebih sering memakai runbook, dan keduanya sering dipakai bergantian [S12]. Sebagian produk SOAR juga menyebut alur otomatisnya "playbook". Karena itu, cek definisi yang dipakai di organisasimu. Di PT JAB, konvensinya seperti di atas: playbook per jenis kejadian, runbook per tindakan teknis.

**Analogi:** playbook adalah prosedur penanganan kebakaran gedung: siapa membunyikan alarm, siapa memandu evakuasi, kapan memanggil pemadam, titik kumpul di mana, siapa yang memutuskan gedung boleh dimasuki lagi. Runbook adalah instruksi tombol di setiap panel: cara mematikan aliran listrik lantai 3, cara membuka pintu darurat dari ruang kontrol, cara mereset panel alarm merek tertentu. Batasnya: prosedur kebakaran tidak berubah walaupun panel alarmnya diganti merek lain, sedangkan instruksi tombol harus ditulis ulang setiap alat berganti. Keduanya juga harus dilatih; prosedur yang belum pernah dicoba sering gagal di langkah yang paling sederhana.

**Cara kerja:** playbook menunjuk runbook di langkah-langkahnya.

```
 PB-04 Akun dicurigai diambil alih (playbook)
  1. Konfirmasi: hubungi pemilik akun lewat telepon kantor, bukan lewat email akun itu
  2. Bila pemilik tidak melakukan login itu atau menyetujui MFA tanpa sengaja: eskalasi ke L2 (target 30 menit)
  3. Tahan (L2): putus sesi aktif ......................... RB-11 (VPN), RB-13 (Microsoft 365)
                 nonaktifkan akun sementara ............... RB-12 (AD dan Entra ID)
  4. Lingkup: periksa aktivitas sesi (proxy, file server, email)
  5. Pulihkan: reset password bersama pemilik, cabut sesi lama, cek metode MFA
  6. Putuskan: buka insiden bila ada akses ke data atau sistem; catat di tiket
```

**Contoh di PT JAB:** saat menangani `SOC-2027-0854`, kamu menjalankan langkah 1 dan 2 dari PB-04. Yoga Pratama (L2) menjalankan langkah 3 dengan RB-11 pukul 16:09 dan RB-12 pukul 16:11. Runbook RB-11 berisi layar dan tombol di konsol `jkt-vpn01`; bila PT JAB mengganti produk VPN tahun depan, RB-11 ditulis ulang, sedangkan PB-04 tetap.

**Beda playbook dengan use case:** use case (bagian 1.6) berakhir di "alert muncul dan ditangani dengan playbook apa"; playbook dimulai dari situ. Satu playbook bisa dipakai beberapa use case: PB-04 dipakai oleh UC-017 (MFA fatigue) dan oleh use case login dari negara yang tidak biasa.

**Salah paham umum:**
- "Playbook yang lengkap membuat analyst tidak perlu berpikir." Playbook memberi kerangka dan titik keputusan; ia tidak bisa memuat semua situasi. NIST sendiri menyebut tidak mungkin punya prosedur rinci untuk setiap situasi, jadi organisasi mendahulukan jenis insiden yang paling umum dan proses yang paling mendesak [S4].

### 1.10 Tier L1, L2, dan L3

Pertanyaan kesembilan Dimas ("siapa mengerjakan apa") terjawab di tiket `SOC-2027-0854`: kamu memeriksa dan menelepon, Yoga memutus sesi dan membuka insiden, dan Dimas menerima laporan ringkas. Itulah pembagian tier.

**Apa itu:** tier adalah pembagian kerja analyst SOC berdasarkan kedalaman dan kerumitan pekerjaan. Gambaran umum yang dipakai banyak SOC [S15]:

- **L1 (tier 1):** memantau antrean alert, melakukan triage awal (memilah alert mana yang perlu ditindaklanjuti), menjalankan runbook dan playbook standar, menutup yang jelas, dan meneruskan yang di luar wewenangnya dengan ringkasan lengkap.
- **L2 (tier 2):** investigasi lebih dalam, menentukan cakupan dan dampak, merekomendasikan atau menjalankan penahanan, dan menangani insiden.
- **L3 (tier 3):** threat hunting (mencari ancaman secara proaktif, dibahas di Day 13), forensik mendalam, membuat dan menyetel deteksi, dan memimpin insiden besar.

Alasan model ini: sebagian besar alert ternyata bukan serangan atau berprioritas rendah, jadi menyaringnya bertahap menyimpan waktu orang yang paling berpengalaman untuk kasus yang benar-benar membutuhkannya. Kelemahannya juga sering dibahas: konteks bisa hilang di setiap perpindahan tier, dan kriteria eskalasi bisa subjektif.

**Analogi:** satpam pos depan, kepala regu, dan penyidik. Satpam pos depan melihat semua yang datang, menangani urusan biasa sendiri, dan memanggil kepala regu bila ada yang aneh. Kepala regu memutuskan tindakan dan mengatur anggota. Penyidik datang untuk kasus besar dan menelusuri apa yang sebenarnya terjadi. Batasnya: tier bukan pangkat kecerdasan, dan pekerjaan L1 lebih dari meneruskan alert. Catatan L1 yang lengkap menentukan seberapa cepat L2 bisa bertindak, dan banyak temuan penting justru datang dari L1 yang curiga pada hal kecil.

**Cara kerja:** tabel berikut memetakan tier ke orang dan pekerjaan di PT JAB sore ini; baca kolom terakhir untuk melihat contoh nyatanya.

| Tier | Orang di PT JAB | Pekerjaan utama | Contoh hari ini |
|---|---|---|---|
| L1 | Dwi Cahyono, Gilang Ramadhan, kamu | Pantau antrean, triage, enrichment, runbook, tutup atau eskalasi | `SOC-2027-0853`, `0855`, `0856`, `0857`; langkah 1-2 PB-04 untuk `0854` |
| L2 | Sari Kusuma, Yoga Pratama, Rudi Hartanto | Investigasi, scoping, penahanan, memimpin insiden kecil dan sedang | Yoga memutus sesi dan membuka `INC-2027-089` |
| L3 | Belum ada posisi khusus; dibagi Dimas dan L2 senior, ditambah penyedia IR luar untuk insiden besar | Hunting, forensik, menulis dan menyetel use case | Sari meninjau UC-021 dan UC-034 setelah `0853` |
| SOC lead | Dimas Prasetyo | Prioritas, metrik, koordinasi dengan tim lain, laporan ke Direktur Teknologi | Dashboard Juli (bagian 2.3) |

**Contoh di PT JAB:** aturan eskalasi PT JAB tertulis di setiap playbook. Untuk PB-04, L1 wajib eskalasi ke L2 paling lambat 30 menit setelah mulai menangani bila pemilik akun menyangkal login atau menyetujui MFA tanpa sengaja. Kriteria dan cara eskalasi secara umum dibahas di Day 11.

### 1.11 Ticketing

Bagian kedua pertanyaan kesembilan: kenapa semua harus lewat tiket? Sore ini kamu sempat menelepon Teguh sebelum mencatat apa pun di tiket, dan Sari langsung memintamu menulis jam teleponnya.

**Apa itu:** ticketing adalah sistem pencatatan pekerjaan di mana setiap kasus mendapat nomor unik, prioritas, status, pemilik, dan jejak waktu setiap perubahan. NIST SP 800-61r3 menyarankan organisasi mempertimbangkan pembuatan dan penugasan tiket secara otomatis di sistem ticketing ketika jenis alert tertentu muncul [S4]. Di SOC, tiket adalah satu-satunya tempat yang memuat seluruh cerita sebuah alert: apa yang dicek, oleh siapa, jam berapa, apa hasilnya, dan kenapa diputuskan begitu.

**Analogi:** buku laporan kejadian bernomor di pos satpam, atau nomor pengaduan saat kamu menelepon layanan pelanggan. Siapa pun yang menerima telepon berikutnya bisa membaca nomor itu dan melanjutkan tanpa bertanya dari awal. Batasnya: tiket bukan pekerjaannya. Tiket yang ditutup cepat dengan catatan "sudah dicek" tanpa isi terlihat bagus di dashboard tetapi tidak membantu siapa pun.

**Cara kerja:** di PT JAB, setiap alert dari Splunk otomatis membuat tiket dengan nomor yang sama (`SOC-2027-0854`). Siklus statusnya:

```
 New ---> In progress ---> Resolved ---> Closed
              |   ^
              |   +-- Pending (menunggu pihak lain, misalnya tim Infrastruktur)
              +-----> Escalated (ke L2; terhubung ke catatan insiden INC-2027-xxx bila ada)
```

Field minimal di setiap tiket PT JAB:

- nomor, judul, prioritas (P1 sampai P4; arti prioritas dibahas di Day 11), use case asal;
- waktu dibuat, waktu mulai ditangani (acknowledge), waktu eskalasi, waktu selesai;
- pemilik saat ini;
- catatan kerja bertanda waktu: apa yang dicek, hasilnya, siapa yang dihubungi;
- keputusan akhir dan alasannya, tautan ke insiden bila ada.

Tiket penting karena empat hal: shift berikutnya melanjutkan dari catatan, bukan dari ingatan (bagian 1.14); setiap keputusan punya pemilik dan alasan, sejalan dengan prinsip accounting di Day 01 bagian 1.2; MTTA dan MTTR dihitung dari jejak waktu tiket (bagian 1.13), jadi waktu yang tidak dicatat tidak bisa diukur; dan tiket yang berulang dari rule yang sama menunjukkan rule yang perlu disetel.

**Contoh di PT JAB:** tiket `SOC-2027-0854` lengkap dengan jejak waktunya ada di bagian 2.2. Catatan insiden `INC-2027-089` dibuka terpisah oleh Yoga dan ditautkan ke tiket itu; insiden memakai severity SEV-1 sampai SEV-4, sedangkan alert memakai prioritas P1 sampai P4 (Day 11).

**Beda tiket dengan catatan insiden:** setiap alert punya tiket; hanya sebagian kecil tiket yang menjadi insiden. Catatan insiden memuat hal yang lebih luas: cakupan, dampak, keputusan manajemen, komunikasi, dan pelajaran.

### 1.12 SLA

Pertanyaan kesepuluh Dimas dimulai dari angka di pojok dashboard: "SLA P2 92,7%". Untuk membacanya, kamu perlu tahu dulu apa yang dijanjikan.

**Apa itu:** SLA (service level agreement) adalah komitmen antara penyedia layanan dan satu atau lebih pelanggannya yang memuat tanggung jawab, jenis layanan, kinerja yang diharapkan (misalnya keandalan, kualitas, dan waktu respons), serta ketentuan pelaporan dan penyelesaian [S3]. Glosarium NIST juga menyebut SLA menetapkan tanggung jawab spesifik penyedia dan mengatur harapan pelanggan [S3]. Di SOC, SLA biasanya mengatur berapa lama alert boleh menunggu sebelum mulai ditangani, berapa lama sebelum eskalasi, dan seberapa sering pihak terkait diberi kabar. SLA bisa berupa kontrak dengan pihak luar (misalnya MSSP atau pelanggan korporat), atau target internal antara SOC dan manajemen.

**Analogi:** janji teknisi AC "datang paling lambat 4 jam setelah laporan". Janji itu jelas, bisa diukur, dan berlaku per laporan. Batasnya: janji datang dalam 4 jam tidak menjamin AC-nya langsung dingin. SLA waktu respons tidak menjamin hasil penanganannya benar; ia hanya menjamin kasus tidak dibiarkan menunggu.

**Cara kerja:** SLA dihitung per tiket, lalu dirangkum menjadi persentase kepatuhan. Tabel berikut adalah SLA internal SOC PT JAB; cari kolom "Mulai ditangani" untuk batas yang paling sering diukur.

| Prioritas | Contoh | Mulai ditangani (acknowledge) | Ketentuan lain |
|---|---|---|---|
| P1 | Ransomware aktif, akun admin domain diambil alih | 15 menit | Telepon L2 dan SOC lead langsung; kabar ke Direktur Teknologi tiap 30 menit |
| P2 | Akun karyawan kemungkinan diambil alih | 30 menit | Eskalasi ke L2 paling lambat 30 menit setelah mulai ditangani bila ada indikasi kuat |
| P3 | Serangan web yang diblokir WAF, log source diam | 4 jam | Selesai dalam shift yang sama atau diserahterimakan |
| P4 | Program iklan yang sudah diblokir | 24 jam | Boleh ditutup dengan template runbook |

Kepatuhan SLA = jumlah tiket yang memenuhi batas dibagi jumlah tiket di prioritas itu. Di bulan Juli, 38 dari 41 tiket P2 mulai ditangani dalam 30 menit, jadi kepatuhannya 38 / 41 = 92,7% (bagian 2.3).

**Contoh di PT JAB:** `SOC-2027-0854` (P2) muncul pukul 15:48:10 dan kamu mulai menanganinya pukul 15:52:40, 4 menit 30 detik kemudian; SLA 30 menit terpenuhi. `SOC-2027-0853` (P3) muncul 14:15 dan ditangani Dwi 14:19; SLA 4 jam terpenuhi dengan longgar, tetapi Dwi tidak menunggu karena tahu dampaknya pada dua use case.

**Beda SLA dengan metrik MTTx:** SLA adalah janji per kasus ("setiap P2 ditangani dalam 30 menit"); MTTA dan kawan-kawan adalah rata-rata dari banyak kasus. Rata-rata bisa terlihat baik walaupun beberapa kasus melanggar SLA dengan parah, jadi keduanya dibaca bersama.

**Salah paham umum:**
- "SLA terpenuhi berarti SOC bekerja baik." SLA acknowledge bisa dipenuhi dengan menekan tombol "ambil" lalu membiarkan tiket. Karena itu PT JAB juga melihat isi catatan kerja dan waktu sampai tindakan nyata, bukan hanya waktu acknowledge.

### 1.13 MTTD, MTTA, dan MTTR

Bagian terakhir pertanyaan kesepuluh: dashboard Juli menunjukkan MTTD 2 jam 45 menit dan MTTR 33 jam, sedangkan vendor kemarin mengklaim "MTTR 15 menit". Sebelum membandingkan, tanyakan dulu jam mana yang dipakai sebagai awal dan akhir.

**Apa itu:** ketiganya adalah rata-rata (mean) durasi antara dua titik waktu dalam penanganan kejadian.

- **MTTD (mean time to detect):** rata-rata waktu dari kejadian berbahaya dimulai sampai terdeteksi (alert muncul atau kejadian dikenali). Dalam alur kejadian, MTTD mengalir langsung ke MTTR: akhir MTTD adalah awal MTTR [S13].
- **MTTA (mean time to acknowledge):** rata-rata waktu dari alert muncul sampai tim mulai mengerjakannya [S14].
- **MTTR:** huruf R-nya punya beberapa arti, dan sumber-sumber tidak seragam [S13][S14]:
  - **respond:** dari deteksi sampai langkah respons selesai, biasanya sampai ancaman tertahan (contained); pemulihan penuh tidak termasuk [S13];
  - **recover:** sampai sistem pulih; titik mulainya dibiarkan terbuka, sebagian organisasi mulai dari saat sistem disusupi, sebagian lagi dari akhir fase respons [S13];
  - **resolve:** mencakup seluruh insiden sampai pelajaran dibahas dan kasus ditutup [S13];
  - **repair:** istilah dari dunia perawatan perangkat, rata-rata waktu memperbaiki sistem sampai berfungsi lagi [S14].

Pesan dari sumber-sumber itu sama: definisi yang dipilih harus ditulis jelas dan dipakai konsisten [S13], karena singkatan yang sama bisa menghasilkan angka yang sangat berbeda.

**Analogi:** kebakaran di gedung. MTTD adalah rata-rata berapa lama sejak api mulai sampai asapnya ketahuan. MTTA adalah rata-rata berapa lama sejak alarm berbunyi sampai petugas menjawab. MTTR bisa berarti berapa lama sampai api dikendalikan (respond), sampai gedung bisa dipakai lagi (recover), atau sampai laporan dan perbaikan selesai (resolve). Batasnya: "kapan api mulai" sering baru diketahui belakangan, setelah penyelidikan. Di dunia digital, awal sebuah serangan sering baru terungkap berhari-hari kemudian, sehingga MTTD bisa berubah setelah insiden ditutup.

**Cara kerja:** hitung dulu durasi setiap kasus, lalu bagi totalnya dengan jumlah kasus.

```
 rumus umum : MTTx = (jumlah durasi semua kasus) / (jumlah kasus)

 SOC-2027-0854 (satu kasus):
   aktivitas penyerang pertama (MFA ditolak pertama)  15:31:07
   login berhasil                                      15:46:02
   alert muncul (deteksi)                              15:48:10
   mulai ditangani (acknowledge)                       15:52:40
   akun dinonaktifkan (tertahan)                       16:11:10

   waktu deteksi  : 15:31:07 -> 15:48:10 = 17 menit 3 detik   (dihitung dari aktivitas pertama)
                    15:46:02 -> 15:48:10 =  2 menit 8 detik   (dihitung dari login berhasil)
   waktu ack      : 15:48:10 -> 15:52:40 =  4 menit 30 detik
   waktu respond  : 15:48:10 -> 16:11:10 = 23 menit
```

Perhatikan baris waktu deteksi. Kasus yang sama menghasilkan 17 menit atau 2 menit, tergantung kejadian mana yang dianggap awal serangan. Rata-rata dari banyak kasus juga mudah ditarik oleh satu kasus yang sangat lambat; karena itu median (nilai tengah) sering ditampilkan di samping rata-rata. Perhitungan bulan Juli lengkap ada di bagian 2.3.

**Contoh di PT JAB:** dashboard PT JAB menulis definisinya di bawah setiap angka: MTTD dari aktivitas berbahaya pertama yang diketahui sampai alert, MTTA dari alert sampai acknowledge, MTTR (respond) dari alert sampai tertahan, dan MTTR (resolve) dari alert sampai insiden ditutup. Klaim vendor "MTTR 15 menit" dibedah di bagian 2.3.

**Beda MTTA dengan MTTR:** MTTA mengukur seberapa cepat alert mulai disentuh; MTTR mengukur seberapa cepat masalahnya benar-benar teratasi. MTTA yang sangat cepat dengan MTTR yang lambat biasanya menandakan tiket diambil cepat lalu dibiarkan menunggu.

**Salah paham umum:**
- "MTTR yang turun selalu berarti SOC makin baik." Angka bisa turun karena kasus sulit ditutup terlalu cepat, karena definisi diubah, atau karena kasus panjang dikeluarkan dari hitungan. Metrik yang dijadikan target cenderung dikejar dengan cara yang tidak diinginkan; baca angkanya bersama isi tiket dan jumlah insiden yang dibuka ulang.

### 1.14 Shift dan handover

Pertanyaan terakhir Dimas adalah pekerjaan terakhirmu malam ini. SOC PT JAB bekerja dalam tiga shift: pagi 07:00 sampai 15:00, sore 15:00 sampai 23:00, dan malam 23:00 sampai 07:00. Setiap delapan jam, semua yang sedang berjalan harus berpindah tangan tanpa ada yang jatuh.

**Apa itu:** shift adalah giliran jaga dalam operasi yang berjalan terus-menerus. Handover (serah terima) adalah pemindahan pekerjaan yang belum selesai, kondisi sistem, dan hal yang perlu diwaspadai dari tim yang selesai jaga ke tim berikutnya. Sebuah studi tahun 2026 yang mewawancarai praktisi tim tanggap insiden menemukan bahwa penunjuk yang jelas ke informasi (signposting), prosedur yang terus diperbarui, dan proses yang ringkas adalah hal yang paling dihargai, dan para praktisi meminta bagian khusus tentang gangguan atau masalah teknis dimasukkan ke dalam pedoman handover [S16].

**Analogi:** serah terima jaga satpam dengan buku laporan. Satpam yang pulang tidak cukup bilang "aman, Pak"; ia menunjuk buku: pintu gudang belum bisa dikunci karena gemboknya rusak, tukang datang besok pagi; ada tamu yang belum keluar; kamera parkir mati sejak jam dua. Batasnya: buku hanya berguna bila diisi lengkap dan dibaca. Serah terima lisan yang terburu-buru di menit terakhir paling sering kehilangan hal yang paling penting.

**Cara kerja:** catatan handover PT JAB mengikuti lima bagian tetap.

```
 1. RINGKASAN    : jumlah alert masuk, ditutup, dieskalasi, masih terbuka
 2. TERBUKA      : per tiket: apa yang sudah dicek, apa yang belum, pemilik berikutnya, batas waktu
 3. DIESKALASI   : tiket yang dipegang L2 atau terhubung ke insiden; apa yang harus dilakukan shift
                   berikutnya bila terjadi sesuatu
 4. KONDISI      : log source yang diam atau baru pulih, celah data, jendela perubahan (maintenance)
 5. PANTAU       : IP, akun, atau host yang perlu diawasi, dan pemicu untuk menelepon siapa
```

Bagian 4 sering dilupakan, padahal paling berbahaya bila hilang. Shift malam yang tidak tahu bahwa log Bandung sempat bolong akan percaya pada dashboard yang tampak bersih. Bagian 2 juga perlu menulis apa yang sudah disingkirkan ("IP ini tidak muncul di log VPN"), supaya shift berikutnya tidak mengulang pemeriksaan yang sama.

**Contoh di PT JAB:** catatan yang kamu terima dari Dwi pukul 14:50 ada di bagian 2.1, dan catatan yang kamu serahkan ke Gilang Ramadhan pukul 22:55 ada di bagian 2.4. Serah terima di PT JAB dilakukan tatap muka sepuluh menit sebelum pergantian, dengan catatan tertulis sebagai pegangan, dan L2 on-call shift berikutnya (malam ini Rudi Hartanto) ikut menerima bagian 3.

**Beda handover dengan tiket:** tiket menyimpan cerita satu kasus; handover menyimpan gambaran seluruh shift, termasuk hal yang tidak punya tiket (rencana perubahan, firasat tentang IP yang muncul berulang, alat yang lambat).

## 2. Contoh nyata

Semua contoh di bagian ini adalah keluaran ilustrasi dari organisasi fiktif PT JAB, bukan hasil eksekusi nyata. Nama host, alamat IP, akun, nomor, jam, dan angka dibuat untuk latihan. Format log disederhanakan supaya mudah dibaca.

### 2.1 Catatan serah terima dari shift pagi

Ini catatan yang diserahkan Dwi pukul 14:50 dan menjadi titik awal shift sore (pertanyaan 5 dan 11).

```
SERAH TERIMA SHIFT   Jumat 2027-08-13   pagi (07:00-15:00) ke sore (15:00-23:00)
Dari : Dwi Cahyono (L1)
Ke   : [kamu] (L1), Sari Kusuma (L2)

1. RINGKASAN
   27 alert masuk; 24 ditutup; 2 dieskalasi dan sudah ditutup L2; 1 terbuka.

2. TERBUKA
   SOC-2027-0853  P3  Log source diam: bdg-fw01 (firewall kantor Bandung)
     - Log terakhir 13:42:18. Rule data health (diam > 30 menit, cek tiap 5 menit) bunyi 14:15. Ack 14:19.
     - Dugaan: upgrade firmware bdg-fw01 di jendela perubahan CHG-2027-0412 (13:30-14:00).
       Tim Infrastruktur Bandung (lewat Agung Prabowo) sedang cek tujuan syslog.
     - Dampak: UC-021 dan UC-034 buta untuk 10.30.0.0/16 sejak 13:42.
     - Kompensasi sementara: alert Defender dari laptop Bandung dicek manual tiap jam (14:30 dan 14:45: tidak ada).
     - Belum: pastikan log kembali; minta ekspor log lokal bdg-fw01 untuk celah; jalankan ulang UC-021
       dan UC-034 untuk rentang celah.

3. DIESKALASI
   Tidak ada yang masih terbuka.

4. KONDISI
   - Semua log source lain normal per 14:45.
   - Jendela perubahan malam: CHG-2027-0415 patch jkt-proxy01, 19:00-21:00. Log proxy berhenti selama
     patch itu wajar; catat bila belum kembali setelah 21:15.

5. PANTAU
   Tidak ada.
```

**Cara membaca:** hitung dulu ringkasannya: 24 + 2 + 1 = 27, cocok. Bagian 2 menjawab tiga pertanyaan yang dibutuhkan penerima: apa yang terjadi (sumber diam sejak jam berapa), apa dampaknya (use case mana yang buta), dan apa yang belum dikerjakan. Angka di rule data health juga konsisten: pada pemeriksaan 14:10 sumber baru diam 27 menit 42 detik, belum lewat batas 30 menit; pada pemeriksaan 14:15 sudah 32 menit 42 detik, jadi alert muncul saat itu. Artinya, sebuah sumber bisa diam sampai sekitar 35 menit sebelum SOC tahu; itu harga dari batas 30 menit dan jadwal 5 menit.

**Yang terjadi sesudahnya:** log `bdg-fw01` kembali pukul 16:25 setelah tim Infrastruktur menemukan bahwa upgrade firmware mengembalikan tujuan syslog ke pengaturan bawaan, sehingga log dikirim ke alamat yang tidak ada. Celahnya sekitar 2 jam 43 menit (13:42 sampai 16:25). `bdg-fw01` menyimpan log lokal dalam jumlah terbatas, jadi tim Infrastruktur mengekspor log lokal untuk rentang celah dan SOC memasukkannya ke Splunk pukul 17:30. Pukul 17:45 kamu menjalankan ulang logika UC-021 dan UC-034 secara manual untuk 13:42 sampai 16:25: nol hasil. Baru pada titik ini "tidak ada temuan" berarti benar-benar tidak ada temuan, bukan tidak ada data. Tiket ditutup 17:50, dan tim Infrastruktur menambahkan "cek tujuan syslog" ke daftar langkah setiap upgrade firmware.

### 2.2 `SOC-2027-0854`: dari log mentah sampai insiden

Alert ini menjawab pertanyaan 4 dan memperlihatkan hampir semua istilah Day ini bekerja berurutan. Teguh Wibowo (`teguh.wibowo@jab.example`, Penjualan Korporat) sedang di kantor Jakarta dengan laptop `JKT-WS-1101` (`10.10.40.101`). Berikut cuplikan log mentah dari tiga sumber.

```
# jkt-vpn01 (waktu WIB, ISO 8601)
2027-08-13T15:31:07+07:00 jkt-vpn01 login=fail user=teguh.wibowo@jab.example src=192.0.2.171 reason=mfa-denied
  ... 5 baris serupa: 15:33:15, 15:35:40, 15:38:02, 15:40:26, 15:42:31
2027-08-13T15:44:50+07:00 jkt-vpn01 login=fail user=teguh.wibowo@jab.example src=192.0.2.171 reason=mfa-denied
2027-08-13T15:46:02+07:00 jkt-vpn01 login=success user=teguh.wibowo@jab.example src=192.0.2.171 mfa=push-approved assigned_ip=10.10.33.244 group=Penjualan

# jkt-radius01 (syslog, waktu UTC, tanpa tahun dan zona)
Aug 13 08:46:01 jkt-radius01 radiusd: Auth OK user="CORP\teguh.wibowo" client=jkt-vpn01 calling_station=192.0.2.171

# Entra ID, log login (JSON disederhanakan, waktu UTC)
{"createdDateTime":"2027-08-13T08:44:49Z","userPrincipalName":"Teguh.Wibowo@jab.example","ipAddress":"192.0.2.171","result":"MFA denied by user"}
```

**Parsing dan normalisasi:** setelah dibongkar menjadi field dan diseragamkan, empat baris terpenting terlihat seperti ini. Tabel ini dipakai untuk melihat bahwa ketiga sumber membicarakan orang, alamat, dan menit yang sama.

| `_time` (WIB) | Sumber | `user` | `src` | `action` | Keterangan |
|---|---|---|---|---|---|
| 15:44:49 | Entra ID | `teguh.wibowo` | `192.0.2.171` | failure | MFA ditolak user |
| 15:44:50 | `jkt-vpn01` | `teguh.wibowo` | `192.0.2.171` | failure | Login VPN gagal karena MFA ditolak |
| 15:46:01 | `jkt-radius01` | `teguh.wibowo` | `192.0.2.171` | success | Password benar |
| 15:46:02 | `jkt-vpn01` | `teguh.wibowo` | `192.0.2.171` | success | MFA disetujui, alamat `10.10.33.244` diberikan |

Tiga hal dinormalisasi: jam UTC ditambah 7 jam (08:44:49 menjadi 15:44:49, 08:46:01 menjadi 15:46:01), awalan `CORP\` dan akhiran `@jab.example` dibuang, dan huruf besar dijadikan huruf kecil. Tanpa itu, rule yang mengelompokkan per `user` akan melihat tiga orang berbeda.

**Correlation rule UC-017:** ada 7 kegagalan MFA dari 15:31:07 sampai 15:44:50, rentang 13 menit 43 detik, jadi syarat "minimal 5 dalam 15 menit" terpenuhi. Login berhasil datang 15:46:02, 1 menit 12 detik setelah kegagalan terakhir, jadi syarat "berhasil dalam 10 menit" juga terpenuhi. Rule berjalan tiap 5 menit, dan putaran pukul 15:48 menangkap urutan ini. Alert P2 muncul pukul 15:48:10.

**Enrichment otomatis (15:48:12):** IP `192.0.2.171` milik penyedia hosting di luar negeri dan tidak pernah dipakai akun PT JAB mana pun dalam 90 hari; Teguh berlokasi di Jakarta; laptop Teguh `JKT-WS-1101` aktif di jaringan kantor sejak 08:05 menurut log proxy. Korelasi sederhana ini sudah sangat kuat: orangnya duduk di kantor, tetapi akunnya login VPN dari luar negeri.

**Jejak tiket:** tabel berikut adalah catatan kerja tiket `SOC-2027-0854`; perhatikan bahwa setiap baris punya jam dan pelaku, karena dari sinilah metrik dihitung.

| Waktu | Pelaku | Catatan | Status |
|---|---|---|---|
| 15:48:10 | Splunk | Alert UC-017 dibuat, P2 | New |
| 15:48:12 | Otomasi | Enrichment ditambahkan | New |
| 15:52:40 | Kamu (L1) | Diambil; mulai PB-04 langkah 1 | In progress |
| 15:58:00 | Kamu | Telepon Teguh di ext. kantor: ia menerima banyak notifikasi saat rapat dan menekan "setujui" supaya berhenti; ia tidak login VPN | In progress |
| 16:01:00 | Kamu | Eskalasi ke Yoga (L2 yang bertugas sore ini; Sari sedang mendampingimu) sesuai PB-04 langkah 2 | Escalated |
| 16:09:30 | Yoga (L2) | Sesi VPN `10.10.33.244` diputus (RB-11) | Escalated |
| 16:11:10 | Yoga | Akun dinonaktifkan sementara di AD dan Entra ID, sesi cloud dicabut (RB-12) | Escalated |
| 16:20:00 | Yoga | Selama sesi 15:46:02 sampai 16:09:30, akun membuka intranet dan membaca 12 file di `\\JKT-FS01\Penjualan`. Insiden `INC-2027-089` (SEV-3) dibuka | Escalated |
| 16:40:00 | Yoga | Password direset bersama Teguh; Teguh diingatkan tidak menyetujui MFA yang tidak ia minta | Escalated |

**Cara membaca:** sesi penyerang berlangsung 23 menit 28 detik (15:46:02 sampai 16:09:30). Waktu ack 4 menit 30 detik memenuhi SLA P2 30 menit. Eskalasi terjadi 8 menit 20 detik setelah ack (15:52:40 sampai 16:01:00), di dalam batas 30 menit PB-04. Waktu dari alert sampai tertahan adalah 23 menit (15:48:10 sampai 16:11:10). Pertanyaan "dari mana penyerang tahu password Teguh" belum terjawab dan menjadi bagian investigasi insiden.

### 2.3 Dashboard metrik Juli 2027

Ini dashboard yang dibawa Dimas pukul 18:30 (pertanyaan 10). Bagian pertama adalah volume dan kepatuhan SLA acknowledge per prioritas.

```
DASHBOARD SOC PT JAB   Juli 2027

Alert masuk        : 1.284   (P1: 3   P2: 41   P3: 318   P4: 922)
SLA acknowledge    : P1  3 / 3     = 100%     (batas 15 menit)
                     P2  38 / 41   = 92,7%    (batas 30 menit)
                     P3  309 / 318 = 97,2%    (batas 4 jam)
                     P4  915 / 922 = 99,2%    (batas 24 jam)
Insiden dibuka     : 4   (A, B, C, D)
```

Hitung ulang: 3 + 41 + 318 + 922 = 1.284. 38 / 41 = 0,927; 309 / 318 = 0,972; 915 / 922 = 0,992. Bagian kedua adalah jejak waktu keempat insiden, tempat MTTD, MTTA, dan MTTR dihitung. Kolom menit dihitung dari kolom jam di sebelah kirinya.

| Insiden | Aktivitas berbahaya pertama | Alert (deteksi) | Ack | Tertahan | Ditutup | Deteksi (menit) | Ack (menit) | Respond (menit) | Resolve (menit) |
|---|---|---|---|---|---|---|---|---|---|
| A, tautan phishing diklik | 07-03 09:10 | 07-03 09:40 | 09:45 | 10:40 | 07-04 15:40 | 30 | 5 | 60 | 1.800 |
| B, login RDP ke server uji | 07-09 22:00 | 07-10 06:00 | 06:12 | 08:00 | 07-12 06:00 | 480 | 12 | 120 | 2.880 |
| C, malware di laptop | 07-17 14:00 | 07-17 14:20 | 14:23 | 15:10 | 07-17 20:20 | 20 | 3 | 50 | 360 |
| D, akun layanan dipakai dari luar | 07-25 01:00 | 07-25 03:10 | 03:30 | 05:40 | 07-27 03:10 | 130 | 20 | 150 | 2.880 |
| Jumlah | | | | | | 660 | 40 | 380 | 7.920 |

```
MTTD           = 660 / 4   = 165 menit   = 2 jam 45 menit
MTTA           = 40 / 4    = 10 menit
MTTR (respond) = 380 / 4   = 95 menit    = 1 jam 35 menit
MTTR (resolve) = 7.920 / 4 = 1.980 menit = 33 jam

Median waktu deteksi: urutkan 20, 30, 130, 480 -> nilai tengah (30 + 130) / 2 = 80 menit
```

**Cara membaca:**

- **Satu kasus menarik rata-rata.** MTTD 2 jam 45 menit terlihat buruk, tetapi mediannya 1 jam 20 menit. Penyebabnya insiden B: login dimulai pukul 22:00, tetapi agen pengirim log server uji itu berhenti malam itu dan baru pulih pukul 06:00. Begitu log masuk, rule langsung menemukan login dari 22:00. Masalahnya bukan rule yang lambat, melainkan log source yang diam, kasus yang sama dengan `bdg-fw01` sore ini.
- **Dua MTTR, dua cerita.** MTTR (respond) 1 jam 35 menit menunjukkan seberapa cepat SOC menahan ancaman. MTTR (resolve) 33 jam memuat pemulihan dan penutupan, yang melibatkan tim lain dan sering menunggu hari kerja. Keduanya benar; yang salah adalah membandingkannya tanpa menyebut versinya.
- **Klaim vendor.** "MTTR 15 menit" dari vendor dihitung dari alert sampai tindakan otomatis pertama. Dengan definisi itu, angka PT JAB lebih mirip MTTA (10 menit). Pertanyaan yang tepat untuk vendor: R-nya apa, jam awal dan akhirnya kejadian apa, dan kasus mana yang dihitung.
- **Tiga P2 yang melanggar SLA.** Dari 41 tiket P2, 3 tidak diambil dalam 30 menit. Dimas meminta daftar ketiganya untuk melihat apakah polanya sama (misalnya semua terjadi saat serah terima shift).

### 2.4 Catatan serah terima ke shift malam

Ini catatan yang kamu tulis dan serahkan ke Gilang Ramadhan pukul 22:55 (pertanyaan 11). Bandingkan bentuknya dengan catatan Dwi di bagian 2.1.

```
SERAH TERIMA SHIFT   Jumat 2027-08-13   sore (15:00-23:00) ke malam (23:00-07:00)
Dari : [kamu] (L1), Sari Kusuma (L2)
Ke   : Gilang Ramadhan (L1), Rudi Hartanto (L2 on-call)

1. RINGKASAN
   31 alert masuk shift sore; 29 ditutup; 1 dieskalasi (terhubung insiden); 1 terbuka.
   Warisan shift pagi SOC-2027-0853 ditutup 17:50.

2. TERBUKA
   SOC-2027-0857  P3  jkt-waf01 memblokir 37 permintaan SQL injection dari 192.0.2.176
                      ke portal.jab.example (22:38-22:41). Ack 22:47 (kamu).
     - Sudah: semua 37 dijawab 403 oleh WAF. 192.0.2.176 tidak muncul di log jkt-vpn01,
       jkt-fw01, atau Entra ID (dicek 22:45-22:55).
     - Belum: cek log aplikasi jkt-portal01 22:30-23:00 untuk respons selain 403 dari IP itu.
     - Pemilik berikutnya: Gilang. Target selesai sebelum 03:00.

3. DIESKALASI
   SOC-2027-0854 / INC-2027-089 (SEV-3)  MFA fatigue VPN, akun teguh.wibowo
     - Sesi diputus 16:09:30, akun dinonaktifkan 16:11:10, password direset 16:40. Pemilik: Yoga (L2).
     - Shift malam: bila akun teguh.wibowo login dari mana pun selain kantor Jakarta,
       atau 192.0.2.171 muncul di log apa pun, telepon Rudi lalu Yoga.

4. KONDISI
   - bdg-fw01: log kembali 16:25; celah 13:42-16:25 diisi dari ekspor log lokal 17:30;
     UC-021 dan UC-034 dijalankan ulang manual 17:45 untuk celah, 0 hasil.
   - Patch jkt-proxy01 (CHG-2027-0415) selesai 20:10; log proxy normal sejak 20:12.
   - Semua log source utama mengirim data per 22:50. Tidak ada jendela perubahan malam ini.

5. PANTAU
   - 192.0.2.171 dan 192.0.2.176 sudah masuk watchlist Splunk (daftar pantau: alert bila muncul di log mana pun).
   - Alert ditutup yang bisa ditanyakan: SOC-2027-0855 (unduhan Ratna, sah, dikonfirmasi atasan 17:40),
     SOC-2027-0856 (PUA di JKT-WS-1107, diblokir Defender, ditutup 19:36).
```

**Cara membaca:** ringkasan konsisten (29 + 1 + 1 = 31). Bagian 2 menulis yang sudah disingkirkan, sehingga Gilang tidak mengulang pemeriksaan VPN dan firewall. Bagian 3 tidak meminta Gilang mengerjakan insiden, tetapi memberinya pemicu yang jelas: kejadian apa yang membuatnya harus menelepon siapa. Bagian 4 memberi tahu bahwa data Bandung sore ini sempat bolong dan sudah diperiksa, sehingga Gilang tidak perlu menebak. Catatan ini juga memuat bagian khusus tentang gangguan teknis, hal yang menurut studi handover paling sering diminta praktisi [S16].

## 3. Perbandingan istilah yang sering tertukar

### 3.1 Log management, SIEM, UEBA, SOAR, dan XDR

Lima istilah ini sering muncul di satu presentasi vendor. Tabel berikut membedakannya dengan satu pertanyaan kunci; cari kolom "Tidak melakukan" untuk menghindari salah paham yang paling sering.

| Istilah | Pertanyaan kunci | Melakukan | Tidak melakukan |
|---|---|---|---|
| Log management (server syslog) | Di mana log disimpan? | Mengumpulkan, menyimpan, memutar, mengarsipkan log | Menyeragamkan dan mengorelasikan isi |
| SIEM | Apa yang terjadi di seluruh lingkungan? | Mengumpulkan, normalisasi, korelasi, alert, pencarian investigasi | Bertindak sendiri terhadap ancaman |
| UEBA | Apakah ini normal untuk user atau entitas ini? | Membangun baseline, memberi skor penyimpangan | Menyatakan seseorang bersalah |
| SOAR | Apa yang bisa dikerjakan otomatis? | Menyambungkan alat, enrichment, menjalankan langkah respons | Memperbaiki alert yang salah; ia mengulang kesalahan dengan cepat |
| XDR (Day 06) | Apa cerita lengkap di produk keamanan yang saling kenal? | Korelasi siap pakai lintas endpoint, email, identitas, dan respons lintas produk | Membaca log dari sumber yang tidak tersambung atau tidak berlisensi |

### 3.2 Correlation rule, use case, playbook, dan runbook

Empat istilah ini adalah lapisan berbeda dari satu alur yang sama. Tabel berikut memakai UC-017 sebagai contoh; baca dari atas ke bawah untuk melihat urutannya.

| Istilah | Menjawab | Contoh di PT JAB | Berubah bila |
|---|---|---|---|
| Use case | Ancaman apa yang ingin dideteksi dan kenapa, dengan data apa, ditangani bagaimana? | UC-017 MFA fatigue di VPN | Ancaman atau aset berubah |
| Correlation rule | Pola apa di log yang memicu alert? | Minimal 5 MFA ditolak dalam 15 menit, lalu login berhasil dalam 10 menit | Format log atau pola serangan berubah |
| Playbook | Jenis kejadian ini ditangani bagaimana, oleh siapa, kapan eskalasi? | PB-04 Akun dicurigai diambil alih | Struktur tim atau kebijakan berubah |
| Runbook | Di alat ini, langkah teknisnya apa? | RB-11 Memutus sesi VPN di `jkt-vpn01` | Alat atau versinya berganti |

### 3.3 MTTD, MTTA, MTTR, dan SLA

Keempatnya sering ditulis berdampingan di dashboard. Tabel berikut menunjukkan titik awal dan akhir masing-masing; cari kolom "Jebakan" sebelum membandingkan angka antar organisasi.

| Istilah | Mulai | Selesai | Satuan | Jebakan |
|---|---|---|---|---|
| MTTD | Aktivitas berbahaya pertama (bila diketahui) | Alert atau kejadian dikenali | Rata-rata banyak kasus | Titik awal sering baru diketahui belakangan; satu kasus lambat menarik rata-rata |
| MTTA | Alert muncul | Mulai ditangani | Rata-rata banyak kasus | Bisa dipercepat dengan "mengambil" tiket tanpa mengerjakannya |
| MTTR | Deteksi (umumnya) | Tertahan (respond), pulih (recover), atau ditutup (resolve) | Rata-rata banyak kasus | Huruf R tidak seragam; selalu tanyakan versinya |
| SLA | Ditentukan kesepakatan (biasanya alert muncul) | Ditentukan kesepakatan (biasanya mulai ditangani atau eskalasi) | Batas per kasus, dirangkum sebagai persentase kepatuhan | Terpenuhi tidak berarti penanganannya benar |

## 4. Salah paham umum

- **Anggapan:** dashboard SIEM yang hijau dan antrean yang kosong berarti lingkungan aman. **Kenyataannya:** antrean kosong bisa berarti tidak ada serangan, atau berarti log source diam, parsing rusak, atau rule tidak cocok lagi dengan format log. NIST menempatkan pemantauan status logging setiap sumber sebagai tugas rutin [S1]. Pada `SOC-2027-0853`, dua use case buta selama hampir tiga jam tanpa satu error pun (bagian 1.5 dan 2.1).
- **Anggapan:** semakin banyak otomasi, semakin aman. **Kenyataannya:** otomasi mempercepat apa pun yang diberikan kepadanya, termasuk kesalahan. Panduan CISA dan mitranya meminta SOAR hanya bertindak pada insiden nyata, bukan aktivitas normal [S6]; karena itu PT JAB memulai dari enrichment dan menahan tindakan berdampak di persetujuan manusia (bagian 1.8).
- **Anggapan:** L1 hanya meneruskan alert ke L2. **Kenyataannya:** L1 menutup sebagian besar alert sendiri dan menentukan kualitas eskalasi. Pada `SOC-2027-0854`, telepon L1 ke Teguh yang mengubah dugaan menjadi kepastian, dan catatan L1 yang membuat Yoga bisa menahan akun 10 menit setelah menerima eskalasi (bagian 1.10 dan 2.2).
- **Anggapan:** metrik yang bagus membuktikan SOC yang bagus. **Kenyataannya:** angka bergantung pada definisi dan bisa dikejar dengan cara yang salah. MTTR 15 menit vendor dan MTTR 33 jam PT JAB mengukur hal yang berbeda, dan MTTD PT JAB terlihat buruk karena satu log source yang diam, bukan karena rule yang lambat (bagian 1.13 dan 2.3).
- **Anggapan:** serah terima cukup dengan "aman, tidak ada apa-apa". **Kenyataannya:** yang paling berbahaya untuk dilupakan justru hal yang tidak punya alert: log yang sempat bolong, jendela perubahan, dan pemicu untuk menelepon L2. Catatan tertulis dengan bagian tetap mengurangi risiko itu (bagian 1.14 dan 2.4).

## 5. Catatan terkini

Bagian ini mencatat versi dokumen acuan, tanggal terbit, dan perubahan istilah yang perlu diketahui saat membaca sumber lain.

- NIST SP 800-92 "Guide to Computer Security Log Management" terbit September 2006 dan masih berstatus final [S1]. Revisinya, SP 800-92 Rev. 1 "Cybersecurity Log Management Planning Guide", terbit sebagai initial public draft pada 11 Oktober 2023 dengan masa komentar sampai 29 November 2023; per 2026-10-21 halaman CSRC masih menampilkannya sebagai draf [S2]. Definisi teknis di Day ini memakai versi 2006 karena itu versi final; cek status Rev. 1 sebelum mengutipnya di dokumen formal.
- NIST SP 800-61 Revision 3 terbit April 2025, menggantikan Revision 2 (2012). Isinya ditulis ulang total dan disusun sebagai CSF 2.0 Community Profile, dengan fokus pada penyatuan respons insiden ke dalam manajemen risiko [S4]. Rekomendasi tentang SIEM, SOAR, korelasi, tiket otomatis, dan playbook di Day ini berasal dari versi ini.
- CISA bersama ASD's ACSC dan mitra internasional menerbitkan tiga dokumen "Implementing SIEM and SOAR Platforms" pada 27 Mei 2025: Executive Guidance, Practitioner Guidance, dan Priority Logs for SIEM Ingestion [S5]. Dokumen terakhir berisi daftar log source yang diprioritaskan, antara lain EDR, sistem Windows dan Linux, perangkat jaringan, dan cloud [S6].
- Splunk Enterprise Security 8 memakai istilah detection untuk correlation search atau risk rule terjadwal, dengan dua jenis: event-based detection yang membaca event mentah dan finding-based detection yang mengelompokkan finding menjadi finding group; intermediate finding tidak tampil di analyst queue [S7]. Dokumentasi dan banyak tulisan lama memakai istilah correlation search dan notable event; keduanya perlu dikenali.
- Dokumentasi Splunk CIM yang dipakai di Day ini adalah versi 5.2 [S8]. Nama data model dan field bisa bertambah antar versi; cek referensi versi-mu.
- Halaman UEBA Microsoft Sentinel yang dipakai di Day ini diperbarui 17 Juli 2026 dan menyebut UEBA termasuk dalam Sentinel tanpa biaya tambahan, dengan data disimpan di tabel Log Analytics [S9]. Fitur dan nama tabel UEBA berubah cukup sering; cek halaman terbarunya.
- Studi "Passing the Baton" tentang serah terima shift di tim tanggap insiden terbit di arXiv pada 12 Januari 2026 sebagai preprint, dengan enam narasumber praktisi [S16]. Temuannya berguna sebagai gambaran praktik, tetapi sampelnya kecil dan belum melalui peer review.

## 6. Cheat sheet

```
SOC                : tim + proses + teknologi untuk memantau, mendeteksi, dan menangani kejadian keamanan
NOC                : tim yang menjaga jaringan tetap hidup dan cepat (availability, performa)
Log / log entry    : catatan kejadian / satu baris catatan untuk satu kejadian
Log source         : perangkat atau aplikasi penghasil log; pantau juga kapan ia DIAM
Log management     : hasilkan, kirim, simpan, akses, buang log
SIEM               : kumpulkan log banyak sumber, parsing, normalisasi, korelasi, alert, pencarian
Parsing            : bongkar baris log menjadi field bernama
Normalisasi        : seragamkan nama field, waktu (satu zona, NTP), dan nilai antar sumber
Correlation rule   : aturan terjadwal yang mencocokkan beberapa kejadian lalu memunculkan alert
                     (ES 8: detection; lama: correlation search)
Use case           : paket lengkap satu skenario: alasan, log source, normalisasi, rule, playbook, pemilik, uji
UEBA               : baseline perilaku user/entitas; anomali = tidak biasa, bukan pasti jahat
SOAR               : sambungkan alat + otomasi langkah respons; mulai dari enrichment, tindakan berdampak
                     butuh persetujuan
Enrichment         : tambahkan konteks ke alert (pemilik, reputasi IP, riwayat)
Playbook           : prosedur per jenis kejadian (apa, siapa, kapan eskalasi)
Runbook            : langkah teknis per tindakan di satu alat
L1 / L2 / L3       : triage dan runbook / investigasi dan penahanan / hunting, forensik, deteksi
Ticketing          : nomor, prioritas, status, pemilik, jejak waktu; sumber semua metrik
SLA                : janji per kasus (mis. P2 diambil dalam 30 menit); dirangkum sebagai % kepatuhan
MTTD               : rata-rata aktivitas berbahaya pertama -> terdeteksi
MTTA               : rata-rata alert -> mulai ditangani
MTTR               : respond / recover / resolve / repair; SELALU tanyakan versinya
Rata-rata vs median: satu kasus lambat menarik rata-rata; tampilkan keduanya
Shift / handover   : giliran jaga / serah terima: ringkasan, terbuka, dieskalasi, kondisi, pantau
```

## 7. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Dari 13:42 sampai 16:25 tidak ada satu pun alert dari jaringan Bandung, dan semua rule berjalan tanpa error. Jadi jaringan Bandung aman selama itu." Benarkah?

<details><summary>Jawaban</summary>

Tidak bisa disimpulkan begitu. Selama rentang itu `bdg-fw01` tidak mengirim log, sehingga rule UC-021 dan UC-034 membaca data kosong dan selesai dengan hasil nol. SIEM tidak bisa membedakan "tidak ada serangan" dari "tidak ada data". Kesimpulan "tidak ada temuan" baru sah setelah log celah dimasukkan dari ekspor lokal dan logika kedua use case dijalankan ulang untuk rentang itu, seperti yang dilakukan pukul 17:45. Lihat bagian 1.2, 1.5, dan 2.1.

</details>

**2. Skenario keputusan.** Sebuah vendor MDR mengklaim "MTTR kami 15 menit", sedangkan dashboard PT JAB menunjukkan MTTR (resolve) 33 jam. Hendra Wijaya (Direktur Teknologi) bertanya apakah SOC PT JAB jauh tertinggal. Apa jawaban yang paling tepat?

- A. Ya, PT JAB jauh tertinggal dan perlu memakai vendor itu.
- B. Belum bisa dibandingkan: tanyakan dulu huruf R yang dipakai vendor, kejadian apa yang menjadi jam awal dan akhir, dan kasus mana yang dihitung; dengan definisi vendor (alert sampai tindakan otomatis pertama), angka PT JAB lebih dekat ke MTTA 10 menit.
- C. Tidak, karena MTTR PT JAB dihitung dari empat insiden saja sehingga tidak berarti apa-apa.

<details><summary>Jawaban</summary>

B. Singkatan MTTR dipakai untuk respond, recover, resolve, dan repair, dan titik awal serta akhirnya berbeda antar organisasi, jadi angka hanya bisa dibandingkan setelah definisinya disamakan. MTTR (resolve) PT JAB memuat pemulihan dan penutupan yang melibatkan tim lain, sedangkan angka vendor berhenti di tindakan otomatis pertama. A keliru karena membandingkan dua ukuran yang berbeda. C keliru karena jumlah kasus yang sedikit memang membuat rata-rata rapuh (karena itu median juga ditampilkan), tetapi itu tidak membuat angkanya tidak berarti. Lihat bagian 1.13 dan 2.3.

</details>

**3. Pertanyaan jebakan.** "Log RADIUS sudah masuk Splunk sejak tahun lalu, jadi rule login gagal berulang pasti sudah menghitung kegagalan dari `jkt-radius01`." Benarkah?

<details><summary>Jawaban</summary>

Belum tentu. Log yang sudah masuk belum tentu bisa dipakai rule. Di PT JAB, log RADIUS menulis user dengan awalan `CORP\` dan jam UTC, sedangkan rule mengelompokkan per user tanpa awalan dalam WIB. Sebelum normalisasi diterapkan, rule tidak pernah cocok dengan log RADIUS, dan tidak ada error yang memberi tahu. Lihat bagian 1.4 dan 2.2.

</details>

**4. Skenario keputusan.** Dalam pilot SOAR, Dimas harus memilih otomasi pertama untuk UC-017 (MFA fatigue di VPN). Mana yang paling tepat?

- A. Otomatis menonaktifkan akun dan memblokir IP asal setiap kali UC-017 berbunyi, tanpa menunggu analyst.
- B. Otomatis melakukan enrichment dan membuat tiket, lalu menyiapkan tombol "putus sesi dan nonaktifkan akun" yang dijalankan setelah L2 menyetujui.
- C. Tidak mengotomatiskan apa pun sampai semua rule PT JAB tidak pernah salah bunyi.

<details><summary>Jawaban</summary>

B. Enrichment dan pembuatan tiket tidak mengubah apa pun sehingga aman diotomatiskan, sedangkan penahanan berdampak langsung pada karyawan, jadi tetap menunggu persetujuan manusia sampai rule terbukti stabil. A keliru karena otomasi mengulang kesalahan dengan cepat: setiap kali rule salah bunyi, karyawan sah kehilangan akses, dan panduan CISA dan mitranya meminta SOAR hanya bertindak pada insiden nyata. C keliru karena menunggu rule sempurna berarti tidak pernah mulai; otomasi aman seperti enrichment sudah memberi manfaat sekarang. Lihat bagian 1.8.

</details>

**5. Jelaskan ulang.** Jelaskan kepada anggota keluargamu yang bukan orang IT, dalam tiga kalimat, apa yang kamu kerjakan di shift sore SOC dan kenapa catatan serah terima di akhir shift itu penting.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Aku jaga di ruang pemantauan keamanan kantor, mirip satpam di ruang CCTV: komputer mengumpulkan catatan dari semua alat dan memberi tanda bila ada yang mencurigakan, lalu aku memeriksa tanda-tanda itu satu per satu. Karena kantornya dijaga 24 jam bergantian, di akhir giliranku aku menulis buku laporan untuk teman yang jaga malam: kasus mana yang belum selesai, alat mana yang sempat mati, dan kapan dia harus menelepon atasan. Tanpa catatan itu, teman berikutnya bisa mengira semuanya aman padahal ada kamera yang tadi sempat mati atau kasus yang masih menggantung."

Kesalahan yang sering muncul:
- Memakai istilah seperti SIEM, alert, atau eskalasi tanpa penjelasan.
- Menggambarkan serah terima sebagai formalitas "semua aman", tanpa menyebut hal yang belum selesai dan alat yang sempat mati.
- Mengira pekerjaan SOC hanya menunggu alarm, padahal sebagian penting justru memastikan alat pemantaunya sendiri masih bekerja.

</details>

**6. Pertanyaan jebakan.** "Alert `SOC-2027-0855` dari analitik perilaku menunjukkan Ratna mengunduh lebih dari 35 kali kebiasaannya, jadi Ratna hampir pasti sedang mencuri data." Benarkah?

<details><summary>Jawaban</summary>

Tidak. UEBA dan analitik berbasis baseline hanya mengatakan perilakunya tidak biasa untuk orang itu dan kelompoknya; anomali berarti tidak biasa, bukan jahat. Keputusan butuh konteks yang tidak dimiliki mesin. Pada kasus ini atasan Ratna mengonfirmasi bahwa unduhan itu persiapan arsip untuk auditor eksternal, sehingga tiket ditutup sebagai aktivitas sah dengan catatan. Lihat bagian 1.7.

</details>

**7. Interview question (English).** "What is the difference between a SIEM and a SOAR, and how do they work together in a SOC?"

<details><summary>Sample answer</summary>

"A SIEM is where visibility comes from. It collects logs from many sources such as firewalls, VPN, domain controllers, EDR and cloud, parses and normalizes them so the same user or IP looks the same everywhere, correlates events across sources, and raises alerts. A SOAR is where action gets faster. It takes those alerts, connects the tools through their APIs, and runs workflows: enrichment such as IP reputation and asset owner, ticket creation, and containment steps like disabling an account or ending a VPN session. They depend on each other in one direction: a SOAR is only as good as the alerts it receives, so if detections are noisy, automation just repeats the mistakes faster. In practice I would automate the safe parts first, enrichment and ticketing, and keep impactful actions behind an analyst approval until the detection has proven reliable. And I would watch the SIEM side for silent failures, like a log source that stops sending, because neither tool will tell you about data that never arrives unless you monitor for it."

What makes this answer strong: it defines each tool by the job it does rather than by the acronym, explains the dependency between them, shows judgment about what to automate first, and ends with a practical operational risk (silent log sources) that shows real SOC experience.

</details>

## 8. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | NIST SP 800-92: Guide to Computer Security Log Management | https://csrc.nist.gov/pubs/sp/800/92/final<br>https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-92.pdf | primer | 2006-09; diakses 2026-10-21 | Tinggi. Definisi log, log source, parsing, normalisasi, filtering, aggregation, event correlation, SIEM agent/agentless, sinkronisasi waktu, pemantauan status logging. Dokumen lama, tetapi masih versi final |
| S2 | NIST SP 800-92 Rev. 1 (Initial Public Draft): Cybersecurity Log Management Planning Guide | https://csrc.nist.gov/pubs/sp/800/92/r1/ipd | primer (draf) | 2023-10-11; diakses 2026-10-21 | Sedang sampai tinggi. Masih draf; dipakai untuk definisi log management yang diperbarui dan catatan versi |
| S3 | NIST CSRC Glossary: SIEM, SOAR, Security Operations Center, service level agreement | https://csrc.nist.gov/glossary/term/security_information_and_event_management<br>https://csrc.nist.gov/glossary/term/security_orchestration_automation_and_response<br>https://csrc.nist.gov/glossary/term/security_operations_center<br>https://csrc.nist.gov/glossary/term/service_level_agreement | primer (glosarium NIST) | diakses 2026-10-21 | Tinggi. Entri SIEM dari SP 800-92; entri SOAR dan SOC hanya memuat singkatan dan daftar publikasi; SLA dari CNSSI 4009-2022, SP 800-152, SP 800-47 Rev. 1 |
| S4 | NIST SP 800-61r3: Incident Response Recommendations and Considerations for Cybersecurity Risk Management | https://doi.org/10.6028/NIST.SP.800-61r3<br>https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf | primer | 2025-04; diakses 2026-10-21 | Tinggi. Definisi event, SOC dialihdayakan ke MSSP, playbook, rekomendasi SIEM/SOAR (DE.AE-02, DE.AE-03), tiket otomatis (DE.AE-06), prioritas berbasis risiko (RS.MA) |
| S5 | CISA: Guidance for SIEM and SOAR Implementation | https://www.cisa.gov/resources-tools/resources/guidance-siem-and-soar-implementation | primer | 2025-05-27; diakses 2026-10-21 | Tinggi untuk tanggal, penerbit, dan susunan tiga dokumen. Isi lengkap dokumen di situs ASD ACSC tidak dapat dibuka saat riset |
| S6 | Infosecurity Magazine: Governments Urge Organizations to Prioritize SIEM/SOAR Adoption | https://www.infosecurity-magazine.com/news/governments-prioritize-siem-soar/ | sekunder (berita) | 2025-05; diakses 2026-10-21 | Sedang. Ringkasan isi panduan CISA, NSA, dan ASD ACSC: fungsi SIEM dan SOAR, kebutuhan personel, biaya ingest, SOAR hanya bertindak pada insiden nyata |
| S7 | Splunk: Use detections to search for threats in Splunk Enterprise Security (ES 8.0) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.0/detections/use-detections-to-search-for-threats-in-splunk-enterprise-security | primer (dokumentasi vendor) | diakses 2026-10-21 | Tinggi untuk istilah ES 8: detection, event-based dan finding-based, finding, intermediate finding, analyst queue |
| S8 | Splunk: Overview of the Splunk Common Information Model (CIM 5.2) | https://help.splunk.com/en/splunk-enterprise/common-information-model/5.2/introduction | primer (dokumentasi vendor) | diakses 2026-10-21 | Tinggi. Normalisasi saat pencarian dengan nama field dan tag bersama, data mentah tetap utuh |
| S9 | Microsoft Learn: Advanced threat detection with User and Entity Behavior Analytics (UEBA) in Microsoft Sentinel | https://learn.microsoft.com/en-us/azure/sentinel/identify-threats-with-entity-behavior-analytics | primer (dokumentasi vendor) | diperbarui 2026-07-17; diakses 2026-10-21 | Tinggi untuk cara kerja UEBA di Sentinel: baseline dari riwayat sendiri, peer group, dan organisasi; skor risiko |
| S10 | Splunk Blog: NOCs vs. SOCs: Network and Security Operations Centers Compared | https://www.splunk.com/en_us/blog/learn/noc-vs-soc.html | sekunder (blog vendor) | 2024-10-28; diakses 2026-10-21 | Sedang. Perbedaan fokus NOC dan SOC dan area yang tumpang tindih |
| S11 | ISACA Journal: A Framework for SIEM Implementation (Grant Hughes) | https://www.isaca.org/resources/isaca-journal/issues/2023/volume-3/a-framework-for-siem-implementation | sekunder (jurnal profesi) | 2023-05-17; diakses 2026-10-21 | Sedang sampai tinggi. Use case sebagai penentu nilai SIEM, purpose-driven logging, normalisasi nama field |
| S12 | TechTarget: Compare runbooks vs. playbooks for IT process documentation (Stephen J. Bigelow) | https://www.techtarget.com/it-infrastructure/tip/Compare-runbooks-vs-playbooks-for-IT-process-documentation | sekunder | 2020-10-12; diakses 2026-10-21 | Sedang. Isi khas runbook dan catatan bahwa perbedaan istilah sebagian besar soal kebiasaan |
| S13 | Corelight Glossary: MTTR (mean time to respond, recover, resolve) | https://corelight.com/resources/glossary/mttr-mean-time-to-respond-recover-resolve | sekunder (glosarium vendor) | diakses 2026-10-21 | Sedang. Titik awal dan akhir tiap versi MTTR; hubungan MTTD dan MTTR |
| S14 | FireHydrant: What is MTTR? Incident metrics explained (MTBF, MTTF, MTTA) | https://firehydrant.com/blog/mttr/ | sekunder (blog vendor) | diakses 2026-10-21 | Sedang. Definisi MTTA dan empat arti huruf R. Satu contoh hitungan di artikel itu tidak konsisten, jadi hanya definisinya yang dipakai |
| S15 | Wiz Academy: Tier 1 SOC analysts, responsibilities and career path | https://www.wiz.io/academy/cloud-careers/soc-analyst-tier-1 | sekunder (materi vendor) | tanpa tanggal; diakses 2026-10-21 | Sedang. Gambaran umum pekerjaan tier 1, 2, dan 3 dan eskalasi |
| S16 | Kent, Tuptuk, Becker: Passing the Baton: Shift Handovers within Cybersecurity Incident Response Teams (arXiv:2601.07788v1) | https://arxiv.org/abs/2601.07788v1 | sekunder (preprint penelitian) | 2026-01-12; diakses 2026-10-21 | Sedang. Studi eksploratif dengan enam narasumber; belum peer review |

**Catatan sumber:** definisi SOAR di bagian 1.8 tidak berasal dari teks definisi NIST, karena entri glosarium NIST untuk SOAR dan SOC hanya memuat singkatan [S3]; isinya disusun dari rekomendasi SP 800-61r3 [S4] dan ringkasan berita tentang panduan CISA, NSA, dan ASD ACSC [S6], karena teks lengkap dokumen panduan di situs ASD ACSC tidak dapat dibuka saat riset. Cek ulang kutipan tentang SOAR di Executive Guidance dan Practitioner Guidance bila hendak dikutip di dokumen formal. Definisi use case di bagian 1.6 dan pembagian tier di bagian 1.10 bersumber sekunder [S11][S15]; tidak ada definisi baku dari badan standar untuk keduanya, dan isi kartu use case adalah susunan catatan ini. Pembedaan playbook dan runbook mengikuti konvensi PT JAB yang ditulis di catatan ini; sumber lain memakainya bergantian [S12]. Definisi MTTD, MTTA, dan MTTR bersumber dari glosarium dan blog vendor [S13][S14] karena tidak ada definisi baku lintas organisasi. Seluruh isi PT JAB (alert `SOC-2027-0853` sampai `0857`, insiden `INC-2027-089`, use case, playbook, runbook, SLA, jadwal shift, dan dashboard Juli) adalah contoh fiktif.
