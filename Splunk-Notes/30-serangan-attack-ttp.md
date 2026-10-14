---
day: 30
title: Jenis serangan, attack vector, dan glosarium istilah ancaman
researched_on: 2026-10-07
versions_checked: MITRE ATT&CK v19 (Enterprise, 15 taktik; v19 rilis 28 Apr 2026; v19.2 Agu 2026); NIST CSRC Glossary (APT dari SP 800-39; zero trust dari SP 800-207); Verizon DBIR 2026 (19 Mei 2026); FBI IC3 Internet Crime Report 2025 (via liputan); Splunk CIM 6.4
---

# Day 30: Jenis serangan, attack vector, dan glosarium

Cakupan: jenis serangan dan attack vector umum; istilah supply chain attack, ransomware, registry, exfiltration, social engineering, DoS, DDoS, bot dan botnet, C2, zero trust, account takeover, email compromise, threat actor, APT, adversary.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- mendefinisikan setiap istilah serangan yang sering dipakai dengan kata-katamu sendiri, lalu menghubungkannya ke taktik dan teknik ATT&CK.
- membedakan attack vector (jalan masuk) dari attack type (jenis serangan/tujuan).
- menyebut sinyal data di Splunk/CIM untuk setiap jenis serangan, sebagai titik awal deteksi atau investigasi.
- memakai data tren terbaru (DBIR 2026, IC3 2025) untuk memprioritaskan.

## 2. Konteks singkat

Topik ini banyak berisi definisi. Kamu tentu sudah mengenal istilah-istilah ini dari pekerjaan. Tantangannya ada di presisi: bedanya threat actor vs adversary vs APT, DoS vs DDoS, BEC vs account takeover. Selain itu, ada perubahan ATT&CK v19 yang memengaruhi cara memetakan teknik.

## 3. Konsep inti

### 3.1 Vector vs type

- **Attack vector:** jalur atau metode masuk. Contoh: phishing email, eksploitasi aplikasi yang menghadap internet, kredensial curian di VPN, perangkat/USB, pihak ketiga (supply chain).
- **Attack type:** jenis serangan menurut cara atau tujuannya. Contoh: ransomware, DoS/DDoS, exfiltration, BEC, defacement.

Satu insiden biasanya punya satu vector awal dan beberapa tahap. Contoh: phishing (vector), lalu eksekusi makro, C2, exfiltration, dan akhirnya ransomware (type/impact).

**Tren vector terbaru:** Verizon DBIR 2026 (rilis 19 Mei 2026; 22.000 breach terkonfirmasi) melaporkan eksploitasi kerentanan (31%) untuk pertama kalinya mengalahkan penyalahgunaan kredensial (13%) sebagai vector akses awal teratas. Ransomware muncul di 48% breach, dan breach yang melibatkan pihak ketiga/supply chain naik sekitar 60% [S1] `[sekunder: liputan media atas DBIR]`, cek angka di laporan asli.

### 3.2 Taktik ATT&CK v19 sebagai peta

ATT&CK Enterprise kini memiliki 15 taktik [S2]:

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

**Perubahan v19 (28 Apr 2026):** taktik Defense Evasion dipecah menjadi Stealth (mewarisi ID TA0005; menyembunyikan aktivitas di balik perilaku sah) dan Defense Impairment (TA0112, baru; menonaktifkan, merusak, atau mengkompromikan kontrol keamanan seperti logging dan alat keamanan). Beberapa teknik dipetakan ke keduanya [S2][S3].

Banyak materi lama masih menyebut 14 taktik dengan Defense Evasion. Kenali keduanya supaya tidak salah saat membaca tulisan lama.

### 3.3 Glosarium istilah serangan

| Istilah | Definisi (kata sendiri) | ATT&CK terkait | Sinyal di Splunk/CIM |
|---|---|---|---|
| Supply chain attack | Mengkompromikan produk, pembaruan, atau penyedia sebelum sampai ke korban, sehingga korban "mengundang" penyerang lewat jalur tepercaya | T1195 Supply Chain Compromise (.001 dependensi/alat dev, .002 software supply chain, .003 hardware), taktik Initial Access [S4] | Proses anak tak biasa dari updater/agen vendor (Endpoint.Processes), koneksi baru dari aplikasi tepercaya (Network_Traffic) |
| Ransomware | Malware yang mengenkripsi atau mengunci data/sistem lalu meminta tebusan. Sering disertai pencurian data (double extortion) | Impact: T1486 Data Encrypted for Impact, T1490 Inhibit System Recovery (hapus shadow copy/backup); sering juga mematikan alat keamanan (Defense Impairment) | Banyak modifikasi file (Endpoint.Filesystem), `vssadmin`/`wbadmin` (Endpoint.Processes), catatan tebusan |
| Registry | Basis data konfigurasi hierarkis Windows (hive, key, value). Disalahgunakan untuk persistence, konfigurasi malware, atau melemahkan pertahanan | Persistence: T1547.001 Registry Run Keys / Startup Folder; T1112 Modify Registry (, cek taktiknya di v19, dulu Defense Evasion) | Sysmon EID 12-14 ke Endpoint.Registry (`registry_path`, `registry_value_data`) |
| Exfiltration | Mengeluarkan data dari lingkungan korban | Taktik TA0010 [S2] | Volume keluar besar/tak biasa (`bytes_out`), unggahan ke cloud storage (Web.Storage), DNS tunneling (Network_Resolution) |
| Social engineering | Memanipulasi manusia agar memberi akses, data, atau melakukan tindakan | T1566 Phishing (Initial Access) | Email (Email DM), klik URL (Web), login setelah phishing (Authentication) |
| DoS | Membuat layanan tidak tersedia dari satu sumber (atau sedikit) | Impact: T1498 Network Denial of Service, T1499 Endpoint Denial of Service | Lonjakan koneksi dari satu `src`, error 5xx |
| DDoS | DoS dari banyak sumber terdistribusi (sering botnet), sehingga sulit diblokir per IP | Impact | Lonjakan dari banyak `src` sekaligus (Network_Traffic), dc(src) tinggi |
| Bot / botnet | Bot: perangkat yang dikendalikan otomatis oleh penyerang. Botnet: jaringan bot yang dikendalikan terpusat lewat C2 | Resource Development, C2 | Beaconing periodik (Day 39), koneksi ke infrastruktur C2 yang dikenal |
| C2 (command and control) | Kanal komunikasi penyerang dengan sistem yang dikompromikan | Taktik TA0011 ("The adversary is trying to communicate with compromised systems to control them"). Teknik: Application Layer Protocol T1071, Encrypted Channel T1573, Dynamic Resolution T1568, Proxy T1090, Remote Access Tools T1219 [S5] | DNS/HTTP periodik, domain baru/DGA, user-agent aneh, alat remote access tak resmi |
| Zero trust | Prinsip keamanan yang meminimalkan ketidakpastian dalam keputusan akses least privilege per permintaan, dengan asumsi jaringan sudah terkompromi (NIST SP 800-207) [S6] | (konsep pertahanan, bukan teknik) | Log keputusan akses IdP/ZTNA, MFA, posture device (Authentication) |
| Account takeover (ATO) | Penyerang menguasai akun sah (kredensial curian, credential stuffing, session hijacking) dan memakainya seperti pemilik | T1078 Valid Accounts, Credential Access | Login dari lokasi/perangkat baru, impossible travel, reset MFA, aktivitas tidak biasa setelah login |
| Email compromise / BEC | Penipuan lewat email (sering memakai akun sah yang diambil alih atau pemalsuan), umumnya untuk transfer dana atau data. Bisa memakai ATO sebagai sarana | Phishing, Valid Accounts, aturan kotak masuk: T1114.003 Email Forwarding Rule, T1564.008 Email Hiding Rules (, cek taktik T1564 di v19) | Pembuatan inbox rule/forwarding di M365 (`o365:management:activity`, cek operasi), login aneh ke email |
| Threat actor | Individu/kelompok yang melakukan atau berniat melakukan aktivitas berbahaya (kriminal, negara, hacktivist, insider) | Groups di ATT&CK | Konteks CTI (Day 30) |
| APT | Adversary dengan keahlian dan sumber daya signifikan yang memakai banyak vektor untuk membangun pijakan, mengejar tujuan berulang dalam waktu lama, beradaptasi terhadap pertahanan, dan bertekad mempertahankan akses (NIST, dari SP 800-39) [S7] | Groups (mis. Gxxxx) | Dwell time panjang, teknik low-and-slow, living off the land |
| Adversary | Istilah umum untuk pihak yang berlawanan (melakukan serangan). Dipakai ATT&CK sebagai sudut pandang "adversary behavior" | Seluruh ATT&CK | - |

**Membedakan istilah yang mirip:**
- Threat actor = siapa yang mungkin menyerang. Adversary = pihak yang menyerang dalam konteks spesifik/berlawanan. APT = jenis adversary yang canggih dan persisten.
- BEC = tujuan/penipuan lewat email. ATO = cara menguasai akun. BEC sering memakai ATO, tetapi bisa juga memakai domain mirip tanpa ATO.

### 3.4 Dampak dan prioritas (data 2025-2026)

Laporan IC3 FBI 2025 (via liputan media) [S8] `[sekunder]`, cek di laporan asli ic3.gov:
- **BEC**: sekitar USD 3,046 miliar kerugian yang dilaporkan (24.768 aduan). Ancaman berorientasi bisnis yang paling merusak secara finansial di AS. Ada kerugian BEC dengan keterkaitan AI.
- **Ransomware**: kerugian yang dilaporkan hanya sekitar USD 32,3 juta, tetapi 63 varian baru teridentifikasi.

Angka kerugian ransomware di IC3 jauh di bawah kesan umum karena hanya mencakup yang dilaporkan dan dihitung IC3. Biaya downtime dan pemulihan umumnya tidak tercakup. Hal ini sering disebut dalam analisis laporan IC3, perlu dicek. Angka total kerugian berbeda antar liputan (sekitar USD 17 miliar untuk penipuan siber vs 20,877 miliar untuk kejahatan berbasis siber). Rujuk laporan asli.

### 3.5 Enterprise vs ES

Definisi tidak bergantung produk. ES menambahkan:
- annotation ATT&CK pada detection (Day 29);
- threat intel untuk aktor/indikator (Day 30);
- analytic story ESCU per jenis serangan (mis. ransomware, BEC) (Day 45).

## 4. Contoh SPL dan langkah di ES

> Sketsa deteksi/investigasi berbasis CIM, berlabel ilustrasi. Ambang adalah asumsi. Uji dulu dengan `makeresults` (Day 12).

### 4.1 Ransomware: penghapusan shadow copy

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

- Penghapusan shadow copy adalah langkah klasik sebelum enkripsi agar korban sulit memulihkan data. Di ATT&CK ini T1490 Inhibit System Recovery di taktik Impact.
- Wildcard di nilai `Processes.process` di `tstats` didukung (Day 25). Leading wildcard tetap mahal (Day 14).
- **Penjelasan jinak:** alat backup/administrasi bisa menjalankan perintah serupa, jadi lihat `parent_process_name` dan `user`.

### 4.2 Registry persistence: Run key

```
| tstats summariesonly=false count values(Registry.registry_value_data) AS data
    from datamodel=Endpoint.Registry
    where Registry.registry_path="*\\CurrentVersion\\Run*" Registry.action=modified
    by Registry.dest Registry.registry_path Registry.registry_value_name
| rename Registry.* AS *
```

- Cek nama objek `Endpoint.Registry` dan nilai `action` (mis. `modified`, `created`) di CIM 6.4 dan TA Sysmon.
- **Cara membaca hasil:** nilai yang menunjuk ke `%APPDATA%`, `%TEMP%`, atau `C:\Users\Public` lebih mencurigakan daripada `Program Files`.

### 4.3 Exfiltration: volume keluar tidak biasa per host

```
| tstats summariesonly=false sum(All_Traffic.bytes_out) AS out from datamodel=Network_Traffic.All_Traffic
    where earliest=-24h by All_Traffic.src All_Traffic.dest
| rename All_Traffic.* AS *
| eventstats avg(out) AS avg_out stdev(out) AS sd_out
| where out > avg_out + 3*sd_out
| eval out_MB=round(out/1024/1024,1)
| sort - out
```

- `eventstats` menghitung rata-rata dan simpangan baku seluruh pasangan. Pasangan yang jauh di atas rata-rata ditandai. Ini outlier sederhana (Day 39).
- **Penjelasan jinak:** backup, sinkronisasi cloud, pembaruan OS.

### 4.4 DDoS vs DoS: satu sumber atau banyak sumber?

```
| tstats summariesonly=false count dc(All_Traffic.src) AS sources from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.dest="203.0.113.10" earliest=-1h by _time span=1m
| eval pattern=case(sources>500, "banyak sumber (DDoS?)", count>10000 AND sources<5, "sedikit sumber (DoS?)", true(), "normal")
```

- `dc(src)` per menit membedakan pola DoS (sumber sedikit, volume tinggi) dari DDoS (sumber banyak). Ambang adalah ilustrasi.

### 4.5 BEC: inbox rule mencurigakan di Microsoft 365

```
index=* sourcetype="o365:management:activity" (Operation="New-InboxRule" OR Operation="Set-InboxRule") earliest=-7d
| stats count values(Parameters{}.Value) AS params BY UserId ClientIP
```

- Aturan inbox yang meneruskan atau menyembunyikan email adalah pola BEC/ATO yang umum.
- Cek nama operasi, field (`UserId`, `ClientIP`, `Parameters{}`), dan index di add-on Office 365-mu. Ganti `index=*` dengan index yang benar (Day 14).

### 4.6 Di ES (generik)

- Cari analytic story ESCU untuk ransomware, BEC/O365, dan supply chain di content management (Day 45).
- Periksa annotation ATT&CK detection-mu terhadap v19. Teknik yang dulu di "Defense Evasion" kini mungkin dipetakan ke Stealth atau Defense Impairment, yang memengaruhi laporan cakupan (Day 27, 29).

## 5. Lab praktik

1. Buat kartu glosarium dari tabel bagian 3.3 (istilah | definisi sendiri | ATT&CK | sinyal data).
2. Buka attack.mitre.org v19. Untuk setiap baris bertanda, cek di bagian 3.3, cari ID teknik yang benar dan perbaiki kartumu.
3. Di VM Windows lab (snapshot dulu), jalankan Atomic Red Team untuk:
   - T1547.001 (Run key), cek nomor test;
   - satu test penghapusan shadow copy hanya bila snapshot tersedia, karena test ini merusak kemampuan pemulihan VM.
   
   Lalu jalankan bagian 4.1-4.2.
4. Jalankan bagian 4.3 di data lab, lalu buat transfer besar dari VM (mis. salin file 500 MB ke share lain) dan lihat apakah terdeteksi.
5. Di BOTS v1 (skenario ransomware, Day 20), cari bukti penghapusan shadow copy atau modifikasi registry dengan pola bagian 4.1-4.2. Fokus pada metodenya.

**Hasil yang sebaiknya tersimpan:**
- Kartu glosarium lengkap dengan ID ATT&CK v19 terverifikasi.
- Minimal 2 sketsa deteksi diuji dengan data lab.
- Penjelasan jinak untuk setiap sketsa ditulis.

**Variasi tantangan:** pilih satu laporan publik tentang serangan supply chain (penerbit dan tahun disebut, tanpa menyalin isinya). Petakan tahapannya ke taktik v19, lalu tentukan sumber data Splunk untuk tiap tahap.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Sketsa Endpoint tidak menemukan apa pun | Sysmon/EDR tidak mencatat command line atau registry; model tidak terisi | Day 21 (profil Sysmon), Day 23 (CIM) |
| `bytes_out` kosong | Sumber firewall tidak menyediakan atau TA tidak memetakan | Cek `tstats ... by sourcetype` dan field yang tersedia (Day 24) |
| Mapping ATT&CK di laporan berbeda dari materi | Perubahan v19 (Stealth/Defense Impairment) | Perbarui konten/annotation; catat versi ATT&CK [S2] |
| Statistik ancaman berbeda antar artikel | Sumber sekunder/metodologi berbeda | Rujuk laporan asli (DBIR, IC3) |

## 7. Kesalahan umum dan jebakan

- Menyebut "Defense Evasion" sebagai taktik ATT&CK terkini. Di v19 sudah dipecah [S2][S3]. Saat membaca tulisan orang lain, perhatikan versi ATT&CK yang mereka pakai.
- Menyamakan BEC dengan phishing biasa. BEC berfokus pada penipuan bisnis, sering tanpa malware.
- Menyamakan DoS dan DDoS. Bedanya terletak pada jumlah dan sebaran sumber.
- Menganggap APT selalu "negara". Definisi NIST menekankan kemampuan, persistensi, dan adaptasi, bukan afiliasi [S7].
- Mengutip angka tren dari sumber sekunder tanpa cek laporan asli [S1][S8].
- `[komunitas]` Tidak ada sumber komunitas. Definisi berasal dari NIST dan MITRE (primer), sedangkan tren dari liputan laporan.

## 8. Catatan terkini

- **ATT&CK v19 (28 Apr 2026):** Defense Evasion dipecah menjadi Stealth (TA0005) dan Defense Impairment (TA0112). v19.2 (Agu 2026) adalah rilis Agile pertama [S2][S3].
- **DBIR 2026:** eksploitasi kerentanan menjadi vector awal teratas; ransomware di 48% breach; peran AI dalam serangan meningkat [S1].
- **IC3 2025:** BEC tetap penyebab kerugian bisnis terbesar; muncul kasus BEC dengan keterkaitan AI [S8].
- Teknik T1219 kini bernama "Remote Access Tools" [S5]. Materi lama menyebut "Remote Access Software", perlu dicek.

## 9. Cheat sheet

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
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | TechRepublic: New Verizon report reveals the security gap attackers are exploiting most (DBIR 2026); liputan lain | https://www.techrepublic.com/article/news-verizon-dbir-vulnerability-exploitation-2026/ | sekunder | 2026-05 | Sedang. Angka perlu dicocokkan dengan laporan Verizon |
| S2 | MITRE ATT&CK: Enterprise tactics (v19) | https://attack.mitre.org/tactics/enterprise/ | primer | diakses 2026-10-07 | Tinggi. 15 taktik |
| S3 | MITRE ATT&CK: Updates April 2026 (v19); D3 Security blog tentang split Defense Evasion | https://attack.mitre.org/resources/updates/updates-april-2026/ | primer + sekunder | 2026-04-28 | Tinggi |
| S4 | MITRE ATT&CK: T1195 Supply Chain Compromise | https://attack.mitre.org/techniques/T1195/ | primer | diakses 2026-10-07 | Tinggi |
| S5 | MITRE ATT&CK: TA0011 Command and Control | https://attack.mitre.org/tactics/TA0011/ | primer | diakses 2026-10-07 | Tinggi |
| S6 | NIST CSRC Glossary: zero trust (SP 800-207) | https://csrc.nist.gov/glossary/term/zero_trust | primer | diakses 2026-10-07 | Tinggi |
| S7 | NIST CSRC Glossary: advanced persistent threat (SP 800-39) | https://csrc.nist.gov/glossary/term/advanced_persistent_threat | primer | diakses 2026-10-07 | Tinggi |
| S8 | Liputan FBI IC3 2025 Internet Crime Report (McDonald Hopkins, The Record, JD Supra) | https://therecord.media/cyber-fraud-surges-to-17-billion-fbi-ic3 | sekunder | 2026 | Sedang. Angka total berbeda antar liputan |
| S9 | CIM 6.4 data models (lihat Day 23/24) | https://help.splunk.com/en/data-management/common-information-model/6.4/data-models | primer | diakses 2026-10-07 | Tinggi |

**Catatan sumber:** daftar 15 taktik v19.2 berasal dari halaman taktik ATT&CK [S2]. ID teknik yang stabil lintas versi (T1486, T1490, T1547.001, T1112, T1566, T1078, T1498, T1499, T1114.003, T1564.008) ditulis apa adanya, sedangkan penempatan taktik v19 untuk T1112 dan T1564 (Stealth atau Defense Impairment) perlu dicek di halaman tekniknya. Angka DBIR 2026 [S1] dan IC3 2025 [S8] berasal dari liputan media, jadi cocokkan dengan laporan aslinya sebelum dikutip. Nama field operasi Office 365 di CIM perlu dicek di add-on versi-mu.
