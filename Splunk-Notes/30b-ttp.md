---
day: 30
title: 'Tactics, techniques, and procedures (TTP): definisi, struktur ATT&CK, dan pandangan industri'
researched_on: 2026-10-10
versions_checked: NIST SP 800-150 (definisi TTP via CSRC Glossary); MITRE ATT&CK v19 (contoh T1053.005 v1.8, dimodifikasi 12 Mei 2026; Detection Strategy DET0441, Analytic AN1221); MITRE "TTP-Based Hunting" (Mar 2019); Pyramid of Pain (Bianco, 2013); Windows Security event 4698 (Microsoft Learn); Splunk ES 8.7
---

# Day 30: Tactics, techniques, and procedures (TTP)

Cakupan: definisi tactics, techniques, and procedures, cara membaca struktur ATT&CK v19, alasan industri memprioritaskan deteksi TTP, dan cara mengukur cakupan per procedure dengan contoh T1053.005 di Splunk.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- mendefinisikan tactic, technique, dan procedure dengan tepat, serta memberi contoh berjenjang.
- membaca halaman teknik ATT&CK v19: sub-technique, taktik ganda, procedure examples, mitigations, Detection Strategy/Analytic.
- menjelaskan kenapa industri menilai deteksi berbasis TTP lebih bernilai daripada IOC (Pyramid of Pain, TTP-based hunting).
- menulis detection pada level procedure dan menjelaskan batas cakupannya terhadap technique.

## 2. Konteks singkat

Day 30 memperkenalkan 15 taktik ATT&CK v19. Hari ini kita turun ke dalam strukturnya. TTP adalah bahasa utama detection engineering, hunting, dan CTI. Ketika laporan intel berkata "aktor memakai scheduled task untuk persistence", itu TTP. Detection yang menangkap perilaku itu bertahan lebih lama daripada blokir IP aktor yang bisa diganti dalam hitungan menit.

## 3. Konsep inti

### 3.1 Definisi

NIST SP 800-150 mendefinisikan TTP sebagai perilaku aktor, dengan tiga tingkat [S1]:
- **Tactic:** deskripsi tingkat tertinggi, yaitu tujuan (kenapa).
- **Technique:** deskripsi lebih rinci tentang perilaku dalam konteks sebuah taktik, yaitu cara umum (bagaimana).
- **Procedure:** deskripsi tingkat terendah dan sangat rinci dalam konteks teknik, yaitu implementasi spesifik (alat, perintah, parameter yang dipakai aktor tertentu).

Contoh berjenjang:

| Tingkat | Contoh |
|---|---|
| Tactic | Persistence (TA0003): penyerang ingin bertahan di sistem |
| Technique | Scheduled Task/Job (T1053) |
| Sub-technique | Scheduled Task (T1053.005) |
| Procedure | "Aktor X menjalankan `schtasks /create /sc onlogon /tr C:\Users\Public\u.bat` dari PowerShell", atau Sandworm Team memakai scheduled task lewat GPO untuk menjalankan wiper pada waktu tertentu (procedure example di ATT&CK) [S2] |

### 3.2 Anatomi halaman teknik ATT&CK (v19)

Ambil contoh T1053.005 Scheduled Task (versi 1.8, dimodifikasi 12 Mei 2026) [S2]:
- **Parent technique:** T1053 Scheduled Task/Job.
- **Taktik:** Execution (TA0002), Persistence (TA0003), Privilege Escalation (TA0004). Satu teknik bisa melayani beberapa taktik, karena tujuan menentukan taktik, bukan alatnya.
- **Procedure examples:** contoh nyata dari Groups (mis. APT29 G0016, Sandworm Team G0034) dan Software (mis. Agent Tesla S0331) [S2]. Ini level procedure.
- **Mitigations:** mis. M1047 Audit, M1028 OS Configuration, M1026 Privileged Account Management, M1018 User Account Management [S2].
- **Detection:** sejak v18, berupa Detection Strategy (mis. DET0441) dan Analytic (mis. AN1221), yang menjelaskan apa perilakunya dan bagaimana mendeteksinya per platform: pembuatan/modifikasi/penghapusan task lewat Task Scheduler, WMI, PowerShell, atau API, serta pola eksekusi anomali [S2].

Objek lain di ATT&CK dan format ID-nya:

| Objek | Format ID | Contoh | Dipakai untuk |
|---|---|---|---|
| Tactic | TAxxxx | TA0003 Persistence | Mengelompokkan detection dan finding menurut tujuan penyerang |
| Technique | Txxxx | T1053 Scheduled Task/Job | Satuan utama pemetaan detection dan laporan cakupan |
| Sub-technique | Txxxx.yyy | T1053.005 Scheduled Task | Pemetaan yang lebih presisi; pakai bila tersedia |
| Group | Gxxxx | G0016 APT29 | Menghubungkan aktor dengan teknik yang pernah dipakai |
| Software | Sxxxx | S0331 Agent Tesla | Malware dan tool beserta tekniknya |
| Campaign | Cxxxx | (kampanye dengan rentang waktu) | Aktivitas spesifik dalam periode tertentu |
| Mitigation | Mxxxx | M1047 Audit | Kontrol pencegahan per teknik |
| Detection Strategy | DETxxxx | DET0441 | Gambaran cara mendeteksi satu teknik (v18 ke atas) |
| Analytic | ANxxxx | AN1221 | Logika deteksi per platform di dalam Detection Strategy |
| Data Component | DCxxxx | (mis. pembuatan scheduled job) | Jenis telemetri yang dibutuhkan analytic |

Saat menulis annotation atau laporan, pakai ID sub-technique bila ada dan selalu sebut versi ATT&CK, karena nama dan penempatan taktik bisa berubah antar versi (contohnya pemecahan Defense Evasion di v19, Day 30).

### 3.3 Pandangan industri: kenapa TTP

Pyramid of Pain (David Bianco, 2013): indikator diurutkan menurut seberapa "sakit" bagi penyerang bila indikator itu dideteksi dan ditolak [S3][S4]:

```
            TTPs              <- paling sulit diubah penyerang ("Tough!")
           Tools
     Network/Host Artifacts
        Domain Names
        IP Addresses
        Hash Values           <- paling mudah diubah ("Trivial")
```

Bila kamu mendeteksi dan menolak TTP dengan cepat, penyerang terpaksa mempelajari perilaku baru, yang merupakan hal paling mahal baginya [S4]. Mengganti hash atau IP murah sekali.

| Level | Contoh | Biaya bagi penyerang untuk mengganti | Konsekuensi untuk SOC |
|---|---|---|---|
| Hash values | SHA256 file loader | Hampir nol: kompilasi ulang atau ubah satu byte | Bagus untuk retro-hunt dan blokir cepat, tidak tahan lama |
| IP addresses | IP server C2 | Rendah: sewa VPS baru, pakai proxy atau layanan cloud | Cepat basi; IP bisa berpindah ke pemilik sah (Day 30) |
| Domain names | Domain C2 | Rendah sampai sedang: registrasi dan reputasi butuh sedikit waktu | Sedikit lebih awet dari IP; perhatikan domain baru dan NXDomain |
| Network/host artifacts | Pola URI, user agent, nama file, nama task, registry key | Sedang: harus mengubah konfigurasi tool | Mulai menyentuh perilaku; masih bisa diakali dengan konfigurasi |
| Tools | Tool dump kredensial tertentu, framework C2 tertentu | Tinggi: harus mencari atau membuat tool lain | Detection berbasis karakteristik tool, bukan hash-nya |
| TTPs | Membuat scheduled task untuk persistence, dump LSASS | Paling tinggi: harus mengganti cara kerja | Detection perilaku bertahan lintas kampanye dan tool |

Cara memakai tabel ini di pekerjaan: saat menerima laporan intel, pisahkan isinya ke level piramida. Level bawah dimasukkan ke threat list dengan masa berlaku. Level atas diubah menjadi hipotesis hunting dan detection perilaku.

TTP-Based Hunting (MITRE, Mar 2019) [S5]: mengumpulkan dan memfilter data berdasarkan pengetahuan TTP adalah cara efektif mendeteksi aktivitas berbahaya. Alasannya: teknologi tempat penyerang beroperasi membatasi jumlah dan jenis teknik yang bisa mereka pakai setelah kompromi. Pendekatan ini disebut efisien dan relatif murah dibanding manfaatnya. Laporan ini dibuat untuk Cyber National Mission Force (USCYBERCOM) [S5].

**Keseimbangan:** IOC tetap berguna untuk respons cepat dan retro-hunt. Tetapi program deteksi yang matang memprioritaskan TTP dan mengukur cakupan per teknik (Detection Studio, Day 27).

### 3.4 Procedure vs technique: masalah cakupan

Detection biasanya menangkap satu atau beberapa procedure, bukan seluruh teknik. Contoh T1053.005:
- Detection "schtasks.exe /create dari PowerShell" menangkap satu procedure.
- Ia tidak menangkap task yang dibuat lewat COM/API, WMI, atau GPO. Semua cara itu disebut di Detection Strategy [S2].

Jadi "cakupan T1053.005" harus dibaca sebagai "cakupan procedure X dan Y dari T1053.005". Karena itu cakupan sebaiknya dilaporkan per procedure, dan setiap teknik prioritas didukung lebih dari satu sumber data. Satu sumber data bisa hilang (agen mati, audit policy berubah), dan satu procedure bisa diganti penyerang dengan mudah.

Peta procedure dan sumber data untuk T1053.005 di Windows:

| Procedure | Sumber data yang menangkapnya | Event/field kunci |
|---|---|---|
| `schtasks.exe /create` dari shell atau script | Sysmon EID 1 atau Security 4688 dengan command line | `process_name=schtasks.exe`, `process` berisi `/create` |
| Cmdlet `Register-ScheduledTask` atau `New-ScheduledTask` | PowerShell Script Block Logging (4104), Security 4698 | Teks cmdlet di script block; task baru di 4698 |
| API Task Scheduler (COM) langsung dari program | Security 4698, log `Microsoft-Windows-TaskScheduler/Operational` | 4698 berisi XML task; Operational EID 106 (task registered) |
| Task dibuat lewat WMI atau dari host lain (remote) | Security 4698 di host target, logon jaringan (4624 type 3) | Subject di 4698 berasal dari sesi remote |
| Task di-deploy lewat GPO | 4698 di banyak host dalam waktu berdekatan, perubahan di SYSVOL | Pola massal, bukan satu host |
| Modifikasi task yang sudah ada | Security 4702 (task updated), Operational EID 140 | Perubahan `Command` pada task lama |
| Jejak file dan registry | Sysmon EID 11 (file di `C:\Windows\System32\Tasks\`), Sysmon EID 12/13 (key `TaskCache\Tree`) | Berguna bila log Security tidak lengkap |

Event Security lain dari keluarga yang sama: 4699 (task deleted), 4700 (task enabled), dan 4701 (task disabled). Semuanya membutuhkan subkategori audit "Audit Other Object Access Events" [S7]. Eksekusi task terlihat di Operational EID 200 (action started) dan 201 (action completed), serta sebagai proses anak dari `svchost.exe` yang menjalankan layanan Schedule (atau `taskeng.exe` di Windows lama).

### 3.5 Dari laporan intel ke detection: contoh fiktif

Laporan intel fiktif menulis: "Setelah akses awal lewat dokumen, aktor membuat scheduled task bernama mirip layanan update yang menjalankan script dari folder `C:\Users\Public` setiap logon." Cara mengolahnya:

1. **Pisahkan level piramida.** Nama task dan path script adalah host artifact (mudah diganti). Membuat scheduled task untuk persistence adalah TTP: T1053.005, taktik Persistence (dan Execution saat task berjalan).
2. **Tulis hipotesis hunting.** "Bila aktor ini ada di lingkungan kita, akan ada task baru dengan action yang menjalankan file dari folder user-writable, dibuat oleh proses selain installer yang dikenal."
3. **Pilih procedure dan sumber data.** Dari tabel di bagian 3.4: Sysmon EID 1 untuk `schtasks.exe`, 4698 untuk semua cara pembuatan task, dan 4104 untuk cmdlet PowerShell.
4. **Bangun detection.** Satu detection perilaku (bagian 4.1), satu detection berbasis 4698 yang memeriksa path di action (bagian 4.2), dan satu lookup berisi artifact dari laporan dengan masa berlaku untuk retro-hunt.
5. **Laporkan cakupan per procedure.** Contoh: "T1053.005: schtasks dari shell (Sysmon EID 1, aktif), semua pembuatan via 4698 (aktif, audit sudah dinyalakan di 92% host), cmdlet PowerShell (4104, belum ada di server lama)."

Hasilnya lebih jujur daripada satu baris "T1053.005: covered", dan langsung menunjukkan di mana celahnya.

### 3.6 TTP di Splunk

- **Annotations ES:** detection dipetakan ke `annotations.mitre_attack.mitre_technique_id` dan taktik (Day 29, 30).
- **research.splunk.com:** detection dan analytic story dikelompokkan per teknik ATT&CK (Day 45).
- **SSE:** MITRE ATT&CK Framework dashboard dan Benchmark (Day 27).
- **Detection Studio (ES 8.7):** skor cakupan teknik untuk detection aktif (Day 27).

## 4. Contoh SPL dan langkah di ES

> Keluaran berlabel ilustrasi.

### 4.1 IOC vs TTP untuk ancaman yang sama

**Pendekatan IOC (rapuh):**

```
| tstats count from datamodel=Endpoint.Processes
    where Processes.process_hash IN ("<hash1>","<hash2>") by Processes.dest
```

**Pendekatan TTP, procedure "schtasks /create" dari script host (lebih tahan lama):**

```
| tstats summariesonly=false count min(_time) AS first values(Processes.process) AS cmd
    from datamodel=Endpoint.Processes
    where Processes.process_name="schtasks.exe" Processes.process="*/create*"
      (Processes.parent_process_name IN ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe"))
    by Processes.dest Processes.user Processes.parent_process_name
| rename Processes.* AS *
| convert ctime(first)
```

- Pendekatan pertama gagal begitu penyerang mengompilasi ulang malware (hash baru).
- Pendekatan kedua menangkap perilaku apa pun malware-nya, selama prosedurnya sama.
- `<field> IN (...)` didukung di klausa WHERE `tstats` (lihat sintaks di Day 25 bagian 3.4). Bila hasilnya aneh di versi lama, ganti dengan rangkaian `OR`.

### 4.2 Menambah sumber kedua untuk procedure lain (task dibuat lewat API/COM)

```
index=wineventlog sourcetype="XmlWinEventLog:Security" EventCode=4698 earliest=-24h
| stats count values(TaskName) AS tasks BY host SubjectUserName
```

- Event 4698 ("A scheduled task was created") mencatat pembuatan task apa pun caranya, asalkan subkategori audit "Audit Other Object Access Events" aktif [S7]. Isinya: akun pembuat (Subject), nama task, dan isi lengkap task dalam bentuk XML (`TaskContent`), termasuk trigger, akun yang menjalankan, dan `<Command>`/`<Arguments>` di bagian action.
- Cek nama field (`TaskName`, `SubjectUserName`, `TaskContent`) di TA-mu; format klasik dan XML berbeda.

Versi yang lebih tajam memeriksa isi action:

```
index=wineventlog sourcetype="XmlWinEventLog:Security" EventCode=4698 earliest=-24h
| rex field=TaskContent "<Command>(?<task_command>[^<]+)</Command>"
| eval suspicious_path=if(match(lower(task_command), "\\\\users\\\\public\\\\|\\\\appdata\\\\|\\\\temp\\\\|\\\\programdata\\\\"), 1, 0)
| where suspicious_path=1
| table _time host SubjectUserName TaskName task_command
```

- `rex` mengambil isi `<Command>` dari XML task (Day 11).
- `match(lower(...))` mencari folder yang bisa ditulis user biasa. Satu backslash literal di regex ditulis `\\` oleh PCRE, dan karena string `eval` juga memakai backslash sebagai escape, di dalam tanda kutip SPL ia menjadi `\\\\`.
- **Cara membaca hasil:** task dari folder user-writable yang dibuat akun non-admin atau di luar jam deployment layak diinvestigasi. Task dari agen vendor biasanya menunjuk ke `Program Files`.
- **Kapan gagal:** pada format klasik, XML bisa ter-escape (`&lt;Command&gt;`), sehingga regex harus disesuaikan. Command yang memakai variabel lingkungan (`%PUBLIC%`) juga lolos dari pola di atas, jadi tambahkan variasinya setelah diuji dengan `makeresults`.
- Kombinasi bagian 4.1 dan 4.2 menutup lebih banyak procedure dari T1053.005, sesuai arahan Detection Strategy [S2].

### 4.3 Cakupan teknik dari detection aktif (ES)

```
| rest /servicesNS/-/-/saved/searches splunk_server=local count=0
| search action.correlationsearch.enabled=1 disabled=0
| spath input=action.correlationsearch.annotations path=mitre_attack{} output=technique
| mvexpand technique
| stats dc(title) AS detections values(title) AS names BY technique
| sort - detections
```

- Menghitung berapa detection aktif per teknik ATT&CK dari annotation (Day 29 bagian 4.2), cek path JSON dan atribut di ES 8.7.
- **Cara membaca hasil:** teknik dengan satu detection berbasis satu procedure adalah cakupan tipis.

### 4.4 Di ES (generik)

- Buka Detection Studio (Day 27), lihat cakupan per teknik, lalu bandingkan dengan teknik prioritas dari CTI (Day 30).
- Untuk setiap teknik prioritas, minimal punya dua procedure atau dua sumber data.

## 5. Lab praktik

1. Buka halaman T1053.005 di ATT&CK v19. Tulis: taktik, 3 procedure examples (dengan ID group/software), mitigations, dan Detection Strategy/Analytic ID [S2].
2. Di VM Windows lab (snapshot), jalankan dua cara membuat scheduled task:
   - (a) `schtasks /create ...` dari PowerShell;
   - (b) via PowerShell cmdlet `Register-ScheduledTask` (memakai API, bukan `schtasks.exe`).
   
   Bisa juga lewat Atomic Red Team T1053.005, cek nomor test.
3. Jalankan bagian 4.1 (TTP). Hasil yang diharapkan: (a) terdeteksi, (b) tidak.
4. Aktifkan audit Other Object Access di VM lab (bila belum), ulangi (b), lalu jalankan bagian 4.2. Hasil yang diharapkan: (b) terdeteksi lewat 4698.
5. Tulis tabel cakupan T1053.005: procedure | sumber data | detection | status.

**Hasil yang sebaiknya tersimpan:**
- Ringkasan halaman ATT&CK T1053.005.
- Bukti bahwa bagian 4.1 menangkap (a) tetapi tidak (b).
- Bukti bahwa bagian 4.2 menangkap (b).
- Tabel cakupan per procedure.

**Variasi tantangan:** pilih teknik lain yang punya banyak procedure, misalnya T1059.001 PowerShell. Buat matriks procedure x sumber data (Sysmon EID 1, PowerShell Script Block Logging event 4104 di log `Microsoft-Windows-PowerShell/Operational`, AMSI), lalu tentukan kombinasi minimum untuk cakupan yang layak.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Event 4698 tidak muncul | Subkategori audit tidak aktif | Aktifkan "Audit Other Object Access Events" (mis. `auditpol /set /subcategory:"Other Object Access Events" /success:enable`) |
| Detection TTP berisik | Installer/agen sah membuat task | Filter sempit (path vendor yang dikenal, nama task spesifik), bukan mengecualikan semua task yang dibuat SYSTEM, karena penyerang dengan hak admin juga membuat task sebagai SYSTEM |
| Annotation teknik usang | Mapping sebelum v19 | Perbarui ke ID/taktik v19 (Day 30) |
| Cakupan tampak "penuh" padahal tes lolos | Satu procedure dianggap satu teknik | Laporkan cakupan per procedure (bagian 3.4) |

## 7. Kesalahan umum dan jebakan

- Menyamakan technique dengan tactic. Tactic = tujuan; technique = cara [S1].
- Satu teknik = satu taktik. Banyak teknik memetakan ke beberapa taktik (T1053.005 ada di 3 taktik) [S2].
- Mengklaim cakupan teknik dari satu detection procedure (bagian 3.4).
- Mengabaikan IOC sepenuhnya. IOC tetap berguna untuk respons cepat. Yang keliru adalah menjadikannya satu-satunya andalan [S4].
- Memakai daftar taktik lama (14, dengan Defense Evasion) tanpa catatan versi (Day 30).
- Menganggap nama task atau path script dari laporan intel sebagai TTP. Itu artifact; TTP-nya adalah perilaku membuat task untuk persistence (bagian 3.5).
- Mengandalkan 4698 tanpa memastikan audit policy aktif di semua host. Cakupan nyata sama dengan persentase host yang mengirim event itu.

## 8. Catatan terkini

- **ATT&CK v18 (Okt 2025):** detection > Detection Strategies (DETxxxx) + Analytics (ANxxxx) (Day 21).
- **ATT&CK v19 (Apr 2026):** Defense Evasion dipecah menjadi Stealth dan Defense Impairment; v19.2 (Agu 2026) rilis Agile (Day 30).
- Contoh T1053.005 diperbarui 12 Mei 2026 (versi 1.8) dan memuat DET0441/AN1221 [S2]. Mapping lama tanpa Detection Strategy kini kurang lengkap.

## 9. Cheat sheet

```
TTP (NIST SP 800-150): perilaku aktor ; Tactic = tujuan (why) ; Technique = cara (how) ; Procedure = implementasi spesifik
ATT&CK   Tactic TAxxxx > Technique Txxxx > Sub-technique Txxxx.yyy > Procedure examples (Groups Gxxxx, Software Sxxxx, Campaigns Cxxxx)
         + Mitigations Mxxxx + Detection Strategy DETxxxx + Analytic ANxxxx (v18+)
CONTOH   T1053.005 Scheduled Task -> Execution, Persistence, PrivEsc ; DET0441/AN1221 ; M1047 M1028 M1026 M1018
PYRAMID  hash < IP < domain < network/host artifacts < tools < TTPs (paling sakit bagi penyerang)
INDUSTRI TTP-based hunting (MITRE 2019): teknologi membatasi teknik penyerang -> hunting/deteksi TTP efektif & efisien
CAKUPAN  detection = procedure ; teknik butuh >=2 procedure/sumber data ; laporkan per procedure
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | NIST CSRC Glossary: Tactics, Techniques, and Procedures (SP 800-150) | https://csrc.nist.gov/glossary/term/tactics_techniques_and_procedures | primer | diakses 2026-10-07 | Tinggi |
| S2 | MITRE ATT&CK: T1053.005 Scheduled Task (v19) | https://attack.mitre.org/techniques/T1053/005/ | primer | dimodifikasi 2026-05-12; diakses 2026-10-07 | Tinggi. Taktik, procedure examples, mitigations, Detection Strategy |
| S3 | TaHiTI Threat Hunting Methodology whitepaper (memuat gambar Pyramid of Pain) | https://www.betaalvereniging.nl/wp-content/uploads/2026/03/TaHiTI-Threat-Hunting-Methodology-whitepaper.pdf | primer (mengutip Bianco) | diakses 2026-10-07 | Tinggi untuk urutan level |
| S4 | David J Bianco: The Pyramid of Pain (slide asli) | https://speakerdeck.com/davidjbianco/the-pyramid-of-pain-intel-driven-detection-and-response-to-increase-your-adversarys-cost-of-operations | primer (penulis) | 2013 (>3 tahun) | Tinggi untuk konsep |
| S5 | MITRE: TTP-Based Hunting (Daszczyszak dkk.) | https://www.mitre.org/news-insights/publication/ttp-based-hunting | primer | 2019-03 (>3 tahun) | Tinggi untuk argumen |
| S6 | MITRE ATT&CK: Enterprise tactics v19 | https://attack.mitre.org/tactics/enterprise/ | primer | diakses 2026-10-07 | Tinggi |
| S7 | Microsoft Learn: 4698(S) A scheduled task was created; Audit Other Object Access Events | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698 | primer | diakses 2026-10-10 | Tinggi. Field event dan subkategori audit; halaman berada di arsip dokumentasi Windows 10 |

**Catatan sumber:** nomor event log `Microsoft-Windows-TaskScheduler/Operational` (106, 140, 200, 201) dan jejak `TaskCache\Tree` di registry berasal dari pengetahuan umum forensik Windows, bukan dari satu dokumen di tabel ini; uji di VM lab sebelum dijadikan detection. Biaya penggantian per level di tabel Pyramid of Pain adalah penjabaran konsep Bianco [S4], bukan angka terukur. Contoh laporan intel di bagian 3.5 fiktif.
