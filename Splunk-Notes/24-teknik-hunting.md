---
day: 24
title: 'Teknik hunting: configuration, modeling (anomali), indicators, behavioral analytics'
researched_on: 2026-10-10
versions_checked: Dragos "The Four Types of Threat Detection" (Caltagirone & Lee, 13 Jul 2018) dan edisi OT (Pahl, Sep 2025); presentasi Robert M. Lee tentang CRASHOVERRIDE dan empat metode deteksi (2017); Splunk PEAK (Apr 2023); MITRE TTP-Based Hunting (2019); Splunk Enterprise 10.6 (SPL)
---

# Day 24: Teknik hunting (configuration, modeling, indicators, behavioral analytics)

Cakupan: mengidentifikasi teknik threat hunting, termasuk configuration, modeling (anomalies), indicators, dan behavioral analytics.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan empat kategori teknik deteksi/hunting, beserta kekuatan, kelemahan, dan contohnya.
- memilih kategori yang tepat untuk sebuah pertanyaan hunting, dan menyadari bahwa kombinasi kategori memberi gambaran terbaik.
- menulis SPL dasar untuk masing-masing kategori di data lab.
- menghubungkan kategori ini dengan tipe hunt PEAK (hypothesis, baseline, model-assisted).

## 2. Konteks singkat

Empat kategori teknik hunting yang dipakai di catatan ini sejalan dengan model "The Four Types of Threat Detection" dari Dragos (Sergio Caltagirone & Robert M. Lee, 2018), yaitu Configuration, Modeling, Indicator, Threat Behavior [S1]. Edisi 2025 (konteks OT) menyebutnya Configuration Changes, Network & Protocol Anomalies, Indicators of Compromise, Threat Behaviors [S2]. Model ini lahir di konteks ICS/OT, tetapi berlaku umum untuk IT.

Prinsip dari kedua dokumen: tidak ada satu tipe yang terbaik untuk semua lingkungan. Tipe-tipe ini bekerja bersama untuk gambaran paling akurat [S2].

Tiga istilah dasar yang dipakai di Day ini:

- **Threat hunting:** pencarian proaktif yang dipimpin manusia untuk menemukan aktivitas penyerang yang lolos dari detection yang ada. Bedanya dengan triage: hunting dimulai dari pertanyaan atau hipotesis, bukan dari alert.
- **PEAK** (Prepare, Execute, Act with Knowledge) adalah kerangka hunting Splunk (2023) dengan tiga tipe hunt: hypothesis-driven (menguji dugaan tentang perilaku penyerang), baseline (memahami normal lalu mencari penyimpangan), dan model-assisted (M-ATH, memakai model statistik atau machine learning untuk menyaring kandidat) [S3]. Langkah per fase dibahas di Day 25.
- **Pyramid of Pain** (David Bianco, 2013) mengurutkan jenis indikator dari yang paling mudah diganti penyerang sampai yang paling sulit: hash value, IP address, domain name, network/host artifacts, tools, lalu TTP di puncak. Makin tinggi indikator yang kamu deteksi, makin mahal bagi penyerang untuk menghindar.


## 3. Konsep inti

### 3.1 Empat kategori

| Kategori | Ide | Kekuatan | Kelemahan | Contoh IT/Splunk |
|---|---|---|---|---|
| Configuration | Pantau pengaturan, parameter, dan status sistem terhadap kondisi baik/kebijakan; alert pada penyimpangan | Menemukan kelemahan sebelum dieksploitasi | Tidak mendeteksi serangan aktif kecuali penyerang mengubah konfigurasi [S2] | Audit policy dimatikan, aturan firewall diubah, akun ditambahkan ke Domain Admins, Defender exclusion ditambah |
| Modeling (anomali) | Bangun baseline/profil perilaku normal, lalu tandai yang menyimpang | Bisa menemukan ancaman baru/zero-day tanpa IOC | FP bila model tidak menangkap variasi sah; berasumsi baseline "bersih" (bila sudah terkompromi saat baseline dibangun, penyerang ikut dianggap normal) [S2] | Volume keluar tak biasa, login di jam aneh, proses langka, koneksi antar host yang belum pernah terjadi |
| Indicator | Cocokkan pola/signature/atribut yang sudah diketahui (hash, IP, domain) | Sangat efektif untuk ancaman yang dikenal | Tidak mendeteksi serangan baru/kustom yang tidak cocok IOC [S2] | Threat match ES, retro-hunt IOC dari laporan intel (Day 16) |
| Threat behavior | Kenali TTP dan pola multi-tahap (lateral movement, exfiltration) | Lebih efektif untuk serangan kompleks dan multi-langkah; tidak bergantung IOC [S2] | Butuh keahlian mendalam tentang lingkungan dan ancaman [S2] | Detection berbasis ATT&CK, RBA multi-taktik (Day 17, 22) |

Behavioral analytics mencakup threat behavior, dan sering juga analitik perilaku user dan entitas (UEBA). Keduanya menilai perilaku, bukan artefak statis.

Atomic vs composite (Dragos 2025) [S2]:
- **Atomic:** satu atau dua titik metadata dari satu sumber. Indicator biasanya atomic.
- **Composite (correlation):** dua atau lebih event dari satu atau beberapa sumber. Banyak detection perilaku terbaik bersifat composite. Komponen-komponennya jinak bila berdiri sendiri, tetapi mencurigakan bila digabung.

Konsep ini sama persis dengan RBA (Day 22): sinyal lemah digabung menjadi temuan kuat.

### 3.2 Hubungan dengan PEAK dan Pyramid of Pain

| Kategori | Tipe hunt PEAK yang paling cocok | Posisi di Pyramid of Pain |
|---|---|---|
| Configuration | Hypothesis-driven ("penyerang menonaktifkan logging") | Network/host artifacts |
| Modeling | Baseline dan Model-Assisted (M-ATH) [S3] | Bervariasi |
| Indicator | Hypothesis/intel-driven (retro-hunt) | Hash/IP/domain (bawah) |
| Threat behavior | Hypothesis-driven berbasis TTP [S4] | TTP (puncak) |

### 3.3 Alat SPL per kategori

- **Configuration:** search atas event perubahan (Windows 4719 "System audit policy was changed"; 4728 anggota ditambahkan ke security-enabled global group, misalnya Domain Admins; 4732 anggota ditambahkan ke security-enabled local group, misalnya Administrators lokal; data model Change), lalu bandingkan dengan lookup "konfigurasi yang diharapkan".
- **Modeling:** `stats`/`eventstats` (rata-rata, simpangan baku, persentil), `streamstats` (deret waktu), command bawaan `anomalydetection`, cek opsi, dan Machine Learning Toolkit (MLTK) untuk model lebih lanjut, cek versi dan algoritma (mis. DensityFunction).
- **Indicator:** `lookup`/threat intel ES, `tstats` dengan subsearch IOC (Day 01 bagian 4.5).
- **Behavior:** detection berbasis data model + ATT&CK, RBA, `transaction`/`stats` untuk urutan (Day 02).

### 3.4 Matriks empat metode dan contoh CRASHOVERRIDE

Robert M. Lee (Dragos) menjelaskan keempat kategori dengan matriks 2x2 dalam presentasinya tentang CRASHOVERRIDE [S5]. Sumbu pertama: apakah deteksi berangkat dari pengetahuan tentang lingkungan (environment) atau tentang ancaman (threat). Sumbu kedua: apakah yang dicari sudah diketahui (known) atau belum (unknown).

| | Environment | Threat |
|---|---|---|
| Unknown | Statistical modeling | Behavioral analytics |
| Known | Configuration analysis | Indicators |

Cara membacanya:

- **Configuration analysis** (environment, known): kamu tahu persis seperti apa kondisi yang benar, lalu mencari penyimpangannya.
- **Statistical modeling** (environment, unknown): kamu belum tahu penyimpangan apa yang akan muncul, jadi kamu memodelkan normal dan menandai yang berbeda.
- **Indicators** (threat, known): kamu tahu artefak ancaman tertentu dan mencarinya.
- **Behavioral analytics** (threat, unknown): kamu tidak tahu artefak persisnya, tetapi tahu cara penyerang bekerja, sehingga deteksi tetap jalan walaupun tool dan infrastrukturnya berganti.

Slide yang sama menekankan prasyarat keahliannya. Kolom environment (configuration dan modeling) menuntut pengetahuan sistem yang dalam: protokol, perilaku vendor, kemampuan deep packet inspection. Kolom threat (indicators dan behavioral) menuntut pengetahuan ancaman yang dalam: pengalaman incident response dan analisis intrusi. Di SOC, ini berarti hunt configuration dan modeling paling baik dikerjakan bersama pemilik sistem, sedangkan hunt behavioral butuh analyst yang paham TTP.

**Latar CRASHOVERRIDE** [S5]. Pada 17 Desember 2016 pukul 23.53 waktu setempat, sebuah substation transmisi milik Ukrenergo di Ukraina padam dan menyebabkan pemadaman di wilayah layanannya. Dragos menamai malware-nya CRASHOVERRIDE (vendor lain menyebutnya Industroyer) dan mengaitkannya dengan kelompok aktivitas yang mereka sebut ELECTRUM. Poin penting dari analisisnya:

- Ini keluarga malware keempat yang dibuat khusus untuk sistem kontrol industri (setelah Stuxnet, Havex, dan BlackEnergy2), dan yang kedua (setelah Stuxnet) yang memang dimaksudkan mengganggu proses fisik.
- Kemampuannya: manipulation of control, denial of control, denial of view, dan penghapusan data.
- Strukturnya modular: backdoor utama yang beaconing lewat proxy internal dan menerima perintah bertahap dari C2, backdoor cadangan, launcher yang menjalankan modul payload untuk protokol IEC 60870-5-101, IEC 60870-5-104, IEC 61850, dan OPC DA, serta modul wiper untuk memperlambat pemulihan.
- Cara masuk awalnya tidak diketahui Dragos. Yang jelas, efek ICS hanya mungkin setelah penyerang punya pijakan dan melakukan pengintaian lebih dulu.

**Empat metode pada modul IEC 104** [S5]. Slide memakai modul IEC 104 (yang berjalan di HMI dan mengirim perintah ke RTU) sebagai contoh bagaimana tiap metode akan melihat serangan yang sama:

| Metode | Apa yang akan terlihat |
|---|---|
| Configuration analysis | Proses baru muncul di HMI; mungkin ada port komunikasi baru yang tidak ada di konfigurasi standar |
| Statistical modeling | Protokol IEC 104 belum pernah dipakai dengan cara seperti itu; perintah yang dikirim anomali dibanding riwayat |
| Indicators | IP address atau hash file yang sudah dikaitkan dengan CRASHOVERRIDE |
| Behavioral analytics | Cara IEC 104 dipakai, digabung dengan informasi lain (proses baru, backdoor yang beaconing lewat proxy), cocok dengan tradecraft CRASHOVERRIDE |

Pelajaran yang bisa langsung dibawa ke lingkungan IT: indicator baru berguna setelah ada yang menganalisis serangannya, sehingga tidak membantu korban pertama. Configuration dan modeling bisa menangkap serangan pertama, tetapi hanya bila kamu sudah tahu kondisi normal sistemmu. Behavioral analytics bertahan paling lama karena penyerang harus mengganti cara kerjanya, bukan sekadar mengganti IP atau mengompilasi ulang biner. Padanan IT dari tabel di atas: proses baru di server kritis (configuration), proses atau koneksi yang belum pernah terlihat (modeling), hash dari laporan intel (indicator), dan rangkaian discovery, credential access, lalu lateral movement pada satu host (behavior, bagian 4.5).

### 3.5 Enterprise vs ES

Semua kategori bisa dijalankan dengan SPL di Splunk Enterprise. ES menambah:
- threat intel framework (indicator);
- RBA (behavior/composite);
- dashboard dan detection terkelola.

Analitik perilaku lanjutan (UEBA) adalah produk/fitur terpisah, cek penamaan dan ketersediaannya di ES 8.x (Day 08).

## 4. Contoh SPL dan langkah di ES

> Keluaran berlabel ilustrasi. Asumsi index lab: `wineventlog`, `sysmon`.

### 4.1 Configuration: perubahan audit policy dan grup sensitif

```
index=wineventlog sourcetype="XmlWinEventLog:Security" (EventCode=4719 OR EventCode=4728 OR EventCode=4732) earliest=-7d
| eval change=case(EventCode=4719,"audit policy changed", in(EventCode,"4728","4732"),"member added to group", true(),"other")
| stats count values(TargetUserName) AS target values(MemberName) AS member BY host SubjectUserName change
```

- Penyerang sering mematikan audit atau menambah dirinya ke grup admin. Di ATT&CK v19, ini wilayah Defense Impairment dan Persistence/Privilege Escalation (Day 15).
- Nama field (`SubjectUserName`, `TargetUserName`, `MemberName`) bergantung TA/format, perlu dicek.
- **Penjelasan jinak:** perubahan terjadwal oleh admin. Cocokkan dengan tiket perubahan.

### 4.2 Modeling: login di luar pola jam normal per user (baseline 30 hari)

```
| tstats summariesonly=false count from datamodel=Authentication.Authentication
    where Authentication.action="success" earliest=-30d@d
    by _time span=1h Authentication.user
| rename Authentication.* AS *
| eval hour=tonumber(strftime(_time,"%H"))
| stats sum(count) AS logins BY user hour
| eventstats sum(logins) AS total BY user
| eval share=round(logins/total*100,2)
| where share < 1 AND logins >= 1
| sort user hour
```

- `sum(count)`, bukan `count`: setelah `tstats ... by _time span=1h`, setiap baris adalah satu jam dengan field `count` berisi jumlah login. `stats count` hanya akan menghitung jumlah baris (jam), bukan jumlah login.
- Untuk setiap user, cari jam yang hampir tidak pernah dipakai (<1% login). Ini contoh baseline sederhana.
- **Kelemahan (sesuai Dragos):** bila akun sudah dipakai penyerang selama 30 hari baseline, pola penyerang ikut menjadi "normal" [S2].
- **Variasi:** jalankan baseline 30 hari, lalu bandingkan dengan 24 jam terakhir. Atau pakai `anomalydetection`/MLTK untuk model yang lebih formal.

### 4.3 Modeling: outlier volume dengan z-score

```
| tstats summariesonly=false sum(All_Traffic.bytes_out) AS out from datamodel=Network_Traffic.All_Traffic
    where earliest=-14d@d by _time span=1d All_Traffic.src
| rename All_Traffic.* AS *
| eventstats avg(out) AS avg stdev(out) AS sd BY src
| eval z=if(sd>0, round((out-avg)/sd,2), 0)
| where z >= 3 AND _time >= relative_time(now(),"-1d@d")
```

- z-score per host terhadap riwayatnya sendiri (bukan rata-rata global, berbeda dengan Day 15 bagian 4.3).
- Day 25 membahas long tail dan outlier lebih dalam.

### 4.4 Indicator: retro-hunt IOC dari laporan intel

```
| tstats summariesonly=false count min(_time) AS first max(_time) AS last
    from datamodel=Network_Resolution.DNS
    where [ | inputlookup lab_ioc_domains.csv | rename domain AS DNS.query | fields DNS.query ] earliest=-90d
    by DNS.src DNS.query
| rename DNS.* AS *
| convert ctime(first) ctime(last)
```

- Subsearch menghasilkan daftar `DNS.query=...` (pola Day 01 bagian 4.5).
- Rentang 90 hari untuk retro-hunt: apakah IOC baru ini pernah muncul sebelumnya?
- Perhatian: Batas subsearch (Day 05). Untuk ribuan IOC, gunakan `lookup` setelah agregasi.

### 4.5 Behavior: discovery yang diikuti credential access pada satu host (composite)

```
| tstats summariesonly=false count values(Processes.process_name) AS procs
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("whoami.exe","net.exe","nltest.exe","quser.exe")
        OR Processes.process="*lsass*" OR Processes.process="*sekurlsa*")
      earliest=-24h
    by _time span=30m Processes.dest Processes.user
| rename Processes.* AS *
| eval discovery=if(match(mvjoin(procs," "),"(whoami|net|nltest|quser)"),1,0),
       cred=if(match(mvjoin(procs," "),"lsass|sekurlsa"),1,0)
| where discovery=1 AND cred=1
```

- **Composite:** discovery saja (jinak, dilakukan admin) dan pola akses LSASS saja (bisa alat sah) digabung dalam jendela 30 menit.
- Pola `*lsass*` di command line hanyalah salah satu procedure. Akses memori LSASS lebih baik dideteksi lewat Sysmon EID 10 (Day 08), cek pemetaan ke CIM.
- Ini sebaiknya dijadikan RBA (intermediate finding per komponen) daripada satu detection kaku (Day 22).

### 4.6 Di ES (generik)

- Indicator: threat intelligence framework/threat match (Day 16).
- Behavior/composite: RBA dengan incident rule multi-taktik (Day 22).
- Modeling: dashboard Predictive analytics (Day 21) dan/atau MLTK, perlu dicek.
- Configuration: detection atas data model Change dan audit.

## 5. Lab praktik

1. **Configuration:** di VM Windows lab (snapshot), ubah satu audit policy (mis. `auditpol /set /subcategory:"Process Creation" /success:disable`, lalu kembalikan dengan `/success:enable`) dan tambahkan user uji ke grup Administrators lokal. Jalankan bagian 4.1. Kembalikan setelahnya.
2. **Modeling:** jalankan bagian 4.2 dan 4.3 dengan data lab minimal 14 hari. Bila data sedikit, catat bahwa baseline lemah. Itu juga temuan.
3. **Indicator:** buat `lab_ioc_domains.csv` (domain `.example` buatan sendiri), lakukan `nslookup` ke salah satunya dari VM, lalu jalankan bagian 4.4.
4. **Behavior:** jalankan `whoami`, `net user`, `nltest /dclist:` di VM lab, lalu jalankan bagian 4.5. Untuk komponen credential, gunakan Atomic Red Team yang jinak untuk T1003.001 hanya bila aman di lab terisolasi, cek test dan dampaknya. Alternatifnya, simulasi dengan `makeresults`.
5. Isi tabel: kategori | hipotesis | query | hasil (ditemukan / tidak / data kurang) | kelemahan.

**Hasil yang sebaiknya tersimpan:**
- Satu hunt per kategori (4) dijalankan dan dicatat.
- Untuk modeling, asumsi baseline dan risikonya dicatat.
- Composite bagian 4.5 menghasilkan temuan dari aktivitas lab.

**Variasi tantangan:** ubah bagian 4.5 menjadi tiga risk rule kecil (Day 22) dan biarkan incident rule menggabungkannya. Bandingkan jumlah alert dan kejelasan konteksnya.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Perbaikan |
|---|---|---|
| Modeling memberi banyak FP | Baseline pendek; variasi sah tidak tertangkap (shift kerja, akhir bulan) | Perpanjang baseline; segmentasi per grup user/host [S2] |
| Modeling tidak menemukan apa pun padahal ada insiden | Baseline "tercemar" penyerang | Gunakan baseline dari periode yang diketahui bersih; kombinasikan dengan behavior [S2] |
| Indicator tidak pernah cocok | IOC basi; format berbeda | Normalisasi; masa berlaku IOC (Day 16) |
| Configuration event tidak ada | Audit policy tidak mencatat perubahan | Aktifkan subkategori audit terkait, perlu dicek |
| Composite terlalu ketat | Jendela waktu terlalu pendek | Perlebar jendela; pakai RBA |

## 7. Kesalahan umum dan jebakan

- Mencari satu teknik terbaik. Dragos menegaskan tidak ada tipe terbaik untuk semua lingkungan [S2].
- Percaya baseline tanpa mempertanyakan kebersihannya [S2].
- Menganggap hunting IOC sebagai hunting matang. IOC ada di dasar Pyramid of Pain (bagian 2), sehingga mudah dihindari penyerang.
- Composite detection tanpa dokumentasi komponen. Analyst bingung saat triage.
- `[komunitas]` Kategori bersumber dari whitepaper dan presentasi Dragos (vendor). Contoh SPL di bagian 4 adalah terjemahan kategori itu ke data IT, bukan contoh dari Dragos.

## 8. Catatan terkini

- Dragos (Sep 2025) menerbitkan ulang kerangka empat tipe untuk OT dengan studi kasus TRISIS, plus konsep atomic vs composite dan sumber telemetri (network, host Windows/Sysmon, asset enrichment) [S2].
- ATT&CK v19 memisahkan Defense Impairment. Hunting configuration (mematikan logging/alat keamanan) kini memetakan ke taktik itu (Day 15).
- PEAK tetap menjadi kerangka hunting Splunk dengan tipe Baseline dan M-ATH untuk modeling [S3].

## 9. Cheat sheet

```
CONFIGURATION   penyimpangan dari setelan baik (audit policy, grup admin, firewall, AV exclusion) -> temukan kelemahan; lemah utk serangan aktif
MODELING        baseline -> deviasi (jam login, volume, proses langka) -> temukan yg baru; FP & baseline tercemar
INDICATOR       cocokkan IOC (hash/IP/domain) -> efektif utk yg dikenal; buta utk yg baru
BEHAVIOR        TTP/multi-tahap -> efektif utk kompleks; butuh keahlian
ATOMIC vs COMPOSITE  satu titik vs gabungan event (jinak sendiri, berbahaya bersama) ~ RBA
SPL   config: Change DM / 4719 4728 4732 | modeling: eventstats avg/stdev, z-score, anomalydetection, MLTK
      indicator: tstats + subsearch lookup / threat match | behavior: DM + ATT&CK + RBA, stats/transaction urutan
PEAK  modeling -> Baseline / M-ATH ; behavior & config -> Hypothesis
MATRIKS (Lee)  environment: known=configuration, unknown=modeling | threat: known=indicator, unknown=behavioral
CRASHOVERRIDE  Ukraina 17-12-2016 ; modul IEC 101/104/61850/OPC DA + wiper ; config=proses baru di HMI, model=perintah IEC 104 anomali, IOC=IP/hash, behavior=tradecraft gabungan
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Dragos: The Four Types of Threat Detection (Caltagirone & Lee) | https://www.manufacturing.net/home/whitepaper/13245081/dragos-the-four-types-of-threat-detection | sekunder (vendor) | 2018-07-13 | Tinggi untuk kategori (karya asli); isi kategori juga tercakup di S2 dan S5 |
| S2 | Dragos: The Four Types of OT Threat Detection in The Dragos Platform (Pahl) | https://dragos.brightspotcdn.com/3e/f8/aefcee7f41b6b19a02b410ac5722/four-types-threat-detection-whitepaper-09-25.pdf | sekunder (vendor) | 2025-09; diakses 2026-10-07 | Tinggi untuk definisi; ada konten pemasaran produk |
| S3 | Splunk: PEAK Threat Hunting Framework | https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html | primer (vendor) | 2023-04-18 | Tinggi |
| S4 | MITRE: TTP-Based Hunting (lihat Day 17) | https://www.mitre.org/news-insights/publication/ttp-based-hunting | primer | 2019-03 | Tinggi |
| S5 | Robert M. Lee (Dragos): CRASHOVERRIDE and Detailing Different Types of Detection, slide presentasi yang dihosting SANS | https://www.sans.org/media/vendor/CRASHOVERRIDE-and-Detailing-Different-Types-of-Detection-Robert%20Lee.pdf | sekunder (vendor, slide) | 2017 (tahun disimpulkan dari isi); diakses 2026-10-10 | Sedang-tinggi. Tautan lama tanpa encoding spasi tidak lagi bisa dibuka; isi yang dipakai sudah dirangkum di bagian 3.4 |

**Catatan sumber:** opsi `anomalydetection` dibahas dengan sumber di Day 25; algoritma MLTK bergantung versi dan perlu dicek. Nama field Windows (`SubjectUserName`, `MemberName`) bergantung TA dan format log. Matriks 2x2 dan contoh CRASHOVERRIDE di bagian 3.4 berasal dari slide presentasi [S5]; slide tidak mencantumkan tanggal, sehingga tahun 2017 disimpulkan dari linimasa di dalamnya. Nama "Configuration, Modeling (Anomalies), Indicators, Behavioral Analytics" dipakai Dragos di beberapa materi, tetapi urutan dan labelnya sedikit berbeda antar dokumen.
