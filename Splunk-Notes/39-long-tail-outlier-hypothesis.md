---
day: 39
title: Long tail analysis, outlier detection, dan langkah hypothesis hunting dengan Splunk
researched_on: 2026-10-10
versions_checked: Splunk PEAK hypothesis-driven hunting (David Bianco, 8 Mei 2023); SPL Search Reference 10.2 (rare, anomalydetection); Splunk Enterprise 10.6
---

# Day 39: Long tail, outlier, dan hypothesis hunting

Cakupan: mendefinisikan long tail analysis, outlier detection, dan beberapa langkah umum hypothesis hunting dengan Splunk.

## Ide inti

Day 38 membagi hunting menjadi empat kategori dan menyisakan satu yang paling banyak butuh teknik, yaitu modeling: membangun gambaran normal lalu mencari yang menyimpang. Day ini masuk ke teknik statistiknya, dan di praktiknya ada dua bentuk yang sering tertukar padahal jenis datanya berbeda. Long tail memperlakukan data sebagai kategori: kelompokkan (stack) nilai, hitung frekuensinya, lalu baca dari yang paling jarang, karena penyerang sering tampak sebagai sesuatu yang langka, misalnya proses yang hanya ada di satu host, user-agent unik, atau service yang baru diinstal. Outlier memperlakukan data sebagai angka: ukur seberapa jauh sebuah nilai dari pusat distribusinya, karena penyerang juga bisa tampak sebagai sesuatu yang ekstrem, misalnya volume keluar yang besar, frekuensi tinggi, atau interval yang sangat teratur. Keduanya jarang berguna sebagai tujuan sendiri. Tempatnya di dalam hunt berbasis hipotesis, dan kerangka yang dipakai di catatan ini adalah PEAK, yang di Day 38 baru disebut namanya dan di sini dibuka sampai lima belas langkahnya.

Analoginya dari pekerjaan NOC ada dua, dan keduanya dipakai sepanjang Day ini. Pertama, grafik trafik satu interface dibaca terhadap riwayat interface itu sendiri, bukan terhadap rata-rata seluruh POP, karena link akses pelanggan rumah dan uplink data center tidak pernah bisa dibandingkan langsung. Kedua, pola yang terlalu rapi di grafik justru mencurigakan: trafik manusia bergelombang, sedangkan jejak polling muncul sebagai gigi yang sama tinggi pada setiap interval. Batas analoginya bekerja di dua arah. Rata-rata populasi menyembunyikan entitas kecil yang menyimpang, sehingga daftar outlier selalu dimenangkan server sibuk dan workstation yang dipakai penyerang tidak pernah muncul. Sebaliknya keteraturan interval juga ciri agen monitoring, update checker, dan NTP yang sah, jadi ia penyaring untuk mempersempit daftar, bukan bukti. Hal yang sama berlaku di sisi long tail: langka hanyalah kandidat.

**Kapan relevan:** saat ada hipotesis yang bisa diuji dengan pertanyaan "apa yang jarang" atau "apa yang ekstrem"; saat daftar hasil terlalu panjang untuk dibaca dan perlu diurutkan menurut prioritas; saat mencari C2 lewat keteraturan interval; dan saat sebuah hunt perlu dikerjakan dengan cara yang bisa diulang serta diserahkan ke orang lain.
**Kapan bukan jawaban:** long tail dan outlier bukan detection. Keduanya menghasilkan daftar kandidat yang harus ditinjau manusia, dan menjadwalkannya sebagai alert hampir selalu menenggelamkan antrean. Keduanya juga tidak tepat untuk pertanyaan yang bentuk jawabannya sudah diketahui, karena untuk itu detection berbasis TTP lebih langsung (Day 36). Pada data yang sangat condong, z-score menyesatkan, dan pada entitas yang perannya berbeda, baseline populasi tidak sah. Bila baseline yang dibutuhkan lebih panjang daripada retensi data mentah, wadah penyimpanannya dibahas di Day 40.

## 1. Konsep inti

### 1.1 Long tail analysis

Ide dasarnya: kelompokkan (stack) nilai, hitung frekuensinya, lalu urutkan dari yang paling jarang. Distribusi data TI biasanya sangat condong: sedikit nilai sangat sering (kepala), banyak nilai jarang (ekor panjang). Aktivitas berbahaya cenderung berada di ekor, karena malware atau perilaku penyerang tidak muncul di ribuan host.

Alat SPL:
- `rare <field> [by ...]`: kebalikan `top`; mengembalikan kombinasi nilai paling jarang. Default `limit=10` (maks 50.000). Menambah `count` dan `percent` [S2].
- `stats count dc(host) BY <field> | sort count`: versi yang lebih fleksibel karena bisa menambah konteks seperti `dc(host)`, `values()`.
- `tstats` untuk skala besar (Day 25).

**Kunci interpretasi:** langka tidak sama dengan jahat. Software khusus satu departemen juga langka. Long tail menghasilkan daftar kandidat yang harus ditinjau, bukan alert.

**Dimensi yang berguna untuk di-stack:**
- proses: `process_name` + `process_path`;
- pasangan parent dan child process (misalnya `winword.exe` yang memunculkan `powershell.exe` jauh lebih jarang dan lebih mencurigakan daripada `explorer.exe` yang memunculkan `powershell.exe`);
- user-agent;
- service yang diinstal;
- persistence autorun;
- domain yang di-resolve;
- port tujuan per host.

### 1.2 Outlier detection

Ide dasarnya: ukur seberapa jauh sebuah nilai dari pusat distribusinya, per entitas atau per grup.

Metode:
- **z-score:** (nilai - rata-rata) / simpangan baku. Sederhana, tetapi peka terhadap outlier yang ikut membentuk rata-rata.
- **IQR / persentil:** batas atas = Q3 + 1,5xIQR, atau di atas p99. Lebih tahan terhadap data condong.
- **Per-entity baseline:** bandingkan host dengan riwayatnya sendiri, bukan dengan seluruh populasi (Day 38 bagian 2.3).

Command `anomalydetection` [S3]:
- metode histogram (default; probabilitas berbasis frekuensi nilai), zscore (seperti `anomalousvalue`, pthresh default 0,01), dan iqr (seperti `outlier`);
- aksi `filter` (default; hanya event anomali), `annotate` (semua event + field anomali), `summary`;
- untuk IQR: `transform` (default; memotong nilai ekstrem) atau `remove`;
- field hasil: `log_event_prob`, `probable_cause` (field yang paling menjelaskan anomali), `probable_cause_freq`, `max_freq`.

### 1.3 Long tail vs outlier

| | Long tail | Outlier |
|---|---|---|
| Pertanyaan | "Apa yang jarang terlihat?" | "Apa yang ekstrem dibanding normal?" |
| Data | Kategori (nama proses, domain, user-agent) | Numerik (bytes, jumlah, durasi, interval) |
| SPL khas | `rare`, `stats count ... \| sort count` | `eventstats avg stdev`, `perc`, `anomalydetection` |
| FP khas | Software khusus yang sah | Backup, update, pekerjaan batch |

### 1.4 Langkah hypothesis hunting (PEAK)

Hunt berbasis hipotesis menurut PEAK punya tiga fase, masing-masing lima langkah [S1]:

| Fase | Langkah |
|---|---|
| Prepare | 1. Select topic; 2. Research topic; 3. Generate hypothesis (dugaan yang bisa diuji); 4. Scope hunt (sistem, data, dan rentang waktu); 5. Plan (alat, teknik, sumber daya) |
| Execute | 1. Gather data; 2. Pre-process data (bersihkan dan standarkan); 3. Analyze (pola, anomali, bukti yang mendukung/membantah); 4. Refine hypothesis; 5. Escalate critical findings (ke IR) |
| Act | 1. Preserve hunt (arsip metode, data, alat); 2. Document findings (termasuk celah); 3. Create detections; 4. Re-add topic to backlog; 5. Communicate findings |

Long tail dan outlier adalah teknik di langkah Analyze. Contohnya, hipotesis "penyerang memakai C2 HTTP berinterval tetap" dianalisis dengan outlier pada keteraturan interval (bagian 2.4).

Sebagai pembanding, TaHiTI (Targeted Hunting integrating Threat Intelligence), metodologi yang disusun komunitas sektor keuangan Belanda pada 2018, memakai tiga fase: Initiate (pemicu hunt dicatat ke backlog), Hunt (definisi, penyempurnaan, dan eksekusi) dan Finalize (dokumentasi serta serah terima ke proses lain seperti detection engineering atau incident response). Strukturnya serupa dengan PEAK: sama-sama memisahkan persiapan, eksekusi, dan tindak lanjut.

**Tanpa ES:** semua teknik di Day ini adalah SPL inti Splunk Enterprise dan dikerjakan di app Search & Reporting, jadi tidak ada satu pun contoh di bagian 2 yang mensyaratkan Enterprise Security. Yang ditambahkan ES adalah konteks: Asset & Identity untuk memisahkan baseline menurut peran aset, dan risk score untuk menampung hasil hunt yang belum pantas menjadi alert (Day 26 dan Day 35). Di PT JAB, Asset & Identity belum lengkap karena aset POP dan perangkat pelanggan belum masuk, sehingga segmentasi per peran untuk sementara dikerjakan dengan lookup inventaris sendiri. Machine Learning Toolkit menambah algoritma yang lebih formal daripada z-score dan IQR; cek versi MLTK dan daftar algoritma yang tersedia di instance-mu.

## 2. Contoh SPL dan langkah di ES

> Keluaran berlabel ilustrasi. Asumsi data lab Sysmon/Network_Traffic/Web. Cek nama field.

### 2.1 Long tail: proses paling jarang di seluruh host

```
| tstats summariesonly=false count dc(Processes.dest) AS hosts values(Processes.dest) AS host_list
    from datamodel=Endpoint.Processes where earliest=-14d
    by Processes.process_name Processes.process_path
| rename Processes.* AS *
| where hosts <= 2
| sort count
| head 50
```

- `dc(dest)` membedakan "jarang karena sedikit host" dari "jarang karena jarang dijalankan".
- **Cara membaca hasil:** biner di `C:\Users\<user>\AppData\` atau `C:\ProgramData\` yang hanya ada di satu host adalah kandidat. Biner di `Program Files` vendor khusus biasanya jinak.

### 2.2 Long tail dengan `rare`: user-agent paling jarang per segmen

```
index=botsv1 sourcetype=stream:http earliest=0
| rare http_user_agent limit=20 showperc=true
```

- `rare` cepat untuk eksplorasi [S2].
- **Cara membaca hasil:** user-agent scanner (mis. memuat nama alat) atau string yang sangat pendek/aneh layak ditinjau.

### 2.3 Outlier: jumlah koneksi keluar per host (IQR, tahan data condong)

```
| tstats summariesonly=false count AS conns from datamodel=Network_Traffic.All_Traffic
    where earliest=-24h by All_Traffic.src
| rename All_Traffic.* AS *
| eventstats perc25(conns) AS q1 perc75(conns) AS q3
| eval iqr=q3-q1, upper=q3+1.5*iqr
| where conns > upper
| sort - conns
```

Alternatif dengan command bawaan:

```
... | stats count AS conns BY src
| anomalydetection method=iqr action=remove conns
```

Perhatikan bahwa `action=remove` membuang outlier [S3]. Untuk hunting, kita justru ingin melihat outlier, jadi versi `eventstats` di atas lebih tepat. Gunakan `method=histogram action=annotate` untuk menandai event anomali beserta `probable_cause` [S3].

### 2.4 Outlier pada keteraturan: beaconing sederhana

**Hipotesis:** "Satu host berkomunikasi ke tujuan eksternal dengan interval sangat teratur (C2)."

```
| tstats summariesonly=false count from datamodel=Network_Traffic.All_Traffic
    where earliest=-24h All_Traffic.dest_port=443 by _time span=1s All_Traffic.src All_Traffic.dest
| rename All_Traffic.* AS *
| sort 0 src dest _time
| streamstats current=f last(_time) AS prev BY src dest
| eval delta=_time-prev
| stats count AS conns avg(delta) AS avg_gap stdev(delta) AS sd_gap BY src dest
| where conns >= 20
| eval jitter=round(sd_gap/avg_gap,3)
| where jitter < 0.1
| sort jitter
```

| Langkah | Fungsi |
|---|---|
| `span=1s` + `sort` | Deret koneksi per pasangan src->dest |
| `streamstats current=f last(_time) AS prev BY src dest` | Waktu koneksi sebelumnya (centralized streaming, Day 14) |
| `delta` | Interval antar koneksi |
| `jitter = sd/avg` | Koefisien variasi. Mendekati 0 berarti sangat teratur |
| `conns >= 20` | Cukup sampel |

- **Penjelasan jinak:** agen monitoring, update check, NTP, dan Wazuh/Splunk forwarder (interval teratur). Bandingkan dengan daftar tujuan yang diketahui (lookup).
- Beaconing canggih menambah jitter acak. Ambang 0,1 adalah ilustrasi. Koefisien variasi (stdev dibagi rata-rata) mudah rusak oleh satu interval panjang, misalnya saat laptop tidur semalam. Versi yang lebih tahan memakai median dan median absolute deviation (MAD) seperti di bawah.

Varian tahan jitter dan interval ekstrem (menggantikan baris setelah `eval delta=...`):

```
| stats count AS conns median(delta) AS med_gap values(delta) AS gaps BY src dest
| where conns >= 20
| mvexpand gaps
| eval absdev=abs(gaps-med_gap)
| stats first(conns) AS conns first(med_gap) AS med_gap median(absdev) AS mad BY src dest
| eval robust_jitter=round(mad/med_gap,3)
| where robust_jitter < 0.15
| sort robust_jitter
```

- `median(delta)` tidak terpengaruh beberapa interval sangat panjang, sehingga beacon 60 detik yang terputus semalam tetap terlihat teratur.
- MAD dibagi median adalah padanan "tahan outlier" dari koefisien variasi. Beacon dengan jitter acak plus minus 20% biasanya menghasilkan nilai di kisaran 0,1; trafik manusia yang membuka situs biasanya jauh di atas 0,5. Angka ini ilustrasi dan perlu dikalibrasi.
- `values(delta)` membuang duplikat. Untuk beacon sangat teratur itu tidak masalah, karena yang dicari adalah sebaran nilai interval. Bila ingin presisi penuh, ganti dengan `list(delta)` dan perhatikan batas 100 nilai default `list`.

### 2.5 Satu hunt PEAK lengkap (template singkat)

```
PREPARE  Topic: persistence via services | Research: ATT&CK T1543.003 Windows Service
         Hypothesis: "Ada service baru di workstation lab dalam 14 hari terakhir yang biner-nya di lokasi user-writable"
         Scope: semua host Windows lab, 14 hari, Sysmon/Windows System log | Plan: SPL long tail + lookup baseline
EXECUTE  Gather: event 7045 "A service was installed" (log System) | Pre-process: normalisasi path (lower, ganti versi)
         Analyze: stack service_name+path -> long tail; filter path user-writable | Refine | Escalate bila ditemukan
ACT      Preserve: simpan SPL + hasil | Document: hasil (ditemukan / tidak / data kurang) + celah
         Create detection: "service baru dari path user-writable" (Day 36) | Backlog | Communicate
```

### 2.6 Studi kasus fiktif: dari long tail ke detection

Konteks: lab berisi 40 workstation Windows. Hipotesis: "Ada persistence lewat service yang binernya berada di lokasi yang bisa ditulis user."

1. **Gather.** Event 7045 dari log System (Service Control Manager mencatat service yang baru diinstal) selama 14 hari: 212 event.
2. **Pre-process.** Path dinormalisasi: huruf kecil, nama user diganti `<user>`, nomor versi diganti `<ver>`. Jumlah kombinasi unik service dan path turun dari 97 menjadi 31. Tanpa normalisasi, setiap update Chrome atau agen backup akan tampak sebagai nilai langka.
3. **Analyze (long tail).** Setelah stacking, 26 kombinasi muncul di lebih dari 10 host (agen EDR, updater browser, driver printer). Lima sisanya hanya ada di satu atau dua host. Keluaran ilustrasi:

```
service_name     image_path_norm                                   hosts  count
UpdateSvcHelper  c:\users\<user>\appdata\roaming\svc\uh.exe         1      1
VendorScanAgent  c:\program files\vendor\scan\agent.exe                2      2
PrintFixSvc      c:\windows\temp\pf.exe                                1      1
LabBackupAgent   c:\program files\labbackup\<ver>\agent.exe            2      4
DiagTrackLite    c:\programdata\diag\dtl.exe                           1      1
```

4. **Refine.** Dua path di `Program Files` dicocokkan dengan inventaris software dan dinyatakan jinak. Tiga sisanya berada di lokasi yang bisa ditulis user (`AppData`, `Windows\Temp`, `ProgramData`). Ketiganya diperiksa: dua berasal dari skrip uji lab yang kamu jalankan sendiri, satu (`UpdateSvcHelper`) dibuat oleh test Atomic Red Team untuk T1543.003 yang lupa dibersihkan.
5. **Act.** Hasil dicatat sebagai "ditemukan, jinak, tetapi membuktikan bahwa jalur ini terlihat". Detection baru dibuat: service baru dengan image path di lokasi user-writable, output intermediate finding dengan skor 30 (Day 35-36), karena software sah sesekali juga melakukannya. Hunt dimasukkan kembali ke backlog dengan catatan: ulangi setelah onboarding log server.

Yang membuat hunt ini berguna bukan temuannya, tetapi tiga artefaknya: daftar baseline service yang sah, aturan normalisasi path, dan satu detection yang sebelumnya tidak ada.

### 2.7 Di ES (generik)

- Hasil hunt yang ditemukan dieskalasikan menjadi investigation (Mission Control) dengan response plan (Day 33).
- Detection yang lahir dari hunt dibuat sebagai event-based detection, sering sebagai intermediate finding/RBA (Day 35-36).

## 3. Lab praktik

1. Jalankan bagian 2.1 di data lab 14 hari. Tinjau 10 baris teratas dan beri label jinak / perlu investigasi.
2. Jalankan bagian 2.2 di BOTS v1. Identifikasi user-agent scanner (metode, bukan jawaban CTF).
3. Jalankan bagian 2.3 dengan dua metode (eventstats IQR vs `anomalydetection method=histogram action=annotate`). Bandingkan hasilnya.
4. **Beaconing lab:** di VM Linux lab, jalankan loop `curl` ke server web lab setiap 60 detik selama 30 menit (`while true; do curl -s http://<lab-web>/ >/dev/null; sleep 60; done`). Jalankan bagian 2.4 dengan `dest_port` yang sesuai. Hasil yang diharapkan: jitter mendekati 0.
5. Jalankan satu hunt PEAK penuh (bagian 2.5) dan dokumentasikan semua 15 langkah, termasuk bila hasilnya "tidak ditemukan".

**Hasil yang sebaiknya tersimpan:**
- Daftar long tail berlabel.
- Perbandingan dua metode outlier.
- Beaconing lab terdeteksi dengan jitter rendah.
- Laporan hunt PEAK lengkap.

**Variasi tantangan:** tambahkan jitter acak sekitar plus minus 20% pada loop beaconing (`sleep $((50 + RANDOM % 20))`). Lalu ubah bagian 2.4 agar tetap menangkapnya, misalnya memakai median interval dan rasio interquartile alih-alih stdev.

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Perbaikan |
|---|---|---|
| Long tail berisi ribuan nilai | Path mengandung versi/nama user/GUID | Normalisasi dengan `rex mode=sed`/`replace` (Day 11) |
| Outlier didominasi server sibuk | Membandingkan host berbeda peran | Segmentasi per peran (A&I category, Day 26); baseline per host |
| Beaconing tidak terdeteksi | Data flow teragregasi (bukan per koneksi); jitter tinggi | Pakai sumber per koneksi (Zeek conn, firewall); metrik tahan jitter |
| `anomalydetection` membuang outlier | `method=iqr` default `transform`/`remove` | Pakai `annotate` atau versi eventstats [S3] |
| Hunt tidak pernah selesai | Tidak ada scope/kriteria | Langkah Scope dan Plan PEAK [S1] |

## 5. Kesalahan umum dan jebakan

- Langka = jahat. Langka hanyalah kandidat.
- z-score pada data sangat condong. Gunakan persentil/IQR.
- Baseline populasi untuk entitas heterogen. Server dan laptop tidak bisa dibandingkan langsung.
- Melewatkan langkah Act (preserve, document, detection). Hunt tanpa jejak tidak bisa diulang [S1].
- Mengabaikan "tidak ditemukan". Itu hasil sah bila scope dan celah datanya dicatat.
- `[komunitas]` Deteksi beaconing berbasis keteraturan interval adalah pendekatan umum di komunitas network security monitoring. Ambang jitter dan jumlah koneksi minimum tidak punya angka baku; kalibrasi dengan trafik jinak di lab-mu.

## 6. Catatan terkini

- PEAK (2023) tetap menjadi kerangka hunting resmi Splunk. Langkah hypothesis-driven berjumlah 15 (5 per fase) [S1].
- **SPL 10.2:** `anomalydetection` menggabungkan kemampuan `anomalousvalue` dan `outlier` (metode histogram/zscore/iqr) [S3].
- Survei SANS 2026 Threat Hunting: hanya 37% organisasi punya metodologi hunting yang didefinisikan formal, turun dari 46% pada 2025 [S6]. Mengikuti PEAK secara disiplin adalah pembeda.

## 7. Cheat sheet

```
LONG TAIL  stack -> hitung -> urut dari terjarang ; kategori ; langka != jahat
           | rare <f> [by g] limit=N  (kebalikan top; count & percent)
           | stats count dc(host) values(...) BY <f> | sort count
OUTLIER    jarak dari pusat ; numerik ; per entity lebih baik
           z = (x-avg)/stdev ; IQR: upper = q3 + 1.5*(q3-q1) ; perc99
           | anomalydetection [method=histogram|zscore|iqr] [action=filter|annotate|summary | transform|remove]
             -> log_event_prob, probable_cause
BEACON     sort src dest _time | streamstats current=f last(_time) AS prev BY src dest | delta | jitter = stdev/avg (kecil = teratur)
PEAK HYPO  Prepare: topic, research, hypothesis, scope, plan
           Execute: gather, pre-process, analyze, refine, escalate
           Act: preserve, document, create detections, re-add to backlog, communicate
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Hasil long tail proses per host mengembalikan 1.800 kombinasi unik, hampir semuanya muncul di satu host saja. Rekanmu menyimpulkan lingkungan PT JAB sangat tidak terkendali. Apa dugaan pertamamu sebelum menerima kesimpulan itu?

<details><summary>Jawaban</summary>

Nilai yang di-stack belum dinormalisasi. Path yang memuat nama user, nomor versi, atau GUID membuat satu software yang sama tampak sebagai puluhan nilai berbeda, sehingga setiap update browser atau agen backup masuk ke ekor. Normalisasi sederhana, yaitu huruf kecil, nama user diganti penanda, dan nomor versi diganti penanda, biasanya memotong jumlah kombinasi unik secara drastis. Setelah itu baru pantas dibaca, dan tetap dibaca sebagai daftar kandidat: langka tidak sama dengan jahat, karena software khusus satu departemen juga langka. Lihat bagian 1.1 dan 2.6.

</details>

**2. Skenario keputusan.** Kamu mencari host dengan jumlah koneksi keluar yang tidak wajar. Daftar hasilnya selalu diisi lima server yang sama, yaitu resolver DNS dan server billing, sementara workstation tidak pernah muncul. Langkah mana yang paling tepat?

- A. Naikkan ambang z-score dari 3 menjadi 5 supaya hanya yang paling ekstrem yang muncul.
- B. Bandingkan setiap host dengan riwayatnya sendiri, dan segmentasi daftar menurut peran aset sebelum mencari outlier.
- C. Buang kelima server itu dari search dengan daftar pengecualian.

<details><summary>Jawaban</summary>

B. Masalahnya bukan ambang, melainkan membandingkan entitas yang perannya berbeda di dalam satu populasi. Resolver memang berhak punya koneksi keluar ratusan kali lebih banyak daripada workstation, dan selama keduanya berada di satu distribusi, rata-rata serta simpangan baku akan ditentukan oleh server dan workstation yang menyimpang tetap tenggelam. A memperburuknya, karena menaikkan ambang hanya mempersempit daftar ke arah yang sudah salah. C menghilangkan gejalanya sekaligus menghilangkan kemampuan melihat bila resolver itu sendiri yang dipakai sebagai jalur keluar. Lihat bagian 1.2 dan 4.

</details>

**3. Pertanyaan jebakan.** Search beaconing dengan ambang jitter di bawah 0,1 mengembalikan enam pasangan src dan dest. Semuanya ternyata forwarder dan update checker. Di minggu yang sama, satu host memang berkomunikasi ke C2 setiap 60 detik, tetapi tidak muncul di hasil. Apa dua hal yang terjadi di sini?

<details><summary>Jawaban</summary>

Pertama, keteraturan interval bukan ciri khas penyerang. Agen monitoring, forwarder, update checker, dan NTP justru dirancang berinterval tetap, sehingga enam hasil itu adalah perilaku yang benar dari search dan bukan false positive dalam arti teknis; yang kurang adalah pembanding berupa daftar tujuan yang diketahui. Kedua, koefisien variasi, yaitu simpangan baku dibagi rata-rata, mudah rusak oleh satu interval yang jauh lebih panjang, misalnya laptop yang tidur semalam, sehingga beacon 60 detik yang terputus sekali bisa melewati ambang. Versi yang lebih tahan memakai median interval dan median absolute deviation. Perlu diingat bahwa ambang jitter dan jumlah koneksi minimum tidak punya angka baku dan harus dikalibrasi dengan trafik jinak di lab sendiri. Lihat bagian 2.4 dan 5.

</details>

**4. Jelaskan ulang.** Jelaskan ke SOC lead, dalam tiga kalimat, kenapa hunt yang tidak menemukan apa pun tetap hasil yang sah dan pantas dilaporkan.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh jawaban: "Sebuah hunt menguji hipotesis, jadi jawaban 'tidak ditemukan' adalah jawaban, selama cakupannya jelas: sistem mana, data mana, dan rentang waktu mana yang benar-benar diperiksa. Nilainya ada di artefak yang ditinggalkan, yaitu daftar normal yang sudah diverifikasi, aturan normalisasi, dan catatan celah data yang membuat hipotesis itu belum bisa diuji sepenuhnya. Tanpa laporan seperti itu, hunt yang sama akan diulang enam bulan kemudian dari nol, dan tidak ada yang tahu apakah hasil kosong berarti bersih atau berarti kita tidak punya datanya."

Kesalahan yang sering muncul: menyebut hasil kosong sebagai bukti lingkungan bersih tanpa menyebut celah data; melewatkan fase Act sehingga tidak ada SPL, baseline, atau dokumen yang tersimpan; dan melaporkan hunt tanpa scope, sehingga pembaca tidak bisa tahu apa yang sebenarnya belum diperiksa. Lihat bagian 1.4 dan 5.

</details>

**5. Interview question (English).** "Walk me through how you would hunt for command and control beaconing in Splunk, and how you would keep it from flooding you with noise."

<details><summary>Sample answer</summary>

"I would write it as a hypothesis first: one host is talking to an external destination at a very regular interval. Then I build the time series per source and destination pair, take the gap between consecutive connections with streamstats, and summarise each pair by how regular those gaps are rather than how many there are. The naive measure is the coefficient of variation, standard deviation over mean, but that breaks as soon as one gap is much longer than the rest, for instance a laptop that slept overnight, so I prefer the median gap with median absolute deviation, which stays stable. I also require a minimum number of connections, otherwise three connections an hour apart look perfectly regular. The important part is what regularity actually proves, which is very little on its own: forwarders, update checkers and NTP are all regular by design, so my output is a candidate list that I join against known destinations and asset context, not an alert. Any threshold I use for jitter is calibrated against benign traffic in my own environment, and I document it, because the number is not transferable between networks. If the data source aggregates flows instead of recording individual connections, I say so, because then the technique cannot work at all and the honest finding is the data gap."

What makes this answer strong: it starts from a hypothesis rather than a query, names the specific statistical failure mode and the more robust replacement, states what the signal does not prove, and ends by treating a data limitation as a reportable result instead of forcing a conclusion.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Splunk: Hypothesis-Driven Hunting with the PEAK Framework (David Bianco) | https://www.splunk.com/en_us/blog/security/peak-hypothesis-driven-threat-hunting.html | primer (vendor; penulis kerangka) | 2023-05-08; diakses 2026-10-07 | Tinggi |
| S2 | SPL Search Reference 10.2: rare | https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.2/search-commands/rare | primer | diakses 2026-10-07 | Tinggi |
| S3 | SPL Search Reference 10.2: anomalydetection | https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.2/search-commands/anomalydetection | primer | diakses 2026-10-07 | Tinggi |
| S4 | Splunk: PEAK framework introduction | https://www.splunk.com/en_us/blog/security/peak-threat-hunting-framework.html | primer | 2023-04-18 | Tinggi |
| S5 | Dragos: Four Types (modeling; lihat Day 38) | https://dragos.brightspotcdn.com/3e/f8/aefcee7f41b6b19a02b410ac5722/four-types-threat-detection-whitepaper-09-25.pdf | sekunder | 2025-09 | Tinggi |
| S6 | SANS: siaran pers SANS 2026 Threat Hunting Survey | https://www.sans.org/press/announcements/threat-hunters-call-data-their-biggest-barrier-overtaking-staffing-first-time-survey-finds | sekunder | 2026-09-23; diakses 2026-10-10 | Sedang-tinggi |
| S7 | TaHiTI Threat Hunting Methodology whitepaper | https://www.betaalvereniging.nl/wp-content/uploads/2026/03/TaHiTI-Threat-Hunting-Methodology-whitepaper.pdf | primer | diakses 2026-10-07 | Tinggi |

**Catatan sumber:** angka survei SANS berasal dari siaran pers [S6]; cocokkan dengan laporan lengkap bila dikutip. Ambang jitter, MAD, dan jumlah koneksi minimum di bagian 2.4 adalah ilustrasi yang perlu dikalibrasi di lab. Uraian TaHiTI mengikuti whitepaper-nya [S7].
