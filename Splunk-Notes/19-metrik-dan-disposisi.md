---
day: 19
title: Metrik kinerja analyst (MTTD, MTTR, dwell time) dan event disposition di ES
researched_on: 2026-10-10
versions_checked: Splunk ES 8.6 (Configure dispositions for findings); Splunk blog "SOC Metrics" (18 Mei 2023) dan "What is MTTD?"; TaHiTI whitepaper (breach detection gap / dwell time); SANS 2026 Threat Hunting & SOC Survey (metrik); ES 8.7
---

# Day 19: Metrik dan disposisi

Cakupan: menjelaskan jenis metrik kinerja analyst seperti MTTR dan dwell time; mengenali disposisi event umum dan menetapkannya dengan benar.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- mendefinisikan MTTD, MTTA (attend & analyze), MTTI, MTTR, MTRS, dwell time, serta FP/FN rate, dan menunjukkan titik awal dan akhir pengukurannya pada timeline insiden.
- menyebut tujuh disposition bawaan ES 8 dan memilih yang tepat untuk sebuah skenario.
- menjelaskan kenapa disposition yang akurat adalah bahan bakar tuning detection dan metrik kualitas.
- menghitung metrik sederhana dari data finding/notable dengan SPL.

## 2. Konteks singkat

Metrik menjawab "apakah SOC membaik?", sedangkan disposition menjawab "alert ini sebenarnya apa?". Keduanya terhubung erat:
- FP rate per detection hanya bisa dihitung bila analyst memberi disposisi yang benar.
- MTTR hanya bermakna bila status dan waktu tutup tercatat konsisten.

Survei SANS 2026 Threat Hunting (500 responden) mencatat hanya 40% program hunting yang mengukur efektivitasnya secara formal, turun dari 64% pada 2024 [S6]. Kemampuan mengukur adalah pembeda.

## 3. Konsep inti

### 3.1 Timeline insiden dan metrik

```
T0 kompromi awal ---- T1 deteksi ---- T2 di-attend/analisis ---- T3 investigasi mulai ---- T4 resolusi/pemulihan
|<------------- dwell time / breach detection gap ------>|
                     |<-- MTTA&A -->|
                     |<--------- MTTI --------->|
                     |<------------------- MTTR (resolve) ------------------------------>|
|<---- MTTD (dari kejadian/kompromi sampai deteksi) ---->|
```

Definisi (Splunk blog SOC Metrics, 2023) [S2]:
- **MTTD (Mean Time to Detect):** rata-rata waktu SOC mendeteksi insiden atau breach.
- **MTTA&A (Mean Time to Attend and Analyze):** rata-rata waktu merespons dan menganalisis insiden, sejak deteksi sampai prioritas, dampak, dan kemungkinan resolusinya dipastikan.
- **MTTI (Mean Time to Investigate):** rata-rata waktu dari deteksi sampai investigasi dimulai.
- **MTTR (Mean Time to Resolution):** rata-rata waktu menyelesaikan insiden sepenuhnya sejak terdeteksi.
- **MTRS (Mean Time to Restore Service):** dari deteksi sampai layanan pulih sepenuhnya.
- **FP rate:** persentase yang salah diklasifikasikan sebagai insiden, padahal bukan ancaman. FN rate: persentase ancaman yang terlewat atau salah dianggap bukan ancaman [S2].

**Catatan singkatan:** "MTTR" sering juga dibaca *Mean Time to Respond*, *Repair*, atau *Recover* tergantung organisasi. Selalu definisikan titik awal dan akhirnya sebelum membandingkan angka.

**Dwell time:** waktu antara kompromi awal dan ditemukannya penyerang. TaHiTI menyebutnya *breach detection gap*, dan tujuan utama threat hunting adalah memperpendeknya [S3]. Dwell time hanya bisa diketahui setelah investigasi menemukan T0. Ia dihitung per insiden dan sering memerlukan forensik.

### 3.2 Metrik yang berguna vs menyesatkan

| Metrik | Mengukur | Risiko salah pakai |
|---|---|---|
| MTTD | Kecepatan deteksi | Bergantung T0 yang sering baru diketahui belakangan |
| MTTA/MTTI | Kecepatan triage | Mendorong "klik cepat" tanpa analisis |
| MTTR | Kecepatan penyelesaian | Mendorong menutup tiket terlalu cepat (resolusi palsu) |
| Dwell time | Efektivitas end-to-end | Sampel kecil; hanya dari insiden yang ditemukan |
| FP rate per detection | Kualitas detection | Butuh disposition yang konsisten |
| Volume per analyst | Beban kerja | Tidak mencerminkan kualitas |

Prinsip: gabungkan metrik kecepatan dengan metrik kualitas. MTTR turun sementara FN naik bukanlah perbaikan.

### 3.3 Disposition di ES 8

ES 8 menyediakan tujuh disposition bawaan [S1]:

| Disposition | Arti | Kapan dipakai |
|---|---|---|
| Undetermined | Default; finding belum/tidak punya disposisi valid | Belum dianalisis. Tidak boleh dibiarkan saat menutup |
| True Positive - Suspicious Activity | Finding menunjukkan aktivitas ancaman yang mencurigakan | Aktivitas berbahaya atau tidak sah yang terkonfirmasi atau sangat mungkin |
| Benign Positive - Suspicious But Expected | Awalnya mencurigakan, ternyata tidak berbahaya dan diharapkan | Detection bekerja benar, tetapi aktivitasnya sah: admin menjalankan alat, pentest resmi, perubahan terjadwal |
| False Positive - Incorrect Analytic Logic | Tidak berbahaya karena logika detection salah | Detection menangkap hal yang tidak sesuai tujuannya -> perbaiki logika |
| False Positive - Inaccurate Data | Tidak berbahaya karena data tidak akurat | Parsing salah, timestamp salah, field CIM keliru -> perbaiki data/TA |
| Other | Kategori serba ada untuk yang tidak terklasifikasi | Jarang; beri catatan |
| Testing | Untuk menguji input field dan drilldown | Uji detection/lab |

Pengaturan [S1]:
- Menu Configure > Findings and investigations > Dispositions.
- Semua disposition aktif secara default, dengan nilai default Undetermined.
- Admin bisa mengaktifkan Required agar disposisi wajib diisi sebelum menutup finding.
- Disposition kustom bisa ditambahkan (+Disposition), dan salah satunya bisa dijadikan default.

**Kenapa pembedaan FP itu penting:**
- *Incorrect Analytic Logic* menjadi pekerjaan detection engineer (ubah logika/filter).
- *Inaccurate Data* menjadi pekerjaan data/platform engineer (TA, CIM, waktu; Day 09).
- *Benign Positive* berarti detection sudah benar; pertimbangkan allowlist sempit atau penurunan prioritas, bukan "memperbaiki" logika.

Pemisahan ini membuat Re-assess (Day 18) mengarah ke pemilik yang tepat.

### 3.4 Status vs disposition

- Status menjawab di mana kasus berada dalam alur kerja (New, In Progress, Pending, Resolved, Closed, dsb. Cek daftar status di ES 8.7).
- Disposition menjawab apa hasil penilaiannya.

Kasus bisa berstatus Closed dengan disposition True Positive. Keduanya diperlukan untuk metrik.

### 3.5 Enterprise vs ES

Tanpa ES, disposisi dan metrik dikelola di ticketing (mis. TheHive) dan dihitung dari datanya. ES menyediakan field disposition dan status bawaan pada finding, serta laporan/dashboard SOC (Day 21).

## 4. Contoh SPL dan langkah di ES

> Keluaran berlabel ilustrasi. Query ES 7.x memakai macro `` `notable` ``. Di ES 8, sumber data finding dan nama field, cek (mis. via dashboard Mission Control/analyst queue).

### 4.1 FP rate per detection (ES 7.x, pola)

```
`notable`
| where in(status_label,"Resolved","Closed")
| eval fp=if(like(disposition_label,"False Positive%"),1,0),
       bp=if(like(disposition_label,"Benign Positive%"),1,0),
       tp=if(like(disposition_label,"True Positive%"),1,0)
| stats count sum(tp) AS tp sum(bp) AS bp sum(fp) AS fp BY rule_name
| eval fp_rate=round(fp/count*100,1), precision=round(tp/count*100,1)
| sort - fp_rate
```

- `disposition_label` dan `status_label` adalah field ES 7.x, cek nama field di ES 8.
- **Cara membaca hasil:** FP rate tinggi + FP berjenis *Incorrect Analytic Logic* berarti perbaiki logika. Jenis *Inaccurate Data* berarti perbaiki data. Benign Positive tinggi berarti pertimbangkan allowlist atau RBA (Day 22).

### 4.2 MTTA dan MTTR dari jejak waktu (pola umum)

```
`notable`
| where in(status_label,"Resolved","Closed")
| eval detect_time=_time
| eval close_time=strptime(status_end, "%Y-%m-%dT%H:%M:%S")
| eval ttr_hours=round((close_time-detect_time)/3600,2)
| stats avg(ttr_hours) AS mttr_hours median(ttr_hours) AS median_ttr p90(ttr_hours) AS p90_ttr BY urgency
```

- `status_end` dan formatnya adalah contoh nama field, cek di instance Splunk-mu. Banyak deployment menghitung dari riwayat audit review (`incident_review` lookup/index), perlu dicek.
- Median dan p90 lebih jujur daripada rata-rata, karena satu kasus panjang bisa merusak rata-rata.

### 4.3 Lab tanpa ES: metrik dari TheHive yang di-ingest ke Splunk

```
index=thehive sourcetype=thehive:case
| eval created=createdAt/1000, closed=endDate/1000
| eval ttr_h=(closed-created)/3600
| stats count median(ttr_h) AS median_ttr BY resolutionStatus
```

Nama index, sourcetype, dan field sepenuhnya asumsi, karena bergantung cara kamu mengirim data TheHive ke Splunk. Pembagian 1000 mengasumsikan TheHive menyimpan waktu sebagai epoch milidetik, yang umum di API TheHive. Cek format waktu di data lab-mu dengan melihat satu event mentah. Contoh ini menunjukkan polanya.

### 4.4 Menghitung dwell time dari investigasi (manual)

```
| makeresults format=csv data="case,t0_compromise,t1_detect,t4_resolve
CASE-001,2026-09-01T02:10:00,2026-09-03T09:00:00,2026-09-03T15:30:00
CASE-002,2026-09-10T14:00:00,2026-09-10T14:20:00,2026-09-10T18:00:00"
| foreach t0_compromise t1_detect t4_resolve [eval <<FIELD>>_e=strptime('<<FIELD>>',"%Y-%m-%dT%H:%M:%S")]
| eval dwell_h=round((t1_detect_e-t0_compromise_e)/3600,1), ttr_h=round((t4_resolve_e-t1_detect_e)/3600,1)
| table case dwell_h ttr_h
```

- T0 berasal dari temuan forensik (mis. event eksekusi pertama), dicatat manual di kasus.
- `foreach` dan `makeresults` dari Day 04.

### 4.5 Di ES 8 (generik)

1. Aktifkan Required untuk disposition (Configure > Findings and investigations > Dispositions) [S1].
2. Latih analyst membedakan Benign Positive vs FP-Logic vs FP-Data. Buat panduan internal satu halaman.
3. Tinjau metrik mingguan: FP rate per detection, median TTR per urgensi.

## 5. Lab praktik

1. Tulis 8 skenario singkat (fiktif/lab) dan beri disposition ES yang tepat beserta alasannya. Sertakan minimal: pentest resmi, parsing timestamp salah, logika regex terlalu luas, malware nyata, uji detection.
2. Dari kasus Day 18 (lab), catat T0, T1, T2, T4. Hitung dwell time, MTTA&A, dan TTR.
3. Jalankan bagian 4.4 dengan 3 kasus lab-mu.
4. Bila memakai ES: tutup 5 finding lab dengan disposition berbeda, lalu jalankan versi ES 8 dari bagian 4.1.
5. Rancang dashboard metrik SOC mini: 4 panel (FP rate per detection, median TTR, jumlah per disposition, tren mingguan).

**Hasil yang sebaiknya tersimpan:**
- 8 skenario dengan disposition dan alasan.
- Metrik waktu untuk minimal 1 kasus.
- Rancangan dashboard metrik.

**Variasi tantangan:** buat aturan sederhana untuk Re-assess otomatis: detection dengan FP-Logic > 30% dalam 30 hari otomatis masuk backlog tuning (mis. saved search yang membuat tiket).

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Perbaikan |
|---|---|---|
| Banyak finding ditutup "Undetermined" | Disposition tidak wajib | Aktifkan Required [S1] |
| FP rate tidak berguna | Semua FP diberi satu label | Pakai pembedaan Logic vs Data vs Benign |
| MTTR "membaik" tapi insiden berulang | Penutupan prematur | Lacak reopen rate dan FN; gunakan median + p90 |
| Dwell time tidak bisa dihitung | T0 tidak dicatat | Tambah field T0 di template kasus/response plan |

## 7. Kesalahan umum dan jebakan

- Menyamakan Benign Positive dengan False Positive. Benign Positive berarti detection benar, tetapi aktivitasnya sah [S1].
- Membandingkan MTTR antar organisasi tanpa definisi titik awal dan akhir yang sama.
- Memakai rata-rata saja. Gunakan median/p90.
- Mengejar MTTR rendah dengan mengorbankan kualitas investigasi.
- Menganggap dwell time = MTTD. MTTD adalah rata-rata kecepatan deteksi. Dwell time dihitung per insiden dari kompromi awal, yang sering baru diketahui lewat forensik.
- `[komunitas]` Definisi metrik berasal dari blog vendor (2023). Organisasi lain bisa memakai titik awal dan akhir berbeda, jadi selalu tulis definisinya di laporan.

## 8. Catatan terkini

- ES 8.x menamai objeknya "finding" dan mengelola disposition di Configure > Findings and investigations > Dispositions, dengan opsi Required dan disposition kustom [S1].
- Daftar tujuh disposition bawaan sama dengan era ES 7 dan dengan dokumentasi ES 8.0-8.6. Cek daftar di instance ES 8.7-mu bila admin menambah disposition kustom.
- ES 8.7 menambah fitur AI SOC Analyst yang dapat menjalankan tindakan respons. Metrik waktu bisa membaik secara artifisial bila tindakan otomatis tidak dibedakan dari tindakan manusia, cek bagaimana ES mencatatnya.

## 9. Cheat sheet

```
TIMELINE  T0 kompromi -> T1 deteksi -> T2 attend/analyze -> T3 investigasi -> T4 resolusi/pulih
DWELL     T0 -> T1 (breach detection gap; per insiden; butuh forensik)
MTTD      rata2 waktu deteksi | MTTA&A  T1->T2 | MTTI  T1->T3 | MTTR  T1->T4 (resolve) | MTRS T1->layanan pulih
FPR/FNR   salah klasifikasi ancaman / ancaman terlewat     -> pakai median & p90 ; DEFINISIKAN titik awal/akhir
ES8 DISPOSITION (7): Undetermined (default) | True Positive - Suspicious Activity
     | Benign Positive - Suspicious But Expected | False Positive - Incorrect Analytic Logic
     | False Positive - Inaccurate Data | Other | Testing
     Configure > Findings and investigations > Dispositions ; Required ; +Disposition
ROUTING   FP-Logic -> detection engineer ; FP-Data -> data/platform engineer ; Benign -> allowlist sempit/RBA
STATUS != DISPOSITION (alur vs hasil)
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | ES 8.6: Configure dispositions for findings in Splunk Enterprise Security | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.6/investigations/configure-dispositions-for-findings-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi |
| S2 | Splunk blog: SOC Metrics: Security Metrics & KPIs for Measuring SOC Success | https://www.splunk.com/en_us/blog/learn/security-operations-metrics.html | primer (vendor) | 2023-05-18; diakses 2026-10-07 | Tinggi untuk definisi |
| S3 | TaHiTI whitepaper (breach detection gap / dwell time) | https://www.betaalvereniging.nl/wp-content/uploads/2026/03/TaHiTI-Threat-Hunting-Methodology-whitepaper.pdf | primer | diakses 2026-10-07 | Tinggi |
| S4 | Splunk blog: What is MTTD? | https://www.splunk.com/en_us/blog/learn/mean-time-to-detect-mttd.html | primer (vendor) | diakses 2026-10-07 | Sedang; pembanding definisi |
| S5 | Splunk blog: Top 8 incident response metrics | https://www.splunk.com/en_us/blog/learn/incident-response-metrics?p=2 | primer (vendor) | diakses 2026-10-07 | Sedang; pembanding definisi |
| S6 | SANS: siaran pers SANS 2026 Threat Hunting Survey | https://www.sans.org/press/announcements/threat-hunters-call-data-their-biggest-barrier-overtaking-staffing-first-time-survey-finds | sekunder | 2026-09-23; diakses 2026-10-10 | Sedang-tinggi; angka dari siaran pers, bukan laporan lengkap |

**Catatan sumber:** nama field notable/finding (status, disposition, waktu tutup) dan daftar status di ES 8.7 perlu dicek di instance sebelum query bagian 4 dipakai di ES 8. Angka survei SANS berasal dari siaran pers; cocokkan dengan laporan lengkapnya bila dipakai di presentasi.
