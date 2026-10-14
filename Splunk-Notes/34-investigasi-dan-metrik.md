---
day: 34
title: Continuous monitoring dan lima tahap dasar investigasi menurut Splunk
researched_on: 2026-10-10
versions_checked: Splunk Lantern "Creating an incident workflow in Splunk Enterprise Security" (5 tahap); Splunk blog "Continuous Monitoring" (7 Mei 2024); ES 8.4 response plans (Mission Control); NIST SP 800-61r3 (Apr 2025); ES 8.7
---

# Day 34: Continuous monitoring dan lima tahap dasar investigasi

Cakupan: menjelaskan continuous monitoring dan lima tahap dasar investigasi menurut Splunk.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- mendefinisikan continuous monitoring beserta komponen dan langkah penerapannya.
- menyebut dan menjelaskan lima tahap alur kerja insiden dari Splunk: Review events, Assessment, Determine risk, Mitigate, dan Re-assess.
- memetakan tahap-tahap itu ke fitur ES (analyst queue/Incident Review, investigation/workbench, response plan) dan ke SPL yang dipakai di tiap tahap.
- membandingkan alur Splunk dengan siklus IR NIST.

## 2. Konteks singkat

Ini inti pekerjaan analyst: bagaimana monitoring berkelanjutan menghasilkan event yang perlu ditinjau, dan bagaimana investigasi berjalan sampai selesai dan dievaluasi ulang.

Nama dan urutan lima tahap di Day ini mengikuti artikel Lantern tentang alur kerja insiden di ES [S1]. Materi pelatihan resmi Splunk bisa memakai nama yang sedikit berbeda. Bila itu terjadi, pegang konsepnya (triage, analisis, mitigasi, evaluasi ulang), karena konsep itu konsisten lintas kerangka.

## 3. Konsep inti

### 3.1 Continuous monitoring

Blog Splunk mendefinisikan continuous monitoring sebagai proses berkelanjutan dan real-time untuk mengumpulkan, menganalisis, dan bertindak atas data di seluruh lingkungan TI guna mendeteksi dan menangani ancaman, kerentanan, dan masalah performa sebelum berdampak [S2].

Empat komponen [S2]:
1. **Data collection:** log, trafik jaringan, aktivitas aplikasi (Day 21).
2. **Analysis:** pola, anomali, ancaman (detection, Day 35-36).
3. **Reporting:** dashboard kesehatan dan keamanan (Day 32).
4. **Response:** alert dan tindakan protektif (Day 41-42).

Langkah penerapan [S2]:
1. tetapkan tujuan monitoring;
2. pilih teknologi untuk sumber data;
3. tetapkan ambang dan parameter alert;
4. siapkan prosedur respons insiden;
5. tinjau efektivitas secara rutin.

Tantangan yang disebut: volume data, kebutuhan sumber daya, kompleksitas integrasi, dan alert fatigue akibat false positive [S2]. Ini alasan RBA (Day 35).

**Kenapa "berkelanjutan":** penyerang tidak bekerja sesuai jadwal audit. Monitoring periodik (mis. tinjauan bulanan) meninggalkan celah waktu yang memperpanjang dwell time (Day 34).

### 3.2 Lima tahap alur kerja insiden menurut Splunk

Dari Lantern "Creating an incident workflow in Splunk Enterprise Security" [S1]:

| # | Tahap | Inti | Pertanyaan analyst | Fitur ES (7 -> 8) |
|---|---|---|---|---|
| 1 | Review events | Meninjau alert atau informasi yang memulai penyelidikan: notable event, alert dari scheduled search, email ke SOC, atau tiket help desk | "Apa yang masuk ke antreanku?" | Incident Review (ES 7), analyst queue (ES 8) |
| 2 | Assessment | Keputusan awal: false alarm, bisa ditutup atau ditunda, atau perlu ditangani; sisanya diprioritaskan menurut severity dan dampak | "Asli atau tidak? Seberapa penting?" | Ubah status/urgensi, assign owner, cek konteks aset/identitas (Day 26) |
| 3 | Determine risk | Membuka investigasi untuk memeriksa artefak terkait dan menilai risiko terhadap aset terdampak dan kejadian secara keseluruhan | "Seberapa luas? Apa yang terkena?" | Investigation workbench (ES 7), investigation di Mission Control (ES 8), Risk analysis, pivot (Day 24) |
| 4 | Mitigate | Memperbarui status investigasi untuk menyerahkan, mengeskalasi, atau menyelesaikannya | "Apa yang harus dilakukan sekarang, dan oleh siapa?" | Adaptive response (Day 41), SOAR playbook (Day 42), response plan |
| 5 | Re-assess | Meninjau kembali investigasi lewat ringkasannya untuk mengajari orang lain, mencari akar masalah, atau membangun pertahanan tambahan | "Apa pelajarannya? Apa yang harus diubah?" | Tuning detection, detection baru, metrik (Day 34) |

Tujuan alur ini: analyst menyelesaikan investigasi secara konsisten, efisien, dan kolaboratif [S1].

**Hubungan dengan siklus NIST:** NIST SP 800-61r3 (Apr 2025) tidak lagi memakai siklus empat fase lama (preparation; detection and analysis; containment, eradication and recovery; post-incident activity). Revisi ini menempatkan respons insiden di dalam manajemen risiko siber organisasi dan memetakannya ke enam fungsi CSF 2.0: Govern, Identify, Protect (persiapan), Detect, Respond, Recover (respons), dengan perbaikan berkelanjutan dari setiap fungsi [S4]. ES 8 menyediakan response plan bawaan, termasuk template "NIST 800-61" dan "Generic Incident Response" dengan fase detect, analyze, contain, eradicate, recover, review [S3]. Pemetaan kasarnya:
- Review events dan Assessment kira-kira setara detect dan analyze awal;
- Determine risk kira-kira setara analyze (scoping);
- Mitigate kira-kira setara contain, eradicate, dan recover;
- Re-assess kira-kira setara review atau lessons learned.

### 3.3 Response plan di ES 8

- Response plan berisi fase dan tugas yang diselesaikan analyst saat menyelidiki dan merespons [S3].
- ES 8 menyertakan 8 template: Account Compromise, Data Breach, Network Indicator Enrichment, NIST 800-61, Generic Incident Response, Self-Replicating Malware, Suspicious Email, Vulnerability Disclosure [S3].
- Penerapan: di Mission Control, pilih investigation, buka View details, masuk ke tab Response, lalu tetapkan response plan, atau kaitkan dengan investigation type agar otomatis diterapkan ke kasus berikutnya [S3].

Response plan adalah cara ES 8 "memaksa" konsistensi tahap 3-5.

### 3.4 Enterprise vs ES

- Tanpa ES: tahap yang sama dijalankan lewat alert Splunk, ticketing eksternal (TheHive di lab-mu), dan search manual.
- Dengan ES: analyst queue, investigation, response plan, risk, dan adaptive response terintegrasi.

## 4. Contoh SPL dan langkah di ES

> Keluaran berlabel ilustrasi. SPL per tahap. Field finding/notable di ES 8, perlu dicek.

### 4.1 Tahap 1, Review events: apa yang baru di antrean?

ES 7.x:

```
`notable`
| where status_label="New"
| stats count BY rule_name urgency
| sort - count
```

Di ES 8, antrean berada di analyst queue (Mission Control). Gunakan UI sebagai acuan, karena index/macro untuk query finding, perlu dicek.

### 4.2 Tahap 2, Assessment: konteks cepat untuk satu finding

```
| tstats summariesonly=false count min(_time) AS first max(_time) AS last
    from datamodel=Authentication.Authentication
    where Authentication.src="10.0.5.23" earliest=-24h
    by Authentication.action Authentication.user Authentication.dest Authentication.dest_priority
| rename Authentication.* AS *
| convert ctime(first) ctime(last)
```

- Pertanyaan assessment: apakah sumber ini punya pola login normal? Apakah targetnya kritis (`dest_priority`, Day 26)?
- **Keputusan:** false positive (tutup + disposisi, Day 34), turunkan prioritas, atau lanjut ke tahap 3.

### 4.3 Tahap 3, Determine risk: scoping lintas data

- Pivot lintas model untuk IP/host/user (Day 24 bagian 4.1-4.3).
- Lihat akumulasi risiko entity (Day 35):

```
index=risk earliest=-7d (risk_object="10.0.5.23" OR risk_object="WIN-LAB01")
| stats sum(risk_score) AS total_risk dc(source) AS detections values(source) AS which BY risk_object risk_object_type
```

Cek nama field risk di ES 8.7.

- Cari host lain dengan indikator yang sama (scoping): ganti filter dengan indikator (hash, domain), bukan host.

### 4.4 Tahap 4, Mitigate: catat tindakan

- Jalankan adaptive response atau playbook SOAR (Day 41-42). Contoh: isolasi host di EDR, nonaktifkan akun, blokir domain.
- Perbarui status investigasi dan isi response plan di Mission Control [S3].

### 4.5 Tahap 5, Re-assess: belajar dari kasus yang sudah ditutup

ES 7.x:

```
`notable`
| where in(status_label,"Resolved","Closed")
| stats count BY rule_name disposition
| eventstats sum(count) AS total BY rule_name
| eval pct=round(count/total*100,1)
| where disposition="false_positive" AND pct>50
```

- Detection yang mayoritas ditutup sebagai false positive adalah kandidat tuning.
- Cek nilai field `disposition` (Day 34) dan ketersediaannya di ES 8.

## 5. Lab praktik

Tanpa ES (Splunk + TheHive di lab-mu):
1. Buat alert Splunk dari detection Day 13 bagian 4.3 (brute force lalu sukses) yang mengirim ke TheHive (lewat webhook/Shuffle).
2. Picu dari VM Windows lab (login gagal berkali-kali, lalu sukses).
3. Jalani lima tahap di TheHive. Tulis catatan per tahap: Review (alert masuk), Assessment (asli/tidak), Determine risk (pivot bagian 4.2-4.3), Mitigate (mis. nonaktifkan akun lab), Re-assess (tuning ambang, detection tambahan).

**Dengan ES 8:**
1. Picu detection yang sama, buka finding di analyst queue, buat investigation, terapkan response plan "Account Compromise" [S3], lalu jalani tahapnya.

**Hasil yang sebaiknya tersimpan:**
- Satu kasus lab dengan catatan lima tahap.
- Minimal satu SPL per tahap dijalankan.
- Satu rekomendasi Re-assess yang konkret (tuning atau detection baru).

**Variasi tantangan:** petakan lima tahap Splunk ke fase response plan "Generic Incident Response" (detect, analyze, contain, eradicate, recover, review) [S3]. Tunjukkan di mana keduanya berbeda.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Perbaikan |
|---|---|---|
| Antrean menumpuk di "New" | Volume finding terlalu tinggi; tidak ada triage SLA | RBA (Day 35), tuning, metrik MTTA (Day 34) |
| Assessment lambat | Konteks aset/identitas kosong | A&I (Day 26) |
| Investigasi tidak konsisten antar analyst | Tidak ada response plan | Response plan + investigation type [S3] |
| Re-assess tidak pernah terjadi | Tidak ada waktu/proses | Jadwal tinjauan mingguan; query bagian 4.5 |

## 7. Kesalahan umum dan jebakan

- Melompat ke Mitigate tanpa Determine risk. Akibatnya hanya satu host yang ditangani, sementara host lain yang terdampak terlewat.
- Menganggap Re-assess opsional. Tanpa tahap ini, detection berisik tetap berisik dan celah yang sama berulang [S1].
- Menutup finding tanpa disposisi yang benar. Metrik dan tuning menjadi bias (Day 34).
- Menyamakan "continuous monitoring" dengan "dashboard real-time". Ini proses (koleksi, analisis, pelaporan, respons, peninjauan), bukan tampilan [S2].

## 8. Catatan terkini

- **ES 8.x:** Incident Review menjadi analyst queue; investigation dan response plan berada di Mission Control. Tersedia 8 template bawaan [S3].
- NIST SP 800-61r3 (Apr 2025) menggantikan r2 [S4]. Response plan ES masih menyediakan template "NIST 800-61" berbasis fase klasik, cek revisi mana yang dirujuk template itu.
- Release notes ES 8.7 menyebut AI SOC Analyst yang dapat menjalankan tindakan respons yang diizinkan dan merekomendasikan langkah berikutnya. Cakupan izinnya perlu dicek di instance-mu, karena ini memengaruhi tahap Mitigate.

## 9. Cheat sheet

```
CONTINUOUS MONITORING = koleksi -> analisis -> pelaporan -> respons (berkelanjutan, real-time)
  langkah: tujuan -> teknologi -> ambang alert -> prosedur IR -> tinjau rutin ; tantangan: volume, biaya, integrasi, alert fatigue
5 TAHAP (Splunk Lantern, alur insiden ES):
  1 Review events   (notable/finding, alert, email, tiket)
  2 Assessment      (FP? turunkan? lanjut? - severity + dampak bisnis)
  3 Determine risk  (workbench/investigation, artefak, aset terdampak, scoping)
  4 Mitigate        (update status, tindak / serahkan remediasi; AR, SOAR)
  5 Re-assess       (tinjau kasus lampau, pelajaran, pertahanan tambahan)
ES8 response plan: fase + tugas ; 8 template (Account Compromise, Data Breach, Network Indicator Enrichment, NIST 800-61,
                   Generic IR, Self-Replicating Malware, Suspicious Email, Vulnerability Disclosure)
                   Mission Control > investigation > View details > Response
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Splunk Lantern: Creating an incident workflow in Splunk Enterprise Security | https://lantern.splunk.com/Security_Use_Cases/Advanced_Threat_Detection/Creating_an_incident_workflow_in_Splunk_Enterprise_Security | primer | tanggal tidak terlihat; diakses 2026-10-07 | Tinggi untuk lima tahap. Kesesuaian dengan materi ujian, perlu dicek |
| S2 | Splunk blog: The Continuous Monitoring Ultimate Guide | https://www.splunk.com/en_us/blog/learn/continuous-monitoring.html | primer (vendor) | 2024-05-07; diakses 2026-10-07 | Tinggi |
| S3 | ES 8.4: Respond to investigations with response plans | https://help.splunk.com/en/splunk-enterprise-security-8/user-guide/8.4/mission-control/respond-to-investigations-with-response-plans-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi |
| S4 | NIST SP 800-61r3: Incident Response Recommendations and Considerations for Cybersecurity Risk Management | https://csrc.nist.gov/pubs/sp/800/61/r3/final | primer | 2025-04; diakses 2026-10-07 | Tinggi |
| S6 | ES 7.3: Investigations in Splunk Enterprise Security | https://help.splunk.com/en/splunk-enterprise-security-7/user-guide/7.3/investigations/investigations-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Sedang-tinggi. Konteks istilah ES 7 |

**Catatan sumber:** nama dan urutan lima tahap mengikuti Lantern [S1]; materi pelatihan resmi Splunk bisa memakai nama berbeda. Nama field notable/finding di ES 8 (status, disposition, waktu tutup) perlu dicek di instance sebelum query bagian 4 dipakai di ES 8. Revisi NIST yang dirujuk template response plan "NIST 800-61" juga perlu dicek.
