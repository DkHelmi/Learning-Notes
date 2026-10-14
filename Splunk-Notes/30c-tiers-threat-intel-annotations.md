---
day: 30
title: Tingkatan threat intelligence dan annotations di Splunk ES
researched_on: 2026-10-10
versions_checked: 'Splunk ES 8.3/8.7 (Threat Intelligence Framework: sumber bawaan; annotations); MWR InfoSecurity/CPNI/CERT-UK "Threat Intelligence: Collecting, Analysing, Evaluating" (2015); Splunk Threat Intelligence Management (Cloud) / Intel Management (Legacy, end of sale); MITRE ATT&CK v19.2'
---

# Day 30: Tingkatan threat intelligence dan annotations di ES

Cakupan: tingkatan umum threat intelligence dan penerapannya pada analisis ancaman; tujuan dan cakupan annotations di Splunk Enterprise Security.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan tingkatan threat intelligence (strategic, operational, tactical, technical), konsumennya, dan inkonsistensi istilah antar sumber.
- menjelaskan bagaimana ES memakai intel: Threat Intelligence Framework (threat list, collection, threat match) vs Threat Intelligence Management (Cloud).
- menjelaskan tujuan dan cakupan annotations di ES: apa yang dianotasi, di mana annotation terlihat, dan untuk apa dipakai.
- memeriksa intel dan annotation dari SPL.

## 2. Konteks singkat

Dua topik ini berbagi satu ide: konteks. Intel memberi konteks tentang ancaman dari luar. Annotation memberi konteks tentang arti sebuah detection (teknik ATT&CK apa, kontrol mana, analytic story apa). Keduanya membuat finding lebih cepat dipahami dan diprioritaskan.

Fokus Day ini adalah tingkatan intel yang perlu dikenali analyst, cara ES memakai intel untuk threat match, dan cara annotation memberi konteks pada detection.

## 3. Konsep inti

### 3.1 Tingkatan threat intelligence

Model empat tipe berbasis konsumen dari MWR/CPNI/CERT-UK (2015) [S1]:

| Tingkat | Isi | Konsumen | Horizon | Contoh pemakaian di SOC |
|---|---|---|---|---|
| Strategic | Risiko yang berubah, tren, motif, dampak bisnis | Board, eksekutif | Panjang | Brief kuartalan untuk CISO; prioritas investasi |
| Operational | Detail serangan spesifik yang akan datang ke organisasi | Defender, kepala IR | Pendek | Peringatan kampanye hacktivist yang mengumumkan target; langka |
| Tactical | TTP: bagaimana aktor beroperasi | Arsitek, sysadmin, detection engineer | Panjang | Detection berbasis perilaku; hipotesis hunting |
| Technical | Indikator: IP, domain, hash | SOC/IR, sistem otomatis | Pendek (cepat basi) | Threat list di ES, blokir, threat match |

**Perhatian:** banyak vendor memakai model tiga tipe dengan arti berbeda. Di model itu, *tactical* = IOC dan *operational* = TTP/kampanye [S2]. Dalam diskusi, sebutkan isinya (mis. "intel berbasis IOC" atau "intel TTP"). Jangan hanya menyebut labelnya.

**Penerapan pada analisis ancaman:**
- Technical intel dicocokkan otomatis dengan data (threat match di ES). Ini cepat, tetapi rapuh dan berumur pendek.
- Tactical intel diubah menjadi detection perilaku dan hipotesis hunting (Day 38-39). Ini lebih tahan lama (Pyramid of Pain).
- Strategic/operational menentukan apa yang diprioritaskan SOC: data, detection, latihan.

### 3.2 Intel di ES: dua sistem

Dokumentasi ES 8 membedakan [S3][S4]:
- Threat Intelligence Framework (on-prem/klasik): mengunduh threat source, mengurai indikator, lalu memuatnya ke KV Store collections untuk threat matching [S3].
  - **Sumber intel bawaan:** Emerging Threats (compromised IPs, firewall IP rules), SANS blocklist, beberapa I-Blocklist (Tor, Spyware, Web attacker, Proxy, dll.), Malware domain host list (Hail a TAXII), Phishtank [S3].
  - Generic intelligence (memperkaya data, bukan threat collection): Cisco Umbrella 1M sites, daftar TLD ICANN, MaxMind GeoIP ASN, Mozilla Public Suffix List, MITRE ATT&CK [S3].
  - **Format/metode yang didukung:** STIX/TAXII, OpenIOC, file terstruktur, API/URL, database. Menambah feed TAXII dilakukan lewat Configure > Threat Intelligence, cek menu di ES 8.7 [S5].
  - **Jenis IOC:** sertifikat X509, email, file (nama/hash), HTTP, IP/domain, proses, registry, service, user [S5].
- **Threat Intelligence Management (Cloud)**: tersedia otomatis untuk ES cloud (versi 6.6 ke atas) di region AWS tertentu. Splunk Intel Management (Legacy) sudah end of sale [S4], cek status terkini dan ketersediaan di deployment on-prem.

Istilah ES 8: *intelligence workflow* menjadi threat list; *threat object/indicator* menjadi observable (Day 45).

### 3.3 Annotations: tujuan dan cakupan

**Apa itu:** metadata yang ditempelkan pada detection (dan analytic story) untuk memetakan detection ke framework dan konteks [S6].

**Tujuan:**
1. **Konteks bagi analyst:** finding menunjukkan teknik ATT&CK atau kontrol terkait, sehingga analyst langsung tahu perilaku apa yang dicurigai.
2. **Pelaporan cakupan:** berapa teknik/kontrol yang ditangani detection aktif (Detection Studio, Day 27).
3. **Agregasi risiko:** event risiko membawa annotation, sehingga bisa dianalisis per taktik/teknik di Risk Analysis (Day 35) [S6].
4. **Kepatuhan:** memetakan detection ke kontrol (CIS, NIST, PCI DSS) untuk audit.

**Cakupan (scope):**
- Framework managed di ES 8.7: MITRE ATT&CK, CIS Critical Security Controls, NIST Cybersecurity Framework, Lockheed Martin Cyber Kill Chain, plus PCI DSS 4.0 [S6].
- **Annotation dari ESCU:** Analytic Story, Confidence, Context, Impact (Day 45) [S7].
- **Managed vs unmanaged:**
  - *managed* disediakan Splunk/ESCU dan diperkaya konteks standar (deskripsi teknik, platform, URL);
  - *unmanaged* adalah label kustom tanpa pengayaan [S6].
- **Di mana disimpan dan terlihat:**
  - JSON di `savedsearches.conf` (`action.correlationsearch.annotations`);
  - field `annotations.<framework>.<field>` pada event;
  - label di Mission Control (analyst queue) dan dashboard Risk Analysis;
  - bisa dicari di `index=risk`. Unmanaged muncul di `annotations._all` dan `annotations._frameworks` [S6].
- **Framework tambahan:** bisa dibuat sendiri (intelligence download + lookup definition + automatic lookup), misalnya dengan mengkloning konfigurasi ATT&CK [S6].

**Yang bukan annotation:** annotation tidak mengubah logika deteksi. Ia label konteks. Detection tanpa annotation tetap berjalan, tetapi analyst kehilangan konteks dan laporan cakupan menjadi bolong.

### 3.4 Enterprise vs ES

- Tanpa ES: intel bisa dipakai dengan lookup biasa (bagian 3.5 dan Day 12), dan mapping ATT&CK dengan lookup kustom (bagian 4.4).
- Dengan ES: framework intel terkelola (download, parsing, collection, threat match), annotation terkelola, dan tampilan di finding dan risk.

### 3.5 Intel tanpa ES dan masa berlaku indikator

Di Splunk Enterprise tanpa ES, threat match bisa ditiru dengan lookup CSV. Strukturnya cukup sederhana: satu baris per indikator dengan kolom `indicator`, `type`, `source`, `first_seen`, `expires`, dan `confidence`. Search lalu mencocokkan field data (mis. `dest_ip` atau `query`) ke kolom `indicator`, dan hanya memakai baris yang belum kedaluwarsa:

```
index=dns earliest=-24h
| stats count min(_time) AS first max(_time) AS last BY src query
| lookup lab_ioc.csv indicator AS query OUTPUT type source expires confidence
| where isnotnull(source) AND strptime(expires, "%Y-%m-%d") > now()
| convert ctime(first) ctime(last)
```

- `lookup` ditaruh setelah `stats`, sehingga pencocokan hanya dilakukan pada nilai unik, bukan pada setiap event (Day 12).
- `where ... expires > now()` membuang indikator yang sudah lewat masa berlakunya. Tanpa ini, IP yang dulu dipakai C2 dan kini dipakai layanan sah tetap memicu match.
- **Cara membaca hasil:** match dengan `confidence` rendah dan sumber tunggal adalah petunjuk untuk diperiksa, bukan kesimpulan. Match yang muncul di beberapa sumber, atau yang cocok dengan perilaku lain di host yang sama, layak naik prioritas.

Kenapa masa berlaku penting: indikator technical cepat basi. IP di cloud publik atau hosting murah berganti penyewa dalam hitungan hari, domain bisa di-sinkhole atau kedaluwarsa, sedangkan hash tetap valid tetapi mudah diganti penyerang. Aturan praktis yang banyak dipakai tim SOC adalah memberi IP masa berlaku pendek (mingguan sampai bulanan), domain sedikit lebih panjang, dan hash paling panjang. Angka persisnya keputusan tim, jadi tulis kebijakannya dan terapkan konsisten. Feed yang tidak mencantumkan tanggal pertama atau terakhir terlihat sebaiknya diberi `confidence` lebih rendah.

## 4. Contoh SPL dan langkah di ES

> Keluaran berlabel ilustrasi. Nama collection dan data model intel, cek di ES 8.7.

### 4.1 Melihat isi collection intel (ES)

```
| inputlookup ip_intel
| stats count BY threat_key
| sort - count
```

- `ip_intel` adalah collection indikator IP di Threat Intelligence Framework. Collection lain mengikuti jenis IOC (file, http, email, certificate, process, registry, service, user) [S5], cek nama persis.
- `threat_key` menunjukkan sumber/feed asal indikator, cek nama field.
- **Cara membaca hasil:** feed yang menyumbang jutaan indikator berkualitas rendah adalah calon sumber false positive.

### 4.2 Aktivitas yang cocok dengan intel (ES)

```
| tstats summariesonly=false count from datamodel=Threat_Intelligence.Threat_Activity
    by Threat_Activity.threat_match_field Threat_Activity.threat_match_value Threat_Activity.threat_collection
| rename Threat_Activity.* AS *
| sort - count
```

- Data model Threat_Intelligence (dataset Threat_Activity) berasal dari ES, bukan CIM umum, cek nama dan field di ES 8.7.
- **Cara membaca hasil:** match pada `dest` ke IP Tor bisa berarti user memakai Tor (pelanggaran kebijakan), bukan malware. Konteks tetap penting.

### 4.3 Annotation pada event risiko

```
index=risk earliest=-7d
| stats count dc(risk_object) AS entities values(source) AS detections
    BY annotations.mitre_attack.mitre_tactic annotations.mitre_attack.mitre_technique_id
| sort - count
```

- Melihat detection mana menghasilkan event risiko per taktik/teknik [S6]. Pola sama dengan Day 29 bagian 4.1.
- Untuk melihat label kustom: `| stats count by annotations._frameworks`, perlu dicek.

### 4.4 Lab tanpa ES: meniru annotation dengan lookup

```
index=sysmon EventCode=1 Image="*\\schtasks.exe" CommandLine="*/create*"
| stats count BY host User
| eval detection="lab_schtasks_create"
| lookup lab_detection_annotations.csv detection OUTPUT mitre_technique_id mitre_tactic kill_chain_phase
```

- `lab_detection_annotations.csv` (buatan sendiri): header `detection,mitre_technique_id,mitre_tactic,kill_chain_phase`, contoh baris `lab_schtasks_create,T1053.005,Persistence,Installation`, cek ID dan taktik di ATT&CK v19.
- Ini meniru apa yang dilakukan annotation ES: label konteks yang menempel pada hasil detection.

### 4.5 Langkah di ES (generik)

1. **Intel:** Configure > Threat Intelligence (atau menu threat list di ES 8.7), periksa feed bawaan, aktifkan yang relevan, lalu tambahkan feed TAXII/CSV milik sendiri bila ada [S5].
2. **Annotation:** Configure > Content management, pilih detection, buka Annotations, lalu tambahkan ATT&CK/CIS/NIST/Kill Chain [S6].
3. Verifikasi di finding (analyst queue) bahwa label muncul.

## 5. Lab praktik

1. Ambil satu laporan ancaman publik (penerbit dan tahun disebut). Pecah isinya ke empat tingkatan (bagian 3.1), dengan kata-katamu sendiri. Tandai bagian yang tidak ada (biasanya operational).
2. Dari bagian technical, buat CSV indikator fiktif atau uji (domain `.example`, IP dokumentasi `192.0.2.x`), lalu:
   - **dengan ES:** tambahkan sebagai threat source, picu trafik uji dari VM lab, dan periksa threat match;
   - **tanpa ES:** pakai lookup (Day 12).
3. Dari bagian tactical, tulis satu detection perilaku (mis. dari Day 30) dan beri annotation ATT&CK, lewat ES atau lookup bagian 4.4.
4. Jalankan bagian 4.3 atau versi lab-mu untuk melihat hasil berlabel.
5. Tulis 5 kalimat: kenapa detection berbasis tactical intel lebih tahan lama daripada technical intel.

**Hasil yang sebaiknya tersimpan:**
- Laporan dipecah ke 4 tingkat (dengan sumber).
- Threat match/lookup IOC uji bekerja.
- Satu detection dengan annotation ATT&CK.
- Penjelasan ketahanan TTP vs IOC.

**Variasi tantangan:** buat framework annotation kustom sederhana, misalnya pemetaan ke kontrol ISO/IEC 27001:2022 Annex A hanya dengan nomor dan judul singkat (mis. 8.15 Logging, 8.16 Monitoring activities, 5.26 Response to information security incidents; jangan menyalin teks standar). Terapkan ke 3 detection lab.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Collection intel kosong | Feed nonaktif, gagal unduh (proxy/firewall), parsing gagal | Status threat source; log unduhan, cek lokasi log |
| Banyak threat match palsu | Feed berkualitas rendah atau basi (IP berganti pemilik) | Nonaktifkan feed lemah; terapkan masa berlaku indikator (bagian 3.5) |
| Annotation tidak muncul di finding | Detection lama tanpa annotation; framework kustom tanpa automatic lookup | Tambahkan annotation; lengkapi tiga komponen framework kustom [S6] |
| Feed TAXII tidak terbaca | Versi TAXII/format STIX tidak cocok | Cek dokumentasi format yang didukung ES 8.7, perlu dicek |

## 7. Kesalahan umum dan jebakan

- Menganggap feed IOC = threat intelligence lengkap. Itu hanya technical intel [S1].
- Memakai label tier tanpa definisi (tactical vs operational berbeda antar sumber) [S1][S2].
- Menganggap annotation mengubah deteksi. Annotation adalah konteks, bukan logika.
- Tidak memperbarui mapping ATT&CK setelah v19 (Stealth/Defense Impairment) (Day 30).
- Mengaktifkan semua feed bawaan tanpa evaluasi relevansi. Akibatnya noise.
- Mencocokkan indikator tanpa melihat masa berlaku dan confidence-nya (bagian 3.5).

## 8. Catatan terkini

- Intel Management (Legacy) end of sale; Threat Intelligence Management (Cloud) disertakan pada ES cloud di region tertentu [S4], perlu dicek.
- ES 8.7 annotations mencakup PCI DSS 4.0 selain empat framework utama [S6].
- ES 8.3.0 (19 Nov 2025) menambahkan manajemen versi detection yang lebih baik [S4]. Ini relevan saat annotation berubah antar versi detection.
- ATT&CK v19.2 dipakai sebagai generic intelligence di ES. Pastikan konten ES memperbarui lookup ATT&CK-nya, cek versi ATT&CK yang dibundel ES 8.7.

## 9. Cheat sheet

```
TIER (MWR, 4)  Strategic: risiko/tren -> board | Operational: serangan spesifik akan datang -> defender (langka)
               Tactical: TTP -> arsitek/detection eng. (awet) | Technical: IOC -> SOC/otomasi (cepat basi)
               AWAS: model 3-tier vendor -> "tactical"=IOC. Sebut ISINYA.
ES INTEL       Threat Intelligence Framework: threat source -> parse -> KV collections -> threat match
               bawaan: Emerging Threats, SANS, I-Blocklist (Tor...), Hail a TAXII, Phishtank
               generic: Umbrella 1M, ICANN TLD, MaxMind ASN, Public Suffix, MITRE ATT&CK
               format: STIX/TAXII, OpenIOC, file, API/URL, DB ; IOC: cert, email, file, http, ip/domain, process, registry, service, user
               TIM (Cloud) untuk ES cloud ; Intel Management (Legacy) end of sale
ANNOTATION     TUJUAN: konteks finding | laporan cakupan | analisis risiko per teknik | kepatuhan
               CAKUPAN: detection & analytic story ; managed (ATT&CK, CIS, NIST CSF, Kill Chain, PCI DSS 4.0; ESCU: story/confidence/context/impact)
                        vs unmanaged (kustom) ; JSON di savedsearches.conf ; annotations.<fw>.<field> ; index=risk ; Mission Control/Risk Analysis
               BUKAN logika deteksi
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | MWR/CPNI/CERT-UK: Threat Intelligence: Collecting, Analysing, Evaluating | https://www.ismsforum.es/ficheros/descargas/threat-intelligence--collecting-analysing.pdf | primer | 2015 (>3 tahun); diakses 2026-10-07 | Tinggi untuk taksonomi |
| S2 | Flashpoint: Three types of threat intelligence | https://flashpoint.io/blog/three-types-of-threat-intelligence/ | sekunder | 2025-09, diperbarui 2026-04; diakses 2026-10-07 | Sedang. Konvensi alternatif |
| S3 | ES 8.3: Available threat intelligence and generic intelligence sources included in Splunk ES | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.3/threat-intelligence/available-threat-intelligence-and-generic-intelligence-sources-included-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi |
| S4 | ES release notes 8.3; Threat Intelligence Management (Cloud); Intel Management (Legacy) end of sale | https://help.splunk.com/en/splunk-enterprise-security-8/release-notes-and-resources/8.3/splunk-enterprise-security-release-notes | primer | tanggal tidak tercatat | Sedang-tinggi |
| S5 | ES 8: Add new threat intelligence sources (format, jenis IOC, TAXII) | https://help.splunk.com/ja-jp/splunk-enterprise-security-8/administer/8.0/threat-intelligence/add-new-threat-intelligence-sources-in-splunk-enterprise-security | primer | tanggal tidak tercatat | Sedang-tinggi. Menu perlu dicek di 8.7 |
| S6 | ES 8.7: Add annotations to detections (lihat Day 29) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/detections/add-annotations-to-detections-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi |
| S7 | ES 8: Add ESCU annotations | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.6/managing-security-content/add-escu-annotations-to-detections-and-analytics-stories-in-splunk-enterprise-security | primer | tanggal tidak tercatat | Sedang-tinggi |

**Catatan sumber:** nama collection intel, field `threat_key`, data model Threat_Intelligence, dan menu Threat Intelligence di ES 8.7 belum terkonfirmasi dokumentasi 8.7; cek di instance ES-mu. Status Threat Intelligence Management dan Intel Management (Legacy) berasal dari release notes 8.3 [S4] dan bisa sudah berubah. Masa berlaku indikator di bagian 3.5 adalah praktik umum tim SOC, bukan angka baku dari satu sumber.
