---
day: 14
title: 'Framework, CIA, dan risiko: kontrol/standar/framework industri, cara Splunk memakainya, information assurance dan manajemen risiko dasar'
researched_on: 2026-10-10
versions_checked: NIST CSF 2.0 (26 Feb 2024); CIS Critical Security Controls v8.1 (Jun 2024); MITRE ATT&CK v19.2 (Agu 2026); ISO/IEC 27001:2022 + Amd 1:2024; NIST SP 800-30 Rev.1; FIPS 199; Splunk ES 8.7 (annotations)
---

# Day 14: Framework, CIA, dan risiko

Cakupan: mengenali kontrol, standar, dan framework industri umum serta bagaimana Splunk mengadopsinya; konsep information assurance (confidentiality, integrity, availability) dan manajemen risiko dasar.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- membedakan kontrol, standar, dan framework, serta memberi contoh masing-masing (CIS Controls, ISO/IEC 27001, NIST CSF, MITRE ATT&CK, Cyber Kill Chain).
- menjelaskan bagaimana Splunk ES memakai framework lewat annotations, dan bagaimana SSE memetakan konten ke ATT&CK.
- mendefinisikan confidentiality, integrity, availability, memberi contoh insiden yang merusak masing-masing, dan menyebut atribut tambahan (authenticity, non-repudiation).
- menjelaskan manajemen risiko dasar: threat, vulnerability, likelihood, impact, risk, opsi penanganan, dan risiko residual.

## 2. Konteks singkat

Framework adalah bahasa bersama antara SOC dan manajemen. Analyst berbicara dalam "teknik T1059", auditor dalam "kontrol 8.15", dan direksi dalam "risiko dan dampak". Splunk menjembatani ketiganya: detection diberi annotation ATT&CK, CIS, atau NIST, lalu finding membawa label itu sampai ke laporan. Di sini fokusnya pada cara Splunk memakai framework itu di detection dan laporan.

## 3. Konsep inti

### 3.1 Kontrol, standar, framework

| Istilah | Arti | Contoh |
|---|---|---|
| Kontrol | Tindakan atau mekanisme yang mengurangi risiko (preventif, detektif, korektif) | MFA, logging terpusat, backup, EDR |
| Standar | Dokumen persyaratan atau spesifikasi yang bisa diaudit | ISO/IEC 27001 (persyaratan ISMS; bisa disertifikasi), PCI DSS |
| Framework | Struktur untuk mengorganisasi praktik/kontrol/pengetahuan; sering sukarela | NIST CSF 2.0, CIS Controls, MITRE ATT&CK, Cyber Kill Chain |

Garisnya tidak selalu tajam. CIS Controls disebut "controls" tetapi berfungsi sebagai framework kontrol yang diprioritaskan.

### 3.2 Framework utama (keadaan 2026)

- NIST CSF 2.0 (26 Feb 2024): enam fungsi, yaitu Govern (baru), Identify, Protect, Detect, Respond, Recover. Berlaku untuk semua organisasi, tidak hanya infrastruktur kritis [S1].
- CIS Critical Security Controls v8.1 (Juni 2024): pembaruan iteratif dari v8.0. Glosarium diperluas, kelas aset direvisi (menambah tipe aset *Documentation*), dan pemetaan fungsi keamanan diselaraskan dengan NIST CSF 2.0. Sampai Oktober 2026 belum ada v9 yang dirilis; cek situs CIS bila membaca catatan ini jauh setelahnya [S2].
- ISO/IEC 27001:2022 (+ Amd 1:2024): standar persyaratan sistem manajemen keamanan informasi (ISMS) yang bisa disertifikasi [S7]. Klausul 4-10 berisi persyaratan sistem manajemen (konteks, kepemimpinan, perencanaan risiko, dukungan, operasi, evaluasi kinerja, perbaikan). Annex A memuat 93 kontrol dalam empat tema: organizational (37), people (8), physical (14), dan technological (34). Kontrol yang paling dekat dengan pekerjaan SOC ada di tema technological, misalnya 8.15 Logging, 8.16 Monitoring activities, dan 5.25-5.26 untuk penilaian dan respons insiden di tema organizational. Amd 1:2024 hanya menambahkan pertimbangan perubahan iklim di klausul konteks, tanpa mengubah kontrol.
- MITRE ATT&CK (v19.2, Agustus 2026): basis pengetahuan taktik (tujuan, mis. Privilege Escalation, Command and Control) dan teknik (cara, mis. Kerberoasting) berdasarkan observasi dunia nyata [S3][S4]. Sejak v18, deteksi dipetakan lewat Detection Strategies/Analytics (Day 08).
- **Lockheed Martin Cyber Kill Chain**: tujuh fase intrusi, yaitu Reconnaissance, Weaponization, Delivery, Exploitation, Installation, Command & Control, Actions on Objectives. Ini model linear lama yang tetap dipakai sebagai annotation di ES [S3], cek penulisan nama fase di lookup annotation ES.

**Peran framework untuk SOC:** ATT&CK dan Kill Chain menjelaskan perilaku penyerang (tactical). CSF, CIS, dan ISO menjelaskan program pertahanan (strategis/kontrol). Detection bisa dipetakan ke keduanya. Satu detection PowerShell, misalnya, berkaitan dengan teknik ATT&CK tertentu dan dengan fungsi CSF *Detect*.

### 3.3 Bagaimana Splunk mengadopsi framework

Annotations di ES 8.7 [S3]:
- Framework managed bawaan: MITRE ATT&CK, CIS Critical Security Controls, NIST Cybersecurity Framework, Lockheed Martin Cyber Kill Chain, ditambah kontrol tata kelola PCI DSS 4.0.
- **Unmanaged annotations:** kustom, tanpa pengayaan standar industri.
- Definisi ATT&CK diisi di `security_framework_annotations.csv`.
- Annotation disimpan di `savedsearches.conf` dalam format JSON pada `action.correlationsearch.annotations`.
- Field hasil berpola `annotations.<framework>.<field>`, mis. `annotations.mitre_attack.mitre_technique_id`, `annotations.mitre_attack.mitre_tactic`.
- UI: Configure > Content management, pilih detection, lalu buka bagian Annotations (tombol + Framework untuk framework kustom).
- Annotation tampil sebagai label di Mission Control dan dashboard Risk Analysis, dan bisa dicari lewat `index=risk`.
- Framework kustom butuh intelligence download, lookup definition, dan automatic lookup. Bisa dikloning dari konfigurasi ATT&CK [S3].

Detail annotation dibahas di Day 16.

**SSE:** memetakan konten ke ATT&CK dan Kill Chain, serta menyediakan dashboard ATT&CK dan Benchmark (Day 06, 12).
**research.splunk.com / ESCU:** setiap detection memuat mapping ATT&CK dan sering juga Kill Chain, CIS, dan NIST (Day 06).
**Kepatuhan:** Splunk App for PCI Compliance memakai CIM yang sama (Day 09).

### 3.4 CIA dan information assurance

Definisi FIPS 199 (FISMA) [S5]:
- **Confidentiality:** mempertahankan pembatasan akses dan pengungkapan informasi yang sah, termasuk melindungi privasi dan informasi proprietary. *Pelanggarannya:* pengungkapan tanpa izin.
- **Integrity:** menjaga dari modifikasi atau perusakan informasi yang tidak semestinya, termasuk menjamin non-repudiation dan authenticity. *Pelanggarannya:* modifikasi atau perusakan tanpa izin.
- **Availability:** menjamin akses dan penggunaan informasi yang tepat waktu dan andal. *Pelanggarannya:* gangguan akses atau penggunaan.

FIPS 199 menilai dampak hilangnya C, I, atau A sebagai low (terbatas), moderate (serius), atau high (parah/katastrofik) [S5].

| Insiden | Pilar utama yang rusak | Sinyal di Splunk |
|---|---|---|
| Exfiltration data pelanggan | Confidentiality | Volume keluar besar (Network_Traffic/Web), akses massal (Data_Access) |
| Defacement web | Integrity | Perubahan file web (Endpoint.Filesystem), upload POST (Web) |
| Ransomware | Availability (+ sering Confidentiality bila double extortion) | Banyak file dimodifikasi, proses mencurigakan (Endpoint), shadow copy dihapus |
| DDoS | Availability | Lonjakan koneksi (Network_Traffic), error layanan (Web status 5xx) |
| Log dihapus penyerang | Integrity (dan akuntabilitas) | Event 1102 "The audit log was cleared" di log Security, sumber berhenti mengirim (Day 08) |

Information assurance lebih luas dari keamanan teknis. Ia mencakup kepercayaan bahwa informasi tetap C, I, A, plus authenticity (benar dari sumber yang diklaim) dan non-repudiation (pelaku tidak bisa menyangkal tindakannya). Bagi SOC, logging yang lengkap dan terlindungi adalah kontrol non-repudiation yang nyata.

### 3.5 Manajemen risiko dasar

Konsep dari NIST SP 800-30 Rev. 1 [S6]:
- **Threat:** keadaan atau peristiwa yang berpotensi berdampak buruk.
- **Vulnerability:** kelemahan pada sistem, prosedur, atau implementasi kontrol yang bisa dieksploitasi sumber ancaman.
- **Likelihood:** kemungkinan peristiwa ancaman terjadi dan menimbulkan dampak (memperhitungkan kemampuan, niat, dan penargetan adversary, serta kerentanan).
- **Impact:** besarnya kerugian (operasi, aset, individu, finansial, legal, reputasi).
- **Risk:** fungsi dari likelihood dan impact.

**Siklus manajemen risiko (umum):** identifikasi, analisis/penilaian (likelihood x impact), evaluasi terhadap risk appetite, penanganan, lalu pemantauan dan tinjauan. Siklus ini berulang.

**Opsi penanganan:**

| Opsi | Arti | Contoh SOC |
|---|---|---|
| Mitigate/modify | Mengurangi likelihood atau impact dengan kontrol | Tambah detection, MFA, segmentasi |
| Transfer/share | Memindahkan sebagian ke pihak lain | Asuransi siber, MSSP |
| Avoid | Menghentikan aktivitas berisiko | Mematikan layanan yang tidak perlu |
| Accept/retain | Menerima secara sadar dan terdokumentasi | Risiko rendah di aset non-kritis |

Inherent risk adalah risiko sebelum kontrol; residual risk adalah sisa setelah kontrol. Risiko tidak pernah nol, dan keputusan menerima residual risk adalah keputusan manajemen, bukan SOC.

**Kaitan dengan ES:** *Risk-Based Alerting* (Day 22) memakai konsep yang mirip tetapi berbeda: skor risiko diberikan ke entity berdasarkan perilaku yang diamati. Itu bukan penilaian risiko organisasi ala SP 800-30. Jangan mencampur istilahnya di ujian: "risk" di RBA berarti akumulasi sinyal per entity.

### 3.6 Enterprise vs ES

- Mapping framework di level SPL bisa dilakukan di Splunk Enterprise biasa (lookup + eval).
- ES menyediakan annotations terkelola, tampilan di finding dan dashboard risiko, serta pemetaan ATT&CK di Detection Studio (Day 12) [S3].

## 4. Contoh SPL dan langkah di ES

> Keluaran berlabel ilustrasi.

### 4.1 Cakupan ATT&CK dari risk index (ES)

```
index=risk earliest=-30d
| stats count dc(risk_object) AS entities BY annotations.mitre_attack.mitre_tactic annotations.mitre_attack.mitre_technique_id
| sort - count
```

- Menunjukkan taktik dan teknik ATT&CK yang paling sering muncul dalam event risiko (intermediate finding).
- `risk_object`: field entity di risk index (nama klasik), cek nama field di ES 8.7 (mungkin tetap `risk_object` meskipun UI menyebut "entity").
- **Cara membaca hasil:** teknik yang dominan menunjukkan apa yang paling sering dilihat detection-mu, bukan cakupan. Cakupan dilihat di Detection Studio (Day 12).

### 4.2 Peta detection ke framework (ES, via REST)

```
| rest /servicesNS/-/-/saved/searches splunk_server=local count=0
| search action.correlationsearch.enabled=1
| table title action.correlationsearch.annotations
| spath input=action.correlationsearch.annotations
| table title mitre_attack{} cis20{} nist{} kill_chain_phases{}
```

- Annotation disimpan sebagai JSON di `action.correlationsearch.annotations` [S3].
- `spath` mengurai JSON menjadi field. Nama key framework (`mitre_attack`, `cis20`, `nist`, `kill_chain_phases`), cek di instance ES-mu dengan melihat isi JSON mentah terlebih dahulu.
- `action.correlationsearch.enabled=1` adalah atribut ES klasik, cek di ES 8.

### 4.3 Matriks risiko sederhana dengan makeresults (latihan konsep)

```
| makeresults format=csv data="risk,likelihood,impact
Ransomware di file server,4,5
Phishing kredensial eksekutif,4,4
Laptop lab tanpa patch,3,1
DDoS situs pemasaran,2,2"
| eval score=likelihood*impact
| eval level=case(score>=15,"high", score>=8,"medium", true(),"low")
| eval treatment=case(level=="high","mitigate", level=="medium","mitigate/transfer", true(),"accept (dokumentasikan)")
| sort - score
```

- Skala 1-5 dan ambang adalah asumsi latihan, bukan standar.
- **Cara membaca hasil:** ini cara cepat menjelaskan prioritas ke manajemen. Hubungkan risiko "high" dengan detection dan data yang dibutuhkan (Day 08/12).

### 4.4 Di ES (generik)

1. Configure > Content management, pilih detection, buka Annotations, lalu tambahkan teknik ATT&CK atau kontrol CIS/NIST [S3].
2. Verifikasi bahwa annotation muncul pada finding dan di dashboard Risk Analysis [S3].

## 5. Lab praktik

1. Ambil 3 detection dari research.splunk.com (Day 06). Catat mapping ATT&CK, dan bila ada, Kill Chain, CIS, dan NIST.
2. Untuk masing-masing, tentukan fungsi NIST CSF 2.0 yang paling relevan (biasanya Detect; bila ada aksi respons, Respond).
3. Isi tabel CIA bagian 3.4 untuk 3 skenario serangan di lab-mu (mis. defacement BOTS v1, ransomware BOTS v1, brute force RDP lab).
4. Jalankan bagian 4.3 dengan 6 risiko lab-mu sendiri, lalu tentukan penanganan untuk masing-masing.
5. (Dengan ES) Tambahkan annotation ATT&CK ke satu detection kustom (mis. dari Day 02 bagian 4.3), picu detection itu, lalu jalankan bagian 4.1.

**Hasil yang sebaiknya tersimpan:**
- Tabel pemetaan detection ke ATT&CK/CSF/CIS.
- Tabel CIA untuk 3 skenario.
- Matriks risiko lab dengan penanganan.
- (ES) Annotation terlihat di risk index.

**Variasi tantangan:** buat lookup kustom yang memetakan teknik ATT&CK ke kontrol CIS v8.1 yang relevan (minimal 5 baris, dibuat sendiri). Pakai di bagian 4.1 untuk menunjukkan "kontrol mana yang paling sering diuji penyerang di lab". Cek pemetaan dengan dokumen pemetaan resmi CIS-ATT&CK bila tersedia.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Field `annotations.*` tidak ada di risk index | Detection tanpa annotation; atau versi lama | Tambahkan annotation [S3]; cek isi event risk |
| Framework kustom tidak terisi detailnya | Lookup/automatic lookup belum dibuat | Ikuti tiga komponen framework kustom [S3] |
| Mapping ATT&CK usang | Lookup ATT&CK lama; teknik berganti ID | Perbarui konten ESCU dan lookup; cek versi ATT&CK (v19.2) [S4] |
| Diskusi risiko macet di "semua high" | Skala tidak dikalibrasi | Definisikan kriteria likelihood/impact tertulis |

## 7. Kesalahan umum dan jebakan

- Menyamakan "risk" di RBA dengan penilaian risiko organisasi (bagian 3.5).
- Menganggap ATT&CK adalah framework kepatuhan. Ia basis pengetahuan perilaku penyerang, bukan daftar persyaratan.
- Menyebut CSF 1.1 (lima fungsi) padahal versi berlaku adalah 2.0 dengan Govern [S1].
- Menyebut CIS "Top 20" (istilah era v7). Sejak v8, jumlahnya 18 kontrol, dan v8.1 tetap 18.
- Mengira availability hanya soal DDoS. Ransomware dan kesalahan konfigurasi juga merusak availability.
- `[komunitas]` Tidak ada sumber komunitas. Day ini konseptual dan bersumber dokumen primer.

## 8. Catatan terkini

- NIST CSF 2.0 (Feb 2024) menambah fungsi Govern [S1].
- CIS Controls v8.1 (Jun 2024) diselaraskan dengan CSF 2.0 [S2].
- **ATT&CK v18 sampai v19.2**: perubahan model deteksi (Detection Strategies/Analytics) dan rilis Agile (Day 08) [S4].
- ES 8.7 menyertakan annotation PCI DSS 4.0 selain empat framework utama [S3].

## 9. Cheat sheet

```
KONTROL = mekanisme (MFA, logging) | STANDAR = persyaratan teraudit (ISO 27001, PCI DSS) | FRAMEWORK = struktur (CSF, CIS, ATT&CK, Kill Chain)
CSF 2.0   Govern | Identify | Protect | Detect | Respond | Recover  (Feb 2024)
CIS       v8.1 (Jun 2024), selaras CSF 2.0
ATT&CK    taktik = TUJUAN ; teknik = CARA ; v19.2 ; v18: Detection Strategies + Analytics
KILL CHAIN Recon -> Weaponization -> Delivery -> Exploitation -> Installation -> C2 -> Actions on Objectives
ES ANNOT  managed: MITRE ATT&CK, CIS, NIST CSF, Kill Chain (+PCI DSS 4.0) | unmanaged: kustom
          annotations.<fw>.<field> ; savedsearches.conf action.correlationsearch.annotations (JSON)
          Configure > Content management > detection > Annotations ; terlihat di index=risk
CIA (FIPS 199)  C = cegah pengungkapan | I = cegah modifikasi (+authenticity, non-repudiation) | A = akses tepat waktu & andal
                dampak low / moderate / high
RISIKO    threat x vulnerability -> likelihood ; impact ; risk = f(likelihood, impact)
          treatment: mitigate | transfer | avoid | accept ; inherent vs residual ; appetite
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | NIST: The NIST Cybersecurity Framework (CSF) 2.0 (NIST CSWP 29) | https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf | primer | 2024-02-26; diakses 2026-10-10 | Tinggi. Enam fungsi, cakupan semua organisasi |
| S2 | CIS: CIS Critical Security Controls v8.1 / Change Log | https://www.cisecurity.org/insights/white-papers/cis-critical-security-controls-v8-1 | primer | 2024-06 | Tinggi |
| S3 | ES 8.7: Add annotations to detections in Splunk Enterprise Security | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/detections/add-annotations-to-detections-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi |
| S4 | MITRE ATT&CK: Updates (v19.2) (lihat Day 08) | https://attack.mitre.org/resources/updates/ | primer | diakses 2026-10-07 | Tinggi |
| S5 | NIST FIPS 199: Standards for Security Categorization of Federal Information and Information Systems | https://csrc.nist.gov/pubs/fips/199/final | primer | 2004 (>3 tahun); diakses 2026-10-10 | Tinggi untuk definisi CIA dan tingkat dampak |
| S6 | NIST SP 800-30 Rev. 1: Guide for Conducting Risk Assessments | https://csrc.nist.gov/pubs/sp/800/30/r1/final | primer | 2012-09 (>3 tahun); diakses 2026-10-10 | Tinggi. Definisi di bagian 3.5 ditulis ulang dengan kata sendiri; cocokkan dengan glosarium dokumen bila dikutip |
| S7 | ISO: ISO/IEC 27001:2022 Information security management systems (halaman komite) | https://committee.iso.org/standard/82875.html | primer | 2022-10; diakses 2026-10-10 | Tinggi untuk edisi dan status; isi standar berbayar |
| S8 | Lockheed Martin Cyber Kill Chain (fase), ditampilkan sebagai annotation di S3 | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/detections/add-annotations-to-detections-in-splunk-enterprise-security | primer (via S3) | diakses 2026-10-07 | Nama fase, cek di lookup ES |

**Catatan sumber:** jumlah kontrol CIS v8.1 (18) dan penulisan nama fase Kill Chain di lookup annotation ES perlu dicek di instance ES-mu [S3][S8]. Nomor dan judul kontrol ISO/IEC 27001 Annex A ditulis dari struktur standar edisi 2022; teks kontrolnya sendiri berbayar dan tidak disalin [S7].
