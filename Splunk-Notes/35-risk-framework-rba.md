---
day: 35
title: Risk framework dan Risk-Based Alerting (RBA) di ES
researched_on: 2026-10-10
versions_checked: Splunk ES 8.7 (Risk scoring / risk-based alerting); Splunk blog "The New & Improved Splunk Guide to Risk-Based Alerting" (Haylee Mills, 29 Agu 2024); komunitas RBA (github.com/splunk/rba, splunk.github.io/rba); ES 8.7 glosarium
---

# Day 35: Risk framework dan Risk-Based Alerting (RBA)

Cakupan: memahami dan menjelaskan dasar Risk Based Alerting dan Risk framework.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan kenapa RBA ada: alert fatigue, dan sinyal lemah yang bermakna bila digabung.
- menjelaskan komponen risk framework ES: risk rule/event-based detection dengan risk analysis, intermediate finding (risk event), entity, risk score, risk factor, finding-based detection (risk incident rule), finding group (risk notable).
- merancang risk rule (entity, tipe, skor, threat object, pesan) dan risk incident rule (ambang skor, keragaman sumber/taktik).
- menyetel RBA: mengatasi *score stacking*, memakai risk factor, dan memakai panel "event risiko tanpa risk notable".

## 2. Konteks singkat

Model alert tradisional: setiap detection langsung menjadi notable. Akibatnya detection yang "lemah tapi berguna" (mis. PowerShell dengan argumen tertentu, akses ke share tak biasa) dimatikan karena berisik, dan analyst tenggelam.

RBA membalik pendekatan itu:
- Detection lemah tidak langsung menjadi alert. Ia memberi skor risiko pada sebuah entity (user/sistem).
- Alert (finding group) baru muncul ketika akumulasi atau pola risiko pada satu entity cukup kuat.

Splunk menggambarkan RBA sebagai cara mengurangi jumlah alert sambil menaikkan fidelitasnya [S2]. FAQ RBA di komunitas Splunk menyebut pelanggan melihat penurunan volume alert 50-90% [S7]. Perlakukan angka itu sebagai klaim vendor dengan rentang lebar: materi Splunk lain pernah memakai rentang berbeda, dan hasil di organisasimu bergantung pada berapa banyak detection berisik yang dipindah ke risk. Ukur sendiri volume finding sebelum dan sesudah.

## 3. Konsep inti

### 3.1 Komponen dan alur (ES 8.7)

```
Risk rule (event-based detection + risk analysis)
   |  setiap match -> INTERMEDIATE FINDING (risk event) di index=risk
   |                  { entity, entity type (system|user), risk score, risk message, threat object(s), annotations }
   v
Risk factors (pengali kontekstual, mis. user_category, prioritas aset)
   v
Risk incident rule (finding-based detection): ambang skor dalam jendela waktu, keragaman taktik/sumber
   v
FINDING GROUP ("risk notable") di analyst queue  -> investigation -> disposition
```

Definisi dari dokumentasi ES 8.7 [S1]:
- **Risk score:** metrik tunggal yang menunjukkan risiko relatif sebuah entity dari waktu ke waktu.
- **Entity:** aset, identitas, user, atau perangkat. Tipenya `system` (dicocokkan dengan lookup aset) atau `user` (lookup identitas).
- **Intermediate finding:** dibuat saat detection menemukan event mencurigakan, berisi entity, tipe entity, risk score, dan risk message, lalu diindeks di risk index.
- **Risk modifier / pengaturan risiko di detection:** pengaturan yang memberi skor ke entity saat detection cocok: field entity, tipe entity, skor, threat object, dan pesan.
- Risk factor (lewat Risk Factor Editor): menyesuaikan skor intermediate finding berdasarkan atribut konteks, misalnya mengalikan skor untuk `user_category` tertentu atau prioritas aset.
- **Finding-based detection:** mengagregasi intermediate finding dengan ambang. Contoh default yang disebut dokumentasi: skor risiko melewati ambang dalam 24 jam, atau terwakilinya beberapa taktik ATT&CK. Saat ambang terlewati, finding dibuat untuk diinvestigasi [S1].
- **Risk analysis dashboard:** Analytics > Dashboards > Risk analysis. Menampilkan skor per entity dan annotation, timeline, serta Ad-Hoc Risk Entry untuk penyesuaian skor manual [S1].
- Risk badge di analyst queue: kuning 0-25, oranye 25-50, merah muda 50-75, merah tua 75+, untuk entity dengan event risiko dalam 7 hari terakhir [S1].

**Catatan field:** dokumentasi ES 8.7 memakai istilah *entity/entity type*. Nama field klasik di risk index adalah `risk_object` dan `risk_object_type` (Day 31), cek nama field fisik di ES 8.7 sebelum menulis SPL produksi.

**Threat object vs entity:**
- Entity adalah korban/pelaku internal yang diberi skor (user, host).
- Threat object (ES 8: observable) adalah artefak ancaman yang menyertai: hash, domain, IP eksternal, command line [S5].

Membedakan keduanya penting untuk deduplikasi dan korelasi lintas entity. Contoh: satu domain berbahaya muncul di 10 host.

### 3.2 Merancang risk rule

Pertimbangan per rule:
1. **Entity yang tepat:** `user`, `dest` (host), atau keduanya. Banyak detection memberi risiko ke dua entity (user dan sistem).
2. **Skor:** proporsional dengan kepercayaan (confidence) dan dampak (impact). ESCU menyediakan annotation Confidence/Impact (Day 45). Detection lemah diberi skor kecil.
3. **Threat object:** artefak yang bisa dipakai untuk pivot dan deduplikasi (hash proses, domain, parent process).
4. **Risk message:** kalimat yang menjelaskan apa yang terjadi, dengan field dinamis. Analyst membacanya di timeline.
5. **Annotation ATT&CK:** wajib agar incident rule berbasis taktik bekerja (Day 29/30).

Panduan RBA menyarankan membangun RBA paralel dengan alerting yang ada, memperkuat threat object untuk tuning, menambah keragaman rule (sumber dan skor), memasukkan sumber berbasis signature (IDS, DLP, EDR) sebagai risiko, dan mengubah konten berisik menjadi risk scoring [S2].

### 3.3 Merancang risk incident rule

Pola umum:

| Pola | Logika | Kekuatan | Risiko |
|---|---|---|---|
| Ambang skor | `sum(risk_score) > N` per entity dalam 24 jam | Sederhana | Score stacking: satu rule berisik bisa mencapai ambang sendirian |
| Keragaman taktik | `dc(taktik ATT&CK) >= k` | Menangkap progresi serangan | Bergantung annotation yang benar |
| Keragaman sumber | `dc(source) >= k` (detection berbeda) | Mencegah stacking dari satu rule | Bisa melewatkan serangan yang hanya memicu satu jenis detection |
| Kombinasi | skor tinggi dan >=2 taktik/sumber | Fidelitas tinggi | Butuh kalibrasi |
| Jendela panjang | ambang lebih rendah dalam 7 hari | Menangkap low-and-slow | Lebih banyak data dan noise |

Komunitas RBA menyediakan contoh search "score stacking limitations", deduplikasi, dan prevalensi threat object [S3][S4] `[komunitas]`. Konsepnya dikonfirmasi oleh dokumentasi ES yang memakai ambang skor dan multi-taktik [S1].

### 3.4 Menyetel RBA

- **Score stacking:** deduplikasi kontribusi per kombinasi (entity, source, threat object) dalam jendela waktu, sebelum dijumlahkan (bagian 4.3).
- **Risk factors:** naikkan skor untuk entity sensitif (admin, eksekutif, server kritis) dan turunkan untuk entity yang diharapkan berisik (jump host, scanner) [S1].
- Allowlist sempit pada risk rule bila benign positive berulang (Day 34).
- Panel Executive summary "jenis event risiko yang tidak menghasilkan risk notable" (Day 32) menunjukkan rule yang tidak pernah berkontribusi. Kandidat dihapus, atau skornya terlalu rendah.
- **Ad-Hoc Risk Entry:** analyst bisa menambah atau mengurangi risiko secara manual saat investigasi [S1]. Gunakan dengan catatan alasan.

### 3.5 Risk di RBA bukan risk management organisasi

Ingat Day 29: risk di RBA adalah akumulasi sinyal perilaku per entity untuk prioritas alert. Itu bukan penilaian risiko organisasi (likelihood x impact atas aset bisnis).

### 3.6 Enterprise vs ES

RBA dan risk framework adalah fitur ES. Di Splunk Enterprise biasa, kamu bisa meniru konsepnya: detection menulis ke index "risk" lab (via `collect`/alert action), lalu saved search mengagregasi per entity (bagian 4.5). Tanpa A&I, risk factor, annotation terkelola, dan finding group.

## 4. Contoh SPL dan langkah di ES

> Keluaran berlabel ilustrasi. Field `risk_object`/`risk_object_type` (klasik), cek di ES 8.7 (mungkin dipetakan ke istilah entity).

### 4.1 Timeline risiko satu entity

```
index=risk earliest=-7d risk_object="alice"
| eval tactic=mvjoin('annotations.mitre_attack.mitre_tactic', ",")
| table _time source risk_score risk_message threat_object tactic
| sort _time
```

**Cara membaca hasil:** progresi taktik (Discovery, lalu Credential Access, lalu Lateral Movement) dalam jam yang berdekatan adalah sinyal kuat. Banyak event dari satu source yang berulang biasanya noise.

### 4.2 Risk incident rule: skor + keragaman (pola)

```
index=risk earliest=-24h
| stats sum(risk_score) AS total_risk dc(source) AS sources
        dc(annotations.mitre_attack.mitre_tactic) AS tactics values(source) AS rules
        BY risk_object risk_object_type
| where total_risk >= 100 AND (sources >= 3 OR tactics >= 2)
| sort - total_risk
```

- Gabungan ambang skor dan keragaman mengurangi stacking.
- Ambang ilustratif. Kalibrasi dengan data 30 hari (bagian 5).

### 4.3 Deduplikasi sebelum menjumlah (anti score stacking)

```
index=risk earliest=-24h
| eval tobj=coalesce(threat_object, "none")
| stats max(risk_score) AS risk_score values(annotations.mitre_attack.mitre_tactic) AS tactic
        BY risk_object risk_object_type source tobj
| stats sum(risk_score) AS total_risk dc(source) AS sources BY risk_object risk_object_type
| where total_risk >= 100
```

- Stats pertama: satu kontribusi per (entity, source, threat object), dengan skor maksimum. Pengulangan dari rule yang sama atas artefak yang sama tidak menumpuk.
- Stats kedua: total per entity.
- Pola ini sejalan dengan diskusi deduplikasi di komunitas RBA [S3][S4] `[komunitas]`.

### 4.4 Rule yang tidak pernah berkontribusi ke risk notable (tuning)

```
index=risk earliest=-30d
| stats count dc(risk_object) AS entities avg(risk_score) AS avg_score BY source
| sort - count
```

Bandingkan dengan finding group 30 hari. Rule dengan volume besar tetapi tidak pernah berada di finding group yang ber-disposition TP adalah kandidat penurunan skor atau perbaikan.

### 4.5 Lab tanpa ES: RBA mini

Langkah 1, tiga "risk rule" lab menulis ke index `lab_risk` (contoh satu rule):

```
index=sysmon EventCode=1 Image="*\\powershell.exe" CommandLine="*-enc*"
| eval risk_object=host, risk_object_type="system", risk_score=20,
       risk_message="Encoded PowerShell on ".host, source="lab_ps_encoded", tactic="Execution"
| table _time risk_object risk_object_type risk_score risk_message source tactic CommandLine
| collect index=lab_risk
```

- `collect` menulis hasil ke index lain, cek izin, index, dan efek `collect` pada lisensi di versi-mu.

Langkah 2, "risk incident rule" terjadwal:

```
index=lab_risk earliest=-24h
| stats sum(risk_score) AS total dc(source) AS sources dc(tactic) AS tactics values(risk_message) AS msgs BY risk_object
| where total>=50 AND sources>=2
```

### 4.6 Langkah di ES (generik)

1. Configure > Content management, pilih detection, lalu atur bagian risiko: entity field, entity type, skor, threat object, pesan [S1], cek nama bagian di editor 8.7.
2. Risk Factor Editor untuk faktor kontekstual [S1], cek menu.
3. Aktifkan/sesuaikan finding-based detection default (ambang 24 jam, multi-taktik) [S1].
4. Pantau Analytics > Dashboards > Risk analysis [S1].

## 5. Lab praktik

1. Bangun RBA mini (bagian 4.5) dengan tiga risk rule lab:
   - PowerShell terenkode (Execution);
   - schtasks dari script host (Persistence, Day 30);
   - `whoami`/`net user` beruntun (Discovery).
   
   Beri skor 10-30 dan tulis ke `lab_risk`.
2. Di VM Windows lab (snapshot), jalankan rangkaian jinak: `whoami /all`, `net user`, PowerShell terenkode `Get-Date`, lalu buat scheduled task uji (hapus setelahnya).
3. Jalankan incident rule bagian 4.5 langkah 2. Hasil yang diharapkan: host lab muncul dengan minimal 2 sumber dan 2 taktik.
4. Tambah noise: jalankan PowerShell terenkode 20 kali. Bandingkan hasil versi tanpa deduplikasi vs versi bagian 4.3. Amati efek score stacking.
5. **Dengan ES:** lakukan hal sama dengan detection ESCU yang setara, lalu buka Risk analysis dan finding group di analyst queue.

**Hasil yang sebaiknya tersimpan:**
- Tiga risk rule menulis event risiko.
- Incident rule menghasilkan "risk notable" untuk host lab.
- Bukti stacking (tanpa dedup) vs teratasi (dengan dedup).
- Penjelasan entity vs threat object pada contohmu.

**Variasi tantangan:** tambahkan "risk factor" lab: lookup `lab_assets.csv` (Day 26) dengan `priority=critical`, lalu kalikan skor 1,5 sebelum dijumlahkan. Bandingkan urutan entity sebelum dan sesudah.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Perbaikan |
|---|---|---|
| Risk notable terlalu banyak | Ambang rendah; stacking dari satu rule | Dedup per source/threat object; syarat keragaman [S3] |
| Tidak pernah ada risk notable | Ambang tinggi; skor terlalu kecil; annotation taktik kosong | Kalibrasi dari data 30 hari; isi annotation |
| Entity terpecah (alice vs LAB\alice) | Identitas tidak ternormalisasi | A&I konvensi identitas (Day 26) |
| Skor tidak sesuai harapan | Risk factor memodifikasi diam-diam | Tinjau Risk Factor Editor [S1] |
| Rule tidak muncul di risk index | Pengaturan risiko di detection belum diisi | Isi entity/score di detection editor |

## 7. Kesalahan umum dan jebakan

- Menjadikan setiap rule RBA sebagai notable juga. Itu menghapus manfaat RBA.
- Menyamakan threat object dengan entity (bagian 3.1).
- Hanya memakai ambang skor. Rentan stacking [S3].
- Annotation ATT&CK kosong, sehingga incident rule multi-taktik tidak bisa bekerja.
- Menyamakan RBA risk dengan risk management organisasi (bagian 3.5).
- `[komunitas]` Komunitas RBA (GitHub, Slack, office hours) aktif dan banyak dipakai praktisi [S2][S3]. Search komunitas perlu diuji di lab sebelum dipakai di produksi.

## 8. Catatan terkini

- ES 8.x memakai istilah intermediate finding, finding-based detection, finding group, dan entity untuk konsep RBA lama (risk event, risk incident rule, risk notable, risk object) [S1][Day 45].
- ES 8.7 mendokumentasikan risk badge berwarna di analyst queue dan Ad-Hoc Risk Entry di Risk analysis [S1].
- Panduan RBA Splunk diperbarui Agustus 2024 (pertama dirilis 2022) dengan langkah kematangan paralel [S2].
- Sebagian tulisan menyamakan threat object dengan teknik ATT&CK. Itu keliru menurut glosarium ES 8: threat object adalah observable, sedangkan teknik ATT&CK masuk lewat annotation [S5].

## 9. Cheat sheet

```
RBA = sinyal lemah -> skor per ENTITY -> alert hanya saat akumulasi/pola kuat (volume turun, fidelitas naik)
RISK RULE (event-based detection + risk settings): entity field | entity type (system|user) | score | threat object | message | annotation
INTERMEDIATE FINDING (risk event) -> index=risk  [field klasik: risk_object, risk_object_type, risk_score, risk_message, threat_object, source]
RISK FACTOR (Risk Factor Editor): pengali kontekstual (user_category, prioritas aset)
FINDING-BASED DETECTION (risk incident rule): default skor > ambang/24 jam ; multi taktik ATT&CK
FINDING GROUP (risk notable) -> analyst queue
DASHBOARD Analytics > Dashboards > Risk analysis (timeline, Ad-Hoc Risk Entry) ; badge 0-25/25-50/50-75/75+
TUNING   dedup (entity, source, threat object) -> sum ; syarat keragaman sumber/taktik ; risk factor ; allowlist sempit
ENTITY (yang diskor) vs THREAT OBJECT/observable (artefak: hash, domain, IP eksternal)
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | ES 8.7: Risk scoring in Splunk Enterprise Security (risk-based alerting) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/risk-based-alerting | primer | diakses 2026-10-07 | Tinggi |
| S2 | Splunk blog: The New & Improved Splunk Guide to Risk-Based Alerting | https://www.splunk.com/en_us/blog/security/the-new-improved-splunk-guide-to-risk-based-alerting.html | primer (vendor) | 2024-08-29; diakses 2026-10-07 | Tinggi untuk konsep dan lima building block |
| S3 | GitHub splunk/rba (komunitas RBA) | https://github.com/splunk/rba | komunitas (repo di org Splunk) | diakses 2026-10-07 | Sedang-tinggi |
| S4 | splunk.github.io/rba: Splunk RBA community site | https://splunk.github.io/rba/ | komunitas | diakses 2026-10-07 | Sedang |
| S5 | ES 8.7 Glossary (entity, observable, intermediate finding; lihat Day 45) | https://help.splunk.com/en/splunk-enterprise-security-8/release-notes-and-resources/8.7/where-to-find-help/glossary | primer | diakses 2026-10-07 | Tinggi |
| S6 | ES 8.7 Executive summary dashboard (panel risk; lihat Day 32) | https://help.splunk.com/en/splunk-enterprise-security-8/user-guide/8.7/analytics/executive-summary-dashboard | primer | diakses 2026-10-07 | Tinggi |
| S7 | Splunk Community: Risk-Based Alerting FAQs | https://community.splunk.com/t5/Splunk-Enterprise-Security/Risk-Based-Alerting-FAQs/td-p/668170 | komunitas (dikelola Splunk) | diakses 2026-10-10 | Sedang; angka reduksi adalah klaim vendor |

**Catatan sumber:** angka penurunan volume alert 50-90% adalah klaim vendor [S7], bukan hasil riset independen; cocokkan dengan teks FAQ sebelum mengutipnya. Nama field fisik risk index di ES 8.7 (apakah masih `risk_object` dan `risk_object_type`) perlu dicek di instance. Search komunitas RBA [S3][S4] perlu diuji di lab sebelum dipakai di produksi.
