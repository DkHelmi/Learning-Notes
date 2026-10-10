---
day: 28
title: 'Review paruh pertama: SOC, ancaman, data, dan investigasi'
researched_on: 2026-10-10
versions_checked: Splunk ES 8.7.0 (2 Sep 2026; rilis ES terbaru per 2026-10-07); CIM 6.4; MITRE ATT&CK v19.2; NIST CSF 2.0
---

# Day 28: Review paruh pertama (SOC, ancaman, data, investigasi)

Cakupan: mengikat kembali empat kelompok materi yang paling konseptual (organisasi SOC dan framework, ancaman dan threat intel, sumber data dan CIM, investigasi dan RBA) lewat ringkasan, peta konsep, glosarium, dan satu lab gabungan.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan setiap topik di Day 08-23 dalam satu sampai tiga kalimat beserta contohnya.
- menghubungkan konsep antar kelompok materi, dari data, CIM, detection, finding dan risk, investigasi, sampai metrik.
- menerjemahkan istilah ES 7 ke ES 8 dengan cepat.
- menandai titik lemah sendiri untuk rencana perbaikan di Day 29.

## 2. Konteks singkat

Materi di Day 08-23 sebagian besar konseptual, tetapi terhubung erat dengan praktik ES sehari-hari. Review ini dipakai untuk menghubungkan, bukan menghafal ulang. Bila sebuah ringkasan terasa asing, kembali ke Day yang dirujuk.

## 3. Ringkasan per topik

### Organisasi SOC, framework, dan risiko (Day 13-14)

| Topik | Inti | Day |
|---|---|---|
| Organisasi SOC | People + process (threat modeling) + technology. Tier 1 triage, tier 2 investigasi, tier 3 hunting/forensik. Analyst = kejadian, Engineer = sistem/konten, Architect = desain. Model tiered vs tierless | 13 |
| Kontrol, standar, framework | Kontrol (mekanisme), standar (ISO 27001, persyaratan teraudit), framework (NIST CSF 2.0 dengan Govern, CIS v8.1, ATT&CK, Kill Chain). Splunk mengadopsinya lewat annotations ES (ATT&CK, CIS, NIST CSF, Kill Chain + PCI DSS 4.0), ESCU, dan SSE | 14 |
| CIA dan risiko | C/I/A (FIPS 199; dampak low/moderate/high), authenticity, non-repudiation. Risiko = f(likelihood, impact); treatment mitigate/transfer/avoid/accept; inherent vs residual. Bukan sama dengan risk di RBA | 14 |

### Ancaman, threat intel, dan TTP (Day 15-17)

| Topik | Inti | Day |
|---|---|---|
| Jenis serangan dan attack vector | Vector = jalan masuk; type = jenis/tujuan. DBIR 2026: eksploitasi kerentanan menjadi vector awal teratas | 15 |
| Istilah serangan | Supply chain (T1195), ransomware, registry, exfiltration (TA0010), social engineering, DoS vs DDoS, bot/botnet, C2 (TA0011), zero trust (SP 800-207), ATO, BEC, threat actor, APT (SP 800-39), adversary | 15 |
| Tier threat intel | Strategic / operational (langka) / tactical (TTP) / technical (IOC). Model vendor 3-tier memakai makna berbeda, jadi sebutkan isinya | 16 |
| Annotations ES | Label konteks pada detection: managed (ATT&CK, CIS, NIST CSF, Kill Chain, PCI DSS 4.0; ESCU: story/confidence/context/impact) vs unmanaged. Tampil di finding dan risk. Bukan logika deteksi | 16 |
| TTP | Tactic = tujuan, technique = cara, procedure = implementasi (SP 800-150). Pyramid of Pain: TTP paling "sakit" bagi penyerang. ATT&CK v19: 15 taktik; Defense Evasion -> Stealth + Defense Impairment | 15, 17 |

### Pertahanan, sumber data, dan CIM (Day 08-12)

| Topik | Inti | Day |
|---|---|---|
| Pertahanan dan sumber data | Lapisan network/web/email/DNS/endpoint/identity/cloud/data. Alat SIEM/SOAR/UEBA/EDR/XDR/NDR/TIP. Prioritas log ASD/CISA 2024. Sysmon. ATT&CK v18 mengganti data sources dengan Detection Strategies/Analytics | 08 |
| SIEM, CIM, data model, acceleration, Asset and Identity, field CIM | CIM = skema saat search (eventtype -> tag -> field -> nilai). 26 DM di CIM 6.4. Akselerasi = summary tsidx (default off; ES enforce). A&I: Exposure Analytics/CSV/LDAP/cloud -> merge -> `asset_lookup_by_str/cidr`, `identity_lookup_expanded`; korelasi src/dest/dvc, user/src_user (bukan host) | 09, 10, 11 |
| Menilai sumber data dengan SSE dan ES | SSE Data Inventory (introspeksi, data source category, CIM coverage), Analytics Advisor/ATT&CK (Available, Needs data). ES 8.7 Detection Studio (coverage + health). Sourcetype umum on-prem dan cloud | 12 |

### Investigasi, penanganan event, detection, dan risk (Day 18-23)

| Topik | Inti | Day |
|---|---|---|
| Continuous monitoring dan lima tahap investigasi | Koleksi -> analisis -> pelaporan -> respons. Review events, Assessment, Determine risk, Mitigate, Re-assess (Lantern) | 18 |
| Metrik | MTTD, MTTA&A, MTTI, MTTR, MTRS, dwell time (T0->T1), FPR/FNR. Gunakan median/p90 | 19 |
| Disposition | 7 bawaan ES 8: Undetermined, TP-Suspicious Activity, BP-Suspicious But Expected, FP-Incorrect Analytic Logic, FP-Inaccurate Data, Other, Testing | 19 |
| Istilah ES | SPL; notable -> finding; risk notable -> finding group; AR action; risk object -> entity; contributing events -> intermediate finding | 20 |
| Dashboard ES | Security posture, Executive summary, SOC operations, Risk analysis, domain (Access/Endpoint/Network/A&I/Threat intel/Web intel), Audit, Predictive analytics. Antrean di Mission Control | 21 |
| RBA dan detection | Risk rule -> intermediate finding (entity, score, threat object, message) -> risk factor -> finding-based detection (ambang 24 jam, multi-taktik) -> finding group. Detection editor: output, trigger, throttling, jadwal real-time vs continuous, jendela berjeda | 22, 23 |

## 3b. Peta konsep

```
           FRAMEWORK & RISIKO (Day 13-14)        ANCAMAN (Day 15-17)
   CSF2.0/CIS/ISO/ATT&CK/KillChain        vector/type, istilah, TTP (ATT&CK v19)
   CIA, risk treatment                     threat intel tiers  -----> threat lists (ES)
            |                                       |
            v                                       v
   SOC (people/process/tech, analyst/engineer/architect) -- annotations --+
            |                                                             |
            v                                                             |
   DATA (Day 08-12): sumber log -> TA -> CIM (tag, field, nilai) -> data model -> akselerasi
            |                         |                                   |
            |                    A&I (prioritas, kategori)                |
            v                         v                                   v
   DETECTION (Day 23) ---> finding (analyst queue) <---- finding group <-- RBA (Day 22)
            |                    |                                ^
            +--> intermediate finding (risk index, entity, score, threat object, annotations)
                                 |
   INVESTIGASI (Day 18): Review -> Assessment -> Determine risk -> Mitigate (AR/SOAR) -> Re-assess
                                 |
   METRIK & DISPOSISI (Day 19) -> dashboard (Day 21) -> tuning detection/data (kembali ke data dan detection)
```

## 3c. Glosarium ES 7 vs ES 8

| ES 7 | ES 8 |
|---|---|
| Correlation search | Detection (event-based) |
| Risk incident rule | Finding-based detection |
| Notable event | Finding |
| Risk notable | Finding (glosarium); dalam praktik finding group dari finding-based detection |
| Risk event / contributing events | Intermediate finding |
| Incident Review | Analyst queue (Mission Control) |
| Risk object | Entity |
| Threat object / indicator | Observable |
| Comment | Note |
| Intelligence workflow | Threat list |
| Correlation search editor | Detection editor |
| Investigation workbench | Investigation di Mission Control |
| Risk score pada risk object | Risk score pada entity |

Istilah lintas versi yang tetap sama dan sering muncul di diskusi:

| Istilah | Arti singkat | Day |
|---|---|---|
| Urgency | Prioritas finding dari severity detection dan prioritas aset | 10, 21 |
| Disposition | Hasil penilaian finding (TP, BP, FP-Logic, FP-Data, dll.) | 19 |
| Status | Posisi kasus di alur kerja (New, In Progress, Closed) | 19 |
| Throttling | Penekan finding duplikat per kombinasi field dalam jendela waktu | 23 |
| Risk factor | Pengali skor risiko berdasarkan atribut entity | 22 |
| Response plan | Template phase dan task untuk investigation | 18 |
| Data model acceleration | Summary tsidx yang membuat `tstats summariesonly=true` cepat | 10 |
| Annotation | Label framework (ATT&CK, CIS, NIST, Kill Chain) pada detection; bukan logika | 16 |

## 3d. Latihan skenario dengan pembahasan

Coba jawab setiap skenario sebelum membaca pembahasannya. Semua skenario fiktif.

**Skenario 1: panel urgency yang tidak informatif.** Dashboard Security posture menunjukkan hampir semua finding berurgency medium, termasuk finding malware di server database utama. Apa penyebab paling mungkin, dan di mana memperbaikinya?

Pembahasan: urgency dihitung dari severity detection dan prioritas aset (Day 10, Day 21). Bila semua jatuh di medium, kemungkinan besar lookup aset kosong atau tidak cocok dengan nilai `dest` di finding, sehingga prioritas aset dianggap unknown. Perbaikannya di Asset and Identity: pastikan server database terdaftar dengan `priority=critical` dan kolom `ip`/`dns`/`nt_host` cocok dengan nilai yang muncul di data. Mengubah severity detection bukan perbaikan, karena masalahnya di konteks, bukan di detection.

**Skenario 2: detection yang tidak pernah menghasilkan finding group.** Tiga risk rule baru aktif seminggu dan menulis event risiko, tetapi finding-based detection multi-taktik tidak pernah terpicu, padahal ada host lab yang jelas menjalankan discovery dan persistence. Apa yang dicek?

Pembahasan: urutan cek dari Day 22 bagian 6. Pertama, apakah annotation ATT&CK terisi pada ketiga rule; aturan multi-taktik menghitung `dc` taktik dari annotation, jadi annotation kosong berarti nol taktik. Kedua, apakah ketiga rule memberi skor ke entity yang sama (nama host bisa tertulis `WIN-LAB01` di satu rule dan `win-lab01.lab.local` di rule lain). Ketiga, apakah ambang dan jendela waktunya cocok dengan rentang aktivitas lab.

**Skenario 3: metrik yang menyesatkan.** Manajer melaporkan MTTR turun dari 9 jam ke 2 jam dalam satu kuartal, tetapi jumlah insiden yang dibuka ulang naik tiga kali lipat. Bagaimana kamu menjelaskannya?

Pembahasan: MTTR yang turun bersamaan dengan reopen rate yang naik adalah tanda penutupan prematur (Day 19). Metrik kecepatan harus dibaca bersama metrik kualitas. Usulan konkret: laporkan median dan p90 TTR, reopen rate, dan proporsi disposition Undetermined. Bila Undetermined tinggi, wajibkan disposition sebelum menutup finding.

**Skenario 4: memilih sumber data untuk pertanyaan.** Tim ingin tahu apakah ada akun yang login ke lebih dari lima server berbeda dalam satu jam. Data model mana yang dipakai, field apa, dan apa jebakannya?

Pembahasan: data model Authentication (Day 09, Day 11), dengan `user`, `dest`, `action`, dan `_time`; hitung `dc(dest)` per `user` dalam `span=1h`. Jebakannya: log Windows klasik bisa memuat dua akun dalam satu event (subject dan target), sehingga `user` bisa multivalue atau berisi akun mesin (`HOST$`). Filter akun mesin dan pastikan TA memetakan akun target ke `user`.

**Skenario 5: istilah dalam laporan.** Draf laporan berbunyi "Risk notable dibuat dari 12 notable kecil pada risk object alice." Tulis ulang dengan istilah ES 8 yang benar.

Pembahasan: "Finding group dibuat oleh finding-based detection dari 12 intermediate finding pada entity `alice`." Dua koreksi penting: event pendukung bukan notable (mereka tidak masuk antrean), dan risk object di ES 8 disebut entity. Untuk pembaca yang terbiasa ES 7, tambahkan padanan lama dalam kurung.

## 4-6. Lab gabungan dan troubleshooting

Skenario lab: "Akun lab dikompromikan, lalu bergerak ke server" (di VM lab terisolasi, akun uji).

1. **Data (Day 09-12):** pastikan Authentication dan Endpoint.Processes terisi untuk VM Windows (Day 09-11). Catat celah di Data Inventory SSE (Day 12).
2. **Konteks aset dan identitas (Day 10):** daftarkan VM sebagai aset (prioritas: workstation medium, "server" lab high) dan akun uji sebagai identitas (Day 10).
3. **Ancaman (Day 15-17):** rencanakan rangkaian jinak yang mewakili taktik ATT&CK v19:
   - Credential Access: brute force lalu sukses;
   - Discovery: `whoami`, `net user`;
   - Persistence: scheduled task;
   - Lateral Movement: login RDP/SMB ke VM "server" dengan akun uji.
4. **Detection (Day 22-23):**
   - detection brute force (Day 23) dengan output finding + intermediate finding;
   - dua detection lain (discovery, schtasks) dengan output intermediate finding saja;
   - beri annotation ATT&CK (Day 16).
5. **RBA (Day 22):** pastikan finding group/risk notable muncul untuk akun uji (atau versi lab Day 22 bagian 4.5).
6. **Investigasi (Day 18):** jalani lima tahap. Terapkan response plan "Account Compromise" (ES) atau checklist di TheHive.
7. **Respons (Day 26-27):** jalankan satu AR ad hoc (Nslookup/Ping) dan satu playbook (Shuffle/SOAR) dengan approval.
8. **Disposition dan metrik (Day 19):** tutup dengan disposition yang tepat. Catat T0, T1, T4. Hitung dwell time dan TTR.
9. **Dashboard (Day 21):** temukan kasus ini di Security posture/Risk analysis, atau di dashboard lab.

**Hasil yang diharapkan per langkah** (lab yang berjalan baik):

| Langkah | Bukti yang harus terlihat |
|---|---|
| 1 Data | `tstats count` dari Authentication dan Endpoint.Processes untuk host lab tidak nol |
| 2 Aset dan identitas | Finding dari VM "server" berurgency lebih tinggi daripada finding serupa dari workstation |
| 4 Detection | Satu finding brute force di antrean; event risiko dari discovery dan schtasks di risk index, tanpa finding sendiri |
| 5 RBA | Satu finding group untuk akun uji atau host lab, berisi minimal tiga event pendukung dari dua taktik |
| 6 Investigasi | Satu investigation dengan catatan per tahap dan response plan yang task-nya terisi |
| 8 Metrik | T0 (aksi pertama di lab), T1 (finding pertama), T4 (penutupan) tercatat, dengan disposition True Positive - Suspicious Activity (atau Testing bila itu kebijakan lab-mu) |

**Hasil yang sebaiknya tersimpan:**

- Tabel bukti di atas, diisi dengan angka dan screenshot catatan sendiri.
- Satu paragraf: langkah mana yang paling lama dan kenapa.
- Daftar topik yang terasa goyah selama lab, untuk tabel rencana di Day 29.

**Troubleshooting ringkas:** bila langkah 5 tidak menghasilkan finding group, cek berurutan: apakah data model terisi, apakah field entity terisi, apakah annotation taktik ada, dan apakah ambang terlalu tinggi (Day 22 bagian 6).

## 7. Kesalahan umum dan jebakan (rangkuman Day 08-23)

- Menyamakan risk score RBA dengan risk management organisasi (Day 14 vs Day 22).
- Memakai daftar taktik ATT&CK lama tanpa menyebut versinya (Day 17).
- Memakai label tier threat intel tanpa menjelaskan isinya (Day 16).
- Menganggap annotation mengubah logika deteksi (Day 16).
- Memilih data model berdasarkan nama field, bukan jenis aktivitasnya (Day 09).
- Mengharapkan korelasi Asset and Identity jalan lewat field `host` di ES 8 (Day 10).
- Mencampur Benign Positive dengan False Positive (Day 19).
- Memakai `count(eval())` di `tstats` (Day 01, Day 23).
- Jendela waktu detection tanpa jeda, sehingga event yang datang terlambat terlewat (Day 23).

## 8. Catatan terkini

- ES 8.7.0 (2 Sep 2026) masih rilis ES terbaru per 2026-10-07 [S1]. Cek halaman release notes bila membaca catatan ini jauh setelah tanggal itu.
- **ATT&CK v19 (Apr 2026)**: Stealth + Defense Impairment; v19.2 Agile (Agu 2026) [S2].
- CIM 6.4 (Feb 2026); SSE 3.8.x; Detection Studio di ES 8.x [S3].
- NIST CSF 2.0 (Govern) dan CIS v8.1 [S4].

## 9. Cheat sheet

```
SOC    T1/T2/T3 ; Analyst=kejadian Engineer=sistem/konten Architect=desain ; People+Process+Tech
FRAME CSF2.0 G-I-P-D-R-R ; CIS v8.1 ; ISO 27001 (standar) ; ATT&CK & Kill Chain (perilaku) ; CIA + risk treatment
ANCAM vector vs type ; 15 istilah ; tiers S/O/T/T ; annotations (konteks, managed/unmanaged) ; TTP + Pyramid ; v19 15 taktik
DATA  sumber data -> TA -> CIM (tag/field/nilai) -> DM (26; akselerasi off default; ES enforce) ; A&I ; field poros src/dest/user/action
      SSE Data Inventory + ATT&CK dashboard ; ES Detection Studio
INVES 5 tahap: Review > Assessment > Determine risk > Mitigate > Re-assess ; MTTD/MTTR/dwell ; 7 disposition
      finding / finding group / intermediate finding / entity / AR ; dashboard ; RBA ; detection editor + jadwal
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Release notes ES 8.7 | https://help.splunk.com/en/splunk-enterprise-security-8/release-notes-and-resources/8.7 | primer | 2026-09-02; dilihat 2026-10-07 | Tinggi |
| S2 | MITRE ATT&CK: Enterprise tactics v19 (Day 15) | https://attack.mitre.org/tactics/enterprise/ | primer | diakses 2026-10-07 | Tinggi |
| S3 | ES 8.7 Detection Studio (Day 12) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/detections/identify-optimal-detections-for-your-security-environment-using-detection-studio-in-splunk-enterprise-security/monitor-detection-coverage-and-health-using-detection-studio-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi |
| S4 | CIS Controls v8.1; NIST CSF 2.0 (Day 14) | https://www.cisecurity.org/insights/white-papers/cis-critical-security-controls-v8-1 | primer | dilihat 2026-10-07 | Tinggi |
| S5 | ES 8.7 Glossary (Day 06) | https://help.splunk.com/en/splunk-enterprise-security-8/release-notes-and-resources/8.7/where-to-find-help/glossary | primer | diakses 2026-10-07 | Tinggi |

Ringkasan di Day ini merangkum Day 08-23. Sumber untuk setiap klaim ada di tabel Sumber Day asalnya; tabel di atas hanya memuat sumber untuk klaim versi dan istilah yang ditulis ulang di sini.

**Catatan sumber:** Day review ini tidak menambah klaim teknis baru selain status versi ES; hal yang masih perlu dicek di Day 08-23 (terutama nama field finding dan risk di ES 8.7) tetap berlaku. Skenario di bagian 3d dan angkanya fiktif.
