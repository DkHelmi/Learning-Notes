---
day: 42
title: SOAR playbook dan cara memicunya dari ES
researched_on: 2026-10-10
versions_checked: Splunk ES 8.7 (Configure automation rules to run playbooks based on findings); ES 8.3 user guide (Automate your investigation response with actions and playbooks); Splunk SOAR (On-premises) 8.6.0 (4 Agu 2026) dan 8.4.0 (18 Feb 2026); SOAR Cloud; Splunk Enterprise 10.6
---

# Day 42: SOAR playbook dan cara memicunya dari ES

Cakupan: menjelaskan penggunaan SOAR playbook dan menyebut cara dasar memicunya dari Enterprise Security.

## Ide inti

Adaptive response di Day 41 menjalankan satu aksi per eksekusi. Begitu respons butuh beberapa langkah, beberapa alat, percabangan, dan persetujuan manusia di tengah jalan, satu aksi tidak lagi cukup. SOAR (Security Orchestration, Automation and Response) mengotomasi alur kerja yang utuh, bukan satu aksi. Contoh alur untuk satu laporan phishing:

1. finding phishing masuk;
2. ekstrak URL dan lampiran;
3. cek reputasi;
4. cari email serupa di kotak masuk lain;
5. minta persetujuan analyst;
6. hapus email dan blokir domain;
7. perbarui kasus.

SANS 2026 SOC Survey menunjukkan adopsi AI/otomasi tinggi tetapi integrasinya ke workflow yang terdefinisi masih rendah (Day 29). Playbook adalah cara membuat otomasi itu terdefinisi, teruji, dan teraudit. Gagasan yang menopang seluruh Day ini ada di urutan langkahnya: enrichment dan scoping tidak mengubah apa pun sehingga boleh berjalan untuk setiap kasus, sedangkan langkah yang mengubah sistem ditaruh di balik persetujuan dan setiap langkah tercatat di kasus. Sisanya adalah soal cara memicu playbook itu dari ES dan cara mengujinya sebelum dipercaya.

Padanannya di NOC adalah runbook yang dijalankan mesin: urutan langkah yang biasanya dikerjakan teknisi satu per satu, kini dieksekusi otomatis lengkap dengan cabang "bila begini, lakukan itu". Batas analoginya, playbook menjalankan langkah, tetapi keputusan disposisi tetap di analyst. Langkah persetujuan (prompt) di tengah playbook ada justru untuk menjaga batas itu, dan playbook yang menutup kasus sendiri hanya sah untuk cabang yang keputusannya sudah terbukti seragam dari data.

Di PT Jaringan Anak Bangsa (PT JAB, ISP menengah fiktif), ES baru dipasang di search head terpisah sementara sebagian alert L1 masih berjalan dari app Search & Reporting, jadi Day ini membahas dua jalur: memicu playbook dari ES 8, dan analog lab yang dipicu webhook dari alert biasa.

**Kapan relevan:** saat respons butuh beberapa langkah dan beberapa alat, ada logika percabangan, atau ada tindakan berisiko yang harus menunggu persetujuan manusia; saat alur yang sama berulang sering (phishing, akun kompromi, malware alert); saat memilih cara memicu playbook dari ES; saat menguji playbook sebelum dipakai; dan saat SOAR akan di-upgrade sementara playbook lama masih dipakai.
**Kapan bukan jawaban:** untuk aksi tunggal yang sederhana, adaptive response sudah cukup (Day 41 bagian 1.4). Playbook tidak memperbaiki detection yang false positive-nya tinggi, karena ia hanya menjalankan langkah yang sama lebih cepat atas pemicu yang keliru. Playbook juga tidak menggantikan keputusan analyst untuk tindakan berdampak tinggi, dan tanpa pairing ES dengan SOAR tidak ada automation rules maupun tab Automation di Mission Control.

## 1. Konsep inti

### 1.1 Konsep SOAR (umum)

Tabel berikut memuat kosakata dasar SOAR; cari terutama beda app, action, dan asset, karena ketiganya sering tertukar saat membaca hasil playbook.

| Konsep | Arti |
|---|---|
| Playbook | Alur otomatis (atau semi-otomatis) berisi langkah, logika, dan percabangan. Di Splunk SOAR dibangun dengan Visual Playbook Editor atau kode Python |
| App | Konektor ke produk lain (EDR, firewall, email, threat intel) |
| Action | Operasi yang disediakan app (mis. "block ip", "get file reputation") |
| Asset | Konfigurasi instans produk (alamat, kredensial) untuk app |
| Container/event + artifact | Wadah kasus dan observable-nya (IP, hash, URL), cek istilah di SOAR 8.x |
| Prompt / approval | Langkah yang meminta keputusan manusia (human-in-the-loop), cek nama fitur |

Versi terkini: Splunk SOAR (On-premises) 8.6.0 dirilis 4 Agu 2026. Release notes-nya menyebut 8.6.0 sebagai rilis terakhir yang mendukung Python 3.9; rilis yang dijadwalkan September 2026 tidak lagi mendukungnya, dan otomasi yang masih dipakai harus dimigrasi ke Python 3.13 [S4]. Rilis 8.4.0 (18 Feb 2026) sudah mengumumkan arah yang sama dan memperkenalkan Action Builder (beta) di Visual Playbook Editor untuk membuat endpoint baru bagi app yang ada tanpa menulis kode [S6]. Dampaknya bagi analyst: playbook lama yang belum dimigrasi bisa berhenti berjalan setelah upgrade, tanpa ada perubahan di sisi ES.

### 1.2 Kapan memakai playbook (vs adaptive response)

Gunakan playbook bila:
- respons butuh beberapa langkah dan beberapa alat;
- ada logika/percabangan (bila reputasi buruk jalankan A, bila tidak jalankan B);
- butuh persetujuan manusia sebelum tindakan berisiko;
- alur yang sama berulang sering (phishing, akun kompromi, malware alert);
- butuh dokumentasi otomatis di kasus.

Gunakan adaptive response (Day 41) untuk aksi tunggal yang sederhana.

### 1.3 Cara memicu playbook dari ES 8

Prasyarat: ES dipasangkan (paired) dengan Splunk SOAR oleh admin [S1][S2].

1. Automation rules (otomatis berbasis finding) [S1]:
   - Jalur menu: Configure > Splunk SOAR > Automation rules. Halaman ini hanya terlihat bila ES dan SOAR sudah dipasangkan. Butuh hak SOAR untuk membuat/mengedit.
   - **Trigger:** finding yang dibuat oleh detection tertentu (berstatus on, menghasilkan finding di analyst queue) dan/atau ingestion dari app tertentu.
   - **Isi rule:** nama unik (tidak bisa diubah), satu/lebih detection, sumber ingestion opsional, satu/lebih playbook (hanya tipe ES), aktif/nonaktif.
   - **Batasan:** satu detection hanya bisa terkait satu automation rule. Bila beberapa playbook terpicu bersamaan, eksekusinya FIFO.
2. Manual dari Mission Control [S2]: pilih investigation di analyst queue, buka tab Automation, klik Run playbook, pilih playbook, lalu Run. Ada juga Run action untuk satu aksi app dengan parameter. Hasil tampil di riwayat otomasi (tabel/peta/JSON), dan Open Playbook membuka detail di SOAR.
3. Response plan task [S2]: admin dapat mengonfigurasi aksi/playbook agar berjalan otomatis ketika task tertentu di response plan selesai (Day 34).
4. **Adaptive response ke SOAR**: disebut sebagai salah satu cara memicu [S1]. Di ES 7.x dikenal sebagai aksi "Send to SOAR/Phantom", cek nama dan ketersediaannya di ES 8.7.

### 1.4 Merancang playbook yang aman

Pola umum (pseudocode, bukan kode):

```
TRIGGER: finding "Lab - Auth - Brute Force Followed By Success" (automation rule)
1. ENRICH   : reputasi src (threat intel) | lokasi geo | konteks user (A&I: category, manager)
2. DECIDE   : jika src internal & user di allowlist -> tambahkan catatan, berhenti
              jika user category=executive atau dest_priority=critical -> PROMPT analyst
3. CONTAIN  : (setelah persetujuan atau aturan aman) paksa reset sesi/MFA, nonaktifkan akun sementara
4. NOTIFY   : kirim ringkasan ke kanal SOC + manajer user
5. DOCUMENT : tulis semua hasil ke investigation (note) dan set status
6. CHECK    : cek login berikutnya dari src (re-query Splunk)
```

Prinsip: enrichment dulu, tindakan belakangan, persetujuan untuk tindakan berdampak tinggi, setiap langkah tercatat, dan mudah di-rollback. Prinsip ini sama dengan guardrail adaptive response (Day 41).

**Tanpa ES:** automation rules, otomasi di Mission Control, response plan, dan pairing adalah fitur ES yang dipasangkan dengan SOAR. Splunk Enterprise biasa yang dipasangkan dengan SOAR memakai alert action atau app untuk mengirim event ke SOAR (Splunk App for SOAR atau varian Export-nya, nama yang tepat perlu dicek), tanpa fitur Mission Control. Untuk lab-mu, Shuffle (SOAR open-source) dan TheHive (case management) menjadi analog yang baik untuk melatih konsep yang sama; langkahnya ada di bagian 2.4.

## 2. Contoh SPL dan langkah di ES

> Keluaran berlabel ilustrasi.

### 2.1 Memilih kandidat otomasi: finding yang sering dan seragam

ES 7 pola:

```
`notable` earliest=-30d
| eval is_closed=if(in(status_label,"Resolved","Closed"),1,0)
| stats count dc(owner) AS analysts avg(is_closed) AS closed_ratio BY rule_name disposition_label
| where count >= 50
| sort - count
```

- Detection yang sering muncul, ditangani dengan langkah serupa, dan disposisinya konsisten adalah kandidat playbook.
- Field ES 7, cek di ES 8.

### 2.2 Query yang dipakai playbook untuk verifikasi (langkah 6)

```
| tstats summariesonly=false count from datamodel=Authentication.Authentication
    where Authentication.src="$src$" Authentication.action="success" earliest=-1h
    by Authentication.user Authentication.dest
```

- `$src$` adalah token yang diisi playbook (mis. lewat aksi "run query" app Splunk di SOAR), cek nama aksi di app Splunk untuk SOAR.

### 2.3 Langkah di ES (generik)

1. Admin memasangkan ES dengan SOAR, cek langkah pairing di dokumentasi ES 8.7.
2. Configure > Splunk SOAR > Automation rules, lalu buat rule dengan detection "Lab - Auth - Brute Force Followed By Success", playbook "account_compromise_lab" (tipe ES), dan status aktif [S1].
3. Picu detection (Day 36). Lihat finding dan hasil playbook di tab Automation investigation [S2].
4. Coba juga Run playbook manual pada investigation lain [S2].

### 2.4 Lab tanpa SOAR Splunk: Shuffle + TheHive

1. Alert Splunk (Day 36 bagian 2.5) mengirim webhook ke workflow Shuffle.
2. Workflow Shuffle:
   - parse alert (src, user);
   - enrichment (mis. cek IP di lookup lokal atau layanan reputasi dengan data uji saja, perhatikan ToS layanan);
   - buat case di TheHive dengan observable;
   - user input/approval sebelum langkah tindakan, cek fitur approval di versi Shuffle-mu;
   - tindakan lab yang aman, mis. menonaktifkan akun uji di VM lab via skrip yang kamu kontrol.
3. Catat semua langkah di case (dokumentasi otomatis).

### 2.5 Contoh lengkap: playbook phishing dan cara mengujinya

Skenario fiktif di PT JAB: karyawan melaporkan email mencurigakan lewat tombol report, dan email itu masuk sebagai finding "Reported Phishing Email". Rata-rata tim menerima 30 laporan sehari, dan 80% di antaranya adalah spam biasa atau newsletter. Ini kandidat otomasi yang ideal: sering, seragam, dan sebagian besar keputusannya bisa diambil dari data.

Tabel desain berikut memetakan alur tujuh langkah di Ide inti menjadi delapan langkah playbook; perhatikan di langkah mana keputusan diambil mesin dan di langkah mana manusia.

| Langkah | Aksi | Keputusan atau keluaran |
|---|---|---|
| 1 Parse | Ambil pengirim, subject, URL, hash lampiran dari email yang dilaporkan | Artifact di container |
| 2 Enrich | Reputasi URL dan domain (umur domain, kategori), reputasi hash lampiran dari sumber internal atau yang diizinkan TLP-nya | Skor reputasi per observable |
| 3 Scope | Search Splunk: berapa user lain menerima email dari pengirim atau dengan URL yang sama dalam 24 jam; siapa yang mengklik (log proxy) | Daftar penerima dan pengklik |
| 4 Decide | Bila semua observable bersih dan tidak ada yang mengklik: tutup sebagai Benign Positive dengan catatan otomatis. Bila ada observable buruk: lanjut | Cabang |
| 5 Approve | Prompt ke analyst: hapus email dari semua kotak masuk dan blokir domain? | Persetujuan manusia |
| 6 Contain | Hapus email (purge), blokir domain di proxy, reset sesi untuk user yang mengklik | Tindakan tercatat |
| 7 Document | Tulis ringkasan ke investigation: observable, jumlah penerima, pengklik, tindakan | Catatan kasus |
| 8 Notify | Balas user pelapor dengan hasilnya | Umpan balik ke user |

Kenapa urutan ini aman: enrichment dan scoping tidak mengubah apa pun, jadi boleh berjalan untuk setiap laporan. Langkah yang mengubah sistem (purge, blokir, reset) berada di balik persetujuan, dan baru bisa dibuat otomatis penuh setelah data beberapa bulan menunjukkan keputusan analyst hampir selalu sama.

Cara menguji sebelum dipakai:

1. **Kasus bersih:** email newsletter dari domain lama dengan reputasi baik. Hasil yang diharapkan: berhenti di langkah 4, tertutup sebagai Benign Positive, tidak ada prompt.
2. **Kasus buruk tanpa klik:** domain `.example` buatan yang ditandai buruk di lookup reputasi lab. Hasil yang diharapkan: prompt muncul, penerima terdaftar, tidak ada reset sesi.
3. **Kasus buruk dengan klik:** sama seperti kasus 2, ditambah satu event proxy lab dari user uji. Hasil yang diharapkan: prompt muncul, dan setelah disetujui, sesi user uji direset.
4. **Kasus gagal:** layanan reputasi tidak bisa dihubungi. Hasil yang diharapkan: playbook tidak menganggap "tidak ada jawaban" sebagai "bersih", melainkan menandai kasus untuk ditinjau manual.

Ukuran keberhasilan setelah sebulan: median waktu dari laporan sampai keputusan (sebelumnya misalnya 45 menit, sesudahnya 5 menit untuk kasus bersih), persentase kasus yang ditutup otomatis, dan jumlah kasus di mana analyst menolak rekomendasi playbook. Angka penolakan yang tinggi berarti logika keputusan di langkah 4 perlu diperbaiki, bukan berarti analyst lambat.

## 3. Lab praktik

1. Pilih satu detection lab (Day 36). Tulis desain playbook dengan pola bagian 1.4: trigger, enrichment, keputusan, tindakan, persetujuan, dokumentasi, verifikasi.
2. Implementasikan di Shuffle + TheHive (bagian 2.4), atau di ES + SOAR bila tersedia (bagian 2.3).
3. Uji tiga kasus:
   - (a) src di allowlist: playbook berhenti setelah enrichment;
   - (b) user biasa: tindakan otomatis di akun uji;
   - (c) user "executive" (fiktif): prompt persetujuan.
4. Ukur waktu dari alert sampai case terdokumentasi, sebelum dan sesudah otomasi (Day 34 metrik).
5. Tulis "kartu playbook": tujuan, trigger, langkah, guardrail, rollback, pemilik, versi.

**Hasil yang sebaiknya tersimpan:**
- Desain playbook tertulis.
- Tiga cabang (allowlist, otomatis, approval) teruji.
- Metrik waktu sebelum/sesudah.
- Kartu playbook tersimpan.

**Variasi tantangan:** sebutkan keempat cara memicu playbook dari ES 8 (bagian 1.3). Untuk masing-masing, beri satu skenario di mana cara itu paling tepat.

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Perbaikan |
|---|---|---|
| Halaman Automation rules tidak terlihat | ES belum dipasangkan dengan SOAR | Pairing oleh admin [S1] |
| Tidak bisa membuat rule | Tidak punya hak SOAR | Minta hak [S1] |
| Detection tidak bisa dipilih di rule baru | Detection sudah terkait rule lain (1:1) | Lepaskan dari rule lama [S1] |
| Playbook tidak muncul di daftar | Bukan tipe ES (mis. tipe SOAR/Input) | Gunakan playbook bertipe ES [S1] |
| Playbook gagal setelah upgrade SOAR | Ketidakcocokan Python (3.9 -> 3.13) | Migrasikan playbook, custom function, dan app ke Python 3.13 [S4] |
| Webhook Shuffle tidak menerima | URL/izin jaringan lab | Cek konektivitas dan log Shuffle |

## 5. Kesalahan umum dan jebakan

- Mengotomasi tindakan berdampak tinggi tanpa persetujuan (Day 41).
- Playbook tanpa dokumentasi ke kasus. Akuntabilitas hilang.
- Mengira satu detection bisa memicu beberapa automation rule. Hubungannya 1 detection : 1 rule [S1].
- Mengabaikan pemeliharaan playbook (perubahan API vendor, versi Python SOAR) [S4].
- Mengunggah data sensitif ke layanan reputasi publik dari playbook. Perhatikan TLP (Traffic Light Protocol: label berbagi informasi CLEAR, GREEN, AMBER, AMBER+STRICT, RED) pada indikator yang diterima, dan ketentuan layanan (ToS) penyedia reputasi, karena banyak layanan publik membagikan file yang diunggah ke pelanggan lain.
- `[komunitas]` Shuffle dan TheHive sebagai analog lab didasarkan pada praktik lab sendiri, bukan dokumentasi Splunk. Nama node dan fitur approval di Shuffle bergantung versi.

## 6. Catatan terkini

Bagian ini mencatat perubahan versi ES dan SOAR yang memengaruhi cara playbook dipicu dan dirawat.

- ES 8.x mengintegrasikan otomasi SOAR ke Mission Control (tab Automation, Run playbook/Run action) dan automation rules di Configure > Splunk SOAR [S1][S2].
- SOAR On-prem 8.6.0 (Agu 2026) adalah rilis terakhir dengan Python 3.9; otomasi perlu dimigrasi ke Python 3.13 [S4]. Action Builder (beta) di VPE sejak 8.4.0 [S6].
- Release notes ES 8.6.1/8.7 menyebut agen AI untuk membantu menulis playbook dan "AI SOC Analyst" yang bisa menjalankan tindakan yang diizinkan (Day 45). Batas izin dan jejak auditnya perlu dicek di instance.

## 7. Cheat sheet

```
SOAR      playbook (VPE / Python) | app -> action | asset | container/artifact | prompt (approval)
VS AR     AR = aksi tunggal ; playbook = alur multi-langkah + logika + persetujuan + dokumentasi
PICU DARI ES 8 (butuh pairing ES<->SOAR):
  1 Automation rules  : Configure > Splunk SOAR > Automation rules ; trigger = finding dari detection/ingestion
                        playbook tipe ES ; 1 detection : 1 rule ; FIFO
  2 Manual            : Mission Control > investigation > Automation > Run playbook / Run action
  3 Response plan task: aksi/playbook saat task selesai
  4 Adaptive response ke SOAR (cek nama di 8.7)
DESAIN    enrich -> decide -> (approve) -> contain -> notify -> document -> verify ; rollback ; guardrail A&I
VERSI     SOAR on-prem 8.6.0 (Agu 2026, terakhir dgn Python 3.9) ; migrasi ke Python 3.13 ; Action Builder beta (8.4.0)
LAB       Splunk alert -> webhook -> Shuffle -> TheHive (+ approval)
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Rekanmu ingin playbook enrichment dan playbook containment untuk detection "Lab - Auth - Brute Force Followed By Success" dikelola terpisah, jadi ia berencana membuat dua automation rule untuk detection yang sama. Kenapa rencana itu tidak akan jalan, dan apa yang bisa ia lakukan?

<details><summary>Jawaban</summary>

Satu detection hanya bisa terkait satu automation rule, sehingga detection yang sudah dipakai rule pertama tidak bisa dipilih lagi di rule kedua. Yang bisa dilakukan adalah memasukkan kedua playbook ke rule yang sama, karena satu rule boleh memuat satu atau lebih playbook, dengan catatan keduanya bertipe ES dan eksekusinya FIFO bila terpicu bersamaan. Bila detection itu tidak muncul di daftar saat membuat rule, periksa dulu apakah ia sudah terkait rule lain dan lepaskan dari rule lama. Lihat bagian 1.3 dan 4.

</details>

**2. Skenario keputusan.** Saat menguji playbook phishing, layanan reputasi URL tidak bisa dihubungi, dan tidak ada satu pun penerima yang mengklik. Apa yang seharusnya dilakukan playbook?

- A. Menutup kasus sebagai Benign Positive, karena tidak ada reputasi buruk yang dilaporkan dan tidak ada klik.
- B. Menandai kasus untuk ditinjau manual.
- C. Langsung menjalankan purge dan blokir domain tanpa prompt, supaya aman.

<details><summary>Jawaban</summary>

B. "Tidak ada jawaban" dari layanan reputasi bukan "bersih", jadi cabang otomatis yang menutup kasus tidak boleh terpicu oleh kegagalan enrichment; kasus seperti ini justru salah satu yang wajib diuji sebelum playbook dipakai. A memperlakukan kegagalan sebagai bukti, sehingga email berbahaya bisa tertutup otomatis hanya karena layanan sedang down. C melompati langkah persetujuan, padahal purge, blokir, dan reset sesi adalah langkah yang mengubah sistem dan sengaja ditaruh di balik prompt. Lihat bagian 2.5.

</details>

**3. Pertanyaan jebakan.** Setelah SOAR on-prem di-upgrade, beberapa playbook lama berhenti berjalan. Rekanmu menghabiskan setengah hari memeriksa konfigurasi ES karena "pemicunya ada di ES". Kenapa itu tempat yang salah untuk mulai, dan apa yang dicek lebih dulu?

<details><summary>Jawaban</summary>

Kegagalan setelah upgrade SOAR bisa terjadi tanpa perubahan apa pun di sisi ES. Release notes SOAR on-prem 8.6.0 menyebut rilis itu sebagai yang terakhir mendukung Python 3.9, dan rilis yang dijadwalkan September 2026 tidak lagi mendukungnya, jadi playbook, custom function, dan app yang belum dimigrasi ke Python 3.13 adalah tersangka pertama. Pemeliharaan seperti ini, ditambah perubahan API vendor, adalah bagian dari merawat playbook, bukan kejadian luar biasa. Lihat bagian 1.1, 4, dan 5.

</details>

**4. Jelaskan ulang.** Jelaskan ke SOC lead, dalam tiga kalimat, kenapa langkah purge dan blokir di playbook phishing masih menunggu persetujuan analyst, dan kapan langkah itu boleh dibuat otomatis penuh.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh jawaban: "Enrichment dan scoping tidak mengubah apa pun, jadi kami jalankan untuk setiap laporan, sedangkan purge, blokir domain, dan reset sesi mengubah sistem sehingga kami taruh di balik prompt ke analyst. Langkah itu baru dibuat otomatis penuh setelah data beberapa bulan menunjukkan keputusan analyst hampir selalu sama dengan rekomendasi playbook. Yang kami pantau untuk itu adalah median waktu dari laporan sampai keputusan, persentase kasus yang ditutup otomatis, dan jumlah kasus di mana analyst menolak rekomendasi playbook, karena penolakan yang tinggi berarti logika keputusannya yang perlu diperbaiki."

Kesalahan yang sering muncul: menganggap persetujuan sebagai tanda playbook belum jadi, padahal itu bagian dari desain; membaca angka penolakan yang tinggi sebagai analyst yang lambat, bukan sebagai logika keputusan di langkah 4 yang salah; dan lupa bahwa setiap langkah harus tercatat di kasus supaya keputusan otomatis bisa dipertanggungjawabkan. Lihat bagian 1.4 dan 2.5.

</details>

**5. Interview question (English).** "Walk me through how you would automate the handling of user-reported phishing emails."

<details><summary>Sample answer</summary>

"I would start by checking that it is a good candidate: phishing reports are frequent, they are handled with similar steps, and most of them turn out to be spam or newsletters, so a large share of the decisions can be made from data. The playbook would parse the reported email into artifacts such as the sender, subject, URLs and attachment hashes, enrich them with reputation from internal sources or sources the indicator's TLP allows, and then scope the case by searching for other recipients of the same sender or URL in the last day and for anyone who clicked, using proxy logs. If everything is clean and nobody clicked, it closes the case as a benign positive with an automatic note. If anything is bad, it prompts an analyst before it purges the email, blocks the domain or resets sessions, because those steps change systems. Every step is written back to the investigation, and the reporter gets an answer. Before trusting it I would test four cases: a clean newsletter, a bad domain with no clicks, a bad domain with a click, and a reputation service that is down, which must send the case to manual review rather than count as clean. After a month I would look at median time to decision, the share of cases closed automatically, and how often analysts reject the playbook's recommendation; a high rejection rate tells me the decision logic is wrong. In Splunk ES 8 I would trigger it with an automation rule tied to the detection, keeping in mind that one detection can belong to only one rule."

What makes this answer strong: it justifies automation from the shape of the workload rather than enthusiasm, separates read-only steps from state-changing ones, includes a failure case in testing, and defines how success and bad decision logic would be measured.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | ES 8.7: Configure automation rules to run playbooks based on findings | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/automation-with-playbooks/configure-automation-rules-to-run-playbooks-based-on-findings-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi |
| S2 | ES 8.3 User Guide: Automate your investigation response with actions and playbooks | https://help.splunk.com/en/splunk-enterprise-security-8/user-guide/8.3/mission-control/automate-your-investigation-response-with-actions-and-playbooks-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi (versi 8.3; cek di 8.7) |
| S3 | ES 8.4: Response plans (lihat Day 34) | https://help.splunk.com/en/splunk-enterprise-security-8/user-guide/8.4/mission-control/respond-to-investigations-with-response-plans-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi |
| S4 | Splunk SOAR (On-premises) release notes 8.6.0 | https://help.splunk.com/en/splunk-soar/soar-on-premises/release-notes/8.6.0/splunk-soar-on-premises-release-notes | primer | 2026-08-04; diakses 2026-10-10 | Tinggi |
| S5 | Splunk App for SOAR release notes | https://help.splunk.com/en/splunk-soar/splunk-app-for-soar/splunk-app-for-soar-release-notes | primer | diakses 2026-10-07 | Sedang |
| S6 | Splunk SOAR (On-premises) release notes 8.4.0 | https://help.splunk.com/en/splunk-soar/soar-on-premises/release-notes/8.4.0/splunk-soar-on-premises-release-notes | primer | 2026-02-18; diakses 2026-10-10 | Sedang-tinggi; rincian Action Builder ringkas |

**Catatan sumber:** nama aksi AR ke SOAR di ES 8.7 perlu dicek di instance. Rincian Action Builder (cakupan dan batasannya) hanya disebut singkat di release notes 8.4.0 [S6]. Fitur approval dan nama node Shuffle bergantung versi Shuffle yang dipakai. Playbook phishing di bagian 2.5 dan angkanya fiktif.
