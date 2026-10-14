---
day: 42
title: SOAR playbook dan cara memicunya dari ES
researched_on: 2026-10-10
versions_checked: Splunk ES 8.7 (Configure automation rules to run playbooks based on findings); ES 8.3 user guide (Automate your investigation response with actions and playbooks); Splunk SOAR (On-premises) 8.6.0 (4 Agu 2026) dan 8.4.0 (18 Feb 2026); SOAR Cloud; Splunk Enterprise 10.6
---

# Day 42: SOAR playbook dan cara memicunya dari ES

Cakupan: menjelaskan penggunaan SOAR playbook dan menyebut cara dasar memicunya dari Enterprise Security.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan apa itu SOAR playbook, kapan memakainya dibanding adaptive response (Day 41), dan komponen umum SOAR.
- menyebut cara memicu playbook dari ES 8: automation rules, Run playbook manual di Mission Control, response plan task, dan adaptive response ke SOAR.
- merancang playbook yang aman (enrichment, keputusan, lalu tindakan dengan persetujuan).
- menerapkan konsep yang sama di lab memakai Shuffle + TheHive.

## 2. Konteks singkat

SOAR (Security Orchestration, Automation and Response) mengotomasi alur kerja, bukan sekadar satu aksi. Contoh:
1. finding phishing masuk;
2. ekstrak URL dan lampiran;
3. cek reputasi;
4. cari email serupa di kotak masuk lain;
5. minta persetujuan analyst;
6. hapus email dan blokir domain;
7. perbarui kasus.

SANS 2026 SOC Survey menunjukkan adopsi AI/otomasi tinggi tetapi integrasinya ke workflow yang terdefinisi masih rendah (Day 29). Playbook adalah cara membuat otomasi itu terdefinisi, teruji, dan teraudit.

## 3. Konsep inti

### 3.1 Konsep SOAR (umum)

| Konsep | Arti |
|---|---|
| Playbook | Alur otomatis (atau semi-otomatis) berisi langkah, logika, dan percabangan. Di Splunk SOAR dibangun dengan Visual Playbook Editor atau kode Python |
| App | Konektor ke produk lain (EDR, firewall, email, threat intel) |
| Action | Operasi yang disediakan app (mis. "block ip", "get file reputation") |
| Asset | Konfigurasi instans produk (alamat, kredensial) untuk app |
| Container/event + artifact | Wadah kasus dan observable-nya (IP, hash, URL), cek istilah di SOAR 8.x |
| Prompt / approval | Langkah yang meminta keputusan manusia (human-in-the-loop), cek nama fitur |

Versi terkini: Splunk SOAR (On-premises) 8.6.0 dirilis 4 Agu 2026. Release notes-nya menyebut 8.6.0 sebagai rilis terakhir yang mendukung Python 3.9; rilis yang dijadwalkan September 2026 tidak lagi mendukungnya, dan otomasi yang masih dipakai harus dimigrasi ke Python 3.13 [S4]. Rilis 8.4.0 (18 Feb 2026) sudah mengumumkan arah yang sama dan memperkenalkan Action Builder (beta) di Visual Playbook Editor untuk membuat endpoint baru bagi app yang ada tanpa menulis kode [S6]. Dampaknya bagi analyst: playbook lama yang belum dimigrasi bisa berhenti berjalan setelah upgrade, tanpa ada perubahan di sisi ES.

### 3.2 Kapan memakai playbook (vs adaptive response)

Gunakan playbook bila:
- respons butuh beberapa langkah dan beberapa alat;
- ada logika/percabangan (bila reputasi buruk jalankan A, bila tidak jalankan B);
- butuh persetujuan manusia sebelum tindakan berisiko;
- alur yang sama berulang sering (phishing, akun kompromi, malware alert);
- butuh dokumentasi otomatis di kasus.

Gunakan adaptive response (Day 41) untuk aksi tunggal yang sederhana.

### 3.3 Cara memicu playbook dari ES 8

Prasyarat: ES dipasangkan (paired) dengan Splunk SOAR oleh admin [S1][S2].

1. Automation rules (otomatis berbasis finding) [S1]:
   - Jalur menu: Configure > Splunk SOAR > Automation rules. Halaman ini hanya terlihat bila ES dan SOAR sudah dipasangkan. Butuh hak SOAR untuk membuat/mengedit.
   - **Trigger:** finding yang dibuat oleh detection tertentu (berstatus on, menghasilkan finding di analyst queue) dan/atau ingestion dari app tertentu.
   - **Isi rule:** nama unik (tidak bisa diubah), satu/lebih detection, sumber ingestion opsional, satu/lebih playbook (hanya tipe ES), aktif/nonaktif.
   - **Batasan:** satu detection hanya bisa terkait satu automation rule. Bila beberapa playbook terpicu bersamaan, eksekusinya FIFO.
2. Manual dari Mission Control [S2]: pilih investigation di analyst queue, buka tab Automation, klik Run playbook, pilih playbook, lalu Run. Ada juga Run action untuk satu aksi app dengan parameter. Hasil tampil di riwayat otomasi (tabel/peta/JSON), dan Open Playbook membuka detail di SOAR.
3. Response plan task [S2]: admin dapat mengonfigurasi aksi/playbook agar berjalan otomatis ketika task tertentu di response plan selesai (Day 34).
4. **Adaptive response ke SOAR**: disebut sebagai salah satu cara memicu [S1]. Di ES 7.x dikenal sebagai aksi "Send to SOAR/Phantom", cek nama dan ketersediaannya di ES 8.7.

### 3.4 Merancang playbook yang aman

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

### 3.5 Enterprise vs ES vs lab

- **ES + SOAR:** automation rules, Mission Control automation, response plan, pairing.
- **Splunk Enterprise + SOAR:** alert action/app untuk mengirim event ke SOAR (Splunk App for SOAR/Export perlu dicek) tanpa fitur Mission Control.
- **Lab-mu:** Shuffle (SOAR open-source) + TheHive (case management) menjadi analog yang baik untuk melatih konsep yang sama.

## 4. Contoh SPL dan langkah di ES

> Keluaran berlabel ilustrasi.

### 4.1 Memilih kandidat otomasi: finding yang sering dan seragam

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

### 4.2 Query yang dipakai playbook untuk verifikasi (langkah 6)

```
| tstats summariesonly=false count from datamodel=Authentication.Authentication
    where Authentication.src="$src$" Authentication.action="success" earliest=-1h
    by Authentication.user Authentication.dest
```

- `$src$` adalah token yang diisi playbook (mis. lewat aksi "run query" app Splunk di SOAR), cek nama aksi di app Splunk untuk SOAR.

### 4.3 Langkah di ES (generik)

1. Admin memasangkan ES dengan SOAR, cek langkah pairing di dokumentasi ES 8.7.
2. Configure > Splunk SOAR > Automation rules, lalu buat rule dengan detection "Lab - Auth - Brute Force Followed By Success", playbook "account_compromise_lab" (tipe ES), dan status aktif [S1].
3. Picu detection (Day 36). Lihat finding dan hasil playbook di tab Automation investigation [S2].
4. Coba juga Run playbook manual pada investigation lain [S2].

### 4.4 Lab tanpa SOAR Splunk: Shuffle + TheHive

1. Alert Splunk (Day 36 bagian 4.5) mengirim webhook ke workflow Shuffle.
2. Workflow Shuffle:
   - parse alert (src, user);
   - enrichment (mis. cek IP di lookup lokal atau layanan reputasi dengan data uji saja, perhatikan ToS layanan);
   - buat case di TheHive dengan observable;
   - user input/approval sebelum langkah tindakan, cek fitur approval di versi Shuffle-mu;
   - tindakan lab yang aman, mis. menonaktifkan akun uji di VM lab via skrip yang kamu kontrol.
3. Catat semua langkah di case (dokumentasi otomatis).

### 4.5 Contoh lengkap: playbook phishing dan cara mengujinya

Skenario fiktif: user melaporkan email mencurigakan lewat tombol report, dan email itu masuk sebagai finding "Reported Phishing Email". Rata-rata tim menerima 30 laporan sehari, dan 80% di antaranya adalah spam biasa atau newsletter. Ini kandidat otomasi yang ideal: sering, seragam, dan sebagian besar keputusannya bisa diambil dari data.

Desain playbook:

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

## 5. Lab praktik

1. Pilih satu detection lab (Day 36). Tulis desain playbook dengan pola bagian 3.4: trigger, enrichment, keputusan, tindakan, persetujuan, dokumentasi, verifikasi.
2. Implementasikan di Shuffle + TheHive (bagian 4.4), atau di ES + SOAR bila tersedia (bagian 4.3).
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

**Variasi tantangan:** sebutkan keempat cara memicu playbook dari ES 8 (bagian 3.3). Untuk masing-masing, beri satu skenario di mana cara itu paling tepat.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Perbaikan |
|---|---|---|
| Halaman Automation rules tidak terlihat | ES belum dipasangkan dengan SOAR | Pairing oleh admin [S1] |
| Tidak bisa membuat rule | Tidak punya hak SOAR | Minta hak [S1] |
| Detection tidak bisa dipilih di rule baru | Detection sudah terkait rule lain (1:1) | Lepaskan dari rule lama [S1] |
| Playbook tidak muncul di daftar | Bukan tipe ES (mis. tipe SOAR/Input) | Gunakan playbook bertipe ES [S1] |
| Playbook gagal setelah upgrade SOAR | Ketidakcocokan Python (3.9 -> 3.13) | Migrasikan playbook, custom function, dan app ke Python 3.13 [S4] |
| Webhook Shuffle tidak menerima | URL/izin jaringan lab | Cek konektivitas dan log Shuffle |

## 7. Kesalahan umum dan jebakan

- Mengotomasi tindakan berdampak tinggi tanpa persetujuan (Day 41).
- Playbook tanpa dokumentasi ke kasus. Akuntabilitas hilang.
- Mengira satu detection bisa memicu beberapa automation rule. Hubungannya 1 detection : 1 rule [S1].
- Mengabaikan pemeliharaan playbook (perubahan API vendor, versi Python SOAR) [S4].
- Mengunggah data sensitif ke layanan reputasi publik dari playbook. Perhatikan TLP (Traffic Light Protocol: label berbagi informasi CLEAR, GREEN, AMBER, AMBER+STRICT, RED) pada indikator yang diterima, dan ketentuan layanan (ToS) penyedia reputasi, karena banyak layanan publik membagikan file yang diunggah ke pelanggan lain.
- `[komunitas]` Shuffle dan TheHive sebagai analog lab didasarkan pada praktik lab sendiri, bukan dokumentasi Splunk. Nama node dan fitur approval di Shuffle bergantung versi.

## 8. Catatan terkini

- ES 8.x mengintegrasikan otomasi SOAR ke Mission Control (tab Automation, Run playbook/Run action) dan automation rules di Configure > Splunk SOAR [S1][S2].
- SOAR On-prem 8.6.0 (Agu 2026) adalah rilis terakhir dengan Python 3.9; otomasi perlu dimigrasi ke Python 3.13 [S4]. Action Builder (beta) di VPE sejak 8.4.0 [S6].
- Release notes ES 8.6.1/8.7 menyebut agen AI untuk membantu menulis playbook dan "AI SOC Analyst" yang bisa menjalankan tindakan yang diizinkan (Day 45). Batas izin dan jejak auditnya perlu dicek di instance.

## 9. Cheat sheet

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

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | ES 8.7: Configure automation rules to run playbooks based on findings | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/automation-with-playbooks/configure-automation-rules-to-run-playbooks-based-on-findings-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi |
| S2 | ES 8.3 User Guide: Automate your investigation response with actions and playbooks | https://help.splunk.com/en/splunk-enterprise-security-8/user-guide/8.3/mission-control/automate-your-investigation-response-with-actions-and-playbooks-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi (versi 8.3; cek di 8.7) |
| S3 | ES 8.4: Response plans (lihat Day 34) | https://help.splunk.com/en/splunk-enterprise-security-8/user-guide/8.4/mission-control/respond-to-investigations-with-response-plans-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi |
| S4 | Splunk SOAR (On-premises) release notes 8.6.0 | https://help.splunk.com/en/splunk-soar/soar-on-premises/release-notes/8.6.0/splunk-soar-on-premises-release-notes | primer | 2026-08-04; diakses 2026-10-10 | Tinggi |
| S5 | Splunk App for SOAR release notes | https://help.splunk.com/en/splunk-soar/splunk-app-for-soar/splunk-app-for-soar-release-notes | primer | diakses 2026-10-07 | Sedang |
| S6 | Splunk SOAR (On-premises) release notes 8.4.0 | https://help.splunk.com/en/splunk-soar/soar-on-premises/release-notes/8.4.0/splunk-soar-on-premises-release-notes | primer | 2026-02-18; diakses 2026-10-10 | Sedang-tinggi; rincian Action Builder ringkas |

**Catatan sumber:** nama aksi AR ke SOAR di ES 8.7 perlu dicek di instance. Rincian Action Builder (cakupan dan batasannya) hanya disebut singkat di release notes 8.4.0 [S6]. Fitur approval dan nama node Shuffle bergantung versi Shuffle yang dipakai. Playbook phishing di bagian 4.5 dan angkanya fiktif.
