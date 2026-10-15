---
day: 22
title: 'Capstone dan interview: satu insiden end-to-end, peta seluruh topik, dan latihan interview L2/IR'
researched_on: 2026-10-15
versions_checked: 'NIST SP 800-61 Rev. 3 (April 2025); NIST SP 800-61 Rev. 2 (Agustus 2012, digantikan Rev. 3); CISA Cybersecurity Incident and Vulnerability Response Playbooks (November 2021); RFC 3227 (Februari 2002); Microsoft Learn Revoke user access in an emergency (ms.date 2026-06-19), Respond to a compromised email account (ms.date 2026-07-03), Token theft playbook (ms.date 2023-07-28); Microsoft Security Blog AiTM (12 Juli 2022); UU 27/2022 (salinan BPK); PP 33/2026 menurut KRES.ID (naskah resmi belum diperiksa); Google SRE Book bab 15 (2016); NIST SP 800-84 (September 2006)'
---

# Day 22: Capstone dan interview

Cakupan: peta Day 01-21 ke tahap IR dan artefaknya, delapan pertanyaan yang diulang di setiap insiden, bank cerita dari kasus PT JAB, dua belas pertanyaan interview L2/IR dengan jawaban contoh, daftar cek kesiapan diri, dan capstone `INC-2027-001` yang dikerjakan bertahap dari alert pertama sampai post-incident review.

## Ide inti

Dua puluh satu Day sebelumnya bisa diringkas menjadi satu kalimat: incident response adalah rangkaian keputusan, dan setiap keputusan meninggalkan artefak yang menjadi bahan keputusan berikutnya. Kartu jam pertama menjadi dasar declare, catatan declare menjadi dasar severity dan aktivasi peran, scope statement menjadi dasar rencana bukti dan memo containment, evidence log menjadi dasar analisis, analisis menjadi dasar eradication dan pelaporan, dan semuanya bertemu di laporan insiden dan post-incident review. Jenis insidennya berganti (phishing, mailbox, identitas cloud, AD, ransomware, web shell, cloud, EDR), tetapi pertanyaannya sama: apa yang dipegang penyerang, apa yang ia tanam, sampai mana itu membawanya, log mana yang membuktikannya, siapa yang memutuskan, dan kapan sebuah tahap boleh dinyatakan selesai. Capstone ini menguji apakah kamu bisa menjalankan rangkaian itu sendiri, pada kasus yang belum pernah kamu baca jawabannya.

Kamu sudah mengenal pola ini dari gangguan besar di NOC. Gangguan dinyatakan dan bridge dibuka, sebarannya dicek POP demi POP, `show tech` diambil sebelum perangkat di-reboot, trafik dialihkan dulu supaya gangguan tidak meluas, modul yang rusak diganti setelah penyebabnya diketahui, layanan dipulihkan dan dipantau sampai stabil, lalu RFO ditulis dan dibahas. Tidak ada engineer senior yang menghafal semua runbook; yang membedakan mereka adalah urutan pertanyaan yang selalu sama dan catatan yang selalu rapi. Bedanya dengan IR: lawannya manusia yang bisa melihat responsmu dan kembali lewat jalan lain, dan sebagian keputusan membawa kewajiban hukum yang jamnya sudah berjalan sebelum kamu selesai menganalisis.

```
alert / laporan
  |
  v
triage + kartu jam pertama ---------- Day 03, Day 08, Day 17
  |
  v
declare + severity + peran ---------- Day 01, Day 02
  |
  v
scoping: pivot IOC, akun, host ------ Day 03, Day 10, Day 17, Day 21
  |                                     ^
  v                                     | temuan baru
bukti sebelum containment ----------- Day 04
  |                                     |
  v                                     |
containment serentak (jam H) -------- Day 05, Day 09, Day 10, Day 11, Day 16
  |  validasi gagal --------------------+
  v
eradication + recovery -------------- Day 06, Day 12, Day 14, Day 15, Day 16
  |
  v
komunikasi + pelaporan (jalan sejak declare) ---- Day 18
  |
  v
laporan insiden + PIR + action item ------------- Day 19
  |
  v
latihan dan otomasi supaya lain kali lebih cepat - Day 20, Day 21
```

Situasi capstone terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif yang sama dengan semua Day sebelumnya. Senin, 11 Januari 2027 pukul 08:40, kamu adalah analyst L2 primary on-call minggu itu. Analyst L1 shift pagi Gilang Ramadhan baru saja mengeskalasi dua alert yang ia hubungkan sendiri, dan SOC lead serta incident commander (IC) Dimas Prasetyo menulis di kanal SOC:

> "Ini kemungkinan besar insiden. Kamu jadi technical lead, saya IC. Saya butuh dalam satu jam: apa yang sudah pasti dan apa yang belum, berapa severity-nya, siapa saja yang terkena dan sampai mana, bukti apa yang harus diamankan sebelum kita menyentuh apa pun, dan apa usulan containment-mu. Setelah itu kita urus pembersihan, Pak Hendra, DPO, dan pelanggan korporat. Minggu depan saya mau laporan dan PIR-nya rapi. Anggap ini ujian kenaikan kelasmu."

Pesan itu memuat delapan permintaan, satu untuk setiap tahap capstone:

1. Apa yang sudah pasti dan apa yang belum (triage).
2. Berapa severity-nya dan siapa yang dilibatkan (declare).
3. Siapa yang terkena dan sampai mana (scoping).
4. Bukti apa yang diamankan lebih dulu (bukti).
5. Apa usulan containment (containment).
6. Bagaimana membersihkan dan memulihkan (eradication dan recovery).
7. Apa yang disampaikan ke siapa, dan kewajiban apa yang berjalan (komunikasi dan pelaporan).
8. Laporan dan PIR (pasca insiden).

Permintaan 1 sampai 8 dikerjakan berurutan di bagian 2-4 (Tahap 1 sampai Tahap 8). Bagian 1 berisi peta seluruh topik, bank cerita, dan latihan interview yang menjadi bekal sebelum dan sesudah capstone.

**Kapan relevan:** setelah semua Day selesai dibaca, sebelum interview untuk posisi L2 atau IR, sebelum pertama kali memegang peran technical lead, dan setiap beberapa bulan untuk menguji apakah urutannya masih melekat tanpa membuka catatan.
**Kapan bukan jawaban:** capstone tidak mengajarkan materi baru. Bila sebuah tahap terasa asing, kembali ke Day asalnya yang disebut di setiap tugas. Capstone juga bukan simulasi teknis; ia menguji keputusan, urutan, dan dokumen, sama seperti tabletop di Day 20, sehingga perintah dan query cukup ditulis, tidak harus dijalankan.

## 1. Ringkasan, peta topik, dan bahan interview

### 1.1 Peta Day 01-21: tahap, pertanyaan, dan artefak

Tabel berikut adalah peta seluruh topik dalam satu halaman. Pakai kolom "Artefak" sebagai daftar dokumen yang harus bisa kamu tulis sendiri; setiap artefak punya contoh lengkap di Day asalnya.

| Day | Tahap atau jenis insiden | Pertanyaan yang dijawab | Artefak utama |
|---|---|---|---|
| 01 | Gambaran IR | Kapan event menjadi insiden, siapa memegang peran, seberapa parah | Catatan declare, pemetaan severity, log aktivasi peran, timeline scribe |
| 02 | IR plan dan eskalasi | Siapa boleh memutuskan apa, siapa ditelepon, apa yang diserahkan antar shift | Outline `JAB-IRP-01`, RACI, matriks eskalasi, jadwal on-call, template handover |
| 03 | Triage dan scoping | Apa yang sudah pasti, sejak kapan, sampai mana | Kartu jam pertama, hipotesis, query pivot, scope statement, case notes |
| 04 | Bukti | Apa yang diambil dulu, bagaimana menjaganya | Rencana bukti, evidence log, formulir chain of custody |
| 05 | Containment | Tahan sekarang atau bersiap, bagaimana serentak, kapan berhasil | Memo keputusan, rencana jam H, query validasi, update status |
| 06 | Eradication dan recovery | Clean atau rebuild, rahasia apa yang dirotasi, kapan selesai | Rencana eradication, gerbang validasi, pernyataan akhir recovery |
| 07 | Review Minggu 1 | Benang tahap, keputusan, dan mundur ke tahap sebelumnya | Peta konsep dan glosarium |
| 08 | Phishing | Dari mana pesan datang, siapa menerima, siapa menyerahkan password | Analisis header, message trace, purge, pesan ke pengguna |
| 09 | BEC dan mailbox | Apa yang ditanam di mailbox, email apa yang dibaca | Timeline Unified Audit Log, analisis MailItemsAccessed, rencana jam H mailbox |
| 10 | Identitas Entra ID | Token mana yang masih hidup, persistence apa di identitas | Timeline sign-in, query session ID, containment identitas, checklist pemulihan akun |
| 11 | AD bagian 1 | Kredensial apa yang dicuri dan sampai mana membawa | Query Kerberoasting dan pass-the-ticket, penilaian blast radius |
| 12 | AD bagian 2 | Apakah domain harus dianggap dikuasai | Query DCSync, memo eviction atau pemulihan forest, rencana eviction |
| 13 | Review Minggu 2 | Apa yang bertahan setelah ganti password, di setiap lapis | Tabel lima insiden dan glosarium |
| 14 | Ransomware | Sejak kapan, dicuri atau dikunci, pulih atau bayar | Perburuan sinyal sebelum enkripsi, gerbang restore, memo tebusan |
| 15 | Web shell Linux | Lewat mana masuk, apa yang ditinggalkan, hapus atau rebuild | Analisis access log, query auditd, daftar persistence, rencana jam H |
| 16 | Cloud AWS dan Azure | Log apa yang ada, kunci mana yang dicabut, data apa yang terbukti diambil | Timeline CloudTrail, bukti dan containment cloud, kriteria selesai |
| 17 | Investigasi EDR | True positive atau bukan, perangkat mana lagi | Process tree, query prevalence dan pivot fleet, live response |
| 18 | Komunikasi dan pelaporan | Siapa diberi tahu apa, kewajiban mana yang berjalan, kapan jam mulai | Peta stakeholder, update internal, catatan keputusan titik mulai, pemberitahuan |
| 19 | Laporan dan PIR | Apa yang terjadi, kenapa, dan apa yang diperbaiki | Kerangka laporan, executive summary, metrik, faktor penyebab, action item |
| 20 | Tabletop | Apakah plan dan orangnya siap sebelum insiden | Rencana latihan, MSEL, formulir evaluator, AAR dan improvement plan |
| 21 | Otomasi | Langkah berulang mana yang aman diotomasi | Skrip triage, ringkasan sign-in, revoke dengan pagar, manifest hash, timeline |

### 1.2 Delapan pertanyaan yang diulang di setiap insiden

Daftar berikut adalah inti yang dipakai berulang di Day 03 sampai Day 19, disusun dalam urutan kerja yang selaras dengan fase respons di NIST dan playbook CISA [S1][S2][S3]. Kalau kamu hanya boleh membawa satu halaman ke malam insiden, bawa daftar ini.

1. **Apa yang sudah pasti, dan dari sumber apa?** Fakta dipisah dari hipotesis, setiap fakta bertanggal dan bersumber (Day 03 bagian 1.1 dan 1.7).
2. **Sejak kapan?** Alert pertama bukan awal insiden; cari titik paling awal lewat pivot waktu (Day 03 bagian 1.4).
3. **Apa yang dipegang penyerang?** Password, sesi, token, hash, tiket, kunci, sertifikat. Masing-masing dicabut dengan cara berbeda (Day 10 bagian 1.4, Day 13 bagian 1.8).
4. **Apa yang ia tanam supaya bisa kembali?** Cron, scheduled task, inbox rule, consent, metode MFA, kunci SSH, web shell kedua (Day 09 bagian 1.4, Day 15 bagian 1.4).
5. **Sampai mana akses itu membawanya?** Blast radius diukur dari akses, bukan dari kabel (Day 03 bagian 1.5, Day 11 bagian 1.5).
6. **Bukti apa yang hilang bila kita bertindak sekarang?** Ambil yang paling cepat hilang lebih dulu (Day 04 bagian 1.1 dan 1.2).
7. **Siapa yang memutuskan?** IC untuk wewenang di muka, executive sponsor untuk dampak bisnis, DPO dan Legal untuk kewajiban hukum (Day 02 bagian 1.3).
8. **Kapan tahap ini boleh dinyatakan selesai?** Selalu berdasarkan kriteria tertulis, bukan karena tindakan sudah dijalankan (Day 05 bagian 1.7, Day 06 bagian 1.7, Day 19 bagian 1.7).

### 1.3 Bank cerita: kasus PT JAB untuk menjawab interview

Pewawancara L2 dan IR hampir selalu meminta contoh nyata. Kasus PT JAB fiktif, tetapi pola keputusannya nyata dan bisa diceritakan sebagai latihan atau sebagai cara kerjamu. Tabel berikut memetakan setiap kasus ke pertanyaan interview yang paling cocok; jangan menceritakannya sebagai pengalaman kerja bila bukan.

| Kasus | Day | Inti cerita | Cocok untuk pertanyaan tentang |
|---|---|---|---|
| `INC-2026-012` web shell portal | 02, 15 | Blokir IP tertunda 96 menit karena wewenang; kanal kedua penyerang tetap hidup setelah blokir | IR plan, wewenang di muka, web shell, persistence |
| `INC-2026-017` ransomware share Keuangan | 01, 14 | Dua sinyal sebelum enkripsi berprioritas rendah; tape offline menyelamatkan restore; keputusan tidak membayar | Ransomware, backup, keputusan bisnis |
| `INC-2026-019` phishing ke server billing | 03-07, 18, 19 | Kredensial di skrip; scope bertambah lewat sinkhole; containment parsial dengan delegasi; 5.000 baris data | Scoping, contain atau tunggu, rebuild, pelaporan, PIR |
| `INC-2026-020` phishing kredensial | 08 | 34 penerima, satu menyerahkan password, purge dan reset segera | Analisis email, purge, kapan "jam H adalah sekarang" |
| `INC-2026-021` BEC | 09 | Inbox rule menyembunyikan balasan; consent aplikasi tetap membaca setelah reset | BEC, mailbox, kenapa ganti password tidak cukup |
| `INC-2026-022` AiTM | 10 | MFA sah sekali, session ID dipakai dari ASN lain; alert pertama ditutup tanpa verifikasi | MFA bypass, token, Conditional Access |
| `INC-2026-023` dan `-024` AD | 11, 12 | Kerberoasting ditahan sebelum domain; AD CS sampai DCSync, eviction dan krbtgt | AD, krbtgt, Tier 0 |
| `INC-2026-025` kunci cloud bocor | 16 | Access key dan secret di repo publik; mining dan data di S3 | Cloud IR, log, mencabut kunci |
| `INC-2026-026` installer palsu | 17 | Perangkat terpenting tidak pernah alert, ditemukan lewat advanced hunting | EDR, hunting, telemetry |

### 1.4 Dua belas pertanyaan interview L2/IR

Pertanyaan berikut disusun dari kebutuhan kerja L2 dan IR yang dibahas di Day 01-21, bukan dari soal ujian sertifikasi. Jawab dulu dengan suaramu sendiri dalam dua menit, baru buka contohnya. Setiap contoh memakai cerita dari bank cerita bagian 1.3; ganti dengan pengalamanmu sendiri bila ada, dan jangan mengaku pernah menangani kasus fiktif.

**1. "Walk me through how you handle an incident, from the first alert to closure."**

<details><summary>Sample answer</summary>

"I start by validating the alert and writing down what's confirmed, what's assumed, and since when, because the first alert is rarely the start of the incident. If it meets our criteria, the incident is declared, severity is set, and roles are assigned: an incident commander who coordinates and a technical lead who investigates. Then I scope by pivoting from indicators to accounts and hosts, and I preserve the most volatile evidence before anyone touches the systems. Containment is done in one coordinated window so the attacker can't move to the access we haven't closed yet, and I only call it successful after an agreed period with no new signs. Eradication means rebuilding what we can't trust, closing the entry point, and rotating every secret the attacker saw. Communication and legal reporting run in parallel from the moment we declare. We close with a report, a blameless review, and action items that each have one owner and a deadline."

What makes this answer strong: it follows a real sequence, says who decides, puts evidence before containment, defines "done" by criteria, and shows that reporting is not an afterthought.

</details>

**2. "How do you decide the severity of an incident, and can it change?"**

<details><summary>Sample answer</summary>

"Severity comes from written criteria, not gut feeling: impact on customer services, whether personal data is involved, and what kind of account or system the attacker controls. The heaviest criterion that's met wins, and if I'm unsure between two levels I pick the higher one and lower it once the evidence supports that. Severity is different from alert priority; one incident can start from a low-priority alert. It also changes during the incident. In a billing server case we raised it twice in one day as we found the attacker connected to the customer database, and lowered it after containment had been verified for 24 hours. Every change is logged with the reason."

What makes this answer strong: it separates severity from alert priority, gives a decision rule for uncertainty, and shows severity moving both ways with a recorded reason.

</details>

**3. "Tell me about a time you had to choose between containing immediately and waiting."**

<details><summary>Sample answer</summary>

"In a case where a phishing attachment led to a compromised service account on a billing server, nothing destructive was happening in the morning, so we delayed containment for a few hours to prepare: finish scoping, capture memory, and line up every action. That delay had a time limit and written triggers that would bring it forward. When we saw the attacker's process connected to the customer database, the clock changed, but we kept the planned window because the firewall and credential changes needed that time. At the agreed hour we cut the C2 and server egress first, then isolated hosts, rotated credentials, and purged the email. A sinkhole we had set up caught a third laptop we hadn't known about. Waiting to watch the attacker longer was rejected because personal data was involved and we had no sandbox."

What makes this answer strong: it separates delaying to prepare from delaying to observe, shows triggers and a time limit, explains the order inside the window, and ends with a measurable result.

</details>

**4. "How do you scope an incident?"**

<details><summary>Sample answer</summary>

"I pivot in three directions: from indicators to every host that touched them, from the compromised account to everywhere it logged in, and from each host to the credentials and trust it holds. Each pivot is a saved query with a fixed time range, and I write what I checked and found nothing, not just what I found, because 'not found' only means something if the search and its limits are stated. The output is a dated scope statement with a confidence level and known blind spots, like hosts without EDR or DNS over HTTPS. Scope almost always grows, so containment includes a way to catch what we missed, such as logging blocks and a DNS sinkhole."

What makes this answer strong: it names concrete pivot directions, treats negative results as evidence with limits, and builds discovery of missed hosts into containment.

</details>

**5. "Why isn't resetting the password enough after an account is compromised?"**

<details><summary>Sample answer</summary>

"Because the password is only one of several things the attacker may hold or plant. Refresh tokens and session cookies keep working until they're revoked, and access tokens until they expire. Attackers add their own MFA method, create inbox rules that hide replies, or get users to consent to an app that keeps reading mail regardless of the password. In Active Directory, Kerberos tickets that were already issued stay valid for a while, and stolen hashes can be reused. So account containment is a set: disable or reset twice, revoke sessions, remove attacker MFA methods, rules and app grants, and isolate the host the account was used from. Then I verify in the sign-in and audit logs that the old session no longer works."

What makes this answer strong: it lists the concrete persistence types per layer and ends with verification in logs rather than trusting the command output.

</details>

**6. "The user had MFA. How did the attacker still get in?"**

<details><summary>Sample answer</summary>

"Most likely adversary-in-the-middle phishing. The fake page proxies the real sign-in, the user enters the password and approves MFA honestly, and the proxy captures the session cookie. The attacker replays that cookie from their own infrastructure, so MFA is satisfied by the claim in the token, not by a new prompt. In the logs that shows as the same session ID used from a different network or ASN, without the user's registered device. The fix is not 'more MFA prompts' but phishing-resistant methods for sensitive accounts and Conditional Access that requires a managed device, plus revoking sessions when it happens."

What makes this answer strong: it explains the mechanism precisely, names the log evidence, and proposes controls that actually stop token replay.

</details>

**7. "How would you investigate a web shell on a Linux server that has no EDR?"**

<details><summary>Sample answer</summary>

"I'd preserve memory and logs first, then find the entry point by matching the file's timestamp to the access log, usually a POST to an upload endpoint just before the file appeared. To separate the attacker from scanners, I look for rare URIs with successful responses and pivot on every IP that used them. Without EDR, auditd execve logging for the web server user tells me what programs were run, but not what the PHP code did inside its own process, so I report that limit. I check every persistence location on a list, not just the first finding, and I check firewall logs for outbound connections and lateral movement. Usually the answer is to rebuild from a clean image with code from the repository, fix the upload flaw, and block script execution in upload directories."

What makes this answer strong: it goes from evidence to entry point to scope to eradication, and it is honest about what the log source cannot show.

</details>

**8. "When do you reset krbtgt, and how?"**

<details><summary>Sample answer</summary>

"Only when there's reason to believe the domain itself is compromised: DCSync from a non-DC, signs of forged tickets, or a Tier 0 account used from somewhere it shouldn't be. Kerberoasting a service account doesn't justify it; there I rotate that account and fix its encryption and permissions. When it is justified, I rotate Tier 0 and sync accounts first, then reset krbtgt twice so both stored keys are replaced. The forest recovery guidance waits for replication and about ten hours between resets, while Microsoft's incident response playbook resets twice in quick succession with a script during active compromise, so we write down which path we take and what triggers the faster one, because it forces re-authentication across services."

What makes this answer strong: it ties the decision to evidence, puts the steps in the right order, and shows awareness that there are two official approaches with different costs.

</details>

**9. "Ransomware is spreading in your network. What do you do in the first hour, and would you pay?"**

<details><summary>Sample answer</summary>

"First I stop the spread: isolate the source hosts and the file servers being encrypted, without powering them off, and cut the attacker's C2. In parallel I check whether data was stolen before encryption, because that turns it into a data breach with reporting obligations even if we restore everything. I also confirm which backups are intact and offline, since attackers go after online backups first. Paying is a business and legal decision for the executive sponsor, not the technical team. My job is to give them the facts: can we restore, how long it takes, what was taken, and what paying would and wouldn't solve. In a case I studied, tape backups were intact, so the decision was to restore and not pay, while reporting ran in parallel."

What makes this answer strong: it prioritises stopping spread, raises exfiltration early, checks backups, and places the payment decision with the right person.

</details>

**10. "How do you communicate during an incident, with executives and regulators?"**

<details><summary>Sample answer</summary>

"Internally, the incident commander sends updates on a fixed rhythm for the severity level, even when nothing has changed, with three parts: what's confirmed, what we don't know yet, and when the next update is. If we suspect the attacker can read email or chat, we move to an out-of-band channel prepared in advance. Externally, there's a single owner per audience: corporate communications for customers and media, and the data protection officer with legal for regulators and data subjects. In Indonesia the personal data protection law requires written notice within three times twenty-four hours, but the law doesn't say exactly when the clock starts, so I'd make sure the DPO records the start time they chose, the alternatives, and the reasons, and that we don't wait for a complete forensic report to send the first notice."

What makes this answer strong: it shows structure and ownership, mentions out-of-band, and handles the legal timer carefully without claiming certainty the law doesn't give.

</details>

**11. "What makes a good post-incident review?"**

<details><summary>Sample answer</summary>

"It's blameless but not ownerless. We reconstruct the timeline from logs and notes, not memory, and look for contributing factors instead of stopping at one person's mistake, because 'the analyst missed the alert' usually means the alert was low priority among hundreds. Metrics like dwell time and time to containment are calculated with the start point written down. Every finding becomes an action item with one owner, a deadline, and a clear done criterion, tracked in the owner's own ticketing system. The incident isn't closed until those items are tracked, and the improvements feed the next tabletop exercise."

What makes this answer strong: it balances blamelessness with accountability, insists on evidence and defined metrics, and links the review to tracked change.

</details>

**12. "Tell me about a mistake made during an incident and what you learned."**

<details><summary>Sample answer</summary>

"One pattern I've studied closely: an alert about a new MFA method registered from outside the company was closed by the first analyst as 'probably a new phone' without checking with the user. The attacker had stolen a session through phishing and kept access for hours. What I took from it isn't 'that analyst was careless', it's that the process allowed closing an identity alert without out-of-band verification. So my rule is to confirm with the user by phone from the directory, never through the account that might be compromised, and to treat that alert type as higher priority. When I make mistakes myself, I write them in the case notes the same way: what I did, what I knew at the time, and what I'd change."

What makes this answer strong: it owns the lesson without blaming a person, turns it into a concrete rule, and shows the habit of documenting one's own mistakes.

</details>

### 1.5 Daftar cek kesiapan diri

Daftar ini menguji apakah kamu siap memegang peran technical lead. Tandai dengan jujur di catatan pribadimu; setiap butir yang belum bisa dikerjakan tanpa membuka catatan adalah Day yang perlu dibaca ulang.

| Kemampuan | Bisa dikerjakan tanpa membuka catatan bila | Day acuan |
|---|---|---|
| Menulis kartu jam pertama | Selesai dalam 15 menit dengan bagian "sengaja belum dilakukan" | Day 03 bagian 2.1 |
| Menentukan severity dan membela pilihan | Bisa menyebut kriteria terberat yang terpenuhi dan pemicu naik turunnya | Day 01 bagian 1.7 dan 1.8 |
| Menulis scope statement | Ada keyakinan, batas visibilitas, dan "sudah diperiksa, tidak ditemukan" | Day 03 bagian 2.4 |
| Menyusun rencana bukti | Urutan volatilitas dan alasan untuk tiap item yang ditunda | Day 04 bagian 2.1 |
| Menyusun memo containment | Minimal tiga pilihan dengan harga layanan dan delegasi bersyarat | Day 05 bagian 2.1 |
| Menyusun rencana jam H | Kolom R, A, verifikasi, dan rollback terisi | Day 05 bagian 2.2 |
| Menahan akun cloud dan on-prem | Urutan disable, reset dua kali, revoke, metode MFA, rule, consent | Day 10 bagian 2.4 dan 2.8 |
| Memutuskan clean atau rebuild | Bisa menyebut apa yang tidak diketahui dan rahasia mana yang dirotasi | Day 06 bagian 1.2 dan 1.4 |
| Menulis update ke executive sponsor | Terverifikasi dipisah dari diperintahkan; ada waktu update berikutnya | Day 05 bagian 2.5, Day 18 bagian 2.2 |
| Mencatat keputusan titik mulai pelaporan | Titik mulai, alasan, tafsir alternatif, dan tenggat masing-masing | Day 18 bagian 2.3 |
| Menghitung metrik insiden | Setiap angka punya titik awal dan titik akhir yang ditulis | Day 19 bagian 2.3 |
| Menulis action item | Satu pemilik, tenggat, dan kriteria selesai per item | Day 19 bagian 2.6 |

## 2-4. Capstone `INC-2027-001` dan troubleshooting

Capstone ini dikerjakan per tahap. Setiap tahap memberi inject (informasi yang kamu terima pada jam itu), tugas dengan format dari Day asalnya, lalu kunci di `<details>`. Tulis jawabanmu lebih dulu di `latihan/day22-capstone.md`, baru buka kuncinya. Jangan membaca inject tahap berikutnya sebelum tahap yang sedang dikerjakan selesai, karena sebagian keputusan memang harus diambil dengan informasi yang belum lengkap. Semua isi fiktif dan merupakan keluaran ilustrasi.

Fakta organisasi yang berlaku di capstone ini (status Januari 2027, fiktif): PT JAB memakai Microsoft 365 E3 (Entra ID P1), Defender for Office 365 Plan 2, dan Defender for Endpoint Plan 2; log Entra ID dan Microsoft 365 masuk Splunk index `o365` dengan retensi satu tahun; retensi `proxy` dan `dns` di Splunk 30 hari. Dari usulan Conditional Access setelah `INC-2026-022`, CA-10 (pendaftaran metode MFA dari luar lokasi tepercaya) dan CA-11 (admin phishing-resistant) sudah enforce sejak November 2026, CA-12 (Microsoft 365 hanya dari perangkat terkelola) masih report-only karena staf POP memakai perangkat pribadi, dan CA-13 masih pilot. NOC memakai JAB NetOps Portal di `jkt-netops01` (`10.20.6.15`), aplikasi web inventaris jaringan yang memakai single sign-on Entra ID dan bisa dibuka dari internet supaya engineer on-call bisa bekerja dari rumah. Log aplikasinya hanya disimpan lokal di server itu dan dirotasi setiap 7 hari; yang dikirim ke Splunk index `netops` hanya log TACACS dan SNMP perangkat jaringan.

### Tahap 1: deteksi dan triage (Senin 2027-01-11, 08:05 sampai 08:40)

**Inject 1.**

- 08:05, `SOC-2027-0002` (rule harian "session ID dari lebih dari satu ASN", dibuat setelah `INC-2026-022`): akun `rendra.kusnadi@jab.example` memakai satu session ID dari dua jaringan. Sign-in interactive ke OfficeHome Jumat 2027-01-08 17:22:40 dari `198.51.100.55`, lalu Outlook Web dan aplikasi lain dari `203.0.113.33` (penyedia VPS) sejak Jumat 17:31:05, terakhir non-interactive Senin 07:58:12.
- 08:07, `SOC-2027-0003` (rule proxy "POST ke domain baru"): `10.30.17.72` mengirim `POST` ke `login.meet-olt.example.net` Senin 07:56:31. Domain itu terdaftar enam hari lalu.
- 08:15, Gilang menemukan bahwa kedua alert menyebut infrastruktur yang sama, lalu menemukan `SOC-2027-0001` yang sudah ditutup: Jumat 17:35, "pendaftaran metode MFA ditolak Conditional Access" untuk `rendra.kusnadi` dari `203.0.113.33`. Analyst L1 shift sore Dwi Cahyono menutupnya pukul 17:52 sebagai benign setelah mengirim chat Teams ke Rendra dan menerima balasan pukul 17:49: "aman, saya lagi setting HP baru".
- 08:28, Gilang menelepon Rendra Kusnadi (engineer NOC Jakarta, `JKT-WS-0474`, `10.10.47.74`) di nomor dari direktori. Rendra tidak mengganti HP, tidak pernah menerima chat dari Dwi, dan ingat membuka undangan rapat vendor OLT Jumat sore lalu login di halaman yang tampak seperti halaman Microsoft.
- 08:31, Gilang memanggilmu sebagai L2 primary on-call.

**Tugas 1.** Tulis kartu jam pertama dengan format Day 03 bagian 2.1: yang sudah pasti (dengan sumber), hipotesis, yang belum diketahui, dan yang sengaja belum dilakukan beserta alasannya.

<details><summary>Kunci tahap 1</summary>

```
INC (calon) | Kartu jam pertama | Senin 2027-01-11 08:40 | TL: <kamu>
SUDAH PASTI (sumber)
- Sesi Rendra dipakai dari 203.0.113.33 sejak Jumat 17:31 sampai Senin 07:58 (sign-in log).
- Rendra tidak mendaftarkan metode MFA dan tidak membalas chat Jumat 17:49 (telepon 08:28).
  Balasan chat itu dikirim dari sesi yang dicuri.
- CA-10 menolak pendaftaran metode MFA penyerang Jumat 17:34 (audit log, alert 0001).
- 10.30.17.72 mengirim POST ke domain yang sama Senin 07:56 (proxy).
HIPOTESIS
- H1 (didukung): phishing AiTM lewat undangan rapat; cookie sesi Rendra dicuri dan diputar ulang.
- H2 (didukung sebagian): pemilik 10.30.17.72 juga menyerahkan password dan MFA pagi ini.
- H3 (belum diuji): penyerang membuka aplikasi lain dengan sesi Rendra, termasuk yang berisi data.
- H4 (belum diuji): penyerang memakai mailbox Rendra untuk menyebar phishing ke dalam.
BELUM DIKETAHUI
- Siapa pemilik 10.30.17.72; semua penerima email; aplikasi apa yang dibuka; data apa yang diambil.
SENGAJA BELUM DILAKUKAN (alasan)
- Revoke dan reset belum dijalankan: scope akun belum lengkap (H2), dan semua tindakan akun
  dijalankan bersama supaya tidak ada sesi yang tertinggal. Target keputusan: sebelum 09:30.
- Balasan ke chat Teams Rendra tidak dikirim: kanal itu mungkin dibaca penyerang.
```

Hal yang sering terlewat:
- Alert yang sudah ditutup Jumat ikut dimasukkan sebagai fakta, bukan diabaikan karena statusnya "benign". Alert itu memberi titik waktu paling awal yang diketahui (Day 03 bagian 1.4).
- Verifikasi ke pengguna dilakukan lewat telepon dari direktori, bukan lewat akun yang mungkin dikuasai. Itu persis kelemahan penutupan alert Jumat.
- Satu session ID yang dipakai dari dua jaringan, dengan MFA yang sah sekali, adalah ciri AiTM: password dan MFA diserahkan ke proxy, lalu cookie sesinya diputar ulang dari infrastruktur penyerang [S7]. Alur investigasinya mengikuti token theft playbook dan Day 10 bagian 1.3 [S8].
- Belum ada tindakan akun, tetapi alasannya ditulis dan diberi batas waktu, sama seperti menunda untuk bersiap di Day 05 bagian 1.3. Karena penyerang masih aktif, batasnya pendek.

</details>

### Tahap 2: declare, severity, dan peran (08:40 sampai 08:50)

**Inject 2.**

- `10.30.17.72` adalah `BDG-WS-0172` milik Yusuf Hidayat, engineer NOC Bandung. Sign-in log menunjukkan Yusuf login lewat `198.51.100.55` pukul 07:57:02, lalu sesinya dipakai dari `203.0.113.33` ke Outlook Web sejak 08:03:40.
- Rendra dan Yusuf sama-sama punya akses ke JAB NetOps Portal, yang berisi inventaris pelanggan dedicated (termasuk nama dan nomor telepon PIC pelanggan korporat) dan backup konfigurasi perangkat jaringan.
- Belum ada tanda login ke perangkat jaringan atau gangguan layanan.

**Tugas 2.** Tulis catatan keputusan declare dengan format Day 01 bagian 2.1, petakan ke severity dengan tabel Day 01 bagian 2.2, dan susun log aktivasi peran seperti Day 01 bagian 2.3.

<details><summary>Kunci tahap 2</summary>

```
INC-2027-001 | Catatan keputusan declare | Senin 2027-01-11 08:50 WIB
Diputuskan: Dimas Prasetyo (IC) | Diusulkan: <kamu> (TL)
Fakta saat declare: dua akun engineer NOC dikuasai lewat sesi yang dicuri (AiTM), satu sejak
  Jumat 17:31, satu sejak Senin 08:03; keduanya punya akses ke portal berisi data PIC pelanggan
  korporat dan konfigurasi perangkat jaringan.
Severity: SEV-2. Kriteria terberat yang terpenuhi: kompromi terkonfirmasi tetapi terbatas;
  data pribadi mungkin terdampak dalam jumlah terbatas.
Pemicu naik ke SEV-1 (tertulis): login ke perangkat jaringan memakai rahasia dari backup
  konfigurasi; perubahan konfigurasi perangkat yang tidak dikenal; gangguan layanan pelanggan;
  bukti data pribadi dalam jumlah besar keluar.
Peran: IC Dimas | TL <kamu> | scribe: L1 kedua shift pagi | NOC: Bambang Hartono (C) |
  executive sponsor Hendra Wijaya (diberi tahu) | DPO Agus Setiawan dan Legal Ratna Sari
  (diberi tahu karena data pribadi mungkin terdampak) | Komunikasi: Maya Lestari (siaga)
Kanal: #inc-2027-001; kanal OOB "JAB-CSIRT-OOB" untuk koordinasi sampai sesi kedua akun
  terverifikasi tercabut, karena chat Teams akun korban terbukti dipakai penyerang.
Update ke executive sponsor: setiap 4 jam (SEV-2).
```

Cara membandingkan dengan jawabanmu:
- SEV-2, bukan SEV-1, karena kriteria SEV-1 (layanan terganggu luas, data dalam jumlah besar, ransomware, domain admin dikuasai) belum terpenuhi; pemicu SEV-1 ditulis supaya kenaikan tidak diperdebatkan ulang (Day 01 bagian 1.8).
- DPO dan Legal diberi tahu saat declare, bukan setelah data terbukti diambil, karena jam kewajiban bisa sudah berjalan (Day 18 bagian 1.4).
- Kanal OOB dipakai karena ada bukti penyerang memakai chat korporat dari akun korban (Day 18 bagian 1.3).

</details>

### Tahap 3: scoping (08:50 sampai 09:20)

**Inject 3.** Hasil query dan pemeriksaan sampai 09:15:

- Message trace: email "Undangan: Evaluasi vendor OLT Q1 2027" dari `agenda@meet-olt.example.net` diterima 12 mailbox IT Infrastruktur dan NOC Jumat 16:58. Email kedua, "Runbook OLT baru, mohon dicek sebelum shift", dikirim dari mailbox Rendra ke 6 engineer NOC lain Minggu 21:40, dengan tautan ke domain yang sama; salinannya dihapus dari Sent Items pukul 21:41. Total 18 penerima, tidak ada yang tumpang tindih.
- Proxy: lima host membuka halaman `login.meet-olt.example.net`; hanya dua yang mengirim `POST`, yaitu `10.10.47.74` (Jumat 17:22:31) dan `10.30.17.72` (Senin 07:56:31).
- Sign-in log 18 penerima (cara Day 10 bagian 2.7): hanya Rendra dan Yusuf yang punya sign-in dari `198.51.100.55` atau `203.0.113.33`.
- Audit log Entra ID: tidak ada metode MFA, perangkat, atau consent aplikasi baru untuk kedua akun; satu pendaftaran metode MFA gagal Jumat 17:34:20 (ditolak CA-10).
- Mailbox: tidak ada inbox rule atau forwarding di kedua mailbox. MailItemsAccessed mencatat 63 item mailbox Rendra dibuka dari `203.0.113.33` Jumat 17:38 sampai 18:25, ditambah email baru yang masuk selama akhir pekan; di OneDrive, `Runbook-NOC-2026.docx` dibuka pukul 17:58.
- Sign-in log juga mencatat sesi Rendra membuka aplikasi "JAB NetOps Portal" dari `203.0.113.33` Jumat 18:09:12.
- Log TACACS dan SNMP di index `netops` sejak Jumat 17:00: semua login dari server NMS dan jump host yang dikenal.
- EDR `JKT-WS-0474` dan `BDG-WS-0172`: tidak ada proses, file, atau persistence baru di sekitar waktu klik; hanya browser.

**Tugas 3.** Perbarui hipotesis, lalu tulis scope statement v1 dengan format Day 03 bagian 2.4, termasuk keyakinan, batas visibilitas, "sudah diperiksa, tidak ditemukan", dan kesiapan containment menurut syarat Day 03 bagian 1.6.

<details><summary>Kunci tahap 3</summary>

```
INC-2027-001 | Scope statement v1 | Senin 2027-01-11 09:20 WIB | SEV-2
Disusun: <kamu> (TL) | Disetujui: Dimas (IC) | Keyakinan: SEDANG
TERKONFIRMASI TERDAMPAK
Akun : rendra.kusnadi (sesi dicuri sejak Jumat 17:31, aktif sampai Senin 07:58 atau lebih)
       yusuf.hidayat  (sesi dicuri sejak Senin 08:03)
Infra: login.meet-olt.example.net (AiTM, 198.51.100.55); 203.0.113.33 (pemakai sesi)
Akses: mailbox dan OneDrive Rendra (63 item + email akhir pekan; Runbook-NOC-2026.docx);
       mailbox Yusuf; JAB NetOps Portal oleh sesi Rendra Jumat 18:09 (aktivitas di dalam
       portal BELUM diketahui)
Penyebaran: phishing internal dari mailbox Rendra Minggu 21:40 ke 6 engineer NOC
SUDAH DIPERIKSA, TIDAK DITEMUKAN
- sign-in dari infrastruktur penyerang untuk 16 penerima lain
- metode MFA, perangkat, consent, inbox rule, forwarding baru di kedua akun
- malware atau persistence di JKT-WS-0474 dan BDG-WS-0172 (EDR)
- login ke perangkat jaringan dari sumber tak dikenal (TACACS, SNMP)
BATAS VISIBILITAS
- log aplikasi JAB NetOps Portal hanya lokal, rotasi 7 hari, belum diperiksa
- 3 host yang membuka halaman tanpa POST: belum dikonfirmasi ke penggunanya
- proxy dan dns hanya 30 hari
KESIAPAN CONTAINMENT: akun, sesi, infrastruktur penyerang, dan jenis persistence diketahui.
Rekomendasi: amankan log portal sekarang, lalu containment akun dan portal serentak 09:30.
```

Cara membandingkan dengan jawabanmu:
- Phishing internal dari mailbox Rendra adalah temuan scope yang penting: email dari mailbox asli lolos autentikasi dan terlihat sah (Day 09 bagian 1.1). Gelombang penerima kedua itu yang menjelaskan Yusuf.
- Portal tercatat sebagai "dibuka", bukan "datanya diambil". Itu baru bisa dijawab dari log aplikasi, yang menjadi bukti paling mendesak di tahap 4.
- "Tidak ditemukan" untuk perangkat jaringan dan workstation memakai sumber yang disebut, sehingga bisa dipercaya sebatas sumber itu (Day 03 bagian 2.4).

</details>

### Tahap 4: bukti (09:15 sampai 09:30)

**Inject 4.** Bambang Hartono mengonfirmasi bahwa log JAB NetOps Portal hanya ada di `jkt-netops01`, dirotasi setiap 7 hari; entri tertua yang masih ada bertanggal Senin 2027-01-04, sehingga entri Jumat 8 Januari akan terhapus Jumat ini. Dari log itu Bambang membacakan tiga baris untuk sesi Rendra: login SSO Jumat 18:09:12 dari `203.0.113.33`, ekspor "Inventaris pelanggan dedicated" (CSV, 2.140 baris: nama perusahaan, nama PIC, telepon PIC, email PIC, alamat lokasi, blok IP) pukul 18:14:22, dan unduhan "Backup konfigurasi core dan agregasi" (ZIP, 412 file) pukul 18:20:47. Tidak ada baris untuk sesi Yusuf.

**Tugas 4.** Tulis rencana bukti dengan format Day 04 bagian 2.1 dan baris evidence log seperti Day 04 bagian 2.5. Tentukan juga apa yang sengaja tidak diambil dan kenapa (Day 04 bagian 1.7).

<details><summary>Kunci tahap 4</summary>

| No | Item | Sumber | Kenapa sekarang | Penanggung jawab |
|---|---|---|---|---|
| E01 | Log aplikasi dan riwayat ekspor JAB NetOps Portal | `jkt-netops01`, salin lewat SSH dari `jkt-bastion01` | Paling cepat hilang (rotasi 7 hari); satu-satunya bukti apa yang diambil | <kamu>, didampingi NOC |
| E02 | Sign-in log interactive dan non-interactive, audit log Entra ID, kedua akun dan 16 penerima lain | Splunk `o365` | Dasar timeline dan verifikasi pencabutan | <kamu> |
| E03 | Unified Audit Log termasuk MailItemsAccessed kedua mailbox | Purview | Menjawab email apa yang dibaca | <kamu> |
| E04 | Kedua email asli (`.eml`) dan message trace | Exchange Online, Threat Explorer | Diambil sebelum purge | <kamu> |
| E05 | Log proxy, DNS, firewall untuk domain dan dua IP penyerang | Splunk `proxy`, `dns`, `firewall` | Retensi 30 hari | <kamu> |
| E06 | Log TACACS dan SNMP sejak Jumat | Splunk `netops` | Dasar penilaian pemicu SEV-1 | NOC |
| E07 | Paket investigasi EDR `JKT-WS-0474` dan `BDG-WS-0172` | Defender for Endpoint | Ringan; menguatkan "tidak ada malware" | <kamu> |

Semua file disimpan di `/evidence/INC-2027-001/` di `jkt-evid01` dengan manifest SHA-256 (Day 21 bagian 2.4) dan dicatat di evidence log (Day 04 bagian 2.5).

Sengaja tidak diambil: image memori dan disk kedua workstation. Tidak ada tanda kode penyerang di endpoint (AiTM bekerja di sisi layanan), sehingga image penuh tidak proporsional (Day 04 bagian 1.7). Keputusan ini ditulis beserta pemicu untuk mengubahnya: tanda proses atau file asing di EDR.

Cara membandingkan dengan jawabanmu:
- E01 di urutan pertama karena paling volatil, sesuai urutan volatilitas (Day 04 bagian 1.2) [S4].
- Hampir semua bukti identitas dan email ada di sisi layanan dan tidak hilang karena revoke atau reset. Karena itu containment tidak perlu menunggu lama setelah E01 aman.

</details>

### Tahap 5: containment (09:20 sampai 10:00)

**Inject 5.** Bambang menyampaikan bahwa JAB NetOps Portal dipakai engineer on-call dari rumah; bila akses dari internet ditutup, on-call malam harus lewat VPN, yang menurutnya "lebih repot tapi bisa". Hendra sudah membaca update pertama dan bertanya lewat grup OOB, "Kenapa tidak tunggu sore supaya rapi seperti waktu billing dulu?"

**Tugas 5.** Tulis memo keputusan singkat dengan format Day 05 bagian 2.1 (minimal tiga pilihan dengan plus, minus, dan durasi), lalu rencana jam H dengan format Day 05 bagian 2.2 dan urutan containment identitas Day 10 bagian 2.4. Tulis juga kriteria selesai containment.

<details><summary>Kunci tahap 5</summary>

Memo (ringkas):

```
PILIHAN
A. Jam H sekarang, 09:30 (rekomendasi): revoke dan reset kedua akun, akhiri semua sesi
   aplikasi portal dan tutup portal dari internet sementara, blok infrastruktur penyerang,
   purge kedua email.
   + Penyerang masih aktif di dua sesi; scope aksesnya (sesi dan password) sudah lengkap.
   - On-call memakai VPN untuk portal sampai kontrol tambahan aktif (perkiraan 2 hari).
B. Jam H sore hari supaya persiapan lebih rapi.
   - Ditolak: tidak ada yang perlu disiapkan lagi, dan setiap jam berarti akses ke mailbox,
     portal, dan kesempatan phishing internal berikutnya.
C. Matikan portal sepenuhnya sampai perbaikan selesai.
   - Ditolak: risiko dari internet sudah tertutup oleh pembatasan akses; NOC butuh portal.
KEPUTUSAN: IC (wewenang di muka: akun, blok, pembatasan alat internal). Hendra diberi tahu;
  tidak ada layanan pelanggan yang dimatikan.
```

| Menit | Tindakan | R | A | Verifikasi |
|---|---|---|---|---|
| H+0 (09:30) | Revoke sessions dan reset password dua kali untuk `rendra.kusnadi` dan `yusuf.hidayat`; akun dinonaktifkan sampai checklist pemulihan selesai | Infrastruktur | IC | Sign-in gagal dari sesi lama di log, bukan hanya keluaran perintah |
| H+0 | Semua sesi aplikasi JAB NetOps Portal diakhiri; portal hanya bisa dibuka dari jaringan internal dan VPN | NOC | IC | Uji buka dari internet gagal; daftar sesi aktif kosong |
| H+0 | Blok `198.51.100.55` dan `203.0.113.33` di firewall dengan logging; `meet-olt.example.net` ke sinkhole dan diblok di proxy; pengirim masuk Tenant Allow/Block List | NOC, <kamu> | IC | Hit deny dan log sinkhole |
| H+5 | Purge kedua email dari 18 mailbox | <kamu> | IC | Status per pesan di Action center |
| H+10 | Telepon tiga pengguna yang membuka halaman tanpa `POST` | Gilang | IC | Konfirmasi tidak ada password yang diketik |
| H+15 | Validasi: tidak ada sign-in sukses dari infrastruktur penyerang atau session ID lama sejak 09:30 | <kamu> | IC | Query sign-in (Day 10 bagian 1.4) |

Kriteria selesai containment: 24 jam tanpa sign-in sukses dari infrastruktur penyerang atau session ID lama; tidak ada akses portal dari luar; tidak ada email phishing baru ke staf; tiga pengguna tanpa `POST` terkonfirmasi; scope statement diperbarui dan disetujui IC.

Cara membandingkan dengan jawabanmu:
- Jawaban untuk Hendra: di `INC-2026-019` waktu persiapan dipakai untuk menemukan host dan kredensial yang belum diketahui dan menyiapkan perubahan firewall serta aplikasi. Di sini akses penyerang adalah sesi dan password yang sudah diketahui semuanya, tidak ada malware yang bisa bereaksi, dan penyerang sedang aktif, jadi jam H-nya adalah sekarang, seperti `INC-2026-020` (Day 13 bagian 1.9).
- Sesi aplikasi portal diakhiri terpisah, karena revoke sessions di Entra ID tidak memutus session token yang diterbitkan aplikasi sendiri (Day 05 bagian 1.5) [S5].
- Pukul 09:41 sign-in log mencatat percobaan sesi Yusuf dari `203.0.113.33` yang ditolak. Itu tanda pencabutan bekerja, bukan kegagalan containment.

</details>

### Tahap 6: eradication dan recovery (Senin siang sampai Selasa)

**Inject 6.** Pemeriksaan isi ZIP yang diunduh penyerang (dari salinan backup yang sama di server) menunjukkan 412 file konfigurasi perangkat core dan agregasi, yang memuat SNMP community dan kunci bersama TACACS perangkat. CSV inventaris berisi data 2.140 baris yang sudah keluar dan tidak bisa ditarik kembali. Tidak ada tanda kode penyerang di `jkt-netops01`; penyerang memakai fungsi ekspor dan unduh yang sah dengan sesi Rendra.

**Tugas 6.** Tulis rencana eradication dan recovery dengan format Day 06 bagian 2.2: rahasia apa yang dirotasi dan dengan urutan apa, apakah `jkt-netops01` perlu dibangun ulang, perbaikan jalan masuk, pemulihan kedua akun dengan checklist Day 10 bagian 2.8, dan kriteria recovery selesai (Day 06 bagian 1.7).

<details><summary>Kunci tahap 6</summary>

- **Rahasia jaringan dirotasi bertahap.** Rahasia yang pernah terlihat penyerang dirotasi semua (Day 06 bagian 1.4), tetapi 412 perangkat tidak bisa diubah dalam satu malam. Gelombang 1: perangkat core dan perangkat yang antarmuka manajemennya paling terbuka, dalam 48 jam. Gelombang 2: sisanya dalam 7 hari. Sampai selesai, NOC memastikan akses manajemen SNMP dan TACACS perangkat hanya diterima dari server NMS dan TACACS, dan SOC memantau index `netops` untuk autentikasi dari sumber tak dikenal (pemicu SEV-1). R: NOC; A: IC; Hendra diberi tahu jadwal change window.
- **`jkt-netops01` tidak dibangun ulang.** Clean atau rebuild ditentukan oleh apa yang tidak diketahui (Day 06 bagian 1.2). Di sini tidak ada indikasi eksekusi kode di server; yang disalahgunakan adalah fungsi aplikasi oleh pengguna sah. Keputusan ini ditulis beserta pemicunya: bila ditemukan file, proses, atau akun asing di server, keputusan diulang.
- **Jalan masuk ditutup.** Portal hanya untuk perangkat terkelola dan jaringan internal; ekspor massal butuh autentikasi ulang dan dibatasi; backup konfigurasi dipindah dari portal atau rahasianya disamarkan; log aplikasi dikirim ke Splunk. CA-12 dipercepat untuk grup IT dan NOC lebih dulu (pilot), sebagai keputusan Infrastruktur dan executive sponsor.
- **Kedua akun dipulihkan dengan checklist Day 10 bagian 2.8:** metode MFA diperiksa (hanya milik pengguna), tidak ada rule atau consent, password sudah direset dua kali, pengguna diberi penjelasan, akun diaktifkan Selasa pagi, dan sign-in dipantau ketat 7 hari.
- **Recovery selesai** bila gelombang 2 rotasi terverifikasi selesai, kontrol portal aktif dan diuji, kedua akun pulih, dan 7 hari setelah rotasi terakhir tidak ada autentikasi dari sumber tak dikenal di perangkat jaringan maupun sign-in dari infrastruktur penyerang. Bila gelombang 2 selesai Selasa 2027-01-19, pernyataan akhir recovery paling cepat Selasa 2027-01-26.

Cara membandingkan dengan jawabanmu:
- Data yang sudah keluar tidak "dieradikasi"; ia menjadi kewajiban pelaporan dan pemberitahuan di tahap 7, seperti ditulis di Kapan bukan jawaban Day 06.
- Rotasi bertahap dengan kompensasi adalah pola containment jangka panjang yang sama dengan Day 05 bagian 1.1: sementara, berbatas waktu, dan dipantau.

</details>

### Tahap 7: komunikasi dan pelaporan (Senin 10:00 sampai Kamis)

**Inject 7.** Pukul 10:05 DPO Agus Setiawan dan Legal Ratna Sari meminta fakta untuk menilai kewajiban, Maya Lestari bertanya apakah perlu pernyataan publik, dan dua account manager pelanggan korporat bertanya apa yang boleh disampaikan ke pelanggannya.

**Tugas 7.** Susun peta stakeholder (Day 18 bagian 2.1), update internal SEV-2 (Day 18 bagian 2.2), dan bahan catatan keputusan titik mulai untuk DPO dengan pohon keputusan Day 18 bagian 2.3, termasuk tafsir alternatif dan tenggatnya. Draf pemberitahuan ke subjek data mengikuti Day 18 bagian 2.4.

<details><summary>Kunci tahap 7</summary>

- **Apakah ini kegagalan pelindungan data pribadi?** Ya menurut definisi Penjelasan Pasal 46: akses tidak sah dan pengungkapan data pribadi PIC (nama, telepon, email) dalam 2.140 baris (Day 18 bagian 1.4) [S9]. Insiden ini terjadi sebelum 16 Januari 2027, tanggal PP 33/2026 dilaporkan mulai berlaku [S10], sehingga dasar yang pasti adalah Pasal 46 UU PDP; status PP dan lembaga tetap dicek Legal.
- **Bahan titik mulai untuk DPO** (aturan PT JAB: titik paling awal yang masuk akal, dengan alternatif tertulis):

| Kandidat | Dasar | Tenggat 3 x 24 jam | Catatan |
|---|---|---|---|
| Jumat 2027-01-08 17:35 | Alert `SOC-2027-0001` | Senin 2027-01-11 17:35 | Alert tentang pendaftaran MFA yang ditolak; belum dasar wajar tentang akses ke data pribadi, tetapi dicatat sebagai tafsir paling awal |
| Senin 2027-01-11 08:40 | Validasi bahwa sesi Rendra dicuri dan dipakai ke aplikasi berisi data pribadi | Kamis 2027-01-14 08:40 | Kandidat yang diusulkan TL |
| Senin 2027-01-11 09:15 | Log portal membuktikan ekspor | Kamis 2027-01-14 09:15 | Kepastian, bukan dasar wajar pertama |

  Yang memilih dan menandatangani adalah DPO dan Legal; TL menyediakan fakta dan jamnya. Karena tafsir paling awal berakhir hari ini pukul 17:35, keputusan itu perlu diambil pagi ini, bukan menunggu laporan lengkap (Day 18 bagian 1.4).
- **Penerima dan pemilik:** subjek data (PIC) dan lembaga lewat DPO dan Legal; pelanggan korporat lewat account manager dengan naskah yang disetujui Legal, karena blok IP dan alamat lokasi juga menyangkut kewajiban kontrak (Day 18 bagian 1.5); media dan publik hanya lewat Maya. Ayat (3) ke masyarakat dinilai Legal; layanan publik tidak terganggu, tetapi holding statement tetap disiapkan.
- **Update internal SEV-2 pukul 13:30** memisahkan yang terverifikasi (dua akun ditahan, portal dibatasi, purge selesai, data 2.140 baris dan 412 konfigurasi keluar) dari yang belum (pemakaian rahasia perangkat oleh penyerang), dengan waktu update berikutnya 17:30.

Cara membandingkan dengan jawabanmu:
- Pemberitahuan pertama tidak menunggu kepastian forensik; isi yang belum pasti ditulis sebagai belum pasti dan dilengkapi kemudian (Day 18 bagian 1.4).
- Kanal OOB dipakai sampai pencabutan terverifikasi pukul 09:45, lalu koordinasi kembali ke `#inc-2027-001`.

</details>

### Tahap 8: laporan insiden dan PIR (Senin 2027-01-18 sampai Selasa 2027-01-19)

**Inject 8.** Hendra meminta executive summary untuk direksi dan PIR dijadwalkan Selasa 2027-01-19 pukul 13:00 dengan fasilitator Nina Kartika. Semua waktu yang dibutuhkan ada di tahap 1 sampai 7.

**Tugas 8.** Hitung metrik dengan format Day 19 bagian 2.3 (tulis titik awal dan titik akhir tiap angka), susun analisis faktor penyebab seperti Day 19 bagian 2.4, daftar action item seperti Day 19 bagian 2.6, dan executive summary seperti Day 19 bagian 2.2.

<details><summary>Kunci tahap 8</summary>

| Metrik | Titik awal | Titik akhir | Nilai |
|---|---|---|---|
| Dwell time | Kredensial Rendra diserahkan, Jumat 17:22:40 | Alert yang ditindaklanjuti, Senin 08:05:00 | 62 j 42 m |
| Alert pertama ke declare | `SOC-2027-0001`, Jumat 17:35 | Declare, Senin 08:50 | 63 j 15 m |
| Alert ke validasi | `SOC-2027-0002`, Senin 08:05 | Validasi, 08:40 | 35 m |
| Alert ke declare | Senin 08:05 | 08:50 | 45 m |
| Declare ke jam H | 08:50 | 09:30 | 40 m |
| Data keluar ke deteksi | Ekspor CSV, Jumat 18:14:22 | Senin 08:05:00 | 61 j 50 m |
| Kredensial Yusuf ke pencabutan | Senin 07:56:31 | 09:30:00 | 1 j 33 m |

Faktor penyebab (bukan satu orang):
1. Alert identitas boleh ditutup setelah verifikasi lewat kanal yang mungkin dikuasai penyerang (chat dari akun korban).
2. CA-12 masih report-only, sehingga sesi yang dicuri bisa diputar ulang dari VPS.
3. Portal yang berisi data pelanggan dan rahasia perangkat terbuka ke internet dengan single sign-on, tanpa autentikasi ulang untuk ekspor massal.
4. Backup konfigurasi dengan rahasia perangkat tersedia untuk diunduh dari portal.
5. Rule session ID lintas ASN berjalan harian, sehingga deteksi baru terjadi Senin pagi.
6. Log aplikasi portal hanya lokal 7 hari dan tidak masuk SIEM.

Yang bekerja dan dicatat juga: CA-10 menolak pendaftaran metode MFA penyerang; rule harian dan rule proxy menghubungkan dua korban; Gilang memverifikasi lewat telepon.

| No | Action item | Pemilik | Tenggat | Kriteria selesai |
|---|---|---|---|---|
| 1 | `JAB-PB-03`: verifikasi pengguna untuk alert identitas wajib lewat telepon dari direktori | SOC lead (Dimas) | 2027-01-29 | Playbook versi baru disetujui dan disosialisasikan ke semua L1 |
| 2 | CA-12 enforce untuk grup IT dan NOC | Infrastruktur | 2027-02-05 | Kebijakan aktif; sign-in dari perangkat tak terkelola ditolak di log |
| 3 | Portal: hanya perangkat terkelola, autentikasi ulang dan batas untuk ekspor | NOC (Bambang) | 2027-02-12 | Uji ekspor dari perangkat tak terkelola gagal |
| 4 | Rahasia di backup konfigurasi disamarkan atau dipindah dari portal | NOC (Bambang) | 2027-02-12 | Sampel 20 file tanpa rahasia terbaca |
| 5 | Rule session ID lintas ASN dijalankan setiap 15 menit | SOC (Sari) | 2027-01-29 | Rule aktif dan diuji di lab |
| 6 | Log aplikasi portal dikirim ke Splunk dengan retensi satu tahun | NOC dan SOC | 2027-02-05 | Event ekspor muncul di Splunk |
| 7 | Skenario AiTM dengan phishing internal masuk tabletop berikutnya | SOC lead (Dimas) | 2027-03-31 | MSEL memuat inject verifikasi lewat kanal yang dikuasai |

Executive summary (ringkas): "Pada 8-11 Januari 2027, penyerang mencuri sesi login dua engineer NOC lewat undangan rapat palsu dan, dengan satu sesi itu, mengunduh data kontak PIC 2.140 baris pelanggan korporat serta konfigurasi 412 perangkat jaringan. Layanan pelanggan tidak terganggu dan tidak ada bukti perangkat jaringan diakses penyerang. Akses penyerang dicabut 40 menit setelah insiden dinyatakan, dan rahasia perangkat sedang dirotasi bertahap sampai 19 Januari. DPO dan Legal mengirim pemberitahuan sesuai UU PDP. Keputusan yang diminta: anggaran dan jadwal untuk mewajibkan perangkat terkelola bagi seluruh pegawai (CA-12)."

Cara membandingkan dengan jawabanmu:
- Faktor 1 ditulis sebagai kelemahan proses, bukan "Dwi salah" (Day 19 bagian 1.5) [S11].
- Hal yang bekerja ikut dicatat, supaya kontrol yang efektif tidak ikut dibongkar saat perbaikan.
- Action item 7 menghubungkan PIR ke latihan berikutnya (Day 20 bagian 1.6) [S12].

</details>

**Hasil yang sebaiknya tersimpan:**

- `latihan/day22-capstone.md` berisi jawabanmu untuk delapan tahap, sebelum dan sesudah membandingkan dengan kunci, dengan catatan di mana jawabanmu berbeda dan Day mana yang dibaca ulang.
- Rekaman atau catatan jawaban lisan untuk dua belas pertanyaan di bagian 1.4, dengan waktu tiap jawaban.
- Tabel kesiapan diri bagian 1.5 yang sudah diisi jujur.

**Variasi tantangan:** jalankan capstone sebagai tabletop dengan format Day 20: satu orang menjadi fasilitator yang membacakan inject, kamu dan rekan memegang peran IC, TL, dan DPO, dan satu evaluator mengisi formulir Day 20 bagian 2.4. Tambahkan inject kejutan: pukul 11:10 index `netops` mencatat login TACACS ke satu router agregasi dari IP yang tidak dikenal.

### Troubleshooting

Tabel ini memuat masalah yang sering muncul saat mengerjakan capstone. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memperbaiki |
|---|---|---|
| Kartu jam pertama berisi kesimpulan tanpa sumber | Fakta dan hipotesis tercampur | Tulis sumber setiap fakta; pindahkan sisanya ke hipotesis (Day 03 bagian 1.2) |
| Severity langsung SEV-1 tanpa alasan | Memilih dari rasa takut, bukan kriteria | Sebut kriteria terberat yang terpenuhi dan tulis pemicu kenaikan (Day 01 bagian 1.7) |
| Containment menunggu "jam H sore" | Pola `INC-2026-019` dipakai tanpa melihat alasannya | Tanya apa yang masih perlu disiapkan; bila tidak ada, jam H adalah sekarang (Day 13 bagian 1.9) |
| Lupa sesi aplikasi pihak ketiga atau internal | Mengira revoke Entra ID mencabut semua | Daftar aplikasi yang dibuka sesi itu dari sign-in log, lalu akhiri sesinya satu per satu (Day 05 bagian 1.5) |
| Titik mulai pelaporan ditulis satu tanpa alternatif | Menganggap tafsir sudah pasti | Tulis kandidat, dasar, dan tenggat masing-masing; keputusan di DPO dan Legal (Day 18 bagian 2.3) |
| Metrik tidak bisa dicek ulang | Titik awal dan akhir tidak ditulis | Setiap angka diberi dua timestamp dan sumbernya (Day 19 bagian 1.3) |

## 5. Kesalahan umum dan jebakan

Kesalahan berikut muncul berulang di kasus PT JAB dan hampir pasti muncul di capstone atau interview. Setiap butir menyebut Day asalnya.

- Menganggap alert pertama sebagai awal insiden, sehingga dwell time, scope, dan titik mulai pelaporan semuanya terlalu pendek (Day 03).
- Memverifikasi pengguna lewat akun yang mungkin dikuasai, atau menutup alert identitas tanpa verifikasi sama sekali (Day 10, capstone).
- Bertindak satu per satu sejak IOC pertama ditemukan, atau sebaliknya menunda tanpa batas waktu dan pemicu (Day 05).
- Mengira reset password menutup semua akses, padahal sesi, token, rule, consent, tiket, dan sesi aplikasi punya jalur sendiri (Day 05, Day 09, Day 10, Day 11).
- Menghapus artefak penyerang sebelum bukti diambil, atau mengambil image penuh untuk insiden yang tidak membutuhkannya (Day 04, Day 15).
- Menyatakan containment atau recovery selesai karena tindakan sudah dijalankan, bukan karena kriteria terpenuhi (Day 05, Day 06).
- Mereset krbtgt untuk serangan yang tidak menyentuh domain, atau tidak mereset saat domain dikuasai (Day 11, Day 12).
- Menunggu laporan forensik lengkap sebelum memberi tahu DPO dan Legal, padahal jam kewajiban mungkin sudah berjalan (Day 18).
- Menulis faktor penyebab yang berhenti di satu orang, dan action item tanpa pemilik atau kriteria selesai (Day 19).
- Menceritakan kasus latihan sebagai pengalaman kerja saat interview. Ceritakan sebagai latihan, atau pakai pengalamanmu sendiri.

## 6. Catatan terkini

Bagian ini menampung status regulasi dan produk yang dipakai capstone dan bisa berubah setelah catatan ini ditulis.

- **NIST SP 800-61 Rev. 3** (April 2025) menggantikan Rev. 2 dan memetakan IR ke fungsi CSF 2.0; Rev. 2 dengan siklus empat fasenya masih sering muncul di lowongan dan pertanyaan interview, jadi keduanya perlu dikenali [S1][S2].
- **UU PDP:** PP 33/2026 dilaporkan mulai berlaku 16 Januari 2027 dengan pemberitahuan diatur di Pasal 114, tetapi naskah resminya belum diperiksa untuk catatan ini [S10]. Untuk insiden setelah tanggal itu, cek naskah resmi PP dan status lembaga pelindungan data pribadi sebelum memakai rumusan pemberitahuan apa pun [S9].
- **Status Conditional Access PT JAB** di capstone (CA-10 dan CA-11 enforce, CA-12 report-only, CA-13 pilot) adalah ketetapan fiktif Januari 2027 yang melanjutkan usulan di Day 10 bagian 2.6.
- **Dokumentasi Microsoft** untuk pencabutan akses darurat dan respons akun email terkompromi diperbarui berkala; cek tanggal halamannya sebelum mengutip umur token atau langkah pemulihan [S5][S6].

## 7. Cheat sheet

```
SATU INSIDEN, DELAPAN TAHAP, SATU ARTEFAK PER TAHAP
  1 triage      kartu jam pertama (pasti | hipotesis | belum tahu | sengaja belum)   Day 03
  2 declare     catatan declare + severity + pemicu naik + peran + kanal             Day 01-02
  3 scoping     scope statement (keyakinan | batas | sudah diperiksa)                Day 03
  4 bukti       rencana bukti + evidence log + manifest hash (volatil dulu)          Day 04, 21
  5 containment memo pilihan + jam H (R, A, verifikasi) + kriteria selesai            Day 05
  6 eradication rebuild/clean + rotasi rahasia + tutup jalan masuk + kriteria         Day 06
  7 komunikasi  peta stakeholder + update + titik mulai (alternatif + tenggat)        Day 18
  8 pasca       metrik (2 timestamp) + faktor penyebab + action item + exec summary  Day 19

DELAPAN PERTANYAAN: pasti apa? | sejak kapan? | dipegang apa? | ditanam apa?
  | sampai mana? | bukti apa hilang? | siapa memutuskan? | kapan selesai?

JAM H: tunda hanya untuk BERSIAP (batas waktu + pemicu); scope lengkap + penyerang aktif = sekarang
AKUN: reset 2x + revoke + metode MFA + rule + consent + sesi aplikasi + verifikasi di log
LAPOR: Pasal 46 UU PDP 3 x 24 jam; titik mulai = keputusan DPO/Legal, tulis alternatif
INTERVIEW: urutan + siapa memutuskan + bukti di log + kriteria selesai + pelajaran tanpa menyalahkan
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Di `INC-2027-001`, CA-10 menolak pendaftaran metode MFA penyerang, jadi Conditional Access sudah mencegah kompromi akun Rendra." Benarkah?

<details><summary>Jawaban</summary>

Tidak. CA-10 hanya mencegah satu bentuk persistence, yaitu metode MFA baru dari luar lokasi tepercaya. Sesi Rendra tetap bisa diputar ulang dari VPS karena CA-12 (perangkat terkelola) masih report-only, sehingga penyerang membaca mailbox, membuka portal, dan mengirim phishing internal. Keduanya dicatat di PIR: CA-10 sebagai kontrol yang bekerja, CA-12 sebagai faktor penyebab. Lihat bagian 2-4 Tahap 3 dan Tahap 8.

</details>

**2. Skenario keputusan.** Pukul 09:20 Senin, kamu harus memilih waktu containment untuk dua akun yang sesinya dicuri. Mana yang tepat?

- A. Jam H sore hari, supaya persiapan serapi containment `INC-2026-019`.
- B. Jam H 09:30: revoke dan reset kedua akun, akhiri sesi portal dan tutup portal dari internet, blok infrastruktur penyerang, purge email, setelah log portal yang volatil diamankan.
- C. Reset password Rendra segera saat ia ditelepon pukul 08:28, lalu lanjutkan scoping.

<details><summary>Jawaban</summary>

B. Akses penyerang adalah sesi dan password yang sudah diketahui semuanya, tidak ada malware yang bisa bereaksi, dan penyerang sedang aktif, sehingga tidak ada persiapan yang membenarkan penundaan; bukti paling volatil sudah diamankan lebih dulu. A keliru karena alasan menunda di `INC-2026-019` (host dan kredensial yang belum diketahui, perubahan firewall dan aplikasi) tidak ada di sini. C keliru karena satu akun ditahan sementara akun kedua dan sesi aplikasi masih terbuka, dan reset saja tidak mencabut sesi yang sudah dicuri. Lihat bagian 2-4 Tahap 5 dan Day 13 bagian 1.9.

</details>

**3. Pertanyaan jebakan.** "Karena tidak ada malware di workstation, insiden AiTM tidak butuh pengamanan bukti; semua lognya ada di cloud." Benarkah?

<details><summary>Jawaban</summary>

Tidak sepenuhnya. Sebagian besar bukti identitas dan email memang ada di sisi layanan dan tidak hilang karena revoke, tetapi bukti terpenting di `INC-2027-001`, yaitu log aplikasi portal yang mencatat ekspor data, hanya ada lokal dan dirotasi tujuh hari. Pengamanan bukti tetap dimulai dari yang paling cepat hilang; yang berubah adalah apa yang tidak perlu diambil (image memori dan disk workstation). Lihat bagian 2-4 Tahap 4 dan Day 04 bagian 1.2 dan 1.7.

</details>

**4. Skenario keputusan.** DPO bertanya titik mulai 3 x 24 jam untuk `INC-2027-001`. Respons TL mana yang tepat?

- A. "Senin 09:15, saat log portal membuktikan ekspor, karena sebelum itu belum pasti ada data yang keluar."
- B. "Itu keputusan Bapak dan Legal. Ini tiga kandidat beserta dasar dan tenggatnya; yang paling awal berakhir hari ini 17:35, jadi keputusannya perlu pagi ini."
- C. "Jumat 17:35, jadi kita sudah pasti terlambat dan tidak perlu terburu-buru."

<details><summary>Jawaban</summary>

B. Teks Pasal 46 dan penjelasannya tidak menyebut titik mulai, sehingga titik mulai adalah tafsir yang diputuskan DPO dan Legal; tugas TL menyediakan fakta, jam, dan tenggat setiap kandidat, dengan aturan PT JAB memakai titik paling awal yang masuk akal dan mencatat alternatifnya. A keliru karena menunggu kepastian forensik bertentangan dengan aturan itu. C keliru karena memilih tafsir sendiri dan menyimpulkan keterlambatan tanpa keputusan DPO. Lihat bagian 2-4 Tahap 7 dan Day 18 bagian 1.4.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Bambang Hartono (Manajer NOC), dalam tiga kalimat, kenapa 412 perangkat harus dirotasi rahasianya padahal tidak ada bukti penyerang login ke perangkat jaringan.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "File konfigurasi yang diunduh penyerang berisi SNMP community dan kunci TACACS, jadi selama rahasia itu belum diganti, kita bergantung sepenuhnya pada ACL manajemen dan pemantauan untuk mencegahnya dipakai. Tidak adanya login sampai sekarang hanya berarti belum dipakai, bukan tidak akan dipakai, dan rahasia yang pernah terlihat penyerang selalu kita anggap bocor. Karena 412 perangkat tidak bisa diubah sekaligus, kita mulai dari core dan perangkat yang paling terbuka dalam 48 jam, sisanya dalam seminggu, sambil SOC memantau setiap autentikasi dari sumber yang tidak dikenal."

Kesalahan yang sering muncul:
- Mengatakan rotasi "untuk jaga-jaga" tanpa menyebut rahasia apa yang terungkap.
- Meminta semua perangkat diubah malam itu juga tanpa memikirkan change window.
- Tidak menyebut kompensasi selama rotasi berjalan.

</details>

**6. Pertanyaan jebakan.** "Analyst L1 yang menutup `SOC-2027-0001` adalah akar masalah `INC-2027-001`, jadi action item yang tepat adalah pelatihan ulang untuk Dwi." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Dwi memverifikasi, tetapi lewat kanal yang ternyata dikuasai penyerang, dan proses saat itu membolehkannya. PIR yang blameless mencari faktor penyebab: aturan verifikasi di playbook, CA-12 yang masih report-only, portal yang terbuka ke internet dengan ekspor massal, rahasia di backup konfigurasi, rule yang hanya berjalan harian, dan log portal yang tidak masuk SIEM. Action item yang tepat mengubah playbook untuk semua L1, bukan menghukum satu orang. Lihat bagian 2-4 Tahap 8 dan Day 19 bagian 1.4 dan 1.5.

</details>

**7. Interview question (English).** "If you joined us as an L2 analyst tomorrow and a serious incident started at 2 a.m., what would you do in the first hour?"

<details><summary>Sample answer</summary>

"In the first fifteen minutes I'd validate the alert and write a first-hour card: what's confirmed with sources, my hypotheses, what we don't know, and what I'm deliberately not doing yet and why. If it meets the criteria I'd page the incident commander by the escalation matrix, not wait for someone to answer email, and propose a severity with the triggers that would raise it. Then I'd scope quickly by pivoting from the indicators to accounts and hosts, and secure whatever evidence disappears first. If the attacker is active and I know the access they hold, I'd recommend coordinated containment right away; if not, I'd ask for a short, time-boxed delay to prepare. From the start I'd keep case notes with times and sources, use an out-of-band channel if our email or chat might be compromised, and make sure the DPO and legal know early if personal data might be involved, because their clock may already be running."

What makes this answer strong: it is concrete about the first hour, respects roles and escalation, links the containment timing to what is known, and shows awareness of evidence, communication, and legal obligations from the start.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | NIST SP 800-61 Rev. 3 (PDF) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf | primer | April 2025; diakses 2026-10-15 | Tinggi. IR sebagai bagian manajemen risiko CSF 2.0; dipakai lewat Day asal |
| S2 | NIST SP 800-61 Rev. 2: Computer Security Incident Handling Guide (PDF) | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf | primer | Agustus 2012 (lebih dari 3 tahun, digantikan Rev. 3); diakses 2026-10-15 | Tinggi untuk siklus empat fase yang masih dipakai di lowongan dan interview |
| S3 | CISA: Cybersecurity Incident and Vulnerability Response Playbooks (PDF) | https://www.cisa.gov/sites/default/files/publications/Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf | primer | November 2021; diakses 2026-10-15 | Tinggi. Urutan respons, tipping off, dan kriteria containment berhasil yang mendasari Day 03-06 |
| S4 | RFC 3227: Guidelines for Evidence Collection and Archiving (BCP 55) | https://www.rfc-editor.org/rfc/rfc3227.txt | primer | Februari 2002 (lebih dari 3 tahun); diakses 2026-10-15 | Tinggi untuk urutan volatilitas |
| S5 | Microsoft Learn: Revoke user access in an emergency in Microsoft Entra ID | https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access | primer (dokumentasi vendor) | ms.date 2026-06-19; diakses 2026-10-15 | Tinggi. Revoke sessions, umur access token, session token aplikasi |
| S6 | Microsoft Learn: Respond to a compromised email account in Microsoft 365 | https://learn.microsoft.com/en-us/defender-office-365/responding-to-a-compromised-email-account | primer (dokumentasi vendor) | ms.date 2026-07-03; diakses 2026-10-15 | Tinggi. Langkah pemulihan akun email, inbox rule dan forwarding |
| S7 | Microsoft Security Blog: From cookie theft to BEC, attackers use AiTM phishing sites as entry point to further financial fraud | https://www.microsoft.com/en-us/security/blog/2022/07/12/from-cookie-theft-to-bec-attackers-use-aitm-phishing-sites-as-entry-point-to-further-financial-fraud/ | sekunder (laporan vendor) | 2022-07-12 (lebih dari 3 tahun); diakses 2026-10-15 | Sedang-tinggi. Mekanisme AiTM yang dipakai skenario capstone |
| S8 | Microsoft Learn: Token theft playbook | https://learn.microsoft.com/en-us/security/operations/token-theft-playbook | primer (dokumentasi vendor) | ms.date 2023-07-28 (lebih dari 2 tahun); diakses 2026-10-15 | Tinggi untuk alur investigasi pencurian token |
| S9 | BPK JDIH: UU Nomor 27 Tahun 2022 tentang Pelindungan Data Pribadi | https://peraturan.bpk.go.id/Details/229798/uu-no-27-tahun-2022 | primer | diundangkan 17 Oktober 2022; diakses 2026-10-15 | Tinggi. Pasal 46 dan Penjelasannya |
| S10 | KRES.ID: Hitung mundur 16 Januari 2027, PP 33/2026 terbit | https://www.kres.id/pp-33-2026-aturan-pelaksana-uu-pdp | sekunder (analisis konsultan) | 2026; diakses 2026-10-15 | Sedang. Tanggal berlaku PP 33/2026 dan Pasal 114; tidak menyebut titik mulai; naskah resmi belum diperiksa |
| S11 | Google SRE Book, bab 15: Postmortem Culture, Learning from Failure | https://sre.google/sre-book/postmortem-culture/ | sekunder | 2016; diakses 2026-10-15 | Tinggi untuk praktik operasi. Blameless postmortem |
| S12 | NIST SP 800-84: Guide to Test, Training, and Exercise Programs for IT Plans and Capabilities (PDF) | https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-84.pdf | primer | September 2006 (lebih dari 3 tahun, masih final); diakses 2026-10-15 | Tinggi. Tabletop dan tindak lanjut latihan |

**Catatan sumber:** capstone ini tidak menambah fakta teknis baru; setiap aturan dan langkah diambil dari Day asal yang disebut di setiap tugas, dan sumber di atas adalah sumber Day asal yang paling langsung mendukung capstone. Skenario `INC-2027-001`, status Conditional Access Januari 2027, JAB NetOps Portal, nama orang, alamat IP, dan semua waktu adalah contoh fiktif. Status PP 33/2026 berasal dari sumber sekunder dan perlu dicek ke naskah resmi di JDIH. Pertanyaan interview disusun dari kebutuhan kerja L2 dan IR yang dibahas di Day 01-21, bukan dari soal ujian sertifikasi mana pun.
