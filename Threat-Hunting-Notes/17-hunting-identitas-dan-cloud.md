---
day: 17
title: 'Hunting identitas dan cloud: pertanyaan yang tidak dijawab mesin risiko'
researched_on: 2026-10-18
versions_checked: 'Microsoft Entra ID Protection risk detections (ms.date 2026-04-22, diperbarui 2026-10-15) dan license requirements (ms.date 2025-10-30); Entra sign-in logs (2025-11-07) dan non-interactive sign-in logs (2026-02-09); Microsoft Graph signIn beta (2025-11-27); Azure Monitor SigninLogs (2026-08-27); Entra data retention (2026-01-06); Conditional Access Token Protection (2026-08-14) dan deployment guide Windows (2026-09-21); app credentials (2025-03-26) dan application management policies; Entra audit activity reference; MITRE ATT&CK v20.0 (13 Okt 2026): T1078.004 v2.0, T1550.001 v2.0, T1550.004 v2.0, T1528 v1.5, T1098.001 v2.8, T1539 v1.5, T1548.005 v2.0; AWS CloudTrail userIdentity element; IAM source identity dan role chaining; GuardDuty IAM finding types; CloudTrail Lake (tertutup untuk pelanggan baru sejak 31 Mei 2026); Amazon Athena untuk CloudTrail; Splunk Enterprise 10.6 (SPL)'
---

# Day 17: Hunting identitas dan cloud (sesi yang dipakai ulang, kredensial aplikasi yang menua, dan first-seen di CloudTrail)

Cakupan: menyusun hunt untuk log sign-in Entra ID, audit direktori, dan CloudTrail, dengan fokus pada perilaku yang tidak ditangkap mesin risiko bawaan maupun rule yang sudah ada, di tenant yang hanya berlisensi Entra ID P1.

## Ide inti

Hunting di endpoint punya keuntungan besar: kamu melihat proses, berkas, dan registry, dan perilaku jahat biasanya terlihat ganjil secara teknis. Di identitas dan cloud, hampir semua yang dilakukan penyerang adalah panggilan API yang sah secara teknis, dilakukan oleh identitas yang sah, dengan kredensial atau token yang sah. Tidak ada biner mencurigakan. Yang ada hanya konteks: siapa, dari jaringan mana, dengan sesi dan perangkat apa, kapan, dan seberapa biasa aksi itu bagi identitas tersebut. Karena itu hunt di wilayah ini hampir selalu berbentuk pertanyaan tentang kelangkaan dan perubahan (first-seen, stacking, sesi yang berpindah jaringan), ditambah satu jenis hunt yang jarang ada di endpoint: hunt berbasis keadaan, yaitu memeriksa inventaris aplikasi, kredensial, dan pemiliknya, karena kunci yang terlupa tidak menghasilkan event sampai dipakai.

Sebelum menyusun hunt, ketahui dulu apa yang sudah dikerjakan mesin. Mesin itu adalah deteksi risiko bawaan penyedia (Entra ID Protection, GuardDuty) dan rule SOC sendiri. Isinya sangat bergantung lisensi: di tenant Entra ID P1, sebagian besar deteksi risiko hanya muncul sebagai label umum tanpa rincian, field tingkat risiko di log sign-in berisi `hidden`, dan kebijakan Conditional Access berbasis risiko tidak tersedia. Hunting tidak menggantikan lisensi, tetapi ia satu-satunya cara untuk mengetahui dengan jujur apa yang lolos di antara deteksi yang ada.

Polanya sama dengan membaca log AAA (TACACS+ atau RADIUS) perangkat jaringan. Setiap perintah di router datang dari akun yang lolos autentikasi; penyusup yang memakai akun engineer hanya terlihat dari konteksnya: NAS atau IP sumber yang tidak pernah dipakai akun itu, satu sesi yang tampak dari dua tempat, perintah yang belum pernah dijalankan akun itu, atau akun vendor lama yang ternyata masih aktif. Batas analoginya ada tiga. Di cloud, sebagian besar identitas adalah mesin (service principal, role, pipeline), sehingga "akun yang biasanya dipakai satu orang" tidak berlaku. Token bisa dipakai berhari-hari tanpa login ulang, jadi tidak selalu ada event autentikasi baru yang bisa diperiksa. Dan definisi "sesi" serta "perangkat" ditentukan penyedia, bukan oleh kita, sehingga setiap field perlu diuji dulu perilakunya di data sendiri.

```
 apa yang sudah ditangkap mesin?             sisa yang menjadi wilayah hunt
 -------------------------------             -------------------------------
 Entra ID Protection (P1: label generic) --> sesi berpindah jaringan di luar jendela rule
 rule SOC (session ID > 1 ASN / 24 jam)  --> sign-in berhasil dari user+ASN baru tanpa label
 Conditional Access (CA-10, CA-11)       --> aplikasi dengan secret menua, owner tidak aktif
 GuardDuty (semua region)                --> identitas cloud menjalankan aksi baru; rantai role
          |
          v
 sumber: sign-in Entra (interaktif, non-interaktif) | audit Entra | inventaris (Graph) | CloudTrail
          |
          v
 hasil: insiden (IR) | celah konfigurasi (pemilik sistem) | jinak terkonfirmasi | celah data
```

Situasi Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan, kantor pusat dan data center di Jakarta, dan POP regional di Bandung, Surabaya, dan Medan. PT JAB memakai Microsoft 365 E3 (dengan Entra ID P1), Defender for Office 365 Plan 2, dan Defender for Endpoint Plan 2. Conditional Access tersedia, tetapi kebijakan berbasis risiko tidak, karena butuh Entra ID P2. Status Conditional Access per April 2027: CA-10 (pendaftaran security info hanya dari lokasi tepercaya) dan CA-11 (akun admin wajib metode phishing-resistant dan hanya dari jump host `JKT-JUMP01`) enforce sejak November 2026; CA-12 (Microsoft 365 hanya dari perangkat terkelola) masih report-only karena staf POP memakai perangkat pribadi; CA-13 (token protection) masih pilot. Log sign-in interaktif, sign-in non-interaktif, dan audit Entra dikirim lewat Event Hub ke Splunk index `o365` (sourcetype `azure:monitor:aad`) dengan retensi satu tahun, sedangkan portal Entra hanya menyimpan 30 hari. CloudTrail akun AWS produksi `310582746193` masuk index `aws`, dan Activity Log subscription Azure `JAB-Azure-Prod` masuk index `azure`.

Dua insiden 2026 di wilayah ini paling mahal. Pada `INC-2026-022` (akhir Oktober 2026), session cookie seorang staf IT dicuri lewat halaman phishing adversary-in-the-middle (AiTM), lalu session ID-nya dipakai dari jaringan lain. Pada `INC-2026-025` (30 November sampai 1 Desember 2026), access key IAM `ci-deploy-selfcare` dan secret service principal `sp-selfcare-reporting` bocor lewat repo GitHub pribadi yang publik, lalu dipakai dari luar; sejak itu pipeline GitLab CI memakai federasi OIDC ke AWS dan federated credential ke Entra, tanpa rahasia tersimpan. Program hunt PT JAB berjalan sejak Februari 2027 dengan kamu (analyst L2) sebagai pemegangnya setiap Selasa dan Kamis. Evaluasi kuartal pertama dipresentasikan ke Direktur Teknologi Hendra Wijaya dan SOC lead Dimas Prasetyo pada Rabu 2027-03-31. Selasa 2027-04-06 pukul 08:15, Dimas menulis:

> "Evaluasi Q1 kemarin diterima, tapi Pak Hendra mencatat satu hal: hampir semua hunt Q1 di endpoint, padahal insiden 2026 yang paling mahal justru identitas dan cloud, yaitu sesi yang dipakai ulang di Oktober dan kunci AWS serta secret Azure yang bocor di akhir November. Beliau tanya, apa yang bisa diburu di sana? Kita cuma P1, jadi sebenarnya apa yang sudah ditangkap Entra dan rule kita, dan apa yang tidak? Data apa yang kita punya dan apa yang bolong? Sesi curian seperti INC-2026-022 masih bisa lolos sekarang? Ada sign-in berhasil dari tempat baru yang tidak ditandai apa pun? Setelah kasus secret sp-selfcare-reporting, masih adakah aplikasi lain yang secret-nya dilupakan orang? Di AWS, bagaimana memastikan tidak ada identitas yang berbuat di luar kebiasaannya, termasuk lewat assume-role berantai? Terakhir, jangan sampai staf POP yang pakai hotspot HP dicurigai tiap minggu; mana yang layak jadi rule?"

Pesan itu memuat tujuh pertanyaan:

1. Apa yang sudah ditangkap mesin risiko dan rule SOC di tenant P1, dan apa yang tersisa untuk hunting?
2. Data identitas dan cloud apa yang PT JAB punya, dan apa batasnya?
3. Apakah sesi curian seperti `INC-2026-022` masih bisa lolos dari rule yang ada, dan bagaimana mencarinya?
4. Adakah sign-in berhasil dari tempat baru yang tidak ditandai apa pun?
5. Masih adakah aplikasi atau service principal dengan kredensial yang dilupakan?
6. Bagaimana memastikan identitas AWS tidak berbuat di luar kebiasaannya, termasuk lewat assume-role berantai?
7. Bagaimana menghindari banjir false positive, dan apa yang layak dijadikan rule?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2 dan 2.1, pertanyaan 3 di bagian 1.3 dan 2.2, pertanyaan 4 di bagian 2.3, pertanyaan 5 di bagian 1.3, 2.4, dan 2.5, pertanyaan 6 di bagian 1.4, 2.6, dan 2.7, dan pertanyaan 7 di bagian 1.5, 1.6, dan 2.8. Bagian 2 berisi tiga hunt hari Selasa (`HUNT-2027-029` sampai `HUNT-2027-031`), dan bagian 2.8 memuat laporan ketiganya plus jawaban untuk Dimas.

**Kapan relevan:** saat organisasi memakai identitas cloud dan penyedia cloud publik, terutama setelah insiden kredensial atau token; saat lisensi tidak memberi deteksi risiko yang lengkap dan SOC perlu tahu persis apa yang tidak tertangkap; saat ada aplikasi dan pipeline yang memegang kredensial jangka panjang; dan saat menilai apakah kontrol seperti Conditional Access benar-benar bekerja.
**Kapan bukan jawaban:** saat ada akun yang sedang dikompromikan (revoke sesi, reset, dan scoping adalah IR, walaupun query-nya mirip); saat kategori log yang dibutuhkan tidak diekspor (hasilnya celah data, bukan "tidak ditemukan"); dan saat perilakunya sudah jelas dan berulang, misalnya pemberian peran Global Administrator atau pemakaian akun root AWS, karena pola seperti itu seharusnya sudah menjadi rule, bukan dijalankan ulang sebagai hunt.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (hipotesis, ABLE, baseline, first-seen, prevalence, stacking, celah visibilitas, risk event, positive control) tidak diulang. Tabel ini memuat istilah baru yang dipakai Day ini; kolom kanan memakai padanan dari pekerjaan NOC dan SOC.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Sign-in interaktif | Sign-in saat pengguna memberi faktor autentikasi (password, MFA, biometrik) | Login engineer ke router dengan password dan token |
| Sign-in non-interaktif | Sign-in atas nama pengguna oleh aplikasi atau komponen OS, memakai token tanpa faktor baru | Re-autentikasi otomatis sesi yang masih hidup |
| Session ID (`sessionId`) | Identifier sesi yang dibuat saat sign-in; dipakai lagi oleh sign-in berikutnya dari sesi yang sama | `Acct-Session-Id` di RADIUS accounting |
| Access token dan refresh token | Token berumur pendek untuk mengakses resource, dan token berumur lebih panjang untuk meminta access token baru | Tiket sesi dan hak memperpanjangnya tanpa login ulang |
| Token replay | Token atau cookie sesi curian dipakai dari tempat lain tanpa login ulang | `Acct-Session-Id` yang sama muncul dari dua NAS berbeda |
| AiTM (adversary-in-the-middle) | Halaman phishing yang meneruskan login asli ke penyedia, sehingga penyerang mendapat cookie sesi setelah MFA | Proxy di tengah sesi yang ikut memegang kunci sesinya |
| Conditional Access (CA) | Kebijakan akses Entra berdasarkan pengguna, aplikasi, perangkat, lokasi; bisa enforce atau report-only | ACL dan AAA policy per kelompok pengguna, dengan mode log-only |
| Risk detection | Deteksi risiko Entra ID Protection untuk sign-in atau pengguna; sebagian premium (butuh P2) | Alarm bawaan vendor yang detailnya hanya terbuka di lisensi tertentu |
| ASN | Nomor sistem otonom jaringan asal IP sumber | ASN peer di tabel BGP |
| App registration dan service principal | Objek aplikasi di tenant, dan identitas aplikasi itu yang benar-benar login dan diberi izin | Definisi akun layanan, dan akun layanan yang aktif di perangkat |
| Client secret, sertifikat, federated credential | Tiga jenis kredensial aplikasi: string rahasia, pasangan kunci, atau kepercayaan pada token dari penerbit lain | Community string SNMP, kunci SSH, dan otentikasi lewat server AAA lain |
| Owner aplikasi | Pengguna yang tercatat berhak mengelola app registration | Penanggung jawab akun layanan di inventaris |
| Workload identity | Identitas non-manusia: aplikasi, service principal, managed identity | Akun mesin untuk polling dan otomasi |
| `userIdentity.type` | Jenis identitas pemanggil di CloudTrail (`AssumedRole`, `IAMUser`, `Root`, `AWSService`, ...) | Kolom "jenis akun" di log AAA |
| AssumeRole dan role session | Panggilan STS yang memberi kredensial sementara sebuah role; hasilnya sesi role dengan nama sesi | Login ke akun bersama lewat jump host, dengan label sesi |
| Role chaining | Memakai kredensial sesi role untuk mengasumsikan role lain | Hop SSH berantai dari router ke router |
| `sourceIdentity` | Identitas asal yang dipasang saat assume role, ikut terbawa di sepanjang rantai dan tidak bisa diubah | Username asli yang dibawa ke setiap hop lewat TACACS+ |
| Federasi OIDC (web identity) | Pipeline atau aplikasi menukar token OIDC dari penerbitnya dengan kredensial cloud berumur pendek | Otentikasi perangkat lewat server AAA pusat, bukan password lokal |

### 1.1 Apa yang sudah ditangkap mesin risiko, dan apa artinya di lisensi P1

Pertanyaan pertama Dimas ("kita cuma P1") harus dijawab sebelum hunt apa pun. Di `INC-2026-022`, yang menaikkan kasus adalah rule korelasi SOC sendiri, bukan deteksi Entra. Itu bukan kebetulan, melainkan konsekuensi lisensi.

Entra ID Protection menghasilkan daftar risk detection yang cukup panjang, terbagi menjadi sign-in risk dan user risk, masing-masing dengan `riskEventType` yang muncul di kueri Microsoft Graph [S1]. Tabel berikut memuat yang paling relevan untuk hunter. Baca kolom "Tipe", karena di tenant P1 baris berlabel premium tidak pernah muncul dengan namanya [S1].

| Perilaku | Nama deteksi | `riskEventType` | Waktu hitung | Tipe |
|---|---|---|---|---|
| Lokasi berjauhan dalam waktu mustahil | Atypical travel | `unlikelyTravel` | real-time | Premium |
| Properti sign-in tak dikenal (IP, ASN, perangkat, browser) | Unfamiliar sign-in properties | `unfamiliarFeatures` | real-time | Premium |
| Token dengan ciri tidak wajar, indikasi replay | Anomalous Token | `anomalousToken` | real-time atau offline | Premium |
| Token SAML dari issuer yang diduga dikompromikan | Token issuer anomaly | `tokenIssuerAnomaly` | offline | Premium |
| Password spray yang berhasil memvalidasi password | Password spray | `passwordSpray` | real-time atau offline | Premium |
| Reverse proxy jahat di tengah sesi | Attacker in the Middle | `attackerinTheMiddle` | offline | Premium (M365 E5 dengan EMS E5) |
| Enumerasi direktori lewat Graph API | Suspicious API traffic | `suspiciousAPITraffic` | offline | Premium |
| Kredensial muncul di kebocoran dan cocok dengan hash aktif | Leaked credentials | `leakedCredentials` | offline | Nonpremium |
| IP anonim (Tor, VPN anonim) | Anonymous IP address | `anonymizedIPAddress` | real-time | Nonpremium |
| Pola yang cocok dengan intel Microsoft | Microsoft Entra threat intelligence | `investigationsThreatIntelligence` | real-time atau offline | Nonpremium |
| Salah satu deteksi premium terpicu | Additional risk detected | `generic` | real-time atau offline | Nonpremium |

Empat hal dari daftar itu menentukan arah hunt-mu [S1][S7]:

1. **Sebagian besar butuh P2.** Tanpa P2, deteksi premium muncul sebagai "Additional risk detected" dengan `riskEventType` bernilai `generic`, tanpa rincian [S1]. Di log sign-in, field `riskLevelDuringSignIn`, `riskLevelAggregated`, dan `riskDetail` dikembalikan sebagai `hidden` untuk semua pelanggan selain P2 [S9][S10]. Laporan Risky sign-ins di P1 tidak menampilkan detail atau tingkat risiko, laporan Risk detections tidak punya panel detail, dan kebijakan risiko (sign-in risk dan user risk lewat Conditional Access) tidak tersedia [S7]. Artinya, di PT JAB seluruh baris premium praktis menjadi pekerjaan hunt manual dan rule sendiri; yang tersisa dari mesin adalah "ada sesuatu" tanpa "apa".
2. **Banyak yang dihitung offline.** Deteksi offline tidak muncul seketika, jadi ada jendela waktu yang hanya bisa ditutup dengan hunt atau dengan rule-mu sendiri.
3. **Password spray hanya terpicu bila penyerang berhasil memvalidasi password.** Upaya spray yang gagal tidak menghasilkan deteksi [S1]. Tahap percobaannya adalah wilayah hunt, dan itulah sebabnya hunt atas kegagalan sign-in tetap berharga meskipun mesin risiko aktif. Di PT JAB, jalur ini sudah diburu lewat stacking kode kegagalan per sumber (Day 11 bagian 2.3).
4. **Sebagian deteksi bergantung produk lain.** Beberapa deteksi diambil dari Defender for Cloud Apps atau Defender for Endpoint, dan butuh lisensi produk itu [S1][S7]. Di lingkungan tanpa produk tersebut, deteksi terkait tidak akan pernah muncul.

Catatan soal `unfamiliarFeatures`: Microsoft menyebut ada periode learning mode untuk pengguna baru, dengan durasi dinamis dan minimum lima hari, dan pengguna bisa kembali ke learning mode setelah lama tidak aktif [S1]. Akun yang baru dibuat karena itu adalah titik buta sementara, dan akun baru yang langsung dipakai dari lokasi tak lazim adalah kandidat hunt yang bagus. Microsoft juga menulis bahwa deteksi ini pada sign-in non-interaktif layak diperiksa lebih ketat karena risiko token replay [S1]; di P1, pemeriksaan itu harus kamu lakukan sendiri.

Mesin di sisi AWS adalah GuardDuty, yang di PT JAB sejak `INC-2026-025` aktif di semua region. Finding IAM-nya bersumber dari CloudTrail management event, dan sebagian memakai model machine learning yang menilai pemanggil, lokasi, dan API yang dipanggil untuk menandai panggilan yang anomali [S21]. Satu sifatnya penting untuk hunter: untuk beberapa finding, bila aktivitas dari sumber yang sama berlanjut, model menganggapnya perilaku yang diharapkan dan berhenti membuat finding untuk sumber itu [S21]. Penyerang yang sabar dan konsisten bisa menjadi "normal" di mata model; hunt first-seen dengan baseline yang kamu kendalikan sendiri menutup celah itu.

Mesin ketiga adalah rule SOC PT JAB: rule harian yang menandai satu session ID dari lebih dari satu ASN dalam 24 jam (rule inilah yang memunculkan kasus `INC-2026-022`), rule `JAB - Login Entra dari negara tidak lazim`, dan alert pendaftaran metode MFA dari luar lokasi tepercaya. Kesimpulan untuk Dimas: di P1, "tidak ada label risiko" hampir tidak berarti apa-apa, dan pertanyaan hunt yang tepat adalah "apa yang lolos dari rule kita sendiri", bukan "apa yang lolos dari Entra".

### 1.2 Tiga sumber dan batasnya

Pertanyaan kedua Dimas ("apa yang bolong") dijawab per sumber. Tabel berikut adalah tiga sumber utama; baca kolom "Batas", karena di sana letak sebagian besar kesimpulan yang salah.

| Sumber | Isi | Batas yang harus kamu tahu |
|---|---|---|
| Sign-in log | Hasil autentikasi, lokasi, perangkat, aplikasi, metode, session ID | Terbagi empat: user interaktif, user non-interaktif, service principal, dan managed identity [S5]; non-interaktif bervolume jauh lebih besar dan sering tidak di-onboard |
| Audit log direktori | Perubahan objek: peran, aplikasi, kredensial, owner, kebijakan | Tidak memuat hasil autentikasi, jadi harus dikorelasikan dengan sign-in; hanya memuat perubahan dalam masa simpannya, bukan keadaan saat ini |
| CloudTrail | Panggilan API AWS | Management event (operasi control plane seperti `CreateUser`, `PutBucketPolicy`) dicatat default; data event (operasi atas isi resource, misalnya `GetObject` di S3) harus diaktifkan per trail lewat event selector dan berbiaya tambahan [S6] |

Detail yang mengubah cara menghitung dan membaca:

- **Non-interaktif mencakup refresh token dan SSO.** Contohnya klien yang memakai refresh token untuk mendapat access token, SSO di PC yang Entra joined, dan aplikasi Office kedua yang memakai sesi aplikasi pertama [S8]. Sejak 11 April 2025, sign-in baru yang mendapat refresh token dengan kunci FIDO2 juga dicatat di log non-interaktif [S8].
- **Di portal, sign-in non-interaktif dikelompokkan.** Baris yang identik kecuali waktunya (aplikasi, pengguna, IP, status, dan resource sama) digabung menjadi satu baris dengan kolom jumlah [S8]. Pengelompokan ini adalah tampilan portal; cek di data Splunk-mu apakah ekspor Event Hub mengirim tiap sign-in sebagai event terpisah sebelum menghitung volume.
- **IP pada sign-in non-interaktif confidential client bisa menipu.** Untuk confidential client, IP yang dicatat bukan IP sumber permintaan refresh token, melainkan IP saat token pertama kali diterbitkan [S8]. Sesi yang dipakai ulang lewat klien seperti itu bisa terlihat seolah tidak pernah berpindah jaringan.
- **`correlationId` bukan kunci join antar layanan.** Microsoft menyebut kehadirannya di beberapa log tidak berarti log itu bisa digabung lewat field tersebut [S11]. Satu login bisa menghasilkan beberapa baris (percobaan yang terputus prompt MFA, lalu percobaan yang berhasil), dan setelah login aplikasi terus memperbarui token sebagai sign-in non-interaktif. Untuk hunting, selalu tentukan lebih dulu apakah kamu menghitung peristiwa autentikasi atau menghitung sesi; untuk sesi, pakai `sessionId`.
- **Retensi.** Portal Entra menyimpan audit dan sign-in 30 hari di P1 dan P2, tujuh hari di Free; laporan Risky sign-ins disimpan 30 hari di P1 dan 90 hari di P2 [S12]. Retensi di SIEM yang membuat hunt satu tahun mungkin.

Peta sumber PT JAB per April 2027 ada di tabel berikut. Baca kolom "Tidak ada", karena di sana jawaban "apa yang bolong" untuk Dimas.

| Data | Di mana | Retensi | Tidak ada |
|---|---|---|---|
| Sign-in interaktif dan non-interaktif Entra | `index=o365` sourcetype `azure:monitor:aad` | 1 tahun di Splunk; 30 hari di portal | Sign-in service principal dan managed identity tidak diekspor ke Event Hub; hanya bisa dilihat di portal 30 hari |
| Audit Entra | `index=o365` sourcetype `azure:monitor:aad` | 1 tahun | Keadaan objek saat ini (owner, kredensial yang sudah ada sebelum masa simpan); harus diambil dari Graph |
| CloudTrail akun `310582746193` | Trail multi-region ke bucket `jab-ct-logs-310582746193`, `index=aws` sourcetype `aws:cloudtrail` | Bucket S3 dan retensi index `aws` (cek sebelum memakai rentang panjang) | Data event S3 hanya untuk bucket ekspor; data event resource lain tidak dicatat |
| Activity Log `JAB-Azure-Prod` | `index=azure` lewat Event Hub | Sesuai index `azure` | Resource log storage belum aktif, jadi pembacaan data lewat storage key tidak tercatat |
| GuardDuty | Konsol AWS (tim DevOps) | Sesuai layanan | Finding tidak masuk Splunk |

Tim SOC PT JAB membuat field alias untuk sign-in Entra supaya query tidak bergantung pada struktur JSON add-on: `user` (UPN), `signin_type` (`interactiveUser` atau `nonInteractiveUser`), `app`, `src_ip`, `src_asn`, `session_id`, `device_id`, `auth_req`, `auth_method`, `ca_status`, dan `result_code`; untuk audit `activity`, `initiated_by`, dan `target`. Nama field CloudTrail mengikuti struktur JSON-nya (`eventName`, `userIdentity.type`, `requestParameters.roleArn`). Semua query di bagian 2 memakai asumsi ini.

### 1.3 Pola hunt identitas: sesi, first-seen, dan inventaris yang menua

Pertanyaan ketiga, keempat, dan kelima Dimas berasal dari tiga insiden: sesi curian `INC-2026-022`, sign-in dari tempat yang tidak ditandai, dan secret yang bocor di `INC-2026-025`. Ketiganya turunan dari stacking dan first-seen (Day 05 bagian 1.2 dan 1.3), ditambah satu hunt berbasis keadaan.

- **Stacking properti langka.** Hitung frekuensi ASN, user agent, atau aplikasi per tenant, lalu lihat ekor paling jarang. Yang menarik bukan nilai yang aneh, melainkan nilai jarang yang dipakai akun berhak tinggi.
- **First-seen per pasangan.** Pasangan user dan ASN, user dan aplikasi, atau user dan negara yang baru muncul pertama kali dalam 90 hari.
- **Sign-in non-interaktif yang menyimpang.** Token replay terlihat di sini, bukan di sign-in interaktif, karena sesi curian dipakai tanpa faktor baru. Microsoft sendiri menyebut `unfamiliarFeatures` pada sign-in non-interaktif layak diperiksa lebih ketat karena risiko token replay [S1].
- **Inventaris yang menua.** Aplikasi OAuth tanpa pemilik, service principal dengan kredensial berumur panjang, akun yang tidak pernah dipakai tapi punya peran tinggi. Ini hunt berbasis keadaan, bukan berbasis peristiwa, dan sering memberi temuan paling cepat di hunt pertama.

**Sesi yang dipakai ulang.** Session ID dibuat saat sign-in dan dibawa oleh sign-in berikutnya dari sesi yang sama [S9][S10]. Satu session ID dari dua jaringan berbeda adalah pola reuse yang dipakai rule SOC PT JAB. Rule itu punya dua batas yang menjadi celah hunt. Pertama, jendelanya 24 jam: sesi yang dipakai pengguna di kantor hari Jumat lalu dipakai penyerang dari jaringan lain hari Sabtu tidak pernah menampilkan dua ASN dalam satu jendela. Kedua, ASN saja tidak cukup: penyerang yang memakai proxy residensial di operator yang sama dengan pengguna tidak mengubah ASN, sehingga sinyal lain dibutuhkan, yaitu perangkat (`device_id` yang hilang padahal sesi dimulai dari perangkat terkelola), ASN yang belum pernah dipakai pengguna itu, dan pola perpindahan bolak-balik antara dua jaringan dalam hitungan menit.

Dalam ATT&CK v20, pencurian dan pemakaian dipisah. Mencuri cookie sesi lewat AiTM adalah T1539 Steal Web Session Cookie, dengan contoh alat AiTM open source yang menangkap cookie selama kampanye phishing [S4]. Memakai cookie curian untuk masuk tanpa autentikasi ulang adalah T1550.004 Web Session Cookie, dan memakai token aplikasi curian (termasuk refresh token) adalah T1550.001 Application Access Token; keduanya di taktik Lateral Movement [S22]. Mencuri token aplikasi (misalnya lewat consent aplikasi jahat atau dari pipeline CI/CD) adalah T1528, di taktik Credential Access [S23]. Hunt dari log sign-in hanya melihat tahap pemakaian, karena pencurian terjadi di halaman phishing atau di mesin korban. Karena itu hipotesis `HUNT-2027-029` dipetakan ke T1550.004 dan T1550.001, dengan T1078.004 Cloud Accounts sebagai teknik payung untuk akun cloud yang dipakai penyerang [S4].

**Token protection.** Token Protection adalah session control Conditional Access yang hanya menerima token sesi yang terikat perangkat, seperti Primary Refresh Token (PRT), sehingga token curian tidak bisa dipakai dari perangkat lain [S13]. Fitur ini butuh Entra ID P1 [S13], jadi tersedia untuk PT JAB, dan itulah CA-13 yang sedang dipilot. Batasnya menentukan apakah hunt `HUNT-2027-029` tetap perlu: dukungan umum hanya untuk aplikasi native di Windows, macOS, dan iOS/iPadOS (Outlook, Teams, OneDrive, Word, Excel, PowerPoint, dan beberapa lainnya) terhadap Exchange Online, SharePoint Online, dan Teams; aplikasi berbasis browser belum didukung kecuali preview untuk sebagian aplikasi web Azure Resource Manager [S13]. Cookie yang dicuri AiTM berasal dari sesi browser, jadi pola `INC-2026-022` tidak tertutup oleh CA-13 walaupun nanti enforce. Microsoft juga menyarankan pilot report-only dengan log interaktif dan non-interaktif sebelum enforce, dan field `tokenProtectionStatusDetails` di log sign-in menunjukkan apakah permintaan terikat perangkat [S13].

**Inventaris kredensial aplikasi.** App registration bisa memegang tiga jenis kredensial: sertifikat, client secret, dan federated credential [S14]. Microsoft menyarankan sertifikat atau federated credential untuk produksi dan menyebut client secret kurang aman; secret yang dibuat lewat portal maksimal 24 bulan, dengan saran kedaluwarsa kurang dari 12 bulan, dan nilainya hanya ditampilkan sekali saat dibuat [S14]. Application management policy bisa membatasi penambahan secret dan umur sertifikat untuk aplikasi yang dibuat setelah tanggal tertentu, dengan saran memblokir client secret dan membatasi umur sertifikat 180 hari [S15]; policy itu tidak mengubah aplikasi lama, jadi inventaris tetap dibutuhkan. Penyerang yang menambah kredensial sendiri ke aplikasi atau service principal adalah T1098.001 Additional Cloud Credentials (Persistence dan Privilege Escalation), dan ATT&CK mencatat kredensial seperti itu bisa bertahan setelah password utama direset [S4]. Kredensial yang terlupa adalah kebalikannya: tidak ada yang menambahkannya hari ini, tetapi siapa pun yang menemukan salinannya bisa memakainya.

Dua hal membuat hunt inventaris tidak bisa hanya dari audit log. Pertama, audit hanya memuat perubahan dalam masa simpan, jadi secret yang dibuat sebelum retensi satu tahun tidak punya jejak penciptaannya. Kedua, keadaan owner (apakah akunnya masih aktif) tidak ada di audit. Keadaan diambil dari Graph: properti `passwordCredentials` di objek application dan servicePrincipal memuat `keyId`, `displayName`, `startDateTime`, `endDateTime`, dan `hint` (tiga karakter pertama), sedangkan nilai secret hanya dikembalikan saat dibuat [S17]. Inventaris harus mencakup objek application dan objek service principal, karena kredensial bisa ditambahkan langsung ke service principal tanpa terlihat di halaman App registrations.

### 1.4 Pola hunt cloud: first-seen identitas dan aksi, dan rantai assume-role

Pertanyaan keenam Dimas lahir dari `INC-2026-025`: kunci `ci-deploy-selfcare` dipakai dari luar untuk enumerasi, membuat kredensial sementara, dan menjalankan instance. Pola yang diburu di CloudTrail:

- **First-seen identitas dan aksi.** Pasangan identitas dan `eventName` yang belum pernah terlihat dalam 90 hari. Ini pola tunggal paling produktif di CloudTrail.
- **Rantai assume-role.** Identitas yang mengasumsikan role, lalu dari role itu mengasumsikan role lain. Rantai lebih dari dua lapis jarang sah dan sering menandakan eskalasi.
- **Kredensial yang menganggur lalu hidup.** Access key yang tidak dipakai berbulan-bulan lalu tiba-tiba aktif dari ASN berbeda.
- **Kegagalan izin bertubi-tubi.** `errorCode` bernilai `AccessDenied` dengan banyak `eventName` berbeda dari satu identitas dalam waktu singkat adalah enumerasi, dan tahap ini biasanya mendahului keberhasilan.

**Kunci identitas yang benar.** Elemen `userIdentity` mencatat jenis identitas pemanggil dan kredensial yang dipakai [S18]. Tabel berikut memuat jenis yang paling sering muncul; baca kolom "Kunci untuk first-seen", karena memilih kunci yang salah membuat hunt banjir atau buta [S18].

| `userIdentity.type` | Artinya | Kunci untuk first-seen |
|---|---|---|
| `IAMUser` | Kredensial IAM user | `userIdentity.arn` (stabil per user) |
| `AssumedRole` | Kredensial sementara dari `AssumeRole`, termasuk role instance EC2 | `userIdentity.sessionContext.sessionIssuer.arn` (ARN role). `userIdentity.arn` memuat nama sesi, yang berganti tiap sesi |
| `Root` | Kredensial akun root | Akun; setiap pemakaian layak ditinjau |
| `AWSService` | Panggilan dari layanan AWS atas nama akun | `userIdentity.invokedBy` |
| `SAMLUser`, `WebIdentityUser` | Panggilan `AssumeRoleWithSAML` dan `AssumeRoleWithWebIdentity` | `userIdentity.identityProvider` dan `userName` |
| `FederatedUser` | Kredensial dari `GetFederationToken` | `sessionContext.sessionIssuer.arn` |

Untuk `AssumedRole`, ARN di `userIdentity.arn` berbentuk `arn:aws:sts::<akun>:assumed-role/<role>/<nama sesi>`, dan `principalId` juga memuat nama sesi yang dikirim ke `AssumeRole` [S18]. Role instance EC2 dan job CI memakai nama sesi yang berganti terus, sehingga first-seen dengan kunci `userIdentity.arn` menandai setiap sesi baru sebagai "identitas baru". Kunci yang stabil adalah ARN role di `sessionIssuer`.

**Rantai assume-role.** Role chaining adalah memakai kredensial sesi role untuk mengasumsikan role kedua; sesi hasil rantai dibatasi maksimal satu jam, apa pun durasi maksimum role, dan permintaan `DurationSeconds` lebih dari satu jam pada rantai akan gagal [S20]. Batas ini punya akibat praktis: rantai yang dipakai lama harus mengulang `AssumeRole` setiap jam, sehingga meninggalkan jejak berkala. Di CloudTrail, event `AssumeRole` yang pemanggilnya bertipe `AssumedRole` adalah satu mata rantai; pemanggilnya tercatat di `userIdentity.arn` (sesi role sebelumnya), role tujuan di `requestParameters.roleArn`, dan sesi baru di `responseElements.assumedRoleUser.arn` [S18]. Mata rantai disambung dengan mencocokkan sesi baru dari satu event dengan pemanggil event berikutnya. `roleSessionName` tidak bisa dipakai sebagai benang: nama itu dipilih pemanggil di setiap lapis dan boleh berbeda.

`sourceIdentity` menyelesaikan masalah "siapa sebenarnya di balik rantai". Administrator bisa mewajibkan identitas mengirim string identitas saat assume role; nilai itu muncul di `requestParameters` event STS dan di `sessionContext` setiap panggilan API selama sesi, tetap terbawa saat role chaining, dan tidak bisa diubah selama sesi [S18][S19]. Untuk SAML, nilainya dikirim lewat atribut `https://aws.amazon.com/SAML/Attributes/SourceIdentity`; untuk OIDC, lewat klaim khusus di token [S19]. Tanpa `sourceIdentity`, rantai dari identitas manusia hanya bisa ditelusuri sejauh nama sesi yang dipilih alatnya. Dalam ATT&CK v20, pemakaian kredensial cloud yang sah oleh penyerang adalah T1078.004 [S4], dan permintaan token jangka pendek untuk hak akun lain di AWS disebut di T1550.001 [S22]. T1548.005 Temporary Elevated Cloud Access menyebut just-in-time access, impersonation, dan PassRole, tetapi tidak menyebut AssumeRole atau role chaining [S24], jadi tidak dipakai sebagai pemetaan utama rantai.

**Federasi OIDC sebagai populasi tersendiri.** Pipeline GitLab CI PT JAB menukar token OIDC dengan kredensial role lewat `AssumeRoleWithWebIdentity`. Di CloudTrail, pemanggil event itu bertipe `WebIdentityUser`, dengan `identityProvider` berisi issuer penerbit token [S18]. Identitas ini menjalankan aksi baru setiap kali pipeline berubah, sehingga ia populasi otomasi dengan baseline sendiri (bagian 1.5).

**Alat untuk rentang panjang.** Athena memungkinkan kueri SQL langsung atas berkas log CloudTrail di S3 [S2]. CloudTrail Lake adalah alternatif yang menyimpan event di data lake sehingga kueri lintas akun, region, dan rentang waktu bisa dilakukan dari konsol CloudTrail tanpa Athena [S2][S3]. Sejak 31 Mei 2026, CloudTrail Lake tidak lagi menerima pelanggan baru; pelanggan lama tetap bisa memakainya, dan AWS mengarahkan kebutuhan serupa ke CloudWatch [S3]. Untuk PT JAB dan lab baru, pilihan praktisnya Splunk untuk rentang retensi index `aws`, dan Athena atas bucket trail untuk rentang yang lebih panjang.

### 1.5 Jebakan khas wilayah ini

Pertanyaan terakhir Dimas ("jangan sampai staf POP dicurigai tiap minggu") adalah soal populasi dan sumbu.

Identitas otomasi mendominasi volume. Kalau kamu mengecualikan seluruh identitas otomasi, penyalahgunaannya jadi tak terlihat; kalau tidak mengecualikan apa pun, hasil hunt tenggelam. Jalan tengahnya adalah memperlakukan identitas otomasi sebagai populasi tersendiri dengan baseline sendiri, bukan mengecualikannya. Pipeline OIDC PT JAB, role instance aplikasi self-care, dan service principal pelaporan masing-masing punya pola yang jauh lebih sempit daripada manusia, sehingga aksi baru di sana justru lebih bermakna asalkan dibandingkan dengan riwayat identitas itu sendiri dan dengan jadwal rilis.

Geolokasi IP cukup sering salah, dan VPN perusahaan membuat seluruh organisasi tampak berasal dari satu tempat. Pakai ASN, bukan negara, sebagai sumbu utama bila datanya ada. Di PT JAB ada tiga hal tambahan:

- **NAT kantor.** Semua karyawan kantor Jakarta keluar lewat `198.51.100.120` di ASN PT JAB `64500`. VPN GlobalProtect memakai split tunnel, jadi sign-in dari laptop di luar kantor datang dari jaringan rumah atau seluler pengguna, bukan dari IP PT JAB.
- **Tethering seluler.** Staf POP dan engineer lapangan sering berpindah antara Wi-Fi kantor POP dan hotspot ponsel. Satu sesi bisa berpindah antara `64500` dan ASN operator seluler berkali-kali dalam sehari, dan karena CA-12 masih report-only, perangkat pribadi mereka tidak membawa `device_id`. Pola ini mirip replay di atas kertas.
- **Baseline yang tercemar.** Rentang baseline Desember 2026 sampai Februari 2027 mencakup `INC-2027-001` (Januari 2027), ketika sesi seorang pengguna dipakai dari penyedia VPS. Baris dari IP penyerang harus dibuang dari baseline; bila tidak, ASN penyerang menjadi "dikenal" untuk akun itu.

Pembeda yang dipakai di Day ini, berurutan dari yang paling kuat: ASN bertipe hosting atau VPN komersial; ASN yang belum pernah dipakai akun itu; sesi yang dimulai dari perangkat terkelola lalu muncul tanpa `device_id`; dan perpindahan bolak-balik dalam hitungan menit di dua jaringan yang keduanya tidak dikenal. Tethering staf POP memenuhi syarat ketiga dan keempat sebagian, tetapi tidak dua yang pertama.

### 1.6 Insiden, celah konfigurasi, atau jinak

Hunt identitas punya satu jenis hasil yang jarang muncul di endpoint: celah konfigurasi. Aplikasi dengan secret berumur dua tahun dan owner yang sudah keluar belum tentu pernah disalahgunakan, tetapi ia jelas bukan "tidak ditemukan". Tabel berikut memisahkan tiga label dan penerimanya; baca kolom "Bukti minimum", karena label tanpa bukti itu tidak boleh dipakai.

| Label | Bukti minimum | Penerima |
|---|---|---|
| Insiden (ke IR) | Pemakaian kredensial atau sesi oleh pihak yang tidak berhak: sesi dari jaringan dan perangkat yang tidak bisa dijelaskan pemiliknya, kredensial dipakai dari tempat yang tidak cocok dengan beban kerjanya, atau perubahan yang tidak diakui siapa pun | Dimas sebagai IC |
| Celah konfigurasi | Keadaan yang memudahkan penyalahgunaan tanpa bukti pemakaian jahat: secret melewati standar, owner tidak aktif, izin berlebih, kategori log tidak diekspor | Pemilik sistem atau aplikasi, dengan tenggat |
| Jinak terkonfirmasi | Penjelasan bisnis yang diverifikasi ke pengguna atau pemilik sistem, cocok dengan data (perangkat, aplikasi, jadwal, tiket) | Dicatat di laporan; pola dikenal ditambahkan dengan tanggal review |

Celah konfigurasi tetap memerlukan dua pemeriksaan sebelum diberi label itu: apakah kredensialnya dipakai, dan bila dipakai, apakah dari tempat yang cocok dengan beban kerjanya. Bila pemeriksaan kedua tidak bisa dilakukan karena datanya tidak ada, laporannya menulis bagian itu sebagai data tidak cukup. Hasil hunt inventaris biasanya daftar pekerjaan untuk tim identitas dan pemilik aplikasi, bukan insiden, dan itu hasil yang sah dan sering bernilai tinggi (Day 15 bagian 1.7).

## 2. Contoh dan langkah praktis: tiga hunt identitas dan cloud hari Selasa

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi; ID akun, GUID, nama aplikasi, dan angka dibuat untuk catatan ini. Query ditulis untuk Splunk PT JAB dengan field alias di bagian 1.2; untuk latihan, jalankan versi yang disesuaikan di lab pribadi (bagian 3). Waktu ditulis dalam WIB; Entra dan CloudTrail menyimpan waktu dalam UTC, dan Splunk PT JAB menampilkan `_time` dalam WIB. Semua IP eksternal dari rentang dokumentasi, dan ASN di luar `64500` memakai nomor ASN dokumentasi.

**Lookup bantu:** `jab_asn_ref.csv` (kolom `asn`, `as_name`, `as_type` dengan nilai `corporate`, `mobile`, `residential`, `customer`, `hosting`, `vpn`, `roaming`) dipelihara SOC dari daftar ASN yang pernah ditinjau; `jab_identity.csv` (kolom `account`, `acct_type`) membedakan akun admin, akun layanan, dan akun pengguna.

### 2.1 Cek data: apa yang benar-benar ada di `o365` dan `aws`

Langkah pertama menjawab pertanyaan kedua Dimas dengan angka, sebelum hunt mana pun dirancang. Pemeriksaan ini dibuka pukul 08:40.

**Tujuan:** mengetahui jenis sign-in apa yang diekspor, berapa volumenya, dan seberapa sering field kunci (`session_id`, `device_id`) terisi selama Maret 2027.

```
index=o365 sourcetype=azure:monitor:aad
    earliest="03/01/2027:00:00:00" latest="04/01/2027:00:00:00"
| eval kind=case(isnotnull(signin_type), signin_type, isnotnull(activity), "audit", true(), "lain")
| stats count dc(user) AS users
        sum(eval(if(isnotnull(session_id) AND session_id!="", 1, 0))) AS with_session
        sum(eval(if(isnotnull(device_id) AND device_id!="", 1, 0))) AS with_device
        BY kind
| eval pct_session=round(100*with_session/count, 1), pct_device=round(100*with_device/count, 1)
| table kind count users pct_session pct_device
```

| Bagian | Fungsi |
|---|---|
| `earliest="03/01/2027:00:00:00" latest="04/01/2027:00:00:00"` | Seluruh Maret (31 hari), rentang absolut supaya hasil bisa diulang |
| `eval kind=case(...)` | Sign-in punya `signin_type`; event audit punya `activity`; sisanya dicatat sebagai `lain` supaya kategori tak terduga terlihat |
| `sum(eval(if(...)))` | Menghitung event yang field-nya terisi, tanpa membuang event yang kosong |
| `pct_session`, `pct_device` | Kelengkapan field kunci per jenis (depth, Day 04 bagian 1.3) |

Keluaran ilustrasi:

```
kind                 count      users  pct_session  pct_device
interactiveUser        412.806  1.171         97.2        65.0
nonInteractiveUser   4.196.551  1.163         98.7        72.0
audit                   92.310      -            -           -
```

**Cara membaca hasil:**

- **Total 4.701.667 event, sekitar 151.700 per hari**, sejalan dengan volume `azure:monitor:aad` yang diukur Februari. Non-interaktif sekitar sepuluh kali interaktif, jadi setiap query sesi harus memfilter awal dengan ketat.
- **Tidak ada baris `servicePrincipal` atau `managedIdentity`.** Diagnostic setting hanya mengirim tiga kategori. Hunt `HUNT-2027-030` karena itu tidak bisa melihat kapan dan dari mana aplikasi memakai kredensialnya lewat Splunk; jalurnya hanya portal 30 hari. Ini celah data pertama untuk Dimas.
- **`session_id` hampir selalu ada (97 sampai 99%)**, cukup untuk hunt sesi. Sekitar 1,3% sign-in non-interaktif tanpa session ID tidak tercakup hunt berbasis sesi.
- **`device_id` hanya 65 sampai 72%.** Sisanya perangkat yang tidak terdaftar, terutama ponsel dan perangkat pribadi staf POP. Sinyal "sesi tanpa perangkat" hanya bermakna bila sesi itu dimulai dari perangkat yang biasanya membawa `device_id`.

Pemeriksaan yang sama untuk CloudTrail memakai `| stats count BY userIdentity.type` atas `index=aws sourcetype=aws:cloudtrail` Maret 2027:

```
userIdentity.type   count
AssumedRole         8.911.407
AWSService            489.209
WebIdentityUser         1.288
SAMLUser                  214
```

Total 9.402.118 event. Tidak ada `IAMUser` dan tidak ada `Root`: sejak `ci-deploy-selfcare` dihapus setelah `INC-2026-025`, tidak ada IAM user yang aktif dipakai. Engineer masuk lewat SAML dari Entra ke role, dan pipeline lewat OIDC. Event `IAMUser` atau `Root` di bulan mana pun sejak itu layak ditinjau satu per satu.

**Variasi:** ulangi query Entra dengan `BY kind app` untuk melihat aplikasi mana yang menyumbang sign-in non-interaktif terbanyak; aplikasi itu menjadi kandidat filter awal yang aman.

**Kapan gagal:** add-on menamai jenis sign-in berbeda (misalnya dari field `category` mentah) sehingga semua event jatuh ke `lain`; cek event mentah dan sesuaikan `case()`.

### 2.2 `HUNT-2027-029`: sesi yang dipakai dari lebih dari satu jaringan

Hunt ini menjawab pertanyaan ketiga Dimas: apakah pola `INC-2026-022` bisa lolos dari rule harian yang ada. Abstract-nya ditulis pukul 09:00.

```
ID             : HUNT-2027-029
Dibuat         : 2027-04-06 (Selasa) 09:00, pemilik: <kamu>, reviewer: Dimas Prasetyo
Trigger        : Insiden historis INC-2026-022 dan INC-2027-001 (sesi dipakai ulang dari jaringan lain);
                 celah rule harian session ID > 1 ASN (jendela 24 jam, hanya sumbu ASN)
Tipe (PEAK)    : Hypothesis-driven
Hipotesis      : Ada sesi Entra ID yang, selama Maret 2027, dipakai dari jaringan yang tidak bisa
                 dijelaskan pemiliknya: ASN hosting/VPN, ASN yang belum pernah dipakai akun itu, atau
                 perpindahan bolak-balik antar jaringan, termasuk yang tersebar lintas hari sehingga
                 tidak pernah tampil dua ASN dalam satu jendela 24 jam.
ATT&CK         : T1550.004 Web Session Cookie, T1550.001 Application Access Token (pemakaian);
                 T1078.004 Cloud Accounts; pencurian (T1539, T1528) di luar jangkauan log ini
Data           : index=o365 azure:monitor:aad, sign-in interaktif dan non-interaktif berhasil,
                 Senin 2027-03-01 00:00 sampai Kamis 2027-04-01 00:00 WIB; baseline user+ASN
                 Selasa 2026-12-01 00:00 sampai Senin 2027-03-01 00:00 (tanpa IP penyerang INC-2027-001)
Di luar cakupan: sesi tanpa session_id (sekitar 1,3% non-interaktif); replay lewat ASN yang sama dengan
                 pengguna tanpa sinyal lain; confidential client yang mencatat IP penerbitan awal
Kriteria sukses: Semua sesi yang lolos tahap B ditinjau dan diberi label; positive control INC-2027-001
                 tertangkap
FP diketahui   : Tethering seluler staf POP dan lapangan; perjalanan dinas; pindah ISP rumah
Handover       : IR (Dimas) bila ditemukan; Sari Kusuma untuk usulan laporan/rule
Target selesai : Selasa 2027-04-06
```

Baseline pasangan user dan ASN dibangun lebih dulu, karena tahap B membutuhkannya:

```
index=o365 sourcetype=azure:monitor:aad signin_type IN ("interactiveUser", "nonInteractiveUser")
    result_code=0 earliest="12/01/2026:00:00:00" latest="03/01/2027:00:00:00"
    NOT src_ip="203.0.113.33"
| stats count min(_time) AS first_seen max(_time) AS last_seen BY user src_asn
| outputlookup jab_hunt_baseline_user_asn.csv
```

- 90 hari, berakhir sebelum jendela hunt dimulai (Day 05 bagian 1.2).
- `NOT src_ip="203.0.113.33"` membuang baris dari penyedia VPS yang dipakai penyerang di `INC-2027-001`. Tanpa baris ini, ASN penyerang tercatat "dikenal" untuk akun korban, dan positive control di bawah gagal tanpa ada yang sadar.
- Keluaran ilustrasi: 7.912 pasangan untuk 1.171 akun.

**Tujuan tahap A:** menemukan semua sesi yang muncul dari lebih dari satu ASN selama Maret, lalu memisahkan yang terlihat dalam satu hari (wilayah rule) dari yang hanya terlihat lintas hari (celah rule).

```
index=o365 sourcetype=azure:monitor:aad signin_type IN ("interactiveUser", "nonInteractiveUser")
    result_code=0 earliest="03/01/2027:00:00:00" latest="04/01/2027:00:00:00"
    session_id=* NOT session_id=""
| bin span=1d _time AS day
| stats values(src_asn) AS asns_day dc(src_asn) AS asn_day BY user session_id day
| stats dc(asns_day) AS asn_total max(asn_day) AS max_asn_day dc(day) AS days BY user session_id
| where asn_total > 1
| eval kelas=if(max_asn_day > 1, "dalam_satu_hari", "lintas_hari_saja")
| outputlookup override_if_empty=false jab_hunt_029_sessions.csv
| stats count AS sessions dc(user) AS users BY kelas
```

| Bagian | Fungsi |
|---|---|
| `result_code=0` | Hanya sign-in berhasil; sesi yang gagal tidak memberi akses |
| `session_id=* NOT session_id=""` | Hunt berbasis sesi hanya untuk event yang membawa session ID |
| `bin span=1d` lalu `stats ... BY user session_id day` | Ringkasan per sesi per hari: ASN apa saja di hari itu |
| `stats dc(asns_day) ... max(asn_day)` | `dc()` atas field multivalue menghitung ASN berbeda di seluruh hari; `max_asn_day` adalah ASN terbanyak dalam satu hari |
| `kelas` | `lintas_hari_saja` berarti tidak pernah ada dua ASN di hari yang sama; rule 24 jam hampir pasti tidak melihatnya (hari kalender adalah pendekatan dari jendela 24 jam yang bergulir) |
| `outputlookup override_if_empty=false` | Daftar sesi disimpan untuk tahap B; file lama tidak terhapus bila hasil kosong |

Keluaran ilustrasi:

```
kelas              sessions  users
dalam_satu_hari       1.904    702
lintas_hari_saja        327    211
```

**Cara membaca hasil:** dari 52.906 sesi berhasil di Maret, 2.231 (4,2%) muncul dari lebih dari satu ASN. 327 sesi tidak pernah menampilkan dua ASN di hari yang sama; sesi-sesi itulah yang paling mungkin lolos dari rule harian. Sepanjang Maret, rule itu menghasilkan 23 alert dan semuanya ditutup jinak, 19 di antaranya sesi staf POP yang sama. Jumlah 2.231 terlalu banyak untuk dibaca satu per satu, dan sebagian besar adalah laptop yang dibawa pulang. Tahap B memberi fitur yang membedakan.

**Tujuan tahap B:** memberi setiap sesi kandidat tiga fitur pembeda (tipe ASN, ASN baru untuk akun itu, jumlah perpindahan jaringan), lalu menyisakan yang memenuhi minimal satu.

```
index=o365 sourcetype=azure:monitor:aad signin_type IN ("interactiveUser", "nonInteractiveUser")
    result_code=0 earliest="03/01/2027:00:00:00" latest="04/01/2027:00:00:00"
    [| inputlookup jab_hunt_029_sessions.csv | fields user session_id]
| lookup jab_asn_ref.csv asn AS src_asn OUTPUT as_type
| lookup jab_hunt_baseline_user_asn.csv user src_asn OUTPUT first_seen AS asn_known
| eval asn_baru=if(isnull(asn_known), 1, 0),
       tanpa_device=if(isnull(device_id) OR device_id="", 1, 0)
| sort 0 user session_id _time
| streamstats current=f last(src_asn) AS prev_asn BY user session_id
| eval pindah=if(isnotnull(prev_asn) AND src_asn!=prev_asn, 1, 0)
| stats dc(src_asn) AS asn_count values(src_asn) AS asns values(as_type) AS as_types
        sum(pindah) AS switches max(asn_baru) AS ada_asn_baru
        sum(eval(if(asn_baru=1 AND tanpa_device=1, 1, 0))) AS baru_tanpa_device
        dc(device_id) AS devices values(app) AS apps
        min(_time) AS first max(_time) AS last count BY user session_id
| eval hosting=if(isnotnull(mvfind(as_types, "^(hosting|vpn)$")), 1, 0)
| where hosting=1 OR ada_asn_baru=1 OR switches >= 6
| eval first=strftime(first, "%Y-%m-%d %H:%M"), last=strftime(last, "%Y-%m-%d %H:%M")
| sort - hosting - baru_tanpa_device - switches
```

| Bagian | Fungsi |
|---|---|
| `[\| inputlookup jab_hunt_029_sessions.csv \| fields user session_id]` | Subsearch yang mengubah 2.231 sesi menjadi filter; di bawah batas default subsearch 10.000 hasil |
| `lookup jab_asn_ref.csv ...` | Tipe jaringan per event; ASN yang belum pernah ditinjau tidak punya `as_type` dan tetap terlihat di `asns` |
| `lookup jab_hunt_baseline_user_asn.csv ...` lalu `asn_baru` | Pasangan user dan ASN yang tidak ada di baseline 90 hari |
| `streamstats current=f last(src_asn) ... BY user session_id` | ASN event sebelumnya dalam sesi yang sama, setelah diurutkan waktu |
| `pindah`, `sum(pindah) AS switches` | Berapa kali sesi berpindah jaringan; laptop yang dibawa pulang berpindah satu sampai tiga kali, sesi yang dipakai bersamaan dari dua tempat bolak-balik |
| `baru_tanpa_device` | Event dari ASN baru yang juga tanpa `device_id`, kombinasi paling kuat setelah hosting |
| `mvfind(as_types, "^(hosting\|vpn)$")` | Bernilai indeks bila salah satu tipe ASN hosting atau VPN komersial |
| `where hosting=1 OR ada_asn_baru=1 OR switches >= 6` | Kriteria kandidat. Ambang 6 perpindahan adalah asumsi awal dari distribusi Maret, bukan nilai baku |

Keluaran ilustrasi, diringkas per kelompok dengan `| stats count AS sessions dc(user) AS users max(switches) AS max_sw sum(baru_tanpa_device) AS baru_tanpa_dev BY kelompok` setelah tiap sesi diberi label kelompok saat ditinjau:

```
kelompok                         sessions  users  max_sw  baru_tanpa_dev  hosting
tethering staf POP                     31     17      22               0        0
perjalanan dinas Singapura              8      6       4               0        0
ISP rumah baru (lintas hari)            6      3       1               0        0
```

Satu baris per kelompok, mewakili isinya:

```
user                         asn_count  asns         as_types                switches  ada_asn_baru  devices  apps                         first             last
dedi.siregar@jab.example             2  64500 64510  corporate mobile              22             0        0  Outlook Mobile, Teams        2027-03-15 07:41  2027-03-15 17:58
wahyu.prasetyo@jab.example           2  64508 65541  roaming                       4             1        1  Outlook, Teams, OneDrive     2027-03-15 06:52  2027-03-17 22:35
nanda.putri@jab.example              2  64500 64509  corporate residential         1             1        1  Outlook, Teams               2027-03-19 16:02  2027-03-22 08:47
```

**Cara membaca hasil:** 45 sesi dari 26 akun lolos tahap B, tidak satu pun dari ASN hosting atau VPN komersial, dan tidak ada event dari ASN baru yang sekaligus tanpa perangkat.

- **Tethering staf POP (31 sesi, 17 akun).** Contoh: `dedi.siregar`, teknisi POP Medan, berpindah 22 kali antara `64500` (jaringan POP) dan `64510` (operator seluler) dalam satu hari kerja. Semua sesi dimulai dengan sign-in interaktif dari `64500`, aplikasinya Outlook Mobile dan Teams di ponsel pribadi (tanpa `device_id` karena CA-12 masih report-only), dan ASN seluler sudah ada di baseline akun-akun itu. Tiga pengguna dan manajer POP Medan mengonfirmasi bahwa Wi-Fi POP sering putus dan ponsel otomatis pindah ke data seluler; tiket NOC tentang Wi-Fi POP Medan terbuka sejak Februari. Label: jinak terkonfirmasi.
- **Perjalanan dinas (8 sesi, 6 akun).** Enam karyawan menghadiri forum ISP regional di Singapura 15 sampai 17 Maret. ASN `64508` (operator seluler Singapura, roaming) dan `65541` (jaringan hotel, saat itu belum ada di `jab_asn_ref.csv` sehingga tanpa `as_type`, lalu ditambahkan setelah ditinjau) baru untuk mereka, tetapi `device_id` laptop terkelola tetap ada, sesi diawali sign-in interaktif dengan MFA dari Singapura, dan surat tugas perjalanan cocok dengan tanggalnya. Label: jinak terkonfirmasi. Rule `JAB - Login Entra dari negara tidak lazim` juga sudah memunculkan sign-in interaktif mereka, jadi kelompok ini bukan celah rule.
- **ISP rumah baru (6 sesi, 3 akun), semuanya `lintas_hari_saja`.** Contoh: `nanda.putri` membuka sesi di kantor Jumat sore, lalu memakainya dari `64509` (ISP rumah) Senin pagi. Tiga pengguna baru pindah rumah atau berganti paket internet; perangkatnya sama dengan sesi awal. Label: jinak terkonfirmasi. Kelompok ini menunjukkan bentuk yang lolos dari rule 24 jam, dan bentuk itu yang perlu dijaga.

**Positive control:** tahap A dan B dijalankan ulang pada Jumat 2027-01-08 00:00 sampai Selasa 2027-01-12 00:00, rentang `INC-2027-001`. Sesi `rendra.kusnadi` muncul di urutan teratas: dua ASN, salah satunya bertipe hosting (penyedia VPS `203.0.113.33`), ASN itu baru untuk akunnya karena baris penyerang dibuang dari baseline, dan sesi berlangsung empat hari kalender. Query ini sanggup menangkap pola yang dicari; bila baris `NOT src_ip` di baseline dihapus, `ada_asn_baru` sesi itu menjadi 0 dan ia hanya tertangkap lewat `hosting`.

**Variasi (versi lama yang diperbaiki).** Versi awal hunt ini membandingkan ASN sign-in interaktif dan non-interaktif per akun per hari. Bentuk yang benar memakai tanggal penuh, bukan `date_mday` (angka tanggal yang sama di bulan berbeda tergabung), dan menghitung ASN non-interaktif yang tidak pernah muncul di sign-in interaktif hari itu:

```
index=o365 sourcetype=azure:monitor:aad signin_type IN ("interactiveUser", "nonInteractiveUser")
    result_code=0 earliest="03/01/2027:00:00:00" latest="04/01/2027:00:00:00"
| eval day=strftime(_time, "%Y-%m-%d")
| eval asn_i=if(signin_type="interactiveUser", src_asn, null()),
       asn_n=if(signin_type="nonInteractiveUser", src_asn, null())
| stats values(asn_i) AS asn_interaktif values(asn_n) AS asn_noninteraktif BY user day
| eval asn_hanya_noninteraktif=mvmap(asn_noninteraktif,
        if(isnull(mvfind(asn_interaktif, "^".asn_noninteraktif."$")), asn_noninteraktif, null()))
| where mvcount(asn_hanya_noninteraktif) > 0
```

`mvmap` dan `mvfind` tersedia di Splunk 8.0 ke atas; cek di versi-mu. Hasilnya lebih berisik daripada tahap B (laptop yang hanya sign-in interaktif di kantor lalu non-interaktif di rumah ikut muncul), sehingga dipakai sebagai pembanding, bukan hunt utama.

**Kapan gagal:** penyerang memakai proxy residensial di ASN operator yang sama dengan korban dan meniru user agent; session ID kosong untuk jenis sign-in tertentu; klien confidential mencatat IP penerbitan awal [S8]; atau penyerang memakai refresh token curian untuk membuat sesi baru, sehingga tidak ada session ID yang dibagi dengan pengguna. Kasus terakhir hanya terlihat sebagai sesi baru dari ASN baru, yaitu wilayah bagian 2.3.

### 2.3 `HUNT-2027-029` lanjutan: sign-in berhasil dari pasangan user dan ASN baru

Bagian ini menjawab pertanyaan keempat Dimas dan menutup celah terakhir bagian 2.2. Hipotesisnya: ada sign-in interaktif berhasil dari pasangan user dan ASN yang belum pernah terlihat dalam 90 hari, yang tidak diberi label risiko dan tidak memicu rule SOC.

```
index=o365 sourcetype=azure:monitor:aad signin_type="interactiveUser" result_code=0
    earliest="03/01/2027:00:00:00" latest="04/01/2027:00:00:00"
| lookup jab_hunt_baseline_user_asn.csv user src_asn OUTPUT first_seen AS asn_known
| where isnull(asn_known)
| eval account=mvindex(split(user, "@"), 0)
| lookup jab_identity.csv account OUTPUT acct_type
| lookup jab_asn_ref.csv asn AS src_asn OUTPUT as_type
| eval risk_label=coalesce('properties.riskEventTypes_v2', "none")
| stats count min(_time) AS first values(app) AS apps values(auth_method) AS methods
        values(risk_label) AS risk_labels values(ca_status) AS ca BY user src_asn as_type acct_type
| eval dilabeli=if(mvcount(mvfilter(risk_labels!="none" AND risk_labels!="[]")) > 0, "ya", "tidak")
| eval first=strftime(first, "%Y-%m-%d %H:%M")
```

| Bagian | Fungsi |
|---|---|
| `where isnull(asn_known)` | Pola first-seen 90 hari (Day 05 bagian 1.3) diterapkan ke pasangan user dan ASN |
| `split(user, "@")` lalu `lookup jab_identity.csv` | `jab_identity.csv` memakai nama akun tanpa domain |
| `'properties.riskEventTypes_v2'` | Field mentah daftar risk event di ekspor Azure Monitor [S10]; di P1 nilai yang bisa muncul hanya deteksi nonpremium dan `generic` [S1] |
| `mvfilter(...)` | Menyisakan label selain `none` dan daftar kosong |

Keluaran ilustrasi, diringkas per `as_type`:

```
as_type       pairs  users  dilabeli  admin
mobile           97     84         0      0
residential      89     72         0      0
customer         17     11         0      0
roaming          11      6         2      0
hosting           0      0         0      0
total           214    171         2      0
```

**Cara membaca hasil:**

- **214 pasangan baru dari 171 akun, nol dari ASN hosting, nol untuk akun admin.** Yang ditinjau satu per satu adalah yang paling berisiko: hosting (kosong), luar negeri (11 pasangan, semuanya perjalanan dinas Singapura di bagian 2.2), dan admin (kosong). 203 pasangan domestik seluler, rumah, dan jaringan pelanggan korporat tempat engineer bekerja tidak ditinjau per baris dan ditulis begitu di laporan. Itu keputusan cakupan, bukan klaim bahwa semuanya bersih.
- **Hanya 2 pasangan berlabel, keduanya `generic`.** Itu "Additional risk detected": salah satu deteksi premium terpicu, tetapi P1 tidak memberi tahu yang mana [S1]. Keduanya milik peserta forum Singapura. Label `generic` menyuruh kamu melihat, tetapi tidak memberi alasan untuk menutup atau menaikkan; keputusan tetap dari data sesi.
- **Nol sign-in berhasil akun admin dari ASN baru adalah bukti kontrol bekerja.** CA-11 mewajibkan akun admin masuk dari `JKT-JUMP01` (NAT `198.51.100.120`). Pivot ke sign-in gagal (`result_code!=0`) untuk akun admin menemukan tiga percobaan `adm.taufik` dari `64509` pada Sabtu 2027-03-13 dengan `ca_status=failure`: kebijakan memblokirnya. Taufik mengonfirmasi mencoba membuka portal admin dari rumah untuk tiket mendesak. Label: jinak, dengan catatan edukasi ke Dimas.

**Penyempit yang berguna:** batasi ke akun berperan tinggi lebih dulu. Dijalankan ke seluruh tenant, hunt ini menghasilkan ratusan baris yang sebagian besar adalah orang berganti provider internet.

**Variasi:** ganti `BY user src_asn` dengan `BY user app` untuk first-seen pasangan user dan aplikasi; aplikasi pihak ketiga yang baru muncul untuk satu akun adalah pintu ke pola consent aplikasi seperti `INC-2026-021`.

**Kapan gagal:** nama field risk event di ekspor berbeda (`RiskEventTypes_V2`, atau berupa string JSON); cek bentuknya di event mentah. Baseline yang terlalu pendek (misalnya 30 hari) membuat setiap orang yang kembali dari cuti panjang tampak baru.

### 2.4 `HUNT-2027-030`: inventaris aplikasi dan kredensial yang menua

Hunt ini menjawab pertanyaan kelima Dimas. Pemicunya `INC-2026-025`: secret `sp-selfcare-reporting` berumur panjang tersalin ke repo publik. Abstract-nya ditulis pukul 09:20, dan Lutfi Hakim (Lead DevOps, pemegang proses app registration sejak insiden itu) menjalankan ekspor Graph read-only atas permintaanmu pukul 09:40.

```
ID             : HUNT-2027-030
Dibuat         : 2027-04-06 (Selasa) 09:20, pemilik: <kamu>, reviewer: Dimas Prasetyo
Trigger        : Insiden historis INC-2026-025 (secret service principal bocor); celah: tidak ada
                 inventaris kredensial aplikasi yang ditinjau berkala
Tipe (PEAK)    : Baseline (berbasis keadaan), dilanjutkan hypothesis-driven per aplikasi
Hipotesis      : Ada app registration atau service principal di tenant PT JAB yang memegang client
                 secret masih berlaku dan berumur lebih dari 12 bulan (standar IAM PT JAB sejak
                 Desember 2026) tanpa owner aktif, sehingga kredensial itu bisa dipakai tanpa ada
                 yang menyadarinya.
ATT&CK         : T1098.001 Additional Cloud Credentials (penambahan oleh penyerang);
                 T1078.004 Cloud Accounts (pemakaian kredensial yang ada); T1528 (token dari CI/CD)
Data           : Ekspor Graph application dan servicePrincipal (passwordCredentials, keyCredentials,
                 federatedIdentityCredentials, owners) per 2027-04-06 09:40 sebagai lookup
                 jab_hunt_030_appcreds.csv; audit Entra index=o365 2026-04-06 sampai 2027-04-06;
                 sign-in service principal di portal Entra (30 hari, tidak ada di Splunk)
Di luar cakupan: aplikasi milik tenant lain yang hanya punya service principal tanpa kredensial di
                 tenant PT JAB; pemakaian kredensial lebih dari 30 hari lalu (tidak ada data)
Kriteria sukses: Semua secret yang melewati standar diberi label dan penerima; dua pemeriksaan
                 pemakaian (bagian 2.5) dijalankan untuk aplikasi tanpa owner aktif
Handover       : Lutfi Hakim (proses app registration) dan pemilik aplikasi; IR bila ada indikasi
                 pemakaian tidak sah
Target selesai : Selasa 2027-04-06
```

**Tujuan langkah 1 (audit):** melihat perubahan kredensial dan owner aplikasi selama setahun terakhir, dan siapa yang melakukannya.

```
index=o365 sourcetype=azure:monitor:aad
    earliest="04/06/2026:00:00:00" latest="04/06/2027:00:00:00"
    activity IN ("Update application - Certificates and secrets management",
                 "Add service principal credentials", "Remove service principal credentials",
                 "Add owner to application", "Remove owner from application",
                 "Add owner to service principal", "Remove owner from service principal")
| eval ref=strptime("2027-04-06", "%Y-%m-%d")
| stats count latest(_time) AS last_change values(activity) AS ops
        latest(initiated_by) AS last_actor dc(initiated_by) AS actors BY target
| eval hari_sejak_ubah=round((ref-last_change)/86400, 0)
| eval punya_pemilik=if(match(mvjoin(ops, ","), "Add owner"), "ya", "tidak jelas")
| sort - hari_sejak_ubah
```

| Bagian | Fungsi |
|---|---|
| `activity IN (...)` | Nama aktivitas persis dari referensi audit Entra, kategori ApplicationManagement [S16]. Tanda hubung di "Update application - Certificates and secrets management" adalah tanda hubung biasa |
| `ref=strptime("2027-04-06", ...)` | Tanggal acuan tetap, supaya umur yang dihitung sama bila query diulang besok; versi lama memakai `now()` |
| `stats ... BY target` | Satu baris per aplikasi atau service principal yang diubah |
| `punya_pemilik` | Sengaja bernilai "tidak jelas", bukan "tidak", karena audit hanya memuat perubahan kepemilikan dalam rentang ini. Keadaan sebenarnya dari Graph (langkah 2) |

Keluaran ilustrasi (ringkas):

```
Update application - Certificates and secrets management : 58 event, 21 aplikasi, 6 pelaku
Add service principal credentials / Remove ...            : 0 event
Add owner to application                                  : 37 event
Remove owner from application                             : 12 event
```

**Cara membaca hasil:** 58 perubahan kredensial dalam setahun dari enam pelaku, yaitu Lutfi, Tari Anjani (developer self-care), dua engineer DevOps, `adm.agung`, dan satu admin Infrastruktur lain, semuanya pada jam kerja dan cocok dengan tiket change; termasuk penggantian kredensial `sp-selfcare-reporting` ke federated credential pada 1 Desember 2026. Tidak ada kredensial yang ditambahkan langsung ke service principal, pola T1098.001 yang paling sulit dilihat dari halaman App registrations. Yang tidak bisa dijawab audit: secret mana yang masih berlaku tetapi dibuat sebelum April 2026, dan apakah owner-nya masih aktif.

**Tujuan langkah 2 (keadaan):** dari ekspor Graph, menemukan secret yang masih berlaku, berumur lebih dari 12 bulan, beserta jumlah owner aktifnya.

```
| inputlookup jab_hunt_030_appcreds.csv
| where cred_type="password"
| eval ref=strptime("2027-04-06", "%Y-%m-%d"),
       start_e=strptime(start, "%Y-%m-%dT%H:%M:%SZ"),
       end_e=strptime(end, "%Y-%m-%dT%H:%M:%SZ"),
       umur_hari=round((ref-start_e)/86400, 0),
       sisa_hari=round((end_e-ref)/86400, 0)
| where sisa_hari > 0 AND umur_hari > 365
| stats count AS secrets max(umur_hari) AS umur_maks min(sisa_hari) AS sisa_min
        values(owners) AS owners max(owners_active) AS owners_active values(app_permissions) AS izin
        BY object_type app_name app_id
| sort owners_active - umur_maks
```

| Bagian | Fungsi |
|---|---|
| `cred_type="password"` | Client secret saja; sertifikat dan federated credential dihitung terpisah |
| `start`, `end` | `startDateTime` dan `endDateTime` dari `passwordCredentials`, dalam UTC format ISO 8601 [S17] |
| `sisa_hari > 0 AND umur_hari > 365` | Masih berlaku dan melewati standar 12 bulan, yang sejalan dengan saran Microsoft kurang dari 12 bulan [S14] |
| `object_type` | `application` atau `servicePrincipal`; kredensial di level service principal ikut terlihat |
| `owners_active` | Jumlah owner yang akunnya masih aktif, dihitung saat ekspor |

Keluaran ilustrasi. Inventaris memuat 64 app registration: 27 client secret aktif di 19 aplikasi, 11 sertifikat di 8 aplikasi, dan 6 federated credential di 4 aplikasi; tidak ada secret di level service principal. Enam secret di empat aplikasi melewati standar:

```
object_type  app_name                 secrets  umur_maks  sisa_min  owners                      owners_active  izin
application  JAB-NOC-CapacityExport         1        687        43  bayu.saputra@jab.example                0  Sites.ReadWrite.All (application)
application  JAB-Survey-Connector           2        610       120  -                                       0  User.Read.All (application)
application  JAB-Payroll-SlipSync           1        372       358  2 owner HR                              1  Files.ReadWrite.All (application, site HR)
application  JAB-Billing-Notify             2        401       329  lutfi.hakim, 1 engineer DevOps          2  Mail.Send (application)
```

**Cara membaca hasil:**

- **`JAB-Billing-Notify` dan `JAB-Payroll-SlipSync`** punya owner aktif dan tiket rotasi yang sudah dijadwalkan April. Label: celah konfigurasi kecil, sudah ditangani pemiliknya; dicatat dengan tanggal tiket.
- **`JAB-NOC-CapacityExport`**: secret dibuat 2025-05-19 dengan masa berlaku 24 bulan (maksimum portal [S14]), berakhir 2027-05-19. Owner satu-satunya `bayu.saputra`, mantan engineer NOC yang keluar akhir Oktober 2026; akunnya dinonaktifkan, tetapi kepemilikan aplikasinya tidak pernah dicabut. Izin application `Sites.ReadWrite.All` berarti aplikasi ini bisa membaca dan menulis semua site SharePoint tanpa pengguna. Penciptaan secret-nya tidak ada di audit karena lebih tua dari retensi satu tahun.
- **`JAB-Survey-Connector`**: dua secret dari 2025-08-04, berakhir 2027-08-04, tanpa owner sama sekali. Audit menunjukkan "Remove owner from application" pada 2026-07-14 oleh `adm.agung` saat offboarding staf Marketing; aplikasinya tidak ikut ditinjau. Izin `User.Read.All` application memberi akses baca ke seluruh direktori pengguna.
- **Pembanding positif:** `sp-selfcare-reporting` (appId `8b6e1f42-3c9a-4d7e-a5b2-71c0d9e4f6a3`) kini memegang nol secret dan satu federated credential dengan issuer GitLab internal, sesuai perbaikan pasca-`INC-2026-025`.

Dua aplikasi tanpa owner aktif adalah kandidat temuan. Sebelum diberi label, keduanya diperiksa pemakaiannya (bagian 2.5).

**Variasi:** ganti `cred_type="password"` dengan `cred_type="certificate"` dan ambang 180 hari, sesuai saran umur sertifikat di application management policy [S15]. Tambahkan kolom `hint` (tiga karakter pertama secret [S17]) bila kamu perlu mencocokkan secret yang ditemukan di repo atau berkas konfigurasi dengan entri inventaris tanpa menyalin nilai penuhnya.

**Kapan gagal:** ekspor hanya mengambil objek application, sehingga kredensial di objek service principal tidak terlihat; atau kolom owner hanya berisi ID objek tanpa status akun. Cek isi ekspor sebelum menyimpulkan "tidak ada secret di service principal".

### 2.5 `HUNT-2027-030` lanjutan: apakah kredensial itu dipakai, dan oleh siapa

Pemeriksaan ini adalah syarat label celah konfigurasi di bagian 1.6: apakah kredensial dipakai, dan bila ya, dari tempat yang cocok dengan beban kerjanya.

**Pemeriksaan 1: sign-in service principal (portal, 30 hari).** Karena kategori ini tidak diekspor (bagian 2.1), Lutfi membuka log sign-in service principal di portal Entra untuk Minggu 2027-03-07 sampai Selasa 2027-04-06 dan mengekspornya ke CSV. Field yang dibaca adalah `servicePrincipalCredentialKeyId` (secret mana yang dipakai), `clientCredentialType`, dan IP [S9][S10].

```
app_name                 sign_ins  hari_aktif  ip               clientCredentialType  credential keyId
JAB-NOC-CapacityExport         30          30  198.51.100.130   clientSecret          keyId secret 2025-05-19
JAB-Survey-Connector            0           0  -                -                     -
```

- **`JAB-NOC-CapacityExport`** dipakai sekali sehari sekitar pukul 02:00, selalu dari `198.51.100.130` (NAT data center PT JAB), selalu dengan secret yang sama. Bambang Hartono (Manajer NOC) mengonfirmasi: skrip ekspor laporan kapasitas di `jkt-netops01` mengunggah laporan harian ke site SharePoint NOC, ditulis Bayu tahun 2025, dan tidak ada orang NOC yang tahu skrip itu memakai app registration sendiri. Pemakaiannya cocok dengan beban kerjanya selama 30 hari.
- **`JAB-Survey-Connector`** tidak dipakai sama sekali selama 30 hari. Manajer Marketing menyebut integrasi dengan platform survei vendor itu dihentikan pertengahan 2026.

**Pemeriksaan 2: jejak di Splunk.** Kedua appId (`4c2d8e17-9b3a-4f60-a1d5-7e9b0c3f2a84` untuk `JAB-NOC-CapacityExport`, `a91e5b30-6d2f-4c78-b4e1-0f8c2d7a6b95` untuk `JAB-Survey-Connector`) dicari di `index=azure` (Activity Log, apakah aplikasi punya peran Azure dan pernah dipakai di subscription) dan di `index=o365` (audit atau aktivitas yang dilakukan aplikasi sebagai pelaku):

```
(index=azure OR index=o365) earliest="04/06/2026:00:00:00" latest="04/06/2027:00:00:00"
    ("4c2d8e17-9b3a-4f60-a1d5-7e9b0c3f2a84" OR "a91e5b30-6d2f-4c78-b4e1-0f8c2d7a6b95")
| stats count min(_time) AS first max(_time) AS last BY index sourcetype
```

Keluaran ilustrasi: nol event di `azure` (tidak ada peran Azure) dan hanya event audit perubahan owner di `o365`. Pencarian teks bebas atas appId sengaja dipakai supaya tidak bergantung nama field di dua add-on yang berbeda; harganya lebih lambat, dan rentangnya karena itu dibatasi ke dua appId.

**Hasil `HUNT-2027-030`: DITEMUKAN celah konfigurasi, bukan insiden.** Tidak ada indikasi pemakaian tidak sah dalam 30 hari terakhir; untuk periode sebelum itu, pemakaian kredensial kedua aplikasi tidak bisa diperiksa sama sekali (data tidak cukup), karena sign-in service principal tidak pernah diekspor. Handover pukul 14:30:

- **Ke Bambang (pemilik bisnis `JAB-NOC-CapacityExport`) dan Lutfi:** tetapkan dua owner aktif dari NOC dan DevOps; ganti secret dengan sertifikat (atau managed identity bila skrip dipindah ke Azure) sebelum 2027-05-19, dengan jadwal cutover supaya laporan harian tidak putus; persempit izin dari `Sites.ReadWrite.All` ke site NOC saja; cek salinan secret di `jkt-netops01` dan repositori skrip, lalu hapus setelah rotasi.
- **Ke manajer Marketing dan Lutfi:** konfirmasi tertulis bahwa integrasi berhenti, lalu hapus kedua secret dan nonaktifkan `JAB-Survey-Connector`; hapus aplikasinya setelah 30 hari tanpa keluhan.
- **Ke Lutfi (proses):** offboarding harus memindahkan kepemilikan aplikasi, bukan hanya mencabutnya; application management policy untuk aplikasi baru (blokir client secret, umur sertifikat 180 hari [S15]); inventaris ini dijadwalkan bulanan.
- **Ke Agung Prabowo (telemetri):** tambahkan kategori sign-in service principal dan managed identity ke diagnostic setting Entra yang dikirim ke Event Hub, supaya pertanyaan "dipakai dari mana" bisa dijawab lebih dari 30 hari ke belakang.

**Kapan gagal:** label "celah konfigurasi" ditulis tanpa pemeriksaan pemakaian. Bila sign-in service principal menunjukkan IP di luar data center atau `keyId` yang tidak dikenal, hasilnya bukan celah konfigurasi lagi, dan pekerjaan berpindah ke IR.

### 2.6 `HUNT-2027-031`: first-seen identitas dan aksi di CloudTrail

Hunt ini menjawab pertanyaan keenam Dimas. Abstract-nya ditulis pukul 10:30.

```
ID             : HUNT-2027-031
Dibuat         : 2027-04-06 (Selasa) 10:30, pemilik: <kamu>, reviewer: Dimas Prasetyo
Trigger        : Insiden historis INC-2026-025 (kunci IAM bocor, enumerasi, kredensial sementara);
                 perubahan arsitektur pasca-insiden (OIDC, SAML) belum pernah dibaselinekan
Tipe (PEAK)    : Baseline (first-seen), dilanjutkan hypothesis-driven per identitas
Hipotesis      : Ada identitas di akun AWS 310582746193 yang selama Maret 2027 menjalankan aksi
                 yang belum pernah ia jalankan sejak 2 Desember 2026, atau mengasumsikan role lewat
                 rantai yang tidak sesuai desain, menandakan kredensial dipakai di luar perannya.
ATT&CK         : T1078.004 Cloud Accounts; T1550.001 Application Access Token (token jangka pendek
                 untuk hak role lain)
Data           : index=aws aws:cloudtrail (trail multi-region), baseline Rabu 2026-12-02 00:00 sampai
                 Senin 2027-03-01 00:00 (89 hari, setelah insiden), jendela Senin 2027-03-01 00:00
                 sampai Kamis 2027-04-01 00:00 WIB
Di luar cakupan: data event selain bucket ekspor; akun AWS lain; aktivitas di dalam instance
Kriteria sukses: Semua pasangan identitas dan aksi baru ditinjau; semua rantai AssumeRole dua lapis
                 atau lebih diberi label
FP diketahui   : Rilis aplikasi lewat pipeline; tuning layanan keamanan; latihan responder
Handover       : IR (Dimas) bila ditemukan; Lutfi untuk desain role dan sourceIdentity
Target selesai : Selasa 2027-04-06
```

Baseline dimulai 2 Desember 2026, bukan 1 Desember, karena kunci yang bocor dipakai penyerang pada 1 Desember dini hari dan aktivitas penyerang tidak boleh masuk daftar "normal". Rentang ini masih di dalam retensi index `aws`; cek retensinya sebelum mengulang dengan rentang yang lebih panjang.

```
index=aws sourcetype=aws:cloudtrail
    earliest="12/02/2026:00:00:00" latest="03/01/2027:00:00:00"
| eval ident=coalesce('userIdentity.sessionContext.sessionIssuer.arn', 'userIdentity.arn',
                      'userIdentity.identityProvider', 'userIdentity.invokedBy', 'userIdentity.type')
| stats count min(_time) AS first_seen BY ident eventSource eventName
| outputlookup jab_hunt_baseline_ct_ident_action.csv
```

- `coalesce(...)` memilih kunci identitas yang stabil sesuai tabel bagian 1.4: ARN role untuk sesi role, ARN user untuk IAM user, issuer untuk `WebIdentityUser`, nama layanan untuk `AWSService`.
- `eventSource` ikut menjadi kunci, karena nama aksi yang sama ada di beberapa layanan (misalnya `TagResource`).
- Keluaran ilustrasi: 2.914 kombinasi identitas, layanan, dan aksi.

**Tujuan:** menemukan kombinasi identitas dan aksi di Maret yang tidak ada di baseline.

```
index=aws sourcetype=aws:cloudtrail
    earliest="03/01/2027:00:00:00" latest="04/01/2027:00:00:00"
| eval ident=coalesce('userIdentity.sessionContext.sessionIssuer.arn', 'userIdentity.arn',
                      'userIdentity.identityProvider', 'userIdentity.invokedBy', 'userIdentity.type')
| stats count min(_time) AS first values(sourceIPAddress) AS ips values(awsRegion) AS regions
        values(errorCode) AS errors BY ident eventSource eventName
| lookup jab_hunt_baseline_ct_ident_action.csv ident eventSource eventName OUTPUT first_seen AS known
| where isnull(known)
| eval first=strftime(first, "%Y-%m-%d %H:%M")
| sort ident first
```

| Bagian | Fungsi |
|---|---|
| `eval ident=coalesce(...)` | Kunci yang sama persis dengan baseline; bila berbeda, semua baris tampak baru |
| `values(sourceIPAddress)`, `values(awsRegion)` | Dari mana dan di region mana aksi baru itu terjadi; region selain `ap-southeast-3` langsung menarik |
| `values(errorCode)` | Aksi baru yang ditolak tetap dibaca: percobaan juga jejak |
| `lookup ... OUTPUT first_seen AS known` lalu `where isnull(known)` | First-seen terhadap baseline |

Keluaran ilustrasi: 2.377 kombinasi di Maret, 23 baru dari empat identitas.

```
ident (ARN role, dipendekkan)   baru  contoh eventName                                   first             ips                       regions
role/gitlab-ci-selfcare            9  sqs CreateQueue, SetQueueAttributes, TagQueue;     2027-03-18 14:05  198.51.100.130            ap-southeast-3
                                      kms CreateKey, CreateAlias, PutKeyPolicy, ...
role/SecurityResponder             6  DescribeTrails, GetTrailStatus, GetEventSelectors,  2027-03-10 09:12  198.51.100.120            ap-southeast-3, us-east-1
                                      LookupEvents, GetDetector, ListFindings
role/JAB-DevOps-Admin              5  guardduty UpdateDetector, CreateFilter,            2027-03-09 13:47  198.51.100.120            ap-southeast-3, ap-southeast-1
                                      ListCoverage, GetCoverageStatistics, ...
role/jab-selfcare-app              3  kms GenerateDataKey, Decrypt, DescribeKey          2027-03-18 14:40  10.80.21.14, 10.80.22.9  ap-southeast-3
```

**Cara membaca hasil:**

- **`gitlab-ci-selfcare` (9 aksi baru).** Rilis self-care 3.8 pada Kamis 2027-03-18 14:05 menambah antrean SQS terenkripsi dengan kunci KMS baru. Tari Anjani mengonfirmasi, dan tiket change disetujui Lutfi. IP `198.51.100.130` adalah NAT data center tempat runner GitLab berada. Label: jinak.
- **`jab-selfcare-app` (3 aksi baru)** muncul 35 menit setelah rilis yang sama: role instance aplikasi mulai mengenkripsi pesan dengan kunci itu. Rangkaian waktu pipeline lalu aplikasi itu sendiri adalah konteks yang menguatkan. Label: jinak.
- **`SecurityResponder` (6 aksi baru)** dipakai Rudi Hartanto Rabu 2027-03-10 untuk uji tahunan prosedur responder cloud: membaca konfigurasi trail dan finding GuardDuty. `us-east-1` muncul karena beberapa API global dicatat di region itu; cek perilaku region event global di data-mu. Label: jinak.
- **`JAB-DevOps-Admin` (5 aksi baru)** adalah tuning GuardDuty oleh Lutfi Selasa 2027-03-09, termasuk di `ap-southeast-1`; tiket change ada. Label: jinak.

**Variasi 1, kegagalan izin bertubi-tubi:**

```
index=aws sourcetype=aws:cloudtrail
    earliest="03/01/2027:00:00:00" latest="04/01/2027:00:00:00"
    errorCode IN ("AccessDenied", "Client.UnauthorizedOperation", "UnauthorizedOperation")
| eval ident=coalesce('userIdentity.sessionContext.sessionIssuer.arn', 'userIdentity.arn')
| bin span=1h _time
| stats dc(eventName) AS aksi_ditolak count values(eventName) AS aksi BY ident _time
| where aksi_ditolak >= 10
```

Keluaran ilustrasi: satu baris, `gitlab-ci-selfcare` pada 2027-03-18 jam 14:00 dengan 14 aksi berbeda ditolak. Itu rilis 3.8 yang sama, sebelum policy role diperbarui untuk SQS dan KMS. Polanya identik dengan enumerasi di `INC-2026-025`; pembedanya identitas (pipeline yang dikenal), IP (runner), dan tiket. Nama kode kegagalan berbeda antar layanan AWS; cek nilai `errorCode` yang benar-benar muncul di datamu.

**Variasi 2, Athena untuk rentang di luar retensi Splunk** [S2]:

```sql
WITH baseline AS (
  SELECT coalesce(useridentity.sessioncontext.sessionissuer.arn, useridentity.arn) AS ident,
         eventsource, eventname
  FROM cloudtrail_logs
  WHERE eventtime >= '2026-12-01T17:00:00Z'
    AND eventtime <  '2027-02-28T17:00:00Z'
  GROUP BY 1, 2, 3
),
terbaru AS (
  SELECT coalesce(useridentity.sessioncontext.sessionissuer.arn, useridentity.arn) AS ident,
         eventsource, eventname,
         min(eventtime) AS pertama, count(*) AS jumlah,
         array_agg(DISTINCT sourceipaddress) AS ip_list
  FROM cloudtrail_logs
  WHERE eventtime >= '2027-02-28T17:00:00Z'
    AND eventtime <  '2027-03-31T17:00:00Z'
  GROUP BY 1, 2, 3
)
SELECT t.ident, t.eventsource, t.eventname, t.pertama, t.jumlah, t.ip_list
FROM terbaru t
LEFT JOIN baseline b
  ON b.ident = t.ident AND b.eventsource = t.eventsource AND b.eventname = t.eventname
WHERE b.ident IS NULL
ORDER BY t.jumlah DESC;
```

- Struktur dua CTE memisahkan baseline dari jendela pemeriksaan, sehingga ambang 90 hari bisa diubah tanpa menulis ulang kueri.
- `eventtime` di CloudTrail dalam UTC, jadi batas WIB 00:00 ditulis sebagai 17:00Z hari sebelumnya.
- Kunci identitas memakai ARN role di `sessionissuer`, bukan `useridentity.arn` yang memuat nama sesi. Versi lama kueri ini memakai `useridentity.arn` dan akan menandai setiap sesi role baru sebagai identitas baru.
- **Kapan gagal:** tabel CloudTrail yang tidak dipartisi membuat kueri memindai seluruh bucket dan mahal. Pakai partition projection untuk tabel CloudTrail [S2]. Nama kolom bersarang mengikuti struktur rekaman CloudTrail; verifikasi terhadap tabel yang kamu buat.

**Variasi 3, Azure.** Pola yang sama berlaku untuk Activity Log di `index=azure`: stacking pemanggil (klaim `appid` atau UPN) dan `operationName` terhadap baseline. Di PT JAB nilainya kecil karena hanya `rg-jab-reporting` yang aktif dipakai, tetapi `listKeys` storage account dari pemanggil baru adalah satu baris yang layak dicek setiap bulan, karena itulah jalur data `INC-2026-025` di Azure.

**Kapan gagal:** baseline mencakup periode insiden sehingga aksi penyerang dianggap normal; kunci identitas memakai ARN sesi; atau aksi berbahaya dijalankan sebagai data event yang tidak dicatat (misalnya `GetObject` di bucket selain bucket ekspor).

### 2.7 `HUNT-2027-031` lanjutan: rantai AssumeRole

Bagian kedua pertanyaan keenam Dimas ("assume-role berantai") dijawab dengan menyambung mata rantai lewat ARN sesi, bukan lewat nama sesi (bagian 1.4).

**Tujuan langkah 1:** merangkum semua pemberian kredensial role yang berhasil di Maret, dan memisahkan yang pemanggilnya sudah berupa sesi role (lapis kedua atau lebih).

```
index=aws sourcetype=aws:cloudtrail eventSource="sts.amazonaws.com"
    eventName IN ("AssumeRole", "AssumeRoleWithWebIdentity", "AssumeRoleWithSAML")
    earliest="03/01/2027:00:00:00" latest="04/01/2027:00:00:00"
    NOT errorCode=*
| eval pemanggil_tipe='userIdentity.type',
       pemanggil_sesi='userIdentity.arn',
       pemanggil_role='userIdentity.sessionContext.sessionIssuer.arn',
       role_tujuan='requestParameters.roleArn',
       sesi_baru='responseElements.assumedRoleUser.arn',
       src_identity=coalesce('requestParameters.sourceIdentity',
                             'userIdentity.sessionContext.sourceIdentity')
| fields _time eventName pemanggil_tipe pemanggil_sesi pemanggil_role role_tujuan sesi_baru
         src_identity sourceIPAddress
| outputlookup jab_hunt_031_sts.csv
| stats count values(pemanggil_role) AS dari_role values(sourceIPAddress) AS ips
        dc(src_identity) AS ada_src_identity BY eventName pemanggil_tipe role_tujuan
| sort eventName - count
```

| Bagian | Fungsi |
|---|---|
| `eventName IN (...)` | Tiga cara mendapat kredensial role: dari identitas AWS, dari token OIDC, dan dari assertion SAML |
| `NOT errorCode=*` | Hanya yang berhasil; percobaan yang ditolak dibaca terpisah di variasi 1 bagian 2.6 |
| `pemanggil_sesi` | `userIdentity.arn` pemanggil; untuk lapis kedua, ini ARN sesi role sebelumnya |
| `sesi_baru` | `responseElements.assumedRoleUser.arn`, ARN sesi yang dihasilkan event ini [S18] |
| `src_identity` | `sourceIdentity` di request atau yang terbawa di sesi pemanggil [S18][S19] |
| `outputlookup jab_hunt_031_sts.csv` | Semua event STS disimpan untuk langkah 2 |

Keluaran ilustrasi (ringkas):

```
eventName                   pemanggil_tipe   role_tujuan (dipendekkan)      count  dari_role                    ips                         ada_src_identity
AssumeRole                  AWSService       role/jab-selfcare-app         17.139  -                            ec2.amazonaws.com, ...                     0
AssumeRole                  AssumedRole      role/selfcare-artifact-writer  1.276  role/gitlab-ci-selfcare      198.51.100.130                             0
AssumeRole                  AssumedRole      role/selfcare-db-maint             7  role/JAB-DevOps-Admin        198.51.100.120                             0
AssumeRoleWithSAML          SAMLUser         role/JAB-DevOps-Admin            198  -                            198.51.100.120 + 9 IP lain                 0
AssumeRoleWithSAML          SAMLUser         role/SecurityResponder            16  -                            198.51.100.120                             0
AssumeRoleWithWebIdentity   WebIdentityUser  role/gitlab-ci-selfcare        1.288  -                            198.51.100.130                             0
```

**Tujuan langkah 2:** menemukan rantai tiga lapis atau lebih dengan mencocokkan pemanggil setiap mata rantai ke sesi yang dihasilkan mata rantai sebelumnya.

```
| inputlookup jab_hunt_031_sts.csv
| where pemanggil_tipe="AssumedRole"
| lookup jab_hunt_031_sts.csv sesi_baru AS pemanggil_sesi
         OUTPUT pemanggil_tipe AS induk_tipe pemanggil_role AS induk_role
| eval lapis=if(induk_tipe="AssumedRole", 3, 2)
| stats count BY lapis induk_tipe induk_role pemanggil_role role_tujuan
```

- Pemanggil yang sesinya dibuat oleh `AssumeRole` dari sesi role lain adalah lapis ketiga.
- `induk_tipe` kosong berarti sesi pemanggil dibuat di luar Maret atau oleh mekanisme yang tidak tercatat sebagai event STS ini; baris seperti itu dihitung lapis 2 dan ditinjau manual bila jumlahnya kecil.

Keluaran ilustrasi:

```
lapis  induk_tipe        induk_role  pemanggil_role            role_tujuan                   count
2      WebIdentityUser   -           role/gitlab-ci-selfcare   role/selfcare-artifact-writer  1.276
2      SAMLUser          -           role/JAB-DevOps-Admin     role/selfcare-db-maint             7
```

**Cara membaca hasil:**

- **Nol rantai tiga lapis.**
- **`gitlab-ci-selfcare` ke `selfcare-artifact-writer` (1.276).** Desain pasca-`INC-2026-025`: job pipeline mendapat role pipeline lewat OIDC, lalu role penulis artefak dengan izin per bucket. 1.288 `AssumeRoleWithWebIdentity` dibanding 1.276 mata rantai: 12 job uji tidak membutuhkan role penulis. Semua dari IP runner. Label: jinak, sesuai desain.
- **`JAB-DevOps-Admin` ke `selfcare-db-maint` (7).** Rantai dari identitas manusia, jenis yang paling layak ditinjau. Ketujuhnya cocok dengan tiket pemeliharaan basis data tim Lutfi dan jam kerjanya. Label: jinak. Satu catatan penting: `ada_src_identity` bernilai 0 di semua baris, jadi untuk ketujuh rantai itu siapa orangnya hanya bisa dibaca dari nama sesi SAML di lapis pertama, bukan dari nilai yang terkunci di sepanjang rantai.
- **Batas satu jam.** Sesi `selfcare-db-maint` dari rantai dibatasi satu jam [S20]. Pemeliharaan yang lebih lama terlihat sebagai `AssumeRole` berulang sekitar tiap jam; pola berulang seperti itu di luar jam tiket adalah bentuk yang patut dicurigai.

**Hasil `HUNT-2027-031`: tidak ditemukan.** Rekomendasi ke Lutfi: wajibkan `sourceIdentity` untuk role yang diasumsikan manusia, dengan atribut SAML `https://aws.amazon.com/SAML/Attributes/SourceIdentity` berisi UPN dari Entra [S19], dan tambahkan `sts:SetSourceIdentity` di trust policy role lapis kedua supaya rantai tidak gagal [S19].

**Kapan gagal:** `responseElements` tidak berisi `assumedRoleUser` di sebagian event, atau add-on memotongnya; nama sesi yang sama dipakai ulang sehingga dua sesi berbeda punya ARN yang sama; atau rantai melintas ke akun AWS lain, yang CloudTrail-nya tidak masuk Splunk PT JAB.

### 2.8 Laporan tiga hunt dan jawaban untuk Dimas

Tiga laporan berikut adalah langkah Finalize TaHiTI dan fase Act PEAK untuk Selasa ini.

```
ID            : HUNT-2027-029                        Selesai: Selasa 2027-04-06 15:10
Hasil         : Tidak ditemukan sesi yang dipakai ulang; jinak terkonfirmasi untuk semua kandidat
Cakupan nyata : Sign-in interaktif dan non-interaktif berhasil, 1-31 Mar 2027, 52.906 sesi;
                baseline user+ASN 1 Des 2026 - 1 Mar 2027 (7.912 pasangan, tanpa IP INC-2027-001)
Ambang        : sesi > 1 ASN (2.231; 327 hanya lintas hari); kandidat bila ASN hosting/VPN,
                ASN baru untuk akun, atau >= 6 perpindahan (45 sesi, 26 akun)
Jinak         : tethering staf POP (31 sesi, 17 akun), perjalanan dinas Singapura (8 sesi, 6 akun),
                ISP rumah baru lintas hari (6 sesi, 3 akun); first-seen interaktif 214 pasangan,
                203 domestik tidak ditinjau per baris; 3 sign-in admin dari rumah diblok CA-11
Positive ctrl : Sesi INC-2027-001 tertangkap tahap B (hosting + ASN baru + empat hari)
Di luar cakupan: sesi tanpa session_id; replay lewat ASN yang sama tanpa sinyal lain; confidential
                client yang mencatat IP penerbitan awal; label risiko premium (P1: generic/hidden)
Artefak       : jab_hunt_baseline_user_asn.csv; jab_hunt_029_sessions.csv dihapus setelah laporan
Deteksi       : Usulan laporan mingguan "TH - sesi lintas hari dari ASN baru" ke Sari (bukan alert)
```

```
ID            : HUNT-2027-030                        Selesai: Selasa 2027-04-06 14:30
Hasil         : DITEMUKAN celah konfigurasi (bukan insiden)
Cakupan nyata : 64 app registration dan service principal tenant (ekspor Graph 2027-04-06 09:40);
                audit 6 Apr 2026 - 6 Apr 2027; sign-in service principal portal 7 Mar - 6 Apr 2027
Temuan        : JAB-NOC-CapacityExport (secret 687 hari, owner nonaktif, Sites.ReadWrite.All,
                dipakai harian dari NAT data center); JAB-Survey-Connector (2 secret 610 hari,
                tanpa owner, User.Read.All, tidak dipakai 30 hari)
Lainnya       : 2 aplikasi dengan secret > 12 bulan sudah punya owner aktif dan tiket rotasi;
                0 kredensial di level service principal; sp-selfcare-reporting tanpa secret
Data tidak cukup: pemakaian kredensial > 30 hari lalu (sign-in service principal tidak diekspor)
Handover      : Bambang + Lutfi (CapacityExport), manajer Marketing + Lutfi (Survey-Connector),
                Lutfi (offboarding owner, app management policy, inventaris bulanan),
                Agung (ekspor kategori sign-in service principal dan managed identity)
Deteksi       : Usulan rule "JAB - Kredensial ditambahkan ke aplikasi atau service principal" ke Sari
                (58 event/tahun, sekitar 1 per minggu; pengecualian pelaku dan jam kerja tidak dipakai)
```

```
ID            : HUNT-2027-031                        Selesai: Selasa 2027-04-06 16:20
Hasil         : Tidak ditemukan
Cakupan nyata : CloudTrail akun 310582746193 semua region, 1-31 Mar 2027 (9.402.118 event);
                baseline 2 Des 2026 - 1 Mar 2027 (2.914 kombinasi identitas-layanan-aksi)
Jinak         : 23 aksi baru dari 4 identitas (rilis self-care 3.8, latihan responder, tuning
                GuardDuty); 1 ledakan AccessDenied (rilis 3.8); rantai: 1.276 pipeline OIDC
                (sesuai desain), 7 DevOps ke selfcare-db-maint (tiket); 0 rantai tiga lapis
Di luar cakupan: data event selain bucket ekspor; akun AWS lain; aktivitas di dalam instance
Celah         : sourceIdentity tidak dipakai di role yang diasumsikan manusia -> Lutfi
Deteksi       : Usulan laporan mingguan "TH - aksi baru per identitas AWS" ke Sari (bukan alert)
```

Tabel berikut adalah jawaban yang dikirim ke Dimas Selasa 17:00. Setiap baris merujuk subbagian di atas.

| Pertanyaan Dimas | Jawaban singkat | Dasar |
|---|---|---|
| Apa yang sudah ditangkap di P1 | Deteksi premium hanya muncul sebagai `generic`, field risiko `hidden`, tanpa kebijakan risiko; yang bekerja adalah deteksi nonpremium, rule SOC, CA-10/CA-11, dan GuardDuty | Bagian 1.1 |
| Data yang ada dan yang bolong | Sign-in interaktif, non-interaktif, dan audit 1 tahun; sign-in service principal dan managed identity tidak diekspor; data event S3 hanya bucket ekspor | Bagian 1.2, 2.1 |
| Sesi curian masih bisa lolos? | Rule 24 jam tidak melihat sesi yang berpindah jaringan lintas hari (327 sesi di Maret); hunt 31 hari dengan fitur tambahan tidak menemukan replay, positive control tertangkap | Bagian 1.3, 2.2 |
| Sign-in dari tempat baru tanpa tanda | 214 pasangan baru, nol hosting, nol admin; hanya 2 berlabel `generic`; admin dari rumah diblok CA-11 | Bagian 2.3 |
| Aplikasi dengan secret terlupa | Ya, dua aplikasi tanpa owner aktif; celah konfigurasi, bukan insiden; handover ke pemilik dan Lutfi | Bagian 1.3, 2.4, 2.5 |
| AWS di luar kebiasaan dan rantai role | 23 aksi baru, semuanya rilis atau tugas bertiket; rantai sesuai desain; `sourceIdentity` perlu diwajibkan | Bagian 1.4, 2.6, 2.7 |
| Staf POP dan rule | Tethering dibedakan dengan tipe ASN, ASN baru, dan perangkat; tidak ada alert baru untuk L1, hanya satu rule bervolume rendah dan dua laporan mingguan | Bagian 1.5, 1.6, 2.8 |

Tiga usulan ke Sari Kusuma ditulis dengan alasan volume:

- **"JAB - Kredensial ditambahkan ke aplikasi atau service principal"** (rule): audit `activity` berisi "Update application - Certificates and secrets management" atau "Add service principal credentials". Volume sekitar satu per minggu, setiap event perlu satu pertanyaan ke pelaku, dan pola ini adalah T1098.001 yang paling murah untuk dijaga.
- **"TH - sesi lintas hari dari ASN baru"** (laporan mingguan, bukan alert): tahap A dan B bagian 2.2 dengan rentang tujuh hari. Sebagai alert, kelompok ISP rumah baru akan menjadi tiket jinak setiap minggu.
- **"TH - aksi baru per identitas AWS"** (laporan mingguan): query first-seen bagian 2.6, dengan baseline diperbarui setelah ditinjau. Rilis aplikasi membuat aksi baru hampir setiap minggu, sehingga alert langsung tidak cocok.

Backlog baru dari hari ini: (1) consent pengguna ke aplikasi pihak ketiga (T1528), dari pola `INC-2026-021`; (2) stacking pemanggil `listKeys` storage account di `index=azure` sebagai hunt bulanan.

**Kapan gagal:** jawaban ke Dimas menulis "tidak ada sesi curian" tanpa menyebut 1,3% sesi tanpa session ID dan batas confidential client, atau menulis "aplikasi aman" untuk `JAB-NOC-CapacityExport` hanya karena 30 hari terakhir bersih. Hendra akan membaca keduanya sebagai jaminan yang tidak bisa diberikan datanya.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** tenant Microsoft 365/Entra uji milikmu sendiri (trial, atau tenant developer bila kamu memenuhi syarat programnya; cek syarat terbarunya), dengan diagnostic setting yang mengirim sign-in interaktif, non-interaktif, dan audit ke Event Hub atau storage lalu ke Splunk lab; akun AWS sandbox milikmu dengan satu trail CloudTrail ke S3 (aktifkan data event S3 untuk satu bucket uji bila ingin menguji hunt akses objek); Splunk lab; akses Athena. Sebagai pengganti akun AWS, pakai dataset publik CloudTrail flaws.cloud dari Summit Route: sekitar 1,94 juta event yang sudah dianonimkan, 12 Februari 2017 sampai 7 Oktober 2020, sebagian besar aktivitas serangan terhadap lingkungan latihan [S25]. Karena dataset itu statis, semua query memakai rentang absolut di dalam 2017 sampai 2020. Jangan memakai data, nama, atau kejadian dari pekerjaan nyata; PT JAB hanya contoh fiktif.

1. **Petakan apa yang sudah ditangani mesin.** Daftar `riskEventType` yang muncul di tenant-mu, lalu tandai mana yang premium, mana yang nonpremium, dan mana yang dihitung offline [S1]. Bila tenant uji-mu trial yang membawa P2, catat field apa yang akan `hidden` bila tenant itu P1 [S9][S10]. Hasilnya adalah daftar celah yang menjadi ruang hunt-mu.
2. **Ukur data.** Jalankan query bagian 2.1 dengan rentang absolut sesuai lab. Catat volume interaktif dibanding non-interaktif, persentase `session_id` dan `device_id` terisi, dan kategori yang tidak ada. Angka itu menentukan seberapa agresif kamu harus memfilter di bagian 2.2.
3. **Perilaku session ID.** Masuk ke akun uji dari laptop lab di Wi-Fi rumah, lalu pindahkan laptop yang sama ke hotspot ponsel tanpa logout, dan buka Outlook Web serta OneDrive. Lihat apakah sesi itu membawa session ID yang sama dari dua ASN, dan apakah `device_id` ada. Ulangi keesokan harinya tanpa login ulang. Jangan mengekspor atau memindahkan cookie ke perangkat lain; yang diuji hanya perilaku field pada sesi sah.
4. **Jalankan hunt bagian 2.2** atas data lab: baseline user dan ASN, tahap A, lalu tahap B. Sesi dari langkah 3 harus muncul di tahap A; catat kelas dan jumlah perpindahannya. Bila lab tidak punya sign-in non-interaktif, catat sebagai celah visibilitas, bukan sebagai hunt bersih.
5. **Jalankan hunt bagian 2.3** dua kali: sekali untuk seluruh pengguna, sekali untuk akun berperan tinggi saja. Bandingkan jumlah baris dan waktu yang kamu butuhkan untuk memeriksanya, lalu tulis penyempit mana yang kamu pakai seterusnya.
6. **Inventaris aplikasi.** Buat tiga app registration di tenant uji: satu dengan client secret 6 bulan, satu dengan sertifikat, dan satu dengan client secret tanpa owner (hapus owner setelah dibuat). Ekspor `passwordCredentials`, `keyCredentials`, dan owner lewat Microsoft Graph dengan izin baca saja (cek nama cmdlet atau endpoint di versi modul Graph-mu), simpan sebagai lookup, lalu jalankan query bagian 2.4 dengan ambang yang kamu turunkan, misalnya 0 hari, supaya ketiganya muncul. Jalankan juga query audit bagian 2.4 dan pastikan ketiga pembuatan kredensial tercatat dengan nama aktivitas yang sama [S16].
7. **First-seen CloudTrail.** Buat tabel CloudTrail di Athena dengan partition projection [S2], atau masukkan dataset flaws.cloud ke Splunk lab. Jalankan query bagian 2.6 (Splunk) atau variasi 2 (Athena) dengan baseline 2017-02-12 sampai 2019-12-31 dan jendela 2020-01-01 sampai 2020-10-08. Catat jumlah data yang dipindai dan biayanya bila memakai Athena. Lalu jalankan versi yang memakai `useridentity.arn` sebagai kunci dan bandingkan jumlah kombinasi "baru".
8. **Rantai role.** Di akun sandbox, buat role A dan role B; beri IAM user lab izin assume role A, dan role A izin assume role B. Lakukan rantai lewat AWS CLI, sekali tanpa dan sekali dengan `--source-identity` (tambahkan `sts:SetSourceIdentity` di kedua trust policy [S19]). Coba juga `--duration-seconds 7200` pada lapis kedua dan catat penolakannya [S20]. Jalankan query bagian 2.7 dan pastikan rantai terbaca dua lapis, dengan `sourceIdentity` terbawa di event lapis kedua.
9. **Handover.** Ambil satu hunt yang hasilnya berulang dan dapat dijelaskan, ubah menjadi deteksi atau laporan terjadwal mengikuti Day 14, dan tulis laporan dengan template bagian 2.8, termasuk kategori log yang tidak ada di lab-mu.

**Hasil yang sebaiknya tersimpan:**

- Daftar risk detection di tenant uji beserta celah yang ditinggalkannya bila lisensinya P1.
- Perbandingan volume sign-in interaktif dan non-interaktif, kelengkapan `session_id` dan `device_id`, dan kategori yang tidak diekspor.
- Catatan perilaku session ID saat laptop berpindah jaringan, termasuk keesokan harinya.
- Hasil hunt sesi, first-seen user dan ASN, inventaris aplikasi, first-seen CloudTrail, dan rantai role, masing-masing dengan jumlah baris dan waktu pemeriksaan.
- Perbandingan jumlah kombinasi "baru" dengan kunci `sessionissuer.arn` dan kunci `useridentity.arn`.
- Catatan biaya dan data terpindai untuk kueri Athena.
- Satu hunt yang dinaikkan menjadi deteksi atau laporan, dengan alasannya.

**Variasi tantangan:** ubah ambang `switches >= 6` di bagian 2.2 menjadi 3 dan 10 untuk data lab-mu, lalu catat berapa sesi sah yang ikut dan berapa yang hilang. Tulis rekomendasi ambang beserta alasannya, termasuk pola mana yang tidak akan pernah tertangkap ambang itu.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat menjalankan hunt identitas dan cloud. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Hunt sesi tidak menghasilkan apa pun | Sign-in non-interaktif tidak di-onboard | Jalankan query bagian 2.1; onboard kategori itu bila belum |
| Semua pengguna tampak berasal dari satu ASN | Trafik keluar lewat VPN atau proxy perusahaan | Pakai sumbu lain: aplikasi, perangkat, atau waktu akses; cek konfigurasi split tunnel |
| Ribuan sesi berpindah ASN | Laptop dibawa pulang, tethering | Pakai fitur tahap B (tipe ASN, ASN baru, perpindahan), bukan jumlah ASN saja |
| First-seen menghasilkan ratusan baris tiap hari | Jendela baseline terlalu pendek, atau populasi tidak dipisah | Perpanjang baseline ke 90 hari; pisahkan identitas otomasi sebagai populasi sendiri |
| Positive control tidak tertangkap | Baris penyerang ikut masuk baseline | Buang IP atau sesi insiden dari baseline (bagian 2.2) |
| `riskEventTypes` selalu kosong atau `generic` | Tenant tanpa P2, sehingga detail tidak tersedia | Periksa tingkat lisensi; tanpa P2 deteksi premium muncul sebagai `generic` [S1] |
| Field tingkat risiko berisi `hidden` | Bukan P2 | Perilaku normal di P1 [S9][S10]; jangan dipakai sebagai filter |
| Tidak bisa melihat kapan aplikasi memakai secret-nya | Sign-in service principal tidak diekspor | Portal 30 hari; tambahkan kategori ke diagnostic setting |
| Inventaris tidak menemukan kredensial yang diketahui ada | Ekspor hanya objek application | Ekspor juga objek servicePrincipal |
| Kueri Athena mahal atau lambat | Tabel tidak dipartisi | Pakai partition projection untuk tabel CloudTrail [S2]; batasi rentang `eventtime` |
| Hunt CloudTrail tidak menemukan akses objek | Data event tidak diaktifkan | Periksa event selector di konfigurasi trail; data event harus diaktifkan eksplisit per resource [S6] |
| Setiap sesi role tampak identitas baru | Kunci first-seen memakai `userIdentity.arn` | Pakai `sessionContext.sessionIssuer.arn` (bagian 1.4) |
| Rantai assume-role tidak terbentuk | Disambung lewat `roleSessionName`, atau `responseElements` kosong | Sambung `responseElements.assumedRoleUser.arn` ke `userIdentity.arn` event berikutnya; periksa beberapa event mentah |
| Jumlah sign-in tidak cocok dengan jumlah login | Satu login menghasilkan beberapa baris | Tentukan apakah kamu menghitung peristiwa atau sesi sebelum menghitung apa pun |

## 5. Kesalahan umum dan jebakan

- Membangun ulang hunt untuk perilaku yang sudah ditangkap mesin risiko atau rule SOC, tanpa mengecek daftar deteksinya lebih dulu.
- Menganggap tidak adanya label risiko berarti aman, padahal sebagian deteksi butuh P2, sebagian dihitung offline, dan di P1 field risiko berisi `hidden` [S1][S9].
- Mengira CA-13 (token protection) menutup pola AiTM, padahal dukungan umumnya untuk aplikasi native; sesi browser belum tercakup [S13].
- Memakai negara sebagai sumbu utama padahal geolokasi IP sering salah dan VPN meratakan semuanya.
- Mengecualikan seluruh identitas otomasi, sehingga penyalahgunaannya menjadi titik buta permanen.
- Mencampur sign-in interaktif dan non-interaktif dalam satu perhitungan tanpa memisahkan peristiwa dari sesi.
- Membangun baseline dari periode yang mencakup insiden tanpa membuang baris penyerang.
- Menyimpulkan inventaris aplikasi dari audit log saja; secret yang lebih tua dari retensi tidak punya jejak penciptaan.
- Memberi label "celah konfigurasi" tanpa memeriksa apakah kredensialnya dipakai dan dari mana.
- Menjalankan kueri CloudTrail atas tabel tanpa partisi, lalu menyimpulkan bahwa hunting cloud itu mahal.
- Memakai ARN sesi sebagai kunci first-seen, atau `roleSessionName` sebagai benang rantai role.
- Memperlakukan hunt inventaris sebagai gagal karena tidak menemukan penyerang, padahal hasilnya daftar perbaikan yang nyata.
- Menjalankan hunt yang sama tiap bulan tanpa pernah menaikkannya menjadi deteksi atau laporan terjadwal (Day 14).
- `[komunitas, belum terkonfirmasi]` Praktisi sering menyebut bahwa secret aplikasi bisa dibuat dengan masa berlaku lebih dari 24 bulan lewat API atau PowerShell, berbeda dengan batas portal [S14]. Jangan mengandalkan batas 24 bulan saat menilai inventaris; baca `endDateTime` yang sebenarnya.

## 6. Catatan terkini

Bagian ini menampung detail versi, tanggal, dan perubahan layanan yang tidak mengubah langkah kerja di atas.

- Daftar risk detection Entra ID Protection berubah cukup sering; dokumen yang dirujuk bertanggal 2026-04-22 dan diperbarui 2026-10-15 [S1]. Per versi itu, Atypical travel dihitung real-time (versi lama Day ini menyebutnya offline), dan Attacker in the Middle membutuhkan Microsoft 365 E5 dengan EMS E5. Perbarui pemetaan celah hunt-mu setiap kali daftar itu bertambah, karena setiap deteksi baru berpotensi membuat satu hunt-mu mubazir, atau, di P1, hanya menambah satu kemungkinan arti `generic`.
- Password spray hanya menghasilkan deteksi bila penyerang berhasil memvalidasi password [S1]. Hunt atas percobaan yang gagal karena itu tetap relevan meskipun ID Protection aktif, dan ini pembenaran paling jelas untuk hunt identitas di tenant yang sudah berlisensi penuh.
- Beberapa deteksi Entra bergantung pada produk lain seperti Defender for Cloud Apps atau Defender for Endpoint [S1][S7]. Di lingkungan tanpa produk itu, deteksi terkait tidak akan pernah muncul, dan celahnya harus ditutup hunt atau rule sendiri.
- Token Protection: dokumen konsep diperbarui 2026-08-14 dan deployment guide Windows 2026-09-21; dukungan aplikasi web yang mengakses Azure Resource Manager masih preview, dan perangkat Apple memerlukan Enterprise SSO plug-in dengan perangkat terkelola MDM [S13]. Nilai `enforcedSessionControls` di log sign-in berubah dari `Binding` ke `SignInTokenProtection` pada akhir Juni 2023, jadi query atas data lama perlu mencari keduanya [S13].
- Sejak 11 April 2025, sign-in yang mendapat refresh token dengan kunci FIDO2 dicatat di log non-interaktif [S8]. Hunt yang hanya membaca log interaktif akan melewatkan bagian alur passwordless ini.
- CloudTrail Lake tidak menerima pelanggan baru sejak 31 Mei 2026; pelanggan lama tetap bisa memakainya, dan AWS mengarahkan kebutuhan serupa ke CloudWatch [S3]. Versi lama Day ini menyarankan CloudTrail Lake sebagai alternatif Athena; untuk lab baru, pilihannya Athena atau SIEM.
- ATT&CK v20.0 berlaku sejak 13 Oktober 2026 [S24]. Per v20.0: T1078.004 versi 2.0 dengan taktik Stealth, Persistence, Privilege Escalation, dan Initial Access [S4]; T1098.001 versi 2.8 (diubah 17 September 2026) [S4]; T1539 versi 1.5 [S4]; T1550.001 dan T1550.004 versi 2.0 di Lateral Movement [S22]; T1528 versi 1.5 [S23]; T1548.005 versi 2.0 [S24]. Versi lama Day ini memetakan rantai assume-role ke T1548; halaman T1548.005 tidak menyebut AssumeRole, sehingga pemetaan diganti ke T1078.004 dan T1550.001.
- GuardDuty menambah dan mengganti nama finding dari waktu ke waktu; daftar finding IAM yang dibaca memakai prefix taktik seperti `Stealth:IAMUser/CloudTrailLoggingDisabled` [S21]. Cek daftar terbaru sebelum menulis rule yang bergantung nama finding.

## 7. Cheat sheet

```
PRINSIP   di identitas dan cloud, semua panggilan SAH secara teknis; yang bicara cuma KONTEKS
          hunt = kelangkaan dan perubahan (first-seen, sesi) + KEADAAN (inventaris kredensial)

SEBELUM   cek dulu apa yang sudah ditangkap mesin (riskEventType, GuardDuty, rule SOC)
          P1: premium -> "generic"; riskLevel*/riskDetail = hidden; tanpa kebijakan risiko
          offline = ada jeda; learning mode min 5 hari; spray hanya terpicu kalau password BERHASIL

SUMBER    sign-in (interaktif vs NON-interaktif: pisahkan!) | audit (perubahan, bukan keadaan)
          Graph (keadaan: kredensial, owner) | CloudTrail (management default, data event opt-in)
          cek: sign-in service principal/managed identity diekspor? data event bucket mana?

SESI      session_id dari > 1 ASN; pisahkan dalam_satu_hari vs lintas_hari_saja (celah rule 24 jam)
          fitur: ASN hosting/vpn | ASN baru untuk akun | tanpa device_id | perpindahan bolak-balik
          baseline tanpa IP insiden ; positive control dari insiden lama
          T1539/T1528 = mencuri ; T1550.004/T1550.001 = memakai ; T1078.004 = akun cloud

INVENTARIS secret masih berlaku + umur > standar + owner aktif = 0 -> cek PEMAKAIAN dulu
          application DAN servicePrincipal ; portal secret maks 24 bln, saran < 12 bln ; T1098.001

CLOUDTRAIL kunci identitas: sessionIssuer.arn (role) | arn (IAM user) | identityProvider | invokedBy
          baseline mulai SETELAH insiden ; aksi baru + region + errorCode
          rantai: responseElements.assumedRoleUser.arn == userIdentity.arn event berikutnya
          role chaining maks 1 jam ; sourceIdentity terbawa dan tak bisa diubah

SUMBU     pakai ASN, JANGAN negara (geolokasi meleset, VPN meratakan)
OTOMASI   jangan dibuang; jadikan populasi terpisah dengan baseline sendiri

ALAT      SIEM (cepat, mahal untuk rentang panjang) | Athena (SQL atas S3, WAJIB partition projection)
          CloudTrail Lake: tertutup untuk pelanggan baru sejak 31 Mei 2026

HASIL     insiden (IR) | celah konfigurasi (pemilik, tenggat) | jinak terkonfirmasi | data tidak cukup
KELUAR    hunt yang berulang dan bisa dijelaskan -> rule atau laporan terjadwal (Day 14)
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Sign-in `wahyu.prasetyo` dari Singapura tidak punya `riskLevelDuringSignIn` selain `hidden`, jadi Entra menilai sign-in itu tidak berisiko." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Di tenant P1, `riskLevelDuringSignIn`, `riskLevelAggregated`, dan `riskDetail` dikembalikan sebagai `hidden` untuk semua sign-in, berisiko atau tidak; detailnya hanya tersedia untuk P2. Deteksi premium yang terpicu muncul sebagai `generic` tanpa rincian, dan dua sign-in peserta forum Singapura memang berlabel `generic`. Nilai `hidden` karena itu tidak membawa informasi, dan keputusan harus diambil dari data sesi: perangkat, MFA, ASN, dan konfirmasi perjalanan. Lihat bagian 1.1 dan 2.3.

</details>

**2. Skenario keputusan.** Tahap B menandai sesi teknisi POP Medan yang berpindah 22 kali antara `64500` dan operator seluler `64510` dalam sehari, tanpa `device_id`. Langkah mana yang paling tepat?

- A. Nyatakan insiden dan revoke sesi, karena perpindahan bolak-balik tanpa perangkat adalah pola replay.
- B. Periksa apakah sesi dimulai dengan sign-in interaktif dari jaringan POP, apakah ASN seluler sudah ada di baseline akun itu, dan aplikasi apa yang dipakai; konfirmasi ke pengguna dan manajer POP, lalu catat pola ini sebagai jinak dengan tanggal review.
- C. Keluarkan semua ASN operator seluler dari hunt supaya kandidat seperti ini tidak muncul lagi.

<details><summary>Jawaban</summary>

B. Tethering memenuhi sebagian pembeda (perpindahan, tanpa perangkat karena CA-12 masih report-only), tetapi tidak memenuhi dua yang paling kuat: ASN hosting atau VPN, dan ASN yang baru untuk akun itu. Bukti tambahan (sign-in awal dari POP, aplikasi ponsel yang sama, konfirmasi pengguna dan tiket Wi-Fi POP) membuat label jinak bisa dipertanggungjawabkan. A keliru karena satu sinyal tidak cukup untuk menyatakan insiden, dan revoke tanpa dasar mengganggu staf lapangan. C keliru karena penyerang dengan proxy residensial atau seluler justru akan bersembunyi di ASN seperti itu. Lihat bagian 1.5 dan 2.2.

</details>

**3. Pertanyaan jebakan.** "PT JAB sudah punya rule harian yang menandai session ID dari lebih dari satu ASN, jadi `HUNT-2027-029` hanya mengulang rule." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Rule itu memakai jendela 24 jam, sehingga sesi yang dipakai pengguna di satu hari lalu dari jaringan lain di hari berikutnya tidak pernah menampilkan dua ASN dalam satu jendela; di Maret ada 327 sesi seperti itu. Rule itu juga hanya memakai sumbu ASN, sedangkan hunt menambah tipe ASN, ASN baru untuk akun, perangkat, dan pola perpindahan. Hunt juga membawa positive control dari `INC-2027-001` dan baseline yang sudah dibersihkan dari IP penyerang. Lihat bagian 1.3 dan 2.2.

</details>

**4. Skenario keputusan.** Inventaris menemukan `JAB-NOC-CapacityExport`: secret berumur 687 hari, owner tunggal sudah nonaktif, izin `Sites.ReadWrite.All`, dan sign-in service principal 30 hari terakhir menunjukkan pemakaian harian dari NAT data center. Langkah mana yang paling tepat?

- A. Hapus secret saat itu juga supaya risikonya hilang.
- B. Nyatakan insiden karena aplikasi tanpa owner dipakai setiap hari.
- C. Labeli sebagai celah konfigurasi, tulis bahwa pemakaian lebih dari 30 hari lalu tidak bisa diperiksa, lalu handover ke pemilik bisnis dan Lutfi: dua owner aktif, rotasi ke sertifikat dengan jadwal cutover, persempit izin, dan ekspor sign-in service principal ke Splunk.

<details><summary>Jawaban</summary>

C. Pemakaiannya cocok dengan beban kerjanya (skrip laporan harian NOC, satu IP data center, secret yang sama), jadi tidak ada indikasi pemakaian tidak sah, tetapi keadaan aplikasinya jelas di bawah standar. Celah data di luar 30 hari wajib ditulis supaya label ini tidak dibaca sebagai jaminan. A keliru karena skrip NOC akan berhenti tanpa pengganti, dan pemilik bisnisnya baru tahu saat laporan hilang. B keliru karena pemakaian rutin oleh beban kerja yang dikenal bukan bukti pemakaian oleh pihak yang tidak berhak; insiden butuh bukti seperti IP atau `keyId` yang tidak cocok. Lihat bagian 1.6, 2.4, dan 2.5.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Lutfi Hakim, dalam tiga kalimat, kenapa rantai assume-role tidak bisa ditelusuri lewat `roleSessionName` dan kenapa `sourceIdentity` perlu diwajibkan.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Nama sesi dipilih oleh pemanggil di setiap lapis, jadi lapis pertama dan lapis kedua bisa punya nama yang sama sekali berbeda; yang benar-benar menyambung adalah ARN sesi yang dihasilkan satu `AssumeRole` dan muncul sebagai pemanggil `AssumeRole` berikutnya. Itu cukup untuk menggambar rantainya, tetapi tidak menjawab siapa orangnya, karena di lapis kedua yang tercatat hanya sesi role, dan di bulan Maret ketujuh rantai `JAB-DevOps-Admin` ke `selfcare-db-maint` hanya bisa ditebak dari nama sesi SAML di lapis pertama. Kalau `sourceIdentity` diwajibkan lewat atribut SAML berisi UPN, nilainya ikut terbawa ke setiap lapis dan setiap panggilan API, dan tidak bisa diubah selama sesi, jadi satu filter sudah menjawab siapa di balik aksi apa pun."

Kesalahan yang sering muncul:
- Menyebut `sourceIdentity` bisa diubah di tengah rantai, padahal nilainya terkunci selama sesi.
- Lupa bahwa trust policy role lapis kedua juga butuh `sts:SetSourceIdentity`, sehingga rantai gagal setelah kewajiban diterapkan.
- Menjelaskan dengan `userIdentity.arn` lapis pertama saja, tanpa menyebut sambungan lewat `responseElements.assumedRoleUser.arn`.

</details>

**6. Pertanyaan jebakan.** "Untuk first-seen identitas dan aksi di CloudTrail, `userIdentity.arn` adalah kunci identitas yang paling tepat karena unik per pemanggil." Benarkah?

<details><summary>Jawaban</summary>

Tidak untuk sesi role. Untuk `AssumedRole`, `userIdentity.arn` memuat nama sesi, dan nama sesi role instance EC2 atau job CI berganti terus, sehingga setiap sesi baru tampak sebagai identitas baru dan hunt banjir. Kunci yang stabil adalah ARN role di `userIdentity.sessionContext.sessionIssuer.arn`; `userIdentity.arn` tetap tepat untuk IAM user, sedangkan `WebIdentityUser` dan `AWSService` memakai issuer dan nama layanan. Baseline juga harus dimulai setelah insiden, seperti 2 Desember 2026 di PT JAB, supaya aksi penyerang tidak menjadi normal. Lihat bagian 1.4 dan 2.6.

</details>

**7. Interview question (English).** "How would you hunt for token or session replay in Microsoft Entra ID when you don't have ID Protection P2?"

<details><summary>Sample answer</summary>

"I'd start by being honest about what the tenant gives me. Without P2, premium detections only show up as a generic 'additional risk' label and the risk level fields come back hidden, so the absence of a risk label tells me almost nothing. The data I rely on is the sign-in logs, both interactive and non-interactive, exported to the SIEM with a long retention. Replay shows up in the non-interactive logs, because the stolen session is reused without a new factor. I group sign-ins by session ID over a whole month, not a 24-hour window, because a session reused the next day never shows two networks in one day. Then I add features that separate travel from theft: whether any network is a hosting or commercial VPN ASN, whether the ASN is new for that user against a 90-day baseline that I've cleaned of known incident traffic, whether the device ID disappears, and whether the session flips back and forth between networks within minutes. Mobile tethering and business travel are the usual false positives, so I confirm with device, app and the user. I always run a positive control from a past incident to prove the query catches the pattern, and I document what I can't see, like sessions without a session ID or confidential clients that log the original IP."

What makes this answer strong: it starts from licensing reality instead of assuming risk labels, explains why non-interactive logs and a longer window matter, uses multiple distinguishing features rather than ASN alone, and proves coverage with a positive control while stating the blind spots.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Microsoft Entra ID Protection: What are risk detections? | https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks | primer | ms.date 2026-04-22, diperbarui 2026-10-15; dilihat 2026-10-09, dicek ulang 2026-10-18 | Tinggi. Daftar sign-in risk dan user risk beserta `riskEventType`, real-time atau offline, premium atau nonpremium, `generic` untuk Free/P1, learning mode minimum lima hari, password spray hanya terpicu saat validasi password berhasil, catatan non-interaktif dan token replay |
| S2 | Amazon Athena User Guide: Query AWS CloudTrail logs | https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html | primer | dilihat 2026-10-09, dicek ulang 2026-10-18 | Tinggi. Kueri SQL atas log di S3, partition projection untuk tabel CloudTrail, dan CloudTrail Lake sebagai alternatif lintas akun tanpa Athena |
| S3 | AWS CloudTrail Lake dan CloudTrail Lake availability change | https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-lake.html ; https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-lake-service-availability-change.html | primer | dirujuk 2026-10-09; dicek ulang 2026-10-18 | Tinggi. Posisi CloudTrail Lake sebagai event data store yang bisa dikueri dari konsol; tertutup untuk pelanggan baru sejak 31 Mei 2026, migrasi ke CloudWatch |
| S4 | MITRE ATT&CK: T1078.004 Valid Accounts (Cloud Accounts), T1539 Steal Web Session Cookie, T1098.001 Additional Cloud Credentials | https://attack.mitre.org/techniques/T1078/004/ ; https://attack.mitre.org/techniques/T1539/ ; https://attack.mitre.org/techniques/T1098/001/ | primer | dirujuk 2026-10-09; dicek ulang 2026-10-18 (konten v20.0) | Tinggi. T1078.004 v2.0 (diubah 2026-05-12, taktik Stealth, Persistence, Privilege Escalation, Initial Access, DET0546); T1539 v1.5 (AiTM proxy, DET0509); T1098.001 v2.8 (diubah 2026-09-17, kredensial ke service principal dan aplikasi, DET0531) |
| S5 | Microsoft Learn: Sign-in logs in Microsoft Entra ID | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins | primer | ms.date 2025-11-07; dilihat 2026-10-10, dicek ulang 2026-10-18 | Tinggi untuk empat jenis sign-in log (user interaktif, user non-interaktif, service principal, managed identity) |
| S6 | AWS CloudTrail User Guide: Logging data events | https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html | primer | dilihat 2026-10-10 | Tinggi untuk perbedaan management event dan data event, event selector, dan biaya data event |
| S7 | Microsoft Learn: What is Microsoft Entra ID Protection? (license requirements) | https://learn.microsoft.com/en-us/entra/id-protection/overview-identity-protection | primer | ms.date 2025-10-30; diakses 2026-10-18 | Tinggi. Tabel kemampuan Free, P1, P2: kebijakan risiko hanya P2; Risky sign-ins dan Risk detections terbatas di P1; produk Defender pemilik sinyal |
| S8 | Microsoft Learn: Non-interactive sign-in logs | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-noninteractive-sign-ins | primer | ms.date 2026-02-09; diakses 2026-10-18 | Tinggi. Contoh sign-in non-interaktif, pengelompokan di portal, IP confidential client, FIDO2 sejak 11 April 2025 |
| S9 | Microsoft Graph beta: signIn resource type | https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-beta | primer | ms.date 2025-11-27; diakses 2026-10-18 | Tinggi. `sessionId`, `isInteractive`, `signInEventTypes`, `autonomousSystemNumber`, `clientCredentialType`, `servicePrincipalCredentialKeyId`, `tokenProtectionStatusDetails`; field risiko `hidden` tanpa P2 |
| S10 | Microsoft Learn: Azure Monitor Logs reference, SigninLogs | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs | primer | ms.date 2026-08-27; diakses 2026-10-18 | Tinggi. Kolom `SessionId`, `AutonomousSystemNumber`, `ClientCredentialType`, `RiskEventTypes_V2`, `RiskLevelDuringSignIn` (hidden tanpa P2) pada ekspor Azure Monitor |
| S11 | Microsoft Learn: monitoring and health activity log schemas | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-activity-log-schemas | primer | ms.date 2025-05-27; diakses 2026-10-18 | Tinggi. `correlationId` bukan kunci join antar layanan; nilai `hidden` tanpa lisensi; field utama audit (`activityDisplayName`, `initiatedBy`, `targetResources`) |
| S12 | Microsoft Learn: Microsoft Entra data retention | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-reports-data-retention | primer | ms.date 2026-01-06; diakses 2026-10-18 | Tinggi. Audit dan sign-in 7 hari (Free), 30 hari (P1, P2); Risky sign-ins 30 hari (P1), 90 hari (P2) |
| S13 | Microsoft Learn: Token Protection in Conditional Access, dan Token Protection deployment guide Windows | https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-token-protection ; https://learn.microsoft.com/en-us/entra/identity/conditional-access/deployment-guide-token-protection-windows | primer | ms.date 2026-08-14 dan 2026-09-21; diakses 2026-10-18 | Tinggi. Token terikat perangkat, platform dan resource yang didukung, browser belum didukung kecuali preview ARM, lisensi P1, rollout report-only, field `tokenProtectionStatusDetails`, perubahan `Binding` ke `SignInTokenProtection` |
| S14 | Microsoft Learn: Add and manage app credentials in Microsoft Entra ID | https://learn.microsoft.com/en-us/entra/identity-platform/how-to-add-credentials | primer | ms.date 2025-03-26, diperbarui 2026-06-15; diakses 2026-10-18 | Tinggi. Sertifikat, client secret, federated credential; secret portal maksimal 24 bulan, saran kurang dari 12 bulan, nilai hanya tampil sekali; secret tidak disarankan untuk produksi |
| S15 | Microsoft Learn: Enforce secret and certificate standards using application management policies | https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/tutorial-enforce-secret-standards | primer | ms.date 2024-03-12, diperbarui 2026-06-15; diakses 2026-10-18 | Tinggi. Pembatasan `passwordAddition`, umur sertifikat 180 hari, `restrictForAppsCreatedAfterDateTime` (aplikasi lama tidak terpengaruh); syarat lisensi tidak tercantum di halaman ini |
| S16 | Microsoft Learn: Microsoft Entra audit log activity reference | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities | primer | ms.date 2025-03-25, diperbarui 2026-06-15; diakses 2026-10-18 | Tinggi. Nama aktivitas ApplicationManagement: "Update application - Certificates and secrets management", "Add service principal credentials", "Add owner to application", dan lainnya |
| S17 | Microsoft Graph v1.0: passwordCredential resource type | https://learn.microsoft.com/en-us/graph/api/resources/passwordcredential?view=graph-rest-1.0 | primer | ms.date 2024-07-29; diakses 2026-10-18 | Tinggi. `keyId`, `startDateTime`, `endDateTime`, `hint` tiga karakter, `secretText` hanya saat dibuat; properti di application dan servicePrincipal |
| S18 | AWS CloudTrail User Guide: CloudTrail userIdentity element | https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html | primer | diakses 2026-10-18 | Tinggi. Nilai `type`, `arn` dan `principalId` memuat nama sesi, `sessionContext.sessionIssuer`, `invokedBy`, `SAMLUser` dan `WebIdentityUser`, lokasi `sourceIdentity` di request, response, dan sesi |
| S19 | AWS IAM User Guide: Monitor and control actions taken with assumed roles (source identity) | https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html | primer | diakses 2026-10-18 | Tinggi. Source identity terbawa saat role chaining dan tidak bisa diubah; `sts:SetSourceIdentity` di trust policy; atribut SAML dan klaim OIDC |
| S20 | AWS IAM User Guide: IAM roles, terms and concepts (role chaining) | https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html | primer | diakses 2026-10-18 | Tinggi. Definisi role chaining; sesi rantai maksimal satu jam; `DurationSeconds` lebih dari satu jam pada rantai gagal |
| S21 | Amazon GuardDuty User Guide: IAM finding types | https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html | primer | diakses 2026-10-18 | Tinggi. Daftar finding IAM, sumber CloudTrail management event, model ML anomali, perilaku "berhenti membuat finding" untuk sumber yang terus berulang |
| S22 | MITRE ATT&CK: T1550.001 Application Access Token dan T1550.004 Web Session Cookie | https://attack.mitre.org/techniques/T1550/001/ ; https://attack.mitre.org/techniques/T1550/004/ | primer | v2.0, diubah 2026-05-12; konten v20.0; diakses 2026-10-18 | Tinggi. Pemakaian token aplikasi dan cookie sesi curian, taktik Lateral Movement, DET0185 dan DET0074 |
| S23 | MITRE ATT&CK: T1528 Steal Application Access Token | https://attack.mitre.org/techniques/T1528/ | primer | v1.5, diubah 2026-05-12; diakses 2026-10-18 | Tinggi. Consent aplikasi jahat, token di CI/CD, IMDS, refresh token; DET0515 |
| S24 | MITRE ATT&CK: T1548.005 Temporary Elevated Cloud Access, dan Versions of ATT&CK | https://attack.mitre.org/techniques/T1548/005/ ; https://attack.mitre.org/resources/versions/ | primer | T1548.005 v2.0 (2026-05-12); v20.0 sejak 2026-10-13; diakses 2026-10-18 | Tinggi. Mekanisme JIT, impersonation, PassRole, tanpa AssumeRole; versi ATT&CK berlaku |
| S25 | Summit Route: Public dataset of CloudTrail logs from flaws.cloud | https://summitroute.com/blog/2020/10/09/public_dataset_of_cloudtrail_logs_from_flaws_cloud/ | sekunder (penulis dataset) | 2020-10-09; diakses 2026-10-18 | Sedang-tinggi. 1.939.207 event, 12 Februari 2017 sampai 7 Oktober 2020, dianonimkan; lisensi tidak disebut |

**Catatan sumber:** nama field di query SPL (`signin_type`, `src_asn`, `session_id`, `device_id`, `activity`) adalah field alias SOC PT JAB di atas sourcetype `azure:monitor:aad`, bukan nama baku add-on; nama mentah `properties.riskEventTypes_v2` dan bentuknya (array atau string) perlu dicek di event mentah, karena skema ekspor Azure Monitor dan Microsoft Graph berbeda [S11]. Pola baris ganda per login di bagian 1.2 adalah pengamatan umum dari data sign-in, bukan pernyataan di halaman yang dirujuk. Apakah session ID tetap sama selama berhari-hari saat refresh token dipakai, dan apakah ekspor Event Hub mengirim sign-in non-interaktif tanpa pengelompokan, tidak dinyatakan di dokumen yang dibaca dan perlu diuji di tenant-mu (lab langkah 3). Nama operasi audit di bagian 2.4 diambil dari referensi Microsoft [S16]; apakah pembaruan sertifikat SAML enterprise app tercatat sebagai "Add service principal credentials" perlu dicek di tenant-mu. Kueri Athena di bagian 2.6 mengasumsikan tabel bernama `cloudtrail_logs` dengan skema standar CloudTrail; nama kolom bersarang perlu diverifikasi terhadap tabel yang kamu buat. Klaim bahwa event API global tercatat di `us-east-1` dan nilai `errorCode` per layanan perlu dicek di data CloudTrail-mu. Syarat lisensi application management policy tidak tercantum di [S15]. Seluruh isi PT JAB (`HUNT-2027-029` sampai `-031`, nama aplikasi, akun, ASN, IP, angka, dan label) adalah penerapan catatan ini pada organisasi fiktif, bukan hasil eksekusi nyata.
