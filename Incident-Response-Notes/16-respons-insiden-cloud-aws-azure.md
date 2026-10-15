---
day: 16
title: 'Respons insiden cloud AWS dan Azure: mengamankan log, snapshot, dan mencabut kunci'
researched_on: 2026-10-15
versions_checked: 'AWS Customer Playbook Framework (aws-samples, Compromised IAM Credentials dan EC2 Forensics, diakses 2026-10-15); AWS IAM User Guide (Disabling permissions for temporary security credentials; Revoke IAM role temporary security credentials); AWS managed policy AWSCompromisedKeyQuarantineV3 (diedit 16 Maret 2026); AWS CloudTrail User Guide (event history, data events); Amazon EC2 User Guide (security group connection tracking); Amazon GuardDuty finding types; Azure Monitor Activity Log (ms.date 2026-05-04); Computer forensics chain of custody in Azure (ms.date 2026-04-10); Create a snapshot of an Azure managed disk (ms.date 2026-09-17); Manage storage account access keys (ms.date 2026-08-11); Compromised and malicious applications investigation (ms.date 2025-03-12); az ad app credential (ms.date 2026-06-26); MITRE ATT&CK v20'
---

# Day 16: Respons insiden cloud AWS dan Azure (mengamankan log, snapshot, dan mencabut kunci)

Cakupan: membedakan apa yang bisa dan tidak bisa dilakukan responder di cloud, mengamankan log control plane dan data plane sebelum hilang, menahan kunci yang bocor termasuk kredensial sementara yang terbit darinya, mengambil bukti disk lewat snapshot, mengisolasi resource dengan memahami batas security group, menilai akses ke data di storage, dan membersihkan resource penyerang di semua region dan subscription.

## Ide inti

Di cloud, kunci adalah identitas. Siapa pun yang memegang access key IAM atau secret service principal bisa memanggil API yang sama dengan pemiliknya, dari laptop mana pun di internet, tanpa melewati firewall kantor dan tanpa MFA. Karena itu respons insiden cloud berputar pada tiga pertanyaan yang jawabannya hampir seluruhnya ada di log API: kunci mana yang dipakai, apa saja yang dilakukan dengan kunci itu (termasuk kunci turunan yang diterbitkannya), dan data apa yang disentuh. Pekerjaan teknis responder juga berubah bentuk. Tidak ada server fisik untuk dicabut kabelnya atau disalin memorinya dari luar; yang ada adalah panggilan API untuk mencabut izin, memotret disk, mengganti aturan jaringan, dan mematikan resource. Semua itu hanya berguna bila log yang dibutuhkan sudah aktif sebelum insiden, karena log yang tidak pernah dinyalakan tidak bisa diminta mundur.

Kamu sudah mengenal pola ini dari ISP. Pengelola gedung colocation menjamin listrik, pendingin, dan pintu, tetapi isi rak, konfigurasi router, dan siapa yang memegang password TACACS adalah urusan penyewa. Bila password itu tertulis di skrip yang bocor, pengelola gedung tidak akan tahu dan tidak akan menginvestigasinya; kamu sendiri yang membuka log TACACS accounting, mencabut password, dan memeriksa konfigurasi apa yang diubah. Bedanya di cloud, "router" bisa dibuat baru oleh penyerang dalam hitungan detik di POP yang tidak pernah kamu pantau, dan tagihannya datang ke kamu.

```
kunci bocor (repo publik, laptop, pipeline)
  |
  v
amankan log dulu      CloudTrail / Activity Log / sign-in SP, ekspor sebelum retensi habis
  |
  v
scoping lewat API     kunci -> kunci turunan -> resource dibuat -> data disentuh -> region lain
  |
  v
bukti                 user data, snapshot disk, salinan log (sebelum resource dimatikan)
  |
  v
containment serentak  deny izin + nonaktifkan kunci + matikan resource penyerang
                      + putar rahasia yang ikut terpapar (storage key, secret)
  |
  v
eradication           hapus resource di SEMUA region/subscription, ganti kunci jangka panjang
  |                   dengan kredensial pendek (OIDC, managed identity)
  v
validasi              tidak ada panggilan baru dari kunci lama, tidak ada resource asing
```

Situasi yang dipakai sepanjang Day ini adalah insiden `INC-2026-025` di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif. PT JAB punya satu akun AWS produksi untuk backend aplikasi self-care pelanggan "MyJAB" di region Jakarta, dan satu subscription Azure untuk VM dan storage pelaporan. Senin malam 30 November 2026, seorang developer menyalin repo aplikasi ke repo GitHub pribadi yang publik, lengkap dengan berkas konfigurasi pipeline berisi access key IAM `ci-deploy-selfcare` dan secret service principal pelaporan. Selasa dini hari kunci itu dipakai dari luar. Pukul 05:10 severity dinaikkan ke SEV-1 setelah log menunjukkan berkas ekspor berisi data pelanggan diunduh. Pukul 05:40, Direktur Teknologi Hendra Wijaya menulis di kanal `#inc-2026-025`:

> "Dim, saya ada rapat direksi jam 09:00 dan harus bisa menjelaskan ini. Pertanyaan saya: di cloud kita tidak punya server sendiri, jadi apa yang sebenarnya bisa kita lakukan, dan apa yang tanggung jawab AWS atau Microsoft? Log apa yang kita punya, dan apa yang tidak tercatat? Katanya kunci sudah dinonaktifkan jam 04:15, apakah penyerang sudah pasti tidak bisa apa-apa? Server mining yang dibuat penyerang kenapa tidak langsung dihapus saja? Data pelanggan di S3 benar diambil atau tidak, dan berapa? Di Azure yang bocor 'secret aplikasi', kenapa tim harus memutar kunci storage juga? Terakhir, bagaimana kita yakin ini bersih dan tidak terulang?"

Pesan itu memuat tujuh pertanyaan:

1. Apa yang bisa dilakukan responder di cloud, dan apa yang menjadi tanggung jawab penyedia?
2. Log apa yang ada, berapa lama disimpan, dan apa yang tidak tercatat?
3. Apakah menonaktifkan access key sudah cukup?
4. Kenapa resource penyerang tidak langsung dihapus?
5. Bagaimana menilai data yang diambil dari storage?
6. Kenapa kebocoran secret service principal berarti memutar rahasia lain?
7. Bagaimana memastikan bersih dan tidak terulang?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, pertanyaan 6 di bagian 1.6, dan pertanyaan 7 di bagian 1.7. Bagian 2 berisi query, perintah, dan dokumen PT JAB malam itu.

**Kapan relevan:** setiap kali kunci cloud (access key IAM, secret atau sertifikat service principal, storage account key, token pipeline) terpapar atau dipakai tidak wajar, setiap kali ada resource cloud yang tidak dikenal, dan saat menyiapkan logging, retensi, dan wewenang respons cloud sebelum insiden.
**Kapan bukan jawaban:** kompromi identitas pengguna di Entra ID (sign-in log, pencabutan token pengguna, Conditional Access) dibahas di Day 10; Day ini fokus ke kunci mesin dan resource. Investigasi isi VM yang dikompromi lewat celah aplikasi (bukan lewat kunci) memakai prinsip live response dan bukti di Day 04 dan Day 15, dengan snapshot sebagai pengganti image disk.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (containment, eradication, recovery, severity, IC, scoping, bukti, chain of custody, jam H, service principal, consent, refresh token) tidak diulang. Tabel berikut memuat istilah baru Day ini. Kolom padanan memakai analogi NOC dan SOC yang sama di semua Day IR.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Model tanggung jawab bersama | Pembagian tugas keamanan: penyedia menjaga infrastruktur cloud, pelanggan menjaga identitas, konfigurasi, data, dan log di akunnya | Colocation: gedung menjamin listrik dan pintu, isi rak urusan penyewa |
| Control plane dan data plane | Control plane mengelola resource (buat VM, ubah kebijakan); data plane mengakses isi resource (baca objek, baca secret) | Log TACACS accounting perintah konfigurasi vs NetFlow trafik pelanggan |
| Access key IAM | Pasangan ID dan secret jangka panjang milik IAM user untuk memanggil API AWS | Kunci API NMS yang ditanam di skrip |
| Kredensial sementara (STS) | Kredensial berumur terbatas yang diterbitkan dari kunci atau role, misalnya lewat `GetSessionToken` atau `AssumeRole` | Sesi PPPoE yang terbit dari kredensial pelanggan |
| CloudTrail event history | Catatan 90 hari management event per region yang aktif tanpa konfigurasi | Buffer log bawaan perangkat |
| Trail dan data event | Trail menyimpan event ke bucket untuk jangka panjang; data event (misalnya `GetObject`) harus diaktifkan per resource | Syslog ke server pusat; NetFlow yang harus dinyalakan per interface |
| Activity Log | Log control plane Azure per subscription, disimpan 90 hari | Log perubahan konfigurasi di NMS |
| Resource log | Log data plane Azure per resource, tidak dikumpulkan tanpa diagnostic setting | Debug log per fitur yang harus dinyalakan dulu |
| Snapshot disk | Salinan point-in-time disk EBS atau managed disk Azure | Salinan image flash router sebelum RMA |
| Security group dan NACL | Firewall stateful per instance vs firewall stateless per subnet | ACL stateful di firewall vs ACL stateless di router |
| Connection tracking | Security group terus mengizinkan koneksi yang sudah tercatat walau aturannya diubah | Sesi NAT yang hidup sampai timeout walau ACL sudah diganti |
| Storage account key | Kunci bersama yang memberi akses penuh ke data storage Azure | Community string SNMP read-write |

### 1.1 Apa yang bisa dilakukan responder di cloud

Pertanyaan pertama Hendra wajar, karena semua kebiasaan IR on-premises bergantung pada akses fisik: cabut kabel, ambil memori, salin disk. Di cloud, akses fisik tidak ada, dan sebagian pekerjaan menjadi milik penyedia.

Pembagiannya kira-kira begini. Penyedia menjaga infrastruktur di bawah layanan: data center, hypervisor, jaringan fisik. Pelanggan bertanggung jawab atas semua yang dikonfigurasinya: identitas dan kunci, izin, aturan jaringan, isi VM, data, dan log mana yang diaktifkan. Kebocoran access key di repo publik sepenuhnya berada di sisi pelanggan. Penyedia bisa membantu, tetapi tidak menginvestigasi akunmu untukmu. Playbook kompromi kredensial dari AWS sendiri menyuruh pelanggan membuka support case dengan prioritas tinggi, menyertakan timeline, ARN principal yang dicurigai, dan resource yang terdampak, serta memastikan kontak keamanan alternatif terisi di setiap akun [S1].

AWS juga bertindak sepihak pada kasus tertentu. Bila AWS mendeteksi kunci IAM user terpapar publik, AWS menempelkan managed policy `AWSCompromisedKeyQuarantineV3` ke user itu. Policy ini menolak sekumpulan aksi yang sering disalahgunakan, antara lain `ec2:RunInstances`, `iam:CreateUser`, `iam:CreateAccessKey`, `s3:GetObject`, `s3:ListBucket`, dan `sts:GetSessionToken`, dan dokumentasinya meminta policy itu tidak dilepas [S4]. Policy ini tidak menolak semua aksi, jadi ia rem darurat, bukan containment.

Yang bisa dilakukan responder adalah apa pun yang bisa dilakukan lewat API dengan izin yang cukup:

- **Membaca log**: CloudTrail di AWS, Activity Log dan log Entra ID di Azure, plus log yang sudah diekspor ke SIEM.
- **Mencabut izin**: menempelkan policy deny, menonaktifkan kunci, mematikan service principal.
- **Mengambil bukti disk**: snapshot volume EBS atau managed disk. Snapshot hanya berisi disk. Memori harus diambil dari dalam instance yang masih berjalan dengan alat pihak ketiga, sebelum isolasi atau shutdown, seperti di playbook forensik EC2 [S9]. Azure juga tidak bisa memotret ephemeral OS disk, karena disk itu hanya ada di host lokal [S11].
- **Mengubah jaringan**: mengganti security group atau NSG, menambah NACL.
- **Mematikan atau menghapus resource**.

Konsekuensinya untuk persiapan: wewenang dan peran responder di akun cloud harus disiapkan sebelum insiden. Akun analis yang hanya bisa membaca log tidak bisa menempelkan deny policy jam 04:00.

### 1.2 Log yang ada, retensinya, dan yang tidak tercatat

Pertanyaan kedua Hendra menentukan apa yang bisa dibuktikan. Di cloud, log adalah satu-satunya saksi, dan setiap log punya batas yang harus diketahui sebelum malam insiden.

Tabel berikut merangkum log yang dipakai di `INC-2026-025`. Kolom "Tidak tercatat" adalah kolom yang paling sering membuat kesimpulan salah.

| Log | Aktif tanpa konfigurasi? | Retensi bawaan | Mencatat | Tidak tercatat |
|---|---|---|---|---|
| CloudTrail event history | Ya | 90 hari | Management event per region, termasuk panggilan yang ditolak | Data event (isi S3), Insights; satu region dan satu atribut filter per pencarian [S5] |
| CloudTrail trail atau event data store | Tidak, harus dibuat | Selama disimpan di bucket | Management event semua region bila trail multi-region | Data event, kecuali diaktifkan per resource dengan biaya tambahan [S6] |
| Azure Activity Log | Ya | 90 hari | Operasi control plane (buat VM, `listKeys`), siapa pemanggilnya | Biasanya tidak mencatat operasi baca; data plane ada di resource log yang tidak aktif tanpa diagnostic setting [S10] |
| Sign-in log service principal di Entra ID | Ya | Mengikuti lisensi tenant (Day 10 bagian 1.2) | Autentikasi service principal, IP, resource yang dituju [S13] | Apa yang dilakukan setelah token didapat |
| GuardDuty | Tidak, diaktifkan per region | Tidak dibahas di sini | Pola mencurigakan dari CloudTrail, DNS, flow log [S8] | Region yang GuardDuty-nya tidak aktif |

Tiga hal dari tabel itu menentukan cerita `INC-2026-025`:

- **Event history tidak cukup untuk jangka panjang.** AWS menyebut event history terbatas 90 hari dan menyarankan trail atau event data store untuk catatan berkelanjutan [S5]. PT JAB punya trail multi-region yang menulis ke bucket log dan diambil Splunk, sehingga aktivitas penyerang di region Singapura dan Virginia tetap terlihat walau PT JAB tidak pernah memakai region itu.
- **Data event harus dinyalakan sebelumnya.** Trail tidak mencatat data event secara default [S6]. PT JAB menyalakan data event S3 hanya untuk bucket ekspor yang berisi data pelanggan. Tanpa keputusan itu, pertanyaan Hendra "data diambil atau tidak" tidak akan bisa dijawab dengan bukti.
- **Activity Log 90 hari dan satu-satunya catatan pembuat resource.** Microsoft menyebut Activity Log disimpan 90 hari lalu dihapus, dan alasan paling umum memperpanjang retensinya adalah menyimpan informasi siapa pembuat resource, yang hanya ada di Activity Log [S10]. PT JAB mengalirkan Activity Log ke Splunk lewat Event Hub.

Langkah pertama responder cloud karena itu adalah mengamankan log: memastikan trail masih berjalan (penyerang sering mematikannya; playbook AWS mencantumkan `StopLogging`, `DeleteTrail`, dan `UpdateTrail` sebagai panggilan yang harus dicari [S1]), lalu mengekspor event yang relevan ke penyimpanan bukti sebelum retensi habis.

### 1.3 Menahan kunci: nonaktifkan, lalu cabut izinnya

Pertanyaan ketiga Hendra ("kunci sudah dinonaktifkan, sudah pasti aman?") punya jawaban yang sama dengan pelajaran akun AD di Day 05 bagian 1.5: menahan sumber kredensial belum tentu menahan kredensial yang sudah diterbitkan.

AWS menyebut kredensial sementara berlaku sampai kedaluwarsa, dengan durasi 15 menit sampai 36 jam dan default 12 jam. Kredensial itu bisa dicabut, tetapi izin IAM user atau role yang menerbitkannya juga harus diubah; izin dievaluasi setiap kali kredensial dipakai, jadi setelah semua izin dihapus, permintaan dengan kredensial itu gagal [S2]. Di `INC-2026-025`, penyerang memanggil `GetSessionToken` pukul 00:58 dan mendapat kredensial sementara berawalan `ASIA` yang berlaku sampai sekitar 12:58. Menonaktifkan access key `AKIA...` saja tidak menyentuh kredensial itu.

Karena itu containment kunci AWS di PT JAB selalu berisi dua langkah yang dijalankan bersama:

1. **Cabut izin.** Tempelkan managed policy `AWSDenyAll` ke IAM user, atau policy deny dengan kondisi `aws:TokenIssueTime` [S2]. Deny mengalahkan allow, dan berlaku juga untuk kredensial sementara yang terbit dari user itu.
2. **Nonaktifkan kunci, jangan langsung hapus.** Playbook AWS menyarankan kunci dinonaktifkan dulu, aplikasi dipindah ke kunci baru, dan kunci lama baru dihapus setelah dipastikan tidak ada yang rusak; ID kunci yang dihapus dicatat karena dipakai untuk pencarian CloudTrail [S1].

Untuk role, prinsipnya serupa. Tombol "Revoke active sessions" di konsol IAM menempelkan inline policy `AWSRevokeOlderSessions` yang menolak semua aksi untuk sesi role yang terbit sebelum waktu pencabutan, ditambah sekitar 30 detik untuk menutup jeda propagasi; sesi yang terbit sesudahnya tidak terpengaruh [S3]. Kondisi `aws:TokenIssueTime` hanya ada pada permintaan yang ditandatangani kredensial sementara, jadi policy itu tidak memengaruhi kunci jangka panjang IAM user [S3]. Itu sebabnya kunci jangka panjang tetap dinonaktifkan secara terpisah.

Ada satu pengecualian penting: izin AWS root user tidak bisa diubah, termasuk izin kredensial sementara yang diterbitkan saat login sebagai root [S2]. Kebocoran kredensial root membutuhkan jalur yang berbeda, dimulai dari support case.

### 1.4 Resource penyerang: bukti dulu, lalu matikan, lalu hapus

Pertanyaan keempat Hendra ("kenapa server mining tidak langsung dihapus?") adalah versi cloud dari "kenapa laptop tidak langsung di-reimage" di Day 04 bagian 1.1. Begitu instance di-terminate, disk dan konfigurasinya hilang bersama jawaban atas pertanyaan yang belum ditanyakan.

Yang perlu diamankan dari resource yang dibuat penyerang:

- **Metadata instance**: tipe, AMI, waktu launch, region, security group, key pair. Playbook forensik EC2 mencantumkan field ini untuk dicatat [S9].
- **User data**: skrip yang dijalankan saat instance pertama kali menyala. Untuk instance mining, isinya biasanya alamat unduhan miner dan pool, yang menjadi IOC untuk pencarian di tempat lain.
- **Snapshot disk**: untuk analisis kemudian bila dibutuhkan. Di Azure, Microsoft menggambarkan alur bukti berupa snapshot OS dan data disk yang disalin ke blob storage immutable di subscription SOC terpisah, dengan hash disimpan di key vault [S11].

Urutannya juga penting untuk mencegah bukti hilang tanpa sengaja. Playbook forensik EC2 menyarankan mengubah perilaku shutdown instance menjadi stop, bukan terminate, dan mematikan `DeleteOnTermination` untuk volume [S9].

Untuk instance milik PT JAB yang dikompromi (bukan buatan penyerang), langkahnya lebih panjang: memori diambil dulu dari dalam instance, instance dilepas dari auto scaling group dan load balancer, lalu diberi security group yang menolak semua trafik masuk dan keluar [S9]. Ada jebakan di sini. Security group bersifat stateful dan memakai connection tracking: saat aturan diubah, koneksi yang sudah tercatat tidak langsung terputus dan tetap diizinkan sampai timeout. AWS menyarankan NACL di subnet bila trafik harus terputus seketika, karena NACL stateless dan menambah deny di sana memutus koneksi yang sedang berjalan [S7]. Pengecualiannya, aliran yang tidak di-track (aturan `0.0.0.0/0` dua arah untuk semua port) langsung terputus bila aturannya dihapus [S7]. Artinya, mengganti security group tidak otomatis memutus sesi SSH penyerang yang sudah terbuka.

Di `INC-2026-025`, ke-12 instance mining adalah buatan penyerang, tanpa data PT JAB. Memori miner tidak bernilai cukup untuk menunda; biaya berjalan setiap jam. Keputusannya: user data dan metadata diambil semua, satu snapshot per region diambil sebagai sampel, lalu semua instance di-stop. Terminate menunggu sampai bukti diverifikasi.

### 1.5 Data di storage: yang terbukti, bukan yang dikhawatirkan

Pertanyaan kelima Hendra ("benar diambil atau tidak, dan berapa?") hanya bisa dijawab dengan data event. Management event menunjukkan penyerang melihat daftar bucket; ia tidak menunjukkan objek mana yang dibaca.

Cara membacanya:

- **`GetObject` di data event** menunjukkan objek mana yang diminta, oleh principal mana, dari IP mana, dan berapa byte yang dikirim (`additionalEventData.bytesTransferredOut`). Bila byte yang dikirim sama dengan ukuran objek, objek itu terunduh penuh.
- **CloudTrail tidak menunjukkan isi.** Jumlah baris data pribadi dihitung dari objek yang sama di bucket (versi yang sama), oleh pemilik aplikasi, dan dicatat sebagai bukti terpisah.
- **Tanpa data event**, kesimpulan yang jujur adalah "akses tidak bisa disingkirkan", bukan "tidak ada akses". Pola ini sama dengan log database `jkt-billingdb01` di `INC-2026-019` yang hanya mencatat koneksi.

Teknik ini di ATT&CK v20 adalah Data from Cloud Storage (T1530): mengumpulkan berkas sensitif dari storage cloud, sering lewat kesalahan konfigurasi publik atau kredensial yang bocor [S19]. Kunci yang bocor sendiri adalah Valid Accounts: Cloud Accounts (T1078.004) [S16], dan menemukan kunci di berkas konfigurasi adalah Credentials In Files (T1552.001) [S17].

### 1.6 Service principal dan rahasia turunan di Azure

Pertanyaan keenam Hendra menyentuh pola yang paling sering terlewat: satu rahasia yang bocor membuka rahasia lain.

Service principal `sp-selfcare-reporting` punya peran Contributor di resource group pelaporan. Peran Contributor termasuk aksi `Microsoft.Storage/storageAccounts/listkeys/action` [S15]. Microsoft menyebut storage account key memberi akses penuh ke data storage dan kemampuan membuat SAS token, dan menyarankan kunci diputar bila diduga terkompromi [S15]. Jadi begitu penyerang memanggil `listKeys` (tercatat di Activity Log sebagai operasi control plane), ia memegang kunci yang bisa dipakai membaca isi storage lewat data plane, dan pembacaan itu tidak tercatat di Activity Log. Bila resource log storage tidak diaktifkan, pembacaannya tidak tercatat di mana pun [S10].

Karena itu containment service principal di PT JAB berisi empat langkah:

1. **Matikan sign-in service principal** (`accountEnabled` false). Playbook Microsoft menyebut langkah ini sebagai containment umum yang memberi waktu menilai dampak sebelum kunci diganti atau aplikasi dihapus [S13].
2. **Hapus semua credential lama** di objek aplikasi dan service principal, setelah mencatat `keyId`-nya [S13][S14]. Perhatikan bahwa `az ad app credential reset` tanpa `--append` menghapus semua password dan key lalu membuat password baru [S14]; ini berguna saat recovery, tetapi jalankan setelah daftar credential dicatat.
3. **Putar rahasia yang bisa diakses service principal itu**: storage account key (keduanya), secret di key vault yang bisa dibacanya. Playbook Microsoft mengurutkan prioritasnya: secret yang terbukti dibaca, lalu sisa secret di key vault yang terpapar, lalu sisa secret di subscription yang terpapar [S13]. Memutar storage key juga mencabut account SAS dan service SAS yang ditandatangani kunci itu [S15].
4. **Periksa apa yang dibuat atau diubah** di Activity Log, dan sign-in service principal di Entra ID. Untuk perubahan credential aplikasi, cari aktivitas audit di kategori Application Management yang menyangkut certificates and secrets management [S13].

Sisi identitas pengguna (pencabutan refresh token, Conditional Access) tetap mengikuti Day 10 bagian 1.4 dan 1.7; service principal tidak memakai MFA, jadi kontrol utamanya adalah jenis credential dan izinnya.

### 1.7 Bersih dan tidak terulang: semua region, semua kunci, kredensial pendek

Pertanyaan terakhir Hendra punya tiga bagian: membersihkan, membuktikan bersih, dan mencegah.

**Membersihkan di semua region.** Playbook AWS meminta resource yang dibuat kunci terkompromi dihapus dengan memeriksa semua region, setelah yang diperlukan untuk investigasi dicadangkan, termasuk instance, AMI, volume dan snapshot EBS, dan fungsi Lambda yang tidak dikenal [S1]. Penyerang sengaja memakai region yang tidak dipakai korban, karena di sana tidak ada orang yang melihat. GuardDuty juga diaktifkan per region, sehingga region yang GuardDuty-nya mati tidak menghasilkan finding [S8].

**Mencari persistence.** Playbook AWS mendaftar panggilan yang harus dicari: perubahan IAM (`CreateUser`, `CreateAccessKey`, `AttachUserPolicy`, `CreatePolicyVersion`), perubahan identity provider, gangguan logging (`StopLogging`, `DeleteTrail`, `DeleteDetector`), paparan S3 (`PutBucketPolicy`, `DeleteBucketPublicAccessBlock`), dan perubahan KMS [S1]. Panggilan yang ditolak (`AccessDenied`) juga dibaca: itu niat penyerang yang gagal, dan menunjukkan apa yang akan ia coba lagi dengan kunci lain.

**Mencegah.** Akar masalahnya bukan developer yang ceroboh, tetapi kunci jangka panjang yang bisa disalin. Playbook AWS menyebut penggantian kunci jangka panjang dan pengurangan izin sebagai pelajaran inti [S1], dan Microsoft menyarankan managed identity alih-alih credential yang harus disimpan [S14][S15]. Untuk pipeline CI, penggantinya adalah kredensial pendek yang diterbitkan per job (federasi OIDC ke role AWS, federated credential atau managed identity di Azure), sehingga tidak ada rahasia yang bisa tertinggal di berkas konfigurasi.

PT JAB menuliskan kriteria selesai untuk insiden kunci cloud:

1. Semua kunci yang terpapar dan kunci turunannya tidak lagi menghasilkan panggilan berhasil, dibuktikan di log selama minimal 24 jam.
2. Inventaris resource di semua region dan subscription cocok dengan daftar resource sah; semua resource penyerang dihapus setelah buktinya tersimpan.
3. Tidak ada IAM user, access key, policy, credential aplikasi, atau role assignment baru yang tidak dijelaskan.
4. Rahasia turunan (storage key, secret key vault, kredensial database yang bisa dibaca) sudah diputar.
5. Logging yang kurang saat insiden sudah dinyalakan (GuardDuty semua region, resource log storage).

## 2. Contoh artefak dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi; ID akun, ID kunci, GUID, dan nama resource dibuat untuk catatan ini. Waktu ditulis dalam WIB; CloudTrail dan Activity Log menyimpan waktu dalam UTC (WIB = UTC + 7 jam). CloudTrail masuk Splunk index `aws` dengan sourcetype `aws:cloudtrail`, dan Activity Log masuk index `azure` lewat Event Hub; nama sourcetype dan field bergantung add-on yang kamu pakai, jadi cocokkan di lingkunganmu. Nama field CloudTrail di query (`eventName`, `userIdentity.arn`, `requestParameters.bucketName`) mengikuti struktur JSON CloudTrail.

Jejak cloud PT JAB yang dipakai di bagian ini:

| Elemen | AWS | Azure |
|---|---|---|
| Wadah | Akun produksi `310582746193`, region kerja `ap-southeast-3` (Jakarta) | Subscription `JAB-Azure-Prod` (`5f3c2a91-7d4e-4b6a-9c18-2e7f0a6b3d54`) |
| Identitas yang bocor | IAM user `ci-deploy-selfcare`, access key `AKIAUJAB7EXAMPLE4Q2W`, policy `AmazonEC2FullAccess` + inline S3 ke bucket self-care | Service principal `sp-selfcare-reporting` (appId `8b6e1f42-3c9a-4d7e-a5b2-71c0d9e4f6a3`), Contributor di `rg-jab-reporting` |
| Data | Bucket `jab-selfcare-prod-exports` (ekspor harian tiket gangguan berisi data pelanggan) | Storage account `jabrptstor01` (laporan agregat, tanpa data per pelanggan) |
| Log | Trail multi-region ke `jab-ct-logs-310582746193`, data event S3 hanya untuk bucket ekspor; GuardDuty hanya di `ap-southeast-3` | Activity Log lewat diagnostic setting ke Event Hub; resource log storage belum aktif |

### 2.1 Timeline kunci dari CloudTrail

Query ini menjawab pertanyaan 2 dan 3 Hendra: apa yang dilakukan dengan kunci, dan apakah ada kunci turunan.

**Tujuan:** menyusun semua panggilan API oleh IAM user `ci-deploy-selfcare`, termasuk yang memakai kredensial sementara, sejak repo menjadi publik sampai jam H.

```
index=aws sourcetype=aws:cloudtrail
earliest="11/30/2026:21:00:00" latest="12/01/2026:04:15:00"
userIdentity.arn="arn:aws:iam::310582746193:user/ci-deploy-selfcare"
| eval hasil=if(isnull(errorCode), "Success", errorCode)
| eval jenis_kunci=substr('userIdentity.accessKeyId', 1, 4)
| stats count min(_time) as pertama max(_time) as terakhir
        values(sourceIPAddress) as ip values(jenis_kunci) as kunci by eventName, hasil
| sort pertama
| convert ctime(pertama) ctime(terakhir)
```

Penjelasan tiap bagian:

- Filter memakai ARN user, bukan hanya ID access key. Kredensial sementara dari `GetSessionToken` punya ID kunci sendiri (berawalan `ASIA`), sehingga pencarian dengan `AKIA...` saja melewatkan semua aktivitas sesudahnya. Cocokkan cara CloudTrail mencatat identitas untuk kredensial sementara di data-mu.
- `jenis_kunci` mengambil empat huruf pertama ID kunci: `AKIA` untuk kunci jangka panjang, `ASIA` untuk kredensial sementara.
- `hasil` memisahkan panggilan berhasil dari yang ditolak; keduanya dibaca.

Keluaran ilustrasi (65 event):

```
eventName                       hasil         count  pertama              terakhir             ip              kunci
GetCallerIdentity               Success           1  12/01/2026 00:47:05  12/01/2026 00:47:05  203.0.113.241   AKIA
ListBuckets                     Success           2  12/01/2026 00:47:31  12/01/2026 00:49:10  203.0.113.241   AKIA
ListUsers                       AccessDenied      1  12/01/2026 00:48:02  12/01/2026 00:48:02  203.0.113.241   AKIA
GetAccountAuthorizationDetails  AccessDenied      1  12/01/2026 00:48:15  12/01/2026 00:48:15  203.0.113.241   AKIA
DescribeRegions                 Success           1  12/01/2026 00:50:40  12/01/2026 00:50:40  203.0.113.241   AKIA
DescribeInstances               Success           4  12/01/2026 00:51:02  12/01/2026 00:53:44  203.0.113.241   AKIA
GetSessionToken                 Success           1  12/01/2026 00:58:40  12/01/2026 00:58:40  203.0.113.241   AKIA
CreateUser                      AccessDenied      1  12/01/2026 01:02:13  12/01/2026 01:02:13  203.0.113.246   ASIA
CreateAccessKey                 AccessDenied      1  12/01/2026 01:02:30  12/01/2026 01:02:30  203.0.113.246   ASIA
ImportKeyPair                   Success           2  12/01/2026 01:08:55  12/01/2026 01:12:31  203.0.113.246   ASIA
CreateSecurityGroup             Success           2  12/01/2026 01:09:10  12/01/2026 01:12:40  203.0.113.246   ASIA
AuthorizeSecurityGroupIngress   Success           2  12/01/2026 01:09:21  12/01/2026 01:12:52  203.0.113.246   ASIA
RunInstances                    Success          12  12/01/2026 01:10:22  12/01/2026 01:14:20  203.0.113.246   ASIA
ListObjects                     Success           4  12/01/2026 01:31:10  12/01/2026 01:31:58  203.0.113.246   ASIA
GetObject                       Success          30  12/01/2026 01:32:05  12/01/2026 01:44:52  203.0.113.246   ASIA
```

Cara membaca hasil:

- **Pola enumerasi 00:47 sampai 00:53** dari `203.0.113.241`: siapa saya (`GetCallerIdentity`), apa yang bisa saya lihat (bucket, region, instance), dan apa yang ditolak (`ListUsers`, `GetAccountAuthorizationDetails`). Penolakan memberi tahu kita batas izin user ini, dan juga memberi tahu penyerang.
- **`GetSessionToken` pukul 00:58:40** adalah titik balik: sejak itu semua aktivitas memakai kredensial `ASIA` dari IP kedua `203.0.113.246`. Dengan durasi default 12 jam [S2], kredensial itu berlaku sampai sekitar 12:58.
- **`CreateUser` dan `CreateAccessKey` ditolak** pukul 01:02: penyerang mencoba membuat jalan masuk cadangan dan gagal. Tetap dicatat, karena kunci lain dengan izin IAM akan dicoba dengan cara yang sama.
- **12 `RunInstances`** dengan `ImportKeyPair`, `CreateSecurityGroup`, dan `AuthorizeSecurityGroupIngress` masing-masing dua kali: satu paket per region. Region dicari di query bagian 2.2.
- **30 `GetObject`** hanya terlihat karena data event aktif untuk bucket ekspor; dibahas di bagian 2.3.
- Tidak ada event dari IP runner CI di jendela ini, dan tidak ada `StopLogging`, `DeleteTrail`, atau `PutBucketPolicy`. Penempelan policy karantina oleh AWS pukul 02:52 (`AttachUserPolicy`) tidak muncul di query ini karena pemanggilnya bukan user `ci-deploy-selfcare`; cari dengan `requestParameters.userName`.

**Variasi:** pakai `aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIAUJAB7EXAMPLE4Q2W` bila log belum masuk SIEM. Ingat batasnya: satu region per pencarian, satu atribut filter, hanya management event, 90 hari [S5]; ulangi per region.

**Kapan gagal:** trail hanya single-region, atau dihentikan penyerang. Aktivitas di region lain lalu hanya ada di event history region itu, dan harus dicari region per region sebelum 90 hari lewat.

### 2.2 Bukti dan containment AWS

Langkah ini menjawab pertanyaan 3 dan 4 Hendra. Dijalankan Sari Kusuma (technical lead) dari workstation jump admin dengan role responder `SecurityResponder`, bukan dengan kunci yang bocor.

**Inventaris instance di semua region aktif:**

```bash
for r in $(aws ec2 describe-regions --query "Regions[].RegionName" --output text); do
  aws ec2 describe-instances --region "$r" \
    --filters Name=instance-state-name,Values=pending,running,stopping,stopped \
    --query "Reservations[].Instances[].[InstanceId,InstanceType,LaunchTime,KeyName]" \
    --output text | sed "s/^/$r\t/"
done
```

- `describe-regions` tanpa `--all-regions` mengembalikan region yang aktif untuk akun; region yang tidak diaktifkan tidak bisa dipakai siapa pun, termasuk penyerang.
- Filter status mencakup instance yang di-stop, karena penyerang bisa menyalakannya lagi.

Keluaran ilustrasi (diringkas):

```
ap-southeast-1  i-0a51c7e2d94b3f810  c6i.4xlarge  2026-11-30T18:10:22Z  k-7f3a
... 5 baris lain di ap-southeast-1, KeyName k-7f3a
us-east-1       i-0c92e4a17b65d0f3e  c6i.4xlarge  2026-11-30T18:13:05Z  k-91bd
... 5 baris lain di us-east-1, KeyName k-91bd
ap-southeast-3  i-03d8b2f6a1c4e9a57  m6i.large    2026-10-02T03:11:40Z  jab-selfcare-ops
ap-southeast-3  i-0e7f19c3b8a2d6045  m6i.large    2026-10-02T03:11:41Z  jab-selfcare-ops
```

Cara membaca hasil: enam instance di Singapura dan enam di Virginia dengan key pair asing, dibuat 18:10 sampai 18:14 UTC (01:10 sampai 01:14 WIB), cocok dengan 12 `RunInstances` di bagian 2.1. Dua instance di Jakarta adalah aplikasi self-care yang sah, dibuat Oktober dengan key pair PT JAB; CloudTrail tidak menunjukkan panggilan penyerang ke instance itu.

**Bukti dari instance penyerang (contoh satu instance):**

```bash
aws ec2 describe-instance-attribute --region ap-southeast-1 \
  --instance-id i-0a51c7e2d94b3f810 --attribute userData \
  --query "UserData.Value" --output text | base64 -d > E03-ud-i-0a51c7e2d94b3f810.txt

aws ec2 create-snapshot --region ap-southeast-1 \
  --volume-id vol-0b7d2e94c1a35f608 \
  --description "INC-2026-025-E04 root volume i-0a51c7e2d94b3f810" \
  --tag-specifications 'ResourceType=snapshot,Tags=[{Key=Incident,Value=INC-2026-025},{Key=Evidence,Value=E04}]'
```

- User data disimpan sebagai berkas teks dan di-hash seperti bukti lain (Day 04 bagian 1.6).
- Snapshot diberi tag nomor insiden dan nomor bukti, supaya tidak ikut terhapus saat pembersihan resource penyerang.

Isi user data (keluaran ilustrasi, diringkas dan disensor) berisi perintah mengunduh miner dari `198.51.100.249` dan menghubungi pool `pool.mining-relay.example.net:443`. Keduanya ditambahkan ke daftar IOC untuk dicari di proxy dan firewall PT JAB.

**Containment kunci (jam H 04:15):**

```bash
aws iam attach-user-policy --user-name ci-deploy-selfcare \
  --policy-arn arn:aws:iam::aws:policy/AWSDenyAll

aws iam update-access-key --user-name ci-deploy-selfcare \
  --access-key-id AKIAUJAB7EXAMPLE4Q2W --status Inactive
```

- `AWSDenyAll` menolak semua aksi untuk user itu, termasuk kredensial `ASIA` yang terbit pukul 00:58 [S2].
- `update-access-key` menonaktifkan kunci tanpa menghapusnya [S1].
- Policy `AWSCompromisedKeyQuarantineV3` yang ditempel AWS pukul 02:52 dibiarkan [S4].

Lalu semua instance penyerang di-stop per region dengan `aws ec2 stop-instances`, setelah user data dan snapshot sampel selesai.

**Validasi:** query bagian 2.1 dijalankan ulang dengan rentang mulai 04:15. Keluaran ilustrasi:

```
eventName          hasil         count  pertama              terakhir             ip              kunci
DescribeInstances  AccessDenied      3  12/01/2026 04:22:17  12/01/2026 04:31:40  203.0.113.246   ASIA
```

Tiga percobaan dengan kredensial sementara setelah jam H, semuanya ditolak. Ini bukti bahwa deny policy bekerja pada kredensial `ASIA`, dan sekaligus tanda bahwa penyerang masih memegang kredensial itu dan sedang memeriksa aksesnya.

**Kapan gagal:** containment dijalankan dengan akun yang juga bocor, atau `AWSDenyAll` ditempel ke user yang dipakai aplikasi lain. Di PT JAB, `ci-deploy-selfcare` hanya dipakai pipeline deploy, jadi harga containment adalah deploy self-care berhenti sampai mekanisme baru siap; aplikasi yang sedang berjalan tidak terganggu.

### 2.3 Data di bucket ekspor

Query ini menjawab pertanyaan 5 Hendra.

**Tujuan:** menghitung objek dan byte yang diunduh dari bucket ekspor oleh user yang bocor.

```
index=aws sourcetype=aws:cloudtrail eventName=GetObject
requestParameters.bucketName="jab-selfcare-prod-exports"
userIdentity.arn="arn:aws:iam::310582746193:user/ci-deploy-selfcare"
earliest="11/30/2026:21:00:00" latest="12/01/2026:12:58:40"
| stats count dc(requestParameters.key) as objek
        sum(additionalEventData.bytesTransferredOut) as byte_keluar
        min(_time) as pertama max(_time) as terakhir by sourceIPAddress
| convert ctime(pertama) ctime(terakhir)
```

- Rentang berakhir 12:58:40, saat kredensial sementara kedaluwarsa, supaya akses yang mungkin terjadi setelah jam H tetap tercakup.
- `dc(requestParameters.key)` menghitung objek berbeda; `count` menghitung permintaan. Bila keduanya berbeda, ada objek yang diunduh lebih dari sekali.

Keluaran ilustrasi:

```
sourceIPAddress  count  objek  byte_keluar  pertama              terakhir
203.0.113.246       30     30      7680000  12/01/2026 01:32:05  12/01/2026 01:44:52
```

Cara membaca hasil:

- 30 objek, masing-masing satu kali: `exports/tiket/2026-11/tiket-gangguan-2026-11-01.csv` sampai `-2026-11-30.csv`, satu berkas per hari November.
- Tim aplikasi menjalankan `aws s3api head-object` untuk ke-30 objek; total ukurannya 7.680.000 byte, sama dengan `byte_keluar`. Artinya semua berkas terunduh penuh.
- Tim aplikasi menghitung isi berkas yang sama: 38.400 baris tiket (rata-rata 1.280 baris per berkas), berisi nomor pelanggan, nama, nomor telepon, dan alamat pemasangan, tanpa NIK. Angka ini dari isi berkas, bukan dari CloudTrail, dan dicatat sebagai bukti `INC-2026-025-E10` bersama hash setiap berkas.
- Tidak ada `GetObject` setelah 01:44:52 maupun setelah jam H.

Temuan ini diteruskan ke DPO Agus Setiawan dan Legal Ratna Sari pukul 05:20. Penilaian kewajiban pemberitahuan dan pelaporannya dibahas di Day 18 bagian 1.4 dan 2.3.

**Kapan gagal:** data event tidak aktif untuk bucket itu. Kesimpulan yang bisa ditulis hanya "penyerang punya izin `s3:GetObject` dan memanggil `ListObjects`; pengunduhan tidak bisa dibuktikan atau disingkirkan", dan penilaian dampak harus memakai skenario terburuk.

### 2.4 Azure: Activity Log, service principal, dan storage key

Langkah ini menjawab pertanyaan 6 Hendra.

**Tujuan:** melihat semua operasi control plane oleh `sp-selfcare-reporting` di subscription PT JAB.

```
index=azure "identity.claims.appid"="8b6e1f42-3c9a-4d7e-a5b2-71c0d9e4f6a3"
earliest="11/30/2026:21:00:00" latest="12/01/2026:04:15:00"
| table _time operationName resultType callerIpAddress resourceId
| sort _time
```

- Event Hub mengirim Activity Log dalam JSON dengan `operationName`, `resultType`, `callerIpAddress`, dan klaim token di `identity.claims`, termasuk `appid` [S10]. Nama field setelah diolah add-on bisa berbeda.
- Tanpa SIEM, `az monitor activity-log list --subscription <id> --start-time ... --end-time ...` mengambil event yang sama selama masih dalam 90 hari [S10]; filter per pemanggil dicocokkan dengan cara service principal muncul di field `caller` di data-mu.

Keluaran ilustrasi (diringkas, resourceId dipendekkan):

```
_time                operationName                                           resultType  callerIpAddress  resourceId
12/01/2026 02:17:44  Microsoft.Network/networkSecurityGroups/write           Success     198.51.100.247   .../rg-jab-reporting/.../nsg-tmp
12/01/2026 02:18:09  Microsoft.Compute/virtualMachines/write                 Success     198.51.100.247   .../rg-jab-reporting/.../vm-tmp-01
12/01/2026 02:18:31  Microsoft.Compute/virtualMachines/write                 Success     198.51.100.247   .../rg-jab-reporting/.../vm-tmp-02
12/01/2026 02:18:52  Microsoft.Compute/virtualMachines/write                 Success     198.51.100.247   .../rg-jab-reporting/.../vm-tmp-03
12/01/2026 02:19:14  Microsoft.Compute/virtualMachines/write                 Success     198.51.100.247   .../rg-jab-reporting/.../vm-tmp-04
12/01/2026 02:21:07  Microsoft.Storage/storageAccounts/listKeys/action       Success     198.51.100.247   .../rg-jab-reporting/.../jabrptstor01
```

Cara membaca hasil:

- Empat VM dan satu NSG dibuat di resource group pelaporan, sesuai batas peran Contributor service principal. Tidak ada operasi di resource group lain, dan tidak ada role assignment baru.
- `listKeys` pukul 02:21:07 berarti penyerang memegang storage key `jabrptstor01`. Resource log storage belum aktif, sehingga pembacaan blob dengan kunci itu tidak tercatat. Isi storage adalah laporan agregat tanpa data per pelanggan; dampaknya dicatat sebagai "akses tidak bisa disingkirkan, data tidak berisi data pribadi".
- Sign-in service principal di Entra ID menunjukkan autentikasi pertama dari `198.51.100.247` pukul 02:15:41, dan sebelumnya hanya dari IP runner CI. Cara membaca log sign-in ada di Day 10 bagian 1.3.

**Bukti dan containment Azure (jam H 04:15):**

```bash
# bukti: snapshot OS disk satu VM penyerang ke resource group forensik
osDiskId=$(az vm show -g rg-jab-reporting -n vm-tmp-01 \
  --query "storageProfile.osDisk.managedDisk.id" -o tsv)
az snapshot create -g rg-jab-forensik --source "$osDiskId" \
  --name INC-2026-025-E06-vm-tmp-01-os

# catat credential yang ada sebelum dihapus
az ad app credential list --id 8b6e1f42-3c9a-4d7e-a5b2-71c0d9e4f6a3 > E08-sp-credentials.json
```

```powershell
# matikan sign-in service principal (Microsoft Graph PowerShell)
$sp = Get-MgServicePrincipal -Filter "appId eq '8b6e1f42-3c9a-4d7e-a5b2-71c0d9e4f6a3'"
Update-MgServicePrincipal -ServicePrincipalId $sp.Id -BodyParameter @{ accountEnabled = $false }
```

```bash
# hapus secret yang bocor (keyId dari E08), putar kedua storage key, hentikan VM penyerang
az ad app credential delete --id 8b6e1f42-3c9a-4d7e-a5b2-71c0d9e4f6a3 \
  --key-id 2c7e9a14-5b3d-4f81-9e06-a4d1c8b7f352
az storage account keys renew -g rg-jab-reporting --account-name jabrptstor01 --key primary
az storage account keys renew -g rg-jab-reporting --account-name jabrptstor01 --key secondary
for vm in vm-tmp-01 vm-tmp-02 vm-tmp-03 vm-tmp-04; do
  az vm deallocate -g rg-jab-reporting -n "$vm"
done
```

Penjelasan tiap bagian:

- Snapshot dibuat sebelum VM dihentikan atau dihapus [S12]. Alur bukti yang lebih ketat menyalin snapshot ke storage immutable di subscription SOC terpisah dan menyimpan hash-nya [S11]; PT JAB mencatat hash di evidence log dan menyalin snapshot ke `jkt-evid01` sesudah insiden.
- `accountEnabled` false menghentikan sign-in baru service principal [S13]. Credential dicatat dulu, baru dihapus [S13][S14].
- Kedua storage key diputar, karena penyerang membaca keduanya dengan `listKeys`. Microsoft memperingatkan bahwa semua klien yang memakai kunci lama harus diperbarui [S15]; job laporan PT JAB berhenti sampai Lutfi Hakim (Lead DevOps) memasang kunci baru pukul 08:30.

**Kapan gagal:** service principal dimatikan tetapi storage key tidak diputar. Penyerang tidak butuh service principal lagi; kunci storage yang sudah dipegangnya tetap berlaku.

### 2.5 Update ke Hendra pukul 06:00

Update ini menjawab ketujuh pertanyaan Hendra dalam satu halaman, dikirim Dimas sesuai ritme SEV-1.

```
INC-2026-025 | Update 06:00 | SEV-1 sejak 05:10 | untuk Hendra Wijaya
APA YANG TERJADI
- Senin 21:12 repo aplikasi self-care disalin ke GitHub publik oleh developer,
  berisi access key AWS ci-deploy-selfcare dan secret Azure sp-selfcare-reporting.
- Selasa 00:47-01:44 (AWS): penyerang memakai kunci itu, membuat 12 server mining
  di region Singapura dan Virginia, dan mengunduh 30 berkas ekspor tiket November
  (38.400 baris: nomor pelanggan, nama, telepon, alamat pemasangan; tanpa NIK).
- Selasa 02:15-02:21 (Azure): penyerang membuat 4 VM dan mengambil kunci storage
  pelaporan (isi laporan agregat, tanpa data per pelanggan).
TERVERIFIKASI DITAHAN (jam H 04:15)
- AWS: semua izin user dicabut, kunci dinonaktifkan; 3 percobaan penyerang 04:22-04:31
  ditolak. 12 server penyerang dihentikan; bukti diambil sebelumnya.
- Azure: service principal dimatikan, secret dihapus, kedua kunci storage diganti,
  4 VM dihentikan.
TANGGUNG JAWAB
- Kebocoran dan penanganannya di sisi PT JAB. Support case AWS dibuka 03:25;
  AWS sudah menempelkan policy karantina 02:52.
BELUM DIKETAHUI
- Apakah kunci atau repo ini dipakai pihak lain sebelum 00:47 (GitHub sedang ditanya
  lewat Tari Anjani); apakah ada salinan lain repo itu.
BERIKUTNYA
- Hapus resource penyerang di semua region dan subscription setelah bukti diverifikasi;
  pipeline deploy dipindah ke kredensial pendek; GuardDuty diaktifkan di semua region.
- DPO dan Legal menilai kewajiban pemberitahuan (data pelanggan terunduh).
Update berikutnya: 07:00.
```

Cara membaca elemennya:

- **Angka data ditulis lengkap dengan jenis datanya**, karena itu yang ditanyakan direksi dan DPO, dan dipisah dari Azure yang tidak berisi data pribadi.
- **"Tanggung jawab" satu baris saja**: menjawab pertanyaan pertama Hendra tanpa mencari pihak lain untuk disalahkan.
- **Bukti containment disebut**: tiga percobaan yang ditolak, bukan hanya "kunci sudah dinonaktifkan".

### 2.6 Rencana eradication dan kriteria selesai

Rencana ini menjawab pertanyaan 7 Hendra. Kolom R dan A mengikuti RACI PT JAB (Day 02 bagian 2.2).

| Waktu | Tindakan | R | A | Verifikasi |
|---|---|---|---|---|
| Selasa 10:00 | Verifikasi hash bukti E01 sampai E10; terminate 12 instance, hapus key pair, security group, dan snapshot non-bukti di dua region | Sari, Lutfi | IC | Query inventaris bagian 2.2 hanya menampilkan instance sah |
| Selasa 10:30 | Hapus 4 VM, disk, NSG, dan IP publik penyerang di `rg-jab-reporting`; snapshot E06 dipertahankan | Lutfi | IC | Daftar resource group cocok dengan inventaris sah |
| Selasa 11:00 | Hapus access key lama (ID dicatat); user `ci-deploy-selfcare` dihapus setelah pipeline baru jalan | Lutfi | IC | Tidak ada kunci aktif di user |
| Selasa 13:00 | Pipeline CI memakai federasi OIDC ke role AWS dengan izin per bucket; service principal pelaporan memakai federated credential tanpa secret | Lutfi, Tari | Hendra (perubahan arsitektur) | Deploy uji berhasil tanpa rahasia tersimpan |
| Selasa 14:00 | GuardDuty di semua region aktif; data event untuk semua bucket berisi data pelanggan; resource log `jabrptstor01` ke Splunk | Sari | IC | Status per region; event uji muncul di Splunk |
| Selasa 15:00 | Pencarian ulang 30 hari untuk panggilan IAM, logging, dan S3 di daftar bagian 1.7 dari IP penyerang dan kedua identitas | Sari | IC | Tidak ada temuan baru |
| Rabu 2026-12-02 04:15 | Kriteria 24 jam bagian 1.7 dinilai | Sari | IC | Kelima kriteria terpenuhi atau insiden kembali ke scoping |

Cara membaca elemennya:

- **Terminate menunggu verifikasi bukti**, mengikuti urutan bagian 1.4.
- **Perubahan pipeline punya A Hendra**, karena mengubah cara tim aplikasi bekerja dan butuh dukungan di atas IC.
- **Logging yang kurang saat insiden masuk eradication** dan tidak hanya dicatat sebagai pelajaran, karena tanpa logging itu kriteria selesai insiden berikutnya tidak bisa dibuktikan.

## 3. Lab praktik

Lab ini memakai akun AWS dan tenant atau subscription Azure khusus lab yang terpisah dari pekerjaan, dengan anggaran dan alert biaya. Jangan memakai kunci, akun, atau data pekerjaan, dan jangan pernah menaruh kunci asli di repo publik untuk "menguji". Hapus semua resource lab setelah selesai.

1. **Kunci dan kredensial sementara.** Di akun lab, buat IAM user tanpa akses konsol dengan izin baca EC2 saja, buat access key, lalu panggil `aws sts get-session-token` dengan kunci itu dan simpan kredensial sementaranya di profil terpisah. Nonaktifkan access key. Coba `aws ec2 describe-regions` dengan profil kredensial sementara dan catat hasilnya. Lalu tempelkan `AWSDenyAll` ke user dan coba lagi. Bandingkan hasilnya dengan bagian 1.3.
2. **CloudTrail.** Cari semua panggilan langkah 1 di event history dengan `lookup-events`, lalu di trail (bila kamu membuatnya). Catat batas event history yang kamu alami dibanding bagian 1.2.
3. **Connection tracking.** Jalankan instance kecil dengan security group yang mengizinkan SSH hanya dari IP-mu. Buka sesi SSH, lalu hapus aturan SSH. Apakah sesi terputus? Ulangi dengan NACL deny di subnet. Catat perbedaannya dan cocokkan dengan bagian 1.4.
4. **Snapshot sebagai bukti.** Buat snapshot volume instance langkah 3 dengan tag nomor insiden latihan. Catat ID snapshot, waktu, dan pembuatnya di evidence log dengan format Day 04 bagian 2.5.
5. **Service principal Azure.** Di tenant lab, buat app registration dengan secret dan beri peran Reader di satu resource group. Login dengan secret itu, daftar resource, lalu matikan `accountEnabled` dan hapus secret. Cari sign-in service principal di Entra ID dan operasi di Activity Log.
6. **Storage key.** Buat storage account lab, panggil `az storage account keys list`, lalu cari operasi `listKeys` di Activity Log. Unggah dan unduh satu blob dengan kunci itu. Apakah unduhan muncul di Activity Log? Aktifkan resource log blob dan ulangi.

**Hasil yang sebaiknya tersimpan:**

- `latihan/day16-kredensial-sementara.md`: hasil langkah 1 dan 2, termasuk apa yang masih berjalan setelah kunci dinonaktifkan.
- Catatan langkah 3 tentang perilaku security group dan NACL.
- Evidence log snapshot dari langkah 4.
- `latihan/day16-azure.md`: hasil langkah 5 dan 6, termasuk log mana yang mencatat apa.

**Variasi tantangan:** tulis update satu halaman dengan format bagian 2.5 untuk skenario lab-mu sendiri: kunci lab "bocor", satu resource dibuat di region lain, satu objek S3 diunduh dengan data event mati. Bagaimana kamu menulis bagian "data" tanpa bukti unduhan?

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat respons insiden cloud. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Aktivitas berlanjut setelah access key dinonaktifkan | Kredensial sementara dari `GetSessionToken` atau sesi role masih berlaku | Tempel deny policy ke user, atau revoke sessions untuk role [S2][S3] |
| Pencarian dengan ID kunci tidak menemukan aktivitas sesudah jam tertentu | Penyerang pindah ke kredensial sementara dengan ID kunci berbeda | Cari dengan ARN user, bukan ID kunci saja |
| Event history tidak menunjukkan aktivitas di region lain | Event history per region | Cari per region, atau pakai trail multi-region [S5] |
| Tidak bisa menjawab objek S3 mana yang dibaca | Data event tidak aktif untuk bucket itu | Tulis "tidak bisa disingkirkan"; aktifkan data event untuk bucket sensitif [S6] |
| Sesi SSH penyerang tetap hidup setelah security group diganti | Connection tracking | Tambah NACL deny di subnet atau hentikan instance [S7] |
| GuardDuty tidak menghasilkan finding untuk instance penyerang | GuardDuty tidak aktif di region itu | Aktifkan di semua region; andalkan CloudTrail multi-region [S8] |
| Aplikasi berhenti setelah storage key diputar | Klien masih memakai kunci lama | Perbarui klien; pindah ke managed identity [S15] |
| `az ad app credential reset` menghapus semua credential sebelum dicatat | `reset` tanpa `--append` menimpa semua credential | Jalankan `credential list` dulu dan simpan keluarannya [S14] |
| Tidak tahu siapa pembuat resource Azure yang berumur lebih dari 90 hari | Activity Log tidak diekspor | Ekspor lewat diagnostic setting sebelum insiden [S10] |

## 5. Kesalahan umum dan jebakan

- Menonaktifkan access key dan menganggap selesai. Kredensial sementara yang sudah terbit tetap berlaku sampai izin user dicabut [S2].
- Menghapus access key sebelum ID-nya dicatat, sehingga pencarian log berikutnya kehilangan kata kunci [S1].
- Langsung terminate resource penyerang, sehingga user data, konfigurasi, dan disk hilang sebelum dibaca [S9].
- Mengandalkan penggantian security group untuk memutus sesi yang sedang berjalan [S7].
- Hanya memeriksa region yang biasa dipakai. Penyerang sengaja memakai region lain [S1].
- Melepas policy karantina AWS karena dianggap mengganggu. Dokumentasinya meminta policy itu tidak dilepas [S4].
- Menulis "tidak ada data yang diakses" padahal data event atau resource log tidak aktif.
- Mematikan service principal tetapi tidak memutar rahasia yang bisa dibacanya, misalnya storage key [S13][S15].
- Menjalankan containment dengan kunci atau identitas yang termasuk scope.
- Menganggap ini kesalahan satu developer dan berhenti di situ. Akar masalahnya kunci jangka panjang yang bisa disalin.

## 6. Catatan terkini

Bagian ini menampung detail versi dan perilaku produk yang bisa berubah. Berguna saat memakai fitur yang disebut, tetapi tidak mengubah urutan respons.

- **`AWSCompromisedKeyQuarantineV3`** dibuat Agustus 2024 dan terakhir diedit 16 Maret 2026; daftar aksi yang ditolaknya berubah dari versi ke versi [S4]. Playbook AWS masih menyebut versi V2 [S1]. Cari kedua nama saat memeriksa credential report.
- **GuardDuty** terus menambah dan mempensiunkan finding type, termasuk finding Extended Threat Detection seperti `AttackSequence:IAM/CompromisedCredentials` [S8]. Cek daftar terbaru di dokumentasi.
- **Connection tracking EC2:** instance Nitro v6 punya timeout TCP established default 350 detik, sedangkan instance lain 432.000 detik [S7]. Jenis instance memengaruhi berapa lama koneksi lama bertahan setelah aturan diubah.
- **Azure Activity Log:** halaman yang diperiksa bertanggal 4 Mei 2026; metode ekspor lama (log profiles) disebut sebagai metode legacy dan diganti diagnostic setting [S10].
- **ATT&CK v20:** Resource Hijacking (T1496) kini punya sub-teknik, termasuk Compute Hijacking (T1496.001) dan Cloud Service Hijacking (T1496.004) [S18].

## 7. Cheat sheet

```
KUNCI = IDENTITAS. Log API adalah saksi utama. Log yang tidak aktif tidak bisa diminta mundur.

LOG (cek sebelum insiden)
  AWS  event history 90 hari, management saja, per region | trail multi-region | data event S3 per bucket
  Azure Activity Log 90 hari, control plane | resource log data plane harus diaktifkan | sign-in SP di Entra
  GuardDuty per region

URUTAN
  1 amankan log (cek StopLogging/DeleteTrail), ekspor ke bukti
  2 scoping: cari by ARN user, bukan hanya ID kunci (AKIA vs ASIA)
  3 bukti: metadata + user data + snapshot (stop, bukan terminate; DeleteOnTermination off)
  4 jam H: AWSDenyAll/TokenIssueTime deny + key Inactive (jangan hapus dulu)
           role: Revoke active sessions (AWSRevokeOlderSessions)
           Azure SP: accountEnabled=false + catat credential + hapus + putar storage key/secret
  5 eradication: semua region/subscription, hapus resource penyerang, kunci lama dihapus
  6 cegah: OIDC/federated credential/managed identity, GuardDuty semua region, data event

JEBAKAN
  key Inactive != kredensial sementara mati (default 12 jam, maks 36 jam)
  ganti security group != sesi lama putus (connection tracking) -> NACL
  quarantine policy AWS = rem darurat, jangan dilepas, bukan containment
  listKeys tercatat; baca blob dengan key tidak tercatat tanpa resource log
  credential reset tanpa --append menghapus semua credential

DATA: GetObject + bytesTransferredOut == ukuran objek -> terunduh penuh
      jumlah baris dari isi objek, bukan dari CloudTrail
      tanpa data event: "tidak bisa disingkirkan"

ATT&CK v20: T1552.001 (kunci di berkas) | T1078.004 (akun cloud sah) | T1496 (mining) | T1530 (data storage cloud)
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Access key `AKIAUJAB7EXAMPLE4Q2W` sudah berstatus Inactive sejak 04:15, jadi penyerang sudah tidak bisa memanggil API AWS PT JAB." Benarkah?

<details><summary>Jawaban</summary>

Belum tentu. Penyerang memanggil `GetSessionToken` pukul 00:58 dan memegang kredensial sementara berawalan `ASIA` yang berlaku sampai kedaluwarsa, default 12 jam. AWS menyebut kredensial sementara berlaku sampai kedaluwarsa dan izin user yang menerbitkannya harus diubah untuk menghentikannya. Karena itu PT JAB menempelkan `AWSDenyAll` bersamaan dengan menonaktifkan kunci, dan validasi menunjukkan tiga percobaan dengan kredensial `ASIA` setelah jam H ditolak. Lihat bagian 1.3 dan 2.2.

</details>

**2. Skenario keputusan.** Pukul 03:50, Lutfi menemukan 12 instance asing di dua region. Apa yang dilakukan?

- A. Terminate semua sekarang supaya biaya berhenti, karena instance itu milik penyerang dan tidak berisi data PT JAB.
- B. Ambil metadata dan user data semua instance, snapshot sampel per region, pastikan shutdown behavior stop, lalu stop semua instance; terminate setelah bukti diverifikasi.
- C. Biarkan berjalan beberapa jam untuk melihat ke mana miner terhubung.

<details><summary>Jawaban</summary>

B. User data, metadata, dan disk adalah bukti yang hilang begitu instance di-terminate, dan isinya (alamat unduhan miner, pool) menjadi IOC untuk pencarian lain. Menghentikan instance menghentikan biaya komputasi tanpa menghapus disk. A keliru karena menghapus bukti sebelum dibaca. C keliru karena biaya dan aktivitas penyerang berjalan terus tanpa keuntungan berarti; tujuan miner sudah terlihat dari user data. Lihat bagian 1.4 dan 2.2.

</details>

**3. Pertanyaan jebakan.** "Kita cukup buka CloudTrail event history di konsol untuk melihat berkas S3 mana yang diunduh penyerang." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Event history hanya berisi management event; `GetObject` adalah data event, dan trail maupun event data store tidak mencatat data event kecuali diaktifkan per resource. PT JAB bisa menjawab karena data event S3 sudah diaktifkan untuk bucket ekspor sebelum insiden. Tanpa itu, kesimpulannya hanya "pengunduhan tidak bisa dibuktikan atau disingkirkan". Lihat bagian 1.2, 1.5, dan 2.3.

</details>

**4. Skenario keputusan.** Secret `sp-selfcare-reporting` terbukti bocor dan dipakai. Containment mana yang paling tepat?

- A. Hapus secret yang bocor saja, karena hanya itu yang terpapar.
- B. Matikan sign-in service principal, catat lalu hapus semua credential lama, putar kedua storage key yang dibaca lewat `listKeys`, hentikan resource yang dibuat, dan periksa Activity Log serta sign-in service principal.
- C. Hapus seluruh resource group `rg-jab-reporting` supaya pasti bersih.

<details><summary>Jawaban</summary>

B. Service principal punya peran Contributor yang memungkinkan `listKeys`, dan storage key memberi akses penuh ke data storage terlepas dari service principal. Menghapus secret saja (A) meninggalkan storage key yang sudah dipegang penyerang. C menghapus bukti dan layanan pelaporan sah sekaligus, padahal resource penyerang bisa dihapus satu per satu setelah snapshot diambil. Lihat bagian 1.6 dan 2.4.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Lutfi Hakim (Lead DevOps), dalam tiga kalimat, kenapa pipeline deploy harus berhenti memakai access key jangka panjang walaupun developer yang menyalin repo sudah ditegur.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Selama pipeline butuh kunci yang berlaku bertahun-tahun, kunci itu akan tersalin ke tempat yang tidak kita kontrol, entah repo, laptop, atau log build, dan siapa pun yang memegangnya bisa memakainya dari mana saja tanpa MFA. Kalau pipeline meminta kredensial pendek per job lewat OIDC atau federated credential, tidak ada rahasia yang bisa tertinggal di berkas konfigurasi, dan yang bocor pun kedaluwarsa dalam hitungan menit atau jam. Menegur satu orang hanya menutup satu kejadian; mengganti mekanisme menutup seluruh kelas kejadian ini."

Kesalahan yang sering muncul:
- Menyalahkan developer sebagai akar masalah.
- Tidak menyebut bahwa kunci jangka panjang bisa dipakai dari mana saja.
- Hanya menyarankan "simpan kunci di vault" tanpa menyebut kredensial pendek sebagai pengganti kunci.

</details>

**6. Pertanyaan jebakan.** "GuardDuty PT JAB tidak menghasilkan finding apa pun tentang server mining, jadi server itu belum tentu buatan penyerang." Benarkah?

<details><summary>Jawaban</summary>

Tidak. GuardDuty diaktifkan per region, dan di PT JAB hanya aktif di `ap-southeast-3`. Server mining dibuat di Singapura dan Virginia, region tanpa GuardDuty, sehingga ketiadaan finding tidak berarti apa-apa. Buktinya ada di CloudTrail multi-region: 12 `RunInstances` dengan kredensial sementara dari IP penyerang. Lihat bagian 1.2, 1.7, dan 2.1.

</details>

**7. Interview question (English).** "An AWS access key from your CI pipeline was found in a public GitHub repo and AWS has already attached a quarantine policy. Walk me through your first hours."

<details><summary>Sample answer</summary>

"First I'd make sure the logs are safe: confirm CloudTrail is still running in every region and export the relevant events, because in the cloud the API logs are the whole investigation. Then I'd scope by the IAM user's ARN rather than just the key ID, since attackers often call GetSessionToken and switch to temporary credentials that the original key ID won't match. I'd treat AWS's quarantine policy as an emergency brake, not containment, and leave it attached. Before touching anything the attacker created, I'd capture instance metadata, user data and a sample snapshot, then stop rather than terminate. Containment happens together: attach a deny-all policy to the user so temporary credentials die too, deactivate the key without deleting it, revoke sessions on any roles it could assume, and rotate any secrets the identity could read. Then I check every region for resources, look for IAM persistence attempts including denied calls, answer the data question with S3 data events if they were enabled, and replace the long-lived key with short-lived OIDC credentials so this class of leak can't recur."

What makes this answer strong: it starts with log preservation, catches the temporary-credential trap, preserves evidence before cleanup, coordinates containment, checks all regions, and fixes the root cause instead of the person.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | AWS Customer Playbook Framework: Compromised IAM Credentials | https://github.com/aws-samples/aws-customer-playbook-framework/blob/main/docs/Compromised_IAM_Credentials.md | primer (contoh resmi vendor) | tanpa tanggal; diakses 2026-10-15 | Tinggi. Support case, panggilan API yang dicari, nonaktifkan lalu hapus kunci, revoke sessions role, semua region, pelajaran kunci jangka panjang |
| S2 | AWS IAM User Guide: Disabling permissions for temporary security credentials | https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_disable-perms.html | primer | diakses 2026-10-15 | Tinggi. Kredensial sementara berlaku sampai kedaluwarsa (15 menit sampai 36 jam, default 12 jam), izin dievaluasi setiap pemakaian, `AWSDenyAll`, batas root |
| S3 | AWS IAM User Guide: Revoke IAM role temporary security credentials | https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html | primer | diakses 2026-10-15 | Tinggi. `AWSRevokeOlderSessions`, jeda sekitar 30 detik, `aws:TokenIssueTime` tidak berlaku untuk kunci jangka panjang |
| S4 | AWS Managed Policy Reference: AWSCompromisedKeyQuarantineV3 | https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSCompromisedKeyQuarantineV3.html | primer | dibuat 2024-08-21, diedit 2026-03-16; diakses 2026-10-15 | Tinggi. Aksi yang ditolak, larangan melepas policy |
| S5 | AWS CloudTrail User Guide: Working with CloudTrail event history | https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html | primer | diakses 2026-10-15 | Tinggi. 90 hari, management event saja, per region, satu atribut filter |
| S6 | AWS CloudTrail User Guide: Logging data events | https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html | primer | diakses 2026-10-15 | Tinggi. Data event tidak dicatat default, biaya tambahan, selector per resource |
| S7 | Amazon EC2 User Guide: Security group connection tracking | https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-connection-tracking.html | primer | diakses 2026-10-15 | Tinggi. Koneksi tercatat tidak terputus saat aturan diubah, NACL untuk memutus, aliran tidak di-track, timeout |
| S8 | Amazon GuardDuty User Guide: GuardDuty finding types | https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html | primer | diakses 2026-10-15 | Tinggi. Daftar finding IAM, EC2, S3, attack sequence |
| S9 | AWS Customer Playbook Framework: EC2 Forensics | https://github.com/aws-samples/aws-customer-playbook-framework/blob/main/docs/EC2_Forensics.md | primer (contoh resmi vendor) | tanpa tanggal; diakses 2026-10-15 | Sedang sampai tinggi. Memori sebelum isolasi, shutdown behavior stop, `DeleteOnTermination`, security group isolasi, metadata yang dicatat; langkah berbasis konsol |
| S10 | Microsoft Learn: Activity Log in Azure Monitor | https://learn.microsoft.com/en-us/azure/azure-monitor/platform/activity-log | primer | ms.date 2026-05-04; diakses 2026-10-15 | Tinggi. Control plane vs data plane, 90 hari, pembuat resource, ekspor, format Event Hub |
| S11 | Microsoft Learn: Computer forensics chain of custody in Azure | https://learn.microsoft.com/en-us/azure/architecture/example-scenario/forensics/ | primer | ms.date 2026-04-10; diakses 2026-10-15 | Tinggi untuk alur snapshot ke storage immutable dan hash; dokumen arsitektur, bukan prosedur hukum |
| S12 | Microsoft Learn: Create a snapshot of an Azure managed disk | https://learn.microsoft.com/en-us/azure/virtual-machines/snapshot-copy-managed-disk | primer | ms.date 2026-09-17; diakses 2026-10-15 | Tinggi. `az snapshot create`, snapshot point-in-time OS atau data disk |
| S13 | Microsoft Learn: Compromised and malicious applications investigation | https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-compromised-malicious-app | primer | ms.date 2025-03-12; diakses 2026-10-15 | Tinggi. Sign-in service principal, aktivitas audit credential, `accountEnabled` false, penghapusan credential, prioritas rotasi secret |
| S14 | Microsoft Learn: az ad app credential | https://learn.microsoft.com/en-us/cli/azure/ad/app/credential | primer | ms.date 2026-06-26; diakses 2026-10-15 | Tinggi. `list`, `delete`, `reset` dan perilaku tanpa `--append`, saran managed identity |
| S15 | Microsoft Learn: Manage storage account access keys | https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage | primer | ms.date 2026-08-11; diakses 2026-10-15 | Tinggi. Akses penuh, rotasi bila terkompromi, `keys renew`, SAS ikut dicabut, peran dengan `listkeys/action` |
| S16 | MITRE ATT&CK: Valid Accounts: Cloud Accounts (T1078.004) | https://attack.mitre.org/techniques/T1078/004/ | primer | v2.0, diubah 2026-05-12; ATT&CK v20; diakses 2026-10-15 | Tinggi. Pemakaian akun dan kunci cloud sah, termasuk kunci dari repo publik |
| S17 | MITRE ATT&CK: Unsecured Credentials: Credentials In Files (T1552.001) | https://attack.mitre.org/techniques/T1552/001/ | primer | v1.3, diubah 2026-09-11; ATT&CK v20; diakses 2026-10-15 | Tinggi. Kredensial di berkas konfigurasi |
| S18 | MITRE ATT&CK: Resource Hijacking (T1496) | https://attack.mitre.org/techniques/T1496/ | primer | v2.0, diubah 2025-10-24; ATT&CK v20; diakses 2026-10-15 | Tinggi. Sub-teknik termasuk Compute Hijacking dan Cloud Service Hijacking |
| S19 | MITRE ATT&CK: Data from Cloud Storage (T1530) | https://attack.mitre.org/techniques/T1530/ | primer | v2.2, diubah 2026-05-12; ATT&CK v20; diakses 2026-10-15 | Tinggi |
| S20 | Cybr: My AWS IAM access keys were exposed and exploited, what should I do? (cheat sheet) | https://cybr.com/?p=21730 | komunitas | 2024-01-16, diperbarui 2024-06-18; diakses 2026-10-15 | Sedang. Validasi kunci, scoping dengan Athena, deny-all ke user, peran analis terpisah; dipakai sebagai pembanding praktik, selaras dengan S1 |

**Catatan sumber:** pembagian tanggung jawab di bagian 1.1 ditulis dari isi playbook AWS dan dokumen Microsoft yang disebut, bukan dari dokumen shared responsibility resmi kedua penyedia. Cara CloudTrail mencatat identitas untuk kredensial dari `GetSessionToken` (ARN user dengan ID kunci berawalan `ASIA`) ditulis dari struktur umum CloudTrail; cocokkan dengan record di akunmu. Nama sourcetype Splunk, field Activity Log setelah diolah add-on, dan cara service principal muncul di field `caller` perlu dicek di lingkunganmu. Perintah `aws ec2 describe-instance-attribute`, `create-snapshot`, `stop-instances`, `aws s3api head-object`, dan `az vm deallocate` ditulis dari sintaks CLI umum, bukan dari halaman yang dikutip. Lima kriteria selesai di bagian 1.7 dan pembagian containment empat langkah di bagian 1.6 adalah susunan catatan ini dari sumber yang disebut. Cheat sheet komunitas [S20] hanya dipakai sebagai pembanding dan tidak menjadi satu-satunya dasar klaim. Semua isi PT JAB, termasuk ID akun, ID kunci, GUID, nama resource, angka baris, dan waktu, adalah contoh fiktif.
