---
day: 22
title: 'Disk dan volume terenkripsi: BitLocker, VeraCrypt, dan implikasinya pada akuisisi'
researched_on: 2026-10-22
versions_checked: 'Windows 11 Enterprise 24H2 (host kasus, build 26100); manage-bde (Microsoft Learn, ms.date 2025-12-15, diperbarui 2026-02-16); BitLocker recovery overview dan BitLocker recovery process (ms.date 2025-07-29, diperbarui 2026-10-08); BitLocker overview (ms.date 2026-08-24); Microsoft Graph Get bitlockerRecoveryKey (ms.date 2024-10-24); Microsoft Entra manage device identities (ms.date 2026-06-17); Intune BitLocker (ms.date 2025-11-26); VeraCrypt 1.26.29 (rilis 2026-06-09); Volatility 3 2.28.2; dislocker (cabang master, tanpa rilis bertag); rujukan Day 01, 02, 03, 07, 09, 10, 14, 18, 20'
---

# Day 22: Disk dan volume terenkripsi

Cakupan: apa yang berubah pada keputusan dan urutan akuisisi ketika disk terenkripsi, cara memperoleh kunci BitLocker lewat jalur yang sah dan tercatat, tindakan yang memaksa mode recovery, memori sebagai sumber kunci, cara membuka volume untuk analisis tanpa mengubah bukti, dan cara mengenali kontainer VeraCrypt beserta batas kesimpulannya.

## Ide inti

Seluruh alur di Day 01 sampai Day 20 mengandaikan satu hal: isi disk bisa dibaca begitu image ada di tanganmu. Enkripsi volume mematahkan andaian itu, dan memindahkan keputusan terpenting kasus dari laboratorium ke menit pertama di lokasi. Pada sistem terenkripsi yang masih menyala dan volumenya sedang terbuka (ter-unlock), isi disk bisa dibaca sekarang oleh siapa pun yang punya hak di sistem itu, dan kunci volumenya ada di memori. Begitu daya putus, dua hal itu hilang. Yang tersisa adalah blok terenkripsi yang hanya bisa dibuka dengan kunci dari tempat lain: recovery key yang disimpan terpusat (escrow), kata sandi dari pemiliknya, atau kunci yang sempat tertangkap di image memori. Karena itu pertanyaan pertama di depan laptop terenkripsi bukan "bagaimana mengambil image", melainkan "apakah saya sudah memegang kuncinya, dan untuk volume mana saja". Jawabannya bisa berbeda untuk dua volume di laptop yang sama: BitLocker korporat punya kunci cadangan di escrow, sedangkan kontainer VeraCrypt milik pengguna tidak punya cadangan di mana pun.

Kamu sudah mengenal pola ini dari NOC. Bayangkan sesi console yang sudah login ke router pelanggan yang password enable-nya tidak kamu pegang. Selama sesi itu terbuka, kamu bisa menjalankan `show running-config` dan menyimpan hasilnya; begitu sesi putus, kamu tidak bisa masuk lagi tanpa password dari pelanggan atau dari brankas kredensial NOC. Engineer yang berpengalaman tidak me-reload router itu sebelum memastikan password ada di brankas, dan bila tidak ada, ia mengambil semua yang dibutuhkan dari sesi yang masih terbuka. Batas analoginya ada dua. BitLocker dengan TPM akan membuka dirinya lagi saat laptop di-boot normal di perangkat keras yang sama, jadi "sesi" BitLocker tidak benar-benar hilang saat dimatikan, hanya pindah ke tangan TPM; yang benar-benar hilang adalah isi memori dan volume VeraCrypt yang sedang ter-mount. Dan berbeda dengan brankas kredensial NOC, recovery key BitLocker membuka seluruh isi disk, sehingga setiap pengambilannya harus lewat persetujuan dan meninggalkan jejak audit.

```
laptop terenkripsi ditemukan
  |
  +-- MATI?  -> image fisik (blok terenkripsi) -> kunci dari escrow / pemilik -> buka di lab (read-only)
  |
  +-- MENYALA, volume ter-unlock?
        |
        1. jangan matikan, jangan tutup lid, jangan cabut, jangan restart
        2. memori dulu  (kunci BitLocker dan kunci VeraCrypt ada di RAM)
        3. status volume + ID protector  (manage-bde -status / -protectors -get)
        4. per volume: kuncinya ada di escrow?
              ya   -> ambil lewat jalur tercatat, cocokkan Key ID -> image fisik setelah mati cukup
              tidak -> image logis selagi volume terbuka (dengan izin), memori sebagai cadangan
        5. matikan dengan keputusan tertulis -> image fisik -> buka di lab dengan kunci
  |
  v
laporan: keberadaan enkripsi bukan bukti isi atau niat; tulis jalur kunci dan siapa memegangnya
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan, kantor pusat di Jakarta, dan POP regional di Bandung, Surabaya, dan Medan. Identitasnya hibrida: Active Directory on-prem `corp.jab.example` disinkronkan ke Microsoft Entra ID (lisensi Microsoft 365 E3 dengan Entra ID P1), dan workstation memakai Microsoft Defender for Endpoint Plan 2. Sampai Januari 2027, PT JAB belum pernah menghadapi disk terenkripsi di kasus forensik; rencana penguatan 2027 nomor 10 memintamu memeriksa bersama tim IT status enkripsi workstation dan lokasi recovery key-nya (Day 20 bagian 1.13). Pemeriksaan itu selesai lebih cepat dari target. Kamis 2027-02-04 Agung Prabowo (Lead Infrastruktur) melaporkan bahwa laptop gelombang pengadaan kedua 2026, yang dipasang dari gold image Windows 11 24H2 mulai November 2026, dienkripsi BitLocker secara otomatis lewat kebijakan Intune dengan protector TPM, dan recovery key-nya tersimpan di Entra ID dan sebagian juga di AD DS. Laptop yang lebih lama, dari gold image 23H2, tidak terenkripsi; semua laptop di kasus forensik 2026 dan Januari 2027 termasuk kelompok ini.

Lima hari kemudian, Selasa 2027-02-09, kasus pertamanya datang. Antara pukul 02:14 dan 07:52 WIB, Defender for Endpoint menaikkan sepuluh alert (`SOC-2027-0120` sampai `SOC-2027-0129`) untuk `BDG-WS-0185`, laptop Ilham Maulana (`ilham.maulana`), engineer jaringan POP Bandung: program tak bertanda tangan dari folder profil yang dijalankan scheduled task, koneksi berkala ke alamat eksternal, enumerasi share, dan pembuatan arsip di folder sementara. Ilham meninggalkan laptopnya menyala dan terkunci di meja POP sejak Senin malam. Rudi Hartanto, analyst L2 yang memegang on-call forensik primer sejak 1 Februari, mengisolasi laptop lewat Defender pukul 08:05, dan Dimas Prasetyo (SOC lead, incident commander) menetapkan `INC-2027-012` berseverity SEV-3 pukul 08:10. Fajar Nugraha, teknisi POP Bandung, sudah berdiri di depan laptop itu. Pukul 08:28 Rudi menulis kepadamu sebagai jalur eskalasi di kanal `#inc-2027-012`:

> "Mas, `BDG-WS-0185` ini laptop baru 24H2, jadi BitLocker. Masih nyala, layar terkunci, charger nyambung, sudah saya isolasi 08:05. Dari live response ada `VeraCrypt.exe` jalan di sesi Ilham, dan `History.xml` VeraCrypt menunjuk ke `Documents\Arsip\konfig-bdg.dat` ukuran 8 GiB. Ilham di telepon bilang itu kontainer pribadinya buat backup konfigurasi CPE pelanggan dedicated, dan masih ter-mount sebagai `V:` sejak Senin siang. Fajar tanya, boleh dimatikan lalu SSD-nya dicabut dan di-image seperti biasa? Saya belum pernah pegang laptop BitLocker. Yang saya perlu sebelum Fajar bergerak: dimatikan atau tidak? Urutannya apa: memori dulu, image logis dari volume yang terbuka, atau image fisik plus recovery key? Siapa yang boleh ambil recovery key dan bagaimana tercatatnya? Apa yang terjadi kalau SSD dicabut, laptop di-boot dari USB, atau BIOS-nya diubah? Bisa tidak kuncinya diambil dari memori? Nanti di Jakarta volumenya dibuka bagaimana tanpa mengubah bukti? Terakhir, kontainer VeraCrypt itu: bagaimana memastikan itu kontainer, dan apa yang boleh kita tulis soal isinya?"

Pesan itu memuat tujuh pertanyaan:

1. Apakah laptop dimatikan sekarang, dan kenapa?
2. Urutan akuisisi mana yang dipakai: memori, image logis volume yang ter-unlock, atau image fisik plus recovery key?
3. Siapa yang boleh mengambil recovery key, lewat jalur apa, dan bagaimana pengambilannya tercatat?
4. Apa yang terjadi bila perangkat keras atau jalur boot berubah (SSD dicabut, boot dari USB, BIOS diubah)?
5. Bisakah memori menjadi sumber kunci, dan apa yang realistis diharapkan darinya?
6. Bagaimana volume dibuka untuk analisis tanpa mengubah bukti?
7. Bagaimana mengenali kontainer VeraCrypt, dan apa yang tidak bisa disimpulkan darinya?

Pertanyaan 1 dan 2 dijawab di bagian 1.1 dan 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, pertanyaan 6 di bagian 1.6, dan pertanyaan 7 di bagian 1.7. Bagian 2 berisi status enkripsi PT JAB, case notes pagi itu, perintah dan keluaran ilustrasi tiap langkah akuisisi, cara membuka image di Jakarta, dan catatan keputusan yang kamu kirim ke Rudi.

**Kapan relevan:** setiap kali host yang akan diakuisisi memakai BitLocker, device encryption Windows, VeraCrypt, atau enkripsi volume lain, terutama bila host masih menyala; juga saat menyusun prosedur akuisisi dan kebijakan escrow kunci sebelum insiden.
**Kapan bukan jawaban:** Day ini tidak membahas cara membobol enkripsi, menebak kata sandi, atau menyerang kunci; yang dibahas hanya jalur sah (kunci dari escrow, volume yang ter-unlock, memori host yang hidup, dan kata sandi yang diberikan pemilik) beserta batasnya. Day ini juga tidak membahas enkripsi per file (EFS, Personal Data Encryption), enkripsi perangkat mobile, atau self-encrypting drive pada level firmware.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (order of volatility, akuisisi memori, live response, image disk penuh, triage collection, salinan kerja, read-only mount, chain of custody, hash bukti, jejak responder, smear) tidak diulang. Tabel berikut hanya memuat istilah baru yang dipakai di Day ini; kolom padanan memakai analogi NOC dan SOC yang sama di semua Day.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Volume terenkripsi ter-unlock | Volume yang kuncinya sudah dimuat sehingga sistem membaca isinya sebagai plaintext | Sesi console yang sudah login ke perangkat yang password-nya tidak kamu pegang |
| Key protector | Cara melindungi kunci volume BitLocker: TPM, PIN, recovery password, recovery key, sertifikat DRA | Beberapa metode login ke perangkat yang sama: console lokal, TACACS, kunci SSH |
| TPM-only | Protector yang membuka volume otomatis saat boot bila rantai boot dan perangkat keras tidak berubah | Perangkat yang auto-login dari kredensial tersimpan selama chassis dan firmware sama |
| Recovery password | Angka 48 digit (8 blok 6 digit) yang membuka volume BitLocker dalam mode recovery | Password break-glass perangkat di brankas kredensial NOC |
| Recovery key (`.bek`) | Berkas kunci di media lepasan dengan nama `<protector_id>.bek` | Token fisik cadangan untuk login darurat |
| Key ID | Identitas protector recovery password; tampil di layar recovery dan dipakai mencari kunci di escrow | Nomor seri perangkat yang dicocokkan ke entri brankas, bukan nama host |
| Escrow kunci | Penyimpanan terpusat recovery key: Microsoft Entra ID, AD DS, atau tempat lain yang ditetapkan kebijakan | Brankas kredensial NOC yang setiap pengambilannya tercatat |
| Mode recovery | Keadaan saat BitLocker menolak membuka volume secara otomatis dan meminta recovery password atau recovery key | Perangkat yang menolak boot karena tanda tangan image firmware tidak cocok |
| Clear key | Kunci tidak terproteksi yang ditaruh di metadata volume saat BitLocker disuspend; volume tetap terenkripsi tetapi bisa dibuka tanpa kunci rahasia | Password yang ditempel di casing perangkat selama maintenance |
| Key package | Paket kunci untuk BitLocker Repair Tool, dipakai menyelamatkan volume yang rusak | Backup NVRAM yang hanya berguna bila flash rusak |
| Image logis | Salinan isi volume sebagaimana dibaca sistem operasi (plaintext bila volume ter-unlock), tanpa ruang di luar volume | Ekspor `show running-config` dari sesi yang sedang terbuka |
| Image fisik | Salinan bit-per-bit seluruh media, termasuk blok terenkripsi | Salinan penuh flash router, terenkripsi atau tidak |
| Kontainer VeraCrypt | Berkas biasa yang isinya volume terenkripsi VeraCrypt, tanpa tanda tangan yang bisa dikenali | Tunnel IPsec: terlihat ada lalu lintas berukuran tertentu, isinya tidak |
| Hidden volume | Volume VeraCrypt kedua di dalam ruang kosong volume luar, dirancang tidak bisa dibuktikan keberadaannya | Kanal tersembunyi di dalam tunnel yang sudah terenkripsi |

### 1.1 Enkripsi membalik urutan akuisisi: kenapa laptop tidak dimatikan dulu

Pertanyaan pertama Rudi ("dimatikan atau tidak?") datang dari kebiasaan yang benar untuk disk tidak terenkripsi: laptop yang sudah diisolasi dan memorinya tidak dibutuhkan boleh dimatikan, lalu disk di-image lewat write blocker. Pada laptop BitLocker yang masih menyala, kebiasaan itu perlu diperiksa dulu, karena mematikan mesin menghapus dua hal yang tidak bisa dibuat ulang: isi memori, termasuk kunci volume, dan semua volume yang terbuka tanpa cadangan kunci, di sini kontainer VeraCrypt `V:`.

Order of volatility dari Day 01 bagian 1.3 tetap berlaku; yang berubah adalah apa yang dipertaruhkan di urutan pertama. Pada disk biasa, memori diambil karena berisi proses dan koneksi. Pada disk terenkripsi, memori juga berisi kunci, dan volume yang ter-unlock adalah satu-satunya keadaan saat isi disk bisa dibaca tanpa kunci dari luar. Tabel berikut merangkum keadaan sistem dan urutan yang masuk akal; baca kolom kedua sebagai urutan prioritas, bukan resep yang harus dijalankan semuanya.

| Keadaan sistem | Urutan yang masuk akal |
|---|---|
| Hidup, volume ter-unlock | Memori lebih dulu, lalu akuisisi logis atau image dari dalam sistem hidup, baru pertimbangkan mematikan |
| Hidup, volume terkunci | Memori tetap diambil, lalu cari protector dan recovery password sebelum mematikan |
| Mati, terenkripsi | Image disk tetap diambil sebagai blok terenkripsi, lalu dekripsi dilakukan setelah kunci diperoleh |

Pembalikan ini punya konsekuensi dokumentasi. Akuisisi dari sistem hidup selalu mengubah sistem, dan itu harus ditulis apa adanya di catatan kasus: apa yang dijalankan, kapan, oleh siapa, dan kenapa alternatifnya lebih buruk (Day 01 dan Day 19).

Image disk terenkripsi tetap layak diambil meskipun belum punya kunci. Ia adalah bukti yang membeku, dan kunci bisa muncul belakangan dari AD, dari Entra ID, atau dari pemilik perangkat.

Di `BDG-WS-0185`, jawabannya ke Rudi: jangan matikan dulu. Laptop sudah diisolasi lewat Defender, jadi penyerang tidak lagi punya jalur jaringan ke host itu, dan isolasi tidak mengubah status volume. Menunda pematian sekitar dua jam untuk mengambil memori, membaca status BitLocker, memastikan recovery key ada dan cocok, dan mengambil image logis `V:` tidak menambah risiko yang berarti, sedangkan mematikan lebih dulu bisa menghapus satu-satunya salinan plaintext isi kontainer VeraCrypt. Selama menunggu, Fajar menjaga laptop tetap menyala: charger tetap tersambung, lid tidak ditutup, tidak ada restart, dan tidak ada pembaruan yang dijalankan.

Kapan mematikan lebih dulu justru benar? Bila ada tanda proses destruktif sedang berjalan (enkripsi ransomware, penghapusan massal), bila host tidak bisa diisolasi dan penyerang masih aktif, atau bila tidak ada orang yang bisa mengakuisisi memori dalam waktu wajar. Keputusan itu sah selama alasannya tertulis dan konsekuensinya (volume tanpa cadangan kunci ikut tertutup) disebut.

### 1.2 Anatomi BitLocker yang perlu diketahui pemeriksa

Pertanyaan kedua Rudi (urutan mana yang dipakai) tidak bisa dijawab sebelum tahu bagaimana volume itu dilindungi. BitLocker mengenkripsi seluruh volume dengan satu kunci, lalu melindungi kunci itu dengan satu atau lebih key protector. Volume yang sama bisa dibuka lewat protector mana pun yang terpasang, sehingga yang penting bagi pemeriksa adalah daftar protector, bukan hanya status "terenkripsi".

`manage-bde` adalah alat baris perintah yang mengelola semuanya: `-status` melaporkan keadaan seluruh drive, `-protectors` mengelola metode perlindungan kunci, dan `-unlock` membuka akses memakai recovery password atau recovery key [S1]. Subperintah lain mengubah keadaan volume (`-lock`, `-pause`, `-off`, `-forcerecovery`, `-wipefreespace`) dan tidak pernah dijalankan pada sistem bukti [S1].

Tiga jalan masuk yang sah bagi pemeriksa [S2]:

- **Recovery password.** Angka 48 digit yang membuka volume dalam mode recovery. Bisa disimpan di Microsoft Entra ID, di AD DS, sebagai berkas teks, atau dicetak.
- **Recovery key.** Kunci dalam berkas di media lepasan dengan format nama `<protector_id>.bek`.
- **Data Recovery Agent.** Sertifikat yang terkait dengan principal Active Directory, berfungsi sebagai kunci induk untuk semua volume yang dikonfigurasi dengan kunci publik yang cocok. Untuk volume sistem, drive harus dipasang sebagai data drive di mesin lain agar DRA bisa membukanya [S2].

Ada jalan keempat untuk keadaan darurat. **Key package** adalah kunci dekripsi yang dipakai bersama BitLocker Repair Tool untuk merekonstruksi bagian penting drive dan menyelamatkan data yang masih bisa dipulihkan. Key package hanya bekerja untuk drive dengan identifier yang sesuai, tidak dihasilkan otomatis, dan bisa disimpan di berkas atau di AD DS, tetapi tidak bisa disimpan di Microsoft Entra ID [S2]. Ini penting untuk disk yang rusak sebagian. Key package juga tidak berdiri sendiri: ia tetap butuh recovery password atau recovery key yang sesuai [S7].

Protector TPM-only, yang dipakai laptop gelombang 24H2 PT JAB, punya arti khusus. Saat boot normal di perangkat keras yang sama, TPM melepas kunci tanpa interaksi, sehingga Windows menyala sampai layar login dan volume sudah ter-unlock sebelum siapa pun mengetik apa-apa. Akibatnya ada dua hal. Pertama, laptop TPM-only yang dimatikan tidak "hilang": menyalakannya kembali di perangkat yang sama akan membuka volume lagi, tetapi menyalakan bukti adalah perubahan besar dan tetap tidak memberimu akses tanpa akun. Kedua, image fisik dari SSD yang dicabut tidak membawa TPM, sehingga hanya bisa dibuka dengan recovery password, recovery key, atau DRA.

Satu keadaan lagi perlu dikenali: **clear key**. Saat BitLocker disuspend, kunci disimpan tanpa proteksi di metadata volume, sehingga volume tetap terenkripsi tetapi bisa dibuka tanpa rahasia apa pun [S11][S17]. Device encryption Windows juga memulai enkripsi dengan clear key setelah instalasi bersih, lalu menghapusnya setelah protector TPM dibuat dan recovery key berhasil dicadangkan ke Entra ID, AD DS, atau akun Microsoft; perangkat yang hanya memakai akun lokal tetap tidak terlindungi meskipun datanya terenkripsi [S11]. Sejak Windows 11 24H2, prasyarat device encryption dilonggarkan sehingga lebih banyak perangkat terenkripsi otomatis [S11]. Bagi pemeriksa, artinya laptop yang "tidak pernah diatur BitLocker" pun perlu dicek statusnya, dan volume yang tampak terenkripsi belum tentu butuh kunci rahasia.

Jenis enkripsi juga bisa berbeda. Pada perangkat modern standby dengan enkripsi senyap (silent) lewat Intune, Windows memakai used space only encryption, sedangkan perangkat non-modern standby memakai full disk encryption; `manage-bde -status` menampilkannya di baris `Conversion Status` [S10]. Metode bawaan device encryption adalah XTS-AES 128-bit [S11].

Dari sini jawaban urutan untuk `BDG-WS-0185` bisa disusun per volume:

| Volume | Perlindungan | Kunci di luar laptop | Urutan |
|---|---|---|---|
| `C:` (BitLocker) | TPM + recovery password | Ada di Entra ID dan AD DS (dicek dulu Key ID-nya) | Memori, status, ambil dan cocokkan kunci, matikan, image fisik, buka di lab |
| `V:` (VeraCrypt, berkas `konfig-bdg.dat` di dalam `C:`) | Kata sandi pengguna | Tidak ada; hanya Ilham yang tahu | Memori, image logis selagi ter-mount (dengan izin Legal), baru matikan |

Tabel itu juga menunjukkan kenapa image logis `C:` dari sistem hidup tidak diambil di kasus ini: kunci `C:` tersedia di dua escrow dan bisa diverifikasi sebelum laptop dimatikan, sehingga image fisik setelah mati memberi salinan yang lebih lengkap (termasuk ruang tak teralokasi) dengan perubahan yang lebih sedikit. Image logis adalah jalan untuk volume yang kuncinya tidak ada atau tidak bisa diverifikasi.

### 1.3 Di mana kunci tersimpan, siapa boleh mengambilnya, dan bagaimana tercatat

Pertanyaan ketiga Rudi adalah pertanyaan tata kelola, bukan teknis: recovery password memberi akses ke seluruh isi volume, jadi pengambilannya harus diperlakukan seperti permintaan bukti lain, dengan persetujuan, pelaku yang jelas, dan jejak audit. Microsoft sendiri menekankan bahwa pemegang recovery password bisa membuka volume dan seluruh datanya, sehingga akses ke recovery password harus dikendalikan dan disimpan terpisah dari perangkatnya [S2].

**AD DS.** Informasi recovery disimpan sebagai objek anak dari objek komputer, dengan common name `ms-FVE-RecoveryInformation`. Satu objek komputer bisa punya lebih dari satu objek recovery karena satu volume bisa punya beberapa recovery password [S2]. Tabel berikut memuat atributnya; perhatikan dua baris GUID, karena keduanya yang dipakai mencocokkan kunci ke volume.

| Atribut | Isi |
|---|---|
| `ms-FVE-RecoveryPassword` | Recovery password 48 digit |
| `ms-FVE-RecoveryGuid` | GUID yang terkait dengan satu recovery password; GUID inilah yang ditampilkan di layar recovery |
| `ms-FVE-VolumeGuid` | GUID volume; unik per volume terenkripsi |
| `ms-FVE-KeyPackage` | Key package volume yang diamankan recovery password terkait |

Dua GUID itu yang menyelesaikan masalah pencocokan. Layar recovery menampilkan GUID recovery password, dan itu dicocokkan ke `ms-FVE-RecoveryGuid`; sedangkan `ms-FVE-VolumeGuid` yang menandai volumenya [S2][S5]. Kalau kamu memegang beberapa kunci untuk beberapa mesin, cocokkan lewat GUID, jangan lewat nama mesin.

Satu hal yang menguntungkan pemeriksa: Active Directory menyimpan riwayat seluruh recovery password untuk sebuah objek komputer, dan kunci lama tidak dihapus otomatis kecuali objek komputernya dihapus [S2]. Jadi kunci lama untuk disk lama sering masih ada. Secara bawaan hanya Domain Admins yang bisa membaca informasi recovery di AD DS, dan aksesnya bisa didelegasikan ke principal tertentu [S7].

**Microsoft Entra ID.** Informasi recovery untuk perangkat yang Entra joined disimpan sebagai tipe sumber daya `bitlockerRecoveryKey`, dan bisa diambil lewat pusat admin Entra, pusat admin Intune untuk perangkat terdaftar, PowerShell, atau Microsoft Graph [S2][S3]. Perangkat hybrid joined seperti laptop PT JAB juga mencadangkan kuncinya ke Entra ID bila kebijakannya mengatur begitu [S7][S10]. Key package tidak bisa disimpan di sini [S2]. Entra ID menampung maksimal 200 recovery key per perangkat [S10].

Siapa yang bisa membaca kunci di Entra ID ditentukan peran. Halaman pengelolaan perangkat Entra menyebut pemilik perangkat dan peran Cloud Device Administrator, Helpdesk Administrator, Intune Administrator, Security Administrator, dan Security Reader [S9]; API Graph menambahkan Global Reader sebagai peran yang didukung [S8]. Peran khusus bisa dibuat dengan izin `microsoft.directory/bitlockerKeys/key/read`, dan cakupannya bisa dibatasi ke administrative unit [S7]. Dua fakta dari daftar ini sering mengejutkan. Pertama, Security Reader, peran yang biasa diberikan ke analyst SOC untuk membaca portal keamanan, ikut bisa membaca recovery key. Kedua, secara bawaan pengguna bisa melihat recovery key perangkat miliknya sendiri lewat portal akun, kecuali opsi pembatasan untuk pengguna non-admin diaktifkan [S7][S9]. Perangkat hybrid joined tidak punya pemilik di Entra ID kecuali primary user ditetapkan di Intune [S9].

Pengambilan lewat Entra dan Intune tercatat. Memilih **Show Recovery Key** di detail perangkat membuat entri audit di kategori `KeyManagement` [S9]; Intune menyebut aktivitasnya **Read BitLocker key**, lengkap dengan UPN dan Key ID [S10]. Lewat Graph, properti `key` tidak dikembalikan kecuali diminta dengan `$select=key`, dan permintaan itu yang memicu audit; izin minimum untuk membaca metadata adalah `BitlockerKey.ReadBasic.All`, sedangkan membaca isi kunci butuh `BitlockerKey.Read.All` dengan pemanggil yang memegang peran yang didukung atau pemilik perangkat [S8].

Untuk PT JAB, aturan yang kamu usulkan ke Dimas pagi itu dan dipakai sejak kasus ini:

- **Yang meminta:** analyst forensik yang memegang kasus (di sini Rudi), lewat kanal insiden, dengan nomor kasus, nama host, dan Key ID dari `manage-bde -protectors -get`.
- **Yang menyetujui:** incident commander (Dimas). Untuk kasus orang dalam atau HR, Legal ikut menyetujui.
- **Yang mengambil:** tim IT pemegang peran perangkat (Agung Prabowo, akun admin `adm.agung`), bukan analyst SOC, meskipun peran Security Reader milik SOC secara teknis bisa membacanya. Pemisahan ini membuat setiap pembacaan punya pemohon, penyetuju, dan pelaku yang berbeda.
- **Jalur:** pusat admin Entra atau Intune (tercatat di audit `KeyManagement`), bukan AD DS. Di AD DS, PT JAB belum memasang audit Directory Service Access dengan SACL pada objek recovery, jadi pembacaan di sana tidak meninggalkan catatan yang bisa diperiksa. AD DS dipakai hanya untuk memastikan ada objek dengan GUID yang sama, tanpa membaca atribut kata sandinya. Cek di lab apakah konfigurasi audit DS Access dan event 4662 di DC menangkap pembacaan atribut ini sebelum mengandalkannya.
- **Penyimpanan:** recovery password tidak ditulis di chat, case notes, atau evidence log. Ia disimpan di brankas kata sandi tim IT dengan nama entri yang menunjuk nomor kasus, dan hanya dibagikan ke pemegang bukti (Yoga Pratama) dan analyst yang membuka image. Evidence log hanya mencatat Key ID, siapa membaca, dan kapan.
- **Setelah kasus:** recovery password yang sudah dilihat diganti. Intune punya remote action **BitLocker key rotation** untuk Windows 10 1909 ke atas dan Windows 11, dengan syarat rotasi recovery password berbasis klien dan pencadangan ke Entra ID diaktifkan di kebijakan [S10]; perangkat dengan rotasi otomatis juga mengganti recovery password setelah dipakai membuka drive [S7]. Untuk `BDG-WS-0185`, rotasi baru dijalankan setelah image selesai dan laptop dikembalikan atau di-reimage, supaya tidak ada perubahan pada laptop selama kasus berjalan.

Dua jalur lain tetap sah tetapi dicatat sebagai pilihan kedua. Administrator di sistem yang hidup dan ter-unlock bisa membaca recovery password langsung dari host dengan `manage-bde -protectors -get` atau `Get-BitLockerVolume` [S17]; ini berguna untuk perangkat yang kuncinya tidak ada di escrow, tetapi hasilnya adalah rahasia yang mendarat di keluaran perintah dan harus ditangani seperti kunci dari escrow. Pemilik perangkat juga bisa menyerahkan kunci yang ia simpan sendiri; penyerahan itu dicatat dengan nama, waktu, dan saksi.

### 1.4 Tindakan yang memaksa mode recovery

Pertanyaan keempat Rudi ("kalau SSD dicabut, boot dari USB, atau BIOS diubah?") menyangkut daftar yang harus kamu kenali supaya tidak memicunya sendiri, atau supaya tidak salah membaca akibatnya. Dokumentasi menyebut antara lain: memindahkan drive terproteksi BitLocker ke komputer lain, perubahan pada tabel partisi NTFS, perubahan boot manager, boot lewat PXE, mematikan atau membersihkan TPM, menyembunyikan TPM dari sistem operasi, mengubah PCR yang dipakai profil validasi TPM, memperbarui firmware BIOS atau UEFI, dan memasukkan PIN salah terlalu sering [S2]. Daftar terbaru juga menyebut docking atau undocking laptop, menaruh drive CD/DVD sebelum hard drive di urutan boot, upgrade Windows dari media, kegagalan self-test TPM, penggantian motherboard dengan TPM baru, dan melewati batas gagal login bila kebijakan penguncian akun mesin diatur [S2].

Mode recovery bukan kerusakan. Datanya tetap utuh; yang berubah adalah volume tidak lagi membuka diri secara otomatis dan meminta recovery password atau recovery key. Bagi pemeriksa, akibat praktisnya bergantung pada tindakan:

| Tindakan | Yang terjadi pada bukti | Dampak bagi akuisisi |
|---|---|---|
| SSD dicabut lalu di-image lewat write blocker | Tidak ada yang ditulis ke SSD; TPM tidak ikut, jadi image berisi blok terenkripsi | Aman bila kunci sudah dipegang; tanpa kunci, image tidak bisa dibaca |
| SSD dipasang dan di-boot di komputer lain | Boot ke mode recovery; bila dibuka dengan recovery protector, BitLocker mengikat diri ke TPM baru dan kembali meminta recovery di perangkat asal [S7] | Mengubah metadata volume; tidak pernah dilakukan pada bukti |
| Laptop di-boot dari USB forensik | TPM tidak melepas kunci ke rantai boot lain; volume tetap terkunci | Hanya memberi image terenkripsi, sama dengan mencabut SSD, ditambah perubahan urutan boot |
| BIOS atau UEFI diperbarui, TPM di-clear | Boot berikutnya masuk mode recovery; TPM yang di-clear kehilangan materi kuncinya | Jalur TPM hilang; hanya recovery protector yang tersisa |
| `manage-bde -forcerecovery` | Menghapus seluruh key protector terkait TPM; restart berikutnya hanya bisa dibuka recovery password atau recovery key [S1] | Tidak pernah dijalankan pada sistem bukti |

Baris pertama adalah yang paling sering menjebak: mencabut disk lalu memasangnya di write blocker adalah tindakan standar forensik yang pada sistem BitLocker membuat bukti hanya bisa dibaca dengan kunci dari luar. Karena itu, pada mesin yang hidup dan ter-unlock, pertanyaan pertama bukan "bagaimana mengambil image" melainkan "apakah saya sudah memegang kuncinya". Untuk `BDG-WS-0185`, jawaban ke Fajar: SSD boleh dicabut dan di-image lewat write blocker, tetapi hanya setelah recovery password diverifikasi cocok dengan Key ID volume `C:`, dan laptop tidak boleh dinyalakan lagi setelah dimatikan.

Untuk pekerjaan terencana seperti pembaruan perangkat keras, proteksi bisa disuspend sehingga drive tetap terenkripsi penuh dan recovery tidak terpicu; suspend dan resume juga menyegel ulang kunci enkripsi tanpa perlu memasukkan recovery key [S2]. Perlu diingat bahwa BitLocker otomatis melanjutkan proteksi saat perangkat di-reboot, kecuali jumlah reboot ditentukan lewat PowerShell atau `manage-bde` [S2]. Sebagian praktisi menyarankan suspend sebelum image fisik pada sistem hidup supaya image terbaca tanpa kunci rahasia, karena suspend menaruh clear key di metadata volume [S17]. Di PT JAB pilihan itu tidak dipakai bila kunci tersedia di escrow: suspend menulis ke volume bukti, dan image yang membawa clear key berarti salinan bukti itu terbaca oleh siapa pun yang memegangnya.

`manage-bde -ForceRecovery` melakukan kebalikannya: memaksa drive masuk mode recovery saat restart dan menghapus seluruh key protector terkait TPM, sehingga hanya recovery password atau recovery key yang bisa membukanya [S1]. Jangan pernah menjalankannya pada sistem bukti.

### 1.5 Memori sebagai sumber kunci

Pertanyaan kelima Rudi ("bisa tidak kuncinya diambil dari memori?") punya jawaban yang jujur: kunci memang ada di memori, tetapi mengambilnya bukan pekerjaan rutin internal, dan hasilnya tidak bisa dijanjikan. Pada sistem hidup dengan volume ter-unlock, kunci volume ada di memori. Itu alasan teknis kenapa akuisisi memori mendahului segalanya pada sistem terenkripsi (Day 14 bagian 1.1). Keberhasilan ekstraksi kunci dari memori bergantung pada banyak hal dan tidak bisa dijanjikan, tetapi image memori yang tidak diambil pasti tidak bisa dianalisis nanti.

Untuk VeraCrypt, dokumentasinya sendiri menyatakan bahwa selama volume ter-mount, isi berkas yang sudah didekripsi dan master key berada di RAM, dan banyak program tidak membersihkan buffer-nya sehingga data plaintext bisa tertinggal setelah program ditutup [S13]. Melepas (dismount) volume non-sistem menghapus master key-nya dari RAM, dan shutdown atau restart yang bersih melepas semua volume; sebaliknya, putus daya mendadak atau crash membuat VeraCrypt tidak sempat menghapus apa pun [S13]. Sejak versi 1.24, VeraCrypt punya opsi mengenkripsi master key dan kata sandi yang di-cache di RAM; opsi ini mati secara bawaan, harus diaktifkan manual, dan menonaktifkan hibernate Windows [S12][S13]. Bila opsi itu aktif di laptop pengguna, peluang menemukan kunci yang bisa dipakai dari image memori turun.

Konsekuensinya untuk PT JAB ada tiga:

1. Image memori `BDG-WS-0185` diambil sebelum apa pun, dan ini termasuk sebelum `V:` di-dismount atau laptop dimatikan. Shutdown bersih akan menghapus master key VeraCrypt dari RAM; image memori adalah satu-satunya tempat kunci itu masih ada setelah laptop mati.
2. Volatility 3 2.28.2 tidak punya plugin untuk kunci BitLocker atau VeraCrypt. Daftar plugin Windows-nya hanya memuat `windows.truecrypt.Passphrase`, yang memindai bagian data driver `truecrypt.sys` untuk kata sandi TrueCrypt yang di-cache, tanpa menyebut VeraCrypt [S14]. Volatility tetap berguna untuk hal lain di sekitar enkripsi: membuktikan `VeraCrypt.exe` berjalan di sesi siapa, dan driver `veracrypt.sys` termuat (Day 14 dan Day 16).
3. Ekstraksi kunci dari memori, bila diperlukan, adalah pekerjaan retainer (PT Forensik Digital Contoh) dengan alat yang sudah divalidasi, atas salinan kerja image memori, dengan persetujuan tertulis yang sama seperti membuka volume. Alat komersial semacam itu ada dan mengklaim bisa mencari kunci BitLocker, TrueCrypt, dan VeraCrypt di image RAM [S17]; klaim vendor seperti ini diuji dulu di lab sebelum hasilnya dipakai di laporan. Di Day ini kamu tidak menjalankannya; cukup memastikan image memorinya ada dan rantai buktinya utuh.

Memori juga punya peran kedua yang sering terlupa: ia membuktikan keadaan. Image memori menunjukkan bahwa `V:` sedang ter-mount saat akuisisi, proses mana yang memegang handle ke berkas di `V:`, dan apakah proses penyerang pernah membuka berkas di sana. Itu jawaban untuk pertanyaan kasus ("apakah penyerang menyentuh isi kontainer?"), dan dijawab tanpa perlu kunci.

### 1.6 Membuka volume untuk analisis tanpa mengubah bukti

Pertanyaan keenam Rudi menyangkut pekerjaan di Jakarta setelah image fisik tiba. Prinsipnya sama dengan Day 02 bagian 1.5: master tidak pernah disentuh, semua kerja di salinan kerja, dan alat yang dipakai dibatasi ke mode baca. Yang baru adalah satu lapisan tambahan: salinan kerja harus didekripsi lebih dulu, dan dekripsi itu sendiri adalah langkah yang dicatat (alat, versi, Key ID yang dipakai, siapa, kapan).

Ada tiga cara umum, dan ketiganya dibahas di bagian 2.8:

- **Dekripsi langsung dari image di Linux.** `dislocker` adalah driver FUSE untuk membaca volume BitLocker di Linux dan macOS; ia mendukung AES-CBC dan AES-XTS 128 atau 256 bit [S16]. Opsi `-r` mencegah penulisan ke volume BitLocker, `-V` menunjuk volume, `-O` memberi offset partisi dalam byte, dan `-p` tanpa nilai membuat alat meminta recovery password secara interaktif sehingga kata sandi tidak tertinggal di riwayat shell [S16]. Hasilnya sebuah berkas virtual `dislocker-file` berisi partisi NTFS yang di-mount seperti partisi biasa; menulis ke berkas itu mengubah volume asal, jadi mount-nya juga read-only [S16]. Halaman proyek menyebut Windows Vista sampai Windows 10 dan tidak menyebut Windows 11, jadi uji dulu di lab dengan volume 24H2 [S16].
- **Unlock di Windows.** Salinan kerja di-mount read-only sebagai disk, lalu volumenya dibuka dengan `manage-bde -unlock <huruf>: -recoverypassword <48 digit>` atau `-recoverykey <berkas .bek>` [S1][S2]. Uji di lab apakah unlock tetap berhasil pada disk yang di-mount read-only dan apakah ada yang ditulis ke metadata volume.
- **Alat forensik komersial atau pustaka libbde** yang menerima recovery password saat membuka image [S18]. Dukungan mode XTS dan versi BitLocker berbeda antar alat dan versi, jadi uji dulu di lab dengan volume yang diketahui.

Recovery password yang benar untuk volume yang salah akan ditolak. Bila ditolak, periksa ulang pencocokan Key ID dan GUID sebelum menduga kata sandinya salah ketik; konsol recovery Windows sendiri memakai checksum di setiap blok 6 digit untuk mendeteksi salah ketik [S7]. Sumber yang membahas imaging BitLocker juga mengingatkan bahwa recovery password tidak boleh mengandung spasi, termasuk spasi di belakang, karena sebagian alat menolaknya [S18].

Setelah volume terbuka, analisis berjalan seperti Day 03 sampai Day 13. Satu hal yang perlu dicatat di laporan: image fisik dari volume used space only encryption memuat ruang yang tidak pernah ditulis sebelum enkripsi dalam keadaan apa adanya, sehingga ruang tak teralokasi hasil dekripsinya tidak selalu sama dengan ruang tak teralokasi disk tanpa enkripsi. Cek perilakunya di lab sebelum menyimpulkan apa pun dari carving di volume semacam itu.

### 1.7 VeraCrypt: mengenali kontainer, dan batas kesimpulannya

Pertanyaan ketujuh Rudi punya dua bagian: bagaimana memastikan `konfig-bdg.dat` memang kontainer VeraCrypt, dan apa yang boleh ditulis tentang isinya. Bagian kedua lebih penting, karena di kasus ini kontainer itu milik karyawan yang sejauh ini adalah korban, bukan tersangka.

Kontainer VeraCrypt sengaja dirancang tidak punya tanda tangan yang bisa dikenali. Ruang kosong pada volume VeraCrypt diisi data acak saat volume dibuat, sehingga hidden volume yang tidak sedang di-mount tidak bisa dibedakan dari data acak itu [S4]. Header hidden volume berada di byte 65536 sampai 131071, dan saat mounting VeraCrypt mencoba mendekripsi header standar lebih dulu, lalu mencoba area header hidden bila gagal [S4]. Bila tidak ada hidden volume, area itu hanya berisi data acak, sehingga melihat area itu tidak menjawab apa-apa ke arah mana pun [S4].

Dokumentasinya menyatakan bahwa dengan outer volume ter-mount, seharusnya tidak mungkin membuktikan ada atau tidaknya hidden volume di dalamnya, dengan syarat instruksi pembuatan dan persyaratan keamanannya diikuti [S4]. Syarat itu penting dan sering tidak terpenuhi di dunia nyata, misalnya bila Quick Format atau Dynamic dipakai, atau bila outer volume memuat filesystem yang dienkripsi di tempat [S4].

Karena berkasnya sendiri tidak berbicara, keberadaan kontainer dikenali dari artefak di sekitarnya. Tabel berikut memetakan artefak ke apa yang dibuktikannya; baca kolom ketiga, karena tidak satu pun membuktikan isi.

| Artefak | Lokasi | Yang dibuktikan | Yang tidak |
|---|---|---|---|
| Driver VeraCrypt | `%windir%\System32\drivers\veracrypt.sys` (tidak ada pada mode portable) [S19] | VeraCrypt terpasang sebagai aplikasi, bukan portable | Kapan dan untuk apa dipakai |
| `History.xml` | `%APPDATA%\VeraCrypt\`; daftar dua puluh berkas atau perangkat terakhir yang dicoba di-mount sebagai volume; bisa dimatikan [S19] | Path kontainer yang pernah dicoba di-mount oleh profil itu | Bahwa mount berhasil, atau isi kontainer |
| `Configuration.xml` | `%APPDATA%\VeraCrypt\`; konfigurasi utama [S19] | Pengaturan aplikasi, misalnya riwayat dimatikan atau tidak | Isi volume |
| Prefetch, Amcache, BAM `VERACRYPT.EXE` | Day 07 | Aplikasi dijalankan dan kapan (dengan batas tiap artefak) | Volume mana yang dibuka |
| Volume ber-huruf drive tanpa perangkat fisik | `MountedDevices`, LNK, Jump List, ShellBags (Day 09 dan Day 10) | Ada volume yang pernah dipakai di huruf itu, dengan VolumeID dan label sendiri | Bahwa volume itu milik kontainer tertentu tanpa artefak lain |
| Berkas kandidat | Ukuran bulat dalam satuan biner, tanpa ekstensi yang dikenal, entropi mendekati 8 | Konsisten dengan kontainer terenkripsi | Bukan bukti: berkas terkompresi dan media terenkode juga berentropi tinggi |
| Proses dan driver di memori | `windows.pslist`, `windows.modules` (Day 14 dan Day 16) | VeraCrypt berjalan di sesi tertentu saat akuisisi | Isi volume |

Konsekuensinya untuk laporan: kamu bisa melaporkan keberadaan berkas yang isinya tidak terstruktur dan berentropi tinggi, keberadaan perangkat lunak enkripsi, dan jejak pemakaiannya. Kamu tidak bisa menyimpulkan keberadaan hidden volume dari isi berkas saja. Yang bisa kamu lakukan adalah mengumpulkan artefak di sekitarnya, dan itu biasanya lebih produktif daripada menyerang berkasnya.

Batas yang lebih penting di kasus ini bukan teknis. Keberadaan kontainer terenkripsi bukan bukti isi, dan bukan bukti niat. Ilham menyatakan kontainer itu berisi cadangan konfigurasi perangkat pelanggan, dan artefak di laptopnya bisa menunjukkan apakah keterangan itu konsisten (kapan VeraCrypt dipasang, kapan kontainer dibuat, berkas apa yang dibuka dari `V:`), tetapi tidak bisa membuktikan bahwa kontainer hanya berisi itu. Sebaliknya, menyimpan data di kontainer pribadi tanpa kebijakan yang mengaturnya adalah temuan tata kelola, bukan tanda kesalahan. Kalimat yang boleh ditulis: "Ditemukan berkas `konfig-bdg.dat` berukuran 8 GiB yang tercatat di riwayat VeraCrypt profil `ilham.maulana` dan sedang ter-mount sebagai `V:` saat akuisisi; isinya diambil sebagai image logis dengan izin Legal dan belum diperiksa." Kalimat yang dilarang: "Ilham menyembunyikan data di kontainer terenkripsi", "kontainer berisi data curian", "tidak ada hidden volume".

Membuka isi kontainer adalah keputusan Legal, bukan keputusan teknis. Jalur yang sah ada tiga: image logis yang diambil saat `V:` masih ter-mount (diambil di kasus ini), kata sandi yang diserahkan Ilham secara sukarela dan dicatat, atau kunci dari image memori yang dicari retainer. Menebak kata sandi atau menyerang kontainer bukan jalur yang dipakai.

## 2. Contoh dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi; angka di keluaran dihitung agar konsisten antar tabel dan antar bagian. Perintah di host dijalankan lewat live response Defender for Endpoint atau oleh Fajar di konsol `BDG-WS-0185`; analisis image dijalankan di `jkt-dfir02` (Ubuntu LTS) dan `JKT-DFIR01` (Windows 11) atas salinan kerja. Narasi memakai WIB (UTC+7); keluaran yang menulis UTC diberi label (UTC = WIB dikurangi 7 jam). Recovery password di semua keluaran ditampilkan bertopeng, karena nilai aslinya tidak pernah ditulis di dokumen kasus. Perintah yang mengubah protector atau keadaan volume tidak dijalankan pada sistem bukti.

### 2.1 Status enkripsi workstation PT JAB (laporan Kamis 2027-02-04)

Laporan ini adalah hasil rencana nomor 10 dan menjadi bahan pertama yang kamu buka saat pesan Rudi masuk, karena ia menjawab apakah kunci `BDG-WS-0185` seharusnya ada di escrow. Agung Prabowo menyusunnya dari Encryption report Intune (`Devices > Monitor > Encryption report`) [S10], daftar objek `ms-FVE-RecoveryInformation` di AD DS, dan inventaris aset; dokumennya disimpan di repositori `jab-ir-tools` path `docs/forensik/status-enkripsi-workstation-2027-02.md`. Tabel berikut adalah ringkasannya; cari baris tempat sebuah host berada sebelum memutuskan cara akuisisinya.

| Kelompok | Jumlah | Persen | Kunci di escrow | Keterangan |
|---|---|---|---|---|
| BitLocker lewat kebijakan Intune `JAB-WS-BitLocker`, kunci di Entra ID dan AD DS | 271 | 24,1% | Entra ID dan AD DS | Laptop gold image 24H2 yang dienkripsi sejak GPO pencadangan AD DS dipasang 2026-11-23 |
| BitLocker lewat kebijakan Intune, kunci hanya di Entra ID | 47 | 4,2% | Entra ID | Dienkripsi 2026-11-02 sampai 2026-11-22, sebelum GPO AD DS; pencadangan ke AD DS tidak terjadi otomatis setelah enkripsi [S2] |
| BitLocker aktif dengan `Protection Off` (clear key), tanpa kunci di escrow | 7 | 0,6% | Tidak ada | Laptop demo POP yang dipasang ulang teknisi dengan akun lokal; device encryption berhenti di clear key [S11] |
| Tidak terenkripsi | 801 | 71,1% | Tidak relevan | Gold image 23H2; termasuk semua laptop di kasus forensik 2026 dan Januari 2027 |
| Total workstation Windows | 1.126 | 100 | | Persentase dibulatkan satu desimal |

Kebijakan `JAB-WS-BitLocker` dipasang 2026-11-02 untuk grup perangkat laptop gold image 24H2 (pengadaan gelombang kedua 2026): enkripsi senyap, protector TPM tanpa PIN, XTS-AES 128, pencadangan ke Entra ID wajib sebelum enkripsi dimulai, dan rotasi recovery password berbasis klien untuk perangkat Entra ID dan hybrid joined. Karena sebagian besar laptop itu modern standby, enkripsi senyap menghasilkan used space only encryption [S10].

Laporan itu juga mencatat tiga temuan tata kelola yang langsung relevan dengan kasus:

- Pengaturan tenant yang membatasi pengguna non-admin melihat recovery key perangkatnya sendiri masih bawaan (tidak dibatasi), sehingga pemilik laptop bisa membaca kuncinya lewat portal akun [S7][S9].
- Akun analyst SOC memegang peran Security Reader untuk portal keamanan, yang ikut bisa membaca recovery key [S9]. Belum ada aturan siapa yang boleh memakainya.
- Pembacaan recovery key di AD DS tidak diaudit; pembacaan di Entra ID dan Intune tercatat di kategori `KeyManagement` dan ikut diteruskan ke Splunk index `o365` lewat Event Hub bersama log audit Entra lainnya.

Fakta ini tidak bertentangan dengan kasus sebelumnya. Image `JKT-WS-0388`, `JKT-WS-0412`, `BDG-WS-0142`, `JKT-WS-0457`, `JKT-WS-0441`, `BDG-WS-0163`, dan `JKT-WS-0516` semuanya diambil dari laptop gold image 23H2 di kelompok terakhir, sehingga image fisik mereka langsung terbaca tanpa kunci.

### 2.2 Case notes di lokasi dan keputusan tidak mematikan (08:12 sampai 08:45)

Catatan ini menunjukkan urutan kejadian sebelum satu perintah akuisisi pun dijalankan, dan menjadi dasar jawaban pertanyaan 1. Rudi menulisnya di `\\jkt-evid01\cases\INC-2027-012\notes\case-notes.md`; Fajar mengirim foto lewat grup Signal "JAB-CSIRT-OOB" dan foto itu dicatat dengan hash.

```
2027-02-09 (WIB)
07:58  Gilang (L1 shift pagi) eskalasi 10 alert SOC-2027-0120..0129 (02:14-07:52) BDG-WS-0185 ke Rudi.
08:05  Rudi: isolasi perangkat lewat Defender (koneksi ke layanan Defender tetap ada).
08:10  Dimas: INC-2027-012 ditetapkan, SEV-3, kanal #inc-2027-012.
08:12  Rudi telepon Fajar (POP Bandung). Instruksi: jangan sentuh keyboard/mouse, jangan tutup lid,
       jangan cabut charger atau kabel, foto layar dan posisi laptop.
08:14  Rudi telepon Ilham (lokasi pelanggan, Cimahi; tiba di POP sekitar 10:30). Ilham: laptop dikunci
       Senin 21:52, ditinggal menyala di meja.
08:20  Fajar di meja Ilham: laptop menyala, layar kunci, jam di layar 08:20, charger tersambung, lid terbuka.
       4 foto (layar, label aset, port, posisi). Tidak ada media lepasan terpasang.
08:22  Rudi, live response: processes -> VeraCrypt.exe di sesi Ilham; drivers -> veracrypt.
08:24  Rudi, live response: getfile C:\Users\ilham.maulana\AppData\Roaming\VeraCrypt\History.xml
       (1 entri: C:\Users\ilham.maulana\Documents\Arsip\konfig-bdg.dat); fileinfo berkas itu: 8.589.934.592 byte.
08:26  Ilham (telepon kedua): kontainer miliknya, isi cadangan konfigurasi CPE pelanggan dedicated Bandung,
       ter-mount sebagai V: sejak Senin sekitar 14:05; belum di-dismount.
08:28  Rudi ke kamu (eskalasi): 7 pertanyaan.
08:41  Kamu: rencana tertulis (bagian 2.10). Jangan matikan. Memori dulu.
08:45  Dimas setuju rencana; minta Legal (Ratna Sari) memutuskan image logis V:.
```

Langkah `getfile` atas `History.xml` adalah perubahan kecil yang disengaja: berkasnya kecil, tidak terenkripsi, dan menjawab pertanyaan paling mendesak (berkas mana yang menjadi kontainer) tanpa membuka isi kontainer [S19]. `fileinfo` hanya membaca metadata. Rudi tidak menjalankan `dir V:\`, karena isi volume itu menunggu keputusan Legal.

**Cara membaca hasil:** tiga fakta menentukan rencana. Laptop menyala dan sudah diisolasi, jadi menunda pematian tidak membuka jalur baru bagi penyerang. VeraCrypt sedang ter-mount, jadi ada satu volume yang plaintext-nya hilang saat shutdown. Laptop berasal dari gold image 24H2, jadi `C:` seharusnya punya kunci di escrow, dan itu yang diverifikasi berikutnya.

**Kapan gagal:** bila laptop ditemukan dalam keadaan tidur (modern standby), isi memori tetap ada; jangan membangunkannya dengan menekan tombol daya lama, karena tekanan lama mematikan paksa. Bila baterai hampir habis dan charger tidak ada, pemadaman tak terkendali lebih buruk daripada shutdown yang direncanakan; catat persentase baterai di foto pertama.

### 2.3 Memori lebih dulu: `INC-2027-012-E01`

Langkah ini menjawab bagian pertama pertanyaan 2 dan menyiapkan cadangan untuk pertanyaan 5: image memori diambil sebelum apa pun yang bisa menghapus kunci dari RAM. Caranya mengikuti prosedur memori jarak jauh rencana nomor 3 (Day 20 bagian 1.13), dengan satu perbedaan dari Day 18 bagian 2.1: RAM `BDG-WS-0185` 16 GB, sehingga image terkompresi pun berisiko melewati batas `getfile` 3 GB. Image ditulis langsung ke media bukti yang dicolok Fajar, bukan ditarik lewat jaringan.

Fajar mencolok `USB-E-14` (SSD eksternal NTFS 256 GB, disiapkan dan di-hash kosong di POP Bandung) pukul 08:47; volume muncul sebagai `E:`. Rudi menjalankan skrip dari library live response:

```
run jab-memcapture.ps1 -parameters "-Destination E:\INC-2027-012\E01 -Name INC-2027-012-E01_BDG-WS-0185_mem.raw -Hash SHA256"
```

- `run jab-memcapture.ps1`: skrip bertanda tangan dari repositori `jab-ir-tools` yang menjalankan WinPmem mini dari folder toolkit di media, menulis raw ke tujuan, lalu menghitung hash di titik koleksi.
- `-Destination` dan `-Name`: folder dan nama berkas di media bukti, mengikuti pola nama bukti PT JAB.
- `-Hash SHA256`: hash dihitung di host segera setelah akuisisi selesai, bukan menunggu media tiba di Jakarta (pelajaran E13 di Day 14).

Keluaran ilustrasi (ringkasan log skrip, waktu WIB dari jam host):

```
08:52:10  WinPmem mulai; driver dimuat
09:03:05  selesai: INC-2027-012-E01_BDG-WS-0185_mem.raw  sekitar 18,0 GiB  (655 s)
09:05:41  SHA-256 8b4d...  (ditulis ke INC-2027-012-E01_BDG-WS-0185_mem.raw.sha256)
```

**Cara membaca hasil:** 655 detik untuk sekitar 18,0 GiB setara sekitar 30 MB/s, sejalan dengan akuisisi E01 `JKT-WS-0388` di Day 14. Ukuran file mengikuti alamat fisik tertinggi, bukan RAM terpasang (Day 14 bagian 1.2). Image ini memuat keadaan saat `V:` masih ter-mount dan `C:` ter-unlock; kunci kedua volume ada di dalamnya kecuali VeraCrypt di laptop itu memakai enkripsi RAM, yang belum diketahui sampai `Configuration.xml` diperiksa (bagian 2.9).

**Variasi:** bila live response tidak tersedia, Fajar menjalankan WinPmem sendiri dari `USB-E-14` di sesi `ir-admin`, seperti akuisisi memori laptop Dewi di Oktober. Akibatnya ada logon interaktif dan profil baru di laptop, yang dicatat sebagai jejak responder.

**Kapan gagal:** kebijakan BitLocker bisa menolak penulisan ke removable drive yang tidak dilindungi BitLocker; kebijakan `JAB-WS-BitLocker` tidak mengatur removable drive, dan itu dicek dari ringkasan kebijakan sebelum media dicolok. Cek nama pengaturannya di kebijakan BitLocker versi-mu. Bila skrip berhenti karena timeout `run` (30 menit), image tidak lengkap; ukuran file yang lebih kecil dari alamat tertinggi adalah tandanya.

### 2.4 Membaca status BitLocker dan ID protector: `INC-2027-012-E02`

Langkah ini menjawab bagian kedua pertanyaan 2 (volume mana dilindungi apa) dan menghasilkan Key ID yang dibawa ke pertanyaan 3. Rudi menjalankan skrip library kedua, `jab-bdestatus.ps1`, yang menjalankan perintah baca saja dan menulis keluarannya ke `E:\INC-2027-012\E02\`:

```
manage-bde -status C:
manage-bde -protectors -get C:
Get-Volume
```

- `manage-bde -status C:`: keadaan BitLocker volume `C:` [S1]. Tanpa huruf drive, perintah ini melaporkan semua drive, termasuk yang tidak terlindungi BitLocker [S1].
- `manage-bde -protectors -get C:`: daftar protector beserta ID-nya. Pada sistem yang hidup, keluaran ini juga menampilkan recovery password dalam teks jelas kepada administrator [S17]. Skrip `jab-bdestatus.ps1` mengganti nilai itu dengan tanda bintang sebelum menulis berkas, karena berkas E02 dibaca banyak orang.
- `Get-Volume`: daftar volume yang dilihat Windows, untuk memastikan `V:` memang volume terpasang dan bukan share jaringan.

Keluaran ilustrasi `manage-bde -status C:`:

```
Volume C: [OS]
[OS Volume]

    Size:                 475.70 GB
    BitLocker Version:    2.0
    Conversion Status:    Used Space Only Encrypted
    Percentage Encrypted: 100.0%
    Encryption Method:    XTS-AES 128
    Protection Status:    Protection On
    Lock Status:          Unlocked
    Identification Field: Unknown
    Key Protectors:
        TPM
        Numerical Password
```

Cara membacanya. `Lock Status: Unlocked` pada mesin hidup berarti kamu masih bisa membaca isinya sekarang; itu jendela yang akan tertutup saat mesin mati. `Key Protectors` memberi tahu jalan masuk yang tersedia: `Numerical Password` berarti ada recovery password 48 digit yang mungkin tersimpan di AD atau Entra. `Identification Field` adalah penanda organisasi yang dipakai manajemen DRA [S1][S2]; di PT JAB tidak diatur, dan tidak ada protector DRA. `Used Space Only Encrypted` dan `XTS-AES 128` cocok dengan kebijakan enkripsi senyap di laptop modern standby [S10][S11]. `Protection On` berarti tidak ada clear key: image fisik tidak bisa dibaca tanpa recovery password.

Keluaran ilustrasi `manage-bde -protectors -get C:` (sudah ditopengi skrip):

```
Volume C: [OS]
All Key Protectors

    TPM:
      ID: {0D52E8A7-91C3-4F6B-B2D4-7A19E0C35F88}
      PCR Validation Profile:
        7, 11
        (Uses Secure Boot for integrity validation)

    Numerical Password:
      ID: {6F3A9C21-4B7E-4D18-9A05-2C8E71D4B930}
      Password:
        ******-******-******-******-******-******-******-******
```

Keluaran ini memuat ID protector dan GUID recovery password, dan GUID itulah yang kamu bawa untuk mencari kuncinya. ID protector `Numerical Password` (`6F3A9C21-...`) adalah Key ID yang muncul di Entra ID dan di layar recovery, dan sama dengan `msFVE-RecoveryGuid` di AD DS [S2][S7]. Profil PCR yang tampil di sini adalah ilustrasi; cek profil yang dilaporkan laptop 24H2 di lab.

Keluaran ilustrasi `Get-Volume` (kolom diringkas):

```
DriveLetter FileSystemLabel FileSystem DriveType SizeRemaining      Size
----------- --------------- ---------- --------- -------------      ----
C           OS              NTFS       Fixed          318.42 GB 475.70 GB
E           USB-E-14        NTFS       Removable      220.47 GB 238.47 GB
V           KONFIG          NTFS       Fixed            5.69 GB   8.00 GB
```

**Cara membaca hasil:** `V:` adalah volume NTFS sekitar 8 GB berlabel `KONFIG` dengan sisa sekitar 5,69 GB, jadi sekitar 2,31 GB terpakai. Cara volume VeraCrypt ditampilkan di `Get-Volume` (jenis drive, ukuran tepat) perlu dicek di lab; yang penting di sini adalah volume itu terpasang dan terbaca. `E:` sudah berisi sekitar 18 GB image memori.

**Variasi:** `Get-BitLockerVolume` di PowerShell memberi informasi yang sama dalam bentuk objek, termasuk properti `KeyProtector` dengan `RecoveryPassword` [S17]. Bila volume rusak sebagian dan kunci tidak dicadangkan ke AD DS, hasilkan key package lebih dulu dari volume yang masih sehat selagi bisa:

```
manage-bde.exe -KeyPackage C: -id <id> -path <path>
```

Perintah ini menghasilkan berkas bernama `BitLocker Key Package {<id>}.KPG` di jalur yang ditentukan, dan untuk mengekspornya dibutuhkan akses administrator lokal ke volume yang masih bekerja sebelum kerusakan terjadi [S2]. Di `BDG-WS-0185` perintah ini tidak dijalankan: volume sehat, dan kuncinya ada di dua escrow.

- **Kapan gagal:** perintah butuh hak administrator. Pada mesin yang tidak bisa kamu masuki sebagai admin, informasi yang sama kadang bisa diambil dari konsol manajemen; untuk laptop PT JAB, Key ID juga terlihat di detail perangkat Intune dan Entra.

### 2.5 Mengambil recovery key lewat jalur yang tercatat

Langkah ini menjawab pertanyaan 3 dan menutup syarat sebelum laptop boleh dimatikan: kunci `C:` ada, cocok dengan Key ID dari E02, dan tersimpan di tempat yang benar. Pukul 09:12 Rudi menulis permintaan di `#inc-2027-012` (nomor kasus, host, Key ID `6F3A9C21-4B7E-4D18-9A05-2C8E71D4B930`, alasan); Dimas menyetujui pukul 09:14.

Agung mengambil kunci dari pusat admin Entra dengan akun `adm.agung`: `Entra ID > Devices > All devices`, pilih `BDG-WS-0185`, buka bagian BitLocker keys, lalu **Show Recovery Key** untuk Key ID yang diminta [S9]. Jalur setara di Intune adalah `Devices > All devices`, pilih perangkat, `Monitor > Recovery keys`, lalu **Show Recovery Key** [S10]. Keduanya menulis entri audit.

Untuk mencocokkan Key ID tanpa membaca isi kunci, Agung lebih dulu menjalankan permintaan metadata lewat Microsoft Graph PowerShell:

```
Connect-MgGraph -Scopes 'BitlockerKey.ReadBasic.All' -NoWelcome
$dev = Get-MgDevice -Filter "displayName eq 'BDG-WS-0185'"
Get-MgInformationProtectionBitlockerRecoveryKey -Filter "deviceId eq '$($dev.DeviceId)'"
```

- `BitlockerKey.ReadBasic.All`: izin paling sempit; mengembalikan metadata kunci tanpa properti `key` [S8].
- `Get-MgDevice -Filter`: mencari objek perangkat berdasarkan nama untuk mendapat `DeviceId` [S7].
- `Get-MgInformationProtectionBitlockerRecoveryKey -Filter "deviceId eq ..."`: daftar kunci milik perangkat itu, tanpa isi kunci [S7][S8].

Keluaran ilustrasi:

```
Id                                   CreatedDateTime        DeviceId                             VolumeType
--                                   ---------------        --------                             ----------
6f3a9c21-4b7e-4d18-9a05-2c8e71d4b930 2026-12-14 03:27:15    3e81c0d4-5a92-4b7f-8c16-d29a74e0b513 1
```

**Cara membaca hasil:** satu kunci untuk perangkat ini, dengan `Id` yang sama dengan ID protector `Numerical Password` di E02, dibuat 2026-12-14 03:27:15 UTC (10:27:15 WIB), hari laptop dipasang. `VolumeType` 1 menunjuk volume sistem operasi. Dua kunci atau lebih berarti pernah ada rotasi atau enkripsi ulang; yang dipakai adalah yang ID-nya cocok dengan E02, bukan yang terbaru.

Isi kunci baru dibaca setelah ID cocok. Lewat Graph, permintaannya memakai `$select=key`, dan permintaan itu yang memicu audit [S8]:

```
Get-MgInformationProtectionBitlockerRecoveryKey -BitlockerRecoveryKeyId 6f3a9c21-4b7e-4d18-9a05-2c8e71d4b930 -Property "key"
```

PT JAB memilih tombol **Show Recovery Key** di pusat admin Entra, bukan Graph, supaya prosedur bisa diikuti orang IT yang tidak memakai PowerShell. Agung membaca kunci pukul 09:21:47, menyimpannya ke brankas kata sandi tim IT di entri `INC-2027-012 / BDG-WS-0185 / C:` pukul 09:24, dan membagikan entri itu hanya ke Yoga dan kamu.

Agung juga memastikan AD DS menyimpan objek recovery dengan GUID yang sama, tanpa meminta atribut kata sandinya:

```
Get-ADObject -Filter "objectClass -eq 'msFVE-RecoveryInformation'" `
    -SearchBase "CN=BDG-WS-0185,OU=Workstations,OU=Bandung,DC=corp,DC=jab,DC=example" `
    -Properties msFVE-RecoveryGuid, msFVE-VolumeGuid, whenCreated |
  Select-Object whenCreated, msFVE-RecoveryGuid, msFVE-VolumeGuid |
  Sort-Object whenCreated -Descending
```

- Hasilnya bisa lebih dari satu baris, karena satu objek komputer bisa punya beberapa objek recovery dan AD menyimpan riwayatnya [S2].
- Cocokkan `msFVE-RecoveryGuid` dengan GUID yang ditampilkan layar recovery, atau `msFVE-VolumeGuid` dengan volume yang kamu periksa [S2].
- Nama atribut di PowerShell memakai `msFVE-` sedangkan dokumentasi skema menulis `ms-FVE-`; cocokkan dengan hasil di lab-mu. Atribut GUID disimpan sebagai data biner, jadi keluaran di bawah sudah dikonversi ke bentuk GUID; cek cara konversinya di lab.
- Versi lengkap perintah ini menambahkan `msFVE-RecoveryPassword` di `-Properties` dan `Select-Object`, dan itulah yang dipakai bila kunci hanya ada di AD DS. Di PT JAB versi itu dipakai hanya bila Entra ID tidak menyimpan kuncinya (laptop di luar kelompok 271 dan 47 di bagian 2.1), dengan catatan manual karena pembacaannya tidak diaudit.

Keluaran ilustrasi (waktu lokal WIB, GUID dikonversi):

```
whenCreated          msFVE-RecoveryGuid                     msFVE-VolumeGuid
-----------          ------------------                     ----------------
2026-12-14 10:27:16  {6F3A9C21-4B7E-4D18-9A05-2C8E71D4B930} {B1E47F02-6C3D-4A85-9E21-0F7D3C5A8B64}
```

Pukul 09:26 Agung menulis di kanal: kunci diambil dari Entra ID, Key ID cocok dengan E02, AD DS punya objek dengan GUID yang sama. Dua escrow yang sepakat memberi cadangan bila salah satunya bermasalah.

Entri audit dari pembacaan itu bisa diperiksa siapa saja yang berwenang membaca log audit Entra, dan ikut tersimpan di Splunk. Keluaran ilustrasi pencarian di index `o365`:

```
index=o365 sourcetype="azure:monitor:aad" activity="Read BitLocker key" earliest="02/09/2027:00:00:00" latest="02/10/2027:00:00:00"
| table _time, initiated_by, activity, target
```

```
_time (WIB)          initiated_by           activity           target
2027-02-09 09:21:47  adm.agung@jab.example  Read BitLocker key BDG-WS-0185 / 6f3a9c21-4b7e-4d18-9a05-2c8e71d4b930
```

- `activity="Read BitLocker key"`: nama aktivitas di kategori `KeyManagement` [S10]. Nama field dan sourcetype mengikuti alias SOC PT JAB untuk log audit Entra; cocokkan dengan konfigurasi index di Splunk-mu.
- Rentang waktu ditulis absolut, karena pencarian ini bagian dari dokumentasi kasus yang bisa diulang kapan saja.

**Cara membaca hasil:** tepat satu pembacaan, oleh orang yang ditunjuk, satu menit setelah persetujuan. Pembacaan lain atas kunci perangkat ini di masa depan (misalnya oleh pemilik lewat portal akun) juga akan muncul di pencarian yang sama, dan itu alasan pengaturan pembatasan swalayan diusulkan diubah.

**Kapan gagal:** "No BitLocker key found for this device" di Intune berarti kunci tidak ada di Entra ID [S10]; cek AD DS, lalu bila tetap tidak ada, kembali ke jalur sistem hidup (`manage-bde -protectors -get` tanpa topeng, dijalankan dengan persetujuan yang sama dan keluarannya langsung masuk brankas). Akun dengan peran yang dibatasi ke administrative unit tertentu bisa tidak melihat kunci perangkat di luar unitnya [S7].

### 2.6 Image logis volume VeraCrypt `V:`: `INC-2027-012-E03`, lalu mematikan laptop

Langkah ini adalah satu-satunya jalur yang tidak bergantung pada kerja sama Ilham untuk menyimpan isi kontainer dalam keadaan saat insiden. Pukul 09:35 Ratna Sari (Legal) menyetujui image logis `V:` dengan tiga syarat: isi tidak dibuka sampai lingkup analisisnya diputuskan, yang boleh dilihat hanya hash dan daftar nama berkas beserta metadatanya, dan salinan diperlakukan sebagai data rahasia perusahaan karena berisi konfigurasi perangkat pelanggan.

Image logis butuh sesi interaktif dengan hak administrator. Fajar membuka sesi `ir-admin` lewat Switch user di layar kunci pukul 09:40 (kata sandi `ir-admin` khusus host ini diterima dari Yoga lewat Signal, sesuai rencana nomor 6), lalu menjalankan FTK Imager portabel dari folder alat di `USB-E-15` (SSD eksternal NTFS 1 TB, terpasang sebagai `F:`):

```
File > Create Disk Image > Logical Drive > V:\ - [NTFS]
  Image type          : E01
  Evidence number     : INC-2027-012-E03
  Examiner            : Fajar Nugraha
  Destination         : F:\INC-2027-012\E03\
  Image filename      : INC-2027-012-E03_BDG-WS-0185_V
  Verify after create : ya
```

- `Logical Drive`: sumber berupa volume yang dilihat Windows, sehingga yang tersalin adalah isi `V:` dalam keadaan terdekripsi [S18]. Memilih `Physical Drive` pada sistem hidup memberi blok terenkripsi BitLocker, bukan plaintext [S18].
- `E01` dengan nomor bukti: format dan penamaan sama dengan image lain PT JAB, supaya hash dan metadata akuisisi tersimpan di dalam image.
- `Verify after create`: alat membaca ulang image dan membandingkan hash dengan hash sumber.

Nama menu dan pilihan ditulis sebagai ilustrasi; cocokkan dengan versi FTK Imager di toolkit-mu.

Keluaran ilustrasi (ringkasan log akuisisi, waktu WIB):

```
09:46:12  mulai: sumber V:\ (Logical), sekitar 8 GiB
10:04:37  selesai akuisisi
10:11:02  verifikasi selesai: hash sumber dan hash image cocok
          SHA-256 image (dihitung terpisah di jkt-evid01): 2c95...
```

**Cara membaca hasil:** E03 adalah salinan isi `V:` sebagaimana dibaca Windows pukul 09:46 sampai 10:04, termasuk ruang kosong volume itu yang dalam tampilan terdekripsi berisi data acak hasil pengisian saat volume dibuat [S4], sehingga kompresi E01 hampir tidak mengecilkannya. Image logis tidak memuat apa pun di luar volume `V:`; berkas kontainer `konfig-bdg.dat` sendiri (dalam bentuk terenkripsi) akan ada di image fisik E04. Sebelum memilih sumber, Fajar memastikan `V:` terlihat dari sesi `ir-admin`. Di kasus ini terlihat; apakah volume VeraCrypt yang di-mount pengguna selalu terlihat dari sesi pengguna lain perlu dicek di lab (bagian 3). Bila tidak terlihat, pilihan yang tersisa adalah memori atau kata sandi dari Ilham.

**Variasi:** bila Legal tidak menyetujui image logis, laptop tetap dimatikan setelah memori dan kunci `C:` aman. Isi kontainer kemudian hanya bisa dibuka dengan kata sandi yang diserahkan Ilham secara sukarela atau kunci dari image memori, keduanya dengan persetujuan baru.

**Kapan gagal:** image logis dari volume yang sedang dipakai proses lain bisa tidak konsisten (smear, sama seperti memori); di kasus ini proses penyerang sudah tidak bisa berkomunikasi karena isolasi, tetapi prosesnya belum dihentikan, sehingga isi `V:` bisa berubah selama akuisisi. Catat jendela waktunya, dan jangan menulis bahwa E03 adalah potret satu detik.

Pukul 10:15 Fajar mematikan laptop dari sesi `ir-admin` lewat menu Start, memilih tetap mematikan walau ada pengguna lain yang masih login. `V:` tidak di-dismount secara manual: shutdown bersih melepas volume VeraCrypt dan menghapus master key-nya dari RAM [S13], dan itu sudah diantisipasi dengan E01 dan E03. Laptop mati pukul 10:17.

### 2.7 Image fisik SSD: `INC-2027-012-E04` dan chain of custody

Langkah ini memberi salinan paling lengkap volume `C:`, termasuk ruang tak teralokasi dan berkas kontainer dalam bentuk terenkripsinya, dan menjawab pertanyaan 4 di lapangan: SSD dicabut hanya setelah kunci terverifikasi, dan laptop tidak dinyalakan lagi.

```
10:20  Laptop dimasukkan ke kantong bukti No. 0118 (foto, label aset, keadaan mati).
10:45  Fajar membuka casing di meja bukti POP; foto sebelum dan sesudah. SSD NVMe M.2 512 GB dicabut,
       nomor seri dicatat di formulir CoC. Laptop tanpa SSD kembali ke kantong No. 0118; SSD ke kantong No. 0119.
11:05  SSD dipasang ke write blocker NVMe di stasiun akuisisi POP; akuisisi E01 ke USB-E-15 (F:).
11:48  Akuisisi selesai. 12:26 verifikasi selesai, hash cocok. SHA-256 image d71a...
12:40  USB-E-14 (E01, E02) kantong No. 0120; USB-E-15 (E03, E04) kantong No. 0121.
13:30  Kantong 0118-0121 ke kurir, resi INT-0209-031.
```

**Cara membaca hasil:** E04 berisi tabel partisi GPT, partisi EFI dan recovery yang tidak terenkripsi, dan partisi `C:` yang terenkripsi BitLocker. Tanpa recovery password, isi `C:` di E04 tidak bisa dibaca; dengan recovery password dari brankas, ia dibuka di Jakarta (bagian 2.8). Mencabut SSD tidak menulis apa pun ke SSD; mode recovery hanya terpicu bila SSD itu di-boot di perangkat lain atau laptopnya di-boot dengan konfigurasi yang berubah [S2].

**Kapan gagal:** pada laptop dengan penyimpanan yang disolder ke motherboard, SSD tidak bisa dicabut. Pilihannya image dari sistem hidup sebelum dimatikan (logis atau fisik dengan alat yang membaca disk dari dalam Windows), atau boot media forensik yang hanya menghasilkan blok terenkripsi; keduanya ditimbang sebelum laptop dimatikan, bukan sesudahnya.

Rabu 2027-02-10 pukul 09:10 Yoga menerima kantong 0118-0121 di Jakarta, mencocokkan segel dan resi, lalu menyalin E01 sampai E04 ke `/evidence/INC-2027-012/` di `jkt-evid01`. Hash keempatnya cocok dengan nilai di lokasi. Salinan kerja `E04-W1` dibuat Yoga di `/cases/INC-2027-012/work/` pukul 10:30.

### 2.8 Membuka `E04-W1` untuk analisis

Langkah ini menjawab pertanyaan 6. Prinsipnya: image EWF dibuka sebagai raw, partisi BitLocker didekripsi dalam mode baca saja, lalu NTFS-nya di-mount read-only. Kamu mengerjakannya di `jkt-dfir02` setelah menyalin `E04-W1` ke disk lokal `/data/work/INC-2027-012/E04-W1/` dan mencocokkan hash.

```
sudo mkdir -p /mnt/e04w1-raw /mnt/e04w1-bde /mnt/e04w1-c
sudo ewfmount /data/work/INC-2027-012/E04-W1/INC-2027-012-E04.E01 /mnt/e04w1-raw
sudo mmls /mnt/e04w1-raw/ewf1
```

- `ewfmount`: membuka image EWF sebagai berkas raw virtual `ewf1`, tanpa mengubah image.
- `mmls`: menampilkan tabel partisi dan sektor awal tiap partisi, untuk menghitung offset partisi BitLocker.

Keluaran ilustrasi `mmls` (satuan sektor 512 byte):

```
GUID Partition Table (EFI)
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
004:  000       0000002048   0000206847   0000204800   EFI system partition
005:  001       0000206848   0000239615   0000032768   Microsoft reserved partition
006:  002       0000239616   0997849087   0997609472   Basic data partition
007:  003       0997849088   0999999487   0002150400   Basic data partition
```

**Cara membaca hasil:** partisi slot 002 adalah `C:`: 997.609.472 sektor x 512 byte = 510.776.049.664 byte, sekitar 475,70 GiB, sama dengan `Size` di E02. Offset-nya 239.616 x 512 = 122.683.392 byte. Partisi terakhir sekitar 1,03 GiB adalah partisi recovery Windows.

```
sudo dislocker -r -V /mnt/e04w1-raw/ewf1 -O 122683392 -p -- /mnt/e04w1-bde
sudo mount -o ro,loop /mnt/e04w1-bde/dislocker-file /mnt/e04w1-c
ls -l /mnt/e04w1-c/Users/ilham.maulana/Documents/Arsip/
```

- `-r`: mode baca saja, tidak ada penulisan ke volume BitLocker [S16].
- `-V /mnt/e04w1-raw/ewf1` dan `-O 122683392`: volume sumber dan offset partisi dalam byte [S16].
- `-p` tanpa nilai: dislocker meminta recovery password secara interaktif; kamu menempelnya dari brankas, dan kata sandi tidak tercatat di riwayat shell atau daftar proses [S16].
- `-- /mnt/e04w1-bde`: argumen setelah `--` diteruskan ke FUSE; di titik mount itu muncul `dislocker-file` [S16].
- `mount -o ro,loop`: NTFS di dalam `dislocker-file` di-mount read-only.

Keluaran ilustrasi:

```
-rw-r--r-- 1 root root 8589934592 Feb  8 21:47 konfig-bdg.dat
```

**Cara membaca hasil:** volume terbuka, dan berkas kontainer ada dengan ukuran tepat 8 GiB, sama dengan `fileinfo` live response pukul 08:24. Waktu modifikasi yang ditampilkan bergantung pada zona waktu sistem analisis dan pada perilaku VeraCrypt terhadap timestamp kontainer; waktu yang dipakai di laporan diambil dari `$MFT` (bagian 2.9). Setelah ini, analisis `C:` berjalan seperti Day 03 sampai Day 13 dari `/mnt/e04w1-c`, atau dari salinan artefak yang diambil darinya.

Catat di case notes: alat dan versinya, Key ID yang dipakai (bukan kata sandinya), waktu, dan bahwa dekripsi dilakukan atas `E04-W1`, bukan master.

**Variasi di Windows:** salinan kerja di-mount read-only sebagai disk di `JKT-DFIR01`, volume BitLocker-nya muncul terkunci (misalnya sebagai `H:`), lalu dibuka:

```
manage-bde -unlock H: -recoverypassword 111111-222222-333333-444444-555555-666666-777777-888888
```

- Dijalankan terhadap salinan bukti yang sudah dipasang, bukan terhadap disk asli.
- Alternatifnya `-recoverykey` dengan berkas `.bek` [S1][S2].
- Recovery password di contoh ini fiktif; dalam praktik nilainya ditempel dari brankas dan tidak disimpan di skrip atau riwayat perintah.

**Kapan gagal:** recovery password yang benar untuk volume yang salah akan ditolak. Periksa ulang pencocokan GUID. Spasi di depan atau di belakang kata sandi juga membuat sebagian alat menolaknya [S18]. Bila dislocker tidak mengenali volume, cek offset (`mmls`), lalu cek dukungan alat untuk versi BitLocker di Windows 11 24H2 di lab sebelum mencoba alat lain [S16].

### 2.9 Mengenali kontainer VeraCrypt dari artefak di luar kontainer

Langkah ini menjawab bagian pertama pertanyaan 7 tanpa membuka isi kontainer, dan menguji keterangan Ilham. Semua artefak diambil dari `C:` yang sudah terbuka di bagian 2.8, ditambah E01 untuk keadaan saat akuisisi. Hive dan artefak yang diperlukan disalin dari `/mnt/e04w1-c` ke folder kerja kasus lalu diolah di `JKT-DFIR01`; perintah parsing mengikuti Day 07 sampai Day 10, dan yang khusus di sini adalah apa yang dicari:

```
RECmd.exe -f "C:\DFIR\work\INC-2027-012\E04-W1\reg\NTUSER.DAT" --sa "VeraCrypt"
```

Yang dicari, semuanya artefak di sekitar, bukan isi kontainer:

- Jejak pemasangan dan eksekusi aplikasi: artefak eksekusi (Day 07), layanan dan driver di registry (Day 09).
- Daftar berkas yang pernah dibuka aplikasi itu, termasuk MRU milik aplikasinya sendiri bila ada; untuk VeraCrypt, `History.xml` [S19].
- Jejak volume yang pernah ter-mount: huruf drive yang muncul tanpa perangkat fisik padanan, di `MountedDevices` dan artefak shell (Day 10).
- Berkas kandidat kontainer: ukuran bulat yang tidak lazim, tidak punya ekstensi yang dikenal, tidak pernah dibuka aplikasi lain, dan entropinya tinggi.

Tabel berikut adalah hasilnya untuk `BDG-WS-0185` (keluaran ilustrasi, waktu WIB setelah konversi dari UTC). Baca kolom terakhir: setiap baris membatasi apa yang boleh dikatakan.

| Artefak | Temuan | Artinya |
|---|---|---|
| `veracrypt.sys` dan folder `C:\Program Files\VeraCrypt\` | Dibuat 2026-12-15 13:41:07 | VeraCrypt dipasang sebagai aplikasi (bukan portable) sehari setelah laptop diterima Ilham; pemasangan butuh hak admin lokal, yang dimiliki engineer jaringan POP lewat grup admin lokal untuk alat jaringan |
| Prefetch `VERACRYPT.EXE` | Run count 23, eksekusi terakhir Senin 2027-02-08 14:04:51 | Konsisten dengan keterangan Ilham bahwa `V:` di-mount Senin sekitar 14:05 |
| `History.xml` | Satu entri: `C:\Users\ilham.maulana\Documents\Arsip\konfig-bdg.dat` | Hanya satu kontainer yang pernah dicoba di-mount dari profil ini |
| `Configuration.xml` | Enkripsi RAM tidak aktif | Kunci VeraCrypt di E01 tidak dienkripsi oleh VeraCrypt sendiri; cek nama elemen konfigurasinya di lab |
| `$MFT` `konfig-bdg.dat` | Dibuat 2026-12-15 13:52:10; ukuran 8.589.934.592 byte | Dialokasikan sekaligus dengan ukuran bulat 8 GiB, sepuluh menit setelah pemasangan |
| `MountedDevices` dan LNK di Recent Ilham | Huruf `V:` dengan label `KONFIG`; 41 LNK menunjuk ke `V:\CPE\...` dengan VolumeID yang sama, terakhir Senin 2027-02-08 15:12:40 | Berkas di `V:` dibuka Ilham lewat shell; nama folder konsisten dengan konfigurasi CPE |
| Entropi 64 MiB pertama `konfig-bdg.dat` | Sekitar 7,99 bit per byte | Konsisten dengan data terenkripsi; bukan bukti sendiri |
| E01: proses dan modul | `VeraCrypt.exe` di sesi 1 milik `ilham.maulana`; `veracrypt.sys` termuat | `V:` ter-mount oleh sesi Ilham saat akuisisi |

Cara membaca entropi: nilai mendekati 8 berarti isinya tidak terstruktur, konsisten dengan data terenkripsi atau terkompresi. Ukuran yang persis bulat dalam satuan biner menandakan berkas yang dialokasikan sekaligus, bukan tumbuh perlahan. Keduanya adalah indikasi, bukan bukti.

- **Batas yang wajib ditulis di laporan:** kamu tidak bisa membuktikan isinya kontainer VeraCrypt dari entropi saja, dan kamu tidak bisa membuktikan ada hidden volume di dalamnya [S4]. Yang bisa dilaporkan adalah keberadaan perangkat lunak, jejak pemakaiannya, dan berkas yang karakteristiknya konsisten dengan kontainer.
- Arah yang lebih produktif: cari berkas yang pernah berada di dalam kontainer lewat artefak di luar kontainer, yaitu MRU, jump list, shellbag, prefetch, dan sisa di memori.

Nama berkas di LNK menyebut kode pelanggan, sehingga daftar itu sendiri diperlakukan sebagai data rahasia, sesuai syarat Legal untuk E03. Pertanyaan apakah proses penyerang pernah membuka berkas di `V:` dijawab dari E01 dan telemetri Defender pada tahap analisis berikutnya, bukan dari artefak shell, karena proses tanpa antarmuka tidak menulis LNK atau ShellBags (Day 10).

### 2.10 Catatan keputusan untuk Rudi dan ringkasan untuk Dimas

Catatan pertama kamu kirim ke Rudi pukul 08:41, sebelum satu perintah akuisisi pun dijalankan. Ia sengaja pendek, karena Fajar menunggu di depan laptop:

```
INC-2027-012 / BDG-WS-0185 - rencana akuisisi (08:41)
1. Jangan matikan. Charger tetap, lid terbuka, tanpa restart/update. Isolasi Defender cukup.
2. Memori dulu (E01): Fajar colok USB-E-14, Rudi jalankan jab-memcapture.ps1 via live response.
3. Status BitLocker C: dan ID protector (E02): jab-bdestatus.ps1. Kirim Key ID ke kanal.
4. Kunci C: diambil Agung dari Entra (Show Recovery Key) setelah Dimas setuju; cocokkan Key ID;
   cek AD DS punya GUID sama. Kunci ke brankas IT, bukan ke chat.
5. V: (VeraCrypt) tidak punya kunci cadangan. Minta Legal: image logis V: selagi ter-mount (E03).
   Jangan dismount, jangan buka isinya.
6. Setelah 1-5: shutdown dari Start. Jangan boot lagi. SSD dicabut, image lewat write blocker (E04).
7. Tidak dilakukan: suspend BitLocker, -forcerecovery, boot USB, update BIOS, menebak kata sandi VeraCrypt.
```

Ringkasan untuk Dimas pukul 12:40, setelah E04 terverifikasi, menjawab ketujuh pertanyaan Rudi dalam bentuk keputusan dan statusnya:

| Pertanyaan | Keputusan | Status 12:40 |
|---|---|---|
| 1. Dimatikan? | Tidak sampai memori, kunci, dan `V:` aman; lalu shutdown bersih | Mati 10:17 |
| 2. Urutan | Memori, status, kunci `C:`, image logis `V:`, shutdown, image fisik | E01 sampai E04 selesai, hash cocok |
| 3. Recovery key | Diminta Rudi, disetujui Dimas, dibaca Agung di Entra, audit `Read BitLocker key` 09:21:47; disimpan di brankas | Selesai; rotasi kunci setelah kasus |
| 4. Perubahan hardware/boot | SSD dicabut setelah kunci terverifikasi; tidak ada boot, suspend, atau perubahan firmware | Laptop tidak dinyalakan lagi |
| 5. Kunci dari memori | E01 menyimpan kunci kedua volume; ekstraksi hanya oleh retainer bila diperlukan, dengan izin | Tidak dijalankan |
| 6. Membuka di Jakarta | Salinan kerja, dekripsi baca saja, mount read-only | Dijadwalkan Rabu setelah kurir tiba |
| 7. VeraCrypt | Kontainer dikenali dari artefak di luar; isi dan niat tidak disimpulkan; isi E03 menunggu lingkup dari Legal | Daftar artefak Rabu |

Dua temuan tata kelola ikut dikirim sebagai usulan, bukan sebagai bagian investigasi: atur pembatasan swalayan recovery key untuk pengguna non-admin dan aturan pemakaian peran Security Reader oleh SOC, dan tetapkan kebijakan penyimpanan konfigurasi perangkat pelanggan supaya engineer tidak perlu kontainer pribadi.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** `LAB-WS01` (`172.16.50.10`, Windows 11 24H2) dengan vTPM aktif dan Secure Boot, satu disk virtual tambahan untuk volume data, VeraCrypt terpasang; `LAB-DFIR01` (`172.16.50.20`) sebagai mesin analisis, ditambah VM Linux analisis bila ada (misalnya `LAB-TL01`) untuk dislocker; jaringan host-only `172.16.50.0/24`; snapshot bersih sebelum tiap percobaan. Folder kasus lab `CASE-2026-LAB-022`. Lab domain tidak wajib; bila ada, langkah 3 memakai AD DS lab. Semua kata sandi dan recovery password di lab adalah milik lab dan tidak dipakai di tempat lain. Perintah yang mengubah protector hanya dijalankan di VM lab.

1. **Keadaan awal.** Aktifkan BitLocker pada `C:` dengan protector TPM dan recovery password, dan pada volume data `D:` dengan protector password. Jalankan `manage-bde -status` dan `manage-bde -protectors -get C:` serta `-get D:`, lalu simpan keluarannya sebagai `LAB022-status-awal.txt`. Tulis skrip kecil yang menopengi nilai `Password` sebelum keluaran disimpan, seperti skrip `jab-bdestatus.ps1` di bagian 2.4.
2. **Recovery password dan berkas `.bek`.** Simpan recovery password `D:` ke berkas dan buat recovery key `.bek` ke disk virtual kecil berlabel `LAB-USB`. Kunci `D:`, lalu uji `manage-bde -unlock D:` dengan `-recoverypassword` dan dengan `-recoverykey`. Catat perbedaan prosedurnya dan Key ID yang dipakai.
3. **Escrow (opsional, butuh lab domain).** Konfigurasikan pencadangan recovery ke AD DS lab, lalu ambil kembali dengan perintah `Get-ADObject` di bagian 2.5 dan cocokkan GUID-nya dengan yang ditampilkan `-protectors -get`. Jalankan dua versi: tanpa dan dengan atribut kata sandi. Bila lab domain memasang audit Directory Service Access dengan SACL pada objek recovery, periksa apakah pembacaan atribut itu muncul sebagai event 4662 di DC.
4. **Memori sebelum dan sesudah.** Mount kontainer VeraCrypt lab `lab-kontainer.dat` (1 GiB) sebagai `V:` di sesi `lab.user`, buka satu berkas teks di dalamnya, lalu ambil memori dua kali: lewat snapshot VM (berkas memori hypervisor) dan lewat WinPmem ke `LAB-USB`. Hash keduanya. Jalankan `windows.pslist` dan `windows.modules` dari Volatility 3 untuk menemukan `VeraCrypt.exe` dan `veracrypt.sys`, lalu catat sesi pemiliknya (Day 14).
5. **Visibilitas volume antar sesi.** Masih dengan `V:` ter-mount di sesi `lab.user`, buka sesi kedua dengan admin lokal `lab.ir` lewat Switch user. Catat apakah `V:` terlihat di Explorer, di `Get-Volume`, dan di daftar sumber Logical Drive alat imaging-mu. Ulangi dengan opsi mount VeraCrypt yang berbeda bila ada. Hasil langkah ini menentukan apakah cara di bagian 2.6 bisa diandalkan.
6. **Image logis vs image fisik dari sistem hidup.** Dengan `C:` ter-unlock, buat image logis `C:` dan image fisik disk sistem dari dalam VM (alat yang sama). Buka keduanya di `LAB-DFIR01` tanpa kunci: catat mana yang terbaca dan mana yang hanya berisi blok terenkripsi.
7. **Jebakan akuisisi.** Matikan VM, lepaskan disk virtual sistem, lalu pasang ke VM lain dan nyalakan VM itu dari disk tersebut. Amati layar recovery: catat Key ID yang tampil dan cocokkan dengan keluaran langkah 1 [S2]. Kembalikan snapshot setelah percobaan, karena membuka volume OS dengan recovery protector di perangkat lain mengikatnya ke TPM baru [S7].
8. **Suspend, clear key, dan reboot.** Suspend proteksi `C:`, lakukan satu perubahan yang biasanya memicu recovery (misalnya urutan boot), lalu amati bahwa recovery tidak terpicu. Sebelum reboot, ambil image fisik dan coba buka di `LAB-DFIR01` tanpa kunci; catat apakah alatmu membaca volume ber-clear key. Reboot dan periksa apakah proteksi melanjut sendiri [S2].
9. **Key package.** Hasilkan key package untuk `D:` dengan `manage-bde -KeyPackage`, simpan di luar VM, dan catat format nama berkasnya.
10. **Membuka image di Linux.** Di VM Linux analisis, buka image fisik dari langkah 6 dengan `ewfmount` atau langsung sebagai raw, hitung offset dengan `mmls`, lalu buka dengan `dislocker -r ... -p` dan mount read-only seperti bagian 2.8. Hash image sebelum dan sesudah untuk membuktikan tidak ada yang berubah. Catat versi dislocker dan apakah volume 24H2 terbaca.
11. **Artefak VeraCrypt.** Dari image `C:` yang sudah terbuka, kumpulkan `veracrypt.sys`, `History.xml`, `Configuration.xml`, Prefetch `VERACRYPT.EXE`, `MountedDevices`, LNK, dan ShellBags yang menunjuk `V:`. Tulis daftar berkas yang bisa kamu ketahui pernah ada di dalam kontainer tanpa membukanya. Lalu matikan riwayat VeraCrypt, mount lagi, dan catat apa yang berubah di `History.xml`.
12. **Timestamp kontainer.** Catat timestamp `$MFT` `lab-kontainer.dat` sebelum mount, setelah menulis satu berkas ke `V:`, dan setelah dismount. Simpulkan apakah waktu modifikasi kontainer bisa dipakai sebagai waktu terakhir isi kontainer berubah di versi VeraCrypt-mu.
13. **Entropi.** Hitung entropi beberapa berkas di VM: kontainer VeraCrypt, berkas ZIP, video, dan dokumen biasa. Tulis kesimpulan tentang seberapa jauh entropi bisa membedakan keduanya.
14. **Keputusan tertulis.** Tulis satu halaman keputusan akuisisi untuk skenario laptop terenkripsi yang ditemukan menyala, terkunci layar, dengan satu volume BitLocker berkunci di escrow dan satu volume VeraCrypt ter-mount, lengkap dengan alasan tiap langkah dan kalimat yang boleh dan tidak boleh ditulis tentang kontainer.

**Hasil yang sebaiknya tersimpan:**

- Keluaran `manage-bde -status` dan `-protectors -get` sebelum dan sesudah percobaan, dengan nilai recovery password ditopengi.
- Bukti pencocokan GUID antara layar recovery, hasil `-protectors -get`, dan objek di AD DS lab bila ada.
- Catatan percobaan pemindahan disk yang memicu mode recovery, termasuk Key ID di layar.
- Hasil percobaan suspend dan resume, termasuk perilaku setelah reboot dan apakah image ber-clear key terbaca tanpa kunci.
- Berkas key package beserta format namanya.
- Tabel visibilitas `V:` antar sesi dan per opsi mount.
- Perbandingan image logis dan image fisik dari sistem hidup: mana yang terbaca tanpa kunci.
- Log pembukaan image di Linux dengan hash sebelum dan sesudah.
- Daftar berkas yang teridentifikasi pernah berada di kontainer VeraCrypt, hanya dari artefak di luar, dan perubahan `History.xml` saat riwayat dimatikan.
- Tabel timestamp kontainer di tiga keadaan.
- Tabel entropi beberapa jenis berkas beserta kesimpulan batasnya.
- Satu halaman keputusan akuisisi dengan alasan.

**Variasi tantangan:** ulangi langkah 4 dengan opsi enkripsi RAM VeraCrypt diaktifkan, lalu catat apa yang berubah pada perilaku hibernate dan apakah ada perbedaan yang terlihat di hasil Volatility. Tulis satu paragraf yang menjelaskan ke retainer kenapa image memori dari host dengan opsi itu tidak menjanjikan kunci yang bisa dipakai.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat menangani disk dan volume terenkripsi. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Mesin minta recovery key setelah disk dipindahkan | Memindahkan drive ke komputer lain memang memicu recovery [S2] | Siapkan recovery password sebelum memindahkan apa pun |
| Recovery password ditolak | Kunci untuk volume lain | Cocokkan GUID recovery dan GUID volume [S2] |
| Recovery password ditolak padahal Key ID cocok | Spasi atau karakter tambahan saat menempel; salah ketik satu blok | Tempel ulang tanpa spasi; konsol recovery Windows memeriksa checksum tiap blok 6 digit [S7][S18] |
| Tidak ada objek recovery di AD | Pencadangan ke AD DS tidak dikonfigurasi, atau perangkat Entra joined | Periksa kebijakan pencadangan; cari di Entra sebagai `bitlockerRecoveryKey` [S2][S3] |
| Intune menampilkan "No BitLocker key found for this device" | Kunci tidak dicadangkan ke Entra ID | Cek AD DS; bila tetap tidak ada dan host hidup, baca dari host dengan persetujuan [S10][S17] |
| Admin tidak melihat kunci perangkat tertentu di Entra | Peran dibatasi ke administrative unit lain | Minta admin dengan cakupan yang benar [S7] |
| Key package tidak ada di AD | Key package memang tidak disimpan secara bawaan [S2] | Aktifkan opsi pencadangan key package; ekspor dari volume yang masih sehat |
| Key package tidak ditemukan di Entra | Key package tidak bisa disimpan di Entra ID [S2] | Simpan di AD DS atau sebagai berkas |
| `manage-bde` menolak dijalankan | Butuh hak administrator | Jalankan dari konteks admin; catat bila tidak bisa |
| Volume tampak terenkripsi tetapi terbuka tanpa kunci di alat analisis | Volume dalam keadaan clear key (BitLocker disuspend atau device encryption belum selesai) [S11] | Cek `Protection Status` di keluaran live; catat di laporan bahwa salinan itu terbaca siapa pun |
| Image fisik dari sistem hidup tetap terenkripsi | Sumber yang dipilih disk fisik, bukan volume logis [S18] | Pilih sumber logis bila tujuannya plaintext; image fisik tetap berguna bila kunci ada |
| `V:` tidak terlihat dari sesi admin | Volume di-mount di sesi pengguna lain | Uji di lab (bagian 3 langkah 5); pilihan tersisa memori atau kata sandi dari pemilik |
| dislocker gagal membuka volume | Offset salah, versi BitLocker belum didukung alat, atau kata sandi salah | Hitung ulang offset dengan `mmls`; uji alat dengan volume lab 24H2 [S16] |
| Image memori tidak memuat kunci VeraCrypt yang bisa dipakai | Enkripsi RAM VeraCrypt aktif, atau volume sudah di-dismount sebelum akuisisi [S13] | Cek `Configuration.xml`; catat batasnya, jangan menjanjikan hasil |
| Berkas berentropi tinggi tetapi bukan kontainer | Berkas terkompresi atau media terenkode juga berentropi tinggi | Jangan simpulkan dari entropi saja; cari artefak pendukung |
| Tidak bisa membuktikan ada hidden volume | Memang dirancang begitu [S4] | Laporkan apa adanya; kumpulkan artefak di luar kontainer |

## 5. Kesalahan umum dan jebakan

- Mematikan atau mencabut daya mesin terenkripsi yang masih ter-unlock sebelum memastikan kunci tersedia.
- Mencabut disk untuk dipasang ke write blocker tanpa memegang recovery password lebih dulu [S2].
- Menjalankan `manage-bde -ForceRecovery` pada sistem bukti, yang justru menghapus protector TPM [S1].
- Mencocokkan kunci dengan nama mesin alih-alih dengan GUID.
- Mengambil recovery password tanpa jalur persetujuan yang tercatat, padahal itu memberi akses penuh ke data.
- Membaca recovery key sendiri hanya karena peran SOC (misalnya Security Reader) secara teknis mengizinkannya, sehingga pemohon, penyetuju, dan pelaku menjadi orang yang sama [S9].
- Menulis recovery password di chat, case notes, evidence log, atau keluaran perintah yang disimpan ke folder kasus.
- Mengandaikan kunci ada di AD DS karena perangkat join domain, padahal pencadangan bergantung kebijakan saat enkripsi dimulai [S2][S7].
- Mengandaikan key package tersedia, padahal ia tidak dihasilkan otomatis dan tidak bisa disimpan di Entra [S2].
- Men-dismount volume VeraCrypt atau mematikan host sebelum memori diambil, sehingga master key terhapus dari RAM [S13].
- Menyuspend BitLocker di sistem bukti untuk "memudahkan image" tanpa mencatat bahwa itu menulis clear key ke volume dan membuat salinan terbaca siapa pun [S17].
- Menyalakan kembali laptop terenkripsi yang sudah dimatikan untuk "melihat sebentar".
- Menjanjikan kunci dari memori sebelum image memori dianalisis; hasilnya bergantung pada keadaan saat akuisisi dan konfigurasi aplikasi [S13][S17].
- Menyimpulkan keberadaan kontainer atau hidden volume hanya dari entropi berkas.
- Menulis keberadaan kontainer sebagai tanda menyembunyikan sesuatu; keberadaan bukan bukti isi atau niat.
- Menyerang berkas kontainer, padahal artefak di luar kontainer biasanya menjawab pertanyaan kasus lebih cepat.
- Lupa mencatat bahwa akuisisi dari sistem hidup mengubah sistem, beserta alasan memilihnya.

## 6. Catatan terkini

Bagian ini menampung detail versi, dokumentasi, dan perubahan perilaku yang bisa bergeser; alur keputusan di atas tidak bergantung padanya kecuali disebut.

- Dokumentasi BitLocker menyebut daftar panjang kondisi yang memicu mode recovery, dan beberapa di antaranya adalah tindakan forensik yang biasa dilakukan, terutama memindahkan drive ke komputer lain dan mengubah tabel partisi [S2]. Daftar itu layak dijadikan daftar larangan tersendiri di prosedur akuisisimu. Halaman yang diakses (ms.date 2025-07-29, diperbarui 2026-10-08) juga memuat docking atau undocking laptop dan kegagalan self-test TPM.
- Active Directory menyimpan riwayat seluruh recovery password untuk sebuah objek komputer dan tidak menghapus kunci lama secara otomatis [S2]. Dalam kasus yang menyangkut disk lama atau mesin yang sudah dipakai ulang, ini sering menyelamatkan.
- Key package tidak bisa disimpan di Microsoft Entra ID dan tidak dihasilkan otomatis [S2]. Di organisasi yang sepenuhnya Entra joined, ini celah pemulihan yang perlu disebut saat kamu memberi rekomendasi setelah kasus.
- Sejak Windows 11 24H2, prasyarat DMA dan HSTI atau modern standby untuk device encryption dihapus, sehingga lebih banyak perangkat terenkripsi otomatis; metode bawaannya XTS-AES 128 [S11]. Laptop yang tidak pernah diatur BitLocker oleh tim IT tetap perlu dicek statusnya.
- Intune memakai used space only encryption untuk perangkat modern standby dengan enkripsi senyap dan full disk encryption untuk perangkat lain, kecuali jenisnya diatur eksplisit [S10]. Entra ID menampung maksimal 200 recovery key per perangkat; bila batas itu tercapai, enkripsi senyap gagal karena pencadangan kunci gagal [S10].
- Rotasi recovery key lewat Intune butuh Windows 10 1909 atau lebih baru dan kebijakan rotasi berbasis klien; peran Intune yang mengelolanya adalah peran dengan izin Remote tasks untuk rotasi kunci, misalnya Help Desk Operator dan Endpoint Security Administrator [S10].
- Membaca isi kunci lewat Microsoft Graph butuh `$select=key`; tanpa itu hanya metadata yang dikembalikan, dan audit dipicu oleh permintaan yang menyertakan `$select` [S8]. Halaman API yang diakses bertanggal ms.date 2024-10-24.
- VeraCrypt versi terbaru per 2026-10-22 adalah 1.26.29 (rilis 2026-06-09). Enkripsi RAM untuk kunci dan kata sandi ada sejak 1.24 (Oktober 2019), khusus Windows 64-bit, mati secara bawaan; mode TrueCrypt dihapus sejak 1.26.7 (Oktober 2023), dan 1.25.9 masih bisa dipakai untuk me-mount atau mengonversi volume TrueCrypt [S12].
- Klaim ketidakterbuktian hidden volume VeraCrypt bersifat bersyarat, dan syaratnya menyangkut cara volume dibuat [S4]. Jangan menuliskannya sebagai hal mutlak di laporan, dan jangan pula menuliskan kebalikannya.
- Volatility 3 2.28.2 (rilis 17 September 2026) masih rilis terbaru per 2026-10-22 dan dipakai tanpa perubahan versi di kasus ini [S15]. Daftar plugin Windows-nya hanya memuat `windows.truecrypt.Passphrase` untuk enkripsi volume, tanpa plugin BitLocker atau VeraCrypt [S14].
- dislocker tidak menerbitkan rilis bertag di halaman proyeknya, dan halamannya menyebut dukungan sampai Windows 10 [S16]. Versi yang dipasang di `jkt-dfir02` dicatat dari commit atau paket distribusinya, dan dukungan volume Windows 11 dibuktikan di lab.

## 7. Cheat sheet

```
PRINSIP   disk terenkripsi MEMBALIK urutan akuisisi: jangan matikan dulu, kunci ada di memori
          hidup+unlocked = jendela terbuka; mati = jendela tertutup (mungkin selamanya)
          per VOLUME: kunci ada di escrow? ya -> image fisik setelah mati; tidak -> image logis selagi terbuka

URUTAN    jangan matikan/tutup lid/cabut/restart -> MEMORI -> status + Key ID -> ambil & cocokkan kunci
          -> image logis volume tanpa kunci (izin Legal) -> shutdown -> cabut SSD -> image fisik -> buka di lab

MANAGE-BDE  -status (keadaan semua drive) | -protectors -get (ID + GUID; di sistem hidup juga tampilkan password!)
            -unlock -recoverypassword|-recoverykey (HANYA di salinan kerja)
            -KeyPackage (hasilkan .KPG; butuh admin, HARUS sebelum volume rusak)
            -ForceRecovery = JANGAN di sistem bukti (hapus protector TPM)
            -lock / -off / -pause / -wipefreespace = JANGAN di sistem bukti
            suspend/resume = aman untuk perubahan terencana; resume otomatis saat reboot; suspend = clear key

KUNCI     recovery password = 48 digit (8 blok x 6, checksum per blok) | recovery key = <protector_id>.bek
          DRA = kunci induk | key package = untuk volume RUSAK; tidak otomatis; TIDAK bisa di Entra ID

AD DS     objek anak objek komputer, cn = ms-FVE-RecoveryInformation
          ms-FVE-RecoveryPassword (48 digit) | ms-FVE-RecoveryGuid (yang tampil di layar recovery)
          ms-FVE-VolumeGuid (unik per volume) | ms-FVE-KeyPackage
          AD simpan RIWAYAT; kunci lama tidak dihapus kecuali objek komputer dihapus
          default baca: Domain Admins; pembacaan TIDAK diaudit tanpa SACL
ENTRA     tipe sumber daya bitlockerRecoveryKey (admin Entra/Intune, PowerShell, Graph)
          Show Recovery Key -> audit KeyManagement "Read BitLocker key"
          Graph: metadata = BitlockerKey.ReadBasic.All ; isi kunci = $select=key (memicu audit)
          peran: Cloud Device Admin, Helpdesk Admin, Intune Admin, Security Admin, SECURITY READER, pemilik
COCOKKAN  lewat GUID / Key ID, JANGAN lewat nama mesin
SETELAH   recovery password yang sudah dilihat -> rotasi (Intune BitLocker key rotation)

PEMICU RECOVERY  pindah drive ke komputer lain | ubah tabel partisi | ubah boot manager | PXE boot
                 TPM dimatikan/dibersihkan/disembunyikan | PCR berubah | update BIOS/UEFI | PIN salah berkali-kali
                 docking/undocking | motherboard/TPM baru

BUKA IMAGE  ewfmount -> mmls (offset = start x 512) -> dislocker -r -V <raw> -O <offset> -p -- <mnt>
            -> mount -o ro,loop <mnt>/dislocker-file ; catat alat, versi, Key ID (bukan password)

VERACRYPT  tanpa tanda tangan; free space diisi data ACAK saat volume dibuat
           header hidden volume di byte 65536-131071; mount coba header standar dulu, lalu hidden
           "tidak bisa dibuktikan" = BERSYARAT (tergantung cara volume dibuat)
           artefak: veracrypt.sys | %APPDATA%\VeraCrypt\History.xml (20 terakhir) + Configuration.xml
                    Prefetch/Amcache VERACRYPT.EXE | MountedDevices + LNK/ShellBags huruf drive | memori
           kunci di RAM selama ter-mount; dismount/shutdown bersih HAPUS kunci; enkripsi RAM (1.24+) default mati
           yang BISA dilaporkan: ada software, ada jejak pakai, ada berkas berkarakter kontainer
           yang TIDAK bisa: isi kontainer, keberadaan hidden volume, niat; tidak dari entropi saja
           jalur sah ke isi: image logis saat ter-mount | kata sandi dari pemilik | kunci dari memori (retainer)
           arah produktif: artefak DI LUAR kontainer (MRU, jump list, shellbag, prefetch, memori)

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "`BDG-WS-0185` sudah diisolasi Defender dan recovery key `C:` ada di Entra ID, jadi laptop aman dimatikan sekarang juga; semua bisa dibuka nanti di lab." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Kunci `C:` memang ada di escrow, jadi image fisik `C:` bisa dibuka nanti. Tetapi laptop itu juga punya volume VeraCrypt `V:` yang sedang ter-mount dan tidak punya kunci cadangan di mana pun: shutdown bersih men-dismount-nya dan menghapus master key dari RAM, sehingga isi kontainer hanya bisa dibuka lagi dengan kata sandi Ilham. Mematikan lebih dulu juga menghapus isi memori, termasuk keadaan proses penyerang dan kunci kedua volume. Urutan yang benar adalah memori, status dan Key ID, verifikasi kunci `C:`, image logis `V:` dengan izin Legal, baru shutdown. Lihat bagian 1.1, 1.2, dan 1.5.

</details>

**2. Skenario keputusan.** Key ID volume `C:` sudah ada dari `manage-bde -protectors -get`. Rudi memegang peran Security Reader dan bisa melihat recovery key di pusat admin Entra. Cara mana yang paling tepat?

- A. Rudi langsung menekan Show Recovery Key sendiri, karena perannya mengizinkan dan waktu sempit, lalu menempel kunci ke kanal insiden supaya Fajar dan Yoga bisa memakainya.
- B. Rudi meminta di kanal insiden dengan Key ID, Dimas menyetujui, Agung membaca kunci di pusat admin Entra (tercatat `Read BitLocker key`), mencocokkan Key ID, lalu menyimpannya di brankas kata sandi tim IT untuk Yoga dan analyst yang membuka image.
- C. Agung membaca kunci dari AD DS dengan `Get-ADObject` termasuk `msFVE-RecoveryPassword`, karena tidak meninggalkan jejak di log audit Entra.

<details><summary>Jawaban</summary>

B. Pemohon, penyetuju, dan pelaku berbeda; pembacaan terjadi di jalur yang tercatat di kategori `KeyManagement`; kunci dicocokkan lewat Key ID dan disimpan di tempat yang terpisah dari dokumen kasus. A keliru karena satu orang menjadi pemohon, penyetuju, dan pelaku sekaligus, dan kunci yang memberi akses penuh ke disk berakhir di chat yang dibaca banyak orang. C keliru justru karena alasannya: pembacaan di AD DS PT JAB tidak diaudit, sehingga tidak ada bukti siapa membaca kunci kapan; AD DS dipakai untuk memastikan GUID yang sama ada, bukan untuk membaca kata sandinya. Lihat bagian 1.3 dan 2.5.

</details>

**3. Pertanyaan jebakan.** "Mencabut SSD laptop BitLocker dan memasangnya ke write blocker memicu mode recovery yang merusak data, jadi SSD tidak boleh dicabut sama sekali." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Mencabut SSD dan membacanya lewat write blocker tidak menulis apa pun ke SSD. Mode recovery juga bukan kerusakan: data tetap utuh, hanya volume tidak lagi terbuka otomatis lewat TPM dan meminta recovery password atau recovery key. Yang benar adalah image fisik dari SSD yang dicabut berisi blok terenkripsi, sehingga hanya berguna bila kuncinya sudah dipegang; karena itu SSD dicabut setelah kunci diverifikasi. Yang benar-benar dihindari adalah mem-boot SSD itu di perangkat lain atau mem-boot laptopnya dengan konfigurasi berubah, karena membuka volume OS dengan recovery protector di perangkat lain mengikatnya ke TPM baru. Lihat bagian 1.4 dan 2.7.

</details>

**4. Skenario keputusan.** Image memori E01 sudah ada. Retainer bertanya apakah tim internal bisa mengambil kunci VeraCrypt dari E01. Jawaban mana yang paling tepat?

- A. Jalankan `windows.truecrypt.Passphrase` di Volatility 3; plugin itu menemukan kata sandi VeraCrypt di memori.
- B. Volatility 3 2.28.2 tidak punya plugin kunci BitLocker atau VeraCrypt; internal memakai E01 untuk membuktikan `VeraCrypt.exe` berjalan di sesi siapa dan `veracrypt.sys` termuat, sedangkan ekstraksi kunci, bila diperlukan, dikerjakan retainer dengan alat tervalidasi atas salinan kerja dan dengan izin yang sama seperti membuka volume.
- C. Tidak perlu memori sama sekali, karena recovery key BitLocker sudah ada di Entra ID.

<details><summary>Jawaban</summary>

B. Plugin `windows.truecrypt.Passphrase` memindai driver `truecrypt.sys` untuk kata sandi TrueCrypt yang di-cache dan tidak menyebut VeraCrypt, jadi A menjanjikan sesuatu yang tidak dikerjakan plugin itu. C keliru karena kunci BitLocker di escrow tidak membantu kontainer VeraCrypt, dan memori juga menyimpan keadaan proses yang tidak ada di disk. Hasil ekstraksi kunci dari memori tidak bisa dijanjikan, misalnya bila enkripsi RAM VeraCrypt aktif. Lihat bagian 1.5 dan 2.9.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Ratna Sari (Legal), dalam tiga kalimat, apa yang boleh dan tidak boleh ditulis di laporan tentang kontainer VeraCrypt milik Ilham.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Laporan boleh menyebut bahwa ada berkas `konfig-bdg.dat` berukuran 8 GiB yang tercatat di riwayat VeraCrypt profil Ilham, sedang ter-mount sebagai `V:` saat akuisisi, dan isinya sudah disalin sebagai image logis dengan izin Ibu tetapi belum dibuka. Laporan tidak boleh menyimpulkan isi kontainer, niat Ilham, atau ada tidaknya hidden volume, karena keberadaan kontainer terenkripsi bukan bukti isi atau niat dan VeraCrypt dirancang supaya hidden volume tidak bisa dibuktikan. Artefak di luar kontainer hanya bisa menunjukkan apakah keterangan Ilham konsisten, misalnya kapan VeraCrypt dipasang dan nama folder yang ia buka dari `V:`."

Kesalahan yang sering muncul:
- Menulis kata "menyembunyikan" atau "mencurigakan" untuk kontainer yang keberadaannya sudah dijelaskan pemiliknya.
- Menulis "tidak ada hidden volume" sebagai kesimpulan, padahal hal itu tidak bisa dibuktikan ke arah mana pun.
- Lupa menyebut bahwa isi E03 belum dibuka dan menunggu keputusan lingkup.

</details>

**6. Pertanyaan jebakan.** "Entropi `konfig-bdg.dat` 7,99 bit per byte dan ukurannya tepat 8 GiB. Itu membuktikan berkas ini kontainer VeraCrypt, dan karena tidak ada header lain yang terlihat, tidak ada hidden volume di dalamnya." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Entropi mendekati 8 hanya menunjukkan isi tidak terstruktur, yang juga dimiliki berkas terkompresi dan media terenkode; ukuran bulat hanya menunjukkan alokasi sekaligus. Keduanya indikasi, bukan bukti. Yang menautkan berkas itu ke VeraCrypt di kasus ini adalah artefak lain: `History.xml`, Prefetch `VERACRYPT.EXE`, huruf `V:` di `MountedDevices` dan LNK, dan proses serta driver di memori. Ketiadaan header hidden volume yang terlihat juga tidak membuktikan apa-apa, karena area header hidden volume berisi data acak bila tidak ada hidden volume, dan dirancang tidak bisa dibedakan bila ada. Lihat bagian 1.7 dan 2.9.

</details>

**7. Interview question (English).** "You arrive at a laptop that is powered on, screen-locked, BitLocker-encrypted, and has a VeraCrypt volume mounted. Walk me through your acquisition and how you would handle the keys."

<details><summary>Sample answer</summary>

"First, I don't power it off, close the lid, or unplug anything, and I make sure it's isolated from the network if that hasn't happened already. I capture memory first, because RAM holds the keys for both the BitLocker volume and the mounted VeraCrypt volume, plus the process state. Then I record the BitLocker status and the protector IDs with manage-bde, masking the recovery password in anything I save. For BitLocker I check whether the recovery key is escrowed in Entra ID or AD DS, and I have IT read it through an approved, audited path, match it to the Key ID, and store it in a vault rather than in case notes. The VeraCrypt volume has no escrow, so with legal approval I take a logical image while it's still mounted, because a clean shutdown will dismount it and wipe its keys. Only then do I shut down, pull the SSD, image it through a write blocker, and decrypt a working copy read-only in the lab. In the report I describe the container from artifacts outside it and I don't draw conclusions about its contents, hidden volumes, or the owner's intent."

What makes this answer strong: it treats each volume separately based on whether a key exists outside the machine, puts memory first for a concrete reason, handles the recovery key as sensitive evidence with an audit trail, and closes with the limits of what encryption artifacts can prove.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Microsoft Learn: manage-bde | https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/manage-bde | primer | ms.date 2025-12-15, diperbarui 2026-02-16; dilihat 2026-10-09, dicek ulang 2026-10-22 | Tinggi. Daftar subperintah, arti `-status`, `-protectors`, `-unlock`, `-lock`, `-wipefreespace`, dan peringatan bahwa `-ForceRecovery` menghapus seluruh key protector terkait TPM |
| S2 | Microsoft Learn: BitLocker recovery overview | https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/recovery-overview | primer | ms.date 2025-07-29, diperbarui 2026-10-08; dilihat 2026-10-09, dicek ulang 2026-10-22 | Tinggi. Daftar pemicu mode recovery (termasuk docking dan kegagalan self-test TPM), opsi pemulihan (recovery password 48 digit, recovery key `.bek`, key package, DRA), atribut `ms-FVE-*` di AD DS, riwayat kunci di AD, suspend dan resume, dan keterangan bahwa key package tidak bisa disimpan di Entra ID |
| S3 | Microsoft Graph: bitlockerRecoveryKey resource type | https://learn.microsoft.com/en-us/graph/api/resources/bitlockerrecoverykey | primer | dirujuk 2026-10-09 | Tinggi untuk bentuk sumber daya kunci recovery di Entra ID |
| S4 | VeraCrypt: Hidden Volume | https://veracrypt.io/en/Hidden%20Volume.html | primer | dilihat 2026-10-09, dicek ulang 2026-10-22 | Tinggi. Ruang kosong diisi data acak, letak header hidden volume di byte 65536 sampai 131071, urutan percobaan dekripsi header saat mount, dan sifat bersyarat klaim ketidakterbuktian |
| S5 | Microsoft Learn: ms-FVE-RecoveryPassword attribute | https://learn.microsoft.com/en-us/windows/win32/adschema/a-msfve-recoverypassword | primer | dirujuk 2026-10-09 | Tinggi untuk nama dan arti atribut skema AD |
| S6 | Endpoint-Forensics-note Day 01, 02, 03, 07, 09, 10, 14, 18, 19, 20 | (lokal) | rujukan internal | 2026-10-09, diperbarui 2026-10-22 | Keterkaitan antar Day |
| S7 | Microsoft Learn: BitLocker recovery process | https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/recovery-process | primer | ms.date 2025-07-29, diperbarui 2026-10-08; diakses 2026-10-22 | Tinggi. Pengambilan kunci di Entra ID (peran, izin `microsoft.directory/bitlockerKeys/key/read`, administrative unit, contoh Graph PowerShell), akses bawaan Domain Admins di AD DS, swalayan pengguna, checksum per blok 6 digit, pengikatan ke TPM baru, rotasi recovery password, key package butuh recovery password |
| S8 | Microsoft Graph: Get bitlockerRecoveryKey | https://learn.microsoft.com/en-us/graph/api/bitlockerrecoverykey-get | primer | ms.date 2024-10-24, diperbarui 2025-11-08; diakses 2026-10-22 | Tinggi. Properti `key` hanya dengan `$select=key` yang memicu audit `KeyManagement`; izin `BitlockerKey.ReadBasic.All` dan `BitlockerKey.Read.All`; peran yang didukung termasuk Security Reader dan Global Reader |
| S9 | Microsoft Learn: Manage devices in Microsoft Entra ID (View or copy BitLocker keys) | https://learn.microsoft.com/en-us/entra/identity/devices/manage-device-identities | primer | ms.date 2026-06-17, diperbarui 2026-10-09; diakses 2026-10-22 | Tinggi. Show Recovery Key menulis audit kategori `KeyManagement`; pemilik dan peran yang bisa melihat kunci; perangkat hybrid joined tanpa pemilik kecuali primary user Intune; pengaturan pembatasan swalayan; penghapusan perangkat menghapus kunci BitLocker-nya |
| S10 | Microsoft Learn: Encrypt Windows devices with BitLocker using Intune | https://learn.microsoft.com/en-us/intune/intune-service/protect/encrypt-devices | primer | ms.date 2025-11-26, diperbarui 2026-09-28; diakses 2026-10-22 | Tinggi. Encryption report, Recovery keys di Intune dan audit "Read BitLocker key", batas 200 kunci per perangkat, used space only pada modern standby dengan enkripsi senyap, prasyarat dan peran rotasi kunci |
| S11 | Microsoft Learn: BitLocker overview (Device encryption) | https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/ | primer | ms.date 2026-08-24, diperbarui 2026-10-08; diakses 2026-10-22 | Tinggi. Device encryption dimulai dengan clear key yang setara suspended, dihapus setelah pencadangan; perangkat akun lokal tetap tidak terlindungi; prasyarat dilonggarkan sejak 24H2; metode bawaan XTS-AES 128 |
| S12 | VeraCrypt: Release Notes | https://veracrypt.io/en/Release%20Notes.html | primer | 1.26.29 rilis 2026-06-09; diakses 2026-10-22 | Tinggi. Versi terbaru, enkripsi RAM sejak 1.24, penghapusan kunci saat shutdown, mode TrueCrypt dihapus sejak 1.26.7 |
| S13 | VeraCrypt: Unencrypted Data in RAM | https://veracrypt.io/en/Unencrypted%20Data%20in%20RAM.html | primer | diakses 2026-10-22 | Tinggi. Master key dan data terdekripsi di RAM selama ter-mount; dismount dan shutdown bersih menghapus kunci volume non-sistem; putus daya mendadak tidak; enkripsi RAM manual dan menonaktifkan hibernate |
| S14 | GitHub: volatility3 `windows/truecrypt.py` dan daftar plugin Windows | https://github.com/volatilityfoundation/volatility3/blob/develop/volatility3/framework/plugins/windows/truecrypt.py | primer (repo resmi) | cabang develop; diakses 2026-10-22 | Tinggi. Kelas `Passphrase` memindai `.data` driver `truecrypt.sys`; tidak menyebut VeraCrypt; daftar plugin Windows tidak memuat plugin BitLocker atau VeraCrypt pada tanggal akses |
| S15 | GitHub: volatilityfoundation/volatility3 releases | https://github.com/volatilityfoundation/volatility3/releases | primer | 2.28.2 rilis 17 September (tahun tidak tercantum di halaman, 2026 menurut Day sebelumnya); diakses 2026-10-22 | Tinggi untuk versi rilis terbaru |
| S16 | GitHub: Aorimn/dislocker (README dan man page dislocker-fuse) | https://github.com/Aorimn/dislocker | primer (repo) | tanpa rilis bertag; diakses 2026-10-22 | Sedang-tinggi. FUSE untuk volume BitLocker, AES-CBC dan AES-XTS 128/256, `dislocker-file`; opsi `-V`, `-p` (tanpa nilai meminta interaktif), `-f`, `-r`, `-O`; menyebut Vista sampai Windows 10 |
| S17 | Elcomsoft blog: Live System Analysis: Extracting BitLocker Keys | https://blog.elcomsoft.com/2022/05/live-system-analysis-extracting-bitlocker-keys/ | sekunder (vendor forensik) | 2022-05-20; diakses 2026-10-22 | Sedang. `manage-bde -protectors -get` dan `Get-BitLockerVolume` menampilkan recovery password ke administrator di sistem hidup; suspend menaruh kunci tanpa proteksi di header; klaim alat komersial pencari kunci BitLocker, TrueCrypt, VeraCrypt di RAM (klaim vendor, belum diuji) |
| S18 | Forensics Wiki: BitLocker how to image | https://forensics.wiki/bitlocker_how_to_image/ | komunitas | tanpa tanggal; diakses 2026-10-22 | Sedang-rendah. Image fisik sistem hidup tetap terenkripsi, image partisi logis berisi plaintext; dislocker, libbde, dan modul komersial untuk dekripsi offline; recovery password tanpa spasi; hasil bergantung konfigurasi dan alat |
| S19 | VeraCrypt: System Files and Application Data | https://veracrypt.io/en/VeraCrypt%20System%20Files.html | primer | diakses 2026-10-22 | Tinggi. `veracrypt.sys` di `System32\drivers` (tidak ada pada mode portable); `Configuration.xml` dan `History.xml` (dua puluh berkas atau perangkat terakhir, bisa dimatikan) di `%APPDATA%\VeraCrypt\` |

**Catatan sumber:** keluaran `manage-bde -status`, `-protectors -get`, `Get-Volume`, Graph, `Get-ADObject`, pencarian Splunk, `mmls`, dan dislocker di bagian 2 adalah ilustrasi dengan field yang umum muncul, bukan salinan keluaran nyata; urutan dan nama field bisa berbeda antar versi Windows dan alat. Profil PCR dan nilai `Identification Field` untuk laptop 24H2, tampilan volume VeraCrypt di `Get-Volume`, visibilitas volume VeraCrypt dari sesi pengguna lain, dan perilaku timestamp berkas kontainer tidak dikonfirmasi sumber yang dipakai di sini, jadi dibuktikan di lab (bagian 3). Perintah PowerShell AD disusun dari nama atribut skema yang didokumentasikan; ejaan atribut di modul PowerShell (`msFVE-`) berbeda dari ejaan di dokumentasi skema (`ms-FVE-`), jadi uji di lab domain sebelum memakainya. Pernyataan bahwa pembacaan recovery password di AD DS tidak tercatat tanpa audit Directory Service Access dan SACL adalah keadaan konfigurasi PT JAB fiktif, bukan klaim dari sumber; cara mengauditnya dibuktikan di lab. Nama menu FTK Imager dan opsi sumber Logical Drive ditulis dari praktik umum dan laporan komunitas [S18], bukan dari dokumentasi resmi versi tertentu. `ewfmount` (libewf) dan `mmls` (The Sleuth Kit) dipakai sebagai alat baku tanpa sumber khusus di Day ini; cek opsi di versi yang terpasang. Klaim Elcomsoft tentang alat ekstraksi kunci dari RAM adalah klaim vendor [S17] dan tidak diuji. Nilai entropi dan ukuran berkas di bagian 2.9 adalah ilustrasi, dan ambang entropi yang membedakan data terenkripsi dari data terkompresi tidak ditetapkan di sumber mana pun yang dipakai di sini, jadi tetapkan sendiri dari pengukuran di lab dan nyatakan batasnya di laporan. Semua isi PT JAB, termasuk host, akun, waktu, Key ID, GUID, hash, jumlah perangkat, nama kebijakan dan skrip, adalah contoh fiktif.
