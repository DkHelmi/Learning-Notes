---
day: 19
title: 'SMB dan Kerberos di kabel: membaca lateral movement dari trafik'
researched_on: 2026-10-29
versions_checked: 'Zeek 9.0.1 LTS (26 Okt 2026; LTS sebelumnya 8.0.11): smb_mapping.log, smb_files.log, dce_rpc.log, kerberos.log, ntlm.log; skrip base/protocols/krb/main.zeek, krb/consts.zeek, dce-rpc/main.zeek cabang master dibaca 2026-10-29; Suricata 8.0.7 (EVE smb dan krb5, termasuk ticket_encryption); Wireshark 4.6.9 (field kerberos.* dan smb2.*); IANA Kerberos Encryption Type Numbers (diperbarui 2024-12-06); RFC 4120; MS-SMB2 TRANSFORM_HEADER; MS-SCMR, MS-TSCH, MS-RRP; Microsoft KB5073381 (CVE-2026-20833, diperbarui 14 Apr 2026); Event 4768 dan 4769 (format baru sejak pembaruan 14 Jan 2025); SMB security hardening Windows 11 24H2 dan Windows Server 2025; MITRE ATT&CK v20.0: T1558.003 v1.3, T1558.004 v1.2, T1021.002 v1.3, T1569.002 v1.3; BZAR (README per 10/09/2020); rujukan Day 01, 03, 07, 08, 09, 11, 12, 15, 16'
---

# Day 19: SMB dan Kerberos di kabel

Cakupan: membaca perpindahan penyerang antar host dari dua protokol yang paling sering dipakainya (SMB dengan DCE-RPC di atasnya, dan Kerberos), mengenali penyalahgunaan tiket dari metadata yang masih terlihat, dan menyatakan dengan jujur bagian rantai yang tidak pernah lewat sensor.

Day ini membahas lateral movement dari sisi deteksi dan forensik jaringan. Tidak ada instruksi menjalankan serangan; teknik dirujuk ke katalog MITRE ATT&CK. Data PT JAB fiktif, dan lab memakai jaringan host-only pribadi dengan akun uji.

## Ide inti

Hampir semua perpindahan antar host di jaringan Windows melewati dua protokol: SMB untuk berkas dan panggilan prosedur jarak jauh (DCE-RPC lewat named pipe), dan Kerberos untuk autentikasinya. Keduanya sah dan padat dipakai setiap hari, sehingga tantangannya bukan menemukan trafiknya, melainkan memisahkan yang tidak lazim dari lautan yang lazim. Penyerang yang menaruh berkas di `ADMIN$` lalu menyalakannya sebagai service memakai urutan yang persis sama dengan alat distribusi perangkat lunak. Karena itu seluruh Day ini bersandar pada baseline: pasangan host mana yang biasa saling menghubungi, akun mana yang biasa meminta tiket untuk layanan mana, dan jenis enkripsi apa yang biasa keluar. Tanpa baseline itu, tidak ada satu pun pola di bawah yang bisa dipakai.

Day ini melengkapi Day 11 dari sisi yang berbeda. Day 11 mencari komunikasi keluar ke penyerang; di sini yang dicari adalah gerakan di dalam, yang bentuknya justru menyerupai administrasi normal. Ada satu hal lagi yang membedakannya dari Day lain: sensor PT JAB ada di core switch data center dan di egress, bukan di switch akses kantor. Workstation ke server dan workstation ke domain controller terlihat; workstation ke workstation di switch akses yang sama tidak terlihat sama sekali. Untungnya, setiap logon Kerberos ke host mana pun tetap meminta tiket ke domain controller, dan domain controller ada di data center. Jadi domain controller menjadi saksi untuk gerakan yang tidak pernah lewat sensor.

Polanya sudah kamu kenal dari NOC. Kamu tidak pernah menangkap sesi SSH dari satu router ke router lain di POP yang sama, tetapi log accounting TACACS+ tetap mencatat bahwa user X diotorisasi masuk ke perangkat B dari alamat A pada jam sekian. Kerberos di domain controller berperan seperti server AAA itu: permintaan tiket `cifs/JKT-WS-2093` dari `10.10.60.191` adalah baris accounting untuk sesi SMB yang tidak pernah kamu lihat. Batas analoginya ada tiga. Tiket layanan disimpan di klien dan dipakai ulang selama masa berlakunya, jadi satu baris tiket bisa mewakili banyak sesi, berbeda dari accounting yang mencatat tiap sesi. Autentikasi NTLM dan akun lokal tidak meminta tiket Kerberos, jadi gerakan dengan cara itu tidak meninggalkan baris di `kerberos.log`. Dan baris tiket hanya membuktikan izin diminta, bukan bahwa sesi terjadi atau apa yang dilakukan di dalamnya.

```
  KANTOR JAKARTA (switch akses lantai Billing, tidak di-SPAN)
  JKT-WS-2091 10.10.60.191 --- SMB 445 ---> JKT-WS-2092 / JKT-WS-2093       (blind spot: tidak lewat core DC)
        |
        |  Kerberos 88: AS dan TGS (termasuk TGS cifs/JKT-WS-2093)
        +-----------------------------------------------> jkt-dc01 10.20.8.11 / jkt-dc02 10.20.8.12
        |                                                   (terlihat: kerberos.log, Event 4768/4769)
        |  SMB 445: ADMIN$ tulis berkas, IPC$ \svcctl
        +-----------------------------------------------> jkt-app11 10.20.8.41
                                                            (terlihat: conn, smb_mapping, smb_files,
                                                             files, dce_rpc)
                                                                 |
                                       SYN 443 ke 203.0.113.197 -+-> jkt-fw01 menolak (TAP egress, sebelum NAT)

  DATA CENTER: SPAN core switch DC + TAP egress -> jkt-npb01 -> jkt-zeek01 (10.20.70.12), jkt-ids01 (10.20.70.11)
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan, kantor pusat dan data center di Jakarta, dan NOC 24/7 yang satu lantai dengan SOC. Sejak Senin 2027-05-03, PT JAB menjalankan "Program NSM PT JAB" sebagai percobaan Mei sampai Juli 2027. `jkt-zeek01` (`10.20.70.12`, produksi sejak Selasa 2027-05-18) dan `jkt-ids01` (`10.20.70.11`, Suricata, sejak Rabu 2027-05-19) membaca SPAN core switch data center dan TAP egress Jakarta lewat packet broker `jkt-npb01`. Log Zeek JSON masuk Splunk index `zeek`, termasuk log SMB, DCE-RPC, Kerberos, dan NTLM; Suricata hanya mengirim `eve-alert.json` ke index `suricata`, sementara `eve-proto.json` (flow, dns, http, tls, files) disimpan di sensor 7 hari (Day 09). Domain Active Directory PT JAB adalah `corp.jab.example` dengan dua domain controller di subnet server data center, `jkt-dc01` (`10.20.8.11`) dan `jkt-dc02` (`10.20.8.12`); log Security keduanya masuk `index=wineventlog`. Microsoft Defender for Endpoint (MDE) berjalan di server dan sebagian besar workstation.

Rabu 2027-06-23 pagi, lima alert masuk antrean: Kerberos TGS borongan dari `JKT-WS-2091` (`SOC-2027-0690`, 09:13), permintaan TGT tanpa praautentikasi untuk akun `svc-legacyscan` dari host yang sama (`SOC-2027-0691`, 09:22), tulis berkas ke `ADMIN$` lalu panggilan `svcctl` dari `JKT-WS-2091` ke server Billing `jkt-app11` (`SOC-2027-0692`, 09:41), pola yang sama dari server distribusi perangkat lunak `jkt-mecm01` ke 63 server (`SOC-2027-0693`, 10:02), dan alert MDE tentang service baru di `JKT-WS-2093` yang dipasang lewat logon jaringan dari `10.10.60.191` (`SOC-2027-0694`, 10:20). Pukul 09:50 Dimas Prasetyo (SOC lead) membuka `INC-2027-078`; Yoga Pratama memegang sisi host. Pukul 11:05, Dimas menulis kepadamu:

> "INC-2027-078 sudah di Yoga untuk sisi host, tapi jam 14 aku lapor Pak Hendra dan butuh versi jaringannya. Pertama, dari sensor kita gerakan 2091 ini sebenarnya kelihatan sampai mana? MDE bilang 2093 dapat service dari 2091, tapi Gilang bilang Zeek tidak punya satu baris pun 2091 ke 2093. Kedua, 0690 itu Kerberoasting atau bukan, dan akun mana yang tiketnya keluar dengan RC4? Bukannya RC4 sudah dimatikan sejak update tahun lalu? Ketiga, 0691: svc-legacyscan diminta tanpa praautentikasi dari 2091, itu masalah konfigurasi atau serangan? Keempat, 0692 dan 0693 bentuknya sama, ADMIN$ lalu svcctl; kenapa yang satu insiden dan MECM tidak? Kelima, di jkt-app11 sebenarnya apa yang dijalankan, dan seberapa jauh jaringan bisa membuktikannya? Keenam, Pak Bambang tanya, perlu tidak SPAN tambahan di switch lantai Billing supaya yang seperti 2091 ke 2093 kelihatan? Ketujuh, Pak Agung mau menyalakan enkripsi SMB di jkt-fs02 minggu depan gara-gara INC-071; apa yang hilang buat kita? Terakhir, susun rantainya dengan ATT&CK untuk laporan."

Pesan itu memuat delapan pertanyaan:

1. Sampai mana gerakan `JKT-WS-2091` terlihat dari sensor, dan kenapa tidak ada satu baris pun `JKT-WS-2091` ke `JKT-WS-2093`?
2. Apakah `SOC-2027-0690` Kerberoasting, dan akun mana yang tiketnya keluar dengan RC4 padahal RC4 sudah dibatasi?
3. Apakah `SOC-2027-0691` (TGT tanpa praautentikasi untuk `svc-legacyscan`) temuan konfigurasi atau temuan aktivitas?
4. Kenapa `SOC-2027-0692` insiden sedangkan `SOC-2027-0693` dari `jkt-mecm01` tidak, padahal bentuknya sama?
5. Apa yang dijalankan di `jkt-app11`, dan seberapa jauh jaringan bisa membuktikannya?
6. Perlukah SPAN tambahan di switch akses lantai Billing?
7. Apa yang hilang bila SMB `jkt-fs02` dienkripsi?
8. Bagaimana rantai lateral movement disusun untuk laporan, dengan label ATT&CK?

Pertanyaan 1 dijawab di bagian 1.2 dan 2.7, pertanyaan 2 di bagian 1.5, 1.6, 1.7, 2.4, dan 2.5, pertanyaan 3 di bagian 1.7 dan 2.6, pertanyaan 4 di bagian 1.1, 1.3, 2.1, dan 2.2, pertanyaan 5 di bagian 1.4 dan 2.3, pertanyaan 6 di bagian 1.2 dan 2.7, pertanyaan 7 di bagian 1.8, dan pertanyaan 8 di bagian 1.9 dan 2.8.

**Kapan relevan:** saat alert atau hunt menyangkut akses share administratif, eksekusi jarak jauh lewat service atau scheduled task, atau anomali tiket Kerberos; saat scoping insiden bertanya "host mana lagi yang disentuh dari sini"; dan saat menilai apakah kebijakan enkripsi (RC4, enkripsi SMB) mengubah apa yang bisa dilihat sensor.
**Kapan bukan jawaban:** saat gerakan terjadi sepenuhnya antar workstation di switch akses yang sama dengan NTLM atau akun lokal (tidak ada jejak di sensor maupun di `kerberos.log`, jawabannya ada di EDR dan log host); saat pertanyaannya "perintah apa yang dijalankan" (jaringan memberi nama operasi, bukan argumennya); dan saat SMB sudah dienkripsi end-to-end, karena yang tersisa hanya metadata koneksi dan autentikasi.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (SPAN, TAP, packet broker, blind spot, `uid`, `conn_state`, `files.log` dan `is_orig`, first-seen, prevalence, saved search) tidak diulang; definisinya ada di Day 01 sampai 16 [S7]. Tabel ini hanya memuat istilah yang dipakai Day ini; kolom padanan memakai pengalaman NOC dan ISP.

| Istilah | Arti singkat | Padanan di NOC/ISP |
|---|---|---|
| Lateral movement | Perpindahan penyerang dari satu host yang dikuasai ke host lain di dalam jaringan (ATT&CK TA0008) | Engineer yang lompat dari satu router ke router lain lewat sesi SSH bertingkat |
| SMB (Server Message Block) | Protokol berbagi berkas dan transport panggilan prosedur jarak jauh di Windows, TCP 445 | Protokol transfer image/config ke perangkat (SCP/TFTP) sekaligus kanal manajemennya |
| Share administratif (`ADMIN$`, `C$`) | Share tersembunyi bawaan Windows yang menunjuk ke folder Windows atau drive; hanya untuk akun admin lokal host itu | Akses `flash:` perangkat yang hanya terbuka untuk privilege 15 |
| `IPC$` dan named pipe | Share khusus untuk komunikasi antarproses; named pipe seperti `\PIPE\svcctl` adalah pintu ke layanan tertentu | Port manajemen yang menuju fungsi tertentu (NETCONF, SNMP SET) |
| DCE-RPC | Panggilan prosedur jarak jauh yang berjalan di atas named pipe SMB atau langsung di TCP | Operasi RPC NETCONF (`<edit-config>`, `<commit>`) di atas sesi SSH |
| Kerberos | Protokol autentikasi berbasis tiket; domain controller berperan sebagai KDC (Key Distribution Center), TCP/UDP 88 | Server AAA (TACACS+/RADIUS) yang mengotorisasi setiap login perangkat |
| AS (Authentication Service) | Pertukaran awal: klien membuktikan identitas dan menerima TGT | Login awal ke AAA |
| TGT (Ticket Granting Ticket) | Tiket untuk meminta tiket lain, dienkripsi kunci akun `krbtgt` | Token sesi AAA yang dipakai untuk otorisasi berikutnya |
| TGS (Ticket Granting Service) | Pertukaran untuk meminta tiket layanan tertentu, misalnya `cifs/<host>` | Permintaan otorisasi per perangkat atau per perintah |
| SPN (Service Principal Name) | Nama layanan yang dimintakan tiketnya, misalnya `MSSQLSvc/jkt-sql05.corp.jab.example:1433` | Nama perangkat dan service di daftar otorisasi AAA |
| Praautentikasi | Bukti bahwa klien tahu password sebelum KDC mengirim TGT (biasanya timestamp terenkripsi) | Challenge sebelum AAA memberi akses |
| Encryption type (etype) | Jenis enkripsi tiket atau bagian balasan, bernomor di daftar IANA (17, 18, 23, ...) | Pilihan SNMPv1 community vs SNMPv3 authPriv |
| Kerberoasting | Meminta tiket layanan untuk akun berSPN lalu memecah password akun itu di luar jaringan (T1558.003) | Menyalin hash password dari konfigurasi perangkat untuk dipecahkan offline |
| AS-REP Roasting | Meminta TGT untuk akun tanpa praautentikasi lalu memecah bagian balasannya di luar jaringan (T1558.004) | AAA yang menjawab tanpa challenge untuk akun lama |
| Service execution lewat SCM | Membuat dan menjalankan service di host lain lewat `svcctl` (T1569.002) | Menyalin image ke flash lalu `reload` dengan image itu |
| Enkripsi SMB | Enkripsi pesan SMB 3.x dengan TRANSFORM_HEADER; isi dan nama berkas tidak terbaca | MACsec atau IPsec di link: header luar terlihat, isi tidak |
| SMB signing | Tanda tangan integritas pesan SMB; isi tetap terbaca | Autentikasi MD5 OSPF: paket diautentikasi, bukan dienkripsi |

### 1.1 Lateral movement di kabel: kenapa bentuknya mirip administrasi

Pertanyaan keempat Dimas muncul karena `SOC-2027-0692` dan `SOC-2027-0693` memang identik bentuknya: satu host memetakan `ADMIN$` di host lain, menulis berkas executable, lalu memanggil Service Control Manager lewat `IPC$`. Yang pertama dari workstation Billing ke satu server; yang kedua dari server distribusi ke 63 server.

Lateral movement adalah perpindahan dari satu host yang sudah dikuasai ke host berikutnya. Di jaringan Windows, cara yang paling umum memakai alat bawaan: share administratif SMB untuk menaruh berkas (T1021.002) dan Service Control Manager atau Task Scheduler jarak jauh untuk menjalankannya (T1569.002, T1053.005) [S15][S16]. Analitik ATT&CK untuk T1021.002 mencari akses share `ADMIN$` atau `C$` yang diikuti aktivitas di host tujuan, seperti pembuatan service, scheduled task, atau proses mencurigakan [S15]. Kalimat itu penting karena ATT&CK sendiri tidak menjadikan akses share sebagai temuan; yang menjadi temuan adalah rangkaiannya.

Alat administrasi yang sah melakukan rangkaian yang sama, karena memang itulah cara Windows mengizinkan administrasi jarak jauh. Jadi pembedanya selalu konteks, dan konteks itu terdiri dari empat sumbu:

| Sumbu | Pertanyaan | Di mana jawabannya |
|---|---|---|
| Sumber | Apakah host sumber memang bertugas administrasi (server distribusi, jump host, pemindai)? | Daftar host administrasi yang dirawat SOC |
| Pasangan | Apakah pasangan sumber dan tujuan pernah muncul dalam baseline? | Stacking first-seen di `smb_mapping.log` dan `kerberos.log` |
| Akun | Apakah akun yang dipakai lazim untuk pasangan itu? | `kerberos.log` (`client`), `ntlm.log`, Event 4769 di DC |
| Waktu dan perubahan | Apakah ada jadwal atau tiket perubahan yang menjelaskan? | Change log, jadwal pemeliharaan |

Tabel ini dipakai di setiap alert lateral movement di Day ini; satu sumbu yang menyimpang belum cukup, tetapi tiga sumbu yang menyimpang hampir selalu cukup untuk eskalasi.

### 1.2 Titik pandang PT JAB untuk trafik internal, dan domain controller sebagai saksi

Pertanyaan pertama dan keenam Dimas adalah persoalan posisi sensor. Gilang benar: Zeek tidak punya satu baris pun dari `10.10.60.191` ke `10.10.60.193`. Itu bukan kegagalan sensor.

Sensor program membaca dua titik: SPAN core switch data center dan TAP egress Jakarta di sisi dalam `jkt-fw01` (Day 01 bagian 1.5). Trafik yang melewati core switch data center terlihat; trafik yang tidak pernah sampai ke sana tidak. Tabel berikut adalah peta yang dipakai setiap kali kamu ditanya "apakah gerakan ini terlihat"; cari baris yang sesuai dengan pasangan sumber dan tujuan.

| Pasangan | Lewat titik sensor? | Yang tersedia |
|---|---|---|
| Workstation kantor ke server atau DC di data center | Ya, SPAN core DC | `conn`, `smb_*`, `dce_rpc`, `kerberos`, `ntlm`, `files`; flow router DC 1:1 |
| Workstation ke workstation di switch akses yang sama | Tidak | Tidak ada di Zeek, Suricata, pcap, maupun flow; hanya EDR dan log host. Tiket Kerberos yang diminta ke DC tetap terlihat |
| Workstation ke workstation di lantai lain | Tidak, karena routing antar VLAN kantor dilakukan di switch distribusi kantor yang tidak di-SPAN program | Sama dengan baris di atas |
| Server ke server lintas VLAN di data center | Ya, bila dirutekan di core | Seperti baris pertama; server di VLAN yang sama dan switch akses yang sama di DC tidak terlihat |
| Host internal ke internet | Ya, TAP egress (sebelum NAT) | `conn` dengan alamat internal, alert, pcap 72 jam |

Bagian penting untuk Dimas ada di baris kedua. Gerakan `JKT-WS-2091` ke `JKT-WS-2092` dan `JKT-WS-2093` (semuanya di switch akses lantai Billing) tidak lewat sensor, dan Day 07 sudah mencatatnya sebagai blind spot yang tidak ditutup oleh Zeek dan Suricata. Yang tetap lewat sensor adalah permintaan tiket ke domain controller. Untuk mengakses share di `JKT-WS-2093` dengan Kerberos, klien harus lebih dulu meminta tiket layanan `cifs/JKT-WS-2093.corp.jab.example` ke KDC, dan KDC ada di data center. Baris itu masuk `kerberos.log` dan juga Event 4769 di DC [S2][S4]. Itulah yang dimaksud domain controller sebagai saksi.

Saksi ini punya tiga batas yang harus ditulis di laporan:

- Tiket layanan dipakai ulang selama masa berlakunya, jadi satu baris TGS bisa mewakili banyak koneksi SMB berikutnya; tidak ada baris baru untuk setiap koneksi.
- Logon dengan NTLM (misalnya ketika host tujuan diakses dengan alamat IP, bukan nama, atau dengan hash password) dan logon dengan akun lokal tidak meminta tiket Kerberos. NTLM diverifikasi DC lewat kanal lain, dan jejaknya ada di log host serta log DC, bukan di `kerberos.log` sensor.
- Baris TGS membuktikan izin diminta dan diberikan. Ia tidak membuktikan sesi SMB terjadi, apalagi apa yang dilakukan di dalamnya.

Jawaban untuk Bambang ada di bagian 2.7: SPAN di switch akses bisa menutup sebagian, tetapi biayanya (jumlah switch, kapasitas `jkt-npb01`, dan privasi trafik antar karyawan) harus dibandingkan dengan sumber yang sudah ada, yaitu EDR dan log host.

### 1.3 Membaca SMB dari jaringan

Alert `SOC-2027-0692` dan `SOC-2027-0693` sama-sama dibangun dari log SMB Zeek. Sebelum membandingkan keduanya, kamu perlu tahu apa yang dicatat setiap log dan apa yang tidak.

Zeek menghasilkan beberapa log untuk SMB. Dokumentasinya menyebut `dce_rpc.log`, `kerberos.log`, `ntlm.log`, `smb_cmd.log`, `smb_files.log`, `smb_mapping.log`, `pe.log`, dan `notice.log` sebagai log yang bisa muncul saat Zeek melihat trafik SMB [S1]. Dua yang paling berguna untuk lateral movement adalah `smb_mapping.log`, yang mencatat koneksi ke share, dan `smb_files.log`, yang mencatat operasi tingkat berkas [S1].

Pada `smb_mapping.log`, dua field menentukan artinya [S1]:

| Field | Isi | Cara membacanya |
|---|---|---|
| `path` | Jalur UNC share | Nama share mengungkap niat: share data biasa, atau share administratif |
| `share_type` | Jenis share | `DISK` untuk share berkas termasuk share administratif, `PIPE` untuk `IPC$` yang dipakai Windows untuk panggilan prosedur jarak jauh |

Dokumentasinya menyebut langsung bahwa koneksi ke `ADMIN$` dan `IPC$` mencurigakan bila tidak diotorisasi [S1]. Kalimat itu perlu dibaca dengan hati-hati: keduanya juga dipakai administrasi sah setiap hari. Yang menjadi temuan adalah pasangan host yang tidak biasa, bukan keberadaan share-nya.

Pada `smb_files.log`, yang berguna adalah `action` dengan nilai seperti `SMB::FILE_OPEN`, `SMB::FILE_WRITE`, dan `SMB::FILE_DELETE`, ditambah `path` untuk share, `name` untuk berkas di dalamnya, dan `size` [S1]. Dari semuanya, berkas yang ditulis ke share administratif adalah pola yang paling layak diperiksa, karena itulah cara klasik menaruh sesuatu di host lain.

Empat batas yang disebut dokumentasinya dan perlu kamu pegang [S1]:

- Sebagian layanan non-berkas diperlakukan sebagai berkas. Contoh di dokumentasinya adalah layanan penjadwalan At yang muncul di `smb_files.log` padahal tidak ada berkas yang diekstrak.
- `smb_files.log` tidak menunjukkan arah transfer. Arah diambil dari `files.log`, yang punya `is_orig` (Day 08 bagian 1.5).
- Isi pertukaran DCE-RPC terenkripsi, sehingga `dce_rpc.log` memberi nama operasi tetapi tidak argumennya.
- Entri di log tidak mengungkap maksud. Pemakaian sah layanan penjadwalan oleh administrator sulit dibedakan dari penyalahgunaan hanya dari log, sehingga perintah yang sebenarnya dijalankan perlu dicari di tempat lain.

Batas ketiga dan keempat itu yang menentukan seberapa jauh kamu bisa menyimpulkan dari jaringan saja. Jawabannya: cukup untuk mengetahui apa yang terjadi, tidak cukup untuk mengetahui apa isinya.

Satu hal yang sering disalahpahami: SMB signing tidak menyembunyikan apa pun. Sejak Windows 11 24H2 dan Windows Server 2025, semua koneksi SMB keluar dan masuk wajib ditandatangani secara bawaan; sebelumnya kewajiban itu hanya untuk share `SYSVOL` dan `NETLOGON` serta klien domain controller [S19]. Signing melindungi integritas dan mencegah relay, tetapi isi pesan tetap polos, sehingga Zeek tetap bisa mengurai nama share, nama berkas, dan operasi. Yang menyembunyikan isi adalah enkripsi SMB, yang tidak wajib secara bawaan (bagian 1.8) [S19].

Selain log Zeek, Wireshark mengurai SMB2 dengan field `smb2.cmd`, `smb2.tree`, `smb2.filename`, `smb2.nt_status`, `smb2.acct`, `smb2.host`, `smb2.domain`, dan `smb2.dialect`, semuanya tersedia sampai 4.6.9 [S18]. Day 03 bagian 1.8 dan 2.7 sudah memakainya untuk pcap lab. Di PT JAB, pcap hanya ada di egress, jadi untuk trafik internal yang dipakai adalah log Zeek.

### 1.4 Named pipe dan DCE-RPC sebagai sinyal

Pertanyaan kelima Dimas ("apa yang dijalankan di `jkt-app11`") hanya bisa dijawab sebagian dari jaringan, dan bagian yang bisa dijawab datang dari named pipe dan `dce_rpc.log`.

Koneksi ke `IPC$` membuka jalan ke named pipe, dan nama pipe yang dipakai memberi tahu layanan apa yang dipanggil dari jarak jauh. Tiga yang paling berarti dalam konteks lateral movement, menurut spesifikasi protokol Microsoft [S8]:

| Named pipe | Protokol | Dipakai untuk | Kenapa penting |
|---|---|---|---|
| `\PIPE\svcctl` | MS-SCMR (Service Control Manager Remote) | Membuat, mengubah, dan menjalankan service di host lain | Cara klasik menjalankan berkas yang baru ditaruh di `ADMIN$` (Event ID 7045 di host tujuan) |
| `\PIPE\atsvc` | MS-TSCH (Task Scheduler Remoting) | Membuat dan menjalankan scheduled task di host lain | Eksekusi jarak jauh tanpa membuat service |
| `\PIPE\winreg` | MS-RRP (Remote Registry) | Membaca dan mengubah registry host lain | Persistence, pengintaian konfigurasi, atau pengambilan data kredensial |

Ketiganya adalah cara menjalankan sesuatu di host lain tanpa perlu sesi interaktif. Di Zeek, nama pipe muncul sebagai `name` di `smb_files.log` dengan `path` berakhiran `IPC$`. Administrasi sah juga memakai ketiganya (konsol manajemen, alat deployment), jadi nilainya ada pada pasangan host: pipe `svcctl` dari workstation ke server jauh lebih jarang sah daripada dari server manajemen ke server.

`dce_rpc.log` menambah satu lapis. Field-nya adalah `ts`, `uid`, `id`, `rtt` (waktu bolak-balik permintaan dan balasan, kosong bila salah satunya tidak terlihat), `named_pipe`, `endpoint` (nama layanan hasil pemetaan UUID), dan `operation` (nama operasi yang dipanggil) [S9]. Contoh di dokumentasi Zeek menunjukkan `endpoint` `svcctl` dengan operasi `OpenSCManagerW`, `CreateServiceWOW64W`, `StartServiceW`, dan `DeleteService`, serta `samr` dengan operasi enumerasi pengguna seperti `SamrLookupNamesInDomain` [S1]. Urutan buka SCM, buat service, jalankan, lalu hapus adalah tanda tangan alat eksekusi jarak jauh yang membuat service sementara, dan analitik ATT&CK untuk T1569.002 juga menyebut service sementara yang dibuat lewat API Service Control Manager atau alat semacam PsExec [S16].

Tiga hal yang membuat `dce_rpc.log` tidak lengkap:

- `named_pipe` diambil dari field `sec_addr` di protokol, dan menurut dokumentasinya bisa berisi nomor port lokal, bukan nama pipe [S9]. Cocokkan dengan `smb_files.log` dan `smb_mapping.log` lewat `uid`.
- Zeek secara bawaan mengabaikan operasi yang berisik lewat `DCE_RPC::ignored_operations`: beberapa operasi `spoolss`, `wkssvc`, dan sebagian besar operasi baca `winreg` seperti `BaseRegOpenKey` dan `BaseRegQueryValue` [S9]. Akibatnya, pembacaan registry jarak jauh lewat `winreg` bisa tidak muncul sama sekali di `dce_rpc.log`; yang tersisa hanya pembukaan pipe-nya di `smb_files.log`.
- Argumen operasi (nama service, path biner, perintah) terenkripsi atau tidak diurai, jadi tidak tercatat [S1]. Dokumentasi Zeek mencatat satu kasus ketika string perintah terlihat lewat analisis paket dengan tshark, tetapi tidak di log Zeek [S1]. Di PT JAB, pcap internal tidak ada, jadi pintu itu tertutup.

Yang tersisa sering kali adalah fakta bahwa pipe dan operasi tertentu dipakai, bukan isinya. Itu masih cukup untuk menyusun pertanyaan yang tepat ke tim endpoint: host ini memanggil `CreateServiceW` di host itu pada jam sekian, apa yang terjadi di sana. Di host tujuan, jawabannya biasanya ada di Event ID 7045 (service baru dipasang), 4698 (scheduled task dibuat), dan 4624 dengan logon type 3 (logon jaringan) dari host sumber pada menit yang sama.

Di Zeek, analisis ini diperkuat skrip komunitas BZAR (Bro/Zeek ATT&CK-based Analytics and Reporting) yang memetakan perilaku SMB dan DCE-RPC ke teknik ATT&CK; tanpa skrip semacam itu, entri notice untuk perilaku mencurigakan tidak muncul [S1][S6]. BZAR menandai tulis berkas ke path yang memuat `ADMIN$` atau `C$` (T1021.002), panggilan `svcctl` untuk membuat dan menjalankan service (T1569.002), `atsvc` dan Task Scheduler (T1053), serta panggilan pengintaian ke `samr`, `lsarpc`, `srvsvc`, dan `wkssvc` [S6]. Tiga analitik gabungannya memberi notice berkeyakinan lebih tinggi: tulis ke share administratif yang diikuti indikator eksekusi ke host yang sama dalam satu jendela waktu, banyak percobaan share administratif dari satu sumber, dan banyak panggilan pengintaian dari satu sumber [S6]. Dua catatan dari halaman proyeknya: README menyebut dirinya mutakhir per 10/09/2020, dan deteksi tulis berkas bergantung pada event permintaan tulis, sehingga tidak memastikan tulisnya berhasil [S6]. PT JAB belum memasang BZAR; saved search di bagian 2.3 meniru analitik pertamanya di Splunk.

### 1.5 Membaca Kerberos dari jaringan

Pertanyaan kedua Dimas dimulai dari `kerberos.log`. Alert `SOC-2027-0690` menyala karena satu baris per permintaan tiket memberi tahu siapa meminta tiket untuk layanan apa, dengan enkripsi apa, dan berhasil atau tidak.

Alur Kerberos yang perlu kamu pegang ada tiga langkah [S5]. Permintaan AS adalah autentikasi awal: klien membuktikan identitasnya dan memperoleh TGT. Permintaan TGS adalah permintaan tiket untuk satu layanan tertentu dengan menunjukkan TGT. Permintaan AP adalah saat klien menyerahkan tiket layanan ke server tujuan. AS dan TGS terjadi antara klien dan KDC (domain controller); AP terjadi antara klien dan server tujuan, di dalam protokol aplikasinya (misalnya di SESSION_SETUP SMB).

Zeek menghasilkan satu log Kerberos dengan field yang langsung menjawab pertanyaan pemeriksa [S2]:

| Field | Isi |
|---|---|
| `request_type` | `AS` untuk Authentication Service, `TGS` untuk Ticket Granting Service, `AP` untuk Application Request |
| `client` | Identitas klien |
| `service` | Layanan yang dimintakan tiketnya |
| `success` | Hasil permintaan |
| `error_code`, `error_msg` | Kode dan pesan galat; `error_code` tidak ikut ditulis ke log, hanya `error_msg` |
| `from`, `till` | Masa berlaku tiket |
| `cipher` | Jenis enkripsi tiket |
| `forwardable`, `renewable` | Sifat tiket yang diminta |

Field tambahan muncul bila skrip kebijakan dimuat: subjek sertifikat klien dan server untuk PKINIT, dan hash SHA-256 tiket (`auth_ticket_sha256`, `new_ticket_sha256`) bila `policy/protocols/krb/ticket-logging.zeek` aktif [S2]. Hash tiket berguna untuk melacak tiket yang sama dipakai dari host berbeda.

Cara Zeek mengisi field itu menentukan cara membacanya. Dari kode skrip `krb/main.zeek` [S2]:

- Untuk AS, `client` diisi dari permintaan dalam bentuk `nama/REALM`, dan `service` dari tiket di balasan.
- Untuk TGS, permintaan hanya mengisi `service`; `client` baru diisi dari balasan yang berhasil. Akibatnya, baris TGS yang gagal bisa tanpa `client`. Saved search yang dikelompokkan per `client` akan memecah satu penyerang menjadi dua baris: yang berhasil dengan nama akun, dan yang gagal tanpa nama. Kelompokkan per `id.orig_h`.
- `cipher` diambil dari jenis enkripsi tiket (`ticket$cipher`) di balasan AS dan TGS, dan dari tiket di permintaan AP. Untuk AS, tiket itu adalah TGT yang dienkripsi kunci `krbtgt`, bukan bagian balasan yang dienkripsi kunci akun pengguna (bagian 1.7).
- Galat yang teks balasannya (`error_text`) cocok dengan `KRB::ignored_errors` tidak dicatat sama sekali. Nilai bawaannya `NEEDED_PREAUTH` dan `Need to use PA-ENC-TIMESTAMP/PA-PK-AS-REQ` [S2]. Bila KDC tidak mengirim teks galat, `error_msg` diisi dari tabel kode Zeek, misalnya `KDC_ERR_PREAUTH_REQUIRED` untuk kode 25 dan `KDC_ERR_ETYPE_NOSUPP` untuk kode 14 [S10]. Jadi apakah galat "praautentikasi diperlukan" muncul di log bergantung pada teks yang dikirim KDC-mu; cek di lab sebelum membangun deteksi di atasnya.

Analyzer Kerberos Zeek mendengarkan 88/tcp dan 88/udp secara bawaan [S2]. Windows memakai TCP untuk tiket besar, jadi keduanya perlu terlihat.

Untuk pemeriksa, pasangan `client` dan `service` adalah sumbu analisis utama, dan perlakuannya sama dengan first-seen di hunting: pasangan yang belum pernah terlihat dalam 90 hari lebih menarik daripada pasangan yang muncul ribuan kali sehari. Logikanya sederhana: aktivitas sah cenderung berulang dan tersebar di banyak hari, sedangkan langkah penyerang sering menghasilkan kombinasi yang baru pertama kali muncul. Di PT JAB jendela itu baru 36 hari (Zeek hidup sejak Selasa 2027-05-18), jadi tulis panjang baseline-nya di setiap temuan first-seen.

Sumbu kedua adalah pasangan `client` dan `id.orig_h`. Akun layanan yang biasanya hanya meminta tiket dari satu server aplikasi, lalu tiba-tiba meminta tiket dari workstation, adalah sinyal yang lebih bersih daripada hampir semua ambang volume. Itulah yang terjadi pada `svc-sqlbilling` di bagian 2.5.

Di sisi host, Event 4769 di domain controller mencatat setiap permintaan TGS dengan Account Name, Service Name, Client Address, Ticket Encryption Type, dan Failure Code; Failure Code 0x20 (tiket kedaluwarsa) umum dan biasanya tidak relevan [S4]. Event 4768 mencatat permintaan TGT, termasuk Pre-Authentication Type dan Client Address [S11]. Sejak pembaruan keamanan 14 Januari 2025, Windows Server 2016 ke atas menulis versi baru kedua event itu dengan field tambahan seperti enkripsi yang didukung akun, kunci yang tersedia, etype yang ditawarkan klien, dan hash tiket [S4][S11].

### 1.6 Encryption type sebagai sinyal

Bagian kedua pertanyaan Dimas ("bukannya RC4 sudah dimatikan?") menuntut kamu tahu tiga hal: daftar resmi jenis enkripsi, kebijakan Microsoft yang berubah sepanjang 2026, dan field mana yang benar-benar menunjukkan enkripsi yang bisa dipecahkan.

Field `cipher` menyimpan jenis enkripsi tiket [S2], dan nilainya mengikuti daftar resmi yang dikelola IANA [S3]. Yang perlu kamu kenali:

| Nilai | Nama | Status menurut daftar resmi |
|---|---|---|
| 17 | aes128-cts-hmac-sha1-96 | Standar, RFC 3962 |
| 18 | aes256-cts-hmac-sha1-96 | Standar, RFC 3962 |
| 19 | aes128-cts-hmac-sha256-128 | Standar, RFC 8009 |
| 20 | aes256-cts-hmac-sha384-192 | Standar, RFC 8009 |
| 23 | rc4-hmac | Ditandai deprecated |
| 1, 3, 16 dan sejenisnya | varian DES dan 3DES | Ditandai deprecated |

Di event Windows, nilai yang sama ditulis heksadesimal: 0x11 dan 0x12 untuk AES, 0x17 untuk RC4-HMAC, 0x1 dan 0x3 untuk DES. Microsoft menyarankan memantau Ticket Encryption Type selain 0x11 dan 0x12 sejak Windows Server 2008 [S4][S11]. Satu tabel di halaman Event 4768 dan 4769 menulis RC4-HMAC-NT sebagai desimal 23 dengan heksadesimal 0x18; yang benar untuk desimal 23 adalah 0x17, sesuai tabel Ticket Encryption Type di halaman yang sama, jadi pakai 0x17 [S4][S11].

Kenapa ini berguna: di domain yang sudah memakai AES, permintaan tiket dengan jenis enkripsi yang ditandai deprecated adalah penyimpangan yang layak diperiksa. Penurunan jenis enkripsi adalah teknik yang dikenal karena jenis lama lebih mudah diserang di luar jaringan. Analitik ATT&CK untuk Kerberoasting memantau permintaan TGS dengan RC4 (0x17) dan akun yang meminta banyak tiket layanan dalam waktu singkat [S13].

Kebijakan Microsoft yang mengubah gambaran ini, dari KB5073381 untuk CVE-2026-20833 [S12]:

| Tahap | Rilis | Perubahan |
|---|---|---|
| Awal | Pembaruan 13 Januari 2026 | Event audit KDCSVC 201 sampai 209 di log System domain controller, dan nilai registry `RC4DefaultDisablementPhase` |
| Enforcement dengan rollback manual | Pembaruan 14 April 2026 | Nilai bawaan `DefaultDomainSupportedEncTypes` menjadi AES-SHA1 saja (0x18) untuk akun yang tidak punya `msDS-SupportedEncryptionTypes` eksplisit |
| Enforcement | Juli 2026 | Dukungan `RC4DefaultDisablementPhase` dihapus, enforcement aktif |

Artinya: setelah domain controller menerima pembaruan itu, akun tanpa konfigurasi eksplisit hanya mendapat tiket AES, tetapi akun yang `msDS-SupportedEncryptionTypes`-nya secara eksplisit memuat RC4 tetap dihormati, dan KB itu memang menyarankan cara tersebut untuk layanan yang masih butuh RC4 [S12]. Halaman KB itu sendiri tidak konsisten soal apakah enforcement otomatis sejak April atau Juli; untuk keputusan di lingkunganmu, baca event KDCSVC di domain controller. Event 201 dan 202 adalah peringatan (klien hanya RC4, atau service tanpa kunci AES) yang menjadi galat 203 dan 204 saat enforcement; 205 menandai `DefaultDomainSupportedEncTypes` yang secara eksplisit mengizinkan cipher tidak aman [S12].

Untuk analisis jaringan, akibatnya dua. Pertama, tiket RC4 yang masih keluar hampir pasti berasal dari akun dengan RC4 eksplisit, dan daftar akun itu adalah daftar target paling berharga bagi penyerang. Kedua, permintaan yang hanya menawarkan RC4 untuk akun AES-only sekarang gagal di KDC; di `kerberos.log` itu terlihat sebagai baris TGS gagal dengan `KDC_ERR_ETYPE_NOSUPP`. Rentetan galat itu dari satu klien adalah sinyal tersendiri (bagian 2.5).

Ada jebakan pada field. `cipher` di Zeek adalah enkripsi tiket [S2]. Untuk TGS, tiket dienkripsi kunci akun layanan, jadi `cipher` memang menunjukkan bagian yang bisa dipecahkan pada Kerberoasting. Untuk AS, tiket adalah TGT yang dienkripsi kunci `krbtgt`, sedangkan bagian yang dipecahkan pada AS-REP Roasting adalah bagian balasan yang dienkripsi kunci akun pengguna. Suricata 8.0.7 membedakan keduanya di event `krb5`: `encryption` dan `weak_encryption` untuk enkripsi balasan AS-REP atau TGS-REP, dan `ticket_encryption` serta `ticket_weak_encryption` untuk enkripsi tiket [S17]. Bila yang kamu butuhkan adalah enkripsi bagian yang bisa dipecahkan pada AS-REP, field Suricata `encryption` yang menjawab, bukan `cipher` Zeek. Di Wireshark, nilai yang sama dibaca dari `kerberos.etype`, dengan `kerberos.msg_type`, `kerberos.CNameString`, `kerberos.SNameString`, `kerberos.padata_type`, dan `kerberos.error_code` sebagai pendamping [S18].

Yang perlu kamu hindari adalah menjadikan etype aturan kaku. Sistem lama, aplikasi lama, dan konfigurasi akun tertentu juga menghasilkan jenis enkripsi lama secara sah. Karena itu bangun baseline lebih dulu: hitung distribusi `cipher` per `service` dan per `client` selama beberapa minggu, lalu cari penyimpangan dari baseline itu, bukan dari daftar ideal.

### 1.7 Dua pola penyalahgunaan Kerberos yang terlihat dari jaringan

Alert `SOC-2027-0690` dan `SOC-2027-0691` mewakili dua pola ini. Keduanya berakhir di luar jaringan (pemecahan password berjalan offline), jadi yang bisa kamu lihat hanya langkah pengambilannya.

**Permintaan tiket layanan secara borongan.** Penyerang yang mengumpulkan tiket untuk banyak layanan sekaligus akan menghasilkan deretan permintaan `TGS` dari satu klien ke banyak `service` berbeda dalam waktu singkat. Pola yang dicari: jumlah `service` berbeda per klien dalam jendela pendek, dibandingkan dengan baseline klien itu sendiri. Bila disertai jenis enkripsi yang ditandai deprecated padahal domain memakai AES, sinyalnya menguat [S13]. Setelah pembaruan Microsoft 2026, tambahkan penguat ketiga: banyak TGS gagal dengan `KDC_ERR_ETYPE_NOSUPP` dari klien yang sama, karena klien menawarkan enkripsi yang tidak lagi dimiliki akun tujuan (bagian 1.6).

Batas keyakinannya: alat administrasi dan pemindai kerentanan yang sah juga menghasilkan pola serupa. Selalu periksa identitas pemintanya dan bandingkan dengan jadwal operasional sebelum menyimpulkan.

**Permintaan autentikasi awal tanpa prasyarat.** Akun yang dikonfigurasi "Do not require Kerberos preauthentication" memungkinkan pihak mana pun meminta bahan terenkripsi untuk akun itu [S14]. Dari jaringan, yang terlihat adalah permintaan `AS` untuk akun tertentu yang berhasil tanpa didahului galat prasyarat, sering dari host yang bukan tempat akun itu biasa dipakai. ATT&CK menyebut penyerang bisa menemukan akun semacam itu dengan query LDAP atau dengan mengirim permintaan untuk setiap pengguna dan melihat mana yang berhasil tanpa galat [S14]; cara kedua meninggalkan rentetan AS dari satu klien untuk banyak nama akun. Di domain controller, padanannya adalah Event 4768 dengan Pre-Authentication Type 0, yang menurut Microsoft hanya wajar untuk akun yang memang dikonfigurasi tanpa praautentikasi dan merupakan risiko keamanan [S11].

Batas keyakinannya lebih besar di sini, karena konfigurasi akun semacam itu kadang memang ada secara sah untuk perangkat atau aplikasi lama. Perlakukan sebagai dua temuan terpisah: daftar akun yang berkonfigurasi demikian sebagai temuan konfigurasi, dan permintaan dari host tidak lazim sebagai temuan aktivitas. Dan ingat batas field di bagian 1.5: apakah galat "praautentikasi diperlukan" tercatat di `kerberos.log` bergantung pada teks galat KDC dan `KRB::ignored_errors`, jadi pola "berhasil tanpa didahului galat" harus diuji di lingkunganmu sebelum dipercaya.

Untuk kedua pola, pasangkan dengan log endpoint. Peristiwa permintaan tiket layanan juga tercatat di log Security pengendali domain (4769, dan 4768 untuk TGT) [S4][S11], dan korelasi dua sumber jauh lebih kuat daripada salah satunya.

### 1.8 Apa yang hilang ketika SMB dienkripsi

Pertanyaan ketujuh Dimas datang dari rencana Agung: setelah `INC-2027-071` (Day 12), file server `jkt-fs02` (`10.20.8.22`, share `SALES$`) akan dipasangi enkripsi SMB. Day 12 bagian 2.8 membuktikan pengambilan 2,07 GB dari share itu justru dari `smb_files.log`, karena SMB-nya tidak dienkripsi.

SMB versi modern bisa mengenkripsi datanya, dan bila itu aktif, isi berkas dan rincian operasi tidak lagi terlihat dari jaringan. Secara teknis, pesan terenkripsi dibungkus SMB2 TRANSFORM_HEADER yang hanya berlaku untuk dialek SMB 3.x; header itu diawali ProtocolId `0xFD 'S' 'M' 'B'` dan membawa ukuran pesan asli serta SessionId, sedangkan pesan SMB2 di dalamnya terenkripsi [S20]. Di Wireshark, pesan semacam itu terlihat dengan field `smb2.header.transform.flags.encrypted`, dan permintaan enkripsi sesi dari server terlihat di `smb2.ses_flags.encrypt` [S18].

Yang tersisa adalah metadata koneksi dan autentikasi:

| Masih terlihat | Hilang |
|---|---|
| Siapa menghubungi siapa, kapan, berapa byte, berapa lama (`conn.log`, flow) | Nama berkas, operasi berkas, ukuran per berkas (`smb_files.log`) |
| Negosiasi dialek dan SESSION_SETUP, yang terjadi sebelum kunci enkripsi ada | Operasi DCE-RPC di atas pipe (`dce_rpc.log`) |
| Tiket Kerberos di SESSION_SETUP: SPN `cifs/<host>` dan realm bisa dibaca dari tiket yang tidak terenkripsi bagiannya | Isi berkas dan ekstraksi file (`files.log`, `pe.log`) |
| Untuk NTLM: nama pengguna, domain, dan nama host klien (`ntlm.log`) | Untuk enkripsi tingkat sesi: share mana yang dipetakan |
| Permintaan TGS `cifs/jkt-fs02` dari klien ke DC (`kerberos.log`) | |

Apakah `smb_mapping.log` masih terisi bergantung pada cara enkripsi dinyalakan. Bila enkripsi diwajibkan untuk seluruh sesi, TREE_CONNECT ikut terenkripsi dan share yang dipetakan tidak terlihat. Bila enkripsi dinyalakan per share, permintaan TREE_CONNECT ke share itu dikirim sebelum enkripsi berlaku untuk share tersebut, sehingga nama share masih mungkin terlihat. Perilaku ini perlu dicek di lab dengan Zeek versi-mu sebelum dijanjikan ke siapa pun (bagian 3 langkah 9). Suricata 8.0.7 mencatat realm dan daftar SPN dari tiket Kerberos di dalam event `smb` (`smb.kerberos.realm`, `smb.kerberos.snames`) [S17], tetapi `eve-proto.json` PT JAB belum memuat event `smb`.

Pola yang berlaku sama seperti Day 15 dan Day 16: analisis bergeser dari isi ke metadata dan ke pola. Untuk lateral movement, pergeseran ini tidak sefatal yang dikira, karena pertanyaan utamanya adalah "host mana berbicara ke host mana dengan cara apa", dan itu tetap terjawab. Untuk pertanyaan Day 12 ("data apa yang diambil"), pergeserannya fatal: volume per sesi masih ada, nama folder tidak.

Yang benar-benar hilang adalah kemampuan melihat berkas apa yang disalin. Penggantinya ada di endpoint dan di server berkas: jejak sistem berkas di host tujuan (berkas baru di folder sementara atau `C:\Windows`), telemetri proses yang membuat atau membuka berkas itu, dan audit akses berkas di file server. Jawaban untuk Agung: enkripsi tetap layak dinyalakan (data penjualan melewati jaringan kantor dalam teks polos), tetapi pada hari yang sama audit akses objek di `jkt-fs02` untuk share `SALES$` harus diteruskan ke Splunk, supaya bukti T1039 berpindah dari sensor ke server. Nyatakan pembagian ini di laporan, supaya tidak ada yang berharap jaringan menjawab pertanyaan yang memang bukan wilayahnya.

Satu catatan lagi tentang arah perkembangan: Windows Server 2025 menyediakan SMB over QUIC di semua edisi, dengan TLS 1.3 dan sertifikat sehingga seluruh trafik SMB terenkripsi; port bawaannya 443/UDP dan bisa diganti [S19]. Day 16 sudah mencatat bahwa port 443 UDP tidak selalu berarti HTTP/3 karena alasan ini.

### 1.9 Dari sinyal ke rantai: korelasi host dan label ATT&CK

Pertanyaan terakhir Dimas meminta rantai, bukan daftar alert. Rantai lateral movement disusun dari tiga sumber jaringan (Kerberos, SMB dan DCE-RPC, conn) ditambah satu sumber yang bukan jaringan (log host), dan setiap baris menyebut sumbernya.

Urutan yang berulang di hampir setiap kasus berbentuk seperti ini:

```
TGS cifs/<target> (kerberos.log, 4769 di DC)
  -> map ADMIN$ DISK (smb_mapping.log)
  -> FILE_WRITE berkas executable (smb_files.log; arah dari files.log is_orig=T)
  -> map IPC$ PIPE, pipe svcctl (smb_mapping.log, smb_files.log)
  -> OpenSCManagerW, CreateServiceW, StartServiceW (dce_rpc.log)
  -> [EKSEKUSI di host tujuan: 4624 tipe 3, 7045, proses baru = wilayah ENDPOINT]
```

Baris terakhir sengaja ditandai sebagai wilayah endpoint. Jaringan bisa membuktikan urutan sampai panggilan RPC; apa yang dieksekusi dan apa yang dilakukannya harus datang dari host. Laporan yang baik menyatakan itu alih-alih menyamarkannya.

Label ATT&CK yang biasanya dipakai, dengan status di v20.0 per tanggal riset, dipakai untuk memberi nama setiap langkah di laporan:

| Teknik | Langkah | Sumber jaringan yang mendukung |
|---|---|---|
| T1558.003 Kerberoasting (v1.3, DET0157) | TGS borongan, sering dengan RC4 | `kerberos.log`, 4769 [S13] |
| T1558.004 AS-REP Roasting (v1.2, DET0113) | AS tanpa praautentikasi | `kerberos.log`, 4768 Pre-Auth Type 0, Suricata `krb5` [S14] |
| T1021.002 SMB/Windows Admin Shares (v1.3, DET0530) | Map dan tulis ke `ADMIN$`/`C$` | `smb_mapping.log`, `smb_files.log`, `files.log` [S15] |
| T1569.002 Service Execution (v1.3, DET0421) | Buat dan jalankan service lewat `svcctl` | `dce_rpc.log` [S16] |
| T1078 Valid Accounts | Akun layanan dipakai dari host yang bukan tempatnya | `kerberos.log` (`client` per `id.orig_h`) |

Setiap label ditulis dengan status bukti: "didukung data jaringan", "didukung host", atau "dugaan". Label T1558.003 misalnya hanya bisa "didukung data jaringan" untuk pengambilan tiket; bahwa password akun benar-benar dipecahkan hanya bisa disimpulkan dari pemakaian akun itu setelahnya.

## 2. Contoh dan langkah praktis: merangkai `INC-2027-078` dari data sensor

Semua keluaran di bagian ini adalah keluaran ilustrasi untuk organisasi fiktif PT JAB, bukan hasil eksekusi nyata. Asumsi lingkungan: log Zeek JSON di Splunk index `zeek` dengan sourcetype eksplisit per log; `bro:conn:json` terkonfirmasi, sedangkan `bro:smb_mapping:json`, `bro:smb_files:json`, `bro:dce_rpc:json`, `bro:kerberos:json`, dan `bro:files:json` mengikuti pola yang sama dan perlu divalidasi dengan `| metadata type=sourcetypes index=zeek` (Day 08 bagian 1.9). Arsip Zeek ada di `/opt/zeek/logs/<tanggal UTC>/` dan disalin ke `/cases/INC-2027-078/zeek/` di `jkt-nsm-ws01`, yang zona waktunya UTC; Rabu 09:00 WIB adalah 02:00 UTC di folder `2027-06-23`. Splunk menampilkan WIB. Log Security `jkt-dc01` dan `jkt-dc02` ada di `index=wineventlog`; nama field Windows di contoh mengikuti ekstraksi add-on Windows dan perlu dicocokkan dengan Splunk-mu. Lookup `nsm_admin_sources.csv` (host administrasi yang diketahui) dan `ad_spn_inventory.csv` (ekspor mingguan SPN dari Active Directory oleh tim Agung: SPN, akun pemilik, jenis akun, dan enkripsi yang diizinkan) dirawat SOC. Perintah lama dari catatan versi sebelumnya dipertahankan dan ditempatkan di samping versi untuk data PT JAB.

Host yang muncul di bagian ini, supaya alamat di keluaran bisa dibaca tanpa bolak-balik:

| Host | Alamat | Peran |
|---|---|---|
| `JKT-WS-2091` | `10.10.60.191` | Workstation Billing, sesi `nadia.puspita`; host awal `INC-2027-078` |
| `JKT-WS-2092`, `JKT-WS-2093` | `10.10.60.192`, `10.10.60.193` | Workstation Billing (`reza.kurniawan`, `maya.safitri`), switch akses yang sama dengan `JKT-WS-2091` |
| `jkt-dc01`, `jkt-dc02` | `10.20.8.11`, `10.20.8.12` | Domain controller `corp.jab.example` |
| `jkt-pam01` | `10.20.8.20` | Jump host administrasi |
| `jkt-mecm01` | `10.20.8.30` | Server distribusi perangkat lunak (MECM) |
| `jkt-app07` | `10.20.8.37` | Aplikasi Billing lama, klien SQL yang masih memakai RC4 |
| `jkt-app11` | `10.20.8.41` | Server API Billing; keluar internet hanya ke daftar mitra lewat NAT `198.51.100.219` |
| `jkt-sql05` | `10.20.8.45` | SQL Server Billing, service berjalan sebagai `svc-sqlbilling` |
| `jkt-docscan01` | `10.20.8.77` | Perangkat pemindai dokumen lama, akun `svc-legacyscan` |
| `jkt-vscan01` | `10.20.10.61` | Pemindai kerentanan resmi |

### 2.1 Koneksi share dan named pipe: siapa memetakan `ADMIN$`

**Tujuan:** menjawab pertanyaan keempat Dimas dari sumbu sumber dan pasangan: host mana saja yang memetakan share administratif, dan apakah `10.10.60.191` pernah ada di daftar itu.

Perintah dari catatan lama, untuk `smb_mapping.log` TSV:

```bash
cat smb_mapping.log | zeek-cut ts id.orig_h id.resp_h path share_type \
  | sort -k2,3 | uniq -c -f1 | sort -rn | head -40
```

- `zeek-cut` mengambil lima kolom; `ts` ikut supaya baris bisa diurutkan, lalu dilewati saat dihitung.
- `uniq -c -f1` menghitung baris yang sama persis setelah melewati field pertama (`ts`), jadi satu baris keluaran berarti satu kombinasi sumber, tujuan, share, dan jenis.
- `sort -rn | head -40` menaruh kombinasi terbanyak di atas.

Keluaran ilustrasi dari catatan lama (lab):

```
 412  10.20.0.44  10.20.0.10  \\DC1\IPC$          PIPE
 318  10.20.0.44  10.20.0.21  \\FS01\data         DISK
   3  10.20.0.77  10.20.0.21  \\FS01\ADMIN$       DISK
   2  10.20.0.77  10.20.0.33  \\WS-033\ADMIN$     DISK
   2  10.20.0.77  10.20.0.41  \\WS-041\ADMIN$     DISK
```

Cara membacanya: dua baris teratas adalah pola harian yang wajar, yaitu klien ke pengendali domain dan klien ke share data. Tiga baris terakhir yang menarik, bukan karena `ADMIN$` itu sendiri, melainkan karena satu host menghubungi share administratif di tiga host berbeda dengan jumlah koneksi yang kecil. Itu bentuk penyebaran, dan pola jumlah kecil ke banyak tujuan adalah bentuk yang sama dengan stacking di hunting.

Memisahkan pemakaian named pipe (catatan lama):

```bash
cat smb_mapping.log | zeek-cut id.orig_h id.resp_h share_type \
  | awk '$3 == "PIPE"' | sort | uniq -c | sort -rn | head -20
```

Di PT JAB, log berbentuk JSON dan jendela kasusnya Rabu 09:00 sampai 10:00 WIB (02:00 sampai 03:00 UTC, epoch 1813716000 sampai 1813719600). Versi `jq` di `jkt-nsm-ws01` menghitung berapa share administratif berbeda yang dipetakan setiap sumber:

```bash
cd /cases/INC-2027-078/zeek/2027-06-23
jq -r 'select(.ts >= 1813716000 and .ts < 1813719600)
       | select(.path | test("(ADMIN|C)\\$$"; "i"))
       | [."id.orig_h", .path] | @tsv' smb_mapping.*.log \
  | sort -u | cut -f1 | uniq -c | sort -rn
```

- `select(.ts ...)` membatasi ke jendela kasus; `ts` Zeek adalah epoch UTC.
- `test("(ADMIN|C)\\$$"; "i")` mencocokkan path yang berakhiran `ADMIN$` atau `C$` tanpa peduli huruf besar kecil; `\\$` adalah tanda dolar literal, `$` terakhir adalah akhir string.
- `sort -u` membuang pemetaan berulang ke share yang sama, `cut -f1 | uniq -c` lalu menghitung share berbeda per sumber.

Keluaran ilustrasi:

```
     29 10.20.8.30
      1 10.10.60.191
```

Untuk sumbu pasangan, jendelanya diperlebar ke seluruh umur Zeek (36 hari) di Splunk:

```
index=zeek sourcetype=bro:smb_mapping:json share_type=DISK (path="*ADMIN$" OR path="*C$")
    earliest="05/18/2027:00:00:00" latest="06/23/2027:11:00:00"
| stats count dc(id.resp_h) AS tujuan min(_time) AS pertama max(_time) AS terakhir BY id.orig_h
| lookup nsm_admin_sources.csv src AS id.orig_h OUTPUT nama peran
| convert ctime(pertama) ctime(terakhir)
| sort - count
```

| Bagian | Fungsi |
|---|---|
| `share_type=DISK (path="*ADMIN$" OR path="*C$")` | Hanya share administratif; nilai field di pencarian Splunk tidak peka huruf besar kecil |
| `stats ... BY id.orig_h` | Satu baris per sumber: jumlah pemetaan, jumlah tujuan berbeda, kapan pertama dan terakhir |
| `lookup nsm_admin_sources.csv` | Menempelkan nama dan peran bila sumber terdaftar sebagai host administrasi |

Keluaran ilustrasi:

```
id.orig_h      count  tujuan  pertama              terakhir             nama         peran
10.20.8.30     4131   212     05/18/2027 10:02:11  06/23/2027 10:14:40  jkt-mecm01   distribusi perangkat lunak
10.20.10.61    2906   388     05/18/2027 22:00:04  06/22/2027 23:41:19  jkt-vscan01  pemindai kerentanan
10.20.8.20     187    41      05/19/2027 08:12:55  06/22/2027 16:30:02  jkt-pam01    jump host administrasi
10.10.60.191   1      1       06/23/2027 09:33:13  06/23/2027 09:33:13
```

**Cara membaca hasil:** dalam 36 hari hanya empat sumber pernah memetakan share administratif lewat core switch data center. Tiga terdaftar sebagai host administrasi dan polanya lebar dan berulang (ratusan tujuan, puluhan hari). Yang keempat adalah workstation Billing dengan satu pemetaan ke satu server, pertama kali Rabu pagi. Dua sumbu tabel bagian 1.1 (sumber dan pasangan) sudah menyimpang untuk `10.10.60.191`; untuk `10.20.8.30`, keduanya cocok dengan baseline. Jendela 09:00 sampai 10:00 hanya menangkap 29 dari 63 server MECM karena push berjalan sampai 10:14:40.

**Variasi:** ganti filter `share_type=DISK` dengan `share_type=PIPE` dan `path="*IPC$"` untuk melihat siapa memakai named pipe ke host mana; hasilnya jauh lebih ramai karena setiap workstation memakai `IPC$` di domain controller.

**Kapan gagal:** host administrasi yang sah memang menghubungi `ADMIN$` di banyak mesin. Bandingkan dengan daftar host administrasi yang diketahui, dan dengan jadwal pemeliharaan. Pada perintah lama, `sort -k2,3` mengurutkan hanya menurut sumber dan tujuan, lalu memutus seri dengan seluruh baris (diawali `ts`), sehingga dua share berbeda ke tujuan yang sama bisa berselang-seling dan `uniq` menghitungnya terpecah; `sort -k2` (dari field kedua sampai akhir) lebih aman. Dan pemetaan antar workstation tidak pernah ada di hasil ini (bagian 1.2).

### 2.2 Berkas yang ditulis ke share administratif, dan arahnya

**Tujuan:** memastikan apa yang ditulis ke `ADMIN$` di `jkt-app11`, berapa besar, dan bahwa arahnya memang dari workstation ke server.

Perintah dari catatan lama:

```bash
cat smb_files.log | zeek-cut ts id.orig_h id.resp_h action path name size \
  | grep -iE 'ADMIN\$|C\$' | sort -k1
```

Keluaran ilustrasi dari catatan lama (lab):

```
1791540380  10.20.0.77  10.20.0.33  SMB::FILE_OPEN   \\WS-033\ADMIN$  temp\svc-update.exe  0
1791540381  10.20.0.77  10.20.0.33  SMB::FILE_WRITE  \\WS-033\ADMIN$  temp\svc-update.exe  184320
1791540402  10.20.0.77  10.20.0.33  SMB::FILE_OPEN   \\WS-033\ADMIN$  <share_root>         0
```

Cara membacanya: operasi tulis berkas yang bisa dieksekusi ke share administratif di host lain, diikuti pemakaian named pipe ke host yang sama beberapa detik kemudian, adalah rangkaian klasik menaruh lalu menjalankan. Perhatikan bahwa `smb_files.log` tidak menunjukkan arah transfer, jadi arahnya perlu dipastikan dari `files.log` [S1].

Versi PT JAB, untuk semua tulis ke share administratif di folder kasus:

```bash
jq -r 'select(.action == "SMB::FILE_WRITE" and (.path | test("(ADMIN|C)\\$$"; "i")))
       | [(.ts | floor | todate), ."id.orig_h", ."id.resp_h", .path, .name, .size] | @tsv' smb_files.*.log \
  | sort
```

Keluaran ilustrasi (baris MECM diringkas):

```
2027-06-23T02:33:13Z  10.10.60.191  10.20.8.41  \\JKT-APP11\ADMIN$  Temp\bsvc64.exe        286720
2027-06-23T02:47:12Z  10.20.8.30    10.20.8.52  \\jkt-rpt02\ADMIN$  ccmsetup\ccmsetup.exe  (ukuran sama di 63 baris)
... 62 baris lain dari 10.20.8.30, 02:47:12 sampai 03:14:40 UTC
```

Arah dan isi dari `files.log`, yang sejak Zeek 5.1 memakai `uid` dan `id` (Day 08 bagian 1.5):

```bash
jq -r 'select(.source == "SMB" and ."id.orig_h" == "10.10.60.191")
       | [(.ts | floor | todate), .uid, ."id.resp_h", (.is_orig | tostring), .mime_type,
          .seen_bytes, (.missing_bytes // 0), .sha256] | @tsv' files.*.log
```

Keluaran ilustrasi:

```
2027-06-23T02:33:13Z  CRcY5HhGmzwHsLjMqg  10.20.8.41  true  application/x-dosexec  286720  0  78ba0c93ee9ddcb242c33ca27cacdec7c90964143a1d1a37ac73524722f05ff2
```

**Cara membaca hasil:** `is_orig` = `true` berarti berkas dikirim oleh originator koneksi, yaitu `10.10.60.191`, ke `jkt-app11`. `mime_type` dari isi menunjukkan PE Windows, `seen_bytes` sama dengan `size` di `smb_files.log` (286.720 byte), dan `missing_bytes` nol sehingga hash mewakili berkas utuh. Hash SHA-256 diserahkan ke Yoga untuk dicocokkan dengan berkas di `C:\Windows\Temp\` di `jkt-app11` dan di `JKT-WS-2093`; MDE kemudian mengonfirmasi hash yang sama di kedua host. Nama `bsvc64.exe` tidak membuktikan apa pun; yang membuktikan adalah hash, ukuran, dan urutannya. Berkas tidak diekstrak dari sensor dan tidak disimpan di repo atau folder kasus; analisis isinya di tangan IR.

**Kapan gagal:** alat distribusi perangkat lunak yang sah melakukan hal yang sama persis. Pembedanya adalah host sumber, jadwal, dan apakah pola itu muncul di daftar host yang memang bertugas mendistribusikan. Hash kosong bila `hash-all-files` tidak dimuat; `missing_bytes` bukan nol berarti hash tidak mewakili berkas utuh; dan bila SMB dienkripsi, baris `files.log` dan `smb_files.log` untuk sesi itu tidak ada sama sekali (bagian 1.8).

### 2.3 DCE-RPC: operasi `svcctl` di `jkt-app11`, saved search, dan percobaan keluar

**Tujuan:** menjawab pertanyaan kelima Dimas sejauh jaringan bisa, dan menunjukkan saved search yang menyalakan `SOC-2027-0692` dan `SOC-2027-0693`.

Operasi Service Control Manager yang dipanggil dari `10.10.60.191`:

```bash
jq -r 'select(.endpoint == "svcctl")
       | [(.ts | floor | todate), .uid, ."id.orig_h", ."id.resp_h", .named_pipe, .operation] | @tsv' dce_rpc.*.log \
  | grep 10.10.60.191
```

Keluaran ilustrasi:

```
2027-06-23T02:33:15Z  CqAu9r1gXu5tbKNm4e  10.10.60.191  10.20.8.41  svcctl  OpenSCManagerW
2027-06-23T02:33:15Z  CqAu9r1gXu5tbKNm4e  10.10.60.191  10.20.8.41  svcctl  CreateServiceW
2027-06-23T02:33:16Z  CqAu9r1gXu5tbKNm4e  10.10.60.191  10.20.8.41  svcctl  StartServiceW
2027-06-23T02:33:21Z  CqAu9r1gXu5tbKNm4e  10.10.60.191  10.20.8.41  svcctl  DeleteService
```

**Cara membaca hasil:** satu koneksi (`uid` sama) membuka Service Control Manager, membuat service, menjalankannya, lalu menghapusnya lima detik kemudian. Itu bentuk service sementara yang disebut analitik T1569.002 [S16]. Bandingkan dengan `jkt-mecm01` pada jam yang sama: `OpenSCManagerW`, `CreateServiceW`, `StartServiceW` ke setiap server, tanpa `DeleteService`, karena menurut runbook MECM tim Agung service `ccmsetup` membereskan dirinya sendiri di host tujuan setelah instalasi selesai. Yang tidak terlihat: nama service, path biner, dan argumen `CreateServiceW` (bagian 1.4). Bahwa service itu menjalankan `C:\Windows\Temp\bsvc64.exe` diketahui dari Event 7045 di `jkt-app11` (MDE), bukan dari sensor.

Saved search `NSM - tulis ADMIN$ lalu svcctl` (tiap 10 menit, rentang 15 menit, throttle 60 menit per sumber) meniru analitik pertama BZAR di Splunk:

```
index=zeek earliest=-15m@m latest=@m
    ((sourcetype=bro:smb_files:json action="SMB::FILE_WRITE" (path="*ADMIN$" OR path="*C$"))
     OR (sourcetype=bro:dce_rpc:json endpoint=svcctl operation IN ("CreateServiceW", "CreateServiceWOW64W", "StartServiceW")))
| eval langkah=if(sourcetype="bro:smb_files:json", "tulis", "svcctl")
| stats min(_time) AS mulai dc(langkah) AS n_langkah values(name) AS berkas values(operation) AS operasi
        BY id.orig_h id.resp_h
| where n_langkah=2
| stats min(mulai) AS mulai dc(id.resp_h) AS tujuan values(berkas) AS berkas values(operasi) AS operasi BY id.orig_h
| lookup nsm_admin_sources.csv src AS id.orig_h OUTPUT nama peran
| eval peran=coalesce(peran, "tidak terdaftar"), urgensi=if(peran="tidak terdaftar", "tinggi", "rendah")
| convert ctime(mulai)
```

| Bagian | Fungsi |
|---|---|
| Dua kelompok di baris pencarian | Langkah "tulis" (tulis berkas ke `ADMIN$`/`C$`) dan langkah "svcctl" (membuat atau menjalankan service) |
| `stats ... BY id.orig_h id.resp_h` lalu `where n_langkah=2` | Hanya pasangan yang melakukan kedua langkah ke host yang sama dalam jendela |
| `stats ... BY id.orig_h` kedua | Satu baris per sumber, dengan jumlah tujuan |
| `lookup` dan `eval urgensi` | Host administrasi tidak dikecualikan; ia tetap menyalakan alert, dengan urgensi rendah dan pembanding yang jelas |

Keluaran ilustrasi pada dua jendela yang menyalakan alert:

```
id.orig_h     mulai                tujuan  berkas                 operasi                       nama        peran                       urgensi
10.10.60.191  06/23/2027 09:33:13  1       Temp\bsvc64.exe        CreateServiceW StartServiceW  -           tidak terdaftar             tinggi
10.20.8.30    06/23/2027 09:47:12  29      ccmsetup\ccmsetup.exe  CreateServiceW StartServiceW  jkt-mecm01  distribusi perangkat lunak  rendah
```

Baris pertama berasal dari jendela 09:25 sampai 09:40 dan menjadi `SOC-2027-0692` pukul 09:41; baris kedua dari jendela 09:45 sampai 10:00 dan menjadi `SOC-2027-0693` pukul 10:02. `SOC-2027-0693` ditutup jinak pukul 10:25: sumber terdaftar, tujuan cocok dengan daftar server di `CHG-2027-0461` (push agent MECM, jendela 09:45 sampai 11:30), akun `svc-mecm-push` yang memang dipakai untuk push (dari `kerberos.log`), dan berkas yang sama dengan hash yang sama di 63 server. `SOC-2027-0692` gagal di keempat sumbu bagian 1.1.

Langkah berikutnya: apakah sesuatu di `jkt-app11` mencoba keluar setelah service berjalan. Sumbernya Zeek di TAP egress, yang melihat alamat internal sebelum NAT:

```
index=zeek sourcetype=bro:conn:json "id.orig_h"="10.20.8.41" NOT "id.resp_h"="10.*"
    earliest="06/23/2027:09:30:00" latest="06/23/2027:10:10:00"
| table _time id.orig_h id.resp_h id.resp_p conn_state history orig_bytes
```

Keluaran ilustrasi:

```
_time                    id.orig_h   id.resp_h      id.resp_p  conn_state  history  orig_bytes
2027-06-23 09:33:31.208  10.20.8.41  203.0.113.197  443        REJ         Sr       0
2027-06-23 09:34:31.215  10.20.8.41  203.0.113.197  443        REJ         Sr       0
2027-06-23 09:35:31.230  10.20.8.41  203.0.113.197  443        REJ         Sr       0
```

**Cara membaca hasil:** sepuluh detik setelah service dijalankan, `jkt-app11` mencoba TCP 443 ke `203.0.113.197` tiga kali dengan jeda 60 detik, dan setiap percobaan dijawab RST oleh `jkt-fw01` (`REJ`, `Sr`, nol byte). Aturan keluar server Billing hanya mengizinkan daftar mitra lewat NAT `198.51.100.219`, jadi percobaan ini tidak pernah sampai NAT dan tidak ada di flow router edge; log firewall mencatat tiga penolakan yang sama. Tidak ada data keluar. Setelah 09:35:31 tidak ada percobaan lagi sampai `jkt-app11` diisolasi pukul 10:04; kenapa berhenti hanya bisa dijawab dari host. `203.0.113.197` diteruskan ke IR sebagai indikator, bukan sebagai bukti C2: yang terbukti hanya niat koneksi.

**Kapan gagal:** saved search hanya menangkap pasangan yang kedua langkahnya jatuh di jendela 15 menit yang sama; penyerang yang menaruh berkas dulu dan menjalankannya satu jam kemudian lolos, jadi jalankan juga versi harian dengan jendela 24 jam. Eksekusi lewat `atsvc`, WMI, atau WinRM tidak memakai `svcctl` dan tidak tertangkap search ini. Dan penyerang yang memakai service yang sudah ada (mengubah path biner dengan `ChangeServiceConfigW`) tidak memanggil `CreateServiceW`.

### 2.4 Baseline encryption type Kerberos

**Tujuan:** menjawab bagian kedua pertanyaan kedua Dimas ("bukannya RC4 sudah dimatikan?") dengan distribusi `cipher` di domain PT JAB sendiri, sebelum menilai `SOC-2027-0690`.

Perintah dari catatan lama:

```bash
cat kerberos.log | zeek-cut request_type service cipher success \
  | awk '$1 == "TGS"' | sort | uniq -c | sort -rn | head -30
```

Keluaran ilustrasi dari catatan lama (lab):

```
28412  TGS  cifs/FS01.lab.local     aes256-cts-hmac-sha1-96  T
19877  TGS  host/WS-041.lab.local   aes256-cts-hmac-sha1-96  T
 1204  TGS  ldap/DC1.lab.local      aes256-cts-hmac-sha1-96  T
   17  TGS  MSSQLSvc/APP01:1433     rc4-hmac                 T
```

Cara membacanya: baris terakhir menonjol bukan karena jumlahnya kecil, melainkan karena jenis enkripsinya berbeda dari seluruh domain dan ditandai deprecated di daftar resmi [S3]. Itu titik awal pemeriksaan, bukan kesimpulan.

Versi PT JAB, untuk seluruh umur Zeek sebelum hari kejadian:

```
index=zeek sourcetype=bro:kerberos:json request_type=TGS success=true
    earliest="05/18/2027:00:00:00" latest="06/23/2027:00:00:00"
| stats count dc(id.orig_h) AS klien BY cipher
| eventstats sum(count) AS total
| eval persen=round(100*count/total, 3)
| fields cipher count klien persen
```

Keluaran ilustrasi:

```
cipher                    count     klien  persen
aes256-cts-hmac-sha1-96   48913604  1398   99.888
rc4-hmac                  54789     9      0.112
```

Lalu siapa yang masih mendapat RC4:

```
index=zeek sourcetype=bro:kerberos:json request_type=TGS success=true cipher="rc4-hmac"
    earliest="05/18/2027:00:00:00" latest="06/23/2027:00:00:00"
| stats count dc(id.orig_h) AS klien BY service
| lookup ad_spn_inventory.csv spn AS service OUTPUT akun enc_diizinkan
| sort - count
```

Keluaran ilustrasi:

```
service                                       count  klien  akun            enc_diizinkan
MSSQLSvc/jkt-sql05.corp.jab.example:1433      51360  1      svc-sqlbilling  RC4,AES128,AES256
HTTP/jkt-docscan01.corp.jab.example           2544   3      svc-legacyscan  RC4
MSSQLSvc/jkt-sql02.corp.jab.example:1433      540    2      svc-report01    RC4,AES256
HTTP/crm-old.corp.jab.example                 288    2      svc-crmold      RC4
HTTP/jkt-ivr01.corp.jab.example               36     1      svc-ivr         RC4,AES256
HTTP/jkt-fax01.corp.jab.example               21     1      svc-faxgw       RC4
```

**Cara membaca hasil:** 99,888% tiket layanan dalam 36 hari memakai AES256. Sisa 0,112% (54.789 tiket) berasal dari enam SPN, dan keenamnya milik akun yang `msDS-SupportedEncryptionTypes`-nya secara eksplisit memuat RC4. Itu sesuai dengan perilaku setelah pembaruan Microsoft 2026: akun tanpa konfigurasi eksplisit hanya mendapat AES, akun dengan RC4 eksplisit tetap dihormati [S12]. Jadi jawaban untuk Dimas: RC4 tidak "dimatikan", ia dibatasi ke akun yang dikecualikan secara sengaja. Baris teratas adalah aplikasi Billing lama di `jkt-app07` yang meminta tiket ke `jkt-sql05` tepat 1.440 kali sehari (sekali per menit) sejak Zeek hidup Selasa 2027-05-18 sekitar 08:00, satu klien, setiap hari: 960 tiket di hari pertama ditambah 35 hari penuh menjadi 51.360. Enam akun ini adalah daftar yang paling berharga bagi penyerang, karena tiketnya bisa diminta dalam RC4. Simpan hasil ini sebagai baseline dan jalankan ulang berkala. Perubahan distribusi jenis enkripsi untuk satu layanan adalah sinyal yang jauh lebih bersih daripada ambang absolut apa pun.

**Variasi:** ganti `BY service` dengan `BY id.orig_h client` untuk baseline per klien; pasangan klien dan layanan RC4 yang baru muncul adalah kandidat paling tajam. Di sisi DC, padanannya adalah Event 4769 dengan Ticket Encryption Type 0x17 [S4]; event KDCSVC 201 sampai 209 di log System domain controller menunjukkan akun dan klien yang akan atau sudah terdampak pembatasan RC4 [S12].

**Kapan gagal:** `cipher` kosong di baris yang gagal dan bisa kosong di sebagian baris lain karena field opsional [S2]; baseline 36 hari belum mencakup proses bulanan atau kuartalan; dan bila domain controller belum menerima pembaruan 2026, distribusinya akan jauh lebih campur sehingga RC4 sendiri bukan pembeda.

### 2.5 Permintaan tiket layanan borongan: `SOC-2027-0690`

**Tujuan:** menjawab pertanyaan kedua Dimas: apakah `SOC-2027-0690` Kerberoasting, akun mana yang tiketnya keluar dengan RC4, dan apakah ada tanda tiket itu dipakai.

Perintah dari catatan lama, untuk `kerberos.log` TSV:

```bash
cat kerberos.log | zeek-cut ts id.orig_h client request_type service cipher \
  | awk '$4 == "TGS"' \
  | awk '{bucket=int($1/600); print bucket, $2, $3, $5, $6}' \
  | sort | uniq \
  | awk '{key=$1" "$2" "$3; count[key]++; svc[key]=svc[key]" "$4}
         END {for (k in count) if (count[k] >= 10) print count[k], k, svc[k]}' \
  | sort -rn | head -20
```

Cara membacanya: skrip ini menghitung jumlah layanan berbeda yang dimintakan tiket oleh satu klien dalam jendela sepuluh menit (`int($1/600)` membagi waktu ke ember 600 detik). Ambang sepuluh adalah titik awal yang harus kamu ganti dengan angka dari baseline sendiri.

Tiga penguat yang membuat hasilnya lebih tajam:

- Batasi ke `service` yang berupa akun layanan, bukan host.
- Beri bobot lebih pada permintaan dengan `cipher` yang menyimpang dari baseline (bagian 2.4).
- Periksa apakah klien itu memang alat administrasi atau pemindai yang dijadwalkan.

Satu kelemahan skrip lama yang terlihat setelah membaca kode Zeek (bagian 1.5): kuncinya memuat `client`, padahal baris TGS yang gagal bisa tanpa `client` (`zeek-cut` menulisnya `-`). Satu penyerang lalu terpecah menjadi dua kunci, dan bila sebagian besar permintaannya gagal, keduanya bisa jatuh di bawah ambang. Kelompokkan per `id.orig_h`.

Saved search `NSM - TGS borongan` di PT JAB (tiap 10 menit, rentang 10 menit) memakai ketiga penguat itu:

```
index=zeek sourcetype=bro:kerberos:json request_type=TGS earliest=-10m@m latest=@m
| lookup ad_spn_inventory.csv spn AS service OUTPUT akun jenis_akun enc_diizinkan
| where jenis_akun="user"
| eval gagal=if(success="false", 1, 0), rc4=if(cipher="rc4-hmac", 1, 0)
| stats dc(service) AS layanan count AS tgs sum(gagal) AS gagal sum(rc4) AS rc4
        values(client) AS akun_peminta BY id.orig_h
| where layanan >= 20
| lookup nsm_admin_sources.csv src AS id.orig_h OUTPUT nama peran
```

| Bagian | Fungsi |
|---|---|
| `lookup ad_spn_inventory.csv ... where jenis_akun="user"` | Jaringan tidak tahu apakah sebuah SPN milik akun komputer atau akun pengguna; ekspor AD yang tahu. SPN akun komputer (`cifs/<host>`, `host/<host>`, `ldap/<dc>`) dibuang karena tidak menjadi sasaran Kerberoasting yang berarti. Setel lookup agar tidak peka huruf besar kecil, karena SPN bisa ditulis campur |
| `eval gagal=..., rc4=...` | Menghitung permintaan yang gagal dan tiket RC4 per klien; `success` dari JSON Zeek terbaca sebagai string `true`/`false` di Splunk-mu, cek dengan satu event contoh |
| `stats ... BY id.orig_h` | Per alamat sumber, bukan per `client`, supaya baris gagal tanpa `client` ikut terhitung |
| `where layanan >= 20` | Ambang program. Dalam 36 hari, jumlah SPN akun pengguna berbeda per workstation per 10 menit maksimal 4; `jkt-vscan01` mencapai 31 pada malam pemindaian berautentikasi dan tetap menyalakan alert dengan peran terlampir |

Keluaran ilustrasi (jendela 09:00 sampai 09:10):

```
id.orig_h     layanan  tgs  gagal  rc4  akun_peminta                    nama  peran
10.10.60.191  49       49   43     6    nadia.puspita/CORP.JAB.EXAMPLE
```

Rincian dari arsip, untuk jendela 02:04:00 sampai 02:05:00 UTC (09:04 WIB):

```bash
jq -r 'select(.request_type == "TGS" and ."id.orig_h" == "10.10.60.191"
              and .ts >= 1813716240 and .ts < 1813716300)
       | [(.ts | floor | todate), (.client // "-"), .service, (.success | tostring),
          (.cipher // "-"), (.error_msg // "-")] | @tsv' kerberos.*.log | sort
```

Keluaran ilustrasi (lima dari 49 baris):

```
2027-06-23T02:04:05Z  -                                svc-backup/jkt-bkp01.corp.jab.example        false  -         KDC_ERR_ETYPE_NOSUPP
2027-06-23T02:04:06Z  -                                HTTP/jkt-intranet02.corp.jab.example         false  -         KDC_ERR_ETYPE_NOSUPP
2027-06-23T02:04:07Z  nadia.puspita/CORP.JAB.EXAMPLE   MSSQLSvc/jkt-sql05.corp.jab.example:1433     true   rc4-hmac  -
2027-06-23T02:04:09Z  nadia.puspita/CORP.JAB.EXAMPLE   HTTP/jkt-docscan01.corp.jab.example          true   rc4-hmac  -
2027-06-23T02:04:46Z  -                                MSSQLSvc/jkt-sql09.corp.jab.example:1433     false  -         KDC_ERR_ETYPE_NOSUPP
```

Ringkasan 49 baris dengan `awk -F'\t' '{print $4, $5, $6}' | sort | uniq -c` pada keluaran yang sama:

```
     43 false - KDC_ERR_ETYPE_NOSUPP
      6 true rc4-hmac -
```

Pembanding di domain controller, dari log Security `jkt-dc01`:

```
index=wineventlog host=jkt-dc01 EventCode=4769 Client_Address="*10.10.60.191"
    earliest="06/23/2027:09:04:00" latest="06/23/2027:09:05:00"
| stats count BY Ticket_Encryption_Type Failure_Code
```

```
Ticket_Encryption_Type  Failure_Code  count
0x17                    0x0           6
```

**Cara membaca hasil:** dalam 41 detik (09:04:05 sampai 09:04:46), `JKT-WS-2091` meminta tiket untuk 49 SPN akun pengguna berbeda. Itu seluruh 49 SPN akun pengguna yang ada di ekspor AD, jadi daftarnya sudah dikumpulkan lebih dulu; pengumpulannya sendiri (biasanya lewat LDAP) tidak terlihat sebagai temuan di log sensor. Enam permintaan berhasil, semuanya `rc4-hmac`, dan keenamnya adalah enam akun RC4 eksplisit di bagian 2.4. Empat puluh tiga gagal dengan `KDC_ERR_ETYPE_NOSUPP`: akun tujuan hanya punya kunci AES, dan klien menawarkan enkripsi yang tidak dimiliki akun itu, sehingga penjelasan yang paling cocok adalah klien hanya menawarkan RC4. Workstation Windows biasa menawarkan AES lebih dulu dan tidak akan gagal seperti ini. Event 4769 di DC hanya menunjukkan enam yang berhasil. Microsoft mencatat bahwa sebagian galat, termasuk galat jenis enkripsi, baru diaudit bila `KdcExtraLogLevel` disetel dengan flag 0x10 [S4]; di PT JAB setelan itu belum ada, jadi 43 percobaan gagal hanya ada di sensor.

Pola ini cocok dengan analitik ATT&CK untuk Kerberoasting: banyak tiket layanan dari satu akun dalam waktu singkat, dengan RC4 [S13]. Penjelasan jinak yang diuji: `10.10.60.191` tidak ada di daftar host administrasi atau pemindai, `nadia.puspita` adalah staf Billing tanpa peran administrasi, dan tidak ada perubahan atau jadwal yang menjelaskan. Yoga menemukan di MDE bahwa koneksi ke port 88 pada menit itu dibuat proses tanpa tanda tangan di folder `AppData` pengguna.

Pertanyaan berikutnya: apakah salah satu dari enam tiket itu dipakai. Pemecahan password berjalan di luar jaringan dan tidak terlihat, tetapi akun yang password-nya berhasil dipecahkan akan muncul sebagai `client` dari tempat yang tidak biasa:

```
index=zeek sourcetype=bro:kerberos:json
    (client="svc-sqlbilling/*" OR client="svc-legacyscan/*" OR client="svc-report01/*"
     OR client="svc-crmold/*" OR client="svc-ivr/*" OR client="svc-faxgw/*")
    earliest="05/18/2027:00:00:00" latest="06/23/2027:12:00:00"
| stats count min(_time) AS pertama max(_time) AS terakhir values(request_type) AS jenis dc(service) AS layanan
        BY client id.orig_h
| convert ctime(pertama) ctime(terakhir)
| sort client - count
```

Keluaran ilustrasi (baris yang relevan):

```
client                            id.orig_h     count  pertama              terakhir             jenis   layanan
svc-sqlbilling/CORP.JAB.EXAMPLE   10.20.8.45    8214   05/18/2027 08:00:41  06/23/2027 10:09:57  AS TGS  4
svc-sqlbilling/CORP.JAB.EXAMPLE   10.10.60.191  5      06/23/2027 09:24:58  06/23/2027 09:33:12  AS TGS  4
svc-legacyscan/CORP.JAB.EXAMPLE   10.20.8.77    868    05/18/2027 08:00:33  06/23/2027 11:00:31  AS      1
svc-legacyscan/CORP.JAB.EXAMPLE   10.10.60.191  1      06/23/2027 09:16:40  06/23/2027 09:16:40  AS      1
```

**Cara membaca hasil:** selama 36 hari `svc-sqlbilling` hanya pernah meminta tiket dari `jkt-sql05` (`10.20.8.45`), host tempat service SQL berjalan. Pukul 09:24:58, dua puluh menit setelah tiket RC4-nya diambil, akun itu melakukan AS dari `10.10.60.191`, lalu meminta tiga tiket layanan: `cifs/JKT-WS-2092`, `cifs/JKT-WS-2093`, dan `cifs/jkt-app11` (lima baris: satu galat praautentikasi yang normal, satu AS berhasil, tiga TGS). Akun layanan yang tiba-tiba dipakai dari workstation, tepat setelah tiketnya diambil, adalah indikator terkuat di seluruh kasus. Jaringan tidak bisa membuktikan password itu didapat dari pemecahan tiket; penjelasan lain (password diambil dari berkas konfigurasi atau memori di host lain) tidak bisa disingkirkan dari sensor. Laporkan sebagai "pengambilan tiket terbukti, pemakaian akun dari workstation terbukti, pemecahan password disimpulkan". `svc-legacyscan` muncul juga dari `10.10.60.191`, dan itu kasus bagian 2.6. Empat akun RC4 lain tidak dipakai dari tempat baru sampai pukul 12:00.

**Variasi:** pada Splunk tanpa lookup AD, ganti `where jenis_akun="user"` dengan `where NOT match(service, "^(krbtgt|cifs|host|ldap|RPCSS|GC|DNS)/")` sebagai perkiraan kasar. Untuk TSV, ganti kunci awk lama menjadi `key=$1" "$2` (ember dan sumber saja).

**Kapan gagal:** pemindai kerentanan dan alat inventaris menghasilkan pola yang hampir identik. Daftarkan keduanya sebagai populasi tersendiri yang dianalisis terpisah, jangan dikecualikan begitu saja: pengecualian permanen berdasarkan IP membuat penyerang yang menguasai host pemindai menjadi tak terlihat. Penyerang yang meminta tiket pelan-pelan (satu per jam) tidak pernah melewati ambang 10 menit; jalankan juga agregasi harian per sumber. Dan bila klien menawarkan AES, tiket AES tetap bisa dipecahkan (lebih lambat), sehingga ketiadaan RC4 tidak berarti tidak ada Kerberoasting.

### 2.6 Permintaan autentikasi awal tanpa praautentikasi: `SOC-2027-0691`

**Tujuan:** menjawab pertanyaan ketiga Dimas dengan dua daftar terpisah: temuan konfigurasi dan temuan aktivitas.

`SOC-2027-0691` dipicu rule di log domain controller (Event 4768 dengan Pre-Authentication Type 0 dari alamat yang belum pernah dipakai akun itu). Perintah dari catatan lama untuk sisi jaringan:

```bash
cat kerberos.log | zeek-cut ts id.orig_h client request_type success error_msg cipher \
  | awk '$4 == "AS"' | sort -k3 | head -40
```

Yang dicari: akun yang permintaan `AS`-nya berhasil tanpa didahului galat yang menandakan prasyarat autentikasi diminta, terutama bila berasal dari alamat yang bukan tempat akun itu biasa dipakai.

Lalu susun dua daftar terpisah:

```
daftar-1: akun yang pola AS-nya menunjukkan tidak ada prasyarat  -> temuan konfigurasi
daftar-2: permintaan AS untuk akun itu dari host tidak lazim     -> temuan aktivitas
```

Pemisahan ini penting saat menulis laporan, karena yang pertama adalah masalah yang perlu diperbaiki sedangkan yang kedua adalah peristiwa yang perlu diinvestigasi, dan keduanya punya pemilik yang berbeda.

Di PT JAB, langkah pertama adalah memastikan bahwa galat praautentikasi memang tercatat (bagian 1.5). Agung sudah mengujinya dengan akun uji pada minggu pertama Zeek hidup: logon biasa di `corp.jab.example` menghasilkan satu baris AS gagal dengan `KDC_ERR_PREAUTH_REQUIRED` lalu satu baris AS berhasil. Tanpa uji itu, langkah berikutnya tidak bisa dipercaya. Semua permintaan AS dari `10.10.60.191` hari itu:

```bash
jq -r 'select(.request_type == "AS" and ."id.orig_h" == "10.10.60.191")
       | [(.success | tostring), (.error_msg // "-")] | @tsv' kerberos.*.log \
  | sort | uniq -c | sort -rn
```

Keluaran ilustrasi:

```
    203 false  KDC_ERR_PREAUTH_REQUIRED
     11 false  KDC_ERR_C_PRINCIPAL_UNKNOWN
      4 true   -
```

Empat AS berhasil adalah akun komputer saat boot (08:44:51), `nadia.puspita` saat logon (08:47:09), `svc-legacyscan` (09:16:40), dan `svc-sqlbilling` (09:24:58). Tiga di antaranya didahului galat praautentikasi pada detik yang sama, seperti logon normal. Yang keempat, `svc-legacyscan`, berasal dari satu rentetan pukul 09:15:58 sampai 09:16:40 ke `jkt-dc02`: 212 nama akun berbeda dalam 42 detik, 200 dijawab `KDC_ERR_PREAUTH_REQUIRED`, 11 `KDC_ERR_C_PRINCIPAL_UNKNOWN` (nama tidak ada), dan satu berhasil tanpa galat. Galat praautentikasi lainnya (3) berasal dari tiga logon normal tadi, sehingga totalnya 203. Itu cara kedua yang disebut ATT&CK untuk menemukan akun tanpa praautentikasi: kirim permintaan untuk setiap pengguna dan lihat mana yang berhasil [S14]. Galat `C_PRINCIPAL_UNKNOWN` untuk 11 nama menunjukkan daftar yang dipakai tidak sepenuhnya cocok dengan direktori PT JAB.

Mencari "berhasil tanpa galat sebelumnya" untuk semua host di folder hari itu, sebagai daftar-1 dari sisi jaringan:

```bash
jq -r 'select(.request_type == "AS")
       | [.ts, ."id.orig_h", .client, (.success | tostring), (.error_msg // "-")] | @tsv' kerberos.*.log \
  | sort -t$'\t' -k3,3 -k1,1n \
  | awk -F'\t' '$5 == "KDC_ERR_PREAUTH_REQUIRED" {pre[$3] = $1; next}
                $4 == "true" && !(($3 in pre) && ($1 - pre[$3] < 5)) {print $2 "\t" $3}' \
  | sort | uniq -c
```

- `sort -t$'\t' -k3,3 -k1,1n` mengurutkan per akun, lalu per waktu.
- Baris galat praautentikasi menyimpan waktunya per akun; baris berhasil yang tidak didahului galat untuk akun yang sama dalam 5 detik dicetak.
- Jeda 5 detik adalah pilihan; logon normal di PT JAB menghasilkan galat dan sukses dalam detik yang sama.

Keluaran ilustrasi:

```
      5 10.20.8.77    svc-legacyscan/CORP.JAB.EXAMPLE
      1 10.10.60.191  svc-legacyscan/CORP.JAB.EXAMPLE
```

Pembanding di domain controller:

```
index=wineventlog EventCode=4768 Pre_Authentication_Type=0
    earliest="06/23/2027:00:00:00" latest="06/23/2027:12:00:00"
| stats count values(Client_Address) AS alamat BY Account_Name
```

```
Account_Name    count  alamat
svc-legacyscan  13     ::ffff:10.20.8.77 ::ffff:10.10.60.191
```

**Cara membaca hasil:** daftar-1 (konfigurasi) berisi satu akun yang aktif tanpa praautentikasi, `svc-legacyscan`, dipakai perangkat pemindai dokumen lama `jkt-docscan01` sejak 2019 karena klien Kerberos perangkat itu tidak mendukung praautentikasi; ekspor AD Agung menambah satu akun nonaktif dengan setelan yang sama, `old.helpdesk01`, yang tidak terlihat di jaringan. Daftar-2 (aktivitas) berisi satu permintaan dari `10.10.60.191`, di tengah rentetan enumerasi 212 nama. Angka Zeek (5 dari appliance) lebih kecil dari angka DC (12 dari appliance ditambah 1) karena folder arsip Zeek dimulai 07:00 WIB (00:00 UTC), sedangkan pencarian Splunk dimulai 00:00 WIB; appliance meminta TGT sekali per jam. Jadi jawaban untuk Dimas: dua-duanya. Ada masalah konfigurasi yang sudah lama (pemiliknya Agung), dan ada aktivitas penyerang yang memanfaatkannya (pemiliknya IR).

Batas yang harus ditulis: `cipher` Zeek di baris AS itu adalah `aes256-cts-hmac-sha1-96`, yaitu enkripsi TGT dengan kunci `krbtgt`, bukan enkripsi bagian balasan yang dipecahkan penyerang (bagian 1.6). Karena `svc-legacyscan` hanya mengizinkan RC4 menurut ekspor AD, bagian balasan itu hampir pasti RC4, tetapi sensor PT JAB tidak bisa memastikannya: Suricata 8.0.7 mencatatnya di field `encryption` event `krb5` [S17], sedangkan `eve-proto.json` program baru memuat flow, dns, http, tls, dan files. Rekomendasinya: tambahkan `krb5` dan `smb` ke `eve-proto.json`, volume keduanya kecil dibanding `flow` dan `dns`.

**Kapan gagal:** nilai `error_msg` dan perilaku galat berbeda antar implementasi dan antar versi. Verifikasi perilakunya di lab-mu dengan akun uji sebelum memakai pola ini pada data nyata. Bila KDC mengirim teks galat yang cocok dengan `KRB::ignored_errors`, galat praautentikasi tidak tercatat dan setiap logon normal akan terlihat seperti "berhasil tanpa galat" [S2]. Dan permintaan dari klien MIT Kerberos (Linux, perangkat) kadang memang tidak mengirim praautentikasi di percobaan pertama; menurut Microsoft, galat 0x19 sering muncul di skenario interoperabilitas UNIX dan biasanya bisa diabaikan bila klien melanjutkan dengan praautentikasi [S11].

### 2.7 Yang tidak terlihat: `JKT-WS-2093`, dan jawaban untuk Bambang

**Tujuan:** menjawab pertanyaan pertama dan keenam Dimas: membuktikan bahwa ketiadaan baris `JKT-WS-2091` ke `JKT-WS-2093` adalah blind spot, menemukan jejak yang tetap ada, dan menilai usul SPAN tambahan.

`SOC-2027-0694` datang dari MDE, bukan dari sensor. Temuan Yoga di sisi host: di `JKT-WS-2093`, logon jaringan (4624 tipe 3) akun `svc-sqlbilling` dari `10.10.60.191` pukul 09:26:41, lalu service baru (7045) yang menjalankan `C:\Windows\Temp\bsvc64.exe` pukul 09:27:02, dengan hash yang sama dengan berkas di `jkt-app11`. Di `JKT-WS-2092`, logon jaringan akun yang sama pukul 09:25:04 dan enumerasi share, tanpa service.

Pertama, pastikan memang tidak ada apa pun di sensor:

```
index=zeek "id.orig_h"="10.10.60.191" ("id.resp_h"="10.10.60.192" OR "id.resp_h"="10.10.60.193")
    earliest="06/23/2027:08:00:00" latest="06/23/2027:11:00:00"
| stats count BY sourcetype
```

Keluaran ilustrasi: tidak ada hasil. Hasil kosong ini hanya bermakna bila sensor sehat pada jam itu; `capture_loss` dan saved search `JAB-ZEEK-HEALTH-01` (Day 08 bagian 2.11) tidak mencatat celah antara 08:00 dan 11:00, jadi kekosongannya adalah posisi sensor, bukan kerusakan sensor.

Kedua, cari saksinya di domain controller:

```
index=zeek sourcetype=bro:kerberos:json request_type=TGS service="cifs/JKT-WS-*"
    earliest="05/18/2027:00:00:00" latest="06/23/2027:11:00:00"
| stats count dc(service) AS tujuan values(client) AS akun min(_time) AS pertama max(_time) AS terakhir BY id.orig_h
| lookup nsm_admin_sources.csv src AS id.orig_h OUTPUT nama peran
| convert ctime(pertama) ctime(terakhir)
| sort - count
```

Keluaran ilustrasi:

```
id.orig_h     count  tujuan  akun                              pertama              terakhir             nama         peran
10.20.10.61   9840   1166    svc-vscan/CORP.JAB.EXAMPLE        05/18/2027 22:00:07  06/22/2027 23:40:52  jkt-vscan01  pemindai kerentanan
10.20.8.30    2213   1104    svc-mecm-push/CORP.JAB.EXAMPLE    05/18/2027 10:05:40  06/22/2027 14:22:19  jkt-mecm01   distribusi perangkat lunak
10.20.8.20    96     58      (4 akun adm.*)                    05/19/2027 09:01:12  06/22/2027 16:29:47  jkt-pam01    jump host administrasi
10.10.60.191  2      2       svc-sqlbilling/CORP.JAB.EXAMPLE   06/23/2027 09:25:03  06/23/2027 09:26:40
```

**Cara membaca hasil:** dalam 36 hari, tiket untuk share workstation hanya diminta dari tiga server administrasi. Rabu pagi, untuk pertama kalinya, sebuah workstation meminta tiket `cifs` untuk dua workstation lain, memakai akun layanan SQL, satu detik dan dua puluh satu detik sebelum logon jaringan yang dicatat MDE di masing-masing host. Itulah satu-satunya jejak gerakan antar workstation yang ada di sensor, dan bentuknya cukup bersih untuk dijadikan saved search baru: `NSM - TGS cifs antar workstation`, menyala bila sumber tiket `cifs/JKT-WS-*` atau `host/JKT-WS-*` adalah alamat di `10.10.0.0/16`. Batasnya tetap seperti bagian 1.2: NTLM, akun lokal, dan tiket yang sudah tersimpan di klien tidak menghasilkan baris baru.

Scoping dari saksi ini: akun `svc-sqlbilling` dan alamat `10.10.60.191` tidak meminta tiket untuk workstation atau server lain selain `JKT-WS-2092`, `JKT-WS-2093`, dan `jkt-app11` sampai pukul 12:00. Itu tidak menutup kemungkinan gerakan dengan NTLM atau akun lokal; untuk itu Yoga menjalankan pencarian logon tipe 3 dari `10.10.60.191` di MDE untuk seluruh workstation.

Usul Bambang, dinilai dengan sumber yang ada. Tabel ini dipakai untuk memilih, bukan untuk membandingkan harga; cari kolom "menutup apa".

| Opsi | Menutup apa | Biaya dan batas |
|---|---|---|
| SPAN atau RSPAN switch akses lantai Billing ke `jkt-npb01` | Semua trafik antar host di lantai itu, termasuk NTLM dan akun lokal | Hanya satu lantai dari puluhan switch akses; uplink ke packet broker dan kapasitas `jkt-npb01` harus dihitung; SPAN bisa men-drop saat switch sibuk; trafik antar karyawan (printer, berbagi berkas) ikut terekam sehingga kebijakan akses pcap dan DPO harus dilibatkan; tidak bisa melihat mundur ke 09:26 |
| Saved search TGS `cifs`/`host` antar workstation (sensor yang ada) | Gerakan antar workstation yang memakai Kerberos | Tanpa biaya; buta terhadap NTLM, akun lokal, dan tiket yang dipakai ulang |
| MDE dan log host (4624 tipe 3, 7045) | Semua logon dan eksekusi di host ber-MDE | Sudah ada; host tanpa MDE buta |
| Windows Firewall lewat GPO: tolak SMB masuk ke workstation kecuali dari `jkt-pam01`, `jkt-mecm01`, `jkt-vscan01` | Mencegah jalur itu, bukan hanya melihatnya | Perlu uji aplikasi yang memakai berbagi berkas antar workstation; pengecualian dirawat seperti `nsm_admin_sources.csv` |

Rekomendasi yang dikirim ke Bambang: tidak memasang SPAN permanen di switch akses. Jalur workstation ke workstation lebih murah ditutup daripada diawasi, lewat aturan Windows Firewall di GPO, dan sisa celahnya diawasi dengan saved search TGS dan MDE. SPAN sementara di lantai Billing bisa dipasang selama IR bila tim IR ingin melihat apakah ada aktivitas lanjutan, dengan persetujuan sesuai kebijakan akses pcap.

**Kapan gagal:** hasil kosong di pencarian pertama dibaca sebagai "tidak terjadi" tanpa memeriksa posisi sensor dan kesehatannya; atau akun penyerang memakai NTLM ke alamat IP, sehingga pencarian kedua juga kosong walaupun gerakan terjadi.

### 2.8 Rantai lateral movement, label ATT&CK, dan jawaban untuk Dimas

**Tujuan:** menyusun rantai `INC-2027-078` dari semua sumber, memberi label ATT&CK dengan status bukti, dan menulis ringkasan untuk rapat pukul 14:00.

Bentuk akhir dari catatan lama (lab), sebagai pola tabel:

| Waktu | Sumber | Tujuan | Bukti | Arti |
|---|---|---|---|---|
| 03:02:11 | 10.20.0.77 | DC1 | `kerberos.log`: TGS untuk `cifs/WS-033` | Meminta tiket untuk akses berkas ke WS-033 |
| 03:02:58 | 10.20.0.77 | WS-033 | `smb_mapping.log`: `\\WS-033\ADMIN$` DISK | Memetakan share administratif |
| 03:03:00 | 10.20.0.77 | WS-033 | `smb_files.log`: FILE_WRITE berkas eksekusi | Menaruh berkas |
| 03:03:12 | 10.20.0.77 | WS-033 | `smb_mapping.log`: `\\WS-033\IPC$` PIPE | Memanggil layanan jarak jauh |
| 03:03:20 | WS-033 | (endpoint) | di luar wilayah jaringan | Eksekusi, dijawab log endpoint |

Baris terakhir sengaja menyebut dirinya di luar wilayah. Jaringan bisa membuktikan urutan sampai langkah keempat; langkah kelima harus datang dari endpoint, dan laporan yang baik menyatakan itu alih-alih menyamarkannya.

Timeline `INC-2027-078` (WIB, Rabu 2027-06-23 kecuali disebut lain):

| Waktu | Kejadian | Bukti |
|---|---|---|
| Selasa 16:41 | `JKT-WS-2091` mulai membuka tunnel lewat proxy ke `cdn.ledgerbox.example` (`203.0.113.196`) dengan jeda teratur; ditemukan Sari saat scoping pukul 10:30 dan diserahkan ke IR | Zeek hop core `http.log` (`CONNECT`), log proxy |
| 08:47:09 | Logon `nadia.puspita` di `JKT-WS-2091` | `kerberos.log` AS, 4768 |
| 09:04:05 sampai 09:04:46 | TGS untuk 49 SPN akun pengguna; 6 tiket RC4 keluar, 43 gagal `KDC_ERR_ETYPE_NOSUPP` | `kerberos.log`; 4769 hanya 6 yang berhasil |
| 09:13 | `SOC-2027-0690` | Splunk |
| 09:15:58 sampai 09:16:40 | AS untuk 212 nama ke `jkt-dc02`; `svc-legacyscan` berhasil tanpa praautentikasi | `kerberos.log`, 4768 tipe praautentikasi 0 |
| 09:22 | `SOC-2027-0691` | Splunk (rule log DC) |
| 09:24:58 | `svc-sqlbilling` AS dari `10.10.60.191`, pertama kali dari luar `jkt-sql05` dalam 36 hari | `kerberos.log` |
| 09:25:03 dan 09:25:04 | TGS `cifs/JKT-WS-2092`; logon jaringan di `JKT-WS-2092` | `kerberos.log`; MDE |
| 09:26:40 sampai 09:27:02 | TGS `cifs/JKT-WS-2093`; logon jaringan; service `bsvc64.exe` dipasang | `kerberos.log`; MDE (4624 tipe 3, 7045) |
| 09:33:12 | TGS `cifs/jkt-app11` | `kerberos.log` |
| 09:33:13 | `ADMIN$` dipetakan, `Temp\bsvc64.exe` 286.720 byte ditulis | `smb_mapping.log`, `smb_files.log`, `files.log` (`is_orig` true, SHA-256) |
| 09:33:15 sampai 09:33:21 | `svcctl`: `OpenSCManagerW`, `CreateServiceW`, `StartServiceW`, `DeleteService` | `dce_rpc.log`; 7045 di `jkt-app11` (MDE) |
| 09:33:31, 09:34:31, 09:35:31 | `jkt-app11` SYN ke `203.0.113.197:443`, ditolak `jkt-fw01` | Zeek egress `conn.log` (`REJ`), log firewall |
| 09:41 | `SOC-2027-0692` | Splunk |
| 09:47:12 sampai 10:14:40 | Push agent MECM ke 63 server (`CHG-2027-0461`); `SOC-2027-0693` pukul 10:02, ditutup jinak 10:25 | Bagian 2.3 |
| 09:50 | Dimas membuka `INC-2027-078` | Tiket |
| 09:58 | `JKT-WS-2091` diisolasi lewat MDE | MDE |
| 10:04 | `jkt-app11` diisolasi | MDE |
| 10:10 | `svc-sqlbilling` dinonaktifkan dan password-nya direset oleh Agung; aplikasi Billing lama di `jkt-app07` terganggu sampai 10:45 | Change log |
| 10:20 | `SOC-2027-0694` (MDE, `JKT-WS-2093`) | MDE |
| 10:31 | `JKT-WS-2093` diisolasi | MDE |

Suricata `jkt-ids01` tidak mengeluarkan alert untuk rangkaian ini; seluruh deteksi jaringan datang dari log Zeek dan saved search.

Label ATT&CK untuk laporan:

| Teknik | Status | Dasar |
|---|---|---|
| T1558.003 Kerberoasting | Pengambilan tiket didukung data jaringan; pemecahan disimpulkan | 49 TGS dalam 41 detik, 6 RC4; `svc-sqlbilling` dipakai 20 menit kemudian |
| T1558.004 AS-REP Roasting | Didukung data jaringan dan log DC | Enumerasi 212 nama; `svc-legacyscan` tanpa praautentikasi |
| T1078 Valid Accounts | Didukung data jaringan | `svc-sqlbilling` dari workstation, first-seen dalam 36 hari |
| T1021.002 SMB/Windows Admin Shares | Didukung data jaringan untuk `jkt-app11`; didukung host untuk `JKT-WS-2092` dan `JKT-WS-2093` | `smb_mapping`, `smb_files`, `files`; MDE |
| T1569.002 Service Execution | Didukung data jaringan (operasi) dan host (biner) | `dce_rpc.log` `svcctl`; 7045 |
| Percobaan koneksi keluar dari `jkt-app11` | Percobaan gagal, tanpa data | 3 `REJ` ke `203.0.113.197:443` |
| Akses awal dan kanal ke `203.0.113.196` | Diserahkan ke IR | Di luar Day ini (metode Day 11) |

Ringkasan yang dibawa Dimas:

```
INC-2027-078  Ringkasan lateral movement dari data jaringan (Rabu 2027-06-23 13:30 WIB)
Host awal     : JKT-WS-2091 (10.10.60.191), sesi nadia.puspita (Billing)
Kerberos      : 09:04 tiket layanan untuk 49 akun berSPN diminta; 6 keluar dengan RC4
                (akun RC4 eksplisit), 43 ditolak DC; 09:16 enumerasi 212 nama, svc-legacyscan
                tanpa praautentikasi
Akun dipakai  : svc-sqlbilling dari 10.10.60.191 sejak 09:24:58 (36 hari sebelumnya hanya dari jkt-sql05)
Bergerak ke   : jkt-app11 (terlihat lengkap: ADMIN$, bsvc64.exe 286.720 byte, svcctl buat/jalankan/hapus)
                JKT-WS-2092, JKT-WS-2093 (TIDAK lewat sensor; hanya tiket cifs di DC + MDE)
Keluar        : jkt-app11 mencoba 203.0.113.197:443 tiga kali, semua ditolak firewall, 0 byte
Keyakinan     : tinggi untuk urutan, akun, host, dan waktu; isi bsvc64.exe dan perintah lain = IR
Belum diketahui: akses awal, isi biner, gerakan dengan NTLM atau akun lokal di luar sensor,
                apakah akun RC4 lain sudah dipecahkan
Tindakan      : reset 6 akun RC4 + svc-legacyscan; RC4 eksplisit ditinjau Agung; tolak SMB masuk
                antar workstation lewat GPO; saved search TGS cifs antar workstation; krb5 dan
                smb ke eve-proto; KdcExtraLogLevel 0x10 di DC dipertimbangkan
Data          : /cases/INC-2027-078/ (log Zeek + sha256, ekspor 4768/4769, log firewall)
```

Ringkasan jawaban untuk delapan pertanyaan Dimas:

| Pertanyaan | Jawaban singkat | Bagian |
|---|---|---|
| Sampai mana gerakan terlihat | Ke server dan DC lengkap; antar workstation tidak lewat sensor, hanya tiket `cifs` di DC | 1.2, 2.7 |
| 0690 Kerberoasting? Akun RC4 mana? | Ya, pengambilan tiket terbukti; 6 akun RC4 eksplisit; RC4 dibatasi, bukan dimatikan | 1.5, 1.6, 1.7, 2.4, 2.5 |
| 0691 konfigurasi atau serangan | Keduanya: akun tanpa praautentikasi (Agung) dan permintaan dari workstation (IR) | 1.7, 2.6 |
| 0692 vs 0693 | Sumber, pasangan, akun, dan perubahan cocok untuk MECM; keempatnya menyimpang untuk 2091 | 1.1, 1.3, 2.1, 2.2, 2.3 |
| Apa yang dijalankan di `jkt-app11` | Berkas 286.720 byte (hash) sebagai service sementara; isi dan argumen dari host | 1.4, 2.3 |
| SPAN switch akses | Tidak permanen; tutup jalurnya lewat GPO, awasi sisanya dengan TGS dan MDE | 1.2, 2.7 |
| Enkripsi SMB `jkt-fs02` | Nama berkas dan operasi hilang, koneksi dan autentikasi tersisa; ganti dengan audit di server | 1.8 |
| Rantai dan ATT&CK | Timeline dan tabel label di atas | 1.9, 2.8 |

**Kapan gagal:** timeline yang mencampur jam UTC dari arsip Zeek dengan jam WIB dari Splunk dan MDE tanpa konversi; label ATT&CK yang ditulis tanpa status bukti; dan baris antar workstation yang ditulis seolah-olah dilihat sensor.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** lab domain kecil dengan pengendali domain dan dua workstation di jaringan host-only yang terisolasi (misalnya `192.168.56.0/24`: DC `192.168.56.10`, workstation `192.168.56.21` dan `192.168.56.22`), dengan snapshot sebelum lab, VM sensor Zeek (Day 08) yang melihat ketiganya lewat port mirror hypervisor, Wireshark 4.6.x, dan akun uji yang kamu kendalikan. Tidak ada alat serangan yang perlu dipasang: semua langkah memakai fitur Windows bawaan (`net use`, `copy`, `sc.exe`, `klist`) dan pengaturan akun di Active Directory Users and Computers.

1. Bangun baseline selama beberapa hari: pasangan host yang saling menghubungi lewat SMB, share yang dipetakan, dan distribusi `cipher` Kerberos per layanan. Simpan sebagai berkas acuan.
2. Lakukan administrasi yang sah, misalnya menyalin berkas ke share administratif dari host administrasi, lalu temukan jejaknya di `smb_mapping.log` dan `smb_files.log`.
3. Ulangi langkah 2 dari host yang bukan host administrasi, lalu bandingkan bagaimana keduanya terlihat berbeda hanya dari baseline, bukan dari isi.
4. Petakan `IPC$` dan panggil satu layanan jarak jauh yang sah (misalnya `sc.exe \\<host> query`), lalu catat apa yang terlihat di log dan apa yang tidak.
5. Buat satu akun layanan uji, minta tiket untuknya secara normal (`klist get <SPN>`), lalu periksa nilai `cipher` yang dihasilkan dan bandingkan dengan daftar resmi [S3].
6. Ubah konfigurasi akun uji agar memakai jenis enkripsi lama, ulangi permintaan tiket, dan buktikan perubahannya terlihat di `kerberos.log`. Bila DC lab sudah menerima pembaruan Januari 2026 atau sesudahnya, catat juga event KDCSVC di log System DC [S12].
7. Hasilkan permintaan tiket untuk banyak layanan berbeda dalam waktu singkat memakai akun uji (buat sepuluh SPN uji pada beberapa akun uji, lalu jalankan `klist get` berurutan), lalu jalankan skrip bagian 2.5 dan sesuaikan ambangnya dengan baseline-mu. Bandingkan kunci per `client` dan per `id.orig_h`.
8. Buat satu akun uji tanpa prasyarat autentikasi, amati bagaimana permintaan `AS`-nya terlihat berbeda, lalu kembalikan konfigurasinya. Catat apakah galat praautentikasi untuk akun biasa muncul di `kerberos.log` sebagai `KDC_ERR_PREAUTH_REQUIRED` di versi Zeek dan DC-mu (bagian 1.5).
9. Aktifkan enkripsi SMB pada satu share, ulangi langkah 2, lalu tulis daftar apa yang masih terlihat dan apa yang hilang. Lakukan dua kali: enkripsi per share, lalu enkripsi untuk seluruh server, dan catat apakah `smb_mapping.log` masih memuat nama share di masing-masing.
10. Susun tabel rantai seperti bagian 2.8 dari salah satu percobaanmu, lengkap dengan baris yang menyatakan batas wilayah jaringan.
11. Buat dan jalankan service sementara di workstation kedua dari workstation pertama (`sc.exe \\<host> create`, `start`, `delete`) dengan biner uji yang tidak berbahaya, lalu baca `dce_rpc.log`: urutan `operation`, nilai `named_pipe`, dan apakah nama service muncul di mana pun.
12. Ulangi langkah 7 sambil menangkap paket di VM sensor, lalu buka pcap di Wireshark dengan filter `kerberos.msg_type == 12 || kerberos.msg_type == 13 || kerberos.msg_type == 30` (TGS-REQ, TGS-REP, KRB-ERROR) dan kolom `kerberos.SNameString`, `kerberos.etype`, `kerberos.error_code`. Bandingkan etype yang ditawarkan klien di permintaan dengan `cipher` di `kerberos.log`.

**Hasil yang sebaiknya tersimpan:**

- Berkas baseline: pasangan host SMB, share yang dipetakan, distribusi `cipher` per layanan.
- Perbandingan jejak penyalinan berkas dari host administrasi dan dari host biasa.
- Catatan apa yang terlihat dan tidak terlihat saat memanggil layanan lewat `IPC$`.
- Nilai `cipher` sebelum dan sesudah konfigurasi akun diubah, beserta event KDCSVC bila ada.
- Hasil skrip permintaan tiket borongan beserta ambang yang kamu pilih dari baseline, dan perbedaan hasil antara kunci per `client` dan per `id.orig_h`.
- Catatan bagaimana permintaan `AS` tanpa prasyarat terlihat berbeda, dan apakah galat praautentikasi tercatat di versi-mu.
- Daftar apa yang hilang setelah enkripsi SMB diaktifkan, untuk enkripsi per share dan per server.
- Tabel rantai lateral movement dengan batas wilayah yang dinyatakan.
- Urutan operasi `svcctl` untuk service sementara dan catatan nilai `named_pipe`.
- Tangkapan Wireshark yang menunjukkan etype yang ditawarkan klien dan etype tiket yang dikeluarkan.

## 4. Troubleshooting

Tabel ini dibaca dari kolom gejala; sebagian besar baris berasal dari batas log yang disebut dokumentasi Zeek, bukan dari kerusakan sensor.

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| `smb_files.log` kosong padahal ada transfer | Enkripsi SMB aktif, atau Zeek tidak melihat seluruh sesi | Periksa `smb_mapping.log` dan `conn.log`; periksa titik tap dan `capture_loss` |
| Arah transfer tidak jelas | `smb_files.log` memang tidak menunjukkan arah [S1] | Ambil arah dari `files.log` (`is_orig`) |
| Operasi DCE-RPC tidak terlihat | Sebagian isi DCE-RPC terenkripsi [S1] | Catat pemakaian pipe-nya; lanjutkan ke endpoint |
| Operasi `winreg` tidak ada di `dce_rpc.log` | Masuk `DCE_RPC::ignored_operations` bawaan [S9] | Cari pembukaan pipe `winreg` di `smb_files.log`; ubah daftar abaikan di lab bila perlu |
| `named_pipe` berisi angka | Diambil dari `sec_addr`, bisa berupa port [S9] | Pakai `endpoint` dan `operation`; cocokkan `uid` dengan log SMB |
| Layanan penjadwalan muncul sebagai berkas | Zeek memperlakukan sebagian layanan sebagai berkas [S1] | Wajar; jangan cari berkas yang tidak ada |
| Tidak ada notice untuk perilaku mencurigakan | Skrip pemetaan perilaku tidak terpasang [S1][S6] | Pasang BZAR di lab, atau pakai saved search bagian 2.3 |
| Semua tiket memakai jenis enkripsi lama | Memang konfigurasi domainnya begitu, atau DC belum menerima pembaruan 2026 | Baseline dulu; penyimpangan dari baseline yang dicari, bukan dari ideal |
| `cipher` kosong di sebagian baris | Field bersifat opsional di skema Zeek [S2]; baris gagal tidak punya tiket | Jangan asumsikan hilangnya field berarti anomali |
| Baris TGS gagal tanpa `client` | Zeek mengisi `client` TGS dari balasan yang berhasil [S2] | Kelompokkan per `id.orig_h` |
| Pola permintaan tiket borongan dari satu host rutin | Pemindai atau alat inventaris terjadwal | Jadikan populasi tersendiri, jangan dikecualikan |
| Pola `AS` tidak seperti di catatan ini | Perilaku galat berbeda antar implementasi dan versi; teks galat cocok dengan `KRB::ignored_errors` [S2] | Uji dengan akun uji di lab sebelum memakai pada data nyata |
| Zeek menunjukkan banyak TGS gagal, Event 4769 tidak | Galat jenis enkripsi baru diaudit dengan `KdcExtraLogLevel` 0x10 [S4] | Pakai sensor sebagai sumber; pertimbangkan setelan itu di DC |
| Event 4769 menunjukkan klien `::1` | Permintaan lokal di DC sendiri [S4] | Periksa siapa yang logon ke DC |
| Pencarian Splunk untuk log SMB atau Kerberos kosong | Sourcetype tidak sesuai pola yang dipakai | `\| metadata type=sourcetypes index=zeek` (Day 08 bagian 1.9) |
| Lookup SPN tidak cocok | Huruf besar kecil SPN berbeda | Setel lookup agar tidak peka huruf besar kecil |
| Jam di timeline tidak cocok | Arsip Zeek UTC, Splunk dan MDE WIB | Konversi sebelum menyusun timeline (bagian 2.8) |

## 5. Kesalahan umum dan jebakan

- Memakai keberadaan `ADMIN$` atau `IPC$` sebagai temuan, padahal keduanya dipakai administrasi sah setiap hari.
- Menganalisis SMB dan Kerberos tanpa baseline pasangan host lebih dulu.
- Menyimpulkan arah transfer dari `smb_files.log`, yang memang tidak memuatnya [S1].
- Mengharapkan rincian operasi DCE-RPC yang isinya terenkripsi [S1].
- Memakai daftar jenis enkripsi ideal sebagai acuan, bukan baseline domain sendiri.
- Menyimpulkan penyalahgunaan dari satu permintaan tiket dengan jenis enkripsi lama.
- Mengecualikan pemindai dan alat administrasi, sehingga penyalahgunaan identitas keduanya menjadi tak terlihat.
- Mencampur temuan konfigurasi dan temuan aktivitas dalam satu baris laporan.
- Menjanjikan jaringan bisa menjawab apa yang dieksekusi di host tujuan.
- Memakai pola galat Kerberos dari catatan orang lain tanpa menguji perilakunya di lingkungan sendiri.
- **Membaca hasil kosong sebagai "tidak terjadi".** Antar workstation di kantor tidak lewat sensor; kosong berarti tidak terlihat, dan kesehatan sensor pada jam itu harus dicek dulu.
- **Mengira RC4 sudah hilang karena pembaruan Microsoft.** RC4 dibatasi ke akun dengan konfigurasi eksplisit, dan justru akun itulah sasaran utama.
- **Membaca `cipher` baris AS sebagai enkripsi yang dipecahkan pada AS-REP Roasting.** Itu enkripsi TGT; bagian balasan dibaca dari Suricata `krb5` `encryption` atau Wireshark.
- **Mengelompokkan per `client` saja.** Baris TGS gagal bisa tanpa `client`, sehingga penyerang terpecah dan bisa lolos ambang.
- **Menganggap SMB signing menyembunyikan isi.** Signing hanya integritas; yang menyembunyikan adalah enkripsi.
- **Menutup alert host administrasi hanya karena sumbernya terdaftar.** Sumber terdaftar adalah satu sumbu dari empat; akun, tujuan, dan jadwal tetap dicek.
- **Menganggap 43 TGS gagal tidak penting.** Galat jenis enkripsi dari satu klien ke banyak SPN adalah tanda klien yang hanya menawarkan RC4, dan sering hanya terlihat di sensor.

## 6. Catatan terkini

Bagian ini menampung status versi dan perubahan yang perlu diingat saat membaca materi SMB, Kerberos, dan lateral movement per Oktober 2026.

- Daftar resmi jenis enkripsi Kerberos menandai rc4-hmac dan seluruh varian DES serta 3DES sebagai deprecated, sementara varian AES berstatus standar [S3]. Daftar ini stabil (terakhir diperbarui 6 Desember 2024) dan bisa dipakai sebagai acuan jangka panjang, berbeda dari ambang deteksi yang harus sering disetel ulang.
- Microsoft KB5073381 (CVE-2026-20833) mengubah nilai bawaan `DefaultDomainSupportedEncTypes` menjadi AES-SHA1 saja untuk akun tanpa konfigurasi eksplisit mulai pembaruan April 2026, dan menghapus opsi rollback `RC4DefaultDisablementPhase` pada fase Juli 2026; event KDCSVC 201 sampai 209 ditambahkan sejak Januari 2026 [S12]. Halaman KB tidak konsisten soal kapan enforcement otomatis; cek event di DC-mu.
- Sejak pembaruan keamanan 14 Januari 2025, Event 4768 dan 4769 di Windows Server 2016 ke atas memakai format baru dengan field enkripsi yang didukung akun, kunci tersedia, etype yang ditawarkan klien, dan hash tiket [S4][S11].
- Windows 11 24H2 dan Windows Server 2025 mewajibkan SMB signing secara bawaan, menambah opsi klien untuk mewajibkan enkripsi (tidak bawaan), opsi memblokir NTLM untuk SMB keluar, dan SMB over QUIC di semua edisi Windows Server 2025 [S19].
- Zeek menyediakan `request_type` dengan tiga nilai, yaitu `AS`, `TGS`, dan `AP` [S2]. Nilai ketiga sering diabaikan padahal berguna untuk melihat pemakaian tiket, bukan hanya penerbitannya. Rilis LTS terbaru per 29 Oktober 2026 adalah Zeek 9.0.1 (26 Oktober 2026), dengan 8.0.11 sebagai LTS sebelumnya [S21].
- Dokumentasi Zeek menyebut terus terang bahwa entri SMB tidak mengungkap maksud dan bahwa isi DCE-RPC terenkripsi [S1]. Kejujuran itu layak ditiru di laporanmu: sebutkan apa yang protokol memang tidak sediakan.
- Suricata 8.0.7 mencatat `encryption` dan `ticket_encryption` secara terpisah di event `krb5`, beserta penanda `weak_encryption` dan `ticket_weak_encryption` [S17].
- ATT&CK v20.0: T1558.003 versi 1.3 dan T1558.004 versi 1.2 (keduanya diubah 24 Oktober 2025), T1021.002 versi 1.3 (12 Mei 2026), T1569.002 versi 1.3 (11 September 2026), dengan strategi deteksi DET0157, DET0113, DET0530, dan DET0421 [S13][S14][S15][S16].
- BZAR masih menjadi rujukan pemetaan SMB dan DCE-RPC ke ATT&CK, tetapi README-nya menyebut mutakhir per 10/09/2020 dan sebagian besar endpoint DCE-RPC tambahannya sudah masuk Zeek mainline sejak 2020 [S6]. Uji di lab sebelum dipasang di sensor produksi.
- Peristiwa permintaan tiket layanan juga tercatat di log Security pengendali domain [S4]. Korelasi jaringan dan pengendali domain membuat kesimpulan jauh lebih kuat, dan ketiadaan salah satunya adalah celah yang layak disebut di rekomendasi.
- Dengan enkripsi SMB, analisis bergeser ke metadata, seperti yang terjadi pada TLS di Day 15 dan QUIC di Day 16. Pola ini berulang di seluruh topik, dan keterampilan yang bertahan adalah menyimpulkan dari metadata sambil menyatakan batasnya.

## 7. Cheat sheet

```
POSISI    SPAN core DC: WS -> server/DC terlihat ; WS -> WS (switch akses / lantai) = BLIND SPOT
          saksi WS -> WS = TGS cifs/<ws> atau host/<ws> di DC (kerberos.log, 4769)
          saksi buta untuk: NTLM, akun lokal, tiket yang dipakai ulang

SMB DI ZEEK
  smb_mapping.log  path (UNC share) + share_type: DISK (termasuk ADMIN$, C$) | PIPE (IPC$)
                   ADMIN$ / IPC$ mencurigakan BILA TIDAK DIOTORISASI (bukan karena ada-nya)
  smb_files.log    action (FILE_OPEN/WRITE/DELETE) + path (share) + name (berkas) + size
  dce_rpc.log      named_pipe (dari sec_addr, bisa port) + endpoint (svcctl, atsvc, samr...) + operation
  files.log        arah = is_orig (T: originator mengirim) ; mime_type ; sha256 (hash-all-files)
  BATAS: smb_files tidak menunjukkan ARAH (pakai files.log is_orig)
         sebagian layanan non-berkas muncul SEBAGAI berkas (mis. layanan penjadwalan)
         isi DCE-RPC TERENKRIPSI -> nama operasi saja, tanpa argumen
         winreg baca + sebagian spoolss/wkssvc DIABAIKAN bawaan (ignored_operations)
         entri TIDAK mengungkap MAKSUD -> jawabannya di endpoint
         tanpa skrip pemetaan perilaku (BZAR), notice tidak muncul
  SIGNING  wajib bawaan Win11 24H2/WS2025 ; integritas saja, isi tetap terbaca

POLA SMB  tulis berkas eksekusi ke ADMIN$ lalu IPC$ svcctl ke host yang sama = taruh lalu jalankan
          OpenSCManagerW -> CreateServiceW -> StartServiceW -> DeleteService = service SEMENTARA
          1 host -> ADMIN$ di BANYAK host dengan koneksi SEDIKIT = penyebaran
          pembanding wajib: daftar host administrasi + jadwal + akun + tiket perubahan (4 sumbu)

KERBEROS DI ZEEK
  request_type: AS (autentikasi awal) | TGS (tiket layanan) | AP (pemakaian tiket)
  client, service, success, error_msg, from, till, cipher, forwardable, renewable
  client TGS diisi dari balasan SUKSES -> baris gagal bisa tanpa client -> kelompokkan per id.orig_h
  cipher = enkripsi TIKET (TGS: kunci akun layanan ; AS: kunci krbtgt, BUKAN bagian AS-REP)
  KRB::ignored_errors (NEEDED_PREAUTH ...) cocok ke TEKS galat -> uji di lab
  sumbu utama: client + service (first-seen) ; client + id.orig_h (akun layanan dari workstation)

ETYPE (daftar IANA ; Windows hex)
  17 aes128-cts-hmac-sha1-96 (0x11)   18 aes256-cts-hmac-sha1-96 (0x12)   standar
  19 aes128-cts-hmac-sha256   20 aes256-cts-hmac-sha384               standar
  23 rc4-hmac (0x17)          DEPRECATED
  1/3/16 dsb varian DES/3DES  DEPRECATED
  KB5073381: akun tanpa msDS-SET eksplisit = AES saja ; RC4 eksplisit tetap -> DAFTAR SASARAN
  KDCSVC 201-209 di log System DC ; 4769 galat etype perlu KdcExtraLogLevel 0x10
  -> bandingkan dengan BASELINE DOMAIN SENDIRI, bukan dengan daftar ideal

POLA KRB  TGS borongan: banyak service BERBEDA dari 1 sumber dalam jendela pendek
                        + etype menyimpang dari baseline = sinyal menguat
                        + banyak KDC_ERR_ETYPE_NOSUPP = klien hanya menawarkan RC4
                        TAPI pemindai & alat inventaris berpola sama -> populasi tersendiri
          AS tanpa prasyarat: pisahkan jadi DUA temuan
                        daftar-1 akun berkonfigurasi demikian  = temuan KONFIGURASI
                        daftar-2 permintaan dari host tak lazim = temuan AKTIVITAS
                        DC: 4768 Pre-Authentication Type 0 ; Suricata krb5 encryption/weak_encryption

ENKRIPSI SMB   hilang: isi berkas, nama berkas, operasi, dce_rpc ; share bila enkripsi per sesi
               tersisa: siapa ke siapa, kapan, berapa ; SESSION_SETUP (tiket cifs/<host>, ntlm.log)
               penanda: TRANSFORM_HEADER 0xFD 'S' 'M' 'B' ; smb2.header.transform.flags.encrypted
               pengganti untuk "berkas apa": audit akses di server + artefak endpoint

RANTAI    TGS cifs/<target> -> map ADMIN$ -> FILE_WRITE -> map IPC$ -> svcctl -> [EKSEKUSI = wilayah ENDPOINT]
          selalu tulis baris terakhir sebagai di luar wilayah jaringan
ATT&CK    T1558.003 | T1558.004 | T1078 | T1021.002 | T1569.002 ; tulis STATUS bukti per label
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** MDE mencatat service baru di `JKT-WS-2093` yang dipasang lewat logon jaringan dari `JKT-WS-2091`. Rekan L1 memeriksa index `zeek` dan tidak menemukan satu baris pun antara keduanya, lalu menulis "kemungkinan alert MDE keliru karena tidak ada trafik". Apa yang salah?

<details><summary>Jawaban</summary>

Dua workstation di switch akses yang sama tidak pernah lewat SPAN core data center atau TAP egress, jadi ketiadaan baris adalah posisi sensor, bukan bukti tidak ada trafik. Sebelum menulis apa pun, cek kesehatan sensor pada jam itu, lalu cari saksi di domain controller: TGS `cifs/JKT-WS-2093` dari `10.10.60.191` di `kerberos.log` atau Event 4769. Di `INC-2027-078`, tiket itu ada 21 detik sebelum logon yang dicatat MDE. Saksi itu pun buta terhadap NTLM, akun lokal, dan tiket yang dipakai ulang.

Lihat bagian 1.2 dan 2.7.

</details>

**2. Skenario keputusan.** Sabtu 22:00 saved search `NSM - tulis ADMIN$ lalu svcctl` menyala untuk `jkt-mecm01` ke empat server. Tidak ada tiket perubahan untuk akhir pekan itu. Apa langkahmu?

- A. Tutup sebagai jinak, karena `jkt-mecm01` terdaftar sebagai host administrasi.
- B. Isolasi `jkt-mecm01` segera karena tidak ada tiket perubahan.
- C. Periksa sumbu lain: akun di `kerberos.log` (apakah `svc-mecm-push`), berkas dan hash dibanding push sebelumnya, apakah ada `DeleteService` tak lazim, lalu tanyakan pemilik MECM sebelum memutuskan.

<details><summary>Jawaban</summary>

C. Sumber terdaftar hanya satu dari empat sumbu; jadwal sudah menyimpang, jadi akun, berkas, dan bentuk operasinya harus dicek. Server distribusi adalah sasaran bernilai tinggi justru karena boleh menulis ke `ADMIN$` di mana-mana, jadi A berbahaya. B terlalu cepat: isolasi server distribusi menghentikan operasi dan bisa tidak perlu bila pemiliknya mengonfirmasi push darurat; putuskan setelah sumbu lain dan pemilik dicek, kecuali ada indikator kuat seperti berkas asing atau akun tak lazim.

Lihat bagian 1.1 dan 2.3.

</details>

**3. Pertanyaan jebakan.** Dari satu workstation, `kerberos.log` mencatat 49 TGS ke 49 SPN akun pengguna dalam 41 detik: 6 berhasil dengan `rc4-hmac`, 43 gagal `KDC_ERR_ETYPE_NOSUPP`. Rekan menulis "hanya 6 tiket yang keluar, 43 gagal jadi tidak relevan". Apa yang hilang dari tafsiran itu?

<details><summary>Jawaban</summary>

Pertama, 43 galat jenis enkripsi adalah bukti cara klien meminta: akun tujuan hanya punya kunci AES dan klien gagal, jadi klien hampir pasti hanya menawarkan RC4, sesuatu yang tidak dilakukan workstation Windows biasa. Kedua, jumlah SPN berbeda (49, seluruh SPN akun pengguna) menunjukkan daftar sudah dikumpulkan lebih dulu. Ketiga, galat ini mungkin tidak ada di Event 4769 tanpa `KdcExtraLogLevel` 0x10, sehingga sensor adalah satu-satunya bukti. Enam tiket yang keluar adalah enam akun RC4 eksplisit, dan password keenamnya harus direset.

Lihat bagian 1.6 dan 2.5.

</details>

**4. Pertanyaan jebakan.** Baris AS untuk `svc-legacyscan` yang berhasil tanpa praautentikasi menunjukkan `cipher` `aes256-cts-hmac-sha1-96`. Apakah itu berarti bahan yang diambil penyerang terenkripsi AES?

<details><summary>Jawaban</summary>

Tidak. `cipher` di Zeek adalah enkripsi tiket, dan tiket di balasan AS adalah TGT yang dienkripsi kunci `krbtgt`. Bagian yang dipecahkan pada AS-REP Roasting adalah bagian balasan yang dienkripsi kunci akun pengguna. Enkripsi bagian itu dibaca dari Suricata `krb5` (`encryption`, `weak_encryption`) atau dari Wireshark (`kerberos.etype`). Karena akun ini hanya mengizinkan RC4, bagian itu kemungkinan RC4, tetapi tanpa `krb5` di `eve-proto.json` sensor PT JAB tidak bisa memastikannya.

Lihat bagian 1.6 dan 2.6.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Agung Prabowo (Lead Infrastruktur), dalam tiga kalimat, apa yang hilang bagi SOC bila enkripsi SMB dinyalakan di `jkt-fs02`, dan apa yang perlu disiapkan bersamaan.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Setelah enkripsi aktif, sensor masih melihat siapa terhubung ke `jkt-fs02`, kapan, berapa byte, dan tiket Kerberos yang dipakai, tetapi tidak lagi melihat nama berkas, operasi, dan isi, persis bukti yang dipakai untuk membuktikan pengambilan data di `INC-2027-071`. Jadi enkripsinya tetap layak dinyalakan karena data penjualan sekarang lewat jaringan dalam teks polos. Pada hari yang sama, tolong aktifkan audit akses berkas untuk share `SALES$` dan teruskan ke Splunk, supaya bukti 'berkas apa yang dibaca siapa' pindah dari sensor ke server."

Kesalahan yang sering muncul:

- Menyarankan jangan mengenkripsi supaya sensor tetap bisa membaca.
- Menyamakan enkripsi dengan signing, atau mengira signing bawaan Windows 11 24H2 sudah membutakan sensor.
- Tidak menyebut pengganti bukti di sisi server.

</details>

**6. Skenario keputusan.** Seorang engineer berkata: "Sejak Windows 11 24H2 semua SMB wajib signing, jadi saved search `ADMIN$` di Zeek sudah tidak berguna; kita pindah total ke log host." Bagaimana tanggapanmu?

- A. Setuju; signing menyembunyikan nama berkas dan share.
- B. Tidak setuju; signing hanya menjamin integritas dan isi tetap terbaca, sehingga Zeek tetap bisa mengurai share, berkas, dan operasi. Yang membutakan sensor adalah enkripsi SMB, yang tidak wajib secara bawaan.
- C. Setuju sebagian; signing menyembunyikan nama berkas tetapi tidak nama share.

<details><summary>Jawaban</summary>

B. Signing mencegah perubahan pesan dan relay, tetapi tidak mengenkripsi. Microsoft menyebut enkripsi tidak wajib secara bawaan, berbeda dari signing. A dan C keliru tentang fungsi signing. Log host tetap perlu, tetapi sebagai pasangan, bukan pengganti.

Lihat bagian 1.3 dan 1.8.

</details>

**7. Interview question (English).** "Your network sensors sit at the data center core and the internet egress. How would you detect and scope lateral movement in a Windows environment from network data, and what can't you see?"

<details><summary>Sample answer</summary>

"I'd start with what the sensor position allows. Workstation-to-server and anything touching the domain controllers crosses the core, so I get SMB, DCE-RPC, and Kerberos metadata there. On SMB, I look for admin share writes followed by service control calls to the same host, like CreateService and StartService over svcctl, and I compare every source against a baseline of known admin hosts, accounts, and change windows, because software distribution does exactly the same thing. On Kerberos, I baseline encryption types and client-to-service pairs: bursts of service ticket requests, RC4 where the domain uses AES, encryption-type errors from one client, or a service account suddenly authenticating from a workstation. Workstation-to-workstation traffic on the same access switch never reaches my sensor, but the Kerberos service ticket for cifs on the target host still goes to the domain controller, so the DC becomes my witness. I'd be explicit about the limits: NTLM and local accounts leave no Kerberos trace, ticket reuse hides repeat sessions, DCE-RPC arguments aren't logged, and SMB encryption removes file names. What actually executed has to come from endpoint telemetry."

What makes this answer strong: it ties detection to sensor placement, treats admin-looking activity with a baseline instead of a blanket rule, uses the domain controller as an indirect witness for a known blind spot, and clearly separates what the network proves from what only the endpoint can answer.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Zeek documentation: SMB logs | https://docs.zeek.org/en/master/logs/smb.html | primer | dilihat 2026-10-09, dicek ulang 2026-10-29 | Tinggi. Daftar log yang muncul untuk SMB (dce_rpc, kerberos, ntlm, smb_cmd, smb_files, smb_mapping, pe, notice); `smb_mapping.log` dengan `path` dan `share_type` bernilai DISK dan PIPE, `smb_files.log` dengan `action`, `path`, `name`, `size`; contoh `dce_rpc.log` untuk `svcctl` dan `samr`; keterangan bahwa `ADMIN$` dan `IPC$` mencurigakan bila tidak diotorisasi; batas: layanan non-berkas diperlakukan sebagai berkas, arah transfer tidak ada, isi DCE-RPC terenkripsi, dan entri tidak mengungkap maksud; rekomendasi BZAR |
| S2 | Zeek documentation dan kode sumber: base/protocols/krb/main.zeek (KRB::Info) | https://docs.zeek.org/en/master/scripts/base/protocols/krb/main.zeek.html | primer | dilihat 2026-10-09, dicek ulang 2026-10-29 | Tinggi. Daftar field beserta tipe dan sifat opsionalnya, tiga nilai `request_type` (AS, TGS, AP), `KRB::ignored_errors` bawaan, port 88/tcp dan 88/udp; cara pengisian `client`, `service`, `cipher`, dan pemeriksaan `error_text` dibaca dari kode di https://github.com/zeek/zeek/blob/master/scripts/base/protocols/krb/main.zeek (cabang master, bisa berubah antar rilis) |
| S3 | IANA: Kerberos Encryption Type Numbers | https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml | primer | dilihat 2026-10-09, dicek ulang 2026-10-29 | Tinggi. Nomor dan nama jenis enkripsi beserta penandaan deprecated, termasuk 1, 3, 16, 17, 18, 19, 20, dan 23; registry terakhir diperbarui 2024-12-06 |
| S4 | Microsoft Learn: 4769(S, F) A Kerberos service ticket was requested | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769 | primer | diakses 2026-10-10, dicek ulang 2026-10-29 (halaman diperbarui 2026-04-27) | Tinggi. Field Account Name, Service Name, Client Address, Ticket Encryption Type, Failure Code (0x20 = tiket kedaluwarsa); format baru sejak pembaruan 14 Januari 2025; galat tertentu termasuk jenis enkripsi hanya diaudit dengan `KdcExtraLogLevel` 0x10; rekomendasi memantau etype selain 0x11 dan 0x12. Catatan versi sebelumnya merujuk https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769; halaman yang dibaca 2026-10-29 ada di jalur previous-versions (arsip) |
| S5 | RFC 4120: The Kerberos Network Authentication Service (V5) | https://www.rfc-editor.org/rfc/rfc4120.html | primer | dirujuk 2026-10-09 | Tinggi untuk alur AS, TGS, dan AP |
| S6 | BZAR (Bro/Zeek ATT&CK-based Analytics and Reporting) | https://github.com/mitre-attack/bzar | primer (repo resmi proyek) | dirujuk 2026-10-09, dicek ulang 2026-10-29 | Sedang-tinggi. Skrip yang memetakan perilaku SMB dan DCE-RPC ke teknik ATT&CK, tiga analitik SumStats, ekstraksi berkas; README menyebut mutakhir per 10/09/2020, tanpa rilis; deteksi tulis bergantung pada `smb2_write_request` |
| S7 | Network-Forensics-note Day 01, 03, 07, 08, 09, 11, 12, 15, 16 | (lokal) | rujukan internal | 2026-10-10, diperbarui 2026-10-29 | Posisi sensor dan blind spot, SMB di Wireshark, Zeek dan Splunk, Suricata, `INC-2027-071` |
| S8 | Microsoft Open Specifications: MS-SCMR dan MS-TSCH (Standards Assignments, named pipe `\PIPE\svcctl` dan `\PIPE\atsvc`); MS-RRP (Windows Remote Registry Protocol) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/e7a38186-cde2-40ad-90c7-650822bd6333 | primer | diakses 2026-10-10 | Tinggi untuk `svcctl` dan `atsvc`; MS-TSCH di https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/fbab083e-f79f-4216-af4c-d5104a913d40 dan MS-RRP di https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/0fa3191d-bb79-490a-81bd-54c2601b7a78 |
| S9 | Zeek documentation: base/protocols/dce-rpc/main.zeek (DCE_RPC::Info) | https://docs.zeek.org/en/master/scripts/base/protocols/dce-rpc/main.zeek.html | primer | diakses 2026-10-29 | Tinggi. Field `rtt`, `named_pipe` (dari `sec_addr`, bisa berisi port), `endpoint`, `operation`; `DCE_RPC::ignored_operations` bawaan untuk `spoolss`, `wkssvc`, dan `winreg`; port bawaan 135/tcp |
| S10 | Zeek documentation: base/protocols/krb/consts.zeek | https://docs.zeek.org/en/master/scripts/base/protocols/krb/consts.zeek.html | primer | diakses 2026-10-29 | Tinggi. Tabel `KRB::error_msg` (6 `KDC_ERR_C_PRINCIPAL_UNKNOWN`, 14 `KDC_ERR_ETYPE_NOSUPP`, 25 `KDC_ERR_PREAUTH_REQUIRED`) dan `KRB::cipher_name` (17, 18, 23) |
| S11 | Microsoft Learn: 4768(S, F) A Kerberos authentication ticket (TGT) was requested | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768 | primer | diakses 2026-10-29 (halaman diperbarui 2026-04-27) | Tinggi. Pre-Authentication Type (0 tanpa praautentikasi, 2 PA-ENC-TIMESTAMP), Client Address, Result Code (0x19 di skenario interoperabilitas UNIX), tabel Ticket Encryption Type; format baru sejak 14 Januari 2025. Satu tabel menulis RC4-HMAC-NT desimal 23 sebagai 0x18, bertentangan dengan tabel Ticket Encryption Type (0x17) di halaman yang sama |
| S12 | Microsoft Support KB5073381: How to manage Kerberos KDC usage of RC4 for service account ticket issuance changes related to CVE-2026-20833 | https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc | primer | terbit 2026-01-13, diperbarui 2026-04-14, diakses 2026-10-29 | Tinggi untuk fase dan event KDCSVC 201-209; halaman tidak konsisten soal enforcement otomatis April atau Juli 2026 |
| S13 | MITRE ATT&CK T1558.003 Steal or Forge Kerberos Tickets: Kerberoasting | https://attack.mitre.org/techniques/T1558/003/ | primer | diakses 2026-10-29 | Tinggi. Versi 1.3, diubah 24 Oktober 2025; DET0157; TGS RC4 (0x17), banyak tiket layanan dalam waktu singkat; ATT&CK v20.0 |
| S14 | MITRE ATT&CK T1558.004 Steal or Forge Kerberos Tickets: AS-REP Roasting | https://attack.mitre.org/techniques/T1558/004/ | primer | diakses 2026-10-29 | Tinggi. Versi 1.2, diubah 24 Oktober 2025; DET0113; 4768 Pre-Auth Type 0, RC4; penemuan akun lewat LDAP atau permintaan per pengguna |
| S15 | MITRE ATT&CK T1021.002 Remote Services: SMB/Windows Admin Shares | https://attack.mitre.org/techniques/T1021/002/ | primer | diakses 2026-10-29 | Tinggi. Versi 1.3, diubah 12 Mei 2026; DET0530; akses `ADMIN$`/`C$` diikuti service, scheduled task, atau proses di host tujuan |
| S16 | MITRE ATT&CK T1569.002 System Services: Service Execution | https://attack.mitre.org/techniques/T1569/002/ | primer | diakses 2026-10-29 | Tinggi. Versi 1.3, diubah 11 September 2026; DET0421; service sementara lewat API SCM, sc.exe, atau PsExec |
| S17 | Suricata 8.0.7 User Guide: EVE JSON Format (event smb dan krb5) | https://docs.suricata.io/en/suricata-8.0.7/output/eve/eve-json-format.html | primer | diakses 2026-10-29 | Tinggi. `krb5`: `msg_type`, `cname`, `realm`, `sname`, `encryption`, `weak_encryption`, `ticket_encryption`, `ticket_weak_encryption`, `error_code`, `failed_request`; `smb`: `share`, `share_type`, `filename`, `dcerpc.interfaces`, `ntlmssp`, `kerberos.realm`, `kerberos.snames` |
| S18 | Wireshark Display Filter Reference: kerberos dan smb2 | https://www.wireshark.org/docs/dfref/k/kerberos.html | primer | diakses 2026-10-29 | Tinggi. `kerberos.msg_type`, `kerberos.CNameString`, `kerberos.SNameString`, `kerberos.etype`, `kerberos.padata_type`, `kerberos.error_code` (sampai 4.6.9); halaman smb2 di https://www.wireshark.org/docs/dfref/s/smb2.html: `smb2.cmd`, `smb2.tree`, `smb2.filename`, `smb2.acct`, `smb2.header.transform.flags.encrypted`, `smb2.ses_flags.encrypt` |
| S19 | Microsoft Learn: SMB security hardening in Windows Server and Windows Client | https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening | primer | diperbarui 2025-09-15, diakses 2026-10-29 | Tinggi. Signing wajib bawaan di Windows 11 24H2 dan Windows Server 2025, enkripsi klien bisa diwajibkan tetapi tidak bawaan, NTLM blocking untuk SMB, SMB over QUIC di semua edisi Windows Server 2025, port alternatif |
| S20 | Microsoft Open Specifications: MS-SMB2 SMB2 TRANSFORM_HEADER | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/d6ce2327-a4c9-4793-be66-7b5bad2175fa | primer | diperbarui 2026-01-14, diakses 2026-10-29 | Tinggi. Hanya untuk dialek SMB 3.x; ProtocolId 0xFD 'S' 'M' 'B'; OriginalMessageSize, SessionId, Flags/EncryptionAlgorithm |
| S21 | Zeek: Get Zeek (halaman rilis) | https://zeek.org/get-zeek/ | primer | diakses 2026-10-29 | Tinggi. Zeek 9.0.1 LTS dan 8.0.11, keduanya 26 Oktober 2026 |

**Catatan sumber:** nama pipe `svcctl` dan `atsvc` berasal dari spesifikasi Microsoft [S8]; `winreg` untuk MS-RRP adalah nama yang umum dikenal dan perlu dicocokkan dengan bagian transport di spesifikasi MS-RRP. Cocokkan juga dengan nama yang muncul di `smb_files.log` dan `dce_rpc.log` lab-mu; nama operasi `CreateServiceW` mengikuti nama prosedur MS-SCMR, sedangkan contoh di dokumentasi Zeek memakai varian `CreateServiceWOW64W` [S1], jadi saved search bagian 2.3 memuat keduanya. Skrip awk di bagian 2.5 dan 2.6 adalah susunan sendiri untuk menjelaskan logikanya, bukan alat yang teruji, dan ambang di dalamnya adalah angka awal yang harus diganti dari baseline. Pola permintaan `AS` tanpa prasyarat dijelaskan pada tingkat perilaku; apakah galat praautentikasi tercatat di `kerberos.log` bergantung pada teks galat yang dikirim KDC dan `KRB::ignored_errors` [S2], sehingga perlu diuji di lingkungan sendiri. Field Event 4768 dan 4769 yang dipakai untuk korelasi mengikuti halaman Microsoft [S4][S11]; nama field di Splunk (`Client_Address`, `Ticket_Encryption_Type`, `Pre_Authentication_Type`) bergantung pada add-on Windows yang dipakai. Perilaku `smb_mapping.log` saat enkripsi SMB per share dibanding per sesi adalah penalaran dari urutan pesan SMB 3.x, belum diuji; bagian 3 langkah 9 mengujinya. Perilaku service `ccmsetup` MECM disebut sebagai isi runbook PT JAB fiktif, bukan klaim tentang produk. Fase pembatasan RC4 mengikuti KB5073381 per 14 April 2026 [S12]; halaman itu sendiri tidak konsisten tentang kapan enforcement otomatis.
