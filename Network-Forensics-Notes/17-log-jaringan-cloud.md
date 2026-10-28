---
day: 17
title: 'Log jaringan cloud: VPC Flow Logs, VNet flow logs, dan batas yang tidak terlihat'
researched_on: 2026-10-29
versions_checked: 'AWS VPC Flow Logs record fields versi 2 sampai 11 (VPC User Guide, diakses 2026-10-29; field versi 11 termasuk interface-type dan next-hop-*; resource-id untuk regional NAT gateway di versi 9); AWS flow log limitations dan record examples (diakses 2026-10-29); Azure virtual network flow logs overview (ms.date 2026-02-10, diperbarui 2026-10-06; contoh memakai flowLogVersion 4); Azure NSG flow logs pensiun 30 September 2027 dan pembuatan baru tidak lagi didukung (halaman diperbarui 2026-02-10); Amazon Athena DDL VPC flow logs (kolom versi 2 sampai 5); Splunk Add-on for AWS 8.3.1 (Splunkbase 1876, 21 Oktober 2026); Splunk Add-on for Microsoft Cloud Services 6.3.3 (Splunkbase 3110, 10 September 2026); Amazon Route 53 Resolver query logging; AWS Traffic Mirroring; rujukan Day 04, 05, 10, 11, 12, 15, 16'
---

# Day 17: Log jaringan cloud

Cakupan: membaca rekaman flow log dari AWS dan Azure, mengetahui apa yang tidak dicatatnya, menghitung volume dan waktu dengan benar, dan memakai keduanya untuk menjawab pertanyaan insiden ketika tidak ada pcap sama sekali.

## Ide inti

Di data center sendiri, bukti jaringan bisa kamu pilih: pasang TAP, minta SPAN, simpan pcap, jalankan Zeek. Di cloud publik pilihan itu hampir hilang. Kamu tidak memegang switch, tidak bisa memasang TAP, dan pengambilan paket penuh butuh fitur khusus yang harus disiapkan sebelum kejadian. Yang hampir selalu ada hanya flow log dari penyedia: AWS VPC Flow Logs dan Azure virtual network flow logs. Di Day 10 flow menjadi pengganti pcap pada jaringan besar; di cloud flow sering menjadi satu-satunya bukti jaringan. Gagasan inti Day ini: flow log cloud adalah ekspor milik penyedia, dicatat per antarmuka, dengan template dan waktu yang ditentukan penyedia. Kemampuan memakainya ditentukan oleh dua kebiasaan: membaca setiap field persis seperti definisinya (alamat antarmuka atau alamat paket, waktu yang bisa meleset, byte sejak rekaman sebelumnya), dan menuliskan apa yang tidak dicatat sebagai bagian tetap laporan, bukan menyembunyikannya.

Kamu sudah mengenal posisi ini dari NOC. Pelanggan korporat yang memakai CPE terkelola milik penyedia lain tidak bisa kamu SPAN; yang kamu terima hanya NetFlow yang diekspor perangkat itu, dengan template yang dipilih pemiliknya. Bila router NAT mengekspor flow di interface inside dan outside, satu sesi muncul dua kali: sebelum translasi dengan alamat privat, sesudah translasi dengan alamat publik, dan tanpa log translasi kamu tidak bisa menautkan keduanya dengan pasti. VPC Flow Logs bekerja dengan cara yang sama per elastic network interface (ENI): rekaman di antarmuka NAT gateway memperlihatkan dua kaki itu, dan field tingkat paket (`pkt-srcaddr`, `pkt-dstaddr`) berperan seperti log translasinya. Batas analoginya ada tiga. Template flow log cloud tidak bisa diubah setelah dibuat; kamu harus membuat flow log baru, dan data lama tetap dengan format lamanya. Penyedia menulis sendiri daftar trafik yang tidak dicatat, termasuk DNS ke resolver bawaan. Dan waktu di rekaman bisa meleset sampai satu menit, jauh lebih kasar daripada `ts` Zeek.

```
 AWS ap-southeast-3, VPC jab-prod 10.110.0.0/16 (flow log level VPC, format bawaan v2, interval maks 10 menit)

 jab-rpt-db01 10.110.40.15 --(1) baca data laporan--> jab-rpt-worker01 10.110.21.37 (m6i, Nitro: rekaman <= 1 menit)
   [ENI db]                                             [ENI worker]
                                                            |
                         (2) kaki 1: 10.110.21.37 -> 10.110.0.37:443 (dstaddr = alamat privat NAT)
                                                            v
                                     NAT gateway nat-0c41e7a9b2d3f6018, ENI 10.110.0.37, EIP 198.51.100.217
                                                            |
                         (3) kaki 2: 10.110.0.37 -> 203.0.113.192:443 (srcaddr = alamat privat NAT)
                                                            v
                                                     internet: ingest.pdfkit-cdn.example
 satu unggahan = tercatat di ENI worker, kaki 1, dan kaki 2  => dijumlah begitu saja = 3 kali lipat

 Azure Indonesia Central, VNet vnet-jab-prod-idc 10.120.0.0/16 (VNet flow logs sejak Selasa 2027-06-15)
 jab-az-batch01 10.120.2.14 --SYN 443--> 203.0.113.192 / .193   X NSG UserRule_Deny-Internet-Out (state D)
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan, kantor pusat dan data center di Jakarta, dan NOC 24/7 yang satu lantai dengan SOC. Sejak Mei 2027 PT JAB menjalankan "Program NSM PT JAB": Zeek `jkt-zeek01` dan Suricata `jkt-ids01` menerima trafik dari TAP egress Jakarta di sisi dalam firewall `jkt-fw01` dan dari SPAN core switch data center, ring buffer `jkt-pcap01` merekam egress, dan workstation kantor keluar ke web hanya lewat proxy eksplisit `jkt-proxy01` (`10.20.3.60:3128`). Sejak awal program, workload di AWS dan Azure sudah dicatat sebagai blind spot (Day 01 bagian 1.5): sensor tidak melihat apa pun di sana, dan index Splunk `aws` serta `azure` hanya berisi log penyedia. Aplikasi laporan tagihan pelanggan korporat berjalan di AWS (akun produksi `310582746193`, region Jakarta `ap-southeast-3`) dan punya jalur cadangan di Azure (subscription `JAB-Azure-Prod`, region Indonesia Central). Satu-satunya bukti jaringan di kedua tempat adalah flow log.

Rabu 2027-06-16 pukul 14:05, pipeline GitLab CI `billing/report-builder` men-deploy image baru `report-worker:2027.06.16-1` ke `jab-rpt-worker01` di AWS dan ke `jab-az-batch01` di Azure; image itu memuat versi baru sebuah library pihak ketiga, `pdfx-fontcache` 3.2.1 (nama fiktif). Kamis 2027-06-17 dini hari, antrean shift malam Dwi Cahyono (L1), dengan Rudi Hartanto (L2) sebagai on-call, menerima dua alert dari index `aws`: unggahan sekitar 1,94 GB dari NAT gateway produksi ke `203.0.113.192:443` antara 01:20 dan 02:10 (`SOC-2027-0680`, 02:31), dan rekaman `SKIPDATA` pada antarmuka `jab-rpt-worker01` di tengah jendela yang sama (`SOC-2027-0681`, 02:46). Pukul 03:05 Rudi membuka `INC-2027-076`, dan pukul 03:40 Lead DevOps Lutfi Hakim memindahkan `jab-rpt-worker01` ke security group karantina. Sepanjang Kamis menyusul tiga alert lain: penolakan NSG berulang dari `jab-az-batch01` ke `203.0.113.192` dan `.193` (`SOC-2027-0682`, 08:15), lonjakan volume ingest index `azure` (`SOC-2027-0684`, 09:30), dan hasil retro-hunt IOC di proxy kantor untuk `JKT-WS-2081` (`SOC-2027-0683`, 10:40). Jumat 2027-06-18 pukul 08:00, SOC lead Dimas Prasetyo menulis kepadamu, dengan Lutfi dan DPO Agus Setiawan di CC:

> "Jam 13:00 aku harus menjelaskan INC-2027-076 ke Pak Hendra, dan ini insiden cloud pertama sejak program NSM jalan. Sensor kita tidak melihat AWS dan Azure sama sekali, jadi apa yang sebenarnya kita punya di sana sebagai bukti jaringan? Alert jam 02:31 menyebut NAT gateway sebagai sumber; bagaimana kita tahu instance mana yang mengirim, dan apa arti angka di rekaman itu? Seberapa tepat jamnya, dan berapa persisnya yang keluar, termasuk satu menit yang katanya SKIPDATA? Di Azure kenapa log tiba-tiba dobel, dan apa yang bisa kita baca dari sana? Pak Agus perlu tahu data apa yang keluar: bisa kita pastikan dari log ini? Apa saja yang tidak tercatat, supaya aku tidak salah bilang 'tidak ada trafik lain'? Bisakah analisis beacon dan exfil yang biasa kita pakai dijalankan di atas log cloud? Terakhir, apa yang harus diubah supaya kejadian berikutnya tidak sebuta ini?"

Pesan itu memuat delapan pertanyaan:

1. Apa bukti jaringan yang tersedia di AWS dan Azure, dan kenapa sensor program tidak membantu?
2. Apa isi satu rekaman VPC Flow Logs, dan field mana yang dibutuhkan untuk pemeriksaan?
3. Bagaimana menemukan instance pengirim bila rekaman menyebut NAT gateway, dan bagaimana membedakan upaya koneksi dari koneksi yang terbentuk?
4. Seberapa tepat waktu di flow log, dan bagaimana menghitung volume yang hilang karena `SKIPDATA`?
5. Apa yang terlihat di Azure, kenapa lognya dobel, dan bagaimana membaca flow tuple-nya?
6. Apa yang tidak tercatat di kedua cloud, dan apa artinya bagi kalimat "tidak ditemukan trafik"?
7. Bisakah analisis beacon, exfiltration, dan scan dijalankan di atas flow log, dan apa batas kesimpulannya, termasuk soal isi data?
8. Apa yang harus diubah supaya kejadian berikutnya lebih terlihat?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3 dan 1.4, pertanyaan 4 di bagian 1.5, pertanyaan 5 di bagian 1.6 dan 1.7, pertanyaan 6 di bagian 1.8, pertanyaan 7 di bagian 1.9, dan pertanyaan 8 di bagian 1.1, 1.8, dan 2.10. Bagian 2 berisi artefak hari Kamis dan Jumat: rekaman mentah AWS (`SOC-2027-0680`), kueri Athena dan jebakan hitung ganda, penelusuran dari NAT gateway ke instance, perhitungan ulang menit `SKIPDATA` (`SOC-2027-0681`), flow log kedua dengan format kustom, flow tuple Azure (`SOC-2027-0682`), log ganda Azure (`SOC-2027-0684`), jangkar dari proxy kantor (`SOC-2027-0683`), perangkaian `INC-2027-076`, lalu peta celah dan jawaban untuk Dimas.

**Kapan relevan:** saat insiden menyentuh workload di AWS atau Azure dan satu-satunya bukti jaringan adalah flow log penyedia; saat alert menyebut NAT gateway, load balancer, atau gateway lain sebagai sumber; saat volume, waktu, atau keputusan izinkan dan tolak harus dilaporkan dengan angka; dan saat merancang konfigurasi flow log sebelum insiden terjadi.
**Kapan bukan jawaban:** saat yang dibutuhkan adalah isi paket, nama domain, atau URI, karena flow log tidak memuatnya; saat workload berjalan di layanan yang tidak didukung flow log (misalnya Azure Functions atau App Service); saat yang dibutuhkan adalah urutan peristiwa berresolusi detik; dan saat pertanyaannya tentang aktivitas API cloud (siapa membuat atau mengubah sumber daya), karena itu wilayah log audit penyedia seperti CloudTrail dan Activity Log, bukan flow log.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (flow, exporter, kolektor, active dan idle timeout, sampling, `conn.log`, beacon, CV, PCR, prevalence, proxy eksplisit, splice, bump) tidak diulang; definisinya ada di Day 01 sampai 16 [S5]. Tabel ini memuat istilah yang dipakai Day ini; kolom kanan memakai padanan dari pekerjaan NOC dan ISP.

| Istilah | Arti singkat | Padanan di NOC/ISP |
|---|---|---|
| VPC (Virtual Private Cloud) | Jaringan privat logis milik satu akun di AWS | VRF pelanggan di backbone penyedia |
| ENI (elastic network interface) | Antarmuka jaringan virtual di AWS; flow log dicatat per ENI | Interface fisik atau subinterface tempat NetFlow diaktifkan |
| Requester-managed interface | ENI yang dibuat layanan AWS (NAT gateway, endpoint, load balancer), bukan instance milikmu | Interface di perangkat terkelola milik penyedia |
| NAT gateway (zonal dan regional) | Layanan NAT terkelola AWS untuk subnet privat keluar ke internet | Router NAT atau CGNAT |
| Elastic IP (EIP) | Alamat publik tetap yang dipasang ke sumber daya AWS | Alamat publik statis dari pool penyedia |
| VPC Flow Logs | Rekaman lima-tuple, volume, waktu, dan keputusan izinkan atau tolak per ENI per interval agregasi | NetFlow dari perangkat yang tidak kamu kelola |
| Format bawaan dan format kustom | Template field tetap versi 2, atau daftar field pilihan sendiri | Template NetFlow v5 tetap vs template IPFIX yang bisa dipilih |
| Interval agregasi | Jendela waktu tempat satu alur dikumpulkan menjadi satu rekaman (maksimum 10 atau 1 menit) | Active timeout exporter |
| `log-status` (`OK`, `NODATA`, `SKIPDATA`) | Status pencatatan per rekaman | Counter flow yang di-drop exporter |
| Security group dan network ACL | Filter AWS: security group stateful di ENI, network ACL stateless di subnet | ACL stateful di firewall vs ACL stateless di router |
| NSG (network security group) | Filter Azure berisi rule izinkan dan tolak, dipasang di subnet atau NIC | ACL di interface |
| NSG flow logs | Flow log Azure generasi lama, dicatat per NSG; pensiun 30 September 2027 | NetFlow per ACL |
| VNet flow logs | Flow log Azure generasi baru, diaktifkan di tingkat virtual network | NetFlow per VRF |
| Flow tuple | String berpisah koma di log Azure berisi waktu, lima-tuple, arah, state, enkripsi, dan hitungan | Satu record flow dalam bentuk teks |
| Flow state (`B`, `C`, `E`, `D`) | Awal, berlanjut, akhir, atau ditolak | Record start, interim-update, stop, dan deny ACL |
| Traffic Mirroring | Fitur AWS yang menyalin paket dari ENI ke alat pemantau, dibungkus VXLAN | SPAN atau RSPAN jarak jauh |
| Resolver query logging | Log query DNS ke Route 53 Resolver di VPC | Log query resolver ISP |

### 1.1 Cloud tanpa TAP: flow log sebagai satu-satunya bukti jaringan

Pertanyaan pertama Dimas lahir dari rancangan sensor di Day 01: TAP egress Jakarta dan SPAN core switch data center hanya melihat trafik yang lewat di gedung PT JAB. Unggahan dari `jab-rpt-worker01` ke internet keluar lewat NAT gateway AWS di Jakarta, tidak pernah menyentuh `jkt-fw01`, dan karena itu tidak ada di `conn.log`, di Suricata, maupun di ring buffer.

Day 10 memakai flow sebagai pengganti pcap pada jaringan besar. Di cloud, flow sering bukan pengganti melainkan satu-satunya yang ada: kamu tidak bisa memasang tap, tidak bisa melakukan port mirroring sembarangan, dan pengambilan paket penuh butuh konfigurasi tersendiri yang mahal. Konsekuensinya, kemampuan membaca flow log cloud dengan benar menentukan apakah kamu bisa menjawab pertanyaan insiden di lingkungan cloud sama sekali.

Pengambilan paket di AWS memang ada, tetapi bentuknya berbeda dari SPAN. Traffic Mirroring menyalin trafik masuk dan keluar dari ENI sebuah instance ke target pemantau (ENI instance lain, Network Load Balancer, atau Gateway Load Balancer dengan listener UDP), dan paket yang cocok dengan filter dibungkus header VXLAN sebelum dikirim [S11]. Ada empat konsekuensi bagi pemeriksa:

- Ia harus disiapkan sebelum kejadian: sesi mirror, filter, target, dan alat analisis di target. Paket yang lewat sebelum sesi dibuat tidak bisa diambil mundur, sama seperti ring buffer yang tertimpa.
- Hanya keluarga instance tertentu yang didukung sebagai sumber, dan daftar resminya tidak memuat semua generasi [S11]; cek tipe instance sebelum menjadikannya rencana.
- Biayanya dihitung per jam per sesi aktif ditambah transfer data [S11], sehingga mirror permanen untuk semua workload jarang masuk akal.
- Trafik sumber yang di-mirror tidak dicatat flow log; yang tercatat hanya trafik ke target mirror [S7]. Mirror dan flow log saling melengkapi, bukan saling menggantikan.

Di PT JAB tidak ada sesi Traffic Mirroring, dan tidak ada sensor di Azure. Jadi bukti jaringan untuk `INC-2027-076` terdiri dari empat hal: VPC Flow Logs akun `310582746193` (format bawaan, level VPC, sejak 2 Desember 2026), VNet flow logs `vnet-jab-prod-idc` (baru sejak Selasa 2027-06-15), NSG flow logs lama di subnet aplikasi Azure, dan data sensor kantor untuk host yang kebetulan menghubungi tujuan yang sama. Bagian 2.10 membahas apa yang perlu ditambah.

Day ini juga menegaskan satu hal yang sering dilewatkan: flow log cloud punya daftar panjang hal yang tidak dicatatnya, dan daftar itu harus masuk ke laporanmu, bukan disembunyikan (bagian 1.8).

### 1.2 Rekaman VPC Flow Logs

Alert `SOC-2027-0680` hanya berisi angka. Sebelum angka itu bisa dibawa ke rapat, kamu harus tahu persis apa yang diwakili satu baris.

Satu rekaman mewakili satu alur jaringan dalam VPC, pada dasarnya lima-tuple per antarmuka jaringan, yang terjadi dalam satu interval agregasi [S1]. Format bawaannya memuat field versi 2, dan urutannya tidak bisa diubah; untuk field lain kamu harus memakai format kustom [S1]. Bila sebuah field tidak berlaku atau tidak bisa dihitung untuk rekaman tertentu, nilainya `-` [S1].

Empat belas field bawaan [S1]. Tabel ini dibaca sebagai kamus: cari kolom catatan untuk mengetahui jebakan tiap field.

| Field | Isi | Catatan untuk pemeriksa |
|---|---|---|
| `version` | Versi format | 2 untuk format bawaan; pada format kustom, versi tertinggi di antara field yang dipilih |
| `account-id` | Akun pemilik antarmuka sumber | Bisa bernilai unknown untuk antarmuka yang dibuat layanan AWS |
| `interface-id` | ID antarmuka jaringan | Bernilai `-` untuk alur yang terkait NAT gateway regional |
| `srcaddr`, `dstaddr` | Alamat sumber dan tujuan | Pada antarmuka, ini alamat privat; lihat `pkt-srcaddr` |
| `srcport`, `dstport` | Port sumber dan tujuan | |
| `protocol` | Nomor protokol IANA | Bukan nama protokol |
| `packets`, `bytes` | Jumlah paket dan byte | Agregat dalam interval |
| `start`, `end` | Waktu paket pertama dan terakhir, dalam detik Unix | Bisa meleset sampai 60 detik dari waktu paket sebenarnya |
| `action` | ACCEPT atau REJECT | REJECT berarti ditolak security group atau network ACL, atau paket tiba setelah koneksi ditutup |
| `log-status` | OK, NODATA, atau SKIPDATA | Lihat bagian 1.5 |

Field tambahan yang paling berguna untuk pemeriksaan, dari versi 3 ke atas [S1]: `vpc-id`, `subnet-id`, dan `instance-id` untuk konteks sumber daya; `tcp-flags` untuk membedakan upaya koneksi dari koneksi yang terbentuk; `pkt-srcaddr` dan `pkt-dstaddr` untuk alamat tingkat paket; `flow-direction` dan `traffic-path` untuk arah dan jalur keluar; serta `pkt-src-aws-service` dan `pkt-dst-aws-service` untuk menandai alamat milik layanan AWS.

Daftar field kini sampai versi 11, dan beberapa tambahan baru langsung berguna untuk forensik [S1]:

| Field | Versi | Kegunaan |
|---|---|---|
| `flow-direction` | 5 | `ingress` atau `egress` relatif terhadap antarmuka tempat rekaman dicatat |
| `traffic-path` | 5 | Jalur trafik keluar: 1 sumber daya lain di VPC yang sama, 2 internet gateway atau gateway VPC endpoint, 3 virtual private gateway, 4 dan 5 VPC peering intra dan antar region, 6 Local Zone atau Wavelength, 7 gateway VPC endpoint, 8 internet gateway; `-` bila tidak ada yang berlaku |
| `ecs-*` | 7 | Cluster, service, dan task ECS bila trafik berasal dari task ECS |
| `reject-reason` | 8 | `BPA` (VPC Block Public Access) atau `EC` (encryption controls); `-` untuk alasan lain, termasuk security group dan network ACL |
| `resource-id` | 9 | ID regional NAT gateway |
| `encryption-status` | 10 | Status enkripsi menurut VPC Encryption Controls; `-` bila fitur tidak aktif |
| `instance-tag`, `interface-tag`, `asg-tag` | 11 | Nilai tag sumber daya, sehingga nama aplikasi ikut tercatat |
| `interface-type`, `next-hop-*` | 11 | Jenis antarmuka lokal (misalnya `nat_gateway`) dan antarmuka hop berikutnya |

Dua catatan untuk tabel itu. `reject-reason` tidak menjelaskan penolakan oleh security group atau network ACL, jadi nilai `-` pada rekaman REJECT adalah hal biasa [S1]. Field tag dan `next-hop-*` punya batas sendiri: tag bisa kosong atau keliru pada jam pertama setelah flow log dibuat, dan `next-hop-*` tidak tersedia untuk trafik ke internet gateway atau lintas region [S7].

Satu peringatan dari dokumentasinya yang perlu kamu pegang: field metadata yang tidak berasal langsung dari header paket adalah perkiraan best effort, dan nilainya bisa hilang atau tidak akurat [S1]. Jangan membangun kesimpulan keras di atas field semacam itu.

Di PT JAB, flow log `fl-04c7a2e9b1d8f3a56` dibuat 2 Desember 2026, setelah insiden kunci akses AWS yang bocor di akhir 2026, dengan format bawaan, level VPC, interval maksimum 10 menit, dan tujuan bucket S3 `jab-vpcflow-310582746193`. Format bawaan dipilih waktu itu karena paling murah dan langsung dikenali add-on Splunk. Akibatnya terasa malam Kamis: tidak ada `instance-id`, tidak ada `pkt-*`, tidak ada `tcp-flags`.

### 1.3 Alamat antarmuka dan alamat paket

Pertanyaan ketiga Dimas muncul karena rule `SOC-2027-0680` ditulis atas antarmuka NAT gateway (`eni-0f3a9c27b1d84e605`, alamat privat `10.110.0.37`), dan baris yang memicunya bersumber `10.110.0.37`, bukan alamat instance mana pun.

Ini perbedaan yang paling sering menyesatkan. `srcaddr` dan `dstaddr` adalah alamat pada antarmuka tempat alur dicatat, sedangkan `pkt-srcaddr` dan `pkt-dstaddr` adalah alamat asli tingkat paket [S1]. Dokumentasinya memberi dua contoh di mana keduanya berbeda: trafik yang melewati antarmuka NAT gateway, dan pod di Amazon EKS yang alamatnya berbeda dari alamat antarmuka node tempat ia berjalan [S1].

Contoh NAT gateway zonal di dokumentasi AWS menunjukkan persis apa yang terjadi [S6]. Satu koneksi dari instance privat ke host internet menghasilkan empat rekaman di antarmuka NAT gateway, dan `instance-id` bernilai `-` karena antarmuka NAT adalah requester-managed:

| Kaki | `srcaddr` | `dstaddr` | `pkt-srcaddr` | `pkt-dstaddr` |
|---|---|---|---|---|
| Instance ke NAT | alamat instance | alamat privat NAT | alamat instance | alamat internet |
| NAT ke internet | alamat privat NAT | alamat internet | alamat privat NAT | alamat internet |
| Internet ke NAT | alamat internet | alamat privat NAT | alamat internet | alamat privat NAT |
| NAT ke instance | alamat privat NAT | alamat instance | alamat internet | alamat instance |

Tabel itu dibaca kolom demi kolom. Dengan format bawaan, kamu hanya punya dua kolom pertama: kaki pertama tahu instance-nya tetapi tujuannya tercatat sebagai alamat NAT, dan kaki kedua tahu tujuan internetnya tetapi sumbernya tercatat sebagai alamat NAT. Tidak ada satu baris pun di antarmuka NAT yang memuat instance dan tujuan internet sekaligus. Hanya `pkt-dstaddr` di kaki pertama yang mengikat keduanya.

Akibat praktisnya langsung. Bila kamu memeriksa trafik keluar lewat NAT gateway dan hanya memakai `srcaddr` di rekaman antarmuka NAT, seluruh trafik akan terlihat berasal dari NAT gateway, dan kamu tidak bisa memastikan instance mana yang sebenarnya dari baris itu saja. Hal yang sama berlaku untuk kluster kontainer. Untuk lingkungan yang memakai NAT gateway atau kontainer, field tingkat paket bukan tambahan opsional, melainkan syarat agar flow log berguna.

Ada jalan keluar bila flow log dibuat di level VPC atau subnet, seperti di PT JAB. ENI instance juga punya flow log sendiri, dan di sana `srcaddr` sama dengan `pkt-srcaddr` karena instance bukan perantara: rekaman di ENI instance langsung memuat alamat instance dan alamat internet tujuan [S6]. Jadi pertanyaan "instance mana" dijawab dari ENI instance, bukan dari ENI NAT. Bagian 2.3 melakukannya untuk `jab-rpt-worker01`.

Daftar batasan AWS menambah tiga kasus serupa [S7]: trafik ke alamat privat sekunder ENI, trafik ke ENI yang tujuannya bukan alamat ENI itu, dan trafik keluar dengan sumber yang bukan alamat ENI semuanya tercatat dengan alamat primer ENI; hanya `pkt-*` yang memuat alamat aslinya. Pada perantara dengan client IP preservation, `pkt-*` bisa memuat alamat klien yang dipertahankan [S7].

Regional NAT gateway, jenis NAT gateway yang bisa melayani subnet di beberapa Availability Zone, mengubah aturan mainnya. Untuk alur yang terkait regional NAT gateway, `interface-id` dan `subnet-id` bernilai `-`, dan ID gateway muncul di field `resource-id` (versi 9) [S1]. Untuk trafik keluar dari regional NAT gateway, `srcaddr` diisi alamat tingkat paket yang sama dengan `pkt-srcaddr` [S1], sehingga contoh AWS untuk regional NAT gateway memperlihatkan alamat instance dan alamat internet di baris yang sama, lalu alamat publik gateway di kaki ke internet [S6]. Query yang mengelompokkan per `interface_id` akan menaruh semua alur regional NAT gateway di satu baris `-`. Cek jenis NAT gateway di akunmu sebelum menulis rule. NAT gateway PT JAB `nat-0c41e7a9b2d3f6018` adalah zonal.

### 1.4 `tcp-flags`: upaya atau koneksi

Setelah karantina pukul 03:40, Rudi ingin tahu apakah proses di `jab-rpt-worker01` masih mencoba keluar. Format bawaan hanya memberi REJECT; ia tidak bisa membedakan SYN yang ditolak dari paket sisa koneksi lama.

`tcp-flags` punya perilaku yang perlu diketahui [S1]: nilainya bitmask dengan FIN 1, SYN 2, RST 4, dan SYN-ACK 18; flag yang tidak didukung seperti ACK dan PSH menghasilkan nilai 0 bila sendirian, tetapi bila menyertai flag yang didukung maka yang dilaporkan adalah nilai flag yang didukung. Contoh resminya: SYN bersama ECE dilaporkan 2, dan bila kombinasi flag tidak valid nilainya `-` [S1]. Flag juga bisa digabung dengan OR selama interval agregasi, sehingga koneksi pendek bisa menghasilkan nilai 19 untuk SYN-ACK bersama FIN, atau 3 untuk SYN bersama FIN [S1].

Contoh urutan flag di dokumentasi AWS memperlihatkan cara membacanya [S6]: dua SYN (nilai 2) dari klien dengan port sumber berbeda, masing-masing dibalas SYN-ACK (18) dari server; di interval berikutnya satu koneksi ditutup dengan FIN (1) dari kedua arah. Arah koneksi terbaca dari sisi mana yang mengirim 2 dan sisi mana yang mengirim 18. Dalam satu interval yang memuat seluruh koneksi pendek, klien muncul dengan 3 dan server dengan 19.

Padanannya di NOC adalah membaca `show ip cache flow` dengan kolom flag: kamu tidak melihat setiap paket, hanya gabungan flag yang pernah muncul di cache selama flow itu hidup. Dari situ tiga pola dasar terbaca:

| Pola di satu pasangan | Arti yang paling mungkin | Penjelasan lain |
|---|---|---|
| Hanya 2, tanpa 18 dari arah balik | Upaya koneksi yang tidak dijawab: pemindaian, layanan mati, atau ditolak filter | Balasan dicatat di ENI lain atau tidak tercatat |
| 2 dan 18, lalu 1 | Koneksi terbentuk dan ditutup normal | |
| 4 dari server | Port tertutup atau koneksi direset | RST dari perangkat di tengah |

Untuk `jab-rpt-worker01`, format bawaan tidak punya `tcp-flags`. Flow log tidak bisa diubah setelah dibuat [S7], jadi Lutfi membuat flow log kedua dengan format kustom pukul 04:10; hasilnya di bagian 2.5.

### 1.5 Waktu, agregasi, jeda, dan `log-status`

Pertanyaan keempat Dimas soal "seberapa tepat jamnya" punya jawaban berupa tiga angka, dan satu baris status yang tidak boleh dilewatkan.

Tiga angka yang harus kamu ketahui sebelum melakukan korelasi waktu [S1]:

- Interval agregasi maksimum bawaan adalah 10 menit, dan bisa disetel menjadi 1 menit. Pada antarmuka yang terpasang di instance berbasis Nitro, intervalnya selalu 1 menit atau kurang terlepas dari setelan.
- Nilai `start` bisa sampai 60 detik sebelum paket diterima di antarmuka atau sampai 60 detik sesudah paket dikirim; `end` bisa sampai 60 detik setelah paket dikirim atau diterima.
- Setelah data ditangkap, pengiriman biasanya memakan sekitar 5 menit ke CloudWatch Logs dan sekitar 10 menit ke S3, dengan dasar best effort sehingga bisa lebih lambat.

Gabungan ketiganya berarti waktu di flow log cloud tidak cocok dipakai untuk korelasi berresolusi detik. Untuk urutan peristiwa yang rapat, pakai sumber lain sebagai jangkar dan perlakukan flow log sebagai konfirmasi kasar.

Di PT JAB ketiga angka itu muncul bersamaan. `jab-rpt-worker01` adalah `m6i.large`, instance Nitro, sehingga rekamannya per menit walaupun flow log disetel 10 menit. Antarmuka NAT gateway bukan antarmuka yang terpasang di instance, dan rekamannya di data PT JAB mengikuti interval 10 menit yang disetel; cek perilaku ini di akunmu sebelum mengandalkannya. Satu unggahan 49 menit karena itu tercatat per menit di ENI worker (49 menit, satu di antaranya `SKIPDATA`) tetapi hanya sebagai 5 rekaman di ENI NAT. Polanya sama dengan active timeout di Day 10 bagian 1.4: satu koneksi panjang dipecah menjadi banyak rekaman berbagi lima-tuple yang sama, dan total diperoleh dengan menjumlahkan. Jeda pengiriman ke S3 menjelaskan kenapa rule Splunk PT JAB untuk index `aws` membaca jendela yang berakhir 20 menit sebelum waktu jalan: alert unggahan yang selesai 02:10 baru muncul 02:31.

Nilai `log-status` menjelaskan kualitas data itu sendiri [S1]: OK berarti pencatatan normal; NODATA berarti memang tidak ada trafik pada interval itu; dan SKIPDATA berarti sebagian rekaman dilewati, yang bisa disebabkan keterbatasan kapasitas internal atau galat internal. Contoh resmi AWS menambahkan satu detail yang penting untuk hitungan: satu rekaman SKIPDATA bisa mewakili beberapa alur yang tidak tercatat untuk antarmuka itu selama interval tersebut [S6]. Baris SKIPDATA adalah pengakuan resmi bahwa ada data yang hilang, tanpa menyebut berapa banyak, dan itu wajib disebut di laporan bila muncul pada jendela yang kamu periksa.

Padanannya di NOC adalah counter "flows dropped" atau "export failed" di exporter NetFlow saat cache penuh. Batasnya: counter router menyebut jumlah yang hilang, SKIPDATA tidak. Jalan keluarnya sama dengan kebiasaan NOC: cari titik ukur kedua. Untuk `SOC-2027-0681`, menit 01:47 yang hilang di ENI worker masih tercatat di dua kaki ENI NAT (bagian 2.4).

Satu lagi soal zona waktu. `start` dan `end` adalah detik Unix, dan partisi tanggal S3 serta Athena mengikuti UTC. Unggahan Kamis 01:21 WIB tersimpan di partisi tanggal Rabu 2027-06-16. Query yang hanya membaca partisi Kamis tidak akan menemukan apa pun.

### 1.6 Azure: dari NSG flow logs ke VNet flow logs

Pertanyaan kelima Dimas punya dua bagian, dan bagian "kenapa log tiba-tiba dobel" hanya bisa dijawab dengan sejarah fitur ini.

Azure punya dua generasi flow log, dan yang lama sedang dipensiunkan. NSG flow logs dinyatakan pensiun pada 30 September 2027, dan setelah tanggal itu Azure tidak lagi mendukung traffic analytics untuk NSG flow logs serta menghapus sumber daya NSG flow log yang ada di langganan [S3]. Halaman yang sama kini menyatakan bahwa karena fiturnya pensiun, pembuatan NSG flow log baru tidak lagi didukung, dan bahwa rekaman yang sudah tersimpan di Azure Storage tidak ikut dihapus, tetapi tetap mengikuti kebijakan retensinya [S3]. Penggantinya adalah virtual network flow logs, yang diaktifkan di tingkat virtual network sehingga trafik seluruh beban kerja yang didukung di dalamnya ikut tercatat [S2].

Perbedaan keduanya yang paling berpengaruh bagi pemeriksa dirangkum di tabel ini; cari baris yang menyentuh lingkungan yang sedang kamu periksa.

| Hal | NSG flow logs | VNet flow logs |
|---|---|---|
| Dipasang di | NSG (subnet atau NIC) | Virtual network, subnet, atau NIC |
| Kolom protokol | `T` atau `U` | Nomor protokol IANA |
| Keputusan | Kolom terpisah `A` atau `D`, state `B`, `C`, `E` (versi 2) | State `D` untuk ditolak |
| Byte untuk alur stateless | Tidak didukung | Didukung |
| Rule Azure Virtual Network Manager | Tidak | Ya |
| Status enkripsi | Tidak | Ya |
| VM keluarga D, E, F seri v6 | Tidak didukung | Didukung |
| Status | Pensiun 30 September 2027 | Pengganti |

Isi tabel diambil dari kedua halaman dokumentasi [S2][S3]. Baris VM seri v6 penting di PT JAB: `jab-az-batch01` adalah `Standard_D4s_v6`, sehingga NSG flow logs di `nsg-snet-batch` tidak pernah mencatat trafiknya [S3]. Sebelum VNet flow logs diaktifkan Selasa 2027-06-15 pukul 10:00 (`CHG-2027-0533`), tidak ada satu pun data jaringan untuk VM itu. Insiden ini kebetulan terjadi sehari setelahnya.

Untuk pemeriksa, peralihan ini punya tiga akibat yang nyata. Lingkungan yang kamu periksa tahun ini bisa masih memakai format lama, format baru, atau keduanya. Dokumentasi menganjurkan menonaktifkan NSG flow logs sebelum mengaktifkan VNet flow logs pada beban kerja yang sama untuk menghindari pencatatan ganda dan biaya tambahan [S2]; bila keduanya aktif, kamu bisa melihat log ganda atau hanya VNet flow logs saja. Dan alat analisis atau SIEM yang kamu pakai belum tentu mendukung format baru, sehingga perlu diperiksa sebelum insiden terjadi. Di PT JAB, `CHG-2027-0533` mengaktifkan VNet flow logs untuk seluruh `vnet-jab-prod-idc` tanpa mematikan NSG flow logs lama di `nsg-snet-app`; itulah sumber `SOC-2027-0684` (bagian 2.7).

Untuk akibat ketiga, kondisi di Splunk jelas: halaman sourcetype Splunk Add-on for Microsoft Cloud Services menyatakan add-on hanya mendukung ingest bawaan untuk sourcetype yang tercantum, dan VNet flow logs termasuk format yang butuh metode ingest generik [S10]. PT JAB membaca blob VNet flow logs lewat input Storage Blob dengan sourcetype buatan sendiri `mscs:vnet:flow`, dan NSG flow logs lama dengan `mscs:nsg:flow`. Karena tidak ada ekstraksi bawaan, penguraian flow tuple ditulis sendiri (bagian 2.6).

Ada satu perilaku NSG flow logs yang sering memancing alert palsu dan perlu dikenali bila datanya masih kamu baca: VM tanpa alamat publik memakai default SNAT untuk keluar, dan percobaan masuk dari alamat internet ke port SNAT itu tetap tercatat di NSG flow log walaupun Azure tidak meneruskannya ke VM [S3]. Baris masuk yang ditolak dari internet ke VM privat belum tentu berarti VM itu terekspos.

### 1.7 Membaca flow tuple Azure

Untuk `SOC-2027-0682`, kamu harus membaca baris seperti `1813129672000,10.120.2.14,203.0.113.192,50412,443,6,O,D,NX,0,0,0,0` tanpa alat.

Log ditulis dalam JSON, dikumpulkan pada interval satu menit, dan beroperasi di lapis 4 [S2]. Inti datanya ada di `flowTuples`, yaitu string dengan properti dipisah koma [S2]:

```
waktu,IP sumber,IP tujuan,port sumber,port tujuan,protokol,arah,flow state,
flow encryption,paket terkirim,byte terkirim,paket diterima,byte diterima
```

Arah bernilai `I` untuk masuk dan `O` untuk keluar [S2]. Flow state punya empat nilai [S2]: `B` saat alur dibuat dan tanpa statistik, `C` untuk alur berjalan dengan statistik tiap lima menit, `E` saat alur berakhir dengan statistik, dan `D` saat alur ditolak.

Tuple itu bersarang di dalam struktur JSON empat lapis: `records`, lalu `flowRecords.flows` (satu entri per pengevaluasi, dengan `aclID` berupa NSG atau Virtual Network Manager), lalu `flowGroups` (satu entri per rule, dengan nama di `rule`), lalu `flowTuples` [S2]. Lapis luar juga memuat `macAddress` antarmuka tempat event ditangkap, `targetResourceID` sumber daya yang diawasi, dan `flowLogVersion` [S2]. Untuk trafik yang ditolak karena enkripsi, `aclID` dan `rule` bernilai `unspecified` [S2].

Perhatikan satuan waktu. Dokumentasi menyebut kolom pertama sebagai epoch Unix [S2], tetapi contoh JSON di halaman yang sama memakai 13 digit (milidetik), sedangkan contoh perhitungan bandwidth di bawahnya memakai 10 digit (detik) [S2]. Data PT JAB berbentuk 13 digit. Kode yang mengasumsikan detik akan menaruh event di tahun puluhan ribu atau gagal. Selalu cek jumlah digit sebelum mengonversi.

Perhitungan volume punya aturan tersendiri: untuk state `C` dan `E`, jumlah byte dan paket adalah hitungan agregat sejak rekaman tuple sebelumnya, sehingga total satu percakapan diperoleh dengan menjumlahkan seluruh nilainya [S2]. Contoh resminya: percakapan TCP dengan tuple `B` (kosong), `C` (1.021 paket dan 588.096 byte terkirim, 8.005 paket dan 4.610.880 byte diterima), dan `E` (52 paket, 29.952 byte, 47 paket, 27.072 byte) totalnya 9.125 paket dan 5.256.000 byte [S2]. Menjumlahkan hanya baris `E` akan memberi angka yang terlalu kecil: di contoh itu hanya 99 paket dan 57.024 byte. Byte di sini mencakup header dan payload paket [S2].

Status enkripsi punya sembilan nilai, dan dua yang paling sering kamu lihat adalah `X` untuk koneksi terenkripsi dan `NX` untuk tidak terenkripsi; dokumentasinya menegaskan trafik di virtual network bersifat tidak terenkripsi secara bawaan [S2]. Nilai lain menjelaskan kenapa enkripsi tidak terjadi, misalnya perangkat keras tidak mendukung (`NX_HW_NOT_SUPPORTED`), perangkat lunak belum siap (`NX_SW_NOT_READY`), atau tujuan berada di host yang sama (`NX_LOCAL_DST`) [S2]. Status ini tentang enkripsi virtual network oleh platform Azure, bukan tentang TLS aplikasi: koneksi HTTPS dari VM ke internet tetap `NX`.

Satu lagi yang berguna: tiap rekaman menyebut nama rule yang mengizinkan atau menolak trafik [S2], sehingga kamu bisa langsung mengetahui kebijakan mana yang berlaku tanpa menelusuri konfigurasi terpisah. Contoh resmi memuat nama rule bawaan seperti `DefaultRule_AllowInternetOutBound` [S2]. Ada juga rule platform: trafik yang diproses platform Azure sendiri, bukan oleh rule NSG atau Virtual Network Manager, dan entri ini boleh disaring bila analisis hanya tentang rule yang kamu tulis [S2]. Bila trafik aplikasimu muncul di bawah rule platform di luar kasus yang dijelaskan dokumentasi (koneksi load balancer yang dibuat ulang, trafik balasan yang tidak perlu dievaluasi), itu layak diperiksa lebih lanjut [S2].

### 1.8 Apa yang tidak tercatat

Pertanyaan keenam Dimas adalah yang paling penting untuk laporan: kalimat "tidak ada trafik lain dari worker" hanya benar bila kamu tahu apa yang tidak pernah dicatat. Bagian ini yang paling sering hilang dari laporan dan paling sering menimbulkan kesimpulan salah.

Di AWS, flow log tidak memuat isi paket sama sekali, sehingga seluruh analisis Day 05 yang bersandar pada isi kueri DNS atau header HTTP tidak bisa dilakukan. Yang tersisa adalah lima-tuple, volume, waktu, dan keputusan izinkan atau tolak. Selain itu, AWS menulis daftar trafik yang tidak dicatat sama sekali [S7]:

- trafik dari instance ke Amazon DNS server (bila memakai DNS server sendiri, trafik ke server itu tercatat);
- trafik aktivasi lisensi Windows dari instance Windows;
- trafik ke dan dari `169.254.169.254` (instance metadata) dan `169.254.169.123` (Amazon Time Sync Service);
- trafik DHCP dan ARP;
- trafik sumber yang di-mirror (yang terlihat hanya trafik ke target mirror);
- trafik ke alamat reservasi router bawaan VPC;
- trafik antara ENI endpoint dan ENI Network Load Balancer;
- trafik pada regional NAT gateway berumur pendek yang dihapus beberapa menit setelah dibuat.

Butir pertama paling berat akibatnya. Query DNS ke resolver bawaan VPC tidak meninggalkan baris apa pun di flow log, jadi nama domain yang dihubungi `jab-rpt-worker01`, dan DNS tunneling lewat resolver bawaan, tidak terlihat di sana. Sumbernya adalah Route 53 Resolver query logging, yang mencatat region, VPC, alamat dan ID instance sumber, nama yang ditanyakan, tipe record, kode respons, dan jawaban, lalu mengirimnya ke CloudWatch Logs, S3, atau Firehose [S12]. Satu batasnya: Resolver hanya mencatat query unik, bukan query yang dijawab dari cache; query yang sama dari ENI yang sama dalam TTL tidak tercatat lagi [S12]. Jadi log itu cocok untuk "nama apa yang pernah ditanyakan", bukan untuk menghitung frekuensi beacon. Pemakaian metadata instance (`169.254.169.254`), jalur favorit pencurian kredensial di cloud, juga tidak terlihat di flow log. PT JAB tidak mengaktifkan Resolver query logging; bagian 2.8 menunjukkan dari mana nama domain akhirnya didapat.

Ada pula celah konfigurasi yang bukan sifat layanan [S7]: flow log tidak bisa diaktifkan untuk VPC peer milik akun lain, dan setelah flow log dibuat, konfigurasi serta format rekamannya tidak bisa diubah; untuk menambah field, kamu menghapus flow log lama dan membuat yang baru. Data historis tetap dalam format lama.

Di Azure, sejumlah layanan tidak mendukung virtual network flow logs, antara lain Azure Container Instances, Azure Container Apps, Azure Logic Apps, Azure Functions, Azure DNS Private Resolver, App Service, beberapa layanan basis data terkelola (Azure Database for MariaDB, MySQL, dan PostgreSQL), Azure SQL Managed Instance, Azure NetApp Files, dan Microsoft Power Platform [S2]. Ada pula batas pada jalur tertentu: alur keluar dari VM ke sirkuit ExpressRoute tidak tercatat bila pencatatan diaktifkan di subnet gateway ExpressRoute, dan trafik juga melewati gateway itu ketika FastPath aktif [S2]. Trafik tidak bisa dicatat di private endpoint itu sendiri; yang bisa dilakukan adalah menangkapnya di VM sumber [S2]. Di sisi lama, NSG flow logs juga tidak mendukung VM seri v6 keluarga D, E, dan F, dan VM dengan trafik sangat tinggi bisa mengalami kegagalan pencatatan [S3].

Tulis daftar ini sebagai bagian tetap dari laporan cloud-mu. Kalimat "tidak ditemukan trafik ke alamat itu" punya arti yang sangat berbeda bila beban kerjanya kebetulan berjalan di layanan yang memang tidak tercatat. Peta celah PT JAB untuk Jumat itu ada di bagian 2.10.

### 1.9 Analisis Day 10 sampai Day 12 di atas flow log, dan batas kesimpulannya

Pertanyaan ketujuh Dimas sebenarnya dua: bisakah metode yang biasa dipakai berjalan di data ini, dan apa yang bisa dikatakan ke Agus soal data yang keluar.

Metode Day 04, 10, 11, dan 12 bisa berjalan di atas flow log cloud, masing-masing dengan batas yang berbeda. Tabel ini dibaca sebagai daftar periksa sebelum menulis kesimpulan.

| Pertanyaan | Hal yang dipakai | Batas di cloud |
|---|---|---|
| Siapa berbicara dengan siapa (Day 10) | lima-tuple, bytes, packets | Alamat antarmuka vs alamat paket (bagian 1.3); satu paket tercatat di setiap ENI yang dilewati |
| Beaconing (Day 11) | `start` tiap rekaman, pasangan sumber dan tujuan | Interval agregasi menumpulkan keteraturan; pakai interval 1 menit; `start` bisa meleset 60 detik |
| Eksfiltrasi (Day 12) | rasio byte keluar terhadap masuk | Tidak ada isi; tidak bisa memastikan apa yang keluar |
| Pemindaian (Day 04) | REJECT, jumlah port berbeda | REJECT juga muncul untuk paket setelah koneksi tutup |

Baris kedua yang paling perlu kamu perhatikan. Analisis beaconing bersandar pada keteraturan interval, dan agregasi 10 menit menghancurkan sinyal itu bila beacon memakai koneksi yang sama terus-menerus: semua check-in dalam satu jendela digabung menjadi satu rekaman. Bila setiap check-in membuka koneksi baru (port sumber baru), tiap check-in tetap mendapat rekaman sendiri, tetapi `start`-nya membawa ketidakpastian sampai 60 detik [S1]. Dengan ambang Day 11 bagian 1.3 (CV maksimal 0,2), ketidakpastian itu memakan sebagian besar margin: beacon 300 detik dengan jitter plus minus 10% punya CV sekitar 0,06, tetapi CV yang diukur dari `start` bisa mendekati 0,18 (bagian 2.9). Bila lingkungan yang kamu periksa memakai interval bawaan, nyatakan di laporan bahwa analisis beaconing berresolusi halus tidak mungkin dilakukan dari data yang ada.

Baris ketiga menentukan jawaban untuk Agus. Flow log mengatakan berapa byte di tingkat IP yang keluar ke mana dan kapan; ia tidak mengatakan apa isinya. PCR (Day 12 bagian 1.3) bisa dihitung, dengan catatan bahwa byte flow log mencakup header, sedangkan PCR di Day 12 memakai byte aplikasi. Untuk sampai ke "data apa", kamu butuh sumber lain: konten yang dibaca aplikasi sebelum unggahan, kode yang melakukan unggahan, dan log aplikasi. Kecocokan volume ("unggahan kira-kira sebesar data yang dibaca dari database") adalah indikator, bukan bukti isi.

Pembedaan indikator dan kesimpulan sama dengan Day 11 dan Day 12. Indikator dari flow log: tujuan baru dengan prevalence satu, volume keluar jauh di atas baseline, check-in teratur, dan rekaman yang muncul tepat setelah deploy. Kesimpulan "exfiltration lewat saluran C2" (T1041, seperti di Day 12 bagian 1.9) butuh konteks lain: kode library, perubahan pipeline, dan pemilik tujuan. Penjelasan jinak harus disebut dan disingkirkan secara eksplisit: layanan telemetri vendor yang sah, backup ke penyedia baru, atau unggahan laporan ke mitra yang belum didokumentasikan.

## 2. Contoh dan langkah praktis: lima alert cloud hari Kamis

Semua keluaran di bagian ini adalah keluaran ilustrasi dari data fiktif PT JAB, bukan hasil eksekusi nyata; untuk latihan, jalankan kueri yang sama atas data lab sendiri atau akun sandbox (bagian 3). Nama kolom bergantung pada format kustom yang kamu pilih, jadi cocokkan dengan tabelmu. Asumsi lingkungan:

- VPC Flow Logs format bawaan dari bucket `jab-vpcflow-310582746193` dibaca Splunk Add-on for AWS lewat input SQS-based S3 ke index `aws` dengan sourcetype `aws:cloudwatchlogs:vpcflow` [S9]. Field di Splunk PT JAB diberi alias sama dengan nama kolom Athena (`interface_id`, `srcaddr`, `dstaddr`, `srcport`, `dstport`, `packets`, `bytes`, `start`, `end`, `action`, `log_status`) supaya kueri di kedua tempat sejajar; nama field hasil ekstraksi add-on di versi-mu dicek dengan `| fieldsummary` sebelum dipakai. `_time` diambil dari `start`.
- Data yang sama juga dibaca lewat Amazon Athena (workgroup `soc-forensics`, tabel `vpc_flow_logs` untuk format bawaan dan `vpc_flow_logs_v5` untuk flow log kustom yang dibuat Kamis), dipartisi per tanggal UTC.
- VNet flow logs dan NSG flow logs Azure dibaca dari storage account `stjabflowidc01` ke index `azure` dengan sourcetype `mscs:vnet:flow` dan `mscs:nsg:flow` (bagian 1.6); satu event Splunk berisi satu elemen `records`.
- Splunk menampilkan waktu dalam WIB. Field `start` dan `end` AWS, kolom waktu tuple Azure, partisi Athena, dan `ts` Zeek memakai UTC (WIB = UTC + 7).

Peta alamat yang dipakai di seluruh bagian ini (semua fiktif):

| Sumber daya | Alamat | ENI atau ID |
|---|---|---|
| `jab-rpt-worker01` (`m6i.large`, Nitro) | `10.110.21.37` | `eni-07c2d1e9a4b3f8a21`, `i-0b8e2f4c71d9a3065` |
| `jab-rpt-db01` (PostgreSQL di EC2, Nitro) | `10.110.40.15` | `eni-0e5b8a3c9d1f2a746` |
| NAT gateway zonal `nat-0c41e7a9b2d3f6018` | privat `10.110.0.37`, EIP `198.51.100.217` | `eni-0f3a9c27b1d84e605` |
| `jab-bastion01` (tipe lama non-Nitro) | `10.110.0.20` | `eni-0a9d4c1e7b2f5a368` |
| `jab-az-batch01` (`Standard_D4s_v6`) | `10.120.2.14` | subnet `snet-batch`, NSG `nsg-snet-batch` |
| `jab-az-app01` | `10.120.1.10` | subnet `snet-app`, NSG `nsg-snet-app` |
| Tujuan luar | `203.0.113.192`, `203.0.113.193` | `ingest.pdfkit-cdn.example` |

### 2.1 Membaca rekaman AWS mentah: `SOC-2027-0680`

Artefak pertama menjawab pertanyaan 2: apa yang sebenarnya dilihat Rudi saat membuka alert pukul 02:52.

**Tujuan:** membaca rekaman format bawaan tanpa alat, sebelum menulis kueri apa pun.

Rekaman format bawaan terlihat seperti ini, dan kemampuan membacanya tanpa alat adalah keterampilan dasar. Tiga baris pertama berasal dari ENI `jab-bastion01`, instance lama yang bukan Nitro sehingga rekamannya mengikuti interval 10 menit:

```
2 310582746193 eni-0a9d4c1e7b2f5a368 10.110.0.20 192.0.2.10 51314 443 6 18 4312 1813176720 1813177320 ACCEPT OK
2 310582746193 eni-0a9d4c1e7b2f5a368 192.0.2.44 10.110.0.20 44122 22 6 3 180 1813176722 1813177322 REJECT OK
2 310582746193 eni-0a9d4c1e7b2f5a368 - - - - - - - 1813177320 1813177920 - NODATA
```

Cara membacanya: baris pertama adalah koneksi keluar ke port 443 yang diterima, 18 paket dan 4312 byte dalam interval. Baris kedua adalah upaya masuk ke port 22 yang ditolak, dan `protocol` bernilai 6 berarti TCP menurut penomoran IANA [S1][S4]. Baris ketiga menyatakan tidak ada trafik pada interval itu, bukan bahwa pencatatannya gagal. Bentuk ketiganya sama dengan contoh resmi AWS untuk trafik diterima, ditolak, dan tanpa data [S6]. Nilai `start` 1813176720 adalah Rabu 2027-06-16 20:12:00 UTC, atau Kamis 03:12:00 WIB. Tanggalnya berbeda di kedua zona waktu, jadi tulis keduanya di catatan kasus supaya tidak salah hari.

- **Kapan menyesatkan:** satu baris REJECT tidak berarti serangan; ia juga muncul untuk paket yang tiba setelah koneksi ditutup [S1]. Yang bermakna adalah polanya, bukan satu barisnya.

Baris yang memicu `SOC-2027-0680` berasal dari ENI NAT gateway. Dua baris pertama di bawah adalah kaki 1 dan kaki 2 untuk jendela 10 menit pertama:

```
2 310582746193 eni-0f3a9c27b1d84e605 10.110.21.37 10.110.0.37 51874 443 6 249630 362457157 1813170060 1813170599 ACCEPT OK
2 310582746193 eni-0f3a9c27b1d84e605 10.110.0.37 203.0.113.192 30419 443 6 249630 362457157 1813170061 1813170599 ACCEPT OK
```

Dan ini tiga baris dari ENI `jab-rpt-worker01` pada menit pertama unggahan, ditambah satu check-in kecil beberapa menit kemudian:

```
2 310582746193 eni-07c2d1e9a4b3f8a21 10.110.21.37 203.0.113.192 51874 443 6 27955 40589359 1813170060 1813170119 ACCEPT OK
2 310582746193 eni-07c2d1e9a4b3f8a21 203.0.113.192 10.110.21.37 443 51874 6 13977 726804 1813170060 1813170119 ACCEPT OK
2 310582746193 eni-07c2d1e9a4b3f8a21 10.110.21.37 203.0.113.192 51702 443 6 9 2184 1813170270 1813170271 ACCEPT OK
```

**Cara membaca hasil:**

- Kaki 1 di ENI NAT memuat alamat worker (`10.110.21.37`) tetapi tujuannya alamat privat NAT (`10.110.0.37`), dengan port tujuan 443 yang tidak berubah. Kaki 2 memuat tujuan internet tetapi sumbernya alamat NAT, dengan port sumber hasil translasi (30419). Paket dan byte kedua kaki sama persis, 249.630 paket dan 362.457.157 byte, karena NAT hanya menulis ulang alamat dan port. Persamaan angka inilah yang menautkan kedua kaki ketika `pkt-*` tidak ada (bagian 1.3).
- Rentang `start` sampai `end` di ENI NAT sekitar 9 menit (18:21:00 sampai 18:29:59 UTC), sedangkan di ENI worker 59 detik. Itu interval 10 menit yang disetel melawan interval 1 menit instance Nitro (bagian 1.5).
- Baris ENI worker menyatakan langsung `10.110.21.37` ke `203.0.113.192:443`, port sumber 51874 sama dengan kaki 1. Baris kedua adalah arah balik: 13.977 paket berukuran 52 byte, pola ACK murni dari server yang menerima unggahan.
- Baris keempat adalah koneksi lain (port sumber 51702) yang hanya 9 paket dan 2.184 byte, pada 18:24:30 UTC. Bentuk kecil berulang ini adalah check-in yang dibahas di bagian 2.9.

**Variasi:** untuk format kustom, urutan kolom mengikuti daftar yang kamu pilih saat membuat flow log; tulis urutannya di catatan kasus sebelum membaca baris mentah. Untuk IPv6, `srcaddr` dan `dstaddr` berisi alamat IPv6 dan bentuk barisnya sama [S6].

**Kapan gagal:** baris dari ENI requester-managed bisa berisi `unknown` di `account-id` [S1]; baris regional NAT gateway berisi `-` di `interface-id` [S1]; dan membaca kolom dengan urutan format bawaan pada format kustom menghasilkan tafsiran yang salah tanpa pesan galat apa pun.

### 2.2 Kueri dasar di Athena dan jebakan hitung ganda

Artefak kedua menjawab "berapa dan ke mana" untuk seluruh VPC pada malam itu, dan memperlihatkan jebakan yang paling sering membuat angka di laporan cloud membengkak.

**Tujuan:** daftar pasangan dengan volume terbesar di jendela kejadian.

Kueri dasar dari catatan versi sebelumnya:

```sql
SELECT srcaddr, dstaddr, dstport, protocol,
       sum(packets) AS paket, sum(bytes) AS byte,
       count(*) AS rekaman,
       min(from_unixtime(start)) AS mulai, max(from_unixtime("end")) AS selesai
FROM vpc_flow_logs
WHERE start >= to_unixtime(timestamp '2026-10-02 00:00:00')
  AND action = 'ACCEPT'
GROUP BY 1,2,3,4
ORDER BY byte DESC
LIMIT 50;
```

Versi untuk malam Kamis PT JAB, dengan filter partisi:

```sql
SELECT srcaddr, dstaddr, dstport, protocol,
       sum(packets) AS paket, sum(bytes) AS byte,
       count(*) AS rekaman,
       min(from_unixtime(start)) AS mulai, max(from_unixtime("end")) AS selesai
FROM vpc_flow_logs
WHERE "date" = DATE '2027-06-16'
  AND start >= to_unixtime(timestamp '2027-06-16 18:00:00')
  AND start <  to_unixtime(timestamp '2027-06-16 19:30:00')
  AND action = 'ACCEPT'
GROUP BY 1,2,3,4
ORDER BY byte DESC
LIMIT 50;
```

Penjelasan tiap bagian:

- Pola ini menjawab pertanyaan "siapa mengirim paling banyak ke mana", yang biasanya menjadi langkah pertama pada kasus eksfiltrasi (Day 12).
- Kolom `end` perlu dikutip karena itu kata kunci SQL. Dokumentasi Athena meng-escape kata kunci tercadang dengan backtick di DDL (`` `end` ``, `` `date` ``) [S8]; di kueri SELECT, kutip ganda dipakai seperti contoh di atas.
- `"date"` adalah kolom partisi bertipe `date` dari DDL contoh AWS [S8]. Rentang waktu ditulis dalam UTC: 18:00 sampai 19:30 UTC Rabu sama dengan 01:00 sampai 02:30 WIB Kamis, dan karena itu partisi yang dibaca adalah Rabu (bagian 1.5).
- Untuk rentang panjang, pakai partisi (misalnya per tanggal) dan batasi `WHERE` ke partisi itu; layanan query seperti Athena menagih berdasarkan jumlah data yang dipindai, sehingga query tanpa partisi atas log berbulan-bulan bisa mahal dan lambat.
- Nama kolom memakai garis bawah karena dokumentasi Athena mengganti tanda hubung di nama field flow log dengan garis bawah di nama kolom [S8].

Keluaran ilustrasi:

```
srcaddr        dstaddr        dstport  protocol  paket      byte           rekaman  mulai                selesai
10.110.40.15   10.110.21.37   41822    6         263898     2375328420     30       2027-06-16 18:05:00  2027-06-16 18:19:58
10.110.21.37   10.110.0.37    443      6         1338688    1943550085     22       2027-06-16 18:03:25  2027-06-16 19:25:08
10.110.0.37    203.0.113.192  443      6         1338688    1943550085     22       2027-06-16 18:03:25  2027-06-16 19:25:08
10.110.21.37   203.0.113.192  443      6         1312062    1904889230     65       2027-06-16 18:03:25  2027-06-16 19:25:08
10.110.21.37   192.0.2.80     443      6         425296     612430118      22       2027-06-16 18:22:10  2027-06-16 19:05:41
10.110.21.37   10.110.40.15   5432     6         116224     9762816        30       2027-06-16 18:05:00  2027-06-16 18:19:58
```

**Cara membaca hasil:**

- Baris teratas bukan unggahan ke luar, melainkan hasil kueri database yang dikirim `jab-rpt-db01` ke worker antara 01:05 dan 01:20 WIB. Angkanya dobel: transfer yang sama tercatat di ENI database (keluar) dan di ENI worker (masuk), masing-masing 15 rekaman per menit dan 1.187.664.210 byte. Pasangan internal antar dua instance di VPC yang sama selalu muncul dua kali di flow log level VPC.
- Baris kedua sampai keempat adalah satu unggahan yang sama, terlihat di tiga titik: kaki 1 dan kaki 2 di ENI NAT (22 rekaman: 5 jendela unggahan ditambah 17 check-in di jendela kueri), dan ENI worker (65 rekaman: 48 menit unggahan ditambah 17 check-in). Menjumlahkan ketiganya memberi sekitar 5,8 GB, tiga kali lipat yang sebenarnya.
- Selisih baris ketiga dan keempat (38.660.855 byte dan 26.626 paket) adalah menit yang hilang di ENI worker karena `SKIPDATA` (bagian 2.4).
- Baris kelima adalah unggahan laporan PDF yang sah ke bucket S3 `jab-billing-reports` lewat gateway VPC endpoint. Alamat S3 di contoh ini memakai rentang dokumentasi; di data nyata alamatnya dari rentang AWS, dan format bawaan tidak bisa menandainya sebagai S3, sedangkan `pkt-dst-aws-service` (versi 5) akan menulis `S3` [S1].

Aturan praktis dari keluaran ini: kelompokkan juga per `interface_id`, atau pilih satu titik ukur per pertanyaan. Untuk volume keluar ke internet lewat NAT, titik ukurnya kaki 2 di ENI NAT. Untuk volume per instance, titik ukurnya ENI instance dengan `srcaddr` sama dengan alamat instance.

Mencari upaya koneksi yang ditolak secara bertubi-tubi, padanan Day 04 di cloud:

```sql
SELECT srcaddr, count(DISTINCT dstport) AS port_berbeda, count(*) AS upaya
FROM vpc_flow_logs
WHERE action = 'REJECT'
  AND start >= to_unixtime(timestamp '2026-10-02 00:00:00')
GROUP BY 1
HAVING count(DISTINCT dstport) > 20
ORDER BY upaya DESC;
```

Untuk PT JAB, ganti filter waktu dengan `"date" = DATE '2027-06-16'`. Keluaran ilustrasi:

```
srcaddr       port_berbeda  upaya
192.0.2.44    1000          1000
192.0.2.71    64            128
```

**Cara membaca hasil:** kedua sumber adalah alamat internet yang menyapu `jab-bastion01`, kebisingan biasa bagi alamat publik mana pun. Worker tidak muncul: penolakan untuk worker setelah karantina hanya ke satu port tujuan (443), sehingga tidak melewati ambang `HAVING`. Kueri ini mencari pemindaian, bukan percobaan berulang ke satu tujuan; untuk yang kedua, lihat bagian 2.5.

**Kapan gagal:** REJECT juga muncul untuk paket yang tiba setelah koneksi ditutup [S1], jadi ambang rendah di port populer bisa menangkap klien biasa. Network ACL yang stateless menghasilkan REJECT di arah balasan walaupun permintaannya diterima, seperti contoh ping di dokumentasi AWS [S6]; satu ACCEPT yang diikuti REJECT di arah sebaliknya biasanya masalah ACL, bukan serangan.

### 2.3 Dari NAT gateway ke instance

Artefak ketiga menjawab pertanyaan 3 untuk host nyata: instance mana yang mengirim 1,94 GB itu.

**Tujuan:** menautkan rekaman kaki 2 di ENI NAT ke instance pengirim, lalu ke nama sumber daya, tanpa `pkt-*`.

Langkahnya ada tiga. Pertama, ambil kaki 1 di ENI NAT yang punya port tujuan sama dan paket serta byte sama dengan kaki 2 di jendela yang sama. Kedua, konfirmasi dari ENI instance itu sendiri, yang mencatat alamat instance dan alamat internet di baris yang sama (bagian 1.3). Ketiga, terjemahkan alamat privat ke instance.

```sql
-- kaki 1 dan kaki 2 di ENI NAT yang angkanya sama per jendela
SELECT k1.srcaddr AS instance, k2.dstaddr AS tujuan, k2.dstport,
       k1.start, k1.packets, k1.bytes
FROM vpc_flow_logs k1
JOIN vpc_flow_logs k2
  ON  k1.interface_id = k2.interface_id
  AND k1.start BETWEEN k2.start - 60 AND k2.start + 60
  AND k1.packets = k2.packets
  AND k1.bytes = k2.bytes
WHERE k1."date" = DATE '2027-06-16' AND k2."date" = DATE '2027-06-16'
  AND k1.interface_id = 'eni-0f3a9c27b1d84e605'
  AND k1.dstaddr = '10.110.0.37'
  AND k2.srcaddr = '10.110.0.37'
  AND k2.dstaddr = '203.0.113.192'
ORDER BY k1.start;
```

Penjelasan tiap bagian:

- `k1` adalah kaki 1 (tujuan `dstaddr` alamat privat NAT), `k2` adalah kaki 2 (sumber `srcaddr` alamat privat NAT).
- Penautan memakai kesamaan paket dan byte, ditambah toleransi `start` 60 detik [S1]. Untuk unggahan besar, kecocokan angka sampai satuan byte praktis unik. Untuk koneksi kecil yang ukurannya seragam, misalnya check-in 9 paket dan 2.184 byte, banyak pasangan bisa cocok sekaligus; penautan seperti itu hanya kuat bila hanya satu instance yang berbicara ke tujuan itu.

Keluaran ilustrasi (lima baris unggahan; baris check-in dipotong):

```
instance      tujuan         dstport  start       packets  bytes
10.110.21.37  203.0.113.192  443      1813170060  249630   362457157
10.110.21.37  203.0.113.192  443      1813170600  274955   399224401
10.110.21.37  203.0.113.192  443      1813171200  275606   400171652
10.110.21.37  203.0.113.192  443      1813171800  277624   403101538
10.110.21.37  203.0.113.192  443      1813172400  260720   378558209
```

Langkah ketiga menerjemahkan alamat privat ke sumber daya. Alamat privat bisa dipakai ulang setelah instance dihentikan, jadi terjemahan dilakukan untuk waktu kejadian, bukan hanya keadaan sekarang:

```
aws ec2 describe-network-interfaces --region ap-southeast-3 \
    --filters Name=addresses.private-ip-address,Values=10.110.21.37 \
    --query 'NetworkInterfaces[].[NetworkInterfaceId,Attachment.InstanceId,InterfaceType,Description]'
```

Keluaran ilustrasi:

```
[
    [
        "eni-07c2d1e9a4b3f8a21",
        "i-0b8e2f4c71d9a3065",
        "interface",
        "jab-rpt-worker01 primary"
    ]
]
```

**Cara membaca hasil:** kelima jendela kaki 1 menyebut `10.110.21.37`, dan ENI itu milik `i-0b8e2f4c71d9a3065` (`jab-rpt-worker01`). ENI worker sendiri mencatat 65 rekaman ke `203.0.113.192:443` di jendela kueri bagian 2.2, jadi kesimpulan tidak bergantung pada penautan angka saja. Untuk masa lalu yang lebih jauh, riwayat pemasangan ENI dan alamat dibaca dari log audit API (CloudTrail), di luar cakupan Day ini; nama filter `describe-network-interfaces` dicek di dokumentasi CLI versi-mu.

Versi kueri dengan alamat tingkat paket dari catatan sebelumnya:

```sql
SELECT pkt_srcaddr AS sumber_asli, srcaddr AS antarmuka,
       dstaddr, dstport, sum(bytes) AS byte
FROM vpc_flow_logs
WHERE flow_direction = 'egress'
  AND pkt_srcaddr <> srcaddr
GROUP BY 1,2,3,4
ORDER BY byte DESC
LIMIT 50;
```

Kondisi `pkt_srcaddr <> srcaddr` tepat menyaring alur yang melewati lapis perantara seperti NAT gateway [S1]. Perlu dibaca dengan contoh resmi di tangan [S6]: di ENI NAT zonal, baris yang lolos kondisi ini adalah kaki balasan dari NAT ke instance (sumber asli alamat internet, antarmuka alamat NAT, tujuan alamat instance), sedangkan di ENI transit gateway yang lolos adalah kaki permintaan (sumber asli klien di VPC lain). Hasilnya menjawab pertanyaan yang tidak bisa dijawab format bawaan: siapa sebenarnya di ujung lain perantara. Untuk pertanyaan "instance mana mengirim ke alamat internet X lewat NAT", kondisi yang tepat ada di kaki 1:

```sql
SELECT srcaddr AS instance, pkt_dstaddr AS tujuan_internet, dstport,
       sum(bytes) AS byte, count(*) AS rekaman
FROM vpc_flow_logs_v5
WHERE "date" = DATE '2027-06-17'
  AND interface_id = 'eni-0f3a9c27b1d84e605'
  AND dstaddr = '10.110.0.37'
  AND pkt_dstaddr <> dstaddr
GROUP BY 1,2,3
ORDER BY byte DESC
LIMIT 50;
```

Di PT JAB, kueri ini baru bisa berjalan atas flow log kustom yang dibuat Kamis 04:10 (bagian 2.5), setelah worker dikarantina; keluarannya hanya memuat instance lain yang mengambil pembaruan paket lewat NAT, dan `10.110.21.37` tidak muncul lagi.

- **Kapan gagal:** field ini hanya ada bila kamu memakai format kustom yang menyertakannya [S1]. Bila tidak ada, catat sebagai celah dan ubah konfigurasinya untuk ke depan.

### 2.4 `SKIPDATA` dan menghitung volume yang hilang: `SOC-2027-0681`

Artefak keempat menjawab pertanyaan 4: berapa persisnya yang keluar, termasuk menit yang tidak tercatat.

**Tujuan:** menemukan rekaman `SKIPDATA` di jendela kejadian, menilai dampaknya, dan mengisi celahnya dari titik ukur kedua.

Rule di balik `SOC-2027-0681`:

```
index=aws sourcetype=aws:cloudwatchlogs:vpcflow log_status=SKIPDATA earliest=-60m@m latest=-20m@m
| eval mulai=strftime(start, "%Y-%m-%d %H:%M:%S"), selesai=strftime('end', "%Y-%m-%d %H:%M:%S")
| table _time interface_id mulai selesai log_status
```

Keluaran ilustrasi:

```
_time                interface_id           mulai                selesai              log_status
06/17/2027 01:47:00  eni-07c2d1e9a4b3f8a21  2027-06-17 01:47:00  2027-06-17 01:48:00  SKIPDATA
```

Baris mentahnya sama bentuknya dengan contoh resmi [S6]:

```
2 310582746193 eni-07c2d1e9a4b3f8a21 - - - - - - - 1813171620 1813171680 - SKIPDATA
```

Lalu bandingkan dua titik ukur per jendela 10 menit. Port sumber dipakai untuk memisahkan unggahan dari check-in: 51874 di ENI worker dan 30419 hasil translasi di kaki 2 NAT.

```
index=aws sourcetype=aws:cloudwatchlogs:vpcflow earliest="06/17/2027:01:20:00" latest="06/17/2027:02:10:00"
    ((interface_id=eni-07c2d1e9a4b3f8a21 srcaddr=10.110.21.37 dstaddr=203.0.113.192 srcport=51874)
  OR (interface_id=eni-0f3a9c27b1d84e605 srcaddr=10.110.0.37 dstaddr=203.0.113.192 srcport=30419))
| eval titik=if(interface_id="eni-07c2d1e9a4b3f8a21", "worker", "nat_kaki2")
| bin _time span=10m
| chart sum(bytes) OVER _time BY titik
| addcoltotals labelfield=_time label=TOTAL
```

Keluaran ilustrasi:

```
_time                nat_kaki2     worker
06/17/2027 01:20:00  362457157     362457157
06/17/2027 01:30:00  399224401     399224401
06/17/2027 01:40:00  400171652     361510797
06/17/2027 01:50:00  403101538     403101538
06/17/2027 02:00:00  378558209     378558209
TOTAL                1943512957    1904852102
```

**Cara membaca hasil:**

- Empat dari lima jendela sama persis antara dua titik. Itu sekaligus uji bahwa keduanya mengukur hal yang sama, dan bahwa NAT tidak mengubah ukuran paket.
- Jendela 01:40 berbeda 38.660.855 byte, tepat menit 01:47 yang `SKIPDATA` di ENI worker. Paketnya: 275.606 di NAT dikurangi 248.980 di worker sama dengan 26.626 paket.
- Volume unggahan yang dilaporkan: 1.943.512.957 byte dan 1.338.535 paket di tingkat IP, dalam satu koneksi TCP dari 01:21:00 sampai 02:09:59 WIB (49 menit, rata-rata sekitar 5,3 Mbps). Bila 52 byte per paket dianggap header IP dan TCP, data TCP sekitar 1.873.909.137 byte (sekitar 1,87 GB); overhead TLS menguranginya sedikit lagi (Day 12 bagian 1.8).
- Laporan tetap menyebut `SKIPDATA`: angka 01:47 diambil dari titik ukur kedua, bukan dari ENI worker.

**Variasi:** bila tidak ada titik ukur kedua (misalnya trafik internal antar instance tanpa NAT), sebut rentang: volume minimal adalah jumlah rekaman yang ada, dan menit yang hilang diperkirakan dari rata-rata menit di sekitarnya dengan label perkiraan. Satu rekaman `SKIPDATA` bisa mewakili lebih dari satu alur [S6], jadi jangan menganggap hanya satu koneksi yang hilang.

**Kapan gagal:** bila `SKIPDATA` muncul di kedua titik, atau di ENI NAT yang menjadi titik ukur utama, celahnya tidak bisa diisi dari flow log. Rekaman yang dilewati juga membuat jumlah rekaman di AWS Cost Explorer lebih besar daripada yang benar-benar diterbitkan [S1]; selisih itu bukan tanda data dihapus orang.

### 2.5 Flow log kedua dengan format kustom dan `tcp-flags`

Artefak kelima menjawab sisa pertanyaan 3: setelah karantina, apakah proses di worker masih mencoba keluar, dan ke mana.

**Tujuan:** menambah field yang tidak ada di format bawaan untuk sisa kejadian, lalu membedakan upaya koneksi dari koneksi yang terbentuk.

Karena flow log tidak bisa diubah [S7], Lutfi membuat flow log kedua untuk VPC yang sama pada Kamis 04:10 WIB. Urutan field dipilih sama dengan DDL contoh Athena untuk versi 2 sampai 5 [S8], yang juga merupakan urutan format kustom yang dikenali add-on Splunk [S9]:

```
aws ec2 create-flow-logs --region ap-southeast-3 \
    --resource-type VPC --resource-ids vpc-0a7e51c2d9f3b4e10 \
    --traffic-type ALL --max-aggregation-interval 60 \
    --log-destination-type s3 \
    --log-destination arn:aws:s3:::jab-vpcflow-310582746193/v5/ \
    --log-format '${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status} ${vpc-id} ${subnet-id} ${instance-id} ${tcp-flags} ${type} ${pkt-srcaddr} ${pkt-dstaddr} ${region} ${az-id} ${sublocation-type} ${sublocation-id} ${pkt-src-aws-service} ${pkt-dst-aws-service} ${flow-direction} ${traffic-path}'
```

Penjelasan tiap bagian:

- `--max-aggregation-interval 60` memberi rekaman per menit untuk semua antarmuka, termasuk ENI NAT yang sebelumnya 10 menit.
- `--log-format` memakai sintaks `${field}`; versi rekaman menjadi 5 karena field tertinggi berasal dari versi 5 [S1].
- Prefiks `v5/` memisahkan data baru dari data lama, supaya tabel Athena dan input Splunk tidak mencampur dua format. Flow log lama tetap berjalan sampai keputusan bagian 2.10.
- Data baru baru muncul setelah ada trafik di antarmuka yang dicakup [S7].

Satu rekaman dari ENI worker setelah karantina:

```
5 310582746193 eni-07c2d1e9a4b3f8a21 10.110.21.37 203.0.113.192 51990 443 6 3 180 1813180867 1813180870 REJECT OK vpc-0a7e51c2d9f3b4e10 subnet-0d21c6a8e5f7b9341 i-0b8e2f4c71d9a3065 2 IPv4 10.110.21.37 203.0.113.192 ap-southeast-3 apse3-az1 - - - - egress -
```

Baris ini dibaca: Kamis 04:21:07 WIB, worker mengirim 3 paket berjumlah 180 byte (tiga SYN 60 byte, yaitu satu SYN dan dua pengulangan) ke `203.0.113.192:443`, ditolak security group karantina; `tcp-flags` 2 berarti hanya SYN; `instance-id` kini terisi; `traffic-path` `-` karena trafiknya tidak pernah keluar (nilai ini dicek di lab-mu).

Kueri dari catatan versi sebelumnya untuk membedakan upaya dari koneksi:

```sql
SELECT srcaddr, dstaddr, dstport,
       sum(CASE WHEN tcp_flags = 2 THEN 1 ELSE 0 END)  AS hanya_syn,
       sum(CASE WHEN tcp_flags = 18 THEN 1 ELSE 0 END) AS syn_ack,
       sum(CASE WHEN tcp_flags = 4 THEN 1 ELSE 0 END)  AS rst
FROM vpc_flow_logs
WHERE protocol = 6
GROUP BY 1,2,3
HAVING sum(CASE WHEN tcp_flags = 2 THEN 1 ELSE 0 END) > 0
ORDER BY hanya_syn DESC;
```

Untuk PT JAB, ganti tabel dengan `vpc_flow_logs_v5` dan tambahkan `AND "date" BETWEEN DATE '2027-06-16' AND DATE '2027-06-17' AND srcaddr = '10.110.21.37'`. Keluaran ilustrasi:

```
srcaddr        dstaddr        dstport  hanya_syn  syn_ack  rst
10.110.21.37   203.0.113.192  443      84         0        0
10.110.21.37   203.0.113.193  443      84         0        0
```

Cara membacanya: pasangan dengan banyak SYN tanpa SYN-ACK adalah pemindaian atau layanan yang tidak merespons. Di sini penyebabnya diketahui: security group karantina menolak semua trafik keluar, dan proses di worker mencoba lagi sekitar setiap lima menit dari 04:21 sampai 11:18 WIB, saat instance dihentikan setelah akuisisi memori oleh IR. Setiap kali `203.0.113.192` gagal, proses itu mencoba `203.0.113.193` sekitar dua detik kemudian. Sebelum karantina, `.193` tidak pernah dihubungi dari AWS karena `.192` selalu berhasil. Perilaku "coba alamat kedua bila yang pertama gagal" ini sama persis dengan yang terlihat di Azure (bagian 2.6).

Ingat bahwa flag bisa digabung dengan OR selama interval, sehingga koneksi pendek bisa muncul sebagai nilai gabungan seperti 19 atau 3 [S1]. Jangan memakai kecocokan persis untuk analisis yang menentukan. Untuk menghitung koneksi yang terbentuk, versi yang lebih tahan memakai operasi bit, misalnya `bitwise_and(tcp_flags, 2) > 0` untuk "ada SYN", dan memeriksa nilai 18 atau 19 di arah balik.

**Kapan gagal:** paket yang ditolak network ACL di arah balik dan koneksi yang sudah ditutup juga menghasilkan REJECT [S1][S6]; `tcp-flags` hanya ada untuk TCP; dan rekaman dengan kombinasi flag tidak valid bernilai `-` [S1], yang membuat `tcp_flags = 2` bernilai null, bukan salah.

### 2.6 Mengurai flow tuple Azure: `SOC-2027-0682`

Artefak keenam menjawab pertanyaan 5 untuk `jab-az-batch01`: apa yang dicoba VM itu, dan apakah ada yang lolos.

**Tujuan:** mengubah JSON bersarang VNet flow logs menjadi tabel satu baris per tuple, lalu menghitung per tujuan, rule, dan state.

Potongan event dari storage account (satu elemen `records`, dipersingkat):

```json
{
  "time": "2027-06-16T07:08:41.1873301Z",
  "flowLogVersion": 4,
  "macAddress": "7C1E52A04D19",
  "category": "FlowLogFlowEvent",
  "targetResourceID": "/subscriptions/.../resourceGroups/rg-jab-net-idc/providers/Microsoft.Network/virtualNetworks/vnet-jab-prod-idc",
  "operationName": "FlowLogFlowEvent",
  "flowRecords": {
    "flows": [
      {
        "aclID": "6f1d2c3b-...",
        "flowGroups": [
          {
            "rule": "UserRule_Deny-Internet-Out",
            "flowTuples": [
              "1813129672000,10.120.2.14,203.0.113.192,50412,443,6,O,D,NX,0,0,0,0",
              "1813129673514,10.120.2.14,203.0.113.193,50414,443,6,O,D,NX,0,0,0,0"
            ]
          }
        ]
      }
    ]
  }
}
```

Kode Python dari catatan versi sebelumnya, dengan satu koreksi untuk satuan waktu (bagian 1.7):

```python
import json, pandas as pd

kolom = ["ts","src","dst","sport","dport","proto","arah","state","enc",
         "pkt_kirim","byte_kirim","pkt_terima","byte_terima"]

baris = []
for rec in json.load(open("vnetflow.json"))["records"]:
    for flow in rec["flowRecords"]["flows"]:
        for grup in flow["flowGroups"]:
            for t in grup["flowTuples"]:
                nilai = t.split(",")
                baris.append(dict(zip(kolom, nilai),
                                  rule=grup["rule"],
                                  target=rec["targetResourceID"]))

df = pd.DataFrame(baris)
for k in ("pkt_kirim","byte_kirim","pkt_terima","byte_terima"):
    df[k] = pd.to_numeric(df[k], errors="coerce").fillna(0)
ts = df["ts"].astype("int64")
satuan = "ms" if ts.max() > 10**11 else "s"   # 13 digit = milidetik, 10 digit = detik
df["waktu"] = pd.to_datetime(ts, unit=satuan, utc=True)
```

- Struktur bersarangnya empat lapis, dan baris `rule` serta `targetResourceID` diambil dari lapis luar supaya tiap baris tahu asal dan kebijakannya [S2].
- Nilai kosong muncul pada state `B` yang memang tanpa statistik [S2], karena itu `errors="coerce"` dipakai.
- Baris `satuan` adalah koreksinya. Versi lama memakai `unit="s"` untuk semua data; dengan tuple 13 digit seperti contoh JSON resmi [S2] dan data PT JAB, hasilnya tanggal yang mustahil atau galat overflow.

Menghitung volume satu percakapan dengan benar:

```python
percakapan = (df.groupby(["src","dst","sport","dport","proto"])
                [["pkt_kirim","byte_kirim","pkt_terima","byte_terima"]].sum()
                .sort_values("byte_kirim", ascending=False))
```

Penjumlahan dilakukan atas semua state, bukan hanya `E`, sesuai aturan agregat sejak tuple sebelumnya [S2]. Keluaran ilustrasi untuk koneksi sah `jab-az-batch01` ke database `jab-az-db01` (`10.120.5.20:5432`), yang tercatat dengan tuple `B`, dua `C`, dan `E`:

```
                                             pkt_kirim  byte_kirim  pkt_terima  byte_terima
src         dst         sport  dport proto
10.120.2.14 10.120.5.20 50322  5432  6            2713      221132       22273     31337280
```

Bila hanya baris `E` yang dijumlahkan, hasilnya 311 paket dan 25.380 byte terkirim serta 2.540 paket dan 3.571.948 byte diterima, sekitar sepersembilan dari angka sebenarnya.

Mencari trafik yang ditolak dan rule yang menolaknya:

```python
ditolak = (df[df["state"] == "D"]
           .groupby(["rule","src","dport"]).size()
           .sort_values(ascending=False).head(30))
```

Versi Splunk yang dipakai rule `SOC-2027-0682` (path JSON dicek dengan satu event contoh di instance-mu):

```
index=azure sourcetype=mscs:vnet:flow earliest="06/16/2027:14:00:00" latest="06/17/2027:08:00:00"
| spath path=flowRecords.flows{}.flowGroups{} output=grp
| mvexpand grp
| spath input=grp path=rule output=rule
| spath input=grp path=flowTuples{} output=tuple
| mvexpand tuple
| eval f=split(tuple, ",")
| eval ts=tonumber(mvindex(f,0)), src=mvindex(f,1), dst=mvindex(f,2), dport=mvindex(f,4), arah=mvindex(f,6), state=mvindex(f,7)
| eval ts=if(ts > 100000000000, ts/1000, ts)
| where src="10.120.2.14" AND arah="O" AND NOT cidrmatch("10.0.0.0/8", dst)
| stats count min(ts) AS pertama max(ts) AS terakhir values(state) AS state BY rule dst dport
| eval pertama=strftime(pertama, "%m/%d %H:%M:%S"), terakhir=strftime(terakhir, "%m/%d %H:%M:%S")
```

Penjelasan tiap bagian:

- Dua `spath` dan dua `mvexpand` membuka lapis `flowGroups` lalu `flowTuples`; `rule` diambil sebelum tuple dipecah supaya tetap menempel ke tiap baris.
- `split` memecah tuple sesuai urutan kolom bagian 1.7; indeks dimulai dari 0.
- `eval ts=if(...)` menangani satuan milidetik, sama dengan versi Python.
- Filter `cidrmatch` membuang tujuan internal sehingga yang tersisa trafik ke luar.

Keluaran ilustrasi:

```
rule                        dst            dport  count  pertama         terakhir        state
UserRule_Deny-Internet-Out  203.0.113.192  443    215    06/16 14:07:52  06/17 07:57:41  D
UserRule_Deny-Internet-Out  203.0.113.193  443    215    06/16 14:07:53  06/17 07:57:43  D
```

**Cara membaca hasil:**

- 430 tuple `D`: 215 percobaan, masing-masing ke `.192` lalu sekitar 1,5 detik kemudian ke `.193`. Percobaan pertama dua menit setelah deploy Azure pukul 14:05.
- Tidak ada state `B`, `C`, atau `E` ke kedua alamat, jadi tidak ada satu koneksi pun yang terbentuk dari Azure. Rule NSG `Deny-Internet-Out` di `nsg-snet-batch` bekerja; batch Azure tidak menjalankan laporan malam itu, tetapi seandainya menjalankan, unggahannya juga akan ditolak.
- Kolom enkripsi `NX` tidak berarti koneksinya tanpa TLS; itu status enkripsi virtual network (bagian 1.7).
- Format nama rule (`UserRule_` untuk rule buatan, `DefaultRule_` untuk rule bawaan) dicek di data-mu; contoh resmi VNet flow logs hanya memperlihatkan rule bawaan dan nama rule tanpa awalan [S2].

**Variasi:** ganti filter ke `state="D" AND arah="I"` untuk melihat percobaan masuk yang ditolak; ganti `BY rule dst dport` dengan `BY rule` untuk melihat rule mana yang paling sering menolak di seluruh VNet.

**Kapan gagal:** tuple dari layanan yang tidak didukung tidak pernah ada (bagian 1.8); event yang dipotong saat ingest membuat `spath` gagal diam-diam, jadi bandingkan jumlah tuple dengan hitungan di blob untuk satu jam contoh.

### 2.7 Log ganda dan cakupan Azure: `SOC-2027-0684`

Artefak ketujuh menjawab sisa pertanyaan 5: kenapa volume index `azure` melonjak sejak Selasa.

**Tujuan:** membuktikan bahwa lonjakan berasal dari pencatatan ganda, bukan dari trafik baru, dan memutuskan apa yang dimatikan.

```
index=azure (sourcetype=mscs:nsg:flow OR sourcetype=mscs:vnet:flow) earliest="06/14/2027:00:00:00" latest="06/18/2027:00:00:00"
| eval gb=len(_raw)/1024/1024/1024
| timechart span=1d sum(gb) BY sourcetype
```

Keluaran ilustrasi (GiB per hari):

```
_time       mscs:nsg:flow  mscs:vnet:flow
2027-06-14  2.1            0
2027-06-15  1.9            2.0
2027-06-16  1.9            2.7
2027-06-17  1.9            2.8
```

Lalu bandingkan satu VM di subnet yang dicakup keduanya, `jab-az-app01` (`10.120.1.10`), untuk satu jam Rabu 10:00 sampai 11:00. Tuple NSG versi 2 memakai `T`/`U` dan kolom keputusan terpisah, sedangkan tuple VNet memakai nomor protokol (bagian 1.6), jadi kunci perbandingannya disamakan dulu: waktu dibulatkan ke menit, lalu sumber, tujuan, port, dan protokol dalam bentuk angka. Hasil ilustrasi: 41.220 tuple dari `mscs:nsg:flow` dan 41.226 dari `mscs:vnet:flow`, dengan 41.208 kunci sama di keduanya.

**Cara membaca hasil:**

- Lonjakan sejak Selasa hampir seluruhnya berasal dari subnet `snet-app` yang kini tercatat dua kali, persis kemungkinan yang disebut dokumentasi: log ganda atau hanya VNet flow logs [S2].
- Selisih kecil antar keduanya wajar: VNet flow logs mencatat hal yang tidak dicatat NSG flow logs, seperti byte alur stateless [S2], dan kedua pencatat tidak menutup jendela menit di titik yang persis sama.
- Keputusan yang diusulkan: matikan NSG flow logs di `nsg-snet-app` sesuai anjuran dokumentasi [S2], biarkan blob lama mengikuti retensinya (Azure tidak menghapus rekaman yang sudah tersimpan saat fitur pensiun [S3]), dan pindahkan saved search yang masih membaca `mscs:nsg:flow`. Rule lama yang memfilter protokol `T` tidak akan pernah cocok dengan data VNet yang memakai angka 6.

**Kapan gagal:** NSG yang dipasang di subnet dan di NIC sekaligus membuat NSG flow logs mencatat alur di NSG yang diproses terakhir, dan urutannya bergantung platform [S3]; untuk lingkungan seperti itu, perbandingan dua sumber harus memeriksa kedua NSG.

### 2.8 Jangkar dari kantor: `SOC-2027-0683` dan nama domain yang tidak ada di cloud

Artefak kedelapan menjawab sebagian pertanyaan 6 dengan contoh nyata: nama domain tujuan tidak ada di data AWS maupun Azure, dan akhirnya ditemukan di sensor kantor.

Pukul 10:00 Kamis, `203.0.113.192` dan `203.0.113.193` dimasukkan ke lookup IOC, dan retro-hunt otomatis atas `index=proxy` 30 hari terakhir berbunyi pukul 10:40.

**Tujuan:** mencari jejak tujuan yang sama di jaringan kantor, untuk mendapat nama domain, waktu berresolusi detik, dan URI yang tidak pernah tercatat di flow log.

```
index=proxy (url="*203.0.113.192*" OR url="*203.0.113.193*" OR url="*pdfkit-cdn.example*") earliest="05/18/2027:00:00:00" latest="06/17/2027:10:40:00"
| stats count min(_time) AS pertama max(_time) AS terakhir values(method) AS method values(url) AS url values(tls) AS tls values(http_user_agent) AS ua BY src user
| convert ctime(pertama) ctime(terakhir)

index=zeek sourcetype=bro:dns:json query="ingest.pdfkit-cdn.example" earliest="06/16/2027:13:00:00" latest="06/16/2027:14:00:00"
| table _time id.orig_h query qtype_name answers TTLs
```

Penjelasan tiap bagian:

- Kueri pertama memakai logformat proxy PT JAB (`src`, `user`, `method`, `url`, `tls` berisi `splice` atau `bump`). Domain baru yang tidak terkategori di-bump, sehingga URL lengkap tercatat.
- Kueri kedua membaca `dns.log` hop core. Karena proxy eksplisit, query DNS berasal dari proxy (`10.20.3.60`), bukan dari workstation. Sourcetype `bro:dns:json` mengikuti pola TA for Zeek dan divalidasi dengan `| metadata` seperti di Day 08.

Keluaran ilustrasi:

```
src           user           count  pertama              terakhir             method          url                                                              tls   ua
10.10.60.171  reza.maulana   8      06/16/2027 13:22:05  06/16/2027 13:41:02  CONNECT POST    ingest.pdfkit-cdn.example:443 https://ingest.pdfkit-cdn.example/v2/collect  bump  pdfx-fontcache/3.2.1

_time                id.orig_h   query                      qtype_name  answers                        TTLs
06/16/2027 13:22:04  10.20.3.60  ingest.pdfkit-cdn.example  A           203.0.113.192,203.0.113.193    60,60
```

**Cara membaca hasil:**

- `JKT-WS-2081` (`10.10.60.171`) milik Reza Maulana, engineer DevOps tim Lutfi. Empat `CONNECT` dan empat `POST` ke `/v2/collect` (8 baris) antara 13:22:05 dan 13:41:02 WIB Rabu, dengan User-Agent yang menyebut nama library. Itu sesi uji lokal sebelum Reza me-merge pembaruan dependency pukul 13:45; image dibangun dan di-deploy pukul 14:05.
- Nama domain, path URI, dan User-Agent hanya ada di sini. Flow log AWS tidak mencatat query worker ke resolver bawaan VPC [S7], PT JAB belum mengaktifkan Resolver query logging [S12], dan VNet flow logs tidak memuat nama.
- Jawaban DNS dengan dua alamat dan TTL 60 menjelaskan perilaku "coba `.192`, lalu `.193`" di bagian 2.5 dan 2.6.
- Waktu dari proxy dan Zeek berresolusi detik atau lebih halus. Untuk timeline, sesi uji di kantor menjadi jangkar waktu yang lebih kuat daripada `start` flow log mana pun (bagian 1.5).

Keputusan untuk `SOC-2027-0683`: dimasukkan ke lingkup `INC-2027-076` sebagai host terkait, bukan host terkompromi; virtualenv proyek di `JKT-WS-2081` diperiksa IR, dan library dihapus. Isolasi tidak dilakukan karena kiriman dari workstation hanya empat POST uji dan tidak ada koneksi lain ke kedua alamat setelah Rabu 13:41.

**Kapan gagal:** tujuan yang hanya dihubungi dari cloud tidak pernah muncul di sensor kantor; tanpa sesi uji Reza, nama domain baru akan diketahui dari pemeriksaan kode library oleh Lutfi, bukan dari data jaringan.

### 2.9 Merangkai `INC-2027-076`: beacon, volume, dan batas kesimpulan

Artefak kesembilan menjawab pertanyaan 7: analisis Day 10 sampai 12 dijalankan di atas flow log, lalu dibatasi dengan jujur.

**Tujuan:** mengukur keteraturan check-in, menghitung volume dan arah unggahan, lalu menyusun timeline dengan sumber tiap baris.

Check-in dari AWS diukur dari `start` rekaman kecil di ENI worker, dengan pola interval Day 11 bagian 1.3:

```
index=aws sourcetype=aws:cloudwatchlogs:vpcflow interface_id=eni-07c2d1e9a4b3f8a21 srcaddr=10.110.21.37 dstaddr=203.0.113.192 bytes<10000
    earliest="06/16/2027:14:00:00" latest="06/17/2027:03:40:00"
| sort 0 start
| streamstats current=f last(start) AS sebelumnya
| eval delta=start-sebelumnya
| stats count(delta) AS n median(delta) AS median avg(delta) AS rata stdev(delta) AS sd min(delta) AS min max(delta) AS max
| eval cv=round(sd/rata, 3)
```

Keluaran ilustrasi, ditambah hasil kueri yang sama atas waktu tuple `D` ke `.192` di Azure:

```
sumber             n    median  rata    sd     min    max    cv
AWS start          162  298     300.18  52.90  175    418    0.176
Azure tuple (ms)   214  299.3   299.95  16.58  270.7  329.7  0.055
```

**Cara membaca hasil:**

- Kedua sumber melihat perilaku yang sama: 163 check-in dari AWS (Rabu 14:05:41 sampai Kamis 03:36:14 WIB) dan 215 percobaan dari Azure, keduanya sekitar setiap 300 detik. Dengan jitter plus minus 10%, CV sebenarnya sekitar 0,06, dan tuple Azure yang bertimestamp milidetik memberi 0,055.
- CV dari `start` AWS 0,176, hampir tiga kali lipat, karena `start` bisa meleset sampai 60 detik [S1]. Selisih 175 dan 418 detik bukan jitter beacon, melainkan ketidakpastian timestamp. Nilai itu masih di bawah ambang 0,2 Day 11, tetapi beacon dengan jitter sedikit lebih besar akan lolos dari ambang hanya karena sumber datanya.
- Bila worker bukan instance Nitro dan setiap check-in memakai koneksi yang sama, rekaman 10 menit akan menggabungkan dua check-in menjadi satu dan analisis ini tidak bisa dilakukan sama sekali (bagian 1.9).

Volume dan arah unggahan (bagian 2.4) dirangkum dengan PCR seperti Day 12 bagian 1.3, dari 48 menit yang lengkap di ENI worker:

- Keluar 1.904.852.102 byte, masuk 34.108.880 byte, PCR (1.904.852.102 - 34.108.880) / (1.904.852.102 + 34.108.880) = 0,965: murni mengirim. Angka ini memakai byte tingkat IP, bukan byte aplikasi, jadi sedikit berbeda dari PCR yang dihitung dari `conn.log`.
- Total unggahan termasuk menit `SKIPDATA` adalah 1.943.512.957 byte (bagian 2.4).
- Sebelum unggahan, worker menerima 1.187.664.210 byte dari `jab-rpt-db01` (bagian 2.2) dan kemudian mengunggah 612.430.118 byte PDF ke S3. Jumlah keduanya 1.800.094.328 byte, dalam orde yang sama dengan unggahan ke `203.0.113.192`. Ini indikator bahwa unggahan bisa memuat hasil kueri database dan laporan, bukan bukti isinya.

Timeline yang dibawa ke rapat, dengan sumber tiap baris; waktu WIB:

| Waktu | Peristiwa | Sumber |
|---|---|---|
| Rabu 13:22:05 sampai 13:41:02 | `JKT-WS-2081` mengirim empat POST uji ke `ingest.pdfkit-cdn.example` | `index=proxy`, `dns.log` |
| Rabu 13:45 | Merge pembaruan `pdfx-fontcache` 3.2.1 di `billing/report-builder` | GitLab (Lutfi) |
| Rabu 14:05 | Deploy `report-worker:2027.06.16-1` ke AWS dan Azure | Pipeline (Lutfi) |
| Rabu 14:05:41 | Check-in pertama `jab-rpt-worker01` ke `203.0.113.192:443` | VPC Flow Logs, ENI worker (plus minus 60 detik) |
| Rabu 14:07:52 | Percobaan pertama `jab-az-batch01`, ditolak NSG | VNet flow logs |
| Kamis 01:05 sampai 01:20 | Worker membaca 1,19 GB dari `jab-rpt-db01` (job laporan bulanan) | VPC Flow Logs, ENI database dan worker |
| Kamis 01:21:00 sampai 02:09:59 | Unggahan 1.943.512.957 byte ke `203.0.113.192:443` | VPC Flow Logs, ENI worker dan ENI NAT |
| Kamis 01:47 | `SKIPDATA` di ENI worker | VPC Flow Logs |
| Kamis 02:31 dan 02:46 | `SOC-2027-0680`, `SOC-2027-0681` | Splunk |
| Kamis 03:05 | Rudi membuka `INC-2027-076` | Tiket |
| Kamis 03:40 | Worker dipindah ke security group karantina | Lutfi |
| Kamis 04:10 | Flow log kustom versi 5, interval 1 menit | Lutfi |
| Kamis 04:21 sampai 11:18 | 84 percobaan ke `.192` dan 84 ke `.193`, semuanya REJECT dengan `tcp-flags` 2 | VPC Flow Logs kustom |
| Kamis 08:15, 09:30, 10:40 | `SOC-2027-0682`, `SOC-2027-0684`, `SOC-2027-0683` | Splunk |
| Kamis 09:50 | Image dikembalikan ke versi sebelumnya di kedua cloud; `jab-az-batch01` dihentikan setelah snapshot disk | Lutfi |
| Kamis 11:18 | Worker dihentikan setelah akuisisi memori | IR |

Yang bisa dinyatakan dari data jaringan: satu instance AWS mengirim sekitar 1,94 GB di tingkat IP ke alamat yang tidak pernah dihubungi sebelumnya, setelah membaca data laporan dan dalam satu koneksi; instance yang sama dan VM Azure dengan image yang sama melakukan check-in teratur ke tujuan yang sama sejak deploy; tidak ada koneksi yang terbentuk dari Azure. Yang tidak bisa dinyatakan: isi unggahan, apakah datanya terenkripsi tambahan oleh library, dan siapa pengendali tujuan. Label kandidat untuk laporan: exfiltration lewat saluran yang sama dengan check-in (T1041, seperti Day 12 bagian 1.9), dengan library yang disusupi sebagai dugaan jalur masuk yang dibuktikan IR dari kode, bukan dari flow log. Penjelasan jinak yang sudah disingkirkan: tujuan bukan milik vendor PDF yang tercatat di kontrak, bukan penyedia penyimpanan PT JAB, dan library versi sebelumnya tidak pernah menghubungi alamat apa pun di luar S3.

### 2.10 Peta celah cloud dan jawaban untuk Dimas

Artefak terakhir menjawab pertanyaan 8, lalu merangkum semuanya untuk rapat 13:00.

Peta celah ini adalah lampiran tetap laporan `INC-2027-076`. Baca kolom kanan sebagai daftar keputusan yang perlu pemilik.

| Sumber atau jalur | Kondisi Jumat 2027-06-18 | Akibat untuk kasus ini | Usulan |
|---|---|---|---|
| VPC Flow Logs `fl-04c7a2e9b1d8f3a56` | Format bawaan v2, interval maks 10 menit | Tanpa `pkt-*`, `tcp-flags`, `instance-id`; ENI NAT per 10 menit | Pertahankan flow log kustom v5 interval 1 menit; hapus yang lama setelah 30 hari tumpang tindih |
| DNS di VPC | Query ke resolver bawaan tidak tercatat flow log [S7]; Resolver query logging belum aktif | Nama domain hanya didapat dari kantor | Aktifkan Resolver query logging ke S3 dan Splunk; ingat hanya query unik yang tercatat [S12] |
| Metadata instance, DHCP, Time Sync | Tidak tercatat flow log [S7] | Tidak diketahui apakah library menyentuh metadata | Jawaban dari log audit API dan host, bukan flow log |
| Isi paket di AWS | Tidak ada Traffic Mirroring | Isi unggahan tidak diketahui | Runbook mirror on-demand untuk subnet laporan (`m6i` termasuk tipe yang didukung [S11]); bukan mirror permanen |
| Egress AWS | Security group worker mengizinkan 443 ke mana pun | Unggahan berhasil | Batasi keluar ke prefiks S3 dan tujuan vendor terdaftar, seperti NSG Azure |
| VNet flow logs | Aktif sejak Selasa 2027-06-15 | Satu-satunya data `jab-az-batch01` (VM seri v6) | Pertahankan; tambahkan ke inventaris sumber bukti |
| NSG flow logs `nsg-snet-app` | Aktif bersamaan dengan VNet flow logs | Log ganda, `SOC-2027-0684` | Matikan setelah saved search dipindah; blob lama mengikuti retensi |
| Layanan Azure tanpa flow log | `func-jab-billing-notify` (Azure Functions) mengirim email tagihan | Tidak terlihat sama sekali [S2] | Catat di peta; log aplikasi sebagai pengganti |
| DNS di Azure | Tidak dicatat konfigurasi saat ini | Sama dengan AWS | Cek opsi log DNS di Azure; apakah trafik ke resolver Azure tercatat di VNet flow logs dicek di lab |

Ringkasan untuk Dimas, satu baris per pertanyaan; kolom kanan menunjuk bagian yang menjadi dasarnya.

| Pertanyaan | Jawaban singkat | Bagian |
|---|---|---|
| 1. Bukti jaringan di cloud | Hanya flow log penyedia (VPC Flow Logs, VNet flow logs, NSG flow logs lama); tidak ada pcap atau sensor | 1.1 |
| 2. Isi rekaman | Lima-tuple, paket, byte, waktu, ACCEPT atau REJECT, status per ENI per interval | 1.2, 2.1 |
| 3. Instance pengirim | Bukan dari baris ENI NAT; dari ENI worker dan penautan kaki 1 dan 2: `jab-rpt-worker01`; setelah karantina 84 SYN ke tiap alamat ditolak | 1.3, 1.4, 2.3, 2.5 |
| 4. Waktu dan volume | `start` bisa meleset 60 detik; 1.943.512.957 byte (sekitar 1,94 GB) dalam 49 menit, menit `SKIPDATA` diisi dari kaki 2 NAT | 1.5, 2.4 |
| 5. Azure | `jab-az-batch01` mencoba 215 kali, semua ditolak NSG; log dobel karena NSG flow logs dan VNet flow logs aktif bersamaan | 1.6, 1.7, 2.6, 2.7 |
| 6. Yang tidak tercatat | Isi paket, DNS ke resolver bawaan, metadata instance, layanan Azure tertentu; nama domain didapat dari proxy kantor | 1.8, 2.8 |
| 7. Beacon, exfil, isi data | Check-in sekitar 300 detik terukur; volume dan arah jelas; isi data tidak bisa dipastikan dari flow log, harus dari IR | 1.9, 2.9 |
| 8. Perubahan ke depan | Flow log kustom 1 menit, Resolver query logging, egress terbatas di AWS, runbook mirror, matikan NSG flow logs ganda | 2.10 |

## 3. Lab praktik

**Prasyarat:** akun AWS sandbox dengan batas biaya dan langganan Azure uji bila tersedia. Tanpa salah satunya, kerjakan bagian yang ada dan catat sisanya sebagai celah. Lab ini berjalan di akun cloud milikmu sendiri, terisolasi dari lingkungan kerja; tidak ada data PT JAB, tidak ada sampel malware, dan pemindaian hanya ke instance milikmu sendiri.

1. Aktifkan VPC Flow Logs dengan format bawaan ke S3, lalu bangun tabel Athena dengan partisi. Catat biaya dan jumlah data yang dipindai untuk satu kueri sederhana.
2. Hasilkan trafik yang kamu kendalikan: koneksi keluar yang diterima, upaya masuk yang ditolak, dan periode tanpa trafik. Temukan ketiganya di rekaman dan cocokkan dengan waktu sebenarnya.
3. Ukur selisih antara waktu aktivitas sebenarnya dan nilai `start` serta nilai waktu kedatangan log. Bandingkan dengan angka di bagian 1.5.
4. Ulangi langkah 1 dengan interval agregasi satu menit, lalu bandingkan jumlah rekaman dan biayanya.
5. Buat format kustom yang menyertakan `pkt-srcaddr`, `pkt-dstaddr`, `tcp-flags`, dan `flow-direction`. Lewatkan trafik melalui NAT gateway, lalu buktikan bahwa format bawaan tidak bisa menunjukkan instance asalnya.
6. Jalankan pemindaian port jinak terhadap instance uji milikmu sendiri, lalu temukan polanya dengan kueri bagian 2.5. Catat nilai `tcp-flags` yang muncul dan bandingkan dengan tabel di bagian 1.4.
7. Bila ada Azure: aktifkan virtual network flow logs, hasilkan trafik masuk yang ditolak dan trafik keluar yang diterima, lalu urai `flowTuples` dengan kode bagian 2.6.
8. Bila ada Azure: hitung volume satu percakapan dua kali, sekali dengan menjumlahkan semua state dan sekali hanya state `E`. Tulis selisihnya dan jelaskan kenapa.
9. Susun daftar celah untuk lingkunganmu: layanan yang tidak tercatat, jalur yang tidak tercatat, dan interval agregasi yang berlaku. Simpan sebagai lampiran tetap laporan cloud.
10. Jalankan satu analisis dari Day 11 atau Day 12 sepenuhnya di atas flow log, lalu tulis apa yang bisa dan tidak bisa kamu simpulkan tanpa isi paket.

Variasi dan tantangan:

- **Hitung ganda.** Kirim satu file berukuran diketahui dari instance di subnet privat lewat NAT gateway, lalu jumlahkan `bytes` tanpa memisahkan `interface_id`. Tunjukkan bahwa angkanya kira-kira tiga kali ukuran file, lalu perbaiki kuerinya (bagian 2.2).
- **Satuan waktu Azure.** Cek jumlah digit kolom pertama tuple di datamu, lalu jalankan versi lama kode bagian 2.6 (`unit="s"`) dan versi yang diperbaiki; catat apa yang terjadi.
- **DNS yang hilang.** Jalankan `dig` dari instance ke resolver bawaan VPC, lalu buktikan bahwa tidak ada rekaman flow log untuk query itu. Aktifkan Resolver query logging, ulangi query yang sama dua kali dalam TTL, dan catat berapa yang tercatat.

**Hasil yang sebaiknya tersimpan:**

- Tabel Athena berpartisi beserta catatan biaya dan data terpindai.
- Pencocokan tiga jenis aktivitas dengan rekaman yang dihasilkannya.
- Pengukuran selisih waktu antara aktivitas, nilai `start`, dan kedatangan log.
- Perbandingan jumlah rekaman dan biaya untuk interval 10 menit dan 1 menit.
- Bukti bahwa format bawaan tidak bisa menunjukkan asal di balik NAT gateway.
- Nilai `tcp-flags` yang teramati dari pemindaian jinak.
- Hasil penguraian `flowTuples` Azure beserta perhitungan volume dua cara.
- Daftar celah lingkungan sebagai lampiran laporan.
- Satu analisis lengkap di atas flow log beserta batas kesimpulannya.
- Angka hitung ganda sebelum dan sesudah kueri diperbaiki.
- Bukti bahwa query DNS ke resolver bawaan tidak tercatat di flow log, dan jumlah query yang tercatat di Resolver query logging.

## 4. Troubleshooting

Tabel ini dipakai saat hasil tidak sesuai harapan; mulai dari kolom gejala.

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Semua trafik keluar berasal dari satu alamat | Melewati NAT gateway; hanya `srcaddr` yang dipakai | Tambahkan `pkt-srcaddr` ke format kustom [S1]; baca ENI instance (bagian 1.3) |
| Baris dengan nilai `-` di banyak field | Field tidak berlaku atau tidak bisa dihitung untuk rekaman itu [S1] | Wajar; jangan tafsirkan sebagai data hilang |
| Muncul `SKIPDATA` | Sebagian rekaman dilewati karena kapasitas atau galat internal [S1] | Nyatakan di laporan; isi dari titik ukur kedua bila ada (bagian 2.4) |
| Tidak ada rekaman sama sekali | `NODATA` berarti memang tidak ada trafik [S1] | Bedakan dari pencatatan yang tidak aktif |
| Waktu tidak cocok dengan sumber lain | Interval agregasi dan jeda pengiriman [S1] | Pakai sumber lain sebagai jangkar; perlebar jendela korelasi |
| Beaconing tidak terdeteksi | Interval agregasi 10 menit menumpulkan keteraturan | Turunkan ke 1 menit; nyatakan batas bila tidak bisa |
| `tcp-flags` bernilai aneh | Flag di-OR selama interval [S1] | Jangan pakai kecocokan persis; baca sebagai gabungan |
| Log Azure ganda | NSG flow logs dan VNet flow logs aktif bersamaan [S2] | Nonaktifkan yang lama sebelum mengaktifkan yang baru |
| Beban kerja tertentu tidak muncul sama sekali | Layanan itu tidak mendukung flow log [S2] | Cek daftar layanan yang tidak didukung; catat sebagai celah |
| Volume Azure terlihat terlalu kecil | Hanya state `E` yang dijumlahkan | Jumlahkan semua state [S2] |
| Volume AWS terlihat dua atau tiga kali lipat | Trafik yang sama tercatat di setiap ENI yang dilewati (instance, kaki NAT, ENI tujuan internal) | Kelompokkan per `interface_id` atau pilih satu titik ukur (bagian 2.2) |
| Kueri Athena kosong untuk kejadian dini hari WIB | Partisi tanggal mengikuti UTC | Baca partisi hari sebelumnya (bagian 1.5) |
| Tanggal Azure mustahil atau galat overflow | Kolom waktu tuple dalam milidetik dibaca sebagai detik | Cek jumlah digit; 13 digit berarti milidetik (bagian 1.7) |
| Field baru tidak muncul setelah format diubah | Flow log tidak bisa diubah setelah dibuat [S7] | Buat flow log baru; data lama tetap format lama |
| Tidak ada jejak DNS dari instance | Query ke resolver bawaan VPC tidak tercatat flow log [S7] | Pakai Resolver query logging [S12] |
| Add-on Splunk tidak mengekstrak field | Urutan field format kustom tidak sesuai urutan yang dikenali add-on [S9] | Pakai urutan add-on, atau tulis ekstraksi sendiri |
| VM seri v6 tidak ada di NSG flow logs | NSG flow logs tidak mendukung VM keluarga D, E, F seri v6 [S3] | Pakai VNet flow logs |
| Baris masuk ditolak dari internet ke VM tanpa alamat publik | Percobaan ke port SNAT bawaan tetap tercatat di NSG flow logs [S3] | Jangan simpulkan VM terekspos |

## 5. Kesalahan umum dan jebakan

- Memakai format bawaan di lingkungan ber-NAT gateway atau berkontainer, lalu kehilangan asal trafik sebenarnya [S1].
- Menyimpulkan serangan dari satu baris REJECT, padahal ia juga muncul untuk paket setelah koneksi ditutup [S1].
- Melakukan korelasi berresolusi detik di atas data yang waktunya bisa meleset sampai 60 detik [S1].
- Mengabaikan baris `SKIPDATA`, padahal itu pengakuan resmi bahwa data hilang [S1].
- Menjumlahkan hanya state `E` saat menghitung volume di Azure [S2].
- Membiarkan NSG flow logs dan VNet flow logs aktif bersamaan [S2].
- Menyimpulkan tidak ada trafik tanpa memeriksa apakah layanannya memang didukung flow log [S2].
- Menjanjikan analisis isi, padahal flow log tidak memuat isi paket sama sekali.
- Membangun kesimpulan keras di atas field metadata yang memang bersifat perkiraan best effort [S1].
- Menjalankan kueri atas tabel tanpa partisi, lalu menyimpulkan analisis flow log cloud itu mahal.
- Menjumlahkan `bytes` dari semua ENI di VPC dan melaporkan angka dua atau tiga kali lipat (bagian 2.2).
- Mencari instance pengirim di baris ENI NAT, padahal baris ENI instance memuatnya langsung bila flow log berada di level VPC atau subnet [S6].
- Menyimpulkan "worker tidak menghubungi domain apa pun" dari flow log, padahal query ke resolver bawaan tidak pernah tercatat [S7].
- Mengubah konfigurasi flow log setelah insiden lalu berharap data historis ikut lengkap [S7].
- Membaca kolom waktu tuple Azure sebagai detik tanpa memeriksa jumlah digitnya.
- Membaca `NX` di tuple Azure sebagai "koneksi tanpa TLS"; itu status enkripsi virtual network [S2].
- Menafsirkan CV dari `start` AWS dengan ambang yang dibuat untuk timestamp Zeek, tanpa menyebut ketidakpastian 60 detik.
- Menyamakan kecocokan volume dengan bukti isi; unggahan yang sebesar data database adalah indikator, bukan kesimpulan.

## 6. Catatan terkini

Bagian ini menampung detail versi, tanggal terbit, dan perubahan yang perlu dipantau tetapi tidak mengubah langkah di atas.

- Azure NSG flow logs dinyatakan pensiun pada 30 September 2027, dan setelah itu sumber daya NSG flow log di langganan akan dihapus serta traffic analytics untuknya tidak lagi didukung [S3]. Halaman yang sama kini menyatakan pembuatan NSG flow log baru tidak lagi didukung, sedangkan rekaman yang sudah tersimpan di storage tetap mengikuti retensinya [S3]. Periksa lingkungan yang kamu tangani sekarang: data historis yang kamu andalkan untuk kasus lama bisa terpengaruh perencanaan migrasi ini.
- Virtual network flow logs diaktifkan di tingkat virtual network sehingga mencakup sumber daya seperti gateway secara bawaan, yang membuat volume lognya lebih besar [S2]. Perkirakan biayanya sebelum mengaktifkan di lingkungan besar. Halaman harganya menyebut tagihan per GB log yang dikumpulkan dengan kuota gratis 5 GB per bulan per subscription, dan traffic analytics ditagih terpisah tanpa kuota gratis [S2].
- Daftar layanan Azure yang tidak mendukung virtual network flow logs cukup panjang dan mencakup beberapa layanan yang umum dipakai, termasuk Functions, Logic Apps, App Service, dan beberapa basis data terkelola [S2]. Daftar ini berubah, jadi periksa ulang saat memulai kasus. Region Indonesia Central tercantum mendukung VNet flow logs, traffic analytics, dan Log Analytics workspace [S2].
- Di AWS, field tingkat paket dan `tcp-flags` hanya tersedia lewat format kustom [S1]. Mengubah konfigurasi flow log setelah insiden tidak memperbaiki data historis, jadi ini keputusan yang harus diambil sebelum dibutuhkan.
- Daftar field VPC Flow Logs kini sampai versi 11: `reject-reason` (versi 8), `resource-id` untuk regional NAT gateway (versi 9), `encryption-status` (versi 10), serta field tag, `interface-type`, dan `next-hop-*` (versi 11) [S1]. DDL contoh Athena masih memuat kolom versi 2 sampai 5 [S8], dan urutan format kustom yang dikenali Splunk Add-on for AWS juga berhenti di field versi 5 [S9]; field yang lebih baru perlu ekstraksi sendiri.
- Splunk Add-on for AWS versi 8.3.1 (Splunkbase 1876, 21 Oktober 2026) mendukung Splunk 9.3 sampai 10.7 dan CIM 5.x; halaman input VPC Flow Logs-nya menyebut format bawaan baru didukung lagi sejak 6.3.1 [S9]. Splunk Add-on for Microsoft Cloud Services versi 6.3.3 (Splunkbase 3110, 10 September 2026); halaman sourcetype-nya tidak mencantumkan VNet flow logs [S10].
- Flow log cloud menegaskan satu pola yang berulang di Day 15 dan Day 16: visibilitas jaringan makin bergeser dari isi ke metadata. Keterampilan yang bernilai bukan lagi membaca paket, melainkan menyimpulkan sebanyak mungkin dari metadata sambil menyatakan batasnya dengan jujur.

## 7. Cheat sheet

```
AWS VPC FLOW LOGS
BAWAAN (v2, urutan TETAP, tak bisa diubah)
  version account-id interface-id srcaddr dstaddr srcport dstport protocol
  packets bytes start end action log-status
  protocol = NOMOR IANA (6=TCP, 17=UDP) | action = ACCEPT / REJECT
  log-status: OK | NODATA (memang tak ada trafik) | SKIPDATA (REKAMAN HILANG -> tulis di laporan)

KUSTOM (yang benar-benar perlu)
  pkt-srcaddr / pkt-dstaddr   alamat TINGKAT PAKET  <- WAJIB kalau ada NAT gateway / kontainer
  tcp-flags                   FIN=1 SYN=2 RST=4 SYN-ACK=18 ; di-OR dalam interval (19, 3, ...)
  flow-direction, traffic-path, vpc-id, subnet-id, instance-id
  pkt-src-aws-service / pkt-dst-aws-service
  v8 reject-reason (BPA/EC saja) | v9 resource-id (regional NAT) | v11 tag, interface-type, next-hop-*
  flow log TIDAK BISA DIUBAH -> buat flow log baru; data lama tetap format lama

NAT GATEWAY ZONAL (format bawaan)
  kaki 1  instance -> NAT privat   (tahu instance, TIDAK tahu tujuan; pkt-dstaddr = tujuan)
  kaki 2  NAT privat -> internet   (tahu tujuan, TIDAK tahu instance)
  ENI instance (flow log level VPC/subnet) = instance + tujuan internet di SATU baris
  satu unggahan tercatat di 3 titik -> JANGAN jumlahkan semua ENI
  regional NAT: interface-id/subnet-id = '-', ID di resource-id

WAKTU     interval agregasi maks 10 menit (bawaan), bisa 1 menit; Nitro selalu <=1 menit
          start/end bisa MELESET sampai 60 detik
          pengiriman ~5 menit ke CloudWatch Logs, ~10 menit ke S3, best effort
          partisi S3/Athena = tanggal UTC (01:00 WIB Kamis = partisi Rabu)
          -> JANGAN korelasi berresolusi detik; flow log = konfirmasi kasar
          -> interval 10 menit MENGHANCURKAN analisis beaconing (koneksi persisten)
          -> CV dari start bisa ~3x CV sebenarnya

ATHENA    kolom: tanda hubung -> garis bawah ; "end" dan "date" dikutip
          WHERE "date" = DATE 'YYYY-MM-DD' dulu, baru filter start

AZURE
PENSIUN   NSG flow logs pensiun 30 September 2027; sumber dayanya akan DIHAPUS
          pembuatan baru sudah tidak didukung; blob lama ikut retensi
          pengganti: VNet flow logs (aktif di tingkat virtual network)
          jangan aktifkan keduanya bersamaan (log ganda + biaya)
          NSG flow logs TIDAK mendukung VM D/E/F seri v6

TUPLE     ts,src,dst,sport,dport,proto,arah,state,enc,pkt_kirim,byte_kirim,pkt_terima,byte_terima
          ts: cek digit (13 = milidetik, 10 = detik)
          arah: I masuk / O keluar
          state: B begin (TANPA statistik) | C continuing (statistik tiap 5 menit) | E end | D deny
          VOLUME: C dan E = agregat SEJAK TUPLE SEBELUMNYA -> JUMLAHKAN SEMUA STATE, bukan E saja
          enc: X terenkripsi | NX tidak (BAWAAN) | NX_* alasan enkripsi gagal (enkripsi VNet, BUKAN TLS)
          tiap rekaman menyebut NAMA RULE yang mengizinkan/menolak
          NSG lama: proto T/U + keputusan A/D ; VNet: proto angka + state D

TIDAK TERCATAT
  AWS   : ISI PAKET (sama sekali) -> analisis Day 05 tidak mungkin
          DNS ke Amazon DNS server, 169.254.169.254 (metadata), 169.254.169.123 (Time Sync),
          DHCP, ARP, aktivasi lisensi Windows, sumber Traffic Mirroring, router VPC,
          ENI endpoint <-> ENI NLB, regional NAT berumur pendek
          DNS -> Route 53 Resolver query logging (hanya query unik, bukan cache)
  Azure : Container Instances/Apps, Logic Apps, Functions, DNS Private Resolver, App Service,
          beberapa DB terkelola, SQL MI, NetApp Files, Power Platform
          alur VM ke ExpressRoute bila logging di subnet gateway; FastPath; private endpoint itu sendiri
  -> daftar celah ini WAJIB jadi lampiran tetap laporan cloud

SPLUNK    AWS: aws:cloudwatchlogs:vpcflow (Add-on for AWS; SQS-based S3 / Kinesis / CloudWatch Logs)
          Azure: VNet flow logs butuh ingest generik; urai flowTuples sendiri (spath + mvexpand + split)

PCAP DI CLOUD  AWS Traffic Mirroring: ENI -> target (ENI/NLB/GWLB), VXLAN, per sesi per jam,
               tipe instance tertentu; siapkan SEBELUM kejadian
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Rekaman VPC Flow Logs di antarmuka NAT gateway hanya memperlihatkan alamat privat NAT sebagai sumber unggahan ke internet. Seorang rekan menulis: "Karena format bawaan tidak punya `pkt-srcaddr`, instance pengirimnya tidak mungkin diketahui." Benarkah?

<details><summary>Jawaban</summary>

Tidak sepenuhnya. Di antarmuka NAT, kaki 2 memang hanya memuat alamat NAT dan tujuan internet, dan kaki 1 memuat instance tetapi tujuannya alamat NAT. Namun bila flow log dibuat di level VPC atau subnet, ENI instance punya rekaman sendiri yang memuat alamat instance dan alamat internet di baris yang sama, karena instance bukan perantara. Kaki 1 dan kaki 2 juga bisa ditautkan lewat port tujuan, waktu, serta paket dan byte yang sama per jendela. `pkt-*` tetap dibutuhkan bila hanya ENI NAT yang dicatat atau bila banyak instance mengirim koneksi kecil yang seragam.

Lihat bagian 1.3 dan 2.3.

</details>

**2. Skenario keputusan.** Kueri Athena per `srcaddr`, `dstaddr`, `dstport` atas seluruh VPC menunjukkan 5,8 GB keluar ke satu alamat internet malam itu. Apa yang kamu tulis di laporan?

- A. 5,8 GB, karena angka itu jumlah semua rekaman ke alamat tersebut.
- B. Pisahkan per `interface_id`, pilih satu titik ukur (kaki 2 di ENI NAT untuk volume ke internet), lalu laporkan angka dari titik itu.
- C. Bagi dua, karena setiap koneksi tercatat di dua arah.

<details><summary>Jawaban</summary>

B. Unggahan yang lewat NAT gateway tercatat di ENI instance, di kaki 1, dan di kaki 2 ENI NAT, sehingga penjumlahan kasar memberi kira-kira tiga kali lipat; di PT JAB, 5,8 GB itu sebenarnya 1.943.512.957 byte. A melaporkan hitung ganda. C keliru karena kelipatannya bergantung pada jumlah ENI yang dilewati, bukan pada arah; arah balik justru punya `srcaddr` dan `dstaddr` terbalik dan tidak masuk ke baris yang sama.

Lihat bagian 2.2 dan 2.4.

</details>

**3. Hitung.** Tiga tuple VNet flow logs untuk satu percakapan: `B` tanpa statistik; `C` dengan 1.021 paket dan 588.096 byte terkirim serta 8.005 paket dan 4.610.880 byte diterima; `E` dengan 52 paket, 29.952 byte, 47 paket, 27.072 byte. Berapa total paket dan byte, dan berapa yang akan dilaporkan orang yang hanya menjumlahkan baris `E`?

<details><summary>Jawaban</summary>

Total paket 1.021 + 52 + 8.005 + 47 = 9.125, total byte 588.096 + 29.952 + 4.610.880 + 27.072 = 5.256.000, karena state `C` dan `E` memuat hitungan sejak tuple sebelumnya. Hanya baris `E`: 99 paket dan 57.024 byte, jauh terlalu kecil. Byte di sini mencakup header dan payload.

Lihat bagian 1.7.

</details>

**4. Pertanyaan jebakan.** "Flow log `jab-rpt-worker01` selama 30 hari tidak memuat satu pun koneksi ke port 53, jadi worker tidak pernah melakukan query DNS ke domain mencurigakan." Apa yang salah?

<details><summary>Jawaban</summary>

Trafik dari instance ke Amazon DNS server tidak dicatat VPC Flow Logs sama sekali; hanya DNS server milikmu sendiri yang tercatat. Ketiadaan port 53 di flow log adalah sifat layanan, bukan bukti. Nama yang ditanyakan hanya ada di Route 53 Resolver query logging, yang di PT JAB belum aktif, dan log itu pun hanya mencatat query unik, bukan jawaban dari cache. Di kasus ini nama domain akhirnya didapat dari proxy dan `dns.log` kantor.

Lihat bagian 1.8 dan 2.8.

</details>

**5. Skenario keputusan.** Volume index `azure` naik hampir dua kali lipat sejak VNet flow logs diaktifkan, dan L1 menanyakan apakah ada lonjakan trafik di Azure. Apa langkahmu?

- A. Buka insiden, karena volume log yang naik dua kali lipat berarti trafik naik dua kali lipat.
- B. Matikan VNet flow logs, karena NSG flow logs sudah bekerja bertahun-tahun.
- C. Bandingkan tuple kedua sourcetype untuk subnet yang dicakup keduanya; bila sama, matikan NSG flow logs di subnet itu setelah saved search dipindah ke format baru.

<details><summary>Jawaban</summary>

C. Dokumentasi menyebut bahwa NSG flow logs dan VNet flow logs yang aktif bersamaan pada beban kerja yang sama bisa menghasilkan log ganda, dan menganjurkan mematikan yang lama dulu. A menyamakan volume log dengan volume trafik. B membuang generasi yang menggantikan fitur yang pensiun 30 September 2027 dan sudah tidak bisa dibuat baru, dan di PT JAB VNet flow logs adalah satu-satunya data untuk VM seri v6 seperti `jab-az-batch01`.

Lihat bagian 1.6 dan 2.7.

</details>

**6. Jelaskan ulang.** Jelaskan ke Agus Setiawan (DPO) dalam tiga kalimat apa yang bisa dan tidak bisa dikatakan flow log tentang data yang keluar dari `jab-rpt-worker01`.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh jawaban: "Flow log memastikan bahwa satu server laporan mengirim sekitar 1,94 GB ke satu alamat internet yang tidak dikenal, dalam satu koneksi antara 01:21 dan 02:10 WIB Kamis, tepat setelah server itu membaca data laporan dari database. Flow log tidak mencatat isi paket sama sekali, jadi kami tidak bisa memastikan dari log ini data apa yang keluar; besarnya mirip dengan data database ditambah PDF laporan, tetapi itu petunjuk, bukan bukti. Kepastian isi akan datang dari pemeriksaan kode library dan server oleh tim IR, dan kami akan memberi kabar begitu ada."

Kesalahan yang sering muncul: menyebut "data pelanggan bocor 1,94 GB" sebagai fakta padahal isinya belum diketahui; sebaliknya menyebut "tidak ada bukti data keluar" karena isinya tidak terbaca; dan melaporkan angka hitung ganda 5,8 GB.

</details>

**7. Interview question (English).** "You're investigating a suspected data exfiltration from a cloud workload, and VPC Flow Logs are the only network evidence. How do you approach it, and what are the limits?"

<details><summary>Sample answer</summary>

"First I check how the flow log was configured, because it can't be changed afterwards: default or custom format, VPC or interface level, and the aggregation interval. If traffic goes through a NAT gateway, I don't trust srcaddr on the NAT interface; I either use pkt-dstaddr on the first leg or read the instance's own interface records, which show the instance and the internet destination together. I pick one measurement point per question, because the same upload appears on the instance, both NAT legs, and any internal peer, so naive sums double or triple the volume. I check log-status for SKIPDATA and fill gaps from a second measurement point, and I treat start and end as accurate to about a minute, so I anchor the timeline with other sources. Finally, I list what flow logs never capture: payload, DNS to the Amazon resolver, instance metadata, and unsupported services. Flow logs tell me how much went where and when, not what it was."

What makes this answer strong: it starts from configuration rather than queries, handles the NAT and double-counting traps explicitly, treats data gaps and timestamp precision as quantified limits, names concrete blind spots, and separates volume evidence from claims about content.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | AWS VPC User Guide: Flow log records | https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html | primer | dilihat 2026-10-09, dicek ulang 2026-10-29 | Tinggi. Daftar lengkap field versi 2 sampai 11, interval agregasi dan jeda pengiriman, toleransi 60 detik pada `start` dan `end`, nilai `log-status`, perilaku `tcp-flags` termasuk penggabungan OR, perbedaan `srcaddr` dan `pkt-srcaddr`, perilaku regional NAT gateway, `traffic-path`, `reject-reason`, serta peringatan bahwa field metadata bersifat perkiraan best effort |
| S2 | Microsoft Learn: Virtual network flow logs overview | https://learn.microsoft.com/en-us/azure/network-watcher/vnet-flow-logs-overview | primer | halaman diperbarui 2026-10-06 (ms.date 2026-02-10), dilihat 2026-10-09, dicek ulang 2026-10-29 | Tinggi. Struktur JSON dan `flowTuples`, arah `I` dan `O`, flow state `B`, `C`, `E`, `D`, aturan agregasi volume dan contoh perhitungannya, sembilan nilai status enkripsi, interval satu menit, rule platform, anjuran menonaktifkan NSG flow logs lebih dulu, daftar layanan yang tidak didukung, batas ExpressRoute serta private endpoint, tabel cakupan NSG vs VNet, harga, dan ketersediaan region |
| S3 | Microsoft Learn: Network security group flow logs overview (pemberitahuan pensiun) | https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-overview | primer | dilihat 2026-10-09, dicek ulang 2026-10-29 (halaman diperbarui 2026-02-10) | Tinggi. Pensiun 30 September 2027, penghapusan sumber daya NSG flow log, traffic analytics tidak lagi didukung, pembuatan baru tidak didukung, rekaman di storage tidak dihapus, format tuple versi 1 dan 2, VM seri v6 tidak didukung, perilaku SNAT bawaan, dan pencatatan pada NSG yang diproses terakhir |
| S4 | IANA Assigned Internet Protocol Numbers | https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml | primer | dirujuk 2026-10-09 | Tinggi untuk penerjemahan nilai `protocol` |
| S5 | Network-Forensics Day 01, 04, 05, 08, 10, 11, 12, 15, 16 (lokal) | (lokal) | rujukan internal | 2026-10-10, diperbarui 2026-10-29 | Keterkaitan antar Day: blind spot cloud, scan, DNS, Zeek, flow dan timeout, ambang beacon, PCR, label ATT&CK exfiltration |
| S6 | AWS VPC User Guide: Flow log record examples | https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-records-examples.html | primer | diakses 2026-10-29 | Tinggi. Contoh trafik diterima, ditolak, `NODATA`, `SKIPDATA` (satu rekaman bisa mewakili beberapa alur), perilaku security group dan network ACL, urutan `tcp-flags`, empat kaki NAT gateway zonal, regional NAT gateway, transit gateway, dan `traffic-path` |
| S7 | AWS VPC User Guide: Flow log limitations | https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-limitations.html | primer | diakses 2026-10-29 | Tinggi. Flow log tidak bisa diubah setelah dibuat, kasus alamat primer di `srcaddr` dan `dstaddr`, client IP preservation, dan daftar trafik yang tidak dicatat (Amazon DNS, metadata, Time Sync, DHCP, ARP, sumber mirror, dan lainnya) |
| S8 | Amazon Athena User Guide: Query Amazon VPC flow logs dan Create a table for Amazon VPC flow logs and query it | https://docs.aws.amazon.com/athena/latest/ug/vpc-flow-logs.html ; https://docs.aws.amazon.com/athena/latest/ug/vpc-flow-logs-create-table-statement.html | primer | diakses 2026-10-29 | Tinggi. Penggantian tanda hubung dengan garis bawah di nama kolom, escape kata kunci tercadang dengan backtick di DDL, DDL contoh kolom versi 2 sampai 5 dengan partisi `date`, contoh kueri |
| S9 | Splunk Add-on for AWS: Configure VPC Flow Logs inputs; Splunkbase app 1876 | https://splunk.github.io/splunk-add-on-for-amazon-web-services/VPCFlowLogs ; https://splunkbase.splunk.com/app/1876/ | primer | diakses 2026-10-29 | Tinggi untuk sourcetype `aws:cloudwatchlogs:vpcflow`, jalur ingest (Kinesis, CloudWatch Logs, SQS-based S3), dan urutan field yang dikenali; Splunkbase menampilkan versi 8.3.1 bertanggal 21 Oktober 2026. Halaman input tidak memuat nomor versi dokumen |
| S10 | Splunk Add-on for Microsoft Cloud Services: Source types; Splunkbase app 3110 | https://splunk.github.io/splunk-add-on-for-microsoft-cloud-services/Sourcetypes ; https://splunkbase.splunk.com/app/3110 | primer | diakses 2026-10-29 | Sedang-tinggi. Halaman sourcetype menyatakan VNet flow logs butuh metode ingest generik; Splunkbase menampilkan versi 6.3.3 bertanggal 10 September 2026 |
| S11 | Amazon VPC Traffic Mirroring Guide: What is Traffic Mirroring dan How Traffic Mirroring works | https://docs.aws.amazon.com/vpc/latest/mirroring/what-is-traffic-mirroring.html ; https://docs.aws.amazon.com/vpc/latest/mirroring/traffic-mirroring-how-it-works.html | primer | diakses 2026-10-29 | Tinggi. Sumber, filter, target, sesi, pembungkusan VXLAN, daftar tipe instance yang didukung, dan dasar biaya |
| S12 | Amazon Route 53 Developer Guide: Resolver query logging | https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logs.html | primer | diakses 2026-10-29 | Tinggi. Query yang dicatat, nilai yang ada di log, tujuan pengiriman, dan pencatatan hanya untuk query unik (bukan jawaban dari cache) |

**Catatan sumber:** nama kolom di kueri Athena bagian 2.2 sampai 2.5 memakai bentuk dengan garis bawah (`pkt_srcaddr`, `tcp_flags`, `flow_direction`); dokumentasi Athena kini menetapkan penggantian tanda hubung dengan garis bawah [S8], sedangkan dokumentasi AWS VPC menuliskan nama field dengan tanda hubung. Rekaman contoh di bagian 2.1 adalah ilustrasi yang disusun mengikuti urutan field bawaan, bukan salinan keluaran nyata. Tanggal pensiun NSG flow logs dan pernyataan bahwa pembuatan baru tidak lagi didukung diambil dari halaman dokumentasi Microsoft [S3]; tanggal lain yang beredar di tulisan pihak ketiga tidak dipakai. Interval rekaman antarmuka NAT gateway (10 menit di data PT JAB) adalah inferensi dari aturan bahwa batas 1 menit berlaku untuk antarmuka yang terpasang di instance Nitro [S1], bukan pernyataan eksplisit dokumentasi, dan perlu diuji di lab. Penjelasan kueri `pkt_srcaddr <> srcaddr` di bagian 2.3 disesuaikan dengan contoh resmi NAT gateway dan transit gateway [S6]: di ENI NAT zonal kondisi itu menangkap kaki balasan, bukan kaki permintaan. Satuan waktu tuple Azure tidak dinyatakan eksplisit; contoh JSON resmi memakai 13 digit dan contoh perhitungan memakai 10 digit [S2]. Format nama rule buatan pengguna di VNet flow logs (`UserRule_`) diambil dari contoh NSG flow logs [S3] dan perlu dicek di data-mu. Sourcetype `mscs:vnet:flow` adalah konvensi PT JAB, bukan sourcetype yang tercantum di halaman sourcetype add-on versi sekarang [S10]; cek catatan rilis add-on versi-mu sebelum memakai nama yang sama. Perilaku `traffic-path` pada rekaman REJECT, nama filter `addresses.private-ip-address` di AWS CLI, dan pencatatan trafik ke resolver Azure di VNet flow logs belum dicek ke dokumentasi primer. Seluruh isi PT JAB (akun, ID sumber daya, alamat, angka, library `pdfx-fontcache`, domain, alert, keputusan, dan `INC-2027-076`) adalah penerapan catatan ini pada organisasi fiktif, bukan hasil eksekusi nyata; domain memakai `.example` dan alamat memakai rentang dokumentasi.
